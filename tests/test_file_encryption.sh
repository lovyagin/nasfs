#!/usr/bin/env bash

# NASFS File Encryption Integration Test

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${NASFS_SERVER_BIN:-$ROOT_DIR/build/nasfs_server}"
CLIENT_BIN="${NASFS_CLIENT_BIN:-$ROOT_DIR/build/nasfs_client}"
TEST_ROOT="${NASFS_TEST_ROOT:-$ROOT_DIR/tests/workspace_enc}"
STORAGE_DIR="${NASFS_STORAGE_DIR:-$ROOT_DIR/tests/storage_enc}"
LOG_DIR="$TEST_ROOT/logs"

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

cleanup() {
    printf "${YELLOW}%s${NC}\n" "Cleaning up processes and files..."
    if [ -f "$LOG_DIR/server.pid" ]; then
        PID=$(cat "$LOG_DIR/server.pid")
        kill "$PID" 2>/dev/null || true
    fi
    pkill -f nasfs_server 2>/dev/null || true
    rm -rf "$TEST_ROOT" "$STORAGE_DIR"
    printf "${GREEN}%s${NC}\n" "Cleanup complete."
}
trap cleanup EXIT

# Clear any lingering servers
pkill -f nasfs_server 2>/dev/null || true
sleep 1

mkdir -p "$STORAGE_DIR"
mkdir -p "$LOG_DIR"

# Generate 512KB of test data
TEST_INPUT="$TEST_ROOT/plaintext.bin"
dd if=/dev/urandom of="$TEST_INPUT" bs=1k count=512 2>/dev/null
INPUT_HASH=$(hash_file "$TEST_INPUT")
printf "Created 512KB test file. Plaintext hash: %s\n" "$INPUT_HASH"

# Configure server
cat <<EOF > "$TEST_ROOT/server.conf"
ListenAddr 127.0.0.1
Port 8081
MaxConn 10
LogFile $LOG_DIR/server.log
LogLevel Debug
DaemonMode No
PidFile $LOG_DIR/server.pid
StorageDir $STORAGE_DIR
KexAlgorithms ML-KEM-512,Kyber512
CipherAlgorithms xchacha20poly1305
AuthMethods password
AuthPassword super-secret
EOF

# Modify SERVER_IP/SERVER_PORT in CLIENT_BIN is not needed if we run on localhost:8080.
# Wait! In client/src/main.c, SERVER_PORT is hardcoded to 8080!
# Ah! Let's make sure our server port in the config is 8080!
sed -i.bak 's/Port 8081/Port 8080/g' "$TEST_ROOT/server.conf" || sed -i '' 's/Port 8081/Port 8080/g' "$TEST_ROOT/server.conf"

# Start server
printf "Starting server...\n"
"$SERVER_BIN" "$TEST_ROOT/server.conf" > "$LOG_DIR/server_stdout.log" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    printf "${RED}Server failed to start!${NC}\n"
    cat "$LOG_DIR/server_stdout.log"
    exit 1
fi
printf "${GREEN}Server started successfully.${NC}\n"

# Test 1: Upload with encryption enabled
printf "${YELLOW}1. Uploading file with encryption enabled...${NC}\n"
export NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!"

env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="e2e" \
    NASFS_AUTH_PASSWORD="super-secret" \
    NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!" \
    "$CLIENT_BIN" put "$TEST_INPUT" "encrypted_remote.bin" > "$LOG_DIR/client_put.log" 2>&1

# Check if file exists in server storage
SERVER_STORED_FILE="$STORAGE_DIR/encrypted_remote.bin"
if [ ! -f "$SERVER_STORED_FILE" ]; then
    printf "${RED}FAIL: Stored file not found on server!${NC}\n"
    cat "$LOG_DIR/client_put.log"
    exit 1
fi

STORED_HASH=$(hash_file "$SERVER_STORED_FILE")
printf "Server stored file hash: %s\n" "$STORED_HASH"

if [ "$INPUT_HASH" == "$STORED_HASH" ]; then
    printf "${RED}FAIL: Stored file is NOT encrypted! It matches the plaintext hash.${NC}\n"
    exit 1
fi
printf "${GREEN}Success: Stored file is encrypted and does not match plaintext hash.${NC}\n"

# Test 2: Download and decrypt with the correct key
printf "${YELLOW}2. Downloading and decrypting file with the CORRECT key...${NC}\n"
TEST_OUTPUT_CORRECT="$TEST_ROOT/decrypted_correct.bin"

env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="e2e" \
    NASFS_AUTH_PASSWORD="super-secret" \
    NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!" \
    "$CLIENT_BIN" get "encrypted_remote.bin" "$TEST_OUTPUT_CORRECT" > "$LOG_DIR/client_get_correct.log" 2>&1

CORRECT_HASH=$(hash_file "$TEST_OUTPUT_CORRECT")
printf "Decrypted file hash: %s\n" "$CORRECT_HASH"

if [ "$INPUT_HASH" != "$CORRECT_HASH" ]; then
    printf "${RED}FAIL: Decrypted file does not match original file!${NC}\n"
    exit 1
fi
printf "${GREEN}Success: Decrypted file matches the original file exactly!${NC}\n"

# Test 3: Download and decrypt with an INCORRECT key
printf "${YELLOW}3. Downloading and decrypting with an INCORRECT key (should fail)...${NC}\n"
TEST_OUTPUT_INCORRECT="$TEST_ROOT/decrypted_incorrect.bin"

if env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="e2e" \
    NASFS_AUTH_PASSWORD="super-secret" \
    NASFS_ENCRYPTION_KEY="wrong-password-here!!!" \
    "$CLIENT_BIN" get "encrypted_remote.bin" "$TEST_OUTPUT_INCORRECT" > "$LOG_DIR/client_get_incorrect.log" 2>&1; then
    printf "${RED}FAIL: Client get command unexpectedly succeeded with a wrong key!${NC}\n"
    exit 1
fi

printf "${GREEN}Success: Decryption failed as expected when using an incorrect key.${NC}\n"

printf "${GREEN}==============================================${NC}\n"
printf "${GREEN}    ALL FILE ENCRYPTION TESTS PASSED!         ${NC}\n"
printf "${GREEN}==============================================${NC}\n"
