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
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/integration_helpers.sh"
setup_integration

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Generate 512KB of test data
TEST_INPUT="$TEST_ROOT/plaintext.bin"
dd if=/dev/urandom of="$TEST_INPUT" bs=1k count=512 2>/dev/null
INPUT_HASH=$(hash_file "$TEST_INPUT")
printf "Created 512KB test file. Plaintext hash: %s\n" "$INPUT_HASH"

# Configure server
cat <<EOF > "$TEST_ROOT/server.conf"
ListenAddr 127.0.0.1
Port 0
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

start_integration_server "$TEST_ROOT/server.conf"

# Test 1: Upload with encryption enabled
printf '%b%s%b\n' "$YELLOW" "1. Uploading file with encryption enabled..." "$NC"
export NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!"

if ! env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="e2e" \
    NASFS_AUTH_PASSWORD="super-secret" \
    NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!" \
    "$CLIENT_BIN" put "$TEST_INPUT" "encrypted_remote.bin" > "$LOG_DIR/client_put.log" 2>&1; then
  printf '%b%s%b\n' "$RED" "FAIL: Client PUT command failed." "$NC"
  cat "$LOG_DIR/client_put.log"
  exit 1
fi

# Check if file exists in server storage
SERVER_STORED_FILE="$STORAGE_DIR/encrypted_remote.bin"
if [ ! -f "$SERVER_STORED_FILE" ]; then
    printf '%b%s%b\n' "$RED" "FAIL: Stored file not found on server!" "$NC"
    cat "$LOG_DIR/client_put.log"
    exit 1
fi

STORED_HASH=$(hash_file "$SERVER_STORED_FILE")
printf "Server stored file hash: %s\n" "$STORED_HASH"

if [ "$INPUT_HASH" == "$STORED_HASH" ]; then
    printf '%b%s%b\n' "$RED" "FAIL: Stored file is NOT encrypted! It matches the plaintext hash." "$NC"
    exit 1
fi
printf '%b%s%b\n' "$GREEN" "Success: Stored file is encrypted and does not match plaintext hash." "$NC"

# Test 2: Download and decrypt with the correct key
printf '%b%s%b\n' "$YELLOW" "2. Downloading and decrypting file with the CORRECT key..." "$NC"
TEST_OUTPUT_CORRECT="$TEST_ROOT/decrypted_correct.bin"

if ! env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="e2e" \
    NASFS_AUTH_PASSWORD="super-secret" \
    NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!" \
    "$CLIENT_BIN" get "encrypted_remote.bin" "$TEST_OUTPUT_CORRECT" > "$LOG_DIR/client_get_correct.log" 2>&1; then
  printf '%b%s%b\n' "$RED" "FAIL: Client GET (correct key) command failed." "$NC"
  cat "$LOG_DIR/client_get_correct.log"
  exit 1
fi

CORRECT_HASH=$(hash_file "$TEST_OUTPUT_CORRECT")
printf "Decrypted file hash: %s\n" "$CORRECT_HASH"

if [ "$INPUT_HASH" != "$CORRECT_HASH" ]; then
    printf '%b%s%b\n' "$RED" "FAIL: Decrypted file does not match original file!" "$NC"
    exit 1
fi
printf '%b%s%b\n' "$GREEN" "Success: Decrypted file matches the original file exactly!" "$NC"

# Test 3: Download and decrypt with an INCORRECT key
printf '%b%s%b\n' "$YELLOW" "3. Downloading and decrypting with an INCORRECT key (should fail)..." "$NC"
TEST_OUTPUT_INCORRECT="$TEST_ROOT/decrypted_incorrect.bin"
printf 'Keep the previous file.\n' > "$TEST_OUTPUT_INCORRECT"
PREVIOUS_HASH=$(hash_file "$TEST_OUTPUT_INCORRECT")

if env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="e2e" \
    NASFS_AUTH_PASSWORD="super-secret" \
    NASFS_ENCRYPTION_KEY="wrong-password-here!!!" \
    "$CLIENT_BIN" get "encrypted_remote.bin" "$TEST_OUTPUT_INCORRECT" > "$LOG_DIR/client_get_incorrect.log" 2>&1; then
    printf '%b%s%b\n' "$RED" "FAIL: Client get command unexpectedly succeeded with a wrong key!" "$NC"
    exit 1
fi

grep -Fq "Decryption failed. Wrong key or corrupted data" "$LOG_DIR/client_get_incorrect.log"
test "$(hash_file "$TEST_OUTPUT_INCORRECT")" = "$PREVIOUS_HASH"
if compgen -G "$TEST_ROOT/.nasfs-download.*" > /dev/null; then
    printf "Temporary download was not removed.\n" >&2
    exit 1
fi
test "$(hash_file "$SERVER_STORED_FILE")" = "$STORED_HASH"

printf '%b%s%b\n' "$GREEN" "Success: Decryption failed as expected when using an incorrect key." "$NC"

printf '%b%s%b\n' "$GREEN" "==============================================" "$NC"
printf '%b%s%b\n' "$GREEN" "    ALL FILE ENCRYPTION TESTS PASSED!         " "$NC"
printf '%b%s%b\n' "$GREEN" "==============================================" "$NC"
