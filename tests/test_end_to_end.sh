#!/usr/bin/env bash

# NASFS End-to-End Integration Test
# Robust script to verify PUT and GET operations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Paths
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${NASFS_SERVER_BIN:-$ROOT_DIR/server/nasfs_server}"
CLIENT_BIN="${NASFS_CLIENT_BIN:-$ROOT_DIR/client/nasfs_client}"
TEST_ROOT="${NASFS_TEST_ROOT:-$ROOT_DIR/tests/workspace}"
STORAGE_DIR="${NASFS_STORAGE_DIR:-$ROOT_DIR/storage}"
TEST_DIR="$TEST_ROOT"
LOG_DIR="$TEST_DIR/logs"

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Ensure directories exist
mkdir -p "$STORAGE_DIR"
mkdir -p "$LOG_DIR"

printf "${YELLOW}%s${NC}\n" "=============================================="
printf "${YELLOW}%s${NC}\n" "    NASFS End-to-End Integration Test         "
printf "${YELLOW}%s${NC}\n" "=============================================="

# 1. Pre-flight checks
if [ ! -f "$SERVER_BIN" ] || [ ! -f "$CLIENT_BIN" ]; then
    printf "${RED}%s${NC}\n" "Error: Binaries not found. Run 'make' first."
    exit 1
fi

# shellcheck disable=SC2317,SC2329
cleanup() {
    printf "${YELLOW}%s${NC}" "Cleaning up processes and temporary files..."
    # Kill server if it's running
    if [ -f "$LOG_DIR/server.pid" ]; then
        PID=$(cat "$LOG_DIR/server.pid")
        kill "$PID" 2>/dev/null || true
    fi
    # Hard cleanup of any leaked instances
    pkill -f nasfs_server 2>/dev/null || true

    rm -rf "$TEST_DIR/test_file_*"
    printf "${GREEN}%s${NC}\n" " Done."
}
trap cleanup EXIT

# Ensure no server is already running on port 8080
pkill -f nasfs_server 2>/dev/null || true
sleep 1

# 2. Setup Test Data
printf "${YELLOW}%s${NC}\n" "[1/4] Preparing test data..."
TEST_INPUT="$TEST_DIR/test_file_input.bin"
TEST_OUTPUT="$TEST_DIR/test_file_output.bin"
# Create a 2MB file
dd if=/dev/urandom of="$TEST_INPUT" bs=1M count=2 2>/dev/null
INPUT_HASH=$(hash_file "$TEST_INPUT")
printf "      Created 2MB random file. Hash: %s...\n" "${INPUT_HASH:0:16}"

# 3. Start Server
printf "${YELLOW}%s${NC}\n" "[2/4] Starting server..."
# Create a test config
cat <<EOF > "$TEST_DIR/test_server.conf"
ListenAddr 127.0.0.1
Port 8080
MaxConn 10
LogFile $LOG_DIR/server.log
LogLevel Debug
DaemonMode No
PidFile $LOG_DIR/server.pid
StorageDir $STORAGE_DIR
KexAlgorithms ML-KEM-512,Kyber512
CipherAlgorithms xchacha20poly1305
EOF

"$SERVER_BIN" "$TEST_DIR/test_server.conf" > "$LOG_DIR/server_stdout.log" 2>&1 &
SERVER_PROC_PID=$!
sleep 2

if ! kill -0 $SERVER_PROC_PID 2>/dev/null; then
    printf "${RED}%s${NC}\n" "FAIL: Server failed to start. Logs:"
    cat "$LOG_DIR/server.log" 2>/dev/null || cat "$LOG_DIR/server_stdout.log"
    exit 1
fi
printf "${GREEN}%s${NC}\n" "      Server is running."

# 4. Test PUT
printf "${YELLOW}%s${NC}\n" "[3/4] Testing PUT (Upload)..."
REMOTE_NAME="e2e_test_upload.bin"
if ! env NASFS_KEX_ALGORITHMS="ML-KEM-512,Kyber512" \
         NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
         "$CLIENT_BIN" put "$TEST_INPUT" "$REMOTE_NAME" > "$LOG_DIR/client_put.log" 2>&1; then
    printf "${RED}%s${NC}\n" "FAIL: Client PUT command failed."
    printf "--- Client Logs ---\n"
    cat "$LOG_DIR/client_put.log"
    printf "--- Server Logs ---\n"
    cat "$LOG_DIR/server.log" 2>/dev/null
    exit 1
fi

# Verify file exists on server storage
if [ ! -f "$STORAGE_DIR/$REMOTE_NAME" ]; then
    printf "${RED}%s${NC}\n" "FAIL: Uploaded file not found in storage directory."
    exit 1
fi

UPLOAD_HASH=$(hash_file "$STORAGE_DIR/$REMOTE_NAME")
if [ "$INPUT_HASH" != "$UPLOAD_HASH" ]; then
    printf "${RED}%s${NC}\n" "FAIL: Uploaded file hash mismatch!"
    exit 1
fi
printf "${GREEN}%s${NC}\n" "      PUT successful. Integrity verified."

# 5. Test GET
printf "${YELLOW}%s${NC}\n" "[4/4] Testing GET (Download)..."
if ! env NASFS_KEX_ALGORITHMS="ML-KEM-512,Kyber512" \
         NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
         "$CLIENT_BIN" get "$REMOTE_NAME" "$TEST_OUTPUT" > "$LOG_DIR/client_get.log" 2>&1; then
    printf "${RED}%s${NC}\n" "FAIL: Client GET command failed."
    cat "$LOG_DIR/client_get.log"
    exit 1
fi

if [ ! -f "$TEST_OUTPUT" ]; then
    printf "${RED}%s${NC}\n" "FAIL: Downloaded file not found."
    exit 1
fi

DOWNLOAD_HASH=$(hash_file "$TEST_OUTPUT")
if [ "$INPUT_HASH" != "$DOWNLOAD_HASH" ]; then
    printf "${RED}%s${NC}\n" "FAIL: Downloaded file hash mismatch!"
    exit 1
fi
printf "${GREEN}%s${NC}\n" "      GET successful. Integrity verified."

if ! grep -Eq "Negotiated KEX: (ML-KEM-512|Kyber512); control cipher: xchacha20poly1305" "$LOG_DIR/server.log"; then
    printf "${RED}%s${NC}\n" "FAIL: Negotiated suite was not logged as expected."
    cat "$LOG_DIR/server.log"
    exit 1
fi
printf "${GREEN}%s${NC}\n" "      Negotiated suite verified in server logs."

printf "${YELLOW}%s${NC}\n" "=============================================="
printf "${GREEN}%s${NC}\n" "    SUCCESS: All tests passed!               "
printf "${YELLOW}%s${NC}\n" "=============================================="

exit 0
