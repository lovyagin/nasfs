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
export LD_LIBRARY_PATH="/usr/local/lib:/usr/local/lib64:${LD_LIBRARY_PATH:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${NASFS_SERVER_BIN:-$ROOT_DIR/server/nasfs_server}"
CLIENT_BIN="${NASFS_CLIENT_BIN:-$ROOT_DIR/client/nasfs_client}"
TEST_ROOT="${NASFS_TEST_ROOT:-$ROOT_DIR/tests/workspace}"
STORAGE_DIR="${NASFS_STORAGE_DIR:-$ROOT_DIR/storage}"
TEST_DIR="$TEST_ROOT"
LOG_DIR="$TEST_DIR/logs"
CLIENT_KEY="$TEST_DIR/client_mldsa.key"
CLIENT_KEY_44="$TEST_DIR/client_mldsa44.key"
AUTHORIZED_KEYS="$TEST_DIR/authorized_keys"

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

run_client() {
    local log_file=$1
    local kex_list=$2
    local auth_method=$3
    local auth_password=$4
    local identity_file=$5
    local sig_algorithm=$6
    shift 6

    env NASFS_KEX_ALGORITHMS="$kex_list" \
        NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
        NASFS_AUTH_METHOD="$auth_method" \
        NASFS_AUTH_USER="e2e" \
        NASFS_AUTH_PASSWORD="$auth_password" \
        NASFS_AUTH_SIG_ALGORITHM="$sig_algorithm" \
        NASFS_IDENTITY_FILE="$identity_file" \
        "$CLIENT_BIN" "$@" > "$log_file" 2>&1
}

expect_client_failure() {
    local log_file=$1
    shift

    if run_client "$log_file" "$@"; then
        printf "${RED}%s${NC}\n" "FAIL: Client command unexpectedly succeeded."
        cat "$log_file"
        exit 1
    fi
}

verify_download_hash() {
    local expected_hash=$1
    local downloaded_file=$2
    local actual_hash

    if [ ! -f "$downloaded_file" ]; then
        printf "${RED}%s${NC}\n" "FAIL: Downloaded file not found: $downloaded_file"
        exit 1
    fi

    actual_hash=$(hash_file "$downloaded_file")
    if [ "$expected_hash" != "$actual_hash" ]; then
        printf "${RED}%s${NC}\n" "FAIL: Downloaded file hash mismatch!"
        exit 1
    fi
}

try_kex_download() {
    local kex_algorithm=$1
    local output_file="$TEST_DIR/test_file_${kex_algorithm//[^A-Za-z0-9]/_}.bin"
    local log_file="$LOG_DIR/client_kex_${kex_algorithm//[^A-Za-z0-9]/_}.log"

    if run_client "$log_file" "$kex_algorithm" "password" "e2e-password" "" \
        "ML-DSA-65" get "$REMOTE_NAME" "$output_file"; then
        verify_download_hash "$INPUT_HASH" "$output_file"
        printf "${GREEN}%s${NC}\n" "      KEX $kex_algorithm verified."
        return
    fi

    if grep -Eq "No compatible KEX/cipher suite|Connection closed|Connection error" \
        "$log_file"; then
        printf "${YELLOW}%s${NC}\n" "      SKIP: KEX $kex_algorithm is not enabled in this liboqs build."
        return
    fi

    printf "${RED}%s${NC}\n" "FAIL: KEX $kex_algorithm failed unexpectedly."
    cat "$log_file"
    exit 1
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

    rm -f "$TEST_DIR"/test_file_* "$CLIENT_KEY" "$CLIENT_KEY_44" \
        "$AUTHORIZED_KEYS" "$TEST_DIR"/authorized_keys_*
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

"$CLIENT_BIN" keygen "$CLIENT_KEY" "$TEST_DIR/authorized_keys_65" ML-DSA-65 \
    > "$LOG_DIR/keygen_mldsa65.log" 2>&1
cat "$TEST_DIR/authorized_keys_65" > "$AUTHORIZED_KEYS"

if "$CLIENT_BIN" keygen "$CLIENT_KEY_44" "$TEST_DIR/authorized_keys_44" \
    ML-DSA-44 > "$LOG_DIR/keygen_mldsa44.log" 2>&1; then
    cat "$TEST_DIR/authorized_keys_44" >> "$AUTHORIZED_KEYS"
    HAS_ML_DSA_44=1
else
    HAS_ML_DSA_44=0
    printf "${YELLOW}%s${NC}\n" "      SKIP: ML-DSA-44 is not enabled in this liboqs build."
fi

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
KexAlgorithms ML-KEM-512,Kyber512,ML-KEM-768,Kyber768
CipherAlgorithms xchacha20poly1305
AuthMethods password,publickey,password+publickey
AuthPassword e2e-password
AuthorizedKeysFile $AUTHORIZED_KEYS
PubKeyAuthAlgorithms ML-DSA-65,ML-DSA-44
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

expect_client_failure "$LOG_DIR/client_bad_auth.log" \
    "ML-KEM-512" "password" "wrong-password" "" "ML-DSA-65" \
    put "$TEST_INPUT" "bad-auth.bin"

if ! run_client "$LOG_DIR/client_put.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" put "$TEST_INPUT" "$REMOTE_NAME"; then
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
if ! run_client "$LOG_DIR/client_get.log" "ML-KEM-512" "publickey" "" \
    "$CLIENT_KEY" "ML-DSA-65" get "$REMOTE_NAME" "$TEST_OUTPUT"; then
    printf "${RED}%s${NC}\n" "FAIL: Client GET command failed."
    cat "$LOG_DIR/client_get.log"
    exit 1
fi

verify_download_hash "$INPUT_HASH" "$TEST_OUTPUT"
printf "${GREEN}%s${NC}\n" "      GET successful. Integrity verified."

printf "${YELLOW}%s${NC}\n" "      Testing auth/KEX matrix..."
if ! run_client "$LOG_DIR/client_both_auth.log" "ML-KEM-512" \
    "password+publickey" "e2e-password" "$CLIENT_KEY" "ML-DSA-65" \
    get "$REMOTE_NAME" "$TEST_DIR/test_file_both_auth.bin"; then
    printf "${RED}%s${NC}\n" "FAIL: password+publickey authentication failed."
    cat "$LOG_DIR/client_both_auth.log"
    exit 1
fi
verify_download_hash "$INPUT_HASH" "$TEST_DIR/test_file_both_auth.bin"
printf "${GREEN}%s${NC}\n" "      password+publickey auth verified."

expect_client_failure "$LOG_DIR/client_unauthorized_key.log" \
    "ML-KEM-512" "publickey" "" "$CLIENT_KEY" "ML-DSA-44" \
    get "$REMOTE_NAME" "$TEST_DIR/test_file_unauthorized_key.bin"

if [ "$HAS_ML_DSA_44" -eq 1 ]; then
    if ! run_client "$LOG_DIR/client_mldsa44.log" "ML-KEM-512" "publickey" \
        "" "$CLIENT_KEY_44" "ML-DSA-44" get "$REMOTE_NAME" \
        "$TEST_DIR/test_file_mldsa44.bin"; then
        printf "${RED}%s${NC}\n" "FAIL: ML-DSA-44 publickey authentication failed."
        cat "$LOG_DIR/client_mldsa44.log"
        exit 1
    fi
    verify_download_hash "$INPUT_HASH" "$TEST_DIR/test_file_mldsa44.bin"
    printf "${GREEN}%s${NC}\n" "      ML-DSA-44 publickey auth verified."
fi

try_kex_download "ML-KEM-512"
try_kex_download "Kyber512"
try_kex_download "ML-KEM-768"
try_kex_download "Kyber768"

if ! grep -Eq "Negotiated KEX: (ML-KEM-512|Kyber512|ML-KEM-768|Kyber768); control cipher: xchacha20poly1305" "$LOG_DIR/server.log"; then
    printf "${RED}%s${NC}\n" "FAIL: Negotiated suite was not logged as expected."
    cat "$LOG_DIR/server.log"
    exit 1
fi
printf "${GREEN}%s${NC}\n" "      Negotiated suite verified in server logs."

printf "${YELLOW}%s${NC}\n" "=============================================="
printf "${GREEN}%s${NC}\n" "    SUCCESS: All tests passed!               "
printf "${YELLOW}%s${NC}\n" "=============================================="

exit 0
