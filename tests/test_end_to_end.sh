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
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/integration_helpers.sh"
setup_integration

TEST_DIR="$TEST_ROOT"
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
        NASFS_ENCRYPTION_KEY="test-e2e-encryption-key-for-audit" \
        "$CLIENT_BIN" "$@" > "$log_file" 2>&1
}

expect_client_failure() {
    local log_file=$1 expected_error=$2
    shift 2

    if run_client "$log_file" "$@"; then
        printf "${RED}%s${NC}\n" "FAIL: Client command unexpectedly succeeded."
        cat "$log_file"
        exit 1
    fi
    grep -Fq "$expected_error" "$log_file"
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
    local kex_algorithm=$1 required=${2:-yes}
    local output_file="$TEST_DIR/test_file_${kex_algorithm//[^A-Za-z0-9]/_}.bin"
    local log_file="$LOG_DIR/client_kex_${kex_algorithm//[^A-Za-z0-9]/_}.log"

    if run_client "$log_file" "$kex_algorithm" "password" "e2e-password" "" \
        "ML-DSA-65" get "$REMOTE_NAME" "$output_file"; then
        verify_download_hash "$INPUT_HASH" "$output_file"
        printf "${GREEN}%s${NC}\n" "      KEX $kex_algorithm verified."
        return
    fi

    if [[ $required == no ]] && grep -Fq "No compatible KEX/cipher suite" \
        "$log_file"; then
        printf "${YELLOW}%s${NC}\n" "      SKIP: KEX $kex_algorithm is not enabled in this liboqs build."
        return
    fi

    printf "${RED}%s${NC}\n" "FAIL: KEX $kex_algorithm failed unexpectedly."
    cat "$log_file"
    exit 1
}

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
Port 0
MaxConn 10
LogFile $LOG_DIR/server.log
LogLevel Debug
DaemonMode No
PidFile $LOG_DIR/server.pid
StorageDir $STORAGE_DIR
KexAlgorithms ML-KEM-512,Kyber512,ML-KEM-768,Kyber768
CipherAlgorithms xchacha20poly1305
AuthMethods password,publickey,password+publickey,pake
AuthPassword e2e-password
AuthorizedKeysFile $AUTHORIZED_KEYS
PubKeyAuthAlgorithms ML-DSA-65,ML-DSA-44
EOF

start_integration_server "$TEST_DIR/test_server.conf"

# 4. Test PUT
printf "${YELLOW}%s${NC}\n" "[3/4] Testing PUT (Upload)..."
REMOTE_NAME="e2e_test_upload.bin"

if [[ $(uname -s) == Darwin ]]; then
    pin="$HOME/.nasfs/server-$NASFS_SERVER_IP-$NASFS_SERVER_PORT.pub"
    chmod +a "everyone allow write" "$pin"
    expect_client_failure "$LOG_DIR/client_pin_acl.log" "Missing or invalid server pin" \
        "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" \
        put "$TEST_INPUT" "bad-pin.bin"
    chmod -N "$pin"
    chmod +a "everyone allow read" "$NASFS_AUTHOR_SIGNING_SEED"
    expect_client_failure "$LOG_DIR/client_seed_acl.log" "Expected a private NASFS_AUTHOR_SIGNING_SEED" \
        "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" \
        put "$TEST_INPUT" "bad-seed.bin"
    chmod -N "$NASFS_AUTHOR_SIGNING_SEED"
    test ! -e "$STORAGE_DIR/bad-pin.bin"
    test ! -e "$STORAGE_DIR/bad-seed.bin"
fi

expect_client_failure "$LOG_DIR/client_bad_auth.log" "PQC Handshake successful" \
    "ML-KEM-512" "password" "wrong-password" "" "ML-DSA-65" \
    put "$TEST_INPUT" "bad-auth.bin"
grep -Fq "Client authentication failed." "$LOG_DIR/server.log"
test ! -e "$STORAGE_DIR/bad-auth.bin"

if ! run_client "$LOG_DIR/client_put.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" put "$TEST_INPUT" "$REMOTE_NAME"; then
    printf "${RED}%s${NC}\n" "FAIL: Client PUT command failed."
    printf "%s\n" "--- Client Logs ---"
    cat "$LOG_DIR/client_put.log"
    printf "%s\n" "--- Server Logs ---"
    cat "$LOG_DIR/server.log" 2>/dev/null
    exit 1
fi

# Verify encrypted blob exists on server storage.
# The stored file is E2EE ciphertext so its hash intentionally differs from
# the plaintext hash; only verify presence here.
published=$(sed -n 's/^Upload published. Manifest digest: //p' "$LOG_DIR/client_put.log")
if [ ! -f "$STORAGE_DIR/.nasfs-versions/v-$published" ]; then
    printf "${RED}%s${NC}\n" "FAIL: Uploaded file not found in storage directory."
    exit 1
fi
printf "${GREEN}%s${NC}\n" "      PUT successful. Ciphertext blob present on server."

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

expect_client_failure "$LOG_DIR/client_wrong_identity_algorithm.log" \
    "Failed to load identity file" \
    "ML-KEM-512" "publickey" "" "$CLIENT_KEY" "ML-DSA-44" \
    get "$REMOTE_NAME" "$TEST_DIR/test_file_wrong_identity_algorithm.bin"
test ! -e "$TEST_DIR/test_file_wrong_identity_algorithm.bin"

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
try_kex_download "Kyber512" no
try_kex_download "ML-KEM-768"
try_kex_download "Kyber768" no

if ! grep -Eq "Negotiated KEX: (ML-KEM-512|Kyber512|ML-KEM-768|Kyber768); control cipher: xchacha20poly1305" "$LOG_DIR/server.log"; then
    printf "${RED}%s${NC}\n" "FAIL: Negotiated suite was not logged as expected."
    cat "$LOG_DIR/server.log"
    exit 1
fi
printf "${GREEN}%s${NC}\n" "      Negotiated suite verified in server logs."

ln -s "$REMOTE_NAME" "$STORAGE_DIR/storage-link.bin"
STORED_HASH=$(hash_file "$STORAGE_DIR/.nasfs-versions/v-$published")
expect_client_failure "$LOG_DIR/client_storage_link.log" "Server error:" \
    "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" \
    get "storage-link.bin" "$TEST_DIR/storage-link.bin"
test ! -e "$TEST_DIR/storage-link.bin"
test -L "$STORAGE_DIR/storage-link.bin"
test "$(hash_file "$STORAGE_DIR/.nasfs-versions/v-$published")" = "$STORED_HASH"

expect_client_failure "$LOG_DIR/client_missing_source.log" "Cannot open PUT source" \
    "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" \
    put "$TEST_DIR/missing-source.bin" "missing-source.bin"
test ! -e "$STORAGE_DIR/missing-source.bin"

expect_client_failure "$LOG_DIR/client_missing_remote.log" "version unavailable" \
    "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" \
    get "absent.bin" "$TEST_DIR/absent.bin"
test ! -e "$TEST_DIR/absent.bin"

mkdir "$TEST_DIR/get_destination_directory"
expect_client_failure "$LOG_DIR/client_publish_failure.log" "Cannot publish download" \
    "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" \
    get "$REMOTE_NAME" "$TEST_DIR/get_destination_directory"
test -d "$TEST_DIR/get_destination_directory"
printf 'Existing destination\n' > "$TEST_DIR/get_protected"
chmod 444 "$TEST_DIR/get_protected"
mkfifo "$TEST_DIR/get_fifo"
ln -s get_protected "$TEST_DIR/get_symlink"
for destination in get_protected get_fifo get_symlink; do
    expect_client_failure "$LOG_DIR/client_$destination.log" "Cannot publish download" \
        "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" \
        get "$REMOTE_NAME" "$TEST_DIR/$destination"
done
test "$(cat "$TEST_DIR/get_protected")" = 'Existing destination'
test -p "$TEST_DIR/get_fifo"
test -L "$TEST_DIR/get_symlink"
test "$(readlink "$TEST_DIR/get_symlink")" = get_protected
if compgen -G "$TEST_DIR/.nasfs-client.*/.nasfs-download.*" > /dev/null; then
    printf "Temporary download was not removed.\n" >&2
    exit 1
fi

touch "$TEST_DIR/empty_input.bin"
run_client "$LOG_DIR/client_empty_put.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" put "$TEST_DIR/empty_input.bin" "empty.bin"
run_client "$LOG_DIR/client_empty_get.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" get "empty.bin" "$TEST_DIR/empty_output.bin"
test -f "$TEST_DIR/empty_output.bin"
test ! -s "$TEST_DIR/empty_output.bin"

expect_client_failure "$LOG_DIR/client_duplicate_destination.log" "Duplicate batch destination" \
    "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" mget x/file x/file
expect_client_failure "$LOG_DIR/client_duplicate_upload.log" "Duplicate batch destination" \
    "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" mput x/file y/file
# Let the server volume determine whether each pair names the same entry.
mkdir "$TEST_DIR/alias-first" "$TEST_DIR/alias-second"
check_mput_alias() {
    local first=$1 second=$2 label=$3
    local first_input="$TEST_DIR/alias-first/$1"
    local second_input="$TEST_DIR/alias-second/$2"
    printf 'First batch entry\n' > "$first_input"
    printf 'Second batch entry\n' > "$second_input"
    run_client "$LOG_DIR/client_alias_$label.log" "ML-KEM-512" "password" \
        "e2e-password" "" "ML-DSA-65" mput "$first_input" "$second_input"
    run_client "$LOG_DIR/client_alias_second_$label.log" "ML-KEM-512" "password" \
        "e2e-password" "" "ML-DSA-65" get "$second" "$TEST_DIR/alias-second.out"
    cmp "$second_input" "$TEST_DIR/alias-second.out"
    run_client "$LOG_DIR/client_alias_first_$label.log" "ML-KEM-512" "password" \
        "e2e-password" "" "ML-DSA-65" get "$first" "$TEST_DIR/alias-first.out"
    cmp "$first_input" "$TEST_DIR/alias-first.out"
}
check_mput_alias Batch-Case.bin batch-case.bin case
check_mput_alias $'batch-\xc3\xa9.bin' $'batch-e\xcc\x81.bin' unicode

mkdir "$TEST_DIR/first-destination" "$TEST_DIR/second-destination"
run_client "$LOG_DIR/client_distinct_destinations.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" mget "$TEST_DIR/first-destination/$REMOTE_NAME" \
    "$TEST_DIR/second-destination/$REMOTE_NAME"
cmp "$TEST_INPUT" "$TEST_DIR/first-destination/$REMOTE_NAME"
cmp "$TEST_INPUT" "$TEST_DIR/second-destination/$REMOTE_NAME"
ln -s first-destination "$TEST_DIR/destination-link"
for alias_dir in "$TEST_DIR/destination-link" "$TEST_DIR/second-destination/../first-destination"; do
    expect_client_failure "$LOG_DIR/client_local_alias.log" "Duplicate batch destination" \
        "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" mget \
        "$TEST_DIR/first-destination/$REMOTE_NAME" "$alias_dir/$REMOTE_NAME"
    test "$(grep -Fc 'Download complete.' "$LOG_DIR/client_local_alias.log")" = 1
    cmp "$TEST_INPUT" "$TEST_DIR/first-destination/$REMOTE_NAME"
    test -z "$(find "$TEST_DIR/first-destination" -name '.nasfs-download.*' -print)"
done
too_many_files=()
for ((i = 0; i < 513; i++)); do
    too_many_files+=("file-$i")
done
expect_client_failure "$LOG_DIR/client_batch_limit.log" "Batch limit is 512 files" \
    "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" mput "${too_many_files[@]}"

other_input="$TEST_DIR/second_input.bin"
dd if=/dev/urandom of="$other_input" bs=1M count=2 2>/dev/null
other_hash=$(hash_file "$other_input")

run_client "$LOG_DIR/client_concurrent_first.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" put "$TEST_INPUT" "concurrent.bin" &
first_upload=$!
run_client "$LOG_DIR/client_concurrent_second.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" put "$other_input" "concurrent.bin" &
second_upload=$!
first_status=0
second_status=0
wait "$first_upload" || first_status=$?
wait "$second_upload" || second_status=$?
test "$first_status" -eq 0 || test "$second_status" -eq 0

run_client "$LOG_DIR/client_concurrent_get.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" get "concurrent.bin" "$TEST_DIR/concurrent.bin"
concurrent_hash=$(hash_file "$TEST_DIR/concurrent.bin")
test "$concurrent_hash" = "$INPUT_HASH" || test "$concurrent_hash" = "$other_hash"

run_client "$LOG_DIR/client_replace.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" put "$other_input" concurrent.bin
run_client "$LOG_DIR/client_replaced_get.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" get concurrent.bin "$TEST_DIR/replaced.bin"
cmp "$other_input" "$TEST_DIR/replaced.bin"

cp "$TEST_INPUT" "$TEST_DIR/batch_first.bin"
cp "$TEST_INPUT" "$TEST_DIR/concurrent.bin"
cp "$other_input" "$TEST_DIR/batch_last.bin"
expect_client_failure "$LOG_DIR/client_batch_publish_failure.log" "Server could not publish" \
    "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" mput \
    "$TEST_DIR/batch_first.bin" "$TEST_DIR/concurrent.bin" \
    "$TEST_DIR/batch_last.bin"
expect_client_failure "$LOG_DIR/client_batch_last.log" "version unavailable" \
    "ML-KEM-512" "password" "e2e-password" "" "ML-DSA-65" resolve "batch_last.bin"
run_client "$LOG_DIR/client_batch_first_get.log" "ML-KEM-512" "password" \
    "e2e-password" "" "ML-DSA-65" get "batch_first.bin" "$TEST_DIR/batch_first_get.bin"
verify_download_hash "$INPUT_HASH" "$TEST_DIR/batch_first_get.bin"
if compgen -G "$STORAGE_DIR/.nasfs-versions/.attempt.*" > /dev/null; then
    printf "Temporary upload was not removed.\n" >&2
    exit 1
fi

# Verify PAKE and successful batches across independent CLI invocations.
mkdir "$TEST_DIR/batch-input" "$TEST_DIR/batch-output"
cp "$TEST_INPUT" "$TEST_DIR/batch-input/batch_a.bin"
printf 'Second batch member\n' > "$TEST_DIR/batch-input/batch_b.bin"
run_client "$LOG_DIR/client_pake_mput.log" "ML-KEM-512" "pake" \
    "e2e-password" "" "ML-DSA-65" mput "$TEST_DIR/batch-input/batch_a.bin" \
    "$TEST_DIR/batch-input/batch_b.bin"
(
    CLIENT_BIN="$(cd "$(dirname "$CLIENT_BIN")" && pwd)/$(basename "$CLIENT_BIN")"
    cd "$TEST_DIR/batch-output"
    run_client "$LOG_DIR/client_pake_mget.log" "ML-KEM-512" "pake" \
        "e2e-password" "" "ML-DSA-65" mget batch_a.bin batch_b.bin
)
cmp "$TEST_DIR/batch-input/batch_a.bin" "$TEST_DIR/batch-output/batch_a.bin"
cmp "$TEST_DIR/batch-input/batch_b.bin" "$TEST_DIR/batch-output/batch_b.bin"

# Leaving AuthPassword unset or clearing it disables password and PAKE.
for setting in omitted empty; do
    kill -TERM "$SERVER_PID"
    wait "$SERVER_PID"
    SERVER_PID=
    rm "$LOG_DIR/server.log"
    if [[ $setting == omitted ]]; then
        sed '/^AuthPassword /d' "$TEST_DIR/test_server.conf" > "$TEST_DIR/no-password.conf"
    else
        cp "$TEST_DIR/test_server.conf" "$TEST_DIR/no-password.conf"
        printf 'AuthPassword # cleared\n' >> "$TEST_DIR/no-password.conf"
    fi
    start_integration_server "$TEST_DIR/no-password.conf"
    expect_client_failure "$LOG_DIR/client_password_$setting.log" "Authentication failed" \
        "ML-KEM-512" "password" "nasfs" "" "ML-DSA-65" get "$REMOTE_NAME" "$TEST_OUTPUT"
    run_client "$LOG_DIR/client_key_$setting.log" "ML-KEM-512" "publickey" "" \
        "$CLIENT_KEY" "ML-DSA-65" get "$REMOTE_NAME" "$TEST_OUTPUT"
    verify_download_hash "$INPUT_HASH" "$TEST_OUTPUT"
done

printf "${YELLOW}%s${NC}\n" "=============================================="
printf "${GREEN}%s${NC}\n" "    SUCCESS: All tests passed!               "
printf "${YELLOW}%s${NC}\n" "=============================================="

exit 0
