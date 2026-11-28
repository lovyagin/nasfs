#!/usr/bin/env bash

set -euo pipefail

export LD_LIBRARY_PATH="/usr/local/lib:/usr/local/lib64:${LD_LIBRARY_PATH:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${NASFS_SERVER_BIN:-$ROOT_DIR/server/nasfs_server}"
CLIENT_BIN="${NASFS_CLIENT_BIN:-$ROOT_DIR/client/nasfs_client}"
# shellcheck source-path=SCRIPTDIR
source "$ROOT_DIR/tests/integration_helpers.sh"
setup_integration

export NASFS_AUTH_METHOD=password NASFS_AUTH_USER=version-test
export NASFS_AUTH_PASSWORD=test-login NASFS_ENCRYPTION_KEY=test-file-secret
export NASFS_KEX_ALGORITHMS=ML-KEM-512
export NASFS_BLOCK_SIZE=4096

config="$TEST_ROOT/server.conf"
cat > "$config" <<CONFIG
ListenAddr 127.0.0.1
Port 0
MaxConn 20
LogFile $LOG_DIR/server.log
LogLevel Info
DaemonMode No
PidFile $TEST_ROOT/server.pid
StorageDir $STORAGE_DIR
KexAlgorithms ML-KEM-512
CipherAlgorithms xchacha20poly1305
AuthMethods password
AuthPassword test-login
VersionRetentionSeconds 0
CONFIG
printf 'legacy data remains in the original directory\n' > "$STORAGE_DIR/legacy.bin"
start_integration_server "$config"
export NASFS_VERSION_TEST_ROOT="$TEST_ROOT" NASFS_VERSION_TEST_STORAGE="$STORAGE_DIR"
python3 -B "$ROOT_DIR/tests/test_versioned_transfers.py" "$CLIENT_BIN"

# Verify the timed checkpoint survives SIGKILL and server startup cleanup.
NASFS_VERSION_TEST_SERVER_PID="$SERVER_PID" \
    python3 -B "$ROOT_DIR/tests/test_versioned_transfers.py" "$CLIENT_BIN" crash-checkpoint
status=0
wait "$SERVER_PID" 2>/dev/null || status=$?
test "$status" -eq 137
SERVER_PID=
# Older installations keep their original catalog location.
catalog="$STORAGE_DIR/.nasfs-v2"
mv "$STORAGE_DIR/.nasfs-versions" "$catalog"
start_integration_server "$config"
test ! -e "$STORAGE_DIR/.nasfs-versions"
"$CLIENT_BIN" put-resume "$TEST_ROOT/crash.checkpoint" "$TEST_ROOT/missing-after-crash" crash.bin
"$CLIENT_BIN" get crash.bin "$TEST_ROOT/crash-output"
cmp "$TEST_ROOT/crash-source" "$TEST_ROOT/crash-output"

# Inject a short asynchronous write, preserving the previously published head.
if [[ $(uname -s) == Linux ]]; then
    stop_integration_server
    "${CC:-cc}" -shared -fPIC -Wall -Wextra -Werror \
        "$ROOT_DIR/tests/fault_injection.c" -ldl -o "$TEST_ROOT/io-fault.so"
    preload="$TEST_ROOT/io-fault.so"
    asan_lib=$(ldd "$SERVER_BIN" | awk '/libasan\.so/ {print $3; exit}')
    if [[ -n $asan_lib ]]; then preload="$asan_lib:$preload"; fi
    LD_PRELOAD="$preload" NASFS_TEST_SHORT_WRITE=".attempt." \
        start_integration_server "$config"
    if "$CLIENT_BIN" put "$TEST_ROOT/first.bin" crash.bin > "$LOG_DIR/short-write.log" 2>&1; then
        exit 1
    fi
    grep -Fq 'PUT: Write failed: short write' "$LOG_DIR/server.log"
    "$CLIENT_BIN" get crash.bin "$TEST_ROOT/short-write-output"
    cmp "$TEST_ROOT/crash-source" "$TEST_ROOT/short-write-output"
fi

# A deliberately small logical quota blocks publication.
stop_integration_server
printf 'VersionQuotaBytes 1\n' >> "$config"
start_integration_server "$config"
if "$CLIENT_BIN" put "$TEST_ROOT/first.bin" too-large > "$LOG_DIR/quota.log" 2>&1; then
    exit 1
fi
grep -Fq 'quota exceeded' "$LOG_DIR/quota.log"
if "$CLIENT_BIN" resolve too-large > "$LOG_DIR/quota-resolve.log" 2>&1; then
    exit 1
fi
grep -Fq 'version unavailable' "$LOG_DIR/quota-resolve.log"
test -z "$(find "$catalog" -name '.attempt.*' -print)"
