#!/usr/bin/env bash

cleanup_integration() {
    local status=$? log
    if [[ -n $SERVER_PID ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if (( status != 0 )); then
        for log in "$LOG_DIR"/*.log; do
            [[ -f $log ]] || continue
            printf '\n--- %s ---\n' "$log" >&2
            tail -n 100 "$log" >&2
        done
    fi
    rm -rf -- "$TEST_ROOT"
}

setup_integration() {
    if [[ ! -x ${SERVER_BIN:-} || ! -x ${CLIENT_BIN:-} ]]; then
        printf 'Build the NASFS server and client before running integration tests.\n' >&2
        return 1
    fi

    TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/nasfs-integration.XXXXXXXX")
    STORAGE_DIR="$TEST_ROOT/storage"
    LOG_DIR="$TEST_ROOT/logs"
    SERVER_PID=
    trap cleanup_integration EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    export HOME="$TEST_ROOT/home"
    mkdir -p "$STORAGE_DIR" "$LOG_DIR" "$HOME"
}

start_integration_server() {
    local config=$1 deadline=$((SECONDS + 10)) port=
    "$SERVER_BIN" "$config" > "$LOG_DIR/server_stdout.log" 2>&1 &
    SERVER_PID=$!

    while (( SECONDS < deadline )) && kill -0 "$SERVER_PID" 2>/dev/null; do
        if [[ -f $LOG_DIR/server.log ]]; then
            port=$(sed -n 's/.*nasfs_server listening on 127\.0\.0\.1:\([0-9][0-9]*\)\.\.\.$/\1/p' "$LOG_DIR/server.log")
            if [[ -n $port && $port != 0 ]]; then
                export NASFS_SERVER_IP=127.0.0.1 NASFS_SERVER_PORT="$port"
                return
            fi
        fi
        sleep 0.05
    done
    printf 'NASFS server failed to become ready within 10 seconds.\n' >&2
    return 1
}

wait_for_server_log_count() {
    local message=$1 expected=$2 deadline=$((SECONDS + 10)) count
    while (( SECONDS < deadline )); do
        count=$(grep -Fc "$message" "$LOG_DIR/server.log" || true)
        if (( count >= expected )); then
            return
        fi
        sleep 0.05
    done
    printf "Timed out waiting for server log message: %s\n" "$message" >&2
    return 1
}
