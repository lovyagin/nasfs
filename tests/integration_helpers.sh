#!/usr/bin/env bash

stop_integration_server() {
    if [[ -n $SERVER_PID ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=
    fi
}

cleanup_integration() {
    local status=$? log
    stop_integration_server
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
    (umask 077; mkdir -p "$STORAGE_DIR" "$LOG_DIR" "$HOME")
    export NASFS_SERVER_SIGNING_SEED="$TEST_ROOT/server.seed"
    export NASFS_AUTHOR_SIGNING_SEED="$TEST_ROOT/author.seed"
    export NASFS_AUTHOR_PUBLIC_KEY="$TEST_ROOT/author.pub"
    (
        umask 077
        openssl genpkey -algorithm ED25519 -out "$TEST_ROOT/server-key.pem"
        openssl pkey -in "$TEST_ROOT/server-key.pem" -outform DER | tail -c 32 > "$NASFS_SERVER_SIGNING_SEED"
        openssl pkey -in "$TEST_ROOT/server-key.pem" -pubout -outform DER | tail -c 32 > "$TEST_ROOT/server.pub"
        openssl genpkey -algorithm ED25519 -out "$TEST_ROOT/author-key.pem"
        openssl pkey -in "$TEST_ROOT/author-key.pem" -outform DER | tail -c 32 > "$TEST_ROOT/author.seed"
        openssl pkey -in "$TEST_ROOT/author-key.pem" -pubout -outform DER | tail -c 32 > "$TEST_ROOT/author.pub"
    )
}

start_integration_server() {
    local config=$1 deadline=$((SECONDS + 10)) port=
    shift
    if [[ -n $config ]]; then
        "$@" "$SERVER_BIN" "$config" > "$LOG_DIR/server_stdout.log" 2>&1 &
    else
        "$@" "$SERVER_BIN" > "$LOG_DIR/server_stdout.log" 2>&1 &
    fi
    SERVER_PID=$!

    while (( SECONDS < deadline )) && kill -0 "$SERVER_PID" 2>/dev/null; do
        if [[ -f $LOG_DIR/server.log ]]; then
            port=$(sed -n "s/^\[PID=$SERVER_PID .*nasfs_server listening on 127\.0\.0\.1:\([0-9][0-9]*\)\.\.\.$/\1/p" "$LOG_DIR/server.log")
            if [[ -n $port && $port != 0 ]]; then
                export NASFS_SERVER_IP=127.0.0.1 NASFS_SERVER_PORT="$port"
                (umask 077; mkdir -p "$HOME/.nasfs")
                if [[ ! -e "$HOME/.nasfs/server-127.0.0.1-$port.pub" ]]; then
                    cp "$TEST_ROOT/server.pub" "$HOME/.nasfs/server-127.0.0.1-$port.pub"
                fi
                return
            fi
        fi
        sleep 0.05
    done
    printf 'NASFS server failed to become ready within 10 seconds.\n' >&2
    return 1
}
