#!/usr/bin/env bash
# Run explicitly on Linux with a reachable systemd user manager.

set -euo pipefail
SERVER_BIN=${NASFS_SERVER_BIN:?}
CLIENT_BIN=${NASFS_CLIENT_BIN:?}
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/integration_helpers.sh"
systemctl --user show-environment > /dev/null
setup_integration
unit="nasfs-test-$(basename "$TEST_ROOT").service"

cleanup_systemd() {
    local result=$?
    systemctl --user stop "$unit" >/dev/null 2>&1 || true
    if (( result != 0 )); then
        journalctl --user -u "$unit" -n 30 --no-pager >&2 || true
        if [[ -f $LOG_DIR/server.log ]]; then tail -n 50 "$LOG_DIR/server.log" >&2; fi
    fi
    systemctl --user reset-failed "$unit" >/dev/null 2>&1 || true
    rm -rf -- "$TEST_ROOT"
    return "$result"
}
trap cleanup_systemd EXIT

absolute_server="$(cd "$(dirname "$SERVER_BIN")" && pwd)/$(basename "$SERVER_BIN")"
cat > "$TEST_ROOT/nasfs.conf" <<CONFIG
ListenAddr 127.0.0.1
Port 0
LogFile $LOG_DIR/server.log
LogLevel Debug
DaemonMode Yes
PidFile $LOG_DIR/server.pid
StorageDir $STORAGE_DIR
AuthMethods password
AuthPassword integration-password
CONFIG

systemd-run --user --unit="$unit" --property=Type=forking \
    --property="PIDFile=$LOG_DIR/server.pid" \
    --property="ExecStop=/bin/kill -TERM \$MAINPID" \
    --property=TimeoutStartSec=10 --property=TimeoutStopSec=10 \
    --setenv="NASFS_SERVER_SIGNING_SEED=$NASFS_SERVER_SIGNING_SEED" \
    --setenv="NASFS_AUTHOR_PUBLIC_KEY=$NASFS_AUTHOR_PUBLIC_KEY" \
    --setenv="LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}" \
    "$absolute_server" "$TEST_ROOT/nasfs.conf"

check_instance() {
    local port
    systemctl --user is-active --quiet "$unit"
    test "$(systemctl --user show "$unit" -p MainPID --value)" = "$(cat "$LOG_DIR/server.pid")"
    port=$(sed -n 's/.*nasfs_server listening on 127\.0\.0\.1:\([0-9][0-9]*\)\.\.\.$/\1/p' "$LOG_DIR/server.log" | tail -n 1)
    test -n "$port"
    export NASFS_SERVER_IP=127.0.0.1 NASFS_SERVER_PORT="$port"
    (umask 077; mkdir -p "$HOME/.nasfs")
    cp "$TEST_ROOT/server.pub" "$HOME/.nasfs/server-127.0.0.1-$port.pub"
}
check_instance
printf 'NASFS systemd integration\n' > "$TEST_ROOT/source.bin"
export NASFS_AUTH_PASSWORD=integration-password NASFS_ENCRYPTION_KEY=integration-file-secret
"$CLIENT_BIN" put "$TEST_ROOT/source.bin" service.bin
first_pid=$(cat "$LOG_DIR/server.pid")
systemctl --user restart "$unit"
check_instance
test "$(cat "$LOG_DIR/server.pid")" != "$first_pid"
"$CLIENT_BIN" get service.bin "$TEST_ROOT/result.bin"
cmp "$TEST_ROOT/source.bin" "$TEST_ROOT/result.bin"
systemctl --user stop "$unit"
if systemctl --user is-active --quiet "$unit"; then exit 1; fi
test ! -e "$LOG_DIR/server.pid"
