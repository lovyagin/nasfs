#!/usr/bin/env bash
# Run on Linux with a systemd user manager. Install the Release build into a
# disposable prefix configured with CMAKE_INSTALL_PREFIX, then set
# NASFS_TEST_INSTALL_PREFIX to that prefix.

set -euo pipefail
prefix=${NASFS_TEST_INSTALL_PREFIX:?}
SERVER_BIN="$prefix/bin/nasfs_server"
CLIENT_BIN="$prefix/bin/nasfs_client"
installed_config="$prefix/etc/nasfs/nasfs.conf"
installed_unit="$prefix/lib/systemd/system/nasfs.service"
systemd_user_dir="${XDG_RUNTIME_DIR:?}/systemd/user"
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/integration_helpers.sh"
systemctl --user show-environment > /dev/null
setup_integration
unit="nasfs-test-$(basename "$TEST_ROOT").service"
config_saved=0

cleanup_systemd() {
    local result=$? preserve_backup=0
    systemctl --user stop "$unit" >/dev/null 2>&1 || true
    if (( result != 0 )); then
        journalctl --user -u "$unit" -n 30 --no-pager >&2 || true
        if [[ -f $LOG_DIR/server.log ]]; then tail -n 50 "$LOG_DIR/server.log" >&2 || true; fi
    fi
    systemctl --user reset-failed "$unit" >/dev/null 2>&1 || true
    rm -f -- "$systemd_user_dir/$unit" "$systemd_user_dir/$unit.d/keys.conf"
    rmdir "$systemd_user_dir/$unit.d" 2>/dev/null || true
    if (( config_saved )) && ! cp -p "$TEST_ROOT/installed.conf" "$installed_config"; then
        printf 'Could not restore %s. Backup: %s\n' "$installed_config" "$TEST_ROOT/installed.conf" >&2
        preserve_backup=1
    fi
    systemctl --user daemon-reload || true
    if (( ! preserve_backup )); then rm -rf -- "$TEST_ROOT"; fi
    return "$result"
}
trap cleanup_systemd EXIT

pid_file=$(sed -n 's/^PIDFile=//p' "$installed_unit")
test -n "$pid_file"
test "$pid_file" = "$(awk '$1 == "PidFile" {print $2}' "$installed_config")"
grep -Fx "PID_FILE=\"$pid_file\"" "$prefix/bin/nasfsctl"
storage_dir=$(awk '$1 == "StorageDir" {print $2}' "$installed_config")
[[ $storage_dir == "$prefix/"* && -d $storage_dir ]]
grep -Fx "ExecStart=$SERVER_BIN $installed_config" "$installed_unit"
mkdir -p "$systemd_user_dir/$unit.d"
cp "$installed_unit" "$systemd_user_dir/$unit"
cat > "$systemd_user_dir/$unit.d/keys.conf" <<KEYS
[Service]
Environment=NASFS_SERVER_SIGNING_SEED=$NASFS_SERVER_SIGNING_SEED
Environment=NASFS_AUTHOR_PUBLIC_KEY=$NASFS_AUTHOR_PUBLIC_KEY
Environment=LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}
KEYS
cp -p "$installed_config" "$TEST_ROOT/installed.conf"
config_saved=1
cat > "$installed_config" <<CONFIG
ListenAddr 127.0.0.1
Port 0
LogFile $LOG_DIR/server.log
LogLevel Debug
DaemonMode Yes
PidFile $pid_file
StorageDir $storage_dir
AuthMethods password
AuthPassword integration-password
CONFIG
systemctl --user daemon-reload
systemctl --user start "$unit"

check_instance() {
    local port
    systemctl --user is-active --quiet "$unit"
    test "$(systemctl --user show "$unit" -p MainPID --value)" = "$(cat "$pid_file")"
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
first_pid=$(cat "$pid_file")
systemctl --user restart "$unit"
check_instance
test "$(cat "$pid_file")" != "$first_pid"
"$CLIENT_BIN" get service.bin "$TEST_ROOT/result.bin"
cmp "$TEST_ROOT/source.bin" "$TEST_ROOT/result.bin"
systemctl --user stop "$unit"
if systemctl --user is-active --quiet "$unit"; then exit 1; fi
test ! -e "$pid_file"
