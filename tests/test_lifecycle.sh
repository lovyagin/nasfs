#!/usr/bin/env bash

set -euo pipefail
SERVER_BIN=${NASFS_SERVER_BIN:?}
CLIENT_BIN=${NASFS_CLIENT_BIN:?}
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/integration_helpers.sh"
setup_integration

cat > "$TEST_ROOT/server.conf" <<CONFIG
ListenAddr 127.0.0.1
Port 0
MaxConn 1
ClientTimeout 1
LogFile $LOG_DIR/server.log
LogLevel Debug
DaemonMode No
PidFile $LOG_DIR/server.pid
StorageDir $STORAGE_DIR
CONFIG

python3 - "$SERVER_BIN" "$CLIENT_BIN" "$TEST_ROOT" <<'PYTHON'
import errno
import os
from pathlib import Path
import resource
import signal
import socket
import stat
import subprocess
import sys
import time

server, client, root = sys.argv[1:]
root = Path(root)
config = (root / "server.conf").read_text()

def server_failure(config_text, diagnostic):
    path = root / "failure.conf"
    if config_text is not None:
        path.write_text(config_text)
    result = subprocess.run([server, str(path)], capture_output=True, timeout=5)
    assert result.returncode == 1, result
    assert diagnostic in result.stdout + result.stderr, result
    assert not (root / "logs/server.pid").exists()

server_failure(None, b"Failed to load config file")
server_failure(config.replace("ClientTimeout 1", "ClientTimeout 0"),
               b"Invalid ClientTimeout")
def option(name, value):
    return "\n".join(
        f"{name} {value}" if line.startswith(f"{name} ") else line
        for line in config.splitlines()
    ) + "\n"

server_failure(option("StorageDir", root / "missing"),
               b"Cannot open storage directory")
server_failure(option("PidFile", root / "missing/server.pid"),
               b"Failed to create PID file")
server_failure(option("LogFile", root / "missing/server.log"),
               b"Failed to initialize configured log file")

with socket.socket() as occupied:
    occupied.bind(("127.0.0.1", 0))
    occupied.listen()
    server_failure(config.replace("Port 0", f"Port {occupied.getsockname()[1]}"),
                   b"Listen error")

# Bind the FIFO writer but withhold the configuration data. The server
# must still be before listener initialization when the signal is delivered.
fifo = root / "startup.fifo"
os.mkfifo(fifo)
for signum in (signal.SIGINT, signal.SIGTERM):
    with subprocess.Popen([server, str(fifo)], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as child:
        writer = None
        try:
            deadline = time.monotonic() + 5
            while writer is None:
                try:
                    writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as error:
                    if error.errno != errno.ENXIO:
                        raise
                    assert child.poll() is None and time.monotonic() < deadline
                    time.sleep(0.01)
            child.send_signal(signum)
            stdout, stderr = child.communicate(timeout=5)
            assert child.returncode == -signum, (stdout, stderr)
            assert not (root / "logs/server.pid").exists()
        finally:
            if writer is not None:
                os.close(writer)
            if child.poll() is None:
                child.kill()

private, public = root / "private.key", root / "authorized_keys"

def keygen(private, public, ok=False, preexec_fn=None):
    result = subprocess.run([client, "keygen", str(private), str(public), "ML-DSA-65"],
                            capture_output=True, timeout=5, preexec_fn=preexec_fn)
    assert result.returncode == (0 if ok else 1), result
    assert not list(root.glob("*.nasfs-key.*"))

keygen(private, private)
assert not private.exists()
keygen(private, root / "missing" / "key")
assert not private.exists()

def disk_limit():
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (8, 8))

keygen(private, public, preexec_fn=disk_limit)
assert not private.exists() and not public.exists()
keygen(private, public, ok=True)
assert stat.S_IMODE(private.stat().st_mode) == 0o600
old_private, old_public = private.read_bytes(), public.read_bytes()
keygen(private, public)
assert private.read_bytes() == old_private and public.read_bytes() == old_public
other_private = root / "other.key"
keygen(other_private, public)
assert not other_private.exists() and public.read_bytes() == old_public
PYTHON

rm -f "$LOG_DIR/server.log"
start_integration_server "$TEST_ROOT/server.conf"
python3 - "$NASFS_SERVER_PORT" "$LOG_DIR/server.log" <<'PYTHON'
import socket
import sys
import time
from pathlib import Path

port = int(sys.argv[1])
log = Path(sys.argv[2])

with socket.create_connection(("127.0.0.1", port), timeout=5) as first:
    deadline = time.monotonic() + 3
    while "Accepted new client connection" not in log.read_text():
        assert time.monotonic() < deadline
        time.sleep(0.01)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as second:
        assert second.recv(1) == b""
    assert first.recv(1) == b""

lines = log.read_text()
assert "Rejecting connection at session limit." in lines
assert "Session idle timeout." in lines
PYTHON
port=$NASFS_SERVER_PORT
kill -TERM "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=
test ! -e "$LOG_DIR/server.pid"
if NASFS_ENCRYPTION_KEY=lifecycle-file-secret "$CLIENT_BIN" put "$TEST_ROOT/absent" \
    > "$LOG_DIR/client_offline.log" 2>&1; then
    exit 1
fi
grep -Fq 'Connection error:' "$LOG_DIR/client_offline.log"
test ! -e "$STORAGE_DIR/absent"
rm "$LOG_DIR/server.log"
sed "s/^Port 0$/Port $port/" "$TEST_ROOT/server.conf" > "$TEST_ROOT/restart.conf"
start_integration_server "$TEST_ROOT/restart.conf"
test "$NASFS_SERVER_PORT" = "$port"

# A second instance cannot take ownership of a live PID file.
if "$SERVER_BIN" "$TEST_ROOT/server.conf" > "$LOG_DIR/second.log" 2>&1; then
    exit 1
fi
grep -Fq 'Failed to create PID file' "$LOG_DIR/second.log"
test "$(cat "$LOG_DIR/server.pid")" = "$SERVER_PID"

# SIGKILL leaves a stale PID file. The next process takes the released lock.
kill -KILL "$SERVER_PID"
result=0
wait "$SERVER_PID" 2>/dev/null || result=$?
test "$result" -eq 137
test "$(cat "$LOG_DIR/server.pid")" = "$SERVER_PID"
SERVER_PID=
rm "$LOG_DIR/server.log"
start_integration_server "$TEST_ROOT/restart.conf"
test "$(cat "$LOG_DIR/server.pid")" = "$SERVER_PID"

# Exercise the installed control script with paths confined to this test.
kill -TERM "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=
control_root="$TEST_ROOT/control"
mkdir -p "$control_root/bin" "$control_root/etc/nasfs" \
    "$control_root/var/run/nasfs" "$control_root/var/log/nasfs"
server_path="$(cd "$(dirname "$SERVER_BIN")" && pwd)/$(basename "$SERVER_BIN")"
ln -s "$server_path" "$control_root/bin/nasfs_server"
sed -e "s|@NASFS_BINDIR@|$control_root/bin|g" \
    -e "s|@NASFS_SYSCONFDIR@|$control_root/etc/nasfs|g" \
    -e "s|@NASFS_LOCALSTATEDIR@|$control_root/var|g" \
    "$(dirname "${BASH_SOURCE[0]}")/../utils/nasfsctl.in" > "$control_root/bin/nasfsctl"
sed -e "s|^PidFile .*|PidFile $control_root/var/run/nasfs/nasfs-server.pid|" \
    -e "s|^LogFile .*|LogFile $control_root/var/log/nasfs/nasfs-server.log|" \
    "$TEST_ROOT/server.conf" > "$control_root/etc/nasfs/nasfs.conf"
ctl() { sh "$control_root/bin/nasfsctl" "$@"; }
trap 'ctl stop >/dev/null 2>&1 || true; cleanup_integration' EXIT
if ctl status; then exit 1; fi
ctl start
ctl status
ctl restart
ctl status
ctl stop
ctl stop
if ctl status; then exit 1; fi
