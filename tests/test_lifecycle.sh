#!/usr/bin/env bash

set -euo pipefail
SERVER_BIN=${NASFS_SERVER_BIN:?}
CLIENT_BIN=${NASFS_CLIENT_BIN:?}
[[ $SERVER_BIN == /* ]] || SERVER_BIN="$PWD/$SERVER_BIN"
[[ $CLIENT_BIN == /* ]] || CLIENT_BIN="$PWD/$CLIENT_BIN"
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
import re
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
    result = subprocess.run([server, str(path)], cwd=root,
                            capture_output=True, timeout=5)
    assert result.returncode == 1, result
    assert diagnostic in result.stdout + result.stderr, result
    assert not (root / "logs/server.pid").exists()
    return result

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
server_failure(option("StorageDir", "missing-relative").replace(
                   "DaemonMode No", "DaemonMode Yes"),
               b"NASFS daemon failed to start")
assert re.search(r"Cannot open storage directory.*missing-relative",
                 (root / "logs/server.log").read_text())
if sys.platform == "darwin":
    seed = os.environ["NASFS_SERVER_SIGNING_SEED"]
    subprocess.run(["chmod", "+a", "everyone allow read", seed], check=True)
    try:
        server_failure(config, b"Expected ServerSigningSeed and AuthorPublicKey")
    finally:
        subprocess.run(["chmod", "-N", seed], check=True)
server_failure(option("PidFile", root / "missing/server.pid"),
               b"Failed to create PID file")
server_failure(option("LogFile", root / "missing/server.log"),
               b"Failed to initialize configured log file")

with socket.socket() as occupied:
    occupied.bind(("127.0.0.1", 0))
    occupied.listen()
    server_failure(config.replace("Port 0", f"Port {occupied.getsockname()[1]}"),
                   b"Listen error")

secret_prefix = "secret-that-must-not-appear"
long_line = server_failure(config + f"AuthPassword {secret_prefix}" + "x" * 4096,
                           f"Invalid configuration line {len(config.splitlines()) + 1}".encode())
assert secret_prefix.encode() not in long_line.stdout + long_line.stderr

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

oversized = subprocess.run([client, "keygen", str(other_private), str(root / "oversized.pub"),
                            "OV-Is"], capture_output=True, timeout=5)
assert oversized.returncode == 1, oversized
assert (b"exceeds NASFS key size limits" in oversized.stderr or
        b"Unsupported signature algorithm" in oversized.stderr), oversized
assert not other_private.exists() and not (root / "oversized.pub").exists()
assert not list(root.glob("*.nasfs-key.*"))

# Launch a detached server from a directory containing relative paths.
daemon_root = root / "daemon"
daemon_root.mkdir()
(daemon_root / "storage").mkdir(mode=0o700)
(daemon_root / "authorized_keys").write_bytes(public.read_bytes())
daemon_config = daemon_root / "server.conf"
daemon_log = daemon_root / "daemon.log"
daemon_pid = daemon_root / "server.pid"
relative_config = """ListenAddr 127.0.0.1
Port 0
LogFile daemon.log
LogLevel Info
PidFile server.pid
StorageDir storage
AuthorizedKeysFile authorized_keys
DaemonMode Yes
AuthMethods publickey
KexAlgorithms ML-KEM-512
"""

def launch_daemon(text):
    daemon_config.write_text(text)
    return subprocess.run([server, "server.conf"], cwd=daemon_root,
                          capture_output=True, timeout=10, preexec_fn=lambda: os.umask(0))

def wait_until(predicate):
    deadline = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < deadline, daemon_log.read_text()
        time.sleep(0.01)

def daemon_gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False

def assert_daemon_failure(text, diagnostic):
    daemon_log.unlink(missing_ok=True)
    result = launch_daemon(text)
    assert result.returncode == 1 and b"NASFS daemon failed to start" in result.stderr, result
    assert not daemon_pid.exists()
    log = daemon_log.read_text()
    match = re.search(r"\[PID=(\d+) .*" + re.escape(diagnostic), log)
    assert match and daemon_gone(int(match[1])), log

with socket.socket() as occupied:
    occupied.bind(("127.0.0.1", 0))
    occupied.listen()
    assert_daemon_failure(relative_config.replace("Port 0", f"Port {occupied.getsockname()[1]}"),
                          "Listen error")
assert_daemon_failure(relative_config.replace("PidFile server.pid", "PidFile missing/server.pid"),
                      "Failed to create PID file")
assert not (daemon_root / "missing").exists()
daemon_log.unlink()
result = launch_daemon(relative_config)
assert result.returncode == 0, result
pid = int(daemon_pid.read_text())
try:
    match = re.search(r"nasfs_server listening on 127\.0\.0\.1:(\d+)", daemon_log.read_text())
    assert match, daemon_log.read_text()
    port = match[1]
    pins = Path(os.environ["HOME"]) / ".nasfs"
    pins.mkdir(mode=0o700, exist_ok=True)
    pin = pins / f"server-127.0.0.1-{port}.pub"
    pin.write_bytes((root / "server.pub").read_bytes())
    pin.chmod(0o600)
    env = dict(os.environ, NASFS_AUTH_METHOD="publickey",
               NASFS_AUTH_SIG_ALGORITHM="ML-DSA-65", NASFS_IDENTITY_FILE=str(private),
               NASFS_KEX_ALGORITHMS="ML-KEM-512", NASFS_ENCRYPTION_KEY="daemon-file-secret",
               NASFS_SERVER_IP="127.0.0.1", NASFS_SERVER_PORT=port)
    original = daemon_root / "original"
    original.write_bytes(b"daemon relative paths\n")
    for args in (("put", original, "stored"), ("get", "stored", daemon_root / "output")):
        transfer = subprocess.run([client, *args], env=env, capture_output=True, timeout=10)
        assert transfer.returncode == 0, (transfer, daemon_log.read_text())
    assert len(list((daemon_root / "storage/.nasfs-v2").glob("v-*"))) == 1
    assert (daemon_root / "output").read_bytes() == original.read_bytes()
    assert "authenticated with publickey" in daemon_log.read_text()
    daemon_log.rename(daemon_root / "daemon.log.old")
    with socket.create_connection(("127.0.0.1", int(port)), timeout=5):
        wait_until(lambda: daemon_log.is_file() and "Accepted new client" in daemon_log.read_text())
    assert stat.S_IMODE(daemon_log.stat().st_mode) & 0o022 == 0
finally:
    os.kill(pid, signal.SIGTERM)
    wait_until(lambda: not daemon_pid.exists() and "Removed PID file" in daemon_log.read_text())
PYTHON

# Inject pauses between signal registration, bind and listen on Linux.
if [[ $(uname -s) == Linux ]]; then
    "${CC:-cc}" -shared -fPIC -Wall -Wextra -Werror \
        "$(dirname "${BASH_SOURCE[0]}")/fault_injection.c" -ldl -o "$TEST_ROOT/startup.so"
    python3 - "$SERVER_BIN" "$TEST_ROOT" <<'PYTHON'
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

server, root = sys.argv[1:]
root = Path(root)
preload = str(root / "startup.so")
asan = re.search(r"libasan\S* => (\S+)", subprocess.check_output(["ldd", server], text=True))
if asan:
    preload = f"{asan[1]}:{preload}"

for phase, signum, expected in (
    ("before-sigint", signal.SIGINT, -signal.SIGINT),
    ("before-sigterm", signal.SIGINT, 0),
    ("before-sigterm", signal.SIGTERM, -signal.SIGTERM),
    ("before-bind", signal.SIGTERM, 0),
    ("before-listen", signal.SIGINT, 0),
):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = root / "startup.conf"
    config.write_text((root / "server.conf").read_text().replace("Port 0", f"Port {port}"))
    gate = root / "startup-release"
    if gate.exists():
        gate.unlink()
    output = root / "logs" / f"{phase}-{signum}.log"
    env = dict(os.environ, LD_PRELOAD=preload, NASFS_TEST_STARTUP_PHASE=phase,
               NASFS_TEST_STARTUP_GATE=str(gate))
    with output.open("wb") as diagnostics, subprocess.Popen(
            [server, str(config)], env=env, stdout=diagnostics, stderr=diagnostics) as child:
        try:
            deadline = time.monotonic() + 5
            while f"Test fixture startup phase: {phase}" not in output.read_text():
                assert child.poll() is None and time.monotonic() < deadline, output.read_text()
                time.sleep(0.01)
            assert not (root / "logs/server.pid").exists()
            child.send_signal(signum)
            if expected == 0:
                gate.touch()
            assert child.wait(timeout=5) == expected, output.read_text()
        finally:
            gate.touch()
            if child.poll() is None:
                child.kill()
    assert not (root / "logs/server.pid").exists()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))

# Kill the detached process before readiness. The launcher must fail and the
# intermediate process must reap its child before returning that result.
config = root / "startup-daemon.conf"
config.write_text((root / "server.conf").read_text().replace("DaemonMode No", "DaemonMode Yes"))
def child_pid(pid):
    try:
        children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
    except FileNotFoundError:
        return None
    return int(children[0]) if children else None

pid_file = root / "logs/server.pid"

def pid_written(pid):
    try:
        return pid_file.read_text() == f"{pid}\n"
    except FileNotFoundError:
        return False

for phase, has_pid in (("before-listen", False), ("before-daemon-status", True)):
    gate = root / f"daemon-startup-release-{phase}"
    env = dict(os.environ, LD_PRELOAD=preload, NASFS_TEST_STARTUP_PHASE=phase,
               NASFS_TEST_STARTUP_GATE=str(gate))
    with subprocess.Popen([server, str(config)], env=env, stderr=subprocess.PIPE) as launcher:
        daemon = None
        try:
            deadline = time.monotonic() + 5
            while daemon is None or (has_pid and not pid_written(daemon)):
                assert launcher.poll() is None and time.monotonic() < deadline
                intermediate = child_pid(launcher.pid)
                daemon = child_pid(intermediate) if intermediate else None
                time.sleep(0.01)
            if has_pid:
                assert int(pid_file.read_text()) == daemon
            else:
                assert not pid_file.exists()
            os.kill(daemon, signal.SIGKILL)
            _, stderr = launcher.communicate(timeout=5)
            assert launcher.returncode == 1 and b"NASFS daemon failed to start" in stderr
            assert not Path(f"/proc/{daemon}").exists()
            assert not pid_file.exists()
        finally:
            gate.touch()
            if launcher.poll() is None:
                if daemon and Path(f"/proc/{daemon}").exists():
                    os.kill(daemon, signal.SIGKILL)
                launcher.kill()
PYTHON
fi

rm -f "$LOG_DIR/server.log"
server_path="$(cd "$(dirname "$SERVER_BIN")" && pwd)/$(basename "$SERVER_BIN")"
cp "$TEST_ROOT/server.conf" "$TEST_ROOT/nasfs.conf"
test_cwd=$PWD
cd "$TEST_ROOT"
SERVER_BIN="$server_path" start_integration_server ""
cd "$test_cwd"
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
if NASFS_AUTH_PASSWORD=lifecycle-login-password NASFS_ENCRYPTION_KEY=lifecycle-file-secret \
    "$CLIENT_BIN" put "$TEST_ROOT/absent" \
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
printf 'Port invalid\n' > "$TEST_ROOT/nasfs.conf"
mkdir -m 700 "$TEST_ROOT/second-storage"
sed "s|^StorageDir .*|StorageDir $TEST_ROOT/second-storage|" \
    "$TEST_ROOT/server.conf" > "$TEST_ROOT/second.conf"
if (cd "$TEST_ROOT" && "$server_path" "$TEST_ROOT/second.conf") > "$LOG_DIR/second.log" 2>&1; then
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
ctl stop
printf 'ServerSigningSeed %s\nAuthorPublicKey %s\n' \
    "$NASFS_SERVER_SIGNING_SEED" "$NASFS_AUTHOR_PUBLIC_KEY" >> "$control_root/etc/nasfs/nasfs.conf"
env -u NASFS_SERVER_SIGNING_SEED -u NASFS_AUTHOR_PUBLIC_KEY \
    sh "$control_root/bin/nasfsctl" start
ctl status
ctl restart
ctl status
ctl stop
ctl stop
if ctl status; then exit 1; fi

sed 's/^DaemonMode No$/DaemonMode Yes/' "$control_root/etc/nasfs/nasfs.conf" \
    > "$control_root/etc/nasfs/daemon.conf"
mv "$control_root/etc/nasfs/daemon.conf" "$control_root/etc/nasfs/nasfs.conf"
ctl start
ctl status
ctl stop

if [[ $(uname -s) == Linux ]]; then
    python3 - "$control_root" "$TEST_ROOT/startup.so" "$server_path" <<'PYTHON'
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

root = Path(sys.argv[1])
preload, server = sys.argv[2:]
asan = re.search(r"libasan\S* => (\S+)", subprocess.check_output(["ldd", server], text=True))
if asan:
    preload = f"{asan[1]}:{preload}"
pid_path = root / "var/run/nasfs/nasfs-server.pid"
ctl = ["sh", str(root / "bin/nasfsctl")]

for outcome in ("slow", "killed"):
    gate = root / f"release-{outcome}"
    env = dict(os.environ, LD_PRELOAD=preload,
               NASFS_TEST_STARTUP_PHASE="before-daemon-status",
               NASFS_TEST_STARTUP_GATE=str(gate))
    with subprocess.Popen([*ctl, "start"], env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as launcher:
        pid = None
        try:
            deadline = time.monotonic() + 5
            while pid is None:
                assert launcher.poll() is None and time.monotonic() < deadline
                if pid_path.is_file():
                    value = pid_path.read_text().strip()
                    if value:
                        pid = int(value)
                time.sleep(0.01)
            if outcome == "slow":
                time.sleep(5.25)
                assert launcher.poll() is None, launcher.communicate()
                gate.touch()
                assert launcher.wait(timeout=5) == 0, launcher.communicate()
                subprocess.run([*ctl, "status"], check=True, timeout=5)
                subprocess.run([*ctl, "stop"], check=True, timeout=5)
            else:
                os.kill(pid, signal.SIGKILL)
                out, err = launcher.communicate(timeout=5)
                assert launcher.returncode == 1 and b"Failed to start" in err, (out, err)
                assert b"NASFS server started" not in out
                assert not Path(f"/proc/{pid}").exists()
            assert not pid_path.exists()
        finally:
            gate.touch()
            if launcher.poll() is None:
                if pid is not None:
                    os.kill(pid, signal.SIGTERM)
                launcher.kill()
PYTHON
fi
