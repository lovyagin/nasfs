"""Integration coverage for the signed NASFS-V2 catalog and transfer paths."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import re
import signal
import subprocess
import sys
import threading

from test_transfer_recovery import GET_DATA, GET_DONE, PUT_DONE, PUT_RESULT, interrupt_transfer


CLIENT = os.path.abspath(sys.argv[1])
ROOT = Path(os.environ["NASFS_VERSION_TEST_ROOT"])
STORAGE = Path(os.environ["NASFS_VERSION_TEST_STORAGE"])
PORT = int(os.environ["NASFS_SERVER_PORT"])
CATALOG = STORAGE / ".nasfs-v2"


def run(*args, expected=0, env=None):
    result = subprocess.run([CLIENT, *map(str, args)], capture_output=True,
                            timeout=20, env=env)
    assert result.returncode == expected, (args, result.stdout, result.stderr)
    return result


def resolve(name):
    output = run("resolve", name).stdout
    match = re.search(rb"^([0-9a-f]{32}) ([0-9a-f]{64})$", output, re.M)
    assert match, output
    return tuple(word.decode() for word in match.groups())


def put(source, name, **env):
    output = run("put", source, name, env=dict(os.environ, **env)).stdout
    match = re.search(rb"^Upload published. Manifest digest: ([0-9a-f]{64})$", output, re.M)
    assert match, output
    return match[1].decode()


first = ROOT / "first.bin"
first.write_bytes(bytes(i % 251 for i in range(17519)))
second = ROOT / "second.bin"
second.write_bytes(bytes(i % 239 for i in range(29475)))
output = ROOT / "download"

for profile in ("blake2b", "sha256", "blake3"):
    name = f"{profile}.bin"
    digest = put(first, name, NASFS_FILE_HASH=profile)
    object_id, version = resolve(name)
    assert version == digest
    assert (CATALOG / f"v-{digest}").read_bytes()[:8] == b"NASFSV2\0"
    run("get", name, output)
    assert output.read_bytes() == first.read_bytes()
    run("get-version", object_id, digest, 4089, 5028, output)
    assert output.read_bytes() == first.read_bytes()[4089:9117]
    run("get-version", object_id, digest, 17519, 0, output)
    assert not output.read_bytes()

empty = ROOT / "empty"
empty.touch()
put(empty, "empty")
run("get", "empty", output)
assert not output.read_bytes()

name = "versions.bin"
old = put(first, name)
object_id, version = resolve(name)
assert version == old
new = put(second, name)
assert resolve(name) == (object_id, new)
run("get-version", object_id, old, 0, "all", output)
assert output.read_bytes() == first.read_bytes()
wrong = run("get", name, output, expected=1,
            env=dict(os.environ, NASFS_EXPECTED_MANIFEST=old))
assert b"Unexpected file manifest version" in wrong.stderr, wrong.stderr
assert output.read_bytes() == first.read_bytes()

# Deleting the old catalog row does not interrupt an already opened GET.
interrupt_transfer(CLIENT, ["get-version", object_id, old, "0", "all", str(output)],
                   PORT, "get", GET_DATA, None, before_forward=lambda: run("collect"),
                   accepted_codes=(0,))
assert output.read_bytes() == first.read_bytes()
assert not (CATALOG / f"v-{old}").exists()
run("get-version", object_id, old, 0, "all", output, expected=1)

# A transfer paused at GET_DONE keeps the original snapshot of the destination.
original = output.stat()
def update_in_place():
    output.write_bytes(b"x" * original.st_size)
    os.utime(output, ns=(original.st_atime_ns, original.st_mtime_ns))
    assert output.stat().st_ino == original.st_ino

error = interrupt_transfer(CLIENT, ["get", name, str(output)], PORT, "get",
                           GET_DONE, None, before_forward=update_in_place)
assert b"destination changed during transfer" in error, error
assert output.read_bytes() == b"x" * original.st_size

interrupt_transfer(CLIENT, ["get", name, str(output)], PORT, "get", GET_DONE,
                   signal.SIGTERM)
assert output.read_bytes() == b"x" * original.st_size
assert not list(ROOT.glob(".nasfs-client.*/.nasfs-download.*"))

# Both writers resolved the same parent before either PUT_DONE reached NAS.
commit = threading.Barrier(2, timeout=10)
def contender(source):
    return interrupt_transfer(CLIENT, ["put", str(source), str(name)], PORT,
                              "put", PUT_DONE, None,
                              before_forward=commit.wait,
                              accepted_codes=(0, 1))

with ThreadPoolExecutor(max_workers=2) as pool:
    a = pool.submit(contender, first)
    b = pool.submit(contender, second)
    results = [a.result(), b.result()]
assert sum(b"version conflict" in stderr for stderr in results) == 1, results
run("get", name, output)
assert output.read_bytes() in (first.read_bytes(), second.read_bytes())

# A connection can drop after the catalog has committed.
error = interrupt_transfer(CLIENT, ["put", str(first), str(name)], PORT,
                           "get", PUT_RESULT, None)
assert b"PUT outcome unknown" in error, error
run("get", name, output)
assert output.read_bytes() == first.read_bytes()

# A local integrity check failure leaves the previous destination intact.
for position, marker in ((288 + 44, b"hash mismatch"), (288 + 12, b"hash mismatch")):
    digest = put(second, name)
    stored = CATALOG / f"v-{digest}"
    with stored.open("r+b") as stream:
        stream.seek(position)
        value = stream.read(1)
        stream.seek(position)
        stream.write(bytes([value[0] ^ 1]))
    failure = run("get", name, output, expected=1)
    assert marker in failure.stderr, failure.stderr
    assert output.read_bytes() == first.read_bytes()

assert run("get", "legacy.bin", output, expected=1).stderr
assert (STORAGE / "legacy.bin").read_text() == "legacy data remains in the original directory\n"
legacy_client = os.environ.get("NASFS_LEGACY_CLIENT_BIN")
if legacy_client:
    result = subprocess.run([legacy_client, "get", name, output], capture_output=True,
                            timeout=15)
    assert result.returncode == 1 and b"Unsupported transfer format" in result.stderr, result.stderr
assert not list(CATALOG.glob(".attempt.*"))
print("Signed version PUT, verified range GET, conflict, cleanup and recovery checks passed.")
