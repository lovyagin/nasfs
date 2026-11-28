"""Integration coverage for the signed NASFS-V2 catalog and transfer paths."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time

from test_transfer_recovery import GET_DATA, GET_DONE, PUT_DATA, PUT_DONE, PUT_RESULT, interrupt_transfer


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


if len(sys.argv) > 2 and sys.argv[2] == "crash-checkpoint":
    journal = ROOT / "crash.checkpoint"
    source = ROOT / "crash-source"
    source.write_bytes(bytes(i % 247 for i in range(4096 * 16 + 11)))

    def await_checkpoint():
        deadline = time.monotonic() + 6
        while True:
            with sqlite3.connect(CATALOG / "catalog.db") as db:
                row = db.execute(
                    "SELECT sequence FROM attempts WHERE name='crash.bin'"
                ).fetchone()
            if row and row[0] >= 2:
                return
            assert time.monotonic() < deadline, row
            time.sleep(0.04)

    interrupt_transfer(CLIENT, ["put-resume", str(journal), str(source), "crash.bin"],
                       PORT, "put", PUT_DATA, signal.SIGKILL,
                       int(os.environ["NASFS_VERSION_TEST_SERVER_PID"]),
                       occurrence=4, on_pause=await_checkpoint)
    assert not list(ROOT.glob(".nasfs-client.*/.nasfs-download.*"))
    sys.exit(0)


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

# A prepared upload can continue from the server's durable prefix. The
# checkpoint binds a per-attempt token, authenticated subject, name and proof.
journal = ROOT / "upload.checkpoint"
resumable = ROOT / "resume-source"
resumable.write_bytes(first.read_bytes() * 8)
resume_name = "resume.bin"
resumable_args = ["put-resume", str(journal), str(resumable), resume_name]

def competing_resume():
    second_writer = run(*resumable_args, expected=1)
    assert b"Upload attempt unavailable" in second_writer.stderr
    wrong_owner = run(*resumable_args, expected=1,
                      env=dict(os.environ, NASFS_AUTH_USER="different-subject"))
    assert b"Upload attempt unavailable" in wrong_owner.stderr

interrupt_transfer(CLIENT, resumable_args, PORT, "put", PUT_DATA, signal.SIGTERM,
                   occurrence=5, on_pause=competing_resume)
assert journal.stat().st_mode & 0o077 == 0
deadline = time.monotonic() + 5
while True:
    with sqlite3.connect(CATALOG / "catalog.db") as db:
        checkpoint = db.execute(
            "SELECT sequence,result FROM attempts WHERE name=?", (resume_name,)
        ).fetchone()
    if checkpoint and checkpoint[0] > 0:
        break
    assert time.monotonic() < deadline, checkpoint
    time.sleep(0.02)

expected_bytes = resumable.read_bytes()
resumable.unlink()
lost = interrupt_transfer(CLIENT, resumable_args, PORT, "get", PUT_RESULT, None)
assert b"PUT outcome unknown" in lost, lost
committed = resolve(resume_name)
result = run(*resumable_args)
assert committed[1].encode() in result.stdout
assert resolve(resume_name) == committed
run("get", resume_name, output)
assert output.read_bytes() == expected_bytes
run("get", name, output)
assert output.read_bytes() == first.read_bytes()

# The client keeps only verified ciphertext in its local GET journal. A
# subsequent invocation verifies the prefix and requests the same version tail.
get_journal = ROOT / "download.checkpoint"
download_args = ["get-resume", str(get_journal), *committed, str(output)]
previous = output.read_bytes()
def await_download_checkpoint():
    deadline = time.monotonic() + 5
    while not get_journal.exists() or get_journal.stat().st_size <= 328:
        assert time.monotonic() < deadline, "GET journal has no verified rows"
        time.sleep(0.02)

interrupt_transfer(CLIENT, download_args, PORT, "get", GET_DATA,
                   signal.SIGTERM, occurrence=5, on_pause=await_download_checkpoint)
assert output.read_bytes() == previous
result = run(*download_args)
assert b"Restored verified download prefix" in result.stdout, result.stdout
assert output.read_bytes() == expected_bytes
run(*download_args)  # the entire version is already in the local journal
assert output.read_bytes() == expected_bytes
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

# ECC is selected by the signed version, independently of GET environment.
ecc_input = ROOT / "ecc-source"
ecc_input.write_bytes(bytes(i % 241 for i in range(4096 * 19 + 33)))
for profile, failure_limit in (("xor-4+1", 1), ("xor-8+1", 1),
                               ("xor-16+1", 1), ("rs-8+2", 2)):
    digest = put(ecc_input, profile, NASFS_ECC=profile)
    object_id, _ = resolve(profile)
    stored = CATALOG / f"v-{digest}"
    run("get", profile, output)
    assert output.read_bytes() == ecc_input.read_bytes()
    with stored.open("r+b") as stream:
        for index in range(failure_limit):
            position = 288 + index * (4096 + 16 + 44) + 44
            stream.seek(position)
            value = stream.read(1)
            stream.seek(position)
            stream.write(bytes([value[0] ^ 1]))
    result = run("get", profile, output)
    assert b"Recovered ciphertext with ECC" in result.stdout, result.stdout
    assert output.read_bytes() == ecc_input.read_bytes()
    run("get-version", object_id, digest, 123, 9000, output)
    assert output.read_bytes() == ecc_input.read_bytes()[123:9123]
    with stored.open("r+b") as stream:
        position = 288 + failure_limit * (4096 + 16 + 44) + 44
        stream.seek(position)
        value = stream.read(1)
        stream.seek(position)
        stream.write(bytes([value[0] ^ 1]))
    failure = run("get", profile, output, expected=1)
    assert b"ECC recovery failed" in failure.stderr, failure.stderr
    assert output.read_bytes() == ecc_input.read_bytes()[123:9123]

assert run("get", "legacy.bin", output, expected=1).stderr
assert (STORAGE / "legacy.bin").read_text() == "legacy data remains in the original directory\n"
legacy_client = os.environ.get("NASFS_LEGACY_CLIENT_BIN")
if legacy_client:
    result = subprocess.run([legacy_client, "get", name, output], capture_output=True,
                            timeout=15)
    assert result.returncode == 1 and b"Unsupported transfer format" in result.stderr, result.stderr
assert not list(CATALOG.glob(".attempt.*"))
print("Signed version PUT, verified range GET, conflict, cleanup and recovery checks passed.")
