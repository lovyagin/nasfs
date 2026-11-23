#!/usr/bin/env bash

# NASFS File Encryption Integration Test

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${NASFS_SERVER_BIN:-$ROOT_DIR/build/nasfs_server}"
CLIENT_BIN="${NASFS_CLIENT_BIN:-$ROOT_DIR/build/nasfs_client}"
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/integration_helpers.sh"
setup_integration

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Generate 512KB of test data
TEST_INPUT="$TEST_ROOT/plaintext.bin"
dd if=/dev/urandom of="$TEST_INPUT" bs=1k count=512 2>/dev/null
INPUT_HASH=$(hash_file "$TEST_INPUT")
printf "Created 512KB test file. Plaintext hash: %s\n" "$INPUT_HASH"

# Configure server
cat <<EOF > "$TEST_ROOT/server.conf"
ListenAddr 127.0.0.1
Port 0
MaxConn 10
BlockSize 4096
LogFile $LOG_DIR/server.log
LogLevel Debug
DaemonMode No
PidFile $LOG_DIR/server.pid
StorageDir $STORAGE_DIR
KexAlgorithms ML-KEM-512,Kyber512
CipherAlgorithms xchacha20poly1305
AuthMethods password,pake
AuthPassword super-secret
EOF

start_integration_server "$TEST_ROOT/server.conf"

# Fail closed before connecting when the salt cannot be loaded or saved.
transfer() {
    NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password \
        NASFS_AUTH_PASSWORD=super-secret "$CLIENT_BIN" "$@"
}
expect_salt_failure() {
    if transfer put "$TEST_INPUT" rejected.bin > "$LOG_DIR/salt_error.log" 2>&1; then
        return 1
    fi
    grep -Fq 'Cannot load or save ~/.nasfs/master.salt' "$LOG_DIR/salt_error.log"
    test ! -e "$STORAGE_DIR/rejected.bin"
}
export NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!"
salt="$HOME/.nasfs/master.salt"
blocked_home="$TEST_ROOT/blocked-home"
mkdir "$blocked_home"
touch "$blocked_home/.nasfs"
HOME="$blocked_home" expect_salt_failure
(umask 077; printf short > "$salt")
expect_salt_failure
test "$(cat "$salt")" = short
rm "$salt"

# Force a write error after the staging file has been opened.
python3 - "$CLIENT_BIN" "$TEST_INPUT" <<'PYTHON'
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys

signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
result = subprocess.run([sys.argv[1], "put", sys.argv[2], "rejected.bin"],
                        stderr=subprocess.PIPE, timeout=5, restore_signals=False)
assert result.returncode == 1, result.stderr
assert b"Cannot load or save ~/.nasfs/master.salt" in result.stderr, result.stderr
assert not list((Path(os.environ["HOME"]) / ".nasfs").glob("*master.salt*"))
PYTHON
test ! -e "$STORAGE_DIR/rejected.bin"

if transfer get rejected.bin "$TEST_ROOT/rejected-download" > "$LOG_DIR/salt_error.log" 2>&1; then
    exit 1
fi
grep -Fq 'Cannot load or save ~/.nasfs/master.salt' "$LOG_DIR/salt_error.log"
test ! -e "$salt"

# Simulate the disk state left after termination before publishing the salt.
(umask 077; printf partial > "$HOME/.nasfs/.master.salt.interrupted")
transfer put "$TEST_INPUT" concurrent-a.bin > "$LOG_DIR/concurrent-a.log" 2>&1 &
first_put=$!
transfer put "$TEST_INPUT" concurrent-b.bin > "$LOG_DIR/concurrent-b.log" 2>&1 &
second_put=$!
wait "$first_put"
wait "$second_put"
test "$(wc -c < "$salt")" -eq 16
pin="$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
mv "$pin" "$pin.saved"
if transfer get concurrent-a.bin "$TEST_ROOT/untrusted" > "$LOG_DIR/missing_pin.log" 2>&1; then
    exit 1
fi
grep -Fq 'Missing or invalid server pin' "$LOG_DIR/missing_pin.log"
(umask 077; dd if=/dev/zero of="$pin" bs=32 count=1 2>/dev/null)
if transfer get concurrent-a.bin "$TEST_ROOT/untrusted" > "$LOG_DIR/wrong_pin.log" 2>&1; then
    exit 1
fi
grep -Fq 'Server identity verification failed' "$LOG_DIR/wrong_pin.log"
test ! -e "$TEST_ROOT/untrusted"
mv "$pin.saved" "$pin"

for name in concurrent-a.bin concurrent-b.bin; do
    transfer get "$name" "$TEST_ROOT/$name" > "$LOG_DIR/concurrent-get.log" 2>&1
    cmp "$TEST_INPUT" "$TEST_ROOT/$name"
done

# Kill a real Linux client on both sides of the atomic salt link.
if [[ $(uname -s) == Linux ]]; then
    "${CC:-cc}" -shared -fPIC -Wall -Wextra -Werror \
        "$ROOT_DIR/tests/fault_injection.c" -ldl -o "$TEST_ROOT/fault_injection.so"
    NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password NASFS_AUTH_PASSWORD=super-secret \
        python3 - "$CLIENT_BIN" "$TEST_INPUT" "$TEST_ROOT" "$STORAGE_DIR" <<'PYTHON'
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

client, source, root, storage = sys.argv[1:]
root, source, storage = Path(root), Path(source), Path(storage)
libraries = subprocess.check_output(["ldd", client], text=True)
asan = re.search(r"libasan\S* => (\S+)", libraries)
preload = str(root / "fault_injection.so")
if asan:
    preload = f"{asan[1]}:{preload}"
pin_name = f"server-127.0.0.1-{os.environ['NASFS_SERVER_PORT']}.pub"
pin_source = Path(os.environ["HOME"]) / ".nasfs" / pin_name

for checkpoint in ("before", "after"):
    home = root / f"salt-crash-{checkpoint}"
    secrets = home / ".nasfs"
    secrets.mkdir(mode=0o700, parents=True)
    shutil.copy(pin_source, secrets / pin_name)
    salt = secrets / "master.salt"
    env = dict(os.environ, HOME=str(home))
    remote = f"salt-crash-{checkpoint}.bin"
    put = [client, "put", str(source), remote]
    result = subprocess.run(
        put,
        env=dict(env, LD_PRELOAD=preload, NASFS_TEST_SALT_CHECKPOINT=checkpoint),
        capture_output=True, timeout=10,
    )
    assert result.returncode == -signal.SIGKILL, result.stderr
    assert not (storage / remote).exists()
    assert len(list(secrets.glob(".master.salt.*"))) == 1
    if checkpoint == "before":
        assert not salt.exists()
        published_salt = None
    else:
        published_salt = salt.read_bytes()
        assert len(published_salt) == 16
    subprocess.run(put, env=env, check=True, capture_output=True, timeout=10)
    if published_salt is not None:
        assert salt.read_bytes() == published_salt
    output = home / "recovered.bin"
    subprocess.run([client, "get", remote, str(output)], env=env, check=True,
                   capture_output=True, timeout=10)
    assert output.read_bytes() == source.read_bytes()

# Exercise the normal libuv completion path and the pre-publication close.
remote = "concurrent-a.bin"
previous_object = (storage / remote).read_bytes()
read_source = root / "fault-source.bin"
read_source.write_bytes(b"Replacement that must not be published")
result = subprocess.run([client, "put", str(read_source), remote],
                        env=dict(os.environ, LD_PRELOAD=preload,
                                 NASFS_TEST_READ_FAILURE=read_source.name),
                        capture_output=True, timeout=10)
assert result.returncode == 1 and b"Read error: bad file descriptor" in result.stderr, result.stderr
assert (storage / remote).read_bytes() == previous_object

destination = root / "fault-destination.bin"
destination.write_bytes(b"Previous destination")
result = subprocess.run([client, "get", remote, str(destination)],
                        env=dict(os.environ, LD_PRELOAD=preload,
                                 NASFS_TEST_CLOSE_FAILURE=".nasfs-download."),
                        capture_output=True, timeout=10)
assert result.returncode == 1 and b"Local file close failed" in result.stderr, result.stderr
assert destination.read_bytes() == b"Previous destination"
assert not list(root.glob(".nasfs-download.*"))

# The file is visible immediately after rename, even if the process never
# reports success. A subsequent regular GET still reads the same bytes.
result = subprocess.run([client, "get", remote, str(destination)],
                        env=dict(os.environ, LD_PRELOAD=preload,
                                 NASFS_TEST_CRASH_AFTER_DOWNLOAD="1"),
                        capture_output=True, timeout=10)
assert result.returncode == -signal.SIGKILL, result.stderr
assert destination.read_bytes() == source.read_bytes()
assert not list(root.glob(".nasfs-download.*"))
subprocess.run([client, "get", remote, str(destination)], check=True,
               capture_output=True, timeout=10)
assert destination.read_bytes() == source.read_bytes()

# Fail fclose on the second key staging file after it has actually closed.
private, public = root / "fault-private.key", root / "fault-public.key"
result = subprocess.run([client, "keygen", str(private), str(public), "ML-DSA-65"],
                        env=dict(os.environ, LD_PRELOAD=preload,
                                 NASFS_TEST_FCLOSE_FAILURE=public.name),
                        capture_output=True, timeout=10)
assert result.returncode == 1 and b"Failed to save public key file" in result.stderr, result.stderr
assert not private.exists() and not public.exists()
assert not list(root.glob("*.nasfs-key.*"))

private, public = root / "crash-private.key", root / "crash-public.key"
keygen = [client, "keygen", str(private), str(public), "ML-DSA-65"]
result = subprocess.run(keygen,
                        env=dict(os.environ, LD_PRELOAD=preload,
                                 NASFS_TEST_CRASH_AFTER_KEY_LINK=str(private)),
                        capture_output=True, timeout=10)
assert result.returncode == -signal.SIGKILL, result.stderr
assert private.stat().st_mode & 0o777 == 0o600
private_bytes = private.read_bytes()
assert private_bytes.startswith(b"NASFS-MLDSA-PRIVATE-v1\n")
assert not public.exists()
assert len(list(root.glob("crash-*.nasfs-key.*"))) == 2
result = subprocess.run(keygen, capture_output=True, timeout=10)
assert result.returncode == 1 and b"Failed to publish private key file" in result.stderr
assert private.read_bytes() == private_bytes and not public.exists()
new_private, new_public = root / "recovered-private.key", root / "recovered-public.key"
subprocess.run([client, "keygen", str(new_private), str(new_public), "ML-DSA-65"],
               check=True, capture_output=True, timeout=10)
assert new_private.read_text().splitlines()[2] == new_public.read_text().split()[1]
PYTHON
fi

# Every file algorithm and KDF runs through the real CLI.
while read -r cipher hash kdf; do
    remote="profile-$hash.bin"
    NASFS_FILE_CIPHER="$cipher" NASFS_FILE_HASH="$hash" NASFS_KDF="$kdf" \
        transfer put "$TEST_INPUT" "$remote"
    NASFS_KDF="$kdf" transfer get "$remote" "$TEST_ROOT/$remote"
    cmp "$TEST_INPUT" "$TEST_ROOT/$remote"
done <<'PROFILES'
xsalsa20poly1305 blake2b argon2id
xchacha20poly1305 sha256 pbkdf2
aes256gcm crc32 hkdf
xsalsa20poly1305 adler32 argon2id
PROFILES
# Exercise the full Cartesian product on a nonempty fixture. The GET
# intentionally omits the cipher and hash settings used for PUT.
printf 'NASLUKS file profile matrix\n' > "$TEST_ROOT/profile-input.bin"
for cipher in xsalsa20poly1305 xchacha20poly1305 aes256gcm; do
    for hash in blake2b sha256 crc32 adler32; do
        for kdf in argon2id pbkdf2 hkdf; do
            remote="matrix-$cipher-$hash-$kdf.bin"
            NASFS_FILE_CIPHER="$cipher" NASFS_FILE_HASH="$hash" NASFS_KDF="$kdf" \
                transfer put "$TEST_ROOT/profile-input.bin" "$remote" \
                > "$LOG_DIR/matrix-put.log" 2>&1
            NASFS_KDF="$kdf" transfer get "$remote" "$TEST_ROOT/profile-output.bin" \
                > "$LOG_DIR/matrix-get.log" 2>&1
            cmp "$TEST_ROOT/profile-input.bin" "$TEST_ROOT/profile-output.bin"
        done
    done
done
for setting in NASFS_FILE_CIPHER NASFS_FILE_HASH NASFS_KDF NASFS_BLOCK_SIZE; do
    if NASFS_AUTH_PASSWORD=super-secret env "$setting=invalid" "$CLIENT_BIN" \
        put "$TEST_INPUT" invalid-profile.bin > "$LOG_DIR/invalid-profile.log" 2>&1; then
        exit 1
    fi
    grep -Fq "Invalid $setting" "$LOG_DIR/invalid-profile.log"
    test ! -e "$STORAGE_DIR/invalid-profile.bin"
done
if NASFS_KDF=argon2id transfer get profile-sha256.bin "$TEST_ROOT/profile-sha256.bin" \
    > "$LOG_DIR/wrong-kdf.log" 2>&1; then
    exit 1
fi
grep -Fq 'Cannot open NASLUKS owner slot' "$LOG_DIR/wrong-kdf.log"
cmp "$TEST_INPUT" "$TEST_ROOT/profile-sha256.bin"

# Test 1: Upload with encryption enabled
printf '%b%s%b\n' "$YELLOW" "1. Uploading file with encryption enabled..." "$NC"
export NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!"

if ! env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="e2e" \
    NASFS_AUTH_PASSWORD="super-secret" \
    NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!" \
    "$CLIENT_BIN" put "$TEST_INPUT" "encrypted_remote.bin" > "$LOG_DIR/client_put.log" 2>&1; then
  printf '%b%s%b\n' "$RED" "FAIL: Client PUT command failed." "$NC"
  cat "$LOG_DIR/client_put.log"
  exit 1
fi

# Check if file exists in server storage
SERVER_STORED_FILE="$STORAGE_DIR/encrypted_remote.bin"
if [ ! -f "$SERVER_STORED_FILE" ]; then
    printf '%b%s%b\n' "$RED" "FAIL: Stored file not found on server!" "$NC"
    cat "$LOG_DIR/client_put.log"
    exit 1
fi

STORED_HASH=$(hash_file "$SERVER_STORED_FILE")
printf "Server stored file hash: %s\n" "$STORED_HASH"

if [ "$INPUT_HASH" == "$STORED_HASH" ]; then
    printf '%b%s%b\n' "$RED" "FAIL: Stored file is NOT encrypted! It matches the plaintext hash." "$NC"
    exit 1
fi
printf '%b%s%b\n' "$GREEN" "Success: Stored file is encrypted and does not match plaintext hash." "$NC"

# Test 2: Download and decrypt with the correct key
printf '%b%s%b\n' "$YELLOW" "2. Downloading and decrypting file with the CORRECT key..." "$NC"
TEST_OUTPUT_CORRECT="$TEST_ROOT/decrypted_correct.bin"

if ! env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="e2e" \
    NASFS_AUTH_PASSWORD="super-secret" \
    NASFS_ENCRYPTION_KEY="my-secret-encryption-password-123!" \
    "$CLIENT_BIN" get "encrypted_remote.bin" "$TEST_OUTPUT_CORRECT" > "$LOG_DIR/client_get_correct.log" 2>&1; then
  printf '%b%s%b\n' "$RED" "FAIL: Client GET (correct key) command failed." "$NC"
  cat "$LOG_DIR/client_get_correct.log"
  exit 1
fi

CORRECT_HASH=$(hash_file "$TEST_OUTPUT_CORRECT")
printf "Decrypted file hash: %s\n" "$CORRECT_HASH"

if [ "$INPUT_HASH" != "$CORRECT_HASH" ]; then
    printf '%b%s%b\n' "$RED" "FAIL: Decrypted file does not match original file!" "$NC"
    exit 1
fi
printf '%b%s%b\n' "$GREEN" "Success: Decrypted file matches the original file exactly!" "$NC"

# Test 3: Download and decrypt with an INCORRECT key
printf '%b%s%b\n' "$YELLOW" "3. Downloading and decrypting with an INCORRECT key (should fail)..." "$NC"
TEST_OUTPUT_INCORRECT="$TEST_ROOT/decrypted_incorrect.bin"
printf 'Keep the previous file.\n' > "$TEST_OUTPUT_INCORRECT"
PREVIOUS_HASH=$(hash_file "$TEST_OUTPUT_INCORRECT")

if env NASFS_KEX_ALGORITHMS="ML-KEM-512" \
    NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
    NASFS_AUTH_METHOD="password" \
    NASFS_AUTH_USER="e2e" \
    NASFS_AUTH_PASSWORD="super-secret" \
    NASFS_ENCRYPTION_KEY="wrong-password-here!!!" \
    "$CLIENT_BIN" get "encrypted_remote.bin" "$TEST_OUTPUT_INCORRECT" > "$LOG_DIR/client_get_incorrect.log" 2>&1; then
    printf '%b%s%b\n' "$RED" "FAIL: Client get command unexpectedly succeeded with a wrong key!" "$NC"
    exit 1
fi

grep -Fq "Cannot open NASLUKS owner slot" "$LOG_DIR/client_get_incorrect.log"
test "$(hash_file "$TEST_OUTPUT_INCORRECT")" = "$PREVIOUS_HASH"
if compgen -G "$TEST_ROOT/.nasfs-download.*" > /dev/null; then
    printf "Temporary download was not removed.\n" >&2
    exit 1
fi
test "$(hash_file "$SERVER_STORED_FILE")" = "$STORED_HASH"

printf '%b%s%b\n' "$GREEN" "Success: Decryption failed as expected when using an incorrect key." "$NC"

# The server's private identity material cannot substitute for the owner
# secret, even when the client is given the original master salt.
server_seed_hex=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_bytes().hex())' \
    "$NASFS_SERVER_SIGNING_SEED")
if NASFS_ENCRYPTION_KEY="$server_seed_hex" \
    transfer get encrypted_remote.bin "$TEST_OUTPUT_INCORRECT" > "$LOG_DIR/server_secret.log" 2>&1; then
    exit 1
fi
grep -Fq 'Cannot open NASLUKS owner slot' "$LOG_DIR/server_secret.log"
test "$(hash_file "$TEST_OUTPUT_INCORRECT")" = "$PREVIOUS_HASH"

# A short local write must leave an existing destination untouched.
NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password NASFS_AUTH_PASSWORD=super-secret \
    python3 - "$CLIENT_BIN" "$TEST_OUTPUT_INCORRECT" <<'PYTHON'
from pathlib import Path
import resource
import signal
import subprocess
import sys

client, output = sys.argv[1:]
destination = Path(output)
previous = destination.read_bytes()

def limit_file_size():
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))

result = subprocess.run([client, "get", "encrypted_remote.bin", output],
                        capture_output=True, timeout=10, preexec_fn=limit_file_size)
assert result.returncode == 1, result.stderr
assert b"Failed to write downloaded data: short write" in result.stderr, result.stderr
assert destination.read_bytes() == previous
assert not list(destination.parent.glob(".nasfs-download.*"))
PYTHON

# Write with 4 KiB records, then read both formats with the configured
# original block size for the older container.
NASFS_BLOCK_SIZE=4096 transfer put "$TEST_INPUT" records.bin
python3 - "$ROOT_DIR/tests/fixtures/implicit-4096.b64" \
    "$STORAGE_DIR/implicit.bin" "$TEST_ROOT/legacy-expected.bin" <<'PYTHON'
import base64
from pathlib import Path
import sys

fixture, stored, expected = map(Path, sys.argv[1:])
stored.write_bytes(base64.b64decode(fixture.read_bytes()))
expected.write_bytes(b"A" * 4096 + b"nasfs-legacy\n")
PYTHON
legacy_home="$TEST_ROOT/legacy-home"
(umask 077; mkdir -p "$legacy_home/.nasfs"; printf 'nasfs-test-salt!' > "$legacy_home/.nasfs/master.salt")
cp "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub" "$legacy_home/.nasfs/"
if HOME="$legacy_home" NASFS_KDF=pbkdf2 transfer get implicit.bin "$TEST_ROOT/implicit.bin" > "$LOG_DIR/unsigned.log" 2>&1; then
    exit 1
fi
grep -Fq 'File manifest missing or invalid' "$LOG_DIR/unsigned.log"
test ! -e "$TEST_ROOT/implicit.bin"
HOME="$legacy_home" NASFS_KDF=pbkdf2 NASFS_ALLOW_UNSIGNED_READ=1 \
    transfer get implicit.bin "$TEST_ROOT/implicit.bin"
cmp "$TEST_ROOT/legacy-expected.bin" "$TEST_ROOT/implicit.bin"

kill "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=
rm "$LOG_DIR/server.log"
sed 's/^BlockSize 4096$/BlockSize 65536/' "$TEST_ROOT/server.conf" \
    > "$TEST_ROOT/server-restarted.conf"
start_integration_server "$TEST_ROOT/server-restarted.conf"
NASFS_BLOCK_SIZE=131072 transfer get records.bin "$TEST_ROOT/records.bin"
cmp "$TEST_INPUT" "$TEST_ROOT/records.bin"

# A wrong author cannot replace a published file.
before=$(hash_file "$STORAGE_DIR/records.bin")
if NASFS_AUTHOR_SIGNING_SEED="$NASFS_SERVER_SIGNING_SEED" \
    transfer put "$TEST_INPUT" records.bin > "$LOG_DIR/wrong_author.log" 2>&1; then
    exit 1
fi
test "$(hash_file "$STORAGE_DIR/records.bin")" = "$before"

# Verify the published version and reject a different expected version.
version=$(sed -n 's/^Upload published. Manifest digest: //p' "$LOG_DIR/client_put.log")
NASFS_EXPECTED_MANIFEST="$version" transfer get encrypted_remote.bin "$TEST_ROOT/versioned.bin"
cmp "$TEST_INPUT" "$TEST_ROOT/versioned.bin"
if NASFS_EXPECTED_MANIFEST="$(printf '%064d' 0)" \
    transfer get encrypted_remote.bin "$TEST_ROOT/versioned.bin" > "$LOG_DIR/version.log" 2>&1; then
    exit 1
fi
grep -Fq 'Unexpected file manifest version' "$LOG_DIR/version.log"
cmp "$TEST_INPUT" "$TEST_ROOT/versioned.bin"

# Corrupt the owner slot while preserving the records and manifest.
python3 - "$STORAGE_DIR/records.bin" "$STORAGE_DIR/damaged-slot.bin" <<'PYTHON'
from pathlib import Path
import sys
data = bytearray(Path(sys.argv[1]).read_bytes())
assert data[24] & 0x20
data[26] ^= 1
Path(sys.argv[2]).write_bytes(data)
PYTHON
if transfer get damaged-slot.bin "$TEST_ROOT/records.bin" > "$LOG_DIR/slot.log" 2>&1; then
    exit 1
fi
grep -Fq 'Cannot open NASLUKS owner slot' "$LOG_DIR/slot.log"
cmp "$TEST_INPUT" "$TEST_ROOT/records.bin"

# Corrupt only the manifest while preserving all ciphertext bytes.
python3 - "$STORAGE_DIR/records.bin" <<'PYTHON'
from pathlib import Path
import sys
path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
data[-1] ^= 1
path.write_bytes(data)
PYTHON
if transfer get records.bin "$TEST_ROOT/records.bin" > "$LOG_DIR/manifest.log" 2>&1; then
    exit 1
fi
grep -Fq 'File manifest missing or invalid' "$LOG_DIR/manifest.log"
cmp "$TEST_INPUT" "$TEST_ROOT/records.bin"

# Damaged records and a valid container for a different object must never
# replace a local destination. Keep the requested remote name constant.
python3 - "$STORAGE_DIR" "$TEST_ROOT" <<'PYTHON'
from pathlib import Path
import sys

storage, root = map(Path, sys.argv[1:])
original = (storage / "encrypted_remote.bin").read_bytes()
other = (storage / "profile-blake2b.bin").read_bytes()

def records(container):
    assert container[24] & 0xe0 == 0xe0
    cursor = 26 + 72
    output = []
    while True:
        end = cursor + 4
        size = int.from_bytes(container[cursor:end], "big")
        if size == 0:
            assert len(container) - cursor == 4 + 96
            return output, container[cursor:]
        output.append(container[cursor:end + size])
        cursor = end + size

blocks, trailer = records(original)
foreign_blocks, _ = records(other)
assert len(blocks) >= 3
variants = {
    "missing-record": blocks[:-1],
    "repeated-record": [blocks[0], blocks[0], *blocks[1:]],
    "reordered-records": [blocks[1], blocks[0], *blocks[2:]],
    "mixed-records": [foreign_blocks[0], *blocks[1:]],
}
for name, variant in variants.items():
    (root / name).write_bytes(original[:26 + 72] + b"".join(variant) + trailer)
(root / "foreign-object").write_bytes(other)
(root / "original-container").write_bytes(original)
PYTHON
printf 'Keep the previous destination\n' > "$TEST_ROOT/record-destination"
cp "$TEST_ROOT/record-destination" "$TEST_ROOT/record-expected"
while IFS=: read -r variant expected; do
    cp "$TEST_ROOT/$variant" "$STORAGE_DIR/record-variant.tmp"
    mv "$STORAGE_DIR/record-variant.tmp" "$SERVER_STORED_FILE"
    if transfer get encrypted_remote.bin "$TEST_ROOT/record-destination" \
        > "$LOG_DIR/$variant.log" 2>&1; then
        printf 'GET accepted damaged container %s\n' "$variant" >&2
        exit 1
    fi
    grep -Fq "$expected" "$LOG_DIR/$variant.log"
    cmp "$TEST_ROOT/record-expected" "$TEST_ROOT/record-destination"
    test -z "$(find "$TEST_ROOT" -maxdepth 1 -name '.nasfs-download.*' -print)"
done <<'VARIANTS'
missing-record:Integrity error
repeated-record:Decryption failed
reordered-records:Decryption failed
mixed-records:Decryption failed
foreign-object:File manifest missing or invalid
VARIANTS
mv "$TEST_ROOT/original-container" "$SERVER_STORED_FILE"
transfer get encrypted_remote.bin "$TEST_ROOT/record-destination"
cmp "$TEST_INPUT" "$TEST_ROOT/record-destination"

# Missing bytes in a record must preserve an existing download destination.
dd if="$STORAGE_DIR/records.bin" of="$STORAGE_DIR/truncated.bin" bs=1 count=256 2>/dev/null
printf 'Previous destination\n' > "$TEST_ROOT/keep.bin"
cp "$TEST_ROOT/keep.bin" "$TEST_ROOT/expected-keep"
if transfer get truncated.bin "$TEST_ROOT/keep.bin" > "$LOG_DIR/truncated.log" 2>&1; then
    printf 'GET unexpectedly accepted an incomplete record.\n' >&2
    exit 1
fi
cmp "$TEST_ROOT/expected-keep" "$TEST_ROOT/keep.bin"
test -z "$(find "$TEST_ROOT" -maxdepth 1 -name '.nasfs-download.*' -print)"

# Exercise cancellation, loss of the final PUT response and server SIGINT.
NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password NASFS_AUTH_PASSWORD=super-secret \
    python3 "$ROOT_DIR/tests/test_transfer_recovery.py" "$CLIENT_BIN" "$TEST_ROOT" \
        "$STORAGE_DIR" "$TEST_INPUT" "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=
rm "$LOG_DIR/server.log"
start_integration_server "$TEST_ROOT/server-restarted.conf"
transfer get encrypted_remote.bin "$TEST_ROOT/server-recovery.bin"
cmp "$TEST_INPUT" "$TEST_ROOT/server-recovery.bin"

crash_server_during_put() {
    local checkpoint=$1 wait_status=0
    NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password NASFS_AUTH_PASSWORD=super-secret \
        python3 "$ROOT_DIR/tests/test_transfer_recovery.py" "$CLIENT_BIN" "$TEST_ROOT" \
            "$STORAGE_DIR" "$TEST_INPUT" "$SERVER_PID" "$checkpoint"
    wait "$SERVER_PID" 2>/dev/null || wait_status=$?
    test "$wait_status" -eq 137
    SERVER_PID=
    rm "$LOG_DIR/server.log"
    start_integration_server "$TEST_ROOT/server-restarted.conf"
    transfer get encrypted_remote.bin "$TEST_ROOT/crash-recovery.bin"
}

crash_server_during_put crash-before
cmp "$TEST_INPUT" "$TEST_ROOT/crash-recovery.bin"
# Orphaned staging files are excluded from the public object namespace.
orphan=$(find "$STORAGE_DIR" -maxdepth 1 -name '.nasfs-upload.*' -print)
test -f "$orphan"
if transfer get "$(basename "$orphan")" "$TEST_ROOT/unpublished.bin" \
    > "$LOG_DIR/orphan_get.log" 2>&1; then
    exit 1
fi
grep -Fq 'Invalid file name' "$LOG_DIR/orphan_get.log"
test ! -e "$TEST_ROOT/unpublished.bin"
rm "$orphan"

crash_server_during_put crash-after
cmp "$TEST_ROOT/replacement.bin" "$TEST_ROOT/crash-recovery.bin"
transfer put "$TEST_INPUT" encrypted_remote.bin

# Change the actual server key on the same address and port.
original_port=$NASFS_SERVER_PORT
kill "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=
rm "$LOG_DIR/server.log"
sed "s/^Port 0$/Port $original_port/" "$TEST_ROOT/server-restarted.conf" \
    > "$TEST_ROOT/server-rotated.conf"
(
    umask 077
    openssl genpkey -algorithm ED25519 -out "$TEST_ROOT/rotated-key.pem"
    openssl pkey -in "$TEST_ROOT/rotated-key.pem" -outform DER | tail -c 32 > "$NASFS_SERVER_SIGNING_SEED"
    openssl pkey -in "$TEST_ROOT/rotated-key.pem" -pubout -outform DER | tail -c 32 > "$TEST_ROOT/rotated.pub"
)
start_integration_server "$TEST_ROOT/server-rotated.conf"
if transfer get encrypted_remote.bin "$TEST_ROOT/rotated.bin" > "$LOG_DIR/rotation_pending.log" 2>&1; then
    exit 1
fi
grep -Fq 'Server identity verification failed' "$LOG_DIR/rotation_pending.log"
if grep -Fq ' authenticated with ' "$LOG_DIR/server.log"; then
    printf 'Client authenticated before accepting the server key.\n' >&2
    exit 1
fi
pin="$HOME/.nasfs/server-127.0.0.1-$original_port.pub"
cp "$TEST_ROOT/rotated.pub" "$pin.next"
mv "$pin.next" "$pin"
transfer get encrypted_remote.bin "$TEST_ROOT/rotated.bin"
cmp "$TEST_INPUT" "$TEST_ROOT/rotated.bin"

# A short server write must preserve the previous published container.
kill -TERM "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=
rm "$LOG_DIR/server.log"
NASFS_TEST_REAL_SERVER="$(cd "$(dirname "$SERVER_BIN")" && pwd)/$(basename "$SERVER_BIN")"
export NASFS_TEST_REAL_SERVER
cat > "$TEST_ROOT/limited-server" <<'PYTHON'
#!/usr/bin/env python3
import os
import resource
import signal
import sys

signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))
os.execv(os.environ["NASFS_TEST_REAL_SERVER"],
         [os.environ["NASFS_TEST_REAL_SERVER"], *sys.argv[1:]])
PYTHON
chmod +x "$TEST_ROOT/limited-server"
SERVER_BIN="$TEST_ROOT/limited-server" start_integration_server "$TEST_ROOT/server-restarted.conf"
# The server rotated earlier in this test. Provision its public key at the
# temporary endpoint before connecting.
cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
before=$(hash_file "$SERVER_STORED_FILE")
if transfer put "$TEST_INPUT" encrypted_remote.bin > "$LOG_DIR/server_short_write.log" 2>&1; then
    exit 1
fi
grep -Fq 'short write' "$LOG_DIR/server.log"
test "$(hash_file "$SERVER_STORED_FILE")" = "$before"
deadline=$((SECONDS + 5))
while compgen -G "$STORAGE_DIR/.nasfs-upload.*" >/dev/null; do
    test "$SECONDS" -lt "$deadline"
    sleep 0.02
done

if [[ $(uname -s) == Linux ]]; then
    kill -TERM "$SERVER_PID"
    wait "$SERVER_PID"
    SERVER_PID=
    rm "$LOG_DIR/server.log"
    cat > "$TEST_ROOT/fault-server" <<'PYTHON'
#!/usr/bin/env python3
import os
from pathlib import Path
import re
import subprocess
import sys

server = os.environ["NASFS_TEST_REAL_SERVER"]
hook = Path(__file__).parent / "fault_injection.so"
asan = re.search(r"libasan\S* => (\S+)", subprocess.check_output(["ldd", server], text=True))
preload = f"{asan[1]}:{hook}" if asan else str(hook)
env = dict(os.environ, LD_PRELOAD=preload)
if not any(name in env for name in ("NASFS_TEST_DELAY_WRITES",
                                    "NASFS_TEST_BLOCK_WRITES", "NASFS_TEST_OPEN_GATE",
                                    "NASFS_TEST_READ_GATE", "NASFS_TEST_RENAME_GATE")):
    env.update(NASFS_TEST_READ_FAILURE="encrypted_remote.bin",
               NASFS_TEST_CLOSE_FAILURE=".nasfs-upload.")
os.execve(server, [server, *sys.argv[1:]], env)
PYTHON
    chmod +x "$TEST_ROOT/fault-server"
    SERVER_BIN="$TEST_ROOT/fault-server" start_integration_server "$TEST_ROOT/server-restarted.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    if transfer get encrypted_remote.bin "$TEST_ROOT/keep.bin" > "$LOG_DIR/server_read.log" 2>&1; then
        exit 1
    fi
    grep -Fq 'Header read failed' "$LOG_DIR/server_read.log"
    cmp "$TEST_ROOT/expected-keep" "$TEST_ROOT/keep.bin"
    if transfer put "$TEST_INPUT" encrypted_remote.bin > "$LOG_DIR/server_close.log" 2>&1; then
        exit 1
    fi
    grep -Fq 'File close failed' "$LOG_DIR/server.log"
    grep -Fq 'Server could not publish' "$LOG_DIR/server_close.log"
    test "$(hash_file "$SERVER_STORED_FILE")" = "$before"
    test -z "$(find "$STORAGE_DIR" -maxdepth 1 -name '.nasfs-upload.*' -print)"

    kill -TERM "$SERVER_PID"
    wait "$SERVER_PID"
    SERVER_PID=
    rm "$LOG_DIR/server.log"
    NASFS_TEST_DELAY_WRITES=.nasfs-upload. NASFS_TEST_WRITE_GATE="$TEST_ROOT/release-writes" \
        SERVER_BIN="$TEST_ROOT/fault-server" start_integration_server "$TEST_ROOT/server-restarted.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    NASFS_BLOCK_SIZE=4096 NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password \
        NASFS_AUTH_PASSWORD=super-secret python3 "$ROOT_DIR/tests/test_transfer_recovery.py" \
        "$CLIENT_BIN" "$TEST_ROOT" "$STORAGE_DIR" "$TEST_INPUT" "$SERVER_PID" cancel-full-queue
    NASFS_BLOCK_SIZE=4096 transfer put "$TEST_INPUT" queue-test.bin \
        > "$LOG_DIR/queue-put.log" 2>&1
    peak=$(sed -n 's/^Test fixture pending writes: //p' "$LOG_DIR/server_stdout.log" | tail -n 1)
    test "$peak" = 4
    transfer get queue-test.bin "$TEST_ROOT/queue-test.bin" > "$LOG_DIR/queue-get.log" 2>&1
    cmp "$TEST_INPUT" "$TEST_ROOT/queue-test.bin"

    kill -TERM "$SERVER_PID"
    wait "$SERVER_PID"
    SERVER_PID=
    rm "$LOG_DIR/server.log"
    UV_USE_IO_URING=0 UV_THREADPOOL_SIZE=4 NASFS_TEST_BLOCK_WRITES=.nasfs-upload. \
        NASFS_TEST_BLOCK_WRITE_GATE="$TEST_ROOT/release-blocked-writes" \
        SERVER_BIN="$TEST_ROOT/fault-server" start_integration_server "$TEST_ROOT/server-restarted.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    NASFS_BLOCK_SIZE=4096 NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password \
        NASFS_AUTH_PASSWORD=super-secret python3 "$ROOT_DIR/tests/test_transfer_recovery.py" \
        "$CLIENT_BIN" "$TEST_ROOT" "$STORAGE_DIR" "$TEST_INPUT" "$SERVER_PID" stop-full-queue
    wait "$SERVER_PID"
    SERVER_PID=
    test ! -e "$LOG_DIR/server.pid"
    rm "$LOG_DIR/server.log"
    start_integration_server "$TEST_ROOT/server-restarted.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    transfer get encrypted_remote.bin "$TEST_ROOT/queue-stop-recovered.bin"
    cmp "$TEST_INPUT" "$TEST_ROOT/queue-stop-recovered.bin"

    kill -TERM "$SERVER_PID"
    wait "$SERVER_PID"
    SERVER_PID=
    rm "$LOG_DIR/server.log" "$TEST_ROOT/release-blocked-writes"
    sed '/^ClientTimeout /d' "$TEST_ROOT/server-restarted.conf" > "$TEST_ROOT/timeout.conf"
    printf 'ClientTimeout 2\n' >> "$TEST_ROOT/timeout.conf"
    UV_USE_IO_URING=0 UV_THREADPOOL_SIZE=4 NASFS_TEST_BLOCK_WRITES=.nasfs-upload. \
        NASFS_TEST_BLOCK_WRITE_GATE="$TEST_ROOT/release-blocked-writes" \
        SERVER_BIN="$TEST_ROOT/fault-server" start_integration_server "$TEST_ROOT/timeout.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    NASFS_BLOCK_SIZE=4096 NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password \
        NASFS_AUTH_PASSWORD=super-secret python3 "$ROOT_DIR/tests/test_transfer_recovery.py" \
        "$CLIENT_BIN" "$TEST_ROOT" "$STORAGE_DIR" "$TEST_INPUT" "$SERVER_PID" timeout-full-queue
    transfer get encrypted_remote.bin "$TEST_ROOT/queue-timeout-recovered.bin"
    cmp "$TEST_INPUT" "$TEST_ROOT/queue-timeout-recovered.bin"

    kill -TERM "$SERVER_PID"
    wait "$SERVER_PID"
    SERVER_PID=
    rm "$LOG_DIR/server.log"
    NASFS_TEST_OPEN_GATE="$TEST_ROOT/release-open" \
        SERVER_BIN="$TEST_ROOT/fault-server" start_integration_server "$TEST_ROOT/server-restarted.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password NASFS_AUTH_PASSWORD=super-secret \
        python3 "$ROOT_DIR/tests/test_transfer_recovery.py" "$CLIENT_BIN" "$TEST_ROOT" \
        "$STORAGE_DIR" "$TEST_INPUT" "$SERVER_PID" stop-during-open
    wait "$SERVER_PID"
    SERVER_PID=
    test ! -e "$LOG_DIR/server.pid"
    test -z "$(find "$STORAGE_DIR" -maxdepth 1 -name '.nasfs-upload.*' -print)"
    test "$(hash_file "$SERVER_STORED_FILE")" = "$before"

    rm "$LOG_DIR/server.log"
    UV_USE_IO_URING=0 NASFS_TEST_BLOCK_READS=encrypted_remote.bin \
        NASFS_TEST_READ_GATE="$TEST_ROOT/release-read" \
        SERVER_BIN="$TEST_ROOT/fault-server" start_integration_server "$TEST_ROOT/server-restarted.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password NASFS_AUTH_PASSWORD=super-secret \
        python3 "$ROOT_DIR/tests/test_transfer_recovery.py" "$CLIENT_BIN" "$TEST_ROOT" \
        "$STORAGE_DIR" "$TEST_INPUT" "$SERVER_PID" stop-during-read
    wait "$SERVER_PID"
    SERVER_PID=
    test ! -e "$LOG_DIR/server.pid"
    rm "$LOG_DIR/server.log"
    start_integration_server "$TEST_ROOT/server-restarted.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    transfer get encrypted_remote.bin "$TEST_ROOT/read-stop-recovered.bin"
    cmp "$TEST_INPUT" "$TEST_ROOT/read-stop-recovered.bin"

    kill -TERM "$SERVER_PID"
    wait "$SERVER_PID"
    SERVER_PID=
    rm "$LOG_DIR/server.log"
    NASFS_TEST_RENAME_GATE="$TEST_ROOT/release-rename" SERVER_BIN="$TEST_ROOT/fault-server" \
        start_integration_server "$TEST_ROOT/server-restarted.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    NASFS_KEX_ALGORITHMS=ML-KEM-512 NASFS_AUTH_METHOD=password NASFS_AUTH_PASSWORD=super-secret \
        python3 "$ROOT_DIR/tests/test_transfer_recovery.py" "$CLIENT_BIN" "$TEST_ROOT" \
        "$STORAGE_DIR" "$TEST_INPUT" "$SERVER_PID" stop-during-publication
    wait "$SERVER_PID"
    SERVER_PID=
    test ! -e "$LOG_DIR/server.pid"
    rm "$LOG_DIR/server.log"
    start_integration_server "$TEST_ROOT/server-restarted.conf"
    cp "$TEST_ROOT/rotated.pub" "$HOME/.nasfs/server-127.0.0.1-$NASFS_SERVER_PORT.pub"
    transfer get encrypted_remote.bin "$TEST_ROOT/rename-stop-recovered.bin"
    cmp "$TEST_ROOT/replacement.bin" "$TEST_ROOT/rename-stop-recovered.bin"
fi

printf '%b%s%b\n' "$GREEN" "==============================================" "$NC"
printf '%b%s%b\n' "$GREEN" "    ALL FILE ENCRYPTION TESTS PASSED!         " "$NC"
printf '%b%s%b\n' "$GREEN" "==============================================" "$NC"
