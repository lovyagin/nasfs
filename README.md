# NASFS

NASFS is a network file storage prototype with a post-quantum, SSH-like
control-channel negotiation layer and client-side end-to-end file encryption (E2EE).
The server acts as a "dumb storage" node, having zero knowledge of the file contents.

Current protocol characteristics:
- TCP server/client built on `libuv`
- configurable KEX and control-channel cipher selection
- configurable authentication: password, PQ public key, or both
- SSH-like client preference lists with server-side allowlists
- post-quantum KEX via `liboqs`
- post-quantum signatures for public-key authentication via `liboqs`
- encrypted control channel via `libsodium`
- client-side zero-knowledge file encryption via `libsodium` (XSalsa20-Poly1305 + Argon2id)
- cryptographic protection against file truncation and block reordering

## Dependencies

Build dependencies:
- C11 compiler
- `cmake` or GNU autotools
- `pkg-config`
- `libuv`
- `liboqs`
- `libsodium`
- OpenSSL `libcrypto`

CI and linting also use:
- `clang-format`
- `clang-tidy`
- `shellcheck`

## Build

### Autotools

Generate build files:

```sh
./autogen.sh
```

Configure and build:

```sh
./configure
make -j"$(nproc)"
```

Useful options:

```sh
./configure --enable-debug
./configure --disable-systemd
./configure --with-systemdsystemunitdir=/lib/systemd/system
```

Run tests:

```sh
make check
```

Install:

```sh
sudo make install
```

### CMake

Configure and build:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Useful options:

```sh
-DNASFS_INSTALL_SYSTEMD=OFF
-DNASFS_SYSTEMD_UNIT_DIR=/lib/systemd/system
-DNASFS_ENABLE_SANITIZERS=ON
```

Run tests:

```sh
ctest --test-dir build --output-on-failure
```

Install:

```sh
sudo cmake --install build
```

For staged install verification:

```sh
cmake --install build --prefix "$PWD/install-root"
```

`make distclean` cleans Autotools outputs. The optional `./autoclean.sh`
removes generated source-tree bootstrap files and leaves runtime data and
separate build directories in place.

## Installed layout

Default install targets:
- binaries: `/usr/local/bin`
- config: `/usr/local/etc/nasfs/nasfs.conf`
- runtime directories:
  - `/usr/local/var/run/nasfs`
  - `/usr/local/var/log/nasfs`
- systemd unit: `/usr/local/lib/systemd/system/nasfs.service`

Installed commands:
- `nasfs_server`
- `nasfs_client`
- `nasfsctl`

Default PID file:

```text
/usr/local/var/run/nasfs/nasfs-server.pid
```

## Configuration

The server and client default to TCP port 5252. Set `Port` on the server
and `NASFS_SERVER_PORT` on the client to use another port. The installed
config enables public-key login. Password and PAKE login require an explicit,
nonempty `AuthPassword` and a corresponding `AuthMethods` entry.

The default server config is installed as:

```text
/usr/local/etc/nasfs/nasfs.conf
```

Without arguments, `nasfs_server` reads `nasfs.conf` in the working
directory. Run it from the CMake or Autotools build root, or from the
installed config directory. For a build-tree run, prepare the directories
in the generated config or point them at an existing test workspace. To
start the server from elsewhere, pass the config path explicitly. An
explicit path takes precedence.

Important options:
- `ListenAddr`
- `Port`
- `MaxConn`
- `ClientTimeout`
- `LogFile`
- `LogLevel`
- `DaemonMode`
- `PidFile`
- `StorageDir`
- `KexAlgorithms`
- `CipherAlgorithms`
- `AuthMethods`
- `AuthPassword`
- `AuthorizedKeysFile`
- `PubKeyAuthAlgorithms`

Example defaults:

```text
ListenAddr 0.0.0.0
Port 5252
LogFile /usr/local/var/log/nasfs/nasfs-server.log
PidFile /usr/local/var/run/nasfs/nasfs-server.pid
KexAlgorithms ML-KEM-512,Kyber512,ML-KEM-768,Kyber768
CipherAlgorithms xchacha20poly1305
AuthMethods password,publickey,password+publickey
AuthPassword change-me
AuthorizedKeysFile /usr/local/etc/nasfs/authorized_keys
PubKeyAuthAlgorithms ML-DSA-65,ML-DSA-44
```

## Negotiation model

The secure control channel works in an SSH-like way:
- client sends ordered KEX and cipher preference lists
- server intersects them with `KexAlgorithms` and `CipherAlgorithms`
- server selects the first mutually supported suite by client preference order
- server returns the negotiated suite and completes the secure channel setup

At the moment:
- KEX is negotiable
- control-channel cipher is negotiable
- user authentication method is selectable
- file payload encryption (E2EE) is fully supported and enabled via client-side keys

## Authentication

NASFS does not use `libssh`. Authentication is implemented in the NASFS
control protocol after the post-quantum KEX completes and after the control
channel is encrypted.

Supported methods:
- `password`
- `publickey`
- `password+publickey`

Public-key auth uses post-quantum signature algorithms from `liboqs`. The
default is `ML-DSA-65`; `Ed25519` is not used because it is not
post-quantum-resistant.

Generate a client identity and an `authorized_keys` file:

```sh
nasfs_client keygen ~/.nasfs/id_mldsa /usr/local/etc/nasfs/authorized_keys ML-DSA-65
```

The private key file is written in a NASFS-specific text format and should stay
client-side. The public file contains lines in this format:

```text
ML-DSA-65 <hex-encoded-public-key>
```

Password-only client auth:

```sh
NASFS_AUTH_METHOD=password \
NASFS_AUTH_USER=alice \
NASFS_AUTH_PASSWORD='change-me' \
nasfs_client put ./local.bin remote.bin
```

Public-key client auth:

```sh
NASFS_AUTH_METHOD=publickey \
NASFS_AUTH_USER=alice \
NASFS_AUTH_SIG_ALGORITHM=ML-DSA-65 \
NASFS_IDENTITY_FILE=~/.nasfs/id_mldsa \
nasfs_client get remote.bin ./local.bin
```

Password plus public key:

```sh
NASFS_AUTH_METHOD=password+publickey \
NASFS_AUTH_USER=alice \
NASFS_AUTH_PASSWORD='change-me' \
NASFS_AUTH_SIG_ALGORITHM=ML-DSA-65 \
NASFS_IDENTITY_FILE=~/.nasfs/id_mldsa \
nasfs_client put ./local.bin remote.bin
```

## Running

### Portable control script

Use `nasfsctl` for start/stop/status management:

```sh
nasfsctl start
nasfsctl stop
nasfsctl restart
nasfsctl status
```

The script uses:
- installed server binary
- installed config file
- PID file under `/usr/local/var/run/nasfs`
- log file under `/usr/local/var/log/nasfs`

### systemd

Both installers create the default storage directory under `<datadir>/nasfs/storage`.
If you change `StorageDir`, create the replacement directory and grant the
server account access before starting NASFS.

The unit embeds installation paths from the build configuration. For a
custom prefix, set it when configuring CMake or Autotools.

If installed with systemd support, run `sudo systemctl edit nasfs` and add
a service drop-in with the paths to your raw Ed25519 key files:

```ini
[Service]
Environment=NASFS_SERVER_SIGNING_SEED=/etc/nasfs/server.seed
Environment=NASFS_AUTHOR_PUBLIC_KEY=/etc/nasfs/author.pub
```

Keep the signing seed readable only by the service account. Configure
`StorageDir` and authentication in the installed `nasfs.conf`. For this unit,
keep `DaemonMode Yes` and match the config's `PidFile` to the unit's `PIDFile`.
The key paths above are examples.

```sh
sudo systemctl daemon-reload
sudo systemctl enable nasfs
sudo systemctl start nasfs
sudo systemctl status nasfs
```

Server staging files and the publication lock live in a private `.nasfs/`
directory inside `StorageDir`, on the same filesystem as the objects.
PUT and GET reserve that name and its case variants. At startup, NASFS
removes abandoned staging files when it can lock the service directory
exclusively. If another NASFS process is using the same
directory, cleanup waits for a later startup with no other NASFS process
running. On NFS mounts detected by Linux or macOS, and where exclusive
locking is unavailable, startup cleanup is skipped. On detected NFS
mounts, or if shared locking fails, the server uses `.nasfs/.nasfs-upload.unlocked.*` staging
names that are excluded from automatic cleanup. Remove abandoned files
with that prefix only after stopping all servers using the directory.
If cleanup cannot remove an orphan, the server logs a warning and continues
serving readable files. Stop all older NASFS processes sharing the directory
before upgrading.

### Privileged startup and PUT publication

For `nasfsctl` startup through sudo, provision the two absolute key paths
in the installed `nasfs.conf`:

```text
ServerSigningSeed /etc/nasfs/server.seed
AuthorPublicKey /etc/nasfs/author.pub
```

The configured paths take precedence over the corresponding environment
variables. Automatic sudo startup clears those variables. Administrators
must keep the installed executable, configuration, key files and their
parent directories under trusted ownership and protected from unprivileged
writes. Ordinary server startup still accepts the environment variables
when the paths are absent from the config.

PUT requires a storage directory owned by the server account, with no
group or other write permission. On macOS it also requires the directory
to have no extended ACL. NASFS supports replacement on local macOS
filesystems and on Linux ext2/3/4, XFS, Btrfs, tmpfs, OverlayFS and F2FS.
It serializes its publishers with `.nasfs/.nasfs-publish.lock` from the destination checks through
the atomic rename. Replacement requires a regular file owned by the
server account with owner write permission and effective write access.
On macOS, a target with an extended ACL is protected from replacement as
well. Stop all server instances before modifying storage or its permissions
with external tools, and keep the lock file in place. On other
filesystems, including NFS, PUT can atomically create a new name using a
hard link and fails if that name already exists.

The client and server count each successful socket read toward the idle
timeout, including reads that contain only part of a frame.

## Client usage

Upload:

```sh
nasfs_client put ./local.bin remote.bin
```

Download:

```sh
nasfs_client get remote.bin ./local.bin
```

Upload and Download with E2E Encryption:

```sh
NASFS_ENCRYPTION_KEY="super-secret-key" nasfs_client put ./local.bin encrypted_remote.bin
NASFS_ENCRYPTION_KEY="super-secret-key" nasfs_client get encrypted_remote.bin ./local_decrypted.bin
```

Keep a backup of `~/.nasfs/master.salt`. The first upload creates the salt.
`put` and `mput` derive the master key from the file encryption password
with Argon2id. Leave `NASFS_KDF` unset or set it to `argon2id`. Other
selections fail before the client connects.

For an existing file, use the original password, salt, and KDF. If an older
client uploaded the file with `NASFS_KDF=hkdf` or `NASFS_KDF=pbkdf2`, set the
same value for `get` or `mget`. This also applies to older NASLUKS owner
slots. The client stops before connecting when it cannot load or save the salt.

For a container written before record lengths were stored, start the server
with `BlockSize` set to the original upload's `NASFS_BLOCK_SIZE` and use
the original byte order. Verify the downloaded bytes against a trusted hash,
then re-upload under a separate name and verify a second download with the
current server settings before replacing the old object. New containers
record their block lengths and can be downloaded after a block size change.

Override client-side preference lists:

```sh
NASFS_KEX_ALGORITHMS="Kyber512,ML-KEM-512" \
NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
NASFS_AUTH_METHOD="password" \
NASFS_AUTH_USER="alice" \
NASFS_AUTH_PASSWORD="change-me" \
nasfs_client put ./local.bin remote.bin
```

## NASLUKS owner slot

New PUTs generate a random file key and wrap it in one NASLUKS owner slot
using XChaCha20-Poly1305. The wrapping key comes from the client master key
and per-file salt. Backup and recovery require the original encryption
password, client `master.salt`, and `NASFS_KDF`. Keep these on the client.
The login password belongs to a separate authentication flow.

Set `NASFS_AUTHOR_SIGNING_SEED` to a private 32-byte Ed25519 seed on the
uploading client. Independently install its raw public key as
`NASFS_AUTHOR_PUBLIC_KEY` on the server and downloading clients. Use a
separate key pair from the server identity. PUT and GET verify the manifest
before publishing. For an exact version, save the 64-digit manifest digest
reported after PUT and use it as `NASFS_EXPECTED_MANIFEST` for a single GET.

For migration of an unsigned container, explicitly set
`NASFS_ALLOW_UNSIGNED_READ=1` for the historical GET. Verify the resulting
plaintext independently, then upload it under a separate name and check
the new signed download before retiring the old object.

## Server identity

The server requires `NASFS_SERVER_SIGNING_SEED`, the path to a raw 32-byte
Ed25519 seed owned by the server process user with mode `0600`. Set the
variable in the server's process environment, including the service
environment when using a service manager.

Provision a seed and its matching public key using OpenSSL 3:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out server-key.pem
openssl pkey -in server-key.pem -outform DER | tail -c 32 > server.seed
openssl pkey -in server-key.pem -pubout -outform DER | tail -c 32 > server.pub
```

Keep the PEM private along with the seed. Deliver the raw public key to the
client over an independently trusted channel. For a server at
`192.0.2.10:5252`, install it as
`~/.nasfs/server-192.0.2.10-5252.pub` under the client account. To rotate
the identity, verify the replacement public key independently and atomically
replace the endpoint's pin. The CLI reads the pin on each invocation and
requires a valid signature and key-exchange confirmation before sending AUTH
or PAKE. Update client and server together. The handshake requires independent
cryptographic review before release.

The server requires a readable configuration and a writable configured log
file. It rejects a second process using the same PID file. `ClientTimeout`
sets the server's idle session timeout in seconds. Key generation creates
new destination files, so choose unused paths for a replacement key pair.

After forced process termination, a hidden `.nasfs/.nasfs-upload.*` or
`.nasfs-download.*` staging file may remain. Confirm that the process that
owned the file has stopped before removing it. The server rejects staging
names as remote object names. Root-level staging files from older versions
can be removed manually after all old server instances have stopped. Start a fresh transfer to recover; an incomplete
staging file carries no publication result.

If key generation is forcibly stopped between the two publications, the
private key may exist before its corresponding public file. A retry on
those paths preserves the existing private key and fails. To generate a
fresh pair, use two unused paths.

## Testing

The integration tests require Python 3.8 or later.

On Linux with a running systemd user manager, run the optional service test:

```sh
prefix=$(mktemp -d)
cmake -S . -B build-systemd -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_INSTALL_SYSCONFDIR=etc -DCMAKE_INSTALL_LOCALSTATEDIR=var \
    -DNASFS_INSTALL_SYSTEMD=ON
cmake --build build-systemd
cmake --install build-systemd
NASFS_TEST_INSTALL_PREFIX="$prefix" tests/test_systemd.sh
```

Autotools:

```sh
make check
```

CMake:

```sh
ctest --test-dir build --output-on-failure
```

Test suite contents:
- handshake unit test
- config parser unit test
- auth payload unit test
- file encryption unit test
- end-to-end `PUT/GET` integration test
- end-to-end file encryption integration test

The integration tests validate:
- server startup
- secure control-channel negotiation
- failed authentication rejection
- password and post-quantum public-key authentication
- cleartext upload/download integrity
- client-side key derivation (Argon2id)
- encrypted chunk processing and block substitution protection
- zero-knowledge encrypted upload/download integrity

## End-to-end benchmark

Run `tests/benchmark_e2e.sh` with Bash 4 or later and the CMake binaries in
`build/`, or set `NASFS_SERVER_BIN` and `NASFS_CLIENT_BIN`. The script creates
temporary server and author keys, pins its server key, and compares downloaded
bytes with the input. Each NASFS timing includes Argon2id master-key
derivation, connection setup, authentication, and transfer. The optional SFTP
comparison requires a trusted SSH host key and working batch authentication.

## Linting and CI

GitHub Actions currently runs:
- `clang-format`
- `clang-tidy`
- `shellcheck`
- autotools build/test/install checks
- CMake build/test/install checks
- sanitizer build with ASan/UBSan

Typical local lint commands:

```sh
git ls-files '*.c' '*.h' | xargs clang-format --dry-run --Werror
shellcheck autogen.sh autoclean.sh tests/test_end_to_end.sh
cmake -S . -B build-lint -G Ninja -DCMAKE_BUILD_TYPE=Release -DNASFS_INSTALL_SYSTEMD=OFF
git ls-files '*.c' | xargs clang-tidy -p build-lint --quiet --warnings-as-errors='*'
```
