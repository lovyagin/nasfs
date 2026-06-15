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

The default server config is installed as:

```text
/usr/local/etc/nasfs/nasfs.conf
```

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
AuthPassword nasfs
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

If installed with systemd support:

```sh
sudo systemctl enable nasfs
sudo systemctl start nasfs
sudo systemctl status nasfs
```

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

Override client-side preference lists:

```sh
NASFS_KEX_ALGORITHMS="Kyber512,ML-KEM-512" \
NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
NASFS_AUTH_METHOD="password" \
NASFS_AUTH_USER="alice" \
NASFS_AUTH_PASSWORD="change-me" \
nasfs_client put ./local.bin remote.bin
```

## Testing

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
