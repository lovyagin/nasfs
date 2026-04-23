# NASFS

## Network Attached Storage File System

NASFS is a fast, lightweight and secure file system designed for networked storage devices and is intended to shift the load to some powerful server, allowing for example weak routers with OpenWRT firmware to be connected as storage devices.

## Prerequisites

- GCC or compatible C compiler
- GNU Autotools (autoconf, automake, libtool)
- POSIX-compatible operating system
- Pthreads library

## Building and Installation

### Using Autotools

1. Generate the configure script:
   ```
   ./autogen.sh
   ```

2. Make build directory and enter it:
   ```
   mkdir build
   cd build
   ```

3. Configure the build:
   ```
   ../configure
   ```

   Useful install options:
   ```
   ../configure --disable-systemd
   ../configure --with-systemdsystemunitdir=/lib/systemd/system
   ```

4. Build the project:
   ```
   make
   ```

5. Run the full test suite:
   ```
   make check
   ```

5. Install (requires root privileges):
   ```
   sudo make install
   ```

### Configuration

Configuration files are installed to `/etc/nasfs/` by default. The main server configuration file is `/etc/nasfs/nasfs.conf`.

The default PID file path used by the installed layouts is:
`/usr/local/var/run/nasfs/nasfs-server.pid`

The installation also provides:
- `nasfs_server`
- `nasfs_client`
- `nasfsctl`
- `nasfs.service` for `systemd`-based systems when `systemd` install support is enabled

### Using CMake

The CMake build supports the same main features as the autotools build:
- server and client binaries
- `nasfsctl`
- optional `systemd` unit installation
- unit tests
- end-to-end integration test

Example:

```
cmake -S . -B build-cmake
cmake --build build-cmake
ctest --test-dir build-cmake --output-on-failure
cmake --install build-cmake
```

Relevant CMake options:

```
-DNASFS_INSTALL_SYSTEMD=OFF
-DNASFS_SYSTEMD_UNIT_DIR=/lib/systemd/system
```

## Usage

### Starting the Server

After installation, you can control the server using the portable `nasfsctl` command:

```
nasfsctl start    # Start the server
nasfsctl stop     # Stop the server
nasfsctl restart  # Restart the server
nasfsctl status   # Check server status
```

On systems with `systemd`, you can also use:

```
sudo systemctl enable nasfs
sudo systemctl start nasfs
sudo systemctl status nasfs
```

### Connecting to the Server

The server listens on port 8080 by default (configurable in nasfs.conf).

The secure control channel negotiates algorithms in an SSH-like way:
- the client sends ordered KEX and cipher preference lists
- the server selects the first mutually supported suite allowed by `KexAlgorithms` and `CipherAlgorithms`
- the default control cipher is `xchacha20poly1305`

Client-side preferences can be overridden with:

```
NASFS_KEX_ALGORITHMS="Kyber512,ML-KEM-512" \
NASFS_CIPHER_ALGORITHMS="xchacha20poly1305" \
./client/nasfs_client put local.bin remote.bin
```

## Testing

`make check` runs:
- unit tests for handshake payload helpers
- unit tests for server config parsing
- the end-to-end PUT/GET integration test

To run the tests manually:

```
make check
```

## Development

For development purposes, you can configure with debugging enabled:

```
./configure --enable-debug
```

For more information on development, see the [development documentation](docs/development.md).
