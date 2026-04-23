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

4. Build the project:
   ```
   make
   ```

5. Install (requires root privileges):
   ```
   sudo make install
   ```

### Configuration

Configuration files are installed to `/etc/nasfs/` by default. The main server configuration file is `/etc/nasfs/nasfs.conf`.

## Usage

### Starting the Server

After installation, you can control the server using the `nasfsctl` command:

```
nasfsctl start    # Start the server
nasfsctl stop     # Stop the server
nasfsctl restart  # Restart the server
nasfsctl status   # Check server status
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

To run the tests:

```
make check
```

## Development

For development purposes, you can configure with debugging enabled:

```
./configure --enable-debug
```

For more information on development, see the [development documentation](docs/development.md).
