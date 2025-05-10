# NASFS Development Guide

## Project Overview

NASFS (Network Attached Storage File System) is designed to provide efficient and reliable file system operations over a network. This guide covers development practices, build system usage, and contribution workflows.

## Project structure
See [structure.md](structure.md)

## Development Environment Setup

### Prerequisites

- C compiler (GCC 14 recommended)
- GNU Autotools (autoconf, automake, libtool)
- POSIX-compatible operating system
- Development libraries:
  - POSIX threads

### Initial Setup

1. Clone the repository:
   ```
   git clone <repository-url>
   cd nasfs
   ```

2. Bootstrap the build system:
   ```
   ./autogen.sh
   ```

3. Make build directory
   ```
   mkdir build
   cd build
   ```

3. Configure for development:
   ```
   ../configure --enable-debug
   ```

4. Generate a compile database for clangd support if you need:
   ```
   make compile_commands.json
   ```

5. Build the project:
   ```
   make
   ```

## Build System

NASFS uses GNU Autotools (autoconf, automake) for its build system.

### Key Files

- `configure.ac`: Main autoconf configuration
- `Makefile.am`: Top-level automake configuration
- `server/Makefile.am`: Server component build rules
- `tests/Makefile.am`: Test suite build rules

### Common Build Tasks

```
# Full rebuild from scratch
./autogen.sh && ./configure && make

# Build with debug symbols
./configure --enable-debug && make

# Run all tests
make check

# Install the software
sudo make install

# Generate a distribution tarball
make dist
```

## Coding Standards

NASFS follows the [GNU C coding style](https://www.gnu.org/prep/standards/standards.html) with some modifications:

- Use 2-space indentation (as specified in `.clang-format`)
- Follow function naming convention: `lowercase_with_underscores()`
- Include thorough error handling and logging
- Document functions with comments explaining purpose, parameters, and return values

### Code Formatting

The project uses clang-format for consistent formatting:

```
clang-format -i file.c
```

A `.clang-format` file is provided in the repository root.

## Testing

The test suite is organized into categories:

- **Unit tests**: Test individual components in isolation
- **Functional tests**: Test higher-level functionality
- **Integration tests**: Test interactions between components
- **Performance tests**: Measure performance metrics

Run tests with:
```
make check
```

When adding new functionality, create corresponding tests.

## Debugging

For debugging:

1. Configure with debug symbols:
   ```
   ./configure --enable-debug
   ```

2. Use GDB or LLDB:
   ```
   lldb server/nasfs-server
   ```

## Contribution Workflow

1. Create a branch for your work:
   ```
   git checkout -b feature/your-feature-name
   ```

2. Make changes and commit with descriptive messages according to the conventional commits guidelines. Aviable types of commits are feat, fix, ref, style, test, chore, docs, build, ci, perf, revert, wip.

3. Ensure code passes all tests:
   ```
   make check
   ```

4. Format your code:
   ```
   clang-format -i modified_files
   ```

5. Submit a pull request with a clear description of changes

## Documentation

- Document all public API functions
- Update README.md for user-facing changes
- Update this development guide when changing development workflows
- Add comments explaining complex algorithms or non-obvious code

## Release Process

1. Update version in `configure.ac`
2. Update changelog
3. Tag the release:
   ```
   git tag -a v1.0.0 -m "Version 1.0.0"
   ```
4. Build the distribution:
   ```
   make dist
   ```
