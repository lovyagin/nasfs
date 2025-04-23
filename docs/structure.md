# NASFS Project Structure

## Overall Code Organization


```
nasfs/
├── server/         # Server-side components
├── client/         # Client-side components
├── common/         # Shared components
├── utils/          # Utilities
├── tests/          # Tests
├── docs/           # Documentation
├── scripts/        # Deployment and maintenance scripts
└── build/          # Build files
```

## Server-side Components (server/)

```
server/
├── src/
│   ├── main.c                      # Entry point
│   ├── network/                    # Network layer
│   │   ├── server.c                # Connection handling
│   │   ├── protocol.c              # Protocol implementation
│   │   └── session.c               # Session management
│   ├── fs/                         # File system operations
│   │   ├── file_ops.c              # Basic file operations
│   │   ├── directory_ops.c         # Directory operations
│   │   ├── permissions.c           # Access rights handling
│   │   └── metadata.c              # Metadata management
│   ├── auth/                       # Authentication
│   │   ├── users.c                 # User management
│   │   ├── groups.c                # Group management
│   │   └── acl.c                   # Access Control Lists
│   ├── storage/                    # Data storage
│   │   ├── disk_manager.c          # Disk management
│   │   ├── cache.c                 # Caching
│   │   └── quota.c                 # Quota management
│   └── logging/                    # Logging
│       ├── system_log.c            # System logs
│       └── audit.c                 # Access audit
├── include/                        # Header files
└── config/                         # Configuration files
```

## Client-side Components (client/)

```
client/
├── src/
│   ├── api/                        # Client API
│   │   ├── nasfs_client.c          # Main client code
│   │   ├── file_operations.c       # File operations
│   │   └── connection.c            # Connection management
│   ├── os/                         # OS integration
│   │   ├── linux/                  # Linux-specific code
│   │   ├── windows/                # Windows-specific code
│   │   └── macos/                  # macOS-specific code
│   └── tools/                      # Client utilities
│       ├── nasfs_mount.c           # Mount utility
│       ├── nasfs_admin.c           # Administration utility
│       └── nasfs_sync.c            # Synchronization utility
├── include/                        # Header files
└── examples/                       # Usage examples
```

## Shared Components (common/)

```
common/
├── src/
│   ├── protocol/                   # Data exchange protocol
│   │   ├── messages.c              # Message definitions
│   │   ├── serialization.c         # Data serialization
│   │   └── protocol_versions.c     # Protocol version management
│   ├── security/                   # Security components
│   │   ├── encryption.c            # Encryption
│   │   ├── certificates.c          # Certificate management
│   │   └── key_management.c        # Key management
│   └── utils/                      # Common utilities
│       ├── data_structures.c       # Data structures
│       ├── error_handling.c        # Error handling
│       └── config_parser.c         # Configuration parser
└── include/                        # Header files
```

## Tests (tests/)

```
tests/
├── functional/                     # Functional tests
├── unit/                           # Unit tests
│   ├── server/                     # Server-side tests
│   ├── client/                     # Client-side tests
│   └── common/                     # Shared components tests
├── integration/                    # Integration tests
├── performance/                    # Performance tests
└── scripts/                        # Test scripts
```
