noinst_LIBRARIES = libnasfs_common.a

libnasfs_common_a_SOURCES = \
    src/protocol.c \
    src/handshake.c \
    src/auth.c
libnasfs_common_a_CFLAGS = $(UV_CFLAGS) -I$(srcdir)/include
libnasfs_common_a_CPPFLAGS = -I$(srcdir)/include
