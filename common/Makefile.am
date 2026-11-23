noinst_LIBRARIES = libnasfs_common.a

noinst_HEADERS = \
    include/auth.h \
    include/crypto_engine.h \
    include/handshake.h \
    include/pake.h \
    include/protocol.h

libnasfs_common_a_SOURCES = \
    src/protocol.c \
    src/handshake.c \
    src/auth.c \
    src/crypto_engine.c \
    src/pake.c
libnasfs_common_a_CFLAGS = $(UV_CFLAGS) -I$(srcdir)/include
libnasfs_common_a_CPPFLAGS = -I$(srcdir)/include
