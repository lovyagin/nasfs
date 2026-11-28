noinst_LIBRARIES = libnasfs_common.a

noinst_HEADERS = \
    include/auth.h \
    include/crypto_engine.h \
    include/ecc.h \
    include/defaults.h \
    include/handshake.h \
    include/pake.h \
    include/protocol.h \
    include/version.h \
    ../vendor/blake3/blake3.h \
    ../vendor/blake3/blake3_impl.h

libnasfs_common_a_SOURCES = \
    src/protocol.c \
    src/version.c \
    src/handshake.c \
    src/auth.c \
    src/crypto_engine.c \
    src/ecc.c \
    src/pake.c \
    ../vendor/blake3/blake3.c \
    ../vendor/blake3/blake3_dispatch.c \
    ../vendor/blake3/blake3_portable.c
libnasfs_common_a_CPPFLAGS = $(UV_CFLAGS) $(SODIUM_CFLAGS) $(OPENSSL_CFLAGS) -I$(srcdir)/include \
    -I$(top_srcdir)/vendor/blake3 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 \
    -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_USE_NEON=0

EXTRA_DIST = ../vendor/blake3/LICENSE_A2
