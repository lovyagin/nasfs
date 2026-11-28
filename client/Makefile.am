bin_PROGRAMS = nasfs_client
noinst_LIBRARIES = libnasfs_client_api.a
noinst_HEADERS = include/nasfs_client.h

client_flags = $(UV_CFLAGS) $(OQS_CFLAGS) $(SODIUM_CFLAGS) $(OPENSSL_CFLAGS) -I$(top_srcdir)/common/include -I$(srcdir)/include
libnasfs_client_api_a_SOURCES = src/client.c
libnasfs_client_api_a_CFLAGS = $(client_flags)

nasfs_client_SOURCES = src/main.c
nasfs_client_CFLAGS = $(client_flags)
nasfs_client_LDADD = libnasfs_client_api.a $(top_builddir)/common/libnasfs_common.a $(UV_LIBS) $(OQS_LIBS) $(SODIUM_LIBS) $(OPENSSL_LIBS)
