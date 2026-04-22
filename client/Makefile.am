bin_PROGRAMS = nasfs_client

nasfs_client_SOURCES = src/main.c
nasfs_client_CFLAGS = $(UV_CFLAGS) -I$(top_srcdir)/common/include -I$(srcdir)/include
nasfs_client_LDADD = $(top_builddir)/common/libnasfs_common.a $(UV_LIBS)
