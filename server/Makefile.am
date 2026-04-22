bin_PROGRAMS = nasfs_server

nasfs_server_SOURCES = \
    src/main.c \
    src/config/config.c \
    src/logging/log.c \
    src/utils/daemon.c \
    src/utils/pid_file.c \
    src/utils/signal_handler.c

nasfs_server_CFLAGS = $(UV_CFLAGS) -I$(top_srcdir)/common/include -I$(srcdir)/include
nasfs_server_LDADD = $(top_builddir)/common/libnasfs_common.a $(UV_LIBS)
