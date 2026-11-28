bin_PROGRAMS = nasfs_server

noinst_HEADERS = \
    include/config/config.h \
    include/logging/log.h \
    include/file_service.h \
    include/network/session_internal.h \
    include/network/session.h \
    include/storage.h \
    include/utils/daemon.h \
    include/utils/pid_file.h \
    include/utils/signal_handler.h

nasfs_server_SOURCES = \
    src/main.c \
    src/config/config.c \
    src/logging/log.c \
    src/network/session.c \
    src/file_service.c \
    src/storage.c \
    src/utils/daemon.c \
    src/utils/pid_file.c \
    src/utils/signal_handler.c

nasfs_server_CFLAGS = $(UV_CFLAGS) $(OQS_CFLAGS) $(SODIUM_CFLAGS) -I$(top_srcdir)/common/include -I$(srcdir)/include
nasfs_server_LDADD = $(top_builddir)/common/libnasfs_common.a $(UV_LIBS) $(OQS_LIBS) $(SODIUM_LIBS) $(OPENSSL_LIBS)
