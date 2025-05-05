bin_PROGRAMS = nasfs-server

nasfs_server_SOURCES = \
    $(srcdir)/src/main.c \
    $(srcdir)/src/config/config.c \
    $(srcdir)/src/logging/log.c \
    $(srcdir)/src/utils/daemon.c \
    $(srcdir)/src/utils/signal_handler.c \
    $(srcdir)/src/utils/pid_file.c \
    $(srcdir)/src/network/connections.c \
    $(srcdir)/src/network/server.c

nasfs_server_CFLAGS = -Wall -pedantic -std=c99 -I$(srcdir)/include
nasfs_server_LDFLAGS = -lpthread

# Configuration directory and files
configdir = $(sysconfdir)/nasfs
config_DATA = config/nasfs.conf

# Install directories
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/log
	touch $(DESTDIR)$(localstatedir)/log/nasfs-server.log
	chmod 644 $(DESTDIR)$(localstatedir)/log/nasfs-server.log

# Remove files on uninstall
uninstall-hook:
	rm -f $(DESTDIR)$(localstatedir)/log/nasfs-server.log
	rm -f $(DESTDIR)$(localstatedir)/run/nasfs/nasfs-server.pid

# Include all header files in the distribution
EXTRA_DIST = \
    include/config/config.h \
    include/logging/log.h \
    include/network/connections.h \
    include/network/protocol.h \
    include/network/server.h \
    include/utils/daemon.h \
    include/utils/pid_file.h \
    include/utils/signal_handler.h \
    config/nasfs.conf
