# Main Makefile.am for NASFS

# Subdirectories to build
SUBDIRS = common server client tests

# Flag for aclocal to find macros in the m4 directory
ACLOCAL_AMFLAGS = -I m4

# Files to include in the distribution but not part of the build
EXTRA_DIST = README.md tests/test_end_to_end.sh utils/nasfsctl.in systemd/nasfs.service.in

edit_paths = sed \
	-e 's|[@]NASFS_BINDIR[@]|$(bindir)|g' \
	-e 's|[@]NASFS_SYSCONFDIR[@]|$(sysconfdir)/nasfs|g' \
	-e 's|[@]NASFS_LOCALSTATEDIR[@]|$(localstatedir)|g'

bin_SCRIPTS = utils/nasfsctl

nasfsconfdir = $(sysconfdir)/nasfs
dist_nasfsconf_DATA = server/config/nasfs.conf

if INSTALL_SYSTEMD
systemdunitdir = $(systemdsystemunitdir)
dist_systemdunit_DATA = systemd/nasfs.service
endif

CLEANFILES = utils/nasfsctl systemd/nasfs.service
BUILT_SOURCES = utils/nasfsctl systemd/nasfs.service

utils/nasfsctl: utils/nasfsctl.in Makefile
	$(MKDIR_P) $(@D)
	$(edit_paths) $< > $@
	chmod 755 $@

systemd/nasfs.service: systemd/nasfs.service.in Makefile
	$(MKDIR_P) $(@D)
	$(edit_paths) $< > $@

if INSTALL_SYSTEMD
install-data-hook: systemd/nasfs.service
	$(MKDIR_P) $(DESTDIR)$(systemdunitdir)
	$(INSTALL_DATA) systemd/nasfs.service $(DESTDIR)$(systemdunitdir)/nasfs.service
endif

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/run/nasfs
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/log/nasfs
	chmod 755 $(DESTDIR)$(localstatedir)/run/nasfs
	chmod 755 $(DESTDIR)$(localstatedir)/log/nasfs

# Hook into distclean to run our more aggressive cleanup script
distclean-local:
	@echo "Running aggressive cleanup..."
	$(abs_top_srcdir)/autoclean.sh
