# Main Makefile.am for NASFS

# Subdirectories to build (tests is excluded as it has nothing to compile)
SUBDIRS = common server client

# Flag for aclocal to find macros in the m4 directory
ACLOCAL_AMFLAGS = -I m4

# Files to include in the distribution but not part of the build
EXTRA_DIST = config/nasfs.conf README.md tests/test_end_to_end.sh

# Integration with standard 'make check' to run our test script
check-local: all
	@echo "Running end-to-end integration tests..."
	$(abs_top_srcdir)/tests/test_end_to_end.sh

# Hook into distclean to run our more aggressive cleanup script
distclean-local:
	@echo "Running aggressive cleanup..."
	$(abs_top_srcdir)/autoclean.sh
