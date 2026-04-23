# Main Makefile.am for NASFS

# Subdirectories to build
SUBDIRS = common server client tests

# Flag for aclocal to find macros in the m4 directory
ACLOCAL_AMFLAGS = -I m4

# Files to include in the distribution but not part of the build
EXTRA_DIST = config/nasfs.conf README.md

# Convenience target for running the integration tests
test: all
	@echo "Running end-to-end tests..."
	$(abs_top_srcdir)/tests/test_end_to_end.sh

# Integration with standard 'make check'
check-local: test
