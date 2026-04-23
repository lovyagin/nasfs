# Tests Makefile.am for NASFS

# List of scripts to run for 'make check'
TESTS = test_end_to_end.sh

# Files to include in the distribution
EXTRA_DIST = $(TESTS)

# Clean up temporary test artifacts
clean-local:
	rm -rf workspace
