check_PROGRAMS = test_handshake test_config
TESTS = $(check_PROGRAMS) test_end_to_end.sh

EXTRA_DIST = test_end_to_end.sh

AM_CFLAGS = -I$(top_srcdir)/common/include -I$(top_srcdir)/server/include

test_handshake_SOURCES = test_handshake.c
test_handshake_LDADD = $(top_builddir)/common/libnasfs_common.a

test_config_SOURCES = \
	test_config.c \
	$(top_srcdir)/server/src/config/config.c

# Clean up temporary test artifacts
clean-local:
	rm -rf workspace
