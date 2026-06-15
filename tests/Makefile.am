check_PROGRAMS = test_handshake test_config test_auth test_encryption
TESTS = $(check_PROGRAMS) test_end_to_end.sh test_file_encryption.sh
TESTS_ENVIRONMENT = \
	NASFS_SERVER_BIN="$(top_builddir)/server/nasfs_server" \
	NASFS_CLIENT_BIN="$(top_builddir)/client/nasfs_client" \
	NASFS_TEST_ROOT="$(abs_builddir)/workspace" \
	NASFS_STORAGE_DIR="$(abs_builddir)/storage"

EXTRA_DIST = test_end_to_end.sh test_file_encryption.sh

AM_CFLAGS = -I$(top_srcdir)/common/include -I$(top_srcdir)/server/include

test_handshake_SOURCES = test_handshake.c
test_handshake_LDADD = $(top_builddir)/common/libnasfs_common.a

test_config_SOURCES = \
	test_config.c \
	$(top_srcdir)/server/src/config/config.c

test_auth_SOURCES = test_auth.c
test_auth_LDADD = $(top_builddir)/common/libnasfs_common.a

test_encryption_SOURCES = test_encryption.c
test_encryption_LDADD = $(top_builddir)/common/libnasfs_common.a

# Clean up temporary test artifacts
clean-local:
	rm -rf workspace
