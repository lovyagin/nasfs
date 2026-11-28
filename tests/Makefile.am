check_PROGRAMS = test_handshake test_config test_auth test_encryption test_pake
TESTS = $(check_PROGRAMS) test_end_to_end.sh test_file_encryption.sh test_lifecycle.sh
TESTS_ENVIRONMENT = \
	NASFS_SERVER_BIN="$(top_builddir)/server/nasfs_server" \
	NASFS_CLIENT_BIN="$(top_builddir)/client/nasfs_client"

EXTRA_DIST = benchmark_target.py test_end_to_end.sh test_file_encryption.sh test_lifecycle.sh integration_helpers.sh test_transfer_recovery.py test_versioned_transfers.py test_systemd.sh fault_injection.c fixtures/implicit-4096.b64 fixtures/nasluks-author.b64 fixtures/nasluks-master-salt.b64 fixtures/nasluks-hkdf.b64 fixtures/nasluks-pbkdf2.b64

AM_CPPFLAGS = $(UV_CFLAGS) $(OQS_CFLAGS) $(SODIUM_CFLAGS) -I$(top_srcdir)/common/include -I$(top_srcdir)/server/include

test_handshake_SOURCES = test_handshake.c
test_handshake_LDADD = $(top_builddir)/common/libnasfs_common.a $(SODIUM_LIBS) $(OQS_LIBS) $(OPENSSL_LIBS)

test_config_SOURCES = \
	test_config.c \
	$(top_srcdir)/server/src/config/config.c

test_auth_SOURCES = test_auth.c
test_auth_LDADD = $(top_builddir)/common/libnasfs_common.a $(SODIUM_LIBS) $(OQS_LIBS) $(OPENSSL_LIBS)

test_encryption_SOURCES = test_encryption.c
test_encryption_LDADD = $(top_builddir)/common/libnasfs_common.a $(SODIUM_LIBS) $(OQS_LIBS) $(OPENSSL_LIBS)

test_pake_SOURCES = test_pake.c
test_pake_LDADD = $(top_builddir)/common/libnasfs_common.a $(SODIUM_LIBS)
