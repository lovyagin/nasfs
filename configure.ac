AC_PREREQ([2.69])
AC_INIT([nasfs], [0.1.0], [admin@nasfs.local])
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])
AC_CONFIG_SRCDIR([server/src/main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_RANLIB

# Configure CFLAGS for C11
CFLAGS="$CFLAGS -std=c11 -Wall -Wextra"

# Debug option
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug], [Enable debug build (default is no)])],
    [enable_debug=$enableval],
    [enable_debug=no])

AS_IF([test "x$enable_debug" = "xyes"], [
  CFLAGS="$CFLAGS -g -O0 -DDEBUG"
  AC_MSG_NOTICE([Debug build enabled])
], [
  CFLAGS="$CFLAGS -O3"
  AC_MSG_NOTICE([Release build enabled])
])

# Add Homebrew OpenSSL paths for macOS if available
AC_PATH_PROG([BREW_CMD], [brew])
if test -n "$BREW_CMD"; then
    OPENSSL_PREFIX=`"$BREW_CMD" --prefix openssl@3 2>/dev/null`
    if test -n "$OPENSSL_PREFIX"; then
        CPPFLAGS="$CPPFLAGS -I$OPENSSL_PREFIX/include"
        LDFLAGS="$LDFLAGS -L$OPENSSL_PREFIX/lib"
        AC_MSG_NOTICE([Found Homebrew OpenSSL and added its paths.])
    fi
fi

# Checks for libraries.
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([UV], [libuv])
PKG_CHECK_MODULES([OQS], [liboqs])
PKG_CHECK_MODULES([SODIUM], [libsodium])

# Check for OpenSSL's libcrypto
AC_CHECK_LIB([crypto], [CRYPTO_free],
             [LIBS="$LIBS -lcrypto"],
             [AC_MSG_ERROR([OpenSSL (libcrypto) not found])])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Output files
AC_CONFIG_FILES([
    Makefile
    common/Makefile
    server/Makefile
    client/Makefile
    tests/Makefile
])

AC_OUTPUT
