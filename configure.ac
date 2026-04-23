AC_PREREQ([2.69])
AC_INIT([nasfs], [0.1.0], [admin@nasfs.local])
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])
AM_MAINTAINER_MODE([disable])
AC_CONFIG_SRCDIR([server/src/main.c])
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
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

# Installation directories for auxiliary assets.
pkgconfdir='${sysconfdir}/nasfs'
AC_SUBST([pkgconfdir])

AC_ARG_WITH([systemdsystemunitdir],
    [AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
                    [Directory for installing systemd service units])],
    [systemdsystemunitdir=$withval],
    [systemdsystemunitdir='${prefix}/lib/systemd/system'])
AC_SUBST([systemdsystemunitdir])

AC_ARG_ENABLE([systemd],
    [AS_HELP_STRING([--disable-systemd], [Do not install the systemd service unit])],
    [enable_systemd=$enableval],
    [enable_systemd=yes])
AM_CONDITIONAL([INSTALL_SYSTEMD], [test "x$enable_systemd" = "xyes"])

if test "x$prefix" = "xNONE"; then
  nasfs_prefix="$ac_default_prefix"
else
  nasfs_prefix="$prefix"
fi

if test "x$exec_prefix" = "xNONE"; then
  nasfs_exec_prefix="$nasfs_prefix"
else
  nasfs_exec_prefix="$exec_prefix"
fi

save_prefix="$prefix"
save_exec_prefix="$exec_prefix"
prefix="$nasfs_prefix"
exec_prefix="$nasfs_exec_prefix"
eval NASFS_BINDIR="$bindir"
eval NASFS_SYSCONFDIR="$pkgconfdir"
eval NASFS_LOCALSTATEDIR="$localstatedir"
prefix="$save_prefix"
exec_prefix="$save_exec_prefix"

AC_SUBST([NASFS_BINDIR])
AC_SUBST([NASFS_SYSCONFDIR])
AC_SUBST([NASFS_LOCALSTATEDIR])

# Output files
AC_CONFIG_FILES([
    Makefile
    common/Makefile
    server/Makefile
    client/Makefile
    tests/Makefile
])

AC_OUTPUT
