# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([nasfs], [0.1], [email@example.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])
AC_CONFIG_SRCDIR([server/src/main.c])
AC_CONFIG_HEADERS([config.h])

# Debug option
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug], [Enable debug build (default is no)])],
    [enable_debug=$enableval],
    [enable_debug=no])

# Checks for programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Check for pthreads
AC_CHECK_LIB([pthread], [pthread_create], [], [
  AC_MSG_ERROR([pthread library not found])
])

# Configure CFLAGS based on debug option
AS_IF([test "x$enable_debug" = "xyes"], [
  CFLAGS="$CFLAGS -g -O0 -DDEBUG"
  AC_MSG_NOTICE([Debug build enabled])
], [
  CFLAGS="$CFLAGS -O3"
  AC_MSG_NOTICE([Release build enabled])
])

# Checks for header files
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Check for types
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Check for functions
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa memset socket strdup])

# Define DEBUG preprocessor macro in config.h if debug is enabled
AS_IF([test "x$enable_debug" = "xyes"], [
  AC_DEFINE([DEBUG], [1], [Debug mode enabled])
])

# Generate Makefiles
AC_CONFIG_FILES([
  Makefile
  server/Makefile
  tests/Makefile
])

AC_OUTPUT