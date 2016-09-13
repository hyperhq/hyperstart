#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([hyperstart], [0.7.0], [www.hyper.sh])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AM_EXTRA_RECURSIVE_TARGETS([initrd cbfs kernel])
AC_CONFIG_SRCDIR([src/init.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_CHECK_PROG(PKG_CONFIG, [pkg-config], [pkg-config], [:])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h stddef.h stdint.h stdlib.h string.h sys/mount.h sys/socket.h unistd.h stdbool.h],
[headers_found=yes],
[headers_found=no])

if test "x$headers_found" != "xyes"; then
    AC_MSG_ERROR(Unable to find necessary headers)
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([dup2 memmove memset mkdir setenv socket strchr strdup strrchr strtoul], [fail=0], [fail=1])
AC_CHECK_FUNCS([setns])

if test "$fail" = "1" ; then
    AC_MSG_ERROR(Unable to find necessary functions)
fi

AC_ARG_WITH([aarch64],
            [AS_HELP_STRING([--with-aarch64],
                            [run hyperstart with 64-bit ARM architecture])],
            [],[with_aarch64=no])

if test "x$with_aarch64" != "xno" ; then
    AC_DEFINE_UNQUOTED([WITH_AARCH64], 1, [run hyperstart with 64-bit ARM architecture])
fi

AM_CONDITIONAL([WITH_AARCH64], [test "x$with_aarch64" != "xno"])

AC_ARG_WITH([vbox],
            [AS_HELP_STRING([--with-vbox],
                            [run hyperstart on Virtualbox])],
            [],[with_vbox=no])

if test "x$with_vbox" != "xno" ; then
    AC_DEFINE_UNQUOTED([WITH_VBOX], 1, [run hyperstart on Virtualbox])
fi

AM_CONDITIONAL([WITH_VBOX], [test "x$with_vbox" != "xno"])

AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=SYSTEMD_SYSTEM_UNIT_DIR],
                           [path to install systemd system service]),
                           [SYSTEMD_SYSTEMUNIT=${withval}],
                           [SYSTEMD_SYSTEMUNIT="`$PKG_CONFIG --variable=systemdsystemunitdir systemd 2>/dev/null`"])

AS_IF([test -z "$SYSTEMD_SYSTEMUNIT"],[SYSTEMD_SYSTEMUNIT=no])
AS_IF([test "x$enable_daemon" = "xno"],[SYSTEMD_SYSTEMUNIT=no])
AC_SUBST(SYSTEMD_SYSTEMUNIT)
AM_CONDITIONAL(SYSTEMD, test "x${SYSTEMD_SYSTEMUNIT}" != "xno" )

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  build/Makefile
  data/hyperstart.service
])
AC_OUTPUT

AC_MSG_RESULT([
	${PACKAGE}  ${VERSION}
	prefix:		${prefix}

	with-vbox:	${with_vbox}
	with-aarch64:	${with_aarch64}

	compiler:          ${CC}
	cflags:            ${CFLAGS}
	suid cflags:       ${SUID_CFLAGS}
	ldflags:           ${LDFLAGS}
	suid ldflags:      ${SUID_LDFLAGS}
	systemd unit path: ${SYSTEMD_SYSTEMUNIT}
])
