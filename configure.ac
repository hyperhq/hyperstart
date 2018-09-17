#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([hyperstart], [1.1.0], [www.hyper.sh])
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

AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=SYSTEMD_SYSTEM_UNIT_DIR],
                           [path to install systemd system service]),
                           [SYSTEMD_SYSTEMUNIT=${withval}],
                           [SYSTEMD_SYSTEMUNIT="`$PKG_CONFIG --variable=systemdsystemunitdir systemd 2>/dev/null`"])

AS_IF([test -z "$SYSTEMD_SYSTEMUNIT"],[SYSTEMD_SYSTEMUNIT=no])
AS_IF([test "x$enable_daemon" = "xno"],[SYSTEMD_SYSTEMUNIT=no])
AC_SUBST(SYSTEMD_SYSTEMUNIT)
AM_CONDITIONAL(SYSTEMD, test "x${SYSTEMD_SYSTEMUNIT}" != "xno" )

AC_ARG_WITH([kmodules],
	    AS_HELP_STRING([--without-kmodules],
			   [Do not include kernel modules in the rootfs]), [],
			   [])
# by default kernel modules are included
AS_IF([test "x$with_kmodules" = "x"],[with_kmodules=yes])
AM_CONDITIONAL([WITH_KMODULES], [test "x$with_kmodules" = "xyes"])

AC_CHECK_FILE([/usr/include/linux/vm_sockets.h],
	      [have_vsock=yes], [have_vsock=no])
if test "x$have_vsock" == "xyes"; then
    AC_DEFINE_UNQUOTED([HAVE_VSOCK], 1, [enable vm socket support])
fi
AM_CONDITIONAL([HAVE_VSOCK], [test "x$have_vsock" == "xyes"])

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

	with-kmodules:  ${with_kmodules}

	vsock-support:  ${have_vsock}

	compiler:          ${CC}
	cflags:            ${CFLAGS}
	suid cflags:       ${SUID_CFLAGS}
	ldflags:           ${LDFLAGS}
	suid ldflags:      ${SUID_LDFLAGS}
	systemd unit path: ${SYSTEMD_SYSTEMUNIT}
])
