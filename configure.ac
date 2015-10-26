#                                               -*- Autoconf -*-

AC_PREREQ([2.65])
AC_INIT([tcpcrypt], [0.3], [tcpcrypt-users@lists.stanford.edu], [tcpcrypt], [http://tcpcrypt.org])
AC_CONFIG_SRCDIR([src/tcpcryptd.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.9 foreign dist-xz -Wall subdir-objects])
AM_MAINTAINER_MODE([disable])

AC_ARG_VAR([DIVERT_PORT], [Default divert port for tcpcryptd])
if test -n "$DIVERT_PORT"; then
   AC_DEFINE_UNQUOTED([TCPCRYPTD_DIVERT_PORT], [$DIVERT_PORT], [Default divert port for tcpcryptd])
else
   AC_DEFINE([TCPCRYPTD_DIVERT_PORT], 666, [Default divert port for tcpcryptd])
fi

AC_ARG_VAR([CONTROL_SOCKET],
           [Default local control socket for tcpcryptd: unix-domain path or localhost port-number])
if test -n "$CONTROL_SOCKET"; then
    AC_DEFINE_UNQUOTED([TCPCRYPTD_CONTROL_SOCKET], [$CONTROL_SOCKET],
        [Default local control socket for tcpcryptd: unix-domain path or localhost port-number])
else
    AC_DEFINE([TCPCRYPTD_CONTROL_SOCKET], "/var/run/tcpcryptd.control",
        [Default local control socket for tcpcryptd: unix-domain path or localhost port-number])
fi

AC_ARG_VAR([JAIL_DIR], [Default jail directory for tcpcryptd])
if test -n "$JAIL_DIR"; then
   AC_DEFINE_UNQUOTED([TCPCRYPTD_JAIL_DIR], ["$JAIL_DIR"], [Default jail directory for tcpcryptd])
else
   AC_DEFINE([TCPCRYPTD_JAIL_DIR], ["/var/run/tcpcryptd"], [Default jail directory for tcpcryptd])
fi

AC_ARG_VAR([JAIL_USER], [Default jail username for tcpcryptd])
if test -n "$JAIL_USER"; then
   AC_DEFINE_UNQUOTED([TCPCRYPTD_JAIL_USER], ["$JAIL_USER"], [Default jail username for tcpcryptd])
else
   AC_DEFINE([TCPCRYPTD_JAIL_USER], ["tcpcryptd"], [Default jail username for tcpcryptd])
fi

AC_ARG_VAR([TEST_SERVER], [Default network test server for tcpcryptd])
if test -n "$TEST_SERVER"; then
   AC_DEFINE_UNQUOTED([TCPCRYPTD_TEST_SERVER], ["$TEST_SERVER"], [Default network test server for tcpcryptd])
else
   AC_DEFINE([TCPCRYPTD_TEST_SERVER], ["check.tcpcrypt.org"], [Default network test server for tcpcryptd])
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S
AM_PROG_AR
AC_PROG_LIBTOOL
AM_PROG_AS

# Check platform
AC_CANONICAL_HOST
AC_MSG_CHECKING(OS)
if [ echo $host_os | grep linux ]; then
  os_linux=1
else
  os_linux=0
fi
AM_CONDITIONAL(OS_LINUX, [test "$os_linux" -eq 1])
AM_CONDITIONAL(OS_BSD, [echo $host_os | grep -E 'darwin|freebsd'])
AM_CONDITIONAL(OS_MINGW, [echo $host_os | grep mingw])

AS_IF([test "$os_linux" -eq 1],
      [AC_DEFINE([OS_LINUX], 1, [Define to 1 if compiling for a Linux system])],
      [AC_DEFINE([OS_LINUX], 0, [Define to 1 if compiling for a Linux system])])

CFLAGS="$CFLAGS -Wall -Wno-deprecated-declarations"

# DEBUG
AC_ARG_ENABLE(debug, 
    AS_HELP_STRING([--enable-debug],
                   [enable tracing and debugging flags for all components]),
    [enable_debug="$enableval"],
    [])
if test "${enable_debug}" = yes; then
    CXXFLAGS="$CXXFLAGS -DDEBUG -g"
    CFLAGS="$CFLAGS -DDEBUG -g"

    AC_SUBST(CXXFLAGS)
    AC_SUBST(CFLAGS)
fi

# ASM
AC_MSG_CHECKING(whether to use asm checksum routine)
AC_ARG_ENABLE(asm, 
    AS_HELP_STRING([--enable-asm],
                   [use asm checksum routine]),
    [enable_asm="$enableval"],
    [enable_asm="no"])
if test "${enable_asm}" = yes; then
   AC_MSG_RESULT(yes)
else
   AC_MSG_RESULT(no)
   AC_DEFINE(NO_ASM, 1, [No asm?])
fi
AM_CONDITIONAL(NO_ASM, test x$enable_asm = xno)

AM_CONDITIONAL(HAVE_NI, false)

# libs
AC_CHECK_LIB([cap], [cap_set_flag], [tcpcryptd_LDADD="-lcap $tcpcryptd_LDADD"])
AC_CHECK_LIB([crypto], [EVP_OpenInit], [crypto_LDADD="-lcrypto"])

AC_CHECK_LIB([netfilter_queue], [nfq_open], [tcpcryptd_LDADD="-lnetfilter_queue $tcpcryptd_LDADD"])

AC_CHECK_LIB([nfnetlink], [nfnl_rcvbufsiz], [tcpcryptd_LDADD="-lnfnetlink $tcpcryptd_LDADD"])
AC_CHECK_LIB([pcap], [pcap_open_live], [tcpcryptd_LDADD="-lpcap $tcpcryptd_LDADD"])
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([wsock32], [bind]) # TODO: find symbol name
AC_CHECK_LIB([iphlpapi], [GetAdaptersInfo]) # TODO: find symbol name
AC_SUBST([tcpcryptd_LDADD])
AC_SUBST([crypto_LDADD])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# testing
AC_CONFIG_TESTDIR([tests], [.])
AC_CONFIG_FILES([tests/atlocal])

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero clock_gettime gettimeofday inet_ntoa memmove memset select socket strchr strdup strtoul])

AC_CONFIG_FILES([Makefile src/tcpcrypt_version.h])
AC_OUTPUT
