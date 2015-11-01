ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS =  src/tcpcryptd util/tcnetstat util/tcs
dist_man8_MANS = src/tcpcryptd.man util/tcnetstat.man
lib_LTLIBRARIES = lib/libtcpcrypt.la
TESTSUITE = tests/testsuite
TESTSUITEFLAGS = --directory tests
EXTRA_DIST = \
	launch_tcpcryptd.sh \
	src/tcpcrypt_version.h \
	src/tcpcryptd.man.md util/tcnetstat.man.md \
	tests/package.m4 tests/atlocal.in \
	tests/testsuite.at tests/version.at tests/hmac.at \
	$(TESTSUITE)

if MAINTAINER_MODE
SUFFIXES = .man.md .man
.man.md.man:
	pandoc -s -w man $^ -o $@
endif

TCPCRYPT_SRC = $(srcdir)/src
TCPCRYPT_INCLUDE = $(srcdir)/include

AM_CFLAGS = -I$(TCPCRYPT_SRC) -I$(TCPCRYPT_INCLUDE)

# include generated headers like tcpcrypt_version.h
AM_CFLAGS += -I$(builddir)/src

PRIV_SOURCES = src/priv.h
PRIV_LDADD =
if OS_MINGW
PRIV_SOURCES += win/priv.c
else
PRIV_SOURCES += unix/priv.c
if OS_LINUX
PRIV_SOURCES += unix/linux/priv.c
PRIV_LDADD += -lcap
endif
endif

# lib_libtcpcrypt

lib_libtcpcrypt_ladir = $(includedir)/tcpcrypt
lib_libtcpcrypt_la_HEADERS = include/tcpcrypt/tcpcrypt.h
lib_libtcpcrypt_la_SOURCES = \
	lib/sockopt.c \
	shared/socket_address.c shared/socket_address.h \
	src/tcpcrypt_ctl.h \
	lib/libtcpcrypt.sym

TCPCRYPT_LIBRARY_VERSION = 0:0:0
lib_libtcpcrypt_la_LDFLAGS = \
	-version-info $(TCPCRYPT_LIBRARY_VERSION) \
	-export-symbols $(top_srcdir)/lib/libtcpcrypt.sym

if OS_MINGW
lib_libtcpcrypt_la_LIBADD = -lws2_32
endif


# util_tcnetstat

util_tcnetstat_SOURCES = \
	util/tcnetstat.c \
	include/tcpcrypt/tcpcrypt.h \
	shared/socket_address.c shared/socket_address.h \
	lib/libtcpcrypt.la

util_tcnetstat_LDADD = lib/libtcpcrypt.la
if OS_MINGW
util_tcnetstat_LDADD += -lwsock32 -liphlpapi
endif

util_tcnetstat_CFLAGS = $(AM_CFLAGS)

# util_tcs

util_tcs_SOURCES = util/tcs.c \
	shared/socket_address.c shared/socket_address.h \
	$(PRIV_SOURCES)

util_tcs_LDADD = lib/libtcpcrypt.la $(PRIV_LDADD)

util_tcs_CFLAGS = $(AM_CFLAGS)

# src_tcpcryptd

src_tcpcryptd_SOURCES = \
	src/tcpcryptd.c src/tcpcrypt.c src/crypto.c src/crypto_rsa.c src/crypto_aes.c \
	src/crypto_hmac.c src/crypto_dummy.c src/profile.c src/checksum.c src/test.c  \
	src/crypto_hkdf.c \
	src/crypto_reg.c src/crypto_ecdhe.c \
	src/inc.h src/tcpcrypt_ctl.h src/tcpcrypt_divert.h src/tcpcrypt.h src/tcpcryptd.h \
	src/profile.h src/checksum.h src/test.h src/crypto.h src/tcpcrypt_strings.h \
	src/util.c src/util.h \
	src/tcpcrypt_version.h \
	shared/socket_address.c shared/socket_address.h \
	$(PRIV_SOURCES)

src_tcpcryptd_LDADD = @tcpcryptd_LDADD@ @crypto_LDADD@

if OS_BSD
src_tcpcryptd_SOURCES += src/freebsd.c
endif

if OS_LINUX
src_tcpcryptd_SOURCES += src/linux.c
endif

if OS_MINGW
src_tcpcryptd_SOURCES += src/mingw.c src/res.rc src/cygwin.c contrib/win_port.h
src_tcpcryptd_LDADD	  += -lwsock32 -liphlpapi -lWinDivert
else
src_tcpcryptd_SOURCES += src/unix.c
endif

if !NO_ASM
src_tcpcryptd_SOURCES += src/checksum_32.S
endif

src_tcpcryptd_CFLAGS = $(AM_CFLAGS)

# tests/

tests/package.m4: $(top_srcdir)/configure.ac
	{ \
	  echo '# Signature of the current package.' && \
	  echo 'm4_define([AT_PACKAGE_NAME],  [$(PACKAGE_NAME)])' && \
	  echo 'm4_define([AT_PACKAGE_TARNAME],  [$(PACKAGE_TARNAME)])' && \
	  echo 'm4_define([AT_PACKAGE_VERSION],  [$(PACKAGE_VERSION)])' && \
	  echo 'm4_define([AT_PACKAGE_STRING],  [$(PACKAGE_STRING)])' && \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT],  [$(PACKAGE_BUGREPORT)])'; \
	  echo 'm4_define([AT_PACKAGE_URL],  [$(PACKAGE_URL)])'; \
	} >$@

tests/atconfig: config.status
	./config.status $@

ALL_TESTS = tests/version.at tests/hmac.at

RUN_TESTSUITE = $(SHELL) $(srcdir)/tests/testsuite $(TESTSUITEFLAGS)

check-local: tests/atconfig tests/atlocal $(TESTSUITE)
	$(RUN_TESTSUITE) AUTOTEST_PATH='tests:src:util'

installcheck-local: tests/atconfig tests/atlocal $(TESTSUITE)
	$(RUN_TESTSUITE) AUTOTEST_PATH='tests:$(bindir)'

clean-local:
	test ! -f '$(TESTSUITE)' || $(RUN_TESTSUITE) --clean
	rm -f '$(TESTSUITE)'
	rm -f tests/testsuite.log
	rm -f tests/atconfig

AUTOM4TE = $(SHELL) $(srcdir)/config/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): tests/testsuite.at tests/package.m4 $(ALL_TESTS)
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

## test programs:

## all tests against crypto elements should include these:
cryptosources = \
 src/inc.h \
 src/crypto.h \
 src/profile.h \
 src/crypto.c \
 src/profile.c \
 src/util.c

check_PROGRAMS = tests/hmac

tests_hmac_SOURCES = tests/hmac.c \
  src/crypto_hmac.c \
  $(cryptosources)

tests_hmac_LDADD = @crypto_LDADD@
