ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = util/tcnetstat src/tcpcryptd
dist_man8_MANS = src/tcpcryptd.man util/tcnetstat.man
lib_LTLIBRARIES = lib/libtcpcrypt.la
TESTSUITE = tests/testsuite
TESTSUITEFLAGS = --directory tests
EXTRA_DIST = src/tcpcryptd.man.md launch_tcpcryptd.sh util/tcnetstat.man.md src/tcpcrypt_version.h \
  tests/testsuite.at tests/package.m4 $(TESTSUITE) tests/atlocal.in

AM_CFLAGS = -Iinclude -I. -Isrc

if MAINTAINER_MODE
SUFFIXES = .man.md .man
.man.md.man:
	pandoc -s -w man $^ -o $@
endif



# lib/ -- builds libtcpcrypt

lib_libtcpcrypt_ladir = $(includedir)/tcpcrypt
lib_libtcpcrypt_la_HEADERS = include/tcpcrypt/tcpcrypt.h
lib_libtcpcrypt_la_SOURCES = \
	lib/sockopt.c \
	src/tcpcrypt_ctl.h \
	shared/socket_address.h \
	shared/socket_address.c \
	lib/libtcpcrypt.sym

lib_libtcpcrypt_la_CFLAGS = -export-symbols lib/libtcpcrypt.sym

TCPCRYPT_LIBRARY_VERSION = 0:0:0
lib_libtcpcrypt_la_LDFLAGS = -version-info $(TCPCRYPT_LIBRARY_VERSION)

if OS_MINGW
lib_libtcpcrypt_la_LIBADD = -lws2_32
endif

# util/ -- builds tcnetstat

util_tcnetstat_SOURCES = util/tcnetstat.c libtcpcrypt.la include/tcpcrypt/tcpcrypt.h
util_tcnetstat_LDADD = lib/libtcpcrypt.la

if OS_MINGW
util_tcnetstat_LDADD	  += -lwsock32 -liphlpapi
endif


# src/ -- builds tcpcryptd

src_tcpcryptd_SOURCES = \
	src/tcpcryptd.c src/tcpcrypt.c src/crypto.c src/crypto_rsa.c src/crypto_aes.c \
	src/crypto_hmac.c src/crypto_dummy.c src/profile.c src/checksum.c src/test.c  \
	src/crypto_hkdf.c \
	src/crypto_reg.c src/crypto_ecdhe.c \
	shared/socket_address.c \
	shared/socket_address.h \
	src/inc.h src/tcpcrypt_ctl.h src/tcpcrypt_divert.h src/tcpcrypt.h src/tcpcryptd.h \
	src/profile.h src/checksum.h src/test.h src/crypto.h src/tcpcrypt_strings.h \
        src/util.c \
	src/tcpcrypt_version.h

src_tcpcryptd_LDADD = @tcpcryptd_LDADD@ @crypto_LDADD@

if OS_BSD
src_tcpcryptd_SOURCES += freebsd.c
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


# tests

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

check-local: tests/atconfig tests/atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

installcheck-local: tests/atconfig tests/atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
	  $(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
	 $(SHELL) '$(TESTSUITE)' --clean
	rm -f '$(TESTSUITE)'

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
