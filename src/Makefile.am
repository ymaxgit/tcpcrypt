bin_PROGRAMS      = tcpcryptd
tcpcryptd_SOURCES = \
	tcpcryptd.c tcpcrypt.c crypto.c crypto_rsa.c crypto_aes.c \
	crypto_hmac.c crypto_dummy.c profile.c checksum.c test.c  \
	crypto_hkdf.c \
	crypto_reg.c crypto_ecdhe.c \
	$(top_srcdir)/shared/socket_address.c \
	$(top_srcdir)/shared/socket_address.h \
	inc.h tcpcrypt_ctl.h tcpcrypt_divert.h tcpcrypt.h tcpcryptd.h \
	profile.h checksum.h test.h crypto.h tcpcrypt_strings.h \
	tcpcrypt_version.h

tcpcryptd_CFLAGS = -I$(top_srcdir)/include/ -I$(top_srcdir)
tcpcryptd_LDADD = @tcpcryptd_LDADD@

if OS_BSD
tcpcryptd_SOURCES += freebsd.c
endif

if OS_LINUX
tcpcryptd_SOURCES += linux.c
endif

if OS_MINGW
tcpcryptd_SOURCES += mingw.c res.rc cygwin.c $(top_srcdir)/contrib/win_port.h
tcpcryptd_LDADD	  += -lwsock32 -liphlpapi -lWinDivert
else
tcpcryptd_SOURCES += unix.c
endif

if !NO_ASM
tcpcryptd_SOURCES += checksum_32.S
endif

dist_man8_MANS = tcpcryptd.man

if MAINTAINER_MODE
tcpcryptd.man: tcpcryptd.man.md
	pandoc -s -w man $^ -o $@
endif

EXTRA_DIST = tcpcryptd.man.md
