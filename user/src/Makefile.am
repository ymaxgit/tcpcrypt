bin_PROGRAMS      = tcpcryptd
tcpcryptd_SOURCES = \
	tcpcryptd.c tcpcrypt.c crypto.c crypto_rsa.c crypto_aes.c \
	crypto_hmac.c crypto_dummy.c profile.c checksum.c test.c  \
	crypto_umac.c crypto_hkdf.c \
	crypto_reg.c crypto_ecdhe.c \
	$(top_srcdir)/contrib/umac.c \
	$(top_srcdir)/contrib/rijndael-alg-fst.c \
	\
	inc.h tcpcrypt_ctl.h tcpcrypt_divert.h tcpcrypt.h tcpcryptd.h \
	profile.h checksum.h test.h crypto.h tcpcrypt_strings.h \
	tcpcrypt_version.h \
	$(top_srcdir)/contrib/rijndael-alg-fst.h \
	$(top_srcdir)/contrib/umac.h

tcpcryptd_CFLAGS = -I$(top_srcdir)/include/ -iquote$(top_srcdir)
tcpcryptd_LDADD  = -lcrypto

if OS_BSD
tcpcryptd_SOURCES += freebsd.c
endif

if OS_LINUX
tcpcryptd_SOURCES += linux.c
tcpcryptd_LDADD += -lnetfilter_queue -lnfnetlink -lcap
endif

if OS_MINGW
tcpcryptd_SOURCES += mingw.c res.rc cygwin.c
tcpcryptd_LDADD	  += -lwsock32 -liphlpapi -lWinDivert
else
tcpcryptd_SOURCES += unix.c
endif

if !NO_ASM
tcpcryptd_SOURCES += checksum_32.S
endif

