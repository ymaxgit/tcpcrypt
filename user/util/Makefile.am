bin_PROGRAMS = tcnetstat
tcnetstat_SOURCES = tcnetstat.c
tcnetstat_LDADD = $(top_builddir)/lib/libtcpcrypt.la $(AM_LDFLAGS)
tcnetstat_CFLAGS  = -I$(top_srcdir)/include/ -iquote$(top_srcdir)/

if OS_MINGW
tcnetstat_LDADD	  += -lwsock32 -liphlpapi
endif

dist_man8_MANS = tcnetstat.man

if MAINTAINER_MODE
tcnetstat.man: tcnetstat.man.md
	pandoc -s -w man $^ -o $@
endif

EXTRA_DIST = tcnetstat.man.md
