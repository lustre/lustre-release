# Administration utilities Makefile
DEFS=

CFLAGS:=-g -O2 -I$(top_srcdir)/utils -I$(PORTALS)/include  -I$(srcdir)/../include -Wall -L$(PORTALSLIB)
KFLAGS:=
CPPFLAGS = $(HAVE_LIBREADLINE)
obdctl_LDADD := $(LIBREADLINE)
lctl_LDADD := $(LIBREADLINE) -lptlctl
sbin_PROGRAMS = lctl lfind obdctl
sbin_SCRIPTS = lconf lmc
obdctl_SOURCES = parser.c obdctl.c obd.c parser.h obdctl.h
lctl_SOURCES = parser.c obd.c lctl.c parser.h
lfind_SOURCES = lfind.c
lfind_CPPFLAGS = -D_XOPEN_SOURCE=500
EXTRA_DIST = $(sbin_SCRIPTS)

include $(top_srcdir)/Rules
