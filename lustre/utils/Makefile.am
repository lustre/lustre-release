# Administration utilities Makefile
DEFS=
SUBDIRS = Lustre

CFLAGS:=-g -O2 -I$(top_srcdir)/utils -I$(top_srcdir)/portals/include  -I$(srcdir)/../include -Wall -L../portals/utils
KFLAGS:=
CPPFLAGS = $(HAVE_LIBREADLINE)
lctl_LDADD := $(LIBREADLINE) -lptlctl
lload_LDADD := -lptlctl
sbin_PROGRAMS = lctl lfind lstripe obdio obdbarrier obdstat lload wirecheck
sbin_SCRIPTS = lconf lmc llanalyze
wirecheck_SOURCES = wirecheck.c
lctl_SOURCES = parser.c obd.c lctl.c parser.h obdctl.h
lload_SOURCES = lload.c 
obdio_SOURCES = obdio.c obdiolib.c obdiolib.h
obdbarrier_SOURCES = obdbarrier.c obdiolib.c obdiolib.h
lfind_SOURCES = lfind.c
lstripe_SOURCES = lstripe.c
lfind_CPPFLAGS = -D_XOPEN_SOURCE=500
EXTRA_DIST = $(sbin_SCRIPTS)

include $(top_srcdir)/Rules
