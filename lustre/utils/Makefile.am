# Administration utilities Makefile
DEFS=
SUBDIRS = Lustre

CFLAGS:=-g -O2 -I$(top_srcdir)/utils -I$(top_srcdir)/portals/include  -I$(srcdir)/../include -Wall -L../portals/utils
KFLAGS:=
CPPFLAGS = $(HAVE_LIBREADLINE)
lctl_LDADD := $(LIBREADLINE) -lptlctl
lfs_LDADD := $(LIBREADLINE) parser.o liblustreapi.a
lload_LDADD := -lptlctl
sbin_PROGRAMS = lctl obdio obdbarrier lload wirecheck lfs llmount
sbin_SCRIPTS = \
	lconf lmc llanalyze llstat.pl llobdstat.pl lactive load_ldap.sh \
	lwizard
bin_SCRIPTS = lfind lstripe
lib_LIBRARIES = liblustreapi.a
liblustreapi_a_SOURCES = liblustreapi.c
wirecheck_SOURCES = wirecheck.c
lctl_SOURCES = parser.c obd.c lustre_cfg.c lctl.c parser.h obdctl.h
lload_SOURCES = lload.c 
obdio_SOURCES = obdio.c obdiolib.c obdiolib.h
obdbarrier_SOURCES = obdbarrier.c obdiolib.c obdiolib.h
lfs_SOURCES = lfs.c 
llmount_SOURCES = llmount.c

EXTRA_DIST = $(bin_SCRIPTS) $(sbin_SCRIPTS)

include $(top_srcdir)/Rules

wiretest.c: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	./wirecheck >> $@

