# Administration utilities Makefile

SUBDIRS = Lustre

AM_CFLAGS=$(LLCFLAGS)
AM_CPPFLAGS=$(LLCPPFLAGS)
AM_LDFLAGS := -L$(top_builddir)/portals/utils

if UTILS
rootsbin_SCRIPTS = mount.lustre
sbin_PROGRAMS = lctl obdio obdbarrier lload wirecheck wiretest llmount
sbin_SCRIPTS = lconf lmc llanalyze llstat.pl llobdstat.pl lactive load_ldap.sh lrun
sbin_SCRIPTS += lwizard
bin_SCRIPTS = lfind lstripe
bin_PROGRAMS = lfs
lib_LIBRARIES = liblustreapi.a
if LIBLUSTRE
sbin_SCRIPTS += lrun
endif # LIBLUSTRE
endif # UTILS

lctl_LDADD := $(LIBREADLINE) -lptlctl
lfs_LDADD := $(LIBREADLINE) parser.o liblustreapi.a -lptlctl obd.o
lload_LDADD := $(LIBREADLINE) -lptlctl
liblustreapi_a_SOURCES = liblustreapi.c
wirecheck_SOURCES = wirecheck.c
wiretest_SOURCES = wiretest.c
lctl_SOURCES = parser.c obd.c lustre_cfg.c lctl.c parser.h obdctl.h
lload_SOURCES = lload.c 
obdio_SOURCES = obdio.c obdiolib.c obdiolib.h
obdbarrier_SOURCES = obdbarrier.c obdiolib.c obdiolib.h
lfs_SOURCES = lfs.c 
llmount_SOURCES = llmount.c 
llmount_LDADD = $(LIBREADLINE) -lptlctl

EXTRA_DIST = $(bin_SCRIPTS) $(sbin_SCRIPTS)

# NOTE: this should only be run on i386.
newwiretest: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	./wirecheck >> wiretest.c

mount.lustre$(EXEEXT): llmount
	cp $< $@
