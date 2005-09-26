# Administration utilities Makefile

SUBDIRS = Lustre

AM_CFLAGS=$(LLCFLAGS)
AM_CPPFLAGS=$(LLCPPFLAGS) -DLUSTRE_UTILS=1
AM_LDFLAGS := -L$(top_builddir)/portals/utils

LIBPTLCTL := $(top_builddir)/portals/utils/libptlctl.a

sbin_scripts = lconf lmc llanalyze llstat.pl llobdstat.pl lactive	\
	load_ldap.sh lrun lwizard
bin_scripts = lfind lstripe

if UTILS
rootsbin_SCRIPTS = mount.lustre
sbin_PROGRAMS = lctl obdio obdbarrier lload wirecheck wiretest llmount  \
                l_getgroups
bin_PROGRAMS = lfs
lib_LIBRARIES = liblustreapi.a
sbin_SCRIPTS = $(sbin_scripts)
bin_SCRIPTS = $(bin_scripts)
endif # UTILS

lctl_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
lctl_DEPENDENCIES := $(LIBPTLCTL)

lfs_LDADD := $(LIBREADLINE) liblustreapi.a $(LIBPTLCTL)
lfs_DEPENDENCIES := $(LIBPTLCTL) liblustreapi.a

lload_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
lload_DEPENDENCIES := $(LIBPTLCTL)

liblustreapi_a_SOURCES = liblustreapi.c

wirecheck_SOURCES = wirecheck.c
wirecheck_CPPFLAGS = -DCC="\"$(CC)\""
wiretest_SOURCES = wiretest.c

lctl_SOURCES = parser.c obd.c lustre_cfg.c lctl.c parser.h obdctl.h
lload_SOURCES = lload.c 
obdio_SOURCES = obdio.c obdiolib.c obdiolib.h
obdbarrier_SOURCES = obdbarrier.c obdiolib.c obdiolib.h
lfs_SOURCES = lfs.c parser.c obd.c
llmount_SOURCES = llmount.c 
llmount_LDADD = $(LIBREADLINE) $(LIBPTLCTL)
llmount_DEPENDENCIES := $(LIBPTLCTL)

EXTRA_DIST = $(bin_scripts) $(sbin_scripts)

# NOTE: this should only be run on i386.
newwiretest: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	./wirecheck >> wiretest.c

mount.lustre$(EXEEXT): llmount
	cp $< $@
