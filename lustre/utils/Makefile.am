# Administration utilities Makefile

SUBDIRS = Lustre

AM_CFLAGS=$(LLCFLAGS)
AM_CPPFLAGS=$(LLCPPFLAGS) -DLUSTRE_UTILS=1
AM_LDFLAGS := -L$(top_builddir)/lnet/utils

LIBPTLCTL := $(top_builddir)/lnet/utils/libptlctl.a

sbin_scripts = lconf lmc llanalyze llstat.pl llobdstat.pl lactive	\
	load_ldap.sh lrun lwizard
bin_scripts = lfind lstripe

if UTILS
rootsbin_SCRIPTS =
sbin_PROGRAMS = lctl obdio obdbarrier lload wirecheck wiretest \
	mount_lustre mount.lustre mkfs_lustre mkfs.lustre l_getgroups 
bin_PROGRAMS = lfs llog_reader
lib_LIBRARIES = liblustreapi.a
sbin_SCRIPTS = $(sbin_scripts)
bin_SCRIPTS = $(bin_scripts)
endif # UTILS

liblustreapi_a_SOURCES = liblustreapi.c

wirecheck_SOURCES = wirecheck.c
wirecheck_CPPFLAGS = -DCC="\"$(CC)\""
wiretest_SOURCES = wiretest.c

lctl_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
lctl_DEPENDENCIES := $(LIBPTLCTL)
lctl_SOURCES = parser.c obd.c lustre_cfg.c lctl.c parser.h obdctl.h

lload_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
lload_DEPENDENCIES := $(LIBPTLCTL)
lload_SOURCES = lload.c 

obdio_SOURCES = obdio.c obdiolib.c obdiolib.h
obdbarrier_SOURCES = obdbarrier.c obdiolib.c obdiolib.h

lfs_LDADD := $(LIBREADLINE) liblustreapi.a $(LIBPTLCTL)
lfs_DEPENDENCIES := $(LIBPTLCTL) liblustreapi.a
lfs_SOURCES = lfs.c parser.c obd.c

llog_reader_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
llog_reader_DEPENDENCIES := $(LIBPTLCTL)
llog_reader_SOURCES = llog_reader.c

# FIXME whats this GM stuff for??
mount_lustre_CFLAGS = $(LLMOUNT_GM_CFLAGS)
mount_lustre_LDADD := $(LIBREADLINE) $(LIBPTLCTL) $(LLMOUNT_GM_LDADD)
mount_lustre_DEPENDENCIES := $(LIBPTLCTL)
mount_lustre_SOURCES = mount_lustre.c 

mkfs_lustre_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
mkfs_lustre_DEPENDENCIES := $(LIBPTLCTL)
mkfs_lustre_SOURCES = parser.c obd.c lustre_cfg.c mkfs_lustre.c parser.h obdctl.h

EXTRA_DIST = $(bin_scripts) $(sbin_scripts)

# NOTE: this should only be run on i386.
newwiretest: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	./wirecheck >> wiretest.c

mount.lustre$(EXEEXT): mount_lustre
	cp $< $@

mkfs.lustre$(EXEEXT): mkfs_lustre
	cp $< $@
