# Administration utilities Makefile

SUBDIRS = Lustre

AM_CFLAGS=$(LLCFLAGS)
AM_CPPFLAGS=$(LLCPPFLAGS) -DLUSTRE_UTILS=1

LIBPTLCTL := $(top_builddir)/portals/utils/libptlctl.a

sbin_scripts = lconf lmc llanalyze llstat.pl llobdstat.pl lactive	\
	load_ldap.sh lrun lwizard mount.lustre mkfs.lustre
bin_scripts = lfind lstripe llog_reader

if UTILS
rootsbin_SCRIPTS = mount.lustre mkfs.lustre
sbin_PROGRAMS = lctl obdio obdbarrier lload wirecheck wiretest mount.lustre mkfs.lustre
bin_PROGRAMS = lfs llog_reader
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

llog_reader_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
llog_reader_DEPENDENCIES := $(LIBPTLCTL)

liblustreapi_a_SOURCES = liblustreapi.c

wirecheck_SOURCES = wirecheck.c
wirecheck_CPPFLAGS = -DCC="\"$(CC)\""
wiretest_SOURCES = wiretest.c

lctl_SOURCES = parser.c obd.c lustre_cfg.c lctl.c parser.h obdctl.h

lload_SOURCES = lload.c 
obdio_SOURCES = obdio.c obdiolib.c obdiolib.h
obdbarrier_SOURCES = obdbarrier.c obdiolib.c obdiolib.h
lfs_SOURCES = lfs.c parser.c obd.c

mount_lustre_LDADD = $(LIBREADLINE) $(LIBPTLCTL)
mount_lustre_DEPENDENCIES := $(LIBPTLCTL)
mount_lustre_SOURCES = mount_lustre.c 

mkfs_lustre_LDADD = $(LIBREADLINE) $(LIBPTLCTL)
mkfs_lustre_DEPENDENCIES := $(LIBPTLCTL)
mkfs_lustre_SOURCES = mkfs_lustre.c lustre_cfg.c obd.c obdctl.h

llog_reader_SOURCES = llog_reader.c

EXTRA_DIST = $(bin_scripts) $(sbin_scripts)

# NOTE: this should only be run on i386.
newwiretest: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	./wirecheck >> wiretest.c

mount.lustre$(EXEEXT): mount_lustre
	cp $< $@

mkfs.lustre$(EXEEXT): mkfs_lustre
	cp $< $@
