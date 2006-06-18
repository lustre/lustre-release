# Administration utilities Makefile

SUBDIRS = Lustre

AM_CFLAGS=$(LLCFLAGS)
AM_CPPFLAGS=$(LLCPPFLAGS) -DLUSTRE_UTILS=1
AM_LDFLAGS := -L$(top_builddir)/lnet/utils

LIBPTLCTL := $(top_builddir)/lnet/utils/libptlctl.a

sbin_scripts = llanalyze llstat.pl llobdstat.pl lactive lrun 
bin_scripts = lfind lstripe

if UTILS
# mount only finds helpers in /sbin
rootsbin_PROGRAMS = mount.lustre
sbin_PROGRAMS = lctl obdio obdbarrier lload wirecheck wiretest \
	mount_lustre mkfs_lustre mkfs.lustre \
	tunefs_lustre tunefs.lustre l_getgroups
bin_PROGRAMS = lfs llog_reader create_iam req_layout
lib_LIBRARIES = liblustreapi.a
sbin_SCRIPTS = $(sbin_scripts)
bin_SCRIPTS = $(bin_scripts)
endif # UTILS

lctl_SOURCES = parser.c obd.c lustre_cfg.c lctl.c parser.h obdctl.h platform.h
lctl_LDADD := $(LIBREADLINE) $(LIBPTLCTL) 
lctl_DEPENDENCIES := $(LIBPTLCTL) 

lfs_SOURCES = lfs.c parser.c obd.c
lfs_LDADD := $(LIBREADLINE) liblustreapi.a $(LIBPTLCTL)
lfs_DEPENDENCIES := $(LIBPTLCTL) liblustreapi.a 

lload_SOURCES = lload.c 
lload_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
lload_DEPENDENCIES := $(LIBPTLCTL)

liblustreapi_a_SOURCES = liblustreapi.c

wirecheck_SOURCES = wirecheck.c
wirecheck_CPPFLAGS = -DCC="\"$(CC)\""

wiretest_SOURCES = wiretest.c

obdio_SOURCES = obdio.c obdiolib.c obdiolib.h
obdbarrier_SOURCES = obdbarrier.c obdiolib.c obdiolib.h
create_iam_SOURCES = create_iam.c
req_layout_SOURCES = create-iam.c

llog_reader_SOURCES = llog_reader.c
llog_reader_LDADD := $(LIBPTLCTL)
llog_reader_DEPENDENCIES := $(LIBPTLCTL)

mount_lustre_SOURCES = mount_lustre.c 
mount_lustre_LDADD := $(LIBPTLCTL)
mount_lustre_DEPENDENCIES := $(LIBPTLCTL)

mkfs_lustre_SOURCES = mkfs_lustre.c
mkfs_lustre_CPPFLAGS = -UTUNEFS $(AM_CPPFLAGS)
mkfs_lustre_LDADD := $(LIBPTLCTL)
mkfs_lustre_DEPENDENCIES := $(LIBPTLCTL)

tunefs_lustre_SOURCES = $(mkfs_lustre_SOURCES)
tunefs_lustre_CPPFLAGS = -DTUNEFS $(AM_CPPFLAGS)
tunefs_lustre_LDADD := $(mkfs_lustre_LDADD)
tunefs_lustre_DEPENDENCIES := $(mkfs_lustre_DEPENDENCIES)

EXTRA_DIST = $(bin_scripts) $(sbin_scripts)

# NOTE: this should only be run on i386.
newwiretest: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	./wirecheck >> wiretest.c

# Apparently I can't use .'s in automake names
mount.lustre$(EXEEXT): mount_lustre
	cp $< $@

mkfs.lustre$(EXEEXT): mkfs_lustre
	cp $< $@

tunefs.lustre$(EXEEXT): tunefs_lustre
	cp $< $@
