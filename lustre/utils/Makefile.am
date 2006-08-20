# Administration utilities Makefile

AM_CFLAGS=$(LLCFLAGS)
AM_CPPFLAGS=$(LLCPPFLAGS) -DLUSTRE_UTILS=1
AM_LDFLAGS := -L$(top_builddir)/lnet/utils

LIBPTLCTL := $(top_builddir)/lnet/utils/libptlctl.a

sbin_scripts = llstat.pl llobdstat.pl lrun 

if UTILS
noinst_PROGRAMS = mount_lustre mkfs_lustre tunefs_lustre \
	llog_reader lr_reader wirecheck wiretest lload obdio obdbarrier
# mount only finds helpers in /sbin
rootsbin_PROGRAMS = mount.lustre
sbin_PROGRAMS = mkfs.lustre tunefs.lustre lctl \
	l_getgroups llverfs llverdev
bin_PROGRAMS = lfs req_layout
sbin_SCRIPTS = $(sbin_scripts)
endif # UTILS

lib_LIBRARIES = liblustreapi.a libiam.a

lctl_SOURCES = parser.c obd.c lustre_cfg.c lctl.c parser.h obdctl.h platform.h
lctl_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
lctl_DEPENDENCIES := $(LIBPTLCTL)

lfs_SOURCES = lfs.c parser.c obd.c
lfs_LDADD := $(LIBREADLINE) liblustreapi.a $(LIBPTLCTL)
lfs_DEPENDENCIES := $(LIBPTLCTL) liblustreapi.a 

lload_SOURCES = lload.c 
lload_LDADD := $(LIBREADLINE) $(LIBPTLCTL)
lload_DEPENDENCIES := $(LIBPTLCTL)

if EXT2FS_DEVEL
EXT2FSLIB = -lext2fs
E2PLIB = -le2p
else
E2PLIB = 
EXT2FSLIB =
endif

if BLKID
BLKIDLIB = -lblkid
else
BLKIDLIB =
endif

llverfs_LDADD := $(EXT2FSLIB) $(E2PLIB)

llverdev_LDADD := $(EXT2FSLIB) $(BLKIDLIB)

liblustreapi_a_SOURCES = liblustreapi.c
libiam_a_SOURCES = libiam.c

wirecheck_SOURCES = wirecheck.c
wirecheck_CPPFLAGS = -DCC="\"$(CC)\""

wiretest_SOURCES = wiretest.c

obdio_SOURCES = obdio.c obdiolib.c obdiolib.h
obdbarrier_SOURCES = obdbarrier.c obdiolib.c obdiolib.h
req_layout_SOURCES = req-layout.c

llog_reader_SOURCES = llog_reader.c
llog_reader_LDADD := $(LIBPTLCTL)
llog_reader_DEPENDENCIES := $(LIBPTLCTL)

lr_reader_SOURCES = lr_reader.c

mount_lustre_SOURCES = mount_lustre.c 
mount_lustre_LDADD := $(LIBPTLCTL)
mount_lustre_DEPENDENCIES := $(LIBPTLCTL)

mkfs_lustre_SOURCES = mkfs_lustre.c
mkfs_lustre_CPPFLAGS = -UTUNEFS $(AM_CPPFLAGS)
mkfs_lustre_LDADD := libiam.a $(LIBPTLCTL)
mkfs_lustre_DEPENDENCIES := $(LIBPTLCTL) libiam.a

tunefs_lustre_SOURCES = $(mkfs_lustre_SOURCES)
tunefs_lustre_CPPFLAGS = -DTUNEFS $(AM_CPPFLAGS)
tunefs_lustre_LDADD := $(mkfs_lustre_LDADD)
tunefs_lustre_DEPENDENCIES := $(mkfs_lustre_DEPENDENCIES)

EXTRA_DIST = $(sbin_scripts)

# NOTE: this should only be run on i386.
newwiretest: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	./wirecheck >> wiretest.c
	cp ../ptlrpc/wirehdr.c ../ptlrpc/wiretest.c
	./wirecheck >> ../ptlrpc/wiretest.c

# Apparently I can't use .'s in automake names
mount.lustre$(EXEEXT): mount_lustre
	cp $< $@

mkfs.lustre$(EXEEXT): mkfs_lustre
	cp $< $@

tunefs.lustre$(EXEEXT): tunefs_lustre
	cp $< $@
