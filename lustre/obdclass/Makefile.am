# FIXME: we need to make it clear that obdclass.o depends on
# lustre_build_version, or 'make -j2' breaks!
DEFS=
MODULE = obdclass

if LINUX25
FSMOD = fsfilt_ext3
else
FSMOD = fsfilt_extN
endif

modulefs_DATA = lustre_build_version obdclass.o $(FSMOD).o fsfilt_reiserfs.o
EXTRA_PROGRAMS = obdclass $(FSMOD) fsfilt_reiserfs

obdclass_SOURCES = debug.c genops.c class_obd.c sysctl.c uuid.c lprocfs_status.c
obdclass_SOURCES += fsfilt.c statfs_pack.c

include $(top_srcdir)/Rules

# XXX I'm sure there's some automake mv-if-different helper for this.
lustre_build_version:
	perl $(top_srcdir)/scripts/version_tag.pl $(top_srcdir) $(top_builddir)> tmpver
	cmp -z $(top_builddir)/include/linux/lustre_build_version.h tmpver \
		2> /dev/null &&                                            \
		$(RM) tmpver ||                                            \
		mv tmpver $(top_builddir)/include/linux/lustre_build_version.h
