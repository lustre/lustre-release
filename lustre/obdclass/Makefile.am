# FIXME: we need to make it clear that obdclass.o depends on
# lustre_build_version, or 'make -j2' breaks!
DEFS=
MODULE = obdclass
modulefs_DATA = lustre_build_version obdclass.o
EXTRA_PROGRAMS = obdclass
obdclass_SOURCES = debug.c genops.c class_obd.c sysctl.c uuid.c lprocfs_status.c
include $(top_srcdir)/Rules
lustre_build_version:
	perl $(top_srcdir)/scripts/version_tag.pl $(top_srcdir) > tmpver
	diff -u $(top_builddir)/include/linux/lustre_build_version.h tmpver \
			2> /dev/null &&\
		$(RM) tmpver || \
		mv tmpver $(top_builddir)/include/linux/lustre_build_version.h
