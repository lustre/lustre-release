DEFS=
MODULE = obdclass
modulefs_DATA = lustre_build_version obdclass.o
EXTRA_PROGRAMS = obdclass
obdclass_SOURCES = debug.c genops.c class_obd.c sysctl.c uuid.c lprocfs_status.c
include $(top_srcdir)/Rules
lustre_build_version:
	perl $(top_srcdir)/scripts/version_tag.pl $(top_srcdir) > tmpver
	diff -u tmpver $(top_builddir)/include/linux/lustre_build_version.h &&\
		$(RM) tmpver || \
		mv tmpver $(top_builddir)/include/linux/lustre_build_version.h
