
# FIXME: we need to make it clear that obdclass.o depends on
# lustre_build_version, or 'make -j2' breaks!
DEFS=
MODULE = obdclass

if LINUX25
FSMOD = fsfilt_ext3
else
FSMOD = fsfilt_extN
endif

if LIBLUSTRE
lib_LIBRARIES = liblustreclass.a
liblustreclass_a_SOURCES = uuid.c statfs_pack.c genops.c debug.c class_obd.c lustre_handles.c lustre_peer.c lprocfs_status.c

class_obd.o: lustre_version

lustre_version:
	echo '#define LUSTRE_VERSION 12' > $(top_builddir)/include/linux/lustre_build_version.h
	echo '#define BUILD_VERSION "1"' >> $(top_builddir)/include/linux/lustre_build_version.h

else
modulefs_DATA = lustre_build_version obdclass.o $(FSMOD).o fsfilt_reiserfs.o
EXTRA_PROGRAMS = obdclass $(FSMOD) fsfilt_reiserfs

obdclass_SOURCES = class_obd.c debug.c genops.c sysctl.c uuid.c lprocfs_status.c lustre_handles.c lustre_peer.c
obdclass_SOURCES += fsfilt.c statfs_pack.c
endif

include $(top_srcdir)/Rules

# XXX I'm sure there's some automake mv-if-different helper for this.
lustre_build_version:
	perl $(top_srcdir)/scripts/version_tag.pl $(top_srcdir) $(top_builddir) > tmpver
	cmp -z $(top_builddir)/include/linux/lustre_build_version.h tmpver \
		2> /dev/null &&                                            \
		$(RM) tmpver ||                                            \
		mv tmpver $(top_builddir)/include/linux/lustre_build_version.h
