DEFS=
MODULE = obdclass

if EXTN
FSMOD = fsfilt_extN
else
FSMOD = fsfilt_ext3
endif

class_obd.o: lustre_build_version

if LIBLUSTRE
lib_LIBRARIES = liblustreclass.a
liblustreclass_a_SOURCES = uuid.c statfs_pack.c genops.c debug.c class_obd.c
liblustreclass_a_SOURCES += lustre_handles.c lustre_peer.c lprocfs_status.c
liblustreclass_a_SOURCES += simple.c recov_log.c obdo.c

else
modulefs_DATA = lustre_build_version obdclass.o $(FSMOD).o fsfilt_reiserfs.o
EXTRA_PROGRAMS = obdclass $(FSMOD) fsfilt_reiserfs

obdclass_SOURCES = class_obd.c debug.c genops.c sysctl.c uuid.c simple.c
obdclass_SOURCES += lprocfs_status.c lustre_handles.c lustre_peer.c
obdclass_SOURCES += fsfilt.c statfs_pack.c otree.c recov_log.c obdo.c
endif

include $(top_srcdir)/Rules

lustre_build_version:
	perl $(top_srcdir)/scripts/version_tag.pl $(top_srcdir) $(top_builddir) > tmpver
	echo #define LUSTRE_RELEASE @RELEASE@ >> tmpver
	cmp -s $(top_builddir)/include/linux/lustre_build_version.h tmpver \
                2> /dev/null &&                                            \
                $(RM) tmpver ||                                            \
                mv tmpver $(top_builddir)/include/linux/lustre_build_version.h

