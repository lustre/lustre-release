DEFS=
MODULE = obdclass

if LIBLUSTRE

noinst_LIBRARIES = liblustreclass.a
liblustreclass_a_SOURCES = class_obd.c debug.c genops.c statfs_pack.c uuid.c 
liblustreclass_a_SOURCES += lustre_handles.c lustre_peer.c lprocfs_status.c
liblustreclass_a_SOURCES += obdo.c obd_config.c llog.c llog_obd.c llog_cat.c
liblustreclass_a_SOURCES += llog_lvfs.c #llog_ioctl.c rbtree.c
liblustreclass_a_CFLAGS = -fPIC

class_obd.c: lustre_build_version

lustre_build_version:
	echo '#define LUSTRE_VERSION 32' > $(top_builddir)/include/linux/lustre_build_version.h
	echo '#define BUILD_VERSION "1"' >> $(top_builddir)/include/linux/lustre_build_version.h

else

class_obd.o: lustre_build_version

modulefs_DATA = lustre_build_version obdclass.o llog_test.o
EXTRA_PROGRAMS = obdclass llog_test

obdclass_SOURCES = llog.c llog_cat.c llog_lvfs.c llog_obd.c  class_obd.c debug.c genops.c sysctl.c uuid.c llog_ioctl.c
obdclass_SOURCES += lprocfs_status.c lustre_handles.c lustre_peer.c
obdclass_SOURCES += statfs_pack.c obdo.c obd_config.c llog_internal.h

lustre_build_version:
	perl $(top_srcdir)/scripts/version_tag.pl $(top_srcdir) $(top_builddir) > tmpver
	echo "#define LUSTRE_RELEASE @RELEASE@" >> tmpver
	cmp -s $(top_builddir)/include/linux/lustre_build_version.h tmpver \
                2> /dev/null &&                                            \
                $(RM) tmpver ||                                            \
                mv tmpver $(top_builddir)/include/linux/lustre_build_version.h
endif

include $(top_srcdir)/Rules

if LINUX25
# workaround for llog_test
llog_test.o: llog_test.c
	$(COMPILE) -UKBUILD_MODNAME -DKBUILD_MODNAME=llog_test -c -o llog_test_tmp.o $<
	rm -f llog_test_tmp.c
	$(LINUX)/scripts/modpost $(LINUX)/vmlinux llog_test_tmp.o
	$(COMPILE) -UKBUILD_MODNAME -UKBUILD_BASENAME -DKBUILD_BASENAME=llog_test \
		-c llog_test_tmp.mod.c
	$(LD) -m "`$(LD) --help | awk '/supported emulations/ {print $$4}'`" -r \
		-o llog_test.o llog_test_tmp.o llog_test_tmp.mod.o
endif
