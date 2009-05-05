noinst_PROGRAMS = test_copy test_stats test_path test_list \
	test_getcwd test_link test_unlink test_symlink test_rename \
	test_regions test_stddir test_fcntl_lock test_mknod test_mkdir \
	test_chown

CLEANFILES=drv_data.c

if WITH_NATIVE_DRIVER
NATIVE_DRIVER_NAME=native
NATIVE_DRIVER_CFLAGS= -I$(top_srcdir)/drivers/native
else
NATIVE_DRIVER_NAME=
NATIVE_DRIVER_CFLAGS=
endif

if WITH_INCORE_DRIVER
INCORE_DRIVER_NAME=incore
INCORE_DRIVER_CFLAGS= -I$(top_srcdir)/drivers/incore
else
INCORE_DRIVER_NAME=
INCORE_DRIVER_CFLAGS=
endif

if WITH_CPLANT_YOD
YOD_DRIVER_NAME=yod
YOD_DRIVER_CFLAGS= -DCPLANT_YOD
else
YOD_DRIVER_NAME=
YOD_DRIVER_CFLAGS=
endif

DRIVERS=$(NATIVE_DRIVER_NAME) $(INCORE_DRIVER_NAME) $(YOD_DRIVER_NAME) \
	$(STFD_DEV_NAME)

CMNSRC=startup.c drv_init_all.c drv_data.c

BUILT_SOURCES=drv_data.c

CFL=$(AM_CFLAGS) $(AM_CPPFLAGS) \
	$(NATIVE_DRIVER_CFLAGS) $(INCORE_DRIVER_CFLAGS) \
	$(STDFD_DEV_CFLAGS) $(YOD_DRIVER_CFLAGS)

LIBS=$(LIBBUILD_DIR)/libsysio.a

test_copy_SOURCES=test_copy.c $(CMNSRC)
test_copy_CFLAGS=$(CFL)
test_copy_DEPENDENCIES=$(LIBS)

test_stats_SOURCES=test_stats.c $(CMNSRC)
test_stats_CFLAGS=$(CFL)
test_stats_DEPENDENCIES=$(LIBS)

test_path_SOURCES=test_path.c $(CMNSRC)
test_path_CFLAGS=$(CFL)
test_path_DEPENDENCIES=$(LIBS)

test_list_SOURCES=test_list.c $(CMNSRC)
test_list_CFLAGS=$(CFL)
test_list_DEPENDENCIES=$(LIBS)

test_getcwd_SOURCES=test_getcwd.c $(CMNSRC)
test_getcwd_CFLAGS=$(CFL)
test_getcwd_DEPENDENCIES=$(LIBS)

test_link_SOURCES=test_link.c $(CMNSRC)
test_link_CFLAGS=$(CFL)
test_link_DEPENDENCIES=$(LIBS)

test_unlink_SOURCES=test_unlink.c $(CMNSRC)
test_unlink_CFLAGS=$(CFL)
test_unlink_DEPENDENCIES=$(LIBS)

test_symlink_SOURCES=test_symlink.c $(CMNSRC)
test_symlink_CFLAGS=$(CFL)
test_symlink_DEPENDENCIES=$(LIBS)

test_rename_SOURCES=test_rename.c $(CMNSRC)
test_rename_CFLAGS=$(CFL)
test_rename_DEPENDENCIES=$(LIBS)

test_regions_SOURCES=test_regions.c $(CMNSRC)
test_regions_CFLAGS=$(CFL)
test_regions_DEPENDENCIES=$(LIBS)

test_stddir_SOURCES=test_stddir.c $(CMNSRC)
test_stddir_CFLAGS=$(CFL)
test_stddir_DEPENDENCIES=$(LIBS)

test_fcntl_lock_SOURCES=test_fcntl_lock.c $(CMNSRC)
test_fcntl_lock_CFLAGS=$(CFL)
test_fcntl_lock_DEPENDENCIES=$(LIBS)

test_mknod_SOURCES=test_mknod.c $(CMNSRC)
test_mknod_CFLAGS=$(CFL)
test_mknod_DEPENDENCIES=$(LIBS)

test_mkdir_SOURCES=test_mkdir.c $(CMNSRC)
test_mkdir_CFLAGS=$(CFL)
test_mkdir_DEPENDENCIES=$(LIBS)

test_chown_SOURCES=test_chown.c $(CMNSRC)
test_chown_CFLAGS=$(CFL)
test_chown_DEPENDENCIES=$(LIBS)

drv_data.c: $(CONFIG_DEPENDENCIES) $(top_srcdir)/tests/gendrvdata.sh
	test -z "drv_data.c" && rm -f drv_data.c; \
	$(SHELL) $(top_srcdir)/tests/gendrvdata.sh $(DRIVERS) > drv_data.c

lib_LIBRARIES=libruntime.a

libruntime_a_SOURCES=sysio-run-start.c startup.c drv_init_all.c drv_data.c

AM_CFLAGS = -L$(LIBBUILD_DIR)
include $(top_srcdir)/Rules.make
