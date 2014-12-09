# Administration utilities Makefile

if GSS
SUBDIRS = gss
endif

AM_CFLAGS=$(LLCFLAGS)
AM_CPPFLAGS=$(LLCPPFLAGS) -DLUSTRE_UTILS=1 -D_FILE_OFFSET_BITS=64
AM_LDFLAGS := -L$(top_builddir)/lnet/utils

MNTMODLDFLAGS := -rdynamic -ldl
MNTMODCFLAGS := -DPLUGIN_DIR=\"${pkglibdir}\"

LIBPTLCTL := $(top_builddir)/lnet/utils/libptlctl.a \
	     $(top_builddir)/libcfs/libcfs/libcfsutil.a \
	     $(top_builddir)/libcfs/libcfs/libcfs.a

if TESTS
EXTRA_PROGRAMS = wirecheck
endif

if UTILS
# mount only finds helpers in /sbin
rootsbin_PROGRAMS = mount.lustre
bin_SCRIPTS   = llstat llobdstat plot-llstat
bin_PROGRAMS  = lfs
sbin_PROGRAMS = lctl l_getidentity llverfs lustre_rsync ltrack_stats

if TESTS
bin_PROGRAMS  += req_layout
sbin_PROGRAMS += wiretest
endif # TESTS

if SERVER
sbin_PROGRAMS += mkfs.lustre tunefs.lustre llverdev lr_reader \
	ll_recover_lost_found_objs ll_decode_filter_fid llog_reader
endif
if LIBPTHREAD
sbin_PROGRAMS += lhsmtool_posix
endif

pkglib_LTLIBRARIES =
lib_LIBRARIES = liblustreapi.a
if LDISKFS_ENABLED
lib_LIBRARIES += libiam.a
endif
noinst_LIBRARIES = liblustreapitmp.a
endif # UTILS

lctl_SOURCES = lustre_lfsck.c obd.c lustre_cfg.c lctl.c obdctl.h
lctl_LDADD :=  liblustreapi.a $(LIBPTLCTL) $(PTHREAD_LIBS) $(LIBREADLINE)
lctl_DEPENDENCIES := $(LIBPTLCTL) liblustreapi.a

lfs_SOURCES = lfs.c
lfs_LDADD := liblustreapi.a $(LIBPTLCTL) $(LIBREADLINE)
lfs_DEPENDENCIES := $(LIBPTLCTL) liblustreapi.a

lustre_rsync_SOURCES = lustre_rsync.c obd.c lustre_cfg.c lustre_rsync.h
lustre_rsync_LDADD :=  liblustreapi.a $(LIBPTLCTL) $(PTHREAD_LIBS) $(LIBREADLINE)
lustre_rsync_DEPENDENCIES := $(LIBPTLCTL) liblustreapi.a

ll_recover_lost_found_objs_SOURCES = ll_recover_lost_found_objs.c
ll_recover_lost_found_objs_LDADD := $(LIBPTLCTL)
ll_recover_lost_found_objs_DEPENDENCIES := $(LIBPTLCTL)

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

L_STRING := $(top_builddir)/libcfs/libcfs/user-string.c
L_IOCTL := $(top_builddir)/libcfs/libcfs/util/l_ioctl.c
L_KERNELCOMM := $(top_builddir)/libcfs/libcfs/kernel_user_comm.c
liblustreapitmp_a_SOURCES = liblustreapi.c liblustreapi_hsm.c \
			    liblustreapi_nodemap.c lustreapi_internal.h \
			    liblustreapi_json.c liblustreapi_layout.c \
			    liblustreapi_lease.c liblustreapi_util.c \
			    $(L_IOCTL) $(L_KERNELCOMM) $(L_STRING)

if UTILS
# build static and shared lib lustreapi
liblustreapi.a : liblustreapitmp.a
	rm -f liblustreapi.a liblustreapi.so
	$(CC) $(LDFLAGS) -shared -o liblustreapi.so `$(AR) -t liblustreapitmp.a`
	mv liblustreapitmp.a liblustreapi.a

install-exec-hook: liblustreapi.so
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	@list=$< ; for p in $$list; do \
	  if test -f $$p; then \
	    f="`echo $$p | sed -e 's|^.*/||'`"; \
	    echo " $(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/$$f"; \
	    $(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/$$f; \
	  else :; fi; \
	done
endif

if LDISKFS_ENABLED
libiam_a_SOURCES = libiam.c
endif

req_layout_SOURCES = req-layout.c

llog_reader_SOURCES = llog_reader.c
llog_reader_LDADD := $(LIBPTLCTL)
llog_reader_DEPENDENCIES := $(LIBPTLCTL)

lr_reader_SOURCES = lr_reader.c

if UTILS

if ZFS_ENABLED
pkglib_LTLIBRARIES += mount_osd_zfs.la

mount_osd_zfs_la_SOURCES = mount_utils_zfs.c
mount_osd_zfs_la_CPPFLAGS = -DHAVE_IOCTL_IN_UNISTD_H
mount_osd_zfs_la_CPPFLAGS += $(ZFS_LIBZFS_INCLUDE)
mount_osd_zfs_la_LDFLAGS =  -pthread $(ZFS_LIBZFS_LDFLAGS)
mount_osd_zfs_la_LDFLAGS += -shared -export-dynamic -module -avoid-version
endif

if LDISKFS_ENABLED
pkglib_LTLIBRARIES += mount_osd_ldiskfs.la

mount_osd_ldiskfs_la_SOURCES = mount_utils_ldiskfs.c
mount_osd_ldiskfs_la_LDFLAGS = -shared -export-dynamic -module -avoid-version
mount_osd_ldiskfs_la_LIBADD := $(SELINUX)
endif

mount_lustre_SOURCES = mount_lustre.c mount_utils.c mount_utils.h
mount_lustre_CPPFLAGS = $(AM_CPPFLAGS) ${MNTMODCFLAGS}
mount_lustre_LDADD := $(LIBPTLCTL) $(SELINUX)
mount_lustre_DEPENDENCIES := $(LIBPTLCTL)
mount_lustre_LDFLAGS = ${MNTMODLDFLAGS}

mkfs_lustre_SOURCES = mkfs_lustre.c mount_utils.c mount_utils.h
mkfs_lustre_CPPFLAGS = -UTUNEFS $(AM_CPPFLAGS) ${MNTMODCFLAGS}
mkfs_lustre_LDADD := $(LIBPTLCTL)
mkfs_lustre_DEPENDENCIES := $(LIBPTLCTL)
mkfs_lustre_LDFLAGS = ${MNTMODLDFLAGS}

tunefs_lustre_SOURCES = mkfs_lustre.c mount_utils.c mount_utils.h
tunefs_lustre_CPPFLAGS = -DTUNEFS $(AM_CPPFLAGS) ${MNTMODCFLAGS}
tunefs_lustre_LDADD := $(mkfs_lustre_LDADD)
tunefs_lustre_DEPENDENCIES := $(mkfs_lustre_DEPENDENCIES)
tunefs_lustre_LDFLAGS = ${MNTMODLDFLAGS}

l_getidentity_SOURCES = l_getidentity.c
l_getidentity_LDADD := $(LIBPTLCTL)
l_getidentity_DEPENDENCIES := $(LIBPTLCTL)

ltrack_stats_SOURCES = ltrack_stats.c

lhsmtool_posix_SOURCES = lhsmtool_posix.c
lhsmtool_posix_LDADD := liblustreapi.a $(LIBPTLCTL) $(PTHREAD_LIBS)
lhsmtool_posix_DEPENDENCIES := liblustreapi.a $(LIBPTLCTL)

wirecheck_SOURCES = wirecheck.c
wirecheck_CPPFLAGS = -DCC="\"$(CC)\""

wiretest_SOURCES = wiretest.c

endif # UTILS

EXTRA_DIST = llstat llobdstat plot-llstat

# NOTE: this should only be run on i386.
newwiretest: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	LANG=C ./wirecheck >> wiretest.c
	cp ../ptlrpc/wirehdr.c ../ptlrpc/wiretest.c
	LANG=C ./wirecheck >> ../ptlrpc/wiretest.c
