# Administration utilities Makefile

AM_CFLAGS  := -fPIC -D_GNU_SOURCE \
	      -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS=1
AM_LDFLAGS := -L$(top_builddir)/lnet/utils

LIBCFS := $(top_builddir)/libcfs/libcfs/libcfs.a

if TESTS
EXTRA_PROGRAMS = wirecheck
endif

if UTILS

if GSS
SUBDIRS = gss
GSSSRC = gss/err_util.c gss/err_util.h
if GSS_SSK
GSSSRC += gss/sk_utils.c gss/sk_utils.h
endif
GSSLIB = -lcrypto -lssl -lkeyutils -lm
else
GSSSRC =
GSSLIB =
endif

# mount only finds helpers in /sbin
rootsbin_PROGRAMS = mount.lustre
bin_SCRIPTS   = llstat llobdstat plot-llstat
bin_PROGRAMS  = lfs
sbin_SCRIPTS  = ldlm_debug_upcall
sbin_PROGRAMS = lctl l_getidentity llverfs lustre_rsync ll_decode_linkea

if TESTS
sbin_PROGRAMS += wiretest
endif # TESTS

if SERVER
sbin_PROGRAMS += mkfs.lustre tunefs.lustre llverdev lr_reader lshowmount \
		 ll_decode_filter_fid llog_reader
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

lctl_SOURCES = portals.c debug.c obd.c lustre_cfg.c lctl.c obdctl.h
if SERVER
lctl_SOURCES += lustre_lfsck.c lsnapshot.c
endif
lctl_LDADD :=  liblustreapi.a $(LIBCFS) $(LIBREADLINE) $(PTHREAD_LIBS)
lctl_DEPENDENCIES := $(LIBCFS) liblustreapi.a

lfs_SOURCES = lfs.c
lfs_LDADD := liblustreapi.a $(LIBCFS) $(LIBREADLINE)
lfs_DEPENDENCIES := $(LIBCFS) liblustreapi.a

lustre_rsync_SOURCES = lustre_rsync.c lustre_rsync.h
lustre_rsync_LDADD :=  liblustreapi.a $(LIBCFS) $(LIBREADLINE) $(PTHREAD_LIBS)
lustre_rsync_DEPENDENCIES := $(LIBCFS) liblustreapi.a

lshowmount_SOURCES = lshowmount.c nidlist.c nidlist.h
lshowmount_LDADD :=  liblustreapi.a

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

liblustreapitmp_a_SOURCES = liblustreapi.c liblustreapi_hsm.c \
			    liblustreapi_nodemap.c lustreapi_internal.h \
			    liblustreapi_json.c liblustreapi_layout.c \
			    liblustreapi_lease.c liblustreapi_util.c \
			    liblustreapi_kernelconn.c liblustreapi_param.c \
			    liblustreapi_mirror.c \
			    $(top_builddir)/libcfs/libcfs/util/string.c \
			    $(top_builddir)/libcfs/libcfs/util/param.c \
			    liblustreapi_ladvise.c liblustreapi_chlg.c
if UTILS
LIB_TARGETS = liblustreapi.so
if PLUGINS
if LDISKFS_ENABLED
LIB_TARGETS += mount_osd_ldiskfs.so
endif
if ZFS_ENABLED
LIB_TARGETS += mount_osd_zfs.so
endif
endif

# build static and shared lib lustreapi
liblustreapi.a : liblustreapitmp.a
	rm -f liblustreapi.a liblustreapi.so
	$(CC) $(LDFLAGS) -shared -o liblustreapi.so `$(AR) -t liblustreapitmp.a`
	mv liblustreapitmp.a liblustreapi.a

install-exec-hook:
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	$(mkinstalldirs) $(DESTDIR)$(libdir)/lustre
	for p in $(LIB_TARGETS); do \
	  if test -f $$p; then \
	    f="`echo $$p | sed -e 's|^.*/||'`"; \
	    if `echo -n $$p | grep -q mount`; then \
		echo " $(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/lustre/$$f"; \
		$(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/lustre/$$f; \
	    else \
		echo " $(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/$$f"; \
		$(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/$$f; \
	    fi; \
	  else :; fi; \
	done
endif # UTILS

if LDISKFS_ENABLED
libiam_a_SOURCES = libiam.c
endif

llog_reader_SOURCES = llog_reader.c
llog_reader_LDADD := $(LIBCFS) liblustreapi.a
llog_reader_DEPENDENCIES := $(LIBCFS) liblustreapi.a

lr_reader_SOURCES = lr_reader.c

lib_LTLIBRARIES =

if UTILS

PLUGIN_LIB =
if PLUGINS
MNTMODLDFLAGS := -rdynamic -ldl
MNTMODCFLAGS := -DPLUGIN_DIR=\"${pkglibdir}\"
endif # PLUGINS

if ZFS_ENABLED
noinst_LIBRARIES += libmount_utils_zfs.a

libmount_utils_zfs_a_SOURCES = libmount_utils_zfs.c
libmount_utils_zfs_a_CPPFLAGS := -DHAVE_IOCTL_IN_UNISTD_H $(ZFS_LIBZFS_INCLUDE)

if PLUGINS
lib_LTLIBRARIES += libmount_utils_zfs.la
libmount_utils_zfs.la : libmount_utils_zfs.a
	$(CC) $(LDFLAGS) $(MNTMODLDFLAGS) -shared -export-dynamic -pthread \
			 $(ZFS_LIBZFS_LDFLAGS) -o mount_osd_zfs.so \
			 `$(AR) -t libmount_utils_zfs.a`
else
MNTMODLDFLAGS := $(ZFS_LIBZFS_LDFLAGS)
PLUGIN_LIB += libmount_utils_zfs.a
endif # PLUGINS
endif # ZFS_ENABLED

if LDISKFS_ENABLED
noinst_LIBRARIES += libmount_utils_ldiskfs.a

libmount_utils_ldiskfs_a_SOURCES = libmount_utils_ldiskfs.c
libmount_utils_ldiskfs_a_CPPFLAGS := $(SELINUX)

if PLUGINS
lib_LTLIBRARIES += libmount_utils_ldiskfs.la
libmount_utils_ldiskfs.la : libmount_utils_ldiskfs.a
	$(CC) $(LDFLAGS) $(MNTMODLDFLAGS) -shared -export-dynamic \
			 $(SELINUX) -o mount_osd_ldiskfs.so \
			 `$(AR) -t libmount_utils_ldiskfs.a`
else
PLUGIN_LIB += libmount_utils_ldiskfs.a
endif # PLUGINS
endif # LDISKFS_ENABLED

mount_lustre_SOURCES = mount_lustre.c mount_utils.c mount_utils.h $(GSSSRC)
mount_lustre_CPPFLAGS := ${MNTMODCFLAGS}
mount_lustre_LDFLAGS  := ${MNTMODLDFLAGS}
mount_lustre_LDADD    := $(LIBCFS) $(SELINUX) $(LDLIBMOUNT) $(PLUGIN_LIB) $(GSSLIB)

mkfs_lustre_SOURCES = mkfs_lustre.c mount_utils.c mount_utils.h $(GSSSRC)
mkfs_lustre_CPPFLAGS := -UTUNEFS ${MNTMODCFLAGS}
mkfs_lustre_LDFLAGS  := ${MNTMODLDFLAGS}
mkfs_lustre_LDADD    := $(mount_lustre_LDADD)

tunefs_lustre_SOURCES = mkfs_lustre.c mount_utils.c mount_utils.h $(GSSSRC)
tunefs_lustre_CPPFLAGS := -DTUNEFS ${MNTMODCFLAGS}
tunefs_lustre_LDFLAGS  := ${MNTMODLDFLAGS}
tunefs_lustre_LDADD    := $(mkfs_lustre_LDADD)

l_getidentity_SOURCES = l_getidentity.c
l_getidentity_LDADD := $(LIBCFS)
l_getidentity_DEPENDENCIES := $(LIBCFS)

lhsmtool_posix_SOURCES = lhsmtool_posix.c
lhsmtool_posix_LDADD := liblustreapi.a $(LIBCFS) $(PTHREAD_LIBS)
lhsmtool_posix_DEPENDENCIES := liblustreapi.a $(LIBCFS)

wirecheck_SOURCES = wirecheck.c
wirecheck_CPPFLAGS := -DCC="\"$(CC)\""

wiretest_SOURCES = wiretest.c

endif # UTILS

EXTRA_DIST = llstat llobdstat plot-llstat ldlm_debug_upcall

# NOTE: this should only be run on i386.
newwiretest: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	LANG=C ./wirecheck >> wiretest.c
	cp ../ptlrpc/wirehdr.c ../ptlrpc/wiretest.c
	LANG=C ./wirecheck >> ../ptlrpc/wiretest.c
