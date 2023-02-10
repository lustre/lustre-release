# Administration utilities Makefile

AM_CFLAGS  := -fPIC -D_GNU_SOURCE \
	      -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS=1 $(UTILS_CFLAGS)
AM_LDFLAGS := $(UTILS_LDFLAGS)

if TESTS
EXTRA_PROGRAMS = wirecheck
endif

if UTILS

if GSS
SUBDIRS = . gss
GSSSRC = gss/err_util.c gss/err_util.h
GSSLIB = -lm
if GSS_SSK
GSSSRC += gss/sk_utils.c gss/sk_utils.h
GSSLIB += -lkeyutils -lcrypto -lssl
endif
if GSS_KEYRING
GSSLIB += -lkeyutils
endif
else
GSSSRC =
GSSLIB =
endif

# mount only finds helpers in /sbin
rootsbin_PROGRAMS = mount.lustre
if SERVER
rootsbin_PROGRAMS += mount.lustre_tgt
endif
bin_SCRIPTS   = llstat llobdstat plot-llstat
bin_PROGRAMS  = lfs
sbin_SCRIPTS  = ldlm_debug_upcall
sbin_PROGRAMS = lctl l_getidentity llverfs lustre_rsync ll_decode_linkea \
		llsom_sync l_foreign_symlink

if TESTS
sbin_PROGRAMS += wiretest
endif # TESTS

if SERVER
sbin_PROGRAMS += mkfs.lustre tunefs.lustre llverdev lr_reader lshowmount \
		 ll_decode_filter_fid llog_reader l_tunedisk \
		 ofd_access_log_reader
endif
if LIBPTHREAD
sbin_PROGRAMS += lhsmtool_posix
endif

if SELINUX
if GETSEPOL
sbin_PROGRAMS += l_getsepol
endif
endif
endif # UTILS

lib_LIBRARIES =
noinst_LIBRARIES =
if LDISKFS_ENABLED
libiam_a_SOURCES = libiam.c
lib_LIBRARIES += libiam.a
endif

pkglib_LTLIBRARIES =
lib_LTLIBRARIES = liblustreapi.la

lctl_SOURCES = portals.c debug.c obd.c lustre_cfg.c lctl.c obdctl.h
if SERVER
lctl_SOURCES += lustre_lfsck.c lsnapshot.c
endif
lctl_LDADD :=  liblustreapi.la $(PTHREAD_LIBS) -lyaml
lctl_DEPENDENCIES := liblustreapi.la

lfs_SOURCES = lfs.c lfs_project.c lfs_project.h
lfs_CFLAGS := -fPIC $(AM_CFLAGS) -I $(top_builddir)/lnet/utils
lfs_LDADD := liblustreapi.la -lz
lfs_LDADD += $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la
lfs_DEPENDENCIES := liblustreapi.la

lustre_rsync_SOURCES = lustre_rsync.c lustre_rsync.h callvpe.c callvpe.h
lustre_rsync_LDADD :=  liblustreapi.la $(PTHREAD_LIBS)
lustre_rsync_DEPENDENCIES := liblustreapi.la

llsom_sync_LDADD := liblustreapi.la
llsom_sync_DEPENDENCIES := liblustreapi.la

lshowmount_SOURCES = lshowmount.c nidlist.c nidlist.h
lshowmount_LDADD :=  liblustreapi.la

if EXT2FS_DEVEL
EXT2FSLIB = -lext2fs
E2PLIB = -le2p
else
E2PLIB =
EXT2FSLIB =
endif

llverfs_LDADD := $(EXT2FSLIB) $(E2PLIB)

liblustreapi_la_SOURCES = liblustreapi.c liblustreapi_hsm.c \
			  liblustreapi_nodemap.c lustreapi_internal.h \
			  liblustreapi_json.c liblustreapi_layout.c \
			  liblustreapi_lease.c liblustreapi_util.c \
			  liblustreapi_kernelconn.c liblustreapi_param.c \
			  liblustreapi_mirror.c liblustreapi_fid.c \
			  liblustreapi_ladvise.c liblustreapi_chlg.c \
			  liblustreapi_heat.c liblustreapi_pcc.c \
			  liblustreapi_lseek.c liblustreapi_swap.c
liblustreapi_la_LDFLAGS = $(LIBREADLINE) -version-info 1:0:0 \
			  -Wl,--version-script=liblustreapi.map
liblustreapi_la_LIBADD = $(top_builddir)/libcfs/libcfs/libcfs.la \
			 $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la \
			 -lpthread

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lustre.pc

if UTILS
LIB_TARGETS =
if PLUGINS
if LDISKFS_ENABLED
LIB_TARGETS += mount_osd_ldiskfs.so
endif
if ZFS_ENABLED
LIB_TARGETS += mount_osd_zfs.so
endif
endif

install-exec-hook:
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	$(mkinstalldirs) $(DESTDIR)$(libdir)/lustre
	for p in $(LIB_TARGETS); do \
	  if test -f $$p; then \
	    f="`echo $$p | sed -e 's|^.*/||'`"; \
	    echo " $(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/lustre/$$f"; \
	    $(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/lustre/$$f; \
	  else :; fi; \
	done
endif # UTILS

llog_reader_SOURCES = llog_reader.c
llog_reader_LDADD := liblustreapi.la
llog_reader_DEPENDENCIES := liblustreapi.la

lr_reader_SOURCES = lr_reader.c

ofd_access_log_reader_SOURCES = \
	lstddef.h \
	ofd_access_batch.c \
	ofd_access_batch.h \
	ofd_access_log_reader.c
ofd_access_log_reader_LDADD := -lpthread

if UTILS

PLUGIN_LIB =
if PLUGINS
MNTMODLDFLAGS := -rdynamic
MNTMODLIBS := -ldl
MNTMODCFLAGS := -DPLUGIN_DIR=\"${pkglibdir}\"
else
MNTMODLIBS :=
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
			 `$(AR) -t libmount_utils_zfs.a` \
			 $(MNTMODLIBS) $(ZFS_LIBZFS_LIBS)
else
MNTMODLDFLAGS := $(ZFS_LIBZFS_LDFLAGS)
MNTMODLIBS += $(ZFS_LIBZFS_LIBS)
PLUGIN_LIB += libmount_utils_zfs.a
endif # PLUGINS
endif # ZFS_ENABLED

if LDISKFS_ENABLED
noinst_LIBRARIES += libmount_utils_ldiskfs.a

libmount_utils_ldiskfs_a_SOURCES = libmount_utils_ldiskfs.c
libmount_utils_ldiskfs_a_CPPFLAGS :=

if PLUGINS
lib_LTLIBRARIES += libmount_utils_ldiskfs.la
libmount_utils_ldiskfs.la : libmount_utils_ldiskfs.a
	$(CC) $(LDFLAGS) $(MNTMODLDFLAGS) -shared -export-dynamic \
			 -o mount_osd_ldiskfs.so \
			 `$(AR) -t libmount_utils_ldiskfs.a` \
			 $(MNTMODLIBS) -lext2fs
else
MNTMODLIBS += -lext2fs
PLUGIN_LIB += libmount_utils_ldiskfs.a
endif # PLUGINS
endif # LDISKFS_ENABLED

mount_lustre_SOURCES = mount_lustre.c mount_utils.c mount_utils.h $(GSSSRC)
mount_lustre_CPPFLAGS := ${MNTMODCFLAGS}
mount_lustre_LDFLAGS  := ${MNTMODLDFLAGS}
mount_lustre_LDADD    := $(SELINUX) $(LDLIBMOUNT) $(PLUGIN_LIB) $(GSSLIB) \
			 $(top_builddir)/libcfs/libcfs/libcfs.la $(MNTMODLIBS)
mount_lustre_tgt_SOURCES = ${mount_lustre_SOURCES}
mount_lustre_tgt_CPPFLAGS = ${mount_lustre_CPPFLAGS}
mount_lustre_tgt_LDFLAGS = ${mount_lustre_LDFLAGS}
mount_lustre_tgt_LDADD = ${mount_lustre_LDADD}

mkfs_lustre_SOURCES = mkfs_lustre.c mount_utils.c mount_utils.h $(GSSSRC)
mkfs_lustre_CPPFLAGS := -UTUNEFS ${MNTMODCFLAGS}
mkfs_lustre_LDFLAGS  := ${MNTMODLDFLAGS}
mkfs_lustre_LDADD    := $(mount_lustre_LDADD)

tunefs_lustre_SOURCES = mkfs_lustre.c mount_utils.c mount_utils.h $(GSSSRC)
tunefs_lustre_CPPFLAGS := -DTUNEFS ${MNTMODCFLAGS}
tunefs_lustre_LDFLAGS  := ${MNTMODLDFLAGS}
tunefs_lustre_LDADD    := $(mkfs_lustre_LDADD)

l_tunedisk_SOURCES = l_tunedisk.c mount_utils.c mount_utils.h $(GSSSRC)
l_tunedisk_CPPFLAGS := ${MNTMODCFLAGS}
l_tunedisk_LDFLAGS  := ${MNTMODLDFLAGS}
l_tunedisk_LDADD    := $(mount_lustre_LDADD)

l_foreign_symlink_SOURCES = l_foreign_symlink.c
l_foreign_symlink_LDADD := $(top_builddir)/libcfs/libcfs/libcfs.la
l_foreign_symlink_DEPENDENCIES := $(top_builddir)/libcfs/libcfs/libcfs.la

l_getidentity_SOURCES = l_getidentity.c
l_getidentity_LDADD := $(top_builddir)/libcfs/libcfs/libcfs.la
l_getidentity_DEPENDENCIES := $(top_builddir)/libcfs/libcfs/libcfs.la

lhsmtool_posix_SOURCES = lhsmtool_posix.c pid_file.c pid_file.h
lhsmtool_posix_LDADD := liblustreapi.la $(PTHREAD_LIBS) \
		$(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la

l_getsepol_SOURCES = l_getsepol.c
l_getsepol_LDADD := liblustreapi.la -lcrypto $(SELINUX)
l_getsepol_DEPENDENCIES := liblustreapi.la

wirecheck_SOURCES = wirecheck.c
wirecheck_CPPFLAGS := -DCC="\"$(CC)\""

wiretest_SOURCES = wiretest.c

endif # UTILS

EXTRA_DIST = llstat llobdstat plot-llstat ldlm_debug_upcall liblustreapi.map

# NOTE: this should only be run on i386.
newwiretest: wirehdr.c wirecheck
	cp wirehdr.c wiretest.c
	LANG=C ./wirecheck >> wiretest.c
	cp ../ptlrpc/wirehdr.c ../ptlrpc/wiretest.c
	LANG=C ./wirecheck >> ../ptlrpc/wiretest.c
