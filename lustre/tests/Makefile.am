# Lustre test Makefile
AM_CFLAGS := -fPIC -D_GNU_SOURCE \
	     -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64

DIST_SUBDIRS = mpi
DIST_SUBDIRS += lutf

noinst_DATA = disk2_4-ldiskfs.tar.bz2 disk2_4-zfs.tar.bz2
noinst_DATA += disk2_7-ldiskfs.tar.bz2 disk2_7-zfs.tar.bz2
noinst_DATA += disk2_9-zfs.tar.bz2 disk2_9-ldiskfs.tar.bz2
noinst_DATA += disk2_10-ldiskfs.tar.bz2 disk2_12-ldiskfs.tar.bz2
noinst_DATA += ldiskfs_mdt1_2_11.tar.bz2 ldiskfs_mdt2_2_11.tar.bz2
noinst_DATA += ldiskfs_ost1_2_11.tar.bz2 ldiskfs_ost2_2_11.tar.bz2
noinst_DATA += zfs_mdt1_2_11.tar.bz2 zfs_mdt2_2_11.tar.bz2
noinst_DATA += zfs_ost1_2_11.tar.bz2 zfs_ost2_2_11.tar.bz2
noinst_SCRIPTS = leak_finder.pl llmount.sh llmountcleanup.sh functions.sh
noinst_SCRIPTS += test-framework.sh runvmstat runiozone runtests sanity.sh
noinst_SCRIPTS += rundbench acceptance-small.sh compile.sh conf-sanity.sh
noinst_SCRIPTS += insanity.sh oos.sh oos2.sh dne_sanity.sh
noinst_SCRIPTS += recovery-small.sh replay-dual.sh sanity-quota.sh
noinst_SCRIPTS += replay-ost-single.sh replay-single.sh run-llog.sh sanityn.sh
noinst_SCRIPTS += large-scale.sh racer.sh replay-vbr.sh
noinst_SCRIPTS += performance-sanity.sh mdsrate-create-small.sh
noinst_SCRIPTS += mdsrate-create-large.sh mdsrate-lookup-1dir.sh
noinst_SCRIPTS += mdsrate-lookup-10dirs.sh sanity-benchmark.sh
noinst_SCRIPTS += mdsrate-stat-small.sh mdsrate-stat-large.sh
noinst_SCRIPTS += lockorder.sh socketclient socketserver runmultiop_bg_pause
noinst_SCRIPTS += sanity-sec.sh sanity-gss.sh sanity-selinux.sh
noinst_SCRIPTS += sanity-krb5.sh krb5_login.sh setup_kerberos.sh
noinst_SCRIPTS += recovery-mds-scale.sh run_dd.sh run_tar.sh run_iozone.sh
noinst_SCRIPTS += run_dbench.sh run_IOR.sh recovery-double-scale.sh
noinst_SCRIPTS += recovery-random-scale.sh parallel-scale.sh metadata-updates.sh
noinst_SCRIPTS += lustre-rsync-test.sh ost-pools.sh rpc.sh yaml.sh
if BUILD_LUTF
noinst_SCRIPTS += lutf.sh
endif # BUILD_LUTF
noinst_SCRIPTS += lnet-selftest.sh obdfilter-survey.sh mmp.sh mmp_mark.sh
noinst_SCRIPTS += sgpdd-survey.sh maloo_upload.sh auster setup-nfs.sh
noinst_SCRIPTS += mds-survey.sh parallel-scale-nfs.sh large-lun.sh
noinst_SCRIPTS += parallel-scale-nfsv3.sh parallel-scale-nfsv4.sh
noinst_SCRIPTS += setup-cifs.sh parallel-scale-cifs.sh
noinst_SCRIPTS += posix.sh sanity-scrub.sh scrub-performance.sh ha.sh pjdfstest.sh
noinst_SCRIPTS += sanity-lfsck.sh lfsck-performance.sh
noinst_SCRIPTS += resolveip
noinst_SCRIPTS += sanity-hsm.sh sanity-lsnapshot.sh sanity-pfl.sh sanity-flr.sh
noinst_SCRIPTS += sanity-dom.sh sanity-pcc.sh dom-performance.sh sanity-lnet.sh
nobase_noinst_SCRIPTS = cfg/local.sh
nobase_noinst_SCRIPTS += test-groups/regression test-groups/regression-mpi
nobase_noinst_SCRIPTS += acl/make-tree acl/run cfg/ncli.sh
nobase_noinst_SCRIPTS += racer/dir_create.sh racer/file_create.sh racer/file_list.sh
nobase_noinst_SCRIPTS += racer/file_rm.sh racer/racer.sh racer/file_concat.sh racer/file_exec.sh
nobase_noinst_SCRIPTS += racer/file_link.sh racer/file_rename.sh racer/file_symlink.sh
nobase_noinst_SCRIPTS += racer/dir_remote.sh racer/dir_migrate.sh racer/file_chmod.sh
nobase_noinst_SCRIPTS += racer/file_chown.sh racer/file_delxattr.sh racer/file_getxattr.sh
nobase_noinst_SCRIPTS += racer/file_mknod.sh racer/file_setxattr.sh racer/file_truncate.sh
nobase_noinst_SCRIPTS += racer/lss_create.sh racer/lss_destroy.sh
nobase_noinst_SCRIPTS += posix/posix.cfg
nobase_noinst_DATA = acl/cp.test acl/getfacl-noacl.test acl/inheritance.test
nobase_noinst_DATA += acl/misc.test acl/permissions.test acl/setfacl.test
nobase_noinst_DATA += acl/permissions_xattr.test
nobase_noinst_DATA += acl/974.test acl/974_remote.test
nobase_noinst_DATA += acl/2561.test acl/2561_zfs.test acl/4924.test
nobase_noinst_DATA += clientapi/simple_test.c

EXTRA_DIST = $(noinst_SCRIPTS) $(noinst_DATA) \
             $(nobase_noinst_SCRIPTS) $(nobase_noinst_DATA)

THETESTS = openunlink truncate directio writeme mlink utime
THETESTS += tchmod fsx test_brw sendfile
THETESTS += createmany chownmany statmany multifstat createtest
THETESTS += opendirunlink opendevunlink unlinkmany checkstat
THETESTS += statone runas openfile smalliomany
THETESTS += small_write multiop ll_sparseness_verify
THETESTS += ll_sparseness_write mrename ll_dirstripe_verify mkdirmany
THETESTS += openfilleddirunlink rename_many memhog euid_access
THETESTS += rw_seq_cst_vs_drop_caches
THETESTS += mmap_sanity writemany reads flocks_test flock_deadlock
THETESTS += write_time_limit rwv lgetxattr_size_check checkfiemap
THETESTS += listxattr_size_check check_fhandle_syscalls badarea_io
THETESTS += llapi_layout_test orphan_linkea_check llapi_hsm_test
THETESTS += group_lock_test llapi_fid_test sendfile_grouplock mmap_cat
THETESTS += swap_lock_test lockahead_test mirror_io mmap_mknod_test
THETESTS += create_foreign_file parse_foreign_file
THETESTS += create_foreign_dir parse_foreign_dir
THETESTS += check_fallocate splice-test lseek_test expand_truncate_test
THETESTS += foreign_symlink_striping lov_getstripe_old

if LIBAIO
THETESTS += aiocp
endif

if TESTS
if MPITESTS
SUBDIRS = mpi
endif

# Build LUTF only if the packages are available
if BUILD_LUTF
if MPITESTS
SUBDIRS += lutf
else
SUBDIRS = lutf
endif
endif # BUILD_LUTF

bin_PROGRAMS = mcreate munlink statx
testdir = $(libdir)/lustre/tests
test_SCRIPTS = $(noinst_SCRIPTS)
test_PROGRAMS = $(THETESTS)
nobase_test_SCRIPTS = $(nobase_noinst_SCRIPTS)
test_DATA = $(noinst_DATA)
nobase_test_DATA = $(nobase_noinst_DATA)

LIBLUSTREAPI = $(top_builddir)/lustre/utils/liblustreapi.la

badarea_io_CFLAGS=-Wno-stringop-overflow
mmap_sanity_LDADD = $(LIBLUSTREAPI)
multiop_LDADD = $(LIBLUSTREAPI) $(PTHREAD_LIBS)
llapi_layout_test_LDADD = $(LIBLUSTREAPI)
llapi_hsm_test_LDADD = $(LIBLUSTREAPI)
group_lock_test_LDADD = $(LIBLUSTREAPI)
llapi_fid_test_LDADD = $(LIBLUSTREAPI)
rw_seq_cst_vs_drop_caches_LDADD = $(PTHREAD_LIBS)
sendfile_grouplock_LDADD = $(LIBLUSTREAPI)
swap_lock_test_LDADD = $(LIBLUSTREAPI)
statmany_LDADD = $(LIBLUSTREAPI)
statone_LDADD = $(LIBLUSTREAPI)
rwv_LDADD = $(LIBLUSTREAPI)
lockahead_test_LDADD = $(LIBLUSTREAPI)
mirror_io_LDADD = $(LIBLUSTREAPI)
ll_dirstripe_verify_LDADD = $(LIBLUSTREAPI)
lov_getstripe_old_LDADD = $(LIBLUSTREAPI)
flocks_test_LDADD = $(LIBLUSTREAPI) $(PTHREAD_LIBS)
create_foreign_dir_LDADD = $(LIBLUSTREAPI)
check_fallocate_LDADD = $(LIBLUSTREAPI)
if LIBAIO
aiocp_LDADD= -laio
endif
statx_LDADD = $(SELINUX)
endif # TESTS
