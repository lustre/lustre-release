LIBCFS = $(top_builddir)/libcfs/libcfs/libcfs.a
LIBLUSTREAPI = $(top_builddir)/lustre/utils/liblustreapi.a

# Lustre test Makefile
AM_CFLAGS := -fPIC -D_GNU_SOURCE \
	     -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS=1 \
	     -I/opt/lam/include

DIST_SUBDIRS = mpi

noinst_DATA = disk1_8_up_2_5-ldiskfs.tar.bz2 disk2_1_up_2_5-ldiskfs.tar.bz2
noinst_DATA += disk2_3_up_2_5-ldiskfs.tar.bz2 disk2_4-ldiskfs.tar.bz2
noinst_DATA += disk2_4-zfs.tar.bz2 disk2_7-ldiskfs.tar.bz2 disk2_7-zfs.tar.bz2
noinst_DATA += disk2_9-zfs.tar.bz2 disk2_9-ldiskfs.tar.bz2
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
noinst_SCRIPTS += lnet-selftest.sh obdfilter-survey.sh mmp.sh mmp_mark.sh
noinst_SCRIPTS += sgpdd-survey.sh maloo_upload.sh auster setup-nfs.sh
noinst_SCRIPTS += mds-survey.sh parallel-scale-nfs.sh large-lun.sh
noinst_SCRIPTS += parallel-scale-nfsv3.sh parallel-scale-nfsv4.sh
noinst_SCRIPTS += setup-cifs.sh parallel-scale-cifs.sh
noinst_SCRIPTS += posix.sh sanity-scrub.sh scrub-performance.sh ha.sh
noinst_SCRIPTS += sanity-lfsck.sh lfsck-performance.sh
noinst_SCRIPTS += resolveip
noinst_SCRIPTS += sanity-hsm.sh sanity-lsnapshot.sh sanity-pfl.sh
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

if TESTS
if MPITESTS
SUBDIRS = mpi
endif
noinst_PROGRAMS = openunlink truncate directio writeme mlink utime it_test
noinst_PROGRAMS += tchmod fsx test_brw sendfile
noinst_PROGRAMS += createmany chownmany statmany multifstat createtest
noinst_PROGRAMS += opendirunlink opendevunlink unlinkmany checkstat
noinst_PROGRAMS += statone runas openfile rmdirmany
noinst_PROGRAMS += small_write multiop ll_sparseness_verify
noinst_PROGRAMS += ll_sparseness_write mrename ll_dirstripe_verify mkdirmany
noinst_PROGRAMS += openfilleddirunlink rename_many memhog
noinst_PROGRAMS += mmap_sanity writemany reads flocks_test flock_deadlock
noinst_PROGRAMS += write_time_limit rwv lgetxattr_size_check checkfiemap
noinst_PROGRAMS += listxattr_size_check check_fhandle_syscalls badarea_io
noinst_PROGRAMS += llapi_layout_test orphan_linkea_check llapi_hsm_test
noinst_PROGRAMS += group_lock_test llapi_fid_test sendfile_grouplock mmap_cat
noinst_PROGRAMS += swap_lock_test

bin_PROGRAMS = mcreate munlink
testdir = $(libdir)/lustre/tests
test_SCRIPTS = $(noinst_SCRIPTS) $(noinst_PROGRAMS)
nobase_test_SCRIPTS = $(nobase_noinst_SCRIPTS)
test_DATA = $(noinst_DATA)
nobase_test_DATA = $(nobase_noinst_DATA)
endif # TESTS

mmap_sanity_SOURCES= mmap_sanity.c
mmap_sanity_LDADD=$(LIBCFS)

multiop_LDADD=$(LIBLUSTREAPI) $(LIBCFS) $(PTHREAD_LIBS)
llapi_layout_test_LDADD=$(LIBLUSTREAPI)
llapi_hsm_test_LDADD=$(LIBLUSTREAPI)
group_lock_test_LDADD=$(LIBLUSTREAPI)
llapi_fid_test_LDADD=$(LIBLUSTREAPI)
sendfile_grouplock_LDADD=$(LIBLUSTREAPI)
swap_lock_test_LDADD=$(LIBLUSTREAPI)
statmany_LDADD=$(LIBLUSTREAPI)
statone_LDADD=$(LIBLUSTREAPI)
it_test_LDADD=$(LIBCFS)
rwv_LDADD=$(LIBCFS)

ll_dirstripe_verify_SOURCES = ll_dirstripe_verify.c
ll_dirstripe_verify_LDADD = $(LIBLUSTREAPI) $(LIBCFS) $(PTHREAD_LIBS)

flocks_test_SOURCES=flocks_test.c
flocks_test_LDADD=$(PTHREAD_LIBS)
