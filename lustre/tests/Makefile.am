# Lustre test Makefile
AM_CPPFLAGS = $(LLCPPFLAGS) -I/opt/lam/include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS
AM_CFLAGS = $(LLCFLAGS)
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence

DIST_SUBDIRS := mpi

noinst_DATA = disk1_6.tar.bz2
noinst_SCRIPTS = leak_finder.pl llmount.sh llmountcleanup.sh functions.sh
noinst_SCRIPTS += test-framework.sh runvmstat runiozone runtests
noinst_SCRIPTS += sanity.sh rundbench acceptance-small.sh compile.sh
noinst_SCRIPTS += conf-sanity.sh insanity.sh lfsck.sh oos.sh oos2.sh
noinst_SCRIPTS += llog-test.sh recovery-small.sh replay-dual.sh sanity-quota.sh
noinst_SCRIPTS += replay-ost-single.sh replay-single.sh run-llog.sh sanityn.sh
noinst_SCRIPTS += large-scale.sh racer.sh performance-sanity.sh
noinst_SCRIPTS += mdsrate-create-small.sh mdsrate-create-large.sh
noinst_SCRIPTS += mdsrate-lookup-1dir.sh mdsrate-lookup-10dirs.sh
noinst_SCRIPTS += mdsrate-stat-small.sh mdsrate-stat-large.sh replay-vbr.sh
noinst_SCRIPTS += sanity-benchmark.sh liblustre.sh
noinst_SCRIPTS += lockorder.sh socketclient socketserver runmultiop_bg_pause
noinst_SCRIPTS += recovery-mds-scale.sh run_dd.sh run_tar.sh run_iozone.sh
noinst_SCRIPTS += run_dbench.sh run_IOR.sh recovery-double-scale.sh
noinst_SCRIPTS += recovery-random-scale.sh parallel-scale.sh metadata-updates.sh
noinst_SCRIPTS += ost-pools.sh rpc.sh lnet-selftest.sh obdfilter-survey.sh mmp.sh mmp_mark.sh
noinst_SCRIPTS += sgpdd-survey.sh auster yaml.sh maloo_upload.sh setup-nfs.sh
noinst_SCRIPTS += parallel-scale-nfs.sh parallel-scale-nfsv3.sh parallel-scale-nfsv4.sh
noinst_SCRIPTS += ha.sh posix.sh
nobase_noinst_SCRIPTS = cfg/local.sh
nobase_noinst_SCRIPTS += test-groups/regression test-groups/regression-mpi
nobase_noinst_SCRIPTS += acl/make-tree acl/run cfg/ncli.sh
nobase_noinst_SCRIPTS += racer/dir_create.sh racer/file_create.sh racer/file_list.sh
nobase_noinst_SCRIPTS += racer/file_rm.sh racer/racer.sh racer/file_concat.sh
nobase_noinst_SCRIPTS += racer/file_link.sh racer/file_rename.sh racer/file_symlink.sh
nobase_noinst_SCRIPTS += posix/posix.cfg
nobase_noinst_DATA = acl/cp.test acl/getfacl-noacl.test acl/inheritance.test
nobase_noinst_DATA += acl/misc.test acl/permissions.test acl/setfacl.test

EXTRA_DIST = $(noinst_SCRIPTS) $(noinst_DATA) \
             $(nobase_noinst_SCRIPTS) $(nobase_noinst_DATA)

if TESTS
if MPITESTS
SUBDIRS = mpi
endif
noinst_PROGRAMS = openunlink truncate directio writeme mlink utime it_test
noinst_PROGRAMS += tchmod fsx test_brw
noinst_PROGRAMS += createmany chownmany statmany multifstat createtest
noinst_PROGRAMS += opendirunlink opendevunlink unlinkmany checkstat
noinst_PROGRAMS += statone runas openfile rmdirmany
noinst_PROGRAMS += small_write multiop ll_sparseness_verify
noinst_PROGRAMS += ll_sparseness_write mrename ll_dirstripe_verify mkdirmany
noinst_PROGRAMS += openfilleddirunlink rename_many memhog iopentest1 iopentest2
noinst_PROGRAMS += mmap_sanity flock_test writemany reads flocks_test
# noinst_PROGRAMS += copy_attr mkdirdeep
bin_PROGRAMS = mcreate munlink
testdir = $(libdir)/lustre/tests
test_SCRIPTS = $(noinst_SCRIPTS) $(noinst_PROGRAMS)
nobase_test_SCRIPTS = $(nobase_noinst_SCRIPTS)
test_DATA = $(noinst_DATA)
nobase_test_DATA = $(nobase_noinst_DATA)
endif # TESTS

# mkdirdeep_LDADD=-L$(top_builddir)/lnet/utils -lptlctl $(LIBREADLINE)
mmap_sanity_SOURCES= mmap_sanity.c

LIBLUSTREAPI := $(top_builddir)/lustre/utils/liblustreapi.a
multiop_LDADD=$(LIBLUSTREAPI) -lrt $(PTHREAD_LIBS)

ll_dirstripe_verify_SOURCES= ll_dirstripe_verify.c
ll_dirstripe_verify_LDADD= -L$(top_builddir)/lustre/utils -llustreapi

flocks_test_SOURCES=flocks_test.c
flocks_test_LDADD=-lpthread

#copy_attr_LDADD= -lattr
