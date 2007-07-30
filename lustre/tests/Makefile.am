# Lustre test Makefile
AM_CPPFLAGS = $(LLCPPFLAGS) -I/opt/lam/include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS
AM_CFLAGS = $(LLCFLAGS)
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence

noinst_DATA = 
noinst_SCRIPTS = leak_finder.pl llecho.sh llmount.sh llmountcleanup.sh 
noinst_SCRIPTS += sanity.sh rundbench test-framework.sh
noinst_SCRIPTS += acceptance-small.sh compile.sh conf-sanity.sh 
noinst_SCRIPTS += echo.sh insanity.sh lfscktest.sh llechocleanup.sh 
noinst_SCRIPTS += llog-test.sh lockorder.sh lstiming.sh mount2fs.sh oos2.sh 
noinst_SCRIPTS += oos.sh recovery-cleanup.sh recovery-small.sh replay-dual.sh 
noinst_SCRIPTS += replay-ost-single.sh replay-single.sh routed.sh run-llog.sh 
noinst_SCRIPTS += run-quotacheck.sh run-quotactl.sh run-quotafmt.sh 
noinst_SCRIPTS += sanity-buffalo.sh sanityN.sh sanity-quota.sh tmpfs-sanity.sh
noinst_SCRIPTS += kbuild lkcdmap rundbench runiozone runvmstat runslabinfo 
noinst_SCRIPTS += runtests socketclient socketserver sanity-sec.sh
nobase_noinst_SCRIPTS = cfg/insanity-local.sh cfg/insanity-ltest.sh 
nobase_noinst_SCRIPTS += cfg/local.sh acl/make-tree acl/run
nobase_noinst_DATA = acl/cp.test acl/getfacl-noacl.test acl/inheritance.test 
nobase_noinst_DATA += acl/misc.test acl/permissions.test acl/setfacl.test

EXTRA_DIST = $(noinst_SCRIPTS) $(noinst_DATA) \
             $(nobase_noinst_SCRIPTS) $(nobase_noinst_DATA)

if TESTS
noinst_PROGRAMS = openunlink truncate directio openme writeme
noinst_PROGRAMS += tchmod toexcl fsx test_brw openclose createdestroy
noinst_PROGRAMS += stat createmany chownmany statmany multifstat createtest mlink utime
noinst_PROGRAMS += opendirunlink opendevunlink unlinkmany fchdir_test checkstat
noinst_PROGRAMS += wantedi statone runas openfile getdents o_directory
noinst_PROGRAMS += small_write multiop sleeptest ll_sparseness_verify cmknod
noinst_PROGRAMS += ll_sparseness_write mrename ll_dirstripe_verify mkdirmany rmdirmany
noinst_PROGRAMS += openfilleddirunlink rename_many memhog iopentest1 iopentest2
noinst_PROGRAMS += mmap_sanity flock_test writemany random-reads flocks_test
noinst_PROGRAMS += ll_getstripe_info
if MPITESTS
noinst_PROGRAMS += parallel_grouplock write_append_truncate createmany_mpi
noinst_PROGRAMS += iam_ut
endif
# noinst_PROGRAMS += ldaptest copy_attr mkdirdeep 
bin_PROGRAMS = mcreate munlink
testdir = $(libdir)/lustre/tests
test_SCRIPTS = $(noinst_SCRIPTS) $(noinst_PROGRAMS)
nobase_test_SCRIPTS = $(nobase_noinst_SCRIPTS)
test_DATA = $(noinst_DATA)
nobase_test_DATA = $(nobase_noinst_DATA)
endif # TESTS

stat_SOURCES = stat.c stat_fs.h
# mkdirdeep_LDADD=-L$(top_builddir)/lnet/utils -lptlctl $(LIBREADLINE)
mmap_sanity_SOURCES= mmap_sanity.c

LIBLUSTREAPI := $(top_builddir)/lustre/utils/liblustreapi.a
ll_getstripe_info_LDADD=$(LIBLUSTREAPI)

if MPITESTS
LAM_LD_FLAGS=-L/opt/lam/lib -lmpi -llam -lpthread
write_append_truncate_SOURCES=write_append_truncate.c
write_append_truncate_LDADD=$(LAM_LD_FLAGS)
createmany_mpi_SOURCES=createmany-mpi.c
createmany_mpi_LDADD=$(LAM_LD_FLAGS)
parallel_grouplock_SOURCES=parallel_grouplock.c lp_utils.c
parallel_grouplock_LDADD=$(LAM_LD_FLAGS)
endif

#copy_attr_LDADD= -lattr
