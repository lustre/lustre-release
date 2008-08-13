# Lustre test Makefile
AM_CPPFLAGS = $(LLCPPFLAGS) -I/opt/lam/include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS
AM_CFLAGS = $(LLCFLAGS)
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence

noinst_DATA = disk1_4.zip
noinst_SCRIPTS = leak_finder.pl llecho.sh llmount.sh llmountcleanup.sh
noinst_SCRIPTS += test-framework.sh runvmstat runiozone runtests
noinst_SCRIPTS += sanity.sh rundbench acceptance-small.sh compile.sh
noinst_SCRIPTS += conf-sanity.sh insanity.sh lfscktest.sh oos.sh oos2.sh
noinst_SCRIPTS += llog-test.sh recovery-small.sh replay-dual.sh sanity-quota.sh
noinst_SCRIPTS += replay-ost-single.sh replay-single.sh run-llog.sh sanityN.sh
noinst_SCRIPTS += lockorder.sh socketclient socketserver runmultiop_bg_pause
noinst_SCRIPTS += sanity-sec.sh sanity-gss.sh krb5_login.sh setup_kerberos.sh
nobase_noinst_SCRIPTS = cfg/local.sh
nobase_noinst_SCRIPTS += acl/make-tree acl/run cfg/ncli.sh
nobase_noinst_SCRIPTS += racer/dir_create.sh racer/file_create.sh racer/file_list.sh
nobase_noinst_SCRIPTS += racer/file_rm.sh racer/racer.sh racer/file_concat.sh
nobase_noinst_SCRIPTS += racer/file_link.sh racer/file_rename.sh racer/file_symlink.sh
nobase_noinst_SCRIPTS += rmtacl/make-tree rmtacl/run
nobase_noinst_DATA = acl/cp.test acl/getfacl-noacl.test acl/inheritance.test
nobase_noinst_DATA += acl/misc.test acl/permissions.test acl/setfacl.test
nobase_noinst_DATA += rmtacl/misc.test rmtacl/permissions.test
nobase_noinst_DATA += rmtacl/setfacl.test rmtacl/cp.test
nobase_noinst_DATA += rmtacl/getfacl-noacl.test rmtacl/inheritance.test

EXTRA_DIST = $(noinst_SCRIPTS) $(noinst_DATA) \
             $(nobase_noinst_SCRIPTS) $(nobase_noinst_DATA)

if TESTS
noinst_PROGRAMS = openunlink truncate directio openme writeme mlink utime it_test
noinst_PROGRAMS += tchmod toexcl fsx test_brw openclose createdestroy
noinst_PROGRAMS += createmany chownmany statmany multifstat createtest
noinst_PROGRAMS += opendirunlink opendevunlink unlinkmany fchdir_test checkstat
noinst_PROGRAMS += wantedi statone runas openfile getdents o_directory rmdirmany
noinst_PROGRAMS += small_write multiop sleeptest ll_sparseness_verify cmknod
noinst_PROGRAMS += ll_sparseness_write mrename ll_dirstripe_verify mkdirmany
noinst_PROGRAMS += openfilleddirunlink rename_many memhog iopentest1 iopentest2
noinst_PROGRAMS += mmap_sanity flock_test writemany reads flocks_test
noinst_PROGRAMS += ll_getstripe_info write_time_limit
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

# mkdirdeep_LDADD=-L$(top_builddir)/lnet/utils -lptlctl $(LIBREADLINE)
mmap_sanity_SOURCES= mmap_sanity.c

LIBLUSTREAPI := $(top_builddir)/lustre/utils/liblustreapi.a
ll_getstripe_info_LDADD=$(LIBLUSTREAPI)
multiop_LDADD=$(LIBLUSTREAPI)

ll_dirstripe_verify_SOURCES= ll_dirstripe_verify.c
ll_dirstripe_verify_LDADD= -L$(top_builddir)/lustre/utils -llustreapi

flocks_test_SOURCES=flocks_test.c
flocks_test_LDADD=-lpthread

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
