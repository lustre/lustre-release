# Lustre test Makefile
AM_CPPFLAGS = $(LLCPPFLAGS) -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = $(LLCFLAGS)
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence

pkgexample_scripts = llmount.sh llmountcleanup.sh llecho.sh llechocleanup.sh
pkgexample_scripts += local.sh echo.sh uml.sh lov.sh

noinst_DATA =
noinst_SCRIPTS = leak_finder.pl llecho.sh llmount.sh llmountcleanup.sh tbox.sh
noinst_SCRIPTS += llrmount.sh runfailure-mds runvmstat runfailure-net
noinst_SCRIPTS += runfailure-ost runiozone runregression-net.sh runtests
noinst_SCRIPTS += sanity.sh rundbench

EXTRA_DIST = $(pkgexample_scripts) $(noinst_SCRIPTS) $(noinst_DATA) \
       sanity.sh rundbench
if TESTS
pkgexample_SCRIPTS = $(pkgexample_scripts)

noinst_PROGRAMS = openunlink testreq truncate directio openme writeme open_delay
noinst_PROGRAMS += tchmod toexcl fsx test_brw openclose createdestroy
noinst_PROGRAMS += stat createmany statmany multifstat createtest mlink utime
noinst_PROGRAMS += opendirunlink opendevunlink unlinkmany fchdir_test checkstat
noinst_PROGRAMS += wantedi statone runas openfile getdents mkdirdeep o_directory
noinst_PROGRAMS += small_write multiop sleeptest ll_sparseness_verify cmknod

noinst_PROGRAMS += ll_sparseness_write mrename ll_dirstripe_verify mkdirmany rmdirmany
noinst_PROGRAMS += openfilleddirunlink rename_many memhog iopentest1 iopentest2
noinst_PROGRAMS += mmap_sanity
# noinst_PROGRAMS += ldaptest copy_attr
bin_PROGRAMS = mcreate munlink
endif # TESTS

# ldaptest_SOURCES = ldaptest.c

stat_SOURCES = stat.c stat_fs.h
mkdirdeep_LDADD=-L$(top_builddir)/portals/utils -lptlctl $(LIBREADLINE)
#write_append_truncate_CC=mpicc
#createmany_mpi_CC=mpicc
#parallel_grouplock_SOURCES=parallel_grouplock.c lp_utils.c
#parallel_grouplock_CC=mpicc

#copy_attr_LDADD= -lattr
mmap_sanity_SOURCES= mmap_sanity.c

