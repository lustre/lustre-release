# Lustre test Makefile
DEFS=
CPPFLAGS = -I. -I$(top_srcdir)/portals/include/ -I$(top_srcdir)/include -D_LARGEFILE64_SOURCE
CFLAGS := -g -Wall
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence
EXTRA_DIST = $(pkgexample_SCRIPTS) $(noinst_SCRIPTS) $(noinst_DATA) \
	sanity.sh          rundbench    mcreate
pkgexample_SCRIPTS = llmount.sh llmountcleanup.sh llecho.sh llechocleanup.sh local.sh echo.sh uml.sh lov.sh
noinst_DATA =
noinst_SCRIPTS = leak_finder.pl llecho.sh llmount.sh llmountcleanup.sh tbox.sh \
	llrmount.sh runfailure-mds runvmstat runfailure-net runfailure-ost \
	runiozone runregression-net.sh runtests sanity.sh rundbench
noinst_PROGRAMS = openunlink testreq truncate directio openme writeme open_delay
noinst_PROGRAMS += munlink tchmod toexcl fsx test_brw openclose createdestroy
noinst_PROGRAMS += stat createmany statmany multifstat createtest mlink
noinst_PROGRAMS += opendirunlink opendevunlink unlinkmany fchdir_test checkstat
noinst_PROGRAMS += wantedi statone runas openfile getdents o_directory
# noinst_PROGRAMS += ldaptest
sbin_PROGRAMS = mcreate mkdirmany

# ldaptest_SOURCES = ldaptest.c
tchmod_SOURCES = tchmod.c
toexcl_SOURCES = toexcl.c
testreq_SOURCES = testreq.c
mcreate_SOURCES = mcreate.c
munlink_SOURCES = munlink.c
mlink_SOURCES = mlink.c
truncate_SOURCES = truncate.c
directio_SOURCES = directio.c
openunlink_SOURCES = openunlink.c
openme_SOURCES = openme.c
writeme_SOURCES = writeme.c
fsx_SOURCES = fsx.c
test_brw_SOURCES = test_brw.c
openclose_SOURCES = openclose.c
createdestroy_SOURCES = createdestroy.c
stat_SOURCES = stat.c
createmany_SOURCES = createmany.c
statmany_SOURCES = statmany.c
unlinkmany_SOURCES = unlinkmany.c
statone_SOURCES = statone.c
mkdirmany_SOURCES = mkdirmany.c
multifstat_SOURCES = multifstat.c
checkstat_SOURCES = checkstat.c
runas_SOURCES = runas.c
openfile_SOURCES = openfile.c
wantedi_SOURCES = wantedi.c
createtest_SOURCES = createtest.c
open_delay_SOURCES = open_delay.c
opendirunlink_SOURCES=opendirunlink.c
opendevunlink_SOURCES=opendirunlink.c
fchdir_test_SOURCES=fchdir_test.c
getdents_SOURCES=getdents.c
o_directory_SOURCES = o_directory.c
#mkdirdeep_SOURCES= mkdirdeep.c
#mkdirdeep_LDADD=-L../portals/util -lptlctl
#mkdirdeep_CPPFLAGS=-I$(top_srcdir)/portals/include

include $(top_srcdir)/Rules
