# Lustre test Makefile
DEFS=
CPPFLAGS = -I. -I$(PORTALS)/include -I$(top_srcdir)/include -D_LARGEFILE64_SOURCE
CFLAGS := -g -Wall
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence
EXTRA_DIST = $(pkgexample_SCRIPTS) $(noinst_SCRIPTS) $(noinst_DATA) \
	common.sh lustre.cfg \
	client-echo.cfg    elan-server.cfg  net-client.cfg  obdecho.cfg \
	client-mount.cfg   ldlm.cfg         net-local.cfg   obdfilter.cfg \
	client-mount2.cfg  lustre.cfg       net-server.cfg  sanity.sh \
	rundbench          mcreate \
	elan-client.cfg    mds.cfg 	trivial.sh
pkgexampledir = '${exec_prefix}/usr/lib/$(PACKAGE)/examples'
pkgexample_SCRIPTS = llmount.sh llmountcleanup.sh llecho.sh llechocleanup.sh local.sh echo.sh uml.sh lov.sh
noinst_SCRIPTS = llsetup.sh llrsetup.sh llcleanup.sh
noinst_DATA = lustre.cfg
noinst_SCRIPTS += fs.sh intent-test.sh intent-test2.sh leak_finder.pl \
	lldlm.sh llecho.sh llext3.sh llmodules.sh llmount-client.sh \
	llmount-server.sh llmount.sh llmountcleanup.sh llrext3.sh \
	llrmount.sh llsimple.sh  mdcreq.sh mdcreqcleanup.sh \
	ostreq.sh runfailure-client-mds-recover.sh runfailure-mds \
	runfailure-net runfailure-ost runiozone runregression-net.sh \
	runtests runvmstat snaprun.sh tbox.sh  common.sh
noinst_PROGRAMS = openunlink testreq truncate directio openme writeme open_delay
noinst_PROGRAMS += munlink tchmod toexcl fsx test_brw openclose createdestroy
noinst_PROGRAMS += stat createmany statmany multifstat createtest mlink
# noinst_PROGRAMS += ldaptest 
noinst_PROGRAMS += checkstat wantedi statone runas
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
statone_SOURCES = statone.c
mkdirmany_SOURCES = mkdirmany.c
multifstat_SOURCES = multifstat.c
checkstat_SOURCES = checkstat.c
runas_SOURCES = runas.c
wantedi_SOURCES = wantedi.c
createtest_SOURCES = createtest.c
open_delay_SOURCES = open_delay.c

include $(top_srcdir)/Rules
