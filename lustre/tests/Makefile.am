# Lustre test Makefile
DEFS=
CPPFLAGS = -I. -I$(PORTALS)/include -I$(top_srcdir)/include -D_LARGEFILE64_SOURCE
CFLAGS := -g -Wall
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence
pkglibdir = @libdir@/$(PACKAGE)
pkgcfgdir = @sysconfdir@/$(PACKAGE)
EXTRA_DIST = $(sbin_SCRIPTS) $(noinst_SCRIPTS) $(noinst_DATA) \
	common.sh lustre.cfg \
	client-echo.cfg    elan-server.cfg  net-client.cfg  obdecho.cfg \
	client-mount.cfg   ldlm.cfg         net-local.cfg   obdfilter.cfg \
	client-mount2.cfg  lustre.cfg       net-server.cfg \
	elan-client.cfg    mds.cfg 	trivial.sh
sbin_SCRIPTS = llsetup.sh llrsetup.sh llcleanup.sh
noinst_DATA = ext2_10000.gz ext2_25000.gz ext3_10000.gz lov.xml
noinst_SCRIPTS = fs.sh intent-test.sh intent-test2.sh leak_finder.pl \
	lldlm.sh llecho.sh llext3.sh llmodules.sh llmount-client.sh \
	llmount-server.sh llmount.sh llmountcleanup.sh llrext3.sh \
	llrmount.sh llsimple.sh  mdcreq.sh mdcreqcleanup.sh \
	ostreq.sh runfailure-client-mds-recover.sh runfailure-mds \
	runfailure-net runfailure-ost runiozone runregression-net.sh \
	runtests runvmstat snaprun.sh tbox.sh
pkglib_SCRIPTS = common.sh
pkgcfg_DATA = lustre.cfg
noinst_PROGRAMS = openunlink testreq truncate directio openme writeme mcreate
noinst_PROGRAMS += munlink tchmod toexcl fsx test_brw openclose #ldaptest 

# ldaptest_SOURCES = ldaptest.c
tchmod_SOURCES = tchmod.c
toexcl_SOURCES = toexcl.c
testreq_SOURCES = testreq.c
mcreate_SOURCES = mcreate.c
munlink_SOURCES = munlink.c
truncate_SOURCES = truncate.c
directio_SOURCES = directio.c
openunlink_SOURCES = openunlink.c
openme_SOURCES = openme.c
writeme_SOURCES = writeme.c
fsx_SOURCES = fsx.c
test_brw_SOURCES = test_brw.c
openclose_SOURCES = openclose.c

include $(top_srcdir)/Rules
