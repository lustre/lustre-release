# Lustre test Makefile
DEFS=
CPPFLAGS = -I. -I$(PORTALS)/include -I$(top_srcdir)/include -D_LARGEFILE64_SOURCE
CFLAGS := -g -Wall
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence
pkglibdir = @libdir@/$(PACKAGE)
pkgcfgdir = @sysconfdir@/$(PACKAGE)
EXTRA_DIST = llsetup.sh llrsetup.sh llcleanup.sh common.sh lustre.cfg \
client-echo.cfg    elan-server.cfg  net-client.cfg  obdecho.cfg \
client-mount.cfg   ldlm.cfg         net-local.cfg   obdfilter.cfg \
client-mount2.cfg  lustre.cfg       net-server.cfg \
elan-client.cfg    mds.cfg 
sbin_SCRIPTS = llsetup.sh llrsetup.sh llcleanup.sh
pkglib_SCRIPTS = common.sh
pkgcfg_DATA = lustre.cfg
noinst_PROGRAMS = openunlink testreq truncate directio openme writeme mcreate tchmod toexcl fsx #ldaptest 

# ldaptest_SOURCES = ldaptest.c
tchmod_SOURCES = tchmod.c
toexcl_SOURCES = toexcl.c
testreq_SOURCES = testreq.c
mcreate_SOURCES = mcreate.c
truncate_SOURCES = truncate.c
directio_SOURCES = directio.c
openunlink_SOURCES = openunlink.c
openme_SOURCES = openme.c
writeme_SOURCES = writeme.c
fsx_SOURCES = fsx.c

include $(top_srcdir)/Rules
