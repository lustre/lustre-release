DEFS:=
CPPFLAGS := -I. -I$(PORTALS)/include -I$(top_srcdir)/include -D_LARGEFILE64_SOURCE
CFLAGS := -g -Wall
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence
bin_PROGRAMS = openunlink testreq truncate directio openme writeme mcreate tchmod toexcl fsx #ldaptest 

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

