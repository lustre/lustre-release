DEFS:=
CPPFLAGS := -I. -I$(PORTALS)/include -I$(top_srcdir)/include -D_LARGEFILE64_SOURCE
CFLAGS := -g -Wall
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence
bin_PROGRAMS = openunlink testreq truncate #ldaptest 

# ldaptest_SOURCES = ldaptest.c
testreq_SOURCES = testreq.c
truncate_SOURCES = truncate.c
openunlink_SOURCES = openunlink.c

include $(top_srcdir)/Rules

