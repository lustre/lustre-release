DEFS:=
CPPFLAGS := -g -I. -I$(PORTALS)/include -I$(top_srcdir)/include -Wall -D_LARGEFILE64_SOURCE
# LDADD = -lldap
# LDADD := -lreadline -ltermcap # -lefence
bin_PROGRAMS = ldaptest openunlink testreq truncate

# ldaptest_SOURCES = ldaptest.c
testreq_SOURCES = testreq.c
truncate_SOURCES = truncate.c
openunlink_SOURCES = openunlink.c

include $(top_srcdir)/Rules

