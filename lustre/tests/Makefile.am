DEFS:=
CPPFLAGS := -g -I. -I$(PORTALS)/include -I$(top_srcdir)/include -Wall -D_LARGEFILE64_SOURCE
# LDADD := -lreadline -ltermcap # -lefence
bin_PROGRAMS = openunlink testreq truncate

testreq_SOURCES = testreq.c
truncate_SOURCES = truncate.c
openunlink_SOURCES = openunlink.c

include $(top_srcdir)/Rules

