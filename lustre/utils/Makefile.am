bin_SCRIPTS = obdcontrol
EXTRA_DIST = $(bin_SCRIPTS)

CFLAGS:=-g -I. -I/usr/include/glib-1.2 -I/usr/lib/glib/include -I../include -Wall
KFLAGS:=
CPPFLAGS :=
LDADD := -lreadline -ltermcap # -lefence
bin_PROGRAMS = obdctl testreq
obdctl_SOURCES = parser.c obdctl.c
testreq_SOURCES = testreq.c

