DEFS:=

CFLAGS:=-g -I. -I/usr/include/glib-1.2 -I$(PORTALS)/include -I/usr/lib/glib/include -I../include -Wall
KFLAGS:=
CPPFLAGS :=
LDADD := -lreadline -ltermcap # -lefence
bin_PROGRAMS = obdctl
obdctl_SOURCES = parser.c obdctl.c
