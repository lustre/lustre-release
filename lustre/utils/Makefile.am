bin_SCRIPTS = obdcontrol
EXTRA_DIST = $(bin_SCRIPTS)

CFLAGS:=-g -I. -I../include -Wall
KFLAGS:=
CPPFLAGS :=
LDADD := -lreadline -ltermcap -lefence
bin_PROGRAMS = obdctl
obdctl_SOURCES = parser.c obdctl.c

