DEFS:=

EXTRA_DIST = parser.h lctl.h
CFLAGS:=-g -I. -I/usr/include/libxml2 -I/usr/include/glib-1.2 -I$(PORTALS)/include \
-I/usr/lib/glib/include -I$(srcdir)/../include -Wall
KFLAGS:=
CPPFLAGS :=
LDADD := -lreadline -lncurses -lxml2 # -lefence
bin_PROGRAMS = obdctl lctl
obdctl_SOURCES = parser.c obdctl.c
lctl_SOURCES = parser.c network.c device.c debug.c lctl.c 

include $(top_srcdir)/Rules
