# Administration utilities Makefile
DEFS=

CFLAGS:=-g -O2 -I. -I/usr/include/libxml2 -I/usr/include/glib-1.2 -I$(PORTALS)/include \
-I/usr/lib/glib/include -I$(srcdir)/../include -Wall
KFLAGS:=
CPPFLAGS = $(HAVE_LIBREADLINE)
obdctl_LDADD := $(LIBREADLINE) -lxml2 # -lefence
lctl_LDADD := $(LIBREADLINE)
sbin_PROGRAMS = lctl obdctl
obdctl_SOURCES = parser.c obdctl.c parser.h
lctl_SOURCES = parser.c network.c device.c debug.c lctl.c lctl.h parser.h

include $(top_srcdir)/Rules
