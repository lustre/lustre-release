# Administration utilities Makefile
DEFS=

CFLAGS:=-g -O2 -I. -I$(PORTALS)/include  -I$(srcdir)/../include -Wall\
 -L$(PORTALS)/linux/utils
KFLAGS:=
CPPFLAGS = $(HAVE_LIBREADLINE)
obdctl_LDADD := $(LIBREADLINE)
lctl_LDADD := $(LIBREADLINE) -lptlctl
sbin_PROGRAMS = lctl obdctl
obdctl_SOURCES = parser.c obdctl.c obd.c parser.h obdctl.h
lctl_SOURCES = parser.c obd.c lctl.c parser.h

include $(top_srcdir)/Rules
