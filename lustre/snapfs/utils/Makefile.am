# Administration utilities Makefile
#CPPFLAGS = $(HAVE_LIBREADLINE) -I$(top_srcdir)/utils -I$(top_srcdir)/portals/include  -I$(srcdir)/../ -Wall -L../../portals/utils
#CFLAGS:= -g -O2 
DEFS=

CFLAGS:=-g -O2 -I$(top_srcdir)/utils -I$(top_srcdir)/portals/include  -I$(srcdir)/../ -Wall -L../../portals/utils
CPPFLAGS = $(HAVE_LIBREADLINE)
KFLAGS:=
noinst_PROGRAMS = snapconf
snapconf_LDADD := $(LIBREADLINE)  -ltermcap
snapconf_SOURCES = parser.c snapctl.c snapconf.c parser.h snapctl.h
include $(top_srcdir)/Rules

