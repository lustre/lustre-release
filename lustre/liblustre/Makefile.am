# Administration utilities Makefile
DEFS=

CFLAGS:=-g -O2 -I$(top_srcdir)/utils -I$(PORTALS)/include  -I$(srcdir)/../include -Wall -L$(PORTALSLIB)

KFLAGS:=
CPPFLAGS = $(HAVE_LIBREADLINE)
LIBS=
LLIBS= ../lov/liblov.a ../obdecho/libobdecho.a ../osc/libosc.a ../ldlm/libldlm.a  ../ptlrpc/libptlrpc.a ../obdclass/liblustreclass.a

libtest_LDADD := $(LIBREADLINE)  $(LLIBS) \
                 $(PORTALS)/user/procbridge/libprocbridge.a  $(PORTALS)/user/tcpnal/libtcpnal.a \
	         $(PORTALS)/user/util/libtcpnalutil.a $(PORTALS)/user/$(PORTALS)/api/libptlapi.a \
                 $(PORTALS)/lib/libptllib.a -lptlctl -lpthread -lefence
bin_PROGRAMS = libtest
libtest_SOURCES = libtest.c

include $(top_srcdir)/Rules
