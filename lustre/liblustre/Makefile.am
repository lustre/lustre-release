# Administration utilities Makefile
DEFS=

CFLAGS:=-g -I$(top_srcdir)/utils -I$(top_srcdir)/portals/include  -I$(srcdir)/../include -I$(top_srcdir)/../libsysio/include -Wall -L../portals/utils

KFLAGS:=
CPPFLAGS = $(HAVE_EFENCE) -D_LARGEFILE64_SOURCE=1
LIBS = $(LIBEFENCE)
LLIBS= ./libllite.a ../lov/liblov.a ../obdecho/libobdecho.a ../osc/libosc.a ../ldlm/libldlm.a  ../ptlrpc/libptlrpc.a ../obdclass/liblustreclass.a ../mdc/libmdc.a

lib_LIBRARIES = libllite.a
libllite_a_SOURCES = llite_lib.c super.c file.c rw.c

bin_PROGRAMS = libtest lltest

libtest_LDADD := $(LIBREADLINE)  $(LLIBS) \
                 ../portals/unals/libtpcnal.a \
                 ../portals/portals/libportals.a\
	          -lptlctl -lpthread 
libtest_SOURCES = libtest.c

lltest_LDADD := $(LIBREADLINE)  $(LLIBS) \
                ../../libsysio/src/libsysio.a ../../libsysio/dev/stdfd/libsysio_stdfd.a \
                -lc \
                ../portals/unals/libtcpnal.a ../portals/portals/libportals.a \
		-lptlctl -lpthread
lltest_SOURCES = lltest.c

include $(top_srcdir)/Rules

