## Liblustre excecutables & libraries Makefile
DEFS=

SUBDIRS = . tests

LL_CFLAGS = -g -Wall -I$(top_srcdir)/utils -I$(top_srcdir)/portals/include \
          -I$(top_srcdir)/portals/unals -I$(SYSIO)/include -fPIC

CPPFLAGS = $(HAVE_EFENCE) -D_LARGEFILE64_SOURCE=1
LIBS = $(LIBEFENCE)

LUSTRE_LIBS = libllite.a \
              $(top_srcdir)/lov/liblov.a \
              $(top_srcdir)/obdecho/libobdecho.a \
              $(top_srcdir)/osc/libosc.a \
              $(top_srcdir)/mdc/libmdc.a \
              $(top_srcdir)/ptlrpc/libptlrpc.a \
              $(top_srcdir)/obdclass/liblustreclass.a \
              $(top_srcdir)/lvfs/liblvfs.a

PTL_LIBS = $(top_srcdir)/portals/utils/libuptlctl.a \
           $(top_srcdir)/portals/unals/libtcpnal.a \
           $(top_srcdir)/portals/portals/libportals.a

SYSIO_LIBS = $(SYSIO)/drivers/native/libsysio_native.a \
             $(SYSIO)/drivers/sockets/libsysio_sockets.a \
             $(SYSIO)/src/libsysio.a \
             $(SYSIO)/dev/stdfd/libsysio_stdfd.a

lib_LIBRARIES = liblustre.a
noinst_LIBRARIES = libllite.a

libllite_a_SOURCES = llite_lib.c super.c namei.c rw.c file.c dir.c
libllite_a_CFLAGS = $(LL_CFLAGS)

# for make rpms -- need cleanup
liblustre_a_SOURCES = llite_lib.c super.c namei.c rw.c file.c dir.c
liblustre_a_CFLAGS = $(LL_CFLAGS)

liblustre.a : $(LUSTRE_LIBS) $(PTL_LIBS) $(SYSIO_LIBS)
	$(shell ./genlib.sh $(SYSIO) $(AR) $(LINK))

include $(top_srcdir)/Rules

