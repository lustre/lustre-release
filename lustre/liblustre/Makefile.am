## Liblustre excecutables & libraries Makefile
DEFS=

SUBDIRS = . tests

LL_CFLAGS = -I$(SYSIO)/include

LIBS = $(LIBEFENCE)

LUSTRE_LIBS = libllite.a \
              $(top_builddir)/lov/liblov.a \
              $(top_builddir)/obdecho/libobdecho.a \
              $(top_builddir)/osc/libosc.a \
              $(top_builddir)/mdc/libmdc.a \
              $(top_builddir)/ptlrpc/libptlrpc.a \
              $(top_builddir)/obdclass/liblustreclass.a \
              $(top_builddir)/lvfs/liblvfs.a

PTL_LIBS =    $(top_builddir)/portals/utils/libuptlctl.a \
              $(top_builddir)/portals/unals/libtcpnal.a \
              $(top_builddir)/portals/portals/libportals.a

SYSIO_LIBS =  $(SYSIO)/drivers/native/libsysio_native.a \
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
	$(shell $(top_srcdir)/liblustre/genlib.sh $(SYSIO) $(AR) $(LINK))

include $(top_srcdir)/Rules

