## Liblustre excecutables & libraries Makefile
SUBDIRS = . tests

AM_CPPFLAGS = $(HAVE_EFENCE) -I$(SYSIO)/include -D_LARGEFILE64_SOURCE=1 $(LLCPPFLAGS) -I$(top_srcdir)/portals/unals
AM_CFLAGS = $(LLCFLAGS)

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

if LIBLUSTRE
lib_LIBRARIES = liblustre.a
noinst_LIBRARIES = libllite.a
endif

libllite_a_SOURCES = llite_lib.c super.c namei.c rw.c file.c dir.c llite_lib.h

# for make rpms -- need cleanup
liblustre_a_SOURCES = llite_lib.c super.c namei.c rw.c file.c dir.c

liblustre.a : $(LUSTRE_LIBS) $(PTL_LIBS) $(SYSIO_LIBS)
	$(srcdir)/genlib.sh $(SYSIO) $(AR) $(LINK) || ( rm -f $@; exit 1 )

EXTRA_DIST = genlib.sh
