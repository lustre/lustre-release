## Liblustre excecutables & libraries Makefile
SUBDIRS = . tests

AM_CPPFLAGS = $(HAVE_EFENCE) -I$(SYSIO)/include -D_LARGEFILE64_SOURCE=1 \
              $(LLCPPFLAGS) -I$(top_srcdir)/portals/unals
AM_CFLAGS = $(LLCFLAGS)

LIBS = $(LIBEFENCE)

LUSTRE_LIBS = liblutils.a libllite.a \
              $(top_builddir)/lov/liblov.a \
              $(top_builddir)/obdecho/libobdecho.a \
              $(top_builddir)/osc/libosc.a \
              $(top_builddir)/mdc/libmdc.a \
              $(top_builddir)/ptlrpc/libptlrpc.a \
              $(top_builddir)/obdclass/liblustreclass.a \
              $(top_builddir)/lvfs/liblvfs.a

if !CRAY_PORTALS
PTL_LIBS =    $(top_builddir)/portals/utils/libuptlctl.a \
              $(top_builddir)/portals/unals/libtcpnal.a \
              $(top_builddir)/portals/portals/libportals.a
else
PTL_LIBS =    $(top_builddir)/portals/utils/libuptlctl.a \
              $(CRAY_PORTALS_PATH)/lib_TV/snos64/libportals.a
endif

SYSIO_LIBS =  $(SYSIO)/lib/libsysio.a

if LIBLUSTRE
lib_LIBRARIES = liblustre.a
noinst_LIBRARIES = liblutils.a libllite.a

install-exec-hook: liblustre.so
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	@list=$< ; for p in $$list; do \
	  if test -f $$p; then \
	    f="`echo $$p | sed -e 's|^.*/||'`"; \
	    echo " $(libLIBRARIES_INSTALL) $$p $(DESTDIR)$(libdir)/$$f"; \
	    $(libLIBRARIES_INSTALL) $$p $(DESTDIR)$(libdir)/$$f; \
	  else :; fi; \
	done
else
install-exec-hook:
endif

liblutils_a_SOURCES = lutil.c lutil.h

libllite_a_SOURCES = llite_lib.c super.c namei.c rw.c file.c dir.c \
		     llite_lib.h

# for make rpms -- need cleanup
liblustre_a_SOURCES = llite_lib.c super.c namei.c rw.c file.c dir.c

liblustre.a : $(LUSTRE_LIBS) $(PTL_LIBS) $(SYSIO_LIBS)
	sh $(srcdir)/genlib.sh $(SYSIO) $(CRAY_PORTALS_PATH)

EXTRA_DIST = genlib.sh

CLEANFILES := liblsupport.a liblustre.so
