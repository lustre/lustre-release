## Liblustre excecutables & libraries Makefile
SUBDIRS = . tests

AM_CPPFLAGS = $(HAVE_EFENCE) -I$(SYSIO)/include -D_LARGEFILE64_SOURCE=1 \
              $(LLCPPFLAGS) -I$(top_srcdir)/lnet/ulnds
AM_CFLAGS = $(LLCFLAGS)

AM_LIBS = $(LIBEFENCE)



LUSTRE_LIBS = libllite.a \
              $(top_builddir)/lustre/lov/liblov.a \
              $(top_builddir)/lustre/obdecho/libobdecho.a \
              $(top_builddir)/lustre/osc/libosc.a \
              $(top_builddir)/lustre/fid/libfid.a \
              $(top_builddir)/lustre/fld/libfld.a \
              $(top_builddir)/lustre/lmv/liblmv.a \
              $(top_builddir)/lustre/mdc/libmdc.a \
              $(top_builddir)/lustre/mgc/libmgc.a \
              $(top_builddir)/lustre/ptlrpc/libptlrpc.a \
	      $(top_builddir)/lustre/obdclass/liblustreclass.a

LND_LIBS =
if BUILD_USOCKLND
LND_LIBS +=    $(top_builddir)/lnet/ulnds/socklnd/libsocklnd.a
endif

LNET_LIBS =   $(top_builddir)/lnet/utils/libuptlctl.a \
              $(top_builddir)/lnet/lnet/liblnet.a

SYSIO_LIBS =  $(SYSIO)/lib/libsysio.a

if LIBLUSTRE
lib_LIBRARIES = liblustre.a
noinst_LIBRARIES = libllite.a

install-exec-hook: liblustre.so
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	@list=$< ; for p in $$list; do \
	  if test -f $$p; then \
	    f="`echo $$p | sed -e 's|^.*/||'`"; \
	    echo " $(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/$$f"; \
	    $(INSTALL_DATA) $$p $(DESTDIR)$(libdir)/$$f; \
	  else :; fi; \
	done
else
install-exec-hook:
endif

libllite_a_SOURCES = llite_lib.c super.c namei.c rw.c file.c dir.c \
		     lutil.c lutil.h llite_lib.h llite_cl.c \
                     ../lclient/lcommon_cl.c ../lclient/glimpse.c ../lclient/lcommon_misc.c

# for make rpms -- need cleanup
liblustre_a_SOURCES = llite_lib.c super.c namei.c rw.c file.c dir.c \
		     llite_lib.h llite_cl.c

export CC
export LDFLAGS
export AR
export RANLIB

liblustre.a : $(LUSTRE_LIBS) $(LND_LIBS) $(LNET_LIBS) $(SYSIO_LIBS)
	sh $(srcdir)/genlib.sh "$(SYSIO)" "$(LIBS)" "$(LND_LIBS)" "$(PTHREAD_LIBS)" "$(CAP_LIBS)" "$(ZLIB)"

EXTRA_DIST = genlib.sh

CLEANFILES = liblsupport.a liblustre.so
