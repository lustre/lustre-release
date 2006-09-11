# gss daemons Makefile

SUBDIRS =

AM_CFLAGS=$(LLCFLAGS)
AM_CPPFLAGS=$(LLCPPFLAGS) -DLUSTRE_UTILS=1
AM_LDFLAGS := -L$(top_builddir)/lnet/utils

LIBPTLCTL := $(top_builddir)/lnet/utils/libptlctl.a

sbin_PROGRAMS = lgssd lsvcgssd

COMMON_SRCS = \
        context.c \
        context_mit.c \
        context_heimdal.c \
        context_spkm3.c \
        gss_util.c \
        gss_oids.c \
        err_util.c \
        lsupport.c \
        \
        context.h \
        err_util.h \
        gss_oids.h \
        gss_util.h \
	lsupport.h

lgssd_SOURCES = \
        $(COMMON_SRCS) \
        gssd.c \
        gssd_main_loop.c \
        gssd_proc.c \
        krb5_util.c \
        \
        gssd.h \
        krb5_util.h \
        write_bytes.h

lgssd_LDADD = $(GSSAPI_LIBS) $(KRBLIBS)
lgssd_LDFLAGS = $(KRBLDFLAGS)
lgssd_CFLAGS = $(AM_CFLAGS) $(CFLAGS) $(KRBCFLAGS)

lsvcgssd_SOURCES = \
        $(COMMON_SRCS) \
        cacheio.c \
        svcgssd.c \
        svcgssd_main_loop.c \
        svcgssd_mech2file.c \
        svcgssd_proc.c \
        \
        cacheio.h \
        svcgssd.h

lsvcgssd_LDADD = $(GSSAPI_LIBS) $(KRBLIBS)
lsvcgssd_LDFLAGS = $(KRBLDFLAGS)
lsvcgssd_CFLAGS = $(AM_CFLAGS) $(CFLAGS) $(KRBCFLAGS)

EXTRA_DIST =
