# GSS daemons & tools Makefile

AM_CFLAGS := -fPIC \
	     -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS=1

LIBCFS := $(top_builddir)/libcfs/libcfs/libcfsutil.a \
	  $(top_builddir)/libcfs/libcfs/libcfs.a

sbin_PROGRAMS = lsvcgssd l_idmap

if GSS_KEYRING
sbin_PROGRAMS += lgss_keyring
endif

if GSS_PIPEFS
sbin_PROGRAMS += lgssd
endif

COMMON_SRCS = \
        context.c \
        context_lucid.c \
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

lgssd_CFLAGS = $(AM_CFLAGS) $(CFLAGS) $(KRBCFLAGS)
lgssd_LDADD =  $(GSSAPI_LIBS) $(KRBLIBS)
lgssd_LDFLAGS = $(KRBLDFLAGS)

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

lsvcgssd_CFLAGS = $(AM_CFLAGS) $(CFLAGS) $(KRBCFLAGS)
lsvcgssd_LDADD = $(LIBCFS) $(GSSAPI_LIBS) $(KRBLIBS)
lsvcgssd_LDFLAGS = $(KRBLDFLAGS)
lsvcgssd_DEPENDENCIES = $(LIBCFS)

l_idmap_SOURCES = \
	l_idmap.c \
	lsupport.c \
	err_util.c \
	\
	lsupport.h

l_idmap_LDADD = $(LIBCFS)

lgss_keyring_SOURCES = \
	lgss_keyring.c \
	context.c \
	context_lucid.c \
	context_mit.c \
	context_heimdal.c \
	lgss_krb5_utils.c \
	lgss_utils.c \
	lsupport.c \
	\
	lgss_krb5_utils.h \
	lgss_utils.h \
	lsupport.h

lgss_keyring_CFLAGS = $(AM_CFLAGS) $(CFLAGS) $(KRBCFLAGS) -D _NEW_BUILD_
lgss_keyring_LDADD = $(LIBCFS) -lkeyutils $(GSSAPI_LIBS) $(KRBLIBS)
lgss_keyring_LDFLAGS = $(KRBLDFLAGS)
lgss_keyring_DEPENDENCIES = $(LIBCFS)

EXTRA_DIST =
