## Liblustre excecutables & libraries Makefile

AM_CPPFLAGS = -I$(SYSIO)/include -I/opt/lam/include $(LLCPPFLAGS) -I$(top_srcdir)/lnet/ulnds
AM_CFLAGS = $(LLCFLAGS)
AM_LIBS = $(LIBEFENCE) $(LIBREADLINE)

LLIB_EXEC = $(top_builddir)/lustre/utils/liblustreapi.a $(top_builddir)/lustre/liblustre/liblustre.a $(CAP_LIBS) $(PTHREAD_LIBS) $(ZLIB)

if LIBLUSTRE
noinst_LIBRARIES = libtestcommon.a

if LIBLUSTRE_TESTS
if MPITESTS
SUBDIRS = mpi
endif # MPITESTS

noinst_PROGRAMS = sanity

noinst_PROGRAMS += recovery_small replay_single replay_ost_single

liblustre_testdir=$(libdir)/lustre/liblustre/tests
liblustre_test_PROGRAMS = $(noinst_PROGRAMS)
liblustre_test_LIBRARIES = $(noinst_LIBRARIES)

endif # LIBLUSTRE_TESTS
endif # LIBLUSTRE

DIST_SUBDIRS = mpi

libtestcommon_a_SOURCES = test_common.c test_common.h

sanity_SOURCES = sanity.c
sanity_CFLAGS = $(LL_CFLAGS)
sanity_LDADD := libtestcommon.a $(LLIB_EXEC)
sanity_DEPENDENCIES = $(top_builddir)/lustre/liblustre/liblustre.a libtestcommon.a

recovery_small_SOURCES = recovery_small.c
recovery_small_CFLAGS = $(LL_CFLAGS)
recovery_small_LDADD := libtestcommon.a $(LLIB_EXEC) 
recovery_small_DEPENDENCIES = $(top_builddir)/lustre/liblustre/liblustre.a libtestcommon.a

replay_single_SOURCES = replay_single.c
replay_single_CFLAGS = $(LL_CFLAGS)
replay_single_LDADD := libtestcommon.a $(LLIB_EXEC)
replay_single_DEPENDENCIES = $(top_builddir)/lustre/liblustre/liblustre.a libtestcommon.a

replay_ost_single_SOURCES = replay_ost_single.c
replay_ost_single_CFLAGS = $(LL_CFLAGS)
replay_ost_single_LDADD := libtestcommon.a $(LLIB_EXEC)
replay_ost_single_DEPENDENCIES = $(top_builddir)/lustre/liblustre/liblustre.a libtestcommon.a
