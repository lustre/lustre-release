## Liblustre excecutables & libraries Makefile

AM_CPPFLAGS = -I$(SYSIO)/include -I/opt/lam/include $(LLCPPFLAGS) -I$(top_srcdir)/portals/unals
AM_CFLAGS = $(LLCFLAGS)
LIBS = $(LIBEFENCE) $(LIBREADLINE)

LLIB_EXEC= ../liblustre.a -lpthread

noinst_LIBRARIES = libtestcommon.a
libtestcommon_a_SOURCES = test_common.c test_common.h

def_tests = echo_test sanity recovery_small replay_single replay_ost_single

if MPITESTS
bin_PROGRAMS = $(def_tests) test_lock_cancel
else
bin_PROGRAMS = $(def_tests)
endif

echo_test_SOURCES = echo_test.c  ../../utils/parser.c ../../utils/obd.c ../../utils/lustre_cfg.c
echo_test_CFLAGS = $(LL_CFLAGS)
echo_test_LDADD = ../liblsupport.a $(LIBREADLINE) -lpthread 
echo_test_DEPENDENCIES=$(top_builddir)/liblustre/liblsupport.a

sanity_SOURCES = sanity.c
sanity_CFLAGS = $(LL_CFLAGS)
sanity_LDADD := ./libtestcommon.a $(LLIB_EXEC)
sanity_DEPENDENCIES = $(top_builddir)/liblustre/liblustre.a ./libtestcommon.a

recovery_small_SOURCES = recovery_small.c
recovery_small_CFLAGS = $(LL_CFLAGS)
recovery_small_LDADD := ./libtestcommon.a $(LLIB_EXEC) 
recovery_small_DEPENDENCIES = $(top_builddir)/liblustre/liblustre.a

replay_single_SOURCES = replay_single.c
replay_single_CFLAGS = $(LL_CFLAGS)
replay_single_LDADD := ./libtestcommon.a $(LLIB_EXEC)
replay_single_DEPENDENCIES = $(top_builddir)/liblustre/liblustre.a

replay_ost_single_SOURCES = replay_ost_single.c
replay_ost_single_CFLAGS = $(LL_CFLAGS)
replay_ost_single_LDADD := ./libtestcommon.a $(LLIB_EXEC)
replay_ost_single_DEPENDENCIES = $(top_builddir)/liblustre/liblustre.a

if MPITESTS
test_lock_cancel_SOURCES = test_lock_cancel.c
test_lock_cancel_CFLAGS = $(LL_CFLAGS) -I/opt/lam/include -L/opt/lam/lib
test_lock_cancel_LDADD :=  $(LLIB_EXEC) -lmpi -llam
endif


