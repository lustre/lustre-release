## Liblustre excecutables & libraries Makefile
DEFS=

CFLAGS := -g -Wall -I$(top_srcdir)/utils -I$(top_srcdir)/portals/include \
          -I$(top_srcdir)/portals/unals -I$(SYSIO)/include \
          -I/opt/lam/include -L/opt/lam/lib

KFLAGS:=
CPPFLAGS = $(HAVE_EFENCE) -D_LARGEFILE64_SOURCE=1
LIBS = $(LIBEFENCE)


LLIB_EXEC= ../liblustre.a -lpthread

noinst_LIBRARIES = libtestcommon.a
libtestcommon_a_SOURCES = test_common.c

bin_PROGRAMS = echo_test sanity recovery_small replay_single test_lock_cancel

echo_test_SOURCES = echo_test.c  ../../utils/parser.c ../../utils/obd.c ../../utils/lustre_cfg.c
echo_test_LDADD = ../liblsupport.a $(LIBREADLINE) -lpthread 
echo_test_DEPENDENCIES=$(top_srcdir)/liblustre/liblsupport.a

sanity_SOURCES = sanity.c
sanity_LDADD := ./libtestcommon.a $(LLIB_EXEC)
sanity_DEPENDENCIES = $(top_srcdir)/liblustre/liblustre.a ./libtestcommon.a

recovery_small_SOURCES = recovery_small.c
recovery_small_LDADD := ./libtestcommon.a $(LLIB_EXEC) 
recovery_small_DEPENDENCIES = $(top_srcdir)/liblustre/liblustre.a

replay_single_SOURCES = replay_single.c
replay_single_LDADD := ./libtestcommon.a $(LLIB_EXEC)
replay_single_DEPENDENCIES = $(top_srcdir)/liblustre/liblustre.a

test_lock_cancel_SOURCES = test_lock_cancel.c
test_lock_cancel_LDADD :=  $(LLIB_EXEC) -lmpi -llam

include $(top_srcdir)/Rules

