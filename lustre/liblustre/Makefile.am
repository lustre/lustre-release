## Liblustre excecutables & libraries Makefile
DEFS=

CFLAGS := -g -Wall -I$(top_srcdir)/utils -I$(top_srcdir)/portals/include \
          -I$(top_srcdir)/portals/unals -I$(SYSIO)/include \
          -I/opt/lam/include -L/opt/lam/lib

KFLAGS:=
CPPFLAGS = $(HAVE_EFENCE) -D_LARGEFILE64_SOURCE=1
LIBS = $(LIBEFENCE)

## lustre components libs
LLIBS := ./libllite.a \
         ../lov/liblov.a \
         ../obdecho/libobdecho.a \
         ../osc/libosc.a \
         ../mdc/libmdc.a \
         ../ldlm/libldlm.a \
         ../ptlrpc/libptlrpc.a \
         ../obdclass/liblustreclass.a \
	 ../lvfs/liblvfs.a

## portals components libs
PTLLIBS := ../portals/utils/libptlctl.a \
	   ../portals/unals/libtcpnal.a \
           ../portals/portals/libportals.a

## sysio components libs
SYSIOLIBS := $(SYSIO)/drivers/native/libsysio_native.a \
             $(SYSIO)/drivers/sockets/libsysio_sockets.a \
             $(SYSIO)/src/libsysio.a \
             $(SYSIO)/dev/stdfd/libsysio_stdfd.a

LLIB_EXEC= $(PTLLIBS) $(SYSIOLIBS) -lpthread

lib_LIBRARIES = 
noinst_LIBRARIES = libllite.a libtestcommon.a
libllite_a_SOURCES = llite_lib.c super.c namei.c rw.c file.c
libtestcommon_a_SOURCES = test_common.c

bin_PROGRAMS = libtest lltest recovery_small replay_single #test_lock_cancel

libtest_SOURCES = libtest.c  ../utils/parser.c ../utils/obd.c ../utils/lustre_cfg.c
libtest_LDADD := $(LLIBS) $(PTLLIBS) \
                 $(LIBREADLINE) -lpthread 

liblustre.a : libllite.a
	$(shell ./genlib.sh $(SYSIO) $(AR) $(LINK))

lltest_SOURCES = lltest.c
lltest_LDADD := ./libtestcommon.a $(LLIBS) $(LLIB_EXEC) $(LIBREADLINE)

recovery_small_SOURCES = recovery_small.c
recovery_small_LDADD := ./libtestcommon.a $(LLIBS) $(LLIB_EXEC) $(LIBREADLINE)

replay_single_SOURCES = replay_single.c
replay_single_LDADD := ./libtestcommon.a $(LLIBS) $(LLIB_EXEC) $(LIBREADLINE)

#test_lock_cancel_SOURCES = test_lock_cancel.c
#test_lock_cancel_LDADD :=  $(LLIBS) $(LLIB_EXEC) -lmpi -llam

include $(top_srcdir)/Rules

