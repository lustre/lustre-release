AM_CPPFLAGS = $(LLCPPFLAGS) -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS
AM_CFLAGS = $(LLCFLAGS)

LIBPTLCTL := $(top_builddir)/lnet/utils/libptlctl.a $(top_builddir)/libcfs/libcfs/libcfsutil.a

sbin_PROGRAMS = lctl
sbin_PROGRAMS += loadgen
bin_PROGRAMS = lfs

CC = $(PTHREAD_CC)
LD = $(PTHREAD_CC)

lctl_CFLAGS = $(PTHREAD_CFLAGS)
lctl_SOURCES = ../obd.c ../lustre_cfg.c ../lctl.c ../obdctl.h
lctl_LDFLAGS := $(PTHREAD_CFLAGS)
lctl_LDADD := $(LIBREADLINE) ../liblustreapi.a $(LIBPTLCTL) $(PTHREAD_LIBS)
lctl_DEPENDENCIES := $(LIBPTLCTL) ../liblustreapi.a

lfs_CFLAGS = $(PTHREAD_CFLAGS)
lfs_SOURCES = ../lfs.c ../lustre_cfg.c ../obd.c
lfs_LDFLAGS := $(PTHREAD_CFLAGS)
lfs_LDADD := $(LIBREADLINE) ../liblustreapi.a $(LIBPTLCTL) $(PTHREAD_LIBS)
lfs_DEPENDENCIES := $(LIBPTLCTL) ../liblustreapi.a

loadgen_CFLAGS = $(PTHREAD_CFLAGS)
loadgen_SOURCES = ../loadgen.c ../lustre_cfg.c ../obd.c
loadgen_LDFLAGS := $(PTHREAD_CFLAGS)
loadgen_LDADD := $(LIBREADLINE) ../liblustreapi.a $(LIBPTLCTL) $(PTHREAD_LIBS)
loadgen_DEPENDENCIES := $(LIBPTLCTL) ../liblustreapi.a
