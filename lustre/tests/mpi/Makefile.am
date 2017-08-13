# Lustre MPI test Makefile
AM_CFLAGS := -fPIC \
	     -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS=1

LIBCFS :=  $(top_builddir)/libcfs/libcfs/libcfs.a
LIBLUSTREAPI = $(top_builddir)/lustre/utils/liblustreapi.la

CC = @MPICC_WRAPPER@

THETESTS = parallel_grouplock write_append_truncate createmany_mpi \
	   mdsrate write_disjoint cascading_rw

if TESTS
if MPITESTS
testdir = $(libdir)/lustre/tests
test_PROGRAMS = $(THETESTS)
else
noinst_PROGRAMS = $(THETESTS)
endif
else
noinst_PROGRAMS = $(THETESTS)
endif

createmany_mpi_SOURCES=createmany-mpi.c
parallel_grouplock_SOURCES=parallel_grouplock.c lp_utils.c lp_utils.h

cascading_rw_SOURCES=cascading_rw.c lp_utils.c lp_utils.h
cascading_rw_LDADD=$(LIBLUSTREAPI) $(LIBCFS)

mdsrate_SOURCES=mdsrate.c
mdsrate_LDADD=$(LIBLUSTREAPI) $(LIBCFS)
