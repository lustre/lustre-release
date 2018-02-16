# Lustre MPI test Makefile
AM_CFLAGS := -fPIC -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64

CC = @MPICC_WRAPPER@

THETESTS = parallel_grouplock write_append_truncate createmany_mpi \
	   mdsrate write_disjoint cascading_rw rr_alloc

if TESTS
if MPITESTS
testdir = $(libdir)/lustre/tests
test_PROGRAMS = $(THETESTS)
else
noinst_PROGRAMS = $(THETESTS)
endif
endif

write_append_truncate_SOURCES=write_append_truncate.c
write_disjoint_SOURCES=write_disjoint.c
createmany_mpi_SOURCES=createmany-mpi.c
parallel_grouplock_SOURCES=parallel_grouplock.c lp_utils.c lp_utils.h
rr_alloc_SOURCES=rr_alloc.c

cascading_rw_SOURCES=cascading_rw.c lp_utils.c lp_utils.h
cascading_rw_LDADD=$(top_builddir)/lustre/utils/liblustreapi.la

mdsrate_SOURCES=mdsrate.c
mdsrate_LDADD=$(top_builddir)/lustre/utils/liblustreapi.la
