# Lustre MPI test Makefile
AM_CPPFLAGS = $(LLCPPFLAGS) -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DLUSTRE_UTILS
AM_CFLAGS = $(LLCFLAGS)

CC = @MPICC_WRAPPER@

noinst_PROGRAMS = parallel_grouplock write_append_truncate createmany_mpi mdsrate
testdir = $(libdir)/lustre/tests
test_SCRIPTS = $(noinst_PROGRAMS)

write_append_truncate_SOURCES=write_append_truncate.c
createmany_mpi_SOURCES=createmany-mpi.c
parallel_grouplock_SOURCES=parallel_grouplock.c lp_utils.c lp_utils.h
mdsrate_SOURCES=mdsrate.c
mdsrate_LDADD=-L$(top_builddir)/lustre/utils -llustreapi
