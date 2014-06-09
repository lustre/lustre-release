## Liblustre MPI tests Makefile

AM_CPPFLAGS = -I$(SYSIO)/include $(LLCPPFLAGS) -I$(top_srcdir)/lnet/ulnds
AM_CFLAGS = $(LLCFLAGS)

LLIB_EXEC = $(top_builddir)/lustre/utils/liblustreapi.a $(top_builddir)/lustre/liblustre/liblustre.a $(CAP_LIBS) $(PTHREAD_LIBS)

CC = @MPICC_WRAPPER@

if LIBLUSTRE
if LIBLUSTRE_TESTS
noinst_PROGRAMS = test_lock_cancel
endif # LIBLUSTRE_TESTS
endif # LIBLUSTRE

test_lock_cancel_SOURCES = test_lock_cancel.c
test_lock_cancel_LDADD :=  $(LLIB_EXEC)
