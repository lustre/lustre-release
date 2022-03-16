if TESTS
testdir = $(libdir)/lustre/tests
test_PROGRAMS = iabf
endif

iabf_CPPFLAGS = -D_GNU_SOURCE
iabf_CFLAGS = -g -Wall -Werror
iabf_LDFLAGS = -pthread
iabf_SOURCES = iabf.c callvpe.c callvpe.h
