
if BUILD_UPTLLND
if LIBLUSTRE 
noinst_LIBRARIES = libptllnd.a
noinst_HEADERS =  ptllnd.h
libptllnd_a_SOURCES = ptllnd.h ptllnd.c ptllnd_cb.c
libptllnd_a_CPPFLAGS= $(LLCPPFLAGS)
# I need $(PTLNDCPPLFLAGS) to be AFTER $(CPPFLAGS)
# Adding them into $(AM_CFLAGS) seems wrong, but lets me get on..
libptllnd_a_CFLAGS= $(PTLLNDCPPFLAGS) $(LLCFLAGS)
endif
endif
