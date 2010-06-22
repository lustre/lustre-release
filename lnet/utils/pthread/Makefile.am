sbin_PROGRAMS = lstclient

CC = $(PTHREAD_CC)
LD = $(PTHREAD_CC)

lstclient_CFLAGS = $(PTHREAD_CFLAGS)
lstclient_SOURCES = ../lstclient.c
lstclient_LDFLAGS = $(PTHREAD_CFLAGS)
lstclient_LDADD = -L.. -lptlctl -llst $(LIBREADLINE) $(LIBEFENCE) $(PTHREAD_LIBS)
lstclient_DEPENDENCIES = ../libptlctl.a ../liblst.a
