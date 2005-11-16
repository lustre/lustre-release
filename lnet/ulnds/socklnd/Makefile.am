if LIBLUSTRE
if BUILD_USOCKLND
noinst_LIBRARIES = libsocklnd.a
endif
endif

noinst_HEADERS =  pqtimer.h dispatch.h table.h timer.h \
	          connection.h bridge.h procbridge.h
libsocklnd_a_SOURCES = pqtimer.c select.c table.c pqtimer.h \
		      dispatch.h table.h timer.h procapi.c proclib.c \
		      connection.c tcplnd.c connection.h
libsocklnd_a_CPPFLAGS = $(LLCPPFLAGS)
libsocklnd_a_CFLAGS = $(LLCFLAGS)
