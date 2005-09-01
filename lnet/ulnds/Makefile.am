if LIBLUSTRE
if !CRAY_PORTALS
noinst_LIBRARIES = libtcplnd.a
endif
endif

noinst_HEADERS =  pqtimer.h dispatch.h table.h timer.h \
	          connection.h bridge.h procbridge.h
libtcplnd_a_SOURCES = debug.c pqtimer.c select.c table.c pqtimer.h \
		      dispatch.h table.h timer.h procapi.c proclib.c \
		      connection.c tcplnd.c connection.h
libtcplnd_a_CPPFLAGS = $(LLCPPFLAGS)
libtcplnd_a_CFLAGS = $(LLCFLAGS)
