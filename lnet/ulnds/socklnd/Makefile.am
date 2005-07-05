if LIBLUSTRE
if !CRAY_PORTALS
noinst_LIBRARIES = libtcpnal.a
endif
endif

noinst_HEADERS =  pqtimer.h dispatch.h table.h timer.h \
	          connection.h bridge.h procbridge.h
libtcpnal_a_SOURCES = debug.c pqtimer.c select.c table.c pqtimer.h \
		      dispatch.h table.h timer.h procapi.c proclib.c \
		      connection.c tcpnal.c connection.h
libtcpnal_a_CPPFLAGS = $(LLCPPFLAGS)
libtcpnal_a_CFLAGS = $(LLCFLAGS)
