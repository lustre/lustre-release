if LIBLUSTRE
noinst_LIBRARIES = libtcpnal.a
endif

if !CRAY_PORTALS
pkginclude_HEADERS =  pqtimer.h dispatch.h table.h timer.h connection.h ipmap.h bridge.h procbridge.h
libtcpnal_a_SOURCES = debug.c pqtimer.c select.c table.c pqtimer.h dispatch.h table.h timer.h address.c procapi.c proclib.c connection.c tcpnal.c connection.h
libtcpnal_a_CPPFLAGS = $(LLCPPFLAGS)
libtcpnal_a_CFLAGS = $(LLCFLAGS)
endif