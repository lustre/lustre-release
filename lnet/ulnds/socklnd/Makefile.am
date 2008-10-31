if LIBLUSTRE
if BUILD_USOCKLND
noinst_LIBRARIES = libsocklnd.a
endif
endif

noinst_HEADERS = usocklnd.h
libsocklnd_a_SOURCES = usocklnd.h usocklnd.c usocklnd_cb.c poll.c \
                       handlers.c conn.c
libsocklnd_a_CPPFLAGS = $(LLCPPFLAGS)
libsocklnd_a_CFLAGS = $(LLCFLAGS)
