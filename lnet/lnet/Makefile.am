# Copyright (C) 2002  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS =

my_sources = api-eq.c api-init.c api-me.c api-errno.c api-ni.c api-wrap.c \
		lib-dispatch.c lib-init.c lib-me.c lib-msg.c lib-eq.c \
		lib-md.c lib-move.c lib-ni.c lib-pid.c

noinst_LIBRARIES= libportals.a
libportals_a_SOURCES= $(my_sources)

if LIBLUSTRE
libportals_a_CFLAGS= -fPIC
else

MODULE = portals
modulenet_DATA = portals.o
EXTRA_PROGRAMS = portals

DISTCLEANFILES = *.orig *.rej

portals_SOURCES= module.c $(my_sources)

# Don't distribute any patched files.
dist-hook:
	list='$(EXT2C)'; for f in $$list; do rm -f $(distdir)/$$f; done

include ../Rules.linux
endif
