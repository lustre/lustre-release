# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

## $(srcdir)/../ for <portals/*.h>, ../../ for generated <config.h>
#COMPILE = $(CC) -Wall -g -I$(srcdir)/../include -I../../include
#LINK = $(CC) -o $@

if LIBLUSTRE
noinst_LIBRARIES = libuptlctl.a
endif

libuptlctl_a_SOURCES = portals.c debug.c l_ioctl.c
libuptlctl_a_CPPFLAGS = $(LLCPPFLAGS) -DLUSTRE_UTILS=1
libuptlctl_a_CFLAGS = $(LLCFLAGS)

sbin_PROGRAMS = debugctl

lib_LIBRARIES = libptlctl.a

libptlctl_a_SOURCES = portals.c debug.c l_ioctl.c parser.c parser.h

if UTILS
if !CRAY_PORTALS
sbin_PROGRAMS += acceptor ptlctl routerstat wirecheck 
endif
if BUILD_GMNAL
sbin_PROGRAMS += gmnalnid
endif
endif

acceptor_SOURCES = acceptor.c
acceptor_LDADD = $(LIBWRAP)

wirecheck_SOURCES = wirecheck.c

gmnalnid_SOURCES = gmnalnid.c
gmnalnid_CFLAGS = $(GMCPPFLAGS)
gmnalnid_LDFLAGS = -static
gmnalnid_LDADD = $(GMLIBS) -lgm

ptlctl_SOURCES = ptlctl.c
ptlctl_LDADD =  -L. -lptlctl $(LIBREADLINE) $(LIBEFENCE)
ptlctl_DEPENDENCIES = libptlctl.a

routerstat_SOURCES = routerstat.c

debugctl_SOURCES = debugctl.c
debugctl_LDADD = -L. -lptlctl $(LIBREADLINE) $(LIBEFENCE)
debugctl_DEPENDENCIES = libptlctl.a
