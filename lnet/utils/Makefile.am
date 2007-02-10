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

libuptlctl_a_SOURCES = portals.c nidstrings.c debug.c l_ioctl.c
libuptlctl_a_CPPFLAGS = $(LLCPPFLAGS)
libuptlctl_a_CFLAGS = $(LLCFLAGS) -DLUSTRE_UTILS=1

sbin_PROGRAMS = debugctl

lib_LIBRARIES = libptlctl.a

libptlctl_a_SOURCES = portals.c nidstrings.c debug.c l_ioctl.c parser.c parser.h

if UTILS
sbin_PROGRAMS += ptlctl routerstat wirecheck 
if BUILD_GMLND
sbin_PROGRAMS += gmlndnid
endif
endif

wirecheck_SOURCES = wirecheck.c

gmlndnid_SOURCES = gmlndnid.c
gmlndnid_CFLAGS = $(GMCPPFLAGS)
gmlndnid_LDFLAGS = -static
gmlndnid_LDADD = $(GMLIBS) -lgm

ptlctl_SOURCES = ptlctl.c
ptlctl_LDADD =  -L. -lptlctl $(LIBREADLINE) $(LIBEFENCE)
ptlctl_DEPENDENCIES = libptlctl.a

routerstat_SOURCES = routerstat.c

debugctl_SOURCES = debugctl.c
debugctl_LDADD = -L. -lptlctl $(LIBREADLINE) $(LIBEFENCE)
debugctl_DEPENDENCIES = libptlctl.a

nidstrings.c: @top_srcdir@/lnet/libcfs/nidstrings.c
	ln -sf $< $@
