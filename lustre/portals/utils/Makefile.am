# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

COMPILE = $(CC) -Wall -g -I$(srcdir)/../include
LINK = $(CC) -o $@

if LIBLUSTRE

noinst_LIBRARIES = libuptlctl.a
libuptlctl_a_SOURCES = portals.c debug.c l_ioctl.c parser.c parser.h
libuptlctl_a_CFLAGS = -fPIC

else

sbin_PROGRAMS = acceptor ptlctl debugctl routerstat wirecheck gmnalnid
lib_LIBRARIES = libptlctl.a

acceptor_SOURCES = acceptor.c # -lefence

wirecheck_SOURCES = wirecheck.c

libptlctl_a_SOURCES = portals.c debug.c l_ioctl.c parser.c parser.h

gmnalnid_SOURCES = gmnalnid.c

ptlctl_SOURCES = ptlctl.c
ptlctl_LDADD =  -L. -lptlctl $(LIBREADLINE) $(LIBEFENCE)
ptlctl_DEPENDENCIES = libptlctl.a

debugctl_SOURCES = debugctl.c
debugctl_LDADD = -L. -lptlctl $(LIBREADLINE) $(LIBEFENCE)
debugctl_DEPENDENCIES = libptlctl.a

routerstat_SOURCES = routerstat.c
endif
