# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution


COMPILE = $(CC) -Wall -g -I$(srcdir)/../include
LINK = $(CC) -o $@

if LIBLUSTRE
tmp=
else
tmp=gmnalnid
endif

sbin_PROGRAMS = acceptor ptlctl debugctl routerstat wirecheck $(tmp)
lib_LIBRARIES = libptlctl.a

acceptor_SOURCES = acceptor.c # -lefence

wirecheck_SOURCES = wirecheck.c

libptlctl_a_SOURCES = portals.c debug.c l_ioctl.c parser.c parser.h
libptlctl_a_CFLAGS = -fPIC

gmnalnid_SOURCES = gmnalnid.c

ptlctl_SOURCES = ptlctl.c
ptlctl_LDADD =  -L. -lptlctl -lncurses # -lefence
ptlctl_DEPENDENCIES = libptlctl.a

debugctl_SOURCES = debugctl.c
debugctl_LDADD = -L. -lptlctl -lncurses # -lefence
debugctl_DEPENDENCIES = libptlctl.a

routerstat_SOURCES = routerstat.c
