# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution


COMPILE = gcc -Wall -g -I$(srcdir)/../include 
LINK = gcc -o $@

sbin_PROGRAMS = acceptor ptlctl debugctl routerstat
lib_LIBRARIES = libptlctl.a

acceptor_SOURCES = acceptor.c # -lefence

libptlctl_a_SOURCES = portals.c debug.c l_ioctl.c parser.c parser.h

ptlctl_SOURCES = ptlctl.c
ptlctl_LDADD =  -L. -lptlctl -lncurses # -lefence
ptlctl_DEPENDENCIES = libptlctl.a

debugctl_SOURCES = debugctl.c
debugctl_LDADD = -L. -lptlctl -lncurses # -lefence
debugctl_DEPENDENCIES = libptlctl.a

routerstat_SOURCES = routerstat.c
