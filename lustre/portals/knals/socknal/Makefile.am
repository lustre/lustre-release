# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include ../../Rules.linux

MODULE = ksocknal
modulenet_DATA = ksocknal.o
EXTRA_PROGRAMS = ksocknal

# If you don't build with -O2, your modules won't insert, becahse htonl is
# just special that way.
AM_CFLAGS = -O2

DEFS =
ksocknal_SOURCES = socknal.c socknal_cb.c socknal.h
