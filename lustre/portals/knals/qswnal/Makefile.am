# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include ../../Rules.linux

MODULE = kqswnal
modulenet_DATA = kqswnal.o
EXTRA_PROGRAMS = kqswnal


#CFLAGS:= @KCFLAGS@ 
#CPPFLAGS:=@KCPPFLAGS@
DEFS =
CPPFLAGS=@CPPFLAGS@ @with_quadrics@
kqswnal_SOURCES = qswnal.c qswnal_cb.c qswnal.h
