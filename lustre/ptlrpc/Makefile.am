# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

if LIBLUSTRE
lib_LIBRARIES = libptlrpc.a
libptlrpc_a_SOURCES = client.c niobuf.c pack_generic.c recovd.c recover.c connection.c rpc.c events.c  # lproc_ptlrpc.c service.c
else
MODULE = ptlrpc
modulefs_DATA = ptlrpc.o
EXTRA_PROGRAMS = ptlrpc

ptlrpc_SOURCES = recovd.c recover.c connection.c rpc.c events.c service.c client.c niobuf.c pack_generic.c lproc_ptlrpc.c
endif

include $(top_srcdir)/Rules
