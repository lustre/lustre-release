# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

if LIBLUSTRE
lib_LIBRARIES = libptlrpc.a
libptlrpc_a_SOURCES = client.c niobuf.c pack_generic.c recover.c connection.c \
ptlrpc_module.c events.c ptlrpc_lib.c
else
MODULE = ptlrpc
modulefs_DATA = ptlrpc.o
EXTRA_PROGRAMS = ptlrpc

ptlrpc_SOURCES = recover.c connection.c ptlrpc_module.c events.c service.c \
client.c niobuf.c pack_generic.c lproc_ptlrpc.c pinger.c ptlrpc_lib.c \
ptlrpc_internal.h
endif

include $(top_srcdir)/Rules
