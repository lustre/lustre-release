# Copyright (C) 2003  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += ptlrpc.o
ptlrpc-objs := recover.o connection.o ptlrpc_module.o events.o service.o \
		client.o niobuf.o pack_generic.o lproc_ptlrpc.o pinger.o
