# Copyright (C) 2003  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += ptlrpc.o

ptlrpc-objs := recover.o connection.o ptlrpc_module.o events.o service.o \
		client.o niobuf.o pack_generic.o lproc_ptlrpc.o pinger.o \
		recov_thread.o import.o llog_net.o llog_client.o \
		llog_server.o ptlrpcd.o ../ldlm/l_lock.o ../ldlm/ldlm_lock.o \
		../ldlm/ldlm_resource.o ../ldlm/ldlm_extent.o \
		../ldlm/ldlm_request.o ../ldlm/ldlm_lockd.o \
		../ldlm/ldlm_lib.o ../ldlm/ldlm_flock.o ../ldlm/ldlm_plain.o \
		../ldlm/ldlm_inodebits.o

