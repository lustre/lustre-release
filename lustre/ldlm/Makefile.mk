# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += ldlm.o
ldlm-objs := l_lock.o ldlm_lock.o ldlm_resource.o ldlm_extent.o ldlm_request.o \
		ldlm_lockd.o ldlm_lib.o
