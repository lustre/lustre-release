# Copyright (C) 2003  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += lov.o
lov-objs := lov_obd.o lov_pack.o lproc_lov.o lov_log.o lov_offset.o lov_merge.o lov_request.o lov_qos.o
