# Copyright (C) 2003  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += ost.o
ost-objs := ost_handler.o lproc_ost.o
