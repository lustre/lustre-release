# Copyright (C) 2003  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += lmv.o
lmv-objs := lmv_obd.o lmv_intent.o lmv_objmgr.o lproc_lmv.o
