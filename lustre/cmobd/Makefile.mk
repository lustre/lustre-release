# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += cmobd.o
cmobd-objs := cm_obd.o cm_reint.o cm_write.o \ 
	      cm_oss_reint.o cm_mds_reint.o lproc_cm.o
	
