# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += cmobd.o
cmobd-objs := cache_manager_obd.o cmobd_reint.o cmobd_write.o \ 
	      cmobd_oss_reint.o cmobd_mds_reint.o lproc_cm.o
	
