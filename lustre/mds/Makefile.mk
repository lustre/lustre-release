# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include fs/lustre/portals/Kernelenv

obj-y += mds.o

mds-objs    := mds_lov.o handler.o mds_reint.o mds_fs.o lproc_mds.o mds_internal.h mds_updates.o mds_open.o simple.o target.o
