# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include fs/lustre/portals/Kernelenv

obj-y += libcfs.o
libcfs-objs    := module.o proc.o debug.o
