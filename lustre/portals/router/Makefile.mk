# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../Kernelenv

obj-y += kptlrouter.o
kptlrouter-objs    := router.o proc.o
