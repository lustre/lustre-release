# Copyright (C) 2003  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += llite.o
llite-objs := dcache.o commit_callback.o super.o rw.o iod.o super25.o \
		file.o dir.o sysctl.o symlink.o namei.o lproc_llite.o
