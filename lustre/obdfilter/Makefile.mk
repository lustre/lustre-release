# Copyright (C) 2003  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += obdfilter.o
obdfilter-objs := filter.o lproc_obdfilter.o filter_log.o filter_io.o \
			filter_san.o filter_io_26.o

