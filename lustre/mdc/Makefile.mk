# Copyright (C) 2003  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += mdc.o
mdc-objs := mdc_request.o mdc_reint.o lproc_mdc.o
