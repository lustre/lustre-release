# Copyright (C) 2004  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += ptlrpcs.o
ptlrpcs-objs := sec.o sec_null.o svcsec.o svcsec_null.o upcall_cache.o

