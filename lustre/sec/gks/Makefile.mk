# Copyright (C) 2004  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../../portals/Kernelenv

#obj-y += ptlrpcs_gss.o ptlrpcs_gss_krb5.o
obj-y += gks.o gkc.o
gks-objs := lprocfs_gks.o gks_server.o
gkc-objs := lprofs_gks.o gks_client.o 
