# Copyright (C) 2004  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../../portals/Kernelenv

#obj-y += ptlrpcs_gss.o ptlrpcs_gss_krb5.o
obj-y += ptlrpcs_gss.o
ptlrpcs_gss-objs := sec_gss.o svcsec_gss.o rawobj.o gss_mech_switch.o \
                    gss_generic_token.o gss_krb5_crypto.o gss_krb5_seal.o \
                    gss_krb5_unseal.o gss_krb5_seqnum.o gss_krb5_mech.o \
		    gss_krb5_wrap.o
#ptlrpcs_gss_krb5-objs := gss_krb5_mech.o
