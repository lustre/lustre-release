# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += ptlrpc_gss.o

ptlrpc_gss-objs := sec_gss.o gss_bulk.o gss_cli_upcall.o gss_svc_upcall.o \
		   gss_rawobj.o lproc_gss.o \
		   gss_generic_token.o gss_mech_switch.o gss_krb5_mech.o \
		   gss_null_mech.o gss_crypto.o

ifdef CONFIG_LUSTRE_FS_GSS_SSK
ptlrpc_gss-objs += gss_sk_mech.o
endif
ifdef CONFIG_LUSTRE_FS_GSS_KEYRING
ptlrpc_gss-objs += gss_keyring.o
endif
