# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += fid.o
fid-objs := fid_request.o lproc_fid.o
ifdef CONFIG_LUSTRE_FS_SERVER
fid-objs += fid_handler.o fid_store.o fid_lib.o
endif
