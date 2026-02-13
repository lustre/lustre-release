# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += fld.o
fld-objs := fld_request.o fld_cache.o lproc_fld.o
ifdef CONFIG_LUSTRE_FS_SERVER
fld-objs += fld_handler.o fld_index.o
endif

