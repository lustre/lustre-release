# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += mgc.o
mgc-objs := mgc_request.o lproc_mgc.o
ifdef CONFIG_LUSTRE_FS_SERVER
mgc-objs += mgc_request_server.o
endif
