# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += obdecho.o
obdecho-objs := echo_client.o debug.o
ifdef CONFIG_LUSTRE_FS_SERVER
obdecho-objs += echo.o
endif
