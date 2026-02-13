# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += ec.o
ec-objs := ec_kmod.o

lobj := ec_base.o ec_base_aliases.o

ec_base_o_CPPFLAGS = -I . -DGF_LARGE_TABLES

ec-objs += $(lobj)
