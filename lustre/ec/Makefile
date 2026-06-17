# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += ec.o
ec-objs := ec_kmod.o

lobj := ec_base.o ec_base_aliases.o

ec-objs += $(lobj)

ifdef CONFIG_GCOV_PROFILE_LUSTRE
GCOV_PROFILE := y
endif
