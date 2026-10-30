# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

this-makefile := $(lastword $(MAKEFILE_LIST))
lsrctree := $(realpath $(dir $(this-makefile)))

obj-$(CONFIG_LUSTRE_FS_LDISKFS) += ldiskfs/
obj-m += lnet/
obj-m += lustre/

# lustre_compat shadows kernel headers, so it must come before them.
NOSTDINC_FLAGS += -I$(lsrctree)/include/lustre_compat
NOSTDINC_FLAGS += -include $(lsrctree)/config.h
NOSTDINC_FLAGS += -I$(lsrctree)/include

subdir-ccflags-y := -I$(lsrctree)/include/uapi

# Silence these C warnings for RHEL8
subdir-ccflags-y += $(call cc-option, -Wno-format-truncation)
subdir-ccflags-y += $(call cc-option, -Wno-stringop-truncation)
subdir-ccflags-y += $(call cc-option, -Wno-stringop-overflow)

subdir-ccflags-y += $(KMOD_WERROR_FLAG)
