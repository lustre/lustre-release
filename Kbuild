# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

this-makefile := $(lastword $(MAKEFILE_LIST))
lsrctree := $(realpath $(dir $(this-makefile)))

ifdef CONFIG_LUSTRE_FS_LDISKFS
obj-m += ldiskfs/
endif
obj-m += lnet/
obj-m += lustre/

NOSTDINC_FLAGS += -I$(lsrctree)/lnet/include
NOSTDINC_FLAGS += -I$(lsrctree)/lustre/include
NOSTDINC_FLAGS += -I$(lsrctree)/include/uapi
NOSTDINC_FLAGS += -I$(lsrctree)/include

subdir-ccflags-y := -include $(lsrctree)/config.h
subdir-ccflags-y += $(call cc-option, -Wno-format-truncation)
subdir-ccflags-y += $(call cc-option, -Wno-stringop-truncation)
subdir-ccflags-y += $(call cc-option, -Wno-stringop-overflow)
subdir-ccflags-y += $(KMOD_WERROR_FLAG)
