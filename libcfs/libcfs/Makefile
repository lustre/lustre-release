# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += libcfs.o

# Debug objects
libcfs-y := debug.o fail.o module.o tracefile.o

# Compat: core (lustre_compat/module.c, symbols.c, misc.c)
include $(src)/../../lustre_compat/Makefile
libcfs-y += $(patsubst %,../../lustre_compat/%,$(module_objs))

# Compat: fs/crypto (conditional on CONFIG_LL_ENCRYPTION)
include $(src)/../../lustre_compat/fs/crypto/Makefile
ifneq ($(shell grep -c 'define CONFIG_LL_ENCRYPTION 1' $(src)/../../config.h 2>/dev/null),0)
libcfs-y += $(patsubst %,../../lustre_compat/fs/crypto/%,$(fscrypt_objs))
endif

# Compat: mm
include $(src)/../../lustre_compat/mm/Makefile
libcfs-y += $(patsubst %,../../lustre_compat/mm/%,$(mm_objs))

ifdef CONFIG_GCOV_PROFILE_LUSTRE
GCOV_PROFILE := y
endif
