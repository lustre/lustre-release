# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

ifneq ($(BUILD_EXT_O2IB),)

obj-m += ko2iblnd.o

endif

ko2iblnd-objs := o2iblnd.o o2iblnd_cb.o o2iblnd_modparams.o

ccflags-y += $(EXTRA_KCFLAGS)

lsrctree := $(realpath $(src)/../../..)

# Include the Lustre header paths
ccflags-y += -include $(lsrctree)/config.h
NOSTDINC_FLAGS += -I$(lsrctree)/lnet/include/uapi
NOSTDINC_FLAGS += -I$(lsrctree)/lnet/include
NOSTDINC_FLAGS += -I$(lsrctree)/lustre/include/uapi
NOSTDINC_FLAGS += -I$(lsrctree)/lustre/include
NOSTDINC_FLAGS += -I$(lsrctree)/include

# Need to make sure that an external OFED source pool overrides
# any in-kernel OFED sources
NOSTDINC_FLAGS += $(EXTRA_OFED_CONFIG) $(EXTRA_OFED_INCLUDE)
# Identify this as the External driver build
NOSTDINC_FLAGS += -DEXTERNAL_OFED_BUILD -DEXTERNAL_OFED_VERSION='"$(EXT_O2IB_VER)"'

ifdef CONFIG_GCOV_PROFILE_LNET
GCOV_PROFILE := y
endif
