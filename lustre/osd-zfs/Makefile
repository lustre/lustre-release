# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-$(CONFIG_LUSTRE_FS_ZFS) += osd_zfs.o
osd_zfs-objs := osd_handler.o osd_lproc.o osd_quota.o
osd_zfs-objs += osd_object.o osd_io.o osd_oi.o osd_xattr.o osd_index.o
osd_zfs-objs += osd_scrub.o

ifdef LUSTRE_OOT_BUILD
zfs_incdir := $(ZFS)/include
spl_incdir := $(SPL)/include
else
ZFS     := $(srctree)/include/zfs
ZFS_OBJ := $(srctree)/include/zfs
SPL     := $(srctree)/include/zfs
SPL_OBJ := $(srctree)/include/zfs
zfs_incdir := $(ZFS)
spl_incdir := $(SPL)
endif

ifdef CONFIG_LUSTRE_FS_SPL
ccflags-y += -include $(SPL_OBJ)/spl_config.h
ccflags-y += -I$(SPL) -I$(spl_incdir)
endif
ccflags-y += -include $(ZFS_OBJ)/zfs_config.h
ccflags-y += -I$(zfs_incdir)/os/linux/kernel
ccflags-y += -I$(zfs_incdir)/os/linux/spl -I$(zfs_incdir)/os/linux/zfs
ccflags-y += -I$(ZFS) -I$(zfs_incdir)
ifndef CONFIG_LUSTRE_FS_SPL
ccflags-y += -I$(zfs_incdir)/spl
endif

ifdef CONFIG_GCOV_PROFILE_LUSTRE
GCOV_PROFILE := y
endif
