# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += osd_zfs.o
osd_zfs-objs := osd_handler.o osd_lproc.o osd_quota.o
osd_zfs-objs += osd_object.o osd_io.o osd_oi.o osd_xattr.o osd_index.o
osd_zfs-objs += osd_scrub.o

ifdef CONFIG_LUSTRE_FS_SPL
ccflags-y += -include $(SPL_OBJ)/spl_config.h
ccflags-y += -I$(SPL) -I$(SPL)/include
endif
ccflags-y += -include $(ZFS_OBJ)/zfs_config.h
ccflags-y += -I$(ZFS)/include/os/linux/kernel
ccflags-y += -I$(ZFS)/include/os/linux/spl -I$(ZFS)/include/os/linux/zfs
ccflags-y += -I$(ZFS) -I$(ZFS)/include
ifndef CONFIG_LUSTRE_FS_SPL
ccflags-y += -I$(ZFS)/include/spl
endif
