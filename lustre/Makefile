# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-$(CONFIG_LUSTRE_FS_COMMON) += fid/ obdclass/ ptlrpc/ ldlm/ obdecho/ mgc/ ec/

obj-$(CONFIG_LUSTRE_FS) += lov/ osc/ mdc/ lmv/ llite/ fld/

obj-$(CONFIG_LUSTRE_FS_SERVER) += mgs/ mdt/ mdd/ ofd/ quota/ osp/ lod/ lfsck/
obj-$(CONFIG_LUSTRE_FS_SERVER) += target/

obj-$(CONFIG_LUSTRE_FS_WBCFS) += osd-wbcfs/
obj-$(CONFIG_LUSTRE_FS_LDISKFS) += osd-ldiskfs/
obj-$(CONFIG_LUSTRE_FS_ZFS) += osd-zfs/

obj-$(CONFIG_LUSTRE_FS_TESTS) += kunit/


subdir-ccflags-y += -I$(src)/include
