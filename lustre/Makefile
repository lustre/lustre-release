# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += fid/ obdclass/ ptlrpc/ ldlm/ obdecho/ mgc/ ec/

obj-$(CONFIG_LUSTRE_FS_TESTS) += kunit/
obj-$(CONFIG_LUSTRE_FS_SERVER) += mgs/ mdt/ mdd/ ofd/ quota/ osp/ lod/ lfsck/
obj-$(CONFIG_LUSTRE_FS_SERVER) += target/ osd-wbcfs/
obj-$(CONFIG_LUSTRE_FS) += lov/ osc/ mdc/ lmv/ llite/ fld/
obj-$(CONFIG_LUSTRE_FS_LDISKFS) += osd-ldiskfs/
obj-$(CONFIG_LUSTRE_FS_ZFS) += osd-zfs/

ifneq ($(OSDADDON),)
$(eval $(OSDADDON))
endif
