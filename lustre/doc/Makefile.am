#
# GPL HEADER START
#
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License version 2 for more details (a copy is included
# in the LICENSE file that accompanied this code).
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; If not, see
# http://www.gnu.org/licenses/gpl-2.0.html
#
# GPL HEADER END
#

#
# Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2011, 2017, Intel Corporation.
#

#
# This file is part of Lustre, http://www.lustre.org/
#

MANFILES =					\
	lctl.8					\
	lctl-dl.8				\
	lctl-device_list.8			\
	lctl-get_param.8			\
	lctl-list_param.8			\
	lctl-network.8				\
	lctl-pcc.8				\
	lctl-pool_add.8				\
	lctl-pool_new.8				\
	lctl-set_param.8			\
	ldev.8					\
	ldev.conf.5				\
	lfs.1					\
	lfs-changelog.1				\
	lfs-changelog_clear.1			\
	lfs-df.1				\
	lfs-fid2path.1				\
	lfs-find.1				\
	lfs-flushctx.1				\
	lfs-getdirstripe.1			\
	lfs-getname.1				\
	lfs-getsom.1				\
	lfs-getstripe.1				\
	lfs-heat_get.1				\
	lfs-heat_set.1				\
	lfs-hsm.1				\
	lfs-hsm_action.1			\
	lfs-hsm_clear.1				\
	lfs-hsm_set.1				\
	lfs-hsm_state.1				\
	lfs-ladvise.1				\
	lfs_migrate.1				\
	lfs-migrate.1				\
	lfs-mirror-copy.1			\
	lfs-mirror-create.1			\
	lfs-mirror-delete.1			\
	lfs-mirror-extend.1			\
	lfs-mirror-read.1			\
	lfs-mirror-resync.1			\
	lfs-mirror-split.1			\
	lfs-mirror-verify.1			\
	lfs-mirror-write.1			\
	lfs-mkdir.1				\
	lfs-path2fid.1				\
	lfs-pcc-detach.1			\
	lfs-pcc-state.1				\
	lfs-pcc.1				\
	lfs-project.1				\
	lfs-quota.1				\
	lfs-rm_entry.8				\
	lfs-rmentry.8				\
	lfs-rmfid.1				\
	lfs-setdirstripe.1			\
	lfs-setquota.1				\
	lfs-setstripe.1				\
	lgss_sk.8				\
	lhbadm.8				\
	ll_decode_linkea.8			\
	llsom_sync.8				\
	llstat.8				\
	lustre.7				\
	lustre_routes_config.8			\
	lustre_routes_conversion.8		\
	lustre_rsync.8				\
	mount.lustre.8				\
	nids.5					\
	plot-llstat.8				\
	routerstat.8


LIBMAN = 					\
	lustreapi.7				\
	llapi_layout.7


SERVER_MANFILES =				\
	l_getidentity.8				\
	l_getsepol.8				\
	lctl-barrier.8				\
	lctl-changelog_deregister.8		\
	lctl-changelog_register.8		\
	lctl-clear_conf.8			\
	lctl-erase_lcfg.8			\
	lctl-fork_lcfg.8			\
	lctl-lcfg_clear.8			\
	lctl-lcfg_erase.8			\
	lctl-lcfg_fork.8			\
	lctl-lfsck-query.8			\
	lctl-lfsck_query.8			\
	lctl-lfsck-start.8			\
	lctl-lfsck_start.8			\
	lctl-lfsck-stop.8			\
	lctl-lfsck_stop.8			\
	lctl-llog_cancel.8			\
	lctl-llog_catlist.8			\
	lctl-llog_info.8			\
	lctl-llog_print.8			\
	lctl-llog_remove.8			\
	lctl-del_ost.8				\
	lctl-nodemap-activate.8			\
	lctl-nodemap_activate.8			\
	lctl-nodemap-add-idmap.8		\
	lctl-nodemap_add_idmap.8		\
	lctl-nodemap-add-range.8		\
	lctl-nodemap_add_range.8		\
	lctl-nodemap-add.8			\
	lctl-nodemap_add.8			\
	lctl-nodemap-del-idmap.8		\
	lctl-nodemap_del_idmap.8		\
	lctl-nodemap-del-range.8		\
	lctl-nodemap_del_range.8		\
	lctl-nodemap-del.8			\
	lctl-nodemap_del.8			\
	lctl-nodemap-modify.8			\
	lctl-nodemap_modify.8			\
	lctl-nodemap-set-fileset.8		\
	lctl-nodemap_set_fileset.8		\
	lctl-nodemap-set-sepol.8		\
	lctl-nodemap_set_sepol.8		\
	lctl-nodemap-test-nid.8			\
	lctl-nodemap_test_nid.8			\
	lctl-nodemap-add-offset.8		\
	lctl-nodemap_add_offset.8		\
	lctl-nodemap-del-offset.8		\
	lctl-nodemap_del_offset.8		\
	lctl-snapshot-create.8			\
	lctl-snapshot-destroy.8			\
	lctl-snapshot-list.8			\
	lctl-snapshot-modify.8			\
	lctl-snapshot-mount.8			\
	lctl-snapshot-umount.8			\
	ll_decode_filter_fid.8			\
	llobdstat.8				\
	lljobstat.8				\
	llog_reader.8				\
	llverdev.8				\
	lshowmount.8				\
	mkfs.lustre.8				\
	mount.lustre_tgt.8			\
	tunefs.lustre.8

if MANPAGES
man_MANS = $(LIBMAN)
if SERVER
man_MANS += $(SERVER_MANFILES)
endif

if UTILS
man_MANS += $(MANFILES)
endif
endif

CLEANFILES = *.aux *.tex *.log *.pdf

EXTRA_DIST = $(MANFILES) $(SERVER_MANFILES) $(LIBMAN)

all:
