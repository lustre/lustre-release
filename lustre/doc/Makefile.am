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
# Copyright (c) 2011, 2016, Intel Corporation.
#

#
# This file is part of Lustre, http://www.lustre.org/
# Lustre is a trademark of Sun Microsystems, Inc.
#

MANFILES =					\
	lctl.8					\
	lctl-network.8				\
	ldev.8					\
	ldev.conf.5				\
	lfs.1					\
	lfs-df.1				\
	lfs-getdirstripe.1			\
	lfs-hsm.1				\
	lfs-ladvise.1				\
	lfs_migrate.1				\
	lfs-migrate.1				\
	lfs-mkdir.1				\
	lfs-setdirstripe.1			\
	lfs-setstripe.1				\
	l_getidentity.8				\
	lgss_sk.8				\
	lhbadm.8				\
	llapi_fd2parent.3			\
	llapi_file_create.3			\
	llapi_file_get_stripe.3			\
	llapi_file_open.3			\
	llapi_group_lock.3			\
	llapi_group_unlock.3			\
	llapi_hsm_action_begin.3		\
	llapi_hsm_action_end.3			\
	llapi_hsm_action_get_dfid.3		\
	llapi_hsm_action_get_fd.3		\
	llapi_hsm_action_progress.3		\
	llapi_hsm_copytool_get_fd.3		\
	llapi_hsm_copytool_recv.3		\
	llapi_hsm_copytool_register.3		\
	llapi_hsm_copytool_unregister.3		\
	llapi_hsm_state_get.3			\
	llapi_hsm_state_set.3			\
	llapi_ladvise.3				\
	llapi_layout.7				\
	llapi_layout_alloc.3			\
	llapi_layout_comp_add.3			\
	llapi_layout_comp_del.3			\
	llapi_layout_comp_extent_get.3		\
	llapi_layout_comp_extent_set.3		\
	llapi_layout_comp_flags_clear.3		\
	llapi_layout_comp_flags_get.3		\
	llapi_layout_comp_flags_set.3		\
	llapi_layout_comp_id_get.3		\
	llapi_layout_comp_use.3			\
	llapi_layout_comp_use_id.3		\
	llapi_layout_file_comp_add.3		\
	llapi_layout_file_comp_del.3		\
	llapi_layout_file_create.3		\
	llapi_layout_file_open.3		\
	llapi_layout_free.3			\
	llapi_layout_get_by_fd.3		\
	llapi_layout_get_by_fid.3		\
	llapi_layout_get_by_path.3		\
	llapi_layout_ost_index_get.3		\
	llapi_layout_ost_index_set.3		\
	llapi_layout_pattern_get.3		\
	llapi_layout_pattern_set.3		\
	llapi_layout_pool_name_get.3		\
	llapi_layout_pool_name_set.3		\
	llapi_layout_stripe_count_get.3		\
	llapi_layout_stripe_count_set.3		\
	llapi_layout_stripe_size_get.3		\
	llapi_layout_stripe_size_set.3		\
	llapi_path2fid.3			\
	llapi_path2parent.3			\
	llapi_quotactl.3			\
	ll_decode_filter_fid.8			\
	ll_decode_linkea.8			\
	llobdstat.8				\
	llog_reader.8				\
	llstat.8				\
	llverdev.8				\
	lnetctl.8				\
	lst.8					\
	lustre.7				\
	lustreapi.7				\
	lustre_routes_config.8			\
	lustre_routes_conversion.8		\
	lustre_rsync.8				\
	mount.lustre.8				\
	nids.5					\
	plot-llstat.8				\
	routerstat.8

SERVER_MANFILES =				\
	lctl-lfsck-query.8			\
	lctl-lfsck-start.8			\
	lctl-lfsck-stop.8			\
	lctl-llog_catlist.8			\
	lctl-llog_info.8			\
	lctl-llog_print.8			\
	lctl-nodemap-activate.8			\
	lctl-nodemap-add.8			\
	lctl-nodemap-add-idmap.8		\
	lctl-nodemap-add-range.8		\
	lctl-nodemap-del.8			\
	lctl-nodemap-del-idmap.8		\
	lctl-nodemap-del-range.8		\
	lctl-nodemap-modify.8			\
	lctl-lcfg.8				\
	lctl-barrier.8				\
	lctl-snapshot-create.8			\
	lctl-snapshot-destroy.8			\
	lctl-snapshot-modify.8			\
	lctl-snapshot-list.8			\
	lctl-snapshot-mount.8			\
	lctl-snapshot-umount.8			\
	lshowmount.8				\
	mkfs.lustre.8				\
	tunefs.lustre.8

if SERVER
MANFILES += $(SERVER_MANFILES)
else
DISTONLY_MANFILES = $(SERVER_MANFILES)
endif

if UTILS
if MANPAGES
man_MANS = $(MANFILES)
endif
endif

CLEANFILES = *.aux *.tex *.log *.pdf

EXTRA_DIST = $(MANFILES) $(DISTONLY_MANFILES)

all:
