# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

MANFILES = 					\
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
	lfs-rm_entry.8				\
	lfs-rmentry.8				\
	lgss_sk.8				\
	lhbadm.8				\
	ll_decode_linkea.8			\
	llsom_sync.8				\
	llstat.8				\
	lnetctl.8				\
	lst.8					\
	lustre_routes_config.8			\
	lustre_routes_conversion.8		\
	lustre_rsync.8				\
	mount.lustre.8				\
	plot-llstat.8				\
	routerstat.8

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
	lctl-nodemap-info.8			\
	lctl-nodemap_info.8			\
	lctl-nodemap-modify.8			\
	lctl-nodemap_modify.8			\
	lctl-nodemap-set-cap.8			\
	lctl-nodemap_set_cap.8			\
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
	lctl-nodemap-banlist-add.8		\
	lctl-nodemap_banlist_add.8		\
	lctl-nodemap-banlist-del.8		\
	lctl-nodemap_banlist_del.8		\
	lctl-nodemap-fileset-add.8		\
	lctl-nodemap_fileset_add.8		\
	lctl-nodemap-fileset-del.8		\
	lctl-nodemap_fileset_del.8		\
	lctl-nodemap-fileset-modify.8		\
	lctl-nodemap_fileset_modify.8		\
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
man_MANS =
if SERVER
man_MANS += $(SERVER_MANFILES)
endif

if UTILS
man_MANS += $(MANFILES)
endif
endif

CLEANFILES = *.aux *.tex *.log *.pdf
EXTRA_DIST = $(MANFILES) $(SERVER_MANFILES)

all:
