# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

LIBMAN = 					\
	llapi_changelog_clear.3			\
	llapi_changelog_fini.3			\
	llapi_changelog_free.3			\
	llapi_changelog_get_fd.3		\
	llapi_changelog_in_buf.3		\
	llapi_changelog_recv.3			\
	llapi_changelog_set_xflags.3		\
	llapi_changelog_start.3			\
	llapi_create_volatile_param.3		\
	llapi_fd2parent.3			\
	llapi_fid_parse.3			\
	llapi_fid_to_handle.3			\
	llapi_file_create.3			\
	llapi_file_create_foreign.3		\
	llapi_file_get_stripe.3			\
	llapi_file_open.3			\
	llapi_get_fsname.3			\
	llapi_get_fsname_instance.3		\
	llapi_get_instance.3			\
	llapi_get_lum_dir.3			\
	llapi_get_lum_dir_fd.3			\
	llapi_get_lum_file.3			\
	llapi_get_lum_file_fd.3			\
	llapi_getname.3				\
	llapi_group_lock.3			\
	llapi_group_unlock.3			\
	llapi_heat_get.3			\
	llapi_heat_set.3			\
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
	llapi_ioctl.3				\
	llapi_ladvise.3				\
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
	llapi_layout_extension_size_get.3	\
	llapi_layout_extension_size_set.3	\
	llapi_layout_file_comp_add.3		\
	llapi_layout_file_comp_del.3		\
	llapi_layout_file_create.3		\
	llapi_layout_file_open.3		\
	llapi_layout_free.3			\
	llapi_layout_get_by_fd.3		\
	llapi_layout_get_by_fid.3		\
	llapi_layout_get_by_path.3		\
	llapi_layout_get_by_xattr.3		\
	llapi_layout_ost_index_get.3		\
	llapi_layout_ost_index_set.3		\
	llapi_layout_ost_index_reset.3		\
	llapi_layout_pattern_get.3		\
	llapi_layout_pattern_set.3		\
	llapi_layout_pool_name_get.3		\
	llapi_layout_pool_name_set.3		\
	llapi_layout_stripe_count_get.3		\
	llapi_layout_stripe_count_set.3		\
	llapi_layout_stripe_size_get.3		\
	llapi_layout_stripe_size_set.3		\
	llapi_open_by_fid.3			\
	llapi_open_by_fid_at.3			\
	llapi_param_get_paths.3			\
	llapi_param_get_value.3			\
	llapi_path2fid.3			\
	llapi_path2parent.3			\
	llapi_pcc_attach.3			\
	llapi_pcc_attach_fid.3			\
	llapi_pcc_attach_fid_str.3		\
	llapi_pcc_detach_fid.3			\
	llapi_pcc_detach_fid_fd.3		\
	llapi_pcc_detach_fid_str.3		\
	llapi_pcc_detach_file.3			\
	llapi_pccdev_get.3			\
	llapi_pccdev_set.3			\
	llapi_pcc_state_get.3			\
	llapi_pcc_state_get_fd.3		\
	llapi_pcc_clear.3			\
	llapi_pcc_del.3				\
	llapi_quotactl.3			\
	llapi_rmfid.3				\
	llapi_rmfid_at.3			\
	llapi_search_mdt.3			\
	llapi_search_ost.3			\
	llapi_search_tgt.3			\
	llapi_search_rootpath.3			\
	llapi_search_rootpath_by_dev.3		\
	llapi_unlink_foreign.3

if MANPAGES
man_MANS = $(LIBMAN)
endif

CLEANFILES = *.aux *.tex *.log *.pdf
EXTRA_DIST = $(LIBMAN)

all:
