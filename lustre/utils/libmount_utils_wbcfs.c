// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2024, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Author: Timothy Day <timday@amazon.com>
 */

#include "mount_utils.h"

#define VAR_SIZE 64

enum osd_tgt_type {
	MGT,
	MDT,
	OST,
	INVALID
};

int wbcfs_write_ldd(struct mkfs_opts *mop)
{
	return 0;
}

int wbcfs_erase_ldd(struct mkfs_opts *mop, char *param)
{
	return 0;
}

static int get_wbcfs_env(char *out, char *env)
{
	if (!getenv(env)) {
		fprintf(stderr, "%s is undefined\n", env);
		return -EINVAL;
	}

	strscpy(out, getenv(env), VAR_SIZE);
	fprintf(stderr, "%s=%s\n", env, out);

	return 0;
}

int wbcfs_read_ldd(char *ds, struct lustre_disk_data *ldd)
{
	enum osd_tgt_type tgt_type = INVALID;
	char tgt_type_var[VAR_SIZE];
	char name_var[VAR_SIZE];
	char params[2 * VAR_SIZE];
	char svname[2 * VAR_SIZE];
	int rc = 0;

	memset(ldd, 0, sizeof(struct lustre_disk_data));
	ldd->ldd_magic = LDD_MAGIC;
	ldd->ldd_config_ver = 1;
	ldd->ldd_mount_type = LDD_MT_WBCFS;

	rc = get_wbcfs_env(tgt_type_var, "OSD_WBC_TGT_TYPE");
	if (rc)
		return rc;

	if (!strcmp(tgt_type_var, "OST")) {
		ldd->ldd_flags = LDD_F_UPDATE | LDD_F_VIRGIN |
			LDD_F_SV_TYPE_OST;
		tgt_type = OST;
	}

	if (!strcmp(tgt_type_var, "MGT")) {
		ldd->ldd_flags = LDD_F_UPDATE | LDD_F_VIRGIN |
			LDD_F_SV_TYPE_MGS;
		tgt_type = MGT;
	}

	if (!strcmp(tgt_type_var, "MDT")) {
		rc = get_wbcfs_env(tgt_type_var, "OSD_WBC_PRIMARY_MDT");
		if (rc)
			return rc;

		if (!strcmp(tgt_type_var, "1")) {
			ldd->ldd_flags = LDD_F_UPDATE | LDD_F_VIRGIN |
				LDD_F_SV_TYPE_MDT | LDD_F_SV_TYPE_MGS;
		} else {
			ldd->ldd_flags = LDD_F_UPDATE | LDD_F_VIRGIN |
				LDD_F_SV_TYPE_MDT;
		}

		tgt_type = MDT;
	}

	if (tgt_type == INVALID) {
		fprintf(stderr, "OSD_WBC_TGT_TYPE is invalid\n");
		return -EINVAL;
	}

	rc = get_wbcfs_env(name_var, "OSD_WBC_FSNAME");
	if (rc)
		return rc;

	strscpy(ldd->ldd_fsname, name_var, VAR_SIZE);

	if (!getenv("OSD_WBC_INDEX")) {
		fprintf(stderr, "OSD_WBC_INDEX is undefined\n");
		return -EINVAL;
	}

	rc = get_wbcfs_env(tgt_type_var, "OSD_WBC_INDEX");
	if (rc)
		return rc;

	ldd->ldd_svindex = strtol(tgt_type_var,
				  NULL, 0);

	if (tgt_type == MGT)
		snprintf(svname, 2 * VAR_SIZE, "%s:%s%04x",
			 ldd->ldd_fsname, "MGS",
			 ldd->ldd_svindex);

	if (tgt_type == MDT)
		snprintf(svname, 2 * VAR_SIZE, "%s:%s%04x",
			 ldd->ldd_fsname, "MDT",
			 ldd->ldd_svindex);

	if (tgt_type == OST)
		snprintf(svname, 2 * VAR_SIZE, "%s:%s%04x",
			 ldd->ldd_fsname, "OST",
			 ldd->ldd_svindex);

	strscpy(ldd->ldd_svname, svname, VAR_SIZE);

	fprintf(stderr, "svname -> %s\n", svname);

	rc = get_wbcfs_env(tgt_type_var, "OSD_WBC_MGS_NID");
	if (rc)
		return rc;

	if (tgt_type != MGT) {
		snprintf(params, 2 * VAR_SIZE, "mgsnode=%s",
			 tgt_type_var);
		strscpy(ldd->ldd_params, params, VAR_SIZE);
		fprintf(stderr, "params -> %s\n", params);
	}

	return 0;
}

void wbcfs_print_ldd_params(struct mkfs_opts *mop)
{
}

int wbcfs_is_lustre(char *ds, unsigned int *mount_type)
{
	if (!strcmp(ds, OSD_WBCFS_DEV)) {
		fprintf(stderr, "Lustre is using wbcfs as backend\n");
		*mount_type = LDD_MT_WBCFS;
		return 1;
	}

	return 0;
}

int wbcfs_make_lustre(struct mkfs_opts *mop)
{
	return 0;
}

int wbcfs_enable_quota(struct mkfs_opts *mop)
{
	return -EOPNOTSUPP;
}

int wbcfs_prepare_lustre(struct mkfs_opts *mop,
			 char *wanted_mountopts, size_t len)
{
	return 0;
}

int wbcfs_tune_lustre(char *dev, struct mount_opts *mop)
{
	return 0;
}

int wbcfs_label_lustre(struct mount_opts *mop)
{
	return 0;
}

int wbcfs_rename_fsname(struct mkfs_opts *mop, const char *oldname)
{
	return 0;
}

int wbcfs_init(void)
{
	return 0;
}

void wbcfs_fini(void)
{
}

#ifndef PLUGIN_DIR
struct module_backfs_ops wbcfs_ops = {
	.init			= wbcfs_init,
	.fini			= wbcfs_fini,
	.read_ldd		= wbcfs_read_ldd,
	.write_ldd		= wbcfs_write_ldd,
	.erase_ldd		= wbcfs_erase_ldd,
	.print_ldd_params	= wbcfs_print_ldd_params,
	.is_lustre		= wbcfs_is_lustre,
	.make_lustre		= wbcfs_make_lustre,
	.prepare_lustre		= wbcfs_prepare_lustre,
	.tune_lustre		= wbcfs_tune_lustre,
	.label_lustre		= wbcfs_label_lustre,
	.enable_quota		= wbcfs_enable_quota,
	.rename_fsname		= wbcfs_rename_fsname,
};
#endif /* PLUGIN_DIR */
