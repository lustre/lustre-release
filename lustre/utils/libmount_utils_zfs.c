/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2017, Intel Corporation.
 * Use is subject to license terms.
 */
/*
 * Author: Brian Behlendorf <behlendorf1@llnl.gov>
 */
#ifndef HAVE_ZFS_MULTIHOST
#include <sys/list.h>
#define list_move_tail(a, b) spl_list_move_tail(a, b)
#include <sys/spa.h>
#endif
#include "mount_utils.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <libzfs.h>
#include <sys/systeminfo.h>

/* Persistent mount data is stored in these user attributes */
#define LDD_PREFIX		"lustre:"
#define LDD_VERSION_PROP	LDD_PREFIX "version"
#define LDD_FLAGS_PROP		LDD_PREFIX "flags"
#define LDD_INDEX_PROP		LDD_PREFIX "index"
#define LDD_FSNAME_PROP		LDD_PREFIX "fsname"
#define LDD_SVNAME_PROP		LDD_PREFIX "svname"
#define LDD_UUID_PROP		LDD_PREFIX "uuid"
#define LDD_USERDATA_PROP	LDD_PREFIX "userdata"
#define LDD_MOUNTOPTS_PROP	LDD_PREFIX "mountopts"

/* This structure is used to help bridge the gap between the ZFS
 * properties Lustre uses and their corresponding internal LDD fields.
 * It is meant to be used internally by the mount utility only. */
struct zfs_ldd_prop_bridge {
	/* Contains the publicly visible name for the property
	 * (i.e. what is shown when running "zfs get") */
	char *zlpb_prop_name;
	/* Contains the offset into the lustre_disk_data structure where
	 * the value of this property is or will be stored. (i.e. the
	 * property is read from and written to this offset within ldd) */
	int   zlpb_ldd_offset;
	/* Function pointer responsible for reading in the @prop
	 * property from @zhp and storing it in @ldd_field */
	int (*zlpb_get_prop_fn)(zfs_handle_t *zhp, char *prop, void *ldd_field);
	/* Function pointer responsible for writing the value of @ldd_field
	 * into the @prop dataset property in @zhp */
	int (*zlpb_set_prop_fn)(zfs_handle_t *zhp, char *prop, void *ldd_field);
};

/* Forward declarations needed to initialize the ldd prop bridge list */
static int zfs_get_prop_int(zfs_handle_t *, char *, void *);
static int zfs_set_prop_int(zfs_handle_t *, char *, void *);
static int zfs_get_prop_str(zfs_handle_t *, char *, void *);
static int zfs_set_prop_str(zfs_handle_t *, char *, void *);

/* Helper for initializing the entries in the special_ldd_prop_params list.
 *    - @name: stored directly in the zlpb_prop_name field
 *             (e.g. lustre:fsname, lustre:version, etc.)
 *    - @field: the field in the lustre_disk_data which directly maps to
 *              the @name property. (e.g. ldd_fsname, ldd_config_ver, etc.)
 *    - @type: The type of @field. Only "int" and "str" are supported.
 */
#define ZLB_INIT(name, field, type)					\
{									\
	.zlpb_prop_name   = name,					\
	.zlpb_ldd_offset  = offsetof(struct lustre_disk_data, field),	\
	.zlpb_get_prop_fn = zfs_get_prop_ ## type,			\
	.zlpb_set_prop_fn = zfs_set_prop_ ## type			\
}

/* These ldd properties are special because they all have their own
 * individual fields in the lustre_disk_data structure, as opposed to
 * being globbed into the ldd_params field. As such, these need special
 * handling when reading/writing the ldd structure to/from persistent
 * storage. */
struct zfs_ldd_prop_bridge special_ldd_prop_params[] = {
	ZLB_INIT(LDD_VERSION_PROP,   ldd_config_ver, int),
	ZLB_INIT(LDD_FLAGS_PROP,     ldd_flags,      int),
	ZLB_INIT(LDD_INDEX_PROP,     ldd_svindex,    int),
	ZLB_INIT(LDD_FSNAME_PROP,    ldd_fsname,     str),
	ZLB_INIT(LDD_SVNAME_PROP,    ldd_svname,     str),
	ZLB_INIT(LDD_UUID_PROP,      ldd_uuid,       str),
	ZLB_INIT(LDD_USERDATA_PROP,  ldd_userdata,   str),
	ZLB_INIT(LDD_MOUNTOPTS_PROP, ldd_mount_opts, str),
	{ NULL }
};

/* indicate if the ZFS OSD has been successfully setup */
static int osd_zfs_setup = 0;

static libzfs_handle_t *g_zfs;

void zfs_fini(void);

static int zfs_set_prop_int(zfs_handle_t *zhp, char *prop, void *val)
{
	char str[64];
	int ret;

	(void) snprintf(str, sizeof (str), "%i", *(int *)val);
	vprint("  %s=%s\n", prop, str);
	ret = zfs_prop_set(zhp, prop, str);

	return ret;
}

/*
 * Write the zfs property string, note that properties with a NULL or
 * zero-length value will not be written and 0 returned.
 */
static int zfs_set_prop_str(zfs_handle_t *zhp, char *prop, void *val)
{
	int ret = 0;

	if (val && strlen(val) > 0) {
		vprint("  %s=%s\n", prop, (char *)val);
		ret = zfs_prop_set(zhp, prop, (char *)val);
	}

	return ret;
}

/*
 * Remove a property from zfs property dataset
 */
static int zfs_remove_prop(zfs_handle_t *zhp, nvlist_t *nvl, char *propname)
{
	nvlist_remove_all(nvl, propname);
	/* XXX: please replace zfs_prop_inherit() if there is a better function
	 * to call zfs_ioctl() to update data on-disk.
	 */
	return zfs_prop_inherit(zhp, propname, false);
}

static int zfs_erase_prop(zfs_handle_t *zhp, char *param)
{
	nvlist_t *nvl;
	char propname[ZFS_MAXPROPLEN];
	int len = strlen(param) + strlen(LDD_PREFIX);

	if (len > ZFS_MAXPROPLEN) {
		fprintf(stderr, "%s: zfs prop to erase is too long-\n%s\n",
			progname, param);
		return EINVAL;
	}

	nvl = zfs_get_user_props(zhp);
	if (!nvl)
		return ENOENT;

	snprintf(propname, len + 1, "%s%s", LDD_PREFIX, param);
	return zfs_remove_prop(zhp, nvl, propname);
}

static int zfs_is_special_ldd_prop_param(char *name)
{
	int i;

	for (i = 0; special_ldd_prop_params[i].zlpb_prop_name != NULL; i++)
		if (!strcmp(name, special_ldd_prop_params[i].zlpb_prop_name))
			return 1;

	return 0;
}

static int zfs_erase_allprops(zfs_handle_t *zhp)
{
	nvlist_t *props;
	nvpair_t *nvp;
	size_t str_size = 1024 * 1024;
	char *strs, *cur;
	int rc = 0;

	strs = malloc(str_size);
	if (!strs)
		return ENOMEM;
	cur = strs;

	props = zfs_get_user_props(zhp);
	if (props == NULL) {
		free(strs);
		return ENOENT;
	}
	nvp = NULL;
	while (nvp = nvlist_next_nvpair(props, nvp), nvp) {
		if (strncmp(nvpair_name(nvp), LDD_PREFIX, strlen(LDD_PREFIX)))
			continue;

		if (zfs_is_special_ldd_prop_param(nvpair_name(nvp)))
			continue;

		rc = snprintf(cur, str_size - (cur - strs), "%s",
			      nvpair_name(nvp));
		if (rc != strlen(nvpair_name(nvp))) {
			fprintf(stderr, "%s: zfs has too many properties to erase, please repeat\n",
				progname);
			rc = EINVAL;
			break;
		}
		cur += strlen(cur) + 1;
	}
	cur = strs;
	while ( cur < (strs + str_size) && strlen(cur) > 0) {
		zfs_prop_inherit(zhp, cur, false);
		cur += strlen(cur) + 1;
	}

	free(strs);
	return rc;
}
/*
 * ZFS on linux 0.7.0-rc5 commit 379ca9cf2beba802f096273e89e30914a2d6bafc
 * Multi-modifier protection (MMP)
 *
 * Introduced spa_get_hostid() along with a few constants like
 * ZPOOL_CONFIG_MMP_HOSTID that can be checked to imply availablity of
 * spa_get_hostid. Supply a fallback when spa_get_hostid is not
 * available.
 *
 * This can be removed when zfs 0.6.x support is dropped.
 */
#if !defined(ZPOOL_CONFIG_MMP_HOSTID) && !defined(HAVE_ZFS_MULTIHOST)
unsigned long _hostid_from_proc(void)
{
	FILE *f;
	unsigned long hostid;
	int rc;

	f = fopen("/proc/sys/kernel/spl/hostid", "r");
	if (f == NULL)
		goto out;

	rc = fscanf(f, "%lx", &hostid);
	fclose(f);
	if (rc == 1)
		return hostid;
out:
	return 0;
}

unsigned long _hostid_from_module_param(void)
{
	FILE *f;
	unsigned long hostid;
	int rc;

	f = fopen("/sys/module/spl/parameters/spl_hostid", "r");
	if (f == NULL)
		goto out;

	rc = fscanf(f, "%li", &hostid);
	fclose(f);
	if (rc == 1)
		return hostid;
out:
	return 0;
}

unsigned long _from_module_param_indirect(void)
{
	FILE *f;
	unsigned long hostid = 0;
	uint32_t hwid;
	int rc;
	char *spl_hostid_path = NULL;

	/* read the module parameter for HW_HOSTID_PATH */
	f = fopen("/sys/module/spl/parameters/spl_hostid_path", "r");
	if (f == NULL) {
		fatal();
		fprintf(stderr, "Failed to open spl_hostid_path param: %s\n",
			strerror(errno));
		goto out;
	}

	rc = fscanf(f, "%ms%*[\n]", &spl_hostid_path);
	fclose(f);
	if (rc == 0 || !spl_hostid_path)
		goto out;

	/* read the hostid from the file */
	f = fopen(spl_hostid_path, "r");
	if (f == NULL) {
		fatal();
		fprintf(stderr, "Failed to open %s param: %s\n",
			spl_hostid_path, strerror(errno));
		goto out;
	}

	/* hostid is the first 4 bytes in native endian order */
	rc = fread(&hwid, sizeof(uint32_t), 1, f);
	fclose(f);
	if (rc == 1)
		hostid = (unsigned long)hwid;

out:
	if (spl_hostid_path)
		free(spl_hostid_path);

	return hostid;
}

unsigned long spa_get_hostid(void)
{
	unsigned long hostid;

	hostid = _hostid_from_proc();
	if (hostid)
		return hostid;

	/* if /proc isn't available, try /sys */
	hostid = _hostid_from_module_param();
	if (hostid)
		return hostid;

	return _from_module_param_indirect();
}
#endif

/*
 * Map '<key>=<value> ...' pairs in the passed string to dataset properties
 * of the form 'lustre:<key>=<value>'. "<key>=" means to remove this key
 * from the dataset.
 */
static int zfs_set_prop_params(zfs_handle_t *zhp, char *params)
{
	char *params_dup, *token, *key, *value;
	char *save_token = NULL;
	char propname[ZFS_MAXPROPLEN];
	int ret = 0;

	params_dup = strdup(params);
	if (params_dup == NULL)
		return ENOMEM;

	token = strtok_r(params_dup, " ", &save_token);
	while (token) {
		key = strtok(token, "=");
		if (key == NULL)
			continue;

		value = strtok(NULL, "=");
		if (!value) {
			/* remove this prop when its value is null */
			ret = zfs_erase_prop(zhp, key);
			if (ret)
				break;
		} else {
			snprintf(propname, strlen(LDD_PREFIX) + strlen(key) + 1,
				 "%s%s", LDD_PREFIX, key);
			vprint("  %s=%s\n", propname, value);

			ret = zfs_prop_set(zhp, propname, value);
			if (ret)
				break;
		}

		token = strtok_r(NULL, " ", &save_token);
	}

	free(params_dup);

	return ret;
}

static int zfs_check_hostid(struct mkfs_opts *mop)
{
	unsigned long hostid;

	if (strstr(mop->mo_ldd.ldd_params, PARAM_FAILNODE) == NULL)
		return 0;

#ifdef HAVE_ZFS_MULTIHOST
	hostid = get_system_hostid();
#else
	hostid = spa_get_hostid();
#endif
	if (hostid == 0) {
		if (mop->mo_flags & MO_NOHOSTID_CHECK) {
			fprintf(stderr, "WARNING: spl_hostid not set. ZFS has "
				"no zpool import protection\n");
		} else {
			fatal();
			fprintf(stderr, "spl_hostid not set. See %s(8)",
				progname);
			return EINVAL;
		}
	}

	return 0;
}

static int osd_check_zfs_setup(void)
{
	if (osd_zfs_setup == 0) {
		/* setup failed */
		fatal();
		fprintf(stderr, "Failed to initialize ZFS library. Are the ZFS "
			"packages and modules correctly installed?\n");
	}
	return osd_zfs_setup == 1;
}

/* Write the server config as properties associated with the dataset */
int zfs_write_ldd(struct mkfs_opts *mop)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	char *ds = mop->mo_device;
	zfs_handle_t *zhp;
	struct zfs_ldd_prop_bridge *bridge;
	int i, ret = EINVAL;

	if (osd_check_zfs_setup() == 0)
		goto out;

	zhp = zfs_open(g_zfs, ds, ZFS_TYPE_FILESYSTEM);
	if (zhp == NULL) {
		fprintf(stderr, "Failed to open zfs dataset %s\n", ds);
		goto out;
	}

	ret = zfs_check_hostid(mop);
	if (ret != 0)
		goto out_close;

	vprint("Writing %s properties\n", ds);

	if (mop->mo_flags & MO_ERASE_ALL)
		ret = zfs_erase_allprops(zhp);
	ret = zfs_set_prop_params(zhp, ldd->ldd_params);

	for (i = 0; special_ldd_prop_params[i].zlpb_prop_name != NULL; i++) {
		bridge = &special_ldd_prop_params[i];
		ret = bridge->zlpb_set_prop_fn(zhp, bridge->zlpb_prop_name,
					(void *)ldd + bridge->zlpb_ldd_offset);
		if (ret)
			goto out_close;
	}

out_close:
	zfs_close(zhp);
out:
	return ret;
}

/* Mark a property to be removed by the form of "key=" */
int zfs_erase_ldd(struct mkfs_opts *mop, char *param)
{
	char key[ZFS_MAXPROPLEN] = "";

	if (strlen(LDD_PREFIX) + strlen(param) > ZFS_MAXPROPLEN) {
		fprintf(stderr, "%s: zfs prop to erase is too long-\n%s\n",
			progname, param);
		return EINVAL;
	}
	snprintf(key, strlen(param) + 2, "%s=", param);
	return add_param(mop->mo_ldd.ldd_params, key, "");
}

static int zfs_get_prop_int(zfs_handle_t *zhp, char *prop, void *val)
{
	nvlist_t *propval;
	char *propstr;
	int ret;

	ret = nvlist_lookup_nvlist(zfs_get_user_props(zhp), prop, &propval);
	if (ret)
		return ret;

	ret = nvlist_lookup_string(propval, ZPROP_VALUE, &propstr);
	if (ret)
		return ret;

	errno = 0;
	*(__u32 *)val = strtoul(propstr, NULL, 10);
	if (errno)
		return errno;

	return ret;
}

static int zfs_get_prop_str(zfs_handle_t *zhp, char *prop, void *val)
{
	nvlist_t *propval;
	char *propstr;
	int ret;

	ret = nvlist_lookup_nvlist(zfs_get_user_props(zhp), prop, &propval);
	if (ret)
		return ret;

	ret = nvlist_lookup_string(propval, ZPROP_VALUE, &propstr);
	if (ret)
		return ret;

	(void) strcpy(val, propstr);

	return ret;
}

static int zfs_get_prop_params(zfs_handle_t *zhp, char *param)
{
	nvlist_t *props;
	nvpair_t *nvp;
	char key[ZFS_MAXPROPLEN] = "";
	char value[PARAM_MAX] = "";
	int ret = 0;

	props = zfs_get_user_props(zhp);
	if (props == NULL)
		return ENOENT;

	nvp = NULL;
	while (nvp = nvlist_next_nvpair(props, nvp), nvp) {
		ret = zfs_get_prop_str(zhp, nvpair_name(nvp), value);
		if (ret)
			break;

		if (strncmp(nvpair_name(nvp), LDD_PREFIX, strlen(LDD_PREFIX)))
			continue;

		if (zfs_is_special_ldd_prop_param(nvpair_name(nvp)))
			continue;

		sprintf(key, "%s=",  nvpair_name(nvp) + strlen(LDD_PREFIX));
		ret = add_param(param, key, value);
		if (ret)
			break;
	}

	return ret;
}

/*
 * Read the server config as properties associated with the dataset.
 * Missing entries as not treated error and are simply skipped.
 */
int zfs_read_ldd(char *ds,  struct lustre_disk_data *ldd)
{
	zfs_handle_t *zhp;
	struct zfs_ldd_prop_bridge *bridge;
	int i, ret = EINVAL;

	if (osd_check_zfs_setup() == 0)
		return EINVAL;

	zhp = zfs_open(g_zfs, ds, ZFS_TYPE_FILESYSTEM);
	if (!zhp) {
		zhp = zfs_open(g_zfs, ds, ZFS_TYPE_SNAPSHOT);
		if (!zhp)
			goto out;
	}

	for (i = 0; special_ldd_prop_params[i].zlpb_prop_name != NULL; i++) {
		bridge = &special_ldd_prop_params[i];
		ret = bridge->zlpb_get_prop_fn(zhp, bridge->zlpb_prop_name,
					(void *)ldd + bridge->zlpb_ldd_offset);
		if (ret && (ret != ENOENT))
			goto out_close;
	}

	ret = zfs_get_prop_params(zhp, ldd->ldd_params);
	if (ret && (ret != ENOENT))
		goto out_close;

	ldd->ldd_mount_type = LDD_MT_ZFS;
	ret = 0;

#ifdef HAVE_ZFS_MULTIHOST
	if (strstr(ldd->ldd_params, PARAM_FAILNODE) != NULL) {
		zpool_handle_t *pool = zfs_get_pool_handle(zhp);
		uint64_t mh = zpool_get_prop_int(pool, ZPOOL_PROP_MULTIHOST,
						 NULL);
		if (!mh)
			fprintf(stderr, "%s: %s is configured for failover "
				"but zpool does not have multihost enabled\n",
				progname, ds);
	}
#endif

out_close:
	zfs_close(zhp);

out:
	return ret;
}

/* Print ldd params */
void zfs_print_ldd_params(struct mkfs_opts *mop)
{
	char *from = mop->mo_ldd.ldd_params;
	char *to;
	int len;

	vprint("Parameters:");
	while (from) {
		/* skip those keys to be removed in the form of "key=" */
		to = strstr(from, "= ");
		if (!to)
			/* "key=" may be in the end */
			if (*(from + strlen(from) - 1) == '=')
				to = from + strlen(from) - 1;

		/* find " " inward */
		len = strlen(from);
		if (to) {
			len = strlen(from) - strlen(to);
			while ((*(from + len) != ' ') && len)
				len--;
		}
		if (len)
			/* no space in the end */
			vprint("%*.*s", len, len, from);

		/* If there is no "key=" or "key=" is in the end, stop. */
		if (!to || strlen(to) == 1)
			break;

		/* skip "=" */
		from = to + 1;
	}
}

int zfs_is_lustre(char *ds, unsigned *mount_type)
{
	struct lustre_disk_data tmp_ldd;
	int ret;

	if (osd_zfs_setup == 0)
		return 0;

	ret = zfs_read_ldd(ds, &tmp_ldd);
	if ((ret == 0) && (tmp_ldd.ldd_config_ver > 0) &&
	    (strlen(tmp_ldd.ldd_svname) > 0)) {
		*mount_type = tmp_ldd.ldd_mount_type;
		return 1;
	}

	return 0;
}

static char *zfs_mkfs_opts(struct mkfs_opts *mop, char *str, int len)
{
	memset(str, 0, len);

	if (strlen(mop->mo_mkfsopts) != 0)
		snprintf(str, len, " -o %s", mop->mo_mkfsopts);
	if (mop->mo_device_kb)
		snprintf(str, len, " -o quota=%llu",
			 (unsigned long long)mop->mo_device_kb * 1024);

	return str;
}

static int zfs_create_vdev(struct mkfs_opts *mop, char *vdev)
{
	int ret = 0;

	/* Silently ignore reserved vdev names */
	if ((strncmp(vdev, "disk", 4) == 0) ||
	    (strncmp(vdev, "file", 4) == 0) ||
	    (strncmp(vdev, "mirror", 6) == 0) ||
	    (strncmp(vdev, "raidz", 5) == 0) ||
	    (strncmp(vdev, "spare", 5) == 0) ||
	    (strncmp(vdev, "log", 3) == 0) ||
	    (strncmp(vdev, "cache", 5) == 0))
		return ret;

	/*
	 * Verify a file exists at the provided absolute path.  If it doesn't
	 * and mo_device_kb is set attempt to create a file vdev to be used.
	 * Relative paths will be passed directly to 'zpool create' which
	 * will check multiple multiple locations under /dev/.
	 */
	if (vdev[0] == '/') {
		ret = access(vdev, F_OK);
		if (ret == 0)
			return ret;

		ret = errno;
		if (ret != ENOENT) {
			fatal();
			fprintf(stderr, "Unable to access required vdev "
				"for pool %s (%d)\n", vdev, ret);
			return ret;
		}

		if (mop->mo_device_kb == 0) {
			fatal();
			fprintf(stderr, "Unable to create vdev due to "
				"missing --device-size=#N(KB) parameter\n");
			return EINVAL;
		}

		ret = file_create(vdev, mop->mo_device_kb);
		if (ret) {
			fatal();
			fprintf(stderr, "Unable to create vdev %s (%d)\n",
				vdev, ret);
			return ret;
		}
	}

	return ret;
}

int zfs_make_lustre(struct mkfs_opts *mop)
{
	zfs_handle_t *zhp;
	zpool_handle_t *php;
	char *pool = NULL;
	char *mkfs_cmd = NULL;
	char *mkfs_tmp = NULL;
	char *ds = mop->mo_device;
	int pool_exists = 0, ret;

	if (osd_check_zfs_setup() == 0)
		return EINVAL;

	/* no automatic index with zfs backend */
	if (mop->mo_ldd.ldd_flags & LDD_F_NEED_INDEX) {
		fatal();
		fprintf(stderr, "The target index must be specified with "
				"--index\n");
		return EINVAL;
	}

	ret = zfs_check_hostid(mop);
	if (ret != 0)
		goto out;

	pool = strdup(ds);
	if (pool == NULL)
		return ENOMEM;

	mkfs_cmd = malloc(PATH_MAX);
	if (mkfs_cmd == NULL) {
		ret = ENOMEM;
		goto out;
	}

	mkfs_tmp = malloc(PATH_MAX);
	if (mkfs_tmp == NULL) {
		ret = ENOMEM;
		goto out;
	}

	/* Due to zfs_prepare_lustre() check the '/' must exist */
	strchr(pool, '/')[0] = '\0';

	/* If --reformat was given attempt to destroy the previous dataset */
	if ((mop->mo_flags & MO_FORCEFORMAT) &&
	    ((zhp = zfs_open(g_zfs, ds, ZFS_TYPE_FILESYSTEM)) != NULL)) {

		ret = zfs_destroy(zhp, 0);
		if (ret) {
			zfs_close(zhp);
			fprintf(stderr, "Failed destroy zfs dataset %s (%d)\n",
				ds, ret);
			goto out;
		}

		zfs_close(zhp);
	}

	/*
	 * Create the zpool if the vdevs have been specified and the pool
	 * does not already exists.  The pool creation itself will be done
	 * with the zpool command rather than the zpool_create() library call
	 * so the existing zpool error handling can be leveraged.
	 */
	php = zpool_open(g_zfs, pool);
	if (php) {
		pool_exists = 1;
		zpool_set_prop(php, "canmount", "off");
		zpool_close(php);
	}

	if ((mop->mo_pool_vdevs != NULL) && (pool_exists == 0)) {

		memset(mkfs_cmd, 0, PATH_MAX);
		snprintf(mkfs_cmd, PATH_MAX,
			"zpool create -f -O canmount=off %s", pool);

		/* Append the vdev config and create file vdevs as required */
		while (*mop->mo_pool_vdevs != NULL) {
			strscat(mkfs_cmd, " ", PATH_MAX);
			strscat(mkfs_cmd, *mop->mo_pool_vdevs, PATH_MAX);

			ret = zfs_create_vdev(mop, *mop->mo_pool_vdevs);
			if (ret)
				goto out;

			mop->mo_pool_vdevs++;
		}

		vprint("mkfs_cmd = %s\n", mkfs_cmd);
		ret = run_command(mkfs_cmd, PATH_MAX);
		if (ret) {
			fatal();
			fprintf(stderr, "Unable to create pool %s (%d)\n",
				pool, ret);
			goto out;
		}
	}

	/*
	 * Set Options on ZPOOL
	 *
	 * ALL   - canmount=off (set above)
	 * 0.7.0 - multihost=on
	 * 0.7.0 - feature@userobj_accounting=enabled
	 */
#if defined(HAVE_ZFS_MULTIHOST) || defined(HAVE_DMU_USEROBJ_ACCOUNTING)
	php = zpool_open(g_zfs, pool);
	if (php) {
#ifdef HAVE_ZFS_MULTIHOST
		zpool_set_prop(php, "multihost", "on");
#endif
#ifdef HAVE_DMU_USEROBJ_ACCOUNTING
		zpool_set_prop(php, "feature@userobj_accounting", "enabled");
#endif
		zpool_close(php);
	}
#endif

	/*
	 * Create the ZFS filesystem with any required mkfs options:
	 * - canmount=off is set to prevent zfs automounting
	 */
	memset(mkfs_cmd, 0, PATH_MAX);
	snprintf(mkfs_cmd, PATH_MAX,
		 "zfs create -o canmount=off %s %s",
		 zfs_mkfs_opts(mop, mkfs_tmp, PATH_MAX), ds);

	vprint("mkfs_cmd = %s\n", mkfs_cmd);
	ret = run_command(mkfs_cmd, PATH_MAX);
	if (ret) {
		fatal();
		fprintf(stderr, "Unable to create filesystem %s (%d)\n",
			ds, ret);
		goto out;
	}

	/*
	 * Attempt to set dataset properties to reasonable defaults
	 * to optimize performance, unless the values were specified
	 * at the mkfs command line. Some ZFS pools or ZFS versions
	 * do not support these properties. We can safely ignore the
	 * errors and continue in those cases.
	 *
	 * zfs 0.6.1 - system attribute based xattrs
	 * zfs 0.6.5 - large block support
	 * zfs 0.7.0 - large dnode support
	 *
	 * Check if zhp is NULL as a defensive measure. Any dataset
	 * validation errors that would cause zfs_open() to fail
	 * should have been caught earlier.
	 */
	zhp = zfs_open(g_zfs, ds, ZFS_TYPE_FILESYSTEM);
	if (zhp) {
		/* zfs 0.6.1 - system attribute based xattrs */
		if (!strstr(mop->mo_mkfsopts, "xattr="))
			zfs_set_prop_str(zhp, "xattr", "sa");

		/* zfs 0.7.0 - large dnode support */
		if (!strstr(mop->mo_mkfsopts, "dnodesize=") &&
		    !strstr(mop->mo_mkfsopts, "dnsize="))
			zfs_set_prop_str(zhp, "dnodesize", "auto");

		if (IS_OST(&mop->mo_ldd)) {
			/* zfs 0.6.5 - large block support */
			if (!strstr(mop->mo_mkfsopts, "recordsize=") &&
			    !strstr(mop->mo_mkfsopts, "recsize="))
				zfs_set_prop_str(zhp, "recordsize", "1M");
		}

		zfs_close(zhp);
	}

out:
	if (pool != NULL)
		free(pool);

	if (mkfs_cmd != NULL)
		free(mkfs_cmd);

	if (mkfs_tmp != NULL)
		free(mkfs_tmp);

	return ret;
}

int zfs_enable_quota(struct mkfs_opts *mop)
{
	fprintf(stderr, "this option is not only valid for zfs\n");
	return ENOSYS;
}

int zfs_prepare_lustre(struct mkfs_opts *mop,
		       char *wanted_mountopts, size_t len)
{
	if (osd_check_zfs_setup() == 0)
		return EINVAL;

	if (zfs_name_valid(mop->mo_device, ZFS_TYPE_FILESYSTEM) == 0) {
		fatal();
		fprintf(stderr, "Invalid filesystem name %s\n", mop->mo_device);
		return EINVAL;
	}

	if (strchr(mop->mo_device, '/') == NULL) {
		fatal();
		fprintf(stderr, "Missing pool in filesystem name %s\n",
			mop->mo_device);
		return EINVAL;
	}

	return 0;
}

int zfs_tune_lustre(char *dev, struct mount_opts *mop)
{
	if (osd_check_zfs_setup() == 0)
		return EINVAL;

	return 0;
}

int zfs_label_lustre(struct mount_opts *mop)
{
	zfs_handle_t *zhp;
	int ret;

	if (osd_check_zfs_setup() == 0)
		return EINVAL;

	zhp = zfs_open(g_zfs, mop->mo_source, ZFS_TYPE_FILESYSTEM);
	if (zhp == NULL)
		return EINVAL;

	ret = zfs_set_prop_str(zhp, LDD_SVNAME_PROP, mop->mo_ldd.ldd_svname);
	zfs_close(zhp);

	return ret;
}

int zfs_rename_fsname(struct mkfs_opts *mop, const char *oldname)
{
	struct mount_opts opts;
	char mntpt[] = "/tmp/mntXXXXXX";
	char *cmd_buf;
	int ret;

	/* Change the filesystem label. */
	opts.mo_ldd = mop->mo_ldd;
	opts.mo_source = mop->mo_device;
	ret = zfs_label_lustre(&opts);
	if (ret) {
		if (errno != 0)
			ret = errno;
		fprintf(stderr, "Can't change filesystem label: %s\n",
			strerror(ret));
		return ret;
	}

	/* Mount this device temporarily in order to write these files */
	if (mkdtemp(mntpt) == NULL) {
		if (errno != 0)
			ret = errno;
		fprintf(stderr, "Can't create temp mount point %s: %s\n",
			mntpt, strerror(ret));
		return ret;
	}

	cmd_buf = malloc(PATH_MAX);
	if (!cmd_buf) {
		ret = ENOMEM;
		goto out_rmdir;
	}

	memset(cmd_buf, 0, PATH_MAX);
	snprintf(cmd_buf, PATH_MAX - 1, "zfs set mountpoint=%s %s && "
		 "zfs set canmount=on %s && zfs mount %s",
		 mntpt, mop->mo_device, mop->mo_device, mop->mo_device);
	ret = run_command(cmd_buf, PATH_MAX);
	if (ret) {
		if (errno != 0)
			ret = errno;
		fprintf(stderr, "Unable to mount %s (%s)\n",
			mop->mo_device, strerror(ret));
		if (ret == ENODEV)
			fprintf(stderr, "Is the %s module available?\n",
				MT_STR(&mop->mo_ldd));
		goto out_free;
	}

	ret = lustre_rename_fsname(mop, mntpt, oldname);
	memset(cmd_buf, 0, PATH_MAX);
	snprintf(cmd_buf, PATH_MAX - 1, "zfs umount %s && "
		 "zfs set canmount=off %s && zfs set mountpoint=none %s",
		 mop->mo_device, mop->mo_device, mop->mo_device);
	run_command(cmd_buf, PATH_MAX);

out_free:
	free(cmd_buf);
out_rmdir:
	rmdir(mntpt);
	return ret;
}

int zfs_init(void)
{
	int ret = 0;

	g_zfs = libzfs_init();

	if (g_zfs == NULL) {
		/* Try to load zfs.ko and retry libzfs_init() */

		ret = system("/sbin/modprobe -q zfs");

		if (ret == 0) {
			g_zfs = libzfs_init();
			if (g_zfs == NULL)
				ret = EINVAL;
		}
	}

	if (ret == 0)
		osd_zfs_setup = 1;
	else
		fprintf(stderr, "Failed to initialize ZFS library: %d\n", ret);

	return ret;
}

void zfs_fini(void)
{
	if (g_zfs) {
		libzfs_fini(g_zfs);
		g_zfs = NULL;
	}
	osd_zfs_setup = 0;
}

#ifndef PLUGIN_DIR
struct module_backfs_ops zfs_ops = {
	.init			= zfs_init,
	.fini			= zfs_fini,
	.read_ldd		= zfs_read_ldd,
	.write_ldd		= zfs_write_ldd,
	.erase_ldd		= zfs_erase_ldd,
	.print_ldd_params	= zfs_print_ldd_params,
	.is_lustre		= zfs_is_lustre,
	.make_lustre		= zfs_make_lustre,
	.prepare_lustre		= zfs_prepare_lustre,
	.tune_lustre		= zfs_tune_lustre,
	.label_lustre		= zfs_label_lustre,
	.enable_quota		= zfs_enable_quota,
	.rename_fsname		= zfs_rename_fsname,
};
#endif /* PLUGIN_DIR */
