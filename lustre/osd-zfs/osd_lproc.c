/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osd-zfs/osd_lproc.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_scrub.h>

#include "osd_internal.h"

static int osd_stats_init(struct osd_device *osd)
{
	int result = -ENOMEM;

	ENTRY;
	osd->od_stats = lprocfs_alloc_stats(LPROC_OSD_LAST, 0);
	if (osd->od_stats) {
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_GET_PAGE,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_CNTR_STDDEV |
				LPROCFS_TYPE_USECS, "get_page");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_NO_PAGE,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_REQS,
				"get_page_failures");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_CACHE_ACCESS,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_PAGES,
				"cache_access");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_CACHE_HIT,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_PAGES,
				"cache_hit");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_CACHE_MISS,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_PAGES,
				"cache_miss");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_COPY_IO,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_PAGES,
				"copy");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_ZEROCOPY_IO,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_PAGES,
				"zerocopy");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_TAIL_IO,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_PAGES,
				"tail");
#ifdef OSD_THANDLE_STATS
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_THANDLE_STARTING,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_USECS,
				"thandle_starting");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_THANDLE_OPEN,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_USECS,
				"thandle_open");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_THANDLE_CLOSING,
				LPROCFS_CNTR_AVGMINMAX | LPROCFS_TYPE_USECS,
				"thandle_closing");
#endif
		result = 0;
	}

	ldebugfs_register_osd_stats(osd->od_dt_dev.dd_debugfs_entry,
				    &osd->od_brw_stats, osd->od_stats);
	/* These fields are not supported for ZFS */
	osd->od_brw_stats.bs_props[BRW_R_DISCONT_BLOCKS / 2].bsp_name = NULL;
	osd->od_brw_stats.bs_props[BRW_R_DIO_FRAGS / 2].bsp_name = NULL;

	RETURN(result);
}

static int zfs_osd_oi_scrub_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *dev = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(dev != NULL);
	if (!dev->od_os)
		return -EINPROGRESS;

	scrub_dump(m, &dev->od_scrub);
	return 0;
}
LDEBUGFS_SEQ_FOPS_RO(zfs_osd_oi_scrub);

static ssize_t auto_scrub_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);

	LASSERT(dev);
	if (!dev->od_os)
		return -EINPROGRESS;

	return scnprintf(buf, PAGE_SIZE, "%lld\n",
			 dev->od_scrub.os_auto_scrub_interval);
}

static ssize_t auto_scrub_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);
	s64 val;
	int rc;

	LASSERT(dev);
	if (!dev->od_os)
		return -EINPROGRESS;

	rc = kstrtoull(buffer, 0, &val);
	if (rc)
		return rc;

	dev->od_scrub.os_auto_scrub_interval = val;
	return count;
}
LUSTRE_RW_ATTR(auto_scrub);

static ssize_t fstype_show(struct kobject *kobj, struct attribute *attr,
			  char *buf)
{
	return sprintf(buf, "zfs\n");
}
LUSTRE_RO_ATTR(fstype);

static ssize_t mntdev_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);

	LASSERT(osd);

	return sprintf(buf, "%s\n", osd->od_mntdev);
}
LUSTRE_RO_ATTR(mntdev);

ssize_t force_sync_store(struct kobject *kobj, struct attribute *attr,
			 const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lu_env env;
	int rc;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		return rc;

	rc = dt_sync(&env, dt);
	lu_env_fini(&env);

	return rc == 0 ? count : rc;
}
LUSTRE_WO_ATTR(force_sync);

static ssize_t sync_on_lseek_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);

	if (!osd->od_os)
		return -EINPROGRESS;

	return sprintf(buf, "%u\n", osd->od_sync_on_lseek);
}

ssize_t sync_on_lseek_store(struct kobject *kobj, struct attribute *attr,
			    const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);
	bool val;
	int rc;

	if (!osd->od_os)
		return -EINPROGRESS;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	osd->od_sync_on_lseek = !!val;

	return count;
}
LUSTRE_RW_ATTR(sync_on_lseek);

static ssize_t nonrotational_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);

	LASSERT(osd);
	if (!osd->od_os)
		return -EINPROGRESS;

	return sprintf(buf, "%u\n", osd->od_nonrotational);
}

static ssize_t nonrotational_store(struct kobject *kobj,
				   struct attribute *attr, const char *buffer,
				   size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *osd = osd_dt_dev(dt);
	bool val;
	int rc;

	LASSERT(osd);
	if (!osd->od_os)
		return -EINPROGRESS;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	osd->od_nonrotational = val;
	return count;
}
LUSTRE_RW_ATTR(nonrotational);

static ssize_t index_backup_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);

	LASSERT(dev);
	if (!dev->od_os)
		return -EINPROGRESS;

	return sprintf(buf, "%d\n", dev->od_index_backup_policy);
}

ssize_t index_backup_store(struct kobject *kobj, struct attribute *attr,
			   const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osd_device *dev = osd_dt_dev(dt);
	int val;
	int rc;

	LASSERT(dev);
	if (!dev->od_os)
		return -EINPROGRESS;

	rc = kstrtoint(buffer, 0, &val);
	if (rc)
		return rc;

	dev->od_index_backup_policy = val;
	return count;
}
LUSTRE_RW_ATTR(index_backup);

static int zfs_osd_readcache_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	if (unlikely(osd->od_os == NULL))
		return -EINPROGRESS;

	seq_printf(m, "%llu\n", osd->od_readcache_max_filesize);
	return 0;
}

static ssize_t
zfs_osd_readcache_seq_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct dt_device *dt = m->private;
	struct osd_device *osd = osd_dt_dev(dt);
	char kernbuf[22] = "";
	u64 val;
	int rc;

	LASSERT(osd != NULL);
	if (unlikely(osd->od_os == NULL))
		return -EINPROGRESS;

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	rc = sysfs_memparse(kernbuf, count, &val, "B");
	if (rc < 0)
		return rc;

	osd->od_readcache_max_filesize = val > OSD_MAX_CACHE_SIZE ?
					 OSD_MAX_CACHE_SIZE : val;
	return count;
}
LDEBUGFS_SEQ_FOPS(zfs_osd_readcache);

static struct attribute *zfs_attrs[] = {
	&lustre_attr_fstype.attr,
	&lustre_attr_mntdev.attr,
	&lustre_attr_force_sync.attr,
	&lustre_attr_nonrotational.attr,
	&lustre_attr_index_backup.attr,
	&lustre_attr_auto_scrub.attr,
	&lustre_attr_sync_on_lseek.attr,
	NULL,
};

struct ldebugfs_vars ldebugfs_osd_obd_vars[] = {
	{ .name	=	"oi_scrub",
	  .fops	=	&zfs_osd_oi_scrub_fops		},
	{ .name =	"readcache_max_filesize",
	  .fops =	&zfs_osd_readcache_fops		},
	{ 0 }
};

KOBJ_ATTRIBUTE_GROUPS(zfs); /* creates zfs_groups from zfs_attrs */

int osd_procfs_init(struct osd_device *osd, const char *name)
{
	struct obd_type *type;
	int rc;

	ENTRY;

	/* at the moment there is no linkage between lu_type
	 * and obd_type, so we lookup obd_type this way
	 */
	type = class_search_type(LUSTRE_OSD_ZFS_NAME);

	LASSERT(type);
	LASSERT(name);

	/* put reference taken by class_search_type */
	kobject_put(&type->typ_kobj);

	osd->od_dt_dev.dd_ktype.default_groups = KOBJ_ATTR_GROUPS(zfs);
	rc = dt_tunables_init(&osd->od_dt_dev, type, name,
			      ldebugfs_osd_obd_vars);
	if (rc) {
		CERROR("%s: cannot setup sysfs / debugfs entry: %d\n",
		       name, rc);
		GOTO(out, rc);
	}

	if (osd->od_proc_entry)
		RETURN(0);

	osd->od_proc_entry = lprocfs_register(name, type->typ_procroot,
					      NULL, &osd->od_dt_dev);
	if (IS_ERR(osd->od_proc_entry)) {
		rc = PTR_ERR(osd->od_proc_entry);
		CERROR("Error %d setting up lprocfs for %s\n", rc, name);
		osd->od_proc_entry = NULL;
		GOTO(out, rc);
	}

	rc = osd_stats_init(osd);

	GOTO(out, rc);
out:
	if (rc)
		osd_procfs_fini(osd);
	return rc;
}

int osd_procfs_fini(struct osd_device *osd)
{
	ENTRY;

	lprocfs_fini_brw_stats(&osd->od_brw_stats);

	if (osd->od_stats)
		lprocfs_free_stats(&osd->od_stats);

	if (osd->od_proc_entry) {
		lprocfs_remove(&osd->od_proc_entry);
		osd->od_proc_entry = NULL;
	}

	return dt_tunables_fini(&osd->od_dt_dev);
}
