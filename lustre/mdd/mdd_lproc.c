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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdd/mdd_lproc.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lprocfs_status.h>
#include <libcfs/libcfs_string.h>
#include "mdd_internal.h"

static ssize_t uuid_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	struct obd_device *obd = mdd2obd_dev(mdd);

	return sprintf(buf, "%s\n", obd->obd_uuid.uuid);
}
LUSTRE_RO_ATTR(uuid);

static ssize_t atime_diff_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return sprintf(buf, "%lld\n", mdd->mdd_atime_diff);
}

static ssize_t atime_diff_store(struct kobject *kobj,
				struct attribute *attr,
				const char *buffer, size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	time64_t diff = 0;
	int rc;

	rc = kstrtoll(buffer, 10, &diff);
	if (rc)
		return rc;

        mdd->mdd_atime_diff = diff;
        return count;
}
LUSTRE_RW_ATTR(atime_diff);

/**** changelogs ****/
static int mdd_changelog_mask_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;
	int i = 0;

	while (i < CL_LAST) {
		if (mdd->mdd_cl.mc_mask & (1 << i))
			seq_printf(m, "%s ", changelog_type2str(i));
		i++;
	}
	seq_putc(m, '\n');
	return 0;
}

static ssize_t
mdd_changelog_mask_seq_write(struct file *file, const char __user *buffer,
			     size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct mdd_device *mdd = m->private;
	char *kernbuf;
	int rc;
	ENTRY;

	if (count >= PAGE_SIZE)
		RETURN(-EINVAL);
	OBD_ALLOC(kernbuf, PAGE_SIZE);
	if (kernbuf == NULL)
		RETURN(-ENOMEM);
	if (copy_from_user(kernbuf, buffer, count))
		GOTO(out, rc = -EFAULT);
	kernbuf[count] = 0;

	rc = cfs_str2mask(kernbuf, changelog_type2str, &mdd->mdd_cl.mc_mask,
			  CHANGELOG_MINMASK, CHANGELOG_ALLMASK);
	if (rc == 0)
		rc = count;
out:
	OBD_FREE(kernbuf, PAGE_SIZE);
	return rc;
}
LDEBUGFS_SEQ_FOPS(mdd_changelog_mask);

static int lprocfs_changelog_users_cb(const struct lu_env *env,
				      struct llog_handle *llh,
				      struct llog_rec_hdr *hdr, void *data)
{
	struct llog_changelog_user_rec *rec;
	struct seq_file *m = data;

	LASSERT(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN);

	rec = (struct llog_changelog_user_rec *)hdr;

	seq_printf(m, CHANGELOG_USER_PREFIX"%-3d %llu (%u)\n",
		   rec->cur_id, rec->cur_endrec, (__u32)get_seconds() -
						 rec->cur_time);
	return 0;
}

static int mdd_changelog_users_seq_show(struct seq_file *m, void *data)
{
	struct lu_env		 env;
	struct mdd_device	*mdd = m->private;
	struct llog_ctxt	*ctxt;
	__u64			 cur;
	int			 rc;

        ctxt = llog_get_context(mdd2obd_dev(mdd),
				LLOG_CHANGELOG_USER_ORIG_CTXT);
        if (ctxt == NULL)
                return -ENXIO;
        LASSERT(ctxt->loc_handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT);

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc) {
		llog_ctxt_put(ctxt);
		return rc;
	}

	spin_lock(&mdd->mdd_cl.mc_lock);
	cur = mdd->mdd_cl.mc_index;
	spin_unlock(&mdd->mdd_cl.mc_lock);

	seq_printf(m, "current index: %llu\n", cur);
	seq_printf(m, "%-5s %s %s\n", "ID", "index", "(idle seconds)");

	llog_cat_process(&env, ctxt->loc_handle, lprocfs_changelog_users_cb,
			 m, 0, 0);

	lu_env_fini(&env);
	llog_ctxt_put(ctxt);
	return 0;
}
LDEBUGFS_SEQ_FOPS_RO(mdd_changelog_users);

static int mdd_changelog_size_ctxt(const struct lu_env *env,
				   struct mdd_device *mdd,
				   int index, __u64 *val)
{
	struct llog_ctxt	*ctxt;

	ctxt = llog_get_context(mdd2obd_dev(mdd),
				index);
	if (ctxt == NULL)
		return -ENXIO;

	if (!(ctxt->loc_handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)) {
		CERROR("%s: ChangeLog has wrong flags: rc = %d\n",
		       ctxt->loc_obd->obd_name, -EINVAL);
		llog_ctxt_put(ctxt);
		return -EINVAL;
	}

	*val += llog_cat_size(env, ctxt->loc_handle);

	llog_ctxt_put(ctxt);

	return 0;
}

static ssize_t changelog_size_show(struct kobject *kobj,
				   struct attribute *attr,
				   char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	struct lu_env env;
	u64 tmp = 0;
	int rc;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		return rc;

	rc = mdd_changelog_size_ctxt(&env, mdd, LLOG_CHANGELOG_ORIG_CTXT, &tmp);
	if (rc) {
		lu_env_fini(&env);
		return rc;
	}

	rc = mdd_changelog_size_ctxt(&env, mdd, LLOG_CHANGELOG_USER_ORIG_CTXT,
				     &tmp);

	rc = sprintf(buf, "%llu\n", tmp);
	lu_env_fini(&env);
	return rc;
}
LUSTRE_RO_ATTR(changelog_size);

static ssize_t changelog_gc_show(struct kobject *kobj,
				 struct attribute *attr,
				 char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return sprintf(buf, "%u\n", mdd->mdd_changelog_gc);
}

static ssize_t changelog_gc_store(struct kobject *kobj,
				  struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdd->mdd_changelog_gc = val;

	return count;
}
LUSTRE_RW_ATTR(changelog_gc);

static ssize_t changelog_max_idle_time_show(struct kobject *kobj,
					    struct attribute *attr,
					    char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return sprintf(buf, "%lld\n", mdd->mdd_changelog_max_idle_time);
}

static ssize_t changelog_max_idle_time_store(struct kobject *kobj,
					     struct attribute *attr,
					     const char *buffer, size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	time64_t val;
	int rc;

	rc = kstrtoll(buffer, 10, &val);
	if (rc)
		return rc;

	/* as it sounds reasonable, do not allow a user to be idle since
	 * more than about 68 years, this will allow to use 32bits
	 * timestamps for comparison
	 */
	if (val < 1 || val > INT_MAX)
		return -ERANGE;

	mdd->mdd_changelog_max_idle_time = val;

	return count;
}
LUSTRE_RW_ATTR(changelog_max_idle_time);

static ssize_t changelog_max_idle_indexes_show(struct kobject *kobj,
					       struct attribute *attr,
					       char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return sprintf(buf, "%lu\n", mdd->mdd_changelog_max_idle_indexes);
}

static ssize_t changelog_max_idle_indexes_store(struct kobject *kobj,
						struct attribute *attr,
						const char *buffer,
						size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	unsigned long val;
	int rc;

	LASSERT(mdd != NULL);
	rc = kstrtoul(buffer, 0, &val);
	if (rc)
		return rc;

	/* XXX may need to limit/check with reasonable elapsed/idle indexes */
	/* XXX may better allow to specify a % of full ChangeLogs */

	mdd->mdd_changelog_max_idle_indexes = val;

	return count;
}
LUSTRE_RW_ATTR(changelog_max_idle_indexes);

static ssize_t changelog_min_gc_interval_show(struct kobject *kobj,
					      struct attribute *attr,
					      char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return sprintf(buf, "%lld\n", mdd->mdd_changelog_min_gc_interval);
}

static ssize_t changelog_min_gc_interval_store(struct kobject *kobj,
					       struct attribute *attr,
					       const char *buffer,
					       size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	time64_t val;
	int rc;

	rc = kstrtoll(buffer, 10, &val);
	if (rc)
		return rc;

	/* XXX may need to limit with reasonable elapsed/interval times */
	if (val < 1)
		return -ERANGE;

	mdd->mdd_changelog_min_gc_interval = val;

	return count;
}
LUSTRE_RW_ATTR(changelog_min_gc_interval);

static ssize_t changelog_min_free_cat_entries_show(struct kobject *kobj,
						   struct attribute *attr,
						   char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return sprintf(buf, "%u\n", mdd->mdd_changelog_min_free_cat_entries);
}

static ssize_t changelog_min_free_cat_entries_store(struct kobject *kobj,
						    struct attribute *attr,
						    const char *buffer,
						    size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	/* XXX may need to limit with more reasonable number of free entries */
	if (val < 1)
		return -ERANGE;

	mdd->mdd_changelog_min_free_cat_entries = val;

	return count;
}
LUSTRE_RW_ATTR(changelog_min_free_cat_entries);

static ssize_t changelog_deniednext_show(struct kobject *kobj,
					 struct attribute *attr,
					 char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return sprintf(buf, "%u\n", mdd->mdd_cl.mc_deniednext);
}

static ssize_t changelog_deniednext_store(struct kobject *kobj,
					  struct attribute *attr,
					  const char *buffer,
					  size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	unsigned int time = 0;
	int rc;

	rc = kstrtouint(buffer, 0, &time);
	if (rc)
		return rc;

	mdd->mdd_cl.mc_deniednext = time;
	return count;
}
LUSTRE_RW_ATTR(changelog_deniednext);

static ssize_t sync_perm_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return sprintf(buf, "%d\n", mdd->mdd_sync_permission);
}

static ssize_t sync_perm_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer, size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdd->mdd_sync_permission = val;

	return count;
}
LUSTRE_RW_ATTR(sync_perm);

static ssize_t lfsck_speed_limit_show(struct kobject *kobj,
				      struct attribute *attr, char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return lfsck_get_speed(buf, mdd->mdd_bottom);
}

static ssize_t lfsck_speed_limit_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer, size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc != 0)
		return rc;

	rc = lfsck_set_speed(mdd->mdd_bottom, val);
	return rc != 0 ? rc : count;
}
LUSTRE_RW_ATTR(lfsck_speed_limit);

static ssize_t lfsck_async_windows_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	return lfsck_get_windows(buf, mdd->mdd_bottom);
}

static ssize_t lfsck_async_windows_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer, size_t count)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	rc = lfsck_set_windows(mdd->mdd_bottom, val);

	return rc != 0 ? rc : count;
}
LUSTRE_RW_ATTR(lfsck_async_windows);

static int mdd_lfsck_namespace_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);

	return lfsck_dump(m, mdd->mdd_bottom, LFSCK_TYPE_NAMESPACE);
}
LDEBUGFS_SEQ_FOPS_RO(mdd_lfsck_namespace);

static int mdd_lfsck_layout_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);

	return lfsck_dump(m, mdd->mdd_bottom, LFSCK_TYPE_LAYOUT);
}
LDEBUGFS_SEQ_FOPS_RO(mdd_lfsck_layout);

static struct lprocfs_vars lprocfs_mdd_obd_vars[] = {
	{ .name =	"changelog_mask",
	  .fops =	&mdd_changelog_mask_fops	},
	{ .name =	"changelog_users",
	  .fops =	&mdd_changelog_users_fops	},
	{ .name =	"lfsck_namespace",
	  .fops =	&mdd_lfsck_namespace_fops	},
	{ .name	=	"lfsck_layout",
	  .fops	=	&mdd_lfsck_layout_fops		},
	{ NULL }
};

static struct attribute *mdd_attrs[] = {
	&lustre_attr_uuid.attr,
	&lustre_attr_atime_diff.attr,
	&lustre_attr_changelog_size.attr,
	&lustre_attr_changelog_gc.attr,
	&lustre_attr_changelog_max_idle_time.attr,
	&lustre_attr_changelog_max_idle_indexes.attr,
	&lustre_attr_changelog_min_gc_interval.attr,
	&lustre_attr_changelog_min_free_cat_entries.attr,
	&lustre_attr_changelog_deniednext.attr,
	&lustre_attr_lfsck_async_windows.attr,
	&lustre_attr_lfsck_speed_limit.attr,
	&lustre_attr_sync_perm.attr,
	NULL,
};

static void mdd_sysfs_release(struct kobject *kobj)
{
	struct mdd_device *mdd = container_of(kobj, struct mdd_device,
					      mdd_kobj);

	complete(&mdd->mdd_kobj_unregister);
}

int mdd_procfs_init(struct mdd_device *mdd, const char *name)
{
	struct obd_device *obd = mdd2obd_dev(mdd);
	struct obd_type *type;
	int rc;

	ENTRY;
	/* at the moment there is no linkage between lu_type
	 * and obd_type, so we lookup obd_type this way
	 */
	type = class_search_type(LUSTRE_MDD_NAME);

	LASSERT(name != NULL);
	LASSERT(type != NULL);
	LASSERT(obd  != NULL);

	mdd->mdd_ktype.default_attrs = mdd_attrs;
	mdd->mdd_ktype.release = mdd_sysfs_release;
	mdd->mdd_ktype.sysfs_ops = &lustre_sysfs_ops;

	init_completion(&mdd->mdd_kobj_unregister);
	rc = kobject_init_and_add(&mdd->mdd_kobj, &mdd->mdd_ktype,
				  &type->typ_kobj, "%s", name);
	if (rc)
		return rc;

	/* Find the type procroot and add the proc entry for this device */
	obd->obd_vars = lprocfs_mdd_obd_vars;
	obd->obd_debugfs_entry = ldebugfs_register(name,
						   type->typ_debugfs_entry,
						   obd->obd_vars, mdd);
	if (IS_ERR_OR_NULL(obd->obd_debugfs_entry)) {
		rc = obd->obd_debugfs_entry ? PTR_ERR(obd->obd_debugfs_entry)
					    : -ENOMEM;
		CERROR("Error %d setting up debugfs for %s\n",
		       rc, name);
		obd->obd_debugfs_entry = NULL;

		kobject_put(&mdd->mdd_kobj);
	}

	RETURN(rc);
}

void mdd_procfs_fini(struct mdd_device *mdd)
{
	struct obd_device *obd = mdd2obd_dev(mdd);

	kobject_put(&mdd->mdd_kobj);
	wait_for_completion(&mdd->mdd_kobj_unregister);

	if (!IS_ERR_OR_NULL(obd->obd_debugfs_entry))
		ldebugfs_remove(&obd->obd_debugfs_entry);
}
