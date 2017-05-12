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
 * Copyright (c) 2012, 2016, Intel Corporation.
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

static ssize_t
mdd_atime_diff_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct mdd_device *mdd = m->private;
	char kernbuf[20], *end;
	unsigned long diff = 0;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';

        diff = simple_strtoul(kernbuf, &end, 0);
        if (kernbuf == end)
                return -EINVAL;

        mdd->mdd_atime_diff = diff;
        return count;
}

static int mdd_atime_diff_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	seq_printf(m, "%lu\n", mdd->mdd_atime_diff);
	return 0;
}
LPROC_SEQ_FOPS(mdd_atime_diff);

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
LPROC_SEQ_FOPS(mdd_changelog_mask);

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
LPROC_SEQ_FOPS_RO(mdd_changelog_users);

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

static int mdd_changelog_size_seq_show(struct seq_file *m, void *data)
{
	struct lu_env		 env;
	struct mdd_device	*mdd = m->private;
	__u64			 tmp = 0;
	int			 rc;

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

	seq_printf(m, "%llu\n", tmp);
	lu_env_fini(&env);
	return rc;
}
LPROC_SEQ_FOPS_RO(mdd_changelog_size);

static int mdd_changelog_gc_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);
	seq_printf(m, "%u\n", mdd->mdd_changelog_gc);
	return 0;
}

static ssize_t
mdd_changelog_gc_seq_write(struct file *file, const char __user *buffer,
			   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct mdd_device *mdd = m->private;
	int rc;
	__s64 val;

	LASSERT(mdd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	mdd->mdd_changelog_gc = !!val;

	return count;
}
LPROC_SEQ_FOPS(mdd_changelog_gc);

static int mdd_changelog_max_idle_time_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);
	seq_printf(m, "%u\n", mdd->mdd_changelog_max_idle_time);
	return 0;
}

static ssize_t
mdd_changelog_max_idle_time_seq_write(struct file *file,
				      const char __user *buffer, size_t count,
				      loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct mdd_device *mdd = m->private;
	int rc;
	__s64 val;

	LASSERT(mdd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	/* XXX may need to limit with reasonable elapsed/idle times */
	if (val < 1 || val > INT_MAX)
		return -ERANGE;

	mdd->mdd_changelog_max_idle_time = val;

	return count;
}
LPROC_SEQ_FOPS(mdd_changelog_max_idle_time);

static int mdd_changelog_max_idle_indexes_seq_show(struct seq_file *m,
						   void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);
	seq_printf(m, "%lu\n", mdd->mdd_changelog_max_idle_indexes);
	return 0;
}

static ssize_t
mdd_changelog_max_idle_indexes_seq_write(struct file *file,
					 const char __user *buffer,
					 size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct mdd_device *mdd = m->private;
	int rc;
	__s64 val;

	LASSERT(mdd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	/* XXX may need to limit/check with reasonable elapsed/idle indexes */
	/* XXX may better allow to specify a % of full ChangeLogs */

	mdd->mdd_changelog_max_idle_indexes = val;

	return count;
}
LPROC_SEQ_FOPS(mdd_changelog_max_idle_indexes);

static int mdd_changelog_min_gc_interval_seq_show(struct seq_file *m,
						  void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);
	seq_printf(m, "%u\n", mdd->mdd_changelog_min_gc_interval);
	return 0;
}

static ssize_t
mdd_changelog_min_gc_interval_seq_write(struct file *file,
					const char __user *buffer,
					size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct mdd_device *mdd = m->private;
	int rc;
	__s64 val;

	LASSERT(mdd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	/* XXX may need to limit with reasonable elapsed/interval times */
	if (val < 1 || val > UINT_MAX)
		return -ERANGE;

	mdd->mdd_changelog_min_gc_interval = val;

	return count;
}
LPROC_SEQ_FOPS(mdd_changelog_min_gc_interval);

static int mdd_changelog_min_free_cat_entries_seq_show(struct seq_file *m,
						       void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);
	seq_printf(m, "%u\n", mdd->mdd_changelog_min_free_cat_entries);
	return 0;
}

static ssize_t
mdd_changelog_min_free_cat_entries_seq_write(struct file *file,
					     const char __user *buffer,
					     size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct mdd_device *mdd = m->private;
	int rc;
	__s64 val;

	LASSERT(mdd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	/* XXX may need to limit with more reasonable number of free entries */
	if (val < 1 || (__u64)val > UINT_MAX)
		return -ERANGE;

	mdd->mdd_changelog_min_free_cat_entries = val;

	return count;
}
LPROC_SEQ_FOPS(mdd_changelog_min_free_cat_entries);

static int mdd_sync_perm_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);
	seq_printf(m, "%d\n", mdd->mdd_sync_permission);
	return 0;
}

static ssize_t
mdd_sync_perm_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct mdd_device *mdd = m->private;
	int rc;
	__s64 val;

	LASSERT(mdd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	mdd->mdd_sync_permission = !!val;

	return count;
}
LPROC_SEQ_FOPS(mdd_sync_perm);

static int mdd_lfsck_speed_limit_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);
	return lfsck_get_speed(m, mdd->mdd_bottom);
}

static ssize_t
mdd_lfsck_speed_limit_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct mdd_device *mdd = m->private;
	__s64 val;
	int rc;

	LASSERT(mdd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc != 0)
		return rc;
	if (val < 0 || val > INT_MAX)
		return -ERANGE;

	rc = lfsck_set_speed(mdd->mdd_bottom, val);
	return rc != 0 ? rc : count;
}
LPROC_SEQ_FOPS(mdd_lfsck_speed_limit);

static int mdd_lfsck_async_windows_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);
	return lfsck_get_windows(m, mdd->mdd_bottom);
}

static ssize_t
mdd_lfsck_async_windows_seq_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t *off)
{
	struct seq_file   *m = file->private_data;
	struct mdd_device *mdd = m->private;
	__s64		   val;
	int		   rc;

	LASSERT(mdd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < 0 || val > INT_MAX)
		return -ERANGE;

	rc = lfsck_set_windows(mdd->mdd_bottom, val);

	return rc != 0 ? rc : count;
}
LPROC_SEQ_FOPS(mdd_lfsck_async_windows);

static int mdd_lfsck_namespace_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);

	return lfsck_dump(m, mdd->mdd_bottom, LFSCK_TYPE_NAMESPACE);
}
LPROC_SEQ_FOPS_RO(mdd_lfsck_namespace);

static int mdd_lfsck_layout_seq_show(struct seq_file *m, void *data)
{
	struct mdd_device *mdd = m->private;

	LASSERT(mdd != NULL);

	return lfsck_dump(m, mdd->mdd_bottom, LFSCK_TYPE_LAYOUT);
}
LPROC_SEQ_FOPS_RO(mdd_lfsck_layout);

static struct lprocfs_vars lprocfs_mdd_obd_vars[] = {
	{ .name =	"atime_diff",
	  .fops =	&mdd_atime_diff_fops		},
	{ .name =	"changelog_mask",
	  .fops =	&mdd_changelog_mask_fops	},
	{ .name =	"changelog_users",
	  .fops =	&mdd_changelog_users_fops	},
	{ .name =	"changelog_size",
	  .fops =	&mdd_changelog_size_fops	},
	{ .name =	"changelog_gc",
	  .fops =	&mdd_changelog_gc_fops		},
	{ .name =	"changelog_max_idle_time",
	  .fops =	&mdd_changelog_max_idle_time_fops	},
	{ .name =	"changelog_max_idle_indexes",
	  .fops =	&mdd_changelog_max_idle_indexes_fops	},
	{ .name =	"changelog_min_gc_interval",
	  .fops =	&mdd_changelog_min_gc_interval_fops	},
	{ .name =	"changelog_min_free_cat_entries",
	  .fops =	&mdd_changelog_min_free_cat_entries_fops	},
	{ .name =	"sync_permission",
	  .fops =	&mdd_sync_perm_fops		},
	{ .name =	"lfsck_speed_limit",
	  .fops =	&mdd_lfsck_speed_limit_fops	},
	{ .name =	"lfsck_async_windows",
	  .fops =	&mdd_lfsck_async_windows_fops	},
	{ .name =	"lfsck_namespace",
	  .fops =	&mdd_lfsck_namespace_fops	},
	{ .name	=	"lfsck_layout",
	  .fops	=	&mdd_lfsck_layout_fops		},
	{ NULL }
};

int mdd_procfs_init(struct mdd_device *mdd, const char *name)
{
	struct obd_device *obd = mdd2obd_dev(mdd);
	struct obd_type   *type;
	int		   rc;
	ENTRY;

	/* at the moment there is no linkage between lu_type
	 * and obd_type, so we lookup obd_type this way */
	type = class_search_type(LUSTRE_MDD_NAME);

	LASSERT(name != NULL);
	LASSERT(type != NULL);
	LASSERT(obd  != NULL);

	/* Find the type procroot and add the proc entry for this device */
	obd->obd_vars = lprocfs_mdd_obd_vars;
	mdd->mdd_proc_entry = lprocfs_register(name, type->typ_procroot,
					       obd->obd_vars, mdd);
	if (IS_ERR(mdd->mdd_proc_entry)) {
		rc = PTR_ERR(mdd->mdd_proc_entry);
		CERROR("Error %d setting up lprocfs for %s\n",
		       rc, name);
		mdd->mdd_proc_entry = NULL;
		GOTO(out, rc);
	}
	rc = 0;
	EXIT;
out:
	if (rc)
		mdd_procfs_fini(mdd);
	return rc;
}

void mdd_procfs_fini(struct mdd_device *mdd)
{
	if (mdd->mdd_proc_entry)
		lprocfs_remove(&mdd->mdd_proc_entry);
}
