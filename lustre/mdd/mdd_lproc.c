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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
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

int mdd_procfs_init(struct mdd_device *mdd, const char *name)
{
        struct lprocfs_static_vars lvars;
        struct obd_type     *type;
        int                  rc;
        ENTRY;

	/* at the moment there is no linkage between lu_type
	 * and obd_type, so we lookup obd_type this way */
	type = class_search_type(LUSTRE_MDD_NAME);

        LASSERT(name != NULL);
        LASSERT(type != NULL);

        /* Find the type procroot and add the proc entry for this device */
        lprocfs_mdd_init_vars(&lvars);
        mdd->mdd_proc_entry = lprocfs_register(name, type->typ_procroot,
                                               lvars.obd_vars, mdd);
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

int mdd_procfs_fini(struct mdd_device *mdd)
{
        if (mdd->mdd_proc_entry) {
                 lprocfs_remove(&mdd->mdd_proc_entry);
                 mdd->mdd_proc_entry = NULL;
        }
        RETURN(0);
}

static int lprocfs_wr_atime_diff(struct file *file, const char *buffer,
                                 unsigned long count, void *data)
{
        struct mdd_device *mdd = data;
        char kernbuf[20], *end;
        unsigned long diff = 0;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

        if (cfs_copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';

        diff = simple_strtoul(kernbuf, &end, 0);
        if (kernbuf == end)
                return -EINVAL;

        mdd->mdd_atime_diff = diff;
        return count;
}

static int lprocfs_rd_atime_diff(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct mdd_device *mdd = data;

        *eof = 1;
        return snprintf(page, count, "%lu\n", mdd->mdd_atime_diff);
}


/**** changelogs ****/
static int lprocfs_rd_changelog_mask(char *page, char **start, off_t off,
                                     int count, int *eof, void *data)
{
        struct mdd_device *mdd = data;
        int i = 0, rc = 0;

        *eof = 1;
        while (i < CL_LAST) {
                if (mdd->mdd_cl.mc_mask & (1 << i))
                        rc += snprintf(page + rc, count - rc, "%s ",
                                       changelog_type2str(i));
                i++;
        }
        return rc;
}

static int lprocfs_wr_changelog_mask(struct file *file, const char *buffer,
                                     unsigned long count, void *data)
{
        struct mdd_device *mdd = data;
        char *kernbuf;
        int rc;
        ENTRY;

        if (count >= CFS_PAGE_SIZE)
                RETURN(-EINVAL);
        OBD_ALLOC(kernbuf, CFS_PAGE_SIZE);
        if (kernbuf == NULL)
                RETURN(-ENOMEM);
        if (cfs_copy_from_user(kernbuf, buffer, count))
                GOTO(out, rc = -EFAULT);
        kernbuf[count] = 0;

        rc = cfs_str2mask(kernbuf, changelog_type2str, &mdd->mdd_cl.mc_mask,
                          CHANGELOG_MINMASK, CHANGELOG_ALLMASK);
        if (rc == 0)
                rc = count;
out:
        OBD_FREE(kernbuf, CFS_PAGE_SIZE);
        return rc;
}

struct cucb_data {
        char *page;
        int count;
        int idx;
};

static int lprocfs_changelog_users_cb(const struct lu_env *env,
				      struct llog_handle *llh,
				      struct llog_rec_hdr *hdr, void *data)
{
        struct llog_changelog_user_rec *rec;
        struct cucb_data *cucb = (struct cucb_data *)data;

        LASSERT(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN);

        rec = (struct llog_changelog_user_rec *)hdr;

        cucb->idx += snprintf(cucb->page + cucb->idx, cucb->count - cucb->idx,
                              CHANGELOG_USER_PREFIX"%-3d "LPU64"\n",
                              rec->cur_id, rec->cur_endrec);
        if (cucb->idx >= cucb->count)
                return -ENOSPC;

        return 0;
}

static int lprocfs_rd_changelog_users(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{
	struct lu_env		 env;
	struct mdd_device	*mdd = data;
	struct llog_ctxt	*ctxt;
	struct cucb_data	 cucb;
	__u64			 cur;
	int			 rc;

        *eof = 1;

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

        cucb.count = count;
        cucb.page = page;
        cucb.idx = 0;

        cucb.idx += snprintf(cucb.page + cucb.idx, cucb.count - cucb.idx,
                              "current index: "LPU64"\n", cur);

        cucb.idx += snprintf(cucb.page + cucb.idx, cucb.count - cucb.idx,
                              "%-5s %s\n", "ID", "index");

	llog_cat_process(&env, ctxt->loc_handle, lprocfs_changelog_users_cb,
			 &cucb, 0, 0);

	lu_env_fini(&env);
	llog_ctxt_put(ctxt);
	return cucb.idx;
}

static int lprocfs_rd_sync_perm(char *page, char **start, off_t off,
                                int count, int *eof, void *data)
{
        struct mdd_device *mdd = data;

        LASSERT(mdd != NULL);
        return snprintf(page, count, "%d\n", mdd->mdd_sync_permission);
}

static int lprocfs_wr_sync_perm(struct file *file, const char *buffer,
                                unsigned long count, void *data)
{
        struct mdd_device *mdd = data;
        int val, rc;

        LASSERT(mdd != NULL);
        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdd->mdd_sync_permission = !!val;
        return count;
}

static int lprocfs_rd_lfsck_speed_limit(char *page, char **start, off_t off,
					int count, int *eof, void *data)
{
	struct mdd_device *mdd = data;

	LASSERT(mdd != NULL);
	*eof = 1;
	return snprintf(page, count, "%u\n",
			mdd->mdd_lfsck.ml_bookmark_ram.lb_speed_limit);
}

static int lprocfs_wr_lfsck_speed_limit(struct file *file, const char *buffer,
					unsigned long count, void *data)
{
	struct mdd_device *mdd = data;
	struct md_lfsck *lfsck;
	__u32 val;
	int rc;

	LASSERT(mdd != NULL);
	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc != 0)
		return rc;

	lfsck = &mdd->mdd_lfsck;
	if (val != lfsck->ml_bookmark_ram.lb_speed_limit) {
		struct lu_env env;

		rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
		if (rc != 0)
			return rc;

		rc = mdd_lfsck_set_speed(&env, lfsck, val);
		lu_env_fini(&env);
	}
	return rc != 0 ? rc : count;
}

static int lprocfs_rd_lfsck_namespace(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	struct lu_env env;
	struct mdd_device *mdd = data;
	int rc;

	LASSERT(mdd != NULL);
	*eof = 1;

	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0)
		return rc;

	rc = mdd_lfsck_dump(&env, &mdd->mdd_lfsck, LT_NAMESPACE, page, count);
	lu_env_fini(&env);
	return rc;
}

static struct lprocfs_vars lprocfs_mdd_obd_vars[] = {
        { "atime_diff",      lprocfs_rd_atime_diff, lprocfs_wr_atime_diff, 0 },
        { "changelog_mask",  lprocfs_rd_changelog_mask,
                             lprocfs_wr_changelog_mask, 0 },
        { "changelog_users", lprocfs_rd_changelog_users, 0, 0},
        { "sync_permission", lprocfs_rd_sync_perm, lprocfs_wr_sync_perm, 0 },
	{ "lfsck_speed_limit", lprocfs_rd_lfsck_speed_limit,
			       lprocfs_wr_lfsck_speed_limit, 0 },
	{ "lfsck_namespace", lprocfs_rd_lfsck_namespace, 0, 0 },
	{ 0 }
};

static struct lprocfs_vars lprocfs_mdd_module_vars[] = {
        { "num_refs",   lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

void lprocfs_mdd_init_vars(struct lprocfs_static_vars *lvars)
{
        lvars->module_vars  = lprocfs_mdd_module_vars;
        lvars->obd_vars     = lprocfs_mdd_obd_vars;
}

