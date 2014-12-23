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
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mgs/mgs_fs.c
 *
 * Lustre Management Server (MGS) filesystem interface code
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_MGS

#include <lustre_fid.h>
#include "mgs_internal.h"

int mgs_export_stats_init(struct obd_device *obd, struct obd_export *exp,
			  void *localdata)
{
	lnet_nid_t *client_nid = localdata;
	struct nid_stat *tmp;
	int rc, is_new_nid;
	ENTRY;

	rc = lprocfs_exp_setup(exp, client_nid, &is_new_nid);
	if (rc != 0) {
		/* Mask error for already created /proc entries */
		if (rc == -EALREADY)
			rc = 0;
		GOTO(out, rc = 0);
        }

	if (!is_new_nid)
		GOTO(out, rc = 0);

	tmp = exp->exp_nid_stats;
	tmp->nid_stats = lprocfs_alloc_stats(NUM_OBD_STATS + LPROC_MGS_LAST,
					     LPROCFS_STATS_FLAG_NOPERCPU);
	if (tmp->nid_stats == NULL)
		GOTO(out, rc = -ENOMEM);

	lprocfs_init_ops_stats(LPROC_MGS_LAST, tmp->nid_stats);
	mgs_stats_counter_init(tmp->nid_stats);
	rc = lprocfs_register_stats(tmp->nid_proc, "stats", tmp->nid_stats);
	if (rc != 0)
		GOTO(out, rc);

	rc = lprocfs_nid_ldlm_stats_init(tmp);
	if (rc != 0)
		GOTO(out, rc);

	RETURN(0);
out:
	return rc;
}

/**
 * Add client export data to the MGS.  This data is currently NOT stored on
 * disk in the last_rcvd file or anywhere else.  In the event of a MGS
 * crash all connections are treated as new connections.
 */
int mgs_client_add(struct obd_device *obd, struct obd_export *exp,
                   void *localdata)
{
        return 0;
}

/* Remove client export data from the MGS */
int mgs_client_free(struct obd_export *exp)
{
        return 0;
}

int mgs_fs_setup(const struct lu_env *env, struct mgs_device *mgs)
{
	struct lu_fid		 fid;
	struct dt_object	*o;
	struct lu_fid		 rfid;
	struct dt_object	*root;
	int			 rc;

	ENTRY;

	OBD_SET_CTXT_MAGIC(&mgs->mgs_obd->obd_lvfs_ctxt);
	mgs->mgs_obd->obd_lvfs_ctxt.dt = mgs->mgs_bottom;

	/* XXX: fix when support for N:1 layering is implemented */
	LASSERT(mgs->mgs_dt_dev.dd_lu_dev.ld_site);
	mgs->mgs_dt_dev.dd_lu_dev.ld_site->ls_top_dev =
		&mgs->mgs_dt_dev.dd_lu_dev;

	/* Setup the configs dir */
	fid.f_seq = FID_SEQ_LOCAL_NAME;
	fid.f_oid = 1;
	fid.f_ver = 0;
	rc = local_oid_storage_init(env, mgs->mgs_bottom, &fid, &mgs->mgs_los);
	if (rc)
		GOTO(out, rc);

	rc = dt_root_get(env, mgs->mgs_bottom, &rfid);
	if (rc)
		GOTO(out_los, rc);

	root = dt_locate_at(env, mgs->mgs_bottom, &rfid,
			    &mgs->mgs_dt_dev.dd_lu_dev, NULL);
	if (unlikely(IS_ERR(root)))
		GOTO(out_los, rc = PTR_ERR(root));

	o = local_file_find_or_create(env, mgs->mgs_los, root,
				      MOUNT_CONFIGS_DIR,
				      S_IFDIR | S_IRUGO | S_IWUSR | S_IXUGO);
	if (IS_ERR(o))
		GOTO(out_root, rc = PTR_ERR(o));

	if (!dt_try_as_dir(env, o)) {
		lu_object_put(env, &o->do_lu);
		GOTO(out_root, rc = -ENOTDIR);
	}

	mgs->mgs_configs_dir = o;

	/* create directory to store nid table versions */
	o = local_file_find_or_create(env, mgs->mgs_los, root, MGS_NIDTBL_DIR,
				      S_IFDIR | S_IRUGO | S_IWUSR | S_IXUGO);
	if (IS_ERR(o)) {
		lu_object_put(env, &mgs->mgs_configs_dir->do_lu);
		mgs->mgs_configs_dir = NULL;
		GOTO(out_root, rc = PTR_ERR(o));
	}

	mgs->mgs_nidtbl_dir = o;

out_root:
	lu_object_put(env, &root->do_lu);
out_los:
	if (rc) {
		local_oid_storage_fini(env, mgs->mgs_los);
		mgs->mgs_los = NULL;
	}
out:
	mgs->mgs_dt_dev.dd_lu_dev.ld_site->ls_top_dev = NULL;

	return rc;
}

int mgs_fs_cleanup(const struct lu_env *env, struct mgs_device *mgs)
{
	class_disconnect_exports(mgs->mgs_obd); /* cleans up client info too */

	if (mgs->mgs_configs_dir) {
		lu_object_put(env, &mgs->mgs_configs_dir->do_lu);
		mgs->mgs_configs_dir = NULL;
	}
	if (mgs->mgs_nidtbl_dir) {
		lu_object_put(env, &mgs->mgs_nidtbl_dir->do_lu);
		mgs->mgs_nidtbl_dir = NULL;
	}
	if (mgs->mgs_los) {
		local_oid_storage_fini(env, mgs->mgs_los);
		mgs->mgs_los = NULL;
	}

	return 0;
}
