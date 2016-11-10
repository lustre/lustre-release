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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2015, Intel Corporation.
 * Use is subject to license terms.
 *
 * lustre/mdt/mdt_lvb.c
 *
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

/* Called with res->lr_lvb_sem held */
static int mdt_lvbo_init(struct ldlm_resource *res)
{
	if (IS_LQUOTA_RES(res)) {
		struct mdt_device	*mdt;

		mdt = ldlm_res_to_ns(res)->ns_lvbp;
		if (mdt->mdt_qmt_dev == NULL)
			return 0;

		/* call lvbo init function of quota master */
		return qmt_hdls.qmth_lvbo_init(mdt->mdt_qmt_dev, res);
	}

	return 0;
}

static int mdt_lvbo_update(struct ldlm_resource *res,
			   struct ptlrpc_request *req,
			   int increase_only)
{
	if (IS_LQUOTA_RES(res)) {
		struct mdt_device	*mdt;

		mdt = ldlm_res_to_ns(res)->ns_lvbp;
		if (mdt->mdt_qmt_dev == NULL)
			return 0;

		/* call lvbo update function of quota master */
		return qmt_hdls.qmth_lvbo_update(mdt->mdt_qmt_dev, res, req,
						 increase_only);
	}

	return 0;
}


static int mdt_lvbo_size(struct ldlm_lock *lock)
{
	struct mdt_device *mdt;

	/* resource on server side never changes. */
	mdt = ldlm_res_to_ns(lock->l_resource)->ns_lvbp;
	LASSERT(mdt != NULL);

	if (IS_LQUOTA_RES(lock->l_resource)) {
		if (mdt->mdt_qmt_dev == NULL)
			return 0;

		/* call lvbo size function of quota master */
		return qmt_hdls.qmth_lvbo_size(mdt->mdt_qmt_dev, lock);
	}

	if (ldlm_has_layout(lock))
		return mdt->mdt_max_mdsize;

	return 0;
}

static int mdt_lvbo_fill(struct ldlm_lock *lock, void *lvb, int lvblen)
{
	struct lu_env env;
	struct mdt_thread_info *info;
	struct mdt_device *mdt;
	struct lu_fid *fid;
	struct mdt_object *obj = NULL;
	struct md_object *child = NULL;
	int rc;
	ENTRY;

	mdt = ldlm_lock_to_ns(lock)->ns_lvbp;
	if (IS_LQUOTA_RES(lock->l_resource)) {
		if (mdt->mdt_qmt_dev == NULL)
			RETURN(0);

		/* call lvbo fill function of quota master */
		rc = qmt_hdls.qmth_lvbo_fill(mdt->mdt_qmt_dev, lock, lvb,
					     lvblen);
		RETURN(rc);
	}

	/* Only fill layout if layout lock is granted */
	if (!ldlm_has_layout(lock) || lock->l_granted_mode != lock->l_req_mode)
		RETURN(0);

	/* layout lock will be granted to client, fill in lvb with layout */

	/* XXX create an env to talk to mdt stack. We should get this env from
	 * ptlrpc_thread->t_env. */
	rc = lu_env_init(&env, LCT_MD_THREAD);
	/* Likely ENOMEM */
	if (rc)
		RETURN(rc);

	info = lu_context_key_get(&env.le_ctx, &mdt_thread_key);
	/* Likely ENOMEM */
	if (info == NULL)
		GOTO(out, rc = -ENOMEM);

	memset(info, 0, sizeof *info);
	info->mti_env = &env;
	info->mti_exp = lock->l_export;
	info->mti_mdt = mdt;

	/* XXX get fid by resource id. why don't include fid in ldlm_resource */
	fid = &info->mti_tmp_fid2;
	fid_extract_from_res_name(fid, &lock->l_resource->lr_name);

	obj = mdt_object_find(&env, info->mti_mdt, fid);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	if (!mdt_object_exists(obj) || mdt_object_remote(obj))
		GOTO(out, rc = -ENOENT);

	child = mdt_object_child(obj);

	/* get the length of lsm */
	rc = mo_xattr_get(&env, child, &LU_BUF_NULL, XATTR_NAME_LOV);
	if (rc < 0)
		GOTO(out, rc);

	if (rc > 0) {
		struct lu_buf *lmm = NULL;

		if (lvblen < rc) {
			CERROR("%s: expected %d actual %d.\n",
				mdt_obd_name(mdt), rc, lvblen);
			GOTO(out, rc = -ERANGE);
		}

		lmm = &info->mti_buf;
		lmm->lb_buf = lvb;
		lmm->lb_len = rc;

		rc = mo_xattr_get(&env, child, lmm, XATTR_NAME_LOV);
		if (rc < 0)
			GOTO(out, rc);
	}

out:
	if (obj != NULL && !IS_ERR(obj))
		mdt_object_put(&env, obj);
	lu_env_fini(&env);
	RETURN(rc < 0 ? 0 : rc);
}

static int mdt_lvbo_free(struct ldlm_resource *res)
{
	if (IS_LQUOTA_RES(res)) {
		struct mdt_device	*mdt;

		mdt = ldlm_res_to_ns(res)->ns_lvbp;
		if (mdt->mdt_qmt_dev == NULL)
			return 0;

		/* call lvbo free function of quota master */
		return qmt_hdls.qmth_lvbo_free(mdt->mdt_qmt_dev, res);
	}

	return 0;
}

struct ldlm_valblock_ops mdt_lvbo = {
	.lvbo_init	= mdt_lvbo_init,
	.lvbo_update	= mdt_lvbo_update,
	.lvbo_size	= mdt_lvbo_size,
	.lvbo_fill	= mdt_lvbo_fill,
	.lvbo_free	= mdt_lvbo_free
};
