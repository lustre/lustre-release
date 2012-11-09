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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_lvb.c
 *
 * Author: Mikhail Pershin <tappro@whamcloud.com>
 * Author: Alexey Zhuravlev <bzzz@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

static int ofd_lvbo_free(struct ldlm_resource *res)
{
	if (res->lr_lvb_data)
		OBD_FREE(res->lr_lvb_data, res->lr_lvb_len);

	return 0;
}

/* Called with res->lr_lvb_sem held */
static int ofd_lvbo_init(struct ldlm_resource *res)
{
	struct ost_lvb		*lvb;
	struct ofd_device	*ofd;
	struct ofd_object	*fo;
	struct ofd_thread_info	*info;
	struct lu_env		 env;
	int			 rc = 0;

	ENTRY;

	LASSERT(res);
	LASSERT_MUTEX_LOCKED(&res->lr_lvb_mutex);

	if (res->lr_lvb_data != NULL)
		RETURN(0);

	ofd = ldlm_res_to_ns(res)->ns_lvbp;
	LASSERT(ofd != NULL);

	if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_OST_LVB))
		RETURN(-ENOMEM);

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);

	OBD_ALLOC_PTR(lvb);
	if (lvb == NULL)
		GOTO(out_env, rc = -ENOMEM);

	res->lr_lvb_data = lvb;
	res->lr_lvb_len = sizeof(*lvb);

	info = ofd_info_init(&env, NULL);
	ost_fid_from_resid(&info->fti_fid, &res->lr_name);
	fo = ofd_object_find(&env, ofd, &info->fti_fid);
	if (IS_ERR(fo))
		GOTO(out_lvb, rc = PTR_ERR(fo));

	rc = ofd_attr_get(&env, fo, &info->fti_attr);
	if (rc)
		GOTO(out_obj, rc);

	lvb->lvb_size = info->fti_attr.la_size;
	lvb->lvb_blocks = info->fti_attr.la_blocks;
	lvb->lvb_mtime = info->fti_attr.la_mtime;
	lvb->lvb_atime = info->fti_attr.la_atime;
	lvb->lvb_ctime = info->fti_attr.la_ctime;

	CDEBUG(D_DLMTRACE, "res: "DFID" initial lvb size: "LPU64", "
	       "mtime: "LPX64", blocks: "LPX64"\n",
	       PFID(&info->fti_fid), lvb->lvb_size,
	       lvb->lvb_mtime, lvb->lvb_blocks);

	EXIT;
out_obj:
	ofd_object_put(&env, fo);
out_lvb:
	if (rc != 0)
		OST_LVB_SET_ERR(lvb->lvb_blocks, rc);
out_env:
	lu_env_fini(&env);
	/* Don't free lvb data on lookup error */
	return rc;
}

/* This will be called in two ways:
 *
 *   r != NULL : called by the DLM itself after a glimpse callback
 *   r == NULL : called by the ofd after a disk write
 *
 *   If 'increase_only' is true, don't allow values to move backwards.
 */
static int ofd_lvbo_update(struct ldlm_resource *res,
			   struct ptlrpc_request *req, int increase_only)
{
	struct ofd_device	*ofd;
	struct ofd_object	*fo;
	struct ofd_thread_info	*info;
	struct ost_lvb		*lvb;
	struct lu_env		 env;
	int			 rc = 0;

	ENTRY;

	LASSERT(res != NULL);

	ofd = ldlm_res_to_ns(res)->ns_lvbp;
	LASSERT(ofd != NULL);

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);

	info = ofd_info_init(&env, NULL);
	fid_extract_from_res_name(&info->fti_fid, &res->lr_name);

	lvb = res->lr_lvb_data;
	if (lvb == NULL) {
		CERROR("%s: no LVB data for "DFID"\n",
		       ofd_obd(ofd)->obd_name, PFID(&info->fti_fid));
		GOTO(out_env, rc = 0);
	}

	/* Update the LVB from the network message */
	if (req != NULL) {
		struct ost_lvb *rpc_lvb;
		bool lvb_type;

		if (req->rq_import != NULL)
			lvb_type = imp_connect_lvb_type(req->rq_import);
		else
			lvb_type = exp_connect_lvb_type(req->rq_export);

		if (!lvb_type) {
			struct ost_lvb_v1 *lvb_v1;

			lvb_v1 = req_capsule_server_swab_get(&req->rq_pill,
					&RMF_DLM_LVB, lustre_swab_ost_lvb_v1);
			if (lvb_v1 == NULL)
				goto disk_update;

			rpc_lvb = &info->fti_lvb;
			memcpy(rpc_lvb, lvb_v1, sizeof *lvb_v1);
			rpc_lvb->lvb_mtime_ns = 0;
			rpc_lvb->lvb_atime_ns = 0;
			rpc_lvb->lvb_ctime_ns = 0;
		} else {
			rpc_lvb = req_capsule_server_swab_get(&req->rq_pill,
							      &RMF_DLM_LVB,
							lustre_swab_ost_lvb);
			if (rpc_lvb == NULL)
				goto disk_update;
		}

		lock_res(res);
		if (rpc_lvb->lvb_size > lvb->lvb_size || !increase_only) {
			CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb size: "
			       LPU64" -> "LPU64"\n", PFID(&info->fti_fid),
			       lvb->lvb_size, rpc_lvb->lvb_size);
			lvb->lvb_size = rpc_lvb->lvb_size;
		}
		if (rpc_lvb->lvb_mtime > lvb->lvb_mtime || !increase_only) {
			CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb mtime: "
			       LPU64" -> "LPU64"\n", PFID(&info->fti_fid),
			       lvb->lvb_mtime, rpc_lvb->lvb_mtime);
			lvb->lvb_mtime = rpc_lvb->lvb_mtime;
		}
		if (rpc_lvb->lvb_atime > lvb->lvb_atime || !increase_only) {
			CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb atime: "
			       LPU64" -> "LPU64"\n", PFID(&info->fti_fid),
			       lvb->lvb_atime, rpc_lvb->lvb_atime);
			lvb->lvb_atime = rpc_lvb->lvb_atime;
		}
		if (rpc_lvb->lvb_ctime > lvb->lvb_ctime || !increase_only) {
			CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb ctime: "
			       LPU64" -> "LPU64"\n", PFID(&info->fti_fid),
			       lvb->lvb_ctime, rpc_lvb->lvb_ctime);
			lvb->lvb_ctime = rpc_lvb->lvb_ctime;
		}
		if (rpc_lvb->lvb_blocks > lvb->lvb_blocks || !increase_only) {
			CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb blocks: "
			       LPU64" -> "LPU64"\n", PFID(&info->fti_fid),
			       lvb->lvb_blocks, rpc_lvb->lvb_blocks);
			lvb->lvb_blocks = rpc_lvb->lvb_blocks;
		}
		unlock_res(res);
	}

disk_update:
	/* Update the LVB from the disk inode */
	ost_fid_from_resid(&info->fti_fid, &res->lr_name);
	fo = ofd_object_find(&env, ofd, &info->fti_fid);
	if (IS_ERR(fo))
		GOTO(out_env, rc = PTR_ERR(fo));

	rc = ofd_attr_get(&env, fo, &info->fti_attr);
	if (rc)
		GOTO(out_obj, rc);

	lock_res(res);
	if (info->fti_attr.la_size > lvb->lvb_size || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb size from disk: "
		       LPU64" -> %llu\n", PFID(&info->fti_fid),
		       lvb->lvb_size, info->fti_attr.la_size);
		lvb->lvb_size = info->fti_attr.la_size;
	}

	if (info->fti_attr.la_mtime >lvb->lvb_mtime || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb mtime from disk: "
		       LPU64" -> "LPU64"\n", PFID(&info->fti_fid),
		       lvb->lvb_mtime, info->fti_attr.la_mtime);
		lvb->lvb_mtime = info->fti_attr.la_mtime;
	}
	if (info->fti_attr.la_atime >lvb->lvb_atime || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb atime from disk: "
		       LPU64" -> "LPU64"\n", PFID(&info->fti_fid),
		       lvb->lvb_atime, info->fti_attr.la_atime);
		lvb->lvb_atime = info->fti_attr.la_atime;
	}
	if (info->fti_attr.la_ctime >lvb->lvb_ctime || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb ctime from disk: "
		       LPU64" -> "LPU64"\n", PFID(&info->fti_fid),
		       lvb->lvb_ctime, info->fti_attr.la_ctime);
		lvb->lvb_ctime = info->fti_attr.la_ctime;
	}
	if (info->fti_attr.la_blocks > lvb->lvb_blocks || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb blocks from disk: "
		       LPU64" -> %llu\n", PFID(&info->fti_fid), lvb->lvb_blocks,
		       (unsigned long long)info->fti_attr.la_blocks);
		lvb->lvb_blocks = info->fti_attr.la_blocks;
	}
	unlock_res(res);

out_obj:
	ofd_object_put(&env, fo);
out_env:
	lu_env_fini(&env);
	return rc;
}

static int ofd_lvbo_size(struct ldlm_lock *lock)
{
	if (lock->l_export != NULL && exp_connect_lvb_type(lock->l_export))
		return sizeof(struct ost_lvb);
	else
		return sizeof(struct ost_lvb_v1);
}

static int ofd_lvbo_fill(struct ldlm_lock *lock, void *buf, int buflen)
{
	struct ldlm_resource *res = lock->l_resource;
	int lvb_len;

	/* Former lvbo_init not allocate the "LVB". */
	if (unlikely(res->lr_lvb_len == 0))
		return 0;

	lvb_len = ofd_lvbo_size(lock);
	LASSERT(lvb_len <= res->lr_lvb_len);

	if (lvb_len > buflen)
		lvb_len = buflen;

	lock_res(res);
	memcpy(buf, res->lr_lvb_data, lvb_len);
	unlock_res(res);

	return lvb_len;
}

struct ldlm_valblock_ops ofd_lvbo = {
	.lvbo_init	= ofd_lvbo_init,
	.lvbo_update	= ofd_lvbo_update,
	.lvbo_free	= ofd_lvbo_free,
	.lvbo_size	= ofd_lvbo_size,
	.lvbo_fill	= ofd_lvbo_fill
};
