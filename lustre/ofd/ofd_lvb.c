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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ofd/ofd_lvb.c
 *
 * This file contains methods for OBD Filter Device (OFD)
 * Lock Value Block (LVB) operations.
 *
 * LVB is special opaque (to LDLM) data that is associated with an LDLM lock
 * and transferred from client to server and back. OFD LVBs are used to
 * maintain current object size/times.
 *
 * Author: Andreas Dilger <andreas.dilger@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <lustre_swab.h>
#include "ofd_internal.h"

/**
 * Implementation of ldlm_valblock_ops::lvbo_free for OFD.
 *
 * This function frees allocated LVB data if it associated with the given
 * LDLM resource.
 *
 * \param[in] res	LDLM resource
 *
 * \retval		0 on successful setup
 * \retval		negative value on error
 */
static int ofd_lvbo_free(struct ldlm_resource *res)
{
	if (res->lr_lvb_data)
		OBD_FREE(res->lr_lvb_data, res->lr_lvb_len);

	return 0;
}

/**
 * Implementation of ldlm_valblock_ops::lvbo_init for OFD.
 *
 * This function allocates and initializes new LVB data for the given
 * LDLM resource if it is not allocated yet. New LVB is filled with attributes
 * of the object associated with that resource. Function does nothing if LVB
 * for the given LDLM resource is allocated already.
 *
 * Called with res->lr_lvb_sem held.
 *
 * \param[in] lock	LDLM lock on resource
 *
 * \retval		0 on successful setup
 * \retval		negative value on error
 */
static int ofd_lvbo_init(struct ldlm_resource *res)
{
	struct ost_lvb		*lvb;
	struct ofd_device	*ofd;
	struct ofd_object	*fo;
	struct ofd_thread_info	*info;
	struct lu_env *env;
	int rc = 0;
	ENTRY;

	LASSERT(res);
	LASSERT(mutex_is_locked(&res->lr_lvb_mutex));

	if (res->lr_lvb_data != NULL)
		RETURN(0);

	ofd = ldlm_res_to_ns(res)->ns_lvbp;
	LASSERT(ofd != NULL);

	if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_OST_LVB))
		RETURN(-ENOMEM);

	env = lu_env_find();
	LASSERT(env);

	OBD_ALLOC_PTR(lvb);
	if (lvb == NULL)
		GOTO(out, rc = -ENOMEM);

	info = ofd_info(env);
	res->lr_lvb_data = lvb;
	res->lr_lvb_len = sizeof(*lvb);

	ost_fid_from_resid(&info->fti_fid, &res->lr_name,
			   ofd->ofd_lut.lut_lsd.lsd_osd_index);
	fo = ofd_object_find(env, ofd, &info->fti_fid);
	if (IS_ERR(fo))
		GOTO(out_lvb, rc = PTR_ERR(fo));

	rc = ofd_attr_get(env, fo, &info->fti_attr);
	if (rc) {
		struct ofd_seq		*oseq;
		__u64			 seq;

		/* Object could be recreated during the first
		 * CLEANUP_ORPHAN request. */
		if (rc == -ENOENT) {
			seq = fid_seq(&info->fti_fid);
			oseq = ofd_seq_load(env, ofd, fid_seq_is_idif(seq) ?
					    FID_SEQ_OST_MDT0 : seq);
			if (!IS_ERR_OR_NULL(oseq)) {
				if (!oseq->os_last_id_synced)
					rc = -EAGAIN;
				ofd_seq_put(env, oseq);
			}
		}
		GOTO(out_obj, rc);
	}

	lvb->lvb_size = info->fti_attr.la_size;
	lvb->lvb_blocks = info->fti_attr.la_blocks;
	lvb->lvb_mtime = info->fti_attr.la_mtime;
	lvb->lvb_atime = info->fti_attr.la_atime;
	lvb->lvb_ctime = info->fti_attr.la_ctime;

	if (fo->ofo_atime_ondisk == 0)
		fo->ofo_atime_ondisk = info->fti_attr.la_atime;

	CDEBUG(D_DLMTRACE,
	       "res: "DFID" initial LVB size: %llu, mtime: %#llx, atime: %#llx, ctime: %#llx, blocks: %#llx\n",
	       PFID(&info->fti_fid), lvb->lvb_size, lvb->lvb_mtime,
	       lvb->lvb_atime, lvb->lvb_ctime, lvb->lvb_blocks);

	info->fti_attr.la_valid = 0;

	EXIT;
out_obj:
	ofd_object_put(env, fo);
out_lvb:
	if (rc != 0)
		OST_LVB_SET_ERR(lvb->lvb_blocks, rc);
out:
	/* Don't free lvb data on lookup error */
	return rc;
}

/**
 * Implementation of ldlm_valblock_ops::lvbo_update for OFD.
 *
 * When a client generates a glimpse enqueue, it wants to get the current
 * file size and updated attributes for a stat() type operation, but these
 * attributes may be writeback cached on another client. The client with
 * the DLM extent lock at the highest offset is asked for its current
 * attributes via a glimpse callback on its extent lock, on the assumption
 * that it has the highest file size and the newest timestamps. The timestamps
 * are guaranteed to be correct if there is only a single writer on the file,
 * but may be slightly inaccurate if there are multiple concurrent writers on
 * the same object. In order to avoid race conditions between the glimpse AST
 * and the client cancelling the lock, ofd_lvbo_update() also updates
 * the attributes from the local object. If the last client hasn't done any
 * writes yet, or has already written its data and cancelled its lock before
 * it processed the glimpse, then the local inode will have more uptodate
 * information.
 *
 * This is called in two ways:
 *  \a req != NULL : called by the DLM itself after a glimpse callback
 *  \a req == NULL : called by the OFD after a disk write
 *
 * \param[in] lock		LDLM lock
 * \param[in] req		PTLRPC request
 * \param[in] increase_only	don't allow LVB values to decrease
 *
 * \retval		0 on successful setup
 * \retval		negative value on error
 */
static int ofd_lvbo_update(struct ldlm_resource *res, struct ldlm_lock *lock,
			   struct ptlrpc_request *req, int increase_only)
{
	struct ofd_thread_info *info;
	struct ofd_device *ofd;
	struct ofd_object *fo;
	struct ost_lvb	*lvb;
	const struct lu_env *env;
	int rc = 0;

	ENTRY;

	env = lu_env_find();
	LASSERT(env);
	info = ofd_info(env);
	LASSERT(res != NULL);

	ofd = ldlm_res_to_ns(res)->ns_lvbp;
	LASSERT(ofd != NULL);

	fid_extract_from_res_name(&info->fti_fid, &res->lr_name);

	lvb = res->lr_lvb_data;
	if (lvb == NULL) {
		CERROR("%s: no LVB data for "DFID"\n",
		       ofd_name(ofd), PFID(&info->fti_fid));
		GOTO(out, rc = 0);
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
			       "%llu -> %llu\n", PFID(&info->fti_fid),
			       lvb->lvb_size, rpc_lvb->lvb_size);
			lvb->lvb_size = rpc_lvb->lvb_size;
		}
		if (rpc_lvb->lvb_mtime > lvb->lvb_mtime || !increase_only) {
			CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb mtime: "
			       "%llu -> %llu\n", PFID(&info->fti_fid),
			       lvb->lvb_mtime, rpc_lvb->lvb_mtime);
			lvb->lvb_mtime = rpc_lvb->lvb_mtime;
		}
		if (rpc_lvb->lvb_atime > lvb->lvb_atime || !increase_only) {
			CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb atime: "
			       "%llu -> %llu\n", PFID(&info->fti_fid),
			       lvb->lvb_atime, rpc_lvb->lvb_atime);
			lvb->lvb_atime = rpc_lvb->lvb_atime;
		}
		if (rpc_lvb->lvb_ctime > lvb->lvb_ctime || !increase_only) {
			CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb ctime: "
			       "%llu -> %llu\n", PFID(&info->fti_fid),
			       lvb->lvb_ctime, rpc_lvb->lvb_ctime);
			lvb->lvb_ctime = rpc_lvb->lvb_ctime;
		}
		if (rpc_lvb->lvb_blocks > lvb->lvb_blocks || !increase_only) {
			CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb blocks: "
			       "%llu -> %llu\n", PFID(&info->fti_fid),
			       lvb->lvb_blocks, rpc_lvb->lvb_blocks);
			lvb->lvb_blocks = rpc_lvb->lvb_blocks;
		}
		unlock_res(res);
	}

disk_update:
	/* Update the LVB from the disk inode */
	ost_fid_from_resid(&info->fti_fid, &res->lr_name,
			   ofd->ofd_lut.lut_lsd.lsd_osd_index);
	fo = ofd_object_find(env, ofd, &info->fti_fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));

	rc = ofd_attr_get(env, fo, &info->fti_attr);
	if (rc)
		GOTO(out_obj, rc);

	lock_res(res);
	if (info->fti_attr.la_size > lvb->lvb_size || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb size from disk: "
		       "%llu -> %llu\n", PFID(&info->fti_fid),
		       lvb->lvb_size, info->fti_attr.la_size);
		lvb->lvb_size = info->fti_attr.la_size;
	}

	if (info->fti_attr.la_mtime >lvb->lvb_mtime || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb mtime from disk: "
		       "%llu -> %llu\n", PFID(&info->fti_fid),
		       lvb->lvb_mtime, info->fti_attr.la_mtime);
		lvb->lvb_mtime = info->fti_attr.la_mtime;
	}
	if (info->fti_attr.la_atime >lvb->lvb_atime || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb atime from disk: "
		       "%llu -> %llu\n", PFID(&info->fti_fid),
		       lvb->lvb_atime, info->fti_attr.la_atime);
		lvb->lvb_atime = info->fti_attr.la_atime;
	}
	if (info->fti_attr.la_ctime >lvb->lvb_ctime || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb ctime from disk: "
		       "%llu -> %llu\n", PFID(&info->fti_fid),
		       lvb->lvb_ctime, info->fti_attr.la_ctime);
		lvb->lvb_ctime = info->fti_attr.la_ctime;
	}
	if (info->fti_attr.la_blocks > lvb->lvb_blocks || !increase_only) {
		CDEBUG(D_DLMTRACE, "res: "DFID" updating lvb blocks from disk: "
		       "%llu -> %llu\n", PFID(&info->fti_fid), lvb->lvb_blocks,
		       (unsigned long long)info->fti_attr.la_blocks);
		lvb->lvb_blocks = info->fti_attr.la_blocks;
	}
	unlock_res(res);

	info->fti_attr.la_valid = 0;
out_obj:
	ofd_object_put(env, fo);
out:
	return rc;
}

/**
 * Implementation of ldlm_valblock_ops::lvbo_size for OFD.
 *
 * This function returns size of LVB data so appropriate RPC size will be
 * reserved. This is used for compatibility needs between server and client
 * of different Lustre versions.
 *
 * \param[in] lock	LDLM lock
 *
 * \retval		size of LVB data
 */
static int ofd_lvbo_size(struct ldlm_lock *lock)
{
	if (lock->l_export != NULL && exp_connect_lvb_type(lock->l_export))
		return sizeof(struct ost_lvb);
	else
		return sizeof(struct ost_lvb_v1);
}

/**
 * Implementation of ldlm_valblock_ops::lvbo_fill for OFD.
 *
 * This function is called to fill the given RPC buffer \a buf with LVB data
 *
 * \param[in] env	execution environment
 * \param[in] lock	LDLM lock
 * \param[in] buf	RPC buffer to fill
 * \param[in] buflen	buffer length
 *
 * \retval		size of LVB data written into \a buf buffer
 */
static int ofd_lvbo_fill(struct ldlm_lock *lock, void *buf, int *buflen)
{
	struct ldlm_resource *res = lock->l_resource;
	int lvb_len;

	/* Former lvbo_init not allocate the "LVB". */
	if (unlikely(res->lr_lvb_len == 0))
		return 0;

	lvb_len = ofd_lvbo_size(lock);
	LASSERT(lvb_len <= res->lr_lvb_len);

	if (lvb_len > *buflen)
		lvb_len = *buflen;

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
