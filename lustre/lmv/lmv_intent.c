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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LMV
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/math64.h>
#include <linux/seq_file.h>
#include <linux/namei.h>
#include <lustre_intent.h>

#include <obd_support.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <lustre_mdc.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "lmv_internal.h"

static int lmv_intent_remote(struct obd_export *exp, struct lookup_intent *it,
			     const struct lu_fid *parent_fid,
			     struct ptlrpc_request **reqp,
			     ldlm_blocking_callback cb_blocking,
			     __u64 extra_lock_flags,
			     const char *secctx_name, __u32 secctx_name_size)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lmv_obd		*lmv = &obd->u.lmv;
	struct ptlrpc_request	*req = NULL;
	struct lustre_handle	plock;
	struct md_op_data	*op_data;
	struct lmv_tgt_desc	*tgt;
	struct mdt_body		*body;
	int			pmode;
	int			rc = 0;
	ENTRY;

	body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
	if (body == NULL)
		RETURN(-EPROTO);

	LASSERT((body->mbo_valid & OBD_MD_MDS));

	/*
	 * We got LOOKUP lock, but we really need attrs.
	 */
	pmode = it->it_lock_mode;
	if (pmode) {
		plock.cookie = it->it_lock_handle;
		it->it_lock_mode = 0;
		it->it_request = NULL;
	}

	LASSERT(fid_is_sane(&body->mbo_fid1));

	tgt = lmv_find_target(lmv, &body->mbo_fid1);
	if (IS_ERR(tgt))
		GOTO(out, rc = PTR_ERR(tgt));

	OBD_ALLOC_PTR(op_data);
	if (op_data == NULL)
		GOTO(out, rc = -ENOMEM);

	op_data->op_fid1 = body->mbo_fid1;
	/* Sent the parent FID to the remote MDT */
	if (parent_fid != NULL) {
		/* The parent fid is only for remote open to
		 * check whether the open is from OBF,
		 * see mdt_cross_open */
		LASSERT(it->it_op & IT_OPEN);
		op_data->op_fid2 = *parent_fid;
	}

	op_data->op_bias = MDS_CROSS_REF;
	CDEBUG(D_INODE, "REMOTE_INTENT with fid="DFID" -> mds #%u\n",
	       PFID(&body->mbo_fid1), tgt->ltd_idx);

	/* ask for security context upon intent */
	if (it->it_op & (IT_LOOKUP | IT_GETATTR | IT_OPEN) &&
	    secctx_name_size != 0 && secctx_name != NULL) {
		op_data->op_file_secctx_name = secctx_name;
		op_data->op_file_secctx_name_size = secctx_name_size;
		CDEBUG(D_SEC, "'%.*s' is security xattr to fetch for "
		       DFID"\n",
		       secctx_name_size, secctx_name, PFID(&body->mbo_fid1));
	}

	rc = md_intent_lock(tgt->ltd_exp, op_data, it, &req, cb_blocking,
			    extra_lock_flags);
        if (rc)
                GOTO(out_free_op_data, rc);

	/*
	 * LLite needs LOOKUP lock to track dentry revocation in order to
	 * maintain dcache consistency. Thus drop UPDATE|PERM lock here
	 * and put LOOKUP in request.
	 */
	if (it->it_lock_mode != 0) {
		it->it_remote_lock_handle =
					it->it_lock_handle;
		it->it_remote_lock_mode = it->it_lock_mode;
	}

	if (pmode) {
		it->it_lock_handle = plock.cookie;
		it->it_lock_mode = pmode;
	}

	EXIT;
out_free_op_data:
	OBD_FREE_PTR(op_data);
out:
	if (rc && pmode)
		ldlm_lock_decref(&plock, pmode);

	ptlrpc_req_finished(*reqp);
	*reqp = req;
	return rc;
}

int lmv_revalidate_slaves(struct obd_export *exp,
			  const struct lmv_stripe_md *lsm,
			  ldlm_blocking_callback cb_blocking,
			  int extra_lock_flags)
{
	struct obd_device *obd = exp->exp_obd;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct ptlrpc_request *req = NULL;
	struct mdt_body *body;
	struct md_op_data *op_data;
	int i;
	int valid_stripe_count = 0;
	int rc = 0;

	ENTRY;

	/**
	 * revalidate slaves has some problems, temporarily return,
	 * we may not need that
	 */
	OBD_ALLOC_PTR(op_data);
	if (op_data == NULL)
		RETURN(-ENOMEM);

	/**
	 * Loop over the stripe information, check validity and update them
	 * from MDS if needed.
	 */
	for (i = 0; i < lsm->lsm_md_stripe_count; i++) {
		struct lu_fid		fid;
		struct lookup_intent	it = { .it_op = IT_GETATTR };
		struct lustre_handle	*lockh = NULL;
		struct lmv_tgt_desc	*tgt = NULL;
		struct inode		*inode;

		fid = lsm->lsm_md_oinfo[i].lmo_fid;
		inode = lsm->lsm_md_oinfo[i].lmo_root;

		if (!inode)
			continue;

		/*
		 * Prepare op_data for revalidating. Note that @fid2 shluld be
		 * defined otherwise it will go to server and take new lock
		 * which is not needed here.
		 */
		memset(op_data, 0, sizeof(*op_data));
		op_data->op_fid1 = fid;
		op_data->op_fid2 = fid;
		/* shard revalidate only needs to fetch attributes and UPDATE
		 * lock, which is similar to the bottom half of remote object
		 * getattr, set this flag so that MDT skips checking whether
		 * it's remote object.
		 */
		op_data->op_bias = MDS_CROSS_REF;

		tgt = lmv_get_target(lmv, lsm->lsm_md_oinfo[i].lmo_mds, NULL);
		if (IS_ERR(tgt))
			GOTO(cleanup, rc = PTR_ERR(tgt));

		CDEBUG(D_INODE, "Revalidate slave "DFID" -> mds #%u\n",
		       PFID(&fid), tgt->ltd_idx);

		if (req != NULL) {
			ptlrpc_req_finished(req);
			req = NULL;
		}

		rc = md_intent_lock(tgt->ltd_exp, op_data, &it, &req,
				    cb_blocking, extra_lock_flags);
		if (rc == -ENOENT) {
			/* skip stripe is not exists */
			rc = 0;
			continue;
		}

		if (rc < 0)
			GOTO(cleanup, rc);

		lockh = (struct lustre_handle *)&it.it_lock_handle;
		if (rc > 0 && req == NULL) {
			/* slave inode is still valid */
			CDEBUG(D_INODE, "slave "DFID" is still valid.\n",
			       PFID(&fid));
			rc = 0;
		} else {
			/* refresh slave from server */
			body = req_capsule_server_get(&req->rq_pill,
						      &RMF_MDT_BODY);
			if (body == NULL) {
				if (it.it_lock_mode && lockh) {
					ldlm_lock_decref(lockh,
						 it.it_lock_mode);
					it.it_lock_mode = 0;
				}
				GOTO(cleanup, rc = -ENOENT);
			}

			i_size_write(inode, body->mbo_size);
			inode->i_blocks = body->mbo_blocks;
			set_nlink(inode, body->mbo_nlink);
			inode->i_atime.tv_sec = body->mbo_atime;
			inode->i_ctime.tv_sec = body->mbo_ctime;
			inode->i_mtime.tv_sec = body->mbo_mtime;
		}

		md_set_lock_data(tgt->ltd_exp, lockh, inode, NULL);
		if (it.it_lock_mode != 0 && lockh != NULL) {
			ldlm_lock_decref(lockh, it.it_lock_mode);
			it.it_lock_mode = 0;
		}

		valid_stripe_count++;
	}

cleanup:
	if (req != NULL)
		ptlrpc_req_finished(req);

	/* if all stripes are invalid, return -ENOENT to notify user */
	if (!rc && !valid_stripe_count)
		rc = -ENOENT;

	OBD_FREE_PTR(op_data);
	RETURN(rc);
}

/*
 * IT_OPEN is intended to open (and create, possible) an object. Parent (pid)
 * may be split dir.
 */
static int lmv_intent_open(struct obd_export *exp, struct md_op_data *op_data,
			   struct lookup_intent *it,
			   struct ptlrpc_request **reqp,
			   ldlm_blocking_callback cb_blocking,
			   __u64 extra_lock_flags)
{
	struct obd_device *obd = exp->exp_obd;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lmv_tgt_desc *tgt;
	struct mdt_body *body;
	__u64 flags = it->it_flags;
	int rc;

	ENTRY;

	if ((it->it_op & IT_CREAT) && !(flags & MDS_OPEN_BY_FID)) {
		/* don't allow create under dir with bad hash */
		if (lmv_is_dir_bad_hash(op_data->op_mea1))
			RETURN(-EBADF);

		if (lmv_is_dir_migrating(op_data->op_mea1)) {
			if (flags & O_EXCL) {
				/*
				 * open(O_CREAT | O_EXCL) needs to check
				 * existing name, which should be done on both
				 * old and new layout, to avoid creating new
				 * file under old layout, check old layout on
				 * client side.
				 */
				tgt = lmv_locate_tgt(lmv, op_data,
						     &op_data->op_fid1);
				if (IS_ERR(tgt))
					RETURN(PTR_ERR(tgt));

				rc = md_getattr_name(tgt->ltd_exp, op_data,
						     reqp);
				if (!rc) {
					ptlrpc_req_finished(*reqp);
					*reqp = NULL;
					RETURN(-EEXIST);
				}

				if (rc != -ENOENT)
					RETURN(rc);

				op_data->op_post_migrate = true;
			} else {
				/*
				 * open(O_CREAT) will be sent to MDT in old
				 * layout first, to avoid creating new file
				 * under old layout, clear O_CREAT.
				 */
				it->it_flags &= ~O_CREAT;
			}
		}
	}

retry:
	if (it->it_flags & MDS_OPEN_BY_FID) {
		LASSERT(fid_is_sane(&op_data->op_fid2));

		/* for striped directory, we can't know parent stripe fid
		 * without name, but we can set it to child fid, and MDT
		 * will obtain it from linkea in open in such case. */
		if (op_data->op_mea1 != NULL)
			op_data->op_fid1 = op_data->op_fid2;

		tgt = lmv_find_target(lmv, &op_data->op_fid2);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));

		op_data->op_mds = tgt->ltd_idx;
	} else {
		LASSERT(fid_is_sane(&op_data->op_fid1));
		LASSERT(fid_is_zero(&op_data->op_fid2));
		LASSERT(op_data->op_name != NULL);

		tgt = lmv_locate_tgt(lmv, op_data, &op_data->op_fid1);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));
	}

	/* If it is ready to open the file by FID, do not need
	 * allocate FID at all, otherwise it will confuse MDT */
	if ((it->it_op & IT_CREAT) && !(it->it_flags & MDS_OPEN_BY_FID)) {
		/*
		 * For lookup(IT_CREATE) cases allocate new fid and setup FLD
		 * for it.
		 */
		rc = lmv_fid_alloc(NULL, exp, &op_data->op_fid2, op_data);
		if (rc != 0)
			RETURN(rc);
	}

	CDEBUG(D_INODE, "OPEN_INTENT with fid1="DFID", fid2="DFID","
	       " name='%s' -> mds #%u\n", PFID(&op_data->op_fid1),
	       PFID(&op_data->op_fid2), op_data->op_name, tgt->ltd_idx);

	rc = md_intent_lock(tgt->ltd_exp, op_data, it, reqp, cb_blocking,
			    extra_lock_flags);
	if (rc != 0)
		RETURN(rc);
	/*
	 * Nothing is found, do not access body->fid1 as it is zero and thus
	 * pointless.
	 */
	if ((it->it_disposition & DISP_LOOKUP_NEG) &&
	    !(it->it_disposition & DISP_OPEN_CREATE) &&
	    !(it->it_disposition & DISP_OPEN_OPEN)) {
		if (!(it->it_flags & MDS_OPEN_BY_FID) &&
		    lmv_dir_retry_check_update(op_data)) {
			ptlrpc_req_finished(*reqp);
			it->it_request = NULL;
			it->it_disposition = 0;
			*reqp = NULL;

			it->it_flags = flags;
			fid_zero(&op_data->op_fid2);
			goto retry;
		}

		RETURN(rc);
	}

	body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
	if (body == NULL)
		RETURN(-EPROTO);

	/* Not cross-ref case, just get out of here. */
	if (unlikely((body->mbo_valid & OBD_MD_MDS))) {
		rc = lmv_intent_remote(exp, it, &op_data->op_fid1, reqp,
				       cb_blocking, extra_lock_flags,
				       op_data->op_file_secctx_name,
				       op_data->op_file_secctx_name_size);
		if (rc != 0)
			RETURN(rc);

		body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
		if (body == NULL)
			RETURN(-EPROTO);
	}

	RETURN(rc);
}

/*
 * Handler for: getattr, lookup and revalidate cases.
 */
static int
lmv_intent_lookup(struct obd_export *exp, struct md_op_data *op_data,
		  struct lookup_intent *it, struct ptlrpc_request **reqp,
		  ldlm_blocking_callback cb_blocking,
		  __u64 extra_lock_flags)
{
	struct obd_device *obd = exp->exp_obd;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lmv_tgt_desc *tgt = NULL;
	struct mdt_body *body;
	int rc;
	ENTRY;

retry:
	if (op_data->op_flags & MF_GETATTR_BY_FID) {
		/* getattr by FID, replace fid1 with stripe FID,
		 * NB, don't replace if name is "/", because it may be a subtree
		 * mount, and if it's a striped directory, fid1 will be replaced
		 * to stripe FID by hash, while fid2 is master object FID, which
		 * will be treated as a remote object if the two FIDs are
		 * located on different MDTs, and LOOKUP lock can't be fetched.
		 */
		LASSERT(op_data->op_name);
		if (op_data->op_namelen != 1 ||
		    strncmp(op_data->op_name, "/", 1) != 0) {
			tgt = lmv_locate_tgt(lmv, op_data, &op_data->op_fid1);
			if (IS_ERR(tgt))
				RETURN(PTR_ERR(tgt));
		}

		/* name is used to locate stripe target, clear it here
		 * to avoid packing name in request, so that MDS knows
		 * it's getattr by FID.
		 */
		op_data->op_name = NULL;
		op_data->op_namelen = 0;

		/* getattr request is sent to MDT where fid2 inode is */
		tgt = lmv_find_target(lmv, &op_data->op_fid2);
	} else if (op_data->op_name) {
		/* getattr by name */
		tgt = lmv_locate_tgt(lmv, op_data, &op_data->op_fid1);
		if (!fid_is_sane(&op_data->op_fid2))
			fid_zero(&op_data->op_fid2);
	} else {
		/* old way to getattr by FID, parent FID not packed */
		tgt = lmv_find_target(lmv, &op_data->op_fid1);
	}
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	CDEBUG(D_INODE, "LOOKUP_INTENT with fid1="DFID", fid2="DFID
	       ", name='%s' -> mds #%u\n",
	       PFID(&op_data->op_fid1), PFID(&op_data->op_fid2),
	       op_data->op_name ? op_data->op_name : "<NULL>",
	       tgt->ltd_idx);

	op_data->op_bias &= ~MDS_CROSS_REF;

	rc = md_intent_lock(tgt->ltd_exp, op_data, it, reqp, cb_blocking,
			    extra_lock_flags);
	if (rc < 0)
		RETURN(rc);

	if (*reqp == NULL) {
		/* If RPC happens, lsm information will be revalidated
		 * during update_inode process (see ll_update_lsm_md) */
		if (op_data->op_mea2 != NULL) {
			rc = lmv_revalidate_slaves(exp, op_data->op_mea2,
						   cb_blocking,
						   extra_lock_flags);
			if (rc != 0)
				RETURN(rc);
		}
		RETURN(rc);
	} else if (it_disposition(it, DISP_LOOKUP_NEG) &&
		   lmv_dir_retry_check_update(op_data)) {
		ptlrpc_req_finished(*reqp);
		it->it_request = NULL;
		it->it_disposition = 0;
		*reqp = NULL;

		goto retry;
	}

	if (!it_has_reply_body(it))
		RETURN(0);

	/*
	 * MDS has returned success. Probably name has been resolved in
	 * remote inode. Let's check this.
	 */
	body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
	if (body == NULL)
		RETURN(-EPROTO);

	/* Not cross-ref case, just get out of here. */
	if (unlikely((body->mbo_valid & OBD_MD_MDS))) {
		rc = lmv_intent_remote(exp, it, NULL, reqp, cb_blocking,
				       extra_lock_flags,
				       op_data->op_file_secctx_name,
				       op_data->op_file_secctx_name_size);
		if (rc != 0)
			RETURN(rc);
		body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
		if (body == NULL)
			RETURN(-EPROTO);
	}

	RETURN(rc);
}

int lmv_intent_lock(struct obd_export *exp, struct md_op_data *op_data,
		    struct lookup_intent *it, struct ptlrpc_request **reqp,
		    ldlm_blocking_callback cb_blocking,
		    __u64 extra_lock_flags)
{
	int rc;
	ENTRY;

	LASSERT(it != NULL);
	LASSERT(fid_is_sane(&op_data->op_fid1));

	CDEBUG(D_INODE, "INTENT LOCK '%s' for "DFID" '%.*s' on "DFID"\n",
		LL_IT2STR(it), PFID(&op_data->op_fid2),
		(int)op_data->op_namelen, op_data->op_name,
		PFID(&op_data->op_fid1));

	if (it->it_op & (IT_LOOKUP | IT_GETATTR | IT_LAYOUT | IT_GETXATTR))
		rc = lmv_intent_lookup(exp, op_data, it, reqp, cb_blocking,
				       extra_lock_flags);
	else if (it->it_op & IT_OPEN)
		rc = lmv_intent_open(exp, op_data, it, reqp, cb_blocking,
				     extra_lock_flags);
	else
		LBUG();

	if (rc < 0) {
		struct lustre_handle lock_handle;

		if (it->it_lock_mode != 0) {
			lock_handle.cookie = it->it_lock_handle;
			ldlm_lock_decref_and_cancel(&lock_handle,
						    it->it_lock_mode);
		}

		it->it_lock_handle = 0;
		it->it_lock_mode = 0;

		if (it->it_remote_lock_mode != 0) {
			lock_handle.cookie = it->it_remote_lock_handle;
			ldlm_lock_decref_and_cancel(&lock_handle,
						    it->it_remote_lock_mode);
		}

		it->it_remote_lock_handle = 0;
		it->it_remote_lock_mode = 0;
	}

	RETURN(rc);
}
