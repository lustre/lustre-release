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
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdt/mdt_recovery.c
 *
 * Lustre Metadata Target (mdt) recovery-related methods
 *
 * Author: Huang Hua <huanghua@clusterfs.com>
 * Author: Pershin Mike <tappro@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

struct lu_buf *mdt_buf(const struct lu_env *env, void *area, ssize_t len)
{
        struct lu_buf *buf;
        struct mdt_thread_info *mti;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        buf = &mti->mti_buf;
        buf->lb_buf = area;
        buf->lb_len = len;
        return buf;
}

const struct lu_buf *mdt_buf_const(const struct lu_env *env,
                                   const void *area, ssize_t len)
{
        struct lu_buf *buf;
        struct mdt_thread_info *mti;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        buf = &mti->mti_buf;

        buf->lb_buf = (void *)area;
        buf->lb_len = len;
        return buf;
}

/*
 * last_rcvd & last_committed update callbacks
 */
extern struct lu_context_key mdt_thread_key;

/* This callback notifies MDT that transaction was done. This is needed by
 * mdt_save_lock() only. It is similar to new target code and will be removed
 * as mdt_save_lock() will be converted to use target structures */
static int mdt_txn_stop_cb(const struct lu_env *env,
                           struct thandle *txn, void *cookie)
{
	struct mdt_thread_info	*mti;

	mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
	LASSERT(mti);

	if (mti->mti_has_trans)
		CDEBUG(D_INFO, "More than one transaction\n");
	else
		mti->mti_has_trans = 1;
	return 0;
}

int mdt_fs_setup(const struct lu_env *env, struct mdt_device *mdt,
		 struct obd_device *obd, struct lustre_sb_info *lsi)
{
	int rc = 0;

	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_FS_SETUP))
		RETURN(-ENOENT);

	/* prepare transactions callbacks */
	mdt->mdt_txn_cb.dtc_txn_start = NULL;
	mdt->mdt_txn_cb.dtc_txn_stop = mdt_txn_stop_cb;
	mdt->mdt_txn_cb.dtc_txn_commit = NULL;
	mdt->mdt_txn_cb.dtc_cookie = NULL;
	mdt->mdt_txn_cb.dtc_tag = LCT_MD_THREAD;
	INIT_LIST_HEAD(&mdt->mdt_txn_cb.dtc_linkage);

	dt_txn_callback_add(mdt->mdt_bottom, &mdt->mdt_txn_cb);

	RETURN(rc);
}

void mdt_fs_cleanup(const struct lu_env *env, struct mdt_device *mdt)
{
        ENTRY;

        /* Remove transaction callback */
        dt_txn_callback_del(mdt->mdt_bottom, &mdt->mdt_txn_cb);
        EXIT;
}

/* reconstruction code */
static void mdt_steal_ack_locks(struct ptlrpc_request *req)
{
	struct ptlrpc_service_part *svcpt;
	struct obd_export *exp = req->rq_export;
	struct list_head *tmp;
	struct ptlrpc_reply_state *rs;
	int i;

	/* CAVEAT EMPTOR: spinlock order */
	spin_lock(&exp->exp_lock);
	list_for_each(tmp, &exp->exp_outstanding_replies) {
		rs = list_entry(tmp, struct ptlrpc_reply_state,
				    rs_exp_list);

		if (rs->rs_xid != req->rq_xid)
			continue;

		if (rs->rs_opc != lustre_msg_get_opc(req->rq_reqmsg))
			CERROR("%s: Resent req xid %llu has mismatched opc: "
			       "new %d old %d\n", exp->exp_obd->obd_name,
			       req->rq_xid, lustre_msg_get_opc(req->rq_reqmsg),
			       rs->rs_opc);

		svcpt = rs->rs_svcpt;

		CDEBUG(D_HA, "Stealing %d locks from rs %p x%lld.t%lld"
		       " o%d NID %s\n",
		       rs->rs_nlocks, rs,
		       rs->rs_xid, rs->rs_transno, rs->rs_opc,
		       libcfs_nid2str(exp->exp_connection->c_peer.nid));

		spin_lock(&svcpt->scp_rep_lock);
		list_del_init(&rs->rs_exp_list);

		spin_lock(&rs->rs_lock);
		for (i = 0; i < rs->rs_nlocks; i++)
			ptlrpc_save_lock(req, &rs->rs_locks[i],
					 rs->rs_modes[i], rs->rs_no_ack,
					 rs->rs_convert_lock);
		rs->rs_nlocks = 0;

		DEBUG_REQ(D_HA, req, "stole locks for");
		ptlrpc_schedule_difficult_reply(rs);
		spin_unlock(&rs->rs_lock);

		spin_unlock(&svcpt->scp_rep_lock);
		break;
	}
	spin_unlock(&exp->exp_lock);

	/* if exp_disconnected, decref stolen locks */
	if (exp->exp_disconnected) {
		rs = req->rq_reply_state;

		for (i = 0; i < rs->rs_nlocks; i++)
			ldlm_lock_decref(&rs->rs_locks[i], rs->rs_modes[i]);

		rs->rs_nlocks = 0;
	}
}

__u64 mdt_req_from_lrd(struct ptlrpc_request *req,
		       struct tg_reply_data *trd)
{
	struct lsd_reply_data *lrd;

	LASSERT(trd != NULL);
	lrd = &trd->trd_reply;

	DEBUG_REQ(D_HA, req, "restoring transno %lld/status %d",
		  lrd->lrd_transno, lrd->lrd_result);

	req->rq_transno = lrd->lrd_transno;
	req->rq_status = lrd->lrd_result;

	lustre_msg_set_versions(req->rq_repmsg, trd->trd_pre_versions);

	if (req->rq_status != 0)
		req->rq_transno = 0;
	lustre_msg_set_transno(req->rq_repmsg, req->rq_transno);
	lustre_msg_set_status(req->rq_repmsg, req->rq_status);

	DEBUG_REQ(D_RPCTRACE, req, "restoring transno %lld/status %d",
		  req->rq_transno, req->rq_status);

	mdt_steal_ack_locks(req);

	return lrd->lrd_data;
}


void mdt_reconstruct_generic(struct mdt_thread_info *mti,
			     struct mdt_lock_handle *lhc)
{
	struct ptlrpc_request *req = mdt_info_req(mti);

	mdt_req_from_lrd(req, mti->mti_reply_data);
	return;
}

/**
 * Generate fake attributes for a non-existing object
 *
 * While the client was waiting for the reply, the original transaction
 * got committed and corresponding rep-ack lock got released, then another
 * client was able to destroy the object. But we still need to send some
 * attributes back. So we fake them and set nlink=0, so the client will
 * be able to detect a non-existing object and drop it from the cache
 * immediately.
 *
 * \param[out] ma	attributes to fill
 */
static void mdt_fake_ma(struct md_attr *ma)
{
	ma->ma_valid = MA_INODE;
	memset(&ma->ma_attr, 0, sizeof(ma->ma_attr));
	ma->ma_attr.la_valid = LA_NLINK;
	ma->ma_attr.la_mode = S_IFREG;
}

static void mdt_reconstruct_create(struct mdt_thread_info *mti,
                                   struct mdt_lock_handle *lhc)
{
	struct ptlrpc_request  *req = mdt_info_req(mti);
	struct obd_export *exp = req->rq_export;
	struct mdt_device *mdt = mti->mti_mdt;
	struct mdt_object *child;
	struct mdt_body *body;
	int rc;

	mdt_req_from_lrd(req, mti->mti_reply_data);
	if (req->rq_status)
		return;

	/* if no error, so child was created with requested fid */
	child = mdt_object_find(mti->mti_env, mdt, mti->mti_rr.rr_fid2);
	if (IS_ERR(child)) {
		rc = PTR_ERR(child);
		LCONSOLE_WARN("cannot lookup child "DFID": rc = %d; "
			      "evicting client %s with export %s\n",
			      PFID(mti->mti_rr.rr_fid2), rc,
			      obd_uuid2str(&exp->exp_client_uuid),
			      obd_export_nid2str(exp));
		mdt_export_evict(exp);
		RETURN_EXIT;
	}

        body = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
        mti->mti_attr.ma_need = MA_INODE;
        mti->mti_attr.ma_valid = 0;
	rc = mdt_attr_get_complex(mti, child, &mti->mti_attr);
	if (rc == -ENOENT) {
		mdt_fake_ma(&mti->mti_attr);
	} else if (rc == -EREMOTE) {
		/* object was created on remote server */
		if (!mdt_is_dne_client(exp))
			/* Return -EIO for old client */
			rc = -EIO;

		req->rq_status = rc;
		body->mbo_valid |= OBD_MD_MDS;
	}
	mdt_pack_attr2body(mti, body, &mti->mti_attr.ma_attr,
			   mdt_object_fid(child));
	mdt_object_put(mti->mti_env, child);
}

static void mdt_reconstruct_setattr(struct mdt_thread_info *mti,
                                    struct mdt_lock_handle *lhc)
{
        struct ptlrpc_request  *req = mdt_info_req(mti);
        struct obd_export *exp = req->rq_export;
        struct mdt_device *mdt = mti->mti_mdt;
        struct mdt_object *obj;
        struct mdt_body *body;
	int rc;

	mdt_req_from_lrd(req, mti->mti_reply_data);
	if (req->rq_status)
		return;

        body = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
        obj = mdt_object_find(mti->mti_env, mdt, mti->mti_rr.rr_fid1);
	if (IS_ERR(obj)) {
		rc = PTR_ERR(obj);
		LCONSOLE_WARN("cannot lookup "DFID": rc = %d; "
			      "evicting client %s with export %s\n",
			      PFID(mti->mti_rr.rr_fid1), rc,
			      obd_uuid2str(&exp->exp_client_uuid),
			      obd_export_nid2str(exp));
		mdt_export_evict(exp);
		RETURN_EXIT;
	}

        mti->mti_attr.ma_need = MA_INODE;
        mti->mti_attr.ma_valid = 0;

	rc = mdt_attr_get_complex(mti, obj, &mti->mti_attr);
	if (rc == -ENOENT)
		mdt_fake_ma(&mti->mti_attr);
        mdt_pack_attr2body(mti, body, &mti->mti_attr.ma_attr,
                           mdt_object_fid(obj));

	mdt_object_put(mti->mti_env, obj);
}

typedef void (*mdt_reconstructor)(struct mdt_thread_info *mti,
                                  struct mdt_lock_handle *lhc);

static mdt_reconstructor reconstructors[REINT_MAX] = {
        [REINT_SETATTR]  = mdt_reconstruct_setattr,
        [REINT_CREATE]   = mdt_reconstruct_create,
        [REINT_LINK]     = mdt_reconstruct_generic,
        [REINT_UNLINK]   = mdt_reconstruct_generic,
        [REINT_RENAME]   = mdt_reconstruct_generic,
        [REINT_OPEN]     = mdt_reconstruct_open,
	[REINT_SETXATTR] = mdt_reconstruct_generic,
	[REINT_RMENTRY]  = mdt_reconstruct_generic,
	[REINT_MIGRATE] = mdt_reconstruct_generic
};

void mdt_reconstruct(struct mdt_thread_info *mti,
                     struct mdt_lock_handle *lhc)
{
	mdt_reconstructor reconst;
        ENTRY;
	LASSERT(mti->mti_rr.rr_opcode < REINT_MAX &&
		(reconst = reconstructors[mti->mti_rr.rr_opcode]) != NULL);
	reconst(mti, lhc);
        EXIT;
}
