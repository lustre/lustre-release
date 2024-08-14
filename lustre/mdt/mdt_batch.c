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
 * Copyright (c) 2020, DDN Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * lustre/mdt/mdt_batch.c
 *
 * Batch Metadata Updating on the server (MDT)
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

#include <lustre_mds.h>
#include "mdt_internal.h"

static struct ldlm_callback_suite mdt_dlm_cbs = {
	.lcs_completion	= ldlm_server_completion_ast,
	.lcs_blocking	= tgt_blocking_ast,
	.lcs_glimpse	= ldlm_server_glimpse_ast
};

static int mdt_batch_unpack(struct mdt_thread_info *info, __u32 opc)
{
	int rc = 0;

	switch (opc) {
	case BUT_GETATTR:
		info->mti_dlm_req = req_capsule_client_get(info->mti_pill,
							   &RMF_DLM_REQ);
		if (info->mti_dlm_req == NULL)
			RETURN(-EFAULT);
		break;
	default:
		rc = -EOPNOTSUPP;
		CERROR("%s: Unexpected opcode %d: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), opc, rc);
		break;
	}

	RETURN(rc);
}

static int mdt_batch_pack_repmsg(struct mdt_thread_info *info)
{
	return 0;
}

typedef int (*mdt_batch_reconstructor)(struct tgt_session_info *tsi);

static mdt_batch_reconstructor reconstructors[BUT_LAST_OPC];

static int mdt_batch_reconstruct(struct tgt_session_info *tsi, long opc)
{
	mdt_batch_reconstructor reconst;
	int rc;

	ENTRY;

	if (opc >= BUT_LAST_OPC)
		RETURN(-EOPNOTSUPP);

	reconst = reconstructors[opc];
	LASSERT(reconst != NULL);
	rc = reconst(tsi);
	RETURN(rc);
}

static int mdt_batch_getattr(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = mdt_th_info(tsi->tsi_env);
	struct req_capsule *pill = &info->mti_sub_pill;
	int rc;

	ENTRY;

	rc = ldlm_handle_enqueue(info->mti_exp->exp_obd->obd_namespace,
				 pill, info->mti_dlm_req, &mdt_dlm_cbs);

	RETURN(rc);
}

/* Batch UpdaTe Request with a format known in advance */
#define TGT_BUT_HDL(flags, opc, fn)			\
[opc - BUT_FIRST_OPC] = {				\
	.th_name	= #opc,				\
	.th_fail_id	= 0,				\
	.th_opc		= opc,				\
	.th_flags	= flags,			\
	.th_act		= fn,				\
	.th_fmt		= &RQF_ ## opc,			\
	.th_version	= LUSTRE_MDS_VERSION,		\
	.th_hp		= NULL,				\
}

static struct tgt_handler mdt_batch_handlers[] = {
TGT_BUT_HDL(HAS_KEY | HAS_REPLY,	BUT_GETATTR,	mdt_batch_getattr),
};

static struct tgt_handler *mdt_batch_handler_find(__u32 opc)
{
	struct tgt_handler *h;

	h = NULL;
	if (opc >= BUT_FIRST_OPC && opc < BUT_LAST_OPC) {
		h = &mdt_batch_handlers[opc - BUT_FIRST_OPC];
		LASSERTF(h->th_opc == opc, "opcode mismatch %d != %d\n",
			 h->th_opc, opc);
	} else {
		h = NULL; /* unsupported opc */
	}
	return h;
}

int mdt_batch(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = tsi2mdt_info(tsi);
	struct req_capsule *pill = &info->mti_sub_pill;
	struct ptlrpc_request *req = tgt_ses_req(tsi);
	struct but_update_header *buh;
	struct but_update_buffer *bub = NULL;
	struct batch_update_reply *reply = NULL;
	struct ptlrpc_bulk_desc *desc = NULL;
	struct tg_reply_data *trd = NULL;
	struct lustre_msg *repmsg = NULL;
	bool need_reconstruct;
	__u32 handled_update_count = 0;
	__u32 update_buf_count;
	__u32 packed_replen;
	void **update_bufs;
	bool grown = false;
	int buh_size;
	int rc;
	int i;

	ENTRY;

	buh_size = req_capsule_get_size(&req->rq_pill, &RMF_BUT_HEADER,
					RCL_CLIENT);
	if (buh_size <= 0)
		RETURN(err_serious(-EPROTO));

	buh = req_capsule_client_get(&req->rq_pill, &RMF_BUT_HEADER);
	if (buh == NULL)
		RETURN(err_serious(-EPROTO));

	if (buh->buh_magic != BUT_HEADER_MAGIC) {
		CERROR("%s: invalid update header magic %x expect %x: "
		       "rc = %d\n", tgt_name(tsi->tsi_tgt), buh->buh_magic,
		       BUT_HEADER_MAGIC, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	update_buf_count = buh->buh_count;
	if (update_buf_count == 0)
		RETURN(err_serious(-EPROTO));

	OBD_ALLOC_PTR_ARRAY(update_bufs, update_buf_count);
	if (update_bufs == NULL)
		RETURN(err_serious(-ENOMEM));

	if (buh->buh_inline_length > 0) {
		update_bufs[0] = buh->buh_inline_data;
	} else {
		struct but_update_buffer *tmp;
		int page_count = 0;

		bub = req_capsule_client_get(&req->rq_pill, &RMF_BUT_BUF);
		if (bub == NULL)
			GOTO(out, rc = err_serious(-EPROTO));

		for (i = 0; i < update_buf_count; i++)
			/* First *and* last might be partial pages, hence +1 */
			page_count += DIV_ROUND_UP(bub[i].bub_size,
						   PAGE_SIZE) + 1;

		desc = ptlrpc_prep_bulk_exp(req, page_count,
					    PTLRPC_BULK_OPS_COUNT,
					    PTLRPC_BULK_GET_SINK,
					    MDS_BULK_PORTAL,
					    &ptlrpc_bulk_kiov_nopin_ops);
		if (desc == NULL)
			GOTO(out, rc = err_serious(-ENOMEM));

		tmp = bub;
		for (i = 0; i < update_buf_count; i++, tmp++) {
			if (tmp->bub_size >= OUT_MAXREQSIZE)
				GOTO(out, rc = err_serious(-EPROTO));

			OBD_ALLOC_LARGE(update_bufs[i], tmp->bub_size);
			if (update_bufs[i] == NULL)
				GOTO(out, rc = err_serious(-ENOMEM));

			desc->bd_frag_ops->add_iov_frag(desc, update_bufs[i],
							tmp->bub_size);
		}

		req->rq_bulk_write = 1;
		rc = sptlrpc_svc_prep_bulk(req, desc);
		if (rc != 0)
			GOTO(out, rc = err_serious(rc));

		rc = target_bulk_io(req->rq_export, desc);
		if (rc < 0)
			GOTO(out, rc = err_serious(rc));
	}

	req_capsule_set_size(&req->rq_pill, &RMF_BUT_REPLY, RCL_SERVER,
			     buh->buh_reply_size);
	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc != 0) {
		DEBUG_REQ(D_ERROR, req, "%s: Can't pack response: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		GOTO(out, rc);
	}

	/* Prepare the update reply buffer */
	reply = req_capsule_server_get(&req->rq_pill, &RMF_BUT_REPLY);
	if (reply == NULL)
		GOTO(out, rc = -EPROTO);

	reply->burp_magic = BUT_REPLY_MAGIC;
	packed_replen = sizeof(*reply);
	info->mti_batch_env = 1;
	info->mti_pill = pill;
	tsi->tsi_batch_env = true;

	OBD_ALLOC_PTR(trd);
	if (trd == NULL)
		GOTO(out, rc = -ENOMEM);

	need_reconstruct = tgt_check_resent(req, trd);
	/* Walk through sub requests in the batch request to execute them. */
	for (i = 0; i < update_buf_count; i++) {
		struct batch_update_request *bur;
		struct lustre_msg *reqmsg = NULL;
		struct tgt_handler *h;
		int update_count;
		int j;

		bur = update_bufs[i];
		update_count = bur->burq_count;
		for (j = 0; j < update_count; j++) {
			__u32 replen;

			reqmsg = batch_update_reqmsg_next(bur, reqmsg);
			repmsg = batch_update_repmsg_next(reply, repmsg);

			if (handled_update_count > buh->buh_update_count)
				GOTO(out, rc = -EOVERFLOW);

			LASSERT(reqmsg != NULL && repmsg != NULL);
			LASSERTF(reqmsg->lm_magic == LUSTRE_MSG_MAGIC_V2,
				 "Invalid reqmsg magic %x expected %x\n",
				 reqmsg->lm_magic, LUSTRE_MSG_MAGIC_V2);

			h = mdt_batch_handler_find(reqmsg->lm_opc);
			if (unlikely(h == NULL)) {
				CERROR("%s: unsupported opc: 0x%x\n",
				       tgt_name(tsi->tsi_tgt), reqmsg->lm_opc);
				GOTO(out, rc = -ENOTSUPP);
			}

			LASSERT(h->th_fmt != NULL);
			req_capsule_subreq_init(pill, h->th_fmt, req,
						reqmsg, repmsg, RCL_SERVER);

			rc = mdt_batch_unpack(info, reqmsg->lm_opc);
			if (rc) {
				CERROR("%s: Can't unpack subreq, rc = %d\n",
				       mdt_obd_name(info->mti_mdt), rc);
				GOTO(out, rc);
			}

			rc = mdt_batch_pack_repmsg(info);
			if (rc)
				GOTO(out, rc);

			/* Need to reconstruct the reply for committed sub
			 * requests in a batched RPC.
			 * It only calls reconstruct for modification sub
			 * requests.
			 * For uncommitted or read-only sub requests, the server
			 * should re-execute them via the ->th_act() below.
			 */
			if ((h->th_flags & IS_MUTABLE) && need_reconstruct &&
			    handled_update_count <=
			    trd->trd_reply.lrd_batch_idx) {
				rc = mdt_batch_reconstruct(tsi, reqmsg->lm_opc);
				if (rc)
					GOTO(out, rc);
				GOTO(next, rc);
			}

			tsi->tsi_batch_idx = handled_update_count;
			rc = h->th_act(tsi);
next:
			/*
			 * As @repmsg may be changed if the reply buffer is
			 * too small to grow, thus it needs to reload it here.
			 */
			if (repmsg != pill->rc_repmsg) {
				repmsg = pill->rc_repmsg;
				grown = true;
			}

			if (rc)
				GOTO(out, rc);

			repmsg->lm_result = rc;
			mdt_thread_info_reset(info);

			replen = lustre_packed_msg_size(repmsg);
			packed_replen += replen;
			handled_update_count++;
		}
	}

	CDEBUG(D_INFO, "reply size %u packed replen %u\n",
	       buh->buh_reply_size, packed_replen);
	if (buh->buh_reply_size > packed_replen)
		req_capsule_shrink(&req->rq_pill, &RMF_BUT_REPLY,
				   packed_replen, RCL_SERVER);
out:
	if (reply != NULL) {
		if (grown) {
			reply = req_capsule_server_get(&req->rq_pill,
						       &RMF_BUT_REPLY);
			if (reply == NULL)
				GOTO(out_free, rc = -EPROTO);
		}
		reply->burp_count = handled_update_count;
	}

out_free:
	if (update_bufs != NULL) {
		if (bub != NULL) {
			for (i = 0; i < update_buf_count; i++, bub++) {
				if (update_bufs[i] != NULL)
					OBD_FREE_LARGE(update_bufs[i],
						       bub->bub_size);
			}
		}

		OBD_FREE_PTR_ARRAY(update_bufs, update_buf_count);
	}

	OBD_FREE_PTR(trd);

	if (desc != NULL)
		ptlrpc_free_bulk(desc);

	mdt_thread_info_fini(info);
	tsi->tsi_reply_fail_id = OBD_FAIL_BUT_UPDATE_NET_REP;
	RETURN(rc);
}

