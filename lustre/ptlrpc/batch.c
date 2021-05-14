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
 * Copyright (c) 2020, 2022, DDN/Whamcloud Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * lustre/ptlrpc/batch.c
 *
 * Batch Metadata Updating on the client
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/module.h>
#include <obd_class.h>
#include <obd.h>
#ifdef HAVE_SERVER_SUPPORT
#include <lustre_update.h>
#else

#define OUT_UPDATE_REPLY_SIZE		4096

static inline struct lustre_msg *
batch_update_repmsg_next(struct batch_update_reply *bur,
			 struct lustre_msg *repmsg)
{
	if (repmsg)
		return (struct lustre_msg *)((char *)repmsg +
					     lustre_packed_msg_size(repmsg));
	else
		return &bur->burp_repmsg[0];
}
#endif

struct batch_update_buffer {
	struct batch_update_request	*bub_req;
	size_t				 bub_size;
	size_t				 bub_end;
	struct list_head		 bub_item;
};

struct batch_update_args {
	struct batch_update_head	*ba_head;
};

/**
 * Prepare inline update request
 *
 * Prepare BUT update ptlrpc inline request, and the request usuanlly includes
 * one update buffer, which does not need bulk transfer.
 */
static int batch_prep_inline_update_req(struct batch_update_head *head,
					struct ptlrpc_request *req,
					int repsize)
{
	struct batch_update_buffer *buf;
	struct but_update_header *buh;
	int rc;

	buf = list_entry(head->buh_buf_list.next,
			  struct batch_update_buffer, bub_item);
	req_capsule_set_size(&req->rq_pill, &RMF_BUT_HEADER, RCL_CLIENT,
			     buf->bub_end + sizeof(*buh));

	rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, MDS_BATCH);
	if (rc != 0)
		RETURN(rc);

	buh = req_capsule_client_get(&req->rq_pill, &RMF_BUT_HEADER);
	buh->buh_magic = BUT_HEADER_MAGIC;
	buh->buh_count = 1;
	buh->buh_inline_length = buf->bub_end;
	buh->buh_reply_size = repsize;
	buh->buh_update_count = head->buh_update_count;

	memcpy(buh->buh_inline_data, buf->bub_req, buf->bub_end);

	req_capsule_set_size(&req->rq_pill, &RMF_BUT_REPLY,
			     RCL_SERVER, repsize);

	ptlrpc_request_set_replen(req);
	req->rq_request_portal = OUT_PORTAL;
	req->rq_reply_portal = OSC_REPLY_PORTAL;

	RETURN(rc);
}

static int batch_prep_update_req(struct batch_update_head *head,
				 struct ptlrpc_request **reqp)
{
	struct ptlrpc_request *req;
	struct ptlrpc_bulk_desc *desc;
	struct batch_update_buffer *buf;
	struct but_update_header *buh;
	struct but_update_buffer *bub;
	int page_count = 0;
	int total = 0;
	int repsize;
	int rc;

	ENTRY;

	repsize = head->buh_repsize +
		  cfs_size_round(offsetof(struct batch_update_reply,
					  burp_repmsg[0]));
	if (repsize < OUT_UPDATE_REPLY_SIZE)
		repsize = OUT_UPDATE_REPLY_SIZE;

	LASSERT(head->buh_buf_count > 0);

	req = ptlrpc_request_alloc(class_exp2cliimp(head->buh_exp),
				   &RQF_MDS_BATCH);
	if (req == NULL)
		RETURN(-ENOMEM);

	if (head->buh_buf_count == 1) {
		buf = list_entry(head->buh_buf_list.next,
				 struct batch_update_buffer, bub_item);

		/* Check whether it can be packed inline */
		if (buf->bub_end + sizeof(struct but_update_header) <
		    OUT_UPDATE_MAX_INLINE_SIZE) {
			rc = batch_prep_inline_update_req(head, req, repsize);
			if (rc == 0)
				*reqp = req;
			GOTO(out_req, rc);
		}
	}

	req_capsule_set_size(&req->rq_pill, &RMF_BUT_HEADER, RCL_CLIENT,
			     sizeof(struct but_update_header));
	req_capsule_set_size(&req->rq_pill, &RMF_BUT_BUF, RCL_CLIENT,
			     head->buh_buf_count * sizeof(*bub));

	rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, MDS_BATCH);
	if (rc != 0)
		GOTO(out_req, rc);

	buh = req_capsule_client_get(&req->rq_pill, &RMF_BUT_HEADER);
	buh->buh_magic = BUT_HEADER_MAGIC;
	buh->buh_count = head->buh_buf_count;
	buh->buh_inline_length = 0;
	buh->buh_reply_size = repsize;
	buh->buh_update_count = head->buh_update_count;
	bub = req_capsule_client_get(&req->rq_pill, &RMF_BUT_BUF);
	list_for_each_entry(buf, &head->buh_buf_list, bub_item) {
		bub->bub_size = buf->bub_size;
		bub++;
		/* First *and* last might be partial pages, hence +1 */
		page_count += DIV_ROUND_UP(buf->bub_size, PAGE_SIZE) + 1;
	}

	req->rq_bulk_write = 1;
	desc = ptlrpc_prep_bulk_imp(req, page_count,
				    MD_MAX_BRW_SIZE >> LNET_MTU_BITS,
				    PTLRPC_BULK_GET_SOURCE,
				    MDS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_nopin_ops);
	if (desc == NULL)
		GOTO(out_req, rc = -ENOMEM);

	list_for_each_entry(buf, &head->buh_buf_list, bub_item) {
		desc->bd_frag_ops->add_iov_frag(desc, buf->bub_req,
						buf->bub_size);
		total += buf->bub_size;
	}
	CDEBUG(D_OTHER, "Total %d in %u\n", total, head->buh_update_count);

	req_capsule_set_size(&req->rq_pill, &RMF_BUT_REPLY,
			     RCL_SERVER, repsize);

	ptlrpc_request_set_replen(req);
	req->rq_request_portal = OUT_PORTAL;
	req->rq_reply_portal = OSC_REPLY_PORTAL;
	*reqp = req;

out_req:
	if (rc < 0)
		ptlrpc_req_finished(req);

	RETURN(rc);
}

static struct batch_update_buffer *
current_batch_update_buffer(struct batch_update_head *head)
{
	if (list_empty(&head->buh_buf_list))
		return NULL;

	return list_entry(head->buh_buf_list.prev, struct batch_update_buffer,
			  bub_item);
}

static int batch_update_buffer_create(struct batch_update_head *head,
				      size_t size)
{
	struct batch_update_buffer *buf;
	struct batch_update_request *bur;

	OBD_ALLOC_PTR(buf);
	if (buf == NULL)
		return -ENOMEM;

	LASSERT(size > 0);
	size = round_up(size, PAGE_SIZE);
	OBD_ALLOC_LARGE(bur, size);
	if (bur == NULL) {
		OBD_FREE_PTR(buf);
		return -ENOMEM;
	}

	bur->burq_magic = BUT_REQUEST_MAGIC;
	bur->burq_count = 0;
	buf->bub_req = bur;
	buf->bub_size = size;
	buf->bub_end = sizeof(*bur);
	INIT_LIST_HEAD(&buf->bub_item);
	list_add_tail(&buf->bub_item, &head->buh_buf_list);
	head->buh_buf_count++;

	return 0;
}

/**
 * Destroy an @object_update_callback.
 */
static void object_update_callback_fini(struct object_update_callback *ouc)
{
	LASSERT(list_empty(&ouc->ouc_item));

	OBD_FREE_PTR(ouc);
}

/**
 * Insert an @object_update_callback into the the @batch_update_head.
 *
 * Usually each update in @batch_update_head will have one correspondent
 * callback, and these callbacks will be called in ->rq_interpret_reply.
 */
static int
batch_insert_update_callback(struct batch_update_head *head, void *data,
			     object_update_interpret_t interpret)
{
	struct object_update_callback *ouc;

	OBD_ALLOC_PTR(ouc);
	if (ouc == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&ouc->ouc_item);
	ouc->ouc_interpret = interpret;
	ouc->ouc_head = head;
	ouc->ouc_data = data;
	list_add_tail(&ouc->ouc_item, &head->buh_cb_list);

	return 0;
}

/**
 * Allocate and initialize batch update request.
 *
 * @batch_update_head is being used to track updates being executed on
 * this OBD device. The update buffer will be 4K initially, and increased
 * if needed.
 */
static struct batch_update_head *
batch_update_request_create(struct obd_export *exp, struct lu_batch *bh)
{
	struct batch_update_head *head;
	int rc;

	OBD_ALLOC_PTR(head);
	if (head == NULL)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&head->buh_cb_list);
	INIT_LIST_HEAD(&head->buh_buf_list);
	head->buh_exp = exp;
	head->buh_batch = bh;

	rc = batch_update_buffer_create(head, PAGE_SIZE);
	if (rc != 0) {
		OBD_FREE_PTR(head);
		RETURN(ERR_PTR(rc));
	}

	return head;
}

static void batch_update_request_destroy(struct batch_update_head *head)
{
	struct batch_update_buffer *bub, *tmp;

	if (head == NULL)
		return;

	list_for_each_entry_safe(bub, tmp, &head->buh_buf_list, bub_item) {
		list_del(&bub->bub_item);
		if (bub->bub_req)
			OBD_FREE_LARGE(bub->bub_req, bub->bub_size);
		OBD_FREE_PTR(bub);
	}

	OBD_FREE_PTR(head);
}

static int batch_update_request_fini(struct batch_update_head *head,
				     struct ptlrpc_request *req,
				     struct batch_update_reply *reply, int rc)
{
	struct object_update_callback *ouc, *next;
	struct lustre_msg *repmsg = NULL;
	int count = 0;
	int index = 0;

	ENTRY;

	if (reply)
		count = reply->burp_count;

	list_for_each_entry_safe(ouc, next, &head->buh_cb_list, ouc_item) {
		int rc1 = 0;

		list_del_init(&ouc->ouc_item);

		/*
		 * The peer may only have handled some requests (indicated by
		 * @count) in the packaged OUT PRC, we can only get results
		 * for the handled part.
		 */
		if (index < count) {
			repmsg = batch_update_repmsg_next(reply, repmsg);
			if (repmsg == NULL)
				rc1 = -EPROTO;
			else
				rc1 = repmsg->lm_result;
		} else {
			/*
			 * The peer did not handle these request, let us return
			 * -ECANCELED to the update interpreter for now.
			 */
			repmsg = NULL;
			rc1 = -ECANCELED;
			/*
			 * TODO: resend the unfinished sub request when the
			 * return code is -EOVERFLOW.
			 */
		}

		if (ouc->ouc_interpret != NULL)
			ouc->ouc_interpret(req, repmsg, ouc, rc1);

		index++;
		object_update_callback_fini(ouc);
		if (rc == 0 && rc1 < 0)
			rc = rc1;
	}

	batch_update_request_destroy(head);

	RETURN(rc);
}

static int batch_update_interpret(const struct lu_env *env,
				  struct ptlrpc_request *req,
				  void *args, int rc)
{
	struct batch_update_args *aa = (struct batch_update_args *)args;
	struct batch_update_reply *reply = NULL;

	ENTRY;

	if (aa->ba_head == NULL)
		RETURN(0);

	ptlrpc_put_mod_rpc_slot(req);
	/* Unpack the results from the reply message. */
	if (req->rq_repmsg != NULL && req->rq_replied) {
		reply = req_capsule_server_sized_get(&req->rq_pill,
						     &RMF_BUT_REPLY,
						     sizeof(*reply));
		if ((reply == NULL ||
		     reply->burp_magic != BUT_REPLY_MAGIC) && rc == 0)
			rc = -EPROTO;
	}

	rc = batch_update_request_fini(aa->ba_head, req, reply, rc);

	RETURN(rc);
}

static int batch_send_update_req(const struct lu_env *env,
				 struct batch_update_head *head)
{
	struct obd_device *obd;
	struct ptlrpc_request *req = NULL;
	struct batch_update_args *aa;
	struct lu_batch *bh;
	int rc;

	ENTRY;

	if (head == NULL)
		RETURN(0);

	obd = class_exp2obd(head->buh_exp);
	bh = head->buh_batch;
	rc = batch_prep_update_req(head, &req);
	if (rc) {
		rc = batch_update_request_fini(head, NULL, NULL, rc);
		RETURN(rc);
	}

	aa = ptlrpc_req_async_args(aa, req);
	aa->ba_head = head;
	req->rq_interpret_reply = batch_update_interpret;

	/*
	 * Only acquire modification RPC slot for the batched RPC
	 * which contains metadata updates.
	 */
	if (!(bh->lbt_flags & BATCH_FL_RDONLY))
		ptlrpc_get_mod_rpc_slot(req);

	if (bh->lbt_flags & BATCH_FL_SYNC) {
		rc = ptlrpc_queue_wait(req);
	} else {
		if ((bh->lbt_flags & (BATCH_FL_RDONLY | BATCH_FL_RQSET)) ==
		    BATCH_FL_RDONLY) {
			ptlrpcd_add_req(req);
		} else if (bh->lbt_flags & BATCH_FL_RQSET) {
			ptlrpc_set_add_req(bh->lbt_rqset, req);
			ptlrpc_check_set(env, bh->lbt_rqset);
		} else {
			ptlrpcd_add_req(req);
		}
		req = NULL;
	}

	if (req != NULL)
		ptlrpc_req_finished(req);

	lprocfs_oh_tally_log2(&obd->u.cli.cl_batch_rpc_hist,
			      head->buh_update_count);
	RETURN(rc);
}

static int batch_update_request_add(struct batch_update_head **headp,
				    struct md_op_item *item,
				    md_update_pack_t packer,
				    object_update_interpret_t interpreter)
{
	struct batch_update_head *head = *headp;
	struct lu_batch *bh = head->buh_batch;
	struct batch_update_buffer *buf;
	struct lustre_msg *reqmsg;
	size_t max_len;
	int rc;

	ENTRY;

	for (; ;) {
		buf = current_batch_update_buffer(head);
		LASSERT(buf != NULL);
		max_len = buf->bub_size - buf->bub_end;
		reqmsg = (struct lustre_msg *)((char *)buf->bub_req +
						buf->bub_end);
		rc = packer(head, reqmsg, &max_len, item);
		if (rc == -E2BIG) {
			int rc2;

			/* Create new batch object update buffer */
			rc2 = batch_update_buffer_create(head,
				max_len + offsetof(struct batch_update_request,
						   burq_reqmsg[0]) + 1);
			if (rc2 != 0) {
				rc = rc2;
				break;
			}
		} else {
			if (rc == 0) {
				buf->bub_end += max_len;
				buf->bub_req->burq_count++;
				head->buh_update_count++;
				head->buh_repsize += reqmsg->lm_repsize;
			}
			break;
		}
	}

	if (rc)
		GOTO(out, rc);

	rc = batch_insert_update_callback(head, item, interpreter);
	if (rc)
		GOTO(out, rc);

	/* Unplug the batch queue if accumulated enough update requests. */
	if (bh->lbt_max_count && head->buh_update_count >= bh->lbt_max_count) {
		rc = batch_send_update_req(NULL, head);
		*headp = NULL;
	}
out:
	if (rc) {
		batch_update_request_destroy(head);
		*headp = NULL;
	}

	RETURN(rc);
}

struct lu_batch *cli_batch_create(struct obd_export *exp,
				  enum lu_batch_flags flags, __u32 max_count)
{
	struct cli_batch *cbh;
	struct lu_batch *bh;

	ENTRY;

	OBD_ALLOC_PTR(cbh);
	if (!cbh)
		RETURN(ERR_PTR(-ENOMEM));

	bh = &cbh->cbh_super;
	bh->lbt_result = 0;
	bh->lbt_flags = flags;
	bh->lbt_max_count = max_count;

	cbh->cbh_head = batch_update_request_create(exp, bh);
	if (IS_ERR(cbh->cbh_head)) {
		bh = (struct lu_batch *)cbh->cbh_head;
		OBD_FREE_PTR(cbh);
	}

	RETURN(bh);
}
EXPORT_SYMBOL(cli_batch_create);

int cli_batch_stop(struct obd_export *exp, struct lu_batch *bh)
{
	struct cli_batch *cbh;
	int rc;

	ENTRY;

	cbh = container_of(bh, struct cli_batch, cbh_super);
	rc = batch_send_update_req(NULL, cbh->cbh_head);

	OBD_FREE_PTR(cbh);
	RETURN(rc);
}
EXPORT_SYMBOL(cli_batch_stop);

int cli_batch_flush(struct obd_export *exp, struct lu_batch *bh, bool wait)
{
	struct cli_batch *cbh;
	int rc;

	ENTRY;

	cbh = container_of(bh, struct cli_batch, cbh_super);
	if (cbh->cbh_head == NULL)
		RETURN(0);

	rc = batch_send_update_req(NULL, cbh->cbh_head);
	cbh->cbh_head = NULL;

	RETURN(rc);
}
EXPORT_SYMBOL(cli_batch_flush);

int cli_batch_add(struct obd_export *exp, struct lu_batch *bh,
		  struct md_op_item *item, md_update_pack_t packer,
		  object_update_interpret_t interpreter)
{
	struct cli_batch *cbh;
	int rc;

	ENTRY;

	cbh = container_of(bh, struct cli_batch, cbh_super);
	if (cbh->cbh_head == NULL) {
		cbh->cbh_head = batch_update_request_create(exp, bh);
		if (IS_ERR(cbh->cbh_head))
			RETURN(PTR_ERR(cbh->cbh_head));
	}

	rc = batch_update_request_add(&cbh->cbh_head, item,
				      packer, interpreter);

	RETURN(rc);
}
EXPORT_SYMBOL(cli_batch_add);
