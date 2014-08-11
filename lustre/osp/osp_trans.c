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
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * lustre/osp/osp_trans.c
 *
 *
 * 1. OSP (Object Storage Proxy) transaction methods
 *
 * Implement OSP layer transaction related interfaces for the dt_device API
 * dt_device_operations.
 *
 *
 * 2. Handle asynchronous idempotent operations
 *
 * The OSP uses OUT (Object Unified Target) RPC to talk with other server
 * (MDT or OST) for kinds of operations, such as create, unlink, insert,
 * delete, lookup, set_(x)attr, get_(x)attr, and etc. To reduce the number
 * of RPCs, we allow multiple operations to be packaged together in single
 * OUT RPC.
 *
 * For the asynchronous idempotent operations, such as get_(x)attr, related
 * RPCs will be inserted into an osp_device based shared asynchronous request
 * queue - osp_device::opd_async_requests. When the queue is full, all the
 * requests in the queue will be packaged into a single OUT RPC and given to
 * the ptlrpcd daemon (for sending), then the queue is purged and other new
 * requests can be inserted into it.
 *
 * When the asynchronous idempotent operation inserts the request into the
 * shared queue, it will register an interpreter. When the packaged OUT RPC
 * is replied (or failed to be sent out), all the registered interpreters
 * will be called one by one to handle each own result.
 *
 *
 * There are three kinds of transactions
 *
 * 1. Local transaction, all of updates of the transaction are in the local MDT.
 * 2. Remote transaction, all of updates of the transaction are in one remote
 * MDT, which only happens in LFSCK now.
 * 3. Distribute transaction, updates for the transaction are in mulitple MDTs.
 *
 * Author: Di Wang <di.wang@intel.com>
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "osp_internal.h"

/**
 * The argument for the interpreter callback of osp request.
 */
struct osp_update_args {
	struct dt_update_request *oaua_update;
	atomic_t		 *oaua_count;
	wait_queue_head_t	 *oaua_waitq;
	bool			  oaua_flow_control;
};

/**
 * Call back for each update request.
 */
struct osp_update_callback {
	/* list in the dt_update_request::dur_cb_items */
	struct list_head		 ouc_list;

	/* The target of the async update request. */
	struct osp_object		*ouc_obj;

	/* The data used by or_interpreter. */
	void				*ouc_data;

	/* The interpreter function called after the async request handled. */
	osp_update_interpreter_t	ouc_interpreter;
};

static struct object_update_request *object_update_request_alloc(size_t size)
{
	struct object_update_request *ourq;

	OBD_ALLOC_LARGE(ourq, size);
	if (ourq == NULL)
		return ERR_PTR(-ENOMEM);

	ourq->ourq_magic = UPDATE_REQUEST_MAGIC;
	ourq->ourq_count = 0;

	return ourq;
}

static void object_update_request_free(struct object_update_request *ourq,
				       size_t ourq_size)
{
	if (ourq != NULL)
		OBD_FREE_LARGE(ourq, ourq_size);
}

/**
 * Allocate and initialize dt_update_request
 *
 * dt_update_request is being used to track updates being executed on
 * this dt_device(OSD or OSP). The update buffer will be 4k initially,
 * and increased if needed.
 *
 * \param [in] dt	dt device
 *
 * \retval		dt_update_request being allocated if succeed
 * \retval		ERR_PTR(errno) if failed
 */
struct dt_update_request *dt_update_request_create(struct dt_device *dt)
{
	struct dt_update_request *dt_update;
	struct object_update_request *ourq;

	OBD_ALLOC_PTR(dt_update);
	if (dt_update == NULL)
		return ERR_PTR(-ENOMEM);

	ourq = object_update_request_alloc(OUT_UPDATE_INIT_BUFFER_SIZE);
	if (IS_ERR(ourq)) {
		OBD_FREE_PTR(dt_update);
		return ERR_CAST(ourq);
	}

	dt_update->dur_buf.ub_req = ourq;
	dt_update->dur_buf.ub_req_size = OUT_UPDATE_INIT_BUFFER_SIZE;

	dt_update->dur_dt = dt;
	dt_update->dur_batchid = 0;
	INIT_LIST_HEAD(&dt_update->dur_cb_items);

	return dt_update;
}

/**
 * Destroy dt_update_request
 *
 * \param [in] dt_update	dt_update_request being destroyed
 */
void dt_update_request_destroy(struct dt_update_request *dt_update)
{
	if (dt_update == NULL)
		return;

	object_update_request_free(dt_update->dur_buf.ub_req,
				   dt_update->dur_buf.ub_req_size);
	OBD_FREE_PTR(dt_update);
}

static void
object_update_request_dump(const struct object_update_request *ourq,
			   unsigned int mask)
{
	unsigned int i;
	size_t total_size = 0;

	for (i = 0; i < ourq->ourq_count; i++) {
		struct object_update	*update;
		size_t			size = 0;

		update = object_update_request_get(ourq, i, &size);
		LASSERT(update != NULL);
		CDEBUG(mask, "i = %u fid = "DFID" op = %s master = %u"
		       "params = %d batchid = "LPU64" size = %zu\n",
		       i, PFID(&update->ou_fid),
		       update_op_str(update->ou_type),
		       update->ou_master_index, update->ou_params_count,
		       update->ou_batchid, size);

		total_size += size;
	}

	CDEBUG(mask, "updates = %p magic = %x count = %d size = %zu\n", ourq,
	       ourq->ourq_magic, ourq->ourq_count, total_size);
}

/**
 * Allocate an osp request and initialize it with the given parameters.
 *
 * \param[in] obj		pointer to the operation target
 * \param[in] data		pointer to the data used by the interpreter
 * \param[in] interpreter	pointer to the interpreter function
 *
 * \retval			pointer to the asychronous request
 * \retval			NULL if the allocation failed
 */
static struct osp_update_callback *
osp_update_callback_init(struct osp_object *obj, void *data,
			 osp_update_interpreter_t interpreter)
{
	struct osp_update_callback *ouc;

	OBD_ALLOC_PTR(ouc);
	if (ouc == NULL)
		return NULL;

	lu_object_get(osp2lu_obj(obj));
	INIT_LIST_HEAD(&ouc->ouc_list);
	ouc->ouc_obj = obj;
	ouc->ouc_data = data;
	ouc->ouc_interpreter = interpreter;

	return ouc;
}

/**
 * Destroy the osp_update_callback.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] ouc	pointer to osp_update_callback
 */
static void osp_update_callback_fini(const struct lu_env *env,
				     struct osp_update_callback *ouc)
{
	LASSERT(list_empty(&ouc->ouc_list));

	lu_object_put(env, osp2lu_obj(ouc->ouc_obj));
	OBD_FREE_PTR(ouc);
}

/**
 * Interpret the packaged OUT RPC results.
 *
 * For every packaged sub-request, call its registered interpreter function.
 * Then destroy the sub-request.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] req	pointer to the RPC
 * \param[in] arg	pointer to data used by the interpreter
 * \param[in] rc	the RPC return value
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_update_interpret(const struct lu_env *env,
				struct ptlrpc_request *req, void *arg, int rc)
{
	struct object_update_reply	*reply	= NULL;
	struct osp_update_args		*oaua	= arg;
	struct dt_update_request	*dt_update = oaua->oaua_update;
	struct osp_update_callback	*ouc;
	struct osp_update_callback	*next;
	int				 count	= 0;
	int				 index  = 0;
	int				 rc1	= 0;

	if (oaua->oaua_flow_control)
		obd_put_request_slot(
				&dt2osp_dev(dt_update->dur_dt)->opd_obd->u.cli);

	/* Unpack the results from the reply message. */
	if (req->rq_repmsg != NULL) {
		reply = req_capsule_server_sized_get(&req->rq_pill,
						     &RMF_OUT_UPDATE_REPLY,
						     OUT_UPDATE_REPLY_SIZE);
		if (reply == NULL || reply->ourp_magic != UPDATE_REPLY_MAGIC)
			rc1 = -EPROTO;
		else
			count = reply->ourp_count;
	} else {
		rc1 = rc;
	}

	list_for_each_entry_safe(ouc, next, &dt_update->dur_cb_items,
				 ouc_list) {
		list_del_init(&ouc->ouc_list);

		/* The peer may only have handled some requests (indicated
		 * by the 'count') in the packaged OUT RPC, we can only get
		 * results for the handled part. */
		if (index < count && reply->ourp_lens[index] > 0) {
			struct object_update_result *result;

			result = object_update_result_get(reply, index, NULL);
			if (result == NULL)
				rc1 = -EPROTO;
			else
				rc1 = result->our_rc;
		} else {
			rc1 = rc;
			if (unlikely(rc1 == 0))
				rc1 = -EINVAL;
		}

		if (ouc->ouc_interpreter != NULL)
			ouc->ouc_interpreter(env, reply, req, ouc->ouc_obj,
					     ouc->ouc_data, index, rc1);

		osp_update_callback_fini(env, ouc);
		index++;
	}

	if (oaua->oaua_count != NULL && atomic_dec_and_test(oaua->oaua_count))
		wake_up_all(oaua->oaua_waitq);

	dt_update_request_destroy(dt_update);

	return 0;
}

/**
 * Pack all the requests in the shared asynchronous idempotent request queue
 * into a single OUT RPC that will be given to the background ptlrpcd daemon.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] osp	pointer to the OSP device
 * \param[in] update	pointer to the shared queue
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osp_unplug_async_request(const struct lu_env *env,
			     struct osp_device *osp,
			     struct dt_update_request *update)
{
	struct osp_update_args	*args;
	struct ptlrpc_request	*req = NULL;
	int			 rc;

	rc = osp_prep_update_req(env, osp->opd_obd->u.cli.cl_import,
				 update->dur_buf.ub_req, &req);
	if (rc != 0) {
		struct osp_update_callback *ouc;
		struct osp_update_callback *next;

		list_for_each_entry_safe(ouc, next,
					 &update->dur_cb_items, ouc_list) {
			list_del_init(&ouc->ouc_list);
			if (ouc->ouc_interpreter != NULL)
				ouc->ouc_interpreter(env, NULL, NULL,
						     ouc->ouc_obj,
						     ouc->ouc_data, 0, rc);
			osp_update_callback_fini(env, ouc);
		}
		dt_update_request_destroy(update);
	} else {
		args = ptlrpc_req_async_args(req);
		args->oaua_update = update;
		args->oaua_count = NULL;
		args->oaua_waitq = NULL;
		args->oaua_flow_control = false;
		req->rq_interpret_reply = osp_update_interpret;
		ptlrpcd_add_req(req, PDL_POLICY_LOCAL, -1);
	}

	return rc;
}

/**
 * Find or create (if NOT exist or purged) the shared asynchronous idempotent
 * request queue - osp_device::opd_async_requests.
 *
 * If the osp_device::opd_async_requests is not NULL, then return it directly;
 * otherwise create new dt_update_request and attach it to opd_async_requests.
 *
 * \param[in] osp	pointer to the OSP device
 *
 * \retval		pointer to the shared queue
 * \retval		negative error number on failure
 */
static struct dt_update_request *
osp_find_or_create_async_update_request(struct osp_device *osp)
{
	struct dt_update_request *update = osp->opd_async_requests;

	if (update != NULL)
		return update;

	update = dt_update_request_create(&osp->opd_dt_dev);
	if (!IS_ERR(update))
		osp->opd_async_requests = update;

	return update;
}

/**
 * Insert an osp_update_callback into the dt_update_request.
 *
 * Insert an osp_update_callback to the dt_update_request. Usually each update
 * in the dt_update_request will have one correspondent callback, and these
 * callbacks will be called in rq_interpret_reply.
 *
 * \param[in] env		pointer to the thread context
 * \param[in] obj		pointer to the operation target object
 * \param[in] data		pointer to the data used by the interpreter
 * \param[in] interpreter	pointer to the interpreter function
 *
 * \retval			0 for success
 * \retval			negative error number on failure
 */
int osp_insert_update_callback(const struct lu_env *env,
			       struct dt_update_request *update,
			       struct osp_object *obj, void *data,
			       osp_update_interpreter_t interpreter)
{
	struct osp_update_callback  *ouc;

	ouc = osp_update_callback_init(obj, data, interpreter);
	if (ouc == NULL)
		RETURN(-ENOMEM);

	list_add_tail(&ouc->ouc_list, &update->dur_cb_items);

	return 0;
}

/**
 * Insert an asynchronous idempotent request to the shared request queue that
 * is attached to the osp_device.
 *
 * This function generates a new osp_async_request with the given parameters,
 * then tries to insert the request into the osp_device-based shared request
 * queue. If the queue is full, then triggers the packaged OUT RPC to purge
 * the shared queue firstly, and then re-tries.
 *
 * NOTE: must hold the osp::opd_async_requests_mutex to serialize concurrent
 *	 osp_insert_async_request call from others.
 *
 * \param[in] env		pointer to the thread context
 * \param[in] op		operation type, see 'enum update_type'
 * \param[in] obj		pointer to the operation target
 * \param[in] count		array size of the subsequent \a lens and \a bufs
 * \param[in] lens		buffer length array for the subsequent \a bufs
 * \param[in] bufs		the buffers to compose the request
 * \param[in] data		pointer to the data used by the interpreter
 * \param[in] interpreter	pointer to the interpreter function
 *
 * \retval			0 for success
 * \retval			negative error number on failure
 */
int osp_insert_async_request(const struct lu_env *env, enum update_type op,
			     struct osp_object *obj, int count,
			     __u16 *lens, const void **bufs, void *data,
			     osp_update_interpreter_t interpreter)
{
	struct osp_device	     *osp = lu2osp_dev(osp2lu_obj(obj)->lo_dev);
	struct dt_update_request	*update;
	struct object_update		*object_update;
	size_t				max_update_size;
	struct object_update_request	*ureq;
	int				rc = 0;
	ENTRY;

	update = osp_find_or_create_async_update_request(osp);
	if (IS_ERR(update))
		RETURN(PTR_ERR(update));

again:
	ureq = update->dur_buf.ub_req;
	max_update_size = update->dur_buf.ub_req_size -
			    object_update_request_size(ureq);

	object_update = update_buffer_get_update(ureq, ureq->ourq_count);
	rc = out_update_pack(env, object_update, max_update_size, op,
			     lu_object_fid(osp2lu_obj(obj)), count, lens, bufs);
	/* The queue is full. */
	if (rc == -E2BIG) {
		osp->opd_async_requests = NULL;
		mutex_unlock(&osp->opd_async_requests_mutex);

		rc = osp_unplug_async_request(env, osp, update);
		mutex_lock(&osp->opd_async_requests_mutex);
		if (rc != 0)
			RETURN(rc);

		update = osp_find_or_create_async_update_request(osp);
		if (IS_ERR(update))
			RETURN(PTR_ERR(update));

		goto again;
	} else {
		if (rc < 0)
			RETURN(rc);

		ureq->ourq_count++;
	}

	rc = osp_insert_update_callback(env, update, obj, data, interpreter);

	RETURN(rc);
}

int osp_trans_update_request_create(struct thandle *th)
{
	struct osp_thandle		*oth = thandle_to_osp_thandle(th);
	struct dt_update_request	*update;

	if (oth->ot_dur != NULL)
		return 0;

	update = dt_update_request_create(th->th_dev);
	if (IS_ERR(update)) {
		th->th_result = PTR_ERR(update);
		return PTR_ERR(update);
	}

	if (dt2osp_dev(th->th_dev)->opd_connect_mdt)
		update->dur_flags = UPDATE_FL_SYNC;

	oth->ot_dur = update;
	return 0;
}

/**
 * The OSP layer dt_device_operations::dt_trans_create() interface
 * to create a transaction.
 *
 * There are two kinds of transactions that will involve OSP:
 *
 * 1) If the transaction only contains the updates on remote server
 *    (MDT or OST), such as re-generating the lost OST-object for
 *    LFSCK, then it is a remote transaction. For remote transaction,
 *    the upper layer caller (such as the LFSCK engine) will call the
 *    dt_trans_create() (with the OSP dt_device as the parameter),
 *    then the call will be directed to the osp_trans_create() that
 *    creates the transaction handler and returns it to the caller.
 *
 * 2) If the transcation contains both local and remote updates,
 *    such as cross MDTs create under DNE mode, then the upper layer
 *    caller will not trigger osp_trans_create(). Instead, it will
 *    call dt_trans_create() on other dt_device, such as LOD that
 *    will generate the transaction handler. Such handler will be
 *    used by the whole transaction in subsequent sub-operations.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] d		pointer to the OSP dt_device
 *
 * \retval		pointer to the transaction handler
 * \retval		negative error number on failure
 */
struct thandle *osp_trans_create(const struct lu_env *env, struct dt_device *d)
{
	struct osp_thandle		*oth;
	struct thandle			*th = NULL;
	ENTRY;

	OBD_ALLOC_PTR(oth);
	if (unlikely(oth == NULL))
		RETURN(ERR_PTR(-ENOMEM));

	th = &oth->ot_super;
	th->th_dev = d;
	th->th_tags = LCT_TX_HANDLE;

	RETURN(th);
}

/**
 * Prepare update request.
 *
 * Prepare OUT update ptlrpc request, and the request usually includes
 * all of updates (stored in \param ureq) from one operation.
 *
 * \param[in] env	execution environment
 * \param[in] imp	import on which ptlrpc request will be sent
 * \param[in] ureq	hold all of updates which will be packed into the req
 * \param[in] reqp	request to be created
 *
 * \retval		0 if preparation succeeds.
 * \retval		negative errno if preparation fails.
 */
int osp_prep_update_req(const struct lu_env *env, struct obd_import *imp,
			const struct object_update_request *ureq,
			struct ptlrpc_request **reqp)
{
	struct ptlrpc_request		*req;
	struct object_update_request	*tmp;
	int				ureq_len;
	int				rc;
	ENTRY;

	object_update_request_dump(ureq, D_INFO);
	req = ptlrpc_request_alloc(imp, &RQF_OUT_UPDATE);
	if (req == NULL)
		RETURN(-ENOMEM);

	ureq_len = object_update_request_size(ureq);
	req_capsule_set_size(&req->rq_pill, &RMF_OUT_UPDATE, RCL_CLIENT,
			     ureq_len);

	rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, OUT_UPDATE);
	if (rc != 0) {
		ptlrpc_req_finished(req);
		RETURN(rc);
	}

	req_capsule_set_size(&req->rq_pill, &RMF_OUT_UPDATE_REPLY,
			     RCL_SERVER, OUT_UPDATE_REPLY_SIZE);

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_OUT_UPDATE);
	memcpy(tmp, ureq, ureq_len);

	ptlrpc_request_set_replen(req);
	req->rq_request_portal = OUT_PORTAL;
	req->rq_reply_portal = OSC_REPLY_PORTAL;
	*reqp = req;

	RETURN(rc);
}

/**
 * Send update RPC.
 *
 * Send update request to the remote MDT synchronously.
 *
 * \param[in] env	execution environment
 * \param[in] imp	import on which ptlrpc request will be sent
 * \param[in] dt_update	hold all of updates which will be packed into the req
 * \param[in] reqp	request to be created
 *
 * \retval		0 if RPC succeeds.
 * \retval		negative errno if RPC fails.
 */
int osp_remote_sync(const struct lu_env *env, struct osp_device *osp,
		    struct dt_update_request *dt_update,
		    struct ptlrpc_request **reqp)
{
	struct obd_import	*imp = osp->opd_obd->u.cli.cl_import;
	struct ptlrpc_request	*req = NULL;
	int			rc;
	ENTRY;

	rc = osp_prep_update_req(env, imp, dt_update->dur_buf.ub_req, &req);
	if (rc != 0)
		RETURN(rc);

	/* Note: some dt index api might return non-zero result here, like
	 * osd_index_ea_lookup, so we should only check rc < 0 here */
	rc = ptlrpc_queue_wait(req);
	if (rc < 0) {
		ptlrpc_req_finished(req);
		dt_update->dur_rc = rc;
		RETURN(rc);
	}

	if (reqp != NULL) {
		*reqp = req;
		RETURN(rc);
	}

	dt_update->dur_rc = rc;

	ptlrpc_req_finished(req);

	RETURN(rc);
}

/**
 * Trigger the request for remote updates.
 *
 * If th_sync is set, then the request will be sent synchronously,
 * otherwise, the RPC will be sent asynchronously.
 *
 * Please refer to osp_trans_create() for transaction type.
 *
 * \param[in] env		pointer to the thread context
 * \param[in] osp		pointer to the OSP device
 * \param[in] dt_update		pointer to the dt_update_request
 * \param[in] th		pointer to the transaction handler
 * \param[out] sent		whether the RPC has been sent
 *
 * \retval			0 for success
 * \retval			negative error number on failure
 */
static int osp_trans_trigger(const struct lu_env *env, struct osp_device *osp,
			     struct dt_update_request *dt_update,
			     struct thandle *th, int *sent)
{
	struct osp_update_args	*args;
	struct ptlrpc_request	*req;
	int	rc = 0;
	ENTRY;

	rc = osp_prep_update_req(env, osp->opd_obd->u.cli.cl_import,
				 dt_update->dur_buf.ub_req, &req);
	if (rc != 0)
		RETURN(rc);

	*sent = 1;
	req->rq_interpret_reply = osp_update_interpret;
	args = ptlrpc_req_async_args(req);
	args->oaua_update = dt_update;
	if (is_only_remote_trans(th) && !th->th_sync) {
		args->oaua_flow_control = true;

		if (!osp->opd_connect_mdt) {
			down_read(&osp->opd_async_updates_rwsem);
			args->oaua_count = &osp->opd_async_updates_count;
			args->oaua_waitq = &osp->opd_syn_barrier_waitq;
			up_read(&osp->opd_async_updates_rwsem);
			atomic_inc(args->oaua_count);
		}

		ptlrpcd_add_req(req, PDL_POLICY_LOCAL, -1);
	} else {
		osp_get_rpc_lock(osp);
		args->oaua_flow_control = false;
		rc = ptlrpc_queue_wait(req);
		osp_put_rpc_lock(osp);
		ptlrpc_req_finished(req);
	}

	RETURN(rc);
}

/**
 * Get local thandle for osp_thandle
 *
 * Get the local OSD thandle from the OSP thandle. Currently, there
 * are a few OSP API (osp_object_create() and osp_sync_add()) needs
 * to update the object on local OSD device.
 *
 * If the osp_thandle comes from normal stack (MDD->LOD->OSP), then
 * we will get local thandle by thandle_get_sub_by_dt.
 *
 * If the osp_thandle is remote thandle (th_top == NULL, only used
 * by LFSCK), then it will create a local thandle, and stop it in
 * osp_trans_stop(). And this only happens on OSP for OST.
 *
 * These are temporary solution, once OSP accessing OSD object is
 * being fixed properly, this function should be removed. XXX
 *
 * \param[in] env		pointer to the thread context
 * \param[in] th		pointer to the transaction handler
 * \param[in] dt		pointer to the OSP device
 *
 * \retval			pointer to the local thandle
 * \retval			ERR_PTR(errno) if it fails.
 **/
struct thandle *osp_get_storage_thandle(const struct lu_env *env,
					struct thandle *th,
					struct osp_device *osp)
{
	struct osp_thandle	*oth;
	struct thandle		*local_th;

	if (th->th_top != NULL)
		return thandle_get_sub_by_dt(env, th->th_top,
					     osp->opd_storage);

	LASSERT(!osp->opd_connect_mdt);
	oth = thandle_to_osp_thandle(th);
	if (oth->ot_storage_th != NULL)
		return oth->ot_storage_th;

	local_th = dt_trans_create(env, osp->opd_storage);
	if (IS_ERR(local_th))
		return local_th;

	oth->ot_storage_th = local_th;

	return local_th;
}

/**
 * The OSP layer dt_device_operations::dt_trans_start() interface
 * to start the transaction.
 *
 * If the transaction is a remote transaction, then related remote
 * updates will be triggered in the osp_trans_stop().
 * Please refer to osp_trans_create() for transaction type.
 *
 * \param[in] env		pointer to the thread context
 * \param[in] dt		pointer to the OSP dt_device
 * \param[in] th		pointer to the transaction handler
 *
 * \retval			0 for success
 * \retval			negative error number on failure
 */
int osp_trans_start(const struct lu_env *env, struct dt_device *dt,
		    struct thandle *th)
{
	struct osp_thandle	*oth = thandle_to_osp_thandle(th);

	/* For remote thandle, if there are local thandle, start it here*/
	if (is_only_remote_trans(th) && oth->ot_storage_th != NULL)
		return dt_trans_start(env, oth->ot_storage_th->th_dev,
				      oth->ot_storage_th);
	return 0;
}

/**
 * The OSP layer dt_device_operations::dt_trans_stop() interface
 * to stop the transaction.
 *
 * If the transaction is a remote transaction, related remote
 * updates will be triggered here via osp_trans_trigger().
 *
 * For synchronous mode update or any failed update, the request
 * will be destroyed explicitly when the osp_trans_stop().
 *
 * Please refer to osp_trans_create() for transaction type.
 *
 * \param[in] env		pointer to the thread context
 * \param[in] dt		pointer to the OSP dt_device
 * \param[in] th		pointer to the transaction handler
 *
 * \retval			0 for success
 * \retval			negative error number on failure
 */
int osp_trans_stop(const struct lu_env *env, struct dt_device *dt,
		   struct thandle *th)
{
	struct osp_thandle	 *oth = thandle_to_osp_thandle(th);
	struct dt_update_request *dt_update;
	int			 rc = 0;
	int			 sent = 0;
	ENTRY;

	/* For remote transaction, if there is local storage thandle,
	 * stop it first */
	if (oth->ot_storage_th != NULL && th->th_top == NULL) {
		dt_trans_stop(env, oth->ot_storage_th->th_dev,
			      oth->ot_storage_th);
		oth->ot_storage_th = NULL;
	}

	dt_update = oth->ot_dur;
	if (dt_update == NULL)
		GOTO(out, rc);

	LASSERT(dt_update != LP_POISON);

	/* If there are no updates, destroy dt_update and thandle */
	if (dt_update->dur_buf.ub_req == NULL ||
	    dt_update->dur_buf.ub_req->ourq_count == 0) {
		dt_update_request_destroy(dt_update);
		GOTO(out, rc);
	}

	if (is_only_remote_trans(th) && !th->th_sync) {
		struct osp_device *osp = dt2osp_dev(th->th_dev);
		struct client_obd *cli = &osp->opd_obd->u.cli;

		rc = obd_get_request_slot(cli);
		if (rc != 0)
			GOTO(out, rc);

		if (!osp->opd_imp_active || !osp->opd_imp_connected) {
			obd_put_request_slot(cli);
			GOTO(out, rc = -ENOTCONN);
		}

		rc = osp_trans_trigger(env, dt2osp_dev(dt),
				       dt_update, th, &sent);
		if (rc != 0)
			obd_put_request_slot(cli);
	} else {
		rc = osp_trans_trigger(env, dt2osp_dev(dt), dt_update,
				       th, &sent);
	}

out:
	/* If RPC is triggered successfully, dt_update will be freed in
	 * osp_update_interpreter() */
	if (rc != 0 && dt_update != NULL && sent == 0) {
		struct osp_update_callback *ouc;
		struct osp_update_callback *next;

		list_for_each_entry_safe(ouc, next, &dt_update->dur_cb_items,
				 ouc_list) {
			list_del_init(&ouc->ouc_list);
			if (ouc->ouc_interpreter != NULL)
				ouc->ouc_interpreter(env, NULL, NULL,
						     ouc->ouc_obj,
						     ouc->ouc_data, 0, rc);
			osp_update_callback_fini(env, ouc);
		}

		dt_update_request_destroy(dt_update);
	}

	OBD_FREE_PTR(oth);

	RETURN(rc);
}
