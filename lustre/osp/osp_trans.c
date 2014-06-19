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
 * RPCs will be inserted into a osp_device based shared asynchronous request
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
 * Author: Di Wang <di.wang@intel.com>
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "osp_internal.h"

struct osp_async_update_args {
	struct dt_update_request *oaua_update;
	atomic_t		 *oaua_count;
	wait_queue_head_t	 *oaua_waitq;
	bool			  oaua_flow_control;
};

struct osp_async_request {
	/* list in the dt_update_request::dur_cb_items */
	struct list_head		 oar_list;

	/* The target of the async update request. */
	struct osp_object		*oar_obj;

	/* The data used by oar_interpreter. */
	void				*oar_data;

	/* The interpreter function called after the async request handled. */
	osp_async_request_interpreter_t	 oar_interpreter;
};

/**
 * Allocate an asynchronous request and initialize it with the given parameters.
 *
 * \param[in] obj		pointer to the operation target
 * \param[in] data		pointer to the data used by the interpreter
 * \param[in] interpreter	pointer to the interpreter function
 *
 * \retval			pointer to the asychronous request
 * \retval			NULL if the allocation failed
 */
static struct osp_async_request *
osp_async_request_init(struct osp_object *obj, void *data,
		       osp_async_request_interpreter_t interpreter)
{
	struct osp_async_request *oar;

	OBD_ALLOC_PTR(oar);
	if (oar == NULL)
		return NULL;

	lu_object_get(osp2lu_obj(obj));
	INIT_LIST_HEAD(&oar->oar_list);
	oar->oar_obj = obj;
	oar->oar_data = data;
	oar->oar_interpreter = interpreter;

	return oar;
}

/**
 * Destroy the asychronous request.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] oar	pointer to asychronous request
 */
static void osp_async_request_fini(const struct lu_env *env,
				   struct osp_async_request *oar)
{
	LASSERT(list_empty(&oar->oar_list));

	lu_object_put(env, osp2lu_obj(oar->oar_obj));
	OBD_FREE_PTR(oar);
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
static int osp_async_update_interpret(const struct lu_env *env,
				      struct ptlrpc_request *req,
				      void *arg, int rc)
{
	struct object_update_reply	*reply	= NULL;
	struct osp_async_update_args	*oaua	= arg;
	struct dt_update_request	*dt_update = oaua->oaua_update;
	struct osp_async_request	*oar;
	struct osp_async_request	*next;
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

	list_for_each_entry_safe(oar, next, &dt_update->dur_cb_items,
				 oar_list) {
		list_del_init(&oar->oar_list);

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

		oar->oar_interpreter(env, reply, req, oar->oar_obj,
				       oar->oar_data, index, rc1);
		osp_async_request_fini(env, oar);
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
	struct osp_async_update_args	*args;
	struct ptlrpc_request		*req = NULL;
	int				 rc;

	rc = osp_prep_update_req(env, osp->opd_obd->u.cli.cl_import,
				 update->dur_buf.ub_req, &req);
	if (rc != 0) {
		struct osp_async_request *oar;
		struct osp_async_request *next;

		list_for_each_entry_safe(oar, next,
					 &update->dur_cb_items, oar_list) {
			list_del_init(&oar->oar_list);
			oar->oar_interpreter(env, NULL, NULL, oar->oar_obj,
					       oar->oar_data, 0, rc);
			osp_async_request_fini(env, oar);
		}
		dt_update_request_destroy(update);
	} else {
		args = ptlrpc_req_async_args(req);
		args->oaua_update = update;
		args->oaua_count = NULL;
		args->oaua_waitq = NULL;
		args->oaua_flow_control = false;
		req->rq_interpret_reply = osp_async_update_interpret;
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
			     osp_async_request_interpreter_t interpreter)
{
	struct osp_async_request     *oar;
	struct osp_device	     *osp = lu2osp_dev(osp2lu_obj(obj)->lo_dev);
	struct dt_update_request     *update;
	int			      rc  = 0;
	ENTRY;

	oar = osp_async_request_init(obj, data, interpreter);
	if (oar == NULL)
		RETURN(-ENOMEM);

	update = osp_find_or_create_async_update_request(osp);
	if (IS_ERR(update))
		GOTO(out, rc = PTR_ERR(update));

again:
	/* The queue is full. */
	rc = out_update_pack(env, &update->dur_buf, op,
			     lu_object_fid(osp2lu_obj(obj)), count, lens, bufs,
			     0);
	if (rc == -E2BIG) {
		osp->opd_async_requests = NULL;
		mutex_unlock(&osp->opd_async_requests_mutex);

		rc = osp_unplug_async_request(env, osp, update);
		mutex_lock(&osp->opd_async_requests_mutex);
		if (rc != 0)
			GOTO(out, rc);

		update = osp_find_or_create_async_update_request(osp);
		if (IS_ERR(update))
			GOTO(out, rc = PTR_ERR(update));

		goto again;
	}

	if (rc == 0)
		list_add_tail(&oar->oar_list, &update->dur_cb_items);

	GOTO(out, rc);

out:
	if (rc != 0)
		osp_async_request_fini(env, oar);

	return rc;
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
	struct dt_update_request	*update;
	ENTRY;

	OBD_ALLOC_PTR(oth);
	if (unlikely(oth == NULL))
		RETURN(ERR_PTR(-ENOMEM));

	th = &oth->ot_super;
	th->th_dev = d;
	th->th_tags = LCT_TX_HANDLE;

	update = dt_update_request_create(d);
	if (IS_ERR(update)) {
		OBD_FREE_PTR(oth);
		RETURN(ERR_CAST(update));
	}

	oth->ot_dur = update;
	oth->ot_send_updates_after_local_trans = false;

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
		    struct ptlrpc_request **reqp, bool rpc_lock)
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
	if (rpc_lock)
		osp_get_rpc_lock(osp);
	rc = ptlrpc_queue_wait(req);
	if (rpc_lock)
		osp_put_rpc_lock(osp);
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
 * If the transaction is not a remote one or it is required to be sync mode
 * (th->th_sync is set), then it will be sent synchronously; otherwise, the
 * RPC will be sent asynchronously.
 *
 * Please refer to osp_trans_create() for transaction type.
 *
 * \param[in] env		pointer to the thread context
 * \param[in] osp		pointer to the OSP device
 * \param[in] dt_update		pointer to the dt_update_request
 * \param[in] th		pointer to the transaction handler
 * \param[in] flow_control	whether need to control the flow
 *
 * \retval			0 for success
 * \retval			negative error number on failure
 */
static int osp_trans_trigger(const struct lu_env *env, struct osp_device *osp,
			     struct dt_update_request *dt_update,
			     struct thandle *th, bool flow_control)
{
	int	rc = 0;

	if (is_only_remote_trans(th) && !th->th_sync) {
		struct osp_async_update_args	*args;
		struct ptlrpc_request		*req;

		rc = osp_prep_update_req(env, osp->opd_obd->u.cli.cl_import,
					 dt_update->dur_buf.ub_req, &req);
		if (rc != 0)
			return rc;
		down_read(&osp->opd_async_updates_rwsem);

		args = ptlrpc_req_async_args(req);
		args->oaua_update = dt_update;
		args->oaua_count = &osp->opd_async_updates_count;
		args->oaua_waitq = &osp->opd_syn_barrier_waitq;
		args->oaua_flow_control = flow_control;
		req->rq_interpret_reply =
			osp_async_update_interpret;

		atomic_inc(args->oaua_count);
		up_read(&osp->opd_async_updates_rwsem);

		ptlrpcd_add_req(req, PDL_POLICY_LOCAL, -1);
	} else {
		rc = osp_remote_sync(env, osp, dt_update, NULL, true);
	}

	return rc;
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
 * updates will be triggered in the osp_trans_stop(); otherwise the
 * transaction contains both local and remote update(s), then when
 * the OUT RPC will be triggered depends on the operation, and is
 * indicated by the dt_device::tu_sent_after_local_trans, for example:
 *
 * 1) If it is remote create, it will send the remote req after local
 * transaction. i.e. create the object locally first, then insert the
 * remote name entry.
 *
 * 2) If it is remote unlink, it will send the remote req before the
 * local transaction, i.e. delete the name entry remotely first, then
 * destroy the local object.
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
int osp_trans_start(const struct lu_env *env, struct dt_device *dt,
		    struct thandle *th)
{
	struct osp_thandle	 *oth = thandle_to_osp_thandle(th);
	struct dt_update_request *dt_update;
	int			 rc = 0;

	dt_update = oth->ot_dur;
	LASSERT(dt_update != NULL);

	/* return if there are no updates,  */
	if (dt_update->dur_buf.ub_req == NULL ||
	    dt_update->dur_buf.ub_req->ourq_count == 0)
		GOTO(out, rc = 0);

	/* Note: some updates needs to send before local transaction,
	 * some needs to send after local transaction.
	 *
	 * If the transaction only includes remote updates, it will
	 * send updates to remote MDT in osp_trans_stop.
	 *
	 * If it is remote create, it will send the remote req after
	 * local transaction. i.e. create the object locally first,
	 * then insert the name entry.
	 *
	 * If it is remote unlink, it will send the remote req before
	 * the local transaction, i.e. delete the name entry remote
	 * first, then destroy the local object. */
	if (!is_only_remote_trans(th) &&
	    !oth->ot_send_updates_after_local_trans)
		rc = osp_trans_trigger(env, dt2osp_dev(dt), dt_update, th,
				       false);

out:
	/* For remote thandle, if there are local thandle, start it here*/
	if (th->th_top == NULL && oth->ot_storage_th != NULL)
		rc = dt_trans_start(env, oth->ot_storage_th->th_dev,
				    oth->ot_storage_th);

	return rc;
}

/**
 * The OSP layer dt_device_operations::dt_trans_stop() interface
 * to stop the transaction.
 *
 * If the transaction is a remote transaction, or the update handler
 * is marked as 'tu_sent_after_local_trans', then related remote
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
	bool			 keep_dt_update = false;
	ENTRY;

	dt_update = oth->ot_dur;
	LASSERT(dt_update != NULL);
	LASSERT(dt_update != LP_POISON);

	/* For remote transaction, if there is local storage thandle,
	 * stop it first */
	if (oth->ot_storage_th != NULL && th->th_top == NULL) {
		dt_trans_stop(env, oth->ot_storage_th->th_dev,
			      oth->ot_storage_th);
		oth->ot_storage_th = NULL;
	}
	/* If there are no updates, destroy dt_update and thandle */
	if (dt_update->dur_buf.ub_req == NULL ||
	    dt_update->dur_buf.ub_req->ourq_count == 0)
		GOTO(out, rc);

	if (is_only_remote_trans(th) && !th->th_sync) {
		struct osp_device *osp = dt2osp_dev(th->th_dev);
		struct client_obd *cli = &osp->opd_obd->u.cli;

		if (th->th_result != 0) {
			rc = th->th_result;
			GOTO(out, rc);
		}

		rc = obd_get_request_slot(cli);
		if (!osp->opd_imp_active || !osp->opd_imp_connected) {
			if (rc == 0)
				obd_put_request_slot(cli);
			rc = -ENOTCONN;
		}
		if (rc != 0)
			GOTO(out, rc);

		rc = osp_trans_trigger(env, dt2osp_dev(dt),
				       dt_update, th, true);
		if (rc != 0)
			obd_put_request_slot(cli);
		else
			keep_dt_update = true;
	} else {
		if (oth->ot_send_updates_after_local_trans ||
		   (is_only_remote_trans(th) && th->th_sync))
			rc = osp_trans_trigger(env, dt2osp_dev(dt), dt_update,
					       th, false);
		rc = dt_update->dur_rc;
	}

out:
	if (!keep_dt_update)
		dt_update_request_destroy(dt_update);
	OBD_FREE_PTR(oth);

	RETURN(rc);
}
