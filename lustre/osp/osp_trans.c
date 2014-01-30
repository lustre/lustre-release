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
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * lustre/osp/osp_trans.c
 *
 * Author: Di Wang <di.wang@intel.com>
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "osp_internal.h"

struct osp_async_update_args {
	struct update_request	*oaua_update;
};

struct osp_async_update_item {
	struct list_head		 oaui_list;
	struct osp_object		*oaui_obj;
	void				*oaui_data;
	osp_async_update_interpterer_t	 oaui_interpterer;
};

static struct osp_async_update_item *
osp_async_update_item_init(struct osp_object *obj, void *data,
			   osp_async_update_interpterer_t interpterer)
{
	struct osp_async_update_item *oaui;

	OBD_ALLOC_PTR(oaui);
	if (oaui == NULL)
		return NULL;

	lu_object_get(osp2lu_obj(obj));
	INIT_LIST_HEAD(&oaui->oaui_list);
	oaui->oaui_obj = obj;
	oaui->oaui_data = data;
	oaui->oaui_interpterer = interpterer;

	return oaui;
}

static void osp_async_update_item_fini(const struct lu_env *env,
				       struct osp_async_update_item *oaui)
{
	LASSERT(list_empty(&oaui->oaui_list));

	lu_object_put(env, osp2lu_obj(oaui->oaui_obj));
	OBD_FREE_PTR(oaui);
}

static int osp_async_update_interpret(const struct lu_env *env,
				      struct ptlrpc_request *req,
				      void *arg, int rc)
{
	struct update_reply		*reply	= NULL;
	struct osp_async_update_args	*oaua	= arg;
	struct update_request		*update = oaua->oaua_update;
	struct osp_async_update_item	*oaui;
	struct osp_async_update_item	*next;
	int				 count	= 0;
	int				 index  = 0;
	int				 rc1	= 0;

	if (rc == 0 || req->rq_repmsg != NULL) {
		reply = req_capsule_server_sized_get(&req->rq_pill,
						     &RMF_UPDATE_REPLY,
						     UPDATE_BUFFER_SIZE);
		if (reply == NULL || reply->ur_version != UPDATE_REPLY_V1)
			rc1 = -EPROTO;
		else
			count = reply->ur_count;
	} else {
		rc1 = rc;
	}

	list_for_each_entry_safe(oaui, next, &update->ur_cb_items, oaui_list) {
		list_del_init(&oaui->oaui_list);
		if (index < count && reply->ur_lens[index] > 0) {
			char *ptr = update_get_buf_internal(reply, index, NULL);

			LASSERT(ptr != NULL);

			rc1 = le32_to_cpu(*(int *)ptr);
		} else {
			rc1 = rc;
			if (unlikely(rc1 == 0))
				rc1 = -EINVAL;
		}

		oaui->oaui_interpterer(env, reply, oaui->oaui_obj,
				       oaui->oaui_data, index, rc1);
		osp_async_update_item_fini(env, oaui);
		index++;
	}

	out_destroy_update_req(update);

	return 0;
}

int osp_unplug_async_update(const struct lu_env *env,
			    struct osp_device *osp,
			    struct update_request *update)
{
	struct osp_async_update_args	*args;
	struct ptlrpc_request		*req = NULL;
	int				 rc;

	rc = out_prep_update_req(env, osp->opd_obd->u.cli.cl_import,
				 update->ur_buf, UPDATE_BUFFER_SIZE, &req);
	if (rc != 0) {
		struct osp_async_update_item *oaui;
		struct osp_async_update_item *next;

		list_for_each_entry_safe(oaui, next,
					 &update->ur_cb_items, oaui_list) {
			list_del_init(&oaui->oaui_list);
			oaui->oaui_interpterer(env, NULL, oaui->oaui_obj,
					       oaui->oaui_data, 0, rc);
			osp_async_update_item_fini(env, oaui);
		}
		out_destroy_update_req(update);
	} else {
		LASSERT(list_empty(&update->ur_list));

		args = ptlrpc_req_async_args(req);
		args->oaua_update = update;
		req->rq_interpret_reply = osp_async_update_interpret;
		ptlrpcd_add_req(req, PDL_POLICY_LOCAL, -1);
	}

	return rc;
}

/* with osp::opd_async_requests_mutex held */
struct update_request *
osp_find_or_create_async_update_request(struct osp_device *osp)
{
	struct update_request *update = osp->opd_async_requests;

	if (update != NULL)
		return update;

	update = out_create_update_req(&osp->opd_dt_dev);
	if (!IS_ERR(update))
		osp->opd_async_requests = update;

	return update;
}

/* with osp::opd_async_requests_mutex held */
int osp_insert_async_update(const struct lu_env *env,
			    struct update_request *update, int op,
			    struct osp_object *obj, int count,
			    int *lens, const char **bufs, void *data,
			    osp_async_update_interpterer_t interpterer)
{
	struct osp_async_update_item *oaui;
	struct osp_device	     *osp = lu2osp_dev(osp2lu_obj(obj)->lo_dev);
	int			      rc  = 0;
	ENTRY;

	oaui = osp_async_update_item_init(obj, data, interpterer);
	if (oaui == NULL)
		RETURN(-ENOMEM);

again:
	rc = out_insert_update(env, update, op, lu_object_fid(osp2lu_obj(obj)),
			       count, lens, bufs);
	if (rc == -E2BIG) {
		osp->opd_async_requests = NULL;
		mutex_unlock(&osp->opd_async_requests_mutex);

		rc = osp_unplug_async_update(env, osp, update);
		mutex_lock(&osp->opd_async_requests_mutex);
		if (rc != 0)
			GOTO(out, rc);

		update = osp_find_or_create_async_update_request(osp);
		if (IS_ERR(update))
			GOTO(out, rc = PTR_ERR(update));

		goto again;
	}

	if (rc == 0)
		list_add_tail(&oaui->oaui_list, &update->ur_cb_items);

	GOTO(out, rc);

out:
	if (rc != 0)
		osp_async_update_item_fini(env, oaui);

	return rc;
}

struct thandle *osp_trans_create(const struct lu_env *env,
				 struct dt_device *d)
{
	struct thandle *th;

	OBD_ALLOC_PTR(th);
	if (unlikely(th == NULL))
		return ERR_PTR(-ENOMEM);

	th->th_dev = d;
	th->th_tags = LCT_TX_HANDLE;
	INIT_LIST_HEAD(&th->th_remote_update_list);

	return th;
}

static int osp_trans_trigger(const struct lu_env *env, struct osp_device *osp,
			     struct thandle *th)
{
	struct update_request	*update = th->th_current_request;
	int			 rc	= 0;

	if (unlikely(update == NULL || update->ur_buf == NULL ||
		     update->ur_buf->ub_count == 0))
		return 0;

	if (is_remote_trans(th)) {
		struct osp_async_update_args	*args;
		struct ptlrpc_request		*req;

		list_del_init(&update->ur_list);
		th->th_current_request = NULL;
		rc = out_prep_update_req(env, osp->opd_obd->u.cli.cl_import,
					 update->ur_buf,
					 UPDATE_BUFFER_SIZE, &req);
		if (rc == 0) {
			args = ptlrpc_req_async_args(req);
			args->oaua_update = update;
			req->rq_interpret_reply =
				osp_async_update_interpret;
			ptlrpcd_add_req(req, PDL_POLICY_LOCAL, -1);
		} else {
			out_destroy_update_req(update);
		}
	} else {
		th->th_sync = 1;
		rc = out_remote_sync(env, osp->opd_obd->u.cli.cl_import,
				     update, NULL);
	}

	return rc;
}

int osp_trans_start(const struct lu_env *env, struct dt_device *dt,
		    struct thandle *th)
{
	int rc = 0;

	if (!is_remote_trans(th))
		rc = osp_trans_trigger(env, dt2osp_dev(dt), th);

	return rc;
}

int osp_trans_stop(const struct lu_env *env, struct thandle *th)
{
	struct update_request	*update = th->th_current_request;
	int			 rc	= 0;

	if (is_remote_trans(th)) {
		LASSERT(update == NULL);

		update = out_find_update(th, th->th_dev);
		th->th_current_request = update;
		if (th->th_result == 0)
			rc = osp_trans_trigger(env, dt2osp_dev(th->th_dev), th);
		else
			rc = th->th_result;

		if (th->th_current_request != NULL)
			out_destroy_update_req(update);

		OBD_FREE_PTR(th);
	} else {
		LASSERT(update != NULL);

		rc = update->ur_rc;
		out_destroy_update_req(update);
		th->th_current_request = NULL;
	}

	return rc;
}
