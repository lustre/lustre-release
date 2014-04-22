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
 * lustre/target/out_lib.c
 *
 * Author: Di Wang <di.wang@intel.com>
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <lu_target.h>
#include <lustre_update.h>
#include <obd.h>

struct dt_update_request*
out_find_update(struct thandle_update *tu, struct dt_device *dt_dev)
{
	struct dt_update_request   *dt_update;

	list_for_each_entry(dt_update, &tu->tu_remote_update_list,
			    dur_list) {
		if (dt_update->dur_dt == dt_dev)
			return dt_update;
	}
	return NULL;
}
EXPORT_SYMBOL(out_find_update);

void out_destroy_update_req(struct dt_update_request *dt_update)
{
	if (dt_update == NULL)
		return;

	list_del(&dt_update->dur_list);
	if (dt_update->dur_req != NULL)
		OBD_FREE_LARGE(dt_update->dur_req, dt_update->dur_req_len);

	OBD_FREE_PTR(dt_update);
	return;
}
EXPORT_SYMBOL(out_destroy_update_req);

struct dt_update_request *out_create_update_req(struct dt_device *dt)
{
	struct dt_update_request *dt_update;

	OBD_ALLOC_PTR(dt_update);
	if (!dt_update)
		return ERR_PTR(-ENOMEM);

	OBD_ALLOC_LARGE(dt_update->dur_req, OUT_UPDATE_INIT_BUFFER_SIZE);
	if (dt_update->dur_req == NULL) {
		OBD_FREE_PTR(dt_update);
		return ERR_PTR(-ENOMEM);
	}

	dt_update->dur_req_len = OUT_UPDATE_INIT_BUFFER_SIZE;
	INIT_LIST_HEAD(&dt_update->dur_list);
	dt_update->dur_dt = dt;
	dt_update->dur_batchid = 0;
	dt_update->dur_req->ourq_magic = UPDATE_REQUEST_MAGIC;
	dt_update->dur_req->ourq_count = 0;
	INIT_LIST_HEAD(&dt_update->dur_cb_items);

	return dt_update;
}
EXPORT_SYMBOL(out_create_update_req);

/**
 * Find or create one loc in th_dev/dev_obj_update for the update,
 * Because only one thread can access this thandle, no need
 * lock now.
 */
struct dt_update_request *out_find_create_update_loc(struct thandle *th,
						  struct dt_object *dt)
{
	struct dt_device	*dt_dev = lu2dt_dev(dt->do_lu.lo_dev);
	struct thandle_update	*tu = th->th_update;
	struct dt_update_request *update;
	ENTRY;

	if (tu == NULL) {
		OBD_ALLOC_PTR(tu);
		if (tu == NULL)
			RETURN(ERR_PTR(-ENOMEM));

		INIT_LIST_HEAD(&tu->tu_remote_update_list);
		tu->tu_sent_after_local_trans = 0;
		th->th_update = tu;
	}

	update = out_find_update(tu, dt_dev);
	if (update != NULL)
		RETURN(update);

	update = out_create_update_req(dt_dev);
	if (IS_ERR(update))
		RETURN(update);

	list_add_tail(&update->dur_list, &tu->tu_remote_update_list);

	if (!tu->tu_only_remote_trans)
		thandle_get(th);

	RETURN(update);
}
EXPORT_SYMBOL(out_find_create_update_loc);

int out_prep_update_req(const struct lu_env *env, struct obd_import *imp,
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
EXPORT_SYMBOL(out_prep_update_req);

int out_remote_sync(const struct lu_env *env, struct obd_import *imp,
		    struct dt_update_request *dt_update,
		    struct ptlrpc_request **reqp)
{
	struct ptlrpc_request	*req = NULL;
	int			rc;
	ENTRY;

	rc = out_prep_update_req(env, imp, dt_update->dur_req, &req);
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
EXPORT_SYMBOL(out_remote_sync);

static int out_resize_update_req(struct dt_update_request *dt_update,
				 int new_size)
{
	struct object_update_request *ureq;

	LASSERT(new_size > dt_update->dur_req_len);

	CDEBUG(D_INFO, "%s: resize update_size from %d to %d\n",
	       dt_update->dur_dt->dd_lu_dev.ld_obd->obd_name,
	       dt_update->dur_req_len, new_size);

	OBD_ALLOC_LARGE(ureq, new_size);
	if (ureq == NULL)
		return -ENOMEM;

	memcpy(ureq, dt_update->dur_req,
	       object_update_request_size(dt_update->dur_req));

	OBD_FREE_LARGE(dt_update->dur_req, dt_update->dur_req_len);

	dt_update->dur_req = ureq;
	dt_update->dur_req_len = new_size;

	return 0;
}

#define OUT_UPDATE_BUFFER_SIZE_ADD	4096
#define OUT_UPDATE_BUFFER_SIZE_MAX	(64 * 4096)  /* 64KB update size now */
/**
 * Insert the update into the th_bufs for the device.
 */

int out_insert_update(const struct lu_env *env,
		      struct dt_update_request *update, int op,
		      const struct lu_fid *fid, int params_count, int *lens,
		      const char **bufs)
{
	struct object_update_request	*ureq = update->dur_req;
	int				ureq_len;
	struct object_update		*obj_update;
	struct object_update_param	*param;
	int				update_length;
	int				rc = 0;
	char				*ptr;
	int				i;
	ENTRY;

	/* Check update size to make sure it can fit into the buffer */
	ureq_len = object_update_request_size(ureq);
	update_length = offsetof(struct object_update, ou_params[0]);
	for (i = 0; i < params_count; i++)
		update_length += cfs_size_round(lens[i] + sizeof(*param));

	if (unlikely(cfs_size_round(ureq_len + update_length) >
		     update->dur_req_len)) {
		int new_size = update->dur_req_len;

		/* enlarge object update request size */
		while (new_size <
		       cfs_size_round(ureq_len + update_length))
			new_size += OUT_UPDATE_BUFFER_SIZE_ADD;
		if (new_size >= OUT_UPDATE_BUFFER_SIZE_MAX)
			RETURN(-E2BIG);

		rc = out_resize_update_req(update, new_size);
		if (rc != 0)
			RETURN(rc);

		ureq = update->dur_req;
	}

	/* fill the update into the update buffer */
	obj_update = (struct object_update *)((char *)ureq + ureq_len);
	obj_update->ou_fid = *fid;
	obj_update->ou_type = op;
	obj_update->ou_params_count = (__u16)params_count;
	obj_update->ou_batchid = update->dur_batchid;
	param = &obj_update->ou_params[0];
	for (i = 0; i < params_count; i++) {
		param->oup_len = lens[i];
		ptr = &param->oup_buf[0];
		memcpy(&param->oup_buf[0], bufs[i], lens[i]);
		param = (struct object_update_param *)((char *)param +
			 object_update_param_size(param));
	}

	ureq->ourq_count++;

	CDEBUG(D_INFO, "%s: %p "DFID" idx %d: op %d params %d:%d\n",
	       update->dur_dt->dd_lu_dev.ld_obd->obd_name, ureq, PFID(fid),
	       ureq->ourq_count, op, params_count, ureq_len + update_length);

	RETURN(rc);
}
EXPORT_SYMBOL(out_insert_update);
