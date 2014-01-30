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

struct update_request *out_find_update(struct thandle *th,
				       struct dt_device *dt_dev)
{
	struct update_request   *update;

	list_for_each_entry(update, &th->th_remote_update_list, ur_list) {
		if (update->ur_dt == dt_dev)
			return update;
	}

	return NULL;
}
EXPORT_SYMBOL(out_find_update);

void out_destroy_update_req(struct update_request *update)
{
	if (update == NULL)
		return;

	LASSERT(list_empty(&update->ur_cb_items));

	list_del(&update->ur_list);
	if (update->ur_buf != NULL)
		OBD_FREE_LARGE(update->ur_buf, UPDATE_BUFFER_SIZE);

	OBD_FREE_PTR(update);
}
EXPORT_SYMBOL(out_destroy_update_req);

struct update_request *out_create_update_req(struct dt_device *dt)
{
	struct update_request *update;

	OBD_ALLOC_PTR(update);
	if (update == NULL)
		return ERR_PTR(-ENOMEM);

	OBD_ALLOC_LARGE(update->ur_buf, UPDATE_BUFFER_SIZE);
	if (update->ur_buf == NULL) {
		OBD_FREE_PTR(update);

		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&update->ur_list);
	update->ur_dt = dt;
	update->ur_buf->ub_magic = UPDATE_BUFFER_MAGIC;
	update->ur_buf->ub_count = 0;
	INIT_LIST_HEAD(&update->ur_cb_items);

	return update;
}
EXPORT_SYMBOL(out_create_update_req);

/**
 * Find one loc in th_dev/dev_obj_update for the update,
 * Because only one thread can access this thandle, no need
 * lock now.
 */
struct update_request *out_find_create_update_loc(struct thandle *th,
						  struct dt_object *dt)
{
	struct dt_device	*dt_dev = lu2dt_dev(dt->do_lu.lo_dev);
	struct update_request	*update;
	ENTRY;

	update = out_find_update(th, dt_dev);
	if (update != NULL)
		RETURN(update);

	update = out_create_update_req(dt_dev);
	if (IS_ERR(update))
		RETURN(update);

	list_add_tail(&update->ur_list, &th->th_remote_update_list);

	RETURN(update);
}
EXPORT_SYMBOL(out_find_create_update_loc);

int out_prep_update_req(const struct lu_env *env, struct obd_import *imp,
			const struct update_buf *ubuf, int ubuf_len,
			struct ptlrpc_request **reqp)
{
	struct ptlrpc_request  *req;
	struct update_buf      *tmp;
	int			rc;
	ENTRY;

	req = ptlrpc_request_alloc(imp, &RQF_UPDATE_OBJ);
	if (req == NULL)
		RETURN(-ENOMEM);

	req_capsule_set_size(&req->rq_pill, &RMF_UPDATE, RCL_CLIENT,
			     UPDATE_BUFFER_SIZE);

	rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, UPDATE_OBJ);
	if (rc != 0) {
		ptlrpc_req_finished(req);
		RETURN(rc);
	}

	req_capsule_set_size(&req->rq_pill, &RMF_UPDATE_REPLY, RCL_SERVER,
			     UPDATE_BUFFER_SIZE);

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_UPDATE);
	memcpy(tmp, ubuf, ubuf_len);
	ptlrpc_request_set_replen(req);
	req->rq_request_portal = OUT_PORTAL;
	req->rq_reply_portal = OSC_REPLY_PORTAL;
	*reqp = req;

	RETURN(rc);
}
EXPORT_SYMBOL(out_prep_update_req);

int out_remote_sync(const struct lu_env *env, struct obd_import *imp,
		    struct update_request *update,
		    struct ptlrpc_request **reqp)
{
	struct ptlrpc_request	*req = NULL;
	int			 rc;
	ENTRY;

	rc = out_prep_update_req(env, imp, update->ur_buf,
				 UPDATE_BUFFER_SIZE, &req);
	if (rc != 0)
		RETURN(rc);

	/* Note: some dt index api might return non-zero result here, like
	 * osd_index_ea_lookup, so we should only check rc < 0 here */
	rc = ptlrpc_queue_wait(req);
	if (rc < 0) {
		ptlrpc_req_finished(req);
		update->ur_rc = rc;
		RETURN(rc);
	}

	if (reqp != NULL) {
		*reqp = req;
	} else {
		update->ur_rc = rc;
		ptlrpc_req_finished(req);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(out_remote_sync);

int out_insert_update(const struct lu_env *env, struct update_request *update,
		      int op, const struct lu_fid *fid, int count,
		      int *lens, const char **bufs)
{
	struct update_buf    *ubuf = update->ur_buf;
	struct update        *obj_update;
	char                 *ptr;
	int                   i;
	int                   update_length;
	ENTRY;

	obj_update = (struct update *)((char *)ubuf +
		      cfs_size_round(update_buf_size(ubuf)));

	/* Check update size to make sure it can fit into the buffer */
	update_length = cfs_size_round(offsetof(struct update,
				       u_bufs[0]));
	for (i = 0; i < count; i++)
		update_length += cfs_size_round(lens[i]);

	if (cfs_size_round(update_buf_size(ubuf)) + update_length >
	    UPDATE_BUFFER_SIZE || ubuf->ub_count >= UPDATE_MAX_OPS)
		RETURN(-E2BIG);

	if (count > UPDATE_BUF_COUNT)
		RETURN(-E2BIG);

	/* fill the update into the update buffer */
	fid_cpu_to_le(&obj_update->u_fid, fid);
	obj_update->u_type = cpu_to_le32(op);
	obj_update->u_batchid = update->ur_batchid;
	for (i = 0; i < count; i++)
		obj_update->u_lens[i] = cpu_to_le32(lens[i]);

	ptr = (char *)obj_update +
			cfs_size_round(offsetof(struct update, u_bufs[0]));
	for (i = 0; i < count; i++)
		LOGL(bufs[i], lens[i], ptr);

	ubuf->ub_count++;

	CDEBUG(D_INFO, "%s: %p "DFID" idx %d: op %d params %d:%lu\n",
	       update->ur_dt->dd_lu_dev.ld_obd->obd_name, ubuf, PFID(fid),
	       ubuf->ub_count, op, count, update_buf_size(ubuf));

	RETURN(0);
}
EXPORT_SYMBOL(out_insert_update);
