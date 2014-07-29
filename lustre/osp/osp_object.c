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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osp/osp_object.c
 *
 * Lustre OST Proxy Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.tappro@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "osp_internal.h"

static inline __u32 osp_dev2node(struct osp_device *osp)
{
	return osp->opd_storage->dd_lu_dev.ld_site->ld_seq_site->ss_node_id;
}

static inline bool is_ost_obj(struct lu_object *lo)
{
	return !lu2osp_dev(lo->lo_dev)->opd_connect_mdt;
}

static void osp_object_assign_fid(const struct lu_env *env,
				  struct osp_device *d, struct osp_object *o)
{
	struct osp_thread_info *osi = osp_env_info(env);

	LASSERT(fid_is_zero(lu_object_fid(&o->opo_obj.do_lu)));
	LASSERT(o->opo_reserved);
	o->opo_reserved = 0;

	osp_precreate_get_fid(env, d, &osi->osi_fid);

	lu_object_assign_fid(env, &o->opo_obj.do_lu, &osi->osi_fid);
}

static int osp_oac_init(struct osp_object *obj)
{
	struct osp_object_attr *ooa;

	OBD_ALLOC_PTR(ooa);
	if (ooa == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&ooa->ooa_xattr_list);
	spin_lock(&obj->opo_lock);
	if (likely(obj->opo_ooa == NULL)) {
		obj->opo_ooa = ooa;
		spin_unlock(&obj->opo_lock);
	} else {
		spin_unlock(&obj->opo_lock);
		OBD_FREE_PTR(ooa);
	}

	return 0;
}

static struct osp_xattr_entry *
osp_oac_xattr_find_locked(struct osp_object_attr *ooa,
			  const char *name, size_t namelen)
{
	struct osp_xattr_entry *oxe;

	list_for_each_entry(oxe, &ooa->ooa_xattr_list, oxe_list) {
		if (namelen == oxe->oxe_namelen &&
		    strncmp(name, oxe->oxe_buf, namelen) == 0)
			return oxe;
	}

	return NULL;
}

static struct osp_xattr_entry *osp_oac_xattr_find(struct osp_object *obj,
						  const char *name, bool unlink)
{
	struct osp_xattr_entry *oxe = NULL;

	spin_lock(&obj->opo_lock);
	if (obj->opo_ooa != NULL) {
		oxe = osp_oac_xattr_find_locked(obj->opo_ooa, name,
						strlen(name));
		if (oxe != NULL) {
			if (unlink)
				list_del_init(&oxe->oxe_list);
			else
				atomic_inc(&oxe->oxe_ref);
		}
	}
	spin_unlock(&obj->opo_lock);

	return oxe;
}

static struct osp_xattr_entry *
osp_oac_xattr_find_or_add(struct osp_object *obj, const char *name, size_t len)
{
	struct osp_object_attr *ooa	= obj->opo_ooa;
	struct osp_xattr_entry *oxe;
	struct osp_xattr_entry *tmp	= NULL;
	size_t			namelen = strlen(name);
	size_t			size	= sizeof(*oxe) + namelen + 1 + len;

	LASSERT(ooa != NULL);

	oxe = osp_oac_xattr_find(obj, name, false);
	if (oxe != NULL)
		return oxe;

	OBD_ALLOC(oxe, size);
	if (unlikely(oxe == NULL))
		return NULL;

	INIT_LIST_HEAD(&oxe->oxe_list);
	oxe->oxe_buflen = size;
	oxe->oxe_namelen = namelen;
	memcpy(oxe->oxe_buf, name, namelen);
	oxe->oxe_value = oxe->oxe_buf + namelen + 1;
	/* One ref is for the caller, the other is for the entry on the list. */
	atomic_set(&oxe->oxe_ref, 2);

	spin_lock(&obj->opo_lock);
	tmp = osp_oac_xattr_find_locked(ooa, name, namelen);
	if (tmp == NULL)
		list_add_tail(&oxe->oxe_list, &ooa->ooa_xattr_list);
	else
		atomic_inc(&tmp->oxe_ref);
	spin_unlock(&obj->opo_lock);

	if (tmp != NULL) {
		OBD_FREE(oxe, size);
		oxe = tmp;
	}

	return oxe;
}

static struct osp_xattr_entry *
osp_oac_xattr_replace(struct osp_object *obj,
		      struct osp_xattr_entry **poxe, size_t len)
{
	struct osp_object_attr *ooa	= obj->opo_ooa;
	struct osp_xattr_entry *oxe;
	size_t			namelen = (*poxe)->oxe_namelen;
	size_t			size	= sizeof(*oxe) + namelen + 1 + len;

	LASSERT(ooa != NULL);

	OBD_ALLOC(oxe, size);
	if (unlikely(oxe == NULL))
		return NULL;

	INIT_LIST_HEAD(&oxe->oxe_list);
	oxe->oxe_buflen = size;
	oxe->oxe_namelen = namelen;
	memcpy(oxe->oxe_buf, (*poxe)->oxe_buf, namelen);
	oxe->oxe_value = oxe->oxe_buf + namelen + 1;
	/* One ref is for the caller, the other is for the entry on the list. */
	atomic_set(&oxe->oxe_ref, 2);

	spin_lock(&obj->opo_lock);
	*poxe = osp_oac_xattr_find_locked(ooa, oxe->oxe_buf, namelen);
	LASSERT(*poxe != NULL);

	list_del_init(&(*poxe)->oxe_list);
	list_add_tail(&oxe->oxe_list, &ooa->ooa_xattr_list);
	spin_unlock(&obj->opo_lock);

	return oxe;
}

static inline void osp_oac_xattr_put(struct osp_xattr_entry *oxe)
{
	if (atomic_dec_and_test(&oxe->oxe_ref)) {
		LASSERT(list_empty(&oxe->oxe_list));

		OBD_FREE(oxe, oxe->oxe_buflen);
	}
}

static int osp_get_attr_from_reply(const struct lu_env *env,
				   struct object_update_reply *reply,
				   struct ptlrpc_request *req,
				   struct lu_attr *attr,
				   struct osp_object *obj, int index)
{
	struct osp_thread_info	*osi	= osp_env_info(env);
	struct lu_buf		*rbuf	= &osi->osi_lb2;
	struct obdo		*lobdo	= &osi->osi_obdo;
	struct obdo		*wobdo;
	int			rc;

	rc = object_update_result_data_get(reply, rbuf, index);
	if (rc < 0)
		return rc;

	wobdo = rbuf->lb_buf;
	if (rbuf->lb_len != sizeof(*wobdo))
		return -EPROTO;

	LASSERT(req != NULL);
	if (ptlrpc_req_need_swab(req))
		lustre_swab_obdo(wobdo);

	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	spin_lock(&obj->opo_lock);
	if (obj->opo_ooa != NULL) {
		la_from_obdo(&obj->opo_ooa->ooa_attr, lobdo, lobdo->o_valid);
		if (attr != NULL)
			*attr = obj->opo_ooa->ooa_attr;
	} else {
		LASSERT(attr != NULL);

		la_from_obdo(attr, lobdo, lobdo->o_valid);
	}
	spin_unlock(&obj->opo_lock);

	return 0;
}

static int osp_attr_get_interpterer(const struct lu_env *env,
				    struct object_update_reply *reply,
				    struct ptlrpc_request *req,
				    struct osp_object *obj,
				    void *data, int index, int rc)
{
	struct lu_attr *attr = data;

	LASSERT(obj->opo_ooa != NULL);

	if (rc == 0) {
		osp2lu_obj(obj)->lo_header->loh_attr |= LOHA_EXISTS;
		obj->opo_non_exist = 0;

		return osp_get_attr_from_reply(env, reply, req, NULL, obj,
					       index);
	} else {
		if (rc == -ENOENT) {
			osp2lu_obj(obj)->lo_header->loh_attr &= ~LOHA_EXISTS;
			obj->opo_non_exist = 1;
		}

		spin_lock(&obj->opo_lock);
		attr->la_valid = 0;
		spin_unlock(&obj->opo_lock);
	}

	return 0;
}

static int osp_declare_attr_get(const struct lu_env *env, struct dt_object *dt,
				struct lustre_capa *capa)
{
	struct osp_object	*obj	= dt2osp_obj(dt);
	struct osp_device	*osp	= lu2osp_dev(dt->do_lu.lo_dev);
	int			 rc	= 0;

	if (obj->opo_ooa == NULL) {
		rc = osp_oac_init(obj);
		if (rc != 0)
			return rc;
	}

	mutex_lock(&osp->opd_async_requests_mutex);
	rc = osp_insert_async_request(env, OUT_ATTR_GET, obj, 0, NULL, NULL,
				      &obj->opo_ooa->ooa_attr,
				      osp_attr_get_interpterer);
	mutex_unlock(&osp->opd_async_requests_mutex);

	return rc;
}

int osp_attr_get(const struct lu_env *env, struct dt_object *dt,
		 struct lu_attr *attr, struct lustre_capa *capa)
{
	struct osp_device		*osp = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object		*obj = dt2osp_obj(dt);
	struct dt_device		*dev = &osp->opd_dt_dev;
	struct dt_update_request	*update;
	struct object_update_reply	*reply;
	struct ptlrpc_request		*req = NULL;
	int				rc = 0;
	ENTRY;

	if (is_ost_obj(&dt->do_lu) && obj->opo_non_exist)
		RETURN(-ENOENT);

	if (obj->opo_ooa != NULL) {
		spin_lock(&obj->opo_lock);
		if (obj->opo_ooa->ooa_attr.la_valid != 0) {
			*attr = obj->opo_ooa->ooa_attr;
			spin_unlock(&obj->opo_lock);

			RETURN(0);
		}
		spin_unlock(&obj->opo_lock);
	}

	update = out_create_update_req(dev);
	if (IS_ERR(update))
		RETURN(PTR_ERR(update));

	rc = out_insert_update(env, update, OUT_ATTR_GET,
			       lu_object_fid(&dt->do_lu), 0, NULL, NULL);
	if (rc != 0) {
		CERROR("%s: Insert update error "DFID": rc = %d\n",
		       dev->dd_lu_dev.ld_obd->obd_name,
		       PFID(lu_object_fid(&dt->do_lu)), rc);

		GOTO(out, rc);
	}

	rc = out_remote_sync(env, osp->opd_obd->u.cli.cl_import, update, &req);
	if (rc != 0) {
		if (rc == -ENOENT) {
			osp2lu_obj(obj)->lo_header->loh_attr &= ~LOHA_EXISTS;
			obj->opo_non_exist = 1;
		} else {
			CERROR("%s:osp_attr_get update error "DFID": rc = %d\n",
			       dev->dd_lu_dev.ld_obd->obd_name,
			       PFID(lu_object_fid(&dt->do_lu)), rc);
		}

		GOTO(out, rc);
	}

	osp2lu_obj(obj)->lo_header->loh_attr |= LOHA_EXISTS;
	obj->opo_non_exist = 0;
	reply = req_capsule_server_sized_get(&req->rq_pill,
					     &RMF_OUT_UPDATE_REPLY,
					     OUT_UPDATE_REPLY_SIZE);
	if (reply == NULL || reply->ourp_magic != UPDATE_REPLY_MAGIC)
		GOTO(out, rc = -EPROTO);

	rc = osp_get_attr_from_reply(env, reply, req, attr, obj, 0);
	if (rc != 0)
		GOTO(out, rc);

	GOTO(out, rc = 0);

out:
	if (req != NULL)
		ptlrpc_req_finished(req);

	out_destroy_update_req(update);

	return rc;
}

static int __osp_attr_set(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_attr *attr, struct thandle *th)
{
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*o = dt2osp_obj(dt);
	struct lu_attr		*la;
	int			 rc = 0;
	ENTRY;

	/*
	 * Usually we don't allow server stack to manipulate size
	 * but there is a special case when striping is created
	 * late, after stripless file got truncated to non-zero.
	 *
	 * In this case we do the following:
	 *
	 * 1) grab id in declare - this can lead to leaked OST objects
	 *    but we don't currently have proper mechanism and the only
	 *    options we have are to do truncate RPC holding transaction
	 *    open (very bad) or to grab id in declare at cost of leaked
	 *    OST object in same very rare unfortunate case (just bad)
	 *    notice 1.6-2.0 do assignment outside of running transaction
	 *    all the time, meaning many more chances for leaked objects.
	 *
	 * 2) send synchronous truncate RPC with just assigned id
	 */

	/* there are few places in MDD code still passing NULL
	 * XXX: to be fixed soon */
	if (attr == NULL)
		RETURN(0);

	if (attr->la_valid & LA_SIZE && attr->la_size > 0 &&
	    fid_is_zero(lu_object_fid(&o->opo_obj.do_lu))) {
		LASSERT(!dt_object_exists(dt));
		osp_object_assign_fid(env, d, o);
		rc = osp_object_truncate(env, dt, attr->la_size);
		if (rc)
			RETURN(rc);
	}

	if (o->opo_new)
		/* no need in logging for new objects being created */
		RETURN(0);

	if (!(attr->la_valid & (LA_UID | LA_GID)))
		RETURN(0);

	if (!is_only_remote_trans(th))
		/*
		 * track all UID/GID changes via llog
		 */
		rc = osp_sync_declare_add(env, o, MDS_SETATTR64_REC, th);
	else
		/* It is for OST-object attr_set directly without updating
		 * local MDT-object attribute. It is usually used by LFSCK. */
		rc = osp_md_declare_attr_set(env, dt, attr, th);

	if (rc != 0 || o->opo_ooa == NULL)
		RETURN(rc);

	/* Update the OSP object attributes cache. */
	la = &o->opo_ooa->ooa_attr;
	spin_lock(&o->opo_lock);
	if (attr->la_valid & LA_UID) {
		la->la_uid = attr->la_uid;
		la->la_valid |= LA_UID;
	}

	if (attr->la_valid & LA_GID) {
		la->la_gid = attr->la_gid;
		la->la_valid |= LA_GID;
	}
	spin_unlock(&o->opo_lock);

	RETURN(0);
}

/**
 * XXX: NOT prepare set_{attr,xattr} RPC for remote transaction.
 *
 * According to our current transaction/dt_object_lock framework (to make
 * the cross-MDTs modification for DNE1 to be workable), the transaction
 * sponsor will start the transaction firstly, then try to acquire related
 * dt_object_lock if needed. Under such rules, if we want to prepare the
 * set_{attr,xattr} RPC in the RPC declare phase, then related attr/xattr
 * should be known without dt_object_lock. But such condition maybe not
 * true for some remote transaction case. For example:
 *
 * For linkEA repairing (by LFSCK) case, before the LFSCK thread obtained
 * the dt_object_lock on the target MDT-object, it cannot know whether
 * the MDT-object has linkEA or not, neither invalid or not.
 *
 * Since the LFSCK thread cannot hold dt_object_lock before the (remote)
 * transaction start (otherwise there will be some potential deadlock),
 * it cannot prepare related RPC for repairing during the declare phase
 * as other normal transactions do.
 *
 * To resolve the trouble, we will make OSP to prepare related RPC
 * (set_attr/set_xattr/del_xattr) after remote transaction started,
 * and trigger the remote updating (RPC sending) when trans_stop.
 * Then the up layer users, such as LFSCK, can follow the general
 * rule to handle trans_start/dt_object_lock for repairing linkEA
 * inconsistency without distinguishing remote MDT-object.
 *
 * In fact, above solution for remote transaction should be the normal
 * model without considering DNE1. The trouble brought by DNE1 will be
 * resolved in DNE2. At that time, this patch can be removed.
 */
static int osp_declare_attr_set(const struct lu_env *env, struct dt_object *dt,
				const struct lu_attr *attr, struct thandle *th)
{
	int rc = 0;

	if (!is_only_remote_trans(th))
		rc = __osp_attr_set(env, dt, attr, th);

	return rc;
}

static int osp_attr_set(const struct lu_env *env, struct dt_object *dt,
			const struct lu_attr *attr, struct thandle *th,
			struct lustre_capa *capa)
{
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;
	ENTRY;

	if (is_only_remote_trans(th)) {
		rc = __osp_attr_set(env, dt, attr, th);
		if (rc != 0)
			RETURN(rc);
	}

	/* we're interested in uid/gid changes only */
	if (!(attr->la_valid & (LA_UID | LA_GID)))
		RETURN(0);

	/* new object, the very first ->attr_set()
	 * initializing attributes needs no logging
	 * all subsequent one are subject to the
	 * logging and synchronization with OST */
	if (o->opo_new) {
		o->opo_new = 0;
		RETURN(0);
	}

	if (!is_only_remote_trans(th))
		/*
		 * once transaction is committed put proper command on
		 * the queue going to our OST
		 */
		rc = osp_sync_add(env, o, MDS_SETATTR64_REC, th, attr);
		/* XXX: send new uid/gid to OST ASAP? */
	else
		/* It is for OST-object attr_set directly without updating
		 * local MDT-object attribute. It is usually used by LFSCK. */
		rc = osp_md_attr_set(env, dt, attr, th, capa);

	RETURN(rc);
}

static int osp_xattr_get_interpterer(const struct lu_env *env,
				     struct object_update_reply *reply,
				     struct ptlrpc_request *req,
				     struct osp_object *obj,
				     void *data, int index, int rc)
{
	struct osp_object_attr	*ooa  = obj->opo_ooa;
	struct osp_xattr_entry	*oxe  = data;
	struct lu_buf		*rbuf = &osp_env_info(env)->osi_lb2;

	LASSERT(ooa != NULL);

	if (rc == 0) {
		size_t len = sizeof(*oxe) + oxe->oxe_namelen + 1;

		rc = object_update_result_data_get(reply, rbuf, index);
		if (rc < 0 || rbuf->lb_len > (oxe->oxe_buflen - len)) {
			spin_lock(&obj->opo_lock);
			oxe->oxe_ready = 0;
			spin_unlock(&obj->opo_lock);
			osp_oac_xattr_put(oxe);

			return rc < 0 ? rc : -ERANGE;
		}

		spin_lock(&obj->opo_lock);
		oxe->oxe_vallen = rbuf->lb_len;
		memcpy(oxe->oxe_value, rbuf->lb_buf, rbuf->lb_len);
		oxe->oxe_exist = 1;
		oxe->oxe_ready = 1;
		spin_unlock(&obj->opo_lock);
	} else if (rc == -ENOENT || rc == -ENODATA) {
		spin_lock(&obj->opo_lock);
		oxe->oxe_exist = 0;
		oxe->oxe_ready = 1;
		spin_unlock(&obj->opo_lock);
	} else {
		spin_lock(&obj->opo_lock);
		oxe->oxe_ready = 0;
		spin_unlock(&obj->opo_lock);
	}

	osp_oac_xattr_put(oxe);

	return 0;
}

static int osp_declare_xattr_get(const struct lu_env *env, struct dt_object *dt,
				 struct lu_buf *buf, const char *name,
				 struct lustre_capa *capa)
{
	struct osp_object	*obj	 = dt2osp_obj(dt);
	struct osp_device	*osp	 = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_xattr_entry	*oxe;
	int			 namelen = strlen(name);
	int			 rc	 = 0;

	LASSERT(buf != NULL);
	LASSERT(name != NULL);

	/* If only for xattr size, return directly. */
	if (unlikely(buf->lb_len == 0))
		return 0;

	if (obj->opo_ooa == NULL) {
		rc = osp_oac_init(obj);
		if (rc != 0)
			return rc;
	}

	oxe = osp_oac_xattr_find_or_add(obj, name, buf->lb_len);
	if (oxe == NULL)
		return -ENOMEM;

	mutex_lock(&osp->opd_async_requests_mutex);
	rc = osp_insert_async_request(env, OUT_XATTR_GET, obj, 1,
				      &namelen, &name, oxe,
				      osp_xattr_get_interpterer);
	if (rc != 0) {
		mutex_unlock(&osp->opd_async_requests_mutex);
		osp_oac_xattr_put(oxe);
	} else {
		struct dt_update_request *update;

		/* XXX: Currently, we trigger the batched async OUT
		 *	RPC via dt_declare_xattr_get(). It is not
		 *	perfect solution, but works well now.
		 *
		 *	We will improve it in the future. */
		update = osp->opd_async_requests;
		if (update != NULL && update->dur_req != NULL &&
		    update->dur_req->ourq_count > 0) {
			osp->opd_async_requests = NULL;
			mutex_unlock(&osp->opd_async_requests_mutex);
			rc = osp_unplug_async_request(env, osp, update);
		} else {
			mutex_unlock(&osp->opd_async_requests_mutex);
		}
	}

	return rc;
}

int osp_xattr_get(const struct lu_env *env, struct dt_object *dt,
		  struct lu_buf *buf, const char *name,
		  struct lustre_capa *capa)
{
	struct osp_device	*osp	= lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*obj	= dt2osp_obj(dt);
	struct dt_device	*dev	= &osp->opd_dt_dev;
	struct lu_buf		*rbuf	= &osp_env_info(env)->osi_lb2;
	struct dt_update_request *update = NULL;
	struct ptlrpc_request	*req	= NULL;
	struct object_update_reply *reply;
	struct osp_xattr_entry	*oxe	= NULL;
	const char		*dname  = dt->do_lu.lo_dev->ld_obd->obd_name;
	int			 namelen;
	int			 rc	= 0;
	ENTRY;

	LASSERT(buf != NULL);
	LASSERT(name != NULL);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_NETWORK) &&
	    osp->opd_index == cfs_fail_val &&
	    osp_dev2node(osp) == cfs_fail_val)
		RETURN(-ENOTCONN);

	if (unlikely(obj->opo_non_exist))
		RETURN(-ENOENT);

	oxe = osp_oac_xattr_find(obj, name, false);
	if (oxe != NULL) {
		spin_lock(&obj->opo_lock);
		if (oxe->oxe_ready) {
			if (!oxe->oxe_exist)
				GOTO(unlock, rc = -ENODATA);

			if (buf->lb_buf == NULL)
				GOTO(unlock, rc = oxe->oxe_vallen);

			if (buf->lb_len < oxe->oxe_vallen)
				GOTO(unlock, rc = -ERANGE);

			memcpy(buf->lb_buf, oxe->oxe_value, oxe->oxe_vallen);

			GOTO(unlock, rc = oxe->oxe_vallen);

unlock:
			spin_unlock(&obj->opo_lock);
			osp_oac_xattr_put(oxe);

			return rc;
		}
		spin_unlock(&obj->opo_lock);
	}

	update = out_create_update_req(dev);
	if (IS_ERR(update))
		GOTO(out, rc = PTR_ERR(update));

	namelen = strlen(name) + 1;
	rc = out_insert_update(env, update, OUT_XATTR_GET,
			       lu_object_fid(&dt->do_lu), 1, &namelen, &name);
	if (rc != 0) {
		CERROR("%s: Insert update error "DFID": rc = %d\n",
		       dname, PFID(lu_object_fid(&dt->do_lu)), rc);

		GOTO(out, rc);
	}

	rc = out_remote_sync(env, osp->opd_obd->u.cli.cl_import, update, &req);
	if (rc != 0) {
		if (obj->opo_ooa == NULL)
			GOTO(out, rc);

		if (oxe == NULL)
			oxe = osp_oac_xattr_find_or_add(obj, name, buf->lb_len);

		if (oxe == NULL) {
			CWARN("%s: Fail to add xattr (%s) to cache for "
			      DFID" (1): rc = %d\n", dname, name,
			      PFID(lu_object_fid(&dt->do_lu)), rc);

			GOTO(out, rc);
		}

		spin_lock(&obj->opo_lock);
		if (rc == -ENOENT || rc == -ENODATA) {
			oxe->oxe_exist = 0;
			oxe->oxe_ready = 1;
		} else {
			oxe->oxe_ready = 0;
		}
		spin_unlock(&obj->opo_lock);

		GOTO(out, rc);
	}

	reply = req_capsule_server_sized_get(&req->rq_pill,
					     &RMF_OUT_UPDATE_REPLY,
					     OUT_UPDATE_REPLY_SIZE);
	if (reply->ourp_magic != UPDATE_REPLY_MAGIC) {
		CERROR("%s: Wrong version %x expected %x "DFID": rc = %d\n",
		       dname, reply->ourp_magic, UPDATE_REPLY_MAGIC,
		       PFID(lu_object_fid(&dt->do_lu)), -EPROTO);

		GOTO(out, rc = -EPROTO);
	}

	rc = object_update_result_data_get(reply, rbuf, 0);
	if (rc < 0)
		GOTO(out, rc);

	if (buf->lb_buf == NULL)
		GOTO(out, rc = rbuf->lb_len);

	if (unlikely(buf->lb_len < rbuf->lb_len))
		GOTO(out, rc = -ERANGE);

	memcpy(buf->lb_buf, rbuf->lb_buf, rbuf->lb_len);
	rc = rbuf->lb_len;
	if (obj->opo_ooa == NULL)
		GOTO(out, rc);

	if (oxe == NULL) {
		oxe = osp_oac_xattr_find_or_add(obj, name, rbuf->lb_len);
		if (oxe == NULL) {
			CWARN("%s: Fail to add xattr (%s) to "
			      "cache for "DFID" (2): rc = %d\n",
			      dname, name, PFID(lu_object_fid(&dt->do_lu)), rc);

			GOTO(out, rc);
		}
	}

	if (oxe->oxe_buflen - oxe->oxe_namelen - 1 < rbuf->lb_len) {
		struct osp_xattr_entry *old = oxe;
		struct osp_xattr_entry *tmp;

		tmp = osp_oac_xattr_replace(obj, &old, rbuf->lb_len);
		osp_oac_xattr_put(oxe);
		oxe = tmp;
		if (tmp == NULL) {
			CWARN("%s: Fail to update xattr (%s) to "
			      "cache for "DFID": rc = %d\n",
			      dname, name, PFID(lu_object_fid(&dt->do_lu)), rc);
			spin_lock(&obj->opo_lock);
			old->oxe_ready = 0;
			spin_unlock(&obj->opo_lock);

			GOTO(out, rc);
		}

		/* Drop the ref for entry on list. */
		osp_oac_xattr_put(old);
	}

	spin_lock(&obj->opo_lock);
	oxe->oxe_vallen = rbuf->lb_len;
	memcpy(oxe->oxe_value, rbuf->lb_buf, rbuf->lb_len);
	oxe->oxe_exist = 1;
	oxe->oxe_ready = 1;
	spin_unlock(&obj->opo_lock);

	GOTO(out, rc);

out:
	if (req != NULL)
		ptlrpc_req_finished(req);

	if (update != NULL && !IS_ERR(update))
		out_destroy_update_req(update);

	if (oxe != NULL)
		osp_oac_xattr_put(oxe);

	return rc;
}

static int __osp_xattr_set(const struct lu_env *env, struct dt_object *dt,
			   const struct lu_buf *buf, const char *name,
			   int flag, struct thandle *th)
{
	struct dt_update_request *update;
	struct lu_fid		 *fid;
	int			 sizes[3]	= { strlen(name),
						    buf->lb_len,
						    sizeof(int) };
	char			 *bufs[3]	= { (char *)name,
						    (char *)buf->lb_buf };
	struct osp_xattr_entry	 *oxe;
	struct osp_object	 *o		= dt2osp_obj(dt);
	int			 rc;
	ENTRY;

	LASSERT(buf->lb_len > 0 && buf->lb_buf != NULL);

	update = out_find_create_update_loc(th, dt);
	if (IS_ERR(update)) {
		CERROR("%s: Get OSP update buf failed "DFID": rc = %d\n",
		       dt->do_lu.lo_dev->ld_obd->obd_name,
		       PFID(lu_object_fid(&dt->do_lu)),
		       (int)PTR_ERR(update));

		RETURN(PTR_ERR(update));
	}

	flag = cpu_to_le32(flag);
	bufs[2] = (char *)&flag;

	fid = (struct lu_fid *)lu_object_fid(&dt->do_lu);
	rc = out_insert_update(env, update, OUT_XATTR_SET, fid,
			       ARRAY_SIZE(sizes), sizes, (const char **)bufs);
	if (rc != 0 || o->opo_ooa == NULL)
		RETURN(rc);

	oxe = osp_oac_xattr_find_or_add(o, name, buf->lb_len);
	if (oxe == NULL) {
		CWARN("%s: Fail to add xattr (%s) to cache for "DFID,
		      dt->do_lu.lo_dev->ld_obd->obd_name,
		      name, PFID(lu_object_fid(&dt->do_lu)));

		RETURN(0);
	}

	if (oxe->oxe_buflen - oxe->oxe_namelen - 1 < buf->lb_len) {
		struct osp_xattr_entry *old = oxe;
		struct osp_xattr_entry *tmp;

		tmp = osp_oac_xattr_replace(o, &old, buf->lb_len);
		osp_oac_xattr_put(oxe);
		oxe = tmp;
		if (tmp == NULL) {
			CWARN("%s: Fail to update xattr (%s) to cache for "DFID,
			      dt->do_lu.lo_dev->ld_obd->obd_name,
			      name, PFID(lu_object_fid(&dt->do_lu)));
			spin_lock(&o->opo_lock);
			old->oxe_ready = 0;
			spin_unlock(&o->opo_lock);

			RETURN(0);
		}

		/* Drop the ref for entry on list. */
		osp_oac_xattr_put(old);
	}

	spin_lock(&o->opo_lock);
	oxe->oxe_vallen = buf->lb_len;
	memcpy(oxe->oxe_value, buf->lb_buf, buf->lb_len);
	oxe->oxe_exist = 1;
	oxe->oxe_ready = 1;
	spin_unlock(&o->opo_lock);
	osp_oac_xattr_put(oxe);

	RETURN(0);
}

int osp_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *buf, const char *name,
			  int flag, struct thandle *th)
{
	int rc = 0;

	/* Please check the comment in osp_attr_set() for handling
	 * remote transaction. */
	if (!is_only_remote_trans(th))
		rc = __osp_xattr_set(env, dt, buf, name, flag, th);

	return rc;
}

int osp_xattr_set(const struct lu_env *env, struct dt_object *dt,
		  const struct lu_buf *buf, const char *name, int fl,
		  struct thandle *th, struct lustre_capa *capa)
{
	int rc = 0;

	CDEBUG(D_INFO, "xattr %s set object "DFID"\n", name,
	       PFID(&dt->do_lu.lo_header->loh_fid));

	/* Please check the comment in osp_attr_set() for handling
	 * remote transaction. */
	if (is_only_remote_trans(th))
		rc = __osp_xattr_set(env, dt, buf, name, fl, th);

	return rc;
}

static int __osp_xattr_del(const struct lu_env *env, struct dt_object *dt,
			   const char *name, struct thandle *th)
{
	struct dt_update_request *update;
	const struct lu_fid	 *fid;
	struct osp_object	 *o	= dt2osp_obj(dt);
	struct osp_xattr_entry	 *oxe;
	int			  size	= strlen(name);
	int			  rc;

	update = out_find_create_update_loc(th, dt);
	if (IS_ERR(update))
		return PTR_ERR(update);

	fid = lu_object_fid(&dt->do_lu);

	rc = out_insert_update(env, update, OUT_XATTR_DEL, fid, 1, &size,
			       (const char **)&name);
	if (rc != 0 || o->opo_ooa == NULL)
		return rc;

	oxe = osp_oac_xattr_find(o, name, true);
	if (oxe != NULL)
		/* Drop the ref for entry on list. */
		osp_oac_xattr_put(oxe);

	return 0;
}

int osp_declare_xattr_del(const struct lu_env *env, struct dt_object *dt,
			  const char *name, struct thandle *th)
{
	int rc = 0;

	/* Please check the comment in osp_attr_set() for handling
	 * remote transaction. */
	if (!is_only_remote_trans(th))
		rc = __osp_xattr_del(env, dt, name, th);

	return rc;
}

int osp_xattr_del(const struct lu_env *env, struct dt_object *dt,
		  const char *name, struct thandle *th,
		  struct lustre_capa *capa)
{
	int rc = 0;

	CDEBUG(D_INFO, "xattr %s del object "DFID"\n", name,
	       PFID(&dt->do_lu.lo_header->loh_fid));

	/* Please check the comment in osp_attr_set() for handling
	 * remote transaction. */
	if (is_only_remote_trans(th))
		rc = __osp_xattr_del(env, dt, name, th);

	return rc;
}

static int osp_declare_object_create(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lu_attr *attr,
				     struct dt_allocation_hint *hint,
				     struct dt_object_format *dof,
				     struct thandle *th)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*o = dt2osp_obj(dt);
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	int			 rc = 0;

	ENTRY;

	if (is_only_remote_trans(th)) {
		LASSERT(fid_is_sane(fid));

		rc = osp_md_declare_object_create(env, dt, attr, hint, dof, th);

		RETURN(rc);
	}

	/* should happen to non-0 OSP only so that at least one object
	 * has been already declared in the scenario and LOD should
	 * cleanup that */
	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OSC_CREATE_FAIL) && d->opd_index == 1)
		RETURN(-ENOSPC);

	LASSERT(d->opd_last_used_oid_file);

	/*
	 * There can be gaps in precreated ids and record to unlink llog
	 * XXX: we do not handle gaps yet, implemented before solution
	 *	was found to be racy, so we disabled that. there is no
	 *	point in making useless but expensive llog declaration.
	 */
	/* rc = osp_sync_declare_add(env, o, MDS_UNLINK64_REC, th); */

	if (unlikely(!fid_is_zero(fid))) {
		/* replay case: caller knows fid */
		osi->osi_off = sizeof(osi->osi_id) * d->opd_index;
		osi->osi_lb.lb_len = sizeof(osi->osi_id);
		osi->osi_lb.lb_buf = NULL;
		rc = dt_declare_record_write(env, d->opd_last_used_oid_file,
					     &osi->osi_lb, osi->osi_off, th);
		RETURN(rc);
	}

	/*
	 * in declaration we need to reserve object so that we don't block
	 * awaiting precreation RPC to complete
	 */
	rc = osp_precreate_reserve(env, d);
	/*
	 * we also need to declare update to local "last used id" file for
	 * recovery if object isn't used for a reason, we need to release
	 * reservation, this can be made in osd_object_release()
	 */
	if (rc == 0) {
		/* mark id is reserved: in create we don't want to talk
		 * to OST */
		LASSERT(o->opo_reserved == 0);
		o->opo_reserved = 1;

		/* common for all OSPs file hystorically */
		osi->osi_off = sizeof(osi->osi_id) * d->opd_index;
		osi->osi_lb.lb_len = sizeof(osi->osi_id);
		osi->osi_lb.lb_buf = NULL;
		rc = dt_declare_record_write(env, d->opd_last_used_oid_file,
					     &osi->osi_lb, osi->osi_off, th);
	} else {
		/* not needed in the cache anymore */
		set_bit(LU_OBJECT_HEARD_BANSHEE,
			    &dt->do_lu.lo_header->loh_flags);
	}
	RETURN(rc);
}

static int osp_object_create(const struct lu_env *env, struct dt_object *dt,
			     struct lu_attr *attr,
			     struct dt_allocation_hint *hint,
			     struct dt_object_format *dof, struct thandle *th)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*o = dt2osp_obj(dt);
	int			rc = 0;
	struct lu_fid		*fid = &osi->osi_fid;
	ENTRY;

	if (is_only_remote_trans(th)) {
		LASSERT(fid_is_sane(lu_object_fid(&dt->do_lu)));

		rc = osp_md_object_create(env, dt, attr, hint, dof, th);
		if (rc == 0)
			o->opo_non_exist = 0;

		RETURN(rc);
	}

	o->opo_non_exist = 0;
	if (o->opo_reserved) {
		/* regular case, fid is assigned holding trunsaction open */
		 osp_object_assign_fid(env, d, o);
	}

	memcpy(fid, lu_object_fid(&dt->do_lu), sizeof(*fid));

	LASSERTF(fid_is_sane(fid), "fid for osp_object %p is insane"DFID"!\n",
		 o, PFID(fid));

	if (!o->opo_reserved) {
		/* special case, id was assigned outside of transaction
		 * see comments in osp_declare_attr_set */
		LASSERT(d->opd_pre != NULL);
		spin_lock(&d->opd_pre_lock);
		osp_update_last_fid(d, fid);
		spin_unlock(&d->opd_pre_lock);
	}

	CDEBUG(D_INODE, "fid for osp_object %p is "DFID"\n", o, PFID(fid));

	/* If the precreate ends, it means it will be ready to rollover to
	 * the new sequence soon, all the creation should be synchronized,
	 * otherwise during replay, the replay fid will be inconsistent with
	 * last_used/create fid */
	if (osp_precreate_end_seq(env, d) && osp_is_fid_client(d))
		th->th_sync = 1;

	/*
	 * it's OK if the import is inactive by this moment - id was created
	 * by OST earlier, we just need to maintain it consistently on the disk
	 * once import is reconnected, OSP will claim this and other objects
	 * used and OST either keep them, if they exist or recreate
	 */

	/* we might have lost precreated objects */
	if (unlikely(d->opd_gap_count) > 0) {
		LASSERT(d->opd_pre != NULL);
		spin_lock(&d->opd_pre_lock);
		if (d->opd_gap_count > 0) {
			int count = d->opd_gap_count;

			ostid_set_id(&osi->osi_oi,
				     fid_oid(&d->opd_gap_start_fid));
			d->opd_gap_count = 0;
			spin_unlock(&d->opd_pre_lock);

			CDEBUG(D_HA, "Writting gap "DFID"+%d in llog\n",
			       PFID(&d->opd_gap_start_fid), count);
			/* real gap handling is disabled intil ORI-692 will be
			 * fixed, now we only report gaps */
		} else {
			spin_unlock(&d->opd_pre_lock);
		}
	}

	/* new object, the very first ->attr_set()
	 * initializing attributes needs no logging */
	o->opo_new = 1;

	/* Only need update last_used oid file, seq file will only be update
	 * during seq rollover */
	osp_objid_buf_prep(&osi->osi_lb, &osi->osi_off,
			   &d->opd_last_used_fid.f_oid, d->opd_index);

	rc = dt_record_write(env, d->opd_last_used_oid_file, &osi->osi_lb,
			     &osi->osi_off, th);

	CDEBUG(D_HA, "%s: Wrote last used FID: "DFID", index %d: %d\n",
	       d->opd_obd->obd_name, PFID(fid), d->opd_index, rc);

	RETURN(rc);
}

int osp_declare_object_destroy(const struct lu_env *env,
			       struct dt_object *dt, struct thandle *th)
{
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;

	ENTRY;

	/*
	 * track objects to be destroyed via llog
	 */
	rc = osp_sync_declare_add(env, o, MDS_UNLINK64_REC, th);

	RETURN(rc);
}

int osp_object_destroy(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;

	ENTRY;

	o->opo_non_exist = 1;
	/*
	 * once transaction is committed put proper command on
	 * the queue going to our OST
	 */
	rc = osp_sync_add(env, o, MDS_UNLINK64_REC, th, NULL);

	/* not needed in cache any more */
	set_bit(LU_OBJECT_HEARD_BANSHEE, &dt->do_lu.lo_header->loh_flags);

	RETURN(rc);
}

static int osp_orphan_index_lookup(const struct lu_env *env,
				   struct dt_object *dt,
				   struct dt_rec *rec,
				   const struct dt_key *key,
				   struct lustre_capa *capa)
{
	return -EOPNOTSUPP;
}

static int osp_orphan_index_declare_insert(const struct lu_env *env,
					   struct dt_object *dt,
					   const struct dt_rec *rec,
					   const struct dt_key *key,
					   struct thandle *handle)
{
	return -EOPNOTSUPP;
}

static int osp_orphan_index_insert(const struct lu_env *env,
				   struct dt_object *dt,
				   const struct dt_rec *rec,
				   const struct dt_key *key,
				   struct thandle *handle,
				   struct lustre_capa *capa,
				   int ignore_quota)
{
	return -EOPNOTSUPP;
}

static int osp_orphan_index_declare_delete(const struct lu_env *env,
					   struct dt_object *dt,
					   const struct dt_key *key,
					   struct thandle *handle)
{
	return -EOPNOTSUPP;
}

static int osp_orphan_index_delete(const struct lu_env *env,
				   struct dt_object *dt,
				   const struct dt_key *key,
				   struct thandle *handle,
				   struct lustre_capa *capa)
{
	return -EOPNOTSUPP;
}

struct dt_it *osp_it_init(const struct lu_env *env, struct dt_object *dt,
			  __u32 attr, struct lustre_capa *capa)
{
	struct osp_it *it;

	OBD_ALLOC_PTR(it);
	if (it == NULL)
		return ERR_PTR(-ENOMEM);

	it->ooi_pos_ent = -1;
	it->ooi_obj = dt;

	return (struct dt_it *)it;
}

void osp_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osp_it	*it = (struct osp_it *)di;
	struct page	**pages	= it->ooi_pages;
	int		npages = it->ooi_total_npages;
	int		i;

	if (pages != NULL) {
		for (i = 0; i < npages; i++) {
			if (pages[i] != NULL) {
				if (pages[i] == it->ooi_cur_page) {
					kunmap(pages[i]);
					it->ooi_cur_page = NULL;
				}
				__free_page(pages[i]);
			}
		}
		OBD_FREE(pages, npages * sizeof(*pages));
	}
	OBD_FREE_PTR(it);
}

static int osp_it_fetch(const struct lu_env *env, struct osp_it *it)
{
	struct lu_device	 *dev	= it->ooi_obj->do_lu.lo_dev;
	struct osp_device	 *osp	= lu2osp_dev(dev);
	struct page		**pages;
	struct ptlrpc_request	 *req	= NULL;
	struct ptlrpc_bulk_desc  *desc;
	struct idx_info 	 *ii;
	int			  npages;
	int			  rc;
	int			  i;
	ENTRY;

	/* 1MB bulk */
	npages = min_t(unsigned int, OFD_MAX_BRW_SIZE, 1 << 20);
	npages /= PAGE_CACHE_SIZE;

	OBD_ALLOC(pages, npages * sizeof(*pages));
	if (pages == NULL)
		RETURN(-ENOMEM);

	it->ooi_pages = pages;
	it->ooi_total_npages = npages;
	for (i = 0; i < npages; i++) {
		pages[i] = alloc_page(GFP_IOFS);
		if (pages[i] == NULL)
			RETURN(-ENOMEM);
	}

	req = ptlrpc_request_alloc(osp->opd_obd->u.cli.cl_import,
				   &RQF_OBD_IDX_READ);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OBD_VERSION, OBD_IDX_READ);
	if (rc != 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	req->rq_request_portal = OUT_PORTAL;
	ii = req_capsule_client_get(&req->rq_pill, &RMF_IDX_INFO);
	memset(ii, 0, sizeof(*ii));
	if (fid_is_last_id(lu_object_fid(&it->ooi_obj->do_lu))) {
		/* LFSCK will iterate orphan object[FID_SEQ_LAYOUT_BTREE,
		 * ost_index, 0] with LAST_ID FID, so it needs to replace
		 * the FID with orphan FID here */
		ii->ii_fid.f_seq = FID_SEQ_LAYOUT_RBTREE;
		ii->ii_fid.f_oid = osp->opd_index;
		ii->ii_fid.f_ver = 0;
		ii->ii_flags = II_FL_NOHASH;
	} else {
		ii->ii_fid = *lu_object_fid(&it->ooi_obj->do_lu);
		ii->ii_flags = II_FL_NOHASH | II_FL_NOKEY | II_FL_VARKEY |
			       II_FL_VARREC;
	}
	ii->ii_magic = IDX_INFO_MAGIC;
	ii->ii_count = npages * LU_PAGE_COUNT;
	ii->ii_hash_start = it->ooi_next;
	ii->ii_attrs = osp_dev2node(osp);

	ptlrpc_at_set_req_timeout(req);

	desc = ptlrpc_prep_bulk_imp(req, npages, 1, BULK_PUT_SINK,
				    MDS_BULK_PORTAL);
	if (desc == NULL) {
		ptlrpc_request_free(req);
		RETURN(-ENOMEM);
	}

	for (i = 0; i < npages; i++)
		ptlrpc_prep_bulk_page_pin(desc, pages[i], 0, PAGE_CACHE_SIZE);

	ptlrpc_request_set_replen(req);
	rc = ptlrpc_queue_wait(req);
	if (rc != 0)
		GOTO(out, rc);

	rc = sptlrpc_cli_unwrap_bulk_read(req, req->rq_bulk,
					  req->rq_bulk->bd_nob_transferred);
	if (rc < 0)
		GOTO(out, rc);
	rc = 0;

	ii = req_capsule_server_get(&req->rq_pill, &RMF_IDX_INFO);
	if (ii->ii_magic != IDX_INFO_MAGIC)
		 GOTO(out, rc = -EPROTO);

	npages = (ii->ii_count + LU_PAGE_COUNT - 1) >>
		 (PAGE_CACHE_SHIFT - LU_PAGE_SHIFT);
	if (npages > it->ooi_total_npages) {
		CERROR("%s: returned more pages than expected, %u > %u\n",
		       osp->opd_obd->obd_name, npages, it->ooi_total_npages);
		GOTO(out, rc = -EINVAL);
	}

	it->ooi_valid_npages = npages;
	if (ptlrpc_rep_need_swab(req))
		it->ooi_swab = 1;

	it->ooi_next = ii->ii_hash_end;

out:
	ptlrpc_req_finished(req);

	return rc;
}

int osp_it_next_page(const struct lu_env *env, struct dt_it *di)
{
	struct osp_it		*it = (struct osp_it *)di;
	struct lu_idxpage	*idxpage;
	struct page		**pages;
	int			rc;
	int			i;
	ENTRY;

again2:
	idxpage = it->ooi_cur_idxpage;
	if (idxpage != NULL) {
		if (idxpage->lip_nr == 0)
			RETURN(1);

		if (it->ooi_pos_ent < idxpage->lip_nr) {
			CDEBUG(D_INFO, "ooi_pos %d nr %d\n",
			       (int)it->ooi_pos_ent, (int)idxpage->lip_nr);
			RETURN(0);
		}
		it->ooi_cur_idxpage = NULL;
		it->ooi_pos_lu_page++;
again1:
		if (it->ooi_pos_lu_page < LU_PAGE_COUNT) {
			it->ooi_cur_idxpage = (void *)it->ooi_cur_page +
					 LU_PAGE_SIZE * it->ooi_pos_lu_page;
			if (it->ooi_swab)
				lustre_swab_lip_header(it->ooi_cur_idxpage);
			if (it->ooi_cur_idxpage->lip_magic != LIP_MAGIC) {
				struct osp_device *osp =
					lu2osp_dev(it->ooi_obj->do_lu.lo_dev);

				CERROR("%s: invalid magic (%x != %x) for page "
				       "%d/%d while read layout orphan index\n",
				       osp->opd_obd->obd_name,
				       it->ooi_cur_idxpage->lip_magic,
				       LIP_MAGIC, it->ooi_pos_page,
				       it->ooi_pos_lu_page);
				/* Skip this lu_page next time. */
				it->ooi_pos_ent = idxpage->lip_nr - 1;
				RETURN(-EINVAL);
			}
			it->ooi_pos_ent = -1;
			goto again2;
		}

		kunmap(it->ooi_cur_page);
		it->ooi_cur_page = NULL;
		it->ooi_pos_page++;

again0:
		pages = it->ooi_pages;
		if (it->ooi_pos_page < it->ooi_valid_npages) {
			it->ooi_cur_page = kmap(pages[it->ooi_pos_page]);
			it->ooi_pos_lu_page = 0;
			goto again1;
		}

		for (i = 0; i < it->ooi_total_npages; i++) {
			if (pages[i] != NULL)
				__free_page(pages[i]);
		}
		OBD_FREE(pages, it->ooi_total_npages * sizeof(*pages));

		it->ooi_pos_page = 0;
		it->ooi_total_npages = 0;
		it->ooi_valid_npages = 0;
		it->ooi_swab = 0;
		it->ooi_ent = NULL;
		it->ooi_cur_page = NULL;
		it->ooi_cur_idxpage = NULL;
		it->ooi_pages = NULL;
	}

	if (it->ooi_next == II_END_OFF)
		RETURN(1);

	rc = osp_it_fetch(env, it);
	if (rc == 0)
		goto again0;

	RETURN(rc);
}

int osp_orphan_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osp_it		*it = (struct osp_it *)di;
	struct lu_idxpage	*idxpage;
	int			rc;
	ENTRY;

again:
	idxpage = it->ooi_cur_idxpage;
	if (idxpage != NULL) {
		if (idxpage->lip_nr == 0)
			RETURN(1);

		it->ooi_pos_ent++;
		if (it->ooi_pos_ent < idxpage->lip_nr) {
			it->ooi_ent =
				(struct lu_orphan_ent *)idxpage->lip_entries +
							it->ooi_pos_ent;
			if (it->ooi_swab)
				lustre_swab_orphan_ent(it->ooi_ent);
			RETURN(0);
		}
	}

	rc = osp_it_next_page(env, di);
	if (rc == 0)
		goto again;

	RETURN(rc);
}

int osp_it_get(const struct lu_env *env, struct dt_it *di,
	       const struct dt_key *key)
{
	return 1;
}

void osp_it_put(const struct lu_env *env, struct dt_it *di)
{
}

struct dt_key *osp_orphan_it_key(const struct lu_env *env,
				 const struct dt_it *di)
{
	struct osp_it	*it  = (struct osp_it *)di;
	struct lu_orphan_ent	*ent = (struct lu_orphan_ent *)it->ooi_ent;

	if (likely(ent != NULL))
		return (struct dt_key *)(&ent->loe_key);

	return NULL;
}

int osp_orphan_it_key_size(const struct lu_env *env, const struct dt_it *di)
{
	return sizeof(struct lu_fid);
}

int osp_orphan_it_rec(const struct lu_env *env, const struct dt_it *di,
		      struct dt_rec *rec, __u32 attr)
{
	struct osp_it	*it  = (struct osp_it *)di;
	struct lu_orphan_ent	*ent = (struct lu_orphan_ent *)it->ooi_ent;

	if (likely(ent != NULL)) {
		*(struct lu_orphan_rec *)rec = ent->loe_rec;
		return 0;
	}

	return -EINVAL;
}

__u64 osp_it_store(const struct lu_env *env, const struct dt_it *di)
{
	struct osp_it	*it = (struct osp_it *)di;

	return it->ooi_next;
}

/**
 * \retval	 +1: locate to the exactly position
 * \retval	  0: cannot locate to the exactly position,
 *		     call next() to move to a valid position.
 * \retval	-ve: on error
 */
int osp_orphan_it_load(const struct lu_env *env, const struct dt_it *di,
		       __u64 hash)
{
	struct osp_it	*it	= (struct osp_it *)di;
	int		 rc;

	it->ooi_next = hash;
	rc = osp_orphan_it_next(env, (struct dt_it *)di);
	if (rc == 1)
		return 0;

	if (rc == 0)
		return 1;

	return rc;
}

int osp_it_key_rec(const struct lu_env *env, const struct dt_it *di,
		   void *key_rec)
{
	return 0;
}

static const struct dt_index_operations osp_orphan_index_ops = {
	.dio_lookup		= osp_orphan_index_lookup,
	.dio_declare_insert	= osp_orphan_index_declare_insert,
	.dio_insert		= osp_orphan_index_insert,
	.dio_declare_delete	= osp_orphan_index_declare_delete,
	.dio_delete		= osp_orphan_index_delete,
	.dio_it = {
		.init		= osp_it_init,
		.fini		= osp_it_fini,
		.next		= osp_orphan_it_next,
		.get		= osp_it_get,
		.put		= osp_it_put,
		.key		= osp_orphan_it_key,
		.key_size	= osp_orphan_it_key_size,
		.rec		= osp_orphan_it_rec,
		.store		= osp_it_store,
		.load		= osp_orphan_it_load,
		.key_rec	= osp_it_key_rec,
	}
};

static int osp_index_try(const struct lu_env *env,
			 struct dt_object *dt,
			 const struct dt_index_features *feat)
{
	const struct lu_fid *fid = lu_object_fid(&dt->do_lu);

	if (fid_is_last_id(fid) && fid_is_idif(fid))
		dt->do_index_ops = &osp_orphan_index_ops;
	else
		dt->do_index_ops = &osp_md_index_ops;
	return 0;
}

struct dt_object_operations osp_obj_ops = {
	.do_declare_attr_get	= osp_declare_attr_get,
	.do_attr_get		= osp_attr_get,
	.do_declare_attr_set	= osp_declare_attr_set,
	.do_attr_set		= osp_attr_set,
	.do_declare_xattr_get	= osp_declare_xattr_get,
	.do_xattr_get		= osp_xattr_get,
	.do_declare_xattr_set	= osp_declare_xattr_set,
	.do_xattr_set		= osp_xattr_set,
	.do_declare_create	= osp_declare_object_create,
	.do_create		= osp_object_create,
	.do_declare_destroy	= osp_declare_object_destroy,
	.do_destroy		= osp_object_destroy,
	.do_index_try		= osp_index_try,
};

static int osp_object_init(const struct lu_env *env, struct lu_object *o,
			   const struct lu_object_conf *conf)
{
	struct osp_object	*po = lu2osp_obj(o);
	int			rc = 0;
	ENTRY;

	spin_lock_init(&po->opo_lock);
	o->lo_header->loh_attr |= LOHA_REMOTE;

	if (is_ost_obj(o)) {
		po->opo_obj.do_ops = &osp_obj_ops;
	} else {
		struct lu_attr *la = &osp_env_info(env)->osi_attr;

		po->opo_obj.do_ops = &osp_md_obj_ops;
		po->opo_obj.do_body_ops = &osp_md_body_ops;
		rc = po->opo_obj.do_ops->do_attr_get(env, lu2dt_obj(o),
						     la, NULL);
		if (rc == 0)
			o->lo_header->loh_attr |=
				LOHA_EXISTS | (la->la_mode & S_IFMT);
		if (rc == -ENOENT) {
			po->opo_non_exist = 1;
			rc = 0;
		}
		init_rwsem(&po->opo_sem);
	}
	RETURN(rc);
}

static void osp_object_free(const struct lu_env *env, struct lu_object *o)
{
	struct osp_object	*obj = lu2osp_obj(o);
	struct lu_object_header	*h = o->lo_header;

	dt_object_fini(&obj->opo_obj);
	lu_object_header_fini(h);
	if (obj->opo_ooa != NULL) {
		struct osp_xattr_entry *oxe;
		struct osp_xattr_entry *tmp;
		int			count;

		list_for_each_entry_safe(oxe, tmp,
					 &obj->opo_ooa->ooa_xattr_list,
					 oxe_list) {
			list_del(&oxe->oxe_list);
			count = atomic_read(&oxe->oxe_ref);
			LASSERTF(count == 1,
				 "Still has %d users on the xattr entry %.*s\n",
				 count-1, (int)oxe->oxe_namelen, oxe->oxe_buf);

			OBD_FREE(oxe, oxe->oxe_buflen);
		}
		OBD_FREE_PTR(obj->opo_ooa);
	}
	OBD_SLAB_FREE_PTR(obj, osp_object_kmem);
}

static void osp_object_release(const struct lu_env *env, struct lu_object *o)
{
	struct osp_object	*po = lu2osp_obj(o);
	struct osp_device	*d  = lu2osp_dev(o->lo_dev);

	ENTRY;

	/*
	 * release reservation if object was declared but not created
	 * this may require lu_object_put() in LOD
	 */
	if (unlikely(po->opo_reserved)) {
		LASSERT(d->opd_pre != NULL);
		LASSERT(d->opd_pre_reserved > 0);
		spin_lock(&d->opd_pre_lock);
		d->opd_pre_reserved--;
		spin_unlock(&d->opd_pre_lock);

		/* not needed in cache any more */
		set_bit(LU_OBJECT_HEARD_BANSHEE, &o->lo_header->loh_flags);
	}

	if (is_ost_obj(o))
		/* XXX: Currently, NOT cache OST-object on MDT because:
		 *	1. it is not often accessed on MDT.
		 *	2. avoid up layer (such as LFSCK) to load too many
		 *	   once-used OST-objects. */
		set_bit(LU_OBJECT_HEARD_BANSHEE, &o->lo_header->loh_flags);

	EXIT;
}

static int osp_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *l)
{
	const struct osp_object *o = lu2osp_obj((struct lu_object *)l);

	return (*p)(env, cookie, LUSTRE_OSP_NAME"-object@%p", o);
}

static int osp_object_invariant(const struct lu_object *o)
{
	LBUG();
}

struct lu_object_operations osp_lu_obj_ops = {
	.loo_object_init	= osp_object_init,
	.loo_object_free	= osp_object_free,
	.loo_object_release	= osp_object_release,
	.loo_object_print	= osp_object_print,
	.loo_object_invariant	= osp_object_invariant
};
