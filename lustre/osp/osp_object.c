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
			  const char *name, int namelen, bool unlink)
{
	struct osp_xattr_entry *oxe;

	list_for_each_entry(oxe, &ooa->ooa_xattr_list, oxe_list) {
		if (namelen == oxe->oxe_namelen &&
		    strncmp(name, oxe->oxe_buf, namelen) == 0) {
			if (unlink)
				list_del_init(&oxe->oxe_list);
			else
				atomic_inc(&oxe->oxe_ref);

			return oxe;
		}
	}

	return NULL;
}

static struct osp_xattr_entry *osp_oac_xattr_find(struct osp_object *obj,
						  const char *name)
{
	struct osp_xattr_entry *oxe = NULL;

	spin_lock(&obj->opo_lock);
	if (obj->opo_ooa != NULL)
		oxe = osp_oac_xattr_find_locked(obj->opo_ooa, name,
						strlen(name), false);
	spin_unlock(&obj->opo_lock);

	return oxe;
}

static struct osp_xattr_entry *
osp_oac_xattr_find_or_add(struct osp_object *obj, const char *name, int len)
{
	struct osp_object_attr *ooa	= obj->opo_ooa;
	struct osp_xattr_entry *oxe;
	struct osp_xattr_entry *tmp	= NULL;
	int			namelen = strlen(name);
	int			size	= sizeof(*oxe) + namelen + 1 + len;

	LASSERT(ooa != NULL);

	oxe = osp_oac_xattr_find(obj, name);
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
	tmp = osp_oac_xattr_find_locked(ooa, name, namelen, false);
	if (tmp == NULL)
		list_add_tail(&oxe->oxe_list, &ooa->ooa_xattr_list);
	spin_unlock(&obj->opo_lock);

	if (tmp != NULL) {
		OBD_FREE(oxe, size);
		oxe = tmp;
	}

	return oxe;
}

static struct osp_xattr_entry *
osp_oac_xattr_replace(struct osp_object *obj,
		      struct osp_xattr_entry **poxe, int len)
{
	struct osp_object_attr *ooa	= obj->opo_ooa;
	struct osp_xattr_entry *old	= *poxe;
	struct osp_xattr_entry *oxe;
	struct osp_xattr_entry *tmp	= NULL;
	int			namelen = old->oxe_namelen;
	int			size	= sizeof(*oxe) + namelen + 1 + len;

	LASSERT(ooa != NULL);

	OBD_ALLOC(oxe, size);
	if (unlikely(oxe == NULL))
		return NULL;

	INIT_LIST_HEAD(&oxe->oxe_list);
	oxe->oxe_buflen = size;
	oxe->oxe_namelen = namelen;
	memcpy(oxe->oxe_buf, old->oxe_buf, namelen);
	oxe->oxe_value = oxe->oxe_buf + namelen + 1;
	/* One ref is for the caller, the other is for the entry on the list. */
	atomic_set(&oxe->oxe_ref, 2);

	spin_lock(&obj->opo_lock);
	tmp = osp_oac_xattr_find_locked(ooa, oxe->oxe_buf, namelen, true);
	list_add_tail(&oxe->oxe_list, &ooa->ooa_xattr_list);
	spin_unlock(&obj->opo_lock);

	*poxe = tmp;
	LASSERT(tmp != NULL);

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
				   struct update_reply *reply,
				   struct lu_attr *attr,
				   struct osp_object *obj, int index)
{
	struct osp_thread_info	*osi	= osp_env_info(env);
	struct lu_buf		*rbuf	= &osi->osi_lb2;
	struct obdo		*lobdo	= &osi->osi_obdo;
	struct obdo		*wobdo;
	int			 rc;

	rc = update_get_reply_buf(reply, rbuf, index);
	if (rc < 0)
		return rc;

	wobdo = rbuf->lb_buf;
	if (rbuf->lb_len != sizeof(*wobdo))
		return -EPROTO;

	obdo_le_to_cpu(wobdo, wobdo);
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
				    struct update_reply *reply,
				    struct osp_object *obj,
				    void *data, int index, int rc)
{
	struct lu_attr *attr = data;

	LASSERT(obj->opo_ooa != NULL);

	if (rc == 0) {
		osp2lu_obj(obj)->lo_header->loh_attr |= LOHA_EXISTS;
		obj->opo_non_exist = 0;

		return osp_get_attr_from_reply(env, reply, NULL, obj, index);
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
	struct update_request	*update;
	int			 rc	= 0;

	if (obj->opo_ooa == NULL) {
		rc = osp_oac_init(obj);
		if (rc != 0)
			return rc;
	}

	mutex_lock(&osp->opd_async_requests_mutex);
	update = osp_find_or_create_async_update_request(osp);
	if (IS_ERR(update))
		rc = PTR_ERR(update);
	else
		rc = osp_insert_async_update(env, update, OBJ_ATTR_GET, obj, 0,
					     NULL, NULL,
					     &obj->opo_ooa->ooa_attr,
					     osp_attr_get_interpterer);
	mutex_unlock(&osp->opd_async_requests_mutex);

	return rc;
}

int osp_attr_get(const struct lu_env *env, struct dt_object *dt,
		 struct lu_attr *attr, struct lustre_capa *capa)
{
	struct osp_device	*osp	= lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*obj	= dt2osp_obj(dt);
	struct dt_device	*dev	= &osp->opd_dt_dev;
	struct update_request	*update;
	struct update_reply	*reply;
	struct ptlrpc_request	*req	= NULL;
	int			 rc	= 0;
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

	rc = out_insert_update(env, update, OBJ_ATTR_GET,
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
	reply = req_capsule_server_sized_get(&req->rq_pill, &RMF_UPDATE_REPLY,
					     UPDATE_BUFFER_SIZE);
	if (reply == NULL || reply->ur_version != UPDATE_REPLY_V1)
		GOTO(out, rc = -EPROTO);

	rc = osp_get_attr_from_reply(env, reply, attr, obj, 0);
	if (rc != 0)
		GOTO(out, rc);

	if (!is_ost_obj(&dt->do_lu)) {
		if (attr->la_flags == 1)
			obj->opo_empty = 0;
		else
			obj->opo_empty = 1;
	}

	GOTO(out, rc = 0);

out:
	if (req != NULL)
		ptlrpc_req_finished(req);

	out_destroy_update_req(update);

	return rc;
}

static int osp_declare_attr_set(const struct lu_env *env, struct dt_object *dt,
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

	if (o->opo_new) {
		/* no need in logging for new objects being created */
		RETURN(0);
	}

	if (!(attr->la_valid & (LA_UID | LA_GID)))
		RETURN(0);

	if (!is_remote_trans(th))
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

static int osp_attr_set(const struct lu_env *env, struct dt_object *dt,
			const struct lu_attr *attr, struct thandle *th,
			struct lustre_capa *capa)
{
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;

	ENTRY;

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

	if (!is_remote_trans(th))
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
				     struct update_reply *reply,
				     struct osp_object *obj,
				     void *data, int index, int rc)
{
	struct osp_object_attr	*ooa  = obj->opo_ooa;
	struct osp_xattr_entry	*oxe  = data;
	struct lu_buf		*rbuf = &osp_env_info(env)->osi_lb2;

	LASSERT(ooa != NULL);

	if (rc == 0) {
		int len = sizeof(*oxe) + oxe->oxe_namelen + 1;

		rc = update_get_reply_buf(reply, rbuf, index);
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
	struct update_request	*update;
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
	update = osp_find_or_create_async_update_request(osp);
	if (IS_ERR(update)) {
		rc = PTR_ERR(update);
		mutex_unlock(&osp->opd_async_requests_mutex);
		osp_oac_xattr_put(oxe);
	} else {
		rc = osp_insert_async_update(env, update, OBJ_XATTR_GET, obj,
					     1, &namelen, &name, oxe,
					     osp_xattr_get_interpterer);
		if (rc != 0) {
			mutex_unlock(&osp->opd_async_requests_mutex);
			osp_oac_xattr_put(oxe);
		} else {
			/* XXX: Currently, we trigger the batched async OUT
			 *	RPC via dt_declare_xattr_get(). It is not
			 *	perfect solution, but works well now.
			 *
			 *	We will improve it in the future. */
			update = osp->opd_async_requests;
			if (update != NULL && update->ur_buf != NULL &&
			    update->ur_buf->ub_count > 0) {
				osp->opd_async_requests = NULL;
				mutex_unlock(&osp->opd_async_requests_mutex);
				rc = osp_unplug_async_update(env, osp, update);
			} else {
				mutex_unlock(&osp->opd_async_requests_mutex);
			}
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
	struct update_request	*update = NULL;
	struct ptlrpc_request	*req	= NULL;
	struct update_reply	*reply;
	struct osp_xattr_entry	*oxe	= NULL;
	const char		*dname  = dt->do_lu.lo_dev->ld_obd->obd_name;
	int			 namelen;
	int			 rc	= 0;
	ENTRY;

	LASSERT(buf != NULL);
	LASSERT(name != NULL);

	if (unlikely(obj->opo_non_exist))
		RETURN(-ENOENT);

	oxe = osp_oac_xattr_find(obj, name);
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

	namelen = strlen(name);
	rc = out_insert_update(env, update, OBJ_XATTR_GET,
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

	reply = req_capsule_server_sized_get(&req->rq_pill, &RMF_UPDATE_REPLY,
					    UPDATE_BUFFER_SIZE);
	if (reply->ur_version != UPDATE_REPLY_V1) {
		CERROR("%s: Wrong version %x expected %x "DFID": rc = %d\n",
		       dname, reply->ur_version, UPDATE_REPLY_V1,
		       PFID(lu_object_fid(&dt->do_lu)), -EPROTO);

		GOTO(out, rc = -EPROTO);
	}

	rc = update_get_reply_buf(reply, rbuf, 0);
	if (rc < 0)
		GOTO(out, rc);

	LASSERT(rbuf->lb_len > 0 && rbuf->lb_len < PAGE_CACHE_SIZE);

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
			oxe->oxe_ready = 0;
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

int osp_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *buf, const char *name,
			  int flag, struct thandle *th)
{
	struct osp_object	*o	 = dt2osp_obj(dt);
	struct update_request	*update;
	struct lu_fid		*fid;
	struct osp_xattr_entry	*oxe;
	int			sizes[3] = {strlen(name), buf->lb_len,
					    sizeof(int)};
	char			*bufs[3] = {(char *)name, (char *)buf->lb_buf };
	int			rc;

	LASSERT(buf->lb_len > 0 && buf->lb_buf != NULL);

	update = out_find_create_update_loc(th, dt);
	if (IS_ERR(update)) {
		CERROR("%s: Get OSP update buf failed "DFID": rc = %d\n",
		       dt->do_lu.lo_dev->ld_obd->obd_name,
		       PFID(lu_object_fid(&dt->do_lu)),
		       (int)PTR_ERR(update));

		return PTR_ERR(update);
	}

	flag = cpu_to_le32(flag);
	bufs[2] = (char *)&flag;

	fid = (struct lu_fid *)lu_object_fid(&dt->do_lu);
	rc = out_insert_update(env, update, OBJ_XATTR_SET, fid,
			       ARRAY_SIZE(sizes), sizes, (const char **)bufs);
	if (rc != 0 || o->opo_ooa == NULL)
		return rc;

	oxe = osp_oac_xattr_find_or_add(o, name, buf->lb_len);
	if (oxe == NULL) {
		CWARN("%s: Fail to add xattr (%s) to cache for "DFID
		      ": rc = %d\n", dt->do_lu.lo_dev->ld_obd->obd_name,
		      name, PFID(lu_object_fid(&dt->do_lu)), rc);

		return 0;
	}

	if (oxe->oxe_buflen - oxe->oxe_namelen - 1 < buf->lb_len) {
		struct osp_xattr_entry *old = oxe;
		struct osp_xattr_entry *tmp;

		tmp = osp_oac_xattr_replace(o, &old, buf->lb_len);
		osp_oac_xattr_put(oxe);
		oxe = tmp;
		if (tmp == NULL) {
			CWARN("%s: Fail to update xattr (%s) to cache for "DFID
			      ": rc = %d\n", dt->do_lu.lo_dev->ld_obd->obd_name,
			      name, PFID(lu_object_fid(&dt->do_lu)), rc);
			spin_lock(&o->opo_lock);
			oxe->oxe_ready = 0;
			spin_unlock(&o->opo_lock);

			return 0;
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

	return 0;
}

int osp_xattr_set(const struct lu_env *env, struct dt_object *dt,
		  const struct lu_buf *buf, const char *name, int fl,
		  struct thandle *th, struct lustre_capa *capa)
{
	CDEBUG(D_INFO, "xattr %s set object "DFID"\n", name,
	       PFID(&dt->do_lu.lo_header->loh_fid));

	return 0;
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

	if (is_remote_trans(th)) {
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
		rc = dt_declare_record_write(env, d->opd_last_used_oid_file,
					     sizeof(osi->osi_id), osi->osi_off,
					     th);
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
		rc = dt_declare_record_write(env, d->opd_last_used_oid_file,
					     sizeof(osi->osi_id), osi->osi_off,
					     th);
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

	if (is_remote_trans(th)) {
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
				 count - 1, oxe->oxe_namelen, oxe->oxe_buf);

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
