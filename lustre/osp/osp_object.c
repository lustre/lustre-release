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
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * lustre/osp/osp_object.c
 *
 * Lustre OST Proxy Device (OSP) is the agent on the local MDT for the OST
 * or remote MDT.
 *
 * OSP object attributes cache
 * ---------------------------
 * OSP object is the stub of the remote OST-object or MDT-object. Both the
 * attribute and the extended attributes are stored on the peer side remotely.
 * It is inefficient to send RPC to peer to fetch those attributes when every
 * get_attr()/get_xattr() called. For a large system, the LFSCK synchronous
 * mode scanning is prohibitively inefficient.
 *
 * So the OSP maintains the OSP object attributes cache to cache some
 * attributes on the local MDT. The cache is organized against the OSP
 * object as follows:
 *
 * struct osp_xattr_entry {
 *	struct list_head	 oxe_list;
 *	atomic_t		 oxe_ref;
 *	void			*oxe_value;
 *	int			 oxe_buflen;
 *	int			 oxe_namelen;
 *	int			 oxe_vallen;
 *	unsigned int		 oxe_exist:1,
 *				 oxe_ready:1;
 *	char			 oxe_buf[0];
 * };
 *
 * struct osp_object {
 *	...
 *	struct lu_attr		opo_attr;
 *	struct list_head	opo_xattr_list;
 *	spinlock_t		opo_lock;
 *	...
 * };
 *
 * The basic attributes, such as owner/mode/flags, are stored in the
 * osp_object::opo_attr. The extended attributes will be stored
 * as osp_xattr_entry. Every extended attribute has an independent
 * osp_xattr_entry, and all the osp_xattr_entry are linked into the
 * osp_object::opo_xattr_list. The OSP object attributes cache
 * is protected by the osp_object::opo_lock.
 *
 * Not all OSP objects have an attributes cache because maintaining
 * the cache requires some resources. Currently, the OSP object
 * attributes cache will be initialized when the attributes or the
 * extended attributes are pre-fetched via osp_declare_attr_get()
 * or osp_declare_xattr_get(). That is usually for LFSCK purpose,
 * but it also can be shared by others.
 *
 *
 * XXX: NOT prepare out RPC for remote transaction. ((please refer to the
 *	comment of osp_trans_create() for remote transaction)
 *
 * According to our current transaction/dt_object_lock framework (to make
 * the cross-MDTs modification for DNE1 to be workable), the transaction
 * sponsor will start the transaction firstly, then try to acquire related
 * dt_object_lock if needed. Under such rules, if we want to prepare the
 * OUT RPC in the transaction declare phase, then related attr/xattr
 * should be known without dt_object_lock. But such condition maybe not
 * true for some remote transaction case. For example:
 *
 * For linkEA repairing (by LFSCK) case, before the LFSCK thread obtained
 * the dt_object_lock on the target MDT-object, it cannot know whether
 * the MDT-object has linkEA or not, neither invalid or not.
 *
 * Since the LFSCK thread cannot hold dt_object_lock before the remote
 * transaction start (otherwise there will be some potential deadlock),
 * it cannot prepare related OUT RPC for repairing during the declare
 * phase as other normal transactions do.
 *
 * To resolve the trouble, we will make OSP to prepare related OUT RPC
 * after remote transaction started, and trigger the remote updating
 * (send RPC) when trans_stop. Then the up layer users, such as LFSCK,
 * can follow the general rule to handle trans_start/dt_object_lock
 * for repairing linkEA inconsistency without distinguishing remote
 * MDT-object.
 *
 * In fact, above solution for remote transaction should be the normal
 * model without considering DNE1. The trouble brought by DNE1 will be
 * resolved in DNE2. At that time, this patch can be removed.
 *
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.tappro@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <lustre_obdo.h>
#include <lustre_swab.h>

#include "osp_internal.h"

static inline __u32 osp_dev2node(struct osp_device *osp)
{
	return osp->opd_storage->dd_lu_dev.ld_site->ld_seq_site->ss_node_id;
}

static inline const char *osp_dto2name(struct osp_object *obj)
{
	return obj->opo_obj.do_lu.lo_dev->ld_obd->obd_name;
}

static inline bool is_ost_obj(struct lu_object *lo)
{
	return !lu2osp_dev(lo->lo_dev)->opd_connect_mdt;
}

static inline void __osp_oac_xattr_assignment(struct osp_object *obj,
					      struct osp_xattr_entry *oxe,
					      const struct lu_buf *buf)
{
	if (buf->lb_len > 0)
		memcpy(oxe->oxe_value, buf->lb_buf, buf->lb_len);

	oxe->oxe_vallen = buf->lb_len;
	oxe->oxe_exist = 1;
	oxe->oxe_ready = 1;
}

/**
 * Assign FID to the OST object.
 *
 * This function will assign the FID to the OST object of a striped file.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] d		pointer to the OSP device
 * \param[in] o		pointer to the OSP object that the FID will be
 *			assigned to
 */
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

#define OXE_DEFAULT_LEN	16

/**
 * Release reference from the OSP object extended attribute entry.
 *
 * If it is the last reference, then free the entry.
 *
 * \param[in] oxe	pointer to the OSP object extended attribute entry.
 */
static inline void osp_oac_xattr_put(struct osp_xattr_entry *oxe)
{
	if (atomic_dec_and_test(&oxe->oxe_ref)) {
		LASSERT(list_empty(&oxe->oxe_list));

		OBD_FREE(oxe, oxe->oxe_buflen);
	}
}

/**
 * Find the named extended attribute in the OSP object attributes cache.
 *
 * The caller should take the osp_object::opo_lock before calling
 * this function.
 *
 * \param[in] obj	pointer to the OSP object
 * \param[in] name	the name of the extended attribute
 * \param[in] namelen	the name length of the extended attribute
 *
 * \retval		pointer to the found extended attribute entry
 * \retval		NULL if the specified extended attribute is not
 *			in the cache
 */
static struct osp_xattr_entry *
osp_oac_xattr_find_locked(struct osp_object *obj, const char *name,
			  size_t namelen)
{
	struct osp_xattr_entry *oxe;

	list_for_each_entry(oxe, &obj->opo_xattr_list, oxe_list) {
		if (namelen == oxe->oxe_namelen &&
		    strncmp(name, oxe->oxe_buf, namelen) == 0)
			return oxe;
	}

	return NULL;
}

/**
 * Find the named extended attribute in the OSP object attributes cache.
 *
 * Call osp_oac_xattr_find_locked() with the osp_object::opo_lock held.
 *
 * \param[in] obj	pointer to the OSP object
 * \param[in] name	the name of the extended attribute
 * \param[in] unlink	true if the extended attribute entry is to be removed
 *			from the cache
 *
 * \retval		pointer to the found extended attribute entry
 * \retval		NULL if the specified extended attribute is not
 *			in the cache
 */
static struct osp_xattr_entry *osp_oac_xattr_find(struct osp_object *obj,
						  const char *name, bool unlink)
{
	struct osp_xattr_entry *oxe = NULL;

	spin_lock(&obj->opo_lock);
	oxe = osp_oac_xattr_find_locked(obj, name, strlen(name));
	if (oxe) {
		if (unlink)
			list_del_init(&oxe->oxe_list);
		else
			atomic_inc(&oxe->oxe_ref);
	}
	spin_unlock(&obj->opo_lock);

	return oxe;
}

/**
 * Find the named extended attribute in the OSP object attributes cache.
 *
 * If it is not in the cache, then add an empty entry (that will be
 * filled later) to cache with the given name.
 *
 * \param[in] obj	pointer to the OSP object
 * \param[in] name	the name of the extended attribute
 * \param[in] len	the length of the extended attribute value
 *
 * \retval		pointer to the found or new-created extended
 *			attribute entry
 * \retval		NULL if the specified extended attribute is not in the
 *			cache or fail to add new empty entry to the cache.
 */
static struct osp_xattr_entry *
osp_oac_xattr_find_or_add(struct osp_object *obj, const char *name, size_t len)
{
	struct osp_xattr_entry *oxe;
	struct osp_xattr_entry *tmp = NULL;
	size_t namelen = strlen(name);
	size_t size = sizeof(*oxe) + namelen + 1 +
		      (len ? len : OXE_DEFAULT_LEN);

	oxe = osp_oac_xattr_find(obj, name, false);
	if (oxe)
		return oxe;

	OBD_ALLOC(oxe, size);
	if (unlikely(!oxe))
		return NULL;

	INIT_LIST_HEAD(&oxe->oxe_list);
	oxe->oxe_buflen = size;
	oxe->oxe_namelen = namelen;
	memcpy(oxe->oxe_buf, name, namelen);
	oxe->oxe_value = oxe->oxe_buf + namelen + 1;
	/* One ref is for the caller, the other is for the entry on the list. */
	atomic_set(&oxe->oxe_ref, 2);

	spin_lock(&obj->opo_lock);
	tmp = osp_oac_xattr_find_locked(obj, name, namelen);
	if (!tmp)
		list_add_tail(&oxe->oxe_list, &obj->opo_xattr_list);
	else
		atomic_inc(&tmp->oxe_ref);
	spin_unlock(&obj->opo_lock);

	if (tmp) {
		OBD_FREE(oxe, size);
		oxe = tmp;
	}

	return oxe;
}

/**
 * Assign the cached OST-object's EA with the given value.
 *
 * If the current EA entry in cache has not enough space to hold the new
 * value, remove it, create a new one, then assign with the given value.
 *
 * \param[in] obj	pointer to the OSP object
 * \param[in] oxe	pointer to the cached EA entry to be assigned
 * \param[in] buf	pointer to the buffer with new EA value
 *
 * \retval		pointer to the new created EA entry in cache if
 *			current entry is not big enough; otherwise, the
 *			input 'oxe' will be returned.
 */
static struct osp_xattr_entry *
osp_oac_xattr_assignment(struct osp_object *obj, struct osp_xattr_entry *oxe,
			 const struct lu_buf *buf)
{
	struct osp_xattr_entry *new = NULL;
	struct osp_xattr_entry *old = NULL;
	int namelen = oxe->oxe_namelen;
	size_t size = sizeof(*oxe) + namelen + 1 + buf->lb_len;
	bool unlink_only = false;

	if (oxe->oxe_buflen < size) {
		OBD_ALLOC(new, size);
		if (likely(new)) {
			INIT_LIST_HEAD(&new->oxe_list);
			new->oxe_buflen = size;
			new->oxe_namelen = namelen;
			memcpy(new->oxe_buf, oxe->oxe_buf, namelen);
			new->oxe_value = new->oxe_buf + namelen + 1;
			/* One ref is for the caller,
			 * the other is for the entry on the list. */
			atomic_set(&new->oxe_ref, 2);
			__osp_oac_xattr_assignment(obj, new, buf);
		} else {
			unlink_only = true;
			CWARN("%s: cannot update cached xattr %.*s of "DFID"\n",
			      osp_dto2name(obj), namelen, oxe->oxe_buf,
			      PFID(lu_object_fid(&obj->opo_obj.do_lu)));
		}
	}

	spin_lock(&obj->opo_lock);
	old = osp_oac_xattr_find_locked(obj, oxe->oxe_buf, namelen);
	if (likely(old)) {
		if (new) {
			/* Unlink the 'old'. */
			list_del_init(&old->oxe_list);

			/* Drop the ref for 'old' on list. */
			osp_oac_xattr_put(old);

			/* Drop the ref for current using. */
			osp_oac_xattr_put(oxe);
			oxe = new;

			/* Insert 'new' into list. */
			list_add_tail(&new->oxe_list, &obj->opo_xattr_list);
		} else if (unlink_only) {
			/* Unlink the 'old'. */
			list_del_init(&old->oxe_list);

			/* Drop the ref for 'old' on list. */
			osp_oac_xattr_put(old);
		} else {
			__osp_oac_xattr_assignment(obj, oxe, buf);
		}
	} else if (new) {
		/* Drop the ref for current using. */
		osp_oac_xattr_put(oxe);
		oxe = new;

		/* Someone unlinked the 'old' by race,
		 * insert the 'new' one into list. */
		list_add_tail(&new->oxe_list, &obj->opo_xattr_list);
	}
	spin_unlock(&obj->opo_lock);

	return oxe;
}

/**
 * Parse the OSP object attribute from the RPC reply.
 *
 * If the attribute is valid, then it will be added to the OSP object
 * attributes cache.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] reply	pointer to the RPC reply
 * \param[in] req	pointer to the RPC request
 * \param[out] attr	pointer to buffer to hold the output attribute
 * \param[in] obj	pointer to the OSP object
 * \param[in] index	the index of the attribute buffer in the reply
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
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
	la_from_obdo(&obj->opo_attr, lobdo, lobdo->o_valid);
	if (attr != NULL)
		*attr = obj->opo_attr;
	spin_unlock(&obj->opo_lock);

	return 0;
}

/**
 * Interpreter function for getting OSP object attribute asynchronously.
 *
 * Called to interpret the result of an async mode RPC for getting the
 * OSP object attribute.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] reply	pointer to the RPC reply
 * \param[in] req	pointer to the RPC request
 * \param[in] obj	pointer to the OSP object
 * \param[out] data	pointer to buffer to hold the output attribute
 * \param[in] index	the index of the attribute buffer in the reply
 * \param[in] rc	the result for handling the RPC
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_attr_get_interpterer(const struct lu_env *env,
				    struct object_update_reply *reply,
				    struct ptlrpc_request *req,
				    struct osp_object *obj,
				    void *data, int index, int rc)
{
	struct lu_attr *attr = data;

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

/**
 * Implement OSP layer dt_object_operations::do_declare_attr_get() interface.
 *
 * Declare that the caller will get attribute from the specified OST object.
 *
 * This function adds an Object Unified Target (OUT) sub-request to the per-OSP
 * based shared asynchronous request queue. The osp_attr_get_interpterer()
 * is registered as the interpreter function to handle the result of this
 * sub-request.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_declare_attr_get(const struct lu_env *env, struct dt_object *dt)
{
	struct osp_object	*obj	= dt2osp_obj(dt);
	struct osp_device	*osp	= lu2osp_dev(dt->do_lu.lo_dev);
	int			 rc	= 0;

	mutex_lock(&osp->opd_async_requests_mutex);
	rc = osp_insert_async_request(env, OUT_ATTR_GET, obj, 0, NULL, NULL,
				      &obj->opo_attr, sizeof(struct obdo),
				      osp_attr_get_interpterer);
	mutex_unlock(&osp->opd_async_requests_mutex);

	return rc;
}

/**
 * Implement OSP layer dt_object_operations::do_attr_get() interface.
 *
 * Get attribute from the specified MDT/OST object.
 *
 * If the attribute is in the OSP object attributes cache, then return
 * the cached attribute directly. Otherwise it will trigger an OUT RPC
 * to the peer to get the attribute synchronously, if successful, add it
 * to the OSP attributes cache. (\see lustre/osp/osp_trans.c for OUT RPC.)
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[out] attr	pointer to the buffer to hold the output attribute
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osp_attr_get(const struct lu_env *env, struct dt_object *dt,
		 struct lu_attr *attr)
{
	struct osp_device		*osp = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object		*obj = dt2osp_obj(dt);
	struct dt_device		*dev = &osp->opd_dt_dev;
	struct osp_update_request	*update;
	struct object_update_reply	*reply;
	struct ptlrpc_request		*req = NULL;
	int				rc = 0;
	ENTRY;

	if (is_ost_obj(&dt->do_lu) && obj->opo_non_exist)
		RETURN(-ENOENT);

	spin_lock(&obj->opo_lock);
	if (obj->opo_attr.la_valid != 0 && !obj->opo_stale) {
		*attr = obj->opo_attr;
		spin_unlock(&obj->opo_lock);

		RETURN(0);
	}
	spin_unlock(&obj->opo_lock);

	update = osp_update_request_create(dev);
	if (IS_ERR(update))
		RETURN(PTR_ERR(update));

	rc = osp_update_rpc_pack(env, attr_get, update, OUT_ATTR_GET,
				 lu_object_fid(&dt->do_lu));
	if (rc != 0) {
		CERROR("%s: Insert update error "DFID": rc = %d\n",
		       dev->dd_lu_dev.ld_obd->obd_name,
		       PFID(lu_object_fid(&dt->do_lu)), rc);

		GOTO(out, rc);
	}

	rc = osp_remote_sync(env, osp, update, &req);
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

	spin_lock(&obj->opo_lock);
	obj->opo_stale = 0;
	spin_unlock(&obj->opo_lock);

	GOTO(out, rc);

out:
	if (req != NULL)
		ptlrpc_req_finished(req);

	osp_update_request_destroy(env, update);

	return rc;
}

/**
 * Implement OSP layer dt_object_operations::do_declare_attr_set() interface.
 *
 * If the transaction is not remote one, then declare the credits that will
 * be used for the subsequent llog record for the object's attributes.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[in] attr	pointer to the attribute to be set
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_declare_attr_set(const struct lu_env *env, struct dt_object *dt,
				const struct lu_attr *attr, struct thandle *th)
{
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*o = dt2osp_obj(dt);
	int			rc;

	if (is_only_remote_trans(th))
		return osp_md_declare_attr_set(env, dt, attr, th);
	/*
	 * Usually we don't allow server stack to manipulate size
	 * but there is a special case when striping is created
	 * late, after stripeless file got truncated to non-zero.
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
		if (rc != 0)
			RETURN(rc);
	}

	if (!(attr->la_valid & (LA_UID | LA_GID | LA_PROJID)))
		RETURN(0);

	/* track all UID/GID changes via llog */
	rc = osp_sync_declare_add(env, o, MDS_SETATTR64_REC, th);

	return 0;
}

/**
 * Implement OSP layer dt_object_operations::do_attr_set() interface.
 *
 * Set attribute to the specified OST object.
 *
 * If the transaction is a remote one, then add OUT_ATTR_SET sub-request
 * in the OUT RPC that will be flushed when the remote transaction stop.
 * Otherwise, it will generate a MDS_SETATTR64_REC record in the llog that
 * will be handled by a dedicated thread asynchronously.
 *
 * If the attribute entry exists in the OSP object attributes cache,
 * then update the cached attribute according to given attribute.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[in] attr	pointer to the attribute to be set
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_attr_set(const struct lu_env *env, struct dt_object *dt,
			const struct lu_attr *attr, struct thandle *th)
{
	struct osp_object	*o = dt2osp_obj(dt);
	int			 rc = 0;
	ENTRY;

	/* we're interested in uid/gid/projid changes only */
	if (!(attr->la_valid & (LA_UID | LA_GID | LA_PROJID)))
		RETURN(0);

	if (!is_only_remote_trans(th)) {
		rc = osp_sync_add(env, o, MDS_SETATTR64_REC, th, attr);
		/* XXX: send new uid/gid to OST ASAP? */
	} else {
		struct lu_attr	*la;

		/* It is for OST-object attr_set directly without updating
		 * local MDT-object attribute. It is usually used by LFSCK. */
		rc = osp_md_attr_set(env, dt, attr, th);
		CDEBUG(D_INFO, "(1) set attr "DFID": rc = %d\n",
		       PFID(&dt->do_lu.lo_header->loh_fid), rc);

		if (rc != 0)
			RETURN(rc);

		/* Update the OSP object attributes cache. */
		la = &o->opo_attr;
		spin_lock(&o->opo_lock);
		if (attr->la_valid & LA_UID) {
			la->la_uid = attr->la_uid;
			la->la_valid |= LA_UID;
		}

		if (attr->la_valid & LA_GID) {
			la->la_gid = attr->la_gid;
			la->la_valid |= LA_GID;
		}
		if (attr->la_valid & LA_PROJID) {
			la->la_projid = attr->la_projid;
			la->la_valid |= LA_PROJID;
		}
		spin_unlock(&o->opo_lock);
	}

	RETURN(rc);
}

/**
 * Interpreter function for getting OSP object extended attribute asynchronously
 *
 * Called to interpret the result of an async mode RPC for getting the
 * OSP object extended attribute.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] reply	pointer to the RPC reply
 * \param[in] req	pointer to the RPC request
 * \param[in] obj	pointer to the OSP object
 * \param[out] data	pointer to OSP object attributes cache
 * \param[in] index	the index of the attribute buffer in the reply
 * \param[in] rc	the result for handling the RPC
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_xattr_get_interpterer(const struct lu_env *env,
				     struct object_update_reply *reply,
				     struct ptlrpc_request *req,
				     struct osp_object *obj,
				     void *data, int index, int rc)
{
	struct osp_xattr_entry *oxe = data;
	struct lu_buf *rbuf = &osp_env_info(env)->osi_lb2;

	if (!rc) {
		size_t len = sizeof(*oxe) + oxe->oxe_namelen + 1;

		rc = object_update_result_data_get(reply, rbuf, index);
		spin_lock(&obj->opo_lock);
		if (rc < 0 || rbuf->lb_len == 0 ||
		    rbuf->lb_len > (oxe->oxe_buflen - len)) {
			if (unlikely(rc == -ENODATA)) {
				oxe->oxe_exist = 0;
				oxe->oxe_ready = 1;
			} else {
				oxe->oxe_ready = 0;
			}
			spin_unlock(&obj->opo_lock);
			/* Put the reference obtained in the
			 * osp_declare_xattr_get(). */
			osp_oac_xattr_put(oxe);

			return rc < 0 ? rc : -ERANGE;
		}

		__osp_oac_xattr_assignment(obj, oxe, rbuf);
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

	/* Put the reference obtained in the osp_declare_xattr_get(). */
	osp_oac_xattr_put(oxe);

	return 0;
}

/**
 * Implement OSP dt_object_operations::do_declare_xattr_get() interface.
 *
 * Declare that the caller will get extended attribute from the specified
 * OST object.
 *
 * This function will add an OUT_XATTR_GET sub-request to the per OSP
 * based shared asynchronous request queue with the interpreter function:
 * osp_xattr_get_interpterer().
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[out] buf	pointer to the lu_buf to hold the extended attribute
 * \param[in] name	the name for the expected extended attribute
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_declare_xattr_get(const struct lu_env *env, struct dt_object *dt,
				 struct lu_buf *buf, const char *name)
{
	struct osp_object	*obj	 = dt2osp_obj(dt);
	struct osp_device	*osp	 = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_xattr_entry	*oxe;
	__u16 namelen;
	int			 rc	 = 0;

	LASSERT(buf != NULL);
	LASSERT(name != NULL);

	if (unlikely(buf->lb_len == 0))
		return -EINVAL;

	oxe = osp_oac_xattr_find_or_add(obj, name, buf->lb_len);
	if (oxe == NULL)
		return -ENOMEM;

	namelen = strlen(name);
	mutex_lock(&osp->opd_async_requests_mutex);
	rc = osp_insert_async_request(env, OUT_XATTR_GET, obj, 1,
				      &namelen, (const void **)&name,
				      oxe, buf->lb_len,
				      osp_xattr_get_interpterer);
	if (rc != 0) {
		mutex_unlock(&osp->opd_async_requests_mutex);
		osp_oac_xattr_put(oxe);
	} else {
		struct osp_update_request *our;
		struct osp_update_request_sub *ours;

		/* XXX: Currently, we trigger the batched async OUT
		 *	RPC via dt_declare_xattr_get(). It is not
		 *	perfect solution, but works well now.
		 *
		 *	We will improve it in the future. */
		our = osp->opd_async_requests;
		ours = osp_current_object_update_request(our);
		if (ours != NULL && ours->ours_req != NULL &&
		    ours->ours_req->ourq_count > 0) {
			osp->opd_async_requests = NULL;
			mutex_unlock(&osp->opd_async_requests_mutex);
			rc = osp_unplug_async_request(env, osp, our);
		} else {
			mutex_unlock(&osp->opd_async_requests_mutex);
		}
	}

	return rc;
}

/**
 * Implement OSP layer dt_object_operations::do_xattr_get() interface.
 *
 * Get extended attribute from the specified MDT/OST object.
 *
 * If the extended attribute is in the OSP object attributes cache, then
 * return the cached extended attribute directly. Otherwise it will get
 * the extended attribute synchronously, if successful, add it to the OSP
 * attributes cache. (\see lustre/osp/osp_trans.c for OUT RPC.)
 *
 * There is a race condition: some other thread has added the named extended
 * attributed entry to the OSP object attributes cache during the current
 * OUT_XATTR_GET handling. If such case happens, the OSP will replace the
 * (just) existing extended attribute entry with the new replied one.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[out] buf	pointer to the lu_buf to hold the extended attribute
 * \param[in] name	the name for the expected extended attribute
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osp_xattr_get(const struct lu_env *env, struct dt_object *dt,
		  struct lu_buf *buf, const char *name)
{
	struct osp_device	*osp	= lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*obj	= dt2osp_obj(dt);
	struct dt_device	*dev	= &osp->opd_dt_dev;
	struct lu_buf		*rbuf	= &osp_env_info(env)->osi_lb2;
	struct osp_update_request *update = NULL;
	struct ptlrpc_request	*req	= NULL;
	struct object_update_reply *reply;
	struct osp_xattr_entry	*oxe	= NULL;
	const char *dname = osp_dto2name(obj);
	int rc = 0;
	ENTRY;

	LASSERT(buf != NULL);
	LASSERT(name != NULL);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_NETWORK) &&
	    osp->opd_index == cfs_fail_val) {
		if (is_ost_obj(&dt->do_lu)) {
			if (osp_dev2node(osp) == cfs_fail_val)
				RETURN(-ENOTCONN);
		} else {
			if (strcmp(name, XATTR_NAME_LINK) == 0)
				RETURN(-ENOTCONN);
		}
	}

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

			memcpy(buf->lb_buf, oxe->oxe_value,
			       oxe->oxe_vallen);

			GOTO(unlock, rc = oxe->oxe_vallen);

unlock:
			spin_unlock(&obj->opo_lock);
			osp_oac_xattr_put(oxe);

			return rc;
		}
		spin_unlock(&obj->opo_lock);
	}
	update = osp_update_request_create(dev);
	if (IS_ERR(update))
		GOTO(out, rc = PTR_ERR(update));

	rc = osp_update_rpc_pack(env, xattr_get, update, OUT_XATTR_GET,
				 lu_object_fid(&dt->do_lu), name, buf->lb_len);
	if (rc != 0) {
		CERROR("%s: Insert update error "DFID": rc = %d\n",
		       dname, PFID(lu_object_fid(&dt->do_lu)), rc);
		GOTO(out, rc);
	}

	rc = osp_remote_sync(env, osp, update, &req);
	if (rc < 0) {
		if (rc == -ENOENT) {
			dt->do_lu.lo_header->loh_attr &= ~LOHA_EXISTS;
			obj->opo_non_exist = 1;
		}

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
	if (rc < 0 || rbuf->lb_len == 0) {
		if (oxe) {
			spin_lock(&obj->opo_lock);
			if (unlikely(rc == -ENODATA)) {
				oxe->oxe_exist = 0;
				oxe->oxe_ready = 1;
			} else {
				oxe->oxe_ready = 0;
			}
			spin_unlock(&obj->opo_lock);
		}

		GOTO(out, rc);
	}

	/* For detecting EA size. */
	if (!buf->lb_buf)
		GOTO(out, rc);

	if (!oxe) {
		oxe = osp_oac_xattr_find_or_add(obj, name, rbuf->lb_len);
		if (!oxe) {
			CWARN("%s: Fail to add xattr (%s) to "
			      "cache for "DFID" (2): rc = %d\n",
			      dname, name, PFID(lu_object_fid(&dt->do_lu)), rc);

			GOTO(out, rc);
		}
	}

	oxe = osp_oac_xattr_assignment(obj, oxe, rbuf);

	GOTO(out, rc);

out:
	if (rc > 0 && buf->lb_buf) {
		if (unlikely(buf->lb_len < rbuf->lb_len))
			rc = -ERANGE;
		else
			memcpy(buf->lb_buf, rbuf->lb_buf, rbuf->lb_len);
	}

	if (req)
		ptlrpc_req_finished(req);

	if (update && !IS_ERR(update))
		osp_update_request_destroy(env, update);

	if (oxe)
		osp_oac_xattr_put(oxe);

	return rc;
}

/**
 * Implement OSP layer dt_object_operations::do_declare_xattr_set() interface.
 *
 * Declare that the caller will set extended attribute to the specified
 * MDT/OST object.
 *
 * If it is non-remote transaction, it will add an OUT_XATTR_SET sub-request
 * to the OUT RPC that will be flushed when the transaction start. And if the
 * OSP attributes cache is initialized, then check whether the name extended
 * attribute entry exists in the cache or not. If yes, replace it; otherwise,
 * add the extended attribute to the cache.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[in] buf	pointer to the lu_buf to hold the extended attribute
 * \param[in] name	the name of the extended attribute to be set
 * \param[in] flag	to indicate the detailed set operation: LU_XATTR_CREATE
 *			or LU_XATTR_REPLACE or others
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osp_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *buf, const char *name,
			  int flag, struct thandle *th)
{
	return osp_trans_update_request_create(th);
}

/**
 * Implement OSP layer dt_object_operations::do_xattr_set() interface.
 *
 * Set extended attribute to the specified MDT/OST object.
 *
 * Add an OUT_XATTR_SET sub-request into the OUT RPC that will be flushed in
 * the transaction stop. And if the OSP attributes cache is initialized, then
 * check whether the name extended attribute entry exists in the cache or not.
 * If yes, replace it; otherwise, add the extended attribute to the cache.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[in] buf	pointer to the lu_buf to hold the extended attribute
 * \param[in] name	the name of the extended attribute to be set
 * \param[in] fl	to indicate the detailed set operation: LU_XATTR_CREATE
 *			or LU_XATTR_REPLACE or others
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osp_xattr_set(const struct lu_env *env, struct dt_object *dt,
		  const struct lu_buf *buf, const char *name, int fl,
		  struct thandle *th)
{
	struct osp_object	*o = dt2osp_obj(dt);
	struct osp_update_request *update;
	struct osp_xattr_entry	*oxe;
	int			rc;
	ENTRY;

	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	CDEBUG(D_INODE, DFID" set xattr '%s' with size %zd\n",
	       PFID(lu_object_fid(&dt->do_lu)), name, buf->lb_len);

	rc = osp_update_rpc_pack(env, xattr_set, update, OUT_XATTR_SET,
				 lu_object_fid(&dt->do_lu), buf, name, fl);
	if (rc != 0)
		RETURN(rc);

	/* Do not cache linkEA that may be self-adjusted by peers
	 * under EA overflow case. */
	if (strcmp(name, XATTR_NAME_LINK) == 0) {
		oxe = osp_oac_xattr_find(o, name, true);
		if (oxe != NULL)
			osp_oac_xattr_put(oxe);

		RETURN(0);
	}

	oxe = osp_oac_xattr_find_or_add(o, name, buf->lb_len);
	if (oxe == NULL) {
		CWARN("%s: cannot cache xattr '%s' of "DFID"\n",
		      osp_dto2name(o), name, PFID(lu_object_fid(&dt->do_lu)));

		RETURN(0);
	}

	oxe = osp_oac_xattr_assignment(o, oxe, buf);
	if (oxe)
		osp_oac_xattr_put(oxe);

	RETURN(0);
}

/**
 * Implement OSP layer dt_object_operations::do_declare_xattr_del() interface.
 *
 * Declare that the caller will delete extended attribute on the specified
 * MDT/OST object.
 *
 * If it is non-remote transaction, it will add an OUT_XATTR_DEL sub-request
 * to the OUT RPC that will be flushed when the transaction start. And if the
 * name extended attribute entry exists in the OSP attributes cache, then remove
 * it from the cache.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[in] name	the name of the extended attribute to be set
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osp_declare_xattr_del(const struct lu_env *env, struct dt_object *dt,
			  const char *name, struct thandle *th)
{
	return osp_trans_update_request_create(th);
}

/**
 * Implement OSP layer dt_object_operations::do_xattr_del() interface.
 *
 * Delete extended attribute on the specified MDT/OST object.
 *
 * If it is remote transaction, it will add an OUT_XATTR_DEL sub-request into
 * the OUT RPC that will be flushed when the transaction stop. And if the name
 * extended attribute entry exists in the OSP attributes cache, then remove it
 * from the cache.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[in] name	the name of the extended attribute to be set
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osp_xattr_del(const struct lu_env *env, struct dt_object *dt,
		  const char *name, struct thandle *th)
{
	struct osp_update_request *update;
	const struct lu_fid	 *fid = lu_object_fid(&dt->do_lu);
	struct osp_object	 *o	= dt2osp_obj(dt);
	struct osp_xattr_entry	 *oxe;
	int			  rc;

	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	rc = osp_update_rpc_pack(env, xattr_del, update, OUT_XATTR_DEL,
				 fid, name);
	if (rc != 0)
		return rc;

	oxe = osp_oac_xattr_find(o, name, true);
	if (oxe != NULL)
		/* Drop the ref for entry on list. */
		osp_oac_xattr_put(oxe);

	return 0;
}

void osp_obj_invalidate_cache(struct osp_object *obj)
{
	struct osp_xattr_entry *oxe;
	struct osp_xattr_entry *tmp;

	spin_lock(&obj->opo_lock);
	list_for_each_entry_safe(oxe, tmp, &obj->opo_xattr_list, oxe_list) {
		oxe->oxe_ready = 0;
		list_del_init(&oxe->oxe_list);
		osp_oac_xattr_put(oxe);
	}
	obj->opo_attr.la_valid = 0;
	spin_unlock(&obj->opo_lock);
}

/**
 * Implement OSP layer dt_object_operations::do_invalidate() interface.
 *
 * Invalidate attributes cached on the specified MDT/OST object.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osp_invalidate(const struct lu_env *env, struct dt_object *dt)
{
	struct osp_object *obj = dt2osp_obj(dt);
	ENTRY;

	CDEBUG(D_HA, "Invalidate osp_object "DFID"\n",
	       PFID(lu_object_fid(&dt->do_lu)));
	osp_obj_invalidate_cache(obj);

	spin_lock(&obj->opo_lock);
	obj->opo_stale = 1;
	spin_unlock(&obj->opo_lock);

	RETURN(0);
}

/**
 * Implement OSP layer dt_object_operations::do_declare_create() interface.
 *
 * Declare that the caller will create the OST object.
 *
 * If the transaction is a remote transaction and the FID for the OST-object
 * has been assigned already, then handle it as creating (remote) MDT object
 * via osp_md_declare_create(). This function is usually used for LFSCK
 * to re-create the lost OST object. Otherwise, if it is not replay case, the
 * OSP will reserve pre-created object for the subsequent create operation;
 * if the MDT side cached pre-created objects are less than some threshold,
 * then it will wakeup the pre-create thread.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[in] attr	the attribute for the object to be created
 * \param[in] hint	pointer to the hint for creating the object, such as
 *			the parent object
 * \param[in] dof	pointer to the dt_object_format for help the creation
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_declare_create(const struct lu_env *env, struct dt_object *dt,
			      struct lu_attr *attr,
			      struct dt_allocation_hint *hint,
			      struct dt_object_format *dof, struct thandle *th)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*o = dt2osp_obj(dt);
	const struct lu_fid	*fid = lu_object_fid(&dt->do_lu);
	struct thandle		*local_th;
	int			 rc = 0;

	ENTRY;

	if (is_only_remote_trans(th) && !fid_is_zero(fid)) {
		LASSERT(fid_is_sane(fid));

		rc = osp_md_declare_create(env, dt, attr, hint, dof, th);

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

	local_th = osp_get_storage_thandle(env, th, d);
	if (IS_ERR(local_th))
		RETURN(PTR_ERR(local_th));

	if (unlikely(!fid_is_zero(fid))) {
		/* replay case: caller knows fid */
		osi->osi_off = sizeof(osi->osi_id) * d->opd_index;
		osi->osi_lb.lb_len = sizeof(osi->osi_id);
		osi->osi_lb.lb_buf = NULL;

		rc = dt_declare_record_write(env, d->opd_last_used_oid_file,
					     &osi->osi_lb, osi->osi_off,
					     local_th);
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
					     &osi->osi_lb, osi->osi_off,
					     local_th);
	} else {
		/* not needed in the cache anymore */
		set_bit(LU_OBJECT_HEARD_BANSHEE,
			    &dt->do_lu.lo_header->loh_flags);
	}
	RETURN(rc);
}

/**
 * Implement OSP layer dt_object_operations::do_create() interface.
 *
 * Create the OST object.
 *
 * If the transaction is a remote transaction and the FID for the OST-object
 * has been assigned already, then handle it as handling MDT object via the
 * osp_md_create(). For other cases, the OSP will assign FID to the
 * object to be created, and update last_used Object ID (OID) file.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[in] attr	the attribute for the object to be created
 * \param[in] hint	pointer to the hint for creating the object, such as
 *			the parent object
 * \param[in] dof	pointer to the dt_object_format for help the creation
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_create(const struct lu_env *env, struct dt_object *dt,
		      struct lu_attr *attr, struct dt_allocation_hint *hint,
		      struct dt_object_format *dof, struct thandle *th)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object	*o = dt2osp_obj(dt);
	int			rc = 0;
	struct lu_fid		*fid = &osi->osi_fid;
	struct thandle		*local_th;
	struct lu_fid		*last_fid = &d->opd_last_used_fid;
	ENTRY;

	if (is_only_remote_trans(th) &&
	    !fid_is_zero(lu_object_fid(&dt->do_lu))) {
		LASSERT(fid_is_sane(lu_object_fid(&dt->do_lu)));

		rc = osp_md_create(env, dt, attr, hint, dof, th);
		if (rc == 0)
			o->opo_non_exist = 0;

		RETURN(rc);
	}

	o->opo_non_exist = 0;
	if (o->opo_reserved) {
		/* regular case, fid is assigned holding transaction open */
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

	local_th = osp_get_storage_thandle(env, th, d);
	if (IS_ERR(local_th))
		RETURN(PTR_ERR(local_th));
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

			rc = ostid_set_id(&osi->osi_oi,
					  fid_oid(&d->opd_gap_start_fid));
			if (rc) {
				spin_unlock(&d->opd_pre_lock);
				RETURN(rc);
			}
			d->opd_gap_count = 0;
			spin_unlock(&d->opd_pre_lock);

			CDEBUG(D_HA, "Writing gap "DFID"+%d in llog\n",
			       PFID(&d->opd_gap_start_fid), count);
			/* real gap handling is disabled intil ORI-692 will be
			 * fixed, now we only report gaps */
		} else {
			spin_unlock(&d->opd_pre_lock);
		}
	}

	/* Only need update last_used oid file, seq file will only be update
	 * during seq rollover */
	if (fid_is_idif((last_fid)))
		osi->osi_id = fid_idif_id(fid_seq(last_fid),
					  fid_oid(last_fid), fid_ver(last_fid));
	else
		osi->osi_id = fid_oid(last_fid);
	osp_objid_buf_prep(&osi->osi_lb, &osi->osi_off,
			   &osi->osi_id, d->opd_index);

	rc = dt_record_write(env, d->opd_last_used_oid_file, &osi->osi_lb,
			     &osi->osi_off, local_th);

	CDEBUG(D_HA, "%s: Wrote last used FID: "DFID", index %d: %d\n",
	       d->opd_obd->obd_name, PFID(fid), d->opd_index, rc);

	RETURN(rc);
}

/**
 * Implement OSP layer dt_object_operations::do_declare_destroy() interface.
 *
 * Declare that the caller will destroy the specified OST object.
 *
 * The OST object destroy will be handled via llog asynchronously. This
 * function will declare the credits for generating MDS_UNLINK64_REC llog.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object to be destroyed
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int osp_declare_destroy(const struct lu_env *env, struct dt_object *dt,
			struct thandle *th)
{
	struct osp_object	*o = dt2osp_obj(dt);
	struct osp_device	*osp = lu2osp_dev(dt->do_lu.lo_dev);
	int			 rc = 0;

	ENTRY;

	LASSERT(!osp->opd_connect_mdt);
	rc = osp_sync_declare_add(env, o, MDS_UNLINK64_REC, th);

	RETURN(rc);
}

/**
 * Implement OSP layer dt_object_operations::do_destroy() interface.
 *
 * Destroy the specified OST object.
 *
 * The OSP generates a MDS_UNLINK64_REC record in the llog. There
 * will be some dedicated thread to handle the llog asynchronously.
 *
 * It also marks the object as non-cached.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object to be destroyed
 * \param[in] th	pointer to the transaction handler
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_destroy(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	struct osp_object	*o = dt2osp_obj(dt);
	struct osp_device	*osp = lu2osp_dev(dt->do_lu.lo_dev);
	int			 rc = 0;

	ENTRY;

	o->opo_non_exist = 1;

	LASSERT(!osp->opd_connect_mdt);
	/* once transaction is committed put proper command on
	 * the queue going to our OST. */
	rc = osp_sync_add(env, o, MDS_UNLINK64_REC, th, NULL);
	if (rc < 0)
		RETURN(rc);

	/* not needed in cache any more */
	set_bit(LU_OBJECT_HEARD_BANSHEE, &dt->do_lu.lo_header->loh_flags);

	RETURN(rc);
}

static int osp_orphan_index_lookup(const struct lu_env *env,
				   struct dt_object *dt,
				   struct dt_rec *rec,
				   const struct dt_key *key)
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
				   struct thandle *handle)
{
	return -EOPNOTSUPP;
}

/**
 * Initialize the OSP layer index iteration.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the index object to be iterated
 * \param[in] attr	unused
 *
 * \retval		pointer to the iteration structure
 * \retval		negative error number on failure
 */
struct dt_it *osp_it_init(const struct lu_env *env, struct dt_object *dt,
			  __u32 attr)
{
	struct osp_it *it;

	OBD_ALLOC_PTR(it);
	if (it == NULL)
		return ERR_PTR(-ENOMEM);

	it->ooi_pos_ent = -1;
	it->ooi_obj = dt;
	it->ooi_attr = attr;

	return (struct dt_it *)it;
}

/**
 * Finalize the OSP layer index iteration.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] di	pointer to the iteration structure
 */
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

/**
 * Get more records for the iteration from peer.
 *
 * The new records will be filled in an array of pages. The OSP side
 * allows 1MB bulk data to be transferred.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] it	pointer to the iteration structure
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
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
	npages /= PAGE_SIZE;

	OBD_ALLOC(pages, npages * sizeof(*pages));
	if (pages == NULL)
		RETURN(-ENOMEM);

	it->ooi_pages = pages;
	it->ooi_total_npages = npages;
	for (i = 0; i < npages; i++) {
		pages[i] = alloc_page(GFP_NOFS);
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

	osp_set_req_replay(osp, req);
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
		ii->ii_attrs = osp_dev2node(osp);
	} else {
		ii->ii_fid = *lu_object_fid(&it->ooi_obj->do_lu);
		ii->ii_flags = II_FL_NOHASH | II_FL_NOKEY | II_FL_VARKEY |
			       II_FL_VARREC;
		ii->ii_attrs = it->ooi_attr;
	}
	ii->ii_magic = IDX_INFO_MAGIC;
	ii->ii_count = npages * LU_PAGE_COUNT;
	ii->ii_hash_start = it->ooi_next;

	ptlrpc_at_set_req_timeout(req);

	desc = ptlrpc_prep_bulk_imp(req, npages, 1,
				    PTLRPC_BULK_PUT_SINK | PTLRPC_BULK_BUF_KIOV,
				    MDS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_pin_ops);
	if (desc == NULL)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < npages; i++)
		desc->bd_frag_ops->add_kiov_frag(desc, pages[i], 0,
						 PAGE_SIZE);

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
		 (PAGE_SHIFT - LU_PAGE_SHIFT);
	if (npages > it->ooi_total_npages) {
		CERROR("%s: returned more pages than expected, %u > %u\n",
		       osp->opd_obd->obd_name, npages, it->ooi_total_npages);
		GOTO(out, rc = -EINVAL);
	}

	it->ooi_rec_size = ii->ii_recsize;
	it->ooi_valid_npages = npages;
	if (ptlrpc_rep_need_swab(req))
		it->ooi_swab = 1;

	it->ooi_next = ii->ii_hash_end;

out:
	ptlrpc_req_finished(req);

	return rc;
}

/**
 * Move the iteration cursor to the next lu_page.
 *
 * One system page (PAGE_SIZE) may contain multiple lu_page (4KB),
 * that depends on the LU_PAGE_COUNT. If it is not the last lu_page
 * in current system page, then move the iteration cursor to the next
 * lu_page in current system page. Otherwise, if there are more system
 * pages in the cache, then move the iteration cursor to the next system
 * page. If all the cached records (pages) have been iterated, then fetch
 * more records via osp_it_fetch().
 *
 * \param[in] env	pointer to the thread context
 * \param[in] di	pointer to the iteration structure
 *
 * \retval		positive for end of the directory
 * \retval		0 for success
 * \retval		negative error number on failure
 */
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

/**
 * Move the iteration cursor to the next record.
 *
 * If there are more records in the lu_page, then move the iteration
 * cursor to the next record directly. Otherwise, move the iteration
 * cursor to the record in the next lu_page via osp_it_next_page()
 *
 * \param[in] env	pointer to the thread context
 * \param[in] di	pointer to the iteration structure
 *
 * \retval		positive for end of the directory
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_orphan_it_next(const struct lu_env *env, struct dt_it *di)
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
			if (it->ooi_rec_size ==
					sizeof(struct lu_orphan_rec_v2)) {
				it->ooi_ent =
				(struct lu_orphan_ent_v2 *)idxpage->lip_entries+
							it->ooi_pos_ent;
				if (it->ooi_swab)
					lustre_swab_orphan_ent_v2(it->ooi_ent);
			} else {
				it->ooi_ent =
				(struct lu_orphan_ent *)idxpage->lip_entries +
							it->ooi_pos_ent;
				if (it->ooi_swab)
					lustre_swab_orphan_ent(it->ooi_ent);
			}
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

static struct dt_key *osp_orphan_it_key(const struct lu_env *env,
					const struct dt_it *di)
{
	struct osp_it	*it  = (struct osp_it *)di;
	struct lu_orphan_ent	*ent = (struct lu_orphan_ent *)it->ooi_ent;

	if (likely(ent != NULL))
		return (struct dt_key *)(&ent->loe_key);

	return NULL;
}

static int osp_orphan_it_key_size(const struct lu_env *env,
				  const struct dt_it *di)
{
	return sizeof(struct lu_fid);
}

static int osp_orphan_it_rec(const struct lu_env *env, const struct dt_it *di,
			     struct dt_rec *rec, __u32 attr)
{
	struct osp_it *it = (struct osp_it *)di;

	if (likely(it->ooi_ent)) {
		if (it->ooi_rec_size == sizeof(struct lu_orphan_rec_v2)) {
			struct lu_orphan_ent_v2 *ent =
				(struct lu_orphan_ent_v2 *)it->ooi_ent;

			*(struct lu_orphan_rec_v2 *)rec = ent->loe_rec;
		} else {
			struct lu_orphan_ent *ent =
				(struct lu_orphan_ent *)it->ooi_ent;

			*(struct lu_orphan_rec *)rec = ent->loe_rec;
		}
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
 * Locate the iteration cursor to the specified position (cookie).
 *
 * \param[in] env	pointer to the thread context
 * \param[in] di	pointer to the iteration structure
 * \param[in] hash	the specified position
 *
 * \retval		positive number for locating to the exactly position
 *			or the next
 * \retval		0 for arriving at the end of the iteration
 * \retval		negative error number on failure
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

/**
 * Implement OSP layer dt_object_operations::do_index_try() interface.
 *
 * Negotiate the index type.
 *
 * If the target index is an IDIF object, then use osp_orphan_index_ops.
 * Otherwise, assign osp_md_index_ops to the dt_object::do_index_ops.
 * (\see lustre/include/lustre_fid.h for IDIF.)
 *
 * \param[in] env	pointer to the thread context
 * \param[in] dt	pointer to the OSP layer dt_object
 * \param[in] feat	unused
 *
 * \retval		0 for success
 */
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

static struct dt_object_operations osp_obj_ops = {
	.do_declare_attr_get	= osp_declare_attr_get,
	.do_attr_get		= osp_attr_get,
	.do_declare_attr_set	= osp_declare_attr_set,
	.do_attr_set		= osp_attr_set,
	.do_declare_xattr_get	= osp_declare_xattr_get,
	.do_xattr_get		= osp_xattr_get,
	.do_declare_xattr_set	= osp_declare_xattr_set,
	.do_xattr_set		= osp_xattr_set,
	.do_declare_create	= osp_declare_create,
	.do_create		= osp_create,
	.do_declare_destroy	= osp_declare_destroy,
	.do_destroy		= osp_destroy,
	.do_index_try		= osp_index_try,
};

/**
 * Implement OSP layer lu_object_operations::loo_object_init() interface.
 *
 * Initialize the object.
 *
 * If it is a remote MDT object, then call do_attr_get() to fetch
 * the attribute from the peer.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] o		pointer to the OSP layer lu_object
 * \param[in] conf	unused
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int osp_object_init(const struct lu_env *env, struct lu_object *o,
			   const struct lu_object_conf *conf)
{
	struct osp_object	*po = lu2osp_obj(o);
	int			rc = 0;
	ENTRY;

	spin_lock_init(&po->opo_lock);
	o->lo_header->loh_attr |= LOHA_REMOTE;
	INIT_LIST_HEAD(&po->opo_xattr_list);
	INIT_LIST_HEAD(&po->opo_invalidate_cb_list);

	if (is_ost_obj(o)) {
		po->opo_obj.do_ops = &osp_obj_ops;
	} else {
		struct lu_attr *la = &osp_env_info(env)->osi_attr;

		po->opo_obj.do_ops = &osp_md_obj_ops;
		po->opo_obj.do_body_ops = &osp_md_body_ops;

		if (conf != NULL && conf->loc_flags & LOC_F_NEW) {
			po->opo_non_exist = 1;
		} else {
			rc = po->opo_obj.do_ops->do_attr_get(env, lu2dt_obj(o),
							     la);
			if (rc == 0)
				o->lo_header->loh_attr |=
					LOHA_EXISTS | (la->la_mode & S_IFMT);
			if (rc == -ENOENT) {
				po->opo_non_exist = 1;
				rc = 0;
			}
		}
		init_rwsem(&po->opo_sem);
	}
	RETURN(rc);
}

/**
 * Implement OSP layer lu_object_operations::loo_object_free() interface.
 *
 * Finalize the object.
 *
 * If the OSP object has attributes cache, then destroy the cache.
 * Free the object finally.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] o		pointer to the OSP layer lu_object
 */
static void osp_object_free(const struct lu_env *env, struct lu_object *o)
{
	struct osp_object	*obj = lu2osp_obj(o);
	struct lu_object_header	*h = o->lo_header;
	struct osp_xattr_entry *oxe;
	struct osp_xattr_entry *tmp;
	int			count;

	dt_object_fini(&obj->opo_obj);
	lu_object_header_fini(h);
	list_for_each_entry_safe(oxe, tmp, &obj->opo_xattr_list, oxe_list) {
		list_del(&oxe->oxe_list);
		count = atomic_read(&oxe->oxe_ref);
		LASSERTF(count == 1,
			 "Still has %d users on the xattr entry %.*s\n",
			 count-1, (int)oxe->oxe_namelen, oxe->oxe_buf);

		OBD_FREE(oxe, oxe->oxe_buflen);
	}
	OBD_SLAB_FREE_PTR(obj, osp_object_kmem);
}

/**
 * Implement OSP layer lu_object_operations::loo_object_release() interface.
 *
 * Cleanup (not free) the object.
 *
 * If it is a reserved object but failed to be created, or it is an OST
 * object, then mark the object as non-cached.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] o		pointer to the OSP layer lu_object
 */
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
