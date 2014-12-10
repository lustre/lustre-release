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
 * Copyright (c) 2013, 2014, Intel Corporation.
 *
 * lustre/target/out_handler.c
 *
 * Object update handler between targets.
 *
 * Author: di.wang <di.wang@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd_class.h>
#include <md_object.h>
#include "tgt_internal.h"
#include <lustre_update.h>

static int tx_extend_args(struct thandle_exec_args *ta, int new_alloc_ta)
{
	struct tx_arg	**new_ta;
	int		i;
	int		rc = 0;

	if (ta->ta_alloc_args >= new_alloc_ta)
		return 0;

	OBD_ALLOC(new_ta, sizeof(*new_ta) * new_alloc_ta);
	if (new_ta == NULL)
		return -ENOMEM;

	for (i = 0; i < new_alloc_ta; i++) {
		if (i < ta->ta_alloc_args) {
			/* copy the old args to new one */
			new_ta[i] = ta->ta_args[i];
		} else {
			OBD_ALLOC_PTR(new_ta[i]);
			if (new_ta[i] == NULL)
				GOTO(out, rc = -ENOMEM);
		}
	}

	/* free the old args */
	if (ta->ta_args != NULL)
		OBD_FREE(ta->ta_args, sizeof(ta->ta_args[0]) *
				      ta->ta_alloc_args);

	ta->ta_args = new_ta;
	ta->ta_alloc_args = new_alloc_ta;
out:
	if (rc != 0) {
		for (i = 0; i < new_alloc_ta; i++) {
			if (new_ta[i] != NULL)
				OBD_FREE_PTR(new_ta[i]);
		}
		OBD_FREE(new_ta, sizeof(*new_ta) * new_alloc_ta);
	}
	return rc;
}

#define TX_ALLOC_STEP	8
static struct tx_arg *tx_add_exec(struct thandle_exec_args *ta,
				  tx_exec_func_t func, tx_exec_func_t undo,
				  const char *file, int line)
{
	int rc;
	int i;

	LASSERT(ta != NULL);
	LASSERT(func != NULL);

	if (ta->ta_argno + 1 >= ta->ta_alloc_args) {
		rc = tx_extend_args(ta, ta->ta_alloc_args + TX_ALLOC_STEP);
		if (rc != 0)
			return ERR_PTR(rc);
	}

	i = ta->ta_argno;

	ta->ta_argno++;

	ta->ta_args[i]->exec_fn = func;
	ta->ta_args[i]->undo_fn = undo;
	ta->ta_args[i]->file    = file;
	ta->ta_args[i]->line    = line;

	return ta->ta_args[i];
}

static void out_reconstruct(const struct lu_env *env, struct dt_device *dt,
			    struct dt_object *obj,
			    struct object_update_reply *reply,
			    int index)
{
	CDEBUG(D_INFO, "%s: fork reply reply %p index %d: rc = %d\n",
	       dt_obd_name(dt), reply, index, 0);

	object_update_result_insert(reply, NULL, 0, index, 0);
	return;
}

typedef void (*out_reconstruct_t)(const struct lu_env *env,
				  struct dt_device *dt,
				  struct dt_object *obj,
				  struct object_update_reply *reply,
				  int index);

static inline int out_check_resent(const struct lu_env *env,
				   struct dt_device *dt,
				   struct dt_object *obj,
				   struct ptlrpc_request *req,
				   out_reconstruct_t reconstruct,
				   struct object_update_reply *reply,
				   int index)
{
	if (likely(!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT)))
		return 0;

	if (req_xid_is_last(req)) {
		reconstruct(env, dt, obj, reply, index);
		return 1;
	}
	DEBUG_REQ(D_HA, req, "no reply for RESENT req (have "LPD64")",
		 req->rq_export->exp_target_data.ted_lcd->lcd_last_xid);
	return 0;
}

static int out_obj_destroy(const struct lu_env *env, struct dt_object *dt_obj,
			   struct thandle *th)
{
	int rc;

	CDEBUG(D_INFO, "%s: destroy "DFID"\n", dt_obd_name(th->th_dev),
	       PFID(lu_object_fid(&dt_obj->do_lu)));

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_destroy(env, dt_obj, th);
	dt_write_unlock(env, dt_obj);

	return rc;
}

/**
 * All of the xxx_undo will be used once execution failed,
 * But because all of the required resource has been reserved in
 * declare phase, i.e. if declare succeed, it should make sure
 * the following executing phase succeed in anyway, so these undo
 * should be useless for most of the time in Phase I
 */
static int out_tx_create_undo(const struct lu_env *env, struct thandle *th,
			      struct tx_arg *arg)
{
	int rc;

	rc = out_obj_destroy(env, arg->object, th);
	if (rc != 0)
		CERROR("%s: undo failure, we are doomed!: rc = %d\n",
		       dt_obd_name(th->th_dev), rc);
	return rc;
}

static int out_tx_create_exec(const struct lu_env *env, struct thandle *th,
			      struct tx_arg *arg)
{
	struct dt_object	*dt_obj = arg->object;
	int			 rc;

	CDEBUG(D_OTHER, "%s: create "DFID": dof %u, mode %o\n",
	       dt_obd_name(th->th_dev),
	       PFID(lu_object_fid(&arg->object->do_lu)),
	       arg->u.create.dof.dof_type,
	       arg->u.create.attr.la_mode & S_IFMT);

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_create(env, dt_obj, &arg->u.create.attr,
		       &arg->u.create.hint, &arg->u.create.dof, th);

	dt_write_unlock(env, dt_obj);

	CDEBUG(D_INFO, "%s: insert create reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int __out_tx_create(const struct lu_env *env, struct dt_object *obj,
			   struct lu_attr *attr, struct lu_fid *parent_fid,
			   struct dt_object_format *dof,
			   struct thandle_exec_args *ta,
			   struct object_update_reply *reply,
			   int index, const char *file, int line)
{
	struct tx_arg *arg;
	int rc;

	LASSERT(ta->ta_handle != NULL);
	rc = dt_declare_create(env, obj, attr, NULL, dof,
				       ta->ta_handle);
	if (rc != 0)
		return rc;

	arg = tx_add_exec(ta, out_tx_create_exec, out_tx_create_undo, file,
			  line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	/* release the object in out_trans_stop */
	lu_object_get(&obj->do_lu);
	arg->object = obj;
	arg->u.create.attr = *attr;
	if (parent_fid != NULL)
		arg->u.create.fid = *parent_fid;
	memset(&arg->u.create.hint, 0, sizeof(arg->u.create.hint));
	arg->u.create.dof  = *dof;
	arg->reply = reply;
	arg->index = index;

	return 0;
}

static int out_create(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object        *obj = tti->tti_u.update.tti_dt_object;
	struct dt_object_format	*dof = &tti->tti_u.update.tti_update_dof;
	struct obdo		*lobdo = &tti->tti_u.update.tti_obdo;
	struct lu_attr		*attr = &tti->tti_attr;
	struct lu_fid		*fid = NULL;
	struct obdo		*wobdo;
	size_t			size;
	int			rc;

	ENTRY;

	wobdo = object_update_param_get(update, 0, &size);
	if (wobdo == NULL || size != sizeof(*wobdo)) {
		CERROR("%s: obdo is NULL, invalid RPC: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	if (ptlrpc_req_need_swab(tsi->tsi_pill->rc_req))
		lustre_swab_obdo(wobdo);
	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	la_from_obdo(attr, lobdo, lobdo->o_valid);

	dof->dof_type = dt_mode_to_dft(attr->la_mode);
	if (update->ou_params_count > 1) {
		fid = object_update_param_get(update, 1, &size);
		if (fid == NULL || size != sizeof(*fid)) {
			CERROR("%s: invalid fid: rc = %d\n",
			       tgt_name(tsi->tsi_tgt), -EPROTO);
			RETURN(err_serious(-EPROTO));
		}
		if (ptlrpc_req_need_swab(tsi->tsi_pill->rc_req))
			lustre_swab_lu_fid(fid);
		if (!fid_is_sane(fid)) {
			CERROR("%s: invalid fid "DFID": rc = %d\n",
			       tgt_name(tsi->tsi_tgt), PFID(fid), -EPROTO);
			RETURN(err_serious(-EPROTO));
		}
	}

	if (lu_object_exists(&obj->do_lu))
		RETURN(-EEXIST);

	rc = out_tx_create(tsi->tsi_env, obj, attr, fid, dof,
			   &tti->tti_tea,
			   tti->tti_u.update.tti_update_reply,
			   tti->tti_u.update.tti_update_reply_index);

	RETURN(rc);
}

static int out_tx_attr_set_undo(const struct lu_env *env,
				struct thandle *th, struct tx_arg *arg)
{
	CERROR("%s: attr set undo "DFID" unimplemented yet!: rc = %d\n",
	       dt_obd_name(th->th_dev),
	       PFID(lu_object_fid(&arg->object->do_lu)), -ENOTSUPP);

	return -ENOTSUPP;
}

static int out_tx_attr_set_exec(const struct lu_env *env, struct thandle *th,
				struct tx_arg *arg)
{
	struct dt_object	*dt_obj = arg->object;
	int			rc;

	CDEBUG(D_OTHER, "%s: attr set "DFID"\n", dt_obd_name(th->th_dev),
	       PFID(lu_object_fid(&dt_obj->do_lu)));

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_attr_set(env, dt_obj, &arg->u.attr_set.attr, th);
	dt_write_unlock(env, dt_obj);

	CDEBUG(D_INFO, "%s: insert attr_set reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int __out_tx_attr_set(const struct lu_env *env,
			     struct dt_object *dt_obj,
			     const struct lu_attr *attr,
			     struct thandle_exec_args *th,
			     struct object_update_reply *reply,
			     int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	LASSERT(th->ta_handle != NULL);
	rc = dt_declare_attr_set(env, dt_obj, attr, th->ta_handle);
	if (rc != 0)
		return rc;

	arg = tx_add_exec(th, out_tx_attr_set_exec, out_tx_attr_set_undo,
			  file, line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->u.attr_set.attr = *attr;
	arg->reply = reply;
	arg->index = index;
	return 0;
}

static int out_attr_set(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct lu_attr		*attr = &tti->tti_attr;
	struct dt_object        *obj = tti->tti_u.update.tti_dt_object;
	struct obdo		*lobdo = &tti->tti_u.update.tti_obdo;
	struct obdo		*wobdo;
	size_t			 size;
	int			 rc;

	ENTRY;

	wobdo = object_update_param_get(update, 0, &size);
	if (wobdo == NULL || size != sizeof(*wobdo)) {
		CERROR("%s: empty obdo in the update: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	attr->la_valid = 0;
	attr->la_valid = 0;

	if (ptlrpc_req_need_swab(tsi->tsi_pill->rc_req))
		lustre_swab_obdo(wobdo);
	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	la_from_obdo(attr, lobdo, lobdo->o_valid);

	rc = out_tx_attr_set(tsi->tsi_env, obj, attr, &tti->tti_tea,
			     tti->tti_u.update.tti_update_reply,
			     tti->tti_u.update.tti_update_reply_index);

	RETURN(rc);
}

static int out_attr_get(struct tgt_session_info *tsi)
{
	const struct lu_env	*env = tsi->tsi_env;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct obdo		*obdo = &tti->tti_u.update.tti_obdo;
	struct lu_attr		*la = &tti->tti_attr;
	struct dt_object        *obj = tti->tti_u.update.tti_dt_object;
	int			idx = tti->tti_u.update.tti_update_reply_index;
	int			rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu)) {
		/* Usually, this will be called when the master MDT try
		 * to init a remote object(see osp_object_init), so if
		 * the object does not exist on slave, we need set BANSHEE flag,
		 * so the object can be removed from the cache immediately */
		set_bit(LU_OBJECT_HEARD_BANSHEE,
			&obj->do_lu.lo_header->loh_flags);
		RETURN(-ENOENT);
	}

	dt_read_lock(env, obj, MOR_TGT_CHILD);
	rc = dt_attr_get(env, obj, la);
	if (rc)
		GOTO(out_unlock, rc);

	obdo->o_valid = 0;
	obdo_from_la(obdo, la, la->la_valid);
	lustre_set_wire_obdo(NULL, obdo, obdo);

out_unlock:
	dt_read_unlock(env, obj);

	CDEBUG(D_INFO, "%s: insert attr get reply %p index %d: rc = %d\n",
	       tgt_name(tsi->tsi_tgt), tti->tti_u.update.tti_update_reply,
	       0, rc);

	object_update_result_insert(tti->tti_u.update.tti_update_reply, obdo,
				    sizeof(*obdo), idx, rc);

	RETURN(rc);
}

static int out_xattr_get(struct tgt_session_info *tsi)
{
	const struct lu_env	   *env = tsi->tsi_env;
	struct tgt_thread_info	   *tti = tgt_th_info(env);
	struct object_update	   *update = tti->tti_u.update.tti_update;
	struct lu_buf		   *lbuf = &tti->tti_buf;
	struct object_update_reply *reply = tti->tti_u.update.tti_update_reply;
	struct dt_object           *obj = tti->tti_u.update.tti_dt_object;
	char			   *name;
	struct object_update_result *update_result;
	int			idx = tti->tti_u.update.tti_update_reply_index;
	int			   rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu)) {
		set_bit(LU_OBJECT_HEARD_BANSHEE,
			&obj->do_lu.lo_header->loh_flags);
		RETURN(-ENOENT);
	}

	name = object_update_param_get(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for xattr get: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	update_result = object_update_result_get(reply, 0, NULL);
	if (update_result == NULL) {
		CERROR("%s: empty name for xattr get: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	lbuf->lb_buf = update_result->our_data;
	lbuf->lb_len = OUT_UPDATE_REPLY_SIZE -
		       cfs_size_round((unsigned long)update_result->our_data -
				      (unsigned long)update_result);
	dt_read_lock(env, obj, MOR_TGT_CHILD);
	rc = dt_xattr_get(env, obj, lbuf, name);
	dt_read_unlock(env, obj);
	if (rc < 0) {
		lbuf->lb_len = 0;
		GOTO(out, rc);
	}
	if (rc == 0) {
		lbuf->lb_len = 0;
		GOTO(out, rc = -ENOENT);
	}
	lbuf->lb_len = rc;
	rc = 0;
	CDEBUG(D_INFO, "%s: "DFID" get xattr %s len %d\n",
	       tgt_name(tsi->tsi_tgt), PFID(lu_object_fid(&obj->do_lu)),
	       name, (int)lbuf->lb_len);

	GOTO(out, rc);

out:
	object_update_result_insert(reply, lbuf->lb_buf, lbuf->lb_len, idx, rc);
	RETURN(rc);
}

static int out_index_lookup(struct tgt_session_info *tsi)
{
	const struct lu_env	*env = tsi->tsi_env;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	char			*name;
	int			 rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	name = object_update_param_get(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for lookup: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	dt_read_lock(env, obj, MOR_TGT_CHILD);
	if (!dt_try_as_dir(env, obj))
		GOTO(out_unlock, rc = -ENOTDIR);

	rc = dt_lookup(env, obj, (struct dt_rec *)&tti->tti_fid1,
		       (struct dt_key *)name);

	if (rc < 0)
		GOTO(out_unlock, rc);

	if (rc == 0)
		rc += 1;

out_unlock:
	dt_read_unlock(env, obj);

	CDEBUG(D_INFO, "lookup "DFID" %s get "DFID" rc %d\n",
	       PFID(lu_object_fid(&obj->do_lu)), name,
	       PFID(&tti->tti_fid1), rc);

	CDEBUG(D_INFO, "%s: insert lookup reply %p index %d: rc = %d\n",
	       tgt_name(tsi->tsi_tgt), tti->tti_u.update.tti_update_reply,
	       0, rc);

	object_update_result_insert(tti->tti_u.update.tti_update_reply,
			    &tti->tti_fid1, sizeof(tti->tti_fid1),
			    tti->tti_u.update.tti_update_reply_index, rc);
	RETURN(rc);
}

static int out_tx_xattr_set_exec(const struct lu_env *env,
				 struct thandle *th,
				 struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

	CDEBUG(D_INFO, "%s: set xattr buf %p name %s flag %d\n",
	       dt_obd_name(th->th_dev), arg->u.xattr_set.buf.lb_buf,
	       arg->u.xattr_set.name, arg->u.xattr_set.flags);

	if (!lu_object_exists(&dt_obj->do_lu))
		GOTO(out, rc = -ENOENT);

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_xattr_set(env, dt_obj, &arg->u.xattr_set.buf,
			  arg->u.xattr_set.name, arg->u.xattr_set.flags, th);
	/**
	 * Ignore errors if this is LINK EA
	 **/
	if (unlikely(rc != 0 &&
		     strcmp(arg->u.xattr_set.name, XATTR_NAME_LINK) == 0)) {
		/* XXX: If the linkEA is overflow, then we need to notify the
		 *	namespace LFSCK to skip "nlink" attribute verification
		 *	on this object to avoid the "nlink" to be shrinked by
		 *	wrong. It may be not good an interaction with LFSCK
		 *	like this. We will consider to replace it with other
		 *	mechanism in future. LU-5802. */
		if (rc == -ENOSPC) {
			struct lfsck_request *lr = &tgt_th_info(env)->tti_lr;

			lfsck_pack_rfa(lr, lu_object_fid(&dt_obj->do_lu),
				       LE_SKIP_NLINK, LFSCK_TYPE_NAMESPACE);
			tgt_lfsck_in_notify(env,
				tgt_ses_info(env)->tsi_tgt->lut_bottom, lr, th);
		}

		rc = 0;
	}
	dt_write_unlock(env, dt_obj);

out:
	CDEBUG(D_INFO, "%s: insert xattr set reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int __out_tx_xattr_set(const struct lu_env *env,
			      struct dt_object *dt_obj,
			      const struct lu_buf *buf,
			      const char *name, int flags,
			      struct thandle_exec_args *ta,
			      struct object_update_reply *reply,
			      int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	LASSERT(ta->ta_handle != NULL);
	rc = dt_declare_xattr_set(env, dt_obj, buf, name, flags, ta->ta_handle);
	if (rc != 0)
		return rc;

	if (strcmp(name, XATTR_NAME_LINK) == 0) {
		struct lfsck_request *lr = &tgt_th_info(env)->tti_lr;

		/* XXX: If the linkEA is overflow, then we need to notify the
		 *	namespace LFSCK to skip "nlink" attribute verification
		 *	on this object to avoid the "nlink" to be shrinked by
		 *	wrong. It may be not good an interaction with LFSCK
		 *	like this. We will consider to replace it with other
		 *	mechanism in future. LU-5802. */
		lfsck_pack_rfa(lr, lu_object_fid(&dt_obj->do_lu),
			       LE_SKIP_NLINK_DECLARE, LFSCK_TYPE_NAMESPACE);
		rc = tgt_lfsck_in_notify(env,
					 tgt_ses_info(env)->tsi_tgt->lut_bottom,
					 lr, ta->ta_handle);
		if (rc != 0)
			return rc;
	}

	arg = tx_add_exec(ta, out_tx_xattr_set_exec, NULL, file, line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->u.xattr_set.name = name;
	arg->u.xattr_set.flags = flags;
	arg->u.xattr_set.buf = *buf;
	arg->reply = reply;
	arg->index = index;
	arg->u.xattr_set.csum = 0;
	return 0;
}

static int out_xattr_set(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	struct lu_buf		*lbuf = &tti->tti_buf;
	char			*name;
	char			*buf;
	__u32			*tmp;
	size_t			 buf_len = 0;
	int			 flag;
	size_t			 size = 0;
	int			 rc;
	ENTRY;

	name = object_update_param_get(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for xattr set: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	buf = object_update_param_get(update, 1, &buf_len);
	if (buf == NULL || buf_len == 0) {
		CERROR("%s: empty buf for xattr set: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	lbuf->lb_buf = buf;
	lbuf->lb_len = buf_len;

	tmp = object_update_param_get(update, 2, &size);
	if (tmp == NULL || size != sizeof(*tmp)) {
		CERROR("%s: emptry or wrong size %zu flag: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), size, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	if (ptlrpc_req_need_swab(tsi->tsi_pill->rc_req))
		__swab32s(tmp);
	flag = *tmp;

	rc = out_tx_xattr_set(tsi->tsi_env, obj, lbuf, name, flag,
			      &tti->tti_tea,
			      tti->tti_u.update.tti_update_reply,
			      tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_tx_xattr_del_exec(const struct lu_env *env, struct thandle *th,
				 struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

	CDEBUG(D_INFO, "%s: del xattr name '%s' on "DFID"\n",
	       dt_obd_name(th->th_dev), arg->u.xattr_set.name,
	       PFID(lu_object_fid(&dt_obj->do_lu)));

	if (!lu_object_exists(&dt_obj->do_lu))
		GOTO(out, rc = -ENOENT);

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_xattr_del(env, dt_obj, arg->u.xattr_set.name, th);
	dt_write_unlock(env, dt_obj);
out:
	CDEBUG(D_INFO, "%s: insert xattr del reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int __out_tx_xattr_del(const struct lu_env *env,
			      struct dt_object *dt_obj, const char *name,
			      struct thandle_exec_args *ta,
			      struct object_update_reply *reply,
			      int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	rc = dt_declare_xattr_del(env, dt_obj, name, ta->ta_handle);
	if (rc != 0)
		return rc;

	arg = tx_add_exec(ta, out_tx_xattr_del_exec, NULL, file, line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->u.xattr_set.name = name;
	arg->reply = reply;
	arg->index = index;
	return 0;
}

static int out_xattr_del(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	char			*name;
	int			 rc;
	ENTRY;

	name = object_update_param_get(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for xattr set: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	rc = out_tx_xattr_del(tsi->tsi_env, obj, name, &tti->tti_tea,
			      tti->tti_u.update.tti_update_reply,
			      tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_obj_ref_add(const struct lu_env *env,
			   struct dt_object *dt_obj,
			   struct thandle *th)
{
	int rc;

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_ref_add(env, dt_obj, th);
	dt_write_unlock(env, dt_obj);

	return rc;
}

static int out_obj_ref_del(const struct lu_env *env,
			   struct dt_object *dt_obj,
			   struct thandle *th)
{
	int rc;

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_ref_del(env, dt_obj, th);
	dt_write_unlock(env, dt_obj);

	return rc;
}

static int out_tx_ref_add_exec(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

	rc = out_obj_ref_add(env, dt_obj, th);

	CDEBUG(D_INFO, "%s: insert ref_add reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);
	return rc;
}

static int out_tx_ref_add_undo(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	return out_obj_ref_del(env, arg->object, th);
}

static int __out_tx_ref_add(const struct lu_env *env,
			    struct dt_object *dt_obj,
			    struct thandle_exec_args *ta,
			    struct object_update_reply *reply,
			    int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	LASSERT(ta->ta_handle != NULL);
	rc = dt_declare_ref_add(env, dt_obj, ta->ta_handle);
	if (rc != 0)
		return rc;

	arg = tx_add_exec(ta, out_tx_ref_add_exec, out_tx_ref_add_undo, file,
			  line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	return 0;
}

/**
 * increase ref of the object
 **/
static int out_ref_add(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	int			 rc;

	ENTRY;

	rc = out_tx_ref_add(tsi->tsi_env, obj, &tti->tti_tea,
			    tti->tti_u.update.tti_update_reply,
			    tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_tx_ref_del_exec(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	struct dt_object	*dt_obj = arg->object;
	int			 rc;

	rc = out_obj_ref_del(env, dt_obj, th);

	CDEBUG(D_INFO, "%s: insert ref_del reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, 0);

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int out_tx_ref_del_undo(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	return out_obj_ref_add(env, arg->object, th);
}

static int __out_tx_ref_del(const struct lu_env *env,
			    struct dt_object *dt_obj,
			    struct thandle_exec_args *ta,
			    struct object_update_reply *reply,
			    int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	LASSERT(ta->ta_handle != NULL);
	rc = dt_declare_ref_del(env, dt_obj, ta->ta_handle);
	if (rc != 0)
		return rc;

	arg = tx_add_exec(ta, out_tx_ref_del_exec, out_tx_ref_del_undo, file,
			  line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	return 0;
}

static int out_ref_del(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	int			 rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	rc = out_tx_ref_del(tsi->tsi_env, obj, &tti->tti_tea,
			    tti->tti_u.update.tti_update_reply,
			    tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_obj_index_insert(const struct lu_env *env,
				struct dt_object *dt_obj,
				const struct dt_rec *rec,
				const struct dt_key *key,
				struct thandle *th)
{
	int rc;

	CDEBUG(D_INFO, "%s: index insert "DFID" name: %s fid "DFID", type %u\n",
	       dt_obd_name(th->th_dev), PFID(lu_object_fid(&dt_obj->do_lu)),
	       (char *)key, PFID(((struct dt_insert_rec *)rec)->rec_fid),
	       ((struct dt_insert_rec *)rec)->rec_type);

	if (dt_try_as_dir(env, dt_obj) == 0)
		return -ENOTDIR;

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_insert(env, dt_obj, rec, key, th, 0);
	dt_write_unlock(env, dt_obj);

	return rc;
}

static int out_obj_index_delete(const struct lu_env *env,
				struct dt_object *dt_obj,
				const struct dt_key *key,
				struct thandle *th)
{
	int rc;

	CDEBUG(D_INFO, "%s: index delete "DFID" name: %s\n",
	       dt_obd_name(th->th_dev), PFID(lu_object_fid(&dt_obj->do_lu)),
	       (char *)key);

	if (dt_try_as_dir(env, dt_obj) == 0)
		return -ENOTDIR;

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_delete(env, dt_obj, key, th);
	dt_write_unlock(env, dt_obj);

	return rc;
}

static int out_tx_index_insert_exec(const struct lu_env *env,
				    struct thandle *th, struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

	if (unlikely(!dt_object_exists(dt_obj)))
		RETURN(-ESTALE);

	rc = out_obj_index_insert(env, dt_obj,
				  (const struct dt_rec *)&arg->u.insert.rec,
				  arg->u.insert.key, th);

	CDEBUG(D_INFO, "%s: insert idx insert reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int out_tx_index_insert_undo(const struct lu_env *env,
				    struct thandle *th, struct tx_arg *arg)
{
	return out_obj_index_delete(env, arg->object, arg->u.insert.key, th);
}

static int __out_tx_index_insert(const struct lu_env *env,
				 struct dt_object *dt_obj,
				 const struct dt_rec *rec,
				 const struct dt_key *key,
				 struct thandle_exec_args *ta,
				 struct object_update_reply *reply,
				 int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	LASSERT(ta->ta_handle != NULL);
	if (dt_try_as_dir(env, dt_obj) == 0) {
		rc = -ENOTDIR;
		return rc;
	}

	rc = dt_declare_insert(env, dt_obj, rec, key, ta->ta_handle);
	if (rc != 0)
		return rc;

	arg = tx_add_exec(ta, out_tx_index_insert_exec,
			  out_tx_index_insert_undo, file, line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	arg->u.insert.rec = *(const struct dt_insert_rec *)rec;
	arg->u.insert.key = key;

	return 0;
}

static int out_index_insert(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti	= tgt_th_info(tsi->tsi_env);
	struct object_update	*update	= tti->tti_u.update.tti_update;
	struct dt_object	*obj	= tti->tti_u.update.tti_dt_object;
	struct dt_insert_rec	*rec	= &tti->tti_rec;
	struct lu_fid		*fid;
	char			*name;
	__u32			*ptype;
	int			 rc	= 0;
	size_t			 size;
	ENTRY;

	name = object_update_param_get(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for index insert: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	fid = object_update_param_get(update, 1, &size);
	if (fid == NULL || size != sizeof(*fid)) {
		CERROR("%s: invalid fid: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		       RETURN(err_serious(-EPROTO));
	}

	if (ptlrpc_req_need_swab(tsi->tsi_pill->rc_req))
		lustre_swab_lu_fid(fid);

	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID": rc = %d\n",
		       tgt_name(tsi->tsi_tgt), PFID(fid), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	ptype = object_update_param_get(update, 2, &size);
	if (ptype == NULL || size != sizeof(*ptype)) {
		CERROR("%s: invalid type for index insert: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	if (ptlrpc_req_need_swab(tsi->tsi_pill->rc_req))
		__swab32s(ptype);

	rec->rec_fid = fid;
	rec->rec_type = *ptype;

	rc = out_tx_index_insert(tsi->tsi_env, obj, (const struct dt_rec *)rec,
				 (const struct dt_key *)name, &tti->tti_tea,
				 tti->tti_u.update.tti_update_reply,
				 tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_tx_index_delete_exec(const struct lu_env *env,
				    struct thandle *th,
				    struct tx_arg *arg)
{
	int rc;

	rc = out_obj_index_delete(env, arg->object, arg->u.insert.key, th);

	CDEBUG(D_INFO, "%s: delete idx insert reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int out_tx_index_delete_undo(const struct lu_env *env,
				    struct thandle *th,
				    struct tx_arg *arg)
{
	CERROR("%s: Oops, can not rollback index_delete yet: rc = %d\n",
	       dt_obd_name(th->th_dev), -ENOTSUPP);
	return -ENOTSUPP;
}

static int __out_tx_index_delete(const struct lu_env *env,
				 struct dt_object *dt_obj,
				 const struct dt_key *key,
				 struct thandle_exec_args *ta,
				 struct object_update_reply *reply,
				 int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	if (dt_try_as_dir(env, dt_obj) == 0) {
		rc = -ENOTDIR;
		return rc;
	}

	LASSERT(ta->ta_handle != NULL);
	rc = dt_declare_delete(env, dt_obj, key, ta->ta_handle);
	if (rc != 0)
		return rc;

	arg = tx_add_exec(ta, out_tx_index_delete_exec,
			  out_tx_index_delete_undo, file, line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	arg->u.insert.key = key;
	return 0;
}

static int out_index_delete(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	char			*name;
	int			 rc = 0;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	name = object_update_param_get(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for index delete: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	rc = out_tx_index_delete(tsi->tsi_env, obj, (const struct dt_key *)name,
				 &tti->tti_tea,
				 tti->tti_u.update.tti_update_reply,
				 tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_tx_destroy_exec(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

	rc = out_obj_destroy(env, dt_obj, th);

	CDEBUG(D_INFO, "%s: insert destroy reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);

	RETURN(rc);
}

static int out_tx_destroy_undo(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	CERROR("%s: not support destroy undo yet!: rc = %d\n",
	       dt_obd_name(th->th_dev), -ENOTSUPP);
	return -ENOTSUPP;
}

static int __out_tx_destroy(const struct lu_env *env, struct dt_object *dt_obj,
			     struct thandle_exec_args *ta,
			     struct object_update_reply *reply,
			     int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	LASSERT(ta->ta_handle != NULL);
	rc = dt_declare_destroy(env, dt_obj, ta->ta_handle);
	if (rc != 0)
		return rc;

	arg = tx_add_exec(ta, out_tx_destroy_exec, out_tx_destroy_undo,
			  file, line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	return 0;
}

static int out_destroy(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	struct lu_fid		*fid;
	int			 rc;
	ENTRY;

	fid = &update->ou_fid;
	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID": rc = %d\n",
		       tgt_name(tsi->tsi_tgt), PFID(fid), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	rc = out_tx_destroy(tsi->tsi_env, obj, &tti->tti_tea,
			    tti->tti_u.update.tti_update_reply,
			    tti->tti_u.update.tti_update_reply_index);

	RETURN(rc);
}

static int out_tx_write_exec(const struct lu_env *env, struct thandle *th,
			     struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_record_write(env, dt_obj, &arg->u.write.buf,
			     &arg->u.write.pos, th);
	dt_write_unlock(env, dt_obj);

	if (rc == 0)
		rc = arg->u.write.buf.lb_len;

	object_update_result_insert(arg->reply, NULL, 0, arg->index, rc);

	return rc > 0 ? 0 : rc;
}

static int __out_tx_write(const struct lu_env *env,
			  struct dt_object *dt_obj,
			  const struct lu_buf *buf,
			  loff_t pos, struct thandle_exec_args *ta,
			  struct object_update_reply *reply,
			  int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	LASSERT(ta->ta_handle != NULL);
	rc = dt_declare_record_write(env, dt_obj, buf, pos, ta->ta_handle);
	if (rc != 0)
		return rc;

	arg = tx_add_exec(ta, out_tx_write_exec, NULL, file, line);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->u.write.buf = *buf;
	arg->u.write.pos = pos;
	arg->reply = reply;
	arg->index = index;
	return 0;
}

static int out_write(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	struct lu_buf		*lbuf = &tti->tti_buf;
	char			*buf;
	__u64			*tmp;
	size_t			size = 0;
	size_t			buf_len = 0;
	loff_t			pos;
	int			 rc;
	ENTRY;

	buf = object_update_param_get(update, 0, &buf_len);
	if (buf == NULL || buf_len == 0) {
		CERROR("%s: empty buf for xattr set: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}
	lbuf->lb_buf = buf;
	lbuf->lb_len = buf_len;

	tmp = object_update_param_get(update, 1, &size);
	if (tmp == NULL || size != sizeof(*tmp)) {
		CERROR("%s: empty or wrong size %zu pos: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), size, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	if (ptlrpc_req_need_swab(tsi->tsi_pill->rc_req))
		__swab64s(tmp);
	pos = *tmp;

	rc = out_tx_write(tsi->tsi_env, obj, lbuf, pos,
			  &tti->tti_tea,
			  tti->tti_u.update.tti_update_reply,
			  tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

#define DEF_OUT_HNDL(opc, name, flags, fn)     \
[opc - OUT_CREATE] = {					\
	.th_name    = name,				\
	.th_fail_id = 0,				\
	.th_opc     = opc,				\
	.th_flags   = flags,				\
	.th_act     = fn,				\
	.th_fmt     = NULL,				\
	.th_version = 0,				\
}

static struct tgt_handler out_update_ops[] = {
	DEF_OUT_HNDL(OUT_CREATE, "out_create", MUTABOR | HABEO_REFERO,
		     out_create),
	DEF_OUT_HNDL(OUT_DESTROY, "out_create", MUTABOR | HABEO_REFERO,
		     out_destroy),
	DEF_OUT_HNDL(OUT_REF_ADD, "out_ref_add", MUTABOR | HABEO_REFERO,
		     out_ref_add),
	DEF_OUT_HNDL(OUT_REF_DEL, "out_ref_del", MUTABOR | HABEO_REFERO,
		     out_ref_del),
	DEF_OUT_HNDL(OUT_ATTR_SET, "out_attr_set",  MUTABOR | HABEO_REFERO,
		     out_attr_set),
	DEF_OUT_HNDL(OUT_ATTR_GET, "out_attr_get",  HABEO_REFERO,
		     out_attr_get),
	DEF_OUT_HNDL(OUT_XATTR_SET, "out_xattr_set", MUTABOR | HABEO_REFERO,
		     out_xattr_set),
	DEF_OUT_HNDL(OUT_XATTR_DEL, "out_xattr_del", MUTABOR | HABEO_REFERO,
		     out_xattr_del),
	DEF_OUT_HNDL(OUT_XATTR_GET, "out_xattr_get", HABEO_REFERO,
		     out_xattr_get),
	DEF_OUT_HNDL(OUT_INDEX_LOOKUP, "out_index_lookup", HABEO_REFERO,
		     out_index_lookup),
	DEF_OUT_HNDL(OUT_INDEX_INSERT, "out_index_insert",
		     MUTABOR | HABEO_REFERO, out_index_insert),
	DEF_OUT_HNDL(OUT_INDEX_DELETE, "out_index_delete",
		     MUTABOR | HABEO_REFERO, out_index_delete),
	DEF_OUT_HNDL(OUT_WRITE, "out_write", MUTABOR | HABEO_REFERO, out_write),
};

static struct tgt_handler *out_handler_find(__u32 opc)
{
	struct tgt_handler *h;

	h = NULL;
	if (OUT_CREATE <= opc && opc < OUT_LAST) {
		h = &out_update_ops[opc - OUT_CREATE];
		LASSERTF(h->th_opc == opc, "opcode mismatch %d != %d\n",
			 h->th_opc, opc);
	} else {
		h = NULL; /* unsupported opc */
	}
	return h;
}

static int out_tx_start(const struct lu_env *env, struct dt_device *dt,
			struct thandle_exec_args *ta, struct obd_export *exp)
{
	ta->ta_argno = 0;
	ta->ta_handle = dt_trans_create(env, dt);
	if (IS_ERR(ta->ta_handle)) {
		int rc;

		rc = PTR_ERR(ta->ta_handle);
		ta->ta_handle = NULL;
		CERROR("%s: start handle error: rc = %d\n", dt_obd_name(dt),
		       rc);
		return rc;
	}
	if (exp->exp_need_sync)
		ta->ta_handle->th_sync = 1;

	return 0;
}

static int out_trans_start(const struct lu_env *env,
			   struct thandle_exec_args *ta)
{
	return dt_trans_start(env, ta->ta_handle->th_dev, ta->ta_handle);
}

static int out_trans_stop(const struct lu_env *env,
			  struct thandle_exec_args *ta, int err)
{
	int i;
	int rc;

	ta->ta_handle->th_result = err;
	rc = dt_trans_stop(env, ta->ta_handle->th_dev, ta->ta_handle);
	for (i = 0; i < ta->ta_argno; i++) {
		if (ta->ta_args[i]->object != NULL) {
			struct dt_object *obj = ta->ta_args[i]->object;

			/* If the object is being created during this
			 * transaction, we need to remove them from the
			 * cache immediately, because a few layers are
			 * missing in OUT handler, i.e. the object might
			 * not be initialized in all layers */
			if (ta->ta_args[i]->exec_fn == out_tx_create_exec)
				set_bit(LU_OBJECT_HEARD_BANSHEE,
					&obj->do_lu.lo_header->loh_flags);
			lu_object_put(env, &ta->ta_args[i]->object->do_lu);
			ta->ta_args[i]->object = NULL;
		}
	}
	ta->ta_handle = NULL;
	ta->ta_argno = 0;

	return rc;
}

static int out_tx_end(const struct lu_env *env, struct thandle_exec_args *ta,
		      int declare_ret)
{
	struct tgt_session_info	*tsi = tgt_ses_info(env);
	int			i;
	int			rc;
	int			rc1;
	ENTRY;

	if (ta->ta_handle == NULL)
		RETURN(0);

	if (declare_ret != 0 || ta->ta_argno == 0)
		GOTO(stop, rc = declare_ret);

	LASSERT(ta->ta_handle->th_dev != NULL);
	rc = out_trans_start(env, ta);
	if (unlikely(rc != 0))
		GOTO(stop, rc);

	for (i = 0; i < ta->ta_argno; i++) {
		rc = ta->ta_args[i]->exec_fn(env, ta->ta_handle,
					     ta->ta_args[i]);
		if (unlikely(rc != 0)) {
			CDEBUG(D_INFO, "error during execution of #%u from"
			       " %s:%d: rc = %d\n", i, ta->ta_args[i]->file,
			       ta->ta_args[i]->line, rc);
			while (--i >= 0) {
				if (ta->ta_args[i]->undo_fn != NULL)
					ta->ta_args[i]->undo_fn(env,
							       ta->ta_handle,
							       ta->ta_args[i]);
				else
					CERROR("%s: undo for %s:%d: rc = %d\n",
					     dt_obd_name(ta->ta_handle->th_dev),
					       ta->ta_args[i]->file,
					       ta->ta_args[i]->line, -ENOTSUPP);
			}
			break;
		}
		CDEBUG(D_INFO, "%s: executed %u/%u: rc = %d\n",
		       dt_obd_name(ta->ta_handle->th_dev), i, ta->ta_argno, rc);
	}

	/* Only fail for real update */
	tsi->tsi_reply_fail_id = OBD_FAIL_OUT_UPDATE_NET_REP;
stop:
	rc1 = out_trans_stop(env, ta, rc);
	if (rc == 0)
		rc = rc1;

	ta->ta_handle = NULL;
	ta->ta_argno = 0;

	RETURN(rc);
}

/**
 * Object updates between Targets. Because all the updates has been
 * dis-assemblied into object updates at sender side, so OUT will
 * call OSD API directly to execute these updates.
 *
 * In DNE phase I all of the updates in the request need to be executed
 * in one transaction, and the transaction has to be synchronously.
 *
 * Please refer to lustre/include/lustre/lustre_idl.h for req/reply
 * format.
 */
int out_handle(struct tgt_session_info *tsi)
{
	const struct lu_env		*env = tsi->tsi_env;
	struct tgt_thread_info		*tti = tgt_th_info(env);
	struct thandle_exec_args	*ta = &tti->tti_tea;
	struct req_capsule		*pill = tsi->tsi_pill;
	struct dt_device		*dt = tsi->tsi_tgt->lut_bottom;
	struct object_update_request	*ureq;
	struct object_update		*update;
	struct object_update_reply	*reply;
	int				 bufsize;
	int				 count;
	int				 current_batchid = -1;
	int				 i;
	int				 rc = 0;
	int				 rc1 = 0;

	ENTRY;

	req_capsule_set(pill, &RQF_OUT_UPDATE);
	ureq = req_capsule_client_get(pill, &RMF_OUT_UPDATE);
	if (ureq == NULL) {
		CERROR("%s: No buf!: rc = %d\n", tgt_name(tsi->tsi_tgt),
		       -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	bufsize = req_capsule_get_size(pill, &RMF_OUT_UPDATE, RCL_CLIENT);
	if (bufsize != object_update_request_size(ureq)) {
		CERROR("%s: invalid bufsize %d: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), bufsize, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	if (ureq->ourq_magic != UPDATE_REQUEST_MAGIC) {
		CERROR("%s: invalid update buffer magic %x expect %x: "
		       "rc = %d\n", tgt_name(tsi->tsi_tgt), ureq->ourq_magic,
		       UPDATE_REQUEST_MAGIC, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	count = ureq->ourq_count;
	if (count <= 0) {
		CERROR("%s: empty update: rc = %d\n", tgt_name(tsi->tsi_tgt),
		       -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	req_capsule_set_size(pill, &RMF_OUT_UPDATE_REPLY, RCL_SERVER,
			     OUT_UPDATE_REPLY_SIZE);
	rc = req_capsule_server_pack(pill);
	if (rc != 0) {
		CERROR("%s: Can't pack response: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}

	/* Prepare the update reply buffer */
	reply = req_capsule_server_get(pill, &RMF_OUT_UPDATE_REPLY);
	if (reply == NULL)
		RETURN(err_serious(-EPROTO));
	object_update_reply_init(reply, count);
	tti->tti_u.update.tti_update_reply = reply;
	tti->tti_mult_trans = !req_is_replay(tgt_ses_req(tsi));

	/* Walk through updates in the request to execute them synchronously */
	for (i = 0; i < count; i++) {
		struct tgt_handler	*h;
		struct dt_object	*dt_obj;

		update = object_update_request_get(ureq, i, NULL);
		if (update == NULL)
			GOTO(out, rc = -EPROTO);

		if (ptlrpc_req_need_swab(pill->rc_req))
			lustre_swab_object_update(update);

		if (!fid_is_sane(&update->ou_fid)) {
			CERROR("%s: invalid FID "DFID": rc = %d\n",
			       tgt_name(tsi->tsi_tgt), PFID(&update->ou_fid),
			       -EPROTO);
			GOTO(out, rc = err_serious(-EPROTO));
		}

		dt_obj = dt_locate(env, dt, &update->ou_fid);
		if (IS_ERR(dt_obj))
			GOTO(out, rc = PTR_ERR(dt_obj));

		if (dt->dd_record_fid_accessed) {
			lfsck_pack_rfa(&tti->tti_lr,
				       lu_object_fid(&dt_obj->do_lu),
				       LE_FID_ACCESSED,
				       LFSCK_TYPE_LAYOUT);
			tgt_lfsck_in_notify(env, dt, &tti->tti_lr, NULL);
		}

		tti->tti_u.update.tti_dt_object = dt_obj;
		tti->tti_u.update.tti_update = update;
		tti->tti_u.update.tti_update_reply_index = i;

		h = out_handler_find(update->ou_type);
		if (unlikely(h == NULL)) {
			CERROR("%s: unsupported opc: 0x%x\n",
			       tgt_name(tsi->tsi_tgt), update->ou_type);
			GOTO(next, rc = -ENOTSUPP);
		}

		/* Check resend case only for modifying RPC */
		if (h->th_flags & MUTABOR) {
			struct ptlrpc_request *req = tgt_ses_req(tsi);

			if (out_check_resent(env, dt, dt_obj, req,
					     out_reconstruct, reply, i))
				GOTO(next, rc = 0);
		}

		/* start transaction for modification RPC only */
		if (h->th_flags & MUTABOR && current_batchid == -1) {
			current_batchid = update->ou_batchid;
			rc = out_tx_start(env, dt, ta, tsi->tsi_exp);
			if (rc != 0)
				GOTO(next, rc);
		}

		/* Stop the current update transaction, if the update has
		 * different batchid, or read-only update */
		if (((current_batchid != update->ou_batchid) ||
		     !(h->th_flags & MUTABOR)) && ta->ta_handle != NULL) {
			rc = out_tx_end(env, ta, rc);
			current_batchid = -1;
			if (rc != 0)
				GOTO(next, rc);

			/* start a new transaction if needed */
			if (h->th_flags & MUTABOR) {
				rc = out_tx_start(env, dt, ta, tsi->tsi_exp);
				if (rc != 0)
					GOTO(next, rc);

				current_batchid = update->ou_batchid;
			}
		}

		rc = h->th_act(tsi);
next:
		lu_object_put(env, &dt_obj->do_lu);
		if (rc < 0)
			GOTO(out, rc);
	}
out:
	if (current_batchid != -1) {
		rc1 = out_tx_end(env, ta, rc);
		if (rc == 0)
			rc = rc1;
	}

	RETURN(rc);
}

struct tgt_handler tgt_out_handlers[] = {
TGT_UPDATE_HDL(MUTABOR,	OUT_UPDATE,	out_handle),
};
EXPORT_SYMBOL(tgt_out_handlers);

