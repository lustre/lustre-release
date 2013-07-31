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
 *
 * lustre/mdt/out_handler.c
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

struct tx_arg *tx_add_exec(struct thandle_exec_args *ta, tx_exec_func_t func,
			   tx_exec_func_t undo, char *file, int line)
{
	int i;

	LASSERT(ta);
	LASSERT(func);

	i = ta->ta_argno;
	LASSERT(i < UPDATE_MAX_OPS);

	ta->ta_argno++;

	ta->ta_args[i].exec_fn = func;
	ta->ta_args[i].undo_fn = undo;
	ta->ta_args[i].file    = file;
	ta->ta_args[i].line    = line;

	return &ta->ta_args[i];
}

static int out_tx_start(const struct lu_env *env, struct dt_device *dt,
			struct thandle_exec_args *ta, struct obd_export *exp)
{
	memset(ta, 0, sizeof(*ta));
	ta->ta_handle = dt_trans_create(env, dt);
	if (IS_ERR(ta->ta_handle)) {
		CERROR("%s: start handle error: rc = %ld\n",
		       dt_obd_name(dt), PTR_ERR(ta->ta_handle));
		return PTR_ERR(ta->ta_handle);
	}
	ta->ta_dev = dt;
	if (exp->exp_need_sync)
		ta->ta_handle->th_sync = 1;

	return 0;
}

static int out_trans_start(const struct lu_env *env,
			   struct thandle_exec_args *ta)
{
	return dt_trans_start(env, ta->ta_dev, ta->ta_handle);
}

static int out_trans_stop(const struct lu_env *env,
			  struct thandle_exec_args *ta, int err)
{
	int i;
	int rc;

	ta->ta_handle->th_result = err;
	rc = dt_trans_stop(env, ta->ta_dev, ta->ta_handle);
	for (i = 0; i < ta->ta_argno; i++) {
		if (ta->ta_args[i].object != NULL) {
			lu_object_put(env, &ta->ta_args[i].object->do_lu);
			ta->ta_args[i].object = NULL;
		}
	}

	return rc;
}

int out_tx_end(const struct lu_env *env, struct thandle_exec_args *ta)
{
	struct tgt_session_info *tsi = tgt_ses_info(env);
	int i = 0, rc;

	LASSERT(ta->ta_dev);
	LASSERT(ta->ta_handle);

	if (ta->ta_err != 0 || ta->ta_argno == 0)
		GOTO(stop, rc = ta->ta_err);

	rc = out_trans_start(env, ta);
	if (unlikely(rc))
		GOTO(stop, rc);

	for (i = 0; i < ta->ta_argno; i++) {
		rc = ta->ta_args[i].exec_fn(env, ta->ta_handle,
					    &ta->ta_args[i]);
		if (unlikely(rc)) {
			CDEBUG(D_INFO, "error during execution of #%u from"
			       " %s:%d: rc = %d\n", i, ta->ta_args[i].file,
			       ta->ta_args[i].line, rc);
			while (--i >= 0) {
				LASSERTF(ta->ta_args[i].undo_fn != NULL,
				    "can't undo changes, hope for failover!\n");
				ta->ta_args[i].undo_fn(env, ta->ta_handle,
						       &ta->ta_args[i]);
			}
			break;
		}
	}

	/* Only fail for real update */
	tsi->tsi_reply_fail_id = OBD_FAIL_UPDATE_OBJ_NET_REP;
stop:
	CDEBUG(D_INFO, "%s: executed %u/%u: rc = %d\n",
	       dt_obd_name(ta->ta_dev), i, ta->ta_argno, rc);
	out_trans_stop(env, ta, rc);
	ta->ta_handle = NULL;
	ta->ta_argno = 0;
	ta->ta_err = 0;

	RETURN(rc);
}

static void out_reconstruct(const struct lu_env *env, struct dt_device *dt,
			    struct dt_object *obj, struct update_reply *reply,
			    int index)
{
	CDEBUG(D_INFO, "%s: fork reply reply %p index %d: rc = %d\n",
	       dt_obd_name(dt), reply, index, 0);

	update_insert_reply(reply, NULL, 0, index, 0);
	return;
}

typedef void (*out_reconstruct_t)(const struct lu_env *env,
				  struct dt_device *dt,
				  struct dt_object *obj,
				  struct update_reply *reply,
				  int index);

static inline int out_check_resent(const struct lu_env *env,
				   struct dt_device *dt,
				   struct dt_object *obj,
				   struct ptlrpc_request *req,
				   out_reconstruct_t reconstruct,
				   struct update_reply *reply,
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
int out_tx_create_undo(const struct lu_env *env, struct thandle *th,
		       struct tx_arg *arg)
{
	int rc;

	rc = out_obj_destroy(env, arg->object, th);
	if (rc != 0)
		CERROR("%s: undo failure, we are doomed!: rc = %d\n",
		       dt_obd_name(th->th_dev), rc);
	return rc;
}

int out_tx_create_exec(const struct lu_env *env, struct thandle *th,
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

	update_insert_reply(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int __out_tx_create(const struct lu_env *env, struct dt_object *obj,
			   struct lu_attr *attr, struct lu_fid *parent_fid,
			   struct dt_object_format *dof,
			   struct thandle_exec_args *ta,
			   struct update_reply *reply,
			   int index, char *file, int line)
{
	struct tx_arg *arg;

	LASSERT(ta->ta_handle != NULL);
	ta->ta_err = dt_declare_create(env, obj, attr, NULL, dof,
				       ta->ta_handle);
	if (ta->ta_err != 0)
		return ta->ta_err;

	arg = tx_add_exec(ta, out_tx_create_exec, out_tx_create_undo, file,
			  line);
	LASSERT(arg);

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
	struct update		*update = tti->tti_u.update.tti_update;
	struct dt_object        *obj = tti->tti_u.update.tti_dt_object;
	struct dt_object_format	*dof = &tti->tti_u.update.tti_update_dof;
	struct obdo		*lobdo = &tti->tti_u.update.tti_obdo;
	struct lu_attr		*attr = &tti->tti_attr;
	struct lu_fid		*fid = NULL;
	struct obdo		*wobdo;
	int			size;
	int			rc;

	ENTRY;

	wobdo = update_param_buf(update, 0, &size);
	if (wobdo == NULL || size != sizeof(*wobdo)) {
		CERROR("%s: obdo is NULL, invalid RPC: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	obdo_le_to_cpu(wobdo, wobdo);
	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	la_from_obdo(attr, lobdo, lobdo->o_valid);

	dof->dof_type = dt_mode_to_dft(attr->la_mode);
	if (update->u_lens[1] > 0) {
		int size;

		fid = update_param_buf(update, 1, &size);
		if (fid == NULL || size != sizeof(*fid)) {
			CERROR("%s: invalid fid: rc = %d\n",
			       tgt_name(tsi->tsi_tgt), -EPROTO);
			RETURN(err_serious(-EPROTO));
		}
		fid_le_to_cpu(fid, fid);
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
	rc = dt_attr_set(env, dt_obj, &arg->u.attr_set.attr, th, NULL);
	dt_write_unlock(env, dt_obj);

	CDEBUG(D_INFO, "%s: insert attr_set reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	update_insert_reply(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int __out_tx_attr_set(const struct lu_env *env,
			     struct dt_object *dt_obj,
			     const struct lu_attr *attr,
			     struct thandle_exec_args *th,
			     struct update_reply *reply, int index,
			     char *file, int line)
{
	struct tx_arg		*arg;

	LASSERT(th->ta_handle != NULL);
	th->ta_err = dt_declare_attr_set(env, dt_obj, attr, th->ta_handle);
	if (th->ta_err != 0)
		return th->ta_err;

	arg = tx_add_exec(th, out_tx_attr_set_exec, out_tx_attr_set_undo,
			  file, line);
	LASSERT(arg);
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
	struct update		*update = tti->tti_u.update.tti_update;
	struct lu_attr		*attr = &tti->tti_attr;
	struct dt_object        *obj = tti->tti_u.update.tti_dt_object;
	struct obdo		*lobdo = &tti->tti_u.update.tti_obdo;
	struct obdo		*wobdo;
	int			 size;
	int			 rc;

	ENTRY;

	wobdo = update_param_buf(update, 0, &size);
	if (wobdo == NULL || size != sizeof(*wobdo)) {
		CERROR("%s: empty obdo in the update: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	attr->la_valid = 0;
	attr->la_valid = 0;
	obdo_le_to_cpu(wobdo, wobdo);
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
	int			rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	dt_read_lock(env, obj, MOR_TGT_CHILD);
	rc = dt_attr_get(env, obj, la, NULL);
	if (rc)
		GOTO(out_unlock, rc);
	/*
	 * If it is a directory, we will also check whether the
	 * directory is empty.
	 * la_flags = 0 : Empty.
	 *          = 1 : Not empty.
	 */
	la->la_flags = 0;
	if (S_ISDIR(la->la_mode)) {
		struct dt_it		*it;
		const struct dt_it_ops	*iops;

		if (!dt_try_as_dir(env, obj))
			GOTO(out_unlock, rc = -ENOTDIR);

		iops = &obj->do_index_ops->dio_it;
		it = iops->init(env, obj, LUDA_64BITHASH, BYPASS_CAPA);
		if (!IS_ERR(it)) {
			int  result;
			result = iops->get(env, it, (const void *)"");
			if (result > 0) {
				int i;
				for (result = 0, i = 0; result == 0 && i < 3;
				     ++i)
					result = iops->next(env, it);
				if (result == 0)
					la->la_flags = 1;
			} else if (result == 0)
				/*
				 * Huh? Index contains no zero key?
				 */
				rc = -EIO;

			iops->put(env, it);
			iops->fini(env, it);
		}
	}

	obdo->o_valid = 0;
	obdo_from_la(obdo, la, la->la_valid);
	obdo_cpu_to_le(obdo, obdo);
	lustre_set_wire_obdo(NULL, obdo, obdo);

out_unlock:
	dt_read_unlock(env, obj);

	CDEBUG(D_INFO, "%s: insert attr get reply %p index %d: rc = %d\n",
	       tgt_name(tsi->tsi_tgt), tti->tti_u.update.tti_update_reply,
	       0, rc);

	update_insert_reply(tti->tti_u.update.tti_update_reply, obdo,
			    sizeof(*obdo),
			    tti->tti_u.update.tti_update_reply_index, rc);
	RETURN(rc);
}

static int out_xattr_get(struct tgt_session_info *tsi)
{
	const struct lu_env	*env = tsi->tsi_env;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct update		*update = tti->tti_u.update.tti_update;
	struct lu_buf		*lbuf = &tti->tti_buf;
	struct update_reply     *reply = tti->tti_u.update.tti_update_reply;
	struct dt_object        *obj = tti->tti_u.update.tti_dt_object;
	char			*name;
	void			*ptr;
	int			 idx = tti->tti_u.update.tti_update_reply_index;
	int			 rc;

	ENTRY;

	name = (char *)update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for xattr get: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	ptr = update_get_buf_internal(reply, idx, NULL);
	LASSERT(ptr != NULL);

	/* The first 4 bytes(int) are used to store the result */
	lbuf->lb_buf = (char *)ptr + sizeof(int);
	lbuf->lb_len = UPDATE_BUFFER_SIZE - sizeof(struct update_reply);
	dt_read_lock(env, obj, MOR_TGT_CHILD);
	rc = dt_xattr_get(env, obj, lbuf, name, NULL);
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
	*(int *)ptr = rc;
	reply->ur_lens[idx] = lbuf->lb_len + sizeof(int);

	return rc;
}

static int out_index_lookup(struct tgt_session_info *tsi)
{
	const struct lu_env	*env = tsi->tsi_env;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct update		*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	char			*name;
	int			 rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	name = (char *)update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for lookup: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	dt_read_lock(env, obj, MOR_TGT_CHILD);
	if (!dt_try_as_dir(env, obj))
		GOTO(out_unlock, rc = -ENOTDIR);

	rc = dt_lookup(env, obj, (struct dt_rec *)&tti->tti_fid1,
		(struct dt_key *)name, NULL);

	if (rc < 0)
		GOTO(out_unlock, rc);

	if (rc == 0)
		rc += 1;

	CDEBUG(D_INFO, "lookup "DFID" %s get "DFID" rc %d\n",
	       PFID(lu_object_fid(&obj->do_lu)), name,
	       PFID(&tti->tti_fid1), rc);
	fid_cpu_to_le(&tti->tti_fid1, &tti->tti_fid1);

out_unlock:
	dt_read_unlock(env, obj);

	CDEBUG(D_INFO, "%s: insert lookup reply %p index %d: rc = %d\n",
	       tgt_name(tsi->tsi_tgt), tti->tti_u.update.tti_update_reply,
	       0, rc);

	update_insert_reply(tti->tti_u.update.tti_update_reply,
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

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_xattr_set(env, dt_obj, &arg->u.xattr_set.buf,
			  arg->u.xattr_set.name, arg->u.xattr_set.flags,
			  th, NULL);
	dt_write_unlock(env, dt_obj);
	/**
	 * Ignore errors if this is LINK EA
	 **/
	if (unlikely(rc && !strcmp(arg->u.xattr_set.name, XATTR_NAME_LINK)))
		rc = 0;

	CDEBUG(D_INFO, "%s: insert xattr set reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	update_insert_reply(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int __out_tx_xattr_set(const struct lu_env *env,
			      struct dt_object *dt_obj,
			      const struct lu_buf *buf,
			      const char *name, int flags,
			      struct thandle_exec_args *ta,
			      struct update_reply *reply, int index,
			      char *file, int line)
{
	struct tx_arg		*arg;

	LASSERT(ta->ta_handle != NULL);
	ta->ta_err = dt_declare_xattr_set(env, dt_obj, buf, name,
					  flags, ta->ta_handle);
	if (ta->ta_err != 0)
		return ta->ta_err;

	arg = tx_add_exec(ta, out_tx_xattr_set_exec, NULL, file, line);
	LASSERT(arg);
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
	struct update		*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	struct lu_buf		*lbuf = &tti->tti_buf;
	char			*name;
	char			*buf;
	char			*tmp;
	int			 buf_len = 0;
	int			 flag;
	int			 rc;
	ENTRY;

	name = update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for xattr set: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	buf = (char *)update_param_buf(update, 1, &buf_len);
	if (buf == NULL || buf_len == 0) {
		CERROR("%s: empty buf for xattr set: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	lbuf->lb_buf = buf;
	lbuf->lb_len = buf_len;

	tmp = (char *)update_param_buf(update, 2, NULL);
	if (tmp == NULL) {
		CERROR("%s: empty flag for xattr set: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	flag = le32_to_cpu(*(int *)tmp);

	rc = out_tx_xattr_set(tsi->tsi_env, obj, lbuf, name, flag,
			      &tti->tti_tea,
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

	update_insert_reply(arg->reply, NULL, 0, arg->index, rc);
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
			    struct update_reply *reply,
			    int index, char *file, int line)
{
	struct tx_arg	*arg;

	LASSERT(ta->ta_handle != NULL);
	ta->ta_err = dt_declare_ref_add(env, dt_obj, ta->ta_handle);
	if (ta->ta_err != 0)
		return ta->ta_err;

	arg = tx_add_exec(ta, out_tx_ref_add_exec, out_tx_ref_add_undo, file,
			  line);
	LASSERT(arg);
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

	update_insert_reply(arg->reply, NULL, 0, arg->index, rc);

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
			    struct update_reply *reply,
			    int index, char *file, int line)
{
	struct tx_arg	*arg;

	LASSERT(ta->ta_handle != NULL);
	ta->ta_err = dt_declare_ref_del(env, dt_obj, ta->ta_handle);
	if (ta->ta_err != 0)
		return ta->ta_err;

	arg = tx_add_exec(ta, out_tx_ref_del_exec, out_tx_ref_del_undo, file,
			  line);
	LASSERT(arg);
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

	CDEBUG(D_INFO, "%s: index insert "DFID" name: %s fid "DFID"\n",
	       dt_obd_name(th->th_dev), PFID(lu_object_fid(&dt_obj->do_lu)),
	       (char *)key, PFID((struct lu_fid *)rec));

	if (dt_try_as_dir(env, dt_obj) == 0)
		return -ENOTDIR;

	dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
	rc = dt_insert(env, dt_obj, rec, key, th, NULL, 0);
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
	rc = dt_delete(env, dt_obj, key, th, NULL);
	dt_write_unlock(env, dt_obj);

	return rc;
}

static int out_tx_index_insert_exec(const struct lu_env *env,
				    struct thandle *th, struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

	rc = out_obj_index_insert(env, dt_obj, arg->u.insert.rec,
				  arg->u.insert.key, th);

	CDEBUG(D_INFO, "%s: insert idx insert reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	update_insert_reply(arg->reply, NULL, 0, arg->index, rc);

	return rc;
}

static int out_tx_index_insert_undo(const struct lu_env *env,
				    struct thandle *th, struct tx_arg *arg)
{
	return out_obj_index_delete(env, arg->object, arg->u.insert.key, th);
}

static int __out_tx_index_insert(const struct lu_env *env,
				 struct dt_object *dt_obj,
				 char *name, struct lu_fid *fid,
				 struct thandle_exec_args *ta,
				 struct update_reply *reply,
				 int index, char *file, int line)
{
	struct tx_arg *arg;

	LASSERT(ta->ta_handle != NULL);

	if (lu_object_exists(&dt_obj->do_lu)) {
		if (dt_try_as_dir(env, dt_obj) == 0) {
			ta->ta_err = -ENOTDIR;
			return ta->ta_err;
		}
		ta->ta_err = dt_declare_insert(env, dt_obj,
					       (struct dt_rec *)fid,
					       (struct dt_key *)name,
					       ta->ta_handle);
	}

	if (ta->ta_err != 0)
		return ta->ta_err;

	arg = tx_add_exec(ta, out_tx_index_insert_exec,
			  out_tx_index_insert_undo, file,
			  line);
	LASSERT(arg);
	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	arg->u.insert.rec = (struct dt_rec *)fid;
	arg->u.insert.key = (struct dt_key *)name;

	return 0;
}

static int out_index_insert(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct update	  *update = tti->tti_u.update.tti_update;
	struct dt_object  *obj = tti->tti_u.update.tti_dt_object;
	struct lu_fid	  *fid;
	char		  *name;
	int		   rc = 0;
	int		   size;

	ENTRY;

	name = (char *)update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for index insert: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	fid = (struct lu_fid *)update_param_buf(update, 1, &size);
	if (fid == NULL || size != sizeof(*fid)) {
		CERROR("%s: invalid fid: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		       RETURN(err_serious(-EPROTO));
	}

	fid_le_to_cpu(fid, fid);
	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID": rc = %d\n",
		       tgt_name(tsi->tsi_tgt), PFID(fid), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	rc = out_tx_index_insert(tsi->tsi_env, obj, name, fid,
				 &tti->tti_tea,
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

	CDEBUG(D_INFO, "%s: insert idx insert reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	update_insert_reply(arg->reply, NULL, 0, arg->index, rc);

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
				 struct dt_object *dt_obj, char *name,
				 struct thandle_exec_args *ta,
				 struct update_reply *reply,
				 int index, char *file, int line)
{
	struct tx_arg *arg;

	if (dt_try_as_dir(env, dt_obj) == 0) {
		ta->ta_err = -ENOTDIR;
		return ta->ta_err;
	}

	LASSERT(ta->ta_handle != NULL);
	ta->ta_err = dt_declare_delete(env, dt_obj,
				       (struct dt_key *)name,
				       ta->ta_handle);
	if (ta->ta_err != 0)
		return ta->ta_err;

	arg = tx_add_exec(ta, out_tx_index_delete_exec,
			  out_tx_index_delete_undo, file,
			  line);
	LASSERT(arg);
	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	arg->u.insert.key = (struct dt_key *)name;
	return 0;
}

static int out_index_delete(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct update		*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	char			*name;
	int			 rc = 0;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	name = (char *)update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for index delete: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	rc = out_tx_index_delete(tsi->tsi_env, obj, name, &tti->tti_tea,
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

	update_insert_reply(arg->reply, NULL, 0, arg->index, rc);

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
			     struct update_reply *reply,
			     int index, char *file, int line)
{
	struct tx_arg *arg;

	LASSERT(ta->ta_handle != NULL);
	ta->ta_err = dt_declare_destroy(env, dt_obj, ta->ta_handle);
	if (ta->ta_err)
		return ta->ta_err;

	arg = tx_add_exec(ta, out_tx_destroy_exec, out_tx_destroy_undo,
			  file, line);
	LASSERT(arg);
	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	return 0;
}

static int out_destroy(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct update		*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	struct lu_fid		*fid;
	int			 rc;
	ENTRY;

	fid = &update->u_fid;
	fid_le_to_cpu(fid, fid);
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

#define DEF_OUT_HNDL(opc, name, flags, fn)     \
[opc - OBJ_CREATE] = {					\
	.th_name    = name,				\
	.th_fail_id = 0,				\
	.th_opc     = opc,				\
	.th_flags   = flags,				\
	.th_act     = fn,				\
	.th_fmt     = NULL,				\
	.th_version = 0,				\
}

#define out_handler mdt_handler
static struct tgt_handler out_update_ops[] = {
	DEF_OUT_HNDL(OBJ_CREATE, "obj_create", MUTABOR | HABEO_REFERO,
		     out_create),
	DEF_OUT_HNDL(OBJ_DESTROY, "obj_create", MUTABOR | HABEO_REFERO,
		     out_destroy),
	DEF_OUT_HNDL(OBJ_REF_ADD, "obj_ref_add", MUTABOR | HABEO_REFERO,
		     out_ref_add),
	DEF_OUT_HNDL(OBJ_REF_DEL, "obj_ref_del", MUTABOR | HABEO_REFERO,
		     out_ref_del),
	DEF_OUT_HNDL(OBJ_ATTR_SET, "obj_attr_set",  MUTABOR | HABEO_REFERO,
		     out_attr_set),
	DEF_OUT_HNDL(OBJ_ATTR_GET, "obj_attr_get",  HABEO_REFERO,
		     out_attr_get),
	DEF_OUT_HNDL(OBJ_XATTR_SET, "obj_xattr_set", MUTABOR | HABEO_REFERO,
		     out_xattr_set),
	DEF_OUT_HNDL(OBJ_XATTR_GET, "obj_xattr_get", HABEO_REFERO,
		     out_xattr_get),
	DEF_OUT_HNDL(OBJ_INDEX_LOOKUP, "obj_index_lookup", HABEO_REFERO,
		     out_index_lookup),
	DEF_OUT_HNDL(OBJ_INDEX_INSERT, "obj_index_insert",
		     MUTABOR | HABEO_REFERO, out_index_insert),
	DEF_OUT_HNDL(OBJ_INDEX_DELETE, "obj_index_delete",
		     MUTABOR | HABEO_REFERO, out_index_delete),
};

struct tgt_handler *out_handler_find(__u32 opc)
{
	struct tgt_handler *h;

	h = NULL;
	if (OBJ_CREATE <= opc && opc < OBJ_LAST) {
		h = &out_update_ops[opc - OBJ_CREATE];
		LASSERTF(h->th_opc == opc, "opcode mismatch %d != %d\n",
			 h->th_opc, opc);
	} else {
		h = NULL; /* unsupported opc */
	}
	return h;
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
	struct update_buf		*ubuf;
	struct update			*update;
	struct update_reply		*update_reply;
	int				 bufsize;
	int				 count;
	int				 old_batchid = -1;
	unsigned			 off;
	int				 i;
	int				 rc = 0;
	int				 rc1 = 0;

	ENTRY;

	req_capsule_set(pill, &RQF_UPDATE_OBJ);
	bufsize = req_capsule_get_size(pill, &RMF_UPDATE, RCL_CLIENT);
	if (bufsize != UPDATE_BUFFER_SIZE) {
		CERROR("%s: invalid bufsize %d: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), bufsize, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	ubuf = req_capsule_client_get(pill, &RMF_UPDATE);
	if (ubuf == NULL) {
		CERROR("%s: No buf!: rc = %d\n", tgt_name(tsi->tsi_tgt),
		       -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	if (ubuf->ub_magic != UPDATE_BUFFER_MAGIC) {
		CERROR("%s: invalid magic %x expect %x: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), ubuf->ub_magic,
		       UPDATE_BUFFER_MAGIC, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	count = ubuf->ub_count;
	if (count <= 0) {
		CERROR("%s: No update!: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	req_capsule_set_size(pill, &RMF_UPDATE_REPLY, RCL_SERVER,
			     UPDATE_BUFFER_SIZE);
	rc = req_capsule_server_pack(pill);
	if (rc != 0) {
		CERROR("%s: Can't pack response: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}

	/* Prepare the update reply buffer */
	update_reply = req_capsule_server_get(pill, &RMF_UPDATE_REPLY);
	if (update_reply == NULL)
		RETURN(err_serious(-EPROTO));
	update_init_reply_buf(update_reply, count);
	tti->tti_u.update.tti_update_reply = update_reply;

	rc = out_tx_start(env, dt, ta, tsi->tsi_exp);
	if (rc != 0)
		RETURN(rc);

	tti->tti_mult_trans = !req_is_replay(tgt_ses_req(tsi));

	/* Walk through updates in the request to execute them synchronously */
	off = cfs_size_round(offsetof(struct update_buf, ub_bufs[0]));
	for (i = 0; i < count; i++) {
		struct tgt_handler	*h;
		struct dt_object	*dt_obj;

		update = (struct update *)((char *)ubuf + off);
		if (old_batchid == -1) {
			old_batchid = update->u_batchid;
		} else if (old_batchid != update->u_batchid) {
			/* Stop the current update transaction,
			 * create a new one */
			rc = out_tx_end(env, ta);
			if (rc != 0)
				RETURN(rc);

			rc = out_tx_start(env, dt, ta, tsi->tsi_exp);
			if (rc != 0)
				RETURN(rc);
			old_batchid = update->u_batchid;
		}

		fid_le_to_cpu(&update->u_fid, &update->u_fid);
		if (!fid_is_sane(&update->u_fid)) {
			CERROR("%s: invalid FID "DFID": rc = %d\n",
			       tgt_name(tsi->tsi_tgt), PFID(&update->u_fid),
			       -EPROTO);
			GOTO(out, rc = err_serious(-EPROTO));
		}

		dt_obj = dt_locate(env, dt, &update->u_fid);
		if (IS_ERR(dt_obj))
			GOTO(out, rc = PTR_ERR(dt_obj));

		tti->tti_u.update.tti_dt_object = dt_obj;
		tti->tti_u.update.tti_update = update;
		tti->tti_u.update.tti_update_reply_index = i;

		h = out_handler_find(update->u_type);
		if (likely(h != NULL)) {
			/* For real modification RPC, check if the update
			 * has been executed */
			if (h->th_flags & MUTABOR) {
				struct ptlrpc_request *req = tgt_ses_req(tsi);

				if (out_check_resent(env, dt, dt_obj, req,
						     out_reconstruct,
						     update_reply, i))
					GOTO(next, rc);
			}

			rc = h->th_act(tsi);
		} else {
			CERROR("%s: The unsupported opc: 0x%x\n",
			       tgt_name(tsi->tsi_tgt), update->u_type);
			lu_object_put(env, &dt_obj->do_lu);
			GOTO(out, rc = -ENOTSUPP);
		}
next:
		lu_object_put(env, &dt_obj->do_lu);
		if (rc < 0)
			GOTO(out, rc);
		off += cfs_size_round(update_size(update));
	}
out:
	rc1 = out_tx_end(env, ta);
	if (rc == 0)
		rc = rc1;
	RETURN(rc);
}

struct tgt_handler tgt_out_handlers[] = {
TGT_UPDATE_HDL(MUTABOR,	UPDATE_OBJ,	out_handle),
};
EXPORT_SYMBOL(tgt_out_handlers);

