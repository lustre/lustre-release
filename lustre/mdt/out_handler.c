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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"
#include <lustre_update.h>

static const char dot[] = ".";
static const char dotdot[] = "..";

/* Current out and mdt shared the same thread info, but in the future,
 * this should be decoupled with MDT XXX*/
#define out_thread_info		mdt_thread_info
#define out_thread_key		mdt_thread_key

struct out_thread_info *out_env_info(const struct lu_env *env)
{
	struct out_thread_info *info;

	info = lu_context_key_get(&env->le_ctx, &out_thread_key);
	LASSERT(info != NULL);
	return info;
}

static inline char *dt_obd_name(struct dt_device *dt)
{
	return dt->dd_lu_dev.ld_obd->obd_name;
}

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
			struct thandle_exec_args *th)
{
	memset(th, 0, sizeof(*th));
	th->ta_handle = dt_trans_create(env, dt);
	if (IS_ERR(th->ta_handle)) {
		CERROR("%s: start handle error: rc = %ld\n",
		       dt_obd_name(dt), PTR_ERR(th->ta_handle));
		return PTR_ERR(th->ta_handle);
	}
	th->ta_dev = dt;
	/*For phase I, sync for cross-ref operation*/
	th->ta_handle->th_sync = 1;
	return 0;
}

static int out_trans_start(const struct lu_env *env,
			   struct thandle_exec_args *th)
{
	/* Always do sync commit for Phase I */
	LASSERT(th->ta_handle->th_sync != 0);
	return dt_trans_start(env, th->ta_dev, th->ta_handle);
}

static int out_trans_stop(const struct lu_env *env,
			  struct thandle_exec_args *th, int err)
{
	int i;
	int rc;

	th->ta_handle->th_result = err;
	LASSERT(th->ta_handle->th_sync != 0);
	rc = dt_trans_stop(env, th->ta_dev, th->ta_handle);
	for (i = 0; i < th->ta_argno; i++) {
		if (th->ta_args[i].object != NULL) {
			lu_object_put(env, &th->ta_args[i].object->do_lu);
			th->ta_args[i].object = NULL;
		}
	}

	return rc;
}

int out_tx_end(const struct lu_env *env, struct thandle_exec_args *th)
{
	struct out_thread_info *info = out_env_info(env);
	int i = 0, rc;

	LASSERT(th->ta_dev);
	LASSERT(th->ta_handle);

	if (th->ta_err != 0 || th->ta_argno == 0)
		GOTO(stop, rc = th->ta_err);

	rc = out_trans_start(env, th);
	if (unlikely(rc))
		GOTO(stop, rc);

	for (i = 0; i < th->ta_argno; i++) {
		rc = th->ta_args[i].exec_fn(env, th->ta_handle,
					    &th->ta_args[i]);
		if (unlikely(rc)) {
			CDEBUG(D_INFO, "error during execution of #%u from"
			       " %s:%d: rc = %d\n", i, th->ta_args[i].file,
			       th->ta_args[i].line, rc);
			while (--i >= 0) {
				LASSERTF(th->ta_args[i].undo_fn != NULL,
				    "can't undo changes, hope for failover!\n");
				th->ta_args[i].undo_fn(env, th->ta_handle,
						       &th->ta_args[i]);
			}
			break;
		}
	}

	/* Only fail for real update */
	info->mti_fail_id = OBD_FAIL_UPDATE_OBJ_NET_REP;
stop:
	CDEBUG(D_INFO, "%s: executed %u/%u: rc = %d\n",
	       dt_obd_name(th->ta_dev), i, th->ta_argno, rc);
	out_trans_stop(env, th, rc);
	th->ta_handle = NULL;
	th->ta_argno = 0;
	th->ta_err = 0;

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
	struct dt_object *dt_obj = arg->object;
	int rc;

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
			   struct thandle_exec_args *th,
			   struct update_reply *reply,
			   int index, char *file, int line)
{
	struct tx_arg *arg;

	LASSERT(th->ta_handle != NULL);
	th->ta_err = dt_declare_create(env, obj, attr, NULL, dof,
				       th->ta_handle);
	if (th->ta_err != 0)
		return th->ta_err;

	arg = tx_add_exec(th, out_tx_create_exec, out_tx_create_undo, file,
			  line);
	LASSERT(arg);

	/* release the object in out_trans_stop */
	lu_object_get(&obj->do_lu);
	arg->object = obj;
	arg->u.create.attr = *attr;
	if (parent_fid)
		arg->u.create.fid = *parent_fid;
	memset(&arg->u.create.hint, 0, sizeof(arg->u.create.hint));
	arg->u.create.dof  = *dof;
	arg->reply = reply;
	arg->index = index;

	return 0;
}

static int out_create(struct out_thread_info *info)
{
	struct update		*update = info->mti_u.update.mti_update;
	struct dt_object        *obj = info->mti_u.update.mti_dt_object;
	struct dt_object_format	*dof = &info->mti_u.update.mti_update_dof;
	struct obdo		*lobdo = &info->mti_u.update.mti_obdo;
	struct lu_attr		*attr = &info->mti_attr.ma_attr;
	struct lu_fid		*fid = NULL;
	struct obdo		*wobdo;
	int			size;
	int			rc;

	ENTRY;

	wobdo = update_param_buf(update, 0, &size);
	if (wobdo == NULL || size != sizeof(*wobdo)) {
		CERROR("%s: obdo is NULL, invalid RPC: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	obdo_le_to_cpu(wobdo, wobdo);
	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	la_from_obdo(attr, lobdo, lobdo->o_valid);

	dof->dof_type = dt_mode_to_dft(attr->la_mode);
	if (S_ISDIR(attr->la_mode)) {
		int size;

		fid = update_param_buf(update, 1, &size);
		if (fid == NULL || size != sizeof(*fid)) {
			CERROR("%s: invalid fid: rc = %d\n",
			       mdt_obd_name(info->mti_mdt), -EPROTO);
			RETURN(err_serious(-EPROTO));
		}
		fid_le_to_cpu(fid, fid);
		if (!fid_is_sane(fid)) {
			CERROR("%s: invalid fid "DFID": rc = %d\n",
			       mdt_obd_name(info->mti_mdt),
			       PFID(fid), -EPROTO);
			RETURN(err_serious(-EPROTO));
		}
	}

	if (lu_object_exists(&obj->do_lu))
		RETURN(-EEXIST);

	rc = out_tx_create(info->mti_env, obj, attr, fid, dof,
			   &info->mti_handle,
			   info->mti_u.update.mti_update_reply,
			   info->mti_u.update.mti_update_reply_index);

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
	rc = dt_attr_set(env, dt_obj, &arg->u.attr_set.attr,
			 th, NULL);
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

static int out_attr_set(struct out_thread_info *info)
{
	struct update		*update = info->mti_u.update.mti_update;
	struct lu_attr		*attr = &info->mti_attr.ma_attr;
	struct dt_object        *obj = info->mti_u.update.mti_dt_object;
	struct obdo		*lobdo = &info->mti_u.update.mti_obdo;
	struct obdo		*wobdo;
	int			size;
	int			rc;

	ENTRY;

	wobdo = update_param_buf(update, 0, &size);
	if (wobdo == NULL || size != sizeof(*wobdo)) {
		CERROR("%s: empty obdo in the update: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	attr->la_valid = 0;
	attr->la_valid = 0;
	obdo_le_to_cpu(wobdo, wobdo);
	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	la_from_obdo(attr, lobdo, lobdo->o_valid);

	rc = out_tx_attr_set(info->mti_env, obj, attr, &info->mti_handle,
			     info->mti_u.update.mti_update_reply,
			     info->mti_u.update.mti_update_reply_index);

	RETURN(rc);
}

static int out_attr_get(struct out_thread_info *info)
{
	struct obdo		*obdo = &info->mti_u.update.mti_obdo;
	const struct lu_env	*env = info->mti_env;
	struct lu_attr		*la = &info->mti_attr.ma_attr;
	struct dt_object        *obj = info->mti_u.update.mti_dt_object;
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
		struct dt_it     *it;
		const struct dt_it_ops *iops;

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
	       mdt_obd_name(info->mti_mdt),
	       info->mti_u.update.mti_update_reply, 0, rc);

	update_insert_reply(info->mti_u.update.mti_update_reply, obdo,
			    sizeof(*obdo), 0, rc);
	RETURN(rc);
}

static int out_xattr_get(struct out_thread_info *info)
{
	struct update		*update = info->mti_u.update.mti_update;
	const struct lu_env     *env = info->mti_env;
	struct lu_buf		*lbuf = &info->mti_buf;
	struct update_reply     *reply = info->mti_u.update.mti_update_reply;
	struct dt_object        *obj = info->mti_u.update.mti_dt_object;
	char			*name;
	void			*ptr;
	int			rc;

	ENTRY;

	name = (char *)update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for xattr get: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	ptr = update_get_buf_internal(reply, 0, NULL);
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
	       mdt_obd_name(info->mti_mdt), PFID(lu_object_fid(&obj->do_lu)),
	       name, (int)lbuf->lb_len);
out:
	*(int *)ptr = rc;
	reply->ur_lens[0] = lbuf->lb_len + sizeof(int);
	RETURN(rc);
}

static int out_index_lookup(struct out_thread_info *info)
{
	struct update		*update = info->mti_u.update.mti_update;
	const struct lu_env	*env = info->mti_env;
	struct dt_object	*obj = info->mti_u.update.mti_dt_object;
	char			*name;
	int			rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	name = (char *)update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for lookup: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	dt_read_lock(env, obj, MOR_TGT_CHILD);
	if (!dt_try_as_dir(env, obj))
		GOTO(out_unlock, rc = -ENOTDIR);

	rc = dt_lookup(env, obj, (struct dt_rec *)&info->mti_tmp_fid1,
		(struct dt_key *)name, NULL);

	if (rc < 0)
		GOTO(out_unlock, rc);

	if (rc == 0)
		rc += 1;

	CDEBUG(D_INFO, "lookup "DFID" %s get "DFID" rc %d\n",
	       PFID(lu_object_fid(&obj->do_lu)), name,
	       PFID(&info->mti_tmp_fid1), rc);
	fid_cpu_to_le(&info->mti_tmp_fid1, &info->mti_tmp_fid1);

out_unlock:
	dt_read_unlock(env, obj);

	CDEBUG(D_INFO, "%s: insert lookup reply %p index %d: rc = %d\n",
	       mdt_obd_name(info->mti_mdt),
	       info->mti_u.update.mti_update_reply, 0, rc);

	update_insert_reply(info->mti_u.update.mti_update_reply,
			    &info->mti_tmp_fid1, sizeof(info->mti_tmp_fid1),
			    0, rc);
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
	if (unlikely(rc && !strncmp(arg->u.xattr_set.name, XATTR_NAME_LINK,
				    strlen(XATTR_NAME_LINK))))
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
			      struct thandle_exec_args *th,
			      struct update_reply *reply, int index,
			      char *file, int line)
{
	struct tx_arg		*arg;

	LASSERT(th->ta_handle != NULL);
	th->ta_err = dt_declare_xattr_set(env, dt_obj, buf, name,
					  flags, th->ta_handle);
	if (th->ta_err != 0)
		return th->ta_err;

	arg = tx_add_exec(th, out_tx_xattr_set_exec, NULL, file, line);
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

static int out_xattr_set(struct out_thread_info *info)
{
	struct update		*update = info->mti_u.update.mti_update;
	struct dt_object	*obj = info->mti_u.update.mti_dt_object;
	struct lu_buf		*lbuf = &info->mti_buf;
	char			*name;
	char			*buf;
	char			*tmp;
	int			buf_len = 0;
	int			flag;
	int			rc;
	ENTRY;

	name = update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for xattr set: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	buf = (char *)update_param_buf(update, 1, &buf_len);
	if (buf == NULL || buf_len == 0) {
		CERROR("%s: empty buf for xattr set: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	lbuf->lb_buf = buf;
	lbuf->lb_len = buf_len;

	tmp = (char *)update_param_buf(update, 2, NULL);
	if (tmp == NULL) {
		CERROR("%s: empty flag for xattr set: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	flag = le32_to_cpu(*(int *)tmp);

	rc = out_tx_xattr_set(info->mti_env, obj, lbuf, name, flag,
			      &info->mti_handle,
			      info->mti_u.update.mti_update_reply,
			      info->mti_u.update.mti_update_reply_index);
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
			    struct thandle_exec_args *th,
			    struct update_reply *reply,
			    int index, char *file, int line)
{
	struct tx_arg		*arg;

	LASSERT(th->ta_handle != NULL);
	th->ta_err = dt_declare_ref_add(env, dt_obj, th->ta_handle);
	if (th->ta_err != 0)
		return th->ta_err;

	arg = tx_add_exec(th, out_tx_ref_add_exec, out_tx_ref_add_undo, file,
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
static int out_ref_add(struct out_thread_info *info)
{
	struct dt_object  *obj = info->mti_u.update.mti_dt_object;
	int		  rc;

	ENTRY;

	rc = out_tx_ref_add(info->mti_env, obj, &info->mti_handle,
			    info->mti_u.update.mti_update_reply,
			    info->mti_u.update.mti_update_reply_index);
	RETURN(rc);
}

static int out_tx_ref_del_exec(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

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
			    struct thandle_exec_args *th,
			    struct update_reply *reply,
			    int index, char *file, int line)
{
	struct tx_arg		*arg;

	LASSERT(th->ta_handle != NULL);
	th->ta_err = dt_declare_ref_del(env, dt_obj, th->ta_handle);
	if (th->ta_err != 0)
		return th->ta_err;

	arg = tx_add_exec(th, out_tx_ref_del_exec, out_tx_ref_del_undo, file,
			  line);
	LASSERT(arg);
	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	return 0;
}

static int out_ref_del(struct out_thread_info *info)
{
	struct dt_object  *obj = info->mti_u.update.mti_dt_object;
	int		  rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	rc = out_tx_ref_del(info->mti_env, obj, &info->mti_handle,
			    info->mti_u.update.mti_update_reply,
			    info->mti_u.update.mti_update_reply_index);
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
				 struct thandle_exec_args *th,
				 struct update_reply *reply,
				 int index, char *file, int line)
{
	struct tx_arg *arg;

	LASSERT(th->ta_handle != NULL);

	if (lu_object_exists(&dt_obj->do_lu)) {
		if (dt_try_as_dir(env, dt_obj) == 0) {
			th->ta_err = -ENOTDIR;
			return th->ta_err;
		}
		th->ta_err = dt_declare_insert(env, dt_obj,
					       (struct dt_rec *)fid,
					       (struct dt_key *)name,
					       th->ta_handle);
	}

	if (th->ta_err != 0)
		return th->ta_err;

	arg = tx_add_exec(th, out_tx_index_insert_exec,
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

static int out_index_insert(struct out_thread_info *info)
{
	struct update	  *update = info->mti_u.update.mti_update;
	struct dt_object  *obj = info->mti_u.update.mti_dt_object;
	struct lu_fid	  *fid;
	char		  *name;
	int		  rc = 0;
	int		  size;
	ENTRY;

	name = (char *)update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for index insert: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	fid = (struct lu_fid *)update_param_buf(update, 1, &size);
	if (fid == NULL || size != sizeof(*fid)) {
		CERROR("%s: invalid fid: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		       RETURN(err_serious(-EPROTO));
	}

	fid_le_to_cpu(fid, fid);
	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID": rc = %d\n",
		       mdt_obd_name(info->mti_mdt), PFID(fid),
		       -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	rc = out_tx_index_insert(info->mti_env, obj, name, fid,
				 &info->mti_handle,
				 info->mti_u.update.mti_update_reply,
				 info->mti_u.update.mti_update_reply_index);
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
				 struct thandle_exec_args *th,
				 struct update_reply *reply,
				 int index, char *file, int line)
{
	struct tx_arg *arg;

	if (dt_try_as_dir(env, dt_obj) == 0) {
		th->ta_err = -ENOTDIR;
		return th->ta_err;
	}

	LASSERT(th->ta_handle != NULL);
	th->ta_err = dt_declare_delete(env, dt_obj,
				       (struct dt_key *)name,
				       th->ta_handle);
	if (th->ta_err != 0)
		return th->ta_err;

	arg = tx_add_exec(th, out_tx_index_delete_exec,
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

static int out_index_delete(struct out_thread_info *info)
{
	struct update		*update = info->mti_u.update.mti_update;
	struct dt_object	*obj = info->mti_u.update.mti_dt_object;
	char			*name;
	int			rc = 0;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);
	name = (char *)update_param_buf(update, 0, NULL);
	if (name == NULL) {
		CERROR("%s: empty name for index delete: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	rc = out_tx_index_delete(info->mti_env, obj, name, &info->mti_handle,
				 info->mti_u.update.mti_update_reply,
				 info->mti_u.update.mti_update_reply_index);
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
			     struct thandle_exec_args *th,
			     struct update_reply *reply,
			     int index, char *file, int line)
{
	struct tx_arg *arg;

	LASSERT(th->ta_handle != NULL);
	th->ta_err = dt_declare_destroy(env, dt_obj, th->ta_handle);
	if (th->ta_err)
		return th->ta_err;

	arg = tx_add_exec(th, out_tx_destroy_exec, out_tx_destroy_undo,
			  file, line);
	LASSERT(arg);
	lu_object_get(&dt_obj->do_lu);
	arg->object = dt_obj;
	arg->reply = reply;
	arg->index = index;
	return 0;
}

static int out_destroy(struct out_thread_info *info)
{
	struct update		*update = info->mti_u.update.mti_update;
	struct dt_object	*obj = info->mti_u.update.mti_dt_object;
	struct lu_fid		*fid;
	int			rc;
	ENTRY;

	fid = &update->u_fid;
	fid_le_to_cpu(fid, fid);
	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID": rc = %d\n",
		       mdt_obd_name(info->mti_mdt), PFID(fid), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	rc = out_tx_destroy(info->mti_env, obj, &info->mti_handle,
			    info->mti_u.update.mti_update_reply,
			    info->mti_u.update.mti_update_reply_index);

	RETURN(rc);
}

#define DEF_OUT_HNDL(opc, name, fail_id, flags, fn)     \
[opc - OBJ_CREATE] = {					\
	.mh_name    = name,				\
	.mh_fail_id = fail_id,				\
	.mh_opc     = opc,				\
	.mh_flags   = flags,				\
	.mh_act     = fn,				\
	.mh_fmt     = NULL				\
}

#define out_handler mdt_handler
static struct out_handler out_update_ops[] = {
	DEF_OUT_HNDL(OBJ_CREATE, "obj_create", 0, MUTABOR | HABEO_REFERO,
		     out_create),
	DEF_OUT_HNDL(OBJ_DESTROY, "obj_create", 0, MUTABOR | HABEO_REFERO,
		     out_destroy),
	DEF_OUT_HNDL(OBJ_REF_ADD, "obj_ref_add", 0, MUTABOR | HABEO_REFERO,
		     out_ref_add),
	DEF_OUT_HNDL(OBJ_REF_DEL, "obj_ref_del", 0, MUTABOR | HABEO_REFERO,
		     out_ref_del),
	DEF_OUT_HNDL(OBJ_ATTR_SET, "obj_attr_set", 0,  MUTABOR | HABEO_REFERO,
		     out_attr_set),
	DEF_OUT_HNDL(OBJ_ATTR_GET, "obj_attr_get", 0,  HABEO_REFERO,
		     out_attr_get),
	DEF_OUT_HNDL(OBJ_XATTR_SET, "obj_xattr_set", 0, MUTABOR | HABEO_REFERO,
		     out_xattr_set),
	DEF_OUT_HNDL(OBJ_XATTR_GET, "obj_xattr_get", 0, HABEO_REFERO,
		     out_xattr_get),
	DEF_OUT_HNDL(OBJ_INDEX_LOOKUP, "obj_index_lookup", 0, HABEO_REFERO,
		     out_index_lookup),
	DEF_OUT_HNDL(OBJ_INDEX_INSERT, "obj_index_insert", 0,
		     MUTABOR | HABEO_REFERO, out_index_insert),
	DEF_OUT_HNDL(OBJ_INDEX_DELETE, "obj_index_delete", 0,
		     MUTABOR | HABEO_REFERO, out_index_delete),
};

#define out_opc_slice mdt_opc_slice
static struct out_opc_slice out_handlers[] = {
	{
		.mos_opc_start = OBJ_CREATE,
		.mos_opc_end   = OBJ_LAST,
		.mos_hs	= out_update_ops
	},
};

/**
 * Object updates between Targets. Because all the updates has been
 * dis-assemblied into object updates in master MDD layer, so out
 * will skip MDD layer, and call OSD API directly to execute these
 * updates.
 *
 * In phase I, all of the updates in the request need to be executed
 * in one transaction, and the transaction has to be synchronously.
 *
 * Please refer to lustre/include/lustre/lustre_idl.h for req/reply
 * format.
 */
int out_handle(struct out_thread_info *info)
{
	struct thandle_exec_args	*th = &info->mti_handle;
	struct req_capsule		*pill = info->mti_pill;
	struct mdt_device		*mdt = info->mti_mdt;
	struct dt_device		*dt = mdt->mdt_bottom;
	const struct lu_env		*env = info->mti_env;
	struct update_buf		*ubuf;
	struct update			*update;
	struct update_reply		*update_reply;
	int				bufsize;
	int				count;
	int				old_batchid = -1;
	unsigned			off;
	int				i;
	int				rc = 0;
	int				rc1 = 0;
	ENTRY;

	req_capsule_set(pill, &RQF_UPDATE_OBJ);
	bufsize = req_capsule_get_size(pill, &RMF_UPDATE, RCL_CLIENT);
	if (bufsize != UPDATE_BUFFER_SIZE) {
		CERROR("%s: invalid bufsize %d: rc = %d\n",
		       mdt_obd_name(mdt), bufsize, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	ubuf = req_capsule_client_get(pill, &RMF_UPDATE);
	if (ubuf == NULL) {
		CERROR("%s: No buf!: rc = %d\n", mdt_obd_name(mdt),
		       -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	if (le32_to_cpu(ubuf->ub_magic) != UPDATE_BUFFER_MAGIC) {
		CERROR("%s: invalid magic %x expect %x: rc = %d\n",
		       mdt_obd_name(mdt), le32_to_cpu(ubuf->ub_magic),
		       UPDATE_BUFFER_MAGIC, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	count = le32_to_cpu(ubuf->ub_count);
	if (count <= 0) {
		CERROR("%s: No update!: rc = %d\n",
		       mdt_obd_name(mdt), -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	req_capsule_set_size(pill, &RMF_UPDATE_REPLY, RCL_SERVER,
			     UPDATE_BUFFER_SIZE);
	rc = req_capsule_server_pack(pill);
	if (rc != 0) {
		CERROR("%s: Can't pack response: rc = %d\n",
		       mdt_obd_name(mdt), rc);
		RETURN(rc);
	}

	/* Prepare the update reply buffer */
	update_reply = req_capsule_server_get(pill, &RMF_UPDATE_REPLY);
	update_init_reply_buf(update_reply, count);
	info->mti_u.update.mti_update_reply = update_reply;

	rc = out_tx_start(env, dt, th);
	if (rc != 0)
		RETURN(rc);

	/* Walk through updates in the request to execute them synchronously */
	off = cfs_size_round(offsetof(struct update_buf, ub_bufs[0]));
	for (i = 0; i < count; i++) {
		struct out_handler *h;
		struct dt_object   *dt_obj;

		update = (struct update *)((char *)ubuf + off);
		if (old_batchid == -1) {
			old_batchid = update->u_batchid;
		} else if (old_batchid != update->u_batchid) {
			/* Stop the current update transaction,
			 * create a new one */
			rc = out_tx_end(env, th);
			if (rc != 0)
				RETURN(rc);

			rc = out_tx_start(env, dt, th);
			if (rc != 0)
				RETURN(rc);
			old_batchid = update->u_batchid;
		}

		fid_le_to_cpu(&update->u_fid, &update->u_fid);
		if (!fid_is_sane(&update->u_fid)) {
			CERROR("%s: invalid FID "DFID": rc = %d\n",
			       mdt_obd_name(mdt), PFID(&update->u_fid),
			       -EPROTO);
			GOTO(out, rc = err_serious(-EPROTO));
		}

		dt_obj = dt_locate(env, dt, &update->u_fid);
		if (IS_ERR(dt_obj))
			GOTO(out, rc = PTR_ERR(dt_obj));

		info->mti_u.update.mti_dt_object = dt_obj;
		info->mti_u.update.mti_update = update;
		info->mti_u.update.mti_update_reply_index = i;

		h = mdt_handler_find(update->u_type, out_handlers);
		if (likely(h != NULL)) {
			/* For real modification RPC, check if the update
			 * has been executed */
			if (h->mh_flags & MUTABOR) {
				struct ptlrpc_request *req = mdt_info_req(info);

				if (out_check_resent(env, dt, dt_obj, req,
						     out_reconstruct,
						     update_reply, i))
					GOTO(next, rc);
			}

			rc = h->mh_act(info);
		} else {
			CERROR("%s: The unsupported opc: 0x%x\n",
			       mdt_obd_name(mdt), update->u_type);
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
	rc1 = out_tx_end(env, th);
	rc = rc == 0 ? rc1 : rc;
	RETURN(rc);
}
