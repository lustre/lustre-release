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
 * Copyright (c) 2014, 2017, Intel Corporation.
 */
/*
 * lustre/target/out_lib.c
 *
 * Author: Di Wang <di.wang@intel.com>
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <lu_target.h>
#include <lustre_obdo.h>
#include <lustre_update.h>
#include <md_object.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_linkea.h>

#include "tgt_internal.h"

const char *update_op_str(__u16 opc)
{
	static const char *opc_str[] = {
		[OUT_START] = "start",
		[OUT_CREATE] = "create",
		[OUT_DESTROY] = "destroy",
		[OUT_REF_ADD] = "ref_add",
		[OUT_REF_DEL] = "ref_del" ,
		[OUT_ATTR_SET] = "attr_set",
		[OUT_ATTR_GET] = "attr_get",
		[OUT_XATTR_SET] = "xattr_set",
		[OUT_XATTR_GET] = "xattr_get",
		[OUT_XATTR_LIST] = "xattr_list",
		[OUT_INDEX_LOOKUP] = "lookup",
		[OUT_INDEX_INSERT] = "insert",
		[OUT_INDEX_DELETE] = "delete",
		[OUT_WRITE] = "write",
		[OUT_XATTR_DEL] = "xattr_del",
		[OUT_PUNCH] = "punch",
		[OUT_READ] = "read",
		[OUT_NOOP] = "noop",
	};

	if (opc < ARRAY_SIZE(opc_str) && opc_str[opc] != NULL)
		return opc_str[opc];
	else
		return "unknown";
}
EXPORT_SYMBOL(update_op_str);

/**
 * Fill object update header
 *
 * Only fill the object update header, and parameters will be filled later
 * in other functions.
 *
 * \params[in] env		execution environment
 * \params[in] update		object update to be filled
 * \params[in,out] max_update_size	maximum object update size, if the
 *                                      current update length equals or
 *                                      exceeds the size, it will return -E2BIG.
 * \params[in] update_op	update type
 * \params[in] fid		object FID of the update
 * \params[in] param_count	the count of the update parameters
 * \params[in] param_sizes	the length of each parameters
 *
 * \retval			0 if packing succeeds.
 * \retval			-E2BIG if packing exceeds the maximum length.
 */
int out_update_header_pack(const struct lu_env *env,
			   struct object_update *update,
			   size_t *max_update_size,
			   enum update_type update_op,
			   const struct lu_fid *fid,
			   unsigned int param_count,
			   __u16 *param_sizes,
			   __u32 reply_size)
{
	struct object_update_param	*param;
	unsigned int			i;
	size_t				update_size;

	if (reply_size  >= LNET_MTU)
		return -EINVAL;

	/* Check whether the packing exceeding the maxima update length */
	update_size = sizeof(*update);
	for (i = 0; i < param_count; i++)
		update_size += cfs_size_round(sizeof(*param) + param_sizes[i]);

	if (unlikely(update_size >= *max_update_size)) {
		*max_update_size = update_size;
		return -E2BIG;
	}

	update->ou_fid = *fid;
	update->ou_type = update_op;
	update->ou_params_count = param_count;
	update->ou_result_size = reply_size;
	param = &update->ou_params[0];
	for (i = 0; i < param_count; i++) {
		param->oup_len = param_sizes[i];
		param = (struct object_update_param *)((char *)param +
			 object_update_param_size(param));
	}

	return 0;
}

/**
 * Packs one update into the update_buffer.
 *
 * \param[in] env	execution environment
 * \param[in] update	update to be packed
 * \param[in] max_update_size	*maximum size of \a update
 * \param[in] op	update operation (enum update_type)
 * \param[in] fid	object FID for this update
 * \param[in] param_count	number of parameters for this update
 * \param[in] param_sizes	array of parameters length of this update
 * \param[in] param_bufs	parameter buffers
 *
 * \retval		= 0 if updates packing succeeds
 * \retval		negative errno if updates packing fails
 **/
int out_update_pack(const struct lu_env *env, struct object_update *update,
		    size_t *max_update_size, enum update_type op,
		    const struct lu_fid *fid, unsigned int param_count,
		    __u16 *param_sizes, const void **param_bufs,
		    __u32 reply_size)
{
	struct object_update_param	*param;
	unsigned int			i;
	int				rc;
	ENTRY;

	rc = out_update_header_pack(env, update, max_update_size, op, fid,
				    param_count, param_sizes, reply_size);
	if (rc != 0)
		RETURN(rc);

	param = &update->ou_params[0];
	for (i = 0; i < param_count; i++) {
		memcpy(&param->oup_buf[0], param_bufs[i], param_sizes[i]);
		param = (struct object_update_param *)((char *)param +
			 object_update_param_size(param));
	}

	RETURN(0);
}
EXPORT_SYMBOL(out_update_pack);

/**
 * Pack various updates into the update_buffer.
 *
 * The following functions pack different updates into the update_buffer
 * So parameters of these API is basically same as its correspondent OSD/OSP
 * API, for detail description of these parameters see osd_handler.c or
 * osp_md_object.c.
 *
 * \param[in] env	execution environment
 * \param[in] ubuf	update buffer
 * \param[in] fid	fid of this object for the update
 *
 * \retval		0 if insertion succeeds.
 * \retval		negative errno if insertion fails.
 */
int out_create_pack(const struct lu_env *env, struct object_update *update,
		    size_t *max_update_size, const struct lu_fid *fid,
		    const struct lu_attr *attr, struct dt_allocation_hint *hint,
		    struct dt_object_format *dof)
{
	struct obdo		*obdo;
	__u16			sizes[2] = {sizeof(*obdo), 0};
	int			buf_count = 1;
	const struct lu_fid	*parent_fid = NULL;
	int			rc;
	ENTRY;

	if (hint != NULL && hint->dah_parent) {
		parent_fid = lu_object_fid(&hint->dah_parent->do_lu);
		sizes[1] = sizeof(*parent_fid);
		buf_count++;
	}

	rc = out_update_header_pack(env, update, max_update_size, OUT_CREATE,
				    fid, buf_count, sizes, 0);
	if (rc != 0)
		RETURN(rc);

	obdo = object_update_param_get(update, 0, NULL);
	if (IS_ERR(obdo))
		RETURN(PTR_ERR(obdo));

	obdo->o_valid = 0;
	obdo_from_la(obdo, attr, attr->la_valid);

	if (parent_fid != NULL) {
		struct lu_fid *tmp;

		tmp = object_update_param_get(update, 1, NULL);
		if (IS_ERR(tmp))
			RETURN(PTR_ERR(tmp));

		fid_cpu_to_le(tmp, parent_fid);
	}

	RETURN(0);
}
EXPORT_SYMBOL(out_create_pack);

int out_ref_del_pack(const struct lu_env *env, struct object_update *update,
		     size_t *max_update_size, const struct lu_fid *fid)
{
	return out_update_pack(env, update, max_update_size, OUT_REF_DEL, fid,
			       0, NULL, NULL, 0);
}
EXPORT_SYMBOL(out_ref_del_pack);

int out_ref_add_pack(const struct lu_env *env, struct object_update *update,
		     size_t *max_update_size, const struct lu_fid *fid)
{
	return out_update_pack(env, update, max_update_size, OUT_REF_ADD, fid,
			       0, NULL, NULL, 0);
}
EXPORT_SYMBOL(out_ref_add_pack);

int out_attr_set_pack(const struct lu_env *env, struct object_update *update,
		      size_t *max_update_size, const struct lu_fid *fid,
		      const struct lu_attr *attr)
{
	struct obdo		*obdo;
	__u16			size = sizeof(*obdo);
	int			rc;
	ENTRY;

	rc = out_update_header_pack(env, update, max_update_size,
				    OUT_ATTR_SET, fid, 1, &size, 0);
	if (rc != 0)
		RETURN(rc);

	obdo = object_update_param_get(update, 0, NULL);
	if (IS_ERR(obdo))
		RETURN(PTR_ERR(obdo));

	obdo->o_valid = 0;
	obdo_from_la(obdo, attr, attr->la_valid);

	RETURN(0);
}
EXPORT_SYMBOL(out_attr_set_pack);

int out_xattr_set_pack(const struct lu_env *env, struct object_update *update,
		       size_t *max_update_size, const struct lu_fid *fid,
		       const struct lu_buf *buf, const char *name, __u32 flag)
{
	__u16	sizes[3] = {strlen(name) + 1, buf->lb_len, sizeof(flag)};
	const void *bufs[3] = {(char *)name, (char *)buf->lb_buf,
			       (char *)&flag};

	return out_update_pack(env, update, max_update_size, OUT_XATTR_SET,
			       fid, ARRAY_SIZE(sizes), sizes, bufs, 0);
}
EXPORT_SYMBOL(out_xattr_set_pack);

int out_xattr_del_pack(const struct lu_env *env, struct object_update *update,
		       size_t *max_update_size, const struct lu_fid *fid,
		       const char *name)
{
	__u16	size = strlen(name) + 1;

	return out_update_pack(env, update, max_update_size, OUT_XATTR_DEL,
			       fid, 1, &size, (const void **)&name, 0);
}
EXPORT_SYMBOL(out_xattr_del_pack);

int out_index_insert_pack(const struct lu_env *env,
			  struct object_update *update,
			  size_t *max_update_size, const struct lu_fid *fid,
			  const struct dt_rec *rec, const struct dt_key *key)
{
	struct dt_insert_rec	   *rec1 = (struct dt_insert_rec *)rec;
	struct lu_fid		   rec_fid;
	__u32			    type = cpu_to_le32(rec1->rec_type);
	__u16			    sizes[3] = { strlen((char *)key) + 1,
						sizeof(rec_fid),
						sizeof(type) };
	const void		   *bufs[3] = { (char *)key,
						(char *)&rec_fid,
						(char *)&type };

	fid_cpu_to_le(&rec_fid, rec1->rec_fid);

	return out_update_pack(env, update, max_update_size, OUT_INDEX_INSERT,
			       fid, ARRAY_SIZE(sizes), sizes, bufs, 0);
}
EXPORT_SYMBOL(out_index_insert_pack);

int out_index_delete_pack(const struct lu_env *env,
			  struct object_update *update,
			  size_t *max_update_size, const struct lu_fid *fid,
			  const struct dt_key *key)
{
	__u16	size = strlen((char *)key) + 1;
	const void *buf = key;

	return out_update_pack(env, update, max_update_size, OUT_INDEX_DELETE,
			       fid, 1, &size, &buf, 0);
}
EXPORT_SYMBOL(out_index_delete_pack);

int out_destroy_pack(const struct lu_env *env, struct object_update *update,
		     size_t *max_update_size, const struct lu_fid *fid)
{
	return out_update_pack(env, update, max_update_size, OUT_DESTROY, fid,
			       0, NULL, NULL, 0);
}
EXPORT_SYMBOL(out_destroy_pack);

int out_write_pack(const struct lu_env *env, struct object_update *update,
		   size_t *max_update_size, const struct lu_fid *fid,
		   const struct lu_buf *buf, __u64 pos)
{
	__u16		sizes[2] = {buf->lb_len, sizeof(pos)};
	const void	*bufs[2] = {(char *)buf->lb_buf, (char *)&pos};
	int		rc;

	pos = cpu_to_le64(pos);

	rc = out_update_pack(env, update, max_update_size, OUT_WRITE, fid,
			     ARRAY_SIZE(sizes), sizes, bufs, 0);
	return rc;
}
EXPORT_SYMBOL(out_write_pack);

/**
 * Pack various readonly updates into the update_buffer.
 *
 * The following update funcs are only used by read-only ops, lookup,
 * getattr etc, so it does not need transaction here. Currently they
 * are only used by OSP.
 *
 * \param[in] env	execution environment
 * \param[in] fid	fid of this object for the update
 * \param[in] ubuf	update buffer
 *
 * \retval		= 0 pack succeed.
 *                      < 0 pack failed.
 **/
int out_index_lookup_pack(const struct lu_env *env,
			  struct object_update *update,
			  size_t *max_update_size, const struct lu_fid *fid,
			  struct dt_rec *rec, const struct dt_key *key)
{
	const void	*name = key;
	__u16		size = strlen((char *)name) + 1;

	/* XXX: this shouldn't be hardcoded */
	return out_update_pack(env, update, max_update_size, OUT_INDEX_LOOKUP,
			       fid, 1, &size, &name, 256);
}
EXPORT_SYMBOL(out_index_lookup_pack);

int out_attr_get_pack(const struct lu_env *env, struct object_update *update,
		      size_t *max_update_size, const struct lu_fid *fid)
{
	return out_update_pack(env, update, max_update_size, OUT_ATTR_GET,
			       fid, 0, NULL, NULL, sizeof(struct obdo));
}
EXPORT_SYMBOL(out_attr_get_pack);

int out_xattr_get_pack(const struct lu_env *env, struct object_update *update,
		       size_t *max_update_size, const struct lu_fid *fid,
		       const char *name, const int bufsize)
{
	__u16 size;

	LASSERT(name != NULL);
	size = strlen(name) + 1;

	return out_update_pack(env, update, max_update_size, OUT_XATTR_GET,
			       fid, 1, &size, (const void **)&name, bufsize);
}
EXPORT_SYMBOL(out_xattr_get_pack);

int out_xattr_list_pack(const struct lu_env *env, struct object_update *update,
		       size_t *max_update_size, const struct lu_fid *fid,
		       const int bufsize)
{
	return out_update_pack(env, update, max_update_size, OUT_XATTR_LIST,
			       fid, 0, NULL, NULL, bufsize);
}
EXPORT_SYMBOL(out_xattr_list_pack);

int out_read_pack(const struct lu_env *env, struct object_update *update,
		  size_t *max_update_size, const struct lu_fid *fid,
		  size_t size, loff_t pos)
{
	__u16		sizes[2] = {sizeof(size), sizeof(pos)};
	const void	*bufs[2] = {&size, &pos};

	LASSERT(size > 0);
	size = cpu_to_le64(size);
	pos = cpu_to_le64(pos);

	return out_update_pack(env, update, max_update_size, OUT_READ, fid,
			       ARRAY_SIZE(sizes), sizes, bufs, size);
}
EXPORT_SYMBOL(out_read_pack);

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
struct tx_arg *tx_add_exec(struct thandle_exec_args *ta,
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

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0, arg->index,
					    rc);

	return rc;
}

/**
 * Add create update to thandle
 *
 * Declare create updates and add the update to the thandle updates
 * exec array.
 *
 * \param [in] env	execution environment
 * \param [in] obj	object to be created
 * \param [in] attr	attributes of the creation
 * \param [in] parent_fid the fid of the parent
 * \param [in] dof	dt object format of the creation
 * \param [in] ta	thandle execuation args where all of updates
 *                      of the transaction are stored
 * \param [in] th	thandle for this update
 * \param [in] reply	reply of the updates
 * \param [in] index	index of the reply
 * \param [in] file	the file name where the function is called,
 *                      which is only for debugging purpose.
 * \param [in] line	the line number where the funtion is called,
 *                      which is only for debugging purpose.
 *
 * \retval		0 if updates is added successfully.
 * \retval		negative errno if update adding fails.
 */
int out_create_add_exec(const struct lu_env *env, struct dt_object *obj,
			struct lu_attr *attr, struct lu_fid *parent_fid,
			struct dt_object_format *dof,
			struct thandle_exec_args *ta,
			struct thandle	*th,
			struct object_update_reply *reply,
			int index, const char *file, int line)
{
	struct tx_arg *arg;
	int rc;

	/* LU-13653: ignore quota for DNE directory creation */
	if (dof->dof_type == DFT_DIR)
		th->th_ignore_quota = 1;

	rc = dt_declare_create(env, obj, attr, NULL, dof, th);
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

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0,
					    arg->index, rc);

	return rc;
}

int out_attr_set_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			  const struct lu_attr *attr,
			  struct thandle_exec_args *ta,
			  struct thandle *th, struct object_update_reply *reply,
			  int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	rc = dt_declare_attr_set(env, dt_obj, attr, th);
	if (rc != 0)
		return rc;

	if (attr->la_valid & LA_FLAGS &&
	    attr->la_flags & LUSTRE_SET_SYNC_FL)
		th->th_sync |= 1;

	arg = tx_add_exec(ta, out_tx_attr_set_exec, out_tx_attr_set_undo,
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

static int out_tx_write_exec(const struct lu_env *env, struct thandle *th,
			     struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

	CDEBUG(D_INFO, "write "DFID" pos %llu buf %p, len %lu\n",
	       PFID(lu_object_fid(&dt_obj->do_lu)), arg->u.write.pos,
	       arg->u.write.buf.lb_buf, (unsigned long)arg->u.write.buf.lb_len);

	if (OBD_FAIL_CHECK(OBD_FAIL_OUT_ENOSPC)) {
		rc = -ENOSPC;
	} else {
		dt_write_lock(env, dt_obj, MOR_TGT_CHILD);
		rc = dt_record_write(env, dt_obj, &arg->u.write.buf,
				     &arg->u.write.pos, th);
		dt_write_unlock(env, dt_obj);

		if (rc == 0)
			rc = arg->u.write.buf.lb_len;
	}

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0, arg->index,
					    rc);

	return rc > 0 ? 0 : rc;
}

int out_write_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
		       const struct lu_buf *buf, loff_t pos,
		       struct thandle_exec_args *ta, struct thandle *th,
		       struct object_update_reply *reply, int index,
		       const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	rc = dt_declare_record_write(env, dt_obj, buf, pos, th);
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

static int out_tx_xattr_set_exec(const struct lu_env *env,
				 struct thandle *th,
				 struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;
	ENTRY;

	CDEBUG(D_INFO, "%s: set xattr buf %p name %s flag %d\n",
	       dt_obd_name(th->th_dev), arg->u.xattr_set.buf.lb_buf,
	       arg->u.xattr_set.name, arg->u.xattr_set.flags);

	if (!lu_object_exists(&dt_obj->do_lu)) {
		rc = -ENOENT;
	} else {
		struct linkea_data ldata = { 0 };
		bool linkea;

		ldata.ld_buf = &arg->u.xattr_set.buf;
		if (strcmp(arg->u.xattr_set.name, XATTR_NAME_LINK) == 0) {
			struct link_ea_header *leh;

			linkea = true;
			rc = linkea_init(&ldata);
			if (unlikely(rc))
				GOTO(out, rc == -ENODATA ? -EINVAL : rc);

			leh = ldata.ld_leh;
			LASSERT(leh != NULL);

			/* If the new linkEA contains overflow timestamp,
			 * then two cases:
			 *
			 * 1. The old linkEA for the object has already
			 *    overflowed before current setting, the new
			 *    linkEA does not contains new link entry. So
			 *    the linkEA overflow timestamp is unchanged.
			 *
			 * 2. There are new link entry in the new linkEA,
			 *    so its overflow timestamp is differnt from
			 *    the old one. Usually, the overstamp in the
			 *    given linkEA is newer. But because of clock
			 *    drift among MDTs, the timestamp may become
			 *    older. So here, we convert the timestamp to
			 *    the server local time. Then namespace LFSCK
			 *    that uses local time can handle it easily. */
			if (unlikely(leh->leh_overflow_time)) {
				struct lu_buf tbuf = { 0 };
				bool update = false;

				lu_buf_alloc(&tbuf, MAX_LINKEA_SIZE);
				if (tbuf.lb_buf == NULL)
					GOTO(unlock, rc = -ENOMEM);

				rc = dt_xattr_get(env, dt_obj, &tbuf,
						  XATTR_NAME_LINK);
				if (rc > 0) {
					struct linkea_data tdata = { 0 };

					tdata.ld_buf = &tbuf;
					rc = linkea_init(&tdata);
					if (rc || leh->leh_overflow_time !=
					    tdata.ld_leh->leh_overflow_time)
						update = true;
				} else {
					/* Update the timestamp by force if
					 * fail to load the old linkEA. */
					update = true;
				}

				lu_buf_free(&tbuf);
				if (update) {
					leh->leh_overflow_time = ktime_get_real_seconds();
					if (unlikely(!leh->leh_overflow_time))
						leh->leh_overflow_time++;
				}
			}
		} else {
			linkea = false;
		}

		dt_write_lock(env, dt_obj, MOR_TGT_CHILD);

again:
		rc = dt_xattr_set(env, dt_obj, ldata.ld_buf,
				  arg->u.xattr_set.name, arg->u.xattr_set.flags,
				  th);
		if (unlikely(rc == -ENOSPC && linkea)) {
			rc = linkea_overflow_shrink(&ldata);
			if (likely(rc > 0)) {
				arg->u.xattr_set.buf.lb_len = rc;
				goto again;
			}
		}

unlock:
		dt_write_unlock(env, dt_obj);
	}

	GOTO(out, rc);

out:
	CDEBUG(D_INFO, "%s: insert xattr set reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0, arg->index,
					    rc);

	return rc;
}

int out_xattr_set_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			   const struct lu_buf *buf, const char *name,
			   int flags, struct thandle_exec_args *ta,
			   struct thandle *th,
			   struct object_update_reply *reply,
			   int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	rc = dt_declare_xattr_set(env, dt_obj, buf, name, flags, th);
	if (rc != 0)
		return rc;

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
	rc = dt_xattr_del(env, dt_obj, arg->u.xattr_set.name,
			  th);
	dt_write_unlock(env, dt_obj);
out:
	CDEBUG(D_INFO, "%s: insert xattr del reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0, arg->index,
					    rc);

	return rc;
}

int out_xattr_del_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			   const char *name, struct thandle_exec_args *ta,
			   struct thandle *th,
			   struct object_update_reply *reply, int index,
			   const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	rc = dt_declare_xattr_del(env, dt_obj, name, th);
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

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0, arg->index,
					    rc);
	return rc;
}

static int out_tx_ref_add_undo(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	return out_obj_ref_del(env, arg->object, th);
}

int out_ref_add_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			 struct thandle_exec_args *ta,
			 struct thandle *th,
			 struct object_update_reply *reply, int index,
			 const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	rc = dt_declare_ref_add(env, dt_obj, th);
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

static int out_tx_ref_del_exec(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	struct dt_object	*dt_obj = arg->object;
	int			 rc;

	rc = out_obj_ref_del(env, dt_obj, th);

	CDEBUG(D_INFO, "%s: insert ref_del reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, 0);

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0, arg->index,
					    rc);

	return rc;
}

static int out_tx_ref_del_undo(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	return out_obj_ref_add(env, arg->object, th);
}

int out_ref_del_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			 struct thandle_exec_args *ta,
			 struct thandle *th,
			 struct object_update_reply *reply, int index,
			 const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	rc = dt_declare_ref_del(env, dt_obj, th);
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
	rc = dt_insert(env, dt_obj, rec, key, th);
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

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0, arg->index,
					    rc);
	return rc;
}

static int out_tx_index_insert_undo(const struct lu_env *env,
				    struct thandle *th, struct tx_arg *arg)
{
	return out_obj_index_delete(env, arg->object, arg->u.insert.key, th);
}

int out_index_insert_add_exec(const struct lu_env *env,
			      struct dt_object *dt_obj,
			      const struct dt_rec *rec,
			      const struct dt_key *key,
			      struct thandle_exec_args *ta,
			      struct thandle *th,
			      struct object_update_reply *reply,
			      int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	if (dt_try_as_dir(env, dt_obj) == 0) {
		rc = -ENOTDIR;
		return rc;
	}

	rc = dt_declare_insert(env, dt_obj, rec, key, th);
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

static int out_tx_index_delete_exec(const struct lu_env *env,
				    struct thandle *th,
				    struct tx_arg *arg)
{
	int rc;

	rc = out_obj_index_delete(env, arg->object, arg->u.insert.key, th);

	CDEBUG(D_INFO, "%s: delete idx insert reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0, arg->index,
					    rc);

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

int out_index_delete_add_exec(const struct lu_env *env,
			      struct dt_object *dt_obj,
			      const struct dt_key *key,
			      struct thandle_exec_args *ta,
			      struct thandle *th,
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
	rc = dt_declare_delete(env, dt_obj, key, th);
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

static int out_tx_destroy_exec(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	struct dt_object *dt_obj = arg->object;
	int rc;

	rc = out_obj_destroy(env, dt_obj, th);

	CDEBUG(D_INFO, "%s: insert destroy reply %p index %d: rc = %d\n",
	       dt_obd_name(th->th_dev), arg->reply, arg->index, rc);

	if (arg->reply != NULL)
		object_update_result_insert(arg->reply, NULL, 0, arg->index,
					    rc);

	RETURN(rc);
}

static int out_tx_destroy_undo(const struct lu_env *env, struct thandle *th,
			       struct tx_arg *arg)
{
	CERROR("%s: not support destroy undo yet!: rc = %d\n",
	       dt_obd_name(th->th_dev), -ENOTSUPP);
	return -ENOTSUPP;
}

int out_destroy_add_exec(const struct lu_env *env, struct dt_object *dt_obj,
			 struct thandle_exec_args *ta, struct thandle *th,
			 struct object_update_reply *reply,
			 int index, const char *file, int line)
{
	struct tx_arg	*arg;
	int		rc;

	rc = dt_declare_destroy(env, dt_obj, th);
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
