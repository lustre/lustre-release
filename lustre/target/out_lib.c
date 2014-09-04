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
 * Copyright (c) 2014, Intel Corporation.
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
#include <obd_class.h>

#define OUT_UPDATE_BUFFER_SIZE_ADD	4096
#define OUT_UPDATE_BUFFER_SIZE_MAX	(256 * 4096)  /* 1MB update size now */

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
		[OUT_INDEX_LOOKUP] = "lookup",
		[OUT_INDEX_INSERT] = "insert",
		[OUT_INDEX_DELETE] = "delete",
		[OUT_WRITE] = "write",
		[OUT_XATTR_DEL] = "xattr_del",
		[OUT_PUNCH] = "punch",
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
 * \params[in] max_update_size	maximum object update size, if the current
 *                              update length equals or exceeds the size, it
 *                              will return -E2BIG.
 * \params[in] update_op	update type
 * \params[in] fid		object FID of the update
 * \params[in] params_count	the count of the update parameters
 * \params[in] params_sizes	the length of each parameters
 *
 * \retval			0 if packing succeeds.
 * \retval			-E2BIG if packing exceeds the maximum length.
 */
int out_update_header_pack(const struct lu_env *env,
			   struct object_update *update, size_t max_update_size,
			   enum update_type update_op, const struct lu_fid *fid,
			   unsigned int param_count, __u16 *params_sizes)
{
	struct object_update_param	*param;
	unsigned int			i;
	size_t				update_size;

	/* Check whether the packing exceeding the maxima update length */
	update_size = sizeof(*update);
	for (i = 0; i < param_count; i++)
		update_size += cfs_size_round(sizeof(*param) + params_sizes[i]);

	if (unlikely(update_size >= max_update_size))
		return -E2BIG;

	update->ou_fid = *fid;
	update->ou_type = update_op;
	update->ou_params_count = param_count;
	param = &update->ou_params[0];
	for (i = 0; i < param_count; i++) {
		param->oup_len = params_sizes[i];
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
		    size_t max_update_size, enum update_type op,
		    const struct lu_fid *fid, unsigned int param_count,
		    __u16 *param_sizes, const void **param_bufs)
{
	struct object_update_param	*param;
	unsigned int			i;
	int				rc;
	ENTRY;

	rc = out_update_header_pack(env, update, max_update_size, op, fid,
				    param_count, param_sizes);
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
		    size_t max_update_size, const struct lu_fid *fid,
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
				    fid, buf_count, sizes);
	if (rc != 0)
		RETURN(rc);

	obdo = object_update_param_get(update, 0, NULL);
	LASSERT(obdo != NULL);
	obdo->o_valid = 0;
	obdo_from_la(obdo, attr, attr->la_valid);
	lustre_set_wire_obdo(NULL, obdo, obdo);

	if (parent_fid != NULL) {
		struct lu_fid *tmp;

		tmp = object_update_param_get(update, 1, NULL);
		LASSERT(tmp != NULL);
		fid_cpu_to_le(tmp, parent_fid);
	}

	RETURN(0);
}
EXPORT_SYMBOL(out_create_pack);

int out_ref_del_pack(const struct lu_env *env, struct object_update *update,
		     size_t max_update_size, const struct lu_fid *fid)
{
	return out_update_pack(env, update, max_update_size, OUT_REF_DEL, fid,
			       0, NULL, NULL);
}
EXPORT_SYMBOL(out_ref_del_pack);

int out_ref_add_pack(const struct lu_env *env, struct object_update *update,
		     size_t max_update_size, const struct lu_fid *fid)
{
	return out_update_pack(env, update, max_update_size, OUT_REF_ADD, fid,
			       0, NULL, NULL);
}
EXPORT_SYMBOL(out_ref_add_pack);

int out_attr_set_pack(const struct lu_env *env, struct object_update *update,
		      size_t max_update_size, const struct lu_fid *fid,
		      const struct lu_attr *attr)
{
	struct obdo		*obdo;
	__u16			size = sizeof(*obdo);
	int			rc;
	ENTRY;

	rc = out_update_header_pack(env, update, max_update_size,
				    OUT_ATTR_SET, fid, 1, &size);
	if (rc != 0)
		RETURN(rc);

	obdo = object_update_param_get(update, 0, NULL);
	LASSERT(obdo != NULL);
	obdo->o_valid = 0;
	obdo_from_la(obdo, attr, attr->la_valid);
	lustre_set_wire_obdo(NULL, obdo, obdo);

	RETURN(0);
}
EXPORT_SYMBOL(out_attr_set_pack);

int out_xattr_set_pack(const struct lu_env *env, struct object_update *update,
		       size_t max_update_size, const struct lu_fid *fid,
		       const struct lu_buf *buf, const char *name, __u32 flag)
{
	__u16	sizes[3] = {strlen(name) + 1, buf->lb_len, sizeof(flag)};
	const void *bufs[3] = {(char *)name, (char *)buf->lb_buf,
			       (char *)&flag};

	return out_update_pack(env, update, max_update_size, OUT_XATTR_SET,
			       fid, ARRAY_SIZE(sizes), sizes, bufs);
}
EXPORT_SYMBOL(out_xattr_set_pack);

int out_xattr_del_pack(const struct lu_env *env, struct object_update *update,
		       size_t max_update_size, const struct lu_fid *fid,
		       const char *name)
{
	__u16	size = strlen(name) + 1;

	return out_update_pack(env, update, max_update_size, OUT_XATTR_DEL,
			       fid, 1, &size, (const void **)&name);
}
EXPORT_SYMBOL(out_xattr_del_pack);


int out_index_insert_pack(const struct lu_env *env,
			  struct object_update *update,
			  size_t max_update_size, const struct lu_fid *fid,
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
			       fid, ARRAY_SIZE(sizes), sizes, bufs);
}
EXPORT_SYMBOL(out_index_insert_pack);

int out_index_delete_pack(const struct lu_env *env,
			  struct object_update *update,
			  size_t max_update_size, const struct lu_fid *fid,
			  const struct dt_key *key)
{
	__u16	size = strlen((char *)key) + 1;
	const void *buf = key;

	return out_update_pack(env, update, max_update_size, OUT_INDEX_DELETE,
			       fid, 1, &size, &buf);
}
EXPORT_SYMBOL(out_index_delete_pack);

int out_object_destroy_pack(const struct lu_env *env,
			    struct object_update *update,
			    size_t max_update_size, const struct lu_fid *fid)
{
	return out_update_pack(env, update, max_update_size, OUT_DESTROY, fid,
			       0, NULL, NULL);
}
EXPORT_SYMBOL(out_object_destroy_pack);

int out_write_pack(const struct lu_env *env, struct object_update *update,
		   size_t max_update_size, const struct lu_fid *fid,
		   const struct lu_buf *buf, __u64 pos)
{
	__u16		sizes[2] = {buf->lb_len, sizeof(pos)};
	const void	*bufs[2] = {(char *)buf->lb_buf, (char *)&pos};
	int		rc;

	pos = cpu_to_le64(pos);

	rc = out_update_pack(env, update, max_update_size, OUT_WRITE, fid,
			     ARRAY_SIZE(sizes), sizes, bufs);
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
			  size_t max_update_size, const struct lu_fid *fid,
			  struct dt_rec *rec, const struct dt_key *key)
{
	const void	*name = key;
	__u16		size = strlen((char *)name) + 1;

	return out_update_pack(env, update, max_update_size, OUT_INDEX_LOOKUP,
			       fid, 1, &size, &name);
}
EXPORT_SYMBOL(out_index_lookup_pack);

int out_attr_get_pack(const struct lu_env *env, struct object_update *update,
		      size_t max_update_size, const struct lu_fid *fid)
{
	return out_update_pack(env, update, max_update_size, OUT_ATTR_GET,
			       fid, 0, NULL, NULL);
}
EXPORT_SYMBOL(out_attr_get_pack);

int out_xattr_get_pack(const struct lu_env *env, struct object_update *update,
		       size_t max_update_size, const struct lu_fid *fid,
		       const char *name)
{
	__u16 size;

	LASSERT(name != NULL);
	size = strlen(name) + 1;

	return out_update_pack(env, update, max_update_size, OUT_XATTR_GET,
			       fid, 1, &size, (const void **)&name);
}
EXPORT_SYMBOL(out_xattr_get_pack);
