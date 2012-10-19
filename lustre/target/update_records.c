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
 * Copyright (c) 2015, Intel Corporation.
 */

/*
 * lustre/target/update_records.c
 *
 * This file implement the methods to pack updates as update records, which
 * will be written to the disk as llog record, and might be used during
 * recovery.
 *
 * For cross-MDT operation, all of updates of the operation needs to be
 * recorded in the disk, then during recovery phase, the recovery thread
 * will retrieve and redo these updates if it needed.
 *
 * See comments above struct update_records for the format of update_records.
 *
 * Author: Di Wang <di.wang@intel.com>
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <lu_target.h>
#include <lustre_obdo.h>
#include <lustre_update.h>
#include <obd.h>
#include <obd_class.h>

#include "tgt_internal.h"

#define UPDATE_RECORDS_BUFFER_SIZE	8192
#define UPDATE_PARAMS_BUFFER_SIZE	8192
/**
 * Dump update record.
 *
 * Dump all of updates in the update_records, mostly for debugging purpose.
 *
 * \param[in] records	update records to be dumpped
 * \param[in] mask	debug level mask
 * \param[in] dump_params if dump all of updates the updates.
 *
 */
void update_records_dump(const struct update_records *records,
			 unsigned int mask, bool dump_updates)
{
	const struct update_ops	*ops;
	const struct update_op	*op = NULL;
	struct update_params	*params = NULL;
	unsigned int		i;

	CDEBUG(mask, "master transno = %llu batchid = %llu flags = %x"
	       " ops = %d params = %d\n", records->ur_master_transno,
	       records->ur_batchid, records->ur_flags, records->ur_update_count,
	       records->ur_param_count);

	if (records->ur_update_count == 0)
		return;

	if (!dump_updates)
		return;

	ops = &records->ur_ops;
	if (records->ur_param_count > 0)
		params = update_records_get_params(records);

	op = &ops->uops_op[0];
	for (i = 0; i < records->ur_update_count; i++,
				  op = update_op_next_op(op)) {
		unsigned int j;

		CDEBUG(mask, "update %dth "DFID" %s params_count = %hu\n", i,
		       PFID(&op->uop_fid), update_op_str(op->uop_type),
		       op->uop_param_count);

		if (params == NULL)
			continue;

		for (j = 0;  j < op->uop_param_count; j++) {
			struct object_update_param *param;

			param = update_params_get_param(params,
				(unsigned int)op->uop_params_off[j],
					records->ur_param_count);

			if (param == NULL)
				continue;
			CDEBUG(mask, "param = %p %dth off = %hu size = %hu\n",
			       param, j, op->uop_params_off[j], param->oup_len);
		}
	}
}

/**
 * Pack parameters to update records
 *
 * Find and insert parameter to update records, if the parameter
 * already exists in \a params, then just return the offset of this
 * parameter, otherwise insert the parameter and return its offset
 *
 * \param[in] params	update params in which to insert parameter
 * \param[in] new_param	parameters to be inserted.
 * \param[in] new_param_size	the size of \a new_param
 *
 * \retval		index inside \a params if parameter insertion
 *                      succeeds.
 * \retval		negative errno if it fails.
 */
static unsigned int update_records_param_pack(struct update_params *params,
					      const void *new_param,
					      size_t new_param_size,
					      unsigned int *param_count)
{
	struct object_update_param	*param;
	unsigned int			i;

	for (i = 0; i < *param_count; i++) {
		struct object_update_param *param;

		param = update_params_get_param(params, i, *param_count);
		if ((new_param == NULL && param->oup_len == new_param_size) ||
		    (param->oup_len == new_param_size &&
		     memcmp(param->oup_buf, new_param, new_param_size) == 0))
			/* Found the parameter and return its index */
			return i;
	}

	param = (struct object_update_param *)((char *)params +
				update_params_size(params, *param_count));

	param->oup_len = new_param_size;
	if (new_param != NULL)
		memcpy(param->oup_buf, new_param, new_param_size);

	*param_count = *param_count + 1;

	return *param_count - 1;
}

/**
 * Pack update to update records
 *
 * Pack the update and its parameters to the update records. First it will
 * insert parameters, get the offset of these parameter, then fill the
 * update with these offset. If insertion exceed the maximum size of
 * current update records, it will return -E2BIG here, and the caller might
 * extend the update_record size \see lod_updates_pack.
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the update.
 * \param[in] op_type	operation type of the update
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count	pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] param_bufs	buffers of parameters
 * \param[in] params_buf_count	the count of the parameter buffers
 * \param[in] param_size	sizes of parameters
 *
 * \retval		0 if packing succeeds
 * \retval		negative errno if packing fails
 */
static int update_records_update_pack(const struct lu_env *env,
				      const struct lu_fid *fid,
				      enum update_type op_type,
				      struct update_ops *ops,
				      unsigned int *op_count,
				      size_t *max_op_size,
				      struct update_params *params,
				      unsigned int *param_count,
				      size_t *max_param_size,
				      unsigned int param_bufs_count,
				      const void **param_bufs,
				      size_t *param_sizes)
{
	struct update_op	*op;
	size_t			total_param_sizes = 0;
	int			index;
	unsigned int		i;

	/* Check whether the packing exceeding the maximum update size */
	if (unlikely(*max_op_size < update_op_size(param_bufs_count))) {
		CDEBUG(D_INFO, "max_op_size = %zu update_op = %zu\n",
		       *max_op_size, update_op_size(param_bufs_count));
		*max_op_size = update_op_size(param_bufs_count);
		return -E2BIG;
	}

	for (i = 0; i < param_bufs_count; i++)
		total_param_sizes +=
			cfs_size_round(sizeof(struct object_update_param) +
				       param_sizes[i]);

	/* Check whether the packing exceeding the maximum parameter size */
	if (unlikely(*max_param_size < total_param_sizes)) {
		CDEBUG(D_INFO, "max_param_size = %zu params size = %zu\n",
		       *max_param_size, total_param_sizes);

		*max_param_size = total_param_sizes;
		return -E2BIG;
	}

	op = update_ops_get_op(ops, *op_count, *op_count);
	op->uop_fid = *fid;
	op->uop_type = op_type;
	op->uop_param_count = param_bufs_count;
	for (i = 0; i < param_bufs_count; i++) {
		index = update_records_param_pack(params, param_bufs[i],
						  param_sizes[i], param_count);
		if (index < 0)
			return index;

		CDEBUG(D_INFO, "%s %uth param offset = %d size = %zu\n",
		       update_op_str(op_type), i, index, param_sizes[i]);

		op->uop_params_off[i] = index;
	}
	CDEBUG(D_INFO, "%huth "DFID" %s param_count = %u\n",
	       *op_count, PFID(fid), update_op_str(op_type), *param_count);

	*op_count = *op_count + 1;

	return 0;
}

/**
 * Calculate update_records size
 *
 * Calculate update_records size by param_count and param_sizes array.
 *
 * \param[in] param_count	the count of parameters
 * \param[in] sizes		the size array of these parameters
 *
 * \retval			the size of this update
 */
static size_t update_records_update_size(__u32 param_count, size_t *sizes)
{
	int i;
	size_t size;

	/* Check whether the packing exceeding the maximum update size */
	size = update_op_size(param_count);

	for (i = 0; i < param_count; i++)
		size += cfs_size_round(sizeof(struct object_update_param) +
				       sizes[i]);

	return size;
}

/**
 * Calculate create update size
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in] fid	FID of the object to be created
 * \param[in] attr	attribute of the object to be created
 * \param[in] hint	creation hint
 * \param[in] dof	creation format information
 *
 * \retval		size of create update.
 */
size_t update_records_create_size(const struct lu_env *env,
				  const struct lu_fid *fid,
				  const struct lu_attr *attr,
				  const struct dt_allocation_hint *hint,
				  struct dt_object_format *dof)
{
	size_t	sizes[2];
	int	param_count = 0;

	if (attr != NULL) {
		sizes[param_count] = sizeof(struct obdo);
		param_count++;
	}

	if (hint != NULL && hint->dah_parent != NULL) {
		sizes[param_count] = sizeof(*fid);
		param_count++;
	}

	return update_records_update_size(param_count, sizes);
}
EXPORT_SYMBOL(update_records_create_size);

/**
 * Pack create update
 *
 * Pack create update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count	pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to be created
 * \param[in] attr	attribute of the object to be created
 * \param[in] hint	creation hint
 * \param[in] dof	creation format information
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_create_pack(const struct lu_env *env,
			       struct update_ops *ops,
			       unsigned int *op_count,
			       size_t *max_ops_size,
			       struct update_params *params,
			       unsigned int *param_count,
			       size_t *max_param_size,
			       const struct lu_fid *fid,
			       const struct lu_attr *attr,
			       const struct dt_allocation_hint *hint,
			       struct dt_object_format *dof)
{
	size_t			sizes[2];
	const void		*bufs[2];
	int			buf_count = 0;
	const struct lu_fid	*parent_fid = NULL;
	struct lu_fid		tmp_fid;
	int			rc;
	struct obdo		*obdo;

	if (attr != NULL) {
		obdo = &update_env_info(env)->uti_obdo;
		obdo->o_valid = 0;
		obdo_from_la(obdo, attr, attr->la_valid);
		bufs[buf_count] = obdo;
		sizes[buf_count] = sizeof(*obdo);
		buf_count++;
	}

	if (hint != NULL && hint->dah_parent != NULL) {
		parent_fid = lu_object_fid(&hint->dah_parent->do_lu);
		fid_cpu_to_le(&tmp_fid, parent_fid);
		bufs[buf_count] = &tmp_fid;
		sizes[buf_count] = sizeof(tmp_fid);
		buf_count++;
	}

	rc = update_records_update_pack(env, fid, OUT_CREATE, ops, op_count,
					max_ops_size, params, param_count,
					max_param_size, buf_count, bufs, sizes);
	return rc;
}
EXPORT_SYMBOL(update_records_create_pack);

/**
 * Calculate attr set update size
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in] fid	FID of the object to set attr
 * \param[in] attr	attribute of attr set
 *
 * \retval		size of attr set update.
 */
size_t update_records_attr_set_size(const struct lu_env *env,
				    const struct lu_fid *fid,
				    const struct lu_attr *attr)
{
	size_t size = sizeof(struct obdo);

	return update_records_update_size(1, &size);
}
EXPORT_SYMBOL(update_records_attr_set_size);

/**
 * Pack attr set update
 *
 * Pack attr_set update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to set attr
 * \param[in] attr	attribute of attr set
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_attr_set_pack(const struct lu_env *env,
				 struct update_ops *ops,
				 unsigned int *op_count,
				 size_t *max_ops_size,
				 struct update_params *params,
				 unsigned int *param_count,
				 size_t *max_param_size,
				 const struct lu_fid *fid,
				 const struct lu_attr *attr)
{
	struct obdo *obdo = &update_env_info(env)->uti_obdo;
	size_t size = sizeof(*obdo);

	obdo->o_valid = 0;
	obdo_from_la(obdo, attr, attr->la_valid);
	return update_records_update_pack(env, fid, OUT_ATTR_SET, ops, op_count,
					  max_ops_size, params, param_count,
					  max_param_size, 1,
					  (const void **)&obdo, &size);
}
EXPORT_SYMBOL(update_records_attr_set_pack);

/**
 * Calculate ref add update size
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the object to add reference
 *
 * \retval		size of ref_add udpate.
 */
size_t update_records_ref_add_size(const struct lu_env *env,
				   const struct lu_fid *fid)
{
	return update_records_update_size(0, NULL);
}
EXPORT_SYMBOL(update_records_ref_add_size);

/**
 * Pack ref add update
 *
 * Pack ref add update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to add reference
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_ref_add_pack(const struct lu_env *env,
				struct update_ops *ops,
				unsigned int *op_count,
				size_t *max_ops_size,
				struct update_params *params,
				unsigned int *param_count,
				size_t *max_param_size,
				const struct lu_fid *fid)
{
	return update_records_update_pack(env, fid, OUT_REF_ADD, ops, op_count,
					  max_ops_size, params, param_count,
					  max_param_size, 0, NULL, NULL);
}
EXPORT_SYMBOL(update_records_ref_add_pack);

/**
 * Pack noop update
 *
 * Pack no op update into update records. Note: no op means
 * the update does not need do anything, which is only used
 * in test case to verify large size record.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to add reference
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_noop_pack(const struct lu_env *env,
			     struct update_ops *ops,
			     unsigned int *op_count,
			     size_t *max_ops_size,
			     struct update_params *params,
			     unsigned int *param_count,
			     size_t *max_param_size,
			     const struct lu_fid *fid)
{
	return update_records_update_pack(env, fid, OUT_NOOP, ops, op_count,
					  max_ops_size, params, param_count,
					  max_param_size, 0, NULL, NULL);
}
EXPORT_SYMBOL(update_records_noop_pack);

/**
 * Calculate ref del update size
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the object to delete reference
 *
 * \retval		size of ref_del update.
 */
size_t update_records_ref_del_size(const struct lu_env *env,
				   const struct lu_fid *fid)
{
	return update_records_update_size(0, NULL);
}
EXPORT_SYMBOL(update_records_ref_del_size);

/**
 * Pack ref del update
 *
 * Pack ref del update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count	pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to delete reference
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_ref_del_pack(const struct lu_env *env,
				struct update_ops *ops,
				unsigned int *op_count,
				size_t *max_ops_size,
				struct update_params *params,
				unsigned int *param_count,
				size_t *max_param_size,
				const struct lu_fid *fid)
{
	return update_records_update_pack(env, fid, OUT_REF_DEL, ops, op_count,
					  max_ops_size, params, param_count,
					  max_param_size, 0, NULL, NULL);
}
EXPORT_SYMBOL(update_records_ref_del_pack);

/**
 * Calculate object destroy update size
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the object to delete reference
 *
 * \retval		size of object destroy update.
 */
size_t update_records_destroy_size(const struct lu_env *env,
					  const struct lu_fid *fid)
{
	return update_records_update_size(0, NULL);
}
EXPORT_SYMBOL(update_records_destroy_size);

/**
 * Pack object destroy update
 *
 * Pack object destroy update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to delete reference
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_destroy_pack(const struct lu_env *env,
				       struct update_ops *ops,
				       unsigned int *op_count,
				       size_t *max_ops_size,
				       struct update_params *params,
				       unsigned int *param_count,
				       size_t *max_param_size,
				       const struct lu_fid *fid)
{
	return update_records_update_pack(env, fid, OUT_DESTROY, ops, op_count,
					  max_ops_size, params, param_count,
					  max_param_size, 0, NULL, NULL);
}
EXPORT_SYMBOL(update_records_destroy_pack);

/**
 * Calculate index insert update size
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the object to insert index
 * \param[in] rec	record of insertion
 * \param[in] key	key of insertion
 *
 * \retval		the size of index insert update.
 */
size_t update_records_index_insert_size(const struct lu_env *env,
					const struct lu_fid *fid,
					const struct dt_rec *rec,
					const struct dt_key *key)
{
	size_t			   sizes[3] = { strlen((const char *)key) + 1,
						sizeof(struct lu_fid),
						sizeof(__u32) };
	return update_records_update_size(3, sizes);
}
EXPORT_SYMBOL(update_records_index_insert_size);

/**
 * Pack index insert update
 *
 * Pack index insert update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in] op_count	pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to insert index
 * \param[in] rec	record of insertion
 * \param[in] key	key of insertion
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_index_insert_pack(const struct lu_env *env,
				     struct update_ops *ops,
				     unsigned int *op_count,
				     size_t *max_ops_size,
				     struct update_params *params,
				     unsigned int *param_count,
				     size_t *max_param_size,
				     const struct lu_fid *fid,
				     const struct dt_rec *rec,
				     const struct dt_key *key)
{
	struct dt_insert_rec	   *rec1 = (struct dt_insert_rec *)rec;
	struct lu_fid		   rec_fid;
	__u32			   type = cpu_to_le32(rec1->rec_type);
	size_t			   sizes[3] = { strlen((const char *)key) + 1,
						sizeof(rec_fid),
						sizeof(type) };
	const void		   *bufs[3] = { key,
						&rec_fid,
						&type };

	fid_cpu_to_le(&rec_fid, rec1->rec_fid);

	return update_records_update_pack(env, fid, OUT_INDEX_INSERT, ops,
					  op_count, max_ops_size, params,
					  param_count, max_param_size,
					  3, bufs, sizes);
}
EXPORT_SYMBOL(update_records_index_insert_pack);

/**
 * Calculate index delete update size
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the object to delete index
 * \param[in] key	key of deletion
 *
 * \retval		the size of index delete update
 */
size_t update_records_index_delete_size(const struct lu_env *env,
					const struct lu_fid *fid,
					const struct dt_key *key)
{
	size_t size = strlen((const char *)key) + 1;

	return update_records_update_size(1, &size);
}
EXPORT_SYMBOL(update_records_index_delete_size);

/**
 * Pack index delete update
 *
 * Pack index delete update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count	pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|ount] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to delete index
 * \param[in] key	key of deletion
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_index_delete_pack(const struct lu_env *env,
				     struct update_ops *ops,
				     unsigned int *op_count,
				     size_t *max_ops_size,
				     struct update_params *params,
				     unsigned int *param_count,
				     size_t *max_param_size,
				     const struct lu_fid *fid,
				     const struct dt_key *key)
{
	size_t size = strlen((const char *)key) + 1;

	return update_records_update_pack(env, fid, OUT_INDEX_DELETE, ops,
					  op_count, max_ops_size, params,
					  param_count, max_param_size,
					  1, (const void **)&key, &size);
}
EXPORT_SYMBOL(update_records_index_delete_pack);

/**
 * Calculate xattr set size
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the object to set xattr
 * \param[in] buf	xattr to be set
 * \param[in] name	name of the xattr
 * \param[in] flag	flag for setting xattr
 *
 * \retval		size of xattr set update.
 */
size_t update_records_xattr_set_size(const struct lu_env *env,
				     const struct lu_fid *fid,
				     const struct lu_buf *buf,
				     const char *name, __u32 flag)
{
	size_t	sizes[3] = {strlen(name) + 1, buf->lb_len, sizeof(flag)};

	return update_records_update_size(3, sizes);
}
EXPORT_SYMBOL(update_records_xattr_set_size);

/**
 * Pack xattr set update
 *
 * Pack xattr set update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count	pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to set xattr
 * \param[in] buf	xattr to be set
 * \param[in] name	name of the xattr
 * \param[in] flag	flag for setting xattr
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_xattr_set_pack(const struct lu_env *env,
				  struct update_ops *ops,
				  unsigned int *op_count,
				  size_t *max_ops_size,
				  struct update_params *params,
				  unsigned int *param_count,
				  size_t *max_param_size,
				  const struct lu_fid *fid,
				  const struct lu_buf *buf, const char *name,
				  __u32 flag)
{
	size_t	sizes[3] = {strlen(name) + 1, buf->lb_len, sizeof(flag)};
	const void *bufs[3] = {name, buf->lb_buf, &flag};

	flag = cpu_to_le32(flag);

	return update_records_update_pack(env, fid, OUT_XATTR_SET, ops,
					  op_count, max_ops_size, params,
					  param_count, max_param_size,
					  3, bufs, sizes);
}
EXPORT_SYMBOL(update_records_xattr_set_pack);

/**
 * Calculate xattr delete update size.
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the object to delete xattr
 * \param[in] name	name of the xattr
 *
 * \retval		size of xattr delet updatee.
 */
size_t update_records_xattr_del_size(const struct lu_env *env,
				     const struct lu_fid *fid,
				     const char *name)
{
	size_t	size = strlen(name) + 1;

	return update_records_update_size(1, &size);
}
EXPORT_SYMBOL(update_records_xattr_del_size);

/**
 * Pack xattr delete update
 *
 * Pack xattr delete update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count	pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to delete xattr
 * \param[in] name	name of the xattr
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_xattr_del_pack(const struct lu_env *env,
				  struct update_ops *ops,
				  unsigned int *op_count,
				  size_t *max_ops_size,
				  struct update_params *params,
				  unsigned int *param_count,
				  size_t *max_param_size,
				  const struct lu_fid *fid,
				  const char *name)
{
	size_t	size = strlen(name) + 1;

	return update_records_update_pack(env, fid, OUT_XATTR_DEL, ops,
					  op_count, max_ops_size, params,
					  param_count, max_param_size,
					  1, (const void **)&name, &size);
}
EXPORT_SYMBOL(update_records_xattr_del_pack);

/**
 * Calculate write update size
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the object to write into
 * \param[in] buf	buffer to write which includes an embedded size field
 * \param[in] pos	offet in the object to start writing at
 *
 * \retval		size of write udpate.
 */
size_t update_records_write_size(const struct lu_env *env,
				 const struct lu_fid *fid,
				 const struct lu_buf *buf,
				 __u64 pos)
{
	size_t	sizes[2] = {buf->lb_len, sizeof(pos)};

	return update_records_update_size(2, sizes);
}
EXPORT_SYMBOL(update_records_write_size);

/**
 * Pack write update
 *
 * Pack write update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count	pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to write into
 * \param[in] buf	buffer to write which includes an embedded size field
 * \param[in] pos	offet in the object to start writing at
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_write_pack(const struct lu_env *env,
			      struct update_ops *ops,
			      unsigned int *op_count,
			      size_t *max_ops_size,
			      struct update_params *params,
			      unsigned int *param_count,
			      size_t *max_param_size,
			      const struct lu_fid *fid,
			      const struct lu_buf *buf,
			      __u64 pos)
{
	size_t		sizes[2] = {buf->lb_len, sizeof(pos)};
	const void	*bufs[2] = {buf->lb_buf, &pos};

	pos = cpu_to_le64(pos);

	return update_records_update_pack(env, fid, OUT_WRITE, ops,
					  op_count, max_ops_size, params,
					  param_count, max_param_size,
					  2, bufs, sizes);
}
EXPORT_SYMBOL(update_records_write_pack);

/**
 * Calculate size of punch update.
 *
 * \param[in] env	execution environment
 * \param[in] fid	FID of the object to write into
 * \param[in] start	start offset of punch
 * \param[in] end	end offet of punch
 *
 * \retval		size of update punch.
 */
size_t update_records_punch_size(const struct lu_env *env,
				 const struct lu_fid *fid,
				 __u64 start, __u64 end)
{
	size_t	sizes[2] = {sizeof(start), sizeof(end)};

	return update_records_update_size(2, sizes);
}
EXPORT_SYMBOL(update_records_punch_size);

/**
 * Pack punch
 *
 * Pack punch update into update records.
 *
 * \param[in] env	execution environment
 * \param[in] ops	ur_ops in update records
 * \param[in|out] op_count	pointer to the count of ops
 * \param[in|out] max_op_size maximum size of the update
 * \param[in] params	ur_params in update records
 * \param[in|out] param_count	pointer to the count of params
 * \param[in|out] max_param_size maximum size of the parameter
 * \param[in] fid	FID of the object to write into
 * \param[in] start	start offset of punch
 * \param[in] end	end offet of punch
 *
 * \retval		0 if packing succeeds.
 * \retval		negative errno if packing fails.
 */
int update_records_punch_pack(const struct lu_env *env,
			      struct update_ops *ops,
			      unsigned int *op_count,
			      size_t *max_ops_size,
			      struct update_params *params,
			      unsigned int *param_count,
			      size_t *max_param_size,
			      const struct lu_fid *fid,
			      __u64 start, __u64 end)
{
	size_t		sizes[2] = {sizeof(start), sizeof(end)};
	const void	*bufs[2] = {&start, &end};

	start = cpu_to_le64(start);
	end = cpu_to_le64(end);

	return update_records_update_pack(env, fid, OUT_PUNCH, ops, op_count,
					  max_ops_size, params, param_count,
					  max_param_size, 2, bufs, sizes);
}
EXPORT_SYMBOL(update_records_punch_pack);

/**
 * Create update records in thandle_update_records
 *
 * Allocate update_records for thandle_update_records, the initial size
 * will be 4KB.
 *
 * \param[in] tur	thandle_update_records where update_records will be
 *                      allocated
 * \retval		0 if allocation succeeds.
 * \retval		negative errno if allocation fails.
 */
static int tur_update_records_create(struct thandle_update_records *tur)
{
	if (tur->tur_update_records != NULL)
		return 0;

	OBD_ALLOC_LARGE(tur->tur_update_records,
			UPDATE_RECORDS_BUFFER_SIZE);

	if (tur->tur_update_records == NULL)
		return -ENOMEM;

	tur->tur_update_records_buf_size = UPDATE_RECORDS_BUFFER_SIZE;

	return 0;
}

/**
 * Extend update records
 *
 * Extend update_records to the new size in thandle_update_records.
 *
 * \param[in] tur	thandle_update_records where update_records will be
 *                      extended.
 * \retval		0 if extension succeeds.
 * \retval		negative errno if extension fails.
 */
int tur_update_records_extend(struct thandle_update_records *tur,
			      size_t new_size)
{
	struct llog_update_record	*record;

	OBD_ALLOC_LARGE(record, new_size);
	if (record == NULL)
		return -ENOMEM;

	if (tur->tur_update_records != NULL) {
		memcpy(record, tur->tur_update_records,
		       tur->tur_update_records_buf_size);
		OBD_FREE_LARGE(tur->tur_update_records,
			       tur->tur_update_records_buf_size);
	}

	tur->tur_update_records = record;
	tur->tur_update_records_buf_size = new_size;

	return 0;
}
EXPORT_SYMBOL(tur_update_records_extend);

/**
 * Extend update records
 *
 * Extend update records in thandle to make sure it is able to hold
 * the update with certain update_op and params size.
 *
 * \param [in] tur	thandle_update_records to be extend
 * \param [in] new_op_size update_op size of the update record
 * \param [in] new_param_size params size of the update record
 *
 * \retval		0 if the update_records is being extended.
 * \retval		negative errno if the update_records is not being
 *                      extended.
 */
int tur_update_extend(struct thandle_update_records *tur,
		      size_t new_op_size, size_t new_param_size)
{
	size_t record_size;
	size_t params_size;
	size_t extend_size;
	int rc;
	ENTRY;

	record_size = llog_update_record_size(tur->tur_update_records);
	/* extend update records buffer */
	if (new_op_size >= (tur->tur_update_records_buf_size - record_size)) {
		extend_size = round_up(new_op_size, UPDATE_RECORDS_BUFFER_SIZE);
		rc = tur_update_records_extend(tur,
				tur->tur_update_records_buf_size +
				extend_size);
		if (rc != 0)
			RETURN(rc);
	}

	/* extend parameters buffer */
	params_size = update_params_size(tur->tur_update_params,
					 tur->tur_update_param_count);
	if (new_param_size >= (tur->tur_update_params_buf_size -
			      params_size)) {
		extend_size = round_up(new_param_size,
				       UPDATE_PARAMS_BUFFER_SIZE);
		rc = tur_update_params_extend(tur,
				tur->tur_update_params_buf_size +
				extend_size);
		if (rc != 0)
			RETURN(rc);
	}

	RETURN(0);
}
EXPORT_SYMBOL(tur_update_extend);

/**
 * Create update params in thandle_update_records
 *
 * Allocate update_params for thandle_update_records, the initial size
 * will be 4KB.
 *
 * \param[in] tur	thandle_update_records where update_params will be
 *                      allocated
 * \retval		0 if allocation succeeds.
 * \retval		negative errno if allocation fails.
 */
static int tur_update_params_create(struct thandle_update_records *tur)
{
	if (tur->tur_update_params != NULL)
		return 0;

	OBD_ALLOC_LARGE(tur->tur_update_params, UPDATE_PARAMS_BUFFER_SIZE);
	if (tur->tur_update_params == NULL)
		return -ENOMEM;

	tur->tur_update_params_buf_size = UPDATE_PARAMS_BUFFER_SIZE;
	return 0;
}

/**
 * Extend update params
 *
 * Extend update_params to the new size in thandle_update_records.
 *
 * \param[in] tur	thandle_update_records where update_params will be
 *                      extended.
 * \retval		0 if extension succeeds.
 * \retval		negative errno if extension fails.
 */
int tur_update_params_extend(struct thandle_update_records *tur,
			     size_t new_size)
{
	struct update_params	*params;

	OBD_ALLOC_LARGE(params, new_size);
	if (params == NULL)
		return -ENOMEM;

	if (tur->tur_update_params != NULL) {
		memcpy(params, tur->tur_update_params,
		       tur->tur_update_params_buf_size);
		OBD_FREE_LARGE(tur->tur_update_params,
			       tur->tur_update_params_buf_size);
	}

	tur->tur_update_params = params;
	tur->tur_update_params_buf_size = new_size;

	return 0;
}
EXPORT_SYMBOL(tur_update_params_extend);

/**
 * Check and prepare whether it needs to record update.
 *
 * Checks if the transaction needs to record updates, and if it
 * does, then initialize the update record buffer in the transaction.
 *
 * \param[in] env	execution environment
 * \param[in] th	transaction handle
 *
 * \retval		0 if updates recording succeeds.
 * \retval		negative errno if updates recording fails.
 */
int check_and_prepare_update_record(const struct lu_env *env,
				    struct thandle_update_records *tur)
{
	struct llog_update_record	*lur;
	int rc;

	if (tur->tur_update_records == NULL) {
		rc = tur_update_records_create(tur);
		if (rc < 0)
			RETURN(rc);
	}

	if (tur->tur_update_params == NULL) {
		rc = tur_update_params_create(tur);
		if (rc < 0)
			RETURN(rc);
	}

	lur = tur->tur_update_records;
	lur->lur_update_rec.ur_update_count = 0;
	lur->lur_update_rec.ur_param_count = 0;
	lur->lur_update_rec.ur_master_transno = 0;
	lur->lur_update_rec.ur_batchid = 0;
	lur->lur_update_rec.ur_flags = 0;
	lur->lur_hdr.lrh_len = LLOG_MIN_CHUNK_SIZE;

	tur->tur_update_param_count = 0;

	RETURN(0);
}

static void update_key_fini(const struct lu_context *ctx,
			    struct lu_context_key *key, void *data)
{
	struct update_thread_info *info = data;
	struct thandle_exec_args  *args = &info->uti_tea;
	int			  i;

	for (i = 0; i < args->ta_alloc_args; i++) {
		if (args->ta_args[i] != NULL)
			OBD_FREE_PTR(args->ta_args[i]);
	}

	if (args->ta_args != NULL)
		OBD_FREE(args->ta_args, sizeof(args->ta_args[0]) *
			 args->ta_alloc_args);

	if (info->uti_tur.tur_update_records != NULL)
		OBD_FREE_LARGE(info->uti_tur.tur_update_records,
			       info->uti_tur.tur_update_records_buf_size);
	if (info->uti_tur.tur_update_params != NULL)
		OBD_FREE_LARGE(info->uti_tur.tur_update_params,
			       info->uti_tur.tur_update_params_buf_size);

	OBD_FREE_PTR(info);
}

/* context key constructor/destructor: update_key_init, update_key_fini */
LU_KEY_INIT(update, struct update_thread_info);
/* context key: update_thread_key */
LU_CONTEXT_KEY_DEFINE(update, LCT_MD_THREAD | LCT_MG_THREAD |
			      LCT_DT_THREAD | LCT_LOCAL);
EXPORT_SYMBOL(update_thread_key);
LU_KEY_INIT_GENERIC(update);

void update_info_init(void)
{
	update_key_init_generic(&update_thread_key, NULL);
	lu_context_key_register(&update_thread_key);
}

void update_info_fini(void)
{
	lu_context_key_degister(&update_thread_key);
}
