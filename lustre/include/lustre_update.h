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
 * http://www.gnu.org/licenses/gpl-2.0.htm
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2013, 2014, Intel Corporation.
 */
/*
 * lustre/include/lustre_update.h
 *
 * Author: Di Wang <di.wang@intel.com>
 */

#ifndef _LUSTRE_UPDATE_H
#define _LUSTRE_UPDATE_H
#include <lustre_net.h>
#include <dt_object.h>

#define OUT_UPDATE_INIT_BUFFER_SIZE	4096
/* 16KB, the current biggest size is llog header(8KB) */
#define OUT_UPDATE_REPLY_SIZE		16384

struct dt_key;
struct dt_rec;
struct object_update_param;

struct update_buffer {
	struct object_update_request	*ub_req;
	size_t				ub_req_size;
};

/**
 * Tracking the updates being executed on this dt_device.
 */
struct dt_update_request {
	struct dt_device		*dur_dt;
	/* attached itself to thandle */
	int				dur_flags;
	/* update request result */
	int				dur_rc;
	/* Current batch(transaction) id */
	__u64				dur_batchid;
	/* Holding object updates */
	struct update_buffer		dur_buf;
	struct list_head		dur_cb_items;
};

struct update_params {
	struct object_update_param	up_params[0];
};

static inline size_t update_params_size(const struct update_params *params,
					unsigned int param_count)
{
	struct object_update_param	*param;
	size_t total_size = sizeof(*params);
	unsigned int i;

	param = (struct object_update_param *)&params->up_params[0];
	for (i = 0; i < param_count; i++) {
		size_t size = object_update_param_size(param);

		param = (struct object_update_param *)((char *)param + size);
		total_size += size;
	}

	return total_size;
}

static inline struct object_update_param *
update_params_get_param(const struct update_params *params,
			unsigned int index, unsigned int param_count)
{
	struct object_update_param *param;
	unsigned int		i;

	if (index > param_count)
		return NULL;

	param = (struct object_update_param *)&params->up_params[0];
	for (i = 0; i < index; i++)
		param = (struct object_update_param *)((char *)param +
			object_update_param_size(param));

	return param;
}

struct update_op {
	struct lu_fid uop_fid;
	__u16	uop_type;
	__u16	uop_param_count;
	__u16	uop_params_off[0];
};

static inline size_t
update_op_size(unsigned int param_count)
{
	return offsetof(struct update_op, uop_params_off[param_count]);
}

static inline struct update_op *
update_op_next_op(const struct update_op *uop)
{
	return (struct update_op *)((char *)uop +
				update_op_size(uop->uop_param_count));
}

/* All of updates in the mulitple_update_record */
struct update_ops {
	struct update_op	uops_op[0];
};

static inline size_t update_ops_size(const struct update_ops *ops,
				     unsigned int update_count)
{
	struct update_op *op;
	size_t total_size = sizeof(*ops);
	unsigned int i;

	op = (struct update_op *)&ops->uops_op[0];
	for (i = 0; i < update_count; i++, op = update_op_next_op(op))
		total_size += update_op_size(op->uop_param_count);

	return total_size;
}

/*
 * This is the update record format used to store the updates in
 * disk. All updates of the operation will be stored in ur_ops.
 * All of parameters for updates of the operation will be stored
 * in ur_params.
 * To save the space of the record, parameters in ur_ops will only
 * remember their offset in ur_params, so to avoid storing duplicate
 * parameters in ur_params, which can help us save a lot space for
 * operation like creating striped directory.
 */
struct update_records {
	__u64			ur_master_transno;
	__u64			ur_batchid;
	__u32			ur_flags;
	__u32			ur_param_count;
	__u32			ur_update_count;
	struct update_ops	ur_ops;
	 /* Note ur_ops has a variable size, so comment out
	  * the following ur_params, in case some use it directly
	  * update_records->ur_params
	  *
	  * struct update_params	ur_params;
	  */
};

struct llog_update_record {
	struct llog_rec_hdr	lur_hdr;
	struct update_records	lur_update_rec;
	/* Note ur_update_rec has a variable size, so comment out
	 * the following ur_tail, in case someone use it directly
	 *
	 * struct llog_rec_tail	lur_tail;
	 */
};

static inline struct update_params *
update_records_get_params(const struct update_records *record)
{
	return (struct update_params *)((char *)record +
		offsetof(struct update_records, ur_ops) +
		update_ops_size(&record->ur_ops, record->ur_update_count));
}

static inline size_t
update_records_size(const struct update_records *record)
{
	struct update_params *params;

	params = update_records_get_params(record);

	return cfs_size_round(offsetof(struct update_records, ur_ops) +
	       update_ops_size(&record->ur_ops, record->ur_update_count) +
	       update_params_size(params, record->ur_param_count));
}

static inline size_t
llog_update_record_size(const struct llog_update_record *lur)
{
	return cfs_size_round(sizeof(lur->lur_hdr) +
			      update_records_size(&lur->lur_update_rec) +
			      sizeof(struct llog_rec_tail));
}

static inline struct update_op *
update_ops_get_op(const struct update_ops *ops, unsigned int index,
		  unsigned int update_count)
{
	struct update_op *op;
	unsigned int i;

	if (index > update_count)
		return NULL;

	op = (struct update_op *)&ops->uops_op[0];
	for (i = 0; i < index; i++)
		op = update_op_next_op(op);

	return op;
}

static inline void
*object_update_param_get(const struct object_update *update, size_t index,
			 size_t *size)
{
	const struct	object_update_param *param;
	size_t		i;

	if (index >= update->ou_params_count)
		return ERR_PTR(-EINVAL);

	param = &update->ou_params[0];
	for (i = 0; i < index; i++)
		param = (struct object_update_param *)((char *)param +
			object_update_param_size(param));

	if (size != NULL)
		*size = param->oup_len;

	if (param->oup_len == 0)
		return NULL;

	return (void *)&param->oup_buf[0];
}

static inline unsigned long
object_update_request_size(const struct object_update_request *our)
{
	unsigned long	size;
	size_t		i = 0;

	size = offsetof(struct object_update_request, ourq_updates[0]);
	for (i = 0; i < our->ourq_count; i++) {
		struct object_update *update;

		update = (struct object_update *)((char *)our + size);
		size += object_update_size(update);
	}
	return size;
}

static inline void
object_update_reply_init(struct object_update_reply *reply, size_t count)
{
	reply->ourp_magic = UPDATE_REPLY_MAGIC;
	reply->ourp_count = count;
}

static inline void
object_update_result_insert(struct object_update_reply *reply,
			    void *data, size_t data_len, size_t index,
			    int rc)
{
	struct object_update_result *update_result;
	char *ptr;

	update_result = object_update_result_get(reply, index, NULL);
	LASSERT(update_result != NULL);

	update_result->our_rc = ptlrpc_status_hton(rc);
	if (data_len > 0) {
		LASSERT(data != NULL);
		ptr = (char *)update_result +
			cfs_size_round(sizeof(struct object_update_reply));
		update_result->our_datalen = data_len;
		memcpy(ptr, data, data_len);
	}

	reply->ourp_lens[index] = cfs_size_round(data_len +
					sizeof(struct object_update_result));
}

static inline int
object_update_result_data_get(const struct object_update_reply *reply,
			      struct lu_buf *lbuf, size_t index)
{
	struct object_update_result *update_result;
	size_t size = 0;
	int    result;

	LASSERT(lbuf != NULL);
	update_result = object_update_result_get(reply, index, &size);
	if (update_result == NULL ||
	    size < cfs_size_round(sizeof(struct object_update_reply)) ||
	    update_result->our_datalen > size)
		RETURN(-EFAULT);

	result = ptlrpc_status_ntoh(update_result->our_rc);
	if (result < 0)
		return result;

	lbuf->lb_buf = update_result->our_data;
	lbuf->lb_len = update_result->our_datalen;

	return 0;
}

/**
 * Attached in the thandle to record the updates for distribute
 * distribution.
 */
struct thandle_update_records {
	/* All of updates for the cross-MDT operation. */
	struct llog_update_record	*tur_update_records;
	size_t				tur_update_records_buf_size;

	/* All of parameters for the cross-MDT operation */
	struct update_params    *tur_update_params;
	unsigned int		tur_update_param_count;
	size_t			tur_update_params_buf_size;
};

#define TOP_THANDLE_MAGIC	0x20140917
/* {top,sub}_thandle are used to manage distributed transactions which
 * include updates on several nodes. A top_handle represents the
 * whole operation, and sub_thandle represents updates on each node. */
struct top_thandle {
	struct thandle		tt_super;
	__u32			tt_magic;
	atomic_t		tt_refcount;
	/* The master sub transaction. */
	struct thandle		*tt_master_sub_thandle;

	/* Other sub thandle will be listed here. */
	struct list_head	tt_sub_thandle_list;

	/* All of update records will packed here */
	struct thandle_update_records *tt_update_records;
};

struct sub_thandle {
	/* point to the osd/osp_thandle */
	struct thandle		*st_sub_th;

	/* linked to top_thandle */
	struct list_head	st_sub_list;

	/* If this sub thandle is committed */
	bool			st_committed:1,
				st_record_update:1;
};


/* target/out_lib.c */
int out_update_pack(const struct lu_env *env, struct object_update *update,
		    size_t max_update_size, enum update_type op,
		    const struct lu_fid *fid, unsigned int params_count,
		    __u16 *param_sizes, const void **param_bufs);
int out_create_pack(const struct lu_env *env, struct object_update *update,
		    size_t max_update_size, const struct lu_fid *fid,
		    const struct lu_attr *attr, struct dt_allocation_hint *hint,
		    struct dt_object_format *dof);
int out_object_destroy_pack(const struct lu_env *env,
			    struct object_update *update,
			    size_t max_update_size,
			    const struct lu_fid *fid);
int out_index_delete_pack(const struct lu_env *env,
			  struct object_update *update, size_t max_update_size,
			  const struct lu_fid *fid, const struct dt_key *key);
int out_index_insert_pack(const struct lu_env *env,
			  struct object_update *update, size_t max_update_size,
			  const struct lu_fid *fid, const struct dt_rec *rec,
			  const struct dt_key *key);
int out_xattr_set_pack(const struct lu_env *env,
		       struct object_update *update, size_t max_update_size,
		       const struct lu_fid *fid, const struct lu_buf *buf,
		       const char *name, __u32 flag);
int out_xattr_del_pack(const struct lu_env *env,
		       struct object_update *update, size_t max_update_size,
		       const struct lu_fid *fid, const char *name);
int out_attr_set_pack(const struct lu_env *env,
		      struct object_update *update, size_t max_update_size,
		      const struct lu_fid *fid, const struct lu_attr *attr);
int out_ref_add_pack(const struct lu_env *env,
		     struct object_update *update, size_t max_update_size,
		     const struct lu_fid *fid);
int out_ref_del_pack(const struct lu_env *env,
		     struct object_update *update, size_t max_update_size,
		     const struct lu_fid *fid);
int out_write_pack(const struct lu_env *env,
		   struct object_update *update, size_t max_update_size,
		   const struct lu_fid *fid, const struct lu_buf *buf,
		   __u64 pos);
int out_attr_get_pack(const struct lu_env *env,
		      struct object_update *update, size_t max_update_size,
		      const struct lu_fid *fid);
int out_index_lookup_pack(const struct lu_env *env,
			  struct object_update *update, size_t max_update_size,
			  const struct lu_fid *fid, struct dt_rec *rec,
			  const struct dt_key *key);
int out_xattr_get_pack(const struct lu_env *env,
		       struct object_update *update, size_t max_update_size,
		       const struct lu_fid *fid, const char *name);
int out_read_pack(const struct lu_env *env, struct object_update *update,
		  size_t max_update_length, const struct lu_fid *fid,
		  size_t size, loff_t pos);

const char *update_op_str(__u16 opcode);

/* target/update_trans.c */
struct thandle *thandle_get_sub_by_dt(const struct lu_env *env,
				      struct thandle *th,
				      struct dt_device *sub_dt);

static inline struct thandle *
thandle_get_sub(const struct lu_env *env, struct thandle *th,
		 const struct dt_object *sub_obj)
{
	return thandle_get_sub_by_dt(env, th, lu2dt_dev(sub_obj->do_lu.lo_dev));
}

struct thandle *
top_trans_create(const struct lu_env *env, struct dt_device *master_dev);

int top_trans_start(const struct lu_env *env, struct dt_device *master_dev,
		    struct thandle *th);

int top_trans_stop(const struct lu_env *env, struct dt_device *master_dev,
		   struct thandle *th);

void top_thandle_destroy(struct top_thandle *top_th);

/* update_records.c */
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
			       struct dt_object_format *dof);
int update_records_attr_set_pack(const struct lu_env *env,
				 struct update_ops *ops,
				 unsigned int *op_count,
				 size_t *max_ops_size,
				 struct update_params *params,
				 unsigned int *param_count,
				 size_t *max_param_size,
				 const struct lu_fid *fid,
				 const struct lu_attr *attr);
int update_records_ref_add_pack(const struct lu_env *env,
				struct update_ops *ops,
				unsigned int *op_count,
				size_t *max_ops_size,
				struct update_params *params,
				unsigned int *param_count,
				size_t *max_param_size,
				const struct lu_fid *fid);
int update_records_ref_del_pack(const struct lu_env *env,
				struct update_ops *ops,
				unsigned int *op_count,
				size_t *max_ops_size,
				struct update_params *params,
				unsigned int *param_count,
				size_t *max_param_size,
				const struct lu_fid *fid);
int update_records_object_destroy_pack(const struct lu_env *env,
				       struct update_ops *ops,
				       unsigned int *op_count,
				       size_t *max_ops_size,
				       struct update_params *params,
				       unsigned int *param_count,
				       size_t *max_param_size,
				       const struct lu_fid *fid);
int update_records_index_insert_pack(const struct lu_env *env,
				     struct update_ops *ops,
				     unsigned int *op_count,
				     size_t *max_ops_size,
				     struct update_params *params,
				     unsigned int *param_count,
				     size_t *max_param_size,
				     const struct lu_fid *fid,
				     const struct dt_rec *rec,
				     const struct dt_key *key);
int update_records_index_delete_pack(const struct lu_env *env,
				     struct update_ops *ops,
				     unsigned int *op_count,
				     size_t *max_ops_size,
				     struct update_params *params,
				     unsigned int *param_count,
				     size_t *max_param_size,
				     const struct lu_fid *fid,
				     const struct dt_key *key);
int update_records_xattr_set_pack(const struct lu_env *env,
				  struct update_ops *ops,
				  unsigned int *op_count,
				  size_t *max_ops_size,
				  struct update_params *params,
				  unsigned int *param_count,
				  size_t *max_param_size,
				  const struct lu_fid *fid,
				  const struct lu_buf *buf, const char *name,
				  __u32 flag);
int update_records_xattr_del_pack(const struct lu_env *env,
				  struct update_ops *ops,
				  unsigned int *op_count,
				  size_t *max_ops_size,
				  struct update_params *params,
				  unsigned int *param_count,
				  size_t *max_param_size,
				  const struct lu_fid *fid,
				  const char *name);
int update_records_write_pack(const struct lu_env *env,
			      struct update_ops *ops,
			      unsigned int *op_count,
			      size_t *max_ops_size,
			      struct update_params *params,
			      unsigned int *param_count,
			      size_t *max_param_size,
			      const struct lu_fid *fid,
			      const struct lu_buf *buf,
			      __u64 pos);
int update_records_punch_pack(const struct lu_env *env,
			      struct update_ops *ops,
			      unsigned int *op_count,
			      size_t *max_ops_size,
			      struct update_params *params,
			      unsigned int *param_count,
			      size_t *max_param_size,
			      const struct lu_fid *fid,
			      __u64 start, __u64 end);

int tur_update_records_extend(struct thandle_update_records *tur,
			      size_t new_size);
int tur_update_params_extend(struct thandle_update_records *tur,
			     size_t new_size);
int check_and_prepare_update_record(const struct lu_env *env,
				    struct thandle *th);
int merge_params_updates_buf(const struct lu_env *env,
			     struct thandle_update_records *tur);
int tur_update_extend(struct thandle_update_records *tur,
		      size_t new_op_size, size_t new_param_size);

#define update_record_pack(name, th, ...)				\
({									\
	struct top_thandle *top_th;					\
	struct thandle_update_records *tur;				\
	struct llog_update_record     *lur;				\
	size_t		avail_param_size;				\
	size_t		avail_op_size;					\
	int		ret;						\
									\
	while (1) {							\
		top_th = container_of(th, struct top_thandle, tt_super);\
		tur = top_th->tt_update_records;			\
		lur = tur->tur_update_records;				\
		avail_param_size = tur->tur_update_params_buf_size -	\
			     update_params_size(tur->tur_update_params,	\
					tur->tur_update_param_count);	\
		avail_op_size = tur->tur_update_records_buf_size -	\
				llog_update_record_size(lur);		\
		ret = update_records_##name##_pack(env,			\
					  &lur->lur_update_rec.ur_ops,	\
				  &lur->lur_update_rec.ur_update_count,	\
				  &avail_op_size,			\
				  tur->tur_update_params,		\
				  &tur->tur_update_param_count,		\
				  &avail_param_size, __VA_ARGS__);	\
		if (ret == -E2BIG) {					\
			ret = tur_update_extend(tur, avail_op_size,	\
						   avail_param_size);	\
			if (ret != 0)					\
				break;					\
			continue;					\
		} else {						\
			break;						\
		}							\
	}								\
	ret;								\
})
#endif
