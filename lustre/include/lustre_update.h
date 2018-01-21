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
 * Copyright (c) 2013, 2017, Intel Corporation.
 */
/*
 * lustre/include/lustre_update.h
 *
 * Author: Di Wang <di.wang@intel.com>
 */

#ifndef _LUSTRE_UPDATE_H
#define _LUSTRE_UPDATE_H
#include <dt_object.h>
#include <lustre_net.h>
#include <obj_update.h>

#define OUT_UPDATE_REPLY_SIZE		4096
#define OUT_BULK_BUFFER_SIZE		4096

struct dt_key;
struct dt_rec;
struct object_update_param;
struct llog_update_record;

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

static inline void*
update_params_get_param_buf(const struct update_params *params, __u16 index,
			    unsigned int param_count, __u16 *size)
{
	struct object_update_param *param;

	param = update_params_get_param(params, (unsigned int)index,
					param_count);
	if (param == NULL)
		return NULL;

	if (size != NULL)
		*size = param->oup_len;

	return param->oup_buf;
}

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

static inline struct update_params *
update_records_get_params(const struct update_records *record)
{
	return (struct update_params *)((char *)record +
		offsetof(struct update_records, ur_ops) +
		update_ops_size(&record->ur_ops, record->ur_update_count));
}

static inline struct update_param *
update_param_next_param(const struct update_param *param)
{
	return (struct update_param *)((char *)param +
				       object_update_param_size(
					  (struct object_update_param *)param));
}

static inline size_t
__update_records_size(size_t raw_size)
{
	return cfs_size_round(offsetof(struct update_records, ur_ops) +
			      raw_size);
}

static inline size_t
update_records_size(const struct update_records *record)
{
	size_t op_size = 0;
	size_t param_size = 0;

	if (record->ur_update_count > 0)
		op_size = update_ops_size(&record->ur_ops,
					  record->ur_update_count);
	if (record->ur_param_count > 0) {
		struct update_params *params;

		params = update_records_get_params(record);
		param_size = update_params_size(params, record->ur_param_count);
	}

	return __update_records_size(op_size + param_size);
}

static inline size_t
__llog_update_record_size(size_t records_size)
{
	return cfs_size_round(sizeof(struct llog_rec_hdr) + records_size +
			      sizeof(struct llog_rec_tail));
}

static inline size_t
llog_update_record_size(const struct llog_update_record *lur)
{
	return __llog_update_record_size(
			update_records_size(&lur->lur_update_rec));
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
		return ERR_PTR(-ENODATA);

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
object_update_result_insert(struct object_update_reply *reply,
			    void *data, size_t data_len, size_t index,
			    int rc)
{
	struct object_update_result *update_result;

	update_result = object_update_result_get(reply, index, NULL);
	LASSERT(update_result);

	update_result->our_rc = ptlrpc_status_hton(rc);
	if (rc >= 0) {
		if (data_len > 0 && data)
			memcpy(update_result->our_data, data, data_len);
		update_result->our_datalen = data_len;
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

	return result;
}

/**
 * Attached in the thandle to record the updates for distribute
 * distribution.
 */
struct thandle_update_records {
	/* All of updates for the cross-MDT operation, vmalloc'd. */
	struct llog_update_record	*tur_update_records;
	size_t				tur_update_records_buf_size;

	/* All of parameters for the cross-MDT operation, vmalloc'd */
	struct update_params    *tur_update_params;
	unsigned int		tur_update_param_count;
	size_t			tur_update_params_buf_size;
};

#define TOP_THANDLE_MAGIC	0x20140917
struct top_multiple_thandle {
	struct dt_device	*tmt_master_sub_dt;
	atomic_t		tmt_refcount;
	/* Other sub transactions will be listed here. */
	struct list_head	tmt_sub_thandle_list;
	spinlock_t		tmt_sub_lock;

	struct list_head	tmt_commit_list;
	/* All of update records will packed here */
	struct thandle_update_records *tmt_update_records;

	wait_queue_head_t	tmt_stop_waitq;
	__u64			tmt_batchid;
	int			tmt_result;
	__u32			tmt_magic;
	size_t			tmt_record_size;
	__u32			tmt_committed:1;
};

/* {top,sub}_thandle are used to manage distributed transactions which
 * include updates on several nodes. A top_handle represents the
 * whole operation, and sub_thandle represents updates on each node. */
struct top_thandle {
	struct thandle		tt_super;
	/* The master sub transaction. */
	struct thandle		*tt_master_sub_thandle;

	struct top_multiple_thandle *tt_multiple_thandle;
};

struct sub_thandle_cookie {
	struct llog_cookie	stc_cookie;
	struct list_head	stc_list;
};

/* Sub thandle is used to track multiple sub thandles under one parent
 * thandle */
struct sub_thandle {
	struct thandle		*st_sub_th;
	struct dt_device	*st_dt;
	struct list_head	st_cookie_list;
	struct dt_txn_commit_cb	st_commit_dcb;
	struct dt_txn_commit_cb	st_stop_dcb;
	int			st_result;

	/* linked to top_thandle */
	struct list_head	st_sub_list;

	/* If this sub thandle is committed */
	bool			st_committed:1,
				st_stopped:1,
				st_started:1;
};

struct tx_arg;
typedef int (*tx_exec_func_t)(const struct lu_env *env, struct thandle *th,
			      struct tx_arg *ta);

/* Structure for holding one update execution */
struct tx_arg {
	tx_exec_func_t		 exec_fn;
	tx_exec_func_t		 undo_fn;
	struct dt_object	*object;
	const char		*file;
	struct object_update_reply *reply;
	int			 line;
	int			 index;
	union {
		struct {
			struct dt_insert_rec	 rec;
			const struct dt_key	*key;
		} insert;
		struct {
		} ref;
		struct {
			struct lu_attr	 attr;
		} attr_set;
		struct {
			struct lu_buf	 buf;
			const char	*name;
			int		 flags;
			__u32		 csum;
		} xattr_set;
		struct {
			struct lu_attr			attr;
			struct dt_allocation_hint	hint;
			struct dt_object_format		dof;
			struct lu_fid			fid;
		} create;
		struct {
			struct lu_buf	buf;
			loff_t		pos;
		} write;
		struct {
			struct ost_body	    *body;
		} destroy;
	} u;
};

/* Structure for holding all update executations of one transaction */
struct thandle_exec_args {
	struct thandle		*ta_handle;
	int			ta_argno;   /* used args */
	int			ta_alloc_args; /* allocated args count */
	struct tx_arg		**ta_args;
};

/* target/out_lib.c */
int out_update_pack(const struct lu_env *env, struct object_update *update,
		    size_t *max_update_size, enum update_type op,
		    const struct lu_fid *fid, unsigned int params_count,
		    __u16 *param_sizes, const void **param_bufs,
		    __u32 reply_size);
int out_create_pack(const struct lu_env *env, struct object_update *update,
		    size_t *max_update_size, const struct lu_fid *fid,
		    const struct lu_attr *attr, struct dt_allocation_hint *hint,
		    struct dt_object_format *dof);
int out_destroy_pack(const struct lu_env *env, struct object_update *update,
		     size_t *max_update_size, const struct lu_fid *fid);
int out_index_delete_pack(const struct lu_env *env,
			  struct object_update *update, size_t *max_update_size,
			  const struct lu_fid *fid, const struct dt_key *key);
int out_index_insert_pack(const struct lu_env *env,
			  struct object_update *update, size_t *max_update_size,
			  const struct lu_fid *fid, const struct dt_rec *rec,
			  const struct dt_key *key);
int out_xattr_set_pack(const struct lu_env *env,
		       struct object_update *update, size_t *max_update_size,
		       const struct lu_fid *fid, const struct lu_buf *buf,
		       const char *name, __u32 flag);
int out_xattr_del_pack(const struct lu_env *env,
		       struct object_update *update, size_t *max_update_size,
		       const struct lu_fid *fid, const char *name);
int out_attr_set_pack(const struct lu_env *env,
		      struct object_update *update, size_t *max_update_size,
		      const struct lu_fid *fid, const struct lu_attr *attr);
int out_ref_add_pack(const struct lu_env *env,
		     struct object_update *update, size_t *max_update_size,
		     const struct lu_fid *fid);
int out_ref_del_pack(const struct lu_env *env,
		     struct object_update *update, size_t *max_update_size,
		     const struct lu_fid *fid);
int out_write_pack(const struct lu_env *env,
		   struct object_update *update, size_t *max_update_size,
		   const struct lu_fid *fid, const struct lu_buf *buf,
		   __u64 pos);
int out_attr_get_pack(const struct lu_env *env,
		      struct object_update *update, size_t *max_update_size,
		      const struct lu_fid *fid);
int out_index_lookup_pack(const struct lu_env *env,
			  struct object_update *update, size_t *max_update_size,
			  const struct lu_fid *fid, struct dt_rec *rec,
			  const struct dt_key *key);
int out_xattr_get_pack(const struct lu_env *env,
		       struct object_update *update, size_t *max_update_size,
		       const struct lu_fid *fid, const char *name,
		       const int bufsize);
int out_xattr_list_pack(const struct lu_env *env, struct object_update *update,
		       size_t *max_update_size, const struct lu_fid *fid,
		       const int bufsize);
int out_read_pack(const struct lu_env *env, struct object_update *update,
		  size_t *max_update_length, const struct lu_fid *fid,
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
void top_multiple_thandle_destroy(struct top_multiple_thandle *tmt);

static inline void top_multiple_thandle_get(struct top_multiple_thandle *tmt)
{
	atomic_inc(&tmt->tmt_refcount);
}

static inline void top_multiple_thandle_put(struct top_multiple_thandle *tmt)
{
	if (atomic_dec_and_test(&tmt->tmt_refcount))
		top_multiple_thandle_destroy(tmt);
}

struct sub_thandle *lookup_sub_thandle(struct top_multiple_thandle *tmt,
				       struct dt_device *dt_dev);
int sub_thandle_trans_create(const struct lu_env *env,
			     struct top_thandle *top_th,
			     struct sub_thandle *st);

/* update_records.c */
size_t update_records_create_size(const struct lu_env *env,
				  const struct lu_fid *fid,
				  const struct lu_attr *attr,
				  const struct dt_allocation_hint *hint,
				  struct dt_object_format *dof);
size_t update_records_attr_set_size(const struct lu_env *env,
				    const struct lu_fid *fid,
				    const struct lu_attr *attr);
size_t update_records_ref_add_size(const struct lu_env *env,
				   const struct lu_fid *fid);
size_t update_records_ref_del_size(const struct lu_env *env,
				   const struct lu_fid *fid);
size_t update_records_destroy_size(const struct lu_env *env,
				   const struct lu_fid *fid);
size_t update_records_index_insert_size(const struct lu_env *env,
					const struct lu_fid *fid,
					const struct dt_rec *rec,
					const struct dt_key *key);
size_t update_records_index_delete_size(const struct lu_env *env,
					const struct lu_fid *fid,
					const struct dt_key *key);
size_t update_records_xattr_set_size(const struct lu_env *env,
				     const struct lu_fid *fid,
				     const struct lu_buf *buf,
				     const char *name,
				     __u32 flag);
size_t update_records_xattr_del_size(const struct lu_env *env,
				     const struct lu_fid *fid,
				     const char *name);
size_t update_records_write_size(const struct lu_env *env,
				 const struct lu_fid *fid,
				 const struct lu_buf *buf,
				 __u64 pos);
size_t update_records_punch_size(const struct lu_env *env,
				 const struct lu_fid *fid,
				 __u64 start, __u64 end);

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
int update_records_destroy_pack(const struct lu_env *env,
				struct update_ops *ops, unsigned int *op_count,
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
int update_records_noop_pack(const struct lu_env *env,
			     struct update_ops *ops,
			     unsigned int *op_count,
			     size_t *max_ops_size,
			     struct update_params *params,
			     unsigned int *param_count,
			     size_t *max_param_size,
			     const struct lu_fid *fid);

int tur_update_records_extend(struct thandle_update_records *tur,
			      size_t new_size);
int tur_update_params_extend(struct thandle_update_records *tur,
			     size_t new_size);
int tur_update_extend(struct thandle_update_records *tur,
		      size_t new_op_size, size_t new_param_size);

#define update_record_pack(name, th, ...)				\
({									\
	struct top_thandle *top_th;					\
	struct top_multiple_thandle *tmt;				\
	struct thandle_update_records *tur;				\
	struct llog_update_record     *lur;				\
	size_t		avail_param_size;				\
	size_t		avail_op_size;					\
	int		ret;						\
									\
	while (1) {							\
		top_th = container_of(th, struct top_thandle, tt_super);\
		tmt = top_th->tt_multiple_thandle;			\
		tur = tmt->tmt_update_records;				\
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

#define update_record_size(env, name, th, ...)				\
({									\
	struct top_thandle *top_th;					\
	struct top_multiple_thandle *tmt;				\
									\
	top_th = container_of(th, struct top_thandle, tt_super);	\
									\
	LASSERT(top_th->tt_multiple_thandle != NULL);			\
	tmt = top_th->tt_multiple_thandle;				\
	tmt->tmt_record_size +=						\
		update_records_##name##_size(env, __VA_ARGS__);		\
})
#endif
