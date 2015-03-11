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

#define OUT_UPDATE_INIT_BUFFER_SIZE	4096
#define OUT_UPDATE_REPLY_SIZE		8192

struct dt_object;
struct dt_object_hint;
struct dt_object_format;
struct dt_allocation_hint;
struct dt_key;
struct dt_rec;
struct thandle;

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
	struct list_head		dur_list;
	int				dur_flags;
	/* update request result */
	int				dur_rc;
	/* Current batch(transaction) id */
	__u64				dur_batchid;
	/* Holding object updates */
	struct update_buffer		dur_buf;
	struct list_head		dur_cb_items;
};

static inline void
*object_update_param_get(const struct object_update *update, size_t index,
			 size_t *size)
{
	const struct	object_update_param *param;
	size_t		i;

	if (index >= update->ou_params_count)
		return NULL;

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

static inline void update_inc_batchid(struct dt_update_request *update)
{
	update->dur_batchid++;
}

/* target/out_lib.c */
struct thandle_update;
struct dt_update_request *out_find_update(struct thandle_update *tu,
					  struct dt_device *dt_dev);
void dt_update_request_destroy(struct dt_update_request *update);
struct dt_update_request *dt_update_request_create(struct dt_device *dt);
struct dt_update_request *dt_update_request_find_or_create(struct thandle *th,
							  struct dt_object *dt);
int out_update_pack(const struct lu_env *env, struct update_buffer *ubuf,
		    enum update_type op, const struct lu_fid *fid,
		    int params_count, __u16 *param_sizes, const void **bufs,
		    __u64 batchid);
int out_create_pack(const struct lu_env *env, struct update_buffer *ubuf,
		    const struct lu_fid *fid, struct lu_attr *attr,
		    struct dt_allocation_hint *hint,
		    struct dt_object_format *dof, __u64 batchid);
int out_object_destroy_pack(const struct lu_env *env,
			    struct update_buffer *ubuf,
			    const struct lu_fid *fid, __u64 batchid);
int out_index_delete_pack(const struct lu_env *env, struct update_buffer *ubuf,
			  const struct lu_fid *fid, const struct dt_key *key,
			  __u64 batchid);
int out_index_insert_pack(const struct lu_env *env, struct update_buffer *ubuf,
			  const struct lu_fid *fid, const struct dt_rec *rec,
			  const struct dt_key *key, __u64 batchid);
int out_xattr_set_pack(const struct lu_env *env, struct update_buffer *ubuf,
		       const struct lu_fid *fid, const struct lu_buf *buf,
		       const char *name, int flag, __u64 batchid);
int out_xattr_del_pack(const struct lu_env *env, struct update_buffer *ubuf,
		       const struct lu_fid *fid, const char *name,
		       __u64 batchid);
int out_attr_set_pack(const struct lu_env *env, struct update_buffer *ubuf,
		      const struct lu_fid *fid, const struct lu_attr *attr,
		      __u64 batchid);
int out_ref_add_pack(const struct lu_env *env, struct update_buffer *ubuf,
		     const struct lu_fid *fid, __u64 batchid);
int out_ref_del_pack(const struct lu_env *env, struct update_buffer *ubuf,
		     const struct lu_fid *fid, __u64 batchid);
int out_write_pack(const struct lu_env *env, struct update_buffer *ubuf,
		   const struct lu_fid *fid, const struct lu_buf *buf,
		   loff_t pos, __u64 batchid);
int out_attr_get_pack(const struct lu_env *env, struct update_buffer *ubuf,
		      const struct lu_fid *fid);
int out_index_lookup_pack(const struct lu_env *env, struct update_buffer *ubuf,
			  const struct lu_fid *fid, struct dt_rec *rec,
			  const struct dt_key *key);
int out_xattr_get_pack(const struct lu_env *env, struct update_buffer *ubuf,
		       const struct lu_fid *fid, const char *name);
#endif
