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
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * lustre/include/lustre_update.h
 *
 * Author: Di Wang <di.wang@intel.com>
 */

#ifndef _LUSTRE_UPDATE_H
#define _LUSTRE_UPDATE_H
#include <lustre_net.h>

#define OUT_UPDATE_INIT_BUFFER_SIZE	8192
#define OUT_UPDATE_REPLY_SIZE	8192
struct dt_update_request {
	struct dt_device		*dur_dt;
	/* attached itself to thandle */
	struct list_head		dur_list;
	int				dur_flags;
	/* update request result */
	int				dur_rc;
	/* Current batch(transaction) id */
	__u64				dur_batchid;
	/* Holding the update req */
	struct object_update_request	*dur_req;
	int				dur_req_len;
	struct list_head		dur_cb_items;
};

static inline unsigned long
object_update_param_size(const struct object_update_param *param)
{
	return cfs_size_round(sizeof(*param) + param->oup_len);
}

static inline unsigned long
object_update_size(const struct object_update *update)
{
	const struct	object_update_param *param;
	unsigned long	size;
	int		i;

	size = offsetof(struct object_update, ou_params[0]);
	for (i = 0; i < update->ou_params_count; i++) {
		param = (struct object_update_param *)((char *)update + size);
		size += object_update_param_size(param);
	}

	return size;
}

static inline void
*object_update_param_get(const struct object_update *update, int index,
			 int *size)
{
	const struct	object_update_param *param;
	int		i;

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
	unsigned long size;
	int	   i = 0;

	size = offsetof(struct object_update_request, ourq_updates[0]);
	for (i = 0; i < our->ourq_count; i++) {
		struct object_update *update;

		update = (struct object_update *)((char *)our + size);
		size += object_update_size(update);
	}
	return size;
}

static inline struct object_update
*object_update_request_get(const struct object_update_request *our,
			   int index, int *size)
{
	void	*ptr;
	int	i;

	if (index >= our->ourq_count)
		return NULL;

	ptr = (char *)our + offsetof(struct object_update_request,
				     ourq_updates[0]);
	for (i = 0; i < index; i++)
		ptr += object_update_size((struct object_update *)ptr);

	if (size != NULL)
		*size = object_update_size((struct object_update *)ptr);

	return ptr;
}

static inline void
object_update_reply_init(struct object_update_reply *reply, int count)
{
	reply->ourp_magic = UPDATE_REPLY_MAGIC;
	reply->ourp_count = count;
}

static inline struct object_update_result
*object_update_result_get(const struct object_update_reply *reply,
			  int index, int *size)
{
	char *ptr;
	int count = reply->ourp_count;
	int i;

	if (index >= count)
		return NULL;

	ptr = (char *)reply +
	      cfs_size_round(offsetof(struct object_update_reply,
				      ourp_lens[count]));
	for (i = 0; i < index; i++) {
		LASSERT(reply->ourp_lens[i] > 0);
		ptr += cfs_size_round(reply->ourp_lens[i]);
	}

	if (size != NULL)
		*size = reply->ourp_lens[index];

	return (struct object_update_result *)ptr;
}

static inline void
object_update_result_insert(struct object_update_reply *reply,
			    void *data, int data_len, int index,
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
			      struct lu_buf *lbuf, int index)
{
	struct object_update_result *update_result;
	int  size = 0;
	int  result;

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

#endif
