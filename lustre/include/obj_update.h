/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Selection of object_update and object_update_param handling functions
 */

#ifndef _OBJ_UPDATE_H_
#define _OBJ_UPDATE_H_

#include <uapi/linux/lustre/lustre_idl.h>

static inline size_t
object_update_param_size(const struct object_update_param *param)
{
	return round_up(sizeof(*param) + param->oup_len, 8);
}

static inline size_t
object_update_params_size(const struct object_update *update)
{
	const struct object_update_param *param;
	size_t				 total_size = 0;
	unsigned int			 i;

	param = &update->ou_params[0];
	for (i = 0; i < update->ou_params_count; i++) {
		size_t size = object_update_param_size(param);

		param = (struct object_update_param *)((char *)param + size);
		total_size += size;
	}

	return total_size;
}

static inline size_t
object_update_size(const struct object_update *update)
{
	return offsetof(struct object_update, ou_params[0]) +
	       object_update_params_size(update);
}

static inline struct object_update *
object_update_request_get(const struct object_update_request *our,
			  unsigned int index, size_t *size)
{
	void	*ptr;
	unsigned int i;

	if (index >= our->ourq_count)
		return NULL;

	ptr = (void *)&our->ourq_updates[0];
	for (i = 0; i < index; i++)
		ptr += object_update_size(ptr);

	if (size != NULL)
		*size = object_update_size(ptr);

	return ptr;
}



static inline struct object_update_result *
object_update_result_get(const struct object_update_reply *reply,
			 unsigned int index, size_t *size)
{
	__u16 count = reply->ourp_count;
	unsigned int i;
	void *ptr;

	if (index >= count)
		return NULL;

	ptr = (char *)reply +
	      round_up(offsetof(struct object_update_reply,
				ourp_lens[count]), 8);
	for (i = 0; i < index; i++) {
		if (reply->ourp_lens[i] == 0)
			return NULL;

		ptr += round_up(reply->ourp_lens[i], 8);
	}

	if (size != NULL)
		*size = reply->ourp_lens[index];

	return ptr;
}

static inline struct lustre_msg *
batch_update_reqmsg_next(struct batch_update_request *bur,
			 struct lustre_msg *reqmsg)
{
	if (reqmsg)
		return (struct lustre_msg *)((char *)reqmsg +
					     lustre_packed_msg_size(reqmsg));
	else
		return &bur->burq_reqmsg[0];
}

static inline struct lustre_msg *
batch_update_repmsg_next(struct batch_update_reply *bur,
			 struct lustre_msg *repmsg)
{
	if (repmsg)
		return (struct lustre_msg *)((char *)repmsg +
					     lustre_packed_msg_size(repmsg));
	else
		return &bur->burp_repmsg[0];
}
#endif
