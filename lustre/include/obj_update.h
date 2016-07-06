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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 *
 * Selection of object_update and object_update_param handling functions
 */

#ifndef _OBJ_UPDATE_H_
#define _OBJ_UPDATE_H_

#include <lustre/lustre_idl.h>

static inline size_t
object_update_param_size(const struct object_update_param *param)
{
	return cfs_size_round(sizeof(*param) + param->oup_len);
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
	      cfs_size_round(offsetof(struct object_update_reply,
				      ourp_lens[count]));
	for (i = 0; i < index; i++) {
		if (reply->ourp_lens[i] == 0)
			return NULL;

		ptr += cfs_size_round(reply->ourp_lens[i]);
	}

	if (size != NULL)
		*size = reply->ourp_lens[index];

	return ptr;
}
#endif
