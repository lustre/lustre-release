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
 * GPL HEADER END
 */
/*
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ptlrpc/pack_server.c
 *
 * (Un)packing of OST requests
 *
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <llog_swab.h>
#include <obd_class.h>

void lustre_swab_object_update(struct object_update *ou)
{
	struct object_update_param *param;
	size_t	i;

	__swab16s(&ou->ou_type);
	__swab16s(&ou->ou_params_count);
	__swab32s(&ou->ou_result_size);
	__swab32s(&ou->ou_flags);
	__swab32s(&ou->ou_padding1);
	__swab64s(&ou->ou_batchid);
	lustre_swab_lu_fid(&ou->ou_fid);
	param = &ou->ou_params[0];
	for (i = 0; i < ou->ou_params_count; i++) {
		__swab16s(&param->oup_len);
		__swab16s(&param->oup_padding);
		__swab32s(&param->oup_padding2);
		param = (struct object_update_param *)((char *)param +
			 object_update_param_size(param));
	}
}

int lustre_swab_object_update_request(struct object_update_request *our,
				      __u32 len)
{
	__u32 i, size = 0;
	struct object_update *ou;

	__swab32s(&our->ourq_magic);
	__swab16s(&our->ourq_count);
	__swab16s(&our->ourq_padding);

	/* Don't need to calculate request size if len is 0. */
	if (len > 0) {
		size = sizeof(struct object_update_request);
		for (i = 0; i < our->ourq_count; i++) {
			ou = object_update_request_get(our, i, NULL);
			if (ou == NULL)
				return -EPROTO;
			size += sizeof(struct object_update) +
				ou->ou_params_count *
				sizeof(struct object_update_param);
		}
		if (unlikely(size > len))
			return -EOVERFLOW;
	}

	for (i = 0; i < our->ourq_count; i++) {
		ou = object_update_request_get(our, i, NULL);
		lustre_swab_object_update(ou);
	}

	return size;
}

void lustre_swab_object_update_result(struct object_update_result *our)
{
	__swab32s(&our->our_rc);
	__swab16s(&our->our_datalen);
	__swab16s(&our->our_padding);
}

int lustre_swab_object_update_reply(struct object_update_reply *our, __u32 len)
{
	__u32 i, size;

	__swab32s(&our->ourp_magic);
	__swab16s(&our->ourp_count);
	__swab16s(&our->ourp_padding);

	size = sizeof(struct object_update_reply) + our->ourp_count *
	       (sizeof(__u16) + sizeof(struct object_update_result));
	if (unlikely(size > len))
		return -EOVERFLOW;

	for (i = 0; i < our->ourp_count; i++) {
		struct object_update_result *ourp;

		__swab16s(&our->ourp_lens[i]);
		ourp = object_update_result_get(our, i, NULL);
		if (ourp == NULL)
			return -EPROTO;
		lustre_swab_object_update_result(ourp);
	}

	return size;
}

void lustre_swab_out_update_header(struct out_update_header *ouh)
{
	__swab32s(&ouh->ouh_magic);
	__swab32s(&ouh->ouh_count);
	__swab32s(&ouh->ouh_inline_length);
	__swab32s(&ouh->ouh_reply_size);
}
EXPORT_SYMBOL(lustre_swab_out_update_header);

void lustre_swab_out_update_buffer(struct out_update_buffer *oub)
{
	__swab32s(&oub->oub_size);
	__swab32s(&oub->oub_padding);
}
EXPORT_SYMBOL(lustre_swab_out_update_buffer);
