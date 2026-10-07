// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * (Un)packing of OST requests
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <lustre_swab.h>
#include <llog_swab.h>
#include <obd_class.h>

static void
lustre_swab_object_update_result_no_len(struct object_update_result *our)
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
		lustre_swab_object_update_result_no_len(ourp);
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
