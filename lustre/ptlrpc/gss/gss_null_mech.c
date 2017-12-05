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
 * Copyright (C) 2013, 2015, Trustees of Indiana University
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 * Author: Jeremy Filizetti <jfilizet@iu.edu>
 * Author: Andrew Korty <ajk@iu.edu>
 */

#define DEBUG_SUBSYSTEM S_SEC
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/mutex.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"
#include "gss_asn1.h"

struct null_ctx {
	__u64 nc_token;
};

static
__u32 gss_import_sec_context_null(rawobj_t *inbuf, struct gss_ctx *gss_context)
{
	struct null_ctx *null_context;

	if (inbuf == NULL || inbuf->data == NULL ||
	    inbuf->len != sizeof(*null_context)) {
		CDEBUG(D_SEC, "Invalid input buffer for null context\n");
		return GSS_S_FAILURE;
	}

	OBD_ALLOC_PTR(null_context);
	if (null_context == NULL)
		return GSS_S_FAILURE;

	memcpy(&null_context->nc_token, inbuf->data, inbuf->len);

	gss_context->internal_ctx_id = null_context;
	CDEBUG(D_SEC, "successfully imported null context\n");

	return GSS_S_COMPLETE;
}

static
__u32 gss_copy_reverse_context_null(struct gss_ctx *gss_context_old,
				    struct gss_ctx *gss_context_new)
{
	struct null_ctx *null_context_old;
	struct null_ctx *null_context_new;

	OBD_ALLOC_PTR(null_context_new);
	if (null_context_new == NULL)
		return GSS_S_FAILURE;

	null_context_old = gss_context_old->internal_ctx_id;
	memcpy(null_context_new, null_context_old, sizeof(*null_context_new));
	gss_context_new->internal_ctx_id = null_context_new;
	CDEBUG(D_SEC, "successfully copied reverse null context\n");

	return GSS_S_COMPLETE;
}

static
__u32 gss_inquire_context_null(struct gss_ctx *gss_context,
			       time64_t *endtime)
{
	/* quick timeout for testing purposes */
	*endtime = ktime_get_real_seconds() + 60;
	return GSS_S_COMPLETE;
}

static
__u32 gss_wrap_null(struct gss_ctx *gss_context, rawobj_t *gss_header,
		    rawobj_t *message, int message_buffer_length,
		    rawobj_t *token)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_unwrap_null(struct gss_ctx *gss_context, rawobj_t *gss_header,
		      rawobj_t *token, rawobj_t *message)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_prep_bulk_null(struct gss_ctx *gss_context,
			 struct ptlrpc_bulk_desc *desc)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_wrap_bulk_null(struct gss_ctx *gss_context,
			 struct ptlrpc_bulk_desc *desc, rawobj_t *token,
			 int adj_nob)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_unwrap_bulk_null(struct gss_ctx *gss_context,
			   struct ptlrpc_bulk_desc *desc,
			   rawobj_t *token, int adj_nob)
{
	return GSS_S_COMPLETE;
}

static
void gss_delete_sec_context_null(void *internal_context)
{
	struct null_ctx *null_context = internal_context;

	OBD_FREE_PTR(null_context);
}

int gss_display_null(struct gss_ctx *gss_context, char *buf, int bufsize)
{
	return snprintf(buf, bufsize, "null");
}

static
__u32 gss_get_mic_null(struct gss_ctx *gss_context, int message_count,
		       rawobj_t *messages, int iov_count, lnet_kiov_t *iovs,
		       rawobj_t *token)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_verify_mic_null(struct gss_ctx *gss_context, int message_count,
			  rawobj_t *messages, int iov_count, lnet_kiov_t *iovs,
			  rawobj_t *token)
{
	return GSS_S_COMPLETE;
}

static struct gss_api_ops gss_null_ops = {
	.gss_import_sec_context     = gss_import_sec_context_null,
	.gss_copy_reverse_context   = gss_copy_reverse_context_null,
	.gss_inquire_context        = gss_inquire_context_null,
	.gss_get_mic                = gss_get_mic_null,
	.gss_verify_mic             = gss_verify_mic_null,
	.gss_wrap                   = gss_wrap_null,
	.gss_unwrap                 = gss_unwrap_null,
	.gss_prep_bulk              = gss_prep_bulk_null,
	.gss_wrap_bulk              = gss_wrap_bulk_null,
	.gss_unwrap_bulk            = gss_unwrap_bulk_null,
	.gss_delete_sec_context     = gss_delete_sec_context_null,
	.gss_display                = gss_display_null,
};

static struct subflavor_desc gss_null_sfs[] = {
	{
		.sf_subflavor   = SPTLRPC_SUBFLVR_GSSNULL,
		.sf_qop         = 0,
		.sf_service     = SPTLRPC_SVC_NULL,
		.sf_name        = "gssnull"
	},
};

static struct gss_api_mech gss_null_mech = {
	/* .gm_owner uses default NULL value for THIS_MODULE */
	.gm_name        = "gssnull",
	.gm_oid         = (rawobj_t) {
		12,
		"\053\006\001\004\001\311\146\215\126\001\000\000"
	},
	.gm_ops         = &gss_null_ops,
	.gm_sf_num      = 1,
	.gm_sfs         = gss_null_sfs,
};

int __init init_null_module(void)
{
	int status;

	status = lgss_mech_register(&gss_null_mech);
	if (status)
		CERROR("Failed to register null gss mechanism!\n");

	return status;
}

void cleanup_null_module(void)
{
	lgss_mech_unregister(&gss_null_mech);
}
