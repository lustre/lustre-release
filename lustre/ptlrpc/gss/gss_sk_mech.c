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
 * Copyright (C) 2013, Trustees of Indiana University
 *
 * Copyright (c) 2014, Intel Corporation.
 *
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

struct sk_ctx {
};

static
__u32 gss_import_sec_context_sk(rawobj_t *inbuf, struct gss_ctx *gss_context)
{
	struct sk_ctx *sk_context;

	if (inbuf == NULL || inbuf->data == NULL)
		return GSS_S_FAILURE;

	OBD_ALLOC_PTR(sk_context);
	if (sk_context == NULL)
		return GSS_S_FAILURE;

	gss_context->internal_ctx_id = sk_context;
	CDEBUG(D_SEC, "successfully imported sk context\n");

	return GSS_S_COMPLETE;
}

static
__u32 gss_copy_reverse_context_sk(struct gss_ctx *gss_context_old,
				    struct gss_ctx *gss_context_new)
{
	struct sk_ctx *sk_context_old;
	struct sk_ctx *sk_context_new;

	OBD_ALLOC_PTR(sk_context_new);
	if (sk_context_new == NULL)
		return GSS_S_FAILURE;

	sk_context_old = gss_context_old->internal_ctx_id;
	memcpy(sk_context_new, sk_context_old, sizeof(*sk_context_new));
	gss_context_new->internal_ctx_id = sk_context_new;
	CDEBUG(D_SEC, "successfully copied reverse sk context\n");

	return GSS_S_COMPLETE;
}

static
__u32 gss_inquire_context_sk(struct gss_ctx *gss_context,
			       unsigned long *endtime)
{
	*endtime = 0;
	return GSS_S_COMPLETE;
}

static
__u32 gss_get_mic_sk(struct gss_ctx *gss_context,
		     int message_count,
		     rawobj_t *messages,
		     int iov_count,
		     lnet_kiov_t *iovs,
		     rawobj_t *token)
{
	token->data = NULL;
	token->len = 0;

	return GSS_S_COMPLETE;
}

static
__u32 gss_verify_mic_sk(struct gss_ctx *gss_context,
			int message_count,
			rawobj_t *messages,
			int iov_count,
			lnet_kiov_t *iovs,
			rawobj_t *token)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_wrap_sk(struct gss_ctx *gss_context, rawobj_t *gss_header,
		    rawobj_t *message, int message_buffer_length,
		    rawobj_t *token)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_unwrap_sk(struct gss_ctx *gss_context, rawobj_t *gss_header,
		      rawobj_t *token, rawobj_t *message)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_prep_bulk_sk(struct gss_ctx *gss_context,
			 struct ptlrpc_bulk_desc *desc)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_wrap_bulk_sk(struct gss_ctx *gss_context,
			 struct ptlrpc_bulk_desc *desc, rawobj_t *token,
			 int adj_nob)
{
	return GSS_S_COMPLETE;
}

static
__u32 gss_unwrap_bulk_sk(struct gss_ctx *gss_context,
			   struct ptlrpc_bulk_desc *desc,
			   rawobj_t *token, int adj_nob)
{
	return GSS_S_COMPLETE;
}

static
void gss_delete_sec_context_sk(void *internal_context)
{
	struct sk_ctx *sk_context = internal_context;

	OBD_FREE_PTR(sk_context);
}

int gss_display_sk(struct gss_ctx *gss_context, char *buf, int bufsize)
{
	return snprintf(buf, bufsize, "sk");
}

static struct gss_api_ops gss_sk_ops = {
	.gss_import_sec_context     = gss_import_sec_context_sk,
	.gss_copy_reverse_context   = gss_copy_reverse_context_sk,
	.gss_inquire_context        = gss_inquire_context_sk,
	.gss_get_mic                = gss_get_mic_sk,
	.gss_verify_mic             = gss_verify_mic_sk,
	.gss_wrap                   = gss_wrap_sk,
	.gss_unwrap                 = gss_unwrap_sk,
	.gss_prep_bulk              = gss_prep_bulk_sk,
	.gss_wrap_bulk              = gss_wrap_bulk_sk,
	.gss_unwrap_bulk            = gss_unwrap_bulk_sk,
	.gss_delete_sec_context     = gss_delete_sec_context_sk,
	.gss_display                = gss_display_sk,
};

static struct subflavor_desc gss_sk_sfs[] = {
	{
		.sf_subflavor   = SPTLRPC_SUBFLVR_SKI,
		.sf_qop         = 0,
		.sf_service     = SPTLRPC_SVC_INTG,
		.sf_name        = "ski"
	},
	{
		.sf_subflavor   = SPTLRPC_SUBFLVR_SKPI,
		.sf_qop         = 0,
		.sf_service     = SPTLRPC_SVC_PRIV,
		.sf_name        = "skpi"
	},
};

/*
 * currently we leave module owner NULL
 */
static struct gss_api_mech gss_sk_mech = {
	.gm_owner       = NULL, /*THIS_MODULE, */
	.gm_name        = "sk",
	.gm_oid         = (rawobj_t) {
		12,
		"\053\006\001\004\001\311\146\215\126\001\000\001",
	},
	.gm_ops         = &gss_sk_ops,
	.gm_sf_num      = 2,
	.gm_sfs         = gss_sk_sfs,
};

int __init init_sk_module(void)
{
	int status;

	status = lgss_mech_register(&gss_sk_mech);
	if (status)
		CERROR("Failed to register sk gss mechanism!\n");

	return status;
}

void cleanup_sk_module(void)
{
	lgss_mech_unregister(&gss_sk_mech);
}
