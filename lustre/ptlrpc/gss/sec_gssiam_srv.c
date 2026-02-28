// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google
 *
 * GSSIAM Security Policy for Lustre server
 *
 */
#define DEBUG_SUBSYSTEM S_SEC

#include <linux/module.h>
#include <linux/string.h>
#include <linux/random.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_sec.h>
#include <upcall_cache.h>
#include <lustre_gssiam.h>

#include "../ptlrpc_internal.h"
#include "gss_internal.h"
#include "gss_api.h"
#include "gss_err.h"

static void gssiam_delete_sec_context(void *internal_ctx_id)
{
}

static struct gss_api_ops gssiam_ops = {
	.gss_delete_sec_context = gssiam_delete_sec_context,
};

static struct gss_api_mech gssiam_mech = {
	.gm_owner = NULL,
	.gm_name  = "gssiam",
	.gm_ops   = &gssiam_ops,
};

int gssiam_handle_init(struct ptlrpc_request *req, struct gss_svc_reqctx *grctx,
		       struct obd_device *target, rawobj_t *in_token,
		       __u32 **secdata, __u32 *seclen)
{
	rawobj_t subdir_obj = RAWOBJ_EMPTY;
	rawobj_t options_obj = RAWOBJ_EMPTY;
	struct lustre_gssiam_desc *lid = NULL;
	struct gss_rsc rsc_key;
	__u64 key_hash;
	struct gss_rsc *rscp = NULL;
	int replen = sizeof(struct ptlrpc_body);
	struct ptlrpc_reply_state *rs;
	struct gss_rep_header *rephdr;
	__u32 major = GSS_S_FAILURE;
	int rc;

	if (rawobj_extract(&subdir_obj, secdata, seclen)) {
		rc = -EINVAL;
		major = GSS_S_DEFECTIVE_TOKEN;
		CDEBUG(D_SEC, "%s: can't extract subdirectory: rc = %d\n",
		       target->obd_name, rc);
		GOTO(out, rc);
	}

	if (rawobj_extract(&options_obj, secdata, seclen)) {
		rc = -EINVAL;
		major = GSS_S_DEFECTIVE_TOKEN;
		CDEBUG(D_SEC, "%s: can't extract client options: rc = %d\n",
		       target->obd_name, rc);
		GOTO(out, rc);
	}

	if (options_obj.len != sizeof(__u32)) {
		rc = -EINVAL;
		major = GSS_S_DEFECTIVE_TOKEN;
		CDEBUG(D_SEC,
		       "%s: invalid client options: got %u expect %zu: rc = %d\n",
		       target->obd_name, options_obj.len, sizeof(__u32), rc);
		GOTO(out, rc);
	}

	if (in_token->len > GSSIAM_MAX_TOKEN_LEN) {
		rc = -EINVAL;
		major = GSS_S_DEFECTIVE_TOKEN;
		CDEBUG(D_SEC,
		       "%s: in_token length too long (%u > %u): rc = %d\n",
		       target->obd_name, in_token->len, GSSIAM_MAX_TOKEN_LEN, rc);
		GOTO(out, rc);
	}

	if (subdir_obj.len > PATH_MAX) {
		rc = -EINVAL;
		major = GSS_S_DEFECTIVE_TOKEN;
		CDEBUG(D_SEC,
		       "%s: subdirectory path too long (%u > %u): rc = %d\n",
		       target->obd_name, subdir_obj.len, PATH_MAX, rc);
		GOTO(out, rc);
	}

	OBD_ALLOC_PTR(lid);
	if (!lid)
		GOTO(out, rc = -ENOMEM);

	lid->lid_options = le32_to_cpu(*(__le32 *)options_obj.data);
	lid->lid_token_len = in_token->len;
	if (lid->lid_token_len > 0) {
		OBD_ALLOC(lid->lid_token, lid->lid_token_len);
		if (!lid->lid_token)
			GOTO(out, rc = -ENOMEM);
		memcpy(lid->lid_token, in_token->data, lid->lid_token_len);
	}

	OBD_ALLOC(lid->lid_subdir, subdir_obj.len + 1);
	if (!lid->lid_subdir)
		GOTO(out, rc = -ENOMEM);

	memcpy(lid->lid_subdir, subdir_obj.data, subdir_obj.len);

	/*
	 * XXX verify GSSIAM in the following patches
	 */

	/* Create ephemeral context */
	memset(&rsc_key, 0, sizeof(rsc_key));
#ifdef HAVE_GET_RANDOM_U32_AND_U64
	key_hash = get_random_u64();
#else
	key_hash = ((__u64)prandom_u32() << 32) | prandom_u32();
#endif
	/* Use hash as handle */
	if (rawobj_alloc(&rsc_key.sc_handle, (char *)&key_hash,
			 sizeof(key_hash)))
		GOTO(out, rc = -ENOMEM);

	rscp = rsc_entry_get(rsccache, &rsc_key);
	rawobj_free(&rsc_key.sc_handle);
	if (IS_ERR(rscp)) {
		rc = PTR_ERR(rscp);
		CERROR("%s: failed to get rsc for GSSIAM: rc = %d\n",
		       target->obd_name, rc);
		GOTO(out, rc);
	}

	if (!rscp->sc_ctx.gsc_mechctx) {
		struct gss_ctx *gctx;

		OBD_ALLOC_PTR(gctx);
		if (!gctx) {
			rc = -ENOMEM;
			CERROR("%s: failed to alloc gctx for GSSIAM: rc = %d\n",
			       target->obd_name, rc);
			GOTO(out, rc);
		}

		gctx->mech_type = lgss_mech_get(&gssiam_mech);
		gctx->internal_ctx_id = &rscp->sc_ctx;
		rscp->sc_ctx.gsc_mechctx = gctx;
	}

	/* Attach to request context */
	upcall_cache_get_entry_raw(rscp->sc_uc_entry);
	grctx->src_ctx = &rscp->sc_ctx;
	grctx->src_init = 1;

	/* Pack reply */
	rc = lustre_pack_reply_v2(req, 1, &replen, NULL, 0);
	if (rc) {
		CERROR("%s: failed to pack GSSIAM reply: rc = %d\n",
		       target->obd_name, rc);
		GOTO(out, rc);
	}

	rs = req->rq_reply_state;
	rephdr = lustre_msg_buf(rs->rs_repbuf, 0, 0);
	rephdr->gh_version = PTLRPC_GSS_VERSION;
	rephdr->gh_flags = 0;
	rephdr->gh_proc = PTLRPC_GSS_PROC_INIT;
	rephdr->gh_major = GSS_S_COMPLETE;
	rephdr->gh_minor = 0;
	rephdr->gh_seqwin = GSS_SEQ_WIN;
	rephdr->gh_handle.len = sizeof(key_hash);
	memcpy(rephdr->gh_handle.data, &key_hash, sizeof(key_hash));

	rs->rs_repdata_len = lustre_packed_msg_size(rs->rs_repbuf);

	req->rq_reqmsg = lustre_msg_buf(req->rq_reqbuf, 1, 0);
	req->rq_reqlen = lustre_msg_buflen(req->rq_reqbuf, 1);

out:
	if (!IS_ERR_OR_NULL(rscp)) {
		if (rc)
			UC_CACHE_SET_INVALID(rscp->sc_uc_entry);
		rsc_entry_put(rsccache, rscp);
	}
	if (rc) {
		rc = gss_pack_err_notify(req, major, 0);
		if (!rc)
			rc = SECSVC_COMPLETE;
		else
			rc = SECSVC_DROP;
	} else {
		rc = SECSVC_OK;
	}

	if (lid) {
		OBD_FREE(lid->lid_token, lid->lid_token_len);
		OBD_FREE(lid->lid_subdir, subdir_obj.len + 1);
		OBD_FREE_PTR(lid);
	}
	return rc;
}
