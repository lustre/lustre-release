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
#include <lustre_nodemap.h>
#include <upcall_cache.h>
#include <lustre_gssiam.h>

#include "../ptlrpc_internal.h"
#include "gss_internal.h"
#include "gss_api.h"
#include "gss_err.h"

static void gssiam_delete_sec_context(void *internal_ctx_id)
{
	struct gss_svc_ctx *ctx = internal_ctx_id;
	struct lu_nodemap *nodemap;

	nodemap = xchg(&ctx->gsc_gssiam_nodemap, NULL);
	if (nodemap)
		nodemap_putref(nodemap);
}

static struct gss_api_ops gssiam_ops = {
	.gss_delete_sec_context = gssiam_delete_sec_context,
};

static struct gss_api_mech gssiam_mech = {
	.gm_owner = NULL,
	.gm_name  = "gssiam",
	.gm_ops   = &gssiam_ops,
};

static int gssiam_update_nodemap_identity(const char *nm_name,
				  const struct lustre_gssiam_info *gssiam_info)
{
	char *identity;
	int len;
	const char *principal = gssiam_info->lii_desc.lid_principal ?
				gssiam_info->lii_desc.lid_principal : "";
	const char *subdir = gssiam_info->lii_desc.lid_subdir ?
			     gssiam_info->lii_desc.lid_subdir : "";
	const char *auth_str = "deny";
	int rc;

	if (gssiam_info->lii_auth_permission & GSSIAM_AUTH_RW)
		auth_str = "rw";
	else if (gssiam_info->lii_auth_permission & GSSIAM_AUTH_RO)
		auth_str = "ro";
	else if (gssiam_info->lii_auth_permission & GSSIAM_AUTH_EXPIRED)
		auth_str = "expired";

	len = strlen(principal) + strlen(subdir) + strlen(auth_str) + 3;
	OBD_ALLOC(identity, len);
	if (!identity)
		return -ENOMEM;

	snprintf(identity, len, "%s:%s:%s", principal, subdir,
		 auth_str);
	rc = nodemap_set_identity(nm_name, identity);
	OBD_FREE(identity, len);
	return rc;
}

/**
 * gssiam_get_nodemap() - Find or create nodemap for a GSSIAM connection
 * @target:	OBD device.
 * @gssiam_info: GSSIAM info (Project ID and options).
 *
 * This function handles the lifecycle of GSSIAM-specific nodemaps.
 * It first ensures the "gssiam" parent nodemap exists (creating and
 * hardening it if necessary). It then looks up or creates a unique
 * nodemap for the specific IAM identity/token and updates its policy
 * (Project ID, RO/RW status, and Fileset) to match the IAM policy.
 *
 * Return: pointer to struct lu_nodemap on success,
 * or ERR_PTR(rc) on failure.
 */
static struct lu_nodemap *gssiam_get_nodemap(struct obd_device *target,
				   const struct lustre_gssiam_info *gssiam_info)
{
	char nm_name[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	char add_name[LUSTRE_NODEMAP_NAME_LENGTH + 16];
	const char *subdir = gssiam_info->lii_desc.lid_subdir;
	struct lu_nodemap *nodemap;
	int rc;

	/*
	 * If dynamically created, it inherits from 'default'. To prevent
	 * unauthenticated clients or GSSIAM clients from accidentally
	 * inheriting permissive 'default' access, we explicitly lock down
	 * the 'gssiam' parent nodemap upon creation.
	 */
	nodemap = nodemap_lookup_unlocked("gssiam");
	if (IS_ERR(nodemap)) {
		rc = nodemap_add("default/gssiam", true);
		if (rc == 0) {
			rc = nodemap_set_gssiam_managed("gssiam", true);
			if (rc)
				return ERR_PTR(rc);
			rc = nodemap_set_allow_root("gssiam", false);
			if (rc)
				return ERR_PTR(rc);
			rc = nodemap_set_trust_client_ids("gssiam", false);
			if (rc)
				return ERR_PTR(rc);
			/* Allow child dynamic nodemaps to raise admin privileges
			 * (allow_root) when authorized. By default, allow_root is
			 * false on the parent so rootsquash is enforced.
			 */
			rc = nodemap_set_raise_privs("gssiam",
						     NODEMAP_RAISE_PRIV_ADMIN,
						     NODEMAP_RBAC_NONE);
			if (rc)
				return ERR_PTR(rc);
		} else if (rc != -EEXIST) {
			return ERR_PTR(rc);
		}
	} else {
		nodemap_putref(nodemap);
	}

	gssiam_nodemap_name(nm_name, sizeof(nm_name),
			    gssiam_info->lii_desc.lid_token,
			    gssiam_info->lii_desc.lid_token_len, subdir,
			    gssiam_info->lii_desc.lid_projid,
			    gssiam_info->lii_auth_permission);

	nodemap = nodemap_lookup_unlocked(nm_name);
	if (IS_ERR(nodemap)) {
		/* Create as dynamic child */
		snprintf(add_name, sizeof(add_name), "gssiam/%s", nm_name);
		rc = nodemap_add(add_name, true);
		if (rc == 0 || rc == -EEXIST) {
			nodemap = nodemap_lookup_unlocked(nm_name);
			if (IS_ERR(nodemap)) {
				CERROR("%s: failed nodemap %s: rc = %ld\n",
				       target->obd_name, nm_name,
				       PTR_ERR(nodemap));
				return nodemap;
			}
		} else {
			CERROR("%s: add nodemap failed : rc = %d\n",
			       target->obd_name, rc);
			return ERR_PTR(rc);
		}
	}

	rc = gssiam_update_nodemap_identity(nm_name, gssiam_info);
	if (rc) {
		/* Let's ignore the identity update failure, though
		 * lctl get_param nodemap may not retrieve the real
		 * identity.
		 */
		CWARN("%s: failed to update identity on nodemap %s: rc = %d\n",
		      target->obd_name, nm_name, rc);
	}

	/*
	 * The gssiam_info contains the latest truth obtained from the
	 * GSSIAM authentication process (either from upcall or cache).
	 * Updating the nodemap here ensures that the connection's
	 * permissions (RO/RW) and resource attribution (ProjID) are
	 * perfectly synchronized with the central IAM policy.
	 */
	rc = nodemap_gssiam_attrs_update(nm_name,
					 gssiam_info->lii_desc.lid_projid,
					 (gssiam_info->lii_auth_permission &
					  GSSIAM_AUTH_RO) != 0, false);
	if (rc) {
		CERROR("%s: failed to update gssiam on nodemap %s: rc = %d\n",
		       target->obd_name, nm_name, rc);
		GOTO(out_put, rc);
	}

	/* Enforce the fileset specified by the IAM policy */
	if (subdir && strlen(subdir) > 0)
		rc = nodemap_fileset_add(nm_name, subdir, false,
					 false);
	else
		rc = nodemap_fileset_clear(nm_name, false);

	if (rc && rc != -EPERM && rc != -EEXIST) {
		CERROR("%s: failed to set fileset on nodemap %s: rc = %d\n",
		       target->obd_name, nm_name, rc);
		GOTO(out_put, rc);
	} else if (rc == -EPERM || rc == -EEXIST) {
		/* Fallback to the secure, inherited parent fileset if the
		 * client's requested fileset is broader (-EPERM) or different
		 * from the pre-existing inherited fileset (-EEXIST).
		 */
		rc = 0;
	}

	CDEBUG(D_SEC, "projid %u auth_perm 0x%x subdir %s\n",
	       gssiam_info->lii_desc.lid_projid,
	       gssiam_info->lii_auth_permission,
	       subdir ? subdir : "none");
out_put:
	if (rc) {
		nodemap_putref(nodemap);
		nodemap = ERR_PTR(rc);
	}

	return nodemap;
}

static void gssiam_ctx_install_nodemap(struct gss_svc_reqctx *grctx,
				       struct obd_export *exp)
{
	struct lu_nodemap *nodemap;

	nodemap = xchg(&grctx->src_ctx->gsc_gssiam_nodemap, NULL);
	if (!nodemap)
		return;

	nodemap_export_refresh(nodemap, exp);

	/*
	 * The nodemap is looked up and referenced during the SEC_CTX_INIT
	 * RPC (gssiam_handle_init()) and temporarily stored in the server
	 * context (gsc_gssiam_nodemap).
	 *
	 * When the subsequent CONNECT RPC arrives, we attach this nodemap
	 * to the client's export here. Since the export now holds its own
	 * reference to the nodemap (via nodemap_export_refresh), we drop
	 * the temporary reference held by the security context.
	 */
	nodemap_putref(nodemap);
}

/* Install the security context to the export */
int gssiam_install_ctx(struct obd_export *exp, struct ptlrpc_request *req)
{
	struct gss_svc_reqctx *grctx;
	struct gss_rsc *rscp;

	ENTRY;

	/*
	 * In GSSIAM's Hybrid RPC Model, only handshake (SEC_CTX_INIT) and
	 * Connect RPCs are GSS-framed. All other RPCs (regular Data/Metadata
	 * RPCs) use Null framing for performance.
	 *
	 * Skip static Null-framed service contexts (&gssiam_svc_ctx). Note that
	 * "Null-framed" here refers to unframed GSSIAM Data/Metadata RPCs (i.e.
	 * RPCs other than SEC_CTX_INIT & Connect), not the Null security
	 * flavor.
	 *
	 * Calling gss_svc_ctx2reqctx() on the 24-byte shared gssiam_svc_ctx
	 * would calculate an invalid container_of() pointer and dereference
	 * random memory in .data when inspecting grctx->src_ctx.
	 */
	if (!req->rq_svc_ctx || gssiam_is_null_svc_ctx(req->rq_svc_ctx))
		RETURN(0);

	grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);
	if (!grctx->src_ctx)
		RETURN(0);

	if (!grctx->src_ctx->gsc_gssiam_nodemap)
		RETURN(0);

	gssiam_ctx_install_nodemap(grctx, exp);

	rscp = container_of(grctx->src_ctx, struct gss_rsc, sc_ctx);
	/*
	 * The GSSIAM gss_svc_ctx is highly ephemeral. Once the identity is
	 * pinned to the export (the connection) above, the handshake is
	 * complete. We immediately invalidate the context so the cache
	 * garbage collector can free it via our GSSIAM GSS mechanism.
	 */
	upcall_cache_update_entry(rsccache, rscp->sc_uc_entry, 0,
				  UC_CACHE_INVALID);
	RETURN(0);
}

static int gssiam_verify_target(struct obd_device *target,
			  struct lustre_gssiam_desc *lid,
			  struct lustre_gssiam_info **gssiam_info,
			  time64_t *gssiam_expire, __u32 *major)
{
	/* XXX following patches will reset other values */
	*major = GSS_S_FAILURE;
	return -EOPNOTSUPP;
}

int gssiam_handle_init(struct ptlrpc_request *req, struct gss_svc_reqctx *grctx,
		       struct obd_device *target, rawobj_t *in_token,
		       __u32 **secdata, __u32 *seclen)
{
	rawobj_t subdir_obj = RAWOBJ_EMPTY;
	rawobj_t options_obj = RAWOBJ_EMPTY;
	struct lustre_gssiam_desc *lid = NULL;
	struct lustre_gssiam_info *gssiam_info = NULL;
	struct gss_rsc rsc_key;
	__u64 key_hash;
	struct gss_rsc *rscp = NULL;
	int replen = sizeof(struct ptlrpc_body);
	struct ptlrpc_reply_state *rs;
	struct gss_rep_header *rephdr;
	__u32 major = GSS_S_FAILURE;
	time64_t gssiam_expire = ktime_get_seconds() +
				 rsccache->uc_entry_expire;
	struct lu_nodemap *nodemap;
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

	rc = gssiam_verify_target(target, lid, &gssiam_info, &gssiam_expire,
				  &major);
	if (rc) {
		CERROR("%s: GSSIAM verify failed: rc = %d\n", target->obd_name,
		       rc);
		GOTO(out, rc);
	}

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

	/* Locate or Create Nodemap */
	nodemap = gssiam_get_nodemap(target, gssiam_info);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("%s: failed to get/create nodemap for GSSIAM: rc = %d\n",
		       target->obd_name, rc);
		GOTO(out, rc);
	}

	if (rscp->sc_ctx.gsc_gssiam_nodemap)
		nodemap_putref(rscp->sc_ctx.gsc_gssiam_nodemap);
	rscp->sc_ctx.gsc_gssiam_nodemap = nodemap;

	if (rscp->sc_ctx.gsc_nm_name == NULL) {
		OBD_ALLOC(rscp->sc_ctx.gsc_nm_name,
			  LUSTRE_NODEMAP_NAME_LENGTH + 1);
		if (!rscp->sc_ctx.gsc_nm_name) {
			rc = -ENOMEM;
			CERROR("%s: failed to alloc nodemap name for GSSIAM: rc = %d\n",
			       target->obd_name, rc);
			GOTO(out, rc);
		}
		strscpy(rscp->sc_ctx.gsc_nm_name, nodemap->nm_name,
			LUSTRE_NODEMAP_NAME_LENGTH + 1);
	}

	upcall_cache_update_entry(rsccache, rscp->sc_uc_entry, gssiam_expire,
				  0);

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
	if (gssiam_info) {
		OBD_FREE(gssiam_info->lii_desc.lid_token,
			 gssiam_info->lii_desc.lid_token_len);
		OBD_FREE_STR(gssiam_info->lii_desc.lid_subdir);
		OBD_FREE_STR(gssiam_info->lii_desc.lid_principal);
		OBD_FREE_PTR(gssiam_info);
	}
	return rc;
}
