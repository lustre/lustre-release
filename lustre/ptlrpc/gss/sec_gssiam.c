// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google
 *
 * GSSIAM Security Policy for Lustre
 *
 * Overview:
 * ---------
 * The GSSIAM (Identity Access Management) security flavor provides a
 * high-performance, identity-based authentication and authorization mechanism
 * for Lustre. It utilizes a Hybrid RPC Model designed to balance strong
 * initial authentication with minimal overhead for data traffic.
 *
 * Hybrid RPC Model:
 * -----------------
 * 1. Handshake (GSS Framing): The initial security context establishment
 *    (SEC_CTX_INIT) uses GSS framing to securely transport the client's GSSIAM
 *    identity (Token and Subdirectory/Fileset).
 * 2. Data RPCs (Null Framing): Once the context is established and pinned to
 *    the server-side export, all subsequent RPCs (including metadata and bulk
 *    data) use standard Null security framing. This eliminates GSS header
 *    (gss_svc_accept()) and signing overhead (gss_alloc_reqbuf_intg(),
 *    gss_cli_ctx_sign()) for every request, achieving performance parity with
 *    unauthenticated traffic while maintaining session-based security.
 *
 * Nodemap Integration:
 * --------------------
 * GSSIAM integrates with the Lustre Nodemap framework to provide
 * access control (UID/GID/PROJID squashing, RBAC, and Fileset
 * restrictions) by mapping verified client identities to server-side
 * nodemaps.
 *
 * Security Context Lifecycle:
 * ---------------------------
 * - Mount/Connect: The client triggers an upcall to retrieve the GSSIAM token
 *   and subdirectory from its local environment.
 * - Context Init: The client sends a SEC_CTX_INIT RPC. The server executes
 *   an external upcall (l_gssiam_upcall) to verify the token and permissions.
 * - Installation: Upon success, the GSSIAM info is installed onto the
 *   server-side export.
 * - Verification: Subsequent RPCs are verified against the established export
 *   context.
 */
#define DEBUG_SUBSYSTEM S_SEC

#include <linux/module.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/random.h>
#include <linux/user_namespace.h>
#include <linux/uidgid.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_sec.h>
#include <lustre_mds.h>
#include <lustre_req_layout.h>
#include <upcall_cache.h>
#include <lustre_gssiam.h>

#include "../ptlrpc_internal.h"
#include "gss_internal.h"
#include "gss_err.h"
#include <lprocfs_status.h>

static struct ptlrpc_sec_policy sptlrpc_gssiam_policy;
static struct upcall_cache *gssiam_upcall_cache;

static inline __u64 gssiam_sec_cache_key(struct ptlrpc_sec *sec)
{
	if (sec && sec->ps_gssiam) {
		const char *p = sec->ps_gssiam->lgmi_principal;

		if (p && *p)
			return lustre_hash_fnv_1a_64(p, strlen(p));
		return (__u64)sec->ps_gssiam->lgmi_loginuid;
	}
	return 0;
}

static struct kobject *gssiam_kobj;

struct gssiam_sec {
	struct ptlrpc_sec		gis_base;
	spinlock_t			gis_lock;
	struct mutex			gis_mutex;
	struct gssiam_cli_ctx __rcu	*gis_ctx;
};

struct gssiam_cli_ctx {
	struct ptlrpc_cli_ctx	gicc_base;
	struct lustre_gssiam_desc	gicc_lid;
	struct rawobj_s		gicc_ich_handle;
};

static inline struct gssiam_sec *gss_sec2gssiam(struct ptlrpc_sec *sec)
{
	return container_of(sec, struct gssiam_sec, gis_base);
}

static inline struct gssiam_cli_ctx *gss_ctx2gssiam(struct ptlrpc_cli_ctx *ctx)
{
	return container_of(ctx, struct gssiam_cli_ctx, gicc_base);
}

/* Upcall Cache Operations */
static void gssiam_entry_init(struct upcall_cache_entry *entry, void *args)
{
	struct ptlrpc_sec *sec = args;

	entry->u.gssiam.gd_uc_entry = entry;
	entry->u.gssiam.gd_token = NULL;
	entry->u.gssiam.gd_token_len = 0;
	entry->u.gssiam.gd_subdir = NULL;
	entry->u.gssiam.gd_options = 0;
	entry->u.gssiam.gd_auth_permission = GSSIAM_AUTH_DENY;
	if (sec && sec->ps_gssiam)
		entry->u.gssiam.gd_loginuid = sec->ps_gssiam->lgmi_loginuid;
	else
		entry->u.gssiam.gd_loginuid = from_kuid(&init_user_ns,
							INVALID_UID);

	if (sec && sec->ps_gssiam && sec->ps_gssiam->lgmi_principal) {
		OBD_STRDUP(entry->u.gssiam.gd_principal,
			   sec->ps_gssiam->lgmi_principal);
		if (!entry->u.gssiam.gd_principal)
			UC_CACHE_SET_INVALID(entry);
	} else {
		entry->u.gssiam.gd_principal = NULL;
	}
}

static void gssiam_entry_free(struct upcall_cache *cache,
			       struct upcall_cache_entry *entry)
{
	OBD_FREE_STR(entry->u.gssiam.gd_principal);
	OBD_FREE(entry->u.gssiam.gd_token,
		 entry->u.gssiam.gd_token_len);
	OBD_FREE_STR(entry->u.gssiam.gd_subdir);
}

static int gssiam_upcall_compare(struct upcall_cache *cache,
				  struct upcall_cache_entry *entry,
				  __u64 key, void *args)
{
	struct ptlrpc_sec *sec = args;
	const char *principal;
	const char *p1, *p2;

	if (entry->ue_key != key)
		return -1;

	if (!sec)
		return 0;

	if (!sec->ps_gssiam) {
		/* sec is not NULL, but ps_gssiam is not yet
		 * populated: no identity to match
		 */
		return -1;
	}

	if (entry->u.gssiam.gd_loginuid != sec->ps_gssiam->lgmi_loginuid)
		return -1;

	principal = sec->ps_gssiam->lgmi_principal;

	p1 = entry->u.gssiam.gd_principal ? entry->u.gssiam.gd_principal : "";
	p2 = principal ? principal : "";

	if (strcmp(p1, p2) != 0)
		return -1;

	return 0;
}

/*
 * gssiam_principal_match() - Compare a kernel principal string (p1) with a
 * downcall principal buffer (p2, of length len2).
 *
 * Note: len2 (data->idd_principal_len) includes the '\0' null terminator
 * (and any trailing '\0' padding), so we strip trailing '\0' bytes
 * before comparing lengths and content.
 */
static bool gssiam_principal_match(const char *p1, const char *p2,
				   size_t len2)
{
	size_t len1 = p1 ? strlen(p1) : 0;

	while (len2 > 0 && p2 && p2[len2 - 1] == '\0')
		len2--;

	return len1 == len2 && (len1 == 0 || memcmp(p1, p2, len1) == 0);
}

static int gssiam_downcall_compare(struct upcall_cache *cache,
				    struct upcall_cache_entry *entry,
				    __u64 key, void *args)
{
	struct gssiam_downcall_data *data = args;
	const char *p1, *p2;

	if (!data)
		return 0;

	if (entry->u.gssiam.gd_loginuid != data->idd_loginuid)
		return -1;

	p1 = entry->u.gssiam.gd_principal;
	p2 = (data->idd_principal_len > 0) ?  idd_principal(data) : NULL;

	if (!gssiam_principal_match(p1, p2, data->idd_principal_len))
		return -1;

	return 0;
}

static int gssiam_do_upcall(struct upcall_cache *cache,
			     struct upcall_cache_entry *entry)
{
	char *argv[7];
	char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/usr/sbin",
		NULL
	};
	char buf[32];
	char lbuf[32];
	int rc, argc = 0;

	snprintf(buf, sizeof(buf), "%llu", entry->ue_key);

	down_read(&cache->uc_upcall_rwsem);
	if (cache->uc_upcall[0] == '\0') {
		rc = -EINVAL;
		CERROR("%s: upcall path is empty: rc = %d\n",
		       cache->uc_name, rc);
		GOTO(out, rc);
	}

	argv[argc++] = cache->uc_upcall;
	if (entry->u.gssiam.gd_principal &&
	    strlen(entry->u.gssiam.gd_principal) > 0) {
		argv[argc++] = "-p";
		argv[argc++] = entry->u.gssiam.gd_principal;
	}

	snprintf(lbuf, sizeof(lbuf), "%u", entry->u.gssiam.gd_loginuid);
	argv[argc++] = "-l";
	argv[argc++] = lbuf;

	argv[argc++] = buf;
	argv[argc] = NULL;

	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (rc < 0)
		CERROR("%s: upcall %s %s failed: rc = %d\n",
		       cache->uc_name, argv[0], buf, rc);

out:
	up_read(&cache->uc_upcall_rwsem);
	return rc;
}

static int gssiam_parse_downcall(struct upcall_cache *cache,
				 struct upcall_cache_entry *entry,
				 void *args)
{
	struct gssiam_downcall_data *data = args;

	if (data->idd_token_len > 0) {
		OBD_ALLOC(entry->u.gssiam.gd_token, data->idd_token_len);
		if (!entry->u.gssiam.gd_token)
			return -ENOMEM;
		entry->u.gssiam.gd_token_len = data->idd_token_len;
		memcpy(entry->u.gssiam.gd_token, idd_token(data),
		       entry->u.gssiam.gd_token_len);
		entry->u.gssiam.gd_auth_permission = GSSIAM_AUTH_RW;
	} else {
		entry->u.gssiam.gd_auth_permission = GSSIAM_AUTH_DENY;
	}

	return 0;
}

static struct upcall_cache_ops gssiam_upcall_ops = {
	.init_entry	= gssiam_entry_init,
	.free_entry	= gssiam_entry_free,
	.upcall_compare	= gssiam_upcall_compare,
	.downcall_compare = gssiam_downcall_compare,
	.do_upcall	= gssiam_do_upcall,
	.parse_downcall	= gssiam_parse_downcall,
};

static inline bool gssiam_is_connect(struct ptlrpc_request *req)
{
	return req->rq_pill.rc_fmt == &RQF_CONNECT ||
	       req->rq_pill.rc_fmt == &RQF_MDS_CONNECT ||
	       req->rq_pill.rc_fmt == &RQF_OST_CONNECT;
}

/* client operations */
static void gssiam_ctx_die(struct ptlrpc_cli_ctx *ctx, int grace)
{
	struct gssiam_sec *gssiam = gss_sec2gssiam(ctx->cc_sec);
	bool put = false;

	spin_lock(&gssiam->gis_lock);
	if (rcu_dereference_protected(gssiam->gis_ctx,
				      lockdep_is_held(&gssiam->gis_lock)) ==
	    gss_ctx2gssiam(ctx)) {
		RCU_INIT_POINTER(gssiam->gis_ctx, NULL);
		put = true;
	}
	spin_unlock(&gssiam->gis_lock);
	if (put) {
		synchronize_rcu();
		sptlrpc_cli_ctx_put(ctx, 1);
	}
}

static
int gssiam_ctx_sign(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req)
{
	struct gssiam_cli_ctx *ictx = gss_ctx2gssiam(ctx);
	struct gss_header *ghdr;
	__u32 flags = 0;

	/* init ctx RPC does not need sign */
	if (req->rq_ctx_init) {
		req->rq_gss_framed = 1;
		return 0;
	}

	if (gssiam_is_connect(req))
		req->rq_gss_framed = 1;

	/* Non-connect RPC shares the same sign with NULL security */
	if (!req->rq_gss_framed)
		return null_ctx_sign_common(ctx, req, SPTLRPC_FLVR_GSSIAM);

	if (req->rq_pack_bulk)
		flags |= LUSTRE_GSS_PACK_BULK;
	if (req->rq_pack_udesc)
		flags |= LUSTRE_GSS_PACK_USER;

	ghdr = lustre_msg_buf(req->rq_reqbuf, 0, sizeof(*ghdr));
	if (!ghdr)
		return -EFAULT;

	ghdr->gh_version = PTLRPC_GSS_VERSION;
	ghdr->gh_sp = (__u8) ctx->cc_sec->ps_part;
	ghdr->gh_flags = flags;
	ghdr->gh_proc = PTLRPC_GSS_PROC_DATA;
	ghdr->gh_seq = 0;
	ghdr->gh_svc = SPTLRPC_SVC_NULL;
	ghdr->gh_handle.len = ictx->gicc_ich_handle.len;
	if (ictx->gicc_ich_handle.len)
		memcpy(ghdr->gh_handle.data, ictx->gicc_ich_handle.data,
		       ictx->gicc_ich_handle.len);

	req->rq_reqdata_len = lustre_shrink_msg(req->rq_reqbuf, 0,
					sizeof(*ghdr) + ghdr->gh_handle.len, 1);

	return 0;
}

static
int gssiam_ctx_verify(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req)
{
	struct lustre_msg *msg = req->rq_repdata;
	struct gss_rep_header *ghdr;
	int swabbed;
	int rc = 0;

	ENTRY;
	if (!req->rq_gss_framed)
		RETURN(null_ctx_verify(ctx, req));

	if (msg->lm_bufcount < 2 || msg->lm_bufcount > 4)
		RETURN(-EPROTO);

	swabbed = req_capsule_rep_need_swab(&req->rq_pill);

	ghdr = (struct gss_rep_header *)gss_swab_header(msg, 0, swabbed);
	if (!ghdr) {
		rc = -EPROTO;
		CERROR("%s: can't decode gss header: rc = %d\n",
		       ctx->cc_sec->ps_import->imp_obd->obd_name, rc);
		RETURN(rc);
	}

	if (ghdr->gh_handle.len > PTLRPC_GSS_MAX_HANDLE_SIZE) {
		rc = -EPROTO;
		CERROR("%s: GSSIAM handle len %u too large: rc = %d\n",
		       ctx->cc_sec->ps_import->imp_obd->obd_name,
		       ghdr->gh_handle.len, rc);
		RETURN(rc);
	}

	if (ghdr->gh_version != PTLRPC_GSS_VERSION) {
		rc = -EPROTO;
		CERROR("%s: gss version %u mismatch, expect %u: rc = %d\n",
		       ctx->cc_sec->ps_import->imp_obd->obd_name,
		       ghdr->gh_version, PTLRPC_GSS_VERSION, rc);
		RETURN(rc);
	}

	if (ghdr->gh_proc == PTLRPC_GSS_PROC_ERR) {
		struct gss_err_header *errhdr = (struct gss_err_header *)ghdr;

		if (req->rq_ctx_init) {
			if ((errhdr->gh_major == GSS_S_UNAVAILABLE ||
			     errhdr->gh_major == GSS_S_CREDENTIALS_EXPIRED ||
			     errhdr->gh_major == GSS_S_NO_CONTEXT)) {
				sptlrpc_cli_ctx_expire(ctx);
				RETURN(-EAGAIN);
			}
			rc = -EPERM;
			CERROR("%s: GSSIAM init failed: %u/%u: rc = %d\n",
			       ctx->cc_sec->ps_import->imp_obd->obd_name,
			       errhdr->gh_major, errhdr->gh_minor, rc);
			sptlrpc_cli_ctx_expire(ctx);
			RETURN(rc);
		}

		if (errhdr->gh_major == GSS_S_NO_CONTEXT) {
			CWARN("%s: ctxt from %s (uid %u) unknown, retrying: rc = %d\n",
			      ctx->cc_sec->ps_import->imp_obd->obd_name,
			      req->rq_import ?
			      obd_import_nid2str(req->rq_import) : "0@<0:0>",
			      ctx->cc_vcred.vc_uid, -EAGAIN);

			sptlrpc_cli_ctx_expire(ctx);

			if (req->rq_import) {
				spin_lock(&req->rq_import->imp_lock);
				set_bit(IMPF_FORCE_VERIFY,
					req->rq_import->imp_flags);
				spin_unlock(&req->rq_import->imp_lock);
			}

			RETURN(-EAGAIN);
		}
		RETURN(-EACCES);
	}

	if (req->rq_ctx_init && !req->rq_early) {
		if (ghdr->gh_proc != PTLRPC_GSS_PROC_INIT) {
			rc = -EPROTO;
			CERROR("%s: unexpected proc %u: rc = %d\n",
			       ctx->cc_sec->ps_import->imp_obd->obd_name,
			       ghdr->gh_proc, rc);
			RETURN(rc);
		}

		if (ghdr->gh_major != GSS_S_COMPLETE) {
			rc = -EPERM;
			CERROR("%s: GSSIAM init failed: %u/%u: rc = %d\n",
			       ctx->cc_sec->ps_import->imp_obd->obd_name,
			       ghdr->gh_major, ghdr->gh_minor, rc);
			sptlrpc_cli_ctx_expire(ctx);
			RETURN(rc);
		}

		if (ghdr->gh_handle.len > 0) {
			struct gssiam_cli_ctx *ictx = gss_ctx2gssiam(ctx);

			if (rawobj_from_netobj_alloc(&ictx->gicc_ich_handle,
						     &ghdr->gh_handle))
				RETURN(-ENOMEM);
		}
	} else if (ghdr->gh_proc != PTLRPC_GSS_PROC_DATA) {
		rc = -EPROTO;
		CERROR("%s: unexpected proc %u: rc = %d\n",
		       ctx->cc_sec->ps_import->imp_obd->obd_name,
		       ghdr->gh_proc, rc);
		RETURN(rc);
	}

	req->rq_repmsg = lustre_msg_buf(msg, 1, 0);
	req->rq_replen = msg->lm_buflens[1];
	RETURN(rc);
}

static struct ptlrpc_ctx_ops gssiam_ctx_ops = {
	.sign		= gssiam_ctx_sign,
	.verify		= gssiam_ctx_verify,
	.die		= gssiam_ctx_die,
};

static void gssiam_destroy_sec(struct ptlrpc_sec *sec)
{
	struct gssiam_sec *gssiam = gss_sec2gssiam(sec);

	LASSERT(atomic_read(&sec->ps_nctx) == 0);
	LASSERT(atomic_read(&sec->ps_refcount) == 0);
	LASSERT(rcu_access_pointer(gssiam->gis_ctx) == NULL);

	if (sec->ps_import) {
		class_import_put(sec->ps_import);
		sec->ps_import = NULL;
	}

	if (sec->ps_gssiam) {
		OBD_FREE_STR(sec->ps_gssiam->lgmi_subdir);
		OBD_FREE_STR(sec->ps_gssiam->lgmi_principal);
		OBD_FREE_PTR(sec->ps_gssiam);
	}

	mutex_destroy(&gssiam->gis_mutex);
	OBD_FREE_PTR(gssiam);
}

static struct ptlrpc_sec *gssiam_create_sec(struct obd_import *imp,
					     struct ptlrpc_svc_ctx *svc_ctx,
					     struct sptlrpc_flavor *sf)
{
	struct gssiam_sec *gssiam;
	struct ptlrpc_sec *sec;

	OBD_ALLOC_PTR(gssiam);
	if (!gssiam)
		return NULL;

	sec = &gssiam->gis_base;
	sec->ps_policy = &sptlrpc_gssiam_policy;
	atomic_set(&sec->ps_refcount, 0);
	sec->ps_id = sptlrpc_get_next_secid();
	sec->ps_import = class_import_get(imp);
	sec->ps_flvr = *sf;
	sec->ps_dying = 0;
	spin_lock_init(&sec->ps_lock);
	atomic_set(&sec->ps_nctx, 0);
	INIT_LIST_HEAD(&sec->ps_gc_list);
	sec->ps_gc_interval = 0;
	sec->ps_gc_next = 0;

	spin_lock_init(&gssiam->gis_lock);
	mutex_init(&gssiam->gis_mutex);
	gssiam->gis_ctx = NULL;

	return sec;
}

/**
 * gssiam_init_pack_request() - Pack SEC_CTX_INIT request in GSS format.
 * @imp: OBD import associated with the request.
 * @req: The RPC request being packed.
 * @ctx: The GSSIAM client context containing the token and subdir.
 *
 * This function is strictly used during the initial security context
 * establishment (e.g., at mount time or context refresh), NOT for every
 * subsequent data/metadata RPC.
 *
 * It packs the user's GSSIAM token and the requested mount subdirectory
 * into a SEC_CTX_INIT RPC. The server uses this information to perform
 * an external upcall to verify the user's authorization for the specific
 * subdirectory. Upon success, the verified context is attached to the
 * client's export, which enforces access boundaries for all future
 * lightweight (Null-framed) RPCs.
 *
 * Specifically, the packed SEC_CTX_INIT request payload contains:
 * 1. Lustre service type (e.g., MGS, MDS, or OSS).
 * 2. Target OBD UUID.
 * 3. Reverse context handle (dummy/empty for GSSIAM).
 * 4. Client GSSIAM token representing authentication credentials.
 * 5. Requested target mount subdirectory (fileset).
 * 6. Connection/mount options (recently added to support enhanced
 *    properties).
 *
 * On the server side, the SEC_CTX_INIT request is processed and verified
 * by executing an external upcall (e.g., l_gssiam_upcall) to authorize
 * the client's request. A later patch adds the server-side verification
 * (e.g., via tgt_verify_gssiam() and external upcall).
 *
 * Return: 0 on success, negative errno on failure.
 */
static int gssiam_init_pack_request(struct obd_import *imp,
				     struct ptlrpc_request *req,
				     struct gssiam_cli_ctx *ctx)
{
	struct lustre_msg *msg = req->rq_reqbuf;
	struct gss_header *ghdr;
	__u32 *p, size, offset = 2;
	rawobj_t obj;
	__u32 lustre_svc;
	__u32 le_options;
	void *token = ctx->gicc_lid.lid_token;
	int token_size = ctx->gicc_lid.lid_token_len;
	int rc;

	msg->lm_secflvr = req->rq_flvr.sf_rpc;
	req->rq_gss_framed = 1;

	ghdr = lustre_msg_buf(msg, 0, sizeof(*ghdr));
	ghdr->gh_version = PTLRPC_GSS_VERSION;
	ghdr->gh_sp = (__u8) imp->imp_sec->ps_part;
	ghdr->gh_flags = 0;
	ghdr->gh_proc = PTLRPC_GSS_PROC_INIT;
	ghdr->gh_seq = 0;
	ghdr->gh_svc = SPTLRPC_SVC_NULL;
	ghdr->gh_handle.len = 0;

	if (req->rq_pack_udesc)
		offset++;

	/* security payload */
	p = lustre_msg_buf(msg, offset, 0);
	if (!p)
		return -EINVAL;
	size = msg->lm_buflens[offset];
	if (size < 4)
		return -EINVAL;

	/* 1. lustre svc type */
	lustre_svc = import_to_gss_svc(imp);
	*p++ = cpu_to_le32(lustre_svc);
	size -= 4;

	/* 2. target uuid */
	obj.len = strlen(imp->imp_obd->u.cli.cl_target_uuid.uuid) + 1;
	obj.data = imp->imp_obd->u.cli.cl_target_uuid.uuid;
	rc = rawobj_serialize(&obj, &p, &size);
	if (rc)
		return rc;

	/* 3. reverse context handle (dummy for GSSIAM) */
	obj.len = 0;
	obj.data = NULL;
	rc = rawobj_serialize(&obj, &p, &size);
	if (rc)
		return rc;

	/* 4. token */
	obj.len = token_size;
	obj.data = token;
	rc = rawobj_serialize(&obj, &p, &size);
	if (rc)
		return rc;

	/* 5. subdir */
	if (ctx->gicc_lid.lid_subdir)
		obj.data = ctx->gicc_lid.lid_subdir;
	else
		obj.data = "";
	obj.len = strlen((char *)obj.data) + 1;

	rc = rawobj_serialize(&obj, &p, &size);
	if (rc)
		return rc;

	/* 6. options */
	le_options = cpu_to_le32(ctx->gicc_lid.lid_options);
	obj.data = (__u8 *)&le_options;
	obj.len = sizeof(le_options);

	rc = rawobj_serialize(&obj, &p, &size);
	if (rc)
		return rc;

	req->rq_reqdata_len = lustre_shrink_msg(req->rq_reqbuf, offset,
					msg->lm_buflens[offset] - size, 0);

	return 0;
}

static int gssiam_refresh_token(struct gssiam_cli_ctx *ctx)
{
	struct ptlrpc_sec *sec = ctx->gicc_base.cc_sec;
	struct obd_import *imp = sec->ps_import;
	struct upcall_cache_entry *entry;
	int rc = 0;

	/* Always use key gssiam_sec_cache_key(sec) to fetch mount token */
	entry = upcall_cache_get_entry(gssiam_upcall_cache,
				       gssiam_sec_cache_key(sec), sec);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CERROR("%s: Failed to get shared GSSIAM token: rc = %d\n",
		       imp->imp_obd->obd_name, rc);
		return rc;
	}

	if (!UC_CACHE_IS_VALID(entry) ||
	    entry->u.gssiam.gd_auth_permission == GSSIAM_AUTH_DENY)
		GOTO(out, rc = -EACCES);

	/* Free old token if it exists */
	if (ctx->gicc_lid.lid_token) {
		OBD_FREE(ctx->gicc_lid.lid_token, ctx->gicc_lid.lid_token_len);
		ctx->gicc_lid.lid_token = NULL;
		ctx->gicc_lid.lid_token_len = 0;
	}

	/* Copy new token */
	if (entry->u.gssiam.gd_token) {
		OBD_ALLOC(ctx->gicc_lid.lid_token,
			  entry->u.gssiam.gd_token_len);
		if (!ctx->gicc_lid.lid_token)
			GOTO(out, rc = -ENOMEM);
		ctx->gicc_lid.lid_token_len = entry->u.gssiam.gd_token_len;
		memcpy(ctx->gicc_lid.lid_token, entry->u.gssiam.gd_token,
		       ctx->gicc_lid.lid_token_len);
	}

out:
	upcall_cache_put_entry(gssiam_upcall_cache, entry);
	return rc;
}

static int gssiam_send_init_rpc(struct gssiam_cli_ctx *gssiam_ctx)
{
	struct ptlrpc_cli_ctx *ctx = &gssiam_ctx->gicc_base;
	struct obd_import *imp = gssiam_ctx->gicc_base.cc_sec->ps_import;
	struct ptlrpc_request *req;
	bool retried = false;
	int rc;

retry:
	rc = gssiam_refresh_token(gssiam_ctx);
	if (rc)
		GOTO(out, rc);

	/* Prepare SEC_CTX_INIT request */
	req = ptlrpc_request_alloc(imp, &RQF_SEC_CTX);
	if (!req)
		GOTO(out, rc = -ENOMEM);

	rc = ptlrpc_request_bufs_pack(req, LUSTRE_OBD_VERSION, SEC_CTX_INIT,
				      NULL, ctx);
	if (rc) {
		ptlrpc_request_free(req);
		GOTO(out, rc);
	}

	/* req->rq_cli_ctx is already set by ptlrpc_request_bufs_pack */
	LASSERT(req->rq_ctx_init == 1);
	rc = gssiam_init_pack_request(imp, req, gssiam_ctx);
	if (rc) {
		ptlrpc_req_put(req);
		GOTO(out, rc);
	}

	ptlrpc_request_set_replen(req);
	DEBUG_REQ(D_SEC, req, "send init GSSIAM req");
	rc = ptlrpc_queue_wait(req);
	ptlrpc_req_put(req);
	if (rc) {
		if ((rc == -EAGAIN || rc == -EKEYEXPIRED ||
		     rc == -ESTALE || rc == -EACCES || rc == -ETIMEDOUT) &&
		     !retried) {
			retried = true;
			CDEBUG(D_SEC, "%s: retry SEC_CTX_INIT (%d)\n",
			       imp->imp_obd->obd_name, rc);
			if (gssiam_upcall_cache)
				upcall_cache_invalidate_one(
					gssiam_upcall_cache,
					gssiam_sec_cache_key(ctx->cc_sec),
					ctx->cc_sec);
			rawobj_free(&gss_ctx2gssiam(ctx)->gicc_ich_handle);
			goto retry;
		}
		CERROR("%s: GSSIAM SEC_CTX_INIT failed: rc = %d\n",
		       imp->imp_obd->obd_name, rc);
		GOTO(out, rc);
	}

	set_bit(PTLRPC_CTX_UPTODATE_BIT, &ctx->cc_flags);
out:
	return rc;
}

static void
gssiam_ctx_free(struct gssiam_cli_ctx *ctx)
{
	rawobj_free(&ctx->gicc_ich_handle);
	if (ctx->gicc_lid.lid_token)
		OBD_FREE(ctx->gicc_lid.lid_token, ctx->gicc_lid.lid_token_len);
	OBD_FREE_STR(ctx->gicc_lid.lid_subdir);
	OBD_FREE_PTR(ctx);
}

static struct gssiam_cli_ctx *gssiam_ctx_alloc(struct ptlrpc_sec *sec)
{
	struct gssiam_cli_ctx *ctx;

	/* Create new context */
	OBD_ALLOC_PTR(ctx);
	if (!ctx)
		return NULL;

	atomic_set(&ctx->gicc_base.cc_refcount, 1); /* caller ref */
	ctx->gicc_base.cc_sec = sec;
	ctx->gicc_base.cc_ops = &gssiam_ctx_ops;
	ctx->gicc_base.cc_expire = 0;
	ctx->gicc_base.cc_flags = PTLRPC_CTX_CACHED | PTLRPC_CTX_ETERNAL;
	ctx->gicc_base.cc_vcred.vc_uid = 0;
	spin_lock_init(&ctx->gicc_base.cc_lock);
	INIT_LIST_HEAD(&ctx->gicc_base.cc_req_list);
	INIT_LIST_HEAD(&ctx->gicc_base.cc_gc_chain);
	if (sec->ps_gssiam && !sec_is_reverse(sec)) {
		OBD_STRDUP(ctx->gicc_lid.lid_subdir,
			   sec->ps_gssiam->lgmi_subdir);
		if (!ctx->gicc_lid.lid_subdir) {
			OBD_FREE_PTR(ctx);
			return NULL;
		}
		ctx->gicc_lid.lid_options = sec->ps_gssiam->lgmi_options;
	}
	atomic_inc(&sec->ps_refcount);

	return ctx;
}

static struct ptlrpc_cli_ctx *gssiam_lookup_ctx(struct ptlrpc_sec *sec,
						struct vfs_cred *vcred,
						int create, int remove_dead)
{
	struct obd_import *imp = sec->ps_import;
	struct gssiam_sec *gssiam = gss_sec2gssiam(sec);
	struct gssiam_cli_ctx *ctx;
	int rc;

	/* Check existing contexts locklessly via RCU */
	rcu_read_lock();
	ctx = rcu_dereference(gssiam->gis_ctx);
	if (ctx && !atomic_inc_not_zero(&ctx->gicc_base.cc_refcount))
		ctx = NULL;
	rcu_read_unlock();
	if (ctx)
		return &ctx->gicc_base;

	/* For reverse import, just install a null ctx */
	if (unlikely(sec_is_reverse(sec))) {
		struct gssiam_cli_ctx *ctx_new;

		ctx_new = gssiam_ctx_alloc(sec);
		if (!ctx_new)
			return ERR_PTR(-ENOMEM);

		set_bit(PTLRPC_CTX_UPTODATE_BIT, &ctx_new->gicc_base.cc_flags);

		spin_lock(&gssiam->gis_lock);
		ctx = rcu_dereference_protected(gssiam->gis_ctx,
					lockdep_is_held(&gssiam->gis_lock));
		if (ctx && atomic_inc_not_zero(&ctx->gicc_base.cc_refcount)) {
			spin_unlock(&gssiam->gis_lock);
			gssiam_ctx_free(ctx_new);
			sptlrpc_sec_put(sec);
			return &ctx->gicc_base;
		}

		atomic_inc(&ctx_new->gicc_base.cc_refcount); /* list ref */
		rcu_assign_pointer(gssiam->gis_ctx, ctx_new);
		atomic_inc(&sec->ps_nctx);
		spin_unlock(&gssiam->gis_lock);

		return &ctx_new->gicc_base;
	}

	if (!create)
		return ERR_PTR(-ENODATA);

	/* Serialize context creation to ensure single-shot SEC_CTX_INIT */
	mutex_lock(&gssiam->gis_mutex);

	/* Re-check under lock in case another thread initialized it */
	spin_lock(&gssiam->gis_lock);
	ctx = rcu_dereference_protected(gssiam->gis_ctx,
					lockdep_is_held(&gssiam->gis_lock));
	if (ctx && !atomic_inc_not_zero(&ctx->gicc_base.cc_refcount))
		ctx = NULL;
	spin_unlock(&gssiam->gis_lock);
	if (ctx) {
		mutex_unlock(&gssiam->gis_mutex);
		return &ctx->gicc_base;
	}

	/* Get other GSSIAM information from llite before getting entry */
	rc = obd_notify_observer(imp->imp_obd, imp->imp_obd, OBD_NOTIFY_GSSIAM);
	if (rc) {
		CERROR("%s: GSSIAM upcall notify failed: rc = %d\n",
		       imp->imp_obd->obd_name, rc);
		mutex_unlock(&gssiam->gis_mutex);
		return ERR_PTR(rc);
	}

	/* Create new context */
	ctx = gssiam_ctx_alloc(sec);
	if (!ctx) {
		mutex_unlock(&gssiam->gis_mutex);
		return ERR_PTR(-ENOMEM);
	}

	/* Send SEC_CTX_INIT RPC */
	rc = gssiam_send_init_rpc(ctx);
	if (rc)
		GOTO(out_err, rc);

	/* Cache context */
	spin_lock(&gssiam->gis_lock);
	atomic_inc(&ctx->gicc_base.cc_refcount); /* list ref */
	rcu_assign_pointer(gssiam->gis_ctx, ctx);
	atomic_inc(&sec->ps_nctx);
	spin_unlock(&gssiam->gis_lock);

	mutex_unlock(&gssiam->gis_mutex);

	return &ctx->gicc_base;

out_err:
	mutex_unlock(&gssiam->gis_mutex);
	gssiam_ctx_free(ctx);
	sptlrpc_sec_put(sec);
	return ERR_PTR(rc);
}

static void gssiam_release_ctx(struct ptlrpc_sec *sec,
				struct ptlrpc_cli_ctx *ctx, int sync)
{
	struct gssiam_cli_ctx *gssiam_ctx = gss_ctx2gssiam(ctx);

	LASSERT(atomic_read(&ctx->cc_refcount) == 0);

	gssiam_ctx_free(gssiam_ctx);
	atomic_dec(&sec->ps_nctx);
	sptlrpc_sec_put(sec);
}

static int gssiam_flush_ctx_cache(struct ptlrpc_sec *sec, uid_t uid, int grace,
				  int force)
{
	struct gssiam_sec *gssiam = gss_sec2gssiam(sec);
	struct gssiam_cli_ctx *ctx = NULL;

	spin_lock(&gssiam->gis_lock);
	ctx = rcu_dereference_protected(gssiam->gis_ctx,
					lockdep_is_held(&gssiam->gis_lock));
	if (ctx)
		RCU_INIT_POINTER(gssiam->gis_ctx, NULL);
	spin_unlock(&gssiam->gis_lock);

	if (ctx) {
		synchronize_rcu();
		sptlrpc_cli_ctx_put(&ctx->gicc_base, 1);
	}

	/* Also flush upcall cache */
	if (gssiam_upcall_cache)
		upcall_cache_invalidate_one(gssiam_upcall_cache,
					    gssiam_sec_cache_key(sec), sec);

	return 0;
}

static int gssiam_alloc_reqbuf(struct ptlrpc_sec *sec,
				struct ptlrpc_request *req,
				int msgsize)
{
	if (req->rq_ctx_init || gssiam_is_connect(req)) {
		req->rq_gss_framed = 1;
		return gss_alloc_reqbuf(sec, req, msgsize);
	}

	return null_alloc_reqbuf(sec, req, msgsize);
}

static
void gssiam_free_reqbuf(struct ptlrpc_sec *sec, struct ptlrpc_request *req)
{
	if (req->rq_gss_framed)
		gss_free_reqbuf(sec, req);
	else
		null_free_reqbuf(sec, req);
}

static int gssiam_alloc_repbuf(struct ptlrpc_sec *sec,
			       struct ptlrpc_request *req,
			       int msgsize)
{
	if (req->rq_ctx_init || gssiam_is_connect(req)) {
		req->rq_gss_framed = 1;
		return gss_alloc_repbuf(sec, req, msgsize);
	}

	return null_alloc_repbuf(sec, req, msgsize);
}

static void gssiam_free_repbuf(struct ptlrpc_sec *sec,
			       struct ptlrpc_request *req)
{
	if (req->rq_gss_framed)
		gss_free_repbuf(sec, req);
	else
		null_free_repbuf(sec, req);
}

static int gssiam_enlarge_reqbuf(struct ptlrpc_sec *sec,
				  struct ptlrpc_request *req,
				  int segment, int newsize)
{
	if (req->rq_gss_framed)
		return gss_enlarge_reqbuf(sec, req, segment, newsize);

	return null_enlarge_reqbuf(sec, req, segment, newsize);
}

static void gssiam_kill_sec(struct ptlrpc_sec *sec)
{
	sec->ps_dying = 1;
}

static struct ptlrpc_sec_cops gssiam_sec_cops = {
	.create_sec	= gssiam_create_sec,
	.destroy_sec	= gssiam_destroy_sec,
	.kill_sec	= gssiam_kill_sec,
	.lookup_ctx	= gssiam_lookup_ctx,
	.release_ctx	= gssiam_release_ctx,
	.flush_ctx_cache = gssiam_flush_ctx_cache,
	.alloc_reqbuf	= gssiam_alloc_reqbuf,
	.free_reqbuf	= gssiam_free_reqbuf,
	.alloc_repbuf	= gssiam_alloc_repbuf,
	.free_repbuf	= gssiam_free_repbuf,
	.enlarge_reqbuf	= gssiam_enlarge_reqbuf,
};

static struct ptlrpc_svc_ctx gssiam_svc_ctx = {
	.sc_refcount    = REFCOUNT_INIT(1),
	.sc_policy      = &sptlrpc_gssiam_policy,
};

static int gssiam_alloc_rs(struct ptlrpc_request *req, int msgsize)
{
	if (req->rq_svc_ctx != &gssiam_svc_ctx)
		return gss_svc_alloc_rs(req, msgsize);
	else
		return null_alloc_rs(req, msgsize);
}

static void gssiam_free_rs(struct ptlrpc_reply_state *rs)
{
	if (rs->rs_svc_ctx == &gssiam_svc_ctx) {
		null_free_rs(rs);
		return;
	}
	gss_svc_free_rs(rs);
}

static int gssiam_authorize(struct ptlrpc_request *req)
{
	/* Check if we are using generic context (Null flavor) */
	if (req->rq_svc_ctx == &gssiam_svc_ctx) {
		null_authorize_common(req, req->rq_flvr.sf_rpc);
		return 0;
	}

	/* GSS context (Connect requests) */
	return gss_svc_authorize(req);
}

static void gssiam_free_ctx(struct ptlrpc_svc_ctx *ctx)
{
	if (ctx == &gssiam_svc_ctx)
		return;
	gss_svc_free_ctx(ctx);
}

static void gssiam_invalidate_ctx(struct ptlrpc_svc_ctx *ctx)
{
	if (ctx == &gssiam_svc_ctx)
		return;
	gss_svc_invalidate_ctx(ctx);
}

/* server operations */
static int gssiam_accept(struct ptlrpc_request *req)
{
	/* XXX the following patch will check the gssiam req */
	null_accept_common(req, &gssiam_svc_ctx);
	return SECSVC_OK;
}

static struct ptlrpc_sec_sops gssiam_sops = {
	.accept		= gssiam_accept,
	.alloc_rs	= gssiam_alloc_rs,
	.authorize	= gssiam_authorize,
	.free_ctx	= gssiam_free_ctx,
	.free_rs	= gssiam_free_rs,
	.invalidate_ctx	= gssiam_invalidate_ctx,
};

static struct ptlrpc_sec_policy sptlrpc_gssiam_policy = {
	.sp_owner  = THIS_MODULE,
	.sp_name   = "gssiam",
	.sp_policy = SPTLRPC_POLICY_GSSIAM,
	.sp_cops   = &gssiam_sec_cops,
	.sp_sops   = &gssiam_sops,
};

static ssize_t gssiam_upcall_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	ssize_t len;

	down_read(&gssiam_upcall_cache->uc_upcall_rwsem);
	len = scnprintf(buf, PAGE_SIZE, "%s\n",
			gssiam_upcall_cache->uc_upcall);
	up_read(&gssiam_upcall_cache->uc_upcall_rwsem);

	return len;
}

static
ssize_t gssiam_upcall_store(struct kobject *kobj, struct attribute *attr,
			    const char *buf, size_t count)
{
	int rc;

	rc = upcall_cache_set_upcall(gssiam_upcall_cache, buf, count, true);
	if (rc)
		CERROR("%s: incorrect gssiam upcall %.*s: rc = %d\n",
		       gssiam_upcall_cache->uc_name, (int)count, buf, rc);

	return rc ?: count;
}
LUSTRE_RW_ATTR(gssiam_upcall);

static
ssize_t gssiam_downcall_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer, size_t count)
{
	const struct gssiam_downcall_data *param;
	size_t size = sizeof(*param);
	int rc;

	if (count < size) {
		rc = -EINVAL;
		CERROR("%s: gssiam downcall data too small: %zu: rc = %d\n",
		       gssiam_upcall_cache->uc_name, count, rc);
		return rc;
	}

	param = (const struct gssiam_downcall_data *)buffer;
	if (param->idd_magic != GSSIAM_DOWNCALL_MAGIC) {
		rc = -EINVAL;
		CERROR("%s: gssiam downcall bad magic: %08x: rc = %d\n",
			gssiam_upcall_cache->uc_name, param->idd_magic, rc);
		return rc;
	}

	if (param->idd_token_len > count - size ||
	    param->idd_principal_len > count - size ||
	    (param->idd_principal_len > 0 &&
	     __ALIGN_KERNEL(param->idd_token_len, 8) +
	     (size_t)param->idd_principal_len > count - size)) {
		rc = -EINVAL;
		CERROR("%s: gssiam downcall invalid string lengths: token_len=%u principal_len=%u count=%zu: rc = %d\n",
		       gssiam_upcall_cache->uc_name, param->idd_token_len,
		       param->idd_principal_len, count, rc);
		return rc;
	}

	rc = upcall_cache_downcall(gssiam_upcall_cache, param->idd_err,
				   param->idd_key, (void *)param);

	return rc ? rc : count;
}
LUSTRE_WO_ATTR(gssiam_downcall);

static
ssize_t gssiam_flush_store(struct kobject *kobj, struct attribute *attr,
			    const char *buffer, size_t count)
{
	unsigned long long key;
	int rc;

	/*
	 * gssiam_sec_cache_key() produces 64-bit fnv_1a_64() hash keys that
	 * span the full unsigned 64-bit range. Use kstrtoull() to avoid
	 * -ERANGE errors when keys exceed LLONG_MAX.
	 */
	rc = kstrtoull(buffer, 0, &key);
	if (rc) {
		long long sval;

		/*
		 * kstrtoull() rejects negative numbers. If -1 is passed as
		 * the flush-all sentinel, parse it via kstrtoll().
		 */
		rc = kstrtoll(buffer, 0, &sval);
		if (rc || sval != -1)
			return rc ? rc : -EINVAL;

		/* Invalidate all upcall cache entries */
		key = ULLONG_MAX;
	}

	if (key == ULLONG_MAX) {
		/* Invalidate all upcall cache entries */
		upcall_cache_invalidate_all(gssiam_upcall_cache);
	} else {
		/* Invalidate the entry indicated by the key */
		upcall_cache_invalidate_one(gssiam_upcall_cache,
					    (__u64)key, NULL);
	}
	return count;
}
LUSTRE_WO_ATTR(gssiam_flush);

static struct attribute *gssiam_attrs[] = {
	&lustre_attr_gssiam_upcall.attr,
	&lustre_attr_gssiam_downcall.attr,
	&lustre_attr_gssiam_flush.attr,
	NULL
};

static struct attribute_group gssiam_attr_group = {
	.attrs = gssiam_attrs,
};

static int gssiam_tunables_init(void)
{
	int rc;

	gssiam_kobj = kobject_create_and_add("gssiam", sptlrpc_kobj);
	if (!gssiam_kobj)
		return -ENOMEM;

	rc = sysfs_create_group(gssiam_kobj, &gssiam_attr_group);
	if (rc) {
		kobject_put(gssiam_kobj);
		gssiam_kobj = NULL;
	}
	return rc;
}

static void gssiam_tunables_fini(void)
{
	if (gssiam_kobj) {
		sysfs_remove_group(gssiam_kobj, &gssiam_attr_group);
		kobject_put(gssiam_kobj);
		gssiam_kobj = NULL;
	}
}

#define UC_GSSIAM_HASH_SIZE 128
#define GSSIAM_UPCALL_PATH "/usr/sbin/l_gssiam_upcall"
#define GSSIAM_CACHE_NAME "gssiam"

int __init sptlrpc_gssiam_init(void)
{
	int rc;

	gssiam_upcall_cache = upcall_cache_init(GSSIAM_CACHE_NAME,
						 GSSIAM_UPCALL_PATH,
						 UC_GSSIAM_HASH_SIZE,
						 3600, /* entry expire */
						 30, /* acquire expire */
						 false, /* replay */
						 &gssiam_upcall_ops);
	if (IS_ERR(gssiam_upcall_cache)) {
		int rc = PTR_ERR(gssiam_upcall_cache);

		gssiam_upcall_cache = NULL;
		CERROR("%s: Failed to init GSSIAM upcall cache: rc = %d\n",
		       GSSIAM_CACHE_NAME, rc);
		return rc;
	}

	/* XXX register GSSIAM policy once all patches are landed */
	rc = gssiam_tunables_init();
	if (rc) {
		upcall_cache_cleanup(gssiam_upcall_cache);
		return rc;
	}

	return 0;
}

void sptlrpc_gssiam_exit(void)
{
	gssiam_tunables_fini();
	upcall_cache_cleanup(gssiam_upcall_cache);
}
