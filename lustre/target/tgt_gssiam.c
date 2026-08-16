// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google
 *
 * Lustre GSSIAM Target operations
 *
 */
#define DEBUG_SUBSYSTEM S_SEC

#include <linux/kmod.h>
#include <linux/slab.h>
#include <upcall_cache.h>
#include <lustre_gssiam.h>
#include <lustre_import.h>
#include <lustre_net.h>
#include <lustre_req_layout.h>
#include <lustre_mds.h>
#include <lustre_sec.h>
#include <lustre_nodemap.h>
#include <obd_class.h>
#include <obd_target.h>
#include "tgt_internal.h"

struct gssiam_entry_arg {
	struct obd_uuid uuid;
	const struct lustre_gssiam_desc *lid;
};

static void tgt_gssiam_entry_init(struct upcall_cache_entry *entry, void *args)
{
	struct gssiam_desc *gssiam = &entry->u.gssiam;
	struct gssiam_entry_arg *arg = args;
	const struct lustre_gssiam_desc *src = arg ? arg->lid : NULL;

	ENTRY;

	gssiam->gd_uc_entry = entry;
	gssiam->gd_auth_projid = MDT_INVALID_PROJID;
	if (arg)
		gssiam->gd_obd_uuid = arg->uuid;

	if (src) {
		CDEBUG(D_INFO, "src: token_len=%u subdir=%s\n",
		       src->lid_token_len, src->lid_subdir);
		if (src->lid_token_len > 0) {
			OBD_ALLOC(gssiam->gd_token, src->lid_token_len);
			if (gssiam->gd_token) {
				gssiam->gd_token_len = src->lid_token_len;
				memcpy(gssiam->gd_token, src->lid_token,
				       gssiam->gd_token_len);
			} else {
				gssiam->gd_token_len = 0;
			}
		} else {
			gssiam->gd_token = NULL;
			gssiam->gd_token_len = 0;
		}
		OBD_STRDUP(gssiam->gd_subdir, src->lid_subdir);
		gssiam->gd_options = src->lid_options;
	} else {
		gssiam->gd_token = NULL;
		gssiam->gd_token_len = 0;
		gssiam->gd_subdir = NULL;
		gssiam->gd_options = 0;
	}
	gssiam->gd_auth_permission = GSSIAM_AUTH_DENY;
	atomic_set(&gssiam->gd_export_count, 0);
	EXIT;
}

static void tgt_gssiam_entry_free(struct upcall_cache *cache,
				  struct upcall_cache_entry *entry)
{
	struct gssiam_desc *gssiam = &entry->u.gssiam;

	OBD_FREE(gssiam->gd_token, gssiam->gd_token_len);
	OBD_FREE_STR(gssiam->gd_subdir);
	OBD_FREE_STR(gssiam->gd_resolved_subdir);
	OBD_FREE_STR(gssiam->gd_principal);
}

static int tgt_gssiam_upcall_compare(struct upcall_cache *cache,
				     struct upcall_cache_entry *entry,
				     __u64 key, void *args)
{
	struct gssiam_desc *gssiam = &entry->u.gssiam;
	struct gssiam_entry_arg *arg = args;
	const struct lustre_gssiam_desc *arg_gssiam = arg ? arg->lid : NULL;
	const char *s1, *s2;

	if (entry->ue_key != key)
		return -1;

	if (gssiam->gd_token_len !=
	    (arg_gssiam ? arg_gssiam->lid_token_len : 0))
		return -1;

	if (gssiam->gd_token && arg_gssiam && arg_gssiam->lid_token) {
		if (memcmp(gssiam->gd_token, arg_gssiam->lid_token,
			   gssiam->gd_token_len) != 0)
			return -1;
	} else if (gssiam->gd_token || (arg_gssiam && arg_gssiam->lid_token)) {
		return -1;
	}

	s1 = gssiam->gd_subdir ? gssiam->gd_subdir : "";
	s2 = (arg_gssiam && arg_gssiam->lid_subdir) ?
		arg_gssiam->lid_subdir : "";
	if (strcmp(s1, s2) != 0)
		return -1;

	return 0;
}

static int tgt_gssiam_downcall_compare(struct upcall_cache *cache,
				       struct upcall_cache_entry *entry,
				       __u64 key, void *args)
{
	/* For downcall, we usually match by key (hash) */
	if (entry->ue_key != key)
		return -1;
	return 0;
}

static int tgt_gssiam_local_upcall(struct upcall_cache *cache,
				   struct upcall_cache_entry *entry)
{
	char key_buf[32];
	char opt_buf[32];
	char *token_encoded = NULL;
	int token_encoded_len = 0;
	/* Prefer the subdir resolved on MDT0, falling back to gd_subdir */
	const char *subdir = entry->u.gssiam.gd_resolved_subdir ?:
			     entry->u.gssiam.gd_subdir ?: "";
	char *argv[] = {
		[0] = cache->uc_upcall,
		[1] = key_buf,
		[2] = "",
		[3] = (char *)subdir,
		[4] = cache->uc_name,
		[5] = opt_buf,
		[6] = NULL
	};
	static char *envp[] = {
		[0] = "HOME=/",
		[1] = "PATH=/sbin:/usr/sbin",
		[2] = NULL
	};
	char *dst;
	int dstlen;
	int rc;

	ENTRY;

	snprintf(key_buf, sizeof(key_buf), "%llu", entry->ue_key);
	snprintf(opt_buf, sizeof(opt_buf), "%u", entry->u.gssiam.gd_options);

	down_read(&cache->uc_upcall_rwsem);
	if (unlikely(!strcmp(cache->uc_upcall, "NONE") ||
		     cache->uc_upcall[0] == '\0'))
		GOTO(out_rwsem, rc = -EREMCHG);
	argv[0] = cache->uc_upcall;

	if (!entry->u.gssiam.gd_token || entry->u.gssiam.gd_token_len == 0)
		GOTO(out_rwsem, rc = -EINVAL);

	/**
	 * The GSSIAM token is an opaque binary buffer and might contain
	 * null bytes. To safely pass it to userspace via argv, we base64url
	 * encode it.
	 */
	token_encoded_len =
		BASE64URL_CHARS(entry->u.gssiam.gd_token_len) + 2;
	OBD_ALLOC(token_encoded, token_encoded_len);
	if (!token_encoded)
		GOTO(out_rwsem, rc = -ENOMEM);

	dst = token_encoded;
	dstlen = token_encoded_len;
	rc = gss_base64url_encode(&dst, &dstlen, entry->u.gssiam.gd_token,
				  entry->u.gssiam.gd_token_len);
	if (rc)
		GOTO(out_free, rc);

	/**
	 * call_usermodehelper() requires the string to be NUL
	 * terminated. gss_base64url_encode() does not add any
	 * trailing NUL byte, so we explicitly terminate it at *dst.
	 **/
	if (dst > token_encoded)
		*dst = '\0';

	argv[2] = token_encoded;

	/* argv[2] is the client's bearer token, so never log it */
	CDEBUG(D_INFO, "GSSIAM upcall: %s %s <token len %u> %s %s %s\n",
	       argv[0], argv[1], entry->u.gssiam.gd_token_len, argv[3],
	       argv[4], argv[5]);

	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (rc < 0) {
		CERROR("%s: error invoking GSSIAM %p upcall %s: rc = %d\n",
		       cache->uc_name, cache, argv[0], rc);
	} else if (rc > 0) {
		CERROR("%s: GSSIAM upcall %s failed: rc = %d\n",
		       cache->uc_name, argv[0], rc);
		rc = -EPERM;
	}

out_free:
	OBD_FREE(token_encoded, token_encoded_len);
out_rwsem:
	up_read(&cache->uc_upcall_rwsem);

	RETURN(rc);
}

/**
 * tgt_gssiam_get_entry() - Get or allocate an entry in GSSIAM upcall cache
 * @cache: Upcall cache.
 * @lid: GSSIAM descriptor.
 * @uuid: Target UUID.
 *
 * Calls upcall_cache_get_entry() to find or allocate an entry.
 *
 * Return: upcall_cache_entry pointer on success, or ERR_PTR on failure.
 */
struct upcall_cache_entry *tgt_gssiam_get_entry(struct upcall_cache *cache,
					const struct lustre_gssiam_desc *lid,
						const struct obd_uuid *uuid)
{
	struct gssiam_entry_arg arg;
	__u64 key;

	if (!cache || !lid)
		return ERR_PTR(-EINVAL);

	if (uuid)
		arg.uuid = *uuid;
	else
		memset(&arg.uuid, 0, sizeof(arg.uuid));
	arg.lid = lid;

	key = lustre_gssiam_hash_key(lid->lid_token, lid->lid_token_len,
				     lid->lid_subdir, lid->lid_options);
	CDEBUG(D_INFO, "lid: token_len=%u subdir=%s key=%llu\n",
	       lid->lid_token_len, lid->lid_subdir, key);

	return upcall_cache_get_entry(cache, key, &arg);
}
EXPORT_SYMBOL(tgt_gssiam_get_entry);

static tgt_gssiam_projid_cb_t gssiam_projid_cb;

void tgt_gssiam_register_projid_cb(tgt_gssiam_projid_cb_t cb)
{
	gssiam_projid_cb = cb;
}
EXPORT_SYMBOL(tgt_gssiam_register_projid_cb);

void tgt_gssiam_unregister_projid_cb(void)
{
	gssiam_projid_cb = NULL;
}
EXPORT_SYMBOL(tgt_gssiam_unregister_projid_cb);

/**
 * tgt_gssiam_get_local_mdt0_obd() - Find a running MDT0 on this node
 * @obd: Target the request arrived on, used for the filesystem name
 *
 * MDT0 can be unmounted while the caller walks its namespace, so it is
 * returned with a reference that the caller drops with
 * class_decref(mdt0_obd, "find", current).
 *
 * Return: referenced MDT0 obd_device, or NULL if none is set up here.
 */
static struct obd_device *tgt_gssiam_get_local_mdt0_obd(struct obd_device *obd)
{
	char mdt0_name[MTI_NAME_MAXLEN];
	struct obd_device *mdt0_obd;
	char *p;

	if (!obd || !obd->obd_name[0])
		return NULL;

	p = strchr(obd->obd_name, '-');
	if (!p)
		return NULL;

	snprintf(mdt0_name, sizeof(mdt0_name), "%.*s-MDT0000",
		 (int)(p - obd->obd_name), obd->obd_name);

	mdt0_obd = class_str2obd(mdt0_name);
	if (!mdt0_obd)
		return NULL;

	if (!test_bit(OBDF_SET_UP, mdt0_obd->obd_flags) ||
	    test_bit(OBDF_STOPPING, mdt0_obd->obd_flags)) {
		class_decref(mdt0_obd, "find", current);
		return NULL;
	}

	return mdt0_obd;
}

/*
 * The upcall cache turns any error from do_upcall() or from a downcall
 * into -EIDRM, which the client treats as a hard failure.  When the token
 * could not be checked for a transient reason (no connection to MDT0 yet,
 * or the forwarded RPC failed), complete the acquire with an expired
 * entry instead: tgt_gssiam_verify() then returns -EAGAIN and the client
 * retries its context init.
 */
static int tgt_gssiam_downcall_retry(struct upcall_cache *cache,
				     struct upcall_cache_entry *entry)
{
	char buf[] = "expired:0:0:";

	return upcall_cache_downcall(cache, 0, entry->ue_key, buf);
}

static int tgt_gssiam_do_upcall(struct upcall_cache *cache,
				struct upcall_cache_entry *entry)
{
	struct obd_device *obd = class_uuid2obd(&entry->u.gssiam.gd_obd_uuid);
	struct obd_device_target *obt = obd ? (void *)&obd->u : NULL;
	struct lu_target *lut = (obt && obt->obt_magic == OBT_MAGIC) ?
				obt->obt_lut : NULL;
	struct obd_device *mdt0_obd;
	int rc;

	mdt0_obd = obd ? tgt_gssiam_get_local_mdt0_obd(obd) : NULL;
	if (mdt0_obd && gssiam_projid_cb) {
		char *resolved_subdir = NULL;
		__u32 projid;

		rc = gssiam_projid_cb(mdt0_obd, entry->u.gssiam.gd_subdir,
				      &projid, &resolved_subdir);
		class_decref(mdt0_obd, "find", current);
		if (rc)
			return rc;

		entry->u.gssiam.gd_auth_projid = projid;
		if (resolved_subdir) {
			OBD_FREE_STR(entry->u.gssiam.gd_resolved_subdir);
			entry->u.gssiam.gd_resolved_subdir = resolved_subdir;
		}

		return tgt_gssiam_local_upcall(cache, entry);
	}
	if (mdt0_obd)
		class_decref(mdt0_obd, "find", current);

	rc = -EAGAIN;
	if (lut && lut->lut_tsi.tsi_gssiam_authenticate_remote)
		rc = lut->lut_tsi.tsi_gssiam_authenticate_remote(lut, cache,
								  entry);
	if (rc == -EAGAIN) {
		CDEBUG(D_SEC, "%s: no connection to MDT0, client will retry\n",
		       obd ? obd->obd_name : cache->uc_name);
		rc = tgt_gssiam_downcall_retry(cache, entry);
	}

	return rc;
}

static int tgt_gssiam_parse_downcall(struct upcall_cache *cache,
				  struct upcall_cache_entry *entry,
				  void *args)

{
	struct gssiam_desc *gssiam = &entry->u.gssiam;
	char *buf = args;
	char *option;
	char *expire_str;
	char *principal_str = NULL;
	time64_t expire;
	__u32 perm = GSSIAM_AUTH_DENY;

	/* Format: mount_option:expire:principal */
	option = buf;
	expire_str = strchr(buf, ':');
	if (!expire_str) {
		CWARN("%s: options is %s: rc = %d\n", cache->uc_name, option,
		      -EINVAL);
		return -EINVAL;
	}

	/* Strip trailing newline from the entire string to simplify parsing */
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = '\0';

	*expire_str = '\0';
	expire_str++;

	principal_str = strchr(expire_str, ':');
	if (principal_str) {
		*principal_str = '\0';
		principal_str++;
	}

	if (kstrtoll(expire_str, 10, &expire)) {
		CERROR("%s: option is %s: rc = %d\n", cache->uc_name,
		       expire_str, -EINVAL);
		return -EINVAL;
	}

	/*
	 * Supported modes:
	 * GSSIAM_AUTH_DENY = 0
	 * GSSIAM_AUTH_RO   = 1
	 * GSSIAM_AUTH_RW   = 2
	 */
	if (strcmp(option, "deny") == 0) {
		perm = GSSIAM_AUTH_DENY;
	} else if (strcmp(option, "ro") == 0) {
		perm = GSSIAM_AUTH_RO;
	} else if (strcmp(option, "rw") == 0) {
		perm = GSSIAM_AUTH_RW;
	} else if (strcmp(option, "expired") == 0) {
		perm = GSSIAM_AUTH_EXPIRED;
	} else {
		CERROR("%s: Invalid options %s: rc = %d\n", cache->uc_name,
		       option, -EINVAL);
		return -EINVAL;
	}

	entry->ue_expire = ktime_get_seconds() + expire;

	if ((perm & (GSSIAM_AUTH_RO | GSSIAM_AUTH_RW)) &&
	    (!principal_str || !*principal_str)) {
		CERROR("%s: principal required in downcall (%s): rc = %d\n",
		       cache->uc_name, option, -EINVAL);
		return -EINVAL;
	}

	if (gssiam->gd_principal) {
		OBD_FREE_STR(gssiam->gd_principal);
		gssiam->gd_principal = NULL;
	}
	if (principal_str && *principal_str) {
		OBD_STRDUP(gssiam->gd_principal, principal_str);
		if (!gssiam->gd_principal)
			return -ENOMEM;
	}

	gssiam->gd_auth_permission = perm;

	CDEBUG(D_INFO, "permission=0x%x expire=%lld projid=%u principal=%s\n",
	       gssiam->gd_auth_permission, (long long)expire,
	       gssiam->gd_auth_projid,
	       gssiam->gd_principal ? gssiam->gd_principal : "none");

	return 0;
}

struct upcall_cache *tgt_gssiam_cache;
EXPORT_SYMBOL(tgt_gssiam_cache);

static struct upcall_cache_ops tgt_gssiam_upcall_cache_ops = {
	.init_entry	= tgt_gssiam_entry_init,
	.free_entry	= tgt_gssiam_entry_free,
	.upcall_compare = tgt_gssiam_upcall_compare,
	.downcall_compare = tgt_gssiam_downcall_compare,
	.do_upcall	= tgt_gssiam_do_upcall,
	.parse_downcall = tgt_gssiam_parse_downcall,
};

#define GSSIAM_TGT_AUTH_PATH "/usr/sbin/l_gssiam_auth"
#define GSSIAM_TGT_CACHE_NAME "gssiam_server"
#define GSSIAM_TGT_UC_HASH_SIZE 128
int tgt_gssiam_init(void)
{
	int rc = 0;

	tgt_gssiam_cache = upcall_cache_init(GSSIAM_TGT_CACHE_NAME,
					     GSSIAM_TGT_AUTH_PATH,
					     GSSIAM_TGT_UC_HASH_SIZE,
					     3600, /* entry expire: 60 mn */
					     60, /* acquire expire: 60 s */
					     false, /* acquire can replay */
					     &tgt_gssiam_upcall_cache_ops);
	if (IS_ERR(tgt_gssiam_cache)) {
		rc = PTR_ERR(tgt_gssiam_cache);
		tgt_gssiam_cache = NULL;
		return rc;
	}

	return 0;
}

void tgt_gssiam_fini(void)
{
	if (tgt_gssiam_cache) {
		upcall_cache_cleanup(tgt_gssiam_cache);
		tgt_gssiam_cache = NULL;
	}
}

static int tgt_gssiam_rpc_auth_callback(const struct lu_env *env,
					struct ptlrpc_request *req, void *arg,
					int rc1)
{
	struct upcall_cache_entry *entry = req->rq_async_args.pointer_arg[0];
	struct upcall_cache *cache = req->rq_async_args.pointer_arg[1];
	struct gssiam_auth_rep *rep;
	char *downcall_str = NULL;
	const char *perm_str = "deny";
	int rc = rc1 != 0 ? rc1 : req->rq_status;
	int rep_size;
	int princ_len = 0;
	int str_len = 0;
	int needed;

	if (rc != 0 || !ptlrpc_client_replied(req)) {
		rc = rc ? rc : -EIO;
		GOTO(out_downcall, rc);
	}

	rep_size = req_capsule_get_size(&req->rq_pill, &RMF_GETINFO_VAL,
					RCL_SERVER);
	rep = req_capsule_server_sized_get(&req->rq_pill, &RMF_GETINFO_VAL,
					   rep_size);
	if (rep == NULL || rep_size < sizeof(*rep))
		GOTO(out_downcall, rc = -EPROTO);

	entry->u.gssiam.gd_auth_projid = le32_to_cpu(rep->gar_projid);

	if (rep_size > sizeof(*rep)) {
		princ_len = rep_size - sizeof(*rep);
		if (strnlen(rep->gar_principal, princ_len) == princ_len)
			GOTO(out_downcall, rc = -EPROTO);
	}

	if (le32_to_cpu(rep->gar_permission) & GSSIAM_AUTH_EXPIRED)
		perm_str = "expired";
	else if (le32_to_cpu(rep->gar_permission) & GSSIAM_AUTH_RW)
		perm_str = "rw";
	else if (le32_to_cpu(rep->gar_permission) & GSSIAM_AUTH_RO)
		perm_str = "ro";

	/**
	 * 128 bytes should be enough to hold the following downcall_str
	 * before principal
	 */
	str_len = princ_len + 128;
	OBD_ALLOC(downcall_str, str_len);
	if (!downcall_str)
		GOTO(out_downcall, rc = -ENOMEM);

	needed = snprintf(downcall_str, str_len, "%s:%llu:%s", perm_str,
			  (unsigned long long)le64_to_cpu(rep->gar_expire),
			  princ_len > 0 ? rep->gar_principal : "");

	if (needed >= str_len || needed < 0)
		GOTO(out_downcall, rc = -EINVAL);

out_downcall:
	if (rc == -EPROTO || rc == -EINVAL) {
		upcall_cache_downcall(cache, rc, entry->ue_key, NULL);
	} else if (rc) {
		CDEBUG(D_SEC, "%s: GSSIAM auth RPC to MDT0 failed, client will retry: rc = %d\n",
		       cache->uc_name, rc);
		tgt_gssiam_downcall_retry(cache, entry);
	} else {
		rc = upcall_cache_downcall(cache, 0, entry->ue_key,
					   downcall_str);
	}

	OBD_FREE(downcall_str, str_len);
	upcall_cache_put_entry(cache, entry);
	return rc;
}

int tgt_gssiam_rpc_authenticate(struct obd_export *exp,
				struct upcall_cache *cache,
				struct upcall_cache_entry *entry)
{
	struct gssiam_desc *gssiam = &entry->u.gssiam;
	struct ptlrpc_request *req;
	char *tmp;
	int rc;
	const char *subdir;
	const char *token;
	int subdir_len, token_len;

	if (exp == NULL || exp->exp_obd == NULL ||
	    exp->exp_obd->u.cli.cl_import == NULL)
		return -EINVAL;

	req = ptlrpc_request_alloc(exp->exp_obd->u.cli.cl_import,
				   &RQF_MDS_GET_INFO);
	if (req == NULL)
		return -ENOMEM;

	subdir = gssiam->gd_subdir ? gssiam->gd_subdir : "";
	subdir_len = strlen(subdir) + 1;
	token = gssiam->gd_token ? gssiam->gd_token : "";
	token_len = gssiam->gd_token ? gssiam->gd_token_len : 1;

	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_KEY, RCL_CLIENT,
			     sizeof(KEY_GSSIAM_AUTHENTICATE));
	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_VAL, RCL_CLIENT,
			     sizeof(__u32) + token_len + subdir_len);
	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_VAL, RCL_SERVER,
			     sizeof(struct gssiam_auth_rep) + 1024);

	rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, MDS_GET_INFO);
	if (rc) {
		ptlrpc_request_free(req);
		return rc;
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_GETINFO_KEY);
	memcpy(tmp, KEY_GSSIAM_AUTHENTICATE, sizeof(KEY_GSSIAM_AUTHENTICATE));

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_GETINFO_VAL);
	*(__u32 *)tmp = cpu_to_le32(token_len);
	tmp += sizeof(__u32);
	if (token_len > 0)
		memcpy(tmp, token, token_len);
	memcpy(tmp + token_len, subdir, subdir_len);

	ptlrpc_request_set_replen(req);

	req->rq_async_args.pointer_arg[0] = entry;
	req->rq_async_args.pointer_arg[1] = cache;
	req->rq_interpret_reply = tgt_gssiam_rpc_auth_callback;

	/* Hold a reference for the callback */
	upcall_cache_get_entry_raw(entry);

	ptlrpcd_add_req(req);

	return 0;
}
EXPORT_SYMBOL(tgt_gssiam_rpc_authenticate);

static int tgt_gssiam_info_alloc(struct lustre_gssiam_info **gssiam_info_ptr,
				 const struct lustre_gssiam_desc *lid,
				 struct upcall_cache_entry *entry)
{
	struct lustre_gssiam_info *gssiam_info = NULL;
	/* On MDT0, gd_resolved_subdir contains the canonical path from
	 * the root namespace (e.g. "/exports/user1/foo"), which is used for
	 * nodemap_fileset_add(). On non-MDT0 targets, gd_resolved_subdir is
	 * NULL and we gracefully fall back to gd_subdir (raw_subdir).
	 */
	const char *subdir = entry->u.gssiam.gd_resolved_subdir ?
			     entry->u.gssiam.gd_resolved_subdir :
			     (entry->u.gssiam.gd_subdir ?
			      entry->u.gssiam.gd_subdir : lid->lid_subdir);

	__u32 perm;
	int rc = 0;

	OBD_ALLOC_PTR(gssiam_info);
	if (gssiam_info == NULL)
		return -ENOMEM;

	if (subdir) {
		OBD_STRDUP(gssiam_info->lii_desc.lid_subdir, subdir);
		if (!gssiam_info->lii_desc.lid_subdir)
			GOTO(out_free, rc = -ENOMEM);
	}

	if (!entry->u.gssiam.gd_principal ||
	    !*entry->u.gssiam.gd_principal)
		GOTO(out_free, rc = -EINVAL);

	OBD_STRDUP(gssiam_info->lii_desc.lid_principal,
		   entry->u.gssiam.gd_principal);
	if (!gssiam_info->lii_desc.lid_principal)
		GOTO(out_free, rc = -ENOMEM);

	/*
	 * lid->lid_options is extracted from the incoming GSS security context
	 * RPC (secdata) sent by the client. If the client indicates it has
	 * mounted the filesystem as read-only (OBD_CONNECT_RDONLY), we demote
	 * any granted RW permissions to GSSIAM_AUTH_RO while preserving other
	 * states (such as DENY or EXPIRED). Otherwise, we adopt the permissions
	 * returned by the GSSIAM upcall cache entry.
	 */
	perm = entry->u.gssiam.gd_auth_permission;
	if ((lid->lid_options & OBD_CONNECT_RDONLY) &&
	    (perm & GSSIAM_AUTH_RW)) {
		perm &= ~GSSIAM_AUTH_RW;
		perm |= GSSIAM_AUTH_RO;
	}

	gssiam_info->lii_auth_permission = perm;
	gssiam_info->lii_desc.lid_projid = entry->u.gssiam.gd_auth_projid;
	*gssiam_info_ptr = gssiam_info;

out_free:
	if (rc) {
		OBD_FREE_STR(gssiam_info->lii_desc.lid_subdir);
		OBD_FREE_STR(gssiam_info->lii_desc.lid_principal);
		OBD_FREE_PTR(gssiam_info);
	}

	return rc;
}

/**
 * tgt_gssiam_attach_cache_entry() - Attach the GSSIAM upcall cache
 * entry to the export
 * @exp: The export to attach the entry to
 * @entry: The upcall cache entry
 */
void tgt_gssiam_attach_cache_entry(struct obd_export *exp,
				   struct upcall_cache_entry *entry)
{
	struct upcall_cache_entry *old_entry = NULL;

	if (!entry || !exp || !exp->exp_obd)
		return;

	spin_lock(&exp->exp_lock);
	if (exp->exp_target_data.ted_gssiam_entry != entry) {
		old_entry = exp->exp_target_data.ted_gssiam_entry;
		upcall_cache_get_entry_raw(entry);
		exp->exp_target_data.ted_gssiam_entry = entry;
		atomic_inc(&entry->u.gssiam.gd_export_count);
	}
	spin_unlock(&exp->exp_lock);

	if (old_entry) {
		if (atomic_dec_and_test(&old_entry->u.gssiam.gd_export_count)) {
			if (tgt_gssiam_cache &&
			    atomic_read(&old_entry->ue_refcount) == 1)
				upcall_cache_update_entry(tgt_gssiam_cache,
							  old_entry, 0,
							  UC_CACHE_EXPIRED);
		}
		if (tgt_gssiam_cache)
			upcall_cache_put_entry(tgt_gssiam_cache, old_entry);
	}
}
EXPORT_SYMBOL(tgt_gssiam_attach_cache_entry);

/**
 * tgt_gssiam_detach_cache_entry() - Detach the GSSIAM upcall cache
 * entry from the export
 * @exp: The export to detach the entry from
 *
 * Destroy the gssiam upcall entry when all exports are disconnected.
 */
void tgt_gssiam_detach_cache_entry(struct obd_export *exp)
{
	struct upcall_cache_entry *entry;

	spin_lock(&exp->exp_lock);
	entry = exp->exp_target_data.ted_gssiam_entry;
	exp->exp_target_data.ted_gssiam_entry = NULL;
	spin_unlock(&exp->exp_lock);

	if (!entry)
		return;

	if (atomic_dec_and_test(&entry->u.gssiam.gd_export_count)) {
		/**
		 * This means no export use the upcall cache for
		 * gssiam anymore, i.e. all clients from the
		 * same principal has umount, so let's remove
		 * the entry from the upcall cache completely,
		 * then any new mount request needs to do upcall
		 * again.
		 */
		if (tgt_gssiam_cache &&
		    atomic_read(&entry->ue_refcount) == 1)
			upcall_cache_update_entry(tgt_gssiam_cache, entry, 0,
						  UC_CACHE_INVALID);
	}
	if (tgt_gssiam_cache)
		upcall_cache_put_entry(tgt_gssiam_cache, entry);
}
EXPORT_SYMBOL(tgt_gssiam_detach_cache_entry);

/**
 * tgt_gssiam_verify() - Verify GSSIAM token via target upcall cache
 * @lut: The target device (MDT/OST)
 * @exp: The existing export (connection), if any
 * @lid: The IAM descriptor provided by the client
 * @gssiam_info_ptr: Output pointer for resolved GSSIAM info
 * @gssiam_expire: Output for token expiration time
 *
 * This function orchestrates the verification of a GSSIAM token by utilizing
 * the upcall cache infrastructure. The verification flow is as follows:
 *
 * 1. Attempt to look up the (token, subdir) pair in the target's GSSIAM cache.
 * 2. On a cache miss, the upcall cache subsystem automatically triggers
 *    tgt_gssiam_do_upcall(), which delegates to the target-specific
 *    tsi_gssiam_authenticate_remote() handler on non-MDT0 targets.
 * 3. Authentication Behavior:
 *    - On MDT0: The upcall resolves the Project ID locally from the namespace
 *      via mdt_gssiam_projid_cb() and invokes the local userspace upcall
 *      (l_gssiam_auth) to cryptographically verify the token.
 *    - On Remote MDTs & OSTs: The handlers (mdt_gssiam_authenticate_remote /
 *      ofd_gssiam_authenticate_remote) delegate the verification to MDT0 via
 *      an internal RPC (tgt_gssiam_rpc_authenticate), as MDT0 is the central
 *      authority.
 * 4. Once verified (or denied), the results are cached locally.
 * 5. Finally, the function provisions the resolved identity and Project ID
 *    into the client's session context and binds it to the export.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int tgt_gssiam_verify(struct lu_target *lut, struct obd_export *exp,
		      const struct lustre_gssiam_desc *lid,
		      struct lustre_gssiam_info **gssiam_info_ptr,
		      time64_t *gssiam_expire)
{
	struct upcall_cache_entry *entry;
	int rc = 0;

	ENTRY;

	if (!lut->lut_tsi.tsi_gssiam_cache)
		RETURN(-EOPNOTSUPP);

	entry = tgt_gssiam_get_entry(lut->lut_tsi.tsi_gssiam_cache, lid,
				     &lut->lut_obd->obd_uuid);
	if (IS_ERR(entry))
		RETURN(PTR_ERR(entry));

	if (!UC_CACHE_IS_VALID(entry)) {
		CWARN("%s: entry is not valid\n", lut->lut_obd->obd_name);
		GOTO(out_put, rc = -EACCES);
	}

	/* The token is expired; client will be notified to refresh */
	if (entry->u.gssiam.gd_auth_permission & GSSIAM_AUTH_EXPIRED) {
		struct gssiam_entry_arg arg = {
			.uuid = lut->lut_obd->obd_uuid,
			.lid = lid,
		};

		upcall_cache_invalidate_one(lut->lut_tsi.tsi_gssiam_cache,
					    entry->ue_key, &arg);
		GOTO(out_put, rc = -EAGAIN);
	}

	/* The authentication is denied */
	if (!(entry->u.gssiam.gd_auth_permission &
	      (GSSIAM_AUTH_RO | GSSIAM_AUTH_RW)))
		GOTO(out_put, rc = -EPERM);

	/* Entry must have a valid non-empty principal */
	if (!entry->u.gssiam.gd_principal ||
	    !*entry->u.gssiam.gd_principal)
		GOTO(out_put, rc = -EINVAL);

	*gssiam_expire = entry->ue_expire;

	rc = tgt_gssiam_info_alloc(gssiam_info_ptr, lid, entry);
	if (rc)
		GOTO(out_put, rc);

	if (exp) {
		/* If export already exist, then attach the entry to
		 * the export directly
		 */
		tgt_gssiam_attach_cache_entry(exp, entry);
	} else if (*gssiam_info_ptr) {
		/* Otherwise store the entry to the context, which then
		 * will be attached to the export
		 * in gssiam_install_ctx()
		 */
		upcall_cache_get_entry_raw(entry);
		(*gssiam_info_ptr)->lii_gssiam_entry = entry;
	}

out_put:
	upcall_cache_put_entry(lut->lut_tsi.tsi_gssiam_cache, entry);
	RETURN(rc);
}
EXPORT_SYMBOL(tgt_gssiam_verify);
