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
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ptlrpc/gss/gss_keyring.c
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_SEC
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/key.h>
#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <linux/mutex.h>
#include <asm/atomic.h>

#include <libcfs/linux/linux-list.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_sec.h>
#include <lustre_net.h>
#include <lustre_import.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"

#ifdef HAVE_GET_REQUEST_KEY_AUTH
#include <keys/request_key_auth-type.h>
#endif

static struct ptlrpc_sec_policy gss_policy_keyring;
static struct ptlrpc_ctx_ops gss_keyring_ctxops;
static struct key_type gss_key_type;

static int sec_install_rctx_kr(struct ptlrpc_sec *sec,
                               struct ptlrpc_svc_ctx *svc_ctx);
static void request_key_unlink(struct key *key, bool fullsearch);

/*
 * the timeout is only for the case that upcall child process die abnormally.
 * in any other cases it should finally update kernel key.
 *
 * FIXME we'd better to incorporate the client & server side upcall timeouts
 * into the framework of Adaptive Timeouts, but we need to figure out how to
 * make sure that kernel knows the upcall processes is in-progress or died
 * unexpectedly.
 */
#define KEYRING_UPCALL_TIMEOUT  (obd_timeout + obd_timeout)

/* Check caller's namespace in gss_keyring upcall */
unsigned int gss_check_upcall_ns = 1;

/****************************************
 * internal helpers                     *
 ****************************************/

static inline void keyring_upcall_lock(struct gss_sec_keyring *gsec_kr)
{
#ifdef HAVE_KEYRING_UPCALL_SERIALIZED
	mutex_lock(&gsec_kr->gsk_uc_lock);
#endif
}

static inline void keyring_upcall_unlock(struct gss_sec_keyring *gsec_kr)
{
#ifdef HAVE_KEYRING_UPCALL_SERIALIZED
	mutex_unlock(&gsec_kr->gsk_uc_lock);
#endif
}

static inline void key_invalidate_locked(struct key *key)
{
	set_bit(KEY_FLAG_INVALIDATED, &key->flags);
}

static void ctx_upcall_timeout_kr(cfs_timer_cb_arg_t data)
{
	struct gss_cli_ctx_keyring *gctx_kr = cfs_from_timer(gctx_kr,
							     data, gck_timer);
	struct ptlrpc_cli_ctx *ctx = &(gctx_kr->gck_base.gc_base);
	struct obd_import *imp = ctx->cc_sec->ps_import;
	struct key *key	= gctx_kr->gck_key;

	if (key)
		CDEBUG(D_SEC,
		       "%s: GSS context (%p) negotiation timeout, invalidating key (%p)\n",
		       imp->imp_obd->obd_name, ctx, key);
	else
		CDEBUG(D_SEC,
		       "%s: GSS context (%p) negotiation timeout, ignoring already unlinked key\n",
		       imp->imp_obd->obd_name, ctx);

	cli_ctx_expire(ctx);
	if (key)
		key_invalidate_locked(key);
}

static void ctx_start_timer_kr(struct ptlrpc_cli_ctx *ctx, time64_t timeout)
{
	struct gss_cli_ctx_keyring *gctx_kr = ctx2gctx_keyring(ctx);
	struct timer_list *timer = &gctx_kr->gck_timer;

	LASSERT(timer);

	CDEBUG(D_SEC, "ctx %p: start timer %llds\n", ctx, timeout);

	cfs_timer_setup(timer, ctx_upcall_timeout_kr,
			(unsigned long)gctx_kr, 0);
	timer->expires = cfs_time_seconds(timeout) + jiffies;
	add_timer(timer);
}

/*
 * caller should make sure no race with other threads
 */
static
void ctx_clear_timer_kr(struct ptlrpc_cli_ctx *ctx)
{
        struct gss_cli_ctx_keyring *gctx_kr = ctx2gctx_keyring(ctx);
	struct timer_list          *timer = &gctx_kr->gck_timer;

        CDEBUG(D_SEC, "ctx %p, key %p\n", ctx, gctx_kr->gck_key);

        timer_delete_sync(timer);
}

static
struct ptlrpc_cli_ctx *ctx_create_kr(struct ptlrpc_sec *sec,
                                     struct vfs_cred *vcred)
{
	struct ptlrpc_cli_ctx      *ctx;
	struct gss_cli_ctx_keyring *gctx_kr;

	OBD_ALLOC_PTR(gctx_kr);
	if (gctx_kr == NULL)
		return NULL;

	cfs_timer_setup(&gctx_kr->gck_timer, NULL, 0, 0);

	ctx = &gctx_kr->gck_base.gc_base;

	if (gss_cli_ctx_init_common(sec, ctx, &gss_keyring_ctxops, vcred)) {
		OBD_FREE_PTR(gctx_kr);
		return NULL;
	}

	ctx->cc_expire = ktime_get_real_seconds() + KEYRING_UPCALL_TIMEOUT;
	clear_bit(PTLRPC_CTX_NEW_BIT, &ctx->cc_flags);
	atomic_inc(&ctx->cc_refcount); /* for the caller */

	return ctx;
}

static void ctx_destroy_kr(struct ptlrpc_cli_ctx *ctx)
{
	struct ptlrpc_sec		*sec = ctx->cc_sec;
	struct gss_cli_ctx_keyring	*gctx_kr = ctx2gctx_keyring(ctx);

	CDEBUG(D_SEC, "destroying ctx %p\n", ctx);

        /* at this time the association with key has been broken. */
        LASSERT(sec);
	LASSERT(atomic_read(&sec->ps_refcount) > 0);
	LASSERT(atomic_read(&sec->ps_nctx) > 0);
	LASSERT(test_bit(PTLRPC_CTX_CACHED_BIT, &ctx->cc_flags) == 0);
        LASSERT(gctx_kr->gck_key == NULL);

	ctx_clear_timer_kr(ctx);

	if (gss_cli_ctx_fini_common(sec, ctx))
		return;

	OBD_FREE_PTR(gctx_kr);

	atomic_dec(&sec->ps_nctx);
	sptlrpc_sec_put(sec);
}

static void ctx_release_kr(struct ptlrpc_cli_ctx *ctx, int sync)
{
	if (sync) {
		ctx_destroy_kr(ctx);
	} else {
		atomic_inc(&ctx->cc_refcount);
		sptlrpc_gc_add_ctx(ctx);
	}
}

static void ctx_put_kr(struct ptlrpc_cli_ctx *ctx, int sync)
{
	LASSERT(atomic_read(&ctx->cc_refcount) > 0);

	if (atomic_dec_and_test(&ctx->cc_refcount))
		ctx_release_kr(ctx, sync);
}

/*
 * key <-> ctx association and rules:
 * - ctx might not bind with any key
 * - key/ctx binding is protected by key semaphore (if the key present)
 * - key and ctx each take a reference of the other
 * - ctx enlist/unlist is protected by ctx spinlock
 * - never enlist a ctx after it's been unlisted
 * - whoever do enlist should also do bind, lock key before enlist:
 *   - lock key -> lock ctx -> enlist -> unlock ctx -> bind -> unlock key
 * - whoever do unlist should also do unbind:
 *   - lock key -> lock ctx -> unlist -> unlock ctx -> unbind -> unlock key
 *   - lock ctx -> unlist -> unlock ctx -> lock key -> unbind -> unlock key
 */

static inline void spin_lock_if(spinlock_t *lock, int condition)
{
	if (condition)
		spin_lock(lock);
}

static inline void spin_unlock_if(spinlock_t *lock, int condition)
{
	if (condition)
		spin_unlock(lock);
}

static void ctx_enlist_kr(struct ptlrpc_cli_ctx *ctx, int is_root, int locked)
{
	struct ptlrpc_sec	*sec = ctx->cc_sec;
	struct gss_sec_keyring	*gsec_kr = sec2gsec_keyring(sec);

	LASSERT(!test_bit(PTLRPC_CTX_CACHED_BIT, &ctx->cc_flags));
	LASSERT(atomic_read(&ctx->cc_refcount) > 0);

	spin_lock_if(&sec->ps_lock, !locked);

	atomic_inc(&ctx->cc_refcount);
	set_bit(PTLRPC_CTX_CACHED_BIT, &ctx->cc_flags);
	hlist_add_head(&ctx->cc_cache, &gsec_kr->gsk_clist);
	if (is_root)
		gsec_kr->gsk_root_ctx = ctx;

	spin_unlock_if(&sec->ps_lock, !locked);
}

/*
 * Note after this get called, caller should not access ctx again because
 * it might have been freed, unless caller hold at least one refcount of
 * the ctx.
 *
 * return non-zero if we indeed unlist this ctx.
 */
static int ctx_unlist_kr(struct ptlrpc_cli_ctx *ctx, int locked)
{
	struct ptlrpc_sec	*sec = ctx->cc_sec;
	struct gss_sec_keyring	*gsec_kr = sec2gsec_keyring(sec);

	/* if hashed bit has gone, leave the job to somebody who is doing it */
	if (test_and_clear_bit(PTLRPC_CTX_CACHED_BIT, &ctx->cc_flags) == 0)
		return 0;

	/* drop ref inside spin lock to prevent race with other operations */
	spin_lock_if(&sec->ps_lock, !locked);

	if (gsec_kr->gsk_root_ctx == ctx)
		gsec_kr->gsk_root_ctx = NULL;
	hlist_del_init(&ctx->cc_cache);
	atomic_dec(&ctx->cc_refcount);

	spin_unlock_if(&sec->ps_lock, !locked);

	return 1;
}

/*
 * Get specific payload. Newer kernels support 4 slots.
 */
static void *
key_get_payload(struct key *key, unsigned int index)
{
	void *key_ptr = NULL;

#ifdef HAVE_KEY_PAYLOAD_DATA_ARRAY
	key_ptr = key->payload.data[index];
#else
	if (!index)
		key_ptr = key->payload.data;
#endif
	return key_ptr;
}

/*
 * Set specific payload. Newer kernels support 4 slots.
 */
static int key_set_payload(struct key *key, unsigned int index,
			   struct ptlrpc_cli_ctx *ctx)
{
	int rc = -EINVAL;

#ifdef HAVE_KEY_PAYLOAD_DATA_ARRAY
	if (index < 4) {
		key->payload.data[index] = ctx;
#else
	if (!index) {
		key->payload.data = ctx;
#endif
		rc = 0;
	}
	return rc;
}

/*
 * bind a key with a ctx together.
 * caller must hold write lock of the key, as well as ref on key & ctx.
 */
static void bind_key_ctx(struct key *key, struct ptlrpc_cli_ctx *ctx)
{
	LASSERT(atomic_read(&ctx->cc_refcount) > 0);
	LASSERT(ll_read_key_usage(key) > 0);
	LASSERT(ctx2gctx_keyring(ctx)->gck_key == NULL);
	LASSERT(!key_get_payload(key, 0));

	/* at this time context may or may not in list. */
	key_get(key);
	atomic_inc(&ctx->cc_refcount);
	ctx2gctx_keyring(ctx)->gck_key = key;
	LASSERT(!key_set_payload(key, 0, ctx));
}

/*
 * unbind a key and a ctx.
 * caller must hold write lock, as well as a ref of the key.
 */
static void unbind_key_ctx(struct key *key, struct ptlrpc_cli_ctx *ctx)
{
	/* give up on invalidated or empty key,
	 * someone else already took care of it
	 */
	if (test_bit(KEY_FLAG_INVALIDATED, &key->flags) ||
	    key_get_payload(key, 0) != ctx) {
		CDEBUG(D_SEC, "key %08x already handled\n", key->serial);
		return;
	}

	/* must invalidate the key, or others may find it during lookup */
	key_invalidate_locked(key);
	request_key_unlink(key, false);

	key_set_payload(key, 0, NULL);
	ctx2gctx_keyring(ctx)->gck_key = NULL;

	/* once ctx get split from key, the timer is meaningless */
	ctx_clear_timer_kr(ctx);

	ctx_put_kr(ctx, 1);
	key_put(key);
}

/*
 * given a ctx, unbind with its coupled key, if any.
 * unbind could only be called once, so we don't worry the key be released
 * by someone else.
 */
static void unbind_ctx_kr(struct ptlrpc_cli_ctx *ctx)
{
	struct key      *key = ctx2gctx_keyring(ctx)->gck_key;

	if (key) {
		key_get(key);
		down_write(&key->sem);
		unbind_key_ctx(key, ctx);
		up_write(&key->sem);
		key_put(key);
	}
}

/*
 * given a key, unbind with its coupled ctx, if any.
 * caller must hold write lock, as well as a ref of the key.
 */
static void unbind_key_locked(struct key *key)
{
	struct ptlrpc_cli_ctx *ctx = key_get_payload(key, 0);

        if (ctx)
                unbind_key_ctx(key, ctx);
}

/*
 * unlist a ctx, and unbind from coupled key
 */
static void kill_ctx_kr(struct ptlrpc_cli_ctx *ctx)
{
        if (ctx_unlist_kr(ctx, 0))
                unbind_ctx_kr(ctx);
}

/*
 * given a key, unlist and unbind with the coupled ctx (if any).
 * caller must hold write lock, as well as a ref of the key.
 */
static void kill_key_locked(struct key *key)
{
	struct ptlrpc_cli_ctx *ctx = key_get_payload(key, 0);

        if (ctx && ctx_unlist_kr(ctx, 0))
                unbind_key_locked(key);
}

/*
 * caller should hold one ref on contexts in freelist.
 */
static void dispose_ctx_list_kr(struct hlist_head *freelist)
{
	struct hlist_node *next;
	struct ptlrpc_cli_ctx	*ctx;
	struct gss_cli_ctx	*gctx;

	hlist_for_each_entry_safe(ctx, next, freelist, cc_cache) {
		hlist_del_init(&ctx->cc_cache);

		/* reverse ctx: update current seq to buddy svcctx if exist.
		 * ideally this should be done at gss_cli_ctx_finalize(), but
		 * the ctx destroy could be delayed by:
		 *  1) ctx still has reference;
		 *  2) ctx destroy is asynchronous;
		 * and reverse import call inval_all_ctx() require this be done
		 * _immediately_ otherwise newly created reverse ctx might copy
		 * the very old sequence number from svcctx. */
		gctx = ctx2gctx(ctx);
		if (!rawobj_empty(&gctx->gc_svc_handle) &&
		    sec_is_reverse(gctx->gc_base.cc_sec)) {
			gss_svc_upcall_update_sequence(&gctx->gc_svc_handle,
					(__u32) atomic_read(&gctx->gc_seq));
		}

		/* we need to wakeup waiting reqs here. the context might
		 * be forced released before upcall finished, then the
		 * late-arrived downcall can't find the ctx even. */
		sptlrpc_cli_ctx_wakeup(ctx);

		unbind_ctx_kr(ctx);
		ctx_put_kr(ctx, 0);
	}
}

/*
 * lookup a root context directly in a sec, return root ctx with a
 * reference taken or NULL.
 */
static
struct ptlrpc_cli_ctx * sec_lookup_root_ctx_kr(struct ptlrpc_sec *sec)
{
	struct gss_sec_keyring  *gsec_kr = sec2gsec_keyring(sec);
	struct ptlrpc_cli_ctx   *ctx = NULL;
	time64_t now = ktime_get_real_seconds();

	spin_lock(&sec->ps_lock);

	ctx = gsec_kr->gsk_root_ctx;

	/* Need to find valid rev ctx if we do not have one yet,
	 * or if it is expired.
	 */
	if (unlikely(sec_is_reverse(sec)) &&
	    (ctx == NULL || ctx->cc_expire < now)) {
		struct ptlrpc_cli_ctx	*tmp;

		/* For reverse context, browse list and pick the one with
		 * shortest expire time and that has not expired yet.
		 * This one is most likely to have an established peer context
		 * on client side.
		 */
		hlist_for_each_entry(tmp, &gsec_kr->gsk_clist, cc_cache) {
			if (ctx == NULL || ctx->cc_expire == 0 ||
			    (tmp->cc_expire > now &&
			     tmp->cc_expire < ctx->cc_expire) ||
			    (ctx->cc_expire < now &&
			     tmp->cc_expire > ctx->cc_expire)) {
				ctx = tmp;
				/* promote to be root_ctx */
				gsec_kr->gsk_root_ctx = ctx;
			}
		}
	}

	if (ctx) {
		LASSERT(atomic_read(&ctx->cc_refcount) > 0);
		LASSERT(!hlist_empty(&gsec_kr->gsk_clist));
		atomic_inc(&ctx->cc_refcount);
	}

	spin_unlock(&sec->ps_lock);

	return ctx;
}

#define RVS_CTX_EXPIRE_NICE    (10)

static
void rvs_sec_install_root_ctx_kr(struct ptlrpc_sec *sec,
                                 struct ptlrpc_cli_ctx *new_ctx,
                                 struct key *key)
{
	struct gss_sec_keyring *gsec_kr = sec2gsec_keyring(sec);
	struct ptlrpc_cli_ctx *ctx;
	struct hlist_node *next;
	time64_t now;

	ENTRY;
	LASSERT(sec_is_reverse(sec));

	spin_lock(&sec->ps_lock);

	now = ktime_get_real_seconds();

	/* set all existing ctxs short expiry */
	hlist_for_each_entry_safe(ctx, next, &gsec_kr->gsk_clist, cc_cache) {
		if (ctx->cc_expire > now + RVS_CTX_EXPIRE_NICE) {
			ctx->cc_early_expire = 1;
			ctx->cc_expire = now + RVS_CTX_EXPIRE_NICE;
		} else if (ctx != gsec_kr->gsk_root_ctx &&
			   ctx->cc_expire < now) {
			/* unlist expired context to remove it from gsk_clist */
			if (ctx_unlist_kr(ctx, 1)) {
				/* release unlisted ctx to destroy it */
				set_bit(PTLRPC_CTX_DEAD_BIT, &ctx->cc_flags);
				ctx_release_kr(ctx, 1);
			}
		}
	}

	/* If there's root_ctx there, instead obsolete the current
	 * immediately, we leave it continue operating for a little while.
	 * hopefully when the first backward rpc with newest ctx send out,
	 * the client side already have the peer ctx well established.
	 */
	ctx_enlist_kr(new_ctx, gsec_kr->gsk_root_ctx ? 0 : 1, 1);

	if (key)
		bind_key_ctx(key, new_ctx);

	spin_unlock(&sec->ps_lock);
}

static void construct_key_desc(void *buf, int bufsize,
                               struct ptlrpc_sec *sec, uid_t uid)
{
        snprintf(buf, bufsize, "%d@%x", uid, sec->ps_id);
        ((char *)buf)[bufsize - 1] = '\0';
}

/****************************************
 * sec apis                             *
 ****************************************/

static
struct ptlrpc_sec * gss_sec_create_kr(struct obd_import *imp,
                                      struct ptlrpc_svc_ctx *svcctx,
                                      struct sptlrpc_flavor *sf)
{
        struct gss_sec_keyring  *gsec_kr;
        ENTRY;

        OBD_ALLOC(gsec_kr, sizeof(*gsec_kr));
        if (gsec_kr == NULL)
                RETURN(NULL);

	INIT_HLIST_HEAD(&gsec_kr->gsk_clist);
        gsec_kr->gsk_root_ctx = NULL;
	mutex_init(&gsec_kr->gsk_root_uc_lock);
#ifdef HAVE_KEYRING_UPCALL_SERIALIZED
	mutex_init(&gsec_kr->gsk_uc_lock);
#endif

        if (gss_sec_create_common(&gsec_kr->gsk_base, &gss_policy_keyring,
                                  imp, svcctx, sf))
                goto err_free;

        if (svcctx != NULL &&
            sec_install_rctx_kr(&gsec_kr->gsk_base.gs_base, svcctx)) {
                gss_sec_destroy_common(&gsec_kr->gsk_base);
                goto err_free;
        }

        RETURN(&gsec_kr->gsk_base.gs_base);

err_free:
        OBD_FREE(gsec_kr, sizeof(*gsec_kr));
        RETURN(NULL);
}

static
void gss_sec_destroy_kr(struct ptlrpc_sec *sec)
{
        struct gss_sec          *gsec = sec2gsec(sec);
        struct gss_sec_keyring  *gsec_kr = sec2gsec_keyring(sec);

        CDEBUG(D_SEC, "destroy %s@%p\n", sec->ps_policy->sp_name, sec);

	LASSERT(atomic_read(&sec->ps_nctx) == 0);
	LASSERT(hlist_empty(&gsec_kr->gsk_clist));
        LASSERT(gsec_kr->gsk_root_ctx == NULL);

        gss_sec_destroy_common(gsec);

        OBD_FREE(gsec_kr, sizeof(*gsec_kr));
}

static inline int user_is_root(struct ptlrpc_sec *sec, struct vfs_cred *vcred)
{
        /* except the ROOTONLY flag, treat it as root user only if real uid
         * is 0, euid/fsuid being 0 are handled as setuid scenarios */
        if (sec_is_rootonly(sec) || (vcred->vc_uid == 0))
                return 1;
        else
                return 0;
}

/*
 * When lookup_user_key is available use the kernel API rather than directly
 * accessing the uid_keyring and session_keyring via the current process
 * credentials.
 */
#ifdef HAVE_LOOKUP_USER_KEY

#ifdef HAVE_KEY_NEED_UNLINK
/* from Linux security/keys/internal.h: */
#  ifndef KEY_LOOKUP_PARTIAL
#    define KEY_LOOKUP_PARTIAL 0x2
#  endif
#else
#  define KEY_NEED_UNLINK 0
#  ifndef KEY_LOOKUP_FOR_UNLINK
#    define KEY_LOOKUP_FOR_UNLINK 0x4
#  endif
#  define KEY_LOOKUP_PARTIAL KEY_LOOKUP_FOR_UNLINK
#endif /* HAVE_KEY_NEED_UNLINK */

static struct key *_user_key(key_serial_t id)
{
	key_ref_t ref;

	might_sleep();
	ref = lookup_user_key(id, KEY_LOOKUP_PARTIAL, KEY_NEED_UNLINK);
	if (IS_ERR(ref))
		return NULL;
	return key_ref_to_ptr(ref);
}

static inline struct key *get_user_session_keyring(const struct cred *cred)
{
	return _user_key(KEY_SPEC_USER_SESSION_KEYRING);
}

static inline struct key *get_user_keyring(const struct cred *cred)
{
	return _user_key(KEY_SPEC_USER_KEYRING);
}

static inline struct key *get_session_keyring(const struct cred *cred)
{
	return _user_key(KEY_SPEC_SESSION_KEYRING);
}
#else
static inline struct key *get_user_session_keyring(const struct cred *cred)
{
	return key_get(cred->user->session_keyring);
}

static inline struct key *get_user_keyring(const struct cred *cred)
{
	return key_get(cred->user->uid_keyring);
}

static inline struct key *get_session_keyring(const struct cred *cred)
{
	return key_get(cred->session_keyring);
}
#endif

/*
 * Get the appropriate destination keyring for the request.
 *
 * The keyring selected is returned with an extra reference upon it which the
 * caller must release.
 */
/*
 * Function inspired from the kernel's one, unfortunately not exported.
 */
static int construct_get_dest_keyring(struct key **_dest_keyring)
{
	struct key *dest_keyring = *_dest_keyring;
	const struct cred *cred = current_cred();

	if (dest_keyring) {
		/* the caller supplied one */
		key_get(dest_keyring);
		return 0;
	}

	switch (cred->jit_keyring) {
	case KEY_REQKEY_DEFL_DEFAULT:
	case KEY_REQKEY_DEFL_REQUESTOR_KEYRING:
#ifdef HAVE_GET_REQUEST_KEY_AUTH
		if (cred->request_key_auth) {
			struct request_key_auth *rka;
			struct key *authkey = cred->request_key_auth;

			down_read(&authkey->sem);
			rka = get_request_key_auth(authkey);
			if (!test_bit(KEY_FLAG_REVOKED, &authkey->flags))
				dest_keyring = key_get(rka->dest_keyring);
			up_read(&authkey->sem);
			if (dest_keyring)
				break;
		}
#endif
		fallthrough;
	case KEY_REQKEY_DEFL_THREAD_KEYRING:
		dest_keyring = key_get(cred->thread_keyring);
		if (dest_keyring)
			break;
		fallthrough;
	case KEY_REQKEY_DEFL_PROCESS_KEYRING:
		dest_keyring = key_get(cred->process_keyring);
		if (dest_keyring)
			break;
		fallthrough;
	case KEY_REQKEY_DEFL_SESSION_KEYRING:
		dest_keyring = get_session_keyring(cred);
		if (dest_keyring) {
			if (!test_bit(KEY_FLAG_REVOKED, &dest_keyring->flags))
				break;
			key_put(dest_keyring);
		}
		fallthrough;
	case KEY_REQKEY_DEFL_USER_SESSION_KEYRING:
		dest_keyring = get_user_session_keyring(cred);
		break;
	case KEY_REQKEY_DEFL_USER_KEYRING:
		dest_keyring = get_user_keyring(cred);
		break;
	case KEY_REQKEY_DEFL_GROUP_KEYRING:
	default:
		LBUG();
	}

	*_dest_keyring = dest_keyring;
	return 0;
}

/*
 * Unlink key from its keyring, which was linked during request_key().
 */
static void request_key_unlink(struct key *key, bool fullsearch)
{
	kuid_t kuid_orig = current_cred()->user->uid;
#ifdef HAVE_USER_UID_KEYRING
	struct key *root_uid_keyring = NULL;
#endif
	const struct cred *old_cred = NULL;
	struct cred *new_cred = NULL;
	struct key *ring = NULL;
	uid_t uid, key_uid;
	int res;

	uid = from_kuid(current_user_ns(), kuid_orig);
	key_uid = from_kuid(&init_user_ns, key->uid);
	/* unlink key with user's creds if it's a user key */
	if (key_uid != uid) {
		new_cred = prepare_creds();
		if (new_cred == NULL)
			goto search;

		new_cred->uid = key->uid;
		new_cred->user->uid = key->uid;
		if (new_cred->user_ns != &init_user_ns) {
			put_user_ns(new_cred->user_ns);
			new_cred->user_ns = get_user_ns(&init_user_ns);
		}
#ifdef HAVE_USER_UID_KEYRING
		root_uid_keyring = current_cred()->user->uid_keyring;
		new_cred->user->uid_keyring = NULL;
#endif
		old_cred = override_creds(new_cred);
	}

	/* User keys are linked to the user keyring. So get it now. */
	if (key_uid && !fullsearch) {
		/* Getting a key(ring) normally increases its refcount by 1.
		 * But if we overrode creds above, calling get_user_keyring()
		 * will add one more ref, because of the user switch.
		 */
		ring = get_user_keyring(current_cred());
	} else {
search:
		if (construct_get_dest_keyring(&ring))
			ring = NULL;
	}

	if (ring) {
		res = key_unlink(ring, key);
		CDEBUG(D_SEC,
		       "Unlink key %08x (%p) from keyring %08x: %d\n",
		       key->serial, key, ring->serial, res);
		/* matches key_get()/get_user_keyring() above */
		key_put(ring);
	} else {
		CDEBUG(D_SEC,
		       "Missing keyring, key %08x (%p) could not be unlinked, ignored\n",
		       key->serial, key);
	}

	if (old_cred) {
		revert_creds(old_cred);
		put_cred(new_cred);
		current_cred()->user->uid = kuid_orig;
#ifdef HAVE_USER_UID_KEYRING
		/* We are switching creds back, so need to drop ref on keyring
		 * for kernel implementation based on user keyring pinned from
		 * the user_struct struct.
		 */
		if (key_uid && !fullsearch)
			key_put(ring);
		if (root_uid_keyring)
			current_cred()->user->uid_keyring = root_uid_keyring;
#endif
	}
}

/**
 * \retval a valid context on success
 * \retval -ev error number or NULL on error
 */
static
struct ptlrpc_cli_ctx * gss_sec_lookup_ctx_kr(struct ptlrpc_sec *sec,
                                              struct vfs_cred *vcred,
                                              int create, int remove_dead)
{
	struct obd_import *imp = sec->ps_import;
	struct gss_sec_keyring *gsec_kr = sec2gsec_keyring(sec);
	struct ptlrpc_cli_ctx *ctx = NULL;
	unsigned int is_root = 0, create_new = 0;
	const struct cred *old_cred = NULL;
	struct cred *new_cred = NULL;
	struct key *key;
	char desc[24];
	char *coinfo;
	int coinfo_size;
	const char *sec_part_flags = "";
	char svc_flag = '-';
	pid_t caller_pid;
	struct lnet_nid primary;
	ENTRY;

	LASSERT(imp != NULL);

	is_root = user_is_root(sec, vcred);

	/* a little bit optimization for root context */
	if (is_root) {
		ctx = sec_lookup_root_ctx_kr(sec);
		/*
		 * Only lookup directly for REVERSE sec, which should
		 * always succeed.
		 */
		if (ctx || sec_is_reverse(sec))
			RETURN(ctx);
	}

	if (!create)
		RETURN(ERR_PTR(-ENODATA));

	/* for root context, obtain lock and check again, this time hold
	 * the root upcall lock, make sure nobody else populated new root
	 * context after last check.
	 */
	if (is_root) {
		mutex_lock(&gsec_kr->gsk_root_uc_lock);

		ctx = sec_lookup_root_ctx_kr(sec);
		if (ctx)
			goto out;

		/* update reverse handle for root user */
		sec2gsec(sec)->gs_rvs_hdl = gss_get_next_ctx_index();

		switch (sec->ps_part) {
		case LUSTRE_SP_MDT:
			sec_part_flags = "m";
			break;
		case LUSTRE_SP_OST:
			sec_part_flags = "o";
			break;
		case LUSTRE_SP_MGC:
			sec_part_flags = "rmo";
			break;
		case LUSTRE_SP_CLI:
			sec_part_flags = "r";
			break;
		case LUSTRE_SP_MGS:
		default:
			LBUG();
		}

		switch (SPTLRPC_FLVR_SVC(sec->ps_flvr.sf_rpc)) {
		case SPTLRPC_SVC_NULL:
			svc_flag = 'n';
			break;
		case SPTLRPC_SVC_AUTH:
			svc_flag = 'a';
			break;
		case SPTLRPC_SVC_INTG:
			svc_flag = 'i';
			break;
		case SPTLRPC_SVC_PRIV:
			svc_flag = 'p';
			break;
		default:
			LBUG();
		}
	}

	/* in case of setuid, key will be constructed as owner of fsuid/fsgid,
	 * but we do authentication based on real uid/gid. the key permission
	 * bits will be exactly as POS_ALL, so only processes who subscribed
	 * this key could have the access, although the quota might be counted
	 * on others (fsuid/fsgid).
	 *
	 * keyring will use fsuid/fsgid as upcall parameters, so we have to
	 * encode real uid/gid into callout info.
	 */

	/* But first we need to make sure the obd type is supported */
	if (strcmp(imp->imp_obd->obd_type->typ_name, LUSTRE_MDC_NAME) &&
	    strcmp(imp->imp_obd->obd_type->typ_name, LUSTRE_OSC_NAME) &&
	    strcmp(imp->imp_obd->obd_type->typ_name, LUSTRE_MGC_NAME) &&
	    strcmp(imp->imp_obd->obd_type->typ_name, LUSTRE_LWP_NAME) &&
	    strcmp(imp->imp_obd->obd_type->typ_name, LUSTRE_OSP_NAME)) {
		CERROR("obd %s is not a supported device\n",
		       imp->imp_obd->obd_name);
		GOTO(out, ctx = NULL);
	}

	construct_key_desc(desc, sizeof(desc), sec, vcred->vc_uid);

	/* callout info format:
	 * secid:mech:uid:gid:sec_flags:svc_flag:svc_type:peer_nid:target_uuid:
	 * self_nid:pid
	 */
	coinfo_size = sizeof(struct obd_uuid) + MAX_OBD_NAME + 64;
	OBD_ALLOC(coinfo, coinfo_size);
	if (coinfo == NULL)
		goto out;

	/* Last callout parameter is pid of process whose namespace will be used
	 * for credentials' retrieval.
	 */
	if (gss_check_upcall_ns) {
		/* For user's credentials (in which case sec_part_flags is
		 * empty), use current PID instead of import's reference
		 * PID to get reference namespace.
		 */
		if (sec_part_flags[0] == '\0')
			caller_pid = current->pid;
		else
			caller_pid = imp->imp_sec_refpid;
	} else {
		/* Do not switch namespace in gss keyring upcall. */
		caller_pid = 0;
	}
	primary = imp->imp_connection->c_self;
	LNetPrimaryNID(&primary);

	/* FIXME !! Needs to support larger NIDs */
	snprintf(coinfo, coinfo_size, "%d:%s:%u:%u:%s:%c:%d:%#llx:%s:%#llx:%d",
		 sec->ps_id, sec2gsec(sec)->gs_mech->gm_name,
		 vcred->vc_uid, vcred->vc_gid,
		 sec_part_flags, svc_flag, import_to_gss_svc(imp),
		 lnet_nid_to_nid4(&imp->imp_connection->c_peer.nid),
		 imp->imp_obd->obd_name,
		 lnet_nid_to_nid4(&primary),
		 caller_pid);

	CDEBUG(D_SEC, "requesting key for %s\n", desc);

	if (vcred->vc_uid) {
		/* If the session keyring is revoked, it must not be used by
		 * request_key(), otherwise we would get -EKEYREVOKED and
		 * the user keyring would not even be searched.
		 * So prepare new creds with no session keyring.
		 */
		if (current_cred()->session_keyring &&
		    test_bit(KEY_FLAG_REVOKED,
			     &current_cred()->session_keyring->flags)) {
			new_cred = prepare_creds();
			if (new_cred) {
				new_cred->session_keyring = NULL;
				old_cred = override_creds(new_cred);
			}
		}
	}

	keyring_upcall_lock(gsec_kr);
	key = request_key(&gss_key_type, desc, coinfo);
	keyring_upcall_unlock(gsec_kr);
	if (old_cred) {
		revert_creds(old_cred);
		put_cred(new_cred);
	}

	OBD_FREE(coinfo, coinfo_size);

	if (IS_ERR(key)) {
		CERROR("%s: request key failed for uid %d: rc = %ld\n",
		       imp->imp_obd->obd_name, vcred->vc_uid,
		       PTR_ERR(key));
		ctx = ERR_CAST(key);
		goto out;
	}
	CDEBUG(D_SEC, "obtained key %08x for %s\n", key->serial, desc);

	/* once payload.data was pointed to a ctx, it never changes until
	 * we de-associate them; but parallel request_key() may return
	 * a key with payload.data == NULL at the same time. so we still
	 * need wirtelock of key->sem to serialize them.
	 */
	down_write(&key->sem);

	ctx = key_get_payload(key, 0);
	if (likely(ctx)) {
		LASSERT(atomic_read(&ctx->cc_refcount) >= 1);
		LASSERT(ctx2gctx_keyring(ctx)->gck_key == key);
		LASSERT(ll_read_key_usage(key) >= 2);

		/* simply take a ref and return. it's upper layer's
		 * responsibility to detect & replace dead ctx.
		 */
		atomic_inc(&ctx->cc_refcount);
	} else {
		/* pre initialization with a cli_ctx. this can't be done in
		 * key_instantiate() because we'v no enough information
		 * there.
		 */
		ctx = ctx_create_kr(sec, vcred);
		if (ctx != NULL) {
			ctx_enlist_kr(ctx, is_root, 0);
			bind_key_ctx(key, ctx);

			ctx_start_timer_kr(ctx, KEYRING_UPCALL_TIMEOUT);

			CDEBUG(D_SEC, "installed key %p <-> ctx %p (sec %p)\n",
			       key, ctx, sec);
		} else {
			CDEBUG(D_SEC, "invalidating key %08x (%p)\n",
			       key->serial, key);
			key_invalidate_locked(key);
		}

		create_new = 1;
	}

	up_write(&key->sem);

	/* We want user keys to be linked to the user keyring (see call to
	 * keyctl_instantiate() from prepare_and_instantiate() in userspace).
	 * But internally request_key() links the key to the session or
	 * user session keyring, depending on jit_keyring value. Avoid that by
	 * unlinking the key from this keyring. It will spare
	 * us pain when we need to remove the key later on.
	 */
	if (!is_root || create_new)
		request_key_unlink(key, true);

	key_put(key);
out:
	if (is_root)
		mutex_unlock(&gsec_kr->gsk_root_uc_lock);
	RETURN(ctx);
}

static
void gss_sec_release_ctx_kr(struct ptlrpc_sec *sec,
                            struct ptlrpc_cli_ctx *ctx,
                            int sync)
{
	LASSERT(atomic_read(&sec->ps_refcount) > 0);
	LASSERT(atomic_read(&ctx->cc_refcount) == 0);
        ctx_release_kr(ctx, sync);
}

/*
 * flush context of normal user, we must resort to keyring itself to find out
 * contexts which belong to me.
 *
 * Note here we suppose only to flush _my_ context, the "uid" will
 * be ignored in the search.
 */
static void flush_user_ctx_cache_kr(struct ptlrpc_sec *sec, uid_t uid,
				    int grace, int force)
{
	const struct cred *old_cred = NULL;
	struct cred *new_cred = NULL;
	struct key *key;
	char desc[24];

	/* nothing to do for reverse or rootonly sec */
	if (sec_is_reverse(sec) || sec_is_rootonly(sec))
		return;

	construct_key_desc(desc, sizeof(desc), sec, uid);

	if (uid) {
		/* If the session keyring is revoked, it must not be used by
		 * request_key(), otherwise we would get -EKEYREVOKED and
		 * the user keyring would not even be searched.
		 * So prepare new creds with no session keyring.
		 */
		if (current_cred()->session_keyring &&
		    test_bit(KEY_FLAG_REVOKED,
			     &current_cred()->session_keyring->flags)) {
			new_cred = prepare_creds();
			if (new_cred) {
				new_cred->session_keyring = NULL;
				old_cred = override_creds(new_cred);
			}
		}
	}

	/* there should be only one valid key, but we put it in the
	 * loop in case of any weird cases */
	for (;;) {
		key = request_key(&gss_key_type, desc, NULL);
		if (IS_ERR(key)) {
			CDEBUG(D_SEC,
			       "No more key found for current user: rc=%ld\n",
				PTR_ERR(key));
			break;
		}

		down_write(&key->sem);

		kill_key_locked(key);

		/* kill_key_locked() should usually revoke the key, but we
		 * invalidate it as well to completely get rid of it.
		 */
		key_invalidate_locked(key);

		up_write(&key->sem);
		key_put(key);
	}

	if (old_cred) {
		revert_creds(old_cred);
		put_cred(new_cred);
	}
}

/*
 * flush context of root or all, we iterate through the list.
 */
static
void flush_spec_ctx_cache_kr(struct ptlrpc_sec *sec, uid_t uid, int grace,
			     int force)
{
	struct gss_sec_keyring	*gsec_kr;
	struct hlist_head	 freelist = HLIST_HEAD_INIT;
	struct hlist_node *next;
	struct ptlrpc_cli_ctx	*ctx;
	ENTRY;

        gsec_kr = sec2gsec_keyring(sec);

	spin_lock(&sec->ps_lock);
	hlist_for_each_entry_safe(ctx, next, &gsec_kr->gsk_clist,
				  cc_cache) {
		LASSERT(atomic_read(&ctx->cc_refcount) > 0);

		if (uid != -1 && uid != ctx->cc_vcred.vc_uid)
			continue;

		/* at this moment there's at least 2 base reference:
		 * key association and in-list. */
		if (atomic_read(&ctx->cc_refcount) > 2) {
			if (!force)
				continue;
			CWARN("flush busy ctx %p(%u->%s, extra ref %d)\n",
			      ctx, ctx->cc_vcred.vc_uid,
			      sec2target_str(ctx->cc_sec),
			      atomic_read(&ctx->cc_refcount) - 2);
		}

		set_bit(PTLRPC_CTX_DEAD_BIT, &ctx->cc_flags);
		if (!grace)
			clear_bit(PTLRPC_CTX_UPTODATE_BIT, &ctx->cc_flags);

		atomic_inc(&ctx->cc_refcount);

		if (ctx_unlist_kr(ctx, 1)) {
			hlist_add_head(&ctx->cc_cache, &freelist);
		} else {
			LASSERT(atomic_read(&ctx->cc_refcount) >= 2);
			atomic_dec(&ctx->cc_refcount);
		}
	}
	spin_unlock(&sec->ps_lock);

	dispose_ctx_list_kr(&freelist);
	EXIT;
}

static
int gss_sec_flush_ctx_cache_kr(struct ptlrpc_sec *sec,
                               uid_t uid, int grace, int force)
{
	ENTRY;

	CDEBUG(D_SEC, "sec %p(%d, nctx %d), uid %d, grace %d, force %d\n",
	       sec, atomic_read(&sec->ps_refcount),
	       atomic_read(&sec->ps_nctx),
	       uid, grace, force);

	if (uid != -1 && uid != 0)
		flush_user_ctx_cache_kr(sec, uid, grace, force);
	else
		flush_spec_ctx_cache_kr(sec, uid, grace, force);

	RETURN(0);
}

static
void gss_sec_gc_ctx_kr(struct ptlrpc_sec *sec)
{
	struct gss_sec_keyring *gsec_kr = sec2gsec_keyring(sec);
	struct hlist_head freelist = HLIST_HEAD_INIT;
	struct ptlrpc_cli_ctx *ctx;
	struct gss_cli_ctx *gctx;
	struct hlist_node *next;
	ENTRY;

	CDEBUG(D_SEC, "running gc\n");

	spin_lock(&sec->ps_lock);
	hlist_for_each_entry_safe(ctx, next, &gsec_kr->gsk_clist,
				  cc_cache) {
		LASSERT(atomic_read(&ctx->cc_refcount) > 0);

		atomic_inc(&ctx->cc_refcount);

		if (cli_ctx_check_death(ctx) && ctx_unlist_kr(ctx, 1)) {
			gctx = ctx2gctx(ctx);

			hlist_add_head(&ctx->cc_cache, &freelist);
			CWARN("%s: cleaning gss ctx hdl %#llx:%#llx\n",
			      ctx->cc_sec->ps_import->imp_obd->obd_name,
			      gss_handle_to_u64(&gctx->gc_handle),
			      gss_handle_to_u64(&gctx->gc_svc_handle));
		} else {
			LASSERT(atomic_read(&ctx->cc_refcount) >= 2);
			atomic_dec(&ctx->cc_refcount);
		}
	}
	spin_unlock(&sec->ps_lock);

	dispose_ctx_list_kr(&freelist);
	EXIT;
}

static
int gss_sec_display_kr(struct ptlrpc_sec *sec, struct seq_file *seq)
{
	struct gss_sec_keyring *gsec_kr = sec2gsec_keyring(sec);
	struct hlist_node *next;
	struct ptlrpc_cli_ctx *ctx;
	struct gss_cli_ctx *gctx;
	struct ptlrpc_connection *conn;
	time64_t now = ktime_get_real_seconds();

	ENTRY;
	spin_lock(&sec->ps_lock);
	hlist_for_each_entry_safe(ctx, next, &gsec_kr->gsk_clist,
				  cc_cache) {
		struct key *key;
		char flags_str[40];
		char mech[40];

		gctx = ctx2gctx(ctx);
		key = ctx2gctx_keyring(ctx)->gck_key;
		if (sec_is_reverse(sec) &&
		    ctx->cc_sec && ctx->cc_sec->ps_import &&
		    ctx->cc_sec->ps_import->imp_connection)
			conn = ctx->cc_sec->ps_import->imp_connection;
		else
			conn = NULL;

		gss_cli_ctx_flags2str(ctx->cc_flags,
				      flags_str, sizeof(flags_str));

		if (gctx->gc_mechctx)
			lgss_display(gctx->gc_mechctx, mech, sizeof(mech));
		else
			snprintf(mech, sizeof(mech), "N/A");
		mech[sizeof(mech) - 1] = '\0';

		seq_printf(seq,
			   "- { %s%s%suid: %u, ctxref: %d, expire: %lld, delta: %lld, flags: [%s], seq: %d, win: %u, key: %08x, keyref: %d, hdl: \"%#llx:%#llx\", mech: \"%s\" }\n",
			   conn ? "peer_nid: " : "",
			   conn ? libcfs_nidstr(&conn->c_peer.nid) : "",
			   conn ? ", " : "",
			   ctx->cc_vcred.vc_uid, atomic_read(&ctx->cc_refcount),
			   ctx->cc_expire,
			   ctx->cc_expire ?  ctx->cc_expire - now : 0,
			   flags_str, atomic_read(&gctx->gc_seq),
			   gctx->gc_win, key ? key->serial : 0,
			   key ? ll_read_key_usage(key) : 0,
			   gss_handle_to_u64(&gctx->gc_handle),
			   gss_handle_to_u64(&gctx->gc_svc_handle),
			   mech);
	}
	spin_unlock(&sec->ps_lock);

	RETURN(0);
}

/****************************************
 * cli_ctx apis                         *
 ****************************************/

static
int gss_cli_ctx_refresh_kr(struct ptlrpc_cli_ctx *ctx)
{
	/* upcall is already on the way */
	struct gss_cli_ctx *gctx = ctx ? ctx2gctx(ctx) : NULL;

	/* record latest sequence number in buddy svcctx */
	if (gctx && !rawobj_empty(&gctx->gc_svc_handle) &&
	    sec_is_reverse(gctx->gc_base.cc_sec)) {
		return gss_svc_upcall_update_sequence(&gctx->gc_svc_handle,
					     (__u32)atomic_read(&gctx->gc_seq));
	}
	return 0;
}

static
int gss_cli_ctx_validate_kr(struct ptlrpc_cli_ctx *ctx)
{
	LASSERT(atomic_read(&ctx->cc_refcount) > 0);
	LASSERT(ctx->cc_sec);

	if (cli_ctx_check_death(ctx)) {
		kill_ctx_kr(ctx);
		return 1;
	}

	if (cli_ctx_is_ready(ctx))
		return 0;
	return 1;
}

static
void gss_cli_ctx_die_kr(struct ptlrpc_cli_ctx *ctx, int grace)
{
	LASSERT(atomic_read(&ctx->cc_refcount) > 0);
	LASSERT(ctx->cc_sec);

	cli_ctx_expire(ctx);
	kill_ctx_kr(ctx);
}

/****************************************
 * (reverse) service                    *
 ****************************************/

/*
 * reverse context could have nothing to do with keyrings. here we still keep
 * the version which bind to a key, for future reference.
 */
#define HAVE_REVERSE_CTX_NOKEY

#ifdef HAVE_REVERSE_CTX_NOKEY

static
int sec_install_rctx_kr(struct ptlrpc_sec *sec,
			struct ptlrpc_svc_ctx *svc_ctx)
{
	struct ptlrpc_cli_ctx *cli_ctx;
	struct vfs_cred vcred = { .vc_uid = 0 };
	int rc;

        LASSERT(sec);
        LASSERT(svc_ctx);

        cli_ctx = ctx_create_kr(sec, &vcred);
        if (cli_ctx == NULL)
                return -ENOMEM;

        rc = gss_copy_rvc_cli_ctx(cli_ctx, svc_ctx);
        if (rc) {
                CERROR("failed copy reverse cli ctx: %d\n", rc);

                ctx_put_kr(cli_ctx, 1);
                return rc;
        }

        rvs_sec_install_root_ctx_kr(sec, cli_ctx, NULL);

        ctx_put_kr(cli_ctx, 1);

        return 0;
}

#else /* ! HAVE_REVERSE_CTX_NOKEY */

static
int sec_install_rctx_kr(struct ptlrpc_sec *sec,
			struct ptlrpc_svc_ctx *svc_ctx)
{
	struct ptlrpc_cli_ctx *cli_ctx = NULL;
	struct key *key;
	struct vfs_cred vcred = { .vc_uid = 0 };
	char desc[64];
	int rc;

        LASSERT(sec);
        LASSERT(svc_ctx);
        CWARN("called\n");

        construct_key_desc(desc, sizeof(desc), sec, 0);

        key = key_alloc(&gss_key_type, desc, 0, 0,
                        KEY_POS_ALL | KEY_USR_ALL, 1);
        if (IS_ERR(key)) {
                CERROR("failed to alloc key: %ld\n", PTR_ERR(key));
                return PTR_ERR(key);
        }

        rc = key_instantiate_and_link(key, NULL, 0, NULL, NULL);
        if (rc) {
                CERROR("failed to instantiate key: %d\n", rc);
                goto err_revoke;
        }

        down_write(&key->sem);

	LASSERT(!key_get_payload(key, 0));

        cli_ctx = ctx_create_kr(sec, &vcred);
        if (cli_ctx == NULL) {
                rc = -ENOMEM;
                goto err_up;
        }

        rc = gss_copy_rvc_cli_ctx(cli_ctx, svc_ctx);
        if (rc) {
                CERROR("failed copy reverse cli ctx: %d\n", rc);
                goto err_put;
        }

        rvs_sec_install_root_ctx_kr(sec, cli_ctx, key);

        ctx_put_kr(cli_ctx, 1);
        up_write(&key->sem);

        rc = 0;
        CWARN("ok!\n");
out:
        key_put(key);
        return rc;

err_put:
        ctx_put_kr(cli_ctx, 1);
err_up:
        up_write(&key->sem);
err_revoke:
        key_revoke(key);
        goto out;
}

#endif /* HAVE_REVERSE_CTX_NOKEY */

/****************************************
 * service apis                         *
 ****************************************/

static
int gss_svc_accept_kr(struct ptlrpc_request *req)
{
        return gss_svc_accept(&gss_policy_keyring, req);
}

static
int gss_svc_install_rctx_kr(struct obd_import *imp,
                            struct ptlrpc_svc_ctx *svc_ctx)
{
        struct ptlrpc_sec *sec;
        int                rc;

        sec = sptlrpc_import_sec_ref(imp);
        LASSERT(sec);

        rc = sec_install_rctx_kr(sec, svc_ctx);
        sptlrpc_sec_put(sec);

        return rc;
}

/****************************************
 * key apis                             *
 ****************************************/

static
#ifdef HAVE_KEY_TYPE_INSTANTIATE_2ARGS
int gss_kt_instantiate(struct key *key, struct key_preparsed_payload *prep)
{
	const void *data = prep->data;
	size_t datalen = prep->datalen;
#else
int gss_kt_instantiate(struct key *key, const void *data, size_t datalen)
{
#endif
	struct key *keyring;
	int uid, rc;

	ENTRY;

	CDEBUG(D_SEC, "instantiating key %08x (%p)\n", key->serial, key);

	if (data != NULL || datalen != 0) {
		CERROR("invalid: data %p, len %lu\n", data, (long)datalen);
		RETURN(-EINVAL);
	}

	if (key_get_payload(key, 0)) {
		CERROR("key already have payload\n");
		RETURN(-EINVAL);
	}

	/* link the key to session keyring, so following context negotiation
	 * rpc fired from user space could find this key. This will be unlinked
	 * automatically when upcall processes die.
	 *
	 * we can't do this through keyctl from userspace, because the upcall
	 * might be neither possessor nor owner of the key (setuid).
	 *
	 * the session keyring is created upon upcall, and don't change all
	 * the way until upcall finished, so rcu lock is not needed here.
	 *
	 * But for end users, link to the user keyring. This simplifies key
	 * management, makes them shared accross all user sessions, and avoids
	 * unfortunate key leak if lfs flushctx is not called at user logout.
	 */
	uid = from_kuid(&init_user_ns, current_uid());
	if (uid == 0)
		keyring = get_session_keyring(current_cred());
	else
		keyring = get_user_keyring(current_cred());

	lockdep_off();
	rc = key_link(keyring, key);
	lockdep_on();
	if (unlikely(rc)) {
		CERROR("failed to link key %08x to keyring %08x: %d\n",
		       key->serial, keyring->serial, rc);
		GOTO(out, rc);
	}

	CDEBUG(D_SEC,
	      "key %08x (%p) linked to keyring %08x and instantiated, ctx %p\n",
	       key->serial, key, keyring->serial, key_get_payload(key, 0));
out:
	key_put(keyring);
	RETURN(rc);
}

/*
 * called with key semaphore write locked. it means we can operate
 * on the context without fear of loosing refcount.
 */
static
#ifdef HAVE_KEY_TYPE_INSTANTIATE_2ARGS
int gss_kt_update(struct key *key, struct key_preparsed_payload *prep)
{
	const void *data = prep->data;
	__u32 datalen32 = (__u32) prep->datalen;
#else
int gss_kt_update(struct key *key, const void *data, size_t datalen)
{
	__u32 datalen32 = (__u32) datalen;
#endif
	struct ptlrpc_cli_ctx *ctx = key_get_payload(key, 0);
	struct gss_cli_ctx *gctx;
	rawobj_t tmpobj = RAWOBJ_EMPTY;
	int rc;
	ENTRY;

	CDEBUG(D_SEC, "updating key %08x (%p)\n", key->serial, key);

	if (data == NULL || datalen32 == 0) {
		CWARN("invalid: data %p, len %lu\n", data, (long)datalen32);
		RETURN(-EINVAL);
	}

	/* if upcall finished negotiation too fast (mostly likely because
	 * of local error happened) and call kt_update(), the ctx
	 * might be still NULL. but the key will finally be associate
	 * with a context, or be revoked. if key status is fine, return
	 * -EAGAIN to allow userspace sleep a while and call again. */
	if (ctx == NULL) {
		CDEBUG(D_SEC, "update too soon: key %08x (%p) flags %lx\n",
		       key->serial, key, key->flags);

		rc = key_validate(key);
		if (rc == 0)
			RETURN(-EAGAIN);
		else
			RETURN(rc);
	}

	LASSERT(atomic_read(&ctx->cc_refcount) > 0);
	LASSERT(ctx->cc_sec);

	ctx_clear_timer_kr(ctx);

	/* don't proceed if already refreshed */
	if (cli_ctx_is_refreshed(ctx)) {
		CWARN("ctx already done refresh\n");
		RETURN(0);
	}

	sptlrpc_cli_ctx_get(ctx);
	gctx = ctx2gctx(ctx);

	rc = buffer_extract_bytes(&data, &datalen32, &gctx->gc_win,
				  sizeof(gctx->gc_win));
	if (rc) {
		CERROR("failed extract seq_win\n");
		goto out;
	}

	if (gctx->gc_win == 0) {
		__u32   nego_rpc_err, nego_gss_err;

		rc = buffer_extract_bytes(&data, &datalen32, &nego_rpc_err,
					  sizeof(nego_rpc_err));
		if (rc) {
			CERROR("cannot extract RPC: rc = %d\n", rc);
			goto out;
		}

		rc = buffer_extract_bytes(&data, &datalen32, &nego_gss_err,
					  sizeof(nego_gss_err));
		if (rc) {
			CERROR("failed to extract gss rc = %d\n", rc);
			goto out;
		}

		CERROR("negotiation: rpc err %d, gss err %x\n",
		       nego_rpc_err, nego_gss_err);

		rc = nego_rpc_err ? nego_rpc_err : -EACCES;
	} else {
		rc = rawobj_extract_local_alloc(&gctx->gc_handle,
						(__u32 **) &data, &datalen32);
		if (rc) {
			CERROR("failed extract handle\n");
			goto out;
		}

		rc = rawobj_extract_local(&tmpobj,
					  (__u32 **) &data, &datalen32);
		if (rc) {
			CERROR("failed extract mech\n");
			goto out;
		}

		rc = lgss_import_sec_context(&tmpobj,
					     sec2gsec(ctx->cc_sec)->gs_mech,
					     &gctx->gc_mechctx);
		if (rc != GSS_S_COMPLETE)
			CERROR("failed import context\n");
		else
			rc = 0;
	}
out:
	CDEBUG(D_SEC, "update of key %08x (%p): %d\n", key->serial, key, rc);
	/* we don't care what current status of this ctx, even someone else
	 * is operating on the ctx at the same time. we just add up our own
	 * opinions here. */
	if (rc == 0) {
		gss_cli_ctx_uptodate(gctx);
		/* In case of success, only the companion key for root ctx can
		 * be unbound. User keys are required to be able to retrieve
		 * the associated gss context.
		 */
		if (ctx->cc_vcred.vc_uid == 0)
			unbind_key_ctx(key, ctx);
	} else {
		/* In case of failure, unbind the companion key for all contexts
		 * i.e root and regular users. It will also invalidate the key.
		 */
		unbind_key_ctx(key, ctx);
		if (rc != -ERESTART)
			set_bit(PTLRPC_CTX_ERROR_BIT, &ctx->cc_flags);
		cli_ctx_expire(ctx);
	}

	/* let user space think it's a success */
	sptlrpc_cli_ctx_put(ctx, 1);
	RETURN(0);
}

#ifndef HAVE_KEY_MATCH_DATA
static int
gss_kt_match(const struct key *key, const void *desc)
{
	return strcmp(key->description, (const char *) desc) == 0 &&
		!test_bit(KEY_FLAG_REVOKED, &key->flags);
}
#else /* ! HAVE_KEY_MATCH_DATA */
static bool
gss_kt_match(const struct key *key, const struct key_match_data *match_data)
{
	const char *desc = match_data->raw_data;

	return strcmp(key->description, desc) == 0 &&
		!test_bit(KEY_FLAG_REVOKED, &key->flags);
}

/*
 * Preparse the match criterion.
 */
static int gss_kt_match_preparse(struct key_match_data *match_data)
{
	match_data->lookup_type = KEYRING_SEARCH_LOOKUP_DIRECT;
	match_data->cmp = gss_kt_match;
	return 0;
}
#endif /* HAVE_KEY_MATCH_DATA */

static
void gss_kt_destroy(struct key *key)
{
	ENTRY;
	LASSERT(!key_get_payload(key, 0));
	CDEBUG(D_SEC, "destroy key %08x %p\n", key->serial, key);
	EXIT;
}

static
void gss_kt_describe(const struct key *key, struct seq_file *s)
{
        if (key->description == NULL)
                seq_puts(s, "[null]");
        else
                seq_puts(s, key->description);
}

static void gss_kt_revoke(struct key *key)
{
	CDEBUG(D_SEC, "revoking key %08x (%p) ref %d\n",
	       key->serial, key, ll_read_key_usage(key));
	kill_key_locked(key);
	CDEBUG(D_SEC, "key %08x (%p) revoked ref %d\n",
	       key->serial, key, ll_read_key_usage(key));
}

static struct key_type gss_key_type =
{
	.name		= "lgssc",
	.def_datalen	= 0,
	.instantiate	= gss_kt_instantiate,
	.update		= gss_kt_update,
#ifdef HAVE_KEY_MATCH_DATA
	.match_preparse = gss_kt_match_preparse,
#else
	.match		= gss_kt_match,
#endif
	.destroy	= gss_kt_destroy,
	.describe	= gss_kt_describe,
	.revoke		= gss_kt_revoke,
};

/****************************************
 * lustre gss keyring policy            *
 ****************************************/

static struct ptlrpc_ctx_ops gss_keyring_ctxops = {
        .match                  = gss_cli_ctx_match,
        .refresh                = gss_cli_ctx_refresh_kr,
        .validate               = gss_cli_ctx_validate_kr,
        .die                    = gss_cli_ctx_die_kr,
        .sign                   = gss_cli_ctx_sign,
        .verify                 = gss_cli_ctx_verify,
        .seal                   = gss_cli_ctx_seal,
        .unseal                 = gss_cli_ctx_unseal,
        .wrap_bulk              = gss_cli_ctx_wrap_bulk,
        .unwrap_bulk            = gss_cli_ctx_unwrap_bulk,
};

static struct ptlrpc_sec_cops gss_sec_keyring_cops = {
        .create_sec             = gss_sec_create_kr,
        .destroy_sec            = gss_sec_destroy_kr,
        .kill_sec               = gss_sec_kill,
        .lookup_ctx             = gss_sec_lookup_ctx_kr,
        .release_ctx            = gss_sec_release_ctx_kr,
        .flush_ctx_cache        = gss_sec_flush_ctx_cache_kr,
        .gc_ctx                 = gss_sec_gc_ctx_kr,
        .install_rctx           = gss_sec_install_rctx,
        .alloc_reqbuf           = gss_alloc_reqbuf,
        .free_reqbuf            = gss_free_reqbuf,
        .alloc_repbuf           = gss_alloc_repbuf,
        .free_repbuf            = gss_free_repbuf,
        .enlarge_reqbuf         = gss_enlarge_reqbuf,
        .display                = gss_sec_display_kr,
};

static struct ptlrpc_sec_sops gss_sec_keyring_sops = {
        .accept                 = gss_svc_accept_kr,
        .invalidate_ctx         = gss_svc_invalidate_ctx,
        .alloc_rs               = gss_svc_alloc_rs,
        .authorize              = gss_svc_authorize,
        .free_rs                = gss_svc_free_rs,
        .free_ctx               = gss_svc_free_ctx,
        .prep_bulk              = gss_svc_prep_bulk,
        .unwrap_bulk            = gss_svc_unwrap_bulk,
        .wrap_bulk              = gss_svc_wrap_bulk,
        .install_rctx           = gss_svc_install_rctx_kr,
};

static struct ptlrpc_sec_policy gss_policy_keyring = {
        .sp_owner               = THIS_MODULE,
        .sp_name                = "gss.keyring",
        .sp_policy              = SPTLRPC_POLICY_GSS,
        .sp_cops                = &gss_sec_keyring_cops,
        .sp_sops                = &gss_sec_keyring_sops,
};


int __init gss_init_keyring(void)
{
        int rc;

        rc = register_key_type(&gss_key_type);
        if (rc) {
                CERROR("failed to register keyring type: %d\n", rc);
                return rc;
        }

        rc = sptlrpc_register_policy(&gss_policy_keyring);
        if (rc) {
                unregister_key_type(&gss_key_type);
                return rc;
        }

        return 0;
}

void __exit gss_exit_keyring(void)
{
        unregister_key_type(&gss_key_type);
        sptlrpc_unregister_policy(&gss_policy_keyring);
}
