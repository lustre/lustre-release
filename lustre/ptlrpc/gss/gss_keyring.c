/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2007 Cluster File Systems, Inc.
 *   Author: Eric Mei <ericm@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC
#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <linux/key.h>
#include <linux/keyctl.h>
#include <linux/mutex.h>
#include <asm/atomic.h>
#else
#include <liblustre.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre/lustre_idl.h>
#include <lustre_sec.h>
#include <lustre_net.h>
#include <lustre_import.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"

static struct ptlrpc_sec_policy gss_policy_keyring;
static struct ptlrpc_ctx_ops gss_keyring_ctxops;
static struct key_type gss_key_type;

static int sec_install_rctx_kr(struct ptlrpc_sec *sec,
                               struct ptlrpc_svc_ctx *svc_ctx);

/*
 * the timeout is only for the case that upcall child process die abnormally.
 * in any other cases it should finally update kernel key. so we set this
 * timeout value excessive long.
 */
#define KEYRING_UPCALL_TIMEOUT  (obd_timeout + obd_timeout)

/****************************************
 * internal helpers                     *
 ****************************************/

#define DUMP_PROCESS_KEYRINGS(tsk)                                      \
{                                                                       \
        CWARN("DUMP PK: %s[%u,%u/%u](<-%s[%u,%u/%u]): "                 \
              "a %d, t %d, p %d, s %d, u %d, us %d, df %d\n",           \
              tsk->comm, tsk->pid, tsk->uid, tsk->fsuid,                \
              tsk->parent->comm, tsk->parent->pid,                      \
              tsk->parent->uid, tsk->parent->fsuid,                     \
              task_aux(tsk)->request_key_auth ?                         \
              task_aux(tsk)->request_key_auth->serial : 0,              \
              task_aux(tsk)->thread_keyring ?                           \
              task_aux(tsk)->thread_keyring->serial : 0,                \
              tsk->signal->process_keyring ?                            \
              tsk->signal->process_keyring->serial : 0,                 \
              tsk->signal->session_keyring ?                            \
              tsk->signal->session_keyring->serial : 0,                 \
              tsk->user->uid_keyring ?                                  \
              tsk->user->uid_keyring->serial : 0,                       \
              tsk->user->session_keyring ?                              \
              tsk->user->session_keyring->serial : 0,                   \
              task_aux(tsk)->jit_keyring                                \
             );                                                         \
}

#define DUMP_KEY(key)                                                   \
{                                                                       \
        CWARN("DUMP KEY: %p(%d) ref %d u%u/g%u desc %s\n",              \
              key, key->serial, atomic_read(&key->usage),               \
              key->uid, key->gid,                                       \
              key->description ? key->description : "n/a"               \
             );                                                         \
}


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

static inline void key_revoke_locked(struct key *key)
{
        set_bit(KEY_FLAG_REVOKED, &key->flags);
}

static void ctx_upcall_timeout_kr(unsigned long data)
{
        struct ptlrpc_cli_ctx *ctx = (struct ptlrpc_cli_ctx *) data;
        struct key            *key = ctx2gctx_keyring(ctx)->gck_key;

        CWARN("ctx %p, key %p\n", ctx, key);

        LASSERT(key);

        cli_ctx_expire(ctx);
        key_revoke_locked(key);
        sptlrpc_cli_ctx_wakeup(ctx);
}

static
void ctx_start_timer_kr(struct ptlrpc_cli_ctx *ctx, long timeout)
{
        struct gss_cli_ctx_keyring *gctx_kr = ctx2gctx_keyring(ctx);
        struct timer_list          *timer = gctx_kr->gck_timer;

        LASSERT(timer);

        CWARN("ctx %p: start timer %lds\n", ctx, timeout);
        timeout = timeout * HZ + cfs_time_current();

        init_timer(timer);
        timer->expires = timeout;
        timer->data = (unsigned long ) ctx;
        timer->function = ctx_upcall_timeout_kr;

        add_timer(timer);
}

static
void ctx_clear_timer_kr(struct ptlrpc_cli_ctx *ctx)
{
        struct gss_cli_ctx_keyring *gctx_kr = ctx2gctx_keyring(ctx);
        struct timer_list          *timer = gctx_kr->gck_timer;

        CWARN("ctx %p, key %p\n", ctx, gctx_kr->gck_key);
        if (timer == NULL)
                return;

        gctx_kr->gck_timer = NULL;

        del_singleshot_timer_sync(timer);

        OBD_FREE_PTR(timer);
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

        OBD_ALLOC_PTR(gctx_kr->gck_timer);
        if (gctx_kr->gck_timer == NULL) {
                OBD_FREE_PTR(gctx_kr);
                return NULL;
        }
        init_timer(gctx_kr->gck_timer);

        ctx = &gctx_kr->gck_base.gc_base;

        if (gss_cli_ctx_init_common(sec, ctx, &gss_keyring_ctxops, vcred)) {
                OBD_FREE_PTR(gctx_kr->gck_timer);
                OBD_FREE_PTR(gctx_kr);
                return NULL;
        }

        ctx->cc_expire = cfs_time_current_sec() + KEYRING_UPCALL_TIMEOUT;
        clear_bit(PTLRPC_CTX_NEW_BIT, &ctx->cc_flags);
        atomic_inc(&ctx->cc_refcount); /* for the caller */

        return ctx;
}

static void ctx_destroy_kr(struct ptlrpc_cli_ctx *ctx)
{
        struct ptlrpc_sec          *sec = ctx->cc_sec;
        struct gss_cli_ctx_keyring *gctx_kr = ctx2gctx_keyring(ctx);
        int                         rc;

        CWARN("destroying ctx %p\n", ctx);

        /* at this time the association with key has been broken. */
        LASSERT(sec);
        LASSERT(test_bit(PTLRPC_CTX_CACHED_BIT, &ctx->cc_flags) == 0);
        LASSERT(gctx_kr->gck_key == NULL);

        ctx_clear_timer_kr(ctx);
        LASSERT(gctx_kr->gck_timer == NULL);

        rc = gss_cli_ctx_fini_common(sec, ctx);

        OBD_FREE_PTR(gctx_kr);

        if (rc) {
                CWARN("released the last ctx, proceed to destroy sec %s@%p\n",
                      sec->ps_policy->sp_name, sec);
                sptlrpc_sec_destroy(sec);
        }
}

static void ctx_put_kr(struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);

        if (atomic_dec_and_test(&ctx->cc_refcount))
                ctx_destroy_kr(ctx);
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

static
void ctx_enlist_kr(struct ptlrpc_cli_ctx *ctx, int is_root, int locked)
{
        struct ptlrpc_sec      *sec = ctx->cc_sec;
        struct gss_sec_keyring *gsec_kr = sec2gsec_keyring(sec);

        LASSERT(!test_bit(PTLRPC_CTX_CACHED_BIT, &ctx->cc_flags));
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);

        spin_lock_if(&sec->ps_lock, !locked);

        atomic_inc(&ctx->cc_refcount);
        set_bit(PTLRPC_CTX_CACHED_BIT, &ctx->cc_flags);
        hlist_add_head(&ctx->cc_hash, &gsec_kr->gsk_clist);
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
static
int ctx_unlist_kr(struct ptlrpc_cli_ctx *ctx, int locked)
{
        struct ptlrpc_sec       *sec = ctx->cc_sec;
        struct gss_sec_keyring  *gsec_kr = sec2gsec_keyring(sec);

        /*
         * if hashed bit has gone, leave the job to somebody who is doing it
         */
        if (test_and_clear_bit(PTLRPC_CTX_CACHED_BIT, &ctx->cc_flags) == 0)
                return 0;

        CWARN("ctx %p(%d) unlist\n", ctx, atomic_read(&ctx->cc_refcount));

        /*
         * drop ref inside spin lock to prevent race with other operations
         */
        spin_lock_if(&sec->ps_lock, !locked);

        if (gsec_kr->gsk_root_ctx == ctx)
                gsec_kr->gsk_root_ctx = NULL;
        hlist_del_init(&ctx->cc_hash);
        atomic_dec(&ctx->cc_refcount);

        spin_unlock_if(&sec->ps_lock, !locked);

        return 1;
}

/*
 * bind a key with a ctx together.
 * caller must hold write lock of the key, as well as ref on key & ctx.
 */
static
void bind_key_ctx(struct key *key, struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);
        LASSERT(atomic_read(&key->usage) > 0);
        LASSERT(ctx2gctx_keyring(ctx)->gck_key == NULL);
        LASSERT(key->payload.data == NULL);
        /*
         * at this time context may or may not in list.
         */
        key_get(key);
        atomic_inc(&ctx->cc_refcount);
        ctx2gctx_keyring(ctx)->gck_key = key;
        key->payload.data = ctx;
}

/*
 * unbind a key and a ctx.
 * caller must hold write lock, as well as a ref of the key.
 */
static
void unbind_key_ctx(struct key *key, struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(key->payload.data == ctx);
        LASSERT(test_bit(PTLRPC_CTX_CACHED_BIT, &ctx->cc_flags) == 0);

        /* must revoke the key, or others may treat it as newly created */
        key_revoke_locked(key);

        key->payload.data = NULL;
        ctx2gctx_keyring(ctx)->gck_key = NULL;

        /* once ctx get split from key, the timer is meaningless */
        ctx_clear_timer_kr(ctx);

        ctx_put_kr(ctx);
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
                LASSERT(key->payload.data == ctx);

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
        struct ptlrpc_cli_ctx   *ctx = key->payload.data;

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
        struct ptlrpc_cli_ctx *ctx = key->payload.data;

        if (ctx && ctx_unlist_kr(ctx, 0))
                unbind_key_locked(key);
}

/*
 * since this called, nobody else could touch the ctx in @freelist
 */
static void dispose_ctx_list_kr(struct hlist_head *freelist)
{
        struct hlist_node      *pos, *next;
        struct ptlrpc_cli_ctx  *ctx;

        hlist_for_each_entry_safe(ctx, pos, next, freelist, cc_hash) {
                hlist_del_init(&ctx->cc_hash);

                atomic_inc(&ctx->cc_refcount);
                unbind_ctx_kr(ctx);
                ctx_put_kr(ctx);
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

        spin_lock(&sec->ps_lock);

        ctx = gsec_kr->gsk_root_ctx;
        if (ctx) {
                LASSERT(atomic_read(&ctx->cc_refcount) > 0);
                LASSERT(!hlist_empty(&gsec_kr->gsk_clist));
                atomic_inc(&ctx->cc_refcount);
        }

        spin_unlock(&sec->ps_lock);

        return ctx;
}

static void sec_replace_root_ctx_kr(struct ptlrpc_sec *sec,
                                    struct ptlrpc_cli_ctx *new_ctx,
                                    struct key *key)
{
        struct gss_sec_keyring *gsec_kr = sec2gsec_keyring(sec);
        struct ptlrpc_cli_ctx  *root_ctx;
        struct hlist_head       freelist = HLIST_HEAD_INIT;
        ENTRY;

        spin_lock(&sec->ps_lock);

        if (gsec_kr->gsk_root_ctx) {
                root_ctx = gsec_kr->gsk_root_ctx;

                set_bit(PTLRPC_CTX_DEAD_BIT, &root_ctx->cc_flags);

                if (ctx_unlist_kr(root_ctx, 1))
                        hlist_add_head(&root_ctx->cc_hash, &freelist);
        }

        /*
         * at this time, we can't guarantee the gsk_root_ctx is NULL, because
         * another thread might clear the HASHED flag of root ctx earlier,
         * and waiting for spinlock which is held by us. But anyway we just
         * install the new root ctx.
         */
        ctx_enlist_kr(new_ctx, 1, 1);

        if (key)
                bind_key_ctx(key, new_ctx);

        spin_unlock(&sec->ps_lock);

        dispose_ctx_list_kr(&freelist);
}

static void construct_key_desc(void *buf, int bufsize,
                               struct ptlrpc_sec *sec, uid_t uid)
{
        snprintf(buf, bufsize, "%d@%x", uid, sec2gsec_keyring(sec)->gsk_id);
        ((char *)buf)[bufsize - 1] = '\0';
}

/****************************************
 * sec apis                             *
 ****************************************/

static atomic_t gss_sec_id_kr = ATOMIC_INIT(0);

static
struct ptlrpc_sec * gss_sec_create_kr(struct obd_import *imp,
                                      struct ptlrpc_svc_ctx *ctx,
                                      __u32 flavor,
                                      unsigned long flags)
{
        struct gss_sec_keyring  *gsec_kr;
        ENTRY;

        OBD_ALLOC(gsec_kr, sizeof(*gsec_kr));
        if (gsec_kr == NULL)
                RETURN(NULL);

        gsec_kr->gsk_id = atomic_inc_return(&gss_sec_id_kr);
        INIT_HLIST_HEAD(&gsec_kr->gsk_clist);
        gsec_kr->gsk_root_ctx = NULL;
        mutex_init(&gsec_kr->gsk_root_uc_lock);
#ifdef HAVE_KEYRING_UPCALL_SERIALIZED
        mutex_init(&gsec_kr->gsk_uc_lock);
#endif

        if (gss_sec_create_common(&gsec_kr->gsk_base, &gss_policy_keyring,
                                  imp, ctx, flavor, flags))
                goto err_free;

        if (ctx != NULL) {
                if (sec_install_rctx_kr(&gsec_kr->gsk_base.gs_base, ctx)) {
                        gss_sec_destroy_common(&gsec_kr->gsk_base);
                        goto err_free;
                }
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

        CWARN("destroy %s@%p\n", sec->ps_policy->sp_name, sec);

        LASSERT(hlist_empty(&gsec_kr->gsk_clist));
        LASSERT(gsec_kr->gsk_root_ctx == NULL);

        gss_sec_destroy_common(gsec);

        OBD_FREE(gsec_kr, sizeof(*gsec_kr));
}

static
int user_is_root(struct ptlrpc_sec *sec, struct vfs_cred *vcred)
{
        if (sec->ps_flags & PTLRPC_SEC_FL_ROOTONLY)
                return 1;

        /* FIXME
         * more precisely deal with setuid. maybe add more infomation
         * into vfs_cred ??
         */
        return (vcred->vc_uid == 0);
}

/*
 * unlink request key from it's ring, which is linked during request_key().
 * sadly, we have to 'guess' which keyring it's linked to.
 *
 * FIXME this code is fragile, depend on how request_key_link() is implemented.
 */
static void request_key_unlink(struct key *key)
{
        struct task_struct *tsk = current;
        struct key *ring;

        switch (task_aux(tsk)->jit_keyring) {
        case KEY_REQKEY_DEFL_DEFAULT:
        case KEY_REQKEY_DEFL_THREAD_KEYRING:
                ring = key_get(task_aux(tsk)->thread_keyring);
                if (ring)
                        break;
        case KEY_REQKEY_DEFL_PROCESS_KEYRING:
                ring = key_get(tsk->signal->process_keyring);
                if (ring)
                        break;
        case KEY_REQKEY_DEFL_SESSION_KEYRING:
                rcu_read_lock();
                ring = key_get(rcu_dereference(tsk->signal->session_keyring));
                rcu_read_unlock();
                if (ring)
                        break;
        case KEY_REQKEY_DEFL_USER_SESSION_KEYRING:
                ring = key_get(tsk->user->session_keyring);
                break;
        case KEY_REQKEY_DEFL_USER_KEYRING:
                ring = key_get(tsk->user->uid_keyring);
                break;
        case KEY_REQKEY_DEFL_GROUP_KEYRING:
        default:
                LBUG();
        }

        LASSERT(ring);
        key_unlink(ring, key);
        key_put(ring);
}

static
struct ptlrpc_cli_ctx * gss_sec_lookup_ctx_kr(struct ptlrpc_sec *sec,
                                              struct vfs_cred *vcred,
                                              int create, int remove_dead)
{
        struct obd_import       *imp = sec->ps_import;
        struct gss_sec_keyring  *gsec_kr = sec2gsec_keyring(sec);
        struct ptlrpc_cli_ctx   *ctx = NULL;
        unsigned int             is_root = 0, create_new = 0;
        struct key              *key;
        char                     desc[24];
        char                    *coinfo;
        const int                coinfo_size = sizeof(struct obd_uuid) + 64;
        char                    *co_flags = "";
        ENTRY;

        LASSERT(imp != NULL);

        is_root = user_is_root(sec, vcred);

        /*
         * a little bit optimization for root context
         */
        if (is_root) {
                ctx = sec_lookup_root_ctx_kr(sec);
                /*
                 * Only lookup directly for REVERSE sec, which should
                 * always succeed.
                 */
                if (ctx || (sec->ps_flags & PTLRPC_SEC_FL_REVERSE))
                        RETURN(ctx);
        }

        LASSERT(create != 0);

        /*
         * for root context, obtain lock and check again, this time hold
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

                co_flags = "r";
        }

        construct_key_desc(desc, sizeof(desc), sec, vcred->vc_uid);

        /*
         * callout info: mech:flags:svc_type:peer_nid:target_uuid
         */
        OBD_ALLOC(coinfo, coinfo_size);
        if (coinfo == NULL)
                goto out;

        snprintf(coinfo, coinfo_size, "%s:%s:%d:"LPX64":%s",
                 sec2gsec(sec)->gs_mech->gm_name,
                 co_flags, import_to_gss_svc(imp),
                 imp->imp_connection->c_peer.nid, imp->imp_obd->obd_name);

        keyring_upcall_lock(gsec_kr);
        key = request_key(&gss_key_type, desc, coinfo);
        keyring_upcall_unlock(gsec_kr);

        OBD_FREE(coinfo, coinfo_size);

        if (IS_ERR(key)) {
                CERROR("failed request key: %ld\n", PTR_ERR(key));
                goto out;
        }

        /*
         * once payload.data was pointed to a ctx, it never changes until
         * we de-associate them; but parallel request_key() may return
         * a key with payload.data == NULL at the same time. so we still
         * need wirtelock of key->sem to serialize them.
         */
        down_write(&key->sem);

        if (likely(key->payload.data != NULL)) {
                ctx = key->payload.data;

                LASSERT(atomic_read(&ctx->cc_refcount) >= 1);
                LASSERT(ctx2gctx_keyring(ctx)->gck_key == key);
                LASSERT(atomic_read(&key->usage) >= 2);

                /* simply take a ref and return. it's upper layer's
                 * responsibility to detect & replace dead ctx.
                 */
                atomic_inc(&ctx->cc_refcount);
        } else {
                /* pre initialization with a cli_ctx. this can't be done in
                 * key_instantiate() because we'v no enough information there.
                 */
                ctx = ctx_create_kr(sec, vcred);
                if (ctx != NULL) {
                        ctx_enlist_kr(ctx, is_root, 0);
                        bind_key_ctx(key, ctx);

                        ctx_start_timer_kr(ctx, KEYRING_UPCALL_TIMEOUT);

                        CWARN("installed key %p <-> ctx %p (sec %p)\n",
                              key, ctx, sec);
                } else {
                        /*
                         * we'd prefer to call key_revoke(), but we more like
                         * to revoke it within this key->sem locked period.
                         */
                        key_revoke_locked(key);
                }

                create_new = 1;
        }

        up_write(&key->sem);

        if (is_root && create_new)
                request_key_unlink(key);

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
        CWARN("ctx %p\n", ctx);
        ctx_destroy_kr(ctx);
}

/*
 * flush context of normal user, we must resort to keyring itself to find out
 * contexts which belong to me.
 *
 * Note here we suppose only to flush _my_ context, the "uid" will
 * be ignored in the search.
 */
static
void flush_user_ctx_cache_kr(struct ptlrpc_sec *sec,
                             uid_t uid,
                             int grace, int force)
{
        struct key              *key;
        char                     desc[24];

        /* nothing to do for reverse or rootonly sec */
        if (sec->ps_flags & (PTLRPC_SEC_FL_REVERSE | PTLRPC_SEC_FL_ROOTONLY))
                return;

        construct_key_desc(desc, sizeof(desc), sec, uid);

        /* there should be only one valid key, but we put it in the
         * loop in case of any weird cases
         */
        for (;;) {
                key = request_key(&gss_key_type, desc, NULL);
                if (IS_ERR(key)) {
                        CWARN("No more key found for current user\n");
                        break;
                }

                down_write(&key->sem);

                CWARN("invalidating key %p - ctx %p\n", key, key->payload.data);
                kill_key_locked(key);

                /* kill_key_locked() should usually revoke the key, but we
                 * revoke it again to make sure, e.g. some case the key may
                 * not well coupled with a context.
                 */
                key_revoke_locked(key);

                up_write(&key->sem);

                key_put(key);
        }
}

/*
 * flush context of root or all, we iterate through the list.
 */
static
void flush_spec_ctx_cache_kr(struct ptlrpc_sec *sec,
                             uid_t uid,
                             int grace, int force)
{
        struct gss_sec_keyring *gsec_kr;
        struct hlist_head       freelist = HLIST_HEAD_INIT;
        struct hlist_node      *pos, *next;
        struct ptlrpc_cli_ctx  *ctx;
        ENTRY;

        gsec_kr = sec2gsec_keyring(sec);

        spin_lock(&sec->ps_lock);
        hlist_for_each_entry_safe(ctx, pos, next,
                                  &gsec_kr->gsk_clist, cc_hash) {
                LASSERT(atomic_read(&ctx->cc_refcount) > 0);

                if (uid != -1 && uid != ctx->cc_vcred.vc_uid)
                        continue;

                /* at this moment there's at least 2 base reference:
                 * key association and in-list.
                 */
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

                if (ctx_unlist_kr(ctx, 1)) {
                        hlist_add_head(&ctx->cc_hash, &freelist);
                        CWARN("unlisted ctx %p\n", ctx);
                } else
                        CWARN("ctx %p: unlist return 0, let it go\n", ctx);

        }
        spin_unlock(&sec->ps_lock);

        dispose_ctx_list_kr(&freelist);
        EXIT;
}

static
int gss_sec_flush_ctx_cache_kr(struct ptlrpc_sec *sec,
                               uid_t uid,
                               int grace, int force)
{
        ENTRY;

        CWARN("sec %p(%d, busy %d), uid %d, grace %d, force %d\n",
              sec, atomic_read(&sec->ps_refcount), atomic_read(&sec->ps_busy),
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
        struct hlist_head       freelist = HLIST_HEAD_INIT;
        struct hlist_node      *pos, *next;
        struct ptlrpc_cli_ctx  *ctx;
        ENTRY;

        CWARN("running gc\n");

        spin_lock(&sec->ps_lock);
        hlist_for_each_entry_safe(ctx, pos, next,
                                  &gsec_kr->gsk_clist, cc_hash) {
                LASSERT(atomic_read(&ctx->cc_refcount) > 0);

                if (cli_ctx_check_death(ctx) && ctx_unlist_kr(ctx, 1)) {
                        hlist_add_head(&ctx->cc_hash, &freelist);
                        CWARN("unhashed ctx %p\n", ctx);
                }
        }
        spin_unlock(&sec->ps_lock);

        dispose_ctx_list_kr(&freelist);
        EXIT;
        return;
}

static
int gss_sec_display_kr(struct ptlrpc_sec *sec, char *buf, int bufsize)
{
        struct gss_sec_keyring *gsec_kr = sec2gsec_keyring(sec);
        struct hlist_node      *pos, *next;
        struct ptlrpc_cli_ctx  *ctx;
        int                     written = 0;
        ENTRY;

        written = snprintf(buf, bufsize, "context list ===>\n");
        bufsize -= written;
        buf += written;

        spin_lock(&sec->ps_lock);
        hlist_for_each_entry_safe(ctx, pos, next,
                                  &gsec_kr->gsk_clist, cc_hash) {
                struct key *key;
                int         len;

                key = ctx2gctx_keyring(ctx)->gck_key;

                len = snprintf(buf, bufsize, "%p(%d): expire %ld(%ld), "
                               "uid %u, flags 0x%lx, key %08x(%d)\n",
                               ctx, atomic_read(&ctx->cc_refcount),
                               ctx->cc_expire,
                               ctx->cc_expire - cfs_time_current_sec(),
                               ctx->cc_vcred.vc_uid,
                               ctx->cc_flags,
                               key ? key->serial : 0,
                               key ? atomic_read(&key->usage) : 0);

                written += len;
                buf += len;
                bufsize -= len;

                if (bufsize < len)
                        break;
        }
        spin_unlock(&sec->ps_lock);

        RETURN(written);
}

/****************************************
 * cli_ctx apis                         *
 ****************************************/

static
int gss_cli_ctx_refresh_kr(struct ptlrpc_cli_ctx *ctx)
{
        /* upcall is already on the way */
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

        if (cli_ctx_is_uptodate(ctx))
                return 0;
        return 1;
}

static
void gss_cli_ctx_die_kr(struct ptlrpc_cli_ctx *ctx, int grace)
{
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);
        LASSERT(ctx->cc_sec);

        CWARN("ctx %p(%d)\n", ctx, atomic_read(&ctx->cc_refcount));
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
        struct ptlrpc_cli_ctx   *cli_ctx;
        struct vfs_cred          vcred = { 0, 0 };
        int                      rc;

        LASSERT(sec);
        LASSERT(svc_ctx);

        cli_ctx = ctx_create_kr(sec, &vcred);
        if (cli_ctx == NULL)
                return -ENOMEM;

        rc = gss_copy_rvc_cli_ctx(cli_ctx, svc_ctx);
        if (rc) {
                CERROR("failed copy reverse cli ctx: %d\n", rc);

                ctx_put_kr(cli_ctx);
                return rc;
        }

        sec_replace_root_ctx_kr(sec, cli_ctx, NULL);

        ctx_put_kr(cli_ctx);

        return 0;
}

#else /* ! HAVE_REVERSE_CTX_NOKEY */

static
int sec_install_rctx_kr(struct ptlrpc_sec *sec,
                        struct ptlrpc_svc_ctx *svc_ctx)
{
        struct ptlrpc_cli_ctx   *cli_ctx = NULL;
        struct key              *key;
        struct vfs_cred          vcred = { 0, 0 };
        char                     desc[64];
        int                      rc;

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

        LASSERT(key->payload.data == NULL);

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

        sec_replace_root_ctx_kr(sec, cli_ctx, key);

        ctx_put_kr(cli_ctx);
        up_write(&key->sem);

        rc = 0;
        CWARN("ok!\n");
out:
        key_put(key);
        return rc;

err_put:
        ctx_put_kr(cli_ctx);
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
        LASSERT(imp->imp_sec);

        return sec_install_rctx_kr(imp->imp_sec, svc_ctx);
}

/****************************************
 * key apis                             *
 ****************************************/

static
int gss_kt_instantiate(struct key *key, const void *data, size_t datalen)
{
        ENTRY;

        if (data != NULL || datalen != 0) {
                CERROR("invalid: data %p, len %d\n", data, datalen);
                RETURN(-EINVAL);
        }

        if (key->payload.data != 0) {
                CERROR("key already have payload\n");
                RETURN(-EINVAL);
        }

        /* XXX */
        key->perm |= KEY_POS_ALL | KEY_USR_ALL;
        CWARN("key %p instantiated, ctx %p\n", key, key->payload.data);
        RETURN(0);
}

/*
 * called with key semaphore write locked. it means we can operate
 * on the context without fear of loosing refcount.
 */
static
int gss_kt_update(struct key *key, const void *data, size_t datalen)
{
        struct ptlrpc_cli_ctx   *ctx = key->payload.data;
        struct gss_cli_ctx      *gctx;
        rawobj_t                 tmpobj = RAWOBJ_EMPTY;
        int                      rc;
        ENTRY;

        if (data == NULL || datalen == 0) {
                CWARN("invalid: data %p, len %d\n", data, datalen);
                RETURN(-EINVAL);
        }

        /*
         * there's a race between userspace parent - child processes. if
         * child finish negotiation too fast and call kt_update(), the ctx
         * might be still NULL. but the key will finally be associate
         * with a context, or be revoked. if key status is fine, return
         * -EAGAIN to allow userspace sleep a while and call again.
         */
        if (ctx == NULL) {
                CWARN("race in userspace. key %p(%x) flags %lx\n",
                      key, key->serial, key->flags);

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
                sptlrpc_cli_ctx_wakeup(ctx);
                RETURN(0);
        }

        sptlrpc_cli_ctx_get(ctx);
        gctx = ctx2gctx(ctx);
        rc = -EFAULT;

        if (buffer_extract_bytes(&data, &datalen,
                                 &gctx->gc_win, sizeof(gctx->gc_win))) {
                CERROR("failed extract seq_win\n");
                goto out;
        }

        CWARN("secwin is %d\n", gctx->gc_win);
        if (gctx->gc_win == 0) {
                __u32   nego_rpc_err, nego_gss_err;

                if (buffer_extract_bytes(&data, &datalen,
                                         &nego_rpc_err, sizeof(nego_rpc_err))) {
                        CERROR("failed to extrace rpc rc\n");
                        goto out;
                }

                if (buffer_extract_bytes(&data, &datalen,
                                         &nego_gss_err, sizeof(nego_gss_err))) {
                        CERROR("failed to extrace gss rc\n");
                        goto out;
                }

                CERROR("negotiation: rpc err %d, gss err %x\n",
                       nego_rpc_err, nego_gss_err);

                if (nego_rpc_err)
                        rc = nego_rpc_err;
        } else {
                if (rawobj_extract_local_alloc(&gctx->gc_handle,
                                               (__u32 **)&data, &datalen)) {
                        CERROR("failed extract handle\n");
                        goto out;
                }

                if (rawobj_extract_local(&tmpobj, (__u32 **)&data, &datalen)) {
                        CERROR("failed extract mech\n");
                        goto out;
                }

                if (lgss_import_sec_context(&tmpobj,
                                            sec2gsec(ctx->cc_sec)->gs_mech,
                                            &gctx->gc_mechctx) !=
                    GSS_S_COMPLETE) {
                        CERROR("failed import context\n");
                        goto out;
                }

                rc = 0;
        }
out:
        /* we don't care what current status of this ctx, even someone else
         * is operating on the ctx at the same time. we just add up our own
         * opinions here.
         */
        if (rc == 0) {
                gss_cli_ctx_uptodate(gctx);
        } else {
                cli_ctx_expire(ctx);

                if (rc != -ERESTART)
                        set_bit(PTLRPC_CTX_ERROR_BIT, &ctx->cc_flags);

                /* this will also revoke the key. has to be done before
                 * wakeup waiters otherwise they can find the stale key
                 */
                kill_key_locked(key);
        }

        sptlrpc_cli_ctx_wakeup(ctx);

        /* let user space think it's a success */
        sptlrpc_cli_ctx_put(ctx, 1);
        RETURN(0);
}

static
int gss_kt_match(const struct key *key, const void *desc)
{
        return (strcmp(key->description, (const char *) desc) == 0);
}

static
void gss_kt_destroy(struct key *key)
{
        ENTRY;
        LASSERT(key->payload.data == NULL);
        CWARN("destroy key %p\n", key);
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

static struct key_type gss_key_type =
{
        .name           = "lgssc",
        .def_datalen    = 0,
        .instantiate    = gss_kt_instantiate,
        .update         = gss_kt_update,
        .match          = gss_kt_match,
        .destroy        = gss_kt_destroy,
        .describe       = gss_kt_describe,
};

/****************************************
 * lustre gss keyring policy            *
 ****************************************/

static struct ptlrpc_ctx_ops gss_keyring_ctxops = {
        .match                  = gss_cli_ctx_match,
        .refresh                = gss_cli_ctx_refresh_kr,
        .validate               = gss_cli_ctx_validate_kr,
        .die                    = gss_cli_ctx_die_kr,
        .display                = gss_cli_ctx_display,
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
