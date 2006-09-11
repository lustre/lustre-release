/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004-2006 Cluster File Systems, Inc.
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
#define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/libcfs.h>
#ifndef __KERNEL__
#include <liblustre.h>
#include <libcfs/list.h>
#else
#include <linux/crypto.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

static void sptlrpc_sec_destroy(struct ptlrpc_sec *sec);
static int sptlrpc_sec_destroy_ctx(struct ptlrpc_sec *sec,
                                   struct ptlrpc_cli_ctx *ctx);
static void sptlrpc_ctx_refresh(struct ptlrpc_cli_ctx *ctx);

/***********************************************
 * policy registers                            *
 ***********************************************/

static spinlock_t policy_lock = SPIN_LOCK_UNLOCKED;
static struct ptlrpc_sec_policy *policies[SPTLRPC_POLICY_MAX] = {
        NULL,
};

int sptlrpc_register_policy(struct ptlrpc_sec_policy *policy)
{
        __u32 number = policy->sp_policy;

        LASSERT(policy->sp_name);
        LASSERT(policy->sp_cops);
        LASSERT(policy->sp_sops);

        if (number >= SPTLRPC_POLICY_MAX)
                return -EINVAL;

        spin_lock(&policy_lock);
        if (policies[number]) {
                spin_unlock(&policy_lock);
                return -EALREADY;
        }
        policies[number] = policy;
        spin_unlock(&policy_lock);

        CDEBUG(D_SEC, "%s: registered\n", policy->sp_name);
        return 0;
}
EXPORT_SYMBOL(sptlrpc_register_policy);

int sptlrpc_unregister_policy(struct ptlrpc_sec_policy *policy)
{
        __u32 number = policy->sp_policy;

        LASSERT(number < SPTLRPC_POLICY_MAX);

        spin_lock(&policy_lock);
        if (!policies[number]) {
                spin_unlock(&policy_lock);
                CERROR("%s: already unregistered\n", policy->sp_name);
                return -EINVAL;
        }

        LASSERT(policies[number] == policy);
        policies[number] = NULL;
        spin_unlock(&policy_lock);

        CDEBUG(D_SEC, "%s: unregistered\n", policy->sp_name);
        return 0;
}
EXPORT_SYMBOL(sptlrpc_unregister_policy);

static
struct ptlrpc_sec_policy * sptlrpc_flavor2policy(ptlrpc_flavor_t flavor)
{
        static int load_module = 0;
        struct ptlrpc_sec_policy *policy;
        __u32 number = SEC_FLAVOR_POLICY(flavor);

        if (number >= SPTLRPC_POLICY_MAX)
                return NULL;

again:
        spin_lock(&policy_lock);
        policy = policies[number];
        if (policy && !try_module_get(policy->sp_owner))
                policy = NULL;
        spin_unlock(&policy_lock);

        /* if failure, try to load gss module, once */
        if (policy == NULL && load_module == 0 &&
            number == SPTLRPC_POLICY_GSS) {
                load_module = 1;
                if (request_module("ptlrpc_gss") == 0)
                        goto again;
        }

        return policy;
}

ptlrpc_flavor_t sptlrpc_name2flavor(const char *name)
{
        if (!strcmp(name, "null"))
                return SPTLRPC_FLVR_NULL;
        if (!strcmp(name, "plain"))
                return SPTLRPC_FLVR_PLAIN;
        if (!strcmp(name, "krb5"))
                return SPTLRPC_FLVR_KRB5;
        if (!strcmp(name, "krb5i"))
                return SPTLRPC_FLVR_KRB5I;
        if (!strcmp(name, "krb5p"))
                return SPTLRPC_FLVR_KRB5P;

        return SPTLRPC_FLVR_INVALID;
}
EXPORT_SYMBOL(sptlrpc_name2flavor);

char *sptlrpc_flavor2name(ptlrpc_flavor_t flavor)
{
        switch (flavor) {
        case SPTLRPC_FLVR_NULL:
                return "null";
        case SPTLRPC_FLVR_PLAIN:
                return "plain";
        case SPTLRPC_FLVR_KRB5:
                return "krb5";
        case SPTLRPC_FLVR_KRB5I:
                return "krb5i";
        case SPTLRPC_FLVR_KRB5P:
                return "krb5p";
        default:
                CERROR("invalid flavor 0x%x(p%u,s%u,v%u)\n", flavor,
                       SEC_FLAVOR_POLICY(flavor), SEC_FLAVOR_SUBPOLICY(flavor),
                       SEC_FLAVOR_SVC(flavor));
        }
        return "UNKNOWN";
}
EXPORT_SYMBOL(sptlrpc_flavor2name);

/***********************************************
 * context helpers                             *
 * internal APIs                               *
 * cache management                            *
 ***********************************************/

static inline
unsigned long ctx_status(struct ptlrpc_cli_ctx *ctx)
{
        smp_mb();
        return (ctx->cc_flags & PTLRPC_CTX_STATUS_MASK);
}

static inline
int ctx_is_uptodate(struct ptlrpc_cli_ctx *ctx)
{
        return (ctx_status(ctx) == PTLRPC_CTX_UPTODATE);
}

static inline
int ctx_is_refreshed(struct ptlrpc_cli_ctx *ctx)
{
        return (ctx_status(ctx) != 0);
}

static inline
int ctx_is_dead(struct ptlrpc_cli_ctx *ctx)
{
        smp_mb();
        return ((ctx->cc_flags & (PTLRPC_CTX_DEAD | PTLRPC_CTX_ERROR)) != 0);
}

static inline
int ctx_is_eternal(struct ptlrpc_cli_ctx *ctx)
{
        smp_mb();
        return ((ctx->cc_flags & PTLRPC_CTX_ETERNAL) != 0);
}

static
int ctx_expire(struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(atomic_read(&ctx->cc_refcount));

        if (!test_and_set_bit(PTLRPC_CTX_DEAD_BIT, &ctx->cc_flags)) {
                cfs_time_t now = cfs_time_current_sec();

                smp_mb();
                clear_bit(PTLRPC_CTX_UPTODATE_BIT, &ctx->cc_flags);

                if (ctx->cc_expire && cfs_time_aftereq(now, ctx->cc_expire))
                        CWARN("ctx %p(%u->%s): get expired (%lds exceeds)\n",
                              ctx, ctx->cc_vcred.vc_uid,
                              sec2target_str(ctx->cc_sec),
                              cfs_time_sub(now, ctx->cc_expire));
                else
                        CWARN("ctx %p(%u->%s): force to die (%lds remains)\n",
                              ctx, ctx->cc_vcred.vc_uid,
                              sec2target_str(ctx->cc_sec),
                              ctx->cc_expire == 0 ? 0 :
                              cfs_time_sub(ctx->cc_expire, now));

                return 1;
        }
        return 0;
}

static
void ctx_enhash(struct ptlrpc_cli_ctx *ctx, struct hlist_head *hash)
{
        set_bit(PTLRPC_CTX_HASHED_BIT, &ctx->cc_flags);
        atomic_inc(&ctx->cc_refcount);
        hlist_add_head(&ctx->cc_hash, hash);
}

static
void ctx_unhash(struct ptlrpc_cli_ctx *ctx, struct hlist_head *freelist)
{
        LASSERT_SPIN_LOCKED(&ctx->cc_sec->ps_lock);
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);
        LASSERT(test_bit(PTLRPC_CTX_HASHED_BIT, &ctx->cc_flags));
        LASSERT(!hlist_unhashed(&ctx->cc_hash));

        clear_bit(PTLRPC_CTX_HASHED_BIT, &ctx->cc_flags);

        if (atomic_dec_and_test(&ctx->cc_refcount)) {
                __hlist_del(&ctx->cc_hash);
                hlist_add_head(&ctx->cc_hash, freelist);
        } else
                hlist_del_init(&ctx->cc_hash);
}

/*
 * return 1 if the context is dead.
 */
static
int ctx_check_death(struct ptlrpc_cli_ctx *ctx, struct hlist_head *freelist)
{
        if (unlikely(ctx_is_dead(ctx)))
                goto unhash;

        /* expire is 0 means never expire. a newly created gss context
         * which during upcall also has 0 expiration
         */
        smp_mb();
        if (ctx->cc_expire == 0)
                return 0;

        /* check real expiration */
        smp_mb();
        if (cfs_time_after(ctx->cc_expire, cfs_time_current_sec()))
                return 0;

        ctx_expire(ctx);

unhash:
        if (freelist)
                ctx_unhash(ctx, freelist);

        return 1;
}

static inline
int ctx_check_death_locked(struct ptlrpc_cli_ctx *ctx,
                           struct hlist_head *freelist)
{
        LASSERT(ctx->cc_sec);
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);
        LASSERT_SPIN_LOCKED(&ctx->cc_sec->ps_lock);
        LASSERT(test_bit(PTLRPC_CTX_HASHED_BIT, &ctx->cc_flags));

        return ctx_check_death(ctx, freelist);
}

static
int ctx_check_uptodate(struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(ctx->cc_sec);
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);

        if (!ctx_check_death(ctx, NULL) && ctx_is_uptodate(ctx))
                return 1;
        return 0;
}

static inline
int ctx_match(struct ptlrpc_cli_ctx *ctx, struct vfs_cred *vcred)
{
        /* a little bit optimization for null policy */
        if (!ctx->cc_ops->match)
                return 1;

        return ctx->cc_ops->match(ctx, vcred);
}

static
void ctx_list_destroy(struct hlist_head *head)
{
        struct ptlrpc_cli_ctx *ctx;

        while (!hlist_empty(head)) {
                ctx = hlist_entry(head->first, struct ptlrpc_cli_ctx, cc_hash);

                LASSERT(atomic_read(&ctx->cc_refcount) == 0);
                LASSERT(test_bit(PTLRPC_CTX_HASHED_BIT, &ctx->cc_flags) == 0);

                hlist_del_init(&ctx->cc_hash);
                sptlrpc_sec_destroy_ctx(ctx->cc_sec, ctx);
        }
}

static
void ctx_cache_gc(struct ptlrpc_sec *sec, struct hlist_head *freelist)
{
        struct ptlrpc_cli_ctx *ctx;
        struct hlist_node *pos, *next;
        int i;
        ENTRY;

        CDEBUG(D_SEC, "do gc on sec %s@%p\n", sec->ps_policy->sp_name, sec);

        for (i = 0; i < sec->ps_ccache_size; i++) {
                hlist_for_each_entry_safe(ctx, pos, next,
                                          &sec->ps_ccache[i], cc_hash)
                        ctx_check_death_locked(ctx, freelist);
        }

        sec->ps_gc_next = cfs_time_current_sec() + sec->ps_gc_interval;
        EXIT;
}

/*
 * @uid: which user. "-1" means flush all.
 * @grace: mark context DEAD, allow graceful destroy like notify
 *         server side, etc.
 * @force: also flush busy entries.
 *
 * return the number of busy context encountered.
 *
 * In any cases, never touch "eternal" contexts.
 */
static
int ctx_cache_flush(struct ptlrpc_sec *sec, uid_t uid, int grace, int force)
{
        struct ptlrpc_cli_ctx *ctx;
        struct hlist_node *pos, *next;
        HLIST_HEAD(freelist);
        int i, busy = 0;
        ENTRY;

        might_sleep_if(grace);

        spin_lock(&sec->ps_lock);
        for (i = 0; i < sec->ps_ccache_size; i++) {
                hlist_for_each_entry_safe(ctx, pos, next,
                                          &sec->ps_ccache[i], cc_hash) {
                        LASSERT(atomic_read(&ctx->cc_refcount) > 0);

                        if (ctx_is_eternal(ctx))
                                continue;
                        if (uid != -1 && uid != ctx->cc_vcred.vc_uid)
                                continue;

                        if (atomic_read(&ctx->cc_refcount) > 1) {
                                busy++;
                                if (!force)
                                        continue;

                                CWARN("flush busy(%d) ctx %p(%u->%s) by force, "
                                      "grace %d\n",
                                      atomic_read(&ctx->cc_refcount),
                                      ctx, ctx->cc_vcred.vc_uid,
                                      sec2target_str(ctx->cc_sec), grace);
                        }
                        ctx_unhash(ctx, &freelist);

                        set_bit(PTLRPC_CTX_DEAD_BIT, &ctx->cc_flags);
                        if (!grace)
                                clear_bit(PTLRPC_CTX_UPTODATE_BIT,
                                          &ctx->cc_flags);
                }
        }
        spin_unlock(&sec->ps_lock);

        ctx_list_destroy(&freelist);
        RETURN(busy);
}

static inline
unsigned int ctx_hash_index(struct ptlrpc_sec *sec, __u64 key)
{
        return (unsigned int) (key & (sec->ps_ccache_size - 1));
}

/*
 * return matched context. If it's a newly created one, we also give the
 * first push to refresh. return NULL if error happens.
 */
static
struct ptlrpc_cli_ctx * ctx_cache_lookup(struct ptlrpc_sec *sec,
                                         struct vfs_cred *vcred,
                                         int create, int remove_dead)
{
        struct ptlrpc_cli_ctx *ctx = NULL, *new = NULL;
        struct hlist_head *hash_head;
        struct hlist_node *pos, *next;
        HLIST_HEAD(freelist);
        unsigned int hash, gc = 0, found = 0;
        ENTRY;

        might_sleep();

        hash = ctx_hash_index(sec, (__u64) vcred->vc_uid);
        LASSERT(hash < sec->ps_ccache_size);
        hash_head = &sec->ps_ccache[hash];

retry:
        spin_lock(&sec->ps_lock);

        /* gc_next == 0 means never do gc */
        if (remove_dead && sec->ps_gc_next &&
            cfs_time_after(cfs_time_current_sec(), sec->ps_gc_next)) {
                ctx_cache_gc(sec, &freelist);
                gc = 1;
        }

        hlist_for_each_entry_safe(ctx, pos, next, hash_head, cc_hash) {
                if (gc == 0 &&
                    ctx_check_death_locked(ctx, remove_dead ? &freelist : NULL))
                        continue;

                if (ctx_match(ctx, vcred)) {
                        found = 1;
                        break;
                }
        }

        if (found) {
                if (new && new != ctx) {
                        /* lost the race, just free it */
                        hlist_add_head(&new->cc_hash, &freelist);
                        new = NULL;
                }

                /* hot node, move to head */
                if (hash_head->first != &ctx->cc_hash) {
                        __hlist_del(&ctx->cc_hash);
                        hlist_add_head(&ctx->cc_hash, hash_head);
                }
        } else {
                /* don't allocate for reverse sec */
                if (sec->ps_flags & PTLRPC_SEC_FL_REVERSE) {
                        spin_unlock(&sec->ps_lock);
                        RETURN(NULL);
                }

                if (new) {
                        ctx_enhash(new, hash_head);
                        ctx = new;
                } else if (create) {
                        spin_unlock(&sec->ps_lock);
                        new = sec->ps_policy->sp_cops->create_ctx(sec, vcred);
                        if (new) {
                                atomic_inc(&sec->ps_busy);
                                goto retry;
                        }
                } else
                        ctx = NULL;
        }

        /* hold a ref */
        if (ctx)
                atomic_inc(&ctx->cc_refcount);

        spin_unlock(&sec->ps_lock);

        /* the allocator of the context must give the first push to refresh */
        if (new) {
                LASSERT(new == ctx);
                sptlrpc_ctx_refresh(new);
        }

        ctx_list_destroy(&freelist);
        RETURN(ctx);
}

static inline
struct ptlrpc_cli_ctx *get_my_ctx(struct ptlrpc_sec *sec)
{
        struct vfs_cred vcred = { cfs_current()->uid, cfs_current()->gid };
        int create = 1, remove_dead = 1;

        if (sec->ps_flags & PTLRPC_SEC_FL_REVERSE) {
                vcred.vc_uid = 0;
                create = 0;
                remove_dead = 0;
        } else if (sec->ps_flags & PTLRPC_SEC_FL_ROOTONLY)
                vcred.vc_uid = 0;

        if (sec->ps_policy->sp_cops->lookup_ctx)
                return sec->ps_policy->sp_cops->lookup_ctx(sec, &vcred);
        else
                return ctx_cache_lookup(sec, &vcred, create, remove_dead);
}

/**************************************************
 * client context APIs                            *
 **************************************************/

static
void sptlrpc_ctx_refresh(struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);

        if (!ctx_is_refreshed(ctx) && ctx->cc_ops->refresh)
                ctx->cc_ops->refresh(ctx);
}

struct ptlrpc_cli_ctx *sptlrpc_ctx_get(struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);
        atomic_inc(&ctx->cc_refcount);
        return ctx;
}
EXPORT_SYMBOL(sptlrpc_ctx_get);

void sptlrpc_ctx_put(struct ptlrpc_cli_ctx *ctx, int sync)
{
        struct ptlrpc_sec *sec = ctx->cc_sec;

        LASSERT(sec);
        LASSERT(atomic_read(&ctx->cc_refcount));

        if (!atomic_dec_and_test(&ctx->cc_refcount))
                return;

        LASSERT(test_bit(PTLRPC_CTX_HASHED_BIT, &ctx->cc_flags) == 0);
        LASSERT(hlist_unhashed(&ctx->cc_hash));

        /* if required async, we must clear the UPTODATE bit to prevent extra
         * rpcs during destroy procedure.
         */
        if (!sync)
                clear_bit(PTLRPC_CTX_UPTODATE_BIT, &ctx->cc_flags);

        /* destroy this context */
        if (!sptlrpc_sec_destroy_ctx(sec, ctx))
                return;

        CWARN("%s@%p: put last ctx, also destroy the sec\n",
              sec->ps_policy->sp_name, sec);

        sptlrpc_sec_destroy(sec);
}
EXPORT_SYMBOL(sptlrpc_ctx_put);

/*
 * mark a ctx as DEAD, and pull it out from hash table.
 *
 * NOTE: the caller must hold at least 1 ref on the ctx.
 */
void sptlrpc_ctx_expire(struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(ctx->cc_sec);
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);

        ctx_expire(ctx);

        spin_lock(&ctx->cc_sec->ps_lock);

        if (test_and_clear_bit(PTLRPC_CTX_HASHED_BIT, &ctx->cc_flags)) {
                LASSERT(!hlist_unhashed(&ctx->cc_hash));
                LASSERT(atomic_read(&ctx->cc_refcount) > 1);

                hlist_del_init(&ctx->cc_hash);
                if (atomic_dec_and_test(&ctx->cc_refcount))
                        LBUG();
        }

        spin_unlock(&ctx->cc_sec->ps_lock);
}
EXPORT_SYMBOL(sptlrpc_ctx_expire);

void sptlrpc_ctx_replace(struct ptlrpc_sec *sec, struct ptlrpc_cli_ctx *new)
{
        struct ptlrpc_cli_ctx *ctx;
        struct hlist_node *pos, *next;
        HLIST_HEAD(freelist);
        unsigned int hash;
        ENTRY;

        hash = ctx_hash_index(sec, (__u64) new->cc_vcred.vc_uid);
        LASSERT(hash < sec->ps_ccache_size);

        spin_lock(&sec->ps_lock);

        hlist_for_each_entry_safe(ctx, pos, next,
                                  &sec->ps_ccache[hash], cc_hash) {
                if (!ctx_match(ctx, &new->cc_vcred))
                        continue;

                ctx_expire(ctx);
                ctx_unhash(ctx, &freelist);
                break;
        }

        ctx_enhash(new, &sec->ps_ccache[hash]);
        atomic_inc(&sec->ps_busy);

        spin_unlock(&sec->ps_lock);

        ctx_list_destroy(&freelist);
        EXIT;
}
EXPORT_SYMBOL(sptlrpc_ctx_replace);

int sptlrpc_req_get_ctx(struct ptlrpc_request *req)
{
        struct obd_import *imp = req->rq_import;
        ENTRY;

        LASSERT(!req->rq_cli_ctx);
        LASSERT(imp);

        req->rq_cli_ctx = get_my_ctx(imp->imp_sec);

        if (!req->rq_cli_ctx) {
                CERROR("req %p: fail to get context from cache\n", req);
                RETURN(-ENOMEM);
        }

        RETURN(0);
}

void sptlrpc_ctx_wakeup(struct ptlrpc_cli_ctx *ctx)
{
        struct ptlrpc_request *req, *next;

        spin_lock(&ctx->cc_lock);
        list_for_each_entry_safe(req, next, &ctx->cc_req_list, rq_ctx_chain) {
                list_del_init(&req->rq_ctx_chain);
                ptlrpc_wake_client_req(req);
        }
        spin_unlock(&ctx->cc_lock);
}
EXPORT_SYMBOL(sptlrpc_ctx_wakeup);

void sptlrpc_req_put_ctx(struct ptlrpc_request *req)
{
        ENTRY;

        LASSERT(req);
        LASSERT(req->rq_cli_ctx);

        /* request might be asked to release earlier while still
         * in the context waiting list.
         */
        if (!list_empty(&req->rq_ctx_chain)) {
                spin_lock(&req->rq_cli_ctx->cc_lock);
                list_del_init(&req->rq_ctx_chain);
                spin_unlock(&req->rq_cli_ctx->cc_lock);
        }

        /* this could be called with spinlock hold, use async mode */
        sptlrpc_ctx_put(req->rq_cli_ctx, 0);
        req->rq_cli_ctx = NULL;
        EXIT;
}

/*
 * request must have a context. if failed to get new context,
 * just restore the old one
 */
int sptlrpc_req_replace_dead_ctx(struct ptlrpc_request *req)
{
        struct ptlrpc_cli_ctx *ctx = req->rq_cli_ctx;
        int rc;
        ENTRY;

        LASSERT(ctx);
        LASSERT(test_bit(PTLRPC_CTX_DEAD_BIT, &ctx->cc_flags));

        /* make sure not on context waiting list */
        spin_lock(&ctx->cc_lock);
        list_del_init(&req->rq_ctx_chain);
        spin_unlock(&ctx->cc_lock);

        sptlrpc_ctx_get(ctx);
        sptlrpc_req_put_ctx(req);
        rc = sptlrpc_req_get_ctx(req);
        if (!rc) {
                LASSERT(req->rq_cli_ctx);
                LASSERT(req->rq_cli_ctx != ctx);
                sptlrpc_ctx_put(ctx, 1);
        } else {
                LASSERT(!req->rq_cli_ctx);
                req->rq_cli_ctx = ctx;
        }
        RETURN(rc);
}

static
int ctx_check_refresh(struct ptlrpc_cli_ctx *ctx)
{
        smp_mb();
        if (ctx_is_refreshed(ctx))
                return 1;
        return 0;
}

static
int ctx_refresh_timeout(void *data)
{
        struct ptlrpc_request *req = data;
        int rc;

        /* conn_cnt is needed in expire_one_request */
        lustre_msg_set_conn_cnt(req->rq_reqmsg, req->rq_import->imp_conn_cnt);

        rc = ptlrpc_expire_one_request(req);
        /* if we started recovery, we should mark this ctx dead; otherwise
         * in case of lgssd died nobody would retire this ctx, following
         * connecting will still find the same ctx thus cause deadlock.
         * there's an assumption that expire time of the request should be
         * later than the context refresh expire time.
         */
        if (rc == 0)
                ctx_expire(req->rq_cli_ctx);
        return rc;
}

static
void ctx_refresh_interrupt(void *data)
{
        /* do nothing */
}

/*
 * the status of context could be subject to be changed by other threads at any
 * time. we allow this race. but once we return with 0, the caller will
 * suppose it's uptodated and keep using it until the affected rpc is done.
 *
 * @timeout:
 *    < 0  - don't wait
 *    = 0  - wait until success or fatal error occur
 *    > 0  - timeout value
 *
 * return 0 only if the context is uptodated.
 */
int sptlrpc_req_refresh_ctx(struct ptlrpc_request *req, long timeout)
{
        struct ptlrpc_cli_ctx  *ctx = req->rq_cli_ctx;
        struct l_wait_info      lwi;
        int                     rc;
        ENTRY;

        LASSERT(ctx);

        /* special ctxs */
        if (ctx_is_eternal(ctx) || req->rq_ctx_init || req->rq_ctx_fini)
                RETURN(0);

        /* reverse ctxs, don't refresh */
        if (ctx->cc_sec->ps_flags & PTLRPC_SEC_FL_REVERSE)
                RETURN(0);

        spin_lock(&ctx->cc_lock);
again:
        if (ctx_check_uptodate(ctx)) {
                if (!list_empty(&req->rq_ctx_chain))
                        list_del_init(&req->rq_ctx_chain);
                spin_unlock(&ctx->cc_lock);
                RETURN(0);
        }

        if (test_bit(PTLRPC_CTX_ERROR_BIT, &ctx->cc_flags)) {
                req->rq_err = 1;
                if (!list_empty(&req->rq_ctx_chain))
                        list_del_init(&req->rq_ctx_chain);
                spin_unlock(&ctx->cc_lock);
                RETURN(-EPERM);
        }

        /* This is subtle. For resent message we have to keep original
         * context to survive following situation:
         *  1. the request sent to server
         *  2. recovery was kick start
         *  3. recovery finished, the request marked as resent
         *  4. resend the request
         *  5. old reply from server received (because xid is the same)
         *  6. verify reply (has to be success)
         *  7. new reply from server received, lnet drop it
         *
         * Note we can't simply change xid for resent request because
         * server reply on it for reply reconstruction.
         *
         * Commonly the original context should be uptodate because we
         * have a expiry nice time; And server will keep their half part
         * context because we at least hold a ref of old context which
         * prevent the context detroy RPC be sent. So server still can
         * accept the request and finish RPC. Two cases:
         *  1. If server side context has been trimed, a NO_CONTEXT will
         *     be returned, gss_cli_ctx_verify/unseal will switch to new
         *     context by force.
         *  2. Current context never be refreshed, then we are fine: we
         *     never really send request with old context before.
         */
        if (test_bit(PTLRPC_CTX_UPTODATE, &ctx->cc_flags) &&
            req->rq_reqmsg &&
            lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
                if (!list_empty(&req->rq_ctx_chain))
                        list_del_init(&req->rq_ctx_chain);
                spin_unlock(&ctx->cc_lock);
                RETURN(0);
        }

        if (unlikely(test_bit(PTLRPC_CTX_DEAD_BIT, &ctx->cc_flags))) {
                spin_unlock(&ctx->cc_lock);

                /* don't have to, but we don't want to release it too soon */
                sptlrpc_ctx_get(ctx);

                rc = sptlrpc_req_replace_dead_ctx(req);
                if (rc) {
                        LASSERT(ctx == req->rq_cli_ctx);
                        CERROR("req %p: failed to replace dead ctx %p\n",
                                req, ctx);
                        req->rq_err = 1;
                        LASSERT(list_empty(&req->rq_ctx_chain));
                        sptlrpc_ctx_put(ctx, 1);
                        RETURN(-ENOMEM);
                }

                LASSERT(ctx != req->rq_cli_ctx);
                CWARN("req %p: replace dead ctx %p(%u->%s) => %p\n",
                      req, ctx, ctx->cc_vcred.vc_uid,
                      sec2target_str(ctx->cc_sec), req->rq_cli_ctx);

                sptlrpc_ctx_put(ctx, 1);
                ctx = req->rq_cli_ctx;
                LASSERT(list_empty(&req->rq_ctx_chain));

                spin_lock(&ctx->cc_lock);
                goto again;
        }

        /* Now we're sure this context is during upcall, add myself into
         * waiting list
         */
        if (list_empty(&req->rq_ctx_chain))
                list_add(&req->rq_ctx_chain, &ctx->cc_req_list);

        spin_unlock(&ctx->cc_lock);

        if (timeout < 0) {
                RETURN(-EWOULDBLOCK);
        }

        /* Clear any flags that may be present from previous sends */
        LASSERT(req->rq_receiving_reply == 0);
        spin_lock(&req->rq_lock);
        req->rq_err = 0;
        req->rq_timedout = 0;
        req->rq_resend = 0;
        req->rq_restart = 0;
        spin_unlock(&req->rq_lock);

        lwi = LWI_TIMEOUT_INTR(timeout == 0 ? LONG_MAX : timeout * HZ,
                               ctx_refresh_timeout, ctx_refresh_interrupt, req);
        rc = l_wait_event(req->rq_reply_waitq, ctx_check_refresh(ctx), &lwi);

        spin_lock(&ctx->cc_lock);
        /* five cases we are here:
         * 1. successfully refreshed;
         * 2. someone else mark this ctx dead by force;
         * 3. interruptted;
         * 4. timedout, and we don't want recover from the failure;
         * 5. timedout, and waked up upon recovery finished;
         */
        if (!ctx_is_refreshed(ctx)) {
                /* timed out or interruptted */
                list_del_init(&req->rq_ctx_chain);
                spin_unlock(&ctx->cc_lock);

                LASSERT(rc != 0);
                RETURN(rc);
        }

        goto again;
}

void sptlrpc_req_set_flavor(struct ptlrpc_request *req, int opcode)
{
        struct sec_flavor_config *conf;

        LASSERT(req->rq_import);
        LASSERT(req->rq_import->imp_sec);
        LASSERT(req->rq_cli_ctx);
        LASSERT(req->rq_cli_ctx->cc_sec);
        LASSERT(req->rq_bulk_read == 0 || req->rq_bulk_write == 0);

        /* special security flags accoding to opcode */
        switch (opcode) {
        case OST_READ:
        case OST_SAN_READ:
                req->rq_bulk_read = 1;
                break;
        case OST_WRITE:
        case OST_SAN_WRITE:
                req->rq_bulk_write = 1;
                break;
        case SEC_CTX_INIT:
                req->rq_ctx_init = 1;
                break;
        case SEC_CTX_FINI:
                req->rq_ctx_fini = 1;
                break;
        }

        req->rq_sec_flavor = req->rq_cli_ctx->cc_sec->ps_flavor;

        /* force SVC_NONE for context initiation rpc, SVC_AUTH for context
         * destruction rpc
         */
        if (unlikely(req->rq_ctx_init)) {
                req->rq_sec_flavor = SEC_MAKE_RPC_FLAVOR(
                                SEC_FLAVOR_POLICY(req->rq_sec_flavor),
                                SEC_FLAVOR_SUBPOLICY(req->rq_sec_flavor),
                                SEC_FLAVOR_SVC(SPTLRPC_SVC_NONE));
        } else if (unlikely(req->rq_ctx_fini)) {
                req->rq_sec_flavor = SEC_MAKE_RPC_FLAVOR(
                                SEC_FLAVOR_POLICY(req->rq_sec_flavor),
                                SEC_FLAVOR_SUBPOLICY(req->rq_sec_flavor),
                                SEC_FLAVOR_SVC(SPTLRPC_SVC_AUTH));
        }

        conf = &req->rq_import->imp_obd->u.cli.cl_sec_conf;

        /* user descriptor flag, except ROOTONLY which don't need, and
         * null security which can't
         */
        if ((conf->sfc_flags & PTLRPC_SEC_FL_ROOTONLY) == 0 &&
            req->rq_sec_flavor != SPTLRPC_FLVR_NULL)
                req->rq_sec_flavor |= SEC_FLAVOR_FL_USER;

        /* bulk security flag */
        if ((req->rq_bulk_read || req->rq_bulk_write) &&
            (conf->sfc_bulk_priv != BULK_PRIV_ALG_NULL ||
             conf->sfc_bulk_csum != BULK_CSUM_ALG_NULL))
                req->rq_sec_flavor |= SEC_FLAVOR_FL_BULK;
}

void sptlrpc_request_out_callback(struct ptlrpc_request *req)
{
        if (SEC_FLAVOR_SVC(req->rq_sec_flavor) != SPTLRPC_SVC_PRIV)
                return;

        LASSERT(req->rq_clrbuf);
        if (req->rq_pool || !req->rq_reqbuf)
                return;

        OBD_FREE(req->rq_reqbuf, req->rq_reqbuf_len);
        req->rq_reqbuf = NULL;
        req->rq_reqbuf_len = 0;
}

/*
 * check whether current user have valid context for an import or not.
 * might repeatedly try in case of non-fatal errors.
 * return 0 on success, < 0 on failure
 */
int sptlrpc_import_check_ctx(struct obd_import *imp)
{
        struct ptlrpc_cli_ctx *ctx;
        struct ptlrpc_request *req = NULL;
        int rc;
        ENTRY;

        might_sleep();

        ctx = get_my_ctx(imp->imp_sec);
        if (!ctx)
                RETURN(1);

        if (ctx_is_eternal(ctx)) {
                sptlrpc_ctx_put(ctx, 1);
                RETURN(0);
        }

        OBD_ALLOC(req, sizeof(*req));
        if (!req)
                RETURN(-ENOMEM);

        spin_lock_init(&req->rq_lock);
        atomic_set(&req->rq_refcount, 10000);
        INIT_LIST_HEAD(&req->rq_ctx_chain);
        init_waitqueue_head(&req->rq_reply_waitq);
        req->rq_import = imp;
        req->rq_cli_ctx = ctx;

        rc = sptlrpc_req_refresh_ctx(req, 0);
        LASSERT(list_empty(&req->rq_ctx_chain));
        sptlrpc_ctx_put(req->rq_cli_ctx, 1);
        OBD_FREE(req, sizeof(*req));

        RETURN(rc);
}

int sptlrpc_cli_wrap_request(struct ptlrpc_request *req)
{
        struct ptlrpc_cli_ctx *ctx = req->rq_cli_ctx;
        int rc = 0;
        ENTRY;

        LASSERT(ctx);
        LASSERT(ctx->cc_sec);
        LASSERT(req->rq_reqbuf || req->rq_clrbuf);

        /* we wrap bulk request here because now we can be sure
         * the context is uptodate.
         */
        if (req->rq_bulk) {
                rc = sptlrpc_cli_wrap_bulk(req, req->rq_bulk);
                if (rc)
                        RETURN(rc);
        }

        switch (SEC_FLAVOR_SVC(req->rq_sec_flavor)) {
        case SPTLRPC_SVC_NONE:
        case SPTLRPC_SVC_AUTH:
                LASSERT(ctx->cc_ops->sign);
                rc = ctx->cc_ops->sign(ctx, req);
                break;
        case SPTLRPC_SVC_PRIV:
                LASSERT(ctx->cc_ops->seal);
                rc = ctx->cc_ops->seal(ctx, req);
                break;
        default:
                LBUG();
        }

        if (rc == 0) {
                LASSERT(req->rq_reqdata_len);
                LASSERT(req->rq_reqdata_len % 8 == 0);
                LASSERT(req->rq_reqdata_len <= req->rq_reqbuf_len);
        }

        RETURN(rc);
}

/*
 * rq_nob_received is the actual received data length
 */
int sptlrpc_cli_unwrap_reply(struct ptlrpc_request *req)
{
        struct ptlrpc_cli_ctx *ctx = req->rq_cli_ctx;
        int rc;
        ENTRY;

        LASSERT(ctx);
        LASSERT(ctx->cc_sec);
        LASSERT(ctx->cc_ops);
        LASSERT(req->rq_repbuf);

        req->rq_repdata_len = req->rq_nob_received;

        if (req->rq_nob_received < sizeof(struct lustre_msg)) {
                CERROR("replied data length %d too small\n",
                       req->rq_nob_received);
                RETURN(-EPROTO);
        }

        if (req->rq_repbuf->lm_magic == LUSTRE_MSG_MAGIC_V1 ||
            req->rq_repbuf->lm_magic == LUSTRE_MSG_MAGIC_V1_SWABBED) {
                /* it's must be null flavor, so our requets also should be
                 * in null flavor */
                if (SEC_FLAVOR_POLICY(req->rq_sec_flavor) !=
                    SPTLRPC_POLICY_NULL) {
                        CERROR("request flavor is %x but reply with null\n",
                               req->rq_sec_flavor);
                        RETURN(-EPROTO);
                }
        } else {
                /* v2 message... */
                ptlrpc_flavor_t tmpf = req->rq_repbuf->lm_secflvr;

                if (req->rq_repbuf->lm_magic == LUSTRE_MSG_MAGIC_V2_SWABBED)
                        __swab32s(&tmpf);

                if (SEC_FLAVOR_POLICY(tmpf) !=
                    SEC_FLAVOR_POLICY(req->rq_sec_flavor)) {
                        CERROR("request policy %u while reply with %d\n",
                               SEC_FLAVOR_POLICY(req->rq_sec_flavor),
                               SEC_FLAVOR_POLICY(tmpf));
                        RETURN(-EPROTO);
                }

                if ((SEC_FLAVOR_POLICY(req->rq_sec_flavor) !=
                     SPTLRPC_POLICY_NULL) &&
                    lustre_unpack_msg(req->rq_repbuf, req->rq_nob_received))
                        RETURN(-EPROTO);
        }

        switch (SEC_FLAVOR_SVC(req->rq_sec_flavor)) {
        case SPTLRPC_SVC_NONE:
        case SPTLRPC_SVC_AUTH:
                LASSERT(ctx->cc_ops->verify);
                rc = ctx->cc_ops->verify(ctx, req);
                break;
        case SPTLRPC_SVC_PRIV:
                LASSERT(ctx->cc_ops->unseal);
                rc = ctx->cc_ops->unseal(ctx, req);
                break;
        default:
                LBUG();
        }

        LASSERT(rc || req->rq_repmsg);
        RETURN(rc);
}

/**************************************************
 * security APIs                                  *
 **************************************************/

/*
 * let policy module to determine whether take refrence of
 * import or not.
 */
static
struct ptlrpc_sec * sptlrpc_sec_create(struct obd_import *imp,
                                       struct ptlrpc_svc_ctx *ctx,
                                       __u32 flavor,
                                       unsigned long flags)
{
        struct ptlrpc_sec_policy *policy;
        struct ptlrpc_sec *sec;
        ENTRY;

        flavor = SEC_FLAVOR_RPC(flavor);

        if (ctx) {
                LASSERT(imp->imp_dlm_fake == 1);

                CDEBUG(D_SEC, "%s %s: reverse sec using flavor %s\n",
                       imp->imp_obd->obd_type->typ_name,
                       imp->imp_obd->obd_name,
                       sptlrpc_flavor2name(flavor));

                policy = sptlrpc_policy_get(ctx->sc_policy);
                flags |= PTLRPC_SEC_FL_REVERSE | PTLRPC_SEC_FL_ROOTONLY;
        } else {
                LASSERT(imp->imp_dlm_fake == 0);

                CDEBUG(D_SEC, "%s %s: select security flavor %s\n",
                       imp->imp_obd->obd_type->typ_name,
                       imp->imp_obd->obd_name,
                       sptlrpc_flavor2name(flavor));

                policy = sptlrpc_flavor2policy(flavor);
                if (!policy) {
                        CERROR("invalid flavor 0x%x\n", flavor);
                        RETURN(NULL);
                }
        }

        sec = policy->sp_cops->create_sec(imp, ctx, flavor, flags);
        if (sec) {
                atomic_inc(&sec->ps_refcount);

                /* take 1 busy count on behalf of sec itself,
                 * balanced in sptlrpc_set_put()
                 */
                atomic_inc(&sec->ps_busy);
        } else
                sptlrpc_policy_put(policy);

        RETURN(sec);
}

static
void sptlrpc_sec_destroy(struct ptlrpc_sec *sec)
{
        struct ptlrpc_sec_policy *policy = sec->ps_policy;

        LASSERT(policy);
        LASSERT(atomic_read(&sec->ps_refcount) == 0);
        LASSERT(atomic_read(&sec->ps_busy) == 0);
        LASSERT(policy->sp_cops->destroy_sec);

        policy->sp_cops->destroy_sec(sec);
        sptlrpc_policy_put(policy);
}

static
void sptlrpc_sec_put(struct ptlrpc_sec *sec)
{
        struct ptlrpc_sec_policy *policy = sec->ps_policy;

        if (!atomic_dec_and_test(&sec->ps_refcount)) {
                sptlrpc_policy_put(policy);
                return;
        }

        ctx_cache_flush(sec, -1, 1, 1);

        if (atomic_dec_and_test(&sec->ps_busy))
                sptlrpc_sec_destroy(sec);
        else
                CWARN("delay to destroy %s@%p: busy contexts\n",
                      policy->sp_name, sec);
}

/*
 * return 1 means we should also destroy the sec structure.
 * normally return 0
 */
static
int sptlrpc_sec_destroy_ctx(struct ptlrpc_sec *sec,
                            struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(sec == ctx->cc_sec);
        LASSERT(atomic_read(&sec->ps_busy));
        LASSERT(atomic_read(&ctx->cc_refcount) == 0);
        LASSERT(hlist_unhashed(&ctx->cc_hash));
        LASSERT(list_empty(&ctx->cc_req_list));
        LASSERT(sec->ps_policy->sp_cops->destroy_ctx);

        sec->ps_policy->sp_cops->destroy_ctx(sec, ctx);

        if (atomic_dec_and_test(&sec->ps_busy)) {
                LASSERT(atomic_read(&sec->ps_refcount) == 0);
                return 1;
        }

        return 0;
}

/*
 * when complete successfully, req->rq_reqmsg should point to the
 * right place.
 */
int sptlrpc_cli_alloc_reqbuf(struct ptlrpc_request *req, int msgsize)
{
        struct ptlrpc_cli_ctx *ctx = req->rq_cli_ctx;
        struct ptlrpc_sec_policy *policy;
        int rc;

        LASSERT(ctx);
        LASSERT(atomic_read(&ctx->cc_refcount));
        LASSERT(ctx->cc_sec);
        LASSERT(ctx->cc_sec->ps_policy);
        LASSERT(req->rq_reqmsg == NULL);

        policy = ctx->cc_sec->ps_policy;
        rc = policy->sp_cops->alloc_reqbuf(ctx->cc_sec, req, msgsize);
        if (!rc) {
                LASSERT(req->rq_reqmsg);
                LASSERT(req->rq_reqbuf || req->rq_clrbuf);

                /* zeroing preallocated buffer */
                if (req->rq_pool)
                        memset(req->rq_reqmsg, 0, msgsize);
        }

        return rc;
}

void sptlrpc_cli_free_reqbuf(struct ptlrpc_request *req)
{
        struct ptlrpc_cli_ctx *ctx = req->rq_cli_ctx;
        struct ptlrpc_sec_policy *policy;

        LASSERT(ctx);
        LASSERT(atomic_read(&ctx->cc_refcount));
        LASSERT(ctx->cc_sec);
        LASSERT(ctx->cc_sec->ps_policy);
        LASSERT(req->rq_reqbuf || req->rq_clrbuf);

        policy = ctx->cc_sec->ps_policy;
        policy->sp_cops->free_reqbuf(ctx->cc_sec, req);
}

int sptlrpc_cli_alloc_repbuf(struct ptlrpc_request *req, int msgsize)
{
        struct ptlrpc_cli_ctx *ctx = req->rq_cli_ctx;
        struct ptlrpc_sec_policy *policy;
        ENTRY;

        LASSERT(ctx);
        LASSERT(atomic_read(&ctx->cc_refcount));
        LASSERT(ctx->cc_sec);
        LASSERT(ctx->cc_sec->ps_policy);

        if (req->rq_repbuf)
                RETURN(0);

        policy = ctx->cc_sec->ps_policy;
        RETURN(policy->sp_cops->alloc_repbuf(ctx->cc_sec, req, msgsize));
}

void sptlrpc_cli_free_repbuf(struct ptlrpc_request *req)
{
        struct ptlrpc_cli_ctx *ctx = req->rq_cli_ctx;
        struct ptlrpc_sec_policy *policy;
        ENTRY;

        LASSERT(ctx);
        LASSERT(atomic_read(&ctx->cc_refcount));
        LASSERT(ctx->cc_sec);
        LASSERT(ctx->cc_sec->ps_policy);
        LASSERT(req->rq_repbuf);

        policy = ctx->cc_sec->ps_policy;
        policy->sp_cops->free_repbuf(ctx->cc_sec, req);
        EXIT;
}

int sptlrpc_import_get_sec(struct obd_import *imp,
                           struct ptlrpc_svc_ctx *ctx,
                           __u32 flavor,
                           unsigned long flags)
{
        struct obd_device *obd = imp->imp_obd;
        ENTRY;

        LASSERT(obd);
        LASSERT(obd->obd_type);

        /* old sec might be still there in reconnecting */
        if (imp->imp_sec)
                RETURN(0);

        imp->imp_sec = sptlrpc_sec_create(imp, ctx, flavor, flags);
        if (!imp->imp_sec)
                RETURN(-EINVAL);

        RETURN(0);
}

void sptlrpc_import_put_sec(struct obd_import *imp)
{
        if (imp->imp_sec == NULL)
                return;

        sptlrpc_sec_put(imp->imp_sec);
        imp->imp_sec = NULL;
}

void sptlrpc_import_flush_root_ctx(struct obd_import *imp)
{
        if (imp == NULL || imp->imp_sec == NULL)
                return;

        /* use 'grace' mode, it's crutial see explain in
         * sptlrpc_req_refresh_ctx()
         */
        ctx_cache_flush(imp->imp_sec, 0, 1, 1);
}

void sptlrpc_import_flush_my_ctx(struct obd_import *imp)
{
        if (imp == NULL || imp->imp_sec == NULL)
                return;

        ctx_cache_flush(imp->imp_sec, cfs_current()->uid, 1, 1);
}
EXPORT_SYMBOL(sptlrpc_import_flush_my_ctx);

int sptlrpc_cli_install_rvs_ctx(struct obd_import *imp,
                                struct ptlrpc_cli_ctx *ctx)
{
        struct ptlrpc_sec_policy *policy = ctx->cc_sec->ps_policy;

        if (!policy->sp_cops->install_rctx)
                return 0;
        return policy->sp_cops->install_rctx(imp, ctx->cc_sec, ctx);
}

int sptlrpc_svc_install_rvs_ctx(struct obd_import *imp,
                                struct ptlrpc_svc_ctx *ctx)
{
        struct ptlrpc_sec_policy *policy = ctx->sc_policy;

        if (!policy->sp_sops->install_rctx)
                return 0;
        return policy->sp_sops->install_rctx(imp, ctx);
}

/****************************************
 * server side security                 *
 ****************************************/

int sptlrpc_svc_unwrap_request(struct ptlrpc_request *req)
{
        struct ptlrpc_sec_policy *policy;
        struct lustre_msg *msg = req->rq_reqbuf;
        int rc;
        ENTRY;

        LASSERT(msg);
        LASSERT(req->rq_reqmsg == NULL);
        LASSERT(req->rq_repmsg == NULL);

        /* 
         * in any case we avoid to call unpack_msg() for request of null flavor
         * which will later be done by ptlrpc_server_handle_request().
         */
        if (req->rq_reqdata_len < sizeof(struct lustre_msg)) {
                CERROR("request size %d too small\n", req->rq_reqdata_len);
                RETURN(SECSVC_DROP);
        }

        if (msg->lm_magic == LUSTRE_MSG_MAGIC_V1 ||
            msg->lm_magic == LUSTRE_MSG_MAGIC_V1_SWABBED) {
                req->rq_sec_flavor = SPTLRPC_FLVR_NULL;
        } else {
                req->rq_sec_flavor = msg->lm_secflvr;

                if (msg->lm_magic == LUSTRE_MSG_MAGIC_V2_SWABBED)
                        __swab32s(&req->rq_sec_flavor);

                if ((SEC_FLAVOR_POLICY(req->rq_sec_flavor) !=
                     SPTLRPC_POLICY_NULL) &&
                    lustre_unpack_msg(msg, req->rq_reqdata_len))
                        RETURN(SECSVC_DROP);
        }

        policy = sptlrpc_flavor2policy(req->rq_sec_flavor);
        if (!policy) {
                CERROR("unsupported security flavor %x\n", req->rq_sec_flavor);
                RETURN(SECSVC_DROP);
        }

        LASSERT(policy->sp_sops->accept);
        rc = policy->sp_sops->accept(req);

        LASSERT(req->rq_reqmsg || rc != SECSVC_OK);
        sptlrpc_policy_put(policy);

        /* FIXME move to proper place */
        if (rc == SECSVC_OK) {
                __u32 opc = lustre_msg_get_opc(req->rq_reqmsg);

                if (opc == OST_WRITE || opc == OST_SAN_WRITE)
                        req->rq_bulk_write = 1;
                else if (opc == OST_READ || opc == OST_SAN_READ)
                        req->rq_bulk_read = 1;
        }

        RETURN(rc);
}

int sptlrpc_svc_alloc_rs(struct ptlrpc_request *req,
                         int msglen)
{
        struct ptlrpc_sec_policy *policy;
        struct ptlrpc_reply_state *rs;
        int rc;
        ENTRY;

        LASSERT(req->rq_svc_ctx);
        LASSERT(req->rq_svc_ctx->sc_policy);

        policy = req->rq_svc_ctx->sc_policy;
        LASSERT(policy->sp_sops->alloc_rs);

        rc = policy->sp_sops->alloc_rs(req, msglen);
        if (unlikely(rc == -ENOMEM)) {
                /* failed alloc, try emergency pool */
                rs = lustre_get_emerg_rs(req->rq_rqbd->rqbd_service);
                if (rs == NULL)
                        RETURN(-ENOMEM);

                req->rq_reply_state = rs;
                rc = policy->sp_sops->alloc_rs(req, msglen);
                if (rc) {
                        lustre_put_emerg_rs(rs);
                        req->rq_reply_state = NULL;
                }
        }

        LASSERT(rc != 0 ||
                (req->rq_reply_state && req->rq_reply_state->rs_msg));

        RETURN(rc);
}

int sptlrpc_svc_wrap_reply(struct ptlrpc_request *req)
{
        struct ptlrpc_sec_policy *policy;
        int rc;
        ENTRY;

        LASSERT(req->rq_svc_ctx);
        LASSERT(req->rq_svc_ctx->sc_policy);

        policy = req->rq_svc_ctx->sc_policy;
        LASSERT(policy->sp_sops->authorize);

        rc = policy->sp_sops->authorize(req);
        LASSERT(rc || req->rq_reply_state->rs_repdata_len);

        RETURN(rc);
}

void sptlrpc_svc_free_rs(struct ptlrpc_reply_state *rs)
{
        struct ptlrpc_sec_policy *policy;
        unsigned int prealloc;
        ENTRY;

        LASSERT(rs->rs_svc_ctx);
        LASSERT(rs->rs_svc_ctx->sc_policy);

        policy = rs->rs_svc_ctx->sc_policy;
        LASSERT(policy->sp_sops->free_rs);

        prealloc = rs->rs_prealloc;
        policy->sp_sops->free_rs(rs);

        if (prealloc)
                lustre_put_emerg_rs(rs);
        EXIT;
}

void sptlrpc_svc_ctx_addref(struct ptlrpc_request *req)
{
        struct ptlrpc_svc_ctx *ctx = req->rq_svc_ctx;

        if (ctx == NULL)
                return;

        LASSERT(atomic_read(&ctx->sc_refcount) > 0);
        atomic_inc(&ctx->sc_refcount);
}

void sptlrpc_svc_ctx_decref(struct ptlrpc_request *req)
{
        struct ptlrpc_svc_ctx *ctx = req->rq_svc_ctx;

        if (ctx == NULL)
                return;

        LASSERT(atomic_read(&ctx->sc_refcount) > 0);
        if (atomic_dec_and_test(&ctx->sc_refcount)) {
                if (ctx->sc_policy->sp_sops->free_ctx)
                        ctx->sc_policy->sp_sops->free_ctx(ctx);
        }
        req->rq_svc_ctx = NULL;
}

/****************************************
 * bulk security                        *
 ****************************************/

int sptlrpc_cli_wrap_bulk(struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_cli_ctx *ctx;

        if (!SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor))
                return 0;

        LASSERT(req->rq_bulk_read || req->rq_bulk_write);

        ctx = req->rq_cli_ctx;
        if (ctx->cc_ops->wrap_bulk)
                return ctx->cc_ops->wrap_bulk(ctx, req, desc);
        return 0;
}
EXPORT_SYMBOL(sptlrpc_cli_wrap_bulk);

static
void pga_to_bulk_desc(int nob, obd_count pg_count, struct brw_page **pga,
                      struct ptlrpc_bulk_desc *desc)
{
        int i;

        LASSERT(pga);
        LASSERT(*pga);

        for (i = 0; i < pg_count && nob > 0; i++) {
#ifdef __KERNEL__
                desc->bd_iov[i].kiov_page = pga[i]->pg;
                desc->bd_iov[i].kiov_len = pga[i]->count > nob ?
                                           nob : pga[i]->count;
                desc->bd_iov[i].kiov_offset = pga[i]->off & ~CFS_PAGE_MASK;
#else
#warning FIXME for liblustre!
                desc->bd_iov[i].iov_base = pga[i]->pg->addr;
                desc->bd_iov[i].iov_len = pga[i]->count > nob ?
                                           nob : pga[i]->count;
#endif

                desc->bd_iov_count++;
                nob -= pga[i]->count;
        }
}

int sptlrpc_cli_unwrap_bulk_read(struct ptlrpc_request *req,
                                 int nob, obd_count pg_count,
                                 struct brw_page **pga)
{
        struct ptlrpc_bulk_desc *desc;
        struct ptlrpc_cli_ctx *ctx;
        int rc = 0;

        if (!SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor))
                return 0;

        LASSERT(req->rq_bulk_read && !req->rq_bulk_write);

        OBD_ALLOC(desc, offsetof(struct ptlrpc_bulk_desc, bd_iov[pg_count]));
        if (desc == NULL) {
                CERROR("out of memory, can't verify bulk read data\n");
                return -ENOMEM;
        }

        pga_to_bulk_desc(nob, pg_count, pga, desc);

        ctx = req->rq_cli_ctx;
        if (ctx->cc_ops->unwrap_bulk)
                rc = ctx->cc_ops->unwrap_bulk(ctx, req, desc);

        OBD_FREE(desc, offsetof(struct ptlrpc_bulk_desc, bd_iov[pg_count]));

        return rc;
}
EXPORT_SYMBOL(sptlrpc_cli_unwrap_bulk_read);

int sptlrpc_cli_unwrap_bulk_write(struct ptlrpc_request *req,
                                  struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_cli_ctx *ctx;

        if (!SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor))
                return 0;

        LASSERT(!req->rq_bulk_read && req->rq_bulk_write);

        ctx = req->rq_cli_ctx;
        if (ctx->cc_ops->unwrap_bulk)
                return ctx->cc_ops->unwrap_bulk(ctx, req, desc);

        return 0;
}
EXPORT_SYMBOL(sptlrpc_cli_unwrap_bulk_write);

int sptlrpc_svc_wrap_bulk(struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_svc_ctx *ctx;

        if (!SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor))
                return 0;

        LASSERT(req->rq_bulk_read || req->rq_bulk_write);

        ctx = req->rq_svc_ctx;
        if (ctx->sc_policy->sp_sops->wrap_bulk)
                return ctx->sc_policy->sp_sops->wrap_bulk(req, desc);

        return 0;
}
EXPORT_SYMBOL(sptlrpc_svc_wrap_bulk);

int sptlrpc_svc_unwrap_bulk(struct ptlrpc_request *req,
                            struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_svc_ctx *ctx;

        if (!SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor))
                return 0;

        LASSERT(req->rq_bulk_read || req->rq_bulk_write);

        ctx = req->rq_svc_ctx;
        if (ctx->sc_policy->sp_sops->unwrap_bulk);
                return ctx->sc_policy->sp_sops->unwrap_bulk(req, desc);

        return 0;
}
EXPORT_SYMBOL(sptlrpc_svc_unwrap_bulk);


/****************************************
 * user descriptor helpers              *
 ****************************************/

int sptlrpc_user_desc_size(void)
{
#ifdef __KERNEL__
        int ngroups = current_ngroups;

        if (ngroups > LUSTRE_MAX_GROUPS)
                ngroups = LUSTRE_MAX_GROUPS;

        return sizeof(struct ptlrpc_user_desc) + ngroups * sizeof(__u32);
#else
        return sizeof(struct ptlrpc_user_desc);
#endif
}
EXPORT_SYMBOL(sptlrpc_user_desc_size);

int sptlrpc_pack_user_desc(struct lustre_msg *msg, int offset)
{
        struct ptlrpc_user_desc *pud;

        pud = lustre_msg_buf(msg, offset, 0);

        pud->pud_uid = cfs_current()->uid;
        pud->pud_gid = cfs_current()->gid;
        pud->pud_fsuid = cfs_current()->fsuid;
        pud->pud_fsgid = cfs_current()->fsgid;
        pud->pud_cap = cfs_current()->cap_effective;
        pud->pud_ngroups = (msg->lm_buflens[offset] - sizeof(*pud)) / 4;

#ifdef __KERNEL__
        task_lock(current);
        if (pud->pud_ngroups > current_ngroups)
                pud->pud_ngroups = current_ngroups;
        memcpy(pud->pud_groups, cfs_current()->group_info->blocks[0],
               pud->pud_ngroups * sizeof(__u32));
        task_unlock(current);
#endif

        return 0;
}
EXPORT_SYMBOL(sptlrpc_pack_user_desc);

int sptlrpc_unpack_user_desc(struct lustre_msg *msg, int offset)
{
        struct ptlrpc_user_desc *pud;
        int                      i;

        pud = lustre_msg_buf(msg, offset, sizeof(*pud));
        if (!pud)
                return -EINVAL;

        if (lustre_msg_swabbed(msg)) {
                __swab32s(&pud->pud_uid);
                __swab32s(&pud->pud_gid);
                __swab32s(&pud->pud_fsuid);
                __swab32s(&pud->pud_fsgid);
                __swab32s(&pud->pud_cap);
                __swab32s(&pud->pud_ngroups);
        }

        if (pud->pud_ngroups > LUSTRE_MAX_GROUPS) {
                CERROR("%u groups is too large\n", pud->pud_ngroups);
                return -EINVAL;
        }

        if (sizeof(*pud) + pud->pud_ngroups * sizeof(__u32) >
            msg->lm_buflens[offset]) {
                CERROR("%u groups are claimed but bufsize only %u\n",
                       pud->pud_ngroups, msg->lm_buflens[offset]);
                return -EINVAL;
        }

        if (lustre_msg_swabbed(msg)) {
                for (i = 0; i < pud->pud_ngroups; i++)
                        __swab32s(&pud->pud_groups[i]);
        }

        return 0;
}
EXPORT_SYMBOL(sptlrpc_unpack_user_desc);

/****************************************
 * Helpers to assist policy modules to  *
 * implement checksum funcationality    *
 ****************************************/

struct {
        char    *name;
        int      size;
} csum_types[] = {
        [BULK_CSUM_ALG_NULL]    = { "null",     0 },
        [BULK_CSUM_ALG_CRC32]   = { "crc32",    4 },
        [BULK_CSUM_ALG_MD5]     = { "md5",     16 },
        [BULK_CSUM_ALG_SHA1]    = { "sha1",    20 },
        [BULK_CSUM_ALG_SHA256]  = { "sha256",  32 },
        [BULK_CSUM_ALG_SHA384]  = { "sha384",  48 },
        [BULK_CSUM_ALG_SHA512]  = { "sha512",  64 },
};

int bulk_sec_desc_size(__u32 csum_alg, int request, int read)
{
        int size = sizeof(struct ptlrpc_bulk_sec_desc);

        LASSERT(csum_alg < BULK_CSUM_ALG_MAX);

        /* read request don't need extra data */
        if (!(read && request))
                size += csum_types[csum_alg].size;

        return size;
}
EXPORT_SYMBOL(bulk_sec_desc_size);

int bulk_sec_desc_unpack(struct lustre_msg *msg, int offset)
{
        struct ptlrpc_bulk_sec_desc *bsd;
        int    size = msg->lm_buflens[offset];

        bsd = lustre_msg_buf(msg, offset, sizeof(*bsd));
        if (bsd == NULL) {
                CERROR("Invalid bulk sec desc: size %d\n", size);
                return -EINVAL;
        }

        if (lustre_msg_swabbed(msg)) {
                __swab32s(&bsd->bsd_version);
                __swab32s(&bsd->bsd_pad);
                __swab32s(&bsd->bsd_csum_alg);
                __swab32s(&bsd->bsd_priv_alg);
        }

        if (bsd->bsd_version != 0) {
                CERROR("Unexpected version %u\n", bsd->bsd_version);
                return -EPROTO;
        }

        if (bsd->bsd_csum_alg >= BULK_CSUM_ALG_MAX) {
                CERROR("Unsupported checksum algorithm %u\n",
                       bsd->bsd_csum_alg);
                return -EINVAL;
        }
        if (bsd->bsd_priv_alg >= BULK_PRIV_ALG_MAX) {
                CERROR("Unsupported cipher algorithm %u\n",
                       bsd->bsd_priv_alg);
                return -EINVAL;
        }

        if (size > sizeof(*bsd) &&
            size < sizeof(*bsd) + csum_types[bsd->bsd_csum_alg].size) {
                CERROR("Mal-formed checksum data: csum alg %u, size %d\n",
                       bsd->bsd_csum_alg, size);
                return -EINVAL;
        }

        return 0;
}
EXPORT_SYMBOL(bulk_sec_desc_unpack);

#ifdef __KERNEL__
static
int do_bulk_checksum_crc32(struct ptlrpc_bulk_desc *desc, void *buf)
{
        struct page *page;
        int off;
        char *ptr;
        __u32 crc32 = ~0;
        int len, i;

        for (i = 0; i < desc->bd_iov_count; i++) {
                page = desc->bd_iov[i].kiov_page;
                off = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                ptr = cfs_kmap(page) + off;
                len = desc->bd_iov[i].kiov_len;

                crc32 = crc32_le(crc32, ptr, len);

                cfs_kunmap(page);
        }

        *((__u32 *) buf) = crc32;
        return 0;
}

static
int do_bulk_checksum(struct ptlrpc_bulk_desc *desc, __u32 alg, void *buf)
{
        struct crypto_tfm *tfm;
        struct scatterlist *sl;
        int i, rc = 0;

        LASSERT(alg > BULK_CSUM_ALG_NULL &&
                alg < BULK_CSUM_ALG_MAX);

        if (alg == BULK_CSUM_ALG_CRC32)
                return do_bulk_checksum_crc32(desc, buf);

        tfm = crypto_alloc_tfm(csum_types[alg].name, 0);
        if (tfm == NULL) {
                CERROR("Unable to allocate tfm %s\n", csum_types[alg].name);
                return -ENOMEM;
        }

        OBD_ALLOC(sl, sizeof(*sl) * desc->bd_iov_count);
        if (sl == NULL) {
                rc = -ENOMEM;
                goto out_tfm;
        }

        for (i = 0; i < desc->bd_iov_count; i++) {
                sl[i].page = desc->bd_iov[i].kiov_page;
                sl[i].offset = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                sl[i].length = desc->bd_iov[i].kiov_len;
        }

        crypto_digest_init(tfm);
        crypto_digest_update(tfm, sl, desc->bd_iov_count);
        crypto_digest_final(tfm, buf);

        OBD_FREE(sl, sizeof(*sl) * desc->bd_iov_count);

out_tfm:
        crypto_free_tfm(tfm);
        return rc;
}
                         
#else /* !__KERNEL__ */
static
int do_bulk_checksum(struct ptlrpc_bulk_desc *desc, __u32 alg, void *buf)
{
        __u32 crc32 = ~0;
        int i;

        LASSERT(alg == BULK_CSUM_ALG_CRC32);

        for (i = 0; i < desc->bd_iov_count; i++) {
                char *ptr = desc->bd_iov[i].iov_base;
                int len = desc->bd_iov[i].iov_len;

                crc32 = crc32_le(crc32, ptr, len);
        }

        *((__u32 *) buf) = crc32;
        return 0;
}
#endif

/*
 * perform algorithm @alg checksum on @desc, store result in @buf.
 * if anything goes wrong, leave 'alg' be BULK_CSUM_ALG_NULL.
 */
static
int generate_bulk_csum(struct ptlrpc_bulk_desc *desc, __u32 alg,
                       struct ptlrpc_bulk_sec_desc *bsd, int bsdsize)
{
        int rc;

        LASSERT(bsd);
        LASSERT(alg < BULK_CSUM_ALG_MAX);

        bsd->bsd_csum_alg = BULK_CSUM_ALG_NULL;

        if (alg == BULK_CSUM_ALG_NULL)
                return 0;

        LASSERT(bsdsize >= sizeof(*bsd) + csum_types[alg].size);

        rc = do_bulk_checksum(desc, alg, bsd->bsd_csum);
        if (rc == 0)
                bsd->bsd_csum_alg = alg;

        return rc;
}

static
int verify_bulk_csum(struct ptlrpc_bulk_desc *desc, int read,
                     struct ptlrpc_bulk_sec_desc *bsdv, int bsdvsize,
                     struct ptlrpc_bulk_sec_desc *bsdr, int bsdrsize)
{
        char *csum_p;
        char *buf = NULL;
        int   csum_size, rc = 0;

        LASSERT(bsdv);
        LASSERT(bsdv->bsd_csum_alg < BULK_CSUM_ALG_MAX);

        if (bsdr)
                bsdr->bsd_csum_alg = BULK_CSUM_ALG_NULL;

        if (bsdv->bsd_csum_alg == BULK_CSUM_ALG_NULL)
                return 0;

        /* for all supported algorithms */
        csum_size = csum_types[bsdv->bsd_csum_alg].size;

        if (bsdvsize < sizeof(*bsdv) + csum_size) {
                CERROR("verifier size %d too small, require %d\n",
                       bsdvsize, sizeof(*bsdv) + csum_size);
                return -EINVAL;
        }

        if (bsdr) {
                LASSERT(bsdrsize >= sizeof(*bsdr) + csum_size);
                csum_p = (char *) bsdr->bsd_csum;
        } else {
                OBD_ALLOC(buf, csum_size);
                if (buf == NULL)
                        return -EINVAL;
                csum_p = buf;
        }

        rc = do_bulk_checksum(desc, bsdv->bsd_csum_alg, csum_p);

        if (memcmp(bsdv->bsd_csum, csum_p, csum_size)) {
                CERROR("BAD %s CHECKSUM (%s), data mutated during "
                       "transfer!\n", read ? "READ" : "WRITE",
                       csum_types[bsdv->bsd_csum_alg].name);
                rc = -EINVAL;
        } else {
                CDEBUG(D_SEC, "bulk %s checksum (%s) verified\n",
                      read ? "read" : "write",
                      csum_types[bsdv->bsd_csum_alg].name);
        }

        if (bsdr) {
                bsdr->bsd_csum_alg = bsdv->bsd_csum_alg;
                memcpy(bsdr->bsd_csum, csum_p, csum_size);
        } else {
                LASSERT(buf);
                OBD_FREE(buf, csum_size);
        }

        return rc;
}

int bulk_csum_cli_request(struct ptlrpc_bulk_desc *desc, int read,
                          __u32 alg, struct lustre_msg *rmsg, int roff)
{
        struct ptlrpc_bulk_sec_desc *bsdr;
        int    rsize, rc = 0;

        rsize = rmsg->lm_buflens[roff];
        bsdr = lustre_msg_buf(rmsg, roff, sizeof(*bsdr));

        LASSERT(bsdr);
        LASSERT(rsize >= sizeof(*bsdr));
        LASSERT(alg < BULK_CSUM_ALG_MAX);

        if (read)
                bsdr->bsd_csum_alg = alg;
        else {
                rc = generate_bulk_csum(desc, alg, bsdr, rsize);
                if (rc) {
                        CERROR("client bulk write: failed to perform "
                               "checksum: %d\n", rc);
                }
        }

        return rc;
}
EXPORT_SYMBOL(bulk_csum_cli_request);

int bulk_csum_cli_reply(struct ptlrpc_bulk_desc *desc, int read,
                        struct lustre_msg *rmsg, int roff,
                        struct lustre_msg *vmsg, int voff)
{
        struct ptlrpc_bulk_sec_desc *bsdv, *bsdr;
        int    rsize, vsize;

        rsize = rmsg->lm_buflens[roff];
        vsize = vmsg->lm_buflens[voff];
        bsdr = lustre_msg_buf(rmsg, roff, 0);
        bsdv = lustre_msg_buf(vmsg, voff, 0);

        if (bsdv == NULL || vsize < sizeof(*bsdv)) {
                CERROR("Invalid checksum verifier from server: size %d\n",
                       vsize);
                return -EINVAL;
        }

        LASSERT(bsdr);
        LASSERT(rsize >= sizeof(*bsdr));
        LASSERT(vsize >= sizeof(*bsdv));

        if (bsdr->bsd_csum_alg != bsdv->bsd_csum_alg) {
                CERROR("bulk %s: checksum algorithm mismatch: client request "
                       "%s but server reply with %s. try to use the new one "
                       "for checksum verification\n",
                       read ? "read" : "write",
                       csum_types[bsdr->bsd_csum_alg].name,
                       csum_types[bsdv->bsd_csum_alg].name);
        }

        if (read)
                return verify_bulk_csum(desc, 1, bsdv, vsize, NULL, 0);
        else {
                char *cli, *srv, *new = NULL;
                int csum_size = csum_types[bsdr->bsd_csum_alg].size;

                LASSERT(bsdr->bsd_csum_alg < BULK_CSUM_ALG_MAX);
                if (bsdr->bsd_csum_alg == BULK_CSUM_ALG_NULL)
                        return 0;

                if (vsize < sizeof(*bsdv) + csum_size) {
                        CERROR("verifier size %d too small, require %d\n",
                               vsize, sizeof(*bsdv) + csum_size);
                        return -EINVAL;
                }

                cli = (char *) (bsdr + 1);
                srv = (char *) (bsdv + 1);

                if (!memcmp(cli, srv, csum_size)) {
                        /* checksum confirmed */
                        CDEBUG(D_SEC, "bulk write checksum (%s) confirmed\n",
                              csum_types[bsdr->bsd_csum_alg].name);
                        return 0;
                }

                /* checksum mismatch, re-compute a new one and compare with
                 * others, give out proper warnings.
                 */
                OBD_ALLOC(new, csum_size);
                if (new == NULL)
                        return -ENOMEM;

                do_bulk_checksum(desc, bsdr->bsd_csum_alg, new);

                if (!memcmp(new, srv, csum_size)) {
                        CERROR("BAD WRITE CHECKSUM (%s): pages were mutated "
                               "on the client after we checksummed them\n",
                               csum_types[bsdr->bsd_csum_alg].name);
                } else if (!memcmp(new, cli, csum_size)) {
                        CERROR("BAD WRITE CHECKSUM (%s): pages were mutated "
                               "in transit\n",
                               csum_types[bsdr->bsd_csum_alg].name);
                } else {
                        CERROR("BAD WRITE CHECKSUM (%s): pages were mutated "
                               "in transit, and the current page contents "
                               "don't match the originals and what the server "
                               "received\n",
                               csum_types[bsdr->bsd_csum_alg].name);
                }
                OBD_FREE(new, csum_size);

                return -EINVAL;
        }
}
EXPORT_SYMBOL(bulk_csum_cli_reply);

int bulk_csum_svc(struct ptlrpc_bulk_desc *desc, int read,
                  struct lustre_msg *vmsg, int voff,
                  struct lustre_msg *rmsg, int roff)
{
        struct ptlrpc_bulk_sec_desc *bsdv, *bsdr;
        int    vsize, rsize, rc;

        vsize = vmsg->lm_buflens[voff];
        rsize = rmsg->lm_buflens[roff];
        bsdv = lustre_msg_buf(vmsg, voff, 0);
        bsdr = lustre_msg_buf(rmsg, roff, 0);

        LASSERT(vsize >= sizeof(*bsdv));
        LASSERT(rsize >= sizeof(*bsdr));
        LASSERT(bsdv && bsdr);

        if (read) {
                rc = generate_bulk_csum(desc, bsdv->bsd_csum_alg, bsdr, rsize);
                if (rc)
                        CERROR("bulk read: server failed to generate %s "
                               "checksum: %d\n",
                               csum_types[bsdv->bsd_csum_alg].name, rc);
        } else
                rc = verify_bulk_csum(desc, 0, bsdv, vsize, bsdr, rsize);

        return rc;
}
EXPORT_SYMBOL(bulk_csum_svc);

/****************************************
 * user supplied flavor string parsing  *
 ****************************************/

static
int get_default_flavor(enum lustre_part to_part, struct sec_flavor_config *conf)
{
        conf->sfc_bulk_priv = BULK_PRIV_ALG_NULL;
        conf->sfc_bulk_csum = BULK_CSUM_ALG_NULL;
        conf->sfc_flags = 0;

        switch (to_part) {
        case LUSTRE_MDT:
                conf->sfc_rpc_flavor = SPTLRPC_FLVR_PLAIN;
                return 0;
        case LUSTRE_OST:
                conf->sfc_rpc_flavor = SPTLRPC_FLVR_NULL;
                return 0;
        default:
                CERROR("Unknown to lustre part %d, apply defaults\n", to_part);
                conf->sfc_rpc_flavor = SPTLRPC_FLVR_NULL;
                return -EINVAL;
        }
}

static
void get_flavor_by_rpc(__u32 rpc_flavor, struct sec_flavor_config *conf)
{
        conf->sfc_rpc_flavor = rpc_flavor;
        conf->sfc_bulk_priv = BULK_PRIV_ALG_NULL;
        conf->sfc_bulk_csum = BULK_CSUM_ALG_NULL;
        conf->sfc_flags = 0;

        switch (rpc_flavor) {
        case SPTLRPC_FLVR_NULL:
        case SPTLRPC_FLVR_PLAIN:
                break;
        case SPTLRPC_FLVR_KRB5P:
                conf->sfc_bulk_priv = BULK_PRIV_ALG_ARC4;
                /* fall through */
        case SPTLRPC_FLVR_KRB5I:
                conf->sfc_bulk_csum = BULK_CSUM_ALG_SHA1;
                break;
        default:
                LBUG();
        }
}

static
void get_flavor_by_rpc_bulk(__u32 rpc_flavor, int bulk_priv,
                            struct sec_flavor_config *conf)
{
        if (bulk_priv)
                conf->sfc_bulk_priv = BULK_PRIV_ALG_ARC4;
        else
                conf->sfc_bulk_priv = BULK_PRIV_ALG_NULL;

        switch (rpc_flavor) {
        case SPTLRPC_FLVR_PLAIN:
                conf->sfc_bulk_csum = BULK_CSUM_ALG_MD5;
                break;
        case SPTLRPC_FLVR_KRB5I:
        case SPTLRPC_FLVR_KRB5P:
                conf->sfc_bulk_csum = BULK_CSUM_ALG_SHA1;
                break;
        default:
                LBUG();
        }
}

static __u32 __flavors[] = {
        SPTLRPC_FLVR_NULL,
        SPTLRPC_FLVR_PLAIN,
        SPTLRPC_FLVR_KRB5I,
        SPTLRPC_FLVR_KRB5P,
};

#define __nflavors      (sizeof(__flavors)/sizeof(__u32))

/*
 * flavor string format: rpc[-bulk[:cksum/enc]]
 * for examples:
 *  null
 *  plain-bulki
 *  krb5p-bulkn
 *  krb5i-bulkp
 *  krb5i-bulkp:sha512/arc4
 */
int sptlrpc_parse_flavor(enum lustre_part from_part, enum lustre_part to_part,
                         char *str, struct sec_flavor_config *conf)
{
        char   *f, *bulk, *alg, *enc;
        char    buf[64];
        int     i, bulk_priv;
        ENTRY;

        if (str == NULL) {
                if (get_default_flavor(to_part, conf))
                        return -EINVAL;
                goto set_flags;
        }

        for (i = 0; i < __nflavors; i++) {
                f = sptlrpc_flavor2name(__flavors[i]);
                if (strncmp(str, f, strlen(f)) == 0)
                        break;
        }

        if (i >= __nflavors)
                GOTO(invalid, -EINVAL);

        /* prepare local buffer thus we can modify it as we want */
        strncpy(buf, str, 64);
        buf[64 - 1] = '\0';

        /* find bulk string */
        bulk = strchr(buf, '-');
        if (bulk)
                *bulk++ = '\0';

        /* now the first part must equal to rpc flavor name */
        if (strcmp(buf, f) != 0)
                GOTO(invalid, -EINVAL);

        get_flavor_by_rpc(__flavors[i], conf);

        if (bulk == NULL)
                goto set_flags;

        /* null flavor should not have any suffix */
        if (__flavors[i] == SPTLRPC_FLVR_NULL)
                GOTO(invalid, -EINVAL);

        /* find bulk algorithm string */
        alg = strchr(bulk, ':');
        if (alg)
                *alg++ = '\0';

        /* verify bulk section */
        if (strcmp(bulk, "bulkn") == 0) {
                conf->sfc_bulk_csum = BULK_CSUM_ALG_NULL;
                conf->sfc_bulk_priv = BULK_PRIV_ALG_NULL;
                goto set_flags;
        }

        if (strcmp(bulk, "bulki") == 0)
                bulk_priv = 0;
        else if (strcmp(bulk, "bulkp") == 0)
                bulk_priv = 1;
        else
                GOTO(invalid, -EINVAL);

        /* plain policy dosen't support bulk encryption */
        if (bulk_priv && __flavors[i] == SPTLRPC_FLVR_PLAIN)
                GOTO(invalid, -EINVAL);

        get_flavor_by_rpc_bulk(__flavors[i], bulk_priv, conf);

        if (alg == NULL)
                goto set_flags;

        /* find encryption algorithm string */
        enc = strchr(alg, '/');
        if (enc)
                *enc++ = '\0';

        /* bulk combination sanity check */
        if ((bulk_priv && enc == NULL) || (bulk_priv == 0 && enc))
                GOTO(invalid, -EINVAL);

        /* checksum algorithm */
        for (i = 0; i < BULK_CSUM_ALG_MAX; i++) {
                if (strcmp(alg, csum_types[i].name) == 0) {
                        conf->sfc_bulk_csum = i;
                        break;
                }
        }
        if (i >= BULK_CSUM_ALG_MAX)
                GOTO(invalid, -EINVAL);

        /* privacy algorithm */
        if (enc) {
                if (strcmp(enc, "arc4") != 0)
                        GOTO(invalid, -EINVAL);
                conf->sfc_bulk_priv = BULK_PRIV_ALG_ARC4;
        }

set_flags:
        /* set ROOTONLY flag to:
         *  - to OST
         *  - from MDT to MDT
         */
        if ((to_part == LUSTRE_MDT && from_part == LUSTRE_MDT) ||
            to_part == LUSTRE_OST)
                conf->sfc_flags |= PTLRPC_SEC_FL_ROOTONLY;

#ifdef __BIG_ENDIAN
        __swab32s(&conf->sfc_rpc_flavor);
        __swab32s(&conf->sfc_bulk_csum);
        __swab32s(&conf->sfc_bulk_priv);
        __swab32s(&conf->sfc_flags);
#endif
        return 0;
invalid:
        CERROR("invalid flavor string: %s\n", str);
        return -EINVAL;
}
EXPORT_SYMBOL(sptlrpc_parse_flavor);

/****************************************
 * misc helpers                         *
 ****************************************/

const char * sec2target_str(struct ptlrpc_sec *sec)
{
        if (!sec || !sec->ps_import || !sec->ps_import->imp_obd)
                return "*";
        if (sec->ps_flags & PTLRPC_SEC_FL_REVERSE)
                return "c";
        return obd_uuid2str(&sec->ps_import->imp_obd->u.cli.cl_target_uuid);
}
EXPORT_SYMBOL(sec2target_str);

int sptlrpc_lprocfs_rd(char *page, char **start, off_t off, int count,
                       int *eof, void *data)
{
        struct obd_device        *obd = data;
        struct sec_flavor_config *conf = &obd->u.cli.cl_sec_conf;
        struct ptlrpc_sec        *sec = NULL;
        char                      flags_str[20];

        if (obd == NULL)
                return 0;

        LASSERT(strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) == 0 ||
                strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) == 0 ||
                strcmp(obd->obd_type->typ_name, LUSTRE_MGC_NAME) == 0);
        LASSERT(conf->sfc_bulk_csum < BULK_CSUM_ALG_MAX);
        LASSERT(conf->sfc_bulk_priv < BULK_PRIV_ALG_MAX);

        if (obd->u.cli.cl_import)
                sec = obd->u.cli.cl_import->imp_sec;

        flags_str[0] = '\0';
        if (conf->sfc_flags & PTLRPC_SEC_FL_REVERSE)
                strncat(flags_str, "reverse,", sizeof(flags_str));
        if (conf->sfc_flags & PTLRPC_SEC_FL_ROOTONLY)
                strncat(flags_str, "rootonly,", sizeof(flags_str));
        if (flags_str[0] != '\0')
                flags_str[strlen(flags_str) - 1] = '\0';

        return snprintf(page, count,
                        "rpc_flavor:  %s\n"
                        "bulk_flavor: %s checksum, %s encryption\n"
                        "flags:       %s\n"
                        "ctx_cache:   size %u, busy %d\n"
                        "gc:          interval %lus, next %lds\n",
                        sptlrpc_flavor2name(conf->sfc_rpc_flavor),
                        csum_types[conf->sfc_bulk_csum].name,
                        conf->sfc_bulk_priv == BULK_PRIV_ALG_NULL ?
                        "null" : "arc4", // XXX
                        flags_str,
                        sec ? sec->ps_ccache_size : 0,
                        sec ? atomic_read(&sec->ps_busy) : 0,
                        sec ? sec->ps_gc_interval: 0,
                        sec ? (sec->ps_gc_interval ?
                               sec->ps_gc_next - cfs_time_current_sec() : 0)
                              : 0);
}
EXPORT_SYMBOL(sptlrpc_lprocfs_rd);


int sptlrpc_init(void)
{
        int rc;

        rc = sptlrpc_null_init();
        if (rc)
                goto out;

        rc = sptlrpc_plain_init();
        if (rc)
                goto out_null;
        return 0;

out_null:
        sptlrpc_null_exit();
out:
        return rc;
}

int sptlrpc_exit(void)
{
        sptlrpc_plain_exit();
        sptlrpc_null_exit();
        return 0;
}
