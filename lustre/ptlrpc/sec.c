/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004-2007 Cluster File Systems, Inc.
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
#define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/libcfs.h>
#ifndef __KERNEL__
#include <liblustre.h>
#include <libcfs/list.h>
#else
#include <linux/crypto.h>
#include <linux/key.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

/***********************************************
 * policy registers                            *
 ***********************************************/

static rwlock_t policy_lock = RW_LOCK_UNLOCKED;
static struct ptlrpc_sec_policy *policies[SPTLRPC_POLICY_MAX] = {
        NULL,
};

int sptlrpc_register_policy(struct ptlrpc_sec_policy *policy)
{
        __u16 number = policy->sp_policy;

        LASSERT(policy->sp_name);
        LASSERT(policy->sp_cops);
        LASSERT(policy->sp_sops);

        if (number >= SPTLRPC_POLICY_MAX)
                return -EINVAL;

        write_lock(&policy_lock);
        if (unlikely(policies[number])) {
                write_unlock(&policy_lock);
                return -EALREADY;
        }
        policies[number] = policy;
        write_unlock(&policy_lock);

        CDEBUG(D_SEC, "%s: registered\n", policy->sp_name);
        return 0;
}
EXPORT_SYMBOL(sptlrpc_register_policy);

int sptlrpc_unregister_policy(struct ptlrpc_sec_policy *policy)
{
        __u16 number = policy->sp_policy;

        LASSERT(number < SPTLRPC_POLICY_MAX);

        write_lock(&policy_lock);
        if (unlikely(policies[number] == NULL)) {
                write_unlock(&policy_lock);
                CERROR("%s: already unregistered\n", policy->sp_name);
                return -EINVAL;
        }

        LASSERT(policies[number] == policy);
        policies[number] = NULL;
        write_unlock(&policy_lock);

        CDEBUG(D_SEC, "%s: unregistered\n", policy->sp_name);
        return 0;
}
EXPORT_SYMBOL(sptlrpc_unregister_policy);

static
struct ptlrpc_sec_policy * sptlrpc_rpcflavor2policy(__u16 flavor)
{
        static DECLARE_MUTEX(load_mutex);
        static atomic_t           loaded = ATOMIC_INIT(0);
        struct ptlrpc_sec_policy *policy;
        __u16                     number = RPC_FLVR_POLICY(flavor), flag = 0;

        if (number >= SPTLRPC_POLICY_MAX)
                return NULL;

        while (1) {
                read_lock(&policy_lock);
                policy = policies[number];
                if (policy && !try_module_get(policy->sp_owner))
                        policy = NULL;
                if (policy == NULL)
                        flag = atomic_read(&loaded);
                read_unlock(&policy_lock);

                if (policy != NULL || flag != 0 ||
                    number != SPTLRPC_POLICY_GSS)
                        break;

                /* try to load gss module, once */
                mutex_down(&load_mutex);
                if (atomic_read(&loaded) == 0) {
                        if (request_module("ptlrpc_gss") == 0)
                                CWARN("module ptlrpc_gss loaded on demand\n");
                        else
                                CERROR("Unable to load module ptlrpc_gss\n");

                        atomic_set(&loaded, 1);
                }
                mutex_up(&load_mutex);
        }

        return policy;
}

__u16 sptlrpc_name2rpcflavor(const char *name)
{
        if (!strcmp(name, "null"))
                return SPTLRPC_FLVR_NULL;
        if (!strcmp(name, "plain"))
                return SPTLRPC_FLVR_PLAIN;
        if (!strcmp(name, "krb5n"))
                return SPTLRPC_FLVR_KRB5N;
        if (!strcmp(name, "krb5a"))
                return SPTLRPC_FLVR_KRB5A;
        if (!strcmp(name, "krb5i"))
                return SPTLRPC_FLVR_KRB5I;
        if (!strcmp(name, "krb5p"))
                return SPTLRPC_FLVR_KRB5P;

        return SPTLRPC_FLVR_INVALID;
}
EXPORT_SYMBOL(sptlrpc_name2rpcflavor);

const char *sptlrpc_rpcflavor2name(__u16 flavor)
{
        switch (flavor) {
        case SPTLRPC_FLVR_NULL:
                return "null";
        case SPTLRPC_FLVR_PLAIN:
                return "plain";
        case SPTLRPC_FLVR_KRB5N:
                return "krb5n";
        case SPTLRPC_FLVR_KRB5A:
                return "krb5a";
        case SPTLRPC_FLVR_KRB5I:
                return "krb5i";
        case SPTLRPC_FLVR_KRB5P:
                return "krb5p";
        default:
                CERROR("invalid rpc flavor 0x%x(p%u,s%u,v%u)\n", flavor,
                       RPC_FLVR_POLICY(flavor), RPC_FLVR_MECH(flavor),
                       RPC_FLVR_SVC(flavor));
        }
        return "unknown";
}
EXPORT_SYMBOL(sptlrpc_rpcflavor2name);

int sptlrpc_flavor2name(struct sptlrpc_flavor *sf, char *buf, int bufsize)
{
        char           *bulk;

        if (sf->sf_bulk_ciph != BULK_CIPH_ALG_NULL)
                bulk = "bulkp";
        else if (sf->sf_bulk_hash != BULK_HASH_ALG_NULL)
                bulk = "bulki";
        else
                bulk = "bulkn";

        snprintf(buf, bufsize, "%s-%s:%s/%s",
                 sptlrpc_rpcflavor2name(sf->sf_rpc), bulk,
                 sptlrpc_get_hash_name(sf->sf_bulk_hash),
                 sptlrpc_get_ciph_name(sf->sf_bulk_ciph));
        return 0;
}
EXPORT_SYMBOL(sptlrpc_flavor2name);

/**************************************************
 * client context APIs                            *
 **************************************************/

static
struct ptlrpc_cli_ctx *get_my_ctx(struct ptlrpc_sec *sec)
{
        struct vfs_cred vcred;
        int create = 1, remove_dead = 1;

        LASSERT(sec);
        LASSERT(sec->ps_policy->sp_cops->lookup_ctx);

        if (sec->ps_flvr.sf_flags & (PTLRPC_SEC_FL_REVERSE |
                                     PTLRPC_SEC_FL_ROOTONLY)) {
                vcred.vc_uid = 0;
                vcred.vc_gid = 0;
                if (sec->ps_flvr.sf_flags & PTLRPC_SEC_FL_REVERSE) {
                        create = 0;
                        remove_dead = 0;
                }
        } else {
                vcred.vc_uid = cfs_current()->uid;
                vcred.vc_gid = cfs_current()->gid;
        }

        return sec->ps_policy->sp_cops->lookup_ctx(sec, &vcred,
                                                   create, remove_dead);
}

struct ptlrpc_cli_ctx *sptlrpc_cli_ctx_get(struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(atomic_read(&ctx->cc_refcount) > 0);
        atomic_inc(&ctx->cc_refcount);
        return ctx;
}
EXPORT_SYMBOL(sptlrpc_cli_ctx_get);

void sptlrpc_cli_ctx_put(struct ptlrpc_cli_ctx *ctx, int sync)
{
        struct ptlrpc_sec *sec = ctx->cc_sec;

        LASSERT(sec);
        LASSERT(atomic_read(&ctx->cc_refcount));

        if (!atomic_dec_and_test(&ctx->cc_refcount))
                return;

        sec->ps_policy->sp_cops->release_ctx(sec, ctx, sync);
}
EXPORT_SYMBOL(sptlrpc_cli_ctx_put);

/*
 * expire the context immediately.
 * the caller must hold at least 1 ref on the ctx.
 */
void sptlrpc_cli_ctx_expire(struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(ctx->cc_ops->die);
        ctx->cc_ops->die(ctx, 0);
}
EXPORT_SYMBOL(sptlrpc_cli_ctx_expire);

void sptlrpc_cli_ctx_wakeup(struct ptlrpc_cli_ctx *ctx)
{
        struct ptlrpc_request *req, *next;

        spin_lock(&ctx->cc_lock);
        list_for_each_entry_safe(req, next, &ctx->cc_req_list, rq_ctx_chain) {
                list_del_init(&req->rq_ctx_chain);
                ptlrpc_wake_client_req(req);
        }
        spin_unlock(&ctx->cc_lock);
}
EXPORT_SYMBOL(sptlrpc_cli_ctx_wakeup);

int sptlrpc_cli_ctx_display(struct ptlrpc_cli_ctx *ctx, char *buf, int bufsize)
{
        LASSERT(ctx->cc_ops);

        if (ctx->cc_ops->display == NULL)
                return 0;

        return ctx->cc_ops->display(ctx, buf, bufsize);
}

static int sptlrpc_import_sec_check_expire(struct obd_import *imp)
{
        int     adapt = 0;

        spin_lock(&imp->imp_lock);
        if (imp->imp_sec_expire &&
            imp->imp_sec_expire < cfs_time_current_sec()) {
                adapt = 1;
                imp->imp_sec_expire = 0;
        }
        spin_unlock(&imp->imp_lock);

        if (!adapt)
                return 0;

        CDEBUG(D_SEC, "found delayed sec adapt expired, do it now\n");
        return sptlrpc_import_sec_adapt(imp, NULL, 0);
}

int sptlrpc_req_get_ctx(struct ptlrpc_request *req)
{
        struct obd_import *imp = req->rq_import;
        struct ptlrpc_sec *sec;
        int                rc;
        ENTRY;

        LASSERT(!req->rq_cli_ctx);
        LASSERT(imp);

        if (unlikely(imp->imp_sec_expire)) {
                rc = sptlrpc_import_sec_check_expire(imp);
                if (rc)
                        RETURN(rc);
        }

        sec = sptlrpc_import_sec_ref(imp);
        if (sec == NULL) {
                CERROR("import %p (%s) with no ptlrpc_sec\n",
                       imp, ptlrpc_import_state_name(imp->imp_state));
                RETURN(-EACCES);
        }

        if (unlikely(sec->ps_dying)) {
                CERROR("attempt to use dying sec %p\n", sec);
                return -EACCES;
        }

        req->rq_cli_ctx = get_my_ctx(sec);

        sptlrpc_sec_put(sec);

        if (!req->rq_cli_ctx) {
                CERROR("req %p: fail to get context\n", req);
                RETURN(-ENOMEM);
        }

        RETURN(0);
}

/*
 * if @sync == 0, this function should return quickly without sleep;
 * otherwise might trigger ctx destroying rpc to server.
 */
void sptlrpc_req_put_ctx(struct ptlrpc_request *req, int sync)
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

        sptlrpc_cli_ctx_put(req->rq_cli_ctx, sync);
        req->rq_cli_ctx = NULL;
        EXIT;
}

static
int sptlrpc_req_ctx_switch(struct ptlrpc_request *req,
                           struct ptlrpc_cli_ctx *oldctx,
                           struct ptlrpc_cli_ctx *newctx)
{
        struct sptlrpc_flavor   old_flvr;
        char                   *reqmsg;
        int                     reqmsg_size;
        int                     rc;

        if (likely(oldctx->cc_sec == newctx->cc_sec))
                return 0;

        LASSERT(req->rq_reqmsg);
        LASSERT(req->rq_reqlen);
        LASSERT(req->rq_replen);

        CWARN("req %p: switch ctx %p -> %p, switch sec %p(%s) -> %p(%s)\n",
              req, oldctx, newctx,
              oldctx->cc_sec, oldctx->cc_sec->ps_policy->sp_name,
              newctx->cc_sec, newctx->cc_sec->ps_policy->sp_name);

        /* save flavor */
        old_flvr = req->rq_flvr;

        /* save request message */
        reqmsg_size = req->rq_reqlen;
        OBD_ALLOC(reqmsg, reqmsg_size);
        if (reqmsg == NULL)
                return -ENOMEM;
        memcpy(reqmsg, req->rq_reqmsg, reqmsg_size);

        /* release old req/rep buf */
        req->rq_cli_ctx = oldctx;
        sptlrpc_cli_free_reqbuf(req);
        sptlrpc_cli_free_repbuf(req);
        req->rq_cli_ctx = newctx;

        /* recalculate the flavor */
        sptlrpc_req_set_flavor(req, 0);

        /* alloc new request buffer
         * we don't need to alloc reply buffer here, leave it to the
         * rest procedure of ptlrpc
         */
        rc = sptlrpc_cli_alloc_reqbuf(req, reqmsg_size);
        if (!rc) {
                LASSERT(req->rq_reqmsg);
                memcpy(req->rq_reqmsg, reqmsg, reqmsg_size);
        } else {
                CWARN("failed to alloc reqbuf: %d\n", rc);
                req->rq_flvr = old_flvr;
        }

        OBD_FREE(reqmsg, reqmsg_size);
        return rc;
}

/*
 * request must have a context. in any case of failure, restore the
 * restore the old one. a request must have a ctx.
 */
int sptlrpc_req_replace_dead_ctx(struct ptlrpc_request *req)
{
        struct ptlrpc_cli_ctx *oldctx = req->rq_cli_ctx;
        struct ptlrpc_cli_ctx *newctx;
        int                    rc;
        ENTRY;

        LASSERT(oldctx);
        LASSERT(test_bit(PTLRPC_CTX_DEAD_BIT, &oldctx->cc_flags));

        sptlrpc_cli_ctx_get(oldctx);
        sptlrpc_req_put_ctx(req, 0);

        rc = sptlrpc_req_get_ctx(req);
        if (unlikely(rc)) {
                LASSERT(!req->rq_cli_ctx);

                /* restore old ctx */
                req->rq_cli_ctx = oldctx;
                RETURN(rc);
        }

        newctx = req->rq_cli_ctx;
        LASSERT(newctx);

        if (unlikely(newctx == oldctx)) {
                /*
                 * still get the old ctx, usually means system busy
                 */
                CWARN("ctx (%p, fl %lx) doesn't switch, relax a little bit\n",
                      newctx, newctx->cc_flags);

                schedule_timeout(HZ);
        } else {
                rc = sptlrpc_req_ctx_switch(req, oldctx, newctx);
                if (rc) {
                        /* restore old ctx */
                        sptlrpc_req_put_ctx(req, 0);
                        req->rq_cli_ctx = oldctx;
                        RETURN(rc);
                }

                LASSERT(req->rq_cli_ctx == newctx);
        }

        sptlrpc_cli_ctx_put(oldctx, 1);
        RETURN(0);
}
EXPORT_SYMBOL(sptlrpc_req_replace_dead_ctx);

static
int ctx_check_refresh(struct ptlrpc_cli_ctx *ctx)
{
        if (cli_ctx_is_refreshed(ctx))
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
                req->rq_cli_ctx->cc_ops->die(req->rq_cli_ctx, 0);
        return rc;
}

static
void ctx_refresh_interrupt(void *data)
{
        struct ptlrpc_request *req = data;

        spin_lock(&req->rq_lock);
        req->rq_intr = 1;
        spin_unlock(&req->rq_lock);
}

static
void req_off_ctx_list(struct ptlrpc_request *req, struct ptlrpc_cli_ctx *ctx)
{
        spin_lock(&ctx->cc_lock);
        if (!list_empty(&req->rq_ctx_chain))
                list_del_init(&req->rq_ctx_chain);
        spin_unlock(&ctx->cc_lock);
}

/*
 * the status of context could be subject to be changed by other threads at any
 * time. we allow this race. but once we return with 0, the caller will
 * suppose it's uptodated and keep using it until the owning rpc is done.
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

        /*
         * during the process a request's context might change type even
         * (e.g. from gss ctx to plain ctx), so each loop we need to re-check
         * everything
         */
again:
        /* skip special ctxs */
        if (cli_ctx_is_eternal(ctx) || req->rq_ctx_init || req->rq_ctx_fini)
                RETURN(0);

        if (test_bit(PTLRPC_CTX_NEW_BIT, &ctx->cc_flags)) {
                LASSERT(ctx->cc_ops->refresh);
                ctx->cc_ops->refresh(ctx);
        }
        LASSERT(test_bit(PTLRPC_CTX_NEW_BIT, &ctx->cc_flags) == 0);

        LASSERT(ctx->cc_ops->validate);
        if (ctx->cc_ops->validate(ctx) == 0) {
                req_off_ctx_list(req, ctx);
                RETURN(0);
        }

        if (unlikely(test_bit(PTLRPC_CTX_ERROR_BIT, &ctx->cc_flags))) {
                req->rq_err = 1;
                req_off_ctx_list(req, ctx);
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
        if (test_bit(PTLRPC_CTX_UPTODATE_BIT, &ctx->cc_flags) &&
            unlikely(req->rq_reqmsg) &&
            lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
                req_off_ctx_list(req, ctx);
                RETURN(0);
        }

        if (unlikely(test_bit(PTLRPC_CTX_DEAD_BIT, &ctx->cc_flags))) {
                rc = sptlrpc_req_replace_dead_ctx(req);
                if (rc) {
                        LASSERT(ctx == req->rq_cli_ctx);
                        CERROR("req %p: failed to replace dead ctx %p: %d\n",
                                req, ctx, rc);
                        req->rq_err = 1;
                        LASSERT(list_empty(&req->rq_ctx_chain));
                        RETURN(rc);
                }

                CWARN("req %p: replace dead ctx %p => ctx %p (%u->%s)\n",
                      req, ctx, req->rq_cli_ctx,
                      req->rq_cli_ctx->cc_vcred.vc_uid,
                      sec2target_str(req->rq_cli_ctx->cc_sec));

                ctx = req->rq_cli_ctx;
                LASSERT(list_empty(&req->rq_ctx_chain));

                goto again;
        }

        /* Now we're sure this context is during upcall, add myself into
         * waiting list
         */
        spin_lock(&ctx->cc_lock);
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

        lwi = LWI_TIMEOUT_INTR(timeout * HZ, ctx_refresh_timeout,
                               ctx_refresh_interrupt, req);
        rc = l_wait_event(req->rq_reply_waitq, ctx_check_refresh(ctx), &lwi);

        /* following cases we could be here:
         * - successfully refreshed;
         * - interruptted;
         * - timedout, and we don't want recover from the failure;
         * - timedout, and waked up upon recovery finished;
         * - someone else mark this ctx dead by force;
         * - someone invalidate the req and call wake_client_req(),
         *   e.g. ptlrpc_abort_inflight();
         */
        if (!cli_ctx_is_refreshed(ctx)) {
                /* timed out or interruptted */
                req_off_ctx_list(req, ctx);

                LASSERT(rc != 0);
                RETURN(rc);
        }

        goto again;
}

/*
 * Note this could be called in two situations:
 * - new request from ptlrpc_pre_req(), with proper @opcode
 * - old request which changed ctx in the middle, with @opcode == 0
 */
void sptlrpc_req_set_flavor(struct ptlrpc_request *req, int opcode)
{
        struct ptlrpc_sec *sec;

        LASSERT(req->rq_import);
        LASSERT(req->rq_cli_ctx);
        LASSERT(req->rq_cli_ctx->cc_sec);
        LASSERT(req->rq_bulk_read == 0 || req->rq_bulk_write == 0);

        /* special security flags accoding to opcode */
        switch (opcode) {
        case OST_READ:
                req->rq_bulk_read = 1;
                break;
        case OST_WRITE:
                req->rq_bulk_write = 1;
                break;
        case SEC_CTX_INIT:
                req->rq_ctx_init = 1;
                break;
        case SEC_CTX_FINI:
                req->rq_ctx_fini = 1;
                break;
        case 0:
                /* init/fini rpc won't be resend, so can't be here */
                LASSERT(req->rq_ctx_init == 0);
                LASSERT(req->rq_ctx_fini == 0);

                /* cleanup flags, which should be recalculated */
                req->rq_pack_udesc = 0;
                req->rq_pack_bulk = 0;
                break;
        }

        sec = req->rq_cli_ctx->cc_sec;

        spin_lock(&sec->ps_lock);
        req->rq_flvr = sec->ps_flvr;
        spin_unlock(&sec->ps_lock);

        /* force SVC_NULL for context initiation rpc, SVC_INTG for context
         * destruction rpc */
        if (unlikely(req->rq_ctx_init))
                rpc_flvr_set_svc(&req->rq_flvr.sf_rpc, SPTLRPC_SVC_NULL);
        else if (unlikely(req->rq_ctx_fini))
                rpc_flvr_set_svc(&req->rq_flvr.sf_rpc, SPTLRPC_SVC_INTG);

        /* user descriptor flag, null security can't do it anyway */
        if ((sec->ps_flvr.sf_flags & PTLRPC_SEC_FL_UDESC) &&
            (req->rq_flvr.sf_rpc != SPTLRPC_FLVR_NULL))
                req->rq_pack_udesc = 1;

        /* bulk security flag */
        if ((req->rq_bulk_read || req->rq_bulk_write) &&
            (req->rq_flvr.sf_bulk_ciph != BULK_CIPH_ALG_NULL ||
             req->rq_flvr.sf_bulk_hash != BULK_HASH_ALG_NULL))
                req->rq_pack_bulk = 1;
}

void sptlrpc_request_out_callback(struct ptlrpc_request *req)
{
        if (RPC_FLVR_SVC(req->rq_flvr.sf_rpc) != SPTLRPC_SVC_PRIV)
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
        struct ptlrpc_sec     *sec;
        struct ptlrpc_cli_ctx *ctx;
        struct ptlrpc_request *req = NULL;
        int rc;
        ENTRY;

        might_sleep();

        sec = sptlrpc_import_sec_ref(imp);
        ctx = get_my_ctx(sec);
        sptlrpc_sec_put(sec);

        if (!ctx)
                RETURN(1);

        if (cli_ctx_is_eternal(ctx) ||
            ctx->cc_ops->validate(ctx) == 0) {
                sptlrpc_cli_ctx_put(ctx, 1);
                RETURN(0);
        }

        OBD_ALLOC_PTR(req);
        if (!req)
                RETURN(-ENOMEM);

        spin_lock_init(&req->rq_lock);
        atomic_set(&req->rq_refcount, 10000);
        CFS_INIT_LIST_HEAD(&req->rq_ctx_chain);
        init_waitqueue_head(&req->rq_reply_waitq);
        req->rq_import = imp;
        req->rq_cli_ctx = ctx;

        rc = sptlrpc_req_refresh_ctx(req, 0);
        LASSERT(list_empty(&req->rq_ctx_chain));
        sptlrpc_cli_ctx_put(req->rq_cli_ctx, 1);
        OBD_FREE_PTR(req);

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

        switch (RPC_FLVR_SVC(req->rq_flvr.sf_rpc)) {
        case SPTLRPC_SVC_NULL:
        case SPTLRPC_SVC_AUTH:
        case SPTLRPC_SVC_INTG:
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

static int do_cli_unwrap_reply(struct ptlrpc_request *req)
{
        struct ptlrpc_cli_ctx *ctx = req->rq_cli_ctx;
        int                    rc;
        __u16                  rpc_flvr;
        ENTRY;

        LASSERT(ctx);
        LASSERT(ctx->cc_sec);
        LASSERT(req->rq_repbuf);
        LASSERT(req->rq_repdata);
        LASSERT(req->rq_repmsg == NULL);

        if (req->rq_repdata_len < sizeof(struct lustre_msg)) {
                CERROR("replied data length %d too small\n",
                       req->rq_repdata_len);
                RETURN(-EPROTO);
        }

        /* v2 message, check request/reply policy match */
        rpc_flvr = WIRE_FLVR_RPC(req->rq_repdata->lm_secflvr);

        if (req->rq_repdata->lm_magic == LUSTRE_MSG_MAGIC_V2_SWABBED)
                __swab16s(&rpc_flvr);

        if (RPC_FLVR_POLICY(rpc_flvr) !=
            RPC_FLVR_POLICY(req->rq_flvr.sf_rpc)) {
                CERROR("request policy was %u while reply with %u\n",
                       RPC_FLVR_POLICY(req->rq_flvr.sf_rpc),
                       RPC_FLVR_POLICY(rpc_flvr));
                RETURN(-EPROTO);
        }

        /* do nothing if it's null policy; otherwise unpack the
         * wrapper message */
        if (RPC_FLVR_POLICY(rpc_flvr) != SPTLRPC_POLICY_NULL &&
            lustre_unpack_msg(req->rq_repdata, req->rq_repdata_len))
                RETURN(-EPROTO);

        switch (RPC_FLVR_SVC(req->rq_flvr.sf_rpc)) {
        case SPTLRPC_SVC_NULL:
        case SPTLRPC_SVC_AUTH:
        case SPTLRPC_SVC_INTG:
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

        LASSERT(rc || req->rq_repmsg || req->rq_resend);
        RETURN(rc);
}

/*
 * upon this be called, the reply buffer should have been un-posted,
 * so nothing is going to change.
 */
int sptlrpc_cli_unwrap_reply(struct ptlrpc_request *req)
{
        LASSERT(req->rq_repbuf);
        LASSERT(req->rq_repdata == NULL);
        LASSERT(req->rq_repmsg == NULL);
        LASSERT(req->rq_reply_off + req->rq_nob_received <= req->rq_repbuf_len);

        if (req->rq_reply_off == 0) {
                CERROR("real reply with offset 0\n");
                return -EPROTO;
        }

        if (req->rq_reply_off % 8 != 0) {
                CERROR("reply at odd offset %u\n", req->rq_reply_off);
                return -EPROTO;
        }

        req->rq_repdata = (struct lustre_msg *)
                                (req->rq_repbuf + req->rq_reply_off);
        req->rq_repdata_len = req->rq_nob_received;

        return do_cli_unwrap_reply(req);
}

/*
 * Upon called, the receive buffer might be still posted, so the reply data
 * might be changed at any time, no matter we're holding rq_lock or not. we
 * expect the rq_reply_off be 0, rq_nob_received is the early reply size.
 *
 * we allocate a separate buffer to hold early reply data, pointed by
 * rq_repdata, rq_repdata_len is the early reply size, and round up to power2
 * is the actual buffer size.
 *
 * caller _must_ call sptlrpc_cli_finish_early_reply() after this, before
 * process another early reply or real reply, to restore ptlrpc_request
 * to normal status.
 */
int sptlrpc_cli_unwrap_early_reply(struct ptlrpc_request *req)
{
        struct lustre_msg      *early_buf;
        int                     early_bufsz, early_size;
        int                     rc;
        ENTRY;

        LASSERT(req->rq_repbuf);
        LASSERT(req->rq_repdata == NULL);
        LASSERT(req->rq_repmsg == NULL);

        early_size = req->rq_nob_received;
        if (early_size < sizeof(struct lustre_msg)) {
                CERROR("early reply length %d too small\n", early_size);
                RETURN(-EPROTO);
        }

        early_bufsz = size_roundup_power2(early_size);
        OBD_ALLOC(early_buf, early_bufsz);
        if (early_buf == NULL)
                RETURN(-ENOMEM);

        /* copy data out, do it inside spinlock */
        spin_lock(&req->rq_lock);

        if (req->rq_replied) {
                spin_unlock(&req->rq_lock);
                GOTO(err_free, rc = -EALREADY);
        }

        if (req->rq_reply_off != 0) {
                CERROR("early reply with offset %u\n", req->rq_reply_off);
                GOTO(err_free, rc = -EPROTO);
        }

        if (req->rq_nob_received != early_size) {
                /* even another early arrived the size should be the same */
                CWARN("data size has changed from %u to %u\n",
                      early_size, req->rq_nob_received);
                spin_unlock(&req->rq_lock);
                GOTO(err_free, rc = -EINVAL);
        }

        if (req->rq_nob_received < sizeof(struct lustre_msg)) {
                CERROR("early reply length %d too small\n",
                       req->rq_nob_received);
                spin_unlock(&req->rq_lock);
                GOTO(err_free, rc = -EALREADY);
        }

        memcpy(early_buf, req->rq_repbuf, early_size);
        spin_unlock(&req->rq_lock);

        req->rq_repdata = early_buf;
        req->rq_repdata_len = early_size;

        rc = do_cli_unwrap_reply(req);

        /* treate resend as an error case. in fact server should never ask
         * resend via early reply. */
        if (req->rq_resend) {
                req->rq_resend = 0;
                rc = -EPROTO;
        }

        if (rc) {
                LASSERT(req->rq_repmsg == NULL);
                req->rq_repdata = NULL;
                req->rq_repdata_len = 0;
                GOTO(err_free, rc);
        }

        LASSERT(req->rq_repmsg);
        RETURN(0);

err_free:
        OBD_FREE(early_buf, early_bufsz);
        RETURN(rc);
}

int sptlrpc_cli_finish_early_reply(struct ptlrpc_request *req)
{
        int     early_bufsz;

        LASSERT(req->rq_repdata);
        LASSERT(req->rq_repdata_len);
        LASSERT(req->rq_repmsg);

        early_bufsz = size_roundup_power2(req->rq_repdata_len);
        OBD_FREE(req->rq_repdata, early_bufsz);

        req->rq_repdata = NULL;
        req->rq_repdata_len = 0;
        req->rq_repmsg = NULL;
        return 0;
}

/**************************************************
 * sec ID                                         *
 **************************************************/

/*
 * "fixed" sec (e.g. null) use sec_id < 0
 */
static atomic_t sptlrpc_sec_id = ATOMIC_INIT(1);

int sptlrpc_get_next_secid(void)
{
        return atomic_inc_return(&sptlrpc_sec_id);
}
EXPORT_SYMBOL(sptlrpc_get_next_secid);

/**************************************************
 * client side high-level security APIs           *
 **************************************************/

static int sec_cop_flush_ctx_cache(struct ptlrpc_sec *sec, uid_t uid,
                                   int grace, int force)
{
        struct ptlrpc_sec_policy *policy = sec->ps_policy;

        LASSERT(policy->sp_cops);
        LASSERT(policy->sp_cops->flush_ctx_cache);

        return policy->sp_cops->flush_ctx_cache(sec, uid, grace, force);
}

static void sec_cop_destroy_sec(struct ptlrpc_sec *sec)
{
        struct ptlrpc_sec_policy *policy = sec->ps_policy;

        LASSERT(atomic_read(&sec->ps_refcount) == 0);
        LASSERT(atomic_read(&sec->ps_nctx) == 0);
        LASSERT(policy->sp_cops->destroy_sec);

        CDEBUG(D_SEC, "%s@%p: being destroied\n", sec->ps_policy->sp_name, sec);

        policy->sp_cops->destroy_sec(sec);
        sptlrpc_policy_put(policy);
}

void sptlrpc_sec_destroy(struct ptlrpc_sec *sec)
{
        sec_cop_destroy_sec(sec);
}
EXPORT_SYMBOL(sptlrpc_sec_destroy);

static void sptlrpc_sec_kill(struct ptlrpc_sec *sec)
{
        LASSERT(atomic_read(&sec->ps_refcount) > 0);

        if (sec->ps_policy->sp_cops->kill_sec) {
                sec->ps_policy->sp_cops->kill_sec(sec);

                sec_cop_flush_ctx_cache(sec, -1, 1, 1);
        }
}

struct ptlrpc_sec *sptlrpc_sec_get(struct ptlrpc_sec *sec)
{
        if (sec) {
                LASSERT(atomic_read(&sec->ps_refcount) > 0);
                atomic_inc(&sec->ps_refcount);
        }

        return sec;
}
EXPORT_SYMBOL(sptlrpc_sec_get);

void sptlrpc_sec_put(struct ptlrpc_sec *sec)
{
        if (sec) {
                LASSERT(atomic_read(&sec->ps_refcount) > 0);

                if (atomic_dec_and_test(&sec->ps_refcount)) {
                        LASSERT(atomic_read(&sec->ps_nctx) == 0);

                        sptlrpc_gc_del_sec(sec);
                        sec_cop_destroy_sec(sec);
                }
        }
}
EXPORT_SYMBOL(sptlrpc_sec_put);

/*
 * it's policy module responsible for taking refrence of import
 */
static
struct ptlrpc_sec * sptlrpc_sec_create(struct obd_import *imp,
                                       struct ptlrpc_svc_ctx *svc_ctx,
                                       struct sptlrpc_flavor *sf,
                                       enum lustre_sec_part sp)
{
        struct ptlrpc_sec_policy *policy;
        struct ptlrpc_sec        *sec;
        ENTRY;

        if (svc_ctx) {
                LASSERT(imp->imp_dlm_fake == 1);

                CDEBUG(D_SEC, "%s %s: reverse sec using flavor %s\n",
                       imp->imp_obd->obd_type->typ_name,
                       imp->imp_obd->obd_name,
                       sptlrpc_rpcflavor2name(sf->sf_rpc));

                policy = sptlrpc_policy_get(svc_ctx->sc_policy);
                sf->sf_flags |= PTLRPC_SEC_FL_REVERSE | PTLRPC_SEC_FL_ROOTONLY;
        } else {
                LASSERT(imp->imp_dlm_fake == 0);

                CDEBUG(D_SEC, "%s %s: select security flavor %s\n",
                       imp->imp_obd->obd_type->typ_name,
                       imp->imp_obd->obd_name,
                       sptlrpc_rpcflavor2name(sf->sf_rpc));

                policy = sptlrpc_rpcflavor2policy(sf->sf_rpc);
                if (!policy) {
                        CERROR("invalid flavor 0x%x\n", sf->sf_rpc);
                        RETURN(NULL);
                }
        }

        sec = policy->sp_cops->create_sec(imp, svc_ctx, sf);
        if (sec) {
                atomic_inc(&sec->ps_refcount);

                sec->ps_part = sp;

                if (sec->ps_gc_interval && policy->sp_cops->gc_ctx)
                        sptlrpc_gc_add_sec(sec);
        } else {
                sptlrpc_policy_put(policy);
        }

        RETURN(sec);
}

struct ptlrpc_sec *sptlrpc_import_sec_ref(struct obd_import *imp)
{
        struct ptlrpc_sec *sec;

        spin_lock(&imp->imp_lock);
        sec = sptlrpc_sec_get(imp->imp_sec);
        spin_unlock(&imp->imp_lock);

        return sec;
}
EXPORT_SYMBOL(sptlrpc_import_sec_ref);

static void sptlrpc_import_sec_install(struct obd_import *imp,
                                       struct ptlrpc_sec *sec)
{
        struct ptlrpc_sec *old_sec;

        LASSERT(atomic_read(&sec->ps_refcount) > 0);

        spin_lock(&imp->imp_lock);
        old_sec = imp->imp_sec;
        imp->imp_sec = sec;
        spin_unlock(&imp->imp_lock);

        if (old_sec) {
                sptlrpc_sec_kill(old_sec);

                /* balance the ref taken by this import */
                sptlrpc_sec_put(old_sec);
        }
}

static void sptlrpc_import_sec_adapt_inplace(struct obd_import *imp,
                                             struct ptlrpc_sec *sec,
                                             struct sptlrpc_flavor *sf)
{
        if (sf->sf_bulk_ciph != sec->ps_flvr.sf_bulk_ciph ||
            sf->sf_bulk_hash != sec->ps_flvr.sf_bulk_hash) {
                CWARN("imp %p (%s->%s): changing bulk flavor %s/%s -> %s/%s\n",
                      imp, imp->imp_obd->obd_name,
                      obd_uuid2str(&imp->imp_connection->c_remote_uuid),
                      sptlrpc_get_ciph_name(sec->ps_flvr.sf_bulk_ciph),
                      sptlrpc_get_hash_name(sec->ps_flvr.sf_bulk_hash),
                      sptlrpc_get_ciph_name(sf->sf_bulk_ciph),
                      sptlrpc_get_hash_name(sf->sf_bulk_hash));

                spin_lock(&sec->ps_lock);
                sec->ps_flvr.sf_bulk_ciph = sf->sf_bulk_ciph;
                sec->ps_flvr.sf_bulk_hash = sf->sf_bulk_hash;
                spin_unlock(&sec->ps_lock);
        }

        if (!equi(sf->sf_flags & PTLRPC_SEC_FL_UDESC,
                  sec->ps_flvr.sf_flags & PTLRPC_SEC_FL_UDESC)) {
                CWARN("imp %p (%s->%s): %s shipping user descriptor\n",
                      imp, imp->imp_obd->obd_name,
                      obd_uuid2str(&imp->imp_connection->c_remote_uuid),
                      (sf->sf_flags & PTLRPC_SEC_FL_UDESC) ? "start" : "stop");

                spin_lock(&sec->ps_lock);
                sec->ps_flvr.sf_flags &= ~PTLRPC_SEC_FL_UDESC;
                sec->ps_flvr.sf_flags |= sf->sf_flags & PTLRPC_SEC_FL_UDESC;
                spin_unlock(&sec->ps_lock);
        }
}

/*
 * for normal import, @svc_ctx should be NULL and @rpc_flavor is ignored;
 * for reverse import, @svc_ctx and @rpc_flavor is from incoming request.
 */
int sptlrpc_import_sec_adapt(struct obd_import *imp,
                             struct ptlrpc_svc_ctx *svc_ctx,
                             __u16 rpc_flavor)
{
        struct ptlrpc_connection   *conn;
        struct sptlrpc_flavor       sf;
        struct ptlrpc_sec          *sec, *newsec;
        enum lustre_sec_part        sp;
        int                         rc;

        if (imp == NULL)
                return 0;

        conn = imp->imp_connection;

        if (svc_ctx == NULL) {
                /* normal import, determine flavor from rule set */
                sptlrpc_rule_set_choose(&imp->imp_obd->u.cli.cl_sptlrpc_rset,
                                        LUSTRE_SP_ANY, conn->c_self, &sf);

                sp = imp->imp_obd->u.cli.cl_sec_part;
        } else {
                /* reverse import, determine flavor from incoming reqeust */
                sf.sf_rpc = rpc_flavor;
                sf.sf_bulk_ciph = BULK_CIPH_ALG_NULL;
                sf.sf_bulk_hash = BULK_HASH_ALG_NULL;
                sf.sf_flags = PTLRPC_SEC_FL_REVERSE | PTLRPC_SEC_FL_ROOTONLY;

                sp = sptlrpc_target_sec_part(imp->imp_obd);
        }

        sec = sptlrpc_import_sec_ref(imp);
        if (sec) {
                if (svc_ctx == NULL) {
                        /* normal import, only check rpc flavor, if just bulk
                         * flavor or flags changed, we can handle it on the fly
                         * without switching sec. */
                        if (sf.sf_rpc == sec->ps_flvr.sf_rpc) {
                                sptlrpc_import_sec_adapt_inplace(imp, sec, &sf);

                                rc = 0;
                                goto out;
                        }
                } else {
                        /* reverse import, do not compare bulk flavor */
                        if (sf.sf_rpc == sec->ps_flvr.sf_rpc) {
                                rc = 0;
                                goto out;
                        }
                }

                CWARN("%simport %p (%s%s%s): changing flavor "
                      "(%s, %s/%s) -> (%s, %s/%s)\n",
                      svc_ctx ? "reverse " : "",
                      imp, imp->imp_obd->obd_name,
                      svc_ctx == NULL ? "->" : "<-",
                      obd_uuid2str(&conn->c_remote_uuid),
                      sptlrpc_rpcflavor2name(sec->ps_flvr.sf_rpc),
                      sptlrpc_get_hash_name(sec->ps_flvr.sf_bulk_hash),
                      sptlrpc_get_ciph_name(sec->ps_flvr.sf_bulk_ciph),
                      sptlrpc_rpcflavor2name(sf.sf_rpc),
                      sptlrpc_get_hash_name(sf.sf_bulk_hash),
                      sptlrpc_get_ciph_name(sf.sf_bulk_ciph));
        } else {
                CWARN("%simport %p (%s%s%s) netid %x: "
                      "select initial flavor (%s, %s/%s)\n",
                      svc_ctx == NULL ? "" : "reverse ",
                      imp, imp->imp_obd->obd_name,
                      svc_ctx == NULL ? "->" : "<-",
                      obd_uuid2str(&conn->c_remote_uuid),
                      LNET_NIDNET(conn->c_self),
                      sptlrpc_rpcflavor2name(sf.sf_rpc),
                      sptlrpc_get_hash_name(sf.sf_bulk_hash),
                      sptlrpc_get_ciph_name(sf.sf_bulk_ciph));
        }

        mutex_down(&imp->imp_sec_mutex);

        newsec = sptlrpc_sec_create(imp, svc_ctx, &sf, sp);
        if (newsec) {
                sptlrpc_import_sec_install(imp, newsec);
                rc = 0;
        } else {
                CERROR("%simport %p (%s): failed to create new sec\n",
                       svc_ctx == NULL ? "" : "reverse ",
                       imp, obd_uuid2str(&conn->c_remote_uuid));
                rc = -EPERM;
        }

        mutex_up(&imp->imp_sec_mutex);

out:
        sptlrpc_sec_put(sec);
        return 0;
}

void sptlrpc_import_sec_put(struct obd_import *imp)
{
        if (imp->imp_sec) {
                sptlrpc_sec_kill(imp->imp_sec);

                sptlrpc_sec_put(imp->imp_sec);
                imp->imp_sec = NULL;
        }
}

static void import_flush_ctx_common(struct obd_import *imp,
                                    uid_t uid, int grace, int force)
{
        struct ptlrpc_sec *sec;

        if (imp == NULL)
                return;

        sec = sptlrpc_import_sec_ref(imp);
        if (sec == NULL)
                return;

        sec_cop_flush_ctx_cache(sec, uid, grace, force);
        sptlrpc_sec_put(sec);
}

void sptlrpc_import_inval_all_ctx(struct obd_import *imp)
{
        /* use grace == 0 */
        import_flush_ctx_common(imp, -1, 0, 1);
}

void sptlrpc_import_flush_root_ctx(struct obd_import *imp)
{
        /* it's important to use grace mode, see explain in
         * sptlrpc_req_refresh_ctx() */
        import_flush_ctx_common(imp, 0, 1, 1);
}

void sptlrpc_import_flush_my_ctx(struct obd_import *imp)
{
        import_flush_ctx_common(imp, cfs_current()->uid, 1, 1);
}
EXPORT_SYMBOL(sptlrpc_import_flush_my_ctx);

void sptlrpc_import_flush_all_ctx(struct obd_import *imp)
{
        import_flush_ctx_common(imp, -1, 1, 1);
}
EXPORT_SYMBOL(sptlrpc_import_flush_all_ctx);

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

        if (req->rq_reqbuf == NULL && req->rq_clrbuf == NULL)
                return;

        policy = ctx->cc_sec->ps_policy;
        policy->sp_cops->free_reqbuf(ctx->cc_sec, req);
}

/*
 * NOTE caller must guarantee the buffer size is enough for the enlargement
 */
void _sptlrpc_enlarge_msg_inplace(struct lustre_msg *msg,
                                  int segment, int newsize)
{
        void   *src, *dst;
        int     oldsize, oldmsg_size, movesize;

        LASSERT(segment < msg->lm_bufcount);
        LASSERT(msg->lm_buflens[segment] <= newsize);

        if (msg->lm_buflens[segment] == newsize)
                return;

        /* nothing to do if we are enlarging the last segment */
        if (segment == msg->lm_bufcount - 1) {
                msg->lm_buflens[segment] = newsize;
                return;
        }

        oldsize = msg->lm_buflens[segment];

        src = lustre_msg_buf(msg, segment + 1, 0);
        msg->lm_buflens[segment] = newsize;
        dst = lustre_msg_buf(msg, segment + 1, 0);
        msg->lm_buflens[segment] = oldsize;

        /* move from segment + 1 to end segment */
        LASSERT(msg->lm_magic == LUSTRE_MSG_MAGIC_V2);
        oldmsg_size = lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);
        movesize = oldmsg_size - ((unsigned long) src - (unsigned long) msg);
        LASSERT(movesize >= 0);

        if (movesize)
                memmove(dst, src, movesize);

        /* note we don't clear the ares where old data live, not secret */

        /* finally set new segment size */
        msg->lm_buflens[segment] = newsize;
}
EXPORT_SYMBOL(_sptlrpc_enlarge_msg_inplace);

/*
 * enlarge @segment of upper message req->rq_reqmsg to @newsize, all data
 * will be preserved after enlargement. this must be called after rq_reqmsg has
 * been intialized at least.
 *
 * caller's attention: upon return, rq_reqmsg and rq_reqlen might have
 * been changed.
 */
int sptlrpc_cli_enlarge_reqbuf(struct ptlrpc_request *req,
                               int segment, int newsize)
{
        struct ptlrpc_cli_ctx    *ctx = req->rq_cli_ctx;
        struct ptlrpc_sec_cops   *cops;
        struct lustre_msg        *msg = req->rq_reqmsg;

        LASSERT(ctx);
        LASSERT(msg);
        LASSERT(msg->lm_bufcount > segment);
        LASSERT(msg->lm_buflens[segment] <= newsize);

        if (msg->lm_buflens[segment] == newsize)
                return 0;

        cops = ctx->cc_sec->ps_policy->sp_cops;
        LASSERT(cops->enlarge_reqbuf);
        return cops->enlarge_reqbuf(ctx->cc_sec, req, segment, newsize);
}
EXPORT_SYMBOL(sptlrpc_cli_enlarge_reqbuf);

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

        if (req->rq_repbuf == NULL)
                return;
        LASSERT(req->rq_repbuf_len);

        policy = ctx->cc_sec->ps_policy;
        policy->sp_cops->free_repbuf(ctx->cc_sec, req);
        EXIT;
}

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

static int flavor_allowed(struct sptlrpc_flavor *exp,
                          struct ptlrpc_request *req)
{
        struct sptlrpc_flavor *flvr = &req->rq_flvr;

        if (exp->sf_rpc == flvr->sf_rpc)
                return 1;

        if ((req->rq_ctx_init || req->rq_ctx_fini) &&
            RPC_FLVR_POLICY(exp->sf_rpc) == RPC_FLVR_POLICY(flvr->sf_rpc) &&
            RPC_FLVR_MECH(exp->sf_rpc) == RPC_FLVR_MECH(flvr->sf_rpc))
                return 1;

        return 0;
}

#define EXP_FLVR_UPDATE_EXPIRE      (OBD_TIMEOUT_DEFAULT + 10)

int sptlrpc_target_export_check(struct obd_export *exp,
                                struct ptlrpc_request *req)
{
        struct sptlrpc_flavor   flavor;

        if (exp == NULL)
                return 0;

        /* client side export has no imp_reverse, skip
         * FIXME maybe we should check flavor this as well??? */
        if (exp->exp_imp_reverse == NULL)
                return 0;

        /* don't care about ctx fini rpc */
        if (req->rq_ctx_fini)
                return 0;

        spin_lock(&exp->exp_lock);

        /* if flavor just changed (exp->exp_flvr_changed != 0), we wait for
         * the first req with the new flavor, then treat it as current flavor,
         * adapt reverse sec according to it.
         * note the first rpc with new flavor might not be with root ctx, in
         * which case delay the sec_adapt by leaving exp_flvr_adapt == 1. */
        if (unlikely(exp->exp_flvr_changed) &&
            flavor_allowed(&exp->exp_flvr_old[1], req)) {
                /* make the new flavor as "current", and old ones as
                 * about-to-expire */
                CDEBUG(D_SEC, "exp %p: just changed: %x->%x\n", exp,
                       exp->exp_flvr.sf_rpc, exp->exp_flvr_old[1].sf_rpc);
                flavor = exp->exp_flvr_old[1];
                exp->exp_flvr_old[1] = exp->exp_flvr_old[0];
                exp->exp_flvr_expire[1] = exp->exp_flvr_expire[0];
                exp->exp_flvr_old[0] = exp->exp_flvr;
                exp->exp_flvr_expire[0] = cfs_time_current_sec() +
                                          EXP_FLVR_UPDATE_EXPIRE;
                exp->exp_flvr = flavor;

                /* flavor change finished */
                exp->exp_flvr_changed = 0;
                LASSERT(exp->exp_flvr_adapt == 1);

                /* if it's gss, we only interested in root ctx init */
                if (req->rq_auth_gss &&
                    !(req->rq_ctx_init && (req->rq_auth_usr_root ||
                                           req->rq_auth_usr_mdt))) {
                        spin_unlock(&exp->exp_lock);
                        CDEBUG(D_SEC, "is good but not root(%d:%d:%d:%d)\n",
                               req->rq_auth_gss, req->rq_ctx_init,
                               req->rq_auth_usr_root, req->rq_auth_usr_mdt);
                        return 0;
                }

                exp->exp_flvr_adapt = 0;
                spin_unlock(&exp->exp_lock);

                return sptlrpc_import_sec_adapt(exp->exp_imp_reverse,
                                                req->rq_svc_ctx, flavor.sf_rpc);
        }

        /* if it equals to the current flavor, we accept it, but need to
         * dealing with reverse sec/ctx */
        if (likely(flavor_allowed(&exp->exp_flvr, req))) {
                /* most cases should return here, we only interested in
                 * gss root ctx init */
                if (!req->rq_auth_gss || !req->rq_ctx_init ||
                    (!req->rq_auth_usr_root && !req->rq_auth_usr_mdt)) {
                        spin_unlock(&exp->exp_lock);
                        return 0;
                }

                /* if flavor just changed, we should not proceed, just leave
                 * it and current flavor will be discovered and replaced
                 * shortly, and let _this_ rpc pass through */
                if (exp->exp_flvr_changed) {
                        LASSERT(exp->exp_flvr_adapt);
                        spin_unlock(&exp->exp_lock);
                        return 0;
                }

                if (exp->exp_flvr_adapt) {
                        exp->exp_flvr_adapt = 0;
                        CDEBUG(D_SEC, "exp %p (%x|%x|%x): do delayed adapt\n",
                               exp, exp->exp_flvr.sf_rpc,
                               exp->exp_flvr_old[0].sf_rpc,
                               exp->exp_flvr_old[1].sf_rpc);
                        flavor = exp->exp_flvr;
                        spin_unlock(&exp->exp_lock);

                        return sptlrpc_import_sec_adapt(exp->exp_imp_reverse,
                                                        req->rq_svc_ctx,
                                                        flavor.sf_rpc);
                } else {
                        CDEBUG(D_SEC, "exp %p (%x|%x|%x): is current flavor, "
                               "install rvs ctx\n", exp, exp->exp_flvr.sf_rpc,
                               exp->exp_flvr_old[0].sf_rpc,
                               exp->exp_flvr_old[1].sf_rpc);
                        spin_unlock(&exp->exp_lock);

                        return sptlrpc_svc_install_rvs_ctx(exp->exp_imp_reverse,
                                                           req->rq_svc_ctx);
                }
        }

        if (exp->exp_flvr_expire[0]) {
                if (exp->exp_flvr_expire[0] >= cfs_time_current_sec()) {
                        if (flavor_allowed(&exp->exp_flvr_old[0], req)) {
                                CDEBUG(D_SEC, "exp %p (%x|%x|%x): match the "
                                       "middle one ("CFS_DURATION_T")\n", exp,
                                       exp->exp_flvr.sf_rpc,
                                       exp->exp_flvr_old[0].sf_rpc,
                                       exp->exp_flvr_old[1].sf_rpc,
                                       exp->exp_flvr_expire[0] -
                                                cfs_time_current_sec());
                                spin_unlock(&exp->exp_lock);
                                return 0;
                        }
                } else {
                        CDEBUG(D_SEC, "mark middle expired\n");
                        exp->exp_flvr_expire[0] = 0;
                }
                CDEBUG(D_SEC, "exp %p (%x|%x|%x): %x not match middle\n", exp,
                       exp->exp_flvr.sf_rpc,
                       exp->exp_flvr_old[0].sf_rpc, exp->exp_flvr_old[1].sf_rpc,
                       req->rq_flvr.sf_rpc);
        }

        /* now it doesn't match the current flavor, the only chance we can
         * accept it is match the old flavors which is not expired. */
        if (exp->exp_flvr_changed == 0 && exp->exp_flvr_expire[1]) {
                if (exp->exp_flvr_expire[1] >= cfs_time_current_sec()) {
                        if (flavor_allowed(&exp->exp_flvr_old[1], req)) {
                                CDEBUG(D_SEC, "exp %p (%x|%x|%x): match the "
                                       "oldest one ("CFS_DURATION_T")\n", exp,
                                       exp->exp_flvr.sf_rpc,
                                       exp->exp_flvr_old[0].sf_rpc,
                                       exp->exp_flvr_old[1].sf_rpc,
                                       exp->exp_flvr_expire[1] -
                                                cfs_time_current_sec());
                                spin_unlock(&exp->exp_lock);
                                return 0;
                        }
                } else {
                        CDEBUG(D_SEC, "mark oldest expired\n");
                        exp->exp_flvr_expire[1] = 0;
                }
                CDEBUG(D_SEC, "exp %p (%x|%x|%x): %x not match found\n",
                       exp, exp->exp_flvr.sf_rpc,
                       exp->exp_flvr_old[0].sf_rpc, exp->exp_flvr_old[1].sf_rpc,
                       req->rq_flvr.sf_rpc);
        } else {
                CDEBUG(D_SEC, "exp %p (%x|%x|%x): skip the last one\n",
                       exp, exp->exp_flvr.sf_rpc, exp->exp_flvr_old[0].sf_rpc,
                       exp->exp_flvr_old[1].sf_rpc);
        }

        spin_unlock(&exp->exp_lock);

        CWARN("req %p: (%u|%u|%u|%u|%u) with unauthorized flavor %x\n",
              req, req->rq_auth_gss, req->rq_ctx_init, req->rq_ctx_fini,
              req->rq_auth_usr_root, req->rq_auth_usr_mdt, req->rq_flvr.sf_rpc);
        return -EACCES;
}

void sptlrpc_target_update_exp_flavor(struct obd_device *obd,
                                      struct sptlrpc_rule_set *rset)
{
        struct obd_export       *exp;
        struct sptlrpc_flavor    new_flvr;

        LASSERT(obd);

        spin_lock(&obd->obd_dev_lock);

        list_for_each_entry(exp, &obd->obd_exports, exp_obd_chain) {
                if (exp->exp_connection == NULL)
                        continue;

                /* note if this export had just been updated flavor
                 * (exp_flvr_changed == 1), this will override the
                 * previous one. */
                spin_lock(&exp->exp_lock);
                sptlrpc_rule_set_choose(rset, exp->exp_sp_peer,
                                        exp->exp_connection->c_peer.nid,
                                        &new_flvr);
                if (exp->exp_flvr_changed ||
                    memcmp(&new_flvr, &exp->exp_flvr, sizeof(new_flvr))) {
                        exp->exp_flvr_old[1] = new_flvr;
                        exp->exp_flvr_expire[1] = 0;
                        exp->exp_flvr_changed = 1;
                        exp->exp_flvr_adapt = 1;
                        CDEBUG(D_SEC, "exp %p (%s): updated flavor %x->%x\n",
                               exp, sptlrpc_part2name(exp->exp_sp_peer),
                               exp->exp_flvr.sf_rpc,
                               exp->exp_flvr_old[1].sf_rpc);
                }
                spin_unlock(&exp->exp_lock);
        }

        spin_unlock(&obd->obd_dev_lock);
}
EXPORT_SYMBOL(sptlrpc_target_update_exp_flavor);

static int sptlrpc_svc_check_from(struct ptlrpc_request *req, int svc_rc)
{
        if (svc_rc == SECSVC_DROP)
                return SECSVC_DROP;

        switch (req->rq_sp_from) {
        case LUSTRE_SP_CLI:
        case LUSTRE_SP_MDT:
        case LUSTRE_SP_OST:
        case LUSTRE_SP_MGS:
        case LUSTRE_SP_ANY:
                break;
        default:
                DEBUG_REQ(D_ERROR, req, "invalid source %u", req->rq_sp_from);
                return SECSVC_DROP;
        }

        if (!req->rq_auth_gss)
                return svc_rc;

        if (unlikely(req->rq_sp_from == LUSTRE_SP_ANY)) {
                CERROR("not specific part\n");
                return SECSVC_DROP;
        }

        /* from MDT, must be authenticated as MDT */
        if (unlikely(req->rq_sp_from == LUSTRE_SP_MDT &&
                     !req->rq_auth_usr_mdt)) {
                DEBUG_REQ(D_ERROR, req, "fake source MDT");
                return SECSVC_DROP;
        }

        /* from OST, must be callback to MDT and CLI, the reverse sec
         * was from mdt/root keytab, so it should be MDT or root FIXME */
        if (unlikely(req->rq_sp_from == LUSTRE_SP_OST &&
                     !req->rq_auth_usr_mdt && !req->rq_auth_usr_root)) {
                DEBUG_REQ(D_ERROR, req, "fake source OST");
                return SECSVC_DROP;
        }

        return svc_rc;
}

int sptlrpc_svc_unwrap_request(struct ptlrpc_request *req)
{
        struct ptlrpc_sec_policy *policy;
        struct lustre_msg *msg = req->rq_reqbuf;
        int rc;
        ENTRY;

        LASSERT(msg);
        LASSERT(req->rq_reqmsg == NULL);
        LASSERT(req->rq_repmsg == NULL);

        req->rq_sp_from = LUSTRE_SP_ANY;
        req->rq_auth_uid = INVALID_UID;
        req->rq_auth_mapped_uid = INVALID_UID;

        if (req->rq_reqdata_len < sizeof(struct lustre_msg)) {
                CERROR("request size %d too small\n", req->rq_reqdata_len);
                RETURN(SECSVC_DROP);
        }

        /*
         * v2 message.
         */
        if (msg->lm_magic == LUSTRE_MSG_MAGIC_V2)
                req->rq_flvr.sf_rpc = WIRE_FLVR_RPC(msg->lm_secflvr);
        else
                req->rq_flvr.sf_rpc = WIRE_FLVR_RPC(__swab32(msg->lm_secflvr));

        /* unpack the wrapper message if the policy is not null */
        if ((RPC_FLVR_POLICY(req->rq_flvr.sf_rpc) != SPTLRPC_POLICY_NULL) &&
             lustre_unpack_msg(msg, req->rq_reqdata_len))
                RETURN(SECSVC_DROP);

        policy = sptlrpc_rpcflavor2policy(req->rq_flvr.sf_rpc);
        if (!policy) {
                CERROR("unsupported rpc flavor %x\n", req->rq_flvr.sf_rpc);
                RETURN(SECSVC_DROP);
        }

        LASSERT(policy->sp_sops->accept);
        rc = policy->sp_sops->accept(req);

        LASSERT(req->rq_reqmsg || rc != SECSVC_OK);
        sptlrpc_policy_put(policy);

        /* sanity check for the request source */
        rc = sptlrpc_svc_check_from(req, rc);

        /* FIXME move to proper place */
        if (rc == SECSVC_OK) {
                __u32 opc = lustre_msg_get_opc(req->rq_reqmsg);

                if (opc == OST_WRITE)
                        req->rq_bulk_write = 1;
                else if (opc == OST_READ)
                        req->rq_bulk_read = 1;
        }

        LASSERT(req->rq_svc_ctx || rc == SECSVC_DROP);
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

void sptlrpc_svc_ctx_invalidate(struct ptlrpc_request *req)
{
        struct ptlrpc_svc_ctx *ctx = req->rq_svc_ctx;

        if (ctx == NULL)
                return;

        LASSERT(atomic_read(&ctx->sc_refcount) > 0);
        if (ctx->sc_policy->sp_sops->invalidate_ctx)
                ctx->sc_policy->sp_sops->invalidate_ctx(ctx);
}
EXPORT_SYMBOL(sptlrpc_svc_ctx_invalidate);

/****************************************
 * bulk security                        *
 ****************************************/

int sptlrpc_cli_wrap_bulk(struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_cli_ctx *ctx;

        if (!req->rq_pack_bulk)
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

        if (!req->rq_pack_bulk)
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

        if (!req->rq_pack_bulk)
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

        if (!req->rq_pack_bulk)
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

        if (!req->rq_pack_bulk)
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

int sptlrpc_current_user_desc_size(void)
{
        int ngroups;

#ifdef __KERNEL__
        ngroups = current_ngroups;

        if (ngroups > LUSTRE_MAX_GROUPS)
                ngroups = LUSTRE_MAX_GROUPS;
#else
        ngroups = 0;
#endif
        return sptlrpc_user_desc_size(ngroups);
}
EXPORT_SYMBOL(sptlrpc_current_user_desc_size);

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
 * misc helpers                         *
 ****************************************/

const char * sec2target_str(struct ptlrpc_sec *sec)
{
        if (!sec || !sec->ps_import || !sec->ps_import->imp_obd)
                return "*";
        if (sec_is_reverse(sec))
                return "c";
        return obd_uuid2str(&sec->ps_import->imp_obd->u.cli.cl_target_uuid);
}
EXPORT_SYMBOL(sec2target_str);

/****************************************
 * crypto API helper/alloc blkciper     *
 ****************************************/

#ifdef __KERNEL__
#ifndef HAVE_ASYNC_BLOCK_CIPHER
struct ll_crypto_cipher *ll_crypto_alloc_blkcipher(const char * algname,
                                                   u32 type, u32 mask)
{
        char        buf[CRYPTO_MAX_ALG_NAME + 1];
        const char *pan = algname;
        u32         flag = 0; 

        if (strncmp("cbc(", algname, 4) == 0)
                flag |= CRYPTO_TFM_MODE_CBC;
        else if (strncmp("ecb(", algname, 4) == 0)
                flag |= CRYPTO_TFM_MODE_ECB;
        if (flag) {
                char *vp = strnchr(algname, CRYPTO_MAX_ALG_NAME, ')');
                if (vp) {
                        memcpy(buf, algname + 4, vp - algname - 4);
                        buf[vp - algname - 4] = '\0';
                        pan = buf;
                } else {
                        flag = 0;
                }
        }
        return crypto_alloc_tfm(pan, flag);
}
EXPORT_SYMBOL(ll_crypto_alloc_blkcipher);
#endif
#endif

/****************************************
 * initialize/finalize                  *
 ****************************************/

int __init sptlrpc_init(void)
{
        int rc;

        rc = sptlrpc_gc_start_thread();
        if (rc)
                goto out;

        rc = sptlrpc_enc_pool_init();
        if (rc)
                goto out_gc;

        rc = sptlrpc_null_init();
        if (rc)
                goto out_pool;

        rc = sptlrpc_plain_init();
        if (rc)
                goto out_null;

        rc = sptlrpc_lproc_init();
        if (rc)
                goto out_plain;

        return 0;

out_plain:
        sptlrpc_plain_fini();
out_null:
        sptlrpc_null_fini();
out_pool:
        sptlrpc_enc_pool_fini();
out_gc:
        sptlrpc_gc_stop_thread();
out:
        return rc;
}

void __exit sptlrpc_fini(void)
{
        sptlrpc_lproc_fini();
        sptlrpc_plain_fini();
        sptlrpc_null_fini();
        sptlrpc_enc_pool_fini();
        sptlrpc_gc_stop_thread();
}
