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
        __u32 number = policy->sp_policy;

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
        __u32 number = policy->sp_policy;

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
struct ptlrpc_sec_policy * sptlrpc_flavor2policy(ptlrpc_sec_flavor_t flavor)
{
#ifdef CONFIG_KMOD
        static DECLARE_MUTEX(load_mutex);
#endif
        static atomic_t         loaded = ATOMIC_INIT(0);
        struct                  ptlrpc_sec_policy *policy;
        __u32                   number = SEC_FLAVOR_POLICY(flavor), flag = 0;

        if (number >= SPTLRPC_POLICY_MAX)
                return NULL;

#ifdef CONFIG_KMOD
again:
#endif
        read_lock(&policy_lock);
        policy = policies[number];
        if (policy && !try_module_get(policy->sp_owner))
                policy = NULL;
        if (policy == NULL)
                flag = atomic_read(&loaded);
        read_unlock(&policy_lock);

#ifdef CONFIG_KMOD
        /* if failure, try to load gss module, once */
        if (unlikely(policy == NULL) &&
            flag == 0 &&
            (number == SPTLRPC_POLICY_GSS ||
             number == SPTLRPC_POLICY_GSS_PIPEFS)) {
                mutex_down(&load_mutex);
                if (atomic_read(&loaded) == 0) {
                        if (request_module("ptlrpc_gss") != 0)
                                CERROR("Unable to load module ptlrpc_gss\n");
                        else
                                CWARN("module ptlrpc_gss loaded\n");

                        atomic_set(&loaded, 1);
                }
                mutex_up(&load_mutex);

                goto again;
        }
#endif

        return policy;
}

ptlrpc_sec_flavor_t sptlrpc_name2flavor(const char *name)
{
        if (!strcmp(name, "null"))
                return SPTLRPC_FLVR_NULL;
        if (!strcmp(name, "plain"))
                return SPTLRPC_FLVR_PLAIN;
        if (!strcmp(name, "krb5n"))
                return SPTLRPC_FLVR_KRB5N;
        if (!strcmp(name, "krb5i"))
                return SPTLRPC_FLVR_KRB5I;
        if (!strcmp(name, "krb5p"))
                return SPTLRPC_FLVR_KRB5P;

        return SPTLRPC_FLVR_INVALID;
}
EXPORT_SYMBOL(sptlrpc_name2flavor);

char *sptlrpc_flavor2name(ptlrpc_sec_flavor_t flavor)
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
                CERROR("invalid flavor 0x%x(p%u,s%u,v%u)\n", flavor,
                       SEC_FLAVOR_POLICY(flavor), SEC_FLAVOR_MECH(flavor),
                       SEC_FLAVOR_SVC(flavor));
        }
        return "UNKNOWN";
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

        if (sec->ps_flags & (PTLRPC_SEC_FL_REVERSE | PTLRPC_SEC_FL_ROOTONLY)) {
                vcred.vc_uid = 0;
                vcred.vc_gid = 0;
                if (sec->ps_flags & PTLRPC_SEC_FL_REVERSE) {
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

int sptlrpc_req_get_ctx(struct ptlrpc_request *req)
{
        struct obd_import *imp = req->rq_import;
        ENTRY;

        LASSERT(!req->rq_cli_ctx);
        LASSERT(imp);

        if (imp->imp_sec == NULL) {
                CERROR("import %p (%s) with no sec pointer\n",
                       imp, ptlrpc_import_state_name(imp->imp_state));
                RETURN(-EACCES);
        }

        req->rq_cli_ctx = get_my_ctx(imp->imp_sec);

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

        sptlrpc_cli_ctx_get(ctx);
        sptlrpc_req_put_ctx(req, 0);
        rc = sptlrpc_req_get_ctx(req);
        if (!rc) {
                LASSERT(req->rq_cli_ctx);
                sptlrpc_cli_ctx_put(ctx, 1);
        } else {
                LASSERT(!req->rq_cli_ctx);
                req->rq_cli_ctx = ctx;
        }
        RETURN(rc);
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

        /* skip special ctxs */
        if (cli_ctx_is_eternal(ctx) || req->rq_ctx_init || req->rq_ctx_fini)
                RETURN(0);

        if (test_bit(PTLRPC_CTX_NEW_BIT, &ctx->cc_flags)) {
                LASSERT(ctx->cc_ops->refresh);
                ctx->cc_ops->refresh(ctx);
        }
        LASSERT(test_bit(PTLRPC_CTX_NEW_BIT, &ctx->cc_flags) == 0);

again:
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
                /* don't have to, but we don't want to release it too soon */
                sptlrpc_cli_ctx_get(ctx);

                rc = sptlrpc_req_replace_dead_ctx(req);
                if (rc) {
                        LASSERT(ctx == req->rq_cli_ctx);
                        CERROR("req %p: failed to replace dead ctx %p\n",
                                req, ctx);
                        req->rq_err = 1;
                        LASSERT(list_empty(&req->rq_ctx_chain));
                        sptlrpc_cli_ctx_put(ctx, 1);
                        RETURN(-ENOMEM);
                }

                /* FIXME
                 * if ctx didn't really switch, might be cpu tight or sth,
                 * we just relax a little bit.
                 */
                if (ctx == req->rq_cli_ctx)
                        schedule();

                CWARN("req %p: replace dead ctx %p(%u->%s) => %p\n",
                      req, ctx, ctx->cc_vcred.vc_uid,
                      sec2target_str(ctx->cc_sec), req->rq_cli_ctx);

                sptlrpc_cli_ctx_put(ctx, 1);
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

        /* five cases we are here:
         * 1. successfully refreshed;
         * 2. someone else mark this ctx dead by force;
         * 3. interruptted;
         * 4. timedout, and we don't want recover from the failure;
         * 5. timedout, and waked up upon recovery finished;
         */
        if (!cli_ctx_is_refreshed(ctx)) {
                /* timed out or interruptted */
                req_off_ctx_list(req, ctx);

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
        }

        req->rq_sec_flavor = req->rq_cli_ctx->cc_sec->ps_flavor;

        /* force SVC_NULL for context initiation rpc, SVC_INTG for context
         * destruction rpc
         */
        if (unlikely(req->rq_ctx_init)) {
                req->rq_sec_flavor = SEC_MAKE_RPC_FLAVOR(
                                SEC_FLAVOR_POLICY(req->rq_sec_flavor),
                                SEC_FLAVOR_MECH(req->rq_sec_flavor),
                                SPTLRPC_SVC_NULL);
        } else if (unlikely(req->rq_ctx_fini)) {
                req->rq_sec_flavor = SEC_MAKE_RPC_FLAVOR(
                                SEC_FLAVOR_POLICY(req->rq_sec_flavor),
                                SEC_FLAVOR_MECH(req->rq_sec_flavor),
                                SPTLRPC_SVC_INTG);
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

        switch (SEC_FLAVOR_SVC(req->rq_sec_flavor)) {
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
                ptlrpc_sec_flavor_t tmpf = req->rq_repbuf->lm_secflvr;

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

/**************************************************
 * client side high-level security APIs           *
 **************************************************/

static
void sec_cop_destroy_sec(struct ptlrpc_sec *sec)
{
        struct ptlrpc_sec_policy *policy = sec->ps_policy;

        LASSERT(atomic_read(&sec->ps_refcount) == 0);
        LASSERT(atomic_read(&sec->ps_busy) == 0);
        LASSERT(policy->sp_cops->destroy_sec);

        CDEBUG(D_SEC, "%s@%p: being destroied\n", sec->ps_policy->sp_name, sec);

        policy->sp_cops->destroy_sec(sec);
        sptlrpc_policy_put(policy);
}

static
int sec_cop_flush_ctx_cache(struct ptlrpc_sec *sec, uid_t uid,
                            int grace, int force)
{
        struct ptlrpc_sec_policy *policy = sec->ps_policy;

        LASSERT(policy->sp_cops);
        LASSERT(policy->sp_cops->flush_ctx_cache);

        return policy->sp_cops->flush_ctx_cache(sec, uid, grace, force);
}

void sptlrpc_sec_destroy(struct ptlrpc_sec *sec)
{
        sec_cop_destroy_sec(sec);
}
EXPORT_SYMBOL(sptlrpc_sec_destroy);

/*
 * let policy module to determine whether take refrence of
 * import or not.
 */
static
struct ptlrpc_sec * import_create_sec(struct obd_import *imp,
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

                if (sec->ps_gc_interval && policy->sp_cops->gc_ctx)
                        sptlrpc_gc_add_sec(sec);
        } else
                sptlrpc_policy_put(policy);

        RETURN(sec);
}

int sptlrpc_import_get_sec(struct obd_import *imp,
                           struct ptlrpc_svc_ctx *ctx,
                           __u32 flavor,
                           unsigned long flags)
{
        might_sleep();

        /* old sec might be still there in reconnecting */
        if (imp->imp_sec)
                return 0;

        imp->imp_sec = import_create_sec(imp, ctx, flavor, flags);
        if (!imp->imp_sec)
                return -EINVAL;

        return 0;
}

void sptlrpc_import_put_sec(struct obd_import *imp)
{
        struct ptlrpc_sec        *sec;
        struct ptlrpc_sec_policy *policy;

        might_sleep();

        if (imp->imp_sec == NULL)
                return;

        sec = imp->imp_sec;
        policy = sec->ps_policy;

        if (atomic_dec_and_test(&sec->ps_refcount)) {
                sec_cop_flush_ctx_cache(sec, -1, 1, 1);
                sptlrpc_gc_del_sec(sec);

                if (atomic_dec_and_test(&sec->ps_busy))
                        sec_cop_destroy_sec(sec);
                else {
                        CWARN("delay destroying busy sec %s %p\n",
                              policy->sp_name, sec);
                }
        } else {
                sptlrpc_policy_put(policy);
        }

        imp->imp_sec = NULL;
}

void sptlrpc_import_flush_root_ctx(struct obd_import *imp)
{
        if (imp == NULL || imp->imp_sec == NULL)
                return;

        /* it's important to use grace mode, see explain in
         * sptlrpc_req_refresh_ctx()
         */
        sec_cop_flush_ctx_cache(imp->imp_sec, 0, 1, 1);
}

void sptlrpc_import_flush_my_ctx(struct obd_import *imp)
{
        if (imp == NULL || imp->imp_sec == NULL)
                return;

        sec_cop_flush_ctx_cache(imp->imp_sec, cfs_current()->uid, 1, 1);
}
EXPORT_SYMBOL(sptlrpc_import_flush_my_ctx);

void sptlrpc_import_flush_all_ctx(struct obd_import *imp)
{
        if (imp == NULL || imp->imp_sec == NULL)
                return;

        sec_cop_flush_ctx_cache(imp->imp_sec, -1, 1, 1);
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
        LASSERT(req->rq_reqbuf || req->rq_clrbuf);

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
        LASSERT(req->rq_repbuf);

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

int sptlrpc_target_export_check(struct obd_export *exp,
                                struct ptlrpc_request *req)
{
        if (!req->rq_auth_gss ||
            (!req->rq_auth_usr_root && !req->rq_auth_usr_mdt))
                return 0;

        if (!req->rq_ctx_init)
                return 0;

        LASSERT(exp->exp_imp_reverse);
        sptlrpc_svc_install_rvs_ctx(exp->exp_imp_reverse, req->rq_svc_ctx);
        return 0;
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
        case SPTLRPC_FLVR_KRB5N:
        case SPTLRPC_FLVR_KRB5A:
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
        case SPTLRPC_FLVR_KRB5N:
        case SPTLRPC_FLVR_KRB5A:
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
        SPTLRPC_FLVR_KRB5N,
        SPTLRPC_FLVR_KRB5A,
        SPTLRPC_FLVR_KRB5I,
        SPTLRPC_FLVR_KRB5P,
};

#define __nflavors      (sizeof(__flavors)/sizeof(__u32))

/*
 * flavor string format: rpc[-bulk{n|i|p}[:cksum/enc]]
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
                if (strcmp(alg, sptlrpc_bulk_csum_alg2name(i)) == 0) {
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
        /* * set ROOTONLY flag:
         *   - to OST
         *   - from MDT to MDT
         * * set BULK flag for:
         *   - from CLI to OST
         */
        if (to_part == LUSTRE_OST ||
            (from_part == LUSTRE_MDT && to_part == LUSTRE_MDT))
                conf->sfc_flags |= PTLRPC_SEC_FL_ROOTONLY;
        if (from_part == LUSTRE_CLI && to_part == LUSTRE_OST)
                conf->sfc_flags |= PTLRPC_SEC_FL_BULK;

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
        if (sec_is_reverse(sec))
                return "c";
        return obd_uuid2str(&sec->ps_import->imp_obd->u.cli.cl_target_uuid);
}
EXPORT_SYMBOL(sec2target_str);

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
