/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004-2006 Cluster File Systems, Inc.
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

#ifndef __KERNEL__
#include <liblustre.h>
#endif

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_sec.h>

static struct ptlrpc_sec_policy null_policy;
static struct ptlrpc_sec        null_sec;
static struct ptlrpc_cli_ctx    null_cli_ctx;
static struct ptlrpc_svc_ctx    null_svc_ctx;

static
int null_ctx_refresh(struct ptlrpc_cli_ctx *ctx)
{
        /* should never reach here */
        LBUG();
        return 0;
}

static
int null_ctx_sign(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req)
{
        if (req->rq_reqbuf->lm_magic != LUSTRE_MSG_MAGIC_V1)
                req->rq_reqbuf->lm_secflvr = SPTLRPC_FLVR_NULL;
        req->rq_reqdata_len = req->rq_reqlen;
        return 0;
}

static
int null_ctx_verify(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req)
{
        req->rq_repmsg = req->rq_repbuf;
        req->rq_replen = req->rq_repdata_len;
        return 0;
}

static struct ptlrpc_ctx_ops null_ctx_ops = {
        .refresh        = null_ctx_refresh,
        .sign           = null_ctx_sign,
        .verify         = null_ctx_verify,
};

static struct ptlrpc_svc_ctx null_svc_ctx = {
        .sc_refcount    = ATOMIC_INIT(1),
        .sc_policy      = &null_policy,
};

static
struct ptlrpc_sec* null_create_sec(struct obd_import *imp,
                                   struct ptlrpc_svc_ctx *ctx,
                                   __u32 flavor,
                                   unsigned long flags)
{
        LASSERT(SEC_FLAVOR_POLICY(flavor) == SPTLRPC_POLICY_NULL);
        return &null_sec;
}

static
void null_destroy_sec(struct ptlrpc_sec *sec)
{
        LASSERT(sec == &null_sec);
}

static
struct ptlrpc_cli_ctx *null_lookup_ctx(struct ptlrpc_sec *sec,
                                       struct vfs_cred *vcred,
                                       int create, int remove_dead)
{
        atomic_inc(&null_cli_ctx.cc_refcount);
        return &null_cli_ctx;
}

static
int null_flush_ctx_cache(struct ptlrpc_sec *sec,
                         uid_t uid,
                         int grace, int force)
{
        return 0;
}

static
int null_alloc_reqbuf(struct ptlrpc_sec *sec,
                      struct ptlrpc_request *req,
                      int msgsize)
{
        if (!req->rq_reqbuf) {
                int alloc_size = size_roundup_power2(msgsize);

                LASSERT(!req->rq_pool);
                OBD_ALLOC(req->rq_reqbuf, alloc_size);
                if (!req->rq_reqbuf)
                        return -ENOMEM;

                req->rq_reqbuf_len = alloc_size;
        } else {
                LASSERT(req->rq_pool);
                LASSERT(req->rq_reqbuf_len >= msgsize);
                memset(req->rq_reqbuf, 0, msgsize);
        }

        req->rq_reqmsg = req->rq_reqbuf;
        return 0;
}

static
void null_free_reqbuf(struct ptlrpc_sec *sec,
                      struct ptlrpc_request *req)
{
        if (!req->rq_pool) {
                LASSERTF(req->rq_reqmsg == req->rq_reqbuf,
                         "reqmsg %p is not reqbuf %p in null sec\n",
                         req->rq_reqmsg, req->rq_reqbuf);
                LASSERTF(req->rq_reqbuf_len >= req->rq_reqlen,
                         "reqlen %d should smaller than buflen %d\n",
                         req->rq_reqlen, req->rq_reqbuf_len);

                OBD_FREE(req->rq_reqbuf, req->rq_reqbuf_len);
                req->rq_reqmsg = req->rq_reqbuf = NULL;
                req->rq_reqbuf_len = 0;
        }
}

static
int null_alloc_repbuf(struct ptlrpc_sec *sec,
                      struct ptlrpc_request *req,
                      int msgsize)
{
        msgsize = size_roundup_power2(msgsize);

        OBD_ALLOC(req->rq_repbuf, msgsize);
        if (!req->rq_repbuf)
                return -ENOMEM;

        req->rq_repbuf_len = msgsize;
        return 0;
}

static
void null_free_repbuf(struct ptlrpc_sec *sec,
                      struct ptlrpc_request *req)
{
        OBD_FREE(req->rq_repbuf, req->rq_repbuf_len);
        req->rq_repbuf = NULL;
        req->rq_repbuf_len = 0;
}

static
int null_enlarge_reqbuf(struct ptlrpc_sec *sec,
                        struct ptlrpc_request *req,
                        int segment, int newsize)
{
        struct lustre_msg      *newbuf;
        struct lustre_msg      *oldbuf = req->rq_reqmsg;
        int                     oldsize, newmsg_size, alloc_size;

        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_reqbuf == req->rq_reqmsg);
        LASSERT(req->rq_reqbuf_len >= req->rq_reqlen);
        LASSERT(req->rq_reqlen == lustre_packed_msg_size(oldbuf));

        /* compute new message size */
        oldsize = req->rq_reqbuf->lm_buflens[segment];
        req->rq_reqbuf->lm_buflens[segment] = newsize;
        newmsg_size = lustre_packed_msg_size(oldbuf);
        req->rq_reqbuf->lm_buflens[segment] = oldsize;

        /* request from pool should always have enough buffer */
        LASSERT(!req->rq_pool || req->rq_reqbuf_len >= newmsg_size);

        if (req->rq_reqbuf_len < newmsg_size) {
                alloc_size = size_roundup_power2(newmsg_size);

                OBD_ALLOC(newbuf, alloc_size);
                if (newbuf == NULL)
                        return -ENOMEM;

                memcpy(newbuf, req->rq_reqbuf, req->rq_reqlen);

                OBD_FREE(req->rq_reqbuf, req->rq_reqbuf_len);
                req->rq_reqbuf = req->rq_reqmsg = newbuf;
                req->rq_reqbuf_len = alloc_size;
        }

        _sptlrpc_enlarge_msg_inplace(req->rq_reqmsg, segment, newsize);
        req->rq_reqlen = newmsg_size;

        return 0;
}

static
int null_accept(struct ptlrpc_request *req)
{
        LASSERT(SEC_FLAVOR_POLICY(req->rq_sec_flavor) == SPTLRPC_POLICY_NULL);

        if (SEC_FLAVOR_RPC(req->rq_sec_flavor) != SPTLRPC_FLVR_NULL) {
                CERROR("Invalid flavor 0x%x\n", req->rq_sec_flavor);
                return SECSVC_DROP;
        }

        req->rq_reqmsg = req->rq_reqbuf;
        req->rq_reqlen = req->rq_reqdata_len;

        req->rq_svc_ctx = &null_svc_ctx;
        atomic_inc(&req->rq_svc_ctx->sc_refcount);

        return SECSVC_OK;
}

static
int null_alloc_rs(struct ptlrpc_request *req, int msgsize)
{
        struct ptlrpc_reply_state *rs;
        int rs_size = sizeof(*rs) + msgsize;

        LASSERT(msgsize % 8 == 0);

        rs = req->rq_reply_state;

        if (rs) {
                /* pre-allocated */
                LASSERT(rs->rs_size >= rs_size);
        } else {
                OBD_ALLOC(rs, rs_size);
                if (rs == NULL)
                        return -ENOMEM;

                rs->rs_size = rs_size;
        }

        rs->rs_svc_ctx = req->rq_svc_ctx;
        atomic_inc(&req->rq_svc_ctx->sc_refcount);

        rs->rs_repbuf = (struct lustre_msg *) (rs + 1);
        rs->rs_repbuf_len = rs_size - sizeof(*rs);
        rs->rs_msg = rs->rs_repbuf;

        req->rq_reply_state = rs;
        return 0;
}

static
void null_free_rs(struct ptlrpc_reply_state *rs)
{
        LASSERT(atomic_read(&rs->rs_svc_ctx->sc_refcount) > 1);
        atomic_dec(&rs->rs_svc_ctx->sc_refcount);

        if (!rs->rs_prealloc)
                OBD_FREE(rs, rs->rs_size);
}

static
int null_authorize(struct ptlrpc_request *req)
{
        struct ptlrpc_reply_state *rs = req->rq_reply_state;

        LASSERT(rs);
        if (rs->rs_repbuf->lm_magic != LUSTRE_MSG_MAGIC_V1)
                rs->rs_repbuf->lm_secflvr = SPTLRPC_FLVR_NULL;
        rs->rs_repdata_len = req->rq_replen;
        return 0;
}

static struct ptlrpc_sec_cops null_sec_cops = {
        .create_sec             = null_create_sec,
        .destroy_sec            = null_destroy_sec,
        .lookup_ctx             = null_lookup_ctx,
        .flush_ctx_cache        = null_flush_ctx_cache,
        .alloc_reqbuf           = null_alloc_reqbuf,
        .alloc_repbuf           = null_alloc_repbuf,
        .free_reqbuf            = null_free_reqbuf,
        .free_repbuf            = null_free_repbuf,
        .enlarge_reqbuf         = null_enlarge_reqbuf,
};

static struct ptlrpc_sec_sops null_sec_sops = {
        .accept                 = null_accept,
        .alloc_rs               = null_alloc_rs,
        .authorize              = null_authorize,
        .free_rs                = null_free_rs,
};

static struct ptlrpc_sec_policy null_policy = {
        .sp_owner               = THIS_MODULE,
        .sp_name                = "sec.null",
        .sp_policy              = SPTLRPC_POLICY_NULL,
        .sp_cops                = &null_sec_cops,
        .sp_sops                = &null_sec_sops,
};

static
void null_init_internal(void)
{
        static HLIST_HEAD(__list);

        null_sec.ps_policy = &null_policy;
        atomic_set(&null_sec.ps_refcount, 1);     /* always busy */
        null_sec.ps_import = NULL;
        null_sec.ps_flavor = SPTLRPC_FLVR_NULL;
        null_sec.ps_flags = 0;
        spin_lock_init(&null_sec.ps_lock);
        atomic_set(&null_sec.ps_busy, 1);         /* for "null_cli_ctx" */
        INIT_LIST_HEAD(&null_sec.ps_gc_list);
        null_sec.ps_gc_interval = 0;
        null_sec.ps_gc_next = 0;

        hlist_add_head(&null_cli_ctx.cc_cache, &__list);
        atomic_set(&null_cli_ctx.cc_refcount, 1);    /* for hash */
        null_cli_ctx.cc_sec = &null_sec;
        null_cli_ctx.cc_ops = &null_ctx_ops;
        null_cli_ctx.cc_expire = 0;
        null_cli_ctx.cc_flags = PTLRPC_CTX_CACHED | PTLRPC_CTX_ETERNAL |
                                PTLRPC_CTX_UPTODATE;
        null_cli_ctx.cc_vcred.vc_uid = 0;
        spin_lock_init(&null_cli_ctx.cc_lock);
        INIT_LIST_HEAD(&null_cli_ctx.cc_req_list);
        INIT_LIST_HEAD(&null_cli_ctx.cc_gc_chain);
}

int sptlrpc_null_init(void)
{
        int rc;

        null_init_internal();

        rc = sptlrpc_register_policy(&null_policy);
        if (rc)
                CERROR("failed to register %s: %d\n", null_policy.sp_name, rc);

        return rc;
}

void sptlrpc_null_fini(void)
{
        int rc;

        rc = sptlrpc_unregister_policy(&null_policy);
        if (rc)
                CERROR("failed to unregister %s: %d\n", null_policy.sp_name,rc);
}
