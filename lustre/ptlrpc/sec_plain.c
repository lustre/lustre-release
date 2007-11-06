/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2006 Cluster File Systems, Inc.
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

static struct ptlrpc_sec_policy plain_policy;
static struct ptlrpc_ctx_ops    plain_ctx_ops;
static struct ptlrpc_sec        plain_sec;
static struct ptlrpc_cli_ctx    plain_cli_ctx;
static struct ptlrpc_svc_ctx    plain_svc_ctx;

/****************************************
 * cli_ctx apis                         *
 ****************************************/

static
int plain_ctx_refresh(struct ptlrpc_cli_ctx *ctx)
{
        /* should never reach here */
        LBUG();
        return 0;
}

static
int plain_ctx_sign(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req)
{
        struct lustre_msg_v2 *msg = req->rq_reqbuf;
        ENTRY;

        msg->lm_secflvr = req->rq_sec_flavor;
        req->rq_reqdata_len = lustre_msg_size_v2(msg->lm_bufcount,
                                                 msg->lm_buflens);
        RETURN(0);
}

static
int plain_ctx_verify(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req)
{
        struct lustre_msg *msg = req->rq_repbuf;
        ENTRY;

        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                if (msg->lm_bufcount != 2) {
                        CERROR("Protocol error: invalid buf count %d\n",
                               msg->lm_bufcount);
                        RETURN(-EPROTO);
                }

                if (bulk_sec_desc_unpack(msg, 1)) {
                        CERROR("Mal-formed bulk checksum reply\n");
                        RETURN(-EINVAL);
                }
        }

        req->rq_repmsg = lustre_msg_buf(msg, 0, 0);
        req->rq_replen = msg->lm_buflens[0];
        RETURN(0);
}

static
int plain_cli_wrap_bulk(struct ptlrpc_cli_ctx *ctx,
                        struct ptlrpc_request *req,
                        struct ptlrpc_bulk_desc *desc)
{
        struct sec_flavor_config *conf;

        LASSERT(req->rq_import);
        LASSERT(SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor));
        LASSERT(req->rq_reqbuf->lm_bufcount >= 2);

        conf = &req->rq_import->imp_obd->u.cli.cl_sec_conf;
        return bulk_csum_cli_request(desc, req->rq_bulk_read,
                                     conf->sfc_bulk_csum,
                                     req->rq_reqbuf,
                                     req->rq_reqbuf->lm_bufcount - 1);
}

static
int plain_cli_unwrap_bulk(struct ptlrpc_cli_ctx *ctx,
                          struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc)
{
        LASSERT(SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor));
        LASSERT(req->rq_reqbuf->lm_bufcount >= 2);
        LASSERT(req->rq_repbuf->lm_bufcount >= 2);

        return bulk_csum_cli_reply(desc, req->rq_bulk_read,
                                   req->rq_reqbuf,
                                   req->rq_reqbuf->lm_bufcount - 1,
                                   req->rq_repbuf,
                                   req->rq_repbuf->lm_bufcount - 1);
}

/****************************************
 * sec apis                             *
 ****************************************/

static
struct ptlrpc_sec* plain_create_sec(struct obd_import *imp,
                                    struct ptlrpc_svc_ctx *ctx,
                                    __u32 flavor,
                                    unsigned long flags)
{
        ENTRY;
        LASSERT(SEC_FLAVOR_POLICY(flavor) == SPTLRPC_POLICY_PLAIN);
        RETURN(&plain_sec);
}

static
void plain_destroy_sec(struct ptlrpc_sec *sec)
{
        ENTRY;
        LASSERT(sec == &plain_sec);
        EXIT;
}

static
struct ptlrpc_cli_ctx *plain_lookup_ctx(struct ptlrpc_sec *sec,
                                        struct vfs_cred *vcred,
                                        int create, int remove_dead)
{
        ENTRY;
        atomic_inc(&plain_cli_ctx.cc_refcount);
        RETURN(&plain_cli_ctx);
}

static
int plain_flush_ctx_cache(struct ptlrpc_sec *sec,
                          uid_t uid,
                          int grace, int force)
{
        return 0;
}

static
int plain_alloc_reqbuf(struct ptlrpc_sec *sec,
                       struct ptlrpc_request *req,
                       int msgsize)
{
        struct sec_flavor_config *conf;
        int bufcnt = 1, buflens[2], alloc_len;
        ENTRY;

        buflens[0] = msgsize;

        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor))
                buflens[bufcnt++] = sptlrpc_current_user_desc_size();

        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                LASSERT(req->rq_bulk_read || req->rq_bulk_write);

                conf = &req->rq_import->imp_obd->u.cli.cl_sec_conf;
                buflens[bufcnt++] = bulk_sec_desc_size(conf->sfc_bulk_csum, 1,
                                                       req->rq_bulk_read);
        }

        alloc_len = lustre_msg_size_v2(bufcnt, buflens);

        if (!req->rq_reqbuf) {
                LASSERT(!req->rq_pool);

                alloc_len = size_roundup_power2(alloc_len);
                OBD_ALLOC(req->rq_reqbuf, alloc_len);
                if (!req->rq_reqbuf)
                        RETURN(-ENOMEM);

                req->rq_reqbuf_len = alloc_len;
        } else {
                LASSERT(req->rq_pool);
                LASSERT(req->rq_reqbuf_len >= alloc_len);
                memset(req->rq_reqbuf, 0, alloc_len);
        }

        lustre_init_msg_v2(req->rq_reqbuf, bufcnt, buflens, NULL);
        req->rq_reqmsg = lustre_msg_buf_v2(req->rq_reqbuf, 0, 0);

        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor))
                sptlrpc_pack_user_desc(req->rq_reqbuf, 1);

        RETURN(0);
}

static
void plain_free_reqbuf(struct ptlrpc_sec *sec,
                       struct ptlrpc_request *req)
{
        ENTRY;
        if (!req->rq_pool) {
                OBD_FREE(req->rq_reqbuf, req->rq_reqbuf_len);
                req->rq_reqbuf = NULL;
                req->rq_reqbuf_len = 0;
        }
        EXIT;
}

static
int plain_alloc_repbuf(struct ptlrpc_sec *sec,
                       struct ptlrpc_request *req,
                       int msgsize)
{
        struct sec_flavor_config *conf;
        int bufcnt = 1, buflens[2], alloc_len;
        ENTRY;

        buflens[0] = msgsize;

        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                LASSERT(req->rq_bulk_read || req->rq_bulk_write);

                conf = &req->rq_import->imp_obd->u.cli.cl_sec_conf;
                buflens[bufcnt++] = bulk_sec_desc_size(conf->sfc_bulk_csum, 0,
                                                       req->rq_bulk_read);
        }

        alloc_len = lustre_msg_size_v2(bufcnt, buflens);
        alloc_len = size_roundup_power2(alloc_len);

        OBD_ALLOC(req->rq_repbuf, alloc_len);
        if (!req->rq_repbuf)
                RETURN(-ENOMEM);

        req->rq_repbuf_len = alloc_len;
        RETURN(0);
}

static
void plain_free_repbuf(struct ptlrpc_sec *sec,
                       struct ptlrpc_request *req)
{
        ENTRY;
        OBD_FREE(req->rq_repbuf, req->rq_repbuf_len);
        req->rq_repbuf = NULL;
        req->rq_repbuf_len = 0;
        EXIT;
}

static
int plain_enlarge_reqbuf(struct ptlrpc_sec *sec,
                         struct ptlrpc_request *req,
                         int segment, int newsize)
{
        struct lustre_msg      *newbuf;
        int                     oldsize;
        int                     newmsg_size, newbuf_size;
        ENTRY;

        /* embedded msg always at seg 0 */
        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_reqbuf_len >= req->rq_reqlen);
        LASSERT(lustre_msg_buf(req->rq_reqbuf, 0, 0) == req->rq_reqmsg);

        /* compute new embedded msg size.  */
        oldsize = req->rq_reqmsg->lm_buflens[segment];
        req->rq_reqmsg->lm_buflens[segment] = newsize;
        newmsg_size = lustre_msg_size_v2(req->rq_reqmsg->lm_bufcount,
                                         req->rq_reqmsg->lm_buflens);
        req->rq_reqmsg->lm_buflens[segment] = oldsize;

        /* compute new wrapper msg size.  */
        oldsize = req->rq_reqbuf->lm_buflens[0];
        req->rq_reqbuf->lm_buflens[0] = newmsg_size;
        newbuf_size = lustre_msg_size_v2(req->rq_reqbuf->lm_bufcount,
                                         req->rq_reqbuf->lm_buflens);
        req->rq_reqbuf->lm_buflens[0] = oldsize;

        /* request from pool should always have enough buffer */
        LASSERT(!req->rq_pool || req->rq_reqbuf_len >= newbuf_size);

        if (req->rq_reqbuf_len < newbuf_size) {
                newbuf_size = size_roundup_power2(newbuf_size);

                OBD_ALLOC(newbuf, newbuf_size);
                if (newbuf == NULL)
                        RETURN(-ENOMEM);

                memcpy(newbuf, req->rq_reqbuf, req->rq_reqbuf_len);

                OBD_FREE(req->rq_reqbuf, req->rq_reqbuf_len);
                req->rq_reqbuf = newbuf;
                req->rq_reqbuf_len = newbuf_size;
                req->rq_reqmsg = lustre_msg_buf(req->rq_reqbuf, 0, 0);
        }

        _sptlrpc_enlarge_msg_inplace(req->rq_reqbuf, 0, newmsg_size);
        _sptlrpc_enlarge_msg_inplace(req->rq_reqmsg, segment, newsize);

        req->rq_reqlen = newmsg_size;
        RETURN(0);
}

/****************************************
 * service apis                         *
 ****************************************/

static struct ptlrpc_svc_ctx plain_svc_ctx = {
        .sc_refcount    = ATOMIC_INIT(1),
        .sc_policy      = &plain_policy,
};

static
int plain_accept(struct ptlrpc_request *req)
{
        struct lustre_msg *msg = req->rq_reqbuf;
        int                bufcnt = 1;
        ENTRY;

        LASSERT(SEC_FLAVOR_POLICY(req->rq_sec_flavor) == SPTLRPC_POLICY_PLAIN);

        if (SEC_FLAVOR_RPC(req->rq_sec_flavor) != SPTLRPC_FLVR_PLAIN) {
                CERROR("Invalid flavor 0x%x\n", req->rq_sec_flavor);
                return SECSVC_DROP;
        }

        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor)) {
                if (msg->lm_bufcount < ++bufcnt) {
                        CERROR("Protocal error: too small buf count %d\n",
                               msg->lm_bufcount);
                        RETURN(SECSVC_DROP);
                }

                if (sptlrpc_unpack_user_desc(msg, bufcnt - 1)) {
                        CERROR("Mal-formed user descriptor\n");
                        RETURN(SECSVC_DROP);
                }

                req->rq_user_desc = lustre_msg_buf(msg, bufcnt - 1, 0);
        }

        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                if (msg->lm_bufcount != ++bufcnt) {
                        CERROR("Protocal error: invalid buf count %d\n",
                               msg->lm_bufcount);
                        RETURN(SECSVC_DROP);
                }

                if (bulk_sec_desc_unpack(msg, bufcnt - 1)) {
                        CERROR("Mal-formed bulk checksum request\n");
                        RETURN(SECSVC_DROP);
                }
        }

        req->rq_reqmsg = lustre_msg_buf(msg, 0, 0);
        req->rq_reqlen = msg->lm_buflens[0];

        req->rq_svc_ctx = &plain_svc_ctx;
        atomic_inc(&req->rq_svc_ctx->sc_refcount);

        RETURN(SECSVC_OK);
}

static
int plain_alloc_rs(struct ptlrpc_request *req, int msgsize)
{
        struct ptlrpc_reply_state *rs;
        struct ptlrpc_bulk_sec_desc *bsd;
        int bufcnt = 1, buflens[2];
        int rs_size = sizeof(*rs);
        ENTRY;

        LASSERT(msgsize % 8 == 0);

        buflens[0] = msgsize;
        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor) &&
            (req->rq_bulk_read || req->rq_bulk_write)) {
                bsd = lustre_msg_buf(req->rq_reqbuf,
                                     req->rq_reqbuf->lm_bufcount - 1,
                                     sizeof(*bsd));
                LASSERT(bsd);

                buflens[bufcnt++] = bulk_sec_desc_size(bsd->bsd_csum_alg, 0,
                                                       req->rq_bulk_read);
        }
        rs_size += lustre_msg_size_v2(bufcnt, buflens);

        rs = req->rq_reply_state;

        if (rs) {
                /* pre-allocated */
                LASSERT(rs->rs_size >= rs_size);
        } else {
                OBD_ALLOC(rs, rs_size);
                if (rs == NULL)
                        RETURN(-ENOMEM);

                rs->rs_size = rs_size;
        }

        rs->rs_svc_ctx = req->rq_svc_ctx;
        atomic_inc(&req->rq_svc_ctx->sc_refcount);
        rs->rs_repbuf = (struct lustre_msg *) (rs + 1);
        rs->rs_repbuf_len = rs_size - sizeof(*rs);

        lustre_init_msg_v2(rs->rs_repbuf, bufcnt, buflens, NULL);
        rs->rs_msg = lustre_msg_buf_v2(rs->rs_repbuf, 0, 0);

        req->rq_reply_state = rs;
        RETURN(0);
}

static
void plain_free_rs(struct ptlrpc_reply_state *rs)
{
        ENTRY;

        LASSERT(atomic_read(&rs->rs_svc_ctx->sc_refcount) > 1);
        atomic_dec(&rs->rs_svc_ctx->sc_refcount);

        if (!rs->rs_prealloc)
                OBD_FREE(rs, rs->rs_size);
        EXIT;
}

static
int plain_authorize(struct ptlrpc_request *req)
{
        struct ptlrpc_reply_state *rs = req->rq_reply_state;
        struct lustre_msg_v2      *msg = rs->rs_repbuf;
        int                        len;
        ENTRY;

        LASSERT(rs);
        LASSERT(msg);

        if (req->rq_replen != msg->lm_buflens[0])
                len = lustre_shrink_msg(msg, 0, req->rq_replen, 1);
        else
                len = lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);

        msg->lm_secflvr = req->rq_sec_flavor;
        rs->rs_repdata_len = len;
        RETURN(0);
}

static
int plain_svc_unwrap_bulk(struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_reply_state      *rs = req->rq_reply_state;
        int                             voff, roff;

        LASSERT(rs);

        voff = req->rq_reqbuf->lm_bufcount - 1;
        roff = rs->rs_repbuf->lm_bufcount - 1;

        return bulk_csum_svc(desc, req->rq_bulk_read,
                             lustre_msg_buf(req->rq_reqbuf, voff, 0),
                             lustre_msg_buflen(req->rq_reqbuf, voff),
                             lustre_msg_buf(rs->rs_repbuf, roff, 0),
                             lustre_msg_buflen(rs->rs_repbuf, roff));
}

static
int plain_svc_wrap_bulk(struct ptlrpc_request *req,
                        struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_reply_state      *rs = req->rq_reply_state;
        int                             voff, roff;

        LASSERT(rs);

        voff = req->rq_reqbuf->lm_bufcount - 1;
        roff = rs->rs_repbuf->lm_bufcount - 1;

        return bulk_csum_svc(desc, req->rq_bulk_read,
                             lustre_msg_buf(req->rq_reqbuf, voff, 0),
                             lustre_msg_buflen(req->rq_reqbuf, voff),
                             lustre_msg_buf(rs->rs_repbuf, roff, 0),
                             lustre_msg_buflen(rs->rs_repbuf, roff));
}

static struct ptlrpc_ctx_ops plain_ctx_ops = {
        .refresh                = plain_ctx_refresh,
        .sign                   = plain_ctx_sign,
        .verify                 = plain_ctx_verify,
        .wrap_bulk              = plain_cli_wrap_bulk,
        .unwrap_bulk            = plain_cli_unwrap_bulk,
};

static struct ptlrpc_sec_cops plain_sec_cops = {
        .create_sec             = plain_create_sec,
        .destroy_sec            = plain_destroy_sec,
        .lookup_ctx             = plain_lookup_ctx,
        .flush_ctx_cache        = plain_flush_ctx_cache,
        .alloc_reqbuf           = plain_alloc_reqbuf,
        .alloc_repbuf           = plain_alloc_repbuf,
        .free_reqbuf            = plain_free_reqbuf,
        .free_repbuf            = plain_free_repbuf,
        .enlarge_reqbuf         = plain_enlarge_reqbuf,
};

static struct ptlrpc_sec_sops plain_sec_sops = {
        .accept                 = plain_accept,
        .alloc_rs               = plain_alloc_rs,
        .authorize              = plain_authorize,
        .free_rs                = plain_free_rs,
        .unwrap_bulk            = plain_svc_unwrap_bulk,
        .wrap_bulk              = plain_svc_wrap_bulk,
};

static struct ptlrpc_sec_policy plain_policy = {
        .sp_owner               = THIS_MODULE,
        .sp_name                = "sec.plain",
        .sp_policy              = SPTLRPC_POLICY_PLAIN,
        .sp_cops                = &plain_sec_cops,
        .sp_sops                = &plain_sec_sops,
};

static
void plain_init_internal(void)
{
        static HLIST_HEAD(__list);

        plain_sec.ps_policy = &plain_policy;
        atomic_set(&plain_sec.ps_refcount, 1);     /* always busy */
        plain_sec.ps_import = NULL;
        plain_sec.ps_flavor = SPTLRPC_FLVR_PLAIN;
        plain_sec.ps_flags = 0;
        spin_lock_init(&plain_sec.ps_lock);
        atomic_set(&plain_sec.ps_busy, 1);         /* for "plain_cli_ctx" */
        CFS_INIT_LIST_HEAD(&plain_sec.ps_gc_list);
        plain_sec.ps_gc_interval = 0;
        plain_sec.ps_gc_next = 0;

        hlist_add_head(&plain_cli_ctx.cc_cache, &__list);
        atomic_set(&plain_cli_ctx.cc_refcount, 1);    /* for hash */
        plain_cli_ctx.cc_sec = &plain_sec;
        plain_cli_ctx.cc_ops = &plain_ctx_ops;
        plain_cli_ctx.cc_expire = 0;
        plain_cli_ctx.cc_flags = PTLRPC_CTX_CACHED | PTLRPC_CTX_ETERNAL |
                                 PTLRPC_CTX_UPTODATE;
        plain_cli_ctx.cc_vcred.vc_uid = 0;
        spin_lock_init(&plain_cli_ctx.cc_lock);
        CFS_INIT_LIST_HEAD(&plain_cli_ctx.cc_req_list);
        CFS_INIT_LIST_HEAD(&plain_cli_ctx.cc_gc_chain);
}

int sptlrpc_plain_init(void)
{
        int rc;

        plain_init_internal();

        rc = sptlrpc_register_policy(&plain_policy);
        if (rc)
                CERROR("failed to register sec.plain: %d\n", rc);

        return rc;
}

void sptlrpc_plain_fini(void)
{
        int rc;

        rc = sptlrpc_unregister_policy(&plain_policy);
        if (rc)
                CERROR("cannot unregister sec.plain: %d\n", rc);
}
