/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2006-2007 Cluster File Systems, Inc.
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
#include <obd_cksum.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_sec.h>

struct plain_sec {
        struct ptlrpc_sec       pls_base;
        rwlock_t                pls_lock;
        struct ptlrpc_cli_ctx  *pls_ctx;
};

static inline struct plain_sec *sec2plsec(struct ptlrpc_sec *sec)
{
        return container_of(sec, struct plain_sec, pls_base);
}

static struct ptlrpc_sec_policy plain_policy;
static struct ptlrpc_ctx_ops    plain_ctx_ops;
static struct ptlrpc_svc_ctx    plain_svc_ctx;

static unsigned int plain_at_offset;

/*
 * flavor flags (maximum 8 flags)
 */
#define PLAIN_WFLVR_FLAGS_OFFSET        (12)
#define PLAIN_WFLVR_FLAG_BULK           (1 << (0 + PLAIN_WFLVR_FLAGS_OFFSET))
#define PLAIN_WFLVR_FLAG_USER           (1 << (1 + PLAIN_WFLVR_FLAGS_OFFSET))

#define PLAIN_WFLVR_HAS_BULK(wflvr)      \
        (((wflvr) & PLAIN_WFLVR_FLAG_BULK) != 0)
#define PLAIN_WFLVR_HAS_USER(wflvr)      \
        (((wflvr) & PLAIN_WFLVR_FLAG_USER) != 0)

#define PLAIN_WFLVR_TO_RPC(wflvr)       \
        ((wflvr) & ((1 << PLAIN_WFLVR_FLAGS_OFFSET) - 1))

/*
 * similar to null sec, temporarily use the third byte of lm_secflvr to identify
 * the source sec part.
 */
static inline
void plain_encode_sec_part(struct lustre_msg *msg, enum lustre_sec_part sp)
{
        msg->lm_secflvr |= (((__u32) sp) & 0xFF) << 16;
}

static inline
enum lustre_sec_part plain_decode_sec_part(struct lustre_msg *msg)
{
        return (msg->lm_secflvr >> 16) & 0xFF;
}

/*
 * for simplicity, plain policy rpc use fixed layout.
 */
#define PLAIN_PACK_SEGMENTS             (3)

#define PLAIN_PACK_MSG_OFF              (0)
#define PLAIN_PACK_USER_OFF             (1)
#define PLAIN_PACK_BULK_OFF             (2)

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
int plain_ctx_validate(struct ptlrpc_cli_ctx *ctx)
{
        return 0;
}

static
int plain_ctx_sign(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req)
{
        struct lustre_msg_v2 *msg = req->rq_reqbuf;
        ENTRY;

        msg->lm_secflvr = req->rq_flvr.sf_rpc;
        if (req->rq_pack_bulk)
                msg->lm_secflvr |= PLAIN_WFLVR_FLAG_BULK;
        if (req->rq_pack_udesc)
                msg->lm_secflvr |= PLAIN_WFLVR_FLAG_USER;

        plain_encode_sec_part(msg, ctx->cc_sec->ps_part);

        req->rq_reqdata_len = lustre_msg_size_v2(msg->lm_bufcount,
                                                 msg->lm_buflens);
        RETURN(0);
}

static
int plain_ctx_verify(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req)
{
        struct lustre_msg *msg = req->rq_repdata;
        int                early = 0;
        __u32              cksum;
        ENTRY;

        if (msg->lm_bufcount != PLAIN_PACK_SEGMENTS) {
                CERROR("unexpected reply buf count %u\n", msg->lm_bufcount);
                RETURN(-EPROTO);
        }

        /* find out if it's an early reply */
        if ((char *) msg < req->rq_repbuf ||
            (char *) msg >= req->rq_repbuf + req->rq_repbuf_len)
                early = 1;

        /* expect no user desc in reply */
        if (PLAIN_WFLVR_HAS_USER(msg->lm_secflvr)) {
                CERROR("Unexpected udesc flag in reply\n");
                RETURN(-EPROTO);
        }

        if (unlikely(early)) {
                cksum = crc32_le(!(__u32) 0,
                                 lustre_msg_buf(msg, PLAIN_PACK_MSG_OFF, 0),
                                 lustre_msg_buflen(msg, PLAIN_PACK_MSG_OFF));
                if (cksum != msg->lm_cksum) {
                        CWARN("early reply checksum mismatch: %08x != %08x\n",
                              cpu_to_le32(cksum), msg->lm_cksum);
                        RETURN(-EINVAL);
                }
        } else {
                /* whether we sent with bulk or not, we expect the same
                 * in reply, except for early reply */
                if (!early &&
                    !equi(req->rq_pack_bulk == 1,
                          PLAIN_WFLVR_HAS_BULK(msg->lm_secflvr))) {
                        CERROR("%s bulk checksum in reply\n",
                               req->rq_pack_bulk ? "Missing" : "Unexpected");
                        RETURN(-EPROTO);
                }

                if (PLAIN_WFLVR_HAS_BULK(msg->lm_secflvr) &&
                    bulk_sec_desc_unpack(msg, PLAIN_PACK_BULK_OFF)) {
                        CERROR("Mal-formed bulk checksum reply\n");
                        RETURN(-EINVAL);
                }
        }

        req->rq_repmsg = lustre_msg_buf(msg, PLAIN_PACK_MSG_OFF, 0);
        req->rq_replen = lustre_msg_buflen(msg, PLAIN_PACK_MSG_OFF);
        RETURN(0);
}

static
int plain_cli_wrap_bulk(struct ptlrpc_cli_ctx *ctx,
                        struct ptlrpc_request *req,
                        struct ptlrpc_bulk_desc *desc)
{
        LASSERT(req->rq_pack_bulk);
        LASSERT(req->rq_reqbuf->lm_bufcount == PLAIN_PACK_SEGMENTS);

        return bulk_csum_cli_request(desc, req->rq_bulk_read,
                                     req->rq_flvr.sf_bulk_hash,
                                     req->rq_reqbuf,
                                     PLAIN_PACK_BULK_OFF);
}

static
int plain_cli_unwrap_bulk(struct ptlrpc_cli_ctx *ctx,
                          struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc)
{
        LASSERT(req->rq_pack_bulk);
        LASSERT(req->rq_reqbuf->lm_bufcount == PLAIN_PACK_SEGMENTS);
        LASSERT(req->rq_repdata->lm_bufcount == PLAIN_PACK_SEGMENTS);

        return bulk_csum_cli_reply(desc, req->rq_bulk_read,
                                   req->rq_reqbuf, PLAIN_PACK_BULK_OFF,
                                   req->rq_repdata, PLAIN_PACK_BULK_OFF);
}

/****************************************
 * sec apis                             *
 ****************************************/

static
struct ptlrpc_cli_ctx *plain_sec_install_ctx(struct plain_sec *plsec)
{
        struct ptlrpc_cli_ctx  *ctx, *ctx_new;

        OBD_ALLOC_PTR(ctx_new);

        write_lock(&plsec->pls_lock);

        ctx = plsec->pls_ctx;
        if (ctx) {
                atomic_inc(&ctx->cc_refcount);

                if (ctx_new)
                        OBD_FREE_PTR(ctx_new);
        } else if (ctx_new) {
                ctx = ctx_new;

                atomic_set(&ctx->cc_refcount, 1); /* for cache */
                ctx->cc_sec = &plsec->pls_base;
                ctx->cc_ops = &plain_ctx_ops;
                ctx->cc_expire = 0;
                ctx->cc_flags = PTLRPC_CTX_CACHED | PTLRPC_CTX_UPTODATE;
                ctx->cc_vcred.vc_uid = 0;
                spin_lock_init(&ctx->cc_lock);
                CFS_INIT_LIST_HEAD(&ctx->cc_req_list);
                CFS_INIT_LIST_HEAD(&ctx->cc_gc_chain);

                plsec->pls_ctx = ctx;
                atomic_inc(&plsec->pls_base.ps_nctx);
                atomic_inc(&plsec->pls_base.ps_refcount);

                atomic_inc(&ctx->cc_refcount); /* for caller */
        }

        write_unlock(&plsec->pls_lock);

        return ctx;
}

static
void plain_destroy_sec(struct ptlrpc_sec *sec)
{
        struct plain_sec       *plsec = sec2plsec(sec);
        ENTRY;

        LASSERT(sec->ps_policy == &plain_policy);
        LASSERT(sec->ps_import);
        LASSERT(atomic_read(&sec->ps_refcount) == 0);
        LASSERT(atomic_read(&sec->ps_nctx) == 0);
        LASSERT(plsec->pls_ctx == NULL);

        class_import_put(sec->ps_import);

        OBD_FREE_PTR(plsec);
        EXIT;
}

static
void plain_kill_sec(struct ptlrpc_sec *sec)
{
        sec->ps_dying = 1;
}

static
struct ptlrpc_sec *plain_create_sec(struct obd_import *imp,
                                    struct ptlrpc_svc_ctx *svc_ctx,
                                    struct sptlrpc_flavor *sf)
{
        struct plain_sec       *plsec;
        struct ptlrpc_sec      *sec;
        struct ptlrpc_cli_ctx  *ctx;
        ENTRY;

        LASSERT(RPC_FLVR_POLICY(sf->sf_rpc) == SPTLRPC_POLICY_PLAIN);

        if (sf->sf_bulk_ciph != BULK_CIPH_ALG_NULL) {
                CERROR("plain policy don't support bulk cipher: %u\n",
                       sf->sf_bulk_ciph);
                RETURN(NULL);
        }

        OBD_ALLOC_PTR(plsec);
        if (plsec == NULL)
                RETURN(NULL);

        /*
         * initialize plain_sec
         */
        plsec->pls_lock = RW_LOCK_UNLOCKED;
        plsec->pls_ctx = NULL;

        sec = &plsec->pls_base;
        sec->ps_policy = &plain_policy;
        atomic_set(&sec->ps_refcount, 0);
        atomic_set(&sec->ps_nctx, 0);
        sec->ps_id = sptlrpc_get_next_secid();
        sec->ps_import = class_import_get(imp);
        sec->ps_flvr = *sf;
        sec->ps_lock = SPIN_LOCK_UNLOCKED;
        CFS_INIT_LIST_HEAD(&sec->ps_gc_list);
        sec->ps_gc_interval = 0;
        sec->ps_gc_next = 0;

        /* install ctx immediately if this is a reverse sec */
        if (svc_ctx) {
                ctx = plain_sec_install_ctx(plsec);
                if (ctx == NULL) {
                        plain_destroy_sec(sec);
                        RETURN(NULL);
                }
                sptlrpc_cli_ctx_put(ctx, 1);
        }

        RETURN(sec);
}

static
struct ptlrpc_cli_ctx *plain_lookup_ctx(struct ptlrpc_sec *sec,
                                        struct vfs_cred *vcred,
                                        int create, int remove_dead)
{
        struct plain_sec       *plsec = sec2plsec(sec);
        struct ptlrpc_cli_ctx  *ctx;
        ENTRY;

        read_lock(&plsec->pls_lock);
        ctx = plsec->pls_ctx;
        if (ctx)
                atomic_inc(&ctx->cc_refcount);
        read_unlock(&plsec->pls_lock);

        if (unlikely(ctx == NULL))
                ctx = plain_sec_install_ctx(plsec);

        RETURN(ctx);
}

static
void plain_release_ctx(struct ptlrpc_sec *sec,
                       struct ptlrpc_cli_ctx *ctx, int sync)
{
        LASSERT(atomic_read(&sec->ps_refcount) > 0);
        LASSERT(atomic_read(&sec->ps_nctx) > 0);
        LASSERT(atomic_read(&ctx->cc_refcount) == 0);
        LASSERT(ctx->cc_sec == sec);

        OBD_FREE_PTR(ctx);

        atomic_dec(&sec->ps_nctx);
        sptlrpc_sec_put(sec);
}

static
int plain_flush_ctx_cache(struct ptlrpc_sec *sec,
                          uid_t uid, int grace, int force)
{
        struct plain_sec       *plsec = sec2plsec(sec);
        struct ptlrpc_cli_ctx  *ctx;
        ENTRY;

        /* do nothing unless caller want to flush for 'all' */
        if (uid != -1)
                RETURN(0);

        write_lock(&plsec->pls_lock);
        ctx = plsec->pls_ctx;
        plsec->pls_ctx = NULL;
        write_unlock(&plsec->pls_lock);

        if (ctx)
                sptlrpc_cli_ctx_put(ctx, 1);
        RETURN(0);
}

static
int plain_alloc_reqbuf(struct ptlrpc_sec *sec,
                       struct ptlrpc_request *req,
                       int msgsize)
{
        int buflens[PLAIN_PACK_SEGMENTS] = { 0, };
        int alloc_len;
        ENTRY;

        buflens[PLAIN_PACK_MSG_OFF] = msgsize;

        if (req->rq_pack_udesc)
                buflens[PLAIN_PACK_USER_OFF] = sptlrpc_current_user_desc_size();

        if (req->rq_pack_bulk) {
                LASSERT(req->rq_bulk_read || req->rq_bulk_write);

                buflens[PLAIN_PACK_BULK_OFF] = bulk_sec_desc_size(
                                                req->rq_flvr.sf_bulk_hash, 1,
                                                req->rq_bulk_read);
        }

        alloc_len = lustre_msg_size_v2(PLAIN_PACK_SEGMENTS, buflens);

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

        lustre_init_msg_v2(req->rq_reqbuf, PLAIN_PACK_SEGMENTS, buflens, NULL);
        req->rq_reqmsg = lustre_msg_buf_v2(req->rq_reqbuf, 0, 0);

        if (req->rq_pack_udesc)
                sptlrpc_pack_user_desc(req->rq_reqbuf, PLAIN_PACK_USER_OFF);

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

        req->rq_reqmsg = NULL;
        EXIT;
}

static
int plain_alloc_repbuf(struct ptlrpc_sec *sec,
                       struct ptlrpc_request *req,
                       int msgsize)
{
        int buflens[PLAIN_PACK_SEGMENTS] = { 0, };
        int alloc_len;
        ENTRY;

        buflens[PLAIN_PACK_MSG_OFF] = msgsize;

        if (req->rq_pack_bulk) {
                LASSERT(req->rq_bulk_read || req->rq_bulk_write);
                buflens[PLAIN_PACK_BULK_OFF] = bulk_sec_desc_size(
                                                req->rq_flvr.sf_bulk_hash, 0,
                                                req->rq_bulk_read);
        }

        alloc_len = lustre_msg_size_v2(PLAIN_PACK_SEGMENTS, buflens);

        /* add space for early reply */
        alloc_len += plain_at_offset;

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

        req->rq_repmsg = NULL;
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

        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_reqbuf_len >= req->rq_reqlen);
        LASSERT(lustre_msg_buf(req->rq_reqbuf, PLAIN_PACK_MSG_OFF, 0) ==
                req->rq_reqmsg);

        /* compute new embedded msg size.  */
        oldsize = req->rq_reqmsg->lm_buflens[segment];
        req->rq_reqmsg->lm_buflens[segment] = newsize;
        newmsg_size = lustre_msg_size_v2(req->rq_reqmsg->lm_bufcount,
                                         req->rq_reqmsg->lm_buflens);
        req->rq_reqmsg->lm_buflens[segment] = oldsize;

        /* compute new wrapper msg size.  */
        oldsize = req->rq_reqbuf->lm_buflens[PLAIN_PACK_MSG_OFF];
        req->rq_reqbuf->lm_buflens[PLAIN_PACK_MSG_OFF] = newmsg_size;
        newbuf_size = lustre_msg_size_v2(req->rq_reqbuf->lm_bufcount,
                                         req->rq_reqbuf->lm_buflens);
        req->rq_reqbuf->lm_buflens[PLAIN_PACK_MSG_OFF] = oldsize;

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
                req->rq_reqmsg = lustre_msg_buf(req->rq_reqbuf,
                                                PLAIN_PACK_MSG_OFF, 0);
        }

        _sptlrpc_enlarge_msg_inplace(req->rq_reqbuf, PLAIN_PACK_MSG_OFF,
                                     newmsg_size);
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
        ENTRY;

        LASSERT(RPC_FLVR_POLICY(req->rq_flvr.sf_rpc) == SPTLRPC_POLICY_PLAIN);

        if (msg->lm_bufcount < PLAIN_PACK_SEGMENTS) {
                CERROR("unexpected request buf count %u\n", msg->lm_bufcount);
                RETURN(SECSVC_DROP);
        }

        if (req->rq_flvr.sf_rpc != SPTLRPC_FLVR_PLAIN) {
                CERROR("Invalid rpc flavor %x\n", req->rq_flvr.sf_rpc);
                RETURN(SECSVC_DROP);
        }

        req->rq_sp_from = plain_decode_sec_part(msg);

        if (PLAIN_WFLVR_HAS_USER(msg->lm_secflvr)) {
                if (sptlrpc_unpack_user_desc(msg, PLAIN_PACK_USER_OFF)) {
                        CERROR("Mal-formed user descriptor\n");
                        RETURN(SECSVC_DROP);
                }

                req->rq_pack_udesc = 1;
                req->rq_user_desc = lustre_msg_buf(msg, PLAIN_PACK_USER_OFF, 0);
        }

        if (PLAIN_WFLVR_HAS_BULK(msg->lm_secflvr)) {
                if (bulk_sec_desc_unpack(msg, PLAIN_PACK_BULK_OFF)) {
                        CERROR("Mal-formed bulk checksum request\n");
                        RETURN(SECSVC_DROP);
                }

                req->rq_pack_bulk = 1;
        }

        req->rq_reqmsg = lustre_msg_buf(msg, PLAIN_PACK_MSG_OFF, 0);
        req->rq_reqlen = msg->lm_buflens[PLAIN_PACK_MSG_OFF];

        req->rq_svc_ctx = &plain_svc_ctx;
        atomic_inc(&req->rq_svc_ctx->sc_refcount);

        RETURN(SECSVC_OK);
}

static
int plain_alloc_rs(struct ptlrpc_request *req, int msgsize)
{
        struct ptlrpc_reply_state   *rs;
        struct ptlrpc_bulk_sec_desc *bsd;
        int                          buflens[PLAIN_PACK_SEGMENTS] = { 0, };
        int                          rs_size = sizeof(*rs);
        ENTRY;

        LASSERT(msgsize % 8 == 0);

        buflens[PLAIN_PACK_MSG_OFF] = msgsize;

        if (req->rq_pack_bulk && (req->rq_bulk_read || req->rq_bulk_write)) {
                bsd = lustre_msg_buf(req->rq_reqbuf,
                                     PLAIN_PACK_BULK_OFF, sizeof(*bsd));
                LASSERT(bsd);

                buflens[PLAIN_PACK_BULK_OFF] = bulk_sec_desc_size(
                                                        bsd->bsd_hash_alg, 0,
                                                        req->rq_bulk_read);
        }
        rs_size += lustre_msg_size_v2(PLAIN_PACK_SEGMENTS, buflens);

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

        lustre_init_msg_v2(rs->rs_repbuf, PLAIN_PACK_SEGMENTS, buflens, NULL);
        rs->rs_msg = lustre_msg_buf_v2(rs->rs_repbuf, PLAIN_PACK_MSG_OFF, 0);

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

        if (req->rq_replen != msg->lm_buflens[PLAIN_PACK_MSG_OFF])
                len = lustre_shrink_msg(msg, PLAIN_PACK_MSG_OFF,
                                        req->rq_replen, 1);
        else
                len = lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);

        msg->lm_secflvr = req->rq_flvr.sf_rpc;
        if (req->rq_pack_bulk)
                msg->lm_secflvr |= PLAIN_WFLVR_FLAG_BULK;

        rs->rs_repdata_len = len;

        if (likely(req->rq_packed_final)) {
                req->rq_reply_off = plain_at_offset;
        } else {
                msg->lm_cksum = crc32_le(!(__u32) 0,
                                lustre_msg_buf(msg, PLAIN_PACK_MSG_OFF, 0),
                                lustre_msg_buflen(msg, PLAIN_PACK_MSG_OFF));
                req->rq_reply_off = 0;
        }

        RETURN(0);
}

static
int plain_svc_unwrap_bulk(struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_reply_state      *rs = req->rq_reply_state;

        LASSERT(rs);
        LASSERT(req->rq_pack_bulk);
        LASSERT(req->rq_reqbuf->lm_bufcount >= PLAIN_PACK_SEGMENTS);
        LASSERT(rs->rs_repbuf->lm_bufcount == PLAIN_PACK_SEGMENTS);

        return bulk_csum_svc(desc, req->rq_bulk_read,
                             lustre_msg_buf(req->rq_reqbuf,
                                            PLAIN_PACK_BULK_OFF, 0),
                             lustre_msg_buflen(req->rq_reqbuf,
                                               PLAIN_PACK_BULK_OFF),
                             lustre_msg_buf(rs->rs_repbuf,
                                            PLAIN_PACK_BULK_OFF, 0),
                             lustre_msg_buflen(rs->rs_repbuf,
                                               PLAIN_PACK_BULK_OFF));
}

static
int plain_svc_wrap_bulk(struct ptlrpc_request *req,
                        struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_reply_state      *rs = req->rq_reply_state;

        LASSERT(rs);
        LASSERT(req->rq_pack_bulk);
        LASSERT(req->rq_reqbuf->lm_bufcount >= PLAIN_PACK_SEGMENTS);
        LASSERT(rs->rs_repbuf->lm_bufcount == PLAIN_PACK_SEGMENTS);

        return bulk_csum_svc(desc, req->rq_bulk_read,
                             lustre_msg_buf(req->rq_reqbuf,
                                            PLAIN_PACK_BULK_OFF, 0),
                             lustre_msg_buflen(req->rq_reqbuf,
                                               PLAIN_PACK_BULK_OFF),
                             lustre_msg_buf(rs->rs_repbuf,
                                            PLAIN_PACK_BULK_OFF, 0),
                             lustre_msg_buflen(rs->rs_repbuf,
                                               PLAIN_PACK_BULK_OFF));
}

static struct ptlrpc_ctx_ops plain_ctx_ops = {
        .refresh                = plain_ctx_refresh,
        .validate               = plain_ctx_validate,
        .sign                   = plain_ctx_sign,
        .verify                 = plain_ctx_verify,
        .wrap_bulk              = plain_cli_wrap_bulk,
        .unwrap_bulk            = plain_cli_unwrap_bulk,
};

static struct ptlrpc_sec_cops plain_sec_cops = {
        .create_sec             = plain_create_sec,
        .destroy_sec            = plain_destroy_sec,
        .kill_sec               = plain_kill_sec,
        .lookup_ctx             = plain_lookup_ctx,
        .release_ctx            = plain_release_ctx,
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
        .sp_name                = "plain",
        .sp_policy              = SPTLRPC_POLICY_PLAIN,
        .sp_cops                = &plain_sec_cops,
        .sp_sops                = &plain_sec_sops,
};

int sptlrpc_plain_init(void)
{
        int buflens[PLAIN_PACK_SEGMENTS] = { 0, };
        int rc;

        buflens[PLAIN_PACK_MSG_OFF] = lustre_msg_early_size();
        plain_at_offset = lustre_msg_size_v2(PLAIN_PACK_SEGMENTS, buflens);

        rc = sptlrpc_register_policy(&plain_policy);
        if (rc)
                CERROR("failed to register: %d\n", rc);

        return rc;
}

void sptlrpc_plain_fini(void)
{
        int rc;

        rc = sptlrpc_unregister_policy(&plain_policy);
        if (rc)
                CERROR("cannot unregister: %d\n", rc);
}
