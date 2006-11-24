/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004 - 2006, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 * Neil Brown <neilb@cse.unsw.edu.au>
 * J. Bruce Fields <bfields@umich.edu>
 * Andy Adamson <andros@umich.edu>
 * Dug Song <dugsong@monkey.org>
 *
 * RPCSEC_GSS server authentication.
 * This implements RPCSEC_GSS as defined in rfc2203 (rpcsec_gss) and rfc2078
 * (gssapi)
 *
 * The RPCSEC_GSS involves three stages:
 *  1/ context creation
 *  2/ data exchange
 *  3/ context destruction
 *
 * Context creation is handled largely by upcalls to user-space.
 *  In particular, GSS_Accept_sec_context is handled by an upcall
 * Data exchange is handled entirely within the kernel
 *  In particular, GSS_GetMIC, GSS_VerifyMIC, GSS_Seal, GSS_Unseal are in-kernel.
 * Context destruction is handled in-kernel
 *  GSS_Delete_sec_context is in-kernel
 *
 * Context creation is initiated by a RPCSEC_GSS_INIT request arriving.
 * The context handle and gss_token are used as a key into the rpcsec_init cache.
 * The content of this cache includes some of the outputs of GSS_Accept_sec_context,
 * being major_status, minor_status, context_handle, reply_token.
 * These are sent back to the client.
 * Sequence window management is handled by the kernel.  The window size if currently
 * a compile time constant.
 *
 * When user-space is happy that a context is established, it places an entry
 * in the rpcsec_context cache. The key for this cache is the context_handle.
 * The content includes:
 *   uid/gidlist - for determining access rights
 *   mechanism type
 *   mechanism specific information, such as a key
 *
 */

#define DEBUG_SUBSYSTEM S_SEC
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hash.h>
#else
#include <liblustre.h>
#endif

#include <linux/sunrpc/cache.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre/lustre_idl.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_sec.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"

#define GSS_SVC_UPCALL_TIMEOUT  (20)

static spinlock_t __ctx_index_lock = SPIN_LOCK_UNLOCKED;
static __u64 __ctx_index = 1ULL;

__u64 gss_get_next_ctx_index(void)
{
        __u64 idx;

        spin_lock(&__ctx_index_lock);
        idx = __ctx_index++;
        spin_unlock(&__ctx_index_lock);

        return idx;
}

static inline
unsigned long hash_mem(char *buf, int length, int bits)
{
        unsigned long hash = 0;
        unsigned long l = 0;
        int len = 0;
        unsigned char c;

        do {
                if (len == length) {
                        c = (char) len;
                        len = -1;
                } else
                        c = *buf++;

                l = (l << 8) | c;
                len++;

                if ((len & (BITS_PER_LONG/8-1)) == 0)
                        hash = hash_long(hash^l, BITS_PER_LONG);
        } while (len);

        return hash >> (BITS_PER_LONG - bits);
}

/****************************************
 * rsi cache                            *
 ****************************************/

#define RSI_HASHBITS    (6)
#define RSI_HASHMAX     (1 << RSI_HASHBITS)
#define RSI_HASHMASK    (RSI_HASHMAX - 1)

struct rsi {
        struct cache_head       h;
        __u32                   lustre_svc;
        __u64                   nid;
        wait_queue_head_t       waitq;
        rawobj_t                in_handle, in_token;
        rawobj_t                out_handle, out_token;
        int                     major_status, minor_status;
};

static struct cache_head *rsi_table[RSI_HASHMAX];
static struct cache_detail rsi_cache;
static struct rsi *rsi_lookup(struct rsi *item, int set);

static
void rsi_free(struct rsi *rsi)
{
        rawobj_free(&rsi->in_handle);
        rawobj_free(&rsi->in_token);
        rawobj_free(&rsi->out_handle);
        rawobj_free(&rsi->out_token);
}

static
void rsi_put(struct cache_head *item, struct cache_detail *cd)
{
        struct rsi *rsi = container_of(item, struct rsi, h);

        LASSERT(atomic_read(&item->refcnt) > 0);

        if (cache_put(item, cd)) {
                LASSERT(item->next == NULL);
                rsi_free(rsi);
                kfree(rsi); /* created by cache mgmt using kmalloc */
        }
}

static inline
int rsi_hash(struct rsi *item)
{
        return hash_mem((char *)item->in_handle.data, item->in_handle.len,
                        RSI_HASHBITS) ^
               hash_mem((char *)item->in_token.data, item->in_token.len,
                        RSI_HASHBITS);
}

static inline
int rsi_match(struct rsi *item, struct rsi *tmp)
{
        return (rawobj_equal(&item->in_handle, &tmp->in_handle) &&
                rawobj_equal(&item->in_token, &tmp->in_token));
}

static
void rsi_request(struct cache_detail *cd,
                 struct cache_head *h,
                 char **bpp, int *blen)
{
        struct rsi *rsi = container_of(h, struct rsi, h);
        __u64 index = 0;

        /* if in_handle is null, provide kernel suggestion */
        if (rsi->in_handle.len == 0)
                index = gss_get_next_ctx_index();

        qword_addhex(bpp, blen, (char *) &rsi->lustre_svc,
                     sizeof(rsi->lustre_svc));
        qword_addhex(bpp, blen, (char *) &rsi->nid, sizeof(rsi->nid));
        qword_addhex(bpp, blen, (char *) &index, sizeof(index));
        qword_addhex(bpp, blen, rsi->in_handle.data, rsi->in_handle.len);
        qword_addhex(bpp, blen, rsi->in_token.data, rsi->in_token.len);
        (*bpp)[-1] = '\n';
}

static inline
void rsi_init(struct rsi *new, struct rsi *item)
{
        new->out_handle = RAWOBJ_EMPTY;
        new->out_token = RAWOBJ_EMPTY;

        new->in_handle = item->in_handle;
        item->in_handle = RAWOBJ_EMPTY;
        new->in_token = item->in_token;
        item->in_token = RAWOBJ_EMPTY;

        new->lustre_svc = item->lustre_svc;
        new->nid = item->nid;
        init_waitqueue_head(&new->waitq);
}

static inline
void rsi_update(struct rsi *new, struct rsi *item)
{
        LASSERT(new->out_handle.len == 0);
        LASSERT(new->out_token.len == 0);

        new->out_handle = item->out_handle;
        item->out_handle = RAWOBJ_EMPTY;
        new->out_token = item->out_token;
        item->out_token = RAWOBJ_EMPTY;

        new->major_status = item->major_status;
        new->minor_status = item->minor_status;
}

static
int rsi_parse(struct cache_detail *cd, char *mesg, int mlen)
{
        char           *buf = mesg;
        char           *ep;
        int             len;
        struct rsi      rsii, *rsip = NULL;
        time_t          expiry;
        int             status = -EINVAL;
        ENTRY;


        memset(&rsii, 0, sizeof(rsii));

        /* handle */
        len = qword_get(&mesg, buf, mlen);
        if (len < 0)
                goto out;
        if (rawobj_alloc(&rsii.in_handle, buf, len)) {
                status = -ENOMEM;
                goto out;
        }

        /* token */
        len = qword_get(&mesg, buf, mlen);
        if (len < 0)
                goto out;
        if (rawobj_alloc(&rsii.in_token, buf, len)) {
                status = -ENOMEM;
                goto out;
        }

        /* expiry */
        expiry = get_expiry(&mesg);
        if (expiry == 0)
                goto out;

        len = qword_get(&mesg, buf, mlen);
        if (len <= 0)
                goto out;

        /* major */
        rsii.major_status = simple_strtol(buf, &ep, 10);
        if (*ep)
                goto out;

        /* minor */
        len = qword_get(&mesg, buf, mlen);
        if (len <= 0)
                goto out;
        rsii.minor_status = simple_strtol(buf, &ep, 10);
        if (*ep)
                goto out;

        /* out_handle */
        len = qword_get(&mesg, buf, mlen);
        if (len < 0)
                goto out;
        if (rawobj_alloc(&rsii.out_handle, buf, len)) {
                status = -ENOMEM;
                goto out;
        }

        /* out_token */
        len = qword_get(&mesg, buf, mlen);
        if (len < 0)
                goto out;
        if (rawobj_alloc(&rsii.out_token, buf, len)) {
                status = -ENOMEM;
                goto out;
        }

        rsii.h.expiry_time = expiry;
        rsip = rsi_lookup(&rsii, 1);
        status = 0;
out:
        rsi_free(&rsii);
        if (rsip) {
                wake_up_all(&rsip->waitq);
                rsi_put(&rsip->h, &rsi_cache);
        }

        if (status)
                CERROR("rsi parse error %d\n", status);
        RETURN(status);
}

static struct cache_detail rsi_cache = {
        .hash_size      = RSI_HASHMAX,
        .hash_table     = rsi_table,
        .name           = "auth.ptlrpcs.init",
        .cache_put      = rsi_put,
        .cache_request  = rsi_request,
        .cache_parse    = rsi_parse,
};

static DefineSimpleCacheLookup(rsi, 0)

/****************************************
 * rsc cache                            *
 ****************************************/

#define RSC_HASHBITS    (10)
#define RSC_HASHMAX     (1 << RSC_HASHBITS)
#define RSC_HASHMASK    (RSC_HASHMAX - 1)

struct rsc {
        struct cache_head       h;
        struct obd_device      *target;
        rawobj_t                handle;
        struct gss_svc_ctx      ctx;
};

static struct cache_head *rsc_table[RSC_HASHMAX];
static struct cache_detail rsc_cache;
static struct rsc *rsc_lookup(struct rsc *item, int set);

static
void rsc_free(struct rsc *rsci)
{
        rawobj_free(&rsci->handle);
        rawobj_free(&rsci->ctx.gsc_rvs_hdl);
        lgss_delete_sec_context(&rsci->ctx.gsc_mechctx);
}

static
void rsc_put(struct cache_head *item, struct cache_detail *cd)
{
        struct rsc *rsci = container_of(item, struct rsc, h);

        LASSERT(atomic_read(&item->refcnt) > 0);

        if (cache_put(item, cd)) {
                LASSERT(item->next == NULL);
                rsc_free(rsci);
                kfree(rsci); /* created by cache mgmt using kmalloc */
        }
}

static inline
int rsc_hash(struct rsc *rsci)
{
        return hash_mem((char *)rsci->handle.data,
                        rsci->handle.len, RSC_HASHBITS);
}

static inline
int rsc_match(struct rsc *new, struct rsc *tmp)
{
        return rawobj_equal(&new->handle, &tmp->handle);
}

static inline
void rsc_init(struct rsc *new, struct rsc *tmp)
{
        new->handle = tmp->handle;
        tmp->handle = RAWOBJ_EMPTY;

        new->target = NULL;
        memset(&new->ctx, 0, sizeof(new->ctx));
        new->ctx.gsc_rvs_hdl = RAWOBJ_EMPTY;
}

static inline
void rsc_update(struct rsc *new, struct rsc *tmp)
{
        new->ctx = tmp->ctx;
        tmp->ctx.gsc_rvs_hdl = RAWOBJ_EMPTY;
        tmp->ctx.gsc_mechctx = NULL;

        memset(&new->ctx.gsc_seqdata, 0, sizeof(new->ctx.gsc_seqdata));
        spin_lock_init(&new->ctx.gsc_seqdata.ssd_lock);
}

static
int rsc_parse(struct cache_detail *cd, char *mesg, int mlen)
{
        char       *buf = mesg;
        int         len, rv, tmp_int;
        struct rsc  rsci, *rscp = NULL;
        time_t      expiry;
        int         status = -EINVAL;

        memset(&rsci, 0, sizeof(rsci));

        /* context handle */
        len = qword_get(&mesg, buf, mlen);
        if (len < 0) goto out;
        status = -ENOMEM;
        if (rawobj_alloc(&rsci.handle, buf, len))
                goto out;

        rsci.h.flags = 0;
        /* expiry */
        expiry = get_expiry(&mesg);
        status = -EINVAL;
        if (expiry == 0)
                goto out;

        /* remote flag */
        rv = get_int(&mesg, &tmp_int);
        if (rv) {
                CERROR("fail to get remote flag\n");
                goto out;
        }
        rsci.ctx.gsc_remote = (tmp_int != 0);

        /* root user flag */
        rv = get_int(&mesg, &tmp_int);
        if (rv) {
                CERROR("fail to get oss user flag\n");
                goto out;
        }
        rsci.ctx.gsc_usr_root = (tmp_int != 0);

        /* mds user flag */
        rv = get_int(&mesg, &tmp_int);
        if (rv) {
                CERROR("fail to get mds user flag\n");
                goto out;
        }
        rsci.ctx.gsc_usr_mds = (tmp_int != 0);

        /* mapped uid */
        rv = get_int(&mesg, (int *) &rsci.ctx.gsc_mapped_uid);
        if (rv) {
                CERROR("fail to get mapped uid\n");
                goto out;
        }

        /* uid, or NEGATIVE */
        rv = get_int(&mesg, (int *) &rsci.ctx.gsc_uid);
        if (rv == -EINVAL)
                goto out;
        if (rv == -ENOENT) {
                CERROR("NOENT? set rsc entry negative\n");
                set_bit(CACHE_NEGATIVE, &rsci.h.flags);
        } else {
                struct gss_api_mech *gm;
                rawobj_t tmp_buf;
                unsigned long ctx_expiry;

                /* gid */
                if (get_int(&mesg, (int *) &rsci.ctx.gsc_gid))
                        goto out;

                /* mech name */
                len = qword_get(&mesg, buf, mlen);
                if (len < 0)
                        goto out;
                gm = lgss_name_to_mech(buf);
                status = -EOPNOTSUPP;
                if (!gm)
                        goto out;

                status = -EINVAL;
                /* mech-specific data: */
                len = qword_get(&mesg, buf, mlen);
                if (len < 0) {
                        lgss_mech_put(gm);
                        goto out;
                }
                tmp_buf.len = len;
                tmp_buf.data = (unsigned char *)buf;
                if (lgss_import_sec_context(&tmp_buf, gm,
                                            &rsci.ctx.gsc_mechctx)) {
                        lgss_mech_put(gm);
                        goto out;
                }

                /* currently the expiry time passed down from user-space
                 * is invalid, here we retrive it from mech.
                 */
                if (lgss_inquire_context(rsci.ctx.gsc_mechctx, &ctx_expiry)) {
                        CERROR("unable to get expire time, drop it\n");
                        lgss_mech_put(gm);
                        goto out;
                }
                expiry = (time_t) ctx_expiry;

                lgss_mech_put(gm);
        }

        rsci.h.expiry_time = expiry;
        rscp = rsc_lookup(&rsci, 1);
        status = 0;
out:
        rsc_free(&rsci);
        if (rscp)
                rsc_put(&rscp->h, &rsc_cache);

        if (status)
                CERROR("parse rsc error %d\n", status);
        return status;
}

/****************************************
 * rsc cache flush                      *
 ****************************************/

typedef int rsc_entry_match(struct rsc *rscp, long data);

static
void rsc_flush(rsc_entry_match *match, long data)
{
        struct cache_head **ch;
        struct rsc *rscp;
        int n;
        ENTRY;

        write_lock(&rsc_cache.hash_lock);
        for (n = 0; n < RSC_HASHMAX; n++) {
                for (ch = &rsc_cache.hash_table[n]; *ch;) {
                        rscp = container_of(*ch, struct rsc, h);

                        if (!match(rscp, data)) {
                                ch = &((*ch)->next);
                                continue;
                        }

                        /* it seems simply set NEGATIVE doesn't work */
                        *ch = (*ch)->next;
                        rscp->h.next = NULL;
                        cache_get(&rscp->h);
                        set_bit(CACHE_NEGATIVE, &rscp->h.flags);
                        rsc_put(&rscp->h, &rsc_cache);
                        rsc_cache.entries--;
                }
        }
        write_unlock(&rsc_cache.hash_lock);
        EXIT;
}

static
int match_uid(struct rsc *rscp, long uid)
{
        if ((int) uid == -1)
                return 1;
        return ((int) rscp->ctx.gsc_uid == (int) uid);
}

static
int match_target(struct rsc *rscp, long target)
{
        return (rscp->target == (struct obd_device *) target);
}

static inline
void rsc_flush_uid(int uid)
{
        if (uid == -1)
                CWARN("flush all gss contexts...\n");

        rsc_flush(match_uid, (long) uid);
}

static inline
void rsc_flush_target(struct obd_device *target)
{
        rsc_flush(match_target, (long) target);
}

void gss_secsvc_flush(struct obd_device *target)
{
        rsc_flush_target(target);
}
EXPORT_SYMBOL(gss_secsvc_flush);

static struct cache_detail rsc_cache = {
        .hash_size      = RSC_HASHMAX,
        .hash_table     = rsc_table,
        .name           = "auth.ptlrpcs.context",
        .cache_put      = rsc_put,
        .cache_parse    = rsc_parse,
};

static DefineSimpleCacheLookup(rsc, 0);

static
struct rsc *gss_svc_searchbyctx(rawobj_t *handle)
{
        struct rsc  rsci;
        struct rsc *found;

        memset(&rsci, 0, sizeof(rsci));
        if (rawobj_dup(&rsci.handle, handle))
                return NULL;

        found = rsc_lookup(&rsci, 0);
        rsc_free(&rsci);
        if (!found)
                return NULL;
        if (cache_check(&rsc_cache, &found->h, NULL))
                return NULL;
        return found;
}

int gss_svc_upcall_install_rvs_ctx(struct obd_import *imp,
                                   struct gss_sec *gsec,
                                   struct gss_cli_ctx *gctx)
{
        struct rsc      rsci, *rscp;
        unsigned long   ctx_expiry;
        __u32           major;
        ENTRY;

        memset(&rsci, 0, sizeof(rsci));

        if (rawobj_alloc(&rsci.handle, (char *) &gsec->gs_rvs_hdl,
                         sizeof(gsec->gs_rvs_hdl))) {
                CERROR("unable alloc handle\n");
                RETURN(-ENOMEM);
        }

        major = lgss_copy_reverse_context(gctx->gc_mechctx,
                                          &rsci.ctx.gsc_mechctx);
        if (major != GSS_S_COMPLETE) {
                CERROR("unable to copy reverse context\n");
                rsc_free(&rsci);
                RETURN(-ENOMEM);
        }

        if (lgss_inquire_context(rsci.ctx.gsc_mechctx, &ctx_expiry)) {
                CERROR("unable to get expire time, drop it\n");
                rsc_free(&rsci);
                RETURN(-EINVAL);
        }

        rsci.h.expiry_time = (time_t) ctx_expiry;
        rsci.target = imp->imp_obd;

        rscp = rsc_lookup(&rsci, 1);
        rsc_free(&rsci);
        if (rscp)
                rsc_put(&rscp->h, &rsc_cache);

        CWARN("client installed reverse svc ctx to %s: idx %llx\n",
              imp->imp_obd->u.cli.cl_target_uuid.uuid,
              gsec->gs_rvs_hdl);

        imp->imp_next_reconnect = gss_round_imp_reconnect(ctx_expiry);
        CWARN("import to %s: set force reconnect at %lu(%lds valid time)\n",
              imp->imp_obd->u.cli.cl_target_uuid.uuid,
              imp->imp_next_reconnect,
              (long) (imp->imp_next_reconnect - get_seconds()));

        RETURN(0);
}

#if 0
static int
gss_svc_unseal_request(struct ptlrpc_request *req,
                       struct rsc *rsci,
                       struct gss_wire_cred *gc,
                       __u32 *vp, __u32 vlen)
{
        struct ptlrpcs_wire_hdr *sec_hdr;
        struct gss_ctx *ctx = rsci->mechctx;
        rawobj_t cipher_text, plain_text;
        __u32 major;
        ENTRY;

        sec_hdr = (struct ptlrpcs_wire_hdr *) req->rq_reqbuf;

        if (vlen < 4) {
                CERROR("vlen only %u\n", vlen);
                RETURN(GSS_S_CALL_BAD_STRUCTURE);
        }

        cipher_text.len = le32_to_cpu(*vp++);
        cipher_text.data = (__u8 *) vp;
        vlen -= 4;
        
        if (cipher_text.len > vlen) {
                CERROR("cipher claimed %u while buf only %u\n",
                        cipher_text.len, vlen);
                RETURN(GSS_S_CALL_BAD_STRUCTURE);
        }

        plain_text = cipher_text;

        major = lgss_unwrap(ctx, GSS_C_QOP_DEFAULT, &cipher_text, &plain_text);
        if (major) {
                CERROR("unwrap error 0x%x\n", major);
                RETURN(major);
        }

        if (gss_check_seq_num(&rsci->seqdata, gc->gc_seq)) {
                CERROR("discard replayed request %p(o%u,x"LPU64",t"LPU64")\n",
                        req, req->rq_reqmsg->opc, req->rq_xid,
                        req->rq_reqmsg->transno);
                RETURN(GSS_S_DUPLICATE_TOKEN);
        }

        req->rq_reqmsg = (struct lustre_msg *) (vp);
        req->rq_reqlen = plain_text.len;

        CDEBUG(D_SEC, "msg len %d\n", req->rq_reqlen);

        RETURN(GSS_S_COMPLETE);
}
#endif

static
struct cache_deferred_req* cache_upcall_defer(struct cache_req *req)
{
        return NULL;
}
static struct cache_req cache_upcall_chandle = { cache_upcall_defer };

int gss_svc_upcall_handle_init(struct ptlrpc_request *req,
                               struct gss_svc_reqctx *grctx,
                               struct gss_wire_ctx *gw,
                               struct obd_device *target,
                               __u32 lustre_svc,
                               rawobj_t *rvs_hdl,
                               rawobj_t *in_token)
{
        struct ptlrpc_reply_state *rs;
        struct rsc                *rsci = NULL;
        struct rsi                *rsip = NULL, rsikey;
        wait_queue_t               wait;
        int                        replen = sizeof(struct ptlrpc_body);
        struct gss_rep_header     *rephdr;
        int                        first_check = 1;
        int                        rc = SECSVC_DROP;
        ENTRY;

        memset(&rsikey, 0, sizeof(rsikey));
        rsikey.lustre_svc = lustre_svc;
        rsikey.nid = (__u64) req->rq_peer.nid;

        /* duplicate context handle. for INIT it always 0 */
        if (rawobj_dup(&rsikey.in_handle, &gw->gw_handle)) {
                CERROR("fail to dup context handle\n");
                GOTO(out, rc);
        }

        if (rawobj_dup(&rsikey.in_token, in_token)) {
                CERROR("can't duplicate token\n");
                rawobj_free(&rsikey.in_handle);
                GOTO(out, rc);
        }

        rsip = rsi_lookup(&rsikey, 0);
        rsi_free(&rsikey);
        if (!rsip) {
                CERROR("error in rsi_lookup.\n");

                if (!gss_pack_err_notify(req, GSS_S_FAILURE, 0))
                        rc = SECSVC_COMPLETE;

                GOTO(out, rc);
        }

        cache_get(&rsip->h); /* take an extra ref */
        init_waitqueue_head(&rsip->waitq);
        init_waitqueue_entry(&wait, current);
        add_wait_queue(&rsip->waitq, &wait);

cache_check:
        /* Note each time cache_check() will drop a reference if return
         * non-zero. We hold an extra reference on initial rsip, but must
         * take care of following calls.
         */
        rc = cache_check(&rsi_cache, &rsip->h, &cache_upcall_chandle);
        switch (rc) {
        case -EAGAIN: {
                int valid;

                if (first_check) {
                        first_check = 0;

                        read_lock(&rsi_cache.hash_lock);
                        valid = test_bit(CACHE_VALID, &rsip->h.flags);
                        if (valid == 0)
                                set_current_state(TASK_INTERRUPTIBLE);
                        read_unlock(&rsi_cache.hash_lock);

                        if (valid == 0) {
                                unsigned long j1, j2;

                                j1 = jiffies;
                                schedule_timeout(GSS_SVC_UPCALL_TIMEOUT * HZ);
                                j2 = jiffies;
                                CWARN("slept %lu ticks for cache refill\n",
                                      j2 - j1);
                        }

                        cache_get(&rsip->h);
                        goto cache_check;
                }
                CWARN("waited %ds timeout, drop\n", GSS_SVC_UPCALL_TIMEOUT);
                break;
        }
        case -ENOENT:
                CWARN("cache_check return ENOENT, drop\n");
                break;
        case 0:
                /* if not the first check, we have to release the extra
                 * reference we just added on it.
                 */
                if (!first_check)
                        cache_put(&rsip->h, &rsi_cache);
                CDEBUG(D_SEC, "cache_check is good\n");
                break;
        }

        remove_wait_queue(&rsip->waitq, &wait);
        cache_put(&rsip->h, &rsi_cache);

        if (rc)
                GOTO(out, rc = SECSVC_DROP);

        rc = SECSVC_DROP;
        rsci = gss_svc_searchbyctx(&rsip->out_handle);
        if (!rsci) {
                CERROR("authentication failed\n");

                if (!gss_pack_err_notify(req, GSS_S_FAILURE, 0))
                        rc = SECSVC_COMPLETE;

                GOTO(out, rc);
        } else {
                cache_get(&rsci->h);
                grctx->src_ctx = &rsci->ctx;
        }

        if (rawobj_dup(&rsci->ctx.gsc_rvs_hdl, rvs_hdl)) {
                CERROR("failed duplicate reverse handle\n");
                GOTO(out, rc);
        }

        rsci->target = target;

        CWARN("server create rsc %p(%u->%s)\n",
              rsci, rsci->ctx.gsc_uid, libcfs_nid2str(req->rq_peer.nid));

        if (rsip->out_handle.len > PTLRPC_GSS_MAX_HANDLE_SIZE) {
                CERROR("handle size %u too large\n", rsip->out_handle.len);
                GOTO(out, rc = SECSVC_DROP);
        }

        grctx->src_init = 1;
        grctx->src_reserve_len = size_round4(rsip->out_token.len);

        rc = lustre_pack_reply_v2(req, 1, &replen, NULL);
        if (rc) {
                CERROR("failed to pack reply: %d\n", rc);
                GOTO(out, rc = SECSVC_DROP);
        }

        rs = req->rq_reply_state;
        LASSERT(rs->rs_repbuf->lm_bufcount == 3);
        LASSERT(rs->rs_repbuf->lm_buflens[0] >=
                sizeof(*rephdr) + rsip->out_handle.len);
        LASSERT(rs->rs_repbuf->lm_buflens[2] >= rsip->out_token.len);

        rephdr = lustre_msg_buf(rs->rs_repbuf, 0, 0);
        rephdr->gh_version = PTLRPC_GSS_VERSION;
        rephdr->gh_flags = 0;
        rephdr->gh_proc = PTLRPC_GSS_PROC_ERR;
        rephdr->gh_major = rsip->major_status;
        rephdr->gh_minor = rsip->minor_status;
        rephdr->gh_seqwin = GSS_SEQ_WIN;
        rephdr->gh_handle.len = rsip->out_handle.len;
        memcpy(rephdr->gh_handle.data, rsip->out_handle.data,
               rsip->out_handle.len);

        memcpy(lustre_msg_buf(rs->rs_repbuf, 2, 0), rsip->out_token.data,
               rsip->out_token.len);

        rs->rs_repdata_len = lustre_shrink_msg(rs->rs_repbuf, 2,
                                               rsip->out_token.len, 0);

        if (rsci->ctx.gsc_usr_mds)
                CWARN("user from %s authenticated as mds\n",
                      libcfs_nid2str(req->rq_peer.nid));

        rc = SECSVC_OK;

out:
        /* it looks like here we should put rsip also, but this mess up
         * with NFS cache mgmt code... FIXME
         */
#if 0
        if (rsip)
                rsi_put(&rsip->h, &rsi_cache);
#endif

        if (rsci) {
                /* if anything went wrong, we don't keep the context too */
                if (rc != SECSVC_OK)
                        set_bit(CACHE_NEGATIVE, &rsci->h.flags);

                rsc_put(&rsci->h, &rsc_cache);
        }
        RETURN(rc);
}

struct gss_svc_ctx *gss_svc_upcall_get_ctx(struct ptlrpc_request *req,
                                           struct gss_wire_ctx *gw)
{
        struct rsc *rsc;

        rsc = gss_svc_searchbyctx(&gw->gw_handle);
        if (!rsc) {
                CWARN("Invalid gss context handle from %s\n",
                      libcfs_nid2str(req->rq_peer.nid));
                return NULL;
        }

        return &rsc->ctx;
}

void gss_svc_upcall_put_ctx(struct gss_svc_ctx *ctx)
{
        struct rsc *rsc = container_of(ctx, struct rsc, ctx);

        rsc_put(&rsc->h, &rsc_cache);
}

void gss_svc_upcall_destroy_ctx(struct gss_svc_ctx *ctx)
{
        struct rsc *rsc = container_of(ctx, struct rsc, ctx);

        set_bit(CACHE_NEGATIVE, &rsc->h.flags);
}

int __init gss_svc_init_upcall(void)
{
        int     i;

        cache_register(&rsi_cache);
        cache_register(&rsc_cache);

        /* FIXME this looks stupid. we intend to give lsvcgssd a chance to open
         * the init upcall channel, otherwise there's big chance that the first
         * upcall issued before the channel be opened thus nfsv4 cache code will
         * drop the request direclty, thus lead to unnecessary recovery time.
         * here we wait at miximum 1.5 seconds.
         */
        for (i = 0; i < 6; i++) {
                if (atomic_read(&rsi_cache.readers) > 0)
                        break;
                set_current_state(TASK_UNINTERRUPTIBLE);
                LASSERT(HZ >= 4);
                schedule_timeout(HZ / 4);
        }

        if (atomic_read(&rsi_cache.readers) == 0)
                CWARN("Init channel is not opened by lsvcgssd, following "
                      "request might be dropped until lsvcgssd is active\n");

        return 0;
}

void __exit gss_svc_exit_upcall(void)
{
        int rc;

        cache_purge(&rsi_cache);
        if ((rc = cache_unregister(&rsi_cache)))
                CERROR("unregister rsi cache: %d\n", rc);

        cache_purge(&rsc_cache);
        if ((rc = cache_unregister(&rsc_cache)))
                CERROR("unregister rsc cache: %d\n", rc);
}
