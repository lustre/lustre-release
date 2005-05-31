/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004, Cluster File Systems, Inc.
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

#include <libcfs/kp30.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_net.h>
#include <linux/lustre_import.h>
#include <linux/lustre_sec.h>
                                                                                                                        
#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"

static inline unsigned long hash_mem(char *buf, int length, int bits)
{
        unsigned long hash = 0;
        unsigned long l = 0;
        int len = 0;
        unsigned char c;
        do {
                if (len == length) {
                        c = (char)len; len = -1;
                } else
                        c = *buf++;
                l = (l << 8) | c;
                len++;
                if ((len & (BITS_PER_LONG/8-1))==0)
                        hash = hash_long(hash^l, BITS_PER_LONG);
        } while (len);
        return hash >> (BITS_PER_LONG - bits);
}

/* The rpcsec_init cache is used for mapping RPCSEC_GSS_{,CONT_}INIT requests
 * into replies.
 *
 * Key is context handle (\x if empty) and gss_token.
 * Content is major_status minor_status (integers) context_handle, reply_token.
 *
 */

#define RSI_HASHBITS    6
#define RSI_HASHMAX     (1<<RSI_HASHBITS)
#define RSI_HASHMASK    (RSI_HASHMAX-1)

struct rsi {
        struct cache_head       h;
        __u32                   naltype;
        __u32                   netid;
        __u64                   nid;
        rawobj_t                in_handle, in_token;
        rawobj_t                out_handle, out_token;
        int                     major_status, minor_status;
};

static struct cache_head *rsi_table[RSI_HASHMAX];
static struct cache_detail rsi_cache;

static void rsi_free(struct rsi *rsii)
{
        rawobj_free(&rsii->in_handle);
        rawobj_free(&rsii->in_token);
        rawobj_free(&rsii->out_handle);
        rawobj_free(&rsii->out_token);
}

static void rsi_put(struct cache_head *item, struct cache_detail *cd)
{
        struct rsi *rsii = container_of(item, struct rsi, h);
        if (cache_put(item, cd)) {
                rsi_free(rsii);
                OBD_FREE(rsii, sizeof(*rsii));
        }
}

static inline int rsi_hash(struct rsi *item)
{
        return hash_mem((char *)item->in_handle.data, item->in_handle.len, RSI_HASHBITS)
                ^ hash_mem((char *)item->in_token.data, item->in_token.len, RSI_HASHBITS);
}

static inline int rsi_match(struct rsi *item, struct rsi *tmp)
{
        return (rawobj_equal(&item->in_handle, &tmp->in_handle) &&
                rawobj_equal(&item->in_token, &tmp->in_token));
}

static void rsi_request(struct cache_detail *cd,
                        struct cache_head *h,
                        char **bpp, int *blen)
{
        struct rsi *rsii = container_of(h, struct rsi, h);

        qword_addhex(bpp, blen, (char *)&rsii->naltype, sizeof(rsii->naltype));
        qword_addhex(bpp, blen, (char *)&rsii->netid, sizeof(rsii->netid));
        qword_addhex(bpp, blen, (char *)&rsii->nid, sizeof(rsii->nid));
        qword_addhex(bpp, blen, (char *)rsii->in_handle.data, rsii->in_handle.len);
        qword_addhex(bpp, blen, (char *)rsii->in_token.data, rsii->in_token.len);
        (*bpp)[-1] = '\n';
}

static int
gssd_reply(struct rsi *item)
{
        struct rsi *tmp;
        struct cache_head **hp, **head;
        ENTRY;

        head = &rsi_cache.hash_table[rsi_hash(item)];
        write_lock(&rsi_cache.hash_lock);
        for (hp = head; *hp != NULL; hp = &tmp->h.next) {
                tmp = container_of(*hp, struct rsi, h);
                if (rsi_match(tmp, item)) {
                        cache_get(&tmp->h);
                        clear_bit(CACHE_HASHED, &tmp->h.flags);
                        *hp = tmp->h.next;
                        tmp->h.next = NULL;
                        rsi_cache.entries--;
                        if (test_bit(CACHE_VALID, &tmp->h.flags)) {
                                write_unlock(&rsi_cache.hash_lock);
                                rsi_put(&tmp->h, &rsi_cache);
                                RETURN(-EINVAL);
                        }
                        set_bit(CACHE_HASHED, &item->h.flags);
                        item->h.next = *hp;
                        *hp = &item->h;
                        rsi_cache.entries++;
                        set_bit(CACHE_VALID, &item->h.flags);
                        item->h.last_refresh = get_seconds();
                        write_unlock(&rsi_cache.hash_lock);
                        cache_fresh(&rsi_cache, &tmp->h, 0);
                        rsi_put(&tmp->h, &rsi_cache);
                        RETURN(0);
                }
        }
        write_unlock(&rsi_cache.hash_lock);
        RETURN(-EINVAL);
}

/* XXX
 * here we just wait here for its completion or timedout. it's a
 * hacking but works, and we'll comeup with real fix if we decided
 * to still stick with NFS4 cache code
 */
static struct rsi *
gssd_upcall(struct rsi *item, struct cache_req *chandle)
{
        struct rsi *tmp;
        struct cache_head **hp, **head;
        unsigned long starttime;
        ENTRY;

        head = &rsi_cache.hash_table[rsi_hash(item)];
        read_lock(&rsi_cache.hash_lock);
        for (hp = head; *hp != NULL; hp = &tmp->h.next) {
                tmp = container_of(*hp, struct rsi, h);
                if (rsi_match(tmp, item)) {
                        LBUG();
                        if (!test_bit(CACHE_VALID, &tmp->h.flags)) {
                                CERROR("found rsi without VALID\n");
                                read_unlock(&rsi_cache.hash_lock);
                                return NULL;
                        }
                        *hp = tmp->h.next;
                        tmp->h.next = NULL;
                        rsi_cache.entries--;
                        cache_get(&tmp->h);
                        read_unlock(&rsi_cache.hash_lock);
                        return tmp;
                }
        }
        // cache_get(&item->h);
        set_bit(CACHE_HASHED, &item->h.flags);
        item->h.next = *head;
        *head = &item->h;
        rsi_cache.entries++;
        read_unlock(&rsi_cache.hash_lock);
        cache_get(&item->h);

        cache_check(&rsi_cache, &item->h, chandle);
        starttime = get_seconds();
        do {
                yield();
                read_lock(&rsi_cache.hash_lock);
                for (hp = head; *hp != NULL; hp = &tmp->h.next) {
                        tmp = container_of(*hp, struct rsi, h);
                        if (tmp == item)
                                continue;
                        if (rsi_match(tmp, item)) {
                                if (!test_bit(CACHE_VALID, &tmp->h.flags)) {
                                        read_unlock(&rsi_cache.hash_lock);
                                        return NULL;
                                }
                                cache_get(&tmp->h);
                                clear_bit(CACHE_HASHED, &tmp->h.flags);
                                *hp = tmp->h.next;
                                tmp->h.next = NULL;
                                rsi_cache.entries--;
                                read_unlock(&rsi_cache.hash_lock);
                                return tmp;
                        }
                }
                read_unlock(&rsi_cache.hash_lock);
        } while ((get_seconds() - starttime) <= 5);
        CERROR("5s timeout while waiting cache refill\n");
        return NULL;
}

static int rsi_parse(struct cache_detail *cd,
                     char *mesg, int mlen)
{
        /* context token expiry major minor context token */
        char *buf = mesg;
        char *ep;
        int len;
        struct rsi *rsii;
        time_t expiry;
        int status = -EINVAL;
        ENTRY;

        OBD_ALLOC(rsii, sizeof(*rsii));
        if (!rsii) {
                CERROR("failed to alloc rsii\n");
                RETURN(-ENOMEM);
        }
        cache_init(&rsii->h);

        /* handle */
        len = qword_get(&mesg, buf, mlen);
        if (len < 0)
                goto out;
        status = -ENOMEM;
        if (rawobj_alloc(&rsii->in_handle, buf, len))
                goto out;

        /* token */
        len = qword_get(&mesg, buf, mlen);
        status = -EINVAL;
        if (len < 0)
                goto out;;
        status = -ENOMEM;
        if (rawobj_alloc(&rsii->in_token, buf, len))
                goto out;

        /* expiry */
        expiry = get_expiry(&mesg);
        status = -EINVAL;
        if (expiry == 0)
                goto out;

        /* major/minor */
        len = qword_get(&mesg, buf, mlen);
        if (len < 0)
                goto out;
        if (len == 0) {
                goto out;
        } else {
                rsii->major_status = simple_strtoul(buf, &ep, 10);
                if (*ep)
                        goto out;
                len = qword_get(&mesg, buf, mlen);
                if (len <= 0)
                        goto out;
                rsii->minor_status = simple_strtoul(buf, &ep, 10);
                if (*ep)
                        goto out;

                /* out_handle */
                len = qword_get(&mesg, buf, mlen);
                if (len < 0)
                        goto out;
                status = -ENOMEM;
                if (rawobj_alloc(&rsii->out_handle, buf, len))
                        goto out;

                /* out_token */
                len = qword_get(&mesg, buf, mlen);
                status = -EINVAL;
                if (len < 0)
                        goto out;
                status = -ENOMEM;
                if (rawobj_alloc(&rsii->out_token, buf, len))
                        goto out;
        }
        rsii->h.expiry_time = expiry;
        status = gssd_reply(rsii);
out:
        if (rsii)
                rsi_put(&rsii->h, &rsi_cache);
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

/*
 * The rpcsec_context cache is used to store a context that is
 * used in data exchange.
 * The key is a context handle. The content is:
 *  uid, gidlist, mechanism, service-set, mech-specific-data
 */

#define RSC_HASHBITS    10
#define RSC_HASHMAX     (1<<RSC_HASHBITS)
#define RSC_HASHMASK    (RSC_HASHMAX-1)

#define GSS_SEQ_WIN     512

struct gss_svc_seq_data {
        /* highest seq number seen so far: */
        __u32                   sd_max;
        /* for i such that sd_max-GSS_SEQ_WIN < i <= sd_max, the i-th bit of
         * sd_win is nonzero iff sequence number i has been seen already: */
        unsigned long           sd_win[GSS_SEQ_WIN/BITS_PER_LONG];
        spinlock_t              sd_lock;
};

struct rsc {
        struct cache_head       h;
        rawobj_t                handle;
        __u32                   remote_realm;
        struct vfs_cred         cred;
        uid_t                   mapped_uid;
        struct gss_svc_seq_data seqdata;
        struct gss_ctx         *mechctx;
};

static struct cache_head *rsc_table[RSC_HASHMAX];
static struct cache_detail rsc_cache;

static void rsc_free(struct rsc *rsci)
{
        rawobj_free(&rsci->handle);
        if (rsci->mechctx)
                kgss_delete_sec_context(&rsci->mechctx);
#if 0
        if (rsci->cred.vc_ginfo)
                put_group_info(rsci->cred.vc_ginfo);
#endif
}

static void rsc_put(struct cache_head *item, struct cache_detail *cd)
{
        struct rsc *rsci = container_of(item, struct rsc, h);

        if (cache_put(item, cd)) {
                rsc_free(rsci);
                OBD_FREE(rsci, sizeof(*rsci));
        }
}

static inline int
rsc_hash(struct rsc *rsci)
{
        return hash_mem((char *)rsci->handle.data,
                        rsci->handle.len, RSC_HASHBITS);
}

static inline int
rsc_match(struct rsc *new, struct rsc *tmp)
{
        return rawobj_equal(&new->handle, &tmp->handle);
}

static struct rsc *rsc_lookup(struct rsc *item, int set)
{
        struct rsc *tmp = NULL;
        struct cache_head **hp, **head;
        head = &rsc_cache.hash_table[rsc_hash(item)];
        ENTRY;

        if (set)
                write_lock(&rsc_cache.hash_lock);
        else
                read_lock(&rsc_cache.hash_lock);
        for (hp = head; *hp != NULL; hp = &tmp->h.next) {
                tmp = container_of(*hp, struct rsc, h);
                if (!rsc_match(tmp, item))
                        continue;
                cache_get(&tmp->h);
                if (!set) {
                        goto out_noset;
                }
                *hp = tmp->h.next;
                tmp->h.next = NULL;
                clear_bit(CACHE_HASHED, &tmp->h.flags);
                rsc_put(&tmp->h, &rsc_cache);
                goto out_set;
        }
        /* Didn't find anything */
        if (!set)
                goto out_noset;
        rsc_cache.entries++;
out_set:
        set_bit(CACHE_HASHED, &item->h.flags);
        item->h.next = *head;
        *head = &item->h;
        write_unlock(&rsc_cache.hash_lock);
        cache_fresh(&rsc_cache, &item->h, item->h.expiry_time);
        cache_get(&item->h);
        RETURN(item);
out_noset:
        read_unlock(&rsc_cache.hash_lock);
        RETURN(tmp);
}
                                                                                                                        
static int rsc_parse(struct cache_detail *cd,
                     char *mesg, int mlen)
{
        /* contexthandle expiry [ uid gid N <n gids> mechname
         * ...mechdata... ] */
        char *buf = mesg;
        int len, rv;
        struct rsc *rsci, *res = NULL;
        time_t expiry;
        int status = -EINVAL;

        OBD_ALLOC(rsci, sizeof(*rsci));
        if (!rsci) {
                CERROR("fail to alloc rsci\n");
                return -ENOMEM;
        }
        cache_init(&rsci->h);

        /* context handle */
        len = qword_get(&mesg, buf, mlen);
        if (len < 0) goto out;
        status = -ENOMEM;
        if (rawobj_alloc(&rsci->handle, buf, len))
                goto out;

        /* expiry */
        expiry = get_expiry(&mesg);
        status = -EINVAL;
        if (expiry == 0)
                goto out;

        /* remote flag */
        rv = get_int(&mesg, (int *)&rsci->remote_realm);
        if (rv) {
                CERROR("fail to get remote flag\n");
                goto out;
        }

        /* mapped uid */
        rv = get_int(&mesg, (int *)&rsci->mapped_uid);
        if (rv) {
                CERROR("fail to get mapped uid\n");
                goto out;
        }

        /* uid, or NEGATIVE */
        rv = get_int(&mesg, (int *)&rsci->cred.vc_uid);
        if (rv == -EINVAL)
                goto out;
        if (rv == -ENOENT) {
                CERROR("NOENT? set rsc entry negative\n");
                set_bit(CACHE_NEGATIVE, &rsci->h.flags);
        } else {
                struct gss_api_mech *gm;
                rawobj_t tmp_buf;
                __u64 ctx_expiry;

                /* gid */
                if (get_int(&mesg, (int *)&rsci->cred.vc_gid))
                        goto out;

                /* mech name */
                len = qword_get(&mesg, buf, mlen);
                if (len < 0)
                        goto out;
                gm = kgss_name_to_mech(buf);
                status = -EOPNOTSUPP;
                if (!gm)
                        goto out;

                status = -EINVAL;
                /* mech-specific data: */
                len = qword_get(&mesg, buf, mlen);
                if (len < 0) {
                        kgss_mech_put(gm);
                        goto out;
                }
                tmp_buf.len = len;
                tmp_buf.data = (unsigned char *)buf;
                if (kgss_import_sec_context(&tmp_buf, gm, &rsci->mechctx)) {
                        kgss_mech_put(gm);
                        goto out;
                }

                /* currently the expiry time passed down from user-space
                 * is invalid, here we retrive it from mech.
                 */
                if (kgss_inquire_context(rsci->mechctx, &ctx_expiry)) {
                        CERROR("unable to get expire time, drop it\n");
                        set_bit(CACHE_NEGATIVE, &rsci->h.flags);
                        kgss_mech_put(gm);
                        goto out;
                }
                expiry = (time_t) ctx_expiry;

                kgss_mech_put(gm);
        }
        rsci->h.expiry_time = expiry;
        spin_lock_init(&rsci->seqdata.sd_lock);
        res = rsc_lookup(rsci, 1);
        rsc_put(&res->h, &rsc_cache);
        status = 0;
out:
        if (rsci)
                rsc_put(&rsci->h, &rsc_cache);
        return status;
}

/*
 * flush all entries with @uid. @uid == -1 will match all.
 * we only know the uid, maybe netid/nid in the future, in all cases
 * we must search the whole cache
 */
static void rsc_flush(uid_t uid)
{
        struct cache_head **ch;
        struct rsc *rscp;
        int n;
        ENTRY;

        write_lock(&rsc_cache.hash_lock);
        for (n = 0; n < RSC_HASHMAX; n++) {
                for (ch = &rsc_cache.hash_table[n]; *ch;) {
                        rscp = container_of(*ch, struct rsc, h);
                        if (uid == -1 || rscp->cred.vc_uid == uid) {
                                /* it seems simply set NEGATIVE doesn't work */
                                *ch = (*ch)->next;
                                rscp->h.next = NULL;
                                cache_get(&rscp->h);
                                set_bit(CACHE_NEGATIVE, &rscp->h.flags);
                                clear_bit(CACHE_HASHED, &rscp->h.flags);
                                CDEBUG(D_SEC, "flush rsc %p for uid %u\n",
                                       rscp, rscp->cred.vc_uid);
                                rsc_put(&rscp->h, &rsc_cache);
                                rsc_cache.entries--;
                                continue;
                        }
                        ch = &((*ch)->next);
                }
        }
        write_unlock(&rsc_cache.hash_lock);
        EXIT;
}

static struct cache_detail rsc_cache = {
        .hash_size      = RSC_HASHMAX,
        .hash_table     = rsc_table,
        .name           = "auth.ptlrpcs.context",
        .cache_put      = rsc_put,
        .cache_parse    = rsc_parse,
};

static struct rsc *
gss_svc_searchbyctx(rawobj_t *handle)
{
        struct rsc rsci;
        struct rsc *found;

        rsci.handle = *handle;
        found = rsc_lookup(&rsci, 0);
        if (!found)
                return NULL;

        if (cache_check(&rsc_cache, &found->h, NULL))
                return NULL;

        return found;
}

struct gss_svc_data {
        /* decoded gss client cred: */
        struct rpc_gss_wire_cred        clcred;
        /* internal used status */
        unsigned int                    is_init:1,
                                        is_init_continue:1,
                                        is_err_notify:1,
                                        is_fini:1;
        int                             reserve_len;
};

/* FIXME
 * again hacking: only try to give the svcgssd a chance to handle
 * upcalls.
 */
struct cache_deferred_req* my_defer(struct cache_req *req)
{
        yield();
        return NULL;
}
static struct cache_req my_chandle = {my_defer};

/* Implements sequence number algorithm as specified in RFC 2203. */
static int
gss_check_seq_num(struct gss_svc_seq_data *sd, __u32 seq_num)
{
        int rc = 0;

        spin_lock(&sd->sd_lock);
        if (seq_num > sd->sd_max) {
                if (seq_num >= sd->sd_max + GSS_SEQ_WIN) {
                        memset(sd->sd_win, 0, sizeof(sd->sd_win));
                        sd->sd_max = seq_num;
                } else {
                        while(sd->sd_max < seq_num) {
                                sd->sd_max++;
                                __clear_bit(sd->sd_max % GSS_SEQ_WIN,
                                            sd->sd_win);
                        }
                }
                __set_bit(seq_num % GSS_SEQ_WIN, sd->sd_win);
                goto exit;
        } else if (seq_num + GSS_SEQ_WIN <= sd->sd_max) {
                CERROR("seq %u too low: max %u, win %d\n",
                        seq_num, sd->sd_max, GSS_SEQ_WIN);
                rc = 1;
                goto exit;
        }

        if (__test_and_set_bit(seq_num % GSS_SEQ_WIN, sd->sd_win)) {
                CERROR("seq %u is replay: max %u, win %d\n",
                        seq_num, sd->sd_max, GSS_SEQ_WIN);
                rc = 1;
        }
exit:
        spin_unlock(&sd->sd_lock);
        return rc;
}

static int
gss_svc_verify_request(struct ptlrpc_request *req,
                       struct rsc *rsci,
                       struct rpc_gss_wire_cred *gc,
                       __u32 *vp, __u32 vlen)
{
        struct ptlrpcs_wire_hdr *sec_hdr;
        struct gss_ctx *ctx = rsci->mechctx;
        __u32 maj_stat;
        rawobj_t msg;
        rawobj_t mic;
        ENTRY;

        sec_hdr = (struct ptlrpcs_wire_hdr *) req->rq_reqbuf;

        req->rq_reqmsg = (struct lustre_msg *) (req->rq_reqbuf + sizeof(*sec_hdr));
        req->rq_reqlen = sec_hdr->msg_len;

        msg.len = sec_hdr->msg_len;
        msg.data = (__u8 *)req->rq_reqmsg;

        mic.len = le32_to_cpu(*vp++);
        mic.data = (unsigned char *)vp;
        vlen -= 4;

        if (mic.len > vlen) {
                CERROR("checksum len %d, while buffer len %d\n",
                        mic.len, vlen);
                RETURN(GSS_S_CALL_BAD_STRUCTURE);
        }

        if (mic.len > 256) {
                CERROR("invalid mic len %d\n", mic.len);
                RETURN(GSS_S_CALL_BAD_STRUCTURE);
        }

        maj_stat = kgss_verify_mic(ctx, &msg, &mic, NULL);
        if (maj_stat != GSS_S_COMPLETE) {
                CERROR("MIC verification error: major %x\n", maj_stat);
                RETURN(maj_stat);
        }

        if (gss_check_seq_num(&rsci->seqdata, gc->gc_seq)) {
                CERROR("discard request %p with old seq_num %u\n",
                        req, gc->gc_seq);
                RETURN(GSS_S_DUPLICATE_TOKEN);
        }

        RETURN(GSS_S_COMPLETE);
}

static int
gss_svc_unseal_request(struct ptlrpc_request *req,
                       struct rsc *rsci,
                       struct rpc_gss_wire_cred *gc,
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

        major = kgss_unwrap(ctx, GSS_C_QOP_DEFAULT, &cipher_text, &plain_text);
        if (major) {
                CERROR("unwrap error 0x%x\n", major);
                RETURN(major);
        }

        if (gss_check_seq_num(&rsci->seqdata, gc->gc_seq)) {
                CERROR("discard request %p with old seq_num %u\n",
                        req, gc->gc_seq);
                RETURN(GSS_S_DUPLICATE_TOKEN);
        }

        req->rq_reqmsg = (struct lustre_msg *) (vp);
        req->rq_reqlen = plain_text.len;

        CDEBUG(D_SEC, "msg len %d\n", req->rq_reqlen);

        RETURN(GSS_S_COMPLETE);
}

static int
gss_pack_err_notify(struct ptlrpc_request *req,
                    __u32 major, __u32 minor)
{
        struct gss_svc_data *svcdata = req->rq_sec_svcdata;
        __u32 reslen, *resp, *reslenp;
        char  nidstr[PTL_NALFMT_SIZE];
        const __u32 secdata_len = 7 * 4;
        int rc;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_SVCGSS_ERR_NOTIFY|OBD_FAIL_ONCE, -EINVAL);

        LASSERT(svcdata);
        svcdata->is_err_notify = 1;
        svcdata->reserve_len = 7 * 4;

        rc = lustre_pack_reply(req, 0, NULL, NULL);
        if (rc) {
                CERROR("could not pack reply, err %d\n", rc);
                RETURN(rc);
        }

        LASSERT(req->rq_reply_state);
        LASSERT(req->rq_reply_state->rs_repbuf);
        LASSERT(req->rq_reply_state->rs_repbuf_len >= secdata_len);
        resp = (__u32 *) req->rq_reply_state->rs_repbuf;

        /* header */
        *resp++ = cpu_to_le32(PTLRPC_SEC_GSS);
        *resp++ = cpu_to_le32(PTLRPC_SEC_TYPE_NONE);
        *resp++ = cpu_to_le32(req->rq_replen);
        reslenp = resp++;

        /* skip lustre msg */
        resp += req->rq_replen / 4;
        reslen = svcdata->reserve_len;

        /* gss replay:
         * version, subflavor, notify, major, minor,
         * obj1(fake), obj2(fake)
         */
        *resp++ = cpu_to_le32(PTLRPC_SEC_GSS_VERSION);
        *resp++ = cpu_to_le32(PTLRPC_SEC_GSS_KRB5I);
        *resp++ = cpu_to_le32(PTLRPC_GSS_PROC_ERR);
        *resp++ = cpu_to_le32(major);
        *resp++ = cpu_to_le32(minor);
        *resp++ = 0;
        *resp++ = 0;
        reslen -= (4 * 4);
        /* the actual sec data length */
        *reslenp = cpu_to_le32(secdata_len);

        req->rq_reply_state->rs_repdata_len += (secdata_len);
        CDEBUG(D_SEC, "prepare gss error notify(0x%x/0x%x) to %s\n",
               major, minor,
               portals_nid2str(req->rq_peer.peer_ni->pni_number,
                               req->rq_peer.peer_id.nid, nidstr));
        RETURN(0);
}

static int
gss_svcsec_handle_init(struct ptlrpc_request *req,
                       struct rpc_gss_wire_cred *gc,
                       __u32 *secdata, __u32 seclen,
                       enum ptlrpcs_error *res)
{
        struct gss_svc_data *svcdata = req->rq_sec_svcdata;
        struct rsc          *rsci;
        struct rsi          *rsikey, *rsip;
        rawobj_t             tmpobj;
        __u32 reslen,       *resp, *reslenp;
        char                 nidstr[PTL_NALFMT_SIZE];
        int                  rc;
        ENTRY;

        LASSERT(svcdata);

        CDEBUG(D_SEC, "processing gss init(%d) request from %s\n", gc->gc_proc,
               portals_nid2str(req->rq_peer.peer_ni->pni_number,
                               req->rq_peer.peer_id.nid, nidstr));

        *res = PTLRPCS_BADCRED;
        OBD_FAIL_RETURN(OBD_FAIL_SVCGSS_INIT_REQ|OBD_FAIL_ONCE, SVC_DROP);

        if (gc->gc_proc == RPC_GSS_PROC_INIT &&
            gc->gc_ctx.len != 0) {
                CERROR("proc %d, ctx_len %d: not really init?\n",
                gc->gc_proc == RPC_GSS_PROC_INIT, gc->gc_ctx.len);
                RETURN(SVC_DROP);
        }

        OBD_ALLOC(rsikey, sizeof(*rsikey));
        if (!rsikey) {
                CERROR("out of memory\n");
                RETURN(SVC_DROP);
        }
        cache_init(&rsikey->h);

        if (rawobj_dup(&rsikey->in_handle, &gc->gc_ctx)) {
                CERROR("fail to dup context handle\n");
                GOTO(out_rsikey, rc = SVC_DROP);
        }
        *res = PTLRPCS_BADVERF;
        if (rawobj_extract(&tmpobj, &secdata, &seclen)) {
                CERROR("can't extract token\n");
                GOTO(out_rsikey, rc = SVC_DROP);
        }
        if (rawobj_dup(&rsikey->in_token, &tmpobj)) {
                CERROR("can't duplicate token\n");
                GOTO(out_rsikey, rc = SVC_DROP);
        }

        rsikey->naltype = (__u32) req->rq_peer.peer_ni->pni_number;
        rsikey->netid = 0;
        rsikey->nid = (__u64) req->rq_peer.peer_id.nid;

        rsip = gssd_upcall(rsikey, &my_chandle);
        if (!rsip) {
                CERROR("error in gssd_upcall.\n");
                GOTO(out_rsikey, rc = SVC_DROP);
        }

        rsci = gss_svc_searchbyctx(&rsip->out_handle);
        if (!rsci) {
                CERROR("rsci still not mature yet?\n");

                if (gss_pack_err_notify(req, GSS_S_FAILURE, 0))
                        rc = SVC_DROP;
                else
                        rc = SVC_COMPLETE;

                GOTO(out_rsip, rc);
        }
        CDEBUG(D_SEC, "svcsec create gss context %p(%u@%s)\n",
               rsci, rsci->cred.vc_uid,
               portals_nid2str(req->rq_peer.peer_ni->pni_number,
                               req->rq_peer.peer_id.nid, nidstr));

        svcdata->is_init = 1;
        svcdata->reserve_len = 6 * 4 +
                size_round4(rsip->out_handle.len) +
                size_round4(rsip->out_token.len);

        rc = lustre_pack_reply(req, 0, NULL, NULL);
        if (rc) {
                CERROR("failed to pack reply, rc = %d\n", rc);
                set_bit(CACHE_NEGATIVE, &rsci->h.flags);
                GOTO(out, rc = SVC_DROP);
        }

        /* header */
        resp = (__u32 *) req->rq_reply_state->rs_repbuf;
        *resp++ = cpu_to_le32(PTLRPC_SEC_GSS);
        *resp++ = cpu_to_le32(PTLRPC_SEC_TYPE_NONE);
        *resp++ = cpu_to_le32(req->rq_replen);
        reslenp = resp++;

        resp += req->rq_replen / 4;
        reslen = svcdata->reserve_len;

        /* gss reply:
         * status, major, minor, seq, out_handle, out_token
         */
        *resp++ = cpu_to_le32(PTLRPCS_OK);
        *resp++ = cpu_to_le32(rsip->major_status);
        *resp++ = cpu_to_le32(rsip->minor_status);
        *resp++ = cpu_to_le32(GSS_SEQ_WIN);
        reslen -= (4 * 4);
        if (rawobj_serialize(&rsip->out_handle,
                             &resp, &reslen))
                LBUG();
        if (rawobj_serialize(&rsip->out_token,
                             &resp, &reslen))
                LBUG();
        /* the actual sec data length */
        *reslenp = cpu_to_le32(svcdata->reserve_len - reslen);

        req->rq_reply_state->rs_repdata_len += le32_to_cpu(*reslenp);
        CDEBUG(D_SEC, "req %p: msgsize %d, authsize %d, "
               "total size %d\n", req, req->rq_replen,
               le32_to_cpu(*reslenp),
               req->rq_reply_state->rs_repdata_len);

        *res = PTLRPCS_OK;

        req->rq_auth_uid = rsci->cred.vc_uid;
        req->rq_remote_realm = rsci->remote_realm;
        req->rq_mapped_uid = rsci->mapped_uid;

        /* This is simplified since right now we doesn't support
         * INIT_CONTINUE yet.
         */
        if (gc->gc_proc == RPC_GSS_PROC_INIT) {
                struct ptlrpcs_wire_hdr *hdr;

                hdr = buf_to_sec_hdr(req->rq_reqbuf);
                req->rq_reqmsg = buf_to_lustre_msg(req->rq_reqbuf);
                req->rq_reqlen = hdr->msg_len;

                rc = SVC_LOGIN;
        } else
                rc = SVC_COMPLETE;

out:
        rsc_put(&rsci->h, &rsc_cache);
out_rsip:
        rsi_put(&rsip->h, &rsi_cache);
out_rsikey:
        rsi_put(&rsikey->h, &rsi_cache);

        RETURN(rc);
}

static int
gss_svcsec_handle_data(struct ptlrpc_request *req,
                       struct rpc_gss_wire_cred *gc,
                       __u32 *secdata, __u32 seclen,
                       enum ptlrpcs_error *res)
{
        struct rsc          *rsci;
        char                 nidstr[PTL_NALFMT_SIZE];
        __u32                major;
        int                  rc;
        ENTRY;

        *res = PTLRPCS_GSS_CREDPROBLEM;

        rsci = gss_svc_searchbyctx(&gc->gc_ctx);
        if (!rsci) {
                CWARN("Invalid gss context handle from %s\n",
                       portals_nid2str(req->rq_peer.peer_ni->pni_number,
                                       req->rq_peer.peer_id.nid, nidstr));
                major = GSS_S_NO_CONTEXT;
                goto notify_err;
        }

        switch (gc->gc_svc) {
        case PTLRPC_GSS_SVC_INTEGRITY:
                major = gss_svc_verify_request(req, rsci, gc, secdata, seclen);
                if (major == GSS_S_COMPLETE)
                        break;

                CWARN("fail in verify:0x%x: ctx %p@%s\n", major, rsci,
                       portals_nid2str(req->rq_peer.peer_ni->pni_number,
                                       req->rq_peer.peer_id.nid, nidstr));
                goto notify_err;
        case PTLRPC_GSS_SVC_PRIVACY:
                major = gss_svc_unseal_request(req, rsci, gc, secdata, seclen);
                if (major == GSS_S_COMPLETE)
                        break;

                CWARN("fail in decrypt:0x%x: ctx %p@%s\n", major, rsci,
                       portals_nid2str(req->rq_peer.peer_ni->pni_number,
                                       req->rq_peer.peer_id.nid, nidstr));
                goto notify_err;
        default:
                CERROR("unsupported gss service %d\n", gc->gc_svc);
                GOTO(out, rc = SVC_DROP);
        }

        req->rq_auth_uid = rsci->cred.vc_uid;
        req->rq_remote_realm = rsci->remote_realm;
        req->rq_mapped_uid = rsci->mapped_uid;

        *res = PTLRPCS_OK;
        GOTO(out, rc = SVC_OK);

notify_err:
        if (gss_pack_err_notify(req, major, 0))
                rc = SVC_DROP;
        else
                rc = SVC_COMPLETE;
out:
        if (rsci)
                rsc_put(&rsci->h, &rsc_cache);
        RETURN(rc);
}

static int
gss_svcsec_handle_destroy(struct ptlrpc_request *req,
                          struct rpc_gss_wire_cred *gc,
                          __u32 *secdata, __u32 seclen,
                          enum ptlrpcs_error *res)
{
        struct gss_svc_data *svcdata = req->rq_sec_svcdata;
        struct rsc          *rsci;
        char                 nidstr[PTL_NALFMT_SIZE];
        int                  rc;
        ENTRY;

        LASSERT(svcdata);
        *res = PTLRPCS_GSS_CREDPROBLEM;

        rsci = gss_svc_searchbyctx(&gc->gc_ctx);
        if (!rsci) {
                CWARN("invalid gss context handle for destroy.\n");
                RETURN(SVC_DROP);
        }

        if (gc->gc_svc != PTLRPC_GSS_SVC_INTEGRITY) {
                CERROR("service %d is not supported in destroy.\n",
                        gc->gc_svc);
                GOTO(out, rc = SVC_DROP);
        }

        *res = gss_svc_verify_request(req, rsci, gc, secdata, seclen);
        if (*res)
                GOTO(out, rc = SVC_DROP);

        /* compose reply, which is actually nothing */
        svcdata->is_fini = 1;
        if (lustre_pack_reply(req, 0, NULL, NULL))
                GOTO(out, rc = SVC_DROP);

        CDEBUG(D_SEC, "svcsec destroy gss context %p(%u@%s)\n",
               rsci, rsci->cred.vc_uid,
               portals_nid2str(req->rq_peer.peer_ni->pni_number,
                               req->rq_peer.peer_id.nid, nidstr));

        set_bit(CACHE_NEGATIVE, &rsci->h.flags);
        *res = PTLRPCS_OK;
        rc = SVC_LOGOUT;
out:
        rsc_put(&rsci->h, &rsc_cache);
        RETURN(rc);
}

/*
 * let incomming request go through security check:
 *  o context establishment: invoke user space helper
 *  o data exchange: verify/decrypt
 *  o context destruction: mark context invalid
 *
 * in most cases, error will result to drop the packet silently.
 */
static int
gss_svcsec_accept(struct ptlrpc_request *req, enum ptlrpcs_error *res)
{
        struct gss_svc_data *svcdata;
        struct rpc_gss_wire_cred *gc;
        struct ptlrpcs_wire_hdr *sec_hdr;
        __u32 seclen, *secdata, version, subflavor;
        int rc;
        ENTRY;

        CDEBUG(D_SEC, "request %p\n", req);
        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_reqbuf_len);

        *res = PTLRPCS_BADCRED;

        sec_hdr = buf_to_sec_hdr(req->rq_reqbuf);
        LASSERT(sec_hdr->flavor == PTLRPC_SEC_GSS);

        seclen = req->rq_reqbuf_len - sizeof(*sec_hdr) - sec_hdr->msg_len;
        secdata = (__u32 *) buf_to_sec_data(req->rq_reqbuf);

        if (sec_hdr->sec_len > seclen) {
                CERROR("seclen %d, while max buf %d\n",
                        sec_hdr->sec_len, seclen);
                RETURN(SVC_DROP);
        }

        if (seclen < 6 * 4) {
                CERROR("sec size %d too small\n", seclen);
                RETURN(SVC_DROP);
        }

        LASSERT(!req->rq_sec_svcdata);
        OBD_ALLOC(svcdata, sizeof(*svcdata));
        if (!svcdata) {
                CERROR("fail to alloc svcdata\n");
                RETURN(SVC_DROP);
        }
        req->rq_sec_svcdata = svcdata;
        gc = &svcdata->clcred;

        /* Now secdata/seclen is what we want to parse
         */
        version = le32_to_cpu(*secdata++);      /* version */
        subflavor = le32_to_cpu(*secdata++);    /* subflavor */
        gc->gc_proc = le32_to_cpu(*secdata++);  /* proc */
        gc->gc_seq = le32_to_cpu(*secdata++);   /* seq */
        gc->gc_svc = le32_to_cpu(*secdata++);   /* service */
        seclen -= 5 * 4;

        CDEBUG(D_SEC, "wire gss_hdr: %u/%u/%u/%u/%u\n",
               version, subflavor, gc->gc_proc, gc->gc_seq, gc->gc_svc);

        if (version != PTLRPC_SEC_GSS_VERSION) {
                CERROR("gss version mismatch: %d - %d\n",
                        version, PTLRPC_SEC_GSS_VERSION);
                GOTO(err_free, rc = SVC_DROP);
        }

        if (rawobj_extract(&gc->gc_ctx, &secdata, &seclen)) {
                CERROR("fail to obtain gss context handle\n");
                GOTO(err_free, rc = SVC_DROP);
        }

        *res = PTLRPCS_BADVERF;
        switch(gc->gc_proc) {
        case RPC_GSS_PROC_INIT:
        case RPC_GSS_PROC_CONTINUE_INIT:
                rc = gss_svcsec_handle_init(req, gc, secdata, seclen, res);
                break;
        case RPC_GSS_PROC_DATA:
                rc = gss_svcsec_handle_data(req, gc, secdata, seclen, res);
                break;
        case RPC_GSS_PROC_DESTROY:
                rc = gss_svcsec_handle_destroy(req, gc, secdata, seclen, res);
                break;
        default:
                rc = SVC_DROP;
                LBUG();
        }

err_free:
        if (rc == SVC_DROP && req->rq_sec_svcdata) {
                OBD_FREE(req->rq_sec_svcdata, sizeof(struct gss_svc_data));
                req->rq_sec_svcdata = NULL;
        }

        RETURN(rc);
}

static int
gss_svcsec_authorize(struct ptlrpc_request *req)
{
        struct ptlrpc_reply_state *rs = req->rq_reply_state;
        struct gss_svc_data *gsd = (struct gss_svc_data *)req->rq_sec_svcdata;
        struct rpc_gss_wire_cred  *gc = &gsd->clcred;
        struct rsc                *rscp;
        struct ptlrpcs_wire_hdr   *sec_hdr;
        rawobj_buf_t               msg_buf;
        rawobj_t                   cipher_buf;
        __u32                     *vp, *vpsave, major, vlen, seclen;
        rawobj_t                   lmsg, mic;
        int                        ret;
        ENTRY;

        LASSERT(rs);
        LASSERT(rs->rs_repbuf);
        LASSERT(gsd);

        if (gsd->is_init || gsd->is_init_continue ||
            gsd->is_err_notify || gsd->is_fini) {
                /* nothing to do in these cases */
                CDEBUG(D_SEC, "req %p: init/fini/err\n", req);
                RETURN(0);
        }

        if (gc->gc_proc != RPC_GSS_PROC_DATA) {
                CERROR("proc %d not support\n", gc->gc_proc);
                RETURN(-EINVAL);
        }

        rscp = gss_svc_searchbyctx(&gc->gc_ctx);
        if (!rscp) {
                CERROR("ctx disapeared under us?\n");
                RETURN(-EINVAL);
        }

        sec_hdr = (struct ptlrpcs_wire_hdr *) rs->rs_repbuf;
        switch (gc->gc_svc) {
        case  PTLRPC_GSS_SVC_INTEGRITY:
                /* prepare various pointers */
                lmsg.len = req->rq_replen;
                lmsg.data = (__u8 *) (rs->rs_repbuf + sizeof(*sec_hdr));
                vp = (__u32 *) (lmsg.data + lmsg.len);
                vlen = rs->rs_repbuf_len - sizeof(*sec_hdr) - lmsg.len;
                seclen = vlen;

                sec_hdr->flavor = cpu_to_le32(PTLRPC_SEC_GSS);
                sec_hdr->sectype = cpu_to_le32(PTLRPC_SEC_TYPE_AUTH);
                sec_hdr->msg_len = cpu_to_le32(req->rq_replen);

                /* standard gss hdr */
                LASSERT(vlen >= 7 * 4);
                *vp++ = cpu_to_le32(PTLRPC_SEC_GSS_VERSION);
                *vp++ = cpu_to_le32(PTLRPC_SEC_GSS_KRB5I);
                *vp++ = cpu_to_le32(RPC_GSS_PROC_DATA);
                *vp++ = cpu_to_le32(gc->gc_seq);
                *vp++ = cpu_to_le32(PTLRPC_GSS_SVC_INTEGRITY);
                *vp++ = 0;      /* fake ctx handle */
                vpsave = vp++;  /* reserve size */
                vlen -= 7 * 4;

                mic.len = vlen;
                mic.data = (unsigned char *)vp;

                major = kgss_get_mic(rscp->mechctx, 0, &lmsg, &mic);
                if (major) {
                        CERROR("fail to get MIC: 0x%x\n", major);
                        GOTO(out, ret = -EINVAL);
                }
                *vpsave = cpu_to_le32(mic.len);
                seclen = seclen - vlen + mic.len;
                sec_hdr->sec_len = cpu_to_le32(seclen);
                rs->rs_repdata_len += size_round(seclen);
                break;
        case  PTLRPC_GSS_SVC_PRIVACY:
                vp = (__u32 *) (rs->rs_repbuf + sizeof(*sec_hdr));
                vlen = rs->rs_repbuf_len - sizeof(*sec_hdr);
                seclen = vlen;

                sec_hdr->flavor = cpu_to_le32(PTLRPC_SEC_GSS);
                sec_hdr->sectype = cpu_to_le32(PTLRPC_SEC_TYPE_PRIV);
                sec_hdr->msg_len = cpu_to_le32(0);

                /* standard gss hdr */
                LASSERT(vlen >= 7 * 4);
                *vp++ = cpu_to_le32(PTLRPC_SEC_GSS_VERSION);
                *vp++ = cpu_to_le32(PTLRPC_SEC_GSS_KRB5I);
                *vp++ = cpu_to_le32(RPC_GSS_PROC_DATA);
                *vp++ = cpu_to_le32(gc->gc_seq);
                *vp++ = cpu_to_le32(PTLRPC_GSS_SVC_PRIVACY);
                *vp++ = 0;      /* fake ctx handle */
                vpsave = vp++;  /* reserve size */
                vlen -= 7 * 4;

                msg_buf.buf = (__u8 *) rs->rs_msg - GSS_PRIVBUF_PREFIX_LEN;
                msg_buf.buflen = req->rq_replen + GSS_PRIVBUF_PREFIX_LEN +
                                 GSS_PRIVBUF_SUFFIX_LEN;
                msg_buf.dataoff = GSS_PRIVBUF_PREFIX_LEN;
                msg_buf.datalen = req->rq_replen;

                cipher_buf.data = (__u8 *) vp;
                cipher_buf.len = vlen;

                major = kgss_wrap(rscp->mechctx, GSS_C_QOP_DEFAULT,
                                &msg_buf, &cipher_buf);
                if (major) {
                        CERROR("failed to wrap: 0x%x\n", major);
                        GOTO(out, ret = -EINVAL);
                }

                *vpsave = cpu_to_le32(cipher_buf.len);
                seclen = seclen - vlen + cipher_buf.len;
                sec_hdr->sec_len = cpu_to_le32(seclen);
                rs->rs_repdata_len += size_round(seclen);
                break;
        default:
                CERROR("Unknown service %d\n", gc->gc_svc);
                GOTO(out, ret = -EINVAL);
        }
        ret = 0;
out:
        rsc_put(&rscp->h, &rsc_cache);

        RETURN(ret);
}

static
void gss_svcsec_cleanup_req(struct ptlrpc_svcsec *svcsec,
                            struct ptlrpc_request *req)
{
        struct gss_svc_data *gsd = (struct gss_svc_data *) req->rq_sec_svcdata;

        if (!gsd) {
                CDEBUG(D_SEC, "no svc_data present. do nothing\n");
                return;
        }

        /* gsd->clclred.gc_ctx is NOT allocated, just set pointer
         * to the incoming packet buffer, so don't need free it
         */
        OBD_FREE(gsd, sizeof(*gsd));
        req->rq_sec_svcdata = NULL;
        return;
}

static
int gss_svcsec_est_payload(struct ptlrpc_svcsec *svcsec,
                           struct ptlrpc_request *req,
                           int msgsize)
{
        struct gss_svc_data *svcdata = req->rq_sec_svcdata;
        ENTRY;

        /* just return the pre-set reserve_len for init/fini/err cases.
         */
        LASSERT(svcdata);
        if (svcdata->is_init) {
                CDEBUG(D_SEC, "is_init, reserver size %d(%d)\n",
                       size_round(svcdata->reserve_len),
                       svcdata->reserve_len);
                LASSERT(svcdata->reserve_len);
                LASSERT(svcdata->reserve_len % 4 == 0);
                RETURN(size_round(svcdata->reserve_len));
        } else if (svcdata->is_err_notify) {
                CDEBUG(D_SEC, "is_err_notify, reserver size %d(%d)\n",
                       size_round(svcdata->reserve_len),
                       svcdata->reserve_len);
                RETURN(size_round(svcdata->reserve_len));
        } else if (svcdata->is_fini) {
                CDEBUG(D_SEC, "is_fini, reserver size 0\n");
                RETURN(0);
        } else {
                if (svcdata->clcred.gc_svc == PTLRPC_GSS_SVC_NONE ||
                    svcdata->clcred.gc_svc == PTLRPC_GSS_SVC_INTEGRITY)
                        RETURN(size_round(GSS_MAX_AUTH_PAYLOAD));
                else if (svcdata->clcred.gc_svc == PTLRPC_GSS_SVC_PRIVACY)
                        RETURN(size_round16(GSS_MAX_AUTH_PAYLOAD + msgsize +
                                            GSS_PRIVBUF_PREFIX_LEN +
                                            GSS_PRIVBUF_SUFFIX_LEN));
                else {
                        CERROR("unknown gss svc %u\n", svcdata->clcred.gc_svc);
                        *((int *)0) = 0;
                        LBUG();
                }
        }
        RETURN(0);
}

int gss_svcsec_alloc_repbuf(struct ptlrpc_svcsec *svcsec,
                            struct ptlrpc_request *req,
                            int msgsize)
{
        struct gss_svc_data *gsd = (struct gss_svc_data *) req->rq_sec_svcdata;
        struct ptlrpc_reply_state *rs;
        int msg_payload, sec_payload;
        int privacy, rc;
        ENTRY;

        /* determine the security type: none/auth or priv, we have
         * different pack scheme for them.
         * init/fini/err will always be treated as none/auth.
         */
        LASSERT(gsd);
        if (!gsd->is_init && !gsd->is_init_continue &&
            !gsd->is_fini && !gsd->is_err_notify &&
            gsd->clcred.gc_svc == PTLRPC_GSS_SVC_PRIVACY)
                privacy = 1;
        else
                privacy = 0;

        msg_payload = privacy ? 0 : msgsize;
        sec_payload = gss_svcsec_est_payload(svcsec, req, msgsize);

        rc = svcsec_alloc_reply_state(req, msg_payload, sec_payload);
        if (rc)
                RETURN(rc);

        rs = req->rq_reply_state;
        LASSERT(rs);
        rs->rs_msg_len = msgsize;

        if (privacy) {
                /* we can choose to let msg simply point to the rear of the
                 * buffer, which lead to buffer overlap when doing encryption.
                 * usually it's ok and it indeed passed all existing tests.
                 * but not sure if there will be subtle problems in the future.
                 * so right now we choose to alloc another new buffer. we'll
                 * see how it works.
                 */
#if 0
                rs->rs_msg = (struct lustre_msg *)
                             (rs->rs_repbuf + rs->rs_repbuf_len -
                              msgsize - GSS_PRIVBUF_SUFFIX_LEN);
#endif
                char *msgbuf;

                msgsize += GSS_PRIVBUF_PREFIX_LEN + GSS_PRIVBUF_SUFFIX_LEN;
                OBD_ALLOC(msgbuf, msgsize);
                if (!msgbuf) {
                        CERROR("can't alloc %d\n", msgsize);
                        svcsec_free_reply_state(rs);
                        req->rq_reply_state = NULL;
                        RETURN(-ENOMEM);
                }
                rs->rs_msg = (struct lustre_msg *)
                                (msgbuf + GSS_PRIVBUF_PREFIX_LEN);
        }

        req->rq_repmsg = rs->rs_msg;

        RETURN(0);
}

static
void gss_svcsec_free_repbuf(struct ptlrpc_svcsec *svcsec,
                            struct ptlrpc_reply_state *rs)
{
        unsigned long p1 = (unsigned long) rs->rs_msg;
        unsigned long p2 = (unsigned long) rs->rs_buf;

        LASSERT(rs->rs_buf);
        LASSERT(rs->rs_msg);
        LASSERT(rs->rs_msg_len);

        if (p1 < p2 || p1 >= p2 + rs->rs_buf_len) {
                char *start = (char*) rs->rs_msg - GSS_PRIVBUF_PREFIX_LEN;
                int size = rs->rs_msg_len + GSS_PRIVBUF_PREFIX_LEN +
                           GSS_PRIVBUF_SUFFIX_LEN;
                OBD_FREE(start, size);
        }

        svcsec_free_reply_state(rs);
}

struct ptlrpc_svcsec svcsec_gss = {
        .pss_owner              = THIS_MODULE,
        .pss_name               = "GSS_SVCSEC",
        .pss_flavor             = {PTLRPC_SEC_GSS, 0},
        .accept                 = gss_svcsec_accept,
        .authorize              = gss_svcsec_authorize,
        .alloc_repbuf           = gss_svcsec_alloc_repbuf,
        .free_repbuf            = gss_svcsec_free_repbuf,
        .cleanup_req            = gss_svcsec_cleanup_req,
};

/* XXX hacking */
void lgss_svc_cache_purge_all(void)
{
        cache_purge(&rsi_cache);
        cache_purge(&rsc_cache);
}
EXPORT_SYMBOL(lgss_svc_cache_purge_all);

void lgss_svc_cache_flush(__u32 uid)
{
        rsc_flush(uid);
}
EXPORT_SYMBOL(lgss_svc_cache_flush);

int gss_svc_init(void)
{
        int rc;

        rc = svcsec_register(&svcsec_gss);
        if (!rc) {
                cache_register(&rsc_cache);
                cache_register(&rsi_cache);
        }
        return rc;
}

void gss_svc_exit(void)
{
        int rc;
        if ((rc = cache_unregister(&rsi_cache)))
                CERROR("unregister rsi cache: %d\n", rc);
        if ((rc = cache_unregister(&rsc_cache)))
                CERROR("unregister rsc cache: %d\n", rc);
        if ((rc = svcsec_unregister(&svcsec_gss)))
                CERROR("unregister svcsec_gss: %d\n", rc);
}
