/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004 - 2006, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 * linux/net/sunrpc/auth_gss.c
 *
 * RPCSEC_GSS client authentication.
 *
 *  Copyright (c) 2000 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Dug Song       <dugsong@monkey.org>
 *  Andy Adamson   <andros@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
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
#include <asm/atomic.h>
#else
#include <liblustre.h>
#endif

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

#include <linux/crypto.h>

/* pre-definition */
static struct ptlrpc_sec_policy gss_policy;
static struct ptlrpc_cli_ctx * gss_sec_create_ctx(struct ptlrpc_sec *sec,
                                                  struct vfs_cred *vcred);
static void gss_sec_destroy_ctx(struct ptlrpc_sec *sec,
                                struct ptlrpc_cli_ctx *ctx);
static __gss_mod_initialized = 0;
/********************************************
 * wire data swabber                        *
 ********************************************/

static
void gss_header_swabber(struct gss_header *ghdr)
{
        __swab32s(&ghdr->gh_version);
        __swab32s(&ghdr->gh_flags);
        __swab32s(&ghdr->gh_proc);
        __swab32s(&ghdr->gh_seq);
        __swab32s(&ghdr->gh_svc);
        __swab32s(&ghdr->gh_pad1);
        __swab32s(&ghdr->gh_pad2);
        __swab32s(&ghdr->gh_pad3);
        __swab32s(&ghdr->gh_handle.len);
}

struct gss_header *gss_swab_header(struct lustre_msg *msg, int segment)
{
        struct gss_header *ghdr;

        ghdr = lustre_swab_buf(msg, segment, sizeof(*ghdr),
                               gss_header_swabber);

        if (ghdr &&
            sizeof(*ghdr) + ghdr->gh_handle.len > msg->lm_buflens[segment]) {
                CERROR("gss header require length %d, now %d received\n",
                       sizeof(*ghdr) + ghdr->gh_handle.len,
                       msg->lm_buflens[segment]);
                return NULL;
        }

        return ghdr;
}

static
void gss_netobj_swabber(netobj_t *obj)
{
        __swab32s(&obj->len);
}

netobj_t *gss_swab_netobj(struct lustre_msg *msg, int segment)
{
        netobj_t  *obj;

        obj = lustre_swab_buf(msg, segment, sizeof(*obj), gss_netobj_swabber);
        if (obj && sizeof(*obj) + obj->len > msg->lm_buflens[segment]) {
                CERROR("netobj require length %d but only %d received\n",
                       sizeof(*obj) + obj->len, msg->lm_buflens[segment]);
                return NULL;
        }

        return obj;
}

/*
 * payload should be obtained from mechanism. but currently since we
 * only support kerberos, we could simply use fixed value.
 * krb5 header:         16
 * krb5 checksum:       20
 */
#define GSS_KRB5_INTEG_MAX_PAYLOAD      (40)

static inline
int gss_estimate_payload(struct gss_ctx *mechctx, int msgsize, int privacy)
{
        if (privacy) {
                /* we suppose max cipher block size is 16 bytes. here we
                 * add 16 for confounder and 16 for padding.
                 */
                return GSS_KRB5_INTEG_MAX_PAYLOAD + msgsize + 16 + 16 + 16;
        } else {
                return GSS_KRB5_INTEG_MAX_PAYLOAD;
        }
}

/*
 * return signature size, otherwise < 0 to indicate error
 */
static
int gss_sign_msg(struct lustre_msg *msg,
                 struct gss_ctx *mechctx,
                 __u32 proc, __u32 seq,
                 rawobj_t *handle)
{
        struct gss_header      *ghdr;
        rawobj_t                text[3], mic;
        int                     textcnt, mic_idx = msg->lm_bufcount - 1;
        __u32                   major;

        LASSERT(msg->lm_bufcount >= 3);

        /* gss hdr */
        LASSERT(msg->lm_buflens[0] >=
                sizeof(*ghdr) + (handle ? handle->len : 0));
        ghdr = lustre_msg_buf(msg, 0, 0);

        ghdr->gh_version = PTLRPC_GSS_VERSION;
        ghdr->gh_flags = 0;
        ghdr->gh_proc = proc;
        ghdr->gh_seq = seq;
        ghdr->gh_svc = PTLRPC_GSS_SVC_INTEGRITY;
        if (!handle) {
                /* fill in a fake one */
                ghdr->gh_handle.len = 0;
        } else {
                ghdr->gh_handle.len = handle->len;
                memcpy(ghdr->gh_handle.data, handle->data, handle->len);
        }

        /* MIC */
        for (textcnt = 0; textcnt < mic_idx; textcnt++) {
                text[textcnt].len = msg->lm_buflens[textcnt];
                text[textcnt].data = lustre_msg_buf(msg, textcnt, 0);
        }

        mic.len = msg->lm_buflens[mic_idx];
        mic.data = lustre_msg_buf(msg, mic_idx, 0);

        major = lgss_get_mic(mechctx, textcnt, text, &mic);
        if (major != GSS_S_COMPLETE) {
                CERROR("fail to generate MIC: %08x\n", major);
                return -EPERM;
        }
        LASSERT(mic.len <= msg->lm_buflens[mic_idx]);

        return lustre_shrink_msg(msg, mic_idx, mic.len, 0);
}

/*
 * return gss error
 */
static
__u32 gss_verify_msg(struct lustre_msg *msg,
                   struct gss_ctx *mechctx)
{
        rawobj_t         text[3];
        rawobj_t         mic;
        int              textcnt, mic_idx = msg->lm_bufcount - 1;
        __u32            major;

        for (textcnt = 0; textcnt < mic_idx; textcnt++) {
                text[textcnt].len = msg->lm_buflens[textcnt];
                text[textcnt].data = lustre_msg_buf(msg, textcnt, 0);
        }

        mic.len = msg->lm_buflens[mic_idx];
        mic.data = lustre_msg_buf(msg, mic_idx, 0);

        major = lgss_verify_mic(mechctx, textcnt, text, &mic);
        if (major != GSS_S_COMPLETE)
                CERROR("mic verify error: %08x\n", major);

        return major;
}

/*
 * return gss error code
 */
static
__u32 gss_unseal_msg(struct gss_ctx *mechctx,
                   struct lustre_msg *msgbuf,
                   int *msg_len, int msgbuf_len)
{
        rawobj_t                 clear_obj, micobj, msgobj, token;
        __u8                    *clear_buf;
        int                      clear_buflen;
        __u32                    major;
        ENTRY;

        if (msgbuf->lm_bufcount != 3) {
                CERROR("invalid bufcount %d\n", msgbuf->lm_bufcount);
                RETURN(GSS_S_FAILURE);
        }

        /* verify gss header */
        msgobj.len = msgbuf->lm_buflens[0];
        msgobj.data = lustre_msg_buf(msgbuf, 0, 0);
        micobj.len = msgbuf->lm_buflens[1];
        micobj.data = lustre_msg_buf(msgbuf, 1, 0);

        major = lgss_verify_mic(mechctx, 1, &msgobj, &micobj);
        if (major != GSS_S_COMPLETE) {
                CERROR("priv: mic verify error: %08x\n", major);
                RETURN(major);
        }

        /* temporary clear text buffer */
        clear_buflen = msgbuf->lm_buflens[2];
        OBD_ALLOC(clear_buf, clear_buflen);
        if (!clear_buf)
                RETURN(GSS_S_FAILURE);

        token.len = msgbuf->lm_buflens[2];
        token.data = lustre_msg_buf(msgbuf, 2, 0);

        clear_obj.len = clear_buflen;
        clear_obj.data = clear_buf;

        major = lgss_unwrap(mechctx, &token, &clear_obj);
        if (major != GSS_S_COMPLETE) {
                CERROR("priv: unwrap message error: %08x\n", major);
                GOTO(out_free, major = GSS_S_FAILURE);
        }
        LASSERT(clear_obj.len <= clear_buflen);

        /* now the decrypted message */
        memcpy(msgbuf, clear_obj.data, clear_obj.len);
        *msg_len = clear_obj.len;

        major = GSS_S_COMPLETE;
out_free:
        OBD_FREE(clear_buf, clear_buflen);
        RETURN(major);
}

/********************************************
 * gss client context manipulation helpers  *
 ********************************************/

void gss_cli_ctx_uptodate(struct gss_cli_ctx *gctx)
{
        struct ptlrpc_cli_ctx *ctx = &gctx->gc_base;
        unsigned long ctx_expiry;

        if (lgss_inquire_context(gctx->gc_mechctx, &ctx_expiry)) {
                CERROR("ctx %p(%u): unable to inquire, expire it now\n",
                       gctx, ctx->cc_vcred.vc_uid);
                ctx_expiry = 1; /* make it expired now */
        }

        ctx->cc_expire = gss_round_ctx_expiry(ctx_expiry,
                                              ctx->cc_sec->ps_flags);

        /* At this point this ctx might have been marked as dead by
         * someone else, in which case nobody will make further use
         * of it. we don't care, and mark it UPTODATE will help
         * destroying server side context when it be destroied.
         */
        set_bit(PTLRPC_CTX_UPTODATE_BIT, &ctx->cc_flags);

        CWARN("%s ctx %p(%u->%s), will expire at %lu(%lds lifetime)\n",
              (ctx->cc_sec->ps_flags & PTLRPC_SEC_FL_REVERSE ?
               "server installed reverse" : "client refreshed"),
              ctx, ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec),
              ctx->cc_expire, (long) (ctx->cc_expire - get_seconds()));
}

static
void gss_cli_ctx_finalize(struct gss_cli_ctx *gctx)
{
        if (gctx->gc_mechctx)
                lgss_delete_sec_context(&gctx->gc_mechctx);

        rawobj_free(&gctx->gc_handle);
}

/*
 * Based on sequence number algorithm as specified in RFC 2203.
 *
 * modified for our own problem: arriving request has valid sequence number,
 * but unwrapping request might cost a long time, after that its sequence
 * are not valid anymore (fall behind the window). It rarely happen, mostly
 * under extreme load.
 *
 * note we should not check sequence before verify the integrity of incoming
 * request, because just one attacking request with high sequence number might
 * cause all following request be dropped.
 *
 * so here we use a multi-phase approach: prepare 2 sequence windows,
 * "main window" for normal sequence and "back window" for fall behind sequence.
 * and 3-phase checking mechanism:
 *  0 - before integrity verification, perform a initial sequence checking in
 *      main window, which only try and don't actually set any bits. if the
 *      sequence is high above the window or fit in the window and the bit
 *      is 0, then accept and proceed to integrity verification. otherwise
 *      reject this sequence.
 *  1 - after integrity verification, check in main window again. if this
 *      sequence is high above the window or fit in the window and the bit
 *      is 0, then set the bit and accept; if it fit in the window but bit
 *      already set, then reject; if it fall behind the window, then proceed
 *      to phase 2.
 *  2 - check in back window. if it is high above the window or fit in the
 *      window and the bit is 0, then set the bit and accept. otherwise reject.
 *
 * return value:
 *   1: looks like a replay
 *   0: is ok
 *  -1: is a replay
 *
 * note phase 0 is necessary, because otherwise replay attacking request of
 * sequence which between the 2 windows can't be detected.
 *
 * this mechanism can't totally solve the problem, but could help much less
 * number of valid requests be dropped.
 */
static
int gss_do_check_seq(unsigned long *window, __u32 win_size, __u32 *max_seq,
                     __u32 seq_num, int phase)
{
        LASSERT(phase >= 0 && phase <= 2);

        if (seq_num > *max_seq) {
                /*
                 * 1. high above the window
                 */
                if (phase == 0)
                        return 0;

                if (seq_num >= *max_seq + win_size) {
                        memset(window, 0, win_size / 8);
                        *max_seq = seq_num;
                } else {
                        while(*max_seq < seq_num) {
                                (*max_seq)++;
                                __clear_bit((*max_seq) % win_size, window);
                        }
                }
                __set_bit(seq_num % win_size, window);
        } else if (seq_num + win_size <= *max_seq) {
                /*
                 * 2. low behind the window
                 */
                if (phase == 0 || phase == 2)
                        goto replay;

                CWARN("seq %u is %u behind (size %d), check backup window\n",
                      seq_num, *max_seq - win_size - seq_num, win_size);
                return 1;
        } else {
                /*
                 * 3. fit into the window
                 */
                switch (phase) {
                case 0:
                        if (test_bit(seq_num % win_size, window))
                                goto replay;
                        break;
                case 1:
                case 2:
                     if (__test_and_set_bit(seq_num % win_size, window))
                                goto replay;
                        break;
                }
        }

        return 0;

replay:
        CERROR("seq %u (%s %s window) is a replay: max %u, winsize %d\n",
               seq_num,
               seq_num + win_size > *max_seq ? "in" : "behind",
               phase == 2 ? "backup " : "main",
               *max_seq, win_size);
        return -1;
}

/*
 * Based on sequence number algorithm as specified in RFC 2203.
 *
 * if @set == 0: initial check, don't set any bit in window
 * if @sec == 1: final check, set bit in window
 */
int gss_check_seq_num(struct gss_svc_seq_data *ssd, __u32 seq_num, int set)
{
        int rc = 0;

        spin_lock(&ssd->ssd_lock);

        if (set == 0) {
                /*
                 * phase 0 testing
                 */
                rc = gss_do_check_seq(ssd->ssd_win_main, GSS_SEQ_WIN_MAIN,
                                      &ssd->ssd_max_main, seq_num, 0);
                if (unlikely(rc))
                        gss_stat_oos_record_svc(0, 1);
        } else {
                /*
                 * phase 1 checking main window
                 */
                rc = gss_do_check_seq(ssd->ssd_win_main, GSS_SEQ_WIN_MAIN,
                                      &ssd->ssd_max_main, seq_num, 1);
                switch (rc) {
                case -1:
                        gss_stat_oos_record_svc(1, 1);
                        /* fall through */
                case 0:
                        goto exit;
                }
                /*
                 * phase 2 checking back window
                 */
                rc = gss_do_check_seq(ssd->ssd_win_back, GSS_SEQ_WIN_BACK,
                                      &ssd->ssd_max_back, seq_num, 2);
                if (rc)
                        gss_stat_oos_record_svc(2, 1);
                else
                        gss_stat_oos_record_svc(2, 0);
        }
exit:
        spin_unlock(&ssd->ssd_lock);
        return rc;
}

/***************************************
 * cred APIs                           *
 ***************************************/

static inline
int gss_cli_payload(struct ptlrpc_cli_ctx *ctx,
                    int msgsize, int privacy)
{
        return gss_estimate_payload(NULL, msgsize, privacy);
}

static
int gss_cli_ctx_refresh(struct ptlrpc_cli_ctx *ctx)
{
        /* if we are refreshing for root, also update the reverse
         * handle index, do not confuse reverse contexts.
         */
        if (ctx->cc_vcred.vc_uid == 0) {
                struct gss_sec *gsec;

                gsec = container_of(ctx->cc_sec, struct gss_sec, gs_base);
                gsec->gs_rvs_hdl = gss_get_next_ctx_index();
        }

        return gss_ctx_refresh_pipefs(ctx);
}

static
int gss_cli_ctx_match(struct ptlrpc_cli_ctx *ctx, struct vfs_cred *vcred)
{
        return (ctx->cc_vcred.vc_pag == vcred->vc_pag);
}

static
void gss_cli_ctx_flags2str(unsigned long flags, char *buf, int bufsize)
{
        buf[0] = '\0';

        if (flags & PTLRPC_CTX_UPTODATE)
                strncat(buf, "uptodate,", bufsize);
        if (flags & PTLRPC_CTX_DEAD)
                strncat(buf, "dead,", bufsize);
        if (flags & PTLRPC_CTX_ERROR)
                strncat(buf, "error,", bufsize);
        if (flags & PTLRPC_CTX_HASHED)
                strncat(buf, "hashed,", bufsize);
        if (flags & PTLRPC_CTX_ETERNAL)
                strncat(buf, "eternal,", bufsize);
        if (buf[0] == '\0')
                strncat(buf, "-,", bufsize);

        buf[strlen(buf) - 1] = '\0';
}

static
int gss_cli_ctx_display(struct ptlrpc_cli_ctx *ctx, char *buf, int bufsize)
{
        struct gss_cli_ctx     *gctx;
        char                    flags_str[40];
        int                     written;

        gctx = container_of(ctx, struct gss_cli_ctx, gc_base);

        gss_cli_ctx_flags2str(ctx->cc_flags, flags_str, sizeof(flags_str));

        written = snprintf(buf, bufsize,
                        "UID %d:\n" 
                        "  flags:       %s\n"
                        "  seqwin:      %d\n"
                        "  sequence:    %d\n",
                        ctx->cc_vcred.vc_uid,
                        flags_str,
                        gctx->gc_win,
                        atomic_read(&gctx->gc_seq));

        if (gctx->gc_mechctx) {
                written += lgss_display(gctx->gc_mechctx,
                                        buf + written, bufsize - written);
        }

        return written;
}

static
int gss_cli_ctx_sign(struct ptlrpc_cli_ctx *ctx,
                     struct ptlrpc_request *req)
{
        struct gss_cli_ctx      *gctx;
        __u32                    seq;
        int                      rc;
        ENTRY;

        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_reqbuf->lm_bufcount >= 3);
        LASSERT(req->rq_cli_ctx == ctx);

        /* nothing to do for context negotiation RPCs */
        if (req->rq_ctx_init)
                RETURN(0);

        gctx = container_of(ctx, struct gss_cli_ctx, gc_base);
redo:
        seq = atomic_inc_return(&gctx->gc_seq);

        rc = gss_sign_msg(req->rq_reqbuf, gctx->gc_mechctx,
                          gctx->gc_proc, seq, &gctx->gc_handle);
        if (rc < 0)
                RETURN(rc);

        /* gss_sign_msg() msg might take long time to finish, in which period
         * more rpcs could be wrapped up and sent out. if we found too many
         * of them we should repack this rpc, because sent it too late might
         * lead to the sequence number fall behind the window on server and
         * be dropped. also applies to gss_cli_ctx_seal().
         */
        if (atomic_read(&gctx->gc_seq) - seq > GSS_SEQ_REPACK_THRESHOLD) {
                int behind = atomic_read(&gctx->gc_seq) - seq;

                gss_stat_oos_record_cli(behind);
                CWARN("req %p: %u behind, retry signing\n", req, behind);
                goto redo;
        }

        req->rq_reqdata_len = rc;
        RETURN(0);
}

static
int gss_cli_ctx_handle_err_notify(struct ptlrpc_cli_ctx *ctx,
                                  struct ptlrpc_request *req,
                                  struct gss_header *ghdr)
{
        struct gss_err_header *errhdr;
        int rc;

        LASSERT(ghdr->gh_proc == PTLRPC_GSS_PROC_ERR);

        errhdr = (struct gss_err_header *) ghdr;

        /* server return NO_CONTEXT might be caused by context expire
         * or server reboot/failover. we refresh the cred transparently
         * to upper layer.
         * In some cases, our gss handle is possible to be incidentally
         * identical to another handle since the handle itself is not
         * fully random. In krb5 case, the GSS_S_BAD_SIG will be
         * returned, maybe other gss error for other mechanism.
         *
         * if we add new mechanism, make sure the correct error are
         * returned in this case.
         *
         * but in any cases, don't resend ctx destroying rpc, don't resend
         * reverse rpc.
         */
        if (req->rq_ctx_fini) {
                CWARN("server respond error (%08x/%08x) for ctx fini\n",
                      errhdr->gh_major, errhdr->gh_minor);
                rc = -EINVAL;
        } else if (ctx->cc_sec->ps_flags & PTLRPC_SEC_FL_REVERSE) {
                CWARN("reverse server respond error (%08x/%08x)\n",
                      errhdr->gh_major, errhdr->gh_minor);
                rc = -EINVAL;
        } else if (errhdr->gh_major == GSS_S_NO_CONTEXT ||
                   errhdr->gh_major == GSS_S_BAD_SIG) {
                CWARN("req x"LPU64"/t"LPU64": server respond ctx %p(%u->%s) "
                      "%s, server might lost the context.\n",
                      req->rq_xid, req->rq_transno, ctx, ctx->cc_vcred.vc_uid,
                      sec2target_str(ctx->cc_sec),
                      errhdr->gh_major == GSS_S_NO_CONTEXT ?
                      "NO_CONTEXT" : "BAD_SIG");

                sptlrpc_ctx_expire(ctx);
                req->rq_resend = 1;
                rc = 0;
        } else {
                CERROR("req %p: server report gss error (%x/%x)\n",
                        req, errhdr->gh_major, errhdr->gh_minor);
                rc = -EACCES;
        }

        return rc;
}

static
int gss_cli_ctx_verify(struct ptlrpc_cli_ctx *ctx,
                       struct ptlrpc_request *req)
{
        struct gss_cli_ctx     *gctx;
        struct gss_header      *ghdr, *reqhdr;
        struct lustre_msg      *msg = req->rq_repbuf;
        __u32                   major;
        int                     rc = 0;
        ENTRY;

        LASSERT(req->rq_cli_ctx == ctx);
        LASSERT(msg);

        req->rq_repdata_len = req->rq_nob_received;
        gctx = container_of(ctx, struct gss_cli_ctx, gc_base);

        /* special case for context negotiation, rq_repmsg/rq_replen actually
         * are not used currently.
         */
        if (req->rq_ctx_init) {
                req->rq_repmsg = lustre_msg_buf(msg, 1, 0);
                req->rq_replen = msg->lm_buflens[1];
                RETURN(0);
        }

        if (msg->lm_bufcount < 3 || msg->lm_bufcount > 4) {
                CERROR("unexpected bufcount %u\n", msg->lm_bufcount);
                RETURN(-EPROTO);
        }

        ghdr = gss_swab_header(msg, 0);
        if (ghdr == NULL) {
                CERROR("can't decode gss header\n");
                RETURN(-EPROTO);
        }

        /* sanity checks */
        reqhdr = lustre_msg_buf(msg, 0, sizeof(*reqhdr));
        LASSERT(reqhdr);

        if (ghdr->gh_version != reqhdr->gh_version) {
                CERROR("gss version %u mismatch, expect %u\n",
                       ghdr->gh_version, reqhdr->gh_version);
                RETURN(-EPROTO);
        }

        switch (ghdr->gh_proc) {
        case PTLRPC_GSS_PROC_DATA:
                if (ghdr->gh_seq != reqhdr->gh_seq) {
                        CERROR("seqnum %u mismatch, expect %u\n",
                               ghdr->gh_seq, reqhdr->gh_seq);
                        RETURN(-EPROTO);
                }

                if (ghdr->gh_svc != PTLRPC_GSS_SVC_INTEGRITY) {
                        CERROR("unexpected svc %d\n", ghdr->gh_svc);
                        RETURN(-EPROTO);
                }

                if (lustre_msg_swabbed(msg))
                        gss_header_swabber(ghdr);

                major = gss_verify_msg(msg, gctx->gc_mechctx);
                if (major != GSS_S_COMPLETE)
                        RETURN(-EPERM);

                req->rq_repmsg = lustre_msg_buf(msg, 1, 0);
                req->rq_replen = msg->lm_buflens[1];

                if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                        if (msg->lm_bufcount < 4) {
                                CERROR("Invalid reply bufcount %u\n",
                                       msg->lm_bufcount);
                                RETURN(-EPROTO);
                        }

                        /* bulk checksum is the second last segment */
                        rc = bulk_sec_desc_unpack(msg, msg->lm_bufcount - 2);
                }
                break;
        case PTLRPC_GSS_PROC_ERR:
                rc = gss_cli_ctx_handle_err_notify(ctx, req, ghdr);
                break;
        default:
                CERROR("unknown gss proc %d\n", ghdr->gh_proc);
                rc = -EPROTO;
        }

        RETURN(rc);
}

static
int gss_cli_ctx_seal(struct ptlrpc_cli_ctx *ctx,
                     struct ptlrpc_request *req)
{
        struct gss_cli_ctx      *gctx;
        rawobj_t                 msgobj, cipher_obj, micobj;
        struct gss_header       *ghdr;
        int                      buflens[3], wiresize, rc;
        __u32                    major;
        ENTRY;

        LASSERT(req->rq_clrbuf);
        LASSERT(req->rq_cli_ctx == ctx);
        LASSERT(req->rq_reqlen);

        gctx = container_of(ctx, struct gss_cli_ctx, gc_base);

        /* close clear data length */
        req->rq_clrdata_len = lustre_msg_size_v2(req->rq_clrbuf->lm_bufcount,
                                                 req->rq_clrbuf->lm_buflens);

        /* calculate wire data length */
        buflens[0] = PTLRPC_GSS_HEADER_SIZE;
        buflens[1] = gss_cli_payload(&gctx->gc_base, buflens[0], 0);
        buflens[2] = gss_cli_payload(&gctx->gc_base, req->rq_clrdata_len, 1);
        wiresize = lustre_msg_size_v2(3, buflens);

        /* allocate wire buffer */
        if (req->rq_pool) {
                /* pre-allocated */
                LASSERT(req->rq_reqbuf);
                LASSERT(req->rq_reqbuf != req->rq_clrbuf);
                LASSERT(req->rq_reqbuf_len >= wiresize);
        } else {
                OBD_ALLOC(req->rq_reqbuf, wiresize);
                if (!req->rq_reqbuf)
                        RETURN(-ENOMEM);
                req->rq_reqbuf_len = wiresize;
        }

        lustre_init_msg_v2(req->rq_reqbuf, 3, buflens, NULL);
        req->rq_reqbuf->lm_secflvr = req->rq_sec_flavor;

        /* gss header */
        ghdr = lustre_msg_buf(req->rq_reqbuf, 0, 0);
        ghdr->gh_version = PTLRPC_GSS_VERSION;
        ghdr->gh_flags = 0;
        ghdr->gh_proc = gctx->gc_proc;
        ghdr->gh_seq = atomic_inc_return(&gctx->gc_seq);
        ghdr->gh_svc = PTLRPC_GSS_SVC_PRIVACY;
        ghdr->gh_handle.len = gctx->gc_handle.len;
        memcpy(ghdr->gh_handle.data, gctx->gc_handle.data, gctx->gc_handle.len);

redo:
        /* header signature */
        msgobj.len = req->rq_reqbuf->lm_buflens[0];
        msgobj.data = lustre_msg_buf(req->rq_reqbuf, 0, 0);
        micobj.len = req->rq_reqbuf->lm_buflens[1];
        micobj.data = lustre_msg_buf(req->rq_reqbuf, 1, 0);

        major = lgss_get_mic(gctx->gc_mechctx, 1, &msgobj, &micobj);
        if (major != GSS_S_COMPLETE) {
                CERROR("priv: sign message error: %08x\n", major);
                GOTO(err_free, rc = -EPERM);
        }
        /* perhaps shrink msg has potential problem in re-packing???
         * ship a little bit more data is fine.
        lustre_shrink_msg(req->rq_reqbuf, 1, micobj.len, 0);
         */

        /* clear text */
        msgobj.len = req->rq_clrdata_len;
        msgobj.data = (__u8 *) req->rq_clrbuf;

        /* cipher text */
        cipher_obj.len = req->rq_reqbuf->lm_buflens[2];
        cipher_obj.data = lustre_msg_buf(req->rq_reqbuf, 2, 0);

        major = lgss_wrap(gctx->gc_mechctx, &msgobj, req->rq_clrbuf_len,
                          &cipher_obj);
        if (major != GSS_S_COMPLETE) {
                CERROR("priv: wrap message error: %08x\n", major);
                GOTO(err_free, rc = -EPERM);
        }
        LASSERT(cipher_obj.len <= buflens[2]);

        /* see explain in gss_cli_ctx_sign() */
        if (atomic_read(&gctx->gc_seq) - ghdr->gh_seq >
            GSS_SEQ_REPACK_THRESHOLD) {
                int behind = atomic_read(&gctx->gc_seq) - ghdr->gh_seq;

                gss_stat_oos_record_cli(behind);
                CWARN("req %p: %u behind, retry sealing\n", req, behind);

                ghdr->gh_seq = atomic_inc_return(&gctx->gc_seq);
                goto redo;
        }

        /* now set the final wire data length */
        req->rq_reqdata_len = lustre_shrink_msg(req->rq_reqbuf, 2,
                                                cipher_obj.len, 0);

        RETURN(0);

err_free:
        if (!req->rq_pool) {
                OBD_FREE(req->rq_reqbuf, req->rq_reqbuf_len);
                req->rq_reqbuf = NULL;
                req->rq_reqbuf_len = 0;
        }
        RETURN(rc);
}

static
int gss_cli_ctx_unseal(struct ptlrpc_cli_ctx *ctx,
                       struct ptlrpc_request *req)
{
        struct gss_cli_ctx      *gctx;
        struct gss_header       *ghdr;
        int                      msglen, rc;
        __u32                    major;
        ENTRY;

        LASSERT(req->rq_repbuf);
        LASSERT(req->rq_cli_ctx == ctx);

        gctx = container_of(ctx, struct gss_cli_ctx, gc_base);

        ghdr = gss_swab_header(req->rq_repbuf, 0);
        if (ghdr == NULL) {
                CERROR("can't decode gss header\n");
                RETURN(-EPROTO);
        }

        /* sanity checks */
        if (ghdr->gh_version != PTLRPC_GSS_VERSION) {
                CERROR("gss version %u mismatch, expect %u\n",
                       ghdr->gh_version, PTLRPC_GSS_VERSION);
                RETURN(-EPROTO);
        }

        switch (ghdr->gh_proc) {
        case PTLRPC_GSS_PROC_DATA:
                if (lustre_msg_swabbed(req->rq_repbuf))
                        gss_header_swabber(ghdr);

                major = gss_unseal_msg(gctx->gc_mechctx, req->rq_repbuf,
                                       &msglen, req->rq_repbuf_len);
                if (major != GSS_S_COMPLETE) {
                        rc = -EPERM;
                        break;
                }

                if (lustre_unpack_msg(req->rq_repbuf, msglen)) {
                        CERROR("Failed to unpack after decryption\n");
                        RETURN(-EPROTO);
                }
                req->rq_repdata_len = msglen;

                if (req->rq_repbuf->lm_bufcount < 1) {
                        CERROR("Invalid reply buffer: empty\n");
                        RETURN(-EPROTO);
                }

                if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                        if (req->rq_repbuf->lm_bufcount < 2) {
                                CERROR("Too few request buffer segments %d\n",
                                       req->rq_repbuf->lm_bufcount);
                                RETURN(-EPROTO);
                        }

                        /* bulk checksum is the last segment */
                        if (bulk_sec_desc_unpack(req->rq_repbuf,
                                                 req->rq_repbuf->lm_bufcount-1))
                                RETURN(-EPROTO);
                }

                req->rq_repmsg = lustre_msg_buf(req->rq_repbuf, 0, 0);
                req->rq_replen = req->rq_repbuf->lm_buflens[0];

                rc = 0;
                break;
        case PTLRPC_GSS_PROC_ERR:
                rc = gss_cli_ctx_handle_err_notify(ctx, req, ghdr);
                break;
        default:
                CERROR("unexpected proc %d\n", ghdr->gh_proc);
                rc = -EPERM;
        }

        RETURN(rc);
}

static struct ptlrpc_ctx_ops gss_ctxops = {
        .refresh        = gss_cli_ctx_refresh,
        .match          = gss_cli_ctx_match,
        .display        = gss_cli_ctx_display,
        .sign           = gss_cli_ctx_sign,
        .verify         = gss_cli_ctx_verify,
        .seal           = gss_cli_ctx_seal,
        .unseal         = gss_cli_ctx_unseal,
        .wrap_bulk      = gss_cli_ctx_wrap_bulk,
        .unwrap_bulk    = gss_cli_ctx_unwrap_bulk,
};

/*********************************************
 * reverse context installation              *
 *********************************************/
static
int gss_install_rvs_cli_ctx(struct gss_sec *gsec,
                            struct ptlrpc_svc_ctx *svc_ctx)
{
        struct vfs_cred          vcred;
        struct gss_svc_reqctx   *grctx;
        struct ptlrpc_cli_ctx   *cli_ctx;
        struct gss_cli_ctx      *cli_gctx;
        struct gss_ctx          *mechctx = NULL;
        __u32                    major;
        int                      rc;
        ENTRY;

        vcred.vc_pag = 0;
        vcred.vc_uid = 0;
        vcred.vc_gid = 0;

        cli_ctx = gss_sec_create_ctx(&gsec->gs_base, &vcred);
        if (!cli_ctx)
                RETURN(-ENOMEM);

        grctx = container_of(svc_ctx, struct gss_svc_reqctx, src_base);
        LASSERT(grctx);
        LASSERT(grctx->src_ctx);
        LASSERT(grctx->src_ctx->gsc_mechctx);

        major = lgss_copy_reverse_context(grctx->src_ctx->gsc_mechctx, &mechctx);
        if (major != GSS_S_COMPLETE)
                GOTO(err_ctx, rc = -ENOMEM);

        cli_gctx = container_of(cli_ctx, struct gss_cli_ctx, gc_base);

        cli_gctx->gc_proc = PTLRPC_GSS_PROC_DATA;
        cli_gctx->gc_win = GSS_SEQ_WIN;
        atomic_set(&cli_gctx->gc_seq, 0);

        if (rawobj_dup(&cli_gctx->gc_handle, &grctx->src_ctx->gsc_rvs_hdl))
                GOTO(err_mechctx, rc = -ENOMEM);

        cli_gctx->gc_mechctx = mechctx;
        gss_cli_ctx_uptodate(cli_gctx);

        sptlrpc_ctx_replace(&gsec->gs_base, cli_ctx);
        RETURN(0);

err_mechctx:
        lgss_delete_sec_context(&mechctx);
err_ctx:
        gss_sec_destroy_ctx(cli_ctx->cc_sec, cli_ctx);
        return rc;
}


static inline
int gss_install_rvs_svc_ctx(struct obd_import *imp,
                            struct gss_sec *gsec,
                            struct gss_cli_ctx *gctx)
{
        return gss_svc_upcall_install_rvs_ctx(imp, gsec, gctx);
}

/*********************************************
 * GSS security APIs                         *
 *********************************************/

static
struct ptlrpc_cli_ctx * gss_sec_create_ctx(struct ptlrpc_sec *sec,
                                           struct vfs_cred *vcred)
{
        struct gss_cli_ctx    *gctx;
        struct ptlrpc_cli_ctx *ctx;
        ENTRY;

        OBD_ALLOC_PTR(gctx);
        if (!gctx)
                RETURN(NULL);

        gctx->gc_win = 0;
        atomic_set(&gctx->gc_seq, 0);

        ctx = &gctx->gc_base;
        INIT_HLIST_NODE(&ctx->cc_hash);
        atomic_set(&ctx->cc_refcount, 0);
        ctx->cc_sec = sec;
        ctx->cc_ops = &gss_ctxops;
        ctx->cc_expire = 0;
        ctx->cc_flags = 0;
        ctx->cc_vcred = *vcred;
        spin_lock_init(&ctx->cc_lock);
        INIT_LIST_HEAD(&ctx->cc_req_list);

        CDEBUG(D_SEC, "create a gss cred at %p(uid %u)\n", ctx, vcred->vc_uid);
        RETURN(ctx);
}

static
void gss_sec_destroy_ctx(struct ptlrpc_sec *sec, struct ptlrpc_cli_ctx *ctx)
{
        struct gss_cli_ctx *gctx;
        ENTRY;

        LASSERT(ctx);
        LASSERT(atomic_read(&ctx->cc_refcount) == 0);

        gctx = container_of(ctx, struct gss_cli_ctx, gc_base);
        if (gctx->gc_mechctx) {
                gss_do_ctx_fini_rpc(gctx);
                gss_cli_ctx_finalize(gctx);
        }

        CWARN("%s@%p: destroy ctx %p(%u->%s)\n",
              ctx->cc_sec->ps_policy->sp_name, ctx->cc_sec,
              ctx, ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec));

        OBD_FREE_PTR(gctx);
        EXIT;
}

#define GSS_CCACHE_SIZE         (32)

static
struct ptlrpc_sec* gss_sec_create(struct obd_import *imp,
                                  struct ptlrpc_svc_ctx *ctx,
                                  __u32 flavor,
                                  unsigned long flags)
{
        struct gss_sec      *gsec;
        struct ptlrpc_sec   *sec;
        int                  alloc_size, cache_size, i;
        ENTRY;

        LASSERT(imp);
        LASSERT(SEC_FLAVOR_POLICY(flavor) == SPTLRPC_POLICY_GSS);

        if (ctx || flags & (PTLRPC_SEC_FL_ROOTONLY | PTLRPC_SEC_FL_REVERSE))
                cache_size = 1;
        else
                cache_size = GSS_CCACHE_SIZE;

        alloc_size = sizeof(*gsec) + sizeof(struct list_head) * cache_size;

        OBD_ALLOC(gsec, alloc_size);
        if (!gsec)
                RETURN(NULL);

        gsec->gs_mech = lgss_subflavor_to_mech(SEC_FLAVOR_SUB(flavor));
        if (!gsec->gs_mech) {
                CERROR("gss backend 0x%x not found\n", SEC_FLAVOR_SUB(flavor));
                goto err_free;
        }

        spin_lock_init(&gsec->gs_lock);
        gsec->gs_rvs_hdl = 0ULL; /* will be updated later */

        sec = &gsec->gs_base;
        sec->ps_policy = &gss_policy;
        sec->ps_flavor = flavor;
        sec->ps_flags = flags;
        sec->ps_import = class_import_get(imp);
        sec->ps_lock = SPIN_LOCK_UNLOCKED;
        sec->ps_ccache_size = cache_size;
        sec->ps_ccache = (struct hlist_head *) (gsec + 1);
        atomic_set(&sec->ps_busy, 0);

        for (i = 0; i < cache_size; i++)
                INIT_HLIST_HEAD(&sec->ps_ccache[i]);

        if (!ctx) {
                if (gss_sec_upcall_init(gsec))
                        goto err_mech;

                sec->ps_gc_interval = 30 * 60; /* 30 minutes */
                sec->ps_gc_next = cfs_time_current_sec() + sec->ps_gc_interval;
        } else {
                LASSERT(sec->ps_flags & PTLRPC_SEC_FL_REVERSE);

                if (gss_install_rvs_cli_ctx(gsec, ctx))
                        goto err_mech;

                /* never do gc on reverse sec */
                sec->ps_gc_interval = 0;
                sec->ps_gc_next = 0;
        }

        if (SEC_FLAVOR_SVC(flavor) == SPTLRPC_SVC_PRIV &&
            flags & PTLRPC_SEC_FL_BULK)
                sptlrpc_enc_pool_add_user();

        CWARN("create %s%s@%p\n", (ctx ? "reverse " : ""),
              gss_policy.sp_name, gsec);
        RETURN(sec);

err_mech:
        lgss_mech_put(gsec->gs_mech);
err_free:
        OBD_FREE(gsec, alloc_size);
        RETURN(NULL);
}

static
void gss_sec_destroy(struct ptlrpc_sec *sec)
{
        struct gss_sec *gsec;
        ENTRY;

        gsec = container_of(sec, struct gss_sec, gs_base);
        CWARN("destroy %s@%p\n", gss_policy.sp_name, gsec);

        LASSERT(gsec->gs_mech);
        LASSERT(sec->ps_import);
        LASSERT(sec->ps_ccache);
        LASSERT(sec->ps_ccache_size);
        LASSERT(atomic_read(&sec->ps_refcount) == 0);
        LASSERT(atomic_read(&sec->ps_busy) == 0);

        gss_sec_upcall_cleanup(gsec);
        lgss_mech_put(gsec->gs_mech);

        class_import_put(sec->ps_import);

        if (SEC_FLAVOR_SVC(sec->ps_flavor) == SPTLRPC_SVC_PRIV &&
            sec->ps_flags & PTLRPC_SEC_FL_BULK)
                sptlrpc_enc_pool_del_user();

        OBD_FREE(gsec, sizeof(*gsec) +
                       sizeof(struct list_head) * sec->ps_ccache_size);
        EXIT;
}

static
int gss_alloc_reqbuf_auth(struct ptlrpc_sec *sec,
                          struct ptlrpc_request *req,
                          int msgsize)
{
        struct sec_flavor_config *conf;
        int bufsize, txtsize;
        int buflens[5], bufcnt = 2;
        ENTRY;

        /*
         * - gss header
         * - lustre message
         * - user descriptor
         * - bulk sec descriptor
         * - signature
         */
        buflens[0] = PTLRPC_GSS_HEADER_SIZE;
        buflens[1] = msgsize;
        txtsize = buflens[0] + buflens[1];

        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor)) {
                buflens[bufcnt] = sptlrpc_user_desc_size();
                txtsize += buflens[bufcnt];
                bufcnt++;
        }

        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                conf = &req->rq_import->imp_obd->u.cli.cl_sec_conf;
                buflens[bufcnt] = bulk_sec_desc_size(conf->sfc_bulk_csum, 1,
                                                     req->rq_bulk_read);
                txtsize += buflens[bufcnt];
                bufcnt++;
        }

        buflens[bufcnt++] = req->rq_ctx_init ? GSS_CTX_INIT_MAX_LEN :
                            gss_cli_payload(req->rq_cli_ctx, txtsize, 0);

        bufsize = lustre_msg_size_v2(bufcnt, buflens);

        if (!req->rq_reqbuf) {
                bufsize = size_roundup_power2(bufsize);

                OBD_ALLOC(req->rq_reqbuf, bufsize);
                if (!req->rq_reqbuf)
                        RETURN(-ENOMEM);

                req->rq_reqbuf_len = bufsize;
        } else {
                LASSERT(req->rq_pool);
                LASSERT(req->rq_reqbuf_len >= bufsize);
                memset(req->rq_reqbuf, 0, bufsize);
        }

        lustre_init_msg_v2(req->rq_reqbuf, bufcnt, buflens, NULL);
        req->rq_reqbuf->lm_secflvr = req->rq_sec_flavor;

        req->rq_reqmsg = lustre_msg_buf(req->rq_reqbuf, 1, msgsize);
        LASSERT(req->rq_reqmsg);

        /* pack user desc here, later we might leave current user's process */
        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor))
                sptlrpc_pack_user_desc(req->rq_reqbuf, 2);

        RETURN(0);
}

static
int gss_alloc_reqbuf_priv(struct ptlrpc_sec *sec,
                          struct ptlrpc_request *req,
                          int msgsize)
{
        struct sec_flavor_config *conf;
        int ibuflens[3], ibufcnt;
        int buflens[3];
        int clearsize, wiresize;
        ENTRY;

        LASSERT(req->rq_clrbuf == NULL);
        LASSERT(req->rq_clrbuf_len == 0);

        /* Inner (clear) buffers
         *  - lustre message
         *  - user descriptor
         *  - bulk checksum
         */
        ibufcnt = 1;
        ibuflens[0] = msgsize;

        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor))
                ibuflens[ibufcnt++] = sptlrpc_user_desc_size();
        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                conf = &req->rq_import->imp_obd->u.cli.cl_sec_conf;
                ibuflens[ibufcnt++] = bulk_sec_desc_size(conf->sfc_bulk_csum, 1,
                                                         req->rq_bulk_read);
        }
        clearsize = lustre_msg_size_v2(ibufcnt, ibuflens);
        /* to allow append padding during encryption */
        clearsize += GSS_MAX_CIPHER_BLOCK;

        /* Wrapper (wire) buffers
         *  - gss header
         *  - signature of gss header
         *  - cipher text
         */
        buflens[0] = PTLRPC_GSS_HEADER_SIZE;
        buflens[1] = gss_cli_payload(req->rq_cli_ctx, buflens[0], 0);
        buflens[2] = gss_cli_payload(req->rq_cli_ctx, clearsize, 1);
        wiresize = lustre_msg_size_v2(3, buflens);

        if (req->rq_pool) {
                /* rq_reqbuf is preallocated */
                LASSERT(req->rq_reqbuf);
                LASSERT(req->rq_reqbuf_len >= wiresize);

                memset(req->rq_reqbuf, 0, req->rq_reqbuf_len);

                /* if the pre-allocated buffer is big enough, we just pack
                 * both clear buf & request buf in it, to avoid more alloc.
                 */
                if (clearsize + wiresize <= req->rq_reqbuf_len) {
                        req->rq_clrbuf =
                                (void *) (((char *) req->rq_reqbuf) + wiresize);
                } else {
                        CWARN("pre-allocated buf size %d is not enough for "
                              "both clear (%d) and cipher (%d) text, proceed "
                              "with extra allocation\n", req->rq_reqbuf_len,
                              clearsize, wiresize);
                }
        }

        if (!req->rq_clrbuf) {
                clearsize = size_roundup_power2(clearsize);

                OBD_ALLOC(req->rq_clrbuf, clearsize);
                if (!req->rq_clrbuf)
                        RETURN(-ENOMEM);
        }
        req->rq_clrbuf_len = clearsize;

        lustre_init_msg_v2(req->rq_clrbuf, ibufcnt, ibuflens, NULL);
        req->rq_reqmsg = lustre_msg_buf(req->rq_clrbuf, 0, msgsize);

        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor))
                sptlrpc_pack_user_desc(req->rq_clrbuf, 1);

        RETURN(0);
}

/*
 * NOTE: any change of request buffer allocation should also consider
 * changing enlarge_reqbuf() series functions.
 */
static
int gss_alloc_reqbuf(struct ptlrpc_sec *sec,
                     struct ptlrpc_request *req,
                     int msgsize)
{
        LASSERT(!SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor) ||
                (req->rq_bulk_read || req->rq_bulk_write));

        switch (SEC_FLAVOR_SVC(req->rq_sec_flavor)) {
        case SPTLRPC_SVC_NONE:
        case SPTLRPC_SVC_AUTH:
                return gss_alloc_reqbuf_auth(sec, req, msgsize);
        case SPTLRPC_SVC_PRIV:
                return gss_alloc_reqbuf_priv(sec, req, msgsize);
        default:
                LBUG();
        }
        return 0;
}

static
void gss_free_reqbuf(struct ptlrpc_sec *sec,
                     struct ptlrpc_request *req)
{
        int privacy;
        ENTRY;

        LASSERT(!req->rq_pool || req->rq_reqbuf);
        privacy = SEC_FLAVOR_SVC(req->rq_sec_flavor) == SPTLRPC_SVC_PRIV;

        if (!req->rq_clrbuf)
                goto release_reqbuf;

        /* release clear buffer */
        LASSERT(privacy);
        LASSERT(req->rq_clrbuf_len);

        if (req->rq_pool &&
            req->rq_clrbuf >= req->rq_reqbuf &&
            (char *) req->rq_clrbuf <
            (char *) req->rq_reqbuf + req->rq_reqbuf_len)
                goto release_reqbuf;

        OBD_FREE(req->rq_clrbuf, req->rq_clrbuf_len);
        req->rq_clrbuf = NULL;
        req->rq_clrbuf_len = 0;

release_reqbuf:
        if (!req->rq_pool && req->rq_reqbuf) {
                OBD_FREE(req->rq_reqbuf, req->rq_reqbuf_len);
                req->rq_reqbuf = NULL;
                req->rq_reqbuf_len = 0;
        }

        EXIT;
}

static
int gss_alloc_repbuf(struct ptlrpc_sec *sec,
                     struct ptlrpc_request *req,
                     int msgsize)
{
        struct sec_flavor_config *conf;
        int privacy = (SEC_FLAVOR_SVC(req->rq_sec_flavor) == SPTLRPC_SVC_PRIV);
        int bufsize, txtsize;
        int buflens[4], bufcnt;
        ENTRY;

        LASSERT(!SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor) ||
                (req->rq_bulk_read || req->rq_bulk_write));

        if (privacy) {
                bufcnt = 1;
                buflens[0] = msgsize;
                if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                        conf = &req->rq_import->imp_obd->u.cli.cl_sec_conf;
                        buflens[bufcnt++] = bulk_sec_desc_size(
                                                        conf->sfc_bulk_csum, 0,
                                                        req->rq_bulk_read);
                }
                txtsize = lustre_msg_size_v2(bufcnt, buflens);
                txtsize += GSS_MAX_CIPHER_BLOCK;

                bufcnt = 3;
                buflens[0] = PTLRPC_GSS_HEADER_SIZE;
                buflens[1] = gss_cli_payload(req->rq_cli_ctx, buflens[0], 0);
                buflens[2] = gss_cli_payload(req->rq_cli_ctx, txtsize, 1);
        } else {
                bufcnt = 2;
                buflens[0] = PTLRPC_GSS_HEADER_SIZE;
                buflens[1] = msgsize;
                txtsize = buflens[0] + buflens[1];

                if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                        conf = &req->rq_import->imp_obd->u.cli.cl_sec_conf;
                        buflens[bufcnt] = bulk_sec_desc_size(
                                                        conf->sfc_bulk_csum, 0,
                                                        req->rq_bulk_read);
                        txtsize += buflens[bufcnt];
                        bufcnt++;
                }
                buflens[bufcnt++] = req->rq_ctx_init ? GSS_CTX_INIT_MAX_LEN :
                                   gss_cli_payload(req->rq_cli_ctx, txtsize, 0);
        }

        bufsize = lustre_msg_size_v2(bufcnt, buflens);
        bufsize = size_roundup_power2(bufsize);

        OBD_ALLOC(req->rq_repbuf, bufsize);
        if (!req->rq_repbuf)
                return -ENOMEM;

        req->rq_repbuf_len = bufsize;
        return 0;
}

static
void gss_free_repbuf(struct ptlrpc_sec *sec,
                     struct ptlrpc_request *req)
{
        OBD_FREE(req->rq_repbuf, req->rq_repbuf_len);
        req->rq_repbuf = NULL;
        req->rq_repbuf_len = 0;
}

static int get_enlarged_msgsize(struct lustre_msg *msg,
                                int segment, int newsize)
{
        int save, newmsg_size;

        LASSERT(newsize >= msg->lm_buflens[segment]);

        save = msg->lm_buflens[segment];
        msg->lm_buflens[segment] = newsize;
        newmsg_size = lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);
        msg->lm_buflens[segment] = save;

        return newmsg_size;
}

static int get_enlarged_msgsize2(struct lustre_msg *msg,
                                 int segment1, int newsize1,
                                 int segment2, int newsize2)
{
        int save1, save2, newmsg_size;

        LASSERT(newsize1 >= msg->lm_buflens[segment1]);
        LASSERT(newsize2 >= msg->lm_buflens[segment2]);

        save1 = msg->lm_buflens[segment1];
        save2 = msg->lm_buflens[segment2];
        msg->lm_buflens[segment1] = newsize1;
        msg->lm_buflens[segment2] = newsize2;
        newmsg_size = lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);
        msg->lm_buflens[segment1] = save1;
        msg->lm_buflens[segment2] = save2;

        return newmsg_size;
}

static inline int msg_last_seglen(struct lustre_msg *msg)
{
        return msg->lm_buflens[msg->lm_bufcount - 1];
}

static
int gss_enlarge_reqbuf_auth(struct ptlrpc_sec *sec,
                            struct ptlrpc_request *req,
                            int segment, int newsize)
{
        struct lustre_msg      *newbuf;
        int                     txtsize, sigsize, i;
        int                     newmsg_size, newbuf_size;

        /*
         * embedded msg is at seg 1; signature is at the last seg
         */
        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_reqbuf_len > req->rq_reqlen);
        LASSERT(req->rq_reqbuf->lm_bufcount >= 2);
        LASSERT(lustre_msg_buf(req->rq_reqbuf, 1, 0) == req->rq_reqmsg);

        /* compute new embedded msg size */
        newmsg_size = get_enlarged_msgsize(req->rq_reqmsg, segment, newsize);
        LASSERT(newmsg_size >= req->rq_reqbuf->lm_buflens[1]);

        /* compute new wrapper msg size */
        for (txtsize = 0, i = 0; i < req->rq_reqbuf->lm_bufcount; i++)
                txtsize += req->rq_reqbuf->lm_buflens[i];
        txtsize += newmsg_size - req->rq_reqbuf->lm_buflens[1];

        sigsize = gss_cli_payload(req->rq_cli_ctx, txtsize, 0);
        LASSERT(sigsize >= msg_last_seglen(req->rq_reqbuf));
        newbuf_size = get_enlarged_msgsize2(req->rq_reqbuf, 1, newmsg_size,
                                            req->rq_reqbuf->lm_bufcount - 1,
                                            sigsize);

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
                req->rq_reqmsg = lustre_msg_buf(req->rq_reqbuf, 1, 0);
        }

        _sptlrpc_enlarge_msg_inplace(req->rq_reqbuf,
                                     req->rq_reqbuf->lm_bufcount - 1, sigsize);
        _sptlrpc_enlarge_msg_inplace(req->rq_reqbuf, 1, newmsg_size);
        _sptlrpc_enlarge_msg_inplace(req->rq_reqmsg, segment, newsize);

        req->rq_reqlen = newmsg_size;
        RETURN(0);
}

static
int gss_enlarge_reqbuf_priv(struct ptlrpc_sec *sec,
                            struct ptlrpc_request *req,
                            int segment, int newsize)
{
        struct lustre_msg      *newclrbuf;
        int                     newmsg_size, newclrbuf_size, newcipbuf_size;
        int                     buflens[3];

        /*
         * embedded msg is at seg 0 of clear buffer;
         * cipher text is at seg 2 of cipher buffer;
         */
        LASSERT(req->rq_pool ||
                (req->rq_reqbuf == NULL && req->rq_reqbuf_len == 0));
        LASSERT(req->rq_reqbuf == NULL ||
                (req->rq_pool && req->rq_reqbuf->lm_bufcount == 3));
        LASSERT(req->rq_clrbuf);
        LASSERT(req->rq_clrbuf_len > req->rq_reqlen);
        LASSERT(lustre_msg_buf(req->rq_clrbuf, 0, 0) == req->rq_reqmsg);

        /* compute new embedded msg size */
        newmsg_size = get_enlarged_msgsize(req->rq_reqmsg, segment, newsize);

        /* compute new clear buffer size */
        newclrbuf_size = get_enlarged_msgsize(req->rq_clrbuf, 0, newmsg_size);
        newclrbuf_size += GSS_MAX_CIPHER_BLOCK;

        /* compute new cipher buffer size */
        buflens[0] = PTLRPC_GSS_HEADER_SIZE;
        buflens[1] = gss_cli_payload(req->rq_cli_ctx, buflens[0], 0);
        buflens[2] = gss_cli_payload(req->rq_cli_ctx, newclrbuf_size, 1);
        newcipbuf_size = lustre_msg_size_v2(3, buflens);

        /*
         * handle the case that we put both clear buf and cipher buf into
         * pre-allocated single buffer.
         */
        if (unlikely(req->rq_pool) &&
            req->rq_clrbuf >= req->rq_reqbuf &&
            (char *) req->rq_clrbuf <
            (char *) req->rq_reqbuf + req->rq_reqbuf_len) {
                /*
                 * it couldn't be better we still fit into the
                 * pre-allocated buffer.
                 */
                if (newclrbuf_size + newcipbuf_size <= req->rq_reqbuf_len) {
                        void *src, *dst;

                        /* move clear text backward. */
                        src = req->rq_clrbuf;
                        dst = (char *) req->rq_reqbuf + newcipbuf_size;

                        memmove(dst, src, req->rq_clrbuf_len);

                        req->rq_clrbuf = (struct lustre_msg *) dst;
                        req->rq_clrbuf_len = newclrbuf_size;
                        req->rq_reqmsg = lustre_msg_buf(req->rq_clrbuf, 0, 0);
                } else {
                        /*
                         * sadly we have to split out the clear buffer
                         */
                        LASSERT(req->rq_reqbuf_len >= newcipbuf_size);
                        LASSERT(req->rq_clrbuf_len < newclrbuf_size);
                }
        }

        if (req->rq_clrbuf_len < newclrbuf_size) {
                newclrbuf_size = size_roundup_power2(newclrbuf_size);

                OBD_ALLOC(newclrbuf, newclrbuf_size);
                if (newclrbuf == NULL)
                        RETURN(-ENOMEM);

                memcpy(newclrbuf, req->rq_clrbuf, req->rq_clrbuf_len);

                if (req->rq_reqbuf == NULL ||
                    req->rq_clrbuf < req->rq_reqbuf ||
                    (char *) req->rq_clrbuf >=
                    (char *) req->rq_reqbuf + req->rq_reqbuf_len) {
                        OBD_FREE(req->rq_clrbuf, req->rq_clrbuf_len);
                }

                req->rq_clrbuf = newclrbuf;
                req->rq_clrbuf_len = newclrbuf_size;
                req->rq_reqmsg = lustre_msg_buf(req->rq_clrbuf, 0, 0);
        }

        _sptlrpc_enlarge_msg_inplace(req->rq_clrbuf, 0, newmsg_size);
        _sptlrpc_enlarge_msg_inplace(req->rq_reqmsg, segment, newsize);
        req->rq_reqlen = newmsg_size;

        RETURN(0);
}

static
int gss_enlarge_reqbuf(struct ptlrpc_sec *sec,
                       struct ptlrpc_request *req,
                       int segment, int newsize)
{
        LASSERT(!req->rq_ctx_init && !req->rq_ctx_fini);

        switch (SEC_FLAVOR_SVC(req->rq_sec_flavor)) {
        case SPTLRPC_SVC_AUTH:
                return gss_enlarge_reqbuf_auth(sec, req, segment, newsize);
        case SPTLRPC_SVC_PRIV:
                return gss_enlarge_reqbuf_priv(sec, req, segment, newsize);
        default:
                LASSERTF(0, "bad flavor %x\n", req->rq_sec_flavor);
                return 0;
        }
}

static
int gss_sec_install_rctx(struct obd_import *imp,
                         struct ptlrpc_sec *sec,
                         struct ptlrpc_cli_ctx *ctx)
{
        struct gss_sec     *gsec;
        struct gss_cli_ctx *gctx;
        int                 rc;

        gsec = container_of(sec, struct gss_sec, gs_base);
        gctx = container_of(ctx, struct gss_cli_ctx, gc_base);

        rc = gss_install_rvs_svc_ctx(imp, gsec, gctx);
        return rc;
}

static struct ptlrpc_sec_cops gss_sec_cops = {
        .create_sec             = gss_sec_create,
        .destroy_sec            = gss_sec_destroy,
        .create_ctx             = gss_sec_create_ctx,
        .destroy_ctx            = gss_sec_destroy_ctx,
        .install_rctx           = gss_sec_install_rctx,
        .alloc_reqbuf           = gss_alloc_reqbuf,
        .free_reqbuf            = gss_free_reqbuf,
        .alloc_repbuf           = gss_alloc_repbuf,
        .free_repbuf            = gss_free_repbuf,
        .enlarge_reqbuf         = gss_enlarge_reqbuf,
};

/********************************************
 * server side API                          *
 ********************************************/

static inline
int gss_svc_reqctx_is_special(struct gss_svc_reqctx *grctx)
{
        LASSERT(grctx);
        return (grctx->src_init || grctx->src_init_continue ||
                grctx->src_err_notify);
}

static
void gss_svc_reqctx_free(struct gss_svc_reqctx *grctx)
{
        if (grctx->src_ctx)
                gss_svc_upcall_put_ctx(grctx->src_ctx);

        sptlrpc_policy_put(grctx->src_base.sc_policy);
        OBD_FREE_PTR(grctx);
}

static inline
void gss_svc_reqctx_addref(struct gss_svc_reqctx *grctx)
{
        LASSERT(atomic_read(&grctx->src_base.sc_refcount) > 0);
        atomic_inc(&grctx->src_base.sc_refcount);
}

static inline
void gss_svc_reqctx_decref(struct gss_svc_reqctx *grctx)
{
        LASSERT(atomic_read(&grctx->src_base.sc_refcount) > 0);

        if (atomic_dec_and_test(&grctx->src_base.sc_refcount))
                gss_svc_reqctx_free(grctx);
}

static
int gss_svc_sign(struct ptlrpc_request *req,
                 struct ptlrpc_reply_state *rs,
                 struct gss_svc_reqctx *grctx)
{
        int     rc;
        ENTRY;

        LASSERT(rs->rs_msg == lustre_msg_buf(rs->rs_repbuf, 1, 0));

        /* embedded lustre_msg might have been shrinked */
        if (req->rq_replen != rs->rs_repbuf->lm_buflens[1])
                lustre_shrink_msg(rs->rs_repbuf, 1, req->rq_replen, 1);

        rc = gss_sign_msg(rs->rs_repbuf, grctx->src_ctx->gsc_mechctx,
                          PTLRPC_GSS_PROC_DATA, grctx->src_wirectx.gw_seq,
                          NULL);
        if (rc < 0)
                RETURN(rc);

        rs->rs_repdata_len = rc;
        RETURN(0);
}

int gss_pack_err_notify(struct ptlrpc_request *req, __u32 major, __u32 minor)
{
        struct gss_svc_reqctx     *grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);
        struct ptlrpc_reply_state *rs;
        struct gss_err_header     *ghdr;
        int                        replen = sizeof(struct ptlrpc_body);
        int                        rc;
        ENTRY;

        //OBD_FAIL_RETURN(OBD_FAIL_SVCGSS_ERR_NOTIFY|OBD_FAIL_ONCE, -EINVAL);

        grctx->src_err_notify = 1;
        grctx->src_reserve_len = 0;

        rc = lustre_pack_reply_v2(req, 1, &replen, NULL);
        if (rc) {
                CERROR("could not pack reply, err %d\n", rc);
                RETURN(rc);
        }

        /* gss hdr */
        rs = req->rq_reply_state;
        LASSERT(rs->rs_repbuf->lm_buflens[1] >= sizeof(*ghdr));
        ghdr = lustre_msg_buf(rs->rs_repbuf, 0, 0);
        ghdr->gh_version = PTLRPC_GSS_VERSION;
        ghdr->gh_flags = 0;
        ghdr->gh_proc = PTLRPC_GSS_PROC_ERR;
        ghdr->gh_major = major;
        ghdr->gh_minor = minor;
        ghdr->gh_handle.len = 0; /* fake context handle */

        rs->rs_repdata_len = lustre_msg_size_v2(rs->rs_repbuf->lm_bufcount,
                                                rs->rs_repbuf->lm_buflens);

        CDEBUG(D_SEC, "prepare gss error notify(0x%x/0x%x) to %s\n",
               major, minor, libcfs_nid2str(req->rq_peer.nid));
        RETURN(0);
}

static
int gss_svc_handle_init(struct ptlrpc_request *req,
                        struct gss_wire_ctx *gw)
{
        struct gss_svc_reqctx     *grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);
        struct lustre_msg         *reqbuf = req->rq_reqbuf;
        struct obd_uuid           *uuid;
        struct obd_device         *target;
        rawobj_t                   uuid_obj, rvs_hdl, in_token;
        __u32                      lustre_svc;
        __u32                     *secdata, seclen;
        int                        rc;
        ENTRY;

        CDEBUG(D_SEC, "processing gss init(%d) request from %s\n", gw->gw_proc,
               libcfs_nid2str(req->rq_peer.nid));

        if (gw->gw_proc == PTLRPC_GSS_PROC_INIT && gw->gw_handle.len != 0) {
                CERROR("proc %u: invalid handle length %u\n",
                       gw->gw_proc, gw->gw_handle.len);
                RETURN(SECSVC_DROP);
        }

        if (reqbuf->lm_bufcount < 3 || reqbuf->lm_bufcount > 4){
                CERROR("Invalid bufcount %d\n", reqbuf->lm_bufcount);
                RETURN(SECSVC_DROP);
        }

        /* ctx initiate payload is in last segment */
        secdata = lustre_msg_buf(reqbuf, reqbuf->lm_bufcount - 1, 0);
        seclen = reqbuf->lm_buflens[reqbuf->lm_bufcount - 1];

        if (seclen < 4 + 4) {
                CERROR("sec size %d too small\n", seclen);
                RETURN(SECSVC_DROP);
        }

        /* lustre svc type */
        lustre_svc = le32_to_cpu(*secdata++);
        seclen -= 4;

        /* extract target uuid, note this code is somewhat fragile
         * because touched internal structure of obd_uuid
         */
        if (rawobj_extract(&uuid_obj, &secdata, &seclen)) {
                CERROR("failed to extract target uuid\n");
                RETURN(SECSVC_DROP);
        }
        uuid_obj.data[uuid_obj.len - 1] = '\0';

        uuid = (struct obd_uuid *) uuid_obj.data;
        target = class_uuid2obd(uuid);
        if (!target || target->obd_stopping || !target->obd_set_up) {
                CERROR("target '%s' is not available for context init (%s)",
                       uuid->uuid, target == NULL ? "no target" :
                       (target->obd_stopping ? "stopping" : "not set up"));
                RETURN(SECSVC_DROP);
        }

        /* extract reverse handle */
        if (rawobj_extract(&rvs_hdl, &secdata, &seclen)) {
                CERROR("failed extract reverse handle\n");
                RETURN(SECSVC_DROP);
        }

        /* extract token */
        if (rawobj_extract(&in_token, &secdata, &seclen)) {
                CERROR("can't extract token\n");
                RETURN(SECSVC_DROP);
        }

        rc = gss_svc_upcall_handle_init(req, grctx, gw, target, lustre_svc,
                                        &rvs_hdl, &in_token);
        if (rc != SECSVC_OK)
                RETURN(rc);

        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor)) {
                if (reqbuf->lm_bufcount < 4) {
                        CERROR("missing user descriptor\n");
                        RETURN(SECSVC_DROP);
                }
                if (sptlrpc_unpack_user_desc(reqbuf, 2)) {
                        CERROR("Mal-formed user descriptor\n");
                        RETURN(SECSVC_DROP);
                }
                req->rq_user_desc = lustre_msg_buf(reqbuf, 2, 0);
        }

        req->rq_reqmsg = lustre_msg_buf(reqbuf, 1, 0);
        req->rq_reqlen = lustre_msg_buflen(reqbuf, 1);

        RETURN(rc);
}

/*
 * last segment must be the gss signature.
 */
static
int gss_svc_verify_request(struct ptlrpc_request *req,
                           struct gss_svc_ctx *gctx,
                           struct gss_wire_ctx *gw,
                           __u32 *major)
{
        struct lustre_msg  *msg = req->rq_reqbuf;
        int                 offset = 2;
        ENTRY;

        *major = GSS_S_COMPLETE;

        if (msg->lm_bufcount < 3) {
                CERROR("Too few segments (%u) in request\n", msg->lm_bufcount);
                RETURN(-EINVAL);
        }

        if (gss_check_seq_num(&gctx->gsc_seqdata, gw->gw_seq, 0)) {
                CERROR("phase 0: discard replayed req: seq %u\n", gw->gw_seq);
                *major = GSS_S_DUPLICATE_TOKEN;
                RETURN(-EACCES);
        }

        *major = gss_verify_msg(msg, gctx->gsc_mechctx);
        if (*major != GSS_S_COMPLETE)
                RETURN(-EACCES);

        if (gss_check_seq_num(&gctx->gsc_seqdata, gw->gw_seq, 1)) {
                CERROR("phase 1+: discard replayed req: seq %u\n", gw->gw_seq);
                *major = GSS_S_DUPLICATE_TOKEN;
                RETURN(-EACCES);
        }

        /* user descriptor */
        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor)) {
                if (msg->lm_bufcount < (offset + 1 + 1)) {
                        CERROR("no user desc included\n");
                        RETURN(-EINVAL);
                }

                if (sptlrpc_unpack_user_desc(msg, offset)) {
                        CERROR("Mal-formed user descriptor\n");
                        RETURN(-EINVAL);
                }

                req->rq_user_desc = lustre_msg_buf(msg, offset, 0);
                offset++;
        }

        /* check bulk cksum data */
        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                if (msg->lm_bufcount < (offset + 1 + 1)) {
                        CERROR("no bulk checksum included\n");
                        RETURN(-EINVAL);
                }

                if (bulk_sec_desc_unpack(msg, offset))
                        RETURN(-EINVAL);
        }

        req->rq_reqmsg = lustre_msg_buf(msg, 1, 0);
        req->rq_reqlen = msg->lm_buflens[1];
        RETURN(0);
}

static
int gss_svc_unseal_request(struct ptlrpc_request *req,
                           struct gss_svc_ctx *gctx,
                           struct gss_wire_ctx *gw,
                           __u32 *major)
{
        struct lustre_msg  *msg = req->rq_reqbuf;
        int                 msglen, offset = 1;
        ENTRY;

        if (gss_check_seq_num(&gctx->gsc_seqdata, gw->gw_seq, 0)) {
                CERROR("phase 0: discard replayed req: seq %u\n", gw->gw_seq);
                *major = GSS_S_DUPLICATE_TOKEN;
                RETURN(-EACCES);
        }

        *major = gss_unseal_msg(gctx->gsc_mechctx, msg,
                               &msglen, req->rq_reqdata_len);
        if (*major != GSS_S_COMPLETE)
                RETURN(-EACCES);

        if (gss_check_seq_num(&gctx->gsc_seqdata, gw->gw_seq, 1)) {
                CERROR("phase 1+: discard replayed req: seq %u\n", gw->gw_seq);
                *major = GSS_S_DUPLICATE_TOKEN;
                RETURN(-EACCES);
        }

        if (lustre_unpack_msg(msg, msglen)) {
                CERROR("Failed to unpack after decryption\n");
                RETURN(-EINVAL);
        }
        req->rq_reqdata_len = msglen;

        if (msg->lm_bufcount < 1) {
                CERROR("Invalid buffer: is empty\n");
                RETURN(-EINVAL);
        }

        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor)) {
                if (msg->lm_bufcount < offset + 1) {
                        CERROR("no user descriptor included\n");
                        RETURN(-EINVAL);
                }

                if (sptlrpc_unpack_user_desc(msg, offset)) {
                        CERROR("Mal-formed user descriptor\n");
                        RETURN(-EINVAL);
                }

                req->rq_user_desc = lustre_msg_buf(msg, offset, 0);
                offset++;
        }

        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                if (msg->lm_bufcount < offset + 1) {
                        CERROR("no bulk checksum included\n");
                        RETURN(-EINVAL);
                }

                if (bulk_sec_desc_unpack(msg, offset))
                        RETURN(-EINVAL);
        }

        req->rq_reqmsg = lustre_msg_buf(req->rq_reqbuf, 0, 0);
        req->rq_reqlen = req->rq_reqbuf->lm_buflens[0];
        RETURN(0);
}

static
int gss_svc_handle_data(struct ptlrpc_request *req,
                        struct gss_wire_ctx *gw)
{
        struct gss_svc_reqctx *grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);
        __u32                  major = 0;
        int                    rc = 0;
        ENTRY;

        grctx->src_ctx = gss_svc_upcall_get_ctx(req, gw);
        if (!grctx->src_ctx) {
                major = GSS_S_NO_CONTEXT;
                goto error;
        }

        switch (gw->gw_svc) {
        case PTLRPC_GSS_SVC_INTEGRITY:
                rc = gss_svc_verify_request(req, grctx->src_ctx, gw, &major);
                break;
        case PTLRPC_GSS_SVC_PRIVACY:
                rc = gss_svc_unseal_request(req, grctx->src_ctx, gw, &major);
                break;
        default:
                CERROR("unsupported gss service %d\n", gw->gw_svc);
                rc = -EINVAL;
        }

        if (rc == 0)
                RETURN(SECSVC_OK);

        CERROR("svc %u failed: major 0x%08x: ctx %p(%u->%s)\n",
               gw->gw_svc, major, grctx->src_ctx, grctx->src_ctx->gsc_uid,
               libcfs_nid2str(req->rq_peer.nid));
error:
        /*
         * we only notify client in case of NO_CONTEXT/BAD_SIG, which
         * might happen after server reboot, to allow recovery.
         */
        if ((major == GSS_S_NO_CONTEXT || major == GSS_S_BAD_SIG) &&
            gss_pack_err_notify(req, major, 0) == 0)
                RETURN(SECSVC_COMPLETE);

        RETURN(SECSVC_DROP);
}

static
int gss_svc_handle_destroy(struct ptlrpc_request *req,
                           struct gss_wire_ctx *gw)
{
        struct gss_svc_reqctx  *grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);
        int                     replen = sizeof(struct ptlrpc_body);
        __u32                   major;
        ENTRY;

        grctx->src_ctx = gss_svc_upcall_get_ctx(req, gw);
        if (!grctx->src_ctx) {
                CWARN("invalid gss context handle for destroy.\n");
                RETURN(SECSVC_DROP);
        }

        if (gw->gw_svc != PTLRPC_GSS_SVC_INTEGRITY) {
                CERROR("svc %u is not supported in destroy.\n", gw->gw_svc);
                RETURN(SECSVC_DROP);
        }

        if (gss_svc_verify_request(req, grctx->src_ctx, gw, &major))
                RETURN(SECSVC_DROP);

        if (lustre_pack_reply_v2(req, 1, &replen, NULL))
                RETURN(SECSVC_DROP);

        CWARN("gss svc destroy ctx %p(%u->%s)\n", grctx->src_ctx,
              grctx->src_ctx->gsc_uid, libcfs_nid2str(req->rq_peer.nid));

        gss_svc_upcall_destroy_ctx(grctx->src_ctx);

        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor)) {
                if (req->rq_reqbuf->lm_bufcount < 4) {
                        CERROR("missing user descriptor, ignore it\n");
                        RETURN(SECSVC_OK);
                }
                if (sptlrpc_unpack_user_desc(req->rq_reqbuf, 2)) {
                        CERROR("Mal-formed user descriptor, ignore it\n");
                        RETURN(SECSVC_OK);
                }
                req->rq_user_desc = lustre_msg_buf(req->rq_reqbuf, 2, 0);
        }

        RETURN(SECSVC_OK);
}

static
int gss_svc_accept(struct ptlrpc_request *req)
{
        struct gss_header      *ghdr;
        struct gss_svc_reqctx  *grctx;
        struct gss_wire_ctx    *gw;
        int                     rc;
        ENTRY;

        LASSERTF((__gss_mod_initialized == 1),
                 "not initialized %d\n", __gss_mod_initialized);
        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_svc_ctx == NULL);

        if (req->rq_reqbuf->lm_bufcount < 2) {
                CERROR("buf count only %d\n", req->rq_reqbuf->lm_bufcount);
                RETURN(SECSVC_DROP);
        }

        ghdr = gss_swab_header(req->rq_reqbuf, 0);
        if (ghdr == NULL) {
                CERROR("can't decode gss header\n");
                RETURN(SECSVC_DROP);
        }

        /* sanity checks */
        if (ghdr->gh_version != PTLRPC_GSS_VERSION) {
                CERROR("gss version %u, expect %u\n", ghdr->gh_version,
                       PTLRPC_GSS_VERSION);
                RETURN(SECSVC_DROP);
        }

        /* alloc grctx data */
        OBD_ALLOC_PTR(grctx);
        if (!grctx) {
                CERROR("fail to alloc svc reqctx\n");
                RETURN(SECSVC_DROP);
        }
        grctx->src_base.sc_policy = sptlrpc_policy_get(&gss_policy);
        atomic_set(&grctx->src_base.sc_refcount, 1);
        req->rq_svc_ctx = &grctx->src_base;
        gw = &grctx->src_wirectx;

        /* save wire context */
        gw->gw_proc = ghdr->gh_proc;
        gw->gw_seq = ghdr->gh_seq;
        gw->gw_svc = ghdr->gh_svc;
        rawobj_from_netobj(&gw->gw_handle, &ghdr->gh_handle);

        /* keep original wire header which subject to checksum verification */
        if (lustre_msg_swabbed(req->rq_reqbuf))
                gss_header_swabber(ghdr);

        switch(ghdr->gh_proc) {
        case PTLRPC_GSS_PROC_INIT:
        case PTLRPC_GSS_PROC_CONTINUE_INIT:
                rc = gss_svc_handle_init(req, gw);
                break;
        case PTLRPC_GSS_PROC_DATA:
                rc = gss_svc_handle_data(req, gw);
                break;
        case PTLRPC_GSS_PROC_DESTROY:
                rc = gss_svc_handle_destroy(req, gw);
                break;
        default:
                CERROR("unknown proc %u\n", gw->gw_proc);
                rc = SECSVC_DROP;
                break;
        }

        switch (rc) {
        case SECSVC_OK:
                LASSERT (grctx->src_ctx);

                req->rq_auth_gss = 1;
                req->rq_auth_remote = grctx->src_ctx->gsc_remote;
                req->rq_auth_usr_mdt = grctx->src_ctx->gsc_usr_mds;
                req->rq_auth_usr_root = grctx->src_ctx->gsc_usr_root;
                req->rq_auth_uid = grctx->src_ctx->gsc_uid;
                req->rq_auth_mapped_uid = grctx->src_ctx->gsc_mapped_uid;
                break;
        case SECSVC_COMPLETE:
                break;
        case SECSVC_DROP:
                gss_svc_reqctx_free(grctx);
                req->rq_svc_ctx = NULL;
                break;
        }

        RETURN(rc);
}

static
void gss_svc_invalidate_ctx(struct ptlrpc_svc_ctx *svc_ctx)
{
        struct gss_svc_reqctx  *grctx;
        ENTRY;

        if (svc_ctx == NULL) {
                EXIT;
                return;
        }

        grctx = gss_svc_ctx2reqctx(svc_ctx);

        CWARN("gss svc invalidate ctx %p(%u)\n",
              grctx->src_ctx, grctx->src_ctx->gsc_uid);
        gss_svc_upcall_destroy_ctx(grctx->src_ctx);

        EXIT;
}

static inline
int gss_svc_payload(struct gss_svc_reqctx *grctx, int msgsize, int privacy)
{
        if (gss_svc_reqctx_is_special(grctx))
                return grctx->src_reserve_len;

        return gss_estimate_payload(NULL, msgsize, privacy);
}

static
int gss_svc_alloc_rs(struct ptlrpc_request *req, int msglen)
{
        struct gss_svc_reqctx       *grctx;
        struct ptlrpc_reply_state   *rs;
        struct ptlrpc_bulk_sec_desc *bsd;
        int                          privacy;
        int                          ibuflens[2], ibufcnt = 0;
        int                          buflens[4], bufcnt;
        int                          txtsize, wmsg_size, rs_size;
        ENTRY;

        LASSERT(msglen % 8 == 0);

        if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor) &&
            !req->rq_bulk_read && !req->rq_bulk_write) {
                CERROR("client request bulk sec on non-bulk rpc\n");
                RETURN(-EPROTO);
        }

        grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);
        if (gss_svc_reqctx_is_special(grctx))
                privacy = 0;
        else
                privacy = (SEC_FLAVOR_SVC(req->rq_sec_flavor) ==
                           SPTLRPC_SVC_PRIV);

        if (privacy) {
                /* Inner buffer */
                ibufcnt = 1;
                ibuflens[0] = msglen;

                if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                        LASSERT(req->rq_reqbuf->lm_bufcount >= 2);
                        bsd = lustre_msg_buf(req->rq_reqbuf,
                                             req->rq_reqbuf->lm_bufcount - 1,
                                             sizeof(*bsd));

                        ibuflens[ibufcnt++] = bulk_sec_desc_size(
                                                        bsd->bsd_csum_alg, 0,
                                                        req->rq_bulk_read);
                }

                txtsize = lustre_msg_size_v2(ibufcnt, ibuflens);
                txtsize += GSS_MAX_CIPHER_BLOCK;

                /* wrapper buffer */
                bufcnt = 3;
                buflens[0] = PTLRPC_GSS_HEADER_SIZE;
                buflens[1] = gss_svc_payload(grctx, buflens[0], 0);
                buflens[2] = gss_svc_payload(grctx, txtsize, 1);
        } else {
                bufcnt = 2;
                buflens[0] = PTLRPC_GSS_HEADER_SIZE;
                buflens[1] = msglen;
                txtsize = buflens[0] + buflens[1];

                if (SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor)) {
                        LASSERT(req->rq_reqbuf->lm_bufcount >= 4);
                        bsd = lustre_msg_buf(req->rq_reqbuf,
                                             req->rq_reqbuf->lm_bufcount - 2,
                                             sizeof(*bsd));

                        buflens[bufcnt] = bulk_sec_desc_size(
                                                        bsd->bsd_csum_alg, 0,
                                                        req->rq_bulk_read);
                        txtsize += buflens[bufcnt];
                        bufcnt++;
                }
                buflens[bufcnt++] = gss_svc_payload(grctx, txtsize, 0);
        }

        wmsg_size = lustre_msg_size_v2(bufcnt, buflens);

        rs_size = sizeof(*rs) + wmsg_size;
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

        rs->rs_repbuf = (struct lustre_msg *) (rs + 1);
        rs->rs_repbuf_len = wmsg_size;

        if (privacy) {
                lustre_init_msg_v2(rs->rs_repbuf, ibufcnt, ibuflens, NULL);
                rs->rs_msg = lustre_msg_buf(rs->rs_repbuf, 0, msglen);
        } else {
                lustre_init_msg_v2(rs->rs_repbuf, bufcnt, buflens, NULL);
                rs->rs_repbuf->lm_secflvr = req->rq_sec_flavor;

                rs->rs_msg = (struct lustre_msg *)
                                lustre_msg_buf(rs->rs_repbuf, 1, 0);
        }

        gss_svc_reqctx_addref(grctx);
        rs->rs_svc_ctx = req->rq_svc_ctx;

        LASSERT(rs->rs_msg);
        req->rq_reply_state = rs;
        RETURN(0);
}

static
int gss_svc_seal(struct ptlrpc_request *req,
                 struct ptlrpc_reply_state *rs,
                 struct gss_svc_reqctx *grctx)
{
        struct gss_svc_ctx      *gctx = grctx->src_ctx;
        rawobj_t                 msgobj, cipher_obj, micobj;
        struct gss_header       *ghdr;
        __u8                    *cipher_buf;
        int                      cipher_buflen, buflens[3];
        int                      msglen, rc;
        __u32                    major;
        ENTRY;

        /* embedded lustre_msg might have been shrinked */
        if (req->rq_replen != rs->rs_repbuf->lm_buflens[0])
                lustre_shrink_msg(rs->rs_repbuf, 0, req->rq_replen, 1);

        /* clear data length */
        msglen = lustre_msg_size_v2(rs->rs_repbuf->lm_bufcount,
                                    rs->rs_repbuf->lm_buflens);

        /* clear text */
        msgobj.len = msglen;
        msgobj.data = (__u8 *) rs->rs_repbuf;

        /* allocate temporary cipher buffer */
        cipher_buflen = gss_estimate_payload(gctx->gsc_mechctx, msglen, 1);
        OBD_ALLOC(cipher_buf, cipher_buflen);
        if (!cipher_buf)
                RETURN(-ENOMEM);

        cipher_obj.len = cipher_buflen;
        cipher_obj.data = cipher_buf;

        major = lgss_wrap(gctx->gsc_mechctx, &msgobj, rs->rs_repbuf_len,
                          &cipher_obj);
        if (major != GSS_S_COMPLETE) {
                CERROR("priv: wrap message error: %08x\n", major);
                GOTO(out_free, rc = -EPERM);
        }
        LASSERT(cipher_obj.len <= cipher_buflen);

        /* now the real wire data */
        buflens[0] = PTLRPC_GSS_HEADER_SIZE;
        buflens[1] = gss_estimate_payload(gctx->gsc_mechctx, buflens[0], 0);
        buflens[2] = cipher_obj.len;

        LASSERT(lustre_msg_size_v2(3, buflens) <= rs->rs_repbuf_len);
        lustre_init_msg_v2(rs->rs_repbuf, 3, buflens, NULL);
        rs->rs_repbuf->lm_secflvr = req->rq_sec_flavor;

        /* gss header */
        ghdr = lustre_msg_buf(rs->rs_repbuf, 0, 0);
        ghdr->gh_version = PTLRPC_GSS_VERSION;
        ghdr->gh_flags = 0;
        ghdr->gh_proc = PTLRPC_GSS_PROC_DATA;
        ghdr->gh_seq = grctx->src_wirectx.gw_seq;
        ghdr->gh_svc = PTLRPC_GSS_SVC_PRIVACY;
        ghdr->gh_handle.len = 0;

        /* header signature */
        msgobj.len = rs->rs_repbuf->lm_buflens[0];
        msgobj.data = lustre_msg_buf(rs->rs_repbuf, 0, 0);
        micobj.len = rs->rs_repbuf->lm_buflens[1];
        micobj.data = lustre_msg_buf(rs->rs_repbuf, 1, 0);

        major = lgss_get_mic(gctx->gsc_mechctx, 1, &msgobj, &micobj);
        if (major != GSS_S_COMPLETE) {
                CERROR("priv: sign message error: %08x\n", major);
                GOTO(out_free, rc = -EPERM);
        }
        lustre_shrink_msg(rs->rs_repbuf, 1, micobj.len, 0);

        /* cipher token */
        memcpy(lustre_msg_buf(rs->rs_repbuf, 2, 0),
               cipher_obj.data, cipher_obj.len);

        rs->rs_repdata_len = lustre_shrink_msg(rs->rs_repbuf, 2,
                                               cipher_obj.len, 0);

        /* to catch upper layer's further access */
        rs->rs_msg = NULL;
        req->rq_repmsg = NULL;
        req->rq_replen = 0;

        rc = 0;
out_free:
        OBD_FREE(cipher_buf, cipher_buflen);
        RETURN(rc);
}

int gss_svc_authorize(struct ptlrpc_request *req)
{
        struct ptlrpc_reply_state *rs = req->rq_reply_state;
        struct gss_svc_reqctx     *grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);
        struct gss_wire_ctx       *gw;
        int                        rc;
        ENTRY;

        if (gss_svc_reqctx_is_special(grctx))
                RETURN(0);

        gw = &grctx->src_wirectx;
        if (gw->gw_proc != PTLRPC_GSS_PROC_DATA &&
            gw->gw_proc != PTLRPC_GSS_PROC_DESTROY) {
                CERROR("proc %d not support\n", gw->gw_proc);
                RETURN(-EINVAL);
        }

        LASSERT(grctx->src_ctx);

        switch (gw->gw_svc) {
        case  PTLRPC_GSS_SVC_INTEGRITY:
                rc = gss_svc_sign(req, rs, grctx);
                break;
        case  PTLRPC_GSS_SVC_PRIVACY:
                rc = gss_svc_seal(req, rs, grctx);
                break;
        default:
                CERROR("Unknown service %d\n", gw->gw_svc);
                GOTO(out, rc = -EINVAL);
        }
        rc = 0;

out:
        RETURN(rc);
}

static
void gss_svc_free_rs(struct ptlrpc_reply_state *rs)
{
        struct gss_svc_reqctx *grctx;

        LASSERT(rs->rs_svc_ctx);
        grctx = container_of(rs->rs_svc_ctx, struct gss_svc_reqctx, src_base);

        gss_svc_reqctx_decref(grctx);
        rs->rs_svc_ctx = NULL;

        if (!rs->rs_prealloc)
                OBD_FREE(rs, rs->rs_size);
}

static
void gss_svc_free_ctx(struct ptlrpc_svc_ctx *ctx)
{
        LASSERT(atomic_read(&ctx->sc_refcount) == 0);
        gss_svc_reqctx_free(gss_svc_ctx2reqctx(ctx));
}

static
int gss_svc_install_rctx(struct obd_import *imp, struct ptlrpc_svc_ctx *ctx)
{
        struct gss_sec *gsec;

        LASSERT(imp->imp_sec);
        LASSERT(ctx);

        gsec = container_of(imp->imp_sec, struct gss_sec, gs_base);
        return gss_install_rvs_cli_ctx(gsec, ctx);
}

static struct ptlrpc_sec_sops gss_sec_sops = {
        .accept                 = gss_svc_accept,
        .invalidate_ctx         = gss_svc_invalidate_ctx,
        .alloc_rs               = gss_svc_alloc_rs,
        .authorize              = gss_svc_authorize,
        .free_rs                = gss_svc_free_rs,
        .free_ctx               = gss_svc_free_ctx,
        .unwrap_bulk            = gss_svc_unwrap_bulk,
        .wrap_bulk              = gss_svc_wrap_bulk,
        .install_rctx           = gss_svc_install_rctx,
};

static struct ptlrpc_sec_policy gss_policy = {
        .sp_owner               = THIS_MODULE,
        .sp_name                = "sec.gss",
        .sp_policy              = SPTLRPC_POLICY_GSS,
        .sp_cops                = &gss_sec_cops,
        .sp_sops                = &gss_sec_sops,
};

int __init sptlrpc_gss_init(void)
{
        int rc;

        rc = sptlrpc_register_policy(&gss_policy);
        if (rc)
                return rc;

        rc = gss_init_lproc();
        if (rc)
                goto out_type;

        rc = gss_init_upcall();
        if (rc)
                goto out_lproc;

        rc = init_kerberos_module();
        if (rc)
                goto out_upcall;

        __gss_mod_initialized = 1;
        return 0;
out_upcall:
        gss_exit_upcall();
out_lproc:
        gss_exit_lproc();
out_type:
        sptlrpc_unregister_policy(&gss_policy);
        return rc;
}

static void __exit sptlrpc_gss_exit(void)
{
        cleanup_kerberos_module();
        gss_exit_upcall();
        gss_exit_lproc();
        sptlrpc_unregister_policy(&gss_policy);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("GSS security policy for Lustre");
MODULE_LICENSE("GPL");

module_init(sptlrpc_gss_init);
module_exit(sptlrpc_gss_exit);
