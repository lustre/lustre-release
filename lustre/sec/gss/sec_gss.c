/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004, Cluster File Systems, Inc.
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
 * $Id: sec_gss.c,v 1.3 2005/04/04 13:12:39 yury Exp $
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
/* for rpc_pipefs */
struct rpc_clnt;
#include <linux/sunrpc/rpc_pipe_fs.h>
#else
#include <liblustre.h>
#endif

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

#define GSS_CREDCACHE_EXPIRE    (60)               /* 1 minute */
#define GSS_CRED_EXPIRE         (8 * 60 * 60)      /* 8 hours */
#define GSS_CRED_SIGN_SIZE      (1024)
#define GSS_CRED_VERIFY_SIZE    (56)

#define LUSTRE_PIPEDIR          "/lustre"

/**********************************************
 * gss security init/fini helper              *
 **********************************************/

#define SECINIT_RPC_TIMEOUT     (10)
#define SECFINI_RPC_TIMEOUT     (10)

static int secinit_compose_request(struct obd_import *imp,
                                   char *buf, int bufsize,
                                   char __user *token)
{
        struct ptlrpcs_wire_hdr *hdr;
        struct lustre_msg       *lmsg;
        char __user             *token_buf;
        __u64                    token_size;
        __u32                    lmsg_size, *p;
        int rc;

        lmsg_size = lustre_msg_size(0, NULL);

        if (copy_from_user(&token_size, token, sizeof(token_size))) {
                CERROR("read token error\n");
                return -EFAULT;
        }
        if (sizeof(*hdr) + lmsg_size + size_round(token_size) > bufsize) {
                CERROR("token size "LPU64" too large\n", token_size);
                return -EINVAL;
        }

        if (copy_from_user(&token_buf, (token + sizeof(token_size)),
                           sizeof(void*))) {
                CERROR("read token buf pointer error\n");
                return -EFAULT;
        }

        /* security wire hdr */
        hdr = buf_to_sec_hdr(buf);
        hdr->flavor  = cpu_to_le32(PTLRPC_SEC_GSS);
        hdr->sectype = cpu_to_le32(PTLRPC_SEC_TYPE_NONE);
        hdr->msg_len = cpu_to_le32(lmsg_size);
        hdr->sec_len = cpu_to_le32(7 * 4 + token_size);

        /* lustre message */
        lmsg = buf_to_lustre_msg(buf);
        lustre_init_msg(lmsg, 0, NULL, NULL);
        lmsg->handle   = imp->imp_remote_handle;
        lmsg->type     = PTL_RPC_MSG_REQUEST;
        lmsg->opc      = SEC_INIT;
        lmsg->flags    = 0;
        lmsg->conn_cnt = imp->imp_conn_cnt;

        p = (__u32 *) (buf + sizeof(*hdr) + lmsg_size);

        /* gss hdr */
        *p++ = cpu_to_le32(PTLRPC_SEC_GSS_VERSION);     /* gss version */
        *p++ = cpu_to_le32(PTLRPC_SEC_GSS_KRB5I);       /* subflavor */
        *p++ = cpu_to_le32(PTLRPC_GSS_PROC_INIT);       /* proc */
        *p++ = cpu_to_le32(0);                          /* seq */
        *p++ = cpu_to_le32(PTLRPC_GSS_SVC_NONE);        /* service */
        *p++ = cpu_to_le32(0);                          /* context handle */

        /* now the token part */
        *p++ = (__u32)(cpu_to_le64(token_size));
        LASSERT(((char *)p - buf) + token_size <= bufsize);

        rc = copy_from_user(p, token_buf, token_size);
        if (rc) {
                CERROR("can't copy token\n");
                return -EFAULT;
        }

        rc = size_round(((char *)p - buf) + token_size);
        return rc;
}

static int secinit_parse_reply(char *repbuf, int replen,
                               char __user *outbuf, int outlen)
{
        __u32 *p = (__u32 *)repbuf;
        __u32 lmsg_len, sec_len, status, major, minor, seq, obj_len, round_len;
        __u32 effective = 0;

        if (replen <= (4 + 6) * 4) {
                CERROR("reply size %d too small\n", replen);
                return -EINVAL;
        }

        lmsg_len = le32_to_cpu(p[2]);
        sec_len = le32_to_cpu(p[3]);

        /* sanity checks */
        if (p[0] != cpu_to_le32(PTLRPC_SEC_GSS) ||
            p[1] != cpu_to_le32(PTLRPC_SEC_TYPE_NONE)) {
                CERROR("unexpected reply\n");
                return -EINVAL;
        }
        if (lmsg_len % 8 ||
            4 * 4 + lmsg_len + sec_len > replen) {
                CERROR("unexpected reply\n");
                return -EINVAL;
        }
        if (sec_len > outlen) {
                CERROR("outbuf too small\n");
                return -EINVAL;
        }

        p += 4;                 /* skip hdr */
        p += lmsg_len / 4;      /* skip lmsg */
        effective = 0;

        status = le32_to_cpu(*p++);
        major = le32_to_cpu(*p++);
        minor = le32_to_cpu(*p++);
        seq = le32_to_cpu(*p++);
        effective += 4 * 4;

        copy_to_user(outbuf, &status, 4);
        outbuf += 4;
        copy_to_user(outbuf, &major, 4);
        outbuf += 4;
        copy_to_user(outbuf, &minor, 4);
        outbuf += 4;
        copy_to_user(outbuf, &seq, 4);
        outbuf += 4;

        obj_len = le32_to_cpu(*p++);
        round_len = (obj_len + 3) & ~ 3;
        copy_to_user(outbuf, &obj_len, 4);
        outbuf += 4;
        copy_to_user(outbuf, (char *)p, round_len);
        p += round_len / 4;
        outbuf += round_len;
        effective += 4 + round_len;

        obj_len = le32_to_cpu(*p++);
        round_len = (obj_len + 3) & ~ 3;
        copy_to_user(outbuf, &obj_len, 4);
        outbuf += 4;
        copy_to_user(outbuf, (char *)p, round_len);
        p += round_len / 4;
        outbuf += round_len;
        effective += 4 + round_len;

        return effective;
}

/* input: 
 *   1. ptr to uuid
 *   2. ptr to send_token
 *   3. ptr to output buffer
 *   4. output buffer size
 * output:
 *   1. return code. 0 is success
 *   2. no meaning
 *   3. ptr output data
 *   4. output data size
 *
 * return:
 *   < 0: error
 *   = 0: success
 *
 * FIXME This interface looks strange, should be reimplemented
 */
static int gss_send_secinit_rpc(__user char *buffer, unsigned long count)
{
        struct obd_import *imp;
        const int reqbuf_size = 1024;
        const int repbuf_size = 1024;
        char *reqbuf, *repbuf;
        struct obd_device *obd;
        char obdname[64];
        long inbuf[4], lsize;
        int rc, reqlen, replen;

        if (count != 4 * sizeof(long)) {
                CERROR("count %lu\n", count);
                RETURN(-EINVAL);
        }
        if (copy_from_user(inbuf, buffer, count)) {
                CERROR("Invalid pointer\n");
                RETURN(-EFAULT);
        }

        /* take name */
        if (strncpy_from_user(obdname, (char *)inbuf[0],
                              sizeof(obdname)) <= 0) {
                CERROR("Invalid obdname pointer\n");
                RETURN(-EFAULT);
        }

        obd = class_name2obd(obdname);
        if (!obd) {
                CERROR("no such obd %s\n", obdname);
                RETURN(-EINVAL);
        }
        if (strcmp(obd->obd_type->typ_name, "mdc") &&
            strcmp(obd->obd_type->typ_name, "osc")) {
                CERROR("%s not a mdc/osc device\n", obdname);
                RETURN(-EINVAL);
        }

        imp = class_import_get(obd->u.cli.cl_import);

        OBD_ALLOC(reqbuf, reqbuf_size);
        OBD_ALLOC(repbuf, reqbuf_size);

        if (!reqbuf || !repbuf) {
                CERROR("Can't alloc buffer: %p/%p\n", reqbuf, repbuf);
                GOTO(out_free, rc = -ENOMEM);
        }

        /* get token */
        reqlen = secinit_compose_request(imp, reqbuf, reqbuf_size,
                                         (char *)inbuf[1]);
        if (reqlen < 0)
                GOTO(out_free, rc = reqlen);

        replen = repbuf_size;
        rc = ptlrpc_do_rawrpc(imp, reqbuf, reqlen,
                              repbuf, &replen, SECINIT_RPC_TIMEOUT);
        if (rc)
                GOTO(out_free, rc);

        if (replen > inbuf[3]) {
                CERROR("output buffer size %ld too small, need %d\n",
                        inbuf[3], replen);
                GOTO(out_free, rc = -EINVAL);
        }

        lsize = secinit_parse_reply(repbuf, replen,
                                    (char *)inbuf[2], (int)inbuf[3]);
        if (lsize < 0)
                GOTO(out_free, rc = (int)lsize);

        copy_to_user(buffer + 3 * sizeof(long), &lsize, sizeof(lsize));
        lsize = 0;
        copy_to_user((char*)buffer, &lsize, sizeof(lsize));
        rc = 0;
out_free:
        class_import_put(imp);
        if (repbuf)
                OBD_FREE(repbuf, repbuf_size);
        if (reqbuf)
                OBD_FREE(reqbuf, reqbuf_size);
        RETURN(rc);
}

static int gss_send_secfini_rpc(struct obd_import *imp,
                                char *reqbuf, int reqlen)
{
        const int repbuf_size = 1024;
        char *repbuf;
        int replen = repbuf_size;
        int rc;

        OBD_ALLOC(repbuf, repbuf_size);
        if (!repbuf) {
                CERROR("Out of memory\n");
                return -ENOMEM;
        }

        rc = ptlrpc_do_rawrpc(imp, reqbuf, reqlen, repbuf, &replen,
                              SECFINI_RPC_TIMEOUT);

        OBD_FREE(repbuf, repbuf_size);
        return rc;
}

/**********************************************
 * structure definitions                      *
 **********************************************/
struct gss_sec {
        struct ptlrpc_sec       gs_base;
        struct gss_api_mech    *gs_mech;
#ifdef __KERNEL__
        spinlock_t              gs_lock;
        struct list_head        gs_upcalls;
        char                    gs_pipepath[64];
        struct dentry          *gs_depipe;
#endif
};

static rwlock_t gss_ctx_lock = RW_LOCK_UNLOCKED;

#ifdef __KERNEL__

struct gss_upcall_msg {
        struct rpc_pipe_msg             gum_base;
        atomic_t                        gum_refcount;
        struct list_head                gum_list;
        struct gss_sec                 *gum_gsec;
        wait_queue_head_t               gum_waitq;
        char                            gum_obdname[64];
        uid_t                           gum_uid;
        __u32                           gum_ip; /* XXX IPv6? */
        __u32                           gum_svc;
        __u32                           gum_pad;
};

/**********************************************
 * rpc_pipe upcall helpers                    *
 **********************************************/
static
void gss_release_msg(struct gss_upcall_msg *gmsg)
{
        ENTRY;
        LASSERT(atomic_read(&gmsg->gum_refcount) > 0);

        if (!atomic_dec_and_test(&gmsg->gum_refcount)) {
                CDEBUG(D_SEC, "gmsg %p ref %d\n", gmsg,
                       atomic_read(&gmsg->gum_refcount));
                EXIT;
                return;
        }
        LASSERT(list_empty(&gmsg->gum_list));
        OBD_FREE(gmsg, sizeof(*gmsg));
        EXIT;
}

static void
gss_unhash_msg_nolock(struct gss_upcall_msg *gmsg)
{
        ENTRY;
        if (list_empty(&gmsg->gum_list)) {
                EXIT;
                return;
        }
        /* FIXME should not do this. when we in upper upcall queue,
         * downcall will call unhash_msg, thus later put_msg might
         * free msg buffer while it's not dequeued XXX */
        list_del_init(&gmsg->gum_base.list);
        /* FIXME */

        list_del_init(&gmsg->gum_list);
        wake_up(&gmsg->gum_waitq);
        atomic_dec(&gmsg->gum_refcount);
        CDEBUG(D_SEC, "gmsg %p refcount now %d\n",
               gmsg, atomic_read(&gmsg->gum_refcount));
        LASSERT(atomic_read(&gmsg->gum_refcount) > 0);
        EXIT;
}

static void
gss_unhash_msg(struct gss_upcall_msg *gmsg)
{
        struct gss_sec *gsec = gmsg->gum_gsec;

        spin_lock(&gsec->gs_lock);
        gss_unhash_msg_nolock(gmsg);
        spin_unlock(&gsec->gs_lock);
}

static
struct gss_upcall_msg * gss_find_upcall(struct gss_sec *gsec,
                                        char *obdname,
                                        uid_t uid, __u32 dest_ip)
{
        struct gss_upcall_msg *gmsg;
        ENTRY;

        list_for_each_entry(gmsg, &gsec->gs_upcalls, gum_list) {
                if (gmsg->gum_uid != uid)
                        continue;
                if (gmsg->gum_ip != dest_ip)
                        continue;
                if (strcmp(gmsg->gum_obdname, obdname))
                        continue;
                atomic_inc(&gmsg->gum_refcount);
                CDEBUG(D_SEC, "found gmsg at %p: obdname %s, uid %d, ref %d\n",
                       gmsg, obdname, uid, atomic_read(&gmsg->gum_refcount));
                RETURN(gmsg);
        }
        RETURN(NULL);
}

static void gss_init_upcall_msg(struct gss_upcall_msg *gmsg,
                                struct gss_sec *gsec,
                                char *obdname,
                                uid_t uid, __u32 dest_ip, __u32 svc)
{
        struct rpc_pipe_msg *rpcmsg;
        ENTRY;

        /* 2 refs: 1 for hash, 1 for current user */
        init_waitqueue_head(&gmsg->gum_waitq);
        list_add(&gmsg->gum_list, &gsec->gs_upcalls);
        atomic_set(&gmsg->gum_refcount, 2);
        gmsg->gum_gsec = gsec;
        strncpy(gmsg->gum_obdname, obdname, sizeof(gmsg->gum_obdname));
        gmsg->gum_uid = uid;
        gmsg->gum_ip = dest_ip;
        gmsg->gum_svc = svc;

        rpcmsg = &gmsg->gum_base;
        rpcmsg->data = &gmsg->gum_uid;
        rpcmsg->len = sizeof(gmsg->gum_uid) + sizeof(gmsg->gum_ip) +
                      sizeof(gmsg->gum_svc) + sizeof(gmsg->gum_pad);
        EXIT;
}
#endif /* __KERNEL__ */

/********************************************
 * gss cred manupulation helpers            *
 ********************************************/
static
int gss_cred_is_uptodate_ctx(struct ptlrpc_cred *cred)
{
        struct gss_cred *gcred = container_of(cred, struct gss_cred, gc_base);
        int res = 0;

        read_lock(&gss_ctx_lock);
        if ((cred->pc_flags & PTLRPC_CRED_UPTODATE) && gcred->gc_ctx)
                res = 1;
        read_unlock(&gss_ctx_lock);
        return res;
}

static inline
struct gss_cl_ctx * gss_get_ctx(struct gss_cl_ctx *ctx)
{
        atomic_inc(&ctx->gc_refcount);
        return ctx;
}

static
void gss_destroy_ctx(struct gss_cl_ctx *ctx)
{
        ENTRY;

        CDEBUG(D_SEC, "destroy cl_ctx %p\n", ctx);
        if (ctx->gc_gss_ctx)
                kgss_delete_sec_context(&ctx->gc_gss_ctx);

        if (ctx->gc_wire_ctx.len > 0) {
                OBD_FREE(ctx->gc_wire_ctx.data, ctx->gc_wire_ctx.len);
                ctx->gc_wire_ctx.len = 0;
        }

        OBD_FREE(ctx, sizeof(*ctx));
}

static
void gss_put_ctx(struct gss_cl_ctx *ctx)
{
        if (atomic_dec_and_test(&ctx->gc_refcount))
                gss_destroy_ctx(ctx);
}

static
struct gss_cl_ctx *gss_cred_get_ctx(struct ptlrpc_cred *cred)
{
        struct gss_cred *gcred = container_of(cred, struct gss_cred, gc_base);
        struct gss_cl_ctx *ctx = NULL;

        read_lock(&gss_ctx_lock);
        if (gcred->gc_ctx)
                ctx = gss_get_ctx(gcred->gc_ctx);
        read_unlock(&gss_ctx_lock);
        return ctx;
}

static
void gss_cred_set_ctx(struct ptlrpc_cred *cred, struct gss_cl_ctx *ctx)
{
        struct gss_cred *gcred = container_of(cred, struct gss_cred, gc_base);
        struct gss_cl_ctx *old;
        __u64 ctx_expiry;
        ENTRY;

        if (kgss_inquire_context(ctx->gc_gss_ctx, &ctx_expiry)) {
                CERROR("unable to get expire time\n");
                ctx_expiry = 1; /* make it expired now */
        }
        cred->pc_expire = (unsigned long) ctx_expiry;

        write_lock(&gss_ctx_lock);
        old = gcred->gc_ctx;
        gcred->gc_ctx = ctx;
        cred->pc_flags |= PTLRPC_CRED_UPTODATE;
        write_unlock(&gss_ctx_lock);
        if (old)
                gss_put_ctx(old);

        CWARN("client refreshed gss cred %p(uid %u)\n", cred, cred->pc_uid);
        EXIT;
}

static int
simple_get_bytes(char **buf, __u32 *buflen, void *res, __u32 reslen)
{
        if (*buflen < reslen) {
                CERROR("buflen %u < %u\n", *buflen, reslen);
                return -EINVAL;
        }

        memcpy(res, *buf, reslen);
        *buf += reslen;
        *buflen -= reslen;
        return 0;
}

/* data passed down:
 *  - uid
 *  - timeout
 *  - gc_win / error
 *  - wire_ctx (rawobj)
 *  - mech_ctx? (rawobj)
 */
static
int gss_parse_init_downcall(struct gss_api_mech *gm, rawobj_t *buf,
                            struct gss_cl_ctx **gc, struct vfs_cred *vcred,
                            __u32 *dest_ip, int *gss_err)
{
        char *p = buf->data;
        __u32 len = buf->len;
        struct gss_cl_ctx *ctx;
        rawobj_t tmp_buf;
        unsigned int timeout;
        int err = -EIO;
        ENTRY;

        *gc = NULL;

        OBD_ALLOC(ctx, sizeof(*ctx));
        if (!ctx)
                RETURN(-ENOMEM);

        ctx->gc_proc = RPC_GSS_PROC_DATA;
        ctx->gc_seq = 0;
        spin_lock_init(&ctx->gc_seq_lock);
        atomic_set(&ctx->gc_refcount,1);

        if (simple_get_bytes(&p, &len, &vcred->vc_uid, sizeof(vcred->vc_uid)))
                GOTO(err_free_ctx, err);
        vcred->vc_pag = vcred->vc_uid; /* FIXME */
        if (simple_get_bytes(&p, &len, dest_ip, sizeof(*dest_ip)))
                GOTO(err_free_ctx, err);
        /* FIXME: discarded timeout for now */
        if (simple_get_bytes(&p, &len, &timeout, sizeof(timeout)))
                GOTO(err_free_ctx, err);
        *gss_err = 0;
        if (simple_get_bytes(&p, &len, &ctx->gc_win, sizeof(ctx->gc_win)))
                GOTO(err_free_ctx, err);
        /* gssd signals an error by passing ctx->gc_win = 0: */
        if (!ctx->gc_win) {
                /* in which case the next int is an error code: */
                if (simple_get_bytes(&p, &len, gss_err, sizeof(*gss_err)))
                        GOTO(err_free_ctx, err);
                GOTO(err_free_ctx, err = 0);
        }
        if (rawobj_extract_local(&tmp_buf, (__u32 **) &p, &len))
                GOTO(err_free_ctx, err);
        if (rawobj_dup(&ctx->gc_wire_ctx, &tmp_buf)) {
                GOTO(err_free_ctx, err = -ENOMEM);
        }
        if (rawobj_extract_local(&tmp_buf, (__u32 **) &p, &len))
                GOTO(err_free_wire_ctx, err);
        if (len) {
                CERROR("unexpected trailing %u bytes\n", len);
                GOTO(err_free_wire_ctx, err);
        }
        if (kgss_import_sec_context(&tmp_buf, gm, &ctx->gc_gss_ctx))
                GOTO(err_free_wire_ctx, err);

        *gc = ctx;
        RETURN(0);

err_free_wire_ctx:
        if (ctx->gc_wire_ctx.data)
                OBD_FREE(ctx->gc_wire_ctx.data, ctx->gc_wire_ctx.len);
err_free_ctx:
        OBD_FREE(ctx, sizeof(*ctx));
        CDEBUG(D_SEC, "err_code %d, gss code %d\n", err, *gss_err);
        return err;
}

/***************************************
 * cred APIs                           *
 ***************************************/
#ifdef __KERNEL__
static int gss_cred_refresh(struct ptlrpc_cred *cred)
{
        struct obd_import          *import;
        struct gss_sec             *gsec;
        struct gss_upcall_msg      *gss_msg, *gss_new;
        struct dentry              *dentry;
        char                       *obdname, *obdtype;
        wait_queue_t                wait;
        uid_t                       uid = cred->pc_uid;
        ptl_nid_t                   peer_nid;
        __u32                       dest_ip, svc;
        int                         res;
        ENTRY;

        if (ptlrpcs_cred_is_uptodate(cred))
                RETURN(0);

        LASSERT(cred->pc_sec);
        LASSERT(cred->pc_sec->ps_import);
        LASSERT(cred->pc_sec->ps_import->imp_obd);

        import = cred->pc_sec->ps_import;
        if (!import->imp_connection) {
                CERROR("import has no connection set\n");
                RETURN(-EINVAL);
        }

        peer_nid = import->imp_connection->c_peer.peer_id.nid;
        dest_ip = (__u32) (peer_nid & 0xFFFFFFFF);

        obdtype = import->imp_obd->obd_type->typ_name;
        if (!strcmp(obdtype, "mdc"))
                svc = 0;
        else if (!strcmp(obdtype, "osc"))
                svc = 1;
        else {
                CERROR("gss on %s?\n", obdtype);
                RETURN(-EINVAL);
        }

        gsec = container_of(cred->pc_sec, struct gss_sec, gs_base);
        obdname = import->imp_obd->obd_name;
        dentry = gsec->gs_depipe;
        gss_new = NULL;
        res = 0;

        CWARN("Initiate gss context %p(%u@%s)\n",
               container_of(cred, struct gss_cred, gc_base),
               uid, import->imp_target_uuid.uuid);

again:
        spin_lock(&gsec->gs_lock);
        gss_msg = gss_find_upcall(gsec, obdname, uid, dest_ip);
        if (gss_msg) {
                spin_unlock(&gsec->gs_lock);
                GOTO(waiting, res);
        }
        if (!gss_new) {
                spin_unlock(&gsec->gs_lock);
                OBD_ALLOC(gss_new, sizeof(*gss_new));
                if (!gss_new) {
                        CERROR("fail to alloc memory\n");
                        RETURN(-ENOMEM);
                }
                goto again;
        }
        /* so far we'v created gss_new */
        gss_init_upcall_msg(gss_new, gsec, obdname, uid, dest_ip, svc);

        if (gss_cred_is_uptodate_ctx(cred)) {
                /* someone else had done it for us, simply cancel
                 * our own upcall */
                CDEBUG(D_SEC, "cred("LPU64"/%u) has been refreshed by someone "
                       "else, simply drop our request\n",
                       cred->pc_pag, cred->pc_uid);
                gss_unhash_msg_nolock(gss_new);
                spin_unlock(&gsec->gs_lock);
                gss_release_msg(gss_new);
                RETURN(0);
        }

        /* need to make upcall now */
        spin_unlock(&gsec->gs_lock);
        res = rpc_queue_upcall(dentry->d_inode, &gss_new->gum_base);
        if (res) {
                CERROR("rpc_queue_upcall failed: %d\n", res);
                gss_unhash_msg(gss_new);
                gss_release_msg(gss_new);
                RETURN(res);
        }
        gss_msg = gss_new;

waiting:
        init_waitqueue_entry(&wait, current);
        spin_lock(&gsec->gs_lock);
        add_wait_queue(&gss_msg->gum_waitq, &wait);
        set_current_state(TASK_INTERRUPTIBLE);
        spin_unlock(&gsec->gs_lock);

        schedule();

        remove_wait_queue(&gss_msg->gum_waitq, &wait);
        if (signal_pending(current)) {
                CERROR("interrupted gss upcall %p\n", gss_msg);
                res = -EINTR;
        }
        gss_release_msg(gss_msg);
        RETURN(res);
}
#else /* !__KERNEL__ */
extern int lgss_handle_krb5_upcall(uid_t uid, __u32 dest_ip,
                                   char *obd_name,
                                   char *buf, int bufsize,
                                   int (*callback)(char*, unsigned long));

static int gss_cred_refresh(struct ptlrpc_cred *cred)
{
        char                    buf[4096];
        rawobj_t                obj;
        struct obd_import      *imp;
        struct gss_sec         *gsec;
        struct gss_api_mech    *mech;
        struct gss_cl_ctx      *ctx = NULL;
        struct vfs_cred         vcred = { 0 };
        ptl_nid_t               peer_nid;
        __u32                   dest_ip;
        __u32                   subflavor;
        int                     rc, gss_err;

        LASSERT(cred);
        LASSERT(cred->pc_sec);
        LASSERT(cred->pc_sec->ps_import);
        LASSERT(cred->pc_sec->ps_import->imp_obd);

        if (ptlrpcs_cred_is_uptodate(cred))
                RETURN(0);

        imp = cred->pc_sec->ps_import;
        peer_nid = imp->imp_connection->c_peer.peer_id.nid;
        dest_ip = (__u32) (peer_nid & 0xFFFFFFFF);
        subflavor = cred->pc_sec->ps_flavor.subflavor;

        if (subflavor != PTLRPC_SEC_GSS_KRB5I) {
                CERROR("unknown subflavor %u\n", subflavor);
                GOTO(err_out, rc = -EINVAL);
        }

        rc = lgss_handle_krb5_upcall(cred->pc_uid, dest_ip,
                                     imp->imp_obd->obd_name,
                                     buf, sizeof(buf),
                                     gss_send_secinit_rpc);
        LASSERT(rc != 0);
        if (rc < 0)
                goto err_out;

        obj.data = buf;
        obj.len = rc;

        gsec = container_of(cred->pc_sec, struct gss_sec, gs_base);
        mech = gsec->gs_mech;
        LASSERT(mech);
        rc = gss_parse_init_downcall(mech, &obj, &ctx, &vcred, &dest_ip,
                                     &gss_err);
        if (rc) {
                CERROR("parse init downcall error %d\n", rc);
                goto err_out;
        }

        if (gss_err) {
                CERROR("cred fresh got gss error %x\n", gss_err);
                rc = -EINVAL;
                goto err_out;
        }

        gss_cred_set_ctx(cred, ctx);
        LASSERT(gss_cred_is_uptodate_ctx(cred));

        return 0;
err_out:
        cred->pc_flags |= PTLRPC_CRED_DEAD;
        return rc;
}
#endif

static int gss_cred_match(struct ptlrpc_cred *cred,
                          struct ptlrpc_request *req,
                          struct vfs_cred *vcred)
{
        RETURN(cred->pc_pag == vcred->vc_pag);
}

static int gss_cred_sign(struct ptlrpc_cred *cred,
                         struct ptlrpc_request *req)
{
        struct gss_cred         *gcred;
        struct gss_cl_ctx       *ctx;
        rawobj_t                 lmsg, mic;
        __u32                   *vp, *vpsave, vlen, seclen;
        __u32                    seqnum, major, rc = 0;
        ENTRY;

        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_cred == cred);

        gcred = container_of(cred, struct gss_cred, gc_base);
        ctx = gss_cred_get_ctx(cred);
        if (!ctx) {
                CERROR("cred %p("LPU64"/%u) invalidated?\n",
                        cred, cred->pc_pag, cred->pc_uid);
                RETURN(-EPERM);
        }

        lmsg.len = req->rq_reqlen;
        lmsg.data = (__u8 *) req->rq_reqmsg;

        vp = (__u32 *) (lmsg.data + lmsg.len);
        vlen = req->rq_reqbuf_len - sizeof(struct ptlrpcs_wire_hdr) -
               lmsg.len;
        seclen = vlen;

        if (vlen < 6 * 4 + size_round4(ctx->gc_wire_ctx.len)) {
                CERROR("vlen %d, need %d\n",
                        vlen, 6 * 4 + size_round4(ctx->gc_wire_ctx.len));
                rc = -EIO;
                goto out;
        }

        spin_lock(&ctx->gc_seq_lock);
        seqnum = ctx->gc_seq++;
        spin_unlock(&ctx->gc_seq_lock);

        *vp++ = cpu_to_le32(PTLRPC_SEC_GSS_VERSION);    /* version */
        *vp++ = cpu_to_le32(PTLRPC_SEC_GSS_KRB5I);      /* subflavor */
        *vp++ = cpu_to_le32(ctx->gc_proc);              /* proc */
        *vp++ = cpu_to_le32(seqnum);                    /* seq */
        *vp++ = cpu_to_le32(PTLRPC_GSS_SVC_INTEGRITY);  /* service */
        vlen -= 5 * 4;

        if (rawobj_serialize(&ctx->gc_wire_ctx, &vp, &vlen)) {
                rc = -EIO;
                goto out;
        }
        CDEBUG(D_SEC, "encoded wire_ctx length %d\n", ctx->gc_wire_ctx.len);

        vpsave = vp++;  /* reserve for size */
        vlen -= 4;

        mic.len = vlen;
        mic.data = (char *) vp;

        CDEBUG(D_SEC, "reqbuf at %p, lmsg at %p, len %d, mic at %p, len %d\n",
               req->rq_reqbuf, lmsg.data, lmsg.len, mic.data, mic.len);
        major = kgss_get_mic(ctx->gc_gss_ctx, GSS_C_QOP_DEFAULT, &lmsg, &mic);
        if (major) {
                CERROR("gss compute mic error, major %x\n", major);
                rc = -EACCES;
                goto out;
        }

        *vpsave = cpu_to_le32(mic.len);
        
        seclen = seclen - vlen + mic.len;
        buf_to_sec_hdr(req->rq_reqbuf)->sec_len = cpu_to_le32(seclen);
        req->rq_reqdata_len += size_round(seclen);
        CDEBUG(D_SEC, "msg size %d, checksum size %d, total sec size %d\n",
               lmsg.len, mic.len, seclen);
out:
        gss_put_ctx(ctx);
        RETURN(rc);
}

static int gss_cred_verify(struct ptlrpc_cred *cred,
                           struct ptlrpc_request *req)
{
        struct gss_cred        *gcred;
        struct gss_cl_ctx      *ctx;
        struct ptlrpcs_wire_hdr *sec_hdr;
        rawobj_t                lmsg, mic;
        __u32                   *vp, vlen, subflavor, proc, seq, svc;
        __u32                   major, minor, rc;
        ENTRY;

        LASSERT(req->rq_repbuf);
        LASSERT(req->rq_cred == cred);

        sec_hdr = buf_to_sec_hdr(req->rq_repbuf);
        vp = (__u32 *) (req->rq_repbuf + sizeof(*sec_hdr) + sec_hdr->msg_len);
        vlen = sec_hdr->sec_len;

        if (vlen < 7 * 4) {
                CERROR("reply sec size %u too small\n", vlen);
                RETURN(-EPROTO);
        }

        if (*vp++ != cpu_to_le32(PTLRPC_SEC_GSS_VERSION)) {
                CERROR("reply have different gss version\n");
                RETURN(-EPROTO);
        }
        subflavor = le32_to_cpu(*vp++);
        proc = le32_to_cpu(*vp++);
        vlen -= 3 * 4;

        switch (proc) {
        case PTLRPC_GSS_PROC_DATA:
                seq = le32_to_cpu(*vp++);
                svc = le32_to_cpu(*vp++);
                if (svc != PTLRPC_GSS_SVC_INTEGRITY) {
                        CERROR("Unknown svc %d\n", svc);
                        RETURN(-EPROTO);
                }
                if (*vp++ != 0) {
                        CERROR("Unexpected ctx handle\n");
                        RETURN(-EPROTO);
                }
                mic.len = le32_to_cpu(*vp++);
                vlen -= 4 * 4;
                if (vlen < mic.len) {
                        CERROR("vlen %d, mic.len %d\n", vlen, mic.len);
                        RETURN(-EINVAL);
                }
                mic.data = (char *) vp;

                gcred = container_of(cred, struct gss_cred, gc_base);
                ctx = gss_cred_get_ctx(cred);
                LASSERT(ctx);

                lmsg.len = sec_hdr->msg_len;
                lmsg.data = (__u8 *) buf_to_lustre_msg(req->rq_repbuf);

                major = kgss_verify_mic(ctx->gc_gss_ctx, &lmsg, &mic, NULL);
                if (major != GSS_S_COMPLETE) {
                        CERROR("gss verify mic error: major %x\n", major);
                        GOTO(proc_data_out, rc = -EINVAL);
                }

                req->rq_repmsg = (struct lustre_msg *) lmsg.data;
                req->rq_replen = lmsg.len;

                /* here we could check the seq number is the same one
                 * we sent to server. but portals has prevent us from
                 * replay attack, so maybe we don't need check it again.
                 */
                rc = 0;
proc_data_out:
                gss_put_ctx(ctx);
                break;
        case PTLRPC_GSS_PROC_ERR:
                major = le32_to_cpu(*vp++);
                minor = le32_to_cpu(*vp++);
                /* server return NO_CONTEXT might be caused by context expire
                 * or server reboot/failover. we refresh the cred transparently
                 * to upper layer.
                 * In some cases, our gss handle is possible to be incidentally
                 * identical to another handle since the handle itself is not
                 * fully random. In krb5 case, the GSS_S_BAD_SIG will be
                 * returned, maybe other gss error for other mechanism. Here we
                 * only consider krb5 mech (FIXME) and try to establish new
                 * context.
                 */
                if (major == GSS_S_NO_CONTEXT ||
                    major == GSS_S_BAD_SIG) {
                        CWARN("req %p: server report cred %p %s, expired?\n",
                               req, cred, (major == GSS_S_NO_CONTEXT) ?
                                           "NO_CONTEXT" : "BAD_SIG");

                        ptlrpcs_cred_die(cred);
                        rc = ptlrpcs_req_replace_dead_cred(req);
                        if (!rc)
                                req->rq_ptlrpcs_restart = 1;
                        else
                                CERROR("replace dead cred failed %d\n", rc);
                } else {
                        CERROR("Unrecognized gss error (%x/%x)\n",
                                major, minor);
                        rc = -EACCES;
                }
                break;
        default:
                CERROR("unknown gss proc %d\n", proc);
                rc = -EPROTO;
        }

        RETURN(rc);
}

static int gss_cred_seal(struct ptlrpc_cred *cred,
                         struct ptlrpc_request *req)
{
        struct gss_cred         *gcred;
        struct gss_cl_ctx       *ctx;
        struct ptlrpcs_wire_hdr *sec_hdr;
        rawobj_buf_t             msg_buf;
        rawobj_t                 cipher_buf;
        __u32                   *vp, *vpsave, vlen, seclen;
        __u32                    major, seqnum, rc = 0;
        ENTRY;

        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_cred == cred);

        gcred = container_of(cred, struct gss_cred, gc_base);
        ctx = gss_cred_get_ctx(cred);
        if (!ctx) {
                CERROR("cred %p("LPU64"/%u) invalidated?\n",
                        cred, cred->pc_pag, cred->pc_uid);
                RETURN(-EPERM);
        }

        vp = (__u32 *) (req->rq_reqbuf + sizeof(*sec_hdr));
        vlen = req->rq_reqbuf_len - sizeof(*sec_hdr);
        seclen = vlen;

        if (vlen < 6 * 4 + size_round4(ctx->gc_wire_ctx.len)) {
                CERROR("vlen %d, need %d\n",
                        vlen, 6 * 4 + size_round4(ctx->gc_wire_ctx.len));
                rc = -EIO;
                goto out;
        }

        spin_lock(&ctx->gc_seq_lock);
        seqnum = ctx->gc_seq++;
        spin_unlock(&ctx->gc_seq_lock);

        *vp++ = cpu_to_le32(PTLRPC_SEC_GSS_VERSION);    /* version */
        *vp++ = cpu_to_le32(PTLRPC_SEC_GSS_KRB5P);      /* subflavor */
        *vp++ = cpu_to_le32(ctx->gc_proc);              /* proc */
        *vp++ = cpu_to_le32(seqnum);                    /* seq */
        *vp++ = cpu_to_le32(PTLRPC_GSS_SVC_PRIVACY);    /* service */
        vlen -= 5 * 4;

        if (rawobj_serialize(&ctx->gc_wire_ctx, &vp, &vlen)) {
                rc = -EIO;
                goto out;
        }
        CDEBUG(D_SEC, "encoded wire_ctx length %d\n", ctx->gc_wire_ctx.len);

        vpsave = vp++;  /* reserve for size */
        vlen -= 4;

        msg_buf.buf = (__u8 *) req->rq_reqmsg - GSS_PRIVBUF_PREFIX_LEN;
        msg_buf.buflen = req->rq_reqlen + GSS_PRIVBUF_PREFIX_LEN + GSS_PRIVBUF_SUFFIX_LEN;
        msg_buf.dataoff = GSS_PRIVBUF_PREFIX_LEN;
        msg_buf.datalen = req->rq_reqlen;

        cipher_buf.data = (__u8 *) vp;
        cipher_buf.len = vlen;

        major = kgss_wrap(ctx->gc_gss_ctx, GSS_C_QOP_DEFAULT,
                          &msg_buf, &cipher_buf);
        if (major) {
                CERROR("error wrap: major 0x%x\n", major);
                GOTO(out, rc = -EINVAL);
        }

        *vpsave = cpu_to_le32(cipher_buf.len);

        seclen = seclen - vlen + cipher_buf.len;
        sec_hdr = buf_to_sec_hdr(req->rq_reqbuf);
        sec_hdr->sec_len = cpu_to_le32(seclen);
        req->rq_reqdata_len += size_round(seclen);

        CDEBUG(D_SEC, "msg size %d, total sec size %d\n",
               req->rq_reqlen, seclen);
out:
        gss_put_ctx(ctx);
        RETURN(rc);
}

static int gss_cred_unseal(struct ptlrpc_cred *cred,
                           struct ptlrpc_request *req)
{
        struct gss_cred        *gcred;
        struct gss_cl_ctx      *ctx;
        struct ptlrpcs_wire_hdr *sec_hdr;
        rawobj_t                cipher_text, plain_text;
        __u32                   *vp, vlen, subflavor, proc, seq, svc;
        int                     rc;
        ENTRY;

        LASSERT(req->rq_repbuf);
        LASSERT(req->rq_cred == cred);

        sec_hdr = buf_to_sec_hdr(req->rq_repbuf);
        if (sec_hdr->msg_len != 0) {
                CERROR("unexpected msg_len %u\n", sec_hdr->msg_len);
                RETURN(-EPROTO);
        }

        vp = (__u32 *) (req->rq_repbuf + sizeof(*sec_hdr));
        vlen = sec_hdr->sec_len;

        if (vlen < 7 * 4) {
                CERROR("reply sec size %u too small\n", vlen);
                RETURN(-EPROTO);
        }

        if (*vp++ != cpu_to_le32(PTLRPC_SEC_GSS_VERSION)) {
                CERROR("reply have different gss version\n");
                RETURN(-EPROTO);
        }
        subflavor = le32_to_cpu(*vp++);
        proc = le32_to_cpu(*vp++);
        seq = le32_to_cpu(*vp++);
        svc = le32_to_cpu(*vp++);
        vlen -= 5 * 4;

        switch (proc) {
        case PTLRPC_GSS_PROC_DATA:
                if (svc != PTLRPC_GSS_SVC_PRIVACY) {
                        CERROR("Unknown svc %d\n", svc);
                        RETURN(-EPROTO);
                }
                if (*vp++ != 0) {
                        CERROR("Unexpected ctx handle\n");
                        RETURN(-EPROTO);
                }
                vlen -= 4;

                cipher_text.len = le32_to_cpu(*vp++);
                cipher_text.data = (__u8 *) vp;
                vlen -= 4;

                if (vlen < cipher_text.len) {
                        CERROR("cipher text to be %u while buf only %u\n",
                                cipher_text.len, vlen);
                        RETURN(-EPROTO);
                }

                plain_text = cipher_text;

                gcred = container_of(cred, struct gss_cred, gc_base);
                ctx = gss_cred_get_ctx(cred);
                LASSERT(ctx);

                rc = kgss_unwrap(ctx->gc_gss_ctx, GSS_C_QOP_DEFAULT,
                                 &cipher_text, &plain_text);
                if (rc) {
                        CERROR("error unwrap: 0x%x\n", rc);
                        GOTO(proc_out, rc = -EINVAL);
                }

                req->rq_repmsg = (struct lustre_msg *) vp;
                req->rq_replen = plain_text.len;

                rc = 0;
proc_out:
                gss_put_ctx(ctx);
                break;
        default:
                CERROR("unknown gss proc %d\n", proc);
                rc = -EPROTO;
        }

        RETURN(rc);
}

static void destroy_gss_context(struct ptlrpc_cred *cred)
{
        struct ptlrpcs_wire_hdr *hdr;
        struct lustre_msg       *lmsg;
        struct gss_cred         *gcred;
        struct ptlrpc_request    req;
        struct obd_import       *imp;
        __u32                   *vp, lmsg_size;
        ENTRY;

        /* cred's refcount is 0, steal one */
        atomic_inc(&cred->pc_refcount);

        gcred = container_of(cred, struct gss_cred, gc_base);
        gcred->gc_ctx->gc_proc = PTLRPC_GSS_PROC_DESTROY;
        imp = cred->pc_sec->ps_import;
        LASSERT(imp);

        if (!(cred->pc_flags & PTLRPC_CRED_UPTODATE)) {
                CWARN("Destroy a dead gss cred %p(%u@%s), don't send rpc\n",
                       gcred, cred->pc_uid, imp->imp_target_uuid.uuid);
                atomic_dec(&cred->pc_refcount);
                EXIT;
                return;
        }

        CWARN("client destroy gss cred %p(%u@%s)\n",
               gcred, cred->pc_uid, imp->imp_target_uuid.uuid);

        lmsg_size = lustre_msg_size(0, NULL);
        req.rq_reqbuf_len = sizeof(*hdr) + lmsg_size +
                            ptlrpcs_est_req_payload(cred->pc_sec, lmsg_size);

        OBD_ALLOC(req.rq_reqbuf, req.rq_reqbuf_len);
        if (!req.rq_reqbuf) {
                CERROR("Fail to alloc reqbuf, cancel anyway\n");
                atomic_dec(&cred->pc_refcount);
                EXIT;
                return;
        }

        /* wire hdr */
        hdr = buf_to_sec_hdr(req.rq_reqbuf);
        hdr->flavor  = cpu_to_le32(PTLRPC_SEC_GSS);
        hdr->sectype = cpu_to_le32(PTLRPC_SEC_TYPE_AUTH);
        hdr->msg_len = cpu_to_le32(lmsg_size);
        hdr->sec_len = cpu_to_le32(0);

        /* lustre message */
        lmsg = buf_to_lustre_msg(req.rq_reqbuf);
        lustre_init_msg(lmsg, 0, NULL, NULL);
        lmsg->handle   = imp->imp_remote_handle;
        lmsg->type     = PTL_RPC_MSG_REQUEST;
        lmsg->opc      = SEC_FINI;
        lmsg->flags    = 0;
        lmsg->conn_cnt = imp->imp_conn_cnt;
        /* add this for randomize */
        get_random_bytes(&lmsg->last_xid, sizeof(lmsg->last_xid));
        get_random_bytes(&lmsg->transno, sizeof(lmsg->transno));

        vp = (__u32 *) req.rq_reqbuf;

        req.rq_cred = cred;
        req.rq_reqmsg = buf_to_lustre_msg(req.rq_reqbuf);
        req.rq_reqlen = lmsg_size;
        req.rq_reqdata_len = sizeof(*hdr) + lmsg_size;

        if (gss_cred_sign(cred, &req)) {
                CERROR("failed to sign, cancel anyway\n");
                atomic_dec(&cred->pc_refcount);
                goto exit;
        }
        atomic_dec(&cred->pc_refcount);

        /* send out */
        gss_send_secfini_rpc(imp, req.rq_reqbuf, req.rq_reqdata_len);
exit:
        OBD_FREE(req.rq_reqbuf, req.rq_reqbuf_len);
        EXIT;
}

static void gss_cred_destroy(struct ptlrpc_cred *cred)
{
        struct gss_cred *gcred;
        ENTRY;

        LASSERT(cred);
        LASSERT(!atomic_read(&cred->pc_refcount));

        gcred = container_of(cred, struct gss_cred, gc_base);
        if (gcred->gc_ctx) {
                destroy_gss_context(cred);
                gss_put_ctx(gcred->gc_ctx);
        }

        CDEBUG(D_SEC, "GSS_SEC: destroy cred %p\n", gcred);

        OBD_FREE(gcred, sizeof(*gcred));
        EXIT;
}

static struct ptlrpc_credops gss_credops = {
        .refresh        = gss_cred_refresh,
        .match          = gss_cred_match,
        .sign           = gss_cred_sign,
        .verify         = gss_cred_verify,
        .seal           = gss_cred_seal,
        .unseal         = gss_cred_unseal,
        .destroy        = gss_cred_destroy,
};

#ifdef __KERNEL__
/*******************************************
 * rpc_pipe APIs                           *
 *******************************************/
static ssize_t
gss_pipe_upcall(struct file *filp, struct rpc_pipe_msg *msg,
                char *dst, size_t buflen)
{
        char *data = (char *)msg->data + msg->copied;
        ssize_t mlen = msg->len;
        ssize_t left;
        ENTRY;

        if (mlen > buflen)
                mlen = buflen;
        left = copy_to_user(dst, data, mlen);
        if (left < 0) {
                msg->errno = left;
                RETURN(left);
        }
        mlen -= left;
        msg->copied += mlen;
        msg->errno = 0;
        RETURN(mlen);
}

static ssize_t
gss_pipe_downcall(struct file *filp, const char *src, size_t mlen)
{
        char *buf;
        const int bufsize = 1024;
        rawobj_t obj;
        struct inode *inode = filp->f_dentry->d_inode;
        struct rpc_inode *rpci = RPC_I(inode);
        struct obd_import *import;
        struct ptlrpc_sec *sec;
        struct gss_sec *gsec;
        char *obdname;
        struct gss_api_mech *mech;
        struct vfs_cred vcred = { 0 };
        struct ptlrpc_cred *cred;
        struct gss_upcall_msg *gss_msg;
        struct gss_cl_ctx *ctx = NULL;
        __u32  dest_ip;
        ssize_t left;
        int err, gss_err;
        ENTRY;

        if (mlen > bufsize) {
                CERROR("mlen %ld > bufsize %d\n", (long)mlen, bufsize);
                RETURN(-ENOSPC);
        }

        OBD_ALLOC(buf, bufsize);
        if (!buf) {
                CERROR("alloc mem failed\n");
                RETURN(-ENOMEM);
        }

        left = copy_from_user(buf, src, mlen);
        if (left)
                GOTO(err_free, err = -EFAULT);

        obj.data = buf;
        obj.len = mlen;

        LASSERT(rpci->private);
        gsec = (struct gss_sec *)rpci->private;
        sec = &gsec->gs_base;
        LASSERT(sec->ps_import);
        import = class_import_get(sec->ps_import);
        LASSERT(import->imp_obd);
        obdname = import->imp_obd->obd_name;
        mech = gsec->gs_mech;

        err = gss_parse_init_downcall(mech, &obj, &ctx, &vcred, &dest_ip,
                                      &gss_err);
        if (err) {
                CERROR("parse downcall err %d\n", err);
                GOTO(err, err);
        }
        cred = ptlrpcs_cred_lookup(sec, &vcred);
        if (!cred) {
                CWARN("didn't find cred\n");
                GOTO(err, err);
        }
        if (gss_err) {
                CERROR("got gss err %d, set cred %p dead\n", gss_err, cred);
                cred->pc_flags |= PTLRPC_CRED_DEAD;
        } else {
                CDEBUG(D_SEC, "get initial ctx:\n");
                gss_cred_set_ctx(cred, ctx);
        }

        spin_lock(&gsec->gs_lock);
        gss_msg = gss_find_upcall(gsec, obdname, vcred.vc_uid, dest_ip);
        if (gss_msg) {
                gss_unhash_msg_nolock(gss_msg);
                spin_unlock(&gsec->gs_lock);
                gss_release_msg(gss_msg);
        } else
                spin_unlock(&gsec->gs_lock);

        ptlrpcs_cred_put(cred, 1);
        class_import_put(import);
        OBD_FREE(buf, bufsize);
        RETURN(mlen);
err:
        if (ctx)
                gss_destroy_ctx(ctx);
        class_import_put(import);
err_free:
        OBD_FREE(buf, bufsize);
        CDEBUG(D_SEC, "gss_pipe_downcall returning %d\n", err);
        RETURN(err);
}

static
void gss_pipe_destroy_msg(struct rpc_pipe_msg *msg)
{
        struct gss_upcall_msg *gmsg;
        static unsigned long ratelimit;
        ENTRY;

        if (msg->errno >= 0) {
                EXIT;
                return;
        }

        gmsg = container_of(msg, struct gss_upcall_msg, gum_base);
        CDEBUG(D_SEC, "destroy gmsg %p\n", gmsg);
        atomic_inc(&gmsg->gum_refcount);
        gss_unhash_msg(gmsg);
        if (msg->errno == -ETIMEDOUT || msg->errno == -EPIPE) {
                unsigned long now = get_seconds();
                if (time_after(now, ratelimit)) {
                        CWARN("GSS_SEC upcall timed out.\n"
                              "Please check user daemon is running!\n");
                        ratelimit = now + 15;
                }
        }
        gss_release_msg(gmsg);
        EXIT;
}

static
void gss_pipe_release(struct inode *inode)
{
        struct rpc_inode *rpci = RPC_I(inode);
        struct ptlrpc_sec *sec;
        struct gss_sec *gsec;
        ENTRY;

        gsec = (struct gss_sec *)rpci->private;
        sec = &gsec->gs_base;
        spin_lock(&gsec->gs_lock);
        while (!list_empty(&gsec->gs_upcalls)) {
                struct gss_upcall_msg *gmsg;

                gmsg = list_entry(gsec->gs_upcalls.next,
                                  struct gss_upcall_msg, gum_list);
                gmsg->gum_base.errno = -EPIPE;
                atomic_inc(&gmsg->gum_refcount);
                gss_unhash_msg_nolock(gmsg);
                gss_release_msg(gmsg);
        }
        spin_unlock(&gsec->gs_lock);
        EXIT;
}

static struct rpc_pipe_ops gss_upcall_ops = {
        .upcall         = gss_pipe_upcall,
        .downcall       = gss_pipe_downcall,
        .destroy_msg    = gss_pipe_destroy_msg,
        .release_pipe   = gss_pipe_release,
};
#endif /* __KERNEL__ */

/*********************************************
 * GSS security APIs                         *
 *********************************************/

static
struct ptlrpc_sec* gss_create_sec(ptlrpcs_flavor_t *flavor,
                                  const char *pipe_dir,
                                  void *pipe_data)
{
        struct gss_sec *gsec;
        struct ptlrpc_sec *sec;
        char *pos;
        ENTRY;

        LASSERT(flavor->flavor == PTLRPC_SEC_GSS);

        OBD_ALLOC(gsec, sizeof(*gsec));
        if (!gsec) {
                CERROR("can't alloc gsec\n");
                RETURN(NULL);
        }

        gsec->gs_mech = kgss_subflavor_to_mech(flavor->subflavor);
        if (!gsec->gs_mech) {
                CERROR("subflavor %d not found\n", flavor->subflavor);
                goto err_free;
        }

        /* initialize gss sec */
#ifdef __KERNEL__
        INIT_LIST_HEAD(&gsec->gs_upcalls);
        spin_lock_init(&gsec->gs_lock);

        snprintf(gsec->gs_pipepath, sizeof(gsec->gs_pipepath),
                 LUSTRE_PIPEDIR"/%s", pipe_dir);
        if (IS_ERR(rpc_mkdir(gsec->gs_pipepath, NULL))) {
                CERROR("can't make pipedir %s\n", gsec->gs_pipepath);
                goto err_mech_put;
        }

        snprintf(gsec->gs_pipepath, sizeof(gsec->gs_pipepath),
                 LUSTRE_PIPEDIR"/%s/%s", pipe_dir, gsec->gs_mech->gm_name); 
        gsec->gs_depipe = rpc_mkpipe(gsec->gs_pipepath, gsec,
                                     &gss_upcall_ops, RPC_PIPE_WAIT_FOR_OPEN);
        if (IS_ERR(gsec->gs_depipe)) {
                CERROR("failed to make rpc_pipe %s: %ld\n",
                        gsec->gs_pipepath, PTR_ERR(gsec->gs_depipe));
                goto err_rmdir;
        }
        CDEBUG(D_SEC, "gss sec %p, pipe path %s\n", gsec, gsec->gs_pipepath);
#endif

        sec = &gsec->gs_base;

        switch (flavor->subflavor) {
        case PTLRPC_SEC_GSS_KRB5I:
                sec->ps_sectype = PTLRPC_SEC_TYPE_AUTH;
                break;
        case PTLRPC_SEC_GSS_KRB5P:
                sec->ps_sectype = PTLRPC_SEC_TYPE_PRIV;
                break;
        default:
                LBUG();
        }

        sec->ps_expire = GSS_CREDCACHE_EXPIRE;
        sec->ps_nextgc = get_seconds() + sec->ps_expire;
        sec->ps_flags = 0;

        CDEBUG(D_SEC, "Create GSS security instance at %p(external %p)\n",
               gsec, sec);
        RETURN(sec);

#ifdef __KERNEL__
err_rmdir:
        pos = strrchr(gsec->gs_pipepath, '/');
        LASSERT(pos);
        *pos = 0;
        rpc_rmdir(gsec->gs_pipepath);
err_mech_put:
#endif
        kgss_mech_put(gsec->gs_mech);
err_free:
        OBD_FREE(gsec, sizeof(*gsec));
        RETURN(NULL);
}

static
void gss_destroy_sec(struct ptlrpc_sec *sec)
{
        struct gss_sec *gsec;
        char *pos;
        ENTRY;

        gsec = container_of(sec, struct gss_sec, gs_base);
        CDEBUG(D_SEC, "Destroy GSS security instance at %p\n", gsec);

        LASSERT(gsec->gs_mech);
        LASSERT(!atomic_read(&sec->ps_refcount));
        LASSERT(!atomic_read(&sec->ps_credcount));
#ifdef __KERNEL__
        rpc_unlink(gsec->gs_pipepath);
        pos = strrchr(gsec->gs_pipepath, '/');
        LASSERT(pos);
        *pos = 0;
        rpc_rmdir(gsec->gs_pipepath);
#endif

        kgss_mech_put(gsec->gs_mech);
        OBD_FREE(gsec, sizeof(*gsec));
        EXIT;
}

static
struct ptlrpc_cred * gss_create_cred(struct ptlrpc_sec *sec,
                                     struct ptlrpc_request *req,
                                     struct vfs_cred *vcred)
{
        struct gss_cred *gcred;
        struct ptlrpc_cred *cred;
        ENTRY;

        OBD_ALLOC(gcred, sizeof(*gcred));
        if (!gcred)
                RETURN(NULL);

        cred = &gcred->gc_base;
        INIT_LIST_HEAD(&cred->pc_hash);
        atomic_set(&cred->pc_refcount, 0);
        cred->pc_sec = sec;
        cred->pc_ops = &gss_credops;
        cred->pc_req = req;
        cred->pc_expire = get_seconds() + GSS_CRED_EXPIRE;
        cred->pc_flags = 0;
        cred->pc_pag = vcred->vc_pag;
        cred->pc_uid = vcred->vc_uid;
        CDEBUG(D_SEC, "create a gss cred at %p("LPU64"/%u)\n",
               cred, vcred->vc_pag, vcred->vc_uid);

        RETURN(cred);
}

static int gss_estimate_payload(struct ptlrpc_sec *sec, int msgsize)
{
        switch (sec->ps_sectype) {
        case PTLRPC_SEC_TYPE_AUTH:
                return GSS_MAX_AUTH_PAYLOAD;
        case PTLRPC_SEC_TYPE_PRIV:
                return size_round16(GSS_MAX_AUTH_PAYLOAD + msgsize +
                                    GSS_PRIVBUF_PREFIX_LEN +
                                    GSS_PRIVBUF_SUFFIX_LEN);
        default:
                LBUG();
                return 0;
        }
}

static int gss_alloc_reqbuf(struct ptlrpc_sec *sec,
                            struct ptlrpc_request *req,
                            int lmsg_size)
{
        int msg_payload, sec_payload;
        int privacy, rc;
        ENTRY;

        /* In PRIVACY mode, lustre message is always 0 (already encoded into
         * security payload).
         */
        privacy = sec->ps_sectype == PTLRPC_SEC_TYPE_PRIV;
        msg_payload = privacy ? 0 : lmsg_size;
        sec_payload = gss_estimate_payload(sec, lmsg_size);

        rc = sec_alloc_reqbuf(sec, req, msg_payload, sec_payload);
        if (rc)
                return rc;

        if (privacy) {
                int buflen = lmsg_size + GSS_PRIVBUF_PREFIX_LEN +
                             GSS_PRIVBUF_SUFFIX_LEN;
                char *buf;

                OBD_ALLOC(buf, buflen);
                if (!buf) {
                        CERROR("Fail to alloc %d\n", buflen);
                        sec_free_reqbuf(sec, req);
                        RETURN(-ENOMEM);
                }
                req->rq_reqmsg = (struct lustre_msg *)
                                        (buf + GSS_PRIVBUF_PREFIX_LEN);
        }

        RETURN(0);
}

static void gss_free_reqbuf(struct ptlrpc_sec *sec,
                            struct ptlrpc_request *req)
{
        char *buf;
        int privacy;
        ENTRY;

        LASSERT(req->rq_reqmsg);
        LASSERT(req->rq_reqlen);

        privacy = sec->ps_sectype == PTLRPC_SEC_TYPE_PRIV;
        if (privacy) {
                buf = (char *) req->rq_reqmsg - GSS_PRIVBUF_PREFIX_LEN;
                LASSERT(buf < req->rq_reqbuf ||
                        buf >= req->rq_reqbuf + req->rq_reqbuf_len);
                OBD_FREE(buf, req->rq_reqlen + GSS_PRIVBUF_PREFIX_LEN +
                              GSS_PRIVBUF_SUFFIX_LEN);
                req->rq_reqmsg = NULL;
        }

        sec_free_reqbuf(sec, req);
}

static struct ptlrpc_secops gss_secops = {
        .create_sec             = gss_create_sec,
        .destroy_sec            = gss_destroy_sec,
        .create_cred            = gss_create_cred,
        .est_req_payload        = gss_estimate_payload,
        .est_rep_payload        = gss_estimate_payload,
        .alloc_reqbuf           = gss_alloc_reqbuf,
        .free_reqbuf            = gss_free_reqbuf,
};

static struct ptlrpc_sec_type gss_type = {
        .pst_owner      = THIS_MODULE,
        .pst_name       = "GSS_SEC",
        .pst_inst       = ATOMIC_INIT(0),
        .pst_flavor     = {PTLRPC_SEC_GSS, 0},
        .pst_ops        = &gss_secops,
};

extern int
(*lustre_secinit_downcall_handler)(char *buffer, unsigned long count);

int __init ptlrpcs_gss_init(void)
{
        int rc;

        rc = ptlrpcs_register(&gss_type);
        if (rc)
                return rc;

#ifdef __KERNEL__
        gss_svc_init();

        rc = PTR_ERR(rpc_mkdir(LUSTRE_PIPEDIR, NULL));
        if (IS_ERR((void *)rc) && rc != -EEXIST) {
                CERROR("fail to make rpcpipedir for lustre\n");
                gss_svc_exit();
                ptlrpcs_unregister(&gss_type);
                return -1;
        }
        rc = 0;
#else
#endif
        rc = init_kerberos_module();
        if (rc) {
                ptlrpcs_unregister(&gss_type);
        }

        lustre_secinit_downcall_handler = gss_send_secinit_rpc;

        return rc;
}

static void __exit ptlrpcs_gss_exit(void)
{
        lustre_secinit_downcall_handler = NULL;

        cleanup_kerberos_module();
#ifndef __KERNEL__
#else
        rpc_rmdir(LUSTRE_PIPEDIR);
        gss_svc_exit();
#endif
        ptlrpcs_unregister(&gss_type);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("GSS Security module for Lustre");
MODULE_LICENSE("GPL");

module_init(ptlrpcs_gss_init);
module_exit(ptlrpcs_gss_exit);
