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

#define LUSTRE_PIPEDIR          "/lustre"

#define GSS_CREDCACHE_EXPIRE    (30 * 60)          /* 30 minute */

#define GSS_TIMEOUT_DELTA       (5)
#define CRED_REFRESH_UPCALL_TIMEOUT                             \
        ({                                                      \
                int timeout = obd_timeout - GSS_TIMEOUT_DELTA;  \
                                                                \
                if (timeout < GSS_TIMEOUT_DELTA * 2)            \
                        timeout = GSS_TIMEOUT_DELTA * 2;        \
                timeout;                                        \
        })
#define SECINIT_RPC_TIMEOUT                                     \
        ({                                                      \
                int timeout = CRED_REFRESH_UPCALL_TIMEOUT -     \
                              GSS_TIMEOUT_DELTA;                \
                if (timeout < GSS_TIMEOUT_DELTA)                \
                        timeout = GSS_TIMEOUT_DELTA;            \
                timeout;                                        \
        })
#define SECFINI_RPC_TIMEOUT     (GSS_TIMEOUT_DELTA)


/**********************************************
 * gss security init/fini helper              *
 **********************************************/

static int secinit_compose_request(struct obd_import *imp,
                                   char *buf, int bufsize,
                                   int lustre_srv,
                                   uid_t uid, gid_t gid,
                                   long token_size,
                                   char __user *token)
{
        struct ptlrpcs_wire_hdr *hdr;
        struct lustre_msg       *lmsg;
        struct mds_req_sec_desc *secdesc;
        int                      size = sizeof(*secdesc);
        __u32                    lmsg_size, *p;
        int                      rc;

        lmsg_size = lustre_msg_size(1, &size);

        if (sizeof(*hdr) + lmsg_size + size_round(token_size) > bufsize) {
                CERROR("token size %ld too large\n", token_size);
                return -EINVAL;
        }

        /* security wire hdr */
        hdr = buf_to_sec_hdr(buf);
        hdr->flavor  = cpu_to_le32(PTLRPCS_FLVR_GSS_NONE);
        hdr->msg_len = cpu_to_le32(lmsg_size);
        hdr->sec_len = cpu_to_le32(8 * 4 + token_size);

        /* lustre message & secdesc */
        lmsg = buf_to_lustre_msg(buf);

        lustre_init_msg(lmsg, 1, &size, NULL);
        secdesc = lustre_msg_buf(lmsg, 0, size);
        secdesc->rsd_uid = secdesc->rsd_fsuid = uid;
        secdesc->rsd_gid = secdesc->rsd_fsgid = gid;
        secdesc->rsd_cap = secdesc->rsd_ngroups = 0;

        lmsg->handle   = imp->imp_remote_handle;
        lmsg->type     = PTL_RPC_MSG_REQUEST;
        lmsg->opc      = SEC_INIT;
        lmsg->flags    = 0;
        lmsg->conn_cnt = imp->imp_conn_cnt;

        p = (__u32 *) (buf + sizeof(*hdr) + lmsg_size);

        /* gss hdr */
        *p++ = cpu_to_le32(PTLRPC_SEC_GSS_VERSION);     /* gss version */
        *p++ = cpu_to_le32(PTLRPCS_FLVR_KRB5I);         /* subflavor */
        *p++ = cpu_to_le32(PTLRPCS_GSS_PROC_INIT);      /* proc */
        *p++ = cpu_to_le32(0);                          /* seq */
        *p++ = cpu_to_le32(PTLRPCS_GSS_SVC_NONE);       /* service */
        *p++ = cpu_to_le32(0);                          /* context handle */

        /* plus lustre svc type */
        *p++ = cpu_to_le32(lustre_srv);

        /* now the token part */
        *p++ = cpu_to_le32((__u32) token_size);
        LASSERT(((char *)p - buf) + token_size <= bufsize);

        rc = copy_from_user(p, token, token_size);
        if (rc) {
                CERROR("can't copy token\n");
                return -EFAULT;
        }

        rc = size_round(((char *)p - buf) + token_size);
        return rc;
}

static int secinit_parse_reply(char *repbuf, int replen,
                               char __user *outbuf, long outlen)
{
        __u32                   *p = (__u32 *)repbuf;
        struct ptlrpcs_wire_hdr *hdr = (struct ptlrpcs_wire_hdr *) repbuf;
        __u32                    lmsg_len, sec_len, status;
        __u32                    major, minor, seq, obj_len, round_len;
        __u32                    effective = 0;

        if (replen <= (4 + 6) * 4) {
                CERROR("reply size %d too small\n", replen);
                return -EINVAL;
        }

        hdr->flavor = le32_to_cpu(hdr->flavor);
        hdr->msg_len = le32_to_cpu(hdr->msg_len);
        hdr->sec_len = le32_to_cpu(hdr->sec_len);

        lmsg_len = le32_to_cpu(p[2]);
        sec_len = le32_to_cpu(p[3]);

        /* sanity checks */
        if (hdr->flavor != PTLRPCS_FLVR_GSS_NONE) {
                CERROR("unexpected reply\n");
                return -EINVAL;
        }
        if (hdr->msg_len % 8 ||
            sizeof(*hdr) + hdr->msg_len + hdr->sec_len > replen) {
                CERROR("unexpected reply\n");
                return -EINVAL;
        }
        if (hdr->sec_len > outlen) {
                CERROR("outbuf too small\n");
                return -EINVAL;
        }

        p = (__u32 *) buf_to_sec_data(repbuf);
        effective = 0;

        status = le32_to_cpu(*p++);
        major = le32_to_cpu(*p++);
        minor = le32_to_cpu(*p++);
        seq = le32_to_cpu(*p++);
        effective += 4 * 4;

        if (copy_to_user(outbuf, &status, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, &major, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, &minor, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, &seq, 4))
                return -EFAULT;
        outbuf += 4;

        obj_len = le32_to_cpu(*p++);
        round_len = (obj_len + 3) & ~ 3;
        if (copy_to_user(outbuf, &obj_len, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, (char *)p, round_len))
                return -EFAULT;
        p += round_len / 4;
        outbuf += round_len;
        effective += 4 + round_len;

        obj_len = le32_to_cpu(*p++);
        round_len = (obj_len + 3) & ~ 3;
        if (copy_to_user(outbuf, &obj_len, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, (char *)p, round_len))
                return -EFAULT;
        p += round_len / 4;
        outbuf += round_len;
        effective += 4 + round_len;

        return effective;
}

/* XXX move to where lgssd could see */
struct lgssd_ioctl_param {
        int             version;        /* in   */
        char           *uuid;           /* in   */
        int             lustre_svc;     /* in   */
        uid_t           uid;            /* in   */
        gid_t           gid;            /* in   */
        long            send_token_size;/* in   */
        char           *send_token;     /* in   */
        long            reply_buf_size; /* in   */
        char           *reply_buf;      /* in   */
        long            status;         /* out  */
        long            reply_length;   /* out  */
};

static int gss_send_secinit_rpc(__user char *buffer, unsigned long count)
{
        struct obd_import        *imp;
        struct ptlrpc_request    *request = NULL;
        struct lgssd_ioctl_param  param;
        const int                 reqbuf_size = 1024;
        const int                 repbuf_size = 1024;
        char                     *reqbuf, *repbuf;
        struct obd_device        *obd;
        char                      obdname[64];
        long                      lsize;
        int                       rc, reqlen, replen;

        if (count != sizeof(param)) {
                CERROR("ioctl size %lu, expect %d, please check lgssd version\n",
                        count, sizeof(param));
                RETURN(-EINVAL);
        }
        if (copy_from_user(&param, buffer, sizeof(param))) {
                CERROR("failed copy data from lgssd\n");
                RETURN(-EFAULT);
        }

        if (param.version != GSSD_INTERFACE_VERSION) {
                CERROR("gssd interface version %d (expect %d)\n",
                        param.version, GSSD_INTERFACE_VERSION);
                RETURN(-EINVAL);
        }

        /* take name */
        if (strncpy_from_user(obdname, param.uuid,
                              sizeof(obdname)) <= 0) {
                CERROR("Invalid obdname pointer\n");
                RETURN(-EFAULT);
        }

        obd = class_name2obd(obdname);
        if (!obd) {
                CERROR("no such obd %s\n", obdname);
                RETURN(-EINVAL);
        }

        imp = class_import_get(obd->u.cli.cl_import);

        OBD_ALLOC(reqbuf, reqbuf_size);
        OBD_ALLOC(repbuf, reqbuf_size);

        if (!reqbuf || !repbuf) {
                CERROR("Can't alloc buffer: %p/%p\n", reqbuf, repbuf);
                param.status = -ENOMEM;
                goto out_copy;
        }

        /* get token */
        reqlen = secinit_compose_request(imp, reqbuf, reqbuf_size,
                                         param.lustre_svc,
                                         param.uid, param.gid,
                                         param.send_token_size,
                                         param.send_token);
        if (reqlen < 0) {
                param.status = reqlen;
                goto out_copy;
        }

        request = ptl_do_rawrpc(imp, reqbuf, reqbuf_size, reqlen,
                                repbuf, repbuf_size, &replen,
                                SECINIT_RPC_TIMEOUT, &rc);
        if (request == NULL || rc) {
                param.status = rc;
                goto out_copy;
        }

        if (replen > param.reply_buf_size) {
                CERROR("output buffer size %ld too small, need %d\n",
                        param.reply_buf_size, replen);
                param.status = -EINVAL;
                goto out_copy;
        }

        lsize = secinit_parse_reply(repbuf, replen,
                                    param.reply_buf, param.reply_buf_size);
        if (lsize < 0) {
                param.status = (int) lsize;
                goto out_copy;
        }

        param.status = 0;
        param.reply_length = lsize;

out_copy:
        if (copy_to_user(buffer, &param, sizeof(param)))
                rc = -EFAULT;
        else
                rc = 0;

        class_import_put(imp);
        if (request == NULL) {
                if (repbuf)
                        OBD_FREE(repbuf, repbuf_size);
                if (reqbuf)
                        OBD_FREE(reqbuf, reqbuf_size);
        } else {
                rawrpc_req_finished(request);
        }
        RETURN(rc);
}

/**********************************************
 * structure definitions                      *
 **********************************************/
struct gss_sec {
        struct ptlrpc_sec       gs_base;
        struct gss_api_mech    *gs_mech;
        spinlock_t              gs_lock;
        struct list_head        gs_upcalls;
        char                   *gs_pipepath;
        struct dentry          *gs_depipe;
};

struct gss_upcall_msg_data {
        __u64                           gum_pag;
        __u32                           gum_uid;
        __u32                           gum_svc;
        __u32                           gum_nal;
        __u32                           gum_netid;
        __u64                           gum_nid;
};

struct gss_upcall_msg {
        struct rpc_pipe_msg             gum_base;
        atomic_t                        gum_refcount;
        struct list_head                gum_list;
        struct gss_sec                 *gum_gsec;
        wait_queue_head_t               gum_waitq;
        char                            gum_obdname[64];
        struct gss_upcall_msg_data      gum_data;
};

#ifdef __KERNEL__
static rwlock_t gss_ctx_lock = RW_LOCK_UNLOCKED;
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
#if 0
        LASSERT(list_empty(&gmsg->gum_base.list));
#else
        /* XXX */
        if (!list_empty(&gmsg->gum_base.list)) {
                int error = gmsg->gum_base.errno;
                
                CWARN("msg %p: list: %p/%p/%p, copied %d, err %d, wq %d\n",
                      gmsg, &gmsg->gum_base.list, gmsg->gum_base.list.prev,
                      gmsg->gum_base.list.next, gmsg->gum_base.copied, error,
                      list_empty(&gmsg->gum_waitq.task_list));
                LBUG();
        }
#endif
        OBD_FREE(gmsg, sizeof(*gmsg));
        EXIT;
}

static void
gss_unhash_msg_nolock(struct gss_upcall_msg *gmsg)
{
        LASSERT_SPIN_LOCKED(&gmsg->gum_gsec->gs_lock);

        if (list_empty(&gmsg->gum_list))
                return;

        list_del_init(&gmsg->gum_list);
        wake_up(&gmsg->gum_waitq);
        LASSERT(atomic_read(&gmsg->gum_refcount) > 1);
        atomic_dec(&gmsg->gum_refcount);
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
                                        struct gss_upcall_msg_data *gmd)
{
        struct gss_upcall_msg *gmsg;
        ENTRY;

        LASSERT_SPIN_LOCKED(&gsec->gs_lock);

        list_for_each_entry(gmsg, &gsec->gs_upcalls, gum_list) {
                if (memcmp(&gmsg->gum_data, gmd, sizeof(*gmd)))
                        continue;
                if (strcmp(gmsg->gum_obdname, obdname))
                        continue;
                LASSERT(atomic_read(&gmsg->gum_refcount) > 0);
                atomic_inc(&gmsg->gum_refcount);
                CDEBUG(D_SEC, "found gmsg at %p: obdname %s, uid %d, ref %d\n",
                       gmsg, obdname, gmd->gum_uid,
                       atomic_read(&gmsg->gum_refcount));
                RETURN(gmsg);
        }
        RETURN(NULL);
}

static void gss_init_upcall_msg(struct gss_upcall_msg *gmsg,
                                struct gss_sec *gsec, char *obdname,
                                struct gss_upcall_msg_data *gmd)
{
        struct rpc_pipe_msg *rpcmsg;
        ENTRY;

        /* 2 refs: 1 for hash, 1 for current user */
        init_waitqueue_head(&gmsg->gum_waitq);
        list_add(&gmsg->gum_list, &gsec->gs_upcalls);
        atomic_set(&gmsg->gum_refcount, 2);
        gmsg->gum_gsec = gsec;
        strncpy(gmsg->gum_obdname, obdname, sizeof(gmsg->gum_obdname));
        memcpy(&gmsg->gum_data, gmd, sizeof(*gmd));

        rpcmsg = &gmsg->gum_base;
        INIT_LIST_HEAD(&rpcmsg->list);
        rpcmsg->data = &gmsg->gum_data;
        rpcmsg->len = sizeof(gmsg->gum_data);
        rpcmsg->copied = 0;
        rpcmsg->errno = 0;
        EXIT;
}
#endif /* __KERNEL__ */

/* this seems to be used only from userspace code */
#ifndef __KERNEL__
/********************************************
 * gss cred manipulation helpers            *
 ********************************************/
static
int gss_cred_is_uptodate_ctx(struct ptlrpc_cred *cred)
{
        struct gss_cred *gcred = container_of(cred, struct gss_cred, gc_base);
        int res = 0;

        read_lock(&gss_ctx_lock);
        if (((cred->pc_flags & PTLRPC_CRED_FLAGS_MASK) ==
             PTLRPC_CRED_UPTODATE) &&
            gcred->gc_ctx)
                res = 1;
        read_unlock(&gss_ctx_lock);
        return res;
}
#endif

static inline
struct gss_cl_ctx *gss_get_ctx(struct gss_cl_ctx *ctx)
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
        set_bit(PTLRPC_CRED_UPTODATE_BIT, &cred->pc_flags);
        write_unlock(&gss_ctx_lock);
        if (old)
                gss_put_ctx(old);

        CDEBUG(D_SEC, "client refreshed gss cred %p(uid %u)\n",
               cred, cred->pc_uid);
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
                            struct gss_cl_ctx **gc,
                            struct gss_upcall_msg_data *gmd, int *gss_err)
{
        char *p = (char *)buf->data;
        struct gss_cl_ctx *ctx;
        __u32 len = buf->len;
        unsigned int timeout;
        rawobj_t tmp_buf;
        int err = -EPERM;
        ENTRY;

        *gc = NULL;
        *gss_err = 0;

        OBD_ALLOC(ctx, sizeof(*ctx));
        if (!ctx)
                RETURN(-ENOMEM);

        ctx->gc_proc = RPC_GSS_PROC_DATA;
        ctx->gc_seq = 0;
        spin_lock_init(&ctx->gc_seq_lock);
        atomic_set(&ctx->gc_refcount,1);

        if (simple_get_bytes(&p, &len, &gmd->gum_pag, sizeof(gmd->gum_pag)))
                goto err_free_ctx;
        if (simple_get_bytes(&p, &len, &gmd->gum_uid, sizeof(gmd->gum_uid)))
                goto err_free_ctx;
        if (simple_get_bytes(&p, &len, &gmd->gum_svc, sizeof(gmd->gum_svc)))
                goto err_free_ctx;
        if (simple_get_bytes(&p, &len, &gmd->gum_nal, sizeof(gmd->gum_nal)))
                goto err_free_ctx;
        if (simple_get_bytes(&p, &len, &gmd->gum_netid, sizeof(gmd->gum_netid)))
                goto err_free_ctx;
        if (simple_get_bytes(&p, &len, &gmd->gum_nid, sizeof(gmd->gum_nid)))
                goto err_free_ctx;
        /* FIXME: discarded timeout for now */
        if (simple_get_bytes(&p, &len, &timeout, sizeof(timeout)))
                goto err_free_ctx;
        if (simple_get_bytes(&p, &len, &ctx->gc_win, sizeof(ctx->gc_win)))
                goto err_free_ctx;

        /* lgssd signals an error by passing ctx->gc_win = 0: */
        if (!ctx->gc_win) {
                /* in which case the next 2 int are:
                 * - rpc error
                 * - gss error
                 */
                if (simple_get_bytes(&p, &len, &err, sizeof(err))) {
                        err = -EPERM;
                        goto err_free_ctx;
                }
                if (simple_get_bytes(&p, &len, gss_err, sizeof(*gss_err))) {
                        err = -EPERM;
                        goto err_free_ctx;
                }
                if (err == 0 && *gss_err == 0) {
                        CERROR("no error passed from downcall\n");
                        err = -EPERM;
                }
                goto err_free_ctx;
        }

        if (rawobj_extract_local(&tmp_buf, (__u32 **) ((void *)&p), &len))
                goto err_free_ctx;
        if (rawobj_dup(&ctx->gc_wire_ctx, &tmp_buf)) {
                err = -ENOMEM;
                goto err_free_ctx;
        }
        if (rawobj_extract_local(&tmp_buf, (__u32 **) ((void *)&p), &len))
                goto err_free_wire_ctx;
        if (len) {
                CERROR("unexpected trailing %u bytes\n", len);
                goto err_free_wire_ctx;
        }
        if (kgss_import_sec_context(&tmp_buf, gm, &ctx->gc_gss_ctx))
                goto err_free_wire_ctx;

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
        struct gss_upcall_msg_data  gmd;
        struct dentry              *dentry;
        char                       *obdname, *obdtype;
        wait_queue_t                wait;
        int                         res;
        ENTRY;

        might_sleep();

        /* any flags means it has been handled, do nothing */
        if (cred->pc_flags & PTLRPC_CRED_FLAGS_MASK)
                RETURN(0);

        LASSERT(cred->pc_sec);
        LASSERT(cred->pc_sec->ps_import);
        LASSERT(cred->pc_sec->ps_import->imp_obd);

        import = cred->pc_sec->ps_import;
        if (!import->imp_connection) {
                CERROR("import has no connection set\n");
                RETURN(-EINVAL);
        }

        gmd.gum_pag = cred->pc_pag;
        gmd.gum_uid = cred->pc_uid;
        gmd.gum_nal = import->imp_connection->c_peer.peer_ni->pni_number;
        gmd.gum_netid = 0;
        gmd.gum_nid = import->imp_connection->c_peer.peer_id.nid;

        obdtype = import->imp_obd->obd_type->typ_name;
        if (!strcmp(obdtype, OBD_MDC_DEVICENAME))
                gmd.gum_svc = LUSTRE_GSS_SVC_MDS;
        else if (!strcmp(obdtype, OBD_OSC_DEVICENAME))
                gmd.gum_svc = LUSTRE_GSS_SVC_OSS;
        else {
                CERROR("gss on %s?\n", obdtype);
                RETURN(-EINVAL);
        }

        gsec = container_of(cred->pc_sec, struct gss_sec, gs_base);
        obdname = import->imp_obd->obd_name;
        dentry = gsec->gs_depipe;
        gss_new = NULL;
        res = 0;

        CDEBUG(D_SEC, "Initiate gss context %p(%u@%s)\n",
               container_of(cred, struct gss_cred, gc_base),
               cred->pc_uid, import->imp_target_uuid.uuid);

again:
        spin_lock(&gsec->gs_lock);
        gss_msg = gss_find_upcall(gsec, obdname, &gmd);
        if (gss_msg) {
                if (gss_new) {
                        OBD_FREE(gss_new, sizeof(*gss_new));
                        gss_new = NULL;
                }
                GOTO(waiting, res);
        }

        if (!gss_new) {
                spin_unlock(&gsec->gs_lock);
                OBD_ALLOC(gss_new, sizeof(*gss_new));
                if (!gss_new)
                        RETURN(-ENOMEM);
                goto again;
        }
        /* so far we'v created gss_new */
        gss_init_upcall_msg(gss_new, gsec, obdname, &gmd);

        /* we'v created upcall msg, nobody else should touch the
         * flag of this cred, unless be set as dead/expire by
         * administrator via lctl etc.
         */
        if (cred->pc_flags & PTLRPC_CRED_FLAGS_MASK) {
                CWARN("cred %p("LPU64"/%u) was set flags %lx unexpectedly\n",
                      cred, cred->pc_pag, cred->pc_uid, cred->pc_flags);
                cred->pc_flags |= PTLRPC_CRED_DEAD | PTLRPC_CRED_ERROR;
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
                cred->pc_flags |= PTLRPC_CRED_DEAD | PTLRPC_CRED_ERROR;
                RETURN(res);
        }
        gss_msg = gss_new;
        spin_lock(&gsec->gs_lock);

waiting:
        /* upcall might finish quickly */
        if (list_empty(&gss_msg->gum_list)) {
                spin_unlock(&gsec->gs_lock);
                res = 0;
                goto out;
        }

        init_waitqueue_entry(&wait, current);
        set_current_state(TASK_INTERRUPTIBLE);
        add_wait_queue(&gss_msg->gum_waitq, &wait);
        spin_unlock(&gsec->gs_lock);

        if (gss_new)
                res = schedule_timeout(CRED_REFRESH_UPCALL_TIMEOUT * HZ);
        else {
                schedule();
                res = 0;
        }

        remove_wait_queue(&gss_msg->gum_waitq, &wait);

        /* - the one who refresh the cred for us should also be responsible
         *   to set the status of cred, we can simply return.
         * - if cred flags has been set, we also don't need to do that again,
         *   no matter signal pending or timeout etc.
         */
        if (!gss_new || cred->pc_flags & PTLRPC_CRED_FLAGS_MASK)
                goto out;

        if (signal_pending(current)) {
                CERROR("%s: cred %p: interrupted upcall\n",
                       current->comm, cred);
                cred->pc_flags |= PTLRPC_CRED_DEAD | PTLRPC_CRED_ERROR;
                res = -EINTR;
        } else if (res == 0) {
                CERROR("cred %p: upcall timedout\n", cred);
                set_bit(PTLRPC_CRED_DEAD_BIT, &cred->pc_flags);
                res = -ETIMEDOUT;
        } else
                res = 0;

out:
        gss_release_msg(gss_msg);

        RETURN(res);
}
#else /* !__KERNEL__ */
extern int lgss_handle_krb5_upcall(uid_t uid, __u32 dest_ip,
                                   char *obd_name, char *buf, int bufsize,
                                   int (*callback)(char*, unsigned long));

static int gss_cred_refresh(struct ptlrpc_cred *cred)
{
        char                    buf[4096];
        rawobj_t                obj;
        struct obd_import      *imp;
        struct gss_sec         *gsec;
        struct gss_api_mech    *mech;
        struct gss_cl_ctx      *ctx = NULL;
        ptl_nid_t               peer_nid;
        __u32                   dest_ip;
        __u32                   subflavor;
        int                     rc, gss_err;
        struct gss_upcall_msg_data gmd = { 0 };

        LASSERT(cred);
        LASSERT(cred->pc_sec);
        LASSERT(cred->pc_sec->ps_import);
        LASSERT(cred->pc_sec->ps_import->imp_obd);

        if (ptlrpcs_cred_is_uptodate(cred))
                RETURN(0);

        imp = cred->pc_sec->ps_import;
        peer_nid = imp->imp_connection->c_peer.peer_id.nid;
        dest_ip = (__u32) (peer_nid & 0xFFFFFFFF);
        subflavor = cred->pc_sec->ps_flavor;

        if (subflavor != PTLRPCS_SUBFLVR_KRB5I) {
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

        rc = gss_parse_init_downcall(mech, &obj, &ctx, &gmd,
                                     &gss_err);
        if (rc || gss_err) {
                CERROR("parse init downcall: rpc %d, gss 0x%x\n", rc, gss_err);
                if (rc != -ERESTART || gss_err != 0)
                        set_bit(PTLRPC_CRED_ERROR_BIT, &cred->pc_flags);
                if (rc == 0)
                        rc = -EPERM;
                goto err_out;
        }

        LASSERT(ctx);
        gss_cred_set_ctx(cred, ctx);
        LASSERT(gss_cred_is_uptodate_ctx(cred));

        return 0;
err_out:
        set_bit(PTLRPC_CRED_DEAD_BIT, &cred->pc_flags);
        return rc;
}
#endif

static int gss_cred_match(struct ptlrpc_cred *cred,
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
        *vp++ = cpu_to_le32(PTLRPCS_FLVR_KRB5I);        /* subflavor */
        *vp++ = cpu_to_le32(ctx->gc_proc);              /* proc */
        *vp++ = cpu_to_le32(seqnum);                    /* seq */
        *vp++ = cpu_to_le32(PTLRPCS_GSS_SVC_INTEGRITY); /* service */
        vlen -= 5 * 4;

        if (rawobj_serialize(&ctx->gc_wire_ctx, &vp, &vlen)) {
                rc = -EIO;
                goto out;
        }
        CDEBUG(D_SEC, "encoded wire_ctx length %d\n", ctx->gc_wire_ctx.len);

        vpsave = vp++;  /* reserve for size */
        vlen -= 4;

        mic.len = vlen;
        mic.data = (unsigned char *)vp;

        CDEBUG(D_SEC, "reqbuf at %p, lmsg at %p, len %d, mic at %p, len %d\n",
               req->rq_reqbuf, lmsg.data, lmsg.len, mic.data, mic.len);
        major = kgss_get_mic(ctx->gc_gss_ctx, GSS_C_QOP_DEFAULT, &lmsg, &mic);
        if (major) {
                CERROR("cred %p: req %p compute mic error, major %x\n",
                       cred, req, major);
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
        case PTLRPCS_GSS_PROC_DATA:
                seq = le32_to_cpu(*vp++);
                svc = le32_to_cpu(*vp++);
                if (svc != PTLRPCS_GSS_SVC_INTEGRITY) {
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
                mic.data = (unsigned char *)vp;

                gcred = container_of(cred, struct gss_cred, gc_base);
                ctx = gss_cred_get_ctx(cred);
                LASSERT(ctx);

                lmsg.len = sec_hdr->msg_len;
                lmsg.data = (__u8 *) buf_to_lustre_msg(req->rq_repbuf);

                major = kgss_verify_mic(ctx->gc_gss_ctx, &lmsg, &mic, NULL);
                if (major != GSS_S_COMPLETE) {
                        CERROR("cred %p: req %p verify mic error: major %x\n",
                               cred, req, major);

                        if (major == GSS_S_CREDENTIALS_EXPIRED ||
                            major == GSS_S_CONTEXT_EXPIRED) {
                                ptlrpcs_cred_expire(cred);
                                req->rq_ptlrpcs_restart = 1;
                                rc = 0;
                        } else
                                rc = -EINVAL;

                        GOTO(proc_data_out, rc);
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
        case PTLRPCS_GSS_PROC_ERR:
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
                        CWARN("req %p: server report cred %p %s\n",
                               req, cred, (major == GSS_S_NO_CONTEXT) ?
                                           "NO_CONTEXT" : "BAD_SIG");

                        ptlrpcs_cred_expire(cred);
                        req->rq_ptlrpcs_restart = 1;
                        rc = 0;
                } else {
                        CERROR("req %p: unrecognized gss error (%x/%x)\n",
                                req, major, minor);
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
        *vp++ = cpu_to_le32(PTLRPCS_FLVR_KRB5P);        /* subflavor */
        *vp++ = cpu_to_le32(ctx->gc_proc);              /* proc */
        *vp++ = cpu_to_le32(seqnum);                    /* seq */
        *vp++ = cpu_to_le32(PTLRPCS_GSS_SVC_PRIVACY);   /* service */
        vlen -= 5 * 4;

        if (rawobj_serialize(&ctx->gc_wire_ctx, &vp, &vlen)) {
                rc = -EIO;
                goto out;
        }
        CDEBUG(D_SEC, "encoded wire_ctx length %d\n", ctx->gc_wire_ctx.len);

        vpsave = vp++;  /* reserve for size */
        vlen -= 4;

        msg_buf.buf = (__u8 *) req->rq_reqmsg - GSS_PRIVBUF_PREFIX_LEN;
        msg_buf.buflen = req->rq_reqlen + GSS_PRIVBUF_PREFIX_LEN +
                                          GSS_PRIVBUF_SUFFIX_LEN;
        msg_buf.dataoff = GSS_PRIVBUF_PREFIX_LEN;
        msg_buf.datalen = req->rq_reqlen;

        cipher_buf.data = (__u8 *) vp;
        cipher_buf.len = vlen;

        major = kgss_wrap(ctx->gc_gss_ctx, GSS_C_QOP_DEFAULT,
                          &msg_buf, &cipher_buf);
        if (major) {
                CERROR("cred %p: error wrap: major 0x%x\n", cred, major);
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
        __u32                   major, rc;
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
        case PTLRPCS_GSS_PROC_DATA:
                if (svc != PTLRPCS_GSS_SVC_PRIVACY) {
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

                major = kgss_unwrap(ctx->gc_gss_ctx, GSS_C_QOP_DEFAULT,
                                    &cipher_text, &plain_text);
                if (major) {
                        CERROR("cred %p: error unwrap: major 0x%x\n",
                               cred, major);

                        if (major == GSS_S_CREDENTIALS_EXPIRED ||
                            major == GSS_S_CONTEXT_EXPIRED) {
                                ptlrpcs_cred_expire(cred);
                                req->rq_ptlrpcs_restart = 1;
                                rc = 0;
                        } else
                                rc = -EINVAL;

                        GOTO(proc_out, rc);
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
        struct ptlrpc_request   *raw_req = NULL;
        const int                repbuf_len = 256;
        char                    *repbuf;
        int                      replen, rc;
        ENTRY;

        imp = cred->pc_sec->ps_import;
        LASSERT(imp);

        if (test_bit(PTLRPC_CRED_ERROR_BIT, &cred->pc_flags) ||
            !test_bit(PTLRPC_CRED_UPTODATE_BIT, &cred->pc_flags)) {
                CDEBUG(D_SEC, "Destroy dead cred %p(%u@%s)\n",
                       cred, cred->pc_uid, imp->imp_target_uuid.uuid);
                EXIT;
                return;
        }

        might_sleep();

        /* cred's refcount is 0, steal one */
        atomic_inc(&cred->pc_refcount);

        gcred = container_of(cred, struct gss_cred, gc_base);
        gcred->gc_ctx->gc_proc = PTLRPCS_GSS_PROC_DESTROY;

        CDEBUG(D_SEC, "client destroy gss cred %p(%u@%s)\n",
               gcred, cred->pc_uid, imp->imp_target_uuid.uuid);

        lmsg_size = lustre_msg_size(0, NULL);
        req.rq_req_secflvr = cred->pc_sec->ps_flavor;
        req.rq_cred = cred;
        req.rq_reqbuf_len = sizeof(*hdr) + lmsg_size +
                            ptlrpcs_est_req_payload(&req, lmsg_size);

        OBD_ALLOC(req.rq_reqbuf, req.rq_reqbuf_len);
        if (!req.rq_reqbuf) {
                CERROR("Fail to alloc reqbuf, cancel anyway\n");
                atomic_dec(&cred->pc_refcount);
                EXIT;
                return;
        }

        /* wire hdr */
        hdr = buf_to_sec_hdr(req.rq_reqbuf);
        hdr->flavor  = cpu_to_le32(PTLRPCS_FLVR_GSS_AUTH);
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

        OBD_ALLOC(repbuf, repbuf_len);
        if (!repbuf)
                goto exit;

        raw_req = ptl_do_rawrpc(imp, req.rq_reqbuf, req.rq_reqbuf_len,
                                req.rq_reqdata_len, repbuf, repbuf_len, &replen,
                                SECFINI_RPC_TIMEOUT, &rc);
        if (!raw_req)
                OBD_FREE(repbuf, repbuf_len);

exit:
        if (raw_req == NULL)
                OBD_FREE(req.rq_reqbuf, req.rq_reqbuf_len);
        else
                rawrpc_req_finished(raw_req);
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

        CDEBUG(D_SEC, "sec.gss %p: destroy cred %p\n", cred->pc_sec, gcred);

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
        struct gss_upcall_msg_data gmd = { 0 };
        struct gss_cl_ctx *ctx = NULL;
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

        obj.data = (unsigned char *)buf;
        obj.len = mlen;

        LASSERT(rpci->private);
        gsec = (struct gss_sec *)rpci->private;
        sec = &gsec->gs_base;
        LASSERT(sec->ps_import);
        import = class_import_get(sec->ps_import);
        LASSERT(import->imp_obd);
        obdname = import->imp_obd->obd_name;
        mech = gsec->gs_mech;

        err = gss_parse_init_downcall(mech, &obj, &ctx, &gmd, &gss_err);
        if (err)
                CERROR("parse init downcall err %d\n", err);

        vcred.vc_pag = gmd.gum_pag;
        vcred.vc_uid = gmd.gum_uid;

        cred = ptlrpcs_cred_lookup(sec, &vcred);
        if (!cred) {
                CWARN("didn't find cred for uid %u\n", vcred.vc_uid);
                GOTO(err, err = -EINVAL);
        }

        if (err || gss_err) {
                set_bit(PTLRPC_CRED_DEAD_BIT, &cred->pc_flags);
                if (err != -ERESTART || gss_err != 0)
                        set_bit(PTLRPC_CRED_ERROR_BIT, &cred->pc_flags);
                CERROR("cred %p: rpc err %d, gss err 0x%x, fatal %d\n",
                       cred, err, gss_err,
                       (test_bit(PTLRPC_CRED_ERROR_BIT, &cred->pc_flags) != 0));
        } else {
                CDEBUG(D_SEC, "get initial ctx:\n");
                gss_cred_set_ctx(cred, ctx);
        }

        spin_lock(&gsec->gs_lock);
        gss_msg = gss_find_upcall(gsec, obdname, &gmd);
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

        LASSERT(list_empty(&msg->list));

        if (msg->errno >= 0) {
                EXIT;
                return;
        }

        gmsg = container_of(msg, struct gss_upcall_msg, gum_base);
        CDEBUG(D_SEC, "destroy gmsg %p\n", gmsg);
        LASSERT(atomic_read(&gmsg->gum_refcount) > 0);
        atomic_inc(&gmsg->gum_refcount);
        gss_unhash_msg(gmsg);
        if (msg->errno == -ETIMEDOUT || msg->errno == -EPIPE) {
                unsigned long now = get_seconds();
                if (time_after(now, ratelimit)) {
                        CWARN("sec.gss upcall timed out.\n"
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
                LASSERT(list_empty(&gmsg->gum_base.list));
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
struct ptlrpc_sec* gss_create_sec(__u32 flavor,
                                  const char *pipe_dir,
                                  void *pipe_data)
{
        struct gss_sec *gsec;
        struct ptlrpc_sec *sec;
        uid_t save_uid;

#ifdef __KERNEL__
        char *pos;
        int   pipepath_len;
#endif
        ENTRY;

        LASSERT(SEC_FLAVOR_MAJOR(flavor) == PTLRPCS_FLVR_MAJOR_GSS);

        OBD_ALLOC(gsec, sizeof(*gsec));
        if (!gsec) {
                CERROR("can't alloc gsec\n");
                RETURN(NULL);
        }

        gsec->gs_mech = kgss_subflavor_to_mech(SEC_FLAVOR_SUB(flavor));
        if (!gsec->gs_mech) {
                CERROR("subflavor 0x%x not found\n", flavor);
                goto err_free;
        }

        /* initialize gss sec */
#ifdef __KERNEL__
        INIT_LIST_HEAD(&gsec->gs_upcalls);
        spin_lock_init(&gsec->gs_lock);

        pipepath_len = strlen(LUSTRE_PIPEDIR) + strlen(pipe_dir) +
                       strlen(gsec->gs_mech->gm_name) + 3;
        OBD_ALLOC(gsec->gs_pipepath, pipepath_len);
        if (!gsec->gs_pipepath)
                goto err_mech_put;

        /* pipe rpc require root permission */
        save_uid = current->fsuid;
        current->fsuid = 0;

        sprintf(gsec->gs_pipepath, LUSTRE_PIPEDIR"/%s", pipe_dir);
        if (IS_ERR(rpc_mkdir(gsec->gs_pipepath, NULL))) {
                CERROR("can't make pipedir %s\n", gsec->gs_pipepath);
                goto err_free_path;
        }

        sprintf(gsec->gs_pipepath, LUSTRE_PIPEDIR"/%s/%s", pipe_dir,
                gsec->gs_mech->gm_name); 
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
        sec->ps_expire = GSS_CREDCACHE_EXPIRE;
        sec->ps_nextgc = get_seconds() + sec->ps_expire;
        sec->ps_flags = 0;

        current->fsuid = save_uid;

        CDEBUG(D_SEC, "Create sec.gss %p\n", gsec);
        RETURN(sec);

#ifdef __KERNEL__
err_rmdir:
        pos = strrchr(gsec->gs_pipepath, '/');
        LASSERT(pos);
        *pos = 0;
        rpc_rmdir(gsec->gs_pipepath);
err_free_path:
        current->fsuid = save_uid;
        OBD_FREE(gsec->gs_pipepath, pipepath_len);
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
#ifdef __KERNEL__
        char *pos;
        int   pipepath_len;
#endif
        ENTRY;

        gsec = container_of(sec, struct gss_sec, gs_base);
        CDEBUG(D_SEC, "Destroy sec.gss %p\n", gsec);

        LASSERT(gsec->gs_mech);
        LASSERT(!atomic_read(&sec->ps_refcount));
        LASSERT(!atomic_read(&sec->ps_credcount));
#ifdef __KERNEL__
        pipepath_len = strlen(gsec->gs_pipepath) + 1;
        rpc_unlink(gsec->gs_pipepath);
        pos = strrchr(gsec->gs_pipepath, '/');
        LASSERT(pos);
        *pos = 0;
        rpc_rmdir(gsec->gs_pipepath);
        OBD_FREE(gsec->gs_pipepath, pipepath_len);
#endif

        kgss_mech_put(gsec->gs_mech);
        OBD_FREE(gsec, sizeof(*gsec));
        EXIT;
}

static
struct ptlrpc_cred * gss_create_cred(struct ptlrpc_sec *sec,
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
        cred->pc_expire = 0;
        cred->pc_flags = 0;
        cred->pc_pag = vcred->vc_pag;
        cred->pc_uid = vcred->vc_uid;
        CDEBUG(D_SEC, "create a gss cred at %p("LPU64"/%u)\n",
               cred, vcred->vc_pag, vcred->vc_uid);

        RETURN(cred);
}

static int gss_estimate_payload(struct ptlrpc_sec *sec,
                                struct ptlrpc_request *req,
                                int msgsize)
{
        switch (SEC_FLAVOR_SVC(req->rq_req_secflvr)) {
        case PTLRPCS_SVC_AUTH:
                return GSS_MAX_AUTH_PAYLOAD;
        case PTLRPCS_SVC_PRIV:
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
        privacy = (SEC_FLAVOR_SVC(req->rq_req_secflvr) == PTLRPCS_SVC_PRIV);
        msg_payload = privacy ? 0 : lmsg_size;
        sec_payload = gss_estimate_payload(sec, req, lmsg_size);

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

        privacy = SEC_FLAVOR_SVC(req->rq_req_secflvr) == PTLRPCS_SVC_PRIV;
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
        .pst_name       = "sec.gss",
        .pst_inst       = ATOMIC_INIT(0),
        .pst_flavor     = PTLRPCS_FLVR_MAJOR_GSS,
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

#ifdef __KERNEL__
static void __exit ptlrpcs_gss_exit(void)
{
        lustre_secinit_downcall_handler = NULL;

        cleanup_kerberos_module();
        rpc_rmdir(LUSTRE_PIPEDIR);
        gss_svc_exit();
        ptlrpcs_unregister(&gss_type);
}
#endif

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("GSS Security module for Lustre");
MODULE_LICENSE("GPL");

module_init(ptlrpcs_gss_init);
module_exit(ptlrpcs_gss_exit);
