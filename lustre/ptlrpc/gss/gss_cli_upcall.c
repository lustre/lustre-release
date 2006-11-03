/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
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

#define LUSTRE_PIPE_ROOT        "/lustre"
#define LUSTRE_PIPE_KRB5        LUSTRE_PIPE_ROOT"/krb5"

struct gss_upcall_msg_data {
        __u32                           gum_seq;
        __u32                           gum_uid;
        __u32                           gum_gid;
        __u32                           gum_svc;        /* MDS/OSS... */
        __u64                           gum_nid;        /* peer NID */
        __u64                           gum_pag;
        __u8                            gum_obd[64];    /* client obd name */
};

struct gss_upcall_msg {
        struct rpc_pipe_msg             gum_base;
        atomic_t                        gum_refcount;
        struct list_head                gum_list;
        __u32                           gum_mechidx;
        struct gss_sec                 *gum_gsec;
        struct gss_cli_ctx             *gum_gctx;
        struct gss_upcall_msg_data      gum_data;
};

static atomic_t upcall_seq = ATOMIC_INIT(0);

static inline
__u32 upcall_get_sequence(void)
{
        return (__u32) atomic_inc_return(&upcall_seq);
}

enum mech_idx_t {
        MECH_KRB5   = 0,
        MECH_MAX
};

static inline
__u32 mech_name2idx(const char *name)
{
        LASSERT(!strcmp(name, "krb5"));
        return MECH_KRB5;
}

/* pipefs dentries for each mechanisms */
static struct dentry *de_pipes[MECH_MAX] = { NULL, };
/* all upcall messgaes linked here */
static struct list_head upcall_lists[MECH_MAX];
/* and protected by this */
static spinlock_t upcall_locks[MECH_MAX];

static inline
void upcall_list_lock(int idx)
{
        spin_lock(&upcall_locks[idx]);
}

static inline
void upcall_list_unlock(int idx)
{
        spin_unlock(&upcall_locks[idx]);
}

static
void upcall_msg_enlist(struct gss_upcall_msg *msg)
{
        __u32 idx = msg->gum_mechidx;

        upcall_list_lock(idx);
        list_add(&msg->gum_list, &upcall_lists[idx]);
        upcall_list_unlock(idx);
}

static
void upcall_msg_delist(struct gss_upcall_msg *msg)
{
        __u32 idx = msg->gum_mechidx;

        upcall_list_lock(idx);
        list_del_init(&msg->gum_list);
        upcall_list_unlock(idx);
}

/**********************************************
 * rpc_pipe upcall helpers                    *
 **********************************************/
static
void gss_release_msg(struct gss_upcall_msg *gmsg)
{
        ENTRY;
        LASSERT(atomic_read(&gmsg->gum_refcount) > 0);

        if (!atomic_dec_and_test(&gmsg->gum_refcount)) {
                EXIT;
                return;
        }

        if (gmsg->gum_gctx) {
                sptlrpc_ctx_wakeup(&gmsg->gum_gctx->gc_base);
                sptlrpc_ctx_put(&gmsg->gum_gctx->gc_base, 1);
                gmsg->gum_gctx = NULL;
        }

        LASSERT(list_empty(&gmsg->gum_list));
        LASSERT(list_empty(&gmsg->gum_base.list));
        OBD_FREE_PTR(gmsg);
        EXIT;
}

static
void gss_unhash_msg_nolock(struct gss_upcall_msg *gmsg)
{
        __u32 idx = gmsg->gum_mechidx;

        LASSERT(idx < MECH_MAX);
        LASSERT_SPIN_LOCKED(&upcall_locks[idx]);

        if (list_empty(&gmsg->gum_list))
                return;

        list_del_init(&gmsg->gum_list);
        LASSERT(atomic_read(&gmsg->gum_refcount) > 1);
        atomic_dec(&gmsg->gum_refcount);
}

static
void gss_unhash_msg(struct gss_upcall_msg *gmsg)
{
        __u32 idx = gmsg->gum_mechidx;

        LASSERT(idx < MECH_MAX);
        upcall_list_lock(idx);
        gss_unhash_msg_nolock(gmsg);
        upcall_list_unlock(idx);
}

static
void gss_msg_fail_ctx(struct gss_upcall_msg *gmsg)
{
        if (gmsg->gum_gctx) {
                struct ptlrpc_cli_ctx *ctx = &gmsg->gum_gctx->gc_base;

                LASSERT(atomic_read(&ctx->cc_refcount) > 0);
                sptlrpc_ctx_expire(ctx);
                set_bit(PTLRPC_CTX_ERROR_BIT, &ctx->cc_flags);
        }
}

static
struct gss_upcall_msg * gss_find_upcall(__u32 mechidx, __u32 seq)
{
        struct gss_upcall_msg *gmsg;

        upcall_list_lock(mechidx);
        list_for_each_entry(gmsg, &upcall_lists[mechidx], gum_list) {
                if (gmsg->gum_data.gum_seq != seq)
                        continue;

                LASSERT(atomic_read(&gmsg->gum_refcount) > 0);
                LASSERT(gmsg->gum_mechidx == mechidx);

                atomic_inc(&gmsg->gum_refcount);
                upcall_list_unlock(mechidx);
                return gmsg;
        }
        upcall_list_unlock(mechidx);
        return NULL;
}

static
int simple_get_bytes(char **buf, __u32 *buflen, void *res, __u32 reslen)
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

/*******************************************
 * rpc_pipe APIs                           *
 *******************************************/
static
ssize_t gss_pipe_upcall(struct file *filp, struct rpc_pipe_msg *msg,
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

static
ssize_t gss_pipe_downcall(struct file *filp, const char *src, size_t mlen)
{
        struct rpc_inode        *rpci = RPC_I(filp->f_dentry->d_inode);
        struct gss_upcall_msg   *gss_msg;
        struct ptlrpc_cli_ctx   *ctx;
        struct gss_cli_ctx      *gctx = NULL;
        char                    *buf, *data;
        int                      datalen;
        int                      timeout, rc;
        __u32                    mechidx, seq, gss_err;
        ENTRY;

        mechidx = (__u32) rpci->private;
        LASSERT(mechidx < MECH_MAX);

        OBD_ALLOC(buf, mlen);
        if (!buf)
                RETURN(-ENOMEM);

        if (copy_from_user(buf, src, mlen)) {
                CERROR("failed copy user space data\n");
                GOTO(out_free, rc = -EFAULT);
        }
        data = buf;
        datalen = mlen;

        /* data passed down format:
         *  - seq
         *  - timeout
         *  - gc_win / error
         *  - wire_ctx (rawobj)
         *  - mech_ctx (rawobj)
         */
        if (simple_get_bytes(&data, &datalen, &seq, sizeof(seq))) {
                CERROR("fail to get seq\n");
                GOTO(out_free, rc = -EFAULT);
        }

        gss_msg = gss_find_upcall(mechidx, seq);
        if (!gss_msg) {
                CERROR("upcall %u has aborted earlier\n", seq);
                GOTO(out_free, rc = -EINVAL);
        }

        gss_unhash_msg(gss_msg);
        gctx = gss_msg->gum_gctx;
        LASSERT(gctx);
        LASSERT(atomic_read(&gctx->gc_base.cc_refcount) > 0);

        /* timeout is not in use for now */
        if (simple_get_bytes(&data, &datalen, &timeout, sizeof(timeout)))
                GOTO(out_msg, rc = -EFAULT);

        /* lgssd signal an error by gc_win == 0 */
        if (simple_get_bytes(&data, &datalen, &gctx->gc_win,
                             sizeof(gctx->gc_win)))
                GOTO(out_msg, rc = -EFAULT);

        if (gctx->gc_win == 0) {
                /* followed by:
                 * - rpc error
                 * - gss error
                 */
                if (simple_get_bytes(&data, &datalen, &rc, sizeof(rc)))
                        GOTO(out_msg, rc = -EFAULT);
                if (simple_get_bytes(&data, &datalen, &gss_err,sizeof(gss_err)))
                        GOTO(out_msg, rc = -EFAULT);

                if (rc == 0 && gss_err == GSS_S_COMPLETE) {
                        CWARN("both rpc & gss error code not set\n");
                        rc = -EPERM;
                }
        } else {
                rawobj_t tmpobj;

                /* handle */
                if (rawobj_extract_local(&tmpobj, (__u32 **) &data, &datalen))
                        GOTO(out_msg, rc = -EFAULT);
                if (rawobj_dup(&gctx->gc_handle, &tmpobj))
                        GOTO(out_msg, rc = -ENOMEM);

                /* mechctx */
                if (rawobj_extract_local(&tmpobj, (__u32 **) &data, &datalen))
                        GOTO(out_msg, rc = -EFAULT);
                gss_err = lgss_import_sec_context(&tmpobj,
                                                  gss_msg->gum_gsec->gs_mech,
                                                  &gctx->gc_mechctx);
                rc = 0;
        }

        if (likely(rc == 0 && gss_err == GSS_S_COMPLETE)) {
                gss_cli_ctx_uptodate(gctx);
        } else {
                ctx = &gctx->gc_base;
                sptlrpc_ctx_expire(ctx);
                if (rc != -ERESTART || gss_err != GSS_S_COMPLETE)
                        set_bit(PTLRPC_CTX_ERROR_BIT, &ctx->cc_flags);

                CERROR("refresh ctx %p(uid %d) failed: %d/0x%08x: %s\n",
                       ctx, ctx->cc_vcred.vc_uid, rc, gss_err,
                       test_bit(PTLRPC_CTX_ERROR_BIT, &ctx->cc_flags) ?
                       "fatal error" : "non-fatal");
        }

        rc = mlen;

out_msg:
        gss_release_msg(gss_msg);

out_free:
        OBD_FREE(buf, mlen);
        /* FIXME
         * hack pipefs: always return asked length unless all following
         * downcalls might be messed up.
         */
        rc = mlen;
        RETURN(rc);
}

static
void gss_pipe_destroy_msg(struct rpc_pipe_msg *msg)
{
        struct gss_upcall_msg          *gmsg;
        struct gss_upcall_msg_data     *gumd;
        static cfs_time_t               ratelimit = 0;
        ENTRY;

        LASSERT(list_empty(&msg->list));

        /* normally errno is >= 0 */
        if (msg->errno >= 0) {
                EXIT;
                return;
        }

        gmsg = container_of(msg, struct gss_upcall_msg, gum_base);
        gumd = &gmsg->gum_data;
        LASSERT(atomic_read(&gmsg->gum_refcount) > 0);

        CERROR("failed msg %p (seq %u, uid %u, svc %u, nid %llx, obd %.*s): "
               "errno %d\n", msg, gumd->gum_seq, gumd->gum_uid, gumd->gum_svc,
               gumd->gum_nid, sizeof(gumd->gum_obd), gumd->gum_obd, msg->errno);

        atomic_inc(&gmsg->gum_refcount);
        gss_unhash_msg(gmsg);
        if (msg->errno == -ETIMEDOUT || msg->errno == -EPIPE) {
                cfs_time_t now = cfs_time_current_sec();

                if (cfs_time_after(now, ratelimit)) {
                        CWARN("upcall timed out, is lgssd running?\n");
                        ratelimit = now + 15;
                }
        }
        gss_msg_fail_ctx(gmsg);
        gss_release_msg(gmsg);
        EXIT;
}

static
void gss_pipe_release(struct inode *inode)
{
        struct rpc_inode *rpci = RPC_I(inode);
        __u32             idx;
        ENTRY;

        idx = (__u32) rpci->private;
        LASSERT(idx < MECH_MAX);

        upcall_list_lock(idx);
        while (!list_empty(&upcall_lists[idx])) {
                struct gss_upcall_msg      *gmsg;
                struct gss_upcall_msg_data *gumd;

                gmsg = list_entry(upcall_lists[idx].next,
                                  struct gss_upcall_msg, gum_list);
                gumd = &gmsg->gum_data;
                LASSERT(list_empty(&gmsg->gum_base.list));

                CERROR("failing remaining msg %p:seq %u, uid %u, svc %u, "
                       "nid %llx, obd %.*s\n", gmsg,
                       gumd->gum_seq, gumd->gum_uid, gumd->gum_svc,
                       gumd->gum_nid, sizeof(gumd->gum_obd), gumd->gum_obd);

                gmsg->gum_base.errno = -EPIPE;
                atomic_inc(&gmsg->gum_refcount);
                gss_unhash_msg_nolock(gmsg);

                gss_msg_fail_ctx(gmsg);

                upcall_list_unlock(idx);
                gss_release_msg(gmsg);
                upcall_list_lock(idx);
        }
        upcall_list_unlock(idx);
        EXIT;
}

static struct rpc_pipe_ops gss_upcall_ops = {
        .upcall         = gss_pipe_upcall,
        .downcall       = gss_pipe_downcall,
        .destroy_msg    = gss_pipe_destroy_msg,
        .release_pipe   = gss_pipe_release,
};


/*******************************************
 * upcall helper functions                 *
 *******************************************/

static inline
__u32 import_to_gss_svc(struct obd_import *imp)
{
        const char *name = imp->imp_obd->obd_type->typ_name;
        if (!strcmp(name, LUSTRE_MDC_NAME))
                return LUSTRE_GSS_TGT_MDS;
        if (!strcmp(name, LUSTRE_OSC_NAME))
                return LUSTRE_GSS_TGT_OSS;
        LBUG();
        return 0;
}

int gss_ctx_refresh_pipefs(struct ptlrpc_cli_ctx *ctx)
{
        struct obd_import          *imp;
        struct gss_sec             *gsec;
        struct gss_upcall_msg      *gmsg;
        int                         rc = 0;
        ENTRY;

        might_sleep();

        LASSERT(ctx->cc_sec);
        LASSERT(ctx->cc_sec->ps_import);
        LASSERT(ctx->cc_sec->ps_import->imp_obd);

        imp = ctx->cc_sec->ps_import;
        if (!imp->imp_connection) {
                CERROR("import has no connection set\n");
                RETURN(-EINVAL);
        }

        gsec = container_of(ctx->cc_sec, struct gss_sec, gs_base);

        OBD_ALLOC_PTR(gmsg);
        if (!gmsg)
                RETURN(-ENOMEM);

        /* initialize pipefs base msg */
        INIT_LIST_HEAD(&gmsg->gum_base.list);
        gmsg->gum_base.data = &gmsg->gum_data;
        gmsg->gum_base.len = sizeof(gmsg->gum_data);
        gmsg->gum_base.copied = 0;
        gmsg->gum_base.errno = 0;

        /* init upcall msg */
        atomic_set(&gmsg->gum_refcount, 1);
        gmsg->gum_mechidx = mech_name2idx(gsec->gs_mech->gm_name);
        gmsg->gum_gsec = gsec;
        gmsg->gum_gctx = container_of(sptlrpc_ctx_get(ctx),
                                      struct gss_cli_ctx, gc_base);
        gmsg->gum_data.gum_seq = upcall_get_sequence();
        gmsg->gum_data.gum_uid = ctx->cc_vcred.vc_uid;
        gmsg->gum_data.gum_gid = 0; /* not used for now */
        gmsg->gum_data.gum_svc = import_to_gss_svc(imp);
        gmsg->gum_data.gum_nid = imp->imp_connection->c_peer.nid;
        gmsg->gum_data.gum_pag = ctx->cc_vcred.vc_pag;
        strncpy(gmsg->gum_data.gum_obd, imp->imp_obd->obd_name,
                sizeof(gmsg->gum_data.gum_obd));

        /* This only could happen when sysadmin set it dead/expired
         * using lctl by force.
         */
        smp_mb();
        if (ctx->cc_flags & PTLRPC_CTX_STATUS_MASK) {
                CWARN("ctx %p(%u->%s) was set flags %lx unexpectedly\n",
                      ctx, ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec),
                      ctx->cc_flags);

                LASSERT(!(ctx->cc_flags & PTLRPC_CTX_UPTODATE));
                ctx->cc_flags |= PTLRPC_CTX_DEAD | PTLRPC_CTX_ERROR;

                rc = -EIO;
                goto err_free;
        }

        upcall_msg_enlist(gmsg);

        rc = rpc_queue_upcall(de_pipes[gmsg->gum_mechidx]->d_inode,
                              &gmsg->gum_base);
        if (rc) {
                CERROR("rpc_queue_upcall failed: %d\n", rc);

                upcall_msg_delist(gmsg);
                goto err_free;
        }

        RETURN(0);
err_free:
        OBD_FREE_PTR(gmsg);
        RETURN(rc);
}

int gss_sec_upcall_init(struct gss_sec *gsec)
{
        return 0;
}

void gss_sec_upcall_cleanup(struct gss_sec *gsec)
{
}

int gss_init_pipefs(void)
{
        struct dentry   *de;

        /* pipe dir */
        de = rpc_mkdir(LUSTRE_PIPE_ROOT, NULL);
        if (IS_ERR(de) && PTR_ERR(de) != -EEXIST) {
                CERROR("Failed to create gss pipe dir: %ld\n", PTR_ERR(de));
                return PTR_ERR(de);
        }
        /* FIXME
         * hack pipefs: dput will sometimes cause oops during module unload
         * and lgssd close the pipe fds.
         */
        //dput(de);

        /* krb5 mechanism */
        de = rpc_mkpipe(LUSTRE_PIPE_KRB5, (void *) MECH_KRB5, &gss_upcall_ops,
                        RPC_PIPE_WAIT_FOR_OPEN);
        if (!de || IS_ERR(de)) {
                CERROR("failed to make rpc_pipe %s: %ld\n",
                       LUSTRE_PIPE_KRB5, PTR_ERR(de));
                rpc_rmdir(LUSTRE_PIPE_ROOT);
                return PTR_ERR(de);
        }

        de_pipes[MECH_KRB5] = de;
        INIT_LIST_HEAD(&upcall_lists[MECH_KRB5]);
        upcall_locks[MECH_KRB5] = SPIN_LOCK_UNLOCKED;

        return 0;
}

void gss_cleanup_pipefs(void)
{
        __u32   i;

        for (i = 0; i < MECH_MAX; i++) {
                LASSERT(list_empty(&upcall_lists[i]));
                /* FIXME
                 * hack pipefs, dput pipe dentry here might cause lgssd oops.
                 */
                //dput(de_pipes[i]);
                de_pipes[i] = NULL;
        }

        rpc_unlink(LUSTRE_PIPE_KRB5);
        rpc_rmdir(LUSTRE_PIPE_ROOT);
}

/**********************************************
 * gss context init/fini helper               *
 **********************************************/

static
int ctx_init_pack_request(struct obd_import *imp,
                          struct ptlrpc_request *req,
                          int lustre_srv,
                          uid_t uid, gid_t gid,
                          long token_size,
                          char __user *token)
{
        struct lustre_msg       *msg = req->rq_reqbuf;
        struct gss_sec          *gsec;
        struct gss_header       *ghdr;
        struct ptlrpc_user_desc *pud;
        __u32                   *p, size, offset = 2;
        rawobj_t                 obj;

        LASSERT(msg->lm_bufcount <= 4);

        /* gss hdr */
        ghdr = lustre_msg_buf(msg, 0, sizeof(*ghdr));
        ghdr->gh_version = PTLRPC_GSS_VERSION;
        ghdr->gh_flags = 0;
        ghdr->gh_proc = PTLRPC_GSS_PROC_INIT;
        ghdr->gh_seq = 0;
        ghdr->gh_svc = PTLRPC_GSS_SVC_NONE;
        ghdr->gh_handle.len = 0;

        /* fix the user desc */
        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor)) {
                pud = lustre_msg_buf(msg, offset, sizeof(*pud));
                LASSERT(pud);
                pud->pud_uid = pud->pud_fsuid = uid;
                pud->pud_gid = pud->pud_fsgid = gid;
                pud->pud_cap = 0;
                pud->pud_ngroups = 0;
                offset++;
        }

        /* security payload */
        p = lustre_msg_buf(msg, offset, 0);
        size = msg->lm_buflens[offset];

        /* 1. lustre svc type */
        LASSERT(size > 4);
        *p++ = cpu_to_le32(lustre_srv);
        size -= 4;

        /* 2. target uuid */
        obj.len = strlen(imp->imp_obd->u.cli.cl_target_uuid.uuid) + 1;
        obj.data = imp->imp_obd->u.cli.cl_target_uuid.uuid;
        if (rawobj_serialize(&obj, &p, &size))
                LBUG();

        /* 3. reverse context handle. actually only needed by root user,
         *    but we send it anyway.
         */
        gsec = container_of(imp->imp_sec, struct gss_sec, gs_base);
        obj.len = sizeof(gsec->gs_rvs_hdl);
        obj.data = (__u8 *) &gsec->gs_rvs_hdl;
        if (rawobj_serialize(&obj, &p, &size))
                LBUG();

        /* 4. now the token */
        LASSERT(size >= (sizeof(__u32) + token_size));
        *p++ = cpu_to_le32(((__u32) token_size));
        if (copy_from_user(p, token, token_size)) {
                CERROR("can't copy token\n");
                return -EFAULT;
        }
        size -= sizeof(__u32) + size_round4(token_size);

        req->rq_reqdata_len = lustre_shrink_msg(req->rq_reqbuf, offset,
                                                msg->lm_buflens[offset] - size, 0);
        return 0;
}

static
int ctx_init_parse_reply(struct lustre_msg *msg,
                         char __user *outbuf, long outlen)
{
        struct gss_rep_header   *ghdr;
        __u32                    obj_len, round_len;
        __u32                    status, effective = 0;

        if (msg->lm_bufcount != 3) {
                CERROR("unexpected bufcount %u\n", msg->lm_bufcount);
                return -EPROTO;
        }

        ghdr = (struct gss_rep_header *) gss_swab_header(msg, 0);
        if (ghdr == NULL) {
                CERROR("unable to extract gss reply header\n");
                return -EPROTO;
        }

        if (ghdr->gh_version != PTLRPC_GSS_VERSION) {
                CERROR("invalid gss version %u\n", ghdr->gh_version);
                return -EPROTO;
        }

        if (outlen < (4 + 2) * 4 + size_round4(ghdr->gh_handle.len) +
                     size_round4(msg->lm_buflens[2])) {
                CERROR("output buffer size %ld too small\n", outlen);
                return -EFAULT;
        }

        status = 0;
        effective = 0;

        if (copy_to_user(outbuf, &status, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, &ghdr->gh_major, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, &ghdr->gh_minor, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, &ghdr->gh_seqwin, 4))
                return -EFAULT;
        outbuf += 4;
        effective += 4 * 4;

        /* handle */
        obj_len = ghdr->gh_handle.len;
        round_len = (obj_len + 3) & ~ 3;
        if (copy_to_user(outbuf, &obj_len, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, (char *) ghdr->gh_handle.data, round_len))
                return -EFAULT;
        outbuf += round_len;
        effective += 4 + round_len;

        /* out token */
        obj_len = msg->lm_buflens[2];
        round_len = (obj_len + 3) & ~ 3;
        if (copy_to_user(outbuf, &obj_len, 4))
                return -EFAULT;
        outbuf += 4;
        if (copy_to_user(outbuf, lustre_msg_buf(msg, 2, 0), round_len))
                return -EFAULT;
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

int gss_do_ctx_init_rpc(__user char *buffer, unsigned long count)
{
        struct obd_import        *imp;
        struct ptlrpc_request    *req;
        struct lgssd_ioctl_param  param;
        struct obd_device        *obd;
        char                      obdname[64];
        long                      lsize;
        int                       lmsg_size = sizeof(struct ptlrpc_body);
        int                       rc;

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
        if (strncpy_from_user(obdname, param.uuid, sizeof(obdname)) <= 0) {
                CERROR("Invalid obdname pointer\n");
                RETURN(-EFAULT);
        }

        obd = class_name2obd(obdname);
        if (!obd) {
                CERROR("no such obd %s\n", obdname);
                RETURN(-EINVAL);
        }

        imp = class_import_get(obd->u.cli.cl_import);
        LASSERT(imp->imp_sec);

        /* force this import to use v2 msg */
        imp->imp_msg_magic = LUSTRE_MSG_MAGIC_V2;

        req = ptlrpc_prep_req(imp, LUSTRE_OBD_VERSION, SEC_CTX_INIT,
                              1, &lmsg_size, NULL);
        if (!req) {
                param.status = -ENOMEM;
                goto out_copy;
        }

        /* get token */
        rc = ctx_init_pack_request(imp, req,
                                   param.lustre_svc,
                                   param.uid, param.gid,
                                   param.send_token_size,
                                   param.send_token);
        if (rc) {
                param.status = rc;
                goto out_copy;
        }

        req->rq_replen = lustre_msg_size_v2(1, &lmsg_size);

        rc = ptlrpc_queue_wait(req);
        if (rc) {
                /* If any _real_ denial be made, we expect server return
                 * -EACCES reply or return success but indicate gss error
                 * inside reply messsage. All other errors are treated as
                 * timeout, caller might try the negotiation repeatedly,
                 * leave recovery decisions to general ptlrpc layer.
                 *
                 * FIXME maybe some other error code shouldn't be treated
                 * as timeout.
                 */
                param.status = rc;
                if (rc != -EACCES)
                        param.status = -ETIMEDOUT;
                goto out_copy;
        }

        lsize = ctx_init_parse_reply(req->rq_repbuf,
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
        ptlrpc_req_finished(req);
        RETURN(rc);
}

int gss_do_ctx_fini_rpc(struct gss_cli_ctx *gctx)
{
        struct ptlrpc_cli_ctx   *ctx = &gctx->gc_base;
        struct obd_import       *imp = ctx->cc_sec->ps_import;
        struct ptlrpc_request   *req;
        struct ptlrpc_user_desc *pud;
        int                      buflens = sizeof(struct ptlrpc_body);
        int                      rc;
        ENTRY;

        if (ctx->cc_sec->ps_flags & PTLRPC_SEC_FL_REVERSE) {
                CWARN("ctx %p(%u) is reverse, don't send destroy rpc\n",
                      ctx, ctx->cc_vcred.vc_uid);
                RETURN(0);
        }

        if (test_bit(PTLRPC_CTX_ERROR_BIT, &ctx->cc_flags) ||
            !test_bit(PTLRPC_CTX_UPTODATE_BIT, &ctx->cc_flags)) {
                CWARN("ctx %p(%u->%s) already dead, don't send destroy rpc\n",
                      ctx, ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec));
                RETURN(0);
        }

        might_sleep();

        CWARN("client destroy ctx %p(%u->%s)\n",
              ctx, ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec));

        /* context's refcount could be 0, steal one */
        atomic_inc(&ctx->cc_refcount);

        gctx->gc_proc = PTLRPC_GSS_PROC_DESTROY;

        req = ptlrpc_prep_req_pool(imp, LUSTRE_OBD_VERSION, SEC_CTX_FINI,
                                   1, &buflens, NULL, NULL, ctx);
        if (!req) {
                CWARN("ctx %p(%u): fail to prepare rpc, destroy locally\n",
                      ctx, ctx->cc_vcred.vc_uid);
                GOTO(out_ref, rc = -ENOMEM);
        }

        /* fix the user desc */
        if (SEC_FLAVOR_HAS_USER(req->rq_sec_flavor)) {
                /* we rely the fact that this request is in AUTH mode,
                 * and user_desc at offset 2.
                 */
                pud = lustre_msg_buf(req->rq_reqbuf, 2, sizeof(*pud));
                LASSERT(pud);
                pud->pud_uid = pud->pud_fsuid = ctx->cc_vcred.vc_uid;
                pud->pud_gid = pud->pud_fsgid = ctx->cc_vcred.vc_gid;
                pud->pud_cap = 0;
                pud->pud_ngroups = 0;
        }

        req->rq_replen = lustre_msg_size_v2(1, &buflens);

        rc = ptlrpc_queue_wait(req);
        if (rc) {
                CWARN("ctx %p(%u): rpc error %d, destroy locally\n",
                      ctx, ctx->cc_vcred.vc_uid, rc);
        }

        ptlrpc_req_finished(req);
out_ref:
        atomic_dec(&ctx->cc_refcount);
        RETURN(rc);
}

int __init gss_init_upcall(void)
{
        int     rc;

        rc = gss_svc_init_upcall();
        if (rc)
                return rc;

        rc = gss_init_pipefs();
        if (rc)
                gss_svc_exit_upcall();

        return rc;
}

void __exit gss_exit_upcall(void)
{
        gss_svc_exit_upcall();
        gss_cleanup_pipefs();
}
