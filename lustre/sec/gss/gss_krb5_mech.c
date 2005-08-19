/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 *  linux/net/sunrpc/gss_krb5_mech.c
 *
 *  Copyright (c) 2001 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson <andros@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
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
#include <linux/crypto.h>
#else
#include <liblustre.h>
//#include "../kcrypto/libcrypto.h"
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
#include "gss_krb5.h"

rawobj_t gss_mech_krb5_oid =
{9, (__u8 *)"\052\206\110\206\367\022\001\002\002"};

static inline int
get_bytes(char **ptr, const char *end, void *res, int len)
{
        char *p, *q;
        p = *ptr;
        q = p + len;
        if (q > end || q < p)
                return -1;
        memcpy(res, p, len);
        *ptr = q;
        return 0;
}

static inline int
get_rawobj(char **ptr, const char *end, rawobj_t *res)
{
        char *p, *q;
        p = *ptr;
        if (get_bytes(&p, end, &res->len, sizeof(res->len)))
                return -1;
        q = p + res->len;
        if (q > end || q < p)
                return -1;
        OBD_ALLOC(res->data, res->len);
        if (!res->data)
                return -1;
        memcpy(res->data, p, res->len);
        *ptr = q;
        return 0;
}

static inline int
get_key(char **p, char *end, struct crypto_tfm **res)
{
        rawobj_t                key;
        int                     alg, alg_mode;
        char                   *alg_name;

        if (get_bytes(p, end, &alg, sizeof(alg)))
                goto out_err;
        if ((get_rawobj(p, end, &key)))
                goto out_err;

        switch (alg) {
                case ENCTYPE_DES_CBC_RAW:
                        alg_name = "des";
                        alg_mode = CRYPTO_TFM_MODE_CBC;
                        break;
                default:
                        CERROR("unsupported algorithm %d\n", alg);
                        goto out_err_free_key;
        }
        if (!(*res = crypto_alloc_tfm(alg_name, alg_mode)))
                goto out_err_free_key;
        if (crypto_cipher_setkey(*res, key.data, key.len))
                goto out_err_free_tfm;

        OBD_FREE(key.data, key.len);
        return 0;

out_err_free_tfm:
        crypto_free_tfm(*res);
out_err_free_key:
        OBD_FREE(key.data, key.len);
out_err:
        return -1;
}

static __u32
gss_import_sec_context_kerberos(rawobj_t *inbuf,
                                struct gss_ctx *ctx_id)
{
        char            *p = (char *)inbuf->data;
        char            *end = (char *)(inbuf->data + inbuf->len);
        struct krb5_ctx *ctx;

        OBD_ALLOC(ctx, sizeof(*ctx));
        if (!ctx)
                goto out_err;

        if (get_bytes(&p, end, &ctx->initiate, sizeof(ctx->initiate)))
                goto out_err_free_ctx;
        if (get_bytes(&p, end, &ctx->seed_init, sizeof(ctx->seed_init)))
                goto out_err_free_ctx;
        if (get_bytes(&p, end, ctx->seed, sizeof(ctx->seed)))
                goto out_err_free_ctx;
        if (get_bytes(&p, end, &ctx->signalg, sizeof(ctx->signalg)))
                goto out_err_free_ctx;
        if (get_bytes(&p, end, &ctx->sealalg, sizeof(ctx->sealalg)))
                goto out_err_free_ctx;
        if (get_bytes(&p, end, &ctx->endtime, sizeof(ctx->endtime)))
                goto out_err_free_ctx;
        if (get_bytes(&p, end, &ctx->seq_send, sizeof(ctx->seq_send)))
                goto out_err_free_ctx;
        if (get_rawobj(&p, end, &ctx->mech_used))
                goto out_err_free_ctx;
        if (get_key(&p, end, &ctx->enc))
                goto out_err_free_mech;
        if (get_key(&p, end, &ctx->seq))
                goto out_err_free_key1;
        if (p != end)
                goto out_err_free_key2;

        ctx_id->internal_ctx_id = ctx;
        CDEBUG(D_SEC, "Succesfully imported new context.\n");
        return 0;

out_err_free_key2:
        crypto_free_tfm(ctx->seq);
out_err_free_key1:
        crypto_free_tfm(ctx->enc);
out_err_free_mech:
        OBD_FREE(ctx->mech_used.data, ctx->mech_used.len);
out_err_free_ctx:
        OBD_FREE(ctx, sizeof(*ctx));
out_err:
        return GSS_S_FAILURE;
}

static __u32
gss_inquire_context_kerberos(struct gss_ctx    *context_handle,
                             __u64             *endtime)
{
        struct krb5_ctx *kctx = context_handle->internal_ctx_id;

        *endtime = (__u64) ((__u32) kctx->endtime);
        return GSS_S_COMPLETE;
}

static void
gss_delete_sec_context_kerberos(void *internal_ctx)
{
        struct krb5_ctx *ctx = internal_ctx;

        if (ctx->seq)
                crypto_free_tfm(ctx->seq);
        if (ctx->enc)
                crypto_free_tfm(ctx->enc);
        if (ctx->mech_used.data)
                OBD_FREE(ctx->mech_used.data, ctx->mech_used.len);
        OBD_FREE(ctx, sizeof(*ctx));
}

/* XXX the following wrappers have become pointless; kill them. */
static __u32
gss_verify_mic_kerberos(struct gss_ctx *ctx,
                        rawobj_t       *message,
                        rawobj_t       *mic_token,
                        __u32          *qstate)
{
        struct krb5_ctx *kctx = ctx->internal_ctx_id;
        __u32 maj_stat;
        int qop_state;

        maj_stat = krb5_read_token(kctx, mic_token, message, &qop_state);
        if (!maj_stat && qop_state)
            *qstate = qop_state;

        CDEBUG(D_SEC, "returning %d\n", maj_stat);
        return maj_stat;
}

static __u32
gss_get_mic_kerberos(struct gss_ctx    *ctx,
                     __u32              qop,
                     rawobj_t          *message,
                     rawobj_t          *mic_token)
{
        struct krb5_ctx *kctx = ctx->internal_ctx_id;
        __u32 err;

        err = krb5_make_token(kctx, qop, message, mic_token);

        CDEBUG(D_SEC, "returning %d\n",err);
        return err;
}

static struct gss_api_ops gss_kerberos_ops = {
        .gss_import_sec_context     = gss_import_sec_context_kerberos,
        .gss_inquire_context        = gss_inquire_context_kerberos,
        .gss_get_mic                = gss_get_mic_kerberos,
        .gss_verify_mic             = gss_verify_mic_kerberos,
        .gss_wrap                   = gss_wrap_kerberos,
        .gss_unwrap                 = gss_unwrap_kerberos,
        .gss_delete_sec_context     = gss_delete_sec_context_kerberos,
};

static struct subflavor_desc gss_kerberos_sfs[] = {
        {
                .subflavor      = PTLRPCS_SUBFLVR_KRB5,
                .qop            = 0,
                .service        = PTLRPCS_SVC_NONE,
                .name           = "krb5"
        },
        {
                .subflavor      = PTLRPCS_SUBFLVR_KRB5I,
                .qop            = 0,
                .service        = PTLRPCS_SVC_AUTH,
                .name           = "krb5i"
        },
        {
                .subflavor      = PTLRPCS_SUBFLVR_KRB5P,
                .qop            = 0,
                .service        = PTLRPCS_SVC_PRIV,
                .name           = "krb5p"
        }
};

static struct gss_api_mech gss_kerberos_mech = {
        .gm_name        = "krb5",
        .gm_owner       = THIS_MODULE,
        .gm_ops         = &gss_kerberos_ops,
        .gm_sf_num      = 3,
        .gm_sfs         = gss_kerberos_sfs,
};

/*static*/ int __init init_kerberos_module(void)
{
        int status;

        status = kgss_mech_register(&gss_kerberos_mech);
        if (status)
                CERROR("Failed to register kerberos gss mechanism!\n");
        return status;
}

/*static*/ void __exit cleanup_kerberos_module(void)
{
        kgss_mech_unregister(&gss_kerberos_mech);
}

/* XXX enable this when module works */
#if 0
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("GSS Krb5 mechanism for Lustre");

module_init(init_kerberos_module);
module_exit(cleanup_kerberos_module);
#endif
