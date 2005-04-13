/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 *  linux/net/sunrpc/gss_krb5_seal.c
 *
 *  Adapted from MIT Kerberos 5-1.2.1 lib/gssapi/krb5/k5seal.c
 *
 *  Copyright (c) 2000 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson        <andros@umich.edu>
 *  J. Bruce Fields     <bfields@umich.edu>
 */

/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
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
#include <netinet/in.h>
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

spinlock_t krb5_seq_lock = SPIN_LOCK_UNLOCKED;

__u32
krb5_make_token(struct krb5_ctx *ctx,
                int qop_req,
                rawobj_t *text,
                rawobj_t *token)
{
        __s32                   checksum_type;
        rawobj_t                md5cksum = {.len = 0, .data = NULL};
        unsigned char          *ptr, *krb5_hdr, *msg_start;
        __s32                   now, seq_send;
        ENTRY;

        now = get_seconds();

        if (qop_req != 0)
                goto out_err;

        switch (ctx->signalg) {
                case SGN_ALG_DES_MAC_MD5:
                        checksum_type = CKSUMTYPE_RSA_MD5;
                        break;
                default:
                        CERROR("ctx->signalg %d not supported\n", ctx->signalg);
                        goto out_err;
        }
        if (ctx->sealalg != SEAL_ALG_NONE && ctx->sealalg != SEAL_ALG_DES) {
                CERROR("ctx->sealalg %d not supported\n", ctx->sealalg);
                goto out_err;
        }

        token->len = g_token_size(&ctx->mech_used, 22);

        ptr = token->data;
        g_make_token_header(&ctx->mech_used, 22, &ptr);

        *ptr++ = (unsigned char) ((KG_TOK_MIC_MSG>>8)&0xff);
        *ptr++ = (unsigned char) (KG_TOK_MIC_MSG&0xff);

        /* ptr now at byte 2 of header described in rfc 1964, section 1.2.1: */
        krb5_hdr = ptr - 2;
        msg_start = krb5_hdr + 24;

        *(__u16 *)(krb5_hdr + 2) = cpu_to_be16(ctx->signalg);
        memset(krb5_hdr + 4, 0xff, 4);

        if (make_checksum(checksum_type, krb5_hdr, 8, text, &md5cksum))
                goto out_err;

        switch (ctx->signalg) {
        case SGN_ALG_DES_MAC_MD5:
                if (krb5_encrypt(ctx->seq, NULL, md5cksum.data,
                                 md5cksum.data, md5cksum.len))
                        goto out_err;
                memcpy(krb5_hdr + 16,
                       md5cksum.data + md5cksum.len - KRB5_CKSUM_LENGTH,
                       KRB5_CKSUM_LENGTH);

                break;
        default:
                LBUG();
        }

        OBD_FREE(md5cksum.data, md5cksum.len);

        spin_lock(&krb5_seq_lock);
        seq_send = ctx->seq_send++;
        spin_unlock(&krb5_seq_lock);

        if ((krb5_make_seq_num(ctx->seq, ctx->initiate ? 0 : 0xff,
                               seq_send, krb5_hdr + 16, krb5_hdr + 8)))
                goto out_err;

        return ((ctx->endtime < now) ? GSS_S_CONTEXT_EXPIRED : GSS_S_COMPLETE);
out_err:
        if (md5cksum.data)
                OBD_FREE(md5cksum.data, md5cksum.len);
        return GSS_S_FAILURE;
}
