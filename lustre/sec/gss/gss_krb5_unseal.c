/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 *  linux/net/sunrpc/gss_krb5_unseal.c
 *
 *  Adapted from MIT Kerberos 5-1.2.1 lib/gssapi/krb5/k5unseal.c
 *
 *  Copyright (c) 2000 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson   <andros@umich.edu>
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


/* read_token is a mic token, and message_buffer is the data that the mic was
 * supposedly taken over. */

__u32
krb5_read_token(struct krb5_ctx *ctx,
                rawobj_t *read_token,
                rawobj_t *message_buffer,
                int *qop_state)
{
        int                     signalg;
        int                     sealalg;
        __s32                   checksum_type;
        rawobj_t                md5cksum = {.len = 0, .data = NULL};
        __s32                   now;
        int                     direction;
        __s32                   seqnum;
        unsigned char          *ptr = (unsigned char *)read_token->data;
        int                     bodysize;
        __u32                   ret = GSS_S_DEFECTIVE_TOKEN;
        ENTRY;

        if (g_verify_token_header(&ctx->mech_used, &bodysize, &ptr,
                                  read_token->len))
                goto out;

        if ((*ptr++ != ((KG_TOK_MIC_MSG>>8)&0xff)) ||
            (*ptr++ != ( KG_TOK_MIC_MSG    &0xff))   )
                goto out;

        /* XXX sanity-check bodysize?? */

        /* get the sign and seal algorithms */

        signalg = ptr[0] + (ptr[1] << 8);
        sealalg = ptr[2] + (ptr[3] << 8);

        /* Sanity checks */

        if ((ptr[4] != 0xff) || (ptr[5] != 0xff))
                goto out;

        if (sealalg != 0xffff)
                goto out;

        /* there are several mappings of seal algorithms to sign algorithms,
           but few enough that we can try them all. */

        if ((ctx->sealalg == SEAL_ALG_NONE && signalg > 1) ||
            (ctx->sealalg == SEAL_ALG_1 && signalg != SGN_ALG_3) ||
            (ctx->sealalg == SEAL_ALG_DES3KD &&
             signalg != SGN_ALG_HMAC_SHA1_DES3_KD))
                goto out;

        /* compute the checksum of the message */

        /* initialize the the cksum */
        switch (signalg) {
        case SGN_ALG_DES_MAC_MD5:
                checksum_type = CKSUMTYPE_RSA_MD5;
                break;
        default:
                ret = GSS_S_DEFECTIVE_TOKEN;
                goto out;
        }

        switch (signalg) {
        case SGN_ALG_DES_MAC_MD5:
                ret = make_checksum(checksum_type, (char *)(ptr - 2),
                                    8, message_buffer, &md5cksum);
                if (ret)
                        goto out;

                ret = krb5_encrypt(ctx->seq, NULL, md5cksum.data,
                                   md5cksum.data, 16);
                if (ret)
                        goto out;

                if (memcmp(md5cksum.data + 8, ptr + 14, 8)) {
                        ret = GSS_S_BAD_SIG;
                        goto out;
                }
                break;
        default:
                ret = GSS_S_DEFECTIVE_TOKEN;
                goto out;
        }

        /* it got through unscathed.  Make sure the context is unexpired */

        if (qop_state)
                *qop_state = GSS_C_QOP_DEFAULT;

        now = get_seconds();

        ret = GSS_S_CONTEXT_EXPIRED;
        if (now > ctx->endtime)
                goto out;

        /* do sequencing checks */

        ret = GSS_S_BAD_SIG;
        if ((ret = krb5_get_seq_num(ctx->seq, ptr + 14, ptr + 6, &direction,
                                    &seqnum)))
                goto out;

        if ((ctx->initiate && direction != 0xff) ||
            (!ctx->initiate && direction != 0))
                goto out;

        ret = GSS_S_COMPLETE;
out:
        if (md5cksum.data)
                OBD_FREE(md5cksum.data, md5cksum.len);
        return ret;
}
