/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   Modified from NFSv4 projects for Lustre
 *   Copyright 2004, Cluster File Systems, Inc.
 *   All rights reserved
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
#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/random.h>
#else
#include <liblustre.h>
#include "../kcrypto/libcrypto.h"
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
#include "gss_asn1.h"

static inline
int add_padding(rawobj_buf_t *msgbuf, int blocksize)
{
        int padding;

        padding = (blocksize - (msgbuf->datalen & (blocksize - 1))) &
                  (blocksize - 1);
        if (padding == 0)
                return 0;

        CWARN("add padding %d\n", padding);
        if (msgbuf->dataoff + msgbuf->datalen + padding > msgbuf->buflen) {
                CERROR("bufsize %u too small: off %u, len %u, padding %u\n",
                        msgbuf->buflen, msgbuf->dataoff, msgbuf->datalen,
                        padding);
                return -EINVAL;
        }
        memset(msgbuf->buf + msgbuf->dataoff + msgbuf->datalen,
               padding, padding);
        msgbuf->datalen += padding;
        return 0;
}

static inline
int generate_confounder(rawobj_buf_t *msgbuf, int blocksize)
{
        __u8 *p;

        p = msgbuf->buf + msgbuf->dataoff - blocksize;
        if (p < msgbuf->buf) {
                CERROR("buf underflow\n");
                return -EINVAL;
        }

        get_random_bytes(p, blocksize);
        return 0;
}

__u32
gss_wrap_kerberos(struct gss_ctx    *ctx,
                  __u32              qop,
                  rawobj_buf_t      *msgbuf,
                  rawobj_t          *token)
{
        struct krb5_ctx        *kctx = ctx->internal_ctx_id;
        __u32                   checksum_type;
        rawobj_t                data_desc, cipher_out, md5cksum;
        int                     blocksize;
        unsigned char          *ptr, *krb5_hdr, *msg_start;
        int                     head_len, plain_len;
        __u32                   seq_send, major;
        ENTRY;

        if (qop) {
                CERROR("not support qop %x yet\n", qop);
                RETURN(GSS_S_FAILURE);
        }

        switch (kctx->signalg) {
        case SGN_ALG_DES_MAC_MD5:
                checksum_type = CKSUMTYPE_RSA_MD5;
                break;
        default:
                CERROR("not support signalg %x\n", kctx->signalg);
                RETURN(GSS_S_FAILURE);
        }
        if (kctx->sealalg != SEAL_ALG_NONE &&
            kctx->sealalg != SEAL_ALG_DES) {
                CERROR("not support sealalg %x\n", kctx->sealalg);
                RETURN(GSS_S_FAILURE);
        }

        blocksize = crypto_tfm_alg_blocksize(kctx->enc);
        LASSERT(blocksize <= 16);
        LASSERT(blocksize == 8); /* acutally must be 8 for now */

        if (add_padding(msgbuf, blocksize))
                RETURN(GSS_S_FAILURE);

        /* confounder size == blocksize */
        plain_len = msgbuf->datalen + blocksize;

        head_len = g_token_size(&kctx->mech_used, 22 + plain_len) -
                   msgbuf->datalen;

        LASSERT(token->len >= head_len);
        ptr = token->data;

        /*
         * fill in gss header and  krb5 header
         */
        g_make_token_header(&kctx->mech_used, 22 + plain_len, &ptr);
        krb5_hdr = ptr;
        msg_start = krb5_hdr + 24;
        *ptr++ = (unsigned char) ((KG_TOK_WRAP_MSG >> 8) & 0xff);
        *ptr++ = (unsigned char) (KG_TOK_WRAP_MSG & 0xff);
        *(__u16 *)(krb5_hdr + 2) = cpu_to_be16(kctx->signalg);
        memset(krb5_hdr + 4, 0xff, 4);
        *(__u16 *)(krb5_hdr + 4) = cpu_to_be16(kctx->sealalg);

        /*
         * prepend confounder on plain text
         */
        if (generate_confounder(msgbuf, blocksize))
                RETURN(GSS_S_FAILURE);

        /*
         * compute checksum including confounder
         */
        data_desc.data = msgbuf->buf + msgbuf->dataoff - blocksize;
        data_desc.len = msgbuf->datalen + blocksize;

        if (make_checksum(checksum_type, (char *)krb5_hdr,
                          8, &data_desc, &md5cksum)) {
                CERROR("checksum error\n");
                RETURN(GSS_S_FAILURE);
        }

        major = GSS_S_FAILURE;
        switch (kctx->signalg) {
        case SGN_ALG_DES_MAC_MD5:
                if (krb5_encrypt(kctx->seq, NULL, md5cksum.data,
                                 md5cksum.data, md5cksum.len)) {
                        rawobj_free(&md5cksum);
                        RETURN(GSS_S_FAILURE);
                }
                memcpy(krb5_hdr + 16,
                       md5cksum.data + md5cksum.len - KRB5_CKSUM_LENGTH,
                       KRB5_CKSUM_LENGTH);
                break;
        default:
                LBUG();
        }

        rawobj_free(&md5cksum);

        /*
         * fill sequence number in krb5 header
         */
        spin_lock(&krb5_seq_lock);
        seq_send = kctx->seq_send++;
        spin_unlock(&krb5_seq_lock);

        if (krb5_make_seq_num(kctx->seq, kctx->initiate ? 0 : 0xff,
                               seq_send, krb5_hdr + 16, krb5_hdr + 8))
                RETURN(GSS_S_FAILURE);

        /* do encryption */
        data_desc.data = msgbuf->buf + msgbuf->dataoff - blocksize;
        data_desc.len = msgbuf->datalen + blocksize;
        cipher_out.data = msg_start;
        cipher_out.len = token->len - (msg_start - token->data);
        LASSERT(data_desc.len % blocksize == 0);
        LASSERT(data_desc.len <= cipher_out.len);

        if (gss_encrypt_rawobj(kctx->enc, &data_desc, &cipher_out, 1))
                RETURN(GSS_S_FAILURE);

        token->len = (msg_start - token->data) + cipher_out.len;
        RETURN(0);
}

__u32
gss_unwrap_kerberos(struct gss_ctx  *ctx,
                    __u32            qop,
                    rawobj_t        *in_token,
                    rawobj_t        *out_token)
{
        struct krb5_ctx        *kctx = ctx->internal_ctx_id;
        int                     signalg, sealalg;
        rawobj_t                cipher_in, plain_out, md5cksum;
        unsigned char          *ptr, *krb5_hdr, *tmpbuf;
        int                     bodysize;
        int                     blocksize, seqnum, direction;
        __u32                   checksum_type;
        __u32                   major;
        ENTRY;

        ptr = in_token->data;

        /*
         * verify gss header
         */
        major = g_verify_token_header(&kctx->mech_used, &bodysize, &ptr,
                                      in_token->len);
        if (major) {
                CERROR("gss token error %d\n", major);
                RETURN(GSS_S_FAILURE);
        }

        krb5_hdr = ptr;

        if ((*ptr++ != ((KG_TOK_WRAP_MSG >> 8) & 0xff)) ||
            (*ptr++ !=  (KG_TOK_WRAP_MSG & 0xff))) {
                CERROR("token type not matched\n");
                RETURN(G_BAD_TOK_HEADER);
        }

        if (bodysize < 22) {
                CERROR("body size only %d\n", bodysize);
                RETURN(G_WRONG_SIZE);
        }

        /*
         * extract algorithms
         */
        signalg = ptr[0] | (ptr[1] << 8);
        sealalg = ptr[2] | (ptr[3] << 8);

        if (ptr[4] != 0xFF || ptr[5] != 0xFF) {
                CERROR("4/5: %d, %d\n", ptr[4], ptr[5]);
                RETURN(GSS_S_DEFECTIVE_TOKEN);
        }

        if (sealalg != kctx->sealalg) {
                CERROR("sealalg %d not matched my %d\n",
                        sealalg, kctx->sealalg);
                RETURN(GSS_S_DEFECTIVE_TOKEN);
        }

        if ((kctx->sealalg == SEAL_ALG_NONE && signalg > 1) ||
            (kctx->sealalg == SEAL_ALG_1 && signalg != SGN_ALG_3) ||
            (kctx->sealalg == SEAL_ALG_DES3KD &&
             signalg != SGN_ALG_HMAC_SHA1_DES3_KD)) {
                CERROR("bad sealalg %d\n", sealalg);
                RETURN(GSS_S_DEFECTIVE_TOKEN);
        }

        /* make bodysize as the actual cipher text size */
        bodysize -= 22;
        if (bodysize <= 0) {
                CERROR("cipher text size %d?\n", bodysize);
                RETURN(GSS_S_DEFECTIVE_TOKEN);
        }

        blocksize = crypto_tfm_alg_blocksize(kctx->enc);
        if (bodysize % blocksize) {
                CERROR("odd bodysize %d\n", bodysize);
                RETURN(GSS_S_DEFECTIVE_TOKEN);
        }

        OBD_ALLOC(tmpbuf, bodysize);
        if (!tmpbuf) {
                CERROR("fail alloc %d\n", bodysize);
                RETURN(GSS_S_FAILURE);
        }

        cipher_in.data = krb5_hdr + 24;
        cipher_in.len = bodysize;
        plain_out.data = tmpbuf;
        plain_out.len = bodysize;

        major = GSS_S_DEFECTIVE_TOKEN;
        if (gss_encrypt_rawobj(kctx->enc, &cipher_in, &plain_out, 0)) {
                CERROR("error decrypt: 0x%x\n", major);
                GOTO(out_free, major);
        }
        LASSERT(plain_out.len == bodysize);

        /*
         * verify checksum
         */
        switch (signalg) {
        case SGN_ALG_DES_MAC_MD5:
                checksum_type = CKSUMTYPE_RSA_MD5;
                major = make_checksum(checksum_type, (char *)krb5_hdr,
                                      8, &plain_out, &md5cksum);
                if (major) {
                        CERROR("make checksum err: 0x%x\n", major);
                        GOTO(out_free, major);
                }

                major = krb5_encrypt(kctx->seq, NULL, md5cksum.data,
                                     md5cksum.data, md5cksum.len);
                if (major) {
                        CERROR("encrypt checksum err: 0x%x\n", major);
                        rawobj_free(&md5cksum);
                        GOTO(out_free, major);
                }

                if (memcmp(md5cksum.data + 8, krb5_hdr + 16, 8)) {
                        CERROR("checksum mismatch\n");
                        rawobj_free(&md5cksum);
                        GOTO(out_free, major = GSS_S_BAD_SIG);
                }
                break;
        default:
                CERROR("not support signalg %d\n", signalg);
                GOTO(out_free, major);
        }

        rawobj_free(&md5cksum);

        /* FIXME add expire checking here */

        major = krb5_get_seq_num(kctx->seq, krb5_hdr + 16,
                                 krb5_hdr + 8, &direction,
                                 &seqnum);
        if (major) {
                CERROR("get seq number err: 0x%x\n", major);
                GOTO(out_free, major);
        }

        if ((kctx->initiate && direction != 0xff) ||
            (!kctx->initiate && direction != 0)) {
                CERROR("flag checking error\n");
                GOTO(out_free, major = GSS_S_BAD_SIG);
        }

        /* FIXME how to remove the padding? */

        /*
         * copy back
         */
        if (out_token->len < bodysize - blocksize) {
                CERROR("data size %d while buffer only %d\n",
                        bodysize - blocksize, out_token->len);
                GOTO(out_free, major = GSS_S_DEFECTIVE_TOKEN);
        }

        out_token->len = bodysize - blocksize;
        memcpy(out_token->data, plain_out.data + blocksize, out_token->len);
        major = 0;
out_free:
        OBD_FREE(tmpbuf, bodysize);
        RETURN(major);
}
