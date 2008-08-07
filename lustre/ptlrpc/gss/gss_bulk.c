/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ptlrpc/gss/gss_bulk.c
 *
 * Author: Eric Mei <eric.mei@sun.com>
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
#include <linux/mutex.h>
#include <linux/crypto.h>
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

static __u8 zero_iv[CIPHER_MAX_BLKSIZE] = { 0, };

static void buf_to_sl(struct scatterlist *sl,
                      void *buf, unsigned int len)
{
        sl->page = virt_to_page(buf);
        sl->offset = offset_in_page(buf);
        sl->length = len;
}

/*
 * CTS CBC encryption:
 * 1. X(n-1) = P(n-1)
 * 2. E(n-1) = Encrypt(K, X(n-1))
 * 3. C(n)   = HEAD(E(n-1))
 * 4. P      = P(n) | 0
 * 5. D(n)   = E(n-1) XOR P
 * 6. C(n-1) = Encrypt(K, D(n))
 *
 * CTS encryption using standard CBC interface:
 * 1. pad the last partial block with 0.
 * 2. do CBC encryption.
 * 3. swap the last two ciphertext blocks.
 * 4. truncate to original plaintext size.
 */
static int cbc_cts_encrypt(struct ll_crypto_cipher *tfm,
                           struct scatterlist      *sld,
                           struct scatterlist      *sls)
{
        struct scatterlist      slst, sldt;
        struct blkcipher_desc   desc;
        void                   *data;
        __u8                    sbuf[CIPHER_MAX_BLKSIZE];
        __u8                    dbuf[CIPHER_MAX_BLKSIZE];
        unsigned int            blksize, blks, tail;
        int                     rc;

        blksize = ll_crypto_blkcipher_blocksize(tfm);
        blks = sls->length / blksize;
        tail = sls->length % blksize;
        LASSERT(blks > 0 && tail > 0);

        /* pad tail block with 0, copy to sbuf */
        data = cfs_kmap(sls->page);
        memcpy(sbuf, data + sls->offset + blks * blksize, tail);
        memset(sbuf + tail, 0, blksize - tail);
        cfs_kunmap(sls->page);

        buf_to_sl(&slst, sbuf, blksize);
        buf_to_sl(&sldt, dbuf, blksize);
        desc.tfm   = tfm;
        desc.flags = 0;

        /* encrypt head */
        rc = ll_crypto_blkcipher_encrypt(&desc, sld, sls, sls->length - tail);
        if (unlikely(rc)) {
                CERROR("encrypt head (%u) data: %d\n", sls->length - tail, rc);
                return rc;
        }
        /* encrypt tail */
        rc = ll_crypto_blkcipher_encrypt(&desc, &sldt, &slst, blksize);
        if (unlikely(rc)) {
                CERROR("encrypt tail (%u) data: %d\n", slst.length, rc);
                return rc;
        }

        /* swab C(n) and C(n-1), if n == 1, then C(n-1) is the IV */
        data = cfs_kmap(sld->page);

        memcpy(data + sld->offset + blks * blksize,
               data + sld->offset + (blks - 1) * blksize, tail);
        memcpy(data + sld->offset + (blks - 1) * blksize, dbuf, blksize);
        cfs_kunmap(sld->page);

        return 0;
}

/*
 * CTS CBC decryption:
 * 1. D(n)   = Decrypt(K, C(n-1))
 * 2. C      = C(n) | 0
 * 3. X(n)   = D(n) XOR C
 * 4. P(n)   = HEAD(X(n))
 * 5. E(n-1) = C(n) | TAIL(X(n))
 * 6. X(n-1) = Decrypt(K, E(n-1))
 * 7. P(n-1) = X(n-1) XOR C(n-2)
 *
 * CTS decryption using standard CBC interface:
 * 1. D(n)   = Decrypt(K, C(n-1))
 * 2. C(n)   = C(n) | TAIL(D(n))
 * 3. swap the last two ciphertext blocks.
 * 4. do CBC decryption.
 * 5. truncate to original ciphertext size.
 */
static int cbc_cts_decrypt(struct ll_crypto_cipher *tfm,
                           struct scatterlist *sld,
                           struct scatterlist *sls)
{
        struct blkcipher_desc   desc;
        struct scatterlist      slst, sldt;
        void                   *data;
        __u8                    sbuf[CIPHER_MAX_BLKSIZE];
        __u8                    dbuf[CIPHER_MAX_BLKSIZE];
        unsigned int            blksize, blks, tail;
        int                     rc;

        blksize = ll_crypto_blkcipher_blocksize(tfm);
        blks = sls->length / blksize;
        tail = sls->length % blksize;
        LASSERT(blks > 0 && tail > 0);

        /* save current IV, and set IV to zero */
        ll_crypto_blkcipher_get_iv(tfm, sbuf, blksize);
        ll_crypto_blkcipher_set_iv(tfm, zero_iv, blksize);

        /* D(n) = Decrypt(K, C(n-1)) */
        slst = *sls;
        slst.offset += (blks - 1) * blksize;
        slst.length = blksize;

        buf_to_sl(&sldt, dbuf, blksize);
        desc.tfm   = tfm;
        desc.flags = 0;

        rc = ll_crypto_blkcipher_decrypt(&desc, &sldt, &slst, blksize);
        if (unlikely(rc)) {
                CERROR("decrypt C(n-1) (%u): %d\n", slst.length, rc);
                return rc;
        }

        /* restore IV */
        ll_crypto_blkcipher_set_iv(tfm, sbuf, blksize);

        data = cfs_kmap(sls->page);
        /* C(n) = C(n) | TAIL(D(n)) */
        memcpy(dbuf, data + sls->offset + blks * blksize, tail);
        /* swab C(n) and C(n-1) */
        memcpy(sbuf, data + sls->offset + (blks - 1) * blksize, blksize);
        memcpy(data + sls->offset + (blks - 1) * blksize, dbuf, blksize);
        cfs_kunmap(sls->page);

        /* do cbc decrypt */
        buf_to_sl(&slst, sbuf, blksize);
        buf_to_sl(&sldt, dbuf, blksize);

        /* decrypt head */
        rc = ll_crypto_blkcipher_decrypt(&desc, sld, sls, sls->length - tail);
        if (unlikely(rc)) {
                CERROR("decrypt head (%u) data: %d\n", sls->length - tail, rc);
                return rc;
        }
        /* decrypt tail */
        rc = ll_crypto_blkcipher_decrypt(&desc, &sldt, &slst, blksize);
        if (unlikely(rc)) {
                CERROR("decrypt tail (%u) data: %d\n", slst.length, rc);
                return rc;
        }

        /* truncate to original ciphertext size */
        data = cfs_kmap(sld->page);
        memcpy(data + sld->offset + blks * blksize, dbuf, tail);
        cfs_kunmap(sld->page);

        return 0;
}

static inline int do_cts_tfm(struct ll_crypto_cipher *tfm,
                             int encrypt,
                             struct scatterlist *sld,
                             struct scatterlist *sls)
{
#ifndef HAVE_ASYNC_BLOCK_CIPHER
        LASSERT(tfm->crt_cipher.cit_mode == CRYPTO_TFM_MODE_CBC);
#endif

        if (encrypt)
                return cbc_cts_encrypt(tfm, sld, sls);
        else
                return cbc_cts_decrypt(tfm, sld, sls);
}

/*
 * normal encrypt/decrypt of data of even blocksize
 */
static inline int do_cipher_tfm(struct ll_crypto_cipher *tfm,
                                int encrypt,
                                struct scatterlist *sld,
                                struct scatterlist *sls)
{
        struct blkcipher_desc desc;
        desc.tfm   = tfm;
        desc.flags = 0;
        if (encrypt)
                return ll_crypto_blkcipher_encrypt(&desc, sld, sls, sls->length);
        else
                return ll_crypto_blkcipher_decrypt(&desc, sld, sls, sls->length);
}

static struct ll_crypto_cipher *get_stream_cipher(__u8 *key, unsigned int keylen)
{
        const struct sptlrpc_ciph_type *ct;
        struct ll_crypto_cipher        *tfm;
        int                             rc;

        /* using ARC4, the only stream cipher in linux for now */
        ct = sptlrpc_get_ciph_type(BULK_CIPH_ALG_ARC4);
        LASSERT(ct);

        tfm = ll_crypto_alloc_blkcipher(ct->sct_tfm_name, 0, 0);
        if (tfm == NULL) {
                CERROR("Failed to allocate stream TFM %s\n", ct->sct_name);
                return NULL;
        }
        LASSERT(ll_crypto_blkcipher_blocksize(tfm));

        if (keylen > ct->sct_keysize)
                keylen = ct->sct_keysize;

        LASSERT(keylen >= crypto_tfm_alg_min_keysize(tfm));
        LASSERT(keylen <= crypto_tfm_alg_max_keysize(tfm));

        rc = ll_crypto_blkcipher_setkey(tfm, key, keylen);
        if (rc) {
                CERROR("Failed to set key for TFM %s: %d\n", ct->sct_name, rc);
                ll_crypto_free_blkcipher(tfm);
                return NULL;
        }

        return tfm;
}

static int do_bulk_privacy(struct gss_ctx *gctx,
                           struct ptlrpc_bulk_desc *desc,
                           int encrypt, __u32 alg,
                           struct ptlrpc_bulk_sec_desc *bsd)
{
        const struct sptlrpc_ciph_type *ct = sptlrpc_get_ciph_type(alg);
        struct ll_crypto_cipher  *tfm;
        struct ll_crypto_cipher  *stfm = NULL; /* backup stream cipher */
        struct scatterlist        sls, sld, *sldp;
        unsigned int              blksize, keygen_size;
        int                       i, rc;
        __u8                      key[CIPHER_MAX_KEYSIZE];

        LASSERT(ct);

        if (encrypt)
                bsd->bsd_ciph_alg = BULK_CIPH_ALG_NULL;

        if (alg == BULK_CIPH_ALG_NULL)
                return 0;

        if (desc->bd_iov_count <= 0) {
                if (encrypt)
                        bsd->bsd_ciph_alg = alg;
                return 0;
        }

        tfm = ll_crypto_alloc_blkcipher(ct->sct_tfm_name, 0, 0 );
        if (tfm == NULL) {
                CERROR("Failed to allocate TFM %s\n", ct->sct_name);
                return -ENOMEM;
        }
        blksize = ll_crypto_blkcipher_blocksize(tfm);

        LASSERT(crypto_tfm_alg_max_keysize(tfm) >= ct->sct_keysize);
        LASSERT(crypto_tfm_alg_min_keysize(tfm) <= ct->sct_keysize);
        LASSERT(ct->sct_ivsize == 0 ||
                ll_crypto_blkcipher_ivsize(tfm) == ct->sct_ivsize);
        LASSERT(ct->sct_keysize <= CIPHER_MAX_KEYSIZE);
        LASSERT(blksize <= CIPHER_MAX_BLKSIZE);

        /* generate ramdom key seed and compute the secret key based on it.
         * note determined by algorithm which lgss_plain_encrypt use, it
         * might require the key size be its (blocksize * n). so here for
         * simplicity, we force it's be n * MAX_BLKSIZE by padding 0 */
        keygen_size = (ct->sct_keysize + CIPHER_MAX_BLKSIZE - 1) &
                      ~(CIPHER_MAX_BLKSIZE - 1);
        if (encrypt) {
                get_random_bytes(bsd->bsd_key, ct->sct_keysize);
                if (ct->sct_keysize < keygen_size)
                        memset(bsd->bsd_key + ct->sct_keysize, 0,
                               keygen_size - ct->sct_keysize);
        }

        rc = lgss_plain_encrypt(gctx, 0, keygen_size, bsd->bsd_key, key);
        if (rc) {
                CERROR("failed to compute secret key: %d\n", rc);
                goto out;
        }

        rc = ll_crypto_blkcipher_setkey(tfm, key, ct->sct_keysize);
        if (rc) {
                CERROR("Failed to set key for TFM %s: %d\n", ct->sct_name, rc);
                goto out;
        }

        /* stream cipher doesn't need iv */
        if (blksize > 1)
                ll_crypto_blkcipher_set_iv(tfm, zero_iv, blksize);

        for (i = 0; i < desc->bd_iov_count; i++) {
                sls.page = desc->bd_iov[i].kiov_page;
                sls.offset = desc->bd_iov[i].kiov_offset;
                sls.length = desc->bd_iov[i].kiov_len;

                if (unlikely(sls.length == 0)) {
                        CWARN("page %d with 0 length data?\n", i);
                        continue;
                }

                if (unlikely(sls.offset % blksize)) {
                        CERROR("page %d with odd offset %u, TFM %s\n",
                               i, sls.offset, ct->sct_name);
                        rc = -EINVAL;
                        goto out;
                }

                if (desc->bd_enc_pages) {
                        sld.page = desc->bd_enc_pages[i];
                        sld.offset = desc->bd_iov[i].kiov_offset;
                        sld.length = desc->bd_iov[i].kiov_len;

                        sldp = &sld;
                } else {
                        sldp = &sls;
                }

                if (likely(sls.length % blksize == 0)) {
                        /* data length is n * blocksize, do the normal tfm */
                        rc = do_cipher_tfm(tfm, encrypt, sldp, &sls);
                } else if (sls.length < blksize) {
                        /* odd data length, and smaller than 1 block, CTS
                         * doesn't work in this case because it requires
                         * transfer a modified IV to peer. here we use a
                         * "backup" stream cipher to do the tfm */
                        if (stfm == NULL) {
                                stfm = get_stream_cipher(key, ct->sct_keysize);
                                if (tfm == NULL) {
                                        rc = -ENOMEM;
                                        goto out;
                                }
                        }
                        rc = do_cipher_tfm(stfm, encrypt, sldp, &sls);
                } else {
                        /* odd data length but > 1 block, do CTS tfm */
                        rc = do_cts_tfm(tfm, encrypt, sldp, &sls);
                }

                if (unlikely(rc)) {
                        CERROR("error %s page %d/%d: %d\n",
                               encrypt ? "encrypt" : "decrypt",
                               i + 1, desc->bd_iov_count, rc);
                        goto out;
                }

                if (desc->bd_enc_pages)
                        desc->bd_iov[i].kiov_page = desc->bd_enc_pages[i];
        }

        if (encrypt)
                bsd->bsd_ciph_alg = alg;

out:
        if (stfm)
                ll_crypto_free_blkcipher(stfm);

        ll_crypto_free_blkcipher(tfm);
        return rc;
}

int gss_cli_ctx_wrap_bulk(struct ptlrpc_cli_ctx *ctx,
                          struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc)
{
        struct gss_cli_ctx              *gctx;
        struct lustre_msg               *msg;
        struct ptlrpc_bulk_sec_desc     *bsdr;
        int                              offset, rc;
        ENTRY;

        LASSERT(req->rq_pack_bulk);
        LASSERT(req->rq_bulk_read || req->rq_bulk_write);

        switch (RPC_FLVR_SVC(req->rq_flvr.sf_rpc)) {
        case SPTLRPC_SVC_NULL:
                LASSERT(req->rq_reqbuf->lm_bufcount >= 3);
                msg = req->rq_reqbuf;
                offset = msg->lm_bufcount - 1;
                break;
        case SPTLRPC_SVC_AUTH:
        case SPTLRPC_SVC_INTG:
                LASSERT(req->rq_reqbuf->lm_bufcount >= 4);
                msg = req->rq_reqbuf;
                offset = msg->lm_bufcount - 2;
                break;
        case SPTLRPC_SVC_PRIV:
                LASSERT(req->rq_clrbuf->lm_bufcount >= 2);
                msg = req->rq_clrbuf;
                offset = msg->lm_bufcount - 1;
                break;
        default:
                LBUG();
        }

        /* make checksum */
        rc = bulk_csum_cli_request(desc, req->rq_bulk_read,
                                   req->rq_flvr.sf_bulk_hash, msg, offset);
        if (rc) {
                CERROR("client bulk %s: failed to generate checksum: %d\n",
                       req->rq_bulk_read ? "read" : "write", rc);
                RETURN(rc);
        }

        if (req->rq_flvr.sf_bulk_ciph == BULK_CIPH_ALG_NULL)
                RETURN(0);

        /* previous bulk_csum_cli_request() has verified bsdr is good */
        bsdr = lustre_msg_buf(msg, offset, 0);

        if (req->rq_bulk_read) {
                bsdr->bsd_ciph_alg = req->rq_flvr.sf_bulk_ciph;
                RETURN(0);
        }

        /* it turn out to be bulk write */
        rc = sptlrpc_enc_pool_get_pages(desc);
        if (rc) {
                CERROR("bulk write: failed to allocate encryption pages\n");
                RETURN(rc);
        }

        gctx = container_of(ctx, struct gss_cli_ctx, gc_base);
        LASSERT(gctx->gc_mechctx);

        rc = do_bulk_privacy(gctx->gc_mechctx, desc, 1,
                             req->rq_flvr.sf_bulk_ciph, bsdr);
        if (rc)
                CERROR("bulk write: client failed to encrypt pages\n");

        RETURN(rc);
}

int gss_cli_ctx_unwrap_bulk(struct ptlrpc_cli_ctx *ctx,
                            struct ptlrpc_request *req,
                            struct ptlrpc_bulk_desc *desc)
{
        struct gss_cli_ctx              *gctx;
        struct lustre_msg               *rmsg, *vmsg;
        struct ptlrpc_bulk_sec_desc     *bsdr, *bsdv;
        int                              roff, voff, rc;
        ENTRY;

        LASSERT(req->rq_pack_bulk);
        LASSERT(req->rq_bulk_read || req->rq_bulk_write);

        switch (RPC_FLVR_SVC(req->rq_flvr.sf_rpc)) {
        case SPTLRPC_SVC_NULL:
                vmsg = req->rq_repdata;
                voff = vmsg->lm_bufcount - 1;
                LASSERT(vmsg && vmsg->lm_bufcount >= 3);

                rmsg = req->rq_reqbuf;
                roff = rmsg->lm_bufcount - 1; /* last segment */
                LASSERT(rmsg && rmsg->lm_bufcount >= 3);
                break;
        case SPTLRPC_SVC_AUTH:
        case SPTLRPC_SVC_INTG:
                vmsg = req->rq_repdata;
                voff = vmsg->lm_bufcount - 2;
                LASSERT(vmsg && vmsg->lm_bufcount >= 4);

                rmsg = req->rq_reqbuf;
                roff = rmsg->lm_bufcount - 2; /* second last segment */
                LASSERT(rmsg && rmsg->lm_bufcount >= 4);
                break;
        case SPTLRPC_SVC_PRIV:
                vmsg = req->rq_repdata;
                voff = vmsg->lm_bufcount - 1;
                LASSERT(vmsg && vmsg->lm_bufcount >= 2);

                rmsg = req->rq_clrbuf;
                roff = rmsg->lm_bufcount - 1; /* last segment */
                LASSERT(rmsg && rmsg->lm_bufcount >= 2);
                break;
        default:
                LBUG();
        }

        if (req->rq_bulk_read) {
                bsdr = lustre_msg_buf(rmsg, roff, 0);
                if (bsdr->bsd_ciph_alg == BULK_CIPH_ALG_NULL)
                        goto verify_csum;

                bsdv = lustre_msg_buf(vmsg, voff, 0);
                if (bsdr->bsd_ciph_alg != bsdv->bsd_ciph_alg) {
                        CERROR("bulk read: cipher algorithm mismatch: client "
                               "request %s but server reply with %s. try to "
                               "use the new one for decryption\n",
                               sptlrpc_get_ciph_name(bsdr->bsd_ciph_alg),
                               sptlrpc_get_ciph_name(bsdv->bsd_ciph_alg));
                }

                gctx = container_of(ctx, struct gss_cli_ctx, gc_base);
                LASSERT(gctx->gc_mechctx);

                rc = do_bulk_privacy(gctx->gc_mechctx, desc, 0,
                                     bsdv->bsd_ciph_alg, bsdv);
                if (rc) {
                        CERROR("bulk read: client failed to decrypt data\n");
                        RETURN(rc);
                }
        }

verify_csum:
        rc = bulk_csum_cli_reply(desc, req->rq_bulk_read,
                                 rmsg, roff, vmsg, voff);
        RETURN(rc);
}

int gss_svc_unwrap_bulk(struct ptlrpc_request *req,
                        struct ptlrpc_bulk_desc *desc)
{
        struct gss_svc_reqctx        *grctx;
        int                           rc;
        ENTRY;

        LASSERT(req->rq_svc_ctx);
        LASSERT(req->rq_pack_bulk);
        LASSERT(req->rq_bulk_write);

        grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);

        LASSERT(grctx->src_reqbsd);
        LASSERT(grctx->src_repbsd);
        LASSERT(grctx->src_ctx);
        LASSERT(grctx->src_ctx->gsc_mechctx);

        /* decrypt bulk data if it's encrypted */
        if (grctx->src_reqbsd->bsd_ciph_alg != BULK_CIPH_ALG_NULL) {
                rc = do_bulk_privacy(grctx->src_ctx->gsc_mechctx, desc, 0,
                                     grctx->src_reqbsd->bsd_ciph_alg,
                                     grctx->src_reqbsd);
                if (rc) {
                        CERROR("bulk write: server failed to decrypt data\n");
                        RETURN(rc);
                }
        }

        /* verify bulk data checksum */
        rc = bulk_csum_svc(desc, req->rq_bulk_read,
                           grctx->src_reqbsd, grctx->src_reqbsd_size,
                           grctx->src_repbsd, grctx->src_repbsd_size);

        RETURN(rc);
}

int gss_svc_wrap_bulk(struct ptlrpc_request *req,
                      struct ptlrpc_bulk_desc *desc)
{
        struct gss_svc_reqctx        *grctx;
        int                           rc;
        ENTRY;

        LASSERT(req->rq_svc_ctx);
        LASSERT(req->rq_pack_bulk);
        LASSERT(req->rq_bulk_read);

        grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);

        LASSERT(grctx->src_reqbsd);
        LASSERT(grctx->src_repbsd);
        LASSERT(grctx->src_ctx);
        LASSERT(grctx->src_ctx->gsc_mechctx);

        /* generate bulk data checksum */
        rc = bulk_csum_svc(desc, req->rq_bulk_read,
                           grctx->src_reqbsd, grctx->src_reqbsd_size,
                           grctx->src_repbsd, grctx->src_repbsd_size);
        if (rc)
                RETURN(rc);

        /* encrypt bulk data if required */
        if (grctx->src_reqbsd->bsd_ciph_alg != BULK_CIPH_ALG_NULL) {
                rc = do_bulk_privacy(grctx->src_ctx->gsc_mechctx, desc, 1,
                                     grctx->src_reqbsd->bsd_ciph_alg,
                                     grctx->src_repbsd);
                if (rc)
                        CERROR("bulk read: server failed to encrypt data: "
                               "rc %d\n", rc);
        }

        RETURN(rc);
}
