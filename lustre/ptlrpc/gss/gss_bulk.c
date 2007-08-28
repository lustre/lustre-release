/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2006 Cluster File Systems, Inc.
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
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/random.h>
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

static
int do_bulk_privacy(struct gss_ctx *gctx,
                    struct ptlrpc_bulk_desc *desc,
                    int encrypt, __u32 alg,
                    struct ptlrpc_bulk_sec_desc *bsd)
{
        struct crypto_tfm  *tfm;
        struct scatterlist  sg, sg2, *sgd;
        int                 i, rc;
        __u8                local_iv[sizeof(bsd->bsd_iv)];

        LASSERT(alg < BULK_PRIV_ALG_MAX);

        if (encrypt)
                bsd->bsd_priv_alg = BULK_PRIV_ALG_NULL;

        if (alg == BULK_PRIV_ALG_NULL)
                return 0;

        if (encrypt)
                get_random_bytes(bsd->bsd_iv, sizeof(bsd->bsd_iv));

        /* compute the secret iv */
        lgss_plain_encrypt(gctx, sizeof(local_iv), bsd->bsd_iv, local_iv);

        tfm = crypto_alloc_tfm(sptlrpc_bulk_priv_alg2name(alg),
                               sptlrpc_bulk_priv_alg2flags(alg));
        if (tfm == NULL) {
                CERROR("Failed to allocate TFM %s\n",
                       sptlrpc_bulk_priv_alg2name(alg));
                return -ENOMEM;
        }

        rc = crypto_cipher_setkey(tfm, local_iv, sizeof(local_iv));
        if (rc) {
                CERROR("Failed to set key for TFM %s: %d\n",
                       sptlrpc_bulk_priv_alg2name(alg), rc);
                crypto_free_tfm(tfm);
                return rc;
        }

        for (i = 0; i < desc->bd_iov_count; i++) {
                sg.page = desc->bd_iov[i].kiov_page;
                sg.offset = desc->bd_iov[i].kiov_offset;
                sg.length = desc->bd_iov[i].kiov_len;

                if (desc->bd_enc_pages) {
                        sg2.page = desc->bd_enc_pages[i];
                        sg2.offset = desc->bd_iov[i].kiov_offset;
                        sg2.length = desc->bd_iov[i].kiov_len;

                        sgd = &sg2;
                } else
                        sgd = &sg;

                if (encrypt)
                        rc = crypto_cipher_encrypt(tfm, sgd, &sg, sg.length);
                else
                        rc = crypto_cipher_decrypt(tfm, sgd, &sg, sg.length);

                LASSERT(rc == 0);

                if (desc->bd_enc_pages)
                        desc->bd_iov[i].kiov_page = desc->bd_enc_pages[i];

                /* although the procedure might be lengthy, the crypto functions
                 * internally called cond_resched() from time to time.
                 */
        }

        crypto_free_tfm(tfm);

        if (encrypt)
                bsd->bsd_priv_alg = alg;

        return 0;
}

int gss_cli_ctx_wrap_bulk(struct ptlrpc_cli_ctx *ctx,
                          struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc)
{
        struct gss_cli_ctx              *gctx;
        struct lustre_msg               *msg;
        struct ptlrpc_bulk_sec_desc     *bsdr;
        struct sec_flavor_config        *conf;
        int                              offset, rc;
        ENTRY;

        LASSERT(SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor));
        LASSERT(req->rq_bulk_read || req->rq_bulk_write);

        switch (SEC_FLAVOR_SVC(req->rq_sec_flavor)) {
        case SPTLRPC_SVC_AUTH:
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
        conf = &req->rq_import->imp_obd->u.cli.cl_sec_conf;
        rc = bulk_csum_cli_request(desc, req->rq_bulk_read, conf->sfc_bulk_csum,
                                   msg, offset);
        if (rc) {
                CERROR("client bulk %s: failed to generate checksum: %d\n",
                       req->rq_bulk_read ? "read" : "write", rc);
                RETURN(rc);
        }

        if (conf->sfc_bulk_priv == BULK_PRIV_ALG_NULL)
                RETURN(0);

        /* previous bulk_csum_cli_request() has verified bsdr is good */
        bsdr = lustre_msg_buf(msg, offset, 0);

        if (req->rq_bulk_read) {
                bsdr->bsd_priv_alg = conf->sfc_bulk_priv;
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
                             conf->sfc_bulk_priv, bsdr);
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

        LASSERT(SEC_FLAVOR_HAS_BULK(req->rq_sec_flavor));
        LASSERT(req->rq_bulk_read || req->rq_bulk_write);

        switch (SEC_FLAVOR_SVC(req->rq_sec_flavor)) {
        case SPTLRPC_SVC_AUTH:
                vmsg = req->rq_repbuf;
                voff = vmsg->lm_bufcount - 2;
                LASSERT(vmsg && vmsg->lm_bufcount >= 4);

                rmsg = req->rq_reqbuf;
                roff = rmsg->lm_bufcount - 2; /* second last segment */
                LASSERT(rmsg && rmsg->lm_bufcount >= 4);
                break;
        case SPTLRPC_SVC_PRIV:
                vmsg = req->rq_repbuf;
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
                if (bsdr->bsd_priv_alg == BULK_PRIV_ALG_NULL)
                        goto verify_csum;

                bsdv = lustre_msg_buf(vmsg, voff, 0);
                if (bsdr->bsd_priv_alg != bsdv->bsd_priv_alg) {
                        CERROR("bulk read: cipher algorithm mismatch: client "
                               "request %s but server reply with %s. try to "
                               "use the new one for decryption\n",
                               sptlrpc_bulk_priv_alg2name(bsdr->bsd_priv_alg),
                               sptlrpc_bulk_priv_alg2name(bsdv->bsd_priv_alg));
                }

                gctx = container_of(ctx, struct gss_cli_ctx, gc_base);
                LASSERT(gctx->gc_mechctx);

                rc = do_bulk_privacy(gctx->gc_mechctx, desc, 0,
                                     bsdv->bsd_priv_alg, bsdv);
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
        struct ptlrpc_reply_state    *rs = req->rq_reply_state;
        struct gss_svc_reqctx        *grctx;
        struct ptlrpc_bulk_sec_desc  *bsdv;
        int                           voff, roff, rc;
        ENTRY;

        LASSERT(rs);
        LASSERT(req->rq_bulk_write);

        if (SEC_FLAVOR_SVC(req->rq_sec_flavor) == SPTLRPC_SVC_PRIV) {
                LASSERT(req->rq_reqbuf->lm_bufcount >= 2);
                LASSERT(rs->rs_repbuf->lm_bufcount >= 2);
                voff = req->rq_reqbuf->lm_bufcount - 1;
                roff = rs->rs_repbuf->lm_bufcount - 1;
        } else {
                LASSERT(req->rq_reqbuf->lm_bufcount >= 4);
                LASSERT(rs->rs_repbuf->lm_bufcount >= 4);
                voff = req->rq_reqbuf->lm_bufcount - 2;
                roff = rs->rs_repbuf->lm_bufcount - 2;
        }

        bsdv = lustre_msg_buf(req->rq_reqbuf, voff, sizeof(*bsdv));
        if (bsdv->bsd_priv_alg != BULK_PRIV_ALG_NULL) {
                grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);
                LASSERT(grctx->src_ctx);
                LASSERT(grctx->src_ctx->gsc_mechctx);

                rc = do_bulk_privacy(grctx->src_ctx->gsc_mechctx, desc, 0,
                                     bsdv->bsd_priv_alg, bsdv);
                if (rc) {
                        CERROR("bulk write: server failed to decrypt data\n");
                        RETURN(rc);
                }
        }

        rc = bulk_csum_svc(desc, req->rq_bulk_read,
                           req->rq_reqbuf, voff, rs->rs_repbuf, roff);

        RETURN(rc);
}

int gss_svc_wrap_bulk(struct ptlrpc_request *req,
                      struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_reply_state    *rs = req->rq_reply_state;
        struct gss_svc_reqctx        *grctx;
        struct ptlrpc_bulk_sec_desc  *bsdv, *bsdr;
        int                           voff, roff, rc;
        ENTRY;

        LASSERT(rs);
        LASSERT(req->rq_bulk_read);

        if (SEC_FLAVOR_SVC(req->rq_sec_flavor) == SPTLRPC_SVC_PRIV) {
                voff = req->rq_reqbuf->lm_bufcount - 1;
                roff = rs->rs_repbuf->lm_bufcount - 1;
        } else {
                voff = req->rq_reqbuf->lm_bufcount - 2;
                roff = rs->rs_repbuf->lm_bufcount - 2;
        }

        rc = bulk_csum_svc(desc, req->rq_bulk_read,
                           req->rq_reqbuf, voff, rs->rs_repbuf, roff);
        if (rc)
                RETURN(rc);

        bsdv = lustre_msg_buf(req->rq_reqbuf, voff, sizeof(*bsdv));
        if (bsdv->bsd_priv_alg != BULK_PRIV_ALG_NULL) {
                grctx = gss_svc_ctx2reqctx(req->rq_svc_ctx);
                LASSERT(grctx->src_ctx);
                LASSERT(grctx->src_ctx->gsc_mechctx);

                bsdr = lustre_msg_buf(rs->rs_repbuf, roff, sizeof(*bsdr));

                rc = do_bulk_privacy(grctx->src_ctx->gsc_mechctx, desc, 1,
                                     bsdv->bsd_priv_alg, bsdr);
                if (rc)
                        CERROR("bulk read: server failed to encrypt data\n");
        }

        RETURN(rc);
}

