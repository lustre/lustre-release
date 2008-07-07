/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004 - 2006, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 *  linux/net/sunrpc/gss_krb5_mech.c
 *  linux/net/sunrpc/gss_krb5_crypto.c
 *  linux/net/sunrpc/gss_krb5_seal.c
 *  linux/net/sunrpc/gss_krb5_seqnum.c
 *  linux/net/sunrpc/gss_krb5_unseal.c
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
#include <linux/random.h>
#include <linux/mutex.h>
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
#include "gss_asn1.h"
#include "gss_krb5.h"

spinlock_t krb5_seq_lock = SPIN_LOCK_UNLOCKED;

struct krb5_enctype {
        char           *ke_dispname;
        char           *ke_enc_name;            /* linux tfm name */
        char           *ke_hash_name;           /* linux tfm name */
        int             ke_enc_mode;            /* linux tfm mode */
        int             ke_hash_size;           /* checksum size */
        int             ke_conf_size;           /* confounder size */
        unsigned int    ke_hash_hmac:1;         /* is hmac? */
};

/*
 * NOTE: for aes128-cts and aes256-cts, MIT implementation use CTS encryption.
 * but currently we simply CBC with padding, because linux doesn't support CTS
 * yet. this need to be fixed in the future.
 */
static struct krb5_enctype enctypes[] = {
        [ENCTYPE_DES_CBC_RAW] = {               /* des-cbc-md5 */
                "des-cbc-md5",
                "cbc(des)",
                "md5",
                0,
                16,
                8,
                0,
        },
        [ENCTYPE_DES3_CBC_RAW] = {              /* des3-hmac-sha1 */
                "des3-hmac-sha1",
                "cbc(des3_ede)",
                "hmac(sha1)",
                0,
                20,
                8,
                1,
        },
        [ENCTYPE_AES128_CTS_HMAC_SHA1_96] = {   /* aes128-cts */
                "aes128-cts-hmac-sha1-96",
                "cbc(aes)",
                "hmac(sha1)",
                0,
                12,
                16,
                1,
        },
        [ENCTYPE_AES256_CTS_HMAC_SHA1_96] = {   /* aes256-cts */
                "aes256-cts-hmac-sha1-96",
                "cbc(aes)",
                "hmac(sha1)",
                0,
                12,
                16,
                1,
        },
        [ENCTYPE_ARCFOUR_HMAC] = {              /* arcfour-hmac-md5 */
                "arcfour-hmac-md5",
                "ecb(arc4)",
                "hmac(md5)",
                0,
                16,
                8,
                1,
        },
};

#define MAX_ENCTYPES    sizeof(enctypes)/sizeof(struct krb5_enctype)

static const char * enctype2str(__u32 enctype)
{
        if (enctype < MAX_ENCTYPES && enctypes[enctype].ke_dispname)
                return enctypes[enctype].ke_dispname;

        return "unknown";
}

static
int keyblock_init(struct krb5_keyblock *kb, char *alg_name, int alg_mode)
{
        kb->kb_tfm = ll_crypto_alloc_blkcipher(alg_name, alg_mode, 0);
        if (kb->kb_tfm == NULL) {
                CERROR("failed to alloc tfm: %s, mode %d\n",
                       alg_name, alg_mode);
                return -1;
        }

        if (ll_crypto_blkcipher_setkey(kb->kb_tfm, kb->kb_key.data, kb->kb_key.len)) {
                CERROR("failed to set %s key, len %d\n",
                       alg_name, kb->kb_key.len);
                return -1;
        }

        return 0;
}

static
int krb5_init_keys(struct krb5_ctx *kctx)
{
        struct krb5_enctype *ke;

        if (kctx->kc_enctype >= MAX_ENCTYPES ||
            enctypes[kctx->kc_enctype].ke_hash_size == 0) {
                CERROR("unsupported enctype %x\n", kctx->kc_enctype);
                return -1;
        }

        ke = &enctypes[kctx->kc_enctype];

        /* tfm arc4 is stateful, user should alloc-use-free by his own */
        if (kctx->kc_enctype != ENCTYPE_ARCFOUR_HMAC &&
            keyblock_init(&kctx->kc_keye, ke->ke_enc_name, ke->ke_enc_mode))
                return -1;

        /* tfm hmac is stateful, user should alloc-use-free by his own */
        if (ke->ke_hash_hmac == 0 &&
            keyblock_init(&kctx->kc_keyi, ke->ke_enc_name, ke->ke_enc_mode))
                return -1;
        if (ke->ke_hash_hmac == 0 &&
            keyblock_init(&kctx->kc_keyc, ke->ke_enc_name, ke->ke_enc_mode))
                return -1;

        return 0;
}

static
void keyblock_free(struct krb5_keyblock *kb)
{
        rawobj_free(&kb->kb_key);
        if (kb->kb_tfm)
                ll_crypto_free_blkcipher(kb->kb_tfm);
}

static
int keyblock_dup(struct krb5_keyblock *new, struct krb5_keyblock *kb)
{
        return rawobj_dup(&new->kb_key, &kb->kb_key);
}

static
int get_bytes(char **ptr, const char *end, void *res, int len)
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

static
int get_rawobj(char **ptr, const char *end, rawobj_t *res)
{
        char   *p, *q;
        __u32   len;

        p = *ptr;
        if (get_bytes(&p, end, &len, sizeof(len)))
                return -1;

        q = p + len;
        if (q > end || q < p)
                return -1;

        OBD_ALLOC(res->data, len);
        if (!res->data)
                return -1;

        res->len = len;
        memcpy(res->data, p, len);
        *ptr = q;
        return 0;
}

static
int get_keyblock(char **ptr, const char *end,
                 struct krb5_keyblock *kb, __u32 keysize)
{
        char *buf;

        OBD_ALLOC(buf, keysize);
        if (buf == NULL)
                return -1;

        if (get_bytes(ptr, end, buf, keysize)) {
                OBD_FREE(buf, keysize);
                return -1;
        }

        kb->kb_key.len = keysize;
        kb->kb_key.data = buf;
        return 0;
}

static
void delete_context_kerberos(struct krb5_ctx *kctx)
{
        rawobj_free(&kctx->kc_mech_used);

        keyblock_free(&kctx->kc_keye);
        keyblock_free(&kctx->kc_keyi);
        keyblock_free(&kctx->kc_keyc);
}

static
__u32 import_context_rfc1964(struct krb5_ctx *kctx, char *p, char *end)
{
        unsigned int    tmp_uint, keysize;

        /* seed_init flag */
        if (get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
                goto out_err;
        kctx->kc_seed_init = (tmp_uint != 0);

        /* seed */
        if (get_bytes(&p, end, kctx->kc_seed, sizeof(kctx->kc_seed)))
                goto out_err;

        /* sign/seal algorithm, not really used now */
        if (get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)) ||
            get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
                goto out_err;

        /* end time */
        if (get_bytes(&p, end, &kctx->kc_endtime, sizeof(kctx->kc_endtime)))
                goto out_err;

        /* seq send */
        if (get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
                goto out_err;
        kctx->kc_seq_send = tmp_uint;

        /* mech oid */
        if (get_rawobj(&p, end, &kctx->kc_mech_used))
                goto out_err;

        /* old style enc/seq keys in format:
         *   - enctype (u32)
         *   - keysize (u32)
         *   - keydata
         * we decompose them to fit into the new context
         */

        /* enc key */
        if (get_bytes(&p, end, &kctx->kc_enctype, sizeof(kctx->kc_enctype)))
                goto out_err;

        if (get_bytes(&p, end, &keysize, sizeof(keysize)))
                goto out_err;

        if (get_keyblock(&p, end, &kctx->kc_keye, keysize))
                goto out_err;

        /* seq key */
        if (get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)) ||
            tmp_uint != kctx->kc_enctype)
                goto out_err;

        if (get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)) ||
            tmp_uint != keysize)
                goto out_err;

        if (get_keyblock(&p, end, &kctx->kc_keyc, keysize))
                goto out_err;

        /* old style fallback */
        if (keyblock_dup(&kctx->kc_keyi, &kctx->kc_keyc))
                goto out_err;

        if (p != end)
                goto out_err;

        CDEBUG(D_SEC, "succesfully imported rfc1964 context\n");
        return 0;
out_err:
        return GSS_S_FAILURE;
}

/* Flags for version 2 context flags */
#define KRB5_CTX_FLAG_INITIATOR		0x00000001
#define KRB5_CTX_FLAG_CFX		0x00000002
#define KRB5_CTX_FLAG_ACCEPTOR_SUBKEY	0x00000004

static
__u32 import_context_rfc4121(struct krb5_ctx *kctx, char *p, char *end)
{
        unsigned int    tmp_uint, keysize;

        /* end time */
        if (get_bytes(&p, end, &kctx->kc_endtime, sizeof(kctx->kc_endtime)))
                goto out_err;

        /* flags */
        if (get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
                goto out_err;

        if (tmp_uint & KRB5_CTX_FLAG_INITIATOR)
                kctx->kc_initiate = 1;
        if (tmp_uint & KRB5_CTX_FLAG_CFX)
                kctx->kc_cfx = 1;
        if (tmp_uint & KRB5_CTX_FLAG_ACCEPTOR_SUBKEY)
                kctx->kc_have_acceptor_subkey = 1;

        /* seq send */
        if (get_bytes(&p, end, &kctx->kc_seq_send, sizeof(kctx->kc_seq_send)))
                goto out_err;

        /* enctype */
        if (get_bytes(&p, end, &kctx->kc_enctype, sizeof(kctx->kc_enctype)))
                goto out_err;

        /* size of each key */
        if (get_bytes(&p, end, &keysize, sizeof(keysize)))
                goto out_err;

        /* number of keys - should always be 3 */
        if (get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
                goto out_err;

        if (tmp_uint != 3) {
                CERROR("Invalid number of keys: %u\n", tmp_uint);
                goto out_err;
        }

        /* ke */
        if (get_keyblock(&p, end, &kctx->kc_keye, keysize))
                goto out_err;
        /* ki */
        if (get_keyblock(&p, end, &kctx->kc_keyi, keysize))
                goto out_err;
        /* ki */
        if (get_keyblock(&p, end, &kctx->kc_keyc, keysize))
                goto out_err;

        CDEBUG(D_SEC, "succesfully imported v2 context\n");
        return 0;
out_err:
        return GSS_S_FAILURE;
}

/*
 * The whole purpose here is trying to keep user level gss context parsing
 * from nfs-utils unchanged as possible as we can, they are not quite mature
 * yet, and many stuff still not clear, like heimdal etc.
 */
static
__u32 gss_import_sec_context_kerberos(rawobj_t *inbuf,
                                      struct gss_ctx *gctx)
{
        struct krb5_ctx *kctx;
        char            *p = (char *) inbuf->data;
        char            *end = (char *) (inbuf->data + inbuf->len);
        unsigned int     tmp_uint, rc;

        if (get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint))) {
                CERROR("Fail to read version\n");
                return GSS_S_FAILURE;
        }

        /* only support 0, 1 for the moment */
        if (tmp_uint > 2) {
                CERROR("Invalid version %u\n", tmp_uint);
                return GSS_S_FAILURE;
        }

        OBD_ALLOC_PTR(kctx);
        if (!kctx)
                return GSS_S_FAILURE;

        if (tmp_uint == 0 || tmp_uint == 1) {
                kctx->kc_initiate = tmp_uint;
                rc = import_context_rfc1964(kctx, p, end);
        } else {
                rc = import_context_rfc4121(kctx, p, end);
        }

        if (rc == 0)
                rc = krb5_init_keys(kctx);

        if (rc) {
                delete_context_kerberos(kctx);
                OBD_FREE_PTR(kctx);

                return GSS_S_FAILURE;
        }

        gctx->internal_ctx_id = kctx;
        return GSS_S_COMPLETE;
}

static
__u32 gss_copy_reverse_context_kerberos(struct gss_ctx *gctx,
                                        struct gss_ctx *gctx_new)
{
        struct krb5_ctx *kctx = gctx->internal_ctx_id;
        struct krb5_ctx *knew;

        OBD_ALLOC_PTR(knew);
        if (!knew)
                return GSS_S_FAILURE;

        knew->kc_initiate = kctx->kc_initiate ? 0 : 1;
        knew->kc_cfx = kctx->kc_cfx;
        knew->kc_seed_init = kctx->kc_seed_init;
        knew->kc_have_acceptor_subkey = kctx->kc_have_acceptor_subkey;
        knew->kc_endtime = kctx->kc_endtime;

        memcpy(knew->kc_seed, kctx->kc_seed, sizeof(kctx->kc_seed));
        knew->kc_seq_send = kctx->kc_seq_recv;
        knew->kc_seq_recv = kctx->kc_seq_send;
        knew->kc_enctype = kctx->kc_enctype;

        if (rawobj_dup(&knew->kc_mech_used, &kctx->kc_mech_used))
                goto out_err;

        if (keyblock_dup(&knew->kc_keye, &kctx->kc_keye))
                goto out_err;
        if (keyblock_dup(&knew->kc_keyi, &kctx->kc_keyi))
                goto out_err;
        if (keyblock_dup(&knew->kc_keyc, &kctx->kc_keyc))
                goto out_err;
        if (krb5_init_keys(knew))
                goto out_err;

        gctx_new->internal_ctx_id = knew;
        CDEBUG(D_SEC, "succesfully copied reverse context\n");
        return GSS_S_COMPLETE;

out_err:
        delete_context_kerberos(knew);
        OBD_FREE_PTR(knew);
        return GSS_S_FAILURE;
}

static
__u32 gss_inquire_context_kerberos(struct gss_ctx *gctx,
                                   unsigned long  *endtime)
{
        struct krb5_ctx *kctx = gctx->internal_ctx_id;

        *endtime = (unsigned long) ((__u32) kctx->kc_endtime);
        return GSS_S_COMPLETE;
}

static
void gss_delete_sec_context_kerberos(void *internal_ctx)
{
        struct krb5_ctx *kctx = internal_ctx;

        delete_context_kerberos(kctx);
        OBD_FREE_PTR(kctx);
}

static
void buf_to_sg(struct scatterlist *sg, char *ptr, int len)
{
        sg->page = virt_to_page(ptr);
        sg->offset = offset_in_page(ptr);
        sg->length = len;
}

static
__u32 krb5_encrypt(struct ll_crypto_cipher *tfm,
                   int decrypt,
                   void * iv,
                   void * in,
                   void * out,
                   int length)
{
        struct blkcipher_desc desc;
        struct scatterlist    sg;
        __u8 local_iv[16] = {0};
        __u32 ret = -EINVAL;

        LASSERT(tfm);
        desc.tfm  = tfm;
        desc.info = local_iv;
        desc.flags= 0;

        if (length % ll_crypto_blkcipher_blocksize(tfm) != 0) {
                CERROR("output length %d mismatch blocksize %d\n",
                       length, ll_crypto_blkcipher_blocksize(tfm));
                goto out;
        }

        if (ll_crypto_blkcipher_ivsize(tfm) > 16) {
                CERROR("iv size too large %d\n", ll_crypto_blkcipher_ivsize(tfm));
                goto out;
        }

        if (iv)
                memcpy(local_iv, iv, ll_crypto_blkcipher_ivsize(tfm));

        memcpy(out, in, length);
        buf_to_sg(&sg, out, length);

        if (decrypt)
                ret = ll_crypto_blkcipher_decrypt_iv(&desc, &sg, &sg, length);
        else
                ret = ll_crypto_blkcipher_encrypt_iv(&desc, &sg, &sg, length);

out:
        return(ret);
}

static inline
int krb5_digest_hmac(struct ll_crypto_hash *tfm,
                     rawobj_t *key,
                     struct krb5_header *khdr,
                     int msgcnt, rawobj_t *msgs,
                     rawobj_t *cksum)
#ifdef HAVE_ASYNC_BLOCK_CIPHER
{
        struct hash_desc   desc;
        struct scatterlist sg[1];
        int                i;

        ll_crypto_hash_setkey(tfm, key->data, key->len);
        desc.tfm  = tfm;
        desc.flags= 0;

        ll_crypto_hash_init(&desc);

        for (i = 0; i < msgcnt; i++) {
                if (msgs[i].len == 0)
                        continue;
                buf_to_sg(sg, (char *) msgs[i].data, msgs[i].len);
                ll_crypto_hash_update(&desc, sg, msgs[i].len);
        }

        if (khdr) {
                buf_to_sg(sg, (char *) khdr, sizeof(*khdr));
                ll_crypto_hash_update(&desc, sg, sizeof(*khdr));
        }

        return ll_crypto_hash_final(&desc, cksum->data);
}
#else /* HAVE_ASYNC_BLOCK_CIPHER */
{
        struct scatterlist sg[1];
        __u32              keylen = key->len, i;

        crypto_hmac_init(tfm, key->data, &keylen);

        for (i = 0; i < msgcnt; i++) {
                if (msgs[i].len == 0)
                        continue;
                buf_to_sg(sg, (char *) msgs[i].data, msgs[i].len);
                crypto_hmac_update(tfm, sg, 1);
        }

        if (khdr) {
                buf_to_sg(sg, (char *) khdr, sizeof(*khdr));
                crypto_hmac_update(tfm, sg, 1);
        }

        crypto_hmac_final(tfm, key->data, &keylen, cksum->data);
        return 0;
}
#endif /* HAVE_ASYNC_BLOCK_CIPHER */

static inline
int krb5_digest_norm(struct ll_crypto_hash *tfm,
                     struct krb5_keyblock *kb,
                     struct krb5_header *khdr,
                     int msgcnt, rawobj_t *msgs,
                     rawobj_t *cksum)
{
        struct hash_desc   desc;
        struct scatterlist sg[1];
        int                i;

        LASSERT(kb->kb_tfm);
        desc.tfm  = tfm;
        desc.flags= 0;

        ll_crypto_hash_init(&desc);

        for (i = 0; i < msgcnt; i++) {
                if (msgs[i].len == 0)
                        continue;
                buf_to_sg(sg, (char *) msgs[i].data, msgs[i].len);
                ll_crypto_hash_update(&desc, sg, msgs[i].len);
        }

        if (khdr) {
                buf_to_sg(sg, (char *) khdr, sizeof(*khdr));
                ll_crypto_hash_update(&desc, sg, sizeof(*khdr));
        }

        ll_crypto_hash_final(&desc, cksum->data);

        return krb5_encrypt(kb->kb_tfm, 0, NULL, cksum->data,
                            cksum->data, cksum->len);
}

/*
 * compute (keyed/keyless) checksum against the plain text which appended
 * with krb5 wire token header.
 */
static
__s32 krb5_make_checksum(__u32 enctype,
                         struct krb5_keyblock *kb,
                         struct krb5_header *khdr,
                         int msgcnt, rawobj_t *msgs,
                         rawobj_t *cksum)
{
        struct krb5_enctype   *ke = &enctypes[enctype];
        struct ll_crypto_hash *tfm;
        __u32                  code = GSS_S_FAILURE;
        int                    rc;

        if (!(tfm = ll_crypto_alloc_hash(ke->ke_hash_name, 0, 0))) {
                CERROR("failed to alloc TFM: %s\n", ke->ke_hash_name);
                return GSS_S_FAILURE;
        }

        cksum->len = ll_crypto_hash_digestsize(tfm);
        OBD_ALLOC(cksum->data, cksum->len);
        if (!cksum->data) {
                cksum->len = 0;
                goto out_tfm;
        }

        if (ke->ke_hash_hmac)
                rc = krb5_digest_hmac(tfm, &kb->kb_key,
                                      khdr, msgcnt, msgs, cksum);
        else
                rc = krb5_digest_norm(tfm, kb,
                                      khdr, msgcnt, msgs, cksum);

        if (rc == 0)
                code = GSS_S_COMPLETE;
out_tfm:
        ll_crypto_free_hash(tfm);
        return code;
}

static
__u32 gss_get_mic_kerberos(struct gss_ctx *gctx,
                           int msgcnt,
                           rawobj_t *msgs,
                           rawobj_t *token)
{
        struct krb5_ctx     *kctx = gctx->internal_ctx_id;
        struct krb5_enctype *ke = &enctypes[kctx->kc_enctype];
        struct krb5_header  *khdr;
        unsigned char        acceptor_flag;
        rawobj_t             cksum = RAWOBJ_EMPTY;
        __u32                rc = GSS_S_FAILURE;

        acceptor_flag = kctx->kc_initiate ? 0 : FLAG_SENDER_IS_ACCEPTOR;

        /* fill krb5 header */
        LASSERT(token->len >= sizeof(*khdr));
        khdr = (struct krb5_header *) token->data;

        khdr->kh_tok_id = cpu_to_be16(KG_TOK_MIC_MSG);
        khdr->kh_flags = acceptor_flag;
        khdr->kh_filler = 0xff;
        khdr->kh_ec = cpu_to_be16(0xffff);
        khdr->kh_rrc = cpu_to_be16(0xffff);
        spin_lock(&krb5_seq_lock);
        khdr->kh_seq = cpu_to_be64(kctx->kc_seq_send++);
        spin_unlock(&krb5_seq_lock);

        /* checksum */
        if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyc,
                               khdr, msgcnt, msgs, &cksum))
                goto out_err;

        LASSERT(cksum.len >= ke->ke_hash_size);
        LASSERT(token->len >= sizeof(*khdr) + ke->ke_hash_size);
        memcpy(khdr + 1, cksum.data + cksum.len - ke->ke_hash_size,
               ke->ke_hash_size);

        token->len = sizeof(*khdr) + ke->ke_hash_size;
        rc = GSS_S_COMPLETE;
out_err:
        rawobj_free(&cksum);
        return rc;
}

static
__u32 gss_verify_mic_kerberos(struct gss_ctx *gctx,
                              int msgcnt,
                              rawobj_t *msgs,
                              rawobj_t *token)
{
        struct krb5_ctx     *kctx = gctx->internal_ctx_id;
        struct krb5_enctype *ke = &enctypes[kctx->kc_enctype];
        struct krb5_header  *khdr;
        unsigned char        acceptor_flag;
        rawobj_t             cksum = RAWOBJ_EMPTY;
        __u32                rc = GSS_S_FAILURE;

        acceptor_flag = kctx->kc_initiate ? FLAG_SENDER_IS_ACCEPTOR : 0;

        if (token->len < sizeof(*khdr)) {
                CERROR("short signature: %u\n", token->len);
                return GSS_S_DEFECTIVE_TOKEN;
        }

        khdr = (struct krb5_header *) token->data;

        /* sanity checks */
        if (be16_to_cpu(khdr->kh_tok_id) != KG_TOK_MIC_MSG) {
                CERROR("bad token id\n");
                return GSS_S_DEFECTIVE_TOKEN;
        }
        if ((khdr->kh_flags & FLAG_SENDER_IS_ACCEPTOR) != acceptor_flag) {
                CERROR("bad direction flag\n");
                return GSS_S_BAD_SIG;
        }
        if (khdr->kh_filler != 0xff) {
                CERROR("bad filler\n");
                return GSS_S_DEFECTIVE_TOKEN;
        }
        if (be16_to_cpu(khdr->kh_ec) != 0xffff ||
            be16_to_cpu(khdr->kh_rrc) != 0xffff) {
                CERROR("bad EC or RRC\n");
                return GSS_S_DEFECTIVE_TOKEN;
        }

        if (token->len < sizeof(*khdr) + ke->ke_hash_size) {
                CERROR("short signature: %u, require %d\n",
                       token->len, (int) sizeof(*khdr) + ke->ke_hash_size);
                goto out;
        }

        if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyc,
                               khdr, msgcnt, msgs, &cksum))
                return GSS_S_FAILURE;

        LASSERT(cksum.len >= ke->ke_hash_size);
        if (memcmp(khdr + 1, cksum.data + cksum.len - ke->ke_hash_size,
                   ke->ke_hash_size)) {
                CERROR("checksum mismatch\n");
                rc = GSS_S_BAD_SIG;
                goto out;
        }

        rc = GSS_S_COMPLETE;
out:
        rawobj_free(&cksum);
        return rc;
}

static
int add_padding(rawobj_t *msg, int msg_buflen, int blocksize)
{
        int padding;

        padding = (blocksize - (msg->len & (blocksize - 1))) &
                  (blocksize - 1);
        if (!padding)
                return 0;

        if (msg->len + padding > msg_buflen) {
                CERROR("bufsize %u too small: datalen %u, padding %u\n",
                        msg_buflen, msg->len, padding);
                return -EINVAL;
        }

        memset(msg->data + msg->len, padding, padding);
        msg->len += padding;
        return 0;
}

static
int krb5_encrypt_rawobjs(struct ll_crypto_cipher *tfm,
                         int mode_ecb,
                         int inobj_cnt,
                         rawobj_t *inobjs,
                         rawobj_t *outobj,
                         int enc)
{
        struct blkcipher_desc desc;
        struct scatterlist    src, dst;
        __u8                  local_iv[16] = {0}, *buf;
        __u32                 datalen = 0;
        int                   i, rc;
        ENTRY;

        buf = outobj->data;
        desc.tfm  = tfm;
        desc.info = local_iv;
        desc.flags = 0;

        for (i = 0; i < inobj_cnt; i++) {
                LASSERT(buf + inobjs[i].len <= outobj->data + outobj->len);

                buf_to_sg(&src, inobjs[i].data, inobjs[i].len);
                buf_to_sg(&dst, buf, outobj->len - datalen);

                if (mode_ecb) {
                        if (enc)
                                rc = ll_crypto_blkcipher_encrypt(
                                        &desc, &dst, &src, src.length);
                        else
                                rc = ll_crypto_blkcipher_decrypt(
                                        &desc, &dst, &src, src.length);
                } else {
                        if (enc)
                                rc = ll_crypto_blkcipher_encrypt_iv(
                                        &desc, &dst, &src, src.length);
                        else
                                rc = ll_crypto_blkcipher_decrypt_iv(
                                        &desc, &dst, &src, src.length);
                }

                if (rc) {
                        CERROR("encrypt error %d\n", rc);
                        RETURN(rc);
                }

                datalen += inobjs[i].len;
                buf += inobjs[i].len;
        }

        outobj->len = datalen;
        RETURN(0);
}

static
__u32 gss_wrap_kerberos(struct gss_ctx *gctx,
                        rawobj_t *gsshdr,
                        rawobj_t *msg,
                        int msg_buflen,
                        rawobj_t *token)
{
        struct krb5_ctx     *kctx = gctx->internal_ctx_id;
        struct krb5_enctype *ke = &enctypes[kctx->kc_enctype];
        struct krb5_header  *khdr;
        unsigned char        acceptor_flag;
        int                  blocksize;
        rawobj_t             cksum = RAWOBJ_EMPTY;
        rawobj_t             data_desc[4], cipher;
        __u8                 conf[GSS_MAX_CIPHER_BLOCK];
        int                  enc_rc = 0;

        LASSERT(ke);
        LASSERT(ke->ke_conf_size <= GSS_MAX_CIPHER_BLOCK);
        LASSERT(kctx->kc_keye.kb_tfm == NULL ||
                ke->ke_conf_size >=
                ll_crypto_blkcipher_blocksize(kctx->kc_keye.kb_tfm));

        /*
         * final token format:
         * ---------------------------------------------------
         * | krb5 header | cipher text | checksum (16 bytes) |
         * ---------------------------------------------------
         */

        /* fill krb5 header */
        LASSERT(token->len >= sizeof(*khdr));
        khdr = (struct krb5_header *) token->data;
        acceptor_flag = kctx->kc_initiate ? 0 : FLAG_SENDER_IS_ACCEPTOR;

        khdr->kh_tok_id = cpu_to_be16(KG_TOK_WRAP_MSG);
        khdr->kh_flags = acceptor_flag | FLAG_WRAP_CONFIDENTIAL;
        khdr->kh_filler = 0xff;
        khdr->kh_ec = cpu_to_be16(0);
        khdr->kh_rrc = cpu_to_be16(0);
        spin_lock(&krb5_seq_lock);
        khdr->kh_seq = cpu_to_be64(kctx->kc_seq_send++);
        spin_unlock(&krb5_seq_lock);

        /* generate confounder */
        get_random_bytes(conf, ke->ke_conf_size);

        /* get encryption blocksize. note kc_keye might not associated with
         * a tfm, currently only for arcfour-hmac */
        if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
                LASSERT(kctx->kc_keye.kb_tfm == NULL);
                blocksize = 1;
        } else {
                LASSERT(kctx->kc_keye.kb_tfm);
                blocksize = ll_crypto_blkcipher_blocksize(kctx->kc_keye.kb_tfm);
        }
        LASSERT(blocksize <= ke->ke_conf_size);

        /* padding the message */
        if (add_padding(msg, msg_buflen, blocksize))
                return GSS_S_FAILURE;

        /*
         * clear text layout for checksum:
         * ------------------------------------------------------
         * | confounder | gss header | clear msgs | krb5 header |
         * ------------------------------------------------------
         */
        data_desc[0].data = conf;
        data_desc[0].len = ke->ke_conf_size;
        data_desc[1].data = gsshdr->data;
        data_desc[1].len = gsshdr->len;
        data_desc[2].data = msg->data;
        data_desc[2].len = msg->len;
        data_desc[3].data = (__u8 *) khdr;
        data_desc[3].len = sizeof(*khdr);

        /* compute checksum */
        if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyi,
                               khdr, 4, data_desc, &cksum))
                return GSS_S_FAILURE;
        LASSERT(cksum.len >= ke->ke_hash_size);

        /*
         * clear text layout for encryption:
         * -----------------------------------------
         * | confounder | clear msgs | krb5 header |
         * -----------------------------------------
         */
        data_desc[0].data = conf;
        data_desc[0].len = ke->ke_conf_size;
        data_desc[1].data = msg->data;
        data_desc[1].len = msg->len;
        data_desc[2].data = (__u8 *) khdr;
        data_desc[2].len = sizeof(*khdr);

        /* cipher text will be directly inplace */
        cipher.data = (__u8 *) (khdr + 1);
        cipher.len = token->len - sizeof(*khdr);
        LASSERT(cipher.len >= ke->ke_conf_size + msg->len + sizeof(*khdr));

        if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
                rawobj_t                 arc4_keye;
                struct ll_crypto_cipher *arc4_tfm;

                if (krb5_make_checksum(ENCTYPE_ARCFOUR_HMAC, &kctx->kc_keyi,
                                       NULL, 1, &cksum, &arc4_keye)) {
                        CERROR("failed to obtain arc4 enc key\n");
                        GOTO(arc4_out, enc_rc = -EACCES);
                }

                arc4_tfm = ll_crypto_alloc_blkcipher("ecb(arc4)", 0, 0);
                if (arc4_tfm == NULL) {
                        CERROR("failed to alloc tfm arc4 in ECB mode\n");
                        GOTO(arc4_out_key, enc_rc = -EACCES);
                }

                if (ll_crypto_blkcipher_setkey(arc4_tfm, arc4_keye.data,
                                               arc4_keye.len)) {
                        CERROR("failed to set arc4 key, len %d\n",
                               arc4_keye.len);
                        GOTO(arc4_out_tfm, enc_rc = -EACCES);
                }

                enc_rc = krb5_encrypt_rawobjs(arc4_tfm, 1,
                                              3, data_desc, &cipher, 1);
arc4_out_tfm:
                ll_crypto_free_blkcipher(arc4_tfm);
arc4_out_key:
                rawobj_free(&arc4_keye);
arc4_out:
                do {} while(0); /* just to avoid compile warning */
        } else {
                enc_rc = krb5_encrypt_rawobjs(kctx->kc_keye.kb_tfm, 0,
                                              3, data_desc, &cipher, 1);
        }

        if (enc_rc != 0) {
                rawobj_free(&cksum);
                return GSS_S_FAILURE;
        }

        /* fill in checksum */
        LASSERT(token->len >= sizeof(*khdr) + cipher.len + ke->ke_hash_size);
        memcpy((char *)(khdr + 1) + cipher.len,
               cksum.data + cksum.len - ke->ke_hash_size,
               ke->ke_hash_size);
        rawobj_free(&cksum);

        /* final token length */
        token->len = sizeof(*khdr) + cipher.len + ke->ke_hash_size;
        return GSS_S_COMPLETE;
}

static
__u32 gss_unwrap_kerberos(struct gss_ctx  *gctx,
                          rawobj_t        *gsshdr,
                          rawobj_t        *token,
                          rawobj_t        *msg)
{
        struct krb5_ctx     *kctx = gctx->internal_ctx_id;
        struct krb5_enctype *ke = &enctypes[kctx->kc_enctype];
        struct krb5_header  *khdr;
        unsigned char        acceptor_flag;
        unsigned char       *tmpbuf;
        int                  blocksize, bodysize;
        rawobj_t             cksum = RAWOBJ_EMPTY;
        rawobj_t             cipher_in, plain_out;
        rawobj_t             hash_objs[3];
        __u32                rc = GSS_S_FAILURE, enc_rc = 0;

        LASSERT(ke);

        acceptor_flag = kctx->kc_initiate ? FLAG_SENDER_IS_ACCEPTOR : 0;

        if (token->len < sizeof(*khdr)) {
                CERROR("short signature: %u\n", token->len);
                return GSS_S_DEFECTIVE_TOKEN;
        }

        khdr = (struct krb5_header *) token->data;

        /* sanity check header */
        if (be16_to_cpu(khdr->kh_tok_id) != KG_TOK_WRAP_MSG) {
                CERROR("bad token id\n");
                return GSS_S_DEFECTIVE_TOKEN;
        }
        if ((khdr->kh_flags & FLAG_SENDER_IS_ACCEPTOR) != acceptor_flag) {
                CERROR("bad direction flag\n");
                return GSS_S_BAD_SIG;
        }
        if ((khdr->kh_flags & FLAG_WRAP_CONFIDENTIAL) == 0) {
                CERROR("missing confidential flag\n");
                return GSS_S_BAD_SIG;
        }
        if (khdr->kh_filler != 0xff) {
                CERROR("bad filler\n");
                return GSS_S_DEFECTIVE_TOKEN;
        }
        if (be16_to_cpu(khdr->kh_ec) != 0x0 ||
            be16_to_cpu(khdr->kh_rrc) != 0x0) {
                CERROR("bad EC or RRC\n");
                return GSS_S_DEFECTIVE_TOKEN;
        }

        /* block size */
        if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
                LASSERT(kctx->kc_keye.kb_tfm == NULL);
                blocksize = 1;
        } else {
                LASSERT(kctx->kc_keye.kb_tfm);
                blocksize = ll_crypto_blkcipher_blocksize(kctx->kc_keye.kb_tfm);
        }

        /* expected token layout:
         * ----------------------------------------
         * | krb5 header | cipher text | checksum |
         * ----------------------------------------
         */
        bodysize = token->len - sizeof(*khdr) - ke->ke_hash_size;

        if (bodysize % blocksize) {
                CERROR("odd bodysize %d\n", bodysize);
                return GSS_S_DEFECTIVE_TOKEN;
        }

        if (bodysize <= ke->ke_conf_size + sizeof(*khdr)) {
                CERROR("incomplete token: bodysize %d\n", bodysize);
                return GSS_S_DEFECTIVE_TOKEN;
        }

        if (msg->len < bodysize - ke->ke_conf_size - sizeof(*khdr)) {
                CERROR("buffer too small: %u, require %d\n",
                       msg->len, bodysize - ke->ke_conf_size);
                return GSS_S_FAILURE;
        }

        /* decrypting */
        OBD_ALLOC(tmpbuf, bodysize);
        if (!tmpbuf)
                return GSS_S_FAILURE;

        cipher_in.data = (__u8 *) (khdr + 1);
        cipher_in.len = bodysize;
        plain_out.data = tmpbuf;
        plain_out.len = bodysize;

        if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
                rawobj_t                 arc4_keye;
                struct ll_crypto_cipher *arc4_tfm;

                cksum.data = token->data + token->len - ke->ke_hash_size;
                cksum.len = ke->ke_hash_size;

                if (krb5_make_checksum(ENCTYPE_ARCFOUR_HMAC, &kctx->kc_keyi,
                                       NULL, 1, &cksum, &arc4_keye)) {
                        CERROR("failed to obtain arc4 enc key\n");
                        GOTO(arc4_out, enc_rc = -EACCES);
                }

                arc4_tfm = ll_crypto_alloc_blkcipher("ecb(arc4)", 0, 0);
                if (arc4_tfm == NULL) {
                        CERROR("failed to alloc tfm arc4 in ECB mode\n");
                        GOTO(arc4_out_key, enc_rc = -EACCES);
                }

                if (ll_crypto_blkcipher_setkey(arc4_tfm,
                                         arc4_keye.data, arc4_keye.len)) {
                        CERROR("failed to set arc4 key, len %d\n",
                               arc4_keye.len);
                        GOTO(arc4_out_tfm, enc_rc = -EACCES);
                }

                enc_rc = krb5_encrypt_rawobjs(arc4_tfm, 1,
                                              1, &cipher_in, &plain_out, 0);
arc4_out_tfm:
                ll_crypto_free_blkcipher(arc4_tfm);
arc4_out_key:
                rawobj_free(&arc4_keye);
arc4_out:
                cksum = RAWOBJ_EMPTY;
        } else {
                enc_rc = krb5_encrypt_rawobjs(kctx->kc_keye.kb_tfm, 0,
                                              1, &cipher_in, &plain_out, 0);
        }

        if (enc_rc != 0) {
                CERROR("error decrypt\n");
                goto out_free;
        }
        LASSERT(plain_out.len == bodysize);

        /* expected clear text layout:
         * -----------------------------------------
         * | confounder | clear msgs | krb5 header |
         * -----------------------------------------
         */

        /* verify krb5 header in token is not modified */
        if (memcmp(khdr, plain_out.data + plain_out.len - sizeof(*khdr),
                   sizeof(*khdr))) {
                CERROR("decrypted krb5 header mismatch\n");
                goto out_free;
        }

        /* verify checksum, compose clear text as layout:
         * ------------------------------------------------------
         * | confounder | gss header | clear msgs | krb5 header |
         * ------------------------------------------------------
         */
        hash_objs[0].len = ke->ke_conf_size;
        hash_objs[0].data = plain_out.data;
        hash_objs[1].len = gsshdr->len;
        hash_objs[1].data = gsshdr->data;
        hash_objs[2].len = plain_out.len - ke->ke_conf_size;
        hash_objs[2].data = plain_out.data + ke->ke_conf_size;
        if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyi,
                               khdr, 3, hash_objs, &cksum))
                goto out_free;

        LASSERT(cksum.len >= ke->ke_hash_size);
        if (memcmp((char *)(khdr + 1) + bodysize,
                   cksum.data + cksum.len - ke->ke_hash_size,
                   ke->ke_hash_size)) {
                CERROR("cksum mismatch\n");
                goto out_free;
        }

        msg->len =  bodysize - ke->ke_conf_size - sizeof(*khdr);
        memcpy(msg->data, tmpbuf + ke->ke_conf_size, msg->len);

        rc = GSS_S_COMPLETE;
out_free:
        OBD_FREE(tmpbuf, bodysize);
        rawobj_free(&cksum);
        return rc;
}

static
__u32 gss_plain_encrypt_kerberos(struct gss_ctx  *ctx,
                                 int              decrypt,
                                 int              length,
                                 void            *in_buf,
                                 void            *out_buf)
{
        struct krb5_ctx        *kctx = ctx->internal_ctx_id;
        __u32                   rc;

        rc = krb5_encrypt(kctx->kc_keye.kb_tfm, decrypt,
                          NULL, in_buf, out_buf, length);
        if (rc)
                CERROR("plain encrypt error: %d\n", rc);

        return rc;
}

int gss_display_kerberos(struct gss_ctx        *ctx,
                         char                  *buf,
                         int                    bufsize)
{
        struct krb5_ctx    *kctx = ctx->internal_ctx_id;
        int                 written;

        written = snprintf(buf, bufsize, "krb5 (%s)",
                           enctype2str(kctx->kc_enctype));
        return written;
}

static struct gss_api_ops gss_kerberos_ops = {
        .gss_import_sec_context     = gss_import_sec_context_kerberos,
        .gss_copy_reverse_context   = gss_copy_reverse_context_kerberos,
        .gss_inquire_context        = gss_inquire_context_kerberos,
        .gss_get_mic                = gss_get_mic_kerberos,
        .gss_verify_mic             = gss_verify_mic_kerberos,
        .gss_wrap                   = gss_wrap_kerberos,
        .gss_unwrap                 = gss_unwrap_kerberos,
        .gss_plain_encrypt          = gss_plain_encrypt_kerberos,
        .gss_delete_sec_context     = gss_delete_sec_context_kerberos,
        .gss_display                = gss_display_kerberos,
};

static struct subflavor_desc gss_kerberos_sfs[] = {
        {
                .sf_subflavor   = SPTLRPC_SUBFLVR_KRB5N,
                .sf_qop         = 0,
                .sf_service     = SPTLRPC_SVC_NULL,
                .sf_name        = "krb5n"
        },
        {
                .sf_subflavor   = SPTLRPC_SUBFLVR_KRB5A,
                .sf_qop         = 0,
                .sf_service     = SPTLRPC_SVC_AUTH,
                .sf_name        = "krb5a"
        },
        {
                .sf_subflavor   = SPTLRPC_SUBFLVR_KRB5I,
                .sf_qop         = 0,
                .sf_service     = SPTLRPC_SVC_INTG,
                .sf_name        = "krb5i"
        },
        {
                .sf_subflavor   = SPTLRPC_SUBFLVR_KRB5P,
                .sf_qop         = 0,
                .sf_service     = SPTLRPC_SVC_PRIV,
                .sf_name        = "krb5p"
        },
};

/*
 * currently we leave module owner NULL
 */
static struct gss_api_mech gss_kerberos_mech = {
        .gm_owner       = NULL, /*THIS_MODULE, */
        .gm_name        = "krb5",
        .gm_oid         = (rawobj_t)
                                {9, "\052\206\110\206\367\022\001\002\002"},
        .gm_ops         = &gss_kerberos_ops,
        .gm_sf_num      = 4,
        .gm_sfs         = gss_kerberos_sfs,
};

int __init init_kerberos_module(void)
{
        int status;

        status = lgss_mech_register(&gss_kerberos_mech);
        if (status)
                CERROR("Failed to register kerberos gss mechanism!\n");
        return status;
}

void __exit cleanup_kerberos_module(void)
{
        lgss_mech_unregister(&gss_kerberos_mech);
}
