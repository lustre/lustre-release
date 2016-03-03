/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (C) 2013, 2015, Trustees of Indiana University
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 * Author: Jeremy Filizetti <jfilizet@iu.edu>
 * Author: Andrew Korty <ajk@iu.edu>
 */

#define DEBUG_SUBSYSTEM S_SEC
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/mutex.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre/lustre_user.h>

#include "gss_err.h"
#include "gss_crypto.h"
#include "gss_internal.h"
#include "gss_api.h"
#include "gss_asn1.h"

#define SK_INTERFACE_VERSION 1
#define SK_MIN_SIZE 8

struct sk_ctx {
	__u32			sc_version;
	__u16			sc_hmac;
	__u16			sc_crypt;
	__u32			sc_expire;
	rawobj_t		sc_shared_key;
	rawobj_t		sc_iv;
	struct gss_keyblock	sc_session_kb;
};

static struct sk_crypt_type sk_crypt_types[] = {
	[SK_CRYPT_AES256_CTR] = {
		.sct_name = "ctr(aes256)",
		.sct_bytes = 32,
	},
};

static struct sk_hmac_type sk_hmac_types[] = {
	[SK_HMAC_SHA256] = {
		.sht_name = "hmac(sha256)",
		.sht_bytes = 32,
	},
	[SK_HMAC_SHA512] = {
		.sht_name = "hmac(sha512)",
		.sht_bytes = 64,
	},
};

static inline unsigned long sk_block_mask(unsigned long len, int blocksize)
{
	return (len + blocksize - 1) & (~(blocksize - 1));
}

static int sk_init_keys(struct sk_ctx *skc)
{
	int rc;
	unsigned int ivsize;

	rc = gss_keyblock_init(&skc->sc_session_kb,
			       sk_crypt_types[skc->sc_crypt].sct_name, 0);
	if (rc)
		return rc;

	ivsize = crypto_blkcipher_ivsize(skc->sc_session_kb.kb_tfm);
	if (skc->sc_iv.len != ivsize) {
		CERROR("IV size for algorithm (%d) does not match provided IV "
		       "size: %d\n", ivsize, skc->sc_iv.len);
		return -EINVAL;
	}

	crypto_blkcipher_set_iv(skc->sc_session_kb.kb_tfm,
				       skc->sc_iv.data, skc->sc_iv.len);

	return 0;
}

static int fill_sk_context(rawobj_t *inbuf, struct sk_ctx *skc)
{
	char *ptr = inbuf->data;
	char *end = inbuf->data + inbuf->len;
	__u32 tmp;

	/* see sk_serialize_kctx() for format from userspace side */
	/*  1. Version */
	if (gss_get_bytes(&ptr, end, &tmp, sizeof(tmp))) {
		CERROR("Failed to read shared key interface version");
		return -1;
	}
	if (tmp != SK_INTERFACE_VERSION) {
		CERROR("Invalid shared key interface version: %d\n", tmp);
		return -1;
	}

	/* 2. HMAC type */
	if (gss_get_bytes(&ptr, end, &skc->sc_hmac, sizeof(skc->sc_hmac))) {
		CERROR("Failed to read HMAC algorithm type");
		return -1;
	}
	if (skc->sc_hmac >= SK_HMAC_MAX) {
		CERROR("Invalid hmac type: %d\n", skc->sc_hmac);
		return -1;
	}

	/* 3. crypt type */
	if (gss_get_bytes(&ptr, end, &skc->sc_crypt, sizeof(skc->sc_crypt))) {
		CERROR("Failed to read crypt algorithm type");
		return -1;
	}
	if (skc->sc_crypt >= SK_CRYPT_MAX) {
		CERROR("Invalid crypt type: %d\n", skc->sc_crypt);
		return -1;
	}

	/* 4. expiration time */
	if (gss_get_bytes(&ptr, end, &tmp, sizeof(tmp))) {
		CERROR("Failed to read context expiration time");
		return -1;
	}
	skc->sc_expire = tmp + cfs_time_current_sec();

	/* 5. Shared key */
	if (gss_get_rawobj(&ptr, end, &skc->sc_shared_key)) {
		CERROR("Failed to read shared key");
		return -1;
	}
	if (skc->sc_shared_key.len <= SK_MIN_SIZE) {
		CERROR("Shared key must key must be larger than %d bytes\n",
		       SK_MIN_SIZE);
		return -1;
	}

	/* 6. IV, can be empty if not using privacy mode */
	if (gss_get_rawobj(&ptr, end, &skc->sc_iv)) {
		CERROR("Failed to read initialization vector ");
		return -1;
	}

	/* 7. Session key, can be empty if not using privacy mode */
	if (gss_get_rawobj(&ptr, end, &skc->sc_session_kb.kb_key)) {
		CERROR("Failed to read session key");
		return -1;
	}

	return 0;
}

static void delete_sk_context(struct sk_ctx *skc)
{
	if (!skc)
		return;
	gss_keyblock_free(&skc->sc_session_kb);
	rawobj_free(&skc->sc_iv);
	rawobj_free(&skc->sc_shared_key);
}

static
__u32 gss_import_sec_context_sk(rawobj_t *inbuf, struct gss_ctx *gss_context)
{
	struct sk_ctx *skc;
	bool privacy = false;

	if (inbuf == NULL || inbuf->data == NULL)
		return GSS_S_FAILURE;

	OBD_ALLOC_PTR(skc);
	if (!skc)
		return GSS_S_FAILURE;

	if (fill_sk_context(inbuf, skc))
		goto out_error;

	/* Only privacy mode needs to initialize keys */
	if (skc->sc_session_kb.kb_key.len > 0) {
		privacy = true;
		if (sk_init_keys(skc))
			goto out_error;
	}

	gss_context->internal_ctx_id = skc;
	CDEBUG(D_SEC, "successfully imported sk%s context\n",
	       privacy ? "pi" : "i");

	return GSS_S_COMPLETE;

out_error:
	delete_sk_context(skc);
	OBD_FREE_PTR(skc);
	return GSS_S_FAILURE;
}

static
__u32 gss_copy_reverse_context_sk(struct gss_ctx *gss_context_old,
				  struct gss_ctx *gss_context_new)
{
	struct sk_ctx *skc_old = gss_context_old->internal_ctx_id;
	struct sk_ctx *skc_new;

	OBD_ALLOC_PTR(skc_new);
	if (!skc_new)
		return GSS_S_FAILURE;

	skc_new->sc_crypt = skc_old->sc_crypt;
	skc_new->sc_hmac = skc_old->sc_hmac;
	skc_new->sc_expire = skc_old->sc_expire;
	if (rawobj_dup(&skc_new->sc_shared_key, &skc_old->sc_shared_key))
		goto out_error;
	if (rawobj_dup(&skc_new->sc_iv, &skc_old->sc_iv))
		goto out_error;
	if (gss_keyblock_dup(&skc_new->sc_session_kb, &skc_old->sc_session_kb))
		goto out_error;

	/* Only privacy mode needs to initialize keys */
	if (skc_new->sc_session_kb.kb_key.len > 0)
		if (sk_init_keys(skc_new))
			goto out_error;

	gss_context_new->internal_ctx_id = skc_new;
	CDEBUG(D_SEC, "successfully copied reverse sk context\n");

	return GSS_S_COMPLETE;

out_error:
	delete_sk_context(skc_new);
	OBD_FREE_PTR(skc_new);
	return GSS_S_FAILURE;
}

static
__u32 gss_inquire_context_sk(struct gss_ctx *gss_context,
			     unsigned long *endtime)
{
	struct sk_ctx *skc = gss_context->internal_ctx_id;

	*endtime = skc->sc_expire;
	return GSS_S_COMPLETE;
}

static
__u32 sk_make_checksum(char *alg_name, rawobj_t *key,
		       int msg_count, rawobj_t *msgs,
		       int iov_count, lnet_kiov_t *iovs,
		       rawobj_t *token)
{
	struct crypto_hash *tfm;
	int rc;

	tfm = crypto_alloc_hash(alg_name, 0, 0);
	if (!tfm)
		return GSS_S_FAILURE;

	rc = GSS_S_FAILURE;
	LASSERT(token->len >= crypto_hash_digestsize(tfm));
	if (!gss_digest_hmac(tfm, key, NULL, msg_count, msgs, iov_count, iovs,
			    token))
		rc = GSS_S_COMPLETE;

	crypto_free_hash(tfm);
	return rc;
}

static
__u32 gss_get_mic_sk(struct gss_ctx *gss_context,
		     int message_count,
		     rawobj_t *messages,
		     int iov_count,
		     lnet_kiov_t *iovs,
		     rawobj_t *token)
{
	struct sk_ctx *skc = gss_context->internal_ctx_id;
	return sk_make_checksum(sk_hmac_types[skc->sc_hmac].sht_name,
				&skc->sc_shared_key, message_count, messages,
				iov_count, iovs, token);
}

static
__u32 sk_verify_checksum(struct sk_hmac_type *sht,
			 rawobj_t *key,
			 int message_count,
			 rawobj_t *messages,
			 int iov_count,
			 lnet_kiov_t *iovs,
			 rawobj_t *token)
{
	rawobj_t checksum = RAWOBJ_EMPTY;
	__u32 rc = GSS_S_FAILURE;

	checksum.len = sht->sht_bytes;
	if (token->len < checksum.len) {
		CDEBUG(D_SEC, "Token received too short, expected %d "
		       "received %d\n", token->len, checksum.len);
		return GSS_S_DEFECTIVE_TOKEN;
	}

	OBD_ALLOC_LARGE(checksum.data, checksum.len);
	if (!checksum.data)
		return rc;

	if (sk_make_checksum(sht->sht_name, key, message_count,
			     messages, iov_count, iovs, &checksum)) {
		CDEBUG(D_SEC, "Failed to create checksum to validate\n");
		goto cleanup;
	}

	if (memcmp(token->data, checksum.data, checksum.len)) {
		CERROR("checksum mismatch\n");
		rc = GSS_S_BAD_SIG;
		goto cleanup;
	}

	rc = GSS_S_COMPLETE;

cleanup:
	OBD_FREE(checksum.data, checksum.len);
	return rc;
}

static
__u32 gss_verify_mic_sk(struct gss_ctx *gss_context,
			int message_count,
			rawobj_t *messages,
			int iov_count,
			lnet_kiov_t *iovs,
			rawobj_t *token)
{
	struct sk_ctx *skc = gss_context->internal_ctx_id;
	return sk_verify_checksum(&sk_hmac_types[skc->sc_hmac],
				  &skc->sc_shared_key, message_count, messages,
				  iov_count, iovs, token);
}

static
__u32 gss_wrap_sk(struct gss_ctx *gss_context, rawobj_t *gss_header,
		    rawobj_t *message, int message_buffer_length,
		    rawobj_t *token)
{
	struct sk_ctx *skc = gss_context->internal_ctx_id;
	struct sk_hmac_type *sht = &sk_hmac_types[skc->sc_hmac];
	rawobj_t msgbufs[2];
	rawobj_t cipher;
	rawobj_t checksum;
	unsigned int blocksize;

	LASSERT(skc->sc_session_kb.kb_tfm);
	blocksize = crypto_blkcipher_blocksize(skc->sc_session_kb.kb_tfm);

	if (gss_add_padding(message, message_buffer_length, blocksize))
		return GSS_S_FAILURE;

	/* Only encrypting the message data */
	cipher.data = token->data;
	cipher.len = token->len - sht->sht_bytes;
	if (gss_crypt_rawobjs(skc->sc_session_kb.kb_tfm, 0, 1, message,
			      &cipher, 1))
		return GSS_S_FAILURE;

	/* Checksum covers the GSS header followed by the encrypted message */
	msgbufs[0].len = gss_header->len;
	msgbufs[0].data = gss_header->data;
	msgbufs[1].len = cipher.len;
	msgbufs[1].data = cipher.data;

	LASSERT(cipher.len + sht->sht_bytes <= token->len);
	checksum.data = token->data + cipher.len;
	checksum.len = sht->sht_bytes;
	if (sk_make_checksum(sht->sht_name, &skc->sc_shared_key, 2, msgbufs, 0,
			     NULL, &checksum))
		return GSS_S_FAILURE;

	token->len = cipher.len + checksum.len;

	return GSS_S_COMPLETE;
}

static
__u32 gss_unwrap_sk(struct gss_ctx *gss_context, rawobj_t *gss_header,
		      rawobj_t *token, rawobj_t *message)
{
	struct sk_ctx *skc = gss_context->internal_ctx_id;
	struct sk_hmac_type *sht = &sk_hmac_types[skc->sc_hmac];
	rawobj_t msgbufs[2];
	rawobj_t cipher;
	rawobj_t checksum;
	unsigned int blocksize;
	int rc;

	LASSERT(skc->sc_session_kb.kb_tfm);
	blocksize = crypto_blkcipher_blocksize(skc->sc_session_kb.kb_tfm);

	if (token->len < sht->sht_bytes)
		return GSS_S_DEFECTIVE_TOKEN;

	cipher.data = token->data;
	cipher.len = token->len - sht->sht_bytes;
	checksum.data = token->data + cipher.len;
	checksum.len = sht->sht_bytes;

	if (cipher.len % blocksize != 0)
		return GSS_S_DEFECTIVE_TOKEN;

	/* Checksum covers the GSS header followed by the encrypted message */
	msgbufs[0].len = gss_header->len;
	msgbufs[0].data = gss_header->data;
	msgbufs[1].len = cipher.len;
	msgbufs[1].data = cipher.data;
	rc = sk_verify_checksum(sht, &skc->sc_shared_key, 2, msgbufs, 0, NULL,
			       &checksum);
	if (rc)
		return rc;

	message->len = cipher.len;
	if (gss_crypt_rawobjs(skc->sc_session_kb.kb_tfm, 0, 1, &cipher,
			      message, 0))
		return GSS_S_FAILURE;

	return GSS_S_COMPLETE;
}

static
__u32 gss_prep_bulk_sk(struct gss_ctx *gss_context,
		       struct ptlrpc_bulk_desc *desc)
{
	struct sk_ctx *skc = gss_context->internal_ctx_id;
	int blocksize;
	int i;

	LASSERT(skc->sc_session_kb.kb_tfm);
	blocksize = crypto_blkcipher_blocksize(skc->sc_session_kb.kb_tfm);

	for (i = 0; i < desc->bd_iov_count; i++) {
		if (BD_GET_KIOV(desc, i).kiov_offset & blocksize) {
			CERROR("offset %d not blocksize aligned\n",
			       BD_GET_KIOV(desc, i).kiov_offset);
			return GSS_S_FAILURE;
		}

		BD_GET_ENC_KIOV(desc, i).kiov_offset =
			BD_GET_KIOV(desc, i).kiov_offset;
		BD_GET_ENC_KIOV(desc, i).kiov_len =
			sk_block_mask(BD_GET_KIOV(desc, i).kiov_len, blocksize);
	}

	return GSS_S_COMPLETE;
}

static __u32 sk_encrypt_bulk(struct crypto_blkcipher *tfm,
			     struct ptlrpc_bulk_desc *desc,
			     rawobj_t *cipher,
			     int adj_nob)
{
	struct blkcipher_desc cdesc = {
		.tfm = tfm,
		.info = NULL,
		.flags = 0,
	};
	struct scatterlist ptxt;
	struct scatterlist ctxt;
	int blocksize;
	int i;
	int rc;
	int nob = 0;

	blocksize = crypto_blkcipher_blocksize(tfm);

	sg_init_table(&ptxt, 1);
	sg_init_table(&ctxt, 1);

	for (i = 0; i < desc->bd_iov_count; i++) {
		sg_set_page(&ptxt, BD_GET_KIOV(desc, i).kiov_page,
			    sk_block_mask(BD_GET_KIOV(desc, i).kiov_len,
					  blocksize),
			    BD_GET_KIOV(desc, i).kiov_offset);
		if (adj_nob)
			nob += ptxt.length;

		sg_set_page(&ctxt, BD_GET_ENC_KIOV(desc, i).kiov_page,
			    ptxt.length, ptxt.offset);

		BD_GET_ENC_KIOV(desc, i).kiov_offset = ctxt.offset;
		BD_GET_ENC_KIOV(desc, i).kiov_len = ctxt.length;

		rc = crypto_blkcipher_encrypt(&cdesc, &ctxt, &ptxt,
					      ptxt.length);
		if (rc) {
			CERROR("failed to encrypt page: %d\n", rc);
			return rc;
		}
	}

	if (adj_nob)
		desc->bd_nob = nob;

	return 0;
}

static __u32 sk_decrypt_bulk(struct crypto_blkcipher *tfm,
			     struct ptlrpc_bulk_desc *desc,
			     rawobj_t *cipher,
			     int adj_nob)
{
	struct blkcipher_desc cdesc = {
		.tfm = tfm,
		.info = NULL,
		.flags = 0,
	};
	struct scatterlist ptxt;
	struct scatterlist ctxt;
	int blocksize;
	int i;
	int rc;
	int pnob = 0;
	int cnob = 0;

	sg_init_table(&ptxt, 1);
	sg_init_table(&ctxt, 1);

	blocksize = crypto_blkcipher_blocksize(tfm);
	if (desc->bd_nob_transferred % blocksize != 0) {
		CERROR("Transfer not a multiple of block size: %d\n",
		       desc->bd_nob_transferred);
		return GSS_S_DEFECTIVE_TOKEN;
	}

	for (i = 0; i < desc->bd_iov_count; i++) {
		lnet_kiov_t *piov = &BD_GET_KIOV(desc, i);
		lnet_kiov_t *ciov = &BD_GET_ENC_KIOV(desc, i);

		if (piov->kiov_offset % blocksize != 0 ||
		    piov->kiov_len % blocksize != 0) {
			CERROR("Invalid bulk descriptor vector\n");
			return GSS_S_DEFECTIVE_TOKEN;
		}

		/* Must adjust bytes here because we know the actual sizes after
		 * decryption.  Similar to what gss_cli_ctx_unwrap_bulk does for
		 * integrity only mode */
		if (adj_nob) {
			/* cipher text must not exceed transferred size */
			if (ciov->kiov_len + cnob > desc->bd_nob_transferred)
				ciov->kiov_len =
					desc->bd_nob_transferred - cnob;

			piov->kiov_len = ciov->kiov_len;

			/* plain text must not exceed bulk's size */
			if (ciov->kiov_len + pnob > desc->bd_nob)
				piov->kiov_len = desc->bd_nob - pnob;
		} else {
			/* Taken from krb5_decrypt since it was not verified
			 * whether or not LNET guarantees these */
			if (ciov->kiov_len + cnob > desc->bd_nob_transferred ||
			    piov->kiov_len > ciov->kiov_len) {
				CERROR("Invalid decrypted length\n");
				return GSS_S_FAILURE;
			}
		}

		if (ciov->kiov_len == 0)
			continue;

		sg_init_table(&ctxt, 1);
		sg_set_page(&ctxt, ciov->kiov_page, ciov->kiov_len,
			    ciov->kiov_offset);
		ptxt = ctxt;

		/* In the event the plain text size is not a multiple
		 * of blocksize we decrypt in place and copy the result
		 * after the decryption */
		if (piov->kiov_len % blocksize == 0)
			sg_assign_page(&ptxt, piov->kiov_page);

		rc = crypto_blkcipher_decrypt(&cdesc, &ptxt, &ctxt,
					      ctxt.length);
		if (rc) {
			CERROR("Decryption failed for page: %d\n", rc);
			return GSS_S_FAILURE;
		}

		if (piov->kiov_len % blocksize != 0) {
			memcpy(page_address(piov->kiov_page) +
			       piov->kiov_offset,
			       page_address(ciov->kiov_page) +
			       ciov->kiov_offset,
			       piov->kiov_len);
		}

		cnob += ciov->kiov_len;
		pnob += piov->kiov_len;
	}

	/* if needed, clear up the rest unused iovs */
	if (adj_nob)
		while (i < desc->bd_iov_count)
			BD_GET_KIOV(desc, i++).kiov_len = 0;

	if (unlikely(cnob != desc->bd_nob_transferred)) {
		CERROR("%d cipher text transferred but only %d decrypted\n",
		       desc->bd_nob_transferred, cnob);
		return GSS_S_FAILURE;
	}

	if (unlikely(!adj_nob && pnob != desc->bd_nob)) {
		CERROR("%d plain text expected but only %d received\n",
		       desc->bd_nob, pnob);
		return GSS_S_FAILURE;
	}

	return 0;
}

static
__u32 gss_wrap_bulk_sk(struct gss_ctx *gss_context,
			 struct ptlrpc_bulk_desc *desc, rawobj_t *token,
			 int adj_nob)
{
	struct sk_ctx *skc = gss_context->internal_ctx_id;
	struct sk_hmac_type *sht = &sk_hmac_types[skc->sc_hmac];
	rawobj_t cipher = RAWOBJ_EMPTY;
	rawobj_t checksum = RAWOBJ_EMPTY;

	cipher.data = token->data;
	cipher.len = token->len - sht->sht_bytes;

	if (sk_encrypt_bulk(skc->sc_session_kb.kb_tfm, desc, &cipher, adj_nob))
		return GSS_S_FAILURE;

	checksum.data = token->data + cipher.len;
	checksum.len = sht->sht_bytes;

	if (sk_make_checksum(sht->sht_name, &skc->sc_shared_key, 1, &cipher, 0,
			     NULL, &checksum))
		return GSS_S_FAILURE;

	return GSS_S_COMPLETE;
}

static
__u32 gss_unwrap_bulk_sk(struct gss_ctx *gss_context,
			   struct ptlrpc_bulk_desc *desc,
			   rawobj_t *token, int adj_nob)
{
	struct sk_ctx *skc = gss_context->internal_ctx_id;
	struct sk_hmac_type *sht = &sk_hmac_types[skc->sc_hmac];
	rawobj_t cipher = RAWOBJ_EMPTY;
	rawobj_t checksum = RAWOBJ_EMPTY;
	int rc;

	cipher.data = token->data;
	cipher.len = token->len - sht->sht_bytes;
	checksum.data = token->data + cipher.len;
	checksum.len = sht->sht_bytes;

	rc = sk_verify_checksum(&sk_hmac_types[skc->sc_hmac],
				&skc->sc_shared_key, 1, &cipher, 0, NULL,
				&checksum);
	if (rc)
		return rc;

	rc = sk_decrypt_bulk(skc->sc_session_kb.kb_tfm, desc, &cipher, adj_nob);
	if (rc)
		return rc;

	return GSS_S_COMPLETE;
}

static
void gss_delete_sec_context_sk(void *internal_context)
{
	struct sk_ctx *sk_context = internal_context;
	delete_sk_context(sk_context);
	OBD_FREE_PTR(sk_context);
}

int gss_display_sk(struct gss_ctx *gss_context, char *buf, int bufsize)
{
	return snprintf(buf, bufsize, "sk");
}

static struct gss_api_ops gss_sk_ops = {
	.gss_import_sec_context     = gss_import_sec_context_sk,
	.gss_copy_reverse_context   = gss_copy_reverse_context_sk,
	.gss_inquire_context        = gss_inquire_context_sk,
	.gss_get_mic                = gss_get_mic_sk,
	.gss_verify_mic             = gss_verify_mic_sk,
	.gss_wrap                   = gss_wrap_sk,
	.gss_unwrap                 = gss_unwrap_sk,
	.gss_prep_bulk              = gss_prep_bulk_sk,
	.gss_wrap_bulk              = gss_wrap_bulk_sk,
	.gss_unwrap_bulk            = gss_unwrap_bulk_sk,
	.gss_delete_sec_context     = gss_delete_sec_context_sk,
	.gss_display                = gss_display_sk,
};

static struct subflavor_desc gss_sk_sfs[] = {
	{
		.sf_subflavor   = SPTLRPC_SUBFLVR_SKN,
		.sf_qop         = 0,
		.sf_service     = SPTLRPC_SVC_NULL,
		.sf_name        = "skn"
	},
	{
		.sf_subflavor   = SPTLRPC_SUBFLVR_SKA,
		.sf_qop         = 0,
		.sf_service     = SPTLRPC_SVC_AUTH,
		.sf_name        = "ska"
	},
	{
		.sf_subflavor   = SPTLRPC_SUBFLVR_SKI,
		.sf_qop         = 0,
		.sf_service     = SPTLRPC_SVC_INTG,
		.sf_name        = "ski"
	},
	{
		.sf_subflavor   = SPTLRPC_SUBFLVR_SKPI,
		.sf_qop         = 0,
		.sf_service     = SPTLRPC_SVC_PRIV,
		.sf_name        = "skpi"
	},
};

/*
 * currently we leave module owner NULL
 */
static struct gss_api_mech gss_sk_mech = {
	.gm_owner       = NULL, /*THIS_MODULE, */
	.gm_name        = "sk",
	.gm_oid         = (rawobj_t) {
		12,
		"\053\006\001\004\001\311\146\215\126\001\000\001",
	},
	.gm_ops         = &gss_sk_ops,
	.gm_sf_num      = 4,
	.gm_sfs         = gss_sk_sfs,
};

int __init init_sk_module(void)
{
	int status;

	status = lgss_mech_register(&gss_sk_mech);
	if (status)
		CERROR("Failed to register sk gss mechanism!\n");

	return status;
}

void cleanup_sk_module(void)
{
	lgss_mech_unregister(&gss_sk_mech);
}
