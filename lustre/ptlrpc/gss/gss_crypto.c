/*
 * Modifications for Lustre
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
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

#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/linux/linux-crypto.h>
#include <obd.h>
#include <obd_support.h>

#include "gss_internal.h"
#include "gss_crypto.h"

int gss_keyblock_init(struct gss_keyblock *kb, const char *alg_name,
		      const int alg_mode)
{
	int rc;

	kb->kb_tfm = crypto_alloc_sync_skcipher(alg_name, alg_mode, 0);
	if (IS_ERR(kb->kb_tfm)) {
		rc = PTR_ERR(kb->kb_tfm);
		kb->kb_tfm = NULL;
		CERROR("failed to alloc tfm: %s, mode %d: rc = %d\n", alg_name,
		       alg_mode, rc);
		return rc;
	}

	rc = crypto_sync_skcipher_setkey(kb->kb_tfm, kb->kb_key.data,
					 kb->kb_key.len);
	if (rc) {
		CERROR("failed to set %s key, len %d, rc = %d\n", alg_name,
		       kb->kb_key.len, rc);
		return rc;
	}

	return 0;
}

void gss_keyblock_free(struct gss_keyblock *kb)
{
	rawobj_free(&kb->kb_key);
	if (kb->kb_tfm)
		crypto_free_sync_skcipher(kb->kb_tfm);
}

int gss_keyblock_dup(struct gss_keyblock *new, struct gss_keyblock *kb)
{
	return rawobj_dup(&new->kb_key, &kb->kb_key);
}

int gss_get_bytes(char **ptr, const char *end, void *res, size_t len)
{
	char *p, *q;
	p = *ptr;
	q = p + len;
	if (q > end || q < p)
		return -EINVAL;
	memcpy(res, p, len);
	*ptr = q;
	return 0;
}

int gss_get_rawobj(char **ptr, const char *end, rawobj_t *res)
{
	char   *p, *q;
	__u32   len;

	p = *ptr;
	if (gss_get_bytes(&p, end, &len, sizeof(len)))
		return -EINVAL;

	q = p + len;
	if (q > end || q < p)
		return -EINVAL;

	/* Support empty objects */
	if (len != 0) {
		OBD_ALLOC_LARGE(res->data, len);
		if (!res->data)
			return -ENOMEM;
	} else {
		res->len = len;
		res->data = NULL;
		return 0;
	}

	res->len = len;
	memcpy(res->data, p, len);
	*ptr = q;
	return 0;
}

int gss_get_keyblock(char **ptr, const char *end,
		     struct gss_keyblock *kb, __u32 keysize)
{
	char *buf;
	int rc;

	OBD_ALLOC_LARGE(buf, keysize);
	if (buf == NULL)
		return -ENOMEM;

	rc = gss_get_bytes(ptr, end, buf, keysize);
	if (rc) {
		OBD_FREE_LARGE(buf, keysize);
		return rc;
	}

	kb->kb_key.len = keysize;
	kb->kb_key.data = buf;
	return 0;
}

/*
 * Should be used for buffers allocated with k/vmalloc().
 *
 * Dispose of @sgt with gss_teardown_sgtable().
 *
 * @prealloc_sg is to avoid memory allocation inside sg_alloc_table()
 * in cases where a single sg is sufficient.  No attempt to reduce the
 * number of sgs by squeezing physically contiguous pages together is
 * made though, for simplicity.
 *
 * This function is copied from the ceph filesystem code.
 */
int gss_setup_sgtable(struct sg_table *sgt, struct scatterlist *prealloc_sg,
		      const void *buf, unsigned int buf_len)
{
	struct scatterlist *sg;
	const bool is_vmalloc = is_vmalloc_addr(buf);
	unsigned int off = offset_in_page(buf);
	unsigned int chunk_cnt = 1;
	unsigned int chunk_len = PAGE_ALIGN(off + buf_len);
	int i;
	int rc;

	if (buf_len == 0) {
		memset(sgt, 0, sizeof(*sgt));
		return -EINVAL;
	}

	if (is_vmalloc) {
		chunk_cnt = chunk_len >> PAGE_SHIFT;
		chunk_len = PAGE_SIZE;
	}

	if (chunk_cnt > 1) {
		rc = sg_alloc_table(sgt, chunk_cnt, GFP_NOFS);
		if (rc)
			return rc;
	} else {
		WARN_ON_ONCE(chunk_cnt != 1);
		sg_init_table(prealloc_sg, 1);
		sgt->sgl = prealloc_sg;
		sgt->nents = sgt->orig_nents = 1;
	}

	for_each_sg(sgt->sgl, sg, sgt->orig_nents, i) {
		struct page *page;
		unsigned int len = min(chunk_len - off, buf_len);

		if (is_vmalloc)
			page = vmalloc_to_page(buf);
		else
			page = virt_to_page(buf);

		sg_set_page(sg, page, len, off);

		off = 0;
		buf += len;
		buf_len -= len;
	}

	WARN_ON_ONCE(buf_len != 0);

	return 0;
}

void gss_teardown_sgtable(struct sg_table *sgt)
{
	if (sgt->orig_nents > 1)
		sg_free_table(sgt);
}

int gss_crypt_generic(struct crypto_sync_skcipher *tfm, int decrypt,
		      const void *iv, const void *in, void *out, size_t length)
{
	struct scatterlist sg;
	struct sg_table sg_out;
	__u8 local_iv[16] = {0};
	__u32 ret = -EINVAL;
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);

	LASSERT(tfm);

	if (length % crypto_sync_skcipher_blocksize(tfm) != 0) {
		CERROR("output length %zu mismatch blocksize %d\n",
		       length, crypto_sync_skcipher_blocksize(tfm));
		goto out;
	}

	if (crypto_sync_skcipher_ivsize(tfm) > ARRAY_SIZE(local_iv)) {
		CERROR("iv size too large %d\n",
			crypto_sync_skcipher_ivsize(tfm));
		goto out;
	}

	if (iv)
		memcpy(local_iv, iv, crypto_sync_skcipher_ivsize(tfm));

	if (in != out)
		memmove(out, in, length);

	ret = gss_setup_sgtable(&sg_out, &sg, out, length);
	if (ret != 0)
		goto out;

	skcipher_request_set_sync_tfm(req, tfm);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, &sg, &sg, length, local_iv);

	if (decrypt)
		ret = crypto_skcipher_decrypt_iv(req, &sg, &sg, length);
	else
		ret = crypto_skcipher_encrypt_iv(req, &sg, &sg, length);

	skcipher_request_zero(req);
	gss_teardown_sgtable(&sg_out);
out:
	return ret;
}

int gss_digest_hash(struct ahash_request *req,
		    rawobj_t *hdr, int msgcnt, rawobj_t *msgs,
		    int iovcnt, lnet_kiov_t *iovs)
{
	struct scatterlist sg[1];
	struct sg_table sgt;
	int rc = 0;
	int i;

	for (i = 0; i < msgcnt; i++) {
		if (msgs[i].len == 0)
			continue;

		rc = gss_setup_sgtable(&sgt, sg, msgs[i].data, msgs[i].len);
		if (rc)
			return rc;

		ahash_request_set_crypt(req, sg, NULL, msgs[i].len);
		rc = crypto_ahash_update(req);
		gss_teardown_sgtable(&sgt);
		if (rc)
			return rc;
	}

	for (i = 0; i < iovcnt; i++) {
		if (iovs[i].kiov_len == 0)
			continue;

		sg_init_table(sg, 1);
		sg_set_page(&sg[0], iovs[i].kiov_page, iovs[i].kiov_len,
			    iovs[i].kiov_offset);

		ahash_request_set_crypt(req, sg, NULL, iovs[i].kiov_len);
		rc = crypto_ahash_update(req);
		if (rc)
			return rc;
	}

	if (hdr) {
		rc = gss_setup_sgtable(&sgt, sg, hdr->data, hdr->len);
		if (rc)
			return rc;

		ahash_request_set_crypt(req, sg, NULL, hdr->len);
		rc = crypto_ahash_update(req);
		gss_teardown_sgtable(&sgt);
		if (rc)
			return rc;
	}

	return rc;
}

int gss_digest_hash_compat(struct ahash_request *req,
			   rawobj_t *hdr, int msgcnt, rawobj_t *msgs,
			   int iovcnt, lnet_kiov_t *iovs)
{
	struct scatterlist sg[1];
	struct sg_table sgt;
	int rc = 0;
	int i;

	for (i = 0; i < msgcnt; i++) {
		if (msgs[i].len == 0)
			continue;

		rc = gss_setup_sgtable(&sgt, sg, msgs[i].data, msgs[i].len);
		if (rc)
			return rc;

		ahash_request_set_crypt(req, sg, NULL, msgs[i].len);
		rc = crypto_ahash_update(req);
		gss_teardown_sgtable(&sgt);
		if (rc)
			return rc;
	}

	for (i = 0; i < iovcnt; i++) {
		if (iovs[i].kiov_len == 0)
			continue;

		sg_init_table(sg, 1);
		sg_set_page(&sg[0], iovs[i].kiov_page, iovs[i].kiov_len,
			    iovs[i].kiov_offset);

		ahash_request_set_crypt(req, sg, NULL, iovs[i].kiov_len);
		rc = crypto_ahash_update(req);
		if (rc)
			return rc;
	}

	if (hdr) {
		rc = gss_setup_sgtable(&sgt, sg, &(hdr->len), sizeof(hdr->len));
		if (rc)
			return rc;

		ahash_request_set_crypt(req, sg, NULL, sizeof(hdr->len));
		rc = crypto_ahash_update(req);
		gss_teardown_sgtable(&sgt);
		if (rc)
			return rc;
	}

	return rc;
}

int gss_add_padding(rawobj_t *msg, int msg_buflen, int blocksize)
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

int gss_crypt_rawobjs(struct crypto_sync_skcipher *tfm, __u8 *iv,
		      int inobj_cnt, rawobj_t *inobjs, rawobj_t *outobj,
		      int enc)
{
	struct scatterlist src;
	struct scatterlist dst;
	struct sg_table sg_dst;
	struct sg_table sg_src;
	__u8 *buf;
	__u32 datalen = 0;
	int i, rc;
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);

	ENTRY;

	buf = outobj->data;
	skcipher_request_set_sync_tfm(req, tfm);
	skcipher_request_set_callback(req, 0, NULL, NULL);

	for (i = 0; i < inobj_cnt; i++) {
		LASSERT(buf + inobjs[i].len <= outobj->data + outobj->len);

		rc = gss_setup_sgtable(&sg_src, &src, inobjs[i].data,
				   inobjs[i].len);
		if (rc != 0)
			RETURN(rc);

		rc = gss_setup_sgtable(&sg_dst, &dst, buf,
				       outobj->len - datalen);
		if (rc != 0) {
			gss_teardown_sgtable(&sg_src);
			RETURN(rc);
		}

		skcipher_request_set_crypt(req, &src, &dst, src.length, iv);
		if (!iv)
			skcipher_request_set_crypt_iv(req);

		if (enc)
			rc = crypto_skcipher_encrypt_iv(req, &dst, &src,
							src.length);
		else
			rc = crypto_skcipher_decrypt_iv(req, &dst, &src,
							src.length);

		gss_teardown_sgtable(&sg_src);
		gss_teardown_sgtable(&sg_dst);

		if (rc) {
			CERROR("encrypt error %d\n", rc);
			skcipher_request_zero(req);
			RETURN(rc);
		}

		datalen += inobjs[i].len;
		buf += inobjs[i].len;
	}
	skcipher_request_zero(req);

	outobj->len = datalen;
	RETURN(0);
}
