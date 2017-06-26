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

int gss_keyblock_init(struct gss_keyblock *kb, char *alg_name,
		      const int alg_mode)
{
	int rc;

	kb->kb_tfm = crypto_alloc_blkcipher(alg_name, alg_mode, 0);
	if (IS_ERR(kb->kb_tfm)) {
		rc = PTR_ERR(kb->kb_tfm);
		kb->kb_tfm = NULL;
		CERROR("failed to alloc tfm: %s, mode %d: rc = %d\n", alg_name,
		       alg_mode, rc);
		return rc;
	}

	rc = crypto_blkcipher_setkey(kb->kb_tfm, kb->kb_key.data,
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
		crypto_free_blkcipher(kb->kb_tfm);
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

int gss_crypt_generic(struct crypto_blkcipher *tfm, int decrypt, const void *iv,
		      const void *in, void *out, size_t length)
{
	struct blkcipher_desc desc;
	struct scatterlist sg;
	struct sg_table sg_out;
	__u8 local_iv[16] = {0};
	__u32 ret = -EINVAL;

	LASSERT(tfm);
	desc.tfm = tfm;
	desc.info = local_iv;
	desc.flags = 0;

	if (length % crypto_blkcipher_blocksize(tfm) != 0) {
		CERROR("output length %zu mismatch blocksize %d\n",
		       length, crypto_blkcipher_blocksize(tfm));
		goto out;
	}

	if (crypto_blkcipher_ivsize(tfm) > ARRAY_SIZE(local_iv)) {
		CERROR("iv size too large %d\n", crypto_blkcipher_ivsize(tfm));
		goto out;
	}

	if (iv)
		memcpy(local_iv, iv, crypto_blkcipher_ivsize(tfm));

	memcpy(out, in, length);

	ret = gss_setup_sgtable(&sg_out, &sg, out, length);
	if (ret != 0)
		goto out;

	if (decrypt)
		ret = crypto_blkcipher_decrypt_iv(&desc, &sg, &sg, length);
	else
		ret = crypto_blkcipher_encrypt_iv(&desc, &sg, &sg, length);

	gss_teardown_sgtable(&sg_out);
out:
	return ret;
}

int gss_digest_hmac(struct crypto_hash *tfm,
		    rawobj_t *key,
		    rawobj_t *hdr,
		    int msgcnt, rawobj_t *msgs,
		    int iovcnt, lnet_kiov_t *iovs,
		    rawobj_t *cksum)
{
	struct hash_desc desc = {
		.tfm = tfm,
		.flags = 0,
	};
	struct scatterlist sg[1];
	struct sg_table sgt;
	int i;
	int rc;

	rc = crypto_hash_setkey(tfm, key->data, key->len);
	if (rc)
		return rc;

	rc = crypto_hash_init(&desc);
	if (rc)
		return rc;

	for (i = 0; i < msgcnt; i++) {
		if (msgs[i].len == 0)
			continue;

		rc = gss_setup_sgtable(&sgt, sg, msgs[i].data, msgs[i].len);
		if (rc != 0)
			return rc;
		rc = crypto_hash_update(&desc, sg, msgs[i].len);
		if (rc)
			return rc;

		gss_teardown_sgtable(&sgt);
	}

	for (i = 0; i < iovcnt; i++) {
		if (iovs[i].kiov_len == 0)
			continue;

		sg_init_table(sg, 1);
		sg_set_page(&sg[0], iovs[i].kiov_page, iovs[i].kiov_len,
			    iovs[i].kiov_offset);
		rc = crypto_hash_update(&desc, sg, iovs[i].kiov_len);
		if (rc)
			return rc;
	}

	if (hdr) {
		rc = gss_setup_sgtable(&sgt, sg, hdr, sizeof(*hdr));
		if (rc != 0)
			return rc;
		rc = crypto_hash_update(&desc, sg, sizeof(hdr->len));
		if (rc)
			return rc;

		gss_teardown_sgtable(&sgt);
	}

	return crypto_hash_final(&desc, cksum->data);
}

int gss_digest_norm(struct crypto_hash *tfm,
		    struct gss_keyblock *kb,
		    rawobj_t *hdr,
		    int msgcnt, rawobj_t *msgs,
		    int iovcnt, lnet_kiov_t *iovs,
		    rawobj_t *cksum)
{
	struct hash_desc   desc;
	struct scatterlist sg[1];
	struct sg_table sgt;
	int                i;
	int                rc;

	LASSERT(kb->kb_tfm);
	desc.tfm = tfm;
	desc.flags = 0;

	rc = crypto_hash_init(&desc);
	if (rc)
		return rc;

	for (i = 0; i < msgcnt; i++) {
		if (msgs[i].len == 0)
			continue;

		rc = gss_setup_sgtable(&sgt, sg, msgs[i].data, msgs[i].len);
		if (rc != 0)
			return rc;

		rc = crypto_hash_update(&desc, sg, msgs[i].len);
		if (rc)
			return rc;

		gss_teardown_sgtable(&sgt);
	}

	for (i = 0; i < iovcnt; i++) {
		if (iovs[i].kiov_len == 0)
			continue;

		sg_init_table(sg, 1);
		sg_set_page(&sg[0], iovs[i].kiov_page, iovs[i].kiov_len,
			    iovs[i].kiov_offset);
		rc = crypto_hash_update(&desc, sg, iovs[i].kiov_len);
		if (rc)
			return rc;
	}

	if (hdr) {
		rc = gss_setup_sgtable(&sgt, sg, hdr, sizeof(*hdr));
		if (rc != 0)
			return rc;

		rc = crypto_hash_update(&desc, sg, sizeof(*hdr));
		if (rc)
			return rc;

		gss_teardown_sgtable(&sgt);
	}

	rc = crypto_hash_final(&desc, cksum->data);
	if (rc)
		return rc;

	return gss_crypt_generic(kb->kb_tfm, 0, NULL, cksum->data,
				 cksum->data, cksum->len);
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

int gss_crypt_rawobjs(struct crypto_blkcipher *tfm, __u8 *iv,
		      int inobj_cnt, rawobj_t *inobjs, rawobj_t *outobj,
		      int enc)
{
	struct blkcipher_desc desc;
	struct scatterlist src;
	struct scatterlist dst;
	struct sg_table sg_dst;
	struct sg_table sg_src;
	__u8 *buf;
	__u32 datalen = 0;
	int i, rc;
	ENTRY;

	buf = outobj->data;
	desc.tfm  = tfm;
	desc.info = iv;
	desc.flags = 0;

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

		if (iv) {
			if (enc)
				rc = crypto_blkcipher_encrypt_iv(&desc, &dst,
								 &src,
								 src.length);
			else
				rc = crypto_blkcipher_decrypt_iv(&desc, &dst,
								 &src,
								 src.length);
		} else {
			if (enc)
				rc = crypto_blkcipher_encrypt(&desc, &dst, &src,
							      src.length);
			else
				rc = crypto_blkcipher_decrypt(&desc, &dst, &src,
							      src.length);
		}

		gss_teardown_sgtable(&sg_src);
		gss_teardown_sgtable(&sg_dst);

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
