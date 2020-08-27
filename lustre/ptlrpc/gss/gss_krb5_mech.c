/*
 * Modifications for Lustre
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
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
#include <linux/init.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/mutex.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_sec.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"
#include "gss_asn1.h"
#include "gss_krb5.h"
#include "gss_crypto.h"

static DEFINE_SPINLOCK(krb5_seq_lock);

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
	[ENCTYPE_DES_CBC_RAW] = {		/* des-cbc-md5 */
		.ke_dispname	= "des-cbc-md5",
		.ke_enc_name	= "cbc(des)",
		.ke_hash_name	= "md5",
		.ke_hash_size	= 16,
		.ke_conf_size	= 8,
	},
#ifdef HAVE_DES3_SUPPORT
	[ENCTYPE_DES3_CBC_RAW] = {		/* des3-hmac-sha1 */
		.ke_dispname	= "des3-hmac-sha1",
		.ke_enc_name	= "cbc(des3_ede)",
		.ke_hash_name	= "sha1",
		.ke_hash_size	= 20,
		.ke_conf_size	= 8,
		.ke_hash_hmac	= 1,
	},
#endif
	[ENCTYPE_AES128_CTS_HMAC_SHA1_96] = {	/* aes128-cts */
		.ke_dispname	= "aes128-cts-hmac-sha1-96",
		.ke_enc_name	= "cbc(aes)",
		.ke_hash_name	= "sha1",
		.ke_hash_size	= 12,
		.ke_conf_size	= 16,
		.ke_hash_hmac	= 1,
	},
	[ENCTYPE_AES256_CTS_HMAC_SHA1_96] = {	/* aes256-cts */
		.ke_dispname	= "aes256-cts-hmac-sha1-96",
		.ke_enc_name	= "cbc(aes)",
		.ke_hash_name	= "sha1",
		.ke_hash_size	= 12,
		.ke_conf_size	= 16,
		.ke_hash_hmac	= 1,
	},
	[ENCTYPE_ARCFOUR_HMAC] = {		/* arcfour-hmac-md5 */
		.ke_dispname	= "arcfour-hmac-md5",
		.ke_enc_name	= "ecb(arc4)",
		.ke_hash_name	= "md5",
		.ke_hash_size	= 16,
		.ke_conf_size	= 8,
		.ke_hash_hmac	= 1,
	}
};

static const char * enctype2str(__u32 enctype)
{
	if (enctype < ARRAY_SIZE(enctypes) && enctypes[enctype].ke_dispname)
		return enctypes[enctype].ke_dispname;

	return "unknown";
}

static
int krb5_init_keys(struct krb5_ctx *kctx)
{
	struct krb5_enctype *ke;

	if (kctx->kc_enctype >= ARRAY_SIZE(enctypes) ||
	    enctypes[kctx->kc_enctype].ke_hash_size == 0) {
		CERROR("unsupported enctype %x\n", kctx->kc_enctype);
		return -1;
	}

        ke = &enctypes[kctx->kc_enctype];

	/* tfm arc4 is stateful, user should alloc-use-free by his own */
	if (kctx->kc_enctype != ENCTYPE_ARCFOUR_HMAC &&
	    gss_keyblock_init(&kctx->kc_keye, ke->ke_enc_name, ke->ke_enc_mode))
		return -1;

	/* tfm hmac is stateful, user should alloc-use-free by his own */
	if (ke->ke_hash_hmac == 0 &&
	    gss_keyblock_init(&kctx->kc_keyi, ke->ke_enc_name, ke->ke_enc_mode))
		return -1;
	if (ke->ke_hash_hmac == 0 &&
	    gss_keyblock_init(&kctx->kc_keyc, ke->ke_enc_name, ke->ke_enc_mode))
		return -1;

        return 0;
}

static
void delete_context_kerberos(struct krb5_ctx *kctx)
{
	rawobj_free(&kctx->kc_mech_used);

	gss_keyblock_free(&kctx->kc_keye);
	gss_keyblock_free(&kctx->kc_keyi);
	gss_keyblock_free(&kctx->kc_keyc);
}

static
__u32 import_context_rfc1964(struct krb5_ctx *kctx, char *p, char *end)
{
	unsigned int    tmp_uint, keysize;

	/* seed_init flag */
	if (gss_get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
		goto out_err;
	kctx->kc_seed_init = (tmp_uint != 0);

	/* seed */
	if (gss_get_bytes(&p, end, kctx->kc_seed, sizeof(kctx->kc_seed)))
		goto out_err;

	/* sign/seal algorithm, not really used now */
	if (gss_get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)) ||
	    gss_get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
		goto out_err;

	/* end time. While kc_endtime might be 64 bit the krb5 API
	 * still uses 32 bits. To delay the 2038 bug see the incoming
	 * value as a u32 which give us until 2106. See the link for details:
	 *
	 * http://web.mit.edu/kerberos/www/krb5-current/doc/appdev/y2038.html
	 */
	if (gss_get_bytes(&p, end, &kctx->kc_endtime, sizeof(u32)))
		goto out_err;

	/* seq send */
	if (gss_get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
		goto out_err;
	kctx->kc_seq_send = tmp_uint;

	/* mech oid */
	if (gss_get_rawobj(&p, end, &kctx->kc_mech_used))
		goto out_err;

	/* old style enc/seq keys in format:
	 *   - enctype (u32)
	 *   - keysize (u32)
	 *   - keydata
	 * we decompose them to fit into the new context
	 */

	/* enc key */
	if (gss_get_bytes(&p, end, &kctx->kc_enctype, sizeof(kctx->kc_enctype)))
		goto out_err;

	if (gss_get_bytes(&p, end, &keysize, sizeof(keysize)))
		goto out_err;

	if (gss_get_keyblock(&p, end, &kctx->kc_keye, keysize))
		goto out_err;

	/* seq key */
	if (gss_get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)) ||
	    tmp_uint != kctx->kc_enctype)
		goto out_err;

	if (gss_get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)) ||
	    tmp_uint != keysize)
		goto out_err;

	if (gss_get_keyblock(&p, end, &kctx->kc_keyc, keysize))
		goto out_err;

	/* old style fallback */
	if (gss_keyblock_dup(&kctx->kc_keyi, &kctx->kc_keyc))
		goto out_err;

	if (p != end)
		goto out_err;

	CDEBUG(D_SEC, "successfully imported rfc1964 context\n");
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

	/* end time. While kc_endtime might be 64 bit the krb5 API
	 * still uses 32 bits. To delay the 2038 bug see the incoming
	 * value as a u32 which give us until 2106. See the link for details:
	 *
	 * http://web.mit.edu/kerberos/www/krb5-current/doc/appdev/y2038.html
	 */
	if (gss_get_bytes(&p, end, &kctx->kc_endtime, sizeof(u32)))
		goto out_err;

	/* flags */
	if (gss_get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
		goto out_err;

	if (tmp_uint & KRB5_CTX_FLAG_INITIATOR)
		kctx->kc_initiate = 1;
	if (tmp_uint & KRB5_CTX_FLAG_CFX)
		kctx->kc_cfx = 1;
	if (tmp_uint & KRB5_CTX_FLAG_ACCEPTOR_SUBKEY)
		kctx->kc_have_acceptor_subkey = 1;

	/* seq send */
	if (gss_get_bytes(&p, end, &kctx->kc_seq_send,
	    sizeof(kctx->kc_seq_send)))
		goto out_err;

	/* enctype */
	if (gss_get_bytes(&p, end, &kctx->kc_enctype, sizeof(kctx->kc_enctype)))
		goto out_err;

	/* size of each key */
	if (gss_get_bytes(&p, end, &keysize, sizeof(keysize)))
		goto out_err;

	/* number of keys - should always be 3 */
	if (gss_get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint)))
		goto out_err;

	if (tmp_uint != 3) {
		CERROR("Invalid number of keys: %u\n", tmp_uint);
		goto out_err;
	}

	/* ke */
	if (gss_get_keyblock(&p, end, &kctx->kc_keye, keysize))
		goto out_err;
	/* ki */
	if (gss_get_keyblock(&p, end, &kctx->kc_keyi, keysize))
		goto out_err;
	/* ki */
	if (gss_get_keyblock(&p, end, &kctx->kc_keyc, keysize))
		goto out_err;

	CDEBUG(D_SEC, "successfully imported v2 context\n");
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
	char *p = (char *)inbuf->data;
	char *end = (char *)(inbuf->data + inbuf->len);
	unsigned int tmp_uint, rc;

	if (gss_get_bytes(&p, end, &tmp_uint, sizeof(tmp_uint))) {
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

	if (gss_keyblock_dup(&knew->kc_keye, &kctx->kc_keye))
		goto out_err;
	if (gss_keyblock_dup(&knew->kc_keyi, &kctx->kc_keyi))
		goto out_err;
	if (gss_keyblock_dup(&knew->kc_keyc, &kctx->kc_keyc))
		goto out_err;
        if (krb5_init_keys(knew))
                goto out_err;

        gctx_new->internal_ctx_id = knew;
	CDEBUG(D_SEC, "successfully copied reverse context\n");
        return GSS_S_COMPLETE;

out_err:
        delete_context_kerberos(knew);
        OBD_FREE_PTR(knew);
        return GSS_S_FAILURE;
}

static
__u32 gss_inquire_context_kerberos(struct gss_ctx *gctx,
				   time64_t *endtime)
{
        struct krb5_ctx *kctx = gctx->internal_ctx_id;

	*endtime = kctx->kc_endtime;
        return GSS_S_COMPLETE;
}

static
void gss_delete_sec_context_kerberos(void *internal_ctx)
{
        struct krb5_ctx *kctx = internal_ctx;

        delete_context_kerberos(kctx);
        OBD_FREE_PTR(kctx);
}

/*
 * compute (keyed/keyless) checksum against the plain text which appended
 * with krb5 wire token header.
 */
static
__s32 krb5_make_checksum(__u32 enctype,
			 struct gss_keyblock *kb,
			 struct krb5_header *khdr,
			 int msgcnt, rawobj_t *msgs,
			 int iovcnt, struct bio_vec *iovs,
			 rawobj_t *cksum,
			 digest_hash hash_func)
{
	struct krb5_enctype *ke = &enctypes[enctype];
	struct ahash_request *req = NULL;
	enum cfs_crypto_hash_alg hash_algo;
	rawobj_t hdr;
	int rc;

	hash_algo = cfs_crypto_hash_alg(ke->ke_hash_name);

	/* For the cbc(des) case we want md5 instead of hmac(md5) */
	if (strcmp(ke->ke_enc_name, "cbc(des)"))
		req = cfs_crypto_hash_init(hash_algo, kb->kb_key.data,
					   kb->kb_key.len);
	else
		req = cfs_crypto_hash_init(hash_algo, NULL, 0);
	if (IS_ERR(req)) {
		rc = PTR_ERR(req);
		CERROR("failed to alloc hash %s : rc = %d\n",
		       ke->ke_hash_name, rc);
		goto out_no_hash;
	}

	cksum->len = cfs_crypto_hash_digestsize(hash_algo);
	OBD_ALLOC_LARGE(cksum->data, cksum->len);
	if (!cksum->data) {
		cksum->len = 0;
		rc = -ENOMEM;
		goto out_free_hash;
	}

	hdr.data = (__u8 *)khdr;
	hdr.len = sizeof(*khdr);

	if (!hash_func) {
		rc = -EPROTO;
		CERROR("hash function for %s undefined\n",
		       ke->ke_hash_name);
		goto out_free_hash;
	}
	rc = hash_func(req, &hdr, msgcnt, msgs, iovcnt, iovs);
	if (rc)
		goto out_free_hash;

	if (!ke->ke_hash_hmac) {
		LASSERT(kb->kb_tfm);

		cfs_crypto_hash_final(req, cksum->data, &cksum->len);
		rc = gss_crypt_generic(kb->kb_tfm, 0, NULL,
				       cksum->data, cksum->data,
				       cksum->len);
		goto out_no_hash;
	}

out_free_hash:
	if (req)
		cfs_crypto_hash_final(req, cksum->data, &cksum->len);
out_no_hash:
	return rc ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

static void fill_krb5_header(struct krb5_ctx *kctx,
                             struct krb5_header *khdr,
                             int privacy)
{
        unsigned char acceptor_flag;

        acceptor_flag = kctx->kc_initiate ? 0 : FLAG_SENDER_IS_ACCEPTOR;

        if (privacy) {
                khdr->kh_tok_id = cpu_to_be16(KG_TOK_WRAP_MSG);
                khdr->kh_flags = acceptor_flag | FLAG_WRAP_CONFIDENTIAL;
                khdr->kh_ec = cpu_to_be16(0);
                khdr->kh_rrc = cpu_to_be16(0);
        } else {
                khdr->kh_tok_id = cpu_to_be16(KG_TOK_MIC_MSG);
                khdr->kh_flags = acceptor_flag;
                khdr->kh_ec = cpu_to_be16(0xffff);
                khdr->kh_rrc = cpu_to_be16(0xffff);
        }

        khdr->kh_filler = 0xff;
	spin_lock(&krb5_seq_lock);
	khdr->kh_seq = cpu_to_be64(kctx->kc_seq_send++);
	spin_unlock(&krb5_seq_lock);
}

static __u32 verify_krb5_header(struct krb5_ctx *kctx,
                                struct krb5_header *khdr,
                                int privacy)
{
        unsigned char acceptor_flag;
        __u16         tok_id, ec_rrc;

        acceptor_flag = kctx->kc_initiate ? FLAG_SENDER_IS_ACCEPTOR : 0;

        if (privacy) {
                tok_id = KG_TOK_WRAP_MSG;
                ec_rrc = 0x0;
        } else {
                tok_id = KG_TOK_MIC_MSG;
                ec_rrc = 0xffff;
        }

        /* sanity checks */
        if (be16_to_cpu(khdr->kh_tok_id) != tok_id) {
                CERROR("bad token id\n");
                return GSS_S_DEFECTIVE_TOKEN;
        }
        if ((khdr->kh_flags & FLAG_SENDER_IS_ACCEPTOR) != acceptor_flag) {
                CERROR("bad direction flag\n");
                return GSS_S_BAD_SIG;
        }
        if (privacy && (khdr->kh_flags & FLAG_WRAP_CONFIDENTIAL) == 0) {
                CERROR("missing confidential flag\n");
                return GSS_S_BAD_SIG;
        }
        if (khdr->kh_filler != 0xff) {
                CERROR("bad filler\n");
                return GSS_S_DEFECTIVE_TOKEN;
        }
        if (be16_to_cpu(khdr->kh_ec) != ec_rrc ||
            be16_to_cpu(khdr->kh_rrc) != ec_rrc) {
                CERROR("bad EC or RRC\n");
                return GSS_S_DEFECTIVE_TOKEN;
        }
        return GSS_S_COMPLETE;
}

static
__u32 gss_get_mic_kerberos(struct gss_ctx *gctx,
			   int msgcnt,
			   rawobj_t *msgs,
			   int iovcnt,
			   struct bio_vec *iovs,
			   rawobj_t *token)
{
	struct krb5_ctx     *kctx = gctx->internal_ctx_id;
	struct krb5_enctype *ke = &enctypes[kctx->kc_enctype];
	struct krb5_header  *khdr;
	rawobj_t cksum = RAWOBJ_EMPTY;
	u32 major;

	/* fill krb5 header */
	LASSERT(token->len >= sizeof(*khdr));
	khdr = (struct krb5_header *)token->data;
	fill_krb5_header(kctx, khdr, 0);

	/* checksum */
	if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyc, khdr,
			       msgcnt, msgs, iovcnt, iovs, &cksum,
			       gctx->hash_func))
		GOTO(out_free_cksum, major = GSS_S_FAILURE);

	LASSERT(cksum.len >= ke->ke_hash_size);
	LASSERT(token->len >= sizeof(*khdr) + ke->ke_hash_size);
	memcpy(khdr + 1, cksum.data + cksum.len - ke->ke_hash_size,
	       ke->ke_hash_size);

	token->len = sizeof(*khdr) + ke->ke_hash_size;
	major = GSS_S_COMPLETE;
out_free_cksum:
	rawobj_free(&cksum);
	return major;
}

static
__u32 gss_verify_mic_kerberos(struct gss_ctx *gctx,
			      int msgcnt,
			      rawobj_t *msgs,
			      int iovcnt,
			      struct bio_vec *iovs,
			      rawobj_t *token)
{
	struct krb5_ctx *kctx = gctx->internal_ctx_id;
	struct krb5_enctype *ke = &enctypes[kctx->kc_enctype];
	struct krb5_header *khdr;
	rawobj_t cksum = RAWOBJ_EMPTY;
	u32 major;

	if (token->len < sizeof(*khdr)) {
		CERROR("short signature: %u\n", token->len);
		return GSS_S_DEFECTIVE_TOKEN;
	}

	khdr = (struct krb5_header *)token->data;

	major = verify_krb5_header(kctx, khdr, 0);
	if (major != GSS_S_COMPLETE) {
		CERROR("bad krb5 header\n");
		goto out;
	}

	if (token->len < sizeof(*khdr) + ke->ke_hash_size) {
		CERROR("short signature: %u, require %d\n",
		       token->len, (int) sizeof(*khdr) + ke->ke_hash_size);
		GOTO(out, major = GSS_S_FAILURE);
	}

	if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyc,
			       khdr, msgcnt, msgs, iovcnt, iovs, &cksum,
			       gctx->hash_func))
		GOTO(out_free_cksum, major = GSS_S_FAILURE);

	LASSERT(cksum.len >= ke->ke_hash_size);
	if (memcmp(khdr + 1, cksum.data + cksum.len - ke->ke_hash_size,
		   ke->ke_hash_size)) {
		CERROR("checksum mismatch\n");
		GOTO(out_free_cksum, major = GSS_S_BAD_SIG);
	}
	major = GSS_S_COMPLETE;
out_free_cksum:
	rawobj_free(&cksum);
out:
	return major;
}

/*
 * if adj_nob != 0, we adjust desc->bd_nob to the actual cipher text size.
 */
static
int krb5_encrypt_bulk(struct crypto_sync_skcipher *tfm,
		      struct krb5_header *khdr,
		      char *confounder,
		      struct ptlrpc_bulk_desc *desc,
		      rawobj_t *cipher,
		      int adj_nob)
{
	__u8 local_iv[16] = {0};
	struct scatterlist src, dst;
	struct sg_table sg_src, sg_dst;
	int blocksize, i, rc, nob = 0;
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);

	LASSERT(desc->bd_iov_count);
	LASSERT(desc->bd_enc_vec);

	blocksize = crypto_sync_skcipher_blocksize(tfm);
	LASSERT(blocksize > 1);
	LASSERT(cipher->len == blocksize + sizeof(*khdr));

	/* encrypt confounder */
	rc = gss_setup_sgtable(&sg_src, &src, confounder, blocksize);
	if (rc != 0)
		return rc;

	rc = gss_setup_sgtable(&sg_dst, &dst, cipher->data, blocksize);
	if (rc != 0) {
		gss_teardown_sgtable(&sg_src);
		return rc;
	}
	skcipher_request_set_sync_tfm(req, tfm);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, sg_src.sgl, sg_dst.sgl,
				   blocksize, local_iv);

	rc = crypto_skcipher_encrypt_iv(req, sg_dst.sgl, sg_src.sgl, blocksize);

	gss_teardown_sgtable(&sg_dst);
	gss_teardown_sgtable(&sg_src);

	if (rc) {
		CERROR("error to encrypt confounder: %d\n", rc);
		skcipher_request_zero(req);
		return rc;
	}

	/* encrypt clear pages */
	for (i = 0; i < desc->bd_iov_count; i++) {
		sg_init_table(&src, 1);
		sg_set_page(&src, desc->bd_vec[i].bv_page,
			    (desc->bd_vec[i].bv_len +
				blocksize - 1) &
			    (~(blocksize - 1)),
			    desc->bd_vec[i].bv_offset);
		if (adj_nob)
			nob += src.length;
		sg_init_table(&dst, 1);
		sg_set_page(&dst, desc->bd_enc_vec[i].bv_page,
			    src.length, src.offset);

		desc->bd_enc_vec[i].bv_offset = dst.offset;
		desc->bd_enc_vec[i].bv_len = dst.length;

		skcipher_request_set_crypt(req, &src, &dst,
					  src.length, local_iv);
		rc = crypto_skcipher_encrypt_iv(req, &dst, &src, src.length);
		if (rc) {
			CERROR("error to encrypt page: %d\n", rc);
			skcipher_request_zero(req);
			return rc;
		}
	}

	/* encrypt krb5 header */
	rc = gss_setup_sgtable(&sg_src, &src, khdr, sizeof(*khdr));
	if (rc != 0) {
		skcipher_request_zero(req);
		return rc;
	}

	rc = gss_setup_sgtable(&sg_dst, &dst, cipher->data + blocksize,
			   sizeof(*khdr));
	if (rc != 0) {
		gss_teardown_sgtable(&sg_src);
		skcipher_request_zero(req);
		return rc;
	}

	skcipher_request_set_crypt(req, sg_src.sgl, sg_dst.sgl,
				   sizeof(*khdr), local_iv);
	rc = crypto_skcipher_encrypt_iv(req, sg_dst.sgl, sg_src.sgl,
					sizeof(*khdr));
	skcipher_request_zero(req);

	gss_teardown_sgtable(&sg_dst);
	gss_teardown_sgtable(&sg_src);

        if (rc) {
                CERROR("error to encrypt krb5 header: %d\n", rc);
                return rc;
        }

        if (adj_nob)
                desc->bd_nob = nob;

        return 0;
}

/*
 * desc->bd_nob_transferred is the size of cipher text received.
 * desc->bd_nob is the target size of plain text supposed to be.
 *
 * if adj_nob != 0, we adjust each page's bv_len to the actual
 * plain text size.
 * - for client read: we don't know data size for each page, so
 *   bd_iov[]->bv_len is set to PAGE_SIZE, but actual data received might
 *   be smaller, so we need to adjust it according to
 *   bd_u.bd_kiov.bd_enc_vec[]->bv_len.
 *   this means we DO NOT support the situation that server send an odd size
 *   data in a page which is not the last one.
 * - for server write: we knows exactly data size for each page being expected,
 *   thus bv_len is accurate already, so we should not adjust it at all.
 *   and bd_u.bd_kiov.bd_enc_vec[]->bv_len should be
 *   round_up(bd_iov[]->bv_len) which
 *   should have been done by prep_bulk().
 */
static
int krb5_decrypt_bulk(struct crypto_sync_skcipher *tfm,
		      struct krb5_header *khdr,
		      struct ptlrpc_bulk_desc *desc,
		      rawobj_t *cipher,
		      rawobj_t *plain,
		      int adj_nob)
{
	__u8 local_iv[16] = {0};
	struct scatterlist src, dst;
	struct sg_table sg_src, sg_dst;
	int ct_nob = 0, pt_nob = 0;
	int blocksize, i, rc;
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);

	LASSERT(desc->bd_iov_count);
	LASSERT(desc->bd_enc_vec);
	LASSERT(desc->bd_nob_transferred);

	blocksize = crypto_sync_skcipher_blocksize(tfm);
	LASSERT(blocksize > 1);
	LASSERT(cipher->len == blocksize + sizeof(*khdr));

	if (desc->bd_nob_transferred % blocksize) {
		CERROR("odd transferred nob: %d\n", desc->bd_nob_transferred);
		return -EPROTO;
	}

	/* decrypt head (confounder) */
	rc = gss_setup_sgtable(&sg_src, &src, cipher->data, blocksize);
	if (rc != 0)
		return rc;

	rc = gss_setup_sgtable(&sg_dst, &dst, plain->data, blocksize);
	if (rc != 0) {
		gss_teardown_sgtable(&sg_src);
		return rc;
	}

	skcipher_request_set_sync_tfm(req, tfm);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, sg_src.sgl, sg_dst.sgl,
				   blocksize, local_iv);

	rc = crypto_skcipher_encrypt_iv(req, sg_dst.sgl, sg_src.sgl, blocksize);

	gss_teardown_sgtable(&sg_dst);
	gss_teardown_sgtable(&sg_src);

	if (rc) {
		CERROR("error to decrypt confounder: %d\n", rc);
		skcipher_request_zero(req);
		return rc;
	}

	for (i = 0; i < desc->bd_iov_count && ct_nob < desc->bd_nob_transferred;
	     i++) {
		if (desc->bd_enc_vec[i].bv_offset % blocksize != 0 ||
		    desc->bd_enc_vec[i].bv_len % blocksize != 0) {
			CERROR("page %d: odd offset %u len %u, blocksize %d\n",
			       i, desc->bd_enc_vec[i].bv_offset,
			       desc->bd_enc_vec[i].bv_len,
			       blocksize);
			skcipher_request_zero(req);
			return -EFAULT;
		}

		if (adj_nob) {
			if (ct_nob + desc->bd_enc_vec[i].bv_len >
			    desc->bd_nob_transferred)
				desc->bd_enc_vec[i].bv_len =
					desc->bd_nob_transferred - ct_nob;

			desc->bd_vec[i].bv_len =
			  desc->bd_enc_vec[i].bv_len;
			if (pt_nob + desc->bd_enc_vec[i].bv_len >
			    desc->bd_nob)
				desc->bd_vec[i].bv_len =
				  desc->bd_nob - pt_nob;
		} else {
			/* this should be guaranteed by LNET */
			LASSERT(ct_nob + desc->bd_enc_vec[i].
				bv_len <=
				desc->bd_nob_transferred);
			LASSERT(desc->bd_vec[i].bv_len <=
				desc->bd_enc_vec[i].bv_len);
		}

		if (desc->bd_enc_vec[i].bv_len == 0)
			continue;

		sg_init_table(&src, 1);
		sg_set_page(&src, desc->bd_enc_vec[i].bv_page,
			    desc->bd_enc_vec[i].bv_len,
			    desc->bd_enc_vec[i].bv_offset);
		dst = src;
		if (desc->bd_vec[i].bv_len % blocksize == 0)
			sg_assign_page(&dst,
				       desc->bd_vec[i].bv_page);

		skcipher_request_set_crypt(req, sg_src.sgl, sg_dst.sgl,
					   src.length, local_iv);
		rc = crypto_skcipher_decrypt_iv(req, &dst, &src, src.length);
		if (rc) {
			CERROR("error to decrypt page: %d\n", rc);
			skcipher_request_zero(req);
			return rc;
		}

		if (desc->bd_vec[i].bv_len % blocksize != 0) {
			memcpy(page_address(desc->bd_vec[i].bv_page) +
			       desc->bd_vec[i].bv_offset,
			       page_address(desc->bd_enc_vec[i].
					    bv_page) +
			       desc->bd_vec[i].bv_offset,
			       desc->bd_vec[i].bv_len);
		}

		ct_nob += desc->bd_enc_vec[i].bv_len;
		pt_nob += desc->bd_vec[i].bv_len;
	}

	if (unlikely(ct_nob != desc->bd_nob_transferred)) {
		CERROR("%d cipher text transferred but only %d decrypted\n",
		       desc->bd_nob_transferred, ct_nob);
		skcipher_request_zero(req);
		return -EFAULT;
	}

	if (unlikely(!adj_nob && pt_nob != desc->bd_nob)) {
		CERROR("%d plain text expected but only %d received\n",
		       desc->bd_nob, pt_nob);
		skcipher_request_zero(req);
		return -EFAULT;
	}

	/* if needed, clear up the rest unused iovs */
	if (adj_nob)
		while (i < desc->bd_iov_count)
			desc->bd_vec[i++].bv_len = 0;

	/* decrypt tail (krb5 header) */
	rc = gss_setup_sgtable(&sg_src, &src, cipher->data + blocksize,
			       sizeof(*khdr));
	if (rc != 0)
		return rc;

	rc = gss_setup_sgtable(&sg_dst, &dst, cipher->data + blocksize,
			       sizeof(*khdr));
	if (rc != 0) {
		gss_teardown_sgtable(&sg_src);
		return rc;
	}

	skcipher_request_set_crypt(req, sg_src.sgl, sg_dst.sgl,
				  src.length, local_iv);
	rc = crypto_skcipher_decrypt_iv(req, sg_dst.sgl, sg_src.sgl,
					sizeof(*khdr));
	gss_teardown_sgtable(&sg_src);
	gss_teardown_sgtable(&sg_dst);

	skcipher_request_zero(req);
	if (rc) {
		CERROR("error to decrypt tail: %d\n", rc);
		return rc;
	}

	if (memcmp(cipher->data + blocksize, khdr, sizeof(*khdr))) {
		CERROR("krb5 header doesn't match\n");
		return -EACCES;
	}

	return 0;
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
	int                  blocksize;
	rawobj_t             cksum = RAWOBJ_EMPTY;
	rawobj_t             data_desc[3], cipher;
	__u8                 conf[GSS_MAX_CIPHER_BLOCK];
	__u8                 local_iv[16] = {0};
	u32 major;
	int                  rc = 0;

	LASSERT(ke);
	LASSERT(ke->ke_conf_size <= GSS_MAX_CIPHER_BLOCK);
	LASSERT(kctx->kc_keye.kb_tfm == NULL ||
		ke->ke_conf_size >=
		crypto_sync_skcipher_blocksize(kctx->kc_keye.kb_tfm));

	/*
	 * final token format:
	 * ---------------------------------------------------
	 * | krb5 header | cipher text | checksum (16 bytes) |
	 * ---------------------------------------------------
	 */

	/* fill krb5 header */
	LASSERT(token->len >= sizeof(*khdr));
	khdr = (struct krb5_header *)token->data;
	fill_krb5_header(kctx, khdr, 1);

	/* generate confounder */
	get_random_bytes(conf, ke->ke_conf_size);

	/* get encryption blocksize. note kc_keye might not associated with
	 * a tfm, currently only for arcfour-hmac */
	if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
		LASSERT(kctx->kc_keye.kb_tfm == NULL);
		blocksize = 1;
	} else {
		LASSERT(kctx->kc_keye.kb_tfm);
		blocksize = crypto_sync_skcipher_blocksize(
							kctx->kc_keye.kb_tfm);
	}
	LASSERT(blocksize <= ke->ke_conf_size);

	/* padding the message */
	if (gss_add_padding(msg, msg_buflen, blocksize))
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

	/* compute checksum */
	if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyi,
			       khdr, 3, data_desc, 0, NULL, &cksum,
			       gctx->hash_func))
		GOTO(out_free_cksum, major = GSS_S_FAILURE);
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
	cipher.data = (__u8 *)(khdr + 1);
	cipher.len = token->len - sizeof(*khdr);
	LASSERT(cipher.len >= ke->ke_conf_size + msg->len + sizeof(*khdr));

	if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
		rawobj_t arc4_keye = RAWOBJ_EMPTY;
		struct crypto_sync_skcipher *arc4_tfm;

		if (krb5_make_checksum(ENCTYPE_ARCFOUR_HMAC, &kctx->kc_keyi,
				       NULL, 1, &cksum, 0, NULL, &arc4_keye,
				       gctx->hash_func)) {
			CERROR("failed to obtain arc4 enc key\n");
			GOTO(arc4_out_key, rc = -EACCES);
		}

		arc4_tfm = crypto_alloc_sync_skcipher("ecb(arc4)", 0, 0);
		if (IS_ERR(arc4_tfm)) {
			CERROR("failed to alloc tfm arc4 in ECB mode\n");
			GOTO(arc4_out_key, rc = -EACCES);
		}

		if (crypto_sync_skcipher_setkey(arc4_tfm, arc4_keye.data,
						arc4_keye.len)) {
			CERROR("failed to set arc4 key, len %d\n",
			       arc4_keye.len);
			GOTO(arc4_out_tfm, rc = -EACCES);
		}

		rc = gss_crypt_rawobjs(arc4_tfm, NULL, 3, data_desc,
				       &cipher, 1);
arc4_out_tfm:
		crypto_free_sync_skcipher(arc4_tfm);
arc4_out_key:
		rawobj_free(&arc4_keye);
	} else {
		rc = gss_crypt_rawobjs(kctx->kc_keye.kb_tfm, local_iv, 3,
				       data_desc, &cipher, 1);
	}

	if (rc)
		GOTO(out_free_cksum, major = GSS_S_FAILURE);

	/* fill in checksum */
	LASSERT(token->len >= sizeof(*khdr) + cipher.len + ke->ke_hash_size);
	memcpy((char *)(khdr + 1) + cipher.len,
	       cksum.data + cksum.len - ke->ke_hash_size,
	       ke->ke_hash_size);

	/* final token length */
	token->len = sizeof(*khdr) + cipher.len + ke->ke_hash_size;
	major = GSS_S_COMPLETE;
out_free_cksum:
	rawobj_free(&cksum);
	return major;
}

static
__u32 gss_prep_bulk_kerberos(struct gss_ctx *gctx,
			     struct ptlrpc_bulk_desc *desc)
{
	struct krb5_ctx     *kctx = gctx->internal_ctx_id;
	int                  blocksize, i;

	LASSERT(desc->bd_iov_count);
	LASSERT(desc->bd_enc_vec);
	LASSERT(kctx->kc_keye.kb_tfm);

	blocksize = crypto_sync_skcipher_blocksize(kctx->kc_keye.kb_tfm);

	for (i = 0; i < desc->bd_iov_count; i++) {
		LASSERT(desc->bd_enc_vec[i].bv_page);
		/*
		 * offset should always start at page boundary of either
		 * client or server side.
		 */
		if (desc->bd_vec[i].bv_offset & blocksize) {
			CERROR("odd offset %d in page %d\n",
			       desc->bd_vec[i].bv_offset, i);
			return GSS_S_FAILURE;
		}

		desc->bd_enc_vec[i].bv_offset =
			desc->bd_vec[i].bv_offset;
		desc->bd_enc_vec[i].bv_len =
			(desc->bd_vec[i].bv_len +
			 blocksize - 1) & (~(blocksize - 1));
	}

	return GSS_S_COMPLETE;
}

static
__u32 gss_wrap_bulk_kerberos(struct gss_ctx *gctx,
			     struct ptlrpc_bulk_desc *desc,
			     rawobj_t *token, int adj_nob)
{
	struct krb5_ctx     *kctx = gctx->internal_ctx_id;
	struct krb5_enctype *ke = &enctypes[kctx->kc_enctype];
	struct krb5_header  *khdr;
	int                  blocksz;
	rawobj_t             cksum = RAWOBJ_EMPTY;
	rawobj_t             data_desc[1], cipher;
	__u8                 conf[GSS_MAX_CIPHER_BLOCK];
	int rc = 0;
	u32 major;

	LASSERT(ke);
	LASSERT(ke->ke_conf_size <= GSS_MAX_CIPHER_BLOCK);

	/*
	 * final token format:
	 * --------------------------------------------------
	 * | krb5 header | head/tail cipher text | checksum |
	 * --------------------------------------------------
	 */

	/* fill krb5 header */
	LASSERT(token->len >= sizeof(*khdr));
	khdr = (struct krb5_header *)token->data;
	fill_krb5_header(kctx, khdr, 1);

	/* generate confounder */
	get_random_bytes(conf, ke->ke_conf_size);

	/* get encryption blocksize. note kc_keye might not associated with
	 * a tfm, currently only for arcfour-hmac */
	if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
		LASSERT(kctx->kc_keye.kb_tfm == NULL);
		blocksz = 1;
	} else {
		LASSERT(kctx->kc_keye.kb_tfm);
		blocksz = crypto_sync_skcipher_blocksize(kctx->kc_keye.kb_tfm);
	}

	/*
	 * we assume the size of krb5_header (16 bytes) must be n * blocksize.
	 * the bulk token size would be exactly (sizeof(krb5_header) +
	 * blocksize + sizeof(krb5_header) + hashsize)
	 */
	LASSERT(blocksz <= ke->ke_conf_size);
	LASSERT(sizeof(*khdr) >= blocksz && sizeof(*khdr) % blocksz == 0);
	LASSERT(token->len >= sizeof(*khdr) + blocksz + sizeof(*khdr) + 16);

	/*
	 * clear text layout for checksum:
	 * ------------------------------------------
	 * | confounder | clear pages | krb5 header |
	 * ------------------------------------------
	 */
	data_desc[0].data = conf;
	data_desc[0].len = ke->ke_conf_size;

	/* compute checksum */
	if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyi,
			       khdr, 1, data_desc,
			       desc->bd_iov_count, desc->bd_vec,
			       &cksum, gctx->hash_func))
		GOTO(out_free_cksum, major = GSS_S_FAILURE);
	LASSERT(cksum.len >= ke->ke_hash_size);

	/*
	 * clear text layout for encryption:
	 * ------------------------------------------
	 * | confounder | clear pages | krb5 header |
	 * ------------------------------------------
	 *        |              |             |
	 *        ----------  (cipher pages)   |
	 * result token:   |                   |
	 * -------------------------------------------
	 * | krb5 header | cipher text | cipher text |
	 * -------------------------------------------
	 */
	data_desc[0].data = conf;
	data_desc[0].len = ke->ke_conf_size;

	cipher.data = (__u8 *)(khdr + 1);
	cipher.len = blocksz + sizeof(*khdr);

	if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
		LBUG();
		rc = 0;
	} else {
		rc = krb5_encrypt_bulk(kctx->kc_keye.kb_tfm, khdr,
				       conf, desc, &cipher, adj_nob);
	}
	if (rc)
		GOTO(out_free_cksum, major = GSS_S_FAILURE);

	/* fill in checksum */
	LASSERT(token->len >= sizeof(*khdr) + cipher.len + ke->ke_hash_size);
	memcpy((char *)(khdr + 1) + cipher.len,
	       cksum.data + cksum.len - ke->ke_hash_size,
	       ke->ke_hash_size);

	/* final token length */
	token->len = sizeof(*khdr) + cipher.len + ke->ke_hash_size;
	major = GSS_S_COMPLETE;
out_free_cksum:
	rawobj_free(&cksum);
	return major;
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
	unsigned char       *tmpbuf;
	int                  blocksz, bodysize;
	rawobj_t             cksum = RAWOBJ_EMPTY;
	rawobj_t             cipher_in, plain_out;
	rawobj_t             hash_objs[3];
	int                  rc = 0;
	__u32                major;
	__u8                 local_iv[16] = {0};

	LASSERT(ke);

	if (token->len < sizeof(*khdr)) {
		CERROR("short signature: %u\n", token->len);
		return GSS_S_DEFECTIVE_TOKEN;
	}

	khdr = (struct krb5_header *)token->data;

	major = verify_krb5_header(kctx, khdr, 1);
	if (major != GSS_S_COMPLETE) {
		CERROR("bad krb5 header\n");
		return major;
	}

	/* block size */
	if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
		LASSERT(kctx->kc_keye.kb_tfm == NULL);
		blocksz = 1;
	} else {
		LASSERT(kctx->kc_keye.kb_tfm);
		blocksz = crypto_sync_skcipher_blocksize(kctx->kc_keye.kb_tfm);
	}

	/* expected token layout:
	 * ----------------------------------------
	 * | krb5 header | cipher text | checksum |
	 * ----------------------------------------
	 */
	bodysize = token->len - sizeof(*khdr) - ke->ke_hash_size;

	if (bodysize % blocksz) {
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
	OBD_ALLOC_LARGE(tmpbuf, bodysize);
	if (!tmpbuf)
		return GSS_S_FAILURE;

	major = GSS_S_FAILURE;

	cipher_in.data = (__u8 *)(khdr + 1);
	cipher_in.len = bodysize;
	plain_out.data = tmpbuf;
	plain_out.len = bodysize;

	if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
		rawobj_t		 arc4_keye;
		struct crypto_sync_skcipher *arc4_tfm;

		cksum.data = token->data + token->len - ke->ke_hash_size;
		cksum.len = ke->ke_hash_size;

		if (krb5_make_checksum(ENCTYPE_ARCFOUR_HMAC, &kctx->kc_keyi,
				       NULL, 1, &cksum, 0, NULL, &arc4_keye,
				       gctx->hash_func)) {
			CERROR("failed to obtain arc4 enc key\n");
			GOTO(arc4_out, rc = -EACCES);
		}

		arc4_tfm = crypto_alloc_sync_skcipher("ecb(arc4)", 0, 0);
		if (IS_ERR(arc4_tfm)) {
			CERROR("failed to alloc tfm arc4 in ECB mode\n");
			GOTO(arc4_out_key, rc = -EACCES);
		}

		if (crypto_sync_skcipher_setkey(arc4_tfm, arc4_keye.data,
						arc4_keye.len)) {
			CERROR("failed to set arc4 key, len %d\n",
			       arc4_keye.len);
			GOTO(arc4_out_tfm, rc = -EACCES);
		}

		rc = gss_crypt_rawobjs(arc4_tfm, NULL, 1, &cipher_in,
				       &plain_out, 0);
arc4_out_tfm:
		crypto_free_sync_skcipher(arc4_tfm);
arc4_out_key:
		rawobj_free(&arc4_keye);
arc4_out:
		cksum = RAWOBJ_EMPTY;
	} else {
		rc = gss_crypt_rawobjs(kctx->kc_keye.kb_tfm, local_iv, 1,
				       &cipher_in, &plain_out, 0);
	}

	if (rc != 0) {
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
	hash_objs[2].len = plain_out.len - ke->ke_conf_size - sizeof(*khdr);
	hash_objs[2].data = plain_out.data + ke->ke_conf_size;
	if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyi,
			       khdr, 3, hash_objs, 0, NULL, &cksum,
			       gctx->hash_func))
		goto out_free;

	LASSERT(cksum.len >= ke->ke_hash_size);
	if (memcmp((char *)(khdr + 1) + bodysize,
		   cksum.data + cksum.len - ke->ke_hash_size,
		   ke->ke_hash_size)) {
		CERROR("checksum mismatch\n");
		goto out_free;
	}

	msg->len =  bodysize - ke->ke_conf_size - sizeof(*khdr);
	memcpy(msg->data, tmpbuf + ke->ke_conf_size, msg->len);

	major = GSS_S_COMPLETE;
out_free:
	OBD_FREE_LARGE(tmpbuf, bodysize);
	rawobj_free(&cksum);
	return major;
}

static
__u32 gss_unwrap_bulk_kerberos(struct gss_ctx *gctx,
			       struct ptlrpc_bulk_desc *desc,
			       rawobj_t *token, int adj_nob)
{
	struct krb5_ctx     *kctx = gctx->internal_ctx_id;
	struct krb5_enctype *ke = &enctypes[kctx->kc_enctype];
	struct krb5_header  *khdr;
	int                  blocksz;
	rawobj_t             cksum = RAWOBJ_EMPTY;
	rawobj_t             cipher, plain;
	rawobj_t             data_desc[1];
	int                  rc;
	__u32                major;

	LASSERT(ke);

	if (token->len < sizeof(*khdr)) {
		CERROR("short signature: %u\n", token->len);
		return GSS_S_DEFECTIVE_TOKEN;
	}

	khdr = (struct krb5_header *)token->data;

	major = verify_krb5_header(kctx, khdr, 1);
	if (major != GSS_S_COMPLETE) {
		CERROR("bad krb5 header\n");
		return major;
	}

	/* block size */
	if (kctx->kc_enctype == ENCTYPE_ARCFOUR_HMAC) {
		LASSERT(kctx->kc_keye.kb_tfm == NULL);
		blocksz = 1;
		LBUG();
	} else {
		LASSERT(kctx->kc_keye.kb_tfm);
		blocksz = crypto_sync_skcipher_blocksize(kctx->kc_keye.kb_tfm);
	}
	LASSERT(sizeof(*khdr) >= blocksz && sizeof(*khdr) % blocksz == 0);

	/*
	 * token format is expected as:
	 * -----------------------------------------------
	 * | krb5 header | head/tail cipher text | cksum |
	 * -----------------------------------------------
	 */
	if (token->len < sizeof(*khdr) + blocksz + sizeof(*khdr) +
	    ke->ke_hash_size) {
		CERROR("short token size: %u\n", token->len);
		return GSS_S_DEFECTIVE_TOKEN;
	}

	cipher.data = (__u8 *) (khdr + 1);
	cipher.len = blocksz + sizeof(*khdr);
	plain.data = cipher.data;
	plain.len = cipher.len;

	rc = krb5_decrypt_bulk(kctx->kc_keye.kb_tfm, khdr,
			       desc, &cipher, &plain, adj_nob);
	if (rc)
		return GSS_S_DEFECTIVE_TOKEN;

	/*
	 * verify checksum, compose clear text as layout:
	 * ------------------------------------------
	 * | confounder | clear pages | krb5 header |
	 * ------------------------------------------
	 */
	data_desc[0].data = plain.data;
	data_desc[0].len = blocksz;

	if (krb5_make_checksum(kctx->kc_enctype, &kctx->kc_keyi,
			       khdr, 1, data_desc,
			       desc->bd_iov_count,
			       desc->bd_vec,
			       &cksum, gctx->hash_func))
		return GSS_S_FAILURE;
	LASSERT(cksum.len >= ke->ke_hash_size);

	if (memcmp(plain.data + blocksz + sizeof(*khdr),
		   cksum.data + cksum.len - ke->ke_hash_size,
		   ke->ke_hash_size)) {
		CERROR("checksum mismatch\n");
		rawobj_free(&cksum);
		return GSS_S_BAD_SIG;
	}

	rawobj_free(&cksum);
	return GSS_S_COMPLETE;
}

int gss_display_kerberos(struct gss_ctx        *ctx,
			 char                  *buf,
			 int                    bufsize)
{
	struct krb5_ctx    *kctx = ctx->internal_ctx_id;
	int                 written;

	written = scnprintf(buf, bufsize, "krb5 (%s)",
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
        .gss_prep_bulk              = gss_prep_bulk_kerberos,
        .gss_wrap_bulk              = gss_wrap_bulk_kerberos,
        .gss_unwrap_bulk            = gss_unwrap_bulk_kerberos,
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

static struct gss_api_mech gss_kerberos_mech = {
	/* .gm_owner uses default NULL value for THIS_MODULE */
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

void cleanup_kerberos_module(void)
{
        lgss_mech_unregister(&gss_kerberos_mech);
}
