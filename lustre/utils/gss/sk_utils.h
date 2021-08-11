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
 * Copyright (C) 2015, Trustees of Indiana University
 *
 * Author: Jeremy Filizetti <jfilizet@iu.edu>
 */

#ifndef SK_UTILS_H
#define SK_UTILS_H

#include <gssapi/gssapi.h>
#ifdef HAVE_LIBKEYUTILS
#include <keyutils.h>
#endif
#include <linux/lustre/lustre_idl.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/types.h>

#include <libcfs/libcfs_crypto.h>
#include "lsupport.h"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) ((sizeof(a)) / (sizeof((a)[0])))
#endif /* !ARRAY_SIZE */

/* LL_CRYPTO_MAX_NAME value must match value of
 * CRYPTO_MAX_ALG_NAME in include/linux/crypto.h
 */
#ifdef HAVE_CRYPTO_MAX_ALG_NAME_128
#define LL_CRYPTO_MAX_NAME 128
#else
#define LL_CRYPTO_MAX_NAME 64
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static inline HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *ctx = OPENSSL_malloc(sizeof(*ctx));

	if (ctx != NULL)
		HMAC_CTX_init(ctx);
	return ctx;
}

static inline void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (ctx != NULL) {
		HMAC_CTX_cleanup(ctx);
		OPENSSL_cleanse(ctx, sizeof(*ctx));
		OPENSSL_free(ctx);
	}
}
static inline void DH_get0_pqg(const DH *dh,
			       const BIGNUM **p, const BIGNUM **q,
			       const BIGNUM **g)
{
	if (p != NULL)
		*p = dh->p;
	if (q != NULL)
		*q = dh->q;
	if (g != NULL)
		*g = dh->g;
}

static inline int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	/* If the fields p and g in dh are NULL, the corresponding input
	 * parameters MUST be non-NULL.  q may remain NULL.
	 */
	if ((dh->p == NULL && p == NULL)
	    || (dh->g == NULL && g == NULL))
		return 0;

	if (p != NULL) {
		BN_free(dh->p);
		dh->p = p;
	}
	if (q != NULL) {
		BN_free(dh->q);
		dh->q = q;
	}
	if (g != NULL) {
		BN_free(dh->g);
		dh->g = g;
	}

	if (q != NULL)
		dh->length = BN_num_bits(q);

	return 1;
}

static inline void DH_get0_key(const DH *dh, const BIGNUM **pub_key,
			       const BIGNUM **priv_key)
{
	if (pub_key != NULL)
		*pub_key = dh->pub_key;
	if (priv_key != NULL)
		*priv_key = dh->priv_key;
}
#endif

/* Some limits and defaults */
#define SK_CONF_VERSION 1
#define SK_MSG_VERSION 1
#define SK_GENERATOR 2
#define SK_SESSION_MAX_KEYLEN_BYTES 1024
#define SK_MAX_KEYLEN_BYTES 128
#define SK_MAX_P_BYTES 2048
#define SK_NONCE_SIZE 4
#define MAX_MGSNIDS 16

enum sk_ctx_init_buffers {
	/* Initiator netstring buffer ordering */
	SK_INIT_VERSION	= 0,
	SK_INIT_RANDOM	= 1,
	SK_INIT_P	= 2,
	SK_INIT_PUB_KEY	= 3,
	SK_INIT_TARGET	= 4,
	SK_INIT_NODEMAP	= 5,
	SK_INIT_FLAGS	= 6,
	SK_INIT_HMAC	= 7,
	SK_INIT_BUFFERS = 8,

	/* Responder netstring buffer ordering */
	SK_RESP_VERSION	= 0,
	SK_RESP_RANDOM	= 1,
	SK_RESP_PUB_KEY	= 2,
	SK_RESP_HMAC	= 3,
	SK_RESP_BUFFERS	= 4,
};

/* String consisting of "lustre:fsname:nodemap_hash" */
#define SK_DESCRIPTION_SIZE (9 + MTI_NAME_MAXLEN + LUSTRE_NODEMAP_NAME_LENGTH)

enum sk_key_type {
	SK_TYPE_INVALID	= 0x0,
	SK_TYPE_CLIENT	= 0x1,
	SK_TYPE_SERVER	= 0x2,
	SK_TYPE_MGS	= 0x4,
};

/* This is the packed structure format of key files that are distributed.
 * The on disk format should be store in big-endian. */
struct sk_keyfile_config {
	/* File format version */
	uint32_t	skc_version;
	/* HMAC algorithm used for message integrity */
	uint16_t	skc_hmac_alg;
	/* Crypt algorithm used for privacy mode */
	uint16_t	skc_crypt_alg;
	/* Number of seconds that a context is valid after it is created from
	 * this keyfile */
	uint32_t	skc_expire;
	/* Length of shared key in skc_shared_key */
	uint32_t	skc_shared_keylen;
	/* Length of the prime used in the DHKE */
	uint32_t	skc_prime_bits;
	/* Key type */
	uint8_t		skc_type;
	/* Array of MGS NIDs to load key's for.  This is for the client since
	 * the upcall only knows the target name which is MGC<IP>@<NET>
	 * Only needed when mounting with mgssec */
	lnet_nid_t	skc_mgsnids[MAX_MGSNIDS];
	/* File system name for this key.  It can be unused for MGS only keys */
	char		skc_fsname[MTI_NAME_MAXLEN + 1];
	/* Nodemap name for this key.  Used by the server side to verify the
	 * client is in the correct nodemap */
	char		skc_nodemap[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	/* Shared key */
	unsigned char	skc_shared_key[SK_MAX_KEYLEN_BYTES];
	/* Prime (p) for DHKE */
	unsigned char	skc_p[SK_MAX_P_BYTES];
} __attribute__((packed));

/* Format passed to the kernel from userspace */
struct sk_kernel_ctx {
	uint32_t	skc_version;
	char		skc_hmac_alg[LL_CRYPTO_MAX_NAME];
	char		skc_crypt_alg[LL_CRYPTO_MAX_NAME];
	uint32_t	skc_expire;
	uint32_t	skc_host_random;
	uint32_t	skc_peer_random;
	gss_buffer_desc	skc_hmac_key;
	gss_buffer_desc	skc_encrypt_key;
	gss_buffer_desc	skc_shared_key;
	gss_buffer_desc	skc_session_key;
};

/* Structure used in context initiation to hold all necessary data */
struct sk_cred {
	uint32_t		 sc_flags;
	gss_buffer_desc		 sc_p;
	gss_buffer_desc		 sc_pub_key;
	gss_buffer_desc		 sc_tgt;
	gss_buffer_desc		 sc_nodemap_hash;
	gss_buffer_desc		 sc_hmac;
	gss_buffer_desc		 sc_dh_shared_key;
	struct sk_kernel_ctx	 sc_kctx;
	DH			*sc_params;
};

/* Names match up with openssl enc and dgst commands */
/* When adding new alg types, make sure first occurrence's name
 * matches cht_name in hash_types array.
 */
static const struct sk_crypt_type sk_crypt_algs[] = {
	{
		.sct_name = "null",
		.sct_type = SK_CRYPT_EMPTY
	},
	{
		.sct_name = "NONE",
		.sct_type = SK_CRYPT_EMPTY
	},
	{
		.sct_name = "ctr(aes)",
		.sct_type = SK_CRYPT_AES256_CTR
	},
	{
		.sct_name = "AES-256-CTR",
		.sct_type = SK_CRYPT_AES256_CTR
	}
};
static const struct sk_hmac_type sk_hmac_algs[] = {
	{
		.sht_name = "null",
		.sht_type = SK_HMAC_EMPTY
	},
	{
		.sht_name = "NONE",
		.sht_type = SK_HMAC_EMPTY
	},
	{
		.sht_name = "sha256",
		.sht_type = SK_HMAC_SHA256
	},
	{
		.sht_name = "SHA256",
		.sht_type = SK_HMAC_SHA256
	},
	{
		.sht_name = "sha512",
		.sht_type = SK_HMAC_SHA512
	},
	{
		.sht_name = "SHA512",
		.sht_type = SK_HMAC_SHA512
	}
};

static inline int sk_name2crypt(char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sk_crypt_algs); i++) {
		if (strcasecmp(name, sk_crypt_algs[i].sct_name) == 0)
			return sk_crypt_algs[i].sct_type;
	}

	return SK_CRYPT_INVALID;
}

static inline int sk_name2hmac(char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sk_hmac_algs); i++) {
		if (strcasecmp(name, sk_hmac_algs[i].sht_name) == 0)
			return sk_hmac_algs[i].sht_type;
	}

	return SK_HMAC_INVALID;
}

static inline const char *sk_crypt2name(enum sk_crypt_alg type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sk_crypt_algs); i++) {
		if (type == sk_crypt_algs[i].sct_type)
			return sk_crypt_algs[i].sct_name;
	}

	return NULL;
}

static inline const char *sk_hmac2name(enum sk_hmac_alg type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sk_hmac_algs); i++) {
		if (type == sk_hmac_algs[i].sht_type)
			return sk_hmac_algs[i].sht_name;
	}

	return NULL;
}

void sk_init_logging(char *program, int verbose, int fg);
struct sk_keyfile_config *sk_read_file(char *filename);
int sk_load_keyfile(char *path);
void sk_config_disk_to_cpu(struct sk_keyfile_config *config);
void sk_config_cpu_to_disk(struct sk_keyfile_config *config);
int sk_validate_config(const struct sk_keyfile_config *config);
uint32_t sk_verify_hash(const char *string, const EVP_MD *hash_alg,
			const gss_buffer_desc *current_hash);
struct sk_cred *sk_create_cred(const char *fsname, const char *cluster,
			       const uint32_t flags);
int sk_speedtest_dh_valid(unsigned int usec_check_max);
uint32_t sk_gen_params(struct sk_cred *skc, int num_rounds);
int sk_sign_bufs(gss_buffer_desc *key, gss_buffer_desc *bufs, const int numbufs,
		 const EVP_MD *hash_alg, gss_buffer_desc *hmac);
uint32_t sk_verify_hmac(struct sk_cred *skc, gss_buffer_desc *bufs,
			const int numbufs, const EVP_MD *hash_alg,
			gss_buffer_desc *hmac);
void sk_free_cred(struct sk_cred *skc);
int sk_session_kdf(struct sk_cred *skc, lnet_nid_t client_nid,
		   gss_buffer_desc *client_token, gss_buffer_desc *server_token);
uint32_t sk_compute_dh_key(struct sk_cred *skc, const gss_buffer_desc *pub_key);
int sk_compute_keys(struct sk_cred *skc);
int sk_serialize_kctx(struct sk_cred *skc, gss_buffer_desc *ctx_token);
int sk_decode_netstring(gss_buffer_desc *bufs, int numbufs,
			gss_buffer_desc *ns);
int sk_encode_netstring(gss_buffer_desc *bufs, int numbufs,
			gss_buffer_desc *ns);

#endif /* SK_UTILS_H */
