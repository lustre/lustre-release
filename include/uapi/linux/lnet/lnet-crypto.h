/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/* Copyright 2012 Xyratex Technology Limited
 *
 * Copyright (c) 2014, Intel Corporation.
 */

#ifndef _UAPI_LNET_CRYPTO_H
#define _UAPI_LNET_CRYPTO_H

#include <linux/types.h>
#include <linux/string.h>

struct cfs_crypto_hash_type {
	char		*cht_name;      /* hash algorithm name, equal to
					 * format name for crypto api
					 */
	unsigned int    cht_key;	/* init key by default (vaild for
					 * 4 bytes context like crc32, adler
					 */
	unsigned int    cht_size;       /* hash digest size */
};

struct cfs_crypto_crypt_type {
	char	       *cct_name;	  /* crypto algorithm name, equal to
					   * format name for crypto api
					   */
	unsigned int    cct_size;         /* crypto key size */
};

enum cfs_crypto_hash_alg {
	CFS_HASH_ALG_NULL	= 0,
	CFS_HASH_ALG_ADLER32,
	CFS_HASH_ALG_CRC32,
	CFS_HASH_ALG_CRC32C,
	/* hashes before here will be speed-tested at module load */
	CFS_HASH_ALG_MD5,
	CFS_HASH_ALG_SHA1,
	CFS_HASH_ALG_SHA256,
	CFS_HASH_ALG_SHA384,
	CFS_HASH_ALG_SHA512,
	CFS_HASH_ALG_MAX,
	CFS_HASH_ALG_SPEED_MAX = CFS_HASH_ALG_MD5,
	CFS_HASH_ALG_UNKNOWN	= 0xff
};

enum cfs_crypto_crypt_alg {
	CFS_CRYPT_ALG_NULL	= 0,
	CFS_CRYPT_ALG_AES256_CTR,
	CFS_CRYPT_ALG_MAX,
	CFS_CRYPT_ALG_UNKNOWN	= 0xff
};

static struct cfs_crypto_hash_type hash_types[] = {
	[CFS_HASH_ALG_NULL] = {
		.cht_name	= "null",
		.cht_key	= 0,
		.cht_size	= 0
	},
	[CFS_HASH_ALG_ADLER32] = {
		.cht_name	= "adler32",
		.cht_key	= 1,
		.cht_size	= 4
	},
	[CFS_HASH_ALG_CRC32] = {
		.cht_name	= "crc32",
		.cht_key	= ~0,
		.cht_size	= 4
	},
	[CFS_HASH_ALG_CRC32C] = {
		.cht_name	= "crc32c",
		.cht_key	= ~0,
		.cht_size	= 4
	},
	[CFS_HASH_ALG_MD5] = {
		.cht_name	= "md5",
		.cht_key	= 0,
		.cht_size	= 16
	},
	[CFS_HASH_ALG_SHA1] = {
		.cht_name	= "sha1",
		.cht_key	= 0,
		.cht_size	= 20
	},
	[CFS_HASH_ALG_SHA256] = {
		.cht_name	= "sha256",
		.cht_key	= 0,
		.cht_size	= 32
	},
	[CFS_HASH_ALG_SHA384] = {
		.cht_name	= "sha384",
		.cht_key	= 0,
		.cht_size	= 48
	},
	[CFS_HASH_ALG_SHA512] = {
		.cht_name	= "sha512",
		.cht_key	= 0,
		.cht_size	= 64
	},
	[CFS_HASH_ALG_MAX] = {
		.cht_name	= NULL,
		.cht_key	= 0,
		.cht_size	= 64
	}
};

static struct cfs_crypto_crypt_type crypt_types[] = {
	[CFS_CRYPT_ALG_NULL] = {
		.cct_name	= "null",
		.cct_size	= 0
	},
	[CFS_CRYPT_ALG_AES256_CTR] = {
		.cct_name	= "ctr(aes)",
		.cct_size	= 32
	}
};

/* Maximum size of hash_types[].cht_size */
#define CFS_CRYPTO_HASH_DIGESTSIZE_MAX 64

/*  Array of hash algorithm speed in MByte per second */
extern int cfs_crypto_hash_speeds[CFS_HASH_ALG_MAX];

/**
 * Return hash algorithm information for the specified algorithm identifier
 *
 * Hash information includes algorithm name, initial seed, hash size.
 *
 * RETURN		cfs_crypto_hash_type for valid ID (CFS_HASH_ALG_*)
 *			NULL for unknown algorithm identifier
 */
static inline const struct
cfs_crypto_hash_type *cfs_crypto_hash_type(enum cfs_crypto_hash_alg hash_alg)
{
	struct cfs_crypto_hash_type *ht;

	if (hash_alg < CFS_HASH_ALG_MAX) {
		ht = &hash_types[hash_alg];
		if (ht->cht_name)
			return ht;
	}
	return NULL;
}

/**
 * Return hash name for hash algorithm identifier
 *
 * @hash_alg		hash alrgorithm id (CFS_HASH_ALG_*)
 *
 * RETURN		string name of known hash algorithm
 *			"unknown" if hash algorithm is unknown
 */
static inline const
char *cfs_crypto_hash_name(enum cfs_crypto_hash_alg hash_alg)
{
	const struct cfs_crypto_hash_type *ht;

	ht = cfs_crypto_hash_type(hash_alg);
	if (ht)
		return ht->cht_name;

	return "unknown";
}

/**
 * Return digest size for hash algorithm type
 *
 * @hash_alg		hash alrgorithm id (CFS_HASH_ALG_*)
 *
 * RETURN		hash algorithm digest size in bytes
 *			0 if hash algorithm type is unknown
 */
static inline
unsigned int cfs_crypto_hash_digestsize(enum cfs_crypto_hash_alg hash_alg)
{
	const struct cfs_crypto_hash_type *ht;

	ht = cfs_crypto_hash_type(hash_alg);
	if (ht)
		return ht->cht_size;

	return 0;
}

/**
 * Find hash algorithm ID for the specified algorithm name
 *
 * RETURN		hash algorithm ID for valid ID (CFS_HASH_ALG_*)
 *			CFS_HASH_ALG_UNKNOWN for unknown algorithm name
 */
static inline unsigned char cfs_crypto_hash_alg(const char *algname)
{
	enum cfs_crypto_hash_alg hash_alg;

	for (hash_alg = 0; hash_alg < CFS_HASH_ALG_MAX; hash_alg++)
		if (strcmp(hash_types[hash_alg].cht_name, algname) == 0)
			return hash_alg;

	return CFS_HASH_ALG_UNKNOWN;
}

/**
 * Return crypt algorithm information for the specified algorithm identifier
 *
 * Crypt information includes algorithm name, key size.
 *
 * RETURN		cfs_crypto_crupt_type for valid ID (CFS_CRYPT_ALG_*)
 *			NULL for unknown algorithm identifier
 */
static inline const struct
cfs_crypto_crypt_type *cfs_crypto_crypt_type(
	enum cfs_crypto_crypt_alg crypt_alg)
{
	struct cfs_crypto_crypt_type *ct;

	if (crypt_alg < CFS_CRYPT_ALG_MAX) {
		ct = &crypt_types[crypt_alg];
		if (ct->cct_name)
			return ct;
	}
	return NULL;
}

/**
 * Return crypt name for crypt algorithm identifier
 *
 * @crypt_alg		crypt alrgorithm id (CFS_CRYPT_ALG_*)
 *
 * RETURN		string name of known crypt algorithm
 *			"unknown" if hash algorithm is unknown
 */
static inline const
char *cfs_crypto_crypt_name(enum cfs_crypto_crypt_alg crypt_alg)
{
	const struct cfs_crypto_crypt_type *ct;

	ct = cfs_crypto_crypt_type(crypt_alg);
	if (ct)
		return ct->cct_name;

	return "unknown";
}


/**
 * Return key size for crypto algorithm type
 *
 * @crypt_alg		crypt alrgorithm id (CFS_CRYPT_ALG_*)
 *
 * RETURN		crypt algorithm key size in bytes
 *			0 if crypt algorithm type is unknown
 */
static inline
unsigned int cfs_crypto_crypt_keysize(enum cfs_crypto_crypt_alg crypt_alg)
{
	const struct cfs_crypto_crypt_type *ct;

	ct = cfs_crypto_crypt_type(crypt_alg);
	if (ct)
		return ct->cct_size;

	return 0;
}

/**
 * Find crypto algorithm ID for the specified algorithm name
 *
 * RETURN		crypto algorithm ID for valid ID (CFS_CRYPT_ALG_*)
 *			CFS_CRYPT_ALG_UNKNOWN for unknown algorithm name
 */
static inline unsigned char cfs_crypto_crypt_alg(const char *algname)
{
	enum cfs_crypto_crypt_alg crypt_alg;

	for (crypt_alg = 0; crypt_alg < CFS_CRYPT_ALG_MAX; crypt_alg++)
		if (strcmp(crypt_types[crypt_alg].cct_name, algname) == 0)
			return crypt_alg;

	return CFS_CRYPT_ALG_UNKNOWN;
}

int cfs_crypto_hash_digest(enum cfs_crypto_hash_alg hash_alg,
			   const void *buf, unsigned int buf_len,
			   unsigned char *key, unsigned int key_len,
			   unsigned char *hash, unsigned int *hash_len);

#endif /* _UAPI_LNET_CRYPT_H_ */
