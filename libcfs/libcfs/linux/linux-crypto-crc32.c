/* GPL HEADER START
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
 * version 2 along with this program; If not, see http://www.gnu.org/licenses
 *
 * Please  visit http://www.xyratex.com/contact if you need additional
 * information or have any questions.
 *
 * GPL HEADER END
 */

/*
 * Copyright 2012 Xyratex Technology Limited
 */

/*
 * This is crypto api shash wrappers to crc32_le.
 */

#include <linux/module.h>
#include <linux/crc32.h>
#ifdef HAVE_STRUCT_SHASH_ALG
#include <crypto/internal/hash.h>
#else
#include <linux/crypto.h>
#endif

#define CHKSUM_BLOCK_SIZE	1
#define CHKSUM_DIGEST_SIZE	4

static u32 __crc32_le(u32 crc, unsigned char const *p, size_t len)
{
	return crc32_le(crc, p, len);
}

/** No default init with ~0 */
static int crc32_cra_init(struct crypto_tfm *tfm)
{
	u32 *key = crypto_tfm_ctx(tfm);

	*key = 0;

	return 0;
}


#ifdef HAVE_STRUCT_SHASH_ALG
/*
 * Setting the seed allows arbitrary accumulators and flexible XOR policy
 * If your algorithm starts with ~0, then XOR with ~0 before you set
 * the seed.
 */
static int crc32_setkey(struct crypto_shash *hash, const u8 *key,
			unsigned int keylen)
{
	u32 *mctx = crypto_shash_ctx(hash);

	if (keylen != sizeof(u32)) {
		crypto_shash_set_flags(hash, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	*mctx = le32_to_cpup((__le32 *)key);
	return 0;
}

static int crc32_init(struct shash_desc *desc)
{
	u32 *mctx = crypto_shash_ctx(desc->tfm);
	u32 *crcp = shash_desc_ctx(desc);

	*crcp = *mctx;

	return 0;
}

static int crc32_update(struct shash_desc *desc, const u8 *data,
			unsigned int len)
{
	u32 *crcp = shash_desc_ctx(desc);

	*crcp = __crc32_le(*crcp, data, len);
	return 0;
}
/* No final XOR 0xFFFFFFFF, like crc32_le */
static int __crc32_finup(u32 *crcp, const u8 *data, unsigned int len,
			 u8 *out)
{
	*(__le32 *)out = cpu_to_le32(__crc32_le(*crcp, data, len));
	return 0;
}

static int crc32_finup(struct shash_desc *desc, const u8 *data,
		       unsigned int len, u8 *out)
{
	return __crc32_finup(shash_desc_ctx(desc), data, len, out);
}

static int crc32_final(struct shash_desc *desc, u8 *out)
{
	u32 *crcp = shash_desc_ctx(desc);

	*(__le32 *)out = cpu_to_le32p(crcp);
	return 0;
}

static int crc32_digest(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *out)
{
	return __crc32_finup(crypto_shash_ctx(desc->tfm), data, len,
			     out);
}
static struct shash_alg alg = {
	.setkey		= crc32_setkey,
	.init		= crc32_init,
	.update		= crc32_update,
	.final		= crc32_final,
	.finup		= crc32_finup,
	.digest		= crc32_digest,
	.descsize	= sizeof(u32),
	.digestsize	= CHKSUM_DIGEST_SIZE,
	.base		= {
		.cra_name		= "crc32",
		.cra_driver_name	= "crc32-table",
		.cra_priority		= 100,
		.cra_blocksize		= CHKSUM_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(u32),
		.cra_module		= THIS_MODULE,
		.cra_init		= crc32_cra_init,
	}
};
#else   /* HAVE_STRUCT_SHASH_ALG */
#ifdef HAVE_DIGEST_SETKEY_FLAGS
static int crc32_digest_setkey(struct crypto_tfm *tfm, const u8 *key,
			       unsigned int keylen, unsigned int *flags)
#else
static int crc32_digest_setkey(struct crypto_tfm *tfm, const u8 *key,
			       unsigned int keylen)
#endif
{
	u32 *mctx = crypto_tfm_ctx(tfm);

	if (keylen != sizeof(u32)) {
		tfm->crt_flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}
	*mctx = le32_to_cpup((__le32 *)key);
	return 0;
}

static void crc32_digest_init(struct crypto_tfm *tfm)
{
	u32 *mctx = crypto_tfm_ctx(tfm);

	*mctx = 0;

}
static void crc32_digest_update(struct crypto_tfm *tfm, const u8 *data,
				unsigned int len)
{
	u32 *crcp = crypto_tfm_ctx(tfm);

	*crcp = __crc32_le(*crcp, data, len);
}

static void crc32_digest_final(struct crypto_tfm *tfm, u8 *out)
{
	u32 *crcp = crypto_tfm_ctx(tfm);

	*(__le32 *)out = cpu_to_le32p(crcp);
}

static struct crypto_alg alg = {
	.cra_name		= "crc32",
	.cra_flags		= CRYPTO_ALG_TYPE_DIGEST,
	.cra_driver_name	= "crc32-table",
	.cra_priority		= 100,
	.cra_blocksize		= CHKSUM_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(u32),
	.cra_module		= THIS_MODULE,
	.cra_init		= crc32_cra_init,
	.cra_list		= LIST_HEAD_INIT(alg.cra_list),
	.cra_u			= {
		.digest		= {
			.dia_digestsize	= CHKSUM_DIGEST_SIZE,
			.dia_setkey	= crc32_digest_setkey,
			.dia_init	= crc32_digest_init,
			.dia_update	= crc32_digest_update,
			.dia_final	= crc32_digest_final
		}
	}
};
#endif  /* HAVE_STRUCT_SHASH_ALG */

int cfs_crypto_crc32_register(void)
{
#ifdef HAVE_STRUCT_SHASH_ALG
	return crypto_register_shash(&alg);
#else
	return crypto_register_alg(&alg);
#endif
}
EXPORT_SYMBOL(cfs_crypto_crc32_register);

void cfs_crypto_crc32_unregister(void)
{
#ifdef HAVE_STRUCT_SHASH_ALG
	crypto_unregister_shash(&alg);
#else
	crypto_unregister_alg(&alg);
#endif
}
EXPORT_SYMBOL(cfs_crypto_crc32_unregister);
