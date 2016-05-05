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
 * Wrappers for kernel crypto shash api to pclmulqdq crc32c imlementation.
 *
 * Author:     James Simmons <jsimmons@infradead.org>
 */
#include <linux/crc32.h>
#include <crypto/internal/hash.h>
#include <linux/crc32.h>
#include <asm/cpufeature.h>
#ifdef HAVE_FPU_API_HEADER
#include <asm/fpu/api.h>
#else
#include <asm/i387.h>
#endif
#include <libcfs/libcfs.h>

#define CHKSUM_BLOCK_SIZE	1
#define CHKSUM_DIGEST_SIZE	4

asmlinkage unsigned int crc_pcl(const u8 *buffer, int len,
				unsigned int crc_init);

static int crc32c_pclmul_cra_init(struct crypto_tfm *tfm)
{
	u32 *key = crypto_tfm_ctx(tfm);

	*key = ~0;
	return 0;
}

/*
 * Setting the seed allows arbitrary accumulators and flexible XOR policy
 * If your algorithm starts with ~0, then XOR with ~0 before you set
 * the seed.
 */
static int crc32c_pclmul_setkey(struct crypto_shash *hash, const u8 *key,
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

static int crc32c_pclmul_init(struct shash_desc *desc)
{
	u32 *mctx = crypto_shash_ctx(desc->tfm);
	u32 *crcp = shash_desc_ctx(desc);

	*crcp = *mctx;
	return 0;
}

static int crc32c_pclmul_update(struct shash_desc *desc, const u8 *data,
			       unsigned int len)
{
	u32 *crcp = shash_desc_ctx(desc);

	kernel_fpu_begin();
	*crcp = crc_pcl(data, len, *crcp);
	kernel_fpu_end();
	return 0;
}

/* No final XOR 0xFFFFFFFF, like crc32_le */
static int __crc32c_pclmul_finup(u32 *crcp, const u8 *data, unsigned int len,
				u8 *out)
{
	kernel_fpu_begin();
	*(__le32 *)out = ~cpu_to_le32(crc_pcl(data, len, *crcp));
	kernel_fpu_end();
	return 0;
}

static int crc32c_pclmul_finup(struct shash_desc *desc, const u8 *data,
			      unsigned int len, u8 *out)
{
	return __crc32c_pclmul_finup(shash_desc_ctx(desc), data, len, out);
}

static int crc32c_pclmul_digest(struct shash_desc *desc, const u8 *data,
			       unsigned int len, u8 *out)
{
	return __crc32c_pclmul_finup(crypto_shash_ctx(desc->tfm), data, len,
				    out);
}

static int crc32c_pclmul_final(struct shash_desc *desc, u8 *out)
{
	u32 *crcp = shash_desc_ctx(desc);

	*(__le32 *)out = ~cpu_to_le32p(crcp);
	return 0;
}

static struct shash_alg alg = {
	.setkey		= crc32c_pclmul_setkey,
	.init		= crc32c_pclmul_init,
	.update		= crc32c_pclmul_update,
	.final		= crc32c_pclmul_final,
	.finup		= crc32c_pclmul_finup,
	.digest		= crc32c_pclmul_digest,
	.descsize	= sizeof(u32),
	.digestsize	= CHKSUM_DIGEST_SIZE,
	.base		= {
			.cra_name		= "crc32c",
			.cra_driver_name	= "crc32c-pclmul",
			.cra_priority		= 150,
			.cra_blocksize		= CHKSUM_BLOCK_SIZE,
			.cra_ctxsize		= sizeof(u32),
			.cra_module		= THIS_MODULE,
			.cra_init		= crc32c_pclmul_cra_init,
	}
};

#ifndef X86_FEATURE_XMM4_2
#define X86_FEATURE_XMM4_2	(4*32+20)	/* "sse4_2" SSE-4.2 */
#endif

int cfs_crypto_crc32c_pclmul_register(void)
{
	if (!boot_cpu_has(X86_FEATURE_XMM4_2)) {
		CDEBUG(D_INFO, "CRC32 instruction is not detected.\n");
		return -ENODEV;
	}
	return crypto_register_shash(&alg);
}

void cfs_crypto_crc32c_pclmul_unregister(void)
{
	crypto_unregister_shash(&alg);
}
