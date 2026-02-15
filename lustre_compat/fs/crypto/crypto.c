// SPDX-License-Identifier: GPL-2.0-only
/*
 * This contains encryption functions for per-file encryption.
 *
 * Copyright (C) 2015, Google, Inc.
 * Copyright (C) 2015, Motorola Mobility
 *
 * Written by Michael Halcrow, 2014.
 *
 * Filename encryption additions
 *	Uday Savagaonkar, 2014
 * Encryption policy handling additions
 *	Ildar Muslukhov, 2014
 * Add llcrypt_pullback_bio_page()
 *	Jaegeuk Kim, 2015.
 *
 * This has not yet undergone a rigorous security audit.
 *
 * The usage of AES-XTS should conform to recommendations in NIST
 * Special Publication 800-38E and IEEE P1619/D16.
 */
/*
 * Linux commit 219d54332a09
 * tags/v5.4
 */

#include <linux/pagemap.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/ratelimit.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <crypto/aes.h>
#include <crypto/skcipher.h>
#include "llcrypt_private.h"
#include <lustre_compat.h>
#ifdef HAVE_CIPHER_H
#include <crypto/internal/cipher.h>

MODULE_IMPORT_NS(CRYPTO_INTERNAL);
#endif

static unsigned int num_prealloc_crypto_pages = 32;
static unsigned int num_prealloc_crypto_ctxs = 128;

module_param(num_prealloc_crypto_pages, uint, 0444);
MODULE_PARM_DESC(num_prealloc_crypto_pages,
		"Number of crypto pages to preallocate");
module_param(num_prealloc_crypto_ctxs, uint, 0444);
MODULE_PARM_DESC(num_prealloc_crypto_ctxs,
		"Number of crypto contexts to preallocate");

static char *client_encryption_engine = "aes-ni";
module_param(client_encryption_engine, charp, 0444);
MODULE_PARM_DESC(client_encryption_engine, "Client encryption engine");

enum llcrypt_crypto_engine_type llcrypt_crypto_engine = LLCRYPT_ENGINE_AES_NI;

static mempool_t *llcrypt_bounce_pool = NULL;

static LIST_HEAD(llcrypt_free_ctxs);
static DEFINE_SPINLOCK(llcrypt_ctx_lock);

static struct workqueue_struct *llcrypt_read_workqueue;
static DEFINE_MUTEX(llcrypt_init_mutex);

static struct kmem_cache *llcrypt_ctx_cachep;
struct kmem_cache *llcrypt_info_cachep;

void llcrypt_enqueue_decrypt_work(struct work_struct *work)
{
	queue_work(llcrypt_read_workqueue, work);
}
EXPORT_SYMBOL(llcrypt_enqueue_decrypt_work);

/*
 * A simple mempool-backed page allocator that allocates folios
 * of the order specified by pool_data.
 */
static void *llpool_alloc_folios(gfp_t gfp_mask, void *pool_data)
{
	struct folio *folio = folio_alloc(gfp_mask, (long)pool_data);

	if (IS_ERR_OR_NULL(folio))
		return NULL;
	return folio;
}

static void llpool_free_folios(void *element, void *pool_data)
{
	folio_put(element);
}

static inline mempool_t *llmempool_create_folio_pool(int min_nr, long order)
{
	return mempool_create(min_nr, llpool_alloc_folios, llpool_free_folios,
			      (void *)order);
}

/**
 * llcrypt_release_ctx() - Release a decryption context
 * @ctx: The decryption context to release.
 *
 * If the decryption context was allocated from the pre-allocated pool, return
 * it to that pool.  Else, free it.
 */
void llcrypt_release_ctx(struct llcrypt_ctx *ctx)
{
	unsigned long flags;

	if (ctx->flags & FS_CTX_REQUIRES_FREE_ENCRYPT_FL) {
		kmem_cache_free(llcrypt_ctx_cachep, ctx);
	} else {
		spin_lock_irqsave(&llcrypt_ctx_lock, flags);
		list_add(&ctx->free_list, &llcrypt_free_ctxs);
		spin_unlock_irqrestore(&llcrypt_ctx_lock, flags);
	}
}
EXPORT_SYMBOL(llcrypt_release_ctx);

/**
 * llcrypt_get_ctx() - Get a decryption context
 * @gfp_flags:   The gfp flag for memory allocation
 *
 * Allocate and initialize a decryption context.
 *
 * Return: A new decryption context on success; an ERR_PTR() otherwise.
 */
struct llcrypt_ctx *llcrypt_get_ctx(gfp_t gfp_flags)
{
	struct llcrypt_ctx *ctx;
	unsigned long flags;

	/*
	 * First try getting a ctx from the free list so that we don't have to
	 * call into the slab allocator.
	 */
	spin_lock_irqsave(&llcrypt_ctx_lock, flags);
	ctx = list_first_entry_or_null(&llcrypt_free_ctxs,
					struct llcrypt_ctx, free_list);
	if (ctx)
		list_del(&ctx->free_list);
	spin_unlock_irqrestore(&llcrypt_ctx_lock, flags);
	if (!ctx) {
		ctx = kmem_cache_zalloc(llcrypt_ctx_cachep, gfp_flags);
		if (!ctx)
			return ERR_PTR(-ENOMEM);
		ctx->flags |= FS_CTX_REQUIRES_FREE_ENCRYPT_FL;
	} else {
		ctx->flags &= ~FS_CTX_REQUIRES_FREE_ENCRYPT_FL;
	}
	return ctx;
}
EXPORT_SYMBOL(llcrypt_get_ctx);

struct folio *llcrypt_alloc_bounce(gfp_t gfp_flags)
{
	return mempool_alloc(llcrypt_bounce_pool, gfp_flags);
}

/**
 * llcrypt_free_bounce_folio() - free a ciphertext bounce folio
 *
 * Free a bounce folio that was allocated by llcrypt_encrypt_pagecache_blocks(),
 * or by llcrypt_alloc_bounce() directly.
 */
void llcrypt_free_bounce_folio(struct folio *bounce_folio)
{
	if (!bounce_folio)
		return;
	folio_change_private(bounce_folio, NULL);
	folio_clear_private(bounce_folio);
	mempool_free(bounce_folio, llcrypt_bounce_pool);
}
EXPORT_SYMBOL(llcrypt_free_bounce_folio);

void llcrypt_generate_iv(union llcrypt_iv *iv, u64 lblk_num,
			 const struct llcrypt_info *ci)
{
	memset(iv, 0, ci->ci_mode->ivsize);
	iv->lblk_num = cpu_to_le64(lblk_num);

	if (llcrypt_is_direct_key_policy(&ci->ci_policy))
		memcpy(iv->nonce, ci->ci_nonce, FS_KEY_DERIVATION_NONCE_SIZE);

	if (ci->ci_essiv_tfm != NULL)
		crypto_cipher_encrypt_one(ci->ci_essiv_tfm, iv->raw, iv->raw);
}

static inline void memcpy_folio_page(struct folio *dst, s32 dpg,
				     struct folio *src, s32 spg)
{
	size_t doff __maybe_unused = dpg > 0 ? PAGE_SIZE * dpg : 0;
	size_t soff __maybe_unused = spg > 0 ? PAGE_SIZE * spg : 0;
	void *to = kmap_local_folio(dst, doff);
	void *from = kmap_local_folio(src, soff);

	if (to != from)
		memcpy(to, from, PAGE_SIZE);
	kunmap_local(from);
	kunmap_local(to);
}

/* Encrypt or decrypt a single filesystem block of file contents */
int llcrypt_crypt_block(const struct inode *inode, llcrypt_direction_t rw,
			u64 lblk_num, struct folio *src_folio, s32 spg,
			struct folio *dest_folio, s32 dpg, size_t len,
			size_t offs, gfp_t gfp_flags)
{
	union llcrypt_iv iv;
	struct skcipher_request *req = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist dst, src;
	struct llcrypt_info *ci = llcrypt_info(inode);
	struct crypto_skcipher *tfm = ci->ci_ctfm;
	size_t doff = dpg > 0 ? PAGE_SIZE * dpg : 0;
	size_t soff = spg > 0 ? PAGE_SIZE * spg : 0;
	int res = 0;

	if (tfm == NULL) {
		memcpy_folio_page(dest_folio, dpg, src_folio, spg);
		return 0;
	}

	if (WARN_ON_ONCE(len <= 0))
		return -EINVAL;
	if (WARN_ON_ONCE(len % LL_CRYPTO_BLOCK_SIZE != 0))
		return -EINVAL;

	llcrypt_generate_iv(&iv, lblk_num, ci);

	req = skcipher_request_alloc(tfm, gfp_flags);
	if (!req)
		return -ENOMEM;

	skcipher_request_set_callback(
		req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);

	sg_init_table(&dst, 1);
	sg_set_folio(&dst, dest_folio, len, offs + doff);
	sg_init_table(&src, 1);
	sg_set_folio(&src, src_folio, len, offs + soff);
	skcipher_request_set_crypt(req, &src, &dst, len, &iv);
	if (rw == FS_DECRYPT)
		res = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
	else
		res = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	skcipher_request_free(req);
	if (res) {
		llcrypt_err(inode, "%scryption failed for block %llu: %d",
			    (rw == FS_DECRYPT ? "De" : "En"), lblk_num, res);
		return res;
	}
	return 0;
}

/**
 * llcrypt_encrypt_pagecache_blocks() - Encrypt filesystem blocks from a
 *					pagecache page
 * @folio:	The locked pagecache page containing the block(s) to encrypt
 * @len:	Total size of the block(s) to encrypt.  Must be a nonzero
 *		multiple of the filesystem's block size.
 * @offs:	Byte offset within @folio of the first block to encrypt.
 *		Must be a multiple of the filesystem's block size.
 * @gfp_flags:	Memory allocation flags
 *
 * A new bounce folio is allocated, and the specified block(s) are encrypted
 * into it.  In the bounce folio, the ciphertext block(s) will be located at
 * the same offsets at which the plaintext block(s) were located in the source
 * folio; any other parts of the bounce folio will be left uninitialized.
 * However, normally blocksize == PAGE_SIZE and the whole folio is encrypted
 * at once.
 *
 * This is for use by the filesystem's ->writepages() method.
 *
 * Return: the new encrypted bounce folio on success; an ERR_PTR() on failure
 */
struct folio *llcrypt_encrypt_pagecache_blocks(struct folio *folio, s32 pgno,
					       unsigned int len,
					       unsigned int offs,
					       gfp_t gfp_flags)
{
	const struct inode *inode = folio->mapping->host;
	const unsigned int blockbits = inode->i_blkbits;
	const unsigned int blocksize = 1 << blockbits;
	struct folio *ciphertext;
	pgoff_t index = folio->index + (pgno > 0 ? pgno : 0);
	u64 lblk_num = ((u64)index << (PAGE_SHIFT - blockbits)) +
		       (offs >> blockbits);
	unsigned int i;
	int err;

	if (WARN_ON_ONCE(!folio_test_locked(folio)))
		return ERR_PTR(-EINVAL);

	if (WARN_ON_ONCE(len <= 0 || !IS_ALIGNED(len | offs, blocksize)))
		return ERR_PTR(-EINVAL);

	ciphertext = llcrypt_alloc_bounce(gfp_flags);
	if (!ciphertext)
		return ERR_PTR(-ENOMEM);

	for (i = offs; i < offs + len; i += blocksize, lblk_num++) {
		err = llcrypt_crypt_block(inode, FS_ENCRYPT, lblk_num,
					  folio, pgno, ciphertext, 0,
					  blocksize, i, gfp_flags);
		if (err) {
			llcrypt_free_bounce_folio(ciphertext);
			return ERR_PTR(err);
		}
	}
	folio_set_private(ciphertext);
	folio_bounce_private(ciphertext, 0, folio, pgno);
	return ciphertext;
}
EXPORT_SYMBOL(llcrypt_encrypt_pagecache_blocks);

/**
 * llcrypt_encrypt_block() - Encrypt a filesystem block in a folio
 * @inode:     The inode to which this block belongs
 * @src:       The folio containing the block to encrypt
 * @dst:       The folio which will contain the encrypted data
 * @len:       Size of block to encrypt.  Doesn't need to be a multiple of the
 *		fs block size, but must be a multiple of LL_CRYPTO_BLOCK_SIZE.
 * @offs:      Byte offset within @folio at which the block to encrypt begins
 * @lblk_num:  Filesystem logical block number of the block, i.e. the 0-based
 *		number of the block within the file
 * @gfp_flags: Memory allocation flags
 *
 * Encrypt a possibly-compressed filesystem block that is located in an
 * arbitrary folio, not necessarily in the original pagecache folio.  The @inode
 * and @lblk_num must be specified, as they can't be determined from @folio.
 * The decrypted data will be stored in @dst.
 *
 * Return: 0 on success; -errno on failure
 */
int llcrypt_encrypt_block(const struct inode *inode, struct folio *src, s32 spg,
			  struct folio *dst, s32 dpg, unsigned int len,
			  unsigned int offs, u64 lblk_num, gfp_t gfp_flags)
{
	return llcrypt_crypt_block(inode, FS_ENCRYPT, lblk_num, src, spg, dst,
				   dpg, len, offs, gfp_flags);
}
EXPORT_SYMBOL(llcrypt_encrypt_block);

/**
 * llcrypt_decrypt_pagecache_blocks() - Decrypt filesystem blocks in a
 *					pagecache folio
 * @folio:      The locked pagecache folio containing the block(s) to decrypt
 * @len:       Total size of the block(s) to decrypt.  Must be a nonzero
 *		multiple of the filesystem's block size.
 * @offs:      Byte offset within @folio of the first block to decrypt.  Must be
 *		a multiple of the filesystem's block size.
 *
 * The specified block(s) are decrypted in-place within the pagecache folio,
 * which must still be locked and not uptodate.  Normally, blocksize ==
 * PAGE_SIZE and the whole folio is decrypted at once.
 *
 * This is for use by the filesystem's ->readpages() method.
 *
 * Return: 0 on success; -errno on failure
 */
int llcrypt_decrypt_pagecache_blocks(struct folio *folio, s32 pgno,
				     unsigned int len, unsigned int offs)
{
	const struct inode *inode = folio->mapping->host;
	const unsigned int blockbits = inode->i_blkbits;
	const unsigned int blocksize = 1 << blockbits;
	pgoff_t index = folio->index + (pgno > 0 ? pgno : 0);
	u64 lblk_num = ((u64)index << (PAGE_SHIFT - blockbits)) +
		       (offs >> blockbits);
	unsigned int i;
	int err;

	if (WARN_ON_ONCE(!folio_test_locked(folio)))
		return -EINVAL;

	if (WARN_ON_ONCE(len <= 0 || !IS_ALIGNED(len | offs, blocksize)))
		return -EINVAL;

	for (i = offs; i < offs + len; i += blocksize, lblk_num++) {
		err = llcrypt_crypt_block(inode, FS_DECRYPT, lblk_num,
					  folio, pgno, folio, pgno,
					  blocksize, i, GFP_NOFS);
		if (err)
			return err;
	}
	return 0;
}
EXPORT_SYMBOL(llcrypt_decrypt_pagecache_blocks);

/**
 * llcrypt_decrypt_block() - Cache a decrypted filesystem block in a folio
 * @inode:     The inode to which this block belongs
 * @src:       The folio containing the block to decrypt
 * @dst:       The folio which will contain the plain data
 * @len:       Size of block to decrypt.  Doesn't need to be a multiple of the
 *		fs block size, but must be a multiple of LL_CRYPTO_BLOCK_SIZE.
 * @offs:      Byte offset within @folio at which the block to decrypt begins
 * @lblk_num:  Filesystem logical block number of the block, i.e. the 0-based
 *		number of the block within the file
 *
 * Decrypt a possibly-compressed filesystem block that is located in an
 * arbitrary folio, not necessarily in the original pagecache folio.  The @inode
 * and @lblk_num must be specified, as they can't be determined from @folio.
 * The encrypted data will be stored in @dst.
 *
 * Return: 0 on success; -errno on failure
 */
int llcrypt_decrypt_block(const struct inode *inode, struct folio *src, s32 spg,
			  struct folio *dst, s32 dpg, unsigned int len,
			  unsigned int offs, u64 lblk_num, gfp_t gfp_flags)
{
	return llcrypt_crypt_block(inode, FS_DECRYPT, lblk_num, src, spg, dst,
				   dpg, len, offs, gfp_flags);
}
EXPORT_SYMBOL(llcrypt_decrypt_block);

/*
 * Validate dentries in encrypted directories to make sure we aren't potentially
 * caching stale dentries after a key has been added.
 */
static int llcrypt_d_revalidate(
#ifdef HAVE_D_REVALIDATE_WITH_INODE_NAME
				struct inode *inode, const struct qstr *qstr,
#endif
				struct dentry *dentry, unsigned int flags)
{
	struct dentry *dir;
	int err;
	int valid;

	/*
	 * Plaintext names are always valid, since llcrypt doesn't support
	 * reverting to ciphertext names without evicting the directory's inode
	 * -- which implies eviction of the dentries in the directory.
	 */
	if (!(dentry->d_flags & DCACHE_ENCRYPTED_NAME))
		return 1;

	/*
	 * Ciphertext name; valid if the directory's key is still unavailable.
	 *
	 * Although llcrypt forbids rename() on ciphertext names, we still must
	 * use dget_parent() here rather than use ->d_parent directly.  That's
	 * because a corrupted fs image may contain directory hard links, which
	 * the VFS handles by moving the directory's dentry tree in the dcache
	 * each time ->lookup() finds the directory and it already has a dentry
	 * elsewhere.  Thus ->d_parent can be changing, and we must safely grab
	 * a reference to some ->d_parent to prevent it from being freed.
	 */

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	dir = dget_parent(dentry);
	err = llcrypt_get_encryption_info(d_inode(dir));
	valid = !llcrypt_has_encryption_key(d_inode(dir));
	dput(dir);

	if (err < 0)
		return err;

	return valid;
}

const struct dentry_operations llcrypt_d_ops = {
	.d_revalidate = llcrypt_d_revalidate,
};

static void llcrypt_destroy(void)
{
	struct llcrypt_ctx *pos, *n;

	list_for_each_entry_safe(pos, n, &llcrypt_free_ctxs, free_list)
		kmem_cache_free(llcrypt_ctx_cachep, pos);
	INIT_LIST_HEAD(&llcrypt_free_ctxs);
	mempool_destroy(llcrypt_bounce_pool);
	llcrypt_bounce_pool = NULL;
}

/**
 * llcrypt_initialize() - allocate major buffers for fs encryption.
 * @cop_flags:  llcrypt operations flags
 *
 * We only call this when we start accessing encrypted files, since it
 * results in memory getting allocated that wouldn't otherwise be used.
 *
 * Return: Zero on success, non-zero otherwise.
 */
int llcrypt_initialize(unsigned int cop_flags)
{
	int i, res = -ENOMEM;

	/* No need to allocate a bounce page pool if this FS won't use it. */
	if (cop_flags & LL_CFLG_OWN_PAGES)
		return 0;

	mutex_lock(&llcrypt_init_mutex);
	if (llcrypt_bounce_pool)
		goto already_initialized;

	for (i = 0; i < num_prealloc_crypto_ctxs; i++) {
		struct llcrypt_ctx *ctx;

		ctx = kmem_cache_zalloc(llcrypt_ctx_cachep, GFP_NOFS);
		if (!ctx)
			goto fail;
		list_add(&ctx->free_list, &llcrypt_free_ctxs);
	}

	llcrypt_bounce_pool =
		llmempool_create_folio_pool(num_prealloc_crypto_pages, 0);
	if (!llcrypt_bounce_pool)
		goto fail;

already_initialized:
	mutex_unlock(&llcrypt_init_mutex);
	return 0;
fail:
	llcrypt_destroy();
	mutex_unlock(&llcrypt_init_mutex);
	return res;
}

void llcrypt_msg(const struct inode *inode, int mask,
		 const char *fmt, ...)
{
	static DEFINE_RATELIMIT_STATE(rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	struct va_format vaf;
	va_list args;

	if (!__ratelimit(&rs))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	if (inode)
		CDEBUG(mask, "llcrypt (%s, inode %lu): %pV\n",
		       inode->i_sb->s_id, inode->i_ino, &vaf);
	else
		CDEBUG(mask, "llcrypt: %pV\n", &vaf);
	va_end(args);
}

static inline int set_llcrypt_crypto_engine_type(void)
{
	if (strcmp(client_encryption_engine, "system-default") == 0)
		llcrypt_crypto_engine = LLCRYPT_ENGINE_SYSTEM_DEFAULT;
	else if (strcmp(client_encryption_engine, "aes-ni") == 0)
		llcrypt_crypto_engine = LLCRYPT_ENGINE_AES_NI;
	else
		llcrypt_crypto_engine = LLCRYPT_ENGINE_INVALID;

	if (llcrypt_crypto_engine == LLCRYPT_ENGINE_INVALID)
		return -EINVAL;

	return 0;
}

/**
 * llcrypt_init() - Set up for fs encryption.
 */
int __init llcrypt_init(void)
{
	int err = -ENOMEM;

	/*
	 * Use an unbound workqueue to allow bios to be decrypted in parallel
	 * even when they happen to complete on the same CPU.  This sacrifices
	 * locality, but it's worthwhile since decryption is CPU-intensive.
	 *
	 * Also use a high-priority workqueue to prioritize decryption work,
	 * which blocks reads from completing, over regular application tasks.
	 */
	llcrypt_read_workqueue = alloc_workqueue("llcrypt_read_queue",
						 WQ_UNBOUND | WQ_HIGHPRI,
						 num_online_cpus());
	if (!llcrypt_read_workqueue)
		goto fail;

	llcrypt_ctx_cachep = KMEM_CACHE(llcrypt_ctx, SLAB_RECLAIM_ACCOUNT);
	if (!llcrypt_ctx_cachep)
		goto fail_free_queue;

	llcrypt_info_cachep = KMEM_CACHE(llcrypt_info, SLAB_RECLAIM_ACCOUNT);
	if (!llcrypt_info_cachep)
		goto fail_free_ctx;

	err = set_llcrypt_crypto_engine_type();
	if (err) {
		CERROR("libcfs: bad crypto engine provided via 'client_encryption_engine': rc = %d\n",
		       err);
		goto fail_free_info;
	}

	err = llcrypt_init_keyring();
	if (err)
		goto fail_free_info;

	return 0;

fail_free_info:
	kmem_cache_destroy(llcrypt_info_cachep);
fail_free_ctx:
	kmem_cache_destroy(llcrypt_ctx_cachep);
fail_free_queue:
	destroy_workqueue(llcrypt_read_workqueue);
fail:
	return err;
}

/**
 * llcrypt_exit() - Clean up for fs encryption.
 */
void __exit llcrypt_exit(void)
{
	llcrypt_exit_keyring();

	llcrypt_destroy();
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();

	kmem_cache_destroy(llcrypt_info_cachep);
	kmem_cache_destroy(llcrypt_ctx_cachep);
	destroy_workqueue(llcrypt_read_workqueue);
}
