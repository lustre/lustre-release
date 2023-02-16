/* SPDX-License-Identifier: GPL-2.0 */
/*
 * llcrypt.h: declarations for per-file encryption
 *
 * Filesystems that implement per-file encryption must include this header
 * file.
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * Written by Michael Halcrow, 2015.
 * Modified by Jaegeuk Kim, 2015.
 */
/*
 * Linux commit 219d54332a09
 * tags/v5.4
 */
#ifndef _LINUX_LLCRYPT_H
#define _LINUX_LLCRYPT_H

#ifndef DCACHE_ENCRYPTED_NAME
#define DCACHE_ENCRYPTED_NAME 0x02000000
#endif

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <lustre_disk.h>
#include <uapi/linux/llcrypt.h>

#define LL_CRYPTO_BLOCK_SIZE		16

struct llcrypt_ctx;
struct llcrypt_info;

struct llcrypt_str {
	unsigned char *name;
	u32 len;
};

struct llcrypt_name {
	const struct qstr *usr_fname;
	struct llcrypt_str disk_name;
	u32 hash;
	u32 minor_hash;
	struct llcrypt_str crypto_buf;
	bool is_ciphertext_name;
};

#define LLTR_INIT(n, l)		{ .name = n, .len = l }
#define LLTR_TO_QSTR(f)		QSTR_INIT((f)->name, (f)->len)
#define lname_name(p)		((p)->disk_name.name)
#define lname_len(p)		((p)->disk_name.len)

/* Maximum value for the third parameter of llcrypt_operations.set_context(). */
#define LLCRYPT_SET_CONTEXT_MAX_SIZE	40
#define LLCRYPT_DIGESTED_CHAR_OLD	'_'
#define LLCRYPT_DIGESTED_CHAR		'+'

#ifdef CONFIG_LL_ENCRYPTION
/*
 * llcrypt superblock flags
 */
#define LL_CFLG_OWN_PAGES (1U << 1)

/*
 * crypto operations for filesystems
 */
struct llcrypt_operations {
	unsigned int flags;
	const char *key_prefix;
	int (*get_context)(struct inode *, void *, size_t);
	int (*set_context)(struct inode *, const void *, size_t, void *);
	bool (*dummy_context)(struct inode *);
	bool (*empty_dir)(struct inode *);
	unsigned int max_namelen;
};

/* Decryption work */
struct llcrypt_ctx {
	union {
		struct {
			struct bio *bio;
			struct work_struct work;
		};
		struct list_head free_list;	/* Free list */
	};
	u8 flags;				/* Flags */
};

extern bool llcrypt_has_encryption_key(const struct inode *inode);

static inline bool llcrypt_dummy_context_enabled(struct inode *inode)
{
	struct lustre_sb_info *lsi = s2lsi(inode->i_sb);

	if (unlikely(!lsi))
		return false;

	return lsi->lsi_cop->dummy_context &&
		lsi->lsi_cop->dummy_context(inode);
}

/*
 * When d_splice_alias() moves a directory's encrypted alias to its decrypted
 * alias as a result of the encryption key being added, DCACHE_ENCRYPTED_NAME
 * must be cleared.  Note that we don't have to support arbitrary moves of this
 * flag because llcrypt doesn't allow encrypted aliases to be the source or
 * target of a rename().
 */
static inline void llcrypt_handle_d_move(struct dentry *dentry)
{
	dentry->d_flags &= ~DCACHE_ENCRYPTED_NAME;
}

/* crypto.c */
extern int __init llcrypt_init(void);
extern void __exit llcrypt_exit(void);
extern void llcrypt_enqueue_decrypt_work(struct work_struct *);
extern struct llcrypt_ctx *llcrypt_get_ctx(gfp_t);
extern void llcrypt_release_ctx(struct llcrypt_ctx *);

extern struct page *llcrypt_encrypt_pagecache_blocks(struct page *page,
						     unsigned int len,
						     unsigned int offs,
						     gfp_t gfp_flags);
extern int llcrypt_encrypt_block(const struct inode *inode, struct page *src,
			 struct page *dst, unsigned int len,
			 unsigned int offs, u64 lblk_num, gfp_t gfp_flags);

extern int llcrypt_decrypt_pagecache_blocks(struct page *page, unsigned int len,
					    unsigned int offs);

extern int llcrypt_decrypt_block(const struct inode *inode, struct page *src,
			 struct page *dst, unsigned int len,
			 unsigned int offs, u64 lblk_num, gfp_t gfp_flags);

static inline int llcrypt_decrypt_block_inplace(const struct inode *inode,
						struct page *page,
						unsigned int len,
						unsigned int offs,
						u64 lblk_num)
{
	return llcrypt_decrypt_block(inode, page, page, len, offs, lblk_num,
				     GFP_NOFS);
}

static inline bool llcrypt_is_bounce_page(struct page *page)
{
	return page->mapping == NULL;
}

static inline struct page *llcrypt_pagecache_page(struct page *bounce_page)
{
	return (struct page *)page_private(bounce_page);
}

extern void llcrypt_free_bounce_page(struct page *bounce_page);

/* policy.c */
extern int llcrypt_ioctl_set_policy(struct file *, const void __user *);
extern int llcrypt_ioctl_get_policy(struct file *, void __user *);
extern int llcrypt_ioctl_get_policy_ex(struct file *, void __user *);
extern int llcrypt_has_permitted_context(struct inode *, struct inode *);
extern int llcrypt_inherit_context(struct inode *, struct inode *,
					void *, bool);
extern bool llcrypt_policy_has_filename_enc(struct inode *inode);
/* keyring.c */
extern void llcrypt_sb_free(struct super_block *sb);
extern int llcrypt_ioctl_add_key(struct file *filp, void __user *arg);
extern int llcrypt_ioctl_remove_key(struct file *filp, void __user *arg);
extern int llcrypt_ioctl_remove_key_all_users(struct file *filp,
					      void __user *arg);
extern int llcrypt_ioctl_get_key_status(struct file *filp, void __user *arg);

/* keysetup.c */
extern int llcrypt_get_encryption_info(struct inode *);
extern void llcrypt_put_encryption_info(struct inode *);
extern void llcrypt_free_inode(struct inode *);
extern int llcrypt_drop_inode(struct inode *inode);

/* fname.c */
extern int llcrypt_setup_filename(struct inode *, const struct qstr *,
				int lookup, struct llcrypt_name *);

static inline void llcrypt_free_filename(struct llcrypt_name *fname)
{
	kfree(fname->crypto_buf.name);
}

extern int llcrypt_fname_alloc_buffer(const struct inode *, u32,
				struct llcrypt_str *);
extern void llcrypt_fname_free_buffer(struct llcrypt_str *);
extern int llcrypt_fname_disk_to_usr(struct inode *, u32, u32,
			const struct llcrypt_str *, struct llcrypt_str *);

#define LLCRYPT_FNAME_MAX_UNDIGESTED_SIZE	32

/* Extracts the second-to-last ciphertext block; see explanation below */
#define LLCRYPT_FNAME_DIGEST(name, len)	\
	((name) + round_down((len) - LL_CRYPTO_BLOCK_SIZE - 1, \
			     LL_CRYPTO_BLOCK_SIZE))

#define LLCRYPT_FNAME_DIGEST_SIZE	LL_CRYPTO_BLOCK_SIZE

/**
 * llcrypt_digested_name - alternate identifier for an on-disk filename
 *
 * When userspace lists an encrypted directory without access to the key,
 * filenames whose ciphertext is longer than LLCRYPT_FNAME_MAX_UNDIGESTED_SIZE
 * bytes are shown in this abbreviated form (base64-encoded) rather than as the
 * full ciphertext (base64-encoded).  This is necessary to allow supporting
 * filenames up to NAME_MAX bytes, since base64 encoding expands the length.
 *
 * To make it possible for filesystems to still find the correct directory entry
 * despite not knowing the full on-disk name, we encode any filesystem-specific
 * 'hash' and/or 'minor_hash' which the filesystem may need for its lookups,
 * followed by the second-to-last ciphertext block of the filename.  Due to the
 * use of the CBC-CTS encryption mode, the second-to-last ciphertext block
 * depends on the full plaintext.  (Note that ciphertext stealing causes the
 * last two blocks to appear "flipped".)  This makes accidental collisions very
 * unlikely: just a 1 in 2^128 chance for two filenames to collide even if they
 * share the same filesystem-specific hashes.
 *
 * However, this scheme isn't immune to intentional collisions, which can be
 * created by anyone able to create arbitrary plaintext filenames and view them
 * without the key.  Making the "digest" be a real cryptographic hash like
 * SHA-256 over the full ciphertext would prevent this, although it would be
 * less efficient and harder to implement, especially since the filesystem would
 * need to calculate it for each directory entry examined during a search.
 */
struct llcrypt_digested_name {
	u32 hash;
	u32 minor_hash;
	u8 digest[LLCRYPT_FNAME_DIGEST_SIZE];
};

/**
 * llcrypt_match_name() - test whether the given name matches a directory entry
 * @fname: the name being searched for
 * @de_name: the name from the directory entry
 * @de_name_len: the length of @de_name in bytes
 *
 * Normally @fname->disk_name will be set, and in that case we simply compare
 * that to the name stored in the directory entry.  The only exception is that
 * if we don't have the key for an encrypted directory and a filename in it is
 * very long, then we won't have the full disk_name and we'll instead need to
 * match against the llcrypt_digested_name.
 *
 * Return: %true if the name matches, otherwise %false.
 */
static inline bool llcrypt_match_name(const struct llcrypt_name *fname,
				      const u8 *de_name, u32 de_name_len)
{
	if (unlikely(!fname->disk_name.name)) {
		const struct llcrypt_digested_name *n =
			(const void *)fname->crypto_buf.name;
		if (WARN_ON_ONCE(fname->usr_fname->name[0] != '_'))
			return false;
		if (de_name_len <= LLCRYPT_FNAME_MAX_UNDIGESTED_SIZE)
			return false;
		return !memcmp(LLCRYPT_FNAME_DIGEST(de_name, de_name_len),
			       n->digest, LLCRYPT_FNAME_DIGEST_SIZE);
	}

	if (de_name_len != fname->disk_name.len)
		return false;
	return !memcmp(de_name, fname->disk_name.name, fname->disk_name.len);
}

/* hooks.c */
extern int llcrypt_file_open(struct inode *inode, struct file *filp);
extern int __llcrypt_prepare_link(struct inode *inode, struct inode *dir,
				  struct dentry *dentry);
extern int __llcrypt_prepare_rename(struct inode *old_dir,
				    struct dentry *old_dentry,
				    struct inode *new_dir,
				    struct dentry *new_dentry,
				    unsigned int flags);
extern int __llcrypt_prepare_lookup(struct inode *dir, struct dentry *dentry,
				    struct llcrypt_name *fname);
extern int __llcrypt_prepare_symlink(struct inode *dir, unsigned int len,
				     unsigned int max_len,
				     struct llcrypt_str *disk_link);
extern int __llcrypt_encrypt_symlink(struct inode *inode, const char *target,
				     unsigned int len,
				     struct llcrypt_str *disk_link);
extern const char *llcrypt_get_symlink(struct inode *inode, const void *caddr,
				       unsigned int max_size,
				       struct delayed_call *done);
static inline void llcrypt_set_ops(struct super_block *sb,
				   const struct llcrypt_operations *lsi_cop)
{
	struct lustre_sb_info *lsi = s2lsi(sb);

	if (lsi)
		lsi->lsi_cop = lsi_cop;
}
#else  /* !CONFIG_LL_ENCRYPTION */

struct llcrypt_operations;
#define llcrypt_init()         0
#define llcrypt_exit()         {}

#undef IS_ENCRYPTED
#define IS_ENCRYPTED(x)        0

static inline bool llcrypt_has_encryption_key(const struct inode *inode)
{
	return false;
}

static inline bool llcrypt_dummy_context_enabled(struct inode *inode)
{
	return false;
}

static inline void llcrypt_handle_d_move(struct dentry *dentry)
{
}

/* crypto.c */
static inline void llcrypt_enqueue_decrypt_work(struct work_struct *work)
{
}

static inline struct llcrypt_ctx *llcrypt_get_ctx(gfp_t gfp_flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void llcrypt_release_ctx(struct llcrypt_ctx *ctx)
{
	return;
}

static inline struct page *llcrypt_encrypt_pagecache_blocks(struct page *page,
							    unsigned int len,
							    unsigned int offs,
							    gfp_t gfp_flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int llcrypt_encrypt_block(const struct inode *inode,
					struct page *src, struct page *dst,
					unsigned int len, unsigned int offs,
					u64 lblk_num, gfp_t gfp_flags)
{
	return -EOPNOTSUPP;
}

static inline int llcrypt_decrypt_pagecache_blocks(struct page *page,
						   unsigned int len,
						   unsigned int offs)
{
	return -EOPNOTSUPP;
}

static inline int llcrypt_decrypt_block(const struct inode *inode,
					struct page *src, struct page *dst,
					unsigned int len, unsigned int offs,
					u64 lblk_num, gfp_t gfp_flags)
{
	return -EOPNOTSUPP;
}

static inline int llcrypt_decrypt_block_inplace(const struct inode *inode,
						struct page *page,
						unsigned int len,
						unsigned int offs, u64 lblk_num)
{
	return -EOPNOTSUPP;
}

static inline bool llcrypt_is_bounce_page(struct page *page)
{
	return false;
}

static inline struct page *llcrypt_pagecache_page(struct page *bounce_page)
{
	WARN_ON_ONCE(1);
	return ERR_PTR(-EINVAL);
}

static inline void llcrypt_free_bounce_page(struct page *bounce_page)
{
}

/* policy.c */
static inline int llcrypt_ioctl_set_policy(struct file *filp,
					   const void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int llcrypt_ioctl_get_policy(struct file *filp, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int llcrypt_ioctl_get_policy_ex(struct file *filp,
					      void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int llcrypt_has_permitted_context(struct inode *parent,
						struct inode *child)
{
	return 0;
}

static inline int llcrypt_inherit_context(struct inode *parent,
					  struct inode *child,
					  void *fs_data, bool preload)
{
	return -EOPNOTSUPP;
}
static inline bool llcrypt_policy_has_filename_enc(struct inode *inode)
{
	return false;
}

/* keyring.c */
static inline void llcrypt_sb_free(struct super_block *sb)
{
}

static inline int llcrypt_ioctl_add_key(struct file *filp, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int llcrypt_ioctl_remove_key(struct file *filp, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int llcrypt_ioctl_remove_key_all_users(struct file *filp,
						     void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int llcrypt_ioctl_get_key_status(struct file *filp,
					       void __user *arg)
{
	return -EOPNOTSUPP;
}

/* keysetup.c */
static inline int llcrypt_get_encryption_info(struct inode *inode)
{
	return -EOPNOTSUPP;
}

static inline void llcrypt_put_encryption_info(struct inode *inode)
{
	return;
}

static inline void llcrypt_free_inode(struct inode *inode)
{
}

static inline int llcrypt_drop_inode(struct inode *inode)
{
	return 0;
}

 /* fname.c */
static inline int llcrypt_setup_filename(struct inode *dir,
					 const struct qstr *iname,
					 int lookup, struct llcrypt_name *fname)
{
	if (IS_ENCRYPTED(dir))
		return -EOPNOTSUPP;

	memset(fname, 0, sizeof(*fname));
	fname->usr_fname = iname;
	fname->disk_name.name = (unsigned char *)iname->name;
	fname->disk_name.len = iname->len;
	return 0;
}

static inline void llcrypt_free_filename(struct llcrypt_name *fname)
{
	return;
}

static inline int llcrypt_fname_alloc_buffer(const struct inode *inode,
					     u32 max_encrypted_len,
					     struct llcrypt_str *crypto_str)
{
	return -EOPNOTSUPP;
}

static inline void llcrypt_fname_free_buffer(struct llcrypt_str *crypto_str)
{
	return;
}

static inline int llcrypt_fname_disk_to_usr(struct inode *inode,
					    u32 hash, u32 minor_hash,
					    const struct llcrypt_str *iname,
					    struct llcrypt_str *oname)
{
	return -EOPNOTSUPP;
}

static inline bool llcrypt_match_name(const struct llcrypt_name *fname,
				      const u8 *de_name, u32 de_name_len)
{
	/* Encryption support disabled; use standard comparison */
	if (de_name_len != fname->disk_name.len)
		return false;
	return !memcmp(de_name, fname->disk_name.name, fname->disk_name.len);
}

/* hooks.c */

static inline int llcrypt_file_open(struct inode *inode, struct file *filp)
{
	if (IS_ENCRYPTED(inode))
		return -EOPNOTSUPP;
	return 0;
}

static inline int __llcrypt_prepare_link(struct inode *inode, struct inode *dir,
					 struct dentry *dentry)
{
	return -EOPNOTSUPP;
}

static inline int __llcrypt_prepare_rename(struct inode *old_dir,
					   struct dentry *old_dentry,
					   struct inode *new_dir,
					   struct dentry *new_dentry,
					   unsigned int flags)
{
	return -EOPNOTSUPP;
}

static inline int __llcrypt_prepare_lookup(struct inode *dir,
					   struct dentry *dentry,
					   struct llcrypt_name *fname)
{
	return -EOPNOTSUPP;
}

static inline int __llcrypt_prepare_symlink(struct inode *dir,
					    unsigned int len,
					    unsigned int max_len,
					    struct llcrypt_str *disk_link)
{
	return -EOPNOTSUPP;
}


static inline int __llcrypt_encrypt_symlink(struct inode *inode,
					    const char *target,
					    unsigned int len,
					    struct llcrypt_str *disk_link)
{
	return -EOPNOTSUPP;
}

#define llcrypt_get_symlink(inode, caddr, max_size, done)   ERR_PTR(-EOPNOTSUPP)

static inline void llcrypt_set_ops(struct super_block *sb,
				   const struct llcrypt_operations *lsi_cop)
{
}

#endif	/* !CONFIG_LL_ENCRYPTION */

/**
 * llcrypt_require_key - require an inode's encryption key
 * @inode: the inode we need the key for
 *
 * If the inode is encrypted, set up its encryption key if not already done.
 * Then require that the key be present and return -ENOKEY otherwise.
 *
 * No locks are needed, and the key will live as long as the struct inode --- so
 * it won't go away from under you.
 *
 * Return: 0 on success, -ENOKEY if the key is missing, or another -errno code
 * if a problem occurred while setting up the encryption key.
 */
static inline int llcrypt_require_key(struct inode *inode)
{
	if (IS_ENCRYPTED(inode)) {
		int err = llcrypt_get_encryption_info(inode);

		if (err)
			return err;
		if (!llcrypt_has_encryption_key(inode))
			return -ENOKEY;
	}
	return 0;
}

/**
 * llcrypt_prepare_link - prepare to link an inode into a possibly-encrypted directory
 * @old_dentry: an existing dentry for the inode being linked
 * @dir: the target directory
 * @dentry: negative dentry for the target filename
 *
 * A new link can only be added to an encrypted directory if the directory's
 * encryption key is available --- since otherwise we'd have no way to encrypt
 * the filename.  Therefore, we first set up the directory's encryption key (if
 * not already done) and return an error if it's unavailable.
 *
 * We also verify that the link will not violate the constraint that all files
 * in an encrypted directory tree use the same encryption policy.
 *
 * Return: 0 on success, -ENOKEY if the directory's encryption key is missing,
 * -EXDEV if the link would result in an inconsistent encryption policy, or
 * another -errno code.
 */
static inline int llcrypt_prepare_link(struct dentry *old_dentry,
				       struct inode *dir,
				       struct dentry *dentry)
{
	if (IS_ENCRYPTED(dir))
		return __llcrypt_prepare_link(d_inode(old_dentry), dir, dentry);
	return 0;
}

/**
 * llcrypt_prepare_rename - prepare for a rename between possibly-encrypted directories
 * @old_dir: source directory
 * @old_dentry: dentry for source file
 * @new_dir: target directory
 * @new_dentry: dentry for target location (may be negative unless exchanging)
 * @flags: rename flags (we care at least about %RENAME_EXCHANGE)
 *
 * Prepare for ->rename() where the source and/or target directories may be
 * encrypted.  A new link can only be added to an encrypted directory if the
 * directory's encryption key is available --- since otherwise we'd have no way
 * to encrypt the filename.  A rename to an existing name, on the other hand,
 * *is* cryptographically possible without the key.  However, we take the more
 * conservative approach and just forbid all no-key renames.
 *
 * We also verify that the rename will not violate the constraint that all files
 * in an encrypted directory tree use the same encryption policy.
 *
 * Return: 0 on success, -ENOKEY if an encryption key is missing, -EXDEV if the
 * rename would cause inconsistent encryption policies, or another -errno code.
 */
static inline int llcrypt_prepare_rename(struct inode *old_dir,
					 struct dentry *old_dentry,
					 struct inode *new_dir,
					 struct dentry *new_dentry,
					 unsigned int flags)
{
	if (IS_ENCRYPTED(old_dir) || IS_ENCRYPTED(new_dir))
		return __llcrypt_prepare_rename(old_dir, old_dentry,
						new_dir, new_dentry, flags);
	return 0;
}

/**
 * llcrypt_prepare_lookup - prepare to lookup a name in a possibly-encrypted directory
 * @dir: directory being searched
 * @dentry: filename being looked up
 * @fname: (output) the name to use to search the on-disk directory
 *
 * Prepare for ->lookup() in a directory which may be encrypted by determining
 * the name that will actually be used to search the directory on-disk.  Lookups
 * can be done with or without the directory's encryption key; without the key,
 * filenames are presented in encrypted form.  Therefore, we'll try to set up
 * the directory's encryption key, but even without it the lookup can continue.
 *
 * This also installs a custom ->d_revalidate() method which will invalidate the
 * dentry if it was created without the key and the key is later added.
 *
 * Return: 0 on success; -ENOENT if key is unavailable but the filename isn't a
 * correctly formed encoded ciphertext name, so a negative dentry should be
 * created; or another -errno code.
 */
static inline int llcrypt_prepare_lookup(struct inode *dir,
					 struct dentry *dentry,
					 struct llcrypt_name *fname)
{
	if (IS_ENCRYPTED(dir))
		return __llcrypt_prepare_lookup(dir, dentry, fname);

	memset(fname, 0, sizeof(*fname));
	fname->usr_fname = &dentry->d_name;
	fname->disk_name.name = (unsigned char *)dentry->d_name.name;
	fname->disk_name.len = dentry->d_name.len;
	return 0;
}

/**
 * llcrypt_prepare_setattr - prepare to change a possibly-encrypted inode's attributes
 * @dentry: dentry through which the inode is being changed
 * @attr: attributes to change
 *
 * Prepare for ->setattr() on a possibly-encrypted inode.  On an encrypted file,
 * most attribute changes are allowed even without the encryption key.  However,
 * without the encryption key we do have to forbid truncates.  This is needed
 * because the size being truncated to may not be a multiple of the filesystem
 * block size, and in that case we'd have to decrypt the final block, zero the
 * portion past i_size, and re-encrypt it.  (We *could* allow truncating to a
 * filesystem block boundary, but it's simpler to just forbid all truncates ---
 * and we already forbid all other contents modifications without the key.)
 *
 * Return: 0 on success, -ENOKEY if the key is missing, or another -errno code
 * if a problem occurred while setting up the encryption key.
 */
static inline int llcrypt_prepare_setattr(struct dentry *dentry,
					  struct iattr *attr)
{
	if (attr->ia_valid & ATTR_SIZE)
		return llcrypt_require_key(d_inode(dentry));
	return 0;
}

/**
 * llcrypt_prepare_symlink - prepare to create a possibly-encrypted symlink
 * @dir: directory in which the symlink is being created
 * @target: plaintext symlink target
 * @len: length of @target excluding null terminator
 * @max_len: space the filesystem has available to store the symlink target
 * @disk_link: (out) the on-disk symlink target being prepared
 *
 * This function computes the size the symlink target will require on-disk,
 * stores it in @disk_link->len, and validates it against @max_len.  An
 * encrypted symlink may be longer than the original.
 *
 * Additionally, @disk_link->name is set to @target if the symlink will be
 * unencrypted, but left NULL if the symlink will be encrypted.  For encrypted
 * symlinks, the filesystem must call llcrypt_encrypt_symlink() to create the
 * on-disk target later.  (The reason for the two-step process is that some
 * filesystems need to know the size of the symlink target before creating the
 * inode, e.g. to determine whether it will be a "fast" or "slow" symlink.)
 *
 * Return: 0 on success, -ENAMETOOLONG if the symlink target is too long,
 * -ENOKEY if the encryption key is missing, or another -errno code if a problem
 * occurred while setting up the encryption key.
 */
static inline int llcrypt_prepare_symlink(struct inode *dir,
					  const char *target,
					  unsigned int len,
					  unsigned int max_len,
					  struct llcrypt_str *disk_link)
{
	if ((IS_ENCRYPTED(dir) || llcrypt_dummy_context_enabled(dir)) &&
	    llcrypt_policy_has_filename_enc(dir))
		return __llcrypt_prepare_symlink(dir, len, max_len, disk_link);

	disk_link->name = (unsigned char *)target;
	disk_link->len = len + 1;
	if (disk_link->len > max_len)
		return -ENAMETOOLONG;
	return 0;
}

/**
 * llcrypt_encrypt_symlink - encrypt the symlink target if needed
 * @inode: symlink inode
 * @target: plaintext symlink target
 * @len: length of @target excluding null terminator
 * @disk_link: (in/out) the on-disk symlink target being prepared
 *
 * If the symlink target needs to be encrypted, then this function encrypts it
 * into @disk_link->name.  llcrypt_prepare_symlink() must have been called
 * previously to compute @disk_link->len.  If the filesystem did not allocate a
 * buffer for @disk_link->name after calling llcrypt_prepare_link(), then one
 * will be kmalloc()'ed and the filesystem will be responsible for freeing it.
 *
 * Return: 0 on success, -errno on failure
 */
static inline int llcrypt_encrypt_symlink(struct inode *inode,
					  const char *target,
					  unsigned int len,
					  struct llcrypt_str *disk_link)
{
	if (IS_ENCRYPTED(inode))
		return __llcrypt_encrypt_symlink(inode, target, len, disk_link);
	return 0;
}

/* If *pagep is a bounce page, free it and set *pagep to the pagecache page */
static inline void llcrypt_finalize_bounce_page(struct page **pagep)
{
	struct page *page = *pagep;

	if (llcrypt_is_bounce_page(page)) {
		*pagep = llcrypt_pagecache_page(page);
		llcrypt_free_bounce_page(page);
	}
}

#endif	/* _LINUX_LLCRYPT_H */
