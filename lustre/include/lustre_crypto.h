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
 * Copyright (c) 2019, 2020, Whamcloud.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LUSTRE_CRYPTO_H_
#define _LUSTRE_CRYPTO_H_

#if defined(HAVE_LUSTRE_CRYPTO) && !defined(CONFIG_LL_ENCRYPTION)
#define __FS_HAS_ENCRYPTION 1
#include <linux/fscrypt.h>

#define LL_CRYPTO_BLOCK_SIZE		FS_CRYPTO_BLOCK_SIZE
#define llcrypt_name			fscrypt_name
#define llcrypt_str			fscrypt_str
#define LLTR_INIT			FSTR_INIT
#define llcrypt_operations		fscrypt_operations
#define llcrypt_symlink_data		fscrypt_symlink_data
#define llcrypt_init()			0
#define llcrypt_exit()			{}
#ifndef HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED
#define llcrypt_context			fscrypt_context
#define llcrypt_dummy_context		fscrypt_dummy_context
#endif
#define llcrypt_require_key(inode)     \
	fscrypt_require_key(inode)
#define llcrypt_has_encryption_key(inode) fscrypt_has_encryption_key(inode)
#define llcrypt_encrypt_pagecache_blocks(page, len, offs, gfp_flags)	\
	fscrypt_encrypt_pagecache_blocks(page, len, offs, gfp_flags)
#define llcrypt_decrypt_pagecache_blocks(page, len, offs)	\
	fscrypt_decrypt_pagecache_blocks(page, len, offs)
#define llcrypt_decrypt_block_inplace(inode, page, len, offs, lblk_num)	\
	fscrypt_decrypt_block_inplace(inode, page, len, offs, lblk_num)
#define llcrypt_inherit_context(parent, child, fs_data, preload)	\
	fscrypt_inherit_context(parent, child, fs_data, preload)
#define llcrypt_get_encryption_info(inode) fscrypt_get_encryption_info(inode)
#define llcrypt_put_encryption_info(inode) fscrypt_put_encryption_info(inode)
#define llcrypt_free_inode(inode)	   fscrypt_free_inode(inode)
#define llcrypt_finalize_bounce_page(pagep)  fscrypt_finalize_bounce_page(pagep)
#define llcrypt_file_open(inode, filp)	fscrypt_file_open(inode, filp)
#define llcrypt_ioctl_set_policy(filp, arg)  fscrypt_ioctl_set_policy(filp, arg)
#define llcrypt_ioctl_get_policy_ex(filp, arg)	\
	fscrypt_ioctl_get_policy_ex(filp, arg)
#define llcrypt_policy_has_filename_enc(inode) true
#define llcrypt_ioctl_add_key(filp, arg)	fscrypt_ioctl_add_key(filp, arg)
#define llcrypt_ioctl_remove_key(filp, arg)  fscrypt_ioctl_remove_key(filp, arg)
#define llcrypt_ioctl_remove_key_all_users(filp, arg)	\
	fscrypt_ioctl_remove_key_all_users(filp, arg)
#define llcrypt_ioctl_get_key_status(filp, arg)	\
	fscrypt_ioctl_get_key_status(filp, arg)
#define llcrypt_drop_inode(inode)	fscrypt_drop_inode(inode)
#define llcrypt_prepare_rename(olddir, olddentry, newdir, newdentry, flags) \
	fscrypt_prepare_rename(olddir, olddentry, newdir, newdentry, flags)
#define llcrypt_prepare_link(old_dentry, dir, dentry)	\
	fscrypt_prepare_link(old_dentry, dir, dentry)
#define llcrypt_prepare_setattr(dentry, attr)		\
	fscrypt_prepare_setattr(dentry, attr)
#define __llcrypt_prepare_lookup(inode, dentry, fname)	\
	__fscrypt_prepare_lookup(inode, dentry, fname)
#define llcrypt_set_ops(sb, cop)	fscrypt_set_ops(sb, cop)
#define llcrypt_sb_free(sb)		{}
#define llcrypt_fname_alloc_buffer(inode, max_encrypted_len, crypto_str) \
	fscrypt_fname_alloc_buffer(inode, max_encrypted_len, crypto_str)
#define llcrypt_fname_disk_to_usr(inode, hash, minor_hash, iname, oname) \
	fscrypt_fname_disk_to_usr(inode, hash, minor_hash, iname, oname)
#define llcrypt_fname_free_buffer(crypto_str) \
	fscrypt_fname_free_buffer(crypto_str)
#define llcrypt_setup_filename(dir, iname, lookup, fname) \
	fscrypt_setup_filename(dir, iname, lookup, fname)
#define llcrypt_free_filename(fname) \
	fscrypt_free_filename(fname)
#define llcrypt_match_name(fname, de_name, name_len)		\
	fscrypt_match_name(fname, de_name, name_len)
#define llcrypt_prepare_lookup(dir, dentry, fname) \
	fscrypt_prepare_lookup(dir, dentry, fname)
#define llcrypt_encrypt_symlink(inode, target, len, disk_link) \
	fscrypt_encrypt_symlink(inode, target, len, disk_link)
#define __llcrypt_encrypt_symlink(inode, target, len, disk_link) \
	__fscrypt_encrypt_symlink(inode, target, len, disk_link)
#define llcrypt_prepare_symlink(dir, target, len, max_len, disk_link)	\
	fscrypt_prepare_symlink(dir, target, len, max_len, disk_link)
#define llcrypt_get_symlink(inode, caddr, max_size, done) \
	fscrypt_get_symlink(inode, caddr, max_size, done)

#define LL_IOC_SET_ENCRYPTION_POLICY FS_IOC_SET_ENCRYPTION_POLICY
#define LL_IOC_GET_ENCRYPTION_POLICY_EX FS_IOC_GET_ENCRYPTION_POLICY_EX
#define LL_IOC_ADD_ENCRYPTION_KEY FS_IOC_ADD_ENCRYPTION_KEY
#define LL_IOC_REMOVE_ENCRYPTION_KEY FS_IOC_REMOVE_ENCRYPTION_KEY
#define LL_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS \
	FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS
#define LL_IOC_GET_ENCRYPTION_KEY_STATUS FS_IOC_GET_ENCRYPTION_KEY_STATUS

#else /* HAVE_LUSTRE_CRYPTO && !CONFIG_LL_ENCRYPTION */
#include <libcfs/crypto/llcrypt.h>
#endif /* !HAVE_LUSTRE_CRYPTO || CONFIG_LL_ENCRYPTION */

#ifndef DCACHE_NOKEY_NAME
#define DCACHE_NOKEY_NAME               0x02000000 /* Enc name without key */
#endif

#if !defined(HAVE_FSCRYPT_IS_NOKEY_NAME) || defined(CONFIG_LL_ENCRYPTION)

static inline bool llcrypt_is_nokey_name(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_NOKEY_NAME;
}
#else
#define llcrypt_is_nokey_name(dentry)		\
	fscrypt_is_nokey_name(dentry)
#endif

#if defined(HAVE_LUSTRE_CRYPTO) && !defined(HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED)
#define llcrypt_show_test_dummy_encryption(seq, sep, sb)	\
	fscrypt_show_test_dummy_encryption(seq, sep, sb)
#define llcrypt_set_test_dummy_encryption(sb, arg, ctx)		\
	fscrypt_set_test_dummy_encryption(sb, arg, ctx)
#define llcrypt_free_dummy_context(ctx)				\
	fscrypt_free_dummy_context(ctx)
#else
#define llcrypt_show_test_dummy_encryption(seq, sep, sb)	{}
#define llcrypt_free_dummy_context(ctx)				{}
#endif

/* Macro to extract digest from Lustre specific structures */
#if defined(HAVE_FSCRYPT_DIGESTED_NAME) && !defined(CONFIG_LL_ENCRYPTION)
#define LLCRYPT_EXTRACT_DIGEST		FSCRYPT_FNAME_DIGEST
#else
#define LLCRYPT_EXTRACT_DIGEST(name, len)			\
	((name) + round_down((len) - LL_CRYPTO_BLOCK_SIZE - 1,	\
			     LL_CRYPTO_BLOCK_SIZE))
#endif

struct ll_sb_info;
int ll_set_encflags(struct inode *inode, void *encctx, __u32 encctxlen,
		    bool preload);
void llcrypt_free_ctx(void *encctx, __u32 size);
bool ll_sb_has_test_dummy_encryption(struct super_block *sb);
bool ll_sbi_has_encrypt(struct ll_sb_info *sbi);
void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set);
bool ll_sbi_has_name_encrypt(struct ll_sb_info *sbi);
void ll_sbi_set_name_encrypt(struct ll_sb_info *sbi, bool set);
/* sizeof(struct fscrypt_context_v2) = 40 */
#define LLCRYPT_ENC_CTX_SIZE 40

/* Encoding/decoding routines inspired from yEnc principles.
 * We just take care of a few critical characters:
 * NULL, LF, CR, /, DEL and =.
 * If such a char is found, it is replaced with '=' followed by
 * the char value + 64.
 * All other chars are left untouched.
 * Efficiency of this encoding depends on the occurences of the
 * critical chars, but statistically on binary data it can be much higher
 * than base64 for instance.
 */
static inline int critical_encode(const u8 *src, int len, char *dst)
{
	u8 *p = (u8 *)src, *q = dst;

	while (p - src < len) {
		/* escape NULL, LF, CR, /, DEL and = */
		if (unlikely(*p == 0x0 || *p == 0xA || *p == 0xD ||
			     *p == '/' || *p == 0x7F || *p == '=')) {
			*(q++) = '=';
			*(q++) = *(p++) + 64;
		} else {
			*(q++) = *(p++);
		}
	}

	return (char *)q - dst;
}

/* returns the number of chars encoding would produce */
static inline int critical_chars(const u8 *src, int len)
{
	u8 *p = (u8 *)src;
	int newlen = len;

	while (p - src < len) {
		/* NULL, LF, CR, /, DEL and = cost an additional '=' */
		if (unlikely(*p == 0x0 || *p == 0xA || *p == 0xD ||
			     *p == '/' || *p == 0x7F || *p == '='))
			newlen++;
		p++;
	}

	return newlen;
}

/* decoding routine - returns the number of chars in output */
static inline int critical_decode(const u8 *src, int len, char *dst)
{
	u8 *p = (u8 *)src, *q = dst;

	while (p - src < len) {
		if (unlikely(*p == '=')) {
			*(q++) = *(++p) - 64;
			p++;
		} else {
			*(q++) = *(p++);
		}
	}

	return (char *)q - dst;
}

#endif /* _LUSTRE_CRYPTO_H_ */
