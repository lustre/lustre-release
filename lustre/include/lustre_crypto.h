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

struct ll_sb_info;
int ll_set_encflags(struct inode *inode, void *encctx, __u32 encctxlen,
		    bool preload);
void llcrypt_free_ctx(void *encctx, __u32 size);
bool ll_sbi_has_test_dummy_encryption(struct ll_sb_info *sbi);
bool ll_sbi_has_encrypt(struct ll_sb_info *sbi);
void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set);

#ifdef CONFIG_LL_ENCRYPTION
#include <libcfs/crypto/llcrypt.h>
#else /* !CONFIG_LL_ENCRYPTION */
#ifdef HAVE_LUSTRE_CRYPTO
#define __FS_HAS_ENCRYPTION 1
#include <linux/fscrypt.h>

#define llcrypt_operations	fscrypt_operations
#define llcrypt_symlink_data	fscrypt_symlink_data
#define llcrypt_dummy_context_enabled(inode) \
	fscrypt_dummy_context_enabled(inode)
#define llcrypt_has_encryption_key(inode) fscrypt_has_encryption_key(inode)
#define llcrypt_encrypt_pagecache_blocks(page, len, offs, gfp_flags)	\
	fscrypt_encrypt_pagecache_blocks(page, len, offs, gfp_flags)
#define llcrypt_decrypt_pagecache_blocks(page, len, offs)	\
	fscrypt_decrypt_pagecache_blocks(page, len, offs)
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
#define llcrypt_set_ops(sb, cop)	fscrypt_set_ops(sb, cop)
#else /* !HAVE_LUSTRE_CRYPTO */
#undef IS_ENCRYPTED
#define IS_ENCRYPTED(x)	0
#define llcrypt_dummy_context_enabled(inode)	NULL
/* copied from include/linux/fscrypt.h */
#define llcrypt_has_encryption_key(inode) false
#define llcrypt_encrypt_pagecache_blocks(page, len, offs, gfp_flags)	\
	ERR_PTR(-EOPNOTSUPP)
#define llcrypt_decrypt_pagecache_blocks(page, len, offs)	-EOPNOTSUPP
#define llcrypt_inherit_context(parent, child, fs_data, preload)     -EOPNOTSUPP
#define llcrypt_get_encryption_info(inode)			-EOPNOTSUPP
#define llcrypt_put_encryption_info(inode)			do {} while (0)
#define llcrypt_free_inode(inode)				do {} while (0)
#define llcrypt_finalize_bounce_page(pagep)			do {} while (0)
static inline int llcrypt_file_open(struct inode *inode, struct file *filp)
{
	return IS_ENCRYPTED(inode) ? -EOPNOTSUPP : 0;
}
#define llcrypt_ioctl_set_policy(filp, arg)			-EOPNOTSUPP
#define llcrypt_ioctl_get_policy_ex(filp, arg)			-EOPNOTSUPP
#define llcrypt_ioctl_add_key(filp, arg)			-EOPNOTSUPP
#define llcrypt_ioctl_remove_key(filp, arg)			-EOPNOTSUPP
#define llcrypt_ioctl_remove_key_all_users(filp, arg)		-EOPNOTSUPP
#define llcrypt_ioctl_get_key_status(filp, arg)			-EOPNOTSUPP
#define llcrypt_drop_inode(inode)				 0
#define llcrypt_prepare_rename(olddir, olddentry, newdir, newdentry, flags)    0
#define llcrypt_prepare_link(old_dentry, dir, dentry)		 0
#define llcrypt_prepare_setattr(dentry, attr)			 0
#define llcrypt_set_ops(sb, cop)				do {} while (0)
#endif /* HAVE_LUSTRE_CRYPTO */
#endif /* !CONFIG_LL_ENCRYPTION */

#endif /* _LUSTRE_CRYPTO_H_ */
