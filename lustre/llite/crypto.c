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

#include "llite_internal.h"

#ifdef HAVE_LUSTRE_CRYPTO

static int ll_get_context(struct inode *inode, void *ctx, size_t len)
{
	struct dentry *dentry = d_find_any_alias(inode);
	int rc;

	rc = ll_vfs_getxattr(dentry, inode, LL_XATTR_NAME_ENCRYPTION_CONTEXT,
			     ctx, len);
	if (dentry)
		dput(dentry);

	/* used as encryption unit size */
	if (S_ISREG(inode->i_mode))
		inode->i_blkbits = LUSTRE_ENCRYPTION_BLOCKBITS;
	return rc;
}

int ll_set_encflags(struct inode *inode, void *encctx, __u32 encctxlen,
		    bool preload)
{
	unsigned int ext_flags;
	int rc = 0;

	/* used as encryption unit size */
	if (S_ISREG(inode->i_mode))
		inode->i_blkbits = LUSTRE_ENCRYPTION_BLOCKBITS;
	ext_flags = ll_inode_to_ext_flags(inode->i_flags) | LUSTRE_ENCRYPT_FL;
	ll_update_inode_flags(inode, ext_flags);

	if (encctx && encctxlen)
		rc = ll_xattr_cache_insert(inode,
					   LL_XATTR_NAME_ENCRYPTION_CONTEXT,
					   encctx, encctxlen);
	if (rc)
		return rc;

	return preload ? llcrypt_get_encryption_info(inode) : 0;
}

/* ll_set_context has 2 distinct behaviors, depending on the value of inode
 * parameter:
 * - inode is NULL:
 *   passed fs_data is a struct md_op_data *. We need to store enc ctx in
 *   op_data, so that it will be sent along to the server with the request that
 *   the caller is preparing, thus saving a setxattr request.
 * - inode is not NULL:
 *   normal case in which passed fs_data is a struct dentry *, letting proceed
 *   with setxattr operation.
 *   This use case should only be used when explicitly setting a new encryption
 *   policy on an existing, empty directory.
 */
static int ll_set_context(struct inode *inode, const void *ctx, size_t len,
			  void *fs_data)
{
	struct dentry *dentry;
	int rc;

	if (inode == NULL) {
		struct md_op_data *op_data = (struct md_op_data *)fs_data;

		if (!op_data)
			return -EINVAL;

		OBD_ALLOC(op_data->op_file_encctx, len);
		if (op_data->op_file_encctx == NULL)
			return -ENOMEM;
		op_data->op_file_encctx_size = len;
		memcpy(op_data->op_file_encctx, ctx, len);
		return 0;
	}

	/* Encrypting the root directory is not allowed */
	if (is_root_inode(inode))
		return -EPERM;

	dentry = (struct dentry *)fs_data;
	set_bit(LLIF_SET_ENC_CTX, &ll_i2info(inode)->lli_flags);
	rc = ll_vfs_setxattr(dentry, inode, LL_XATTR_NAME_ENCRYPTION_CONTEXT,
			     ctx, len, XATTR_CREATE);
	if (rc)
		return rc;

	return ll_set_encflags(inode, (void *)ctx, len, false);
}

void llcrypt_free_ctx(void *encctx, __u32 size)
{
	if (encctx)
		OBD_FREE(encctx, size);
}

bool ll_sbi_has_test_dummy_encryption(struct ll_sb_info *sbi)
{
	return unlikely(sbi->ll_flags & LL_SBI_TEST_DUMMY_ENCRYPTION);
}

static bool ll_dummy_context(struct inode *inode)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	return sbi ? ll_sbi_has_test_dummy_encryption(sbi) : false;
}

bool ll_sbi_has_encrypt(struct ll_sb_info *sbi)
{
	return sbi->ll_flags & LL_SBI_ENCRYPT;
}

void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set)
{
	if (set)
		sbi->ll_flags |= LL_SBI_ENCRYPT;
	else
		sbi->ll_flags &=
			~(LL_SBI_ENCRYPT | LL_SBI_TEST_DUMMY_ENCRYPTION);
}

static bool ll_empty_dir(struct inode *inode)
{
	/* used by llcrypt_ioctl_set_policy(), because a policy can only be set
	 * on an empty dir.
	 */
	/* Here we choose to return true, meaning we always call .set_context.
	 * Then we rely on server side, with mdd_fix_attr() that calls
	 * mdd_dir_is_empty() when setting encryption flag on directory.
	 */
	return true;
}

const struct llcrypt_operations lustre_cryptops = {
	.key_prefix		= "lustre:",
	.get_context		= ll_get_context,
	.set_context		= ll_set_context,
	.dummy_context		= ll_dummy_context,
	.empty_dir		= ll_empty_dir,
	.max_namelen		= NAME_MAX,
};
#else /* !HAVE_LUSTRE_CRYPTO */
int ll_set_encflags(struct inode *inode, void *encctx, __u32 encctxlen,
		    bool preload)
{
	return 0;
}

void llcrypt_free_ctx(void *encctx, __u32 size)
{
}

bool ll_sbi_has_test_dummy_encryption(struct ll_sb_info *sbi)
{
	return false;
}

bool ll_sbi_has_encrypt(struct ll_sb_info *sbi)
{
	return false;
}

void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set)
{
}
#endif

