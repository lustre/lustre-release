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
	struct dentry *dentry;
	int rc;

	if (hlist_empty(&inode->i_dentry))
		return -ENODATA;

	hlist_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		break;
	}

	rc = ll_vfs_getxattr(dentry, inode, LL_XATTR_NAME_ENCRYPTION_CONTEXT,
			     ctx, len);

	return rc;
}

static int ll_set_context(struct inode *inode, const void *ctx, size_t len,
			  void *fs_data)
{
	unsigned int ext_flags;
	struct dentry *dentry;
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	int rc;

	if (inode == NULL)
		return 0;

	ext_flags = ll_inode_to_ext_flags(inode->i_flags) | LUSTRE_ENCRYPT_FL;
	dentry = (struct dentry *)fs_data;

	/* Encrypting the root directory is not allowed */
	if (inode->i_ino == inode->i_sb->s_root->d_inode->i_ino)
		return -EPERM;

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	op_data->op_attr_flags = LUSTRE_ENCRYPT_FL;
	op_data->op_xvalid |= OP_XVALID_FLAGS;
	rc = md_setattr(ll_i2sbi(inode)->ll_md_exp, op_data, NULL, 0, &req);
	ll_finish_md_op_data(op_data);
	ptlrpc_req_finished(req);
	if (rc)
		return rc;

	rc = ll_vfs_setxattr(dentry, inode, LL_XATTR_NAME_ENCRYPTION_CONTEXT,
			     ctx, len, XATTR_CREATE);
	if (rc)
		return rc;

	/* used as encryption unit size */
	if (S_ISREG(inode->i_mode))
		inode->i_blkbits = LUSTRE_ENCRYPTION_BLOCKBITS;
	ll_update_inode_flags(inode, ext_flags);
	return 0;
}

inline bool ll_sbi_has_test_dummy_encryption(struct ll_sb_info *sbi)
{
	return unlikely(sbi->ll_flags & LL_SBI_TEST_DUMMY_ENCRYPTION);
}

static bool ll_dummy_context(struct inode *inode)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	return sbi ? ll_sbi_has_test_dummy_encryption(sbi) : false;
}

inline bool ll_sbi_has_encrypt(struct ll_sb_info *sbi)
{
	return sbi->ll_flags & LL_SBI_ENCRYPT;
}

inline void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set)
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
inline bool ll_sbi_has_test_dummy_encryption(struct ll_sb_info *sbi)
{
	return false;
}

inline bool ll_sbi_has_encrypt(struct ll_sb_info *sbi)
{
	return false;
}

inline void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set)
{
}
#endif

