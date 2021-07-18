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
#include <libcfs/libcfs_crypto.h>

static int ll_get_context(struct inode *inode, void *ctx, size_t len)
{
	int rc;

	/* Get enc context xattr directly instead of going through the VFS,
	 * as there is no xattr handler for "encryption.".
	 */
	rc = ll_xattr_list(inode, xattr_for_enc(inode),
			   XATTR_ENCRYPTION_T, ctx, len, OBD_MD_FLXATTR);

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
					   xattr_for_enc(inode),
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
 *   normal case, letting proceed with setxattr operation.
 *   This use case should only be used when explicitly setting a new encryption
 *   policy on an existing, empty directory.
 */
static int ll_set_context(struct inode *inode, const void *ctx, size_t len,
			  void *fs_data)
{
	struct ptlrpc_request *req = NULL;
	struct ll_sb_info *sbi;
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

	sbi = ll_i2sbi(inode);
	/* Send setxattr request to lower layers directly instead of going
	 * through the VFS, as there is no xattr handler for "encryption.".
	 */
	rc = md_setxattr(sbi->ll_md_exp, ll_inode2fid(inode),
			 OBD_MD_FLXATTR, xattr_for_enc(inode),
			 ctx, len, XATTR_CREATE, ll_i2suppgid(inode), &req);
	if (rc)
		return rc;
	ptlrpc_req_finished(req);

	return ll_set_encflags(inode, (void *)ctx, len, false);
}

/**
 * ll_file_open_encrypt() - overlay to llcrypt_file_open
 * @inode: the inode being opened
 * @filp: the struct file being set up
 *
 * This overlay function is necessary to handle encrypted file open without
 * the key. We allow this access pattern to applications that know what they
 * are doing, by using the specific flag O_FILE_ENC.
 * This flag is only compatible with O_DIRECT IOs, to make sure ciphertext
 * data is wiped from page cache once IOs are finished.
 */
int ll_file_open_encrypt(struct inode *inode, struct file *filp)
{
	int rc;

	rc = llcrypt_file_open(inode, filp);
	if (likely(rc != -ENOKEY))
		return rc;

	if (rc == -ENOKEY &&
	    (filp->f_flags & O_FILE_ENC) == O_FILE_ENC &&
	    filp->f_flags & O_DIRECT)
		/* allow file open with O_FILE_ENC flag when we have O_DIRECT */
		rc = 0;

	return rc;
}

void llcrypt_free_ctx(void *encctx, __u32 size)
{
	if (encctx)
		OBD_FREE(encctx, size);
}

#ifdef HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED
bool ll_sb_has_test_dummy_encryption(struct super_block *sb)
{
	struct ll_sb_info *sbi = s2lsi(sb)->lsi_llsbi;

	return sbi ?
	       unlikely(test_bit(LL_SBI_TEST_DUMMY_ENCRYPTION, sbi->ll_flags)) :
	       false;
}

static bool ll_dummy_context(struct inode *inode)
{
	return ll_sb_has_test_dummy_encryption(inode->i_sb);
}
#else
static const union llcrypt_context *
ll_get_dummy_context(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);

	return lsi ? lsi->lsi_dummy_enc_ctx.ctx : NULL;
}

bool ll_sb_has_test_dummy_encryption(struct super_block *sb)
{
	return ll_get_dummy_context(sb) != NULL;
}
#endif

bool ll_sbi_has_encrypt(struct ll_sb_info *sbi)
{
	return test_bit(LL_SBI_ENCRYPT, sbi->ll_flags);
}

void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set)
{
	if (set) {
		set_bit(LL_SBI_ENCRYPT, sbi->ll_flags);
	} else {
		clear_bit(LL_SBI_ENCRYPT, sbi->ll_flags);
		clear_bit(LL_SBI_TEST_DUMMY_ENCRYPTION, sbi->ll_flags);
	}
}

bool ll_sbi_has_name_encrypt(struct ll_sb_info *sbi)
{
	return test_bit(LL_SBI_ENCRYPT_NAME, sbi->ll_flags);
}

void ll_sbi_set_name_encrypt(struct ll_sb_info *sbi, bool set)
{
	if (set)
		set_bit(LL_SBI_ENCRYPT_NAME, sbi->ll_flags);
	else
		clear_bit(LL_SBI_ENCRYPT_NAME, sbi->ll_flags);
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

/**
 * ll_setup_filename() - overlay to llcrypt_setup_filename
 * @dir: the directory that will be searched
 * @iname: the user-provided filename being searched for
 * @lookup: 1 if we're allowed to proceed without the key because it's
 *	->lookup() or we're finding the dir_entry for deletion; 0 if we cannot
 *	proceed without the key because we're going to create the dir_entry.
 * @fname: the filename information to be filled in
 * @fid: fid retrieved from user-provided filename
 *
 * This overlay function is necessary to properly encode @fname after
 * encryption, as it will be sent over the wire.
 * This overlay function is also necessary to handle the case of operations
 * carried out without the key. Normally llcrypt makes use of digested names in
 * that case. Having a digested name works for local file systems that can call
 * llcrypt_match_name(), but Lustre server side is not aware of encryption.
 * So for keyless @lookup operations on long names, for Lustre we choose to
 * present to users the encoded struct ll_digest_filename, instead of a digested
 * name. FID and name hash can then easily be extracted and put into the
 * requests sent to servers.
 */
int ll_setup_filename(struct inode *dir, const struct qstr *iname,
		      int lookup, struct llcrypt_name *fname,
		      struct lu_fid *fid)
{
	int digested = 0;
	struct qstr dname;
	int rc;

	if (fid && IS_ENCRYPTED(dir) && llcrypt_policy_has_filename_enc(dir) &&
	    !llcrypt_has_encryption_key(dir)) {
		struct lustre_sb_info *lsi = s2lsi(dir->i_sb);

		if ((!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI) &&
		     iname->name[0] == LLCRYPT_DIGESTED_CHAR) ||
		    ((lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI) &&
		     iname->name[0] == LLCRYPT_DIGESTED_CHAR_OLD))
			digested = 1;
	}

	dname.name = iname->name + digested;
	dname.len = iname->len - digested;

	if (fid) {
		fid->f_seq = 0;
		fid->f_oid = 0;
		fid->f_ver = 0;
	}
	rc = llcrypt_setup_filename(dir, &dname, lookup, fname);
	if (rc == -ENOENT && lookup) {
		if (((is_root_inode(dir) &&
		     iname->len == strlen(dot_fscrypt_name) &&
		     strncmp(iname->name, dot_fscrypt_name, iname->len) == 0) ||
		     (!llcrypt_has_encryption_key(dir) &&
		      unlikely(filename_is_volatile(iname->name,
						    iname->len, NULL))))) {
			/* In case of subdir mount of an encrypted directory,
			 * we allow lookup of /.fscrypt directory.
			 */
			/* For purpose of migration or mirroring without enc key
			 * we allow lookup of volatile file without enc context.
			 */
			memset(fname, 0, sizeof(struct llcrypt_name));
			fname->disk_name.name = (unsigned char *)iname->name;
			fname->disk_name.len = iname->len;
			rc = 0;
		} else if (!llcrypt_has_encryption_key(dir)) {
			rc = -ENOKEY;
		}
	}
	if (rc)
		return rc;

	if (digested) {
		/* Without the key, for long names user should have struct
		 * ll_digest_filename representation of the dentry instead of
		 * the name. So make sure it is valid, return fid and put
		 * excerpt of cipher text name in disk_name.
		 */
		struct ll_digest_filename *digest;

		if (fname->crypto_buf.len < sizeof(struct ll_digest_filename)) {
			rc = -EINVAL;
			goto out_free;
		}
		digest = (struct ll_digest_filename *)fname->disk_name.name;
		*fid = digest->ldf_fid;
		if (!fid_is_sane(fid)) {
			rc = -EINVAL;
			goto out_free;
		}
		fname->disk_name.name = digest->ldf_excerpt;
		fname->disk_name.len = sizeof(digest->ldf_excerpt);
	}
	if (IS_ENCRYPTED(dir) &&
	    !name_is_dot_or_dotdot(fname->disk_name.name,
				   fname->disk_name.len)) {
		int presented_len = critical_chars(fname->disk_name.name,
						   fname->disk_name.len);
		char *buf;

		buf = kmalloc(presented_len + 1, GFP_NOFS);
		if (!buf) {
			rc = -ENOMEM;
			goto out_free;
		}

		if (presented_len == fname->disk_name.len)
			memcpy(buf, fname->disk_name.name, presented_len);
		else
			critical_encode(fname->disk_name.name,
					fname->disk_name.len, buf);
		buf[presented_len] = '\0';
		kfree(fname->crypto_buf.name);
		fname->crypto_buf.name = buf;
		fname->crypto_buf.len = presented_len;
		fname->disk_name.name = fname->crypto_buf.name;
		fname->disk_name.len = fname->crypto_buf.len;
	}

	return rc;

out_free:
	llcrypt_free_filename(fname);
	return rc;
}

/**
 * ll_fname_disk_to_usr() - overlay to llcrypt_fname_disk_to_usr
 * @inode: the inode to convert name
 * @hash: major hash for inode
 * @minor_hash: minor hash for inode
 * @iname: the user-provided filename needing conversion
 * @oname: the filename information to be filled in
 * @fid: the user-provided fid for filename
 *
 * The caller must have allocated sufficient memory for the @oname string.
 *
 * This overlay function is necessary to properly decode @iname before
 * decryption, as it comes from the wire.
 * This overlay function is also necessary to handle the case of operations
 * carried out without the key. Normally llcrypt makes use of digested names in
 * that case. Having a digested name works for local file systems that can call
 * llcrypt_match_name(), but Lustre server side is not aware of encryption.
 * So for keyless @lookup operations on long names, for Lustre we choose to
 * present to users the encoded struct ll_digest_filename, instead of a digested
 * name. FID and name hash can then easily be extracted and put into the
 * requests sent to servers.
 */
int ll_fname_disk_to_usr(struct inode *inode,
			 u32 hash, u32 minor_hash,
			 struct llcrypt_str *iname, struct llcrypt_str *oname,
			 struct lu_fid *fid)
{
	struct llcrypt_str lltr = LLTR_INIT(iname->name, iname->len);
	struct ll_digest_filename digest;
	int digested = 0;
	char *buf = NULL;
	int rc;

	if (IS_ENCRYPTED(inode)) {
		if (!name_is_dot_or_dotdot(lltr.name, lltr.len) &&
		    strnchr(lltr.name, lltr.len, '=')) {
			/* Only proceed to critical decode if
			 * iname contains espace char '='.
			 */
			int len = lltr.len;

			buf = kmalloc(len, GFP_NOFS);
			if (!buf)
				return -ENOMEM;

			len = critical_decode(lltr.name, len, buf);
			lltr.name = buf;
			lltr.len = len;
		}
		if (lltr.len > LL_CRYPTO_BLOCK_SIZE * 2 &&
		    !llcrypt_has_encryption_key(inode) &&
		    llcrypt_policy_has_filename_enc(inode)) {
			struct lustre_sb_info *lsi = s2lsi(inode->i_sb);

			digested = 1;
			/* Without the key for long names, set the dentry name
			 * to the representing struct ll_digest_filename. It
			 * will be encoded by llcrypt for display, and will
			 * enable further lookup requests.
			 */
			if (!fid)
				return -EINVAL;
			digest.ldf_fid = *fid;
			memcpy(digest.ldf_excerpt,
			       LLCRYPT_EXTRACT_DIGEST(lltr.name, lltr.len),
			       sizeof(digest.ldf_excerpt));

			lltr.name = (char *)&digest;
			lltr.len = sizeof(digest);

			if (!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI))
				oname->name[0] = LLCRYPT_DIGESTED_CHAR;
			else
				oname->name[0] = LLCRYPT_DIGESTED_CHAR_OLD;
			oname->name = oname->name + 1;
			oname->len--;
		}
	}

	rc = llcrypt_fname_disk_to_usr(inode, hash, minor_hash, &lltr, oname);

	kfree(buf);
	oname->name = oname->name - digested;
	oname->len = oname->len + digested;

	return rc;
}

/* Copied from llcrypt_d_revalidate, as it is not exported */
/*
 * Validate dentries in encrypted directories to make sure we aren't potentially
 * caching stale dentries after a key has been added.
 */
int ll_revalidate_d_crypto(struct dentry *dentry, unsigned int flags)
{
	struct dentry *dir;
	int err;
	int valid;

	/*
	 * Plaintext names are always valid, since llcrypt doesn't support
	 * reverting to ciphertext names without evicting the directory's inode
	 * -- which implies eviction of the dentries in the directory.
	 */
	if (!llcrypt_is_nokey_name(dentry))
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

const struct llcrypt_operations lustre_cryptops = {
	.key_prefix		= "lustre:",
	.get_context		= ll_get_context,
	.set_context		= ll_set_context,
#ifdef HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED
	.dummy_context		= ll_dummy_context,
#else
	.get_dummy_context	= ll_get_dummy_context,
#endif
	.empty_dir		= ll_empty_dir,
	.max_namelen		= NAME_MAX,
};
#else /* !HAVE_LUSTRE_CRYPTO */
int ll_set_encflags(struct inode *inode, void *encctx, __u32 encctxlen,
		    bool preload)
{
	return 0;
}

int ll_file_open_encrypt(struct inode *inode, struct file *filp)
{
	return llcrypt_file_open(inode, filp);
}

void llcrypt_free_ctx(void *encctx, __u32 size)
{
}

bool ll_sb_has_test_dummy_encryption(struct super_block *sb)
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

bool ll_sbi_has_name_encrypt(struct ll_sb_info *sbi)
{
	return false;
}

void ll_sbi_set_name_encrypt(struct ll_sb_info *sbi, bool set)
{
}

int ll_setup_filename(struct inode *dir, const struct qstr *iname,
		      int lookup, struct llcrypt_name *fname,
		      struct lu_fid *fid)
{
	if (fid) {
		fid->f_seq = 0;
		fid->f_oid = 0;
		fid->f_ver = 0;
	}

	return llcrypt_setup_filename(dir, iname, lookup, fname);
}

int ll_fname_disk_to_usr(struct inode *inode,
			 u32 hash, u32 minor_hash,
			 struct llcrypt_str *iname, struct llcrypt_str *oname,
			 struct lu_fid *fid)
{
	return llcrypt_fname_disk_to_usr(inode, hash, minor_hash, iname, oname);
}

int ll_revalidate_d_crypto(struct dentry *dentry, unsigned int flags)
{
	return 1;
}
#endif

