// SPDX-License-Identifier: GPL-2.0
/*
 * This contains functions for filename crypto management
 *
 * Copyright (C) 2015, Google, Inc.
 * Copyright (C) 2015, Motorola Mobility
 *
 * Written by Uday Savagaonkar, 2014.
 * Modified by Jaegeuk Kim, 2015.
 *
 * This has not yet undergone a rigorous security audit.
 */
/*
 * Linux commit 219d54332a09
 * tags/v5.4
 */

#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include "llcrypt_private.h"

static inline bool llcrypt_is_dot_dotdot(const struct qstr *str)
{
	if (str->len == 1 && str->name[0] == '.')
		return true;

	if (str->len == 2 && str->name[0] == '.' && str->name[1] == '.')
		return true;

	return false;
}

/**
 * fname_encrypt() - encrypt a filename
 *
 * The output buffer must be at least as large as the input buffer.
 * Any extra space is filled with NUL padding before encryption.
 *
 * Return: 0 on success, -errno on failure
 */
int fname_encrypt(struct inode *inode, const struct qstr *iname,
		  u8 *out, unsigned int olen)
{
	struct skcipher_request *req = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	struct llcrypt_info *ci = llcrypt_info(inode);
	struct crypto_skcipher *tfm = ci->ci_ctfm;
	union llcrypt_iv iv;
	struct scatterlist sg;
	int res;

	/*
	 * Copy the filename to the output buffer for encrypting in-place and
	 * pad it with the needed number of NUL bytes.
	 */
	if (WARN_ON(olen < iname->len))
		return -ENOBUFS;
	memcpy(out, iname->name, iname->len);
	memset(out + iname->len, 0, olen - iname->len);

	if (tfm == NULL)
		return 0;

	/* Initialize the IV */
	llcrypt_generate_iv(&iv, 0, ci);

	/* Set up the encryption request */
	req = skcipher_request_alloc(tfm, GFP_NOFS);
	if (!req)
		return -ENOMEM;
	skcipher_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &wait);
	sg_init_one(&sg, out, olen);
	skcipher_request_set_crypt(req, &sg, &sg, olen, &iv);

	/* Do the encryption */
	res = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	skcipher_request_free(req);
	if (res < 0) {
		llcrypt_err(inode, "Filename encryption failed: %d", res);
		return res;
	}

	return 0;
}

/**
 * fname_decrypt() - decrypt a filename
 *
 * The caller must have allocated sufficient memory for the @oname string.
 *
 * Return: 0 on success, -errno on failure
 */
static int fname_decrypt(struct inode *inode,
				const struct llcrypt_str *iname,
				struct llcrypt_str *oname)
{
	struct skcipher_request *req = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist src_sg, dst_sg;
	struct llcrypt_info *ci = llcrypt_info(inode);
	struct crypto_skcipher *tfm = ci->ci_ctfm;
	union llcrypt_iv iv;
	int res;

	if (tfm == NULL) {
		memcpy(oname->name, iname->name, iname->len);
		oname->name[iname->len] = '\0';
		oname->len = iname->len;
		return 0;
	}

	/* Allocate request */
	req = skcipher_request_alloc(tfm, GFP_NOFS);
	if (!req)
		return -ENOMEM;
	skcipher_request_set_callback(req,
		CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);

	/* Initialize IV */
	llcrypt_generate_iv(&iv, 0, ci);

	/* Create decryption request */
	sg_init_one(&src_sg, iname->name, iname->len);
	sg_init_one(&dst_sg, oname->name, oname->len);
	skcipher_request_set_crypt(req, &src_sg, &dst_sg, iname->len, &iv);
	res = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
	skcipher_request_free(req);
	if (res < 0) {
		llcrypt_err(inode, "Filename decryption failed: %d", res);
		return res;
	}

	oname->len = strnlen(oname->name, iname->len);
	return 0;
}

/*
 * Old fashion base64 encoding, taken from Linux 5.4.
 *
 * This base64 encoding is specific to fscrypt and has been replaced since then
 * with an RFC 4648 compliant base64-url encoding, see llcrypt_base64url_*
 * below.
 * The old fashion base64 encoding is kept for compatibility with older clients.
 */

static const char lookup_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

#define LLCRYPT_BASE64_CHARS(nbytes)	DIV_ROUND_UP((nbytes) * 4, 3)

/**
 * base64_encode() -
 *
 * Encodes the input string using characters from the set [A-Za-z0-9+,].
 * The encoded string is roughly 4/3 times the size of the input string.
 *
 * Return: length of the encoded string
 */
static inline int llcrypt_base64_encode(const u8 *src, int len, char *dst)
{
	int i, bits = 0, ac = 0;
	char *cp = dst;

	for (i = 0; i < len; i++) {
		ac += src[i] << bits;
		bits += 8;
		do {
			*cp++ = lookup_table[ac & 0x3f];
			ac >>= 6;
			bits -= 6;
		} while (bits >= 6);
	}
	if (bits)
		*cp++ = lookup_table[ac & 0x3f];
	return cp - dst;
}

static inline int llcrypt_base64_decode(const char *src, int len, u8 *dst)
{
	int i, bits = 0, ac = 0;
	const char *p;
	u8 *cp = dst;

	for (i = 0; i < len; i++) {
		p = strchr(lookup_table, src[i]);
		if (p == NULL || src[i] == 0)
			return -2;
		ac += (p - lookup_table) << bits;
		bits += 6;
		if (bits >= 8) {
			*cp++ = ac & 0xff;
			ac >>= 8;
			bits -= 8;
		}
	}
	if (ac)
		return -1;
	return cp - dst;
}

/*
 * New fashion base64 encoding, taken from Linux 5.14.
 *
 * This base64 encoding is RFC 4648 compliant base64-url encoding.
 */

static const char base64url_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#define LLCRYPT_BASE64URL_CHARS(nbytes)	DIV_ROUND_UP((nbytes) * 4, 3)

/**
 * llcrypt_base64url_encode() - base64url-encode some binary data
 * @src: the binary data to encode
 * @srclen: the length of @src in bytes
 * @dst: (output) the base64url-encoded string.  Not NUL-terminated.
 *
 * Encodes data using base64url encoding, i.e. the "Base 64 Encoding with URL
 * and Filename Safe Alphabet" specified by RFC 4648.  '='-padding isn't used,
 * as it's unneeded and not required by the RFC.  base64url is used instead of
 * base64 to avoid the '/' character, which isn't allowed in filenames.
 *
 * Return: the length of the resulting base64url-encoded string in bytes.
 *	   This will be equal to LLCRYPT_BASE64URL_CHARS(srclen).
 */
static inline int llcrypt_base64url_encode(const u8 *src, int srclen, char *dst)
{
	u32 ac = 0;
	int bits = 0;
	int i;
	char *cp = dst;

	for (i = 0; i < srclen; i++) {
		ac = (ac << 8) | src[i];
		bits += 8;
		do {
			bits -= 6;
			*cp++ = base64url_table[(ac >> bits) & 0x3f];
		} while (bits >= 6);
	}
	if (bits)
		*cp++ = base64url_table[(ac << (6 - bits)) & 0x3f];
	return cp - dst;
}

/**
 * llcrypt_base64url_decode() - base64url-decode a string
 * @src: the string to decode.  Doesn't need to be NUL-terminated.
 * @srclen: the length of @src in bytes
 * @dst: (output) the decoded binary data
 *
 * Decodes a string using base64url encoding, i.e. the "Base 64 Encoding with
 * URL and Filename Safe Alphabet" specified by RFC 4648.  '='-padding isn't
 * accepted, nor are non-encoding characters such as whitespace.
 *
 * This implementation hasn't been optimized for performance.
 *
 * Return: the length of the resulting decoded binary data in bytes,
 *	   or -1 if the string isn't a valid base64url string.
 */
static inline int llcrypt_base64url_decode(const char *src, int srclen, u8 *dst)
{
	u32 ac = 0;
	int bits = 0;
	int i;
	u8 *bp = dst;

	for (i = 0; i < srclen; i++) {
		const char *p = strchr(base64url_table, src[i]);

		if (p == NULL || src[i] == 0)
			return -1;
		ac = (ac << 6) | (p - base64url_table);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*bp++ = (u8)(ac >> bits);
		}
	}
	if (ac & ((1 << bits) - 1))
		return -1;
	return bp - dst;
}

static inline int base64_chars(struct lustre_sb_info *lsi, int nbytes)
{
	if (!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI))
		return LLCRYPT_BASE64URL_CHARS(nbytes);
	else
		return LLCRYPT_BASE64_CHARS(nbytes);
}

bool llcrypt_fname_encrypted_size(const struct inode *inode, u32 orig_len,
				  u32 max_len, u32 *encrypted_len_ret)
{
	const struct llcrypt_info *ci = llcrypt_info(inode);
	struct crypto_skcipher *tfm = ci->ci_ctfm;
	int padding = 4 << (llcrypt_policy_flags(&ci->ci_policy) &
			    LLCRYPT_POLICY_FLAGS_PAD_MASK);
	u32 encrypted_len;

	if (orig_len > max_len)
		return false;
	if (tfm == NULL) {
		*encrypted_len_ret = orig_len;
	} else {
		encrypted_len = max(orig_len, (u32)LL_CRYPTO_BLOCK_SIZE);
		encrypted_len = round_up(encrypted_len, padding);
		*encrypted_len_ret = min(encrypted_len, max_len);
	}
	return true;
}

/**
 * llcrypt_fname_alloc_buffer - allocate a buffer for presented filenames
 *
 * Allocate a buffer that is large enough to hold any decrypted or encoded
 * filename (null-terminated), for the given maximum encrypted filename length.
 *
 * Return: 0 on success, -errno on failure
 */
int llcrypt_fname_alloc_buffer(const struct inode *inode,
			       u32 max_encrypted_len,
			       struct llcrypt_str *crypto_str)
{
	struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
	const u32 max_encoded_len =
		max_t(u32,
		   base64_chars(lsi, LLCRYPT_FNAME_MAX_UNDIGESTED_SIZE),
		   1 + base64_chars(lsi, sizeof(struct llcrypt_digested_name)));
	u32 max_presented_len;

	max_presented_len = max(max_encoded_len, max_encrypted_len);

	crypto_str->name = kmalloc(max_presented_len + 1, GFP_NOFS);
	if (!crypto_str->name)
		return -ENOMEM;
	crypto_str->len = max_presented_len;
	return 0;
}
EXPORT_SYMBOL(llcrypt_fname_alloc_buffer);

/**
 * llcrypt_fname_free_buffer - free the buffer for presented filenames
 *
 * Free the buffer allocated by llcrypt_fname_alloc_buffer().
 */
void llcrypt_fname_free_buffer(struct llcrypt_str *crypto_str)
{
	if (!crypto_str)
		return;
	kfree(crypto_str->name);
	crypto_str->name = NULL;
}
EXPORT_SYMBOL(llcrypt_fname_free_buffer);

/**
 * llcrypt_fname_disk_to_usr() - converts a filename from disk space to user
 * space
 *
 * The caller must have allocated sufficient memory for the @oname string.
 *
 * If the key is available, we'll decrypt the disk name; otherwise, we'll encode
 * it for presentation.  Short names are directly base64-encoded, while long
 * names are encoded in llcrypt_digested_name format.
 *
 * Return: 0 on success, -errno on failure
 */
int llcrypt_fname_disk_to_usr(struct inode *inode,
			u32 hash, u32 minor_hash,
			const struct llcrypt_str *iname,
			struct llcrypt_str *oname)
{
	int (*b64_encode)(const u8 *src, int srclen, char *dst);
	struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
	const struct qstr qname = LLTR_TO_QSTR(iname);
	struct llcrypt_digested_name digested_name;

	if (llcrypt_is_dot_dotdot(&qname)) {
		oname->name[0] = '.';
		oname->name[iname->len - 1] = '.';
		oname->len = iname->len;
		return 0;
	}

	if (llcrypt_has_encryption_key(inode)) {
		struct llcrypt_info *ci = llcrypt_info(inode);
		struct crypto_skcipher *tfm = ci->ci_ctfm;

		if (tfm && iname->len < LL_CRYPTO_BLOCK_SIZE)
			return -EUCLEAN;

		return fname_decrypt(inode, iname, oname);
	}

	if (!llcrypt_policy_has_filename_enc(inode)) {
		memcpy(oname->name, iname->name, iname->len);
		oname->name[iname->len] = '\0';
		oname->len = iname->len;
		return 0;
	}

	if (!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI))
		b64_encode = llcrypt_base64url_encode;
	else
		b64_encode = llcrypt_base64_encode;

	if (iname->len <= LLCRYPT_FNAME_MAX_UNDIGESTED_SIZE) {
		oname->len = b64_encode(iname->name, iname->len, oname->name);
		return 0;
	}
	if (hash) {
		digested_name.hash = hash;
		digested_name.minor_hash = minor_hash;
	} else {
		digested_name.hash = 0;
		digested_name.minor_hash = 0;
	}
	memcpy(digested_name.digest,
	       LLCRYPT_FNAME_DIGEST(iname->name, iname->len),
	       LLCRYPT_FNAME_DIGEST_SIZE);
	if (!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI))
		oname->name[0] = LLCRYPT_DIGESTED_CHAR;
	else
		oname->name[0] = LLCRYPT_DIGESTED_CHAR_OLD;
	oname->len = 1 + b64_encode((const u8 *)&digested_name,
				    sizeof(digested_name), oname->name + 1);
	return 0;
}
EXPORT_SYMBOL(llcrypt_fname_disk_to_usr);

/**
 * llcrypt_setup_filename() - prepare to search a possibly encrypted directory
 * @dir: the directory that will be searched
 * @iname: the user-provided filename being searched for
 * @lookup: 1 if we're allowed to proceed without the key because it's
 *	->lookup() or we're finding the dir_entry for deletion; 0 if we cannot
 *	proceed without the key because we're going to create the dir_entry.
 * @fname: the filename information to be filled in
 *
 * Given a user-provided filename @iname, this function sets @fname->disk_name
 * to the name that would be stored in the on-disk directory entry, if possible.
 * If the directory is unencrypted this is simply @iname.  Else, if we have the
 * directory's encryption key, then @iname is the plaintext, so we encrypt it to
 * get the disk_name.
 *
 * Else, for keyless @lookup operations, @iname is the presented ciphertext, so
 * we decode it to get either the ciphertext disk_name (for short names) or the
 * llcrypt_digested_name (for long names).  Non-@lookup operations will be
 * impossible in this case, so we fail them with ENOKEY.
 *
 * If successful, llcrypt_free_filename() must be called later to clean up.
 *
 * Return: 0 on success, -errno on failure
 */
int llcrypt_setup_filename(struct inode *dir, const struct qstr *iname,
			      int lookup, struct llcrypt_name *fname)
{
	struct lustre_sb_info *lsi = s2lsi(dir->i_sb);
	int ret;
	int digested;

	memset(fname, 0, sizeof(struct llcrypt_name));
	fname->usr_fname = iname;

	if (!IS_ENCRYPTED(dir) || llcrypt_is_dot_dotdot(iname)) {
		fname->disk_name.name = (unsigned char *)iname->name;
		fname->disk_name.len = iname->len;
		return 0;
	}
	ret = llcrypt_get_encryption_info(dir);
	if (ret)
		return ret;

	if (llcrypt_has_encryption_key(dir)) {
		struct lustre_sb_info *lsi = s2lsi(dir->i_sb);

		if (!llcrypt_fname_encrypted_size(dir, iname->len,
						  lsi ?
						    lsi->lsi_cop->max_namelen :
						    NAME_MAX,
						  &fname->crypto_buf.len))
			return -ENAMETOOLONG;
		fname->crypto_buf.name = kmalloc(fname->crypto_buf.len,
						 GFP_NOFS);
		if (!fname->crypto_buf.name)
			return -ENOMEM;

		ret = fname_encrypt(dir, iname, fname->crypto_buf.name,
				    fname->crypto_buf.len);
		if (ret)
			goto errout;
		fname->disk_name.name = fname->crypto_buf.name;
		fname->disk_name.len = fname->crypto_buf.len;
		return 0;
	}
	if (!lookup)
		return -ENOKEY;

	if (!llcrypt_policy_has_filename_enc(dir)) {
		fname->disk_name.name = (unsigned char *)iname->name;
		fname->disk_name.len = iname->len;
		return 0;
	}

	fname->is_ciphertext_name = true;

	/*
	 * We don't have the key and we are doing a lookup; decode the
	 * user-supplied name
	 */
	if ((!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI) &&
	     iname->name[0] == LLCRYPT_DIGESTED_CHAR) ||
	    ((lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI) &&
	     iname->name[0] == LLCRYPT_DIGESTED_CHAR_OLD)) {
		if (iname->len != 1 + base64_chars(lsi,
					sizeof(struct llcrypt_digested_name))) {
			return -ENOENT;
		}
		digested = 1;
	} else {
		if (iname->len >
		    base64_chars(lsi, LLCRYPT_FNAME_MAX_UNDIGESTED_SIZE))
			return -ENOENT;
		digested = 0;
	}

	fname->crypto_buf.name =
		kmalloc(max_t(size_t, LLCRYPT_FNAME_MAX_UNDIGESTED_SIZE,
			      sizeof(struct llcrypt_digested_name)),
			GFP_KERNEL);
	if (fname->crypto_buf.name == NULL)
		return -ENOMEM;

	if (!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI))
		ret = llcrypt_base64url_decode(iname->name + digested,
					       iname->len - digested,
					       fname->crypto_buf.name);
	else
		ret = llcrypt_base64_decode(iname->name + digested,
					    iname->len - digested,
					    fname->crypto_buf.name);

	if (ret < 0) {
		ret = -ENOENT;
		goto errout;
	}
	fname->crypto_buf.len = ret;
	if (digested) {
		const struct llcrypt_digested_name *n =
			(const void *)fname->crypto_buf.name;
		fname->hash = n->hash;
		fname->minor_hash = n->minor_hash;
	} else {
		fname->disk_name.name = fname->crypto_buf.name;
		fname->disk_name.len = fname->crypto_buf.len;
	}
	return 0;

errout:
	kfree(fname->crypto_buf.name);
	return ret;
}
EXPORT_SYMBOL(llcrypt_setup_filename);
