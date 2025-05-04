// SPDX-License-Identifier: GPL-2.0
/*
 * Encryption policy functions for per-file encryption support.
 *
 * Copyright (C) 2015, Google, Inc.
 * Copyright (C) 2015, Motorola Mobility.
 *
 * Originally written by Michael Halcrow, 2015.
 * Modified by Jaegeuk Kim, 2015.
 * Modified by Eric Biggers, 2019 for v2 policy support.
 */
/*
 * Linux commit 219d54332a09
 * tags/v5.4
 */

#include <linux/random.h>
#include <linux/string.h>
#include <linux/mount.h>
#include <lustre_compat.h>
#include "llcrypt_private.h"

/**
 * llcrypt_policies_equal - check whether two encryption policies are the same
 *
 * Return: %true if equal, else %false
 */
bool llcrypt_policies_equal(const union llcrypt_policy *policy1,
			    const union llcrypt_policy *policy2)
{
	if (policy1->version != policy2->version)
		return false;

	return !memcmp(policy1, policy2, llcrypt_policy_size(policy1));
}

/**
 * llcrypt_supported_policy - check whether an encryption policy is supported
 *
 * Given an encryption policy, check whether all its encryption modes and other
 * settings are supported by this kernel.  (But we don't currently don't check
 * for crypto API support here, so attempting to use an algorithm not configured
 * into the crypto API will still fail later.)
 *
 * Return: %true if supported, else %false
 */
bool llcrypt_supported_policy(const union llcrypt_policy *policy_u,
			      const struct inode *inode)
{
	switch (policy_u->version) {
	case LLCRYPT_POLICY_V1: {
		const struct llcrypt_policy_v1 *policy = &policy_u->v1;

		if (!llcrypt_valid_enc_modes(policy->contents_encryption_mode,
					     policy->filenames_encryption_mode)) {
			llcrypt_warn(inode,
				     "Unsupported encryption modes (contents %d, filenames %d)",
				     policy->contents_encryption_mode,
				     policy->filenames_encryption_mode);
			return false;
		}

		if (policy->flags & ~LLCRYPT_POLICY_FLAGS_VALID) {
			llcrypt_warn(inode,
				     "Unsupported encryption flags (0x%02x)",
				     policy->flags);
			return false;
		}

		return true;
	}
	case LLCRYPT_POLICY_V2: {
		const struct llcrypt_policy_v2 *policy = &policy_u->v2;

		if (!llcrypt_valid_enc_modes(policy->contents_encryption_mode,
					     policy->filenames_encryption_mode)) {
			llcrypt_warn(inode,
				     "Unsupported encryption modes (contents %d, filenames %d)",
				     policy->contents_encryption_mode,
				     policy->filenames_encryption_mode);
			return false;
		}

		if (policy->flags & ~LLCRYPT_POLICY_FLAGS_VALID) {
			llcrypt_warn(inode,
				     "Unsupported encryption flags (0x%02x)",
				     policy->flags);
			return false;
		}

		if (memchr_inv(policy->__reserved, 0,
			       sizeof(policy->__reserved))) {
			llcrypt_warn(inode,
				     "Reserved bits set in encryption policy");
			return false;
		}

		return true;
	}
	}
	return false;
}

/**
 * llcrypt_new_context_from_policy - create a new llcrypt_context from a policy
 *
 * Create an llcrypt_context for an inode that is being assigned the given
 * encryption policy.  A new nonce is randomly generated.
 *
 * Return: the size of the new context in bytes.
 */
static int llcrypt_new_context_from_policy(union llcrypt_context *ctx_u,
					   const union llcrypt_policy *policy_u)
{
	memset(ctx_u, 0, sizeof(*ctx_u));

	switch (policy_u->version) {
	case LLCRYPT_POLICY_V1: {
		const struct llcrypt_policy_v1 *policy = &policy_u->v1;
		struct llcrypt_context_v1 *ctx = &ctx_u->v1;

		ctx->version = LLCRYPT_CONTEXT_V1;
		ctx->contents_encryption_mode =
			policy->contents_encryption_mode;
		ctx->filenames_encryption_mode =
			policy->filenames_encryption_mode;
		ctx->flags = policy->flags;
		memcpy(ctx->master_key_descriptor,
		       policy->master_key_descriptor,
		       sizeof(ctx->master_key_descriptor));
		get_random_bytes(ctx->nonce, sizeof(ctx->nonce));
		return sizeof(*ctx);
	}
	case LLCRYPT_POLICY_V2: {
		const struct llcrypt_policy_v2 *policy = &policy_u->v2;
		struct llcrypt_context_v2 *ctx = &ctx_u->v2;

		ctx->version = LLCRYPT_CONTEXT_V2;
		ctx->contents_encryption_mode =
			policy->contents_encryption_mode;
		ctx->filenames_encryption_mode =
			policy->filenames_encryption_mode;
		ctx->flags = policy->flags;
		memcpy(ctx->master_key_identifier,
		       policy->master_key_identifier,
		       sizeof(ctx->master_key_identifier));
		get_random_bytes(ctx->nonce, sizeof(ctx->nonce));
		return sizeof(*ctx);
	}
	}
	BUG();
}

/**
 * llcrypt_policy_from_context - convert an llcrypt_context to an llcrypt_policy
 *
 * Given an llcrypt_context, build the corresponding llcrypt_policy.
 *
 * Return: 0 on success, or -EINVAL if the llcrypt_context has an unrecognized
 * version number or size.
 *
 * This does *not* validate the settings within the policy itself, e.g. the
 * modes, flags, and reserved bits.  Use llcrypt_supported_policy() for that.
 */
int llcrypt_policy_from_context(union llcrypt_policy *policy_u,
				const union llcrypt_context *ctx_u,
				int ctx_size)
{
	memset(policy_u, 0, sizeof(*policy_u));

	if (ctx_size <= 0 || ctx_size != llcrypt_context_size(ctx_u))
		return -EINVAL;

	switch (ctx_u->version) {
	case LLCRYPT_CONTEXT_V1: {
		const struct llcrypt_context_v1 *ctx = &ctx_u->v1;
		struct llcrypt_policy_v1 *policy = &policy_u->v1;

		policy->version = LLCRYPT_POLICY_V1;
		policy->contents_encryption_mode =
			ctx->contents_encryption_mode;
		policy->filenames_encryption_mode =
			ctx->filenames_encryption_mode;
		policy->flags = ctx->flags;
		memcpy(policy->master_key_descriptor,
		       ctx->master_key_descriptor,
		       sizeof(policy->master_key_descriptor));
		return 0;
	}
	case LLCRYPT_CONTEXT_V2: {
		const struct llcrypt_context_v2 *ctx = &ctx_u->v2;
		struct llcrypt_policy_v2 *policy = &policy_u->v2;

		policy->version = LLCRYPT_POLICY_V2;
		policy->contents_encryption_mode =
			ctx->contents_encryption_mode;
		policy->filenames_encryption_mode =
			ctx->filenames_encryption_mode;
		policy->flags = ctx->flags;
		memcpy(policy->__reserved, ctx->__reserved,
		       sizeof(policy->__reserved));
		memcpy(policy->master_key_identifier,
		       ctx->master_key_identifier,
		       sizeof(policy->master_key_identifier));
		return 0;
	}
	}
	/* unreachable */
	return -EINVAL;
}

/* Retrieve an inode's encryption policy */
static int llcrypt_get_policy(struct inode *inode, union llcrypt_policy *policy)
{
	const struct llcrypt_info *ci;
	union llcrypt_context ctx;
	struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
	int ret;

	ci = (struct llcrypt_info *)READ_ONCE(llcrypt_info_nocast(inode));
	if (ci) {
		/* key available, use the cached policy */
		*policy = ci->ci_policy;
		return 0;
	}

	if (!IS_ENCRYPTED(inode))
		return -ENODATA;

	if (!lsi)
		return -ENODATA;

	ret = lsi->lsi_cop->get_context(inode, &ctx, sizeof(ctx));
	if (ret < 0)
		return (ret == -ERANGE) ? -EINVAL : ret;

	return llcrypt_policy_from_context(policy, &ctx, ret);
}

static int set_encryption_policy(struct inode *inode,
				 const union llcrypt_policy *policy)
{
	union llcrypt_context ctx;
	int ctxsize;
	struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
	int err;

	if (!llcrypt_supported_policy(policy, inode))
		return -EINVAL;

	switch (policy->version) {
	case LLCRYPT_POLICY_V1:
		/*
		 * The original encryption policy version provided no way of
		 * verifying that the correct master key was supplied, which was
		 * insecure in scenarios where multiple users have access to the
		 * same encrypted files (even just read-only access).  The new
		 * encryption policy version fixes this and also implies use of
		 * an improved key derivation function and allows non-root users
		 * to securely remove keys.  So as long as compatibility with
		 * old kernels isn't required, it is recommended to use the new
		 * policy version for all new encrypted directories.
		 */
		pr_warn_once("%s (pid %d) is setting deprecated v1 encryption policy; recommend upgrading to v2.\n",
			     current->comm, current->pid);
		break;
	case LLCRYPT_POLICY_V2:
		err = llcrypt_verify_key_added(inode->i_sb,
					       policy->v2.master_key_identifier);
		if (err)
			return err;
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}

	ctxsize = llcrypt_new_context_from_policy(&ctx, policy);

	if (!lsi)
		return -EINVAL;

	return lsi->lsi_cop->set_context(inode, &ctx, ctxsize, NULL);
}

/* Tell if an inode's encryption policy has filename encryption */
bool llcrypt_policy_has_filename_enc(struct inode *inode)
{
	union llcrypt_policy policy;
	int err;

	err = llcrypt_get_policy(inode, &policy);
	if (err)
		return true;

	if ((policy.version == LLCRYPT_POLICY_V1 &&
	     policy.v1.filenames_encryption_mode == LLCRYPT_MODE_NULL) ||
	    (policy.version == LLCRYPT_POLICY_V2 &&
	     policy.v2.filenames_encryption_mode == LLCRYPT_MODE_NULL))
		return false;
	return true;
}
EXPORT_SYMBOL(llcrypt_policy_has_filename_enc);

int llcrypt_ioctl_set_policy(struct file *filp, const void __user *arg)
{
	union llcrypt_policy policy;
	union llcrypt_policy existing_policy;
	struct inode *inode = file_inode(filp);
	struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
	u8 version;
	int size;
	int ret;

	if (get_user(policy.version, (const u8 __user *)arg))
		return -EFAULT;

	size = llcrypt_policy_size(&policy);
	if (size <= 0)
		return -EINVAL;

	/*
	 * We should just copy the remaining 'size - 1' bytes here, but a
	 * bizarre bug in gcc 7 and earlier (fixed by gcc r255731) causes gcc to
	 * think that size can be 0 here (despite the check above!) *and* that
	 * it's a compile-time constant.  Thus it would think copy_from_user()
	 * is passed compile-time constant ULONG_MAX, causing the compile-time
	 * buffer overflow check to fail, breaking the build. This only occurred
	 * when building an i386 kernel with -Os and branch profiling enabled.
	 *
	 * Work around it by just copying the first byte again...
	 */
	version = policy.version;
	if (copy_from_user(&policy, arg, size))
		return -EFAULT;
	policy.version = version;

	/* Force file/directory name encryption policy to null if
	 * LSI_FILENAME_ENC flag is not set on sb.
	 * This allows enabling filename encryption separately from data
	 * encryption, and can be useful for interoperability with
	 * encryption-unaware clients.
	 */
	if (!(lsi->lsi_flags & LSI_FILENAME_ENC)) {
		CWARN("inode %lu: forcing policy filenames_encryption_mode to null\n",
		      inode->i_ino);
		cfs_tty_write_msg("\n\nForcing policy filenames_encryption_mode to null.\n\n");
		switch (policy.version) {
		case LLCRYPT_POLICY_V1:
			policy.v1.filenames_encryption_mode = LLCRYPT_MODE_NULL;
			break;
		case LLCRYPT_POLICY_V2:
			policy.v2.filenames_encryption_mode = LLCRYPT_MODE_NULL;
			break;
		}
	}

	if (!inode_owner_or_capable(&nop_mnt_idmap, inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	ret = llcrypt_get_policy(inode, &existing_policy);
	if (ret == -ENODATA) {
		struct lustre_sb_info *lsi = s2lsi(inode->i_sb);

		if (!S_ISDIR(inode->i_mode))
			ret = -ENOTDIR;
		else if (IS_DEADDIR(inode))
			ret = -ENOENT;
		else if (lsi && !lsi->lsi_cop->empty_dir(inode))
			ret = -ENOTEMPTY;
		else
			ret = set_encryption_policy(inode, &policy);
	} else if (ret == -EINVAL ||
		   (ret == 0 && !llcrypt_policies_equal(&policy,
							&existing_policy))) {
		/* The file already uses a different encryption policy. */
		ret = -EEXIST;
	}

	inode_unlock(inode);

	mnt_drop_write_file(filp);
	return ret;
}
EXPORT_SYMBOL(llcrypt_ioctl_set_policy);

/* Original ioctl version; can only get the original policy version */
int llcrypt_ioctl_get_policy(struct file *filp, void __user *arg)
{
	union llcrypt_policy policy;
	int err;

	err = llcrypt_get_policy(file_inode(filp), &policy);
	if (err)
		return err;

	if (policy.version != LLCRYPT_POLICY_V1)
		return -EINVAL;

	if (copy_to_user(arg, &policy, sizeof(policy.v1)))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(llcrypt_ioctl_get_policy);

/* Valid filenames_encryption_mode associated with contents_encryption_mode,
 * as imposed by llcrypt_valid_enc_modes()
 */
static inline u8 contents2filenames_encmode(u8 contents_encryption_mode)
{
	if (contents_encryption_mode == LLCRYPT_MODE_AES_128_CBC)
		return LLCRYPT_MODE_AES_128_CTS;
	if (contents_encryption_mode == LLCRYPT_MODE_AES_256_XTS)
		return LLCRYPT_MODE_AES_256_CTS;
	if (contents_encryption_mode == LLCRYPT_MODE_ADIANTUM)
		return LLCRYPT_MODE_ADIANTUM;
	return LLCRYPT_MODE_NULL;
}

/* Extended ioctl version; can get policies of any version */
int llcrypt_ioctl_get_policy_ex(struct file *filp, void __user *uarg)
{
	struct llcrypt_get_policy_ex_arg arg;
	union llcrypt_policy *policy = (union llcrypt_policy *)&arg.policy;
	size_t policy_size;
	struct inode *inode = file_inode(filp);
	int err;

	/* arg is policy_size, then policy */
	BUILD_BUG_ON(offsetof(typeof(arg), policy_size) != 0);
	BUILD_BUG_ON(offsetofend(typeof(arg), policy_size) !=
		     offsetof(typeof(arg), policy));
	BUILD_BUG_ON(sizeof(arg.policy) != sizeof(*policy));

	err = llcrypt_get_policy(file_inode(filp), policy);
	if (err)
		return err;
	policy_size = llcrypt_policy_size(policy);

	if (copy_from_user(&arg, uarg, sizeof(arg.policy_size)))
		return -EFAULT;

	if (policy_size > arg.policy_size)
		return -EOVERFLOW;
	arg.policy_size = policy_size;

	/* Do not return null filenames_encryption_mode to userspace, as it is
	 * unknown. Instead, return valid mode associated with
	 * contents_encryption_mode, as imposed by llcrypt_valid_enc_modes().
	 */
	switch (policy->version) {
	case LLCRYPT_POLICY_V1:
		if (policy->v1.filenames_encryption_mode == LLCRYPT_MODE_NULL) {
			policy->v1.filenames_encryption_mode =
				contents2filenames_encmode(
					policy->v1.contents_encryption_mode);
			CWARN("inode %lu: returning policy filenames_encryption_mode as %d, but is in fact null\n",
			      inode->i_ino,
			      policy->v1.filenames_encryption_mode);
		}
		break;
	case LLCRYPT_POLICY_V2:
		if (policy->v2.filenames_encryption_mode == LLCRYPT_MODE_NULL) {
			policy->v2.filenames_encryption_mode =
				contents2filenames_encmode(
					policy->v2.contents_encryption_mode);
			CWARN("inode %lu: returning policy filenames_encryption_mode as %d, but is in fact null\n",
			      inode->i_ino,
			      policy->v2.filenames_encryption_mode);
		}
		break;
	}

	if (copy_to_user(uarg, &arg, sizeof(arg.policy_size) + policy_size))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL_GPL(llcrypt_ioctl_get_policy_ex);

/**
 * llcrypt_has_permitted_context() - is a file's encryption policy permitted
 *				     within its directory?
 *
 * @parent: inode for parent directory
 * @child: inode for file being looked up, opened, or linked into @parent
 *
 * Filesystems must call this before permitting access to an inode in a
 * situation where the parent directory is encrypted (either before allowing
 * ->lookup() to succeed, or for a regular file before allowing it to be opened)
 * and before any operation that involves linking an inode into an encrypted
 * directory, including link, rename, and cross rename.  It enforces the
 * constraint that within a given encrypted directory tree, all files use the
 * same encryption policy.  The pre-access check is needed to detect potentially
 * malicious offline violations of this constraint, while the link and rename
 * checks are needed to prevent online violations of this constraint.
 *
 * Return: 1 if permitted, 0 if forbidden.
 */
int llcrypt_has_permitted_context(struct inode *parent, struct inode *child)
{
	union llcrypt_policy parent_policy, child_policy;
	int err;

	/* No restrictions on file types which are never encrypted */
	if (!S_ISREG(child->i_mode) && !S_ISDIR(child->i_mode) &&
	    !S_ISLNK(child->i_mode))
		return 1;

	/* No restrictions if the parent directory is unencrypted */
	if (!IS_ENCRYPTED(parent))
		return 1;

	/* Encrypted directories must not contain unencrypted files */
	if (!IS_ENCRYPTED(child))
		return 0;

	/*
	 * Both parent and child are encrypted, so verify they use the same
	 * encryption policy.  Compare the llcrypt_info structs if the keys are
	 * available, otherwise retrieve and compare the llcrypt_contexts.
	 *
	 * Note that the llcrypt_context retrieval will be required frequently
	 * when accessing an encrypted directory tree without the key.
	 * Performance-wise this is not a big deal because we already don't
	 * really optimize for file access without the key (to the extent that
	 * such access is even possible), given that any attempted access
	 * already causes a llcrypt_context retrieval and keyring search.
	 *
	 * In any case, if an unexpected error occurs, fall back to "forbidden".
	 */

	err = llcrypt_get_encryption_info(parent);
	if (err)
		return 0;
	err = llcrypt_get_encryption_info(child);
	if (err)
		return 0;

	err = llcrypt_get_policy(parent, &parent_policy);
	if (err)
		return 0;

	err = llcrypt_get_policy(child, &child_policy);
	if (err)
		return 0;

	return llcrypt_policies_equal(&parent_policy, &child_policy);
}
EXPORT_SYMBOL(llcrypt_has_permitted_context);

/**
 * llcrypt_inherit_context() - Sets a child context from its parent
 * @parent: Parent inode from which the context is inherited.
 * @child:  Child inode that inherits the context from @parent.
 * @fs_data:  private data given by FS.
 * @preload:  preload child crypt info if true
 *
 * Return: 0 on success, -errno on failure
 */
int llcrypt_inherit_context(struct inode *parent, struct inode *child,
						void *fs_data, bool preload)
{
	union llcrypt_context ctx;
	int ctxsize;
	struct llcrypt_info *ci;
	struct lustre_sb_info *lsi = s2lsi(parent->i_sb);
	int res;

	res = llcrypt_get_encryption_info(parent);
	if (res < 0)
		return res;

	ci = (struct llcrypt_info *)READ_ONCE(llcrypt_info_nocast(parent));
	if (ci == NULL)
		return -ENOKEY;

	if (!lsi)
		return -ENOKEY;

	ctxsize = llcrypt_new_context_from_policy(&ctx, &ci->ci_policy);

	BUILD_BUG_ON(sizeof(ctx) != LLCRYPT_SET_CONTEXT_MAX_SIZE);
	res = lsi->lsi_cop->set_context(child, &ctx, ctxsize, fs_data);
	if (res)
		return res;
	return preload ? llcrypt_get_encryption_info(child): 0;
}
EXPORT_SYMBOL(llcrypt_inherit_context);
