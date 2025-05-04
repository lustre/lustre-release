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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/version.h>
#define DEBUG_SUBSYSTEM S_LLITE

#include "llite_internal.h"

/* Must be called with lli_size_mutex locked */
/* HAVE_IOP_GET_LINK is defined from kernel 4.5, whereas
 * IS_ENCRYPTED is brought by kernel 4.14.
 * So there is no need to handle encryption case otherwise.
 */
#ifdef HAVE_IOP_GET_LINK
static int ll_readlink_internal(struct inode *inode,
				struct ptlrpc_request **request,
				char **symname, struct delayed_call *done)
#else
static int ll_readlink_internal(struct inode *inode,
				struct ptlrpc_request **request, char **symname)
#endif
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	int rc, symlen = i_size_read(inode) + 1;
	struct mdt_body *body;
	struct md_op_data *op_data;

	ENTRY;

	*request = NULL;

	if (lli->lli_symlink_name) {
		int print_limit = min_t(int, PAGE_SIZE - 128, symlen);

		*symname = lli->lli_symlink_name;
		/*
		 * If the total CDEBUG() size is larger than a page, it
		 * will print a warning to the console, avoid this by
		 * printing just the last part of the symlink.
		 */
		CDEBUG(D_INODE, "using cached symlink %s%.*s, len = %d\n",
		       print_limit < symlen ? "..." : "", print_limit,
		       (*symname) + symlen - print_limit, symlen);
		RETURN(0);
	}

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, symlen,
                                     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_valid = OBD_MD_LINKNAME;
	rc = md_getattr(sbi->ll_md_exp, op_data, request);
	ll_finish_md_op_data(op_data);
	if (rc) {
		if (rc != -ENOENT)
			CERROR("%s: inode "DFID": rc = %d\n",
			       ll_i2sbi(inode)->ll_fsname,
			       PFID(ll_inode2fid(inode)), rc);
		GOTO(failed, rc);
	}

	body = req_capsule_server_get(&(*request)->rq_pill, &RMF_MDT_BODY);
	LASSERT(body != NULL);
	if ((body->mbo_valid & OBD_MD_LINKNAME) == 0) {
		CERROR("OBD_MD_LINKNAME not set on reply\n");
		GOTO(failed, rc = -EPROTO);
	}

	LASSERT(symlen != 0);
	if (body->mbo_eadatasize != symlen) {
		CERROR("%s: inode "DFID": symlink length %d not expected %d\n",
		       sbi->ll_fsname, PFID(ll_inode2fid(inode)),
		       body->mbo_eadatasize - 1, symlen - 1);
                GOTO(failed, rc = -EPROTO);
	}

	*symname = req_capsule_server_get(&(*request)->rq_pill, &RMF_MDT_MD);
	if (!*symname ||
	    (!IS_ENCRYPTED(inode) &&
	     strnlen(*symname, symlen) != symlen - 1)) {
		/* not full/NULL terminated */
		CERROR("%s: inode "DFID": symlink not NULL terminated string of length %d\n",
		       sbi->ll_fsname,
		       PFID(ll_inode2fid(inode)), symlen - 1);
		GOTO(failed, rc = -EPROTO);
	}

#ifdef HAVE_IOP_GET_LINK
	if (IS_ENCRYPTED(inode)) {
		const char *target = llcrypt_get_symlink(inode, *symname,
							 symlen, done);
		if (IS_ERR(target))
			RETURN(PTR_ERR(target));
		symlen = strlen(target) + 1;
		*symname = (char *)target;

		/* Do not cache symlink targets encoded without the key,
		 * since those become outdated once the key is added.
		 */
		if (!llcrypt_has_encryption_key(inode))
			RETURN(0);
	}
#endif

	OBD_ALLOC(lli->lli_symlink_name, symlen);
	/* do not return an error if we cannot cache the symlink locally */
	if (lli->lli_symlink_name) {
		memcpy(lli->lli_symlink_name, *symname, symlen);
		*symname = lli->lli_symlink_name;
	}
	RETURN(0);

failed:
	RETURN(rc);
}

#ifdef HAVE_SYMLINK_OPS_USE_NAMEIDATA
static void ll_put_link(struct dentry *dentry,
			struct nameidata *nd, void *cookie)
#else
# ifdef HAVE_IOP_GET_LINK
static void ll_put_link(void *cookie)
# else
static void ll_put_link(struct inode *unused, void *cookie)
# endif
#endif
{
	ptlrpc_req_finished(cookie);
}

#ifdef HAVE_SYMLINK_OPS_USE_NAMEIDATA
static void *ll_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	struct ptlrpc_request *request = NULL;
	int rc;
	char *symname = NULL;

	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op\n");
	/*
	 * Limit the recursive symlink depth to 5 instead of default
	 * 8 links when kernel has 4k stack to prevent stack overflow.
	 * For 8k stacks we need to limit it to 7 for local servers.
	 */
	if (THREAD_SIZE < 8192 && current->link_count >= 6) {
		rc = -ELOOP;
	} else if (THREAD_SIZE == 8192 && current->link_count >= 8) {
		rc = -ELOOP;
	} else {
		ll_inode_size_lock(inode);
		rc = ll_readlink_internal(inode, &request, &symname);
		ll_inode_size_unlock(inode);
	}
	if (rc) {
		ptlrpc_req_finished(request);
		request = NULL;
		symname = ERR_PTR(rc);
	}

	nd_set_link(nd, symname);
	/*
	 * symname may contain a pointer to the request message buffer,
	 * we delay request releasing until ll_put_link then.
	 */
	RETURN(request);
}
#else
# ifdef HAVE_IOP_GET_LINK
static const char *ll_get_link(struct dentry *dentry,
			       struct inode *inode,
			       struct delayed_call *done)
{
	struct ptlrpc_request *request;
	char *symname = NULL;
	int rc;

	ENTRY;
	CDEBUG(D_VFSTRACE, "VFS Op:name=%pd, inode="DFID"(%p)\n",
	       dentry, PFID(ll_inode2fid(inode)), inode);
	if (!dentry)
		RETURN(ERR_PTR(-ECHILD));
	ll_inode_size_lock(inode);
	rc = ll_readlink_internal(inode, &request, &symname, done);
	ll_inode_size_unlock(inode);
	if (rc < 0) {
		ptlrpc_req_finished(request);
		return ERR_PTR(rc);
	}

	/*
	 * symname may contain a pointer to the request message buffer,
	 * we delay request releasing then.
	 */
	set_delayed_call(done, ll_put_link, request);
	RETURN(symname);
}
# else
static const char *ll_follow_link(struct dentry *dentry, void **cookie)
{
	struct inode *inode = d_inode(dentry);
	struct ptlrpc_request *request;
	char *symname = NULL;
	int rc;

	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op\n");
	ll_inode_size_lock(inode);
	rc = ll_readlink_internal(inode, &request, &symname);
	ll_inode_size_unlock(inode);
	if (rc < 0) {
		ptlrpc_req_finished(request);
		return ERR_PTR(rc);
	}

	/*
	 * symname may contain a pointer to the request message buffer,
	 * we delay request releasing until ll_put_link then.
	 */
	*cookie = request;
	RETURN(symname);
}
# endif /* HAVE_IOP_GET_LINK */
#endif /* HAVE_SYMLINK_OPS_USE_NAMEIDATA */

/**
 * ll_getattr_link() - link-specific getattr to set the correct st_size
 *		       for encrypted symlinks
 *
 * Override st_size of encrypted symlinks to be the length of the decrypted
 * symlink target (or the no-key encoded symlink target, if the key is
 * unavailable) rather than the length of the encrypted symlink target. This is
 * necessary for st_size to match the symlink target that userspace actually
 * sees.  POSIX requires this, and some userspace programs depend on it.
 *
 * For non encrypted symlinks, this is a just calling ll_getattr().
 * For encrypted symlinks, this additionally requires reading the symlink target
 * from disk if needed, setting up the inode's encryption key if possible, and
 * then decrypting or encoding the symlink target.  This makes lstat() more
 * heavyweight than is normally the case.  However, decrypted symlink targets
 * will be cached in ->i_link, so usually the symlink won't have to be read and
 * decrypted again later if/when it is actually followed, readlink() is called,
 * or lstat() is called again.
 *
 * Return: 0 on success, -errno on failure
 */
#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_INODEOPS_ENHANCED_GETATTR)
static int ll_getattr_link(
#if defined(HAVE_USER_NAMESPACE_ARG)
			   struct mnt_idmap *map,
#endif
			   const struct path *path, struct kstat *stat,
			   u32 request_mask, unsigned int flags)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = d_inode(dentry);
	DEFINE_DELAYED_CALL(done);
	const char *link;
	int rc;

	rc = ll_getattr(map, path, stat, request_mask, flags);
	if (rc || !IS_ENCRYPTED(inode))
		return rc;

	/*
	 * To get the symlink target that userspace will see (whether it's the
	 * decrypted target or the no-key encoded target), we can just get it
	 * in the same way the VFS does during path resolution and readlink().
	 */
	link = READ_ONCE(inode->i_link);
	if (!link) {
		link = inode->i_op->get_link(dentry, inode, &done);
		if (IS_ERR(link))
			return PTR_ERR(link);
	}
	stat->size = strlen(link);
	do_delayed_call(&done);
	return 0;
}
#else /* HAVE_INODEOPS_ENHANCED_GETATTR */
#define ll_getattr_link ll_getattr
#endif

const struct inode_operations ll_fast_symlink_inode_operations = {
#ifdef HAVE_IOP_GENERIC_READLINK
	.readlink	= generic_readlink,
#endif
	.setattr	= ll_setattr,
#ifdef HAVE_IOP_GET_LINK
	.get_link	= ll_get_link,
#else
	.follow_link	= ll_follow_link,
	.put_link	= ll_put_link,
#endif
	.getattr	= ll_getattr_link,
	.permission	= ll_inode_permission,
#ifdef HAVE_IOP_XATTR
	.setxattr	= ll_setxattr,
	.getxattr	= ll_getxattr,
	.removexattr	= ll_removexattr,
#endif
	.listxattr	= ll_listxattr,
};
