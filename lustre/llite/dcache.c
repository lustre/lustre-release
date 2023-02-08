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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/quotaops.h>
#include <linux/kernel.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_dlm.h>

#include "llite_internal.h"

static void free_dentry_data(struct rcu_head *head)
{
	struct ll_dentry_data *lld;

	lld = container_of(head, struct ll_dentry_data, lld_rcu_head);
	OBD_FREE_PTR(lld);
}

/* should NOT be called with the dcache lock, see fs/dcache.c */
static void ll_release(struct dentry *de)
{
        struct ll_dentry_data *lld;
        ENTRY;
        LASSERT(de != NULL);
        lld = ll_d2d(de);
        if (lld == NULL) /* NFS copies the de->d_op methods (bug 4655) */
                RETURN_EXIT;

	de->d_fsdata = NULL;
	call_rcu(&lld->lld_rcu_head, free_dentry_data);

	EXIT;
}

/* Compare if two dentries are the same.  Don't match if the existing dentry
 * is marked invalid.  Returns 1 if different, 0 if the same.
 *
 * This avoids a race where ll_lookup_it() instantiates a dentry, but we get
 * an AST before calling d_revalidate_it().  The dentry still exists (marked
 * INVALID) so d_lookup() matches it, but we have no lock on it (so
 * lock_match() fails) and we spin around real_lookup().
 *
 * This race doesn't apply to lookups in d_alloc_parallel(), and for
 * those we want to ensure that only one dentry with a given name is
 * in ll_lookup_nd() at a time.  So allow invalid dentries to match
 * while d_in_lookup().  We will be called again when the lookup
 * completes, and can give a different answer then.
 */
#if defined(HAVE_D_COMPARE_5ARGS)
static int ll_dcompare(const struct dentry *parent, const struct dentry *dentry,
		       unsigned int len, const char *str,
		       const struct qstr *name)
#elif defined(HAVE_D_COMPARE_4ARGS)
static int ll_dcompare(const struct dentry *dentry, unsigned int len,
		       const char *str, const struct qstr *name)
#endif
{
	ENTRY;

	if (len != name->len)
		RETURN(1);

	if (memcmp(str, name->name, len))
		RETURN(1);

	CDEBUG(D_DENTRY, "found name %.*s(%p) flags %#x refc %d\n",
	       name->len, name->name, dentry, dentry->d_flags,
	       ll_d_count(dentry));

	/* mountpoint is always valid */
	if (d_mountpoint((struct dentry *)dentry))
		RETURN(0);

	/* ensure exclusion against parallel lookup of the same name */
	if (d_in_lookup((struct dentry *)dentry))
		return 0;

	if (d_lustre_invalid(dentry))
		RETURN(1);

	RETURN(0);
}

/**
 * Called when last reference to a dentry is dropped and dcache wants to know
 * whether or not it should cache it:
 * - return 1 to delete the dentry immediately
 * - return 0 to cache the dentry
 * Should NOT be called with the dcache lock, see fs/dcache.c
 */
static int ll_ddelete(const struct dentry *de)
{
	ENTRY;
	LASSERT(de);

	CDEBUG(D_DENTRY, "%s dentry %pd (%p, parent %p, inode %p) %s%s\n",
	       d_lustre_invalid(de) ? "deleting" : "keeping",
	       de, de, de->d_parent, de->d_inode,
	       d_unhashed((struct dentry *)de) ? "" : "hashed,",
	       list_empty(&de->d_subdirs) ? "" : "subdirs");

	/* kernel >= 2.6.38 last refcount is decreased after this function. */
	LASSERT(ll_d_count(de) == 1);

	if (d_lustre_invalid(de))
		RETURN(1);
	RETURN(0);
}

#ifdef HAVE_D_INIT
static int ll_d_init(struct dentry *de)
{
	struct ll_dentry_data *lld;

	OBD_ALLOC_PTR(lld);
	lld->lld_invalid = 1;
	de->d_fsdata = lld;
	return 0;
}
#else /* !HAVE_D_INIT */

bool ll_d_setup(struct dentry *de, bool do_put)
{
	struct ll_dentry_data *lld;
	bool success = true;

	if (de->d_fsdata)
		return success;

	OBD_ALLOC_PTR(lld);
	if (likely(lld)) {
		spin_lock(&de->d_lock);
		/* Since the first d_fsdata test was not
		 * done under the spinlock it could have
		 * changed by time the memory is allocated.
		 */
		if (!de->d_fsdata) {
			lld->lld_invalid = 1;
			de->d_fsdata = lld;
		}
		spin_unlock(&de->d_lock);
		/* See if we lost the race to set d_fsdata. */
		if (de->d_fsdata != lld)
			OBD_FREE_PTR(lld);
	} else {
		success = false;
		if (do_put)
			dput(de);
	}

	return success;
}
#endif /* !HAVE_D_INIT */

void ll_intent_drop_lock(struct lookup_intent *it)
{
	if (it->it_op && it->it_lock_mode) {
		struct lustre_handle handle;

		handle.cookie = it->it_lock_handle;

		CDEBUG(D_DLMTRACE, "releasing lock with cookie %#llx from it %p\n",
		       handle.cookie, it);
		ldlm_lock_decref(&handle, it->it_lock_mode);

		/* bug 494: intent_release may be called multiple times, from
		 * this thread and we don't want to double-decref this lock */
		it->it_lock_mode = 0;
		if (it->it_remote_lock_mode != 0) {
			handle.cookie = it->it_remote_lock_handle;

			CDEBUG(D_DLMTRACE,
			       "releasing remote lock with cookie %#llx from it %p\n",
			       handle.cookie, it);
			ldlm_lock_decref(&handle,
					 it->it_remote_lock_mode);
			it->it_remote_lock_mode = 0;
		}
	}
}

void ll_intent_release(struct lookup_intent *it)
{
        ENTRY;

        CDEBUG(D_INFO, "intent %p released\n", it);
        ll_intent_drop_lock(it);
        /* We are still holding extra reference on a request, need to free it */
        if (it_disposition(it, DISP_ENQ_OPEN_REF))
		ptlrpc_req_finished(it->it_request); /* ll_file_open */

	if (it_disposition(it, DISP_ENQ_CREATE_REF)) /* create rec */
		ptlrpc_req_finished(it->it_request);

	it->it_disposition = 0;
	it->it_request = NULL;
	EXIT;
}

/* mark aliases invalid and prune unused aliases */
void ll_prune_aliases(struct inode *inode)
{
	struct dentry *dentry;
	ENTRY;

	LASSERT(inode != NULL);

	CDEBUG(D_INODE, "marking dentries for inode "DFID"(%p) invalid\n",
	       PFID(ll_inode2fid(inode)), inode);

	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_alias)
		d_lustre_invalidate(dentry);
	spin_unlock(&inode->i_lock);

	d_prune_aliases(inode);

        EXIT;
}

int ll_revalidate_it_finish(struct ptlrpc_request *request,
			    struct lookup_intent *it,
			    struct dentry *de)
{
	struct inode *inode = de->d_inode;
	__u64 bits = 0;
	int rc = 0;

        ENTRY;

	if (!request)
		RETURN(0);

	if (it_disposition(it, DISP_LOOKUP_NEG))
		RETURN(-ENOENT);

	rc = ll_prep_inode(&inode, &request->rq_pill, NULL, it);
	if (rc)
		RETURN(rc);

	ll_set_lock_data(ll_i2sbi(inode)->ll_md_exp, inode, it,
			 &bits);
	if (bits & MDS_INODELOCK_LOOKUP) {
		ll_update_dir_depth(de->d_parent->d_inode, inode);
		if (!ll_d_setup(de, true))
			RETURN(-ENOMEM);
		d_lustre_revalidate(de);
	}

	RETURN(rc);
}

void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry)
{
	LASSERT(it != NULL);
	LASSERT(dentry != NULL);

	if (it->it_lock_mode && dentry->d_inode != NULL) {
		struct inode *inode = dentry->d_inode;
		struct ll_sb_info *sbi = ll_i2sbi(inode);

		CDEBUG(D_DLMTRACE, "setting l_data to inode "DFID"(%p)\n",
		       PFID(ll_inode2fid(inode)), inode);
		ll_set_lock_data(sbi->ll_md_exp, inode, it, NULL);
	}

	/* drop lookup or getattr locks immediately */
	if (it->it_op == IT_LOOKUP || it->it_op == IT_GETATTR)
		ll_intent_drop_lock(it);
}

static int ll_revalidate_dentry(struct dentry *dentry,
				unsigned int lookup_flags)
{
	struct inode *dir = dentry->d_parent->d_inode;
	int rc;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%s, flags=%u\n",
	       dentry->d_name.name, lookup_flags);

	rc = llcrypt_d_revalidate(dentry, lookup_flags);
	if (rc != 1)
		return rc;

	/* If this is intermediate component path lookup and we were able to get
	 * to this dentry, then its lock has not been revoked and the
	 * path component is valid. */
	if (lookup_flags & (LOOKUP_CONTINUE | LOOKUP_PARENT))
		return 1;

	/* Symlink - always valid as long as the dentry was found */
	/* only special case is to prevent ELOOP error from VFS during open
	 * of a foreign symlink file/dir with O_NOFOLLOW, like it happens for
	 * real symlinks. This will allow to open foreign symlink file/dir
	 * for get[dir]stripe/unlock ioctl()s.
	 */
	if (d_is_symlink(dentry)) {
		if (!S_ISLNK(dentry->d_inode->i_mode) &&
		    !(lookup_flags & LOOKUP_FOLLOW))
			return 0;
		else
			return 1;
	}

	/*
	 * VFS warns us that this is the second go around and previous
	 * operation failed (most likely open|creat), so this time
	 * we better talk to the server via the lookup path by name,
	 * not by fid.
	 */
	if (lookup_flags & LOOKUP_REVAL)
		return 0;

	if (lookup_flags & LOOKUP_RCU)
		return -ECHILD;

	if (dentry_may_statahead(dir, dentry))
		ll_revalidate_statahead(dir, &dentry, dentry->d_inode == NULL);

	return 1;
}

const struct dentry_operations ll_d_ops = {
#ifdef HAVE_D_INIT
	.d_init		= ll_d_init,
#endif
	.d_revalidate	= ll_revalidate_dentry,
	.d_release	= ll_release,
	.d_delete	= ll_ddelete,
	.d_compare	= ll_dcompare,
};
