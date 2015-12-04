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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/quotaops.h>
#include <linux/kernel.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre/lustre_idl.h>
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

        if (lld->lld_it) {
                ll_intent_release(lld->lld_it);
                OBD_FREE(lld->lld_it, sizeof(*lld->lld_it));
        }

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
 * lock_match() fails) and we spin around real_lookup(). */
#ifdef HAVE_D_COMPARE_7ARGS
static int ll_dcompare(const struct dentry *parent, const struct inode *pinode,
		       const struct dentry *dentry, const struct inode *inode,
		       unsigned int len, const char *str,
		       const struct qstr *name)
#elif defined(HAVE_D_COMPARE_5ARGS)
static int ll_dcompare(const struct dentry *parent, const struct dentry *dentry,
		       unsigned int len, const char *str,
		       const struct qstr *name)
#else
static int ll_dcompare(struct dentry *parent, struct qstr *d_name,
		       struct qstr *name)
#endif
{
#if !defined(HAVE_D_COMPARE_7ARGS) && !defined(HAVE_D_COMPARE_5ARGS)
	/* XXX: (ugh !) d_name must be in-dentry structure */
	struct dentry *dentry = container_of(d_name, struct dentry, d_name);
	unsigned int len = d_name->len;
	const char *str = d_name->name;
#endif
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

	if (d_lustre_invalid(dentry))
		RETURN(1);

	RETURN(0);
}

static inline int return_if_equal(struct ldlm_lock *lock, void *data)
{
	return (ldlm_is_canceling(lock) && ldlm_is_discard_data(lock)) ?
		LDLM_ITER_CONTINUE : LDLM_ITER_STOP;
}

/* find any ldlm lock of the inode in mdc and lov
 * return 0    not find
 *        1    find one
 *      < 0    error */
static int find_cbdata(struct inode *inode)
{
	struct lu_env			*env;
	__u16				refcheck;
	struct ll_sb_info		*sbi = ll_i2sbi(inode);
	int				rc = 0;
	ENTRY;

	LASSERT(inode);
	rc = md_find_cbdata(sbi->ll_md_exp, ll_inode2fid(inode),
			    return_if_equal, NULL);
	if (rc != 0)
		RETURN(rc);

	if (ll_i2info(inode)->lli_clob != NULL) {
		env = cl_env_get(&refcheck);
		if (IS_ERR(env))
			RETURN(PTR_ERR(env));

		rc = cl_object_find_cbdata(env, ll_i2info(inode)->lli_clob,
					   return_if_equal, NULL);
		cl_env_put(env, &refcheck);
	}

	RETURN(rc);
}

/**
 * Called when last reference to a dentry is dropped and dcache wants to know
 * whether or not it should cache it:
 * - return 1 to delete the dentry immediately
 * - return 0 to cache the dentry
 * Should NOT be called with the dcache lock, see fs/dcache.c
 */
static int ll_ddelete(HAVE_D_DELETE_CONST struct dentry *de)
{
	ENTRY;
	LASSERT(de);

	CDEBUG(D_DENTRY, "%s dentry %.*s (%p, parent %p, inode %p) %s%s\n",
	       d_lustre_invalid((struct dentry *)de) ? "deleting" : "keeping",
	       de->d_name.len, de->d_name.name, de, de->d_parent, de->d_inode,
	       d_unhashed((struct dentry *)de) ? "" : "hashed,",
	       list_empty(&de->d_subdirs) ? "" : "subdirs");

#ifdef HAVE_DCACHE_LOCK
	LASSERT(ll_d_count(de) == 0);
#else
	/* kernel >= 2.6.38 last refcount is decreased after this function. */
	LASSERT(ll_d_count(de) == 1);
#endif

	/* Disable this piece of code temproarily because this is called
	 * inside dcache_lock so it's not appropriate to do lots of work
	 * here. ATTENTION: Before this piece of code enabling, LU-2487 must be
	 * resolved. */
#if 0
	/* if not ldlm lock for this inode, set i_nlink to 0 so that
	 * this inode can be recycled later b=20433 */
	if (de->d_inode && !find_cbdata(de->d_inode))
		clear_nlink(de->d_inode);
#endif

	if (d_lustre_invalid((struct dentry *)de))
		RETURN(1);
	RETURN(0);
}

int ll_d_init(struct dentry *de)
{
	ENTRY;
	LASSERT(de != NULL);

	CDEBUG(D_DENTRY, "ldd on dentry %.*s (%p) parent %p inode %p refc %d\n",
		de->d_name.len, de->d_name.name, de, de->d_parent, de->d_inode,
		ll_d_count(de));

	if (de->d_fsdata == NULL) {
		struct ll_dentry_data *lld;

		OBD_ALLOC_PTR(lld);
		if (likely(lld != NULL)) {
			spin_lock(&de->d_lock);
			if (likely(de->d_fsdata == NULL)) {
				de->d_fsdata = lld;
				__d_lustre_invalidate(de);
#ifdef HAVE_DCACHE_LOCK
				/* kernel >= 2.6.38 d_op is set in d_alloc() */
				de->d_op = &ll_d_ops;
#endif
			} else {
				OBD_FREE_PTR(lld);
			}
			spin_unlock(&de->d_lock);
		} else {
			RETURN(-ENOMEM);
		}
	}
	LASSERT(de->d_op == &ll_d_ops);

	RETURN(0);
}

void ll_intent_drop_lock(struct lookup_intent *it)
{
        if (it->it_op && it->d.lustre.it_lock_mode) {
		struct lustre_handle handle;

		handle.cookie = it->d.lustre.it_lock_handle;

                CDEBUG(D_DLMTRACE, "releasing lock with cookie "LPX64
                       " from it %p\n", handle.cookie, it);
                ldlm_lock_decref(&handle, it->d.lustre.it_lock_mode);

                /* bug 494: intent_release may be called multiple times, from
                 * this thread and we don't want to double-decref this lock */
                it->d.lustre.it_lock_mode = 0;
		if (it->d.lustre.it_remote_lock_mode != 0) {
			handle.cookie = it->d.lustre.it_remote_lock_handle;

			CDEBUG(D_DLMTRACE, "releasing remote lock with cookie"
			       LPX64" from it %p\n", handle.cookie, it);
			ldlm_lock_decref(&handle,
					 it->d.lustre.it_remote_lock_mode);
			it->d.lustre.it_remote_lock_mode = 0;
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
		ptlrpc_req_finished(it->d.lustre.it_data); /* ll_file_open */

        if (it_disposition(it, DISP_ENQ_CREATE_REF)) /* create rec */
                ptlrpc_req_finished(it->d.lustre.it_data);

        it->d.lustre.it_disposition = 0;
        it->d.lustre.it_data = NULL;
        EXIT;
}

void ll_invalidate_aliases(struct inode *inode)
{
	struct dentry *dentry;
	DECLARE_LL_D_HLIST_NODE_PTR(p);
	ENTRY;

	LASSERT(inode != NULL);

	CDEBUG(D_INODE, "marking dentries for inode "DFID"(%p) invalid\n",
	       PFID(ll_inode2fid(inode)), inode);

	ll_lock_dcache(inode);
	ll_d_hlist_for_each_entry(dentry, p, &inode->i_dentry) {
		CDEBUG(D_DENTRY, "dentry in drop %.*s (%p) parent %p "
		       "inode %p flags %d\n", dentry->d_name.len,
		       dentry->d_name.name, dentry, dentry->d_parent,
		       dentry->d_inode, dentry->d_flags);

		if (unlikely(dentry == dentry->d_sb->s_root)) {
			CERROR("%s: called on root dentry=%p, fid="DFID"\n",
			       ll_get_fsname(dentry->d_sb, NULL, 0),
			       dentry, PFID(ll_inode2fid(inode)));
			lustre_dump_dentry(dentry, 1);
                        libcfs_debug_dumpstack(NULL);
                }

		d_lustre_invalidate(dentry, 0);
	}
	ll_unlock_dcache(inode);

        EXIT;
}

int ll_revalidate_it_finish(struct ptlrpc_request *request,
                            struct lookup_intent *it,
                            struct dentry *de)
{
        int rc = 0;
        ENTRY;

        if (!request)
                RETURN(0);

        if (it_disposition(it, DISP_LOOKUP_NEG))
                RETURN(-ENOENT);

        rc = ll_prep_inode(&de->d_inode, request, NULL, it);

        RETURN(rc);
}

void ll_lookup_finish_locks(struct lookup_intent *it, struct dentry *dentry)
{
        LASSERT(it != NULL);
        LASSERT(dentry != NULL);

        if (it->d.lustre.it_lock_mode && dentry->d_inode != NULL) {
                struct inode *inode = dentry->d_inode;
                struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);

		CDEBUG(D_DLMTRACE, "setting l_data to inode "DFID"(%p)\n",
		       PFID(ll_inode2fid(inode)), inode);
                ll_set_lock_data(sbi->ll_md_exp, inode, it, NULL);
        }

        /* drop lookup or getattr locks immediately */
        if (it->it_op == IT_LOOKUP || it->it_op == IT_GETATTR) {
                /* on 2.6 there are situation when several lookups and
                 * revalidations may be requested during single operation.
                 * therefore, we don't release intent here -bzzz */
                ll_intent_drop_lock(it);
        }
}

static int ll_revalidate_dentry(struct dentry *dentry,
				unsigned int lookup_flags)
{
	struct inode *dir = dentry->d_parent->d_inode;

	/* If this is intermediate component path lookup and we were able to get
	 * to this dentry, then its lock has not been revoked and the
	 * path component is valid. */
	if (lookup_flags & (LOOKUP_CONTINUE | LOOKUP_PARENT))
		return 1;

	/* Symlink - always valid as long as the dentry was found */
	if (dentry->d_inode && dentry->d_inode->i_op->follow_link)
		return 1;

	/* Last path component lookup for open or create - we always
	 * return 0 here to go through re-lookup and properly signal
	 * MDS whenever we do or do not want an open-cache to be engaged.
	 * For create we also ensure the entry is really created no matter
	 * what races might have happened.
	 * LU-4367 */
	if (lookup_flags & (LOOKUP_OPEN | LOOKUP_CREATE))
		return 0;

	if (!dentry_may_statahead(dir, dentry))
		return 1;

#ifndef HAVE_DCACHE_LOCK
	if (lookup_flags & LOOKUP_RCU)
		return -ECHILD;
#endif

	ll_statahead(dir, &dentry, dentry->d_inode == NULL);
	return 1;
}

/*
 * Always trust cached dentries. Update statahead window if necessary.
 */
#ifdef HAVE_IOP_ATOMIC_OPEN
static int ll_revalidate_nd(struct dentry *dentry, unsigned int flags)
{
	int rc;
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%s, flags=%u\n",
	       dentry->d_name.name, flags);

	rc = ll_revalidate_dentry(dentry, flags);
	RETURN(rc);
}
#else
static int ll_revalidate_nd(struct dentry *dentry, struct nameidata *nd)
{
	int rc;
	ENTRY;

	/*
	 * this is normally called from NFS export, and we don't know whether
	 * this is the last component.
	 */
	if (nd == NULL)
		RETURN(1);

	CDEBUG(D_VFSTRACE, "VFS Op:name=%s, flags=%u\n",
	       dentry->d_name.name, nd->flags);

	rc = ll_revalidate_dentry(dentry, nd->flags);
	RETURN(rc);
}
#endif

static void ll_d_iput(struct dentry *de, struct inode *inode)
{
	LASSERT(inode);
	if (!find_cbdata(inode))
		clear_nlink(inode);
	iput(inode);
}

const struct dentry_operations ll_d_ops = {
        .d_revalidate = ll_revalidate_nd,
        .d_release = ll_release,
        .d_delete  = ll_ddelete,
        .d_iput    = ll_d_iput,
        .d_compare = ll_dcompare,
};
