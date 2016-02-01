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
#include <linux/mm.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/security.h>
#include <linux/user_namespace.h>
#ifdef HAVE_UIDGID_HEADER
# include <linux/uidgid.h>
#endif

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_fid.h>
#include <lustre_dlm.h>
#include <lustre_ver.h>
#include "llite_internal.h"

static int ll_create_it(struct inode *dir, struct dentry *dentry,
			struct lookup_intent *it);

/* called from iget5_locked->find_inode() under inode_lock spinlock */
static int ll_test_inode(struct inode *inode, void *opaque)
{
	struct ll_inode_info	*lli = ll_i2info(inode);
	struct lustre_md	*md = opaque;

	if (unlikely(!(md->body->mbo_valid & OBD_MD_FLID))) {
		CERROR("MDS body missing FID\n");
		return 0;
	}

	if (!lu_fid_eq(&lli->lli_fid, &md->body->mbo_fid1))
		return 0;

	return 1;
}

static int ll_set_inode(struct inode *inode, void *opaque)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct mdt_body *body = ((struct lustre_md *)opaque)->body;

	if (unlikely(!(body->mbo_valid & OBD_MD_FLID))) {
		CERROR("MDS body missing FID\n");
		return -EINVAL;
	}

	lli->lli_fid = body->mbo_fid1;
	if (unlikely(!(body->mbo_valid & OBD_MD_FLTYPE))) {
		CERROR("Can not initialize inode "DFID" without object type: "
		       "valid = "LPX64"\n",
		       PFID(&lli->lli_fid), body->mbo_valid);
		return -EINVAL;
	}

	inode->i_mode = (inode->i_mode & ~S_IFMT) | (body->mbo_mode & S_IFMT);
	if (unlikely(inode->i_mode == 0)) {
		CERROR("Invalid inode "DFID" type\n", PFID(&lli->lli_fid));
		return -EINVAL;
	}

	ll_lli_init(lli);

	return 0;
}


/**
 * Get an inode by inode number(@hash), which is already instantiated by
 * the intent lookup).
 */
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *md)
{
	struct inode	*inode;
	int		rc = 0;

	ENTRY;

        LASSERT(hash != 0);
        inode = iget5_locked(sb, hash, ll_test_inode, ll_set_inode, md);
	if (inode == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	if (inode->i_state & I_NEW) {
		rc = ll_read_inode2(inode, md);
		if (rc == 0 && S_ISREG(inode->i_mode) &&
		    ll_i2info(inode)->lli_clob == NULL)
			rc = cl_file_inode_init(inode, md);

		if (rc != 0) {
			/* Let's clear directory lsm here, otherwise
			 * make_bad_inode() will reset the inode mode
			 * to regular, then ll_clear_inode will not
			 * be able to clear lsm_md */
			if (S_ISDIR(inode->i_mode))
				ll_dir_clear_lsm_md(inode);
			make_bad_inode(inode);
			unlock_new_inode(inode);
			iput(inode);
			inode = ERR_PTR(rc);
		} else {
			unlock_new_inode(inode);
		}
	} else if (!(inode->i_state & (I_FREEING | I_CLEAR))) {
		rc = ll_update_inode(inode, md);
		CDEBUG(D_VFSTRACE, "got inode: "DFID"(%p): rc = %d\n",
		       PFID(&md->body->mbo_fid1), inode, rc);
		if (rc != 0) {
			if (S_ISDIR(inode->i_mode))
				ll_dir_clear_lsm_md(inode);
			iput(inode);
			inode = ERR_PTR(rc);
		}
	}

        RETURN(inode);
}

static void ll_invalidate_negative_children(struct inode *dir)
{
	struct dentry *dentry, *tmp_subdir;
	DECLARE_LL_D_HLIST_NODE_PTR(p);

	ll_lock_dcache(dir);
	ll_d_hlist_for_each_entry(dentry, p, &dir->i_dentry) {
		spin_lock(&dentry->d_lock);
		if (!list_empty(&dentry->d_subdirs)) {
			struct dentry *child;

			list_for_each_entry_safe(child, tmp_subdir,
						 &dentry->d_subdirs,
						 d_child) {
				if (child->d_inode == NULL)
					d_lustre_invalidate(child, 1);
			}
		}
		spin_unlock(&dentry->d_lock);
	}
	ll_unlock_dcache(dir);
}

int ll_test_inode_by_fid(struct inode *inode, void *opaque)
{
	return lu_fid_eq(&ll_i2info(inode)->lli_fid, opaque);
}

int ll_md_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
		       void *data, int flag)
{
	struct lustre_handle lockh;
	int rc;
	ENTRY;

	switch (flag) {
	case LDLM_CB_BLOCKING:
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		if (rc < 0) {
			CDEBUG(D_INODE, "ldlm_cli_cancel: rc = %d\n", rc);
			RETURN(rc);
		}
		break;
	case LDLM_CB_CANCELING: {
		struct inode *inode = ll_inode_from_resource_lock(lock);
		__u64 bits = lock->l_policy_data.l_inodebits.bits;

		/* Inode is set to lock->l_resource->lr_lvb_inode
		 * for mdc - bug 24555 */
		LASSERT(lock->l_ast_data == NULL);

		if (inode == NULL)
			break;

		/* Invalidate all dentries associated with this inode */
		LASSERT(ldlm_is_canceling(lock));

		if (!fid_res_name_eq(ll_inode2fid(inode),
				     &lock->l_resource->lr_name)) {
			LDLM_ERROR(lock, "data mismatch with object "DFID"(%p)",
				   PFID(ll_inode2fid(inode)), inode);
			LBUG();
		}

		if (bits & MDS_INODELOCK_XATTR) {
			if (S_ISDIR(inode->i_mode))
				ll_i2info(inode)->lli_def_stripe_offset = -1;
			ll_xattr_cache_destroy(inode);
			bits &= ~MDS_INODELOCK_XATTR;
		}

		/* For OPEN locks we differentiate between lock modes
		 * LCK_CR, LCK_CW, LCK_PR - bug 22891 */
		if (bits & MDS_INODELOCK_OPEN)
			ll_have_md_lock(inode, &bits, lock->l_req_mode);

		if (bits & MDS_INODELOCK_OPEN) {
			fmode_t fmode;

			switch (lock->l_req_mode) {
			case LCK_CW:
				fmode = FMODE_WRITE;
				break;
			case LCK_PR:
				fmode = FMODE_EXEC;
				break;
			case LCK_CR:
				fmode = FMODE_READ;
				break;
			default:
				LDLM_ERROR(lock, "bad lock mode for OPEN lock");
				LBUG();
			}

			ll_md_real_close(inode, fmode);

			bits &= ~MDS_INODELOCK_OPEN;
		}

		if (bits & (MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE |
			    MDS_INODELOCK_LAYOUT | MDS_INODELOCK_PERM))
			ll_have_md_lock(inode, &bits, LCK_MINMODE);

		if (bits & MDS_INODELOCK_LAYOUT) {
			struct cl_object_conf conf = {
				.coc_opc = OBJECT_CONF_INVALIDATE,
				.coc_inode = inode,
			};

			rc = ll_layout_conf(inode, &conf);
			if (rc < 0)
				CDEBUG(D_INODE, "cannot invalidate layout of "
				       DFID": rc = %d\n",
				       PFID(ll_inode2fid(inode)), rc);
		}

		if ((bits & MDS_INODELOCK_UPDATE) && S_ISDIR(inode->i_mode)) {
			struct ll_inode_info *lli = ll_i2info(inode);

			CDEBUG(D_INODE, "invalidating inode "DFID" lli = %p, "
			       "pfid  = "DFID"\n", PFID(ll_inode2fid(inode)),
			       lli, PFID(&lli->lli_pfid));
			truncate_inode_pages(inode->i_mapping, 0);

			if (unlikely(!fid_is_zero(&lli->lli_pfid))) {
				struct inode *master_inode = NULL;
				unsigned long hash;

				/* This is slave inode, since all of the child
				 * dentry is connected on the master inode, so
				 * we have to invalidate the negative children
				 * on master inode */
				CDEBUG(D_INODE, "Invalidate s"DFID" m"DFID"\n",
				       PFID(ll_inode2fid(inode)),
				       PFID(&lli->lli_pfid));

				hash = cl_fid_build_ino(&lli->lli_pfid,
					ll_need_32bit_api(ll_i2sbi(inode)));

				/* Do not lookup the inode with ilookup5,
				 * otherwise it will cause dead lock,
				 *
				 * 1. Client1 send chmod req to the MDT0, then
				 * on MDT0, it enqueues master and all of its
				 * slaves lock, (mdt_attr_set() ->
				 * mdt_lock_slaves()), after gets master and
				 * stripe0 lock, it will send the enqueue req
				 * (for stripe1) to MDT1, then MDT1 finds the
				 * lock has been granted to client2. Then MDT1
				 * sends blocking ast to client2.
				 *
				 * 2. At the same time, client2 tries to unlink
				 * the striped dir (rm -rf striped_dir), and
				 * during lookup, it will hold the master inode
				 * of the striped directory, whose inode state
				 * is NEW, then tries to revalidate all of its
				 * slaves, (ll_prep_inode()->ll_iget()->
				 * ll_read_inode2()-> ll_update_inode().). And
				 * it will be blocked on the server side because
				 * of 1.
				 *
				 * 3. Then the client get the blocking_ast req,
				 * cancel the lock, but being blocked if using
				 * ->ilookup5()), because master inode state is
				 *  NEW. */
				master_inode = ilookup5_nowait(inode->i_sb,
						    hash, ll_test_inode_by_fid,
							(void *)&lli->lli_pfid);
				if (master_inode != NULL &&
					!IS_ERR(master_inode)) {
					ll_invalidate_negative_children(
								master_inode);
					iput(master_inode);
				}
			} else {
				ll_invalidate_negative_children(inode);
			}
		}

		if ((bits & (MDS_INODELOCK_LOOKUP | MDS_INODELOCK_PERM)) &&
		    inode->i_sb->s_root != NULL &&
		    inode != inode->i_sb->s_root->d_inode)
			ll_invalidate_aliases(inode);

		iput(inode);
		break;
	}
	default:
		LBUG();
	}

	RETURN(0);
}

__u32 ll_i2suppgid(struct inode *i)
{
	if (in_group_p(i->i_gid))
		return (__u32)from_kgid(&init_user_ns, i->i_gid);
	else
		return (__u32) __kgid_val(INVALID_GID);
}

/* Pack the required supplementary groups into the supplied groups array.
 * If we don't need to use the groups from the target inode(s) then we
 * instead pack one or more groups from the user's supplementary group
 * array in case it might be useful.  Not needed if doing an MDS-side upcall. */
void ll_i2gids(__u32 *suppgids, struct inode *i1, struct inode *i2)
{
	LASSERT(i1 != NULL);
	LASSERT(suppgids != NULL);

	suppgids[0] = ll_i2suppgid(i1);

	if (i2)
		suppgids[1] = ll_i2suppgid(i2);
	else
		suppgids[1] = -1;
}

/*
 * try to reuse three types of dentry:
 * 1. unhashed alias, this one is unhashed by d_invalidate (but it may be valid
 *    by concurrent .revalidate).
 * 2. INVALID alias (common case for no valid ldlm lock held, but this flag may
 *    be cleared by others calling d_lustre_revalidate).
 * 3. DISCONNECTED alias.
 */
static struct dentry *ll_find_alias(struct inode *inode, struct dentry *dentry)
{
	struct dentry *alias, *discon_alias, *invalid_alias;
	DECLARE_LL_D_HLIST_NODE_PTR(p);

	if (ll_d_hlist_empty(&inode->i_dentry))
		return NULL;

	discon_alias = invalid_alias = NULL;

	ll_lock_dcache(inode);
	ll_d_hlist_for_each_entry(alias, p, &inode->i_dentry) {
		LASSERT(alias != dentry);

		spin_lock(&alias->d_lock);
		if (alias->d_flags & DCACHE_DISCONNECTED)
			/* LASSERT(last_discon == NULL); LU-405, bz 20055 */
			discon_alias = alias;
		else if (alias->d_parent == dentry->d_parent             &&
			 alias->d_name.hash == dentry->d_name.hash       &&
			 alias->d_name.len == dentry->d_name.len         &&
			 memcmp(alias->d_name.name, dentry->d_name.name,
				dentry->d_name.len) == 0)
			invalid_alias = alias;
		spin_unlock(&alias->d_lock);

		if (invalid_alias)
			break;
	}
	alias = invalid_alias ?: discon_alias ?: NULL;
	if (alias) {
		spin_lock(&alias->d_lock);
		dget_dlock(alias);
		spin_unlock(&alias->d_lock);
	}
	ll_unlock_dcache(inode);

	return alias;
}

/*
 * Similar to d_splice_alias(), but lustre treats invalid alias
 * similar to DCACHE_DISCONNECTED, and tries to use it anyway.
 */
struct dentry *ll_splice_alias(struct inode *inode, struct dentry *de)
{
	struct dentry *new;
	int rc;

	if (inode) {
		new = ll_find_alias(inode, de);
		if (new) {
			rc = ll_d_init(new);
			if (rc < 0) {
				dput(new);
				return ERR_PTR(rc);
			}
			d_move(new, de);
			iput(inode);
			CDEBUG(D_DENTRY,
			       "Reuse dentry %p inode %p refc %d flags %#x\n",
			      new, new->d_inode, ll_d_count(new), new->d_flags);
			return new;
		}
	}
	rc = ll_d_init(de);
	if (rc < 0)
		return ERR_PTR(rc);
	d_add(de, inode);
	CDEBUG(D_DENTRY, "Add dentry %p inode %p refc %d flags %#x\n",
	       de, de->d_inode, ll_d_count(de), de->d_flags);
        return de;
}

static int ll_lookup_it_finish(struct ptlrpc_request *request,
			       struct lookup_intent *it,
			       struct inode *parent, struct dentry **de)
{
	struct inode		 *inode = NULL;
	__u64			  bits = 0;
	int			  rc;
	ENTRY;

	/* NB 1 request reference will be taken away by ll_intent_lock()
	 * when I return */
	CDEBUG(D_DENTRY, "it %p it_disposition %x\n", it,
	       it->d.lustre.it_disposition);
	if (!it_disposition(it, DISP_LOOKUP_NEG)) {
                rc = ll_prep_inode(&inode, request, (*de)->d_sb, it);
                if (rc)
                        RETURN(rc);

                ll_set_lock_data(ll_i2sbi(parent)->ll_md_exp, inode, it, &bits);

                /* We used to query real size from OSTs here, but actually
                   this is not needed. For stat() calls size would be updated
                   from subsequent do_revalidate()->ll_inode_revalidate_it() in
                   2.4 and
                   vfs_getattr_it->ll_getattr()->ll_inode_revalidate_it() in 2.6
                   Everybody else who needs correct file size would call
                   ll_glimpse_size or some equivalent themselves anyway.
                   Also see bug 7198. */
	}

	/* Only hash *de if it is unhashed (new dentry).
	 * Atoimc_open may passin hashed dentries for open.
	 */
	if (d_unhashed(*de)) {
		struct dentry *alias;

		alias = ll_splice_alias(inode, *de);
		if (IS_ERR(alias))
			GOTO(out, rc = PTR_ERR(alias));

		*de = alias;
	} else if (!it_disposition(it, DISP_LOOKUP_NEG)  &&
		   !it_disposition(it, DISP_OPEN_CREATE)) {
		/* With DISP_OPEN_CREATE dentry will
		   instantiated in ll_create_it. */
		LASSERT((*de)->d_inode == NULL);
		d_instantiate(*de, inode);
	}

	if (!it_disposition(it, DISP_LOOKUP_NEG)) {
		/* we have lookup look - unhide dentry */
		if (bits & MDS_INODELOCK_LOOKUP)
			d_lustre_revalidate(*de);
	} else if (!it_disposition(it, DISP_OPEN_CREATE)) {
		/* If file created on server, don't depend on parent UPDATE
		 * lock to unhide it. It is left hidden and next lookup can
		 * find it in ll_splice_alias.
		 */
		/* Check that parent has UPDATE lock. */
		struct lookup_intent parent_it = {
					.it_op = IT_GETATTR,
					.d.lustre.it_lock_handle = 0 };
		struct lu_fid	fid = ll_i2info(parent)->lli_fid;

		/* If it is striped directory, get the real stripe parent */
		if (unlikely(ll_i2info(parent)->lli_lsm_md != NULL)) {
			rc = md_get_fid_from_lsm(ll_i2mdexp(parent),
						 ll_i2info(parent)->lli_lsm_md,
						 (*de)->d_name.name,
						 (*de)->d_name.len, &fid);
			if (rc != 0)
				GOTO(out, rc);
		}

		if (md_revalidate_lock(ll_i2mdexp(parent), &parent_it, &fid,
				       NULL)) {
			d_lustre_revalidate(*de);
			ll_intent_release(&parent_it);
		}
	}

	GOTO(out, rc = 0);

out:
	if (rc != 0 && it->it_op & IT_OPEN)
		ll_open_cleanup((*de)->d_sb, request);

	return rc;
}

static struct dentry *ll_lookup_it(struct inode *parent, struct dentry *dentry,
				   struct lookup_intent *it)
{
	struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
	struct dentry *save = dentry, *retval;
	struct ptlrpc_request *req = NULL;
	struct md_op_data *op_data = NULL;
        __u32 opc;
        int rc;
        ENTRY;

        if (dentry->d_name.len > ll_i2sbi(parent)->ll_namelen)
                RETURN(ERR_PTR(-ENAMETOOLONG));

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p), intent=%s\n",
	       dentry->d_name.len, dentry->d_name.name,
	       PFID(ll_inode2fid(parent)), parent, LL_IT2STR(it));

        if (d_mountpoint(dentry))
                CERROR("Tell Peter, lookup on mtpt, it %s\n", LL_IT2STR(it));

	if (it == NULL || it->it_op == IT_GETXATTR)
		it = &lookup_it;

	if (it->it_op == IT_GETATTR && dentry_may_statahead(parent, dentry)) {
		rc = ll_statahead(parent, &dentry, 0);
		if (rc == 1)
			RETURN(dentry == save ? NULL : dentry);
	}

	if (it->it_op & IT_OPEN && it->it_flags & FMODE_WRITE &&
	    dentry->d_sb->s_flags & MS_RDONLY)
		RETURN(ERR_PTR(-EROFS));

	if (it->it_op & IT_CREAT)
		opc = LUSTRE_OPC_CREATE;
	else
		opc = LUSTRE_OPC_ANY;

	op_data = ll_prep_md_op_data(NULL, parent, NULL, dentry->d_name.name,
				     dentry->d_name.len, 0, opc, NULL);
	if (IS_ERR(op_data))
		RETURN((void *)op_data);

	/* enforce umask if acl disabled or MDS doesn't support umask */
	if (!IS_POSIXACL(parent) || !exp_connect_umask(ll_i2mdexp(parent)))
		it->it_create_mode &= ~current_umask();

	rc = md_intent_lock(ll_i2mdexp(parent), op_data, it, &req,
			    &ll_md_blocking_ast, 0);
	/* If the MDS allows the client to chgrp (CFS_SETGRP_PERM), but the
	 * client does not know which suppgid should be sent to the MDS, or
	 * some other(s) changed the target file's GID after this RPC sent
	 * to the MDS with the suppgid as the original GID, then we should
	 * try again with right suppgid. */
	if (rc == -EACCES && it->it_op & IT_OPEN &&
	    it_disposition(it, DISP_OPEN_DENY)) {
		struct mdt_body *body;

		LASSERT(req != NULL);

		body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
		if (op_data->op_suppgids[0] == body->mbo_gid ||
		    op_data->op_suppgids[1] == body->mbo_gid ||
		    !in_group_p(make_kgid(&init_user_ns, body->mbo_gid)))
			GOTO(out, retval = ERR_PTR(-EACCES));

		fid_zero(&op_data->op_fid2);
		op_data->op_suppgids[1] = body->mbo_gid;
		ptlrpc_req_finished(req);
		req = NULL;
		ll_intent_release(it);
		rc = md_intent_lock(ll_i2mdexp(parent), op_data, it, &req,
				    &ll_md_blocking_ast, 0);
	}

	if (rc < 0)
		GOTO(out, retval = ERR_PTR(rc));

	rc = ll_lookup_it_finish(req, it, parent, &dentry);
        if (rc != 0) {
                ll_intent_release(it);
                GOTO(out, retval = ERR_PTR(rc));
        }

        if ((it->it_op & IT_OPEN) && dentry->d_inode &&
            !S_ISREG(dentry->d_inode->i_mode) &&
            !S_ISDIR(dentry->d_inode->i_mode)) {
                ll_release_openhandle(dentry, it);
        }
        ll_lookup_finish_locks(it, dentry);

	GOTO(out, retval = (dentry == save) ? NULL : dentry);

out:
	if (op_data != NULL && !IS_ERR(op_data))
		ll_finish_md_op_data(op_data);

	ptlrpc_req_finished(req);
	return retval;
}

#ifdef HAVE_IOP_ATOMIC_OPEN
static struct dentry *ll_lookup_nd(struct inode *parent, struct dentry *dentry,
				   unsigned int flags)
{
	struct lookup_intent *itp, it = { .it_op = IT_GETATTR };
	struct dentry *de;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p), flags=%u\n",
	       dentry->d_name.len, dentry->d_name.name,
	       PFID(ll_inode2fid(parent)), parent, flags);

	/* Optimize away (CREATE && !OPEN). Let .create handle the race. */
	if ((flags & LOOKUP_CREATE) && !(flags & LOOKUP_OPEN))
		return NULL;

	if (flags & (LOOKUP_PARENT|LOOKUP_OPEN|LOOKUP_CREATE))
		itp = NULL;
	else
		itp = &it;
	de = ll_lookup_it(parent, dentry, itp);

	if (itp != NULL)
		ll_intent_release(itp);

	return de;
}

/*
 * For cached negative dentry and new dentry, handle lookup/create/open
 * together.
 */
static int ll_atomic_open(struct inode *dir, struct dentry *dentry,
			  struct file *file, unsigned open_flags,
			  umode_t mode, int *opened)
{
	struct lookup_intent *it;
	struct dentry *de;
	long long lookup_flags = LOOKUP_OPEN;
	int rc = 0;
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p), file %p,"
			   "open_flags %x, mode %x opened %d\n",
	       dentry->d_name.len, dentry->d_name.name,
	       PFID(ll_inode2fid(dir)), dir, file, open_flags, mode, *opened);

	OBD_ALLOC(it, sizeof(*it));
	if (!it)
		RETURN(-ENOMEM);

	it->it_op = IT_OPEN;
	if (open_flags & O_CREAT) {
		it->it_op |= IT_CREAT;
		lookup_flags |= LOOKUP_CREATE;
	}
	it->it_create_mode = (mode & S_IALLUGO) | S_IFREG;
	it->it_flags = (open_flags & ~O_ACCMODE) | OPEN_FMODE(open_flags);
	it->it_flags &= ~MDS_OPEN_FL_INTERNAL;

	/* Dentry added to dcache tree in ll_lookup_it */
	de = ll_lookup_it(dir, dentry, it);
	if (IS_ERR(de))
		rc = PTR_ERR(de);
	else if (de != NULL)
		dentry = de;

	if (!rc) {
		if (it_disposition(it, DISP_OPEN_CREATE)) {
			/* Dentry instantiated in ll_create_it. */
			rc = ll_create_it(dir, dentry, it);
			if (rc) {
				/* We dget in ll_splice_alias. */
				if (de != NULL)
					dput(de);
				goto out_release;
			}

			*opened |= FILE_CREATED;
		}
		if (dentry->d_inode && it_disposition(it, DISP_OPEN_OPEN)) {
			/* Open dentry. */
			if (S_ISFIFO(dentry->d_inode->i_mode)) {
				/* We cannot call open here as it would
				 * deadlock.
				 */
				if (it_disposition(it, DISP_ENQ_OPEN_REF))
					ptlrpc_req_finished(
						       (struct ptlrpc_request *)
							  it->d.lustre.it_data);
				rc = finish_no_open(file, de);
			} else {
				file->private_data = it;
				rc = finish_open(file, dentry, NULL, opened);
				/* We dget in ll_splice_alias. finish_open takes
				 * care of dget for fd open.
				 */
				if (de != NULL)
					dput(de);
			}
		} else {
			rc = finish_no_open(file, de);
		}
	}

out_release:
	ll_intent_release(it);
	OBD_FREE(it, sizeof(*it));

	RETURN(rc);
}

#else /* !HAVE_IOP_ATOMIC_OPEN */
static struct lookup_intent *
ll_convert_intent(struct open_intent *oit, int lookup_flags)
{
	struct lookup_intent *it;

	OBD_ALLOC_PTR(it);
	if (!it)
		return ERR_PTR(-ENOMEM);

	if (lookup_flags & LOOKUP_OPEN) {
		it->it_op = IT_OPEN;
		if (lookup_flags & LOOKUP_CREATE)
			it->it_op |= IT_CREAT;
		it->it_create_mode = (oit->create_mode & S_IALLUGO) | S_IFREG;
		it->it_flags = ll_namei_to_lookup_intent_flag(oit->flags);
		it->it_flags &= ~MDS_OPEN_FL_INTERNAL;
	} else {
		it->it_op = IT_GETATTR;
	}

	return it;
}

static struct dentry *ll_lookup_nd(struct inode *parent, struct dentry *dentry,
                                   struct nameidata *nd)
{
        struct dentry *de;
        ENTRY;

        if (nd && !(nd->flags & (LOOKUP_CONTINUE|LOOKUP_PARENT))) {
                struct lookup_intent *it;

                if (ll_d2d(dentry) && ll_d2d(dentry)->lld_it) {
                        it = ll_d2d(dentry)->lld_it;
                        ll_d2d(dentry)->lld_it = NULL;
                } else {
			if ((nd->flags & LOOKUP_CREATE) &&
			    !(nd->flags & LOOKUP_OPEN))
                                RETURN(NULL);

                        it = ll_convert_intent(&nd->intent.open, nd->flags);
                        if (IS_ERR(it))
                                RETURN((struct dentry *)it);
                }

		de = ll_lookup_it(parent, dentry, it);
                if (de)
                        dentry = de;
                if ((nd->flags & LOOKUP_OPEN) && !IS_ERR(dentry)) { /* Open */
                        if (dentry->d_inode &&
                            it_disposition(it, DISP_OPEN_OPEN)) { /* nocreate */
                                if (S_ISFIFO(dentry->d_inode->i_mode)) {
                                        // We cannot call open here as it would
                                        // deadlock.
                                        ptlrpc_req_finished(
                                                       (struct ptlrpc_request *)
                                                          it->d.lustre.it_data);
                                } else {
					struct file *filp;

					nd->intent.open.file->private_data = it;
					filp = lookup_instantiate_filp(nd,
								       dentry,
								       NULL);
					if (IS_ERR(filp)) {
						if (de)
							dput(de);
						de = (struct dentry *)filp;
					}
                                }
                        } else if (it_disposition(it, DISP_OPEN_CREATE)) {
                                // XXX This can only reliably work on assumption
                                // that there are NO hashed negative dentries.
                                ll_d2d(dentry)->lld_it = it;
                                it = NULL; /* Will be freed in ll_create_nd */
                                /* We absolutely depend on ll_create_nd to be
                                 * called to not leak this intent and possible
                                 * data attached to it */
                        }
                }

                if (it) {
                        ll_intent_release(it);
                        OBD_FREE(it, sizeof(*it));
                }
        } else {
		de = ll_lookup_it(parent, dentry, NULL);
	}

	RETURN(de);
}
#endif /* HAVE_IOP_ATOMIC_OPEN */

/* We depend on "mode" being set with the proper file type/umask by now */
static struct inode *ll_create_node(struct inode *dir, struct lookup_intent *it)
{
        struct inode *inode = NULL;
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int rc;
        ENTRY;

        LASSERT(it && it->d.lustre.it_disposition);

        LASSERT(it_disposition(it, DISP_ENQ_CREATE_REF));
        request = it->d.lustre.it_data;
        it_clear_disposition(it, DISP_ENQ_CREATE_REF);
        rc = ll_prep_inode(&inode, request, dir->i_sb, it);
        if (rc)
                GOTO(out, inode = ERR_PTR(rc));

	LASSERT(ll_d_hlist_empty(&inode->i_dentry));

        /* We asked for a lock on the directory, but were granted a
         * lock on the inode.  Since we finally have an inode pointer,
         * stuff it in the lock. */
	CDEBUG(D_DLMTRACE, "setting l_ast_data to inode "DFID"(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);
        ll_set_lock_data(sbi->ll_md_exp, inode, it, NULL);
        EXIT;
 out:
        ptlrpc_req_finished(request);
        return inode;
}

/*
 * By the time this is called, we already have created the directory cache
 * entry for the new file, but it is so far negative - it has no inode.
 *
 * We defer creating the OBD object(s) until open, to keep the intent and
 * non-intent code paths similar, and also because we do not have the MDS
 * inode number before calling ll_create_node() (which is needed for LOV),
 * so we would need to do yet another RPC to the MDS to store the LOV EA
 * data on the MDS.  If needed, we would pass the PACKED lmm as data and
 * lmm_size in datalen (the MDS still has code which will handle that).
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int ll_create_it(struct inode *dir, struct dentry *dentry,
			struct lookup_intent *it)
{
	struct inode *inode;
	int rc = 0;
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p), intent=%s\n",
	       dentry->d_name.len, dentry->d_name.name,
	       PFID(ll_inode2fid(dir)), dir, LL_IT2STR(it));

	rc = it_open_error(DISP_OPEN_CREATE, it);
	if (rc)
		RETURN(rc);

	inode = ll_create_node(dir, it);
	if (IS_ERR(inode))
		RETURN(PTR_ERR(inode));

	d_instantiate(dentry, inode);

	rc = ll_init_security(dentry, inode, dir);
	if (rc)
		RETURN(rc);

	RETURN(0);
}

void ll_update_times(struct ptlrpc_request *request, struct inode *inode)
{
	struct mdt_body *body = req_capsule_server_get(&request->rq_pill,
						       &RMF_MDT_BODY);

	LASSERT(body);
	if (body->mbo_valid & OBD_MD_FLMTIME &&
	    body->mbo_mtime > LTIME_S(inode->i_mtime)) {
		CDEBUG(D_INODE, "setting fid "DFID" mtime from %lu to "LPU64
		       "\n", PFID(ll_inode2fid(inode)),
		       LTIME_S(inode->i_mtime), body->mbo_mtime);
		LTIME_S(inode->i_mtime) = body->mbo_mtime;
	}

	if (body->mbo_valid & OBD_MD_FLCTIME &&
	    body->mbo_ctime > LTIME_S(inode->i_ctime))
		LTIME_S(inode->i_ctime) = body->mbo_ctime;
}

static int ll_new_node(struct inode *dir, struct dentry *dchild,
		       const char *tgt, umode_t mode, int rdev, __u32 opc)
{
	struct qstr *name = &dchild->d_name;
        struct ptlrpc_request *request = NULL;
        struct md_op_data *op_data;
        struct inode *inode = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        int tgt_len = 0;
        int err;

        ENTRY;
        if (unlikely(tgt != NULL))
                tgt_len = strlen(tgt) + 1;

again:
        op_data = ll_prep_md_op_data(NULL, dir, NULL, name->name,
                                     name->len, 0, opc, NULL);
        if (IS_ERR(op_data))
                GOTO(err_exit, err = PTR_ERR(op_data));

	err = md_create(sbi->ll_md_exp, op_data, tgt, tgt_len, mode,
			from_kuid(&init_user_ns, current_fsuid()),
			from_kgid(&init_user_ns, current_fsgid()),
			cfs_curproc_cap_pack(), rdev, &request);
	ll_finish_md_op_data(op_data);
	if (err < 0 && err != -EREMOTE)
		GOTO(err_exit, err);

	/* If the client doesn't know where to create a subdirectory (or
	 * in case of a race that sends the RPC to the wrong MDS), the
	 * MDS will return -EREMOTE and the client will fetch the layout
	 * of the directory, then create the directory on the right MDT. */
	if (unlikely(err == -EREMOTE)) {
		struct ll_inode_info	*lli = ll_i2info(dir);
		struct lmv_user_md	*lum;
		int			lumsize;
		int			err2;

		ptlrpc_req_finished(request);
		request = NULL;

		err2 = ll_dir_getstripe(dir, (void **)&lum, &lumsize, &request,
					OBD_MD_DEFAULT_MEA);
		if (err2 == 0) {
			/* Update stripe_offset and retry */
			lli->lli_def_stripe_offset = lum->lum_stripe_offset;
		} else if (err2 == -ENODATA &&
			   lli->lli_def_stripe_offset != -1) {
			/* If there are no default stripe EA on the MDT, but the
			 * client has default stripe, then it probably means
			 * default stripe EA has just been deleted. */
			lli->lli_def_stripe_offset = -1;
		} else {
			GOTO(err_exit, err);
		}

		ptlrpc_req_finished(request);
		request = NULL;
		goto again;
	}

        ll_update_times(request, dir);

	err = ll_prep_inode(&inode, request, dchild->d_sb, NULL);
	if (err)
		GOTO(err_exit, err);

	d_instantiate(dchild, inode);

	err = ll_init_security(dchild, inode, dir);
	if (err)
		GOTO(err_exit, err);

        EXIT;
err_exit:
	if (request != NULL)
		ptlrpc_req_finished(request);

        return err;
}

static int ll_mknod(struct inode *dir, struct dentry *dchild, ll_umode_t mode,
		    dev_t rdev)
{
	struct qstr *name = &dchild->d_name;
	int err;
        ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p) mode %o dev %x\n",
	       name->len, name->name, PFID(ll_inode2fid(dir)), dir,
               mode, rdev);

	if (!IS_POSIXACL(dir) || !exp_connect_umask(ll_i2mdexp(dir)))
		mode &= ~current_umask();

        switch (mode & S_IFMT) {
        case 0:
                mode |= S_IFREG; /* for mode = 0 case, fallthrough */
        case S_IFREG:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
		err = ll_new_node(dir, dchild, NULL, mode, old_encode_dev(rdev),
				  LUSTRE_OPC_MKNOD);
                break;
        case S_IFDIR:
                err = -EPERM;
                break;
        default:
                err = -EINVAL;
        }

        if (!err)
                ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_MKNOD, 1);

        RETURN(err);
}

#ifdef HAVE_IOP_ATOMIC_OPEN
/*
 * Plain create. Intent create is handled in atomic_open.
 */
static int ll_create_nd(struct inode *dir, struct dentry *dentry,
			umode_t mode, bool want_excl)
{
	int rc;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p), "
			   "flags=%u, excl=%d\n", dentry->d_name.len,
	       dentry->d_name.name, PFID(ll_inode2fid(dir)),
	       dir, mode, want_excl);

	rc = ll_mknod(dir, dentry, mode, 0);

	ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_CREATE, 1);

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, unhashed %d\n",
	       dentry->d_name.len, dentry->d_name.name, d_unhashed(dentry));

	return rc;
}
#else /* !HAVE_IOP_ATOMIC_OPEN */
static int ll_create_nd(struct inode *dir, struct dentry *dentry,
			ll_umode_t mode, struct nameidata *nd)
{
	struct ll_dentry_data *lld = ll_d2d(dentry);
	struct lookup_intent *it = NULL;
        int rc;

	if (lld != NULL)
		it = lld->lld_it;

        if (!it)
		return ll_mknod(dir, dentry, mode, 0);

	lld->lld_it = NULL;

        /* Was there an error? Propagate it! */
        if (it->d.lustre.it_status) {
                rc = it->d.lustre.it_status;
                goto out;
        }

	rc = ll_create_it(dir, dentry, it);
        if (nd && (nd->flags & LOOKUP_OPEN) && dentry->d_inode) { /* Open */
		struct file *filp;

		nd->intent.open.file->private_data = it;
		filp = lookup_instantiate_filp(nd, dentry, NULL);
		if (IS_ERR(filp))
			rc = PTR_ERR(filp);
        }

out:
        ll_intent_release(it);
        OBD_FREE(it, sizeof(*it));

        if (!rc)
                ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_CREATE, 1);

        return rc;
}
#endif /* HAVE_IOP_ATOMIC_OPEN */

static int ll_symlink(struct inode *dir, struct dentry *dchild,
		      const char *oldpath)
{
	struct qstr *name = &dchild->d_name;
	int err;
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p), target=%.*s\n",
	       name->len, name->name, PFID(ll_inode2fid(dir)),
	       dir, 3000, oldpath);

	err = ll_new_node(dir, dchild, oldpath, S_IFLNK | S_IRWXUGO, 0,
			  LUSTRE_OPC_SYMLINK);

        if (!err)
                ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_SYMLINK, 1);

        RETURN(err);
}

static int ll_link(struct dentry *old_dentry, struct inode *dir,
		   struct dentry *new_dentry)
{
	struct inode *src = old_dentry->d_inode;
	struct qstr *name = &new_dentry->d_name;
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct ptlrpc_request *request = NULL;
	struct md_op_data *op_data;
	int err;

	ENTRY;
	CDEBUG(D_VFSTRACE, "VFS Op: inode="DFID"(%p), dir="DFID"(%p), "
	       "target=%.*s\n", PFID(ll_inode2fid(src)), src,
	       PFID(ll_inode2fid(dir)), dir, name->len, name->name);

        op_data = ll_prep_md_op_data(NULL, src, dir, name->name, name->len,
                                     0, LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        err = md_link(sbi->ll_md_exp, op_data, &request);
        ll_finish_md_op_data(op_data);
        if (err)
                GOTO(out, err);

        ll_update_times(request, dir);
        ll_stats_ops_tally(sbi, LPROC_LL_LINK, 1);
        EXIT;
out:
        ptlrpc_req_finished(request);
        RETURN(err);
}

static int ll_mkdir(struct inode *dir, struct dentry *dchild, ll_umode_t mode)
{
	struct qstr *name = &dchild->d_name;
        int err;
        ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p)\n",
	       name->len, name->name, PFID(ll_inode2fid(dir)), dir);

	if (!IS_POSIXACL(dir) || !exp_connect_umask(ll_i2mdexp(dir)))
		mode &= ~current_umask();

	mode = (mode & (S_IRWXUGO|S_ISVTX)) | S_IFDIR;

	err = ll_new_node(dir, dchild, NULL, mode, 0, LUSTRE_OPC_MKDIR);
	if (err == 0)
		ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_MKDIR, 1);

	RETURN(err);
}

static int ll_rmdir(struct inode *dir, struct dentry *dchild)
{
	struct qstr *name = &dchild->d_name;
        struct ptlrpc_request *request = NULL;
        struct md_op_data *op_data;
        int rc;
        ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p)\n",
	       name->len, name->name, PFID(ll_inode2fid(dir)), dir);

	if (unlikely(d_mountpoint(dchild)))
                RETURN(-EBUSY);

        op_data = ll_prep_md_op_data(NULL, dir, NULL, name->name, name->len,
                                     S_IFDIR, LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

	if (dchild->d_inode != NULL)
		op_data->op_fid3 = *ll_inode2fid(dchild->d_inode);

	op_data->op_fid2 = op_data->op_fid3;
        rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
        ll_finish_md_op_data(op_data);
        if (rc == 0) {
                ll_update_times(request, dir);
                ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_RMDIR, 1);
        }

        ptlrpc_req_finished(request);
        RETURN(rc);
}

/**
 * Remove dir entry
 **/
int ll_rmdir_entry(struct inode *dir, char *name, int namelen)
{
	struct ptlrpc_request *request = NULL;
	struct md_op_data *op_data;
	int rc;
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p)\n",
	       namelen, name, PFID(ll_inode2fid(dir)), dir);

	op_data = ll_prep_md_op_data(NULL, dir, NULL, name, strlen(name),
				     S_IFDIR, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));
	op_data->op_cli_flags |= CLI_RM_ENTRY;
	rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
	ll_finish_md_op_data(op_data);
	if (rc == 0) {
		ll_update_times(request, dir);
		ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_RMDIR, 1);
	}

	ptlrpc_req_finished(request);
	RETURN(rc);
}

/* ll_unlink() doesn't update the inode with the new link count.
 * Instead, ll_ddelete() and ll_d_iput() will update it based upon if
 * there is any lock existing. They will recycle dentries and inodes
 * based upon locks too. b=20433 */
static int ll_unlink(struct inode *dir, struct dentry *dchild)
{
	struct qstr *name = &dchild->d_name;
        struct ptlrpc_request *request = NULL;
        struct md_op_data *op_data;
        int rc;
        ENTRY;
	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p)\n",
	       name->len, name->name, PFID(ll_inode2fid(dir)), dir);

        /*
         * XXX: unlink bind mountpoint maybe call to here,
         * just check it as vfs_unlink does.
         */
	if (unlikely(d_mountpoint(dchild)))
		RETURN(-EBUSY);

	op_data = ll_prep_md_op_data(NULL, dir, NULL, name->name, name->len, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	if (dchild->d_inode != NULL)
		op_data->op_fid3 = *ll_inode2fid(dchild->d_inode);

	op_data->op_fid2 = op_data->op_fid3;
	rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
	ll_finish_md_op_data(op_data);
	if (rc)
		GOTO(out, rc);

        ll_update_times(request, dir);
        ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_UNLINK, 1);

 out:
        ptlrpc_req_finished(request);
        RETURN(rc);
}

static int ll_rename(struct inode *src, struct dentry *src_dchild,
		     struct inode *tgt, struct dentry *tgt_dchild)
{
	struct qstr *src_name = &src_dchild->d_name;
	struct qstr *tgt_name = &tgt_dchild->d_name;
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(src);
        struct md_op_data *op_data;
        int err;
        ENTRY;
	CDEBUG(D_VFSTRACE, "VFS Op:oldname=%.*s, src_dir="DFID
	       "(%p), newname=%.*s, tgt_dir="DFID"(%p)\n",
	       src_name->len, src_name->name,
	       PFID(ll_inode2fid(src)), src, tgt_name->len,
	       tgt_name->name, PFID(ll_inode2fid(tgt)), tgt);

	if (unlikely(d_mountpoint(src_dchild) || d_mountpoint(tgt_dchild)))
		RETURN(-EBUSY);

	op_data = ll_prep_md_op_data(NULL, src, tgt, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	if (src_dchild->d_inode != NULL)
		op_data->op_fid3 = *ll_inode2fid(src_dchild->d_inode);

	if (tgt_dchild->d_inode != NULL)
		op_data->op_fid4 = *ll_inode2fid(tgt_dchild->d_inode);

        err = md_rename(sbi->ll_md_exp, op_data,
                        src_name->name, src_name->len,
                        tgt_name->name, tgt_name->len, &request);
        ll_finish_md_op_data(op_data);
        if (!err) {
                ll_update_times(request, src);
                ll_update_times(request, tgt);
                ll_stats_ops_tally(sbi, LPROC_LL_RENAME, 1);
        }

        ptlrpc_req_finished(request);

	if (err == 0)
		d_move(src_dchild, tgt_dchild);

	RETURN(err);
}

const struct inode_operations ll_dir_inode_operations = {
	.mknod              = ll_mknod,
#ifdef HAVE_IOP_ATOMIC_OPEN
	.atomic_open	    = ll_atomic_open,
#endif
	.lookup             = ll_lookup_nd,
	.create             = ll_create_nd,
	/* We need all these non-raw things for NFSD, to not patch it. */
	.unlink             = ll_unlink,
	.mkdir              = ll_mkdir,
	.rmdir              = ll_rmdir,
	.symlink            = ll_symlink,
	.link               = ll_link,
	.rename             = ll_rename,
	.setattr            = ll_setattr,
	.getattr            = ll_getattr,
	.permission         = ll_inode_permission,
	.setxattr           = ll_setxattr,
	.getxattr           = ll_getxattr,
	.listxattr          = ll_listxattr,
	.removexattr        = ll_removexattr,
#ifdef HAVE_IOP_GET_ACL
	.get_acl	    = ll_get_acl,
#endif
};

const struct inode_operations ll_special_inode_operations = {
	.setattr        = ll_setattr,
	.getattr        = ll_getattr,
	.permission     = ll_inode_permission,
	.setxattr       = ll_setxattr,
	.getxattr       = ll_getxattr,
	.listxattr      = ll_listxattr,
	.removexattr    = ll_removexattr,
#ifdef HAVE_IOP_GET_ACL
	.get_acl	    = ll_get_acl,
#endif
};
