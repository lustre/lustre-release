/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/smp_lock.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include <linux/lustre_snap.h>
#include <linux/security.h>
#include "smfs_internal.h"

//#define NAME_ALLOC_LEN(len)     ((len+16) & ~15)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int smfs_create(struct inode *dir, struct dentry *dentry,
                       int mode)
#else
static int smfs_create(struct inode *dir, struct dentry *dentry,
                       int mode, struct nameidata *nd)
#endif
{
        struct inode *inode = NULL;
        struct inode *parent = I2CI(dentry->d_parent->d_inode);
        struct inode *cache_dir = I2CI(dir);
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void *handle = NULL;
        struct hook_msg msg = {
                .dentry = dentry,
        };
        int rc = 0;
        
        ENTRY;

        LASSERT(cache_dir);
        LASSERT(cache_dir->i_op->create);
        
        cache_parent = pre_smfs_dentry(NULL, parent, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);
        if (!cache_dentry || !cache_parent) {
                rc = -ENOMEM;
                goto exit;
        }
       
        handle = smfs_trans_start(dir, FSFILT_OP_CREATE, NULL);
        if (IS_ERR(handle)) {
                rc = -ENOSPC;
                goto exit;
        }
        
        SMFS_PRE_HOOK(dir, HOOK_CREATE, &msg);

        pre_smfs_inode(dir, cache_dir);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        rc = cache_dir->i_op->create(cache_dir, cache_dentry, mode);
#else
        rc = cache_dir->i_op->create(cache_dir, cache_dentry, mode, nd);
#endif
        if (!rc) {
                inode = smfs_get_inode(dir->i_sb, cache_dentry->d_inode->i_ino,
                                       dir, 0);
                if (inode) {
                        d_instantiate(dentry, inode);
                }
                else
                        rc = -ENOENT;
        }
        
        SMFS_POST_HOOK(dir, HOOK_CREATE, &msg, rc); 

        post_smfs_inode(dir, cache_dir);
        smfs_trans_commit(dir, handle, 0);
        
exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        RETURN(rc);
}

static struct dentry * iopen_connect_dentry(struct dentry * dentry,
                                     struct inode *inode, int rehash)
{
	struct dentry *tmp, *goal = NULL;
	struct list_head *lp;

	/* verify this dentry is really new */
	LASSERT(dentry->d_inode == NULL);
	LASSERT(list_empty(&dentry->d_alias));		/* d_instantiate */
	if (rehash)
		LASSERT(d_unhashed(dentry));	/* d_rehash */
	LASSERT(list_empty(&dentry->d_subdirs));

	spin_lock(&dcache_lock);
	if (!inode)
		goto do_rehash;

	/* preferrably return a connected dentry */
	list_for_each(lp, &inode->i_dentry) {
		tmp = list_entry(lp, struct dentry, d_alias);
		if (tmp->d_flags & DCACHE_DISCONNECTED) {
			LASSERT(tmp->d_alias.next == &inode->i_dentry);
			LASSERT(tmp->d_alias.prev == &inode->i_dentry);
			goal = tmp;
			dget_locked(goal);
			break;
		}
	}

	if (!goal)
		goto do_instantiate;

	/* Move the goal to the de hash queue */
	goal->d_flags &= ~ DCACHE_DISCONNECTED;
	security_d_instantiate(goal, inode);
        __d_rehash(dentry);
        __d_move(goal, dentry);
	spin_unlock(&dcache_lock);
	iput(inode);

	RETURN(goal);

	/* d_add(), but don't drop dcache_lock before adding dentry to inode */
do_instantiate:
	list_add(&dentry->d_alias, &inode->i_dentry);	/* d_instantiate */
	dentry->d_inode = inode;
do_rehash:
	if (rehash)
                __d_rehash(dentry);
	spin_unlock(&dcache_lock);

	RETURN(NULL);

}

static int smfs_do_lookup (struct inode * dir, 
                           struct dentry * dentry,
                           struct nameidata *nd,
                           struct inode **inode)
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *parent = I2CI(dentry->d_parent->d_inode);
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        struct dentry *rdentry = NULL, *tmp = NULL;
        int rc = 0;
        struct hook_msg msg = {
                .dentry = dentry,
        };

        ENTRY;
        
        if (!cache_dir)
                RETURN(-ENOENT);

        LASSERT(cache_dir->i_op->lookup);

        /* preparing artificial backing fs dentries. */
        cache_parent = pre_smfs_dentry(NULL, parent, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);
        if (!cache_dentry || !cache_parent) {
                rc = -ENOMEM;
                goto exit;
        }
        
        SMFS_PRE_HOOK(dir, HOOK_LOOKUP, &msg);
        
        /* perform lookup in backing fs. */
        rdentry = cache_dir->i_op->lookup(cache_dir, cache_dentry, nd);
        if (rdentry) {
                if (IS_ERR(rdentry)) {
                        rc = PTR_ERR(rdentry);
                        rdentry = NULL;
                } else {
                        tmp = rdentry;
                }
        } else {
                tmp = cache_dentry;
        }

        SMFS_POST_HOOK(dir, HOOK_LOOKUP, &msg, rc);
     
        if (tmp) {
                //copy fields if DCACHE_CROSS_REF
                smfs_update_dentry(dentry, tmp);         
                
                if (tmp->d_inode) {
                        if (!tmp->d_inode->i_nlink)
                                CWARN("inode #%lu (%p) nlink is 0\n",
                                      tmp->d_inode->i_ino, tmp->d_inode);
                        
                        *inode = smfs_get_inode(dir->i_sb, tmp->d_inode->i_ino, 
                                        dir, 0); 
                        if (!(*inode))
                                rc = -ENOENT;
                }
        }
        
        if (rdentry) {
                dput(rdentry);
        }
        
exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        
        RETURN(rc);
}

static struct dentry * smfs_iopen_lookup(struct inode * dir, 
                                         struct dentry *dentry,
				         struct nameidata *nd)
{
        struct dentry * alternate = NULL;
	struct inode *inode = NULL;
        int rc = 0;
        ENTRY;
        
        rc = smfs_do_lookup(dir, dentry, nd, &inode);
	if (rc)
                RETURN(ERR_PTR(rc));
        
        LASSERT(inode);
        /* preferrably return a connected dentry */
	spin_lock(&dcache_lock);
	list_for_each_entry(alternate, &inode->i_dentry, d_alias) {
		LASSERT(!(alternate->d_flags & DCACHE_DISCONNECTED));
	}

	list_for_each_entry(alternate, &inode->i_dentry, d_alias) {
		dget_locked(alternate);
		spin_lock(&alternate->d_lock);
		alternate->d_flags |= DCACHE_REFERENCED;
		spin_unlock(&alternate->d_lock);
		iput(inode);
		spin_unlock(&dcache_lock);
		RETURN(alternate);
	}
        
	dentry->d_flags |= DCACHE_DISCONNECTED;

	/* d_add(), but don't drop dcache_lock before adding dentry to inode */
	list_add(&dentry->d_alias, &inode->i_dentry);	/* d_instantiate */
	dentry->d_inode = inode;

	__d_rehash(dentry);				/* d_rehash */
	spin_unlock(&dcache_lock);

	return NULL;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static struct dentry *smfs_lookup(struct inode *dir, struct dentry *dentry)
#else
static struct dentry *smfs_lookup(struct inode *dir, struct dentry *dentry,
                                  struct nameidata *nd)
#endif
{
        struct dentry * rdentry = NULL;
        struct inode * inode = NULL;
        int rc;

        ENTRY;
        
        rc = smfs_do_lookup(dir, dentry, nd, &inode);
        if (rc)
                RETURN(ERR_PTR(rc));
        
        //lmv stuff. Special dentry that has no inode.
        if (dentry->d_flags & DCACHE_CROSS_REF) {
                d_add(dentry, NULL);
                RETURN(NULL);
        }
        //TODO: should flags be checked and copied before?        
        rdentry = iopen_connect_dentry(dentry, inode, 1);
        
        RETURN(rdentry);
}

static int smfs_lookup_raw(struct inode *dir, const char *name,
                           int len, ino_t *data)
{
        struct inode *cache_dir = I2CI(dir);
        int rc = 0;

        if (!cache_dir)
                RETURN(-ENOENT);
        
        if (cache_dir->i_op->lookup_raw) {
                rc = cache_dir->i_op->lookup_raw(cache_dir, name, len, data);
        } else {
                CWARN("do not have raw lookup ops in bottom fs\n");
        }

        RETURN(rc);
}

static int smfs_link(struct dentry *old_dentry,
                     struct inode *dir, struct dentry *dentry)
{
        struct inode *parent = I2CI(dentry->d_parent->d_inode);
        struct inode *cache_dir = I2CI(dir);
        struct inode *old_inode = old_dentry->d_inode;
        struct inode *cache_old_inode = I2CI(old_inode);
        struct dentry *cache_old_dentry = NULL;
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void *handle = NULL;
        int rc = 0;
        struct hook_link_msg msg = {
                .dentry = old_dentry,
                .new_dentry = dentry
        };

        ENTRY;

        if (!cache_dir)
                RETURN(-ENOENT);
        
        if (!cache_old_inode)
                RETURN(-ENOENT);
        
        cache_parent = pre_smfs_dentry(NULL, parent, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);
        cache_old_dentry = pre_smfs_dentry(NULL, cache_old_inode, old_dentry);
        if (!cache_old_dentry || !cache_dentry || !cache_parent) {
                rc = -ENOMEM;
                goto exit;
        }        
        
        handle = smfs_trans_start(dir, FSFILT_OP_LINK, NULL);
        if (IS_ERR(handle)) {
                 rc = -ENOSPC;
                 goto exit;
        }

        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(old_inode, cache_old_inode);

        //lock_kernel();
        SMFS_PRE_HOOK(dir, HOOK_LINK, &msg); 

        rc = cache_dir->i_op->link(cache_old_dentry, cache_dir, cache_dentry);
        if (!rc) {
                atomic_inc(&old_inode->i_count);
                dput(iopen_connect_dentry(dentry, old_inode, 0));
        }

        SMFS_POST_HOOK(dir, HOOK_LINK, &msg, rc); 
        
        post_smfs_inode(old_inode, cache_old_inode);
        post_smfs_inode(dir, cache_dir);

        smfs_trans_commit(dir, handle, 0);
        
exit:
        //unlock_kernel();
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        post_smfs_dentry(cache_old_dentry);
        
        RETURN(rc);
}

static int smfs_unlink(struct inode * dir, struct dentry *dentry)
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct inode *parent = I2CI(dentry->d_parent->d_inode);
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void   *handle = NULL;
        int    rc = 0;
        //int    mode = 0;
        struct hook_unlink_msg msg = {
                .dentry = dentry,
                .mode = dentry->d_inode->i_mode
        };

        ENTRY;
        
        LASSERT(cache_dir);
        LASSERT(cache_inode);
        LASSERT(cache_dir->i_op->unlink);
        LASSERT(parent);
        
        cache_parent = pre_smfs_dentry(NULL, parent, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, cache_inode, dentry);
        if (!cache_dentry || !cache_parent) {
                rc = -ENOMEM;
                goto exit;
        }
                
        handle = smfs_trans_start(dir, FSFILT_OP_UNLINK, NULL);
        if (IS_ERR(handle)) {
                rc = -ENOSPC;
                goto exit;
        }
        
        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(dentry->d_inode, cache_inode);

        SMFS_PRE_HOOK(dir, HOOK_UNLINK, &msg); 
        
        rc = cache_dir->i_op->unlink(cache_dir, cache_dentry);
                
        SMFS_POST_HOOK(dir, HOOK_UNLINK, &msg, rc); 

        post_smfs_inode(dentry->d_inode, cache_dentry->d_inode);
        post_smfs_inode(dir, cache_dir);
        
        smfs_trans_commit(dir, handle, 0);
exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        RETURN(rc);
}

static int smfs_symlink(struct inode *dir, struct dentry *dentry,
                        const char *symname)
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *inode = NULL;
        struct inode *parent = I2CI(dentry->d_parent->d_inode);
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void   *handle = NULL;
        int    rc = 0;
        struct hook_symlink_msg msg = {
                .dentry = dentry,
                .tgt_len = strlen(symname) + 1,
                .symname = (char*)symname
        };

        ENTRY;
        
        LASSERT(cache_dir);
        LASSERT(cache_dir->i_op->symlink);
        LASSERT(parent);

        cache_parent = pre_smfs_dentry(NULL, parent, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);
        if (!cache_parent || !cache_dentry) {
                rc = -ENOMEM;
                goto exit;
        }
       
        handle = smfs_trans_start(dir, FSFILT_OP_SYMLINK, NULL);
        if (IS_ERR(handle)) {
                rc = -ENOSPC;
                goto exit;
        }
        
        pre_smfs_inode(dir, cache_dir);

        SMFS_PRE_HOOK(dir, HOOK_SYMLINK, &msg); 
        
        rc = cache_dir->i_op->symlink(cache_dir, cache_dentry, symname);
        if (!rc) {        
                inode = smfs_get_inode(dir->i_sb, cache_dentry->d_inode->i_ino,
                                       dir, 0);
                if (inode) {
                        d_instantiate(dentry, inode);
                }
                else
                        rc = -ENOENT;
        }
        
        SMFS_POST_HOOK(dir, HOOK_SYMLINK, &msg, rc);
        
        post_smfs_inode(dir, cache_dir);
        smfs_trans_commit(dir, handle, 0);

exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        RETURN(rc);
}

static int smfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *parent = I2CI(dentry->d_parent->d_inode);
        struct inode *inode = NULL;
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void   *handle = NULL;
        int    rc = 0;
        struct hook_msg msg = {
                .dentry = dentry,
        };

        ENTRY;
        
        LASSERT(cache_dir);
        LASSERT(parent);
        
        cache_parent = pre_smfs_dentry(NULL, parent, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);
        if (!cache_parent || !cache_dentry) {
                rc = -ENOMEM;
                goto exit;
        }

        handle = smfs_trans_start(dir, FSFILT_OP_MKDIR, NULL);
        if (IS_ERR(handle)) {
                rc = -ENOSPC;
                goto exit;
        }
        
        pre_smfs_inode(dir, cache_dir);
        SMFS_PRE_HOOK(dir, HOOK_MKDIR, &msg); 
        
        rc = cache_dir->i_op->mkdir(cache_dir, cache_dentry, mode);
        if (!rc) {
                inode = smfs_get_inode(dir->i_sb, cache_dentry->d_inode->i_ino,
                                       dir, 0);
                if (inode) {
                        //smsf_update_dentry(dentry, cache_dentry);
                        d_instantiate(dentry, inode);
                }
                else
                        rc = -ENOENT;
        }

        SMFS_POST_HOOK(dir, HOOK_MKDIR, &msg, rc); 
        post_smfs_inode(dir, cache_dir);
        smfs_trans_commit(dir, handle, 0);

exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        RETURN(rc);
}

static int smfs_rmdir(struct inode *dir, struct dentry *dentry)
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct inode *parent = I2CI(dentry->d_parent->d_inode);
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void *handle = NULL;
        int    rc = 0;
        struct hook_unlink_msg msg = {
                .dentry = dentry,
                .mode = S_IFDIR
        };

        ENTRY;
        
        LASSERT(cache_dir);
        LASSERT(cache_dir->i_op->rmdir);
        LASSERT(parent);

        cache_parent = pre_smfs_dentry(NULL, parent, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, cache_inode, dentry);
        if (!cache_parent || !cache_dentry) {
                rc = -ENOMEM;
                goto exit;
        }

        handle = smfs_trans_start(dir, FSFILT_OP_RMDIR, NULL);
        if (IS_ERR(handle) ) {
                rc = -ENOSPC;
                goto exit;
        }
        
        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(dentry->d_inode, cache_dentry->d_inode);
        
        SMFS_PRE_HOOK(dir, HOOK_RMDIR, &msg); 
        
        rc = cache_dir->i_op->rmdir(cache_dir, cache_dentry);
              
        SMFS_POST_HOOK(dir, HOOK_RMDIR, &msg, rc); 
        
        post_smfs_inode(dir, cache_dir);
        post_smfs_inode(dentry->d_inode, cache_dentry->d_inode);
        //like vfs_rmdir is doing with inode
        if (!rc)
                cache_dentry->d_inode->i_flags |= S_DEAD;
        
        smfs_trans_commit(dir, handle, 0);

exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        RETURN(rc);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int smfs_mknod(struct inode *dir, struct dentry *dentry,
                      int mode, int rdev)
#else
static int smfs_mknod(struct inode *dir, struct dentry *dentry,
                      int mode, dev_t rdev)
#endif
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *inode = NULL;
        struct inode *parent = I2CI(dentry->d_parent->d_inode);
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void *handle = NULL;
        int rc = 0;
        struct hook_msg msg = {
                .dentry = dentry,
        };
 
        ENTRY;
        
        LASSERT(parent);
        LASSERT(cache_dir);
        LASSERT(cache_dir->i_op->mknod);

        cache_parent = pre_smfs_dentry(NULL, parent, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);
        if (!cache_parent || !cache_dentry) {
                rc = -ENOMEM;
                goto exit;
        }

        handle = smfs_trans_start(dir, FSFILT_OP_MKNOD, NULL);
        if (IS_ERR(handle)) {
                rc = -ENOSPC;
                goto exit;
        }
        
        pre_smfs_inode(dir, cache_dir);
        
        SMFS_PRE_HOOK(dir, HOOK_MKNOD, &msg); 
        
        rc = cache_dir->i_op->mknod(cache_dir, cache_dentry, mode, rdev);
        if (!rc) {
                inode = smfs_get_inode(dir->i_sb, cache_dentry->d_inode->i_ino,
                                       dir, 0);
                if (inode) {
                        //smsf_update_dentry(dentry, cache_dentry);
                        d_instantiate(dentry, inode);
                }
                else
                        rc = -ENOENT;
        }

        SMFS_POST_HOOK(dir, HOOK_MKNOD, &msg, rc); 
        
        post_smfs_inode(dir, cache_dir);
        
        smfs_trans_commit(dir, handle, 0);

exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        RETURN(rc);
}

static int smfs_rename(struct inode *old_dir, struct dentry *old_dentry,
                       struct inode *new_dir,struct dentry *new_dentry)
{
        struct inode *cache_old_dir = I2CI(old_dir);
        struct inode *cache_new_dir = I2CI(new_dir);
        struct inode *cache_old_inode = I2CI(old_dentry->d_inode);
        struct inode *old_parent = I2CI(old_dentry->d_parent->d_inode);
        struct inode *new_parent = I2CI(new_dentry->d_parent->d_inode);
        struct inode *cache_new_inode = NULL;
        struct dentry *cache_old_dentry = NULL;
        struct dentry *cache_new_dentry = NULL;
        struct dentry *cache_new_parent = NULL;
        struct dentry *cache_old_parent = NULL;
        void *handle = NULL;
        int    rc = 0;
        struct hook_rename_msg msg = {
                .dentry = old_dentry,
                .new_dir = new_dir,
                .new_dentry = new_dentry
        };

        ENTRY;
                
        if (!cache_old_dir || !cache_new_dir || !cache_old_inode)
                RETURN(-ENOENT);

        if (new_dentry->d_inode) {
                cache_new_inode = I2CI(new_dentry->d_inode);
                if (!cache_new_inode)
                        RETURN(-ENOENT);
        }
        
        cache_old_parent = pre_smfs_dentry(NULL, old_parent, old_dentry->d_parent);
        cache_old_dentry = pre_smfs_dentry(cache_old_parent, cache_old_inode,
                                           old_dentry);
        if (!cache_old_parent || !cache_old_dentry) {
                rc = -ENOMEM;
                goto exit;
        }
        
        cache_new_parent = pre_smfs_dentry(NULL, new_parent, new_dentry->d_parent);
        cache_new_dentry = pre_smfs_dentry(cache_new_parent, cache_new_inode,
                                           new_dentry);
        if (!cache_new_parent || !cache_new_dentry) {
                rc = -ENOMEM;
                goto exit;
        }

        handle = smfs_trans_start(old_dir, FSFILT_OP_RENAME, NULL);
        if (IS_ERR(handle)) {
                rc = -ENOSPC;
                goto exit;
        }
        
        pre_smfs_inode(old_dir, cache_old_dir);
        pre_smfs_inode(new_dir, cache_new_dir);
        if (new_dentry->d_inode)
                pre_smfs_inode(new_dentry->d_inode, cache_new_dentry->d_inode);

        SMFS_PRE_HOOK(old_dir, HOOK_RENAME, &msg); 
        
        rc = cache_old_dir->i_op->rename(cache_old_dir, cache_old_dentry,
                                         cache_new_dir, cache_new_dentry);
        
        SMFS_POST_HOOK(old_dir, HOOK_RENAME, &msg, rc); 

        post_smfs_inode(old_dir, cache_old_dir);
        post_smfs_inode(new_dir, cache_new_dir);
        if (new_dentry->d_inode)
                post_smfs_inode(new_dentry->d_inode, cache_new_dentry->d_inode);
        
        smfs_trans_commit(old_dir, handle, 0);
        
exit:
        post_smfs_dentry(cache_old_dentry);
        post_smfs_dentry(cache_old_parent);
        post_smfs_dentry(cache_new_dentry);
        post_smfs_dentry(cache_new_parent);
        RETURN(rc);
}

struct inode_operations smfs_dir_iops = {
        create:         smfs_create,
        lookup:         smfs_lookup,
        lookup_raw:     smfs_lookup_raw,
        link:           smfs_link,              /* BKL held */
        unlink:         smfs_unlink,            /* BKL held */
        symlink:        smfs_symlink,           /* BKL held */
        mkdir:          smfs_mkdir,             /* BKL held */
        rmdir:          smfs_rmdir,             /* BKL held */
        mknod:          smfs_mknod,             /* BKL held */
        rename:         smfs_rename,            /* BKL held */
        setxattr:       smfs_setxattr,          /* BKL held */
        getxattr:       smfs_getxattr,          /* BKL held */
        listxattr:      smfs_listxattr,         /* BKL held */
        removexattr:    smfs_removexattr,       /* BKL held */
};

struct inode_operations smfs_iopen_iops = {
        lookup:         smfs_iopen_lookup,
};

static ssize_t smfs_read_dir(struct file *filp, char *buf,
                             size_t size, loff_t *ppos)
{
        struct dentry *dentry = filp->f_dentry;
        struct inode *cache_inode = NULL;
        struct smfs_file_info *sfi = NULL;
        loff_t tmp_ppos;
        loff_t *cache_ppos = NULL;
        int    rc = 0;

        ENTRY;
        
        cache_inode = I2CI(dentry->d_inode);

        if (!cache_inode || !cache_inode->i_fop->read)
                RETURN(-EINVAL);

        sfi = F2SMFI(filp);
        if (sfi->magic != SMFS_FILE_MAGIC)
                BUG();

        if (ppos != &(filp->f_pos))
                cache_ppos = &tmp_ppos;
        else
                cache_ppos = &sfi->c_file->f_pos;
        
        *cache_ppos = *ppos;

        rc = cache_inode->i_fop->read(sfi->c_file, buf, size, cache_ppos);
        if (rc)
                RETURN(rc);

        *ppos = *cache_ppos;
        
        duplicate_file(filp, sfi->c_file);
        
        RETURN(rc);
}

static int smfs_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
        struct dentry *dentry = filp->f_dentry;
        struct inode *cache_inode = NULL;
        struct smfs_file_info *sfi = NULL;
        int    rc = 0;
        struct hook_readdir_msg msg = {
                .dentry = dentry,
                .filp = filp,
                .dirent = dirent,
                .filldir = filldir
        };

        ENTRY;
        
        cache_inode = I2CI(dentry->d_inode);
        if (!cache_inode || !cache_inode->i_fop->readdir)
                RETURN(-EINVAL);

        sfi = F2SMFI(filp);
        if (sfi->magic != SMFS_FILE_MAGIC) BUG();

        SMFS_PRE_HOOK(dentry->d_inode, HOOK_READDIR, &msg); 
        
        rc = cache_inode->i_fop->readdir(sfi->c_file, dirent, filldir);
        
        SMFS_POST_HOOK(dentry->d_inode, HOOK_READDIR, &msg, rc);
        duplicate_file(filp, sfi->c_file);

        RETURN(rc);
}

struct file_operations smfs_dir_fops = {
        .read           = smfs_read_dir,
        .readdir        = smfs_readdir,       /* BKL held */
        .ioctl          = smfs_ioctl,         /* BKL held */
        .fsync          = smfs_fsync,         /* BKL held */
        .open           = smfs_open,
        .release        = smfs_release,
};

struct file_operations smfs_iopen_fops = {
        .read           = smfs_read_dir,
};

