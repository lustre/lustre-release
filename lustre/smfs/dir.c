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

#include "smfs_internal.h"

#define NAME_ALLOC_LEN(len)     ((len+16) & ~15)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int smfs_create(struct inode *dir, struct dentry *dentry,
                       int mode)
#else
static int smfs_create(struct inode *dir, struct dentry *dentry,
                       int mode, struct nameidata *nd)
#endif
{
        struct inode  *inode = NULL;
        struct inode  *cache_dir = NULL;
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void *handle = NULL;
        struct inode *cache_inode = NULL;
        int rc = 0;

        ENTRY;

        cache_dir = I2CI(dir);
        LASSERT(cache_dir && cache_dir->i_op->create);

        //lock_kernel();
        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);

        if (!cache_dentry || !cache_parent)
                GOTO(exit, rc = -ENOMEM);
       
        pre_smfs_inode(dir, cache_dir);
        
        handle = smfs_trans_start(dir, FSFILT_OP_CREATE, NULL);
        if (IS_ERR(handle))
                       GOTO(exit, rc = -ENOSPC);
        
        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_CREATE, handle,
                  PRE_HOOK, rc, exit);
        
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        rc = cache_dir->i_op->create(cache_dir, cache_dentry, mode);
#else
        rc = cache_dir->i_op->create(cache_dir, cache_dentry, mode, nd);
#endif
        cache_inode = cache_dentry->d_inode;
        
        if (rc)
                GOTO(exit, rc);
        
        SMFS_IGET(dir, cache_inode->i_ino, inode, rc, exit); 

        d_instantiate(dentry, inode);

        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_CREATE, handle,
                  POST_HOOK, rc,  exit); 

        post_smfs_inode(dir, cache_dir);

exit:
        //unlock_kernel();
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        smfs_trans_commit(dir, handle, 0);
        RETURN(rc);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static struct dentry *smfs_lookup(struct inode *dir, struct dentry *dentry)
#else
static struct dentry *smfs_lookup(struct inode *dir, struct dentry *dentry,
                                  struct nameidata *nd)
#endif
{
        struct inode *cache_dir;
        struct inode *cache_inode;
        struct inode *inode = NULL;
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        struct dentry *rdentry = NULL;
        int rc = 0;

        ENTRY;

        cache_dir = I2CI(dir);
        if (!cache_dir || !cache_dir->i_op->lookup)
                RETURN(ERR_PTR(-ENOENT));

        /* preparing artificial backing fs dentries. */
        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);

        if (!cache_dentry || !cache_parent)
                RETURN (ERR_PTR(-ENOMEM));

        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_LOOKUP, NULL, 
                  PRE_HOOK, rc, exit); 

        /* perform lookup in backing fs. */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        rdentry = cache_dir->i_op->lookup(cache_dir, cache_dentry);
#else
        rdentry = cache_dir->i_op->lookup(cache_dir, cache_dentry, nd);
#endif
        cache_inode = cache_dentry->d_inode;
        
        if (rdentry) {
                if (IS_ERR(rdentry))
                        GOTO(exit, rdentry);
        
                cache_inode = rdentry->d_inode;
                dput(rdentry);
                rdentry = NULL;
        }
        
        if (cache_inode) 
                SMFS_IGET(dir, cache_inode->i_ino, inode, rc, exit);
     
        
        //rdentry = d_splice_alias(inode, dentry);
        d_add(dentry, inode);
        //CDEBUG(D_INODE, "dir %p (inode %p)\n", dir, cache_dir);

        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_LOOKUP, NULL, POST_HOOK, rc, 
                  exit); 
exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        return rdentry;
}

static int smfs_link(struct dentry *old_dentry,
                     struct inode *dir, struct dentry *dentry)
{
        struct inode *cache_old_inode = NULL;
        struct inode *cache_dir = NULL;
        struct inode *old_inode = NULL;
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_old_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void *handle = NULL;
        int rc = 0;

        ENTRY;

        cache_dir = I2CI(dir);
        if (!cache_dir || !cache_dir->i_op->link)
                GOTO(exit, rc = -ENOENT);
        
        old_inode = old_dentry->d_inode;        
        cache_old_inode = I2CI(old_inode);
        if (!cache_old_inode)
                GOTO(exit, rc = -ENOENT);
        
        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);
        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);

        cache_old_dentry = pre_smfs_dentry(NULL, cache_old_inode,
                                           old_dentry);
        if (!cache_old_dentry)
                GOTO(exit, rc = -ENOMEM);
        
        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(old_inode, cache_old_inode);

        handle = smfs_trans_start(dir, FSFILT_OP_LINK, NULL);
        if (IS_ERR(handle))
                 GOTO(exit, rc = -ENOSPC);
        
        //lock_kernel();
        SMFS_HOOK(dir, old_dentry, NULL, NULL, HOOK_LINK, handle,
                  PRE_HOOK, rc, exit); 

        rc = cache_dir->i_op->link(cache_old_dentry, cache_dir,
                                           cache_dentry);
        if (rc)
                GOTO(exit, rc);

        atomic_inc(&old_inode->i_count);
        d_instantiate(dentry, old_inode);

        post_smfs_inode(old_inode, cache_old_inode);
        post_smfs_inode(dir, cache_dir);

        SMFS_HOOK(dir, old_dentry, dentry, NULL, HOOK_LINK, handle,
                  POST_HOOK, rc, exit); 
exit:
        //unlock_kernel();
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        post_smfs_dentry(cache_old_dentry);
        smfs_trans_commit(dir, handle, 0);
        RETURN(rc);
}

static int smfs_unlink(struct inode * dir,
                       struct dentry *dentry)
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct dentry *cache_dentry;
        struct dentry *cache_parent;
        void   *handle = NULL;
        int    rc = 0;
        int    mode = 0;

        ENTRY;
        
        if (!cache_dir || !cache_inode || !cache_dir->i_op->unlink)
                RETURN(-ENOENT);

        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, cache_inode, dentry);

        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);
                
        //lock_kernel();
        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(dentry->d_inode, cache_inode);

        handle = smfs_trans_start(dir, FSFILT_OP_UNLINK, NULL);
        if (IS_ERR(handle))
                GOTO(exit, rc = -ENOSPC);

        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_UNLINK, handle, PRE_HOOK, rc, 
                  exit); 
        
        rc = cache_dir->i_op->unlink(cache_dir, cache_dentry);
        if (rc)
                GOTO(exit, rc);
        
        post_smfs_inode(dentry->d_inode, cache_dentry->d_inode);
        post_smfs_inode(dir, cache_dir);
        //unlock_kernel();
        
        SMFS_HOOK(dir, dentry, &mode, NULL, HOOK_UNLINK, handle, POST_HOOK, 
                  rc, exit); 
exit:
        smfs_trans_commit(dir, handle, 0);
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        RETURN(rc);
}

static int smfs_symlink(struct inode *dir, struct dentry *dentry,
                        const char *symname)
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *inode = NULL;
        struct dentry *cache_dentry;
        struct dentry *cache_parent;
        void   *handle = NULL;
        int    rc = 0, tgt_len;

        ENTRY;
        
        if (!cache_dir || !cache_dir->i_op->symlink)
                RETURN(-ENOENT);

        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);

        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);
       
        pre_smfs_inode(dir, cache_dir);
        
        handle = smfs_trans_start(dir, FSFILT_OP_SYMLINK, NULL);
        if (IS_ERR(handle))
                GOTO(exit, rc = -ENOSPC);
        
        //lock_kernel();
        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_SYMLINK, handle, PRE_HOOK, rc, 
                  exit); 
        
        rc = cache_dir->i_op->symlink(cache_dir, cache_dentry, symname);
        if (rc)
                GOTO(exit, rc);
        
        SMFS_IGET(dir, cache_dentry->d_inode->i_ino, inode, rc, exit); 
        
        d_instantiate(dentry, inode);
        post_smfs_inode(dir, cache_dir);
        
        tgt_len = strlen(symname) + 1;
        SMFS_HOOK(dir, dentry, (char *)symname, &tgt_len, HOOK_SYMLINK, handle, 
                  POST_HOOK, rc, exit); 
        
exit:
        //unlock_kernel();
        smfs_trans_commit(dir, handle, 0);
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        RETURN(rc);
}

static int smfs_mkdir(struct inode *dir, struct dentry *dentry,
                      int mode)
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *inode = NULL;
        struct dentry *cache_dentry;
        struct dentry *cache_parent;
        void   *handle = NULL;
        int    rc = 0;

        ENTRY;
        
        if (!cache_dir || !cache_dir->i_op->mkdir)
                RETURN(-ENOENT);

        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);

        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);

        pre_smfs_inode(dir, cache_dir);

        handle = smfs_trans_start(dir, FSFILT_OP_MKDIR, NULL);
        if (IS_ERR(handle))
                GOTO(exit, rc = -ENOSPC);

        //lock_kernel();
        
        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_MKDIR, handle, PRE_HOOK, rc, 
                  exit); 
        
        rc = cache_dir->i_op->mkdir(cache_dir, cache_dentry, mode);

        if (rc)
                GOTO(exit, rc);
  
        SMFS_IGET(dir, cache_dentry->d_inode->i_ino, inode, rc, exit);
        
        d_instantiate(dentry, inode);
        post_smfs_inode(dir, cache_dir);

        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_MKDIR, handle, POST_HOOK, rc,
                  exit); 
exit:
        //unlock_kernel();
        smfs_trans_commit(dir, handle, 0);
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        RETURN(rc);
}

static int smfs_rmdir(struct inode *dir, struct dentry *dentry)
{
        struct inode *cache_dir = I2CI(dir);
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void *handle = NULL;
        int    rc = 0, mode = S_IFDIR;

        ENTRY;
        
        if (!cache_dir || !cache_dir->i_op->rmdir)
                RETURN(-ENOENT);

        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, cache_inode, dentry);

        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);

        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(dentry->d_inode, cache_dentry->d_inode);
        
        handle = smfs_trans_start(dir, FSFILT_OP_RMDIR, NULL);
        if (IS_ERR(handle) ) {
                CERROR("smfs_do_mkdir: no space for transaction\n");
                GOTO(exit, rc = -ENOSPC);
        }

        //lock_kernel();

        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_RMDIR, handle, PRE_HOOK, rc, 
                  exit); 

        rc = cache_dir->i_op->rmdir(cache_dir, cache_dentry);
        if (rc)
                GOTO(exit, rc);
        
        post_smfs_inode(dir, cache_dir);
        post_smfs_inode(dentry->d_inode, cache_dentry->d_inode);
        //unlock_kernel();
        
        SMFS_HOOK(dir, dentry, &mode, NULL, HOOK_RMDIR, handle, POST_HOOK, 
                  rc, exit); 
exit:
        smfs_trans_commit(dir, handle, 0);
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
        struct dentry *cache_dentry = NULL;
        struct dentry *cache_parent = NULL;
        void *handle = NULL;
        int rc = 0;

        ENTRY;
        
        if (!cache_dir || !cache_dir->i_op->mknod)
                RETURN(-ENOENT);

        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);
        
        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);

        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(dentry->d_inode, cache_dentry->d_inode);

        handle = smfs_trans_start(dir, FSFILT_OP_MKNOD, NULL);
        if (IS_ERR(handle)) {
                CERROR("smfs_do_mkdir: no space for transaction\n");
                GOTO(exit, rc = -ENOSPC);
        }

        //lock_kernel();
        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_MKNOD, handle, PRE_HOOK, rc, 
                  exit); 
        
        rc = cache_dir->i_op->mknod(cache_dir, cache_dentry, mode, rdev);
        if (rc)
                GOTO(exit, rc);

        SMFS_IGET(dir, cache_dentry->d_inode->i_ino, inode, rc, exit); 

        d_instantiate(dentry, inode);

        post_smfs_inode(dir, cache_dir);
        post_smfs_inode(dentry->d_inode, cache_dentry->d_inode);

        SMFS_HOOK(dir, dentry, NULL, NULL, HOOK_MKNOD, handle, POST_HOOK, rc, 
                  exit); 
        
exit:
        //unlock_kernel();
        smfs_trans_commit(dir, handle, 0);
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

        struct inode *cache_new_inode = new_dentry->d_inode ?
            I2CI(new_dentry->d_inode) : NULL;

        struct dentry *cache_old_dentry = NULL;
        struct dentry *cache_new_dentry = NULL;
        struct dentry *cache_new_parent = NULL;
        struct dentry *cache_old_parent = NULL;
        void *handle = NULL;
        int    rc = 0;

        ENTRY;
        
        if (!cache_old_dir || !cache_new_dir || !cache_old_inode
            || !cache_old_dir->i_op->rename)
                RETURN(-ENOENT);

        cache_old_parent = pre_smfs_dentry(NULL, cache_old_dir, old_dentry);

        cache_old_dentry = pre_smfs_dentry(cache_old_parent, cache_old_inode,
                                           old_dentry);
        
        if (!cache_old_parent || !cache_old_dentry)
                GOTO(exit, rc = -ENOMEM);

        cache_new_parent = pre_smfs_dentry(NULL, cache_new_dir, new_dentry);
        cache_new_dentry = pre_smfs_dentry(cache_new_parent, cache_new_inode,
                                           new_dentry);

        if (!cache_new_parent || !cache_new_dentry)
                GOTO(exit, rc = -ENOMEM);

        pre_smfs_inode(old_dir, cache_old_dir);
        pre_smfs_inode(new_dir, cache_new_dir);

        handle = smfs_trans_start(old_dir, FSFILT_OP_RENAME, NULL);
        if (IS_ERR(handle)) {
                CERROR("smfs_do_mkdir: no space for transaction\n");
                GOTO(exit, rc = -ENOSPC);
        }
        //lock_kernel();
        
        SMFS_HOOK(old_dir, old_dentry, new_dir, new_dentry, HOOK_RENAME,
                  handle, PRE_HOOK, rc, exit); 
        
        rc = cache_old_dir->i_op->rename(cache_old_dir, cache_old_dentry,
                                         cache_new_dir, cache_new_dentry);
        
        post_smfs_inode(old_dir, cache_old_dir);
        post_smfs_inode(new_dir, cache_new_dir);

        if (new_dentry->d_inode)
                post_smfs_inode(new_dentry->d_inode, cache_new_dentry->d_inode);
        
        SMFS_HOOK(old_dir, old_dentry, new_dir, new_dentry, HOOK_RENAME, handle, 
                  POST_HOOK, rc, exit); 
        

exit:
        //unlock_kernel();
        smfs_trans_commit(old_dir, handle, 0);
        post_smfs_dentry(cache_old_dentry);
        post_smfs_dentry(cache_old_parent);
        post_smfs_dentry(cache_new_dentry);
        post_smfs_dentry(cache_new_parent);
        RETURN(rc);
}

struct inode_operations smfs_dir_iops = {
        create:         smfs_create,
        lookup:         smfs_lookup,
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

        ENTRY;
        
        cache_inode = I2CI(dentry->d_inode);
        if (!cache_inode || !cache_inode->i_fop->readdir)
                RETURN(-EINVAL);

        sfi = F2SMFI(filp);
        if (sfi->magic != SMFS_FILE_MAGIC) BUG();

        SMFS_HOOK(dentry->d_inode, filp, dirent, filldir, HOOK_READDIR, NULL, 
                  PRE_HOOK, rc, exit); 
        
        rc = cache_inode->i_fop->readdir(sfi->c_file, dirent, filldir);
        CDEBUG(D_INODE,"readdir rc=%u\n",rc);
        if (rc < 0)
                RETURN(rc);

        duplicate_file(filp, sfi->c_file);

        SMFS_HOOK(dentry->d_inode, filp, dirent, filldir, HOOK_READDIR, NULL, 
                  POST_HOOK, rc, exit);
        
exit:
        if (rc > 0)
                rc = 0;
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
