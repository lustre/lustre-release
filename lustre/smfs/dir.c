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
#include <linux/lustre_snap.h>
#include <linux/lustre_smfs.h>

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
        int rc = 0;

        ENTRY;

        cache_dir = I2CI(dir);
        if (!cache_dir)
                RETURN(-ENOENT);

        handle = smfs_trans_start(dir, FSFILT_OP_CREATE, NULL);
        if (IS_ERR(handle))
                       RETURN(-ENOSPC);

        SMFS_CACHE_HOOK_PRE(CACHE_HOOK_CREATE, handle, dir, rc);

        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);

        lock_kernel();
        if (!cache_dentry || !cache_parent)
                GOTO(exit, rc = -ENOMEM);


        SMFS_PRE_COW(dir, dentry, NULL, NULL, REINT_CREATE, "create", rc, exit);
        
        pre_smfs_inode(dir, cache_dir);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (cache_dir && cache_dir->i_op->create)
                rc = cache_dir->i_op->create(cache_dir, cache_dentry,
                                             mode);
#else
        if (cache_dir && cache_dir->i_op->create)
                rc = cache_dir->i_op->create(cache_dir, cache_dentry,
                                             mode, nd);
#endif
        if (rc)
                GOTO(exit, rc);

        inode = iget4(dir->i_sb, cache_dentry->d_inode->i_ino, NULL,
                      &I2SMI(dir)->smi_flags);
        if (!inode)
                GOTO(exit, rc = -ENOMEM);

        d_instantiate(dentry, inode);
        sm_set_inode_ops(cache_dentry->d_inode, inode);
        post_smfs_inode(dir, cache_dir);

        /*Do KML post hook*/

        SMFS_KML_POST(dir, dentry, NULL, NULL, REINT_CREATE,
                      "create", rc, exit);
        SMFS_CACHE_HOOK_POST(CACHE_HOOK_CREATE, handle, dir, dentry,
                             NULL, NULL, rc, exit);
exit:
        unlock_kernel();
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
        struct dentry *rc = NULL;
        void *handle = NULL;
        int rc2 = 0;

        ENTRY;

        if (!(cache_dir = I2CI(dir)))
                RETURN(ERR_PTR(-ENOENT));

        SMFS_CACHE_HOOK_PRE(CACHE_HOOK_LOOKUP, handle, dir, rc2);
        
        if (rc2)
                RETURN(ERR_PTR(rc2));

        /* preparing artificial backing fs dentries. */
        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);

        if (!cache_dentry || !cache_parent)
                GOTO(exit, rc = ERR_PTR(-ENOMEM));

        if (!cache_dir && cache_dir->i_op->lookup)
                GOTO(exit, rc = ERR_PTR(-ENOENT));

        SMFS_PRE_COW(dir, dentry, NULL, NULL, SNAP_LOOKUP, "lookup", rc, exit);

        /* perform lookup in backing fs. */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        rc = cache_dir->i_op->lookup(cache_dir, cache_dentry);
#else
        rc = cache_dir->i_op->lookup(cache_dir, cache_dentry, nd);
#endif

        if (rc && IS_ERR(rc))
                GOTO(exit, rc);

        if ((cache_inode = rc ? rc->d_inode : cache_dentry->d_inode)) {
                if (IS_ERR(cache_inode)) {
                        dentry->d_inode = cache_inode;
                        GOTO(exit, rc = NULL);
                }
                inode = iget4(dir->i_sb, cache_inode->i_ino, NULL,
                                    &I2SMI(dir)->smi_flags);
        } else {
                d_add(dentry, NULL);
                GOTO(exit, rc);
        }

        d_add(dentry, inode);
        rc = NULL;

        SMFS_CACHE_HOOK_POST(CACHE_HOOK_LOOKUP, handle, dir, dentry,
                             NULL, NULL, rc2, exit);
exit:
        if (rc2)
                rc = ERR_PTR(rc2);
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        smfs_trans_commit(dir, handle, 0);
        RETURN(rc);
}

static int smfs_link(struct dentry * old_dentry,
                     struct inode * dir, struct dentry *dentry)
{
        struct        inode *cache_old_inode = NULL;
        struct        inode *cache_dir = I2CI(dir);
        struct        inode *inode = NULL;
        struct  dentry *cache_dentry = NULL;
        struct  dentry *cache_old_dentry = NULL;
        struct  dentry *cache_parent = NULL;
        void        *handle = NULL;
        int        rc = 0;

        inode = old_dentry->d_inode;

        cache_old_inode = I2CI(inode);

        handle = smfs_trans_start(dir, FSFILT_OP_LINK, NULL);
        if (IS_ERR(handle))
                 RETURN(-ENOSPC);

        SMFS_CACHE_HOOK_PRE(CACHE_HOOK_LINK, handle, dir, rc);
        
        lock_kernel();
        
        SMFS_PRE_COW(dir, old_dentry, NULL, NULL, REINT_LINK, "link", rc, exit);
        
        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);

        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);

        cache_old_dentry = pre_smfs_dentry(NULL, cache_old_inode,
                                           old_dentry);
        if (!cache_old_dentry)
                GOTO(exit, rc = -ENOMEM);

        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(inode, cache_old_dentry->d_inode);

        if (cache_dir->i_op->link)
                rc = cache_dir->i_op->link(cache_old_dentry, cache_dir,
                                           cache_dentry);
        if (rc)
                GOTO(exit, rc);

        atomic_inc(&inode->i_count);
        post_smfs_inode(inode, cache_old_dentry->d_inode);
        d_instantiate(dentry, inode);
        post_smfs_inode(dir, cache_dir);

        SMFS_KML_POST(dir, old_dentry, dentry, NULL,
                      REINT_LINK, "link", rc, exit);

        SMFS_CACHE_HOOK_POST(CACHE_HOOK_LINK, handle,
                             dir, old_dentry, NULL, NULL, rc, exit);
exit:
        unlock_kernel();
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

        if (!cache_dir || !cache_inode)
                RETURN(-ENOENT);

        handle = smfs_trans_start(dir, FSFILT_OP_UNLINK, NULL);
        if (IS_ERR(handle))
                RETURN(-ENOSPC);

        SMFS_CACHE_HOOK_PRE(CACHE_HOOK_UNLINK, handle, dir, rc);

        SMFS_PRE_COW(dir, dentry, NULL, NULL, REINT_UNLINK, "unlink", rc, exit);
        
        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, cache_inode, dentry);

        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);
                
        lock_kernel();
        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(dentry->d_inode, cache_inode);
        if (cache_dir->i_op->unlink)
                rc = cache_dir->i_op->unlink(cache_dir, cache_dentry);
        post_smfs_inode(dentry->d_inode, cache_dentry->d_inode);
        post_smfs_inode(dir, cache_dir);
        unlock_kernel();
        SMFS_KML_POST(dir, dentry, &mode, NULL, REINT_UNLINK,
                      "unlink", rc, exit);

        SMFS_CACHE_HOOK_POST(CACHE_HOOK_UNLINK, handle, dir, dentry,
                             NULL, NULL, rc, exit);
exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        smfs_trans_commit(dir, handle, 0);
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

        if (!cache_dir)
                RETURN(-ENOENT);

        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);

        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);

        handle = smfs_trans_start(dir, FSFILT_OP_SYMLINK, NULL);
        if (IS_ERR(handle))
                RETURN(-ENOSPC);

        SMFS_CACHE_HOOK_PRE(CACHE_HOOK_SYMLINK, handle, dir, rc);

        SMFS_PRE_COW(dir, dentry, NULL, NULL, REINT_CREATE, "symlink", rc, 
                     exit);
        
        pre_smfs_inode(dir, cache_dir);
        lock_kernel();
        if (cache_dir->i_op->symlink)
                rc = cache_dir->i_op->symlink(cache_dir, cache_dentry, symname);

        inode = iget4(dir->i_sb, cache_dentry->d_inode->i_ino, NULL,
                      &I2SMI(dir)->smi_flags);
        post_smfs_inode(dir, cache_dir);
        if (inode)
                d_instantiate(dentry, inode);
        else
                rc = -ENOENT;

        tgt_len = strlen(symname) + 1;
        SMFS_KML_POST(dir, dentry, (char*)symname, &tgt_len, REINT_CREATE,
                      "symlink", rc, exit);

        SMFS_CACHE_HOOK_POST(CACHE_HOOK_SYMLINK, handle, dir, dentry,
                             NULL, NULL, rc, exit);
exit:
        unlock_kernel();
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        smfs_trans_commit(dir, handle, 0);
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

        if (!cache_dir)
                RETURN(-ENOENT);

        handle = smfs_trans_start(dir, FSFILT_OP_MKDIR, NULL);
        if (IS_ERR(handle))
                RETURN(-ENOSPC);

        SMFS_CACHE_HOOK_PRE(CACHE_HOOK_MKDIR, handle, dir, rc);

        SMFS_PRE_COW(dir, dentry, NULL, NULL, REINT_CREATE, "mkdir", rc, 
                     exit);
        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);

        lock_kernel();
        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);

        pre_smfs_inode(dir, cache_dir);

        if (cache_dir->i_op->mkdir)
                rc = cache_dir->i_op->mkdir(cache_dir, cache_dentry, mode);

        if (rc)
                GOTO(exit, rc);

        inode = iget4(dir->i_sb, cache_dentry->d_inode->i_ino, NULL,
                      &I2SMI(dir)->smi_flags);
        if (!inode)
                GOTO(exit, rc = -ENOENT);

        d_instantiate(dentry, inode);
        post_smfs_inode(dir, cache_dir);

        SMFS_KML_POST(dir, dentry, NULL, NULL,
                      REINT_CREATE, "mkdir", rc, exit);

        SMFS_CACHE_HOOK_POST(CACHE_HOOK_MKDIR, handle,
                             dir, dentry, NULL, NULL, rc, exit);
exit:
        unlock_kernel();
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        smfs_trans_commit(dir, handle, 0);
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

        if (!cache_dir)
                RETURN(-ENOENT);

        handle = smfs_trans_start(dir, FSFILT_OP_RMDIR, NULL);
        if (IS_ERR(handle) ) {
                CERROR("smfs_do_mkdir: no space for transaction\n");
                RETURN(-ENOSPC);
        }

        SMFS_CACHE_HOOK_PRE(CACHE_HOOK_RMDIR, handle, dir, rc);

        SMFS_PRE_COW(dir, dentry, NULL, NULL, REINT_UNLINK, "rmdir", rc, exit);

        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry);
        cache_dentry = pre_smfs_dentry(cache_parent, cache_inode, dentry);

        lock_kernel();
        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);

        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(dentry->d_inode, cache_dentry->d_inode);
        if (cache_dir->i_op->rmdir)
                rc = cache_dir->i_op->rmdir(cache_dir, cache_dentry);

        post_smfs_inode(dir, cache_dir);
        post_smfs_inode(dentry->d_inode, cache_dentry->d_inode);
        unlock_kernel();
        
        SMFS_KML_POST(dir, dentry, &mode, NULL,
                      REINT_UNLINK, "rmdir", rc, exit);

        SMFS_CACHE_HOOK_POST(CACHE_HOOK_RMDIR, handle, dir, dentry,
                             NULL, NULL, rc, exit);
exit:
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        smfs_trans_commit(dir, handle, 0);
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

        if (!cache_dir)
                RETURN(-ENOENT);

        handle = smfs_trans_start(dir, FSFILT_OP_MKNOD, NULL);
        if (IS_ERR(handle)) {
                CERROR("smfs_do_mkdir: no space for transaction\n");
                RETURN(-ENOSPC);
        }
        SMFS_CACHE_HOOK_PRE(CACHE_HOOK_MKNOD, handle, dir, rc);

        SMFS_PRE_COW(dir, dentry, NULL, NULL, REINT_CREATE, "mknod", rc, exit);
        cache_parent = pre_smfs_dentry(NULL, cache_dir, dentry->d_parent);
        cache_dentry = pre_smfs_dentry(cache_parent, NULL, dentry);
        lock_kernel();
        if (!cache_parent || !cache_dentry)
                GOTO(exit, rc = -ENOMEM);

        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(dentry->d_inode, cache_dentry->d_inode);

        if (!cache_dir->i_op->mknod)
                RETURN(-ENOENT);

        if ((rc = cache_dir->i_op->mknod(cache_dir, cache_dentry,
                                         mode, rdev)))
                GOTO(exit, rc);

        inode = iget4(dir->i_sb, cache_dentry->d_inode->i_ino, NULL,
                      &I2SMI(dir)->smi_flags);
        d_instantiate(dentry, inode);

        pre_smfs_inode(dir, cache_dir);
        pre_smfs_inode(dentry->d_inode, cache_dentry->d_inode);

        SMFS_KML_POST(dir, dentry, NULL, NULL,
                      REINT_CREATE, "mknod", rc, exit);

        SMFS_CACHE_HOOK_POST(CACHE_HOOK_MKNOD, handle, dir,
                             dentry, NULL, NULL, rc, exit);
exit:
        unlock_kernel();
        post_smfs_dentry(cache_dentry);
        post_smfs_dentry(cache_parent);
        smfs_trans_commit(dir, handle, 0);
        RETURN(rc);
}

static int smfs_rename(struct inode * old_dir, struct dentry *old_dentry,
                       struct inode * new_dir,struct dentry *new_dentry)
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

        if (!cache_old_dir || !cache_new_dir || !cache_old_inode)
                RETURN(-ENOENT);

        handle = smfs_trans_start(old_dir, FSFILT_OP_RENAME, NULL);
        if (IS_ERR(handle)) {
                CERROR("smfs_do_mkdir: no space for transaction\n");
                RETURN(-ENOSPC);
        }
        lock_kernel();

        SMFS_PRE_COW(old_dir, old_dentry, new_dir, new_dentry, REINT_RENAME, 
                     "rename", rc, exit);
        SMFS_CACHE_HOOK_PRE(CACHE_HOOK_RENAME, handle, old_dir, rc);

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

        if (cache_old_dir->i_op->rename)
                rc = cache_old_dir->i_op->rename(cache_old_dir, cache_old_dentry,
                                                 cache_new_dir, cache_new_dentry);
        
        post_smfs_inode(old_dir, cache_old_dir);
        post_smfs_inode(new_dir, cache_new_dir);

        SMFS_KML_POST(old_dir, old_dentry, new_dir,
                      new_dentry, REINT_RENAME, "rename", rc, exit);
        if (new_dentry->d_inode)
                post_smfs_inode(new_dentry->d_inode, cache_new_dentry->d_inode);

        SMFS_CACHE_HOOK_POST(CACHE_HOOK_RENAME, handle, old_dir, old_dentry,
                             new_dir, new_dentry, rc, exit);
exit:
        unlock_kernel();
        post_smfs_dentry(cache_old_dentry);
        post_smfs_dentry(cache_old_parent);
        post_smfs_dentry(cache_new_dentry);
        post_smfs_dentry(cache_new_parent);
        smfs_trans_commit(old_dir, handle, 0);
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
        loff_t *cache_ppos;
        int    rc = 0;

        cache_inode = I2CI(dentry->d_inode);

        if (!cache_inode)
                RETURN(-EINVAL);

        sfi = F2SMFI(filp);
        if (sfi->magic != SMFS_FILE_MAGIC) BUG();

        if (ppos != &(filp->f_pos))
                cache_ppos = &tmp_ppos;
        else
                cache_ppos = &sfi->c_file->f_pos;
        *cache_ppos = *ppos;

        if (cache_inode->i_fop->read)
                rc = cache_inode->i_fop->read(sfi->c_file, buf, size,
                                              cache_ppos);

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

        cache_inode = I2CI(dentry->d_inode);
        if (!cache_inode)
                RETURN(-EINVAL);

        sfi = F2SMFI(filp);
        if (sfi->magic != SMFS_FILE_MAGIC) BUG();

        if (cache_inode->i_fop->readdir)
                rc = cache_inode->i_fop->readdir(sfi->c_file, dirent, filldir);

        duplicate_file(filp, sfi->c_file);
        RETURN(rc);
}

struct file_operations smfs_dir_fops = {
        read:           smfs_read_dir,
        readdir:        smfs_readdir,           /* BKL held */
        ioctl:          smfs_ioctl,             /* BKL held */
        fsync:          smfs_fsync,         /* BKL held */
        open:           smfs_open,
        release:        smfs_release,
};
