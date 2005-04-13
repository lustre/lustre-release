/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/inode.c
 *  Lustre filesystem abstraction routines
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
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include <linux/lustre_snap.h>

#include "smfs_internal.h"

static ssize_t smfs_write(struct file *filp, const char *buf, size_t count,
                          loff_t *ppos)
{
        struct inode *cache_inode = I2CI(filp->f_dentry->d_inode);
        struct smfs_file_info *sfi;
        loff_t *cache_ppos = NULL;
        int rc = 0;
        struct hook_write_msg msg = {
                .dentry = filp->f_dentry,
                .count = count,
                .pos = *ppos
        };
         
        ENTRY;

        LASSERT(cache_inode);
        LASSERT(cache_inode->i_fop->write);

        sfi = F2SMFI(filp);

        if (sfi->magic != SMFS_FILE_MAGIC) 
                LBUG();

        if (filp->f_flags & O_APPEND)
                msg.pos = filp->f_dentry->d_inode->i_size;
        
        pre_smfs_inode(filp->f_dentry->d_inode, cache_inode);

        SMFS_PRE_HOOK(filp->f_dentry->d_inode, HOOK_WRITE, &msg);

        if (ppos != &(filp->f_pos)) {
                cache_ppos = &msg.pos;
        } else {
                cache_ppos = &sfi->c_file->f_pos;
        }
        
        *cache_ppos = *ppos;

        rc = cache_inode->i_fop->write(sfi->c_file, buf, count,
                                       cache_ppos);
        
        SMFS_POST_HOOK(filp->f_dentry->d_inode, HOOK_WRITE, &msg, rc);
        
        post_smfs_inode(filp->f_dentry->d_inode, cache_inode);
        *ppos = *cache_ppos;
        duplicate_file(filp, sfi->c_file);
        
        RETURN(rc);
}

int smfs_ioctl(struct inode * inode, struct file * filp,
               unsigned int cmd, unsigned long arg)
{
        struct  inode *cache_inode = I2CI(filp->f_dentry->d_inode);
        struct  smfs_file_info *sfi;
        ssize_t rc = 0;

        ENTRY;

        LASSERT(cache_inode);
        LASSERT(cache_inode->i_fop->ioctl);

        sfi = F2SMFI(filp);
        if (sfi->magic != SMFS_FILE_MAGIC) 
                LBUG();

        pre_smfs_inode(inode, cache_inode);

        rc = cache_inode->i_fop->ioctl(cache_inode, sfi->c_file, cmd, arg);
        
        post_smfs_inode(inode, cache_inode);
        duplicate_file(filp, sfi->c_file);

        RETURN(rc);
}

static ssize_t smfs_read(struct file *filp, char *buf,
                         size_t count, loff_t *ppos)
{
        struct  inode *cache_inode = I2CI(filp->f_dentry->d_inode);
        struct  smfs_file_info *sfi;
        loff_t  tmp_ppos;
        loff_t  *cache_ppos = NULL;
        ssize_t rc = 0;

        ENTRY;

        LASSERT(cache_inode);
        LASSERT(cache_inode->i_fop->read);

        sfi = F2SMFI(filp);
        if (sfi->magic != SMFS_FILE_MAGIC) 
                LBUG();

        if (ppos != &(filp->f_pos)) {
                cache_ppos = &tmp_ppos;
        } else {
                cache_ppos = &sfi->c_file->f_pos;
        }
        *cache_ppos = *ppos;

        pre_smfs_inode(filp->f_dentry->d_inode, cache_inode);

        rc = cache_inode->i_fop->read(sfi->c_file, buf, count, cache_ppos);
        
        *ppos = *cache_ppos;
        post_smfs_inode(filp->f_dentry->d_inode, cache_inode);
        duplicate_file(filp, sfi->c_file);

        RETURN(rc);
}

static loff_t smfs_llseek(struct file *file, loff_t offset, int origin)
{
        struct  inode *cache_inode = I2CI(file->f_dentry->d_inode);
        struct  smfs_file_info *sfi;
        ssize_t rc = 0;

        ENTRY;

        LASSERT(cache_inode);
        LASSERT(cache_inode->i_fop->llseek);

        sfi = F2SMFI(file);
        if (sfi->magic != SMFS_FILE_MAGIC) 
                LBUG();

        pre_smfs_inode(file->f_dentry->d_inode, cache_inode);

        rc = cache_inode->i_fop->llseek(sfi->c_file, offset, origin);
        
        post_smfs_inode(file->f_dentry->d_inode, cache_inode);
        duplicate_file(file, sfi->c_file);

        RETURN(rc);
}

static int smfs_mmap(struct file *file, struct vm_area_struct *vma)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct smfs_file_info *sfi;
        struct inode *cache_inode = I2CI(inode);
        int rc = 0;
        ENTRY;

        LASSERT(cache_inode);
        
        sfi = F2SMFI(file);
        if (sfi->magic != SMFS_FILE_MAGIC)
                LBUG();

        if (cache_inode->i_mapping == &cache_inode->i_data)
                inode->i_mapping = cache_inode->i_mapping;

        pre_smfs_inode(inode, cache_inode);
        
        rc = cache_inode->i_fop->mmap(sfi->c_file, vma);

        post_smfs_inode(inode, cache_inode);
        duplicate_file(file, sfi->c_file);

        RETURN(rc);
}

static int smfs_init_cache_file(struct inode *inode, struct file *filp)
{
        struct smfs_file_info *sfi = NULL;
        struct file *cache_filp = NULL;
        struct dentry *cache_dentry = NULL;
        int rc = 0;
        ENTRY;

        OBD_ALLOC(sfi, sizeof(struct smfs_file_info));
        if (!sfi)
                RETURN(-ENOMEM);

        cache_filp = get_empty_filp();
        if (!cache_filp) {
                rc = -ENOMEM;
                goto err_exit;
        }

        sfi->magic = SMFS_FILE_MAGIC;

        cache_dentry = pre_smfs_dentry(NULL, I2CI(inode), filp->f_dentry);
        if (!cache_dentry) {
                rc = -ENOMEM;
                goto err_exit;
        }

        cache_filp->f_vfsmnt = filp->f_vfsmnt;
        cache_filp->f_dentry = cache_dentry;
        duplicate_file(cache_filp, filp);
        sfi->c_file = cache_filp;

        if (filp->private_data != NULL)
                LBUG();

        filp->private_data = sfi;

        RETURN(0);
err_exit:
        if (sfi)
                OBD_FREE(sfi, sizeof(struct smfs_file_info));
        if (cache_filp)
                put_filp(cache_filp);
        RETURN(rc);
}

static int smfs_cleanup_cache_file(struct file *filp)
{
        struct smfs_file_info *sfi = NULL;
                
        ENTRY;

        if (!filp)
                RETURN(0);
        
        sfi = F2SMFI(filp);

        post_smfs_dentry(sfi->c_file->f_dentry);

        put_filp(sfi->c_file);

        OBD_FREE(sfi, sizeof(struct smfs_file_info));

        filp->private_data = NULL;

        RETURN(0);
}

int smfs_open(struct inode *inode, struct file *filp)
{
        struct inode *cache_inode = I2CI(inode);
        int rc = 0;
        
        ENTRY;
        
        LASSERT(cache_inode);
        
        if ((rc = smfs_init_cache_file(inode, filp)))
                RETURN(rc);
        //it possible that backstore fs has no open(), 
        //but we need it to init cache filp
        if (cache_inode->i_fop->open) {
                rc = cache_inode->i_fop->open(cache_inode, F2CF(filp));
                duplicate_file(filp, F2CF(filp));
        }

        RETURN(rc);
}

int smfs_release(struct inode *inode, struct file *filp)
{
        struct inode *cache_inode = I2CI(inode);
        struct file *cache_file = NULL;
        struct smfs_file_info *sfi = NULL;
        int rc = 0;
        
        ENTRY;

        LASSERT(cache_inode);
        
        if (filp) {
                sfi = F2SMFI(filp);
                if (sfi->magic != SMFS_FILE_MAGIC)
                        LBUG();
                cache_file = sfi->c_file;
        }
        
        if (cache_inode->i_fop->release)
                rc = cache_inode->i_fop->release(cache_inode, cache_file);

        post_smfs_inode(inode, cache_inode);

        smfs_cleanup_cache_file(filp);
        
        RETURN(rc);
}

int smfs_fsync(struct file *file, struct dentry *dentry, int datasync)
{
        struct smfs_file_info *sfi = NULL;
        struct dentry *cache_dentry = NULL;
        struct file *cache_file = NULL;
        struct inode *cache_inode = I2CI(dentry->d_inode);
        int rc = 0;

        ENTRY;
        
        LASSERT(cache_inode);
        LASSERT(cache_inode->i_fop->fsync);
        
        cache_dentry = pre_smfs_dentry(NULL, cache_inode, dentry);
        if (!cache_dentry)
                RETURN(-ENOMEM);

        if (file) {
                sfi = F2SMFI(file);
                if (sfi->magic != SMFS_FILE_MAGIC)
                        LBUG();
                cache_file = sfi->c_file;
        } 

        pre_smfs_inode(dentry->d_inode, cache_inode);

        rc = cache_inode->i_fop->fsync(cache_file,
                                       cache_dentry, datasync);
        
        post_smfs_inode(dentry->d_inode, cache_inode);
        duplicate_file(file, cache_file);
        post_smfs_dentry(cache_dentry);

        RETURN(rc);
}

struct file_operations smfs_file_fops = {
        llseek:         smfs_llseek,
        read:           smfs_read,
        write:          smfs_write,
        ioctl:          smfs_ioctl,
        mmap:           smfs_mmap,
        open:           smfs_open,
        release:        smfs_release,
        fsync:          smfs_fsync,
};

static void smfs_truncate(struct inode *inode)
{
        struct inode *cache_inode = I2CI(inode);

        if (!cache_inode || !cache_inode->i_op->truncate)
                return;

        pre_smfs_inode(inode, cache_inode);
        
        cache_inode->i_op->truncate(cache_inode);

        post_smfs_inode(inode, cache_inode);

        return;
}

int smfs_setattr(struct dentry *dentry, struct iattr *attr)
{
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct dentry *cache_dentry;
        void  *handle = NULL;
        int rc = 0;
        struct hook_setattr_msg msg = {
                .dentry = dentry,
                .attr = attr
        };

        ENTRY;
        
        LASSERT(cache_inode);
        LASSERT(cache_inode->i_op->setattr);

        cache_dentry = pre_smfs_dentry(NULL, cache_inode, dentry);
        if (!cache_dentry)
                RETURN(-ENOMEM);

        handle = smfs_trans_start(dentry->d_inode, FSFILT_OP_SETATTR, NULL);
        if (IS_ERR(handle) ) {
                rc = -ENOSPC;
                goto exit;
        }

        pre_smfs_inode(dentry->d_inode, cache_inode);
        
        SMFS_PRE_HOOK(dentry->d_inode, HOOK_SETATTR, &msg); 
                  
        rc = cache_inode->i_op->setattr(cache_dentry, attr);
        
        SMFS_POST_HOOK(dentry->d_inode, HOOK_SETATTR, &msg, rc);
        
        post_smfs_inode(dentry->d_inode, cache_inode);
        smfs_trans_commit(dentry->d_inode, handle, 0);
exit:
        post_smfs_dentry(cache_dentry);
        RETURN(rc);
}

int smfs_setxattr(struct dentry *dentry, const char *name, const void *value,
                  size_t size, int flags)
{
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct dentry *cache_dentry = NULL;
        int rc = 0;

        ENTRY;
        
        LASSERT(cache_inode);
        LASSERT(cache_inode->i_op->setxattr);
        
        cache_dentry = pre_smfs_dentry(NULL, cache_inode, dentry);
        if (!cache_dentry)
                RETURN(-ENOMEM);

        pre_smfs_inode(dentry->d_inode, cache_inode);

        rc = cache_inode->i_op->setxattr(cache_dentry, name, value,
                                         size, flags);

        post_smfs_inode(dentry->d_inode, cache_inode);
        post_smfs_dentry(cache_dentry);

        RETURN(rc);
}

int smfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
                  size_t size)
{
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct dentry *cache_dentry;
        int rc = 0;

        ENTRY;
        
        LASSERT(cache_inode);
        LASSERT(cache_inode->i_op->getxattr);
        
        cache_dentry = pre_smfs_dentry(NULL, cache_inode, dentry);
        if (!cache_dentry)
                RETURN(-ENOMEM);

        pre_smfs_inode(dentry->d_inode, cache_inode);

        rc = cache_inode->i_op->getxattr(cache_dentry, name, buffer,
                                         size);

        post_smfs_inode(dentry->d_inode, cache_inode);
        post_smfs_dentry(cache_dentry);

        RETURN(rc);
}

ssize_t smfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct dentry *cache_dentry;
        int rc = 0;

        ENTRY;
        
        LASSERT(cache_inode);
        LASSERT(cache_inode->i_op->listxattr);

        cache_dentry = pre_smfs_dentry(NULL, cache_inode, dentry);
        if (!cache_dentry)
                RETURN(-ENOMEM);

        pre_smfs_inode(dentry->d_inode, cache_inode);

        rc = cache_inode->i_op->listxattr(cache_dentry, buffer, size);

        post_smfs_inode(dentry->d_inode, cache_inode);
        post_smfs_dentry(cache_dentry);

        RETURN(rc);
}

int smfs_removexattr(struct dentry *dentry, const char *name)
{
        struct inode *cache_inode = I2CI(dentry->d_inode);
        struct dentry *cache_dentry;
        int rc = 0;

        ENTRY;
        
        LASSERT(cache_inode);
        LASSERT(cache_inode->i_op->removexattr);

        cache_dentry = pre_smfs_dentry(NULL, cache_inode, dentry);
        if (!cache_dentry)
                RETURN(-ENOMEM);

        pre_smfs_inode(dentry->d_inode, cache_inode);

        rc = cache_inode->i_op->removexattr(cache_dentry, name);

        post_smfs_inode(dentry->d_inode, cache_inode);
        post_smfs_dentry(cache_dentry);

        RETURN(rc);
}

struct inode_operations smfs_file_iops = {
        .truncate       = smfs_truncate,          /* BKL held */
        .setattr        = smfs_setattr,           /* BKL held */
        .setxattr       = smfs_setxattr,          /* BKL held */
        .getxattr       = smfs_getxattr,          /* BKL held */
        .listxattr      = smfs_listxattr,         /* BKL held */
        .removexattr    = smfs_removexattr,       /* BKL held */
};

