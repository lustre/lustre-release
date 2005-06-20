/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/cache.c
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

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/lustre_idl.h>
#include <libcfs/list.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>

#include "smfs_internal.h"
int smfs_init_sm_ops(struct smfs_super_info *smb)
{
        struct sm_operations    *sm_ops;   /*cache ops for set cache inode ops*/

        OBD_ALLOC(sm_ops, sizeof(struct sm_operations));
        if (!sm_ops)
                RETURN(-ENOMEM);

        smb->sm_ops = sm_ops;
        RETURN(0);
}

void smfs_cleanup_sm_ops(struct smfs_super_info *smb)
{
        if (smb->sm_ops)
                OBD_FREE(smb->sm_ops, sizeof(struct sm_operations));
}

static void setup_iops(struct inode *cache_inode,
                       struct inode_operations *smfs_iops,
                       struct inode_operations *iops)
{

        LASSERT(cache_inode->i_op && smfs_iops && iops);
        
        if (cache_inode->i_op->create)
                iops->create = smfs_iops->create;
        if (cache_inode->i_op->lookup)
                iops->lookup = smfs_iops->lookup;
        if (cache_inode->i_op->link)
                iops->link = smfs_iops->link;
        if (cache_inode->i_op->unlink)
                iops->unlink = smfs_iops->unlink;
        if (cache_inode->i_op->symlink)
                iops->symlink = smfs_iops->symlink;
        if (cache_inode->i_op->mkdir)
                iops->mkdir = smfs_iops->mkdir;
        if (cache_inode->i_op->rmdir)
                iops->rmdir = smfs_iops->rmdir;
        if (cache_inode->i_op->mknod)
                iops->mknod = smfs_iops->mknod;
        if (cache_inode->i_op->rename)
                iops->rename = smfs_iops->rename;
        if (cache_inode->i_op->readlink)
                iops->readlink = smfs_iops->readlink;
        if (cache_inode->i_op->follow_link)
                iops->follow_link = smfs_iops->follow_link;
        if (cache_inode->i_op->truncate)
                iops->truncate = smfs_iops->truncate;
        if (cache_inode->i_op->permission)
                iops->permission = smfs_iops->permission;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (cache_inode->i_op->revalidate)
                iops->revalidate = smfs_iops->revalidate;
#endif
        if (cache_inode->i_op->setattr)
                iops->setattr = smfs_iops->setattr;
        if (cache_inode->i_op->getattr)
                iops->getattr = smfs_iops->getattr;
        if (cache_inode->i_op->setxattr)
                iops->setxattr = smfs_iops->setxattr;
        if (cache_inode->i_op->getxattr)
                iops->getxattr = smfs_iops->getxattr;
        if (cache_inode->i_op->listxattr)
                iops->listxattr = smfs_iops->listxattr;
        if (cache_inode->i_op->removexattr)
                iops->removexattr = smfs_iops->removexattr;
#if HAVE_LOOKUP_RAW
        if (cache_inode->i_op->lookup_raw)
                iops->lookup_raw = smfs_iops->lookup_raw;
#endif

}

static void setup_fops(struct inode *cache_inode,
                       struct file_operations *smfs_fops,
                       struct file_operations *fops)
{
        LASSERT(cache_inode->i_fop && smfs_fops && fops);
        
        if (cache_inode->i_fop->llseek)
                fops->llseek = smfs_fops->llseek;
        if (cache_inode->i_fop->read)
                fops->read = smfs_fops->read;
        if (cache_inode->i_fop->write)
                fops->write = smfs_fops->write;
        if (cache_inode->i_fop->readdir)
                fops->readdir = smfs_fops->readdir;
        if (cache_inode->i_fop->poll)
                fops->poll = smfs_fops->poll;
        if (cache_inode->i_fop->ioctl)
                fops->ioctl = smfs_fops->ioctl;
        if (cache_inode->i_fop->mmap)
                fops->mmap = smfs_fops->mmap;
        if (cache_inode->i_fop->flush)
                fops->flush = smfs_fops->flush;
        if (cache_inode->i_fop->fsync)
                fops->fsync = smfs_fops->fsync;
        if (cache_inode->i_fop->fasync)
                fops->fasync = smfs_fops->fasync;
        if (cache_inode->i_fop->lock)
                fops->lock = smfs_fops->lock;
        if (cache_inode->i_fop->readv)
                fops->readv = smfs_fops->readv;
        if (cache_inode->i_fop->writev)
                fops->writev = smfs_fops->writev;
        if (cache_inode->i_fop->sendpage)
                fops->sendpage = smfs_fops->sendpage;
        if (cache_inode->i_fop->get_unmapped_area)
                fops->get_unmapped_area = smfs_fops->get_unmapped_area;
                
        /* for dir file we also need replace the open and release method,
         * because we need initialize the cache file structs. */
        fops->open = smfs_fops->open;
        fops->release = smfs_fops->release;
}

static void setup_sm_file_ops(struct inode *inode)
{
        struct smfs_super_info *smb = S2SMI(inode->i_sb);
        struct inode *cache_inode = I2CI(inode);
        
        setup_iops(cache_inode, &smfs_file_iops, &smb->sm_ops->sm_file_iops);
        setup_fops(cache_inode, &smfs_file_fops, &smb->sm_ops->sm_file_fops);

        lock_kernel();
        smb->smsi_ops_check |= FILE_OPS_CHECK;
        unlock_kernel();
}

static void setup_sm_dir_ops(struct inode *inode)
{
        struct smfs_super_info *smb = S2SMI(inode->i_sb);
        struct inode *cache_inode = I2CI(inode);
        
        setup_iops(cache_inode, &smfs_dir_iops, &smb->sm_ops->sm_dir_iops);
        setup_fops(cache_inode, &smfs_dir_fops, &smb->sm_ops->sm_dir_fops);

        lock_kernel();
        smb->smsi_ops_check |= DIR_OPS_CHECK;
        unlock_kernel();
}

static void setup_sm_symlink_ops(struct inode *inode)
{
        struct smfs_super_info *smb = S2SMI(inode->i_sb);
        struct inode *cache_inode = I2CI(inode);
        
        setup_iops(cache_inode, &smfs_sym_iops, &smb->sm_ops->sm_sym_iops);
        setup_fops(cache_inode, &smfs_sym_fops, &smb->sm_ops->sm_sym_fops);

        lock_kernel();
        smb->smsi_ops_check |= SYMLINK_OPS_CHECK;
        unlock_kernel();
}

static void setup_sm_special_ops(struct inode *inode)
{
        struct smfs_super_info *smb = S2SMI(inode->i_sb);
        struct inode *cache_inode = I2CI(inode);
        
        setup_iops(cache_inode, &smfs_special_iops, &smb->sm_ops->sm_special_iops);

        lock_kernel();
        smb->smsi_ops_check |= SPECIAL_OPS_CHECK;
        unlock_kernel();
}

#define SMFS_IOPEN_INO  1

void sm_set_inode_ops(struct inode *inode)
{
        struct smfs_super_info *smb = S2SMI(inode->i_sb);

        //iopen stuff
        if (inode->i_ino == SMFS_IOPEN_INO) {
                inode->i_op = &smfs_iopen_iops;
                inode->i_fop = &smfs_iopen_fops;
                return;
        }

        /* set the correct sm_{file,dir,sym}_iops */
        if (S_ISDIR(inode->i_mode)) {
                if (!(smb->smsi_ops_check & DIR_OPS_CHECK))
                        setup_sm_dir_ops(inode);
                inode->i_op = &smb->sm_ops->sm_dir_iops;
                inode->i_fop = &smb->sm_ops->sm_dir_fops;   
        } else if (S_ISREG(inode->i_mode)) {
                if (!(smb->smsi_ops_check & FILE_OPS_CHECK))
                        setup_sm_file_ops(inode);
                inode->i_fop = &smb->sm_ops->sm_file_fops;
                inode->i_op = &smb->sm_ops->sm_file_iops;

        } else if (S_ISLNK(inode->i_mode)) {
                if (!(smb->smsi_ops_check & SYMLINK_OPS_CHECK))
                        setup_sm_symlink_ops(inode);
                inode->i_op = &smb->sm_ops->sm_sym_iops;
                inode->i_fop =  &smb->sm_ops->sm_sym_fops;
        } else {
                if (!(smb->smsi_ops_check & SPECIAL_OPS_CHECK))
                        setup_sm_special_ops(inode);
                inode->i_op = &smb->sm_ops->sm_special_iops;
        }
}


void sm_set_sb_ops(struct super_block *cache_sb, struct super_block *sb)
{
        struct smfs_super_info *smb = S2SMI(sb);
        struct super_operations *sops = &smb->sm_ops->sm_sb_ops;
        struct super_operations *smfs_sops = &smfs_super_ops;
        ENTRY;

        if (smb->smsi_ops_check & SB_OPS_CHECK)
                return;
        
        //set up only operations exist in backfs
        memset(sops, 0, sizeof (struct super_operations));
        if (cache_sb->s_op) {
                if (cache_sb->s_op->dirty_inode)
                        sops->dirty_inode = smfs_sops->dirty_inode;
                if (cache_sb->s_op->write_inode)
                        sops->write_inode = smfs_sops->write_inode;
                if (cache_sb->s_op->put_super)
                        sops->put_super = smfs_sops->put_super;
                if (cache_sb->s_op->write_super)
                        sops->write_super = smfs_sops->write_super;
                if (cache_sb->s_op->write_super_lockfs)
                        sops->write_super_lockfs = smfs_sops->write_super_lockfs;
                if (cache_sb->s_op->unlockfs)
                        sops->unlockfs = smfs_sops->unlockfs;
                if (cache_sb->s_op->statfs)
                        sops->statfs = smfs_sops->statfs;
                if (cache_sb->s_op->remount_fs)
                        sops->remount_fs = smfs_sops->remount_fs;
                //if (cache_sb->s_op->umount_begin)
                //      sops->umount_begin = smfs_sops->umount_begin;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                if (cache_sb->s_op->fh_to_dentry)
                        sops->fh_to_dentry = smfs_sops->fh_to_dentry;
                if (cache_sb->s_op->dentry_to_fh)
                        sops->dentry_to_fh = smfs_sops->dentry_to_fh;
                if (cache_sb->s_op->show_options)
                        sops->show_options = smfs_sops->show_options;
                
                sops->read_inode2 = smfs_sops->read_inode2;
#endif
                /* these ops are needed always */
                sops->clear_inode = smfs_sops->clear_inode;
                sops->delete_inode = smfs_sops->delete_inode;

        }

        lock_kernel();
        smb->smsi_ops_check |= SB_OPS_CHECK;
        unlock_kernel();
        sb->s_op = sops;
        return;
}


