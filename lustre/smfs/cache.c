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
#include <portals/list.h>
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
                       struct inode_operations *iops,
                       struct inode_operations *cache_iops)
{

        if (cache_inode->i_op && cache_iops && iops) {
                if (cache_inode->i_op->create)
                        iops->create = cache_iops->create;
                if (cache_inode->i_op->lookup)
                        iops->lookup = cache_iops->lookup;
                if (cache_inode->i_op->link)
                        iops->link = cache_iops->link;
                if (cache_inode->i_op->unlink)
                        iops->unlink = cache_iops->unlink;
                if (cache_inode->i_op->symlink)
                        iops->symlink = cache_iops->symlink;
                if (cache_inode->i_op->mkdir)
                        iops->mkdir = cache_iops->mkdir;
                if (cache_inode->i_op->rmdir)
                        iops->rmdir = cache_iops->rmdir;
                if (cache_inode->i_op->mknod)
                        iops->mknod = cache_iops->mknod;
                if (cache_inode->i_op->rename)
                        iops->rename = cache_iops->rename;
                if (cache_inode->i_op->readlink)
                        iops->readlink = cache_iops->readlink;
                if (cache_inode->i_op->follow_link)
                        iops->follow_link = cache_iops->follow_link;
                if (cache_inode->i_op->truncate)
                        iops->truncate = cache_iops->truncate;
                if (cache_inode->i_op->permission)
                        iops->permission = cache_iops->permission;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                if (cache_inode->i_op->revalidate)
                        iops->revalidate = cache_iops->revalidate;
#endif
                if (cache_inode->i_op->setattr)
                        iops->setattr = cache_iops->setattr;
                if (cache_inode->i_op->getattr)
                        iops->getattr = cache_iops->getattr;
                if (cache_inode->i_op->setxattr)
                        iops->setxattr = cache_iops->setxattr;
                if (cache_inode->i_op->getxattr)
                        iops->getxattr = cache_iops->getxattr;
                if (cache_inode->i_op->listxattr)
                        iops->listxattr = cache_iops->listxattr;
                if (cache_inode->i_op->removexattr)
                        iops->removexattr = cache_iops->removexattr;
        }
}

static void setup_fops(struct inode *cache_inode,
                       struct file_operations *fops,
                       struct file_operations *cache_fops)
{
        if (cache_inode->i_fop && cache_fops && fops) {
                if (cache_inode->i_fop->llseek)
                        fops->llseek = cache_fops->llseek;
                if (cache_inode->i_fop->read)
                        fops->read = cache_fops->read;
                if (cache_inode->i_fop->write)
                        fops->write = cache_fops->write;
                if (cache_inode->i_fop->readdir)
                        fops->readdir = cache_fops->readdir;
                if (cache_inode->i_fop->poll)
                        fops->poll = cache_fops->poll;
                if (cache_inode->i_fop->ioctl)
                        fops->ioctl = cache_fops->ioctl;
                if (cache_inode->i_fop->mmap)
                        fops->mmap = cache_fops->mmap;
                if (cache_inode->i_fop->flush)
                        fops->flush = cache_fops->flush;
                if (cache_inode->i_fop->fsync)
                        fops->fsync = cache_fops->fsync;
                if (cache_inode->i_fop->fasync)
                        fops->fasync = cache_fops->fasync;
                if (cache_inode->i_fop->lock)
                        fops->lock = cache_fops->lock;
                if (cache_inode->i_fop->readv)
                        fops->readv = cache_fops->readv;
                if (cache_inode->i_fop->writev)
                        fops->writev = cache_fops->writev;
                if (cache_inode->i_fop->sendpage)
                        fops->sendpage = cache_fops->sendpage;
                if (cache_inode->i_fop->get_unmapped_area)
                        fops->get_unmapped_area = cache_fops->get_unmapped_area;

                /* for dir file we also need replace the open and release method,
                 * because we need initialize the cache file structs. */
                fops->open = cache_fops->open;
                fops->release = cache_fops->release;
        }
}

static void setup_sm_file_ops(struct inode *cache_inode, struct inode *inode,
                              struct inode_operations *cache_iops,
                              struct file_operations *cache_fops)
{
        struct smfs_super_info *smb;
        struct inode_operations *iops;
        struct file_operations *fops;

        smb = S2SMI(inode->i_sb);

        if (smb->smsi_ops_check & FILE_OPS_CHECK)
                return;

        iops = cache_fiops(smb);
        fops = cache_ffops(smb);

        setup_iops(cache_inode, iops, cache_iops);
        setup_fops(cache_inode, fops, cache_fops);

        lock_kernel();
        smb->smsi_ops_check |= FILE_OPS_CHECK;
        unlock_kernel();
}

static void setup_sm_dir_ops(struct inode *cache_inode, struct inode *inode,
                             struct inode_operations *cache_dir_iops,
                             struct file_operations *cache_dir_fops)
{
        struct smfs_super_info *smb;
        struct inode_operations *iops;
        struct file_operations *fops;

        smb = S2SMI(inode->i_sb);

        if (smb->smsi_ops_check & DIR_OPS_CHECK)
                return;

        iops = cache_diops(smb);
        fops = cache_dfops(smb);

        setup_iops(cache_inode, iops, cache_dir_iops);
        setup_fops(cache_inode, fops, cache_dir_fops);

        lock_kernel();
        smb->smsi_ops_check |= DIR_OPS_CHECK;
        unlock_kernel();
}

static void setup_sm_symlink_ops(struct inode *cache_inode, struct inode *inode,
                                 struct inode_operations *cache_sym_iops,
                                 struct file_operations *cache_sym_fops)
{
        struct smfs_super_info *smb;
        struct inode_operations *iops;
        struct file_operations *fops;

        smb = S2SMI(inode->i_sb);

        if (smb->smsi_ops_check & SYMLINK_OPS_CHECK)
                return;

        iops = cache_siops(smb);
        fops = cache_sfops(smb);

        setup_iops(cache_inode, iops, cache_sym_iops);
        setup_fops(cache_inode, fops, cache_sym_fops);

        lock_kernel();
        smb->smsi_ops_check |= SYMLINK_OPS_CHECK;
        unlock_kernel();
}

static void setup_sm_sb_ops(struct super_block *cache_sb, struct super_block *sb,
                            struct super_operations *smfs_sops)
{
        struct smfs_super_info *smb;
        struct super_operations *sops;

        ENTRY;

        smb = S2SMI(sb);

        if (smb->smsi_ops_check & SB_OPS_CHECK)
                return;

        sops = cache_sops(smb);
        memset(sops, 0, sizeof (struct super_operations));

        if (cache_sb->s_op) {
                if (cache_sb->s_op->read_inode)
                        sops->read_inode = smfs_sops->read_inode;
                if (cache_sb->s_op->dirty_inode)
                        sops->dirty_inode = smfs_sops->dirty_inode;
                if (cache_sb->s_op->write_inode)
                        sops->write_inode = smfs_sops->write_inode;
                if (cache_sb->s_op->put_inode)
                        sops->put_inode = smfs_sops->put_inode;
                if (cache_sb->s_op->delete_inode)
                        sops->delete_inode = smfs_sops->delete_inode;
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
                if (cache_sb->s_op->umount_begin)
                        sops->umount_begin = smfs_sops->umount_begin;
                if (cache_sb->s_op->fh_to_dentry)
                        sops->fh_to_dentry = smfs_sops->fh_to_dentry;
                if (cache_sb->s_op->dentry_to_fh)
                        sops->dentry_to_fh = smfs_sops->dentry_to_fh;
                if (cache_sb->s_op->show_options)
                        sops->show_options = smfs_sops->show_options;

                /* FIXME-WANGDI we need this method to clear the cache inode. */
                sops->clear_inode = smfs_sops->clear_inode;
                sops->read_inode2 = smfs_sops->read_inode2;
        }

        lock_kernel();
        smb->smsi_ops_check |= SB_OPS_CHECK;
        unlock_kernel();
        return;
}

void sm_set_inode_ops(struct inode *cache_inode, struct inode *inode)
{
        struct smfs_super_info *smb = S2SMI(inode->i_sb);

        /* XXX now set the correct sm_{file,dir,sym}_iops */
        if (S_ISDIR(inode->i_mode)) {
                setup_sm_dir_ops(cache_inode, inode,
                                 &smfs_dir_iops,
                                 &smfs_dir_fops);
                inode->i_op = cache_diops(smb);
                inode->i_fop = cache_dfops(smb);
        } else if (S_ISREG(inode->i_mode)) {
                setup_sm_file_ops(cache_inode, inode,
                                  &smfs_file_iops,
                                  &smfs_file_fops);
                CDEBUG(D_INODE, "inode %lu, i_op at %p\n",
                       inode->i_ino, inode->i_op);
                inode->i_fop = cache_ffops(smb);
                inode->i_op = cache_fiops(smb);

        } else if (S_ISLNK(inode->i_mode)) {
                setup_sm_symlink_ops(cache_inode, inode,
                                     &smfs_sym_iops,
                                     &smfs_sym_fops);
                inode->i_op = cache_siops(smb);
                inode->i_fop = cache_sfops(smb);
                CDEBUG(D_INODE, "inode %lu, i_op at %p\n",
                       inode->i_ino, inode->i_op);
        }
}

void sm_set_sb_ops(struct super_block *cache_sb, struct super_block *sb)
{
        struct smfs_super_info *smb;

        smb = S2SMI(sb);

        setup_sm_sb_ops(cache_sb, sb, &smfs_super_ops);

        sb->s_op = cache_sops(smb);
        return;
}
struct smfs_hook_ops *smfs_alloc_hook_ops(char *name, smfs_hook_func pre_hook, 
                                       smfs_hook_func post_hook)
{
        struct smfs_hook_ops *smfs_hops = NULL;
        
        ENTRY;
        OBD_ALLOC(smfs_hops, sizeof(struct smfs_hook_ops));

        if (!smfs_hops)
                RETURN(NULL);
 
        OBD_ALLOC(smfs_hops->smh_name, strlen(name) + 1);
        
        if (!smfs_hops->smh_name) { 
                OBD_FREE(smfs_hops, sizeof(struct smfs_hook_ops));
                RETURN(NULL);
        }
        
        memcpy(smfs_hops->smh_name, name, strlen(name));  
       
        smfs_hops->smh_post_op = post_hook;  
        smfs_hops->smh_pre_op = pre_hook;  
        
        RETURN(smfs_hops); 
}

void smfs_free_hook_ops(struct smfs_hook_ops *hops)
{
        if (hops) {
                if (hops->smh_name){
                        OBD_FREE(hops->smh_name, strlen(hops->smh_name) + 1);
                }
                OBD_FREE(hops, sizeof(struct smfs_hook_ops));
        }
}

int smfs_register_hook_ops(struct super_block *sb, 
                           struct smfs_hook_ops *smh_ops)
{
        struct smfs_super_info *smb = S2SMI(sb);
        struct list_head *hlist = &smb->smsi_hook_list;
        struct list_head *p;
        ENTRY;
 
        list_for_each(p, hlist) {
                struct smfs_hook_ops *found;               
                found = list_entry(p, struct smfs_hook_ops, smh_list);
                if (!strcmp(found->smh_name, smh_ops->smh_name)) {
                        CWARN("hook ops %s list  reregister\n", smh_ops->smh_name);
                        RETURN(0);
                }
        }
	list_add(&smh_ops->smh_list, hlist);
        RETURN(0);
} 
struct smfs_hook_ops  *smfs_unregister_hook_ops(struct super_block *sb, 
                                                char *name)
{
        struct smfs_super_info *smb = S2SMI(sb);
        struct list_head *hlist = &smb->smsi_hook_list;
        struct list_head *p;
        ENTRY;      
 
        list_for_each(p, hlist) {
 		struct smfs_hook_ops *found;

                found = list_entry(p, typeof(*found), smh_list);
                if (!memcmp(found->smh_name, name, strlen(name))) {
                        list_del(p);
                        RETURN(found);
                }
        } 
        RETURN(NULL);
}
                        
