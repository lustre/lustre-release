/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/super.c
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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/loop.h>
#include <linux/errno.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include "smfs_internal.h"

static char *smfs_options(char *data, char **devstr, 
                          char **namestr, char *opts, 
                          int *flags)  
{
        struct option *opt_value = NULL;
        char   *pos;
        
        LASSERT(opts && flags);

        while (!(get_opt(&opt_value, &pos))) {
                if (!strcmp(opt_value->opt, "dev")) {
                        if (devstr != NULL)
                                *devstr = opt_value->value;
                } else if (!strcmp(opt_value->opt, "type")) {
                        if (namestr != NULL)
                                *namestr = opt_value->value;
                } else if (!strcmp(opt_value->opt, "kml")) {
                        *flags |= SM_DO_REC;
                } else if (!strcmp(opt_value->opt, "cache")) {
                        *flags |= SM_CACHE_HOOK;
                } else if (!strcmp(opt_value->opt, "snap")) {
                        *flags |= SM_DO_COW;
                } else if (!strcmp(opt_value->opt, "options")) {
                        if (strlen(opts) == 0)
                                sprintf((char *)opts + strlen(opts), "%s",
                                        opt_value->value);
                        else  
                                sprintf((char *)opts + strlen(opts), ",%s",
                                        opt_value->value);
                } else {
                        /* FIXME-WANGDI: how about the opt_value->value */
                        if (strlen(opts) == 0)
                                sprintf((char *)opts + strlen(opts), "%s",
                                        opt_value->opt);
                        else  
                                sprintf((char *)opts + strlen(opts), ",%s",
                                        opt_value->opt);
                }
        }
        return pos;
}

struct super_block *smfs_get_sb_by_path(char *path, int len)
{
        struct super_block *sb;
        struct nameidata nd;
        int error = 0;

        ENTRY;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (path_init(path, LOOKUP_FOLLOW, &nd)) {
#else
        if (path_lookup(path, LOOKUP_FOLLOW, &nd)) {
#endif
                error = path_walk(path, &nd);
                if (error) {
                        path_release(&nd);
                        RETURN(NULL);
                }
        } else {
                RETURN(NULL);
        }

        /* FIXME-WANGDI: add some check code here. */
        sb = nd.dentry->d_sb;
        path_release(&nd);
        RETURN(sb);
}

static struct smfs_super_info *smfs_init_smb(struct super_block *sb)
{
        struct smfs_super_info *smb;
        ENTRY;

        OBD_ALLOC(smb, sizeof(*smb));
        if (!smb)
                RETURN(NULL);        
        
        S2FSI(sb) = smb;
        RETURN(smb);        
}

static int smfs_init_fsfilt_ops(struct smfs_super_info *smb)
{
        ENTRY;
        if (!smb->sm_cache_fsfilt) {
                smb->sm_cache_fsfilt =
                        fsfilt_get_ops(smb->smsi_cache_ftype);
                if (!smb->sm_cache_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by kml\n",
                               smb->smsi_cache_ftype);
                        RETURN(-EINVAL);
                }
        }
        if (!smb->sm_fsfilt) {
                smb->sm_fsfilt =
                        fsfilt_get_ops(smb->smsi_ftype);
                if (!smb->sm_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by kml\n",
                               smb->smsi_ftype);
                        RETURN(-EINVAL);
                }
        }
        RETURN(0);
}

void smfs_cleanup_fsfilt_ops(struct smfs_super_info *smb)
{
        if (smb->sm_cache_fsfilt)
                fsfilt_put_ops(smb->sm_cache_fsfilt);
        if (smb->sm_fsfilt)
                fsfilt_put_ops(smb->sm_fsfilt);
}

static int smfs_mount_cache(struct smfs_super_info *smb, char *devstr, 
                            char *typestr, char *opts)
{
        int err = 0, typelen;
        struct vfsmount *mnt;
        ENTRY;

        typelen = strlen(typestr);

        printk("smfs: mounting %s at %s\n", typestr, devstr);
        mnt = do_kern_mount(typestr, 0, devstr, (void *)opts);
        if (IS_ERR(mnt)) {
                CERROR("do_kern_mount failed: rc = %ld\n", 
                       PTR_ERR(mnt));
                GOTO(err_out, err = PTR_ERR(mnt));
        }

        smb->smsi_sb = mnt->mnt_sb;
        smb->smsi_mnt = mnt;

        smfs_init_sm_ops(smb);

        OBD_ALLOC(smb->smsi_cache_ftype, strlen(typestr) + 1);
        memcpy(smb->smsi_cache_ftype, typestr, strlen(typestr));

        OBD_ALLOC(smb->smsi_ftype, strlen(SMFS_TYPE) + 1);
        memcpy(smb->smsi_ftype, SMFS_TYPE, strlen(SMFS_TYPE));
        
        err = smfs_init_fsfilt_ops(smb);
err_out:
        RETURN(err);
}

static int smfs_umount_cache(struct smfs_super_info *smb)
{
        struct dentry *root = smb->smsi_sb->s_root;
        
        dput(root);
        if (atomic_read(&root->d_inode->i_count) == 0)
                igrab(root->d_inode); 
        
        mntput(smb->smsi_mnt);
        smfs_cleanup_sm_ops(smb);
        smfs_cleanup_fsfilt_ops(smb);

        if (smb->smsi_cache_ftype)
                OBD_FREE(smb->smsi_cache_ftype,
                         strlen(smb->smsi_cache_ftype) + 1);
        if (smb->smsi_ftype)
                OBD_FREE(smb->smsi_ftype, strlen(smb->smsi_ftype) + 1);
               
        return 0;
}

static int smfs_init_hook_ops(struct smfs_super_info *smb)
{
        ENTRY;
        INIT_LIST_HEAD(&smb->smsi_hook_list);
        RETURN(0); 
}

static void smfs_cleanup_hook_ops(struct smfs_super_info *smb)
{
        struct list_head *hlist = &smb->smsi_hook_list;
        ENTRY;

        while (!list_empty(hlist)) {
                struct smfs_hook_ops *smfs_hops;
                
                smfs_hops = list_entry(hlist->next, struct smfs_hook_ops, 
                                       smh_list);
                CERROR("Unregister %s hook ops\n", smfs_hops->smh_name);         
                
                smfs_unregister_hook_ops(smb, smfs_hops->smh_name);
                smfs_free_hook_ops(smfs_hops); 
        } 
        EXIT;
}

static void smfs_cleanup_smb(struct super_block *sb)
{
        struct smfs_super_info *smb;
        ENTRY;

        smb = S2SMI(sb);
        if (smb) 
                OBD_FREE(smb, sizeof(*smb));
        EXIT;
}

void smfs_cleanup_hooks(struct smfs_super_info *smb)
{
        
        if (SMFS_CACHE_HOOK(smb))
                cache_space_hook_exit(smb);
        if (SMFS_DO_REC(smb))
                smfs_rec_cleanup(smb);
#if CONFIG_SNAPFS
        if (SMFS_DO_COW(smb))
                smfs_cow_cleanup(smb);
#endif  
        smfs_cleanup_hook_ops(smb);
}

void smfs_put_super(struct super_block *sb)
{
        struct smfs_super_info *smfs_info = S2SMI(sb);

        smfs_cleanup_hooks(smfs_info);
        
        if (sb)
                smfs_umount_cache(smfs_info);
        smfs_cleanup_smb(sb); 
}

static int smfs_init_hooks(struct super_block *sb)
{ 
        ENTRY;
 
        if (SMFS_DO_REC(S2SMI(sb))) 
                smfs_rec_init(sb);
        if (SMFS_CACHE_HOOK(S2SMI(sb))) 
                cache_space_hook_init(sb);
#if CONFIG_SNAPFS
        if (SMFS_DO_COW(S2SMI(sb))) 
                smfs_cow_init(sb);
#endif
        RETURN(0);
}

int smfs_fill_super(struct super_block *sb, void *data, int silent)
{
        struct inode *root_inode = NULL;
        struct smfs_super_info *smb = NULL;
        char *devstr = NULL, *typestr = NULL; 
        char *opts = NULL, *cache_data = NULL;
        unsigned long page;
        int err = 0; 
        ino_t root_ino;

        ENTRY;

        CDEBUG(D_SUPER, "mount opts: %s\n", data ? 
               (char *)data : "(none)");

        smb = smfs_init_smb(sb);
        if (!smb)
                RETURN(-ENOMEM);
 
        page = __get_free_page(GFP_KERNEL);
        if (!page)
                GOTO(out_err, err = -ENOMEM);
        
        memset((void *)page, 0, PAGE_SIZE);
        opts = (char *)page;

        init_option(data);
        cache_data = smfs_options(data, &devstr, &typestr, opts, 
                                  &smb->smsi_flags); 
        if (*cache_data)
                CWARN("smfs_fill_super(): options parsing stoped at "
                      "option %s\n", cache_data);

        if (!typestr || !devstr) {
                CERROR("mount options name and dev are mandatory\n");
                free_page(page);
                GOTO(out_err, err = -EINVAL);
        }
        
        err = smfs_mount_cache(smb, devstr, typestr, opts);
        free_page(page);
        
        if (err) {
                CERROR("Can not mount %s as %s\n", devstr, typestr);
                GOTO(out_err, err);
        }

        duplicate_sb(sb, smb->smsi_sb);
        sm_set_sb_ops(smb->smsi_sb, sb);

        err = smfs_init_hook_ops(smb);
        if (err) {
                CERROR("Can not init super hook ops err %d\n", err);
                smfs_umount_cache(smb);
                GOTO(out_err, err);
        }
        
        /* init the root_inode of smfs. */ 
        dget(S2CSB(sb)->s_root);
        root_ino = S2CSB(sb)->s_root->d_inode->i_ino;
        root_inode = smfs_get_inode(sb, root_ino, NULL, 0);

        CDEBUG(D_SUPER, "readinode %p, root ino %ld, root inode at %p\n",
               sb->s_op->read_inode, root_ino, root_inode);

        sb->s_root = d_alloc_root(root_inode);

        if (!sb->s_root) {
                smfs_umount_cache(smb);
                GOTO(out_err, err = -ENOMEM);
        }
        
        err = smfs_init_hooks(sb);  
        if (err) {
                smfs_umount_cache(smb);
                GOTO(out_err, err);
        }       
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        CDEBUG(D_SUPER, "sb %lx, &sb->u.generic_sbp: %lx\n",
               (ulong)sb, (ulong)&sb->u.generic_sbp);
#else
        CDEBUG(D_SUPER, "sb %lx, &sb->s_fs_info: %lx\n",
               (ulong)sb, (ulong)&sb->s_fs_info);
#endif
out_err:
        cleanup_option();
        if (err)
                smfs_cleanup_smb(sb);
        return err;
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

int smfs_register_hook_ops(struct smfs_super_info *smb, 
                           struct smfs_hook_ops *smh_ops)
{
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

struct smfs_hook_ops *smfs_unregister_hook_ops(struct smfs_super_info *smb, 
                                               char *name)
{
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

void *smfs_trans_start(struct inode *inode, int op, void *desc_private)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;

        CDEBUG(D_INFO, "trans start %p\n", fsfilt->fs_start);

        SMFS_TRANS_OP(inode, op);
        
        /* There are some problem here. fs_start in fsfilt is used by lustre
         * the journal blocks of write rec are not counted in FIXME later */
        if (fsfilt->fs_start)
                return fsfilt->fs_start(inode, op, desc_private, 0);
        return NULL;
}

void smfs_trans_commit(struct inode *inode, void *handle, int force_sync)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;

        if (!handle)
                return;

        CDEBUG(D_INFO, "trans commit %p\n", fsfilt->fs_commit);

        if (fsfilt->fs_commit)
                fsfilt->fs_commit(inode->i_sb, inode, handle, force_sync);
}

