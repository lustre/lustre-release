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
static char *smfs_options(char *data, char **devstr, char **namestr,
                          int *kml, int *cache, char **opts, int *iopen_nopriv,
                          int *cow)
{
        char *pos;
        struct option *opt_value = NULL;

        while (!(get_opt(&opt_value, &pos))) {
                if (!strcmp(opt_value->opt, "dev")) {
                        if (devstr != NULL)
                                *devstr = opt_value->value;
                } else if (!strcmp(opt_value->opt, "type")) {
                        if (namestr != NULL)
                                *namestr = opt_value->value;
                } else if (!strcmp(opt_value->opt, "kml")) {
                        if (kml)
                                *kml = 1;
                } else if (!strcmp(opt_value->opt, "cache")) {
                        if (cache)
                                *cache = 1;
                } else if (!strcmp(opt_value->opt, "options")) {
                        if (opts != NULL)
                                *opts = opt_value->value;
                } else if (!strcmp(opt_value->opt, "iopen_nopriv")) {
                        if (iopen_nopriv != NULL)
                                *iopen_nopriv = 1;
                } else if (!strcmp(opt_value->opt, "snap")) {
                                *cow = 1;
                } else {
                        break;
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

static int smfs_init_fsfilt_ops(struct super_block *sb)
{
        ENTRY;
        if (!S2SMI(sb)->sm_cache_fsfilt) {
                S2SMI(sb)->sm_cache_fsfilt =
                        fsfilt_get_ops(S2SMI(sb)->smsi_cache_ftype);
                if (!S2SMI(sb)->sm_cache_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by kml\n",
                               S2SMI(sb)->smsi_cache_ftype);
                        RETURN(-EINVAL);
                }
        }
        if (!S2SMI(sb)->sm_fsfilt) {
                S2SMI(sb)->sm_fsfilt =
                        fsfilt_get_ops(S2SMI(sb)->smsi_ftype);
                if (!S2SMI(sb)->sm_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by kml\n",
                               S2SMI(sb)->smsi_ftype);
                        RETURN(-EINVAL);
                }
        }
        RETURN(0);
}

void smfs_cleanup_fsfilt_ops(struct super_block *sb)
{
        if (S2SMI(sb)->sm_cache_fsfilt)
                fsfilt_put_ops(S2SMI(sb)->sm_cache_fsfilt);
        if (S2SMI(sb)->sm_fsfilt)
                fsfilt_put_ops(S2SMI(sb)->sm_fsfilt);
}

static int sm_mount_cache(struct super_block *sb, char *devstr,
                          char *typestr, char *opts, int iopen_nopriv)
{
        struct smfs_super_info *smb = S2SMI(sb);
        int err = 0, typelen;
        struct vfsmount *mnt;
        unsigned long page;
        ENTRY;

        typelen = strlen(typestr);

        page = __get_free_page(GFP_KERNEL);
        if (!page)
                GOTO(err_out, err = -ENOMEM);

        memset((void *)page, 0, PAGE_SIZE);

        if (iopen_nopriv)
                sprintf((char *)page, "iopen_nopriv");

        if (opts && strlen(opts)) {
                int n = strlen((char *)page);
                sprintf((char *)page + n, ",%s", opts);
        }

        printk("smfs: mounting %s at %s\n", typestr, devstr);

        mnt = do_kern_mount(typestr, 0, devstr, (void *)page);
        free_page(page);

        if (IS_ERR(mnt)) {
                CERROR("do_kern_mount failed: rc = %ld\n", PTR_ERR(mnt));
                GOTO(err_out, err = PTR_ERR(mnt));
        }

        smb->smsi_sb = mnt->mnt_sb;
        smb->smsi_mnt = mnt;

        smfs_init_sm_ops(smb);

        OBD_ALLOC(smb->smsi_cache_ftype, strlen(typestr) + 1);
        memcpy(smb->smsi_cache_ftype, typestr, strlen(typestr));

        OBD_ALLOC(smb->smsi_ftype, strlen(SMFS_TYPE) + 1);
        memcpy(smb->smsi_ftype, SMFS_TYPE, strlen(SMFS_TYPE));

        duplicate_sb(sb, mnt->mnt_sb);
        sm_set_sb_ops(mnt->mnt_sb, sb);

        err = smfs_init_fsfilt_ops(sb);
err_out:
        return err;
}

static int sm_umount_cache(struct super_block *sb)
{
        struct smfs_super_info *smb = S2SMI(sb);

        iput(S2CSB(sb)->s_root->d_inode);
        dput(S2CSB(sb)->s_root);
        mntput(smb->smsi_mnt);
        smfs_cleanup_sm_ops(smb);
        smfs_cleanup_fsfilt_ops(sb);

        if (smb->smsi_cache_ftype)
                OBD_FREE(smb->smsi_cache_ftype,
                         strlen(smb->smsi_cache_ftype) + 1);
        if (smb->smsi_ftype)
                OBD_FREE(smb->smsi_ftype, strlen(smb->smsi_ftype) + 1);
               
        return 0;
}

static int smfs_init_hook_ops(struct super_block *sb)
{
        struct smfs_super_info *smb = S2SMI(sb);
        ENTRY;

        INIT_LIST_HEAD(&smb->smsi_hook_list);

        RETURN(0); 
}
static void smfs_cleanup_hook_ops(struct super_block *sb)
{
        struct smfs_super_info *smb = S2SMI(sb);
        struct list_head *hlist = &smb->smsi_hook_list;
        ENTRY;

        while (!list_empty(hlist)) {
                struct smfs_hook_ops *smfs_hops;
                
                smfs_hops = list_entry(hlist->next, struct smfs_hook_ops, 
                                       smh_list);
                CERROR("Unregister %s hook ops\n", smfs_hops->smh_name);         
                
                smfs_unregister_hook_ops(sb, smfs_hops->smh_name);
                smfs_free_hook_ops(smfs_hops); 
        } 
        EXIT;
        return;        
}

void smfs_put_super(struct super_block *sb)
{
        if (SMFS_CACHE_HOOK(S2SMI(sb)))
                cache_space_hook_exit(sb);
        if (SMFS_DO_REC(S2SMI(sb)))
                smfs_rec_cleanup(sb);
#if CONFIG_SNAPFS
        if (SMFS_DO_COW(S2SMI(sb)))
                smfs_cow_cleanup(sb);
#endif  
        smfs_cleanup_hook_ops(sb);
 
        if (sb)
                sm_umount_cache(sb);
        return;
}
int smfs_fill_super(struct super_block *sb, void *data, int silent)
{
        ino_t root_ino;
        char *cache_data;

        int iopen_nopriv = 0;
        struct inode *root_inode = NULL;
        int err = 0, do_rec = 0, cache_hook = 0, do_cow = 0;
        char *devstr = NULL, *typestr = NULL, *opts = NULL;

        ENTRY;

        CDEBUG(D_SUPER, "mount opts: %s\n", data ?
               (char *)data : "(none)");

        init_option(data);

        /* read and validate passed options. */
        cache_data = smfs_options(data, &devstr, &typestr,
                                  &do_rec, &cache_hook, &opts,
                                  &iopen_nopriv, &do_cow);

        if (*cache_data)
                CWARN("smfs_fill_super(): options parsing stoped at "
                      "option %s\n", cache_data);

        if (!typestr || !devstr) {
                CERROR("mount options name and dev mandatory\n");
                GOTO(out_err, err = -EINVAL);
        }
        err = sm_mount_cache(sb, devstr, typestr, opts, iopen_nopriv);
        if (err) {
                CERROR("Can not mount %s as %s\n", devstr, typestr);
                GOTO(out_err, 0);
        }
        
        err = smfs_init_hook_ops(sb);
        if (err) {
                CERROR("Can not init super hook ops err %d\n", err);
                GOTO(out_err, 0);
        }
        
        if (do_rec) smfs_rec_init(sb);
        if (cache_hook) cache_space_hook_init(sb);
        
        dget(S2CSB(sb)->s_root);
        root_ino = S2CSB(sb)->s_root->d_inode->i_ino;
        root_inode = iget(sb, root_ino);

        CDEBUG(D_SUPER, "readinode %p, root ino %ld, root inode at %p\n",
               sb->s_op->read_inode, root_ino, root_inode);

        sb->s_root = d_alloc_root(root_inode);

        if (!sb->s_root) {
                sm_umount_cache(sb);
                GOTO(out_err, err=-EINVAL);
        }
#if CONFIG_SNAPFS
        if (do_cow) smfs_cow_init(sb);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        CDEBUG(D_SUPER, "sb %lx, &sb->u.generic_sbp: %lx\n",
               (ulong)sb, (ulong)&sb->u.generic_sbp);
#else
        CDEBUG(D_SUPER, "sb %lx, &sb->s_fs_info: %lx\n",
               (ulong)sb, (ulong)&sb->s_fs_info);
#endif

out_err:
        cleanup_option();
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

