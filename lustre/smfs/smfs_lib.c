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

int smfs_options(char *data, char **devstr, char **namestr, 
                 char *ret, int *flags)  
{
        char * temp;
        char * pos = NULL, *next = NULL;
                
        ENTRY;
        
        LASSERT(flags);
        //allocate temporary buffer
        OBD_ALLOC(temp, strlen(data) + 1);
        if (!temp) {
                CERROR("Can not allocate memory for options\n");
                RETURN(-ENOMEM);
        }
        
        memcpy(temp, data, strlen(data));
        pos = temp;
        
        while (pos) {
                next = strchr(pos, ',');
                if (next) {
                        *next = '\0';
                        next++;
                }
                
                //now pos points to one-options string
                if (!strncmp(pos, "dev=", 4)) {
                        if (devstr != NULL)
                                *devstr = pos + 4;
                } else if (!strncmp(pos, "type=", 5)) {
                        if (namestr != NULL)
                                *namestr = pos + 5;
                } else if (!strcmp(pos, "kml")) {
                        SMFS_SET(*flags, SMFS_PLG_KML);
                } else if (!strcmp(pos, "cache")) {
                        SMFS_SET(*flags, SMFS_PLG_LRU);
                } else if (!strcmp(pos, "snap")) {
                        SMFS_SET(*flags, SMFS_PLG_COW);
                } else {
                        /* So it is wrong or backfs option,
                         * let's save it
                         */
                        if (strlen(ret))
                                strcat(ret, ",");
                        
                        strcat(ret, pos);
                }
                
                pos = next;
        }

        //save dev & type for further use
        if (*devstr)
                *devstr = strcpy(ret + strlen(ret) + 1, *devstr);
        if (*namestr)
                *namestr = strcpy(*devstr + strlen(*devstr) + 1, *namestr);
        
        OBD_FREE(temp, strlen(data) + 1);
        
        RETURN(0);
}

static struct smfs_super_info *smfs_init_smb(struct super_block *sb)
{
        struct smfs_super_info *smb;
        ENTRY;

        OBD_ALLOC(smb, sizeof(*smb));
        if (!smb)
                RETURN(NULL);        
        
        S2FSI(sb) = smb;
        INIT_LIST_HEAD(&smb->smsi_plg_list);
        
        RETURN(smb);        
}

static void smfs_cleanup_smb(struct smfs_super_info *smb)
{
        ENTRY;

        if (smb) 
                OBD_FREE(smb, sizeof(*smb));
        EXIT;
}

static int smfs_init_fsfilt_ops(struct smfs_super_info *smb)
{
        ENTRY;
        if (!smb->sm_cache_fsfilt) {
                smb->sm_cache_fsfilt =
                        fsfilt_get_ops(smb->smsi_cache_ftype);
                if (!smb->sm_cache_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by smfs\n",
                               smb->smsi_cache_ftype);
                        RETURN(-EINVAL);
                }
        }
        if (!smb->sm_fsfilt) {
                smb->sm_fsfilt =
                        fsfilt_get_ops(smb->smsi_ftype);
                if (!smb->sm_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by smfs\n",
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

static void smfs_filter_flags(struct filter_obd * filt, struct inode * o_dir)
{
        struct dentry * dentry = NULL;
        int i,j;
        
        CDEBUG(D_SUPER,"OST OBD post_setup\n");
        /* enable plugins for all in O */
        SMFS_SET(I2SMI(o_dir)->smi_flags, SMFS_PLG_ALL);
        /* enable plugins for all already created d<n> dirs */
        for (j = 1; j < filt->fo_group_count; j++) {
                for (i = 0; i < filt->fo_subdir_count; i++) {
                        dentry = (filt->fo_subdirs + j)->dentry[i];
                        SMFS_SET(I2SMI(dentry->d_inode)->smi_flags,
                                         SMFS_PLG_ALL);
                }
        }
}

static void smfs_mds_flags(struct mds_obd * mds, struct inode * root)
{
        struct inode * pend = mds->mds_pending_dir->d_inode;
        
        CDEBUG(D_SUPER,"MDS OBD post_setup\n");
        /* enable plugins for all in ROOT */        
        SMFS_SET(I2SMI(root)->smi_flags, SMFS_PLG_ALL);
        /* the same for PENDING */
        SMFS_SET(I2SMI(pend)->smi_flags, SMFS_PLG_ALL);
}
                        

int smfs_post_setup(struct obd_device *obd, struct vfsmount *mnt,
                    struct dentry * root_dentry)
{
        struct lvfs_run_ctxt saved, *current_ctxt = NULL;
        struct smfs_super_info *smb = S2SMI(mnt->mnt_sb);
        int rc = 0;
        
        ENTRY;
 
        OBD_ALLOC(current_ctxt, sizeof(*current_ctxt));
        if (!current_ctxt)
                RETURN(-ENOMEM);
        
        OBD_SET_CTXT_MAGIC(current_ctxt);
        
        current_ctxt->pwdmnt = mnt;
        current_ctxt->pwd = mnt->mnt_root;
        current_ctxt->fs = get_ds();
        smb->smsi_ctxt = current_ctxt;
        
        push_ctxt(&saved, smb->smsi_ctxt, NULL);

        rc = smfs_llog_setup(smb);
        if (!rc) {
                rc = SMFS_PLG_HELP(mnt->mnt_sb, PLG_START, NULL);
        }

        pop_ctxt(&saved, smb->smsi_ctxt, NULL);

        /* connect KML ctxt to obd */
        if (obd && smb->smsi_kml_log) {
                smb->smsi_kml_log->loc_idx = LLOG_REINT_ORIG_CTXT;
                smb->smsi_kml_log->loc_obd = obd;
                obd->obd_llog_ctxt[LLOG_REINT_ORIG_CTXT] = smb->smsi_kml_log;
        }
        
        /* enable plugins for directories on MDS or OST */
        if (obd && obd->obd_type && obd->obd_type->typ_name) {
                if (!strcmp(obd->obd_type->typ_name, "obdfilter")) {
                        struct filter_obd *filt = &obd->u.filter;
 
                        smfs_filter_flags(filt, root_dentry->d_inode);
                }
                else if (!strcmp(obd->obd_type->typ_name, "mds")) {
                        struct mds_obd * mds = &obd->u.mds;
                        
                        smfs_mds_flags(mds, root_dentry->d_inode);
                }
                else
                        CDEBUG(D_SUPER,"Unknown OBD (%s) post_setup\n",
                               obd->obd_type->typ_name);
        }

        if (rc)
                OBD_FREE(current_ctxt, sizeof(*current_ctxt));
  
        RETURN(rc);
}

void smfs_post_cleanup(struct super_block *sb)
{
        struct smfs_super_info *smb = S2SMI(sb);
        
        ENTRY;
        
        smfs_llog_cleanup(smb);
        SMFS_PLG_HELP(sb, PLG_STOP, NULL);
        
        if (smb->smsi_ctxt)
                OBD_FREE(smb->smsi_ctxt, sizeof(struct lvfs_run_ctxt));
        
        EXIT;
}

static int smfs_mount_cache(struct smfs_super_info *smb, char *devstr, 
                            char *typestr, char *opts)
{
        int err = 0, typelen;
        struct vfsmount *mnt;
        ENTRY;

        typelen = strlen(typestr);

        CDEBUG(D_INODE, "smfs: mounting %s at %s\n", typestr, devstr);
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

/* This function initializes plugins in SMFS 
 * @flags: are filled while options parsing 
 * @sb: smfs super block
 */

static int smfs_init_plugins(struct super_block * sb, int flags)
{
        struct smfs_super_info * smb = S2SMI(sb);
        
        ENTRY;
        
        INIT_LIST_HEAD(&smb->smsi_plg_list);

        if (SMFS_IS(flags, SMFS_PLG_KML)) 
                smfs_init_kml(sb);
        if (SMFS_IS(flags, SMFS_PLG_LRU)) 
                smfs_init_lru(sb);
#if CONFIG_SNAPFS
        if (SMFS_IS(flags, SMFS_PLG_COW)) 
                smfs_init_cow(sb);
#endif
        RETURN(0); 
}

static void smfs_remove_plugins(struct super_block *sb)
{
        ENTRY;

        SMFS_PLG_HELP(sb, PLG_EXIT, (void*)sb);
        
        EXIT;
}

void smfs_put_super(struct super_block *sb)
{
        struct smfs_super_info *smb = S2SMI(sb);
        ENTRY;
        smfs_remove_plugins(sb);
        
        dput(sb->s_root);
        
        if (smb->smsi_mnt)
                smfs_umount_cache(smb);
        
        smfs_cleanup_smb(smb);
        EXIT;
}

int smfs_fill_super(struct super_block *sb, void *data, int silent)
{
        struct inode *root_inode = NULL;
        struct smfs_super_info *smb = NULL;
        char *devstr = NULL, *typestr = NULL; 
        char *opts = NULL;
        int err = 0;
        int flags = 0;
        ino_t root_ino;

        ENTRY;
        
        if (!data) {
                CERROR("no mount options. At least name and dev are needed\n");
                err = -EINVAL;
                goto out_err;
        }

        CDEBUG(D_SUPER, "mount opts: %s\n", (char *)data);

        smb = smfs_init_smb(sb);
        if (!smb)
                RETURN(-ENOMEM);
        lock_kernel();
        OBD_ALLOC(opts, strlen(data) + 1);
        if (!opts) {
                err = -ENOMEM;
                goto out_err;
        }
        
        err = smfs_options(data, &devstr, &typestr, opts, &flags);
        if (err)
                goto out_err;
                
        if (!typestr || !devstr) {
                CERROR("mount options name and dev are mandatory\n");
                err = -EINVAL;
                goto out_err;
        }
        
        CDEBUG(D_SUPER, "backfs mount opts: %s\n", opts);

        err = smfs_mount_cache(smb, devstr, typestr, opts);
        if (err) {
                CERROR("Can not mount %s as %s\n", devstr, typestr);
                goto out_err;
        }

        OBD_FREE(opts, strlen(data) + 1);
        opts = NULL;
        
        duplicate_sb(sb, smb->smsi_sb);
        sb->s_bdev = smb->smsi_sb->s_bdev;
        sm_set_sb_ops(smb->smsi_sb, sb);

        /* init the root_inode of smfs. */ 
        root_ino = S2CSB(sb)->s_root->d_inode->i_ino;
        root_inode = smfs_get_inode(sb, root_ino, NULL, 0);

        CDEBUG(D_SUPER, "readinode %p, root ino %ld, root inode at %p\n",
               sb->s_op->read_inode, root_ino, root_inode);

        sb->s_root = d_alloc_root(root_inode);
        if (!sb->s_root) {
                err = -ENOMEM;
                goto out_err;
        }
        
        /* all entries created until post_setup() should not be logged */
        SMFS_CLEAR((I2SMI(root_inode))->smi_flags, SMFS_PLG_ALL);
   
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        CDEBUG(D_SUPER, "sb %lx, &sb->u.generic_sbp: %lx\n",
               (ulong)sb, (ulong)&sb->u.generic_sbp);
#else
        CDEBUG(D_SUPER, "sb %lx(%p), &sb->s_fs_info: %lx\n",
               (ulong)sb, smb->smsi_sb, (ulong)&sb->s_fs_info);
#endif
        
        smfs_init_plugins(sb, flags);
        unlock_kernel();
        RETURN (0);
out_err:
        if (smb->smsi_mnt)
                smfs_umount_cache(smb);

        if (opts)
                OBD_FREE(opts, strlen(data) + 1);

        smfs_cleanup_smb(smb);
        unlock_kernel();
        RETURN(err);
}

void *smfs_trans_start(struct inode *inode, int op, void *desc_private)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;

        if (fsfilt->fs_start)
                return fsfilt->fs_start(inode, op, NULL, 0);
        return NULL;
}

void smfs_trans_commit(struct inode *inode, void *handle, int force_sync)
{
        struct fsfilt_operations *fsfilt = S2SMI(inode->i_sb)->sm_fsfilt;

        if (handle && fsfilt->fs_commit)
                fsfilt->fs_commit(inode->i_sb, inode, handle, force_sync);
}
/* Plugin API */
int smfs_register_plugin(struct super_block * sb,
                         struct smfs_plugin * new_plugin) 
{
        struct smfs_super_info * smb = S2SMI(sb);
        struct smfs_plugin * plg = NULL;
        struct list_head * plist = &S2SMI(sb)->smsi_plg_list;
        
        ENTRY;
        
        list_for_each_entry(plg, plist, plg_list) {
                if (plg->plg_type == new_plugin->plg_type) {
                        CWARN("Plugin is already registered\n");
                        RETURN(-EEXIST);
                }
        }
        
        
        if (SMFS_IS(smb->smsi_flags, new_plugin->plg_type)) {
                CWARN("Plugin is already registered\n");
                RETURN(-EEXIST);  
        }
                
        OBD_ALLOC(plg, sizeof(*plg));
        if (!plg) {
                CWARN("Cannot allocate memory for plugin\n");
                RETURN(-ENOMEM);
        }
        
        memcpy(plg, new_plugin, sizeof(*plg));
        list_add_tail(&plg->plg_list, plist);
        
        RETURN(0);
}

void * smfs_deregister_plugin(struct super_block *sb, int type)
{
        struct smfs_plugin * plg = NULL;
        struct list_head * plist = &S2SMI(sb)->smsi_plg_list;
        void * priv = NULL;
        
        ENTRY;

        list_for_each_entry(plg, plist, plg_list) {
                if (plg->plg_type == type) {
                        list_del(&plg->plg_list);
                        priv = plg->plg_private;
                        OBD_FREE(plg, sizeof(*plg));
                        break;
                }
        }
                
        RETURN(priv);
}

void smfs_pre_hook (struct inode * inode, int op, void * msg) 
{
        struct smfs_super_info *smb = S2SMI(inode->i_sb);    
        struct smfs_inode_info *smi = I2SMI(inode);
        struct list_head *hlist = &smb->smsi_plg_list;
        struct smfs_plugin *plg;
                
        //ENTRY;
        LASSERT(op < HOOK_MAX);
        //call hook operations
        list_for_each_entry(plg, hlist, plg_list) {
                //check that plugin is active
                if(!SMFS_IS(smb->plg_flags, plg->plg_type))
                        continue;
                //check that inode is allowed
                if (!SMFS_IS(smi->smi_flags, plg->plg_type))
                        continue;
                
                if (plg->plg_pre_op)
                        plg->plg_pre_op(op, inode, msg, 0, plg->plg_private);
        }

        //EXIT;
}

void smfs_post_hook (struct inode * inode, int op, void * msg, int ret)
{
        struct smfs_super_info *smb = S2SMI(inode->i_sb);
        struct smfs_inode_info *smi = I2SMI(inode);
        struct list_head *hlist = &smb->smsi_plg_list;
        struct smfs_plugin *plg;
        
        //ENTRY;
        
        list_for_each_entry(plg, hlist, plg_list) {
                //check that plugin is active
                if(!SMFS_IS(smb->plg_flags, plg->plg_type))
                        continue;
                //check that inode is allowed
                if (!SMFS_IS(smi->smi_flags, plg->plg_type))
                        continue;
                
                if (plg->plg_post_op)
                        plg->plg_post_op(op, inode, msg, ret, plg->plg_private);
        }

        //EXIT;
}

int smfs_helper (struct super_block * sb, int op, void * msg) 
{
        struct smfs_super_info *smb = S2SMI(sb);    
        struct list_head *hlist = &smb->smsi_plg_list;
        struct smfs_plugin *plg, *tmp;
        int rc = 0;
        
        //ENTRY;
        LASSERT(op < PLG_HELPER_MAX);
        //call hook operations
        list_for_each_entry_safe(plg, tmp, hlist, plg_list) {
                //check that plugin is active
                if(!SMFS_IS(smb->plg_flags, plg->plg_type) && (op != PLG_START))
                        continue;
               
                if (plg->plg_helper)
                       rc += plg->plg_helper(op, sb, msg, plg->plg_private);
        }

        //EXIT;
        
        return rc;
}


