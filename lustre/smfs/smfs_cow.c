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
#include <linux/pagemap.h>
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

#define SNAPTABLE_SIZE(size) (sizeof(struct snap_table) +       \
                              size * sizeof(struct snap))

int smfs_cleanup_snap_info(struct snap_info *snap_info);

static int smfs_init_snap_super_info(struct smfs_super_info *smfs_info)
{
        struct snap_super_info  *snap_sinfo;
        int rc = 0;

        ENTRY;
        
        OBD_ALLOC(smfs_info->smsi_snap_info,
                  sizeof(struct snap_super_info));
        
        if (!smfs_info->smsi_snap_info) 
                GOTO(exit, rc = -ENOMEM);

        snap_sinfo = smfs_info->smsi_snap_info;

        /*init snap fsfilt operations*/
        if (!snap_sinfo->snap_cache_fsfilt) {
                char *snap_cache_ftype = NULL;
                int   tmp = strlen(smfs_info->smsi_cache_ftype) + strlen("_snap");
                
                OBD_ALLOC(snap_cache_ftype, tmp + 1);  
                sprintf(snap_cache_ftype, "%s_snap", smfs_info->smsi_cache_ftype);
                snap_sinfo->snap_cache_fsfilt = fsfilt_get_ops(snap_cache_ftype);
                OBD_FREE(snap_cache_ftype, tmp + 1);
                if (!snap_sinfo->snap_cache_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by snap\n",
                               snap_cache_ftype);
                        GOTO(exit, rc = -EINVAL);
                }
        }
        if (!snap_sinfo->snap_fsfilt) {
                char *snap_ftype = NULL;
                int   tmp = strlen(smfs_info->smsi_ftype) + strlen("_snap");
                
                OBD_ALLOC(snap_ftype, tmp + 1);  
                sprintf(snap_ftype, "%s_snap", smfs_info->smsi_ftype);
                snap_sinfo->snap_fsfilt = fsfilt_get_ops(snap_ftype);
                OBD_FREE(snap_ftype, tmp + 1);
                if (!snap_sinfo->snap_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by snap\n",
                               snap_ftype);
                        GOTO(exit, rc = -EINVAL);
                }
        }
        INIT_LIST_HEAD(&snap_sinfo->snap_list);
exit:
        if (rc && smfs_info->smsi_snap_info)
                OBD_FREE(snap_sinfo, sizeof(struct snap_super_info));
        RETURN(rc);
}
/*FIXME-wangdi Should remove it when integrated it with lustre*/
static struct dentry *smfs_simple_mkdir(struct dentry *dir, char *name, 
                                        int mode, int fix)
{
        struct dentry *dchild;
        int err = 0;
        
        dchild = ll_lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                GOTO(out_up, dchild);
        
        if (dchild->d_inode) {
                int old_mode = dchild->d_inode->i_mode;
                if (!S_ISDIR(old_mode))
                        GOTO(out_err, err = -ENOTDIR);
                                                                                                                                                                                                     
                /* Fixup directory permissions if necessary */
                if (fix && (old_mode & S_IALLUGO) != (mode & S_IALLUGO)) {
                        CWARN("fixing permissions on %s from %o to %o\n",
                              name, old_mode, mode);
                        dchild->d_inode->i_mode = (mode & S_IALLUGO) |
                                                  (old_mode & ~S_IALLUGO);
                        mark_inode_dirty(dchild->d_inode);
                }
                GOTO(out_up, dchild);
        }
        err = vfs_mkdir(dir->d_inode, dchild, mode);
        if (err)
                GOTO(out_err, err);
        RETURN(dchild);
out_err:
        dput(dchild);
        dchild = ERR_PTR(err);
out_up:
        return dchild;

}
static struct snap_info *smfs_find_snap_info(struct inode *inode)
{
        struct snap_inode_info *snap_iinfo = I2SNAPI(inode);
        struct snap_super_info *snap_sinfo = S2SNAPI(inode->i_sb);
        struct snap_info *snap_info = NULL, *tmp; 

        ENTRY;
        list_for_each_entry_safe(snap_info, tmp, &snap_sinfo->snap_list, 
                                 sni_list) {
               if (snap_info->sni_root_ino == snap_iinfo->sn_root_ino)
                        RETURN(snap_info); 
        }
        RETURN(NULL);
}

#if 0
static int smfs_dotsnap_dir_size(struct inode *inode)
{
        struct snap_super_info *snap_sinfo = S2SNAPI(inode->i_sb);
        struct fsfilt_operations *snapops = snap_sinfo->snap_cache_fsfilt; 
        int size = 0, dir_size = 0, blocks, i = 0;
        struct snap_table *snap_table = NULL; 
        struct snap_info *snap_info = NULL;
        ENTRY;
       
        snap_info = smfs_find_snap_info(inode);
        
        if (!snap_info) {
                CDEBUG(D_INFO, "can not find snap info for inode %p\n", inode);
                RETURN(0);                
        }
        snap_table = snap_info->sni_table;
        for (i = 0; i < snap_table->sntbl_count; i++) {
                char *name = snap_table->sntbl_items[i].sn_name;
                size += snapops->fs_dir_ent_size(name);
        }
        /*FIXME this is only for ext3 dir format, may need fix for other FS*/ 
        blocks = (size + inode->i_sb->s_blocksize - 1) >> 
                                inode->i_sb->s_blocksize_bits; 
        
        dir_size = blocks * inode->i_sb->s_blocksize; 
        RETURN(dir_size); 

}
#endif

static int smfs_init_snap_inode_info(struct inode *inode, struct inode *dir, int index) 
{
        int rc = 0;
        ENTRY;

        if (!inode)
                RETURN(0);

        if (dir) {
                I2SNAPI(inode)->sn_flags = I2SNAPI(dir)->sn_flags;
                I2SNAPI(inode)->sn_gen = I2SNAPI(dir)->sn_gen;
                I2SNAPI(inode)->sn_root_ino = I2SNAPI(dir)->sn_root_ino;
                I2SNAPI(inode)->sn_index = I2SNAPI(inode)->sn_index; 
        } else {
                I2SNAPI(inode)->sn_flags = 0;
                I2SNAPI(inode)->sn_gen = 0;
        }
        
        I2SNAPI(inode)->sn_index = index;
 
        if (smfs_dotsnap_inode(inode)) {
                struct snap_info *snap_info;

                snap_info = smfs_find_snap_info(inode);
                if (!snap_info) {
                        RETURN(-EIO);
                }
                /*init dot_snap inode info*/
//              inode->i_size = (loff_t)smfs_dotsnap_dir_size(inode);
                inode->i_size = snap_info->sni_table->sntbl_count;
                inode->i_nlink = snap_info->sni_table->sntbl_count + 2;
                inode->i_uid = 0;
                inode->i_gid = 0;
        } else if (SMFS_DO_COW(S2SMI(inode->i_sb)) && 
                   (I2SMI(inode)->smi_flags & SM_DO_COW) &&
                   smfs_primary_inode(inode)) {
                struct snap_inode_info *sni_info = I2SNAPI(inode);
                struct fsfilt_operations *sops = I2SNAPCOPS(inode);
                int vallen = 0;
 
                vallen = sizeof(sni_info->sn_gen);
                
                rc = sops->fs_get_snap_info(I2CI(inode), SNAP_GENERATION,
                                            strlen(SNAP_GENERATION),
                                            &sni_info->sn_gen, &vallen);               
        } 
        RETURN(rc);                                              
}

#define COWED_NAME_LEN       (7 + 8 + 1) 
static int smfs_init_cowed_dir(struct snap_info *snap_info, struct inode* inode)  
{
        struct dentry    *dentry = NULL;
        char   name[COWED_NAME_LEN];
        int    rc = 0;
        ENTRY;
         
        sprintf(name, ".cowed_%08x", (__u32)inode->i_ino);
        /*FIXME-WANGDI: will use simple_mkdir, when integrating snap to lustre*/
        dentry = smfs_simple_mkdir(inode->i_sb->s_root, name, 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("create cowed directory: rc = %d\n", rc);
                RETURN(rc);
        }
        snap_info->sni_cowed_dentry = dentry;
        /*cleanup cowed inode attr for cowed dir*/
        SMFS_CLEAN_INODE_COWED(dentry->d_inode);
        RETURN(rc);
}

static int smfs_init_dotinfo(struct snap_info *snap_info)
{
        struct snap_dot_info *dot_info = NULL;
        int rc = 0;
        ENTRY;

        if (snap_info->sni_dot_info)
                RETURN(-EEXIST);
       
        OBD_ALLOC(snap_info->sni_dot_info, sizeof(struct snap_dot_info));
        
        if (!snap_info->sni_dot_info)
                RETURN(-ENOMEM); 
      
        dot_info = snap_info->sni_dot_info;
 
        OBD_ALLOC(dot_info->dot_name,  strlen(DOT_SNAP_NAME) + 1);

        if (!dot_info->dot_name) {
                OBD_FREE(snap_info->sni_dot_info, sizeof(struct snap_dot_info));
                RETURN(-ENOMEM); 
        } 
        memcpy(dot_info->dot_name, DOT_SNAP_NAME, strlen(DOT_SNAP_NAME));
        
        dot_info->dot_name_len = strlen(DOT_SNAP_NAME); 
        dot_info->dot_snap_enable = 1;
        
        RETURN(rc);
}

static int smfs_init_snap_info(struct smfs_super_info *smb, 
                               struct snap_info *snap_info, struct inode *inode) 
{
        struct snap_table        *snap_table = NULL;       
	struct fsfilt_operations *snapcops;
        int                      rc = 0, size, table_size, vallen, i;
 
        ENTRY;

        snapcops = smb->smsi_snap_info->snap_cache_fsfilt;
        /*Initialized table */
        /*get the maxsize of snaptable*/
        vallen = sizeof(int);
        rc = snapcops->fs_get_snap_info(I2CI(inode), MAX_SNAPTABLE_COUNT,
                                       strlen(MAX_SNAPTABLE_COUNT), &size, 
                                       &vallen);
        if (size == 0) {
                CERROR("the Max snaptable count should not be zero\n");
                GOTO(exit, rc);
        }
        table_size = SNAPTABLE_SIZE(size);

        OBD_ALLOC(snap_info->sni_table, table_size);

        if (!snap_info->sni_table) {
                CERROR("No MEM\n");
                RETURN(-ENOMEM);
        }
        snap_table = snap_info->sni_table;
         
        snap_table->sntbl_magic = cpu_to_le32((__u32)SNAPTABLE_MAGIC); 
        snap_table->sntbl_max_count = size;
        /*init sn_index to -1*/ 
        for (i = 0; i < snap_table->sntbl_max_count; i++) 
                snap_table->sntbl_items[i].sn_index = -1;
        /*get snaptable info*/
        rc = snapcops->fs_get_snap_info(I2CI(inode), SNAPTABLE_INFO, 
                                        strlen(SNAPTABLE_INFO), 
                                        snap_table, &table_size);       
        if (rc < 0) {
                if (rc == -ENODATA) {
                        snap_table->sntbl_count = 0;
                        rc = 0;
                } else {
                        CERROR("Can not retrive the snaptable from this filesystem\n");
                        GOTO(exit, rc);
                }
        } else { 
                if (le32_to_cpu(snap_table->sntbl_magic) != SNAPTABLE_MAGIC) {
                        CERROR("On disk snaptable is not right \n");
                        GOTO(exit, rc = -EIO);
                }
        }
        init_MUTEX(&snap_info->sni_sema);
        snap_info->sni_root_ino = inode->i_ino;
        rc = smfs_init_cowed_dir(snap_info, inode);
        if (rc) {
                CERROR("Init cowed dir error rc=%d\n", rc);
                GOTO(exit, rc); 
        }
        rc = smfs_init_dotinfo(snap_info);
exit:
        if (rc && snap_table)
                OBD_FREE(snap_table, table_size);
        RETURN(rc);
}

static struct snap_info *smfs_create_snap_info(struct smfs_super_info *sinfo, 
                                               struct inode *inode)
{
        struct snap_info *snap_info = NULL;
        int rc = 0;
        ENTRY;
 
        OBD_ALLOC(snap_info, sizeof(struct snap_info)); 
        if (!snap_info) 
                RETURN(ERR_PTR(-ENOMEM));  
        rc = smfs_init_snap_info(sinfo, snap_info, inode);  
        if (rc) 
                GOTO(exit, rc);
       
        /*set cow flags for the snap root inode*/ 
        I2SMI(inode)->smi_flags |= SM_DO_COW;
        I2SNAPI(inode)->sn_root_ino = inode->i_ino; 
exit:
        if (rc) {
                OBD_FREE(snap_info, sizeof(struct snap_info));
                snap_info = ERR_PTR(rc);
        }
        RETURN(snap_info);
}

static int smfs_cow_pre(struct inode *dir, void *dentry, void *new_dir, 
                        void *new_dentry, int op);

static int smfs_cow_post(struct inode *dir, void *dentry, void *new_dir, 
                         void *new_dentry, int op);
#define COW_HOOK "cow_hook"
static int smfs_cow_pre_hook(struct inode *inode, void *dentry, void *data1,
                             void *data2, int op, void *handle)
{
        int rc = 0;
        ENTRY;
 
        if (smfs_do_cow(inode)) {
                /*FIXME:WANGDI, get index from the dentry*/
                #if 0
                int index = 0;
                smfs_get_dentry_name_index(dentry, &name, index);       
                smfs_free_dentry_name(&name);
                #endif
                rc = smfs_cow_pre(inode, dentry, data1, data2, op);           
        }
        RETURN(rc);                                                                     
}
static int smfs_cow_post_hook(struct inode *inode, void *dentry, void *data1, 
                              void *data2, int op, void *handle)
{
        int rc = 0;
        ENTRY;
 
        if (smfs_do_cow(inode)) {
                rc = smfs_cow_post(inode, dentry, data1, data2, op);           
        }
        RETURN(rc);                                                                     
}

int smfs_cow_cleanup(struct smfs_super_info *smb)
{
        struct snap_super_info   *snap_sinfo = smb->smsi_snap_info;
        struct list_head      	 *snap_list = &snap_sinfo->snap_list; 
        struct smfs_hook_ops     *cow_hops;
        int                      rc = 0; 
        ENTRY;

        while (!list_empty(snap_list)) {
                struct snap_info *snap_info;
                
                snap_info = list_entry(snap_list->next, struct snap_info,
                                       sni_list); 
                rc = smfs_cleanup_snap_info(snap_info); 
                if (rc) 
                        CERROR("cleanup snap_info error rc=%d\n", rc);
                list_del(&snap_info->sni_list); 
                OBD_FREE(snap_info, sizeof(struct snap_info));
        } 
         
        if (snap_sinfo->snap_fsfilt) 
                fsfilt_put_ops(snap_sinfo->snap_fsfilt);
        if (snap_sinfo->snap_cache_fsfilt)
                fsfilt_put_ops(snap_sinfo->snap_cache_fsfilt);

        cow_hops = smfs_unregister_hook_ops(smb, COW_HOOK);
        smfs_free_hook_ops(cow_hops);

        SMFS_CLEAN_COW(smb);
        if (snap_sinfo) 
               OBD_FREE(snap_sinfo, sizeof(struct snap_super_info));
        RETURN(rc);
}

int smfs_cow_init(struct super_block *sb)
{
        struct smfs_super_info *smfs_info = S2SMI(sb);
        struct smfs_hook_ops *cow_hops = NULL;
        struct fsfilt_operations *sops;
        struct inode *root_inode = smfs_info->smsi_sb->s_root->d_inode; 
        int snap_count = 0, rc = 0, vallen;

        ENTRY;

        SMFS_SET_COW(smfs_info);
      
        cow_hops = smfs_alloc_hook_ops(COW_HOOK, smfs_cow_pre_hook, 
                                       smfs_cow_post_hook);
        if (!cow_hops) {
                RETURN(-ENOMEM);
        }
 
        rc = smfs_register_hook_ops(smfs_info, cow_hops);
        if (rc) {
                smfs_free_hook_ops(cow_hops);
                RETURN(rc);
        }
        
        rc = smfs_init_snap_super_info(smfs_info);
        if (rc && cow_hops) {
                smfs_unregister_hook_ops(smfs_info, cow_hops->smh_name);
                smfs_free_hook_ops(cow_hops);
                RETURN(rc);
        }
        sops = smfs_info->smsi_snap_info->snap_cache_fsfilt; 
        
        vallen = sizeof(int); 
        rc = sops->fs_get_snap_info(root_inode, SNAP_COUNT, strlen(SNAP_COUNT),
                                    &snap_count, &vallen);
        if (rc < 0)
                GOTO(exit, rc);       
 
        if (snap_count > 0) {
                int snap_root_size = snap_count * sizeof(ino_t);
                ino_t *snap_root;
                int i;
                
                OBD_ALLOC(snap_root, snap_root_size);
                
                if (!snap_root)
                        GOTO(exit, rc = -ENOMEM); 
                
                rc = sops->fs_get_snap_info(root_inode, SNAP_ROOT_INO, 
                                            strlen(SNAP_ROOT_INO), snap_root, 
                                            &snap_root_size);
                if (rc < 0) {
                        OBD_FREE(snap_root, sizeof(int) * snap_count);
                        GOTO(exit, rc);
                }
                for (i = 0; i < snap_count; i++) {
                        ino_t root_ino = le32_to_cpu(snap_root[i]);
                        struct snap_info *snap_info;                      
 
                        root_inode = smfs_get_inode(sb, root_ino, NULL, 0);
                        smfs_init_snap_inode_info(root_inode, NULL, 0);
                        snap_info = smfs_create_snap_info(S2SMI(sb), root_inode);
                        iput(root_inode);
                        if (IS_ERR(snap_info)) {
                                OBD_FREE(snap_root, sizeof(int) * snap_count);
                                GOTO(exit, rc = PTR_ERR(snap_info));
                        }                
                        list_add(&snap_info->sni_list, 
                                 &(S2SNAPI(sb)->snap_list));        
                }
        }      
        smfs_info->smsi_snap_info->snap_count = snap_count; 
exit:
        if (rc) 
                smfs_cow_cleanup(smfs_info);
        RETURN(rc);
}

static int smfs_cleanup_dotinfo(struct snap_info *snap_info)
{       
        struct snap_dot_info *dot_info = NULL;
        int rc = 0;
        ENTRY;

        if (!snap_info->sni_dot_info)
                RETURN(rc);
       
        dot_info = snap_info->sni_dot_info;

        if (dot_info->dot_name) { 
                OBD_FREE(dot_info->dot_name, dot_info->dot_name_len + 1);
        }
        
        OBD_FREE(dot_info, sizeof(struct snap_dot_info));

        RETURN(rc);
}

int smfs_cleanup_snap_info(struct snap_info *snap_info)
{
        struct snap_table      *snap_table = snap_info->sni_table;
        int rc = 0, table_size;
        ENTRY;

        l_dput(snap_info->sni_cowed_dentry);
        //d_unalloc(snap_info->sni_cowed_dentry);
        if (snap_table) {
                table_size = SNAPTABLE_SIZE(snap_table->sntbl_max_count);
                OBD_FREE(snap_info->sni_table, table_size);
        }
        smfs_cleanup_dotinfo(snap_info);
        RETURN(rc);
}

int smfs_snap_test_inode(struct inode *inode, void *args)
{ 
        struct smfs_iget_args *sargs = (struct smfs_iget_args*)args;
        struct inode *dir;

        LASSERT(sargs);
        
        dir = sargs->s_inode;
        
        if (sargs->s_index > 0) { 
                if (I2SNAPI(inode)->sn_index != sargs->s_index)
                        return 0;
        }else {
                if (dir && I2SNAPI(inode)->sn_index != I2SNAPI(dir)->sn_index)
                        return 0;
        }
        return 1;
}
/* latest snap: returns 
   -  the index of the latest snapshot before NOW
   -  hence it returns 0 in case all the volume snapshots lie in the future
   -  this is the index where a COW will land (will be created) 
*/
void snap_last(struct inode *inode, struct snap *snap)
{
        time_t now = LTIME_S(CURRENT_TIME);
	struct snap_table *snap_table;
        struct snap_info  *snap_info;
	int i ;

	ENTRY;

        snap_info = smfs_find_snap_info(inode);
        if (!snap_info) {
                CDEBUG(D_INFO, "can not find snap info for inode %p\n", inode);
                EXIT;
                return;
        }
        snap_table = snap_info->sni_table;
	/* start at the highest index in the superblock snaptime array */ 
	if (snap_table->sntbl_count == 0) {
               memset(snap, 0, sizeof(struct snap)); 
        } else {
                i = snap_table->sntbl_count - 1;
                snap->sn_index = snap_table->sntbl_items[i].sn_index;
                snap->sn_time = snap_table->sntbl_items[i].sn_time;
                snap->sn_gen = snap_table->sntbl_items[i].sn_gen;
        }
	CDEBUG(D_INFO, "index: %d, time[i]: %ld, now: %ld\n",
	       snap->sn_index, snap->sn_time, now);
        EXIT;
	return;
}

static inline int get_index_of_item(struct snap_table *table, char *name)
{
	int count = table->sntbl_count;
	int i, j;
        ENTRY;
	
	for (i = 0; i < table->sntbl_max_count; i++) { 
		if (!strcmp(name, table->sntbl_items[i].sn_name)) {
                        CERROR("Duplicate name %s in snaptable\n", name); 
			RETURN(-EINVAL);
                }	
	}

	for (i = 1; i <= table->sntbl_max_count; i++) {
		int found = 0;
		for (j = 0; j < (count + 1); j++) {
			if (table->sntbl_items[j].sn_index == i) {
				found = 1;
				break;	
			}
                }
		if (!found)
			RETURN(i);
	}
        CERROR("snaptable Full\n");
	RETURN(-ENOSPC);
}

static struct dentry *smfs_find_snap_root(struct super_block *sb, 
                                          char *path_name)
{
        struct dentry *dentry = NULL;
        struct nameidata nd;
        int error;
        ENTRY;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (path_init(path_name, LOOKUP_FOLLOW, &nd)) {
                error = path_walk(path_name, &nd);
                if (error) {
                        path_release(&nd);
                        RETURN(NULL);
                }
        } else {
                RETURN(NULL);
        }
#else
        if (path_lookup(path_name, LOOKUP_FOLLOW, &nd))
                RETURN(NULL);
                                                                                                                                                                                                     
#endif
        dentry = dget(nd.dentry); 
        path_release(&nd);
        RETURN(dentry); 
}
static int snap_add_item(struct smfs_super_info *smb, 
                         struct snap_info *snap_info,
                         char *name)
{        
        struct fsfilt_operations *snapops;
        struct snap_table        *snap_table = snap_info->sni_table;
        struct inode             *root_inode = NULL;
        int                      table_size, count = 0, index = 0, rc = 0;
       	struct  snap             *snap_item;
        ENTRY;

        count = snap_table->sntbl_count; 
        root_inode = iget(smb->smsi_sb, snap_info->sni_root_ino);
        if (!root_inode || is_bad_inode(root_inode)) 
                RETURN(-EIO); 
	/* XXX Is down this sema necessary*/
	down_interruptible(&snap_info->sni_sema);
        snap_item = &snap_table->sntbl_items[count];
        snapops = smb->smsi_snap_info->snap_cache_fsfilt;
	/*add item in snap_table set generation*/
	snap_item->sn_time = LTIME_S(CURRENT_TIME);
	/* find table index */
	index = get_index_of_item(snap_table, name);
        if (index < 0) 
		GOTO(exit, rc = index);
	
	snap_item->sn_index = index;
	snap_item->sn_flags = 0;
        snap_item->sn_gen = snap_table->sntbl_generation + 1; 
	memcpy(snap_item->sn_name, name, SNAP_MAX_NAMELEN);
	/* Wrote the whole snap_table to disk */
        table_size = SNAPTABLE_SIZE(snap_table->sntbl_max_count); 
         
        snap_table->sntbl_count++;
	snap_table->sntbl_generation++;
        rc = snapops->fs_set_snap_info(root_inode, SNAPTABLE_INFO, 
                                       strlen(SNAPTABLE_INFO),
				       snap_table, &table_size);
	if (rc) {
                snap_table->sntbl_count--;
	        snap_table->sntbl_generation--;
                CERROR("Set snaptable error rc=%d\n", rc);
                GOTO(exit, rc);
        }
exit:
	up(&snap_info->sni_sema);
        if (root_inode)
                iput(root_inode);
	RETURN(rc);
}

static struct snap_info * smfs_find_create_snap_info(struct super_block *sb, 
                                                     struct inode *inode) 
{	
        struct snap_super_info   *snap_sinfo = S2SNAPI(sb);
        struct fsfilt_operations *sops = snap_sinfo->snap_cache_fsfilt;
        struct snap_info *snap_info, *tmp;
        ino_t *snap_root = NULL;
        int    rino_size, snap_count_size, rc = 0;
        ENTRY;
        
        list_for_each_entry_safe(snap_info, tmp, &snap_sinfo->snap_list, 
                                 sni_list) {
                if (snap_info->sni_root_ino == inode->i_ino) {
                        RETURN(snap_info);
                }      
        } 

        CDEBUG(D_INFO, "create a new  snap info root ino %lu\n", inode->i_ino);

        snap_info = smfs_create_snap_info(S2SMI(sb), inode);  

        if (IS_ERR(snap_info))
                RETURN(snap_info);
  
        snap_sinfo->snap_count++;

        rino_size = snap_sinfo->snap_count * sizeof(ino_t);

        OBD_ALLOC(snap_root, rino_size);
                
        if (!snap_root)
                GOTO(exit, rc = -ENOMEM); 
                
        rc = sops->fs_get_snap_info(I2CI(inode), SNAP_ROOT_INO, 
                                    strlen(SNAP_ROOT_INO), snap_root, 
                                    &rino_size);
        if (rc < 0) {
                if (rc == -ENODATA) {
                        rc = 0;
                } else {
                        GOTO(exit, rc);
                }
        }
        snap_root[snap_sinfo->snap_count - 1] = inode->i_ino;
      
        snap_count_size = sizeof(int);        
        rc = sops->fs_set_snap_info(I2CI(inode), SNAP_COUNT, strlen(SNAP_COUNT), 
                                    &snap_sinfo->snap_count,  &snap_count_size);
        if (rc) 
                GOTO(exit, rc);
       
        rc = sops->fs_set_snap_info(I2CI(inode), SNAP_ROOT_INO,
                                    strlen(SNAP_ROOT_INO), snap_root,
                                    &rino_size); 

        if (rc)
                GOTO(exit, rc);        

        list_add(&snap_info->sni_list, &snap_sinfo->snap_list);        
exit: 
        if (rc) {
                smfs_cleanup_snap_info(snap_info); 
                OBD_FREE(snap_info, sizeof(struct snap_info));
        }
        if (snap_root)
                OBD_FREE(snap_root, rino_size); 
        RETURN(snap_info);  
}         

int smfs_add_snap_item(struct super_block *sb, char *path_name, char *name)
{
        struct dentry  *dentry = NULL;
        struct snap_info *snap_info;
        int            rc = 0;        
        ENTRY;
                
        if (!SMFS_DO_COW(S2SMI(sb))) {
                RETURN(0);
        }

        if (!path_name || !name) {
                CERROR("patch_name and snapshot_name is NULL");
                RETURN(-EINVAL);
        } 
        dentry = smfs_find_snap_root(sb, path_name);
        if (IS_ERR(dentry)) {
                CERROR("can not find snap_shot root by %s\n", path_name);
                RETURN(PTR_ERR(dentry)); 
        }
        snap_info = smfs_find_create_snap_info(sb, dentry->d_inode);
        if (IS_ERR(snap_info)) {
                CERROR("can not find snap_info by %s rc=%lu\n", path_name,
                        PTR_ERR(snap_info));
                GOTO(exit, rc = PTR_ERR(snap_info)); 
        }

        rc = snap_add_item(S2SMI(sb), snap_info, name);
exit:       
        dput(dentry); 
        RETURN(rc); 
}        
//EXPORT_SYMBOL(smfs_add_snap_item);
/*
 * Note: this function should be differnet with snap_do_cow.
 * In smfs_do_cow, we check the EA for whether do cow for that inode.
 * In smfs_needs_cow, we check whether we do need to do cow. 
 */
int smfs_needs_cow(struct inode *inode)
{
	struct smfs_inode_info  *smi_info = I2SMI(inode); 
        struct snap_inode_info *snap_info = NULL;
        struct snap snap;
	int index = -1;
	ENTRY;

	snap_info = &(smi_info->sm_sninfo);
	
        snap_last(inode, &snap);
	/* decision .... if the snapshot is more recent than the object,
	 * then any change to the object should cause a COW.
	 */
	if (snap_info->sn_gen < snap.sn_gen ) 
		index = snap.sn_index;

	CDEBUG(D_INFO, "snap_needs_cow, ino %lu , get index %d\n",
	       inode->i_ino, index);

	RETURN(index);
} /* snap_needs_cow */

static int link_cowed_inode(struct inode *inode)
{
        struct dentry *cowed_dir = NULL;
        char idname[LL_ID_NAMELEN];
        struct snap_info *snap_info;	
        int idlen = 0, rc = 0;
        struct dentry *dchild = NULL;
        struct dentry *tmp = NULL;
        unsigned mode;

        snap_info = smfs_find_snap_info(inode);
        if (!snap_info) {
                CERROR("can not find snap info for inode %p\n", inode);
                RETURN(-EINVAL);                
        }

        cowed_dir = snap_info->sni_cowed_dentry;
        
        down(&cowed_dir->d_inode->i_sem);

        idlen = ll_id2str(idname, inode->i_ino, inode->i_generation);
        dchild = lookup_one_len(idname, cowed_dir, idlen);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                if (rc != -EPERM && rc != -EACCES)
                        CERROR("child lookup error %d\n", rc);
                GOTO(out_lock, rc);
        }
        if (dchild->d_inode != NULL) {
                CERROR("re-cowed file %s?\n", dchild->d_name.name);
                LASSERT(dchild->d_inode == inode);
                GOTO(out_dput, rc = 0);
        }
        tmp = pre_smfs_dentry(NULL, inode, cowed_dir);
        /* link() is semanticaly-wrong for S_IFDIR, so we set S_IFREG
         * for linking and return real mode back then -bzzz */
        mode = inode->i_mode;
        inode->i_mode = S_IFREG;

        rc = cowed_dir->d_inode->i_op->link(tmp, cowed_dir->d_inode, dchild);         

        post_smfs_dentry(tmp);
        if (rc) {
                CERROR("error linking cowed inode %s to COWED: rc = %d\n",
                        idname, rc);
        } 
        inode->i_mode = mode;
        if ((mode & S_IFMT) == S_IFDIR) {
                dchild->d_inode->i_nlink++;
                cowed_dir->d_inode->i_nlink++;
                mark_inode_dirty(cowed_dir->d_inode);
                mark_inode_dirty(dchild->d_inode);
        }
out_dput:
        up(&cowed_dir->d_inode->i_sem);
        dput(dchild);
out_lock:       
        RETURN(rc);
}
/*
 * Make a copy of the data and plug a redirector in between if there
 * is no redirector yet.
 */
int snap_do_cow(struct inode *inode, struct dentry *dparent, int del)
{
	struct fsfilt_operations *snapops = I2SNAPCOPS(inode);
        struct snap snap;
	struct inode *cache_ind = NULL;
        ENTRY;

	if (!snapops || !snapops->fs_create_indirect) 
		RETURN(-EINVAL);

	snap_last(inode, &snap);
	cache_ind = snapops->fs_create_indirect(I2CI(inode), snap.sn_index, 
                                          snap.sn_gen, I2CI(dparent->d_inode), 
                                          del);
	if(cache_ind && IS_ERR(cache_ind)) {
                CERROR("Create ind inode %lu index %d gen %d del %d rc%lu\n",
                        inode->i_ino, snap.sn_index, snap.sn_gen, del,
                        PTR_ERR(cache_ind));
		RETURN(PTR_ERR(cache_ind));
        }
        if (cache_ind) {
                iput(cache_ind);
                if (!SMFS_DO_INODE_COWED(inode)) {
                        /*insert the inode to cowed inode*/
                        SMFS_SET_INODE_COWED(inode); 
                        link_cowed_inode(inode); 
                }
        }
        RETURN(0);
}
/*Dir inode will do cow*/
int smfs_cow_create_pre(struct inode *dir, void *de, void *data1, void *data2)
{
        struct dentry *dparent;
        struct dentry *dentry = (struct dentry *)de;
        int rc = 0;
        ENTRY;

        if (smfs_needs_cow(dir) != -1) {
		CDEBUG(D_INODE, "snap_needs_cow for ino %lu \n",dir->i_ino);
                LASSERT(dentry->d_parent && dentry->d_parent->d_parent);
                dparent = dentry->d_parent->d_parent;
        	if ((rc = snap_do_cow(dir, dparent, 0))) {
			CERROR("Do cow error %d\n", rc);
			RETURN(-EINVAL);
		}
	}
        RETURN(rc);
}

int smfs_cow_setattr_pre(struct inode *dir, void *de, void *data1, void *data2)
{
        struct dentry *dentry = (struct dentry *)de;
        int rc = 0;
        ENTRY;
        if (smfs_needs_cow(dir) != -1) {
		CDEBUG(D_INODE, "snap_needs_cow for ino %lu \n",dir->i_ino);
		if ((snap_do_cow(dir, dentry->d_parent, 0))) {
			CERROR("Do cow error\n");
			RETURN(-EINVAL);
		}
	}
        RETURN(rc);
}

int smfs_cow_link_pre(struct inode *dir, void *de, void *data1, void *data2)
{
        struct dentry *dparent;
        struct dentry *dentry = (struct dentry *)de;
        int rc = 0;
        ENTRY;
 
        if (smfs_needs_cow(dir) != -1) {
		CDEBUG(D_INODE, "snap_needs_cow for ino %lu \n",dir->i_ino);
                LASSERT(dentry->d_parent && dentry->d_parent->d_parent);
                dparent = dentry->d_parent->d_parent;
		if ((snap_do_cow(dir, dparent, 0))) {
			CERROR("Do cow error\n");
			RETURN(-EINVAL);
		}
		if ((snap_do_cow(dentry->d_inode, dentry->d_parent, 0))) {
			CERROR("Do cow error\n");
			RETURN(-EINVAL);
                }
        }
        RETURN(rc);
}

int smfs_cow_unlink_pre(struct inode *dir, void *de, void *data1, void *data2)
{
        struct dentry *dentry = (struct dentry *)de; 
        struct dentry *dparent;
        int rc = 0;
        ENTRY;

        if (smfs_needs_cow(dir) != -1) {
		CDEBUG(D_INODE, "snap_needs_cow for ino %lu \n",dir->i_ino);
                LASSERT(dentry->d_parent && dentry->d_parent->d_parent);
                dparent = dentry->d_parent->d_parent;
		if ((snap_do_cow(dir, dparent, 0))) {
			CERROR("Do cow error\n");
			RETURN(-EINVAL);
		}
               	if ((snap_do_cow(dentry->d_inode, dentry->d_parent, 1))) {
			CERROR("Do cow error\n");
			RETURN(-EINVAL);
                }
        
        }
        RETURN(rc);
}

int smfs_cow_rename_pre(struct inode *dir, void *de, void *data1, void *data2)
{
        struct dentry *dentry = (struct dentry*)de;
        struct inode *new_dir = (struct inode *)data1;
        struct dentry *new_dentry = (struct dentry *)data2;
        struct dentry *dparent;
        int rc = 0;
        ENTRY;
       
        LASSERT(new_dir);
        LASSERT(new_dentry); 
        if (smfs_needs_cow(dir) != -1) {
		CDEBUG(D_INODE, "snap_needs_cow for ino %lu \n", dir->i_ino);
                LASSERT(dentry->d_parent && dentry->d_parent->d_parent);
                dparent = dentry->d_parent->d_parent;
		if ((snap_do_cow(dir, dparent, 0))) {
			CERROR("Do cow error\n");
			RETURN(-EINVAL);
		}
               	if ((snap_do_cow(dentry->d_inode, dentry->d_parent, 0))) {
			CERROR("Do cow error\n");
			RETURN(-EINVAL);
                }
        }
        if (smfs_needs_cow(new_dir) != -1) {
        	CDEBUG(D_INODE, "snap_needs_cow for ino %lu \n", new_dir->i_ino);
                LASSERT(new_dentry->d_parent && new_dentry->d_parent->d_parent);
                dparent = new_dentry->d_parent->d_parent;
		if ((new_dir != dir) && (snap_do_cow(new_dir, dparent, 0))){
			CERROR("Do cow error\n");
			RETURN(-EINVAL);
		}
                if (new_dentry->d_inode && new_dentry->d_inode->i_nlink == 1) {
               	        if ((snap_do_cow(new_dentry->d_inode, 
                                         new_dentry->d_parent, 0))) {
			        CERROR("Do cow error\n");
			        RETURN(-EINVAL);
                        }
                }
        } 
        RETURN(rc);
}

int smfs_cow_write_pre(struct inode *inode, void *de, void *data1, void *data2)
{
        struct dentry *dentry = (struct dentry*)de;
        struct snap_info *snap_info = NULL; 
        struct snap_table *table; 
	long   blocks[2]={-1,-1};
       	int  index = 0, i, rc = 0;
        size_t count;
	loff_t pos;

        ENTRY;

        snap_info = smfs_find_snap_info(inode);
        if (!snap_info) {
                CDEBUG(D_INFO, "can not find snap info for inode %p\n", inode);
                RETURN(0);                
        }
        table = snap_info->sni_table;

        LASSERT(data1);
        LASSERT(data2);
        
        count = *(size_t *)data1;
	pos = *(loff_t*)data2;
 
	down(&inode->i_sem);
        
        if (smfs_needs_cow(inode) != -1 ) {
                CDEBUG(D_INFO, "snap_needs_cow for ino %lu \n",inode->i_ino);
                snap_do_cow(inode, dentry->d_parent, 0);
	}
	
	CDEBUG(D_INFO, "write offset %lld count %u \n", pos, count);
	
	if(pos & (PAGE_CACHE_SIZE - 1)){
	        blocks[0] = pos >> inode->i_sb->s_blocksize_bits;
        }
	pos += count - 1;
	if((pos + 1) & (PAGE_CACHE_SIZE - 1)){
	        blocks[1] = pos >> inode->i_sb->s_blocksize_bits;
	}

	if (blocks[0] == blocks[1]) 
                blocks[1] = -1;
	
        for (i = 0; i < 2; i++) {
		int slot = 0;
                if (blocks[i] == -1) 
			continue;
		/*Find the nearest page in snaptable and copy back it*/
		for (slot = table->sntbl_count - 1; slot >= 0; slot--) {
                        struct fsfilt_operations *sops = I2SNAPCOPS(inode);
			struct inode *cind = NULL;
               		int result = 0;

                        index = table->sntbl_items[slot].sn_index;
			cind = sops->fs_get_indirect(I2CI(inode), NULL, index);
			if (!cind)  continue;

			CDEBUG(D_INFO, "find cache_ino %lu\n", cind->i_ino);
		
			result = sops->fs_copy_block(I2CI(inode), cind, 
                                                     blocks[i]);
			if (result == 1) {
               			iput(cind);
				result = 0;
				break;
			}
			if (result < 0) {
				iput(cind);
				up(&inode->i_sem);
				GOTO(exit, rc = result);
			}
               		iput(cind);
        	}
	}
exit:
        up(&inode->i_sem); 
        RETURN(rc);
}
EXPORT_SYMBOL(smfs_cow_write_pre);
/*lookup inode in dotsnap inode */
static int smfs_dotsnap_lookup(struct inode *dir, struct dentry *dentry,
                               struct snap_info *snap_info)
{ 
        if (dentry->d_name.len == 1 && 
            !strcmp(dentry->d_name.name, ".")) {
                d_add(dentry, iget(dir->i_sb, dir->i_ino));
        } else if (dentry->d_name.len == 2 && 
                   !strcmp(dentry->d_name.name, "..")) {
                struct inode *inode;
                struct dentry *dparent = dentry->d_parent;                                                                                                                                                                                       
                if (dparent->d_inode) {
                        inode = iget(dir->i_sb, dparent->d_inode->i_ino);
                        if (inode) {
                                if (!is_bad_inode(inode))
                                        d_add(dentry, inode);
                                else
                                        iput(inode);
                        }
                }
        } else {
                /*find the name from the snaptable*/
                struct fsfilt_operations *sops = I2SNAPCOPS(dir);
                struct snap_table *table; 
                struct inode *inode;
                ino_t  cino;
                int i = 0, index = -1;

                table = snap_info->sni_table;
                
                for (i = 0; i < table->sntbl_count; i++) {
                        char *name = table->sntbl_items[i].sn_name;
                        if ((dentry->d_name.len == strlen(name)) &&
                            (memcmp(dentry->d_name.name, name,
                                    dentry->d_name.len) == 0)) {
                                index = table->sntbl_items[i].sn_index;
                                break;
                        }
                }
                if (index == -1) {
                       CERROR("No such %s in this .snap dir \n", 
                               dentry->d_name.name);
                       RETURN(-ENOENT);
                }
                cino = sops->fs_get_indirect_ino(S2CSB(dir->i_sb), dir->i_ino,
                                                 index);
                if (cino == 0)
                        cino = dir->i_ino;
                inode = smfs_get_inode(dir->i_sb, cino, dir, index);
                if (!inode || is_bad_inode(inode)) {
                        CERROR("Can not find cino %lu inode\n", cino);
                        RETURN(-ENOENT); 
                } 
                smfs_init_snap_inode_info(inode, dir, index);
                d_add(dentry, inode);
        } 
        RETURN(0);
}
int smfs_cow_lookup_pre(struct inode *inode, void *de, void *data1,
                        void *data2)
{
        struct dentry *dentry = (struct dentry*)de;
        struct snap_info *snap_info;
        struct snap_dot_info *dot_info;
        int rc = 0;
        ENTRY;

        snap_info = smfs_find_snap_info(inode);
        if (!snap_info) {
                CDEBUG(D_INFO, "can not find snap info for inode %p\n", inode);
                RETURN(0);                
        }
        
        dot_info = snap_info->sni_dot_info;

        if (smfs_primary_inode(inode) && 
            dentry->d_name.len == dot_info->dot_name_len &&
            memcmp(dentry->d_name.name, dot_info->dot_name, 
                   strlen(dot_info->dot_name)) == 0) {
                struct inode *dot_inode = NULL; 
                
                dot_inode = smfs_get_inode(inode->i_sb, inode->i_ino, inode,
                                           DOT_SNAP_INDEX);
                smfs_init_snap_inode_info(dot_inode, inode, DOT_SNAP_INDEX);
                d_add(dentry, dot_inode);
                rc = 1;
                RETURN(rc);
        } else if (smfs_dotsnap_inode(inode)) {
                rc = smfs_dotsnap_lookup(inode, dentry, snap_info);
                if (rc == 0)
                        rc = 1;
                RETURN(rc);                
        } else {
                /*HERE: will replace ino in dentry->d_name according to index,
                 *For iopen, will fix it in integrating snapfs to Lustre*/ 
#if 0
                struct fsfilt_operations *snapops = I2SNAPOPS(inode);
                char *name = (char *)dentry->d_name.name;
                unsigned long ino, hash, ind_ino; 
                int len = sizeof(ind_ino);
                 
                ino = simple_strtoul(name, 0, 0);         

                ind_ino = snapops->fs_get_indirect_ino(inode->i_sb, ino, index);
                
                snprintf(name, strlen(name), "0x%lx", ind_ino);                 
                
                hash = init_name_hash();
                while (len--) {
                        unsigned char c; 
                        c = *(const unsigned char *)name++;
                        if (c == '\0') break;
                        hash = partial_name_hash(c, hash);
                }
                dentry->d_name.hash = end_name_hash(hash);
#endif     
        }
        RETURN(rc);         
}

struct inode *smfs_cow_get_ind(struct inode *inode, int index)
{
        long block=(index << PAGE_CACHE_SHIFT) >> inode->i_sb->s_blocksize_bits;
        struct fsfilt_operations *sops = I2SNAPCOPS(inode); 
        struct snap_info *snap_info = NULL;
        struct snap_table *table = NULL;
        int slot;

        ENTRY;
        
        snap_info = smfs_find_snap_info(inode);
        if (!snap_info) {
                CDEBUG(D_INFO, "can not find snap info for inode %p\n", inode);
                RETURN(NULL);                
        }
        
        table = snap_info->sni_table;        

        for (slot = table->sntbl_count - 1; slot >= 0; slot--) {
                struct address_space_operations *aops = inode->i_mapping->a_ops;
                struct inode *cache_inode = NULL;
                int index = 0;

                index = table->sntbl_items[slot].sn_index;
                cache_inode = sops->fs_get_indirect(I2CI(inode), NULL, index);
                                                                                                                                                                                                     
                if (!cache_inode )  continue;
                
                if (aops->bmap(cache_inode->i_mapping, block))
                       RETURN(cache_inode); 
                iput(cache_inode);
        }

        RETURN(NULL);
}
EXPORT_SYMBOL(smfs_cow_get_ind);

static int smfs_cow_readdir_pre(struct inode *dir, void *de, void *data1,
                                void *data2)
{
        struct file *filp = (struct file*)de;
        void *dirent = data1; 
        filldir_t filldir = (filldir_t)data2;
        struct snap_info *snap_info = NULL;
        
        if (smfs_under_dotsnap_inode(dir))
                RETURN(0);

        snap_info = smfs_find_snap_info(dir);

        if (!snap_info) {
                CDEBUG(D_INFO, "can not find snap info for ino %lu\n", 
                       dir->i_ino);
                RETURN(-EINVAL);                
        }

        if (smfs_primary_inode(dir)) {
                if (filp->f_pos == 0) {
                        struct snap_dot_info *dot = snap_info->sni_dot_info;
                        if (filldir(dirent, dot->dot_name, dot->dot_name_len, 
                                    filp->f_pos, -1, 0)) { 
                                CERROR("fill .snap error \n");
                                RETURN(-EINVAL);
                        }
                } else {
                        filp->f_pos -= 1;
                }
        } else if (smfs_dotsnap_inode(dir)) {
                struct snap_table *table = snap_info->sni_table;   
                int i = 0;

                if (filp->f_pos < 0)
                       RETURN(-EINVAL);
        
                if ((filp->f_pos == 0) && filldir(dirent, ".", 1, 
                                                  filp->f_pos++, 
                                                  dir->i_ino, 0) < 0)
                       RETURN(-EIO);
                if ((filp->f_pos == 1) && filldir(dirent, "..", 2, 
                                                  filp->f_pos++, 
                                                  dir->i_ino, 0) < 0)
                       RETURN(-EIO); 
               
                for (i = filp->f_pos - 2; i < table->sntbl_count; i++, 
                     filp->f_pos++) { 
                        int slot = table->sntbl_count - i - 1;
                        
                        if (filldir(dirent, table->sntbl_items[slot].sn_name,
                                    strlen(table->sntbl_items[slot].sn_name),
                                    filp->f_pos, dir->i_ino, 0))
                                break;
                         
                } 
                RETURN(1); 
        }
        
        RETURN(0); 
}


typedef int (*cow_funcs)(struct inode *dir, void *dentry, void *new_dir, 
                         void *new_dentry);

static cow_funcs smfs_cow_pre_funcs[HOOK_MAX + 1] = {
        [HOOK_CREATE]   smfs_cow_create_pre,
        [HOOK_LOOKUP]   smfs_cow_lookup_pre,
        [HOOK_LINK]     smfs_cow_link_pre,
        [HOOK_UNLINK]   smfs_cow_unlink_pre,
        [HOOK_SYMLINK]  smfs_cow_create_pre,
        [HOOK_MKDIR]    smfs_cow_create_pre,
        [HOOK_RMDIR]    smfs_cow_unlink_pre, 
        [HOOK_MKNOD]    smfs_cow_create_pre,
        [HOOK_RENAME]   smfs_cow_rename_pre,
        [HOOK_SETATTR]  smfs_cow_setattr_pre,
        [HOOK_WRITE]    smfs_cow_write_pre,
        [HOOK_READDIR]  smfs_cow_readdir_pre,
};

static int smfs_revalidate_dotsnap_dentry(struct dentry *dentry, 
                                          struct inode *dir, int index)
{
        struct inode *inode = dentry->d_inode;
        ENTRY;       
 
        if (!inode)
                RETURN(0);

        if (index > 0 && index != DOT_SNAP_INDEX) {
                struct fsfilt_operations *sops = I2SNAPCOPS(inode); 
                struct inode *cache_ind = NULL;

                cache_ind = sops->fs_get_indirect(I2CI(inode), NULL, index);
                
                if (cache_ind) {
                        struct inode *ind_inode = NULL;

                        LASSERT(cache_ind->i_ino != I2CI(inode)->i_ino);
                        
                        ind_inode = smfs_get_inode(inode->i_sb, cache_ind->i_ino,
                                                   dir, index);
                        list_del_init(&dentry->d_alias);
                        iput(inode);
                        d_instantiate(dentry, ind_inode);                         
                        iput(cache_ind); 
                }
        }
        RETURN(0);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int
smfs_revalidate_nd(struct dentry *de, struct nameidata *nd)
{
        struct inode *inode = de->d_inode;
        ENTRY;

        if (!inode)
                RETURN(0);
        
        if (smfs_under_dotsnap_inode(inode)) {
                struct inode *dir = de->d_parent->d_inode;
                int index = I2SNAPI(inode)->sn_index;
                
                smfs_revalidate_dotsnap_dentry(de, dir, index);
                smfs_init_snap_inode_info(de->d_inode, dir, index);
        }

        RETURN(0);
}
#else
static int
smfs_revalidate_it(struct dentry *de, int flags,
                   struct nameidata *nd,
                   struct lookup_intent *it)
{
        struct inode *inode = de->d_inode;
        ENTRY;

        if (!inode)
                RETURN(0);
        
        if (smfs_under_dotsnap_inode(inode)) {
                struct inode *dir = de->d_parent->d_inode;
                int index = I2SNAPI(inode)->sn_index;
                
                smfs_revalidate_dotsnap_dentry(de, dir, index);
                smfs_init_snap_inode_info(de->d_inode, dir, index);
        }

        RETURN(0);
}
#endif

static int smfs_delete_dentry(struct dentry *dentry)
{
        dentry->d_op = NULL; 
        return 0;
}
 
struct dentry_operations smfs_cow_dops = {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        .d_revalidate = smfs_revalidate_nd,
#else
        .d_revalidate_it = smfs_revalidate_it,
#endif
        .d_delete     = smfs_delete_dentry,
};

int smfs_cow_lookup_post(struct inode *dir, void *de, void *data1,
                         void *data2)
{
        struct dentry *dentry = (struct dentry*)de;
        struct inode *inode = dentry->d_inode; 
        ENTRY;

        if (inode && smfs_under_dotsnap_inode(inode)) {
                int index = I2SNAPI(dir)->sn_index;
        
                smfs_revalidate_dotsnap_dentry(dentry, dir, index);
                smfs_init_snap_inode_info(inode, dir, index);
        }
        dentry->d_op = &smfs_cow_dops;  
        RETURN(0);
}

static int smfs_cow_readdir_post(struct inode *dir, void *de, void *data1,
                                 void *data2)
{
        struct file *filp = (struct file*)de;
        
        if (smfs_primary_inode(dir)) {
                filp->f_pos += 1;
        }
        RETURN(0); 
}


static cow_funcs smfs_cow_post_funcs[HOOK_MAX + 1] = {
        [HOOK_CREATE]   NULL,
        [HOOK_LOOKUP]   smfs_cow_lookup_post,
        [HOOK_LINK]     NULL,
        [HOOK_UNLINK]   NULL,
        [HOOK_SYMLINK]  NULL,
        [HOOK_MKDIR]    NULL,
        [HOOK_RMDIR]    NULL, 
        [HOOK_MKNOD]    NULL,
        [HOOK_RENAME]   NULL,
        [HOOK_SETATTR]  NULL,
        [HOOK_WRITE]    NULL,
        [HOOK_READDIR]  smfs_cow_readdir_post,
};

static int smfs_cow_pre(struct inode *dir, void *dentry, void *new_dir, 
                        void *new_dentry, int op)
{
        if (smfs_cow_pre_funcs[op]) {
                return smfs_cow_pre_funcs[op](dir, dentry, new_dir, new_dentry);
        }
        return 0;
}

static int smfs_cow_post(struct inode *dir, void *dentry, void *new_dir, 
                         void *new_dentry, int op)
{
        if (smfs_cow_post_funcs[op]) {
                return smfs_cow_post_funcs[op](dir, dentry, new_dir, new_dentry);
        }
        return 0;
}

