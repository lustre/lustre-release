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

#include <linux/lustre_snap.h>
#include <linux/lustre_smfs.h>

#include "smfs_internal.h"
#define SNAPTABLE_SIZE(size) (sizeof(struct snap_table) + size * sizeof(struct snap)) 
static int smfs_init_snaptabe(struct super_block *sb)
{
        struct snap_info         *snap_info = S2SNAPI(sb);	
        struct snap_table        *snap_table = NULL;       
	struct fsfilt_operations *snapops = snap_info->snap_fsfilt;
        struct dentry            *d_root = snap_info->snap_root;
        int                      rc = 0, size, table_size, vallen, i;
 
        ENTRY;

        init_MUTEX(&snap_info->sntbl_sema);
        /*Initialized table */
        /*get the maxsize of snaptable*/
        vallen = sizeof(int);
        rc = snapops->fs_get_snap_info(d_root->d_inode, MAX_SNAPTABLE_COUNT,
                                       strlen(MAX_SNAPTABLE_COUNT), &size, 
                                       &vallen);
        if (size == 0) {
                CERROR("the Max snaptable count should not be zero\n");
                RETURN(-EINVAL);
        }
        
        table_size = SNAPTABLE_SIZE(size);

        OBD_ALLOC(snap_info->sntbl, table_size);

        if (!snap_info->sntbl) {
                CERROR("No MEM\n");
                RETURN(-ENOMEM);
        }
        snap_table = snap_info->sntbl;
         
        snap_table->sntbl_magic = cpu_to_le32((__u32)SNAPTABLE_MAGIC); 
        snap_table->sntbl_max_count = size;
        for (i = 0; i < snap_table->sntbl_max_count; i++) {
                /*init sn_index to -1*/ 
                snap_table->sntbl_items[i].sn_index = -1;
        }
        /*get snaptable info*/
        rc = snapops->fs_get_snap_info(d_root->d_inode, SNAPTABLE_INFO, 
                                       strlen(SNAPTABLE_INFO), 
                                       snap_table, &table_size);       
        if (rc < 0) {
                if (rc == -ENOATTR) {
                        snap_table->sntbl_count = 0;
                        CDEBUG(D_INFO, "No snaptable here\n");
                        RETURN(0);
                } else {
                        CERROR("Can not retrive the snaptable from this filesystem\n");
                        OBD_FREE(snap_table, table_size);
                        RETURN(rc); 
                }
        } 
        if (le32_to_cpu(snap_table->sntbl_magic) != SNAPTABLE_MAGIC) {
                CERROR("On disk snaptable is not right \n");
                OBD_FREE(snap_table, table_size);
                RETURN(-EIO);
        }
        RETURN(rc);
}
#define COWED_NAME_LEN       (7 + 8 + 1) 
static int smfs_init_cowed_dir(struct super_block *sb, struct dentry* cowed_dir)  
{
        struct snap_info *snap_info = S2SNAPI(sb);	
        struct dentry    *dentry = NULL;
        struct lvfs_run_ctxt saved;
        char   name[COWED_NAME_LEN];
        int    rc = 0;
        ENTRY;
         
        sprintf(name, ".cowed_%08x", (__u32)cowed_dir->d_inode->i_ino);
        push_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);
        dentry = simple_mkdir(cowed_dir, name, 0777, 1);
        pop_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("create cowed directory: rc = %d\n", rc);
                RETURN(rc);
        }
        snap_info->sn_cowed_dentry = dentry;
        RETURN(rc);
}
#define DOT_SNAP_NAME          ".snap"
static int smfs_init_dotinfo(struct super_block *sb)
{
        struct snap_info *snap_info = S2SNAPI(sb);
        struct snap_dot_info *dot_info = NULL;
        int rc = 0;
        ENTRY;

        if (snap_info->sn_dot_info)
                RETURN(-EEXIST);
       
        OBD_ALLOC(snap_info->sn_dot_info, sizeof(struct snap_dot_info));
        
        if (!snap_info->sn_dot_info)
                RETURN(-ENOMEM); 
      
        dot_info = snap_info->sn_dot_info;
 
        OBD_ALLOC(dot_info->dot_name,  strlen(DOT_SNAP_NAME) + 1);

        if (!dot_info->dot_name) {
                OBD_FREE(snap_info->sn_dot_info, sizeof(struct snap_dot_info));
                RETURN(-ENOMEM); 
        } 
        memcpy(dot_info->dot_name, DOT_SNAP_NAME, strlen(DOT_SNAP_NAME));
        
        dot_info->dot_name_len = strlen(DOT_SNAP_NAME); 
        dot_info->dot_snap_enable = 1;
        
        RETURN(rc);
}

static int smfs_cleanup_dotinfo(struct super_block *sb)
{       
        struct snap_info *snap_info = S2SNAPI(sb);
        struct snap_dot_info *dot_info = NULL;
        int rc = 0;
        ENTRY;

        if (!snap_info->sn_dot_info)
                RETURN(rc);
       
        dot_info = snap_info->sn_dot_info;

        if (dot_info->dot_name) { 
                OBD_FREE(dot_info->dot_name, dot_info->dot_name_len + 1);
        }
        
        OBD_FREE(dot_info, sizeof(struct snap_dot_info));

        RETURN(rc);
}

int smfs_start_cow(struct super_block *sb)
{
        int rc = 0;

        ENTRY;
        
        /*init snap fsfilt operations*/
        if (!S2SNAPI(sb)->snap_cache_fsfilt) {
                char *snap_cache_ftype = NULL;
                int   tmp = strlen(S2SMI(sb)->smsi_cache_ftype) + strlen("_snap");
                
                OBD_ALLOC(snap_cache_ftype, tmp + 1);  
                sprintf(snap_cache_ftype, "%s_snap", S2SMI(sb)->smsi_cache_ftype);
                S2SNAPI(sb)->snap_cache_fsfilt = fsfilt_get_ops(snap_cache_ftype);
                OBD_FREE(snap_cache_ftype, tmp + 1);
                if (!S2SNAPI(sb)->snap_cache_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by snap\n",
                               snap_cache_ftype);
                        RETURN(-EINVAL);
                }
        }
        if (!S2SNAPI(sb)->snap_fsfilt) {
                char *snap_ftype = NULL;
                int   tmp = strlen(S2SMI(sb)->smsi_ftype) + strlen("_snap");
                
                OBD_ALLOC(snap_ftype, tmp + 1);  
                sprintf(snap_ftype, "%s_snap", S2SMI(sb)->smsi_ftype);
                S2SNAPI(sb)->snap_fsfilt = fsfilt_get_ops(snap_ftype);
                OBD_FREE(snap_ftype, tmp + 1);
                if (!S2SNAPI(sb)->snap_fsfilt) {
                        CERROR("Can not get %s fsfilt ops needed by snap\n",
                               snap_ftype);
                        RETURN(-EINVAL);
                }
        }
        rc = smfs_init_snaptabe(sb); 
        if (rc) {
                CERROR("can not init snaptable rc=%d\n", rc);
                RETURN(rc);
        }
        /*init dot snap info*/
        rc = smfs_init_dotinfo(sb);
        if (rc) {
                CERROR("can not init dot snap info rc=%d\n", rc);
                RETURN(rc);
        }
        /*init cowed dir to put the primary cowed inode
         *FIXME-WANGDI, later the s_root may not be the 
         *snap dir, we can indicate any dir to be cowed*/
        rc = smfs_init_cowed_dir(sb, sb->s_root);
        RETURN(rc);
}
EXPORT_SYMBOL(smfs_start_cow);
int smfs_stop_cow(struct super_block *sb)
{
        struct snap_info       *snap_info = S2SNAPI(sb);	
        struct snap_table      *snap_table = snap_info->sntbl;	
        int rc = 0, table_size;
        ENTRY;

        l_dput(snap_info->sn_cowed_dentry);
         
        if (snap_info->snap_fsfilt) 
                fsfilt_put_ops(snap_info->snap_fsfilt);
        if (snap_info->snap_cache_fsfilt)
                fsfilt_put_ops(snap_info->snap_cache_fsfilt);

        if (snap_table) {
                table_size =  SNAPTABLE_SIZE(snap_table->sntbl_max_count);
                OBD_FREE(snap_info->sntbl, table_size);
        }
        smfs_cleanup_dotinfo(sb);
         
        RETURN(rc);
}
EXPORT_SYMBOL(smfs_stop_cow);

#define COW_HOOK "cow_hook"
static int smfs_cow_pre_hook(struct inode *inode, struct dentry *dentry, 
                             void *data1, void *data2, int op, void *handle)
{
        int rc = 0;
        ENTRY;
 
        if (smfs_do_cow(inode)) {                                              
                rc = smfs_cow(inode, dentry, data1, data2, op);           
        }
        RETURN(rc);                                                                     
}
int smfs_cow_init(struct super_block *sb)
{
        struct smfs_super_info *smfs_info = S2SMI(sb);
        struct smfs_hook_ops *cow_hops = NULL;
        int rc = 0;

        ENTRY;

        SMFS_SET_COW(smfs_info);
      
        cow_hops = smfs_alloc_hook_ops(COW_HOOK, smfs_cow_pre_hook, NULL);
        if (!cow_hops) {
                RETURN(-ENOMEM);
        }
 
        rc = smfs_register_hook_ops(sb, cow_hops);      

        if (rc) {
                smfs_free_hook_ops(cow_hops);
                RETURN(rc);
        }
 
        OBD_ALLOC(smfs_info->smsi_snap_info, sizeof(struct snap_info));
        
        if (!smfs_info->smsi_snap_info) 
                GOTO(exit, rc = -ENOMEM);
exit:
        if (rc && cow_hops) {
                smfs_unregister_hook_ops(sb, cow_hops->smh_name);
                smfs_free_hook_ops(cow_hops);
        } 
        RETURN(rc);
}

int smfs_cow_cleanup(struct super_block *sb)
{
        
        struct snap_info   *snap_info = S2SNAPI(sb);	
        struct smfs_hook_ops *cow_hops; 
        ENTRY;

        cow_hops = smfs_unregister_hook_ops(sb, COW_HOOK);
        smfs_free_hook_ops(cow_hops);

        SMFS_CLEAN_COW(S2SMI(sb));
        if (snap_info) 
               OBD_FREE(snap_info, sizeof(*snap_info)); 
        RETURN(0);
}

/*FIXME Note indirect and primary inode 
* should be recorgnized here*/
int smfs_init_snap_inode_info(struct inode *inode, int flags)
{
        int vallen, rc = 0;
        ENTRY;

        if (SMFS_DO_COW(S2SMI(inode->i_sb)) &&
            (flags & SM_DO_COW)) {
                struct snap_inode_info *sni_info = I2SNAPI(inode);
                struct fsfilt_operations *snapops = I2SNAPOPS(inode);
                
                sni_info->sn_flags = flags;
                vallen = sizeof(sni_info->sn_gen);

                rc = snapops->fs_get_snap_info(inode, SNAP_GENERATION,
                                               strlen(SNAP_GENERATION),
                                               &sni_info->sn_gen, &vallen);               
        } 
        RETURN(rc);                                              
         
}
/* latest snap: returns 
   -  the index of the latest snapshot before NOW
   -  hence it returns 0 in case all the volume snapshots lie in the future
   -  this is the index where a COW will land (will be created) 
*/
void snap_last(struct super_block *sb, struct snap *snap)
{
	struct snap_info *snap_info = S2SNAPI(sb);
	struct snap_table *table = snap_info->sntbl;
        time_t now = CURRENT_TIME;
	int i ;

	ENTRY;
	/* start at the highest index in the superblock snaptime array */ 
	if (table->sntbl_count == 0) {
               memset(snap, 0, sizeof(struct snap)); 
        } else {
                i = table->sntbl_count - 1;
                snap->sn_index = table->sntbl_items[i].sn_index;
                snap->sn_time = table->sntbl_items[i].sn_time;
                snap->sn_gen = table->sntbl_items[i].sn_gen;
        }
	CDEBUG(D_INFO, "index: %d, time[i]: %ld, now: %ld\n",
	       snap->sn_index, snap->sn_time, now);
        EXIT;
	return;
}

static int inline get_index_of_item(struct snap_table *table, char *name)
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

	for (i = 0; i < table->sntbl_max_count; i++) {
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

int smfs_add_snap_item(struct super_block *sb, char *name)
{
	struct snap_info *snap_info = S2SNAPI(sb);
        struct fsfilt_operations *snapops = snap_info->snap_fsfilt;
        struct snap_table *snap_table = snap_info->sntbl;
        struct dentry            *d_root = snap_info->snap_root;
        struct snap      *snap_item;
        int    table_size, count = 0, index = 0, rc = 0;

        count = snap_table->sntbl_count; 
	/* XXX Is down this sema necessary*/
	down_interruptible(&snap_info->sntbl_sema);
        snap_item = &snap_table->sntbl_items[count];

	/*add item in snap_table set generation*/
	snap_item->sn_time = CURRENT_TIME;
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
        
        rc = snapops->fs_set_snap_info(d_root->d_inode, SNAPTABLE_INFO, 
                                       strlen(SNAPTABLE_INFO),
				       snap_table, &table_size);
	if (rc) {
                CERROR("Set snaptable error rc=%d\n", rc);
                GOTO(exit, rc);
        }
        snap_table->sntbl_count++;
	snap_table->sntbl_generation++;
exit:
	up(&snap_info->sntbl_sema);
	RETURN(rc);
}
EXPORT_SYMBOL(smfs_add_snap_item);
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
	
        snap_last(inode->i_sb, &snap);
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
        struct snap_info *snap_info = S2SNAPI(inode->i_sb);	
        struct dentry *cowed_dir = NULL;
        char fidname[LL_FID_NAMELEN];
        int fidlen = 0, rc = 0;
        struct dentry *dchild = NULL;
        struct dentry *tmp = NULL;
        unsigned mode;

        cowed_dir = snap_info->sn_cowed_dentry;
        
        fidlen = ll_fid2str(fidname, inode->i_ino, inode->i_generation);

        down(&cowed_dir->d_inode->i_sem);
        dchild = ll_lookup_one_len(fidname, cowed_dir, fidlen);
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
        rc = vfs_link(tmp, cowed_dir->d_inode, dchild);
        post_smfs_dentry(tmp);
        if (rc) {
                CERROR("error linking cowed inode %s to COWED: rc = %d\n",
                        fidname, rc);
        } 
        inode->i_mode = mode;
        if ((mode & S_IFMT) == S_IFDIR) {
                dchild->d_inode->i_nlink++;
                cowed_dir->d_inode->i_nlink++;
        }
        mark_inode_dirty(dchild->d_inode);
out_dput:
        dput(dchild);
out_lock:       
        up(&cowed_dir->d_inode->i_sem);
        RETURN(rc);
}
/*
 * Make a copy of the data and plug a redirector in between if there
 * is no redirector yet.
 */
int snap_do_cow(struct inode *inode, struct dentry *dparent, int del)
{
        struct snap_info *snap_info = S2SNAPI(inode->i_sb);	
	struct fsfilt_operations *snapops = snap_info->snap_fsfilt;
        struct snap snap;
	struct inode *ind = NULL;

	ENTRY;

	if (!snapops || !snapops->fs_create_indirect) 
		RETURN(-EINVAL);

	snap_last(inode->i_sb, &snap);
	ind = snapops->fs_create_indirect(inode, snap.sn_index, snap.sn_gen, 
                                          dparent->d_inode, del);
	if(ind && IS_ERR(ind)) {
                CERROR("Create ind inode %lu index %d gen %d del %d\n rc%u\n",
                        inode->i_ino, snap.sn_index, snap.sn_gen, del,
                        PTR_ERR(ind));
		RETURN(PTR_ERR(ind));
        }
        if (ind) { 
                if (!SMFS_DO_INODE_COWED(inode)) {
                        /*insert the inode to cowed inode*/
                        SMFS_SET_INODE_COWED(inode); 
                        link_cowed_inode(inode); 
                }
                
                I2SMI(ind)->sm_sninfo.sn_flags = 0;
                I2SMI(ind)->sm_sninfo.sn_gen = snap.sn_gen;
                
                iput(ind);
        }
        RETURN(0);
}
/*Dir inode will do cow*/
int smfs_cow_create(struct inode *dir, struct dentry *dentry,
                    void *data1, void *data2)
{
        int rc = 0;
        struct dentry *dparent;
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

int smfs_cow_setattr(struct inode *dir, struct dentry *dentry,
                     void *data1, void *data2)
{
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

int smfs_cow_link(struct inode *dir, struct dentry *dentry,
                  void *data1, void *data2)
{
        int rc = 0;
        struct dentry *dparent;
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

int smfs_cow_unlink(struct inode *dir, struct dentry *dentry,
                    void *data1, void *data2)
{
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

int smfs_cow_rename(struct inode *dir, struct dentry *dentry, 
                    void *data1, void *data2)
{
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

int smfs_cow_write(struct inode *inode, struct dentry *dentry, void *data1,
                   void *data2)
{
        struct snap_info *snap_info = S2SNAPI(inode->i_sb); 
        struct snap_table *table = snap_info->sntbl; 
	long   blocks[2]={-1,-1};
       	int  index = 0, i, rc = 0;
        size_t count;
	loff_t pos;

        ENTRY;

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
                        struct fsfilt_operations *snapops = snap_info->snap_fsfilt;
			struct inode *cache_inode = NULL;
               		int result = 0;

                        index = table->sntbl_items[slot].sn_index;
			cache_inode = snapops->fs_get_indirect(inode, NULL, index);

			if (!cache_inode)  continue;

			CDEBUG(D_INFO, "find cache_ino %lu\n", cache_inode->i_ino);
		
			result = snapops->fs_copy_block(inode, cache_inode, blocks[i]);
			if (result == 1) {
               			iput(cache_inode);
				result = 0;
				break;
			}
			if (result < 0) {
				iput(cache_inode);
				up(&inode->i_sem);
				GOTO(exit, rc = result);
			}
               		iput(cache_inode);
        	}
	}
exit:
        up(&inode->i_sem); 
        RETURN(rc);
}
EXPORT_SYMBOL(smfs_cow_write);

int smfs_cow_lookup(struct inode *inode, struct dentry *dentry, void *data1,
                    void *data2)
{
        struct snap_info *snap_info = S2SNAPI(inode->i_sb);
        struct fsfilt_operations *snapops = snap_info->snap_fsfilt;
        struct dentry *dparent = dentry->d_parent;
        struct clonefs_info *clone_info=(struct clonefs_info*)dparent->d_fsdata;
        int rc = 0;
 
        if (clone_info && clone_info->clone_flags && SM_CLONE_FS) {
                struct inode *ind_inode = NULL;
                struct inode *cache_ind = NULL;
                struct dentry *cache_dentry = NULL;
                struct dentry *cache_parent = NULL;
                struct inode *cache_inode;
                struct dentry *tmp;
                rc = 1;
 
                ind_inode = snapops->fs_get_indirect(inode, NULL, clone_info->clone_index);
                if (!ind_inode) 
                        RETURN(-ENOENT);
                
                if (!(cache_ind = I2CI(ind_inode)))
                        GOTO(exit, rc = -ENOENT);

                cache_parent=pre_smfs_dentry(NULL, cache_ind, dentry->d_parent);
                cache_dentry=pre_smfs_dentry(cache_parent, NULL, dentry);

                tmp = cache_ind->i_op->lookup(cache_ind, cache_dentry);
        
                if (IS_ERR(tmp))
                        GOTO(exit, rc = -ENOENT);

                if ((cache_inode = tmp ? tmp->d_inode : cache_dentry->d_inode)) {
                        if (IS_ERR(cache_inode)) {
                                dentry->d_inode = cache_inode;
                                GOTO(exit, rc = -ENOENT);
                        }
                        inode = iget4(inode->i_sb, cache_inode->i_ino, NULL,
                                      &I2SMI(inode)->smi_flags);
                } else {
                        d_add(dentry, NULL);
                        GOTO(exit, rc = -ENOENT);
                }
                d_add(dentry, inode);
exit:
                iput(ind_inode);
                post_smfs_dentry(cache_dentry);
                post_smfs_dentry(cache_parent);
                RETURN(rc);
        } 
        RETURN(rc);         
}

struct inode *smfs_cow_get_ind(struct inode *inode, int index)
{
        struct snap_info *snap_info = S2SNAPI(inode->i_sb);
        struct fsfilt_operations *snapops = snap_info->snap_fsfilt; 
        struct snap_table *table = snap_info->sntbl;
        long block=(index << PAGE_CACHE_SHIFT) >> inode->i_sb->s_blocksize_bits;
        int slot;

        ENTRY; 
        for (slot = table->sntbl_count - 1; slot >= 0; slot--) {
                struct address_space_operations *aops = inode->i_mapping->a_ops;
                struct inode *cache_inode = NULL;
                int index = 0;

                index = table->sntbl_items[slot].sn_index;
                cache_inode = snapops->fs_get_indirect(inode, NULL, index);
                                                                                                                                                                                                     
                if (!cache_inode )  continue;
                                                                                                                                                                                                     
                if (aops->bmap(cache_inode->i_mapping, block))
                       RETURN(cache_inode); 
                iput(cache_inode);
        }

        RETURN(NULL);
}
EXPORT_SYMBOL(smfs_cow_get_ind);

typedef int (*cow_funcs)(struct inode *dir, struct dentry *dentry, 
                         void *new_dir, void *new_dentry);

static cow_funcs smfs_cow_funcs[HOOK_MAX + 1] = {
        [HOOK_CREATE]   smfs_cow_create,
        [HOOK_LOOKUP]   smfs_cow_lookup,
        [HOOK_LINK]     smfs_cow_link,
        [HOOK_UNLINK]   smfs_cow_unlink,
        [HOOK_SYMLINK]  smfs_cow_create,
        [HOOK_MKDIR]    smfs_cow_create,
        [HOOK_RMDIR]    smfs_cow_unlink, 
        [HOOK_MKNOD]    smfs_cow_create,
        [HOOK_RENAME]   smfs_cow_rename,
        [HOOK_SETATTR]  smfs_cow_setattr,
        [HOOK_WRITE]    smfs_cow_write,
};

int smfs_cow(struct inode *dir, struct dentry *dentry, void *new_dir, 
             void *new_dentry, int op)
{
        if (smfs_cow_funcs[op]) {
                return smfs_cow_funcs[op](dir, dentry, new_dir, new_dentry);
        }
        return 0;
}

