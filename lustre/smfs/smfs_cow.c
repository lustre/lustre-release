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
#define SNAPTABLE_SIZE(size) (sizeof(struct snap_table) + size * sizeof(struct snap)) 
static int smfs_init_snaptabe(struct super_block *sb)
{
        struct snap_info         *snap_info = S2SNAPI(sb);	
        struct snap_table        *snap_table = NULL;       
	struct fsfilt_operations *snapops = snap_info->snap_fsfilt;
        int                      rc = 0, size, table_size, vallen;
 
        ENTRY;

        init_MUTEX(&snap_info->sntbl_sema);
        /*Initialized table */
        /*get the maxsize of snaptable*/
        vallen = sizeof(int);
        rc = snapops->fs_get_snap_info(sb, NULL, MAX_SNAPTABLE_COUNT,
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
        /*get snaptable info*/

        rc = snapops->fs_get_snap_info(sb, NULL, SNAPTABLE_INFO, 
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

int smfs_cow_init(struct super_block *sb)
{
        struct smfs_super_info *smfs_info = S2SMI(sb);
        struct inode *inode = sb->s_root->d_inode;
        int rc = 0;

        SMFS_SET_COW(smfs_info);
      
        OBD_ALLOC(smfs_info->smsi_snap_info, sizeof(struct snap_info));
     
        if (!smfs_info->smsi_snap_info) 
                RETURN(-ENOMEM);
        
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
        
        RETURN(rc);
}

int smfs_cow_cleanup(struct super_block *sb)
{
        struct smfs_super_info *smfs_info = S2SMI(sb);
        struct snap_info       *snap_info = S2SNAPI(sb);	
        struct snap_table      *snap_table = snap_info->sntbl;	
        int rc = 0, table_size;
        ENTRY;

        SMFS_CLEAN_COW(smfs_info);
       
        if (snap_info->snap_fsfilt) 
                fsfilt_put_ops(snap_info->snap_fsfilt);
        if (snap_info->snap_cache_fsfilt)
                fsfilt_put_ops(snap_info->snap_cache_fsfilt);

        if (snap_table) {
                table_size =  SNAPTABLE_SIZE(snap_table->sntbl_max_count);
                OBD_FREE(snap_info->sntbl, table_size);
        }
        if (snap_info) 
               OBD_FREE(snap_info, sizeof(*snap_info)); 
        
        RETURN(rc);
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

                rc = snapops->fs_get_snap_info(NULL, inode, SNAP_GENERATION,
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
        
        rc = snapops->fs_set_snap_info(sb, NULL, SNAPTABLE_INFO, 
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
	if(!ind)
		RETURN(-EINVAL);

        I2SMI(ind)->sm_sninfo.sn_flags = 0;
        I2SMI(ind)->sm_sninfo.sn_gen = snap.sn_gen;
        
        iput(ind);
        RETURN(0);
}

int smfs_cow_create(struct inode *dir, struct dentry *dentry)
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

int smfs_cow_setattr(struct inode *dir, struct dentry *dentry)
{
        int rc = 0;
        ENTRY;
        
        RETURN(rc);
}

int smfs_cow_link(struct inode *dir, struct dentry *dentry)
{
        int rc = 0;
        ENTRY;
        
        RETURN(rc);
}

int smfs_cow_unlink(struct inode *dir, struct dentry *dentry)
{
        int rc = 0;
        ENTRY;
        
        RETURN(rc);
}

int smfs_cow_rename(struct inode *dir, struct dentry *dentry)
{
        int rc = 0;
        ENTRY;
        
        RETURN(rc);
}

int smfs_cow_write(struct inode *dir, struct dentry *dentry)
{
        int rc = 0;
        ENTRY;
        
        RETURN(rc);
}

typedef int (*cow_funcs)(struct inode *dir, struct dentry *dentry);

static cow_funcs smfs_cow_funcs[REINT_MAX + 1] = {
        [REINT_SETATTR] smfs_cow_setattr,
        [REINT_CREATE]  smfs_cow_create,
        [REINT_LINK]    smfs_cow_link,
        [REINT_UNLINK]  smfs_cow_unlink,
        [REINT_RENAME]  smfs_cow_rename,
        [REINT_WRITE]   smfs_cow_write,
};

int smfs_cow(struct inode *dir, struct dentry *dentry, int op)
{
        return smfs_cow_funcs[op](dir, dentry);
}

