/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc. <info@clusterfs.com>
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
 * SNAP data structures.
 * See also lustre_idl.h for wire formats of requests.
 *
 */
/* maximum number of snapshots available for users */

#ifndef __LUSTRE_SNAP_H
#define __LUSTRE_SNAP_H

#define MAX_SNAPS       20
#define SNAP_ATTR       "@snap"
struct snap_ea{
        int   generation;
        ino_t prev_ino;
        ino_t next_ino;
        ino_t ino[MAX_SNAPS+1]; /* including current snapshot */
        ino_t parent_ino[MAX_SNAPS+1];
};
#define MAX_SNAP_DATA (sizeof(struct snap_ea))

/*
 * Check if the EA @name is Snap EA or not.
 * Snap EA includes the SNAP_ATTR, SNAP_NEW_INO_ATTR and DISK_SNAP_META_ATTR
 */

#define IS_SNAP_EA(name) ( (!strcmp((name), SNAP_ATTR)) || 		\
			   (!strcmp((name), DISK_SNAP_META_ATTR)))


/* file system features */
#define SNAP_FEATURE_COMPAT_SNAPFS              0x0010
#define SNAP_FEATURE_COMPAT_BLOCKCOW            0x0020

/* constants for snap_feature operations */
#define SNAP_CLEAR_FEATURE	0x0
#define SNAP_SET_FEATURE	0x1
#define SNAP_HAS_FEATURE	0x2

/* snap flags for inode, within 1 byte range, each occupy 1 bit */
#define SNAP_INO_MAGIC	0x88		/* magic for snap inode */
#define SNAP_COW_FLAG	0x01		/* snap redirected inode */
#define SNAP_DEL_FLAG	0x02		/* snap deleted inode */
#define SNAP_TABLE_FLAG	0x04		/* snap table inode */
#define SNAP_PRI_FLAG	0x08		/* primary inode */

/* no snapfs attributes for get_indirect_ino */
#define ENOSNAPATTR	320

/* constants used by iterator */
#define SNAP_ITERATE_ALL_INODE          0x0
#define SNAP_ITERATE_COWED_INODE        0x1

/* constants used by create_indirect */
#define SNAP_CREATE_IND_NORMAL		0x0
#define	SNAP_CREATE_IND_DEL_PRI		0x1

/* the data structure represent in the xfs_dinode.pad
	offset  0:	magic	(1 byte)
	offset	1:	flag	(1 byte)
	offset	2:	gen	(4 bytes)
	offset	6:	unused
 */
#define SIZEOF_MAGIC		1
#define SIZEOF_FLAG		1
#define SIZEOF_GENERATION	4

#define MAGIC_OFFSET		0
#define FLAG_OFFSET		1
#define GENERATION_OFFSET	2

#define SNAP_GET_DINODE_MAGIC(dinode)	\
		(((__u8*)(dinode)->di_pad)[MAGIC_OFFSET])
#define SNAP_SET_DINODE_MAGIC(dinode)	\
		((__u8*)(dinode)->di_pad)[MAGIC_OFFSET] = (SNAP_INO_MAGIC)
#define SNAP_GET_DINODE_FLAG(dinode)	\
		(((__u8*)(dinode)->di_pad)[FLAG_OFFSET])
#define SNAP_SET_DINODE_FLAG(dinode, flag)	\
		(((__u8*)(dinode)->di_pad)[FLAG_OFFSET] |= (flag))
#define SNAP_CLEAR_DINODE_FLAG(dinode, flag)	\
		(((__u8*)(dinode)->di_pad)[FLAG_OFFSET] &= ~(flag))
#define SNAP_GET_DINODE_GEN(dinode)	\
		(le32_to_cpu(*(__u32*)(&((__u8*)(dinode)->di_pad)[GENERATION_OFFSET])))
#define SNAP_SET_DINODE_GEN(dinode, gen)	\
		*(__u32*)(&((__u8*)(dinode)->di_pad)[GENERATION_OFFSET]) = cpu_to_le32(gen)
#define SNAP_VERSION(a,b,c)             \
                (((a & 0xFF) << 16) | ((b & 0xFF) << 8) | (c & 0xFF))
#define SNAP_VERSION_MAJOR(v)           \
                ((v >> 16) & 0xFF)
#define SNAP_VERSION_MINOR(v)           \
                ((v >> 8) & 0xFF)
#define SNAP_VERSION_REL(v)             \
                (v & 0xFF)
                                                                                                                                                                                                     
                                                                                                                                                                                                     
#define EXT3_EA_TRANS_BLOCKS            EXT3_DATA_TRANS_BLOCKS
#define EXT3_SETMETA_TRANS_BLOCKS       EXT3_DATA_TRANS_BLOCKS
#define EXT3_NEWINODE_TRANS_BLOCKS      10
#define SNAP_INSERTLIST_TRANS_BLOCKS    (2 * EXT3_EA_TRANS_BLOCKS + 1)
#define SNAP_DELETELIST_TRANS_BLOCKS    (2 * EXT3_EA_TRANS_BLOCKS + 2)
#define SNAP_COPYBLOCK_TRANS_BLOCKS     (EXT3_DATA_TRANS_BLOCKS)
#define SNAP_MIGRATEDATA_TRANS_BLOCKS   2
#define SNAP_SETIND_TRANS_BLOCKS        (SNAP_INSERTLIST_TRANS_BLOCKS + 1)
#define SNAP_ADDORPHAN_TRANS_BLOCKS     2
#define SNAP_REMOVEORPHAN_TRANS_BLOCKS  1
#define SNAP_RESTOREORPHAN_TRANS_BLOCKS (EXT3_EA_TRANS_BLOCKS + \
                                         SNAP_DELETELIST_TRANS_BLOCKS + \
                                         EXT3_NEWINODE_TRANS_BLOCKS + \
                                         2 * SNAP_MIGRATEDATA_TRANS_BLOCKS)
#define SNAP_BIGCOPY_TRANS_BLOCKS       (2 * EXT3_DATA_TRANS_BLOCKS)
#define SNAP_CREATEIND_TRANS_BLOCKS     (EXT3_NEWINODE_TRANS_BLOCKS + \
                                         SNAP_MIGRATEDATA_TRANS_BLOCKS + \
                                         SNAP_SETIND_TRANS_BLOCKS + \
                                         SNAP_BIGCOPY_TRANS_BLOCKS + 3)
#define SNAP_MIGRATEBLK_TRANS_BLOCKS    2
#define SNAP_DESTROY_TRANS_BLOCKS       (SNAP_DELETELIST_TRANS_BLOCKS + \
                                         EXT3_EA_TRANS_BLOCKS + 2)
#define SNAP_RESTORE_TRANS_BLOCKS       (EXT3_NEWINODE_TRANS_BLOCKS + \
                                         2 * SNAP_MIGRATEDATA_TRANS_BLOCKS + 1)
/*Snap Table*/
#define SNAP_MAX		32	
#define SNAP_MAX_TABLES 	32	
#define SNAP_MAX_NAMELEN	64

#define MAX_SNAPTABLE_COUNT  "MAXSnapCount"
#define SNAPTABLE_MAGIC	     0x19760218
#define SNAPTABLE_INFO       "snaptable"
#define SNAP_GENERATION      "snap_generation"
#define SNAP_COUNT           "snapcount"
#define SNAP_ROOT_INO        "snap_root_ino"

#define SNAP_LOOKUP     (REINT_MAX + 1)

struct snap {
        time_t          sn_time;
        unsigned int    sn_index;
        unsigned int    sn_gen;
        unsigned int    sn_flags;
        char    sn_name[SNAP_MAX_NAMELEN];
};

struct snap_table {
	unsigned int   	sntbl_magic;
	unsigned int   	sntbl_count;
	unsigned int   	sntbl_max_count;
	unsigned int	sntbl_generation;
	struct  snap  	sntbl_items[0];
};

#define DOT_NAME_MAX_LEN 32 
struct snap_dot_info {
        char    *dot_name;
        int     dot_name_len;
        int     dot_snap_enable; 
};

struct snap_info {
	struct list_head         sni_list;
        ino_t                    sni_root_ino;
        struct semaphore         sni_sema;
	spinlock_t               sni_lock;
        struct snap_table        *sni_table;
        struct dentry            *sni_cowed_dentry;
        struct snap_dot_info     *sni_dot_info;
};

struct snap_super_info {
        struct fsfilt_operations *snap_fsfilt;  
        struct fsfilt_operations *snap_cache_fsfilt; 
        struct list_head          snap_list;
        int                       snap_table_size;
};

extern int smfs_add_snap_item(struct super_block *sb, char *path_name, 
                              char *name);
extern int smfs_start_cow(struct super_block *sb);
extern int smfs_stop_cow(struct super_block *sb);

struct write_extents {
       size_t w_count;
       loff_t w_pos; 
};
int smfs_cow(struct inode *dir, struct dentry *dentry,
             void *data1, void *data2, int op);
int smfs_cow_write_pre(struct inode *inode, void *de, void *data1, void *data2);
struct inode* smfs_cow_get_ind(struct inode *inode, int index);


#define DOT_SNAP_NAME          ".snap"
#define DOT_SNAP_INDEX         0xffff
static inline int smfs_primary_inode(struct inode *inode)
{
        struct snap_inode_info *sn_info = &I2SMI(inode)->sm_sninfo;

        if (sn_info->sn_index == 0)
                return 1; 
        return 0; 
}
static inline int smfs_dotsnap_inode(struct inode *inode)
{
        struct snap_inode_info *sn_info = &I2SMI(inode)->sm_sninfo;

        if (sn_info->sn_index == DOT_SNAP_INDEX)
                return 1; 
        return 0; 
}
static inline int smfs_under_dotsnap_inode(struct inode *inode)
{
        struct snap_inode_info *sn_info = &I2SMI(inode)->sm_sninfo;
        
        if (sn_info->sn_index > 0 && sn_info->sn_index != DOT_SNAP_INDEX)
                return 1;
        return 0; 
}
#define SNAP_MINOR 242
#define SNAP_MAJOR 10

#endif /*_LUSTRE_SNAP_H*/
