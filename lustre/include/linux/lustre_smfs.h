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
 *   smfs data structures.
 *   See also lustre_idl.h for wire formats of requests.
 *
 */

#ifndef __LUSTRE_SMFS_H
#define __LUSTRE_SMFS_H

struct snap_inode_info {
	int sn_flags;		/*the flags indicated inode type */
	int sn_gen; 	        /*the inode generation*/
        int sn_index;           /*the inode snap_index*/
        ino_t sn_root_ino;        /*the root ino of this snap*/
};
struct smfs_inode_info {
        struct inode *smi_inode;
        __u32  smi_flags;
	struct snap_inode_info sm_sninfo;
};

struct journal_operations {
        void *(*tr_start)(struct inode *, int op);
        void (*tr_commit)(void *handle);
};

struct sm_operations {
        /* operations on the file store */
        struct super_operations sm_sb_ops;
        struct inode_operations sm_dir_iops;
        struct inode_operations sm_file_iops;
        struct inode_operations sm_sym_iops;
        struct file_operations sm_dir_fops;
        struct file_operations sm_file_fops;
        struct file_operations sm_sym_fops;
        struct dentry_operations sm_dentry_ops;
        struct journal_operations sm_journal_ops;
};

/*smfs rec*/
typedef int (*smfs_pack_rec_func)(char *buffer, struct dentry *dentry,
                                  struct inode *dir, void *data1,
                                  void *data2, int op);
typedef enum {
        PACK_NORMAL = 0,
        PACK_OST = 1,
        PACK_MDS = 2,
        PACK_MAX = 3,
} pack_func_t;

struct mds_kml_pack_info {
        int mpi_bufcount;
        int mpi_size[4];
        int mpi_total_size;
};
typedef int (*smfs_hook_func)(struct inode *inode, void *dentry,
                             void *data1, void *data2, int op, void *handle);
struct smfs_hook_ops {
        struct list_head smh_list;
        char *           smh_name;
        smfs_hook_func   smh_post_op;
        smfs_hook_func   smh_pre_op;
};
struct smfs_super_info {
        struct super_block       *smsi_sb;
        struct vfsmount          *smsi_mnt;         /* mount the cache kern */
        struct fsfilt_operations *sm_cache_fsfilt;  /* fsfilt operations */
        struct fsfilt_operations *sm_fsfilt;        /* fsfilt operations */
        struct sm_operations     *sm_ops;           /* cache ops */
        struct lvfs_run_ctxt     *smsi_ctxt;
        struct llog_ctxt         *smsi_rec_log;     /* smfs kml llog */
        struct dentry            *smsi_logs_dir;
        struct dentry            *smsi_objects_dir;
        struct dentry            *smsi_delete_dir;  /* for delete inode dir */
        char                     *smsi_cache_ftype; /* cache file system type */
        char                     *smsi_ftype;       /* file system type */
	struct obd_export	 *smsi_exp;	    /* file system obd exp */
	struct snap_super_info	 *smsi_snap_info;   /* snap table cow */
        smfs_pack_rec_func   	 smsi_pack_rec[PACK_MAX]; /* sm_pack_rec type ops */
        __u32                    smsi_flags;        /* flags */
        __u32                    smsi_ops_check;
        struct list_head         smsi_hook_list;
        kmem_cache_t *           smsi_inode_cachep;  /*inode_cachep*/
};


#define SMFS_FILE_TYPE         "smfs"
#define SMFS_FILE_MAGIC        0x19760218

struct smfs_file_info {
        struct file        *c_file;
        int                 magic;
};

struct smfs_proc_args {
        struct super_block *sr_sb;
        int                 sr_count;
        int                 sr_flags;
        void               *sr_data;
};
struct fs_extent{
        __u32   e_block;        /* first logical block extent covers */
        __u32   e_start;        /* first physical block extents lives */
        __u32   e_num;          /* number of blocks covered by extent */
};

#define I2SMI(inode)  ((struct smfs_inode_info *) ((inode->u.generic_ip)))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define S2SMI(sb)   ((struct smfs_super_info *) ((sb->u.generic_sbp)))
#define S2CSB(sb)   (((struct smfs_super_info *)((sb->u.generic_sbp)))->smsi_sb)
#else
#define S2SMI(sb)   ((struct smfs_super_info *) (sb->s_fs_info))
#define S2CSB(sb)   (((struct smfs_super_info *) (sb->s_fs_info))->smsi_sb)
#endif

#define I2CI(inode) (((struct smfs_inode_info*) ((inode->u.generic_ip)))->smi_inode)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define I2CSB(inode) ((struct smfs_super_info *) ((inode->i_sb->u.generic_sbp)))
#else
#define I2CSB(inode) ((struct smfs_super_info *) (inode->i_sb->s_fs_info))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define I2FOPS(inode) (((struct smfs_super_info *) \
                        ((inode->i_sb->u.generic_sbp)))->sm_cache_fsfilt)
#else
#define I2FOPS(inode) (((struct smfs_super_info *) \
                        (inode->i_sb->s_fs_info))->sm_cache_fsfilt)
#endif

#define I2SNAPI(inode) (&(I2SMI(inode)->sm_sninfo))
#define I2SNAPCOPS(inode) ((S2SMI(inode->i_sb))->smsi_snap_info->snap_cache_fsfilt) 
#define I2SNAPOPS(inode) ((S2SMI(inode->i_sb))->smsi_snap_info->snap_fsfilt) 

#define S2SNAPI(sb) (S2SMI(sb)->smsi_snap_info)
#define F2SMFI(file) ((struct smfs_file_info *)((file->private_data)))
#define F2CF(file) (((struct smfs_file_info *) ((file->private_data)))->c_file)
#define SIZE2BLKS(size, inode) ((size + (I2CI(inode)->i_blksize)) >> (I2CI(inode)->i_blkbits))
#define OFF2BLKS(off, inode) (off >> (I2CI(inode)->i_blkbits))

#define SM_DO_REC               0x1
#define SM_INIT_REC             0x2
#define SM_CACHE_HOOK           0x4
#define SM_OVER_WRITE           0x8
#define SM_DIRTY_WRITE          0x10
#define SM_DO_COW         	0x20
#define SM_DO_COWED         	0x40

#define SMFS_DO_REC(smfs_info) (smfs_info->smsi_flags & SM_DO_REC)
#define SMFS_SET_REC(smfs_info) (smfs_info->smsi_flags |= SM_DO_REC)
#define SMFS_CLEAN_REC(smfs_info) (smfs_info->smsi_flags &= ~SM_DO_REC)

#define SMFS_INIT_REC(smfs_info) (smfs_info->smsi_flags & SM_INIT_REC)
#define SMFS_SET_INIT_REC(smfs_info) (smfs_info->smsi_flags |= SM_INIT_REC)
#define SMFS_CLEAN_INIT_REC(smfs_info) (smfs_info->smsi_flags &= ~SM_INIT_REC)

#define SMFS_SET_INODE_REC(inode) (I2SMI(inode)->smi_flags |= SM_DO_REC)
#define SMFS_DO_INODE_REC(inode) (I2SMI(inode)->smi_flags & SM_DO_REC)
#define SMFS_CLEAN_INODE_REC(inode) (I2SMI(inode)->smi_flags &= ~SM_DO_REC)

#define SMFS_CACHE_HOOK(smfs_info) (smfs_info->smsi_flags & SM_CACHE_HOOK)
#define SMFS_SET_CACHE_HOOK(smfs_info) (smfs_info->smsi_flags |= SM_CACHE_HOOK)
#define SMFS_CLEAN_CACHE_HOOK(smfs_info) (smfs_info->smsi_flags &= ~SM_CACHE_HOOK)

#define SMFS_INODE_CACHE_HOOK(inode) (I2SMI(inode)->smi_flags & SM_CACHE_HOOK)
#define SMFS_SET_INODE_CACHE_HOOK(inode) (I2SMI(inode)->smi_flags |= SM_CACHE_HOOK)
#define SMFS_CLEAN_INODE_CACHE_HOOK(inode) (I2SMI(inode)->smi_flags &= ~SM_CACHE_HOOK)

#define SMFS_INODE_OVER_WRITE(inode) (I2SMI(inode)->smi_flags & SM_OVER_WRITE)
#define SMFS_SET_INODE_OVER_WRITE(inode) (I2SMI(inode)->smi_flags |= SM_OVER_WRITE)
#define SMFS_CLEAN_INODE_OVER_WRITE(inode) (I2SMI(inode)->smi_flags &= ~SM_OVER_WRITE)

#define SMFS_INODE_DIRTY_WRITE(inode) (I2SMI(inode)->smi_flags & SM_DIRTY_WRITE)
#define SMFS_SET_INODE_DIRTY_WRITE(inode) (I2SMI(inode)->smi_flags |= SM_DIRTY_WRITE)
#define SMFS_CLEAN_INODE_DIRTY_WRITE(inode) (I2SMI(inode)->smi_flags &= ~SM_DIRTY_WRITE)

#define SMFS_DO_COW(smfs_info) (smfs_info->smsi_flags & SM_DO_COW)
#define SMFS_SET_COW(smfs_info) (smfs_info->smsi_flags |= SM_DO_COW)
#define SMFS_CLEAN_COW(smfs_info) (smfs_info->smsi_flags &= ~SM_DO_COW)

#define SMFS_SET_INODE_COW(inode) (I2SMI(inode)->smi_flags |= SM_DO_COW)
#define SMFS_DO_INODE_COW(inode) (I2SMI(inode)->smi_flags & SM_DO_COW)
#define SMFS_CLEAN_INODE_COW(inode) (I2SMI(inode)->smi_flags &= ~SM_DO_COW)

#define SMFS_SET_INODE_COWED(inode) (I2SMI(inode)->smi_flags |= SM_DO_COWED)
#define SMFS_DO_INODE_COWED(inode) (I2SMI(inode)->smi_flags & SM_DO_COWED)
#define SMFS_CLEAN_INODE_COWED(inode) (I2SMI(inode)->smi_flags &= ~SM_DO_COWED)


#define LVFS_SMFS_BACK_ATTR "lvfs_back_attr"


#define REC_COUNT_BIT       0
#define REC_COUNT_MASK      0x01 /*0001*/
#define REC_OP_BIT          1
#define REC_OP_MASK         0x06 /*0110*/
#define REC_WRITE_KML_BIT   3
#define REC_WRITE_KML_MASK  0x08 /*1000*/
#define REC_DEC_LINK_BIT    4
#define REC_DEC_LINK_MASK   0x10 /*10000* different with unlink*/
#define REC_GET_OID_BIT     5
#define REC_GET_OID_MASK    0x20 /*100000*/

#define REC_PACK_TYPE_BIT   6
#define REC_PACK_TYPE_MASK  0x1C0 /*111000000*/

#define SET_REC_COUNT_FLAGS(flag, count_flag) \
                (flag |= count_flag << REC_COUNT_BIT)
#define GET_REC_COUNT_FLAGS(flag) \
                ((flag & REC_COUNT_MASK) >> REC_COUNT_BIT)

#define SET_REC_OP_FLAGS(flag, op_flag) \
                (flag |= op_flag << REC_OP_BIT)
#define GET_REC_OP_FLAGS(flag) \
                ((flag & REC_OP_MASK) >> REC_OP_BIT)

#define SET_REC_WRITE_KML_FLAGS(flag, op_flag) \
                (flag |= op_flag << REC_OP_BIT)
#define GET_REC_WRITE_KML_FLAGS(flag) \
                ((flag & REC_WRITE_KML_MASK) >> REC_WRITE_KML_BIT)

#define SET_REC_DEC_LINK_FLAGS(flag, op_flag) \
                (flag |= op_flag << REC_DEC_LINK_BIT)
#define GET_REC_DEC_LINK_FLAGS(flag) \
                ((flag & REC_DEC_LINK_MASK) >> REC_DEC_LINK_BIT)

#define SET_REC_GET_ID_FLAGS(flag, op_flag) \
                (flag |= op_flag << REC_GET_OID_BIT)
#define GET_REC_GET_OID_FLAGS(flag) \
                ((flag & REC_GET_OID_MASK) >> REC_GET_OID_BIT)

#define SET_REC_PACK_TYPE_INDEX(flag, op_flag) \
                (flag |= op_flag << REC_PACK_TYPE_BIT)
#define GET_REC_PACK_TYPE_INDEX(flag) \
                ((flag & REC_PACK_TYPE_MASK) >> REC_PACK_TYPE_BIT)

#define SMFS_REC_ALL             0x1
#define SMFS_REC_BY_COUNT        0x0

#define SMFS_REINT_REC           0x1
#define SMFS_UNDO_REC            0x2

#define SMFS_WRITE_KML           0x1
#define SMFS_DEC_LINK            0x1
#define SMFS_GET_OID             0x1

#define SMFS_DO_REINT_REC(flag) \
         (GET_REC_OP_FLAGS(flag) == SMFS_REINT_REC)
#define SMFS_DO_UNDO_REC(flag) \
         (GET_REC_OP_FLAGS(flag) == SMFS_UNDO_REC)
#define SMFS_DO_REC_ALL(flag) \
        (GET_REC_COUNT_FLAGS(flag) == SMFS_REC_ALL)
#define SMFS_DO_REC_BY_COUNT(flag) \
        (GET_REC_COUNT_FLAGS(flag) == SMFS_REC_BY_COUNT)
#define SMFS_DO_WRITE_KML(flag) \
        (GET_REC_WRITE_KML_FLAGS(flag) == SMFS_WRITE_KML)
#define SMFS_DO_DEC_LINK(flag) \
        (GET_REC_DEC_LINK_FLAGS(flag) == SMFS_DEC_LINK)

#define SMFS_DO_GET_OID(flag) \
        (GET_REC_GET_OID_FLAGS(flag) == SMFS_GET_OID)

/*DIRTY flags of write ops*/
#define REINT_EXTENTS_FLAGS         "replay_flags"
#define SMFS_DIRTY_WRITE        0x01
#define SMFS_OVER_WRITE         0x02


static inline void duplicate_inode(struct inode *dst_inode,
                                   struct inode *src_inode)
{
        dst_inode->i_mode = src_inode->i_mode;
        dst_inode->i_uid = src_inode->i_uid;
        dst_inode->i_gid = src_inode->i_gid;
        dst_inode->i_nlink = src_inode->i_nlink;
        dst_inode->i_size = src_inode->i_size;
        dst_inode->i_atime = src_inode->i_atime;
        dst_inode->i_ctime = src_inode->i_ctime;
        dst_inode->i_mtime = src_inode->i_mtime;
        dst_inode->i_blksize = src_inode->i_blksize;
        dst_inode->i_version = src_inode->i_version;
        dst_inode->i_state = src_inode->i_state;
        dst_inode->i_generation = src_inode->i_generation;
        dst_inode->i_flags = src_inode->i_flags;

        /* This is to make creating special files working. */
        dst_inode->i_rdev = src_inode->i_rdev;
}

static inline void post_smfs_inode(struct inode *inode,
                                   struct inode *cache_inode)
{
        if (inode && cache_inode) {
                duplicate_inode(inode, cache_inode);
                /*Here we must release the cache_inode,
                 *Otherwise we will have no chance to
                 *do it
                 */
                cache_inode->i_state &=~I_LOCK;
                inode->i_blocks = cache_inode->i_blocks;
        }
}

static inline void pre_smfs_inode(struct inode *inode,
                                  struct inode *cache_inode)
{
        if (inode && cache_inode) {
                cache_inode->i_state = inode->i_state;
        //      duplicate_inode(cache_inode, inode);
        }
}

/* instantiate a file handle to the cache file */
static inline void duplicate_file(struct file *dst_file, struct file *src_file)
{
	if (dst_file && src_file) {
		dst_file->f_pos = src_file->f_pos;
		dst_file->f_mode = src_file->f_mode;
		dst_file->f_flags = src_file->f_flags;
		dst_file->f_owner  = src_file->f_owner;
		dst_file->f_vfsmnt = src_file->f_vfsmnt;

	#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
		dst_file->f_reada = src_file->f_reada;
		dst_file->f_ramax = src_file->f_ramax;
		dst_file->f_raend = src_file->f_raend;
		dst_file->f_ralen = src_file->f_ralen;
		dst_file->f_rawin = src_file->f_rawin;
	#else
		dst_file->f_ra = src_file->f_ra;
	#endif
	}
}

static inline void duplicate_sb(struct super_block *dst_sb,
                                struct super_block *src_sb)
{
        dst_sb->s_blocksize = src_sb->s_blocksize;
        dst_sb->s_magic = src_sb->s_magic;
        dst_sb->s_blocksize_bits = src_sb->s_blocksize_bits;
        dst_sb->s_maxbytes = src_sb->s_maxbytes;
        dst_sb->s_flags = src_sb->s_flags;
}

static inline void d_unalloc(struct dentry *dentry)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        list_del(&dentry->d_hash);
        INIT_LIST_HEAD(&dentry->d_hash);
#else
        hlist_del_init(&dentry->d_hash);
        dentry->d_flags |= DCACHE_UNHASHED;
#endif
        dput(dentry); /* this will free the dentry memory */
}

static inline int smfs_get_dentry_name_index(struct dentry *dentry,
                                             struct qstr  *str,
                                             int *index)
{
        char *name = (char *)dentry->d_name.name;
        unsigned long hash;
        unsigned char c;
        char *str_name;
        int len = 0, name_len = 0;

        name_len = dentry->d_name.len;
        if (!name_len)
                return 0;
        hash = init_name_hash();
        while (name_len--) {
                c = *(const unsigned char *)name++;
                if (c == ':' || c == '\0')
                        break;
                hash = partial_name_hash(c, hash);
                len ++;
        }
        str->hash = end_name_hash(hash);
        OBD_ALLOC(str_name, len + 1);
        memcpy(str_name, dentry->d_name.name, len);
        str->len = len; 
        str->name = str_name;
        if (index && c == ':') {
                *index = simple_strtoul(name, 0, 0);         
        }
        return 0;
}

static inline void smfs_free_dentry_name(struct qstr *str)
{
        char *name = (char*)str->name;
        OBD_FREE(name, str->len + 1);
}

static inline struct dentry *pre_smfs_dentry(struct dentry *parent_dentry,
                                             struct inode *cache_inode,
                                             struct dentry *dentry)
{
        struct dentry *cache_dentry = NULL;
        
        cache_dentry = d_alloc(parent_dentry, &dentry->d_name);
        if (!cache_dentry)
                RETURN(NULL);
        if (!parent_dentry)
                cache_dentry->d_parent = cache_dentry;
        if (cache_inode)
                d_add(cache_dentry, cache_inode);
        RETURN(cache_dentry);
}

static inline void post_smfs_dentry(struct dentry *cache_dentry)
{
        if (!cache_dentry)
                return;
        if (cache_dentry->d_inode)
                igrab(cache_dentry->d_inode);
        d_unalloc(cache_dentry);
}

static inline int lookup_by_path(char *path, int flags, struct nameidata *nd)
{
        struct dentry *dentry = NULL;
        int rc = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (path_init(path, flags, nd)) {
#else
        if (path_lookup(path, flags, nd)) {
#endif
                rc = path_walk(path, nd);
                if (rc)
                        RETURN(rc);
        } else {
                RETURN(-EINVAL);
        }

        dentry = nd->dentry;

        if (!dentry->d_inode || is_bad_inode(dentry->d_inode)) {
                path_release(nd);
                RETURN(-ENODEV);
        }
        RETURN(rc);
}

/*FIXME there should be more conditions in this check*/
static inline int smfs_do_rec(struct inode *inode)
{
        struct super_block *sb = inode->i_sb;
        struct smfs_super_info *smfs_info = S2SMI(sb);

        if (SMFS_DO_REC(smfs_info) && SMFS_INIT_REC(smfs_info) &&
            SMFS_DO_INODE_REC(inode))
                return 1;
        return 0;
}

static inline int smfs_cache_hook(struct inode *inode)
{
        struct smfs_super_info  *smfs_info = I2CSB(inode);

        if (SMFS_CACHE_HOOK(smfs_info) && SMFS_INIT_REC(smfs_info) &&
            SMFS_INODE_CACHE_HOOK(inode))
                return 1;
        else
                return 0;
}

static inline int smfs_do_cow(struct inode *inode)
{
        struct super_block *sb = inode->i_sb;
        struct smfs_super_info *smfs_info = S2SMI(sb);

        if (SMFS_DO_COW(smfs_info) && SMFS_DO_INODE_COW(inode))
                return 1;
        return 0;
}


/* XXX BUG 3188 -- must return to one set of opcodes */
#define SMFS_TRANS_OP(inode, op)                \
{                                               \
        if (smfs_do_rec(inode))                 \
                op = op | 0x10;                 \
        if (smfs_cache_hook(inode))             \
                op = op | 0x20;                 \
}

extern int smfs_start_rec(struct super_block *sb, struct vfsmount *mnt);
extern int smfs_stop_rec(struct super_block *sb);
extern int smfs_write_extents(struct inode *dir, struct dentry *dentry,
                              unsigned long from, unsigned long num);
extern int smfs_rec_setattr(struct inode *dir, struct dentry *dentry,
                            struct iattr *attr);
extern int smfs_rec_precreate(struct dentry *dentry, int *num, struct obdo *oa);
extern int smfs_rec_md(struct inode *inode, void * lmm, int lmm_size);
extern int smfs_rec_unpack(struct smfs_proc_args *args, char *record,
                           char **pbuf, int *opcode);
	

extern int smfs_post_setup(struct super_block *sb, struct vfsmount *mnt);
extern int smfs_post_cleanup(struct super_block *sb);
extern struct inode *smfs_get_inode (struct super_block *sb, ino_t hash,
                                     struct inode *dir, int index);

extern int is_smfs_sb(struct super_block *sb);
#endif /* _LUSTRE_SMFS_H */
