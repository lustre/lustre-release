#ifndef __LUSTRE_SMFS_H
#define __LUSTRE_SMFS_H

struct smfs_inode_info {
	struct inode *smi_inode;
	__u32  smi_flags;
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

struct smfs_super_info {
	struct super_block 	 *smsi_sb;
        struct vfsmount 	 *smsi_mnt;         /* mount the cache kern with
						     * kern_do_mount (like MDS) */
	struct fsfilt_operations *sm_cache_fsfilt;  /* fsfilt operations */
	struct fsfilt_operations *sm_fsfilt;	    /* fsfilt operations */
	struct sm_operations     *sm_ops;           /* cache ops for set cache
						     * inode ops */

	struct lvfs_run_ctxt	 *smsi_ctxt;	
	struct llog_ctxt	 *smsi_rec_log;	    /* smfs kml llog */ 
	struct dentry 		 *smsi_logs_dir;
	struct dentry		 *smsi_objects_dir;
	struct dentry		 *smsi_delete_dir;  /* for delete inode dir */
	char   			 *cache_fs_type;    /* cache file system type */
	char   			 *fs_type;	    /* file system type */
	__u32 			 flags;		    /* flags */
	__u32 			 ops_check;
};

#define SMFS_FILE_TYPE "smfs"
#define SMFS_FILE_MAGIC	0x19760218

struct smfs_file_info {
	struct file	*c_file;
	int 		magic;
};

struct smfs_record_extents {
	size_t	sre_count;
	loff_t  sre_off; 
};

#define I2SMI(inode)  ((struct smfs_inode_info *) (&(inode->u.generic_ip)))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define S2SMI(sb)   ((struct smfs_super_info *) (&(sb->u.generic_sbp)))
#define S2CSB(sb)   (((struct smfs_super_info *) (&(sb->u.generic_sbp)))->smsi_sb)
#else
#define S2SMI(sb)   ((struct smfs_super_info *) (sb->s_fs_info))
#define S2CSB(sb)   (((struct smfs_super_info *) (sb->s_fs_info))->smsi_sb)
#endif

#define I2CI(inode) (((struct smfs_inode_info*) (&(inode->u.generic_ip)))->smi_inode)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define I2CSB(inode) ((struct smfs_super_info *) (&(inode->i_sb->u.generic_sbp)))
#else
#define I2CSB(inode) ((struct smfs_super_info *) (inode->i_sb->s_fs_info))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define I2FOPS(inode) (((struct smfs_super_info *) \
			(&(inode->i_sb->u.generic_sbp)))->sm_cache_fsfilt)
#else
#define I2FOPS(inode) (((struct smfs_super_info *) \
			(inode->i_sb->s_fs_info))->sm_cache_fsfilt)
#endif

#define F2SMFI(file) ((struct smfs_file_info *)((file->private_data)))
#define F2CF(file) (((struct smfs_file_info *) ((file->private_data)))->c_file)

#define SM_DO_REC		0x1
#define SM_INIT_REC		0x2
#define SM_CACHE_HOOK		0x4

#define SMFS_DO_REC(smfs_info) (smfs_info->flags & SM_DO_REC)
#define SMFS_SET_REC(smfs_info) (smfs_info->flags |= SM_DO_REC)
#define SMFS_CLEAN_REC(smfs_info) (smfs_info->flags &= ~SM_DO_REC)

#define SMFS_INIT_REC(smfs_info) (smfs_info->flags & SM_INIT_REC)
#define SMFS_SET_INIT_REC(smfs_info) (smfs_info->flags |= SM_INIT_REC)
#define SMFS_CLEAN_INIT_REC(smfs_info) (smfs_info->flags &= ~SM_INIT_REC)

#define SMFS_SET_INODE_REC(inode) (I2SMI(inode)->smi_flags |= SM_DO_REC)
#define SMFS_DO_INODE_REC(inode) (I2SMI(inode)->smi_flags & SM_DO_REC)
#define SMFS_CLEAN_INODE_REC(inode) (I2SMI(inode)->smi_flags &= ~SM_DO_REC)

#define SMFS_CACHE_HOOK(smfs_info) (smfs_info->flags & SM_CACHE_HOOK)
#define SMFS_SET_CACHE_HOOK(smfs_info) (smfs_info->flags |= SM_CACHE_HOOK)
#define SMFS_CLEAN_CACHE_HOOK(smfs_info) (smfs_info->flags &= ~SM_CACHE_HOOK)

#define SMFS_INODE_CACHE_HOOK(inode) (I2SMI(inode)->smi_flags & SM_CACHE_HOOK)
#define SMFS_SET_INODE_CACHE_HOOK(inode) (I2SMI(inode)->smi_flags |= SM_CACHE_HOOK)
#define SMFS_CLEAN_INODE_CACHE_HOOK(inode) (I2SMI(inode)->smi_flags &= ~SM_CACHE_HOOK)

#define LVFS_SMFS_BACK_ATTR "lvfs_back_attr"


#define REC_COUNT_BIT 0
#define REC_COUNT_MASK 0x01 /*0001*/
#define REC_OP_BIT  1
#define REC_OP_MASK 0x06 /*0110*/
#define REC_WRITE_KML_BIT 3
#define REC_WRITE_KML_MASK 0x08 /*1000*/
#define REC_DEC_LINK_BIT    4
#define REC_DEC_LINK_MASK   0x10 /*10000* different with unlink*/


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

#define SMFS_REC_ALL		0x1
#define SMFS_REC_BY_COUNT	0x0

#define SMFS_REINT_REC		0x1
#define SMFS_UNDO_REC		0x2

#define SMFS_WRITE_KML		0x1

#define SMFS_DEC_LINK		0x1

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
	if (inode && cache_inode)
		duplicate_inode(cache_inode, inode);
}

/* instantiate a file handle to the cache file */
static inline void duplicate_file(struct file *dst_file,
			    	  struct file *src_file) 
{
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

static inline void duplicate_sb(struct super_block *dst_sb, 
			 	struct super_block *src_sb)
{
	dst_sb->s_blocksize = src_sb->s_blocksize;
	dst_sb->s_magic = src_sb->s_magic;
	dst_sb->s_blocksize_bits = src_sb->s_blocksize_bits;
	dst_sb->s_maxbytes = src_sb->s_maxbytes;
}

static inline void d_unalloc(struct dentry *dentry)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
	list_del(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_hash);
#else
	hlist_del_init(&dentry->d_hash);
#endif
	dput(dentry); /* this will free the dentry memory */
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
#endif /* _LUSTRE_SMFS_H */
