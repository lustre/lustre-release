#ifndef __LINUX_SMFS_H
#define __LINUX_SMFS_H

struct smfs_inode_info {
	struct inode *smi_inode;
};

struct smfs_super_info {
	struct super_block *smsi_sb;
        struct vfsmount *smsi_mnt;      /* mount the cache kern with kern_do_mount (like MDS) */
	__u32 flags;			/* flags*/
	struct llog_ctxt *kml_llog;	/*smfs kml llog*/ 
	int ops_check;
};

#define I2SMI(inode)  ((struct smfs_inode_info *) (&(inode->u.generic_ip)))
#define S2SMI(sb)   ((struct smfs_super_info *) (&(sb->u.generic_sbp)))
#define S2CSB(sb)   (((struct smfs_super_info *) (&(sb->u.generic_sbp)))->smsi_sb) 
#define I2CI(inode) (((struct smfs_inode_info*) (&(inode->u.generic_ip)))->smi_inode)

#define SB_OPS_CHECK 		0x1
#define INODE_OPS_CHECK 	0x2 
#define FILE_OPS_CHECK 		0x4 
#define DENTRY_OPS_CHECK 	0x8 
#define DEV_OPS_CHECK 		0x10 
#define SYMLINK_OPS_CHECK 	0x20 
#define DIR_OPS_CHECK 		0x40 

#define SM_DO_KML		0x1
 
#include "smfs_support.h"

struct journal_operations {
        void *(*tr_start)(struct inode *, int op);
        void (*tr_commit)(void *handle);
};

struct sm_ops {
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
struct option {
	char *opt;
	char *value;
	struct list_head list;
};

extern int init_smfs_proc_sys(void);
/*options.c*/
extern int get_opt(struct option **option, char **pos);
extern void cleanup_option(void);
extern int init_option(char *data);
/*cache.c*/
void sm_set_inode_ops(struct inode *cache_inode, struct inode *inode);
void sm_set_sb_ops(struct super_block *cache_sb, struct super_block *sb);
void init_smfs_cache(void);
void cleanup_smfs_cache(void);
void setup_sm_journal_ops(char * cache_type);
/*super.c*/
extern int init_smfs(void);
extern int cleanup_smfs(void);
extern void smfs_put_super(struct super_block *sb);
extern void duplicate_sb(struct super_block *csb, struct super_block *sb);
/*sysctl.c*/
extern int sm_debug_level;
extern int sm_inodes;
extern long sm_kmemory;
extern int sm_stack;
/*dir.c*/
extern struct inode_operations smfs_dir_iops; 
extern struct file_operations smfs_dir_fops; 

extern void d_unalloc(struct dentry *dentry);
/*inode.c*/
extern void duplicate_inode(struct inode *cache_inode, struct inode *inode);
/*file.c*/
extern void smfs_prepare_cachefile(struct inode *inode,
			           struct file *file, 
			           struct inode *cache_inode,
			    	   struct file *cache_file,
			    	   struct dentry *cache_dentry);
extern int smfs_ioctl(struct inode * inode, struct file * filp,  unsigned int cmd,
                      unsigned long arg);
extern int smfs_fsync(struct file * file, struct dentry *dentry, int datasync);
extern int smfs_setattr(struct dentry *dentry, struct iattr *attr); 
extern int smfs_setxattr(struct dentry *dentry, const char *name,
              	         const void *value, size_t size, int flags);
extern int smfs_getxattr(struct dentry *dentry, const char *name,
              	         void *buffer, size_t size);
extern ssize_t smfs_listxattr(struct dentry *dentry, char *buffer, size_t size);
extern int smfs_removexattr(struct dentry *dentry, const char *name);
extern void smfs_update_file(struct file *file, struct file *cache_file);
/*journal.c */
extern void *smfs_trans_start(struct inode *inode, int op);
extern void smfs_trans_commit(void *handle);
extern int smfs_journal_mkdir(struct dentry *dentry,
                       struct smfs_version *tgt_dir_ver,
                       struct smfs_version *new_dir_ver, 
		       int mode);
/*journal_ext3.c*/
extern struct journal_operations smfs_ext3_journal_ops;
/*kml.c*/
extern int smfs_kml_init(struct super_block *sb);
extern int smfs_do_kml(struct inode *dir);
extern void smfs_getversion(struct smfs_version * smfs_version, struct inode * inode); 
extern int post_kml_mkdir(struct inode *dir, struct dentry *dentry);
/*smfs_llog.c*/
extern int smfs_llog_setup(struct llog_ctxt **ctxt);
#endif /* __LINUX_SMFS_H */
