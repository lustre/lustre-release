#ifndef __LINUX_SMFS_H
#define __LINUX_SMFS_H

struct smfs_inode_info {
	struct inode *smi_inode;
};

struct smfs_super_info {
	struct super_block *smsi_sb;
        struct vfsmount *smsi_mnt;      /* mount the cache kere with kern_do_mount (like MDS) */
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

#include "smfs_support.h"
struct sm_ops {
        /* operations on the file store */
        struct super_operations sm_sb_ops;
                                                                                                                                                                                                     
        struct inode_operations sm_dir_iops;
        struct inode_operations sm_file_iops;
        struct inode_operations sm_sym_iops;
                                                                                                                                                                                                     
        struct file_operations sm_dir_fops;
        struct file_operations sm_file_fops;
        struct file_operations sm_sym_fops;
                                                                                                                                                                                                     
        struct address_space_operations sm_file_aops;
        struct dentry_operations sm_dentry_ops;
};

struct option {
	char *opt;
	char *value;
	struct list_head list;
};
/*options.c*/
extern int get_opt(struct option **option, char **pos);
extern void cleanup_option(void);
extern int init_option(char *data);
/*cache.c*/
void sm_setup_inode_ops(struct inode *cache_inode, struct inode *inode);
void sm_set_sb_ops(struct super_block *cache_sb, struct super_block *sb);
void init_smfs_cache(void);
void cleanup_smfs_cache(void);

/*sysctl.c*/
extern int sm_debug_level;
extern int sm_inodes;
extern long sm_kmemory;
extern int sm_stack;
#endif /* __LINUX_SNAPFS_H */
