#ifndef __LINUX_SMFS_H
#define __LINUX_SMFS_H

struct smfs_inode_info {
	struct inode *smi_inode;
};

struct smfs_super_info {
	struct super_block *smsi_sb;
        struct vfsmnt *smsi_mnt;      /* mount the cache kere with kern_do_mount (like MDS) */
};

#define I2SMI(inode)  ((struct smfs_inode_info *) (&(inode->u.generic_ip)))
#define S2SMI(sb)   ((struct smfs_super_info *) (&(sb->u.generic_sbp)))

#include "smfs_support.h"
struct option {
	char *opt;
	char *value;
	struct list_head list;
};
/*options.c*/
extern int get_opt(struct option **option, char **pos);
extern void cleanup_option(void);
extern int init_option(char *data);
/*sysctl.c*/
extern int sm_debug_level;
extern int sm_inodes;
extern long sm_kmemory;
extern int sm_stack;
#endif /* __LINUX_SNAPFS_H */
