/* object based disk file system
 * 
 * This software is licensed under the GPL.  See the file COPYING in the
 * top directory of this distribution for details.
 * 
 * Copyright (C), 1999, Stelias Computing Inc
 *
 *
 */


#ifndef _OBDFS_H
#define OBDFS_H
#include <linux/obd_class.h>

/* super.c */
void obdfs_read_inode(struct inode *inode);


/* file.c */
ssize_t obdfs_file_write(struct file *file, const char *buf, size_t count, loff_t *ppos);


/* rw.c */
struct page *obdfs_getpage(struct inode *inode, unsigned long offset, int create, int locked);
int obdfs_write_one_page(struct file *file, struct page *page, unsigned long offset, unsigned long bytes, const char * buf);

/* namei.c */
struct dentry *obdfs_lookup(struct inode * dir, struct dentry *dentry);
int obdfs_create (struct inode * dir, struct dentry * dentry, int mode);
int obdfs_mkdir(struct inode *dir, struct dentry *dentry, int mode);
int obdfs_rmdir(struct inode *dir, struct dentry *dentry);
int obdfs_unlink(struct inode *dir, struct dentry *dentry);
int obdfs_mknod(struct inode *dir, struct dentry *dentry, int mode, int rdev);
int obdfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname);
int obdfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry);
int obdfs_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry);
/* dir.c */
int obdfs_readdir(struct file * filp, void * dirent, filldir_t filldir);
int obdfs_check_dir_entry (const char * function, struct inode * dir,
			  struct ext2_dir_entry_2 * de,
			  struct page * page,
			   unsigned long offset);
/* symlink.c */
int obdfs_readlink (struct dentry *, char *, int);
struct dentry *obdfs_follow_link(struct dentry *, struct dentry *, unsigned int); 

struct obdfs_sb_info {
	struct obd_conn osi_conn;
	struct super_block *osi_super;
	struct obd_device *osi_obd;
	struct obd_ops *osi_ops;     
	ino_t           osi_rootino; /* which root inode */
	int             osi_minor;   /* minor of /dev/obdX */
};

void obdfs_sysctl_init(void);
void obdfs_sysctl_clean(void);

struct obdfs_inode_info;

extern struct file_operations obdfs_file_ops;
extern struct inode_operations obdfs_inode_ops;
extern struct inode_operations obdfs_symlink_inode_operations;

static inline struct obd_ops *iops(struct inode *i)
{
	struct obdfs_sb_info *sbi = (struct obdfs_sb_info *) &i->i_sb->u.generic_sbp;
	return sbi->osi_ops;
}

static inline struct obd_conn *iid(struct inode *i)
{
	struct obdfs_sb_info *sbi = (struct obdfs_sb_info *) &i->i_sb->u.generic_sbp;
	return &sbi->osi_conn;
}

#define NOLOCK 0
#define LOCKED 1

#ifdef OPS
#warning "*** WARNING redefining OPS"
#else
#define OPS(sb,op) ((struct obdfs_sb_info *)(& ## sb ## ->u.generic_sbp))->osi_ops->o_ ## op
#define IOPS(inode,op) ((struct obdfs_sb_info *)(& ## inode->i_sb ## ->u.generic_sbp))->osi_ops->o_ ## op
#endif

#ifdef ID
#warning "*** WARNING redefining ID"
#else
#define ID(sb) (&((struct obdfs_sb_info *)( & ## sb ## ->u.generic_sbp))->osi_conn)
#define IID(inode) (&((struct obdfs_sb_info *)( & ## inode->i_sb ## ->u.generic_sbp))->osi_conn)
#endif

#define OBDFS_SUPER_MAGIC 0x4711

#endif

