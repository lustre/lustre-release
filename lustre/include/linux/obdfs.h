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
#include <../obd/linux/obd_class.h>

/* file.c */
ssize_t obdfs_file_write(struct file *file, const char *buf, size_t count, loff_t *ppos);


/* rw.c */
struct page *obdfs_getpage(struct inode *inode, unsigned long offset, int create, int locked);
int obdfs_writepage(struct file *file, struct page *page);
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

struct obdfs_sb_info {
	struct obd_conn_info osi_conn_info;
	struct super_block *osi_super;
	struct obd_device *osi_obd;
	struct obd_ops *osi_ops;
};

void obdfs_sysctl_init(void);
void obdfs_sysctl_clean(void);

struct obdfs_inode_info;

extern struct file_operations obdfs_file_ops;
extern struct inode_operations obdfs_inode_ops;

static inline struct obd_ops *iops(struct inode *i)
{
	struct obdfs_sb_info *sbi = (struct obdfs_sb_info *) i->i_sb->u.generic_sbp;
	return sbi->osi_ops;
}

#define NOLOCK 0
#define LOCKED 1


#define OBDFS_SUPER_MAGIC 0x4711

#endif

