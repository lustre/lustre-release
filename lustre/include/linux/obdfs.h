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
struct page *obdfs_getpage(struct inode *inode, unsigned long offset);
int obdfs_writepage(struct file *file, struct page *page);
int obdfs_write_one_page(struct file *file, struct page *page, unsigned long offset, unsigned long bytes, const char * buf);

/* namei.c */
struct dentry *obdfs_lookup(struct inode * dir, struct dentry *dentry);

/* dir.c */
int obdfs_readdir(struct file * filp, void * dirent, filldir_t filldir);

struct obdfs_sb_info {
	struct obd_conn_info osi_conn_info;
	struct super_block *osi_super;
	struct obd_device *osi_obd;
	struct obd_ops *osi_ops;
};

void obdfs_sysctl_init(void);
void obdfs_sysctl_clean(void);

struct obdfs_inode_info;

extern struct file_operations obdfs_file_operations;
extern struct inode_perations obdfs_inode_operations;


#define OBDFS_SUPER_MAGIC 0x4711

#endif

