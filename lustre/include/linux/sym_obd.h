#ifndef __LINUX_SYM_OBD_H
#define __LINUX_SYM_OBD_H

#include <linux/fs.h>
#include <linux/ext2_fs.h>

#define SYM_OBD_DEBUG

/*
 * Debug code
 */
#ifdef SYM_OBD_DEBUG
#	define obd_debug(f, a...)	{ \
					printk ("SYM OBD DEBUG (%s, %d): %s:", \
						__FILE__, __LINE__, __FUNCTION__); \
				  	printk (f, ## a); \
					}
#else
#	define obd_debug(f, a...)	/**/
#endif

/*
 * ioctl commands
 */
#define OBD_IOC_CREATE                 _IOR('f', 3, long)
#define OBD_IOC_SETUP                  _IOW('f', 4, long)
#define OBD_IOC_SYNC                   _IOR('f', 5, long)

/* balloc.c */
int obd_new_block (const struct inode * inode, unsigned long goal,
                   u32 * prealloc_count, u32 * prealloc_block, int * err);
void obd_free_blocks (const struct inode * inode, unsigned long block,
                      unsigned long count);
unsigned long obd_count_free_blocks (struct super_block * sb);
int ext2_group_sparse(int group);

/* fsync.c */
int obd_sync_file(struct file * file, struct dentry *dentry);

/* inode.c */
void obd_read_inode (struct inode * inode);
void obd_write_inode (struct inode * inode);
void obd_put_inode (struct inode * inode);
void obd_delete_inode (struct inode * inode);
void obd_discard_prealloc_blocks (struct inode * inode);
int obd_sync_inode (struct inode *inode);
struct buffer_head * obd_bread (struct inode * inode, int block, 
                                int create, int *err);
struct buffer_head * obd_getblk (struct inode * inode, long block,
                                 int create, int * err);

/* interface.c */
extern struct inode * obd_inode_new (int inode_hint, int * err);
extern void obd_inode_destroy (struct inode * inode);
extern unsigned long obd_count_free_inodes (struct super_block * sb);
extern void obd_check_inodes_bitmap (struct super_block * sb);
unsigned long obd_count_free_inodes (struct super_block * sb);

/* ioctl.c */
int obd_ioctl (struct inode * inode, struct file * filp, unsigned int cmd,
	       unsigned long arg);

/* super.c */
#define obd_error obd_warning
#define obd_panic obd_warning
extern void obd_warning (struct super_block *, const char *, const char *, ...)
	__attribute__ ((format (printf, 3, 4)));
int obd_remount (struct super_block * sb, int * flags, char * data);
struct super_block * obd_read_super (struct super_block * sb, void * data,
				     int silent);

/* truncate.c */
void obd_truncate (struct inode * inode);

/* operations */
/* dir.c */
extern struct inode_operations obd_dir_inode_operations;

/* file.c */
extern struct inode_operations obd_file_inode_operations;

#endif /* __LINUX_SYM_OBD_H */
