/* object based disk file system
 * 
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 * 
 * Copyright (C), 1999, Stelias Computing Inc
 *
 *
 */


#ifndef _INOFS_H
#define INOFS_H
#include <linux/obd_class.h>

#include <linux/obdo.h>

/* super.c */
void inofs_read_inode(struct inode *inode);


/* file.c */
ssize_t inofs_file_write(struct file *file, const char *buf, size_t count, loff_t *ppos);


/* rw.c */
struct page *inofs_getpage(struct inode *inode, unsigned long offset, int create, int locked);
int inofs_writepage(struct file *file, struct page *page);
int inofs_write_one_page(struct file *file, struct page *page, unsigned long offset, unsigned long bytes, const char * buf);

/* namei.c */
struct dentry *inofs_lookup(struct inode * dir, struct dentry *dentry);
int inofs_create (struct inode * dir, struct dentry * dentry, int mode);
int inofs_mkdir(struct inode *dir, struct dentry *dentry, int mode);
int inofs_rmdir(struct inode *dir, struct dentry *dentry);
int inofs_unlink(struct inode *dir, struct dentry *dentry);
int inofs_mknod(struct inode *dir, struct dentry *dentry, int mode, int rdev);
int inofs_symlink(struct inode *dir, struct dentry *dentry, const char *symname);
int inofs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry);
int inofs_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry);

/* dir.c */
int inofs_readdir(struct file * filp, void * dirent, filldir_t filldir);

struct inofs_sb_info {
        struct list_head osi_list;      /* list of supers */
        struct obd_conn osi_conn;
        struct super_block *osi_super;
        struct obd_device *osi_obd;
        struct obd_ops *osi_ops;
        struct list_head         osi_inodes;    /* list of dirty inodes */
        unsigned long            osi_cache_count;
        struct semaphore         osi_list_mutex;
};

void inofs_sysctl_init(void);
void inofs_sysctl_clean(void);

struct inofs_inode_info;

extern struct file_operations inofs_file_ops;
extern struct inode_operations inofs_inode_ops;

static inline struct obd_ops *iops(struct inode *i)
{
        struct inofs_sb_info *sbi = (struct inofs_sb_info *) i->i_sb->u.generic_sbp;
        return sbi->osi_ops;
}

#define NOLOCK 0
#define LOCKED 1


#define INOFS_SUPER_MAGIC 0x4711

#endif

