#ifndef __LINUX_SYM_OBD_H
#define __LINUX_SYM_OBD_H

#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/malloc.h>
#include <linux/vmalloc.h>

#define SYM_OBD_DEBUG

/*
 * Debug code
 */
/* global variables */
extern int obd_debug_level;
extern int obd_print_entry;

/* debugging masks */
#define D_PSDEV       1 /* debug information from psdev.c */
#define D_UNUSED1     2
#define D_UNUSED2     4
#define D_UNUSED3     8
#define D_UNUSED4    16
#define D_WARNING    32 /* misc warnings */
#define D_EXT2       64 /* anything from ext2_debug */
#define D_MALLOC    128 /* print malloc, free information */
#define D_CACHE     256 /* cache-related items */
#define D_INFO      512 /* general information, especially from interface.c */
#define D_IOCTL    1024 /* ioctl related information */
#define D_BLOCKS   2048 /* ext2 block allocation */
 
#ifdef SYM_OBD_DEBUG
#define CDEBUG(mask, format, a...)					\
        do {								\
	if (obd_debug_level & mask) {					\
		printk("(%s,l. %d): ",  __FUNCTION__, __LINE__);	\
		printk(format, ## a); }					\
	} while (0)

#define ENTRY								      \
        if (obd_print_entry)						      \
                printk("Process %d entered %s\n", current->pid, __FUNCTION__)

#define EXIT								      \
        if (obd_print_entry)						      \
                printk("Process %d leaving %s\n", current->pid, __FUNCTION__)

#else /* SYM_OBD_DEBUG */

#       define CDEBUG ;
#       define ENTRY ;
#       define EXIT ;

#endif /* SYM_OBD_DEBUG */



#define OBD_ALLOC(ptr, cast, size)					\
do {									\
	if (size <= 4096) {						\
		ptr = (cast)kmalloc((unsigned long) size, GFP_KERNEL);	\
                CDEBUG(D_MALLOC, "kmalloced: %x at %x.\n",		\
		       (int) size, (int) ptr);				\
	} else {							\
		ptr = (cast)vmalloc((unsigned long) size);		\
		CDEBUG(D_MALLOC, "vmalloced: %x at %x.\n",		\
		       (int) size, (int) ptr);				\
	}								\
	if (ptr == 0) {							\
		printk("kernel malloc returns 0 at %s:%d\n",		\
		       __FILE__, __LINE__);				\
	}								\
	memset(ptr, 0, size);						\
} while (0)

#define OBD_FREE(ptr,size)				\
do {							\
	if (size <= 4096) {				\
		kfree_s((ptr), (size));			\
		CDEBUG(D_MALLOC, "kfreed: %x at %x.\n",	\
		       (int) size, (int) ptr);		\
	} else {					\
		vfree((ptr));				\
		CDEBUG(D_MALLOC, "vfreed: %x at %x.\n",	\
		       (int) size, (int) ptr);		\
	}						\
} while (0)


#define MAX_DEVICES 128
struct obd_conn_info {
	unsigned int conn_id;
	unsigned long conn_ino;
	unsigned long conn_blocksize;
	unsigned char conn_blocksize_bits;
};

struct obd_device {
	int refcnt;
	struct super_block * sb;
	unsigned int last_id;
	unsigned long prealloc_quota;
	struct list_head clients;
};

struct obd_client {
	struct list_head cli_chain;
	kdev_t minor;
	unsigned int cli_id;
	unsigned long cli_prealloc_quota;
	struct list_head cli_prealloc_inodes;
};

struct obd_prealloc_inode {
	struct list_head obd_prealloc_chain;
	unsigned long inode;
};

/*
 * ioctl commands
 */
struct oic_prealloc_s {
	unsigned long cli_id;
	unsigned long alloc; /* user sets it to the number of inodes requesting
		     * to be preallocated.  kernel sets it to the actual number
		     * of succesfully preallocated inodes */
	long inodes[32]; /* actual inode numbers */
};
struct oic_attr_s {
	unsigned int conn_id;
	unsigned long inode;

	struct iattr iattr;
};
struct oic_rw_s {
	unsigned int conn_id;
	unsigned long inode;
	char * buf;
	unsigned long count;
	loff_t offset;
};

#define OBD_IOC_CREATE                 _IOR ('f',  3, long)
#define OBD_IOC_SETUP                  _IOW ('f',  4, long)
#define OBD_IOC_SYNC                   _IOR ('f',  5, long)
#define OBD_IOC_DESTROY                _IOW ('f',  6, long)
#define OBD_IOC_PREALLOCATE            _IOWR('f',  7, long)
#define OBD_IOC_DEC_USE_COUNT          _IO  ('f',  8      )
#define OBD_IOC_SETATTR                _IOW ('f',  9, long)
#define OBD_IOC_GETATTR                _IOR ('f', 10, long)
#define OBD_IOC_READ                   _IOWR('f', 11, long)
#define OBD_IOC_WRITE                  _IOWR('f', 12, long)
#define OBD_IOC_CONNECT                _IOR ('f', 13, long)
#define OBD_IOC_DISCONNECT             _IOW ('f', 14, long)
#define OBD_IOC_STATFS                 _IOWR('f', 15, long)
#define OBD_IOC_DEC_FS_USE_COUNT       _IO  ('f', 16      )

/* balloc.c */
int ext2_new_block (const struct inode * inode, unsigned long goal,
                   u32 * prealloc_count, u32 * prealloc_block, int * err);
void ext2_free_blocks (const struct inode * inode, unsigned long block,
                      unsigned long count);
unsigned long ext2_count_free_blocks (struct super_block * sb);
int ext2_group_sparse(int group);
struct ext2_group_desc * ext2_get_group_desc(struct super_block * sb,
					     unsigned int block_group,
					     struct buffer_head ** bh);


/* bitmap.c */
unsigned long ext2_count_free(struct buffer_head * map, unsigned int numchars);

/* fsync.c */
extern int obd_sync_file(struct file * file, struct dentry *dentry);

/* ialloc.c */
extern void ext2_free_inode (struct inode * inode);
extern struct inode * ext2_new_inode (const struct inode * dir, int mode,
				     int * err);
extern unsigned long ext2_count_free_inodes (struct super_block * sb);
extern void ext2_check_inodes_bitmap (struct super_block * sb);
extern int load_inode_bitmap (struct super_block * sb,
			      unsigned int block_group);

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
extern int obd_create (struct super_block * sb, int inode_hint, int * err);
extern void obd_unlink (struct inode * inode);
extern struct obd_client * obd_client(int cli_id);
extern void obd_cleanup_client (struct obd_device * obddev,
				struct obd_client * cli);
void obd_cleanup_device(int dev);
long obd_preallocate_inodes(unsigned int conn_id,
			    int req, long inodes[32], int * err);
long obd_preallocate_quota(struct super_block * sb, struct obd_client * cli,
			   unsigned long req, int * err);
int obd_connect (int minor, struct obd_conn_info * conninfo);
int obd_disconnect (unsigned int conn_id);
int obd_setattr(unsigned int conn_id, unsigned long ino, struct iattr * iattr);
int obd_getattr(unsigned int conn_id, unsigned long ino, struct iattr * iattr);
int obd_destroy(unsigned int conn_id, unsigned long ino);
int obd_statfs(unsigned int conn_id, struct statfs * statfs);
unsigned long obd_read(unsigned int conn_id, unsigned long ino, char * buf,
		       unsigned long count, loff_t offset, int * err);
unsigned long obd_write (unsigned int conn_id, unsigned long ino, char * buf,
			 unsigned long count, loff_t offset, int * err);

/* ioctl.c */
int obd_ioctl (struct inode * inode, struct file * filp, unsigned int cmd,
	       unsigned long arg);

/* super.c */
#define ext2_warning obd_warning
#define ext2_error obd_warning
#define ext2_panic obd_warning

#ifdef EXT2FS_DEBUG
#  undef ext2_debug
#  define ext2_debug(format, a...) CDEBUG(D_EXT2, format, ## a)
#endif

#define obd_error obd_warning
#define obd_panic obd_warning
#define obd_warning(sb, func, format, a...) CDEBUG(D_WARNING, format, ## a)

int obd_remount (struct super_block * sb, int * flags, char * data);
struct super_block * ext2_read_super (struct super_block * sb, void * data,
				      int silent);

/* sysctl.c */
extern void obd_sysctl_init (void);
extern void obd_sysctl_clean (void);

/* truncate.c */
void obd_truncate (struct inode * inode);

/* operations */
/* dir.c */
extern struct inode_operations ext2_dir_inode_operations;

/* file.c */
extern struct file_operations ext2_file_operations;
extern struct inode_operations ext2_file_inode_operations;

/* super.c */
extern struct super_operations ext2_sops;

#endif /* __LINUX_SYM_OBD_H */
