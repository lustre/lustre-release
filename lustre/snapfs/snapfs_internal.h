#ifndef __LINUX_SNAPFS_H
#define __LINUX_SNAPFS_H
/* maximum number of snapshot tables we maintain in the kernel */
#define SNAP_MAX		32	
#define SNAP_MAX_TABLES 	32	
#define SNAP_MAX_NAMELEN	64

/* ioctls for manipulating snapshots 40 - 60 */
#define IOC_SNAP_TYPE                   'f'
#define IOC_SNAP_MIN_NR                 41

#define IOC_SNAP_SETTABLE		_IOWR('f', 41, long)
#define IOC_SNAP_PRINTTABLE		_IOWR('f', 42, long)
#define IOC_SNAP_GETINDEXFROMNAME	_IOWR('f', 43, long)
#define IOC_SNAP_GET_NEXT_INO		_IOWR('f', 44, long)
#define IOC_SNAP_GET_INO_INFO		_IOWR('f', 45, long)

#define IOC_SNAP_ADD			_IOWR('f', 46, long)
#define IOC_SNAP_DELETE			_IOWR('f', 47, long)
#define IOC_SNAP_RESTORE		_IOWR('f', 48, long)
#define IOC_SNAP_DEBUG			_IOWR('f', 49, long)
#define IOC_SNAP_DEVFAIL		_IOWR('f', 50, long)
#define IOC_SNAP_SHOW_DOTSNAP		_IOWR('f', 51, long)

#define IOC_SNAP_MAX_NR                 51 

struct snap {
	time_t 		time;
	unsigned int 	index;
	unsigned int 	gen;
	unsigned int 	flags;
	char 	name[SNAP_MAX_NAMELEN];
};


/*FIXME, use ioc_data temporary, will use obd_ioc_data later*/
struct ioc_data {
	unsigned int ioc_inlen;
	char 	     *ioc_inbuf;
	char	     ioc_bulk[0];
};

/* snap ioctl data for table fiddling */
struct ioc_snap_tbl_data {
	int 		no;		/* which table */
	unsigned long	dev;
	unsigned int 	count;		/* how many snaps */
	struct snap 	snaps[0];	/* sorted times! */
};
struct option {
	char *opt;
	char *value;
	struct list_head list;
};
/* we have just a single snapshot control device
   it contains a list of all the snap_current info's
*/
#define SNAPDEV_NAME "/dev/snapconf"
#define SNAP_PSDEV_MINOR 240
#define SNAP_PSDEV_MAJOR 10

#define SNAP_TABLE_OUTBUF_LEN	1020

#ifdef __KERNEL__

#if 0
#include <linux/lustre_lib.h>
#else
#include "snapfs_support.h" 
#endif
/* What we use to point to IDs in the obdmd data for snapshots.  If we use
 * obd_id (8 bytes) instead of ino_t (4 bytes), we halve the number of
 * available snapshot slots (14 in 56 bytes vs. 7 in 56 bytes until we
 * increase the size of OBD_OBDMDSZ).
 */
typedef ino_t	snap_id;


/* maximum number of snapshots per device 
   must fit in "o_obdmd" area of struct obdo */
//#define OBD_OBDMDSZ  54
//#define SNAP_MAX ((OBD_OBDMDSZ - sizeof(uint32_t))/sizeof(snap_id))



/* if time is 0 this designates the "current" snapshot, i.e.
   the head of the tree 
*/

/* sysctl.c */
extern int init_snapfs_proc_sys(void);
extern void cleanup_spapfs_proc_sys(void);
extern int snap_print_entry;
extern int snap_debug_level;
extern int snap_inodes;
extern long snap_kmemory;
extern int snap_stack;

/* snap cache information: this morally equals the superblock of a
 snap_current_fs.  However, that superblock is the one of the "cache"
 device holding the inodes, hence we store this info in the hash of
 mountpoints hanging of our control device. 
*/
struct snap_cache {
	struct list_head cache_chain;

	kdev_t cache_dev;
	struct super_block *cache_sb; /* the _real_ device */

	struct list_head cache_clone_list;
	int cache_snap_tableno;

	struct filter_fs *cache_filter;

	char cache_type;
	char cache_show_dotsnap;
};

/* this is the snap_clone_info for the sb of snap_clone_fs */
struct snap_clone_info {
	struct snap_cache *clone_cache;
	struct list_head clone_list_entry;
	int clone_index;
};

/* 
 * it is important that things like inode, super and file operations
 * for intermezzo are not defined statically.  If methods are NULL
 * the VFS takes special action based on that.  Given that different
 * cache types have NULL ops at different slots, we must install opeation 
 * talbes for InterMezzo with NULL's in the same spot
 */

struct filter_ops {
	/* operations on the file store */
	struct super_operations filter_sops;

	struct inode_operations filter_dir_iops;
	struct inode_operations filter_file_iops;
	struct inode_operations filter_sym_iops;

	struct file_operations filter_dir_fops;
	struct file_operations filter_file_fops;
	struct file_operations filter_sym_fops;

	struct address_space_operations filter_file_aops;
	struct dentry_operations filter_dentry_ops;
};


struct cache_ops {
	/* operations on the file store */
	struct super_operations *cache_sops;

	struct inode_operations *cache_dir_iops;
	struct inode_operations *cache_file_iops;
	struct inode_operations *cache_sym_iops;

	struct file_operations *cache_dir_fops;
	struct file_operations *cache_file_fops;
	struct file_operations *cache_sym_fops;

	struct address_space_operations *cache_file_aops;
	struct dentry_operations *cache_dentry_ops;
};


#define SNAP_OP_NOOP		0
#define SNAP_OP_CREATE		1
#define SNAP_OP_MKDIR		2
#define SNAP_OP_UNLINK		3
#define SNAP_OP_RMDIR		4
#define SNAP_OP_CLOSE		5
#define SNAP_OP_SYMLINK		6
#define SNAP_OP_RENAME		7
#define SNAP_OP_SETATTR		8
#define SNAP_OP_LINK		9
#define SNAP_OP_OPEN		10
#define SNAP_OP_MKNOD		11
#define SNAP_OP_WRITE		12
#define SNAP_OP_RELEASE		13

struct journal_ops {
	void *(*trans_start)(struct inode *, int op);
	void (*trans_commit)(void *handle);
};

struct snap_control_device {
	struct list_head snap_dev_list;
};

#define D_MAXLEN 1024

#define SNAPSHOT_UNUSED_FLAG		(1 << 0)
#define SNAPSHOT_GOOD_FLAG		(1 << 1)
#define SNAPSHOT_DELETING_FLAG		(1 << 2)
#define SNAPSHOT_BAD_FLAG		(1 << 3)	

struct snap_disk {
	__u64 	time;
	__u32 	gen;
	__u32	index;
	__u32 	flags;
	char	name[SNAP_MAX_NAMELEN];
};
/* snap ioctl data for attach: current always in first slot of this array */
struct snap_obd_data {
	int 	     snap_dev;	/* which device contains the data */
	unsigned int snap_index;/* which snapshot is ours */
	unsigned int snap_table;/* which table do we use */
};
#define DISK_SNAPTABLE_ATTR     "Snaptable12"
#define DISK_SNAP_TABLE_MAGIC	0x1976
struct snap_disk_table {
	unsigned int    	magic;
	unsigned int    	count;
	unsigned int		generation;
	struct  snap_disk  	snap_items[SNAP_MAX];
};

/*Snap Table*/
struct snap_table {
	struct semaphore    tbl_sema;
	spinlock_t          tbl_lock;
	unsigned int 	    tbl_count; /* how many snapshots exist in this table*/
	unsigned int	    generation;
	struct snap    	    snap_items[SNAP_MAX]; 
};

struct snap_iterdata {
	kdev_t dev;	/* snap current device number */ 
	int index;
	int tableno;
	time_t time;
};

struct snap_ioc_data {
	kdev_t dev;
	char name[SNAP_MAX_NAMELEN];
};

struct snap_ino_list_data{
        kdev_t dev;
        ino_t ino;
};
struct filter_inode_info {
	int flags;		/* the flags indicated inode type */
	int generation; 	/*the inode generation*/
};
/* dotsnap.c */
extern int currentfs_is_under_dotsnap(struct dentry *de);

/* cache.c */
inline void snap_free_cache(struct snap_cache *cache);
struct snap_cache *snap_find_cache(kdev_t dev);
typedef int (*snap_cache_cb_t)(struct snap_cache*, void *in, unsigned long *out);
int snap_cache_process(snap_cache_cb_t cb, void* in, unsigned long* out);

/* snaptable.c */
extern struct snap_table snap_tables[SNAP_MAX_TABLES];
void snap_last(struct snap_cache *info, struct snap *snap);
int snap_index2slot(struct snap_table *snap_table, int snap_index);
int snap_needs_cow(struct inode *);
int snapfs_read_snaptable(struct snap_cache *cache, int tableno);
/* snap.c */
int snap_is_redirector(struct inode *inode);
struct inode *snap_redirect(struct inode *inode, struct super_block *clone_sb);
int snap_do_cow(struct inode *inode, ino_t parent_ino, int del);

int snap_iterate(struct super_block *sb,
                int (*repeat)(struct inode *inode, void *priv),
                struct inode **start, void *priv, int flag);

struct inode *snap_get_indirect(struct inode *pri, int *table, int slot);
int snap_destroy_indirect(struct inode *pri, int index, struct inode *next_ind);
int snap_restore_indirect(struct inode *pri, int index );
int snap_migrate_data(struct inode *dst, struct inode *src);
int snap_set_indirect(struct inode *pri, ino_t ind_ino, 
			int index, ino_t parent_ino);

/*super.c */
void put_snap_current_mnt(struct super_block *sb);
void get_snap_current_mnt(struct super_block *sb);
/* inode.c */
extern struct super_operations currentfs_super_ops;
void cleanup_filter_info_cache(void);
int init_filter_info_cache(void);
extern void init_filter_data(struct inode *inode, int flag);
extern void set_filter_ops(struct snap_cache *cache, struct inode *inode);
extern int currentfs_setxattr(struct dentry *dentry, const char *name, 
		       const void *value, size_t size, int flags);
extern int currentfs_removexattr(struct dentry *dentry, const char *name);
extern int currentfs_setattr(struct dentry *dentry, struct iattr *attr);
/* dir.c */
extern struct inode_operations currentfs_dir_iops;
extern struct file_operations currentfs_dir_fops;
extern struct address_space_operations currentfs_file_aops;

/* file.c */
extern struct inode_operations currentfs_file_iops;
extern struct file_operations currentfs_file_fops;

/* symlink.c */
extern struct inode_operations currentfs_sym_iops;
extern struct file_operations currentfs_sym_fops;

extern struct dentry_operations currentfs_dentry_ops;

/* options.c */
extern int init_option(char *data);
extern void cleanup_option(void);
extern int get_opt(struct option **opt, char **pos);
/* clonefs.c */
int clonefs_mounted(struct snap_cache *cache, int index);

#define FILTER_DID_SUPER_OPS 	0x1
#define FILTER_DID_INODE_OPS 	0x2
#define FILTER_DID_FILE_OPS 	0x4
#define FILTER_DID_DENTRY_OPS 	0x8
#define FILTER_DID_DEV_OPS 	0x10
#define FILTER_DID_SYMLINK_OPS 	0x20
#define FILTER_DID_DIR_OPS 	0x40
#define FILTER_DID_SNAPSHOT_OPS 0x80
#define FILTER_DID_JOURNAL_OPS	0x100

struct filter_fs {
	int o_flags;
	struct filter_ops o_fops;
	struct cache_ops  o_caops;
	struct journal_ops *o_trops;
	struct snapshot_operations *o_snapops;
};

#define FILTER_FS_TYPES 3
#define FILTER_FS_EXT2 0
#define FILTER_FS_EXT3 1
#define FILTER_FS_REISER 2
extern struct filter_fs filter_oppar[FILTER_FS_TYPES];
struct filter_fs *filter_get_filter_fs(const char *cache_type);
inline struct super_operations *filter_c2usops(struct filter_fs *cache);
inline struct inode_operations *filter_c2ufiops(struct filter_fs *cache);
inline struct inode_operations *filter_c2udiops(struct filter_fs *cache);
inline struct inode_operations *filter_c2usiops(struct filter_fs *cache);
inline struct super_operations *filter_c2csops(struct filter_fs *cache);
inline struct inode_operations *filter_c2cfiops(struct filter_fs *cache);
inline struct inode_operations *filter_c2cdiops(struct filter_fs *cache);
inline struct inode_operations *filter_c2csiops(struct filter_fs *cache);
inline struct file_operations *filter_c2udfops(struct filter_fs *cache);
inline struct file_operations *filter_c2cffops(struct filter_fs *cache);
inline struct file_operations *filter_c2cdfops(struct filter_fs *cache);
inline struct file_operations *filter_c2csfops(struct filter_fs *cache);
inline struct file_operations *filter_c2uffops(struct filter_fs *cache);
inline struct file_operations *filter_c2usfops(struct filter_fs *cache);
inline struct dentry_operations *filter_c2cdops(struct filter_fs *cache);
inline struct dentry_operations *filter_c2udops(struct filter_fs *cache);
inline struct address_space_operations *filter_c2cfaops(struct filter_fs *cache);
inline struct address_space_operations *filter_c2ufaops(struct filter_fs *cache);
/* for snapfs */
inline struct snapshot_operations *filter_c2csnapops(struct filter_fs *cache);

void filter_setup_file_ops(struct filter_fs 	   *cache, 
			   struct inode		   *inode,
			   struct inode_operations *filter_iops,
			   struct file_operations  *filter_fops,
			   struct address_space_operations *filter_aops);

void filter_setup_dir_ops(struct filter_fs *cache, 
			  struct inode	   *inode,
			  struct inode_operations *filter_iops, 
			  struct file_operations *filter_fops);

void filter_setup_symlink_ops(struct filter_fs *cache, 
			      struct inode *inode,
		              struct inode_operations *filter_iops, 
			      struct file_operations *filter_fops);

void filter_setup_dentry_ops(struct filter_fs *cache,
			     struct dentry_operations *cache_dop, 
			     struct dentry_operations *filter_dop);
void filter_setup_super_ops(struct filter_fs *cache, 
			    struct super_operations *cache_sops, 
			    struct super_operations *filter_sops);
/* for snapfs */
void filter_setup_snapshot_ops(struct filter_fs *cache, 
			       struct snapshot_operations *cache_snapops);
void filter_setup_journal_ops(struct filter_fs *cache, 
			      struct journal_ops *cache_journal_ops);

static inline void* snap_trans_start(struct snap_cache *cache, 
				     struct inode *inode, int op)
{
	if( cache->cache_filter->o_trops )
		return cache->cache_filter->o_trops->trans_start(inode, op);
	return NULL;
};
static inline void snap_trans_commit(struct snap_cache *cache, void *handle)
{
	if( cache->cache_filter->o_trops )
		cache->cache_filter->o_trops->trans_commit(handle);
};

static inline void snapfs_cpy_attrs(struct inode *dst, struct inode *src)
{
	dst->i_mtime = src->i_mtime;
	dst->i_ctime = src->i_ctime;
	dst->i_atime = src->i_atime;
	dst->i_size = src->i_size;
	dst->i_blksize = src->i_blksize;
	dst->i_blocks = src->i_blocks;
	dst->i_generation = src->i_generation;
	dst->i_uid = src->i_uid;
	dst->i_gid = src->i_gid;
	dst->i_mode = src->i_mode;
}
#if 0
extern unsigned int snap_debug_failcode;
#ifdef CONFIG_LOOP_DISCARD
#define BLKDEV_FAIL(dev,fail) loop_discard_io(dev,fail)
#else
#define BLKDEV_FAIL(dev,fail) set_device_ro(dev, 1)
#endif

static inline void snap_debug_device_fail(dev_t dev, unsigned short opcode, unsigned short pos)
{
	unsigned int failcode = (opcode<<16) | pos;

	if( failcode == snap_debug_failcode && !is_read_only(dev)){
		printk(KERN_EMERG "set block device %s into fail mode\n", bdevname(dev));
		BLKDEV_FAIL(dev, 1);
	}
}
#else
#define snap_debug_device_fail(args...) do{}while(0)
#endif

extern int snap_debug_level;
extern int snap_print_entry;

#endif /*_KERNEL_*/
#endif /* __LINUX_SNAPFS_H */
