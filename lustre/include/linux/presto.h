#ifndef __PRESTO_H_
#define __PRESTO_H_ 1

/* super.c */
#if 0
extern struct super_block * ext2_read_super (struct super_block * sb, 
					     void * data,
					     int silent);
#endif
extern struct file_system_type presto_fs_type;
extern int init_presto_fs(void);

int presto_ispresto(struct inode *);

struct bottomfs {
	struct super_operations *bottom_sops;

	struct inode_operations *bottom_dir_iops;
	struct inode_operations *bottom_file_iops;
	struct inode_operations *bottom_sym_iops;

	struct file_operations *bottom_dir_fops;
	struct file_operations *bottom_file_fops;
	struct file_operations *bottom_sym_fops;
	kdev_t bottom_dev;
};
extern struct bottomfs *the_bottom;

/* inode.c */
void presto_read_inode(struct inode *inode);
int presto_notify_change(struct dentry *de, struct iattr *iattr);

/* dcache.c */
extern struct dentry_operations presto_dentry_operations;

/* dir.c */
extern struct inode_operations presto_dir_iops;
extern struct inode_operations presto_file_iops;
extern struct inode_operations presto_sym_iops;
extern struct file_operations presto_dir_fops;
extern struct file_operations presto_file_fops;
extern struct file_operations presto_sym_fops;

void presto_setup_file_ops(struct inode *);
void presto_setup_symlink_ops(struct inode *);

int presto_lookup(struct inode * dir, struct dentry *dentry);
int presto_dir_open(struct inode *inode, struct file *file);
int presto_file_open(struct inode *inode, struct file *file);
int presto_file_release(struct inode *inode, struct file *file);

int presto_mkdir(struct inode *inode, struct dentry *, int mode);
int presto_create(struct inode *inode, struct dentry *, int mode);
int presto_unlink(struct inode *inode, struct dentry *);
int presto_rmdir(struct inode *inode, struct dentry *);
int presto_symlink(struct inode *, struct dentry *, const char *);
int presto_rename(struct inode *old_dir, struct dentry *old_dentry,
		  struct inode *new_dir, struct dentry *new_dentry);

int lento_journal(char *page);

/* intermezzo.c */
#define PRESTO_ATTR		0x00000001 /* attributes cached */
#define PRESTO_DATA		0x00000002 /* data cached */
#define PRESTO_VOLROOT          0x00000004 /* this dentry is root of volume */
#define PRESTO_HASPERMIT        0x00000008 /* we have a permit to WB */

#define EISVOLROOT              0x2001

int presto_chk(struct dentry *dentry, int flag);
void presto_set(struct dentry *dentry, int flag);
void presto_permit(struct inode *);
int presto_mark_dentry(const char *path, int and_bits, int or_bits);

/* journal.c */

#define JOURNAL_PAGE  PAGE_SIZE


#define PRESTO_CREATE  1
#define PRESTO_MKDIR   2
#define PRESTO_UNLINK  3
#define PRESTO_RMDIR   4
#define PRESTO_CLOSE   5
#define PRESTO_SYMLINK 6
#define PRESTO_RENAME  7
#define PRESTO_SETATTR 8
#define PRESTO_LINK    9

void journal_create(struct inode *dirinode, struct inode *fileinode, int len, const char *name, int mode);
void journal_symlink(struct inode *inode, int len, const char *name, const char *target);
void journal_mkdir(struct inode *inode, int len, const char *name, int mode);
void journal_unlink(struct inode *inode, int len, const char *name);
void journal_rmdir(struct inode *inode, int len, const char *name);
void journal_rename(struct inode *old_dir, struct inode *old_file,
		    struct inode *new_dir, int new_len, const char *new_name);
void journal_setattr(struct inode *, int uid, int gid, int fsize, int atime,
		     int mtime, int ctime, int mode, unsigned int flags,
		     unsigned int valid);
void journal_close(struct inode *inode);
void journal_link(struct inode *src, struct inode *tpdiri, 
		  struct inode *ti, int len, const char *name);
void journal_fetch(void);

/* sysctl.c */
void presto_sysctl_init(void);
void presto_sysctl_clean(void);

/* global variables */
extern int presto_debug;
extern int presto_print_entry;

/* debugging masks */
#define D_SUPER     1   /* print results returned by Venus */ 
#define D_INODE     2   /* print entry and exit into procedure */
#define D_FILE      4   
#define D_CACHE     8   /* cache debugging */
#define D_MALLOC    16  /* print malloc, de-alloc information */
#define D_JOURNAL   32
#define D_UPCALL    64  /* up and downcall debugging */
#define D_PSDEV    128  
#define D_PIOCTL   256
#define D_SPECIAL  512
#define D_TIMING  1024
#define D_DOWNCALL 2048
 
#if 0
#define CDEBUG(mask, format, a...)                                \
  do {                                                            \
  if (presto_debug & mask) {                                        \
    printk("(%s,l. %d): ",  __FUNCTION__, __LINE__);              \
    printk(format, ## a); }                                       \
} while (0) ;                            
#else
#define CDEBUG(mask, format, a...) ;
#endif

#define ENTRY    \
    if(presto_print_entry) printk("Process %d entered %s\n",current->pid,__FUNCTION__)

#define EXIT    \
    if(presto_print_entry) printk("Process %d leaving %s\n",current->pid,__FUNCTION__)


#define PRESTO_ALLOC(ptr, cast, size)                                       \
do {                                                                      \
    if (size <= 4096) {                                                    \
        ptr = (cast)kmalloc((unsigned long) size, GFP_KERNEL);            \
                CDEBUG(D_MALLOC, "kmalloced: %x at %x.\n", (int) size, (int) ptr);\
     }  else {                                                             \
        ptr = (cast)vmalloc((unsigned long) size);                        \
	CDEBUG(D_MALLOC, "vmalloced: %x at %x.\n", (int) size, (int) ptr);}\
    if (ptr == 0) {                                                       \
        printk("kernel malloc returns 0 at %s:%d\n", __FILE__, __LINE__);  \
    }                                                                     \
    memset( ptr, 0, size );                                                   \
} while (0)


#define PRESTO_FREE(ptr,size) do {if (size <= 4096) { kfree_s((ptr), (size)); CDEBUG(D_MALLOC, "kfreed: %x at %x.\n", (int) size, (int) ptr); } else { vfree((ptr)); CDEBUG(D_MALLOC, "vfreed: %x at %x.\n", (int) size, (int) ptr);} } while (0)

#endif
