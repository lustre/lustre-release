#ifndef _OBD_RAID1
#define _OBD_RAID1

#include <linux/obd_class.h>

#define MAX_RAID1 16


struct raid1_obd {
	unsigned int raid1_count; /* how many replicas */
	/* devices to replicate on */
	struct obd_device *raid1_devlist[MAX_RAID1];
	/* connections we make */
	struct obd_conn_info raid1_connections[MAX_RAID1];
	struct list_head raid1_clients;  /* clients we have */
};


/* development definitions */
extern struct obdfs_sb_info *obd_sbi;
extern struct file_operations *obd_fso;

/* obd_raid1.c */
extern struct obd_ops raid1_obd_ops;
inline long ext2_block_map (struct inode * inode, long block);

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


int obd_remount (struct super_block * sb, int * flags, char * data);
struct super_block * ext2_read_super (struct super_block * sb, void * data,
				      int silent);

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

#endif
