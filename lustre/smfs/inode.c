/*
 *  fs/snap/snap.c
 *
 *  A snap shot file system.
 *
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "smfs_internal.h" 

void duplicate_inode(struct inode *cache_inode, struct inode *inode)
{
	
	inode->i_mode = cache_inode->i_mode;
	inode->i_uid = cache_inode->i_uid;
	inode->i_gid = cache_inode->i_gid;

	inode->i_nlink = cache_inode->i_nlink;
	inode->i_size = cache_inode->i_size;
	inode->i_atime = cache_inode->i_atime;
	inode->i_ctime = cache_inode->i_ctime;
	inode->i_mtime = cache_inode->i_mtime;
	inode->i_blksize = cache_inode->i_blksize; /* This is the optimal IO size
					 * (for stat), not the fs block
					 * size */  
	inode->i_blocks = cache_inode->i_blocks;
	inode->i_version = cache_inode->i_version;
}
static void smfs_read_inode(struct inode *inode)
{
	struct super_block *cache_sb;
	struct inode *cache_inode;	
	ENTRY;

	if (!inode) 
		return;
	
	CDEBUG(D_INODE, "read_inode ino %lu\n", inode->i_ino);
	cache_sb = S2CSB(inode->i_sb);

	cache_inode = iget(cache_sb, inode->i_ino);
	I2CI(inode) = cache_inode;
	
	if(cache_sb && cache_sb->s_op->read_inode)
		cache_sb->s_op->read_inode(cache_inode);

	duplicate_inode(cache_inode, inode);
	sm_set_inode_ops(cache_inode, inode);
	
	CDEBUG(D_INODE, "read_inode ino %lu icount %d \n", 
	       inode->i_ino, atomic_read(&inode->i_count));
	
	iput(cache_inode);	
	return; 
}
/* Although some filesystem(such as ext3) do not have
 * clear_inode method, but we need it to free the 
 * cache inode 
 */
static void smfs_clear_inode(struct inode *inode)
{
	struct super_block *cache_sb;
	struct inode *cache_inode;	

	ENTRY;
	
	if (!inode) return;
	
	cache_sb = S2CSB(inode->i_sb);
	cache_inode = I2CI(inode);
	clear_inode(cache_inode);
	return;	
}

struct super_operations smfs_super_ops = {
	read_inode:	smfs_read_inode,
	clear_inode:	smfs_clear_inode,
	put_super:	smfs_put_super,
};





