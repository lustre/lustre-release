/*
 *  smfs/inode.c
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
	inode->i_state = cache_inode->i_state;
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

	/*FIXME: because i_count of cache_inode may not 
         * be 0 or 1 in before smfs_delete inode, So we 
         * need to dec it to 1 before we call delete_inode
         * of the bellow cache filesystem Check again latter*/

	if (atomic_read(&cache_inode->i_count) < 1)
		BUG();
	
	while (atomic_read(&cache_inode->i_count) != 1) {
		atomic_dec(&cache_inode->i_count);
	}
	iput(cache_inode);
	
	I2CI(inode) = NULL;
	return;	
}
static void smfs_delete_inode(struct inode *inode)
{
	struct inode *cache_inode;
	struct super_block *cache_sb;

	ENTRY;
	cache_inode = I2CI(inode);
	cache_sb = S2CSB(inode->i_sb);

	if (!cache_inode || !cache_sb)  
		return;

	/*FIXME: because i_count of cache_inode may not 
         * be 0 or 1 in before smfs_delete inode, So we 
         * need to dec it to 1 before we call delete_inode
         * of the bellow cache filesystem Check again latter*/

	if (atomic_read(&cache_inode->i_count) < 1)
		BUG();
	
	while (atomic_read(&cache_inode->i_count) != 1) {
		atomic_dec(&cache_inode->i_count);
	}
	
	duplicate_inode(inode, cache_inode); 
	
	list_del(&cache_inode->i_hash);
        INIT_LIST_HEAD(&cache_inode->i_hash);
        list_del(&cache_inode->i_list);
        INIT_LIST_HEAD(&cache_inode->i_list);
    	
	if (cache_inode->i_data.nrpages)
        	truncate_inode_pages(&cache_inode->i_data, 0);
	
	if (cache_sb->s_op->delete_inode)
		cache_sb->s_op->delete_inode(cache_inode);

	duplicate_inode(cache_inode, inode); 
	
	I2CI(inode) = NULL;
	return;
}
static void smfs_write_inode(struct inode *inode, int wait)
{
	struct inode *cache_inode;
	struct super_block *cache_sb;

	ENTRY;
	cache_inode = I2CI(inode);
	cache_sb = S2CSB(inode->i_sb);

	if (!cache_inode || !cache_sb)
		return;
		
	if (cache_sb->s_op->write_inode)
		cache_sb->s_op->write_inode(cache_inode, wait);

	duplicate_inode(cache_inode, inode); 
	
	return;
}
static void smfs_dirty_inode(struct inode *inode)
{
	struct inode *cache_inode;
	struct super_block *cache_sb;

	ENTRY;
	cache_inode = I2CI(inode);
	cache_sb = S2CSB(inode->i_sb);

	if (!cache_inode || !cache_sb)
		return;
		
	duplicate_inode(inode, cache_inode); 
	if (cache_sb->s_op->dirty_inode)
		cache_sb->s_op->dirty_inode(cache_inode);

	duplicate_inode(cache_inode, inode); 
	return;
}

static void smfs_put_inode(struct inode *inode)
{
	struct inode *cache_inode;
	struct super_block *cache_sb;

	ENTRY;
	cache_inode = I2CI(inode);
	cache_sb = S2CSB(inode->i_sb);

	if (!cache_inode || !cache_sb)
		return;
	if (cache_sb->s_op->put_inode)
		cache_sb->s_op->put_inode(cache_inode);

	return;
}

static void smfs_write_super(struct super_block *sb)
{
	struct super_block *cache_sb;

	ENTRY;
	cache_sb = S2CSB(sb);

	if (!cache_sb)
		return;
		
	if (cache_sb->s_op->write_super)
		cache_sb->s_op->write_super(cache_sb);

	duplicate_sb(cache_sb, sb);
	return;
}

static void smfs_write_super_lockfs(struct super_block *sb)
{
	struct super_block *cache_sb;

	ENTRY;
	cache_sb = S2CSB(sb);

	if (!cache_sb)
		return;
		
	if (cache_sb->s_op->write_super_lockfs)
		cache_sb->s_op->write_super_lockfs(cache_sb);

	duplicate_sb(cache_sb, sb);
	return;
}

static void smfs_unlockfs(struct super_block *sb)
{
	struct super_block *cache_sb;

	ENTRY;
	cache_sb = S2CSB(sb);

	if (!cache_sb)
		return;
		
	if (cache_sb->s_op->unlockfs)
		cache_sb->s_op->unlockfs(cache_sb);

	duplicate_sb(cache_sb, sb);
	return;
}
static int smfs_statfs(struct super_block * sb, struct statfs * buf) 
{
	struct super_block *cache_sb;
	int	rc = 0;

	ENTRY;
	cache_sb = S2CSB(sb);

	if (!cache_sb)
		RETURN(-EINVAL);
		
	if (cache_sb->s_op->statfs)
		rc = cache_sb->s_op->statfs(cache_sb, buf);

	duplicate_sb(cache_sb, sb);
	
	return rc;
}
static int smfs_remount(struct super_block * sb, int * flags, char * data)
{
	struct super_block *cache_sb;
	int    rc = 0;

	ENTRY;
	cache_sb = S2CSB(sb);

	if (!cache_sb)
		RETURN(-EINVAL);
		
	if (cache_sb->s_op->remount_fs)
		rc = cache_sb->s_op->remount_fs(cache_sb, flags, data);

	duplicate_sb(cache_sb, sb);
	RETURN(rc);
}
struct super_operations smfs_super_ops = {
	read_inode:	smfs_read_inode,
	clear_inode:	smfs_clear_inode,
	put_super:	smfs_put_super,
	delete_inode:	smfs_delete_inode,
        write_inode:	smfs_write_inode,
        dirty_inode:    smfs_dirty_inode,       /* BKL not held.  We take it */
        put_inode:      smfs_put_inode,         /* BKL not held.  Don't need */

        write_super:    smfs_write_super,       /* BKL held */
        write_super_lockfs: smfs_write_super_lockfs, /* BKL not held. Take it */
        unlockfs:       smfs_unlockfs,          /* BKL not held.  We take it */
        statfs:         smfs_statfs,            /* BKL held */
        remount_fs:     smfs_remount,           /* BKL held */

};





