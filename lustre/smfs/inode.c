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
#include <linux/lustre_idl.h>
#include "smfs_internal.h" 

static void duplicate_inode(struct inode *dst_inode, 
		     struct inode *src_inode) 
{
	dst_inode->i_mode = src_inode->i_mode;
	dst_inode->i_uid = src_inode->i_uid;
	dst_inode->i_gid = src_inode->i_gid;
	dst_inode->i_nlink = src_inode->i_nlink;
	dst_inode->i_size = src_inode->i_size;
	dst_inode->i_atime = src_inode->i_atime;
	dst_inode->i_ctime = src_inode->i_ctime;
	dst_inode->i_mtime = src_inode->i_mtime;
	dst_inode->i_blksize = src_inode->i_blksize;  
	dst_inode->i_blocks = src_inode->i_blocks;
	dst_inode->i_version = src_inode->i_version;
	dst_inode->i_state = src_inode->i_state;
}

void post_smfs_inode(struct inode *inode, 
		     struct inode *cache_inode)
{
	if (inode && cache_inode) {
		duplicate_inode(inode, cache_inode);
		/*Here we must release the cache_inode,
		 *Otherwise we will have no chance to
		 *do it
		 */
		cache_inode->i_state &=~I_LOCK;	
	}
}
void pre_smfs_inode(struct inode *inode,
		    struct inode *cache_inode)
{
	if (inode && cache_inode) {
		duplicate_inode(cache_inode, inode);
	}
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

	post_smfs_inode(inode, cache_inode);
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
	
	pre_smfs_inode(inode, cache_inode);
	
	list_del(&cache_inode->i_hash);
        INIT_LIST_HEAD(&cache_inode->i_hash);
        list_del(&cache_inode->i_list);
        INIT_LIST_HEAD(&cache_inode->i_list);
    	
	if (cache_inode->i_data.nrpages)
        	truncate_inode_pages(&cache_inode->i_data, 0);
	
	if (cache_sb->s_op->delete_inode)
		cache_sb->s_op->delete_inode(cache_inode);

	post_smfs_inode(inode, cache_inode);
	
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
		
	pre_smfs_inode(inode, cache_inode);
	
	if (cache_sb->s_op->write_inode)
		cache_sb->s_op->write_inode(cache_inode, wait);

	post_smfs_inode(inode, cache_inode);
	
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
		
	pre_smfs_inode(inode, cache_inode);
	if (cache_sb->s_op->dirty_inode)
		cache_sb->s_op->dirty_inode(cache_inode);

	post_smfs_inode(inode, cache_inode);
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





