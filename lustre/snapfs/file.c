/*
 * file.c
 */

#define EXPORT_SYMTAB


#define __NO_VERSION__
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/locks.h>
#include <linux/quotaops.h>
#include <linux/list.h>
#include <linux/file.h>
#include <asm/bitops.h>
#include <asm/byteorder.h>

#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>

/* instantiate a file handle to the cache file */
static void currentfs_prepare_snapfile(struct inode *inode,
				     struct file *clone_file, 
				     struct inode *cache_inode,
				     struct file *cache_file,
				     struct dentry *cache_dentry)
{
	ENTRY;
        cache_file->f_pos = clone_file->f_pos;
        cache_file->f_mode = clone_file->f_mode;
        cache_file->f_flags = clone_file->f_flags;
        cache_file->f_count  = clone_file->f_count;
        cache_file->f_owner  = clone_file->f_owner;
	cache_file->f_op = cache_inode->i_op->default_file_ops;
	cache_file->f_dentry = cache_dentry;
        cache_file->f_dentry->d_inode = cache_inode;
	EXIT;
        return ;
}

/* update the currentfs file struct after IO in cache file */
static void currentfs_restore_snapfile(struct inode *cache_inode,
				   struct file *cache_file, 
				   struct inode *clone_inode,
				   struct file *clone_file)
{
	ENTRY;
        cache_file->f_pos = clone_file->f_pos;
	EXIT;
        return;
}


static ssize_t currentfs_write (struct file *filp, const char *buf, 
				size_t count, loff_t *ppos)
{
        struct snap_cache *cache;
	struct inode *inode = filp->f_dentry->d_inode;
        ssize_t rc;
        struct file_operations *fops;
	loff_t pos;
	long block[2]={-1,-1}, mask, i;
	struct snap_table *table;
	int slot = 0;
	int index = 0;
	struct inode_operations *ciops;
	struct inode *cache_inode = NULL;
	struct snapshot_operations *snapops;
  
	ENTRY;

	if (currentfs_is_under_dotsnap(filp->f_dentry)) {
		EXIT;
		return -ENOSPC;
	}

        cache = snap_find_cache(inode->i_dev);
        if ( !cache ) { 
                EXIT;
                return -EINVAL;
        }

        if ( snap_needs_cow(inode) != -1 ) {
                CDEBUG(D_FILE, "snap_needs_cow for ino %lu \n",inode->i_ino);
                snap_do_cow(inode, filp->f_dentry->d_parent->d_inode->i_ino, 0);
	}

        fops = filter_c2cffops(cache->cache_filter); 
        if (!fops ||
            !fops->write) {
                EXIT;
                return -EINVAL;
        }

        if (filp->f_flags & O_APPEND)
                pos = inode->i_size;
        else {
                pos = *ppos;
                if (pos != *ppos)
                        return -EINVAL;
        }

	/*
	 * we only need to copy back the first and last blocks
	 */
	mask = inode->i_sb->s_blocksize-1;
	if( pos & mask )
		block[0] = pos >> inode->i_sb->s_blocksize_bits;
	pos += count - 1;
	if( (pos+1) &  mask )
		block[1] = pos >> inode->i_sb->s_blocksize_bits;
	if( block[0] == block[1] )
		block[1] = -1;

	ciops = filter_c2cfiops(cache->cache_filter);
	snapops = filter_c2csnapops(cache->cache_filter);

	for( i=0; i<2; i++ ){
		if( block[i]!=-1 && !ciops->bmap(inode, block[i]) ) {
			table = &snap_tables[cache->cache_snap_tableno];
        		for (slot = table->tbl_count ; slot >= 1; slot--)
        		{
				cache_inode = NULL;
                		index = table->tbl_index[slot];
				cache_inode = snap_get_indirect(inode, NULL, index);

				if ( !cache_inode )  continue;

	                	if (cache_inode->i_op->bmap(cache_inode, block[i])) {
					CDEBUG(D_FILE, "find cache_ino %lu\n",
						cache_inode->i_ino);
					if( snapops && snapops->copy_block) {
						snapops->copy_block( inode, 
								cache_inode, block[i]);
					}

					iput(cache_inode);
                        		break;
                		}
                       		 iput(cache_inode);
        		}
		}
	}

        rc = fops->write(filp, buf, count, ppos);
        
        EXIT;
        return rc;
}

static int currentfs_readpage(struct file *file, struct page *page)
{
	int result = 0;
	struct inode *inode = file->f_dentry->d_inode;
	unsigned long ind_ino = inode->i_ino;
	struct inode *pri_inode = NULL;
	struct inode *cache_inode = NULL;
	struct file open_file;
	struct dentry open_dentry ;
	struct inode_operations *ciops;
	struct snap_cache *cache;
 	long block;
	struct snap_table *table;
	int slot = 0;
	int index = 0;
	int search_older = 0;

	ENTRY;

	cache = snap_find_cache(inode->i_dev);
	if ( !cache ) { 
		EXIT;
		return -EINVAL;
	}

	ciops = filter_c2cfiops(cache->cache_filter);

	block = page->offset >> inode->i_sb->s_blocksize_bits;

	/* if there is a block in the cache, return the cache readpage */
	if( inode->i_blocks && ciops->bmap(inode, block) ) {
		CDEBUG(D_FILE, "block %lu in cache, ino %lu\n", 
				block, inode->i_ino);
		result = ciops->readpage(file, page);
        	EXIT;
		return result;
	}

	/*
	 * clonefs_readpage will fill this with primary ino number
	 * we need it to follow the cloned chain of primary inode
	 */
	if( file->f_dentry->d_fsdata ){
		pri_inode = iget(inode->i_sb, (unsigned long)file->f_dentry->d_fsdata);
		if( !pri_inode )
			return -EINVAL;
		inode = pri_inode;
		search_older = 1;
	}

	table = &snap_tables[cache->cache_snap_tableno];

        for (slot = table->tbl_count ; slot >= 1; slot--)
        {
		cache_inode = NULL;
                index = table->tbl_index[slot];
		cache_inode = snap_get_indirect(inode, NULL, index);

		if ( !cache_inode )  continue;

		/* we only want slots between cache_inode to the oldest one */
		if( search_older && cache_inode->i_ino == ind_ino )
			search_older = 0;

                if ( !search_older && cache_inode->i_op->bmap(cache_inode, block)) {
                        break;
                }
                iput(cache_inode);
        }
	if( pri_inode )
		iput(pri_inode);

	if ( !cache_inode ) { 
		EXIT;
		return -EINVAL;
	}

	currentfs_prepare_snapfile(inode, file, cache_inode, &open_file,
			      &open_dentry);

	down(&cache_inode->i_sem);

	if( ciops->readpage ) {
		CDEBUG(D_FILE, "block %lu NOT in cache, use redirected ino %lu\n", block, cache_inode->i_ino );
		result = ciops->readpage(&open_file, page);
	}else {
		CDEBUG(D_FILE, "cache ino %lu, readpage is NULL\n", 
				cache_inode->i_ino);
	}

	up(&cache_inode->i_sem);
	currentfs_restore_snapfile(inode, file, cache_inode, &open_file);
	iput(cache_inode);
        EXIT;
	return result;
}

struct file_operations currentfs_file_fops = {
	write:currentfs_write,
};

struct inode_operations currentfs_file_iops = {
	default_file_ops: &currentfs_file_fops,
	readpage: currentfs_readpage,
};
