/*
 * file.c
 */

#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>

#include "snapfs_internal.h" 

/* instantiate a file handle to the cache file */
static void currentfs_prepare_snapfile(struct inode *inode,
				     struct file *clone_file, 
				     struct inode *cache_inode,
				     struct file *cache_file,
				     struct dentry *cache_dentry)
{
        cache_file->f_pos = clone_file->f_pos;
        cache_file->f_mode = clone_file->f_mode;
        cache_file->f_flags = clone_file->f_flags;
        cache_file->f_count  = clone_file->f_count;
        cache_file->f_owner  = clone_file->f_owner;
	cache_file->f_dentry = cache_dentry;
        cache_file->f_dentry->d_inode = cache_inode;
}

/* update the currentfs file struct after IO in cache file */
static void currentfs_restore_snapfile(struct inode *cache_inode,
				   struct file *cache_file, 
				   struct inode *clone_inode,
				   struct file *clone_file)
{
        cache_file->f_pos = clone_file->f_pos;
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
	struct address_space_operations *aops;
	struct inode *cache_inode = NULL;
	struct snapshot_operations *snapops;
  
	ENTRY;

	if (currentfs_is_under_dotsnap(filp->f_dentry)) 
		RETURN(-ENOSPC);

        cache = snap_find_cache(inode->i_dev);
        if ( !cache ) 
                RETURN(-EINVAL);

        if ( snap_needs_cow(inode) != -1 ) {
                CDEBUG(D_SNAP, "snap_needs_cow for ino %lu \n",inode->i_ino);
                snap_do_cow(inode, filp->f_dentry->d_parent->d_inode->i_ino, 0);
	}

        fops = filter_c2cffops(cache->cache_filter); 
        if (!fops || !fops->write) 
                RETURN(-EINVAL);

        if (filp->f_flags & O_APPEND)
                pos = inode->i_size;
        else {
                pos = *ppos;
                if (pos != *ppos)
                        RETURN(-EINVAL);
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
	
	aops = filter_c2cfaops(cache->cache_filter);
	snapops = filter_c2csnapops(cache->cache_filter);

	for( i=0; i<2; i++ ){
		if(block[i]!=-1 && aops->bmap(inode->i_mapping, block[i])) {
			table = &snap_tables[cache->cache_snap_tableno];
        		for (slot = table->tbl_count ; slot >= 1; slot--) {
				struct address_space_operations *c_aops = 
					cache_inode->i_mapping->a_ops;
				cache_inode = NULL;
                		index = table->snap_items[slot].index;
				cache_inode = snap_get_indirect(inode, NULL, index);

				if ( !cache_inode )  continue;

	                	if (c_aops->bmap(cache_inode->i_mapping, block[i])) {
					CDEBUG(D_SNAP, "find cache_ino %lu\n",
						cache_inode->i_ino);
					if( snapops && snapops->copy_block) {
						snapops->copy_block(inode, 
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
        RETURN(rc);
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
	struct address_space_operations *c_aops;
	struct snap_cache *cache;
 	long block;
	struct snap_table *table;
	int slot = 0;
	int index = 0;
	int search_older = 0;

	ENTRY;

	cache = snap_find_cache(inode->i_dev);
	if ( !cache ) { 
		RETURN(-EINVAL);
	}
	
	c_aops = filter_c2cfaops(cache->cache_filter);

	block = page->index >> inode->i_sb->s_blocksize_bits;

	/* if there is a block in the cache, return the cache readpage */
	if( inode->i_blocks && c_aops->bmap(inode->i_mapping, block) ) {
		CDEBUG(D_SNAP, "block %lu in cache, ino %lu\n", 
				block, inode->i_ino);
		result = c_aops->readpage(file, page);
		RETURN(result);
	}

	/*
	 * clonefs_readpage will fill this with primary ino number
	 * we need it to follow the cloned chain of primary inode
	 */
	if( file->f_dentry->d_fsdata ){
		pri_inode = iget(inode->i_sb, (unsigned long)file->f_dentry->d_fsdata);
		if( !pri_inode )
			RETURN(-EINVAL);
		inode = pri_inode;
		search_older = 1;
	}

	table = &snap_tables[cache->cache_snap_tableno];

        for (slot = table->tbl_count ; slot >= 1; slot--)
        {
		struct address_space_operations *c_aops = 
					cache_inode->i_mapping->a_ops;
		cache_inode = NULL;
                index = table->snap_items[slot].index;
		cache_inode = snap_get_indirect(inode, NULL, index);

		if (!cache_inode )  continue;

		/* we only want slots between cache_inode to the oldest one */
		if(search_older && cache_inode->i_ino == ind_ino )
			search_older = 0;

                if (!search_older && c_aops->bmap(cache_inode->i_mapping, block)) 
                        break;
                iput(cache_inode);
        }
	if( pri_inode )
		iput(pri_inode);

	if ( !cache_inode )  
		RETURN(-EINVAL);

	currentfs_prepare_snapfile(inode, file, cache_inode, &open_file,
			      &open_dentry);

	down(&cache_inode->i_sem);

	if( c_aops->readpage ) {
		CDEBUG(D_SNAP, "block %lu NOT in cache, use redirected ino %lu\n", 
		       block, cache_inode->i_ino );
		result = c_aops->readpage(&open_file, page);
	}else {
		CDEBUG(D_SNAP, "cache ino %lu, readpage is NULL\n", 
		       cache_inode->i_ino);
	}
	up(&cache_inode->i_sem);
	currentfs_restore_snapfile(inode, file, cache_inode, &open_file);
	iput(cache_inode);
	RETURN(result);
}
struct address_space_operations currentfs_file_aops = {
	readpage:       currentfs_readpage,
};
                                                                                                                                                                                                     
struct file_operations currentfs_file_fops = {
	write:          currentfs_write,
};
                                                                                                                                                                                                     
struct inode_operations currentfs_file_iops = {
	revalidate:     NULL,
};

