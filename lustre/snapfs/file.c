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
#include <linux/pagemap.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>

#include "snapfs_internal.h" 

static int has_pages(struct inode *inode, int index)
{
	unsigned long offset = index << PAGE_CACHE_SHIFT;
	unsigned long blk_start = offset >> inode->i_sb->s_blocksize_bits; 
	unsigned long blk_end = (offset + PAGE_CACHE_SIZE) >> inode->i_sb->s_blocksize_bits; 
	int inside = 0;

	while (blk_start <= blk_end) {
		if (inode->i_mapping && inode->i_mapping->a_ops) {
			inside = inode->i_mapping->a_ops->bmap(inode->i_mapping, blk_start);	
		}
		blk_start++;
	}
	return inside;
}

static int copy_back_page(struct inode *dst, struct inode *src,
			   int index)
{
	char *kaddr_src, *kaddr_dst;
        struct snap_cache *cache;
	struct address_space_operations *c_aops;
	struct page *src_page, *dst_page;
	int    err = 0;
	ENTRY;

	if (!has_pages(src, index)) 
		RETURN(0);

	cache = snap_find_cache(src->i_dev);
	if (!cache) 
		RETURN(-EINVAL);
	c_aops = filter_c2cfaops(cache->cache_filter);
	
	if (!c_aops) 
		RETURN(-EINVAL);

	src_page = grab_cache_page(src->i_mapping, index);
	if (!src_page) {
		CERROR("copy block %d from %lu to %lu ENOMEM \n",
			  index, src->i_ino, dst->i_ino);
		RETURN(-ENOMEM);
	}
	
	c_aops->readpage(NULL, src_page);
	wait_on_page(src_page);
	
	kaddr_src = kmap(src_page);
	if (!Page_Uptodate(src_page)) {
		CERROR("Can not read page index %d of inode %lu\n",
			  index, src->i_ino);
		err = -EIO;
		goto unlock_src_page;
	}
	dst_page = grab_cache_page(dst->i_mapping, index);
	if (!dst_page) {
		CERROR("copy block %d from %lu to %lu ENOMEM \n",
			  index, src->i_ino, dst->i_ino);
		err = -ENOMEM;
		goto unlock_src_page;
	}	
	kaddr_dst = kmap(dst_page);

	err = c_aops->prepare_write(NULL, dst_page, 0, PAGE_CACHE_SIZE);
	if (err) 
		goto unlock_dst_page; 
	memcpy(kaddr_dst, kaddr_src, PAGE_CACHE_SIZE);
	flush_dcache_page(dst_page);

	err = c_aops->commit_write(NULL, dst_page, 0, PAGE_CACHE_SIZE);
	if (err) 
		goto unlock_dst_page; 
	err = 1;
unlock_dst_page:
	kunmap(dst_page);
	UnlockPage(dst_page);
	page_cache_release(dst_page);
unlock_src_page:
	kunmap(src_page);
	page_cache_release(src_page);
	RETURN(err);
}

static ssize_t currentfs_write (struct file *filp, const char *buf, 
				size_t count, loff_t *ppos)
{
        struct snap_cache *cache;
	struct inode *inode = filp->f_dentry->d_inode;
        struct file_operations *fops;
	long   page[2]={-1,-1};
	struct snap_table *table;
	struct inode *cache_inode = NULL;
	int slot = 0, index = 0, result = 0;
	long i;
        ssize_t rc;
	loff_t pos;
  
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
#if 0
	mask = inode->i_sb->s_blocksize-1;
	if( pos & mask )
		block[0] = pos >> inode->i_sb->s_blocksize_bits;
	pos += count - 1;
	if( (pos+1) &  mask )
		block[1] = pos >> inode->i_sb->s_blocksize_bits;
	if( block[0] == block[1] )
		block[1] = -1;
	
	snapops = filter_c2csnapops(cache->cache_filter);

	for (i = 0; i < 2; i++) {
		if (block[i] == -1) 
			continue;
		table = &snap_tables[cache->cache_snap_tableno];
		/*Find the nearest block in snaptable and copy back it*/
		for (slot = table->tbl_count - 1; slot >= 1; slot--) {
			cache_inode = NULL;
               		index = table->snap_items[slot].index;
			cache_inode = snap_get_indirect(inode, NULL, index);

			if (!cache_inode)  continue;

			CDEBUG(D_SNAP, "find cache_ino %lu\n", cache_inode->i_ino);
		
			if (snapops && snapops->copy_block) {
				result = snapops->copy_block(inode, cache_inode, block[i]);
				if (result == 1) {
					CDEBUG(D_SNAP, "copy block %lu back from ind %lu to %lu\n", 
					       block[i], cache_inode->i_ino, inode->i_ino);
               				iput(cache_inode);
					result = 0;
					break;
				}
				if (result < 0) {
					iput(cache_inode);
					rc = result;
					goto exit;
				}
			}
               		iput(cache_inode);
        	}
	}
#else
	if (pos & PAGE_CACHE_MASK)
		page[0] = pos >> PAGE_CACHE_SHIFT;
	pos += count - 1;
	if ((pos+1) & PAGE_CACHE_MASK)
		page[1] = pos >> PAGE_CACHE_SHIFT;
	if (page[0] == page[1])
		page[1] = -1;
	
	for (i = 0; i < 2; i++) {
		if (page[i] == -1) 
			continue;
		table = &snap_tables[cache->cache_snap_tableno];
		/*Find the nearest page in snaptable and copy back it*/
		for (slot = table->tbl_count - 1; slot >= 1; slot--) {
			cache_inode = NULL;
               		index = table->snap_items[slot].index;
			cache_inode = snap_get_indirect(inode, NULL, index);

			if (!cache_inode)  continue;

			CDEBUG(D_SNAP, "find cache_ino %lu\n", cache_inode->i_ino);
		
			result = copy_back_page(inode, cache_inode, page[i]);
			if (result == 1) {
				CDEBUG(D_SNAP, "copy page%lu back from ind %lu to %lu\n", 
				       page[i], cache_inode->i_ino, inode->i_ino);
               			iput(cache_inode);
				result = 0;
				break;
			}
			if (result < 0) {
				iput(cache_inode);
				rc = result;
				goto exit;
			}
               		iput(cache_inode);
        	}
	}
#endif
	rc = fops->write(filp, buf, count, ppos);
exit:
        RETURN(rc);
}

static int currentfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file->f_dentry->d_inode;
	unsigned long ind_ino = inode->i_ino;
	struct inode *pri_inode = NULL;
	struct inode *cache_inode = NULL;
	struct address_space_operations *c_aops;
	struct snap_cache *cache;
	struct snap_table *table;
	struct page *cache_page = NULL;
	int rc = 0, slot = 0, index = 0, search_older = 0;
 	long block;

	ENTRY;

	cache = snap_find_cache(inode->i_dev);
	if ( !cache ) { 
		RETURN(-EINVAL);
	}
	
	c_aops = filter_c2cfaops(cache->cache_filter);

	block = page->index >> inode->i_sb->s_blocksize_bits;

	/* if there is a block in the cache, return the cache readpage */
	if(c_aops->bmap(inode->i_mapping, block) ) {
		CDEBUG(D_SNAP, "block %lu in cache, ino %lu\n", 
				block, inode->i_ino);
		rc = c_aops->readpage(file, page);
		RETURN(rc);
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

        for (slot = table->tbl_count - 1; slot >= 1; slot--) {
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
	if (pri_inode) iput(pri_inode);

	if (!cache_inode )  
		RETURN(-EINVAL);

	down(&cache_inode->i_sem);

	/*Here we have changed a file to read,
	 *So we should rewrite generic file read here 
	 *FIXME later, the code is ugly
	 */
	
	cache_page = grab_cache_page(cache_inode->i_mapping, page->index);
	if (!cache_page) 
		GOTO(exit_release, rc = -ENOMEM);
	if ((rc = c_aops->readpage(file, cache_page)))
		GOTO(exit_release, 0);
	
	wait_on_page(cache_page);

	if (!Page_Uptodate(cache_page))
		GOTO(exit_release, rc = -EIO);

	memcpy(kmap(page), kmap(cache_page), PAGE_CACHE_SIZE);

	kunmap(cache_page);
	page_cache_release(cache_page);

	up(&cache_inode->i_sem);
	iput(cache_inode);
	
	kunmap(page);
	SetPageUptodate(page);
	UnlockPage(page);

	RETURN(rc);

exit_release:
	if (cache_page) 
		page_cache_release(cache_page);
	up(&cache_inode->i_sem);
	iput(cache_inode);
	UnlockPage(page);
	RETURN(rc);
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

