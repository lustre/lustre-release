/*
 * OBDFS Super operations
 *
 * Copyright (C) 1996, 1997, Olaf Kirch <okir@monad.swb.de>
 * Copryright (C) 1999 Stelias Computing Inc, 
 *                (author Peter J. Braam <braam@stelias.com>)
 * Copryright (C) 1999 Seagate Technology Inc.
*/


#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/segment.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#include <linux/obd_support.h>
#include <linux/obd_ext2.h>
#include <linux/obdfs.h>


/* SYNCHRONOUS I/O for an inode */
static int obdfs_brw(int rw, struct inode *inode, struct page *page, int create)
{
	obd_count	 num_obdo = 1;
	obd_count	 bufs_per_obdo = 1;
	struct obdo	*oa;
	char		*buf = (char *)page_address(page);
	obd_size	 count = PAGE_SIZE;
	obd_off		 offset = ((obd_off)page->index) << PAGE_SHIFT;
	obd_flag	 flags = create ? OBD_BRW_CREATE : 0;
	int		 err;

	ENTRY;
	oa = obdo_fromid(IID(inode), inode->i_ino, OBD_MD_FLNOTOBD);
	if ( IS_ERR(oa) ) {
		EXIT;
		return PTR_ERR(oa);
	}
	obdfs_from_inode(oa, inode);

	err = IOPS(inode, brw)(rw, IID(inode), num_obdo, &oa, &bufs_per_obdo,
			       &buf, &count, &offset, &flags);

	if ( !err )
		obdfs_to_inode(inode, oa); /* copy o_blocks to i_blocks */

	obdo_free(oa);
	
	EXIT;
	return err;
} /* obdfs_brw */

/* returns the page unlocked, but with a reference */
int obdfs_readpage(struct dentry *dentry, struct page *page)
{
	struct inode *inode = dentry->d_inode;
	int rc;

	ENTRY;
	/* PDEBUG(page, "READ"); */
	rc = obdfs_brw(READ, inode, page, 0);
	if ( !rc ) {
		SetPageUptodate(page);
		UnlockPage(page);
	} 
	/* PDEBUG(page, "READ"); */
	EXIT;
	return rc;
} /* obdfs_readpage */

static kmem_cache_t *obdfs_pgrq_cachep = NULL;

int obdfs_init_pgrqcache(void)
{
	ENTRY;
	if (obdfs_pgrq_cachep == NULL) {
		CDEBUG(D_CACHE, "allocating obdfs_pgrq_cache\n");
		obdfs_pgrq_cachep = kmem_cache_create("obdfs_pgrq",
						      sizeof(struct obdfs_pgrq),
						      0, SLAB_HWCACHE_ALIGN,
						      NULL, NULL);
		if (obdfs_pgrq_cachep == NULL) {
			EXIT;
			return -ENOMEM;
		} else {
			CDEBUG(D_CACHE, "allocated cache at %p\n",
			       obdfs_pgrq_cachep);
		}
	} else {
		CDEBUG(D_CACHE, "using existing cache at %p\n",
		       obdfs_pgrq_cachep);
	}
	EXIT;
	return 0;
} /* obdfs_init_wreqcache */

inline void obdfs_pgrq_del(struct obdfs_pgrq *pgrq)
{
	--obdfs_cache_count;
	CDEBUG(D_INFO, "deleting page %p from list [count %ld]\n",
	       pgrq->rq_page, obdfs_cache_count);
	list_del(&pgrq->rq_plist);
	kmem_cache_free(obdfs_pgrq_cachep, pgrq);
}

void obdfs_cleanup_pgrqcache(void)
{
	ENTRY;
	if (obdfs_pgrq_cachep != NULL) {
		CDEBUG(D_CACHE, "destroying obdfs_pgrqcache at %p, count %ld\n",
		       obdfs_pgrq_cachep, obdfs_cache_count);
		if (kmem_cache_destroy(obdfs_pgrq_cachep))
			printk(KERN_INFO __FUNCTION__
			       ": unable to free all of cache\n");
		obdfs_pgrq_cachep = NULL;
	} else
		printk(KERN_INFO __FUNCTION__ ": called with NULL pointer\n");

	EXIT;
} /* obdfs_cleanup_wreqcache */


/*
 * Find a specific page in the page cache.  If it is found, we return
 * the write request struct associated with it, if not found return NULL.
 * Called with the list lock held.
 */
static struct obdfs_pgrq *
obdfs_find_in_page_list(struct inode *inode, struct page *page)
{
	struct list_head *page_list = obdfs_iplist(inode);
	struct list_head *tmp;

	ENTRY;

	CDEBUG(D_INFO, "looking for inode %ld page %p\n", inode->i_ino, page);
	OIDEBUG(inode);

	if (list_empty(page_list)) {
		CDEBUG(D_INFO, "empty list\n");
		EXIT;
		return NULL;
	}
	tmp = page_list;
	while ( (tmp = tmp->next) != page_list ) {
		struct obdfs_pgrq *pgrq;

		pgrq = list_entry(tmp, struct obdfs_pgrq, rq_plist);
		if (pgrq->rq_page == page) {
			CDEBUG(D_INFO, "found page %p in list\n", page);
			EXIT;
			return pgrq;
		}
	} 

	EXIT;
	return NULL;
} /* obdfs_find_in_page_list */


/* called with the list lock held */
static struct page *obdfs_find_page_index(struct inode *inode,
					  unsigned long index)
{
	struct list_head *page_list = obdfs_iplist(inode);
	struct list_head *tmp;
	struct page *page;

	ENTRY;

	CDEBUG(D_INFO, "looking for inode %ld pageindex %ld\n",
	       inode->i_ino, index);
	OIDEBUG(inode);

	if (list_empty(page_list)) {
		EXIT;
		return NULL;
	}
	tmp = page_list;
	while ( (tmp = tmp->next) != page_list ) {
		struct obdfs_pgrq *pgrq;

		pgrq = list_entry(tmp, struct obdfs_pgrq, rq_plist);
		page = pgrq->rq_page;
		if (index == page->index) {
			CDEBUG(D_INFO,
			       "INDEX SEARCH found page %p, index %ld\n",
			       page, index);
			EXIT;
			return page;
		}
	} 

	EXIT;
	return NULL;
} /* obdfs_find_page_index */


/* call and free pages from Linux page cache: called with io lock on inodes */
int obdfs_do_vec_wr(struct inode **inodes, obd_count num_io,
		    obd_count num_obdos, struct obdo **obdos,
		    obd_count *oa_bufs, struct page **pages, char **bufs,
		    obd_size *counts, obd_off *offsets, obd_flag *flags)
{
	struct super_block *sb = inodes[0]->i_sb;
	struct obdfs_sb_info *sbi = (struct obdfs_sb_info *)&sb->u.generic_sbp;
	int err;

	ENTRY;
	CDEBUG(D_INFO, "writing %d page(s), %d obdo(s) in vector\n",
	       num_io, num_obdos);
	{ /* DEBUGGING */
		int i;
		printk("OBDOS: ");
		for (i = 0; i < num_obdos; i++)
			printk("%ld:0x%p ", (long)obdos[i]->o_id, obdos[i]);

		printk("\nPAGES: ");
		for (i = 0; i < num_io; i++)
			printk("0x%p ", pages[i]);
		printk("\n");
	}

	err = OPS(sb, brw)(WRITE, &sbi->osi_conn, num_obdos, obdos, oa_bufs,
				bufs, counts, offsets, flags);

	CDEBUG(D_CACHE, "BRW done\n");
	/* release the pages from the page cache */
	while ( num_io > 0 ) {
		--num_io;
		CDEBUG(D_INFO, "calling put_page for %p, index %ld\n",
		       pages[num_io], pages[num_io]->index);
		/* PDEBUG(pages[num_io], "do_vec_wr"); */
		put_page(pages[num_io]);
		/* PDEBUG(pages[num_io], "do_vec_wr"); */
	}
	CDEBUG(D_CACHE, "put_page done\n");

	while ( num_obdos > 0) {
		--num_obdos;
		CDEBUG(D_INFO, "free obdo %ld\n",(long)obdos[num_obdos]->o_id);
		obdfs_to_inode(inodes[num_obdos], obdos[num_obdos]);
		obdo_free(obdos[num_obdos]);
	}
	CDEBUG(D_CACHE, "obdo_free done\n");
	EXIT;
	return err;
}


/*
 * Add a page to the write request cache list for later writing
 * ASYNCHRONOUS write method.
 */
static int obdfs_add_page_to_cache(struct inode *inode, struct page *page)
{
	int res = 0;

	ENTRY;

	/* If this page isn't already in the inode page list, add it */
	obd_down(&obdfs_i2sbi(inode)->osi_list_mutex);
	if ( !obdfs_find_in_page_list(inode, page) ) {
		struct obdfs_pgrq *pgrq;
		pgrq = kmem_cache_alloc(obdfs_pgrq_cachep, SLAB_KERNEL);
		if (!pgrq) {
			EXIT;
			obd_up(&obdfs_i2sbi(inode)->osi_list_mutex);
			return -ENOMEM;
		}
		memset(pgrq, 0, sizeof(*pgrq)); 
		
		pgrq->rq_page = page;
		pgrq->rq_jiffies = jiffies;
		get_page(pgrq->rq_page);
		list_add(&pgrq->rq_plist, obdfs_iplist(inode));
		obdfs_cache_count++;
		CDEBUG(D_INFO,
		       "added inode %ld page %p, pgrq: %p, cache count [%ld]\n",
		       inode->i_ino, page, pgrq, obdfs_cache_count);
	}

	/* If inode isn't already on the superblock inodes list, add it,
	 * and increase ref count on inode so it doesn't disappear on us.
	 *
	 * We increment the reference count on the inode to keep it from
	 * being freed from memory.  This _should_ be an iget() with an
	 * iput() in both flush_reqs() and put_inode(), but since put_inode()
	 * is called from iput() we can't call iput() again there.  Instead
	 * we just increment/decrement i_count, which is essentially what
	 * iget/iput do for an inode already in memory.
	 */
	if ( list_empty(obdfs_islist(inode)) ) {
		inode->i_count++;
		CDEBUG(D_INFO, "adding inode %ld to superblock list %p\n",
		       inode->i_ino, obdfs_slist(inode));
		list_add(obdfs_islist(inode), obdfs_slist(inode));
	}
	obd_up(&obdfs_i2sbi(inode)->osi_list_mutex);

	/* XXX For testing purposes, we write out the page here.
	 *     In the future, a flush daemon will write out the page.
	res = obdfs_flush_reqs(obdfs_slist(inode), ~0UL);
	 */

	EXIT;
	return res;
} /* obdfs_add_page_to_cache */


/* select between SYNC and ASYNC I/O methods */
int obdfs_do_writepage(struct inode *inode, struct page *page, int sync)
{
	int err;

	ENTRY;
	/* PDEBUG(page, "WRITEPAGE"); */
	if ( sync )
		err = obdfs_brw(WRITE, inode, page, 1);
	else {
		err = obdfs_add_page_to_cache(inode, page);
		CDEBUG(D_INFO, "DO_WR ino: %ld, page %p, err %d, uptodate %d\n",
		       inode->i_ino, page, err, Page_Uptodate(page));
	}
		
	if ( !err )
		SetPageUptodate(page);
	/* PDEBUG(page,"WRITEPAGE"); */
	EXIT;
	return err;
} /* obdfs_do_writepage */

/* returns the page unlocked, but with a reference */
int obdfs_writepage(struct dentry *dentry, struct page *page)
{
	return obdfs_do_writepage(dentry->d_inode, page, 0);
}

/*
 * This does the "real" work of the write. The generic routine has
 * allocated the page, locked it, done all the page alignment stuff
 * calculations etc. Now we should just copy the data from user
 * space and write it back to the real medium..
 *
 * If the writer ends up delaying the write, the writer needs to
 * increment the page use counts until he is done with the page.
 *
 * Return value is the number of bytes written.
 */
int obdfs_write_one_page(struct file *file, struct page *page,
			 unsigned long offset, unsigned long bytes,
			 const char * buf)
{
	struct inode *inode = file->f_dentry->d_inode;
	int err;

	ENTRY;
	/* We check for complete page writes here, as we then don't have to
	 * get the page before writing over everything anyways.
	 */
	if ( !Page_Uptodate(page) && (offset != 0 || bytes != PAGE_SIZE) ) {
		err = obdfs_brw(READ, inode, page, 0);
		if ( err )
			return err;
		SetPageUptodate(page);
	}

	if (copy_from_user((u8*)page_address(page) + offset, buf, bytes))
		return -EFAULT;

	lock_kernel(); /* XXX do we really need to lock the kernel to write? */
	err = obdfs_writepage(file->f_dentry, page);
	unlock_kernel();

	return (err < 0 ? err : bytes);
} /* obdfs_write_one_page */

/* 
 * return an up to date page:
 *  - if locked is true then is returned locked
 *  - if create is true the corresponding disk blocks are created 
 *  - page is held, i.e. caller must release the page
 *
 * modeled on NFS code.
 */
struct page *obdfs_getpage(struct inode *inode, unsigned long offset,
			   int create, int locked)
{
	struct page * page;
	int index;
	int err;

	ENTRY;

	offset = offset & PAGE_CACHE_MASK;
	CDEBUG(D_INFO, "ino: %ld, offset %ld, create %d, locked %d\n",
	       inode->i_ino, offset, create, locked);
	index = offset >> PAGE_CACHE_SHIFT;

	page = grab_cache_page(&inode->i_data, index);

	/* Yuck, no page */
	if (! page) {
	    printk(KERN_WARNING " grab_cache_page says no dice ...\n");
	    EXIT;
	    return NULL;
	}

	/* PDEBUG(page, "GETPAGE: got page - before reading\n"); */
	/* now check if the data in the page is up to date */
	if ( Page_Uptodate(page)) { 
		if (!locked)
			UnlockPage(page);
		EXIT;
		return page;
	} 


#ifdef EXT2_OBD_DEBUG
	if ((obd_debug_level & D_INFO) && obdfs_find_page_index(inode, index)) {
		CDEBUG(D_INFO, "OVERWRITE: found dirty page %p, index %ld\n",
		       page, page->index);
	}
#endif

	err = obdfs_brw(READ, inode, page, create);

	if ( err ) {
		SetPageError(page);
		UnlockPage(page);
		EXIT;
		return page;
	}

	if ( !locked )
		UnlockPage(page);
	SetPageUptodate(page);
	/* PDEBUG(page,"GETPAGE - after reading"); */
	EXIT;
	return page;
} /* obdfs_getpage */


