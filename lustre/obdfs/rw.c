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


int obdfs_flush_reqs(struct list_head *page_list, 
		     int flush_inode, int check_time);


/* SYNCHRONOUS I/O for an inode */
static int obdfs_brw(int rw, struct inode *inode, struct page *page, int create)
{
	obd_count	 num_io = 1;
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

	err = IOPS(inode, brw)(rw, IID(inode), &num_io, &oa, &buf, &count,
			       &offset, &flags);

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
	PDEBUG(page, "READ");
	rc = obdfs_brw(READ, inode, page, 0);
	if ( !rc ) {
		SetPageUptodate(page);
		UnlockPage(page);
	} 
	PDEBUG(page, "READ");
	EXIT;
	return rc;
} /* obdfs_readpage */

static kmem_cache_t *obdfs_pgrq_cachep = NULL;

int obdfs_init_pgrqcache(void)
{
	ENTRY;
	if (obdfs_pgrq_cachep == NULL) {
		CDEBUG(D_INODE, "allocating obdfs_pgrq_cache\n");
		obdfs_pgrq_cachep = kmem_cache_create("obdfs_pgrq",
						      sizeof(struct obdfs_pgrq),
						      0, SLAB_HWCACHE_ALIGN,
						      NULL, NULL);
		if (obdfs_pgrq_cachep == NULL) {
			EXIT;
			return -ENOMEM;
		} else {
			CDEBUG(D_INODE, "allocated cache at %p\n",
			       obdfs_pgrq_cachep);
		}
	} else {
		CDEBUG(D_INODE, "using existing cache at %p\n",
		       obdfs_pgrq_cachep);
	}
	EXIT;
	return 0;
} /* obdfs_init_wreqcache */

inline void obdfs_pgrq_del(struct obdfs_pgrq *pgrq)
{
		list_del(&pgrq->rq_ilist);
		list_del(&pgrq->rq_slist);
		kmem_cache_free(obdfs_pgrq_cachep, pgrq);
}

void obdfs_cleanup_pgrqcache(void)
{
	ENTRY;
	if (obdfs_pgrq_cachep != NULL) {
		CDEBUG(D_INODE, "destroying obdfs_pgrqcache at %p\n",
		       obdfs_pgrq_cachep);
		if (kmem_cache_destroy(obdfs_pgrq_cachep))
			printk(KERN_INFO "obd_cleanup_pgrqcache: unable to free all of cache\n");
	} else
		printk(KERN_INFO "obd_cleanup_pgrqcache: called with NULL cache pointer\n");

	EXIT;
} /* obdfs_cleanup_wreqcache */


/*
 * Find a specific page in the page cache.  If it is found, we return
 * the write request struct associated with it, if not found return NULL.
 */
#if 0
static struct obdfs_pgrq *
obdfs_find_in_page_cache(struct inode *inode, struct page *page)
{
	struct list_head *page_list = &OBDFS_LIST(inode);
	struct list_head *tmp;
	struct obdfs_pgrq *pgrq;

	ENTRY;
	CDEBUG(D_INODE, "looking for inode %ld page %p\n", inode->i_ino, page);
	if (list_empty(page_list)) {
		CDEBUG(D_INODE, "empty list\n");
		EXIT;
		return NULL;
	}
	tmp = page_list;
	while ( (tmp = tmp->next) != page_list ) {
		pgrq = list_entry(tmp, struct obdfs_pgrq, rq_list);
		CDEBUG(D_INODE, "checking page %p\n", pgrq->rq_page);
		if (pgrq->rq_page == page) {
			CDEBUG(D_INODE, "found page %p in list\n", page);
			EXIT;
			return pgrq;
		}
	} 

	EXIT;
	return NULL;
} /* obdfs_find_in_page_cache */
#endif


int obdfs_do_vec_wr(struct super_block *sb, obd_count *num_io, 
			   struct obdo **obdos,
			   struct page **pages, char **bufs, obd_size *counts,
			   obd_off *offsets, obd_flag *flags)
{
	int last_io = *num_io;
	int err;
	struct obdfs_sb_info *sbi = (struct obdfs_sb_info *)&sb->u.generic_sbp;
	ENTRY;
	CDEBUG(D_INODE, "writing %d pages in vector\n", last_io);
	err = OPS(sb, brw)(WRITE, &sbi->osi_conn, num_io, obdos,
				bufs, counts, offsets, flags);

	do {
		put_page(pages[--last_io]);
	} while ( last_io > 0 );

	EXIT;
	return err;
}


/*
 * Add a page to the write request cache list for later writing
 * ASYNCHRONOUS write method.
 */
static int obdfs_add_page_to_cache(struct inode *inode, struct page *page)
{
	struct obdfs_pgrq *pgrq;
	int rc = 0; 

	ENTRY;
	pgrq = kmem_cache_alloc(obdfs_pgrq_cachep, SLAB_KERNEL);
	CDEBUG(D_INODE, "adding inode %ld page %p, pgrq: %p\n",
	       inode->i_ino, page, pgrq);
	if (!pgrq) {
		EXIT;
		return -ENOMEM;
	}
	memset(pgrq, 0, sizeof(*pgrq)); 

	pgrq->rq_page = page;
	pgrq->rq_inode = inode;

	get_page(pgrq->rq_page);
	list_add(&pgrq->rq_ilist, obdfs_ilist(inode));
	list_add(&pgrq->rq_slist, obdfs_slist(inode));

	/* XXX For testing purposes, we write out the page here.
	 *     In the future, a flush daemon will write out the page.
	return 0;
	 */
	rc = obdfs_flush_reqs(obdfs_slist(inode), 0, 0);
	EXIT;
	return rc;
} /* obdfs_add_page_to_cache */


/* select between SYNC and ASYNC I/O methods */
int obdfs_do_writepage(struct inode *inode, struct page *page, int sync)
{
	int err;

	ENTRY;
	PDEBUG(page, "WRITEPAGE");
	if ( sync )
		err = obdfs_brw(WRITE, inode, page, 1);
	else
		err = obdfs_add_page_to_cache(inode, page);
		
	if ( !err )
		SetPageUptodate(page);
	PDEBUG(page,"WRITEPAGE");
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
	if ( !Page_Uptodate(page) ) {
		err = obdfs_brw(READ, inode, page, 1);
		if ( !err )
			SetPageUptodate(page);
		else
			return err;
	}

	if (copy_from_user((u8*)page_address(page) + offset, buf, bytes))
		return -EFAULT;

	lock_kernel();
	err = obdfs_writepage(file->f_dentry, page);
	unlock_kernel();

	return (err < 0 ? err : bytes);
} /* obdfs_write_one_page */

/* 
   return an up to date page:
    - if locked is true then is returned locked
    - if create is true the corresponding disk blocks are created 
    - page is held, i.e. caller must release the page

   modeled on NFS code.
*/
struct page *obdfs_getpage(struct inode *inode, unsigned long offset, int create, int locked)
{
	struct page *page_cache;
	struct page ** hash;
	struct page * page;
	int err;

	ENTRY;

	offset = offset & PAGE_CACHE_MASK;
	CDEBUG(D_INODE, "\n");
	
	page = NULL;
	page_cache = page_cache_alloc();
	if ( ! page_cache ) {
		EXIT;
		return NULL;
	}
	CDEBUG(D_INODE, "page_cache %p\n", page_cache);

	hash = page_hash(&inode->i_data, offset);
	page = grab_cache_page(&inode->i_data, offset);

	/* Yuck, no page */
	if (! page) {
	    printk("grab_cache_page says no dice ...\n");
	    EXIT;
	    return 0;
	}

	PDEBUG(page, "GETPAGE: got page - before reading\n");
	/* now check if the data in the page is up to date */
	if ( Page_Uptodate(page)) { 
		if (!locked)
			UnlockPage(page);
		EXIT;
		return page;
	} 

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
	PDEBUG(page,"GETPAGE - after reading");
	EXIT;
	return page;
} /* obdfs_getpage */


