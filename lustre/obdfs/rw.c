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

int console_loglevel;

/* SYNCHRONOUS I/O for an inode */
int obdfs_brw(int rw, struct inode *inode, struct page *page, int create)
{
	struct obdo *obdo;
	int res;

	obdo = obdo_alloc();
	if ( ! obdo ) {
		EXIT;
		return -ENOMEM;
	}

	obdo->o_id = inode->i_ino;

	res = IOPS(inode, brw)(rw, IID(inode), obdo, 
			       (char *)page_address(page), 
			       PAGE_SIZE,
			       (page->index) >> PAGE_SHIFT,
			       create);

	obdo_to_inode(inode, obdo); /* copy o_blocks to i_blocks */
	obdo_free(obdo);
	
	if ( res == PAGE_SIZE )
		res = 0;
	return res;
}

/* returns the page unlocked, but with a reference */
int obdfs_readpage(struct dentry *dentry, struct page *page)
{
	struct inode *inode = dentry->d_inode;
	int rc;

        ENTRY;
	PDEBUG(page, "READ");
	rc =  obdfs_brw(READ, inode, page, 0);
	if (!rc) {
		SetPageUptodate(page);
		UnlockPage(page);
	} 
	PDEBUG(page, "READ");
	EXIT;
	return rc;
}

static kmem_cache_t *obdfs_wreq_cachep;

int obdfs_init_wreqcache(void)
{
	/* XXX need to free this somewhere? */
	ENTRY;
	obdfs_wreq_cachep = kmem_cache_create("obdfs_wreq",
					      sizeof(struct obdfs_wreq),
					      0, SLAB_HWCACHE_ALIGN,
					      NULL, NULL);
	if (obdfs_wreq_cachep == NULL) {
		EXIT;
		return -ENOMEM;
	}
	EXIT;
	return 0;
}

void obdfs_cleanup_wreqcache(void)
{
	if (obdfs_wreq_cachep != NULL)
		kmem_cache_destroy(obdfs_wreq_cachep);
	
	obdfs_wreq_cachep = NULL;
}


/*
 * Find a specific page in the page cache.  If it is found, we return
 * the write request struct associated with it, if not found return NULL.
 */
static struct obdfs_wreq *
obdfs_find_in_page_cache(struct inode *inode, struct page *page)
{
	struct list_head *list_head = &OBD_LIST(inode);
	struct obdfs_wreq *head, *wreq;

	ENTRY;
	CDEBUG(D_INODE, "looking for inode %ld page %p\n", inode->i_ino, page);
	if (list_empty(list_head)) {
		CDEBUG(D_INODE, "empty list\n");
		EXIT;
		return NULL;
	}
	wreq = head = WREQ(list_head->next);
	do {
		CDEBUG(D_INODE, "checking page %p\n", wreq->wb_page);
		if (wreq->wb_page == page) {
			CDEBUG(D_INODE, "found page %p in list\n", page);
			EXIT;
			return wreq;
		}
	} while ((wreq = WB_NEXT(wreq)) != head);

	EXIT;
	return NULL;
}


/*
 * Remove a writeback request from a list
 */
static inline int
obdfs_remove_from_page_cache(struct obdfs_wreq *wreq)
{
	struct inode *inode = wreq->wb_inode;
	struct page *page = wreq->wb_page;
	int rc;

	ENTRY;
	CDEBUG(D_INODE, "removing inode %ld page %p, wreq: %p\n",
	       inode->i_ino, page, wreq);
	rc = obdfs_brw(WRITE, inode, page, 1);
	/* XXX probably should handle error here somehow.  I think that
	 *     ext2 also does the same thing - discard write even if error?
	 */
	put_page(page);
        list_del(&wreq->wb_list);
	kmem_cache_free(obdfs_wreq_cachep, wreq);

	EXIT;
	return rc;
}

/*
 * Add a page to the write request cache list for later writing
 */
static int
obdfs_add_to_page_cache(struct inode *inode, struct page *page)
{
	struct obdfs_wreq *wreq;

	ENTRY;
	wreq = kmem_cache_alloc(obdfs_wreq_cachep, SLAB_KERNEL);
	CDEBUG(D_INODE, "adding inode %ld page %p, wreq: %p\n",
	       inode->i_ino, page, wreq);
	if (!wreq) {
		EXIT;
		return -ENOMEM;
	}
	memset(wreq, 0, sizeof(*wreq)); 

	wreq->wb_page = page;
	wreq->wb_inode = inode;

	get_page(wreq->wb_page);
	list_add(&wreq->wb_list, &OBD_LIST(inode));

	/* For testing purposes, we write out the page here.
	 * In the future, a flush daemon will write out the page.
	 */
	wreq = obdfs_find_in_page_cache(inode, page);
	if (!wreq) {
		CDEBUG(D_INODE, "XXXX Can't find page after adding it!!!\n");
		return -EINVAL;
	} else
		return obdfs_remove_from_page_cache(wreq);

	return 0;
}


int obdfs_do_writepage(struct inode *inode, struct page *page, int sync)
{
	int rc;

        ENTRY;
	PDEBUG(page, "WRITEPAGE");
	if ( sync ) {
		rc = obdfs_brw(WRITE, inode, page, 1);
	} else {
		/* XXX flush stuff */
		rc = obdfs_add_to_page_cache(inode, page);
	}
		
	if (!rc)
		SetPageUptodate(page);
	PDEBUG(page,"WRITEPAGE");
	return rc;
}

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
 */
int obdfs_write_one_page(struct file *file, struct page *page, unsigned long offset, unsigned long bytes, const char * buf)
{
	long status;
        struct inode *inode = file->f_dentry->d_inode;

	ENTRY;
	if ( !Page_Uptodate(page) ) {
		status =  obdfs_brw(READ, inode, page, 1);
		if (!status) {
			SetPageUptodate(page);
		} else { 
			return status;
		}
	}
	bytes -= copy_from_user((u8*)page_address(page) + offset, buf, bytes);
	status = -EFAULT;

	if (bytes) {
		lock_kernel();
		status = obdfs_writepage(file->f_dentry, page);
		unlock_kernel();
	}
	EXIT;
	if ( status != PAGE_SIZE ) 
		return status;
	else
		return bytes;
}

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
	int rc;

        ENTRY;

	offset = offset & PAGE_CACHE_MASK;
	CDEBUG(D_INODE, "\n");
	
	page = NULL;
	page_cache = page_cache_alloc();
	if ( ! page_cache ) 
		return NULL;
	CDEBUG(D_INODE, "page_cache %p\n", page_cache);

	hash = page_hash(&inode->i_data, offset);
	page = grab_cache_page(&inode->i_data, offset);

	/* Yuck, no page */
	if (! page) {
	    printk("grab_cache_page says no dice ...\n");
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

	rc = obdfs_brw(READ, inode, page, create);

	if ( rc != PAGE_SIZE ) {
		SetPageError(page);
		UnlockPage(page);
		return page;
	}

	if ( !locked )
		UnlockPage(page);
	SetPageUptodate(page);
	PDEBUG(page,"GETPAGE - after reading");
	EXIT;
	return page;
}


