/*
 * OBDFS Super operations
 *
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

/* VFS super_block ops */

#if 0
int obdfs_brw(struct inode *dir, int rw, struct page *page, int create)
{
	return iops(dir)->o_brw(rw, iid(dir), dir, page, create);
}
#endif

/* returns the page unlocked, but with a reference */
int obdfs_readpage(struct dentry *dentry, struct page *page)
{
	struct inode *inode = dentry->d_inode;
	int rc;

        ENTRY;
	/* XXX flush stuff */
	PDEBUG(page, "READ");
	rc =  iops(inode)->o_brw(READ, iid(inode),inode, page, 0);
	if (rc == PAGE_SIZE ) {
		SetPageUptodate(page);
		UnlockPage(page);
	} 
	PDEBUG(page, "READ");
	if ( rc == PAGE_SIZE ) 
		rc = 0;
	return rc;

}

/* returns the page unlocked, but with a reference */
int obdfs_writepage(struct dentry *dentry, struct page *page)
{
        struct inode *inode = dentry->d_inode;
	int rc;

        ENTRY;
	PDEBUG(page, "WRITEPAGE");
	/* XXX flush stuff */

	rc = iops(inode)->o_brw(WRITE, iid(inode), inode, page, 1);

	SetPageUptodate(page);
	PDEBUG(page,"WRITEPAGE");
	return rc;
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
		status =  iops(inode)->o_brw(READ, iid(inode), inode, page, 1);
		if (status == PAGE_SIZE ) {
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





void report_inode(struct page * page) {
	struct inode *inode = (struct inode *)0;
	int offset = (int)&inode->i_data;
	inode = (struct inode *)( (char *)page->mapping - offset);
	if ( inode->i_sb->s_magic == 0x4711 )
		printk("----> ino %ld , dev %d\n", inode->i_ino, inode->i_dev);
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

	PDEBUG(page, "GETPAGE: got page - before reading\n");
	/* now check if the data in the page is up to date */
	if ( Page_Uptodate(page)) { 
		if (!locked)
			UnlockPage(page);
		EXIT;
		return page;
	} 

	/* it's not: read it */
	if (! page) {
	    printk("get_page_map says no dice ...\n");
	    return 0;
	}

	rc = iops(inode)->o_brw(READ, iid(inode), inode, page, create);
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


