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

#include <../obd/linux/obd_support.h>
#include <../obd/linux/obd_sim.h>
#include <obdfs.h>

int console_loglevel;

/* VFS super_block ops */

/* returns the page unlocked, but with a reference */
int obdfs_readpage(struct file *file, struct page *page)
{
        struct obdfs_sb_info *sbi;
	struct super_block *sb = file->f_dentry->d_inode->i_sb;
	int rc;

        ENTRY;

	/* XXX flush stuff */
	sbi = sb->u.generic_sbp;
	PDEBUG(page, "READ");
	rc =  sbi->osi_ops->o_brw(READ, sbi->osi_conn_info.conn_id, 
		      file->f_dentry->d_inode, page, 0);
	if (rc == PAGE_SIZE ) {
		SetPageUptodate(page);
		UnlockPage(page);
	} 
	PDEBUG(page, "READ");
	if ( rc == PAGE_SIZE ) 
		rc = 0;
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
        struct obdfs_sb_info *sbi = file->f_dentry->d_inode->i_sb->u.generic_sbp;

	ENTRY;
	if ( !Page_Uptodate(page) ) {
		status =  sbi->osi_ops->o_brw(READ, 
					      sbi->osi_conn_info.conn_id, 
					      file->f_dentry->d_inode, 
					      page, 1);
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
		status = obdfs_writepage(file, page);
		unlock_kernel();
	}
	EXIT;
	if ( status != PAGE_SIZE ) 
		return status;
	else
		return bytes;
}




/* returns the page unlocked, but with a reference */
int obdfs_writepage(struct file *file, struct page *page)
{
        struct obdfs_sb_info *sbi = file->f_dentry->d_inode->i_sb->u.generic_sbp;
	int rc;

        ENTRY;
	PDEBUG(page, "WRITEPAGE");
	/* XXX flush stuff */

	rc = sbi->osi_ops->o_brw(WRITE, sbi->osi_conn_info.conn_id, 
		      file->f_dentry->d_inode, page, 1);

	SetPageUptodate(page);
	PDEBUG(page,"WRITEPAGE");
	return rc;
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
	struct obdfs_sb_info *sbi;
	struct super_block *sb = inode->i_sb;
	int rc;

        ENTRY;

	offset = offset & PAGE_CACHE_MASK;
	sbi = sb->u.generic_sbp;
	CDEBUG(D_INODE, "\n");
	
	page = NULL;
	page_cache = page_cache_alloc();
	if ( ! page_cache ) 
		return NULL;
	CDEBUG(D_INODE, "page_cache %p\n", page_cache);

	hash = page_hash(&inode->i_data, offset);
 repeat:
	CDEBUG(D_INODE, "Finding page\n");
	IDEBUG(inode);

	page = __find_lock_page(&inode->i_data, offset, hash); 
	if ( page ) {
		CDEBUG(D_INODE, "Page found freeing\n");
		page_cache_free(page_cache);
	} else {
		page = page_cache;
		if ( page->buffers ) {
			PDEBUG(page, "GETPAGE: buffers bug\n");
			UnlockPage(page);
			return NULL;
		}
		if (add_to_page_cache_unique(page, &inode->i_data, offset, hash)) {
			page_cache_release(page);
			CDEBUG(D_INODE, "Someone raced: try again\n");
			goto repeat;
		}
	}

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



	rc = sbi->osi_ops->o_brw(READ, sbi->osi_conn_info.conn_id, 
				    inode, page, create);
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


struct file_operations obdfs_file_ops = {
	NULL,			/* lseek - default */
	generic_file_read,	/* read */
	obdfs_file_write,     /* write - bad */
        obdfs_readdir,	        /* readdir */
	NULL,			/* poll - default */
	NULL,	                /* ioctl */
	NULL,			/* mmap */
	NULL,			/* no special open code */
	NULL,			/* flush */
	NULL,			/* no special release code */
	NULL,		        /* fsync */
	NULL,			/* fasync */
	NULL,			/* check_media_change */
	NULL			/* revalidate */
};

struct inode_operations obdfs_inode_ops = {
	&obdfs_file_ops,	/* default directory file-ops */
	obdfs_create,	/* create */
	obdfs_lookup,   /* lookup */
	obdfs_link,	/* link */
	obdfs_unlink,	/* unlink */
	obdfs_symlink,	/* symlink */
	obdfs_mkdir,	/* mkdir */
	obdfs_rmdir,	/* rmdir */
	obdfs_mknod,	/* mknod */
	obdfs_rename,	/* rename */
	NULL,		/* readlink */
	NULL,		/* follow_link */
	NULL,           /* get_block */
	obdfs_readpage,	/* readpage */
	obdfs_writepage, /* writepage */
	NULL,		/* flushpage */
	NULL,		/* truncate */
	NULL,		/* permission */
	NULL,		/* smap */
	NULL            /* revalidate */
};
