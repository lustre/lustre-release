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
		      file->f_dentry->d_inode->i_ino, page, 0);
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

	if ( !Page_Uptodate(page) ) {
		status =  sbi->osi_ops->o_brw(READ, 
					      sbi->osi_conn_info.conn_id, 
					      file->f_dentry->d_inode->i_ino, 
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
		      file->f_dentry->d_inode->i_ino, page, 1);
	SetPageUptodate(page);
	PDEBUG(page,"WRITEPAGE");
	return rc;
}


/* 
   page is returned unlocked, with the up to date flag set, 
   and held, i.e. caller must do a page_put
*/
struct page *obdfs_getpage(struct inode *inode, unsigned long offset, int create, int locked)
{
	unsigned long new_page;
	struct page ** hash;
	struct page * page; 
	struct obdfs_sb_info *sbi;
	struct super_block *sb = inode->i_sb;

        ENTRY;

	sbi = sb->u.generic_sbp;
	
	page = find_lock_page(inode, offset); 
	if (page && Page_Uptodate(page)) { 
		PDEBUG(page,"GETPAGE");
		if (!locked)
			UnlockPage(page);
		return page;
	} 
		
	if (page && !Page_Uptodate(page) ) {
		CDEBUG(D_INODE, "Page found but not up to date\n");
	}

	/* page_cache_alloc returns address of page */
	new_page = page_cache_alloc();
	if (!new_page)
		return NULL;
	
	/* corresponding struct page in the mmap */
	hash = page_hash(inode, offset);
	page = page_cache_entry(new_page);
	PDEBUG(page, "GETPAGE");
	if (!add_to_page_cache_unique(page, inode, offset, hash)) {
		CDEBUG(D_INODE, "Page not found. Reading it.\n");
		PDEBUG(page,"GETPAGE");
		sbi->osi_ops->o_brw(READ, sbi->osi_conn_info.conn_id, 
				    inode->i_ino, page, create);
		if ( !locked )
			UnlockPage(page);
		SetPageUptodate(page);
		PDEBUG(page,"GETPAGE");
		return page;
	}
	/*
	 * We arrive here in the unlikely event that someone 
	 * raced with us and added our page to the cache first.
	 */
	CDEBUG(D_INODE, "Page not found. Someone raced us.\n");
	PDEBUG(page,"GETPAGE");
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
