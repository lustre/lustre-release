/*
 * Lustre Light I/O Page Cache
 *
 * Copyright (C) 2002, Cluster File Systems, Inc. 
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
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_light.h>

/*
 * Add a page to the dirty page list.
 */
void __set_page_dirty(struct page *page)
{
        struct address_space *mapping;
        spinlock_t *pg_lock;

        pg_lock = PAGECACHE_LOCK(page);
        spin_lock(pg_lock);

        mapping = page->mapping;
        spin_lock(&mapping->page_lock);

        list_del(&page->list);
        list_add(&page->list, &mapping->dirty_pages);

        spin_unlock(&mapping->page_lock);
        spin_unlock(pg_lock);

        if (mapping->host)
                mark_inode_dirty_pages(mapping->host);
}

static void inline ll_oa_from_inode(struct obdo *oa, struct inode *inode)
{
        struct ll_inode_info *oinfo = ll_i2info(inode);

        if ( oa->o_valid & OBD_MD_FLID )
                oa->o_id = oinfo->lli_objid;
        if ( oa->o_valid & OBD_MD_FLATIME )
                oa->o_atime = inode->i_atime;
        if ( oa->o_valid & OBD_MD_FLMTIME )
                oa->o_mtime = inode->i_mtime;
        if ( oa->o_valid & OBD_MD_FLCTIME )
                oa->o_ctime = inode->i_ctime;
        if ( oa->o_valid & OBD_MD_FLSIZE )
                oa->o_size = inode->i_size;
        if ( oa->o_valid & OBD_MD_FLBLOCKS )   /* allocation of space */
                oa->o_blocks = inode->i_blocks;
        if ( oa->o_valid & OBD_MD_FLBLKSZ )
                oa->o_blksize = inode->i_blksize;
        if ( oa->o_valid & OBD_MD_FLMODE )
                oa->o_mode = inode->i_mode;
        if ( oa->o_valid & OBD_MD_FLUID )
                oa->o_uid = inode->i_uid;
        if ( oa->o_valid & OBD_MD_FLGID )
                oa->o_gid = inode->i_gid;
        if ( oa->o_valid & OBD_MD_FLFLAGS )
                oa->o_flags = inode->i_flags;
        if ( oa->o_valid & OBD_MD_FLNLINK )
                oa->o_nlink = inode->i_nlink;
        if ( oa->o_valid & OBD_MD_FLGENER ) 
                oa->o_generation = inode->i_generation;

        CDEBUG(D_INFO, "src inode %ld, dst obdo %ld valid 0x%08x\n",
               inode->i_ino, (long)oa->o_id, oa->o_valid);
        obdo_from_inode(oa, inode);
	
	/* this will transfer metadata for the logical object to 
	   the oa: that metadata could contain the constituent objects
	*/
	if (ll_has_inline(inode)) {
                CDEBUG(D_INODE, "copying inline data from inode to obdo\n");
                memcpy(oa->o_inline, oinfo->lli_inline, OBD_INLINESZ);
                oa->o_obdflags |= OBD_FL_INLINEDATA;
                oa->o_valid |= OBD_MD_FLINLINE;
        }
} /* ll_oa_from_inode */

/*
 * Add a page to the dirty page list.
 */
#if 0
void set_page_dirty(struct page *page)
{
	if (!test_and_set_bit(PG_dirty, &page->flags)) {
		struct address_space *mapping = page->mapping;

		if (mapping) {
			list_del(&page->list);
			list_add(&page->list, &mapping->dirty_pages);

			if (mapping->host)
				mark_inode_dirty_pages(mapping->host);
		}
	}
}
#endif



/*
 * Remove page from dirty list
 */
void __set_page_clean(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode;
	
	if (!mapping)
		return;

	list_del(&page->list);
	list_add(&page->list, &mapping->clean_pages);

	inode = mapping->host;
	if (list_empty(&mapping->dirty_pages)) { 
		CDEBUG(D_INODE, "inode clean\n");
		inode->i_state &= ~I_DIRTY_PAGES;
	}
	EXIT;
}

inline void set_page_clean(struct page *page)
{
	if (PageDirty(page)) { 
		ClearPageDirty(page);
		__set_page_clean(page);
	}
}

/* SYNCHRONOUS I/O to object storage for an inode -- object attr will be updated too */
static int ll_brw(int rw, struct inode *inode, struct page *page, int create)
{
        obd_count        num_obdo = 1;
        obd_count        bufs_per_obdo = 1;
        struct obdo     *oa;
        obd_size         count = PAGE_SIZE;
        obd_off          offset = ((obd_off)page->index) << PAGE_SHIFT;
        obd_flag         flags = create ? OBD_BRW_CREATE : 0;
        int              err;

        ENTRY;

        oa = obdo_alloc();
        if ( !oa ) {
                EXIT;
                return -ENOMEM;
        }
	oa->o_valid = OBD_MD_FLNOTOBD;
        ll_oa_from_inode(oa, inode);

        err = obd_brw(rw, IID(inode), num_obdo, &oa, &bufs_per_obdo,
                               &page, &count, &offset, &flags);
        //if ( !err )
	//      ll_to_inode(inode, oa); /* copy o_blocks to i_blocks */

        obdo_free(oa);
        EXIT;
        return err;
} /* ll_brw */

extern void set_page_clean(struct page *);

/* SYNCHRONOUS I/O to object storage for an inode -- object attr will be updated too */
static int ll_commit_page(struct page *page, int create, int from, int to)
{
	struct inode *inode = page->mapping->host;
        obd_count        num_obdo = 1;
        obd_count        bufs_per_obdo = 1;
        struct obdo     *oa;
        obd_size         count = to;
        obd_off          offset = (((obd_off)page->index) << PAGE_SHIFT);
        obd_flag         flags = create ? OBD_BRW_CREATE : 0;
        int              err;

        ENTRY;
        oa = obdo_alloc();
        if ( !oa ) {
                EXIT;
                return -ENOMEM;
        }
	oa->o_valid = OBD_MD_FLNOTOBD;
        ll_oa_from_inode(oa, inode);

	CDEBUG(D_INODE, "commit_page writing (at %d) to %d, count %Ld\n", 
	       from, to, count);

        err = obd_brw(WRITE, IID(inode), num_obdo, &oa, &bufs_per_obdo,
                               &page, &count, &offset, &flags);
        if ( !err ) {
                SetPageUptodate(page);
		set_page_clean(page);
	}

        //if ( !err )
	//      ll_to_inode(inode, oa); /* copy o_blocks to i_blocks */

        obdo_free(oa);
        EXIT;
        return err;
} /* ll_brw */


/* returns the page unlocked, but with a reference */
int ll_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
        int rc;

        ENTRY;

	if ( ((inode->i_size + PAGE_CACHE_SIZE -1)>>PAGE_SHIFT) 
	     <= page->index) {
		memset(kmap(page), 0, PAGE_CACHE_SIZE);
		kunmap(page);
		goto readpage_out;
	}

	if (Page_Uptodate(page)) {
		EXIT;
		goto readpage_out;
	}

        rc = ll_brw(READ, inode, page, 0);
        if ( rc ) {
		EXIT; 
		return rc;
        } 
        /* PDEBUG(page, "READ"); */

 readpage_out:
	SetPageUptodate(page);
	obd_unlock_page(page);
        EXIT;
        return 0;
} /* ll_readpage */



/* returns the page unlocked, but with a reference */
int ll_dir_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
        struct ll_sb_info *sbi =
		(struct ll_sb_info *)(&inode->i_sb->u.generic_sbp);
	char *buf;
	__u64 offset;
        int rc = 0;
	struct ptlrep_hdr *hdr;

        ENTRY;

	if ( ((inode->i_size + PAGE_CACHE_SIZE -1)>>PAGE_SHIFT) 
	     <= page->index) {
		memset(kmap(page), 0, PAGE_CACHE_SIZE);
		kunmap(page);
		goto readpage_out;
	}

	if (Page_Uptodate(page)) {
		EXIT;
		goto readpage_out;
	}

	offset = page->index << PAGE_SHIFT; 
	buf = kmap(page);
        rc = mdc_readpage(sbi->ll_peer_ptr, inode->i_ino, S_IFDIR, offset, buf,
			  NULL, &hdr);
	kunmap(page); 
        if ( rc ) {
		EXIT; 
		goto readpage_out;
        } 

	if ((rc = hdr->status)) {
		EXIT;
		goto readpage_out;
	}

        /* PDEBUG(page, "READ"); */

	SetPageUptodate(page);
 readpage_out:
	obd_unlock_page(page);
        EXIT;
        return rc;
} /* ll_dir_readpage */

int ll_prepare_write(struct file *file, struct page *page, unsigned from, unsigned to)
{
        struct inode *inode = page->mapping->host;
        obd_off offset = ((obd_off)page->index) << PAGE_SHIFT;
        int rc = 0;
        ENTRY; 
        
	kmap(page);
        if (Page_Uptodate(page)) { 
                EXIT;
		goto prepare_done;
        }

        if ( (from <= offset) && (to >= offset + PAGE_SIZE) ) {
                EXIT;
                return 0;
        }
        
        rc = ll_brw(READ, inode, page, 0);
        if ( !rc ) {
                SetPageUptodate(page);
        } 

 prepare_done:
	set_page_dirty(page);
	//SetPageDirty(page);
        EXIT;
        return rc;
}


/* select between SYNC and ASYNC I/O methods */
int ll_do_writepage(struct page *page, int sync)
{
        struct inode *inode = page->mapping->host;
        int err;

        ENTRY;
        /* PDEBUG(page, "WRITEPAGE"); */
	/* XXX everything is synchronous now */
	err = ll_brw(WRITE, inode, page, 1);

        if ( !err ) {
                SetPageUptodate(page);
		set_page_clean(page);
	}
        /* PDEBUG(page,"WRITEPAGE"); */
        EXIT;
        return err;
} /* ll_do_writepage */



/* returns the page unlocked, but with a reference */
int ll_writepage(struct page *page)
{
	int rc;
	struct inode *inode = page->mapping->host;
        ENTRY;
	printk("---> writepage called ino %ld!\n", inode->i_ino);
	BUG();
        rc = ll_do_writepage(page, 1);
	if ( !rc ) {
		set_page_clean(page);
	} else {
		CDEBUG(D_INODE, "--> GRR %d\n", rc);
	}
        EXIT;
	return rc;
}

void write_inode_pages(struct inode *inode)
{
	struct list_head *tmp = &inode->i_mapping->dirty_pages;
	
	while ( (tmp = tmp->next) != &inode->i_mapping->dirty_pages) { 
		struct page *page;
		page = list_entry(tmp, struct page, list);
		ll_writepage(page);
	}
}


int ll_commit_write(struct file *file, struct page *page, unsigned from, unsigned to)
{
        struct inode *inode = page->mapping->host;
	int rc = 0;
        loff_t len = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;
	ENTRY;
	CDEBUG(D_INODE, "commit write ino %ld (end at %Ld) from %d to %d ,ind %ld\n",
	       inode->i_ino, len, from, to, page->index);

	rc = ll_commit_page(page, 1, from, to);

        if (len > inode->i_size) {
		ll_set_size(inode, len);
        }

        kunmap(page);
	EXIT;
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
 *
 * Return value is the number of bytes written.
 */
int ll_write_one_page(struct file *file, struct page *page,
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
                err = ll_brw(READ, inode, page, 0);
                if ( err )
                        return err;
                SetPageUptodate(page);
        }

        if (copy_from_user((u8*)page_address(page) + offset, buf, bytes))
                return -EFAULT;

        lock_kernel();
        err = ll_writepage(page);
        unlock_kernel();

        return (err < 0 ? err : bytes);
} /* ll_write_one_page */

/* 
 * return an up to date page:
 *  - if locked is true then is returned locked
 *  - if create is true the corresponding disk blocks are created 
 *  - page is held, i.e. caller must release the page
 *
 * modeled on NFS code.
 */
struct page *ll_getpage(struct inode *inode, unsigned long offset,
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
                if (!locked) {
                        if (PageLocked(page))
                                obd_unlock_page(page);
                } else {
                        printk("file %s, line %d: expecting locked page\n",
                               __FILE__, __LINE__); 
                }
                EXIT;
                return page;
        } 

        err = ll_brw(READ, inode, page, create);

        if ( err ) {
                SetPageError(page);
                obd_unlock_page(page);
                EXIT;
                return page;
        }

        if ( !locked )
                obd_unlock_page(page);
        SetPageUptodate(page);
        /* PDEBUG(page,"GETPAGE - after reading"); */
        EXIT;
        return page;
} /* ll_getpage */


void ll_truncate(struct inode *inode)
{
        struct obdo *oa;
        int err;
        ENTRY;

        //ll_dequeue_pages(inode);

        oa = obdo_alloc();
        if ( !oa ) {
                /* XXX This would give an inconsistent FS, so deal with it as
                 * best we can for now - an obdo on the stack is not pretty.
                 */
                struct obdo obdo;

                printk(__FUNCTION__ ": obdo_alloc failed - using stack!\n");

                obdo.o_valid = OBD_MD_FLNOTOBD;
                ll_oa_from_inode(&obdo, inode);

                err = obd_punch(IID(inode), &obdo, 0, obdo.o_size);
        } else {
                oa->o_valid = OBD_MD_FLNOTOBD;
                ll_oa_from_inode(oa, inode);

                CDEBUG(D_INFO, "calling punch for %ld (%Lu bytes at 0)\n",
                       (long)oa->o_id, oa->o_size);
                err = obd_punch(IID(inode), oa, oa->o_size, 0);

                obdo_free(oa);
        }

        if (err) {
                printk(__FUNCTION__ ": obd_truncate fails (%d)\n", err);
                EXIT;
                return;
        }
        EXIT;
} /* ll_truncate */

struct address_space_operations ll_aops = {
        readpage: ll_readpage,
        writepage: ll_writepage,
        sync_page: block_sync_page,
        prepare_write: ll_prepare_write, 
        commit_write: ll_commit_write,
        bmap: NULL
};


struct address_space_operations ll_dir_aops = {
        readpage: ll_dir_readpage
};
