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
#include <linux/version.h>
#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#define DEBUG_SUBSYSTEM S_LLIGHT

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_light.h>

int ll_inode_setattr(struct inode *inode, struct iattr *attr, int do_trunc);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10))
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
#else
/*
 * Add a page to the dirty page list.
 */
void set_page_dirty(struct page *page)
{
	if (!test_and_set_bit(PG_dirty, &page->flags)) {
		struct address_space *mapping = page->mapping;

		if (mapping) {
			spin_lock(&pagecache_lock);
			list_del(&page->list);
			list_add(&page->list, &mapping->dirty_pages);
			spin_unlock(&pagecache_lock);

			if (mapping->host)
				mark_inode_dirty_pages(mapping->host);
		}
	}
}
#endif

inline struct obdo * ll_oa_from_inode(struct inode *inode, int valid)
{
        struct ll_inode_info *oinfo = ll_i2info(inode);
	struct obdo *oa = obdo_alloc();
        if ( !oa ) {
		CERROR("no memory to allocate obdo!\n"); 
                return NULL;
        }
	oa->o_valid = valid;

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
#if 0
	/* this will transfer metadata for the logical object to 
	   the oa: that metadata could contain the constituent objects
	*/
	if (ll_has_inline(inode)) {
                CDEBUG(D_INODE, "copying inline data from inode to obdo\n");
                memcpy(oa->o_inline, oinfo->lli_inline, OBD_INLINESZ);
                oa->o_obdflags |= OBD_FL_INLINEDATA;
                oa->o_valid |= OBD_MD_FLINLINE;
        }
#endif
	return oa;
} /* ll_oa_from_inode */



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

/* SYNCHRONOUS I/O to object storage for an inode */
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

        oa = ll_oa_from_inode(inode, OBD_MD_FLNOTOBD);
	if (!oa) { 
		return -ENOMEM;
	}
        err = obd_brw(rw, IID(inode), num_obdo, &oa, &bufs_per_obdo,
                               &page, &count, &offset, &flags);

        obdo_free(oa);
        EXIT;
        return err;
} /* ll_brw */

extern void set_page_clean(struct page *);



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

        rc = ll_brw(OBD_BRW_READ, inode, page, 0);
        if ( rc ) {
		EXIT; 
		return rc;
        } 

 readpage_out:
	SetPageUptodate(page);
	obd_unlock_page(page);
        EXIT;
        return 0;
} /* ll_readpage */


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
        
        rc = ll_brw(OBD_BRW_READ, inode, page, 0);
        if ( !rc ) {
                SetPageUptodate(page);
        } 

 prepare_done:
	set_page_dirty(page);
        EXIT;
        return rc;
}

/* returns the page unlocked, but with a reference */
int ll_writepage(struct page *page)
{
        struct inode *inode = page->mapping->host;
        int err;
        ENTRY;

	err = ll_brw(OBD_BRW_WRITE, inode, page, 1);
        if ( !err ) {
                SetPageUptodate(page);
		set_page_clean(page);
	} else {
		CERROR("ll_brw failure %d\n", err);
	}
        EXIT;
	return err;
}

/* SYNCHRONOUS I/O to object storage for an inode -- object attr will be updated too */
int ll_commit_write(struct file *file, struct page *page, 
		    unsigned from, unsigned to)
{
	int create = 1;
	struct inode *inode = page->mapping->host;
        obd_count        num_obdo = 1;
        obd_count        bufs_per_obdo = 1;
        struct obdo     *oa;
        obd_size         count = to;
        obd_off          offset = (((obd_off)page->index) << PAGE_SHIFT) + to;
        obd_flag         flags = create ? OBD_BRW_CREATE : 0;
        int              err;
	struct iattr     iattr;

        ENTRY;
        oa = ll_oa_from_inode(inode, OBD_MD_FLNOTOBD);
	if (! oa ) { 
		return -ENOMEM;
	}

	CDEBUG(D_INODE, "commit_page writing (at %d) to %d, count %Ld\n", 
	       from, to, count);

        err = obd_brw(OBD_BRW_WRITE, IID(inode), num_obdo, &oa, &bufs_per_obdo,
		      &page, &count, &offset, &flags);
        if ( !err ) {
                SetPageUptodate(page);
		set_page_clean(page);
	}
        kunmap(page);

	if (offset > inode->i_size) {
		iattr.ia_valid = ATTR_SIZE;
		iattr.ia_size = offset;
		/* do NOT truncate */
		err = ll_inode_setattr(inode, &iattr, 0);
		if (err) {
			CERROR("failed - %d.\n", err);
			obdo_free(oa);
			EXIT;
			return -EIO;
		}
	}

        obdo_free(oa);
        EXIT;
        return err;
} /* ll_brw */

void ll_truncate(struct inode *inode)
{
        struct obdo *oa;
        int err;
        ENTRY;

	oa = ll_oa_from_inode(inode, OBD_MD_FLNOTOBD);
        if ( !oa ) {
                CERROR("no memory to allocate obdo!\n");
		return; 
        } 
	
	CDEBUG(D_INFO, "calling punch for %ld (%Lu bytes at 0)\n",
	       (long)oa->o_id, oa->o_size);
	err = obd_punch(IID(inode), oa, oa->o_size, 0);
	obdo_free(oa);

        if (err) {
                CERROR("obd_truncate fails (%d)\n", err);
        }
        EXIT;
	return; 
} /* ll_truncate */

struct address_space_operations ll_aops = {
        readpage: ll_readpage,
        writepage: ll_writepage,
        sync_page: block_sync_page,
        prepare_write: ll_prepare_write, 
        commit_write: ll_commit_write,
        bmap: NULL
};

