/*
 * OBDFS Super operations
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
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
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_light.h>

void ll_change_inode(struct inode *inode);

static int cache_writes = 0;


/* page cache support stuff */ 


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

/*
 * Remove page from dirty list
 */
void __set_page_clean(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode;
	
	if (!mapping)
		return;

	spin_lock(&pagecache_lock);
	list_del(&page->list);
	list_add(&page->list, &mapping->clean_pages);

	inode = mapping->host;
	if (list_empty(&mapping->dirty_pages)) { 
		CDEBUG(D_INODE, "inode clean\n");
		inode->i_state &= ~I_DIRTY_PAGES;
	}
	spin_unlock(&pagecache_lock);
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
        ll_from_inode(oa, inode);

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
        ll_from_inode(oa, inode);

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
	char *buf;
	__u64 offset;
        int rc = 0;
	struct mds_rep_hdr *hdr;

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
        rc = mdc_readpage(inode->i_ino, S_IFDIR, offset, buf, NULL, &hdr);
	kunmap(buff); 
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
	unlock_page(page);
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






static kmem_cache_t *ll_pgrq_cachep = NULL;

int ll_init_pgrqcache(void)
{
        ENTRY;
        if (ll_pgrq_cachep == NULL) {
                CDEBUG(D_CACHE, "allocating ll_pgrq_cache\n");
                ll_pgrq_cachep = kmem_cache_create("ll_pgrq",
                                                      sizeof(struct ll_pgrq),
                                                      0, SLAB_HWCACHE_ALIGN,
                                                      NULL, NULL);
                if (ll_pgrq_cachep == NULL) {
                        EXIT;
                        return -ENOMEM;
                } else {
                        CDEBUG(D_CACHE, "allocated cache at %p\n",
                               ll_pgrq_cachep);
                }
        } else {
                CDEBUG(D_CACHE, "using existing cache at %p\n",
                       ll_pgrq_cachep);
        }
        EXIT;
        return 0;
} /* ll_init_wreqcache */

inline void ll_pgrq_del(struct ll_pgrq *pgrq)
{
        --ll_cache_count;
        CDEBUG(D_INFO, "deleting page %p from list [count %ld]\n",
               pgrq->rq_page, ll_cache_count);
        list_del(&pgrq->rq_plist);
        OBDClearCachePage(pgrq->rq_page);
        kmem_cache_free(ll_pgrq_cachep, pgrq);
}

void ll_cleanup_pgrqcache(void)
{
        ENTRY;
        if (ll_pgrq_cachep != NULL) {
                CDEBUG(D_CACHE, "destroying ll_pgrqcache at %p, count %ld\n",
                       ll_pgrq_cachep, ll_cache_count);
                if (kmem_cache_destroy(ll_pgrq_cachep))
                        printk(KERN_INFO __FUNCTION__
                               ": unable to free all of cache\n");
                ll_pgrq_cachep = NULL;
        } else
                printk(KERN_INFO __FUNCTION__ ": called with NULL pointer\n");

        EXIT;
} /* ll_cleanup_wreqcache */


/* called with the list lock held */
static struct page *ll_find_page_index(struct inode *inode,
                                          unsigned long index)
{
        struct list_head *page_list = ll_iplist(inode);
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
                struct ll_pgrq *pgrq;

                pgrq = list_entry(tmp, struct ll_pgrq, rq_plist);
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
} /* ll_find_page_index */


/* call and free pages from Linux page cache: called with io lock on inodes */
int ll_do_vec_wr(struct inode **inodes, obd_count num_io,
                    obd_count num_obdos, struct obdo **obdos,
                    obd_count *oa_bufs, struct page **pages, char **bufs,
                    obd_size *counts, obd_off *offsets, obd_flag *flags)
{
        int err;

        ENTRY;

        CDEBUG(D_INFO, "writing %d page(s), %d obdo(s) in vector\n",
               num_io, num_obdos);
        if (obd_debug_level & D_INFO) { /* DEBUGGING */
                int i;
                printk("OBDOS: ");
                for (i = 0; i < num_obdos; i++)
                        printk("%ld:0x%p ", (long)obdos[i]->o_id, obdos[i]);

                printk("\nPAGES: ");
                for (i = 0; i < num_io; i++)
                        printk("0x%p ", pages[i]);
                printk("\n");
        }

        err = obd_brw(WRITE, IID(inodes[0]), num_obdos, obdos,
                                  oa_bufs, pages, counts, offsets, flags);

        CDEBUG(D_INFO, "BRW done\n");
        /* release the pages from the page cache */
        while ( num_io > 0 ) {
                --num_io;
                CDEBUG(D_INFO, "calling put_page for %p, index %ld\n",
                       pages[num_io], pages[num_io]->index);
                /* PDEBUG(pages[num_io], "do_vec_wr"); */
                put_page(pages[num_io]);
                /* PDEBUG(pages[num_io], "do_vec_wr"); */
        }
        CDEBUG(D_INFO, "put_page done\n");

        while ( num_obdos > 0) {
                --num_obdos;
                CDEBUG(D_INFO, "free obdo %ld\n",(long)obdos[num_obdos]->o_id);
                /* copy o_blocks to i_blocks */
		ll_set_size (inodes[num_obdos], obdos[num_obdos]->o_size);
                //ll_to_inode(inodes[num_obdos], obdos[num_obdos]);
                obdo_free(obdos[num_obdos]);
        }
        CDEBUG(D_INFO, "obdo_free done\n");
        EXIT;
        return err;
}


/*
 * Add a page to the write request cache list for later writing.
 * ASYNCHRONOUS write method.
 */
static int ll_add_page_to_cache(struct inode *inode, struct page *page)
{
        int err = 0;
        ENTRY;

        /* The PG_obdcache bit is cleared by ll_pgrq_del() BEFORE the page
         * is written, so at worst we will write the page out twice.
         *
         * If the page has the PG_obdcache bit set, then the inode MUST be
         * on the superblock dirty list so we don't need to check this.
         * Dirty inodes are removed from the superblock list ONLY when they
         * don't have any more cached pages.  It is possible to have an inode
         * with no dirty pages on the superblock list, but not possible to
         * have an inode with dirty pages NOT on the superblock dirty list.
         */
        if (!OBDAddCachePage(page)) {
                struct ll_pgrq *pgrq;
                pgrq = kmem_cache_alloc(ll_pgrq_cachep, SLAB_KERNEL);
                if (!pgrq) {
                        OBDClearCachePage(page);
                        EXIT;
                        return -ENOMEM;
                }
                /* not really necessary since we set all pgrq fields here
                memset(pgrq, 0, sizeof(*pgrq)); 
                */
                
                pgrq->rq_page = page;
                pgrq->rq_jiffies = jiffies;
                get_page(pgrq->rq_page);

                obd_down(&ll_i2sbi(inode)->ll_list_mutex);
                list_add(&pgrq->rq_plist, ll_iplist(inode));
                ll_cache_count++;
		//printk("-- count %d\n", ll_cache_count);

                /* If inode isn't already on superblock inodes list, add it.
                 *
                 * We increment the reference count on the inode to keep it
                 * from being freed from memory.  This _should_ be an iget()
                 * with an iput() in both flush_reqs() and put_inode(), but
                 * since put_inode() is called from iput() we can't call iput()
                 * again there.  Instead we just increment/decrement i_count,
                 * which is mostly what iget/iput do for an inode in memory.
                 */
                if ( list_empty(ll_islist(inode)) ) {
                        atomic_inc(&inode->i_count);
                        CDEBUG(D_INFO,
                               "adding inode %ld to superblock list %p\n",
                               inode->i_ino, ll_slist(inode));
                        list_add(ll_islist(inode), ll_slist(inode));
                }
                obd_up(&ll_i2sbi(inode)->ll_list_mutex);

        }

        /* XXX For testing purposes, we can write out the page here.
        err = ll_flush_reqs(ll_slist(inode), ~0UL);
         */

        EXIT;
        return err;
} /* ll_add_page_to_cache */

void rebalance(void)
{
	if (ll_cache_count > 60000) {
		printk("-- count %ld\n", ll_cache_count);
		//ll_flush_dirty_pages(~0UL);
		printk("-- count %ld\n", ll_cache_count);
	}
}

/* select between SYNC and ASYNC I/O methods */
int ll_do_writepage(struct page *page, int sync)
{
        struct inode *inode = page->mapping->host;
        int err;

        ENTRY;
        /* PDEBUG(page, "WRITEPAGE"); */
        if ( sync )
                err = ll_brw(WRITE, inode, page, 1);
        else {
                err = ll_add_page_to_cache(inode, page);
                CDEBUG(D_INFO, "DO_WR ino: %ld, page %p, err %d, uptodate %d\n",
                       inode->i_ino, page, err, Page_Uptodate(page));
        }
                
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


	if (cache_writes == 0) { 
		rc = ll_commit_page(page, 1, from, to);
	}

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


#ifdef EXT2_OBD_DEBUG
        if ((obd_debug_level & D_INFO) && ll_find_page_index(inode, index)) {
                CDEBUG(D_INFO, "OVERWRITE: found dirty page %p, index %ld\n",
                       page, page->index);
        }
#endif

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
                ll_from_inode(&obdo, inode);

                err = obd_punch(IID(inode), &obdo, 0, obdo.o_size);
        } else {
                oa->o_valid = OBD_MD_FLNOTOBD;
                ll_from_inode(oa, inode);

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
