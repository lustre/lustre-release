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
#include <linux/version.h>

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

#define DEBUG_SUBSYSTEM S_OBDFS

#include <linux/obd_support.h>
#include <linux/obd_ext2.h>
#include <linux/obdfs.h>

void obdfs_change_inode(struct inode *inode);

static int cache_writes = 0;


/* page cache support stuff */ 

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10)
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

#endif


inline void set_page_clean(struct page *page)
{
        if (PageDirty(page)) { 
                ClearPageDirty(page);
                __set_page_clean(page);
        }
}

/* SYNCHRONOUS I/O to object storage for an inode -- object attr will be updated too */
static int obdfs_brw(int rw, struct inode *inode, struct page *page, int create)
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
        oa->o_valid = (__u32)OBD_MD_FLNOTOBD;
        obdfs_from_inode(oa, inode);

        err = obd_brw(rw, IID(inode), num_obdo, &oa, &bufs_per_obdo,
                       &page, &count, &offset, &flags, NULL);
        //if ( !err )
        //      obdfs_to_inode(inode, oa); /* copy o_blocks to i_blocks */

        obdo_free(oa);
        EXIT;
        return err;
} /* obdfs_brw */

extern void set_page_clean(struct page *);

/* SYNCHRONOUS I/O to object storage for an inode -- object attr will be updated too */
static int obdfs_commit_page(struct page *page, int create, int from, int to)
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
        oa->o_valid = (__u32)OBD_MD_FLNOTOBD;
        obdfs_from_inode(oa, inode);

        CDEBUG(D_INODE, "commit_page writing (at %d) to %d, count %Ld\n",
               from, to, (unsigned long long)count);

        err = obd_brw(WRITE, IID(inode), num_obdo, &oa, &bufs_per_obdo,
                               &page, &count, &offset, &flags, NULL);
        if ( !err ) {
                SetPageUptodate(page);
                set_page_clean(page);
        }

        //if ( !err )
        //      obdfs_to_inode(inode, oa); /* copy o_blocks to i_blocks */

        obdo_free(oa);
        EXIT;
        return err;
} /* obdfs_brw */

/* returns the page unlocked, but with a reference */
int obdfs_writepage(struct page *page)
{
        int rc;
        struct inode *inode = page->mapping->host;
        ENTRY;
        CERROR("---> writepage called ino %ld!\n", inode->i_ino);
        LBUG();
        rc = obdfs_brw(OBD_BRW_WRITE, inode, page, 1);
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
                obdfs_writepage(page);
        }
}


/* returns the page unlocked, but with a reference */
int obdfs_readpage(struct file *file, struct page *page)
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

        rc = obdfs_brw(READ, inode, page, 0);
        if ( rc ) {
                EXIT; 
                return rc;
        } 

 readpage_out:
        SetPageUptodate(page);
        UnlockPage(page);
        EXIT;
        return 0;
} /* obdfs_readpage */

int obdfs_prepare_write(struct file *file, struct page *page, unsigned from, unsigned to)
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
        
        rc = obdfs_brw(READ, inode, page, 0);
        if ( !rc ) {
                SetPageUptodate(page);
        } 

 prepare_done:
        set_page_dirty(page);
        //SetPageDirty(page);
        EXIT;
        return rc;
}


#if 0



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
        OBDClearCachePage(pgrq->rq_page);
        kmem_cache_free(obdfs_pgrq_cachep, pgrq);
}

void obdfs_cleanup_pgrqcache(void)
{
        ENTRY;
        if (obdfs_pgrq_cachep != NULL) {
                CDEBUG(D_CACHE, "destroying obdfs_pgrqcache at %p, count %ld\n",
                       obdfs_pgrq_cachep, obdfs_cache_count);
                if (kmem_cache_destroy(obdfs_pgrq_cachep))
                        CERROR("unable to free all of cache\n");
                obdfs_pgrq_cachep = NULL;
        } else
                CERROR("called with NULL pointer\n");

        EXIT;
} /* obdfs_cleanup_wreqcache */


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

        err = obd_brw(OBD_BRW_WRITE, IID(inodes[0]), num_obdos, obdos,
                      oa_bufs, pages, counts, offsets, flags);

        CDEBUG(D_INFO, "BRW done\n");
        /* release the pages from the page cache */
        while ( num_io > 0 ) {
                --num_io;
                CDEBUG(D_INFO, "calling put_page for %p, index %ld\n",
                       pages[num_io], pages[num_io]->index);
                put_page(pages[num_io]);
        }
        CDEBUG(D_INFO, "put_page done\n");

        while ( num_obdos > 0) {
                --num_obdos;
                CDEBUG(D_INFO, "free obdo %ld\n",(long)obdos[num_obdos]->o_id);
                /* copy o_blocks to i_blocks */
                obdfs_set_size (inodes[num_obdos], obdos[num_obdos]->o_size);
                //obdfs_to_inode(inodes[num_obdos], obdos[num_obdos]);
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
static int obdfs_add_page_to_cache(struct inode *inode, struct page *page)
{
        int err = 0;
        ENTRY;

        /* The PG_obdcache bit is cleared by obdfs_pgrq_del() BEFORE the page
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
                struct obdfs_pgrq *pgrq;
                pgrq = kmem_cache_alloc(obdfs_pgrq_cachep, SLAB_KERNEL);
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

                obd_down(&obdfs_i2sbi(inode)->osi_list_mutex);
                list_add(&pgrq->rq_plist, obdfs_iplist(inode));
                obdfs_cache_count++;
                //CERROR("-- count %d\n", obdfs_cache_count);

                /* If inode isn't already on superblock inodes list, add it.
                 *
                 * We increment the reference count on the inode to keep it
                 * from being freed from memory.  This _should_ be an iget()
                 * with an iput() in both flush_reqs() and put_inode(), but
                 * since put_inode() is called from iput() we can't call iput()
                 * again there.  Instead we just increment/decrement i_count,
                 * which is mostly what iget/iput do for an inode in memory.
                 */
                if ( list_empty(obdfs_islist(inode)) ) {
                        atomic_inc(&inode->i_count);
                        CDEBUG(D_INFO,
                               "adding inode %ld to superblock list %p\n",
                               inode->i_ino, obdfs_slist(inode));
                        list_add(obdfs_islist(inode), obdfs_slist(inode));
                }
                obd_up(&obdfs_i2sbi(inode)->osi_list_mutex);

        }

        /* XXX For testing purposes, we can write out the page here.
        err = obdfs_flush_reqs(obdfs_slist(inode), ~0UL);
         */

        EXIT;
        return err;
} /* obdfs_add_page_to_cache */

void rebalance(void)
{
        if (obdfs_cache_count > 60000) {
                CERROR("-- count %ld\n", obdfs_cache_count);
                //obdfs_flush_dirty_pages(~0UL);
                CERROR("-- count %ld\n", obdfs_cache_count);
        }
}



/* select between SYNC and ASYNC I/O methods */
int obdfs_do_writepage(struct page *page, int sync)
{
        struct inode *inode = page->mapping->host;
        int err;

        ENTRY;
        if ( sync )
                err = obdfs_brw(OBD_BRW_WRITE, inode, page, 1);
        else {
                err = obdfs_add_page_to_cache(inode, page);
                CDEBUG(D_INFO, "DO_WR ino: %ld, page %p, err %d, uptodate %d\n",
                       inode->i_ino, page, err, Page_Uptodate(page));
        }
                
        if ( !err ) {
                SetPageUptodate(page);
                set_page_clean(page);
        }
        EXIT;
        return err;
} /* obdfs_do_writepage */




#endif

int obdfs_commit_write(struct file *file, struct page *page, unsigned from, unsigned to)
{
        struct inode *inode = page->mapping->host;
        int rc = 0;
        loff_t len = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;
        ENTRY;
        CDEBUG(D_INODE, "commit write ino %ld (end at %Ld) from %d to %d ,ind %ld\n",
               inode->i_ino, len, from, to, page->index);


        if (cache_writes == 0) { 
                rc = obdfs_commit_page(page, 1, from, to);
        }

        if (len > inode->i_size) {
                obdfs_set_size(inode, len);
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

        lock_kernel();
        err = obdfs_writepage(page);
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
            CERROR("grab_cache_page says no dice ...\n");
            EXIT;
            return NULL;
        }

        /* now check if the data in the page is up to date */
        if ( Page_Uptodate(page)) { 
                if (!locked) {
                        if (PageLocked(page))
                                UnlockPage(page);
                } else {
                        CERROR("expecting locked page\n");
                }
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
        EXIT;
        return page;
} /* obdfs_getpage */


void obdfs_truncate(struct inode *inode)
{
        struct obdo *oa;
        int err;
        ENTRY;

        //obdfs_dequeue_pages(inode);
        oa = obdo_alloc();
        if ( !oa ) {
                err = -ENOMEM;
                CERROR("obdo_alloc failed!\n");
        } else {
                oa->o_valid = (__u32)OBD_MD_FLNOTOBD;
                obdfs_from_inode(oa, inode);

                CDEBUG(D_INFO, "calling punch for %ld (%Lu bytes at 0)\n",
                       (long)oa->o_id, (unsigned long long)oa->o_size);
                err = obd_punch(IID(inode), oa, oa->o_size, 0);

                obdo_free(oa);
        }

        if (err) {
                CERROR("obd_truncate fails (%d)\n", err);
                EXIT;
                return;
        }
        EXIT;
} /* obdfs_truncate */

struct address_space_operations obdfs_aops = {
        readpage: obdfs_readpage,
        writepage: obdfs_writepage,
        sync_page: block_sync_page,
        prepare_write: obdfs_prepare_write, 
        commit_write: obdfs_commit_write,
        bmap: NULL
};
