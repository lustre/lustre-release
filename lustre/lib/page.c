/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
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

#define DEBUG_SUBSYSTEM S_OST

#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_ha.h>

static int sync_io_timeout(void *data)
{
        struct io_cb_data *cbd = data;
        struct ptlrpc_bulk_desc *desc = cbd->desc;

        ENTRY;
        desc->b_connection->c_level = LUSTRE_CONN_RECOVD;
        desc->b_flags |= PTL_RPC_FL_TIMEOUT;
        if (desc->b_client && desc->b_client->cli_recovd &&
            class_signal_client_failure) {
                /* XXXshaver Do we need a resend strategy, or do we just
                 * XXXshaver return -ERESTARTSYS and punt it?
                 */
                CERROR("signalling failure of client %p\n", desc->b_client);
                class_signal_client_failure(desc->b_client);

                /* We go back to sleep, until we're resumed or interrupted. */
                RETURN(0);
        }
        
        /* If we can't be recovered, just abort the syscall with -ETIMEDOUT. */
        RETURN(1);
}

static int sync_io_intr(void *data)
{
        struct io_cb_data *cbd = data;
        struct ptlrpc_bulk_desc *desc = cbd->desc;

        ENTRY;
        desc->b_flags |= PTL_RPC_FL_INTR;
        RETURN(1); /* ignored, as of this writing */
}

int ll_sync_io_cb(struct io_cb_data *data, int err, int phase)
{
        int ret;
        ENTRY; 

        if (phase == CB_PHASE_START) { 
                struct l_wait_info lwi;
                lwi = LWI_TIMEOUT_INTR(obd_timeout * HZ, sync_io_timeout,
                                       sync_io_intr, data);
                ret = l_wait_event(data->waitq, data->complete, &lwi);
                if (atomic_dec_and_test(&data->refcount))
                        OBD_FREE(data, sizeof(*data));
                if (ret == -ERESTARTSYS)
                        return ret;
        } else if (phase == CB_PHASE_FINISH) { 
                data->err = err;
                data->complete = 1;
                wake_up(&data->waitq); 
                if (atomic_dec_and_test(&data->refcount))
                        OBD_FREE(data, sizeof(*data));
                return err;
        } else 
                LBUG();
        EXIT;
        return 0;
}

struct io_cb_data *ll_init_cb(void)
{
        struct io_cb_data *d;


        OBD_ALLOC(d, sizeof(*d));
        if (d) { 
                init_waitqueue_head(&d->waitq);
                atomic_set(&d->refcount, 2);
        }
        RETURN(d); 
}

/*
 * Remove page from dirty list
 */
static void __set_page_clean(struct page *page)
{
        struct address_space *mapping = page->mapping;
        struct inode *inode;
        
        if (!mapping)
                return;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,4,9))
        spin_lock(&pagecache_lock);
#endif

        list_del(&page->list);
        list_add(&page->list, &mapping->clean_pages);

        inode = mapping->host;
        if (list_empty(&mapping->dirty_pages)) { 
                CDEBUG(D_INODE, "inode clean\n");
                inode->i_state &= ~I_DIRTY_PAGES;
        }
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,4,10))
        spin_unlock(&pagecache_lock);
#endif
        EXIT;
}

inline void set_page_clean(struct page *page)
{
        if (PageDirty(page)) { 
                ClearPageDirty(page);
                __set_page_clean(page);
        }
}

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

inline void lustre_put_page(struct page *page)
{
        kunmap(page);
        page_cache_release(page);
}

struct page *lustre_get_page_read(struct inode *inode, unsigned long index)
{
        struct address_space *mapping = inode->i_mapping;
        struct page *page;
        int rc;

        page = read_cache_page(mapping, index,
                               (filler_t*)mapping->a_ops->readpage, NULL);
        if (!IS_ERR(page)) {
                wait_on_page(page);
                kmap(page);
                if (!Page_Uptodate(page)) {
                        CERROR("page index %lu not uptodate\n", index);
                        GOTO(err_page, rc = -EIO);
                }
                if (PageError(page)) {
                        CERROR("page index %lu has error\n", index);
                        GOTO(err_page, rc = -EIO);
                }
        }
        return page;

err_page:
        lustre_put_page(page);
        return ERR_PTR(rc);
}

struct page *lustre_get_page_write(struct inode *inode, unsigned long index)
{
        struct address_space *mapping = inode->i_mapping;
        struct page *page;
        int rc;

        page = grab_cache_page(mapping, index); /* locked page */

        if (!IS_ERR(page)) {
                kmap(page);
                /* Note: Called with "O" and "PAGE_SIZE" this is essentially
                 * a no-op for most filesystems, because we write the whole
                 * page.  For partial-page I/O this will read in the page.
                 */
                rc = mapping->a_ops->prepare_write(NULL, page, 0, PAGE_SIZE);
                if (rc) {
                        CERROR("page index %lu, rc = %d\n", index, rc);
                        if (rc != -ENOSPC)
                                LBUG();
                        GOTO(err_unlock, rc);
                }
                /* XXX not sure if we need this if we are overwriting page */
                if (PageError(page)) {
                        CERROR("error on page index %lu, rc = %d\n", index, rc);
                        LBUG();
                        GOTO(err_unlock, rc = -EIO);
                }
        }
        return page;

err_unlock:
        unlock_page(page);
        lustre_put_page(page);
        return ERR_PTR(rc);
}

int lustre_commit_write(struct page *page, unsigned from, unsigned to)
{
        struct inode *inode = page->mapping->host;
        int err = 0;

        SetPageUptodate(page);
        set_page_clean(page);

        page->mapping->a_ops->commit_write(NULL, page, from, to);
        if (IS_SYNC(inode))
                err = waitfor_one_page(page);
        UnlockPage(page);
        lustre_put_page(page);
        return err;
}
