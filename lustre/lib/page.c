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
#include <linux/lustre_lib.h>

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

inline void lustre_put_page(struct page *page)
{
        kunmap(page);
        page_cache_release(page);
}

struct page *lustre_get_page_read(struct inode *inode, unsigned long index)
{
        struct address_space *mapping = inode->i_mapping;
        struct page *page = read_cache_page(mapping, index,
                                (filler_t*)mapping->a_ops->readpage, NULL);

        if (!IS_ERR(page)) {
                wait_on_page(page);
                kmap(page);
                if (!Page_Uptodate(page))
                        GOTO(fail, -EIO);
                if (PageError(page))
                        GOTO(fail, -EIO);
        }
        return page;

fail:
        lustre_put_page(page);
        return ERR_PTR(-EIO);
}

struct page *lustre_get_page_write(struct inode *inode, unsigned long index)
{
        struct address_space *mapping = inode->i_mapping;
        struct page *page = grab_cache_page(mapping, index); /* locked page */
        int err;

        if (!IS_ERR(page)) {
                kmap(page);

                /* Note: Called with "O" and "PAGE_SIZE" this is essentially
                 * a no-op for most filesystems, because we write the whole
                 * page.  For partial-page I/O this will read in the page.
                 */
                err = mapping->a_ops->prepare_write(NULL, page, 0, PAGE_SIZE);
                if (err) {
                        CERROR("page index %ld, err %d\n", index, err);
                        LBUG();
                        GOTO(fail, err);
                }
                /* XXX not sure if we need this if we are overwriting page */
                if (PageError(page))
                        GOTO(fail, err = -EIO);
        }
        return page;

fail:
        UnlockPage(page);
        lustre_put_page(page);
        return ERR_PTR(-EIO);
}

int lustre_commit_page(struct page *page, unsigned from, unsigned to)
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
