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

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_light.h>

/*
 * Remove page from dirty list
 */
static void __set_page_clean(struct page *page)
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

inline void lustre_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

struct page * lustre_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_cache_page(mapping, n,
				(filler_t*)mapping->a_ops->readpage, NULL);
	if (!IS_ERR(page)) {
		wait_on_page(page);
		kmap(page);
		if (!Page_Uptodate(page))
			goto fail;
		if (PageError(page))
			goto fail;
	}
	return page;

fail:
	lustre_put_page(page);
	return ERR_PTR(-EIO);
}

void lustre_prepare_page(unsigned from, unsigned to, struct page *page)
{
	int err;

	lock_page(page);
	err = page->mapping->a_ops->prepare_write(NULL, page, from, to);
	if (err)
		BUG();

}

int lustre_commit_page(struct page *page, unsigned from, unsigned to)
{
	struct inode *dir = page->mapping->host;
	int err = 0;

	SetPageUptodate(page);
	set_page_clean(page);

	page->mapping->a_ops->commit_write(NULL, page, from, to);
	if (IS_SYNC(dir))
		err = waitfor_one_page(page);
	UnlockPage(page);
	lustre_put_page(page);
	return err;
}
