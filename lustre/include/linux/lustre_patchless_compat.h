/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef LUSTRE_PATCHLESS_COMPAT_H
#define LUSTRE_PATCHLESS_COMPAT_H

#include <linux/lustre_version.h>
#include <linux/fs.h>

#ifndef HAVE_TRUNCATE_COMPLETE_PAGE
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/hash.h>

/* XXX copy & paste from 2.6.15 kernel */
static inline void ll_remove_from_page_cache(struct page *page)
{
        struct address_space *mapping = page->mapping;

        BUG_ON(!PageLocked(page));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15))
        write_lock_irq(&mapping->tree_lock);
#else
	spin_lock_irq(&mapping->tree_lock);
#endif
        radix_tree_delete(&mapping->page_tree, page->index);
        page->mapping = NULL;
        mapping->nrpages--;
#ifdef HAVE_NR_PAGECACHE
	atomic_add(-1, &nr_pagecache); // XXX pagecache_acct(-1);
#else
	__dec_zone_page_state(page, NR_FILE_PAGES);
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15))
        write_unlock_irq(&mapping->tree_lock);
#else
	spin_unlock_irq(&mapping->tree_lock);
#endif
}

static inline void
truncate_complete_page(struct address_space *mapping, struct page *page)
{
        if (page->mapping != mapping)
                return;

        if (PagePrivate(page))
                page->mapping->a_ops->invalidatepage(page, 0);

#ifdef HAVE_CANCEL_DIRTY_PAGE
        cancel_dirty_page(page, PAGE_SIZE);
#else
        clear_page_dirty(page);
#endif
        ClearPageUptodate(page);
        ClearPageMappedToDisk(page);
        ll_remove_from_page_cache(page);
        page_cache_release(page);       /* pagecache ref */
}
#endif /* HAVE_TRUNCATE_COMPLETE_PAGE */

#if !defined(HAVE_D_REHASH_COND) && !defined(HAVE___D_REHASH)
/* megahack */
static inline void d_rehash_cond(struct dentry * entry, int lock)
{
	if (!lock)
		spin_unlock(&dcache_lock);

	d_rehash(entry);

	if (!lock)
		spin_lock(&dcache_lock);
}

#define __d_rehash(dentry, lock) d_rehash_cond(dentry, lock)
#endif /* !HAVE_D_REHASH_COND && !HAVE___D_REHASH*/

#ifdef ATTR_OPEN
# define ATTR_FROM_OPEN ATTR_OPEN
#else
# ifndef ATTR_FROM_OPEN
#  define ATTR_FROM_OPEN 0
# endif
#endif /* ATTR_OPEN */

#ifndef ATTR_RAW
#define ATTR_RAW 0
#endif

#ifndef ATTR_CTIME_SET
/*
 * set ATTR_CTIME_SET to a high value to avoid any risk of collision with other
 * ATTR_* attributes (see bug 13828)
 */
#define ATTR_CTIME_SET (1 << 28)
#endif

#endif /* LUSTRE_PATCHLESS_COMPAT_H */
