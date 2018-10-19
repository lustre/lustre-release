/*
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
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef LUSTRE_PATCHLESS_COMPAT_H
#define LUSTRE_PATCHLESS_COMPAT_H

#include <linux/fs.h>
#include <linux/mm.h>
#ifndef HAVE_TRUNCATE_COMPLETE_PAGE
#include <linux/list.h>
#include <linux/hash.h>

#ifndef HAVE_DELETE_FROM_PAGE_CACHE /* 2.6.39 */
#ifndef HAVE_REMOVE_FROM_PAGE_CACHE /* 2.6.35 - 2.6.38 */

/* XXX copy & paste from 2.6.15 kernel */
static inline void ll_remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	BUG_ON(!PageLocked(page));

	spin_lock_irq(&mapping->tree_lock);
	radix_tree_delete(&mapping->page_tree, page->index);
	page->mapping = NULL;
	mapping->nrpages--;
	__dec_zone_page_state(page, NR_FILE_PAGES);

	spin_unlock_irq(&mapping->tree_lock);
}
#else /* HAVE_REMOVE_FROM_PAGE_CACHE */
#define ll_remove_from_page_cache(page) remove_from_page_cache(page)
#endif /* !HAVE_REMOVE_FROM_PAGE_CACHE */

static inline void ll_delete_from_page_cache(struct page *page)
{
        ll_remove_from_page_cache(page);
	put_page(page);
}
#else /* HAVE_DELETE_FROM_PAGE_CACHE */
#define ll_delete_from_page_cache(page) delete_from_page_cache(page)
#endif /* !HAVE_DELETE_FROM_PAGE_CACHE */

static inline void
ll_cancel_dirty_page(struct address_space *mapping, struct page *page)
{
#ifdef HAVE_NEW_CANCEL_DIRTY_PAGE
	cancel_dirty_page(page);
#elif defined(HAVE_CANCEL_DIRTY_PAGE)
	cancel_dirty_page(page, PAGE_SIZE);
#else
	if (TestClearPageDirty(page))
		account_page_cleaned(page, mapping);
#endif	/* HAVE_NEW_CANCEL_DIRTY_PAGE */
}

static inline void
truncate_complete_page(struct address_space *mapping, struct page *page)
{
	if (page->mapping != mapping)
		return;

	if (PagePrivate(page))
#ifdef HAVE_INVALIDATE_RANGE
		page->mapping->a_ops->invalidatepage(page, 0, PAGE_SIZE);
#else
		page->mapping->a_ops->invalidatepage(page, 0);
#endif

	ll_cancel_dirty_page(mapping, page);
	ClearPageMappedToDisk(page);
	ll_delete_from_page_cache(page);
}
#endif /* !HAVE_TRUNCATE_COMPLETE_PAGE */

#ifdef HAVE_DCACHE_LOCK
#  define dget_dlock(d)			dget_locked(d)
#  define ll_d_count(d)			atomic_read(&(d)->d_count)
#elif defined(HAVE_D_COUNT)
#  define ll_d_count(d)			d_count(d)
#else
#  define ll_d_count(d)			((d)->d_count)
#endif /* HAVE_DCACHE_LOCK */

#ifndef HAVE_IN_COMPAT_SYSCALL
#define in_compat_syscall	is_compat_task
#endif

#endif /* LUSTRE_PATCHLESS_COMPAT_H */
