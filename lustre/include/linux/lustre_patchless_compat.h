#ifndef LUSTRE_PATCHLESS_COMPAT_H
#define LUSTRE_PATCHLESS_COMPAT_H

#include <linux/lustre_version.h>
#ifndef LUSTRE_KERNEL_VERSION
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
        atomic_add(-1, &nr_pagecache); // XXX pagecache_acct(-1);
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

        clear_page_dirty(page);
        ClearPageUptodate(page);
        ClearPageMappedToDisk(page);
        ll_remove_from_page_cache(page);
        page_cache_release(page);       /* pagecache ref */
}
#endif

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
	
#define LUSTRE_PATCHLESS

#ifndef ATTR_FROM_OPEN
#define ATTR_FROM_OPEN 0
#endif
#ifndef ATTR_RAW
#define ATTR_RAW 0
#endif

#endif /* LUSTRE_KERNEL_VERSION */

#endif
