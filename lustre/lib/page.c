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
