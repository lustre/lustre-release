/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025 Hewlett Packard Enterprise Development LP.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */
#ifndef _LUSTRE_COMPAT_LINUX_FOLIO_H
#define _LUSTRE_COMPAT_LINUX_FOLIO_H

#include <linux/aio.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/posix_acl_xattr.h>
#include <linux/bio.h>
#include <linux/xattr.h>
#include <linux/workqueue.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/pagevec.h>
#include <linux/workqueue.h>

#ifndef HAVE_GENERIC_ERROR_REMOVE_FOLIO
#ifdef HAVE_FOLIO_BATCH
#define generic_folio			folio
#else
#define generic_folio			page
#define folio_page(page, n)		(page)
#define folio_nr_pages(page)		(1)
#define page_folio(page)		(page)
#endif
static inline int generic_error_remove_folio(struct address_space *mapping,
					     struct generic_folio *folio)
{
	int pg, npgs = folio_nr_pages(folio);
	int err = 0;

	for (pg = 0; pg < npgs; pg++) {
		err = generic_error_remove_page(mapping, folio_page(folio, pg));
		if (err)
			break;
	}
	return err;
}
#endif

#if defined(HAVE_FOLIO_BATCH) || defined(HAVE_READ_CACHE_FOLIO_WANTS_FILE)
static inline struct folio *
#else
static inline struct page *
#endif
ll_read_cache_folio(struct address_space *mapping, pgoff_t index,
		    filler_t *filler, void *data)
{
#if defined(HAVE_READ_CACHE_FOLIO_WANTS_FILE)
	struct file dummy_file;

	dummy_file.f_ra.ra_pages = 32; /* unused, modified on ra error */
	dummy_file.private_data = data;
	return read_cache_folio(mapping, index, filler, &dummy_file);
#elif defined(HAVE_FOLIO_BATCH)
	return read_cache_folio(mapping, index, filler, data);
#else
	return read_cache_page(mapping, index, filler, data);
#endif
}

#if defined(HAVE___FILEMAP_GET_FOLIO)
#define get_folio_lock(m, i, f, g)	__filemap_get_folio((m), (i), (f), (g))
#define get_folio_nowait(m, i, f, g)	__filemap_get_folio((m), (i), (f), (g))
#define get_folio_write(m, i, e, f, g)	__filemap_get_folio((m), (i), (f), (g))
#define get_folio_read(m, i, f, g)	__filemap_get_folio((m), (i), (f), (g))
#define get_folio_create(m, i, f, g)	__filemap_get_folio((m), (i), (f), (g))
#define get_folio_grab(m, i, f, g)	__filemap_get_folio((m), (i), (f), (g))
#define get_folio_cache(m, i, f, g)	__filemap_get_folio((m), (i), (f), (g))
#define fpgptr(folio)			(&folio->page)

/* older kernels maintain mapping back to kmap() */
#define ll_kmap_local_folio(f, off)	kmap_local_folio((f), (off))
#define ll_kunmap_local(kaddr)		kunmap_local((kaddr))

#ifndef FGP_WRITEBEGIN
#define FGP_WRITEBEGIN		(FGP_LOCK | FGP_WRITE | FGP_CREAT | FGP_STABLE)
#endif

#ifndef HAVE_SG_SET_FOLIO
#define sg_set_folio(sg, p, len, off)	\
	sg_set_page((sg), fpgptr((p)), (len), (off))
#endif

#ifndef HAVE_BIO_ADD_FOLIO
#define bio_add_folio(bio, pg, sz, off)	\
	bio_add_page((bio), fpgptr((pg)), (sz), (off))
#endif

#else /* !HAVE___FILEMAP_GET_FOLIO */
#define get_folio_lock(m, i, f, g)	find_lock_page((m), (i))
#define get_folio_nowait(m, i, f, g)	grab_cache_page_nowait((m), (i))
#ifdef HAVE_GRAB_CACHE_PAGE_WRITE_BEGIN_WITH_FLAGS
#define get_folio_write(m, i, e, f, g)	\
	grab_cache_page_write_begin((m), (i), (e))
#else
#define get_folio_write(m, i, e, f, g)	grab_cache_page_write_begin((m), (i))
#endif /* HAVE_GRAB_CACHE_PAGE_WRITE_BEGIN_WITH_FLAGS */
#define get_folio_read(m, i, f, g)		\
	find_get_page((m), (i))
#define get_folio_grab(m, i, f, g)		\
	grab_cache_page((m), (i))
#define get_folio_cache(m, i, f, g)		\
	pagecache_get_page((m), (i), (f), (g))
#define get_folio_create(m, i, f, g)		\
	find_or_create_page((m), (i), (g))

#define FGP_WRITEBEGIN			0

/* folio does not exist, Usage a page and provide mappings to struct page api
 * Note this pollutes the use of 'page' as a variable
 */
#define folio				page
#define kmap_local_folio(f, off)	kmap_local_page((f))
#define ll_kmap_local_folio(f, off)	kmap(fpgptr((f)))
#define ll_kunmap_local(kaddr)		kunmap(kmap_to_page((kaddr)))
#define page_folio(page)		(page)
#define fpgptr(page)			(page)
#define fpgno(folio, page)		0

/* private: */
#define folio_get_private(p)		((void *)page_private((p)))
#define folio_clear_private(p)		ClearPagePrivate((p))
#define folio_set_private(p)		SetPagePrivate((p))
#define folio_test_private(p)		PagePrivate((p))
#define folio_attach_private(p, v)		\
do {						\
	get_page(p);				\
	SetPagePrivate(p);			\
	p->private = (unsigned long)v;		\
} while (0)
/* private2: */
#define folio_test_private_2(p)		PagePrivate2((p))
#define folio_set_private_2(p)		SetPagePrivate2((p))
#define folio_clear_private_2(p)	ClearPagePrivate2((p))
/* writeback */
#define folio_test_writeback(p)		PageWriteback((p))
#define folio_wait_writeback(p)		wait_on_page_writeback((p))
#define folio_start_writeback(p)	set_page_writeback((p))
#define folio_end_writeback(p)		end_page_writeback((p))
/* checked */
#define folio_clear_checked(p)		ClearPageChecked((p))
#define folio_test_checked(p)		PageChecked((p))
#define folio_set_checked(p)		SetPageChecked((p))
/* uptodate */
#define folio_test_uptodate(p)		PageUptodate((p))
#define folio_mark_uptodate(p)		SetPageUptodate((p))
#define folio_clear_uptodate(p)		ClearPageUptodate((p))
/* dirty */
#define folio_test_dirty(p)		PageDirty((p))
#define folio_test_set_dirty(p)		TestSetPageDirty((p))
#define folio_clear_dirty_for_io(p)	clear_page_dirty_for_io((p))
/* anon */
#define folio_test_anon(p)		PageAnon((p))
#define folio_clear_reclaim(p)		ClearPageReclaim((p))
#define folio_alloc(gfp, ord)		alloc_page((gfp))
#define folio_test_mlocked(p)		PageMlocked((p))
#define folio_mark_accessed(p)		mark_page_accessed((p))
#define folio_get(p)			get_page((p))
#define folio_put(p)			put_page((p))
#define folio_trylock(p)		trylock_page((p))
#define folio_wait_locked(p)		wait_on_page_locked((p))
#define filemap_add_folio(mapping, folio, offset, gfp)	\
	add_to_page_cache_lru((folio), (mapping), (offset), (gfp))
#define folio_change_private(p, v)	\
	((p)->private = (unsigned long)v)
#define folio_test_locked(p)		PageLocked((p))
#define folio_lock(p)			lock_page((p))
#define folio_unlock(p)			unlock_page((p))
#define folio_pos(p)			page_offset((p))
#define flush_dcache_folio(p)		flush_dcache_page((p))
#define filemap_alloc_folio(gfp, ord)	__page_cache_alloc((gfp))
#define folio_ref_count(p)		page_count((p))
#define virt_to_folio(addr)		virt_to_page((addr))
#define copy_folio_to_iter(f, o, b, i)	\
	copy_page_to_iter((f), (o), (b), (i))
#define sg_set_folio(sg, p, len, off)	\
	sg_set_page((sg), (p), (len), (off))
#define bio_add_folio(bio, pg, sz, off)	\
	bio_add_page((bio), (pg), (sz), (off))
#define folio_zero_range(p, o, len)	zero_user((p), (o), (len))
#define folio_address(p)		page_address((p))
#define folio_page_idx(folio, pg)	0
#endif /* HAVE___FILEMAP_GET_FOLIO */

static inline struct page *ll_read_cache_page(struct address_space *mapping,
					      pgoff_t index, filler_t *filler,
					      void *data)
{
	struct folio *f = ll_read_cache_folio(mapping, index, filler, data);

	return fpgptr(f);
}

static inline bool is_empty_folio(struct folio *folio, size_t off,
				  size_t len)
{
	bool is_zero;
	void *addr = kmap_local_folio(folio, 0);

	is_zero = memchr_inv(addr + off, 0, len) == NULL;
	kunmap_local(addr);

	return is_zero;
}

#if defined(HAVE_FILEMAP_GET_FOLIOS)
# define ll_filemap_get_folios(m, s, e, fbatch) \
	 filemap_get_folios(m, &s, e, fbatch)
#elif defined(HAVE_PAGEVEC_LOOKUP_THREE_PARAM)
# define ll_filemap_get_folios(m, s, e, pvec) \
	 pagevec_lookup((struct pagevec *)pvec, m, &s)
#else
# define ll_filemap_get_folios(m, s, e, pvec) \
	 pagevec_lookup((struct pagevec *)pvec, m, s, PAGEVEC_SIZE)
#endif

#if defined(HAVE_FOLIO_BATCH)
# define ll_folio_batch_init(batch)	folio_batch_init(batch)
# define fbatch_at(fbatch, f)		((fbatch)->folios[(f)])
# define fbatch_at_npgs(fbatch, f)	\
	 folio_nr_pages((fbatch)->folios[(f)])
# define fbatch_at_pg(fbatch, f, pg)	\
	 (fpgptr((fbatch)->folios[(f)]))
# define folio_batch_add_page(fbatch, page) \
	 folio_batch_add(fbatch, page_folio(page))
# ifndef HAVE_FOLIO_BATCH_REINIT
static inline void folio_batch_reinit(struct folio_batch *fbatch)
{
	fbatch->nr = 0;
}
# endif /* HAVE_FOLIO_BATCH_REINIT */

static inline pgoff_t folio_index_page(struct page *page)
{
	struct folio *_f = page_folio(page);

	return _f->index + folio_page_idx(_f, page);
}

#else /* !HAVE_FOLIO_BATCH */

# ifdef HAVE_PAGEVEC
#  define folio_batch			pagevec
# endif
# define folio_batch_init(pvec)		pagevec_init(pvec)
# define folio_batch_reinit(pvec)	pagevec_reinit(pvec)
# define folio_batch_count(pvec)	pagevec_count(pvec)
# define folio_batch_space(pvec)	pagevec_space(pvec)
# define folio_batch_add(pvec, page) \
	 pagevec_add(pvec, page)
# define folio_batch_add_page(pvec, page) \
	 pagevec_add(pvec, page)
# define folio_batch_release(pvec) \
	 pagevec_release(((struct pagevec *)pvec))
# define ll_folio_batch_init(pvec)	pagevec_init(pvec)
# define fbatch_at(pvec, n)		((pvec)->pages[(n)])
# define fbatch_at_npgs(pvec, n)	1
# define fbatch_at_pg(pvec, n, pg)	((pvec)->pages[(n)])
# define folio_index_page(pg)		((pg)->index)

#endif /* HAVE_FOLIO_BATCH */

/**
 * delete_from_page_cache is not exported anymore
 */
#ifdef HAVE_DELETE_FROM_PAGE_CACHE
#define cfs_delete_from_page_cache(page)	delete_from_page_cache((page))
#else
static inline void cfs_delete_from_page_cache(struct page *page)
{
	if (!page->mapping)
		return;
	BUG_ON(!PageLocked(page));
	if (S_ISREG(page->mapping->host->i_mode)) {
		generic_error_remove_folio(page->mapping, page_folio(page));
	} else {
		loff_t lstart = folio_index_page(page) << PAGE_SHIFT;
		loff_t lend = lstart + PAGE_SIZE - 1;
		struct address_space *mapping = page->mapping;

		get_page(page);
		unlock_page(page);
		truncate_inode_pages_range(mapping, lstart, lend);
		lock_page(page);
		put_page(page);
	}
}
#endif

#ifdef HAVE_FOLIO_BATCH
static inline void cfs_folio_delete_from_cache(struct folio *folio)
{
	if (!folio->mapping)
		return;
	BUG_ON(!folio_test_locked(folio));
	/* on entry page is locked */
	if (S_ISREG(folio->mapping->host->i_mode)) {
		generic_error_remove_folio(folio->mapping, folio);
	} else {
		loff_t lstart = folio->index << PAGE_SHIFT;
		loff_t lend = lstart + folio_size(folio) - 1;

		folio_get(folio);
		folio_unlock(folio);
		truncate_inode_pages_range(folio->mapping, lstart, lend);
		folio_lock(folio);
		folio_put(folio);
	}
}
#else
#define cfs_folio_delete_from_cache(pg)	cfs_delete_from_page_cache((pg))
#endif /* HAVE_FOLIO_BATCH */

#ifdef HAVE_NSPROXY_COUNT_AS_REFCOUNT
#define nsproxy_dec(ns)		refcount_dec(&(ns)->count)
#else
#define nsproxy_dec(ns)		atomic_dec(&(ns)->count)
#endif

#ifndef HAVE_INODE_GET_CTIME
#define inode_get_ctime(i)		((i)->i_ctime)
#define inode_set_ctime_to_ts(i, ts)	((i)->i_ctime = ts)
#define inode_set_ctime_current(i) \
	inode_set_ctime_to_ts((i), current_time((i)))

static inline struct timespec64 inode_set_ctime(struct inode *inode,
						time64_t sec, long nsec)
{
	struct timespec64 ts = { .tv_sec  = sec,
				 .tv_nsec = nsec };

	return inode_set_ctime_to_ts(inode, ts);
}
#endif /* !HAVE_INODE_GET_CTIME */

#ifndef HAVE_INODE_GET_MTIME_SEC

#define inode_get_ctime_sec(i)		(inode_get_ctime((i)).tv_sec)

#define inode_get_atime(i)		((i)->i_atime)
#define inode_get_atime_sec(i)		((i)->i_atime.tv_sec)
#define inode_set_atime_to_ts(i, ts)	((i)->i_atime = ts)

static inline struct timespec64 inode_set_atime(struct inode *inode,
						time64_t sec, long nsec)
{
	struct timespec64 ts = { .tv_sec  = sec,
				 .tv_nsec = nsec };
	return inode_set_atime_to_ts(inode, ts);
}

#define inode_get_mtime(i)		((i)->i_mtime)
#define inode_get_mtime_sec(i)		((i)->i_mtime.tv_sec)
#define inode_set_mtime_to_ts(i, ts)	((i)->i_mtime = ts)

static inline struct timespec64 inode_set_mtime(struct inode *inode,
						time64_t sec, long nsec)
{
	struct timespec64 ts = { .tv_sec  = sec,
				 .tv_nsec = nsec };
	return inode_set_mtime_to_ts(inode, ts);
}
#endif  /* !HAVE_INODE_GET_MTIME_SEC */

#ifdef HAVE_WRITE_BEGIN_FOLIO
/* .write_begin is passed **folio which is put with .write_end *folio */
#define wbe_folio			folio
#define wbe_page_folio(page)		page_folio((page))
static inline struct page *wbe_folio_page(struct folio *folio)
{
	BUG_ON(folio_nr_pages(folio) != 1);
	return folio_page(folio, 0);
}
#else
/* .write_begin is passed **page which is put with .write_end *page */
#define wbe_folio			page
#define wbe_page_folio(page)		(page)
#define wbe_folio_page(page)		(page)
#endif

#ifndef HAVE_PAGE_PRIVATE_2
#define PagePrivate2(page)	test_bit(PG_private_2, &(page)->flags)
#define SetPagePrivate2(page)	set_bit(PG_private_2, &(page)->flags)
#define ClearPagePrivate2(page)	clear_bit(PG_private_2, &(page)->flags)
#endif

#ifdef HAVE_FOLIO_MAPCOUNT
/* clone of fs/proc/internal.h:
 *   folio_precise_page_mapcount(struct folio *folio, struct page *page)
 */
static inline int folio_mapcount_page(struct page *page)
{
	struct folio *folio = page_folio(page);
	int mapcount = atomic_read(&page->_mapcount) + 1;

	if (page_mapcount_is_type(mapcount))
		mapcount = 0;
	if (folio_test_large(folio))
		mapcount += folio_entire_mapcount(folio);

	return mapcount;
}
#else /* !HAVE_FOLIO_MAPCOUNT */
#define folio_mapcount(folio)			page_mapcount(fpgptr(folio))
#define folio_mapcount_page(pg)			page_mapcount((pg))
#endif /* HAVE_FOLIO_MAPCOUNT */

#endif /* _LUSTRE_COMPAT_LINUX_FOLIO_H */
