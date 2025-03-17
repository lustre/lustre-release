// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2025-2026, DDN/Whamcloud, Inc.
 */

/*
 * Author: Yingjin Qian <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM	S_OSD

#include <linux/mm.h>
#include <linux/swap.h>

#include <lustre_compat.h>
#include <obd_support.h>

#include "osd_internal.h"

/* Copied from osd-ldiskfs */
static int osd_map_remote_to_local(loff_t offset, ssize_t len, int *nrpages,
				   struct niobuf_local *lnb, int maxlnb)
{
	int rc = 0;

	ENTRY;

	*nrpages = 0;

	while (len > 0) {
		int poff = offset & (PAGE_SIZE - 1);
		int plen = PAGE_SIZE - poff;

		if (*nrpages >= maxlnb) {
			rc = -EOVERFLOW;
			break;
		}

		if (plen > len)
			plen = len;
		lnb->lnb_file_offset = offset;
		lnb->lnb_page_offset = poff;
		lnb->lnb_len = plen;
		lnb->lnb_flags = 0;
		lnb->lnb_page = NULL;
		lnb->lnb_rc = 0;
		lnb->lnb_guard_rpc = 0;
		lnb->lnb_guard_disk = 0;
		lnb->lnb_locked = 0;
		lnb->lnb_hole = 0;

		LASSERTF(plen <= len, "plen %u, len %lld\n", plen,
			 (long long) len);
		offset += plen;
		len -= plen;
		lnb++;
		(*nrpages)++;
	}

	RETURN(rc);
}

static int osd_get_page(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, gfp_t gfp_mask, bool write)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	struct page *page;
	pgoff_t index;

	LASSERT(inode);
	index = lnb->lnb_file_offset >> PAGE_SHIFT;
	if (write) {
		page = find_or_create_page(inode->i_mapping, index, gfp_mask);
		if (page == NULL)
			return -ENOMEM;

		LASSERT(!PagePrivate2(page));
	} else {
		/*
		 * Specially handling for hole in the memory FS during read.
		 * It does not allocate pages for holes, just records them and
		 * free them after reading.
		 * Otherwise, reading on a large sparse file may hit OOM.
		 */
		page = find_lock_page(inode->i_mapping, index);
		/* fallocated page? */
		if (page && !PageUptodate(page)) {
			unlock_page(page);
			put_page(page);
			page = NULL;
		}

		if (page == NULL) {
			page = alloc_page(gfp_mask);
			if (!page)
				return -ENOMEM;

			SetPagePrivate2(page);
			lock_page(page);
			ClearPageUptodate(page);
			page->index = index;
			lnb->lnb_hole = 1;
		}
	}

	lnb->lnb_page = page;
	lnb->lnb_locked = 1;
	if (!lnb->lnb_hole)
		mark_page_accessed(page);

	return 0;
}

/*
 * Unlock and release pages loaded by @osd_bufs_get().
 *
 * Unlock \a npages pages from \a lnb and drop the refcount on them.
 */
static int osd_bufs_put(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages)
{
	struct folio_batch fbatch;
	int i;

	ll_folio_batch_init(&fbatch, 0);
	for (i = 0; i < npages; i++) {
		struct page *page = lnb[i].lnb_page;

		if (page == NULL)
			continue;

		/* If the page is not cached in the memory FS, then free it. */
		if (PagePrivate2(page)) {
			LASSERT(lnb[i].lnb_hole);
			LASSERT(PageLocked(page));
			ClearPagePrivate2(page);
			unlock_page(page);
			__free_page(page);
		} else {
			if (lnb[i].lnb_locked)
				unlock_page(page);
			if (folio_batch_add_page(&fbatch, page) == 0)
				folio_batch_release(&fbatch);
		}

		lnb[i].lnb_page = NULL;
	}

	folio_batch_release(&fbatch);
	return 0;
}

/**
 * osd_bufs_get() - Load and lock pages undergoing IO
 * @env: thread execution environment
 * @dt: dt object undergoing IO (OSD object + methods)
 * @pos: byte offset of IO start
 * @len: number of bytes of IO
 * @lnb: array of extents undergoing IO
 * @maxlnb: maximum lnb
 * @rw: read or write operation, and other flags
 *
 * Pages as described in the \a lnb array are fetched (from disk or cache)
 * and locked for IO by the caller.
 *
 * Returns:
 * %pages - (zero or more) loaded successfully
 * %-ENOMEM - on memory/page allocation error
 */
static int osd_bufs_get(const struct lu_env *env, struct dt_object *dt,
			loff_t pos, ssize_t len, struct niobuf_local *lnb,
			int maxlnb, enum dt_bufs_type rw)
{
	struct osd_object *obj = osd_dt_obj(dt);
	gfp_t gfp_mask;
	int npages;
	int rc;
	int i;

	LASSERT(obj->oo_inode);

	if (unlikely(obj->oo_destroyed))
		RETURN(-ENOENT);

	rc = osd_map_remote_to_local(pos, len, &npages, lnb, maxlnb);
	if (rc)
		RETURN(rc);

	/* this could also try less hard for DT_BUFS_TYPE_READAHEAD pages */
	gfp_mask = rw & DT_BUFS_TYPE_LOCAL ? (GFP_NOFS | __GFP_HIGHMEM) :
					     GFP_HIGHUSER;
	for (i = 0; i < npages; i++, lnb++) {
		rc = osd_get_page(env, dt, lnb, gfp_mask,
				  rw & DT_BUFS_TYPE_WRITE);
		if (rc)
			GOTO(cleanup, rc);
	}

	RETURN(i);

cleanup:
	if (i > 0)
		osd_bufs_put(env, dt, lnb - i, i);
	return rc;
}

static ssize_t osd_read(const struct lu_env *env, struct dt_object *dt,
			struct lu_buf *buf, loff_t *pos)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *dev = osd_obj2dev(obj);
	struct inode *inode = obj->oo_inode;
	struct file *file;
	ssize_t result;

	ENTRY;

	/* TODO: Specially handling for symlink. */
	if (S_ISLNK(dt->do_lu.lo_header->loh_attr))
		RETURN(-EOPNOTSUPP);

	file = osd_alloc_file_pseudo(inode, dev->od_mnt, "/",
				     O_NOATIME | O_RDONLY, inode->i_fop);
	if (IS_ERR(file))
		RETURN(PTR_ERR(file));

	result = cfs_kernel_read(file, buf->lb_buf, buf->lb_len, pos);
	ihold(inode);
	fput(file);
	RETURN(result);
}

static ssize_t osd_write(const struct lu_env *env, struct dt_object *dt,
			 const struct lu_buf *buf, loff_t *pos,
			 struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *dev = osd_obj2dev(obj);
	struct inode *inode = obj->oo_inode;
	struct file *file;
	ssize_t result;

	ENTRY;

	/* TODO: Specially handling for symlink. */
	if (S_ISLNK(dt->do_lu.lo_header->loh_attr))
		RETURN(-EOPNOTSUPP);

	file = osd_alloc_file_pseudo(inode, dev->od_mnt, "/",
				     O_NOATIME | O_WRONLY, inode->i_fop);
	if (IS_ERR(file))
		RETURN(PTR_ERR(file));

	result = cfs_kernel_write(file, buf->lb_buf, buf->lb_len, pos);
	ihold(inode);
	fput(file);
	RETURN(result);
}

/* Can we move all osd_read_prep() codes into osd_bufs_get() ? */
static int osd_read_prep(const struct lu_env *env, struct dt_object *dt,
			 struct niobuf_local *lnb, int npages)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	loff_t isize;
	int i;

	ENTRY;

	LASSERT(inode);
	isize = i_size_read(inode);

	for (i = 0; i < npages; i++) {
		/*
		 * If there is no more data, abort early.
		 * lnb->lnb_rc == 0, so it is easy to detect later.
		 */
		if (isize <= lnb[i].lnb_file_offset)
			break;

		/*
		 * Instead of looking if we go beyond isize, send complete
		 * pages all the time.
		 */
		lnb[i].lnb_rc = lnb[i].lnb_len;
		if (lnb[i].lnb_hole) {
			void *kaddr;

			LASSERT(PagePrivate2(lnb[i].lnb_page));
			kaddr = kmap(lnb[i].lnb_page);
			memset(kaddr, 0, PAGE_SIZE);
			kunmap(lnb[i].lnb_page);
			SetPageUptodate(lnb[i].lnb_page);
		} else {
			/*
			 * The page in cache for MemFS should be always
			 * in uptodate state.
			 */
			LASSERT(PageUptodate(lnb[i].lnb_page));
			unlock_page(lnb[i].lnb_page);
			/*
			 * No need to unlock in osd_bufs_put(). The sooner page
			 * is unlocked, the earlier another client can access
			 * it.
			 */
			lnb[i].lnb_locked = 0;
		}
	}

	RETURN(0);
}

static int osd_write_prep(const struct lu_env *env, struct dt_object *dt,
			  struct niobuf_local *lnb, int npages)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	ssize_t isize;
	__s64 maxidx;
	int i;

	ENTRY;

	LASSERT(inode);

	isize = i_size_read(inode);
	maxidx = ((isize + PAGE_SIZE - 1) >> PAGE_SHIFT) - 1;
	for (i = 0; i < npages; i++) {
		/*
		 * Till commit the content of the page is undefined
		 * we will set it uptodate once bulk is done. Otherwise
		 * subsequent reads can access non-stable data.
		 */
		ClearPageUptodate(lnb[i].lnb_page);

		if (lnb[i].lnb_len == PAGE_SIZE)
			continue;

		if (maxidx < lnb[i].lnb_page->index) {
			long off;
			char *p = kmap(lnb[i].lnb_page);

			off = lnb[i].lnb_page_offset;
			if (off)
				memset(p, 0, off);
			off = (lnb[i].lnb_page_offset + lnb[i].lnb_len) &
			      ~PAGE_MASK;
			if (off)
				memset(p + off, 0, PAGE_SIZE - off);
			kunmap(lnb[i].lnb_page);
		}
	}

	RETURN(0);
}


static int osd_write_commit(const struct lu_env *env, struct dt_object *dt,
			    struct niobuf_local *lnb, int npages,
			    struct thandle *th, __u64 user_size)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	struct address_space *mapping = inode->i_mapping;
	size_t isize;
	int i;

	ENTRY;

	LASSERT(inode);

	for (i = 0; i < npages; i++) {
		if (lnb[i].lnb_rc) { /* ENOSPC, network RPC error, etc. */
			LASSERT(lnb[i].lnb_page);
			generic_error_remove_folio(inode->i_mapping,
						   page_folio(lnb[i].lnb_page));
			continue;
		}

		/*
		 * TODO: @lnb array is a sorted array according to the file
		 * offset, thus it just needs to check the last @lnb for
		 * file size.
		 */
		if (user_size < lnb[i].lnb_file_offset + lnb[i].lnb_len)
			user_size = lnb[i].lnb_file_offset + lnb[i].lnb_len;

		LASSERT(PageLocked(lnb[i].lnb_page));
		LASSERT(!PageWriteback(lnb[i].lnb_page));
		/* LASSERT(!PageDirty(lnb[i].lnb_page)); */

		SetPageUptodate(lnb[i].lnb_page);
#ifdef HAVE_DIRTY_FOLIO
		mapping->a_ops->dirty_folio(mapping,
					    page_folio(lnb[i].lnb_page));
#else
		mapping->a_ops->set_page_dirty(lnb[i].lnb_page);
#endif
	}

	spin_lock(&inode->i_lock);
	isize = i_size_read(inode);
	if (isize < user_size)
		i_size_write(inode, user_size);
	spin_unlock(&inode->i_lock);

	CDEBUG(D_INFO, "Size after write: i_size=%lld user_size=%llu\n",
	       i_size_read(inode), user_size);
	/* No transno is needed for in-memory FS. */
	th->th_local = 1;
	RETURN(0);
}

/* TODO: Implement punch operation. */
static int osd_punch(const struct lu_env *env, struct dt_object *dt,
		     __u64 start, __u64 end, struct thandle *th)
{
	RETURN(0);
}

/* TODO: Implemented lseek operation.  */
static loff_t osd_lseek(const struct lu_env *env, struct dt_object *dt,
			loff_t offset, int whence)
{
	RETURN(0);
}

const struct dt_body_operations osd_body_ops = {
	.dbo_read			= osd_read,
	.dbo_write			= osd_write,
	.dbo_bufs_get			= osd_bufs_get,
	.dbo_bufs_put			= osd_bufs_put,
	.dbo_write_prep			= osd_write_prep,
	.dbo_write_commit		= osd_write_commit,
	.dbo_read_prep			= osd_read_prep,
	.dbo_punch			= osd_punch,
	.dbo_lseek			= osd_lseek,
};

