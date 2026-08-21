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
		lnb->lnb_folio = NULL;
		lnb->lnb_fpgno = 0;
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

static int osd_get_folio(const struct lu_env *env, struct dt_object *dt,
			 struct niobuf_local *lnb, gfp_t gfp_mask, bool write)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	struct folio *folio;
	pgoff_t index;

	LASSERT(inode);
	index = lnb->lnb_file_offset >> PAGE_SHIFT;
	if (write) {
		folio = get_folio_create(inode->i_mapping, index,
					 FGP_LOCK | FGP_ACCESSED | FGP_CREAT,
					 gfp_mask);
		if (IS_ERR_OR_NULL(folio))
			return -ENOMEM;

		LASSERT(!folio_test_private_2(folio));
	} else {
		/*
		 * Specially handling for hole in the memory FS during read.
		 * It does not allocate pages for holes, just records them and
		 * free them after reading.
		 * Otherwise, reading on a large sparse file may hit OOM.
		 */
		folio = get_folio_lock(inode->i_mapping, index, FGP_LOCK,
				       gfp_mask);
		/* fallocated page? */
		if (!IS_ERR_OR_NULL(folio) && !folio_test_uptodate(folio)) {
			folio_unlock(folio);
			folio_put(folio);
			folio = NULL;
		}

		if (IS_ERR_OR_NULL(folio)) {
			folio = folio_alloc(gfp_mask, 0);
			if (!folio)
				return -ENOMEM;

			folio_set_private_2(folio);
			folio_lock(folio);
			folio_clear_uptodate(folio);
			folio->index = index;
			lnb->lnb_hole = 1;
		}
	}

	LASSERT(folio_nr_pages(folio) == 1);
	lnb->lnb_folio = folio;
	lnb->lnb_fpgno = 0;
	lnb->lnb_locked = 1;
	if (!lnb->lnb_hole)
		folio_mark_accessed(folio);

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

	ll_folio_batch_init(&fbatch);
	for (i = 0; i < npages; i++) {
		struct folio *folio = lnb[i].lnb_folio;

		if (IS_ERR_OR_NULL(folio))
			continue;

		/* If the page is not cached in the memory FS, then free it. */
		if (folio_test_private_2(folio)) {
			LASSERT(lnb[i].lnb_hole);
			LASSERT(folio_test_locked(folio));
			folio_clear_private_2(folio);
			folio_unlock(folio);
			folio_put(folio);
		} else {
			if (lnb[i].lnb_locked)
				folio_unlock(folio);
			if (folio_batch_add(&fbatch, folio) == 0)
				folio_batch_release(&fbatch);
		}

		lnb[i].lnb_folio = NULL;
		lnb[i].lnb_fpgno = 0;
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
		rc = osd_get_folio(env, dt, lnb, gfp_mask,
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

	result = kernel_read(file, buf->lb_buf, buf->lb_len, pos);
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

	result = kernel_write(file, buf->lb_buf, buf->lb_len, pos);
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

			LASSERT(folio_test_private_2(lnb[i].lnb_folio));
			kaddr = lnb_kmap_local(&lnb[i]);
			memset(kaddr, 0, PAGE_SIZE);
			kunmap_local(kaddr);
			folio_mark_uptodate(lnb[i].lnb_folio);
		} else {
			/*
			 * The page in cache for MemFS should be always
			 * in uptodate state.
			 */
			LASSERT(folio_test_uptodate(lnb[i].lnb_folio));
			folio_unlock(lnb[i].lnb_folio);
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
		folio_clear_uptodate(lnb[i].lnb_folio);
		if (lnb[i].lnb_len == PAGE_SIZE)
			continue;

		if (maxidx < lnb[i].lnb_folio->index) {
			long off;
			char *p;

			p = lnb_kmap_local(&lnb[i]);
			off = lnb[i].lnb_page_offset;
			if (off)
				memset(p, 0, off);
			off = (lnb[i].lnb_page_offset + lnb[i].lnb_len) &
			      ~PAGE_MASK;
			if (off)
				memset(p + off, 0, PAGE_SIZE - off);
			kunmap_local(p);
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
			LASSERT(!IS_ERR_OR_NULL(lnb[i].lnb_folio));
			generic_error_remove_folio(inode->i_mapping,
						   lnb[i].lnb_folio);
			continue;
		}

		/*
		 * TODO: @lnb array is a sorted array according to the file
		 * offset, thus it just needs to check the last @lnb for
		 * file size.
		 */
		if (user_size < lnb[i].lnb_file_offset + lnb[i].lnb_len)
			user_size = lnb[i].lnb_file_offset + lnb[i].lnb_len;

		LASSERT(folio_test_locked(lnb[i].lnb_folio));
		LASSERT(!folio_test_writeback(lnb[i].lnb_folio));
		/* LASSERT(!folio_test_dirty(lnb[i].lnb_folio)); */

		folio_mark_uptodate(lnb[i].lnb_folio);
#ifdef HAVE_DIRTY_FOLIO
		mapping->a_ops->dirty_folio(mapping, lnb[i].lnb_folio);
#else
		mapping->a_ops->set_page_dirty(fpgptr(lnb[i].lnb_folio));
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

const struct dt_body_operations osd_wbcfs_body_ops = {
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
