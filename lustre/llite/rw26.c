// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre Lite I/O page cache routines for the 2.5/2.6 kernel version
 */

#include <linux/buffer_head.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mpage.h>
#include <linux/pagemap.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/writeback.h>
#include <linux/migrate.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include "llite_internal.h"
#include <lustre_compat.h>

#ifdef HAVE_INVALIDATE_FOLIO
/**
 * ll_invalidate_folio() - Implements Linux VM address_space::invalidate_folio()
 * method. This method is called when the folio is truncated from a file, either
 * as a result of explicit truncate, or when inode is removed from memory
 * (as a result of final iput(), umount, or memory pressure induced icache
 * shrinking).
 * @folio: Pointer to folio struct (collection of pages)
 * @offset: Starting offset in bytes
 * @len: length of folio to be invalidated
 *
 * [0, off] bytes of the folio remain valid (this is for a case of non-page
 * aligned truncate). Lustre leaves partially truncated folios in the cache,
 * relying on struct inode::i_size to limit further accesses.
 */
static void ll_invalidate_folio(struct folio *folio, size_t offset, size_t len)
{
	struct inode *inode;
	struct lu_env *env;
	struct cl_page *page;
	struct cl_object *obj;

	LASSERT(!folio_test_writeback(folio));
	LASSERT(folio_test_locked(folio));

	if (!(offset == 0 && len == folio_size(folio)) &&
	    !folio_test_large(folio))
		return;

	/* Drop the pages from the folio */
	env = cl_env_percpu_get();
	LASSERT(!IS_ERR(env));

	inode = folio_inode(folio);
	obj = ll_i2info(inode)->lli_clob;
	if (obj != NULL) {
		int n, npgs = folio_nr_pages(folio);

		for (n = 0; n < npgs; n++) {
			struct page *vmpage = folio_page(folio, n);

			LASSERT(PageLocked(vmpage));
			LASSERT(!PageWriteback(vmpage));

			page = cl_vmpage_page(vmpage, obj);
			if (page != NULL) {
				cl_page_delete(env, page);
				cl_page_put(env, page);
			}
		}
	} else {
		LASSERT(!folio_get_private(folio));
	}
	cl_env_percpu_put(env);
}
#else

/**
 * ll_invalidatepage() - Implements Linux VM address_space::invalidatepage()
 * method. This method is called when the page is truncate from a file, either
 * as a result of explicit truncate, or when inode is removed from memory
 * (as a result of final iput(), umount, or memory pressure induced icache
 * shrinking).
 *
 * @vmpage: pointer to struct page (single page)
 * @offset: Starting offset in bytes
 *
 * [0, offset] bytes of the page remain valid (this is for a case of not-page
 * aligned truncate). Lustre leaves partially truncated page in the cache,
 * relying on struct inode::i_size to limit further accesses.
 */
static void ll_invalidatepage(struct page *vmpage,
#ifdef HAVE_INVALIDATE_RANGE
				unsigned int offset, unsigned int length
#else
				unsigned long offset
#endif
			     )
{
	struct inode     *inode;
	struct lu_env    *env;
	struct cl_page   *page;
	struct cl_object *obj;

	LASSERT(PageLocked(vmpage));
	LASSERT(!PageWriteback(vmpage));

	/*
	 * It is safe to not check anything in invalidatepage/releasepage
	 * below because they are run with page locked and all our io is
	 * happening with locked page too
	 */
#ifdef HAVE_INVALIDATE_RANGE
	if (offset == 0 && length == PAGE_SIZE) {
#else
	if (offset == 0) {
#endif
		/* See the comment in ll_releasepage() */
		env = cl_env_percpu_get();
		LASSERT(!IS_ERR(env));

		inode = vmpage->mapping->host;
		obj = ll_i2info(inode)->lli_clob;
		if (obj != NULL) {
			page = cl_vmpage_page(vmpage, obj);
			if (page != NULL) {
				cl_page_delete(env, page);
				cl_page_put(env, page);
			}
		} else
			LASSERT(vmpage->private == 0);

		cl_env_percpu_put(env);
	}

	if (CFS_FAIL_PRECHECK(OBD_FAIL_LLITE_PAGE_INVALIDATE_PAUSE)) {
		unlock_page(vmpage);
		CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_PAGE_INVALIDATE_PAUSE,
				 cfs_fail_val);
		lock_page(vmpage);
	}
}
#endif

static bool do_release_page(struct page *vmpage, gfp_t wait)
{
	struct address_space *mapping;
	struct cl_object *obj;
	struct cl_page *page;
	struct lu_env *env;
	int result = 0;

	ENTRY;

	LASSERT(PageLocked(vmpage));
	if (PageWriteback(vmpage) || PageDirty(vmpage))
		RETURN(0);

	mapping = vmpage->mapping;
	if (mapping == NULL)
		RETURN(1);

	obj = ll_i2info(mapping->host)->lli_clob;
	if (obj == NULL)
		RETURN(1);

	page = cl_vmpage_page(vmpage, obj);
	if (page == NULL)
		RETURN(1);

	env = cl_env_percpu_get();
	LASSERT(!IS_ERR(env));

	if (!cl_page_in_use(page)) {
		result = 1;
		cl_page_delete(env, page);
	}

	/* To use percpu env array, the call path can not be rescheduled;
	 * otherwise percpu array will be messed if ll_releaspage() called
	 * again on the same CPU.
	 *
	 * If this page holds the last refc of cl_object, the following
	 * call path may cause reschedule:
	 *   cl_page_put -> cl_page_free -> cl_object_put ->
	 *     lu_object_put -> lu_object_free -> lov_delete_raid0.
	 *
	 * However, the kernel can't get rid of this inode until all pages have
	 * been cleaned up. Now that we hold page lock here, it's pretty safe
	 * that we won't get into object delete path.
	 */
	LASSERT(cl_object_refc(obj) > 1);
	cl_page_put(env, page);

	cl_env_percpu_put(env);
	RETURN(result);
}

#ifdef HAVE_AOPS_RELEASE_FOLIO
static bool ll_release_folio(struct folio *folio, gfp_t wait)
{
	struct page *vmpage = folio_page(folio, 0);

	/* folio_nr_pages(folio) == 1 is fixed with grab_cache_page* */
	BUG_ON(folio_nr_pages(folio) != 1);

	return do_release_page(vmpage, wait);
}
#else /* !HAVE_AOPS_RELEASE_FOLIO */
#ifdef HAVE_RELEASEPAGE_WITH_INT
#define RELEASEPAGE_ARG_TYPE int
#else
#define RELEASEPAGE_ARG_TYPE gfp_t
#endif
static int ll_releasepage(struct page *vmpage, RELEASEPAGE_ARG_TYPE gfp_mask)
{
	return do_release_page(vmpage, gfp_mask);
}
#endif /* HAVE_AOPS_RELEASE_FOLIO */

/* iov_iter_alignment() is introduced in 3.16 similar to HAVE_DIO_ITER */
#if defined(HAVE_DIO_ITER)
static unsigned long iov_iter_alignment_vfs(const struct iov_iter *i)
{
	return iov_iter_alignment(i);
}
#else /* copied from alignment_iovec() */
static unsigned long iov_iter_alignment_vfs(const struct iov_iter *i)
{
	const struct iovec *iov = i->iov;
	unsigned long res;
	size_t size = i->count;
	size_t n;

	if (!size)
		return 0;

	res = (unsigned long)iov->iov_base + i->iov_offset;
	n = iov->iov_len - i->iov_offset;
	if (n >= size)
		return res | size;

	size -= n;
	res |= n;
	while (size > (++iov)->iov_len) {
		res |= (unsigned long)iov->iov_base | iov->iov_len;
		size -= iov->iov_len;
	}
	res |= (unsigned long)iov->iov_base | size;

	return res;
}
#endif

/*
 * Lustre could relax a bit for alignment, io count is not
 * necessary page alignment.
 */
bool ll_iov_iter_is_unaligned(struct iov_iter *i)
{
	size_t orig_size = i->count;
	size_t count = orig_size & ~PAGE_MASK;
	unsigned long res;

	if (iov_iter_count(i) & ~PAGE_MASK)
		return true;

	if (!iov_iter_is_aligned(i, ~PAGE_MASK, 0))
		return true;

	if (!count)
		return iov_iter_alignment_vfs(i) & ~PAGE_MASK;

	if (orig_size > PAGE_SIZE) {
		iov_iter_truncate(i, orig_size - count);
		res = iov_iter_alignment_vfs(i);
		iov_iter_reexpand(i, orig_size);

		return res & ~PAGE_MASK;
	}

	res = iov_iter_alignment_vfs(i);
	/* start address is page aligned */
	if ((res & ~PAGE_MASK) == orig_size)
		return false;

	return res & ~PAGE_MASK;
}

static int
ll_direct_rw_pages(const struct lu_env *env, struct cl_io *io, size_t size,
		   int rw, struct inode *inode, struct cl_sub_dio *sdio)
{
	struct cl_dio_pages *cdp = &sdio->csd_dio_pages;
	struct cl_sync_io *anchor = &sdio->csd_sync;
	struct cl_object *obj = io->ci_obj;
	struct cl_page *page;
	int iot = rw == READ ? CRT_READ : CRT_WRITE;
	loff_t offset = cdp->cdp_file_offset;
	ssize_t rc = 0;
	unsigned int i = 0;

	ENTRY;

	while (size > 0) {
		size_t from = offset & ~PAGE_MASK;
		size_t to = min(from + size, PAGE_SIZE);

		page = cl_page_find(env, obj, offset >> PAGE_SHIFT,
				    cdp->cdp_pages[i], CPT_TRANSIENT);
		if (IS_ERR(page))
			GOTO(out, rc = PTR_ERR(page));

		LASSERT(page->cp_type == CPT_TRANSIENT);

		page->cp_sync_io = anchor;
		if (inode && IS_ENCRYPTED(inode)) {
			/* In case of Direct IO on encrypted file, we need to
			 * add a reference to the inode on the cl_page.
			 * This info is required by llcrypt to proceed
			 * to encryption/decryption.
			 * This is safe because we know these pages are private
			 * to the thread doing the Direct IO.
			 */
			page->cp_inode = inode;
		}
		cdp->cdp_cl_pages[i] = page;
		/*
		 * Call page clip for incomplete pages, to set range of bytes
		 * in the page and to tell transfer formation engine to send
		 * the page even if it is beyond KMS (ie, don't trim IO to KMS)
		 */
		if (from != 0 || to != PAGE_SIZE)
			cl_page_clip(env, page, from, to);
		i++;

		offset += to - from;
		size -= to - from;
	}
	/* on success, we should hit every page in the cdp and have no bytes
	 * left in 'size'
	 */
	LASSERT(i == cdp->cdp_page_count);
	LASSERT(size == 0);

	atomic_add(cdp->cdp_page_count, &anchor->csi_sync_nr);
	/*
	 * Avoid out-of-order execution of adding inflight
	 * modifications count and io submit.
	 */
	smp_mb();
	rc = cl_dio_submit_rw(env, io, iot, cdp);
	if (rc != 0) {
		atomic_add(-cdp->cdp_page_count,
			   &anchor->csi_sync_nr);
		for (i = 0; i < cdp->cdp_page_count; i++) {
			page = cdp->cdp_cl_pages[i];
			page->cp_sync_io = NULL;
		}
	}

out:
	/* cleanup of the page array is handled by cl_sub_dio_end, so there's
	 * no work to do on error here
	 */
	RETURN(rc);
}

#ifdef KMALLOC_MAX_SIZE
#define MAX_MALLOC KMALLOC_MAX_SIZE
#else
#define MAX_MALLOC (128 * 1024)
#endif

/* This is the maximum size of a single O_DIRECT request, based on the
 * kmalloc limit.  We need to fit all of the brw_page structs, each one
 * representing PAGE_SIZE worth of user data, into a single buffer, and
 * then truncate this to be a full-sized RPC.  For 4kB PAGE_SIZE this is
 * up to 22MB for 128kB kmalloc and up to 682MB for 4MB kmalloc. */
#define MAX_DIO_SIZE ((MAX_MALLOC / sizeof(struct brw_page) * PAGE_SIZE) & \
		      ~((size_t)DT_MAX_BRW_SIZE - 1))

static ssize_t
ll_direct_IO_impl(struct kiocb *iocb, struct iov_iter *iter, int rw)
{
	struct ll_cl_context *lcc;
	const struct lu_env *env;
	struct cl_io *io;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct cl_dio_aio *ll_dio_aio;
	struct cl_sub_dio *sdio;
	size_t bytes = iov_iter_count(iter);
	ssize_t tot_bytes = 0, result = 0;
	loff_t file_offset = iocb->ki_pos;
	bool sync_submit = false;
	bool unaligned;
	struct vvp_io *vio;
	ssize_t rc2;

	ENTRY;

	if (file_offset & ~PAGE_MASK)
		unaligned = true;
	else
		unaligned = ll_iov_iter_is_unaligned(iter);

	lcc = ll_cl_find(inode);
	if (lcc == NULL)
		RETURN(-EIO);

	env = lcc->lcc_env;
	LASSERT(!IS_ERR(env));
	vio = vvp_env_io(env);
	io = lcc->lcc_io;
	LASSERT(io != NULL);

	CDEBUG(D_VFSTRACE,
	       "VFS Op:inode="DFID"(%p), size=%zd (max %lu), offset=%lld=%#llx, pages %zd (max %lu)%s%s%s%s\n",
	       PFID(ll_inode2fid(inode)), inode, bytes, MAX_DIO_SIZE,
	       file_offset, file_offset,
	       (bytes >> PAGE_SHIFT) + !!(bytes & ~PAGE_MASK),
	       MAX_DIO_SIZE >> PAGE_SHIFT,
	       io->ci_dio_lock ? ", locked" : ", lockless",
	       io->ci_parallel_dio ? ", parallel" : "",
	       unaligned ? ", unaligned" : "",
	       io->ci_hybrid_switched ? ", hybrid" : "");

	/* Check EOF by ourselves */
	if (rw == READ && file_offset >= i_size_read(inode))
		RETURN(0);

	/* if one part of an I/O is unaligned, just handle all of it that way -
	 * otherwise we create significant complexities with managing the iovec
	 * in different ways, etc, all for very marginal benefits
	 */
	if (unaligned)
		io->ci_unaligned_dio = true;
	if (io->ci_unaligned_dio)
		unaligned = true;

	ll_dio_aio = io->ci_dio_aio;
	LASSERT(ll_dio_aio);
	LASSERT(ll_dio_aio->cda_iocb == iocb);

	/* unaligned DIO support can be turned off, so is it on? */
	if (unaligned && !ll_sbi_has_unaligned_dio(ll_i2sbi(inode)))
		RETURN(-EINVAL);

	/* unaligned AIO is not supported - see LU-18032 */
	if (unaligned && ll_dio_aio->cda_is_aio)
		RETURN(-EINVAL);

	/* the requirement to not return EIOCBQUEUED for pipes (see bottom of
	 * this function) plays havoc with the unaligned I/O lifecycle, so
	 * don't allow unaligned I/O on pipes
	 */
	if (unaligned && iov_iter_is_pipe(iter))
		RETURN(0);

	/* returning 0 here forces the remaining I/O through buffered I/O
	 * while returning -EINVAL stops the I/O from continuing
	 */

	/* Unpatched older servers which cannot safely support unaligned DIO
	 * should abort here
	 */
	if (unaligned && !cl_io_top(io)->ci_allow_unaligned_dio)
		RETURN(0);

	/* We cannot do parallel submission of sub-I/Os - for AIO or regular
	 * DIO - unless lockless because it causes us to release the lock
	 * early.
	 *
	 * There are also several circumstances in which we must disable
	 * parallel DIO, so we check if it is enabled.
	 *
	 * The check for "is_sync_kiocb" excludes AIO, which does not need to
	 * be disabled in these situations.
	 */
	if (io->ci_dio_lock || (is_sync_kiocb(iocb) && !io->ci_parallel_dio))
		sync_submit = true;

	while (iov_iter_count(iter)) {
		struct cl_dio_pages *cdp;

		bytes = min_t(size_t, iov_iter_count(iter), MAX_DIO_SIZE);
		if (rw == READ) {
			if (file_offset >= i_size_read(inode))
				break;

			if (file_offset + bytes > i_size_read(inode))
				bytes = i_size_read(inode) - file_offset;
		}

		/* if we are doing sync_submit, then we free this below,
		 * otherwise it is freed on the final call to cl_sync_io_note
		 * (either in this function or from a ptlrpcd daemon)
		 */
		sdio = cl_sub_dio_alloc(ll_dio_aio, iter, rw == WRITE,
					unaligned, sync_submit);
		if (!sdio)
			GOTO(out, result = -ENOMEM);

		cdp = &sdio->csd_dio_pages;
		cdp->cdp_file_offset = file_offset;
		result = cl_dio_pages_init(env, ll_dio_aio->cda_obj, cdp,
					   iter, rw, bytes, file_offset,
					   unaligned);
		if (unlikely(result <= 0)) {
			cl_sync_io_note(env, &sdio->csd_sync, result);
			if (sync_submit) {
				LASSERT(sdio->csd_creator_free);
				cl_sub_dio_free(sdio);
			}
			GOTO(out, result);
		}
		/* now we have the actual bytes, so store it in the sdio */
		bytes = result;
		sdio->csd_bytes = bytes;

		result = ll_direct_rw_pages(env, io, bytes, rw, inode, sdio);
		/* if the i/o was unsuccessful, we zero the number of bytes to
		 * copy back.  Note that partial I/O completion isn't possible
		 * here - I/O either completes or fails.  So there's no need to
		 * handle short I/O here by changing 'count' with the result
		 * from ll_direct_rw_pages.
		 *
		 * This must be done before we release the reference
		 * immediately below, because releasing the reference allows
		 * i/o completion (and copyback to userspace, if unaligned) to
		 * start.
		 */
		if (result != 0)
			sdio->csd_bytes = 0;
		/* We've submitted pages and can now remove the extra
		 * reference for that
		 */
		cl_sync_io_note(env, &sdio->csd_sync, result);

		if (sync_submit) {
			rc2 = cl_sync_io_wait(env, &sdio->csd_sync,
					     0);
			if (result == 0 && rc2)
				result = rc2;
			LASSERT(sdio->csd_creator_free);
			cl_sub_dio_free(sdio);
		}
		if (unlikely(result < 0))
			GOTO(out, result);

		iov_iter_advance(iter, bytes);

		tot_bytes += bytes;
		file_offset += bytes;
		CDEBUG(D_VFSTRACE,
		       "result %zd tot_bytes %zd count %zd file_offset %lld\n",
		       result, tot_bytes, bytes, file_offset);
	}

out:
	if (rw == WRITE)
		vio->u.readwrite.vui_written += tot_bytes;
	else
		vio->u.readwrite.vui_read += tot_bytes;

	/* AIO is not supported on pipes, so we cannot return EIOCBQEUED like
	 * we normally would for both DIO and AIO here
	 */
	if (result == 0 && !iov_iter_is_pipe(iter))
		result = -EIOCBQUEUED;

	RETURN(result);
}

#ifdef HAVE_DIO_ITER
static ssize_t ll_direct_IO(
#ifndef HAVE_IOV_ITER_RW
	     int rw,
#endif
	     struct kiocb *iocb, struct iov_iter *iter
#ifndef HAVE_DIRECTIO_2ARGS
	     , loff_t file_offset
#endif
	     )
{
	int nrw;

#ifndef HAVE_IOV_ITER_RW
	nrw = rw;
#else
	nrw = iov_iter_rw(iter);
#endif

	return ll_direct_IO_impl(iocb, iter, nrw);
}

#else /* !defined(HAVE_DIO_ITER) */

static ssize_t
ll_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
	     loff_t file_offset, unsigned long nr_segs)
{
	struct iov_iter iter;

	iov_iter_init(&iter, iov, nr_segs, iov_length(iov, nr_segs), 0);
	return ll_direct_IO_impl(iocb, &iter, rw);
}

#endif /* !defined(HAVE_DIO_ITER) */

/**
 * ll_prepare_partial_page() - Prepare partially written-to page for a write.
 * @env: execution environment for this thread
 * @io: pointer to the client I/O structure
 * @pg: owned when passed in and disowned when it returns non-zero result to
 * the caller
 * @file: file structure associated with the page
 *
 * Return:
 * * %0: Success (Ready for read/write)
 * * %-ERRNO: Failure
 */
static int ll_prepare_partial_page(const struct lu_env *env, struct cl_io *io,
				   struct cl_page *pg, struct file *file)
{
	struct cl_attr *attr   = vvp_env_new_attr(env);
	struct cl_object *obj  = io->ci_obj;
	loff_t offset = cl_page_index(pg) << PAGE_SHIFT;
	int result;
	ENTRY;

	cl_object_attr_lock(obj);
	result = cl_object_attr_get(env, obj, attr);
	cl_object_attr_unlock(obj);
	if (result) {
		cl_page_disown(env, io, pg);
		GOTO(out, result);
	}

	/*
	 * If are writing to a new page, no need to read old data.
	 * The extent locking will have updated the KMS, and for our
	 * purposes here we can treat it like i_size.
	 */
	if (attr->cat_kms <= offset) {
		char *kaddr = kmap_atomic(pg->cp_vmpage);

		memset(kaddr, 0, PAGE_SIZE);
		kunmap_atomic(kaddr);
		GOTO(out, result = 0);
	}

	if (pg->cp_defer_uptodate) {
		pg->cp_ra_used = 1;
		GOTO(out, result = 0);
	}

	result = ll_io_read_page(env, io, pg, file);
	if (result)
		GOTO(out, result);

	/* ll_io_read_page() disowns the page */
	result = cl_page_own(env, io, pg);
	if (!result) {
		if (!PageUptodate(cl_page_vmpage(pg))) {
			cl_page_disown(env, io, pg);
			result = -EIO;
		}
	} else if (result == -ENOENT) {
		/* page was truncated */
		result = -EAGAIN;
	}
	EXIT;

out:
	return result;
}

static int ll_tiny_write_begin(struct page *vmpage, struct address_space *mapping)
{
	/* Page must be present, up to date, dirty, and not in writeback. */
	if (!vmpage || !PageUptodate(vmpage) || !PageDirty(vmpage) ||
	    PageWriteback(vmpage) || vmpage->mapping != mapping)
		return -ENODATA;

	return 0;
}

/*
 * write_begin is responsible for allocating page cache pages to be used
 * to hold data for buffered i/o on the 'write' path.
 * Called by generic_perform_write() to allocate one page [or one folio]
 */
static int ll_write_begin(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned int len,
#ifdef HAVE_GRAB_CACHE_PAGE_WRITE_BEGIN_WITH_FLAGS
			  unsigned int flags,
#endif
			  struct wbe_folio **foliop, void **fsdata)
{
	struct ll_cl_context *lcc = NULL;
	const struct lu_env  *env = NULL;
	struct vvp_io *vio;
	struct cl_io   *io = NULL;
	struct cl_page *page = NULL;
	struct inode *inode = file_inode(file);
	struct cl_object *clob = ll_i2info(mapping->host)->lli_clob;
	pgoff_t index = pos >> PAGE_SHIFT;
	struct page *vmpage = NULL;
	unsigned from = pos & (PAGE_SIZE - 1);
	unsigned to = from + len;
	int result = 0;
	int iocb_flags;
	ENTRY;

	CDEBUG(D_VFSTRACE, "Writing %lu of %d to %d bytes\n", index, from, len);

	lcc = ll_cl_find(inode);
	if (lcc == NULL) {
		/* do not allocate a page, only find & lock */
		vmpage = find_lock_page(mapping, index);
		result = ll_tiny_write_begin(vmpage, mapping);
		GOTO(out, result);
	}

	env = lcc->lcc_env;
	io  = lcc->lcc_io;
	vio = vvp_env_io(env);

	iocb_flags = iocb_ki_flags_get(file, vio->vui_iocb);
	if (iocb_ki_flags_check(iocb_flags, DIRECT)) {
		/* direct IO failed because it couldn't clean up cached pages,
		 * this causes a problem for mirror write because the cached
		 * page may belong to another mirror, which will result in
		 * problem submitting the I/O. */
		if (io->ci_designated_mirror > 0)
			GOTO(out, result = -EBUSY);

		/**
		 * Direct write can fall back to buffered read, but DIO is done
		 * with lockless i/o, and buffered requires LDLM locking, so
		 * in this case we must restart without lockless.
		 */
		if (!io->ci_dio_lock) {
			io->ci_dio_lock = 1;
			io->ci_need_restart = 1;
			GOTO(out, result = -ENOLCK);
		}
	}
again:
	/* To avoid deadlock, try to lock page first. */
	vmpage = grab_cache_page_nowait(mapping, index);

	if (unlikely(vmpage == NULL ||
		     PageDirty(vmpage) || PageWriteback(vmpage))) {
		struct vvp_io *vio = vvp_env_io(env);
		struct cl_page_list *plist = &vio->u.readwrite.vui_queue;

                /* if the page is already in dirty cache, we have to commit
		 * the pages right now; otherwise, it may cause deadlock
		 * because it holds page lock of a dirty page and request for
		 * more grants. It's okay for the dirty page to be the first
		 * one in commit page list, though. */
		if (vmpage != NULL && plist->pl_nr > 0) {
			unlock_page(vmpage);
			put_page(vmpage);
			vmpage = NULL;
		}

		/* commit pages and then wait for page lock */
		result = vvp_io_write_commit(env, io);
		if (result < 0)
			GOTO(out, result);

		if (vmpage == NULL) {
			vmpage = grab_cache_page_write_begin(mapping, index
#ifdef HAVE_GRAB_CACHE_PAGE_WRITE_BEGIN_WITH_FLAGS
							     , flags
#endif
							     );
			if (vmpage == NULL)
				GOTO(out, result = -ENOMEM);
		}
	}

	/* page was truncated */
	if (mapping != vmpage->mapping) {
		CDEBUG(D_VFSTRACE, "page: %lu was truncated\n", index);
		unlock_page(vmpage);
		put_page(vmpage);
		vmpage = NULL;
		goto again;
	}

	page = cl_page_find(env, clob, vmpage->index, vmpage, CPT_CACHEABLE);
	if (IS_ERR(page))
		GOTO(out, result = PTR_ERR(page));

	lcc->lcc_page = page;

	cl_page_assume(env, io, page);
	if (!PageUptodate(vmpage)) {
		/*
		 * We're completely overwriting an existing page,
		 * so _don't_ set it up to date until commit_write
		 */
		if (from == 0 && to == PAGE_SIZE) {
			CL_PAGE_HEADER(D_PAGE, env, page, "full page write\n");
			POISON_PAGE(vmpage, 0x11);
		} else {
			/* TODO: can be optimized at OSC layer to check if it
			 * is a lockless IO. In that case, it's not necessary
			 * to read the data. */
			result = ll_prepare_partial_page(env, io, page, file);
			if (result) {
				/* vmpage should have been unlocked */
				put_page(vmpage);
				vmpage = NULL;

				if (result == -EAGAIN)
					goto again;
				GOTO(out, result);
			}
		}
	}
	EXIT;
out:
	if (result < 0) {
		if (vmpage != NULL) {
			unlock_page(vmpage);
			put_page(vmpage);
		}
		/* On tiny_write failure, page and io are always null. */
		if (!IS_ERR_OR_NULL(page)) {
			cl_page_put(env, page);
		}
		if (io)
			io->ci_result = result;
	} else {
		*foliop = wbe_page_folio(vmpage);
		*fsdata = lcc;
	}
	RETURN(result);
}

static int ll_tiny_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned int len, unsigned int copied,
			     struct page *vmpage)
{
	struct cl_page *clpage = (struct cl_page *) vmpage->private;
	loff_t kms = pos+copied;
	loff_t to = kms & (PAGE_SIZE-1) ? kms & (PAGE_SIZE-1) : PAGE_SIZE;
	struct lu_env *env;
	int rc = 0;

	ENTRY;

	/* This page is dirty in cache, so it should have a cl_page pointer
	 * set in vmpage->private.
	 */
	LASSERT(clpage != NULL);

	if (copied == 0)
		goto out;

	/* env_percpu_get cannot fail */
	env = cl_env_percpu_get();

	/* Update the underlying size information in the OSC/LOV objects this
	 * page is part of.
	 */
	cl_page_touch(env, clpage, to);

	cl_env_percpu_put(env);
out:
	/* Must return page unlocked. */
	unlock_page(vmpage);

	RETURN(rc);
}

static int ll_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct wbe_folio *vmfolio, void *fsdata)
{
	struct ll_cl_context *lcc = fsdata;
	const struct lu_env *env;
	struct cl_io *io;
	struct vvp_io *vio;
	struct cl_page *page;
	struct page *vmpage = wbe_folio_page(vmfolio);
	unsigned from = pos & (PAGE_SIZE - 1);
	bool unplug = false;
	int result = 0;
	ENTRY;

	put_page(vmpage);

	CDEBUG(D_VFSTRACE, "pos %llu, len %u, copied %u\n", pos, len, copied);

	if (lcc == NULL) {
		result = ll_tiny_write_end(file, mapping, pos, len, copied,
					   vmpage);
		GOTO(out, result);
	}

	LASSERT(lcc != NULL);
	env  = lcc->lcc_env;
	page = lcc->lcc_page;
	io   = lcc->lcc_io;
	vio  = vvp_env_io(env);

	LASSERT(cl_page_is_owned(page, io));
	if (copied > 0) {
		struct cl_page_list *plist = &vio->u.readwrite.vui_queue;

		lcc->lcc_page = NULL; /* page will be queued */

		/* Add it into write queue */
		cl_page_list_add(plist, page, true);
		if (plist->pl_nr == 1) /* first page */
			vio->u.readwrite.vui_from = from;
		else
			LASSERT(from == 0);
		vio->u.readwrite.vui_to = from + copied;

		/* To address the deadlock in balance_dirty_pages() where
		 * this dirty page may be written back in the same thread. */
		if (PageDirty(vmpage))
			unplug = true;

		/* We may have one full RPC, commit it soon */
		if (plist->pl_nr >= PTLRPC_MAX_BRW_PAGES)
			unplug = true;

		CL_PAGE_DEBUG(D_VFSTRACE, env, page,
			      "queued page: %d.\n", plist->pl_nr);
	} else {
		cl_page_disown(env, io, page);

		lcc->lcc_page = NULL;
		cl_page_put(env, page);

		/* page list is not contiguous now, commit it now */
		unplug = true;
	}
	/* the last call into ->write_begin() can unplug the queue */
	if (io->u.ci_wr.wr_sync && pos + len ==
	    io->u.ci_rw.crw_pos + io->u.ci_rw.crw_bytes)
		unplug = true;
	if (unplug)
		result = vvp_io_write_commit(env, io);

	if (result < 0)
		io->ci_result = result;


out:
	RETURN(result >= 0 ? copied : result);
}

#ifdef CONFIG_MIGRATION
static int ll_migrate_folio(struct address_space *mapping,
			    struct folio_migr *newpage, struct folio_migr *page,
			    enum migrate_mode mode)
{
	/* Always fail page migration until we have a proper implementation */
	return -EIO;
}
#endif

const struct address_space_operations ll_aops = {
#ifdef HAVE_DIRTY_FOLIO
	.dirty_folio		= filemap_dirty_folio,
#else
	.set_page_dirty		= __set_page_dirty_nobuffers,
#endif
#ifdef HAVE_INVALIDATE_FOLIO
	.invalidate_folio	= ll_invalidate_folio,
#else
	.invalidatepage		= ll_invalidatepage,
#endif
#ifdef HAVE_AOPS_READ_FOLIO
	.read_folio		= ll_read_folio,
#else
	.readpage		= ll_readpage,
#endif
#ifdef HAVE_AOPS_RELEASE_FOLIO
	.release_folio		= ll_release_folio,
#else
	.releasepage		= (void *)ll_releasepage,
#endif
	.direct_IO		= ll_direct_IO,
	.writepage		= ll_writepage,
	.writepages		= ll_writepages,
	.write_begin		= ll_write_begin,
	.write_end		= ll_write_end,
#ifdef CONFIG_MIGRATION
	.migrate_folio		= ll_migrate_folio,
#endif
};
