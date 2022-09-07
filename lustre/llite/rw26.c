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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/lustre/llite/rw26.c
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

/**
 * Implements Linux VM address_space::invalidatepage() method. This method is
 * called when the page is truncate from a file, either as a result of
 * explicit truncate, or when inode is removed from memory (as a result of
 * final iput(), umount, or memory pressure induced icache shrinking).
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
}

#ifdef HAVE_RELEASEPAGE_WITH_INT
#define RELEASEPAGE_ARG_TYPE int
#else
#define RELEASEPAGE_ARG_TYPE gfp_t
#endif
static int ll_releasepage(struct page *vmpage, RELEASEPAGE_ARG_TYPE gfp_mask)
{
	struct lu_env		*env;
	struct cl_object	*obj;
	struct cl_page		*clpage;
	struct address_space	*mapping;
	int result = 0;

	LASSERT(PageLocked(vmpage));
	if (PageWriteback(vmpage) || PageDirty(vmpage))
		return 0;

	mapping = vmpage->mapping;
	if (mapping == NULL)
		return 1;

	obj = ll_i2info(mapping->host)->lli_clob;
	if (obj == NULL)
		return 1;

	clpage = cl_vmpage_page(vmpage, obj);
	if (clpage == NULL)
		return 1;

	env = cl_env_percpu_get();
	LASSERT(!IS_ERR(env));

	/* we must not delete the cl_page if the vmpage is in use, otherwise we
	 * disconnect the vmpage from Lustre while it's still alive(!), which
	 * means we won't find it to discard on lock cancellation.
	 *
	 * References here are: caller + cl_page + page cache.
	 * Any other references are potentially transient and must be ignored.
	 */
	if (!cl_page_in_use(clpage) && !vmpage_in_use(vmpage, 1)) {
		result = 1;
		cl_page_delete(env, clpage);
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
	cl_page_put(env, clpage);

	cl_env_percpu_put(env);
	return result;
}

static ssize_t ll_get_user_pages(int rw, struct iov_iter *iter,
				struct page ***pages, ssize_t *npages,
				size_t maxsize)
{
#if defined(HAVE_DIO_ITER)
	size_t start;
	size_t result;

	/*
	 * iov_iter_get_pages_alloc() is introduced in 3.16 similar
	 * to HAVE_DIO_ITER.
	 */
	result = iov_iter_get_pages_alloc(iter, pages, maxsize, &start);
	if (result > 0)
		*npages = DIV_ROUND_UP(result + start, PAGE_SIZE);

	return result;
#else
	unsigned long addr;
	size_t page_count;
	size_t size;
	long result;

	if (!maxsize)
		return 0;

	if (!iter->nr_segs)
		return 0;

	addr = (unsigned long)iter->iov->iov_base + iter->iov_offset;
	if (addr & ~PAGE_MASK)
		return -EINVAL;

	size = min_t(size_t, maxsize, iter->iov->iov_len);
	page_count = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	OBD_ALLOC_PTR_ARRAY_LARGE(*pages, page_count);
	if (*pages == NULL)
		return -ENOMEM;

	mmap_read_lock(current->mm);
	result = get_user_pages(current, current->mm, addr, page_count,
				rw == READ, 0, *pages, NULL);
	mmap_read_unlock(current->mm);

	if (unlikely(result != page_count)) {
		ll_release_user_pages(*pages, page_count);
		*pages = NULL;

		if (result >= 0)
			return -EFAULT;

		return result;
	}
	*npages = page_count;

	return size;
#endif
}

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
static unsigned long ll_iov_iter_alignment(struct iov_iter *i)
{
	size_t orig_size = i->count;
	size_t count = orig_size & ~PAGE_MASK;
	unsigned long res;

	if (!count)
		return iov_iter_alignment_vfs(i);

	if (orig_size > PAGE_SIZE) {
		iov_iter_truncate(i, orig_size - count);
		res = iov_iter_alignment_vfs(i);
		iov_iter_reexpand(i, orig_size);

		return res;
	}

	res = iov_iter_alignment_vfs(i);
	/* start address is page aligned */
	if ((res & ~PAGE_MASK) == orig_size)
		return PAGE_SIZE;

	return res;
}

static int
ll_direct_rw_pages(const struct lu_env *env, struct cl_io *io, size_t size,
		   int rw, struct inode *inode, struct cl_sub_dio *sdio)
{
	struct ll_dio_pages *pv = &sdio->csd_dio_pages;
	struct cl_page    *page;
	struct cl_2queue  *queue = &io->ci_queue;
	struct cl_object  *obj = io->ci_obj;
	struct cl_sync_io *anchor = &sdio->csd_sync;
	loff_t offset   = pv->ldp_file_offset;
	int io_pages    = 0;
	size_t page_size = cl_page_size(obj);
	int i;
	ssize_t rc = 0;

	ENTRY;

	cl_2queue_init(queue);
	for (i = 0; i < pv->ldp_count; i++) {
		LASSERT(!(offset & (PAGE_SIZE - 1)));
		page = cl_page_find(env, obj, cl_index(obj, offset),
				    pv->ldp_pages[i], CPT_TRANSIENT);
		if (IS_ERR(page)) {
			rc = PTR_ERR(page);
			break;
		}
		LASSERT(page->cp_type == CPT_TRANSIENT);
		rc = cl_page_own(env, io, page);
		if (rc) {
			cl_page_put(env, page);
			break;
		}

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
		/* We keep the refcount from cl_page_find, so we don't need
		 * another one here
		 */
		cl_2queue_add(queue, page, false);
		/*
		 * Set page clip to tell transfer formation engine
		 * that page has to be sent even if it is beyond KMS.
		 */
		if (size < page_size)
			cl_page_clip(env, page, 0, size);
		++io_pages;

		offset += page_size;
		size -= page_size;
	}
	if (rc == 0 && io_pages > 0) {
		int iot = rw == READ ? CRT_READ : CRT_WRITE;

		atomic_add(io_pages, &anchor->csi_sync_nr);
		/*
		 * Avoid out-of-order execution of adding inflight
		 * modifications count and io submit.
		 */
		smp_mb();
		rc = cl_io_submit_rw(env, io, iot, queue);
		if (rc == 0) {
			cl_page_list_splice(&queue->c2_qout, &sdio->csd_pages);
		} else {
			atomic_add(-queue->c2_qin.pl_nr,
				   &anchor->csi_sync_nr);
			cl_page_list_for_each(page, &queue->c2_qin)
				page->cp_sync_io = NULL;
		}
		/* handle partially submitted reqs */
		if (queue->c2_qin.pl_nr > 0) {
			CERROR(DFID " failed to submit %d dio pages: %zd\n",
			       PFID(lu_object_fid(&obj->co_lu)),
			       queue->c2_qin.pl_nr, rc);
			if (rc == 0)
				rc = -EIO;
		}
	}

	cl_2queue_discard(env, io, queue);
	cl_2queue_disown(env, io, queue);
	cl_2queue_fini(env, queue);
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
	struct cl_sub_dio *ldp_aio;
	size_t count = iov_iter_count(iter);
	ssize_t tot_bytes = 0, result = 0;
	loff_t file_offset = iocb->ki_pos;
	bool sync_submit = false;
	struct vvp_io *vio;
	ssize_t rc2;

	/* Check EOF by ourselves */
	if (rw == READ && file_offset >= i_size_read(inode))
		return 0;

	/* FIXME: io smaller than PAGE_SIZE is broken on ia64 ??? */
	if (file_offset & ~PAGE_MASK)
		RETURN(-EINVAL);

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), size=%zd (max %lu), "
	       "offset=%lld=%llx, pages %zd (max %lu)\n",
	       PFID(ll_inode2fid(inode)), inode, count, MAX_DIO_SIZE,
	       file_offset, file_offset, count >> PAGE_SHIFT,
	       MAX_DIO_SIZE >> PAGE_SHIFT);

	/* Check that all user buffers are aligned as well */
	if (ll_iov_iter_alignment(iter) & ~PAGE_MASK)
		RETURN(-EINVAL);

	lcc = ll_cl_find(inode);
	if (lcc == NULL)
		RETURN(-EIO);

	env = lcc->lcc_env;
	LASSERT(!IS_ERR(env));
	vio = vvp_env_io(env);
	io = lcc->lcc_io;
	LASSERT(io != NULL);

	ll_dio_aio = io->ci_dio_aio;
	LASSERT(ll_dio_aio);
	LASSERT(ll_dio_aio->cda_iocb == iocb);

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
		struct ll_dio_pages *pvec;
		struct page **pages;

		count = min_t(size_t, iov_iter_count(iter), MAX_DIO_SIZE);
		if (rw == READ) {
			if (file_offset >= i_size_read(inode))
				break;

			if (file_offset + count > i_size_read(inode))
				count = i_size_read(inode) - file_offset;
		}

		/* if we are doing sync_submit, then we free this below,
		 * otherwise it is freed on the final call to cl_sync_io_note
		 * (either in this function or from a ptlrpcd daemon)
		 */
		ldp_aio = cl_sub_dio_alloc(ll_dio_aio, sync_submit);
		if (!ldp_aio)
			GOTO(out, result = -ENOMEM);

		pvec = &ldp_aio->csd_dio_pages;

		result = ll_get_user_pages(rw, iter, &pages,
					   &pvec->ldp_count, count);
		if (unlikely(result <= 0)) {
			cl_sync_io_note(env, &ldp_aio->csd_sync, result);
			if (sync_submit)
				cl_sub_dio_free(ldp_aio, true);
			GOTO(out, result);
		}

		count = result;
		pvec->ldp_file_offset = file_offset;
		pvec->ldp_pages = pages;

		result = ll_direct_rw_pages(env, io, count,
					    rw, inode, ldp_aio);
		/* We've submitted pages and can now remove the extra
		 * reference for that
		 */
		cl_sync_io_note(env, &ldp_aio->csd_sync, result);

		if (sync_submit) {
			rc2 = cl_sync_io_wait(env, &ldp_aio->csd_sync,
					     0);
			if (result == 0 && rc2)
				result = rc2;
			cl_sub_dio_free(ldp_aio, true);
		}
		if (unlikely(result < 0))
			GOTO(out, result);

		iov_iter_advance(iter, count);
		tot_bytes += count;
		file_offset += count;
	}

out:
	ll_dio_aio->cda_bytes += tot_bytes;

	if (rw == WRITE)
		vio->u.readwrite.vui_written += tot_bytes;
	else
		vio->u.readwrite.vui_read += tot_bytes;

	/* AIO is not supported on pipes, so we cannot return EIOCBQEUED like
	 * we normally would for both DIO and AIO here
	 */
	if (result == 0 && !iov_iter_is_pipe(iter))
		result = -EIOCBQUEUED;

	return result;
}

#if defined(HAVE_DIO_ITER)
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
 * Prepare partially written-to page for a write.
 * @pg is owned when passed in and disowned when it returns non-zero result to
 * the caller.
 */
static int ll_prepare_partial_page(const struct lu_env *env, struct cl_io *io,
				   struct cl_page *pg, struct file *file)
{
	struct cl_attr *attr   = vvp_env_thread_attr(env);
	struct cl_object *obj  = io->ci_obj;
	struct vvp_page *vpg   = cl_object_page_slice(obj, pg);
	loff_t          offset = cl_offset(obj, vvp_index(vpg));
	int             result;
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
		char *kaddr = kmap_atomic(vpg->vpg_page);

		memset(kaddr, 0, cl_page_size(obj));
		kunmap_atomic(kaddr);
		GOTO(out, result = 0);
	}

	if (vpg->vpg_defer_uptodate) {
		vpg->vpg_ra_used = 1;
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

static int ll_write_begin(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned flags,
			  struct page **pagep, void **fsdata)
{
	struct ll_cl_context *lcc = NULL;
	const struct lu_env  *env = NULL;
	struct cl_io   *io = NULL;
	struct cl_page *page = NULL;
	struct inode *inode = file_inode(file);
	struct cl_object *clob = ll_i2info(mapping->host)->lli_clob;
	pgoff_t index = pos >> PAGE_SHIFT;
	struct page *vmpage = NULL;
	unsigned from = pos & (PAGE_SIZE - 1);
	unsigned to = from + len;
	int result = 0;
	ENTRY;

	CDEBUG(D_VFSTRACE, "Writing %lu of %d to %d bytes\n", index, from, len);

	lcc = ll_cl_find(inode);
	if (lcc == NULL) {
		vmpage = grab_cache_page_nowait(mapping, index);
		result = ll_tiny_write_begin(vmpage, mapping);
		GOTO(out, result);
	}

	env = lcc->lcc_env;
	io  = lcc->lcc_io;

	if (file->f_flags & O_DIRECT) {
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
			vmpage = grab_cache_page_write_begin(mapping, index,
							     flags);
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
	lu_ref_add(&page->cp_reference, "cl_io", io);

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
			lu_ref_del(&page->cp_reference, "cl_io", io);
			cl_page_put(env, page);
		}
		if (io)
			io->ci_result = result;
	} else {
		*pagep = vmpage;
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
	__u16 refcheck;
	struct lu_env *env = cl_env_get(&refcheck);
	int rc = 0;

	ENTRY;

	if (IS_ERR(env)) {
		rc = PTR_ERR(env);
		goto out;
	}

	/* This page is dirty in cache, so it should have a cl_page pointer
	 * set in vmpage->private.
	 */
	LASSERT(clpage != NULL);

	if (copied == 0)
		goto out_env;

	/* Update the underlying size information in the OSC/LOV objects this
	 * page is part of.
	 */
	cl_page_touch(env, clpage, to);

out_env:
	cl_env_put(env, &refcheck);

out:
	/* Must return page unlocked. */
	unlock_page(vmpage);

	RETURN(rc);
}

static int ll_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *vmpage, void *fsdata)
{
	struct ll_cl_context *lcc = fsdata;
	const struct lu_env *env;
	struct cl_io *io;
	struct vvp_io *vio;
	struct cl_page *page;
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
		lu_ref_del(&page->cp_reference, "cl_io", io);
		cl_page_put(env, page);

		/* page list is not contiguous now, commit it now */
		unplug = true;
	}
	if (unplug || io->u.ci_wr.wr_sync)
		result = vvp_io_write_commit(env, io);

	if (result < 0)
		io->ci_result = result;


out:
	RETURN(result >= 0 ? copied : result);
}

#ifdef CONFIG_MIGRATION
static int ll_migratepage(struct address_space *mapping,
			  struct page *newpage, struct page *page,
			  enum migrate_mode mode)
{
        /* Always fail page migration until we have a proper implementation */
        return -EIO;
}
#endif

const struct address_space_operations ll_aops = {
	.readpage	= ll_readpage,
	.direct_IO	= ll_direct_IO,
	.writepage	= ll_writepage,
	.writepages	= ll_writepages,
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.write_begin	= ll_write_begin,
	.write_end	= ll_write_end,
	.invalidatepage	= ll_invalidatepage,
	.releasepage	= (void *)ll_releasepage,
#ifdef CONFIG_MIGRATION
	.migratepage	= ll_migratepage,
#endif
};
