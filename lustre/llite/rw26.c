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
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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

#ifdef HAVE_MIGRATE_H
#include <linux/migrate.h>
#elif defined(HAVE_MIGRATE_MODE_H)
#include <linux/migrate_mode.h>
#endif

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
	struct cl_page		*page;
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

	/* 1 for caller, 1 for cl_page and 1 for page cache */
	if (page_count(vmpage) > 3)
		return 0;

	page = cl_vmpage_page(vmpage, obj);
	if (page == NULL)
		return 1;

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
	return result;
}

#define MAX_DIRECTIO_SIZE 2*1024*1024*1024UL

static ssize_t
ll_direct_IO_seg(const struct lu_env *env, struct cl_io *io, int rw,
		 struct inode *inode, size_t size, loff_t file_offset,
		 struct page **pages, int page_count)
{
	struct cl_page *clp;
	struct cl_2queue *queue;
	struct cl_object *obj = io->ci_obj;
	int i;
	ssize_t rc = 0;
	size_t page_size = cl_page_size(obj);
	size_t orig_size = size;
	bool do_io;
	int io_pages = 0;

	ENTRY;
	queue = &io->ci_queue;
	cl_2queue_init(queue);
	for (i = 0; i < page_count; i++) {
		LASSERT(!(file_offset & (page_size - 1)));
		clp = cl_page_find(env, obj, cl_index(obj, file_offset),
				   pages[i], CPT_TRANSIENT);
		if (IS_ERR(clp)) {
			rc = PTR_ERR(clp);
			break;
		}

		rc = cl_page_own(env, io, clp);
		if (rc) {
			LASSERT(clp->cp_state == CPS_FREEING);
			cl_page_put(env, clp);
			break;
		}

		do_io = true;

		/* check the page type: if the page is a host page, then do
		 * write directly
		 */
		if (clp->cp_type == CPT_CACHEABLE) {
			struct page *vmpage = cl_page_vmpage(clp);
			struct page *src_page;
			struct page *dst_page;
			void *src;
			void *dst;

			src_page = (rw == WRITE) ? pages[i] : vmpage;
			dst_page = (rw == WRITE) ? vmpage : pages[i];

			src = ll_kmap_atomic(src_page, KM_USER0);
			dst = ll_kmap_atomic(dst_page, KM_USER1);
			memcpy(dst, src, min(page_size, size));
			ll_kunmap_atomic(dst, KM_USER1);
			ll_kunmap_atomic(src, KM_USER0);

			/* make sure page will be added to the transfer by
			 * cl_io_submit()->...->vvp_page_prep_write().
			 */
			if (rw == WRITE)
				set_page_dirty(vmpage);

			if (rw == READ) {
				/* do not issue the page for read, since it
				 * may reread a ra page which has NOT uptodate
				 * bit set.
				 */
				cl_page_disown(env, io, clp);
				do_io = false;
			}
		}

		if (likely(do_io)) {
			cl_2queue_add(queue, clp);

			/*
			 * Set page clip to tell transfer formation engine
			 * that page has to be sent even if it is beyond KMS.
			 */
			cl_page_clip(env, clp, 0, min(size, page_size));

			++io_pages;
		}

		/* drop the reference count for cl_page_find */
		cl_page_put(env, clp);
		size -= page_size;
		file_offset += page_size;
	}

	if (rc == 0 && io_pages) {
		rc = cl_io_submit_sync(env, io,
				       rw == READ ? CRT_READ : CRT_WRITE,
				       queue, 0);
	}
	if (rc == 0)
		rc = orig_size;

	cl_2queue_discard(env, io, queue);
	cl_2queue_disown(env, io, queue);
	cl_2queue_fini(env, queue);
	RETURN(rc);
}

/*  ll_free_user_pages - tear down page struct array
 *  @pages: array of page struct pointers underlying target buffer */
static void ll_free_user_pages(struct page **pages, int npages, int do_dirty)
{
	int i;

	for (i = 0; i < npages; i++) {
		if (pages[i] == NULL)
			break;
		if (do_dirty)
			set_page_dirty_lock(pages[i]);
		put_page(pages[i]);
	}

#if defined(HAVE_DIRECTIO_ITER) || defined(HAVE_IOV_ITER_RW)
	kvfree(pages);
#else
	OBD_FREE_LARGE(pages, npages * sizeof(*pages));
#endif
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
		      ~(DT_MAX_BRW_SIZE - 1))

#ifndef HAVE_IOV_ITER_RW
# define iov_iter_rw(iter)	rw
#endif

#if defined(HAVE_DIRECTIO_ITER) || defined(HAVE_IOV_ITER_RW)
static ssize_t
ll_direct_IO(
# ifndef HAVE_IOV_ITER_RW
	     int rw,
# endif
	     struct kiocb *iocb, struct iov_iter *iter
# ifndef HAVE_DIRECTIO_2ARGS
	     , loff_t file_offset
# endif
	     )
{
#ifdef HAVE_DIRECTIO_2ARGS
	loff_t file_offset = iocb->ki_pos;
#endif
	struct ll_cl_context *lcc;
	const struct lu_env *env;
	struct cl_io *io;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t count = iov_iter_count(iter);
	ssize_t tot_bytes = 0, result = 0;
	size_t size = MAX_DIO_SIZE;

	/* Check EOF by ourselves */
	if (iov_iter_rw(iter) == READ && file_offset >= i_size_read(inode))
		return 0;
	/* FIXME: io smaller than PAGE_SIZE is broken on ia64 ??? */
	if ((file_offset & ~PAGE_MASK) || (count & ~PAGE_MASK))
		return -EINVAL;

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), size=%zd (max %lu), "
	       "offset=%lld=%llx, pages %zd (max %lu)\n",
	       PFID(ll_inode2fid(inode)), inode, count, MAX_DIO_SIZE,
	       file_offset, file_offset, count >> PAGE_SHIFT,
	       MAX_DIO_SIZE >> PAGE_SHIFT);

	/* Check that all user buffers are aligned as well */
	if (iov_iter_alignment(iter) & ~PAGE_MASK)
		return -EINVAL;

	lcc = ll_cl_find(file);
	if (lcc == NULL)
		RETURN(-EIO);

	env = lcc->lcc_env;
	LASSERT(!IS_ERR(env));
	io = lcc->lcc_io;
	LASSERT(io != NULL);

	/* 0. Need locking between buffered and direct access. and race with
	 *    size changing by concurrent truncates and writes.
	 * 1. Need inode mutex to operate transient pages.
	 */
	if (iov_iter_rw(iter) == READ)
		inode_lock(inode);

	while (iov_iter_count(iter)) {
		struct page **pages;
		size_t offs;

		count = min_t(size_t, iov_iter_count(iter), size);
		if (iov_iter_rw(iter) == READ) {
			if (file_offset >= i_size_read(inode))
				break;

			if (file_offset + count > i_size_read(inode))
				count = i_size_read(inode) - file_offset;
		}

		result = iov_iter_get_pages_alloc(iter, &pages, count, &offs);
		if (likely(result > 0)) {
			int n = DIV_ROUND_UP(result + offs, PAGE_SIZE);

			result = ll_direct_IO_seg(env, io, iov_iter_rw(iter),
						  inode, result, file_offset,
						  pages, n);
			ll_free_user_pages(pages, n,
					   iov_iter_rw(iter) == READ);

		}
		if (unlikely(result <= 0)) {
			/* If we can't allocate a large enough buffer
			 * for the request, shrink it to a smaller
			 * PAGE_SIZE multiple and try again.
			 * We should always be able to kmalloc for a
			 * page worth of page pointers = 4MB on i386. */
			if (result == -ENOMEM &&
			    size > (PAGE_SIZE / sizeof(*pages)) *
				    PAGE_SIZE) {
				size = ((((size / 2) - 1) |
					~PAGE_MASK) + 1) & PAGE_MASK;
				CDEBUG(D_VFSTRACE, "DIO size now %zu\n",
				       size);
				continue;
			}

			GOTO(out, result);
		}

		iov_iter_advance(iter, result);
		tot_bytes += result;
		file_offset += result;
	}
out:
	if (iov_iter_rw(iter) == READ)
		inode_unlock(inode);

	if (tot_bytes > 0) {
		struct vvp_io *vio = vvp_env_io(env);

		/* no commit async for direct IO */
		vio->u.write.vui_written += tot_bytes;
	}

	return tot_bytes ? : result;
}
#else /* !HAVE_DIRECTIO_ITER && !HAVE_IOV_ITER_RW */

static inline int ll_get_user_pages(int rw, unsigned long user_addr,
				    size_t size, struct page ***pages,
				    int *max_pages)
{
	int result = -ENOMEM;

	/* set an arbitrary limit to prevent arithmetic overflow */
	if (size > MAX_DIRECTIO_SIZE) {
		*pages = NULL;
		return -EFBIG;
	}

	*max_pages = (user_addr + size + PAGE_SIZE - 1) >>
		      PAGE_SHIFT;
	*max_pages -= user_addr >> PAGE_SHIFT;

	OBD_ALLOC_LARGE(*pages, *max_pages * sizeof(**pages));
	if (*pages) {
		down_read(&current->mm->mmap_sem);
		result = get_user_pages(current, current->mm, user_addr,
					*max_pages, (rw == READ), 0, *pages,
					NULL);
		up_read(&current->mm->mmap_sem);
		if (unlikely(result <= 0))
			OBD_FREE_LARGE(*pages, *max_pages * sizeof(**pages));
	}

	return result;
}

static ssize_t
ll_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
	     loff_t file_offset, unsigned long nr_segs)
{
	struct ll_cl_context *lcc;
	const struct lu_env *env;
	struct cl_io *io;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t count = iov_length(iov, nr_segs);
	ssize_t tot_bytes = 0, result = 0;
	unsigned long seg = 0;
	size_t size = MAX_DIO_SIZE;
	ENTRY;

        /* FIXME: io smaller than PAGE_SIZE is broken on ia64 ??? */
	if ((file_offset & ~PAGE_MASK) || (count & ~PAGE_MASK))
                RETURN(-EINVAL);

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), size=%zd (max %lu), "
	       "offset=%lld=%llx, pages %zd (max %lu)\n",
	       PFID(ll_inode2fid(inode)), inode, count, MAX_DIO_SIZE,
	       file_offset, file_offset, count >> PAGE_SHIFT,
	       MAX_DIO_SIZE >> PAGE_SHIFT);

        /* Check that all user buffers are aligned as well */
        for (seg = 0; seg < nr_segs; seg++) {
		if (((unsigned long)iov[seg].iov_base & ~PAGE_MASK) ||
		    (iov[seg].iov_len & ~PAGE_MASK))
                        RETURN(-EINVAL);
        }

	lcc = ll_cl_find(file);
	if (lcc == NULL)
		RETURN(-EIO);

	env = lcc->lcc_env;
	LASSERT(!IS_ERR(env));
	io = lcc->lcc_io;
	LASSERT(io != NULL);

        for (seg = 0; seg < nr_segs; seg++) {
		size_t iov_left = iov[seg].iov_len;
                unsigned long user_addr = (unsigned long)iov[seg].iov_base;

                if (rw == READ) {
                        if (file_offset >= i_size_read(inode))
                                break;
                        if (file_offset + iov_left > i_size_read(inode))
                                iov_left = i_size_read(inode) - file_offset;
                }

                while (iov_left > 0) {
                        struct page **pages;
                        int page_count, max_pages = 0;
			size_t bytes;

                        bytes = min(size, iov_left);
                        page_count = ll_get_user_pages(rw, user_addr, bytes,
                                                       &pages, &max_pages);
                        if (likely(page_count > 0)) {
                                if (unlikely(page_count <  max_pages))
					bytes = page_count << PAGE_SHIFT;
				result = ll_direct_IO_seg(env, io, rw, inode,
							  bytes, file_offset,
							  pages, page_count);
                                ll_free_user_pages(pages, max_pages, rw==READ);
                        } else if (page_count == 0) {
                                GOTO(out, result = -EFAULT);
                        } else {
                                result = page_count;
                        }
                        if (unlikely(result <= 0)) {
                                /* If we can't allocate a large enough buffer
                                 * for the request, shrink it to a smaller
                                 * PAGE_SIZE multiple and try again.
                                 * We should always be able to kmalloc for a
                                 * page worth of page pointers = 4MB on i386. */
                                if (result == -ENOMEM &&
				    size > (PAGE_SIZE / sizeof(*pages)) *
					   PAGE_SIZE) {
                                        size = ((((size / 2) - 1) |
						 ~PAGE_MASK) + 1) &
						PAGE_MASK;
					CDEBUG(D_VFSTRACE, "DIO size now %zu\n",
                                               size);
                                        continue;
                                }

                                GOTO(out, result);
                        }

                        tot_bytes += result;
                        file_offset += result;
                        iov_left -= result;
                        user_addr += result;
                }
        }
out:
        if (tot_bytes > 0) {
		struct vvp_io *vio = vvp_env_io(env);

		/* no commit async for direct IO */
		vio->u.write.vui_written += tot_bytes;
	}

	RETURN(tot_bytes ? tot_bytes : result);
}
#endif /* HAVE_DIRECTIO_ITER || HAVE_IOV_ITER_RW */

/**
 * Prepare partially written-to page for a write.
 */
static int ll_prepare_partial_page(const struct lu_env *env, struct cl_io *io,
				   struct cl_page *pg)
{
	struct cl_attr *attr   = vvp_env_thread_attr(env);
	struct cl_object *obj  = io->ci_obj;
	struct vvp_page *vpg   = cl_object_page_slice(obj, pg);
	loff_t          offset = cl_offset(obj, vvp_index(vpg));
	int             result;

	cl_object_attr_lock(obj);
	result = cl_object_attr_get(env, obj, attr);
	cl_object_attr_unlock(obj);
	if (result == 0) {
		/*
		 * If are writing to a new page, no need to read old data.
		 * The extent locking will have updated the KMS, and for our
		 * purposes here we can treat it like i_size.
		 */
		if (attr->cat_kms <= offset) {
			char *kaddr = ll_kmap_atomic(vpg->vpg_page, KM_USER0);

			memset(kaddr, 0, cl_page_size(obj));
			ll_kunmap_atomic(kaddr, KM_USER0);
		} else if (vpg->vpg_defer_uptodate)
			vpg->vpg_ra_used = 1;
		else
			result = ll_page_sync_io(env, io, pg, CRT_READ);
	}
	return result;
}

static int ll_write_begin(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned flags,
			  struct page **pagep, void **fsdata)
{
	struct ll_cl_context *lcc;
	const struct lu_env  *env = NULL;
	struct cl_io   *io;
	struct cl_page *page = NULL;

	struct cl_object *clob = ll_i2info(mapping->host)->lli_clob;
	pgoff_t index = pos >> PAGE_SHIFT;
	struct page *vmpage = NULL;
	unsigned from = pos & (PAGE_SIZE - 1);
	unsigned to = from + len;
	int result = 0;
	ENTRY;

	CDEBUG(D_PAGE, "Writing %lu of %d to %d bytes\n", index, from, len);

	lcc = ll_cl_find(file);
	if (lcc == NULL) {
		io = NULL;
		GOTO(out, result = -EIO);
	}

	env = lcc->lcc_env;
	io  = lcc->lcc_io;

	/* To avoid deadlock, try to lock page first. */
	vmpage = grab_cache_page_nowait(mapping, index);

	if (unlikely(vmpage == NULL ||
		     PageDirty(vmpage) || PageWriteback(vmpage))) {
		struct vvp_io *vio = vvp_env_io(env);
		struct cl_page_list *plist = &vio->u.write.vui_queue;

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
			result = ll_prepare_partial_page(env, io, page);
			if (result == 0)
				SetPageUptodate(vmpage);
		}
	}
	if (result < 0)
		cl_page_unassume(env, io, page);
	EXIT;
out:
	if (result < 0) {
		if (vmpage != NULL) {
			unlock_page(vmpage);
			put_page(vmpage);
		}
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

	LASSERT(lcc != NULL);
	env  = lcc->lcc_env;
	page = lcc->lcc_page;
	io   = lcc->lcc_io;
	vio  = vvp_env_io(env);

	LASSERT(cl_page_is_owned(page, io));
	if (copied > 0) {
		struct cl_page_list *plist = &vio->u.write.vui_queue;

		lcc->lcc_page = NULL; /* page will be queued */

		/* Add it into write queue */
		cl_page_list_add(plist, page);
		if (plist->pl_nr == 1) /* first page */
			vio->u.write.vui_from = from;
		else
			LASSERT(from == 0);
		vio->u.write.vui_to = from + copied;

		/* To address the deadlock in balance_dirty_pages() where
		 * this dirty page may be written back in the same thread. */
		if (PageDirty(vmpage))
			unplug = true;

		/* We may have one full RPC, commit it soon */
		if (plist->pl_nr >= PTLRPC_MAX_BRW_PAGES)
			unplug = true;

		CL_PAGE_DEBUG(D_PAGE, env, page,
			      "queued page: %d.\n", plist->pl_nr);
	} else {
		cl_page_disown(env, io, page);

		lcc->lcc_page = NULL;
		lu_ref_del(&page->cp_reference, "cl_io", io);
		cl_page_put(env, page);

		/* page list is not contiguous now, commit it now */
		unplug = true;
	}
	if (unplug || io->u.ci_rw.rw_sync)
		result = vvp_io_write_commit(env, io);

	if (result < 0)
		io->ci_result = result;
	RETURN(result >= 0 ? copied : result);
}

#ifdef CONFIG_MIGRATION
static int ll_migratepage(struct address_space *mapping,
			  struct page *newpage, struct page *page
#ifdef HAVE_MIGRATEPAGE_4ARGS
			  , enum migrate_mode mode
#endif
	)
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
