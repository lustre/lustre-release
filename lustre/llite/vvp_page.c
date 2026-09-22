// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_page for VVP layer.
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 * Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>

#include "llite_internal.h"
#include "vvp_internal.h"

/* Page operations */

static void vvp_page_discard(const struct lu_env *env,
			     const struct cl_page_slice *slice,
			     struct cl_io *unused)
{
	struct cl_page *cp = slice->cpl_page;
	struct folio *folio = cp->cp_folio;

	if (cp->cp_defer_uptodate && !cp->cp_ra_used && folio->mapping != NULL)
		ll_ra_stats_inc(folio->mapping->host, RA_STAT_DISCARDED);
}

static void vvp_page_delete(const struct lu_env *env,
			    const struct cl_page_slice *slice)
{
	struct cl_page *cp = slice->cpl_page;

	if (cp->cp_type == CPT_CACHEABLE) {
		struct folio *folio = cp->cp_folio;
		struct inode *inode = folio->mapping->host;

		LASSERT(folio_get_private(folio) == cp);

		CDEBUG(D_CACHE, "delete page %p index %ld\n",
		       folio, folio->index);
		/* Drop the reference count held in vvp_page_init */
		refcount_dec(&cp->cp_ref);

		/* cl_page was attached to folio in vvp_page_init, detach it */
		folio_clear_private(folio);
		folio_change_private(folio, NULL);

		/* clearpageuptodate prevents the page being read by the
		 * kernel after it has been deleted from Lustre, which avoids
		 * potential stale data reads.  The seqlock allows us to see
		 * that a page was potentially deleted and catch the resulting
		 * SIGBUS - see ll_filemap_fault() (LU-16160)
		 */
		if (folio_test_uptodate(folio)) {
			write_seqlock(&ll_i2info(inode)->lli_page_inv_lock);
			folio_clear_uptodate(folio);
			write_sequnlock(&ll_i2info(inode)->lli_page_inv_lock);
		}
		/* The reference from vmpage to cl_page is removed,
		 * but the reference back is still here. It is removed
		 * later in cl_page_free().
		 */
	}
}

/**
 * vvp_vmpage_error() - Handles page transfer errors at VM level.
 *
 * @inode: inode linked with vmpage(struct page)
 * @folio: struct folio that has error
 * @ioret: type of error
 *
 * This takes inode as a separate argument, because inode on which error is to
 * be set can be different from \a vmpage inode in case of direct-io.
 */
static void vvp_vmpage_error(struct inode *inode, struct folio *folio,
			     int ioret)
{
	struct vvp_object *obj = cl_inode2vvp(inode);

	if (ioret == 0) {
		ClearPageError(folio_page(folio, 0));
		obj->vob_discard_page_warned = 0;
	} else {
		SetPageError(folio_page(folio, 0));
		if (CFS_FAIL_CHECK(OBD_FAIL_LLITE_PANIC_ON_ESTALE))
			LASSERTF(ioret == -ENOSPC,
				 "%s:"DFID" got a stale page %p: rc = %d.\n",
				 obj->vob_cl.co_lu.lo_dev->ld_obd->obd_name,
				 PFID(lu_object_fid(&obj->vob_cl.co_lu)),
				 folio, ioret);

		mapping_set_error(inode->i_mapping, ioret);

		if ((ioret == -ESHUTDOWN || ioret == -EINTR ||
		     ioret == -EIO) && obj->vob_discard_page_warned == 0) {
			obj->vob_discard_page_warned = 1;
			ll_dirty_page_discard_warn(inode, ioret);
		}
	}
}

static void vvp_page_complete_read(const struct lu_env *env,
				   const struct cl_page_slice *slice,
				   int ioret)
{
	struct cl_page *cp = slice->cpl_page;
	struct folio *folio = cp->cp_folio;
	struct inode *inode = vvp_object_inode(cp->cp_obj);

	ENTRY;
	LASSERT(folio_test_locked(folio));
	CL_PAGE_HEADER(D_PAGE, env, cp, "completing READ with %d\n", ioret);

	if (cp->cp_defer_uptodate)
		ll_ra_count_put(ll_i2sbi(inode), 1);

	if (ioret == 0)  {
		/**
		 * cp_defer_uptodate is used for readahead page, and the
		 * folio Uptodate bit is deferred to set in ll_readpage/
		 * ll_io_read_page.
		 */
		if (!cp->cp_defer_uptodate)
			folio_mark_uptodate(folio);
	} else if (cp->cp_defer_uptodate) {
		cp->cp_defer_uptodate = 0;
		if (ioret == -EAGAIN) {
			/* mirror read failed, it needs to destroy the page
			 * because subpage would be from wrong osc when trying
			 * to read from a new mirror
			 */
			generic_error_remove_folio(folio->mapping, folio);
		}
	}

	if (cp->cp_sync_io == NULL)
		folio_unlock(folio);

	EXIT;
}

static void vvp_page_complete_write(const struct lu_env *env,
				    const struct cl_page_slice *slice,
				    int ioret)
{
	struct cl_page *cp = slice->cpl_page;
	struct folio *folio = cp->cp_folio;

	ENTRY;
	CL_PAGE_HEADER(D_PAGE, env, cp, "completing WRITE with %d\n", ioret);

	if (cp->cp_sync_io != NULL) {
		LASSERT(folio_test_locked(folio));
		LASSERT(!folio_test_writeback(folio));
	} else {
		LASSERT(folio_test_writeback(folio));
		/*
		 * Only mark the page error only when it's an async write
		 * because applications won't wait for IO to finish.
		 */
		vvp_vmpage_error(vvp_object_inode(cp->cp_obj), folio, ioret);

		folio_end_writeback(folio);
	}
	EXIT;
}

static const struct cl_page_operations vvp_page_ops = {
	.cpo_delete	   = vvp_page_delete,
	.cpo_discard       = vvp_page_discard,
	.io = {
		[CRT_READ] = {
			.cpo_complete = vvp_page_complete_read,
		},
		[CRT_WRITE] = {
			.cpo_complete = vvp_page_complete_write,
		},
	},
};

static const struct cl_page_operations vvp_transient_page_ops = {
};

int vvp_page_init(const struct lu_env *env, struct cl_object *obj,
		struct cl_page *cl_page, pgoff_t index)
{
	struct cl_page_slice *cpl = cl_object_page_slice(obj, cl_page);

	CLOBINVRNT(env, obj, vvp_object_invariant(obj));

	if (cl_page->cp_type == CPT_TRANSIENT) {
		/* DIO pages are referenced by userspace, we don't need to take
		 * a reference on them. (contrast with folio_attach_private()
		 * call in the CPT_CACHEABLE branch)
		 */
		cl_page_slice_add(cl_page, cpl, obj,
				  &vvp_transient_page_ops);
	} else {
		folio_attach_private(cl_page->cp_folio, cl_page);
		/* in cache, decref in cl_page_delete() */
		refcount_inc(&cl_page->cp_ref);
		cl_page_slice_add(cl_page, cpl, obj, &vvp_page_ops);
	}

	return 0;
}
