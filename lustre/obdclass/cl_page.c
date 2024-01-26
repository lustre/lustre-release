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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Client Lustre Page.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/list.h>
#include <libcfs/libcfs.h>
#include <obd_class.h>
#include <obd_support.h>

#include <cl_object.h>
#include "cl_internal.h"

static void __cl_page_delete(const struct lu_env *env, struct cl_page *pg);
static DEFINE_MUTEX(cl_page_kmem_mutex);

#ifdef LIBCFS_DEBUG
# define PASSERT(env, page, expr)                                       \
do {                                                                    \
	if (unlikely(!(expr))) {                                        \
		CL_PAGE_DEBUG(D_ERROR, (env), (page), #expr "\n");      \
		LASSERT(0);                                             \
	}                                                               \
} while (0)
#else /* !LIBCFS_DEBUG */
#define PASSERT(env, page, exp) \
	((void)sizeof(env), (void)sizeof(page), (void)sizeof !!(exp))
#endif /* !LIBCFS_DEBUG */

#ifdef CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK
# define PINVRNT(env, page, expr)                                       \
do {                                                                    \
	if (unlikely(!(expr))) {                                        \
		CL_PAGE_DEBUG(D_ERROR, (env), (page), #expr "\n");      \
		LINVRNT(0);                                             \
	}                                                               \
} while (0)
#else /* !CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK */
# define PINVRNT(env, page, exp) \
	 ((void)sizeof(env), (void)sizeof(page), (void)sizeof !!(exp))
#endif /* !CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK */

/* Disable page statistic by default due to huge performance penalty. */
static void cs_page_inc(const struct cl_object *obj,
			enum cache_stats_item item)
{
#ifdef CONFIG_DEBUG_PAGESTATE_TRACKING
	atomic_inc(&cl_object_site(obj)->cs_pages.cs_stats[item]);
#endif
}

static void cs_page_dec(const struct cl_object *obj,
			enum cache_stats_item item)
{
#ifdef CONFIG_DEBUG_PAGESTATE_TRACKING
	atomic_dec(&cl_object_site(obj)->cs_pages.cs_stats[item]);
#endif
}

static void cs_pagestate_inc(const struct cl_object *obj,
			     enum cl_page_state state)
{
#ifdef CONFIG_DEBUG_PAGESTATE_TRACKING
	atomic_inc(&cl_object_site(obj)->cs_pages_state[state]);
#endif
}

static void cs_pagestate_dec(const struct cl_object *obj,
			     enum cl_page_state state)
{
#ifdef CONFIG_DEBUG_PAGESTATE_TRACKING
	atomic_dec(&cl_object_site(obj)->cs_pages_state[state]);
#endif
}

/**
 * Internal version of cl_page_get().
 *
 * This function can be used to obtain initial reference to previously
 * unreferenced cached object. It can be called only if concurrent page
 * reclamation is somehow prevented, e.g., by keeping a lock on a VM page,
 * associated with \a page.
 *
 * Use with care! Not exported.
 */
static void cl_page_get_trust(struct cl_page *page)
{
	LASSERT(refcount_read(&page->cp_ref) > 0);
	refcount_inc(&page->cp_ref);
}

static struct cl_page_slice *
cl_page_slice_get(const struct cl_page *cl_page, int index)
{
	if (index < 0 || index >= cl_page->cp_layer_count)
		return NULL;

	/* To get the cp_layer_offset values fit under 256 bytes, we
	 * use the offset beyond the end of struct cl_page.
	 */
	return (struct cl_page_slice *)((char *)cl_page + sizeof(*cl_page) +
					cl_page->cp_layer_offset[index]);
}

#define cl_page_slice_for_each(cl_page, slice, i)		\
	for (i = 0, slice = cl_page_slice_get(cl_page, 0);	\
	     i < (cl_page)->cp_layer_count;			\
	     slice = cl_page_slice_get(cl_page, ++i))

#define cl_page_slice_for_each_reverse(cl_page, slice, i)	\
	for (i = (cl_page)->cp_layer_count - 1,			\
	     slice = cl_page_slice_get(cl_page, i); i >= 0;	\
	     slice = cl_page_slice_get(cl_page, --i))

static void __cl_page_free(struct cl_page *cl_page, unsigned short bufsize)
{
	int index = cl_page->cp_kmem_index;

	if (index >= 0) {
		LASSERT(index < ARRAY_SIZE(cl_page_kmem_array));
		LASSERT(cl_page_kmem_size_array[index] == bufsize);
		OBD_SLAB_FREE(cl_page, cl_page_kmem_array[index], bufsize);
	} else {
		OBD_FREE(cl_page, bufsize);
	}
}

static void cl_page_free(const struct lu_env *env, struct cl_page *cp,
			 struct folio_batch *fbatch)
{
	struct cl_object *obj  = cp->cp_obj;
	unsigned short bufsize = cl_object_header(obj)->coh_page_bufsize;
	struct page *vmpage;

	ENTRY;
	PASSERT(env, cp, list_empty(&cp->cp_batch));

	if (cp->cp_type == CPT_CACHEABLE) {
		PASSERT(env, cp, cp->cp_owner == NULL);
		PASSERT(env, cp, cp->cp_state == CPS_FREEING);
		/* vmpage->private was already cleared when page was
		 * moved into CPS_FREEING state.
		 */
		vmpage = cp->cp_vmpage;
		LASSERT(vmpage != NULL);
		LASSERT((struct cl_page *)vmpage->private != cp);

		if (fbatch != NULL) {
			if (!folio_batch_add_page(fbatch, vmpage))
				folio_batch_release(fbatch);
		} else {
			put_page(vmpage);
		}
	}

	cp->cp_layer_count = 0;
	cs_page_dec(obj, CS_total);
	if (cp->cp_type != CPT_TRANSIENT)
		cs_pagestate_dec(obj, cp->cp_state);
	if (cp->cp_type != CPT_TRANSIENT)
		cl_object_put(env, obj);
	__cl_page_free(cp, bufsize);
	EXIT;
}

static struct cl_page *__cl_page_alloc(struct cl_object *o)
{
	int i = 0;
	struct cl_page *cl_page = NULL;
	unsigned short bufsize = cl_object_header(o)->coh_page_bufsize;

	if (CFS_FAIL_CHECK(OBD_FAIL_LLITE_PAGE_ALLOC))
		return NULL;

check:
	/* the number of entries in cl_page_kmem_array is expected to
	 * only be 2-3 entries, so the lookup overhead should be low.
	 */
	for ( ; i < ARRAY_SIZE(cl_page_kmem_array); i++) {
		if (smp_load_acquire(&cl_page_kmem_size_array[i]) == bufsize) {
			OBD_SLAB_ALLOC_GFP(cl_page, cl_page_kmem_array[i],
					   bufsize, GFP_NOFS);
			if (cl_page)
				cl_page->cp_kmem_index = i;
			return cl_page;
		}
		if (cl_page_kmem_size_array[i] == 0)
			break;
	}

	if (i < ARRAY_SIZE(cl_page_kmem_array)) {
		char cache_name[32];

		mutex_lock(&cl_page_kmem_mutex);
		if (cl_page_kmem_size_array[i]) {
			mutex_unlock(&cl_page_kmem_mutex);
			goto check;
		}
		snprintf(cache_name, sizeof(cache_name),
			 "cl_page_kmem-%u", bufsize);
		cl_page_kmem_array[i] =
			kmem_cache_create(cache_name, bufsize,
					  0, 0, NULL);
		if (cl_page_kmem_array[i] == NULL) {
			mutex_unlock(&cl_page_kmem_mutex);
			return NULL;
		}
		smp_store_release(&cl_page_kmem_size_array[i], bufsize);
		mutex_unlock(&cl_page_kmem_mutex);
		goto check;
	} else {
		OBD_ALLOC_GFP(cl_page, bufsize, GFP_NOFS);
		if (cl_page)
			cl_page->cp_kmem_index = -1;
	}

	return cl_page;
}

struct cl_page *cl_page_alloc(const struct lu_env *env, struct cl_object *o,
			      pgoff_t ind, struct page *vmpage,
			      enum cl_page_type type)
{
	struct cl_page *cl_page;
	struct cl_object *head;

	ENTRY;

	cl_page = __cl_page_alloc(o);
	if (cl_page != NULL) {
		int result = 0;

		/* Please fix cl_page:cp_state/type declaration if
		 * these assertions fail in the future.
		 */
		BUILD_BUG_ON((1 << CP_STATE_BITS) < CPS_NR); /* cp_state */
		BUILD_BUG_ON((1 << CP_TYPE_BITS) < CPT_NR); /* cp_type */
		refcount_set(&cl_page->cp_ref, 1);
		cl_page->cp_obj = o;
		if (type != CPT_TRANSIENT)
			cl_object_get(o);
		cl_page->cp_vmpage = vmpage;
		if (cl_page->cp_type != CPT_TRANSIENT)
			cl_page->cp_state = CPS_CACHED;
		cl_page->cp_type = type;
		if (type == CPT_TRANSIENT)
			/* correct inode to be added in ll_direct_rw_pages */
			cl_page->cp_inode = NULL;
		else
			cl_page->cp_inode = page2inode(vmpage);
		INIT_LIST_HEAD(&cl_page->cp_batch);
		head = o;
		cl_page->cp_page_index = ind;
		cl_object_for_each(o, head) {
			if (o->co_ops->coo_page_init != NULL) {
				result = o->co_ops->coo_page_init(env, o,
							cl_page, ind);
				if (result != 0) {
					__cl_page_delete(env, cl_page);
					cl_page_free(env, cl_page, NULL);
					cl_page = ERR_PTR(result);
					break;
				}
			}
		}
		if (result == 0) {
			cs_page_inc(o, CS_total);
			cs_page_inc(o, CS_create);
			cs_pagestate_dec(o, CPS_CACHED);
		}
	} else {
		cl_page = ERR_PTR(-ENOMEM);
	}
	RETURN(cl_page);
}

/**
 * Returns a cl_page with index \a idx at the object \a o, and associated with
 * the VM page \a vmpage.
 *
 * This is the main entry point into the cl_page caching interface. First, a
 * cache (implemented as a per-object radix tree) is consulted. If page is
 * found there, it is returned immediately. Otherwise new page is allocated
 * and returned. In any case, additional reference to page is acquired.
 *
 * \see cl_object_find(), cl_lock_find()
 */
struct cl_page *cl_page_find(const struct lu_env *env,
			     struct cl_object *o,
			     pgoff_t idx, struct page *vmpage,
			     enum cl_page_type type)
{
	struct cl_page          *page = NULL;
	struct cl_object_header *hdr;

	LASSERT(type == CPT_CACHEABLE || type == CPT_TRANSIENT);
	might_sleep();

	ENTRY;

	hdr = cl_object_header(o);
	cs_page_inc(o, CS_lookup);

	CDEBUG(D_PAGE, "%lu@"DFID" %p %lx %d\n",
	       idx, PFID(&hdr->coh_lu.loh_fid), vmpage, vmpage->private, type);
	/* fast path. */
	if (type == CPT_CACHEABLE) {
		/* vmpage lock used to protect the child/parent relationship */
		LASSERT(PageLocked(vmpage));
		/*
		 * cl_vmpage_page() can be called here without any locks as
		 *
		 *     - "vmpage" is locked (which prevents ->private from
		 *       concurrent updates), and
		 *
		 *     - "o" cannot be destroyed while current thread holds a
		 *       reference on it.
		 */
		page = cl_vmpage_page(vmpage, o);
		if (page != NULL) {
			cs_page_inc(o, CS_hit);
			RETURN(page);
		}
	}

	/* allocate and initialize cl_page */
	page = cl_page_alloc(env, o, idx, vmpage, type);
	RETURN(page);
}
EXPORT_SYMBOL(cl_page_find);

static inline int cl_page_invariant(const struct cl_page *pg)
{
	return cl_page_in_use_noref(pg);
}

static void __cl_page_state_set(const struct lu_env *env,
				struct cl_page *cl_page,
				enum cl_page_state state)
{
	enum cl_page_state old;

	/* Matrix of allowed state transitions [old][new] for sanity checking */
	static const int allowed_transitions[CPS_NR][CPS_NR] = {
		[CPS_CACHED] = {
			[CPS_CACHED]  = 0,
			[CPS_OWNED]   = 1, /* io finds existing cached page */
			[CPS_PAGEIN]  = 0,
			[CPS_PAGEOUT] = 1, /* write-out from the cache */
			[CPS_FREEING] = 1, /* eviction on the memory pressure */
		},
		[CPS_OWNED] = {
			[CPS_CACHED]  = 1, /* release to the cache */
			[CPS_OWNED]   = 0,
			[CPS_PAGEIN]  = 1, /* start read immediately */
			[CPS_PAGEOUT] = 1, /* start write immediately */
			[CPS_FREEING] = 1, /* lock invalidation or truncate */
		},
		[CPS_PAGEIN] = {
			[CPS_CACHED]  = 1, /* io completion */
			[CPS_OWNED]   = 0,
			[CPS_PAGEIN]  = 0,
			[CPS_PAGEOUT] = 0,
			[CPS_FREEING] = 0,
		},
		[CPS_PAGEOUT] = {
			[CPS_CACHED]  = 1, /* io completion */
			[CPS_OWNED]   = 0,
			[CPS_PAGEIN]  = 0,
			[CPS_PAGEOUT] = 0,
			[CPS_FREEING] = 0,
		},
		[CPS_FREEING] = {
			[CPS_CACHED]  = 0,
			[CPS_OWNED]   = 0,
			[CPS_PAGEIN]  = 0,
			[CPS_PAGEOUT] = 0,
			[CPS_FREEING] = 0,
		}
	};

	ENTRY;
	old = cl_page->cp_state;
	PASSERT(env, cl_page, allowed_transitions[old][state]);
	CL_PAGE_HEADER(D_TRACE, env, cl_page, "%d -> %d\n", old, state);
	PASSERT(env, cl_page, cl_page->cp_state == old);
	PASSERT(env, cl_page, equi(state == CPS_OWNED,
				   cl_page->cp_owner != NULL));

	cs_pagestate_dec(cl_page->cp_obj, cl_page->cp_state);
	cs_pagestate_inc(cl_page->cp_obj, state);
	cl_page->cp_state = state;
	EXIT;
}

static void cl_page_state_set(const struct lu_env *env,
			      struct cl_page *page, enum cl_page_state state)
{
	LASSERT(page->cp_type != CPT_TRANSIENT);
	__cl_page_state_set(env, page, state);
}

/**
 * Acquires an additional reference to a page.
 *
 * This can be called only by caller already possessing a reference to \a
 * page.
 *
 * \see cl_object_get(), cl_lock_get().
 */
void cl_page_get(struct cl_page *page)
{
	ENTRY;
	cl_page_get_trust(page);
	EXIT;
}
EXPORT_SYMBOL(cl_page_get);

/**
 * Releases a reference to a page, use the folio_batch to release the pages
 * in batch if provided.
 *
 * Users need to do a final folio_batch_release() to release any trailing pages.
 */
void cl_batch_put(const struct lu_env *env, struct cl_page *page,
		  struct folio_batch *fbatch)
{
	ENTRY;
	CL_PAGE_HEADER(D_TRACE, env, page, "%d\n",
		       refcount_read(&page->cp_ref));

	if (refcount_dec_and_test(&page->cp_ref)) {
		if (page->cp_type != CPT_TRANSIENT) {
			LASSERT(page->cp_state == CPS_FREEING);
			PASSERT(env, page, page->cp_owner == NULL);
		}

		LASSERT(refcount_read(&page->cp_ref) == 0);
		PASSERT(env, page, list_empty(&page->cp_batch));
		/* Page is no longer reachable by other threads. Tear it down */
		cl_page_free(env, page, fbatch);
	}

	EXIT;
}
EXPORT_SYMBOL(cl_batch_put);

/**
 * Releases a reference to a page, wrapper to cl_batch_put
 *
 * When last reference is released, page is returned to the cache, unless it
 * is in cl_page_state::CPS_FREEING state, in which case it is immediately
 * destroyed.
 *
 * \see cl_object_put(), cl_lock_put().
 */
void cl_page_put(const struct lu_env *env, struct cl_page *page)
{
	cl_batch_put(env, page, NULL);
}
EXPORT_SYMBOL(cl_page_put);

/* Returns a cl_page associated with a VM page, and given cl_object. */
struct cl_page *cl_vmpage_page(struct page *vmpage, struct cl_object *obj)
{
	struct cl_page *page;

	ENTRY;
	LASSERT(PageLocked(vmpage));

	/*
	 * NOTE: absence of races and liveness of data are guaranteed by page
	 *       lock on a "vmpage". That works because object destruction has
	 *       bottom-to-top pass.
	 */

	page = (struct cl_page *)vmpage->private;
	if (page != NULL) {
		cl_page_get_trust(page);
		LASSERT(page->cp_type == CPT_CACHEABLE);
	}
	RETURN(page);
}
EXPORT_SYMBOL(cl_vmpage_page);

static void cl_page_owner_clear(struct cl_page *page)
{
	ENTRY;
	if (page->cp_owner != NULL) {
		LASSERT(page->cp_owner->ci_owned_nr > 0);
		page->cp_owner->ci_owned_nr--;
		page->cp_owner = NULL;
	}
	EXIT;
}

static void cl_page_owner_set(struct cl_page *page)
{
	ENTRY;
	LASSERT(page->cp_owner != NULL);
	page->cp_owner->ci_owned_nr++;
	EXIT;
}

void __cl_page_disown(const struct lu_env *env, struct cl_page *cp)
{
	struct page *vmpage;
	enum cl_page_state state;

	ENTRY;

	cl_page_owner_clear(cp);
	state = cp->cp_state;
	PINVRNT(env, cp, state == CPS_OWNED || state == CPS_FREEING);
	PINVRNT(env, cp, cl_page_invariant(cp) || state == CPS_FREEING);
	if (state == CPS_OWNED)
		cl_page_state_set(env, cp, CPS_CACHED);
	vmpage = cp->cp_vmpage;
	LASSERT(vmpage != NULL);
	LASSERT(PageLocked(vmpage));
	unlock_page(vmpage);

	EXIT;
}

/* returns true, iff page is owned by the given io. */
int cl_page_is_owned(const struct cl_page *pg, const struct cl_io *io)
{
	struct cl_io *top = cl_io_top((struct cl_io *)io);

	LINVRNT(cl_object_same(pg->cp_obj, top->ci_obj));
	ENTRY;
	if (pg->cp_type != CPT_TRANSIENT)
		RETURN(pg->cp_state == CPS_OWNED && pg->cp_owner == top);
	else
		RETURN(pg->cp_owner == top);
}
EXPORT_SYMBOL(cl_page_is_owned);

/**
 * Try to own a page by IO.
 *
 * Waits until page is in cl_page_state::CPS_CACHED state, and then switch it
 * into cl_page_state::CPS_OWNED state.
 *
 * \pre  !cl_page_is_owned(cl_page, io)
 * \post result == 0 iff cl_page_is_owned(cl_page, io)
 *
 * \retval 0   success
 *
 * \retval -ve failure, e.g., cl_page was destroyed (and landed in
 *             cl_page_state::CPS_FREEING instead of cl_page_state::CPS_CACHED).
 *             or, page was owned by another thread, or in IO.
 *
 * \see cl_page_disown()
 * \see cl_page_own_try()
 * \see cl_page_own
 */
static int __cl_page_own(const struct lu_env *env, struct cl_io *io,
			 struct cl_page *cl_page, int nonblock)
{
	struct page *vmpage = cl_page->cp_vmpage;
	int result;

	ENTRY;

	LASSERT(cl_page->cp_type != CPT_TRANSIENT);

	PINVRNT(env, cl_page, !cl_page_is_owned(cl_page, io));

	if (cl_page->cp_type != CPT_TRANSIENT &&
	    cl_page->cp_state == CPS_FREEING) {
		result = -ENOENT;
		goto out;
	}

	LASSERT(vmpage != NULL);

	if (nonblock) {
		if (!trylock_page(vmpage)) {
			result = -EAGAIN;
			goto out;
		}

		if (unlikely(PageWriteback(vmpage))) {
			unlock_page(vmpage);
			result = -EAGAIN;
			goto out;
		}
	} else {
		lock_page(vmpage);
		wait_on_page_writeback(vmpage);
	}

	PASSERT(env, cl_page, cl_page->cp_owner == NULL);
	cl_page->cp_owner = cl_io_top(io);
	cl_page_owner_set(cl_page);

	if (cl_page->cp_state == CPS_FREEING) {
		__cl_page_disown(env, cl_page);
		result = -ENOENT;
		goto out;
	}

	cl_page_state_set(env, cl_page, CPS_OWNED);

	result = 0;
out:
	CDEBUG(D_INFO, "res %d\n", result);
	PINVRNT(env, cl_page, ergo(result == 0,
		cl_page_invariant(cl_page)));
	RETURN(result);
}

/* Own a page, might be blocked. (see __cl_page_own()) */
int cl_page_own(const struct lu_env *env, struct cl_io *io, struct cl_page *pg)
{
	return __cl_page_own(env, io, pg, 0);
}
EXPORT_SYMBOL(cl_page_own);

/* Nonblock version of cl_page_own(). (see __cl_page_own()) */
int cl_page_own_try(const struct lu_env *env, struct cl_io *io,
		    struct cl_page *pg)
{
	return __cl_page_own(env, io, pg, 1);
}
EXPORT_SYMBOL(cl_page_own_try);


/**
 * Assume page ownership.
 *
 * Called when page is already locked by the hosting VM.
 *
 * \pre !cl_page_is_owned(cp, io)
 * \post cl_page_is_owned(cp, io)
 */
void cl_page_assume(const struct lu_env *env,
		    struct cl_io *io, struct cl_page *cp)
{
	struct page *vmpage;

	ENTRY;
	PINVRNT(env, cp, cl_object_same(cp->cp_obj, cl_io_top(io)->ci_obj));

	LASSERT(cp->cp_type != CPT_TRANSIENT);
	PASSERT(env, cp, cp->cp_owner == NULL);

	vmpage = cp->cp_vmpage;
	LASSERT(vmpage != NULL);
	LASSERT(PageLocked(vmpage));
	wait_on_page_writeback(vmpage);
	cp->cp_owner = cl_io_top(io);
	cl_page_owner_set(cp);
	cl_page_state_set(env, cp, CPS_OWNED);

	EXIT;
}
EXPORT_SYMBOL(cl_page_assume);

/**
 * Releases page ownership without unlocking the page.
 *
 * Moves cl_page into cl_page_state::CPS_CACHED without releasing a lock
 * on the underlying VM page (as VM is supposed to do this itself).
 *
 * \pre   cl_page_is_owned(cp, io)
 * \post !cl_page_is_owned(cp, io)
 */
void cl_page_unassume(const struct lu_env *env,
		      struct cl_io *io, struct cl_page *cp)
{
	struct page *vmpage;

	ENTRY;

	LASSERT(cp->cp_type != CPT_TRANSIENT);

	PINVRNT(env, cp, cl_page_is_owned(cp, io));
	PINVRNT(env, cp, cl_page_invariant(cp));
	cl_page_owner_clear(cp);
	cl_page_state_set(env, cp, CPS_CACHED);
	vmpage = cp->cp_vmpage;
	LASSERT(vmpage != NULL);
	LASSERT(PageLocked(vmpage));

	EXIT;
}
EXPORT_SYMBOL(cl_page_unassume);

/**
 * Releases page ownership.
 *
 * Moves page into cl_page_state::CPS_CACHED.
 *
 * \pre   cl_page_is_owned(pg, io)
 * \post !cl_page_is_owned(pg, io)
 *
 * \see cl_page_own()
 */
void cl_page_disown(const struct lu_env *env,
		    struct cl_io *io, struct cl_page *pg)
{
	LASSERT(pg->cp_type != CPT_TRANSIENT);

	PINVRNT(env, pg, cl_page_is_owned(pg, cl_io_top(io)) ||
		pg->cp_state == CPS_FREEING);

	__cl_page_disown(env, pg);
}
EXPORT_SYMBOL(cl_page_disown);

/**
 * Called when cl_page is to be removed from the object, e.g.,
 * as a result of truncate.
 *
 * Calls cl_page_operations::cpo_discard() top-to-bottom.
 *
 * \pre cl_page_is_owned(cl_page, io)
 *
 * \see cl_page_operations::cpo_discard()
 */
void cl_page_discard(const struct lu_env *env,
		     struct cl_io *io, struct cl_page *cp)
{
	struct page *vmpage;
	const struct cl_page_slice *slice;
	int i;

	LASSERT(cp->cp_type != CPT_TRANSIENT);

	cl_page_slice_for_each(cp, slice, i) {
		if (slice->cpl_ops->cpo_discard != NULL)
			(*slice->cpl_ops->cpo_discard)(env, slice, io);
	}

	PINVRNT(env, cp, cl_page_is_owned(cp, io));
	PINVRNT(env, cp, cl_page_invariant(cp));
	vmpage = cp->cp_vmpage;
	LASSERT(vmpage != NULL);
	LASSERT(PageLocked(vmpage));
	generic_error_remove_folio(vmpage->mapping, page_folio(vmpage));
}
EXPORT_SYMBOL(cl_page_discard);

/**
 * Version of cl_page_delete() that can be called for not fully constructed
 * cl_pages, e.g. in an error handling cl_page_find()->__cl_page_delete()
 * path. Doesn't check cl_page invariant.
 */
static void __cl_page_delete(const struct lu_env *env, struct cl_page *cp)
{
	const struct cl_page_slice *slice;
	int i;

	ENTRY;

	if (cp->cp_type == CPT_TRANSIENT)
		EXIT;

	/*
	 * Severe all ways to obtain new pointers to @pg.
	 * Transient pages already can't be found because they're not in cache.
	 */
	PASSERT(env, cp, cp->cp_state != CPS_FREEING);
	cl_page_owner_clear(cp);
	__cl_page_state_set(env, cp, CPS_FREEING);

	cl_page_slice_for_each_reverse(cp, slice, i) {
		if (slice->cpl_ops->cpo_delete != NULL)
			(*slice->cpl_ops->cpo_delete)(env, slice);
	}

	EXIT;
}

/**
 * Called when a decision is made to throw page out of memory.
 *
 * Notifies all layers about page destruction by calling
 * cl_page_operations::cpo_delete() method top-to-bottom.
 *
 * Moves page into cl_page_state::CPS_FREEING state (this is the only place
 * where transition to this state happens).
 *
 * Eliminates all venues through which new references to the page can be
 * obtained:
 *
 *     - removes page from the radix trees,
 *
 *     - breaks linkage from VM page to cl_page.
 *
 * Once page reaches cl_page_state::CPS_FREEING, all remaining references will
 * drain after some time, at which point page will be recycled.
 *
 * \pre  VM page is locked
 * \post pg->cp_state == CPS_FREEING
 *
 * \see cl_page_operations::cpo_delete()
 */
void cl_page_delete(const struct lu_env *env, struct cl_page *pg)
{
	PINVRNT(env, pg, cl_page_invariant(pg));
	ENTRY;
	__cl_page_delete(env, pg);
	EXIT;
}
EXPORT_SYMBOL(cl_page_delete);

void cl_page_touch(const struct lu_env *env,
		   const struct cl_page *cl_page, size_t to)
{
	const struct cl_page_slice *slice;
	int i;

	ENTRY;

	cl_page_slice_for_each(cl_page, slice, i) {
		if (slice->cpl_ops->cpo_page_touch != NULL)
			(*slice->cpl_ops->cpo_page_touch)(env, slice, to);
	}

	EXIT;
}
EXPORT_SYMBOL(cl_page_touch);

static enum cl_page_state cl_req_type_state(enum cl_req_type crt)
{
	ENTRY;
	RETURN(crt == CRT_WRITE ? CPS_PAGEOUT : CPS_PAGEIN);
}

static void cl_page_io_start(const struct lu_env *env,
			     struct cl_page *pg, enum cl_req_type crt)
{
	/* Page is queued for IO, change its state. */
	ENTRY;
	cl_page_owner_clear(pg);
	cl_page_state_set(env, pg, cl_req_type_state(crt));
	EXIT;
}

/**
 * Prepares page for immediate transfer. Return -EALREADY if this page
 * should be omitted from transfer.
 */
int cl_page_prep(const struct lu_env *env, struct cl_io *io,
		 struct cl_page *cp, enum cl_req_type crt)
{
	struct page *vmpage = cp->cp_vmpage;
	int rc;

	LASSERT(cp->cp_type != CPT_TRANSIENT);
	PASSERT(env, cp, crt < CRT_NR);
	PINVRNT(env, cp, cl_page_is_owned(cp, io));
	PINVRNT(env, cp, cl_page_invariant(cp));

	if (crt == CRT_READ) {
		if (PageUptodate(vmpage))
			GOTO(out, rc = -EALREADY);
	} else {
		LASSERT(PageLocked(vmpage));
		LASSERT(!PageDirty(vmpage));

		/* ll_writepage path is not a sync write, so need to
		 * set page writeback flag
		 */
		if (cp->cp_sync_io == NULL)
			set_page_writeback(vmpage);
	}

	cl_page_io_start(env, cp, crt);
	rc = 0;
out:
	CL_PAGE_HEADER(D_TRACE, env, cp, "%d %d\n", crt, rc);

	return rc;
}
EXPORT_SYMBOL(cl_page_prep);

/**
 * Notify layers about transfer completion.
 *
 * Invoked by transfer sub-system (which is a part of osc) to notify layers
 * that a transfer, of which this page is a part of has completed.
 *
 * Completion call-backs are executed in the bottom-up order, so that
 * uppermost layer (llite), responsible for the VFS/VM interaction runs last
 * and can release locks safely.
 *
 * \pre  cl_page->cp_state == CPS_PAGEIN || cl_page->cp_state == CPS_PAGEOUT
 * \post cl_page->cl_page_state == CPS_CACHED
 *
 * \see cl_page_operations::cpo_completion()
 */
void cl_page_completion(const struct lu_env *env,
			struct cl_page *cl_page, enum cl_req_type crt,
			int ioret)
{
	const struct cl_page_slice *slice;
	struct cl_sync_io *anchor = cl_page->cp_sync_io;
	int i;

	ENTRY;

	CL_PAGE_HEADER(D_TRACE, env, cl_page, "%d %d\n", crt, ioret);
	PASSERT(env, cl_page, crt < CRT_NR);

	if (cl_page->cp_type != CPT_TRANSIENT) {
		PASSERT(env, cl_page,
			cl_page->cp_state == cl_req_type_state(crt));
		cl_page_state_set(env, cl_page, CPS_CACHED);

		cl_page_slice_for_each_reverse(cl_page, slice, i) {
			if (slice->cpl_ops->io[crt].cpo_completion != NULL)
				(*slice->cpl_ops->io[crt].cpo_completion)(env,
									  slice,
									 ioret);
		}
	}

	if (anchor != NULL) {
		LASSERT(cl_page->cp_sync_io == anchor);
		cl_page->cp_sync_io = NULL;
		cl_sync_io_note(env, anchor, ioret);
	}
	EXIT;
}
EXPORT_SYMBOL(cl_page_completion);

/**
 * Notify layers that transfer formation engine decided to yank this page from
 * the cache and to make it a part of a transfer.
 *
 * \pre  cl_page->cp_state == CPS_CACHED
 * \post cl_page->cp_state == CPS_PAGEIN || cl_page->cp_state == CPS_PAGEOUT
 */
int cl_page_make_ready(const struct lu_env *env, struct cl_page *cp,
		       enum cl_req_type crt)
{
	struct page *vmpage = cp->cp_vmpage;
	bool unlock = false;
	int rc;

	ENTRY;
	PASSERT(env, cp, crt == CRT_WRITE);
	LASSERT(cp->cp_type != CPT_TRANSIENT);

	lock_page(vmpage);
	PASSERT(env, cp, PageUptodate(vmpage));
	unlock = true;

	if (clear_page_dirty_for_io(vmpage)) {
		LASSERT(cp->cp_state == CPS_CACHED);
		/* This actually clears the dirty bit in the radix tree  */
		set_page_writeback(vmpage);
		CL_PAGE_HEADER(D_PAGE, env, cp, "readied\n");
		rc = 0;
	} else if (cp->cp_state == CPS_PAGEOUT) {
		/* is it possible for osc_flush_async_page()
		 * to already make it ready?
		 */
		rc = -EALREADY;
	} else {
		CL_PAGE_DEBUG(D_ERROR, env, cp,
			      "unexpecting page state %d\n",
			      cp->cp_state);
		LBUG();
	}

	if (rc == 0) {
		PASSERT(env, cp, cp->cp_state == CPS_CACHED);
		cl_page_io_start(env, cp, crt);
	}

	if (unlock)
		unlock_page(vmpage);

	CL_PAGE_HEADER(D_TRACE, env, cp, "%d %d\n", crt, rc);

	return rc;
}
EXPORT_SYMBOL(cl_page_make_ready);

/**
 * Called if a page is being written back by kernel's intention.
 *
 * \pre  cl_page_is_owned(cl_page, io)
 * \post ergo(result == 0, cl_page->cp_state == CPS_PAGEOUT)
 *
 * \see cl_page_operations::cpo_flush()
 */
int cl_page_flush(const struct lu_env *env, struct cl_io *io,
		  struct cl_page *cl_page)
{
	const struct cl_page_slice *slice;
	int result = 0;
	int i;

	ENTRY;
	LASSERT(cl_page->cp_type != CPT_TRANSIENT);
	PINVRNT(env, cl_page, cl_page_is_owned(cl_page, io));
	PINVRNT(env, cl_page, cl_page_invariant(cl_page));

	cl_page_slice_for_each(cl_page, slice, i) {
		if (slice->cpl_ops->cpo_flush != NULL)
			result = (*slice->cpl_ops->cpo_flush)(env, slice, io);
		if (result != 0)
			break;
	}
	if (result > 0)
		result = 0;

	CL_PAGE_HEADER(D_TRACE, env, cl_page, "%d\n", result);
	RETURN(result);
}
EXPORT_SYMBOL(cl_page_flush);

/**
 * Tells transfer engine that only part of a page is to be transmitted.
 *
 * \see cl_page_operations::cpo_clip()
 */
void cl_page_clip(const struct lu_env *env, struct cl_page *cl_page,
		  int from, int to)
{
	const struct cl_page_slice *slice;
	int i;

	PINVRNT(env, cl_page, cl_page_invariant(cl_page));

	CL_PAGE_HEADER(D_TRACE, env, cl_page, "%d %d\n", from, to);
	cl_page_slice_for_each(cl_page, slice, i) {
		if (slice->cpl_ops->cpo_clip != NULL)
			(*slice->cpl_ops->cpo_clip)(env, slice, from, to);
	}
}
EXPORT_SYMBOL(cl_page_clip);

/* Prints human readable representation of \a pg to the \a f. */
void cl_page_header_print(const struct lu_env *env, void *cookie,
			  lu_printer_t printer, const struct cl_page *pg)
{
	(*printer)(env, cookie,
		   "page@%p[%d %p %d %d %p]\n",
		   pg, refcount_read(&pg->cp_ref), pg->cp_obj,
		   pg->cp_state, pg->cp_type,
		   pg->cp_owner);
}
EXPORT_SYMBOL(cl_page_header_print);

/* Prints human readable representation of \a cl_page to the \a f. */
void cl_page_print(const struct lu_env *env, void *cookie,
		   lu_printer_t printer, const struct cl_page *cp)
{
	struct page *vmpage = cp->cp_vmpage;
	const struct cl_page_slice *slice;
	int result = 0;
	int i;

	cl_page_header_print(env, cookie, printer, cp);

	(*printer)(env, cookie, "vmpage @%p", vmpage);

	if (vmpage != NULL) {
		(*printer)(env, cookie, " %lx %d:%d %lx %lu %slru",
			   (long)vmpage->flags, page_count(vmpage),
			   page_mapcount(vmpage), vmpage->private,
			   page_index(vmpage),
			   list_empty(&vmpage->lru) ? "not-" : "");
	}

	(*printer)(env, cookie, "\n");

	cl_page_slice_for_each(cp, slice, i) {
		if (slice->cpl_ops->cpo_print != NULL)
			result = (*slice->cpl_ops->cpo_print)(env, slice,
							      cookie, printer);
		if (result != 0)
			break;
	}

	(*printer)(env, cookie, "end page@%p\n", cp);
}
EXPORT_SYMBOL(cl_page_print);

/**
 * Adds page slice to the compound page.
 *
 * This is called by cl_object_operations::coo_page_init() methods to add a
 * per-layer state to the page. New state is added at the end of
 * cl_page::cp_layers list, that is, it is at the bottom of the stack.
 *
 * \see cl_lock_slice_add(), cl_req_slice_add(), cl_io_slice_add()
 */
void cl_page_slice_add(struct cl_page *cl_page, struct cl_page_slice *slice,
		       struct cl_object *obj,
		       const struct cl_page_operations *ops)
{
	unsigned int offset = (char *)slice -
			((char *)cl_page + sizeof(*cl_page));

	ENTRY;
	LASSERT(cl_page->cp_layer_count < CP_MAX_LAYER);
	LASSERT(offset < (1 << sizeof(cl_page->cp_layer_offset[0]) * 8));
	cl_page->cp_layer_offset[cl_page->cp_layer_count++] = offset;
	slice->cpl_ops  = ops;
	slice->cpl_page = cl_page;

	EXIT;
}
EXPORT_SYMBOL(cl_page_slice_add);

/* Allocate and initialize cl_cache, called by ll_init_sbi(). */
struct cl_client_cache *cl_cache_init(unsigned long lru_page_max)
{
	struct cl_client_cache	*cache = NULL;

	ENTRY;
	OBD_ALLOC(cache, sizeof(*cache));
	if (cache == NULL)
		RETURN(NULL);

	/* Initialize cache data */
	refcount_set(&cache->ccc_users, 1);
	cache->ccc_lru_max = lru_page_max;
	atomic_long_set(&cache->ccc_lru_left, lru_page_max);
	atomic_long_set(&cache->ccc_unevict_lru_used, 0);
	spin_lock_init(&cache->ccc_lru_lock);
	INIT_LIST_HEAD(&cache->ccc_lru);

	cache->ccc_unstable_check = 1;
	atomic_long_set(&cache->ccc_unstable_nr, 0);
	mutex_init(&cache->ccc_max_cache_mb_lock);

	RETURN(cache);
}
EXPORT_SYMBOL(cl_cache_init);

/* Increase cl_cache refcount */
void cl_cache_incref(struct cl_client_cache *cache)
{
	refcount_inc(&cache->ccc_users);
}
EXPORT_SYMBOL(cl_cache_incref);

/**
 * Decrease cl_cache refcount and free the cache if refcount=0.
 * Since llite, lov and osc all hold cl_cache refcount,
 * the free will not cause race. (LU-6173)
 */
void cl_cache_decref(struct cl_client_cache *cache)
{
	if (refcount_dec_and_test(&cache->ccc_users))
		OBD_FREE(cache, sizeof(*cache));
}
EXPORT_SYMBOL(cl_cache_decref);
