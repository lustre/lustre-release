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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/lnet/lib-md.c
 *
 * Memory Descriptor management routines
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lib-lnet.h>

/* must be called with lnet_res_lock held */
void
lnet_md_unlink(struct lnet_libmd *md)
{
	if ((md->md_flags & LNET_MD_FLAG_ZOMBIE) == 0) {
		/* first unlink attempt... */
		struct lnet_me *me = md->md_me;

		md->md_flags |= LNET_MD_FLAG_ZOMBIE;

		/* Disassociate from ME (if any), and unlink it if it was created
		 * with LNET_UNLINK */
		if (me != NULL) {
			/* detach MD from portal */
			lnet_ptl_detach_md(me, md);
			if (me->me_unlink == LNET_UNLINK)
				lnet_me_unlink(me);
		}

		/* ensure all future handle lookups fail */
		lnet_res_lh_invalidate(&md->md_lh);
	}

	if (md->md_refcount != 0) {
		CDEBUG(D_NET, "Queueing unlink of md %p\n", md);
		return;
	}

	CDEBUG(D_NET, "Unlinking md %p\n", md);

	LASSERT(!list_empty(&md->md_list));
	list_del_init(&md->md_list);
	LASSERT(!(md->md_flags & LNET_MD_FLAG_HANDLING));
	lnet_md_free(md);
}

struct page *
lnet_kvaddr_to_page(unsigned long vaddr)
{
	if (is_vmalloc_addr((void *)vaddr))
		return vmalloc_to_page((void *)vaddr);

#ifdef CONFIG_HIGHMEM

#ifdef HAVE_KMAP_TO_PAGE
	/*
	 * This ifdef is added to handle the kernel versions
	 * which have kmap_to_page() function exported. If so,
	 * we should use it. Otherwise, remain with the legacy check.
	 */
	return kmap_to_page((void *)vaddr);
#else

	if (vaddr >= PKMAP_ADDR(0) && vaddr < PKMAP_ADDR(LAST_PKMAP)) {
		/* No highmem pages only used for bulk (kiov) I/O */
		CERROR("find page for address in highmem\n");
		LBUG();
	}
	return virt_to_page(vaddr);
#endif /* HAVE_KMAP_TO_PAGE */
#else

	return virt_to_page(vaddr);
#endif /* CONFIG_HIGHMEM */
}
EXPORT_SYMBOL(lnet_kvaddr_to_page);

int
lnet_cpt_of_md(struct lnet_libmd *md, unsigned int offset)
{
	int cpt = CFS_CPT_ANY;
	unsigned int niov;
	struct bio_vec *kiov;

	/*
	 * if the md_options has a bulk handle then we want to look at the
	 * bulk md because that's the data which we will be DMAing
	 */
	if (md && (md->md_options & LNET_MD_BULK_HANDLE) != 0 &&
	    !LNetMDHandleIsInvalid(md->md_bulk_handle))
		md = lnet_handle2md(&md->md_bulk_handle);

	if (!md || md->md_niov == 0)
		return CFS_CPT_ANY;

	kiov = md->md_kiov;
	niov = md->md_niov;

	while (offset >= kiov->bv_len) {
		offset -= kiov->bv_len;
		niov--;
		kiov++;
		if (niov == 0) {
			CERROR("offset %d goes beyond kiov\n", offset);
			goto out;
		}
	}

	cpt = cfs_cpt_of_node(lnet_cpt_table(),
			      page_to_nid(kiov->bv_page));
out:
	return cpt;
}

static int lnet_md_validate(const struct lnet_md *umd);

static struct lnet_libmd *
lnet_md_build(const struct lnet_md *umd, int unlink)
{
	int i;
	unsigned int niov;
	int total_length = 0;
	struct lnet_libmd *lmd;
	unsigned int size;

	if (lnet_md_validate(umd) != 0)
		return ERR_PTR(-EINVAL);

	if (umd->options & LNET_MD_KIOV)
		niov = umd->length;
	else
		niov = DIV_ROUND_UP(offset_in_page(umd->start) + umd->length,
				    PAGE_SIZE);
	size = offsetof(struct lnet_libmd, md_kiov[niov]);

	if (size <= LNET_SMALL_MD_SIZE) {
		lmd = kmem_cache_zalloc(lnet_small_mds_cachep, GFP_NOFS);
		if (lmd) {
			CDEBUG(D_MALLOC,
			       "slab-alloced 'md' of size %u at %p.\n",
			       size, lmd);
		} else {
			CDEBUG(D_MALLOC, "failed to allocate 'md' of size %u\n",
			       size);
		}
	} else {
		LIBCFS_ALLOC(lmd, size);
	}

	if (!lmd)
		return ERR_PTR(-ENOMEM);

	lmd->md_niov = niov;
	INIT_LIST_HEAD(&lmd->md_list);
	lmd->md_me = NULL;
	lmd->md_start = umd->start;
	lmd->md_offset = 0;
	lmd->md_max_size = umd->max_size;
	lmd->md_options = umd->options;
	lmd->md_user_ptr = umd->user_ptr;
	lmd->md_handler = NULL;
	lmd->md_threshold = umd->threshold;
	lmd->md_refcount = 0;
	lmd->md_flags = (unlink == LNET_UNLINK) ? LNET_MD_FLAG_AUTO_UNLINK : 0;
	lmd->md_bulk_handle = umd->bulk_handle;

	if (umd->options & LNET_MD_KIOV) {
		memcpy(lmd->md_kiov, umd->start,
		       niov * sizeof(lmd->md_kiov[0]));

		for (i = 0; i < (int)niov; i++) {
			/* We take the page pointer on trust */
			if (lmd->md_kiov[i].bv_offset +
			    lmd->md_kiov[i].bv_len > PAGE_SIZE) {
				lnet_md_free(lmd);
				return ERR_PTR(-EINVAL); /* invalid length */
			}

			total_length += lmd->md_kiov[i].bv_len;
		}

		lmd->md_length = total_length;

		if ((umd->options & LNET_MD_MAX_SIZE) && /* max size used */
		    (umd->max_size < 0 ||
		     umd->max_size > total_length)) { /* illegal max_size */
			lnet_md_free(lmd);
			return ERR_PTR(-EINVAL);
		}
	} else {   /* contiguous - split into pages */
		void *pa = umd->start;
		int len = umd->length;

		lmd->md_length = len;
		i = 0;
		while (len) {
			int plen;

			plen = min_t(int, len, PAGE_SIZE - offset_in_page(pa));

			lmd->md_kiov[i].bv_page =
				lnet_kvaddr_to_page((unsigned long) pa);
			lmd->md_kiov[i].bv_offset = offset_in_page(pa);
			lmd->md_kiov[i].bv_len = plen;

			len -= plen;
			pa += plen;
			i += 1;
		}
		if ((umd->options & LNET_MD_MAX_SIZE) && /* max size used */
		    (umd->max_size < 0 ||
		     umd->max_size > (int)umd->length)) { /* illegal max_size */
			lnet_md_free(lmd);
			return ERR_PTR(-EINVAL);
		}
		lmd->md_options |= LNET_MD_KIOV;
	}

	return lmd;
}

/* must be called with resource lock held */
static void
lnet_md_link(struct lnet_libmd *md, lnet_handler_t handler, int cpt)
{
	struct lnet_res_container *container = the_lnet.ln_md_containers[cpt];

	/* NB we are passed an allocated, but inactive md.
	 * Caller may lnet_md_unlink() it, or may lnet_md_free() it.
	 */
	/* This implementation doesn't know how to create START events or
	 * disable END events.	Best to LASSERT our caller is compliant so
	 * we find out quickly...  */
	/*  TODO - reevaluate what should be here in light of
	 * the removal of the start and end events
	 * maybe there we shouldn't even allow LNET_EQ_NONE!)
	 * LASSERT (handler != NULL);
	 */
	md->md_handler = handler;

	lnet_res_lh_initialize(container, &md->md_lh);

	LASSERT(list_empty(&md->md_list));
	list_add(&md->md_list, &container->rec_active);
}

void lnet_assert_handler_unused(lnet_handler_t handler)
{
	struct lnet_res_container *container;
	int cpt;

	if (!handler)
		return;
	cfs_percpt_for_each(container, cpt, the_lnet.ln_md_containers) {
		struct lnet_libmd *md;

		lnet_res_lock(cpt);
		list_for_each_entry(md, &container->rec_active, md_list)
			LASSERT(md->md_handler != handler);
		lnet_res_unlock(cpt);
	}
}
EXPORT_SYMBOL(lnet_assert_handler_unused);

/* must be called with lnet_res_lock held */
void
lnet_md_deconstruct(struct lnet_libmd *lmd, struct lnet_event *ev)
{
	ev->md_start = lmd->md_start;
	ev->md_options = lmd->md_options;
	ev->md_user_ptr = lmd->md_user_ptr;
}

static int
lnet_md_validate(const struct lnet_md *umd)
{
	if (umd->start == NULL && umd->length != 0) {
		CERROR("MD start pointer can not be NULL with length %u\n",
		       umd->length);
		return -EINVAL;
	}

	if ((umd->options & LNET_MD_KIOV) &&
	    umd->length > LNET_MAX_IOV) {
		CERROR("Invalid option: too many fragments %u, %d max\n",
		       umd->length, LNET_MAX_IOV);
		return -EINVAL;
	}

	return 0;
}

/**
 * Create a memory descriptor and attach it to a ME
 *
 * \param me An ME to associate the new MD with.
 * \param umd Provides initial values for the user-visible parts of a MD.
 * Other than its use for initialization, there is no linkage between this
 * structure and the MD maintained by the LNet.
 * \param unlink A flag to indicate whether the MD is automatically unlinked
 * when it becomes inactive, either because the operation threshold drops to
 * zero or because the available memory becomes less than \a umd.max_size.
 * (Note that the check for unlinking a MD only occurs after the completion
 * of a successful operation on the MD.) The value LNET_UNLINK enables auto
 * unlinking; the value LNET_RETAIN disables it.
 * \param handle On successful returns, a handle to the newly created MD is
 * saved here. This handle can be used later in LNetMDUnlink().
 *
 * The ME will either be linked to the new MD, or it will be freed.
 *
 * \retval 0	   On success.
 * \retval -EINVAL If \a umd is not valid.
 * \retval -ENOMEM If new MD cannot be allocated.
 */
int
LNetMDAttach(struct lnet_me *me, const struct lnet_md *umd,
	     enum lnet_unlink unlink, struct lnet_handle_md *handle)
{
	LIST_HEAD(matches);
	LIST_HEAD(drops);
	struct lnet_libmd	*md;
	int			cpt;

	LASSERT(the_lnet.ln_refcount > 0);
	LASSERT(!me->me_md);

	if ((umd->options & (LNET_MD_OP_GET | LNET_MD_OP_PUT)) == 0) {
		CERROR("Invalid option: no MD_OP set\n");
		md = ERR_PTR(-EINVAL);
	} else
		md = lnet_md_build(umd, unlink);

	cpt = me->me_cpt;
	lnet_res_lock(cpt);

	if (IS_ERR(md)) {
		lnet_me_unlink(me);
		lnet_res_unlock(cpt);
		return PTR_ERR(md);
	}

	lnet_md_link(md, umd->handler, cpt);

	/* attach this MD to portal of ME and check if it matches any
	 * blocked msgs on this portal */
	lnet_ptl_attach_md(me, md, &matches, &drops);

	lnet_md2handle(handle, md);

	lnet_res_unlock(cpt);

	lnet_drop_delayed_msg_list(&drops, "Bad match");
	lnet_recv_delayed_msg_list(&matches);

	return 0;
}
EXPORT_SYMBOL(LNetMDAttach);

/**
 * Create a "free floating" memory descriptor - a MD that is not associated
 * with a ME. Such MDs are usually used in LNetPut() and LNetGet() operations.
 *
 * \param umd,unlink See the discussion for LNetMDAttach().
 * \param handle On successful returns, a handle to the newly created MD is
 * saved here. This handle can be used later in LNetMDUnlink(), LNetPut(),
 * and LNetGet() operations.
 *
 * \retval 0	   On success.
 * \retval -EINVAL If \a umd is not valid.
 * \retval -ENOMEM If new MD cannot be allocated.
 */
int
LNetMDBind(const struct lnet_md *umd, enum lnet_unlink unlink,
	   struct lnet_handle_md *handle)
{
	struct lnet_libmd	*md;
	int		cpt;
	int		rc;

	LASSERT(the_lnet.ln_refcount > 0);

	if ((umd->options & (LNET_MD_OP_GET | LNET_MD_OP_PUT)) != 0) {
		CERROR("Invalid option: GET|PUT illegal on active MDs\n");
		return -EINVAL;
	}

	md = lnet_md_build(umd, unlink);
	if (IS_ERR(md))
		return PTR_ERR(md);

	if (md->md_length > LNET_MTU) {
		CERROR("Invalid length: too big transfer size %u, %d max\n",
		       md->md_length, LNET_MTU);
		rc = -EINVAL;
		goto out_free;
	}

	cpt = lnet_res_lock_current();

	lnet_md_link(md, umd->handler, cpt);

	lnet_md2handle(handle, md);

	lnet_res_unlock(cpt);
	return 0;

 out_free:
	lnet_md_free(md);
	return rc;
}
EXPORT_SYMBOL(LNetMDBind);

/**
 * Unlink the memory descriptor from any ME it may be linked to and release
 * the internal resources associated with it. As a result, active messages
 * associated with the MD may get aborted.
 *
 * This function does not free the memory region associated with the MD;
 * i.e., the memory the user allocated for this MD. If the ME associated with
 * this MD is not NULL and was created with auto unlink enabled, the ME is
 * unlinked as well (see LNetMEAttach()).
 *
 * Explicitly unlinking a MD via this function call has the same behavior as
 * a MD that has been automatically unlinked, except that no LNET_EVENT_UNLINK
 * is generated in the latter case.
 *
 * An unlinked event can be reported in two ways:
 * - If there's no pending operations on the MD, it's unlinked immediately
 *   and an LNET_EVENT_UNLINK event is logged before this function returns.
 * - Otherwise, the MD is only marked for deletion when this function
 *   returns, and the unlinked event will be piggybacked on the event of
 *   the completion of the last operation by setting the unlinked field of
 *   the event. No dedicated LNET_EVENT_UNLINK event is generated.
 *
 * Note that in both cases the unlinked field of the event is always set; no
 * more event will happen on the MD after such an event is logged.
 *
 * \param mdh A handle for the MD to be unlinked.
 *
 * \retval 0	   On success.
 * \retval -ENOENT If \a mdh does not point to a valid MD object.
 */
int
__LNetMDUnlink(struct lnet_handle_md mdh, bool discard)
{
	struct lnet_event ev;
	struct lnet_libmd *md = NULL;
	lnet_handler_t handler = NULL;
	int cpt;

	LASSERT(the_lnet.ln_refcount > 0);

	cpt = lnet_cpt_of_cookie(mdh.cookie);
	lnet_res_lock(cpt);
	while (!md) {
		md = lnet_handle2md(&mdh);
		if (!md) {
			lnet_res_unlock(cpt);
			return -ENOENT;
		}
		if (md->md_refcount == 0 &&
		    md->md_flags & LNET_MD_FLAG_HANDLING) {
			/* Race with unlocked call to ->md_handler. */
			lnet_md_wait_handling(md, cpt);
			md = NULL;
		}
	}

	md->md_flags |= LNET_MD_FLAG_ABORTED;
	/* If the MD is busy, lnet_md_unlink just marks it for deletion, and
	 * when the LND is done, the completion event flags that the MD was
	 * unlinked. Otherwise, we enqueue an event now... */
	if (md->md_handler && md->md_refcount == 0) {
		lnet_build_unlink_event(md, &ev);
		handler = md->md_handler;
	}

	if (discard)
		md->md_flags |= LNET_MD_FLAG_DISCARD;

	if (md->md_rspt_ptr != NULL)
		lnet_detach_rsp_tracker(md, cpt);

	lnet_md_unlink(md);

	lnet_res_unlock(cpt);

	if (handler)
		handler(&ev);

	return 0;
}
EXPORT_SYMBOL(__LNetMDUnlink);

bool
lnet_md_discarded(struct lnet_libmd *md)
{
	bool rc;
	int cpt;

	if (md == NULL)
		return false;

	cpt = lnet_cpt_of_cookie(md->md_lh.lh_cookie);
	lnet_res_lock(cpt);
	rc = md->md_flags & LNET_MD_FLAG_DISCARD;
	lnet_res_unlock(cpt);

	return rc;
}
EXPORT_SYMBOL(lnet_md_discarded);
