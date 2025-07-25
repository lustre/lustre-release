// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 *
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * osc cache management.
 *
 * Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_OSC

#include <lustre_osc.h>
#include <lustre_dlm.h>

#include "osc_internal.h"

static int extent_debug; /* set it to be true for more debug */

static void osc_update_pending(struct osc_object *obj, int cmd, int delta);
static int osc_extent_wait(const struct lu_env *env, struct osc_extent *ext,
			   enum osc_extent_state state);
static void osc_completion(const struct lu_env *env, struct osc_object *osc,
			   struct osc_async_page *oap, enum cl_req_type crt,
			   int rc);
static int osc_make_ready(const struct lu_env *env, struct osc_async_page *oap,
			  int cmd);
static int osc_refresh_count(const struct lu_env *env, struct osc_object *osc,
			     struct osc_async_page *oap, int cmd);
static int osc_io_unplug_async(const struct lu_env *env,
			       struct client_obd *cli, struct osc_object *osc);
static void osc_free_grant(struct client_obd *cli, unsigned int nr_pages,
			   unsigned int lost_grant, unsigned int dirty_grant);

static void osc_extent_tree_dump0(int mask, struct osc_object *obj,
				  const char *func, int line);
#define osc_extent_tree_dump(mask, obj) \
	osc_extent_tree_dump0(mask, obj, __func__, __LINE__)

static void osc_unreserve_grant(struct client_obd *cli, unsigned int reserved,
				unsigned int unused);

/** \addtogroup osc
 *  @{
 */

/* ------------------ osc extent ------------------ */
static inline char *ext_flags(struct osc_extent *ext, char *flags)
{
	char *buf = flags;
	*buf++ = ext->oe_rw ? 'r' : 'w';
	if (!RB_EMPTY_NODE(&ext->oe_node))
		*buf++ = 'i';
	if (ext->oe_sync)
		*buf++ = 'S';
	if (ext->oe_srvlock)
		*buf++ = 's';
	if (ext->oe_hp)
		*buf++ = 'h';
	if (ext->oe_urgent)
		*buf++ = 'u';
	if (ext->oe_memalloc)
		*buf++ = 'm';
	if (ext->oe_trunc_pending)
		*buf++ = 't';
	if (ext->oe_fsync_wait)
		*buf++ = 'Y';
	*buf = 0;
	return flags;
}

#define EXTSTR       "[%lu -> %lu/%lu]"
#define EXTPARA(ext) (ext)->oe_start, (ext)->oe_end, (ext)->oe_max_end
static const char *const oes_strings[] = {
	"inv", "active", "cache", "locking", "lockdone", "rpc", "trunc", NULL };

#define OSC_EXTENT_DUMP_WITH_LOC(file, func, line, mask, extent, fmt, ...) do {\
	static struct cfs_debug_limit_state cdls;			      \
	struct osc_extent *__ext = (extent);				      \
	char __buf[16];							      \
									      \
	__CDEBUG_WITH_LOC(file, func, line, mask, &cdls,		      \
		"extent %p@{" EXTSTR ", "				      \
		"[%d|%d|%c|%s|%s|%p], [%d|%d|%c|%c|%p|%u|%p]} " fmt,	      \
		/* ----- extent part 0 ----- */				      \
		__ext, EXTPARA(__ext),					      \
		/* ----- part 1 ----- */				      \
		kref_read(&__ext->oe_refc),				      \
		atomic_read(&__ext->oe_users),				      \
		list_empty_marker(&__ext->oe_link),			      \
		oes_strings[__ext->oe_state], ext_flags(__ext, __buf),	      \
		__ext->oe_obj,						      \
		/* ----- part 2 ----- */				      \
		__ext->oe_grants, __ext->oe_nr_pages,			      \
		list_empty_marker(&__ext->oe_pages),			      \
		waitqueue_active(&__ext->oe_waitq) ? '+' : '-',		      \
		__ext->oe_dlmlock, __ext->oe_mppr, __ext->oe_owner,	      \
		/* ----- part 4 ----- */				      \
		## __VA_ARGS__);					      \
	if (mask == D_ERROR && __ext->oe_dlmlock != NULL)		      \
		LDLM_ERROR(__ext->oe_dlmlock, "extent: %p", __ext);	      \
	else								      \
		LDLM_DEBUG(__ext->oe_dlmlock, "extent: %p", __ext);	      \
} while (0)

#define OSC_EXTENT_DUMP(mask, ext, fmt, ...)				\
	OSC_EXTENT_DUMP_WITH_LOC(__FILE__, __func__, __LINE__,		\
				 mask, ext, fmt, ## __VA_ARGS__)

#undef EASSERTF
#define EASSERTF(expr, ext, fmt, args...) do {				\
	if (!(expr)) {							\
		OSC_EXTENT_DUMP(D_ERROR, (ext), fmt, ##args);		\
		osc_extent_tree_dump(D_ERROR, (ext)->oe_obj);		\
		LASSERT(expr);						\
	}								\
} while (0)

#undef EASSERT
#define EASSERT(expr, ext) EASSERTF(expr, ext, "\n")

static inline struct osc_extent *rb_extent(struct rb_node *n)
{
	return rb_entry_safe(n, struct osc_extent, oe_node);
}

static inline struct osc_extent *next_extent(struct osc_extent *ext)
{
	if (ext == NULL)
		return NULL;

	LASSERT(!RB_EMPTY_NODE(&ext->oe_node));
	return rb_extent(rb_next(&ext->oe_node));
}

static inline struct osc_extent *prev_extent(struct osc_extent *ext)
{
	if (ext == NULL)
		return NULL;

	LASSERT(!RB_EMPTY_NODE(&ext->oe_node));
	return rb_extent(rb_prev(&ext->oe_node));
}

static inline struct osc_extent *first_extent(struct osc_object *obj)
{
	return rb_extent(rb_first(&obj->oo_root));
}

/* object must be locked by caller. */
static int osc_extent_sanity_check0(struct osc_extent *ext,
				    const char *func, const int line)
{
	struct osc_object *obj = ext->oe_obj;
	struct osc_async_page *oap;
	size_t page_count;
	int rc = 0;

	assert_osc_object_is_locked(obj);

	if (ext->oe_state >= OES_STATE_MAX)
		GOTO(out, rc = 10);

	if (kref_read(&ext->oe_refc) <= 0)
		GOTO(out, rc = 20);

	if (kref_read(&ext->oe_refc) < atomic_read(&ext->oe_users))
		GOTO(out, rc = 30);

	switch (ext->oe_state) {
	case OES_INV:
		if (ext->oe_nr_pages > 0 || !list_empty(&ext->oe_pages))
			GOTO(out, rc = 35);
		GOTO(out, rc = 0);
		break;
	case OES_ACTIVE:
		if (atomic_read(&ext->oe_users) == 0)
			GOTO(out, rc = 40);
		if (ext->oe_hp)
			GOTO(out, rc = 50);
		if (ext->oe_fsync_wait && !ext->oe_urgent)
			GOTO(out, rc = 55);
		break;
	case OES_CACHE:
		if (ext->oe_grants == 0)
			GOTO(out, rc = 60);
		if (ext->oe_fsync_wait && !ext->oe_urgent && !ext->oe_hp)
			GOTO(out, rc = 65);
		fallthrough;
	default:
		break;
	}

	if (ext->oe_max_end < ext->oe_end || ext->oe_end < ext->oe_start)
		GOTO(out, rc = 80);

	if (ext->oe_sync && ext->oe_grants > 0)
		GOTO(out, rc = 90);

	if (ext->oe_dlmlock != NULL &&
	    ext->oe_dlmlock->l_resource->lr_type == LDLM_EXTENT &&
	    !ldlm_is_failed(ext->oe_dlmlock)) {
		struct ldlm_extent *extent;

		extent = &ext->oe_dlmlock->l_policy_data.l_extent;
		if (!(extent->start <= ext->oe_start << PAGE_SHIFT &&
		      extent->end >= ext->oe_max_end << PAGE_SHIFT))
			GOTO(out, rc = 100);

		if (!(ext->oe_dlmlock->l_granted_mode & (LCK_PW | LCK_GROUP)))
			GOTO(out, rc = 102);
	}

	if (ext->oe_nr_pages > ext->oe_mppr)
		GOTO(out, rc = 105);

	/* Do not verify page list if extent is in RPC. This is because an
	 * in-RPC extent is supposed to be exclusively accessible w/o lock. */
	if (ext->oe_state > OES_CACHE)
		GOTO(out, rc = 0);

	if (!extent_debug)
		GOTO(out, rc = 0);

	page_count = 0;
	list_for_each_entry(oap, &ext->oe_pages, oap_pending_item) {
		pgoff_t index = osc_index(oap2osc(oap));
		++page_count;
		if (index > ext->oe_end || index < ext->oe_start)
			GOTO(out, rc = 110);
	}
	if (page_count != ext->oe_nr_pages)
		GOTO(out, rc = 120);

out:
	if (rc != 0)
		OSC_EXTENT_DUMP_WITH_LOC(__FILE__, func, line, D_ERROR, ext,
					 "sanity check %p failed: rc = %d\n",
					 ext, rc);
	return rc;
}

#define sanity_check_nolock(ext) \
	osc_extent_sanity_check0(ext, __func__, __LINE__)

#define sanity_check(ext) ({                                                   \
	int __res;                                                             \
	osc_object_lock((ext)->oe_obj);                                        \
	__res = sanity_check_nolock(ext);                                      \
	osc_object_unlock((ext)->oe_obj);                                      \
	__res;                                                                 \
})

static inline bool
overlapped(const struct osc_extent *ex1, const struct osc_extent *ex2)
{
	return !(ex1->oe_end < ex2->oe_start || ex2->oe_end < ex1->oe_start);
}

/**
 * sanity check - to make sure there is no overlapped extent in the tree.
 */
static int osc_extent_is_overlapped(struct osc_object *obj,
				    struct osc_extent *ext)
{
	struct osc_extent *tmp;

	assert_osc_object_is_locked(obj);

	if (!extent_debug)
		return 0;

	for (tmp = first_extent(obj); tmp != NULL; tmp = next_extent(tmp)) {
		if (tmp == ext)
			continue;
		if (overlapped(tmp, ext))
			return 1;
	}
	return 0;
}

static void osc_extent_state_set(struct osc_extent *ext, int state)
{
	assert_osc_object_is_locked(ext->oe_obj);
	LASSERT(state >= OES_INV && state < OES_STATE_MAX);

	/* Never try to sanity check a state changing extent :-) */
	/* LASSERT(sanity_check_nolock(ext) == 0); */

	/* TODO: validate the state machine */
	smp_store_release(&ext->oe_state, state);
	wake_up(&ext->oe_waitq);
}

static struct osc_extent *osc_extent_alloc(struct osc_object *obj)
{
	struct osc_extent *ext;

	OBD_SLAB_ALLOC_PTR_GFP(ext, osc_extent_kmem, GFP_NOFS);
	if (ext == NULL)
		return NULL;

	RB_CLEAR_NODE(&ext->oe_node);
	ext->oe_obj = obj;
	cl_object_get(osc2cl(obj));
	kref_init(&ext->oe_refc);
	atomic_set(&ext->oe_users, 0);
	INIT_LIST_HEAD(&ext->oe_link);
	ext->oe_state = OES_INV;
	INIT_LIST_HEAD(&ext->oe_pages);
	init_waitqueue_head(&ext->oe_waitq);
	ext->oe_dlmlock = NULL;

	return ext;
}

static void osc_extent_free(struct kref *kref)
{
	struct osc_extent *ext = container_of(kref, struct osc_extent,
					      oe_refc);

	LASSERT(list_empty(&ext->oe_link));
	LASSERT(atomic_read(&ext->oe_users) == 0);
	LASSERT(ext->oe_state == OES_INV);
	LASSERT(RB_EMPTY_NODE(&ext->oe_node));

	if (ext->oe_dlmlock) {
		ldlm_lock_put(ext->oe_dlmlock);
		ext->oe_dlmlock = NULL;
	}
#if 0
	/* If/When cl_object_put drops the need for 'env',
	 * this code can be enabled, and matching code in
	 * osc_extent_put removed.
	 */
	cl_object_put(osc2cl(ext->oe_obj));

	OBD_SLAB_FREE_PTR(ext, osc_extent_kmem);
#endif
}

static struct osc_extent *osc_extent_get(struct osc_extent *ext)
{
	LASSERT(kref_read(&ext->oe_refc) >= 0);
	kref_get(&ext->oe_refc);
	return ext;
}

static void osc_extent_put(const struct lu_env *env, struct osc_extent *ext)
{
	LASSERT(kref_read(&ext->oe_refc) > 0);
	if (kref_put(&ext->oe_refc, osc_extent_free)) {
		/* This should be in osc_extent_free(), but
		 * while we need to pass 'env' it cannot be.
		 */
		cl_object_put(env, osc2cl(ext->oe_obj));

		OBD_SLAB_FREE_PTR(ext, osc_extent_kmem);
	}
}

/**
 * osc_extent_put_trust() is a special version of osc_extent_put() when
 * it's known that the caller is not the last user. This is to address the
 * problem of lacking of lu_env ;-).
 */
static void osc_extent_put_trust(struct osc_extent *ext)
{
	LASSERT(kref_read(&ext->oe_refc) > 1);
	assert_osc_object_is_locked(ext->oe_obj);
	osc_extent_put(NULL, ext);
}

/**
 * Return the extent which includes pgoff @index, or return the greatest
 * previous extent in the tree.
 */
static struct osc_extent *osc_extent_search(struct osc_object *obj,
					    pgoff_t index)
{
	struct rb_node    *n = obj->oo_root.rb_node;
	struct osc_extent *tmp, *p = NULL;

	assert_osc_object_is_locked(obj);
	while (n != NULL) {
		tmp = rb_extent(n);
		if (index < tmp->oe_start) {
			n = n->rb_left;
		} else if (index > tmp->oe_end) {
			p = rb_extent(n);
			n = n->rb_right;
		} else {
			return tmp;
		}
	}
	return p;
}

/*
 * Return the extent covering @index, otherwise return NULL.
 * caller must have held object lock.
 */
static struct osc_extent *osc_extent_lookup(struct osc_object *obj,
					    pgoff_t index)
{
	struct osc_extent *ext;

	ext = osc_extent_search(obj, index);
	if (ext != NULL && ext->oe_start <= index && index <= ext->oe_end)
		return osc_extent_get(ext);
	return NULL;
}

/* caller must have held object lock. */
static void osc_extent_insert(struct osc_object *obj, struct osc_extent *ext)
{
	struct rb_node   **n      = &obj->oo_root.rb_node;
	struct rb_node    *parent = NULL;
	struct osc_extent *tmp;

	LASSERT(RB_EMPTY_NODE(&ext->oe_node));
	LASSERT(ext->oe_obj == obj);
	assert_osc_object_is_locked(obj);
	while (*n != NULL) {
		tmp = rb_extent(*n);
		parent = *n;

		if (ext->oe_end < tmp->oe_start)
			n = &(*n)->rb_left;
		else if (ext->oe_start > tmp->oe_end)
			n = &(*n)->rb_right;
		else
			EASSERTF(0, tmp, EXTSTR"\n", EXTPARA(ext));
	}
	rb_link_node(&ext->oe_node, parent, n);
	rb_insert_color(&ext->oe_node, &obj->oo_root);
	osc_extent_get(ext);
}

/* caller must have held object lock. */
static void osc_extent_erase(struct osc_extent *ext)
{
	struct osc_object *obj = ext->oe_obj;
	assert_osc_object_is_locked(obj);
	if (!RB_EMPTY_NODE(&ext->oe_node)) {
		rb_erase(&ext->oe_node, &obj->oo_root);
		RB_CLEAR_NODE(&ext->oe_node);
		/* rbtree held a refcount */
		osc_extent_put_trust(ext);
	}
}

static struct osc_extent *osc_extent_hold(struct osc_extent *ext)
{
	struct osc_object *obj = ext->oe_obj;

	assert_osc_object_is_locked(obj);
	LASSERT(ext->oe_state == OES_ACTIVE || ext->oe_state == OES_CACHE);
	if (ext->oe_state == OES_CACHE) {
		osc_extent_state_set(ext, OES_ACTIVE);
		osc_update_pending(obj, OBD_BRW_WRITE, -ext->oe_nr_pages);
	}
	atomic_inc(&ext->oe_users);
	list_del_init(&ext->oe_link);
	return osc_extent_get(ext);
}

static void __osc_extent_remove(struct osc_extent *ext)
{
	assert_osc_object_is_locked(ext->oe_obj);
	LASSERT(list_empty(&ext->oe_pages));
	osc_extent_erase(ext);
	list_del_init(&ext->oe_link);
	osc_extent_state_set(ext, OES_INV);
	OSC_EXTENT_DUMP(D_CACHE, ext, "destroyed.\n");
}

static void osc_extent_remove(struct osc_extent *ext)
{
	struct osc_object *obj = ext->oe_obj;

	osc_object_lock(obj);
	__osc_extent_remove(ext);
	osc_object_unlock(obj);
}

/**
 * This function is used to merge extents to get better performance. It checks
 * if @cur and @victim are contiguous at block level.
 */
static int osc_extent_merge(const struct lu_env *env, struct osc_extent *cur,
			    struct osc_extent *victim)
{
	struct osc_object	*obj = cur->oe_obj;
	struct client_obd	*cli = osc_cli(obj);
	pgoff_t			 chunk_start;
	pgoff_t			 chunk_end;
	int			 ppc_bits;

	LASSERT(cur->oe_state == OES_CACHE);
	assert_osc_object_is_locked(obj);
	if (victim == NULL)
		return -EINVAL;

	if (victim->oe_state != OES_INV &&
	    (victim->oe_state != OES_CACHE || victim->oe_fsync_wait))
		return -EBUSY;

	if (cur->oe_max_end != victim->oe_max_end)
		return -ERANGE;

	/*
	 * In the rare case max_pages_per_rpc (mppr) is changed, don't
	 * merge extents until after old ones have been sent, or the
	 * "extents are aligned to RPCs" checks are unhappy.
	 */
	if (cur->oe_mppr != victim->oe_mppr)
		return -ERANGE;

	LASSERT(cur->oe_dlmlock == victim->oe_dlmlock);
	ppc_bits = osc_cli(obj)->cl_chunkbits - PAGE_SHIFT;
	chunk_start = cur->oe_start >> ppc_bits;
	chunk_end   = cur->oe_end   >> ppc_bits;
	if (chunk_start   != (victim->oe_end >> ppc_bits) + 1 &&
	    chunk_end + 1 != victim->oe_start >> ppc_bits)
		return -ERANGE;

	/* overall extent size should not exceed the max supported limit
	 * reported by the server */
	if (cur->oe_end - cur->oe_start + 1 +
	    victim->oe_end - victim->oe_start + 1 > cli->cl_max_extent_pages)
		return -ERANGE;

	OSC_EXTENT_DUMP(D_CACHE, victim, "will be merged by %p.\n", cur);

	cur->oe_start     = min(cur->oe_start, victim->oe_start);
	cur->oe_end       = max(cur->oe_end,   victim->oe_end);
	/* per-extent tax should be accounted only once for the whole extent */
	cur->oe_grants   += victim->oe_grants - cli->cl_grant_extent_tax;
	cur->oe_nr_pages += victim->oe_nr_pages;
	/* only the following bits are needed to merge */
	cur->oe_urgent   |= victim->oe_urgent;
	cur->oe_memalloc |= victim->oe_memalloc;
	list_splice_init(&victim->oe_pages, &cur->oe_pages);
	victim->oe_nr_pages = 0;

	osc_extent_get(victim);
	__osc_extent_remove(victim);
	osc_extent_put(env, victim);

	OSC_EXTENT_DUMP(D_CACHE, cur, "after merging %p.\n", victim);
	return 0;
}

/**
 * Drop user count of osc_extent, and unplug IO asynchronously.
 */
void osc_extent_release(const struct lu_env *env, struct osc_extent *ext,
			enum cl_io_priority prio)
{
	struct osc_object *obj = ext->oe_obj;
	struct client_obd *cli = osc_cli(obj);
	bool hp = cl_io_high_prio(prio);

	ENTRY;

	LASSERT(atomic_read(&ext->oe_users) > 0);
	LASSERT(sanity_check(ext) == 0);
	LASSERT(ext->oe_grants > 0);

	if (atomic_dec_and_lock(&ext->oe_users, &obj->oo_lock)) {
		if (ext->oe_trunc_pending) {
			/*
			 * A truncate process is waiting for this extent.
			 * This may happen due to a race, check
			 * osc_cache_truncate_start().
			 */
			if (ext->oe_state != OES_ACTIVE) {
				int rc;

				osc_object_unlock(obj);
				rc = osc_extent_wait(env, ext, OES_INV);
				if (rc < 0)
					OSC_EXTENT_DUMP(D_ERROR, ext,
							"error: %d.\n", rc);
				osc_object_lock(obj);
			}
			osc_extent_state_set(ext, OES_TRUNC);
			ext->oe_trunc_pending = 0;
			osc_object_unlock(obj);
		} else if (ext->oe_state == OES_ACTIVE) {
			int grant = 0;

			osc_extent_state_set(ext, OES_CACHE);
			osc_update_pending(obj, OBD_BRW_WRITE,
					   ext->oe_nr_pages);

			/* try to merge the previous and next extent. */
			if (osc_extent_merge(env, ext, prev_extent(ext)) == 0)
				grant += cli->cl_grant_extent_tax;
			if (osc_extent_merge(env, ext, next_extent(ext)) == 0)
				grant += cli->cl_grant_extent_tax;

			if (!hp && !ext->oe_rw && ext->oe_dlmlock) {
				lock_res_and_lock(ext->oe_dlmlock);
				hp = ldlm_is_cbpending(ext->oe_dlmlock);
				unlock_res_and_lock(ext->oe_dlmlock);
			}


			/* HP extent should be written ASAP. */
			if (hp)
				ext->oe_hp = 1;

			if (ext->oe_hp)
				list_move_tail(&ext->oe_link,
					       &obj->oo_hp_exts);
			else if (ext->oe_urgent)
				list_move_tail(&ext->oe_link,
					       &obj->oo_urgent_exts);
			else if (ext->oe_nr_pages == ext->oe_mppr) {
				list_move_tail(&ext->oe_link,
					       &obj->oo_full_exts);
			}
			osc_object_unlock(obj);
			if (grant > 0)
				osc_unreserve_grant(cli, 0, grant);
		} else {
			osc_object_unlock(obj);
		}

		if (unlikely(cl_io_high_prio(prio)))
			osc_io_unplug(env, cli, obj);
		else
			osc_io_unplug_async(env, cli, obj);
	}
	osc_extent_put(env, ext);

	RETURN_EXIT;
}

/**
 * Find or create an extent which includes @index, core function to manage
 * extent tree.
 */
static struct osc_extent *osc_extent_find(const struct lu_env *env,
					  struct osc_object *obj, pgoff_t index,
					  unsigned int *grants)
{
	struct client_obd *cli = osc_cli(obj);
	struct osc_lock   *olck;
	struct cl_lock_descr *descr;
	struct osc_extent *cur;
	struct osc_extent *ext;
	struct osc_extent *conflict = NULL;
	struct osc_extent *found = NULL;
	pgoff_t    chunk;
	pgoff_t    max_end;
	unsigned int max_pages; /* max_pages_per_rpc */
	unsigned int chunksize;
	int        ppc_bits; /* pages per chunk bits */
	pgoff_t    chunk_mask;
	int        rc;
	ENTRY;

	cur = osc_extent_alloc(obj);
	if (cur == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	olck = osc_env_io(env)->oi_write_osclock;
	LASSERTF(olck != NULL, "page %lu is not covered by lock\n", index);
	LASSERT(olck->ols_state == OLS_GRANTED);

	descr = &olck->ols_cl.cls_lock->cll_descr;
	LASSERT(descr->cld_mode >= CLM_WRITE);

	LASSERTF(cli->cl_chunkbits >= PAGE_SHIFT,
		 "chunkbits: %u\n", cli->cl_chunkbits);
	ppc_bits   = cli->cl_chunkbits - PAGE_SHIFT;
	chunk_mask = ~((1 << ppc_bits) - 1);
	chunksize  = 1 << cli->cl_chunkbits;
	chunk      = index >> ppc_bits;

	/* align end to RPC edge. */
	max_pages = cli->cl_max_pages_per_rpc;
	if ((max_pages & ~chunk_mask) != 0) {
		CERROR("max_pages: %#x chunkbits: %u chunk_mask: %#lx\n",
		       max_pages, cli->cl_chunkbits, chunk_mask);
		RETURN(ERR_PTR(-EINVAL));
	}
	max_end = index - (index % max_pages) + max_pages - 1;
	max_end = min_t(pgoff_t, max_end, descr->cld_end);

	/* initialize new extent by parameters so far */
	cur->oe_max_end = max_end;
	cur->oe_start   = index & chunk_mask;
	cur->oe_end     = ((index + ~chunk_mask + 1) & chunk_mask) - 1;
	if (cur->oe_start < descr->cld_start)
		cur->oe_start = descr->cld_start;
	if (cur->oe_end > max_end)
		cur->oe_end = max_end;
	cur->oe_grants  = chunksize + cli->cl_grant_extent_tax;
	cur->oe_mppr    = max_pages;
	if (olck->ols_dlmlock != NULL) {
		LASSERT(olck->ols_hold);
		cur->oe_dlmlock = ldlm_lock_get(olck->ols_dlmlock);
	}

	/* grants has been allocated by caller */
	LASSERTF(*grants >= chunksize + cli->cl_grant_extent_tax,
		 "%u/%u/%u.\n", *grants, chunksize, cli->cl_grant_extent_tax);
	LASSERTF((max_end - cur->oe_start) < max_pages, EXTSTR"\n",
		 EXTPARA(cur));

restart:
	osc_object_lock(obj);
	ext = osc_extent_search(obj, cur->oe_start);
	if (!ext)
		ext = first_extent(obj);
	for (; ext; ext = next_extent(ext)) {
		pgoff_t ext_chk_start = ext->oe_start >> ppc_bits;
		pgoff_t ext_chk_end = ext->oe_end >> ppc_bits;

		LASSERT(sanity_check_nolock(ext) == 0);
		if (chunk > ext_chk_end + 1 || chunk < ext_chk_start)
			break;

		/* if covering by different locks, no chance to match */
		if (olck->ols_dlmlock != ext->oe_dlmlock) {
			EASSERTF(!overlapped(ext, cur), ext,
				 EXTSTR"\n", EXTPARA(cur));

			continue;
		}

		/* discontiguous chunks? */
		if (chunk + 1 < ext_chk_start)
			continue;

		/* ok, from now on, ext and cur have these attrs:
		 * 1. covered by the same lock
		 * 2. contiguous at chunk level or overlapping. */

		if (overlapped(ext, cur)) {
			/* cur is the minimum unit, so overlapping means
			 * full contain. */
			EASSERTF((ext->oe_start <= cur->oe_start &&
				  ext->oe_end >= cur->oe_end),
				 ext, EXTSTR"\n", EXTPARA(cur));

			if (ext->oe_state > OES_CACHE || ext->oe_hp ||
			    ext->oe_fsync_wait) {
				/* for simplicity, we wait for this extent to
				 * finish before going forward. */
				conflict = osc_extent_get(ext);
				break;
			}

			found = osc_extent_hold(ext);
			break;
		}

		/* non-overlapped extent */
		if (ext->oe_state != OES_CACHE || ext->oe_hp ||
		    ext->oe_fsync_wait)
			/* we can't do anything for a non OES_CACHE extent, or
			 * if there is someone waiting for this extent to be
			 * flushed, try next one. */
			continue;

		if (osc_extent_merge(env, ext, cur) == 0) {
			LASSERT(*grants >= chunksize);
			*grants -= chunksize;

			/*
			 * Try to merge with the next one too because we
			 * might have just filled in a gap.
			 */
			if (osc_extent_merge(env, ext, next_extent(ext)) == 0)
				/* we can save extent tax from next extent */
				*grants += cli->cl_grant_extent_tax;

			found = osc_extent_hold(ext);
			break;
		}
	}

	osc_extent_tree_dump(D_CACHE, obj);
	if (found != NULL) {
		LASSERT(conflict == NULL);
		if (!IS_ERR(found)) {
			LASSERT(found->oe_dlmlock == cur->oe_dlmlock);
			OSC_EXTENT_DUMP(D_CACHE, found,
					"found caching ext for %lu.\n", index);
		}
	} else if (conflict == NULL) {
		/* create a new extent */
		EASSERT(osc_extent_is_overlapped(obj, cur) == 0, cur);
		LASSERT(*grants >= cur->oe_grants);
		*grants -= cur->oe_grants;

		cur->oe_state = OES_CACHE;
		found = osc_extent_hold(cur);
		osc_extent_insert(obj, cur);
		OSC_EXTENT_DUMP(D_CACHE, cur, "add into tree %lu/%lu.\n",
				index, descr->cld_end);
	}
	osc_object_unlock(obj);

	if (conflict != NULL) {
		LASSERT(found == NULL);

		/* waiting for IO to finish. Please notice that it's impossible
		 * to be an OES_TRUNC extent. */
		rc = osc_extent_wait(env, conflict, OES_INV);
		osc_extent_put(env, conflict);
		conflict = NULL;
		if (rc < 0)
			GOTO(out, found = ERR_PTR(rc));

		goto restart;
	}
	EXIT;

out:
	osc_extent_put(env, cur);
	return found;
}

/**
 * Called when IO is finished to an extent.
 */
int osc_extent_finish(const struct lu_env *env, struct osc_extent *ext,
		      int sent, int rc)
{
	struct client_obd *cli = osc_cli(ext->oe_obj);
	struct osc_object *osc = ext->oe_obj;
	struct osc_async_page *oap;
	struct osc_async_page *tmp;
	int nr_pages = ext->oe_nr_pages;
	int lost_grant = 0;
	int blocksize = cli->cl_import->imp_obd->obd_osfs.os_bsize ? : 4096;
	loff_t last_off = 0;
	int last_count = -1;
	enum cl_req_type crt;
	ENTRY;

	if (ext->oe_rw == 0)
		crt = CRT_WRITE;
	else
		crt = CRT_READ;

	OSC_EXTENT_DUMP(D_CACHE, ext, "extent finished.\n");

	ext->oe_rc = rc ?: ext->oe_nr_pages;
	EASSERT(ergo(rc == 0, ext->oe_state == OES_RPC), ext);

	/* dio pages do not go in the LRU */
	if (!ext->oe_dio)
		osc_lru_add_batch(cli, &ext->oe_pages);

	list_for_each_entry_safe(oap, tmp, &ext->oe_pages,
				     oap_pending_item) {
		list_del_init(&oap->oap_rpc_item);
		list_del_init(&oap->oap_pending_item);
		if (last_off <= oap->oap_obj_off) {
			last_off = oap->oap_obj_off;
			last_count = oap->oap_count;
		}

		--ext->oe_nr_pages;
		osc_completion(env, osc, oap, crt, rc);
	}
	EASSERT(ext->oe_nr_pages == 0, ext);

	if (!sent) {
		lost_grant = ext->oe_grants;
	} else if (cli->cl_ocd_grant_param == 0 &&
		   blocksize < PAGE_SIZE &&
		   last_count != PAGE_SIZE) {
		/* For short writes without OBD_CONNECT_GRANT support, we
		 * shouldn't count parts of pages that span a whole chunk on
		 * the OST side, or our accounting goes wrong. Should match
		 * the code in tgt_grant_check.
		 */
		int offset = last_off & ~PAGE_MASK;
		int count = last_count + (offset & (blocksize - 1));
		int end = (offset + last_count) & (blocksize - 1);
		if (end)
			count += blocksize - end;

		lost_grant = PAGE_SIZE - count;
	}
	if (ext->oe_grants > 0)
		osc_free_grant(cli, nr_pages, lost_grant, ext->oe_grants);

	osc_extent_remove(ext);
	/* put the refcount for RPC */
	osc_extent_put(env, ext);
	RETURN(0);
}

/**
 * Wait for the extent's state to become @state.
 */
static int osc_extent_wait(const struct lu_env *env, struct osc_extent *ext,
			   enum osc_extent_state state)
{
	struct osc_object *obj = ext->oe_obj;
	int rc = 0;
	ENTRY;

	osc_object_lock(obj);
	LASSERT(sanity_check_nolock(ext) == 0);
	/* `Kick' this extent only if the caller is waiting for it to be
	 * written out. */
	if (state == OES_INV && !ext->oe_urgent && !ext->oe_hp) {
		if (ext->oe_state == OES_ACTIVE) {
			ext->oe_urgent = 1;
		} else if (ext->oe_state == OES_CACHE) {
			ext->oe_urgent = 1;
			osc_extent_hold(ext);
			rc = 1;
		}
	}
	osc_object_unlock(obj);
	if (rc == 1)
		osc_extent_release(env, ext, IO_PRIO_NORMAL);

	/* wait for the extent until its state becomes @state */
	rc = wait_event_idle_timeout(ext->oe_waitq,
				     smp_load_acquire(&ext->oe_state) == state,
				     cfs_time_seconds(600));
	if (rc == 0) {
		OSC_EXTENT_DUMP(D_ERROR, ext,
			"%s: wait ext to %u timedout, recovery in progress?\n",
			cli_name(osc_cli(obj)), state);

		wait_event_idle(ext->oe_waitq,
				smp_load_acquire(&ext->oe_state) == state);
	}
	if (ext->oe_rc < 0)
		rc = ext->oe_rc;
	else
		rc = 0;
	RETURN(rc);
}

/**
 * Discard pages with index greater than @size. If @ext is overlapped with
 * @size, then partial truncate happens.
 */
static int osc_extent_truncate(struct osc_extent *ext, pgoff_t trunc_index,
				bool partial)
{
	struct lu_env         *env;
	struct cl_io          *io;
	struct osc_object     *obj = ext->oe_obj;
	struct client_obd     *cli = osc_cli(obj);
	struct osc_async_page *oap;
	struct osc_async_page *tmp;
	struct folio_batch    *fbatch;
	int                    pages_in_chunk = 0;
	int                    ppc_bits    = cli->cl_chunkbits -
					     PAGE_SHIFT;
	__u64                  trunc_chunk = trunc_index >> ppc_bits;
	int                    grants   = 0;
	int                    nr_pages = 0;
	int                    rc       = 0;
	__u16		       refcheck;
	ENTRY;

	LASSERT(sanity_check(ext) == 0);
	LASSERT(ext->oe_state == OES_TRUNC);
	LASSERT(!ext->oe_urgent);

	/* Request new lu_env.
	 * We can't use that env from osc_cache_truncate_start() because
	 * it's from lov_io_sub and not fully initialized. */
	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io  = osc_env_new_io(env);
	io->ci_obj = cl_object_top(osc2cl(obj));
	io->ci_ignore_layout = 1;
	fbatch = &osc_env_info(env)->oti_fbatch;
	ll_folio_batch_init(fbatch, 0);
	rc = cl_io_init(env, io, CIT_MISC, io->ci_obj);
	if (rc < 0)
		GOTO(out, rc);

	/* discard all pages with index greater than trunc_index */
	list_for_each_entry_safe(oap, tmp, &ext->oe_pages,
				     oap_pending_item) {
		pgoff_t index = osc_index(oap2osc(oap));
		struct cl_page  *page = oap2cl_page(oap);

		LASSERT(list_empty(&oap->oap_rpc_item));

		/* only discard the pages with their index greater than
		 * trunc_index, and ... */
		if (index < trunc_index ||
		    (index == trunc_index && partial)) {
			/* accounting how many pages remaining in the chunk
			 * so that we can calculate grants correctly. */
			if (index >> ppc_bits == trunc_chunk)
				++pages_in_chunk;
			continue;
		}

		list_del_init(&oap->oap_pending_item);

		cl_page_get(page);

		if (cl_page_own(env, io, page) == 0) {
			cl_page_discard(env, io, page);
			cl_page_disown(env, io, page);
		} else {
			LASSERT(page->cp_state == CPS_FREEING);
			LASSERT(0);
		}

		cl_batch_put(env, page, fbatch);

		--ext->oe_nr_pages;
		++nr_pages;
	}
	folio_batch_release(fbatch);

	EASSERTF(ergo(ext->oe_start >= trunc_index + !!partial,
		      ext->oe_nr_pages == 0),
		ext, "trunc_index %lu, partial %d\n", trunc_index, partial);

	osc_object_lock(obj);
	if (ext->oe_nr_pages == 0) {
		LASSERT(pages_in_chunk == 0);
		grants = ext->oe_grants;
		ext->oe_grants = 0;
	} else { /* calculate how many grants we can free */
		int     chunks = (ext->oe_end >> ppc_bits) - trunc_chunk;
		pgoff_t last_index;


		/* if there is no pages in this chunk, we can also free grants
		 * for the last chunk */
		if (pages_in_chunk == 0) {
			/* if this is the 1st chunk and no pages in this chunk,
			 * ext->oe_nr_pages must be zero, so we should be in
			 * the other if-clause. */
			LASSERT(trunc_chunk > 0);
			--trunc_chunk;
			++chunks;
		}

		/* this is what we can free from this extent */
		grants          = chunks << cli->cl_chunkbits;
		ext->oe_grants -= grants;
		last_index      = ((trunc_chunk + 1) << ppc_bits) - 1;
		ext->oe_end     = min(last_index, ext->oe_max_end);
		LASSERT(ext->oe_end >= ext->oe_start);
		LASSERT(ext->oe_grants > 0);
	}
	osc_object_unlock(obj);

	if (grants > 0 || nr_pages > 0)
		osc_free_grant(cli, nr_pages, grants, grants);

out:
	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

/**
 * This function is used to make the extent prepared for transfer.
 * A race with flusing page - ll_writepage() has to be handled cautiously.
 */
static int osc_extent_make_ready(const struct lu_env *env,
				 struct osc_extent *ext)
{
	struct osc_async_page *oap;
	struct osc_async_page *last = NULL;
	struct osc_object *obj = ext->oe_obj;
	unsigned int page_count = 0;
	int rc;
	ENTRY;

	/* we're going to grab page lock, so object lock must not be taken. */
	LASSERT(sanity_check(ext) == 0);
	/* in locking state, any process should not touch this extent. */
	EASSERT(ext->oe_state == OES_LOCKING, ext);
	EASSERT(ext->oe_owner != NULL, ext);

	OSC_EXTENT_DUMP(D_CACHE, ext, "make ready\n");

	list_for_each_entry(oap, &ext->oe_pages, oap_pending_item) {
		++page_count;
		if (last == NULL || last->oap_obj_off < oap->oap_obj_off)
			last = oap;

		/* checking ASYNC_READY is race safe */
		if ((oap->oap_async_flags & ASYNC_READY) != 0)
			continue;

		rc = osc_make_ready(env, oap, OBD_BRW_WRITE);
		switch (rc) {
		case 0:
			oap->oap_async_flags |= ASYNC_READY;
			break;
		case -EALREADY:
			LASSERT((oap->oap_async_flags & ASYNC_READY) != 0);
			break;
		default:
			LASSERTF(0, "unknown return code: %d\n", rc);
		}
	}

	LASSERT(page_count == ext->oe_nr_pages);
	LASSERT(last != NULL);
	/* the last page is the only one we need to refresh its count by
	 * the size of file. */
	if (!(last->oap_async_flags & ASYNC_COUNT_STABLE)) {
		int last_oap_count = osc_refresh_count(env, obj, last,
						       OBD_BRW_WRITE);
		LASSERTF(last_oap_count > 0,
			 "last_oap_count %d\n", last_oap_count);
		LASSERT(last->oap_page_off + last_oap_count <= PAGE_SIZE);
		last->oap_count = last_oap_count;
		last->oap_async_flags |= ASYNC_COUNT_STABLE;
	}

	/* for the rest of pages, we don't need to call osf_refresh_count()
	 * because it's known they are not the last page */
	list_for_each_entry(oap, &ext->oe_pages, oap_pending_item) {
		if (!(oap->oap_async_flags & ASYNC_COUNT_STABLE)) {
			oap->oap_count = PAGE_SIZE - oap->oap_page_off;
			oap->oap_async_flags |= ASYNC_COUNT_STABLE;
		}
	}

	osc_object_lock(obj);
	osc_extent_state_set(ext, OES_RPC);
	osc_object_unlock(obj);
	/* get a refcount for RPC. */
	osc_extent_get(ext);

	RETURN(0);
}

/**
 * Quick and simple version of osc_extent_find(). This function is frequently
 * called to expand the extent for the same IO. To expand the extent, the
 * page index must be in the same or next chunk of ext->oe_end.
 */
static int osc_extent_expand(struct osc_extent *ext, pgoff_t index,
			     unsigned int *grants)
{
	struct osc_object *obj = ext->oe_obj;
	struct client_obd *cli = osc_cli(obj);
	struct osc_extent *next;
	int ppc_bits = cli->cl_chunkbits - PAGE_SHIFT;
	pgoff_t chunk = index >> ppc_bits;
	pgoff_t end_chunk;
	pgoff_t end_index;
	unsigned int chunksize = 1 << cli->cl_chunkbits;
	int rc = 0;
	ENTRY;

	LASSERT(ext->oe_max_end >= index && ext->oe_start <= index);
	osc_object_lock(obj);
	if (ext->oe_state != OES_ACTIVE)
		GOTO(out, rc = -ESTALE);

	LASSERT(sanity_check_nolock(ext) == 0);
	end_chunk = ext->oe_end >> ppc_bits;
	if (chunk > end_chunk + 1)
		GOTO(out, rc = -ERANGE);

	if (end_chunk >= chunk)
		GOTO(out, rc = 0);

	LASSERT(end_chunk + 1 == chunk);

	/* try to expand this extent to cover @index */
	end_index = min(ext->oe_max_end, ((chunk + 1) << ppc_bits) - 1);

	/* don't go over the maximum extent size reported by server */
	if (end_index - ext->oe_start + 1 > cli->cl_max_extent_pages)
		GOTO(out, rc = -ERANGE);

	next = next_extent(ext);
	if (next != NULL && next->oe_start <= end_index)
		/* complex mode - overlapped with the next extent,
		 * this case will be handled by osc_extent_find() */
		GOTO(out, rc = -EAGAIN);

	ext->oe_end = end_index;
	ext->oe_grants += chunksize;
	LASSERT(*grants >= chunksize);
	*grants -= chunksize;
	EASSERTF(osc_extent_is_overlapped(obj, ext) == 0, ext,
		 "overlapped after expanding for %lu.\n", index);
	EXIT;

out:
	osc_object_unlock(obj);
	RETURN(rc);
}

static void osc_extent_tree_dump0(int mask, struct osc_object *obj,
				  const char *func, int line)
{
	struct osc_extent *ext;
	int cnt;

	if (!cfs_cdebug_show(mask, DEBUG_SUBSYSTEM))
		return;

	CDEBUG(mask, "Dump object %p extents at %s:%d, mppr: %u.\n",
	       obj, func, line, osc_cli(obj)->cl_max_pages_per_rpc);

	/* osc_object_lock(obj); */
	cnt = 1;
	for (ext = first_extent(obj); ext != NULL; ext = next_extent(ext))
		OSC_EXTENT_DUMP(mask, ext, "in tree %d.\n", cnt++);

	cnt = 1;
	list_for_each_entry(ext, &obj->oo_hp_exts, oe_link)
		OSC_EXTENT_DUMP(mask, ext, "hp %d.\n", cnt++);

	cnt = 1;
	list_for_each_entry(ext, &obj->oo_urgent_exts, oe_link)
		OSC_EXTENT_DUMP(mask, ext, "urgent %d.\n", cnt++);

	cnt = 1;
	list_for_each_entry(ext, &obj->oo_reading_exts, oe_link)
		OSC_EXTENT_DUMP(mask, ext, "reading %d.\n", cnt++);
	/* osc_object_unlock(obj); */
}

/* ------------------ osc extent end ------------------ */

static inline int osc_is_ready(struct osc_object *osc)
{
	return !list_empty(&osc->oo_ready_item) ||
	       !list_empty(&osc->oo_hp_ready_item);
}

#define OSC_IO_DEBUG(OSC, STR, args...)					       \
	CDEBUG(D_CACHE, "obj %p ready %d|%c|%c wr %d|%c|%c rd %d|%c " STR,     \
	       (OSC), osc_is_ready(OSC),				       \
	       list_empty_marker(&(OSC)->oo_hp_ready_item),		       \
	       list_empty_marker(&(OSC)->oo_ready_item),		       \
	       atomic_read(&(OSC)->oo_nr_writes),			       \
	       list_empty_marker(&(OSC)->oo_hp_exts),			       \
	       list_empty_marker(&(OSC)->oo_urgent_exts),		       \
	       atomic_read(&(OSC)->oo_nr_reads),			       \
	       list_empty_marker(&(OSC)->oo_reading_exts),		       \
	       ##args)

static int osc_make_ready(const struct lu_env *env, struct osc_async_page *oap,
			  int cmd)
{
	struct cl_page  *page = oap2cl_page(oap);
	int result;

	LASSERT(cmd == OBD_BRW_WRITE); /* no cached reads */

	ENTRY;

	result = cl_page_make_ready(env, page, CRT_WRITE);

	RETURN(result);
}

static int osc_refresh_count(const struct lu_env *env, struct osc_object *osc,
			     struct osc_async_page *oap, int cmd)
{
	struct osc_page  *opg = oap2osc_page(oap);
	pgoff_t index = osc_index(oap2osc(oap));
	struct cl_object *obj = osc2cl(osc);
	struct cl_attr   *attr = &osc_env_info(env)->oti_attr;
	int result;
	loff_t kms;

	/* readpage queues with _COUNT_STABLE, shouldn't get here. */
	LASSERT(!(cmd & OBD_BRW_READ));
	LASSERT(opg != NULL);

	cl_object_attr_lock(obj);
	result = cl_object_attr_get(env, obj, attr);
	cl_object_attr_unlock(obj);
	if (result < 0)
		return result;
	kms = attr->cat_kms;
	if (index << PAGE_SHIFT >= kms)
		/* catch race with truncate */
		return 0;
	else if ((index + 1) << PAGE_SHIFT > kms)
		/* catch sub-page write at end of file */
		return kms & ~PAGE_MASK;
	else
		return PAGE_SIZE;
}

/* this must be called holding the loi list lock to give coverage to exit_cache,
 * async_flag maintenance
 */
static void osc_completion(const struct lu_env *env, struct osc_object *osc,
			   struct osc_async_page *oap, enum cl_req_type crt,
			   int rc)
{
	struct osc_page   *opg  = oap2osc_page(oap);
	struct cl_page    *page = oap2cl_page(oap);
	int srvlock;
	int cptype = page->cp_type;

	ENTRY;

	if (cptype != CPT_TRANSIENT) {
		/* As the transfer for this page is done, clear the flags */
		oap->oap_async_flags = 0;

		LASSERTF(equi(page->cp_state == CPS_PAGEIN,
			      crt == CRT_READ),
			 "cp_state:%u, crt:%d\n", page->cp_state, crt);
		LASSERTF(equi(page->cp_state == CPS_PAGEOUT,
			      crt == CRT_WRITE),
			"cp_state:%u, crt:%d\n", page->cp_state, crt);
		LASSERT(opg->ops_transfer_pinned);
		/* Clear opg->ops_transfer_pinned before VM lock is released.*/
		opg->ops_transfer_pinned = 0;
	}

	srvlock = oap->oap_brw_flags & OBD_BRW_SRVLOCK;

	/* statistic */
	if (rc == 0 && srvlock) {
		struct lu_device *ld = osc->oo_cl.co_lu.lo_dev;
		struct osc_stats *stats = &lu2osc_dev(ld)->osc_stats;
		size_t bytes = oap->oap_count;

		if (crt == CRT_READ)
			stats->os_lockless_reads += bytes;
		else
			stats->os_lockless_writes += bytes;
	}

	/*
	 * This has to be the last operation with the page, as locks are
	 * released in cl_page_completion() and nothing except for the
	 * reference counter protects page from concurrent reclaim.
	 */

	/* for transient pages, the last reference can be destroyed by
	 * cl_page_complete, so do not reference the page after this
	 */
	cl_page_complete(env, page, crt, rc);
	if (cptype != CPT_TRANSIENT)
		cl_page_put(env, page);

	EXIT;
	return;
}

#define OSC_DUMP_GRANT(mask, cli, fmt, args...) do {			\
	struct client_obd *__tmp = (cli);				\
	CDEBUG(mask, "%s: grant { dirty: %ld/%ld dirty_pages: %ld/%lu "	\
	       "dropped: %ld avail: %ld, dirty_grant: %ld, "		\
	       "reserved: %ld, flight: %d } lru {in list: %ld, "	\
	       "left: %ld, waiters: %d }" fmt "\n",			\
	       cli_name(__tmp),						\
	       __tmp->cl_dirty_pages, __tmp->cl_dirty_max_pages,	\
	       atomic_long_read(&obd_dirty_pages), obd_max_dirty_pages,	\
	       __tmp->cl_lost_grant, __tmp->cl_avail_grant,		\
	       __tmp->cl_dirty_grant,					\
	       __tmp->cl_reserved_grant, __tmp->cl_w_in_flight,		\
	       atomic_long_read(&__tmp->cl_lru_in_list),		\
	       atomic_long_read(&__tmp->cl_lru_busy),			\
	       atomic_read(&__tmp->cl_lru_shrinkers), ##args);		\
} while (0)

/* caller must hold loi_list_lock */
static void osc_consume_write_grant(struct client_obd *cli,
				    struct brw_page *pga)
{
	LASSERT(!(pga->bp_flag & OBD_BRW_FROM_GRANT));
	cli->cl_dirty_pages++;
	pga->bp_flag |= OBD_BRW_FROM_GRANT;
	CDEBUG(D_CACHE, "using %lu grant credits for brw %p page %p\n",
	       PAGE_SIZE, pga, pga->bp_page);
}

/* the companion to osc_consume_write_grant, called when a brw has completed.
 * must be called with the loi lock held. */
static void osc_release_write_grant(struct client_obd *cli,
				    struct brw_page *pga)
{
	ENTRY;

	if (!(pga->bp_flag & OBD_BRW_FROM_GRANT)) {
		EXIT;
		return;
	}

	pga->bp_flag &= ~OBD_BRW_FROM_GRANT;
	atomic_long_dec(&obd_dirty_pages);
	cli->cl_dirty_pages--;
	EXIT;
}

/**
 * To avoid sleeping with object lock held, it's good for us allocate enough
 * grants before entering into critical section.
 *
 * client_obd_list_lock held by caller
 */
static int osc_reserve_grant(struct client_obd *cli, unsigned int bytes)
{
	int rc = -EDQUOT;

	if (cli->cl_avail_grant >= bytes) {
		cli->cl_avail_grant    -= bytes;
		cli->cl_reserved_grant += bytes;
		rc = 0;
	}
	return rc;
}

static void __osc_unreserve_grant(struct client_obd *cli,
				  unsigned int reserved, unsigned int unused)
{
	/* it's quite normal for us to get more grant than reserved.
	 * Thinking about a case that two extents merged by adding a new
	 * chunk, we can save one extent tax. If extent tax is greater than
	 * one chunk, we can save more grant by adding a new chunk */
	cli->cl_reserved_grant -= reserved;
	if (unused > reserved) {
		cli->cl_avail_grant += reserved;
		cli->cl_lost_grant  += unused - reserved;
		cli->cl_dirty_grant -= unused - reserved;
	} else {
		cli->cl_avail_grant += unused;
		cli->cl_dirty_grant += reserved - unused;
	}
}

static void osc_unreserve_grant_nolock(struct client_obd *cli,
				       unsigned int reserved,
				       unsigned int unused)
{
	__osc_unreserve_grant(cli, reserved, unused);
	if (unused > 0)
		osc_wake_cache_waiters(cli);
}

static void osc_unreserve_grant(struct client_obd *cli,
				unsigned int reserved, unsigned int unused)
{
	spin_lock(&cli->cl_loi_list_lock);
	osc_unreserve_grant_nolock(cli, reserved, unused);
	spin_unlock(&cli->cl_loi_list_lock);
}

/**
 * Free grant after IO is finished or canceled.
 *
 * @lost_grant is used to remember how many grants we have allocated but not
 * used, we should return these grants to OST. There're two cases where grants
 * can be lost:
 * 1. truncate;
 * 2. Without OBD_CONNECT_GRANT support and blocksize at OST is less than
 *    PAGE_SIZE and a partial page was written. In this case OST may use less
 *    chunks to serve this partial write. OSTs don't actually know the page
 *    size on the client side. so clients have to calculate lost grant by the
 *    blocksize on the OST. See tgt_grant_check() for details.
 */
static void osc_free_grant(struct client_obd *cli, unsigned int nr_pages,
			   unsigned int lost_grant, unsigned int dirty_grant)
{
	unsigned long grant;

	grant = (1 << cli->cl_chunkbits) + cli->cl_grant_extent_tax;

	spin_lock(&cli->cl_loi_list_lock);
	atomic_long_sub(nr_pages, &obd_dirty_pages);
	cli->cl_dirty_pages -= nr_pages;
	cli->cl_lost_grant += lost_grant;
	cli->cl_dirty_grant -= dirty_grant;
	if (cli->cl_avail_grant < grant && cli->cl_lost_grant >= grant) {
		/* borrow some grant from truncate to avoid the case that
		 * truncate uses up all avail grant */
		cli->cl_lost_grant -= grant;
		cli->cl_avail_grant += grant;
	}
	osc_wake_cache_waiters(cli);
	spin_unlock(&cli->cl_loi_list_lock);
	CDEBUG(D_CACHE, "lost %u grant: %lu avail: %lu dirty: %lu/%lu\n",
	       lost_grant, cli->cl_lost_grant,
	       cli->cl_avail_grant, cli->cl_dirty_pages << PAGE_SHIFT,
	       cli->cl_dirty_grant);
}

/**
 * The companion to osc_enter_cache(), called when @oap is no longer part of
 * the dirty accounting due to error.
 */
static void osc_exit_cache(struct client_obd *cli, struct osc_async_page *oap)
{
	spin_lock(&cli->cl_loi_list_lock);
	osc_release_write_grant(cli, &oap->oap_brw_page);
	spin_unlock(&cli->cl_loi_list_lock);
}

/**
 * Non-blocking version of osc_enter_cache() that consumes grant only when it
 * is available.
 */
static int osc_enter_cache_try(struct client_obd *cli,
			       struct osc_async_page *oap,
			       int bytes)
{
	int rc;

	OSC_DUMP_GRANT(D_CACHE, cli, "need:%d", bytes);

	rc = osc_reserve_grant(cli, bytes);
	if (rc < 0)
		return 0;

	if (cli->cl_dirty_pages < cli->cl_dirty_max_pages) {
		if (atomic_long_add_return(1, &obd_dirty_pages) <=
		    obd_max_dirty_pages) {
			osc_consume_write_grant(cli, &oap->oap_brw_page);
			rc = 1;
			goto out;
		} else
			atomic_long_dec(&obd_dirty_pages);
	}
	__osc_unreserve_grant(cli, bytes, bytes);

out:
	return rc;
}

/* Following two inlines exist to pass code fragments
 * to wait_event_idle_exclusive_timeout_cmd().  Passing
 * code fragments as macro args can look confusing, so
 * we provide inlines to encapsulate them.
 */
static inline void cli_unlock_and_unplug(const struct lu_env *env,
					 struct client_obd *cli,
					 struct osc_async_page *oap)
{
	spin_unlock(&cli->cl_loi_list_lock);
	osc_io_unplug_async(env, cli, NULL);
	CDEBUG(D_CACHE,
	       "%s: sleeping for cache space for %p\n",
	       cli_name(cli), oap);
}

static inline void cli_lock_after_unplug(struct client_obd *cli)
{
	spin_lock(&cli->cl_loi_list_lock);
}
/**
 * The main entry to reserve dirty page accounting. Usually the grant reserved
 * in this function will be freed in bulk in osc_free_grant() unless it fails
 * to add osc cache, in that case, it will be freed in osc_exit_cache().
 *
 * The process will be put into sleep if it's already run out of grant.
 */
static int osc_enter_cache(const struct lu_env *env, struct client_obd *cli,
			   struct osc_object *osc, struct osc_async_page *oap,
			   int bytes)
{
	struct lov_oinfo *loi = osc->oo_oinfo;
	int rc = -EDQUOT;
	int remain;
	bool entered = false;
	struct obd_device *obd = cli->cl_import->imp_obd;
	/* We cannot wait for a long time here since we are holding ldlm lock
	 * across the actual IO. If no requests complete fast (e.g. due to
	 * overloaded OST that takes a long time to process everything, we'd
	 * get evicted if we wait for a normal obd_timeout or some such.
	 * So we try to wait half the time it would take the client to be
	 * evicted by server which is half obd_timeout when AT is off
	 * or at least ldlm_enqueue_min with AT on.
	 * See LU-13131 */
	unsigned long timeout =
		cfs_time_seconds(obd_at_off(obd) ?
				 obd_timeout / 2 :
				 obd_get_ldlm_enqueue_min(obd) / 2);

	ENTRY;

	OSC_DUMP_GRANT(D_CACHE, cli, "need:%d", bytes);

	spin_lock(&cli->cl_loi_list_lock);

	/* force the caller to try sync io.  this can jump the list
	 * of queued writes and create a discontiguous rpc stream */
	if (CFS_FAIL_CHECK(OBD_FAIL_OSC_NO_GRANT) ||
	    cli->cl_dirty_max_pages == 0 ||
	    cli->cl_ar.ar_force_sync || loi->loi_ar.ar_force_sync) {
		OSC_DUMP_GRANT(D_CACHE, cli, "forced sync i/o");
		GOTO(out, rc = -EDQUOT);
	}

	/*
	 * We can wait here for two reasons: too many dirty pages in cache, or
	 * run out of grants. In both cases we should write dirty pages out.
	 * Adding a cache waiter will trigger urgent write-out no matter what
	 * RPC size will be.
	 * The exiting condition (other than success) is no avail grants
	 * and no dirty pages caching, that really means there is no space
	 * on the OST.
	 */
	remain = wait_event_idle_exclusive_timeout_cmd(
		cli->cl_cache_waiters,
		(entered = osc_enter_cache_try(cli, oap, bytes)) ||
		(cli->cl_dirty_pages == 0 && cli->cl_w_in_flight == 0),
		timeout,
		cli_unlock_and_unplug(env, cli, oap),
		cli_lock_after_unplug(cli));

	if (entered) {
		if (remain == timeout)
			OSC_DUMP_GRANT(D_CACHE, cli, "granted from cache");
		else
			OSC_DUMP_GRANT(D_CACHE, cli,
				       "finally got grant space");
		wake_up(&cli->cl_cache_waiters);
		rc = 0;
	} else if (remain == 0) {
		OSC_DUMP_GRANT(D_CACHE, cli,
			       "timeout, fall back to sync i/o");
		osc_extent_tree_dump(D_CACHE, osc);
		/* fall back to synchronous I/O */
	} else {
		OSC_DUMP_GRANT(D_CACHE, cli,
			       "no grant space, fall back to sync i/o");
		wake_up_all(&cli->cl_cache_waiters);
	}
	EXIT;
out:
	spin_unlock(&cli->cl_loi_list_lock);
	RETURN(rc);
}

static int osc_max_rpc_in_flight(struct client_obd *cli, struct osc_object *osc)
{
	int hprpc = !!list_empty(&osc->oo_hp_exts);
	return rpcs_in_flight(cli) >= cli->cl_max_rpcs_in_flight + hprpc;
}

/* Check whether all I/O RPC slots are used out by parallel DIO. */
static inline bool osc_full_dio_in_flight(struct client_obd *cli)
{
	__u32 rpcs = rpcs_in_flight(cli);

	return rpcs >= cli->cl_max_rpcs_in_flight &&
	       rpcs <= cli->cl_d_in_flight;
}

/* This maintains the lists of pending pages to read/write for a given object
 * (lop).  This is used by osc_check_rpcs->osc_next_obj() and osc_list_maint()
 * to quickly find objects that are ready to send an RPC. */
static int osc_makes_rpc(struct client_obd *cli, struct osc_object *osc,
			 int cmd)
{
	int invalid_import = 0;
	ENTRY;

	/* if we have an invalid import we want to drain the queued pages
	 * by forcing them through rpcs that immediately fail and complete
	 * the pages.  recovery relies on this to empty the queued pages
	 * before canceling the locks and evicting down the llite pages */
	if ((cli->cl_import == NULL || cli->cl_import->imp_invalid))
		invalid_import = 1;

	if (cmd & OBD_BRW_WRITE) {
		if (atomic_read(&osc->oo_nr_writes) == 0)
			RETURN(0);
		if (invalid_import) {
			CDEBUG(D_CACHE, "invalid import forcing RPC\n");
			RETURN(1);
		}
		if (!list_empty(&osc->oo_hp_exts)) {
			CDEBUG(D_CACHE, "high prio request forcing RPC\n");
			RETURN(1);
		}
		if (!list_empty(&osc->oo_urgent_exts)) {
			CDEBUG(D_CACHE, "urgent request forcing RPC\n");
			RETURN(1);
		}
		/* trigger a write rpc stream as long as there are dirtiers
		 * waiting for space.  as they're waiting, they're not going to
		 * create more pages to coalesce with what's waiting..
		 */
		if (waitqueue_active(&cli->cl_cache_waiters)) {
			CDEBUG(D_CACHE, "cache waiters forcing RPC\n");
			RETURN(1);
		}
		if (!list_empty(&osc->oo_full_exts)) {
			CDEBUG(D_CACHE, "full extent ready, make an RPC\n");
			RETURN(1);
		}
	} else {
		if (atomic_read(&osc->oo_nr_reads) == 0)
			RETURN(0);
		if (invalid_import) {
			CDEBUG(D_CACHE, "invalid import forcing RPC\n");
			RETURN(1);
		}
		if (!list_empty(&osc->oo_hp_read_exts)) {
			CDEBUG(D_CACHE, "high prio read request forcing RPC\n");
			RETURN(1);
		}
		/* all read are urgent. */
		if (!list_empty(&osc->oo_reading_exts))
			RETURN(1);
	}

	RETURN(0);
}

static void osc_update_pending(struct osc_object *obj, int cmd, int delta)
{
	struct client_obd *cli = osc_cli(obj);
	if (cmd & OBD_BRW_WRITE) {
		atomic_add(delta, &obj->oo_nr_writes);
		atomic_add(delta, &cli->cl_pending_w_pages);
		LASSERT(atomic_read(&obj->oo_nr_writes) >= 0);
	} else {
		atomic_add(delta, &obj->oo_nr_reads);
		atomic_add(delta, &cli->cl_pending_r_pages);
		LASSERT(atomic_read(&obj->oo_nr_reads) >= 0);
	}
	OSC_IO_DEBUG(obj, "update pending cmd %d delta %d.\n", cmd, delta);
}

static bool osc_makes_hprpc(struct osc_object *obj)
{
	return !list_empty(&obj->oo_hp_exts) ||
	       !list_empty(&obj->oo_hp_read_exts);
}

static void on_list(struct list_head *item, struct list_head *list,
		    int should_be_on)
{
	if (list_empty(item) && should_be_on)
		list_add_tail(item, list);
	else if (!list_empty(item) && !should_be_on)
		list_del_init(item);
}

/* maintain the osc's cli list membership invariants so that osc_send_oap_rpc
 * can find pages to build into rpcs quickly */
static int __osc_list_maint(struct client_obd *cli, struct osc_object *osc)
{
	if (osc_makes_hprpc(osc)) {
		/* HP rpc */
		on_list(&osc->oo_ready_item, &cli->cl_loi_ready_list, 0);
		on_list(&osc->oo_hp_ready_item, &cli->cl_loi_hp_ready_list, 1);
	} else {
		on_list(&osc->oo_hp_ready_item, &cli->cl_loi_hp_ready_list, 0);
		on_list(&osc->oo_ready_item, &cli->cl_loi_ready_list,
			osc_makes_rpc(cli, osc, OBD_BRW_WRITE) ||
			osc_makes_rpc(cli, osc, OBD_BRW_READ));
	}

	on_list(&osc->oo_write_item, &cli->cl_loi_write_list,
		atomic_read(&osc->oo_nr_writes) > 0);

	on_list(&osc->oo_read_item, &cli->cl_loi_read_list,
		atomic_read(&osc->oo_nr_reads) > 0);

	return osc_is_ready(osc);
}

static int osc_list_maint(struct client_obd *cli, struct osc_object *osc)
{
	int is_ready;

	spin_lock(&cli->cl_loi_list_lock);
	is_ready = __osc_list_maint(cli, osc);
	spin_unlock(&cli->cl_loi_list_lock);

	return is_ready;
}

struct extent_rpc_data {
	struct list_head	*erd_rpc_list;
	unsigned int		erd_page_count;
	unsigned int		erd_max_pages;
	unsigned int		erd_max_chunks;
	unsigned int		erd_max_extents;
};

static inline unsigned osc_extent_chunks(const struct osc_extent *ext)
{
	struct client_obd *cli = osc_cli(ext->oe_obj);
	unsigned ppc_bits = cli->cl_chunkbits - PAGE_SHIFT;

	return (ext->oe_end >> ppc_bits) - (ext->oe_start >> ppc_bits) + 1;
}

static inline bool
can_merge(const struct osc_extent *ext, const struct osc_extent *in_rpc)
{
	if (ext->oe_no_merge || in_rpc->oe_no_merge)
		return false;

	if (ext->oe_srvlock != in_rpc->oe_srvlock)
		return false;

	if (ext->oe_ndelay != in_rpc->oe_ndelay)
		return false;

	if (!ext->oe_grants != !in_rpc->oe_grants)
		return false;

	if (ext->oe_dio != in_rpc->oe_dio)
		return false;

	/* It's possible to have overlap on DIO */
	if (in_rpc->oe_dio && overlapped(ext, in_rpc))
		return false;

	if (ext->oe_is_rdma_only != in_rpc->oe_is_rdma_only)
		return false;

	return true;
}

/**
 * Try to add extent to one RPC. We need to think about the following things:
 * - # of pages must not be over max_pages_per_rpc
 * - extent must be compatible with previous ones
 */
static int try_to_add_extent_for_io(struct client_obd *cli,
				    struct osc_extent *ext,
				    struct extent_rpc_data *data)
{
	struct osc_extent *tmp;
	unsigned int chunk_count;
	ENTRY;

	EASSERT((ext->oe_state == OES_CACHE || ext->oe_state == OES_LOCK_DONE),
		ext);
	OSC_EXTENT_DUMP(D_CACHE, ext, "trying to add this extent\n");

	if (data->erd_max_extents == 0)
		RETURN(0);

	chunk_count = osc_extent_chunks(ext);
	EASSERTF(data->erd_page_count != 0 ||
		 chunk_count <= data->erd_max_chunks, ext,
		 "The first extent to be fit in a RPC contains %u chunks, "
		 "which is over the limit %u.\n", chunk_count,
		 data->erd_max_chunks);
	if (chunk_count > data->erd_max_chunks)
		RETURN(0);

	data->erd_max_pages = max(ext->oe_mppr, data->erd_max_pages);
	EASSERTF(data->erd_page_count != 0 ||
		ext->oe_nr_pages <= data->erd_max_pages, ext,
		"The first extent to be fit in a RPC contains %u pages, "
		"which is over the limit %u.\n", ext->oe_nr_pages,
		data->erd_max_pages);
	if (data->erd_page_count + ext->oe_nr_pages > data->erd_max_pages)
		RETURN(0);

	list_for_each_entry(tmp, data->erd_rpc_list, oe_link) {
		EASSERT(tmp->oe_owner == current, tmp);

		if (!can_merge(ext, tmp))
			RETURN(0);
	}

	data->erd_max_extents--;
	data->erd_max_chunks -= chunk_count;
	data->erd_page_count += ext->oe_nr_pages;
	list_move_tail(&ext->oe_link, data->erd_rpc_list);
	ext->oe_owner = current;
	RETURN(1);
}

/**
 * In order to prevent multiple ptlrpcd from breaking contiguous extents,
 * get_write_extent() takes all appropriate extents in atomic.
 *
 * The following policy is used to collect extents for IO:
 * 1. Add as many HP extents as possible;
 * 2. Add the first urgent extent in urgent extent list and take it out of
 *    urgent list;
 * 3. Add subsequent extents of this urgent extent;
 * 4. If urgent list is not empty, goto 2;
 * 5. Traverse the extent tree from the 1st extent;
 * 6. Above steps exit if there is no space in this RPC.
 */
static unsigned int get_write_extents(struct osc_object *obj,
				      struct list_head *rpclist)
{
	struct client_obd *cli = osc_cli(obj);
	struct osc_extent *ext;
	struct extent_rpc_data data = {
		.erd_rpc_list	= rpclist,
		.erd_page_count	= 0,
		.erd_max_pages	= cli->cl_max_pages_per_rpc,
		.erd_max_chunks	= osc_max_write_chunks(cli),
		.erd_max_extents = 256,
	};

	assert_osc_object_is_locked(obj);
	while ((ext = list_first_entry_or_null(&obj->oo_hp_exts,
					       struct osc_extent,
					       oe_link)) != NULL) {
		if (!try_to_add_extent_for_io(cli, ext, &data))
			return data.erd_page_count;
		EASSERT(ext->oe_nr_pages <= data.erd_max_pages, ext);
	}
	if (data.erd_page_count == data.erd_max_pages)
		return data.erd_page_count;

	while ((ext = list_first_entry_or_null(&obj->oo_urgent_exts,
					       struct osc_extent,
					       oe_link)) != NULL) {
		if (!try_to_add_extent_for_io(cli, ext, &data))
			return data.erd_page_count;
	}
	if (data.erd_page_count == data.erd_max_pages)
		return data.erd_page_count;

	/* One key difference between full extents and other extents: full
	 * extents can usually only be added if the rpclist was empty, so if we
	 * can't add one, we continue on to trying to add normal extents.  This
	 * is so we don't miss adding extra extents to an RPC containing high
	 * priority or urgent extents.
	 */
	while ((ext = list_first_entry_or_null(&obj->oo_full_exts,
					       struct osc_extent,
					       oe_link)) != NULL) {
		if (!try_to_add_extent_for_io(cli, ext, &data))
			break;
	}
	if (data.erd_page_count == data.erd_max_pages)
		return data.erd_page_count;

	for (ext = first_extent(obj);
	     ext;
	     ext = next_extent(ext)) {
		if ((ext->oe_state != OES_CACHE) ||
		    /* this extent may be already in current rpclist */
		    (!list_empty(&ext->oe_link) && ext->oe_owner))
			continue;

		if (!try_to_add_extent_for_io(cli, ext, &data))
			return data.erd_page_count;
	}
	return data.erd_page_count;
}

static int
osc_send_write_rpc(const struct lu_env *env, struct client_obd *cli,
		   struct osc_object *osc)
__must_hold(osc)
{
	LIST_HEAD(rpclist);
	struct osc_extent *ext;
	struct osc_extent *tmp;
	struct osc_extent *first = NULL;
	unsigned int page_count = 0;
	int srvlock = 0;
	int rc = 0;
	ENTRY;

	assert_osc_object_is_locked(osc);

	page_count = get_write_extents(osc, &rpclist);
	LASSERT(equi(page_count == 0, list_empty(&rpclist)));

	if (list_empty(&rpclist))
		RETURN(0);

	osc_update_pending(osc, OBD_BRW_WRITE, -page_count);

	list_for_each_entry(ext, &rpclist, oe_link) {
		LASSERT(ext->oe_state == OES_CACHE ||
			ext->oe_state == OES_LOCK_DONE);
		if (ext->oe_state == OES_CACHE)
			osc_extent_state_set(ext, OES_LOCKING);
		else
			osc_extent_state_set(ext, OES_RPC);
	}

	/* we're going to grab page lock, so release object lock because
	 * lock order is page lock -> object lock. */
	osc_object_unlock(osc);

	list_for_each_entry_safe(ext, tmp, &rpclist, oe_link) {
		if (ext->oe_state == OES_LOCKING) {
			rc = osc_extent_make_ready(env, ext);
			if (unlikely(rc < 0)) {
				list_del_init(&ext->oe_link);
				osc_extent_finish(env, ext, 0, rc);
				continue;
			}
		}
		if (first == NULL) {
			first = ext;
			srvlock = ext->oe_srvlock;
		} else {
			LASSERT(srvlock == ext->oe_srvlock);
		}
	}

	if (!list_empty(&rpclist)) {
		LASSERT(page_count > 0);
		rc = osc_build_rpc(env, cli, &rpclist, OBD_BRW_WRITE);
		LASSERT(list_empty(&rpclist));
	}

	osc_object_lock(osc);
	RETURN(rc);
}

static unsigned int get_read_extents(struct osc_object *obj,
				     struct list_head *rpclist)
{
	struct client_obd *cli = osc_cli(obj);
	struct osc_extent *ext;
	struct osc_extent *next;
	struct extent_rpc_data data = {
		.erd_rpc_list	= rpclist,
		.erd_page_count	= 0,
		.erd_max_pages	= cli->cl_max_pages_per_rpc,
		.erd_max_chunks	= UINT_MAX,
		.erd_max_extents = UINT_MAX,
	};

	assert_osc_object_is_locked(obj);
	while ((ext = list_first_entry_or_null(&obj->oo_hp_read_exts,
					       struct osc_extent,
					       oe_link)) != NULL) {
		EASSERT(ext->oe_state == OES_LOCK_DONE, ext);
		if (!try_to_add_extent_for_io(cli, ext, &data))
			return data.erd_page_count;
		osc_extent_state_set(ext, OES_RPC);
		EASSERT(ext->oe_nr_pages <= data.erd_max_pages, ext);
	}
	if (data.erd_page_count == data.erd_max_pages)
		return data.erd_page_count;

	list_for_each_entry_safe(ext, next, &obj->oo_reading_exts, oe_link) {
		EASSERT(ext->oe_state == OES_LOCK_DONE, ext);
		if (!try_to_add_extent_for_io(cli, ext, &data))
			break;
		osc_extent_state_set(ext, OES_RPC);
		EASSERT(ext->oe_nr_pages <= data.erd_max_pages, ext);
	}

	LASSERT(data.erd_page_count <= data.erd_max_pages);
	return data.erd_page_count;
}

/**
 * prepare pages for ASYNC io and put pages in send queue.
 *
 * \param cmd OBD_BRW_* macroses
 * \param lop pending pages
 *
 * \return zero if no page added to send queue.
 * \return 1 if pages successfully added to send queue.
 * \return negative on errors.
 */
static int
osc_send_read_rpc(const struct lu_env *env, struct client_obd *cli,
		  struct osc_object *osc)
__must_hold(osc)
{
	LIST_HEAD(rpclist);
	unsigned int page_count;
	int rc = 0;

	ENTRY;

	assert_osc_object_is_locked(osc);
	page_count = get_read_extents(osc, &rpclist);

	osc_update_pending(osc, OBD_BRW_READ, -page_count);

	if (!list_empty(&rpclist)) {
		osc_object_unlock(osc);

		rc = osc_build_rpc(env, cli, &rpclist, OBD_BRW_READ);
		LASSERT(list_empty(&rpclist));

		osc_object_lock(osc);
	}
	RETURN(rc);
}

#define list_to_obj(list, item) ({					      \
	struct list_head *__tmp = (list)->next;				      \
	list_del_init(__tmp);					      \
	list_entry(__tmp, struct osc_object, oo_##item);		      \
})

/* This is called by osc_check_rpcs() to find which objects have pages that
 * we could be sending.  These lists are maintained by osc_makes_rpc(). */
static struct osc_object *osc_next_obj(struct client_obd *cli)
{
	ENTRY;

	/* First return objects that have blocked locks so that they
	 * will be flushed quickly and other clients can get the lock,
	 * then objects which have pages ready to be stuffed into RPCs */
	if (!list_empty(&cli->cl_loi_hp_ready_list))
		RETURN(list_to_obj(&cli->cl_loi_hp_ready_list, hp_ready_item));
	if (!list_empty(&cli->cl_loi_ready_list))
		RETURN(list_to_obj(&cli->cl_loi_ready_list, ready_item));

	/* then if we have cache waiters, return all objects with queued
	 * writes.  This is especially important when many small files
	 * have filled up the cache and not been fired into rpcs because
	 * they don't pass the nr_pending/object threshhold
	 */
	if (waitqueue_active(&cli->cl_cache_waiters) &&
	    !list_empty(&cli->cl_loi_write_list))
		RETURN(list_to_obj(&cli->cl_loi_write_list, write_item));

	/* then return all queued objects when we have an invalid import
	 * so that they get flushed */
	if (cli->cl_import == NULL || cli->cl_import->imp_invalid) {
		if (!list_empty(&cli->cl_loi_write_list))
			RETURN(list_to_obj(&cli->cl_loi_write_list,
					   write_item));
		if (!list_empty(&cli->cl_loi_read_list))
			RETURN(list_to_obj(&cli->cl_loi_read_list,
					   read_item));
	}
	RETURN(NULL);
}

/* called with the loi list lock held */
static void osc_check_rpcs(const struct lu_env *env, struct client_obd *cli)
__must_hold(&cli->cl_loi_list_lock)
{
	struct osc_object *osc;
	int rc = 0;
	ENTRY;

	while ((osc = osc_next_obj(cli)) != NULL) {
		struct cl_object *obj = osc2cl(osc);

		OSC_IO_DEBUG(osc, "%lu in flight\n", rpcs_in_flight(cli));

		/* even if we have reached our max in flight RPCs, we still
		 * allow all high-priority RPCs through to prevent their
		 * starvation and leading to server evicting us for not
		 * writing out pages in a timely manner LU-13131 */
		if (osc_max_rpc_in_flight(cli, osc) &&
		    list_empty(&osc->oo_hp_exts) &&
		    list_empty(&osc->oo_hp_read_exts)) {
			__osc_list_maint(cli, osc);
			break;
		}

		cl_object_get(obj);
		spin_unlock(&cli->cl_loi_list_lock);

		/* attempt some read/write balancing by alternating between
		 * reads and writes in an object.  The makes_rpc checks here
		 * would be redundant if we were getting read/write work items
		 * instead of objects.  we don't want send_oap_rpc to drain a
		 * partial read pending queue when we're given this object to
		 * do io on writes while there are cache waiters */
		osc_object_lock(osc);
		if (osc_makes_rpc(cli, osc, OBD_BRW_WRITE)) {
			rc = osc_send_write_rpc(env, cli, osc);
			if (rc < 0) {
				CERROR("Write request failed with %d\n", rc);

				/* osc_send_write_rpc failed, mostly because of
				 * memory pressure.
				 *
				 * It can't break here, because if:
				 *  - a page was submitted by osc_io_submit, so
				 *    page locked;
				 *  - no request in flight
				 *  - no subsequent request
				 * The system will be in live-lock state,
				 * because there is no chance to call
				 * osc_io_unplug() and osc_check_rpcs() any
				 * more. pdflush can't help in this case,
				 * because it might be blocked at grabbing
				 * the page lock as we mentioned.
				 *
				 * Anyway, continue to drain pages. */
				/* break; */
			}
		}
		if (osc_makes_rpc(cli, osc, OBD_BRW_READ)) {
			rc = osc_send_read_rpc(env, cli, osc);
			if (rc < 0)
				CERROR("Read request failed with %d\n", rc);
		}
		osc_object_unlock(osc);

		osc_list_maint(cli, osc);
		cl_object_put(env, obj);

		spin_lock(&cli->cl_loi_list_lock);
	}
	EXIT;
}

int osc_io_unplug0(const struct lu_env *env, struct client_obd *cli,
		   struct osc_object *osc, int async)
{
	int rc = 0;

	if (osc != NULL && osc_list_maint(cli, osc) == 0)
		return 0;

	if (!async) {
		spin_lock(&cli->cl_loi_list_lock);
		osc_check_rpcs(env, cli);
		spin_unlock(&cli->cl_loi_list_lock);
	} else {
		CDEBUG(D_CACHE, "Queue writeback work for client %p.\n", cli);
		LASSERT(cli->cl_writeback_work != NULL);
		rc = ptlrpcd_queue_work(cli->cl_writeback_work);
	}
	return rc;
}
EXPORT_SYMBOL(osc_io_unplug0);

int osc_prep_async_page(struct osc_object *osc, struct osc_page *ops,
			struct cl_page *page, loff_t offset)
{
	struct osc_async_page *oap = &ops->ops_oap;

	ENTRY;
	if (!page)
		return round_up(sizeof(*oap), 8);

	oap->oap_obj = osc;
	oap->oap_page = page->cp_vmpage;
	oap->oap_obj_off = offset;
	LASSERT(!(offset & ~PAGE_MASK));

	/* Count of transient (direct i/o) pages is always stable by the time
	 * they're submitted.  Setting this here lets us avoid calling
	 * cl_page_clip later to set this.
	 */
	if (page->cp_type == CPT_TRANSIENT)
		oap->oap_async_flags |= ASYNC_COUNT_STABLE|ASYNC_URGENT|
					ASYNC_READY;

	INIT_LIST_HEAD(&oap->oap_pending_item);
	INIT_LIST_HEAD(&oap->oap_rpc_item);

	CDEBUG(D_INFO, "oap %p vmpage %p obj off %llu\n",
	       oap, oap->oap_page, oap->oap_obj_off);
	RETURN(0);
}
EXPORT_SYMBOL(osc_prep_async_page);

int osc_queue_async_io(const struct lu_env *env, struct cl_io *io,
		       struct osc_object *osc, struct osc_page *ops,
		       cl_commit_cbt cb)
{
	struct osc_io *oio = osc_env_io(env);
	struct osc_extent     *ext = NULL;
	struct osc_async_page *oap = &ops->ops_oap;
	struct client_obd     *cli = osc_cli(osc);
	struct folio_batch    *fbatch = &osc_env_info(env)->oti_fbatch;
	pgoff_t index;
	unsigned int tmp;
	unsigned int grants = 0;
	u32    brw_flags = OBD_BRW_ASYNC;
	int    cmd = OBD_BRW_WRITE;
	int    need_release = 0;
	int    rc = 0;
	ENTRY;

	if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
		RETURN(-EIO);

	if (!list_empty(&oap->oap_pending_item) ||
	    !list_empty(&oap->oap_rpc_item))
		RETURN(-EBUSY);

	/* Set the OBD_BRW_SRVLOCK before the page is queued. */
	brw_flags |= ops->ops_srvlock ? OBD_BRW_SRVLOCK : 0;
	if (io->ci_noquota) {
		brw_flags |= OBD_BRW_NOQUOTA;
		cmd |= OBD_BRW_NOQUOTA;
	}

	if (oio->oi_cap_sys_resource) {
		brw_flags |= OBD_BRW_SYS_RESOURCE;
		cmd |= OBD_BRW_SYS_RESOURCE;
	}

	/* check if the file's owner/group is over quota */
	/* do not check for root without root squash, because in this case
	 * we should bypass quota
	 */
	if ((!oio->oi_cap_sys_resource ||
	     cli->cl_root_squash || cli->cl_root_prjquota) &&
	    !io->ci_noquota) {
		struct cl_object *obj;
		struct cl_attr   *attr;
		unsigned int qid[LL_MAXQUOTAS];

		obj = cl_object_top(&osc->oo_cl);
		attr = &osc_env_info(env)->oti_attr;

		cl_object_attr_lock(obj);
		rc = cl_object_attr_get(env, obj, attr);
		cl_object_attr_unlock(obj);

		qid[USRQUOTA] = attr->cat_uid;
		qid[GRPQUOTA] = attr->cat_gid;
		qid[PRJQUOTA] = attr->cat_projid;
		if (rc == 0 && osc_quota_chkdq(cli, qid) == -EDQUOT)
			rc = -EDQUOT;
		if (rc)
			RETURN(rc);
	}

	oap->oap_cmd = cmd;
	oap->oap_page_off = ops->ops_from;
	oap->oap_count = ops->ops_to - ops->ops_from + 1;
	/* No need to hold a lock here,
	 * since this page is not in any list yet. */
	oap->oap_async_flags = 0;
	oap->oap_brw_flags = brw_flags;

	OSC_IO_DEBUG(osc, "oap %p page %p added for cmd %d\n",
		     oap, oap->oap_page, oap->oap_cmd & OBD_BRW_RWMASK);

	index = osc_index(oap2osc(oap));

	/* Add this page into extent by the following steps:
	 * 1. if there exists an active extent for this IO, mostly this page
	 *    can be added to the active extent and sometimes we need to
	 *    expand extent to accomodate this page;
	 * 2. otherwise, a new extent will be allocated. */

	ext = oio->oi_active;
	if (ext != NULL && ext->oe_state != OES_ACTIVE) {
		need_release = 1;
	} else if (ext != NULL && ext->oe_start <= index &&
		   ext->oe_max_end >= index) {
		/* one chunk plus extent overhead must be enough to write this
		 * page */
		grants = (1 << cli->cl_chunkbits) + cli->cl_grant_extent_tax;
		if (ext->oe_end >= index)
			grants = 0;

		/* it doesn't need any grant to dirty this page */
		spin_lock(&cli->cl_loi_list_lock);
		rc = osc_enter_cache_try(cli, oap, grants);
		if (rc == 0) { /* try failed */
			grants = 0;
			need_release = 1;
		} else if (ext->oe_end < index) {
			tmp = grants;
			/* try to expand this extent */
			rc = osc_extent_expand(ext, index, &tmp);
			if (rc < 0) {
				need_release = 1;
				/* don't free reserved grant */
			} else {
				OSC_EXTENT_DUMP(D_CACHE, ext,
						"expanded for %lu.\n", index);
				osc_unreserve_grant_nolock(cli, grants, tmp);
				grants = 0;
			}
		}
		spin_unlock(&cli->cl_loi_list_lock);
		rc = 0;
	} else if (ext != NULL) {
		/* index is located outside of active extent */
		need_release = 1;
	}
	if (need_release) {
		osc_extent_release(env, ext, IO_PRIO_NORMAL);
		oio->oi_active = NULL;
		ext = NULL;
	}

	if (ext == NULL) {
		tmp = (1 << cli->cl_chunkbits) + cli->cl_grant_extent_tax;

		/* try to find new extent to cover this page */
		LASSERT(oio->oi_active == NULL);
		/* we may have allocated grant for this page if we failed
		 * to expand the previous active extent. */
		LASSERT(ergo(grants > 0, grants >= tmp));

		rc = 0;

		/* We must not hold a page lock while we do osc_enter_cache()
		 * or osc_extent_find(), so we must mark dirty & unlock
		 * any pages in the write commit folio_batch.
		 */
		if (folio_batch_count(fbatch)) {
			cb(env, io, fbatch);
			folio_batch_reinit(fbatch);
		}

		if (grants == 0) {
			rc = osc_enter_cache(env, cli, osc, oap, tmp);
			if (rc == 0)
				grants = tmp;
		}

restart_find:
		tmp = grants;
		if (rc == 0) {
			ext = osc_extent_find(env, osc, index, &tmp);
			if (IS_ERR(ext)) {
				LASSERT(tmp == grants);
				osc_exit_cache(cli, oap);
				rc = PTR_ERR(ext);
				ext = NULL;
			} else {
				oio->oi_active = ext;
			}
		}
		if (grants > 0)
			osc_unreserve_grant(cli, grants, tmp);
	}

	LASSERT(ergo(rc == 0, ext != NULL));
	if (ext != NULL) {
		EASSERTF(ext->oe_end >= index && ext->oe_start <= index,
			 ext, "index = %lu.\n", index);
		LASSERT((oap->oap_brw_flags & OBD_BRW_FROM_GRANT) != 0);

		osc_object_lock(osc);
		if (ext->oe_state != OES_ACTIVE) {
			if (ext->oe_state == OES_CACHE) {
				osc_extent_state_set(ext, OES_ACTIVE);
				osc_update_pending(osc, OBD_BRW_WRITE,
						   -ext->oe_nr_pages);
				list_del_init(&ext->oe_link);
			} else {
				osc_object_unlock(osc);
				osc_extent_get(ext);
				osc_extent_release(env, ext, IO_PRIO_NORMAL);
				oio->oi_active = NULL;

				/* Waiting for IO finished.  */
				rc = osc_extent_wait(env, ext, OES_INV);
				osc_extent_put(env, ext);
				if (rc < 0)
					RETURN(rc);

				GOTO(restart_find, rc);
			}
		}

		if (ext->oe_nr_pages == 0)
			ext->oe_srvlock = ops->ops_srvlock;
		else
			LASSERT(ext->oe_srvlock == ops->ops_srvlock);
		++ext->oe_nr_pages;
		list_add_tail(&oap->oap_pending_item, &ext->oe_pages);
		osc_object_unlock(osc);

		if (!ext->oe_layout_version)
			ext->oe_layout_version = io->ci_layout_version;
	}

	RETURN(rc);
}

int osc_teardown_async_page(const struct lu_env *env,
			    struct osc_object *obj, struct osc_page *ops)
{
	struct osc_async_page *oap = &ops->ops_oap;
	int rc = 0;
	ENTRY;

	CDEBUG(D_INFO, "teardown oap %p page %p at index %lu.\n",
	       oap, ops, osc_index(oap2osc(oap)));

	if (!list_empty(&oap->oap_rpc_item)) {
		CDEBUG(D_CACHE, "oap %p is not in cache.\n", oap);
		rc = -EBUSY;
	} else if (!list_empty(&oap->oap_pending_item)) {
		struct osc_extent *ext = NULL;

		osc_object_lock(obj);
		ext = osc_extent_lookup(obj, osc_index(oap2osc(oap)));
		osc_object_unlock(obj);
		/* only truncated pages are allowed to be taken out.
		 * See osc_extent_truncate() and osc_cache_truncate_start()
		 * for details. */
		if (ext != NULL && ext->oe_state != OES_TRUNC) {
			OSC_EXTENT_DUMP(D_ERROR, ext, "trunc at %lu.\n",
					osc_index(oap2osc(oap)));
			rc = -EBUSY;
		}
		if (ext != NULL)
			osc_extent_put(env, ext);
	}
	RETURN(rc);
}

/**
 * This is called when a page is picked up by kernel to write out.
 *
 * We should find out the corresponding extent and add the whole extent
 * into urgent list. The extent may be being truncated or used, handle it
 * carefully.
 */
int osc_flush_async_page(const struct lu_env *env, struct cl_io *io,
			 struct osc_page *ops)
{
	struct osc_extent *ext   = NULL;
	struct osc_object *obj   = osc_page_object(ops);
	struct cl_page    *cp    = ops->ops_cl.cpl_page;
	pgoff_t            index = osc_index(ops);
	struct osc_async_page *oap = &ops->ops_oap;
	bool unplug = false;
	int rc = 0;
	ENTRY;

	osc_object_lock(obj);
	ext = osc_extent_lookup(obj, index);
	if (ext == NULL) {
		osc_extent_tree_dump(D_ERROR, obj);
		LASSERTF(0, "page index %lu is NOT covered.\n", index);
	}

	switch (ext->oe_state) {
	case OES_RPC:
	case OES_LOCK_DONE:
		CL_PAGE_DEBUG(D_ERROR, env, cp, "flush an in-rpc page?\n");
		LASSERT(0);
		break;
	case OES_LOCKING:
		/* If we know this extent is being written out, we should abort
		 * so that the writer can make this page ready. Otherwise, there
		 * exists a deadlock problem because other process can wait for
		 * page writeback bit holding page lock; and meanwhile in
		 * vvp_page_make_ready(), we need to grab page lock before
		 * really sending the RPC. */
	case OES_TRUNC:
		/* race with truncate, page will be redirtied */
	case OES_ACTIVE:
		/* The extent is active so we need to abort and let the caller
		 * re-dirty the page. If we continued on here, and we were the
		 * one making the extent active, we could deadlock waiting for
		 * the page writeback to clear but it won't because the extent
		 * is active and won't be written out. */
		GOTO(out, rc = -EAGAIN);
	default:
		break;
	}

	rc = cl_page_prep(env, io, cp, CRT_WRITE);
	if (rc)
		GOTO(out, rc);

	oap->oap_async_flags |= ASYNC_READY|ASYNC_URGENT;

	if (current->flags & PF_MEMALLOC)
		ext->oe_memalloc = 1;

	ext->oe_urgent = 1;
	if (ext->oe_state == OES_CACHE) {
		OSC_EXTENT_DUMP(D_CACHE, ext,
				"flush page %p make it urgent.\n", oap);
		if (list_empty(&ext->oe_link))
			list_add_tail(&ext->oe_link, &obj->oo_urgent_exts);
		unplug = true;
	}
	rc = 0;
	EXIT;

out:
	osc_object_unlock(obj);
	osc_extent_put(env, ext);
	if (unplug)
		osc_io_unplug_async(env, osc_cli(obj), obj);
	return rc;
}

int osc_queue_dio_pages(const struct lu_env *env, struct cl_io *io,
			struct osc_object *obj, struct cl_dio_pages *cdp,
			struct list_head *list, int from_page, int to_page,
			int brw_flags)
{
	struct client_obd *cli = osc_cli(obj);
	struct osc_io *oio = osc_env_io(env);
	struct osc_async_page *oap;
	struct osc_extent *ext;
	struct osc_lock *oscl;
	struct cl_page *page;
	struct osc_page *opg;
	int mppr = cli->cl_max_pages_per_rpc;
	pgoff_t start = CL_PAGE_EOF;
	bool can_merge = true;
	enum cl_req_type crt;
	int page_count = 0;
	pgoff_t end = 0;
	int i;

	ENTRY;

	if (brw_flags & OBD_BRW_READ)
		crt = CRT_READ;
	else
		crt = CRT_WRITE;

	for (i = from_page; i <= to_page; i++) {
		pgoff_t index;

		page = cdp->cdp_cl_pages[i];
		opg = osc_cl_page_osc(page, obj);
		oap = &opg->ops_oap;
		index = osc_index(opg);

		if (index > end)
			end = index;
		if (index < start)
			start = index;
		++page_count;
		mppr <<= (page_count > mppr);

		if (unlikely(oap->oap_count < PAGE_SIZE))
			can_merge = false;
	}

	ext = osc_extent_alloc(obj);
	if (ext == NULL) {
		for (i = from_page; i <= to_page; i++) {
			page = cdp->cdp_cl_pages[i];
			opg = osc_cl_page_osc(page, obj);
			oap = &opg->ops_oap;

			list_del_init(&oap->oap_pending_item);
			osc_completion(env, obj, oap, crt, -ENOMEM);
		}
		RETURN(-ENOMEM);
	}

	ext->oe_rw = !!(brw_flags & OBD_BRW_READ);
	ext->oe_sync = 1;
	ext->oe_no_merge = !can_merge;
	ext->oe_urgent = 1;
	ext->oe_start = start;
	ext->oe_end = ext->oe_max_end = end;
	ext->oe_obj = obj;
	ext->oe_srvlock = !!(brw_flags & OBD_BRW_SRVLOCK);
	ext->oe_ndelay = !!(brw_flags & OBD_BRW_NDELAY);
	ext->oe_dio = true;
	if (ext->oe_dio) {
		struct cl_sync_io *anchor;
		struct cl_page *clpage;

		oap = list_first_entry(list, struct osc_async_page,
				       oap_pending_item);
		clpage = oap2cl_page(oap);
		LASSERT(clpage->cp_type == CPT_TRANSIENT);
		anchor = clpage->cp_sync_io;
		ext->oe_csd = anchor->csi_dio_aio;
	}
	oscl = oio->oi_write_osclock ? : oio->oi_read_osclock;
	if (oscl && oscl->ols_dlmlock != NULL)
		ext->oe_dlmlock = ldlm_lock_get(oscl->ols_dlmlock);
	if (!ext->oe_rw) { /* direct io write */
		int grants;
		int ppc;

		ppc = 1 << (cli->cl_chunkbits - PAGE_SHIFT);
		grants = cli->cl_grant_extent_tax;
		grants += (1 << cli->cl_chunkbits) *
			((page_count + ppc - 1) / ppc);

		CDEBUG(D_CACHE, "requesting %d bytes grant\n", grants);
		spin_lock(&cli->cl_loi_list_lock);
		if (osc_reserve_grant(cli, grants) == 0) {
			for (i = from_page; i <= to_page; i++) {
				page = cdp->cdp_cl_pages[i];
				opg = osc_cl_page_osc(page, obj);
				oap = &opg->ops_oap;

				osc_consume_write_grant(cli,
							&oap->oap_brw_page);
			}
			atomic_long_add(page_count, &obd_dirty_pages);
			osc_unreserve_grant_nolock(cli, grants, 0);
			ext->oe_grants = grants;
		} else {
			/* We cannot report ENOSPC correctly if we do parallel
			 * DIO (async RPC submission), so turn off parallel dio
			 * if there is not sufficient grant available.  This
			 * makes individual RPCs synchronous.
			 */
			io->ci_parallel_dio = false;
			CDEBUG(D_CACHE,
			"not enough grant available, switching to sync for this i/o\n");
		}
		spin_unlock(&cli->cl_loi_list_lock);
		osc_update_next_shrink(cli);
	}

	ext->oe_is_rdma_only = !!(brw_flags & OBD_BRW_RDMA_ONLY);
	ext->oe_nr_pages = page_count;
	ext->oe_mppr = mppr;
	list_splice_init(list, &ext->oe_pages);
	ext->oe_layout_version = io->ci_layout_version;

	osc_object_lock(obj);
	/* Reuse the initial refcount for RPC, don't drop it */
	osc_extent_state_set(ext, OES_LOCK_DONE);
	if (!ext->oe_rw) { /* write */
		list_add_tail(&ext->oe_link, &obj->oo_urgent_exts);
		osc_update_pending(obj, OBD_BRW_WRITE, page_count);
	} else {
		list_add_tail(&ext->oe_link, &obj->oo_reading_exts);
		osc_update_pending(obj, OBD_BRW_READ, page_count);
	}
	osc_object_unlock(obj);

	osc_io_unplug_async(env, cli, obj);
	RETURN(0);
}

int osc_queue_sync_pages(const struct lu_env *env, struct cl_io *io,
			 struct osc_object *obj, struct list_head *list,
			 int brw_flags)
{
	struct osc_io *oio = osc_env_io(env);
	struct client_obd     *cli = osc_cli(obj);
	struct osc_extent     *ext;
	struct osc_async_page *oap;
	int     page_count = 0;
	int     mppr       = cli->cl_max_pages_per_rpc;
	bool	can_merge   = true;
	pgoff_t start      = CL_PAGE_EOF;
	pgoff_t end        = 0;
	enum cl_req_type crt;
	ENTRY;

	if (brw_flags & OBD_BRW_READ)
		crt = CRT_READ;
	else
		crt = CRT_WRITE;

	list_for_each_entry(oap, list, oap_pending_item) {
		struct osc_page *opg = oap2osc_page(oap);
		pgoff_t index = osc_index(opg);

		if (index > end)
			end = index;
		if (index < start)
			start = index;
		++page_count;
		mppr <<= (page_count > mppr);

		if (unlikely(opg->ops_from > 0 ||
			     opg->ops_to < PAGE_SIZE - 1))
			can_merge = false;
	}

	ext = osc_extent_alloc(obj);
	if (ext == NULL) {
		struct osc_async_page *tmp;

		list_for_each_entry_safe(oap, tmp, list, oap_pending_item) {
			list_del_init(&oap->oap_pending_item);
			osc_completion(env, obj, oap, crt, -ENOMEM);
		}
		RETURN(-ENOMEM);
	}

	ext->oe_rw = !!(brw_flags & OBD_BRW_READ);
	ext->oe_sync = 1;
	ext->oe_no_merge = !can_merge;
	ext->oe_urgent = 1;
	ext->oe_start = start;
	ext->oe_end = ext->oe_max_end = end;
	ext->oe_obj = obj;
	ext->oe_srvlock = !!(brw_flags & OBD_BRW_SRVLOCK);
	ext->oe_ndelay = !!(brw_flags & OBD_BRW_NDELAY);
	ext->oe_dio = !!(brw_flags & OBD_BRW_NOCACHE);
	if (ext->oe_dio) {
		struct cl_sync_io *anchor;
		struct cl_page *clpage;

		oap = list_first_entry(list, struct osc_async_page,
				       oap_pending_item);
		clpage = oap2cl_page(oap);
		LASSERT(clpage->cp_type == CPT_TRANSIENT);
		anchor = clpage->cp_sync_io;
		ext->oe_csd = anchor->csi_dio_aio;
	}
	if (ext->oe_dio && !ext->oe_rw) { /* direct io write */
		int grants;
		int ppc;

		ppc = 1 << (cli->cl_chunkbits - PAGE_SHIFT);
		grants = cli->cl_grant_extent_tax;
		grants += (1 << cli->cl_chunkbits) *
			((page_count + ppc - 1) / ppc);

		CDEBUG(D_CACHE, "requesting %d bytes grant\n", grants);
		spin_lock(&cli->cl_loi_list_lock);
		if (osc_reserve_grant(cli, grants) == 0 &&
		    cli->cl_dirty_pages + page_count <
						    cli->cl_dirty_max_pages) {
			list_for_each_entry(oap, list, oap_pending_item) {
				osc_consume_write_grant(cli,
							&oap->oap_brw_page);
			}
			atomic_long_add(page_count, &obd_dirty_pages);
			osc_unreserve_grant_nolock(cli, grants, 0);
			ext->oe_grants = grants;
		} else {
			/* We cannot report ENOSPC correctly if we do parallel
			 * DIO (async RPC submission), so turn off parallel dio
			 * if there is not sufficient grant or dirty pages
			 * available. This makes individual RPCs synchronous.
			 */
			io->ci_parallel_dio = false;
			CDEBUG(D_CACHE,
			"not enough grant or dirty pages available, switching to sync for this i/o\n");
		}
		spin_unlock(&cli->cl_loi_list_lock);
		osc_update_next_shrink(cli);
	}

	ext->oe_is_rdma_only = !!(brw_flags & OBD_BRW_RDMA_ONLY);
	ext->oe_nr_pages = page_count;
	ext->oe_mppr = mppr;
	list_splice_init(list, &ext->oe_pages);
	ext->oe_layout_version = io->ci_layout_version;

	osc_object_lock(obj);
	/* Reuse the initial refcount for RPC, don't drop it */
	osc_extent_state_set(ext, OES_LOCK_DONE);
	if (!ext->oe_rw) { /* write */
		if (!ext->oe_srvlock && !ext->oe_dio) {
			/* The most likely case here is from lack of grants
			 * so we are either out of quota or out of space.
			 * Since this means we are holding locks across
			 * potentially multi-striped IO, we must send out
			 * everything out instantly to avoid prolonged
			 * waits resulting in lock eviction (likely since
			 * the extended wait in osc_cache_enter() did not
			 * yield any additional grant due to a timeout.
			 * LU-13131 */
			ext->oe_hp = 1;
			list_add_tail(&ext->oe_link, &obj->oo_hp_exts);
		} else {
			list_add_tail(&ext->oe_link, &obj->oo_urgent_exts);
		}
		osc_update_pending(obj, OBD_BRW_WRITE, page_count);
	} else {
		bool hp_read = false;
		struct ldlm_lock *dlmlock;
		struct osc_lock *oscl;

		/*
		 * The DLM extent lock is under blocking AST, and make
		 * this I/O with high priority.
		 */

		oscl = oio->oi_read_osclock ? : oio->oi_write_osclock;
		dlmlock = oscl ? oscl->ols_dlmlock : NULL;

		if (dlmlock == NULL && !ext->oe_srvlock) {
			CDEBUG(D_CACHE,
			       "NOLCK: io %pK "EXTSTR" dio: %d srvlock: %d\n",
			       io, EXTPARA(ext), ext->oe_dio, ext->oe_srvlock);
		}
		if (!ext->oe_srvlock && dlmlock != NULL) {
			lock_res_and_lock(dlmlock);
			hp_read = ldlm_is_cbpending(dlmlock);
			unlock_res_and_lock(dlmlock);
			if (hp_read)
				CDEBUG(D_CACHE,
				       "HP read: io %pK ext@%pK "EXTSTR"\n",
				       io, ext, EXTPARA(ext));
		}

		if (hp_read)
			list_add_tail(&ext->oe_link, &obj->oo_hp_read_exts);
		else
			list_add_tail(&ext->oe_link, &obj->oo_reading_exts);
		osc_update_pending(obj, OBD_BRW_READ, page_count);
	}

	OSC_EXTENT_DUMP(D_CACHE, ext, "allocate ext: rw=%d\n", ext->oe_rw);
	osc_object_unlock(obj);

	osc_io_unplug_async(env, cli, obj);
	RETURN(0);
}

/**
 * Called by osc_io_setattr_start() to freeze and destroy covering extents.
 */
int osc_cache_truncate_start(const struct lu_env *env, struct osc_object *obj,
			     __u64 size, struct osc_extent **extp)
{
	struct client_obd *cli = osc_cli(obj);
	struct osc_extent *ext;
	struct osc_extent *waiting = NULL;
	pgoff_t index;
	LIST_HEAD(list);
	int result = 0;
	bool partial;
	ENTRY;

	/* pages with index greater or equal to index will be truncated. */
	index = size >> PAGE_SHIFT;
	partial = size > (index << PAGE_SHIFT);

again:
	osc_object_lock(obj);
	ext = osc_extent_search(obj, index);
	if (ext == NULL)
		ext = first_extent(obj);
	else if (ext->oe_end < index)
		ext = next_extent(ext);
	while (ext != NULL) {
		EASSERT(ext->oe_state != OES_TRUNC, ext);

		if (ext->oe_state > OES_CACHE || ext->oe_urgent) {
			/* if ext is in urgent state, it means there must exist
			 * a page already having been flushed by write_page().
			 * We have to wait for this extent because we can't
			 * truncate that page. */
			OSC_EXTENT_DUMP(D_CACHE, ext,
					"waiting for busy extent\n");
			waiting = osc_extent_get(ext);
			break;
		}

		OSC_EXTENT_DUMP(D_CACHE, ext, "try to trunc:%llu.\n", size);

		osc_extent_get(ext);
		if (ext->oe_state == OES_ACTIVE) {
			/* though we grab inode mutex for write path, but we
			 * release it before releasing extent(in osc_io_end()),
			 * so there is a race window that an extent is still
			 * in OES_ACTIVE when truncate starts. */
			LASSERT(!ext->oe_trunc_pending);
			ext->oe_trunc_pending = 1;
		} else {
			EASSERT(ext->oe_state == OES_CACHE, ext);
			osc_extent_state_set(ext, OES_TRUNC);
			osc_update_pending(obj, OBD_BRW_WRITE,
					   -ext->oe_nr_pages);
		}
		/* This extent could be on the full extents list, that's OK */
		if (!list_empty(&ext->oe_link))
			list_move_tail(&ext->oe_link, &list);
		else
			list_add_tail(&ext->oe_link, &list);

		ext = next_extent(ext);
	}
	osc_object_unlock(obj);

	osc_list_maint(cli, obj);

	while ((ext = list_first_entry_or_null(&list,
					       struct osc_extent,
					       oe_link)) != NULL) {
		int rc;

		list_del_init(&ext->oe_link);

		/* extent may be in OES_ACTIVE state because inode mutex
		 * is released before osc_io_end() in file write case */
		if (ext->oe_state != OES_TRUNC)
			osc_extent_wait(env, ext, OES_TRUNC);

		rc = osc_extent_truncate(ext, index, partial);
		if (rc < 0) {
			if (result == 0)
				result = rc;

			OSC_EXTENT_DUMP(D_ERROR, ext,
					"truncate error %d\n", rc);
		} else if (ext->oe_nr_pages == 0) {
			osc_extent_remove(ext);
		} else {
			/* this must be an overlapped extent which means only
			 * part of pages in this extent have been truncated.
			 */
			EASSERTF(ext->oe_start <= index, ext,
				 "trunc index = %lu/%d.\n", index, partial);
			/* fix index to skip this partially truncated extent */
			index = ext->oe_end + 1;
			partial = false;

			/* we need to hold this extent in OES_TRUNC state so
			 * that no writeback will happen. This is to avoid
			 * BUG 17397.
			 * Only partial truncate can reach here, if @size is
			 * not zero, the caller should provide a valid @extp. */
			LASSERT(*extp == NULL);
			*extp = osc_extent_get(ext);
			OSC_EXTENT_DUMP(D_CACHE, ext,
					"trunc at %llu\n", size);
		}
		osc_extent_put(env, ext);
	}
	if (waiting != NULL) {
		int rc;

		/* ignore the result of osc_extent_wait the write initiator
		 * should take care of it. */
		rc = osc_extent_wait(env, waiting, OES_INV);
		if (rc < 0)
			OSC_EXTENT_DUMP(D_CACHE, waiting, "error: %d.\n", rc);

		osc_extent_put(env, waiting);
		waiting = NULL;
		goto again;
	}
	RETURN(result);
}
EXPORT_SYMBOL(osc_cache_truncate_start);

/**
 * Called after osc_io_setattr_end to add oio->oi_trunc back to cache.
 */
void osc_cache_truncate_end(const struct lu_env *env, struct osc_extent *ext)
{
	if (ext != NULL) {
		struct osc_object *obj = ext->oe_obj;
		bool unplug = false;

		EASSERT(ext->oe_nr_pages > 0, ext);
		EASSERT(ext->oe_state == OES_TRUNC, ext);
		EASSERT(!ext->oe_urgent, ext);

		OSC_EXTENT_DUMP(D_CACHE, ext, "trunc -> cache.\n");
		osc_object_lock(obj);
		osc_extent_state_set(ext, OES_CACHE);
		if (ext->oe_fsync_wait && !ext->oe_urgent) {
			ext->oe_urgent = 1;
			list_move_tail(&ext->oe_link, &obj->oo_urgent_exts);
			unplug = true;
		}
		osc_update_pending(obj, OBD_BRW_WRITE, ext->oe_nr_pages);
		osc_object_unlock(obj);
		osc_extent_put(env, ext);

		if (unplug)
			osc_io_unplug_async(env, osc_cli(obj), obj);
	}
}

/**
 * Wait for extents in a specific range to be written out.
 * The caller must have called osc_cache_writeback_range() to issue IO
 * otherwise it will take a long time for this function to finish.
 *
 * Caller must hold inode_mutex , or cancel exclusive dlm lock so that
 * nobody else can dirty this range of file while we're waiting for
 * extents to be written.
 */
int osc_cache_wait_range(const struct lu_env *env, struct osc_object *obj,
			 pgoff_t start, pgoff_t end)
{
	struct osc_extent *ext;
	pgoff_t index = start;
	int     result = 0;
	ENTRY;

again:
	osc_object_lock(obj);
	ext = osc_extent_search(obj, index);
	if (ext == NULL)
		ext = first_extent(obj);
	else if (ext->oe_end < index)
		ext = next_extent(ext);
	while (ext != NULL) {
		int rc;

		if (ext->oe_start > end)
			break;

		if (!ext->oe_fsync_wait) {
			ext = next_extent(ext);
			continue;
		}

		EASSERT(ergo(ext->oe_state == OES_CACHE,
			     ext->oe_hp || ext->oe_urgent), ext);
		EASSERT(ergo(ext->oe_state == OES_ACTIVE,
			     !ext->oe_hp && ext->oe_urgent), ext);

		index = ext->oe_end + 1;
		osc_extent_get(ext);
		osc_object_unlock(obj);

		rc = osc_extent_wait(env, ext, OES_INV);
		if (result == 0)
			result = rc;
		osc_extent_put(env, ext);
		goto again;
	}
	osc_object_unlock(obj);

	OSC_IO_DEBUG(obj, "sync file range.\n");
	RETURN(result);
}
EXPORT_SYMBOL(osc_cache_wait_range);

/**
 * Called to write out a range of osc object.
 *
 * @hp     : should be set this is caused by lock cancel;
 * @discard: is set if dirty pages should be dropped - file will be deleted or
 *	   truncated, this implies there is no partially discarding extents.
 *
 * Return how many pages will be issued, or error code if error occurred.
 */
int osc_cache_writeback_range(const struct lu_env *env, struct osc_object *obj,
			      pgoff_t start, pgoff_t end, int hp, int discard,
			      enum cl_io_priority prio)
{
	struct osc_extent *ext;
	LIST_HEAD(discard_list);
	bool active_ext_check = false;
	bool unplug = false;
	int result = 0;

	ENTRY;

repeat:
	osc_object_lock(obj);
	ext = osc_extent_search(obj, start);
	if (ext == NULL)
		ext = first_extent(obj);
	else if (ext->oe_end < start)
		ext = next_extent(ext);
	while (ext != NULL) {
		if (ext->oe_start > end)
			break;

		ext->oe_fsync_wait = 1;
		switch (ext->oe_state) {
		case OES_CACHE:
			result += ext->oe_nr_pages;
			if (!discard) {
				struct list_head *list = NULL;

				if (ext->oe_hp) {
					/*
					 * The extent is already added into HP
					 * list.
					 * Another thread has already written
					 * back the extent with high priority.
					 */
					unplug = true;
					break;
				} else if (hp) {
					ext->oe_hp = 1;
					list = &obj->oo_hp_exts;
				} else if (!ext->oe_urgent && !ext->oe_hp) {
					ext->oe_urgent = 1;
					list = &obj->oo_urgent_exts;
				}
				if (list != NULL)
					list_move_tail(&ext->oe_link, list);
				unplug = true;
			} else {
				struct client_obd *cli = osc_cli(obj);
				int pcc_bits = cli->cl_chunkbits - PAGE_SHIFT;
				pgoff_t align_by = (1 << pcc_bits);
				pgoff_t a_start = round_down(start, align_by);
				pgoff_t a_end = round_up(end, align_by);

				/* overflow case */
				if (end && !a_end)
					a_end = CL_PAGE_EOF;
				/* the only discarder is lock cancelling, so
				 * [start, end], aligned by chunk size, must
				 * contain this extent */
				LASSERTF(ext->oe_start >= a_start &&
					 ext->oe_end <= a_end,
					 "ext [%lu, %lu] reg [%lu, %lu] "
					 "orig [%lu %lu] align %lu bits "
					 "%d\n", ext->oe_start, ext->oe_end,
					 a_start, a_end, start, end,
					 align_by, pcc_bits);
				osc_extent_state_set(ext, OES_LOCKING);
				ext->oe_owner = current;
				list_move_tail(&ext->oe_link,
						   &discard_list);
				osc_update_pending(obj, OBD_BRW_WRITE,
						   -ext->oe_nr_pages);
			}
			break;
		case OES_ACTIVE:
			/* It's pretty bad to wait for ACTIVE extents, because
			 * we don't know how long we will wait for it to be
			 * flushed since it may be blocked at awaiting more
			 * grants. We do this for the correctness of fsync. */
			LASSERT(hp == 0 && discard == 0);
			ext->oe_urgent = 1;

			if (active_ext_check) {
				osc_extent_state_set(ext, OES_CACHE);
				list_move_tail(&ext->oe_link,
					       &obj->oo_urgent_exts);
				osc_update_pending(obj, OBD_BRW_WRITE,
						   ext->oe_nr_pages);
				unplug = true;
			}

			break;
		case OES_TRUNC:
			/* this extent is being truncated, can't do anything
			 * for it now. it will be set to urgent after truncate
			 * is finished in osc_cache_truncate_end(). */
		default:
			break;
		}
		ext = next_extent(ext);
	}
	osc_object_unlock(obj);

	LASSERT(ergo(!discard, list_empty(&discard_list)));
	if (!list_empty(&discard_list)) {
		struct osc_extent *tmp;
		int rc;

		osc_list_maint(osc_cli(obj), obj);
		list_for_each_entry_safe(ext, tmp, &discard_list, oe_link) {
			list_del_init(&ext->oe_link);
			EASSERT(ext->oe_state == OES_LOCKING, ext);

			/* Discard caching pages. We don't actually write this
			 * extent out but we complete it as if we did. */
			rc = osc_extent_make_ready(env, ext);
			if (unlikely(rc < 0)) {
				OSC_EXTENT_DUMP(D_ERROR, ext,
						"make_ready returned %d\n", rc);
				if (result >= 0)
					result = rc;
			}

			/* finish the extent as if the pages were sent */
			osc_extent_finish(env, ext, 0, 0);
		}
	}

	if (unplug)
		osc_io_unplug(env, osc_cli(obj), obj);

	if (hp || discard) {
		int rc;
		rc = osc_cache_wait_range(env, obj, start, end);
		if (result >= 0 && rc < 0)
			result = rc;
	}

	OSC_IO_DEBUG(obj, "pageout [%lu, %lu] npages %lu: rc=%d.\n",
		     start, end, obj->oo_npages, result);

	/*
	 * Try to flush the active I/O extents of the object.
	 * Otherwise, the user process writing the file may be dirty exceeded
	 * and waiting endless in balance_dirty_pages().
	 */
	if (result == 0 && prio == IO_PRIO_DIRTY_EXCEEDED &&
	    !active_ext_check && atomic_read(&obj->oo_nr_ios) &&
	    obj->oo_npages > 0) {
		osc_extent_tree_dump(D_CACHE, obj);
		active_ext_check = true;
		GOTO(repeat, result);
	}

	RETURN(result);
}
EXPORT_SYMBOL(osc_cache_writeback_range);

/**
 * Returns a list of pages by a given [start, end] of \a obj.
 *
 * Gang tree lookup (radix_tree_gang_lookup()) optimization is absolutely
 * crucial in the face of [offset, EOF] locks.
 *
 * Return at least one page in @queue unless there is no covered page.
 */
bool osc_page_gang_lookup(const struct lu_env *env, struct cl_io *io,
			  struct osc_object *osc, pgoff_t start, pgoff_t end,
			  osc_page_gang_cbt cb, void *cbdata)
{
	struct osc_page *ops;
	struct folio_batch *fbatch;
	void            **pvec;
	pgoff_t         idx;
	unsigned int    nr;
	unsigned int    i;
	unsigned int    j;
	bool            res = true;
	bool            tree_lock = true;
	ENTRY;

	idx = start;
	pvec = osc_env_info(env)->oti_pvec;
	fbatch = &osc_env_info(env)->oti_fbatch;
	ll_folio_batch_init(fbatch, 0);
	spin_lock(&osc->oo_tree_lock);
	while ((nr = radix_tree_gang_lookup(&osc->oo_tree, pvec,
					    idx, OTI_PVEC_SIZE)) > 0) {
		struct cl_page *page;
		bool end_of_region = false;

		for (i = 0, j = 0; i < nr; ++i) {
			ops = pvec[i];
			pvec[i] = NULL;

			idx = osc_index(ops);
			if (idx > end) {
				end_of_region = true;
				break;
			}

			page = ops->ops_cl.cpl_page;
			LASSERT(page->cp_type == CPT_CACHEABLE);
			if (page->cp_state == CPS_FREEING)
				continue;

			cl_page_get(page);
			pvec[j++] = ops;
		}

		/*
		 * Here a delicate locking dance is performed. Current thread
		 * holds a reference to a page, but has to own it before it
		 * can be placed into queue. Owning implies waiting, so
		 * radix-tree lock is to be released. After a wait one has to
		 * check that pages weren't truncated (cl_page_own() returns
		 * error in the latter case).
		 */
		spin_unlock(&osc->oo_tree_lock);
		tree_lock = false;

		res = (*cb)(env, io, pvec, j, cbdata);

		for (i = 0; i < j; ++i) {
			ops = pvec[i];
			page = ops->ops_cl.cpl_page;
			cl_batch_put(env, page, fbatch);
		}
		folio_batch_release(fbatch);

		if (nr < OTI_PVEC_SIZE || end_of_region)
			break;

		if (!res)
			break;

		CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_SLOW_PAGE_EVICT,
				 cfs_fail_val ?: 20);

		if (io->ci_type == CIT_MISC &&
		    io->u.ci_misc.lm_next_rpc_time &&
		    ktime_get_seconds() > io->u.ci_misc.lm_next_rpc_time) {
			osc_send_empty_rpc(osc, idx << PAGE_SHIFT);
			io->u.ci_misc.lm_next_rpc_time = ktime_get_seconds() +
							 5 * obd_timeout / 16;
		}

		if (need_resched())
			cond_resched();

		++idx;
		spin_lock(&osc->oo_tree_lock);
		tree_lock = true;
	}
	if (tree_lock)
		spin_unlock(&osc->oo_tree_lock);
	RETURN(res);
}
EXPORT_SYMBOL(osc_page_gang_lookup);

/**
 * Check if page @page is covered by an extra lock or discard it.
 */
static bool check_and_discard_cb(const struct lu_env *env, struct cl_io *io,
				 void **pvec, int count, void *cbdata)
{
	struct osc_thread_info *info = osc_env_info(env);
	struct osc_object *osc = cbdata;
	int i;

	for (i = 0; i < count; i++) {
		struct osc_page *ops = pvec[i];
		struct cl_page *page = ops->ops_cl.cpl_page;
		pgoff_t index = osc_index(ops);
		bool discard = false;

		/* negative lock caching */
		if (index < info->oti_ng_index) {
			discard = true;
		} else if (index >= info->oti_fn_index) {
			struct ldlm_lock *tmp;
			/* refresh non-overlapped index */
			tmp = osc_dlmlock_at_pgoff(env, osc, index,
					OSC_DAP_FL_TEST_LOCK |
					OSC_DAP_FL_AST |
					OSC_DAP_FL_RIGHT);
			if (tmp != NULL) {
				__u64 end =
					tmp->l_policy_data.l_extent.end;
				__u64 start =
					tmp->l_policy_data.l_extent.start;

				/* no lock covering this page */
				if (index < start >> PAGE_SHIFT) {
					/* no lock at @index,
					 * first lock at @start
					 */
					info->oti_ng_index =
						start >> PAGE_SHIFT;
					discard = true;
				} else {
					/* Cache the first-non-overlapped
					 * index so as to skip all pages
					 * within [index, oti_fn_index).
					 * This is safe because if tmp lock
					 * is canceled, it will discard these
					 * pages.
					 */
					info->oti_fn_index =
						(end + 1) >> PAGE_SHIFT;
					if (end == OBD_OBJECT_EOF)
						info->oti_fn_index =
							CL_PAGE_EOF;
				}
				ldlm_lock_put(tmp);
			} else {
				info->oti_ng_index = CL_PAGE_EOF;
				discard = true;
			}
		}

		if (discard) {
			if (cl_page_own(env, io, page) == 0) {
				cl_page_discard(env, io, page);
				cl_page_disown(env, io, page);
			} else {
				LASSERT(page->cp_state == CPS_FREEING);
			}
		}

		info->oti_next_index = index + 1;
	}
	return true;
}

bool osc_discard_cb(const struct lu_env *env, struct cl_io *io,
		    void **pvec, int count, void *cbdata)
{
	struct osc_thread_info *info = osc_env_info(env);
	int i;

	for (i = 0; i < count; i++) {
		struct osc_page *ops = pvec[i];
		struct cl_page *page = ops->ops_cl.cpl_page;

		/* page is top page. */
		info->oti_next_index = osc_index(ops) + 1;
		if (cl_page_own(env, io, page) == 0) {
			if (!ergo(page->cp_type == CPT_CACHEABLE,
				  !PageDirty(cl_page_vmpage(page))))
				CL_PAGE_DEBUG(D_ERROR, env, page,
					      "discard dirty page?\n");

			/* discard the page */
			cl_page_discard(env, io, page);
			cl_page_disown(env, io, page);
		} else {
			LASSERT(page->cp_state == CPS_FREEING);
		}
	}

	return true;
}
EXPORT_SYMBOL(osc_discard_cb);

/**
 * Discard pages protected by the given lock. This function traverses radix
 * tree to find all covering pages and discard them. If a page is being covered
 * by other locks, it should remain in cache.
 *
 * If error happens on any step, the process continues anyway (the reasoning
 * behind this being that lock cancellation cannot be delayed indefinitely).
 */
int osc_lock_discard_pages(const struct lu_env *env, struct osc_object *osc,
			   pgoff_t start, pgoff_t end, bool discard)
{
	struct osc_thread_info *info = osc_env_info(env);
	struct cl_io *io = osc_env_new_io(env);
	osc_page_gang_cbt cb;
	int result;

	ENTRY;

	io->ci_obj = cl_object_top(osc2cl(osc));
	io->ci_ignore_layout = 1;
	io->ci_invalidate_page_cache = 1;
	io->u.ci_misc.lm_next_rpc_time = ktime_get_seconds() +
					 5 * obd_timeout / 16;
	result = cl_io_init(env, io, CIT_MISC, io->ci_obj);
	if (result != 0)
		GOTO(out, result);

	cb = discard ? osc_discard_cb : check_and_discard_cb;
	info->oti_fn_index = info->oti_next_index = start;
	info->oti_ng_index = 0;

	osc_page_gang_lookup(env, io, osc,
			     info->oti_next_index, end, cb, osc);
out:
	cl_io_fini(env, io);
	RETURN(result);
}

int osc_ldlm_hp_handle(const struct lu_env *env, struct osc_object *obj,
		       pgoff_t start, pgoff_t end, bool read_check_only)
{
	struct client_obd *cli = osc_cli(obj);
	struct osc_extent *ext;
	struct osc_extent *next;
	bool no_rpc_slots = false;
	bool unplug = false;

	ENTRY;

	spin_lock(&cli->cl_loi_list_lock);
	no_rpc_slots = osc_full_dio_in_flight(cli);
	spin_unlock(&cli->cl_loi_list_lock);

	/*
	 * Current we only handle with high priority for the case that
	 * all I/O RPC slots are used out by parallel DIO and there are
	 * conflict I/O extents in lock blocking AST.
	 * TODO: Send all I/Os to OSTs on the object corresponding to
	 * the lock in blocking AST. With higher priority, it does not
	 * need to iterate over all OSC objects one by one, the conflict
	 * I/O can be handled more quickly. Thus the lock taken by this
	 * I/O can be release quickly.
	 */

	CDEBUG(D_CACHE,
	       "High prio I/O check: start %lu end %lu RPC(%d):r%u/w%u/d%u\n",
	       start, end, no_rpc_slots, cli->cl_r_in_flight,
	       cli->cl_w_in_flight, cli->cl_d_in_flight);
	osc_object_lock(obj);
	/* Check buffered read extents. */
	list_for_each_entry_safe(ext, next, &obj->oo_reading_exts, oe_link) {
		EASSERT(ext->oe_state == OES_LOCK_DONE, ext);
		if (ext->oe_end < start || ext->oe_start > end)
			continue;
		if (ext->oe_dio || ext->oe_srvlock)
			continue;

		list_move_tail(&ext->oe_link, &obj->oo_hp_read_exts);
		OSC_EXTENT_DUMP(D_CACHE, ext, "HP read this extent\n");
		unplug = true;
	}

	if (read_check_only)
		GOTO(out_unlock, unplug);

	/* Check buffered write extents. */
	ext = osc_extent_search(obj, start);
	if (ext == NULL)
		ext = first_extent(obj);
	else if (ext->oe_end < start)
		ext = next_extent(ext);
	while (ext != NULL) {
		if (ext->oe_start > end)
			break;

		ext->oe_fsync_wait = 1;
		switch (ext->oe_state) {
		case OES_CACHE:
			/*
			 * The extent in HP (oe_hp) is being written back by
			 * another thread.
			 */
			if (ext->oe_hp || ext->oe_dio || ext->oe_srvlock)
				break;

			ext->oe_hp = 1;
			list_move_tail(&ext->oe_link, &obj->oo_hp_exts);
			OSC_EXTENT_DUMP(D_CACHE, ext, "HP write this extent\n");
			unplug = true;
			break;
		case OES_ACTIVE:
			/*
			 * It is pretty bad to wait for ACTIVE extents, because
			 * we do not know how long we will wait for it to be
			 * flushed since it may be blocked at awaiting more
			 * grants. We do this for the correctness of fsync.
			 */
			ext->oe_urgent = 1;
			break;
		default:
			break;
		}
		ext = next_extent(ext);
	}

out_unlock:
	osc_object_unlock(obj);

	if (unplug)
		osc_io_unplug(env, cli, obj);

	RETURN(0);
}

/** @} osc */
