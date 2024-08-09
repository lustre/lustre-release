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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/page_pools.c
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/linux/linux-mem.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>

/* We have a pool for every power of 2 number of pages. Each pool must
 * be able to provide at least one object of PTLRPC_MAX_BRW_SIZE * 2.
 * Multiplying MAX_BRW_SIZE by 2 is a hack required to successfully
 * compress and uncompress chunks in decompress/compress_request(ask
 * Artem(ablagodarenko@ddn.com) for details why it failed). Most pools
 * will be unused, but that's OK - unused pools are very cheap.
 */
#define POOLS_COUNT (PTLRPC_MAX_BRW_BITS - PAGE_SHIFT + 1)
#define PAGES_TO_MiB(pages)	((pages) >> (20 - PAGE_SHIFT))
#define MiB_TO_PAGES(mb)	((mb) << (20 - PAGE_SHIFT))
/* deprecated - see pool_max_memory_mb below */
static int enc_pool_max_memory_mb;
module_param(enc_pool_max_memory_mb, int, 0644);
MODULE_PARM_DESC(enc_pool_max_memory_mb,
		 "Encoding pool max memory (MB), default unlimited (deprecated, please use pool_max_memory_mb)");

static int pool_max_memory_mb;
module_param(pool_max_memory_mb, int, 0644);
MODULE_PARM_DESC(pool_max_memory_mb,
		 "Encoding pool max memory (MB), default unlimited");
/*
 * lustre page pools
 */

#define PTRS_PER_PAGE   (PAGE_SIZE / sizeof(void *))

#define IDLE_IDX_MAX            (100)
#define IDLE_IDX_WEIGHT         (3)

#define CACHE_QUIESCENT_PERIOD  (20)

static struct obd_page_pool {
	unsigned long opp_max_objects;   /* maximum objects can hold, const */
	unsigned int opp_max_ptr_pages;   /* number of ptr_pages, const */

	/*
	 * wait queue in case of not enough free pages.
	 */
	wait_queue_head_t opp_waitq;   /* waiting threads */
	unsigned int opp_waitqlen;    /* wait queue length */
	unsigned long opp_pages_short; /* # of pages wanted of in-q users */
	unsigned int opp_growing:1;   /* during adding pages */
	unsigned int opp_order;       /* page pool order and index in pools
				       * array (element size is 2^order pages),
				       */

	/*
	 * indicating how idle the pool is, from 0 to MAX_IDLE_IDX
	 * this is counted based on each time when getting pages from
	 * the pool, not based on time. which means in case that system
	 * is idled for a while but the idle_idx might still be low if no
	 * activities happened in the pool.
	 */
	unsigned long opp_idle_idx;

	/* last shrink time due to mem tight */
	time64_t opp_last_shrink;
	time64_t opp_last_access;

	/* in-pool pages bookkeeping */
	spinlock_t opp_lock; /* protect following fields */
	unsigned long opp_total_objects; /* total objects in pool */
	unsigned long opp_free_objects;  /* current objects available */

	/* statistics */
	unsigned long opp_st_max_objects;      /* # of objects ever reached */
	unsigned int opp_st_grows;          /* # of grows */
	unsigned int opp_st_grow_fails;     /* # of add pages failures */
	unsigned int opp_st_shrinks;        /* # of shrinks */
	unsigned long opp_st_access;         /* # of access */
	unsigned long opp_st_missings;       /* # of cache missing */
	unsigned long opp_st_lowfree;        /* lowest free objects reached */
	unsigned int opp_st_max_wqlen;      /* highest waitqueue length */
	ktime_t opp_st_max_wait; /* in nanoseconds */
	unsigned long opp_st_outofmem; /* # of out of mem requests */
	/*
	 * pointers to ptr_pages, may be vmalloc'd
	 */
	void ***opp_ptr_pages;
	/*
	 * memory shrinker
	 */
	struct ll_shrinker_ops opp_shops;
	struct shrinker *pool_shrinker;
	struct mutex add_pages_mutex;
} **page_pools;

static struct shrinker **pool_shrinkers;

static inline int get_pool_index(struct shrinker *shrinker)
{
	int i;

	for (i = 0; i < POOLS_COUNT; i++)
		if (pool_shrinkers[i] == shrinker)
			return i;

	CERROR("Shrinker %p has not been found among %i pools\n",
	       shrinker, POOLS_COUNT);
	LBUG();

	return -1;
}

static int object_size(struct obd_page_pool *pool)
{
	return PAGE_SIZE << pool->opp_order;
}

/*
 * Keep old name (encrypt_page_pool vs page_pool) for compatibility with user
 * tools pulling stats
 *
 * /sys/kernel/debug/lustre/sptlrpc/encrypt_page_pools
 */
int encrypt_page_pools_seq_show(struct seq_file *m, void *v)
{
	struct obd_page_pool *pool = page_pools[0];

	spin_lock(&pool->opp_lock);
	seq_printf(m,
		"physical pages:          %lu\n"
		"pages per pool:          %lu\n"
		"max objects:               %lu\n"
		"max pools:               %u\n"
		"total objects:             %lu\n"
		"total free:              %lu\n"
		"idle index:              %lu/100\n"
		"last shrink:             %llds\n"
		"last access:             %llds\n"
		"max objects reached:       %lu\n"
		"grows:                   %u\n"
		"grows failure:           %u\n"
		"shrinks:                 %u\n"
		"cache access:            %lu\n"
		"cache missing:           %lu\n"
		"low free mark:           %lu\n"
		"max waitqueue depth:     %u\n"
		"max wait time ms:        %lld\n"
		"out of mem:              %lu\n",
		cfs_totalram_pages(), PTRS_PER_PAGE,
		pool->opp_max_objects,
		pool->opp_max_ptr_pages,
		pool->opp_total_objects,
		pool->opp_free_objects,
		pool->opp_idle_idx,
		ktime_get_seconds() - pool->opp_last_shrink,
		ktime_get_seconds() - pool->opp_last_access,
		pool->opp_st_max_objects,
		pool->opp_st_grows,
		pool->opp_st_grow_fails,
		pool->opp_st_shrinks,
		pool->opp_st_access,
		pool->opp_st_missings,
		pool->opp_st_lowfree,
		pool->opp_st_max_wqlen,
		ktime_to_ms(pool->opp_st_max_wait),
		pool->opp_st_outofmem);
	spin_unlock(&pool->opp_lock);

	return 0;
}
EXPORT_SYMBOL(encrypt_page_pools_seq_show);

/*
 * /sys/kernel/debug/lustre/sptlrpc/page_pools
 */
int page_pools_seq_show(struct seq_file *m, void *v)
{
	int pool_order;
	struct obd_page_pool *pool;

	seq_printf(m, "physical_pages: %lu\n"
		      "pools:\n",
		      cfs_totalram_pages());

	for (pool_order = 0; pool_order < POOLS_COUNT; pool_order++) {
		pool = page_pools[pool_order];
		if (!pool->opp_st_access)
			continue;
		spin_lock(&pool->opp_lock);
		seq_printf(m, "  pool_%dk:\n"
			   "    max_objects: %lu\n"
			   "    max_items: %lu\n"
			   "    total_objects: %lu\n"
			   "    total_free: %lu\n"
			   "    idle_index: %lu/100\n"
			   "    last_shrink: %llds\n"
			   "    last_access: %llds\n"
			   "    max_objects_reached: %lu\n"
			   "    grows: %u\n"
			   "    grows_failure: %u\n"
			   "    shrinks: %u\n"
			   "    cache_access: %lu\n"
			   "    cache_missing: %lu\n"
			   "    low_free_mark: %lu\n"
			   "    max_waitqueue_depth: %u\n"
			   "    max_wait_time_ms: %lld\n"
			   "    out_of_mem: %lu\n",
			   /* convert from bytes to KiB */
			   object_size(pool) >> 10,
			   pool->opp_max_objects,
			   pool->opp_max_ptr_pages * PTRS_PER_PAGE,
			   pool->opp_total_objects,
			   pool->opp_free_objects,
			   pool->opp_idle_idx,
			   ktime_get_seconds() - pool->opp_last_shrink,
			   ktime_get_seconds() - pool->opp_last_access,
			   pool->opp_st_max_objects,
			   pool->opp_st_grows,
			   pool->opp_st_grow_fails,
			   pool->opp_st_shrinks,
			   pool->opp_st_access,
			   pool->opp_st_missings,
			   pool->opp_st_lowfree,
			   pool->opp_st_max_wqlen,
			   ktime_to_ms(pool->opp_st_max_wait),
			   pool->opp_st_outofmem);

		spin_unlock(&pool->opp_lock);
	}
	return 0;
}
EXPORT_SYMBOL(page_pools_seq_show);

static void pool_release_free_objects(long nobjects, struct obd_page_pool *pool)
{
	int p_idx, g_idx;
	int p_idx_max1, p_idx_max2;

	LASSERT(nobjects > 0);
	LASSERT(nobjects <= pool->opp_free_objects);
	LASSERT(pool->opp_free_objects <= pool->opp_total_objects);

	/* max pool index before the release */
	p_idx_max2 = (pool->opp_total_objects - 1) / PTRS_PER_PAGE;

	pool->opp_free_objects -= nobjects;
	pool->opp_total_objects -= nobjects;

	/* max pool index after the release */
	p_idx_max1 = pool->opp_total_objects == 0 ? -1 :
		((pool->opp_total_objects - 1) / PTRS_PER_PAGE);

	p_idx = pool->opp_free_objects / PTRS_PER_PAGE;
	g_idx = pool->opp_free_objects % PTRS_PER_PAGE;
	LASSERT(pool->opp_ptr_pages[p_idx]);

	while (nobjects--) {
		LASSERT(pool->opp_ptr_pages[p_idx]);
		LASSERT(pool->opp_ptr_pages[p_idx][g_idx] != NULL);

		if (pool->opp_order == 0)
			__free_page(pool->opp_ptr_pages[p_idx][g_idx]);
		else
			OBD_FREE_LARGE(pool->opp_ptr_pages[p_idx][g_idx],
				       object_size(pool));
		pool->opp_ptr_pages[p_idx][g_idx] = NULL;

		if (++g_idx == PTRS_PER_PAGE) {
			p_idx++;
			g_idx = 0;
		}
	}

	/* free unused ptr_pages */
	while (p_idx_max1 < p_idx_max2) {
		LASSERT(pool->opp_ptr_pages[p_idx_max2]);
		OBD_FREE(pool->opp_ptr_pages[p_idx_max2], PAGE_SIZE);
		pool->opp_ptr_pages[p_idx_max2] = NULL;
		p_idx_max2--;
	}
}

/*
 * we try to keep at least PTLRPC_MAX_BRW_PAGES pages in the pool.
 */
static unsigned long pool_shrink_count(struct shrinker *s,
				       struct shrink_control *sc)
{
	int pool_order;
	struct obd_page_pool *pool;
	unsigned long max_objects;

	pool_order = get_pool_index(s);
	pool = page_pools[pool_order];
	max_objects = PTLRPC_MAX_BRW_PAGES >> pool_order;

	/* Always have at least one element */
	if (max_objects == 0)
		max_objects = 1;

	/*
	 * if no pool access for a long time, we consider it's fully
	 * idle. A little race here is fine.
	 */
	if (pool->opp_idle_idx != IDLE_IDX_MAX &&
	    unlikely(ktime_get_seconds() - pool->opp_last_access >
		     CACHE_QUIESCENT_PERIOD)) {
		spin_lock(&pool->opp_lock);
		pool->opp_idle_idx = IDLE_IDX_MAX;
		spin_unlock(&pool->opp_lock);
	}
	LASSERT(pool->opp_idle_idx <= IDLE_IDX_MAX);

	return (pool->opp_free_objects <= max_objects) ? 0 :
		(pool->opp_free_objects - max_objects) *
		 pool->opp_idle_idx / IDLE_IDX_MAX;
}

/*
 * we try to keep at least PTLRPC_MAX_BRW_PAGES pages in the pool.
 */
static unsigned long pool_shrink_scan(struct shrinker *s,
				      struct shrink_control *sc)
{
	int pool_order;
	struct obd_page_pool *pool;
	unsigned long max_objects;

	pool_order = get_pool_index(s);
	pool = page_pools[pool_order];
	max_objects = PTLRPC_MAX_BRW_PAGES >> pool_order;
	/* Always have at least one element */
	if (max_objects == 0)
		max_objects = 1;

	spin_lock(&pool->opp_lock);
	if (pool->opp_free_objects <= max_objects)
		sc->nr_to_scan = 0;
	else
		sc->nr_to_scan = min_t(unsigned long, sc->nr_to_scan,
				       pool->opp_free_objects - max_objects);
	if (sc->nr_to_scan > 0) {
		pool_release_free_objects(sc->nr_to_scan, pool);
		pool->opp_st_shrinks++;
		pool->opp_last_shrink = ktime_get_seconds();
	}
	spin_unlock(&pool->opp_lock);
	if (sc->nr_to_scan > 0)
		CDEBUG(D_SEC, "released %lu objects, %ld left, order:%u\n",
		       sc->nr_to_scan, pool->opp_free_objects, pool->opp_order);

	return sc->nr_to_scan;
}

#ifndef HAVE_SHRINKER_COUNT
/*
 * could be called frequently for query (@nr_to_scan == 0).
 * we try to keep at least PTLRPC_MAX_BRW_PAGES pages in the pool.
 */
static int pool_shrink(struct shrinker *shrinker, struct shrink_control *sc)
{
	pool_shrink_scan(shrinker, sc);

	return pool_shrink_count(shrinker, sc);
}
#endif /* HAVE_SHRINKER_COUNT */

static inline
int nobjects_to_nptr_pages(unsigned long nobjects)
{
	return (int) ((nobjects + PTRS_PER_PAGE - 1) / PTRS_PER_PAGE);
}

/*
 * return how many objects cleaned up.
 */
static unsigned long pool_cleanup(void ***ptr_pages, int nptr_pages,
				  struct obd_page_pool *pool)
{
	unsigned long cleaned = 0;
	int i, j;

	for (i = 0; i < nptr_pages; i++) {
		if (ptr_pages[i]) {
			for (j = 0; j < PTRS_PER_PAGE; j++) {
				if (ptr_pages[i][j]) {
					if (pool->opp_order == 0) {
						__free_page(ptr_pages[i][j]);
					} else {
						OBD_FREE_LARGE(ptr_pages[i][j],
							object_size(pool));
					}
					cleaned++;
				}
			}
			OBD_FREE(ptr_pages[i], PAGE_SIZE);
			ptr_pages[i] = NULL;
		}
	}

	return cleaned;
}

/*
 * merge @nptr_objects pointed by @ptr_pages which contains @nobjects
 * new objects into current pool.
 *
 * we have options to avoid most memory copy with some tricks. but we choose
 * the simplest way to avoid complexity. It's not frequently called.
 */
static void pool_insert_ptrs(void ***ptr_pages, int nptr_pages, int nobjects,
			     struct obd_page_pool *page_pool)
{
	int freeslot;
	int op_idx, np_idx, og_idx, ng_idx;
	int cur_nptr_page, end_nptr_page;

	LASSERT(nobjects > 0);
	LASSERT(page_pool->opp_total_objects + nobjects <=
					page_pool->opp_max_objects);
	LASSERT(nobjects_to_nptr_pages(nobjects) == nptr_pages);
	LASSERT(page_pool->opp_growing);

	spin_lock(&page_pool->opp_lock);

	/*
	 * (1) fill all the free slots in current pool ptr_pages
	 */
	/*
	 * free slots are those left by rent pages, and the extra ones with
	 * index >= total_pages, locate at the tail of last pool.
	 */
	freeslot = page_pool->opp_total_objects % PTRS_PER_PAGE;
	if (freeslot != 0)
		freeslot = PTRS_PER_PAGE - freeslot;
	freeslot += page_pool->opp_total_objects - page_pool->opp_free_objects;

	op_idx = page_pool->opp_free_objects / PTRS_PER_PAGE;
	og_idx = page_pool->opp_free_objects % PTRS_PER_PAGE;
	np_idx = nptr_pages - 1;
	ng_idx = (nobjects - 1) % PTRS_PER_PAGE;

	while (freeslot) {
		LASSERT(page_pool->opp_ptr_pages[op_idx][og_idx] == NULL);
		LASSERT(ptr_pages[np_idx][ng_idx] != NULL);

		page_pool->opp_ptr_pages[op_idx][og_idx] =
			ptr_pages[np_idx][ng_idx];
		ptr_pages[np_idx][ng_idx] = NULL;

		freeslot--;

		if (++og_idx == PTRS_PER_PAGE) {
			op_idx++;
			og_idx = 0;
		}
		if (--ng_idx < 0) {
			if (np_idx == 0)
				break;
			np_idx--;
			ng_idx = PTRS_PER_PAGE - 1;
		}
	}

	/*
	 * (2) add ptr pages if needed.
	 */
	cur_nptr_page = (page_pool->opp_total_objects + PTRS_PER_PAGE - 1) /
		      PTRS_PER_PAGE;
	end_nptr_page = (page_pool->opp_total_objects + nobjects +
		      PTRS_PER_PAGE - 1) / PTRS_PER_PAGE;
	LASSERT(end_nptr_page <= page_pool->opp_max_ptr_pages);

	np_idx = 0;
	while (cur_nptr_page < end_nptr_page) {
		LASSERT(page_pool->opp_ptr_pages[cur_nptr_page] == NULL);
		LASSERT(np_idx < nptr_pages);
		LASSERT(ptr_pages[np_idx] != NULL);

		page_pool->opp_ptr_pages[cur_nptr_page++] = ptr_pages[np_idx];
		ptr_pages[np_idx++] = NULL;
	}

	/*
	 * (3) free useless source ptr pages
	 */
	while (np_idx < nptr_pages) {
		LASSERT(ptr_pages[np_idx] != NULL);
		CDEBUG(D_SEC, "Free useless ptr pages: %i, %p\n", np_idx,
		       ptr_pages[np_idx]);
		OBD_FREE(ptr_pages[np_idx], PAGE_SIZE);
		ptr_pages[np_idx++] = NULL;
	}

	page_pool->opp_total_objects += nobjects;
	page_pool->opp_free_objects += nobjects;
	page_pool->opp_st_lowfree = page_pool->opp_free_objects;

	if (page_pool->opp_total_objects > page_pool->opp_st_max_objects)
		page_pool->opp_st_max_objects = page_pool->opp_total_objects;

	CDEBUG(D_SEC, "add %d pages to total %lu\n", nobjects,
	       page_pool->opp_total_objects);

	spin_unlock(&page_pool->opp_lock);
}

#define POOL_INIT_SIZE (PTLRPC_MAX_BRW_SIZE / 4)
static int pool_add_objects(int nobjects, struct obd_page_pool *page_pool)
{
	void ***ptr_pages;
	int nptr_pages, alloced = 0;
	int i, j, rc = -ENOMEM;
	unsigned int pool_order = page_pool->opp_order;

	if (nobjects < POOL_INIT_SIZE / object_size(page_pool))
		nobjects = POOL_INIT_SIZE / object_size(page_pool);

	mutex_lock(&page_pool->add_pages_mutex);

	if (nobjects + page_pool->opp_total_objects >
					page_pool->opp_max_objects) {
		nobjects = page_pool->opp_max_objects -
			page_pool->opp_total_objects;
	}
	LASSERT(nobjects > 0);

	page_pool->opp_st_grows++;

	nptr_pages = nobjects_to_nptr_pages(nobjects);
	OBD_ALLOC_PTR_ARRAY(ptr_pages, nptr_pages);
	if (ptr_pages == NULL)
		goto out;

	for (i = 0; i < nptr_pages; i++) {
		OBD_ALLOC(ptr_pages[i], PAGE_SIZE);
		if (ptr_pages[i] == NULL)
			goto out_ptr_pages;

		for (j = 0; j < PTRS_PER_PAGE && alloced < nobjects; j++) {
			if (pool_order == 0)
				ptr_pages[i][j] = alloc_page(GFP_NOFS |
					__GFP_HIGHMEM);
			else {
				OBD_ALLOC_LARGE(ptr_pages[i][j],
					object_size(page_pool));
			}
			if (ptr_pages[i][j] == NULL)
				goto out_ptr_pages;

			alloced++;
		}
	}
	LASSERT(alloced == nobjects);

	pool_insert_ptrs(ptr_pages, nptr_pages, nobjects, page_pool);
	CDEBUG(D_SEC, "added %d elements into pool:%d\n", nobjects, pool_order);
	OBD_FREE_PTR_ARRAY(ptr_pages, nptr_pages);
	rc = 0;

out_ptr_pages:
	if (rc) {
		pool_cleanup(ptr_pages, nptr_pages, page_pool);
	}
out:
	if (rc) {
		page_pool->opp_st_grow_fails++;
		CERROR("Failed to allocate %d objects: rc = %d\n", nobjects, rc);
	}

	mutex_unlock(&page_pool->add_pages_mutex);
	return rc;
}

static inline void pool_wakeup(struct obd_page_pool *pool)
{
	assert_spin_locked(&pool->opp_lock);

	/* waitqueue_active */
	if (unlikely(waitqueue_active(&pool->opp_waitq)))
		wake_up_all(&pool->opp_waitq);
}

static int pool_should_grow(int needed, struct obd_page_pool *pool)
{
	/*
	 * don't grow if someone else is growing the pool right now,
	 * or the pool has reached its full capacity
	 */
	if (pool->opp_growing ||
	    pool->opp_total_objects == pool->opp_max_objects)
		return 0;

	/* if total objects is not enough, we need to grow */
	if (pool->opp_total_objects < needed)
		return 1;
	/*
	 * we wanted to return 0 here if there was a shrink just
	 * happened a moment ago, but this may cause deadlock if both
	 * client and ost live on single node.
	 */

	/*
	 * here we perhaps need consider other factors like wait queue
	 * length, idle index, etc. ?
	 */

	/* grow the pool in any other cases */
	return 1;
}

/*
 * Export the number of free objects in the pool of 'order'
 */
int obd_pool_get_free_objects(unsigned int order)
{
	return page_pools[order]->opp_free_objects;
}
EXPORT_SYMBOL(obd_pool_get_free_objects);

/*
 * Let outside world know if pool full capacity is reached
 */
int pool_is_at_full_capacity(int order)
{
	return (page_pools[order]->opp_total_objects ==
		page_pools[order]->opp_max_objects);
}
EXPORT_SYMBOL(pool_is_at_full_capacity);

static inline void **page_from_bulkdesc(void *array, int index)
{
	struct ptlrpc_bulk_desc *desc = (struct ptlrpc_bulk_desc *)array;

	return (void **)&desc->bd_enc_vec[index].bv_page;
}

static inline void **page_from_pagearray(void *array, int index)
{
	struct page **pa = (struct page **)array;

	return (void **)&pa[index];
}

static inline void **object_from_bufarray(void *array, int index)
{
	return (void **)array;
}

static bool __grow_pool_try(int needed, struct obd_page_pool *pool);

/*
 * we allocate the requested objects atomically.
 */
static inline int __obd_pool_get_objects(void *array, unsigned int count,
				       unsigned int order,
				       void **(*object_from)(void *, int))
{
	struct obd_page_pool *page_pool = page_pools[order];
	wait_queue_entry_t waitlink;
	unsigned long this_idle = -1;
	u64 tick_ns = 0;
	int p_idx, g_idx;
	int i, rc = 0;

	if (!array || count <= 0 || count > page_pool->opp_max_objects)
		return -EINVAL;

	spin_lock(&page_pool->opp_lock);

	page_pool->opp_st_access++;
again:
	if (unlikely(page_pool->opp_free_objects < count)) {
		if (tick_ns == 0)
			tick_ns = ktime_get_ns();

		page_pool->opp_st_missings++;
		page_pool->opp_pages_short += count;

		/* if we aren't able to add objects, check if someone else is
		 * growing the pool and sleep if so, otherwise we return
		 * ENOMEM because we can't sleep here waiting for other ops to
		 * complete (main user is ptlrpcd, which must not sleep waiting
		 * for other ops...  technically sleeping for pool growth is
		 * also questionable but it's very unlikely in practice to get
		 * stuck from this)
		 *
		 * if ENOMEM is returned here, the RPC will go back in the queue
		 */
		if (!__grow_pool_try(count, page_pool)) {
			if (page_pool->opp_growing) {
				if (++page_pool->opp_waitqlen >
				    page_pool->opp_st_max_wqlen)
					page_pool->opp_st_max_wqlen =
						page_pool->opp_waitqlen;

				set_current_state(TASK_UNINTERRUPTIBLE);
				init_wait(&waitlink);
				add_wait_queue(&page_pool->opp_waitq,
					       &waitlink);

				spin_unlock(&page_pool->opp_lock);
				schedule();
				remove_wait_queue(&page_pool->opp_waitq,
						  &waitlink);
				spin_lock(&page_pool->opp_lock);
				page_pool->opp_waitqlen--;
			} else {
				/*
				 * ptlrpcd thread should not sleep in that
				 * case or deadlock may occur!
				 * Instead, return -ENOMEM so that upper layers
				 * will put request back in queue.
				 */
				page_pool->opp_st_outofmem++;
				GOTO(out_unlock, rc = -ENOMEM);
			}
		}

		if (page_pool->opp_pages_short < count)
			GOTO(out_unlock, rc = -EPROTO);
		page_pool->opp_pages_short -= count;

		this_idle = 0;
		goto again;
	}

	/* record max wait time */
	if (unlikely(tick_ns)) {
		ktime_t tick = ktime_sub_ns(ktime_get(), tick_ns);

		if (ktime_after(tick, page_pool->opp_st_max_wait))
			page_pool->opp_st_max_wait = tick;
	}

	/* proceed with rest of allocation */
	page_pool->opp_free_objects -= count;

	p_idx = page_pool->opp_free_objects / PTRS_PER_PAGE;
	g_idx = page_pool->opp_free_objects % PTRS_PER_PAGE;

	for (i = 0; i < count; i++) {
		void **objp = object_from(array, i);

		if (page_pool->opp_ptr_pages[p_idx][g_idx] == NULL)
			GOTO(out_unlock, rc = -EPROTO);
		*objp = page_pool->opp_ptr_pages[p_idx][g_idx];
		page_pool->opp_ptr_pages[p_idx][g_idx] = NULL;

		if (++g_idx == PTRS_PER_PAGE) {
			p_idx++;
			g_idx = 0;
		}
	}

	if (page_pool->opp_free_objects < page_pool->opp_st_lowfree)
		page_pool->opp_st_lowfree =
			page_pool->opp_free_objects;

	/*
	 * new idle index = (old * weight + new) / (weight + 1)
	 */
	if (this_idle == -1) {
		this_idle = page_pool->opp_free_objects * IDLE_IDX_MAX /
			page_pool->opp_total_objects;
	}
	page_pool->opp_idle_idx = (page_pool->opp_idle_idx *
			IDLE_IDX_WEIGHT + this_idle) /
			(IDLE_IDX_WEIGHT + 1);

	page_pool->opp_last_access = ktime_get_seconds();

out_unlock:
	spin_unlock(&page_pool->opp_lock);
	return rc;
}

int obd_pool_get_desc_pages(struct ptlrpc_bulk_desc *desc)
{
	int rc;

	LASSERT(desc->bd_iov_count > 0);
	LASSERT(desc->bd_iov_count <= page_pools[0]->opp_max_objects);

	/* resent bulk, enc iov might have been allocated previously */
	if (desc->bd_enc_vec != NULL)
		return 0;

	OBD_ALLOC_LARGE(desc->bd_enc_vec,
			desc->bd_iov_count * sizeof(*desc->bd_enc_vec));
	if (desc->bd_enc_vec == NULL)
		return -ENOMEM;

	rc = __obd_pool_get_objects((void *)desc, desc->bd_iov_count, 0,
				      page_from_bulkdesc);
	if (rc) {
		OBD_FREE_LARGE(desc->bd_enc_vec,
			       desc->bd_iov_count *
			       sizeof(*desc->bd_enc_vec));
		desc->bd_enc_vec = NULL;
	}
	return rc;
}
EXPORT_SYMBOL(obd_pool_get_desc_pages);

int obd_pool_get_pages_array(struct page **pa, unsigned int count)
{
	return __obd_pool_get_objects((void *)pa, count, 0,
					page_from_pagearray);
}
EXPORT_SYMBOL(obd_pool_get_pages_array);

/* get 2^order pages region */
int obd_pool_get_objects(void **pages, unsigned int order)
{
	return __obd_pool_get_objects((void *)pages, 1, order,
					object_from_bufarray);
}
EXPORT_SYMBOL(obd_pool_get_objects);

static int __obd_pool_put_objects(void *array, unsigned int count,
				    unsigned int order,
				    void **(*object_from)(void *, int))
{
	struct obd_page_pool *page_pool;
	unsigned long this_idle;
	int p_idx, g_idx;
	int i, rc = 0;

	LASSERTF(order < POOLS_COUNT, "count %u, pool %u\n",
		 count, order);
	if (!array) {
		CERROR("Faled to put %u objects, from pool %u\n",
		       count, order);
		return -EINVAL;
	}

	page_pool = page_pools[order];
	LASSERTF(page_pool != NULL, "count %u, pool %u\n", count, order);

	spin_lock(&page_pool->opp_lock);

	p_idx = page_pool->opp_free_objects / PTRS_PER_PAGE;
	g_idx = page_pool->opp_free_objects % PTRS_PER_PAGE;

	if (page_pool->opp_free_objects + count > page_pool->opp_total_objects)
		GOTO(out_unlock, rc = -EPROTO);
	if (!page_pool->opp_ptr_pages[p_idx])
		GOTO(out_unlock, rc = -EPROTO);

	for (i = 0; i < count; i++) {
		void **objp = object_from(array, i);

		if (!*objp ||
		    page_pool->opp_ptr_pages[p_idx][g_idx] != NULL)
			GOTO(out_unlock, rc = -EPROTO);

		page_pool->opp_ptr_pages[p_idx][g_idx] = *objp;
		if (++g_idx == PTRS_PER_PAGE) {
			p_idx++;
			g_idx = 0;
		}
	}

	page_pool->opp_free_objects += count;
	pool_wakeup(page_pool);

	/*
	 * Recalculate opp_idle_idx in __sptlrpc_pool_put_pages the
	 * same way as it done in __sptlrpc_pool_get_pages. It is
	 * possible that opp_idle_idx might become 0 or very small
	 * (less than 10). If there is no new allocations it would
	 * be impossible to free anything from the pool during 40
	 * seconds(CACHE_QUIESCENT_PERIOD) despite the large amount
	 * of free elements ready to shrinking.
	 */
	this_idle = page_pool->opp_free_objects * IDLE_IDX_MAX /
		page_pool->opp_total_objects;
	page_pool->opp_idle_idx = (page_pool->opp_idle_idx *
			IDLE_IDX_WEIGHT + this_idle) /
			(IDLE_IDX_WEIGHT + 1);

out_unlock:
	spin_unlock(&page_pool->opp_lock);
	return rc;
}

void obd_pool_put_desc_pages(struct ptlrpc_bulk_desc *desc)
{
	int rc;

	if (desc->bd_enc_vec == NULL)
		return;

	rc = __obd_pool_put_objects((void *)desc, desc->bd_iov_count, 0,
				      page_from_bulkdesc);
	if (rc)
		CDEBUG(D_SEC, "error putting pages in pool: %d\n", rc);

	OBD_FREE_LARGE(desc->bd_enc_vec,
		       desc->bd_iov_count * sizeof(*desc->bd_enc_vec));
	desc->bd_enc_vec = NULL;
}
EXPORT_SYMBOL(obd_pool_put_desc_pages);

void obd_pool_put_pages_array(struct page **pa, unsigned int count)
{
	int rc;

	rc = __obd_pool_put_objects((void *)pa, count, 0, page_from_pagearray);

	if (rc)
		CDEBUG(D_SEC, "error putting pages in pool: %d\n", rc);
}
EXPORT_SYMBOL(obd_pool_put_pages_array);

/* put 2^order pages region */
void obd_pool_put_objects(void *buf, unsigned int order)
{
	int rc;

	rc = __obd_pool_put_objects(buf, 1, order, object_from_bufarray);
	if (rc)
		CDEBUG(D_SEC, "error putting objects in pool: %d\n", rc);
}
EXPORT_SYMBOL(obd_pool_put_objects);

/* called with pool->opp_lock held */
static bool __grow_pool_try(int needed, struct obd_page_pool *pool)
{
	bool pool_grown = false;

	assert_spin_locked(&pool->opp_lock);

	if (pool_should_grow(needed, pool)) {
		unsigned int to_add;
		int rc;

		pool->opp_growing = 1;
		/* the pool of single pages is grown a large amount on
		 * first use
		 */
		if (pool->opp_order == 0 &&
		    pool->opp_total_objects == 0)
			to_add = PTLRPC_MAX_BRW_PAGES * 2;
		else /* otherwise, we add requested or at least 8 items */
			to_add = max(needed, 8);
		spin_unlock(&pool->opp_lock);

		CDEBUG(D_SEC,
		       "pool %d is %lu elements (size %d bytes), growing by %d items\n",
			pool->opp_order, pool->opp_pages_short,
			object_size(pool), to_add);
		/* we can't hold a spinlock over page allocation */
		rc = pool_add_objects(to_add, pool);
		if (rc == 0)
			pool_grown = true;

		spin_lock(&pool->opp_lock);
		pool->opp_growing = 0;
		pool_wakeup(pool);
	}

	return pool_grown;
}

static bool grow_pool_try(int needed, struct obd_page_pool *pool)
{
	bool rc;

	spin_lock(&pool->opp_lock);
	rc = __grow_pool_try(needed, pool);
	spin_unlock(&pool->opp_lock);

	return rc;
}

/*
 * we don't do much stuff for add_user/del_user anymore, except adding some
 * initial pages in add_user() if current pool is empty, rest would be
 * handled by the pool self-adaption.
 */
void obd_pool_add_user(void)
{
	struct obd_page_pool *pool = page_pools[0];

	/* since this is startup, no one is waiting for these pages, so we
	 * don't worry about sucess or failure here
	 */
	grow_pool_try(1, pool);
}
EXPORT_SYMBOL(obd_pool_add_user);

static inline void pool_ptrs_alloc(struct obd_page_pool *pool)
{
	LASSERT(pool->opp_max_ptr_pages);
	OBD_ALLOC_LARGE(pool->opp_ptr_pages,
			pool->opp_max_ptr_pages *
			sizeof(*pool->opp_ptr_pages));
}

static inline void pool_ptrs_free(struct obd_page_pool *pool)
{
	LASSERT(pool->opp_max_ptr_pages);
	LASSERT(pool->opp_ptr_pages);

	OBD_FREE_LARGE(pool->opp_ptr_pages,
		       pool->opp_max_ptr_pages * sizeof(*pool->opp_ptr_pages));
}

int obd_pool_init(void)
{
	struct obd_page_pool *pool;
	int pool_max_pages = cfs_totalram_pages() / POOLS_COUNT;
	int pool_order = 0;
	int to_revert;
	int rc = 0;

	ENTRY;

	if (pool_max_memory_mb == 0 && enc_pool_max_memory_mb > 0)
		pool_max_memory_mb = enc_pool_max_memory_mb;
	if (pool_max_memory_mb > 0 &&
		pool_max_memory_mb <= PAGES_TO_MiB(cfs_totalram_pages()))
		pool_max_pages = MiB_TO_PAGES(pool_max_memory_mb);

	OBD_ALLOC(page_pools, POOLS_COUNT * sizeof(*page_pools));
	if (page_pools == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC(pool_shrinkers, POOLS_COUNT * sizeof(*pool_shrinkers));
	if (pool_shrinkers == NULL)
		GOTO(fail2, rc = -ENOMEM);

	for (pool_order = 0; pool_order < POOLS_COUNT; pool_order++) {
		OBD_ALLOC(page_pools[pool_order], sizeof(**page_pools));
		if (page_pools[pool_order] == NULL)
			GOTO(fail, rc = -ENOMEM);

		pool = page_pools[pool_order];
		pool->opp_max_objects = pool_max_pages >> pool_order;

		pool->opp_max_ptr_pages =
			nobjects_to_nptr_pages(pool->opp_max_objects);

		init_waitqueue_head(&pool->opp_waitq);
		pool->opp_last_shrink = ktime_get_seconds();
		pool->opp_last_access = ktime_get_seconds();

		spin_lock_init(&pool->opp_lock);
		pool->opp_st_max_wait = ktime_set(0, 0);

		pool_ptrs_alloc(pool);
		pool->opp_order = pool_order;
		CDEBUG(D_SEC, "Allocated pool %i\n", pool_order);
		if (pool->opp_ptr_pages == NULL)
			GOTO(fail, rc = -ENOMEM);
		/* Pass pool number as part of pool_shrinker_seeks value */
#ifdef HAVE_SHRINKER_COUNT
		pool->opp_shops.count_objects = pool_shrink_count;
		pool->opp_shops.scan_objects = pool_shrink_scan;
#else
		pool->opp_shops.shrink = pool_shrink;
		pool->opp_shops.seeks = DEFAULT_SEEKS;
#endif
		pool->pool_shrinker = ll_shrinker_create(&pool->opp_shops, 0,
							 "obd_pool");
		if (IS_ERR(pool->pool_shrinker))
			GOTO(fail, rc = PTR_ERR(pool->pool_shrinker));

		pool_shrinkers[pool_order] = pool->pool_shrinker;
		mutex_init(&pool->add_pages_mutex);
	}

	RETURN(0);

fail:
	to_revert = pool_order;
	for (pool_order = 0; pool_order <= to_revert; pool_order++) {
		pool = page_pools[pool_order];
		if (pool) {
			if (pool->opp_ptr_pages)
				pool_ptrs_free(pool);
			OBD_FREE(pool, sizeof(**page_pools));
		}
	}
	OBD_FREE(pool_shrinkers, POOLS_COUNT * sizeof(*pool_shrinkers));

fail2:
	OBD_FREE(page_pools, POOLS_COUNT * sizeof(*page_pools));
	RETURN(rc);
}
EXPORT_SYMBOL(obd_pool_init);

void obd_pool_fini(void)
{
	unsigned long cleaned, nptr_pages;
	int pool_order;
	struct obd_page_pool *pool;

	for (pool_order = 0; pool_order < POOLS_COUNT; pool_order++) {
		pool = page_pools[pool_order];
		shrinker_free(pool->pool_shrinker);
		LASSERT(pool->opp_ptr_pages);
		LASSERT(pool->opp_total_objects == pool->opp_free_objects);

		nptr_pages = nobjects_to_nptr_pages(pool->opp_total_objects);
		cleaned = pool_cleanup(pool->opp_ptr_pages, nptr_pages, pool);
		LASSERT(cleaned == pool->opp_total_objects);

		pool_ptrs_free(pool);

		if (pool->opp_st_access > 0) {
			CDEBUG(D_SEC,
			       "max objects %lu, grows %u, grow fails %u, shrinks %u, access %lu, missing %lu, max qlen %u, max wait ms %lld, out of mem %lu\n",
			       pool->opp_st_max_objects,
			       pool->opp_st_grows,
			       pool->opp_st_grow_fails,
			       pool->opp_st_shrinks,
			       pool->opp_st_access,
			       pool->opp_st_missings,
			       pool->opp_st_max_wqlen,
			       ktime_to_ms(pool->opp_st_max_wait),
			       pool->opp_st_outofmem);
		}

		OBD_FREE(pool, sizeof(**page_pools));
	}

	OBD_FREE(page_pools, POOLS_COUNT * sizeof(*page_pools));
	OBD_FREE(pool_shrinkers, POOLS_COUNT * sizeof(*pool_shrinkers));
}
EXPORT_SYMBOL(obd_pool_fini);
