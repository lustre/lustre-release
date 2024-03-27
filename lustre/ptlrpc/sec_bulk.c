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
 * lustre/ptlrpc/sec_bulk.c
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/linux/linux-mem.h>

#include <obd.h>
#include <obd_cksum.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

#define PPOOL_MIN_CHUNK_BITS 16 /* 2^16 bytes = 64KiB */
#define PPOOL_MAX_CHUNK_BITS PTLRPC_MAX_BRW_BITS
#define POOLS_COUNT (PPOOL_MAX_CHUNK_BITS - PPOOL_MIN_CHUNK_BITS + 1)
#define PPOOL_ORDER_TO_INDEX(bits) ((bits) - PPOOL_MIN_CHUNK_BITS + 1)
#define POOL_BITS(pool) ((pool) + PPOOL_MIN_CHUNK_BITS - 1)
#define ELEMENT_SIZE(pool) (1 << (PPOOL_MIN_CHUNK_BITS + (pool) - 1))
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
#define PAGES_PER_POOL  (PTRS_PER_PAGE)

#define IDLE_IDX_MAX            (100)
#define IDLE_IDX_WEIGHT         (3)

#define CACHE_QUIESCENT_PERIOD  (20)

static struct ptlrpc_page_pool {
	unsigned long ppp_max_pages;   /* maximum pages can hold, const */
	unsigned int ppp_max_pools;   /* number of pools, const */

	/*
	 * wait queue in case of not enough free pages.
	 */
	wait_queue_head_t ppp_waitq;   /* waiting threads */
	unsigned int ppp_waitqlen;    /* wait queue length */
	unsigned long ppp_pages_short; /* # of pages wanted of in-q users */
	unsigned int ppp_growing:1;   /* during adding pages */

	/*
	 * indicating how idle the pools are, from 0 to MAX_IDLE_IDX
	 * this is counted based on each time when getting pages from
	 * the pools, not based on time. which means in case that system
	 * is idled for a while but the idle_idx might still be low if no
	 * activities happened in the pools.
	 */
	unsigned long ppp_idle_idx;

	/* last shrink time due to mem tight */
	time64_t ppp_last_shrink;
	time64_t ppp_last_access;

	/* in-pool pages bookkeeping */
	spinlock_t ppp_lock; /* protect following fields */
	unsigned long ppp_total_pages; /* total pages in pools */
	unsigned long ppp_free_pages;  /* current pages available */

	/* statistics */
	unsigned long ppp_st_max_pages;      /* # of pages ever reached */
	unsigned int ppp_st_grows;          /* # of grows */
	unsigned int ppp_st_grow_fails;     /* # of add pages failures */
	unsigned int ppp_st_shrinks;        /* # of shrinks */
	unsigned long ppp_st_access;         /* # of access */
	unsigned long ppp_st_missings;       /* # of cache missing */
	unsigned long ppp_st_lowfree;        /* lowest free pages reached */
	unsigned int ppp_st_max_wqlen;      /* highest waitqueue length */
	ktime_t ppp_st_max_wait; /* in nanoseconds */
	unsigned long ppp_st_outofmem; /* # of out of mem requests */
	/*
	 * pointers to pools, may be vmalloc'd
	 */
	void ***ppp_pools;
	/*
	 * memory shrinker
	 */
	struct ll_shrinker_ops ppp_shops;
	struct shrinker *pool_shrinker;
	struct mutex add_pages_mutex;
} **page_pools;

/*
 * Keep old name (encrypt_page_pool vs page_pool) for compatibility with user
 * tools pulling stats
 *
 * /sys/kernel/debug/lustre/sptlrpc/encrypt_page_pools
 */
int encrypt_page_pools_seq_show(struct seq_file *m, void *v)
{
	struct ptlrpc_page_pool *pool = page_pools[PAGES_POOL];

	spin_lock(&pool->ppp_lock);
	seq_printf(m, "physical pages:          %lu\n"
		"pages per pool:          %lu\n"
		"max pages:               %lu\n"
		"max pools:               %u\n"
		"total pages:             %lu\n"
		"total free:              %lu\n"
		"idle index:              %lu/100\n"
		"last shrink:             %llds\n"
		"last access:             %llds\n"
		"max pages reached:       %lu\n"
		"grows:                   %u\n"
		"grows failure:           %u\n"
		"shrinks:                 %u\n"
		"cache access:            %lu\n"
		"cache missing:           %lu\n"
		"low free mark:           %lu\n"
		"max waitqueue depth:     %u\n"
		"max wait time ms:        %lld\n"
		"out of mem:              %lu\n",
		cfs_totalram_pages(), PAGES_PER_POOL,
		pool->ppp_max_pages,
		pool->ppp_max_pools,
		pool->ppp_total_pages,
		pool->ppp_free_pages,
		pool->ppp_idle_idx,
		ktime_get_seconds() - pool->ppp_last_shrink,
		ktime_get_seconds() - pool->ppp_last_access,
		pool->ppp_st_max_pages,
		pool->ppp_st_grows,
		pool->ppp_st_grow_fails,
		pool->ppp_st_shrinks,
		pool->ppp_st_access,
		pool->ppp_st_missings,
		pool->ppp_st_lowfree,
		pool->ppp_st_max_wqlen,
		ktime_to_ms(pool->ppp_st_max_wait),
		pool->ppp_st_outofmem);
	spin_unlock(&pool->ppp_lock);

	return 0;
}

/*
 * /sys/kernel/debug/lustre/sptlrpc/page_pools
 */
int page_pools_seq_show(struct seq_file *m, void *v)
{
	int pool_index;
	struct ptlrpc_page_pool *pool;

	seq_printf(m, "physical_pages: %lu\n"
		      "pages per pool: %lu\n\n"
		      "pools:\n",
		      cfs_totalram_pages(), PAGES_PER_POOL);

	for (pool_index = 0; pool_index < POOLS_COUNT; pool_index++) {
		pool = page_pools[pool_index];
		if (!pool->ppp_st_access)
			continue;
		spin_lock(&pool->ppp_lock);
		seq_printf(m, "  pool_%luk:\n"
			   "    max_pages: %lu\n"
			   "    max_pools: %u\n"
			   "    total_pages: %lu\n"
			   "    total_free: %lu\n"
			   "    idle_index: %lu/100\n"
			   "    last_shrink: %llds\n"
			   "    last_access: %llds\n"
			   "    max_pages_reached: %lu\n"
			   "    grows: %u\n"
			   "    grows_failure: %u\n"
			   "    shrinks: %u\n"
			   "    cache_access: %lu\n"
			   "    cache_missing: %lu\n"
			   "    low_free_mark: %lu\n"
			   "    max_waitqueue_depth: %u\n"
			   "    max_wait_time_ms: %lld\n"
			   "    out_of_mem: %lu\n",
			   (pool_index ? ELEMENT_SIZE(pool_index - 10) :
			   PAGE_SIZE >> 10),
			   pool->ppp_max_pages,
			   pool->ppp_max_pools,
			   pool->ppp_total_pages,
			   pool->ppp_free_pages,
			   pool->ppp_idle_idx,
			   ktime_get_seconds() - pool->ppp_last_shrink,
			   ktime_get_seconds() - pool->ppp_last_access,
			   pool->ppp_st_max_pages,
			   pool->ppp_st_grows,
			   pool->ppp_st_grow_fails,
			   pool->ppp_st_shrinks,
			   pool->ppp_st_access,
			   pool->ppp_st_missings,
			   pool->ppp_st_lowfree,
			   pool->ppp_st_max_wqlen,
			   ktime_to_ms(pool->ppp_st_max_wait),
			   pool->ppp_st_outofmem);

		spin_unlock(&pool->ppp_lock);
	}
	return 0;
}

static void pool_release_free_pages(long npages, unsigned int pool_idx)
{
	int p_idx, g_idx;
	int p_idx_max1, p_idx_max2;
	struct ptlrpc_page_pool *pool = page_pools[pool_idx];

	LASSERT(npages > 0);
	LASSERT(npages <= pool->ppp_free_pages);
	LASSERT(pool->ppp_free_pages <= pool->ppp_total_pages);

	/* max pool index before the release */
	p_idx_max2 = (pool->ppp_total_pages - 1) / PAGES_PER_POOL;

	pool->ppp_free_pages -= npages;
	pool->ppp_total_pages -= npages;

	/* max pool index after the release */
	p_idx_max1 = pool->ppp_total_pages == 0 ? -1 :
		((pool->ppp_total_pages - 1) / PAGES_PER_POOL);

	p_idx = pool->ppp_free_pages / PAGES_PER_POOL;
	g_idx = pool->ppp_free_pages % PAGES_PER_POOL;
	LASSERT(pool->ppp_pools[p_idx]);

	while (npages--) {
		LASSERT(pool->ppp_pools[p_idx]);
		LASSERT(pool->ppp_pools[p_idx][g_idx] != NULL);

		if (pool_idx == PAGES_POOL)
			__free_page(pool->ppp_pools[p_idx][g_idx]);
		else
			OBD_FREE_LARGE(pool->ppp_pools[p_idx][g_idx],
				       ELEMENT_SIZE(pool_idx));
		pool->ppp_pools[p_idx][g_idx] = NULL;

		if (++g_idx == PAGES_PER_POOL) {
			p_idx++;
			g_idx = 0;
		}
	}

	/* free unused pools */
	while (p_idx_max1 < p_idx_max2) {
		LASSERT(pool->ppp_pools[p_idx_max2]);
		OBD_FREE(pool->ppp_pools[p_idx_max2], PAGE_SIZE);
		pool->ppp_pools[p_idx_max2] = NULL;
		p_idx_max2--;
	}
}

#define SEEKS_TO_INDEX(s) (((s)->seeks >> 8) & 0xff)
#define INDEX_TO_SEEKS(i) (DEFAULT_SEEKS | (i << 8))
/*
 * we try to keep at least PTLRPC_MAX_BRW_PAGES pages in the pool.
 */
static unsigned long pool_shrink_count(struct shrinker *s,
				       struct shrink_control *sc)
{
	unsigned int pool_index = SEEKS_TO_INDEX(s);
	struct ptlrpc_page_pool *pool = page_pools[pool_index];
	/*
	 * if no pool access for a long time, we consider it's fully
	 * idle. A little race here is fine.
	 */
	if (unlikely(ktime_get_seconds() - pool->ppp_last_access >
		     CACHE_QUIESCENT_PERIOD)) {
		spin_lock(&pool->ppp_lock);
		pool->ppp_idle_idx = IDLE_IDX_MAX;
		spin_unlock(&pool->ppp_lock);
	}

	LASSERT(pool->ppp_idle_idx <= IDLE_IDX_MAX);

	return (pool->ppp_free_pages <= PTLRPC_MAX_BRW_PAGES) ? 0 :
		(pool->ppp_free_pages - PTLRPC_MAX_BRW_PAGES) *
		(IDLE_IDX_MAX - pool->ppp_idle_idx) / IDLE_IDX_MAX;
}

/*
 * we try to keep at least PTLRPC_MAX_BRW_PAGES pages in the pool.
 */
static unsigned long pool_shrink_scan(struct shrinker *s,
				      struct shrink_control *sc)
{
	/* Get pool number passed as part of pool_shrinker_seeks value */
	unsigned int pool_index = SEEKS_TO_INDEX(s);
	struct ptlrpc_page_pool *pool = page_pools[pool_index];

	spin_lock(&pool->ppp_lock);
	if (pool->ppp_free_pages <= PTLRPC_MAX_BRW_PAGES)
		sc->nr_to_scan = 0;
	else
		sc->nr_to_scan = min_t(unsigned long, sc->nr_to_scan,
			      pool->ppp_free_pages - PTLRPC_MAX_BRW_PAGES);
	if (sc->nr_to_scan > 0) {
		pool_release_free_pages(sc->nr_to_scan, pool_index);
		CDEBUG(D_SEC, "released %ld pages, %ld left\n",
		       (long)sc->nr_to_scan, pool->ppp_free_pages);

		pool->ppp_st_shrinks++;
		pool->ppp_last_shrink = ktime_get_seconds();
	}
	spin_unlock(&pool->ppp_lock);

	/*
	 * if no pool access for a long time, we consider it's fully idle.
	 * a little race here is fine.
	 */
	if (unlikely(ktime_get_seconds() - pool->ppp_last_access >
		     CACHE_QUIESCENT_PERIOD)) {
		spin_lock(&pool->ppp_lock);
		pool->ppp_idle_idx = IDLE_IDX_MAX;
		spin_unlock(&pool->ppp_lock);
	}

	LASSERT(pool->ppp_idle_idx <= IDLE_IDX_MAX);

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
int npages_to_npools(unsigned long npages)
{
	return (int) ((npages + PAGES_PER_POOL - 1) / PAGES_PER_POOL);
}

/*
 * return how many pages cleaned up.
 */
static unsigned long pool_cleanup(void ***pools, int npools, int pool_idx)
{
	unsigned long cleaned = 0;
	int i, j;

	for (i = 0; i < npools; i++) {
		if (pools[i]) {
			for (j = 0; j < PAGES_PER_POOL; j++) {
				if (pools[i][j]) {
					if (pool_idx == PAGES_POOL) {
						__free_page(pools[i][j]);
					} else {
						OBD_FREE_LARGE(pools[i][j],
							ELEMENT_SIZE(pool_idx));
					}
					cleaned++;
				}
			}
			OBD_FREE(pools[i], PAGE_SIZE);
			pools[i] = NULL;
		}
	}

	return cleaned;
}

/*
 * merge @npools pointed by @pools which contains @npages new pages
 * into current pools.
 *
 * we have options to avoid most memory copy with some tricks. but we choose
 * the simplest way to avoid complexity. It's not frequently called.
 */
static void pool_insert(void ***pools, int npools, int npages,
			unsigned int pool_idx)
{
	int freeslot;
	int op_idx, np_idx, og_idx, ng_idx;
	int cur_npools, end_npools;
	struct ptlrpc_page_pool *page_pool = page_pools[pool_idx];

	LASSERT(npages > 0);
	LASSERT(page_pool->ppp_total_pages+npages <= page_pool->ppp_max_pages);
	LASSERT(npages_to_npools(npages) == npools);
	LASSERT(page_pool->ppp_growing);

	spin_lock(&page_pool->ppp_lock);

	/*
	 * (1) fill all the free slots of current pools.
	 */
	/*
	 * free slots are those left by rent pages, and the extra ones with
	 * index >= total_pages, locate at the tail of last pool.
	 */
	freeslot = page_pool->ppp_total_pages % PAGES_PER_POOL;
	if (freeslot != 0)
		freeslot = PAGES_PER_POOL - freeslot;
	freeslot += page_pool->ppp_total_pages - page_pool->ppp_free_pages;

	op_idx = page_pool->ppp_free_pages / PAGES_PER_POOL;
	og_idx = page_pool->ppp_free_pages % PAGES_PER_POOL;
	np_idx = npools - 1;
	ng_idx = (npages - 1) % PAGES_PER_POOL;

	while (freeslot) {
		LASSERT(page_pool->ppp_pools[op_idx][og_idx] == NULL);
		LASSERT(pools[np_idx][ng_idx] != NULL);

		page_pool->ppp_pools[op_idx][og_idx] = pools[np_idx][ng_idx];
		pools[np_idx][ng_idx] = NULL;

		freeslot--;

		if (++og_idx == PAGES_PER_POOL) {
			op_idx++;
			og_idx = 0;
		}
		if (--ng_idx < 0) {
			if (np_idx == 0)
				break;
			np_idx--;
			ng_idx = PAGES_PER_POOL - 1;
		}
	}

	/*
	 * (2) add pools if needed.
	 */
	cur_npools = (page_pool->ppp_total_pages + PAGES_PER_POOL - 1) /
		      PAGES_PER_POOL;
	end_npools = (page_pool->ppp_total_pages + npages +
		      PAGES_PER_POOL - 1) / PAGES_PER_POOL;
	LASSERT(end_npools <= page_pool->ppp_max_pools);

	np_idx = 0;
	while (cur_npools < end_npools) {
		LASSERT(page_pool->ppp_pools[cur_npools] == NULL);
		LASSERT(np_idx < npools);
		LASSERT(pools[np_idx] != NULL);

		page_pool->ppp_pools[cur_npools++] = pools[np_idx];
		pools[np_idx++] = NULL;
	}

	/*
	 * (3) free useless source pools
	 */
	while (np_idx < npools) {
		LASSERT(pools[np_idx] != NULL);
		CDEBUG(D_SEC, "Free useless pool buffer: %i, %p\n", np_idx,
		       pools[np_idx]);
		OBD_FREE(pools[np_idx], PAGE_SIZE);
		pools[np_idx++] = NULL;
	}

	page_pool->ppp_total_pages += npages;
	page_pool->ppp_free_pages += npages;
	page_pool->ppp_st_lowfree = page_pool->ppp_free_pages;

	if (page_pool->ppp_total_pages > page_pool->ppp_st_max_pages)
		page_pool->ppp_st_max_pages = page_pool->ppp_total_pages;

	CDEBUG(D_SEC, "add %d pages to total %lu\n", npages,
	       page_pool->ppp_total_pages);

	spin_unlock(&page_pool->ppp_lock);
}

#define POOL_INIT_SIZE (PTLRPC_MAX_BRW_SIZE / 4)
static int pool_add_pages(int npages, int pool_index)
{
	void ***pools;
	int npools, alloced = 0;
	int i, j, rc = -ENOMEM;
	struct ptlrpc_page_pool *page_pool = page_pools[pool_index];

	if (pool_index == PAGES_POOL) {
		if (npages < POOL_INIT_SIZE >> PAGE_SHIFT)
			npages = POOL_INIT_SIZE >> PAGE_SHIFT;
	} else {
		if (npages < POOL_INIT_SIZE / ELEMENT_SIZE(pool_index))
			npages = POOL_INIT_SIZE / ELEMENT_SIZE(pool_index);
	}

	mutex_lock(&page_pool->add_pages_mutex);

	if (npages + page_pool->ppp_total_pages > page_pool->ppp_max_pages)
		npages = page_pool->ppp_max_pages - page_pool->ppp_total_pages;
	LASSERT(npages > 0);

	page_pool->ppp_st_grows++;

	npools = npages_to_npools(npages);
	OBD_ALLOC_PTR_ARRAY(pools, npools);
	if (pools == NULL)
		goto out;

	for (i = 0; i < npools; i++) {
		OBD_ALLOC(pools[i], PAGE_SIZE);
		if (pools[i] == NULL)
			goto out_pools;

		for (j = 0; j < PAGES_PER_POOL && alloced < npages; j++) {
			if (pool_index == PAGES_POOL)
				pools[i][j] = alloc_page(GFP_NOFS |
					__GFP_HIGHMEM);
			else {
				OBD_ALLOC_LARGE(pools[i][j],
					ELEMENT_SIZE(pool_index));
			}
			if (pools[i][j] == NULL)
				goto out_pools;

			alloced++;
		}
	}
	LASSERT(alloced == npages);

	pool_insert(pools, npools, npages, pool_index);
	CDEBUG(D_SEC, "added %d pages into pools\n", npages);
	OBD_FREE_PTR_ARRAY(pools, npools);
	rc = 0;

out_pools:
	if (rc) {
		pool_cleanup(pools, npools, pool_index);
	}
out:
	if (rc) {
		page_pool->ppp_st_grow_fails++;
		CERROR("Failed to allocate %d pages\n", npages);
	}

	mutex_unlock(&page_pool->add_pages_mutex);
	return rc;
}

static inline void pool_wakeup(unsigned int pool)
{
	assert_spin_locked(&page_pools[pool]->ppp_lock);

	/* waitqueue_active */
	if (unlikely(waitqueue_active(&page_pools[pool]->ppp_waitq)))
		wake_up_all(&page_pools[pool]->ppp_waitq);
}

static int pool_should_grow(int needed, unsigned int pool_index)
{
	struct ptlrpc_page_pool *pool = page_pools[pool_index];

	/*
	 * don't grow if someone else is growing the pools right now,
	 * or the pools has reached its full capacity
	 */
	if (pool->ppp_growing || pool->ppp_total_pages == pool->ppp_max_pages)
		return 0;

	/* if total pages is not enough, we need to grow */
	if (pool->ppp_total_pages < needed)
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

	/* grow the pools in any other cases */
	return 1;
}

/*
 * Export the number of free pages in the pool
 */
int sptlrpc_pool_get_free_pages(unsigned int pool)
{
	return page_pools[pool]->ppp_free_pages;
}
EXPORT_SYMBOL(sptlrpc_pool_get_free_pages);

/*
 * Let outside world know if pool full capacity is reached
 */
int __pool_is_at_full_capacity(unsigned int pool)
{
	return (page_pools[pool]->ppp_total_pages ==
		page_pools[pool]->ppp_max_pages);
}

/*
 * Let outside world know if pool full capacity is reached
 */
int pool_is_at_full_capacity(void)
{
	return __pool_is_at_full_capacity(PAGES_POOL);
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

static inline void **page_from_bufarray(void *array, int index)
{
	return (void **)array;
}

/*
 * we allocate the requested pages atomically.
 */
static inline int __sptlrpc_pool_get_pages(void *array, unsigned int count,
					   unsigned int pool_idx,
					   void **(*page_from)(void *, int))
{
	struct ptlrpc_page_pool *page_pool = page_pools[pool_idx];
	wait_queue_entry_t waitlink;
	unsigned long this_idle = -1;
	u64 tick_ns = 0;
	int p_idx, g_idx;
	int i, rc = 0;

	if (!array || count <= 0 || count > page_pool->ppp_max_pages)
		return -EINVAL;

	spin_lock(&page_pool->ppp_lock);

	page_pool->ppp_st_access++;
again:
	if (unlikely(page_pool->ppp_free_pages < count)) {
		if (tick_ns == 0)
			tick_ns = ktime_get_ns();

		page_pool->ppp_st_missings++;
		page_pool->ppp_pages_short += count;

		if (pool_should_grow(count, pool_idx)) {
			page_pool->ppp_growing = 1;

			spin_unlock(&page_pool->ppp_lock);
			CDEBUG(D_SEC, "ppp_pages_short: %lu\n",
			       page_pool->ppp_pages_short);
			pool_add_pages(8, pool_idx);
			spin_lock(&page_pool->ppp_lock);

			page_pool->ppp_growing = 0;

			pool_wakeup(pool_idx);
		} else {
			if (page_pool->ppp_growing) {
				if (++page_pool->ppp_waitqlen >
				    page_pool->ppp_st_max_wqlen)
					page_pool->ppp_st_max_wqlen =
						page_pool->ppp_waitqlen;

				set_current_state(TASK_UNINTERRUPTIBLE);
				init_wait(&waitlink);
				add_wait_queue(&page_pool->ppp_waitq,
					       &waitlink);

				spin_unlock(&page_pool->ppp_lock);
				schedule();
				remove_wait_queue(&page_pool->ppp_waitq,
						  &waitlink);
				spin_lock(&page_pool->ppp_lock);
				page_pool->ppp_waitqlen--;
			} else {
				/*
				 * ptlrpcd thread should not sleep in that
				 * case or deadlock may occur!
				 * Instead, return -ENOMEM so that upper layers
				 * will put request back in queue.
				 */
				page_pool->ppp_st_outofmem++;
				GOTO(out_unlock, rc = -ENOMEM);
			}
		}

		if (page_pool->ppp_pages_short < count)
			GOTO(out_unlock, rc = -EPROTO);
		page_pool->ppp_pages_short -= count;

		this_idle = 0;
		goto again;
	}

	/* record max wait time */
	if (unlikely(tick_ns)) {
		ktime_t tick = ktime_sub_ns(ktime_get(), tick_ns);

		if (ktime_after(tick, page_pool->ppp_st_max_wait))
			page_pool->ppp_st_max_wait = tick;
	}

	/* proceed with rest of allocation */
	page_pool->ppp_free_pages -= count;

	p_idx = page_pool->ppp_free_pages / PAGES_PER_POOL;
	g_idx = page_pool->ppp_free_pages % PAGES_PER_POOL;

	for (i = 0; i < count; i++) {
		void **pagep = page_from(array, i);

		if (page_pool->ppp_pools[p_idx][g_idx] == NULL)
			GOTO(out_unlock, rc = -EPROTO);
		*pagep = page_pool->ppp_pools[p_idx][g_idx];
		page_pool->ppp_pools[p_idx][g_idx] = NULL;

		if (++g_idx == PAGES_PER_POOL) {
			p_idx++;
			g_idx = 0;
		}
	}

	if (page_pool->ppp_free_pages < page_pool->ppp_st_lowfree)
		page_pool->ppp_st_lowfree =
			page_pool->ppp_free_pages;

	/*
	 * new idle index = (old * weight + new) / (weight + 1)
	 */
	if (this_idle == -1) {
		this_idle = page_pool->ppp_free_pages * IDLE_IDX_MAX /
			page_pool->ppp_total_pages;
	}
	page_pool->ppp_idle_idx = (page_pool->ppp_idle_idx *
			IDLE_IDX_WEIGHT + this_idle) /
			(IDLE_IDX_WEIGHT + 1);

	page_pool->ppp_last_access = ktime_get_seconds();

out_unlock:
	spin_unlock(&page_pool->ppp_lock);
	return rc;
}

int sptlrpc_pool_get_desc_pages(struct ptlrpc_bulk_desc *desc)
{
	int rc;

	LASSERT(desc->bd_iov_count > 0);
	LASSERT(desc->bd_iov_count <= page_pools[PAGES_POOL]->ppp_max_pages);

	/* resent bulk, enc iov might have been allocated previously */
	if (desc->bd_enc_vec != NULL)
		return 0;

	OBD_ALLOC_LARGE(desc->bd_enc_vec,
			desc->bd_iov_count * sizeof(*desc->bd_enc_vec));
	if (desc->bd_enc_vec == NULL)
		return -ENOMEM;

	rc = __sptlrpc_pool_get_pages((void *)desc, desc->bd_iov_count,
				      PAGES_POOL, page_from_bulkdesc);
	if (rc) {
		OBD_FREE_LARGE(desc->bd_enc_vec,
			       desc->bd_iov_count *
			       sizeof(*desc->bd_enc_vec));
		desc->bd_enc_vec = NULL;
	}
	return rc;
}
EXPORT_SYMBOL(sptlrpc_pool_get_desc_pages);

int sptlrpc_pool_get_pages_array(struct page **pa, unsigned int count)
{
	return __sptlrpc_pool_get_pages((void *)pa, count, PAGES_POOL,
					    page_from_pagearray);
}
EXPORT_SYMBOL(sptlrpc_pool_get_pages_array);

int sptlrpc_pool_get_pages(void **pages, unsigned int order)
{
	return __sptlrpc_pool_get_pages((void *)pages, 1,
					    PPOOL_ORDER_TO_INDEX(order),
					    page_from_bufarray);
}
EXPORT_SYMBOL(sptlrpc_pool_get_pages);

static int __sptlrpc_pool_put_pages(void *array, unsigned int count,
					unsigned int pool_idx,
					void **(*page_from)(void *, int))
{
	int p_idx, g_idx;
	int i, rc = 0;
	struct ptlrpc_page_pool *page_pool;

	LASSERTF(pool_idx < POOLS_COUNT, "count %u, pool %u\n",
		 count, pool_idx);
	if (!array) {
		CERROR("Faled to put %u pages, from pool %u\n",
		       count, pool_idx);
		return -EINVAL;
	}

	page_pool = page_pools[pool_idx];
	LASSERTF(page_pool != NULL, "count %u, pool %u\n", count, pool_idx);

	spin_lock(&page_pool->ppp_lock);

	p_idx = page_pool->ppp_free_pages / PAGES_PER_POOL;
	g_idx = page_pool->ppp_free_pages % PAGES_PER_POOL;

	if (page_pool->ppp_free_pages + count > page_pool->ppp_total_pages)
		GOTO(out_unlock, rc = -EPROTO);
	if (!page_pool->ppp_pools[p_idx])
		GOTO(out_unlock, rc = -EPROTO);

	for (i = 0; i < count; i++) {
		void **pagep = page_from(array, i);

		if (!*pagep ||
		    page_pool->ppp_pools[p_idx][g_idx] != NULL)
			GOTO(out_unlock, rc = -EPROTO);

		page_pool->ppp_pools[p_idx][g_idx] = *pagep;
		if (++g_idx == PAGES_PER_POOL) {
			p_idx++;
			g_idx = 0;
		}
	}

	page_pool->ppp_free_pages += count;
	pool_wakeup(pool_idx);

out_unlock:
	spin_unlock(&page_pool->ppp_lock);
	return rc;
}

void sptlrpc_pool_put_desc_pages(struct ptlrpc_bulk_desc *desc)
{
	int rc;

	if (desc->bd_enc_vec == NULL)
		return;

	rc = __sptlrpc_pool_put_pages((void *)desc, desc->bd_iov_count,
					  PAGES_POOL, page_from_bulkdesc);
	if (rc)
		CDEBUG(D_SEC, "error putting pages in pool: %d\n", rc);

	OBD_FREE_LARGE(desc->bd_enc_vec,
		       desc->bd_iov_count * sizeof(*desc->bd_enc_vec));
	desc->bd_enc_vec = NULL;
}

void sptlrpc_pool_put_pages_array(struct page **pa, unsigned int count)
{
	int rc;

	rc = __sptlrpc_pool_put_pages((void *)pa, count, PAGES_POOL,
					  page_from_pagearray);

	if (rc)
		CDEBUG(D_SEC, "error putting pages in pool: %d\n", rc);
}
EXPORT_SYMBOL(sptlrpc_pool_put_pages_array);

void sptlrpc_pool_put_pages(void *buf, unsigned int order)
{
	int rc;

	rc = __sptlrpc_pool_put_pages(buf, 1,
					  PPOOL_ORDER_TO_INDEX(order),
					  page_from_bufarray);
	if (rc)
		CDEBUG(D_SEC, "error putting pages in pool: %d\n", rc);
}
EXPORT_SYMBOL(sptlrpc_pool_put_pages);


/*
 * we don't do much stuff for add_user/del_user anymore, except adding some
 * initial pages in add_user() if current pools are empty, rest would be
 * handled by the pools's self-adaption.
 */
int sptlrpc_pool_add_user(void)
{
	struct ptlrpc_page_pool *pool = page_pools[PAGES_POOL];

	spin_lock(&pool->ppp_lock);
	/* ask for 1 page - so if the pool is empty, it will grow
	 * (this might also grow an in-use pool if it's full, which is fine)
	 */
	if (pool_should_grow(1, PAGES_POOL)) {
		pool->ppp_growing = 1;
		spin_unlock(&pool->ppp_lock);

		pool_add_pages(PTLRPC_MAX_BRW_PAGES * 2, PAGES_POOL);

		spin_lock(&pool->ppp_lock);
		pool->ppp_growing = 0;
		pool_wakeup(PAGES_POOL);
	}
	spin_unlock(&pool->ppp_lock);
	return 0;
}
EXPORT_SYMBOL(sptlrpc_pool_add_user);

static inline void pool_alloc(struct ptlrpc_page_pool *pool)
{
	LASSERT(pool->ppp_max_pools);
	OBD_ALLOC_LARGE(pool->ppp_pools,
			pool->ppp_max_pools *
			sizeof(*pool->ppp_pools));
}

static inline void pool_free(unsigned int pool_index)
{
	struct ptlrpc_page_pool *pool = page_pools[pool_index];

	LASSERT(pool->ppp_max_pools);
	LASSERT(pool->ppp_pools);

	OBD_FREE_LARGE(pool->ppp_pools,
		       pool->ppp_max_pools * sizeof(*pool->ppp_pools));
}

int sptlrpc_pool_init(void)
{
	int pool_index = 0, to_revert;
	int rc = 0;
	struct ptlrpc_page_pool *pool;
	int pool_max_pages = cfs_totalram_pages() / POOLS_COUNT;

	ENTRY;

	if (pool_max_memory_mb == 0 && enc_pool_max_memory_mb > 0)
		pool_max_memory_mb = enc_pool_max_memory_mb;
	if (pool_max_memory_mb > 0 &&
		pool_max_memory_mb <= PAGES_TO_MiB(cfs_totalram_pages()))
		pool_max_pages = MiB_TO_PAGES(pool_max_memory_mb);

	OBD_ALLOC(page_pools, POOLS_COUNT * sizeof(*page_pools));
	if (page_pools == NULL)
		RETURN(-ENOMEM);
	for (pool_index = 0; pool_index < POOLS_COUNT; pool_index++) {
		OBD_ALLOC(page_pools[pool_index], sizeof(**page_pools));
		if (page_pools[pool_index] == NULL)
			GOTO(fail, rc = -ENOMEM);

		pool = page_pools[pool_index];
		pool->ppp_max_pages = pool_max_pages;

		pool->ppp_max_pools =
			npages_to_npools(pool->ppp_max_pages);

		init_waitqueue_head(&pool->ppp_waitq);
		pool->ppp_last_shrink = ktime_get_seconds();
		pool->ppp_last_access = ktime_get_seconds();

		spin_lock_init(&pool->ppp_lock);
		pool->ppp_st_max_wait = ktime_set(0, 0);

		pool_alloc(pool);
		CDEBUG(D_SEC, "Allocated pool %i\n", pool_index);
		if (pool->ppp_pools == NULL)
			GOTO(fail, rc = -ENOMEM);
		/* Pass pool number as part of pool_shrinker_seeks value */
#ifdef HAVE_SHRINKER_COUNT
		pool->ppp_shops.count_objects = pool_shrink_count;
		pool->ppp_shops.scan_objects = pool_shrink_scan;
#else
		pool->ppp_shops.shrink = pool_shrink;
#endif
		pool->ppp_shops.seeks = INDEX_TO_SEEKS(pool_index);

		pool->pool_shrinker = ll_shrinker_create(&pool->ppp_shops, 0,
							 "sptlrpc_pool");
		if (IS_ERR(pool->pool_shrinker))
			GOTO(fail, rc = PTR_ERR(pool->pool_shrinker));

		mutex_init(&pool->add_pages_mutex);
	}

	RETURN(0);
fail:
	to_revert = pool_index;
	for (pool_index = 0; pool_index <= to_revert; pool_index++) {
		pool = page_pools[pool_index];
		if (pool) {
			if (pool->ppp_pools)
				pool_free(pool_index);
			OBD_FREE(pool, sizeof(**page_pools));
		}
	}
	OBD_FREE(page_pools, POOLS_COUNT * sizeof(*page_pools));

	RETURN(rc);
}

void sptlrpc_pool_fini(void)
{
	unsigned long cleaned, npools;
	int pool_index;
	struct ptlrpc_page_pool *pool;

	for (pool_index = 0; pool_index < POOLS_COUNT; pool_index++) {
		pool = page_pools[pool_index];
		shrinker_free(pool->pool_shrinker);
		LASSERT(pool->ppp_pools);
		LASSERT(pool->ppp_total_pages == pool->ppp_free_pages);

		npools = npages_to_npools(pool->ppp_total_pages);
		cleaned = pool_cleanup(pool->ppp_pools, npools, pool_index);
		LASSERT(cleaned == pool->ppp_total_pages);

		pool_free(pool_index);

		if (pool->ppp_st_access > 0) {
			CDEBUG(D_SEC,
			       "max pages %lu, grows %u, grow fails %u, shrinks %u, access %lu, missing %lu, max qlen %u, max wait ms %lld, out of mem %lu\n",
			       pool->ppp_st_max_pages,
			       pool->ppp_st_grows,
			       pool->ppp_st_grow_fails,
			       pool->ppp_st_shrinks,
			       pool->ppp_st_access,
			       pool->ppp_st_missings,
			       pool->ppp_st_max_wqlen,
			       ktime_to_ms(pool->ppp_st_max_wait),
			       pool->ppp_st_outofmem);
		}

		OBD_FREE(pool, sizeof(**page_pools));
	}

	OBD_FREE(page_pools, POOLS_COUNT * sizeof(*page_pools));
}

static int cfs_hash_alg_id[] = {
	[BULK_HASH_ALG_NULL]	= CFS_HASH_ALG_NULL,
	[BULK_HASH_ALG_ADLER32]	= CFS_HASH_ALG_ADLER32,
	[BULK_HASH_ALG_CRC32]	= CFS_HASH_ALG_CRC32,
	[BULK_HASH_ALG_MD5]	= CFS_HASH_ALG_MD5,
	[BULK_HASH_ALG_SHA1]	= CFS_HASH_ALG_SHA1,
	[BULK_HASH_ALG_SHA256]	= CFS_HASH_ALG_SHA256,
	[BULK_HASH_ALG_SHA384]	= CFS_HASH_ALG_SHA384,
	[BULK_HASH_ALG_SHA512]	= CFS_HASH_ALG_SHA512,
};
const char *sptlrpc_get_hash_name(__u8 hash_alg)
{
	return cfs_crypto_hash_name(cfs_hash_alg_id[hash_alg]);
}

__u8 sptlrpc_get_hash_alg(const char *algname)
{
	return cfs_crypto_hash_alg(algname);
}

int bulk_sec_desc_unpack(struct lustre_msg *msg, int offset, int swabbed)
{
	struct ptlrpc_bulk_sec_desc *bsd;
	int size = msg->lm_buflens[offset];

	bsd = lustre_msg_buf(msg, offset, sizeof(*bsd));
	if (bsd == NULL) {
		CERROR("Invalid bulk sec desc: size %d\n", size);
		return -EINVAL;
	}

	if (swabbed)
		__swab32s(&bsd->bsd_nob);

	if (unlikely(bsd->bsd_version != 0)) {
		CERROR("Unexpected version %u\n", bsd->bsd_version);
		return -EPROTO;
	}

	if (unlikely(bsd->bsd_type >= SPTLRPC_BULK_MAX)) {
		CERROR("Invalid type %u\n", bsd->bsd_type);
		return -EPROTO;
	}

	/* FIXME more sanity check here */

	if (unlikely(bsd->bsd_svc != SPTLRPC_BULK_SVC_NULL &&
		     bsd->bsd_svc != SPTLRPC_BULK_SVC_INTG &&
		     bsd->bsd_svc != SPTLRPC_BULK_SVC_PRIV)) {
		CERROR("Invalid svc %u\n", bsd->bsd_svc);
		return -EPROTO;
	}

	return 0;
}
EXPORT_SYMBOL(bulk_sec_desc_unpack);

/*
 * Compute the checksum of an RPC buffer payload.  If the return \a buflen
 * is not large enough, truncate the result to fit so that it is possible
 * to use a hash function with a large hash space, but only use a part of
 * the resulting hash.
 */
int sptlrpc_get_bulk_checksum(struct ptlrpc_bulk_desc *desc, __u8 alg,
			      void *buf, int buflen)
{
	struct ahash_request *req;
	int hashsize;
	unsigned int bufsize;
	int i, err;

	LASSERT(alg > BULK_HASH_ALG_NULL && alg < BULK_HASH_ALG_MAX);
	LASSERT(buflen >= 4);

	req = cfs_crypto_hash_init(cfs_hash_alg_id[alg], NULL, 0);
	if (IS_ERR(req)) {
		CERROR("Unable to initialize checksum hash %s\n",
		       cfs_crypto_hash_name(cfs_hash_alg_id[alg]));
		return PTR_ERR(req);
	}

	hashsize = cfs_crypto_hash_digestsize(cfs_hash_alg_id[alg]);

	for (i = 0; i < desc->bd_iov_count; i++) {
		cfs_crypto_hash_update_page(req,
				  desc->bd_vec[i].bv_page,
				  desc->bd_vec[i].bv_offset &
					      ~PAGE_MASK,
				  desc->bd_vec[i].bv_len);
	}

	if (hashsize > buflen) {
		unsigned char hashbuf[CFS_CRYPTO_HASH_DIGESTSIZE_MAX];

		bufsize = sizeof(hashbuf);
		LASSERTF(bufsize >= hashsize, "bufsize = %u < hashsize %u\n",
			 bufsize, hashsize);
		err = cfs_crypto_hash_final(req, hashbuf, &bufsize);
		memcpy(buf, hashbuf, buflen);
	} else {
		bufsize = buflen;
		err = cfs_crypto_hash_final(req, buf, &bufsize);
	}

	return err;
}
