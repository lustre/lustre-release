/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2006-2007 Cluster File Systems, Inc.
 *   Author: Eric Mei <ericm@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/libcfs.h>
#ifndef __KERNEL__
#include <liblustre.h>
#include <libcfs/list.h>
#else
#include <linux/crypto.h>
#endif

#include <obd.h>
#include <obd_cksum.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

/****************************************
 * bulk encryption page pools           *
 ****************************************/

#ifdef __KERNEL__

#define PTRS_PER_PAGE   (CFS_PAGE_SIZE / sizeof(void *))
#define PAGES_PER_POOL  (PTRS_PER_PAGE)

#define IDLE_IDX_MAX            (100)
#define IDLE_IDX_WEIGHT         (3)

#define CACHE_QUIESCENT_PERIOD  (20)

static struct ptlrpc_enc_page_pool {
        /*
         * constants
         */
        unsigned long    epp_max_pages;   /* maximum pages can hold, const */
        unsigned int     epp_max_pools;   /* number of pools, const */

        /*
         * wait queue in case of not enough free pages.
         */
        cfs_waitq_t      epp_waitq;       /* waiting threads */
        unsigned int     epp_waitqlen;    /* wait queue length */
        unsigned long    epp_pages_short; /* # of pages wanted of in-q users */
        unsigned int     epp_growing:1;   /* during adding pages */

        /*
         * indicating how idle the pools are, from 0 to MAX_IDLE_IDX
         * this is counted based on each time when getting pages from
         * the pools, not based on time. which means in case that system
         * is idled for a while but the idle_idx might still be low if no
         * activities happened in the pools.
         */
        unsigned long    epp_idle_idx;

        /* last shrink time due to mem tight */
        long             epp_last_shrink;
        long             epp_last_access;

        /*
         * in-pool pages bookkeeping
         */
        spinlock_t       epp_lock;        /* protect following fields */
        unsigned long    epp_total_pages; /* total pages in pools */
        unsigned long    epp_free_pages;  /* current pages available */

        /*
         * statistics
         */
        unsigned long    epp_st_max_pages;      /* # of pages ever reached */
        unsigned int     epp_st_grows;          /* # of grows */
        unsigned int     epp_st_grow_fails;     /* # of add pages failures */
        unsigned int     epp_st_shrinks;        /* # of shrinks */
        unsigned long    epp_st_access;         /* # of access */
        unsigned long    epp_st_missings;       /* # of cache missing */
        unsigned long    epp_st_lowfree;        /* lowest free pages reached */
        unsigned int     epp_st_max_wqlen;      /* highest waitqueue length */
        cfs_time_t       epp_st_max_wait;       /* in jeffies */
        /*
         * pointers to pools
         */
        cfs_page_t    ***epp_pools;
} page_pools;

/*
 * memory shrinker
 */
const int pools_shrinker_seeks = DEFAULT_SEEKS;
static struct shrinker *pools_shrinker = NULL;


/*
 * /proc/fs/lustre/sptlrpc/encrypt_page_pools
 */
int sptlrpc_proc_read_enc_pool(char *page, char **start, off_t off, int count,
                               int *eof, void *data)
{
        int     rc;

        spin_lock(&page_pools.epp_lock);

        rc = snprintf(page, count,
                      "physical pages:          %lu\n"
                      "pages per pool:          %lu\n"
                      "max pages:               %lu\n"
                      "max pools:               %u\n"
                      "total pages:             %lu\n"
                      "total free:              %lu\n"
                      "idle index:              %lu/100\n"
                      "last shrink:             %lds\n"
                      "last access:             %lds\n"
                      "max pages reached:       %lu\n"
                      "grows:                   %u\n"
                      "grows failure:           %u\n"
                      "shrinks:                 %u\n"
                      "cache access:            %lu\n"
                      "cache missing:           %lu\n"
                      "low free mark:           %lu\n"
                      "max waitqueue depth:     %u\n"
                      "max wait time:           "CFS_TIME_T"/%u\n"
                      ,
                      num_physpages,
                      PAGES_PER_POOL,
                      page_pools.epp_max_pages,
                      page_pools.epp_max_pools,
                      page_pools.epp_total_pages,
                      page_pools.epp_free_pages,
                      page_pools.epp_idle_idx,
                      cfs_time_current_sec() - page_pools.epp_last_shrink,
                      cfs_time_current_sec() - page_pools.epp_last_access,
                      page_pools.epp_st_max_pages,
                      page_pools.epp_st_grows,
                      page_pools.epp_st_grow_fails,
                      page_pools.epp_st_shrinks,
                      page_pools.epp_st_access,
                      page_pools.epp_st_missings,
                      page_pools.epp_st_lowfree,
                      page_pools.epp_st_max_wqlen,
                      page_pools.epp_st_max_wait, HZ
                     );

        spin_unlock(&page_pools.epp_lock);
        return rc;
}

static void enc_pools_release_free_pages(long npages)
{
        int     p_idx, g_idx;
        int     p_idx_max1, p_idx_max2;

        LASSERT(npages > 0);
        LASSERT(npages <= page_pools.epp_free_pages);
        LASSERT(page_pools.epp_free_pages <= page_pools.epp_total_pages);

        /* max pool index before the release */
        p_idx_max2 = (page_pools.epp_total_pages - 1) / PAGES_PER_POOL;

        page_pools.epp_free_pages -= npages;
        page_pools.epp_total_pages -= npages;

        /* max pool index after the release */
        p_idx_max1 = page_pools.epp_total_pages == 0 ? 0 :
                     ((page_pools.epp_total_pages - 1) / PAGES_PER_POOL);

        p_idx = page_pools.epp_free_pages / PAGES_PER_POOL;
        g_idx = page_pools.epp_free_pages % PAGES_PER_POOL;
        LASSERT(page_pools.epp_pools[p_idx]);

        while (npages--) {
                LASSERT(page_pools.epp_pools[p_idx]);
                LASSERT(page_pools.epp_pools[p_idx][g_idx] != NULL);

                cfs_free_page(page_pools.epp_pools[p_idx][g_idx]);
                page_pools.epp_pools[p_idx][g_idx] = NULL;

                if (++g_idx == PAGES_PER_POOL) {
                        p_idx++;
                        g_idx = 0;
                }
        };

        /* free unused pools */
        while (p_idx_max1 < p_idx_max2) {
                LASSERT(page_pools.epp_pools[p_idx_max2]);
                OBD_FREE(page_pools.epp_pools[p_idx_max2], CFS_PAGE_SIZE);
                page_pools.epp_pools[p_idx_max2] = NULL;
                p_idx_max2--;
        }
}

/*
 * could be called frequently for query (@nr_to_scan == 0)
 */
static int enc_pools_shrink(int nr_to_scan, unsigned int gfp_mask)
{
        unsigned long   ret;

        spin_lock(&page_pools.epp_lock);

        if (nr_to_scan > page_pools.epp_free_pages)
                nr_to_scan = page_pools.epp_free_pages;

        if (nr_to_scan > 0) {
                enc_pools_release_free_pages(nr_to_scan);
                CDEBUG(D_SEC, "released %d pages, %ld left\n",
                       nr_to_scan, page_pools.epp_free_pages);

                page_pools.epp_st_shrinks++;
                page_pools.epp_last_shrink = cfs_time_current_sec();
        }

        /*
         * try to keep at least PTLRPC_MAX_BRW_PAGES pages in the pool
         */
        if (page_pools.epp_free_pages <= PTLRPC_MAX_BRW_PAGES) {
                ret = 0;
                goto out_unlock;
        }

        /*
         * if no pool access for a long time, we consider it's fully idle
         */
        if (cfs_time_current_sec() - page_pools.epp_last_access >
            CACHE_QUIESCENT_PERIOD)
                page_pools.epp_idle_idx = IDLE_IDX_MAX;

        LASSERT(page_pools.epp_idle_idx <= IDLE_IDX_MAX);
        ret = (page_pools.epp_free_pages * page_pools.epp_idle_idx /
               IDLE_IDX_MAX);
        if (page_pools.epp_free_pages - ret < PTLRPC_MAX_BRW_PAGES)
                ret = page_pools.epp_free_pages - PTLRPC_MAX_BRW_PAGES;

out_unlock:
        spin_unlock(&page_pools.epp_lock);
        return ret;
}

static inline
int npages_to_npools(unsigned long npages)
{
        return (int) ((npages + PAGES_PER_POOL - 1) / PAGES_PER_POOL);
}

/*
 * return how many pages cleaned up.
 */
static unsigned long enc_pools_cleanup(cfs_page_t ***pools, int npools)
{
        unsigned long cleaned = 0;
        int           i, j;

        for (i = 0; i < npools; i++) {
                if (pools[i]) {
                        for (j = 0; j < PAGES_PER_POOL; j++) {
                                if (pools[i][j]) {
                                        cfs_free_page(pools[i][j]);
                                        cleaned++;
                                }
                        }
                        OBD_FREE(pools[i], CFS_PAGE_SIZE);
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
static void enc_pools_insert(cfs_page_t ***pools, int npools, int npages)
{
        int     freeslot;
        int     op_idx, np_idx, og_idx, ng_idx;
        int     cur_npools, end_npools;

        LASSERT(npages > 0);
        LASSERT(page_pools.epp_total_pages+npages <= page_pools.epp_max_pages);
        LASSERT(npages_to_npools(npages) == npools);

        spin_lock(&page_pools.epp_lock);

        /*
         * (1) fill all the free slots of current pools.
         */
        /* free slots are those left by rent pages, and the extra ones with
         * index >= total_pages, locate at the tail of last pool. */
        freeslot = page_pools.epp_total_pages % PAGES_PER_POOL;
        if (freeslot != 0)
                freeslot = PAGES_PER_POOL - freeslot;
        freeslot += page_pools.epp_total_pages - page_pools.epp_free_pages;

        op_idx = page_pools.epp_free_pages / PAGES_PER_POOL;
        og_idx = page_pools.epp_free_pages % PAGES_PER_POOL;
        np_idx = npools - 1;
        ng_idx = (npages - 1) % PAGES_PER_POOL;

        while (freeslot) {
                LASSERT(page_pools.epp_pools[op_idx][og_idx] == NULL);
                LASSERT(pools[np_idx][ng_idx] != NULL);

                page_pools.epp_pools[op_idx][og_idx] = pools[np_idx][ng_idx];
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
        cur_npools = (page_pools.epp_total_pages + PAGES_PER_POOL - 1) /
                     PAGES_PER_POOL;
        end_npools = (page_pools.epp_total_pages + npages + PAGES_PER_POOL -1) /
                     PAGES_PER_POOL;
        LASSERT(end_npools <= page_pools.epp_max_pools);

        np_idx = 0;
        while (cur_npools < end_npools) {
                LASSERT(page_pools.epp_pools[cur_npools] == NULL);
                LASSERT(np_idx < npools);
                LASSERT(pools[np_idx] != NULL);

                page_pools.epp_pools[cur_npools++] = pools[np_idx];
                pools[np_idx++] = NULL;
        }

        page_pools.epp_total_pages += npages;
        page_pools.epp_free_pages += npages;
        page_pools.epp_st_lowfree = page_pools.epp_free_pages;

        if (page_pools.epp_total_pages > page_pools.epp_st_max_pages)
                page_pools.epp_st_max_pages = page_pools.epp_total_pages;

        CDEBUG(D_SEC, "add %d pages to total %lu\n", npages,
               page_pools.epp_total_pages);

        spin_unlock(&page_pools.epp_lock);
}

static int enc_pools_add_pages(int npages)
{
        static DECLARE_MUTEX(sem_add_pages);
        cfs_page_t   ***pools;
        int             npools, alloced = 0;
        int             i, j, rc = -ENOMEM;

        if (npages < PTLRPC_MAX_BRW_PAGES)
                npages = PTLRPC_MAX_BRW_PAGES;

        down(&sem_add_pages);

        if (npages + page_pools.epp_total_pages > page_pools.epp_max_pages)
                npages = page_pools.epp_max_pages - page_pools.epp_total_pages;
        LASSERT(npages > 0);

        page_pools.epp_st_grows++;

        npools = npages_to_npools(npages);
        OBD_ALLOC(pools, npools * sizeof(*pools));
        if (pools == NULL)
                goto out;

        for (i = 0; i < npools; i++) {
                OBD_ALLOC(pools[i], CFS_PAGE_SIZE);
                if (pools[i] == NULL)
                        goto out_pools;

                for (j = 0; j < PAGES_PER_POOL && alloced < npages; j++) {
                        pools[i][j] = cfs_alloc_page(CFS_ALLOC_IO |
                                                     CFS_ALLOC_HIGH);
                        if (pools[i][j] == NULL)
                                goto out_pools;

                        alloced++;
                }
        }

        enc_pools_insert(pools, npools, npages);
        CDEBUG(D_SEC, "added %d pages into pools\n", npages);
        rc = 0;

out_pools:
        enc_pools_cleanup(pools, npools);
        OBD_FREE(pools, npools * sizeof(*pools));
out:
        if (rc) {
                page_pools.epp_st_grow_fails++;
                CERROR("Failed to allocate %d enc pages\n", npages);
        }

        up(&sem_add_pages);
        return rc;
}

static inline void enc_pools_wakeup(void)
{
        if (unlikely(page_pools.epp_waitqlen)) {
                LASSERT(page_pools.epp_waitqlen > 0);
                LASSERT(cfs_waitq_active(&page_pools.epp_waitq));
                cfs_waitq_broadcast(&page_pools.epp_waitq);
        }
}

static int enc_pools_should_grow(int page_needed, long now)
{
        /* don't grow if someone else is growing the pools right now,
         * or the pools has reached its full capacity
         */
        if (page_pools.epp_growing ||
            page_pools.epp_total_pages == page_pools.epp_max_pages)
                return 0;

        /* if total pages is not enough, we need to grow */
        if (page_pools.epp_total_pages < page_needed)
                return 1;

        /* if we just did a shrink due to memory tight, we'd better
         * wait a while to grow again.
         */
        if (now - page_pools.epp_last_shrink < 2)
                return 0;

        /*
         * here we perhaps need consider other factors like wait queue
         * length, idle index, etc. ?
         */

        /* grow the pools in any other cases */
        return 1;
}

/*
 * we allocate the requested pages atomically.
 */
int sptlrpc_enc_pool_get_pages(struct ptlrpc_bulk_desc *desc)
{
        cfs_waitlink_t  waitlink;
        unsigned long   this_idle = -1;
        cfs_time_t      tick = 0;
        long            now;
        int             p_idx, g_idx;
        int             i;

        LASSERT(desc->bd_max_iov > 0);
        LASSERT(desc->bd_max_iov <= page_pools.epp_max_pages);

        /* resent bulk, enc pages might have been allocated previously */
        if (desc->bd_enc_pages != NULL)
                return 0;

        OBD_ALLOC(desc->bd_enc_pages,
                  desc->bd_max_iov * sizeof(*desc->bd_enc_pages));
        if (desc->bd_enc_pages == NULL)
                return -ENOMEM;

        spin_lock(&page_pools.epp_lock);

        page_pools.epp_st_access++;
again:
        if (unlikely(page_pools.epp_free_pages < desc->bd_max_iov)) {
                if (tick == 0)
                        tick = cfs_time_current();

                now = cfs_time_current_sec();

                page_pools.epp_st_missings++;
                page_pools.epp_pages_short += desc->bd_max_iov;

                if (enc_pools_should_grow(desc->bd_max_iov, now)) {
                        page_pools.epp_growing = 1;

                        spin_unlock(&page_pools.epp_lock);
                        enc_pools_add_pages(page_pools.epp_pages_short / 2);
                        spin_lock(&page_pools.epp_lock);

                        page_pools.epp_growing = 0;
                } else {
                        if (++page_pools.epp_waitqlen >
                            page_pools.epp_st_max_wqlen)
                                page_pools.epp_st_max_wqlen =
                                                page_pools.epp_waitqlen;

                        set_current_state(TASK_UNINTERRUPTIBLE);
                        cfs_waitlink_init(&waitlink);
                        cfs_waitq_add(&page_pools.epp_waitq, &waitlink);

                        spin_unlock(&page_pools.epp_lock);
                        cfs_schedule();
                        spin_lock(&page_pools.epp_lock);

                        LASSERT(page_pools.epp_waitqlen > 0);
                        page_pools.epp_waitqlen--;
                }

                LASSERT(page_pools.epp_pages_short >= desc->bd_max_iov);
                page_pools.epp_pages_short -= desc->bd_max_iov;

                this_idle = 0;
                goto again;
        }

        /* record max wait time */
        if (unlikely(tick != 0)) {
                tick = cfs_time_current() - tick;
                if (tick > page_pools.epp_st_max_wait)
                        page_pools.epp_st_max_wait = tick;
        }

        /* proceed with rest of allocation */
        page_pools.epp_free_pages -= desc->bd_max_iov;

        p_idx = page_pools.epp_free_pages / PAGES_PER_POOL;
        g_idx = page_pools.epp_free_pages % PAGES_PER_POOL;

        for (i = 0; i < desc->bd_max_iov; i++) {
                LASSERT(page_pools.epp_pools[p_idx][g_idx] != NULL);
                desc->bd_enc_pages[i] = page_pools.epp_pools[p_idx][g_idx];
                page_pools.epp_pools[p_idx][g_idx] = NULL;

                if (++g_idx == PAGES_PER_POOL) {
                        p_idx++;
                        g_idx = 0;
                }
        }

        if (page_pools.epp_free_pages < page_pools.epp_st_lowfree)
                page_pools.epp_st_lowfree = page_pools.epp_free_pages;

        /*
         * new idle index = (old * weight + new) / (weight + 1)
         */
        if (this_idle == -1) {
                this_idle = page_pools.epp_free_pages * IDLE_IDX_MAX /
                            page_pools.epp_total_pages;
        }
        page_pools.epp_idle_idx = (page_pools.epp_idle_idx * IDLE_IDX_WEIGHT +
                                   this_idle) /
                                  (IDLE_IDX_WEIGHT + 1);

        page_pools.epp_last_access = cfs_time_current_sec();

        spin_unlock(&page_pools.epp_lock);
        return 0;
}
EXPORT_SYMBOL(sptlrpc_enc_pool_get_pages);

void sptlrpc_enc_pool_put_pages(struct ptlrpc_bulk_desc *desc)
{
        int     p_idx, g_idx;
        int     i;

        if (desc->bd_enc_pages == NULL)
                return;
        if (desc->bd_max_iov == 0)
                return;

        spin_lock(&page_pools.epp_lock);

        p_idx = page_pools.epp_free_pages / PAGES_PER_POOL;
        g_idx = page_pools.epp_free_pages % PAGES_PER_POOL;

        LASSERT(page_pools.epp_free_pages + desc->bd_max_iov <=
                page_pools.epp_total_pages);
        LASSERT(page_pools.epp_pools[p_idx]);

        for (i = 0; i < desc->bd_max_iov; i++) {
                LASSERT(desc->bd_enc_pages[i] != NULL);
                LASSERT(g_idx != 0 || page_pools.epp_pools[p_idx]);
                LASSERT(page_pools.epp_pools[p_idx][g_idx] == NULL);

                page_pools.epp_pools[p_idx][g_idx] = desc->bd_enc_pages[i];

                if (++g_idx == PAGES_PER_POOL) {
                        p_idx++;
                        g_idx = 0;
                }
        }

        page_pools.epp_free_pages += desc->bd_max_iov;

        enc_pools_wakeup();

        spin_unlock(&page_pools.epp_lock);

        OBD_FREE(desc->bd_enc_pages,
                 desc->bd_max_iov * sizeof(*desc->bd_enc_pages));
        desc->bd_enc_pages = NULL;
}
EXPORT_SYMBOL(sptlrpc_enc_pool_put_pages);

/*
 * we don't do much stuff for add_user/del_user anymore, except adding some
 * initial pages in add_user() if current pools are empty, rest would be
 * handled by the pools's self-adaption.
 */
int sptlrpc_enc_pool_add_user(void)
{
        int     need_grow = 0;

        spin_lock(&page_pools.epp_lock);
        if (page_pools.epp_growing == 0 && page_pools.epp_total_pages == 0) {
                page_pools.epp_growing = 1;
                need_grow = 1;
        }
        spin_unlock(&page_pools.epp_lock);

        if (need_grow) {
                enc_pools_add_pages(PTLRPC_MAX_BRW_PAGES);

                spin_lock(&page_pools.epp_lock);
                page_pools.epp_growing = 0;
                enc_pools_wakeup();
                spin_unlock(&page_pools.epp_lock);
        }
        return 0;
}
EXPORT_SYMBOL(sptlrpc_enc_pool_add_user);

int sptlrpc_enc_pool_del_user(void)
{
        return 0;
}
EXPORT_SYMBOL(sptlrpc_enc_pool_del_user);

static inline void enc_pools_alloc(void)
{
        LASSERT(page_pools.epp_max_pools);
        /*
         * on system with huge memory but small page size, this might lead to
         * high-order allocation. but it's not common, and we suppose memory
         * be not too much fragmented at module loading time.
         */
        OBD_ALLOC(page_pools.epp_pools,
                  page_pools.epp_max_pools * sizeof(*page_pools.epp_pools));
}

static inline void enc_pools_free(void)
{
        LASSERT(page_pools.epp_max_pools);
        LASSERT(page_pools.epp_pools);

        OBD_FREE(page_pools.epp_pools,
                 page_pools.epp_max_pools * sizeof(*page_pools.epp_pools));
}

int sptlrpc_enc_pool_init(void)
{
        /*
         * maximum capacity is 1/8 of total physical memory.
         * is the 1/8 a good number?
         */
        page_pools.epp_max_pages = num_physpages / 8;
        page_pools.epp_max_pools = npages_to_npools(page_pools.epp_max_pages);

        cfs_waitq_init(&page_pools.epp_waitq);
        page_pools.epp_waitqlen = 0;
        page_pools.epp_pages_short = 0;

        page_pools.epp_growing = 0;

        page_pools.epp_idle_idx = 0;
        page_pools.epp_last_shrink = cfs_time_current_sec();
        page_pools.epp_last_access = cfs_time_current_sec();

        spin_lock_init(&page_pools.epp_lock);
        page_pools.epp_total_pages = 0;
        page_pools.epp_free_pages = 0;

        page_pools.epp_st_max_pages = 0;
        page_pools.epp_st_grows = 0;
        page_pools.epp_st_grow_fails = 0;
        page_pools.epp_st_shrinks = 0;
        page_pools.epp_st_access = 0;
        page_pools.epp_st_missings = 0;
        page_pools.epp_st_lowfree = 0;
        page_pools.epp_st_max_wqlen = 0;
        page_pools.epp_st_max_wait = 0;

        enc_pools_alloc();
        if (page_pools.epp_pools == NULL)
                return -ENOMEM;

        pools_shrinker = set_shrinker(pools_shrinker_seeks, enc_pools_shrink);
        if (pools_shrinker == NULL) {
                enc_pools_free();
                return -ENOMEM;
        }

        return 0;
}

void sptlrpc_enc_pool_fini(void)
{
        unsigned long cleaned, npools;

        LASSERT(pools_shrinker);
        LASSERT(page_pools.epp_pools);
        LASSERT(page_pools.epp_total_pages == page_pools.epp_free_pages);

        remove_shrinker(pools_shrinker);

        npools = npages_to_npools(page_pools.epp_total_pages);
        cleaned = enc_pools_cleanup(page_pools.epp_pools, npools);
        LASSERT(cleaned == page_pools.epp_total_pages);

        enc_pools_free();

        if (page_pools.epp_st_access > 0) {
                CWARN("max pages %lu, grows %u, grow fails %u, shrinks %u, "
                      "access %lu, missing %lu, max qlen %u, max wait "
                      CFS_TIME_T"/%d\n",
                      page_pools.epp_st_max_pages, page_pools.epp_st_grows,
                      page_pools.epp_st_grow_fails,
                      page_pools.epp_st_shrinks, page_pools.epp_st_access,
                      page_pools.epp_st_missings, page_pools.epp_st_max_wqlen,
                      page_pools.epp_st_max_wait, HZ);
        }
}

#else /* !__KERNEL__ */

int sptlrpc_enc_pool_get_pages(struct ptlrpc_bulk_desc *desc)
{
        return 0;
}

void sptlrpc_enc_pool_put_pages(struct ptlrpc_bulk_desc *desc)
{
}

int sptlrpc_enc_pool_init(void)
{
        return 0;
}

void sptlrpc_enc_pool_fini(void)
{
}
#endif

/****************************************
 * Helpers to assist policy modules to  *
 * implement checksum funcationality    *
 ****************************************/

static struct sptlrpc_hash_type hash_types[] = {
        [BULK_HASH_ALG_NULL]    = { "null",     "null",         0 },
        [BULK_HASH_ALG_ADLER32] = { "adler32",  "adler32",      4 },
        [BULK_HASH_ALG_CRC32]   = { "crc32",    "crc32",        4 },
        [BULK_HASH_ALG_MD5]     = { "md5",      "md5",          16 },
        [BULK_HASH_ALG_SHA1]    = { "sha1",     "sha1",         20 },
        [BULK_HASH_ALG_SHA256]  = { "sha256",   "sha256",       32 },
        [BULK_HASH_ALG_SHA384]  = { "sha384",   "sha384",       48 },
        [BULK_HASH_ALG_SHA512]  = { "sha512",   "sha512",       64 },
        [BULK_HASH_ALG_WP256]   = { "wp256",    "wp256",        32 },
        [BULK_HASH_ALG_WP384]   = { "wp384",    "wp384",        48 },
        [BULK_HASH_ALG_WP512]   = { "wp512",    "wp512",        64 },
};

const struct sptlrpc_hash_type *sptlrpc_get_hash_type(__u8 hash_alg)
{
        struct sptlrpc_hash_type *ht;

        if (hash_alg < BULK_HASH_ALG_MAX) {
                ht = &hash_types[hash_alg];
                if (ht->sht_tfm_name)
                        return ht;
        }
        return NULL;
}
EXPORT_SYMBOL(sptlrpc_get_hash_type);

const char * sptlrpc_get_hash_name(__u8 hash_alg)
{
        const struct sptlrpc_hash_type *ht;

        ht = sptlrpc_get_hash_type(hash_alg);
        if (ht)
                return ht->sht_name;
        else
                return "unknown";
}
EXPORT_SYMBOL(sptlrpc_get_hash_name);

int bulk_sec_desc_size(__u8 hash_alg, int request, int read)
{
        int size = sizeof(struct ptlrpc_bulk_sec_desc);

        LASSERT(hash_alg < BULK_HASH_ALG_MAX);

        /* read request don't need extra data */
        if (!(read && request))
                size += hash_types[hash_alg].sht_size;

        return size;
}
EXPORT_SYMBOL(bulk_sec_desc_size);

int bulk_sec_desc_unpack(struct lustre_msg *msg, int offset)
{
        struct ptlrpc_bulk_sec_desc *bsd;
        int    size = msg->lm_buflens[offset];

        bsd = lustre_msg_buf(msg, offset, sizeof(*bsd));
        if (bsd == NULL) {
                CERROR("Invalid bulk sec desc: size %d\n", size);
                return -EINVAL;
        }

        /* nothing to swab */

        if (unlikely(bsd->bsd_version != 0)) {
                CERROR("Unexpected version %u\n", bsd->bsd_version);
                return -EPROTO;
        }

        if (unlikely(bsd->bsd_flags != 0)) {
                CERROR("Unexpected flags %x\n", bsd->bsd_flags);
                return -EPROTO;
        }

        if (unlikely(!sptlrpc_get_hash_type(bsd->bsd_hash_alg))) {
                CERROR("Unsupported checksum algorithm %u\n",
                       bsd->bsd_hash_alg);
                return -EINVAL;
        }

        if (unlikely(!sptlrpc_get_ciph_type(bsd->bsd_ciph_alg))) {
                CERROR("Unsupported cipher algorithm %u\n",
                       bsd->bsd_ciph_alg);
                return -EINVAL;
        }

        if (unlikely(size > sizeof(*bsd)) &&
            size < sizeof(*bsd) + hash_types[bsd->bsd_hash_alg].sht_size) {
                CERROR("Mal-formed checksum data: csum alg %u, size %d\n",
                       bsd->bsd_hash_alg, size);
                return -EINVAL;
        }

        return 0;
}
EXPORT_SYMBOL(bulk_sec_desc_unpack);

#ifdef __KERNEL__

#ifdef HAVE_ADLER
static int do_bulk_checksum_adler32(struct ptlrpc_bulk_desc *desc, void *buf)
{
        struct page    *page;
        int             off;
        char           *ptr;
        __u32           adler32 = 1;
        int             len, i;

        for (i = 0; i < desc->bd_iov_count; i++) {
                page = desc->bd_iov[i].kiov_page;
                off = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                ptr = cfs_kmap(page) + off;
                len = desc->bd_iov[i].kiov_len;

                adler32 = adler32(adler32, ptr, len);

                cfs_kunmap(page);
        }

        adler32 = cpu_to_le32(adler32);
        memcpy(buf, &adler32, sizeof(adler32));
        return 0;
}
#endif

static int do_bulk_checksum_crc32(struct ptlrpc_bulk_desc *desc, void *buf)
{
        struct page    *page;
        int             off;
        char           *ptr;
        __u32           crc32 = ~0;
        int             len, i;

        for (i = 0; i < desc->bd_iov_count; i++) {
                page = desc->bd_iov[i].kiov_page;
                off = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                ptr = cfs_kmap(page) + off;
                len = desc->bd_iov[i].kiov_len;

                crc32 = crc32_le(crc32, ptr, len);

                cfs_kunmap(page);
        }

        crc32 = cpu_to_le32(crc32);
        memcpy(buf, &crc32, sizeof(crc32));
        return 0;
}

static int do_bulk_checksum(struct ptlrpc_bulk_desc *desc, __u32 alg, void *buf)
{
        struct hash_desc    hdesc;
        struct scatterlist *sl;
        int i, rc = 0, bytes = 0;

        LASSERT(alg > BULK_HASH_ALG_NULL &&
                alg < BULK_HASH_ALG_MAX);

        switch (alg) {
        case BULK_HASH_ALG_ADLER32:
#ifdef HAVE_ADLER
                return do_bulk_checksum_adler32(desc, buf);
#else
                CERROR("Adler32 not supported\n");
                return -EINVAL;
#endif
        case BULK_HASH_ALG_CRC32:
                return do_bulk_checksum_crc32(desc, buf);
        }

        hdesc.tfm = ll_crypto_alloc_hash(hash_types[alg].sht_tfm_name, 0, 0);
        if (hdesc.tfm == NULL) {
                CERROR("Unable to allocate TFM %s\n", hash_types[alg].sht_name);
                return -ENOMEM;
        }
        hdesc.flags = 0;

        OBD_ALLOC(sl, sizeof(*sl) * desc->bd_iov_count);
        if (sl == NULL) {
                rc = -ENOMEM;
                goto out_tfm;
        }

        for (i = 0; i < desc->bd_iov_count; i++) {
                sl[i].page = desc->bd_iov[i].kiov_page;
                sl[i].offset = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                sl[i].length = desc->bd_iov[i].kiov_len;
                bytes += desc->bd_iov[i].kiov_len;
        }

        ll_crypto_hash_init(&hdesc);
        ll_crypto_hash_update(&hdesc, sl, bytes);
        ll_crypto_hash_final(&hdesc, buf);

        OBD_FREE(sl, sizeof(*sl) * desc->bd_iov_count);

out_tfm:
        ll_crypto_free_hash(hdesc.tfm);
        return rc;
}

#else /* !__KERNEL__ */

static int do_bulk_checksum(struct ptlrpc_bulk_desc *desc, __u32 alg, void *buf)
{
        __u32   csum32;
        int     i;

        LASSERT(alg == BULK_HASH_ALG_ADLER32 || alg == BULK_HASH_ALG_CRC32);

        if (alg == BULK_HASH_ALG_ADLER32)
                csum32 = 1;
        else
                csum32 = ~0;

        for (i = 0; i < desc->bd_iov_count; i++) {
                unsigned char *ptr = desc->bd_iov[i].iov_base;
                int len = desc->bd_iov[i].iov_len;

                switch (alg) {
                case BULK_HASH_ALG_ADLER32:
#ifdef HAVE_ADLER
                        csum32 = adler32(csum32, ptr, len);
#else
                        CERROR("Adler32 not supported\n");
                        return -EINVAL;
#endif
                        break;
                case BULK_HASH_ALG_CRC32:
                        csum32 = crc32_le(csum32, ptr, len);
                        break;
                }
        }

        csum32 = cpu_to_le32(csum32);
        memcpy(buf, &csum32, sizeof(csum32));
        return 0;
}

#endif /* __KERNEL__ */

/*
 * perform algorithm @alg checksum on @desc, store result in @buf.
 * if anything goes wrong, leave 'alg' be BULK_HASH_ALG_NULL.
 */
static
int generate_bulk_csum(struct ptlrpc_bulk_desc *desc, __u32 alg,
                       struct ptlrpc_bulk_sec_desc *bsd, int bsdsize)
{
        int rc;

        LASSERT(bsd);
        LASSERT(alg < BULK_HASH_ALG_MAX);

        bsd->bsd_hash_alg = BULK_HASH_ALG_NULL;

        if (alg == BULK_HASH_ALG_NULL)
                return 0;

        LASSERT(bsdsize >= sizeof(*bsd) + hash_types[alg].sht_size);

        rc = do_bulk_checksum(desc, alg, bsd->bsd_csum);
        if (rc == 0)
                bsd->bsd_hash_alg = alg;

        return rc;
}

static
int verify_bulk_csum(struct ptlrpc_bulk_desc *desc, int read,
                     struct ptlrpc_bulk_sec_desc *bsdv, int bsdvsize,
                     struct ptlrpc_bulk_sec_desc *bsdr, int bsdrsize)
{
        char *csum_p;
        char *buf = NULL;
        int   csum_size, rc = 0;

        LASSERT(bsdv);
        LASSERT(bsdv->bsd_hash_alg < BULK_HASH_ALG_MAX);

        if (bsdr)
                bsdr->bsd_hash_alg = BULK_HASH_ALG_NULL;

        if (bsdv->bsd_hash_alg == BULK_HASH_ALG_NULL)
                return 0;

        /* for all supported algorithms */
        csum_size = hash_types[bsdv->bsd_hash_alg].sht_size;

        if (bsdvsize < sizeof(*bsdv) + csum_size) {
                CERROR("verifier size %d too small, require %d\n",
                       bsdvsize, (int) sizeof(*bsdv) + csum_size);
                return -EINVAL;
        }

        if (bsdr) {
                LASSERT(bsdrsize >= sizeof(*bsdr) + csum_size);
                csum_p = (char *) bsdr->bsd_csum;
        } else {
                OBD_ALLOC(buf, csum_size);
                if (buf == NULL)
                        return -EINVAL;
                csum_p = buf;
        }

        rc = do_bulk_checksum(desc, bsdv->bsd_hash_alg, csum_p);

        if (memcmp(bsdv->bsd_csum, csum_p, csum_size)) {
                CERROR("BAD %s CHECKSUM (%s), data mutated during "
                       "transfer!\n", read ? "READ" : "WRITE",
                       hash_types[bsdv->bsd_hash_alg].sht_name);
                rc = -EINVAL;
        } else {
                CDEBUG(D_SEC, "bulk %s checksum (%s) verified\n",
                      read ? "read" : "write",
                      hash_types[bsdv->bsd_hash_alg].sht_name);
        }

        if (bsdr) {
                bsdr->bsd_hash_alg = bsdv->bsd_hash_alg;
                memcpy(bsdr->bsd_csum, csum_p, csum_size);
        } else {
                LASSERT(buf);
                OBD_FREE(buf, csum_size);
        }

        return rc;
}

int bulk_csum_cli_request(struct ptlrpc_bulk_desc *desc, int read,
                          __u32 alg, struct lustre_msg *rmsg, int roff)
{
        struct ptlrpc_bulk_sec_desc *bsdr;
        int    rsize, rc = 0;

        rsize = rmsg->lm_buflens[roff];
        bsdr = lustre_msg_buf(rmsg, roff, sizeof(*bsdr));

        LASSERT(bsdr);
        LASSERT(rsize >= sizeof(*bsdr));
        LASSERT(alg < BULK_HASH_ALG_MAX);

        if (read) {
                bsdr->bsd_hash_alg = alg;
        } else {
                rc = generate_bulk_csum(desc, alg, bsdr, rsize);
                if (rc)
                        CERROR("bulk write: client failed to compute "
                               "checksum: %d\n", rc);

                /* For sending we only compute the wrong checksum instead
                 * of corrupting the data so it is still correct on a redo */
                if (rc == 0 && OBD_FAIL_CHECK(OBD_FAIL_OSC_CHECKSUM_SEND) &&
                    bsdr->bsd_hash_alg != BULK_HASH_ALG_NULL)
                        bsdr->bsd_csum[0] ^= 0x1;
        }

        return rc;
}
EXPORT_SYMBOL(bulk_csum_cli_request);

int bulk_csum_cli_reply(struct ptlrpc_bulk_desc *desc, int read,
                        struct lustre_msg *rmsg, int roff,
                        struct lustre_msg *vmsg, int voff)
{
        struct ptlrpc_bulk_sec_desc *bsdv, *bsdr;
        int    rsize, vsize;

        rsize = rmsg->lm_buflens[roff];
        vsize = vmsg->lm_buflens[voff];
        bsdr = lustre_msg_buf(rmsg, roff, 0);
        bsdv = lustre_msg_buf(vmsg, voff, 0);

        if (bsdv == NULL || vsize < sizeof(*bsdv)) {
                CERROR("Invalid checksum verifier from server: size %d\n",
                       vsize);
                return -EINVAL;
        }

        LASSERT(bsdr);
        LASSERT(rsize >= sizeof(*bsdr));
        LASSERT(vsize >= sizeof(*bsdv));

        if (bsdr->bsd_hash_alg != bsdv->bsd_hash_alg) {
                CERROR("bulk %s: checksum algorithm mismatch: client request "
                       "%s but server reply with %s. try to use the new one "
                       "for checksum verification\n",
                       read ? "read" : "write",
                       hash_types[bsdr->bsd_hash_alg].sht_name,
                       hash_types[bsdv->bsd_hash_alg].sht_name);
        }

        if (read)
                return verify_bulk_csum(desc, 1, bsdv, vsize, NULL, 0);
        else {
                char *cli, *srv, *new = NULL;
                int csum_size = hash_types[bsdr->bsd_hash_alg].sht_size;

                LASSERT(bsdr->bsd_hash_alg < BULK_HASH_ALG_MAX);
                if (bsdr->bsd_hash_alg == BULK_HASH_ALG_NULL)
                        return 0;

                if (vsize < sizeof(*bsdv) + csum_size) {
                        CERROR("verifier size %d too small, require %d\n",
                               vsize, (int) sizeof(*bsdv) + csum_size);
                        return -EINVAL;
                }

                cli = (char *) (bsdr + 1);
                srv = (char *) (bsdv + 1);

                if (!memcmp(cli, srv, csum_size)) {
                        /* checksum confirmed */
                        CDEBUG(D_SEC, "bulk write checksum (%s) confirmed\n",
                               hash_types[bsdr->bsd_hash_alg].sht_name);
                        return 0;
                }

                /* checksum mismatch, re-compute a new one and compare with
                 * others, give out proper warnings. */
                OBD_ALLOC(new, csum_size);
                if (new == NULL)
                        return -ENOMEM;

                do_bulk_checksum(desc, bsdr->bsd_hash_alg, new);

                if (!memcmp(new, srv, csum_size)) {
                        CERROR("BAD WRITE CHECKSUM (%s): pages were mutated "
                               "on the client after we checksummed them\n",
                               hash_types[bsdr->bsd_hash_alg].sht_name);
                } else if (!memcmp(new, cli, csum_size)) {
                        CERROR("BAD WRITE CHECKSUM (%s): pages were mutated "
                               "in transit\n",
                               hash_types[bsdr->bsd_hash_alg].sht_name);
                } else {
                        CERROR("BAD WRITE CHECKSUM (%s): pages were mutated "
                               "in transit, and the current page contents "
                               "don't match the originals and what the server "
                               "received\n",
                               hash_types[bsdr->bsd_hash_alg].sht_name);
                }
                OBD_FREE(new, csum_size);

                return -EINVAL;
        }
}
EXPORT_SYMBOL(bulk_csum_cli_reply);

#ifdef __KERNEL__
static void corrupt_bulk_data(struct ptlrpc_bulk_desc *desc)
{
        char           *ptr;
        unsigned int    off, i;

        for (i = 0; i < desc->bd_iov_count; i++) {
                if (desc->bd_iov[i].kiov_len == 0)
                        continue;

                ptr = cfs_kmap(desc->bd_iov[i].kiov_page);
                off = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                ptr[off] ^= 0x1;
                cfs_kunmap(desc->bd_iov[i].kiov_page);
                return;
        }
}
#else
static void corrupt_bulk_data(struct ptlrpc_bulk_desc *desc)
{
}
#endif /* __KERNEL__ */

int bulk_csum_svc(struct ptlrpc_bulk_desc *desc, int read,
                  struct ptlrpc_bulk_sec_desc *bsdv, int vsize,
                  struct ptlrpc_bulk_sec_desc *bsdr, int rsize)
{
        int    rc;

        LASSERT(vsize >= sizeof(*bsdv));
        LASSERT(rsize >= sizeof(*bsdr));
        LASSERT(bsdv && bsdr);

        if (read) {
                rc = generate_bulk_csum(desc, bsdv->bsd_hash_alg, bsdr, rsize);
                if (rc)
                        CERROR("bulk read: server failed to generate %s "
                               "checksum: %d\n",
                               hash_types[bsdv->bsd_hash_alg].sht_name, rc);

                /* corrupt the data after we compute the checksum, to
                 * simulate an OST->client data error */
                if (rc == 0 && OBD_FAIL_CHECK(OBD_FAIL_OSC_CHECKSUM_RECEIVE))
                        corrupt_bulk_data(desc);
        } else {
                rc = verify_bulk_csum(desc, 0, bsdv, vsize, bsdr, rsize);
        }

        return rc;
}
EXPORT_SYMBOL(bulk_csum_svc);

/****************************************
 * Helpers to assist policy modules to  *
 * implement encryption funcationality  *
 ****************************************/

/* FIXME */
#ifndef __KERNEL__
#define CRYPTO_TFM_MODE_ECB     (0)
#define CRYPTO_TFM_MODE_CBC     (1)
#endif

static struct sptlrpc_ciph_type cipher_types[] = {
        [BULK_CIPH_ALG_NULL]    = {
                "null",         "null",       0,                   0,  0
        },
        [BULK_CIPH_ALG_ARC4]    = {
                "arc4",         "ecb(arc4)",       0, 0,  16
        },
        [BULK_CIPH_ALG_AES128]  = {
                "aes128",       "cbc(aes)",        0, 16, 16
        },
        [BULK_CIPH_ALG_AES192]  = {
                "aes192",       "cbc(aes)",        0, 16, 24
        },
        [BULK_CIPH_ALG_AES256]  = {
                "aes256",       "cbc(aes)",        0, 16, 32
        },
        [BULK_CIPH_ALG_CAST128] = {
                "cast128",      "cbc(cast5)",      0, 8,  16
        },
        [BULK_CIPH_ALG_CAST256] = {
                "cast256",      "cbc(cast6)",      0, 16, 32
        },
        [BULK_CIPH_ALG_TWOFISH128] = {
                "twofish128",   "cbc(twofish)",    0, 16, 16
        },
        [BULK_CIPH_ALG_TWOFISH256] = {
                "twofish256",   "cbc(twofish)",    0, 16, 32
        },
};

const struct sptlrpc_ciph_type *sptlrpc_get_ciph_type(__u8 ciph_alg)
{
        struct sptlrpc_ciph_type *ct;

        if (ciph_alg < BULK_CIPH_ALG_MAX) {
                ct = &cipher_types[ciph_alg];
                if (ct->sct_tfm_name)
                        return ct;
        }
        return NULL;
}
EXPORT_SYMBOL(sptlrpc_get_ciph_type);

const char *sptlrpc_get_ciph_name(__u8 ciph_alg)
{
        const struct sptlrpc_ciph_type *ct;

        ct = sptlrpc_get_ciph_type(ciph_alg);
        if (ct)
                return ct->sct_name;
        else
                return "unknown";
}
EXPORT_SYMBOL(sptlrpc_get_ciph_name);
