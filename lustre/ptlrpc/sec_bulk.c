/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2006 Cluster File Systems, Inc.
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

static struct ptlrpc_enc_page_pool {
        /*
         * constants
         */
        unsigned long    epp_max_pages;   /* maximum pages can hold, const */
        unsigned int     epp_max_pools;   /* number of pools, const */
        /*
         * users of the pools. the capacity grow as more user added,
         * but doesn't shrink when users gone -- just current policy.
         * during failover there might be user add/remove activities.
         */
        atomic_t         epp_users;       /* shared by how many users (osc) */
        atomic_t         epp_users_gone;  /* users removed */
        /*
         * wait queue in case of not enough free pages.
         */
        cfs_waitq_t      epp_waitq;       /* waiting threads */
        unsigned int     epp_waitqlen;    /* wait queue length */
        unsigned long    epp_pages_short; /* # of pages wanted of in-q users */
        unsigned long    epp_adding:1,    /* during adding pages */
                         epp_full:1;      /* pools are all full */
        /*
         * in-pool pages bookkeeping
         */
        spinlock_t       epp_lock;        /* protect following fields */
        unsigned long    epp_total_pages; /* total pages in pools */
        unsigned long    epp_free_pages;  /* current pages available */
        /*
         * statistics
         */
        unsigned int     epp_st_adds;
        unsigned int     epp_st_failadds; /* # of add pages failures */
        unsigned long    epp_st_reqs;     /* # of get_pages requests */
        unsigned long    epp_st_missings; /* # of cache missing */
        unsigned long    epp_st_lowfree;  /* lowest free pages ever reached */
        unsigned long    epp_st_max_wqlen;/* highest waitqueue length ever */
        cfs_time_t       epp_st_max_wait; /* in jeffies */
        /*
         * pointers to pools
         */
        cfs_page_t    ***epp_pools;
} page_pools;

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
                      "users:                   %d - %d\n"
                      "current waitqueue len:   %u\n"
                      "current pages in short:  %lu\n"
                      "total pages:             %lu\n"
                      "total free:              %lu\n"
                      "add page times:          %u\n"
                      "add page failed times:   %u\n"
                      "total requests:          %lu\n"
                      "cache missing:           %lu\n"
                      "lowest free pages:       %lu\n"
                      "max waitqueue depth:     %lu\n"
                      "max wait time:           "CFS_TIME_T"\n"
                      ,
                      num_physpages,
                      PAGES_PER_POOL,
                      page_pools.epp_max_pages,
                      page_pools.epp_max_pools,
                      atomic_read(&page_pools.epp_users),
                      atomic_read(&page_pools.epp_users_gone),
                      page_pools.epp_waitqlen,
                      page_pools.epp_pages_short,
                      page_pools.epp_total_pages,
                      page_pools.epp_free_pages,
                      page_pools.epp_st_adds,
                      page_pools.epp_st_failadds,
                      page_pools.epp_st_reqs,
                      page_pools.epp_st_missings,
                      page_pools.epp_st_lowfree,
                      page_pools.epp_st_max_wqlen,
                      page_pools.epp_st_max_wait
                     );

        spin_unlock(&page_pools.epp_lock);
        return rc;
}

static inline
int npages_to_npools(unsigned long npages)
{
        return (int) ((npages + PAGES_PER_POOL - 1) / PAGES_PER_POOL);
}

/*
 * return how many pages cleaned up.
 */
static unsigned long enc_cleanup_pools(cfs_page_t ***pools, int npools)
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
static void enc_insert_pool(cfs_page_t ***pools, int npools, int npages)
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
        /*
         * free slots are those left by rent pages, and the extra ones with
         * index >= eep_total_pages, locate at the tail of last pool.
         */
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

        if (page_pools.epp_total_pages == page_pools.epp_max_pages)
                page_pools.epp_full = 1;

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

        down(&sem_add_pages);

        if (npages > page_pools.epp_max_pages - page_pools.epp_total_pages)
                npages = page_pools.epp_max_pages - page_pools.epp_total_pages;
        if (npages == 0) {
                rc = 0;
                goto out;
        }

        page_pools.epp_st_adds++;

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

        enc_insert_pool(pools, npools, npages);
        CDEBUG(D_SEC, "add %d pages into enc page pools\n", npages);
        rc = 0;

out_pools:
        enc_cleanup_pools(pools, npools);
        OBD_FREE(pools, npools * sizeof(*pools));
out:
        if (rc) {
                page_pools.epp_st_failadds++;
                CERROR("Failed to pre-allocate %d enc pages\n", npages);
        }

        up(&sem_add_pages);
        return rc;
}

/*
 * both "max bulk rpcs inflight" and "lnet MTU" are tunable, we use the
 * default fixed value initially.
 */
int sptlrpc_enc_pool_add_user(void)
{
        int page_plus = PTLRPC_MAX_BRW_PAGES * OSC_MAX_RIF_DEFAULT;
        int users, users_gone, shift, rc;

        LASSERT(!in_interrupt());
        LASSERT(atomic_read(&page_pools.epp_users) >= 0);

        users_gone = atomic_dec_return(&page_pools.epp_users_gone);
        if (users_gone >= 0) {
                CWARN("%d users gone, skip\n", users_gone + 1);
                return 0;
        }
        atomic_inc(&page_pools.epp_users_gone);

        /*
         * prepare full pages for first 2 users; 1/2 for next 2 users;
         * 1/4 for next 4 users; 1/8 for next 8 users; 1/16 for next 16 users;
         * ...
         */
        users = atomic_add_return(1, &page_pools.epp_users);
        shift = fls(users - 1);
        shift = shift > 1 ? shift - 1 : 0;
        page_plus = page_plus >> shift;
        page_plus = page_plus > 2 ? page_plus : 2;

        rc = enc_pools_add_pages(page_plus);
        return 0;
}
EXPORT_SYMBOL(sptlrpc_enc_pool_add_user);

int sptlrpc_enc_pool_del_user(void)
{
        atomic_inc(&page_pools.epp_users_gone);
        return 0;
}
EXPORT_SYMBOL(sptlrpc_enc_pool_del_user);

/*
 * we allocate the requested pages atomically.
 */
int sptlrpc_enc_pool_get_pages(struct ptlrpc_bulk_desc *desc)
{
        cfs_waitlink_t  waitlink;
        cfs_time_t      tick1 = 0, tick2;
        int             p_idx, g_idx;
        int             i;

        LASSERT(desc->bd_max_iov > 0);
        LASSERT(desc->bd_max_iov <= page_pools.epp_total_pages);

        /* resent bulk, enc pages might have been allocated previously */
        if (desc->bd_enc_pages != NULL)
                return 0;

        OBD_ALLOC(desc->bd_enc_pages,
                  desc->bd_max_iov * sizeof(*desc->bd_enc_pages));
        if (desc->bd_enc_pages == NULL)
                return -ENOMEM;

        spin_lock(&page_pools.epp_lock);
again:
        page_pools.epp_st_reqs++;

        if (unlikely(page_pools.epp_free_pages < desc->bd_max_iov)) {
                if (tick1 == 0)
                        tick1 = cfs_time_current();

                page_pools.epp_st_missings++;
                page_pools.epp_pages_short += desc->bd_max_iov;

                if (++page_pools.epp_waitqlen > page_pools.epp_st_max_wqlen)
                        page_pools.epp_st_max_wqlen = page_pools.epp_waitqlen;
                /*
                 * we just wait if someone else is adding more pages, or
                 * wait queue length is not deep enough. otherwise try to
                 * add more pages in the pools.
                 *
                 * FIXME the policy of detecting resource tight & growing pool
                 * need to be reconsidered.
                 */
                if (page_pools.epp_adding || page_pools.epp_waitqlen < 2 ||
                    page_pools.epp_full) {
                        set_current_state(TASK_UNINTERRUPTIBLE);
                        cfs_waitlink_init(&waitlink);
                        cfs_waitq_add(&page_pools.epp_waitq, &waitlink);

                        spin_unlock(&page_pools.epp_lock);
                        cfs_schedule();
                        spin_lock(&page_pools.epp_lock);
                } else {
                        page_pools.epp_adding = 1;

                        spin_unlock(&page_pools.epp_lock);
                        enc_pools_add_pages(page_pools.epp_pages_short / 2);
                        spin_lock(&page_pools.epp_lock);

                        page_pools.epp_adding = 0;
                }

                LASSERT(page_pools.epp_pages_short >= desc->bd_max_iov);
                LASSERT(page_pools.epp_waitqlen > 0);
                page_pools.epp_pages_short -= desc->bd_max_iov;
                page_pools.epp_waitqlen--;

                goto again;
        }
        /*
         * record max wait time
         */
        if (unlikely(tick1 != 0)) {
                tick2 = cfs_time_current();
                if (tick2 - tick1 > page_pools.epp_st_max_wait)
                        page_pools.epp_st_max_wait = tick2 - tick1;
        }
        /*
         * proceed with rest of allocation
         */
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

        if (unlikely(page_pools.epp_waitqlen)) {
                LASSERT(page_pools.epp_waitqlen > 0);
                LASSERT(cfs_waitq_active(&page_pools.epp_waitq));
                cfs_waitq_broadcast(&page_pools.epp_waitq);
        }

        spin_unlock(&page_pools.epp_lock);

        OBD_FREE(desc->bd_enc_pages,
                 desc->bd_max_iov * sizeof(*desc->bd_enc_pages));
        desc->bd_enc_pages = NULL;
}
EXPORT_SYMBOL(sptlrpc_enc_pool_put_pages);

int sptlrpc_enc_pool_init(void)
{
        /* constants */
        page_pools.epp_max_pages = num_physpages / 4;
        page_pools.epp_max_pools = npages_to_npools(page_pools.epp_max_pages);

        atomic_set(&page_pools.epp_users, 0);
        atomic_set(&page_pools.epp_users_gone, 0);

        cfs_waitq_init(&page_pools.epp_waitq);
        page_pools.epp_waitqlen = 0;
        page_pools.epp_pages_short = 0;

        page_pools.epp_adding = 0;
        page_pools.epp_full = 0;

        spin_lock_init(&page_pools.epp_lock);
        page_pools.epp_total_pages = 0;
        page_pools.epp_free_pages = 0;

        page_pools.epp_st_adds = 0;
        page_pools.epp_st_failadds = 0;
        page_pools.epp_st_reqs = 0;
        page_pools.epp_st_missings = 0;
        page_pools.epp_st_lowfree = 0;
        page_pools.epp_st_max_wqlen = 0;
        page_pools.epp_st_max_wait = 0;

        OBD_ALLOC(page_pools.epp_pools,
                  page_pools.epp_max_pools * sizeof(*page_pools.epp_pools));
        if (page_pools.epp_pools == NULL)
                return -ENOMEM;

        return 0;
}

void sptlrpc_enc_pool_fini(void)
{
        unsigned long cleaned, npools;

        LASSERT(page_pools.epp_pools);
        LASSERT(page_pools.epp_total_pages == page_pools.epp_free_pages);

        npools = npages_to_npools(page_pools.epp_total_pages);
        cleaned = enc_cleanup_pools(page_pools.epp_pools, npools);
        LASSERT(cleaned == page_pools.epp_total_pages);

        OBD_FREE(page_pools.epp_pools,
                 page_pools.epp_max_pools * sizeof(*page_pools.epp_pools));
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

static struct {
        char    *name;
        int      size;
} csum_types[] = {
        [BULK_CSUM_ALG_NULL]    = { "null",     0 },
        [BULK_CSUM_ALG_CRC32]   = { "crc32",    4 },
        [BULK_CSUM_ALG_MD5]     = { "md5",     16 },
        [BULK_CSUM_ALG_SHA1]    = { "sha1",    20 },
        [BULK_CSUM_ALG_SHA256]  = { "sha256",  32 },
        [BULK_CSUM_ALG_SHA384]  = { "sha384",  48 },
        [BULK_CSUM_ALG_SHA512]  = { "sha512",  64 },
};

const char * sptlrpc_bulk_csum_alg2name(__u32 csum_alg)
{
        if (csum_alg < BULK_CSUM_ALG_MAX)
                return csum_types[csum_alg].name;
        return "unknown_cksum";
}
EXPORT_SYMBOL(sptlrpc_bulk_csum_alg2name);

int bulk_sec_desc_size(__u32 csum_alg, int request, int read)
{
        int size = sizeof(struct ptlrpc_bulk_sec_desc);

        LASSERT(csum_alg < BULK_CSUM_ALG_MAX);

        /* read request don't need extra data */
        if (!(read && request))
                size += csum_types[csum_alg].size;

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

        if (lustre_msg_swabbed(msg)) {
                __swab32s(&bsd->bsd_version);
                __swab32s(&bsd->bsd_pad);
                __swab32s(&bsd->bsd_csum_alg);
                __swab32s(&bsd->bsd_priv_alg);
        }

        if (bsd->bsd_version != 0) {
                CERROR("Unexpected version %u\n", bsd->bsd_version);
                return -EPROTO;
        }

        if (bsd->bsd_csum_alg >= BULK_CSUM_ALG_MAX) {
                CERROR("Unsupported checksum algorithm %u\n",
                       bsd->bsd_csum_alg);
                return -EINVAL;
        }
        if (bsd->bsd_priv_alg >= BULK_PRIV_ALG_MAX) {
                CERROR("Unsupported cipher algorithm %u\n",
                       bsd->bsd_priv_alg);
                return -EINVAL;
        }

        if (size > sizeof(*bsd) &&
            size < sizeof(*bsd) + csum_types[bsd->bsd_csum_alg].size) {
                CERROR("Mal-formed checksum data: csum alg %u, size %d\n",
                       bsd->bsd_csum_alg, size);
                return -EINVAL;
        }

        return 0;
}
EXPORT_SYMBOL(bulk_sec_desc_unpack);

#ifdef __KERNEL__
static
int do_bulk_checksum_crc32(struct ptlrpc_bulk_desc *desc, void *buf)
{
        struct page *page;
        int off;
        char *ptr;
        __u32 crc32 = ~0;
        int len, i;

        for (i = 0; i < desc->bd_iov_count; i++) {
                page = desc->bd_iov[i].kiov_page;
                off = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                ptr = cfs_kmap(page) + off;
                len = desc->bd_iov[i].kiov_len;

                crc32 = crc32_le(crc32, ptr, len);

                cfs_kunmap(page);
        }

        *((__u32 *) buf) = crc32;
        return 0;
}

static
int do_bulk_checksum(struct ptlrpc_bulk_desc *desc, __u32 alg, void *buf)
{
        struct crypto_tfm *tfm;
        struct scatterlist *sl;
        int i, rc = 0;

        LASSERT(alg > BULK_CSUM_ALG_NULL &&
                alg < BULK_CSUM_ALG_MAX);

        if (alg == BULK_CSUM_ALG_CRC32)
                return do_bulk_checksum_crc32(desc, buf);

        tfm = crypto_alloc_tfm(csum_types[alg].name, 0);
        if (tfm == NULL) {
                CERROR("Unable to allocate tfm %s\n", csum_types[alg].name);
                return -ENOMEM;
        }

        OBD_ALLOC(sl, sizeof(*sl) * desc->bd_iov_count);
        if (sl == NULL) {
                rc = -ENOMEM;
                goto out_tfm;
        }

        for (i = 0; i < desc->bd_iov_count; i++) {
                sl[i].page = desc->bd_iov[i].kiov_page;
                sl[i].offset = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                sl[i].length = desc->bd_iov[i].kiov_len;
        }

        crypto_digest_init(tfm);
        crypto_digest_update(tfm, sl, desc->bd_iov_count);
        crypto_digest_final(tfm, buf);

        OBD_FREE(sl, sizeof(*sl) * desc->bd_iov_count);

out_tfm:
        crypto_free_tfm(tfm);
        return rc;
}
                         
#else /* !__KERNEL__ */
static
int do_bulk_checksum(struct ptlrpc_bulk_desc *desc, __u32 alg, void *buf)
{
        __u32 crc32 = ~0;
        int i;

        LASSERT(alg == BULK_CSUM_ALG_CRC32);

        for (i = 0; i < desc->bd_iov_count; i++) {
                char *ptr = desc->bd_iov[i].iov_base;
                int len = desc->bd_iov[i].iov_len;

                crc32 = crc32_le(crc32, ptr, len);
        }

        *((__u32 *) buf) = crc32;
        return 0;
}
#endif

/*
 * perform algorithm @alg checksum on @desc, store result in @buf.
 * if anything goes wrong, leave 'alg' be BULK_CSUM_ALG_NULL.
 */
static
int generate_bulk_csum(struct ptlrpc_bulk_desc *desc, __u32 alg,
                       struct ptlrpc_bulk_sec_desc *bsd, int bsdsize)
{
        int rc;

        LASSERT(bsd);
        LASSERT(alg < BULK_CSUM_ALG_MAX);

        bsd->bsd_csum_alg = BULK_CSUM_ALG_NULL;

        if (alg == BULK_CSUM_ALG_NULL)
                return 0;

        LASSERT(bsdsize >= sizeof(*bsd) + csum_types[alg].size);

        rc = do_bulk_checksum(desc, alg, bsd->bsd_csum);
        if (rc == 0)
                bsd->bsd_csum_alg = alg;

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
        LASSERT(bsdv->bsd_csum_alg < BULK_CSUM_ALG_MAX);

        if (bsdr)
                bsdr->bsd_csum_alg = BULK_CSUM_ALG_NULL;

        if (bsdv->bsd_csum_alg == BULK_CSUM_ALG_NULL)
                return 0;

        /* for all supported algorithms */
        csum_size = csum_types[bsdv->bsd_csum_alg].size;

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

        rc = do_bulk_checksum(desc, bsdv->bsd_csum_alg, csum_p);

        if (memcmp(bsdv->bsd_csum, csum_p, csum_size)) {
                CERROR("BAD %s CHECKSUM (%s), data mutated during "
                       "transfer!\n", read ? "READ" : "WRITE",
                       csum_types[bsdv->bsd_csum_alg].name);
                rc = -EINVAL;
        } else {
                CDEBUG(D_SEC, "bulk %s checksum (%s) verified\n",
                      read ? "read" : "write",
                      csum_types[bsdv->bsd_csum_alg].name);
        }

        if (bsdr) {
                bsdr->bsd_csum_alg = bsdv->bsd_csum_alg;
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
        LASSERT(alg < BULK_CSUM_ALG_MAX);

        if (read)
                bsdr->bsd_csum_alg = alg;
        else {
                rc = generate_bulk_csum(desc, alg, bsdr, rsize);
                if (rc) {
                        CERROR("client bulk write: failed to perform "
                               "checksum: %d\n", rc);
                }
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

        if (bsdr->bsd_csum_alg != bsdv->bsd_csum_alg) {
                CERROR("bulk %s: checksum algorithm mismatch: client request "
                       "%s but server reply with %s. try to use the new one "
                       "for checksum verification\n",
                       read ? "read" : "write",
                       csum_types[bsdr->bsd_csum_alg].name,
                       csum_types[bsdv->bsd_csum_alg].name);
        }

        if (read)
                return verify_bulk_csum(desc, 1, bsdv, vsize, NULL, 0);
        else {
                char *cli, *srv, *new = NULL;
                int csum_size = csum_types[bsdr->bsd_csum_alg].size;

                LASSERT(bsdr->bsd_csum_alg < BULK_CSUM_ALG_MAX);
                if (bsdr->bsd_csum_alg == BULK_CSUM_ALG_NULL)
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
                              csum_types[bsdr->bsd_csum_alg].name);
                        return 0;
                }

                /* checksum mismatch, re-compute a new one and compare with
                 * others, give out proper warnings.
                 */
                OBD_ALLOC(new, csum_size);
                if (new == NULL)
                        return -ENOMEM;

                do_bulk_checksum(desc, bsdr->bsd_csum_alg, new);

                if (!memcmp(new, srv, csum_size)) {
                        CERROR("BAD WRITE CHECKSUM (%s): pages were mutated "
                               "on the client after we checksummed them\n",
                               csum_types[bsdr->bsd_csum_alg].name);
                } else if (!memcmp(new, cli, csum_size)) {
                        CERROR("BAD WRITE CHECKSUM (%s): pages were mutated "
                               "in transit\n",
                               csum_types[bsdr->bsd_csum_alg].name);
                } else {
                        CERROR("BAD WRITE CHECKSUM (%s): pages were mutated "
                               "in transit, and the current page contents "
                               "don't match the originals and what the server "
                               "received\n",
                               csum_types[bsdr->bsd_csum_alg].name);
                }
                OBD_FREE(new, csum_size);

                return -EINVAL;
        }
}
EXPORT_SYMBOL(bulk_csum_cli_reply);

int bulk_csum_svc(struct ptlrpc_bulk_desc *desc, int read,
                  struct ptlrpc_bulk_sec_desc *bsdv, int vsize,
                  struct ptlrpc_bulk_sec_desc *bsdr, int rsize)
{
        int    rc;

        LASSERT(vsize >= sizeof(*bsdv));
        LASSERT(rsize >= sizeof(*bsdr));
        LASSERT(bsdv && bsdr);

        if (read) {
                rc = generate_bulk_csum(desc, bsdv->bsd_csum_alg, bsdr, rsize);
                if (rc)
                        CERROR("bulk read: server failed to generate %s "
                               "checksum: %d\n",
                               csum_types[bsdv->bsd_csum_alg].name, rc);
        } else
                rc = verify_bulk_csum(desc, 0, bsdv, vsize, bsdr, rsize);

        return rc;
}
EXPORT_SYMBOL(bulk_csum_svc);

/****************************************
 * Helpers to assist policy modules to  *
 * implement encryption funcationality  *
 ****************************************/

/*
 * NOTE: These algorithms must be stream cipher!
 */
static struct {
        char    *name;
        __u32    flags;
} priv_types[] = {
        [BULK_PRIV_ALG_NULL]   = { "null", 0   },
        [BULK_PRIV_ALG_ARC4]   = { "arc4", 0   },
};

const char * sptlrpc_bulk_priv_alg2name(__u32 priv_alg)
{
        if (priv_alg < BULK_PRIV_ALG_MAX)
                return priv_types[priv_alg].name;
        return "unknown_priv";
}
EXPORT_SYMBOL(sptlrpc_bulk_priv_alg2name);

__u32 sptlrpc_bulk_priv_alg2flags(__u32 priv_alg)
{
        if (priv_alg < BULK_PRIV_ALG_MAX)
                return priv_types[priv_alg].flags;
        return 0;
}
EXPORT_SYMBOL(sptlrpc_bulk_priv_alg2flags);
