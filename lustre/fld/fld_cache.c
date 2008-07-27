/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/fld/fld_cache.c
 *
 * FLD (Fids Location Database)
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_FLD

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/module.h>
# include <linux/jbd.h>
# include <asm/div64.h>
#else /* __KERNEL__ */
# include <liblustre.h>
# include <libcfs/list.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <dt_object.h>
#include <md_object.h>
#include <lustre_req_layout.h>
#include <lustre_fld.h>
#include "fld_internal.h"

#ifdef __KERNEL__
static inline __u32 fld_cache_hash(seqno_t seq)
{
        return (__u32)seq;
}

void fld_cache_flush(struct fld_cache *cache)
{
        struct fld_cache_entry *flde;
        struct hlist_head *bucket;
        struct hlist_node *scan;
        struct hlist_node *next;
        int i;
        ENTRY;

	/* Free all cache entries. */
	spin_lock(&cache->fci_lock);
	for (i = 0; i < cache->fci_hash_size; i++) {
		bucket = cache->fci_hash_table + i;
		hlist_for_each_entry_safe(flde, scan, next, bucket, fce_list) {
			hlist_del_init(&flde->fce_list);
                        list_del_init(&flde->fce_lru);
                        cache->fci_cache_count--;
			OBD_FREE_PTR(flde);
		}
	}
        spin_unlock(&cache->fci_lock);
        EXIT;
}

struct fld_cache *fld_cache_init(const char *name, int hash_size,
                                 int cache_size, int cache_threshold)
{
	struct fld_cache *cache;
        int i;
        ENTRY;

        LASSERT(name != NULL);
        LASSERT(IS_PO2(hash_size));
        LASSERT(cache_threshold < cache_size);

        OBD_ALLOC_PTR(cache);
        if (cache == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        INIT_LIST_HEAD(&cache->fci_lru);

	cache->fci_cache_count = 0;
        spin_lock_init(&cache->fci_lock);

        strncpy(cache->fci_name, name,
                sizeof(cache->fci_name));

	cache->fci_hash_size = hash_size;
	cache->fci_cache_size = cache_size;
        cache->fci_threshold = cache_threshold;

        /* Init fld cache info. */
        cache->fci_hash_mask = hash_size - 1;
        OBD_ALLOC(cache->fci_hash_table,
                  hash_size * sizeof(*cache->fci_hash_table));
        if (cache->fci_hash_table == NULL) {
                OBD_FREE_PTR(cache);
                RETURN(ERR_PTR(-ENOMEM));
        }

        for (i = 0; i < hash_size; i++)
                INIT_HLIST_HEAD(&cache->fci_hash_table[i]);
        memset(&cache->fci_stat, 0, sizeof(cache->fci_stat));

        CDEBUG(D_INFO, "%s: FLD cache - Size: %d, Threshold: %d\n",
               cache->fci_name, cache_size, cache_threshold);

        RETURN(cache);
}
EXPORT_SYMBOL(fld_cache_init);

void fld_cache_fini(struct fld_cache *cache)
{
        __u64 pct;
        ENTRY;

        LASSERT(cache != NULL);
        fld_cache_flush(cache);

        if (cache->fci_stat.fst_count > 0) {
                pct = cache->fci_stat.fst_cache * 100;
                do_div(pct, cache->fci_stat.fst_count);
        } else {
                pct = 0;
        }

        printk("FLD cache statistics (%s):\n", cache->fci_name);
        printk("  Total reqs: "LPU64"\n", cache->fci_stat.fst_count);
        printk("  Cache reqs: "LPU64"\n", cache->fci_stat.fst_cache);
        printk("  Saved RPCs: "LPU64"\n", cache->fci_stat.fst_inflight);
        printk("  Cache hits: "LPU64"%%\n", pct);

	OBD_FREE(cache->fci_hash_table, cache->fci_hash_size *
		 sizeof(*cache->fci_hash_table));
	OBD_FREE_PTR(cache);
	
        EXIT;
}
EXPORT_SYMBOL(fld_cache_fini);

static inline struct hlist_head *
fld_cache_bucket(struct fld_cache *cache, seqno_t seq)
{
        return cache->fci_hash_table + (fld_cache_hash(seq) &
                                        cache->fci_hash_mask);
}

/*
 * Check if cache needs to be shrinked. If so - do it. Tries to keep all
 * collision lists well balanced. That is, check all of them and remove one
 * entry in list and so on until cache is shrinked enough.
 */
static int fld_cache_shrink(struct fld_cache *cache)
{
        struct fld_cache_entry *flde;
        struct list_head *curr;
        int num = 0;
        ENTRY;

        LASSERT(cache != NULL);

        if (cache->fci_cache_count < cache->fci_cache_size)
                RETURN(0);

        curr = cache->fci_lru.prev;

        while (cache->fci_cache_count + cache->fci_threshold >
               cache->fci_cache_size && curr != &cache->fci_lru)
        {
                flde = list_entry(curr, struct fld_cache_entry, fce_lru);
                curr = curr->prev;

                /* keep inflights */
                if (flde->fce_inflight)
                        continue;

                hlist_del_init(&flde->fce_list);
                list_del_init(&flde->fce_lru);
                cache->fci_cache_count--;
                OBD_FREE_PTR(flde);
                num++;
        }

        CDEBUG(D_INFO, "%s: FLD cache - Shrinked by "
               "%d entries\n", cache->fci_name, num);

        RETURN(0);
}

int fld_cache_insert_inflight(struct fld_cache *cache, seqno_t seq)
{
        struct fld_cache_entry *flde, *fldt;
        struct hlist_head *bucket;
        struct hlist_node *scan;
        ENTRY;

        spin_lock(&cache->fci_lock);

        /* Check if cache already has the entry with such a seq. */
        bucket = fld_cache_bucket(cache, seq);
        hlist_for_each_entry(fldt, scan, bucket, fce_list) {
                if (fldt->fce_seq == seq) {
                        spin_unlock(&cache->fci_lock);
                        RETURN(-EEXIST);
                }
        }
        spin_unlock(&cache->fci_lock);

        /* Allocate new entry. */
        OBD_ALLOC_PTR(flde);
        if (!flde)
                RETURN(-ENOMEM);

        /*
         * Check if cache has the entry with such a seq again. It could be added
         * while we were allocating new entry.
         */
        spin_lock(&cache->fci_lock);
        hlist_for_each_entry(fldt, scan, bucket, fce_list) {
                if (fldt->fce_seq == seq) {
                        spin_unlock(&cache->fci_lock);
                        OBD_FREE_PTR(flde);
                        RETURN(0);
                }
        }

        /* Add new entry to cache and lru list. */
        INIT_HLIST_NODE(&flde->fce_list);
        flde->fce_inflight = 1;
        flde->fce_invalid = 1;
        cfs_waitq_init(&flde->fce_waitq);
        flde->fce_seq = seq;

        hlist_add_head(&flde->fce_list, bucket);
        list_add(&flde->fce_lru, &cache->fci_lru);
        cache->fci_cache_count++;

        spin_unlock(&cache->fci_lock);

        RETURN(0);
}
EXPORT_SYMBOL(fld_cache_insert_inflight);

int fld_cache_insert(struct fld_cache *cache,
                     seqno_t seq, mdsno_t mds)
{
        struct fld_cache_entry *flde, *fldt;
        struct hlist_head *bucket;
        struct hlist_node *scan;
        int rc;
        ENTRY;

        spin_lock(&cache->fci_lock);

        /* Check if need to shrink cache. */
        rc = fld_cache_shrink(cache);
        if (rc) {
                spin_unlock(&cache->fci_lock);
                RETURN(rc);
        }

        /* Check if cache already has the entry with such a seq. */
        bucket = fld_cache_bucket(cache, seq);
        hlist_for_each_entry(fldt, scan, bucket, fce_list) {
                if (fldt->fce_seq == seq) {
                        if (fldt->fce_inflight) {
                                /* set mds for inflight entry */
                                fldt->fce_mds = mds;
                                fldt->fce_inflight = 0;
                                fldt->fce_invalid = 0;
                                cfs_waitq_signal(&fldt->fce_waitq);
                                rc = 0;
                        } else
                                rc = -EEXIST;
                        spin_unlock(&cache->fci_lock);
                        RETURN(rc);
                }
        }
        spin_unlock(&cache->fci_lock);

        /* Allocate new entry. */
        OBD_ALLOC_PTR(flde);
        if (!flde)
                RETURN(-ENOMEM);

        /*
         * Check if cache has the entry with such a seq again. It could be added
         * while we were allocating new entry.
         */
        spin_lock(&cache->fci_lock);
        hlist_for_each_entry(fldt, scan, bucket, fce_list) {
                if (fldt->fce_seq == seq) {
                        spin_unlock(&cache->fci_lock);
                        OBD_FREE_PTR(flde);
                        RETURN(0);
                }
        }

        /* Add new entry to cache and lru list. */
        INIT_HLIST_NODE(&flde->fce_list);
        flde->fce_mds = mds;
        flde->fce_seq = seq;
        flde->fce_inflight = 0;
        flde->fce_invalid = 0;

        hlist_add_head(&flde->fce_list, bucket);
        list_add(&flde->fce_lru, &cache->fci_lru);
        cache->fci_cache_count++;

        spin_unlock(&cache->fci_lock);

        RETURN(0);
}
EXPORT_SYMBOL(fld_cache_insert);

void fld_cache_delete(struct fld_cache *cache, seqno_t seq)
{
        struct fld_cache_entry *flde;
        struct hlist_node *scan, *n;
        struct hlist_head *bucket;
        ENTRY;

        bucket = fld_cache_bucket(cache, seq);
	
        spin_lock(&cache->fci_lock);
        hlist_for_each_entry_safe(flde, scan, n, bucket, fce_list) {
                if (flde->fce_seq == seq) {
                        hlist_del_init(&flde->fce_list);
                        list_del_init(&flde->fce_lru);
                        if (flde->fce_inflight) {
                                flde->fce_inflight = 0;
                                flde->fce_invalid = 1;
                                cfs_waitq_signal(&flde->fce_waitq);
                        }
                        cache->fci_cache_count--;
			OBD_FREE_PTR(flde);
                        GOTO(out_unlock, 0);
                }
        }

        EXIT;
out_unlock:
        spin_unlock(&cache->fci_lock);
}
EXPORT_SYMBOL(fld_cache_delete);

static int fld_check_inflight(struct fld_cache_entry *flde)
{
        return (flde->fce_inflight);
}

int fld_cache_lookup(struct fld_cache *cache,
                     seqno_t seq, mdsno_t *mds)
{
        struct fld_cache_entry *flde;
        struct hlist_node *scan, *n;
        struct hlist_head *bucket;
        ENTRY;

        bucket = fld_cache_bucket(cache, seq);

        spin_lock(&cache->fci_lock);
        cache->fci_stat.fst_count++;
        hlist_for_each_entry_safe(flde, scan, n, bucket, fce_list) {
                if (flde->fce_seq == seq) {
                        if (flde->fce_inflight) {
                                /* lookup RPC is inflight need to wait */
                                struct l_wait_info lwi;
                                spin_unlock(&cache->fci_lock);
                                lwi = LWI_TIMEOUT(0, NULL, NULL);
                                l_wait_event(flde->fce_waitq,
                                             !fld_check_inflight(flde), &lwi);
                                LASSERT(!flde->fce_inflight);
                                if (flde->fce_invalid) 
                                        RETURN(-ENOENT);
                                
                                *mds = flde->fce_mds;
                                cache->fci_stat.fst_inflight++;
                        } else {
                                LASSERT(!flde->fce_invalid);
                                *mds = flde->fce_mds;
                                list_del(&flde->fce_lru);
                                list_add(&flde->fce_lru, &cache->fci_lru);
                                cache->fci_stat.fst_cache++;
                                spin_unlock(&cache->fci_lock);
                        }
                        RETURN(0);
                }
        }
        spin_unlock(&cache->fci_lock);
        RETURN(-ENOENT);
}
EXPORT_SYMBOL(fld_cache_lookup);
#else
int fld_cache_insert_inflight(struct fld_cache *cache, seqno_t seq)
{
        return -ENOTSUPP;
}
EXPORT_SYMBOL(fld_cache_insert_inflight);

int fld_cache_insert(struct fld_cache *cache,
                     seqno_t seq, mdsno_t mds)
{
        return -ENOTSUPP;
}
EXPORT_SYMBOL(fld_cache_insert);

void fld_cache_delete(struct fld_cache *cache,
                      seqno_t seq)
{
        return;
}
EXPORT_SYMBOL(fld_cache_delete);

int fld_cache_lookup(struct fld_cache *cache,
                     seqno_t seq, mdsno_t *mds)
{
        return -ENOTSUPP;
}
EXPORT_SYMBOL(fld_cache_lookup);
#endif
