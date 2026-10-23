// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * FLD (Fids Location Database)
 *
 * Author: Pravin Shelar <pravin.shelar@sun.com>
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_FLD

#include <linux/module.h>
#include <linux/math64.h>
#include <linux/interval_tree_generic.h>

#include <obd_support.h>
#include <lustre_fld.h>

#include "fld_internal.h"

/*
 * The cache maps non-overlapping sequence ranges [lsr_start, lsr_end) to a
 * target, and fld_cache_lookup() must find the range containing a given
 * sequence.  Index the entries with an interval tree so lookup, insert and
 * delete are O(log n) rather than a linear scan.  Intervals are inclusive,
 * so the last sequence of a range is lsr_end - 1.
 *
 * The ranges are assigned when targets are formatted and essentially never
 * change afterwards (a target is given a new range only after creating
 * billions of objects), there are at most a few hundred of them, and they
 * never overlap.  So the cache never grows large enough to need eviction,
 * and there is no range merge or split to perform.
 */
#define FLD_RANGE_START(e)	((e)->fce_range.lsr_start)
#define FLD_RANGE_LAST(e)	((e)->fce_range.lsr_end - 1)

INTERVAL_TREE_DEFINE(struct fld_cache_entry, fce_rb, u64, fce_subtree_last,
		     FLD_RANGE_START, FLD_RANGE_LAST, static __maybe_unused,
		     fldt)

/**
 * fld_cache_init() - create fld cache.
 * @name: name of the cache
 *
 * Returns pointer to struct fld_cache on success or %negative on failure
 */
struct fld_cache *fld_cache_init(const char *name)
{
	struct fld_cache *cache;

	ENTRY;

	LASSERT(name != NULL);

	OBD_ALLOC_PTR(cache);
	if (cache == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	cache->fci_root = RB_ROOT_CACHED;
	rwlock_init(&cache->fci_lock);

	strscpy(cache->fci_name, name, sizeof(cache->fci_name));

	/* Init fld cache info. */
	memset(&cache->fci_stat, 0, sizeof(cache->fci_stat));

	CDEBUG(D_INFO, "%s: FLD cache\n", cache->fci_name);

	RETURN(cache);
}

/**
 * fld_cache_fini() - destroy fld cache.
 * @cache: cache to destroy
 */
void fld_cache_fini(struct fld_cache *cache)
{
	LASSERT(cache != NULL);
	fld_cache_flush(cache);

	CDEBUG(D_INFO, "FLD cache statistics (%s):\n", cache->fci_name);
	CDEBUG(D_INFO, "  Cache reqs: %llu\n", cache->fci_stat.fst_cache);
	CDEBUG(D_INFO, "  Total reqs: %llu\n", cache->fci_stat.fst_count);

	OBD_FREE_PTR(cache);
}

/*
 * Kill all fld cache entries.
 */
void fld_cache_flush(struct fld_cache *cache)
{
	struct fld_cache_entry *flde;
	struct fld_cache_entry *next;

	ENTRY;

	write_lock(&cache->fci_lock);
	rbtree_postorder_for_each_entry_safe(flde, next,
					     &cache->fci_root.rb_root, fce_rb)
		OBD_FREE_PTR(flde);
	cache->fci_root = RB_ROOT_CACHED;
	write_unlock(&cache->fci_lock);

	EXIT;
}

struct fld_cache_entry
*fld_cache_entry_create(const struct lu_seq_range *range)
{
	struct fld_cache_entry *f_new;

	/*
	 * The interval tree indexes an entry by [lsr_start, lsr_end - 1], so an
	 * empty or inverted range would wrap and match every sequence.  Such a
	 * range should never occur, but it can arrive from the on-disk FLDB or
	 * an FLD_QUERY reply, so reject it rather than assert.
	 */
	if (range->lsr_start >= range->lsr_end) {
		CERROR("cannot cache empty FLD range "DRANGE"\n", PRANGE(range));
		RETURN(ERR_PTR(-EINVAL));
	}

	OBD_ALLOC_PTR(f_new);
	if (!f_new)
		RETURN(ERR_PTR(-ENOMEM));

	f_new->fce_range = *range;
	RETURN(f_new);
}

/**
 * fld_cache_insert_nolock() - Insert FLD entry in FLD cache.
 * @cache: fld_cache struct to which the new entry will be inserted
 * @f_new: fld_cache_entry entry to be inserted
 *
 * FLD ranges are fixed and non-overlapping, so if an entry already covers
 * this range it was cached by an earlier lookup; drop the duplicate rather
 * than add an overlapping node.  @f_new is consumed either way.
 *
 * Returns 0 always
 */
int fld_cache_insert_nolock(struct fld_cache *cache,
			    struct fld_cache_entry *f_new)
{
	struct fld_cache_entry *flde;

	ENTRY;

	flde = fldt_iter_first(&cache->fci_root, FLD_RANGE_START(f_new),
			       FLD_RANGE_LAST(f_new));
	if (flde != NULL) {
		CDEBUG(D_INFO, "range "DRANGE" already cached as "DRANGE"\n",
		       PRANGE(&f_new->fce_range), PRANGE(&flde->fce_range));
		OBD_FREE_PTR(f_new);
		RETURN(0);
	}

	CDEBUG(D_INFO, "insert range "DRANGE"\n", PRANGE(&f_new->fce_range));
	fldt_insert(f_new, &cache->fci_root);

	RETURN(0);
}

int fld_cache_insert(struct fld_cache *cache,
		     const struct lu_seq_range *range)
{
	struct fld_cache_entry	*flde;
	int rc;

	flde = fld_cache_entry_create(range);
	if (IS_ERR(flde))
		RETURN(PTR_ERR(flde));

	write_lock(&cache->fci_lock);
	rc = fld_cache_insert_nolock(cache, flde);
	write_unlock(&cache->fci_lock);
	if (rc)
		OBD_FREE_PTR(flde);

	RETURN(rc);
}

void fld_cache_delete_nolock(struct fld_cache *cache,
			     const struct lu_seq_range *range)
{
	struct fld_cache_entry *flde;

	if (range->lsr_start >= range->lsr_end)
		return;

	flde = fldt_iter_first(&cache->fci_root, range->lsr_start,
			       range->lsr_end - 1);
	if (flde != NULL) {
		fldt_remove(flde, &cache->fci_root);
		OBD_FREE_PTR(flde);
	}
}

/**
 * fld_cache_lookup() - lookup @seq sequence for range in fld cache.
 * @cache: fld_cache struct that lookup(search) is done
 * @seq: FID which is being searched
 * @range: lookup/search if success will fill @range [out]
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int fld_cache_lookup(struct fld_cache *cache,
		     const u64 seq, struct lu_seq_range *range)
{
	struct fld_cache_entry *flde;

	ENTRY;

	read_lock(&cache->fci_lock);
	cache->fci_stat.fst_count++;
	/* ranges do not overlap, so at most one entry contains @seq */
	flde = fldt_iter_first(&cache->fci_root, seq, seq);
	if (flde != NULL) {
		*range = flde->fce_range;
		cache->fci_stat.fst_cache++;
		read_unlock(&cache->fci_lock);
		RETURN(0);
	}
	read_unlock(&cache->fci_lock);
	RETURN(-ENOENT);
}
