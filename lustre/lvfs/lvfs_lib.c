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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lvfs/lvfs_lib.c
 *
 * Lustre filesystem abstraction routines
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */
#ifdef __KERNEL__
#include <linux/module.h>
#else
#include <liblustre.h>
#endif
#include <lustre_lib.h>
#include <lprocfs_status.h>

unsigned int obd_alloc_fail_rate = 0;

int obd_alloc_fail(const void *ptr, const char *name, const char *type,
                   size_t size, const char *file, int line)
{
        if (ptr == NULL ||
            (cfs_rand() & OBD_ALLOC_FAIL_MASK) < obd_alloc_fail_rate) {
                CERROR("%s%salloc of %s ("LPU64" bytes) failed at %s:%d\n",
                       ptr ? "force " :"", type, name, (__u64)size, file,
                       line);
                CERROR(LPU64" total bytes and "LPU64" total pages "
                       "("LPU64" bytes) allocated by Lustre, "
                       "%d total bytes by LNET\n",
                       obd_memory_sum(),
                       obd_pages_sum() << CFS_PAGE_SHIFT,
                       obd_pages_sum(),
                       cfs_atomic_read(&libcfs_kmemory));
                return 1;
        }
        return 0;
}
EXPORT_SYMBOL(obd_alloc_fail);

#ifdef LPROCFS
void lprocfs_counter_add(struct lprocfs_stats *stats, int idx,
                                       long amount)
{
	struct lprocfs_counter *percpu_cntr;
	int			smp_id;
	unsigned long		flags = 0;

        if (stats == NULL)
                return;

	/* With per-client stats, statistics are allocated only for
	 * single CPU area, so the smp_id should be 0 always. */
	smp_id = lprocfs_stats_lock(stats, LPROCFS_GET_SMP_ID, &flags);
	if (smp_id < 0)
		return;

        percpu_cntr = &(stats->ls_percpu[smp_id]->lp_cntr[idx]);
        if (!(stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU))
                cfs_atomic_inc(&percpu_cntr->lc_cntl.la_entry);
        percpu_cntr->lc_count++;

        if (percpu_cntr->lc_config & LPROCFS_CNTR_AVGMINMAX) {
		/*
		 * lprocfs_counter_add() can be called in interrupt context,
		 * as memory allocation could trigger memory shrinker call
		 * ldlm_pool_shrink(), which calls lprocfs_counter_add().
		 * LU-1727.
		 */
		if (cfs_in_interrupt())
			percpu_cntr->lc_sum_irq += amount;
		else
			percpu_cntr->lc_sum += amount;
                if (percpu_cntr->lc_config & LPROCFS_CNTR_STDDEV)
                        percpu_cntr->lc_sumsquare += (__s64)amount * amount;
                if (amount < percpu_cntr->lc_min)
                        percpu_cntr->lc_min = amount;
                if (amount > percpu_cntr->lc_max)
                        percpu_cntr->lc_max = amount;
        }
        if (!(stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU))
                cfs_atomic_inc(&percpu_cntr->lc_cntl.la_exit);
        lprocfs_stats_unlock(stats, LPROCFS_GET_SMP_ID, &flags);
}
EXPORT_SYMBOL(lprocfs_counter_add);

void lprocfs_counter_sub(struct lprocfs_stats *stats, int idx, long amount)
{
	struct lprocfs_counter *percpu_cntr;
	int			smp_id;
	unsigned long		flags = 0;

        if (stats == NULL)
                return;

	/* With per-client stats, statistics are allocated only for
	 * single CPU area, so the smp_id should be 0 always. */
	smp_id = lprocfs_stats_lock(stats, LPROCFS_GET_SMP_ID, &flags);
	if (smp_id < 0)
		return;

        percpu_cntr = &(stats->ls_percpu[smp_id]->lp_cntr[idx]);
        if (!(stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU))
                cfs_atomic_inc(&percpu_cntr->lc_cntl.la_entry);
        if (percpu_cntr->lc_config & LPROCFS_CNTR_AVGMINMAX) {
		/*
		 * Sometimes we use RCU callbacks to free memory which calls
		 * lprocfs_counter_sub(), and RCU callbacks may execute in
		 * softirq context - right now that's the only case we're in
		 * softirq context here, use separate counter for that.
		 * bz20650.
		 */
                if (cfs_in_interrupt())
                        percpu_cntr->lc_sum_irq -= amount;
                else
                        percpu_cntr->lc_sum -= amount;
        }
        if (!(stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU))
                cfs_atomic_inc(&percpu_cntr->lc_cntl.la_exit);
        lprocfs_stats_unlock(stats, LPROCFS_GET_SMP_ID, &flags);
}
EXPORT_SYMBOL(lprocfs_counter_sub);

int lprocfs_stats_alloc_one(struct lprocfs_stats *stats, unsigned int idx)
{
	unsigned int	percpusize;
	int		rc	= -ENOMEM;
	unsigned long	flags	= 0;

	/* the 1st percpu entry was statically allocated in
	 * lprocfs_alloc_stats() */
	LASSERT(idx != 0 && stats->ls_percpu[0] != NULL);
	LASSERT(stats->ls_percpu[idx] == NULL);
	LASSERT((stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU) == 0);

	percpusize = CFS_L1_CACHE_ALIGN(offsetof(struct lprocfs_percpu,
						 lp_cntr[stats->ls_num]));
	OBD_ALLOC_GFP(stats->ls_percpu[idx], percpusize, CFS_ALLOC_ATOMIC);
	if (stats->ls_percpu[idx] != NULL) {
		rc = 0;
		if (unlikely(stats->ls_biggest_alloc_num <= idx)) {
			if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE)
				cfs_spin_lock_irqsave(&stats->ls_lock, flags);
			else
				cfs_spin_lock(&stats->ls_lock);
			if (stats->ls_biggest_alloc_num <= idx)
				stats->ls_biggest_alloc_num = idx + 1;
			if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE) {
				cfs_spin_unlock_irqrestore(&stats->ls_lock,
							   flags);
			} else {
				cfs_spin_unlock(&stats->ls_lock);
			}
		}

		/* initialize the ls_percpu[idx] by copying the 0th template
		 * entry */
		memcpy(stats->ls_percpu[idx], stats->ls_percpu[0],
		       percpusize);
	}

	return rc;
}
EXPORT_SYMBOL(lprocfs_stats_alloc_one);
#endif  /* LPROCFS */

EXPORT_SYMBOL(obd_alloc_fail_rate);
