// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Target allocation policy shared by the LOD OST and MDT allocators.
 * This is also built in userspace by lustre/tests/lod_rr_test.c so the
 * allocation can be checked for many target and stripe counts without
 * a filesystem (see lu_tgt_alloc.h).
 */

#define DEBUG_SUBSYSTEM S_CLASS

#ifdef __KERNEL__
#include <linux/random.h>
#include <obd_class.h>
#include <lu_tgt_alloc.h>
#endif

#define LU_RR_RESEED_MULT 30
#define LU_RR_RESEED_MIN  2000

/**
 * lu_rr_place_tgt() - Place one target in the round-robin array
 * @rr: round-robin array, empty slots set to LU_RR_EMPTY
 * @tgt_idx: target index to place
 * @svr_pos: position of @tgt_idx among its server's targets
 * @svr_count: number of targets on @tgt_idx's server
 *
 * Space the targets of each server evenly across @rr, so that walking
 * the array in order alternates between servers.  If the preferred slot
 * is taken by another server's target, use the next free one.
 *
 * Context: caller holds lq_rw_sem for write, and @rr has a free slot.
 */
void lu_rr_place_tgt(struct lu_tgt_pool *rr, __u32 tgt_idx,
		     unsigned int svr_pos, unsigned int svr_count)
{
	unsigned int next = svr_pos * rr->op_count / svr_count;

	while (rr->op_array[next] != LU_RR_EMPTY)
		next = (next + 1) % rr->op_count;

	rr->op_array[next] = tgt_idx;
}
EXPORT_SYMBOL(lu_rr_place_tgt);

/**
 * lu_rr_start() - Set up the round-robin start index for a new layout
 * @lqr: round-robin state
 * @count: number of targets in the round-robin array
 * @stripes: number of stripes to be allocated from the array
 *
 * Reseed the start index at random every few thousand allocations.
 * Otherwise, once the start index has passed the end of the array, wrap
 * it and precess the start by one target if the target/stripe count
 * difference isn't already doing this.
 *
 * Context: caller holds lq_rw_sem for read, takes lqr_alloc.
 */
void lu_rr_start(struct lu_qos_rr *lqr, unsigned int count,
		 unsigned int stripes)
{
	spin_lock(&lqr->lqr_alloc);
	if (--lqr->lqr_start_count <= 0) {
		atomic_set(&lqr->lqr_start_idx, get_random_u32_below(count));
		lqr->lqr_start_count =
			(LU_RR_RESEED_MIN / max(count, 1U) +
			 LU_RR_RESEED_MULT) * max(count, 1U);
	} else if ((unsigned int)atomic_read(&lqr->lqr_start_idx) >= count) {
		atomic_sub(count, &lqr->lqr_start_idx);
		if (stripes > 1 && (count % stripes) != 1)
			++lqr->lqr_offset_idx;
	}
	spin_unlock(&lqr->lqr_alloc);
}
EXPORT_SYMBOL(lu_rr_start);

/**
 * lu_rr_next() - Get the next round-robin index
 * @lqr: round-robin state
 *
 * Context: caller holds lq_rw_sem for read.
 *
 * Return: unbounded index into the round-robin array, which the caller
 * reduces modulo the array size
 */
unsigned int lu_rr_next(struct lu_qos_rr *lqr)
{
	return atomic_inc_return(&lqr->lqr_start_idx) + lqr->lqr_offset_idx;
}
EXPORT_SYMBOL(lu_rr_next);
