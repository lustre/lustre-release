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
#include <linux/gcd.h>
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
 * @key: which layouts share a start index, e.g. the stripe count and
 *	 component extent from lod_rr_key()
 * @cont: this layout continues the previous one with the same @key
 *
 * Layouts with each stripe count, and each component of PFL layouts,
 * have their own start index (see lod_rr_key()), so that a repeating
 * sequence of stripe counts, like the components of a PFL layout,
 * doesn't put the start of each component on the same few targets.
 * The least recently used one is given to a new key, and the start
 * continues from it, so using more than LQR_STREAMS of them in turn
 * is no worse than sharing a single start index.
 *
 * Reseed the start index at random every few thousand allocations.
 * Otherwise, once the start index has passed the end of the array, wrap
 * it.  Advancing by a stride of @stripes per layout, and the stripes of
 * its mirrors or EC parity that continue from it, only starts layouts on
 * targets gcd(stride, @count) apart, and wraps after an uneven number of
 * layouts, so shifting the start by one target on every wrap gave some
 * targets up to twice as many first stripes as others (LU-8933).  Shift
 * it once every @count / gcd(stride, @count) layouts instead, after all
 * of those targets have been used as a start, so that @count consecutive
 * layouts with the same stripe count start once on each target.  Targets
 * that are skipped, and concurrent allocations, change the stride between
 * layouts, but the shift still moves the start.
 *
 * Context: caller holds lq_rw_sem for read, takes lqr_alloc.
 *
 * Return: round-robin state for lu_rr_next()
 */
struct lu_qos_rr_stream *lu_rr_start(struct lu_qos_rr *lqr,
				     unsigned int count, unsigned int stripes,
				     __u64 key, bool cont)
{
	struct lu_qos_rr_stream *lqrs = &lqr->lqr_streams[0];
	unsigned int start, stride;
	int i;

	spin_lock(&lqr->lqr_alloc);
	for (i = 0; i < LQR_STREAMS; i++) {
		struct lu_qos_rr_stream *tmp = &lqr->lqr_streams[i];

		if (tmp->lqrs_used && tmp->lqrs_key == key) {
			lqrs = tmp;
			break;
		}
		/* the least recently used, allowing lqr_clock to wrap */
		if (!tmp->lqrs_used ||
		    (lqrs->lqrs_used &&
		     (__s32)(tmp->lqrs_used - lqrs->lqrs_used) < 0))
			lqrs = tmp;
	}
	/* a new stream continues from the start of the one it replaces */
	if (i == LQR_STREAMS) {
		if (!lqrs->lqrs_used)
			atomic_set(&lqrs->lqrs_start_idx,
				   get_random_u32_below(max(count, 1U)));
		lqrs->lqrs_key = key;
		lqrs->lqrs_stride = 0;
	}
	if (!++lqr->lqr_clock)
		lqr->lqr_clock = 1;
	lqrs->lqrs_used = lqr->lqr_clock;

	/* the mirrors of a file continue in order, to use different OSSs */
	if (cont) {
		lqrs->lqrs_stride += stripes;
		goto out;
	}
	/* the start advanced by the stripes of a layout and its mirrors */
	stride = lqrs->lqrs_stride ?: stripes;
	lqrs->lqrs_stride = stripes;

	if (--lqr->lqr_start_count <= 0) {
		atomic_set(&lqrs->lqrs_start_idx,
			   get_random_u32_below(max(count, 1U)));
		lqr->lqr_start_count =
			(LU_RR_RESEED_MIN / max(count, 1U) +
			 LU_RR_RESEED_MULT) * max(count, 1U);
	} else {
		start = atomic_read(&lqrs->lqrs_start_idx);
		/* overstriped layouts may have wrapped many times */
		if (count && start >= count)
			atomic_sub(start - start % count,
				   &lqrs->lqrs_start_idx);
		if (count &&
		    ++lqrs->lqrs_layouts >= count / gcd(stride, count)) {
			lqrs->lqrs_layouts = 0;
			++lqrs->lqrs_offset_idx;
		}
	}
out:
	spin_unlock(&lqr->lqr_alloc);

	return lqrs;
}
EXPORT_SYMBOL(lu_rr_start);

/**
 * lu_rr_next() - Get the next round-robin index
 * @lqrs: round-robin state from lu_rr_start()
 *
 * Context: caller holds lq_rw_sem for read.
 *
 * Return: unbounded index into the round-robin array, which the caller
 * reduces modulo the array size
 */
unsigned int lu_rr_next(struct lu_qos_rr_stream *lqrs)
{
	return atomic_inc_return(&lqrs->lqrs_start_idx) +
	       lqrs->lqrs_offset_idx;
}
EXPORT_SYMBOL(lu_rr_next);
