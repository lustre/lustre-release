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
#include <linux/sort.h>
#include <obd_class.h>
#include <lu_tgt_alloc.h>
#endif

#define LU_RR_RESEED_MULT 30
#define LU_RR_RESEED_MIN  2000

/* targets without a failure domain are grouped by server instead */
static int lu_rr_cmp_group(const struct lu_rr_tgt *a,
			   const struct lu_rr_tgt *b)
{
	if (a->lrrt_fdom != b->lrrt_fdom)
		return a->lrrt_fdom < b->lrrt_fdom ? -1 : 1;
	if (!a->lrrt_fdom && a->lrrt_svr != b->lrrt_svr)
		return a->lrrt_svr < b->lrrt_svr ? -1 : 1;
	return 0;
}

/*
 * Compare ideal positions (2 * (pos * ranks + rank) + 1) / (2 * count *
 * ranks), so the targets of servers or groups with the same count are
 * staggered by their rank instead of ending up next to each other.
 */
static int lu_rr_cmp_ideal(const struct lu_rr_tgt *a,
			   const struct lu_rr_tgt *b)
{
	__u64 x = (2 * ((__u64)a->lrrt_pos * a->lrrt_ranks + a->lrrt_rank) +
		   1) * b->lrrt_count * b->lrrt_ranks;
	__u64 y = (2 * ((__u64)b->lrrt_pos * b->lrrt_ranks + b->lrrt_rank) +
		   1) * a->lrrt_count * a->lrrt_ranks;

	if (x != y)
		return x < y ? -1 : 1;
	return 0;
}

/* break ties by server then target index, so the order is repeatable */
static int lu_rr_cmp_tgt(const struct lu_rr_tgt *a,
			 const struct lu_rr_tgt *b)
{
	if (a->lrrt_svr != b->lrrt_svr)
		return a->lrrt_svr < b->lrrt_svr ? -1 : 1;
	if (a->lrrt_idx != b->lrrt_idx)
		return a->lrrt_idx < b->lrrt_idx ? -1 : 1;
	return 0;
}

/* group, server, target index */
static int lu_rr_cmp_svr(const void *pa, const void *pb)
{
	return lu_rr_cmp_group(pa, pb) ?: lu_rr_cmp_tgt(pa, pb);
}

/* group, ideal position of the server's target within its group */
static int lu_rr_cmp_group_ideal(const void *pa, const void *pb)
{
	return lu_rr_cmp_group(pa, pb) ?: lu_rr_cmp_ideal(pa, pb) ?:
	       lu_rr_cmp_tgt(pa, pb);
}

/* server, target index, ignoring failure domains */
static int lu_rr_cmp_svr_only(const void *pa, const void *pb)
{
	return lu_rr_cmp_tgt(pa, pb);
}

/* ideal position of the server's target within the array */
static int lu_rr_cmp_svr_ideal(const void *pa, const void *pb)
{
	return lu_rr_cmp_ideal(pa, pb) ?: lu_rr_cmp_tgt(pa, pb);
}

/* ideal position of the group's target within the array */
static int lu_rr_cmp_array_ideal(const void *pa, const void *pb)
{
	return lu_rr_cmp_ideal(pa, pb) ?: lu_rr_cmp_group(pa, pb) ?:
	       lu_rr_cmp_tgt(pa, pb);
}

/*
 * Number each run of targets for which @same() is true, and rank the runs
 * with the same number of targets in order.
 */
static void lu_rr_number(struct lu_rr_tgt *tgts, unsigned int count,
			 bool (*same)(const struct lu_rr_tgt *a,
				       const struct lu_rr_tgt *b))
{
	unsigned int i, j, k;

	for (i = 0; i < count; i = j) {
		for (j = i + 1; j < count && same(&tgts[i], &tgts[j]); j++)
			;
		for (k = i; k < j; k++) {
			tgts[k].lrrt_pos = k - i;
			tgts[k].lrrt_count = j - i;
		}
	}
	for (i = 0; i < count; i += tgts[i].lrrt_count) {
		unsigned int rank = 0, ranks = 0;

		for (j = 0; j < count; j += tgts[j].lrrt_count) {
			if (tgts[j].lrrt_count != tgts[i].lrrt_count)
				continue;
			if (j < i)
				rank++;
			ranks++;
		}
		for (k = i; k < i + tgts[i].lrrt_count; k++) {
			tgts[k].lrrt_rank = rank;
			tgts[k].lrrt_ranks = ranks;
		}
	}
}

static bool lu_rr_same_group(const struct lu_rr_tgt *a,
			     const struct lu_rr_tgt *b)
{
	return !lu_rr_cmp_group(a, b);
}

static bool lu_rr_same_svr(const struct lu_rr_tgt *a,
			   const struct lu_rr_tgt *b)
{
	return !lu_rr_cmp_group(a, b) && a->lrrt_svr == b->lrrt_svr;
}

static bool lu_rr_same_svr_only(const struct lu_rr_tgt *a,
				const struct lu_rr_tgt *b)
{
	return a->lrrt_svr == b->lrrt_svr;
}

/* @a and @b should not be next to each other in the round-robin array */
static unsigned int lu_rr_conflict(const struct lu_rr_tgt *a,
				   const struct lu_rr_tgt *b, bool by_fdom)
{
	/* the same server is worse than only the same group */
	return (a->lrrt_svr == b->lrrt_svr) +
	       (by_fdom && !lu_rr_cmp_group(a, b));
}

/* conflicts of the target in slot @i with its neighbours */
static unsigned int lu_rr_conflicts(const struct lu_rr_tgt *tgts,
				    unsigned int count, unsigned int i,
				    bool by_fdom)
{
	return lu_rr_conflict(&tgts[i], &tgts[(i + count - 1) % count],
			      by_fdom) +
	       lu_rr_conflict(&tgts[i], &tgts[(i + 1) % count], by_fdom);
}

/*
 * The ideal positions of the targets of different servers can coincide,
 * and the first and last targets of a group are next to each other if
 * the array wraps.  Swap a target that is next to another one of its
 * server or group with one elsewhere, whenever that leaves fewer of
 * them next to each other.
 */
static void lu_rr_separate(struct lu_rr_tgt *tgts, unsigned int count,
			   bool by_fdom)
{
	unsigned int i, j, k, m;
	bool moved = true;
	bool swapped;

	/* repeat while a pass moves anything, each swap leaves fewer */
	while (moved) {
		moved = false;
		for (i = 0; i < count; i++) {
			m = (i + 1) % count;
			if (m == i || !lu_rr_conflict(&tgts[i], &tgts[m],
						      by_fdom))
				continue;
			/* move whichever of the pair has a better slot */
			for (swapped = false, j = 0;
			     j < 2 * count && !swapped; j++) {
				unsigned int before, after;

				k = j < count ? m : i;
				if (j % count == i || j % count == m)
					continue;
				before = lu_rr_conflicts(tgts, count, k,
							 by_fdom) +
					 lu_rr_conflicts(tgts, count,
							 j % count, by_fdom);
				swap(tgts[k], tgts[j % count]);
				after = lu_rr_conflicts(tgts, count, k,
							by_fdom) +
					lu_rr_conflicts(tgts, count,
							j % count, by_fdom);
				if (after < before)
					swapped = true;
				else
					swap(tgts[k], tgts[j % count]);
			}
			moved |= swapped;
		}
	}
}

/**
 * lu_rr_fdoms_size() - Size of the failure domain state for lu_rr_fill()
 * @count: number of targets in the round-robin array
 *
 * Return: bytes to allocate for struct lu_rr_fdoms and its arrays
 */
size_t lu_rr_fdoms_size(unsigned int count)
{
	return sizeof(struct lu_rr_fdoms) +
	       count * (sizeof(struct lu_rr_fdom) + 2 * sizeof(__u32));
}
EXPORT_SYMBOL(lu_rr_fdoms_size);

/* list the targets of each group, in round-robin array order */
static void lu_rr_fdoms_init(struct lu_rr_fdoms *fdoms, struct lu_rr_tgt *tgts,
			   unsigned int count)
{
	unsigned int i;

	fdoms->lrfs_count = 0;
	fdoms->lrfs_fdom = (struct lu_rr_fdom *)(fdoms + 1);
	fdoms->lrfs_slot = (__u32 *)(fdoms->lrfs_fdom + count);
	fdoms->lrfs_tgts = fdoms->lrfs_slot + count;

	for (i = 0; i < count; i++) {
		struct lu_rr_fdom *fdom;

		fdoms->lrfs_tgts[i] = tgts[i].lrrt_idx;
		if (tgts[i].lrrt_pos == 0) {
			fdom = &fdoms->lrfs_fdom[fdoms->lrfs_count++];
			memset(fdom, 0, sizeof(*fdom));
			fdom->lrf_first = i;
			fdom->lrf_count = tgts[i].lrrt_count;
		}
		tgts[i].lrrt_seg = fdoms->lrfs_count - 1;
	}
}

/**
 * lu_rr_fill() - Order targets in the round-robin array
 * @rr: round-robin array, with room for @count targets
 * @fdoms: failure domain state of lu_rr_fdoms_size(@count) bytes, or NULL
 * @tgts: targets to place, which are reordered
 * @count: number of targets in @tgts
 *
 * Space the targets of each failure domain evenly across @rr, and within
 * a failure domain alternate between its servers, so that consecutive
 * targets in @rr are in different failure domains and on different
 * servers.  Layouts that need their stripes in different failure domains
 * then rarely skip a target.  Targets with no failure domain are grouped
 * by server, which spaces each server's targets evenly across @rr.  If a
 * server has targets in several failure domains, only space the targets
 * of each server evenly, so that consecutive targets are still on
 * different servers.
 *
 * Each target gets an ideal position (2 * pos + 1) / (2 * count) among
 * the targets of its server within its group, and the targets of each
 * group are sorted by it.  Each target then gets an ideal position among
 * the targets of its group in that order, and all targets are sorted by
 * that position.  Servers or groups with the same number of targets are
 * staggered by their rank among them, so that their ideal positions do
 * not coincide, and targets still next to one of their own server or
 * group, as when sizes differ, are then swapped apart where possible.
 *
 * If @fdoms is given, also record the targets of each group in @rr order
 * for lu_rr_fdom_tgt().
 *
 * Context: caller holds lq_rw_sem for write.
 */
void lu_rr_fill(struct lu_tgt_pool *rr, struct lu_rr_fdoms *fdoms,
		struct lu_rr_tgt *tgts, unsigned int count)
{
	bool by_fdom = true;
	unsigned int i;

	/* order by failure domain only if each server is in just one */
	sort(tgts, count, sizeof(*tgts), lu_rr_cmp_svr_only, NULL);
	for (i = 1; i < count; i++)
		if (tgts[i].lrrt_svr == tgts[i - 1].lrrt_svr &&
		    tgts[i].lrrt_fdom != tgts[i - 1].lrrt_fdom)
			by_fdom = false;

	sort(tgts, count, sizeof(*tgts), lu_rr_cmp_svr, NULL);
	lu_rr_number(tgts, count, lu_rr_same_svr);
	sort(tgts, count, sizeof(*tgts), lu_rr_cmp_group_ideal, NULL);
	lu_rr_number(tgts, count, lu_rr_same_group);
	if (fdoms)
		lu_rr_fdoms_init(fdoms, tgts, count);
	if (by_fdom) {
		sort(tgts, count, sizeof(*tgts), lu_rr_cmp_array_ideal,
		     NULL);
	} else {
		/* keep the servers apart, as for targets without domains */
		sort(tgts, count, sizeof(*tgts), lu_rr_cmp_svr_only, NULL);
		lu_rr_number(tgts, count, lu_rr_same_svr_only);
		sort(tgts, count, sizeof(*tgts), lu_rr_cmp_svr_ideal, NULL);
	}
	lu_rr_separate(tgts, count, by_fdom);

	for (i = 0; i < count; i++) {
		rr->op_array[i] = tgts[i].lrrt_idx;
		if (fdoms)
			fdoms->lrfs_slot[i] = tgts[i].lrrt_seg;
	}
}
EXPORT_SYMBOL(lu_rr_fill);

/**
 * lu_rr_fdom_tgt() - Get a target in the failure domain of an array slot
 * @fdoms: failure domain state from lu_rr_fill()
 * @slot: slot in the round-robin array
 * @stream: index of the lu_rr_start() state in lqr_streams
 * @first: the target is for the first stripe of a layout
 *
 * Layouts that need their stripes in different failure domains skip the
 * slots of domains they already use, so with domains of different sizes
 * they use the targets in some slots more than others.  Use each slot
 * only to pick a failure domain, or a server for targets without one,
 * and take its targets in turn, separately for the first stripes of
 * each stream so they are balanced as well.
 *
 * Context: caller holds lq_rw_sem for read.
 *
 * Return: target index for @slot
 */
__u32 lu_rr_fdom_tgt(struct lu_rr_fdoms *fdoms, unsigned int slot,
		   unsigned int stream, bool first)
{
	struct lu_rr_fdom *fdom = &fdoms->lrfs_fdom[fdoms->lrfs_slot[slot]];
	unsigned int next;

	next = atomic_inc_return(first ? &fdom->lrf_next0[stream] :
					 &fdom->lrf_next) - 1;

	return fdoms->lrfs_tgts[fdom->lrf_first + next % fdom->lrf_count];
}
EXPORT_SYMBOL(lu_rr_fdom_tgt);

/**
 * lu_rr_fdom_count() - Number of targets in the group of an array slot
 * @fdoms: failure domain state from lu_rr_fill()
 * @slot: slot in the round-robin array
 *
 * A layout can use a group more than once, if it has no failure domain
 * or is overstriped, and the first stripe and later ones are taken in
 * turn separately.  The caller can then try the next targets of the
 * group, up to this many, to find one that the layout doesn't use yet.
 *
 * Context: caller holds lq_rw_sem for read.
 *
 * Return: number of targets in the group
 */
unsigned int lu_rr_fdom_count(struct lu_rr_fdoms *fdoms, unsigned int slot)
{
	return fdoms->lrfs_fdom[fdoms->lrfs_slot[slot]].lrf_count;
}
EXPORT_SYMBOL(lu_rr_fdom_count);

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

/**
 * lu_rr_reserve() - Reserve round-robin indices for a whole layout
 * @lqrs: round-robin state from lu_rr_start()
 * @stripes: number of stripes in the layout
 *
 * A layout that skips slots, to keep its stripes in different failure
 * domains, scans forward from the returned index without advancing the
 * shared start index for each slot, so the slots it scans past its
 * reservation are the first ones the next layout uses.  The skipped
 * slots don't use up a target of their domain in lu_rr_fdom_tgt().
 *
 * Context: caller holds lq_rw_sem for read.
 *
 * Return: unbounded index into the round-robin array, the one before the
 * first slot to use, which the caller reduces modulo the array size
 */
unsigned int lu_rr_reserve(struct lu_qos_rr_stream *lqrs,
			   unsigned int stripes)
{
	return atomic_add_return(stripes, &lqrs->lqrs_start_idx) - stripes +
	       lqrs->lqrs_offset_idx;
}
EXPORT_SYMBOL(lu_rr_reserve);
