/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Target allocation policy shared by the LOD OST and MDT allocators.
 *
 * lu_tgt_alloc.c is also built in userspace by lustre/tests/lod_rr_test.c,
 * so it must not use kernel interfaces beyond those stubbed there.  The
 * includer provides the definitions of struct lu_qos_rr and lu_tgt_pool.
 */

#ifndef _LU_TGT_ALLOC_H
#define _LU_TGT_ALLOC_H

#include <linux/types.h>

struct lu_qos_rr;
struct lu_qos_rr_stream;
struct lu_tgt_pool;

#define LU_RR_EMPTY (~0U)

/* a target to be placed in the round-robin array by lu_rr_fill() */
struct lu_rr_tgt {
	__u32	lrrt_idx;	/* target index */
	__u32	lrrt_svr;	/* server id, lsq_id */
	__u32	lrrt_fdom;	/* failure domain, 0 if not set */
	__u32	lrrt_pos;	/* position within its server or group */
	__u32	lrrt_count;	/* number of targets in its server or group */
	__u32	lrrt_rank;	/* rank among servers or groups of its count */
	__u32	lrrt_ranks;	/* number of servers or groups of its count */
	__u32	lrrt_seg;	/* index in lrfs_fdom */
};

/* round-robin state of one failure domain, or server without one */
struct lu_rr_fdom {
	__u32		lrf_first;	/* first target in lrfs_tgts */
	__u32		lrf_count;	/* number of targets in the domain */
	atomic_t	lrf_next;	/* next target for other stripes */
	atomic_t	lrf_next0[LQR_STREAMS]; /* for each stream's first */
};

/* failure domains of a round-robin array, if any target has one */
struct lu_rr_fdoms {
	unsigned int	   lrfs_count;	/* number of groups in lrfs_fdom */
	struct lu_rr_fdom *lrfs_fdom;	/* each group of targets */
	__u32		  *lrfs_slot;	/* lrfs_fdom index of each array slot */
	__u32		  *lrfs_tgts;	/* targets in lrfs_fdom order */
};

size_t lu_rr_fdoms_size(unsigned int count);
void lu_rr_fill(struct lu_tgt_pool *rr, struct lu_rr_fdoms *fdoms,
		struct lu_rr_tgt *tgts, unsigned int count);
__u32 lu_rr_fdom_tgt(struct lu_rr_fdoms *fdoms, unsigned int slot,
		   unsigned int stream, bool first);
unsigned int lu_rr_fdom_count(struct lu_rr_fdoms *fdoms, unsigned int slot);
struct lu_qos_rr_stream *lu_rr_start(struct lu_qos_rr *lqr,
				     unsigned int count, unsigned int stripes,
				     __u64 key, bool cont);
unsigned int lu_rr_next(struct lu_qos_rr_stream *lqrs);
unsigned int lu_rr_reserve(struct lu_qos_rr_stream *lqrs,
			   unsigned int stripes);

#endif /* _LU_TGT_ALLOC_H */
