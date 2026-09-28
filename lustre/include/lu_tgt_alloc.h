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

void lu_rr_place_tgt(struct lu_tgt_pool *rr, __u32 tgt_idx,
		     unsigned int svr_pos, unsigned int svr_count);
struct lu_qos_rr_stream *lu_rr_start(struct lu_qos_rr *lqr,
				     unsigned int count, unsigned int stripes,
				     __u64 key, bool cont);
unsigned int lu_rr_next(struct lu_qos_rr_stream *lqrs);

#endif /* _LU_TGT_ALLOC_H */
