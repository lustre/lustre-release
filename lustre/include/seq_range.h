/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 *
 * Copyright 2015 Cray Inc, all rights reserved.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Define lu_seq_range  associated functions
 *
 * Author: Ben Evans.
 */

#ifndef _SEQ_RANGE_H_
#define _SEQ_RANGE_H_

#include <uapi/linux/lustre/lustre_idl.h>

/**
 * computes the sequence range type \a range
 */

static inline unsigned fld_range_type(const struct lu_seq_range *range)
{
	return range->lsr_flags & LU_SEQ_RANGE_MASK;
}

/**
 *  Is this sequence range an OST? \a range
 */

static inline bool fld_range_is_ost(const struct lu_seq_range *range)
{
	return fld_range_type(range) == LU_SEQ_RANGE_OST;
}

/**
 *  Is this sequence range an MDT? \a range
 */

static inline bool fld_range_is_mdt(const struct lu_seq_range *range)
{
	return fld_range_type(range) == LU_SEQ_RANGE_MDT;
}

/**
 * ANY range is only used when the fld client sends a fld query request,
 * but it does not know whether the seq is an MDT or OST, so it will send the
 * request with ANY type, which means any seq type from the lookup can be
 * expected. /a range
 */
static inline unsigned fld_range_is_any(const struct lu_seq_range *range)
{
	return fld_range_type(range) == LU_SEQ_RANGE_ANY;
}

/**
 * Apply flags to range \a range \a flags
 */

static inline void fld_range_set_type(struct lu_seq_range *range,
				      unsigned flags)
{
	range->lsr_flags |= flags;
}

/**
 * Add MDT to range type \a range
 */

static inline void fld_range_set_mdt(struct lu_seq_range *range)
{
	fld_range_set_type(range, LU_SEQ_RANGE_MDT);
}

/**
 * Add OST to range type \a range
 */

static inline void fld_range_set_ost(struct lu_seq_range *range)
{
	fld_range_set_type(range, LU_SEQ_RANGE_OST);
}

/**
 * Add ANY to range type \a range
 */

static inline void fld_range_set_any(struct lu_seq_range *range)
{
	fld_range_set_type(range, LU_SEQ_RANGE_ANY);
}

/**
 * computes width of given sequence range \a range
 */

static inline __u64 lu_seq_range_space(const struct lu_seq_range *range)
{
	return range->lsr_end - range->lsr_start;
}

/**
 * initialize range to zero \a range
 */

static inline void lu_seq_range_init(struct lu_seq_range *range)
{
	memset(range, 0, sizeof(*range));
}

/**
 * check if given seq id \a s is within given range \a range
 */

static inline bool lu_seq_range_within(const struct lu_seq_range *range,
				       __u64 seq)
{
	return seq >= range->lsr_start && seq < range->lsr_end;
}

/**
 * Is the range sane?  Is the end after the beginning? \a range
 */

static inline bool lu_seq_range_is_sane(const struct lu_seq_range *range)
{
	return range->lsr_end >= range->lsr_start;
}

/**
 * Is the range 0? \a range
 */

static inline bool lu_seq_range_is_zero(const struct lu_seq_range *range)
{
	return range->lsr_start == 0 && range->lsr_end == 0;
}

/**
 * Is the range out of space? \a range
 */

static inline bool lu_seq_range_is_exhausted(const struct lu_seq_range *range)
{
	return lu_seq_range_space(range) == 0;
}

/**
 * return 0 if two ranges have the same location, nonzero if they are
 * different \a r1 \a r2
 */

static inline int lu_seq_range_compare_loc(const struct lu_seq_range *r1,
					   const struct lu_seq_range *r2)
{
	return r1->lsr_index != r2->lsr_index ||
		r1->lsr_flags != r2->lsr_flags;
}

/**
 * printf string and argument list for sequence range
 */
#define DRANGE "[%#16.16llx-%#16.16llx]:%x:%s"

#define PRANGE(range)				\
	(unsigned long long)(range)->lsr_start,	\
	(unsigned long long)(range)->lsr_end,	\
	(range)->lsr_index,			\
	fld_range_is_mdt(range) ? "mdt" : "ost"

#endif
