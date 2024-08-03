/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Range lock is used to allow multiple threads writing a single shared
 * file given each thread is writing to a non-overlapping portion of the
 * file.
 *
 * Refer to the possible upstream kernel version of range lock by
 * Jan Kara <jack@suse.cz>: https://lkml.org/lkml/2013/1/31/480
 *
 * This file could later replaced by the upstream kernel version.
 *
 * Author: Prakash Surya <surya1@llnl.gov>
 * Author: Bobi Jam <bobijam.xu@intel.com>
 */

#ifndef _RANGE_LOCK_H
#define _RANGE_LOCK_H

#include <libcfs/libcfs.h>

#define RL_FMT "[%llu, %llu]"
#define RL_PARA(range)					\
	(unsigned long long)(range)->rl_start,	\
	(unsigned long long)(range)->rl_end

struct range_lock {
	__u64				rl_start,
					rl_end,
					rl_subtree_last;
	struct rb_node			rl_rb;
	/**
	 * Process to enqueue this lock.
	 */
	struct task_struct		*rl_task;
	/**
	 * Number of ranges which are blocking acquisition of the lock
	 */
	unsigned int			rl_blocking_ranges;
	/**
	 * Sequence number of range lock. This number is used to get to know
	 * the order the locks are queued.  One lock can only block another
	 * if it has a higher rl_sequence.
	 */
	__u64				rl_sequence;
};

struct range_lock_tree {
	struct interval_tree_root	rlt_root;
	spinlock_t			rlt_lock;
	__u64				rlt_sequence;
};

void range_lock_tree_init(struct range_lock_tree *tree);
void range_lock_init(struct range_lock *lock, __u64 start, __u64 end);
int  range_lock(struct range_lock_tree *tree, struct range_lock *lock);
void range_unlock(struct range_lock_tree *tree, struct range_lock *lock);
#endif
