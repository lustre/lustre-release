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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Range lock is used to allow multiple threads writing a single shared
 * file given each thread is writing to a non-overlapping portion of the
 * file.
 *
 * Refer to the possible upstream kernel version of range lock by
 * Jan Kara <jack@suse.cz>: https://lkml.org/lkml/2013/1/31/480
 *
 * This file could later replaced by the upstream kernel version.
 */
/*
 * Author: Prakash Surya <surya1@llnl.gov>
 * Author: Bobi Jam <bobijam.xu@intel.com>
 */
#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/signal.h>
#endif
#include <linux/interval_tree_generic.h>
#include <uapi/linux/lustre/lustre_user.h>
#include <range_lock.h>

#define START(node)	((node)->rl_start)
#define LAST(node)	((node)->rl_end)

INTERVAL_TREE_DEFINE(struct range_lock, rl_rb, __u64, rl_subtree_last,
		     START, LAST, static, range_lock)

/**
 * Initialize a range lock tree
 *
 * \param tree [in]	an empty range lock tree
 *
 * Pre:  Caller should have allocated the range lock tree.
 * Post: The range lock tree is ready to function.
 */
void range_lock_tree_init(struct range_lock_tree *tree)
{
	tree->rlt_root = INTERVAL_TREE_ROOT;
	tree->rlt_sequence = 0;
	spin_lock_init(&tree->rlt_lock);
}
EXPORT_SYMBOL(range_lock_tree_init);

/**
 * Intialize a range lock node
 *
 * \param lock  [in]	an empty range lock node
 * \param start [in]	start of the covering region
 * \param end   [in]	end of the covering region
 *
 * Pre:  Caller should have allocated the range lock node.
 * Post: The range lock node is meant to cover [start, end] region
 */
void range_lock_init(struct range_lock *lock, __u64 start, __u64 end)
{
	start >>= PAGE_SHIFT;
	if (end != LUSTRE_EOF)
		end >>= PAGE_SHIFT;
	lock->rl_start = start;
	lock->rl_end = end;

	lock->rl_task = NULL;
	lock->rl_blocking_ranges = 0;
	lock->rl_sequence = 0;
}
EXPORT_SYMBOL(range_lock_init);

/**
 * Unlock a range lock, wake up locks blocked by this lock.
 *
 * \param tree [in]	range lock tree
 * \param lock [in]	range lock to be deleted
 *
 * If this lock has been granted, relase it; if not, just delete it from
 * the tree or the same region lock list. Wake up those locks only blocked
 * by this lock.
 */
void range_unlock(struct range_lock_tree *tree, struct range_lock *lock)
{
	struct range_lock *overlap;
	ENTRY;

	spin_lock(&tree->rlt_lock);

	range_lock_remove(lock, &tree->rlt_root);

	for (overlap = range_lock_iter_first(&tree->rlt_root,
					     lock->rl_start,
					     lock->rl_end);
	     overlap;
	     overlap = range_lock_iter_next(overlap,
					    lock->rl_start,
					    lock->rl_end))
		if (overlap->rl_sequence > lock->rl_sequence) {
			--overlap->rl_blocking_ranges;
			if (overlap->rl_blocking_ranges == 0)
				wake_up_process(overlap->rl_task);
		}

	spin_unlock(&tree->rlt_lock);

	EXIT;
}
EXPORT_SYMBOL(range_unlock);

/**
 * Lock a region
 *
 * \param tree [in]	range lock tree
 * \param lock [in]	range lock node containing the region span
 *
 * \retval 0	get the range lock
 * \retval <0	error code while not getting the range lock
 *
 * If there exists overlapping range lock, the new lock will wait and
 * retry, if later it find that it is not the chosen one to wake up,
 * it wait again.
 */
int range_lock(struct range_lock_tree *tree, struct range_lock *lock)
{
	struct range_lock *overlap;
	int rc = 0;
	ENTRY;

	spin_lock(&tree->rlt_lock);
	/*
	 * We need to check for all conflicting intervals
	 * already in the tree.
	 */
	for (overlap = range_lock_iter_first(&tree->rlt_root,
					     lock->rl_start,
					     lock->rl_end);
	     overlap;
	     overlap = range_lock_iter_next(overlap,
					    lock->rl_start,
					    lock->rl_end))
		lock->rl_blocking_ranges += 1;

	range_lock_insert(lock, &tree->rlt_root);
	lock->rl_sequence = ++tree->rlt_sequence;

	while (lock->rl_blocking_ranges > 0) {
		lock->rl_task = current;
		__set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock(&tree->rlt_lock);
		schedule();

		if (signal_pending(current)) {
			range_unlock(tree, lock);
			GOTO(out, rc = -ERESTARTSYS);
		}
		spin_lock(&tree->rlt_lock);
	}
	spin_unlock(&tree->rlt_lock);
out:
	RETURN(rc);
}
EXPORT_SYMBOL(range_lock);
