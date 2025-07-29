// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * This file handles creation, lookup, and removal of pools themselves, as
 * well as adding and removing targets to pools.
 *
 * Author: Jacques-Charles LAFOUCRIERE <jc.lafoucriere@cea.fr>
 * Author: Alex Lyashkov <Alexey.Lyashkov@Sun.COM>
 * Author: Nathaniel Rutman <Nathan.Rutman@Sun.COM>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd_target.h>
#include <obd_support.h>
#include <lu_object.h>

#define POOL_INIT_COUNT 2
/**
 * lu_tgt_pool_init() - Initialize the pool data structures at startup.
 * @op: pool structure
 * @count: initial size of the target op_array[] array
 *
 * Allocate and initialize the pool data structures with the specified
 * array size.  If pool count is not specified (\a count == 0), then
 * POOL_INIT_COUNT will be used.  Allocating a non-zero initial array
 * size avoids the need to reallocate as new pools are added.
 *
 * Return:
 * * %0 indicates successful pool initialization
 * * %negative error number on failure
 */
int lu_tgt_pool_init(struct lu_tgt_pool *op, unsigned int count)
{
	ENTRY;

	if (count == 0)
		count = POOL_INIT_COUNT;
	op->op_array = NULL;
	op->op_count = 0;
	init_rwsem(&op->op_rw_sem);
	op->op_size = count * sizeof(op->op_array[0]);
	OBD_ALLOC(op->op_array, op->op_size);
	if (op->op_array == NULL) {
		op->op_size = 0;
		RETURN(-ENOMEM);
	}
	EXIT;
	return 0;
}
EXPORT_SYMBOL(lu_tgt_pool_init);

/**
 * lu_tgt_pool_extend() - Inc op_array size to hold more targets in this pool
 * @op: pool structure
 * @min_count: minimum number of entries to handle
 *
 * The size is increased to at least @min_count, but may be larger
 * for an existing pool since ->op_array[] is growing exponentially.
 * Caller must hold write op_rwlock.
 *
 * Return:
 * * %0 on success
 * * %negative error number on failure.
 */
int lu_tgt_pool_extend(struct lu_tgt_pool *op, unsigned int min_count)
{
	__u32 *new;
	__u32 new_size;

	LASSERT(min_count != 0);

	if (op->op_count * sizeof(op->op_array[0]) < op->op_size)
		return 0;

	new_size = max_t(__u32, min_count * sizeof(op->op_array[0]),
			 2 * op->op_size);
	OBD_ALLOC(new, new_size);
	if (new == NULL)
		return -ENOMEM;

	/* copy old array to new one */
	memcpy(new, op->op_array, op->op_size);
	OBD_FREE(op->op_array, op->op_size);
	op->op_array = new;
	op->op_size = new_size;

	return 0;
}
EXPORT_SYMBOL(lu_tgt_pool_extend);

/**
 * lu_tgt_pool_add_lock() - Add a new target to an existing pool.
 * @op: target pool to add new entry
 * @idx: pool index number to add to the @op array
 * @min_count: minimum number of entries to expect in the pool
 * @lock: if true protect lu_tgt_pool use
 *
 * Add a new target device to the pool previously created and returned by
 * lod_pool_new(). Each target can only be in each pool at most one time.
 *
 * Return:
 * * %0 if target could be added to the pool
 * * %negative error if target @idx was not added
 */
int lu_tgt_pool_add_lock(struct lu_tgt_pool *op, __u32 idx,
			 unsigned int min_count, bool lock)
{
	unsigned int i;
	int rc = 0;
	ENTRY;

	if (lock)
		down_write(&op->op_rw_sem);

	/* search ost in pool array */
	for (i = 0; i < op->op_count; i++) {
		if (op->op_array[i] == idx)
			GOTO(out, rc = -EEXIST);
	}

	rc = lu_tgt_pool_extend(op, min_count);
	if (rc)
		GOTO(out, rc);

	/* ost not found we add it */
	op->op_array[op->op_count] = idx;
	op->op_count++;
	EXIT;
out:
	if (lock)
		up_write(&op->op_rw_sem);
	return rc;
}
EXPORT_SYMBOL(lu_tgt_pool_add_lock);

/**
 * lu_tgt_pool_remove() - Remove an existing pool from the system.
 * @op: pointer to the original data structure
 * @idx: target index to be removed
 *
 * The specified pool must have previously been allocated by
 * lod_pool_new() and not have any target members in the pool.
 * If the removed target is not the last, compact the array
 * to remove empty spaces.
 *
 * Return:
 * * %0 on success
 * * %negative error number on failure
 */
int lu_tgt_pool_remove(struct lu_tgt_pool *op, __u32 idx)
{
	unsigned int i;
	ENTRY;

	down_write(&op->op_rw_sem);

	for (i = 0; i < op->op_count; i++) {
		if (op->op_array[i] == idx) {
			memmove(&op->op_array[i], &op->op_array[i + 1],
				(op->op_count - i - 1) *
				sizeof(op->op_array[0]));
			op->op_count--;
			up_write(&op->op_rw_sem);
			EXIT;
			return 0;
		}
	}

	up_write(&op->op_rw_sem);
	RETURN(-EINVAL);
}
EXPORT_SYMBOL(lu_tgt_pool_remove);

int lu_tgt_check_index(int idx, struct lu_tgt_pool *osts)
{
	int i, rc = -ENOENT;
	ENTRY;

	down_read(&osts->op_rw_sem);
	for (i = 0; i < osts->op_count; i++) {
		if (osts->op_array[i] == idx)
			GOTO(out, rc = 0);
	}
	EXIT;
out:
	up_read(&osts->op_rw_sem);
	return rc;
}
EXPORT_SYMBOL(lu_tgt_check_index);

/**
 * lu_tgt_pool_free() - Free pool after it was emptied and removed from /proc.
 * @op: pool to be freed.
 *
 * Note that all of the child/target entries referenced by this pool
 * must have been removed by lod_ost_pool_remove() before it can be
 * deleted from memory.
 */
void lu_tgt_pool_free(struct lu_tgt_pool *op)
{
	ENTRY;

	if (op->op_size == 0)
		RETURN_EXIT;

	down_write(&op->op_rw_sem);

	OBD_FREE(op->op_array, op->op_size);
	op->op_array = NULL;
	op->op_count = 0;
	op->op_size = 0;

	up_write(&op->op_rw_sem);
	EXIT;
}
EXPORT_SYMBOL(lu_tgt_pool_free);
