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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * lustre/target/tgt_pool.c
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

/**
 * Initialize the pool data structures at startup.
 *
 * Allocate and initialize the pool data structures with the specified
 * array size.  If pool count is not specified (\a count == 0), then
 * POOL_INIT_COUNT will be used.  Allocating a non-zero initial array
 * size avoids the need to reallocate as new pools are added.
 *
 * \param[in] op	pool structure
 * \param[in] count	initial size of the target op_array[] array
 *
 * \retval		0 indicates successful pool initialization
 * \retval		negative error number on failure
 */
#define POOL_INIT_COUNT 2
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
 * Increase the op_array size to hold more targets in this pool.
 *
 * The size is increased to at least \a min_count, but may be larger
 * for an existing pool since ->op_array[] is growing exponentially.
 * Caller must hold write op_rwlock.
 *
 * \param[in] op	pool structure
 * \param[in] min_count	minimum number of entries to handle
 *
 * \retval		0 on success
 * \retval		negative error number on failure.
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
 * Add a new target to an existing pool.
 *
 * Add a new target device to the pool previously created and returned by
 * lod_pool_new().  Each target can only be in each pool at most one time.
 *
 * \param[in] op	target pool to add new entry
 * \param[in] idx	pool index number to add to the \a op array
 * \param[in] min_count	minimum number of entries to expect in the pool
 *
 * \retval		0 if target could be added to the pool
 * \retval		negative error if target \a idx was not added
 */
int lu_tgt_pool_add(struct lu_tgt_pool *op, __u32 idx, unsigned int min_count)
{
	unsigned int i;
	int rc = 0;
	ENTRY;

	down_write(&op->op_rw_sem);

	rc = lu_tgt_pool_extend(op, min_count);
	if (rc)
		GOTO(out, rc);

	/* search ost in pool array */
	for (i = 0; i < op->op_count; i++) {
		if (op->op_array[i] == idx)
			GOTO(out, rc = -EEXIST);
	}
	/* ost not found we add it */
	op->op_array[op->op_count] = idx;
	op->op_count++;
	EXIT;
out:
	up_write(&op->op_rw_sem);
	return rc;
}
EXPORT_SYMBOL(lu_tgt_pool_add);

/**
 * Remove an existing pool from the system.
 *
 * The specified pool must have previously been allocated by
 * lod_pool_new() and not have any target members in the pool.
 * If the removed target is not the last, compact the array
 * to remove empty spaces.
 *
 * \param[in] op	pointer to the original data structure
 * \param[in] idx	target index to be removed
 *
 * \retval		0 on success
 * \retval		negative error number on failure
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
	int rc, i;
	ENTRY;

	down_read(&osts->op_rw_sem);
	for (i = 0; i < osts->op_count; i++) {
		if (osts->op_array[i] == idx)
			GOTO(out, rc = 0);
	}
	rc = -ENOENT;
	EXIT;
out:
	up_read(&osts->op_rw_sem);
	return rc;
}
EXPORT_SYMBOL(lu_tgt_check_index);

/**
 * Free the pool after it was emptied and removed from /proc.
 *
 * Note that all of the child/target entries referenced by this pool
 * must have been removed by lod_ost_pool_remove() before it can be
 * deleted from memory.
 *
 * \param[in] op	pool to be freed.
 *
 * \retval		0 on success or if pool was already freed
 */
int lu_tgt_pool_free(struct lu_tgt_pool *op)
{
	ENTRY;

	if (op->op_size == 0)
		RETURN(0);

	down_write(&op->op_rw_sem);

	OBD_FREE(op->op_array, op->op_size);
	op->op_array = NULL;
	op->op_count = 0;
	op->op_size = 0;

	up_write(&op->op_rw_sem);
	RETURN(0);
}
EXPORT_SYMBOL(lu_tgt_pool_free);
