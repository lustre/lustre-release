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
 * GPL HEADER END
 */

/* percpu partition lock
 *
 * There are some use-cases like this in Lustre:
 * . each CPU partition has it's own private data which is frequently changed,
 *   and mostly by the local CPU partition.
 * . all CPU partitions share some global data, these data are rarely changed.
 *
 * LNet is typical example.
 * CPU partition lock is designed for this kind of use-cases:
 * . each CPU partition has it's own private lock
 * . change on private data just needs to take the private lock
 * . read on shared data just needs to take _any_ of private locks
 * . change on shared data needs to take _all_ private locks,
 *   which is slow and should be really rare.
 */
enum {
	CFS_PERCPT_LOCK_EX	= -1,	/* negative */
};

struct cfs_percpt_lock {
	/* cpu-partition-table for this lock */
	struct cfs_cpt_table	 *pcl_cptab;
	/* exclusively locked */
	unsigned int		  pcl_locked;
	/* private lock table */
	spinlock_t		**pcl_locks;
};

/* return number of private locks */
#define cfs_percpt_lock_num(pcl)	cfs_cpt_number(pcl->pcl_cptab)

/* create a cpu-partition lock based on CPU partition table \a cptab,
 * each private lock has extra \a psize bytes padding data
 */
struct cfs_percpt_lock *cfs_percpt_lock_create(struct cfs_cpt_table *cptab,
					       struct lock_class_key *keys);
/* destroy a cpu-partition lock */
void cfs_percpt_lock_free(struct cfs_percpt_lock *pcl);

/* lock private lock \a index of \a pcl */
void cfs_percpt_lock(struct cfs_percpt_lock *pcl, int index);

/* unlock private lock \a index of \a pcl */
void cfs_percpt_unlock(struct cfs_percpt_lock *pcl, int index);

#define CFS_PERCPT_LOCK_KEYS	256

/* NB: don't allocate keys dynamically, lockdep needs them to be in ".data" */
#define cfs_percpt_lock_alloc(cptab)					\
({									\
	static struct lock_class_key ___keys[CFS_PERCPT_LOCK_KEYS];	\
	struct cfs_percpt_lock *___lk;					\
									\
	if (cfs_cpt_number(cptab) > CFS_PERCPT_LOCK_KEYS)		\
		___lk = cfs_percpt_lock_create(cptab, NULL);		\
	else								\
		___lk = cfs_percpt_lock_create(cptab, ___keys);		\
	___lk;								\
})
