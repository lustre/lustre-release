/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_MMAP_LOCK_H__
#define __LIBCFS_LINUX_MMAP_LOCK_H__

#include_next <linux/mmap_lock.h>

#ifndef HAVE_MMAP_LOCK
static inline void mmap_write_lock(struct mm_struct *mm)
{
	down_write(&mm->mmap_sem);
}

static inline bool mmap_write_trylock(struct mm_struct *mm)
{
	return down_write_trylock(&mm->mmap_sem) != 0;
}

static inline void mmap_write_unlock(struct mm_struct *mm)
{
	up_write(&mm->mmap_sem);
}

static inline void mmap_read_lock(struct mm_struct *mm)
{
	down_read(&mm->mmap_sem);
}

static inline bool mmap_read_trylock(struct mm_struct *mm)
{
	return down_read_trylock(&mm->mmap_sem) != 0;
}

static inline void mmap_read_unlock(struct mm_struct *mm)
{
	up_read(&mm->mmap_sem);
}
#else
 #ifndef HAVE_MMAP_WRITE_TRYLOCK
/* Replacement for mmap_write_trylock() */
static inline bool mmap_write_trylock(struct mm_struct *mm)
{
	return down_write_trylock(&mm->mmap_lock) != 0;
}
 #endif /* HAVE_MMAP_WRITE_TRYLOCK */
#endif

#endif /* __LIBCFS_LINUX_MMAP_LOCK_H__ */
