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
 *
 * Dynamic Locks
 *
 * struct dynlock is lockspace
 * one may request lock (exclusive or shared) for some value
 * in that lockspace
 *
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include <libcfs/libcfs.h>

#include <obd_support.h>
#include "osd_dynlocks.h"
#include "osd_internal.h"

#define DYNLOCK_HANDLE_MAGIC	0xd19a10c
#define DYNLOCK_HANDLE_DEAD	0xd1956ee
#define DYNLOCK_LIST_MAGIC	0x11ee91e6

/*
 * dynlock_init
 *
 * initialize lockspace
 *
 */
void dynlock_init(struct dynlock *dl)
{
	spin_lock_init(&dl->dl_list_lock);
	INIT_LIST_HEAD(&dl->dl_list);
	dl->dl_magic = DYNLOCK_LIST_MAGIC;
}

/*
 * dynlock_lock
 *
 * acquires lock (exclusive or shared) in specified lockspace
 * each lock in lockspace is allocated separately, so user have
 * to specify GFP flags.
 * routine returns pointer to lock. this pointer is intended to
 * be passed to dynlock_unlock
 *
 */
struct dynlock_handle *dynlock_lock(struct dynlock *dl, unsigned long value,
				    enum dynlock_type lt, gfp_t gfp)
{
	struct dynlock_handle *nhl = NULL;
	struct dynlock_handle *hl;

	BUG_ON(dl == NULL);
	BUG_ON(dl->dl_magic != DYNLOCK_LIST_MAGIC);

repeat:
	/* find requested lock in lockspace */
	spin_lock(&dl->dl_list_lock);
	BUG_ON(dl->dl_list.next == NULL);
	BUG_ON(dl->dl_list.prev == NULL);
	list_for_each_entry(hl, &dl->dl_list, dh_list) {
		BUG_ON(hl->dh_list.next == NULL);
		BUG_ON(hl->dh_list.prev == NULL);
		BUG_ON(hl->dh_magic != DYNLOCK_HANDLE_MAGIC);
		if (hl->dh_value == value) {
			/* lock is found */
			if (nhl) {
				/* someone else just allocated
				 * lock we didn't find and just created
				 * so, we drop our lock
				 */
				OBD_SLAB_FREE(nhl, dynlock_cachep, sizeof(*nhl));
			}
			hl->dh_refcount++;
			goto found;
		}
	}
	/* lock not found */
	if (nhl) {
		/* we already have allocated lock. use it */
		hl = nhl;
		nhl = NULL;
		list_add(&hl->dh_list, &dl->dl_list);
		goto found;
	}
	spin_unlock(&dl->dl_list_lock);

	/* lock not found and we haven't allocated lock yet. allocate it */
	OBD_SLAB_ALLOC_GFP(nhl, dynlock_cachep, sizeof(*nhl), gfp);
	if (nhl == NULL)
		return NULL;
	nhl->dh_refcount = 1;
	nhl->dh_value = value;
	nhl->dh_readers = 0;
	nhl->dh_writers = 0;
	nhl->dh_magic = DYNLOCK_HANDLE_MAGIC;
	init_waitqueue_head(&nhl->dh_wait);

	/* while lock is being allocated, someone else may allocate it
	 * and put onto to list. check this situation
	 */
	goto repeat;

found:
	if (lt == DLT_WRITE) {
		/* exclusive lock: user don't want to share lock at all
		 * NOTE: one process may take the same lock several times
		 * this functionaly is useful for rename operations */
		while ((hl->dh_writers && hl->dh_pid != current->pid) ||
				hl->dh_readers) {
			spin_unlock(&dl->dl_list_lock);
			wait_event(hl->dh_wait,
				hl->dh_writers == 0 && hl->dh_readers == 0);
			spin_lock(&dl->dl_list_lock);
		}
		hl->dh_writers++;
	} else {
		/* shared lock: user do not want to share lock with writer */
		while (hl->dh_writers) {
			spin_unlock(&dl->dl_list_lock);
			wait_event(hl->dh_wait, hl->dh_writers == 0);
			spin_lock(&dl->dl_list_lock);
		}
		hl->dh_readers++;
	}
	hl->dh_pid = current->pid;
	spin_unlock(&dl->dl_list_lock);

	return hl;
}

/*
 * dynlock_unlock
 *
 * user have to specify lockspace (dl) and pointer to lock structure
 * returned by dynlock_lock()
 *
 */
void dynlock_unlock(struct dynlock *dl, struct dynlock_handle *hl)
{
	int wakeup = 0;

	BUG_ON(dl == NULL);
	BUG_ON(hl == NULL);
	BUG_ON(dl->dl_magic != DYNLOCK_LIST_MAGIC);

	if (hl->dh_magic != DYNLOCK_HANDLE_MAGIC)
		printk(KERN_EMERG "wrong lock magic: %#x\n", hl->dh_magic);

	BUG_ON(hl->dh_magic != DYNLOCK_HANDLE_MAGIC);
	BUG_ON(hl->dh_writers != 0 && current->pid != hl->dh_pid);

	spin_lock(&dl->dl_list_lock);
	if (hl->dh_writers) {
		BUG_ON(hl->dh_readers != 0);
		hl->dh_writers--;
		if (hl->dh_writers == 0)
			wakeup = 1;
	} else if (hl->dh_readers) {
		hl->dh_readers--;
		if (hl->dh_readers == 0)
			wakeup = 1;
	} else {
		BUG();
	}
	if (wakeup) {
		hl->dh_pid = 0;
		wake_up(&hl->dh_wait);
	}
	if (--(hl->dh_refcount) == 0) {
		hl->dh_magic = DYNLOCK_HANDLE_DEAD;
		list_del(&hl->dh_list);
		OBD_SLAB_FREE(hl, dynlock_cachep, sizeof(*hl));
	}
	spin_unlock(&dl->dl_list_lock);
}

int dynlock_is_locked(struct dynlock *dl, unsigned long value)
{
	struct dynlock_handle *hl;
	int result = 0;

	/* find requested lock in lockspace */
	spin_lock(&dl->dl_list_lock);
	BUG_ON(dl->dl_list.next == NULL);
	BUG_ON(dl->dl_list.prev == NULL);
	list_for_each_entry(hl, &dl->dl_list, dh_list) {
		BUG_ON(hl->dh_list.next == NULL);
		BUG_ON(hl->dh_list.prev == NULL);
		BUG_ON(hl->dh_magic != DYNLOCK_HANDLE_MAGIC);
		if (hl->dh_value == value && hl->dh_pid == current->pid) {
			/* lock is found */
			result = 1;
			break;
		}
	}
	spin_unlock(&dl->dl_list_lock);
	return result;
}
