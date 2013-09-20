#ifndef _OSD_DYNLOCKS_H
#define _OSD_DYNLOCKS_H

#include <linux/list.h>
#include <linux/wait.h>

/*
 * lock's namespace:
 *   - list of locks
 *   - lock to protect this list
 */
struct dynlock {
	unsigned		dl_magic;
	struct list_head	dl_list;
	spinlock_t		dl_list_lock;
};

enum dynlock_type {
	DLT_WRITE,
	DLT_READ
};

struct dynlock_handle {
	unsigned		dh_magic;
	struct list_head	dh_list;
	unsigned long		dh_value;	/* lock value */
	int			dh_refcount;	/* number of users */
	int			dh_readers;
	int			dh_writers;
	int			dh_pid;		/* holder of the lock */
	wait_queue_head_t	dh_wait;
};

void dynlock_init(struct dynlock *dl);
struct dynlock_handle *dynlock_lock(struct dynlock *dl, unsigned long value,
				    enum dynlock_type lt, gfp_t gfp);
void dynlock_unlock(struct dynlock *dl, struct dynlock_handle *lock);
int dynlock_is_locked(struct dynlock *dl, unsigned long value);

#endif
