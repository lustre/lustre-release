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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>


/*
 * Wait queue routines
 */

/*
 * init_waitqueue_head
 *   To initialize the wait queue
 *
 * Arguments:
 *   waitq:  pointer to the wait_queue_head_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void init_waitqueue_head(wait_queue_head_t *waitq)
{
    waitq->magic = CFS_WAITQ_MAGIC;
    waitq->flags = 0;
    INIT_LIST_HEAD(&(waitq->waiters));
	spin_lock_init(&(waitq->guard));
}

/*
 * init_waitqueue_entry_current
 *   To initialize the wake link node
 *
 * Arguments:
 *   link:  pointer to the wait_queue_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void init_waitqueue_entry_current(wait_queue_t *link)
{
    struct task_struct * task = current;
    PTASK_SLOT   slot = NULL;

    if (!task) {
        /* should bugchk here */
        cfs_enter_debugger();
        return;
    }

    slot = CONTAINING_RECORD(task, TASK_SLOT, task);
    cfs_assert(slot->Magic == TASKSLT_MAGIC);

    memset(link, 0, sizeof(wait_queue_t));

    link->magic = CFS_WAITLINK_MAGIC;
    link->flags = 0;

    link->event = &(slot->Event);
    link->hits  = &(slot->hits);

    atomic_inc(&slot->count);

    INIT_LIST_HEAD(&(link->waitq[0].link));
    INIT_LIST_HEAD(&(link->waitq[1].link));

    link->waitq[0].waitl = link->waitq[1].waitl = link;
}


/*
 * cfs_waitlink_fini
 *   To finilize the wake link node
 *
 * Arguments:
 *   link:  pointer to the wait_queue_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitlink_fini(wait_queue_t *link)
{
    struct task_struct * task = current;
    PTASK_SLOT   slot = NULL;

    if (!task) {
        /* should bugchk here */
        cfs_enter_debugger();
        return;
    }

    slot = CONTAINING_RECORD(task, TASK_SLOT, task);
    cfs_assert(slot->Magic == TASKSLT_MAGIC);
    cfs_assert(link->magic == CFS_WAITLINK_MAGIC);
    cfs_assert(link->waitq[0].waitq == NULL);
    cfs_assert(link->waitq[1].waitq == NULL);

    atomic_dec(&slot->count);
}


/*
 * cfs_waitq_add_internal
 *   To queue the wait link node to the wait queue
 *
 * Arguments:
 *   waitq:  pointer to the wait_queue_head_t structure
 *   link:   pointer to the wait_queue_t structure
 *   int:    queue no (Normal or Forward waitq)
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitq_add_internal(wait_queue_head_t *waitq,
			    wait_queue_t *link,
                            __u32 waitqid )
{ 
    LASSERT(waitq != NULL);
    LASSERT(link != NULL);
    LASSERT(waitq->magic == CFS_WAITQ_MAGIC);
    LASSERT(link->magic == CFS_WAITLINK_MAGIC);
    LASSERT(waitqid < CFS_WAITQ_CHANNELS);

	spin_lock(&(waitq->guard));
    LASSERT(link->waitq[waitqid].waitq == NULL);
    link->waitq[waitqid].waitq = waitq;
    if (link->flags & CFS_WAITQ_EXCLUSIVE) {
	list_add_tail(&link->waitq[waitqid].link, &waitq->waiters);
    } else {
	list_add(&link->waitq[waitqid].link, &waitq->waiters);
    }
	spin_unlock(&(waitq->guard));
}
/*
 * add_wait_queue
 *   To queue the wait link node to the wait queue
 *
 * Arguments:
 *   waitq:  pointer to the wait_queue_head_t structure
 *   link:  pointer to the wait_queue_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void add_wait_queue(wait_queue_head_t *waitq,
		   wait_queue_t *link)
{ 
    cfs_waitq_add_internal(waitq, link, CFS_WAITQ_CHAN_NORMAL);
}

/*
 * add_wait_queue_exclusive
 *   To set the wait link node to exclusive mode
 *   and queue it to the wait queue
 *
 * Arguments:
 *   waitq:  pointer to the wait_queue_head_t structure
 *   link:  pointer to the cfs_wait_link structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void add_wait_queue_exclusive( wait_queue_head_t *waitq,
			      wait_queue_t *link)
{
    LASSERT(waitq != NULL);
    LASSERT(link != NULL);
    LASSERT(waitq->magic == CFS_WAITQ_MAGIC);
    LASSERT(link->magic == CFS_WAITLINK_MAGIC);

	link->flags |= CFS_WAITQ_EXCLUSIVE;
    add_wait_queue(waitq, link);
}

/*
 * remove_wait_queue
 *   To remove the wait link node from the waitq
 *
 * Arguments:
 *   waitq:  pointer to the cfs_ waitq_t structure
 *   link:  pointer to the wait_queue_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void remove_wait_queue( wait_queue_head_t *waitq,
		    wait_queue_t *link)
{
    int i = 0;

    LASSERT(waitq != NULL);
    LASSERT(link != NULL);

    LASSERT(waitq->magic == CFS_WAITQ_MAGIC);
    LASSERT(link->magic == CFS_WAITLINK_MAGIC);

	spin_lock(&(waitq->guard));

    for (i=0; i < CFS_WAITQ_CHANNELS; i++) {
        if (link->waitq[i].waitq == waitq)
            break;
    }

    if (i < CFS_WAITQ_CHANNELS) {
        link->waitq[i].waitq = NULL;
	list_del_init(&link->waitq[i].link);
    } else {
        cfs_enter_debugger();
    }

	spin_unlock(&(waitq->guard));
}

/*
 * waitqueue_active
 *   Is the waitq active (not empty) ?
 *
 * Arguments:
 *   waitq:  pointer to the cfs_ waitq_t structure
 *
 * Return Value:
 *   Zero: the waitq is empty
 *   Non-Zero: the waitq is active
 *
 * Notes: 
 *   We always returns TRUE here, the same to Darwin.
 */

int waitqueue_active(wait_queue_head_t *waitq)
{
    LASSERT(waitq != NULL);
    LASSERT(waitq->magic == CFS_WAITQ_MAGIC);

	return (1);
}

/*
 * wake_up_nr
 *   To wake up all the non-exclusive tasks plus nr exclusive
 *   ones in the waitq
 *
 * Arguments:
 *   waitq:  pointer to the wait_queue_head_t structure
 *   nr:    number of exclusive tasks to be woken up
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */


void wake_up_nr(wait_queue_head_t *waitq, int nr)
{
    int     result;
    cfs_waitlink_channel_t * scan;

    LASSERT(waitq != NULL);
    LASSERT(waitq->magic == CFS_WAITQ_MAGIC);

	spin_lock(&waitq->guard);
    list_for_each_entry(scan, &waitq->waiters,
                            link) {

	wait_queue_t *waitl = scan->waitl;

        result = cfs_wake_event(waitl->event);
        LASSERT( result == FALSE || result == TRUE );

        if (result) {
	    atomic_inc(waitl->hits);
        }

        if ((waitl->flags & CFS_WAITQ_EXCLUSIVE) && --nr == 0)
            break;
    }

	spin_unlock(&waitq->guard);
	return;
}

/*
 * wake_up
 *   To wake up all the non-exclusive tasks and 1 exclusive
 *
 * Arguments:
 *   waitq:  pointer to the wait_queue_head_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void wake_up(wait_queue_head_t *waitq)
{
    wake_up_nr(waitq, 1);
}


/*
 * wake_up_all
 *   To wake up all the tasks in the waitq
 *
 * Arguments:
 *   waitq:  pointer to the wait_queue_head_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void wake_up_all(wait_queue_head_t *waitq)
{
    LASSERT(waitq != NULL);
    LASSERT(waitq->magic ==CFS_WAITQ_MAGIC);

	wake_up_nr(waitq, 0);
}

/*
 * waitq_wait
 *   To wait on the link node until it is signaled.
 *
 * Arguments:
 *   link:  pointer to the wait_queue_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void waitq_wait(wait_queue_t *link, long state)
{ 
    LASSERT(link != NULL);
    LASSERT(link->magic == CFS_WAITLINK_MAGIC);

    if (atomic_read(link->hits) > 0) {
	atomic_dec(link->hits);
	LASSERT((__u32)atomic_read(link->hits) < (__u32)0xFFFFFF00);
    } else {
        cfs_wait_event_internal(link->event, 0);
    }
}

/*
 * waitq_timedwait
 *   To wait the link node to be signaled with a timeout limit
 *
 * Arguments:
 *   link:   pointer to the wait_queue_t structure
 *   timeout: the timeout limitation
 *
 * Return Value:
 *   Woken up: return the difference of the current time and
 *             the timeout
 *   Timeout:  return 0
 *
 * Notes: 
 *   What if it happens to be woken up at the just timeout time !?
 */

int64_t waitq_timedwait( wait_queue_t *link,
			     long state,
                             int64_t timeout)
{ 

    if (atomic_read(link->hits) > 0) {
	atomic_dec(link->hits);
	LASSERT((__u32)atomic_read(link->hits) < (__u32)0xFFFFFF00);
        return (int64_t)TRUE;
    }

    return (int64_t)cfs_wait_event_internal(link->event, timeout);
}
