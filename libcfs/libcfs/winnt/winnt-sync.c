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
 * cfs_waitq_init
 *   To initialize the wait queue
 *
 * Arguments:
 *   waitq:  pointer to the cfs_waitq_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitq_init(cfs_waitq_t *waitq)
{
    waitq->magic = CFS_WAITQ_MAGIC;
    waitq->flags = 0;
    CFS_INIT_LIST_HEAD(&(waitq->waiters));
	spin_lock_init(&(waitq->guard));
}

/*
 * cfs_waitlink_init
 *   To initialize the wake link node
 *
 * Arguments:
 *   link:  pointer to the cfs_waitlink_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitlink_init(cfs_waitlink_t *link)
{
    cfs_task_t * task = cfs_current();
    PTASK_SLOT   slot = NULL;

    if (!task) {
        /* should bugchk here */
        cfs_enter_debugger();
        return;
    }

    slot = CONTAINING_RECORD(task, TASK_SLOT, task);
    cfs_assert(slot->Magic == TASKSLT_MAGIC);

    memset(link, 0, sizeof(cfs_waitlink_t));

    link->magic = CFS_WAITLINK_MAGIC;
    link->flags = 0;

    link->event = &(slot->Event);
    link->hits  = &(slot->hits);

    cfs_atomic_inc(&slot->count);

    CFS_INIT_LIST_HEAD(&(link->waitq[0].link));
    CFS_INIT_LIST_HEAD(&(link->waitq[1].link));

    link->waitq[0].waitl = link->waitq[1].waitl = link;
}


/*
 * cfs_waitlink_fini
 *   To finilize the wake link node
 *
 * Arguments:
 *   link:  pointer to the cfs_waitlink_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitlink_fini(cfs_waitlink_t *link)
{
    cfs_task_t * task = cfs_current();
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

    cfs_atomic_dec(&slot->count);
}


/*
 * cfs_waitq_add_internal
 *   To queue the wait link node to the wait queue
 *
 * Arguments:
 *   waitq:  pointer to the cfs_waitq_t structure
 *   link:   pointer to the cfs_waitlink_t structure
 *   int:    queue no (Normal or Forward waitq)
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitq_add_internal(cfs_waitq_t *waitq,
                            cfs_waitlink_t *link,
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
        cfs_list_add_tail(&link->waitq[waitqid].link, &waitq->waiters);
    } else {
        cfs_list_add(&link->waitq[waitqid].link, &waitq->waiters);
    }
	spin_unlock(&(waitq->guard));
}
/*
 * cfs_waitq_add
 *   To queue the wait link node to the wait queue
 *
 * Arguments:
 *   waitq:  pointer to the cfs_waitq_t structure
 *   link:  pointer to the cfs_waitlink_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitq_add(cfs_waitq_t *waitq,
                   cfs_waitlink_t *link)
{ 
    cfs_waitq_add_internal(waitq, link, CFS_WAITQ_CHAN_NORMAL);
}

/*
 * cfs_waitq_add_exclusive
 *   To set the wait link node to exclusive mode
 *   and queue it to the wait queue
 *
 * Arguments:
 *   waitq:  pointer to the cfs_waitq_t structure
 *   link:  pointer to the cfs_wait_link structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitq_add_exclusive( cfs_waitq_t *waitq,
                              cfs_waitlink_t *link)
{
    LASSERT(waitq != NULL);
    LASSERT(link != NULL);
    LASSERT(waitq->magic == CFS_WAITQ_MAGIC);
    LASSERT(link->magic == CFS_WAITLINK_MAGIC);

	link->flags |= CFS_WAITQ_EXCLUSIVE;
    cfs_waitq_add(waitq, link);
}

/*
 * cfs_waitq_del
 *   To remove the wait link node from the waitq
 *
 * Arguments:
 *   waitq:  pointer to the cfs_ waitq_t structure
 *   link:  pointer to the cfs_waitlink_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitq_del( cfs_waitq_t *waitq,
                    cfs_waitlink_t *link)
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
        cfs_list_del_init(&link->waitq[i].link);
    } else {
        cfs_enter_debugger();
    }

	spin_unlock(&(waitq->guard));
}

/*
 * cfs_waitq_active
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

int cfs_waitq_active(cfs_waitq_t *waitq)
{
    LASSERT(waitq != NULL);
    LASSERT(waitq->magic == CFS_WAITQ_MAGIC);

	return (1);
}

/*
 * cfs_waitq_signal_nr
 *   To wake up all the non-exclusive tasks plus nr exclusive
 *   ones in the waitq
 *
 * Arguments:
 *   waitq:  pointer to the cfs_waitq_t structure
 *   nr:    number of exclusive tasks to be woken up
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */


void cfs_waitq_signal_nr(cfs_waitq_t *waitq, int nr)
{
    int     result;
    cfs_waitlink_channel_t * scan;

    LASSERT(waitq != NULL);
    LASSERT(waitq->magic == CFS_WAITQ_MAGIC);

	spin_lock(&waitq->guard);
    cfs_list_for_each_entry_typed(scan, &waitq->waiters, 
                            cfs_waitlink_channel_t,
                            link) {

        cfs_waitlink_t *waitl = scan->waitl;

        result = cfs_wake_event(waitl->event);
        LASSERT( result == FALSE || result == TRUE );

        if (result) {
            cfs_atomic_inc(waitl->hits);
        }

        if ((waitl->flags & CFS_WAITQ_EXCLUSIVE) && --nr == 0)
            break;
    }

	spin_unlock(&waitq->guard);
	return;
}

/*
 * cfs_waitq_signal
 *   To wake up all the non-exclusive tasks and 1 exclusive
 *
 * Arguments:
 *   waitq:  pointer to the cfs_waitq_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitq_signal(cfs_waitq_t *waitq)
{
    cfs_waitq_signal_nr(waitq, 1);
}


/*
 * cfs_waitq_broadcast
 *   To wake up all the tasks in the waitq
 *
 * Arguments:
 *   waitq:  pointer to the cfs_waitq_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitq_broadcast(cfs_waitq_t *waitq)
{
    LASSERT(waitq != NULL);
    LASSERT(waitq->magic ==CFS_WAITQ_MAGIC);

	cfs_waitq_signal_nr(waitq, 0);
}

/*
 * cfs_waitq_wait
 *   To wait on the link node until it is signaled.
 *
 * Arguments:
 *   link:  pointer to the cfs_waitlink_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_waitq_wait(cfs_waitlink_t *link, cfs_task_state_t state)
{ 
    LASSERT(link != NULL);
    LASSERT(link->magic == CFS_WAITLINK_MAGIC);

    if (cfs_atomic_read(link->hits) > 0) {
        cfs_atomic_dec(link->hits);
        LASSERT((__u32)cfs_atomic_read(link->hits) < (__u32)0xFFFFFF00);
    } else {
        cfs_wait_event_internal(link->event, 0);
    }
}

/*
 * cfs_waitq_timedwait
 *   To wait the link node to be signaled with a timeout limit
 *
 * Arguments:
 *   link:   pointer to the cfs_waitlink_t structure
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

int64_t cfs_waitq_timedwait( cfs_waitlink_t *link,
                             cfs_task_state_t state,
                             int64_t timeout)
{ 

    if (cfs_atomic_read(link->hits) > 0) {
        cfs_atomic_dec(link->hits);
        LASSERT((__u32)cfs_atomic_read(link->hits) < (__u32)0xFFFFFF00);
        return (int64_t)TRUE;
    }

    return (int64_t)cfs_wait_event_internal(link->event, timeout);
}
