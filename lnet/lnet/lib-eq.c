/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-eq.c
 * Library level Event queue management routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_PORTALS
#include <portals/lib-p30.h>

ptl_err_t
PtlEQAlloc(ptl_handle_ni_t interface, ptl_size_t count,
           ptl_eq_handler_t callback, ptl_handle_eq_t *handle)
{
        ptl_eq_t      *eq;
        unsigned long  flags;

        LASSERT (ptl_init);
        LASSERT (ptl_apini.apini_refcount > 0);
        
        /* We need count to be a power of 2 so that when eq_{enq,deq}_seq
         * overflow, they don't skip entries, so the queue has the same
         * apparant capacity at all times */

        if (count != LOWEST_BIT_SET(count)) {   /* not a power of 2 already */
                do {                    /* knock off all but the top bit... */
                        count &= ~LOWEST_BIT_SET (count);
                } while (count != LOWEST_BIT_SET(count));

                count <<= 1;                             /* ...and round up */
        }

        if (count == 0)        /* catch bad parameter / overflow on roundup */
                return (PTL_VAL_FAILED);
        
        eq = ptl_eq_alloc();
        if (eq == NULL)
                return (PTL_NO_SPACE);

        PORTAL_ALLOC(eq->eq_events, count * sizeof(ptl_event_t));
        if (eq->eq_events == NULL) {
                PTL_LOCK(flags);
                ptl_eq_free (eq);
                PTL_UNLOCK(flags);
        }

        /* NB this resets all event sequence numbers to 0, to be earlier
         * than eq_deq_seq */
        memset(eq->eq_events, 0, count * sizeof(ptl_event_t));

        eq->eq_deq_seq = 1;
        eq->eq_enq_seq = 1;
        eq->eq_size = count;
        eq->eq_refcount = 0;
        eq->eq_callback = callback;

        PTL_LOCK(flags);

        ptl_initialise_handle (&eq->eq_lh, PTL_COOKIE_TYPE_EQ);
        list_add (&eq->eq_list, &ptl_apini.apini_active_eqs);

        PTL_UNLOCK(flags);

        ptl_eq2handle(handle, eq);
        return (PTL_OK);
}

ptl_err_t
PtlEQFree(ptl_handle_eq_t eqh)
{
        ptl_eq_t      *eq;
        int            size;
        ptl_event_t   *events;
        unsigned long  flags;

        LASSERT (ptl_init);
        LASSERT (ptl_apini.apini_refcount > 0);
        
        PTL_LOCK(flags);

        eq = ptl_handle2eq(&eqh);
        if (eq == NULL) {
                PTL_UNLOCK(flags);
                return (PTL_EQ_INVALID);
        }

        if (eq->eq_refcount != 0) {
                PTL_UNLOCK(flags);
                return (PTL_EQ_IN_USE);
        }

        /* stash for free after lock dropped */
        events  = eq->eq_events;
        size    = eq->eq_size;

        ptl_invalidate_handle (&eq->eq_lh);
        list_del (&eq->eq_list);
        ptl_eq_free (eq);

        PTL_UNLOCK(flags);

        PORTAL_FREE(events, size * sizeof (ptl_event_t));

        return PTL_OK;
}

ptl_err_t
lib_get_event (ptl_eq_t *eq, ptl_event_t *ev)
{
        int          new_index = eq->eq_deq_seq & (eq->eq_size - 1);
        ptl_event_t *new_event = &eq->eq_events[new_index];
        int          rc;
        ENTRY;

        CDEBUG(D_INFO, "event: %p, sequence: %lu, eq->size: %u\n",
               new_event, eq->eq_deq_seq, eq->eq_size);

        if (PTL_SEQ_GT (eq->eq_deq_seq, new_event->sequence)) {
                RETURN(PTL_EQ_EMPTY);
        }

        /* We've got a new event... */
        *ev = *new_event;

        /* ...but did it overwrite an event we've not seen yet? */
        if (eq->eq_deq_seq == new_event->sequence) {
                rc = PTL_OK;
        } else {
                CERROR("Event Queue Overflow: eq seq %lu ev seq %lu\n",
                       eq->eq_deq_seq, new_event->sequence);
                rc = PTL_EQ_DROPPED;
        }

        eq->eq_deq_seq = new_event->sequence + 1;
        RETURN(rc);
}


ptl_err_t
PtlEQGet (ptl_handle_eq_t eventq, ptl_event_t *event)
{
        int which;

        return PtlEQPoll(&eventq, 1, 0, 
                         event, &which);
}

ptl_err_t
PtlEQWait (ptl_handle_eq_t eventq, ptl_event_t *event)
{
        int which;

        return PtlEQPoll(&eventq, 1, PTL_TIME_FOREVER,
                         event, &which);
}

ptl_err_t
PtlEQPoll (ptl_handle_eq_t *eventqs, int neq, int timeout_ms,
           ptl_event_t *event, int *which)
{
        unsigned long    flags;
        int              i;
        int              rc;
#ifdef __KERNEL__
        cfs_waitlink_t   wl;
        cfs_time_t       now;
#else
        struct timeval   then;
        struct timeval   now;
        struct timespec  ts;
#endif
        ENTRY;

        LASSERT (ptl_init);
        LASSERT (ptl_apini.apini_refcount > 0);

        if (neq < 1)
                RETURN(PTL_EQ_INVALID);

        PTL_LOCK(flags);

        for (;;) {
                for (i = 0; i < neq; i++) {
                        ptl_eq_t *eq = ptl_handle2eq(&eventqs[i]);

                        rc = lib_get_event (eq, event);
                        if (rc != PTL_EQ_EMPTY) {
                                PTL_UNLOCK(flags);
                                *which = i;
                                RETURN(rc);
                        }
                }
                
                if (timeout_ms == 0) {
                        PTL_UNLOCK (flags);
                        RETURN (PTL_EQ_EMPTY);
                }

                /* Some architectures force us to do spin locking/unlocking
                 * in the same stack frame, means we can abstract the
                 * locking here */
#ifdef __KERNEL__
                cfs_waitlink_init(&wl);
                set_current_state(TASK_INTERRUPTIBLE);
                cfs_waitq_add(&ptl_apini.apini_waitq, &wl);

                PTL_UNLOCK(flags);

                if (timeout_ms < 0) {
                        cfs_waitq_wait (&wl);
                } else { 
                        struct timeval tv;

                        now = cfs_time_current();
                        cfs_waitq_timedwait(&wl, cfs_time_seconds(timeout_ms)/1000);
                        cfs_duration_usec(cfs_time_sub(cfs_time_current(), now), &tv); 
                        timeout_ms -= tv.tv_sec * 1000 + tv.tv_usec / 1000;
                        if (timeout_ms < 0)
                                timeout_ms = 0;
                }
                
                PTL_LOCK(flags);
                cfs_waitq_del(&ptl_apini.apini_waitq, &wl);
#else
                if (timeout_ms < 0) {
                        pthread_cond_wait(&ptl_apini.apini_cond, 
                                          &ptl_apini.apini_mutex);
                } else {
                        gettimeofday(&then, NULL);
                        
                        ts.tv_sec = then.tv_sec + timeout_ms/1000;
                        ts.tv_nsec = then.tv_usec * 1000 + 
                                     (timeout_ms%1000) * 1000000;
                        if (ts.tv_nsec >= 1000000000) {
                                ts.tv_sec++;
                                ts.tv_nsec -= 1000000000;
                        }
                        
                        pthread_cond_timedwait(&ptl_apini.apini_cond,
                                               &ptl_apini.apini_mutex, &ts);
                        
                        gettimeofday(&now, NULL);
                        timeout_ms -= (now.tv_sec - then.tv_sec) * 1000 +
                                      (now.tv_usec - then.tv_usec) / 1000;
                        
                        if (timeout_ms < 0)
                                timeout_ms = 0;
                }
#endif
        }
}
