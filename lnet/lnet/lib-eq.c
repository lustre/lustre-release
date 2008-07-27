/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/lnet/lib-eq.c
 *
 * Library level Event queue management routines
 */

#define DEBUG_SUBSYSTEM S_LNET
#include <lnet/lib-lnet.h>

int
LNetEQAlloc(unsigned int count, lnet_eq_handler_t callback,
            lnet_handle_eq_t *handle)
{
        lnet_eq_t     *eq;

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);

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
                return (-EINVAL);

        eq = lnet_eq_alloc();
        if (eq == NULL)
                return (-ENOMEM);

        LIBCFS_ALLOC(eq->eq_events, count * sizeof(lnet_event_t));
        if (eq->eq_events == NULL) {
                LNET_LOCK();
                lnet_eq_free (eq);
                LNET_UNLOCK();

                return -ENOMEM;
        }

        /* NB this resets all event sequence numbers to 0, to be earlier
         * than eq_deq_seq */
        memset(eq->eq_events, 0, count * sizeof(lnet_event_t));

        eq->eq_deq_seq = 1;
        eq->eq_enq_seq = 1;
        eq->eq_size = count;
        eq->eq_refcount = 0;
        eq->eq_callback = callback;

        LNET_LOCK();

        lnet_initialise_handle (&eq->eq_lh, LNET_COOKIE_TYPE_EQ);
        list_add (&eq->eq_list, &the_lnet.ln_active_eqs);

        LNET_UNLOCK();

        lnet_eq2handle(handle, eq);
        return (0);
}

int
LNetEQFree(lnet_handle_eq_t eqh)
{
        lnet_eq_t     *eq;
        int            size;
        lnet_event_t  *events;

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);

        LNET_LOCK();

        eq = lnet_handle2eq(&eqh);
        if (eq == NULL) {
                LNET_UNLOCK();
                return (-ENOENT);
        }

        if (eq->eq_refcount != 0) {
                CDEBUG(D_NET, "Event queue (%d) busy on destroy.\n",
                       eq->eq_refcount);
                LNET_UNLOCK();
                return (-EBUSY);
        }

        /* stash for free after lock dropped */
        events  = eq->eq_events;
        size    = eq->eq_size;

        lnet_invalidate_handle (&eq->eq_lh);
        list_del (&eq->eq_list);
        lnet_eq_free (eq);

        LNET_UNLOCK();

        LIBCFS_FREE(events, size * sizeof (lnet_event_t));

        return 0;
}

int
lib_get_event (lnet_eq_t *eq, lnet_event_t *ev)
{
        int           new_index = eq->eq_deq_seq & (eq->eq_size - 1);
        lnet_event_t *new_event = &eq->eq_events[new_index];
        int           rc;
        ENTRY;

        CDEBUG(D_INFO, "event: %p, sequence: %lu, eq->size: %u\n",
               new_event, eq->eq_deq_seq, eq->eq_size);

        if (LNET_SEQ_GT (eq->eq_deq_seq, new_event->sequence)) {
                RETURN(0);
        }

        /* We've got a new event... */
        *ev = *new_event;

        /* ...but did it overwrite an event we've not seen yet? */
        if (eq->eq_deq_seq == new_event->sequence) {
                rc = 1;
        } else {
                /* don't complain with CERROR: some EQs are sized small
                 * anyway; if it's important, the caller should complain */
                CDEBUG(D_NET, "Event Queue Overflow: eq seq %lu ev seq %lu\n",
                       eq->eq_deq_seq, new_event->sequence);
                rc = -EOVERFLOW;
        }

        eq->eq_deq_seq = new_event->sequence + 1;
        RETURN(rc);
}


int
LNetEQGet (lnet_handle_eq_t eventq, lnet_event_t *event)
{
        int which;

        return LNetEQPoll(&eventq, 1, 0,
                         event, &which);
}

int
LNetEQWait (lnet_handle_eq_t eventq, lnet_event_t *event)
{
        int which;

        return LNetEQPoll(&eventq, 1, LNET_TIME_FOREVER,
                         event, &which);
}

int
LNetEQPoll (lnet_handle_eq_t *eventqs, int neq, int timeout_ms,
            lnet_event_t *event, int *which)
{
        int              i;
        int              rc;
#ifdef __KERNEL__
        cfs_waitlink_t   wl;
        cfs_time_t       now;
#else
        struct timeval   then;
        struct timeval   now;
# ifdef HAVE_LIBPTHREAD
        struct timespec  ts;
# endif
        lnet_ni_t       *eqwaitni = the_lnet.ln_eqwaitni;
#endif
        ENTRY;

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);

        if (neq < 1)
                RETURN(-ENOENT);

        LNET_LOCK();

        for (;;) {
                for (i = 0; i < neq; i++) {
                        lnet_eq_t *eq = lnet_handle2eq(&eventqs[i]);

                        if (eq == NULL) {
                                LNET_UNLOCK();
                                RETURN(-ENOENT);
                        }

                        rc = lib_get_event (eq, event);
                        if (rc != 0) {
                                LNET_UNLOCK();
                                *which = i;
                                RETURN(rc);
                        }
                }

#ifdef __KERNEL__
                if (timeout_ms == 0) {
                        LNET_UNLOCK();
                        RETURN (0);
                }

                cfs_waitlink_init(&wl);
                set_current_state(TASK_INTERRUPTIBLE);
                cfs_waitq_add(&the_lnet.ln_waitq, &wl);

                LNET_UNLOCK();

                if (timeout_ms < 0) {
                        cfs_waitq_wait (&wl, CFS_TASK_INTERRUPTIBLE);
                } else {
                        struct timeval tv;

                        now = cfs_time_current();
                        cfs_waitq_timedwait(&wl, CFS_TASK_INTERRUPTIBLE,
                                            cfs_time_seconds(timeout_ms)/1000);
                        cfs_duration_usec(cfs_time_sub(cfs_time_current(), now),
                                          &tv);
                        timeout_ms -= tv.tv_sec * 1000 + tv.tv_usec / 1000;
                        if (timeout_ms < 0)
                                timeout_ms = 0;
                }

                LNET_LOCK();
                cfs_waitq_del(&the_lnet.ln_waitq, &wl);
#else
                if (eqwaitni != NULL) {
                        /* I have a single NI that I have to call into, to get
                         * events queued, or to block. */
                        lnet_ni_addref_locked(eqwaitni);
                        LNET_UNLOCK();

                        if (timeout_ms <= 0) {
                                (eqwaitni->ni_lnd->lnd_wait)(eqwaitni, timeout_ms);
                        } else {
                                gettimeofday(&then, NULL);

                                (eqwaitni->ni_lnd->lnd_wait)(eqwaitni, timeout_ms);

                                gettimeofday(&now, NULL);
                                timeout_ms -= (now.tv_sec - then.tv_sec) * 1000 +
                                              (now.tv_usec - then.tv_usec) / 1000;
                                if (timeout_ms < 0)
                                        timeout_ms = 0;
                        }

                        LNET_LOCK();
                        lnet_ni_decref_locked(eqwaitni);

                        /* don't call into eqwaitni again if timeout has
                         * expired */
                        if (timeout_ms == 0)
                                eqwaitni = NULL;

                        continue;               /* go back and check for events */
                }

                if (timeout_ms == 0) {
                        LNET_UNLOCK();
                        RETURN (0);
                }

# ifndef HAVE_LIBPTHREAD
                /* If I'm single-threaded, LNET fails at startup if it can't
                 * set the_lnet.ln_eqwaitni correctly.  */
                LBUG();
# else
                if (timeout_ms < 0) {
                        pthread_cond_wait(&the_lnet.ln_cond,
                                          &the_lnet.ln_lock);
                } else {
                        gettimeofday(&then, NULL);

                        ts.tv_sec = then.tv_sec + timeout_ms/1000;
                        ts.tv_nsec = then.tv_usec * 1000 +
                                     (timeout_ms%1000) * 1000000;
                        if (ts.tv_nsec >= 1000000000) {
                                ts.tv_sec++;
                                ts.tv_nsec -= 1000000000;
                        }

                        pthread_cond_timedwait(&the_lnet.ln_cond,
                                               &the_lnet.ln_lock, &ts);

                        gettimeofday(&now, NULL);
                        timeout_ms -= (now.tv_sec - then.tv_sec) * 1000 +
                                      (now.tv_usec - then.tv_usec) / 1000;

                        if (timeout_ms < 0)
                                timeout_ms = 0;
                }
# endif
#endif
        }
}
