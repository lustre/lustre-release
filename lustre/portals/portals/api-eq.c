/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * api/api-eq.c
 * User-level event queue management routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *  Copyright (c) 2001-2002 Sandia National Laboratories
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2.1 of the GNU Lesser General
 *   Public License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * PtlMDUpdate is here so that it can access the per-eventq
 * structures.
 */

#include <portals/api-support.h>

int ptl_eq_init(void)
{
        /* Nothing to do anymore... */
        return PTL_OK;
}

void ptl_eq_fini(void)
{
        /* Nothing to do anymore... */
}

int ptl_eq_ni_init(nal_t * nal)
{
        /* Nothing to do anymore... */
        return PTL_OK;
}

void ptl_eq_ni_fini(nal_t * nal)
{
        /* Nothing to do anymore... */
}

int PtlEQGet(ptl_handle_eq_t eventq, ptl_event_t * ev)
{
        ptl_eq_t *eq;
        int rc, new_index;
        unsigned long flags;
        ptl_event_t *new_event;
        nal_t *nal;
        ENTRY;

        if (!ptl_init)
                RETURN(PTL_NOINIT);

        nal = ptl_hndl2nal(&eventq);
        if (!nal)
                RETURN(PTL_INV_EQ);

        eq = ptl_handle2usereq(&eventq);
        nal->lock(nal, &flags);

        /* size must be a power of 2 to handle a wrapped sequence # */
        LASSERT (eq->size != 0 &&
                 eq->size == LOWEST_BIT_SET (eq->size));

        new_index = eq->sequence & (eq->size - 1);
        new_event = &eq->base[new_index];
        CDEBUG(D_INFO, "new_event: %p, sequence: %lu, eq->size: %u\n",
               new_event, eq->sequence, eq->size);
        if (PTL_SEQ_GT (eq->sequence, new_event->sequence)) {
                nal->unlock(nal, &flags);
                RETURN(PTL_EQ_EMPTY);
        }

        *ev = *new_event;

        /* Set the unlinked_me interface number if there is one to pass
         * back, since the NAL hasn't a clue what it is and therefore can't
         * set it. */
        if (!PtlHandleEqual (ev->unlinked_me, PTL_HANDLE_NONE))
                ev->unlinked_me.nal_idx = eventq.nal_idx;
        
        /* ensure event is delivered correctly despite possible 
           races with lib_finalize */
        if (eq->sequence != new_event->sequence) {
                CERROR("DROPPING EVENT: eq seq %lu ev seq %lu\n",
                       eq->sequence, new_event->sequence);
                rc = PTL_EQ_DROPPED;
        } else {
                rc = PTL_OK;
        }

        eq->sequence = new_event->sequence + 1;
        nal->unlock(nal, &flags);
        RETURN(rc);
}


int PtlEQWait(ptl_handle_eq_t eventq_in, ptl_event_t *event_out)
{
        int rc;
        
        /* PtlEQGet does the handle checking */
        while ((rc = PtlEQGet(eventq_in, event_out)) == PTL_EQ_EMPTY) {
                nal_t *nal = ptl_hndl2nal(&eventq_in);
                
                if (nal->yield)
                        nal->yield(nal);
        }

        return rc;
}

#ifndef __KERNEL__
static jmp_buf eq_jumpbuf;

static void eq_timeout(int signal)
{
        longjmp(eq_jumpbuf, -1);
}

int PtlEQWait_timeout(ptl_handle_eq_t eventq_in, ptl_event_t * event_out,
                      int timeout)
{
        static void (*prev) (int);
        static int left_over;
        time_t time_at_start;
        int rc;

        if (setjmp(eq_jumpbuf)) {
                signal(SIGALRM, prev);
                alarm(left_over - timeout);
                return PTL_EQ_EMPTY;
        }

        left_over = alarm(timeout);
        prev = signal(SIGALRM, eq_timeout);
        time_at_start = time(NULL);
        if (left_over < timeout)
                alarm(left_over);

        rc = PtlEQWait(eventq_in, event_out);

        signal(SIGALRM, prev);
        alarm(left_over);       /* Should compute how long we waited */

        return rc;
}

#endif

