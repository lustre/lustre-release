/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * api/api-eq.c
 * User-level event queue management routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *  Copyright (c) 2001-2002 Sandia National Laboratories
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
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

#include <portals/api-support.h>

int ptl_get_event (ptl_eq_t *eq, ptl_event_t *ev)
{
        int          new_index = eq->sequence & (eq->size - 1);
        ptl_event_t *new_event = &eq->base[new_index];
        ENTRY;

        CDEBUG(D_INFO, "new_event: %p, sequence: %lu, eq->size: %u\n",
               new_event, eq->sequence, eq->size);

        if (PTL_SEQ_GT (eq->sequence, new_event->sequence)) {
                RETURN(PTL_EQ_EMPTY);
        }

        *ev = *new_event;

        /* ensure event is delivered correctly despite possible 
           races with lib_finalize */
        if (eq->sequence != new_event->sequence) {
                CERROR("DROPPING EVENT: eq seq %lu ev seq %lu\n",
                       eq->sequence, new_event->sequence);
                RETURN(PTL_EQ_DROPPED);
        }

        eq->sequence = new_event->sequence + 1;
        RETURN(PTL_OK);
}

int PtlEQGet(ptl_handle_eq_t eventq, ptl_event_t * ev)
{
        int which;
        
        return (PtlEQPoll (&eventq, 1, 0, ev, &which));
}

int PtlEQWait(ptl_handle_eq_t eventq_in, ptl_event_t *event_out)
{
        int which;
        
        return (PtlEQPoll (&eventq_in, 1, PTL_TIME_FOREVER, 
                           event_out, &which));
}

int PtlEQPoll(ptl_handle_eq_t *eventqs_in, int neq_in, int timeout,
              ptl_event_t *event_out, int *which_out)
{
        nal_t        *nal;
        int           i;
        int           rc;
        unsigned long flags;
        
        if (!ptl_init)
                RETURN(PTL_NO_INIT);

        if (neq_in < 1)
                RETURN(PTL_EQ_INVALID);
        
        nal = ptl_hndl2nal(&eventqs_in[0]);
        if (nal == NULL)
                RETURN(PTL_EQ_INVALID);

        nal->lock(nal, &flags);

        for (;;) {
                for (i = 0; i < neq_in; i++) {
                        ptl_eq_t *eq = ptl_handle2usereq(&eventqs_in[i]);

                        if (i > 0 &&
                            ptl_hndl2nal(&eventqs_in[i]) != nal) {
                                nal->unlock(nal, &flags);
                                RETURN (PTL_EQ_INVALID);
                        }

                        /* size must be a power of 2 to handle a wrapped sequence # */
                        LASSERT (eq->size != 0 &&
                                 eq->size == LOWEST_BIT_SET (eq->size));

                        rc = ptl_get_event (eq, event_out);
                        if (rc != PTL_EQ_EMPTY) {
                                nal->unlock(nal, &flags);
                                *which_out = i;
                                RETURN(rc);
                        }
                }
                
                if (timeout == 0) {
                        nal->unlock(nal, &flags);
                        RETURN (PTL_EQ_EMPTY);
                }
                        
                timeout = nal->yield(nal, &flags, timeout);
        }
}
