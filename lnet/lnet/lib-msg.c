/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-msg.c
 * Message decoding, parsing and finalizing routines
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

#ifndef __KERNEL__
# include <stdio.h>
#else
# define DEBUG_SUBSYSTEM S_PORTALS
# include <linux/kp30.h>
#endif

#include <portals/lib-p30.h>

void
lib_enq_event_locked (nal_cb_t *nal, void *private, 
                      lib_eq_t *eq, ptl_event_t *ev)
{
        ptl_event_t  *eq_slot;
        int           rc;
        
        ev->sequence = eq->sequence++; /* Allocate the next queue slot */

        /* size must be a power of 2 to handle a wrapped sequence # */
        LASSERT (eq->size != 0 &&
                 eq->size == LOWEST_BIT_SET (eq->size));
        eq_slot = eq->base + (ev->sequence & (eq->size - 1));

        /* Copy the event into the allocated slot, ensuring all the rest of
         * the event's contents have been copied _before_ the sequence
         * number gets updated.  A processes 'getting' an event waits on
         * the next queue slot's sequence to be 'new'.  When it is, _all_
         * other event fields had better be consistent.  I assert
         * 'sequence' is the last member, so I only need a 2 stage copy. */

        LASSERT(sizeof (ptl_event_t) ==
                offsetof(ptl_event_t, sequence) + sizeof(ev->sequence));

        rc = nal->cb_write (nal, private, (user_ptr)eq_slot, ev,
                            offsetof (ptl_event_t, sequence));
        LASSERT (rc == PTL_OK);

#ifdef __KERNEL__
        barrier();
#endif
        /* Updating the sequence number is what makes the event 'new' NB if
         * the cb_write below isn't atomic, this could cause a race with
         * PtlEQGet */
        rc = nal->cb_write(nal, private, (user_ptr)&eq_slot->sequence,
                           (void *)&ev->sequence,sizeof (ev->sequence));
        LASSERT (rc == PTL_OK);

#ifdef __KERNEL__
        barrier();
#endif

        if (nal->cb_callback != NULL)
                nal->cb_callback(nal, private, eq, ev);
        else if (eq->event_callback != NULL)
                eq->event_callback(ev);
}

void 
lib_finalize(nal_cb_t *nal, void *private, lib_msg_t *msg, ptl_err_t status)
{
        lib_md_t     *md;
        int           unlink;
        unsigned long flags;
        int           rc;
        ptl_hdr_t     ack;

        /* ni went down while processing this message */
        if (nal->ni.up == 0)
                return;

        if (msg == NULL)
                return;

        /* Only send an ACK if the PUT completed successfully */
        if (status == PTL_OK &&
            !ptl_is_wire_handle_none(&msg->ack_wmd)) {

                LASSERT(msg->ev.type == PTL_EVENT_PUT);

                memset (&ack, 0, sizeof (ack));
                ack.type     = HTON__u32 (PTL_MSG_ACK);
                ack.dest_nid = HTON__u64 (msg->ev.initiator.nid);
                ack.src_nid  = HTON__u64 (nal->ni.nid);
                ack.dest_pid = HTON__u32 (msg->ev.initiator.pid);
                ack.src_pid  = HTON__u32 (nal->ni.pid);
                ack.payload_length = 0;

                ack.msg.ack.dst_wmd = msg->ack_wmd;
                ack.msg.ack.match_bits = msg->ev.match_bits;
                ack.msg.ack.mlength = HTON__u32 (msg->ev.mlength);

                rc = lib_send (nal, private, NULL, &ack, PTL_MSG_ACK,
                               msg->ev.initiator.nid, msg->ev.initiator.pid, 
                               NULL, 0, 0);
                if (rc != PTL_OK) {
                        /* send failed: there's nothing else to clean up. */
                        CERROR("Error %d sending ACK to "LPX64"\n", 
                               rc, msg->ev.initiator.nid);
                }
        }

        md = msg->md;

        state_lock(nal, &flags);

        /* Now it's safe to drop my caller's ref */
        md->pending--;
        LASSERT (md->pending >= 0);

        /* Should I unlink this MD? */
        unlink = (md->pending == 0 &&           /* No other refs */
                  (md->threshold == 0 ||        /* All ops done */
                   md->md_flags & PTL_MD_FLAG_UNLINK) != 0); /* black spot */

        msg->ev.status = status;
        msg->ev.unlinked = unlink;

        if (md->eq != NULL)
                lib_enq_event_locked(nal, private, md->eq, &msg->ev);

        if (unlink)
                lib_md_unlink(nal, md);

        list_del (&msg->msg_list);
        nal->ni.counters.msgs_alloc--;
        lib_msg_free(nal, msg);

        state_unlock(nal, &flags);
}
