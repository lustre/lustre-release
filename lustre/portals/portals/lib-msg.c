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

int lib_finalize(nal_cb_t * nal, void *private, lib_msg_t *msg)
{
        lib_md_t     *md;
        lib_eq_t     *eq;
        int           rc;
        unsigned long flags;

        /* ni went down while processing this message */
        if (nal->ni.up == 0) {
                return -1;
        }

        if (msg == NULL)
                return 0;

        rc = 0;
        if (msg->send_ack) {
                ptl_hdr_t ack;

                LASSERT (!ptl_is_wire_handle_none (&msg->ack_wmd));

                memset (&ack, 0, sizeof (ack));
                ack.type     = HTON__u32 (PTL_MSG_ACK);
                ack.dest_nid = HTON__u64 (msg->nid);
                ack.src_nid  = HTON__u64 (nal->ni.nid);
                ack.dest_pid = HTON__u32 (msg->pid);
                ack.src_pid  = HTON__u32 (nal->ni.pid);
                PTL_HDR_LENGTH(&ack) = 0;

                ack.msg.ack.dst_wmd = msg->ack_wmd;
                ack.msg.ack.match_bits = msg->ev.match_bits;
                ack.msg.ack.mlength = HTON__u32 (msg->ev.mlength);

                rc = lib_send (nal, private, NULL, &ack, PTL_MSG_ACK,
                               msg->nid, msg->pid, NULL, 0, 0);
        }

        md = msg->md;
        LASSERT (md->pending > 0);  /* I've not dropped my ref yet */
        eq = md->eq;

        state_lock(nal, &flags);

        if (eq != NULL) {
                ptl_event_t  *ev = &msg->ev;
                ptl_event_t  *eq_slot;

                /* I have to hold the lock while I bump the sequence number
                 * and copy the event into the queue.  If not, and I was
                 * interrupted after bumping the sequence number, other
                 * events could fill the queue, including the slot I just
                 * allocated to this event.  On resuming, I would overwrite
                 * a more 'recent' event with old event state, and
                 * processes taking events off the queue would not detect
                 * overflow correctly.
                 */

                ev->sequence = eq->sequence++;/* Allocate the next queue slot */

                /* size must be a power of 2 to handle a wrapped sequence # */
                LASSERT (eq->size != 0 &&
                         eq->size == LOWEST_BIT_SET (eq->size));
                eq_slot = eq->base + (ev->sequence & (eq->size - 1));

                /* Invalidate unlinked_me unless this is the last
                 * event for an auto-unlinked MD.  Note that if md was
                 * auto-unlinked, md->pending can only decrease
                 */
                if ((md->md_flags & PTL_MD_FLAG_AUTO_UNLINKED) == 0 || /* not auto-unlinked */
                    md->pending != 1)                       /* not last ref */
                        ev->unlinked_me = PTL_HANDLE_NONE;

                /* Copy the event into the allocated slot, ensuring all the
                 * rest of the event's contents have been copied _before_
                 * the sequence number gets updated.  A processes 'getting'
                 * an event waits on the next queue slot's sequence to be
                 * 'new'.  When it is, _all_ other event fields had better
                 * be consistent.  I assert 'sequence' is the last member,
                 * so I only need a 2 stage copy.
                 */
                LASSERT(sizeof (ptl_event_t) ==
                        offsetof(ptl_event_t, sequence) + sizeof(ev->sequence));

                rc = nal->cb_write (nal, private, (user_ptr)eq_slot, ev,
                                    offsetof (ptl_event_t, sequence));
                LASSERT (rc == 0);

#ifdef __KERNEL__
                barrier();
#endif
                /* Updating the sequence number is what makes the event 'new' */

                /* cb_write is not necessarily atomic, so this could
                   cause a race with PtlEQGet */
                rc = nal->cb_write(nal, private, (user_ptr)&eq_slot->sequence,
                                   (void *)&ev->sequence,sizeof (ev->sequence));
                LASSERT (rc == 0);

#ifdef __KERNEL__
                barrier();
#endif

                /* I must also ensure that (a) callbacks are made in the
                 * same order as the events land in the queue, and (b) the
                 * callback occurs before the event can be removed from the
                 * queue, so I can't drop the lock during the callback. */
                if (nal->cb_callback != NULL)
                        nal->cb_callback(nal, private, eq, ev);
                else  if (eq->event_callback != NULL)
                        (void)((eq->event_callback) (ev));
        }

        LASSERT ((md->md_flags & PTL_MD_FLAG_AUTO_UNLINKED) == 0 ||
                 (md->md_flags & PTL_MD_FLAG_UNLINK) != 0);

        md->pending--;
        if (md->pending == 0 && /* no more outstanding operations on this md */
            (md->threshold == 0 ||              /* done its business */
             (md->md_flags & PTL_MD_FLAG_UNLINK) != 0)) /* marked for death */
                lib_md_unlink(nal, md);

        list_del (&msg->msg_list);
        nal->ni.counters.msgs_alloc--;
        lib_msg_free(nal, msg);

        state_unlock(nal, &flags);

        return rc;
}
