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
lib_enq_event_locked (lib_nal_t *nal, void *private, 
                      lib_eq_t *eq, ptl_event_t *ev)
{
        ptl_event_t  *eq_slot;

        /* Allocate the next queue slot */
        ev->link = ev->sequence = eq->eq_enq_seq++;
        /* NB we don't support START events yet and we don't create a separate
         * UNLINK event unless an explicit unlink succeeds, so the link
         * sequence is pretty useless */

        /* We don't support different uid/jids yet */
        ev->uid = 0;
        ev->jid = 0;
        
        /* size must be a power of 2 to handle sequence # overflow */
        LASSERT (eq->eq_size != 0 &&
                 eq->eq_size == LOWEST_BIT_SET (eq->eq_size));
        eq_slot = eq->eq_events + (ev->sequence & (eq->eq_size - 1));

        /* There is no race since both event consumers and event producers
         * take the LIB_LOCK(), so we don't screw around with memory
         * barriers, setting the sequence number last or wierd structure
         * layout assertions. */
        *eq_slot = *ev;

        /* Call the callback handler (if any) */
        if (eq->eq_callback != NULL)
                eq->eq_callback (eq_slot);

        /* Wake anyone sleeping for an event (see lib-eq.c) */
#ifdef __KERNEL__
        if (waitqueue_active(&nal->libnal_ni.ni_waitq))
                wake_up_all(&nal->libnal_ni.ni_waitq);
#else
        pthread_cond_broadcast(&nal->libnal_ni.ni_cond);
#endif
}

void 
lib_finalize (lib_nal_t *nal, void *private, lib_msg_t *msg, ptl_err_t status)
{
        lib_md_t     *md;
        int           unlink;
        unsigned long flags;
        int           rc;
        ptl_hdr_t     ack;

        if (msg == NULL)
                return;

        /* Only send an ACK if the PUT completed successfully */
        if (status == PTL_OK &&
            !ptl_is_wire_handle_none(&msg->ack_wmd)) {

                LASSERT(msg->ev.type == PTL_EVENT_PUT_END);

                memset (&ack, 0, sizeof (ack));
                ack.type     = HTON__u32 (PTL_MSG_ACK);
                ack.dest_nid = HTON__u64 (msg->ev.initiator.nid);
                ack.dest_pid = HTON__u32 (msg->ev.initiator.pid);
                ack.src_nid  = HTON__u64 (nal->libnal_ni.ni_pid.nid);
                ack.src_pid  = HTON__u32 (nal->libnal_ni.ni_pid.pid);
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

        LIB_LOCK(nal, flags);

        /* Now it's safe to drop my caller's ref */
        md->pending--;
        LASSERT (md->pending >= 0);

        /* Should I unlink this MD? */
        if (md->pending != 0)                   /* other refs */
                unlink = 0;
        else if ((md->md_flags & PTL_MD_FLAG_ZOMBIE) != 0)
                unlink = 1;
        else if ((md->md_flags & PTL_MD_FLAG_AUTO_UNLINK) == 0)
                unlink = 0;
        else
                unlink = lib_md_exhausted(md);

        msg->ev.ni_fail_type = status;
        msg->ev.unlinked = unlink;

        if (md->eq != NULL)
                lib_enq_event_locked(nal, private, md->eq, &msg->ev);

        if (unlink)
                lib_md_unlink(nal, md);

        list_del (&msg->msg_list);
        nal->libnal_ni.ni_counters.msgs_alloc--;
        lib_msg_free(nal, msg);

        LIB_UNLOCK(nal, flags);
}
