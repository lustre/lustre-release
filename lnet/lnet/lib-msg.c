/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-msg.c
 * Message decoding, parsing and finalizing routines
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

#include <lnet/lib-p30.h>

void
ptl_enq_event_locked (void *private, ptl_eq_t *eq, lnet_event_t *ev)
{
        lnet_event_t  *eq_slot;

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
         * take the PTL_LOCK, so we don't screw around with memory
         * barriers, setting the sequence number last or wierd structure
         * layout assertions. */
        *eq_slot = *ev;

        /* Call the callback handler (if any) */
        if (eq->eq_callback != NULL)
                eq->eq_callback (eq_slot);

        /* Wake anyone sleeping for an event (see lib-eq.c) */
#ifdef __KERNEL__
        if (cfs_waitq_active(&ptl_apini.apini_waitq))
                cfs_waitq_broadcast(&ptl_apini.apini_waitq);
#else
        pthread_cond_broadcast(&ptl_apini.apini_cond);
#endif
}

void
ptl_finalize (ptl_ni_t *ni, void *private, ptl_msg_t *msg, int status)
{
        ptl_libmd_t  *md;
        int           unlink;
        unsigned long flags;
        int           rc;
        ptl_hdr_t     ack;

        if (msg == NULL)
                return;

        /* Only send an ACK if the PUT completed successfully */
        if (status == 0 &&
            !ptl_is_wire_handle_none(&msg->msg_ack_wmd)) {

                LASSERT(msg->msg_ev.type == LNET_EVENT_PUT);

                memset (&ack, 0, sizeof (ack));
                ack.msg.ack.dst_wmd = msg->msg_ack_wmd;
                ack.msg.ack.match_bits = msg->msg_ev.match_bits;
                ack.msg.ack.mlength = cpu_to_le32(msg->msg_ev.mlength);

                rc = ptl_send (ni, private, NULL, &ack, PTL_MSG_ACK,
                               msg->msg_ev.initiator, NULL, 0, 0);
                if (rc != 0) {
                        /* send failed: there's nothing else to clean up. */
                        CERROR("Error %d sending ACK to "LPX64"\n",
                               rc, msg->msg_ev.initiator.nid);
                }
        }

        md = msg->msg_md;

        PTL_LOCK(flags);

        /* Now it's safe to drop my caller's ref */
        md->md_pending--;
        LASSERT (md->md_pending >= 0);

        /* Should I unlink this MD? */
        if (md->md_pending != 0)                   /* other refs */
                unlink = 0;
        else if ((md->md_flags & PTL_MD_FLAG_ZOMBIE) != 0)
                unlink = 1;
        else if ((md->md_flags & PTL_MD_FLAG_AUTO_UNLINK) == 0)
                unlink = 0;
        else
                unlink = ptl_md_exhausted(md);

        msg->msg_ev.ni_fail_type = status;
        msg->msg_ev.unlinked = unlink;

        if (md->md_eq != NULL)
                ptl_enq_event_locked(private, md->md_eq, &msg->msg_ev);

        if (unlink)
                ptl_md_unlink(md);

        list_del (&msg->msg_list);
        ptl_apini.apini_counters.msgs_alloc--;
        ptl_msg_free(msg);

        PTL_UNLOCK(flags);
}

lnet_pid_t  ptl_getpid(void) 
{
        return ptl_apini.apini_pid;
}
