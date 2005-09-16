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

#include <lnet/lib-lnet.h>

void
lnet_enq_event_locked (void *private, lnet_eq_t *eq, lnet_event_t *ev)
{
        lnet_event_t  *eq_slot;

        /* Allocate the next queue slot */
        ev->link = ev->sequence = eq->eq_enq_seq++;
        /* NB we don't support START events yet and we don't create a separate
         * UNLINK event unless an explicit unlink succeeds, so the link
         * sequence is pretty useless */

        /* size must be a power of 2 to handle sequence # overflow */
        LASSERT (eq->eq_size != 0 &&
                 eq->eq_size == LOWEST_BIT_SET (eq->eq_size));
        eq_slot = eq->eq_events + (ev->sequence & (eq->eq_size - 1));

        /* There is no race since both event consumers and event producers
         * take the LNET_LOCK, so we don't screw around with memory
         * barriers, setting the sequence number last or wierd structure
         * layout assertions. */
        *eq_slot = *ev;

        /* Call the callback handler (if any) */
        if (eq->eq_callback != NULL)
                eq->eq_callback (eq_slot);

        /* Wake anyone sleeping for an event (see lib-eq.c) */
#ifdef __KERNEL__
        if (cfs_waitq_active(&the_lnet.ln_waitq))
                cfs_waitq_broadcast(&the_lnet.ln_waitq);
#else
        pthread_cond_broadcast(&the_lnet.ln_cond);
#endif
}

void
lnet_finalize (lnet_ni_t *ni, void *private, lnet_msg_t *msg, int status)
{
        lnet_libmd_t *md;
        int           unlink;
        unsigned long flags;
        int           rc;
        int           send_ack;

        if (msg == NULL)
                return;

        LNET_LOCK(flags);

        md = msg->msg_md;
        if (md != NULL) {
                /* Now it's safe to drop my caller's ref */
                md->md_pending--;
                LASSERT (md->md_pending >= 0);

                /* Should I unlink this MD? */
                if (md->md_pending != 0)        /* other refs */
                        unlink = 0;
                else if ((md->md_flags & LNET_MD_FLAG_ZOMBIE) != 0)
                        unlink = 1;
                else if ((md->md_flags & LNET_MD_FLAG_AUTO_UNLINK) == 0)
                        unlink = 0;
                else
                        unlink = lnet_md_exhausted(md);
                
                msg->msg_ev.status = status;
                msg->msg_ev.unlinked = unlink;
                
                if (md->md_eq != NULL)
                        lnet_enq_event_locked(private, md->md_eq, &msg->msg_ev);
                
                if (unlink)
                        lnet_md_unlink(md);

                msg->msg_md = NULL;
        }
        
        /* Only send an ACK if the PUT completed successfully */
        send_ack = (status == 0 &&
                    !lnet_is_wire_handle_none(&msg->msg_ack_wmd));

        if (!send_ack) {
                list_del (&msg->msg_activelist);
                the_lnet.ln_counters.msgs_alloc--;
                lnet_msg_free(msg);

                LNET_UNLOCK(flags);
                return;
        }
                
        LNET_UNLOCK(flags);

        LASSERT(msg->msg_ev.type == LNET_EVENT_PUT);

        memset (&msg->msg_hdr, 0, sizeof(msg->msg_hdr));
        msg->msg_hdr.msg.ack.dst_wmd = msg->msg_ack_wmd;
        msg->msg_hdr.msg.ack.match_bits = msg->msg_ev.match_bits;
        msg->msg_hdr.msg.ack.mlength = cpu_to_le32(msg->msg_ev.mlength);

        msg->msg_ack_wmd = LNET_WIRE_HANDLE_NONE;

        rc = lnet_send(ni, private, msg, LNET_MSG_ACK,
                       msg->msg_ev.initiator, NULL, 0, 0);
        if (rc != 0) {
                /* send failed: there's nothing else to clean up. */
                CERROR("Error %d sending ACK to %s\n",
                       rc, libcfs_id2str(msg->msg_ev.initiator));

                LNET_LOCK(flags);
                list_del (&msg->msg_activelist);
                the_lnet.ln_counters.msgs_alloc--;
                lnet_msg_free(msg);
                LNET_UNLOCK(flags);
        }
}
