/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
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

#include <lnet/lib-lnet.h>

int
lolnd_send (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
        int rc;

        LASSERT (!lntmsg->msg_routing);
        LASSERT (!lntmsg->msg_target_is_router);

        rc = lnet_parse(ni, &lntmsg->msg_hdr, ni->ni_nid, lntmsg);
        if (rc >= 0)
                lnet_finalize(ni, lntmsg, 0);
        
        return rc;
}

int
lolnd_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
            int delayed, unsigned int niov, 
            struct iovec *iov, lnet_kiov_t *kiov,
            unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        lnet_msg_t *sendmsg = private;

        LASSERT (!delayed);

        if (lntmsg == NULL)                     /* discarding */
                return 0;

        if (sendmsg->msg_iov != NULL) {
                if (iov != NULL)
                        lnet_copy_iov2iov(niov, iov, offset,
                                          sendmsg->msg_niov, sendmsg->msg_iov,
                                          sendmsg->msg_offset, mlen);
                else
                        lnet_copy_iov2kiov(niov, kiov, offset,
                                           sendmsg->msg_niov, sendmsg->msg_iov,
                                           sendmsg->msg_offset, mlen);
        } else {
                if (iov != NULL)
                        lnet_copy_kiov2iov(niov, iov, offset,
                                           sendmsg->msg_niov, sendmsg->msg_kiov,
                                           sendmsg->msg_offset, mlen);
                else
                        lnet_copy_kiov2kiov(niov, kiov, offset,
                                            sendmsg->msg_niov, sendmsg->msg_kiov,
                                            sendmsg->msg_offset, mlen);
        }

        lnet_finalize(ni, lntmsg, 0);
        return 0;
}

static int lolnd_instanced;

void
lolnd_shutdown(lnet_ni_t *ni)
{
	CDEBUG (D_NET, "shutdown\n");
        LASSERT (lolnd_instanced);
        
        lolnd_instanced = 0;
}

int
lolnd_startup (lnet_ni_t *ni)
{
	LASSERT (ni->ni_lnd == &the_lolnd);
	LASSERT (!lolnd_instanced);
        lolnd_instanced = 1;

	return (0);
}

lnd_t the_lolnd = {
        .lnd_type       = LOLND,
        .lnd_startup    = lolnd_startup,
        .lnd_shutdown   = lolnd_shutdown,
        .lnd_send       = lolnd_send,
        .lnd_recv       = lolnd_recv,
};

