/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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

/* tcpnal.c:
   This file implements the TCP-based nal by providing glue
   between the connection service and the generic NAL implementation */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pqtimer.h>
#include <dispatch.h>
#include <procbridge.h>
#include <connection.h>
#include <errno.h>

#ifndef __CYGWIN__
#include <syscall.h>
#endif

void
tcpnal_notify(lnet_ni_t *ni, lnet_nid_t nid, int alive)
{
        bridge     b = (bridge)ni->ni_data;
        connection c;

        if (!alive) {
                LBUG();
        }

        c = force_tcp_connection((manager)b->lower, nid, b->local);
        if (c == NULL)
                CERROR("Can't create connection to %s\n",
                       libcfs_nid2str(nid));
}

/*
 * sends a packet to the peer, after insuring that a connection exists
 */
int tcpnal_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
        lnet_hdr_t        *hdr = &lntmsg->msg_hdr;
        lnet_process_id_t  target = lntmsg->msg_target;
        unsigned int       niov = lntmsg->msg_niov;
        struct iovec      *iov = lntmsg->msg_iov;
        unsigned int       offset = lntmsg->msg_offset;
        unsigned int       len = lntmsg->msg_len;

        connection c;
        bridge b = (bridge)ni->ni_data;
        struct iovec tiov[257];
        static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
        int rc = 0;
        int   sysrc;
        int   total;
        int   ntiov;
        int i;

        if (!(c = force_tcp_connection((manager)b->lower, target.nid,
                                       b->local)))
                return(-EIO);

        /* TODO: these results should be checked. furthermore, provision
           must be made for the SIGPIPE which is delivered when
           writing on a tcp socket which has closed underneath
           the application. there is a linux flag in the sendmsg
           call which turns off the signally behaviour, but its
           nonstandard */

        LASSERT (niov <= 256);
        LASSERT (len == 0 || iov != NULL);      /* I don't understand kiovs */

        tiov[0].iov_base = hdr;
        tiov[0].iov_len = sizeof(lnet_hdr_t);
        ntiov = 1 + lnet_extract_iov(256, &tiov[1], niov, iov, offset, len);

        pthread_mutex_lock(&send_lock);
#if 1
        for (i = total = 0; i < ntiov; i++)
                total += tiov[i].iov_len;

        sysrc = syscall(SYS_writev, c->fd, tiov, ntiov);
        if (sysrc != total) {
                fprintf (stderr, "BAD SEND rc %d != %d, errno %d\n",
                         rc, total, errno);
                rc = -errno;
        }
#else
        for (i = total = 0; i <= ntiov; i++) {
                rc = send(c->fd, tiov[i].iov_base, tiov[i].iov_len, 0);

                if (rc != tiov[i].iov_len) {
                        fprintf (stderr, "BAD SEND rc %d != %d, errno %d\n",
                                 rc, tiov[i].iov_len, errno);
                        rc = -errno;
                        break;
                }
                total += rc;
        }
#endif
#if 0
        fprintf (stderr, "sent %s total %d in %d frags\n",
                 hdr->type == LNET_MSG_ACK ? "ACK" :
                 hdr->type == LNET_MSG_PUT ? "PUT" :
                 hdr->type == LNET_MSG_GET ? "GET" :
                 hdr->type == LNET_MSG_REPLY ? "REPLY" :
                 hdr->type == LNET_MSG_HELLO ? "HELLO" : "UNKNOWN",
                 total, niov + 1);
#endif
        pthread_mutex_unlock(&send_lock);

        if (rc == 0) {
                /* NB the NAL only calls lnet_finalize() if it returns 0
                 * from cb_send() */
                lnet_finalize(ni, lntmsg, 0);
        }

        return(rc);
}


int tcpnal_recv(lnet_ni_t     *ni,
                void         *private,
                lnet_msg_t   *cookie,
                int           delayed,
                unsigned int  niov,
                struct iovec *iov,
                lnet_kiov_t  *kiov,
                unsigned int  offset,
                unsigned int  mlen,
                unsigned int  rlen)
{
        struct iovec tiov[256];
        int ntiov;
        int i;

        if (mlen == 0)
                goto finalize;

        LASSERT(iov != NULL);           /* I don't understand kiovs */

        ntiov = lnet_extract_iov(256, tiov, niov, iov, offset, mlen);

        /* FIXME
         * 1. Is this effecient enough? change to use readv() directly?
         * - MeiJia
         */
        for (i = 0; i < ntiov; i++)
                if (!read_connection(private, tiov[i].iov_base, tiov[i].iov_len))
                        return -EIO;
                        

finalize:
        LASSERT(rlen >= mlen);

        if (mlen != rlen){
                int rc;
                char *trash=malloc(rlen - mlen);

                if (!trash)
                        return -ENOMEM;
                
                rc = read_connection(private, trash, rlen - mlen);
                free(trash);
                if (!rc)
                        return -EIO;
        }

        lnet_finalize(ni, cookie, 0);
        return(0);
}


/* Function:  from_connection:
 * Arguments: c: the connection to read from
 * Returns: whether or not to continue reading from this connection,
 *          expressed as a 1 to continue, and a 0 to not
 *
 *  from_connection() is called from the select loop when i/o is
 *  available. It attempts to read the portals header and
 *  pass it to the generic library for processing.
 */
static int from_connection(void *a, void *d)
{
        connection c = d;
        bridge     b = a;
        lnet_hdr_t hdr;
        int  rc;

        if (read_connection(c, (unsigned char *)&hdr, sizeof(hdr))) {
                /* replace dest_nid,pid (socknal sets its own) */
                hdr.dest_nid = cpu_to_le64(b->b_ni->ni_nid);
                hdr.dest_pid = cpu_to_le32(the_lnet.ln_pid);

                rc = lnet_parse(b->b_ni, &hdr, c->peer_nid, c, 0);
                if (rc < 0) {
                        CERROR("Error %d from lnet_parse\n", rc);
                        return 0;
                }

                return(1);
        }
        return(0);
}


void tcpnal_shutdown(bridge b)
{
        shutdown_connections(b->lower);
}

/* Function:  PTL_IFACE_TCP
 * Arguments: pid_request: desired port number to bind to
 *            desired: passed NAL limits structure
 *            actual: returned NAL limits structure
 * Returns: a nal structure on success, or null on failure
 */
int tcpnal_init(bridge b)
{
        manager m;

        tcpnal_set_global_params();

        if (!(m = init_connections(from_connection, b))) {
                /* TODO: this needs to shut down the newly created junk */
                return(-ENXIO);
        }
        b->lower = m;
        return(0);
}
