/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
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
 */

/* tcpnal.c:
   This file implements the TCP-based nal by providing glue
   between the connection service and the generic NAL implementation */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pqtimer.h>
#include <dispatch.h>
#include <bridge.h>
#include <ipmap.h>
#include <connection.h>

/* Function:  tcpnal_send
 * Arguments: nal:     pointer to my nal control block
 *            private: unused
 *            cookie:  passed back to the portals library
 *            hdr:     pointer to the portals header
 *            nid:     destination node
 *            pid:     destination process
 *            data:    body of the message
 *            len:     length of the body
 * Returns: zero on success
 *
 * sends a packet to the peer, after insuring that a connection exists
 */
#warning FIXME: "param 'type' is newly added, make use of it!!"
int tcpnal_send(nal_cb_t *n,
		void *private,
		lib_msg_t *cookie,
		ptl_hdr_t *hdr,
		int type,
		ptl_nid_t nid,
		ptl_pid_t pid,
                unsigned int niov,
                struct iovec *iov,
		size_t len)
{
    connection c;
    bridge b=(bridge)n->nal_data;
    struct iovec tiov[65];

    if (!(c=force_tcp_connection((manager)b->lower,
                                 PNAL_IP(nid,b),
                                 PNAL_PORT(nid,pid)))) 
        return(1);

#if 0
    /* TODO: these results should be checked. furthermore, provision
       must be made for the SIGPIPE which is delivered when
       writing on a tcp socket which has closed underneath
       the application. there is a linux flag in the sendmsg
       call which turns off the signally behaviour, but its
       nonstandard */
    syscall(SYS_write, c->fd,hdr,sizeof(ptl_hdr_t));
    LASSERT (niov <= 1);
    if (len) syscall(SYS_write, c->fd,iov[0].iov_base,len);
#else
    LASSERT (niov <= 64);

    tiov[0].iov_base = hdr;
    tiov[0].iov_len = sizeof(ptl_hdr_t);

    if (niov > 0)
            memcpy(&tiov[1], iov, niov * sizeof(struct iovec));

    syscall(SYS_writev, c->fd, tiov, niov+1);
#endif
    lib_finalize(n, private, cookie);
        
    return(0);
}


/* Function:  tcpnal_recv
 * Arguments: nal_cb_t *nal:     pointer to my nal control block
 *            void *private:     connection pointer passed through
 *                               lib_parse()
 *            lib_msg_t *cookie: passed back to portals library
 *            user_ptr data:     pointer to the destination buffer
 *            size_t mlen:       length of the body
 *            size_t rlen:       length of data in the network
 * Returns: zero on success
 *
 * blocking read of the requested data. must drain out the
 * difference of mainpulated and requested lengths from the network
 */
int tcpnal_recv(nal_cb_t *n,
		void *private,
		lib_msg_t *cookie,
                unsigned int niov,
                struct iovec *iov,
		ptl_size_t mlen,
		ptl_size_t rlen)

{
    if (mlen) {
        LASSERT (niov <= 1);
        read_connection(private,iov[0].iov_base,mlen);
        lib_finalize(n, private, cookie);
    }

    if (mlen!=rlen){
        char *trash=malloc(rlen-mlen);
        
        /*TODO: check error status*/
        read_connection(private,trash,rlen-mlen);
        free(trash);
    }

    return(rlen);
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
static int from_connection(void *a,connection c)
{
    bridge b=a;
    ptl_hdr_t hdr;
    if (read_connection(c, (unsigned char *)&hdr, sizeof(hdr))){
        lib_parse(b->nal_cb, &hdr, c);
        return(1);
    }
    return(0);
}


static void tcpnal_shutdown(bridge b)
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
        
    b->nal_cb->cb_send=tcpnal_send;
    b->nal_cb->cb_recv=tcpnal_recv;
    b->shutdown=tcpnal_shutdown;
    
    if (!(m=init_connections(PNAL_PORT(b->nal_cb->ni.nid,
                                       b->nal_cb->ni.pid),
                             from_connection,b))){
        /* TODO: this needs to shut down the
           newly created junk */
        return(PTL_NAL_FAILED);
    }
    /* XXX cfs hack */
    b->nal_cb->ni.pid=0;
    b->lower=m;
    return(PTL_OK);
}
