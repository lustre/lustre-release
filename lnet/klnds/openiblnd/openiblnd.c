/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
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
 *
 */

#include "openibnal.h"

nal_t                   kibnal_api;
ptl_handle_ni_t         kibnal_ni;
kib_data_t              kibnal_data;
kib_tunables_t          kibnal_tunables;

#define IBNAL_SYSCTL             202

enum {
        IBNAL_SYSCTL_TIMEOUT=1,
        IBNAL_SYSCTL_LISTENER_TIMEOUT,
        IBNAL_SYSCTL_BACKLOG,
        IBNAL_SYSCTL_PORT
};

static ctl_table kibnal_ctl_table[] = {
        {IBNAL_SYSCTL_TIMEOUT, "timeout", 
         &kibnal_tunables.kib_io_timeout, sizeof (int),
         0644, NULL, &proc_dointvec},
        {IBNAL_SYSCTL_LISTENER_TIMEOUT, "listener_timeout", 
         &kibnal_tunables.kib_listener_timeout, sizeof(int),
         0644, NULL, &proc_dointvec},
        {IBNAL_SYSCTL_BACKLOG, "backlog",
         &kibnal_tunables.kib_backlog, sizeof(int),
         0644, NULL, kibnal_listener_procint},
        {IBNAL_SYSCTL_PORT, "port",
         &kibnal_tunables.kib_port, sizeof(int),
         0644, NULL, kibnal_listener_procint},
        { 0 }
};

static ctl_table kibnal_top_ctl_table[] = {
        {IBNAL_SYSCTL, "openibnal", NULL, 0, 0555, kibnal_ctl_table},
        { 0 }
};

__u32 
kibnal_cksum (void *ptr, int nob)
{
        char  *c  = ptr;
        __u32  sum = 0;

        while (nob-- > 0)
                sum = ((sum << 1) | (sum >> 31)) + *c++;

        /* ensure I don't return 0 (== no checksum) */
        return (sum == 0) ? 1 : sum;
}

void
kibnal_init_msg(kib_msg_t *msg, int type, int body_nob)
{
        msg->ibm_type = type;
        msg->ibm_nob  = offsetof(kib_msg_t, ibm_u) + body_nob;
}

void
kibnal_pack_msg(kib_msg_t *msg, int credits, ptl_nid_t dstnid, __u64 dststamp)
{
        /* CAVEAT EMPTOR! all message fields not set here should have been
         * initialised previously. */
        msg->ibm_magic    = IBNAL_MSG_MAGIC;
        msg->ibm_version  = IBNAL_MSG_VERSION;
        /*   ibm_type */
        msg->ibm_credits  = credits;
        /*   ibm_nob */
        msg->ibm_cksum    = 0;
        msg->ibm_srcnid   = kibnal_lib.libnal_ni.ni_pid.nid;
        msg->ibm_srcstamp = kibnal_data.kib_incarnation;
        msg->ibm_dstnid   = dstnid;
        msg->ibm_dststamp = dststamp;
#if IBNAL_CKSUM
        /* NB ibm_cksum zero while computing cksum */
        msg->ibm_cksum    = kibnal_cksum(msg, msg->ibm_nob);
#endif
}

int
kibnal_unpack_msg(kib_msg_t *msg, int nob)
{
        const int hdr_size = offsetof(kib_msg_t, ibm_u);
        __u32     msg_cksum;
        int       flip;
        int       msg_nob;

        if (nob < 6) {
                CERROR("Short message: %d\n", nob);
                return -EPROTO;
        }

        if (msg->ibm_magic == IBNAL_MSG_MAGIC) {
                flip = 0;
        } else if (msg->ibm_magic == __swab32(IBNAL_MSG_MAGIC)) {
                flip = 1;
        } else {
                CERROR("Bad magic: %08x\n", msg->ibm_magic);
                return -EPROTO;
        }

        if (msg->ibm_version != 
            (flip ? __swab16(IBNAL_MSG_VERSION) : IBNAL_MSG_VERSION)) {
                CERROR("Bad version: %d\n", msg->ibm_version);
                return -EPROTO;
        }

        if (nob < hdr_size) {
                CERROR("Short message: %d\n", nob);
                return -EPROTO;
        }

        msg_nob = flip ? __swab32(msg->ibm_nob) : msg->ibm_nob;
        if (msg_nob > nob) {
                CERROR("Short message: got %d, wanted %d\n", nob, msg_nob);
                return -EPROTO;
        }

        /* checksum must be computed with ibm_cksum zero and BEFORE anything
         * gets flipped */
        msg_cksum = flip ? __swab32(msg->ibm_cksum) : msg->ibm_cksum;
        msg->ibm_cksum = 0;
        if (msg_cksum != 0 &&
            msg_cksum != kibnal_cksum(msg, msg_nob)) {
                CERROR("Bad checksum\n");
                return -EPROTO;
        }
        msg->ibm_cksum = msg_cksum;
        
        if (flip) {
                /* leave magic unflipped as a clue to peer endianness */
                __swab16s(&msg->ibm_version);
                LASSERT (sizeof(msg->ibm_type) == 1);
                LASSERT (sizeof(msg->ibm_credits) == 1);
                msg->ibm_nob = msg_nob;
                __swab64s(&msg->ibm_srcnid);
                __swab64s(&msg->ibm_srcstamp);
                __swab64s(&msg->ibm_dstnid);
                __swab64s(&msg->ibm_dststamp);
        }
        
        if (msg->ibm_srcnid == PTL_NID_ANY) {
                CERROR("Bad src nid: "LPX64"\n", msg->ibm_srcnid);
                return -EPROTO;
        }

        switch (msg->ibm_type) {
        default:
                CERROR("Unknown message type %x\n", msg->ibm_type);
                return -EPROTO;
                
        case IBNAL_MSG_SVCQRY:
        case IBNAL_MSG_NOOP:
                break;

        case IBNAL_MSG_SVCRSP:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.svcrsp)) {
                        CERROR("Short SVCRSP: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.svcrsp)));
                        return -EPROTO;
                }
                if (flip) {
                        __swab64s(&msg->ibm_u.svcrsp.ibsr_svc_id);
                        __swab16s(&msg->ibm_u.svcrsp.ibsr_svc_pkey);
                }
                break;

        case IBNAL_MSG_CONNREQ:
        case IBNAL_MSG_CONNACK:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.connparams)) {
                        CERROR("Short CONNREQ: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.connparams)));
                        return -EPROTO;
                }
                if (flip)
                        __swab32s(&msg->ibm_u.connparams.ibcp_queue_depth);
                break;

        case IBNAL_MSG_IMMEDIATE:
                if (msg_nob < offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[0])) {
                        CERROR("Short IMMEDIATE: %d(%d)\n", msg_nob,
                               (int)offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[0]));
                        return -EPROTO;
                }
                break;

        case IBNAL_MSG_PUT_RDMA:
        case IBNAL_MSG_GET_RDMA:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.rdma)) {
                        CERROR("Short RDMA req: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.rdma)));
                        return -EPROTO;
                }
                if (flip) {
                        __swab32s(&msg->ibm_u.rdma.ibrm_desc.rd_key);
                        __swab32s(&msg->ibm_u.rdma.ibrm_desc.rd_nob);
                        __swab64s(&msg->ibm_u.rdma.ibrm_desc.rd_addr);
                }
                break;

        case IBNAL_MSG_PUT_DONE:
        case IBNAL_MSG_GET_DONE:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.completion)) {
                        CERROR("Short RDMA completion: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.completion)));
                        return -EPROTO;
                }
                if (flip)
                        __swab32s(&msg->ibm_u.completion.ibcm_status);
                break;
        }
        return 0;
}

int
kibnal_sock_write (struct socket *sock, void *buffer, int nob)
{
        int           rc;
        mm_segment_t  oldmm = get_fs();
        struct iovec  iov = {
                .iov_base = buffer,
                .iov_len  = nob
        };
        struct msghdr msg = {
                .msg_name       = NULL,
                .msg_namelen    = 0,
                .msg_iov        = &iov,
                .msg_iovlen     = 1,
                .msg_control    = NULL,
                .msg_controllen = 0,
                .msg_flags      = MSG_DONTWAIT
        };

        /* We've set up the socket's send buffer to be large enough for
         * everything we send, so a single non-blocking send should
         * complete without error. */

        set_fs(KERNEL_DS);
        rc = sock_sendmsg(sock, &msg, iov.iov_len);
        set_fs(oldmm);

        if (rc == nob)
                return 0;

        if (rc >= 0)
                return -EAGAIN;

        return rc;
}

int
kibnal_sock_read (struct socket *sock, void *buffer, int nob, int timeout)
{
        int            rc;
        mm_segment_t   oldmm = get_fs();
        long           ticks = timeout * HZ;
        unsigned long  then;
        struct timeval tv;

        LASSERT (nob > 0);
        LASSERT (ticks > 0);

        for (;;) {
                struct iovec  iov = {
                        .iov_base = buffer,
                        .iov_len  = nob
                };
                struct msghdr msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = &iov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = 0
                };

                /* Set receive timeout to remaining time */
                tv = (struct timeval) {
                        .tv_sec = ticks / HZ,
                        .tv_usec = ((ticks % HZ) * 1000000) / HZ
                };
                set_fs(KERNEL_DS);
                rc = sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                                     (char *)&tv, sizeof(tv));
                set_fs(oldmm);
                if (rc != 0) {
                        CERROR("Can't set socket recv timeout %d: %d\n",
                               timeout, rc);
                        return rc;
                }

                set_fs(KERNEL_DS);
                then = jiffies;
                rc = sock_recvmsg(sock, &msg, iov.iov_len, 0);
                ticks -= jiffies - then;
                set_fs(oldmm);

                if (rc < 0)
                        return rc;

                if (rc == 0)
                        return -ECONNABORTED;

                buffer = ((char *)buffer) + rc;
                nob -= rc;

                if (nob == 0)
                        return 0;

                if (ticks <= 0)
                        return -ETIMEDOUT;
        }
}

int
kibnal_create_sock(struct socket **sockp)
{
        struct socket       *sock;
        int                  rc;
        int                  option;
        mm_segment_t         oldmm = get_fs();

        rc = sock_create(PF_INET, SOCK_STREAM, 0, &sock);
        if (rc != 0) {
                CERROR("Can't create socket: %d\n", rc);
                return rc;
        }

        /* Ensure sends will not block */
        option = 2 * sizeof(kib_msg_t);
        set_fs(KERNEL_DS);
        rc = sock_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
                             (char *)&option, sizeof(option));
        set_fs(oldmm);
        if (rc != 0) {
                CERROR("Can't set send buffer %d: %d\n", option, rc);
                goto failed;
        }

        option = 1;
        set_fs(KERNEL_DS);
        rc = sock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                             (char *)&option, sizeof(option));
        set_fs(oldmm);
        if (rc != 0) {
                CERROR("Can't set SO_REUSEADDR: %d\n", rc);
                goto failed;
        }

        *sockp = sock;
        return 0;

 failed:
        sock_release(sock);
        return rc;
}

void
kibnal_pause(int ticks)
{
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(ticks);
}

int
kibnal_connect_sock(kib_peer_t *peer, struct socket **sockp)
{
        struct sockaddr_in  locaddr;
        struct sockaddr_in  srvaddr;
        struct socket      *sock;
        unsigned int        port;
        int                 rc;

        for (port = 1023; port >= 512; port--) {

                memset(&locaddr, 0, sizeof(locaddr)); 
                locaddr.sin_family      = AF_INET; 
                locaddr.sin_port        = htons(port);
                locaddr.sin_addr.s_addr = htonl(INADDR_ANY);

                memset (&srvaddr, 0, sizeof (srvaddr));
                srvaddr.sin_family      = AF_INET;
                srvaddr.sin_port        = htons (peer->ibp_port);
                srvaddr.sin_addr.s_addr = htonl (peer->ibp_ip);

                rc = kibnal_create_sock(&sock);
                if (rc != 0)
                        return rc;

                rc = sock->ops->bind(sock,
                                     (struct sockaddr *)&locaddr, sizeof(locaddr));
                if (rc != 0) {
                        sock_release(sock);
                        
                        if (rc == -EADDRINUSE) {
                                CDEBUG(D_NET, "Port %d already in use\n", port);
                                continue;
                        }

                        CERROR("Can't bind to reserved port %d: %d\n", port, rc);
                        return rc;
                }

                rc = sock->ops->connect(sock,
                                        (struct sockaddr *)&srvaddr, sizeof(srvaddr),
                                        0);
                if (rc == 0) {
                        *sockp = sock;
                        return 0;
                }
                
                sock_release(sock);

                if (rc != -EADDRNOTAVAIL) {
                        CERROR("Can't connect port %d to %u.%u.%u.%u/%d: %d\n",
                               port, HIPQUAD(peer->ibp_ip), peer->ibp_port, rc);
                        return rc;
                }
                
                CDEBUG(D_NET, "Port %d not available for %u.%u.%u.%u/%d\n", 
                       port, HIPQUAD(peer->ibp_ip), peer->ibp_port);
        }

        /* all ports busy */
        return -EHOSTUNREACH;
}

int
kibnal_make_svcqry (kib_conn_t *conn) 
{
        kib_peer_t    *peer = conn->ibc_peer;
        kib_msg_t     *msg;
        struct socket *sock;
        int            rc;
        int            nob;

        LASSERT (conn->ibc_connreq != NULL);
        msg = &conn->ibc_connreq->cr_msg;

        kibnal_init_msg(msg, IBNAL_MSG_SVCQRY, 0);
        kibnal_pack_msg(msg, 0, peer->ibp_nid, 0);

        rc = kibnal_connect_sock(peer, &sock);
        if (rc != 0)
                return rc;
        
        rc = kibnal_sock_write(sock, msg, msg->ibm_nob);
        if (rc != 0) {
                CERROR("Error %d sending svcqry to "
                       LPX64"@%u.%u.%u.%u/%d\n", rc, 
                       peer->ibp_nid, HIPQUAD(peer->ibp_ip), peer->ibp_port);
                goto out;
        }

        nob = offsetof(kib_msg_t, ibm_u) + sizeof(msg->ibm_u.svcrsp);
        rc = kibnal_sock_read(sock, msg, nob, kibnal_tunables.kib_io_timeout);
        if (rc != 0) {
                CERROR("Error %d receiving svcrsp from "
                       LPX64"@%u.%u.%u.%u/%d\n", rc, 
                       peer->ibp_nid, HIPQUAD(peer->ibp_ip), peer->ibp_port);
                goto out;
        }

        rc = kibnal_unpack_msg(msg, nob);
        if (rc != 0) {
                CERROR("Error %d unpacking svcrsp from "
                       LPX64"@%u.%u.%u.%u/%d\n", rc,
                       peer->ibp_nid, HIPQUAD(peer->ibp_ip), peer->ibp_port);
                goto out;
        }
                       
        if (msg->ibm_type != IBNAL_MSG_SVCRSP) {
                CERROR("Unexpected response type %d from "
                       LPX64"@%u.%u.%u.%u/%d\n", msg->ibm_type, 
                       peer->ibp_nid, HIPQUAD(peer->ibp_ip), peer->ibp_port);
                rc = -EPROTO;
                goto out;
        }
        
        if (msg->ibm_dstnid != kibnal_lib.libnal_ni.ni_pid.nid ||
            msg->ibm_dststamp != kibnal_data.kib_incarnation) {
                CERROR("Unexpected dst NID/stamp "LPX64"/"LPX64" from "
                       LPX64"@%u.%u.%u.%u/%d\n", 
                       msg->ibm_dstnid, msg->ibm_dststamp,
                       peer->ibp_nid, HIPQUAD(peer->ibp_ip), peer->ibp_port);
                rc = -EPROTO;
                goto out;
        }

        if (msg->ibm_srcnid != peer->ibp_nid) {
                CERROR("Unexpected src NID "LPX64" from "
                       LPX64"@%u.%u.%u.%u/%d\n", msg->ibm_srcnid,
                       peer->ibp_nid, HIPQUAD(peer->ibp_ip), peer->ibp_port);
                rc = -EPROTO;
                goto out;
        }

        conn->ibc_incarnation = msg->ibm_srcstamp;
        conn->ibc_connreq->cr_svcrsp = msg->ibm_u.svcrsp;
 out:
        sock_release(sock);
        return rc;
}

void
kibnal_handle_svcqry (struct socket *sock)
{
        struct sockaddr_in   addr;
        __u32                peer_ip;
        unsigned int         peer_port;
        kib_msg_t           *msg;
        __u64                srcnid;
        __u64                srcstamp;
        int                  len;
        int                  rc;

        len = sizeof(addr);
        rc = sock->ops->getname(sock, (struct sockaddr *)&addr, &len, 2);
        if (rc != 0) {
                CERROR("Can't get peer's IP: %d\n", rc);
                return;
        }

        peer_ip = ntohl(addr.sin_addr.s_addr);
        peer_port = ntohs(addr.sin_port);

        if (peer_port >= 1024) {
                CERROR("Refusing unprivileged connection from %u.%u.%u.%u/%d\n",
                       HIPQUAD(peer_ip), peer_port);
                return;
        }

        PORTAL_ALLOC(msg, sizeof(*msg));
        if (msg == NULL) {
                CERROR("Can't allocate msgs for %u.%u.%u.%u/%d\n",
                       HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        
        rc = kibnal_sock_read(sock, msg, offsetof(kib_msg_t, ibm_u),
                              kibnal_tunables.kib_listener_timeout);
        if (rc != 0) {
                CERROR("Error %d receiving svcqry from %u.%u.%u.%u/%d\n",
                       rc, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        
        rc = kibnal_unpack_msg(msg, offsetof(kib_msg_t, ibm_u));
        if (rc != 0) {
                CERROR("Error %d unpacking svcqry from %u.%u.%u.%u/%d\n",
                       rc, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        
        if (msg->ibm_type != IBNAL_MSG_SVCQRY) {
                CERROR("Unexpected message %d from %u.%u.%u.%u/%d\n",
                       msg->ibm_type, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        
        if (msg->ibm_dstnid != kibnal_lib.libnal_ni.ni_pid.nid) {
                CERROR("Unexpected dstnid "LPX64"(expected "LPX64" "
                       "from %u.%u.%u.%u/%d\n", msg->ibm_dstnid,
                       kibnal_lib.libnal_ni.ni_pid.nid,
                       HIPQUAD(peer_ip), peer_port);
                goto out;
        }

        srcnid = msg->ibm_srcnid;
        srcstamp = msg->ibm_srcstamp;
        
        kibnal_init_msg(msg, IBNAL_MSG_SVCRSP, sizeof(msg->ibm_u.svcrsp));

        msg->ibm_u.svcrsp.ibsr_svc_id = kibnal_data.kib_svc_id;
        memcpy(msg->ibm_u.svcrsp.ibsr_svc_gid, kibnal_data.kib_svc_gid,
               sizeof(kibnal_data.kib_svc_gid));
        msg->ibm_u.svcrsp.ibsr_svc_pkey = kibnal_data.kib_svc_pkey;

        kibnal_pack_msg(msg, 0, srcnid, srcstamp);
        
        rc = kibnal_sock_write (sock, msg, msg->ibm_nob);
        if (rc != 0) {
                CERROR("Error %d replying to svcqry from %u.%u.%u.%u/%d\n",
                       rc, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        
 out:
        PORTAL_FREE(msg, sizeof(*msg));
}

void
kibnal_free_acceptsock (kib_acceptsock_t *as)
{
        sock_release(as->ibas_sock);
        PORTAL_FREE(as, sizeof(*as));
}

int
kibnal_ip_listener(void *arg)
{
        struct sockaddr_in addr;
        wait_queue_t       wait;
        struct socket     *sock;
        kib_acceptsock_t  *as;
        int                port;
        char               name[16];
        int                rc;
        unsigned long      flags;

        /* Parent thread holds kib_nid_mutex, and is, or is about to
         * block on kib_listener_signal */

        port = kibnal_tunables.kib_port;
        snprintf(name, sizeof(name), "kibnal_lstn%03d", port);
        kportal_daemonize(name);
        kportal_blockallsigs();

        init_waitqueue_entry(&wait, current);

        rc = kibnal_create_sock(&sock);
        if (rc != 0)
                goto out_0;

        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        rc = sock->ops->bind(sock, (struct sockaddr *)&addr, sizeof(addr));
        if (rc != 0) {
                CERROR("Can't bind to port %d\n", port);
                goto out_1;
        }

        rc = sock->ops->listen(sock, kibnal_tunables.kib_backlog);
        if (rc != 0) {
                CERROR("Can't set listen backlog %d: %d\n", 
                       kibnal_tunables.kib_backlog, rc);
                goto out_1;
        }

        LASSERT (kibnal_data.kib_listener_sock == NULL);
        kibnal_data.kib_listener_sock = sock;

        /* unblock waiting parent */
        LASSERT (kibnal_data.kib_listener_shutdown == 0);
        up(&kibnal_data.kib_listener_signal);

        /* Wake me any time something happens on my socket */
        add_wait_queue(sock->sk->sk_sleep, &wait);
        as = NULL;

        while (kibnal_data.kib_listener_shutdown == 0) {

                if (as == NULL) {
                        PORTAL_ALLOC(as, sizeof(*as));
                        if (as == NULL) {
                                CERROR("Out of Memory: pausing...\n");
                                kibnal_pause(HZ);
                                continue;
                        }
                        as->ibas_sock = NULL;
                }

                if (as->ibas_sock == NULL) {
                        as->ibas_sock = sock_alloc();
                        if (as->ibas_sock == NULL) {
                                CERROR("Can't allocate socket: pausing...\n");
                                kibnal_pause(HZ);
                                continue;
                        }
                        /* XXX this should add a ref to sock->ops->owner, if
                         * TCP could be a module */
                        as->ibas_sock->type = sock->type;
                        as->ibas_sock->ops = sock->ops;
                }
                
                set_current_state(TASK_INTERRUPTIBLE);

                rc = sock->ops->accept(sock, as->ibas_sock, O_NONBLOCK);

                /* Sleep for socket activity? */
                if (rc == -EAGAIN &&
                    kibnal_data.kib_listener_shutdown == 0)
                        schedule();

                set_current_state(TASK_RUNNING);

                if (rc == 0) {
                        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
                        
                        list_add_tail(&as->ibas_list, 
                                      &kibnal_data.kib_connd_acceptq);

                        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
                        wake_up(&kibnal_data.kib_connd_waitq);

                        as = NULL;
                        continue;
                }
                
                if (rc != -EAGAIN) {
                        CERROR("Accept failed: %d, pausing...\n", rc);
                        kibnal_pause(HZ);
                }
        }

        if (as != NULL) {
                if (as->ibas_sock != NULL)
                        sock_release(as->ibas_sock);
                PORTAL_FREE(as, sizeof(*as));
        }

        rc = 0;
        remove_wait_queue(sock->sk->sk_sleep, &wait);
 out_1:
        sock_release(sock);
        kibnal_data.kib_listener_sock = NULL;
 out_0:
        /* set completion status and unblock thread waiting for me 
         * (parent on startup failure, executioner on normal shutdown) */
        kibnal_data.kib_listener_shutdown = rc;
        up(&kibnal_data.kib_listener_signal);

        return 0;
}

int
kibnal_start_ip_listener (void)
{
        long           pid;
        int            rc;

        CDEBUG(D_NET, "Starting listener\n");

        /* Called holding kib_nid_mutex: listener stopped */
        LASSERT (kibnal_data.kib_listener_sock == NULL);

        kibnal_data.kib_listener_shutdown = 0;
        pid = kernel_thread(kibnal_ip_listener, NULL, 0);
        if (pid < 0) {
                CERROR("Can't spawn listener: %ld\n", pid);
                return (int)pid;
        }

        /* Block until listener has started up. */
        down(&kibnal_data.kib_listener_signal);

        rc = kibnal_data.kib_listener_shutdown;
        LASSERT ((rc != 0) == (kibnal_data.kib_listener_sock == NULL));

        CDEBUG((rc == 0) ? D_WARNING : D_ERROR, 
               "Listener %s: pid:%ld port:%d backlog:%d\n", 
               (rc == 0) ? "started OK" : "startup failed",
               pid, kibnal_tunables.kib_port, kibnal_tunables.kib_backlog);

        return rc;
}

void
kibnal_stop_ip_listener(int clear_acceptq)
{
        struct list_head  zombie_accepts;
        kib_acceptsock_t *as;
        unsigned long     flags;

        CDEBUG(D_NET, "Stopping listener\n");

        /* Called holding kib_nid_mutex: listener running */
        LASSERT (kibnal_data.kib_listener_sock != NULL);

        kibnal_data.kib_listener_shutdown = 1;
        wake_up_all(kibnal_data.kib_listener_sock->sk->sk_sleep);

        /* Block until listener has torn down. */
        down(&kibnal_data.kib_listener_signal);

        LASSERT (kibnal_data.kib_listener_sock == NULL);
        CDEBUG(D_WARNING, "Listener stopped\n");

        if (!clear_acceptq)
                return;

        /* Close any unhandled accepts */
        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);

        list_add(&zombie_accepts, &kibnal_data.kib_connd_acceptq);
        list_del_init(&kibnal_data.kib_connd_acceptq);

        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
        
        while (!list_empty(&zombie_accepts)) {
                as = list_entry(zombie_accepts.next,
                                kib_acceptsock_t, ibas_list);
                list_del(&as->ibas_list);
                kibnal_free_acceptsock(as);
        }
}

int 
kibnal_listener_procint(ctl_table *table, int write, struct file *filp,
                        void *buffer, size_t *lenp)
{
        int   *tunable = (int *)table->data;
        int    old_val;
        int    rc;

        /* No race with nal initialisation since the nal is setup all the time
         * it's loaded.  When that changes, change this! */
        LASSERT (kibnal_data.kib_init == IBNAL_INIT_ALL);

        down(&kibnal_data.kib_nid_mutex);

        LASSERT (tunable == &kibnal_tunables.kib_port ||
                 tunable == &kibnal_tunables.kib_backlog);
        old_val = *tunable;

        rc = proc_dointvec(table, write, filp, buffer, lenp);

        if (write &&
            (*tunable != old_val ||
             kibnal_data.kib_listener_sock == NULL)) {

                if (kibnal_data.kib_listener_sock != NULL)
                        kibnal_stop_ip_listener(0);

                rc = kibnal_start_ip_listener();
                if (rc != 0) {
                        CERROR("Unable to restart listener with new tunable:"
                               " reverting to old value\n");
                        *tunable = old_val;
                        kibnal_start_ip_listener();
                }
        }

        up(&kibnal_data.kib_nid_mutex);

        LASSERT (kibnal_data.kib_init == IBNAL_INIT_ALL);
        return rc;
}

int
kibnal_start_ib_listener (void) 
{
        int    rc;

        LASSERT (kibnal_data.kib_listen_handle == NULL);

        kibnal_data.kib_svc_id = ib_cm_service_assign();
        CDEBUG(D_NET, "svc id "LPX64"\n", kibnal_data.kib_svc_id);

        rc = ib_cached_gid_get(kibnal_data.kib_device,
                               kibnal_data.kib_port, 0,
                               kibnal_data.kib_svc_gid);
        if (rc != 0) {
                CERROR("Can't get port %d GID: %d\n",
                       kibnal_data.kib_port, rc);
                return rc;
        }
        
        rc = ib_cached_pkey_get(kibnal_data.kib_device,
                                kibnal_data.kib_port, 0,
                                &kibnal_data.kib_svc_pkey);
        if (rc != 0) {
                CERROR ("Can't get port %d PKEY: %d\n",
                        kibnal_data.kib_port, rc);
                return rc;
        }

        rc = ib_cm_listen(kibnal_data.kib_svc_id,
                          TS_IB_CM_SERVICE_EXACT_MASK,
                          kibnal_passive_conn_callback, NULL,
                          &kibnal_data.kib_listen_handle);
        if (rc != 0) {
                kibnal_data.kib_listen_handle = NULL;
                CERROR ("Can't create IB listener: %d\n", rc);
                return rc;
        }
        
        LASSERT (kibnal_data.kib_listen_handle != NULL);
        return 0;
}

void
kibnal_stop_ib_listener (void) 
{
        int    rc;
        
        LASSERT (kibnal_data.kib_listen_handle != NULL);

        rc = ib_cm_listen_stop (kibnal_data.kib_listen_handle);
        if (rc != 0)
                CERROR("Error stopping IB listener: %d\n", rc);
                
        kibnal_data.kib_listen_handle = NULL;
}

int
kibnal_set_mynid (ptl_nid_t nid)
{
        lib_ni_t         *ni = &kibnal_lib.libnal_ni;
        int               rc;

        CDEBUG(D_IOCTL, "setting mynid to "LPX64" (old nid="LPX64")\n",
               nid, ni->ni_pid.nid);

        down (&kibnal_data.kib_nid_mutex);

        if (nid == kibnal_data.kib_nid) {
                /* no change of NID */
                up (&kibnal_data.kib_nid_mutex);
                return (0);
        }

        CDEBUG(D_NET, "NID "LPX64"("LPX64")\n",
               kibnal_data.kib_nid, nid);

        if (kibnal_data.kib_listener_sock != NULL)
                kibnal_stop_ip_listener(1);
        
        if (kibnal_data.kib_listen_handle != NULL)
                kibnal_stop_ib_listener();

        ni->ni_pid.nid = nid;
        kibnal_data.kib_incarnation++;
        mb();
        /* Delete all existing peers and their connections after new
         * NID/incarnation set to ensure no old connections in our brave new
         * world. */
        kibnal_del_peer (PTL_NID_ANY, 0);

        if (ni->ni_pid.nid != PTL_NID_ANY) {
                /* got a new NID to install */
                rc = kibnal_start_ib_listener();
                if (rc != 0) {
                        CERROR("Can't start IB listener: %d\n", rc);
                        goto failed_0;
                }
        
                rc = kibnal_start_ip_listener();
                if (rc != 0) {
                        CERROR("Can't start IP listener: %d\n", rc);
                        goto failed_1;
                }
        }
        
        up(&kibnal_data.kib_nid_mutex);
        return 0;

 failed_1:
        kibnal_stop_ib_listener();
 failed_0:
        ni->ni_pid.nid = PTL_NID_ANY;
        kibnal_data.kib_incarnation++;
        mb();
        kibnal_del_peer (PTL_NID_ANY, 0);
        up(&kibnal_data.kib_nid_mutex);
        return rc;
}

kib_peer_t *
kibnal_create_peer (ptl_nid_t nid)
{
        kib_peer_t *peer;

        LASSERT (nid != PTL_NID_ANY);

        PORTAL_ALLOC (peer, sizeof (*peer));
        if (peer == NULL)
                return (NULL);

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        peer->ibp_nid = nid;
        atomic_set (&peer->ibp_refcount, 1);    /* 1 ref for caller */

        INIT_LIST_HEAD (&peer->ibp_list);       /* not in the peer table yet */
        INIT_LIST_HEAD (&peer->ibp_conns);
        INIT_LIST_HEAD (&peer->ibp_tx_queue);

        peer->ibp_reconnect_time = jiffies;
        peer->ibp_reconnect_interval = IBNAL_MIN_RECONNECT_INTERVAL;

        atomic_inc (&kibnal_data.kib_npeers);
        CDEBUG(D_NET, "peer %p "LPX64"\n", peer, nid);

        return (peer);
}

void
kibnal_destroy_peer (kib_peer_t *peer)
{
        CDEBUG (D_NET, "peer "LPX64" %p deleted\n", peer->ibp_nid, peer);

        LASSERT (atomic_read (&peer->ibp_refcount) == 0);
        LASSERT (peer->ibp_persistence == 0);
        LASSERT (!kibnal_peer_active(peer));
        LASSERT (peer->ibp_connecting == 0);
        LASSERT (list_empty (&peer->ibp_conns));
        LASSERT (list_empty (&peer->ibp_tx_queue));

        PORTAL_FREE (peer, sizeof (*peer));

        /* NB a peer's connections keep a reference on their peer until
         * they are destroyed, so we can be assured that _all_ state to do
         * with this peer has been cleaned up when its refcount drops to
         * zero. */
        atomic_dec (&kibnal_data.kib_npeers);
}

void
kibnal_put_peer (kib_peer_t *peer)
{
        CDEBUG (D_OTHER, "putting peer[%p] -> "LPX64" (%d)\n",
                peer, peer->ibp_nid,
                atomic_read (&peer->ibp_refcount));

        LASSERT (atomic_read (&peer->ibp_refcount) > 0);
        if (!atomic_dec_and_test (&peer->ibp_refcount))
                return;

        kibnal_destroy_peer (peer);
}

kib_peer_t *
kibnal_find_peer_locked (ptl_nid_t nid)
{
        struct list_head *peer_list = kibnal_nid2peerlist (nid);
        struct list_head *tmp;
        kib_peer_t       *peer;

        list_for_each (tmp, peer_list) {

                peer = list_entry (tmp, kib_peer_t, ibp_list);

                LASSERT (peer->ibp_persistence != 0 || /* persistent peer */
                         peer->ibp_connecting != 0 || /* creating conns */
                         !list_empty (&peer->ibp_conns));  /* active conn */

                if (peer->ibp_nid != nid)
                        continue;

                CDEBUG(D_NET, "got peer [%p] -> "LPX64" (%d)\n",
                       peer, nid, atomic_read (&peer->ibp_refcount));
                return (peer);
        }
        return (NULL);
}

kib_peer_t *
kibnal_get_peer (ptl_nid_t nid)
{
        kib_peer_t     *peer;
        unsigned long   flags;

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);
        peer = kibnal_find_peer_locked (nid);
        if (peer != NULL)                       /* +1 ref for caller? */
                atomic_inc (&peer->ibp_refcount);
        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        return (peer);
}

void
kibnal_unlink_peer_locked (kib_peer_t *peer)
{
        LASSERT (peer->ibp_persistence == 0);
        LASSERT (list_empty(&peer->ibp_conns));

        LASSERT (kibnal_peer_active(peer));
        list_del_init (&peer->ibp_list);
        /* lose peerlist's ref */
        kibnal_put_peer (peer);
}

int
kibnal_get_peer_info (int index, ptl_nid_t *nidp, __u32 *ipp, int *portp,
                      int *persistencep)
{
        kib_peer_t        *peer;
        struct list_head  *ptmp;
        unsigned long      flags;
        int                i;

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {

                list_for_each (ptmp, &kibnal_data.kib_peers[i]) {
                        
                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (index-- > 0)
                                continue;

                        *nidp = peer->ibp_nid;
                        *ipp = peer->ibp_ip;
                        *portp = peer->ibp_port;
                        *persistencep = peer->ibp_persistence;
                        
                        read_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                               flags);
                        return (0);
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
        return (-ENOENT);
}

int
kibnal_add_persistent_peer (ptl_nid_t nid, __u32 ip, int port)
{
        unsigned long      flags;
        kib_peer_t        *peer;
        kib_peer_t        *peer2;
        
        if (nid == PTL_NID_ANY)
                return (-EINVAL);

        peer = kibnal_create_peer (nid);
        if (peer == NULL)
                return (-ENOMEM);

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        peer2 = kibnal_find_peer_locked (nid);
        if (peer2 != NULL) {
                kibnal_put_peer (peer);
                peer = peer2;
        } else {
                /* peer table takes existing ref on peer */
                list_add_tail (&peer->ibp_list,
                               kibnal_nid2peerlist (nid));
        }

        peer->ibp_ip = ip;
        peer->ibp_port = port;
        peer->ibp_persistence++;
        
        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
        return (0);
}

void
kibnal_del_peer_locked (kib_peer_t *peer, int single_share)
{
        struct list_head *ctmp;
        struct list_head *cnxt;
        kib_conn_t       *conn;

        if (!single_share)
                peer->ibp_persistence = 0;
        else if (peer->ibp_persistence > 0)
                peer->ibp_persistence--;

        if (peer->ibp_persistence != 0)
                return;

        if (list_empty(&peer->ibp_conns)) {
                kibnal_unlink_peer_locked(peer);
        } else {
                list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                        conn = list_entry(ctmp, kib_conn_t, ibc_list);

                        kibnal_close_conn_locked (conn, 0);
                }
                /* NB peer is no longer persistent; closing its last conn
                 * unlinked it. */
        }
        /* NB peer now unlinked; might even be freed if the peer table had the
         * last ref on it. */
}

int
kibnal_del_peer (ptl_nid_t nid, int single_share)
{
        unsigned long      flags;
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        kib_peer_t        *peer;
        int                lo;
        int                hi;
        int                i;
        int                rc = -ENOENT;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (nid != PTL_NID_ANY)
                lo = hi = kibnal_nid2peerlist(nid) - kibnal_data.kib_peers;
        else {
                lo = 0;
                hi = kibnal_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kibnal_data.kib_peers[i]) {
                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (!(nid == PTL_NID_ANY || peer->ibp_nid == nid))
                                continue;

                        kibnal_del_peer_locked (peer, single_share);
                        rc = 0;         /* matched something */

                        if (single_share)
                                goto out;
                }
        }
 out:
        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        return (rc);
}

kib_conn_t *
kibnal_get_conn_by_idx (int index)
{
        kib_peer_t        *peer;
        struct list_head  *ptmp;
        kib_conn_t        *conn;
        struct list_head  *ctmp;
        unsigned long      flags;
        int                i;

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {
                list_for_each (ptmp, &kibnal_data.kib_peers[i]) {

                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence > 0 ||
                                 peer->ibp_connecting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        list_for_each (ctmp, &peer->ibp_conns) {
                                if (index-- > 0)
                                        continue;

                                conn = list_entry (ctmp, kib_conn_t, ibc_list);
                                CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                                       atomic_read (&conn->ibc_refcount));
                                atomic_inc (&conn->ibc_refcount);
                                read_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                                       flags);
                                return (conn);
                        }
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
        return (NULL);
}

kib_conn_t *
kibnal_create_conn (void)
{
        kib_conn_t  *conn;
        int          i;
        __u64        vaddr = 0;
        __u64        vaddr_base;
        int          page_offset;
        int          ipage;
        int          rc;
        union {
                struct ib_qp_create_param  qp_create;
                struct ib_qp_attribute     qp_attr;
        } params;
        
        PORTAL_ALLOC (conn, sizeof (*conn));
        if (conn == NULL) {
                CERROR ("Can't allocate connection\n");
                return (NULL);
        }

        /* zero flags, NULL pointers etc... */
        memset (conn, 0, sizeof (*conn));

        INIT_LIST_HEAD (&conn->ibc_tx_queue);
        INIT_LIST_HEAD (&conn->ibc_active_txs);
        spin_lock_init (&conn->ibc_lock);
        
        atomic_inc (&kibnal_data.kib_nconns);
        /* well not really, but I call destroy() on failure, which decrements */

        PORTAL_ALLOC (conn->ibc_rxs, IBNAL_RX_MSGS * sizeof (kib_rx_t));
        if (conn->ibc_rxs == NULL)
                goto failed;
        memset (conn->ibc_rxs, 0, IBNAL_RX_MSGS * sizeof(kib_rx_t));

        rc = kibnal_alloc_pages(&conn->ibc_rx_pages,
                                IBNAL_RX_MSG_PAGES,
                                IB_ACCESS_LOCAL_WRITE);
        if (rc != 0)
                goto failed;

        vaddr_base = vaddr = conn->ibc_rx_pages->ibp_vaddr;

        for (i = ipage = page_offset = 0; i < IBNAL_RX_MSGS; i++) {
                struct page *page = conn->ibc_rx_pages->ibp_pages[ipage];
                kib_rx_t   *rx = &conn->ibc_rxs[i];

                rx->rx_conn = conn;
                rx->rx_vaddr = vaddr;
                rx->rx_msg = (kib_msg_t *)(((char *)page_address(page)) + page_offset);
                
                vaddr += IBNAL_MSG_SIZE;
                LASSERT (vaddr <= vaddr_base + IBNAL_RX_MSG_BYTES);
                
                page_offset += IBNAL_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= IBNAL_RX_MSG_PAGES);
                }
        }

        params.qp_create = (struct ib_qp_create_param) {
                .limit = {
                        /* Sends have an optional RDMA */
                        .max_outstanding_send_request    = 2 * IBNAL_MSG_QUEUE_SIZE,
                        .max_outstanding_receive_request = IBNAL_MSG_QUEUE_SIZE,
                        .max_send_gather_element         = 1,
                        .max_receive_scatter_element     = 1,
                },
                .pd              = kibnal_data.kib_pd,
                .send_queue      = kibnal_data.kib_cq,
                .receive_queue   = kibnal_data.kib_cq,
                .send_policy     = IB_WQ_SIGNAL_SELECTABLE,
                .receive_policy  = IB_WQ_SIGNAL_SELECTABLE,
                .rd_domain       = 0,
                .transport       = IB_TRANSPORT_RC,
                .device_specific = NULL,
        };
        
        rc = ib_qp_create (&params.qp_create, &conn->ibc_qp, &conn->ibc_qpn);
        if (rc != 0) {
                CERROR ("Failed to create queue pair: %d\n", rc);
                goto failed;
        }
        
        /* Mark QP created */
        conn->ibc_state = IBNAL_CONN_INIT_QP;

        params.qp_attr = (struct ib_qp_attribute) {
                .state             = IB_QP_STATE_INIT,
                .port              = kibnal_data.kib_port,
                .enable_rdma_read  = 1,
                .enable_rdma_write = 1,
                .valid_fields      = (IB_QP_ATTRIBUTE_STATE |
                                      IB_QP_ATTRIBUTE_PORT |
                                      IB_QP_ATTRIBUTE_PKEY_INDEX |
                                      IB_QP_ATTRIBUTE_RDMA_ATOMIC_ENABLE),
        };
        rc = ib_qp_modify(conn->ibc_qp, &params.qp_attr);
        if (rc != 0) {
                CERROR ("Failed to modify queue pair: %d\n", rc);
                goto failed;
        }

        /* 1 ref for caller */
        atomic_set (&conn->ibc_refcount, 1);
        return (conn);
        
 failed:
        kibnal_destroy_conn (conn);
        return (NULL);
}

void
kibnal_destroy_conn (kib_conn_t *conn)
{
        int    rc;
        
        CDEBUG (D_NET, "connection %p\n", conn);

        LASSERT (atomic_read (&conn->ibc_refcount) == 0);
        LASSERT (list_empty(&conn->ibc_tx_queue));
        LASSERT (list_empty(&conn->ibc_active_txs));
        LASSERT (conn->ibc_nsends_posted == 0);
        LASSERT (conn->ibc_connreq == NULL);

        switch (conn->ibc_state) {
        case IBNAL_CONN_ZOMBIE:
                /* called after connection sequence initiated */

        case IBNAL_CONN_INIT_QP:
                rc = ib_qp_destroy(conn->ibc_qp);
                if (rc != 0)
                        CERROR("Can't destroy QP: %d\n", rc);
                /* fall through */
                
        case IBNAL_CONN_INIT_NOTHING:
                break;

        default:
                LASSERT (0);
        }

        if (conn->ibc_rx_pages != NULL) 
                kibnal_free_pages(conn->ibc_rx_pages);
        
        if (conn->ibc_rxs != NULL)
                PORTAL_FREE(conn->ibc_rxs, 
                            IBNAL_RX_MSGS * sizeof(kib_rx_t));

        if (conn->ibc_peer != NULL)
                kibnal_put_peer(conn->ibc_peer);

        PORTAL_FREE(conn, sizeof (*conn));

        atomic_dec(&kibnal_data.kib_nconns);
        
        if (atomic_read (&kibnal_data.kib_nconns) == 0 &&
            kibnal_data.kib_shutdown) {
                /* I just nuked the last connection on shutdown; wake up
                 * everyone so they can exit. */
                wake_up_all(&kibnal_data.kib_sched_waitq);
                wake_up_all(&kibnal_data.kib_reaper_waitq);
        }
}

void
kibnal_put_conn (kib_conn_t *conn)
{
        unsigned long flags;

        CDEBUG (D_NET, "putting conn[%p] state %d -> "LPX64" (%d)\n",
                conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                atomic_read (&conn->ibc_refcount));

        LASSERT (atomic_read (&conn->ibc_refcount) > 0);
        if (!atomic_dec_and_test (&conn->ibc_refcount))
                return;

        /* last ref only goes on zombies */
        LASSERT (conn->ibc_state == IBNAL_CONN_ZOMBIE);

        spin_lock_irqsave (&kibnal_data.kib_reaper_lock, flags);

        list_add (&conn->ibc_list, &kibnal_data.kib_reaper_conns);
        wake_up (&kibnal_data.kib_reaper_waitq);

        spin_unlock_irqrestore (&kibnal_data.kib_reaper_lock, flags);
}

int
kibnal_close_peer_conns_locked (kib_peer_t *peer, int why)
{
        kib_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry (ctmp, kib_conn_t, ibc_list);

                count++;
                kibnal_close_conn_locked (conn, why);
        }

        return (count);
}

int
kibnal_close_stale_conns_locked (kib_peer_t *peer, __u64 incarnation)
{
        kib_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry (ctmp, kib_conn_t, ibc_list);

                if (conn->ibc_incarnation == incarnation)
                        continue;

                CDEBUG(D_NET, "Closing stale conn nid:"LPX64" incarnation:"LPX64"("LPX64")\n",
                       peer->ibp_nid, conn->ibc_incarnation, incarnation);
                
                count++;
                kibnal_close_conn_locked (conn, -ESTALE);
        }

        return (count);
}

int
kibnal_close_matching_conns (ptl_nid_t nid)
{
        unsigned long       flags;
        kib_peer_t         *peer;
        struct list_head   *ptmp;
        struct list_head   *pnxt;
        int                 lo;
        int                 hi;
        int                 i;
        int                 count = 0;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (nid != PTL_NID_ANY)
                lo = hi = kibnal_nid2peerlist(nid) - kibnal_data.kib_peers;
        else {
                lo = 0;
                hi = kibnal_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kibnal_data.kib_peers[i]) {

                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (!(nid == PTL_NID_ANY || nid == peer->ibp_nid))
                                continue;

                        count += kibnal_close_peer_conns_locked (peer, 0);
                }
        }

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        /* wildcards always succeed */
        if (nid == PTL_NID_ANY)
                return (0);
        
        return (count == 0 ? -ENOENT : 0);
}

int
kibnal_cmd(struct portals_cfg *pcfg, void * private)
{
        int rc = -EINVAL;

        LASSERT (pcfg != NULL);

        switch(pcfg->pcfg_command) {
        case NAL_CMD_GET_PEER: {
                ptl_nid_t   nid = 0;
                __u32       ip = 0;
                int         port = 0;
                int         share_count = 0;

                rc = kibnal_get_peer_info(pcfg->pcfg_count,
                                          &nid, &ip, &port, &share_count);
                pcfg->pcfg_nid   = nid;
                pcfg->pcfg_size  = 0;
                pcfg->pcfg_id    = ip;
                pcfg->pcfg_misc  = port;
                pcfg->pcfg_count = 0;
                pcfg->pcfg_wait  = share_count;
                break;
        }
        case NAL_CMD_ADD_PEER: {
                rc = kibnal_add_persistent_peer (pcfg->pcfg_nid,
                                                 pcfg->pcfg_id, /* IP */
                                                 pcfg->pcfg_misc); /* port */
                break;
        }
        case NAL_CMD_DEL_PEER: {
                rc = kibnal_del_peer (pcfg->pcfg_nid, 
                                       /* flags == single_share */
                                       pcfg->pcfg_flags != 0);
                break;
        }
        case NAL_CMD_GET_CONN: {
                kib_conn_t *conn = kibnal_get_conn_by_idx (pcfg->pcfg_count);

                if (conn == NULL)
                        rc = -ENOENT;
                else {
                        rc = 0;
                        pcfg->pcfg_nid   = conn->ibc_peer->ibp_nid;
                        pcfg->pcfg_id    = 0;
                        pcfg->pcfg_misc  = 0;
                        pcfg->pcfg_flags = 0;
                        kibnal_put_conn (conn);
                }
                break;
        }
        case NAL_CMD_CLOSE_CONNECTION: {
                rc = kibnal_close_matching_conns (pcfg->pcfg_nid);
                break;
        }
        case NAL_CMD_REGISTER_MYNID: {
                if (pcfg->pcfg_nid == PTL_NID_ANY)
                        rc = -EINVAL;
                else
                        rc = kibnal_set_mynid (pcfg->pcfg_nid);
                break;
        }
        }

        return rc;
}

void
kibnal_free_pages (kib_pages_t *p)
{
        int     npages = p->ibp_npages;
        int     rc;
        int     i;
        
        if (p->ibp_mapped) {
                rc = ib_memory_deregister(p->ibp_handle);
                if (rc != 0)
                        CERROR ("Deregister error: %d\n", rc);
        }
        
        for (i = 0; i < npages; i++)
                if (p->ibp_pages[i] != NULL)
                        __free_page(p->ibp_pages[i]);
        
        PORTAL_FREE (p, offsetof(kib_pages_t, ibp_pages[npages]));
}

int
kibnal_alloc_pages (kib_pages_t **pp, int npages, int access)
{
        kib_pages_t                *p;
        struct ib_physical_buffer  *phys_pages;
        int                         i;
        int                         rc;

        PORTAL_ALLOC(p, offsetof(kib_pages_t, ibp_pages[npages]));
        if (p == NULL) {
                CERROR ("Can't allocate buffer %d\n", npages);
                return (-ENOMEM);
        }

        memset (p, 0, offsetof(kib_pages_t, ibp_pages[npages]));
        p->ibp_npages = npages;
        
        for (i = 0; i < npages; i++) {
                p->ibp_pages[i] = alloc_page (GFP_KERNEL);
                if (p->ibp_pages[i] == NULL) {
                        CERROR ("Can't allocate page %d of %d\n", i, npages);
                        kibnal_free_pages(p);
                        return (-ENOMEM);
                }
        }

        PORTAL_ALLOC(phys_pages, npages * sizeof(*phys_pages));
        if (phys_pages == NULL) {
                CERROR ("Can't allocate physarray for %d pages\n", npages);
                kibnal_free_pages(p);
                return (-ENOMEM);
        }

        for (i = 0; i < npages; i++) {
                phys_pages[i].size = PAGE_SIZE;
                phys_pages[i].address =
                        kibnal_page2phys(p->ibp_pages[i]);
        }

        p->ibp_vaddr = 0;
        rc = ib_memory_register_physical(kibnal_data.kib_pd,
                                         phys_pages, npages,
                                         &p->ibp_vaddr,
                                         npages * PAGE_SIZE, 0,
                                         access,
                                         &p->ibp_handle,
                                         &p->ibp_lkey,
                                         &p->ibp_rkey);
        
        PORTAL_FREE(phys_pages, npages * sizeof(*phys_pages));
        
        if (rc != 0) {
                CERROR ("Error %d mapping %d pages\n", rc, npages);
                kibnal_free_pages(p);
                return (rc);
        }
        
        p->ibp_mapped = 1;
        *pp = p;
        return (0);
}

int
kibnal_setup_tx_descs (void)
{
        int           ipage = 0;
        int           page_offset = 0;
        __u64         vaddr;
        __u64         vaddr_base;
        struct page  *page;
        kib_tx_t     *tx;
        int           i;
        int           rc;

        /* pre-mapped messages are not bigger than 1 page */
        LASSERT (IBNAL_MSG_SIZE <= PAGE_SIZE);

        /* No fancy arithmetic when we do the buffer calculations */
        LASSERT (PAGE_SIZE % IBNAL_MSG_SIZE == 0);

        rc = kibnal_alloc_pages(&kibnal_data.kib_tx_pages,
                                IBNAL_TX_MSG_PAGES, 
                                0);            /* local read access only */
        if (rc != 0)
                return (rc);

        vaddr = vaddr_base = kibnal_data.kib_tx_pages->ibp_vaddr;

        for (i = 0; i < IBNAL_TX_MSGS; i++) {
                page = kibnal_data.kib_tx_pages->ibp_pages[ipage];
                tx = &kibnal_data.kib_tx_descs[i];

                memset (tx, 0, sizeof(*tx));    /* zero flags etc */
                
                tx->tx_msg = (kib_msg_t *)(((char *)page_address(page)) + page_offset);
                tx->tx_vaddr = vaddr;
                tx->tx_isnblk = (i >= IBNAL_NTX);
                tx->tx_mapped = KIB_TX_UNMAPPED;

                CDEBUG(D_NET, "Tx[%d] %p->%p - "LPX64"\n", 
                       i, tx, tx->tx_msg, tx->tx_vaddr);

                if (tx->tx_isnblk)
                        list_add (&tx->tx_list, 
                                  &kibnal_data.kib_idle_nblk_txs);
                else
                        list_add (&tx->tx_list, 
                                  &kibnal_data.kib_idle_txs);

                vaddr += IBNAL_MSG_SIZE;
                LASSERT (vaddr <= vaddr_base + IBNAL_TX_MSG_BYTES);

                page_offset += IBNAL_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= IBNAL_TX_MSG_PAGES);
                }
        }
        
        return (0);
}

void
kibnal_api_shutdown (nal_t *nal)
{
        int   i;
        int   rc;

        if (nal->nal_refct != 0) {
                /* This module got the first ref */
                PORTAL_MODULE_UNUSE;
                return;
        }

        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        LASSERT(nal == &kibnal_api);

        switch (kibnal_data.kib_init) {
        default:
                CERROR ("Unexpected state %d\n", kibnal_data.kib_init);
                LBUG();

        case IBNAL_INIT_ALL:
                /* stop calls to nal_cmd */
                libcfs_nal_cmd_unregister(OPENIBNAL);
                /* No new peers */

                /* resetting my NID unadvertises me, removes my
                 * listener and nukes all current peers */
                kibnal_set_mynid (PTL_NID_ANY);

                /* Wait for all peer state to clean up */
                i = 2;
                while (atomic_read (&kibnal_data.kib_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "waiting for %d peers to close down\n",
                               atomic_read (&kibnal_data.kib_npeers));
                        set_current_state (TASK_INTERRUPTIBLE);
                        schedule_timeout (HZ);
                }
                /* fall through */

        case IBNAL_INIT_CQ:
                rc = ib_cq_destroy (kibnal_data.kib_cq);
                if (rc != 0)
                        CERROR ("Destroy CQ error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_TXD:
                kibnal_free_pages (kibnal_data.kib_tx_pages);
                /* fall through */
#if IBNAL_FMR
        case IBNAL_INIT_FMR:
                rc = ib_fmr_pool_destroy (kibnal_data.kib_fmr_pool);
                if (rc != 0)
                        CERROR ("Destroy FMR pool error: %d\n", rc);
                /* fall through */
#endif
        case IBNAL_INIT_PD:
                rc = ib_pd_destroy(kibnal_data.kib_pd);
                if (rc != 0)
                        CERROR ("Destroy PD error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_LIB:
                lib_fini(&kibnal_lib);
                /* fall through */

        case IBNAL_INIT_DATA:
                /* Module refcount only gets to zero when all peers
                 * have been closed so all lists must be empty */
                LASSERT (atomic_read (&kibnal_data.kib_npeers) == 0);
                LASSERT (kibnal_data.kib_peers != NULL);
                for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {
                        LASSERT (list_empty (&kibnal_data.kib_peers[i]));
                }
                LASSERT (atomic_read (&kibnal_data.kib_nconns) == 0);
                LASSERT (list_empty (&kibnal_data.kib_sched_rxq));
                LASSERT (list_empty (&kibnal_data.kib_sched_txq));
                LASSERT (list_empty (&kibnal_data.kib_reaper_conns));
                LASSERT (list_empty (&kibnal_data.kib_connd_peers));
                LASSERT (list_empty (&kibnal_data.kib_connd_acceptq));

                /* flag threads to terminate; wake and wait for them to die */
                kibnal_data.kib_shutdown = 1;
                wake_up_all (&kibnal_data.kib_sched_waitq);
                wake_up_all (&kibnal_data.kib_reaper_waitq);
                wake_up_all (&kibnal_data.kib_connd_waitq);

                i = 2;
                while (atomic_read (&kibnal_data.kib_nthreads) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "Waiting for %d threads to terminate\n",
                               atomic_read (&kibnal_data.kib_nthreads));
                        set_current_state (TASK_INTERRUPTIBLE);
                        schedule_timeout (HZ);
                }
                /* fall through */
                
        case IBNAL_INIT_NOTHING:
                break;
        }

        if (kibnal_data.kib_tx_descs != NULL)
                PORTAL_FREE (kibnal_data.kib_tx_descs,
                             IBNAL_TX_MSGS * sizeof(kib_tx_t));

        if (kibnal_data.kib_peers != NULL)
                PORTAL_FREE (kibnal_data.kib_peers,
                             sizeof (struct list_head) * 
                             kibnal_data.kib_peer_hash_size);

        CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));
        printk(KERN_INFO "Lustre: OpenIB NAL unloaded (final mem %d)\n",
               atomic_read(&portal_kmemory));

        kibnal_data.kib_init = IBNAL_INIT_NOTHING;
}

int
kibnal_api_startup (nal_t *nal, ptl_pid_t requested_pid,
                     ptl_ni_limits_t *requested_limits,
                     ptl_ni_limits_t *actual_limits)
{
        struct timeval    tv;
        ptl_process_id_t  process_id;
        int               pkmem = atomic_read(&portal_kmemory);
        int               rc;
        int               i;

        LASSERT (nal == &kibnal_api);

        if (nal->nal_refct != 0) {
                if (actual_limits != NULL)
                        *actual_limits = kibnal_lib.libnal_ni.ni_actual_limits;
                /* This module got the first ref */
                PORTAL_MODULE_USE;
                return (PTL_OK);
        }

        LASSERT (kibnal_data.kib_init == IBNAL_INIT_NOTHING);

        memset (&kibnal_data, 0, sizeof (kibnal_data)); /* zero pointers, flags etc */

        do_gettimeofday(&tv);
        kibnal_data.kib_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

        init_MUTEX (&kibnal_data.kib_nid_mutex);
        init_MUTEX_LOCKED (&kibnal_data.kib_listener_signal);

        rwlock_init(&kibnal_data.kib_global_lock);

        kibnal_data.kib_peer_hash_size = IBNAL_PEER_HASH_SIZE;
        PORTAL_ALLOC (kibnal_data.kib_peers,
                      sizeof (struct list_head) * kibnal_data.kib_peer_hash_size);
        if (kibnal_data.kib_peers == NULL) {
                goto failed;
        }
        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++)
                INIT_LIST_HEAD(&kibnal_data.kib_peers[i]);

        spin_lock_init (&kibnal_data.kib_reaper_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_reaper_conns);
        init_waitqueue_head (&kibnal_data.kib_reaper_waitq);

        spin_lock_init (&kibnal_data.kib_connd_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_connd_acceptq);
        INIT_LIST_HEAD (&kibnal_data.kib_connd_peers);
        init_waitqueue_head (&kibnal_data.kib_connd_waitq);

        spin_lock_init (&kibnal_data.kib_sched_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_sched_txq);
        INIT_LIST_HEAD (&kibnal_data.kib_sched_rxq);
        init_waitqueue_head (&kibnal_data.kib_sched_waitq);

        spin_lock_init (&kibnal_data.kib_tx_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_idle_txs);
        INIT_LIST_HEAD (&kibnal_data.kib_idle_nblk_txs);
        init_waitqueue_head(&kibnal_data.kib_idle_tx_waitq);

        PORTAL_ALLOC (kibnal_data.kib_tx_descs,
                      IBNAL_TX_MSGS * sizeof(kib_tx_t));
        if (kibnal_data.kib_tx_descs == NULL) {
                CERROR ("Can't allocate tx descs\n");
                goto failed;
        }

        /* lists/ptrs/locks initialised */
        kibnal_data.kib_init = IBNAL_INIT_DATA;
        /*****************************************************/


        process_id.pid = requested_pid;
        process_id.nid = PTL_NID_ANY;           /* don't know my NID yet */
        
        rc = lib_init(&kibnal_lib, nal, process_id,
                      requested_limits, actual_limits);
        if (rc != PTL_OK) {
                CERROR("lib_init failed: error %d\n", rc);
                goto failed;
        }

        /* lib interface initialised */
        kibnal_data.kib_init = IBNAL_INIT_LIB;
        /*****************************************************/

        for (i = 0; i < IBNAL_N_SCHED; i++) {
                rc = kibnal_thread_start (kibnal_scheduler,
                                          (void *)((unsigned long)i));
                if (rc != 0) {
                        CERROR("Can't spawn openibnal scheduler[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        for (i = 0; i < IBNAL_N_CONND; i++) {
                rc = kibnal_thread_start (kibnal_connd,
                                          (void *)((unsigned long)i));
                if (rc != 0) {
                        CERROR("Can't spawn openibnal connd[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        rc = kibnal_thread_start (kibnal_reaper, NULL);
        if (rc != 0) {
                CERROR ("Can't spawn openibnal reaper: %d\n", rc);
                goto failed;
        }

        kibnal_data.kib_device = ib_device_get_by_index(0);
        if (kibnal_data.kib_device == NULL) {
                CERROR ("Can't open ib device 0\n");
                goto failed;
        }
        
        rc = ib_device_properties_get(kibnal_data.kib_device,
                                      &kibnal_data.kib_device_props);
        if (rc != 0) {
                CERROR ("Can't get device props: %d\n", rc);
                goto failed;
        }

        CDEBUG(D_NET, "Max Initiator: %d Max Responder %d\n", 
               kibnal_data.kib_device_props.max_initiator_per_qp,
               kibnal_data.kib_device_props.max_responder_per_qp);

        kibnal_data.kib_port = 0;
        for (i = 1; i <= 2; i++) {
                rc = ib_port_properties_get(kibnal_data.kib_device, i,
                                            &kibnal_data.kib_port_props);
                if (rc == 0) {
                        kibnal_data.kib_port = i;
                        break;
                }
        }
        if (kibnal_data.kib_port == 0) {
                CERROR ("Can't find a port\n");
                goto failed;
        }

        rc = ib_pd_create(kibnal_data.kib_device,
                          NULL, &kibnal_data.kib_pd);
        if (rc != 0) {
                CERROR ("Can't create PD: %d\n", rc);
                goto failed;
        }
        
        /* flag PD initialised */
        kibnal_data.kib_init = IBNAL_INIT_PD;
        /*****************************************************/
#if IBNAL_FMR
        {
                const int pool_size = IBNAL_NTX + IBNAL_NTX_NBLK;
                struct ib_fmr_pool_param params = {
                        .max_pages_per_fmr = PTL_MTU/PAGE_SIZE,
                        .access            = (IB_ACCESS_LOCAL_WRITE |
                                              IB_ACCESS_REMOTE_WRITE |
                                              IB_ACCESS_REMOTE_READ),
                        .pool_size         = pool_size,
                        .dirty_watermark   = (pool_size * 3)/4,
                        .flush_function    = NULL,
                        .flush_arg         = NULL,
                        .cache             = 1,
                };
                rc = ib_fmr_pool_create(kibnal_data.kib_pd, &params,
                                        &kibnal_data.kib_fmr_pool);
                if (rc != 0) {
                        CERROR ("Can't create FMR pool size %d: %d\n", 
                                pool_size, rc);
                        goto failed;
                }
        }

        /* flag FMR pool initialised */
        kibnal_data.kib_init = IBNAL_INIT_FMR;
#endif
        /*****************************************************/

        rc = kibnal_setup_tx_descs();
        if (rc != 0) {
                CERROR ("Can't register tx descs: %d\n", rc);
                goto failed;
        }
        
        /* flag TX descs initialised */
        kibnal_data.kib_init = IBNAL_INIT_TXD;
        /*****************************************************/
        
        {
                struct ib_cq_callback callback = {
                        .context        = IBNAL_CALLBACK_CTXT,
                        .policy         = IB_CQ_PROVIDER_REARM,
                        .function       = {
                                .entry  = kibnal_callback,
                        },
                        .arg            = NULL,
                };
                int  nentries = IBNAL_CQ_ENTRIES;
                
                rc = ib_cq_create (kibnal_data.kib_device, 
                                   &nentries, &callback, NULL,
                                   &kibnal_data.kib_cq);
                if (rc != 0) {
                        CERROR ("Can't create CQ: %d\n", rc);
                        goto failed;
                }

                /* I only want solicited events */
                rc = ib_cq_request_notification(kibnal_data.kib_cq, 1);
                LASSERT (rc == 0);
        }
        
        /* flag CQ initialised */
        kibnal_data.kib_init = IBNAL_INIT_CQ;
        /*****************************************************/
        
        rc = libcfs_nal_cmd_register(OPENIBNAL, &kibnal_cmd, NULL);
        if (rc != 0) {
                CERROR ("Can't initialise command interface (rc = %d)\n", rc);
                goto failed;
        }

        /* flag everything initialised */
        kibnal_data.kib_init = IBNAL_INIT_ALL;
        /*****************************************************/

        printk(KERN_INFO "Lustre: OpenIB NAL loaded "
               "(initial mem %d)\n", pkmem);

        return (PTL_OK);

 failed:
        kibnal_api_shutdown (&kibnal_api);    
        return (PTL_FAIL);
}

void __exit
kibnal_module_fini (void)
{
        if (kibnal_tunables.kib_sysctl != NULL)
                unregister_sysctl_table (kibnal_tunables.kib_sysctl);
        PtlNIFini(kibnal_ni);

        ptl_unregister_nal(OPENIBNAL);
}

int __init
kibnal_module_init (void)
{
        int    rc;

        /* the following must be sizeof(int) for proc_dointvec() */
        LASSERT (sizeof(kibnal_tunables.kib_io_timeout) == sizeof(int));
        LASSERT (sizeof(kibnal_tunables.kib_listener_timeout) == sizeof(int));
        LASSERT (sizeof(kibnal_tunables.kib_backlog) == sizeof(int));
        LASSERT (sizeof(kibnal_tunables.kib_port) == sizeof(int));

        kibnal_api.nal_ni_init = kibnal_api_startup;
        kibnal_api.nal_ni_fini = kibnal_api_shutdown;

        /* Initialise dynamic tunables to defaults once only */
        kibnal_tunables.kib_io_timeout = IBNAL_IO_TIMEOUT;
        kibnal_tunables.kib_listener_timeout = IBNAL_LISTENER_TIMEOUT;
        kibnal_tunables.kib_backlog = IBNAL_BACKLOG;
        kibnal_tunables.kib_port = IBNAL_PORT;

        rc = ptl_register_nal(OPENIBNAL, &kibnal_api);
        if (rc != PTL_OK) {
                CERROR("Can't register IBNAL: %d\n", rc);
                return (-ENOMEM);               /* or something... */
        }

        /* Pure gateways want the NAL started up at module load time... */
        rc = PtlNIInit(OPENIBNAL, LUSTRE_SRV_PTL_PID, NULL, NULL, &kibnal_ni);
        if (rc != PTL_OK && rc != PTL_IFACE_DUP) {
                ptl_unregister_nal(OPENIBNAL);
                return (-ENODEV);
        }
        
        kibnal_tunables.kib_sysctl = 
                register_sysctl_table (kibnal_top_ctl_table, 0);
        if (kibnal_tunables.kib_sysctl == NULL) {
                CERROR("Can't register sysctl table\n");
                PtlNIFini(kibnal_ni);
                ptl_unregister_nal(OPENIBNAL);
                return (-ENOMEM);
        }

        return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel OpenIB NAL v0.01");
MODULE_LICENSE("GPL");

module_init(kibnal_module_init);
module_exit(kibnal_module_fini);

