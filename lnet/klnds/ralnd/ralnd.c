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
#include "ranal.h"


nal_t                   kranal_api;
ptl_handle_ni_t         kranal_ni;
kra_data_t              kranal_data;
kra_tunables_t          kranal_tunables;

#define RANAL_SYSCTL_TIMEOUT           1
#define RANAL_SYSCTL_LISTENER_TIMEOUT  2
#define RANAL_SYSCTL_BACKLOG           3
#define RANAL_SYSCTL_PORT              4
#define RANAL_SYSCTL_MAX_IMMEDIATE     5

#define RANAL_SYSCTL                   202

static ctl_table kranal_ctl_table[] = {
        {RANAL_SYSCTL_TIMEOUT, "timeout", 
         &kranal_tunables.kra_timeout, sizeof(int),
         0644, NULL, &proc_dointvec},
        {RANAL_SYSCTL_LISTENER_TIMEOUT, "listener_timeout", 
         &kranal_tunables.kra_listener_timeout, sizeof(int),
         0644, NULL, &proc_dointvec},
        {RANAL_SYSCTL_BACKLOG, "backlog",
         &kranal_tunables.kra_backlog, sizeof(int),
         0644, NULL, kranal_listener_procint},
        {RANAL_SYSCTL_PORT, "port",
         &kranal_tunables.kra_port, sizeof(int),
         0644, NULL, kranal_listener_procint},
        {RANAL_SYSCTL_MAX_IMMEDIATE, "max_immediate", 
         &kranal_tunables.kra_max_immediate, sizeof(int),
         0644, NULL, &proc_dointvec},
        { 0 }
};

static ctl_table kranal_top_ctl_table[] = {
        {RANAL_SYSCTL, "ranal", NULL, 0, 0555, kranal_ctl_table},
        { 0 }
};

int
kranal_sock_write (struct socket *sock, void *buffer, int nob)
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
kranal_sock_read (struct socket *sock, void *buffer, int nob, int timeout)
{
        int            rc;
        mm_segment_t   oldmm = get_fs();
        long           ticks = timeout * HZ;
        int            wanted = nob;
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

                CDEBUG(D_WARNING, "rc %d at %d/%d bytes %d/%d secs\n",
                       rc, wanted - nob, wanted, timeout - (int)(ticks/HZ), timeout);

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
kranal_create_sock(struct socket **sockp)
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

        /* Ensure sending connection info doesn't block */
        option = 2 * sizeof(kra_connreq_t);
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
kranal_pause(int ticks)
{
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(ticks);
}

void
kranal_pack_connreq(kra_connreq_t *connreq, kra_conn_t *conn, ptl_nid_t dstnid)
{
        RAP_RETURN   rrc;

        memset(connreq, 0, sizeof(*connreq));

        connreq->racr_magic     = RANAL_MSG_MAGIC;
        connreq->racr_version   = RANAL_MSG_VERSION;
        connreq->racr_devid     = conn->rac_device->rad_id;
        connreq->racr_srcnid    = kranal_lib.libnal_ni.ni_pid.nid;
        connreq->racr_dstnid    = dstnid;
        connreq->racr_peerstamp = kranal_data.kra_peerstamp;
        connreq->racr_connstamp = conn->rac_my_connstamp;
        connreq->racr_timeout   = conn->rac_timeout;

        rrc = RapkGetRiParams(conn->rac_rihandle, &connreq->racr_riparams);
        LASSERT(rrc == RAP_SUCCESS);

        CDEBUG(D_WARNING,"devid %d, riparams: HID %08x FDH %08x PT %08x CC %08x\n",
               connreq->racr_devid,
               connreq->racr_riparams.HostId,
               connreq->racr_riparams.FmaDomainHndl,
               connreq->racr_riparams.PTag,
               connreq->racr_riparams.CompletionCookie);
}

int
kranal_recv_connreq(struct socket *sock, kra_connreq_t *connreq, int timeout)
{
        int         rc;

        rc = kranal_sock_read(sock, connreq, sizeof(*connreq), timeout);
        if (rc != 0) {
                CERROR("Read failed: %d\n", rc);
                return rc;
        }

        if (connreq->racr_magic != RANAL_MSG_MAGIC) {
                if (__swab32(connreq->racr_magic) != RANAL_MSG_MAGIC) {
                        CERROR("Unexpected magic %08x\n", connreq->racr_magic);
                        return -EPROTO;
                }

                __swab32s(&connreq->racr_magic);
                __swab16s(&connreq->racr_version);
                __swab16s(&connreq->racr_devid);
                __swab64s(&connreq->racr_srcnid);
                __swab64s(&connreq->racr_dstnid);
                __swab64s(&connreq->racr_peerstamp);
                __swab64s(&connreq->racr_connstamp);
                __swab32s(&connreq->racr_timeout);

                __swab32s(&connreq->racr_riparams.HostId);
                __swab32s(&connreq->racr_riparams.FmaDomainHndl);
                __swab32s(&connreq->racr_riparams.PTag);
                __swab32s(&connreq->racr_riparams.CompletionCookie);
        }

        if (connreq->racr_version != RANAL_MSG_VERSION) {
                CERROR("Unexpected version %d\n", connreq->racr_version);
                return -EPROTO;
        }

        if (connreq->racr_srcnid == PTL_NID_ANY ||
            connreq->racr_dstnid == PTL_NID_ANY) {
                CERROR("Received PTL_NID_ANY\n");
                return -EPROTO;
        }

        if (connreq->racr_timeout < RANAL_MIN_TIMEOUT) {
                CERROR("Received timeout %d < MIN %d\n",
                       connreq->racr_timeout, RANAL_MIN_TIMEOUT);
                return -EPROTO;
        }
        
        return 0;
}

int
kranal_close_stale_conns_locked (kra_peer_t *peer, kra_conn_t *newconn)
{
        kra_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 loopback;
        int                 count = 0;

        loopback = peer->rap_nid == kranal_lib.libnal_ni.ni_pid.nid;

        list_for_each_safe (ctmp, cnxt, &peer->rap_conns) {
                conn = list_entry(ctmp, kra_conn_t, rac_list);

                if (conn == newconn)
                        continue;

                if (conn->rac_peerstamp != newconn->rac_peerstamp) {
                        CDEBUG(D_NET, "Closing stale conn nid:"LPX64
                               " peerstamp:"LPX64"("LPX64")\n", peer->rap_nid,
                               conn->rac_peerstamp, newconn->rac_peerstamp);
                        LASSERT (conn->rac_peerstamp < newconn->rac_peerstamp);
                        count++;
                        kranal_close_conn_locked(conn, -ESTALE);
                        continue;
                }

                if (conn->rac_device != newconn->rac_device)
                        continue;
                
                if (loopback &&
                    newconn->rac_my_connstamp == conn->rac_peer_connstamp &&
                    newconn->rac_peer_connstamp == conn->rac_my_connstamp)
                        continue;
                    
                LASSERT (conn->rac_peer_connstamp < newconn->rac_peer_connstamp);

                CDEBUG(D_NET, "Closing stale conn nid:"LPX64
                       " connstamp:"LPX64"("LPX64")\n", peer->rap_nid, 
                       conn->rac_peer_connstamp, newconn->rac_peer_connstamp);

                count++;
                kranal_close_conn_locked(conn, -ESTALE);
        }

        return count;
}

int
kranal_conn_isdup_locked(kra_peer_t *peer, kra_conn_t *newconn)
{
        kra_conn_t       *conn;
        struct list_head *tmp;
        int               loopback;

        loopback = peer->rap_nid == kranal_lib.libnal_ni.ni_pid.nid;
        
        list_for_each(tmp, &peer->rap_conns) {
                conn = list_entry(tmp, kra_conn_t, rac_list);

                /* 'newconn' is from an earlier version of 'peer'!!! */
                if (newconn->rac_peerstamp < conn->rac_peerstamp)
                        return 1;

                /* 'conn' is from an earlier version of 'peer': it will be
                 * removed when we cull stale conns later on... */
                if (newconn->rac_peerstamp > conn->rac_peerstamp)
                        continue;

                /* Different devices are OK */
                if (conn->rac_device != newconn->rac_device)
                        continue;

                /* It's me connecting to myself */
                if (loopback &&
                    newconn->rac_my_connstamp == conn->rac_peer_connstamp &&
                    newconn->rac_peer_connstamp == conn->rac_my_connstamp)
                        continue;

                /* 'newconn' is an earlier connection from 'peer'!!! */
                if (newconn->rac_peer_connstamp < conn->rac_peer_connstamp)
                        return 2;
                
                /* 'conn' is an earlier connection from 'peer': it will be
                 * removed when we cull stale conns later on... */
                if (newconn->rac_peer_connstamp > conn->rac_peer_connstamp)
                        continue;
                
                /* 'newconn' has the SAME connection stamp; 'peer' isn't
                 * playing the game... */
                return 3;
        }

        return 0;
}

void
kranal_set_conn_uniqueness (kra_conn_t *conn)
{
        unsigned long  flags;

        write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        conn->rac_my_connstamp = kranal_data.kra_connstamp++;

        do {    /* allocate a unique cqid */
                conn->rac_cqid = kranal_data.kra_next_cqid++;
        } while (kranal_cqid2conn_locked(conn->rac_cqid) != NULL);
        
        write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);
}

int
kranal_create_conn(kra_conn_t **connp, kra_device_t *dev)
{
        kra_conn_t    *conn;
        RAP_RETURN     rrc;

        LASSERT (!in_interrupt());
        PORTAL_ALLOC(conn, sizeof(*conn));

        if (conn == NULL)
                return -ENOMEM;

        memset(conn, 0, sizeof(*conn));
        atomic_set(&conn->rac_refcount, 1);
        INIT_LIST_HEAD(&conn->rac_list);
        INIT_LIST_HEAD(&conn->rac_hashlist);
        INIT_LIST_HEAD(&conn->rac_schedlist);
        INIT_LIST_HEAD(&conn->rac_fmaq);
        INIT_LIST_HEAD(&conn->rac_rdmaq);
        INIT_LIST_HEAD(&conn->rac_replyq);
        spin_lock_init(&conn->rac_lock);

        kranal_set_conn_uniqueness(conn);

        conn->rac_device = dev;
        conn->rac_timeout = MAX(kranal_tunables.kra_timeout, RANAL_MIN_TIMEOUT);
        kranal_update_reaper_timeout(conn->rac_timeout);

        rrc = RapkCreateRi(dev->rad_handle, conn->rac_cqid,
                           &conn->rac_rihandle);
        if (rrc != RAP_SUCCESS) {
                CERROR("RapkCreateRi failed: %d\n", rrc);
                PORTAL_FREE(conn, sizeof(*conn));
                return -ENETDOWN;
        }

        atomic_inc(&kranal_data.kra_nconns);
        *connp = conn;
        return 0;
}

void
kranal_destroy_conn(kra_conn_t *conn) 
{
        RAP_RETURN         rrc;

        LASSERT (!in_interrupt());
        LASSERT (!conn->rac_scheduled);
        LASSERT (list_empty(&conn->rac_list));
        LASSERT (list_empty(&conn->rac_hashlist));
        LASSERT (list_empty(&conn->rac_schedlist));
        LASSERT (atomic_read(&conn->rac_refcount) == 0);
        LASSERT (list_empty(&conn->rac_fmaq));
        LASSERT (list_empty(&conn->rac_rdmaq));
        LASSERT (list_empty(&conn->rac_replyq));

        rrc = RapkDestroyRi(conn->rac_device->rad_handle,
                            conn->rac_rihandle);
        LASSERT (rrc == RAP_SUCCESS);

        if (conn->rac_peer != NULL)
                kranal_peer_decref(conn->rac_peer);

        PORTAL_FREE(conn, sizeof(*conn));
        atomic_dec(&kranal_data.kra_nconns);
}

void
kranal_terminate_conn_locked (kra_conn_t *conn)
{
        LASSERT (!in_interrupt());
        LASSERT (conn->rac_state == RANAL_CONN_CLOSING);
        LASSERT (!list_empty(&conn->rac_hashlist));
        LASSERT (list_empty(&conn->rac_list));

        /* Remove from conn hash table: no new callbacks */
        list_del_init(&conn->rac_hashlist);
        kranal_conn_decref(conn);

        conn->rac_state = RANAL_CONN_CLOSED;

        /* schedule to clear out all uncompleted comms in context of dev's
         * scheduler */
        kranal_schedule_conn(conn);
}

void
kranal_close_conn_locked (kra_conn_t *conn, int error)
{
        kra_peer_t        *peer = conn->rac_peer;

        CDEBUG(error == 0 ? D_NET : D_ERROR,
               "closing conn to "LPX64": error %d\n", peer->rap_nid, error);

        LASSERT (!in_interrupt());
        LASSERT (conn->rac_state == RANAL_CONN_ESTABLISHED);
        LASSERT (!list_empty(&conn->rac_hashlist));
        LASSERT (!list_empty(&conn->rac_list));

        list_del_init(&conn->rac_list);

        if (list_empty(&peer->rap_conns) &&
            peer->rap_persistence == 0) {
                /* Non-persistent peer with no more conns... */
                kranal_unlink_peer_locked(peer);
        }
                        
        /* Reset RX timeout to ensure we wait for an incoming CLOSE for the
         * full timeout */
        conn->rac_last_rx = jiffies;
        mb();

        conn->rac_state = RANAL_CONN_CLOSING;
        kranal_schedule_conn(conn);             /* schedule sending CLOSE */

        kranal_conn_decref(conn);               /* lose peer's ref */
}

void
kranal_close_conn (kra_conn_t *conn, int error)
{
        unsigned long    flags;
        

        write_lock_irqsave(&kranal_data.kra_global_lock, flags);
        
        if (conn->rac_state == RANAL_CONN_ESTABLISHED)
                kranal_close_conn_locked(conn, error);
        
        write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);
}

int
kranal_set_conn_params(kra_conn_t *conn, kra_connreq_t *connreq, 
                       __u32 peer_ip, int peer_port)
{
        RAP_RETURN    rrc;

        CDEBUG(D_WARNING,"devid %d, riparams: HID %08x FDH %08x PT %08x CC %08x\n",
               conn->rac_device->rad_id,
               connreq->racr_riparams.HostId,
               connreq->racr_riparams.FmaDomainHndl,
               connreq->racr_riparams.PTag,
               connreq->racr_riparams.CompletionCookie);
        
        rrc = RapkSetRiParams(conn->rac_rihandle, &connreq->racr_riparams);
        if (rrc != RAP_SUCCESS) {
                CERROR("Error setting riparams from %u.%u.%u.%u/%d: %d\n", 
                       HIPQUAD(peer_ip), peer_port, rrc);
                return -EPROTO;
        }
        
        conn->rac_peerstamp = connreq->racr_peerstamp;
        conn->rac_peer_connstamp = connreq->racr_connstamp;
        conn->rac_keepalive = RANAL_TIMEOUT2KEEPALIVE(connreq->racr_timeout);
        kranal_update_reaper_timeout(conn->rac_keepalive);
        return 0;
}

int
kranal_passive_conn_handshake (struct socket *sock, ptl_nid_t *src_nidp, 
                               ptl_nid_t *dst_nidp, kra_conn_t **connp)
{
        struct sockaddr_in   addr;
        __u32                peer_ip;
        unsigned int         peer_port;
        kra_connreq_t        rx_connreq;
        kra_connreq_t        tx_connreq;
        kra_conn_t          *conn;
        kra_device_t        *dev;
        int                  rc;
        int                  len;
        int                  i;

        CDEBUG(D_WARNING,"!!\n");

        len = sizeof(addr);
        rc = sock->ops->getname(sock, (struct sockaddr *)&addr, &len, 2);
        if (rc != 0) {
                CERROR("Can't get peer's IP: %d\n", rc);
                return rc;
        }

        peer_ip = ntohl(addr.sin_addr.s_addr);
        peer_port = ntohs(addr.sin_port);

        CDEBUG(D_WARNING,"%u.%u.%u.%u\n", HIPQUAD(peer_ip));

        if (peer_port >= 1024) {
                CERROR("Refusing unprivileged connection from %u.%u.%u.%u/%d\n",
                       HIPQUAD(peer_ip), peer_port);
                return -ECONNREFUSED;
        }

        CDEBUG(D_WARNING,"%u.%u.%u.%u\n", HIPQUAD(peer_ip));

        rc = kranal_recv_connreq(sock, &rx_connreq, 
                                 kranal_tunables.kra_listener_timeout);
        if (rc != 0) {
                CERROR("Can't rx connreq from %u.%u.%u.%u/%d: %d\n", 
                       HIPQUAD(peer_ip), peer_port, rc);
                return rc;
        }

        CDEBUG(D_WARNING,"%u.%u.%u.%u\n", HIPQUAD(peer_ip));

        for (i = 0;;i++) {
                if (i == kranal_data.kra_ndevs) {
                        CERROR("Can't match dev %d from %u.%u.%u.%u/%d\n",
                               rx_connreq.racr_devid, HIPQUAD(peer_ip), peer_port);
                        return -ENODEV;
                }
                dev = &kranal_data.kra_devices[i];
                if (dev->rad_id == rx_connreq.racr_devid)
                        break;
        }

        CDEBUG(D_WARNING,"%u.%u.%u.%u\n", HIPQUAD(peer_ip));

        rc = kranal_create_conn(&conn, dev);
        if (rc != 0)
                return rc;

        CDEBUG(D_WARNING,"%u.%u.%u.%u\n", HIPQUAD(peer_ip));

        kranal_pack_connreq(&tx_connreq, conn, rx_connreq.racr_srcnid);

        rc = kranal_sock_write(sock, &tx_connreq, sizeof(tx_connreq));
        if (rc != 0) {
                CERROR("Can't tx connreq to %u.%u.%u.%u/%d: %d\n", 
                       HIPQUAD(peer_ip), peer_port, rc);
                kranal_conn_decref(conn);
                return rc;
        }

        CDEBUG(D_WARNING,"%u.%u.%u.%u\n", HIPQUAD(peer_ip));

        rc = kranal_set_conn_params(conn, &rx_connreq, peer_ip, peer_port);
        if (rc != 0) {
                kranal_conn_decref(conn);
                return rc;
        }

        CDEBUG(D_WARNING,"%u.%u.%u.%u\n", HIPQUAD(peer_ip));

        *connp = conn;
        *src_nidp = rx_connreq.racr_srcnid;
        *dst_nidp = rx_connreq.racr_dstnid;
        return 0;
}

int
ranal_connect_sock(kra_peer_t *peer, struct socket **sockp)
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
                srvaddr.sin_port        = htons (peer->rap_port);
                srvaddr.sin_addr.s_addr = htonl (peer->rap_ip);

                rc = kranal_create_sock(&sock);
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
                               port, HIPQUAD(peer->rap_ip), peer->rap_port, rc);
                        return rc;
                }
                
                CDEBUG(D_NET, "Port %d not available for %u.%u.%u.%u/%d\n", 
                       port, HIPQUAD(peer->rap_ip), peer->rap_port);
        }

        /* all ports busy */
        return -EHOSTUNREACH;
}


int
kranal_active_conn_handshake(kra_peer_t *peer, 
                             ptl_nid_t *dst_nidp, kra_conn_t **connp)
{
        kra_connreq_t       connreq;
        kra_conn_t         *conn;
        kra_device_t       *dev;
        struct socket      *sock;
        int                 rc;
        unsigned int        idx;

        CDEBUG(D_WARNING,LPX64"\n", peer->rap_nid);

        /* spread connections over all devices using both peer NIDs to ensure
         * all nids use all devices */
        idx = peer->rap_nid + kranal_lib.libnal_ni.ni_pid.nid;
        dev = &kranal_data.kra_devices[idx % kranal_data.kra_ndevs];

        rc = kranal_create_conn(&conn, dev);
        if (rc != 0)
                return rc;

        CDEBUG(D_WARNING,LPX64"\n", peer->rap_nid);

        kranal_pack_connreq(&connreq, conn, peer->rap_nid);
        
        rc = ranal_connect_sock(peer, &sock);
        if (rc != 0)
                goto failed_0;

        CDEBUG(D_WARNING,LPX64"\n", peer->rap_nid);

        /* CAVEAT EMPTOR: the passive side receives with a SHORT rx timeout
         * immediately after accepting a connection, so we connect and then
         * send immediately. */

        rc = kranal_sock_write(sock, &connreq, sizeof(connreq));
        if (rc != 0) {
                CERROR("Can't tx connreq to %u.%u.%u.%u/%d: %d\n", 
                       HIPQUAD(peer->rap_ip), peer->rap_port, rc);
                goto failed_1;
        }

        CDEBUG(D_WARNING,LPX64"\n", peer->rap_nid);

        rc = kranal_recv_connreq(sock, &connreq, kranal_tunables.kra_timeout);
        if (rc != 0) {
                CERROR("Can't rx connreq from %u.%u.%u.%u/%d: %d\n", 
                       HIPQUAD(peer->rap_ip), peer->rap_port, rc);
                goto failed_1;
        }

        CDEBUG(D_WARNING,LPX64"\n", peer->rap_nid);

        sock_release(sock);
        rc = -EPROTO;

        if (connreq.racr_srcnid != peer->rap_nid) {
                CERROR("Unexpected srcnid from %u.%u.%u.%u/%d: "
                       "received "LPX64" expected "LPX64"\n",
                       HIPQUAD(peer->rap_ip), peer->rap_port, 
                       connreq.racr_srcnid, peer->rap_nid);
                goto failed_0;
        }

        if (connreq.racr_devid != dev->rad_id) {
                CERROR("Unexpected device id from %u.%u.%u.%u/%d: "
                       "received %d expected %d\n",
                       HIPQUAD(peer->rap_ip), peer->rap_port, 
                       connreq.racr_devid, dev->rad_id);
                goto failed_0;
        }

        CDEBUG(D_WARNING,LPX64"\n", peer->rap_nid);

        rc = kranal_set_conn_params(conn, &connreq, 
                                    peer->rap_ip, peer->rap_port);
        if (rc != 0)
                goto failed_0;

        *connp = conn;
        *dst_nidp = connreq.racr_dstnid;
        CDEBUG(D_WARNING,LPX64"\n", peer->rap_nid);
        return 0;

 failed_1:
        sock_release(sock);
 failed_0:
        kranal_conn_decref(conn);
        CDEBUG(D_WARNING,LPX64": %d\n", peer->rap_nid, rc);
        return rc;
}

int
kranal_conn_handshake (struct socket *sock, kra_peer_t *peer)
{
        kra_peer_t        *peer2;
        kra_tx_t          *tx;
        ptl_nid_t          peer_nid;
        ptl_nid_t          dst_nid;
        unsigned long      flags;
        kra_conn_t        *conn;
        int                rc;
        int                nstale;
        int                new_peer = 0;

        if (sock == NULL) {
                /* active: connd wants to connect to 'peer' */
                LASSERT (peer != NULL);
                LASSERT (peer->rap_connecting);
                
                rc = kranal_active_conn_handshake(peer, &dst_nid, &conn);
                if (rc != 0)
                        return rc;

                write_lock_irqsave(&kranal_data.kra_global_lock, flags);

                if (!kranal_peer_active(peer)) {
                        /* raced with peer getting unlinked */
                        write_unlock_irqrestore(&kranal_data.kra_global_lock, 
                                                flags);
                        kranal_conn_decref(conn);
                        return -ESTALE;
                }

                peer_nid = peer->rap_nid;
        } else {
                /* passive: listener accepted 'sock' */
                LASSERT (peer == NULL);

                rc = kranal_passive_conn_handshake(sock, &peer_nid,
                                                   &dst_nid, &conn);
                if (rc != 0)
                        return rc;

                /* assume this is a new peer */
                peer = kranal_create_peer(peer_nid);
                if (peer == NULL) {
                        CERROR("Can't allocate peer for "LPX64"\n", peer_nid);
                        kranal_conn_decref(conn);
                        return -ENOMEM;
                }

                write_lock_irqsave(&kranal_data.kra_global_lock, flags);

                peer2 = kranal_find_peer_locked(peer_nid);
                if (peer2 == NULL) {
                        new_peer = 1;
                } else {
                        /* peer_nid already in the peer table */
                        kranal_peer_decref(peer);
                        peer = peer2;
                }
        }

        LASSERT (!new_peer == !kranal_peer_active(peer));

        /* Refuse connection if peer thinks we are a different NID.  We check
         * this while holding the global lock, to synch with connection
         * destruction on NID change. */
        if (dst_nid != kranal_lib.libnal_ni.ni_pid.nid) {
                write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

                CERROR("Stale/bad connection with "LPX64
                       ": dst_nid "LPX64", expected "LPX64"\n",
                       peer_nid, dst_nid, kranal_lib.libnal_ni.ni_pid.nid);
                rc = -ESTALE;
                goto failed;
        }

        /* Refuse to duplicate an existing connection (both sides might try to
         * connect at once).  NB we return success!  We _are_ connected so we
         * _don't_ have any blocked txs to complete with failure. */
        rc = kranal_conn_isdup_locked(peer, conn);
        if (rc != 0) {
                LASSERT (!list_empty(&peer->rap_conns));
                LASSERT (list_empty(&peer->rap_tx_queue));
                write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);
                CWARN("Not creating duplicate connection to "LPX64": %d\n",
                      peer_nid, rc);
                rc = 0;
                goto failed;
        }

        if (new_peer) {
                /* peer table takes my ref on the new peer */
                list_add_tail(&peer->rap_list,
                              kranal_nid2peerlist(peer_nid));
        }
        
        kranal_peer_addref(peer);               /* +1 ref for conn */
        conn->rac_peer = peer;
        list_add_tail(&conn->rac_list, &peer->rap_conns);

        kranal_conn_addref(conn);               /* +1 ref for conn table */
        list_add_tail(&conn->rac_hashlist,
                      kranal_cqid2connlist(conn->rac_cqid));

        /* Schedule all packets blocking for a connection */
        while (!list_empty(&peer->rap_tx_queue)) {
                tx = list_entry(peer->rap_tx_queue.next,
                                kra_tx_t, tx_list);

                list_del(&tx->tx_list);
                kranal_post_fma(conn, tx);
        }

        nstale = kranal_close_stale_conns_locked(peer, conn);

        write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

        /* CAVEAT EMPTOR: passive peer can disappear NOW */

        if (nstale != 0)
                CWARN("Closed %d stale conns to "LPX64"\n", nstale, peer_nid);

        /* Ensure conn gets checked.  Transmits may have been queued and an
         * FMA event may have happened before it got in the cq hash table */
        kranal_schedule_conn(conn);
        return 0;

 failed:
        if (new_peer)
                kranal_peer_decref(peer);
        kranal_conn_decref(conn);
        return rc;
}

void
kranal_connect (kra_peer_t *peer)
{
        kra_tx_t          *tx;
        unsigned long      flags;
        struct list_head   zombies;
        int                rc;

        LASSERT (peer->rap_connecting);

        CDEBUG(D_WARNING,"About to handshake "LPX64"\n", peer->rap_nid);

        rc = kranal_conn_handshake(NULL, peer);

        CDEBUG(D_WARNING,"Done handshake "LPX64":%d \n", peer->rap_nid, rc);

        write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        LASSERT (peer->rap_connecting);
        peer->rap_connecting = 0;

        if (rc == 0) {
                /* kranal_conn_handshake() queues blocked txs immediately on
                 * success to avoid messages jumping the queue */
                LASSERT (list_empty(&peer->rap_tx_queue));

                /* reset reconnection timeouts */
                peer->rap_reconnect_interval = RANAL_MIN_RECONNECT_INTERVAL;
                peer->rap_reconnect_time = CURRENT_SECONDS;

                write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);
                return;
        }

        LASSERT (peer->rap_reconnect_interval != 0);
        peer->rap_reconnect_time = CURRENT_SECONDS + peer->rap_reconnect_interval;
        peer->rap_reconnect_interval = MAX(RANAL_MAX_RECONNECT_INTERVAL,
                                           1 * peer->rap_reconnect_interval);

        /* Grab all blocked packets while we have the global lock */
        list_add(&zombies, &peer->rap_tx_queue);
        list_del_init(&peer->rap_tx_queue);

        write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

        if (list_empty(&zombies))
                return;

        CWARN("Dropping packets for "LPX64": connection failed\n",
              peer->rap_nid);

        do {
                tx = list_entry(zombies.next, kra_tx_t, tx_list);

                list_del(&tx->tx_list);
                kranal_tx_done(tx, -EHOSTUNREACH);

        } while (!list_empty(&zombies));
}

void
kranal_free_acceptsock (kra_acceptsock_t *ras)
{
        sock_release(ras->ras_sock);
        PORTAL_FREE(ras, sizeof(*ras));
}

int
kranal_listener (void *arg)
{
        struct sockaddr_in addr;
        wait_queue_t       wait;
        struct socket     *sock;
        kra_acceptsock_t  *ras;
        int                port;
        char               name[16];
        int                rc;
        unsigned long      flags;

        /* Parent thread holds kra_nid_mutex, and is, or is about to
         * block on kra_listener_signal */

        port = kranal_tunables.kra_port;
        snprintf(name, sizeof(name), "kranal_lstn%03d", port);
        kportal_daemonize(name);
        kportal_blockallsigs();

        init_waitqueue_entry(&wait, current);

        rc = kranal_create_sock(&sock);
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

        rc = sock->ops->listen(sock, kranal_tunables.kra_backlog);
        if (rc != 0) {
                CERROR("Can't set listen backlog %d: %d\n", 
                       kranal_tunables.kra_backlog, rc);
                goto out_1;
        }

        LASSERT (kranal_data.kra_listener_sock == NULL);
        kranal_data.kra_listener_sock = sock;

        /* unblock waiting parent */
        LASSERT (kranal_data.kra_listener_shutdown == 0);
        up(&kranal_data.kra_listener_signal);

        /* Wake me any time something happens on my socket */
        add_wait_queue(sock->sk->sk_sleep, &wait);
        ras = NULL;

        while (kranal_data.kra_listener_shutdown == 0) {

                if (ras == NULL) {
                        PORTAL_ALLOC(ras, sizeof(*ras));
                        if (ras == NULL) {
                                CERROR("Out of Memory: pausing...\n");
                                kranal_pause(HZ);
                                continue;
                        }
                        ras->ras_sock = NULL;
                }

                if (ras->ras_sock == NULL) {
                        ras->ras_sock = sock_alloc();
                        if (ras->ras_sock == NULL) {
                                CERROR("Can't allocate socket: pausing...\n");
                                kranal_pause(HZ);
                                continue;
                        }
                        /* XXX this should add a ref to sock->ops->owner, if
                         * TCP could be a module */
                        ras->ras_sock->type = sock->type;
                        ras->ras_sock->ops = sock->ops;
                }
                
                set_current_state(TASK_INTERRUPTIBLE);

                rc = sock->ops->accept(sock, ras->ras_sock, O_NONBLOCK);

                /* Sleep for socket activity? */
                if (rc == -EAGAIN &&
                    kranal_data.kra_listener_shutdown == 0)
                        schedule();

                set_current_state(TASK_RUNNING);

                if (rc == 0) {
                        spin_lock_irqsave(&kranal_data.kra_connd_lock, flags);
                        
                        list_add_tail(&ras->ras_list, 
                                      &kranal_data.kra_connd_acceptq);

                        spin_unlock_irqrestore(&kranal_data.kra_connd_lock, flags);
                        wake_up(&kranal_data.kra_connd_waitq);

                        ras = NULL;
                        continue;
                }
                
                if (rc != -EAGAIN) {
                        CERROR("Accept failed: %d, pausing...\n", rc);
                        kranal_pause(HZ);
                }
        }

        if (ras != NULL) {
                if (ras->ras_sock != NULL)
                        sock_release(ras->ras_sock);
                PORTAL_FREE(ras, sizeof(*ras));
        }

        rc = 0;
        remove_wait_queue(sock->sk->sk_sleep, &wait);
 out_1:
        sock_release(sock);
        kranal_data.kra_listener_sock = NULL;
 out_0:
        /* set completion status and unblock thread waiting for me 
         * (parent on startup failure, executioner on normal shutdown) */
        kranal_data.kra_listener_shutdown = rc;
        up(&kranal_data.kra_listener_signal);

        return 0;
}

int
kranal_start_listener (void)
{
        long           pid;
        int            rc;

        CDEBUG(D_WARNING, "Starting listener\n");

        /* Called holding kra_nid_mutex: listener stopped */
        LASSERT (kranal_data.kra_listener_sock == NULL);

        kranal_data.kra_listener_shutdown = 0;
        pid = kernel_thread(kranal_listener, NULL, 0);
        if (pid < 0) {
                CERROR("Can't spawn listener: %ld\n", pid);
                return (int)pid;
        }

        /* Block until listener has started up. */
        down(&kranal_data.kra_listener_signal);

        rc = kranal_data.kra_listener_shutdown;
        LASSERT ((rc != 0) == (kranal_data.kra_listener_sock == NULL));

        CDEBUG(D_WARNING, "Listener %ld started OK\n", pid);
        return rc;
}

void
kranal_stop_listener(int clear_acceptq)
{
        struct list_head  zombie_accepts;
        unsigned long     flags;
        kra_acceptsock_t *ras;

        CDEBUG(D_WARNING, "Stopping listener\n");

        /* Called holding kra_nid_mutex: listener running */
        LASSERT (kranal_data.kra_listener_sock != NULL);

        kranal_data.kra_listener_shutdown = 1;
        wake_up_all(kranal_data.kra_listener_sock->sk->sk_sleep);

        /* Block until listener has torn down. */
        down(&kranal_data.kra_listener_signal);

        LASSERT (kranal_data.kra_listener_sock == NULL);
        CDEBUG(D_WARNING, "Listener stopped\n");

        if (!clear_acceptq)
                return;
        
        /* Close any unhandled accepts */
        spin_lock_irqsave(&kranal_data.kra_connd_lock, flags);

        list_add(&zombie_accepts, &kranal_data.kra_connd_acceptq);
        list_del_init(&kranal_data.kra_connd_acceptq);

        spin_unlock_irqrestore(&kranal_data.kra_connd_lock, flags);
        
        while (!list_empty(&zombie_accepts)) {
                ras = list_entry(zombie_accepts.next, 
                                 kra_acceptsock_t, ras_list);
                list_del(&ras->ras_list);
                kranal_free_acceptsock(ras);
        }
}

int 
kranal_listener_procint(ctl_table *table, int write, struct file *filp,
                        void *buffer, size_t *lenp)
{
        int   *tunable = (int *)table->data;
        int    old_val;
        int    rc;

        /* No race with nal initialisation since the nal is setup all the time
         * it's loaded.  When that changes, change this! */
        LASSERT (kranal_data.kra_init == RANAL_INIT_ALL);

        down(&kranal_data.kra_nid_mutex);

        LASSERT (tunable == &kranal_tunables.kra_port ||
                 tunable == &kranal_tunables.kra_backlog);
        old_val = *tunable;

        rc = proc_dointvec(table, write, filp, buffer, lenp);

        if (write &&
            (*tunable != old_val ||
             kranal_data.kra_listener_sock == NULL)) {

                if (kranal_data.kra_listener_sock != NULL)
                        kranal_stop_listener(0);

                rc = kranal_start_listener();

                if (rc != 0) {
                        CWARN("Unable to start listener with new tunable:"
                              " reverting to old value\n");
                        *tunable = old_val;
                        kranal_start_listener();
                }
        }

        up(&kranal_data.kra_nid_mutex);

        LASSERT (kranal_data.kra_init == RANAL_INIT_ALL);
        return rc;
}

int
kranal_set_mynid(ptl_nid_t nid)
{
        unsigned long    flags;
        lib_ni_t        *ni = &kranal_lib.libnal_ni;
        int              rc = 0;

        CDEBUG(D_NET, "setting mynid to "LPX64" (old nid="LPX64")\n",
               nid, ni->ni_pid.nid);

        down(&kranal_data.kra_nid_mutex);

        if (nid == ni->ni_pid.nid) {
                /* no change of NID */
                up(&kranal_data.kra_nid_mutex);
                return 0;
        }

        if (kranal_data.kra_listener_sock != NULL)
                kranal_stop_listener(1);

        write_lock_irqsave(&kranal_data.kra_global_lock, flags);
        kranal_data.kra_peerstamp++;
        ni->ni_pid.nid = nid;
        write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);
        
        /* Delete all existing peers and their connections after new
         * NID/connstamp set to ensure no old connections in our brave
         * new world. */
        kranal_del_peer(PTL_NID_ANY, 0);

        if (nid != PTL_NID_ANY)
                rc = kranal_start_listener();

        up(&kranal_data.kra_nid_mutex);
        return rc;
}

kra_peer_t *
kranal_create_peer (ptl_nid_t nid)
{
        kra_peer_t *peer;

        LASSERT (nid != PTL_NID_ANY);

        PORTAL_ALLOC(peer, sizeof(*peer));
        if (peer == NULL)
                return NULL;

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        peer->rap_nid = nid;
        atomic_set(&peer->rap_refcount, 1);     /* 1 ref for caller */

        INIT_LIST_HEAD(&peer->rap_list);
        INIT_LIST_HEAD(&peer->rap_connd_list);
        INIT_LIST_HEAD(&peer->rap_conns);
        INIT_LIST_HEAD(&peer->rap_tx_queue);

        peer->rap_reconnect_time = CURRENT_SECONDS;
        peer->rap_reconnect_interval = RANAL_MIN_RECONNECT_INTERVAL;

        atomic_inc(&kranal_data.kra_npeers);
        return peer;
}

void
kranal_destroy_peer (kra_peer_t *peer)
{
        CDEBUG(D_NET, "peer "LPX64" %p deleted\n", peer->rap_nid, peer);

        LASSERT (atomic_read(&peer->rap_refcount) == 0);
        LASSERT (peer->rap_persistence == 0);
        LASSERT (!kranal_peer_active(peer));
        LASSERT (!peer->rap_connecting);
        LASSERT (list_empty(&peer->rap_conns));
        LASSERT (list_empty(&peer->rap_tx_queue));
        LASSERT (list_empty(&peer->rap_connd_list));

        PORTAL_FREE(peer, sizeof(*peer));

        /* NB a peer's connections keep a reference on their peer until
         * they are destroyed, so we can be assured that _all_ state to do
         * with this peer has been cleaned up when its refcount drops to
         * zero. */
        atomic_dec(&kranal_data.kra_npeers);
}

kra_peer_t *
kranal_find_peer_locked (ptl_nid_t nid)
{
        struct list_head *peer_list = kranal_nid2peerlist(nid);
        struct list_head *tmp;
        kra_peer_t       *peer;

        list_for_each (tmp, peer_list) {

                peer = list_entry(tmp, kra_peer_t, rap_list);

                LASSERT (peer->rap_persistence > 0 ||     /* persistent peer */
                         !list_empty(&peer->rap_conns));  /* active conn */

                if (peer->rap_nid != nid)
                        continue;

                CDEBUG(D_NET, "got peer [%p] -> "LPX64" (%d)\n",
                       peer, nid, atomic_read(&peer->rap_refcount));
                return peer;
        }
        return NULL;
}

kra_peer_t *
kranal_find_peer (ptl_nid_t nid)
{
        kra_peer_t     *peer;

        read_lock(&kranal_data.kra_global_lock);
        peer = kranal_find_peer_locked(nid);
        if (peer != NULL)                       /* +1 ref for caller? */
                kranal_peer_addref(peer);
        read_unlock(&kranal_data.kra_global_lock);

        return peer;
}

void
kranal_unlink_peer_locked (kra_peer_t *peer)
{
        LASSERT (peer->rap_persistence == 0);
        LASSERT (list_empty(&peer->rap_conns));

        LASSERT (kranal_peer_active(peer));
        list_del_init(&peer->rap_list);

        /* lose peerlist's ref */
        kranal_peer_decref(peer);
}

int
kranal_get_peer_info (int index, ptl_nid_t *nidp, __u32 *ipp, int *portp, 
                      int *persistencep)
{
        kra_peer_t        *peer;
        struct list_head  *ptmp;
        int                i;

        read_lock(&kranal_data.kra_global_lock);

        for (i = 0; i < kranal_data.kra_peer_hash_size; i++) {

                list_for_each(ptmp, &kranal_data.kra_peers[i]) {

                        peer = list_entry(ptmp, kra_peer_t, rap_list);
                        LASSERT (peer->rap_persistence > 0 ||
                                 !list_empty(&peer->rap_conns));

                        if (index-- > 0)
                                continue;

                        *nidp = peer->rap_nid;
                        *ipp = peer->rap_ip;
                        *portp = peer->rap_port;
                        *persistencep = peer->rap_persistence;

                        read_unlock(&kranal_data.kra_global_lock);
                        return 0;
                }
        }

        read_unlock(&kranal_data.kra_global_lock);
        return -ENOENT;
}

int
kranal_add_persistent_peer (ptl_nid_t nid, __u32 ip, int port)
{
        unsigned long      flags;
        kra_peer_t        *peer;
        kra_peer_t        *peer2;

        if (nid == PTL_NID_ANY)
                return -EINVAL;

        peer = kranal_create_peer(nid);
        if (peer == NULL)
                return -ENOMEM;

        write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        peer2 = kranal_find_peer_locked(nid);
        if (peer2 != NULL) {
                kranal_peer_decref(peer);
                peer = peer2;
        } else {
                /* peer table takes existing ref on peer */
                list_add_tail(&peer->rap_list,
                              kranal_nid2peerlist(nid));
        }

        peer->rap_ip = ip;
        peer->rap_port = port;
        peer->rap_persistence++;

        write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);
        return 0;
}

void
kranal_del_peer_locked (kra_peer_t *peer, int single_share)
{
        struct list_head *ctmp;
        struct list_head *cnxt;
        kra_conn_t       *conn;

        if (!single_share)
                peer->rap_persistence = 0;
        else if (peer->rap_persistence > 0)
                peer->rap_persistence--;

        if (peer->rap_persistence != 0)
                return;

        if (list_empty(&peer->rap_conns)) {
                kranal_unlink_peer_locked(peer);
        } else {
                list_for_each_safe(ctmp, cnxt, &peer->rap_conns) {
                        conn = list_entry(ctmp, kra_conn_t, rac_list);

                        kranal_close_conn_locked(conn, 0);
                }
                /* peer unlinks itself when last conn is closed */
        }
}

int
kranal_del_peer (ptl_nid_t nid, int single_share)
{
        unsigned long      flags;
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        kra_peer_t        *peer;
        int                lo;
        int                hi;
        int                i;
        int                rc = -ENOENT;

        write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        if (nid != PTL_NID_ANY)
                lo = hi = kranal_nid2peerlist(nid) - kranal_data.kra_peers;
        else {
                lo = 0;
                hi = kranal_data.kra_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kranal_data.kra_peers[i]) {
                        peer = list_entry(ptmp, kra_peer_t, rap_list);
                        LASSERT (peer->rap_persistence > 0 ||
                                 !list_empty(&peer->rap_conns));

                        if (!(nid == PTL_NID_ANY || peer->rap_nid == nid))
                                continue;

                        kranal_del_peer_locked(peer, single_share);
                        rc = 0;         /* matched something */

                        if (single_share)
                                goto out;
                }
        }
 out:
        write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

        return rc;
}

kra_conn_t *
kranal_get_conn_by_idx (int index)
{
        kra_peer_t        *peer;
        struct list_head  *ptmp;
        kra_conn_t        *conn;
        struct list_head  *ctmp;
        int                i;

        read_lock (&kranal_data.kra_global_lock);

        for (i = 0; i < kranal_data.kra_peer_hash_size; i++) {
                list_for_each (ptmp, &kranal_data.kra_peers[i]) {

                        peer = list_entry(ptmp, kra_peer_t, rap_list);
                        LASSERT (peer->rap_persistence > 0 ||
                                 !list_empty(&peer->rap_conns));

                        list_for_each (ctmp, &peer->rap_conns) {
                                if (index-- > 0)
                                        continue;

                                conn = list_entry(ctmp, kra_conn_t, rac_list);
                                CDEBUG(D_NET, "++conn[%p] -> "LPX64" (%d)\n",
                                       conn, conn->rac_peer->rap_nid,
                                       atomic_read(&conn->rac_refcount));
                                atomic_inc(&conn->rac_refcount);
                                read_unlock(&kranal_data.kra_global_lock);
                                return conn;
                        }
                }
        }

        read_unlock(&kranal_data.kra_global_lock);
        return NULL;
}

int
kranal_close_peer_conns_locked (kra_peer_t *peer, int why)
{
        kra_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->rap_conns) {
                conn = list_entry(ctmp, kra_conn_t, rac_list);

                count++;
                kranal_close_conn_locked(conn, why);
        }

        return count;
}

int
kranal_close_matching_conns (ptl_nid_t nid)
{
        unsigned long       flags;
        kra_peer_t         *peer;
        struct list_head   *ptmp;
        struct list_head   *pnxt;
        int                 lo;
        int                 hi;
        int                 i;
        int                 count = 0;

        write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        if (nid != PTL_NID_ANY)
                lo = hi = kranal_nid2peerlist(nid) - kranal_data.kra_peers;
        else {
                lo = 0;
                hi = kranal_data.kra_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kranal_data.kra_peers[i]) {

                        peer = list_entry(ptmp, kra_peer_t, rap_list);
                        LASSERT (peer->rap_persistence > 0 ||
                                 !list_empty(&peer->rap_conns));

                        if (!(nid == PTL_NID_ANY || nid == peer->rap_nid))
                                continue;

                        count += kranal_close_peer_conns_locked(peer, 0);
                }
        }

        write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

        /* wildcards always succeed */
        if (nid == PTL_NID_ANY)
                return 0;

        return (count == 0) ? -ENOENT : 0;
}

int
kranal_cmd(struct portals_cfg *pcfg, void * private)
{
        int rc = -EINVAL;

        LASSERT (pcfg != NULL);

        switch(pcfg->pcfg_command) {
        case NAL_CMD_GET_PEER: {
                ptl_nid_t   nid = 0;
                __u32       ip = 0;
                int         port = 0;
                int         share_count = 0;

                rc = kranal_get_peer_info(pcfg->pcfg_count,
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
                rc = kranal_add_persistent_peer(pcfg->pcfg_nid,
                                                pcfg->pcfg_id, /* IP */
                                                pcfg->pcfg_misc); /* port */
                break;
        }
        case NAL_CMD_DEL_PEER: {
                rc = kranal_del_peer(pcfg->pcfg_nid, 
                                     /* flags == single_share */
                                     pcfg->pcfg_flags != 0);
                break;
        }
        case NAL_CMD_GET_CONN: {
                kra_conn_t *conn = kranal_get_conn_by_idx(pcfg->pcfg_count);

                if (conn == NULL)
                        rc = -ENOENT;
                else {
                        rc = 0;
                        pcfg->pcfg_nid   = conn->rac_peer->rap_nid;
                        pcfg->pcfg_id    = conn->rac_device->rad_id;
                        pcfg->pcfg_misc  = 0;
                        pcfg->pcfg_flags = 0;
                        kranal_conn_decref(conn);
                }
                break;
        }
        case NAL_CMD_CLOSE_CONNECTION: {
                rc = kranal_close_matching_conns(pcfg->pcfg_nid);
                break;
        }
        case NAL_CMD_REGISTER_MYNID: {
                if (pcfg->pcfg_nid == PTL_NID_ANY)
                        rc = -EINVAL;
                else
                        rc = kranal_set_mynid(pcfg->pcfg_nid);
                break;
        }
        }

        return rc;
}

void
kranal_free_txdescs(struct list_head *freelist)
{
        kra_tx_t    *tx;

        while (!list_empty(freelist)) {
                tx = list_entry(freelist->next, kra_tx_t, tx_list);

                list_del(&tx->tx_list);
                PORTAL_FREE(tx->tx_phys, PTL_MD_MAX_IOV * sizeof(*tx->tx_phys));
                PORTAL_FREE(tx, sizeof(*tx));
        }
}

int
kranal_alloc_txdescs(struct list_head *freelist, int n)
{
        int            isnblk = (freelist == &kranal_data.kra_idle_nblk_txs);
        int            i;
        kra_tx_t      *tx;

        LASSERT (freelist == &kranal_data.kra_idle_txs ||
                 freelist == &kranal_data.kra_idle_nblk_txs);
        LASSERT (list_empty(freelist));

        for (i = 0; i < n; i++) {

                PORTAL_ALLOC(tx, sizeof(*tx));
                if (tx == NULL) {
                        CERROR("Can't allocate %stx[%d]\n",
                               isnblk ? "nblk " : "", i);
                        kranal_free_txdescs(freelist);
                        return -ENOMEM;
                }

                PORTAL_ALLOC(tx->tx_phys,
                             PTL_MD_MAX_IOV * sizeof(*tx->tx_phys));
                if (tx->tx_phys == NULL) {
                        CERROR("Can't allocate %stx[%d]->tx_phys\n", 
                               isnblk ? "nblk " : "", i);

                        PORTAL_FREE(tx, sizeof(*tx));
                        kranal_free_txdescs(freelist);
                        return -ENOMEM;
                }

                tx->tx_isnblk = isnblk;
                tx->tx_buftype = RANAL_BUF_NONE;
                tx->tx_msg.ram_type = RANAL_MSG_NONE;

                list_add(&tx->tx_list, freelist);
        }

        return 0;
}

int
kranal_device_init(int id, kra_device_t *dev)
{
        const int         total_ntx = RANAL_NTX + RANAL_NTX_NBLK;
        RAP_RETURN        rrc;

        dev->rad_id = id;
        rrc = RapkGetDeviceByIndex(id, kranal_device_callback,
                                   &dev->rad_handle);
        if (rrc != RAP_SUCCESS) {
                CERROR("Can't get Rapidarray Device %d: %d\n", id, rrc);
                goto failed_0;
        }

        rrc = RapkReserveRdma(dev->rad_handle, total_ntx);
        if (rrc != RAP_SUCCESS) {
                CERROR("Can't reserve %d RDMA descriptors"
                       " for device %d: %d\n", total_ntx, id, rrc);
                goto failed_1;
        }

        rrc = RapkCreateCQ(dev->rad_handle, total_ntx, RAP_CQTYPE_SEND,
                           &dev->rad_rdma_cqh);
        if (rrc != RAP_SUCCESS) {
                CERROR("Can't create rdma cq size %d"
                       " for device %d: %d\n", total_ntx, id, rrc);
                goto failed_1;
        }

        rrc = RapkCreateCQ(dev->rad_handle, RANAL_FMA_CQ_SIZE, RAP_CQTYPE_RECV,
                           &dev->rad_fma_cqh);
        if (rrc != RAP_SUCCESS) {
                CERROR("Can't create fma cq size %d"
                       " for device %d: %d\n", RANAL_FMA_CQ_SIZE, id, rrc);
                goto failed_2;
        }

        return 0;

 failed_2:
        RapkDestroyCQ(dev->rad_handle, dev->rad_rdma_cqh);
 failed_1:
        RapkReleaseDevice(dev->rad_handle);
 failed_0:
        return -ENODEV;
}

void
kranal_device_fini(kra_device_t *dev)
{
        LASSERT(dev->rad_scheduler == NULL);
        RapkDestroyCQ(dev->rad_handle, dev->rad_fma_cqh);
        RapkDestroyCQ(dev->rad_handle, dev->rad_rdma_cqh);
        RapkReleaseDevice(dev->rad_handle);
}

void
kranal_api_shutdown (nal_t *nal)
{
        int           i;
        unsigned long flags;
        
        if (nal->nal_refct != 0) {
                /* This module got the first ref */
                PORTAL_MODULE_UNUSE;
                return;
        }

        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read(&portal_kmemory));

        LASSERT (nal == &kranal_api);

        switch (kranal_data.kra_init) {
        default:
                CERROR("Unexpected state %d\n", kranal_data.kra_init);
                LBUG();

        case RANAL_INIT_ALL:
                /* stop calls to nal_cmd */
                libcfs_nal_cmd_unregister(RANAL);
                /* No new persistent peers */

                /* resetting my NID to unadvertises me, removes my
                 * listener and nukes all current peers */
                kranal_set_mynid(PTL_NID_ANY);
                /* no new peers or conns */

                /* Wait for all peer/conn state to clean up */
                i = 2;
                while (atomic_read(&kranal_data.kra_nconns) != 0 ||
                       atomic_read(&kranal_data.kra_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "waiting for %d peers and %d conns to close down\n",
                               atomic_read(&kranal_data.kra_npeers),
                               atomic_read(&kranal_data.kra_nconns));
                        kranal_pause(HZ);
                }
                /* fall through */

        case RANAL_INIT_LIB:
                lib_fini(&kranal_lib);
                /* fall through */

        case RANAL_INIT_DATA:
                break;
        }

        /* flag threads to terminate; wake and wait for them to die */
        kranal_data.kra_shutdown = 1;

        for (i = 0; i < kranal_data.kra_ndevs; i++) {
                kra_device_t *dev = &kranal_data.kra_devices[i];

                LASSERT (list_empty(&dev->rad_connq));

                spin_lock_irqsave(&dev->rad_lock, flags);
                wake_up(&dev->rad_waitq);
                spin_unlock_irqrestore(&dev->rad_lock, flags);
        }

        spin_lock_irqsave(&kranal_data.kra_reaper_lock, flags);
        wake_up_all(&kranal_data.kra_reaper_waitq);
        spin_unlock_irqrestore(&kranal_data.kra_reaper_lock, flags);

        LASSERT (list_empty(&kranal_data.kra_connd_peers));
        spin_lock_irqsave(&kranal_data.kra_connd_lock, flags); 
        wake_up_all(&kranal_data.kra_connd_waitq);
        spin_unlock_irqrestore(&kranal_data.kra_connd_lock, flags); 

        i = 2;
        while (atomic_read(&kranal_data.kra_nthreads) != 0) {
                i++;
                CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                       "Waiting for %d threads to terminate\n",
                       atomic_read(&kranal_data.kra_nthreads));
                kranal_pause(HZ);
        }

        LASSERT (atomic_read(&kranal_data.kra_npeers) == 0);
        if (kranal_data.kra_peers != NULL) {
                for (i = 0; i < kranal_data.kra_peer_hash_size; i++)
                        LASSERT (list_empty(&kranal_data.kra_peers[i]));

                PORTAL_FREE(kranal_data.kra_peers,
                            sizeof (struct list_head) * 
                            kranal_data.kra_peer_hash_size);
        }

        LASSERT (atomic_read(&kranal_data.kra_nconns) == 0);
        if (kranal_data.kra_conns != NULL) {
                for (i = 0; i < kranal_data.kra_conn_hash_size; i++)
                        LASSERT (list_empty(&kranal_data.kra_conns[i]));

                PORTAL_FREE(kranal_data.kra_conns,
                            sizeof (struct list_head) * 
                            kranal_data.kra_conn_hash_size);
        }

        for (i = 0; i < kranal_data.kra_ndevs; i++)
                kranal_device_fini(&kranal_data.kra_devices[i]);

        kranal_free_txdescs(&kranal_data.kra_idle_txs);
        kranal_free_txdescs(&kranal_data.kra_idle_nblk_txs);

        CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
               atomic_read(&portal_kmemory));
        printk(KERN_INFO "Lustre: RapidArray NAL unloaded (final mem %d)\n",
               atomic_read(&portal_kmemory));

        kranal_data.kra_init = RANAL_INIT_NOTHING;
}

int
kranal_api_startup (nal_t *nal, ptl_pid_t requested_pid,
                    ptl_ni_limits_t *requested_limits,
                    ptl_ni_limits_t *actual_limits)
{
        static int        device_ids[] = {RAPK_MAIN_DEVICE_ID,
                                          RAPK_EXPANSION_DEVICE_ID};
        struct timeval    tv;
        ptl_process_id_t  process_id;
        int               pkmem = atomic_read(&portal_kmemory);
        int               rc;
        int               i;
        kra_device_t     *dev;

        LASSERT (nal == &kranal_api);

        if (nal->nal_refct != 0) {
                if (actual_limits != NULL)
                        *actual_limits = kranal_lib.libnal_ni.ni_actual_limits;
                /* This module got the first ref */
                PORTAL_MODULE_USE;
                return PTL_OK;
        }

        LASSERT (kranal_data.kra_init == RANAL_INIT_NOTHING);

        memset(&kranal_data, 0, sizeof(kranal_data)); /* zero pointers, flags etc */

        /* CAVEAT EMPTOR: Every 'Fma' message includes the sender's NID and
         * a unique (for all time) connstamp so we can uniquely identify
         * the sender.  The connstamp is an incrementing counter
         * initialised with seconds + microseconds at startup time.  So we
         * rely on NOT creating connections more frequently on average than
         * 1MHz to ensure we don't use old connstamps when we reboot. */
        do_gettimeofday(&tv);
        kranal_data.kra_connstamp =
        kranal_data.kra_peerstamp = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

        init_MUTEX(&kranal_data.kra_nid_mutex);
        init_MUTEX_LOCKED(&kranal_data.kra_listener_signal);

        rwlock_init(&kranal_data.kra_global_lock);

        for (i = 0; i < RANAL_MAXDEVS; i++ ) {
                kra_device_t  *dev = &kranal_data.kra_devices[i];

                dev->rad_idx = i;
                INIT_LIST_HEAD(&dev->rad_connq);
                init_waitqueue_head(&dev->rad_waitq);
                spin_lock_init(&dev->rad_lock);
        }

        kranal_data.kra_new_min_timeout = MAX_SCHEDULE_TIMEOUT;
        init_waitqueue_head(&kranal_data.kra_reaper_waitq);
        spin_lock_init(&kranal_data.kra_reaper_lock);

        INIT_LIST_HEAD(&kranal_data.kra_connd_acceptq);
        INIT_LIST_HEAD(&kranal_data.kra_connd_peers);
        init_waitqueue_head(&kranal_data.kra_connd_waitq);
        spin_lock_init(&kranal_data.kra_connd_lock);

        INIT_LIST_HEAD(&kranal_data.kra_idle_txs);
        INIT_LIST_HEAD(&kranal_data.kra_idle_nblk_txs);
        init_waitqueue_head(&kranal_data.kra_idle_tx_waitq);
        spin_lock_init(&kranal_data.kra_tx_lock);

        /* OK to call kranal_api_shutdown() to cleanup now */
        kranal_data.kra_init = RANAL_INIT_DATA;
        
        kranal_data.kra_peer_hash_size = RANAL_PEER_HASH_SIZE;
        PORTAL_ALLOC(kranal_data.kra_peers,
                     sizeof(struct list_head) * kranal_data.kra_peer_hash_size);
        if (kranal_data.kra_peers == NULL)
                goto failed;

        for (i = 0; i < kranal_data.kra_peer_hash_size; i++)
                INIT_LIST_HEAD(&kranal_data.kra_peers[i]);

        kranal_data.kra_conn_hash_size = RANAL_PEER_HASH_SIZE;
        PORTAL_ALLOC(kranal_data.kra_conns,
                     sizeof(struct list_head) * kranal_data.kra_conn_hash_size);
        if (kranal_data.kra_conns == NULL)
                goto failed;

        for (i = 0; i < kranal_data.kra_conn_hash_size; i++)
                INIT_LIST_HEAD(&kranal_data.kra_conns[i]);

        rc = kranal_alloc_txdescs(&kranal_data.kra_idle_txs, RANAL_NTX);
        if (rc != 0)
                goto failed;

        rc = kranal_alloc_txdescs(&kranal_data.kra_idle_nblk_txs,RANAL_NTX_NBLK);
        if (rc != 0)
                goto failed;

        process_id.pid = requested_pid;
        process_id.nid = PTL_NID_ANY;           /* don't know my NID yet */

        rc = lib_init(&kranal_lib, nal, process_id,
                      requested_limits, actual_limits);
        if (rc != PTL_OK) {
                CERROR("lib_init failed: error %d\n", rc);
                goto failed;
        }

        /* lib interface initialised */
        kranal_data.kra_init = RANAL_INIT_LIB;
        /*****************************************************/

        rc = kranal_thread_start(kranal_reaper, NULL);
        if (rc != 0) {
                CERROR("Can't spawn ranal reaper: %d\n", rc);
                goto failed;
        }

        for (i = 0; i < RANAL_N_CONND; i++) {
                rc = kranal_thread_start(kranal_connd, (void *)(unsigned long)i);
                if (rc != 0) {
                        CERROR("Can't spawn ranal connd[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        LASSERT(kranal_data.kra_ndevs == 0);
        for (i = 0; i < sizeof(device_ids)/sizeof(device_ids[0]); i++) {
                dev = &kranal_data.kra_devices[kranal_data.kra_ndevs];

                rc = kranal_device_init(device_ids[i], dev);
                if (rc == 0)
                        kranal_data.kra_ndevs++;

                rc = kranal_thread_start(kranal_scheduler, dev);
                if (rc != 0) {
                        CERROR("Can't spawn ranal scheduler[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        if (kranal_data.kra_ndevs == 0)
                goto failed;

        rc = libcfs_nal_cmd_register(RANAL, &kranal_cmd, NULL);
        if (rc != 0) {
                CERROR("Can't initialise command interface (rc = %d)\n", rc);
                goto failed;
        }

        /* flag everything initialised */
        kranal_data.kra_init = RANAL_INIT_ALL;
        /*****************************************************/

        CDEBUG(D_MALLOC, "initial kmem %d\n", atomic_read(&portal_kmemory));
        printk(KERN_INFO "Lustre: RapidArray NAL loaded "
               "(initial mem %d)\n", pkmem);

        return PTL_OK;

 failed:
        kranal_api_shutdown(&kranal_api);    
        return PTL_FAIL;
}

void __exit
kranal_module_fini (void)
{
        if (kranal_tunables.kra_sysctl != NULL)
                unregister_sysctl_table(kranal_tunables.kra_sysctl);

        PtlNIFini(kranal_ni);

        ptl_unregister_nal(RANAL);
}

int __init
kranal_module_init (void)
{
        int    rc;

        /* the following must be sizeof(int) for
         * proc_dointvec/kranal_listener_procint() */
        LASSERT (sizeof(kranal_tunables.kra_timeout) == sizeof(int));
        LASSERT (sizeof(kranal_tunables.kra_listener_timeout) == sizeof(int));
        LASSERT (sizeof(kranal_tunables.kra_backlog) == sizeof(int));
        LASSERT (sizeof(kranal_tunables.kra_port) == sizeof(int));
        LASSERT (sizeof(kranal_tunables.kra_max_immediate) == sizeof(int));

        kranal_api.nal_ni_init = kranal_api_startup;
        kranal_api.nal_ni_fini = kranal_api_shutdown;

        /* Initialise dynamic tunables to defaults once only */
        kranal_tunables.kra_timeout = RANAL_TIMEOUT;
        kranal_tunables.kra_listener_timeout = RANAL_LISTENER_TIMEOUT;
        kranal_tunables.kra_backlog = RANAL_BACKLOG;
        kranal_tunables.kra_port = RANAL_PORT;
        kranal_tunables.kra_max_immediate = RANAL_MAX_IMMEDIATE;

        rc = ptl_register_nal(RANAL, &kranal_api);
        if (rc != PTL_OK) {
                CERROR("Can't register RANAL: %d\n", rc);
                return -ENOMEM;               /* or something... */
        }

        /* Pure gateways want the NAL started up at module load time... */
        rc = PtlNIInit(RANAL, LUSTRE_SRV_PTL_PID, NULL, NULL, &kranal_ni);
        if (rc != PTL_OK && rc != PTL_IFACE_DUP) {
                ptl_unregister_nal(RANAL);
                return -ENODEV;
        }

        kranal_tunables.kra_sysctl = 
                register_sysctl_table(kranal_top_ctl_table, 0);
        if (kranal_tunables.kra_sysctl == NULL) {
                CERROR("Can't register sysctl table\n");
                PtlNIFini(kranal_ni);
                ptl_unregister_nal(RANAL);
                return -ENOMEM;
        }

        return 0;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel RapidArray NAL v0.01");
MODULE_LICENSE("GPL");

module_init(kranal_module_init);
module_exit(kranal_module_fini);
