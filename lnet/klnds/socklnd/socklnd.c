/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@zabbo.net>
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "socknal.h"

ptl_handle_ni_t         ksocknal_ni;
static nal_t            ksocknal_api;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
ksock_nal_data_t ksocknal_data;
#else
static ksock_nal_data_t ksocknal_data;
#endif

kpr_nal_interface_t ksocknal_router_interface = {
        kprni_nalid:      SOCKNAL,
        kprni_arg:        &ksocknal_data,
        kprni_fwd:        ksocknal_fwd_packet,
        kprni_notify:     ksocknal_notify,
};

#define SOCKNAL_SYSCTL	200

#define SOCKNAL_SYSCTL_TIMEOUT     1
#define SOCKNAL_SYSCTL_EAGER_ACK   2
#define SOCKNAL_SYSCTL_ZERO_COPY   3
#define SOCKNAL_SYSCTL_TYPED       4
#define SOCKNAL_SYSCTL_MIN_BULK    5

static ctl_table ksocknal_ctl_table[] = {
        {SOCKNAL_SYSCTL_TIMEOUT, "timeout", 
         &ksocknal_data.ksnd_io_timeout, sizeof (int),
         0644, NULL, &proc_dointvec},
        {SOCKNAL_SYSCTL_EAGER_ACK, "eager_ack", 
         &ksocknal_data.ksnd_eager_ack, sizeof (int),
         0644, NULL, &proc_dointvec},
#if SOCKNAL_ZC
        {SOCKNAL_SYSCTL_EAGER_ACK, "zero_copy", 
         &ksocknal_data.ksnd_zc_min_frag, sizeof (int),
         0644, NULL, &proc_dointvec},
#endif
        {SOCKNAL_SYSCTL_TYPED, "typed", 
         &ksocknal_data.ksnd_typed_conns, sizeof (int),
         0644, NULL, &proc_dointvec},
        {SOCKNAL_SYSCTL_MIN_BULK, "min_bulk", 
         &ksocknal_data.ksnd_min_bulk, sizeof (int),
         0644, NULL, &proc_dointvec},
        { 0 }
};

static ctl_table ksocknal_top_ctl_table[] = {
        {SOCKNAL_SYSCTL, "socknal", NULL, 0, 0555, ksocknal_ctl_table},
        { 0 }
};

int
ksocknal_api_forward(nal_t *nal, int id, void *args, size_t args_len,
                       void *ret, size_t ret_len)
{
        ksock_nal_data_t *k;
        nal_cb_t *nal_cb;

        k = nal->nal_data;
        nal_cb = k->ksnd_nal_cb;

        lib_dispatch(nal_cb, k, id, args, ret); /* ksocknal_send needs k */
        return PTL_OK;
}

int
ksocknal_api_shutdown(nal_t *nal, int ni)
{
        return PTL_OK;
}

void
ksocknal_api_yield(nal_t *nal)
{
        our_cond_resched();
        return;
}

void
ksocknal_api_lock(nal_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *k;
        nal_cb_t *nal_cb;

        k = nal->nal_data;
        nal_cb = k->ksnd_nal_cb;
        nal_cb->cb_cli(nal_cb,flags);
}

void
ksocknal_api_unlock(nal_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *k;
        nal_cb_t *nal_cb;

        k = nal->nal_data;
        nal_cb = k->ksnd_nal_cb;
        nal_cb->cb_sti(nal_cb,flags);
}

nal_t *
ksocknal_init(int interface, ptl_pt_index_t ptl_size,
              ptl_ac_index_t ac_size, ptl_pid_t requested_pid)
{
        CDEBUG(D_NET, "calling lib_init with nid "LPX64"\n", (ptl_nid_t)0);
        lib_init(&ksocknal_lib, (ptl_nid_t)0, 0, 10, ptl_size, ac_size);
        return (&ksocknal_api);
}

/*
 *  EXTRA functions follow
 */

int
ksocknal_set_mynid(ptl_nid_t nid)
{
        lib_ni_t *ni = &ksocknal_lib.ni;

        /* FIXME: we have to do this because we call lib_init() at module
         * insertion time, which is before we have 'mynid' available.  lib_init
         * sets the NAL's nid, which it uses to tell other nodes where packets
         * are coming from.  This is not a very graceful solution to this
         * problem. */

        CDEBUG(D_IOCTL, "setting mynid to "LPX64" (old nid="LPX64")\n",
               nid, ni->nid);

        ni->nid = nid;
        return (0);
}

void
ksocknal_bind_irq (unsigned int irq)
{
#if (defined(CONFIG_SMP) && CPU_AFFINITY)
        int              bind;
        unsigned long    flags;
        char             cmdline[64];
        ksock_irqinfo_t *info;
        char            *argv[] = {"/bin/sh",
                                   "-c",
                                   cmdline,
                                   NULL};
        char            *envp[] = {"HOME=/",
                                   "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
                                   NULL};

        LASSERT (irq < NR_IRQS);
        if (irq == 0)                           /* software NIC */
                return;

        info = &ksocknal_data.ksnd_irqinfo[irq];

        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        LASSERT (info->ksni_valid);
        bind = !info->ksni_bound;
        info->ksni_bound = 1;

        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        if (!bind)                              /* bound already */
                return;

        snprintf (cmdline, sizeof (cmdline),
                  "echo %d > /proc/irq/%u/smp_affinity", 1 << info->ksni_sched, irq);

        printk (KERN_INFO "Lustre: Binding irq %u to CPU %d with cmd: %s\n",
                irq, info->ksni_sched, cmdline);

        /* FIXME: Find a better method of setting IRQ affinity...
         */

        call_usermodehelper (argv[0], argv, envp);
#endif
}

ksock_route_t *
ksocknal_create_route (__u32 ipaddr, int port, int buffer_size,
                       int irq_affinity, int eager)
{
        ksock_route_t *route;

        PORTAL_ALLOC (route, sizeof (*route));
        if (route == NULL)
                return (NULL);

        atomic_set (&route->ksnr_refcount, 1);
        route->ksnr_sharecount = 0;
        route->ksnr_peer = NULL;
        route->ksnr_timeout = jiffies;
        route->ksnr_retry_interval = SOCKNAL_MIN_RECONNECT_INTERVAL;
        route->ksnr_ipaddr = ipaddr;
        route->ksnr_port = port;
        route->ksnr_buffer_size = buffer_size;
        route->ksnr_irq_affinity = irq_affinity;
        route->ksnr_eager = eager;
        route->ksnr_connecting = 0;
        route->ksnr_connected = 0;
        route->ksnr_deleted = 0;
        route->ksnr_conn_count = 0;

        return (route);
}

void
ksocknal_destroy_route (ksock_route_t *route)
{
        LASSERT (route->ksnr_sharecount == 0);

        if (route->ksnr_peer != NULL)
                ksocknal_put_peer (route->ksnr_peer);

        PORTAL_FREE (route, sizeof (*route));
}

void
ksocknal_put_route (ksock_route_t *route)
{
        CDEBUG (D_OTHER, "putting route[%p] (%d)\n",
                route, atomic_read (&route->ksnr_refcount));

        LASSERT (atomic_read (&route->ksnr_refcount) > 0);
        if (!atomic_dec_and_test (&route->ksnr_refcount))
             return;

        ksocknal_destroy_route (route);
}

ksock_peer_t *
ksocknal_create_peer (ptl_nid_t nid)
{
        ksock_peer_t *peer;

        LASSERT (nid != PTL_NID_ANY);

        PORTAL_ALLOC (peer, sizeof (*peer));
        if (peer == NULL)
                return (NULL);

        memset (peer, 0, sizeof (*peer));

        peer->ksnp_nid = nid;
        atomic_set (&peer->ksnp_refcount, 1);   /* 1 ref for caller */
        peer->ksnp_closing = 0;
        INIT_LIST_HEAD (&peer->ksnp_conns);
        INIT_LIST_HEAD (&peer->ksnp_routes);
        INIT_LIST_HEAD (&peer->ksnp_tx_queue);

        atomic_inc (&ksocknal_data.ksnd_npeers);
        return (peer);
}

void
ksocknal_destroy_peer (ksock_peer_t *peer)
{
        CDEBUG (D_NET, "peer "LPX64" %p deleted\n", peer->ksnp_nid, peer);

        LASSERT (atomic_read (&peer->ksnp_refcount) == 0);
        LASSERT (list_empty (&peer->ksnp_conns));
        LASSERT (list_empty (&peer->ksnp_routes));
        LASSERT (list_empty (&peer->ksnp_tx_queue));

        PORTAL_FREE (peer, sizeof (*peer));

        /* NB a peer's connections and autoconnect routes keep a reference
         * on their peer until they are destroyed, so we can be assured
         * that _all_ state to do with this peer has been cleaned up when
         * its refcount drops to zero. */
        atomic_dec (&ksocknal_data.ksnd_npeers);
}

void
ksocknal_put_peer (ksock_peer_t *peer)
{
        CDEBUG (D_OTHER, "putting peer[%p] -> "LPX64" (%d)\n",
                peer, peer->ksnp_nid,
                atomic_read (&peer->ksnp_refcount));

        LASSERT (atomic_read (&peer->ksnp_refcount) > 0);
        if (!atomic_dec_and_test (&peer->ksnp_refcount))
                return;

        ksocknal_destroy_peer (peer);
}

ksock_peer_t *
ksocknal_find_peer_locked (ptl_nid_t nid)
{
        struct list_head *peer_list = ksocknal_nid2peerlist (nid);
        struct list_head *tmp;
        ksock_peer_t     *peer;

        list_for_each (tmp, peer_list) {

                peer = list_entry (tmp, ksock_peer_t, ksnp_list);

                LASSERT (!peer->ksnp_closing);
                LASSERT (!(list_empty (&peer->ksnp_routes) &&
                           list_empty (&peer->ksnp_conns)));

                if (peer->ksnp_nid != nid)
                        continue;

                CDEBUG(D_NET, "got peer [%p] -> "LPX64" (%d)\n",
                       peer, nid, atomic_read (&peer->ksnp_refcount));
                return (peer);
        }
        return (NULL);
}

ksock_peer_t *
ksocknal_get_peer (ptl_nid_t nid)
{
        ksock_peer_t     *peer;

        read_lock (&ksocknal_data.ksnd_global_lock);
        peer = ksocknal_find_peer_locked (nid);
        if (peer != NULL)                       /* +1 ref for caller? */
                atomic_inc (&peer->ksnp_refcount);
        read_unlock (&ksocknal_data.ksnd_global_lock);

        return (peer);
}

void
ksocknal_unlink_peer_locked (ksock_peer_t *peer)
{
        LASSERT (!peer->ksnp_closing);
        peer->ksnp_closing = 1;
        list_del (&peer->ksnp_list);
        /* lose peerlist's ref */
        ksocknal_put_peer (peer);
}

ksock_route_t *
ksocknal_get_route_by_idx (int index)
{
        ksock_peer_t      *peer;
        struct list_head  *ptmp;
        ksock_route_t     *route;
        struct list_head  *rtmp;
        int                i;

        read_lock (&ksocknal_data.ksnd_global_lock);

        for (i = 0; i < ksocknal_data.ksnd_peer_hash_size; i++) {
                list_for_each (ptmp, &ksocknal_data.ksnd_peers[i]) {
                        peer = list_entry (ptmp, ksock_peer_t, ksnp_list);

                        LASSERT (!(list_empty (&peer->ksnp_routes) &&
                                   list_empty (&peer->ksnp_conns)));

                        list_for_each (rtmp, &peer->ksnp_routes) {
                                if (index-- > 0)
                                        continue;

                                route = list_entry (rtmp, ksock_route_t, ksnr_list);
                                atomic_inc (&route->ksnr_refcount);
                                read_unlock (&ksocknal_data.ksnd_global_lock);
                                return (route);
                        }
                }
        }

        read_unlock (&ksocknal_data.ksnd_global_lock);
        return (NULL);
}

int
ksocknal_add_route (ptl_nid_t nid, __u32 ipaddr, int port, int bufnob,
                    int bind_irq, int share, int eager)
{
        unsigned long      flags;
        ksock_peer_t      *peer;
        ksock_peer_t      *peer2;
        ksock_route_t     *route;
        struct list_head  *rtmp;
        ksock_route_t     *route2;
        
        if (nid == PTL_NID_ANY)
                return (-EINVAL);

        /* Have a brand new peer ready... */
        peer = ksocknal_create_peer (nid);
        if (peer == NULL)
                return (-ENOMEM);

        route = ksocknal_create_route (ipaddr, port, bufnob, 
                                       bind_irq, eager);
        if (route == NULL) {
                ksocknal_put_peer (peer);
                return (-ENOMEM);
        }

        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        peer2 = ksocknal_find_peer_locked (nid);
        if (peer2 != NULL) {
                ksocknal_put_peer (peer);
                peer = peer2;
        } else {
                /* peer table takes existing ref on peer */
                list_add (&peer->ksnp_list,
                          ksocknal_nid2peerlist (nid));
        }

        route2 = NULL;
        if (share) {
                /* check for existing route to this NID via this ipaddr */
                list_for_each (rtmp, &peer->ksnp_routes) {
                        route2 = list_entry (rtmp, ksock_route_t, ksnr_list);
                        
                        if (route2->ksnr_ipaddr == ipaddr)
                                break;

                        route2 = NULL;
                }
        }

        if (route2 != NULL) {
                ksocknal_put_route (route);
                route = route2;
        } else {
                /* route takes a ref on peer */
                route->ksnr_peer = peer;
                atomic_inc (&peer->ksnp_refcount);
                /* peer's route list takes existing ref on route */
                list_add_tail (&route->ksnr_list, &peer->ksnp_routes);
        }
        
        route->ksnr_sharecount++;

        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        return (0);
}

void
ksocknal_del_route_locked (ksock_route_t *route, int share, int keep_conn)
{
        ksock_peer_t     *peer = route->ksnr_peer;
        ksock_conn_t     *conn;
        struct list_head *ctmp;
        struct list_head *cnxt;

        if (!share)
                route->ksnr_sharecount = 0;
        else {
                route->ksnr_sharecount--;
                if (route->ksnr_sharecount != 0)
                        return;
        }

        list_for_each_safe (ctmp, cnxt, &peer->ksnp_conns) {
                conn = list_entry(ctmp, ksock_conn_t, ksnc_list);

                if (conn->ksnc_route != route)
                        continue;
                
                if (!keep_conn) {
                        ksocknal_close_conn_locked (conn, 0);
                        continue;
                }
                
                /* keeping the conn; just dissociate it and route... */
                conn->ksnc_route = NULL;
                ksocknal_put_route (route); /* drop conn's ref on route */
        }
        
        route->ksnr_deleted = 1;
        list_del (&route->ksnr_list);
        ksocknal_put_route (route);             /* drop peer's ref */

        if (list_empty (&peer->ksnp_routes) &&
            list_empty (&peer->ksnp_conns)) {
                /* I've just removed the last autoconnect route of a peer
                 * with no active connections */
                ksocknal_unlink_peer_locked (peer);
        }
}

int
ksocknal_del_route (ptl_nid_t nid, __u32 ipaddr, int share, int keep_conn)
{
        unsigned long      flags;
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        ksock_peer_t      *peer;
        struct list_head  *rtmp;
        struct list_head  *rnxt;
        ksock_route_t     *route;
        int                lo;
        int                hi;
        int                i;
        int                rc = -ENOENT;

        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        if (nid != PTL_NID_ANY)
                lo = hi = ksocknal_nid2peerlist(nid) - ksocknal_data.ksnd_peers;
        else {
                lo = 0;
                hi = ksocknal_data.ksnd_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &ksocknal_data.ksnd_peers[i]) {
                        peer = list_entry (ptmp, ksock_peer_t, ksnp_list);

                        if (!(nid == PTL_NID_ANY || peer->ksnp_nid == nid))
                                continue;

                        list_for_each_safe (rtmp, rnxt, &peer->ksnp_routes) {
                                route = list_entry (rtmp, ksock_route_t,
                                                    ksnr_list);

                                if (!(ipaddr == 0 ||
                                      route->ksnr_ipaddr == ipaddr))
                                        continue;

                                ksocknal_del_route_locked (route, share, keep_conn);
                                rc = 0;         /* matched something */
                                if (share)
                                        goto out;
                        }
                }
        }
 out:
        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        return (rc);
}

ksock_conn_t *
ksocknal_get_conn_by_idx (int index)
{
        ksock_peer_t      *peer;
        struct list_head  *ptmp;
        ksock_conn_t      *conn;
        struct list_head  *ctmp;
        int                i;

        read_lock (&ksocknal_data.ksnd_global_lock);

        for (i = 0; i < ksocknal_data.ksnd_peer_hash_size; i++) {
                list_for_each (ptmp, &ksocknal_data.ksnd_peers[i]) {
                        peer = list_entry (ptmp, ksock_peer_t, ksnp_list);

                        LASSERT (!(list_empty (&peer->ksnp_routes) &&
                                   list_empty (&peer->ksnp_conns)));

                        list_for_each (ctmp, &peer->ksnp_conns) {
                                if (index-- > 0)
                                        continue;

                                conn = list_entry (ctmp, ksock_conn_t, ksnc_list);
                                atomic_inc (&conn->ksnc_refcount);
                                read_unlock (&ksocknal_data.ksnd_global_lock);
                                return (conn);
                        }
                }
        }

        read_unlock (&ksocknal_data.ksnd_global_lock);
        return (NULL);
}

void
ksocknal_get_peer_addr (ksock_conn_t *conn)
{
        struct sockaddr_in sin;
        int                len = sizeof (sin);
        int                rc;
        
        rc = conn->ksnc_sock->ops->getname (conn->ksnc_sock,
                                            (struct sockaddr *)&sin, &len, 2);
        /* Didn't need the {get,put}connsock dance to deref ksnc_sock... */
        LASSERT (!conn->ksnc_closing);
        LASSERT (len <= sizeof (sin));

        if (rc != 0) {
                CERROR ("Error %d getting sock peer IP\n", rc);
                return;
        }

        conn->ksnc_ipaddr = ntohl (sin.sin_addr.s_addr);
        conn->ksnc_port   = ntohs (sin.sin_port);
}

unsigned int
ksocknal_conn_irq (ksock_conn_t *conn)
{
        int                irq = 0;
        struct dst_entry  *dst;

        dst = sk_dst_get (conn->ksnc_sock->sk);
        if (dst != NULL) {
                if (dst->dev != NULL) {
                        irq = dst->dev->irq;
                        if (irq >= NR_IRQS) {
                                CERROR ("Unexpected IRQ %x\n", irq);
                                irq = 0;
                        }
                }
                dst_release (dst);
        }
        
        /* Didn't need the {get,put}connsock dance to deref ksnc_sock... */
        LASSERT (!conn->ksnc_closing);
        return (irq);
}

ksock_sched_t *
ksocknal_choose_scheduler_locked (unsigned int irq)
{
        ksock_sched_t    *sched;
        ksock_irqinfo_t  *info;
        int               i;

        LASSERT (irq < NR_IRQS);
        info = &ksocknal_data.ksnd_irqinfo[irq];

        if (irq != 0 &&                         /* hardware NIC */
            info->ksni_valid) {                 /* already set up */
                return (&ksocknal_data.ksnd_schedulers[info->ksni_sched]);
        }

        /* software NIC (irq == 0) || not associated with a scheduler yet.
         * Choose the CPU with the fewest connections... */
        sched = &ksocknal_data.ksnd_schedulers[0];
        for (i = 1; i < SOCKNAL_N_SCHED; i++)
                if (sched->kss_nconns >
                    ksocknal_data.ksnd_schedulers[i].kss_nconns)
                        sched = &ksocknal_data.ksnd_schedulers[i];

        if (irq != 0) {                         /* Hardware NIC */
                info->ksni_valid = 1;
                info->ksni_sched = sched - ksocknal_data.ksnd_schedulers;

                /* no overflow... */
                LASSERT (info->ksni_sched == sched - ksocknal_data.ksnd_schedulers);
        }

        return (sched);
}

int
ksocknal_create_conn (ksock_route_t *route, struct socket *sock,
                      int bind_irq, int type)
{
        ptl_nid_t          nid;
        __u64              incarnation;
        unsigned long      flags;
        ksock_conn_t      *conn;
        ksock_peer_t      *peer;
        ksock_peer_t      *peer2;
        ksock_sched_t     *sched;
        unsigned int       irq;
        ksock_tx_t        *tx;
        int                rc;

        /* NB, sock has an associated file since (a) this connection might
         * have been created in userland and (b) we need to refcount the
         * socket so that we don't close it while I/O is being done on
         * it, and sock->file has that pre-cooked... */
        LASSERT (sock->file != NULL);
        LASSERT (file_count(sock->file) > 0);

        rc = ksocknal_setup_sock (sock);
        if (rc != 0)
                return (rc);

        if (route == NULL) {
                /* acceptor or explicit connect */
                nid = PTL_NID_ANY;
        } else {
                LASSERT (type != SOCKNAL_CONN_NONE);
                /* autoconnect: expect this nid on exchange */
                nid = route->ksnr_peer->ksnp_nid;
        }

        rc = ksocknal_hello (sock, &nid, &type, &incarnation);
        if (rc != 0)
                return (rc);
        
        peer = NULL;
        if (route == NULL) {                    /* not autoconnect */
                /* Assume this socket connects to a brand new peer */
                peer = ksocknal_create_peer (nid);
                if (peer == NULL)
                        return (-ENOMEM);
        }

        PORTAL_ALLOC(conn, sizeof(*conn));
        if (conn == NULL) {
                if (peer != NULL)
                        ksocknal_put_peer (peer);
                return (-ENOMEM);
        }

        memset (conn, 0, sizeof (*conn));
        conn->ksnc_peer = NULL;
        conn->ksnc_route = NULL;
        conn->ksnc_sock = sock;
        conn->ksnc_type = type;
        conn->ksnc_incarnation = incarnation;
        conn->ksnc_saved_data_ready = sock->sk->sk_data_ready;
        conn->ksnc_saved_write_space = sock->sk->sk_write_space;
        atomic_set (&conn->ksnc_refcount, 1);    /* 1 ref for me */

        conn->ksnc_rx_ready = 0;
        conn->ksnc_rx_scheduled = 0;
        ksocknal_new_packet (conn, 0);

        INIT_LIST_HEAD (&conn->ksnc_tx_queue);
        conn->ksnc_tx_ready = 0;
        conn->ksnc_tx_scheduled = 0;
        atomic_set (&conn->ksnc_tx_nob, 0);

        ksocknal_get_peer_addr (conn);

        irq = ksocknal_conn_irq (conn);

        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        if (route != NULL) {
                /* Autoconnected! */
                LASSERT ((route->ksnr_connected & (1 << type)) == 0);
                LASSERT ((route->ksnr_connecting & (1 << type)) != 0);

                if (route->ksnr_deleted) {
                        /* This conn was autoconnected, but the autoconnect
                         * route got deleted while it was being
                         * established! */
                        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock,
                                                 flags);
                        PORTAL_FREE (conn, sizeof (*conn));
                        return (-ESTALE);
                }


                /* associate conn/route */
                conn->ksnc_route = route;
                atomic_inc (&route->ksnr_refcount);

                route->ksnr_connecting &= ~(1 << type);
                route->ksnr_connected  |= (1 << type);
                route->ksnr_conn_count++;
                route->ksnr_retry_interval = SOCKNAL_MIN_RECONNECT_INTERVAL;

                peer = route->ksnr_peer;
        } else {
                /* Not an autoconnected connection; see if there is an
                 * existing peer for this NID */
                peer2 = ksocknal_find_peer_locked (nid);
                if (peer2 != NULL) {
                        ksocknal_put_peer (peer);
                        peer = peer2;
                } else {
                        list_add (&peer->ksnp_list,
                                  ksocknal_nid2peerlist (nid));
                        /* peer list takes over existing ref */
                }
        }

        LASSERT (!peer->ksnp_closing);

        conn->ksnc_peer = peer;
        atomic_inc (&peer->ksnp_refcount);
        peer->ksnp_last_alive = jiffies;
        peer->ksnp_error = 0;

        list_add (&conn->ksnc_list, &peer->ksnp_conns);
        atomic_inc (&conn->ksnc_refcount);

        sched = ksocknal_choose_scheduler_locked (irq);
        sched->kss_nconns++;
        conn->ksnc_scheduler = sched;

        /* NB my callbacks block while I hold ksnd_global_lock */
        sock->sk->sk_user_data = conn;
        sock->sk->sk_data_ready = ksocknal_data_ready;
        sock->sk->sk_write_space = ksocknal_write_space;

        /* Take all the packets blocking for a connection.
         * NB, it might be nicer to share these blocked packets among any
         * other connections that are becoming established, however that
         * confuses the normal packet launching operation, which selects a
         * connection and queues the packet on it without needing an
         * exclusive lock on ksnd_global_lock. */
        while (!list_empty (&peer->ksnp_tx_queue)) {
                tx = list_entry (peer->ksnp_tx_queue.next,
                                 ksock_tx_t, tx_list);

                list_del (&tx->tx_list);
                ksocknal_queue_tx_locked (tx, conn);
        }

        rc = ksocknal_close_stale_conns_locked (peer, incarnation);

        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        if (rc != 0)
                CERROR ("Closed %d stale conns to "LPX64"\n", rc, nid);

        if (bind_irq)                           /* irq binding required */
                ksocknal_bind_irq (irq);

        /* Call the callbacks right now to get things going. */
        ksocknal_data_ready (sock->sk, 0);
        ksocknal_write_space (sock->sk);

        CDEBUG(D_IOCTL, "conn [%p] registered for nid "LPX64"\n",
               conn, conn->ksnc_peer->ksnp_nid);

        ksocknal_put_conn (conn);
        return (0);
}

void
ksocknal_close_conn_locked (ksock_conn_t *conn, int error)
{
        /* This just does the immmediate housekeeping, and queues the
         * connection for the reaper to terminate. 
         * Caller holds ksnd_global_lock exclusively in irq context */
        ksock_peer_t   *peer = conn->ksnc_peer;
        ksock_route_t  *route;

        LASSERT (peer->ksnp_error == 0);
        LASSERT (!conn->ksnc_closing);
        conn->ksnc_closing = 1;
        atomic_inc (&ksocknal_data.ksnd_nclosing_conns);
        
        route = conn->ksnc_route;
        if (route != NULL) {
                /* dissociate conn from route... */
                LASSERT (!route->ksnr_deleted);
                LASSERT ((route->ksnr_connecting & (1 << conn->ksnc_type)) == 0);
                LASSERT ((route->ksnr_connected & (1 << conn->ksnc_type)) != 0);

                route->ksnr_connected &= ~(1 << conn->ksnc_type);
                conn->ksnc_route = NULL;

                list_del (&route->ksnr_list);   /* make route least favourite */
                list_add_tail (&route->ksnr_list, &peer->ksnp_routes);
                
                ksocknal_put_route (route);     /* drop conn's ref on route */
        }

        /* ksnd_deathrow_conns takes over peer's ref */
        list_del (&conn->ksnc_list);

        if (list_empty (&peer->ksnp_conns)) {
                /* No more connections to this peer */

                peer->ksnp_error = error;       /* stash last conn close reason */

                if (list_empty (&peer->ksnp_routes)) {
                        /* I've just closed last conn belonging to a
                         * non-autoconnecting peer */
                        ksocknal_unlink_peer_locked (peer);
                }
        }

        spin_lock (&ksocknal_data.ksnd_reaper_lock);

        list_add_tail (&conn->ksnc_list, &ksocknal_data.ksnd_deathrow_conns);
        wake_up (&ksocknal_data.ksnd_reaper_waitq);
                
        spin_unlock (&ksocknal_data.ksnd_reaper_lock);
}

void
ksocknal_terminate_conn (ksock_conn_t *conn)
{
        /* This gets called by the reaper (guaranteed thread context) to
         * disengage the socket from its callbacks and close it.
         * ksnc_refcount will eventually hit zero, and then the reaper will
         * destroy it. */
        unsigned long   flags;
        ksock_peer_t   *peer = conn->ksnc_peer;
        ksock_sched_t  *sched = conn->ksnc_scheduler;
        struct timeval  now;
        time_t          then = 0;
        int             notify = 0;

        LASSERT(conn->ksnc_closing);

        /* wake up the scheduler to "send" all remaining packets to /dev/null */
        spin_lock_irqsave(&sched->kss_lock, flags);

        if (!conn->ksnc_tx_scheduled &&
            !list_empty(&conn->ksnc_tx_queue)){
                list_add_tail (&conn->ksnc_tx_list,
                               &sched->kss_tx_conns);
                /* a closing conn is always ready to tx */
                conn->ksnc_tx_ready = 1;
                conn->ksnc_tx_scheduled = 1;
                /* extra ref for scheduler */
                atomic_inc (&conn->ksnc_refcount);

                wake_up (&sched->kss_waitq);
        }

        spin_unlock_irqrestore (&sched->kss_lock, flags);

        /* serialise with callbacks */
        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        /* Remove conn's network callbacks.
         * NB I _have_ to restore the callback, rather than storing a noop,
         * since the socket could survive past this module being unloaded!! */
        conn->ksnc_sock->sk->sk_data_ready = conn->ksnc_saved_data_ready;
        conn->ksnc_sock->sk->sk_write_space = conn->ksnc_saved_write_space;

        /* A callback could be in progress already; they hold a read lock
         * on ksnd_global_lock (to serialise with me) and NOOP if
         * sk_user_data is NULL. */
        conn->ksnc_sock->sk->sk_user_data = NULL;

        /* OK, so this conn may not be completely disengaged from its
         * scheduler yet, but it _has_ committed to terminate... */
        conn->ksnc_scheduler->kss_nconns--;

        if (peer->ksnp_error != 0) {
                /* peer's last conn closed in error */
                LASSERT (list_empty (&peer->ksnp_conns));
                
                /* convert peer's last-known-alive timestamp from jiffies */
                do_gettimeofday (&now);
                then = now.tv_sec - (jiffies - peer->ksnp_last_alive)/HZ;
                notify = 1;
        }
        
        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        /* The socket is closed on the final put; either here, or in
         * ksocknal_{send,recv}msg().  Since we set up the linger2 option
         * when the connection was established, this will close the socket
         * immediately, aborting anything buffered in it. Any hung
         * zero-copy transmits will therefore complete in finite time. */
        ksocknal_putconnsock (conn);

        if (notify)
                kpr_notify (&ksocknal_data.ksnd_router, peer->ksnp_nid,
                            0, then);
}

void
ksocknal_destroy_conn (ksock_conn_t *conn)
{
        /* Final coup-de-grace of the reaper */
        CDEBUG (D_NET, "connection %p\n", conn);

        LASSERT (atomic_read (&conn->ksnc_refcount) == 0);
        LASSERT (conn->ksnc_route == NULL);
        LASSERT (!conn->ksnc_tx_scheduled);
        LASSERT (!conn->ksnc_rx_scheduled);
        LASSERT (list_empty(&conn->ksnc_tx_queue));

        /* complete current receive if any */
        switch (conn->ksnc_rx_state) {
        case SOCKNAL_RX_BODY:
#if 0
                lib_finalize (&ksocknal_lib, NULL, conn->ksnc_cookie);
#else
                CERROR ("Refusing to complete a partial receive from "
                        LPX64", ip %08x\n", conn->ksnc_peer->ksnp_nid,
                        conn->ksnc_ipaddr);
                CERROR ("This may hang communications and "
                        "prevent modules from unloading\n");
#endif
                break;
        case SOCKNAL_RX_BODY_FWD:
                ksocknal_fmb_callback (conn->ksnc_cookie, -ECONNABORTED);
                break;
        case SOCKNAL_RX_HEADER:
        case SOCKNAL_RX_SLOP:
                break;
        default:
                LBUG ();
                break;
        }

        ksocknal_put_peer (conn->ksnc_peer);

        PORTAL_FREE (conn, sizeof (*conn));
        atomic_dec (&ksocknal_data.ksnd_nclosing_conns);
}

void
ksocknal_put_conn (ksock_conn_t *conn)
{
        unsigned long flags;

        CDEBUG (D_OTHER, "putting conn[%p] -> "LPX64" (%d)\n",
                conn, conn->ksnc_peer->ksnp_nid,
                atomic_read (&conn->ksnc_refcount));

        LASSERT (atomic_read (&conn->ksnc_refcount) > 0);
        if (!atomic_dec_and_test (&conn->ksnc_refcount))
                return;

        spin_lock_irqsave (&ksocknal_data.ksnd_reaper_lock, flags);

        list_add (&conn->ksnc_list, &ksocknal_data.ksnd_zombie_conns);
        wake_up (&ksocknal_data.ksnd_reaper_waitq);

        spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);
}

int
ksocknal_close_peer_conns_locked (ksock_peer_t *peer, __u32 ipaddr, int why)
{
        ksock_conn_t       *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ksnp_conns) {
                conn = list_entry (ctmp, ksock_conn_t, ksnc_list);

                if (ipaddr == 0 ||
                    conn->ksnc_ipaddr == ipaddr) {
                        count++;
                        ksocknal_close_conn_locked (conn, why);
                }
        }

        return (count);
}

int
ksocknal_close_stale_conns_locked (ksock_peer_t *peer, __u64 incarnation)
{
        ksock_conn_t       *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ksnp_conns) {
                conn = list_entry (ctmp, ksock_conn_t, ksnc_list);

                if (conn->ksnc_incarnation == incarnation)
                        continue;
                
                count++;
                ksocknal_close_conn_locked (conn, -ESTALE);
        }

        return (count);
}

int
ksocknal_close_conn_and_siblings (ksock_conn_t *conn, int why) 
{
        ksock_peer_t     *peer = conn->ksnc_peer;
        __u32             ipaddr = conn->ksnc_ipaddr;
        unsigned long     flags;
        int               count;

        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        count = ksocknal_close_peer_conns_locked (peer, ipaddr, why);
        
        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        return (count);
}

int
ksocknal_close_matching_conns (ptl_nid_t nid, __u32 ipaddr)
{
        unsigned long       flags;
        ksock_peer_t       *peer;
        struct list_head   *ptmp;
        struct list_head   *pnxt;
        int                 lo;
        int                 hi;
        int                 i;
        int                 count = 0;

        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        if (nid != PTL_NID_ANY)
                lo = hi = ksocknal_nid2peerlist(nid) - ksocknal_data.ksnd_peers;
        else {
                lo = 0;
                hi = ksocknal_data.ksnd_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &ksocknal_data.ksnd_peers[i]) {

                        peer = list_entry (ptmp, ksock_peer_t, ksnp_list);

                        if (!(nid == PTL_NID_ANY || nid == peer->ksnp_nid))
                                continue;

                        count += ksocknal_close_peer_conns_locked (peer, ipaddr, 0);
                }
        }

        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        /* wildcards always succeed */
        if (nid == PTL_NID_ANY || ipaddr == 0)
                return (0);
        
        return (count == 0 ? -ENOENT : 0);
}

void
ksocknal_notify (void *arg, ptl_nid_t gw_nid, int alive)
{
        /* The router is telling me she's been notified of a change in
         * gateway state.... */

        CDEBUG (D_NET, "gw "LPX64" %s\n", gw_nid, alive ? "up" : "down");

        if (!alive) {
                /* If the gateway crashed, close all open connections... */
                ksocknal_close_matching_conns (gw_nid, 0);
                return;
        }
        
        /* ...otherwise do nothing.  We can only establish new connections
         * if we have autroutes, and these connect on demand. */
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
struct tcp_opt *sock2tcp_opt(struct sock *sk)
{
        return &(sk->tp_pinfo.af_tcp);
}
#else
struct tcp_opt *sock2tcp_opt(struct sock *sk)
{
        struct tcp_sock *s = (struct tcp_sock *)sk;
        return &s->tcp;
}
#endif

void
ksocknal_push_conn (ksock_conn_t *conn)
{
        struct sock    *sk;
        struct tcp_opt *tp;
        int             nonagle;
        int             val = 1;
        int             rc;
        mm_segment_t    oldmm;

        rc = ksocknal_getconnsock (conn);
        if (rc != 0)                            /* being shut down */
                return;
        
        sk = conn->ksnc_sock->sk;
        tp = sock2tcp_opt(sk);
        
        lock_sock (sk);
        nonagle = tp->nonagle;
        tp->nonagle = 1;
        release_sock (sk);

        oldmm = get_fs ();
        set_fs (KERNEL_DS);

        rc = sk->sk_prot->setsockopt (sk, SOL_TCP, TCP_NODELAY,
                                      (char *)&val, sizeof (val));
        LASSERT (rc == 0);

        set_fs (oldmm);

        lock_sock (sk);
        tp->nonagle = nonagle;
        release_sock (sk);

        ksocknal_putconnsock (conn);
}

void
ksocknal_push_peer (ksock_peer_t *peer)
{
        int               index;
        int               i;
        struct list_head *tmp;
        ksock_conn_t     *conn;

        for (index = 0; ; index++) {
                read_lock (&ksocknal_data.ksnd_global_lock);

                i = 0;
                conn = NULL;

                list_for_each (tmp, &peer->ksnp_conns) {
                        if (i++ == index) {
                                conn = list_entry (tmp, ksock_conn_t, ksnc_list);
                                atomic_inc (&conn->ksnc_refcount);
                                break;
                        }
                }

                read_unlock (&ksocknal_data.ksnd_global_lock);

                if (conn == NULL)
                        break;

                ksocknal_push_conn (conn);
                ksocknal_put_conn (conn);
        }
}

int
ksocknal_push (ptl_nid_t nid)
{
        ksock_peer_t      *peer;
        struct list_head  *tmp;
        int                index;
        int                i;
        int                j;
        int                rc = -ENOENT;

        if (nid != PTL_NID_ANY) {
                peer = ksocknal_get_peer (nid);

                if (peer != NULL) {
                        rc = 0;
                        ksocknal_push_peer (peer);
                        ksocknal_put_peer (peer);
                }
                return (rc);
        }

        for (i = 0; i < ksocknal_data.ksnd_peer_hash_size; i++) {
                for (j = 0; ; j++) {
                        read_lock (&ksocknal_data.ksnd_global_lock);

                        index = 0;
                        peer = NULL;

                        list_for_each (tmp, &ksocknal_data.ksnd_peers[i]) {
                                if (index++ == j) {
                                        peer = list_entry(tmp, ksock_peer_t,
                                                          ksnp_list);
                                        atomic_inc (&peer->ksnp_refcount);
                                        break;
                                }
                        }

                        read_unlock (&ksocknal_data.ksnd_global_lock);

                        if (peer != NULL) {
                                rc = 0;
                                ksocknal_push_peer (peer);
                                ksocknal_put_peer (peer);
                        }
                }

        }

        return (rc);
}

int
ksocknal_cmd(struct portals_cfg *pcfg, void * private)
{
        int rc = -EINVAL;

        LASSERT (pcfg != NULL);

        switch(pcfg->pcfg_command) {
        case NAL_CMD_GET_AUTOCONN: {
                ksock_route_t *route = ksocknal_get_route_by_idx (pcfg->pcfg_count);

                if (route == NULL)
                        rc = -ENOENT;
                else {
                        rc = 0;
                        pcfg->pcfg_nid   = route->ksnr_peer->ksnp_nid;
                        pcfg->pcfg_id    = route->ksnr_ipaddr;
                        pcfg->pcfg_misc  = route->ksnr_port;
                        pcfg->pcfg_count = route->ksnr_conn_count;
                        pcfg->pcfg_size  = route->ksnr_buffer_size;
                        pcfg->pcfg_wait  = route->ksnr_sharecount;
                        pcfg->pcfg_flags = (route->ksnr_irq_affinity ? 2 : 0) |
                                           (route->ksnr_eager        ? 4 : 0);
                        ksocknal_put_route (route);
                }
                break;
        }
        case NAL_CMD_ADD_AUTOCONN: {
                rc = ksocknal_add_route (pcfg->pcfg_nid, pcfg->pcfg_id,
                                         pcfg->pcfg_misc, pcfg->pcfg_size,
                                         (pcfg->pcfg_flags & 0x02) != 0,
                                         (pcfg->pcfg_flags & 0x04) != 0,
                                         (pcfg->pcfg_flags & 0x08) != 0);
                break;
        }
        case NAL_CMD_DEL_AUTOCONN: {
                rc = ksocknal_del_route (pcfg->pcfg_nid, pcfg->pcfg_id, 
                                         (pcfg->pcfg_flags & 1) != 0,
                                         (pcfg->pcfg_flags & 2) != 0);
                break;
        }
        case NAL_CMD_GET_CONN: {
                ksock_conn_t *conn = ksocknal_get_conn_by_idx (pcfg->pcfg_count);

                if (conn == NULL)
                        rc = -ENOENT;
                else {
                        rc = 0;
                        pcfg->pcfg_nid   = conn->ksnc_peer->ksnp_nid;
                        pcfg->pcfg_id    = conn->ksnc_ipaddr;
                        pcfg->pcfg_misc  = conn->ksnc_port;
                        pcfg->pcfg_flags = conn->ksnc_type;
                        ksocknal_put_conn (conn);
                }
                break;
        }
        case NAL_CMD_REGISTER_PEER_FD: {
                struct socket *sock = sockfd_lookup (pcfg->pcfg_fd, &rc);
                int            type = pcfg->pcfg_misc;

                if (sock == NULL)
                        break;

                switch (type) {
                case SOCKNAL_CONN_NONE:
                case SOCKNAL_CONN_ANY:
                case SOCKNAL_CONN_CONTROL:
                case SOCKNAL_CONN_BULK_IN:
                case SOCKNAL_CONN_BULK_OUT:
                        rc = ksocknal_create_conn(NULL, sock, pcfg->pcfg_flags, type);
                default:
                        break;
                }
                if (rc != 0)
                        fput (sock->file);
                break;
        }
        case NAL_CMD_CLOSE_CONNECTION: {
                rc = ksocknal_close_matching_conns (pcfg->pcfg_nid, 
                                                    pcfg->pcfg_id);
                break;
        }
        case NAL_CMD_REGISTER_MYNID: {
                rc = ksocknal_set_mynid (pcfg->pcfg_nid);
                break;
        }
        case NAL_CMD_PUSH_CONNECTION: {
                rc = ksocknal_push (pcfg->pcfg_nid);
                break;
        }
        }

        return rc;
}

void
ksocknal_free_fmbs (ksock_fmb_pool_t *p)
{
        ksock_fmb_t *fmb;
        int          i;

        LASSERT (list_empty(&p->fmp_blocked_conns));
        LASSERT (p->fmp_nactive_fmbs == 0);
        
        while (!list_empty(&p->fmp_idle_fmbs)) {

                fmb = list_entry(p->fmp_idle_fmbs.next,
                                 ksock_fmb_t, fmb_list);
                
                for (i = 0; i < fmb->fmb_npages; i++)
                        if (fmb->fmb_pages[i] != NULL)
                                __free_page(fmb->fmb_pages[i]);
                
                list_del(&fmb->fmb_list);
                PORTAL_FREE(fmb, sizeof(*fmb));
        }
}

void
ksocknal_free_buffers (void)
{
        ksocknal_free_fmbs(&ksocknal_data.ksnd_small_fmp);
        ksocknal_free_fmbs(&ksocknal_data.ksnd_large_fmp);

        LASSERT (atomic_read(&ksocknal_data.ksnd_nactive_ltxs) == 0);

        if (ksocknal_data.ksnd_schedulers != NULL)
                PORTAL_FREE (ksocknal_data.ksnd_schedulers,
                             sizeof (ksock_sched_t) * SOCKNAL_N_SCHED);

        PORTAL_FREE (ksocknal_data.ksnd_peers,
                     sizeof (struct list_head) * 
                     ksocknal_data.ksnd_peer_hash_size);
}

void
ksocknal_module_fini (void)
{
        int   i;

        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        switch (ksocknal_data.ksnd_init) {
        default:
                LASSERT (0);

        case SOCKNAL_INIT_ALL:
#if CONFIG_SYSCTL
                if (ksocknal_data.ksnd_sysctl != NULL)
                        unregister_sysctl_table (ksocknal_data.ksnd_sysctl);
#endif
                kportal_nal_unregister(SOCKNAL);
                PORTAL_SYMBOL_UNREGISTER (ksocknal_ni);
                /* fall through */

        case SOCKNAL_INIT_PTL:
                /* No more calls to ksocknal_cmd() to create new
                 * autoroutes/connections since we're being unloaded. */
                PtlNIFini(ksocknal_ni);

                /* Delete all autoroute entries */
                ksocknal_del_route(PTL_NID_ANY, 0, 0, 0);

                /* Delete all connections */
                ksocknal_close_matching_conns (PTL_NID_ANY, 0);
                
                /* Wait for all peer state to clean up */
                i = 2;
                while (atomic_read (&ksocknal_data.ksnd_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "waiting for %d peers to disconnect\n",
                               atomic_read (&ksocknal_data.ksnd_npeers));
                        set_current_state (TASK_UNINTERRUPTIBLE);
                        schedule_timeout (HZ);
                }

                /* Tell lib we've stopped calling into her. */
                lib_fini(&ksocknal_lib);
                /* fall through */

        case SOCKNAL_INIT_DATA:
                /* Module refcount only gets to zero when all peers
                 * have been closed so all lists must be empty */
                LASSERT (atomic_read (&ksocknal_data.ksnd_npeers) == 0);
                LASSERT (ksocknal_data.ksnd_peers != NULL);
                for (i = 0; i < ksocknal_data.ksnd_peer_hash_size; i++) {
                        LASSERT (list_empty (&ksocknal_data.ksnd_peers[i]));
                }
                LASSERT (list_empty (&ksocknal_data.ksnd_enomem_conns));
                LASSERT (list_empty (&ksocknal_data.ksnd_zombie_conns));
                LASSERT (list_empty (&ksocknal_data.ksnd_autoconnectd_routes));
                LASSERT (list_empty (&ksocknal_data.ksnd_small_fmp.fmp_blocked_conns));
                LASSERT (list_empty (&ksocknal_data.ksnd_large_fmp.fmp_blocked_conns));

                if (ksocknal_data.ksnd_schedulers != NULL)
                        for (i = 0; i < SOCKNAL_N_SCHED; i++) {
                                ksock_sched_t *kss =
                                        &ksocknal_data.ksnd_schedulers[i];

                                LASSERT (list_empty (&kss->kss_tx_conns));
                                LASSERT (list_empty (&kss->kss_rx_conns));
                                LASSERT (kss->kss_nconns == 0);
                        }

                /* stop router calling me */
                kpr_shutdown (&ksocknal_data.ksnd_router);

                /* flag threads to terminate; wake and wait for them to die */
                ksocknal_data.ksnd_shuttingdown = 1;
                wake_up_all (&ksocknal_data.ksnd_autoconnectd_waitq);
                wake_up_all (&ksocknal_data.ksnd_reaper_waitq);

                for (i = 0; i < SOCKNAL_N_SCHED; i++)
                       wake_up_all(&ksocknal_data.ksnd_schedulers[i].kss_waitq);

                while (atomic_read (&ksocknal_data.ksnd_nthreads) != 0) {
                        CDEBUG (D_NET, "waitinf for %d threads to terminate\n",
                                atomic_read (&ksocknal_data.ksnd_nthreads));
                        set_current_state (TASK_UNINTERRUPTIBLE);
                        schedule_timeout (HZ);
                }

                kpr_deregister (&ksocknal_data.ksnd_router);

                ksocknal_free_buffers();
                /* fall through */

        case SOCKNAL_INIT_NOTHING:
                break;
        }

        CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        printk(KERN_INFO "Lustre: Routing socket NAL unloaded (final mem %d)\n",
               atomic_read(&portal_kmemory));
}


void __init
ksocknal_init_incarnation (void)
{
        struct timeval tv;

        /* The incarnation number is the time this module loaded and it
         * identifies this particular instance of the socknal.  Hopefully
         * we won't be able to reboot more frequently than 1MHz for the
         * forseeable future :) */
        
        do_gettimeofday(&tv);
        
        ksocknal_data.ksnd_incarnation = 
                (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;
}

int __init
ksocknal_module_init (void)
{
        int   pkmem = atomic_read(&portal_kmemory);
        int   rc;
        int   i;
        int   j;

        /* packet descriptor must fit in a router descriptor's scratchpad */
        LASSERT(sizeof (ksock_tx_t) <= sizeof (kprfd_scratch_t));
        /* the following must be sizeof(int) for proc_dointvec() */
        LASSERT(sizeof (ksocknal_data.ksnd_io_timeout) == sizeof (int));
        LASSERT(sizeof (ksocknal_data.ksnd_eager_ack) == sizeof (int));
        /* check ksnr_connected/connecting field large enough */
        LASSERT(SOCKNAL_CONN_NTYPES <= 4);
        
        LASSERT (ksocknal_data.ksnd_init == SOCKNAL_INIT_NOTHING);

        ksocknal_api.forward  = ksocknal_api_forward;
        ksocknal_api.shutdown = ksocknal_api_shutdown;
        ksocknal_api.yield    = ksocknal_api_yield;
        ksocknal_api.validate = NULL;           /* our api validate is a NOOP */
        ksocknal_api.lock     = ksocknal_api_lock;
        ksocknal_api.unlock   = ksocknal_api_unlock;
        ksocknal_api.nal_data = &ksocknal_data;

        ksocknal_lib.nal_data = &ksocknal_data;

        memset (&ksocknal_data, 0, sizeof (ksocknal_data)); /* zero pointers */

        ksocknal_data.ksnd_io_timeout = SOCKNAL_IO_TIMEOUT;
        ksocknal_data.ksnd_eager_ack  = SOCKNAL_EAGER_ACK;
        ksocknal_data.ksnd_typed_conns = SOCKNAL_TYPED_CONNS;
        ksocknal_data.ksnd_min_bulk   = SOCKNAL_MIN_BULK;
#if SOCKNAL_ZC
        ksocknal_data.ksnd_zc_min_frag = SOCKNAL_ZC_MIN_FRAG;
#endif
        ksocknal_init_incarnation();
        
        ksocknal_data.ksnd_peer_hash_size = SOCKNAL_PEER_HASH_SIZE;
        PORTAL_ALLOC (ksocknal_data.ksnd_peers,
                      sizeof (struct list_head) * ksocknal_data.ksnd_peer_hash_size);
        if (ksocknal_data.ksnd_peers == NULL)
                return (-ENOMEM);

        for (i = 0; i < ksocknal_data.ksnd_peer_hash_size; i++)
                INIT_LIST_HEAD(&ksocknal_data.ksnd_peers[i]);

        rwlock_init(&ksocknal_data.ksnd_global_lock);

        ksocknal_data.ksnd_nal_cb = &ksocknal_lib;
        spin_lock_init (&ksocknal_data.ksnd_nal_cb_lock);

        spin_lock_init(&ksocknal_data.ksnd_small_fmp.fmp_lock);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_small_fmp.fmp_idle_fmbs);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_small_fmp.fmp_blocked_conns);

        spin_lock_init(&ksocknal_data.ksnd_large_fmp.fmp_lock);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_large_fmp.fmp_idle_fmbs);
        INIT_LIST_HEAD(&ksocknal_data.ksnd_large_fmp.fmp_blocked_conns);

        spin_lock_init (&ksocknal_data.ksnd_reaper_lock);
        INIT_LIST_HEAD (&ksocknal_data.ksnd_enomem_conns);
        INIT_LIST_HEAD (&ksocknal_data.ksnd_zombie_conns);
        INIT_LIST_HEAD (&ksocknal_data.ksnd_deathrow_conns);
        init_waitqueue_head(&ksocknal_data.ksnd_reaper_waitq);

        spin_lock_init (&ksocknal_data.ksnd_autoconnectd_lock);
        INIT_LIST_HEAD (&ksocknal_data.ksnd_autoconnectd_routes);
        init_waitqueue_head(&ksocknal_data.ksnd_autoconnectd_waitq);

        /* NB memset above zeros whole of ksocknal_data, including
         * ksocknal_data.ksnd_irqinfo[all].ksni_valid */

        /* flag lists/ptrs/locks initialised */
        ksocknal_data.ksnd_init = SOCKNAL_INIT_DATA;

        PORTAL_ALLOC(ksocknal_data.ksnd_schedulers,
                     sizeof(ksock_sched_t) * SOCKNAL_N_SCHED);
        if (ksocknal_data.ksnd_schedulers == NULL) {
                ksocknal_module_fini ();
                return (-ENOMEM);
        }

        for (i = 0; i < SOCKNAL_N_SCHED; i++) {
                ksock_sched_t *kss = &ksocknal_data.ksnd_schedulers[i];

                spin_lock_init (&kss->kss_lock);
                INIT_LIST_HEAD (&kss->kss_rx_conns);
                INIT_LIST_HEAD (&kss->kss_tx_conns);
#if SOCKNAL_ZC
                INIT_LIST_HEAD (&kss->kss_zctxdone_list);
#endif
                init_waitqueue_head (&kss->kss_waitq);
        }

        rc = PtlNIInit(ksocknal_init, 32, 4, 0, &ksocknal_ni);
        if (rc != 0) {
                CERROR("ksocknal: PtlNIInit failed: error %d\n", rc);
                ksocknal_module_fini ();
                return (rc);
        }
        PtlNIDebug(ksocknal_ni, ~0);

        ksocknal_data.ksnd_init = SOCKNAL_INIT_PTL; // flag PtlNIInit() called

        for (i = 0; i < SOCKNAL_N_SCHED; i++) {
                rc = ksocknal_thread_start (ksocknal_scheduler,
                                            &ksocknal_data.ksnd_schedulers[i]);
                if (rc != 0) {
                        CERROR("Can't spawn socknal scheduler[%d]: %d\n",
                               i, rc);
                        ksocknal_module_fini ();
                        return (rc);
                }
        }

        for (i = 0; i < SOCKNAL_N_AUTOCONNECTD; i++) {
                rc = ksocknal_thread_start (ksocknal_autoconnectd, (void *)((long)i));
                if (rc != 0) {
                        CERROR("Can't spawn socknal autoconnectd: %d\n", rc);
                        ksocknal_module_fini ();
                        return (rc);
                }
        }

        rc = ksocknal_thread_start (ksocknal_reaper, NULL);
        if (rc != 0) {
                CERROR ("Can't spawn socknal reaper: %d\n", rc);
                ksocknal_module_fini ();
                return (rc);
        }

        rc = kpr_register(&ksocknal_data.ksnd_router,
                          &ksocknal_router_interface);
        if (rc != 0) {
                CDEBUG(D_NET, "Can't initialise routing interface "
                       "(rc = %d): not routing\n", rc);
        } else {
                /* Only allocate forwarding buffers if I'm on a gateway */

                for (i = 0; i < (SOCKNAL_SMALL_FWD_NMSGS +
                                 SOCKNAL_LARGE_FWD_NMSGS); i++) {
                        ksock_fmb_t *fmb;
                        
                        PORTAL_ALLOC(fmb, sizeof(*fmb));
                        if (fmb == NULL) {
                                ksocknal_module_fini();
                                return (-ENOMEM);
                        }

                        if (i < SOCKNAL_SMALL_FWD_NMSGS) {
                                fmb->fmb_npages = SOCKNAL_SMALL_FWD_PAGES;
                                fmb->fmb_pool = &ksocknal_data.ksnd_small_fmp;
                        } else {
                                fmb->fmb_npages = SOCKNAL_LARGE_FWD_PAGES;
                                fmb->fmb_pool = &ksocknal_data.ksnd_large_fmp;
                        }

                        for (j = 0; j < fmb->fmb_npages; j++) {
                                fmb->fmb_pages[j] = alloc_page(GFP_KERNEL);

                                if (fmb->fmb_pages[j] == NULL) {
                                        ksocknal_module_fini ();
                                        return (-ENOMEM);
                                }

                                LASSERT(page_address(fmb->fmb_pages[j]) != NULL);
                        }

                        list_add(&fmb->fmb_list, &fmb->fmb_pool->fmp_idle_fmbs);
                }
        }

        rc = kportal_nal_register(SOCKNAL, &ksocknal_cmd, NULL);
        if (rc != 0) {
                CERROR ("Can't initialise command interface (rc = %d)\n", rc);
                ksocknal_module_fini ();
                return (rc);
        }

        PORTAL_SYMBOL_REGISTER(ksocknal_ni);

#ifdef CONFIG_SYSCTL
        /* Press on regardless even if registering sysctl doesn't work */
        ksocknal_data.ksnd_sysctl = register_sysctl_table (ksocknal_top_ctl_table, 0);
#endif
        /* flag everything initialised */
        ksocknal_data.ksnd_init = SOCKNAL_INIT_ALL;

        printk(KERN_INFO "Lustre: Routing socket NAL loaded "
               "(Routing %s, initial mem %d)\n",
               kpr_routing (&ksocknal_data.ksnd_router) ?
               "enabled" : "disabled", pkmem);

        return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel TCP Socket NAL v0.01");
MODULE_LICENSE("GPL");

module_init(ksocknal_module_init);
module_exit(ksocknal_module_fini);

EXPORT_SYMBOL (ksocknal_ni);
