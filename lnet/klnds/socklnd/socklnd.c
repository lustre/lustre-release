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

ptl_nal_t ksocknal_nal = {
        .nal_type       = SOCKNAL,
        .nal_startup    = ksocknal_startup,
        .nal_shutdown   = ksocknal_shutdown,
        .nal_send       = ksocknal_send,
        .nal_send_pages = ksocknal_send_pages,
        .nal_recv       = ksocknal_recv,
        .nal_recv_pages = ksocknal_recv_pages,
};
ksock_nal_data_t        ksocknal_data;

kpr_nal_interface_t ksocknal_router_interface = {
        kprni_nalid:      SOCKNAL,
        kprni_arg:        &ksocknal_data,
        kprni_fwd:        ksocknal_fwd_packet,
        kprni_notify:     ksocknal_notify,
};

int
ksocknal_set_mynid(ptl_nid_t nid)
{
        ptl_ni_t   *ni = ksocknal_data.ksnd_ni;

        /* FIXME: we have to do this because we call lib_init() at module
         * insertion time, which is before we have 'mynid' available.  lib_init
         * sets the NAL's nid, which it uses to tell other nodes where packets
         * are coming from.  This is not a very graceful solution to this
         * problem. */

        CDEBUG(D_IOCTL, "setting mynid to "LPX64" (old nid="LPX64")\n",
               nid, ni->ni_nid);

        ni->ni_nid = nid;
        return (0);
}

ksock_interface_t *
ksocknal_ip2iface(__u32 ip)
{
        int                i;
        ksock_interface_t *iface;

        for (i = 0; i < ksocknal_data.ksnd_ninterfaces; i++) {
                LASSERT(i < SOCKNAL_MAX_INTERFACES);
                iface = &ksocknal_data.ksnd_interfaces[i];

                if (iface->ksni_ipaddr == ip)
                        return (iface);
        }

        return (NULL);
}

ksock_route_t *
ksocknal_create_route (__u32 ipaddr, int port)
{
        ksock_route_t *route;

        PORTAL_ALLOC (route, sizeof (*route));
        if (route == NULL)
                return (NULL);

        atomic_set (&route->ksnr_refcount, 1);
        route->ksnr_peer = NULL;
        route->ksnr_timeout = cfs_time_current();
        route->ksnr_retry_interval = SOCKNAL_MIN_RECONNECT_INTERVAL;
        route->ksnr_ipaddr = ipaddr;
        route->ksnr_port = port;
        route->ksnr_connecting = 0;
        route->ksnr_connected = 0;
        route->ksnr_deleted = 0;
        route->ksnr_conn_count = 0;
        route->ksnr_share_count = 0;

        return (route);
}

void
ksocknal_destroy_route (ksock_route_t *route)
{
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

        memset (peer, 0, sizeof (*peer));       /* NULL pointers/clear flags etc */

        peer->ksnp_nid = nid;
        atomic_set (&peer->ksnp_refcount, 1);   /* 1 ref for caller */
        peer->ksnp_closing = 0;
        CFS_INIT_LIST_HEAD (&peer->ksnp_conns);
        CFS_INIT_LIST_HEAD (&peer->ksnp_routes);
        CFS_INIT_LIST_HEAD (&peer->ksnp_tx_queue);

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
        int                i;
        __u32              ip;

        for (i = 0; i < peer->ksnp_n_passive_ips; i++) {
                LASSERT (i < SOCKNAL_MAX_INTERFACES);
                ip = peer->ksnp_passive_ips[i];

                ksocknal_ip2iface(ip)->ksni_npeers--;
        }

        LASSERT (list_empty(&peer->ksnp_conns));
        LASSERT (list_empty(&peer->ksnp_routes));
        LASSERT (!peer->ksnp_closing);
        peer->ksnp_closing = 1;
        list_del (&peer->ksnp_list);
        /* lose peerlist's ref */
        ksocknal_put_peer (peer);
}

int
ksocknal_get_peer_info (int index, ptl_nid_t *nid,
                        __u32 *myip, __u32 *peer_ip, int *port,
                        int *conn_count, int *share_count)
{
        ksock_peer_t      *peer;
        struct list_head  *ptmp;
        ksock_route_t     *route;
        struct list_head  *rtmp;
        int                i;
        int                j;
        int                rc = -ENOENT;

        read_lock (&ksocknal_data.ksnd_global_lock);

        for (i = 0; i < ksocknal_data.ksnd_peer_hash_size; i++) {

                list_for_each (ptmp, &ksocknal_data.ksnd_peers[i]) {
                        peer = list_entry (ptmp, ksock_peer_t, ksnp_list);

                        if (peer->ksnp_n_passive_ips == 0 &&
                            list_empty(&peer->ksnp_routes)) {
                                if (index-- > 0)
                                        continue;

                                *nid = peer->ksnp_nid;
                                *myip = 0;
                                *peer_ip = 0;
                                *port = 0;
                                *conn_count = 0;
                                *share_count = 0;
                                rc = 0;
                                goto out;
                        }

                        for (j = 0; j < peer->ksnp_n_passive_ips; j++) {
                                if (index-- > 0)
                                        continue;

                                *nid = peer->ksnp_nid;
                                *myip = peer->ksnp_passive_ips[j];
                                *peer_ip = 0;
                                *port = 0;
                                *conn_count = 0;
                                *share_count = 0;
                                rc = 0;
                                goto out;
                        }

                        list_for_each (rtmp, &peer->ksnp_routes) {
                                if (index-- > 0)
                                        continue;

                                route = list_entry(rtmp, ksock_route_t,
                                                   ksnr_list);

                                *nid = peer->ksnp_nid;
                                *myip = route->ksnr_myipaddr;
                                *peer_ip = route->ksnr_ipaddr;
                                *port = route->ksnr_port;
                                *conn_count = route->ksnr_conn_count;
                                *share_count = route->ksnr_share_count;
                                rc = 0;
                                goto out;
                        }
                }
        }
 out:
        read_unlock (&ksocknal_data.ksnd_global_lock);
        return (rc);
}

void
ksocknal_associate_route_conn_locked(ksock_route_t *route, ksock_conn_t *conn)
{
        ksock_peer_t      *peer = route->ksnr_peer;
        int                type = conn->ksnc_type;
        ksock_interface_t *iface;

        conn->ksnc_route = route;
        atomic_inc (&route->ksnr_refcount);

        if (route->ksnr_myipaddr != conn->ksnc_myipaddr) {
                if (route->ksnr_myipaddr == 0) {
                        /* route wasn't bound locally yet (the initial route) */
                        CWARN("Binding "LPX64" %u.%u.%u.%u to %u.%u.%u.%u\n",
                              peer->ksnp_nid,
                              HIPQUAD(route->ksnr_ipaddr),
                              HIPQUAD(conn->ksnc_myipaddr));
                } else {
                        CWARN("Rebinding "LPX64" %u.%u.%u.%u from "
                              "%u.%u.%u.%u to %u.%u.%u.%u\n",
                              peer->ksnp_nid,
                              HIPQUAD(route->ksnr_ipaddr),
                              HIPQUAD(route->ksnr_myipaddr),
                              HIPQUAD(conn->ksnc_myipaddr));

                        iface = ksocknal_ip2iface(route->ksnr_myipaddr);
                        if (iface != NULL)
                                iface->ksni_nroutes--;
                }
                route->ksnr_myipaddr = conn->ksnc_myipaddr;
                iface = ksocknal_ip2iface(route->ksnr_myipaddr);
                if (iface != NULL)
                        iface->ksni_nroutes++;
        }

        route->ksnr_connected |= (1<<type);
        route->ksnr_conn_count++;

        /* Successful connection => further attempts can
         * proceed immediately */
        route->ksnr_timeout = cfs_time_current();
        route->ksnr_retry_interval = SOCKNAL_MIN_RECONNECT_INTERVAL;
}

void
ksocknal_add_route_locked (ksock_peer_t *peer, ksock_route_t *route)
{
        struct list_head  *tmp;
        ksock_conn_t      *conn;
        int                type;
        ksock_route_t     *route2;

        LASSERT (route->ksnr_peer == NULL);
        LASSERT (!route->ksnr_connecting);
        LASSERT (route->ksnr_connected == 0);

        /* LASSERT(unique) */
        list_for_each(tmp, &peer->ksnp_routes) {
                route2 = list_entry(tmp, ksock_route_t, ksnr_list);

                if (route2->ksnr_ipaddr == route->ksnr_ipaddr) {
                        CERROR ("Duplicate route "LPX64" %u.%u.%u.%u\n",
                                peer->ksnp_nid, HIPQUAD(route->ksnr_ipaddr));
                        LBUG();
                }
        }

        route->ksnr_peer = peer;
        atomic_inc (&peer->ksnp_refcount);
        /* peer's routelist takes over my ref on 'route' */
        list_add_tail(&route->ksnr_list, &peer->ksnp_routes);

        list_for_each(tmp, &peer->ksnp_conns) {
                conn = list_entry(tmp, ksock_conn_t, ksnc_list);
                type = conn->ksnc_type;

                if (conn->ksnc_ipaddr != route->ksnr_ipaddr)
                        continue;

                ksocknal_associate_route_conn_locked(route, conn);
                /* keep going (typed routes) */
        }
}

void
ksocknal_del_route_locked (ksock_route_t *route)
{
        ksock_peer_t      *peer = route->ksnr_peer;
        ksock_interface_t *iface;
        ksock_conn_t      *conn;
        struct list_head  *ctmp;
        struct list_head  *cnxt;

        LASSERT (!route->ksnr_deleted);

        /* Close associated conns */
        list_for_each_safe (ctmp, cnxt, &peer->ksnp_conns) {
                conn = list_entry(ctmp, ksock_conn_t, ksnc_list);

                if (conn->ksnc_route != route)
                        continue;

                ksocknal_close_conn_locked (conn, 0);
        }

        if (route->ksnr_myipaddr != 0) {
                iface = ksocknal_ip2iface(route->ksnr_myipaddr);
                if (iface != NULL)
                        iface->ksni_nroutes--;
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
ksocknal_add_peer (ptl_nid_t nid, __u32 ipaddr, int port)
{
        unsigned long      flags;
        struct list_head  *tmp;
        ksock_peer_t      *peer;
        ksock_peer_t      *peer2;
        ksock_route_t     *route;
        ksock_route_t     *route2;

        if (nid == PTL_NID_ANY)
                return (-EINVAL);

        /* Have a brand new peer ready... */
        peer = ksocknal_create_peer (nid);
        if (peer == NULL)
                return (-ENOMEM);

        route = ksocknal_create_route (ipaddr, port);
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
                /* peer table takes my ref on peer */
                list_add_tail (&peer->ksnp_list,
                               ksocknal_nid2peerlist (nid));
        }

        route2 = NULL;
        list_for_each (tmp, &peer->ksnp_routes) {
                route2 = list_entry(tmp, ksock_route_t, ksnr_list);

                if (route2->ksnr_ipaddr == ipaddr)
                        break;

                route2 = NULL;
        }
        if (route2 == NULL) {
                ksocknal_add_route_locked(peer, route);
                route->ksnr_share_count++;
        } else {
                ksocknal_put_route(route);
                route2->ksnr_share_count++;
        }

        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        return (0);
}

void
ksocknal_del_peer_locked (ksock_peer_t *peer, __u32 ip, int single_share)
{
        ksock_conn_t     *conn;
        ksock_route_t    *route;
        struct list_head *tmp;
        struct list_head *nxt;
        int               nshared;

        LASSERT (!peer->ksnp_closing);

        /* Extra ref prevents peer disappearing until I'm done with it */
        atomic_inc(&peer->ksnp_refcount);

        list_for_each_safe (tmp, nxt, &peer->ksnp_routes) {
                route = list_entry(tmp, ksock_route_t, ksnr_list);

                if (single_share && route->ksnr_share_count == 0)
                        continue;

                /* no match */
                if (!(ip == 0 || route->ksnr_ipaddr == ip))
                        continue;

                if (!single_share)
                        route->ksnr_share_count = 0;
                else if (route->ksnr_share_count > 0)
                        route->ksnr_share_count--;

                if (route->ksnr_share_count == 0) {
                        /* This deletes associated conns too */
                        ksocknal_del_route_locked (route);
                }

                if (single_share)
                        break;
        }

        nshared = 0;
        list_for_each_safe (tmp, nxt, &peer->ksnp_routes) {
                route = list_entry(tmp, ksock_route_t, ksnr_list);
                nshared += route->ksnr_share_count;
        }

        if (nshared == 0) {
                /* remove everything else if there are no explicit entries
                 * left */

                list_for_each_safe (tmp, nxt, &peer->ksnp_routes) {
                        route = list_entry(tmp, ksock_route_t, ksnr_list);

                        /* we should only be removing auto-entries */
                        LASSERT(route->ksnr_share_count == 0);
                        ksocknal_del_route_locked (route);
                }

                list_for_each_safe (tmp, nxt, &peer->ksnp_conns) {
                        conn = list_entry(tmp, ksock_conn_t, ksnc_list);

                        ksocknal_close_conn_locked(conn, 0);
                }
        }

        ksocknal_put_peer(peer);
        /* NB peer unlinks itself when last conn/route is removed */
}

int
ksocknal_del_peer (ptl_nid_t nid, __u32 ip, int single_share)
{
        unsigned long      flags;
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        ksock_peer_t      *peer;
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

                        ksocknal_del_peer_locked (peer, ip, single_share);
                        rc = 0;                 /* matched! */

                        if (single_share)
                                break;
                }
        }

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

                        LASSERT (!peer->ksnp_closing);

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
        for (i = 1; i < ksocknal_data.ksnd_nschedulers; i++)
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
ksocknal_local_ipvec (__u32 *ipaddrs)
{
        int                i;
        int                nip;

        read_lock (&ksocknal_data.ksnd_global_lock);

        nip = ksocknal_data.ksnd_ninterfaces;
        for (i = 0; i < nip; i++) {
                LASSERT (i < SOCKNAL_MAX_INTERFACES);

                ipaddrs[i] = ksocknal_data.ksnd_interfaces[i].ksni_ipaddr;
                LASSERT (ipaddrs[i] != 0);
        }

        read_unlock (&ksocknal_data.ksnd_global_lock);
        return (nip);
}

int
ksocknal_match_peerip (ksock_interface_t *iface, __u32 *ips, int nips)
{
        int   best_netmatch = 0;
        int   best_xor      = 0;
        int   best          = -1;
        int   this_xor;
        int   this_netmatch;
        int   i;

        for (i = 0; i < nips; i++) {
                if (ips[i] == 0)
                        continue;

                this_xor = (ips[i] ^ iface->ksni_ipaddr);
                this_netmatch = ((this_xor & iface->ksni_netmask) == 0) ? 1 : 0;

                if (!(best < 0 ||
                      best_netmatch < this_netmatch ||
                      (best_netmatch == this_netmatch &&
                       best_xor > this_xor)))
                        continue;

                best = i;
                best_netmatch = this_netmatch;
                best_xor = this_xor;
        }

        LASSERT (best >= 0);
        return (best);
}

int
ksocknal_select_ips(ksock_peer_t *peer, __u32 *peerips, int n_peerips)
{
        rwlock_t           *global_lock = &ksocknal_data.ksnd_global_lock;
        unsigned long       flags;
        ksock_interface_t  *iface;
        ksock_interface_t  *best_iface;
        int                 n_ips;
        int                 i;
        int                 j;
        int                 k;
        __u32               ip;
        __u32               xor;
        int                 this_netmatch;
        int                 best_netmatch;
        int                 best_npeers;

        /* CAVEAT EMPTOR: We do all our interface matching with an
         * exclusive hold of global lock at IRQ priority.  We're only
         * expecting to be dealing with small numbers of interfaces, so the
         * O(n**3)-ness shouldn't matter */

        /* Also note that I'm not going to return more than n_peerips
         * interfaces, even if I have more myself */

        write_lock_irqsave(global_lock, flags);

        LASSERT (n_peerips <= SOCKNAL_MAX_INTERFACES);
        LASSERT (ksocknal_data.ksnd_ninterfaces <= SOCKNAL_MAX_INTERFACES);

        n_ips = MIN(n_peerips, ksocknal_data.ksnd_ninterfaces);

        for (i = 0; peer->ksnp_n_passive_ips < n_ips; i++) {
                /*              ^ yes really... */

                /* If we have any new interfaces, first tick off all the
                 * peer IPs that match old interfaces, then choose new
                 * interfaces to match the remaining peer IPS.
                 * We don't forget interfaces we've stopped using; we might
                 * start using them again... */

                if (i < peer->ksnp_n_passive_ips) {
                        /* Old interface. */
                        ip = peer->ksnp_passive_ips[i];
                        best_iface = ksocknal_ip2iface(ip);

                        /* peer passive ips are kept up to date */
                        LASSERT(best_iface != NULL);
                } else {
                        /* choose a new interface */
                        LASSERT (i == peer->ksnp_n_passive_ips);

                        best_iface = NULL;
                        best_netmatch = 0;
                        best_npeers = 0;

                        for (j = 0; j < ksocknal_data.ksnd_ninterfaces; j++) {
                                iface = &ksocknal_data.ksnd_interfaces[j];
                                ip = iface->ksni_ipaddr;

                                for (k = 0; k < peer->ksnp_n_passive_ips; k++)
                                        if (peer->ksnp_passive_ips[k] == ip)
                                                break;

                                if (k < peer->ksnp_n_passive_ips) /* using it already */
                                        continue;

                                k = ksocknal_match_peerip(iface, peerips, n_peerips);
                                xor = (ip ^ peerips[k]);
                                this_netmatch = ((xor & iface->ksni_netmask) == 0) ? 1 : 0;

                                if (!(best_iface == NULL ||
                                      best_netmatch < this_netmatch ||
                                      (best_netmatch == this_netmatch &&
                                       best_npeers > iface->ksni_npeers)))
                                        continue;

                                best_iface = iface;
                                best_netmatch = this_netmatch;
                                best_npeers = iface->ksni_npeers;
                        }

                        best_iface->ksni_npeers++;
                        ip = best_iface->ksni_ipaddr;
                        peer->ksnp_passive_ips[i] = ip;
                        peer->ksnp_n_passive_ips = i+1;
                }

                LASSERT (best_iface != NULL);

                /* mark the best matching peer IP used */
                j = ksocknal_match_peerip(best_iface, peerips, n_peerips);
                peerips[j] = 0;
        }

        /* Overwrite input peer IP addresses */
        memcpy(peerips, peer->ksnp_passive_ips, n_ips * sizeof(*peerips));

        write_unlock_irqrestore(global_lock, flags);

        return (n_ips);
}

void
ksocknal_create_routes(ksock_peer_t *peer, int port,
                       __u32 *peer_ipaddrs, int npeer_ipaddrs)
{
        ksock_route_t      *newroute = NULL;
        rwlock_t           *global_lock = &ksocknal_data.ksnd_global_lock;
        unsigned long       flags;
        struct list_head   *rtmp;
        ksock_route_t      *route;
        ksock_interface_t  *iface;
        ksock_interface_t  *best_iface;
        int                 best_netmatch;
        int                 this_netmatch;
        int                 best_nroutes;
        int                 i;
        int                 j;

        /* CAVEAT EMPTOR: We do all our interface matching with an
         * exclusive hold of global lock at IRQ priority.  We're only
         * expecting to be dealing with small numbers of interfaces, so the
         * O(n**3)-ness here shouldn't matter */

        write_lock_irqsave(global_lock, flags);

        LASSERT (npeer_ipaddrs <= SOCKNAL_MAX_INTERFACES);

        for (i = 0; i < npeer_ipaddrs; i++) {
                if (newroute != NULL) {
                        newroute->ksnr_ipaddr = peer_ipaddrs[i];
                } else {
                        write_unlock_irqrestore(global_lock, flags);

                        newroute = ksocknal_create_route(peer_ipaddrs[i], port);
                        if (newroute == NULL)
                                return;

                        write_lock_irqsave(global_lock, flags);
                }

                /* Already got a route? */
                route = NULL;
                list_for_each(rtmp, &peer->ksnp_routes) {
                        route = list_entry(rtmp, ksock_route_t, ksnr_list);

                        if (route->ksnr_ipaddr == newroute->ksnr_ipaddr)
                                break;

                        route = NULL;
                }
                if (route != NULL)
                        continue;

                best_iface = NULL;
                best_nroutes = 0;
                best_netmatch = 0;

                LASSERT (ksocknal_data.ksnd_ninterfaces <= SOCKNAL_MAX_INTERFACES);

                /* Select interface to connect from */
                for (j = 0; j < ksocknal_data.ksnd_ninterfaces; j++) {
                        iface = &ksocknal_data.ksnd_interfaces[j];

                        /* Using this interface already? */
                        list_for_each(rtmp, &peer->ksnp_routes) {
                                route = list_entry(rtmp, ksock_route_t, ksnr_list);

                                if (route->ksnr_myipaddr == iface->ksni_ipaddr)
                                        break;

                                route = NULL;
                        }
                        if (route != NULL)
                                continue;

                        this_netmatch = (((iface->ksni_ipaddr ^
                                           newroute->ksnr_ipaddr) &
                                           iface->ksni_netmask) == 0) ? 1 : 0;

                        if (!(best_iface == NULL ||
                              best_netmatch < this_netmatch ||
                              (best_netmatch == this_netmatch &&
                               best_nroutes > iface->ksni_nroutes)))
                                continue;

                        best_iface = iface;
                        best_netmatch = this_netmatch;
                        best_nroutes = iface->ksni_nroutes;
                }

                if (best_iface == NULL)
                        continue;

                newroute->ksnr_myipaddr = best_iface->ksni_ipaddr;
                best_iface->ksni_nroutes++;

                ksocknal_add_route_locked(peer, newroute);
                newroute = NULL;
        }

        write_unlock_irqrestore(global_lock, flags);
        if (newroute != NULL)
                ksocknal_put_route(newroute);
}

int
ksocknal_create_conn (ksock_route_t *route, struct socket *sock, int type)
{
        int                passive = (type == SOCKNAL_CONN_NONE);
        rwlock_t          *global_lock = &ksocknal_data.ksnd_global_lock;
        __u32              ipaddrs[SOCKNAL_MAX_INTERFACES];
        int                nipaddrs;
        ptl_nid_t          nid;
        struct list_head  *tmp;
        __u64              incarnation;
        unsigned long      flags;
        ksock_conn_t      *conn;
        ksock_conn_t      *conn2;
        ksock_peer_t      *peer = NULL;
        ksock_peer_t      *peer2;
        ksock_sched_t     *sched;
        unsigned int       irq;
        ksock_tx_t        *tx;
        int                rc;

        /* NB, sock has an associated file since (a) this connection might
         * have been created in userland and (b) we need to refcount the
         * socket so that we don't close it while I/O is being done on
         * it, and sock->file has that pre-cooked... */
        LASSERT (KSN_SOCK2FILE(sock) != NULL);
        LASSERT (cfs_file_count(KSN_SOCK2FILE(sock)) > 0);
        LASSERT (route == NULL || !passive);

        rc = ksocknal_lib_setup_sock (sock);
        if (rc != 0)
                return (rc);

        irq = ksocknal_lib_sock_irq (sock);

        PORTAL_ALLOC(conn, sizeof(*conn));
        if (conn == NULL)
                return (-ENOMEM);

        memset (conn, 0, sizeof (*conn));
        conn->ksnc_peer = NULL;
        conn->ksnc_route = NULL;
        conn->ksnc_sock = sock;
        conn->ksnc_type = type;
        ksocknal_lib_save_callback(sock, conn);
        atomic_set (&conn->ksnc_refcount, 1);    /* 1 ref for me */

        conn->ksnc_rx_ready = 0;
        conn->ksnc_rx_scheduled = 0;
        ksocknal_new_packet (conn, 0);

        CFS_INIT_LIST_HEAD (&conn->ksnc_tx_queue);
        conn->ksnc_tx_ready = 0;
        conn->ksnc_tx_scheduled = 0;
        atomic_set (&conn->ksnc_tx_nob, 0);

        /* stash conn's local and remote addrs */
        rc = ksocknal_lib_get_conn_addrs (conn);
        if (rc != 0)
                goto failed_0;

        if (!passive) {
                /* Active connection sends HELLO eagerly */
                rc = ksocknal_local_ipvec(ipaddrs);
                if (rc < 0)
                        goto failed_0;
                nipaddrs = rc;

                rc = ksocknal_send_hello (conn, ipaddrs, nipaddrs);
                if (rc != 0)
                        goto failed_0;
        }

        /* Find out/confirm peer's NID and connection type and get the
         * vector of interfaces she's willing to let me connect to */
        nid = (route == NULL) ? PTL_NID_ANY : route->ksnr_peer->ksnp_nid;
        rc = ksocknal_recv_hello (conn, &nid, &incarnation, ipaddrs);
        if (rc < 0)
                goto failed_0;
        nipaddrs = rc;
        LASSERT (nid != PTL_NID_ANY);

        if (route != NULL) {
                peer = route->ksnr_peer;
                atomic_inc(&peer->ksnp_refcount);
        } else {
                peer = ksocknal_create_peer(nid);
                if (peer == NULL) {
                        rc = -ENOMEM;
                        goto failed_0;
                }

                write_lock_irqsave(global_lock, flags);

                peer2 = ksocknal_find_peer_locked(nid);
                if (peer2 == NULL) {
                        /* NB this puts an "empty" peer in the peer
                         * table (which takes my ref) */
                        list_add_tail(&peer->ksnp_list,
                                      ksocknal_nid2peerlist(nid));
                } else  {
                        ksocknal_put_peer(peer);
                        peer = peer2;
                }
                /* +1 ref for me */
                atomic_inc(&peer->ksnp_refcount);

                write_unlock_irqrestore(global_lock, flags);
        }

        if (!passive) {
                ksocknal_create_routes(peer, conn->ksnc_port,
                                       ipaddrs, nipaddrs);
                rc = 0;
        } else {
                rc = ksocknal_select_ips(peer, ipaddrs, nipaddrs);
                LASSERT (rc >= 0);
                rc = ksocknal_send_hello (conn, ipaddrs, rc);
        }
        if (rc < 0)
                goto failed_1;

        write_lock_irqsave (global_lock, flags);

        if (peer->ksnp_closing ||
            (route != NULL && route->ksnr_deleted)) {
                /* route/peer got closed under me */
                rc = -ESTALE;
                goto failed_2;
        }

        /* Refuse to duplicate an existing connection (both sides might
         * autoconnect at once), unless this is a loopback connection */
        if (conn->ksnc_ipaddr != conn->ksnc_myipaddr) {
                list_for_each(tmp, &peer->ksnp_conns) {
                        conn2 = list_entry(tmp, ksock_conn_t, ksnc_list);

                        if (conn2->ksnc_ipaddr != conn->ksnc_ipaddr ||
                            conn2->ksnc_myipaddr != conn->ksnc_myipaddr ||
                            conn2->ksnc_type != conn->ksnc_type ||
                            conn2->ksnc_incarnation != incarnation)
                                continue;

                        CWARN("Not creating duplicate connection to "
                              "%u.%u.%u.%u type %d\n",
                              HIPQUAD(conn->ksnc_ipaddr), conn->ksnc_type);
                        rc = -EALREADY;
                        goto failed_2;
                }
        }

        /* If the connection created by this route didn't bind to the IP
         * address the route connected to, the connection/route matching
         * code below probably isn't going to work. */
        if (route != NULL &&
            route->ksnr_ipaddr != conn->ksnc_ipaddr) {
                CERROR("Route "LPX64" %u.%u.%u.%u connected to %u.%u.%u.%u\n",
                       peer->ksnp_nid,
                       HIPQUAD(route->ksnr_ipaddr),
                       HIPQUAD(conn->ksnc_ipaddr));
        }

        /* Search for a route corresponding to the new connection and
         * create an association.  This allows incoming connections created
         * by routes in my peer to match my own route entries so I don't
         * continually create duplicate routes. */
        list_for_each (tmp, &peer->ksnp_routes) {
                route = list_entry(tmp, ksock_route_t, ksnr_list);

                if (route->ksnr_ipaddr != conn->ksnc_ipaddr)
                        continue;

                ksocknal_associate_route_conn_locked(route, conn);
                break;
        }

        /* Give conn a ref on sock->file since we're going to return success */
        cfs_get_file(KSN_SOCK2FILE(sock));

        conn->ksnc_peer = peer;                 /* conn takes my ref on peer */
        conn->ksnc_incarnation = incarnation;
        peer->ksnp_last_alive = cfs_time_current();
        peer->ksnp_error = 0;

        sched = ksocknal_choose_scheduler_locked (irq);
        sched->kss_nconns++;
        conn->ksnc_scheduler = sched;

        /* Set the deadline for the outgoing HELLO to drain */
        conn->ksnc_tx_bufnob = SOCK_WMEM_QUEUED(sock);
        conn->ksnc_tx_deadline = cfs_time_shift(*ksocknal_tunables.ksnd_timeout);
        mb();       /* order with adding to peer's conn list */

        list_add (&conn->ksnc_list, &peer->ksnp_conns);
        atomic_inc (&conn->ksnc_refcount);

        /* NB my callbacks block while I hold ksnd_global_lock */
        ksocknal_lib_set_callback(sock, conn);

        /* Take all the packets blocking for a connection.
         * NB, it might be nicer to share these blocked packets among any
         * other connections that are becoming established. */
        while (!list_empty (&peer->ksnp_tx_queue)) {
                tx = list_entry (peer->ksnp_tx_queue.next,
                                 ksock_tx_t, tx_list);

                list_del (&tx->tx_list);
                ksocknal_queue_tx_locked (tx, conn);
        }

        rc = ksocknal_close_stale_conns_locked(peer, incarnation);
        if (rc != 0)
                CERROR ("Closed %d stale conns to nid "LPX64" ip %d.%d.%d.%d\n",
                        rc, conn->ksnc_peer->ksnp_nid,
                        HIPQUAD(conn->ksnc_ipaddr));

        write_unlock_irqrestore (global_lock, flags);

        ksocknal_lib_bind_irq (irq);

        /* Call the callbacks right now to get things going. */
        if (ksocknal_getconnsock(conn) == 0) {
                ksocknal_lib_act_callback(sock, conn);
                ksocknal_putconnsock(conn);
        }

        CWARN("New conn nid:"LPX64" %u.%u.%u.%u -> %u.%u.%u.%u/%d"
              " incarnation:"LPX64" sched[%d]/%d\n",
              nid, HIPQUAD(conn->ksnc_myipaddr),
              HIPQUAD(conn->ksnc_ipaddr), conn->ksnc_port, incarnation,
              (int)(conn->ksnc_scheduler - ksocknal_data.ksnd_schedulers), irq);

        ksocknal_put_conn (conn);
        return (0);

 failed_2:
        if (!peer->ksnp_closing &&
            list_empty (&peer->ksnp_conns) &&
            list_empty (&peer->ksnp_routes))
                ksocknal_unlink_peer_locked(peer);
        write_unlock_irqrestore(global_lock, flags);

 failed_1:
        ksocknal_put_peer (peer);

 failed_0:
        PORTAL_FREE (conn, sizeof(*conn));

        LASSERT (rc != 0);
        return (rc);
}

void
ksocknal_close_conn_locked (ksock_conn_t *conn, int error)
{
        /* This just does the immmediate housekeeping, and queues the
         * connection for the reaper to terminate.
         * Caller holds ksnd_global_lock exclusively in irq context */
        ksock_peer_t      *peer = conn->ksnc_peer;
        ksock_route_t     *route;
        ksock_conn_t      *conn2;
        struct list_head  *tmp;

        LASSERT (peer->ksnp_error == 0);
        LASSERT (!conn->ksnc_closing);
        conn->ksnc_closing = 1;
        atomic_inc (&ksocknal_data.ksnd_nclosing_conns);

        /* ksnd_deathrow_conns takes over peer's ref */
        list_del (&conn->ksnc_list);

        route = conn->ksnc_route;
        if (route != NULL) {
                /* dissociate conn from route... */
                LASSERT (!route->ksnr_deleted);
                LASSERT ((route->ksnr_connected & (1 << conn->ksnc_type)) != 0);

                conn2 = NULL;
                list_for_each(tmp, &peer->ksnp_conns) {
                        conn2 = list_entry(tmp, ksock_conn_t, ksnc_list);

                        if (conn2->ksnc_route == route &&
                            conn2->ksnc_type == conn->ksnc_type)
                                break;

                        conn2 = NULL;
                }
                if (conn2 == NULL)
                        route->ksnr_connected &= ~(1 << conn->ksnc_type);

                conn->ksnc_route = NULL;

#if 0           /* irrelevent with only eager routes */
                list_del (&route->ksnr_list);   /* make route least favourite */
                list_add_tail (&route->ksnr_list, &peer->ksnp_routes);
#endif
                ksocknal_put_route (route);     /* drop conn's ref on route */
        }

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
        cfs_waitq_signal (&ksocknal_data.ksnd_reaper_waitq);

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

                cfs_waitq_signal (&sched->kss_waitq);
        }

        spin_unlock_irqrestore (&sched->kss_lock, flags);

        /* serialise with callbacks */
        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        ksocknal_lib_reset_callback(conn->ksnc_sock, conn);

        /* OK, so this conn may not be completely disengaged from its
         * scheduler yet, but it _has_ committed to terminate... */
        conn->ksnc_scheduler->kss_nconns--;

        if (peer->ksnp_error != 0) {
                /* peer's last conn closed in error */
                LASSERT (list_empty (&peer->ksnp_conns));

                /* convert peer's last-known-alive timestamp from jiffies */
                do_gettimeofday (&now);
                then = now.tv_sec - cfs_duration_sec(cfs_time_sub(cfs_time_current(),
                                                                  peer->ksnp_last_alive));
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
                CERROR("Completing partial receive from "LPX64
                       ", ip %d.%d.%d.%d:%d, with error\n",
                       conn->ksnc_peer->ksnp_nid,
                       HIPQUAD(conn->ksnc_ipaddr), conn->ksnc_port);
                ptl_finalize (ksocknal_data.ksnd_ni, NULL, 
                              conn->ksnc_cookie, PTL_FAIL);
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
        cfs_waitq_signal (&ksocknal_data.ksnd_reaper_waitq);

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

                CWARN("Closing stale conn nid:"LPX64" ip:%08x/%d "
                      "incarnation:"LPX64"("LPX64")\n",
                      peer->ksnp_nid, conn->ksnc_ipaddr, conn->ksnc_port,
                      conn->ksnc_incarnation, incarnation);

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

                ksocknal_lib_push_conn (conn);
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
ksocknal_add_interface(__u32 ipaddress, __u32 netmask)
{
        unsigned long      flags;
        ksock_interface_t *iface;
        int                rc;
        int                i;
        int                j;
        struct list_head  *ptmp;
        ksock_peer_t      *peer;
        struct list_head  *rtmp;
        ksock_route_t     *route;

        if (ipaddress == 0 ||
            netmask == 0)
                return (-EINVAL);

        write_lock_irqsave(&ksocknal_data.ksnd_global_lock, flags);

        iface = ksocknal_ip2iface(ipaddress);
        if (iface != NULL) {
                /* silently ignore dups */
                rc = 0;
        } else if (ksocknal_data.ksnd_ninterfaces == SOCKNAL_MAX_INTERFACES) {
                rc = -ENOSPC;
        } else {
                iface = &ksocknal_data.ksnd_interfaces[ksocknal_data.ksnd_ninterfaces++];

                iface->ksni_ipaddr = ipaddress;
                iface->ksni_netmask = netmask;
                iface->ksni_nroutes = 0;
                iface->ksni_npeers = 0;

                for (i = 0; i < ksocknal_data.ksnd_peer_hash_size; i++) {
                        list_for_each(ptmp, &ksocknal_data.ksnd_peers[i]) {
                                peer = list_entry(ptmp, ksock_peer_t, ksnp_list);

                                for (j = 0; i < peer->ksnp_n_passive_ips; j++)
                                        if (peer->ksnp_passive_ips[j] == ipaddress)
                                                iface->ksni_npeers++;

                                list_for_each(rtmp, &peer->ksnp_routes) {
                                        route = list_entry(rtmp, ksock_route_t, ksnr_list);

                                        if (route->ksnr_myipaddr == ipaddress)
                                                iface->ksni_nroutes++;
                                }
                        }
                }

                rc = 0;
                /* NB only new connections will pay attention to the new interface! */
        }

        write_unlock_irqrestore(&ksocknal_data.ksnd_global_lock, flags);

        return (rc);
}

void
ksocknal_peer_del_interface_locked(ksock_peer_t *peer, __u32 ipaddr)
{
        struct list_head   *tmp;
        struct list_head   *nxt;
        ksock_route_t      *route;
        ksock_conn_t       *conn;
        int                 i;
        int                 j;

        for (i = 0; i < peer->ksnp_n_passive_ips; i++)
                if (peer->ksnp_passive_ips[i] == ipaddr) {
                        for (j = i+1; j < peer->ksnp_n_passive_ips; j++)
                                peer->ksnp_passive_ips[j-1] =
                                        peer->ksnp_passive_ips[j];
                        peer->ksnp_n_passive_ips--;
                        break;
                }

        list_for_each_safe(tmp, nxt, &peer->ksnp_routes) {
                route = list_entry (tmp, ksock_route_t, ksnr_list);

                if (route->ksnr_myipaddr != ipaddr)
                        continue;

                if (route->ksnr_share_count != 0) {
                        /* Manually created; keep, but unbind */
                        route->ksnr_myipaddr = 0;
                } else {
                        ksocknal_del_route_locked(route);
                }
        }

        list_for_each_safe(tmp, nxt, &peer->ksnp_conns) {
                conn = list_entry(tmp, ksock_conn_t, ksnc_list);

                if (conn->ksnc_myipaddr == ipaddr)
                        ksocknal_close_conn_locked (conn, 0);
        }
}

int
ksocknal_del_interface(__u32 ipaddress)
{
        int                rc = -ENOENT;
        unsigned long      flags;
        struct list_head  *tmp;
        struct list_head  *nxt;
        ksock_peer_t      *peer;
        __u32              this_ip;
        int                i;
        int                j;

        write_lock_irqsave(&ksocknal_data.ksnd_global_lock, flags);

        for (i = 0; i < ksocknal_data.ksnd_ninterfaces; i++) {
                this_ip = ksocknal_data.ksnd_interfaces[i].ksni_ipaddr;

                if (!(ipaddress == 0 ||
                      ipaddress == this_ip))
                        continue;

                rc = 0;

                for (j = i+1; j < ksocknal_data.ksnd_ninterfaces; j++)
                        ksocknal_data.ksnd_interfaces[j-1] =
                                ksocknal_data.ksnd_interfaces[j];

                ksocknal_data.ksnd_ninterfaces--;

                for (j = 0; j < ksocknal_data.ksnd_peer_hash_size; j++) {
                        list_for_each_safe(tmp, nxt, &ksocknal_data.ksnd_peers[j]) {
                                peer = list_entry(tmp, ksock_peer_t, ksnp_list);

                                ksocknal_peer_del_interface_locked(peer, this_ip);
                        }
                }
        }

        write_unlock_irqrestore(&ksocknal_data.ksnd_global_lock, flags);

        return (rc);
}

int
ksocknal_cmd(struct portals_cfg *pcfg, void * private)
{
        int rc;

        switch(pcfg->pcfg_command) {
        case NAL_CMD_GET_INTERFACE: {
                ksock_interface_t *iface;

                read_lock (&ksocknal_data.ksnd_global_lock);

                if (pcfg->pcfg_count < 0 ||
                    pcfg->pcfg_count >= ksocknal_data.ksnd_ninterfaces) {
                        rc = -ENOENT;
                } else {
                        rc = 0;
                        iface = &ksocknal_data.ksnd_interfaces[pcfg->pcfg_count];

                        pcfg->pcfg_id    = iface->ksni_ipaddr;
                        pcfg->pcfg_misc  = iface->ksni_netmask;
                        pcfg->pcfg_fd    = iface->ksni_npeers;
                        pcfg->pcfg_count = iface->ksni_nroutes;
                }

                read_unlock (&ksocknal_data.ksnd_global_lock);
                break;
        }
        case NAL_CMD_ADD_INTERFACE: {
                rc = ksocknal_add_interface(pcfg->pcfg_id, /* IP address */
                                            pcfg->pcfg_misc); /* net mask */
                break;
        }
        case NAL_CMD_DEL_INTERFACE: {
                rc = ksocknal_del_interface(pcfg->pcfg_id); /* IP address */
                break;
        }
        case NAL_CMD_GET_PEER: {
                ptl_nid_t    nid = 0;
                __u32        myip = 0;
                __u32        ip = 0;
                int          port = 0;
                int          conn_count = 0;
                int          share_count = 0;

                rc = ksocknal_get_peer_info(pcfg->pcfg_count, &nid,
                                            &myip, &ip, &port,
                                            &conn_count,  &share_count);
                pcfg->pcfg_nid   = nid;
                pcfg->pcfg_size  = myip;
                pcfg->pcfg_id    = ip;
                pcfg->pcfg_misc  = port;
                pcfg->pcfg_count = conn_count;
                pcfg->pcfg_wait  = share_count;
                break;
        }
        case NAL_CMD_ADD_PEER: {
#if 1
                CDEBUG(D_WARNING, "ADD_PEER: ignoring "
                       LPX64"@%u.%u.%u.%u:%d\n",
                       pcfg->pcfg_nid, 
                       HIPQUAD(pcfg->pcfg_id),  /* IP */
                       pcfg->pcfg_misc);        /* port */
                rc = 0;
#else
                rc = ksocknal_add_peer (pcfg->pcfg_nid,
                                        pcfg->pcfg_id, /* IP */
                                        pcfg->pcfg_misc); /* port */
#endif
                break;
        }
        case NAL_CMD_DEL_PEER: {
                if (pcfg->pcfg_flags) {         /* single_share */
                        CDEBUG(D_WARNING, "DEL_PEER: ignoring "
                               LPX64"@%u.%u.%u.%u\n",
                               pcfg->pcfg_nid, 
                               HIPQUAD(pcfg->pcfg_id)); /* IP */
                        rc = 0;
                        break;
                }
                rc = ksocknal_del_peer (pcfg->pcfg_nid,
                                        pcfg->pcfg_id, /* IP */
                                        pcfg->pcfg_flags); /* single_share? */
                break;
        }
        case NAL_CMD_GET_CONN: {
                ksock_conn_t *conn = ksocknal_get_conn_by_idx (pcfg->pcfg_count);

                if (conn == NULL)
                        rc = -ENOENT;
                else {
                        int   txmem;
                        int   rxmem;
                        int   nagle;

                        ksocknal_lib_get_conn_tunables(conn, &txmem, &rxmem, &nagle);

                        rc = 0;
                        pcfg->pcfg_nid    = conn->ksnc_peer->ksnp_nid;
                        pcfg->pcfg_id     = conn->ksnc_ipaddr;
                        pcfg->pcfg_misc   = conn->ksnc_port;
                        pcfg->pcfg_fd     = conn->ksnc_myipaddr;
                        pcfg->pcfg_flags  = conn->ksnc_type;
                        pcfg->pcfg_gw_nal = conn->ksnc_scheduler -
                                            ksocknal_data.ksnd_schedulers;
                        pcfg->pcfg_count  = txmem;
                        pcfg->pcfg_size   = rxmem;
                        pcfg->pcfg_wait   = nagle;
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
                        rc = ksocknal_create_conn(NULL, sock, type);
                        break;
                default:
                        rc = -EINVAL;
                        break;
                }
                cfs_put_file (KSN_SOCK2FILE(sock));
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
        default:
                rc = -EINVAL;
                break;
        }

        return rc;
}

void
ksocknal_free_fmbs (ksock_fmb_pool_t *p)
{
        int          npages = p->fmp_buff_pages;
        ksock_fmb_t *fmb;
        int          i;

        LASSERT (list_empty(&p->fmp_blocked_conns));
        LASSERT (p->fmp_nactive_fmbs == 0);

        while (!list_empty(&p->fmp_idle_fmbs)) {

                fmb = list_entry(p->fmp_idle_fmbs.next,
                                 ksock_fmb_t, fmb_list);

                for (i = 0; i < npages; i++)
                        if (fmb->fmb_kiov[i].kiov_page != NULL)
                                cfs_free_page(fmb->fmb_kiov[i].kiov_page);

                list_del(&fmb->fmb_list);
                PORTAL_FREE(fmb, offsetof(ksock_fmb_t, fmb_kiov[npages]));
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
                             sizeof (ksock_sched_t) * ksocknal_data.ksnd_nschedulers);

        PORTAL_FREE (ksocknal_data.ksnd_peers,
                     sizeof (struct list_head) *
                     ksocknal_data.ksnd_peer_hash_size);
}

void
ksocknal_shutdown (ptl_ni_t *ni)
{
        ksock_sched_t *sched;
        int            i;

        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        LASSERT(ni->ni_nal == &ksocknal_nal);

        switch (ksocknal_data.ksnd_init) {
        default:
                LASSERT (0);

        case SOCKNAL_INIT_ALL:
                libcfs_nal_cmd_unregister(SOCKNAL);
                /* fall through */

        case SOCKNAL_INIT_DATA:
                /* No more calls to ksocknal_cmd() to create new
                 * peers/connections since we're being unloaded. */

                /* Delete all peers */
                ksocknal_del_peer(PTL_NID_ANY, 0, 0);

                /* Wait for all peer state to clean up */
                i = 2;
                while (atomic_read (&ksocknal_data.ksnd_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "waiting for %d peers to disconnect\n",
                               atomic_read (&ksocknal_data.ksnd_npeers));
                        set_current_state (TASK_UNINTERRUPTIBLE);
                        schedule_timeout (cfs_time_seconds(1));
                }

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
                        for (i = 0; i < ksocknal_data.ksnd_nschedulers; i++) {
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
                cfs_waitq_broadcast (&ksocknal_data.ksnd_autoconnectd_waitq);
                cfs_waitq_broadcast (&ksocknal_data.ksnd_reaper_waitq);

                if (ksocknal_data.ksnd_schedulers != NULL)
                        for (i = 0; i < ksocknal_data.ksnd_nschedulers; i++) {
                                sched = &ksocknal_data.ksnd_schedulers[i];
                                cfs_waitq_broadcast(&sched->kss_waitq);
                        }

                i = 4;
                read_lock(&ksocknal_data.ksnd_global_lock);
                while (ksocknal_data.ksnd_nthreads != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "waiting for %d threads to terminate\n",
                                ksocknal_data.ksnd_nthreads);
                        read_unlock(&ksocknal_data.ksnd_global_lock);
                        set_current_state (TASK_UNINTERRUPTIBLE);
                        schedule_timeout (cfs_time_seconds(1));
                        read_lock(&ksocknal_data.ksnd_global_lock);
                }
                read_unlock(&ksocknal_data.ksnd_global_lock);

                kpr_deregister (&ksocknal_data.ksnd_router);

                ksocknal_free_buffers();

                ksocknal_data.ksnd_init = SOCKNAL_INIT_NOTHING;
                /* fall through */

        case SOCKNAL_INIT_NOTHING:
                break;
        }

        CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        printk(KERN_INFO "Lustre: Routing socket NAL unloaded (final mem %d)\n",
               atomic_read(&portal_kmemory));

        PORTAL_MODULE_UNUSE;
}


void
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

ptl_err_t
ksocknal_startup (ptl_ni_t *ni, char **interfaces)
{
        int               pkmem = atomic_read(&portal_kmemory);
        int               rc;
        int               i;
        int               j;

        LASSERT (ni->ni_nal == &ksocknal_nal);

        if (ksocknal_data.ksnd_init != SOCKNAL_INIT_NOTHING) {
                CERROR ("Only 1 instance supported\n");
                return PTL_FAIL;
        }

        memset (&ksocknal_data, 0, sizeof (ksocknal_data)); /* zero pointers */

        ksocknal_data.ksnd_ni = ni;             /* temp hack */
        ni->ni_data = &ksocknal_data;

        ksocknal_init_incarnation();

        ksocknal_data.ksnd_peer_hash_size = SOCKNAL_PEER_HASH_SIZE;
        PORTAL_ALLOC (ksocknal_data.ksnd_peers,
                      sizeof (struct list_head) * ksocknal_data.ksnd_peer_hash_size);
        if (ksocknal_data.ksnd_peers == NULL)
                return (-ENOMEM);

        for (i = 0; i < ksocknal_data.ksnd_peer_hash_size; i++)
                CFS_INIT_LIST_HEAD(&ksocknal_data.ksnd_peers[i]);

        rwlock_init(&ksocknal_data.ksnd_global_lock);

        spin_lock_init(&ksocknal_data.ksnd_small_fmp.fmp_lock);
        CFS_INIT_LIST_HEAD(&ksocknal_data.ksnd_small_fmp.fmp_idle_fmbs);
        CFS_INIT_LIST_HEAD(&ksocknal_data.ksnd_small_fmp.fmp_blocked_conns);
        ksocknal_data.ksnd_small_fmp.fmp_buff_pages = SOCKNAL_SMALL_FWD_PAGES;

        spin_lock_init(&ksocknal_data.ksnd_large_fmp.fmp_lock);
        CFS_INIT_LIST_HEAD(&ksocknal_data.ksnd_large_fmp.fmp_idle_fmbs);
        CFS_INIT_LIST_HEAD(&ksocknal_data.ksnd_large_fmp.fmp_blocked_conns);
        ksocknal_data.ksnd_large_fmp.fmp_buff_pages = SOCKNAL_LARGE_FWD_PAGES;

        spin_lock_init (&ksocknal_data.ksnd_reaper_lock);
        CFS_INIT_LIST_HEAD (&ksocknal_data.ksnd_enomem_conns);
        CFS_INIT_LIST_HEAD (&ksocknal_data.ksnd_zombie_conns);
        CFS_INIT_LIST_HEAD (&ksocknal_data.ksnd_deathrow_conns);
        cfs_waitq_init(&ksocknal_data.ksnd_reaper_waitq);

        spin_lock_init (&ksocknal_data.ksnd_autoconnectd_lock);
        CFS_INIT_LIST_HEAD (&ksocknal_data.ksnd_autoconnectd_routes);
        cfs_waitq_init(&ksocknal_data.ksnd_autoconnectd_waitq);

        /* NB memset above zeros whole of ksocknal_data, including
         * ksocknal_data.ksnd_irqinfo[all].ksni_valid */

        /* flag lists/ptrs/locks initialised */
        ksocknal_data.ksnd_init = SOCKNAL_INIT_DATA;
        PORTAL_MODULE_USE;

        ksocknal_data.ksnd_nschedulers = ksocknal_nsched();
        PORTAL_ALLOC(ksocknal_data.ksnd_schedulers,
                     sizeof(ksock_sched_t) * ksocknal_data.ksnd_nschedulers);
        if (ksocknal_data.ksnd_schedulers == NULL) {
                ksocknal_shutdown (ni);
                return (-ENOMEM);
        }

        for (i = 0; i < ksocknal_data.ksnd_nschedulers; i++) {
                ksock_sched_t *kss = &ksocknal_data.ksnd_schedulers[i];

                spin_lock_init (&kss->kss_lock);
                CFS_INIT_LIST_HEAD (&kss->kss_rx_conns);
                CFS_INIT_LIST_HEAD (&kss->kss_tx_conns);
#if SOCKNAL_ZC
                CFS_INIT_LIST_HEAD (&kss->kss_zctxdone_list);
#endif
                cfs_waitq_init (&kss->kss_waitq);
        }

        for (i = 0; i < ksocknal_data.ksnd_nschedulers; i++) {
                rc = ksocknal_thread_start (ksocknal_scheduler,
                                            &ksocknal_data.ksnd_schedulers[i]);
                if (rc != 0) {
                        CERROR("Can't spawn socknal scheduler[%d]: %d\n",
                               i, rc);
                        ksocknal_shutdown (ni);
                        return (rc);
                }
        }

        for (i = 0; i < SOCKNAL_N_AUTOCONNECTD; i++) {
                rc = ksocknal_thread_start (ksocknal_autoconnectd, (void *)((long)i));
                if (rc != 0) {
                        CERROR("Can't spawn socknal autoconnectd: %d\n", rc);
                        ksocknal_shutdown (ni);
                        return (rc);
                }
        }

        rc = ksocknal_thread_start (ksocknal_reaper, NULL);
        if (rc != 0) {
                CERROR ("Can't spawn socknal reaper: %d\n", rc);
                ksocknal_shutdown (ni);
                return (rc);
        }

        rc = kpr_register(&ksocknal_data.ksnd_router,
                          &ksocknal_router_interface);
        if (rc != 0) {
                CDEBUG(D_NET, "Can't initialise routing interface "
                       "(rc = %d): not routing\n", rc);
        } else {
                /* Only allocate forwarding buffers if there's a router */

                for (i = 0; i < (SOCKNAL_SMALL_FWD_NMSGS +
                                 SOCKNAL_LARGE_FWD_NMSGS); i++) {
                        ksock_fmb_t      *fmb;
                        ksock_fmb_pool_t *pool;


                        if (i < SOCKNAL_SMALL_FWD_NMSGS)
                                pool = &ksocknal_data.ksnd_small_fmp;
                        else
                                pool = &ksocknal_data.ksnd_large_fmp;

                        PORTAL_ALLOC(fmb, offsetof(ksock_fmb_t,
                                                   fmb_kiov[pool->fmp_buff_pages]));
                        if (fmb == NULL) {
                                ksocknal_shutdown(ni);
                                return (-ENOMEM);
                        }

                        fmb->fmb_pool = pool;

                        for (j = 0; j < pool->fmp_buff_pages; j++) {
                                fmb->fmb_kiov[j].kiov_page = cfs_alloc_page(CFS_ALLOC_STD);

                                if (fmb->fmb_kiov[j].kiov_page == NULL) {
                                        ksocknal_shutdown (ni);
                                        return (-ENOMEM);
                                }

                                LASSERT(cfs_page_address(fmb->fmb_kiov[j].kiov_page) != NULL);
                        }

                        list_add(&fmb->fmb_list, &pool->fmp_idle_fmbs);
                }
        }

        rc = libcfs_nal_cmd_register(SOCKNAL, &ksocknal_cmd, NULL);
        if (rc != 0) {
                CERROR ("Can't initialise command interface (rc = %d)\n", rc);
                ksocknal_shutdown (ni);
                return (rc);
        }

        /* flag everything initialised */
        ksocknal_data.ksnd_init = SOCKNAL_INIT_ALL;

        printk(KERN_INFO "Lustre: Routing socket NAL loaded "
               "(Routing %s, initial mem %d, incarnation "LPX64")\n",
               kpr_routing (&ksocknal_data.ksnd_router) ?
               "enabled" : "disabled", pkmem, ksocknal_data.ksnd_incarnation);
        
        return (0);
}

void __exit
ksocknal_module_fini (void)
{
        ptl_unregister_nal(&ksocknal_nal);
        ksocknal_lib_tunables_fini();
}

int __init
ksocknal_module_init (void)
{
        int    rc;

        /* packet descriptor must fit in a router descriptor's scratchpad */
        CLASSERT(sizeof (ksock_tx_t) <= sizeof (kprfd_scratch_t));
        /* check ksnr_connected/connecting field large enough */
        CLASSERT(SOCKNAL_CONN_NTYPES <= 4);

        rc = ksocknal_lib_tunables_init();
        if (rc != 0)
                return rc;

        ptl_register_nal(&ksocknal_nal);
        return 0;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel TCP Socket NAL v1.0.0");
MODULE_LICENSE("GPL");

cfs_module(ksocknal, "1.0.0", ksocknal_module_init, ksocknal_module_fini);
