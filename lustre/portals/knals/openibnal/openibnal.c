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

nal_t                   koibnal_api;
ptl_handle_ni_t         koibnal_ni;
koib_data_t             koibnal_data;
koib_tunables_t         koibnal_tunables;

#ifdef CONFIG_SYSCTL
#define OPENIBNAL_SYSCTL        202

#define OPENIBNAL_SYSCTL_TIMEOUT     1
#define OPENIBNAL_SYSCTL_ZERO_COPY   2

static ctl_table koibnal_ctl_table[] = {
        {OPENIBNAL_SYSCTL_TIMEOUT, "timeout", 
         &koibnal_tunables.koib_io_timeout, sizeof (int),
         0644, NULL, &proc_dointvec},
        { 0 }
};

static ctl_table koibnal_top_ctl_table[] = {
        {OPENIBNAL_SYSCTL, "openibnal", NULL, 0, 0555, koibnal_ctl_table},
        { 0 }
};
#endif

void
print_service(struct ib_common_attrib_service *service, char *tag, int rc)
{
        char name[32];

        if (service == NULL) 
        {
                CWARN("tag       : %s\n"
                      "status    : %d (NULL)\n", tag, rc);
                return;
        }
        strncpy (name, service->service_name, sizeof(name)-1);
        name[sizeof(name)-1] = 0;
        
        CWARN("tag       : %s\n"
              "status    : %d\n"
              "service id: "LPX64"\n"
              "name      : %s\n"
              "NID       : "LPX64"\n", tag, rc,
              service->service_id, name, service->service_data64[0]);
}

void
koibnal_service_setunset_done (tTS_IB_CLIENT_QUERY_TID tid, int status,
                               struct ib_common_attrib_service *service, void *arg)
{
        *(int *)arg = status;
        up (&koibnal_data.koib_nid_signal);
}

int
koibnal_advertise (void)
{
        __u64   tid;
        int     rc;
        int     rc2;

        LASSERT (koibnal_data.koib_nid != PTL_NID_ANY);

        memset (&koibnal_data.koib_service, 0, 
                sizeof (koibnal_data.koib_service));
        
        koibnal_data.koib_service.service_id
                = koibnal_data.koib_cm_service_id;

        rc = ib_cached_gid_get(koibnal_data.koib_device,
                               koibnal_data.koib_port,
                               0,
                               koibnal_data.koib_service.service_gid);
        if (rc != 0) {
                CERROR ("Can't get port %d GID: %d\n",
                        koibnal_data.koib_port, rc);
                return (rc);
        }
        
        rc = ib_cached_pkey_get(koibnal_data.koib_device,
                                koibnal_data.koib_port,
                                0,
                                &koibnal_data.koib_service.service_pkey);
        if (rc != 0) {
                CERROR ("Can't get port %d PKEY: %d\n",
                        koibnal_data.koib_port, rc);
                return (rc);
        }
        
        koibnal_data.koib_service.service_lease = 0xffffffff;

        koibnal_set_service_keys(&koibnal_data.koib_service, koibnal_data.koib_nid);

        CDEBUG(D_NET, "Advertising service id "LPX64" %s:"LPX64"\n", 
               koibnal_data.koib_service.service_id,
               koibnal_data.koib_service.service_name, 
               *koibnal_service_nid_field(&koibnal_data.koib_service));

        rc = ib_service_set (koibnal_data.koib_device,
                             koibnal_data.koib_port,
                             &koibnal_data.koib_service,
                             IB_SA_SERVICE_COMP_MASK_ID |
                             IB_SA_SERVICE_COMP_MASK_GID |
                             IB_SA_SERVICE_COMP_MASK_PKEY |
                             IB_SA_SERVICE_COMP_MASK_LEASE |
                             KOIBNAL_SERVICE_KEY_MASK,
                             koibnal_tunables.koib_io_timeout * HZ,
                             koibnal_service_setunset_done, &rc2, &tid);

        if (rc == 0) {
                down (&koibnal_data.koib_nid_signal);
                rc = rc2;
        }
        
        if (rc != 0)
                CERROR ("Error %d advertising SM service\n", rc);

        return (rc);
}

int
koibnal_unadvertise (int expect_success)
{
        __u64   tid;
        int     rc;
        int     rc2;

        LASSERT (koibnal_data.koib_nid != PTL_NID_ANY);

        memset (&koibnal_data.koib_service, 0,
                sizeof (koibnal_data.koib_service));

        koibnal_set_service_keys(&koibnal_data.koib_service, koibnal_data.koib_nid);

        CDEBUG(D_NET, "Unadvertising service %s:"LPX64"\n",
               koibnal_data.koib_service.service_name,
               *koibnal_service_nid_field(&koibnal_data.koib_service));

        rc = ib_service_delete (koibnal_data.koib_device,
                                koibnal_data.koib_port,
                                &koibnal_data.koib_service,
                                KOIBNAL_SERVICE_KEY_MASK,
                                koibnal_tunables.koib_io_timeout * HZ,
                                koibnal_service_setunset_done, &rc2, &tid);
        if (rc != 0) {
                CERROR ("Immediate error %d unadvertising NID "LPX64"\n",
                        rc, koibnal_data.koib_nid);
                return (rc);
        }

        down (&koibnal_data.koib_nid_signal);
        
        if ((rc2 == 0) == !!expect_success)
                return (0);

        if (expect_success)
                CERROR("Error %d unadvertising NID "LPX64"\n",
                        rc, koibnal_data.koib_nid);
        else
                CWARN("Removed conflicting NID "LPX64"\n",
                      koibnal_data.koib_nid);

        return (rc);
}

int
koibnal_check_advert (void)
{
        __u64   tid;
        int     rc;
        int     rc2;

        static struct ib_common_attrib_service srv;

        memset (&srv, 0, sizeof (srv));

        koibnal_set_service_keys(&srv, koibnal_data.koib_nid);

        rc = ib_service_get (koibnal_data.koib_device, 
                             koibnal_data.koib_port,
                             &srv,
                             KOIBNAL_SERVICE_KEY_MASK,
                             koibnal_tunables.koib_io_timeout * HZ,
                             koibnal_service_setunset_done, &rc2, 
                             &tid);

        if (rc != 0) {
                CERROR ("Immediate error %d checking SM service\n", rc);
        } else {
                down (&koibnal_data.koib_nid_signal);
                rc = rc2;

                if (rc != 0)
                        CERROR ("Error %d checking SM service\n", rc);
        }

        return (rc);
}

int
koibnal_set_mynid(ptl_nid_t nid)
{
        struct timeval tv;
        lib_ni_t      *ni = &koibnal_lib.libnal_ni;
        int            rc;

        CDEBUG(D_IOCTL, "setting mynid to "LPX64" (old nid="LPX64")\n",
               nid, ni->ni_pid.nid);

        do_gettimeofday(&tv);

        down (&koibnal_data.koib_nid_mutex);

        if (nid == koibnal_data.koib_nid) {
                /* no change of NID */
                up (&koibnal_data.koib_nid_mutex);
                return (0);
        }

        CDEBUG(D_NET, "NID "LPX64"("LPX64")\n",
               koibnal_data.koib_nid, nid);
        
        if (koibnal_data.koib_nid != PTL_NID_ANY) {

                koibnal_unadvertise (1);

                rc = ib_cm_listen_stop (koibnal_data.koib_listen_handle);
                if (rc != 0)
                        CERROR ("Error %d stopping listener\n", rc);
        }
        
        koibnal_data.koib_nid = ni->ni_pid.nid = nid;
        koibnal_data.koib_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;
        
        /* Delete all existing peers and their connections after new
         * NID/incarnation set to ensure no old connections in our brave
         * new world. */
        koibnal_del_peer (PTL_NID_ANY, 0);

        rc = 0;
        if (koibnal_data.koib_nid != PTL_NID_ANY) {
                /* New NID installed */

                /* remove any previous advert (crashed node etc) */
                koibnal_unadvertise(0);

                /* Assign new service number */
                koibnal_data.koib_cm_service_id = ib_cm_service_assign();
                CDEBUG(D_NET, "service_id "LPX64"\n", koibnal_data.koib_cm_service_id);
        
                rc = ib_cm_listen(koibnal_data.koib_cm_service_id,
                                  TS_IB_CM_SERVICE_EXACT_MASK,
                                  koibnal_passive_conn_callback, NULL,
                                  &koibnal_data.koib_listen_handle);
                if (rc != 0) {
                        CERROR ("ib_cm_listen error: %d\n", rc);
                        goto out;
                }

                rc = koibnal_advertise();

                koibnal_check_advert();
        }
        
 out:
        if (rc != 0) {
                koibnal_data.koib_nid = PTL_NID_ANY;
                /* remove any peers that sprung up while I failed to
                 * advertise myself */
                koibnal_del_peer (PTL_NID_ANY, 0);
        }

        up (&koibnal_data.koib_nid_mutex);
        return (0);
}

koib_peer_t *
koibnal_create_peer (ptl_nid_t nid)
{
        koib_peer_t *peer;

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
        peer->ibp_reconnect_interval = OPENIBNAL_MIN_RECONNECT_INTERVAL;

        atomic_inc (&koibnal_data.koib_npeers);
        return (peer);
}

void
koibnal_destroy_peer (koib_peer_t *peer)
{
        CDEBUG (D_NET, "peer "LPX64" %p deleted\n", peer->ibp_nid, peer);

        LASSERT (atomic_read (&peer->ibp_refcount) == 0);
        LASSERT (peer->ibp_persistence == 0);
        LASSERT (!koibnal_peer_active(peer));
        LASSERT (peer->ibp_connecting == 0);
        LASSERT (list_empty (&peer->ibp_conns));
        LASSERT (list_empty (&peer->ibp_tx_queue));

        PORTAL_FREE (peer, sizeof (*peer));

        /* NB a peer's connections keep a reference on their peer until
         * they are destroyed, so we can be assured that _all_ state to do
         * with this peer has been cleaned up when its refcount drops to
         * zero. */
        atomic_dec (&koibnal_data.koib_npeers);
}

void
koibnal_put_peer (koib_peer_t *peer)
{
        CDEBUG (D_OTHER, "putting peer[%p] -> "LPX64" (%d)\n",
                peer, peer->ibp_nid,
                atomic_read (&peer->ibp_refcount));

        LASSERT (atomic_read (&peer->ibp_refcount) > 0);
        if (!atomic_dec_and_test (&peer->ibp_refcount))
                return;

        koibnal_destroy_peer (peer);
}

koib_peer_t *
koibnal_find_peer_locked (ptl_nid_t nid)
{
        struct list_head *peer_list = koibnal_nid2peerlist (nid);
        struct list_head *tmp;
        koib_peer_t      *peer;

        list_for_each (tmp, peer_list) {

                peer = list_entry (tmp, koib_peer_t, ibp_list);

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

koib_peer_t *
koibnal_get_peer (ptl_nid_t nid)
{
        koib_peer_t     *peer;

        read_lock (&koibnal_data.koib_global_lock);
        peer = koibnal_find_peer_locked (nid);
        if (peer != NULL)                       /* +1 ref for caller? */
                atomic_inc (&peer->ibp_refcount);
        read_unlock (&koibnal_data.koib_global_lock);

        return (peer);
}

void
koibnal_unlink_peer_locked (koib_peer_t *peer)
{
        LASSERT (peer->ibp_persistence == 0);
        LASSERT (list_empty(&peer->ibp_conns));

        LASSERT (koibnal_peer_active(peer));
        list_del_init (&peer->ibp_list);
        /* lose peerlist's ref */
        koibnal_put_peer (peer);
}

int
koibnal_get_peer_info (int index, ptl_nid_t *nidp, int *persistencep)
{
        koib_peer_t       *peer;
        struct list_head  *ptmp;
        int                i;

        read_lock (&koibnal_data.koib_global_lock);

        for (i = 0; i < koibnal_data.koib_peer_hash_size; i++) {

                list_for_each (ptmp, &koibnal_data.koib_peers[i]) {
                        
                        peer = list_entry (ptmp, koib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (index-- > 0)
                                continue;

                        *nidp = peer->ibp_nid;
                        *persistencep = peer->ibp_persistence;
                        
                        read_unlock (&koibnal_data.koib_global_lock);
                        return (0);
                }
        }

        read_unlock (&koibnal_data.koib_global_lock);
        return (-ENOENT);
}

int
koibnal_add_persistent_peer (ptl_nid_t nid)
{
        unsigned long      flags;
        koib_peer_t       *peer;
        koib_peer_t       *peer2;
        
        if (nid == PTL_NID_ANY)
                return (-EINVAL);

        peer = koibnal_create_peer (nid);
        if (peer == NULL)
                return (-ENOMEM);

        write_lock_irqsave (&koibnal_data.koib_global_lock, flags);

        peer2 = koibnal_find_peer_locked (nid);
        if (peer2 != NULL) {
                koibnal_put_peer (peer);
                peer = peer2;
        } else {
                /* peer table takes existing ref on peer */
                list_add_tail (&peer->ibp_list,
                               koibnal_nid2peerlist (nid));
        }

        peer->ibp_persistence++;
        
        write_unlock_irqrestore (&koibnal_data.koib_global_lock, flags);
        return (0);
}

void
koibnal_del_peer_locked (koib_peer_t *peer, int single_share)
{
        struct list_head *ctmp;
        struct list_head *cnxt;
        koib_conn_t      *conn;

        if (!single_share)
                peer->ibp_persistence = 0;
        else if (peer->ibp_persistence > 0)
                peer->ibp_persistence--;

        if (peer->ibp_persistence != 0)
                return;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry(ctmp, koib_conn_t, ibc_list);

                koibnal_close_conn_locked (conn, 0);
        }

        /* NB peer unlinks itself when last conn is closed */
}

int
koibnal_del_peer (ptl_nid_t nid, int single_share)
{
        unsigned long      flags;
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        koib_peer_t      *peer;
        int                lo;
        int                hi;
        int                i;
        int                rc = -ENOENT;

        write_lock_irqsave (&koibnal_data.koib_global_lock, flags);

        if (nid != PTL_NID_ANY)
                lo = hi = koibnal_nid2peerlist(nid) - koibnal_data.koib_peers;
        else {
                lo = 0;
                hi = koibnal_data.koib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &koibnal_data.koib_peers[i]) {
                        peer = list_entry (ptmp, koib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (!(nid == PTL_NID_ANY || peer->ibp_nid == nid))
                                continue;

                        koibnal_del_peer_locked (peer, single_share);
                        rc = 0;         /* matched something */

                        if (single_share)
                                goto out;
                }
        }
 out:
        write_unlock_irqrestore (&koibnal_data.koib_global_lock, flags);

        return (rc);
}

koib_conn_t *
koibnal_get_conn_by_idx (int index)
{
        koib_peer_t       *peer;
        struct list_head  *ptmp;
        koib_conn_t       *conn;
        struct list_head  *ctmp;
        int                i;

        read_lock (&koibnal_data.koib_global_lock);

        for (i = 0; i < koibnal_data.koib_peer_hash_size; i++) {
                list_for_each (ptmp, &koibnal_data.koib_peers[i]) {

                        peer = list_entry (ptmp, koib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence > 0 ||
                                 peer->ibp_connecting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        list_for_each (ctmp, &peer->ibp_conns) {
                                if (index-- > 0)
                                        continue;

                                conn = list_entry (ctmp, koib_conn_t, ibc_list);
                                CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                                       atomic_read (&conn->ibc_refcount));
                                atomic_inc (&conn->ibc_refcount);
                                read_unlock (&koibnal_data.koib_global_lock);
                                return (conn);
                        }
                }
        }

        read_unlock (&koibnal_data.koib_global_lock);
        return (NULL);
}

koib_conn_t *
koibnal_create_conn (void)
{
        koib_conn_t *conn;
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
        INIT_LIST_HEAD (&conn->ibc_rdma_queue);
        spin_lock_init (&conn->ibc_lock);
        
        atomic_inc (&koibnal_data.koib_nconns);
        /* well not really, but I call destroy() on failure, which decrements */

        PORTAL_ALLOC (conn->ibc_rxs, OPENIBNAL_RX_MSGS * sizeof (koib_rx_t));
        if (conn->ibc_rxs == NULL)
                goto failed;
        memset (conn->ibc_rxs, 0, OPENIBNAL_RX_MSGS * sizeof(koib_rx_t));

        rc = koibnal_alloc_pages(&conn->ibc_rx_pages,
                                 OPENIBNAL_RX_MSG_PAGES,
                                 IB_ACCESS_LOCAL_WRITE);
        if (rc != 0)
                goto failed;

        vaddr_base = vaddr = conn->ibc_rx_pages->oibp_vaddr;

        for (i = ipage = page_offset = 0; i < OPENIBNAL_RX_MSGS; i++) {
                struct page *page = conn->ibc_rx_pages->oibp_pages[ipage];
                koib_rx_t   *rx = &conn->ibc_rxs[i];

                rx->rx_conn = conn;
                rx->rx_vaddr = vaddr;
                rx->rx_msg = (koib_msg_t *)(((char *)page_address(page)) + page_offset);
                
                vaddr += OPENIBNAL_MSG_SIZE;
                LASSERT (vaddr <= vaddr_base + OPENIBNAL_RX_MSG_BYTES);
                
                page_offset += OPENIBNAL_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= OPENIBNAL_RX_MSG_PAGES);
                }
        }

        params.qp_create = (struct ib_qp_create_param) {
                .limit = {
                        /* Sends have an optional RDMA */
                        .max_outstanding_send_request    = 2 * OPENIBNAL_MSG_QUEUE_SIZE,
                        .max_outstanding_receive_request = OPENIBNAL_MSG_QUEUE_SIZE,
                        .max_send_gather_element         = 1,
                        .max_receive_scatter_element     = 1,
                },
                .pd              = koibnal_data.koib_pd,
                .send_queue      = koibnal_data.koib_tx_cq,
                .receive_queue   = koibnal_data.koib_rx_cq,
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
        conn->ibc_state = OPENIBNAL_CONN_INIT_QP;

        params.qp_attr = (struct ib_qp_attribute) {
                .state             = IB_QP_STATE_INIT,
                .port              = koibnal_data.koib_port,
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
        koibnal_destroy_conn (conn);
        return (NULL);
}

void
koibnal_destroy_conn (koib_conn_t *conn)
{
        int    rc;
        
        CDEBUG (D_NET, "connection %p\n", conn);

        LASSERT (atomic_read (&conn->ibc_refcount) == 0);
        LASSERT (list_empty(&conn->ibc_tx_queue));
        LASSERT (list_empty(&conn->ibc_rdma_queue));
        LASSERT (conn->ibc_nsends_posted == 0);
        LASSERT (conn->ibc_connreq == NULL);

        switch (conn->ibc_state) {
        case OPENIBNAL_CONN_ZOMBIE:
                /* called after connection sequence initiated */

        case OPENIBNAL_CONN_INIT_QP:
                rc = ib_qp_destroy(conn->ibc_qp);
                if (rc != 0)
                        CERROR("Can't destroy QP: %d\n", rc);
                /* fall through */
                
        case OPENIBNAL_CONN_INIT_NOTHING:
                break;

        default:
                LASSERT (0);
        }

        if (conn->ibc_rx_pages != NULL) 
                koibnal_free_pages(conn->ibc_rx_pages);
        
        if (conn->ibc_rxs != NULL)
                PORTAL_FREE(conn->ibc_rxs, 
                            OPENIBNAL_RX_MSGS * sizeof(koib_rx_t));

        if (conn->ibc_peer != NULL)
                koibnal_put_peer(conn->ibc_peer);

        PORTAL_FREE(conn, sizeof (*conn));

        atomic_dec(&koibnal_data.koib_nconns);
        
        if (atomic_read (&koibnal_data.koib_nconns) == 0 &&
            koibnal_data.koib_shutdown) {
                /* I just nuked the last connection on shutdown; wake up
                 * everyone so they can exit. */
                wake_up_all(&koibnal_data.koib_sched_waitq);
                wake_up_all(&koibnal_data.koib_connd_waitq);
        }
}

void
koibnal_put_conn (koib_conn_t *conn)
{
        unsigned long flags;

        CDEBUG (D_NET, "putting conn[%p] state %d -> "LPX64" (%d)\n",
                conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                atomic_read (&conn->ibc_refcount));

        LASSERT (atomic_read (&conn->ibc_refcount) > 0);
        if (!atomic_dec_and_test (&conn->ibc_refcount))
                return;

        /* last ref only goes on zombies */
        LASSERT (conn->ibc_state == OPENIBNAL_CONN_ZOMBIE);

        spin_lock_irqsave (&koibnal_data.koib_connd_lock, flags);

        list_add (&conn->ibc_list, &koibnal_data.koib_connd_conns);
        wake_up (&koibnal_data.koib_connd_waitq);

        spin_unlock_irqrestore (&koibnal_data.koib_connd_lock, flags);
}

int
koibnal_close_peer_conns_locked (koib_peer_t *peer, int why)
{
        koib_conn_t        *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry (ctmp, koib_conn_t, ibc_list);

                count++;
                koibnal_close_conn_locked (conn, why);
        }

        return (count);
}

int
koibnal_close_stale_conns_locked (koib_peer_t *peer, __u64 incarnation)
{
        koib_conn_t        *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry (ctmp, koib_conn_t, ibc_list);

                if (conn->ibc_incarnation == incarnation)
                        continue;

                CDEBUG(D_NET, "Closing stale conn nid:"LPX64" incarnation:"LPX64"("LPX64")\n",
                       peer->ibp_nid, conn->ibc_incarnation, incarnation);
                
                count++;
                koibnal_close_conn_locked (conn, -ESTALE);
        }

        return (count);
}

int
koibnal_close_matching_conns (ptl_nid_t nid)
{
        unsigned long       flags;
        koib_peer_t        *peer;
        struct list_head   *ptmp;
        struct list_head   *pnxt;
        int                 lo;
        int                 hi;
        int                 i;
        int                 count = 0;

        write_lock_irqsave (&koibnal_data.koib_global_lock, flags);

        if (nid != PTL_NID_ANY)
                lo = hi = koibnal_nid2peerlist(nid) - koibnal_data.koib_peers;
        else {
                lo = 0;
                hi = koibnal_data.koib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &koibnal_data.koib_peers[i]) {

                        peer = list_entry (ptmp, koib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (!(nid == PTL_NID_ANY || nid == peer->ibp_nid))
                                continue;

                        count += koibnal_close_peer_conns_locked (peer, 0);
                }
        }

        write_unlock_irqrestore (&koibnal_data.koib_global_lock, flags);

        /* wildcards always succeed */
        if (nid == PTL_NID_ANY)
                return (0);
        
        return (count == 0 ? -ENOENT : 0);
}

int
koibnal_cmd(struct portals_cfg *pcfg, void * private)
{
        int rc = -EINVAL;

        LASSERT (pcfg != NULL);

        switch(pcfg->pcfg_command) {
        case NAL_CMD_GET_PEER: {
                ptl_nid_t   nid = 0;
                int         share_count = 0;

                rc = koibnal_get_peer_info(pcfg->pcfg_count,
                                           &nid, &share_count);
                pcfg->pcfg_nid   = nid;
                pcfg->pcfg_size  = 0;
                pcfg->pcfg_id    = 0;
                pcfg->pcfg_misc  = 0;
                pcfg->pcfg_count = 0;
                pcfg->pcfg_wait  = share_count;
                break;
        }
        case NAL_CMD_ADD_PEER: {
                rc = koibnal_add_persistent_peer (pcfg->pcfg_nid);
                break;
        }
        case NAL_CMD_DEL_PEER: {
                rc = koibnal_del_peer (pcfg->pcfg_nid, 
                                       /* flags == single_share */
                                       pcfg->pcfg_flags != 0);
                break;
        }
        case NAL_CMD_GET_CONN: {
                koib_conn_t *conn = koibnal_get_conn_by_idx (pcfg->pcfg_count);

                if (conn == NULL)
                        rc = -ENOENT;
                else {
                        rc = 0;
                        pcfg->pcfg_nid   = conn->ibc_peer->ibp_nid;
                        pcfg->pcfg_id    = 0;
                        pcfg->pcfg_misc  = 0;
                        pcfg->pcfg_flags = 0;
                        koibnal_put_conn (conn);
                }
                break;
        }
        case NAL_CMD_CLOSE_CONNECTION: {
                rc = koibnal_close_matching_conns (pcfg->pcfg_nid);
                break;
        }
        case NAL_CMD_REGISTER_MYNID: {
                if (pcfg->pcfg_nid == PTL_NID_ANY)
                        rc = -EINVAL;
                else
                        rc = koibnal_set_mynid (pcfg->pcfg_nid);
                break;
        }
        }

        return rc;
}

void
koibnal_free_pages (koib_pages_t *p)
{
        int     npages = p->oibp_npages;
        int     rc;
        int     i;
        
        if (p->oibp_mapped) {
                rc = ib_memory_deregister(p->oibp_handle);
                if (rc != 0)
                        CERROR ("Deregister error: %d\n", rc);
        }
        
        for (i = 0; i < npages; i++)
                if (p->oibp_pages[i] != NULL)
                        __free_page(p->oibp_pages[i]);
        
        PORTAL_FREE (p, offsetof(koib_pages_t, oibp_pages[npages]));
}

int
koibnal_alloc_pages (koib_pages_t **pp, int npages, int access)
{
        koib_pages_t               *p;
        struct ib_physical_buffer  *phys_pages;
        int                         i;
        int                         rc;

        PORTAL_ALLOC(p, offsetof(koib_pages_t, oibp_pages[npages]));
        if (p == NULL) {
                CERROR ("Can't allocate buffer %d\n", npages);
                return (-ENOMEM);
        }

        memset (p, 0, offsetof(koib_pages_t, oibp_pages[npages]));
        p->oibp_npages = npages;
        
        for (i = 0; i < npages; i++) {
                p->oibp_pages[i] = alloc_page (GFP_KERNEL);
                if (p->oibp_pages[i] == NULL) {
                        CERROR ("Can't allocate page %d of %d\n", i, npages);
                        koibnal_free_pages(p);
                        return (-ENOMEM);
                }
        }

        PORTAL_ALLOC(phys_pages, npages * sizeof(*phys_pages));
        if (phys_pages == NULL) {
                CERROR ("Can't allocate physarray for %d pages\n", npages);
                koibnal_free_pages(p);
                return (-ENOMEM);
        }

        for (i = 0; i < npages; i++) {
                phys_pages[i].size = PAGE_SIZE;
                phys_pages[i].address =
                        koibnal_page2phys(p->oibp_pages[i]);
        }

        p->oibp_vaddr = 0;
        rc = ib_memory_register_physical(koibnal_data.koib_pd,
                                         phys_pages, npages,
                                         &p->oibp_vaddr,
                                         npages * PAGE_SIZE, 0,
                                         access,
                                         &p->oibp_handle,
                                         &p->oibp_lkey,
                                         &p->oibp_rkey);
        
        PORTAL_FREE(phys_pages, npages * sizeof(*phys_pages));
        
        if (rc != 0) {
                CERROR ("Error %d mapping %d pages\n", rc, npages);
                koibnal_free_pages(p);
                return (rc);
        }
        
        p->oibp_mapped = 1;
        *pp = p;
        return (0);
}

int
koibnal_setup_tx_descs (void)
{
        int           ipage = 0;
        int           page_offset = 0;
        __u64         vaddr;
        __u64         vaddr_base;
        struct page  *page;
        koib_tx_t    *tx;
        int           i;
        int           rc;

        /* pre-mapped messages are not bigger than 1 page */
        LASSERT (OPENIBNAL_MSG_SIZE <= PAGE_SIZE);

        /* No fancy arithmetic when we do the buffer calculations */
        LASSERT (PAGE_SIZE % OPENIBNAL_MSG_SIZE == 0);

        rc = koibnal_alloc_pages(&koibnal_data.koib_tx_pages,
                                 OPENIBNAL_TX_MSG_PAGES, 
                                 0);            /* local read access only */
        if (rc != 0)
                return (rc);

        vaddr = vaddr_base = koibnal_data.koib_tx_pages->oibp_vaddr;

        for (i = 0; i < OPENIBNAL_TX_MSGS; i++) {
                page = koibnal_data.koib_tx_pages->oibp_pages[ipage];
                tx = &koibnal_data.koib_tx_descs[i];

                memset (tx, 0, sizeof(*tx));    /* zero flags etc */
                
                tx->tx_msg = (koib_msg_t *)(((char *)page_address(page)) + page_offset);
                tx->tx_vaddr = vaddr;
                tx->tx_isnblk = (i >= OPENIBNAL_NTX);
                tx->tx_mapped = KOIB_TX_UNMAPPED;

                CDEBUG(D_NET, "Tx[%d] %p->%p - "LPX64"\n", 
                       i, tx, tx->tx_msg, tx->tx_vaddr);

                if (tx->tx_isnblk)
                        list_add (&tx->tx_list, 
                                  &koibnal_data.koib_idle_nblk_txs);
                else
                        list_add (&tx->tx_list, 
                                  &koibnal_data.koib_idle_txs);

                vaddr += OPENIBNAL_MSG_SIZE;
                LASSERT (vaddr <= vaddr_base + OPENIBNAL_TX_MSG_BYTES);

                page_offset += OPENIBNAL_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= OPENIBNAL_TX_MSG_PAGES);
                }
        }
        
        return (0);
}

void
koibnal_api_shutdown (nal_t *nal)
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

        LASSERT(nal == &koibnal_api);

        switch (koibnal_data.koib_init) {
        default:
                CERROR ("Unexpected state %d\n", koibnal_data.koib_init);
                LBUG();

        case OPENIBNAL_INIT_ALL:
                /* stop calls to nal_cmd */
                libcfs_nal_cmd_unregister(OPENIBNAL);
                /* No new peers */

                /* resetting my NID to unadvertises me, removes my
                 * listener and nukes all current peers */
                koibnal_set_mynid (PTL_NID_ANY);

                /* Wait for all peer state to clean up */
                i = 2;
                while (atomic_read (&koibnal_data.koib_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "waiting for %d peers to close down\n",
                               atomic_read (&koibnal_data.koib_npeers));
                        set_current_state (TASK_INTERRUPTIBLE);
                        schedule_timeout (HZ);
                }
                /* fall through */

        case OPENIBNAL_INIT_TX_CQ:
                rc = ib_cq_destroy (koibnal_data.koib_tx_cq);
                if (rc != 0)
                        CERROR ("Destroy tx CQ error: %d\n", rc);
                /* fall through */

        case OPENIBNAL_INIT_RX_CQ:
                rc = ib_cq_destroy (koibnal_data.koib_rx_cq);
                if (rc != 0)
                        CERROR ("Destroy rx CQ error: %d\n", rc);
                /* fall through */

        case OPENIBNAL_INIT_TXD:
                koibnal_free_pages (koibnal_data.koib_tx_pages);
                /* fall through */
#if OPENIBNAL_FMR
        case OPENIBNAL_INIT_FMR:
                rc = ib_fmr_pool_destroy (koibnal_data.koib_fmr_pool);
                if (rc != 0)
                        CERROR ("Destroy FMR pool error: %d\n", rc);
                /* fall through */
#endif
        case OPENIBNAL_INIT_PD:
                rc = ib_pd_destroy(koibnal_data.koib_pd);
                if (rc != 0)
                        CERROR ("Destroy PD error: %d\n", rc);
                /* fall through */

        case OPENIBNAL_INIT_LIB:
                lib_fini(&koibnal_lib);
                /* fall through */

        case OPENIBNAL_INIT_DATA:
                /* Module refcount only gets to zero when all peers
                 * have been closed so all lists must be empty */
                LASSERT (atomic_read (&koibnal_data.koib_npeers) == 0);
                LASSERT (koibnal_data.koib_peers != NULL);
                for (i = 0; i < koibnal_data.koib_peer_hash_size; i++) {
                        LASSERT (list_empty (&koibnal_data.koib_peers[i]));
                }
                LASSERT (atomic_read (&koibnal_data.koib_nconns) == 0);
                LASSERT (list_empty (&koibnal_data.koib_sched_rxq));
                LASSERT (list_empty (&koibnal_data.koib_sched_txq));
                LASSERT (list_empty (&koibnal_data.koib_connd_conns));
                LASSERT (list_empty (&koibnal_data.koib_connd_peers));

                /* flag threads to terminate; wake and wait for them to die */
                koibnal_data.koib_shutdown = 1;
                wake_up_all (&koibnal_data.koib_sched_waitq);
                wake_up_all (&koibnal_data.koib_connd_waitq);

                i = 2;
                while (atomic_read (&koibnal_data.koib_nthreads) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "Waiting for %d threads to terminate\n",
                               atomic_read (&koibnal_data.koib_nthreads));
                        set_current_state (TASK_INTERRUPTIBLE);
                        schedule_timeout (HZ);
                }
                /* fall through */
                
        case OPENIBNAL_INIT_NOTHING:
                break;
        }

        if (koibnal_data.koib_tx_descs != NULL)
                PORTAL_FREE (koibnal_data.koib_tx_descs,
                             OPENIBNAL_TX_MSGS * sizeof(koib_tx_t));

        if (koibnal_data.koib_peers != NULL)
                PORTAL_FREE (koibnal_data.koib_peers,
                             sizeof (struct list_head) * 
                             koibnal_data.koib_peer_hash_size);

        CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));
        printk(KERN_INFO "Lustre: OpenIB NAL unloaded (final mem %d)\n",
               atomic_read(&portal_kmemory));

        koibnal_data.koib_init = OPENIBNAL_INIT_NOTHING;
}

int
koibnal_api_startup (nal_t *nal, ptl_pid_t requested_pid,
                     ptl_ni_limits_t *requested_limits,
                     ptl_ni_limits_t *actual_limits)
{
        ptl_process_id_t  process_id;
        int               pkmem = atomic_read(&portal_kmemory);
        int               rc;
        int               i;

        LASSERT (nal == &koibnal_api);

        if (nal->nal_refct != 0) {
                if (actual_limits != NULL)
                        *actual_limits = koibnal_lib.libnal_ni.ni_actual_limits;
                /* This module got the first ref */
                PORTAL_MODULE_USE;
                return (PTL_OK);
        }

        LASSERT (koibnal_data.koib_init == OPENIBNAL_INIT_NOTHING);

        memset (&koibnal_data, 0, sizeof (koibnal_data)); /* zero pointers, flags etc */

        init_MUTEX (&koibnal_data.koib_nid_mutex);
        init_MUTEX_LOCKED (&koibnal_data.koib_nid_signal);
        koibnal_data.koib_nid = PTL_NID_ANY;

        rwlock_init(&koibnal_data.koib_global_lock);

        koibnal_data.koib_peer_hash_size = OPENIBNAL_PEER_HASH_SIZE;
        PORTAL_ALLOC (koibnal_data.koib_peers,
                      sizeof (struct list_head) * koibnal_data.koib_peer_hash_size);
        if (koibnal_data.koib_peers == NULL) {
                goto failed;
        }
        for (i = 0; i < koibnal_data.koib_peer_hash_size; i++)
                INIT_LIST_HEAD(&koibnal_data.koib_peers[i]);

        spin_lock_init (&koibnal_data.koib_connd_lock);
        INIT_LIST_HEAD (&koibnal_data.koib_connd_peers);
        INIT_LIST_HEAD (&koibnal_data.koib_connd_conns);
        init_waitqueue_head (&koibnal_data.koib_connd_waitq);

        spin_lock_init (&koibnal_data.koib_sched_lock);
        INIT_LIST_HEAD (&koibnal_data.koib_sched_txq);
        INIT_LIST_HEAD (&koibnal_data.koib_sched_rxq);
        init_waitqueue_head (&koibnal_data.koib_sched_waitq);

        spin_lock_init (&koibnal_data.koib_tx_lock);
        INIT_LIST_HEAD (&koibnal_data.koib_idle_txs);
        INIT_LIST_HEAD (&koibnal_data.koib_idle_nblk_txs);
        init_waitqueue_head(&koibnal_data.koib_idle_tx_waitq);

        PORTAL_ALLOC (koibnal_data.koib_tx_descs,
                      OPENIBNAL_TX_MSGS * sizeof(koib_tx_t));
        if (koibnal_data.koib_tx_descs == NULL) {
                CERROR ("Can't allocate tx descs\n");
                goto failed;
        }

        /* lists/ptrs/locks initialised */
        koibnal_data.koib_init = OPENIBNAL_INIT_DATA;
        /*****************************************************/

        process_id.pid = requested_pid;
        process_id.nid = koibnal_data.koib_nid;
        
        rc = lib_init(&koibnal_lib, nal, process_id,
                      requested_limits, actual_limits);
        if (rc != PTL_OK) {
                CERROR("lib_init failed: error %d\n", rc);
                goto failed;
        }

        /* lib interface initialised */
        koibnal_data.koib_init = OPENIBNAL_INIT_LIB;
        /*****************************************************/

        for (i = 0; i < OPENIBNAL_N_SCHED; i++) {
                rc = koibnal_thread_start (koibnal_scheduler, (void *)i);
                if (rc != 0) {
                        CERROR("Can't spawn openibnal scheduler[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        rc = koibnal_thread_start (koibnal_connd, NULL);
        if (rc != 0) {
                CERROR ("Can't spawn openibnal connd: %d\n", rc);
                goto failed;
        }

        koibnal_data.koib_device = ib_device_get_by_index(0);
        if (koibnal_data.koib_device == NULL) {
                CERROR ("Can't open ib device 0\n");
                goto failed;
        }
        
        rc = ib_device_properties_get(koibnal_data.koib_device,
                                      &koibnal_data.koib_device_props);
        if (rc != 0) {
                CERROR ("Can't get device props: %d\n", rc);
                goto failed;
        }

        CDEBUG(D_NET, "Max Initiator: %d Max Responder %d\n", 
               koibnal_data.koib_device_props.max_initiator_per_qp,
               koibnal_data.koib_device_props.max_responder_per_qp);

        koibnal_data.koib_port = 0;
        for (i = 1; i <= 2; i++) {
                rc = ib_port_properties_get(koibnal_data.koib_device, i,
                                            &koibnal_data.koib_port_props);
                if (rc == 0) {
                        koibnal_data.koib_port = i;
                        break;
                }
        }
        if (koibnal_data.koib_port == 0) {
                CERROR ("Can't find a port\n");
                goto failed;
        }

        rc = ib_pd_create(koibnal_data.koib_device,
                          NULL, &koibnal_data.koib_pd);
        if (rc != 0) {
                CERROR ("Can't create PD: %d\n", rc);
                goto failed;
        }
        
        /* flag PD initialised */
        koibnal_data.koib_init = OPENIBNAL_INIT_PD;
        /*****************************************************/
#if OPENIBNAL_FMR
        {
                const int pool_size = OPENIBNAL_NTX + OPENIBNAL_NTX_NBLK;
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
                rc = ib_fmr_pool_create(koibnal_data.koib_pd, &params,
                                        &koibnal_data.koib_fmr_pool);
                if (rc != 0) {
                        CERROR ("Can't create FMR pool size %d: %d\n", 
                                pool_size, rc);
                        goto failed;
                }
        }

        /* flag FMR pool initialised */
        koibnal_data.koib_init = OPENIBNAL_INIT_FMR;
#endif
        /*****************************************************/

        rc = koibnal_setup_tx_descs();
        if (rc != 0) {
                CERROR ("Can't register tx descs: %d\n", rc);
                goto failed;
        }
        
        /* flag TX descs initialised */
        koibnal_data.koib_init = OPENIBNAL_INIT_TXD;
        /*****************************************************/
        
        {
                struct ib_cq_callback callback = {
                        .context        = OPENIBNAL_CALLBACK_CTXT,
                        .policy         = IB_CQ_PROVIDER_REARM,
                        .function       = {
                                .entry  = koibnal_rx_callback,
                        },
                        .arg            = NULL,
                };
                int  nentries = OPENIBNAL_RX_CQ_ENTRIES;
                
                rc = ib_cq_create (koibnal_data.koib_device, 
                                   &nentries, &callback, NULL,
                                   &koibnal_data.koib_rx_cq);
                if (rc != 0) {
                        CERROR ("Can't create RX CQ: %d\n", rc);
                        goto failed;
                }

                /* I only want solicited events */
                rc = ib_cq_request_notification(koibnal_data.koib_rx_cq, 1);
                LASSERT (rc == 0);
        }
        
        /* flag RX CQ initialised */
        koibnal_data.koib_init = OPENIBNAL_INIT_RX_CQ;
        /*****************************************************/

        {
                struct ib_cq_callback callback = {
                        .context        = OPENIBNAL_CALLBACK_CTXT,
                        .policy         = IB_CQ_PROVIDER_REARM,
                        .function       = {
                                .entry  = koibnal_tx_callback,
                        },
                        .arg            = NULL,
                };
                int  nentries = OPENIBNAL_TX_CQ_ENTRIES;
                
                rc = ib_cq_create (koibnal_data.koib_device, 
                                   &nentries, &callback, NULL,
                                   &koibnal_data.koib_tx_cq);
                if (rc != 0) {
                        CERROR ("Can't create RX CQ: %d\n", rc);
                        goto failed;
                }

                /* I only want solicited events */
                rc = ib_cq_request_notification(koibnal_data.koib_tx_cq, 1);
                LASSERT (rc == 0);
        }
                                   
        /* flag TX CQ initialised */
        koibnal_data.koib_init = OPENIBNAL_INIT_TX_CQ;
        /*****************************************************/
        
        rc = libcfs_nal_cmd_register(OPENIBNAL, &koibnal_cmd, NULL);
        if (rc != 0) {
                CERROR ("Can't initialise command interface (rc = %d)\n", rc);
                goto failed;
        }

        /* flag everything initialised */
        koibnal_data.koib_init = OPENIBNAL_INIT_ALL;
        /*****************************************************/

        printk(KERN_INFO "Lustre: OpenIB NAL loaded "
               "(initial mem %d)\n", pkmem);

        return (PTL_OK);

 failed:
        koibnal_api_shutdown (&koibnal_api);    
        return (PTL_FAIL);
}

void __exit
koibnal_module_fini (void)
{
#ifdef CONFIG_SYSCTL
        if (koibnal_tunables.koib_sysctl != NULL)
                unregister_sysctl_table (koibnal_tunables.koib_sysctl);
#endif
        PtlNIFini(koibnal_ni);

        ptl_unregister_nal(OPENIBNAL);
}

int __init
koibnal_module_init (void)
{
        int    rc;

        /* the following must be sizeof(int) for proc_dointvec() */
        LASSERT(sizeof (koibnal_tunables.koib_io_timeout) == sizeof (int));

        koibnal_api.nal_ni_init = koibnal_api_startup;
        koibnal_api.nal_ni_fini = koibnal_api_shutdown;

        /* Initialise dynamic tunables to defaults once only */
        koibnal_tunables.koib_io_timeout = OPENIBNAL_IO_TIMEOUT;

        rc = ptl_register_nal(OPENIBNAL, &koibnal_api);
        if (rc != PTL_OK) {
                CERROR("Can't register OPENIBNAL: %d\n", rc);
                return (-ENOMEM);               /* or something... */
        }

        /* Pure gateways want the NAL started up at module load time... */
        rc = PtlNIInit(OPENIBNAL, LUSTRE_SRV_PTL_PID, NULL, NULL, &koibnal_ni);
        if (rc != PTL_OK && rc != PTL_IFACE_DUP) {
                ptl_unregister_nal(OPENIBNAL);
                return (-ENODEV);
        }
        
#ifdef CONFIG_SYSCTL
        /* Press on regardless even if registering sysctl doesn't work */
        koibnal_tunables.koib_sysctl = 
                register_sysctl_table (koibnal_top_ctl_table, 0);
#endif
        return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel OpenIB NAL v0.01");
MODULE_LICENSE("GPL");

module_init(koibnal_module_init);
module_exit(koibnal_module_fini);

