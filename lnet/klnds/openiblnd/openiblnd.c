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

#ifdef CONFIG_SYSCTL
#define IBNAL_SYSCTL             202

#define IBNAL_SYSCTL_TIMEOUT     1

static ctl_table kibnal_ctl_table[] = {
        {IBNAL_SYSCTL_TIMEOUT, "timeout", 
         &kibnal_tunables.kib_io_timeout, sizeof (int),
         0644, NULL, &proc_dointvec},
        { 0 }
};

static ctl_table kibnal_top_ctl_table[] = {
        {IBNAL_SYSCTL, "openibnal", NULL, 0, 0555, kibnal_ctl_table},
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
              service->service_id, name, 
              *kibnal_service_nid_field(service));
}

void
kibnal_service_setunset_done (tTS_IB_CLIENT_QUERY_TID tid, int status,
                               struct ib_common_attrib_service *service, void *arg)
{
        *(int *)arg = status;
        up (&kibnal_data.kib_nid_signal);
}

#if IBNAL_CHECK_ADVERT
void
kibnal_check_advert (void)
{
        struct ib_common_attrib_service *svc;
        __u64   tid;
        int     rc;
        int     rc2;

        PORTAL_ALLOC(svc, sizeof(*svc));
        if (svc == NULL)
                return;

        memset (svc, 0, sizeof (*svc));
        kibnal_set_service_keys(svc, kibnal_data.kib_nid);

        rc = ib_service_get (kibnal_data.kib_device, 
                             kibnal_data.kib_port,
                             svc,
                             KIBNAL_SERVICE_KEY_MASK,
                             kibnal_tunables.kib_io_timeout * HZ,
                             kibnal_service_setunset_done, &rc2, 
                             &tid);

        if (rc != 0) {
                CERROR ("Immediate error %d checking SM service\n", rc);
        } else {
                down (&kibnal_data.kib_nid_signal);
                rc = rc2;

                if (rc != 0)
                        CERROR ("Error %d checking SM service\n", rc);
        }

        PORTAL_FREE(svc, sizeof(*svc));
}
#endif

int
kibnal_advertise (void)
{
        struct ib_common_attrib_service *svc;
        __u64   tid;
        int     rc;
        int     rc2;

        LASSERT (kibnal_data.kib_nid != PTL_NID_ANY);

        PORTAL_ALLOC(svc, sizeof(*svc));
        if (svc == NULL)
                return (-ENOMEM);

        memset (svc, 0, sizeof (*svc));
        
        svc->service_id = kibnal_data.kib_service_id;

        rc = ib_cached_gid_get(kibnal_data.kib_device,
                               kibnal_data.kib_port,
                               0,
                               svc->service_gid);
        if (rc != 0) {
                CERROR ("Can't get port %d GID: %d\n",
                        kibnal_data.kib_port, rc);
                goto out;
        }
        
        rc = ib_cached_pkey_get(kibnal_data.kib_device,
                                kibnal_data.kib_port,
                                0,
                                &svc->service_pkey);
        if (rc != 0) {
                CERROR ("Can't get port %d PKEY: %d\n",
                        kibnal_data.kib_port, rc);
                goto out;
        }
        
        svc->service_lease = 0xffffffff;

        kibnal_set_service_keys(svc, kibnal_data.kib_nid);

        CDEBUG(D_NET, "Advertising service id "LPX64" %s:"LPX64"\n", 
               svc->service_id, 
               svc->service_name, *kibnal_service_nid_field(svc));

        rc = ib_service_set (kibnal_data.kib_device,
                             kibnal_data.kib_port,
                             svc,
                             IB_SA_SERVICE_COMP_MASK_ID |
                             IB_SA_SERVICE_COMP_MASK_GID |
                             IB_SA_SERVICE_COMP_MASK_PKEY |
                             IB_SA_SERVICE_COMP_MASK_LEASE |
                             KIBNAL_SERVICE_KEY_MASK,
                             kibnal_tunables.kib_io_timeout * HZ,
                             kibnal_service_setunset_done, &rc2, &tid);

        if (rc != 0) {
                CERROR ("Immediate error %d advertising NID "LPX64"\n",
                        rc, kibnal_data.kib_nid);
                goto out;
        }

        down (&kibnal_data.kib_nid_signal);

        rc = rc2;
        if (rc != 0)
                CERROR ("Error %d advertising NID "LPX64"\n", 
                        rc, kibnal_data.kib_nid);
 out:
        PORTAL_FREE(svc, sizeof(*svc));
        return (rc);
}

void
kibnal_unadvertise (int expect_success)
{
        struct ib_common_attrib_service *svc;
        __u64   tid;
        int     rc;
        int     rc2;

        LASSERT (kibnal_data.kib_nid != PTL_NID_ANY);

        PORTAL_ALLOC(svc, sizeof(*svc));
        if (svc == NULL)
                return;

        memset (svc, 0, sizeof(*svc));

        kibnal_set_service_keys(svc, kibnal_data.kib_nid);

        CDEBUG(D_NET, "Unadvertising service %s:"LPX64"\n",
               svc->service_name, *kibnal_service_nid_field(svc));

        rc = ib_service_delete (kibnal_data.kib_device,
                                kibnal_data.kib_port,
                                svc,
                                KIBNAL_SERVICE_KEY_MASK,
                                kibnal_tunables.kib_io_timeout * HZ,
                                kibnal_service_setunset_done, &rc2, &tid);
        if (rc != 0) {
                CERROR ("Immediate error %d unadvertising NID "LPX64"\n",
                        rc, kibnal_data.kib_nid);
                goto out;
        }

        down (&kibnal_data.kib_nid_signal);
        
        if ((rc2 == 0) == !!expect_success)
                goto out;                       /* success: rc == 0 */

        if (expect_success)
                CERROR("Error %d unadvertising NID "LPX64"\n",
                       rc, kibnal_data.kib_nid);
        else
                CWARN("Removed conflicting NID "LPX64"\n",
                      kibnal_data.kib_nid);
 out:
        PORTAL_FREE(svc, sizeof(*svc));
}

int
kibnal_set_mynid(ptl_nid_t nid)
{
        struct timeval tv;
        lib_ni_t      *ni = &kibnal_lib.libnal_ni;
        int            rc;

        CDEBUG(D_IOCTL, "setting mynid to "LPX64" (old nid="LPX64")\n",
               nid, ni->ni_pid.nid);

        do_gettimeofday(&tv);

        down (&kibnal_data.kib_nid_mutex);

        if (nid == kibnal_data.kib_nid) {
                /* no change of NID */
                up (&kibnal_data.kib_nid_mutex);
                return (0);
        }

        CDEBUG(D_NET, "NID "LPX64"("LPX64")\n",
               kibnal_data.kib_nid, nid);
        
        if (kibnal_data.kib_nid != PTL_NID_ANY) {

                kibnal_unadvertise (1);

                rc = ib_cm_listen_stop (kibnal_data.kib_listen_handle);
                if (rc != 0)
                        CERROR ("Error %d stopping listener\n", rc);
        }
        
        kibnal_data.kib_nid = ni->ni_pid.nid = nid;
        kibnal_data.kib_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;
        
        /* Delete all existing peers and their connections after new
         * NID/incarnation set to ensure no old connections in our brave
         * new world. */
        kibnal_del_peer (PTL_NID_ANY, 0);

        if (kibnal_data.kib_nid == PTL_NID_ANY) {
                /* No new NID to install */
                up (&kibnal_data.kib_nid_mutex);
                return (0);
        }
        
        /* remove any previous advert (crashed node etc) */
        kibnal_unadvertise(0);

        /* Assign new service number */
        kibnal_data.kib_service_id = ib_cm_service_assign();
        CDEBUG(D_NET, "service_id "LPX64"\n", kibnal_data.kib_service_id);
        
        rc = ib_cm_listen(kibnal_data.kib_service_id,
                          TS_IB_CM_SERVICE_EXACT_MASK,
                          kibnal_passive_conn_callback, NULL,
                          &kibnal_data.kib_listen_handle);
        if (rc == 0) {
                rc = kibnal_advertise();
                if (rc == 0) {
#if IBNAL_CHECK_ADVERT
                        kibnal_check_advert();
#endif
                        up (&kibnal_data.kib_nid_mutex);
                        return (0);
                }

                ib_cm_listen_stop(kibnal_data.kib_listen_handle);
                /* remove any peers that sprung up while I failed to
                 * advertise myself */
                kibnal_del_peer (PTL_NID_ANY, 0);
        }
        
        kibnal_data.kib_nid = PTL_NID_ANY;
        up (&kibnal_data.kib_nid_mutex);
        return (rc);
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

        read_lock (&kibnal_data.kib_global_lock);
        peer = kibnal_find_peer_locked (nid);
        if (peer != NULL)                       /* +1 ref for caller? */
                atomic_inc (&peer->ibp_refcount);
        read_unlock (&kibnal_data.kib_global_lock);

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
kibnal_get_peer_info (int index, ptl_nid_t *nidp, int *persistencep)
{
        kib_peer_t        *peer;
        struct list_head  *ptmp;
        int                i;

        read_lock (&kibnal_data.kib_global_lock);

        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {

                list_for_each (ptmp, &kibnal_data.kib_peers[i]) {
                        
                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (index-- > 0)
                                continue;

                        *nidp = peer->ibp_nid;
                        *persistencep = peer->ibp_persistence;
                        
                        read_unlock (&kibnal_data.kib_global_lock);
                        return (0);
                }
        }

        read_unlock (&kibnal_data.kib_global_lock);
        return (-ENOENT);
}

int
kibnal_add_persistent_peer (ptl_nid_t nid)
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
        int                i;

        read_lock (&kibnal_data.kib_global_lock);

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
                                read_unlock (&kibnal_data.kib_global_lock);
                                return (conn);
                        }
                }
        }

        read_unlock (&kibnal_data.kib_global_lock);
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
                wake_up_all(&kibnal_data.kib_connd_waitq);
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

        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);

        list_add (&conn->ibc_list, &kibnal_data.kib_connd_conns);
        wake_up (&kibnal_data.kib_connd_waitq);

        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);
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
                int         share_count = 0;

                rc = kibnal_get_peer_info(pcfg->pcfg_count,
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
                rc = kibnal_add_persistent_peer (pcfg->pcfg_nid);
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
                LASSERT (list_empty (&kibnal_data.kib_connd_conns));
                LASSERT (list_empty (&kibnal_data.kib_connd_peers));

                /* flag threads to terminate; wake and wait for them to die */
                kibnal_data.kib_shutdown = 1;
                wake_up_all (&kibnal_data.kib_sched_waitq);
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

        init_MUTEX (&kibnal_data.kib_nid_mutex);
        init_MUTEX_LOCKED (&kibnal_data.kib_nid_signal);
        kibnal_data.kib_nid = PTL_NID_ANY;

        rwlock_init(&kibnal_data.kib_global_lock);

        kibnal_data.kib_peer_hash_size = IBNAL_PEER_HASH_SIZE;
        PORTAL_ALLOC (kibnal_data.kib_peers,
                      sizeof (struct list_head) * kibnal_data.kib_peer_hash_size);
        if (kibnal_data.kib_peers == NULL) {
                goto failed;
        }
        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++)
                INIT_LIST_HEAD(&kibnal_data.kib_peers[i]);

        spin_lock_init (&kibnal_data.kib_connd_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_connd_peers);
        INIT_LIST_HEAD (&kibnal_data.kib_connd_conns);
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
        process_id.nid = kibnal_data.kib_nid;
        
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

        rc = kibnal_thread_start (kibnal_connd, NULL);
        if (rc != 0) {
                CERROR ("Can't spawn openibnal connd: %d\n", rc);
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
#ifdef CONFIG_SYSCTL
        if (kibnal_tunables.kib_sysctl != NULL)
                unregister_sysctl_table (kibnal_tunables.kib_sysctl);
#endif
        PtlNIFini(kibnal_ni);

        ptl_unregister_nal(OPENIBNAL);
}

int __init
kibnal_module_init (void)
{
        int    rc;

        /* the following must be sizeof(int) for proc_dointvec() */
        LASSERT(sizeof (kibnal_tunables.kib_io_timeout) == sizeof (int));

        kibnal_api.nal_ni_init = kibnal_api_startup;
        kibnal_api.nal_ni_fini = kibnal_api_shutdown;

        /* Initialise dynamic tunables to defaults once only */
        kibnal_tunables.kib_io_timeout = IBNAL_IO_TIMEOUT;

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
        
#ifdef CONFIG_SYSCTL
        /* Press on regardless even if registering sysctl doesn't work */
        kibnal_tunables.kib_sysctl = 
                register_sysctl_table (kibnal_top_ctl_table, 0);
#endif
        return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel OpenIB NAL v0.01");
MODULE_LICENSE("GPL");

module_init(kibnal_module_init);
module_exit(kibnal_module_fini);

