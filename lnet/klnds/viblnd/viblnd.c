/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *   Author: Frank Zago <fzago@systemfabricworks.com>
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

#include "vibnal.h"

nal_t                   kibnal_api;
ptl_handle_ni_t         kibnal_ni;
kib_tunables_t          kibnal_tunables;

kib_data_t              kibnal_data = {
        .kib_service_id = IBNAL_SERVICE_NUMBER,
};

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
        {IBNAL_SYSCTL, "vibnal", NULL, 0, 0555, kibnal_ctl_table},
        { 0 }
};
#endif

#ifdef unused
void
print_service(IB_SERVICE_RECORD *service, char *tag, int rc)
{
        char name[32];

        if (service == NULL) 
        {
                CWARN("tag       : %s\n"
                      "status    : %d (NULL)\n", tag, rc);
                return;
        }
        strncpy (name, service->ServiceName, sizeof(name)-1);
        name[sizeof(name)-1] = 0;
        
        CWARN("tag       : %s\n"
              "status    : %d\n"
              "service id: "LPX64"\n"
              "name      : %s\n"
              "NID       : "LPX64"\n", tag, rc,
              service->RID.ServiceID, name,
              *kibnal_service_nid_field(service));
}
#endif

/* 
 * method is SUBN_ADM_SET, SUBN_ADM_GET, SUBN_ADM_DELETE. Tables not supported.
 * nid is the nid to advertize/query/unadvertize
 */
static void fill_sa_request(struct sa_request *request, int method, ptl_nid_t nid)
{
        gsi_dtgrm_t *dtgrm = request->dtgrm_req;
        sa_mad_v2_t *mad = (sa_mad_v2_t *) dtgrm->mad;
        ib_service_record_v2_t *sr = (ib_service_record_v2_t *) mad->payload;
        
        memset(mad, 0, MAD_BLOCK_SIZE);

        request->mad = mad;

        dtgrm->rlid = kibnal_data.kib_port_attr.port_sma_address_info.sm_lid;
        dtgrm->sl = kibnal_data.kib_port_attr.port_sma_address_info.service_level;

        mad->hdr.base_ver = MAD_IB_BASE_VERSION;
        mad->hdr.class = MAD_CLASS_SUBN_ADM;
        mad->hdr.class_ver = 2;
        mad->hdr.m.ms.method = method;
        mad->hdr.attrib_id = SA_SERVICE_RECORD; /* something(?) will swap that field */

		/* Note: the transaction ID is set by the Voltaire stack if it is 0. */

        /* TODO: change the 40 to sizeof(something) */
        mad->payload_len = cpu_to_be32(0x40 /*header size */  +
                                       sizeof (ib_service_record_v2_t));


        mad->component_mask = cpu_to_be64(
                                          (1ull << 0)  |	/* service_id       */
                                          (1ull << 2)  |	/* service_pkey     */
                                          (1ull << 6)  |	/* service_name     */
                                          (1ull << 7)  |	/* service_data8[0] */
                                          (1ull << 8)  |	/* service_data8[1] */
                                          (1ull << 9)  |	/* service_data8[2] */
                                          (1ull << 10) |	/* service_data8[3] */
                                          (1ull << 11) |	/* service_data8[4] */
                                          (1ull << 12) |	/* service_data8[5] */
                                          (1ull << 13) |	/* service_data8[6] */
                                          (1ull << 14)      /* service_data8[7] */
                                          );

        sr->service_id = cpu_to_be64(kibnal_data.kib_service_id);
        sr->service_pkey = cpu_to_be16(kibnal_data.kib_port_pkey);

        /* Set the service name and the data (bytes 0 to 7) in data8 */
        kibnal_set_service_keys(sr, nid);

        if (method == SUBN_ADM_SET) {
                mad->component_mask |= cpu_to_be64(
                                                   (1ull << 1) |	/* service_gid       */
                                                   (1ull << 4)  	/* service_lease     */
                                                   );

                sr->service_gid = kibnal_data.kib_port_gid;
                gid_swap(&sr->service_gid);
                sr->service_lease = cpu_to_be32(0xffffffff);
        }

        CDEBUG(D_NET, "SA request %02x for service id "LPX64" %s:"LPX64"\n",
               mad->hdr.m.ms.method,
               sr->service_id, 
               sr->service_name,
               *kibnal_service_nid_field(sr));
}

/* Do an advertizement operation: 
 *   SUBN_ADM_GET = 0x01 (i.e. query),
 *   SUBN_ADM_SET = 0x02 (i.e. advertize),
 *   SUBN_ADM_DELETE = 0x15 (i.e. un-advertize).
 * If callback is NULL, the function is synchronous (and context is ignored).
 */
int kibnal_advertize_op(ptl_nid_t nid, int op, sa_request_cb_t callback, void *context)
{
        struct sa_request *request;
        int ret;

        LASSERT (kibnal_data.kib_nid != PTL_NID_ANY);

        CDEBUG(D_NET, "kibnal_advertize_op: nid="LPX64", op=%d\n", nid, op);

        request = alloc_sa_request();
        if (request == NULL) {
                CERROR("Cannot allocate a SA request");
                return -ENOMEM;
        }
                
        fill_sa_request(request, op, nid);

        if (callback) {
                request->callback = callback;
                request->context = context;
        } else {
                init_completion(&request->signal);
        }

        ret = vibnal_start_sa_request(request);
        if (ret) {
                CERROR("vibnal_send_sa failed: %d\n", ret);
                free_sa_request(request);
        } else {
                if (callback) {
                        /* Return. The callback will have to free the SA request. */
                        ret = 0;
                } else {
                        wait_for_completion(&request->signal);

                        ret = request->status;

                        if (ret != 0) {
                                CERROR ("Error %d in advertising operation %d for NID "LPX64"\n",
                                        ret, op, kibnal_data.kib_nid);
                        }
                        
                        free_sa_request(request);
                }
        }

        return ret;
}

static int
kibnal_set_mynid(ptl_nid_t nid)
{
        struct timeval tv;
        lib_ni_t      *ni = &kibnal_lib.libnal_ni;
        int            rc;
        vv_return_t    retval;

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

        /* Unsubscribes the current NID */
        if (kibnal_data.kib_nid != PTL_NID_ANY) {

                rc = kibnal_advertize_op(kibnal_data.kib_nid, SUBN_ADM_DELETE, NULL, NULL);

                if (rc) {
                        CERROR("Error %d unadvertising NID "LPX64"\n",
                               rc, kibnal_data.kib_nid);
                }
        }
        
        kibnal_data.kib_nid = ni->ni_pid.nid = nid;
        kibnal_data.kib_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

        /* Destroys the current endpoint, if any. */
        if (kibnal_data.kib_cep) {
                retval = cm_cancel(kibnal_data.kib_cep);
                if (retval)
                        CERROR ("Error %d stopping listener\n", retval);
        
                retval = cm_destroy_cep(kibnal_data.kib_cep);
                if (retval)
                        CERROR ("Error %d destroying CEP\n", retval);
        
                kibnal_data.kib_cep = NULL;
        }
        
        /* Delete all existing peers and their connections after new
         * NID/incarnation set to ensure no old connections in our brave
         * new world. */
        kibnal_del_peer (PTL_NID_ANY, 0);

        if (kibnal_data.kib_nid == PTL_NID_ANY) {
                /* No new NID to install. The driver is shuting down. */
                up (&kibnal_data.kib_nid_mutex);
                return (0);
        }

        /* remove any previous advert (crashed node etc) */
        kibnal_advertize_op(kibnal_data.kib_nid, SUBN_ADM_DELETE, NULL, NULL);

        kibnal_data.kib_cep = cm_create_cep(cm_cep_transp_rc);
        if (kibnal_data.kib_cep == NULL) {
                CERROR ("Can't create CEP\n");
                rc = -ENOMEM;
        } else {
                cm_return_t cmret;
                cm_listen_data_t info;

                CDEBUG(D_NET, "Created CEP %p for listening\n", kibnal_data.kib_cep);

                memset(&info, 0, sizeof(info));
                info.listen_addr.end_pt.sid = kibnal_data.kib_service_id;

                cmret = cm_listen(kibnal_data.kib_cep, &info,
                                  kibnal_listen_callback, NULL);
                if (cmret) {
                        CERROR ("cm_listen error: %d\n", cmret);
                        rc = -EINVAL;
                } else {
                        rc = 0;
                }
        }
        
        if (rc == 0) {
                rc = kibnal_advertize_op(kibnal_data.kib_nid, SUBN_ADM_SET, NULL, NULL);
                if (rc == 0) {
#ifdef IBNAL_CHECK_ADVERT
                        kibnal_advertize_op(kibnal_data.kib_nid, SUBN_ADM_GET, NULL, NULL);
#endif
                        up (&kibnal_data.kib_nid_mutex);
                        return (0);
                }
                
                retval = cm_cancel (kibnal_data.kib_cep);
                if (retval)
                        CERROR("cm_cancel failed: %d\n", retval);

                retval = cm_destroy_cep (kibnal_data.kib_cep);
                if (retval)
                        CERROR("cm_destroy_cep failed: %d\n", retval);

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

        PORTAL_ALLOC(peer, sizeof (*peer));
        if (peer == NULL) {
                CERROR("Canot allocate perr\n");
                return (NULL);
        }

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        peer->ibp_nid = nid;
        atomic_set (&peer->ibp_refcount, 1);    /* 1 ref for caller */

        INIT_LIST_HEAD (&peer->ibp_list);       /* not in the peer table yet */
        INIT_LIST_HEAD (&peer->ibp_conns);
        INIT_LIST_HEAD (&peer->ibp_tx_queue);

        peer->ibp_reconnect_time = jiffies;
        peer->ibp_reconnect_interval = IBNAL_MIN_RECONNECT_INTERVAL;

        atomic_inc (&kibnal_data.kib_npeers);
        return (peer);
}

void
kibnal_destroy_peer (kib_peer_t *peer)
{

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

/* the caller is responsible for accounting for the additional reference
 * that this creates */
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
                kib_peer_addref(peer);
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
        kib_peer_decref(peer);
}

static int
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

static int
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
                kib_peer_decref (peer);
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

static void
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

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry(ctmp, kib_conn_t, ibc_list);

                kibnal_close_conn_locked (conn, 0);
        }

        /* NB peer unlinks itself when last conn is closed */
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

static kib_conn_t *
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
        vv_qp_attr_t qp_attr;
        vv_return_t  retval;
        int          rc;
        void        *qp_context;
        
        PORTAL_ALLOC(conn, sizeof (*conn));
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

        PORTAL_ALLOC(conn->ibc_rxs, IBNAL_RX_MSGS * sizeof (kib_rx_t));
        if (conn->ibc_rxs == NULL) {
                CERROR("Cannot allocate RX buffers\n");
                goto failed;
        }
        memset (conn->ibc_rxs, 0, IBNAL_RX_MSGS * sizeof(kib_rx_t));

        rc = kibnal_alloc_pages(&conn->ibc_rx_pages, IBNAL_RX_MSG_PAGES, 1);
        if (rc != 0)
                goto failed;

        vaddr_base = vaddr = conn->ibc_rx_pages->ibp_vaddr;

        for (i = ipage = page_offset = 0; i < IBNAL_RX_MSGS; i++) {
                struct page *page = conn->ibc_rx_pages->ibp_pages[ipage];
                kib_rx_t   *rx = &conn->ibc_rxs[i];

                rx->rx_conn = conn;
                rx->rx_msg = (kib_msg_t *)(((char *)page_address(page)) + 
                             page_offset);

                if (kibnal_whole_mem()) {
                        void *newaddr;
                        vv_mem_reg_h_t mem_h;
                        vv_r_key_t r_key;

                        /* Voltaire stack already registers the whole
                         * memory, so use that API. */
                        retval = vv_get_gen_mr_attrib(kibnal_data.kib_hca,
                                                      rx->rx_msg,
                                                      IBNAL_MSG_SIZE,
                                                      &mem_h,
                                                      &rx->l_key,
                                                      &r_key);
                        if (retval) {
                                CERROR("vv_get_gen_mr_attrib failed: %d", retval);
                                /* TODO: free pages? */
                                goto failed;
                        }
                }
                
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

        qp_attr = (vv_qp_attr_t) {
                .create.qp_type          = vv_qp_type_r_conn,
                .create.cq_send_h        = kibnal_data.kib_cq,
                .create.cq_receive_h     = kibnal_data.kib_cq,
                .create.send_max_outstand_wr = IBNAL_TX_MAX_SG * 
                                           IBNAL_MSG_QUEUE_SIZE,
                .create.receive_max_outstand_wr = IBNAL_MSG_QUEUE_SIZE,
                .create.max_scatgat_per_send_wr = 1,
                .create.max_scatgat_per_receive_wr = 1,
                .create.signaling_type   = vv_selectable_signaling, /* TODO: correct? */
                .create.pd_h             = kibnal_data.kib_pd,
                .create.recv_solicited_events = vv_signal_all,
        };
        retval = vv_qp_create(kibnal_data.kib_hca, &qp_attr, NULL,
                              &conn->ibc_qp, &conn->ibc_qp_attrs);
        if (retval != 0) {
                CERROR ("Failed to create queue pair: %d\n", retval);
                goto failed;
        }

        /* Mark QP created */
        conn->ibc_state = IBNAL_CONN_INIT_QP;

        qp_attr = (vv_qp_attr_t) {
                .modify.qp_modify_into_state = vv_qp_state_init,
                .modify.vv_qp_attr_mask      = VV_QP_AT_STATE | VV_QP_AT_PHY_PORT_NUM | VV_QP_AT_P_KEY_IX | VV_QP_AT_ACCESS_CON_F,
                .modify.qp_type              = vv_qp_type_r_conn,

                .modify.params.init.p_key_indx      = 0,
                .modify.params.init.phy_port_num    = kibnal_data.kib_port,
                .modify.params.init.access_control  = vv_acc_r_mem_write | vv_acc_r_mem_read,
        };
        retval = vv_qp_modify(kibnal_data.kib_hca, conn->ibc_qp, &qp_attr, &conn->ibc_qp_attrs);
        if (retval != 0) {
                CERROR ("Failed to modify queue pair: %d\n", retval);
                goto failed;
        }

        retval = vv_qp_query(kibnal_data.kib_hca, conn->ibc_qp, &qp_context, &conn->ibc_qp_attrs);
        if (retval) {
                CERROR ("Failed to query queue pair: %d\n", retval);
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
        vv_return_t retval;
        
        CDEBUG (D_NET, "connection %p\n", conn);

        LASSERT (atomic_read (&conn->ibc_refcount) == 0);
        LASSERT (list_empty(&conn->ibc_tx_queue));
        LASSERT (list_empty(&conn->ibc_active_txs));
        LASSERT (conn->ibc_nsends_posted == 0);
        LASSERT (conn->ibc_connreq == NULL);

        switch (conn->ibc_state) {
        case IBNAL_CONN_DISCONNECTED:
                /* called after connection sequence initiated */
                /* fall through */

        case IBNAL_CONN_INIT_QP:
                /* _destroy includes an implicit Reset of the QP which 
                 * discards posted work */
                retval = vv_qp_destroy(kibnal_data.kib_hca, conn->ibc_qp);
                if (retval)
                        CERROR("Can't destroy QP: %d\n", retval);
                /* fall through */
                
        case IBNAL_CONN_INIT_NOTHING:
                break;

        default:
                LASSERT (0);
        }

        if (conn->ibc_cep != NULL) {
                retval = cm_destroy_cep(conn->ibc_cep);
                if (retval)
                        CERROR("Can't destroy CEP %p: %d\n", conn->ibc_cep, 
                               retval);
        }

        if (conn->ibc_rx_pages != NULL) 
                kibnal_free_pages(conn->ibc_rx_pages);
        
        if (conn->ibc_rxs != NULL)
                PORTAL_FREE(conn->ibc_rxs, 
                            IBNAL_RX_MSGS * sizeof(kib_rx_t));

        if (conn->ibc_peer != NULL)
                kib_peer_decref(conn->ibc_peer);

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

        /* must disconnect before dropping the final ref */
        LASSERT (conn->ibc_state == IBNAL_CONN_DISCONNECTED);

        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);

        list_add (&conn->ibc_list, &kibnal_data.kib_connd_conns);
        wake_up (&kibnal_data.kib_connd_waitq);

        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);
}

static int
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

static int
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

static int
kibnal_cmd(struct portals_cfg *pcfg, void * private)
{
        int rc = -EINVAL;
        ENTRY;

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

        RETURN(rc);
}

void
kibnal_free_pages (kib_pages_t *p)
{
        int     npages = p->ibp_npages;
        vv_return_t retval;
        int     i;
        
        if (p->ibp_mapped) {
                retval = vv_mem_region_destroy(kibnal_data.kib_hca, p->ibp_handle);
                if (retval != 0)
                        CERROR ("Deregister error: %d\n", retval);
        }
        
        for (i = 0; i < npages; i++)
                if (p->ibp_pages[i] != NULL)
                        __free_page(p->ibp_pages[i]);
        
        PORTAL_FREE (p, offsetof(kib_pages_t, ibp_pages[npages]));
}

int
kibnal_alloc_pages (kib_pages_t **pp, int npages, int allow_write)
{
        kib_pages_t   *p;
        vv_phy_list_t  phys_pages;
        vv_phy_buf_t  *phys_buf;
        int            i;
        vv_return_t    retval;

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

        if (kibnal_whole_mem())
                goto out;

        PORTAL_ALLOC(phys_buf, npages * sizeof(vv_phy_buf_t));
        if (phys_buf == NULL) {
                CERROR ("Can't allocate phys_buf for %d pages\n", npages);
                /* XXX free ibp_pages? */
                kibnal_free_pages(p);
                return (-ENOMEM);
        }

        phys_pages.number_of_buff = npages;
        phys_pages.phy_list = phys_buf;

        /* if we were using the _contig_ registration variant we would have
         * an array of PhysAddr/Length pairs, but the discontiguous variant
         * just takes the PhysAddr */
        for (i = 0; i < npages; i++) {
                phys_buf[i].start = kibnal_page2phys(p->ibp_pages[i]);
                phys_buf[i].size = PAGE_SIZE;
        }

        retval = vv_phy_mem_region_register(kibnal_data.kib_hca,
                                            &phys_pages,
                                            0, /* requested vaddr */
                                            npages * PAGE_SIZE,
                                            0, /* offset */
                                            kibnal_data.kib_pd,
                                            vv_acc_l_mem_write | vv_acc_r_mem_write | vv_acc_r_mem_read | vv_acc_mem_bind, /* TODO: translated as-is, but seems incorrect or too much */
                                            &p->ibp_handle, &p->ibp_vaddr,                                           
                                            &p->ibp_lkey, &p->ibp_rkey);
        
        PORTAL_FREE(phys_buf, npages * sizeof(vv_phy_buf_t));
        
        if (retval) {
                CERROR ("Error %d mapping %d pages\n", retval, npages);
                kibnal_free_pages(p);
                return (-ENOMEM);
        }

        CDEBUG(D_NET, "registered %d pages; handle: %x vaddr "LPX64" "
                      "lkey %x rkey %x\n", npages, p->ibp_handle,
                      p->ibp_vaddr, p->ibp_lkey, p->ibp_rkey);
        
        p->ibp_mapped = 1;
out:
        *pp = p;
        return (0);
}

static int
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

        rc = kibnal_alloc_pages(&kibnal_data.kib_tx_pages, IBNAL_TX_MSG_PAGES, 
                                0);
        if (rc != 0)
                return (rc);

        /* ignored for the whole_mem case */
        vaddr = vaddr_base = kibnal_data.kib_tx_pages->ibp_vaddr;

        for (i = 0; i < IBNAL_TX_MSGS; i++) {
                page = kibnal_data.kib_tx_pages->ibp_pages[ipage];
                tx = &kibnal_data.kib_tx_descs[i];

                memset (tx, 0, sizeof(*tx));    /* zero flags etc */
                
                tx->tx_msg = (kib_msg_t *)(((char *)page_address(page)) + 
                                           page_offset);

                if (kibnal_whole_mem()) {
                        void *newaddr;
                        vv_mem_reg_h_t mem_h;
                        vv_return_t  retval;

                        /* Voltaire stack already registers the whole
                         * memory, so use that API. */
                        retval = vv_get_gen_mr_attrib(kibnal_data.kib_hca,
                                                      tx->tx_msg,
                                                      IBNAL_MSG_SIZE,
                                                      &mem_h,
                                                      &tx->l_key,
                                                      &tx->r_key);
                        if (retval) {
                                CERROR("vv_get_gen_mr_attrib failed: %d", retval);
                                /* TODO: free pages? */
                                /* TODO: return. */
                        }
                }

                tx->tx_isnblk = (i >= IBNAL_NTX);
                tx->tx_mapped = KIB_TX_UNMAPPED;

                CDEBUG(D_NET, "Tx[%d] %p->%p\n", i, tx, tx->tx_msg);

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

static void
kibnal_api_shutdown (nal_t *nal)
{
        int   i;
        int   rc;
        vv_return_t retval;

        if (nal->nal_refct != 0) {
                /* This module got the first ref */
                PORTAL_MODULE_UNUSE;
                return;
        }

        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        LASSERT(nal == &kibnal_api);

        switch (kibnal_data.kib_init) {

        case IBNAL_INIT_ALL:
                /* stop calls to nal_cmd */
                libcfs_nal_cmd_unregister(VIBNAL);
                /* No new peers */

                /* resetting my NID to unadvertises me, removes my
                 * listener and nukes all current peers */
                kibnal_set_mynid (PTL_NID_ANY);

                /* Wait for all peer state to clean up (crazy) */
                i = 2;
                while (atomic_read (&kibnal_data.kib_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "waiting for %d peers to disconnect (can take a few seconds)\n",
                               atomic_read (&kibnal_data.kib_npeers));
                        set_current_state (TASK_UNINTERRUPTIBLE);
                        schedule_timeout (HZ);
                }
                /* fall through */

        case IBNAL_INIT_CQ:
                retval = vv_cq_destroy(kibnal_data.kib_hca, kibnal_data.kib_cq);
                if (retval)
                        CERROR ("Destroy CQ error: %d\n", retval);
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
#if IBNAL_WHOLE_MEM==0
                retval = vv_pd_deallocate(kibnal_data.kib_hca, kibnal_data.kib_pd);
                if (retval != 0)
                        CERROR ("Destroy PD error: %d\n", retval);
#endif
                /* fall through */

        case IBNAL_INIT_GSI:
                retval = gsi_deregister_class(kibnal_data.gsi_handle);
                if (retval != 0)
                        CERROR ("GSI deregister failed: %d\n", retval);
                /* fall through */

        case IBNAL_INIT_GSI_POOL:
                gsi_dtgrm_pool_destroy(kibnal_data.gsi_pool_handle);
                /* fall through */

        case IBNAL_INIT_PORT:
                /* XXX ??? */
                /* fall through */

        case IBNAL_INIT_ASYNC:
                retval = vv_dell_async_event_cb (kibnal_data.kib_hca,
                                                 kibnal_ca_async_callback);
                if (retval)
                        CERROR("deregister asynchronous call back error: %d\n", retval);
                        
                /* fall through */

        case IBNAL_INIT_HCA:
                retval = vv_hca_close(kibnal_data.kib_hca);
                if (retval != 0)
                        CERROR ("Close HCA  error: %d\n", retval);
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
        printk(KERN_INFO "Lustre: Voltaire IB NAL unloaded (final mem %d)\n",
               atomic_read(&portal_kmemory));

        kibnal_data.kib_init = IBNAL_INIT_NOTHING;
}

#define roundup_power(val, power) \
        ( (val + (__u64)(power - 1)) & ~((__u64)(power - 1)) )

/* this isn't very portable or sturdy in the face of funny mem/bus configs */
static __u64 max_phys_mem(void)
{
        struct sysinfo si;
        __u64 ret;

        si_meminfo(&si);
        ret = (__u64)max(si.totalram, max_mapnr) * si.mem_unit;
        return roundup_power(ret, 128 * 1024 * 1024);
} 
#undef roundup_power

static int
kibnal_api_startup (nal_t *nal, ptl_pid_t requested_pid,
                     ptl_ni_limits_t *requested_limits,
                     ptl_ni_limits_t *actual_limits)
{
        ptl_process_id_t    process_id;
        int                 pkmem = atomic_read(&portal_kmemory);
        int                 rc;
        int                 i;
        vv_request_event_record_t req_er;
        vv_return_t         retval;

        LASSERT (nal == &kibnal_api);

        if (nal->nal_refct != 0) {
                if (actual_limits != NULL)
                        *actual_limits = kibnal_lib.libnal_ni.ni_actual_limits;
                /* This module got the first ref */
                PORTAL_MODULE_USE;
                return (PTL_OK);
        }

        LASSERT (kibnal_data.kib_init == IBNAL_INIT_NOTHING);

        init_MUTEX (&kibnal_data.kib_nid_mutex);
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

        INIT_LIST_HEAD (&kibnal_data.gsi_pending);
        init_MUTEX (&kibnal_data.gsi_mutex);

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
                rc = kibnal_thread_start (kibnal_scheduler, (void *)i);
                if (rc != 0) {
                        CERROR("Can't spawn vibnal scheduler[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        rc = kibnal_thread_start (kibnal_connd, NULL);
        if (rc != 0) {
                CERROR ("Can't spawn vibnal connd: %d\n", rc);
                goto failed;
        }

        /* TODO: apparently only one adapter is supported */
        retval = vv_hca_open("ANY_HCA", NULL, &kibnal_data.kib_hca);
        if (retval) {
                CERROR ("Can't open CA: %d\n", retval);
                goto failed;
        }

        /* Channel Adapter opened */
        kibnal_data.kib_init = IBNAL_INIT_HCA;

        /* register to get HCA's asynchronous events. */
        req_er.req_event_type = VV_ASYNC_EVENT_ALL_MASK;
        retval = vv_set_async_event_cb (kibnal_data.kib_hca,
                                        req_er,
                                        kibnal_ca_async_callback);

        if (retval) {
                CERROR ("Can't open CA: %d\n", retval);
                goto failed; 
        }

        kibnal_data.kib_init = IBNAL_INIT_ASYNC;

        /*****************************************************/

        retval = vv_hca_query(kibnal_data.kib_hca,
                             &kibnal_data.kib_hca_attrs);
        if (retval) {
                CERROR ("Can't size port attrs: %d\n", retval);
                goto failed;
        }

        kibnal_data.kib_port = -1;

        for (i = 0; i<kibnal_data.kib_hca_attrs.port_num; i++) {

                int port_num = i+1;
                u_int32_t tbl_count;
                vv_port_attrib_t *pattr = &kibnal_data.kib_port_attr;

                retval = vv_port_query(kibnal_data.kib_hca, port_num, pattr);
                if (retval) {
                        CERROR("vv_port_query failed for port %d: %d\n", port_num, retval);
                        continue;
                }

                switch (pattr->port_state) {
                case vv_state_linkDoun:
                        CDEBUG(D_NET, "port[%d] Down\n", port_num);
                        continue;
                case vv_state_linkInit:
                        CDEBUG(D_NET, "port[%d] Init\n", port_num);
                        continue;
                case vv_state_linkArm:
                        CDEBUG(D_NET, "port[%d] Armed\n", port_num);
                        continue;
                case vv_state_linkActive:
                        CDEBUG(D_NET, "port[%d] Active\n", port_num);

                        /* Found a suitable port. Get its GUID and PKEY. */
                        kibnal_data.kib_port = port_num;
                        
                        tbl_count = 1;
                        retval = vv_get_port_gid_tbl(kibnal_data.kib_hca, port_num, &tbl_count, &kibnal_data.kib_port_gid);
                        if (retval) {
                                CERROR("vv_get_port_gid_tbl failed for port %d: %d\n", port_num, retval);
                                continue;
                        }

                        tbl_count = 1;
                        retval = vv_get_port_partition_tbl (kibnal_data.kib_hca, port_num, &tbl_count, &kibnal_data.kib_port_pkey);
                        if (retval) {
                                CERROR("vv_get_port_partition_tbl failed for port %d: %d\n", port_num, retval);
                                continue;
                        }

                        break;
                case vv_state_linkActDefer: /* TODO: correct? */
                case vv_state_linkNoChange:
                        CERROR("Unexpected port[%d] state %d\n",
                               i, pattr->port_state);
                        continue;
                }
                break;
        }

        if (kibnal_data.kib_port == -1) {
                CERROR ("Can't find an active port\n");
                goto failed;
        }

        CDEBUG(D_NET, "Using port %d - GID="LPX64":"LPX64"\n",
               kibnal_data.kib_port, kibnal_data.kib_port_gid.scope.g.subnet, kibnal_data.kib_port_gid.scope.g.eui64);
        CDEBUG(D_NET, "got guid "LPX64"\n", cpu_to_le64(kibnal_data.kib_port_gid.scope.g.eui64));
        
        /* Active port found */
        kibnal_data.kib_init = IBNAL_INIT_PORT;
        /*****************************************************/

        /* Prepare things to be able to send/receive MADS */
        retval = gsi_dtgrm_pool_create(IBNAL_CONCURRENT_PEERS, &kibnal_data.gsi_pool_handle);
        if (retval) {
                CERROR("Could not create GSI pool: %d\n", retval);
                goto failed;
        }
        kibnal_data.kib_init = IBNAL_INIT_GSI_POOL;

        retval = gsi_register_class(MAD_CLASS_SUBN_ADM, /* TODO: correct? */
                                2,	/* version */
                                "ANY_HCA",
#ifdef GSI_PASS_PORT_NUM
                                kibnal_data.kib_port,
#endif                   
                                0, 0,
                                vibnal_mad_sent_cb,	vibnal_mad_received_cb,
                                NULL, &kibnal_data.gsi_handle);
        if (retval) {
                CERROR("Cannot register GSI class: %d\n", retval);
                goto failed;
        }

        kibnal_data.kib_init = IBNAL_INIT_GSI;
        /*****************************************************/

#if IBNAL_WHOLE_MEM==0
        retval = vv_pd_allocate(kibnal_data.kib_hca, &kibnal_data.kib_pd);
#else
        retval = vv_get_gen_pd_h(kibnal_data.kib_hca, &kibnal_data.kib_pd);
#endif
        if (retval) {
                CERROR ("Can't create PD: %d\n", retval);
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
                uint32_t nentries;

                retval = vv_cq_create(kibnal_data.kib_hca, IBNAL_CQ_ENTRIES,
                                      kibnal_ca_callback, 
                                      NULL, /* context */
                                      &kibnal_data.kib_cq, &nentries);
                if (retval) {
                        CERROR ("Can't create RX CQ: %d\n", retval);
                        goto failed;
                }

                /* flag CQ initialised */
                kibnal_data.kib_init = IBNAL_INIT_CQ;

                if (nentries < IBNAL_CQ_ENTRIES) {
                        CERROR ("CQ only has %d entries, need %d\n", 
                                nentries, IBNAL_CQ_ENTRIES);
                        goto failed;
                }

                retval = vv_request_completion_notification(kibnal_data.kib_hca, kibnal_data.kib_cq, vv_next_solicit_unsolicit_event);
                if (retval != 0) {
                        CERROR ("Failed to re-arm completion queue: %d\n", rc);
                        goto failed;
                }
        }
        
        /*****************************************************/

        rc = libcfs_nal_cmd_register(VIBNAL, &kibnal_cmd, NULL);
        if (rc != 0) {
                CERROR ("Can't initialise command interface (rc = %d)\n", rc);
                goto failed;
        }

        /* flag everything initialised */
        kibnal_data.kib_init = IBNAL_INIT_ALL;
        /*****************************************************/

        printk(KERN_INFO "Lustre: Voltaire IB NAL loaded "
               "(initial mem %d)\n", pkmem);

        return (PTL_OK);

 failed:
        CDEBUG(D_NET, "kibnal_api_startup failed\n");
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

        ptl_unregister_nal(VIBNAL);
}

int __init
kibnal_module_init (void)
{
        int    rc;

        if (sizeof(kib_wire_connreq_t) > cm_REQ_priv_data_len) {
                CERROR("sizeof(kib_wire_connreq_t) > cm_REQ_priv_data_len\n");
                return -EINVAL;
        }

        /* the following must be sizeof(int) for proc_dointvec() */
        if (sizeof (kibnal_tunables.kib_io_timeout) != sizeof (int)) {
                CERROR("sizeof (kibnal_tunables.kib_io_timeout) != sizeof (int)\n");
                return -EINVAL;
        }

        kibnal_api.nal_ni_init = kibnal_api_startup;
        kibnal_api.nal_ni_fini = kibnal_api_shutdown;

        /* Initialise dynamic tunables to defaults once only */
        kibnal_tunables.kib_io_timeout = IBNAL_IO_TIMEOUT;

        rc = ptl_register_nal(VIBNAL, &kibnal_api);
        if (rc != PTL_OK) {
                CERROR("Can't register IBNAL: %d\n", rc);
                return (-ENOMEM);               /* or something... */
        }

        /* Pure gateways want the NAL started up at module load time... */
        rc = PtlNIInit(VIBNAL, LUSTRE_SRV_PTL_PID, NULL, NULL, &kibnal_ni);
        if (rc != PTL_OK && rc != PTL_IFACE_DUP) {
                ptl_unregister_nal(VIBNAL);
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
MODULE_DESCRIPTION("Kernel Voltaire IB NAL v0.01");
MODULE_LICENSE("GPL");

module_init(kibnal_module_init);
module_exit(kibnal_module_fini);

