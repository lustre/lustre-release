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

#include "iiblnd.h"

ptl_nal_t kibnal_nal = {
        .nal_type          = IIBNAL,
        .nal_startup       = kibnal_startup,
        .nal_shutdown      = kibnal_shutdown,
        .nal_ctl           = kibnal_ctl,
        .nal_send          = kibnal_send,
        .nal_send_pages    = kibnal_send_pages,
        .nal_recv          = kibnal_recv,
        .nal_recv_pages    = kibnal_recv_pages,
};

lnet_handle_ni_t         kibnal_ni;
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
        {IBNAL_SYSCTL, "iibnal", NULL, 0, 0555, kibnal_ctl_table},
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

static void
kibnal_service_setunset_done (void *arg, FABRIC_OPERATION_DATA *fod,
                              FSTATUS frc, uint32 madrc)
{
        *(FSTATUS *)arg = frc;
        up (&kibnal_data.kib_nid_signal);
}

#if IBNAL_CHECK_ADVERT
static void
kibnal_service_query_done (void *arg, QUERY *qry, 
                           QUERY_RESULT_VALUES *qry_result)
{
        FSTATUS frc = qry_result->Status;

        if (frc != FSUCCESS &&
            qry_result->ResultDataSize == 0)
                frc = FERROR;
        
        *(FSTATUS *)arg = frc;
        up (&kibnal_data.kib_nid_signal);
}

static void
kibnal_check_advert (void)
{
        QUERY                  *qry;
        IB_SERVICE_RECORD      *svc;
        FSTATUS                 frc;
        FSTATUS                 frc2;

        PORTAL_ALLOC(qry, sizeof(*qry));
        if (qry == NULL)
                return;

        memset (qry, 0, sizeof(*qry));
        qry->InputType = InputTypeServiceRecord;
        qry->OutputType = OutputTypeServiceRecord;
        qry->InputValue.ServiceRecordValue.ComponentMask = KIBNAL_SERVICE_KEY_MASK;
        svc = &qry->InputValue.ServiceRecordValue.ServiceRecord;
        kibnal_set_service_keys(svc, kibnal_data.kib_ni->ni_nid);

        frc = iibt_sd_query_port_fabric_information(kibnal_data.kib_sd,
                                                    kibnal_data.kib_port_guid,
                                                    qry,
                                                    kibnal_service_query_done,
                                                    NULL, &frc2);
        if (frc != FSUCCESS && frc != FPENDING) {
                CERROR ("Immediate error %d checking SM service\n", frc);
        } else {
                down (&kibnal_data.kib_nid_signal);
                frc = frc2;

                if (frc != 0)
                        CERROR ("Error %d checking SM service\n", rc);
        }

        return (rc);
}
#endif

static void fill_fod(FABRIC_OPERATION_DATA *fod, FABRIC_OPERATION_TYPE type)
{
        IB_SERVICE_RECORD     *svc;

        memset (fod, 0, sizeof(*fod));
        fod->Type = type;

        svc = &fod->Value.ServiceRecordValue.ServiceRecord;
        svc->RID.ServiceID = kibnal_data.kib_service_id;
        svc->RID.ServiceGID.Type.Global.InterfaceID = kibnal_data.kib_port_guid;
        svc->RID.ServiceGID.Type.Global.SubnetPrefix = DEFAULT_SUBNET_PREFIX;
        svc->RID.ServiceP_Key = kibnal_data.kib_port_pkey;
        svc->ServiceLease = 0xffffffff;

        kibnal_set_service_keys(svc, kibnal_data.kib_ni->ni_nid);
}

static int
kibnal_advertise (void)
{
        FABRIC_OPERATION_DATA *fod;
        IB_SERVICE_RECORD     *svc;
        FSTATUS                frc;
        FSTATUS                frc2;

        LASSERT (kibnal_data.kib_ni->ni_nid != LNET_NID_ANY);

        PORTAL_ALLOC(fod, sizeof(*fod));
        if (fod == NULL)
                return (-ENOMEM);

        fill_fod(fod, FabOpSetServiceRecord);
        svc = &fod->Value.ServiceRecordValue.ServiceRecord;

        CDEBUG(D_NET, "Advertising service id "LPX64" %s:"LPX64"\n", 
               svc->RID.ServiceID, 
               svc->ServiceName, *kibnal_service_nid_field(svc));

        frc = iibt_sd_port_fabric_operation(kibnal_data.kib_sd,
                                            kibnal_data.kib_port_guid,
                                            fod, kibnal_service_setunset_done, 
                                            NULL, &frc2);

        if (frc != FSUCCESS && frc != FPENDING) {
                CERROR ("Immediate error %d advertising NID "LPX64"\n",
                        frc, kibnal_data.kib_ni->ni_nid);
                goto out;
        }

        down (&kibnal_data.kib_nid_signal);

        frc = frc2;
        if (frc != FSUCCESS)
                CERROR ("Error %d advertising BUD "LPX64"\n",
                        frc, kibnal_data.kib_ni->ni_nid);
out:
        PORTAL_FREE(fod, sizeof(*fod));
        return (frc == FSUCCESS) ? 0 : -EINVAL;
}

static void
kibnal_unadvertise (int expect_success)
{
        FABRIC_OPERATION_DATA *fod;
        IB_SERVICE_RECORD     *svc;
        FSTATUS                frc;
        FSTATUS                frc2;

        LASSERT (kibnal_data.kib_ni->ni_nid != LNET_NID_ANY);

        PORTAL_ALLOC(fod, sizeof(*fod));
        if (fod == NULL)
                return;

        fill_fod(fod, FabOpDeleteServiceRecord);
        svc = &fod->Value.ServiceRecordValue.ServiceRecord;

        CDEBUG(D_NET, "Unadvertising service %s:"LPX64"\n",
               svc->ServiceName, *kibnal_service_nid_field(svc));
        
        frc = iibt_sd_port_fabric_operation(kibnal_data.kib_sd,
                                            kibnal_data.kib_port_guid,
                                            fod, kibnal_service_setunset_done, 
                                            NULL, &frc2);

        if (frc != FSUCCESS && frc != FPENDING) {
                CERROR ("Immediate error %d unadvertising NID "LPX64"\n",
                        frc, kibnal_data.kib_ni->ni_nid);
                goto out;
        }

        down (&kibnal_data.kib_nid_signal);

        if ((frc2 == FSUCCESS) == !!expect_success)
                goto out;

        if (expect_success)
                CERROR("Error %d unadvertising NID "LPX64"\n",
                       frc2, kibnal_data.kib_ni->ni_nid);
        else
                CWARN("Removed conflicting NID "LPX64"\n",
                      kibnal_data.kib_ni->ni_nid);
 out:
        PORTAL_FREE(fod, sizeof(*fod));
}

static int
kibnal_set_mynid(lnet_nid_t nid)
{
        struct timeval tv;
        int            rc;
        FSTATUS        frc;

        CDEBUG(D_IOCTL, "setting mynid to "LPX64" (old nid="LPX64")\n",
               nid, kibnal_data.kib_ni->ni_nid);

        do_gettimeofday(&tv);

        down (&kibnal_data.kib_nid_mutex);

        if (nid == kibnal_data.kib_ni->ni_nid) {
                /* no change of NID */
                up (&kibnal_data.kib_nid_mutex);
                return (0);
        }

        CDEBUG(D_NET, "NID "LPX64"("LPX64")\n",
               kibnal_data.kib_ni->ni_nid, nid);
        
        if (kibnal_data.kib_ni->ni_nid != LNET_NID_ANY) {

                kibnal_unadvertise (1);

                frc = iibt_cm_cancel(kibnal_data.kib_cep);
                if (frc != FSUCCESS && frc != FPENDING)
                        CERROR ("Error %d stopping listener\n", frc);

                frc = iibt_cm_destroy_cep(kibnal_data.kib_cep);
                if (frc != FSUCCESS)
                        CERROR ("Error %d destroying CEP\n", frc);

                kibnal_data.kib_cep = NULL;
        }
        
        kibnal_data.kib_ni->ni_nid = nid;
        kibnal_data.kib_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;
        
        /* Delete all existing peers and their connections after new
         * NID/incarnation set to ensure no old connections in our brave
         * new world. */
        kibnal_del_peer(LNET_NID_ANY);

        if (kibnal_data.kib_ni->ni_nid == LNET_NID_ANY) {
                /* No new NID to install */
                up (&kibnal_data.kib_nid_mutex);
                return (0);
        }

        /* remove any previous advert (crashed node etc) */
        kibnal_unadvertise(0);

        kibnal_data.kib_cep = iibt_cm_create_cep(CM_RC_TYPE);
        if (kibnal_data.kib_cep == NULL) {
                CERROR ("Can't create CEP\n");
                rc = -ENOMEM;
        } else {
                CM_LISTEN_INFO info;
                memset (&info, 0, sizeof(info));
                info.ListenAddr.EndPt.SID = kibnal_data.kib_service_id;

                frc = iibt_cm_listen(kibnal_data.kib_cep, &info,
                                     kibnal_listen_callback, NULL);
                if (frc != FSUCCESS && frc != FPENDING) {
                        CERROR ("iibt_cm_listen error: %d\n", frc);
                        rc = -EINVAL;
                } else {
                        rc = 0;
                }
        }
        
        if (rc == 0) {
                rc = kibnal_advertise();
                if (rc == 0) {
#if IBNAL_CHECK_ADVERT
                        kibnal_check_advert();
#endif
                        up (&kibnal_data.kib_nid_mutex);
                        return (0);
                }
                
                iibt_cm_cancel (kibnal_data.kib_cep);
                iibt_cm_destroy_cep (kibnal_data.kib_cep);
                /* remove any peers that sprung up while I failed to
                 * advertise myself */
                kibnal_del_peer(LNET_NID_ANY);
        }

        kibnal_data.kib_ni->ni_nid = LNET_NID_ANY;
        up (&kibnal_data.kib_nid_mutex);
        return (rc);
}

kib_peer_t *
kibnal_create_peer (lnet_nid_t nid)
{
        kib_peer_t *peer;

        LASSERT (nid != LNET_NID_ANY);

        PORTAL_ALLOC (peer, sizeof (*peer));
        if (peer == NULL)
                return (NULL);

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        peer->ibp_nid = nid;
        atomic_set (&peer->ibp_refcount, 1);    /* 1 ref for caller */

        INIT_LIST_HEAD (&peer->ibp_list);       /* not in the peer table yet */
        INIT_LIST_HEAD (&peer->ibp_conns);
        INIT_LIST_HEAD (&peer->ibp_tx_queue);

        peer->ibp_reconnect_interval = 0;       /* OK to connect at any time */

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
kibnal_find_peer_locked (lnet_nid_t nid)
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
kibnal_get_peer (lnet_nid_t nid)
{
        kib_peer_t     *peer;
        unsigned long   flags;

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);
        peer = kibnal_find_peer_locked (nid);
        if (peer != NULL)                       /* +1 ref for caller? */
                kib_peer_addref(peer);
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
        kib_peer_decref(peer);
}

static int
kibnal_get_peer_info (int index, lnet_nid_t *nidp, int *persistencep)
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
                        *persistencep = peer->ibp_persistence;

                        read_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                               flags);
                        return (0);
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
        return (-ENOENT);
}

static int
kibnal_add_persistent_peer (lnet_nid_t nid)
{
        unsigned long      flags;
        kib_peer_t        *peer;
        kib_peer_t        *peer2;
        
        if (nid == LNET_NID_ANY)
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
kibnal_del_peer_locked (kib_peer_t *peer)
{
        struct list_head *ctmp;
        struct list_head *cnxt;
        kib_conn_t       *conn;

        peer->ibp_persistence = 0;

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
kibnal_del_peer (lnet_nid_t nid)
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

        if (nid != LNET_NID_ANY)
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

                        if (!(nid == LNET_NID_ANY || peer->ibp_nid == nid))
                                continue;

                        kibnal_del_peer_locked (peer);
                        rc = 0;         /* matched something */
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
        FSTATUS      frc;
        union {
                IB_QP_ATTRIBUTES_CREATE    qp_create;
                IB_QP_ATTRIBUTES_MODIFY    qp_attr;
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

                if (kibnal_whole_mem()) 
                        rx->rx_vaddr = kibnal_page2phys(page) + 
                                       page_offset + 
                                       kibnal_data.kib_md.md_addr;
                else
                        rx->rx_vaddr = vaddr;
                
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

        params.qp_create = (IB_QP_ATTRIBUTES_CREATE) {
                .Type                    = QPTypeReliableConnected,
                .SendQDepth              = IBNAL_TX_MAX_SG * 
                                           IBNAL_MSG_QUEUE_SIZE,
                .RecvQDepth              = IBNAL_MSG_QUEUE_SIZE,
                .SendDSListDepth         = 1,
                .RecvDSListDepth         = 1,
                .SendCQHandle            = kibnal_data.kib_cq,
                .RecvCQHandle            = kibnal_data.kib_cq,
                .PDHandle                = kibnal_data.kib_pd,
                .SendSignaledCompletions = TRUE,
        };
        frc = iibt_qp_create(kibnal_data.kib_hca, &params.qp_create, NULL,
                             &conn->ibc_qp, &conn->ibc_qp_attrs);
        if (rc != 0) {
                CERROR ("Failed to create queue pair: %d\n", rc);
                goto failed;
        }

        /* Mark QP created */
        conn->ibc_state = IBNAL_CONN_INIT_QP;

        params.qp_attr = (IB_QP_ATTRIBUTES_MODIFY) {
                .RequestState             = QPStateInit,
                .Attrs                    = (IB_QP_ATTR_PORTGUID |
                                             IB_QP_ATTR_PKEYINDEX |
                                             IB_QP_ATTR_ACCESSCONTROL),
                .PortGUID                 = kibnal_data.kib_port_guid,
                .PkeyIndex                = 0,
                .AccessControl = {
                        .s = {
                                .RdmaWrite = 1,
                                .RdmaRead  = 1,
                        },
                },
        };
        rc = iibt_qp_modify(conn->ibc_qp, &params.qp_attr, NULL);
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
        FSTATUS frc;
        
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
                rc = iibt_qp_destroy(conn->ibc_qp);
                if (rc != 0)
                        CERROR("Can't destroy QP: %d\n", rc);
                /* fall through */
                
        case IBNAL_CONN_INIT_NOTHING:
                break;

        default:
                LASSERT (0);
        }

        if (conn->ibc_cep != NULL) {
                frc = iibt_cm_destroy_cep(conn->ibc_cep);
                if (frc != 0)
                        CERROR("Can't destroy CEP %p: %d\n", conn->ibc_cep, 
                               frc);
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
kibnal_close_matching_conns (lnet_nid_t nid)
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

        if (nid != LNET_NID_ANY)
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

                        if (!(nid == LNET_NID_ANY || nid == peer->ibp_nid))
                                continue;

                        count += kibnal_close_peer_conns_locked (peer, 0);
                }
        }

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        /* wildcards always succeed */
        if (nid == LNET_NID_ANY)
                return (0);
        
        return (count == 0 ? -ENOENT : 0);
}

int
kibnal_ctl(ptl_ni_t *ni, unsigned int cmd, void *arg)
{
        struct portal_ioctl_data *data = arg;
        int                       rc = -EINVAL;
        ENTRY;

        LASSERT (ni == kibnal_data.kib_ni);

        switch(cmd) {
        case IOC_PORTAL_GET_PEER: {
                lnet_nid_t   nid = 0;
                int         share_count = 0;

                rc = kibnal_get_peer_info(data->ioc_count,
                                          &nid, &share_count);
                data->ioc_nid   = nid;
                data->ioc_count = share_count;
                break;
        }
        case IOC_PORTAL_ADD_PEER: {
                rc = kibnal_add_persistent_peer (data->ioc_nid);
                break;
        }
        case IOC_PORTAL_DEL_PEER: {
                rc = kibnal_del_peer (data->ioc_nid);
                break;
        }
        case IOC_PORTAL_GET_CONN: {
                kib_conn_t *conn = kibnal_get_conn_by_idx (data->ioc_count);

                if (conn == NULL)
                        rc = -ENOENT;
                else {
                        rc = 0;
                        data->ioc_nid = conn->ibc_peer->ibp_nid;
                        kibnal_put_conn (conn);
                }
                break;
        }
        case IOC_PORTAL_CLOSE_CONNECTION: {
                rc = kibnal_close_matching_conns (data->ioc_nid);
                break;
        }
        case IOC_PORTAL_REGISTER_MYNID: {
                if (data->ioc_nid == LNET_NID_ANY)
                        rc = -EINVAL;
                else
                        rc = kibnal_set_mynid (data->ioc_nid);
                break;
        }
        }

        RETURN(rc);
}

void
kibnal_free_pages (kib_pages_t *p)
{
        int     npages = p->ibp_npages;
        int     rc;
        int     i;
        
        if (p->ibp_mapped) {
                rc = iibt_deregister_memory(p->ibp_handle);
                if (rc != 0)
                        CERROR ("Deregister error: %d\n", rc);
        }
        
        for (i = 0; i < npages; i++)
                if (p->ibp_pages[i] != NULL)
                        __free_page(p->ibp_pages[i]);
        
        PORTAL_FREE (p, offsetof(kib_pages_t, ibp_pages[npages]));
}

int
kibnal_alloc_pages (kib_pages_t **pp, int npages, int allow_write)
{
        kib_pages_t                *p;
        __u64                      *phys_pages;
        int                         i;
        FSTATUS                     frc;
        IB_ACCESS_CONTROL           access;

        memset(&access, 0, sizeof(access));
        access.s.MWBindable = 1;
        access.s.LocalWrite = 1;
        access.s.RdmaRead = 1;
        access.s.RdmaWrite = 1;

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

        PORTAL_ALLOC(phys_pages, npages * sizeof(*phys_pages));
        if (phys_pages == NULL) {
                CERROR ("Can't allocate physarray for %d pages\n", npages);
                /* XXX free ibp_pages? */
                kibnal_free_pages(p);
                return (-ENOMEM);
        }

        /* if we were using the _contig_ registration variant we would have
         * an array of PhysAddr/Length pairs, but the discontiguous variant
         * just takes the PhysAddr */
        for (i = 0; i < npages; i++)
                phys_pages[i] = kibnal_page2phys(p->ibp_pages[i]);

        frc = iibt_register_physical_memory(kibnal_data.kib_hca,
                                            0,          /* requested vaddr */
                                            phys_pages, npages,
                                            0,          /* offset */
                                            kibnal_data.kib_pd,
                                            access,
                                            &p->ibp_handle, &p->ibp_vaddr,
                                            &p->ibp_lkey, &p->ibp_rkey);
        
        PORTAL_FREE(phys_pages, npages * sizeof(*phys_pages));
        
        if (frc != FSUCCESS) {
                CERROR ("Error %d mapping %d pages\n", frc, npages);
                kibnal_free_pages(p);
                return (-ENOMEM);
        }

        CDEBUG(D_NET, "registered %d pages; handle: %p vaddr "LPX64" "
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

                if (kibnal_whole_mem()) 
                        tx->tx_vaddr = kibnal_page2phys(page) + 
                                       page_offset + 
                                       kibnal_data.kib_md.md_addr;
                else
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
kibnal_shutdown (ptl_ni_t *ni)
{
        int   i;
        int   rc;

        LASSERT (ni->ni_data == &kibnal_data);
        LASSERT (ni == kibnal_data.kib_ni);
       
        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read (&portal_kmemory));

        switch (kibnal_data.kib_init) {
        default:
                CERROR ("Unexpected state %d\n", kibnal_data.kib_init);
                LBUG();

        case IBNAL_INIT_ALL:
                /* resetting my NID to unadvertises me, removes my
                 * listener and nukes all current peers */
                kibnal_set_mynid (LNET_NID_ANY);

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
                rc = iibt_cq_destroy(kibnal_data.kib_cq);
                if (rc != 0)
                        CERROR ("Destroy CQ error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_TXD:
                kibnal_free_pages (kibnal_data.kib_tx_pages);
                /* fall through */

        case IBNAL_INIT_MR:
                if (kibnal_data.kib_md.md_handle != NULL) {
                        rc = iibt_deregister_memory(kibnal_data.kib_md.md_handle);
                        if (rc != FSUCCESS)
                                CERROR ("Deregister memory: %d\n", rc);
                }
                /* fall through */

#if IBNAL_FMR
        case IBNAL_INIT_FMR:
                rc = ib_fmr_pool_destroy (kibnal_data.kib_fmr_pool);
                if (rc != 0)
                        CERROR ("Destroy FMR pool error: %d\n", rc);
                /* fall through */
#endif
        case IBNAL_INIT_PD:
                rc = iibt_pd_free(kibnal_data.kib_pd);
                if (rc != 0)
                        CERROR ("Destroy PD error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_SD:
                rc = iibt_sd_deregister(kibnal_data.kib_sd);
                if (rc != 0)
                        CERROR ("Deregister SD error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_PORT:
                /* XXX ??? */
                /* fall through */

        case IBNAL_INIT_PORTATTRS:
                PORTAL_FREE(kibnal_data.kib_hca_attrs.PortAttributesList,
                            kibnal_data.kib_hca_attrs.PortAttributesListSize);
                /* fall through */

        case IBNAL_INIT_HCA:
                rc = iibt_close_hca(kibnal_data.kib_hca);
                if (rc != 0)
                        CERROR ("Close HCA  error: %d\n", rc);
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

        kibnal_data.kib_init = IBNAL_INIT_NOTHING;
        PORTAL_MODULE_UNUSE;
}

#define roundup_power(val, power) \
        ( (val + (__u64)(power - 1)) & ~((__u64)(power - 1)) )

/* this isn't very portable or sturdy in the face of funny mem/bus configs */
static __u64 max_phys_mem(IB_CA_ATTRIBUTES *ca_attr)
{
        struct sysinfo si;
        __u64 ret;

        /* XXX we don't bother with first-gen cards */
        if (ca_attr->VendorId == 0xd0b7 && ca_attr->DeviceId == 0x3101)
                return 0ULL;

        si_meminfo(&si);
        ret = (__u64)max(si.totalram, max_mapnr) * si.mem_unit;
        return roundup_power(ret, 128 * 1024 * 1024);
} 
#undef roundup_power

int
kibnal_startup (ptl_ni_t *ni)
{
        IB_PORT_ATTRIBUTES *pattr;
        FSTATUS             frc;
        int                 rc;
        int                 n;
        int                 i;

        LASSERT (ni->ni_nal == &kibnal_nal);

        /* Only 1 instance supported */
        if (kibnal_data.kib_init != IBNAL_INIT_NOTHING) {
                CERROR ("Only 1 instance supported\n");
                return -EPERM;
        }

        if (ni->ni_interfaces[0] != NULL) {
                CERROR("Explicit interface config not supported\n");
                return -EPERM;
        }
        
        ni->ni_data = &kibnal_data;
        kibnal_data.kib_ni = ni;

        frc = IbtGetInterfaceByVersion(IBT_INTERFACE_VERSION_2, 
                                       &kibnal_data.kib_interfaces);
        if (frc != FSUCCESS) {
                CERROR("IbtGetInterfaceByVersion(IBT_INTERFACE_VERSION_2) = %d\n",
                        frc);
                return -ENOSYS;
        }

        PORTAL_MODULE_USE;

        init_MUTEX (&kibnal_data.kib_nid_mutex);
        init_MUTEX_LOCKED (&kibnal_data.kib_nid_signal);
        kibnal_data.kib_ni->ni_nid = LNET_NID_ANY;

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

        for (i = 0; i < IBNAL_N_SCHED; i++) {
                rc = kibnal_thread_start (kibnal_scheduler, (void *)i);
                if (rc != 0) {
                        CERROR("Can't spawn iibnal scheduler[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        rc = kibnal_thread_start (kibnal_connd, NULL);
        if (rc != 0) {
                CERROR ("Can't spawn iibnal connd: %d\n", rc);
                goto failed;
        }

        n = sizeof(kibnal_data.kib_hca_guids) /
            sizeof(kibnal_data.kib_hca_guids[0]);
        frc = iibt_get_hca_guids(&n, kibnal_data.kib_hca_guids);
        if (frc != FSUCCESS) {
                CERROR ("Can't get channel adapter guids: %d\n", frc);
                goto failed;
        }
        if (n == 0) {
                CERROR ("No channel adapters found\n");
                goto failed;
        }

        /* Infinicon has per-HCA rather than per CQ completion handlers */
        frc = iibt_open_hca(kibnal_data.kib_hca_guids[0],
                            kibnal_ca_callback,
                            kibnal_ca_async_callback,
                            &kibnal_data.kib_hca,
                            &kibnal_data.kib_hca);
        if (frc != FSUCCESS) {
                CERROR ("Can't open CA[0]: %d\n", frc);
                goto failed;
        }
        
        /* Channel Adapter opened */
        kibnal_data.kib_init = IBNAL_INIT_HCA;
        /*****************************************************/

        kibnal_data.kib_hca_attrs.PortAttributesList = NULL;
        kibnal_data.kib_hca_attrs.PortAttributesListSize = 0;
        frc = iibt_query_hca(kibnal_data.kib_hca,
                             &kibnal_data.kib_hca_attrs, NULL);
        if (frc != FSUCCESS) {
                CERROR ("Can't size port attrs: %d\n", frc);
                goto failed;
        }
        
        PORTAL_ALLOC(kibnal_data.kib_hca_attrs.PortAttributesList,
                     kibnal_data.kib_hca_attrs.PortAttributesListSize);
        if (kibnal_data.kib_hca_attrs.PortAttributesList == NULL)
                goto failed;

        /* Port attrs allocated */
        kibnal_data.kib_init = IBNAL_INIT_PORTATTRS;
        /*****************************************************/
        
        frc = iibt_query_hca(kibnal_data.kib_hca, &kibnal_data.kib_hca_attrs,
                             NULL);
        if (frc != FSUCCESS) {
                CERROR ("Can't get port attrs for CA 0: %d\n", frc);
                goto failed;
        }

        for (i = 0, pattr = kibnal_data.kib_hca_attrs.PortAttributesList;
             pattr != NULL;
             i++, pattr = pattr->Next) {
                switch (pattr->PortState) {
                default:
                        CERROR("Unexpected port[%d] state %d\n",
                               i, pattr->PortState);
                        continue;
                case PortStateDown:
                        CDEBUG(D_NET, "port[%d] Down\n", i);
                        continue;
                case PortStateInit:
                        CDEBUG(D_NET, "port[%d] Init\n", i);
                        continue;
                case PortStateArmed:
                        CDEBUG(D_NET, "port[%d] Armed\n", i);
                        continue;
                        
                case PortStateActive:
                        CDEBUG(D_NET, "port[%d] Active\n", i);
                        kibnal_data.kib_port = i;
                        kibnal_data.kib_port_guid = pattr->GUID;
                        kibnal_data.kib_port_pkey = pattr->PkeyTable[0];
                        break;
                }
                break;
        }

        if (pattr == NULL) {
                CERROR ("Can't find an active port\n");
                goto failed;
        }

        CDEBUG(D_NET, "got guid "LPX64"\n", kibnal_data.kib_port_guid);
        
        /* Active port found */
        kibnal_data.kib_init = IBNAL_INIT_PORT;
        /*****************************************************/

        frc = iibt_sd_register(&kibnal_data.kib_sd, NULL);
        if (frc != FSUCCESS) {
                CERROR ("Can't register with SD: %d\n", frc);
                goto failed;
        }
        
        /* Registered with SD OK */
        kibnal_data.kib_init = IBNAL_INIT_SD;
        /*****************************************************/

        frc = iibt_pd_allocate(kibnal_data.kib_hca, 0, &kibnal_data.kib_pd);
        if (frc != FSUCCESS) {
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
        if (IBNAL_WHOLE_MEM) {
                IB_MR_PHYS_BUFFER phys;
                IB_ACCESS_CONTROL access;
                kib_md_t *md = &kibnal_data.kib_md;

                memset(&access, 0, sizeof(access));
                access.s.MWBindable = 1;
                access.s.LocalWrite = 1;
                access.s.RdmaRead = 1;
                access.s.RdmaWrite = 1;

                phys.PhysAddr = 0;
                phys.Length = max_phys_mem(&kibnal_data.kib_hca_attrs);
                if (phys.Length == 0) {
                        CERROR ("couldn't determine the end of phys mem\n");
                        goto failed;
                }
       
                rc = iibt_register_contig_physical_memory(kibnal_data.kib_hca,
                                                          0,
                                                          &phys, 1,
                                                          0,
                                                          kibnal_data.kib_pd,
                                                          access,
                                                          &md->md_handle,
                                                          &md->md_addr,
                                                          &md->md_lkey,
                                                          &md->md_rkey);
                if (rc != FSUCCESS) {
                        CERROR("registering physical memory failed: %d\n", 
                               rc);
                        CERROR("falling back to registration per-rdma\n");
                        md->md_handle = NULL;
                } else {
                        CDEBUG(D_NET, "registered "LPU64" bytes of mem\n",
                               phys.Length);
                        kibnal_data.kib_init = IBNAL_INIT_MR;
                }
        }

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
                uint32 nentries;

                frc = iibt_cq_create(kibnal_data.kib_hca, IBNAL_CQ_ENTRIES,
                                     &kibnal_data.kib_cq, &kibnal_data.kib_cq,
                                     &nentries);
                if (frc != FSUCCESS) {
                        CERROR ("Can't create RX CQ: %d\n", frc);
                        goto failed;
                }

                /* flag CQ initialised */
                kibnal_data.kib_init = IBNAL_INIT_CQ;

                if (nentries < IBNAL_CQ_ENTRIES) {
                        CERROR ("CQ only has %d entries, need %d\n", 
                                nentries, IBNAL_CQ_ENTRIES);
                        goto failed;
                }

                rc = iibt_cq_rearm(kibnal_data.kib_cq, CQEventSelNextWC);
                if (rc != 0) {
                        CERROR ("Failed to re-arm completion queue: %d\n", rc);
                        goto failed;
                }
        }
        
        /* flag everything initialised */
        kibnal_data.kib_init = IBNAL_INIT_ALL;
        /*****************************************************/

        return (0);

 failed:
        kibnal_shutdown (ni);    
        return (-ENETDOWN);
}

void __exit
kibnal_module_fini (void)
{
#ifdef CONFIG_SYSCTL
        if (kibnal_tunables.kib_sysctl != NULL)
                unregister_sysctl_table (kibnal_tunables.kib_sysctl);
#endif
        ptl_unregister_nal(&kibnal_nal);
}

int __init
kibnal_module_init (void)
{
        int    rc;

        if (sizeof(kib_wire_connreq_t) > CM_REQUEST_INFO_USER_LEN) {
                CERROR("sizeof(kib_wire_connreq_t) > CM_REQUEST_INFO_USER_LEN\n");
                return -EINVAL;
        }

        /* the following must be sizeof(int) for proc_dointvec() */
        if (sizeof (kibnal_tunables.kib_io_timeout) != sizeof (int)) {
                CERROR("sizeof (kibnal_tunables.kib_io_timeout) != sizeof (int)\n");
                return -EINVAL;
        }

        /* Initialise dynamic tunables to defaults once only */
        kibnal_tunables.kib_io_timeout = IBNAL_IO_TIMEOUT;

        ptl_register_nal(&kibnal_nal);
        
#ifdef CONFIG_SYSCTL
        /* Press on regardless even if registering sysctl doesn't work */
        kibnal_tunables.kib_sysctl = 
                register_sysctl_table (kibnal_top_ctl_table, 0);
#endif
        return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel Infinicon IB NAL v0.01");
MODULE_LICENSE("GPL");

module_init(kibnal_module_init);
module_exit(kibnal_module_fini);

