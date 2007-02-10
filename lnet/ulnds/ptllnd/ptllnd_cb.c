/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: Eric Barton <eeb@bartonsoftware.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   This file is confidential source code owned by Cluster File Systems.
 *   No viewing, modification, compilation, redistribution, or any other
 *   form of use is permitted except through a signed license agreement.
 *
 *   If you have not signed such an agreement, then you have no rights to
 *   this file.  Please destroy it immediately and contact CFS.
 *
 */

#include "ptllnd.h"

char *
ptllnd_ptlid2str(ptl_process_id_t id)
{
        static char strs[8][32];
        static int  idx = 0;

        char   *str = strs[idx++];
        
        if (idx >= sizeof(strs)/sizeof(strs[0]))
                idx = 0;

        snprintf(str, sizeof(strs[0]), FMT_PTLID, id.pid, id.nid);
        return str;
}

void
ptllnd_destroy_peer(ptllnd_peer_t *peer)
{
        lnet_ni_t         *ni = peer->plp_ni;
        ptllnd_ni_t       *plni = ni->ni_data;

        LASSERT (peer->plp_closing);
        LASSERT (plni->plni_npeers > 0);
        LASSERT (list_empty(&peer->plp_txq));
        LASSERT (list_empty(&peer->plp_activeq));
        plni->plni_npeers--;
        LIBCFS_FREE(peer, sizeof(*peer));
}

void
ptllnd_abort_txs(ptllnd_ni_t *plni, struct list_head *q)
{
        while (!list_empty(q)) {
                ptllnd_tx_t *tx = list_entry(q->next, ptllnd_tx_t, tx_list);

                tx->tx_status = -ESHUTDOWN;
                list_del(&tx->tx_list);
                list_add_tail(&tx->tx_list, &plni->plni_zombie_txs);
        }
}

void
ptllnd_close_peer(ptllnd_peer_t *peer, int error)
{
        lnet_ni_t   *ni = peer->plp_ni;
        ptllnd_ni_t *plni = ni->ni_data;

        if (peer->plp_closing)
                return;

        peer->plp_closing = 1;

        if (!list_empty(&peer->plp_txq) ||
            !list_empty(&peer->plp_activeq) ||
            error != 0) {
                CERROR("Closing %s\n", libcfs_id2str(peer->plp_id));
                ptllnd_debug_peer(ni, peer->plp_id);
        }
        
        ptllnd_abort_txs(plni, &peer->plp_txq);
        ptllnd_abort_txs(plni, &peer->plp_activeq);

        list_del(&peer->plp_list);
        ptllnd_peer_decref(peer);
}

ptllnd_peer_t *
ptllnd_find_peer(lnet_ni_t *ni, lnet_process_id_t id, int create)
{
        ptllnd_ni_t       *plni = ni->ni_data;
        unsigned int       hash = LNET_NIDADDR(id.nid) % plni->plni_peer_hash_size;
        struct list_head  *tmp;
        ptllnd_peer_t     *plp;
        ptllnd_tx_t       *tx;
        int                rc;

        LASSERT (LNET_NIDNET(id.nid) == LNET_NIDNET(ni->ni_nid));

        list_for_each(tmp, &plni->plni_peer_hash[hash]) {
                plp = list_entry(tmp, ptllnd_peer_t, plp_list);

                if (plp->plp_id.nid == id.nid &&
                    plp->plp_id.pid == id.pid) {
                        ptllnd_peer_addref(plp);
                        return plp;
                }
        }

        if (!create)
                return NULL;

        /* New peer: check first for enough posted buffers */
        plni->plni_npeers++;
        rc = ptllnd_grow_buffers(ni);
        if (rc != 0) {
                plni->plni_npeers--;
                return NULL;
        }

        LIBCFS_ALLOC(plp, sizeof(*plp));
        if (plp == NULL) {
                CERROR("Can't allocate new peer %s\n", libcfs_id2str(id));
                plni->plni_npeers--;
                return NULL;
        }

        CDEBUG(D_NET, "new peer=%p\n",plp);

        plp->plp_ni = ni;
        plp->plp_id = id;
        plp->plp_ptlid.nid = LNET_NIDADDR(id.nid);
        plp->plp_ptlid.pid = plni->plni_ptllnd_pid;
        plp->plp_max_credits =
        plp->plp_credits = 1; /* add more later when she gives me credits */
        plp->plp_max_msg_size = plni->plni_max_msg_size; /* until I hear from her */
        plp->plp_outstanding_credits = plni->plni_peer_credits - 1;
        plp->plp_match = 0;
        plp->plp_stamp = 0;
        plp->plp_recvd_hello = 0;
        plp->plp_closing = 0;
        plp->plp_refcount = 1;
        CFS_INIT_LIST_HEAD(&plp->plp_list);
        CFS_INIT_LIST_HEAD(&plp->plp_txq);
        CFS_INIT_LIST_HEAD(&plp->plp_activeq);

        ptllnd_peer_addref(plp);
        list_add_tail(&plp->plp_list, &plni->plni_peer_hash[hash]);

        tx = ptllnd_new_tx(plp, PTLLND_MSG_TYPE_HELLO, 0);
        if (tx == NULL) {
                CERROR("Can't send HELLO to %s\n", libcfs_id2str(id));
                ptllnd_close_peer(plp, -ENOMEM);
                ptllnd_peer_decref(plp);
                return NULL;
        }

        tx->tx_msg.ptlm_u.hello.kptlhm_matchbits = PTL_RESERVED_MATCHBITS;
        tx->tx_msg.ptlm_u.hello.kptlhm_max_msg_size = plni->plni_max_msg_size;

        ptllnd_post_tx(tx);

        return plp;
}

int
ptllnd_count_q(struct list_head *q)
{
        struct list_head *e;
        int               n = 0;
        
        list_for_each(e, q) {
                n++;
        }
        
        return n;
}

const char *
ptllnd_tx_typestr(int type) 
{
        switch (type) {
        case PTLLND_RDMA_WRITE:
                return "rdma_write";
                
        case PTLLND_RDMA_READ:
                return "rdma_read";

        case PTLLND_MSG_TYPE_PUT:
                return "put_req";
                
        case PTLLND_MSG_TYPE_GET:
                return "get_req";

        case PTLLND_MSG_TYPE_IMMEDIATE:
                return "immediate";

        case PTLLND_MSG_TYPE_NOOP:
                return "noop";

        case PTLLND_MSG_TYPE_HELLO:
                return "hello";

        default:
                return "<unknown>";
        }
}

void
ptllnd_debug_tx(ptllnd_tx_t *tx) 
{
        CDEBUG(D_WARNING, "%s %s b "DBGT_FMT"/"DBGT_FMT
               " r "DBGT_FMT"/"DBGT_FMT" status %d\n",
               ptllnd_tx_typestr(tx->tx_type),
               libcfs_id2str(tx->tx_peer->plp_id)
               DBGT_ARGS(tx->tx_bulk_posted) DBGT_ARGS(tx->tx_bulk_done)
               DBGT_ARGS(tx->tx_req_posted) DBGT_ARGS(tx->tx_req_done),
               tx->tx_status);
}

void
ptllnd_debug_peer(lnet_ni_t *ni, lnet_process_id_t id)
{
        ptllnd_peer_t    *plp = ptllnd_find_peer(ni, id, 0);
        struct list_head *tmp;
        ptllnd_ni_t      *plni = ni->ni_data;
        ptllnd_tx_t      *tx;
        
        if (plp == NULL) {
                CDEBUG(D_WARNING, "No peer %s\n", libcfs_id2str(id));
                return;
        }
        
        CDEBUG(D_WARNING, "%s %s%s [%d] "LPD64".%06d m "LPD64" q %d/%d c %d/%d(%d)\n",
               libcfs_id2str(id), 
               plp->plp_recvd_hello ? "H" : "_",
               plp->plp_closing     ? "C" : "_",
               plp->plp_refcount,
               plp->plp_stamp / 1000000, (int)(plp->plp_stamp % 1000000),
               plp->plp_match,
               ptllnd_count_q(&plp->plp_txq),
               ptllnd_count_q(&plp->plp_activeq),
               plp->plp_credits, plp->plp_outstanding_credits, plp->plp_max_credits);

        CDEBUG(D_WARNING, "txq:\n");
        list_for_each (tmp, &plp->plp_txq) {
                tx = list_entry(tmp, ptllnd_tx_t, tx_list);
                
                ptllnd_debug_tx(tx);
        }

        CDEBUG(D_WARNING, "activeq:\n");
        list_for_each (tmp, &plp->plp_activeq) {
                tx = list_entry(tmp, ptllnd_tx_t, tx_list);
                
                ptllnd_debug_tx(tx);
        }

        CDEBUG(D_WARNING, "zombies:\n");
        list_for_each (tmp, &plni->plni_zombie_txs) {
                tx = list_entry(tmp, ptllnd_tx_t, tx_list);
                
                if (tx->tx_peer->plp_id.nid == id.nid &&
                    tx->tx_peer->plp_id.pid == id.pid)
                        ptllnd_debug_tx(tx);
        }
        
        CDEBUG(D_WARNING, "history:\n");
        list_for_each (tmp, &plni->plni_tx_history) {
                tx = list_entry(tmp, ptllnd_tx_t, tx_list);
                
                if (tx->tx_peer->plp_id.nid == id.nid &&
                    tx->tx_peer->plp_id.pid == id.pid)
                        ptllnd_debug_tx(tx);
        }
        
        ptllnd_peer_decref(plp);
}

void
ptllnd_notify(lnet_ni_t *ni, lnet_nid_t nid, int alive)
{
        lnet_process_id_t  id;
        ptllnd_peer_t     *peer;
        time_t             start = cfs_time_current_sec();
        int                w = PTLLND_WARN_LONG_WAIT;
        
        /* This is only actually used to connect to routers at startup! */
        if (!alive) {
                LBUG();
                return;
        }

        id.nid = nid;
        id.pid = LUSTRE_SRV_LNET_PID;
        
        peer = ptllnd_find_peer(ni, id, 1);
        if (peer == NULL)
                return;

        /* wait for the peer to reply */
        while (!peer->plp_recvd_hello) {
                if (cfs_time_current_sec() > start + w) {
                        CWARN("Waited %ds to connect to %s\n",
                              w, libcfs_id2str(id));
                        w *= 2;
                }
                
                ptllnd_wait(ni, w*1000);
        }
        
        ptllnd_peer_decref(peer);
}

__u32
ptllnd_cksum (void *ptr, int nob)
{
        char  *c  = ptr;
        __u32  sum = 0;

        while (nob-- > 0)
                sum = ((sum << 1) | (sum >> 31)) + *c++;

        /* ensure I don't return 0 (== no checksum) */
        return (sum == 0) ? 1 : sum;
}

ptllnd_tx_t *
ptllnd_new_tx(ptllnd_peer_t *peer, int type, int payload_nob)
{
        lnet_ni_t   *ni = peer->plp_ni;
        ptllnd_ni_t *plni = ni->ni_data;
        ptllnd_tx_t *tx;
        int          msgsize;

        CDEBUG(D_NET, "peer=%p type=%d payload=%d\n",peer,type,payload_nob);

        switch (type) {
        default:
                LBUG();

        case PTLLND_RDMA_WRITE:
        case PTLLND_RDMA_READ:
                LASSERT (payload_nob == 0);
                msgsize = 0;
                break;

        case PTLLND_MSG_TYPE_PUT:
        case PTLLND_MSG_TYPE_GET:
                LASSERT (payload_nob == 0);
                msgsize = offsetof(kptl_msg_t, ptlm_u) + 
                          sizeof(kptl_rdma_msg_t);
                break;

        case PTLLND_MSG_TYPE_IMMEDIATE:
                msgsize = offsetof(kptl_msg_t,
                                   ptlm_u.immediate.kptlim_payload[payload_nob]);
                break;

        case PTLLND_MSG_TYPE_NOOP:
                LASSERT (payload_nob == 0);
                msgsize = offsetof(kptl_msg_t, ptlm_u);
                break;

        case PTLLND_MSG_TYPE_HELLO:
                LASSERT (payload_nob == 0);
                msgsize = offsetof(kptl_msg_t, ptlm_u) +
                          sizeof(kptl_hello_msg_t);
                break;
        }

        msgsize = (msgsize + 7) & ~7;
        LASSERT (msgsize <= peer->plp_max_msg_size);

        CDEBUG(D_NET, "msgsize=%d\n",msgsize);

        LIBCFS_ALLOC(tx, offsetof(ptllnd_tx_t, tx_msg) + msgsize);

        if (tx == NULL) {
                CERROR("Can't allocate msg type %d for %s\n",
                       type, libcfs_id2str(peer->plp_id));
                return NULL;
        }

        CFS_INIT_LIST_HEAD(&tx->tx_list);
        tx->tx_peer = peer;
        tx->tx_type = type;
        tx->tx_lnetmsg = tx->tx_lnetreplymsg = NULL;
        tx->tx_niov = 0;
        tx->tx_iov = NULL;
        tx->tx_reqmdh = PTL_INVALID_HANDLE;
        tx->tx_bulkmdh = PTL_INVALID_HANDLE;
        tx->tx_msgsize = msgsize;
        tx->tx_completing = 0;
        tx->tx_status = 0;

        PTLLND_DBGT_INIT(tx->tx_bulk_posted);
        PTLLND_DBGT_INIT(tx->tx_bulk_done);
        PTLLND_DBGT_INIT(tx->tx_req_posted);
        PTLLND_DBGT_INIT(tx->tx_req_done);

        if (msgsize != 0) {
                tx->tx_msg.ptlm_magic = PTLLND_MSG_MAGIC;
                tx->tx_msg.ptlm_version = PTLLND_MSG_VERSION;
                tx->tx_msg.ptlm_type = type;
                tx->tx_msg.ptlm_credits = 0;
                tx->tx_msg.ptlm_nob = msgsize;
                tx->tx_msg.ptlm_cksum = 0;
                tx->tx_msg.ptlm_srcnid = ni->ni_nid;
                tx->tx_msg.ptlm_srcstamp = plni->plni_stamp;
                tx->tx_msg.ptlm_dstnid = peer->plp_id.nid;
                tx->tx_msg.ptlm_dststamp = peer->plp_stamp;
                tx->tx_msg.ptlm_srcpid = the_lnet.ln_pid;
                tx->tx_msg.ptlm_dstpid = peer->plp_id.pid;
        }

        ptllnd_peer_addref(peer);
        plni->plni_ntxs++;

        CDEBUG(D_NET, "tx=%p\n",tx);

        return tx;
}

void
ptllnd_abort_tx(ptllnd_tx_t *tx, ptl_handle_md_t *mdh)
{
        ptllnd_peer_t   *peer = tx->tx_peer;
        lnet_ni_t       *ni = peer->plp_ni;
        int              rc;
        time_t           start = cfs_time_current_sec();
        int              w = PTLLND_WARN_LONG_WAIT;

        while (!PtlHandleIsEqual(*mdh, PTL_INVALID_HANDLE)) {
                rc = PtlMDUnlink(*mdh);
#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                if (rc == PTL_OK) /* unlink successful => no unlinked event */
                        return;
                LASSERT (rc == PTL_MD_IN_USE);
#endif
                if (cfs_time_current_sec() > start + w) {
                        CWARN("Waited %ds to abort tx to %s\n",
                              w, libcfs_id2str(peer->plp_id));
                        w *= 2;
                }
                /* Wait for ptllnd_tx_event() to invalidate */
                ptllnd_wait(ni, w*1000);
        }
}

void
ptllnd_cull_tx_history(ptllnd_ni_t *plni)
{
        int max = plni->plni_max_tx_history;

        while (plni->plni_ntx_history > max) {
                ptllnd_tx_t *tx = list_entry(plni->plni_tx_history.next, 
                                             ptllnd_tx_t, tx_list);
                list_del(&tx->tx_list);

                ptllnd_peer_decref(tx->tx_peer);

                LIBCFS_FREE(tx, offsetof(ptllnd_tx_t, tx_msg) + tx->tx_msgsize);

                LASSERT (plni->plni_ntxs > 0);
                plni->plni_ntxs--;
                plni->plni_ntx_history--;
        }
}

void
ptllnd_tx_done(ptllnd_tx_t *tx)
{
        ptllnd_peer_t   *peer = tx->tx_peer;
        lnet_ni_t       *ni = peer->plp_ni;
        ptllnd_ni_t     *plni = ni->ni_data;

        /* CAVEAT EMPTOR: If this tx is being aborted, I'll continue to get
         * events for this tx until it's unlinked.  So I set tx_completing to
         * flag the tx is getting handled */

        if (tx->tx_completing)
                return;

        tx->tx_completing = 1;

        if (!list_empty(&tx->tx_list))
                list_del_init(&tx->tx_list);

        if (tx->tx_status != 0) {
                CERROR("Completing tx with error\n");
                ptllnd_debug_tx(tx);
                ptllnd_close_peer(peer, tx->tx_status);
        }
        
        ptllnd_abort_tx(tx, &tx->tx_reqmdh);
        ptllnd_abort_tx(tx, &tx->tx_bulkmdh);

        if (tx->tx_niov > 0) {
                LIBCFS_FREE(tx->tx_iov, tx->tx_niov * sizeof(*tx->tx_iov));
                tx->tx_niov = 0;
        }

        if (tx->tx_lnetreplymsg != NULL) {
                LASSERT (tx->tx_type == PTLLND_MSG_TYPE_GET);
                LASSERT (tx->tx_lnetmsg != NULL);
                /* Simulate GET success always  */
                lnet_finalize(ni, tx->tx_lnetmsg, 0);
                CDEBUG(D_NET, "lnet_finalize(tx_lnetreplymsg=%p)\n",tx->tx_lnetreplymsg);
                lnet_finalize(ni, tx->tx_lnetreplymsg, tx->tx_status);
        } else if (tx->tx_lnetmsg != NULL) {
                lnet_finalize(ni, tx->tx_lnetmsg, tx->tx_status);
        }

        plni->plni_ntx_history++;
        list_add_tail(&tx->tx_list, &plni->plni_tx_history);
        
        ptllnd_cull_tx_history(plni);
}

int
ptllnd_set_txiov(ptllnd_tx_t *tx,
                 unsigned int niov, struct iovec *iov,
                 unsigned int offset, unsigned int len)
{
        ptl_md_iovec_t *piov;
        int             npiov;

        if (len == 0) {
                tx->tx_niov = 0;
                return 0;
        }

        CDEBUG(D_NET, "niov  =%d\n",niov);
        CDEBUG(D_NET, "offset=%d\n",offset);
        CDEBUG(D_NET, "len   =%d\n",len);


        /*
         * Remove iovec's at the beginning that
         * are skipped because of the offset.
         * Adjust the offset accordingly
         */
        for (;;) {
                LASSERT (niov > 0);
                if (offset < iov->iov_len)
                        break;
                offset -= iov->iov_len;
                niov--;
                iov++;
        }

        CDEBUG(D_NET, "niov  =%d (after)\n",niov);
        CDEBUG(D_NET, "offset=%d (after)\n",offset);
        CDEBUG(D_NET, "len   =%d (after)\n",len);

        for (;;) {
                int temp_offset = offset;
                int resid = len;
                LIBCFS_ALLOC(piov, niov * sizeof(*piov));
                if (piov == NULL)
                        return -ENOMEM;

                for (npiov = 0;; npiov++) {
                        CDEBUG(D_NET, "npiov=%d\n",npiov);
                        CDEBUG(D_NET, "offset=%d\n",temp_offset);
                        CDEBUG(D_NET, "len=%d\n",resid);
                        CDEBUG(D_NET, "iov[npiov].iov_len=%d\n",iov[npiov].iov_len);

                        LASSERT (npiov < niov);
                        LASSERT (iov->iov_len >= temp_offset);

                        piov[npiov].iov_base = iov[npiov].iov_base + temp_offset;
                        piov[npiov].iov_len = iov[npiov].iov_len - temp_offset;
                        
                        if (piov[npiov].iov_len >= resid) {
                                piov[npiov].iov_len = resid;
                                npiov++;
                                break;
                        }
                        resid -= piov[npiov].iov_len;
                        temp_offset = 0;
                }

                if (npiov == niov) {
                        tx->tx_niov = niov;
                        tx->tx_iov = piov;
                        CDEBUG(D_NET, "tx->tx_iov=%p\n",tx->tx_iov);
                        CDEBUG(D_NET, "tx->tx_niov=%d\n",tx->tx_niov);
                        return 0;
                }

                /* Dang! The piov I allocated was too big and it's a drag to
                 * have to maintain separate 'allocated' and 'used' sizes, so
                 * I'll just do it again; NB this doesn't happen normally... */
                LIBCFS_FREE(piov, niov * sizeof(*piov));
                niov = npiov;
        }
}

void
ptllnd_set_md_buffer(ptl_md_t *md, ptllnd_tx_t *tx)
{
        unsigned int    niov = tx->tx_niov;
        ptl_md_iovec_t *iov = tx->tx_iov;

        LASSERT ((md->options & PTL_MD_IOVEC) == 0);

        if (niov == 0) {
                md->start = NULL;
                md->length = 0;
        } else if (niov == 1) {
                md->start = iov[0].iov_base;
                md->length = iov[0].iov_len;
        } else {
                md->start = iov;
                md->length = niov;
                md->options |= PTL_MD_IOVEC;
        }
}

int
ptllnd_post_buffer(ptllnd_buffer_t *buf)
{
        lnet_ni_t        *ni = buf->plb_ni;
        ptllnd_ni_t      *plni = ni->ni_data;
        ptl_process_id_t  anyid = {
                .nid       = PTL_NID_ANY,
                .pid       = PTL_PID_ANY};
        ptl_md_t          md = {
                .start     = buf->plb_buffer,
                .length    = plni->plni_buffer_size,
                .threshold = PTL_MD_THRESH_INF,
                .max_size  = plni->plni_max_msg_size,
                .options   = (PTLLND_MD_OPTIONS |
                              PTL_MD_OP_PUT | PTL_MD_MAX_SIZE | 
                              PTL_MD_LOCAL_ALIGN8),
                .user_ptr  = ptllnd_obj2eventarg(buf, PTLLND_EVENTARG_TYPE_BUF),
                .eq_handle = plni->plni_eqh};
        ptl_handle_me_t meh;
        int             rc;

        LASSERT (!buf->plb_posted);

        rc = PtlMEAttach(plni->plni_nih, plni->plni_portal,
                         anyid, LNET_MSG_MATCHBITS, 0,
                         PTL_UNLINK, PTL_INS_AFTER, &meh);
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                return -ENOMEM;
        }

        buf->plb_posted = 1;
        plni->plni_nposted_buffers++;

        rc = PtlMDAttach(meh, md, LNET_UNLINK, &buf->plb_md);
        if (rc == PTL_OK)
                return 0;

        CERROR("PtlMDAttach failed: %d\n", rc);

        buf->plb_posted = 0;
        plni->plni_nposted_buffers--;

        rc = PtlMEUnlink(meh);
        LASSERT (rc == PTL_OK);

        return -ENOMEM;
}

void
ptllnd_check_sends(ptllnd_peer_t *peer)
{
        lnet_ni_t      *ni = peer->plp_ni;
        ptllnd_ni_t    *plni = ni->ni_data;
        ptllnd_tx_t    *tx;
        ptl_md_t        md;
        ptl_handle_md_t mdh;
        int             rc;

        CDEBUG(D_NET, "plp_outstanding_credits=%d\n",peer->plp_outstanding_credits);

        if (list_empty(&peer->plp_txq) &&
            peer->plp_outstanding_credits >=
            PTLLND_CREDIT_HIGHWATER(plni)) {

                tx = ptllnd_new_tx(peer, PTLLND_MSG_TYPE_NOOP, 0);
                CDEBUG(D_NET, "NOOP tx=%p\n",tx);
                if (tx == NULL) {
                        CERROR("Can't return credits to %s\n",
                               libcfs_id2str(peer->plp_id));
                } else {
                        list_add_tail(&tx->tx_list, &peer->plp_txq);
                }
        }

        while (!list_empty(&peer->plp_txq)) {
                tx = list_entry(peer->plp_txq.next, ptllnd_tx_t, tx_list);

                CDEBUG(D_NET, "Looking at TX=%p\n",tx);
                CDEBUG(D_NET, "plp_credits=%d\n",peer->plp_credits);
                CDEBUG(D_NET, "plp_outstanding_credits=%d\n",peer->plp_outstanding_credits);

                LASSERT (tx->tx_msgsize > 0);

                LASSERT (peer->plp_outstanding_credits >= 0);
                LASSERT (peer->plp_outstanding_credits <=
                         plni->plni_peer_credits);
                LASSERT (peer->plp_credits >= 0);
                LASSERT (peer->plp_credits <= peer->plp_max_credits);

                if (peer->plp_credits == 0)     /* no credits */
                        break;

                if (peer->plp_credits == 1 &&   /* last credit reserved for */
                    peer->plp_outstanding_credits == 0) /* returning credits */
                        break;

                list_del(&tx->tx_list);
                list_add_tail(&tx->tx_list, &peer->plp_activeq);

                CDEBUG(D_NET, "Sending at TX=%p type=%s (%d)\n",tx,
                        ptllnd_msgtype2str(tx->tx_type),tx->tx_type);

                if (tx->tx_type == PTLLND_MSG_TYPE_NOOP &&
                    (!list_empty(&peer->plp_txq) ||
                     peer->plp_outstanding_credits <
                     PTLLND_CREDIT_HIGHWATER(plni))) {
                        /* redundant NOOP */
                        ptllnd_tx_done(tx);
                        continue;
                }

                /* Set stamp at the last minute; on a new peer, I don't know it
                 * until I receive the HELLO back */
                tx->tx_msg.ptlm_dststamp = peer->plp_stamp;

                CDEBUG(D_NET, "Returning %d to peer\n",peer->plp_outstanding_credits);

                /*
                 * Return all the credits we have
                 */
                tx->tx_msg.ptlm_credits = peer->plp_outstanding_credits;
                peer->plp_outstanding_credits = 0;

                /*
                 * One less credit
                 */
                peer->plp_credits--;

                if (plni->plni_checksum)
                        tx->tx_msg.ptlm_cksum = 
                                ptllnd_cksum(&tx->tx_msg,
                                             offsetof(kptl_msg_t, ptlm_u));

                md.user_ptr = ptllnd_obj2eventarg(tx, PTLLND_EVENTARG_TYPE_TX);
                md.eq_handle = plni->plni_eqh;
                md.threshold = 1;
                md.options = PTLLND_MD_OPTIONS;
                md.start = &tx->tx_msg;
                md.length = tx->tx_msgsize;

                rc = PtlMDBind(plni->plni_nih, md, LNET_UNLINK, &mdh);
                if (rc != PTL_OK) {
                        CERROR("PtlMDBind for %s failed: %d\n",
                               libcfs_id2str(peer->plp_id), rc);
                        tx->tx_status = -EIO;
                        ptllnd_tx_done(tx);
                        break;
                }

                tx->tx_reqmdh = mdh;
                PTLLND_DBGT_STAMP(tx->tx_req_posted);

                rc = PtlPut(mdh, PTL_NOACK_REQ, peer->plp_ptlid,
                            plni->plni_portal, 0, LNET_MSG_MATCHBITS, 0, 0);
                if (rc != PTL_OK) {
                        CERROR("PtlPut for %s failed: %d\n",
                               libcfs_id2str(peer->plp_id), rc);
                        tx->tx_status = -EIO;
                        ptllnd_tx_done(tx);
                        break;
                }
        }
}

int
ptllnd_passive_rdma(ptllnd_peer_t *peer, int type, lnet_msg_t *msg,
                    unsigned int niov, struct iovec *iov,
                    unsigned int offset, unsigned int len)
{
        lnet_ni_t      *ni = peer->plp_ni;
        ptllnd_ni_t    *plni = ni->ni_data;
        ptllnd_tx_t    *tx = ptllnd_new_tx(peer, type, 0);
        __u64           matchbits;
        ptl_md_t        md;
        ptl_handle_md_t mdh;
        ptl_handle_me_t meh;
        int             rc;
        int             rc2;
        time_t          start;
        int             w;

        CDEBUG(D_NET, "niov=%d offset=%d len=%d\n",niov,offset,len);

        LASSERT (type == PTLLND_MSG_TYPE_GET ||
                 type == PTLLND_MSG_TYPE_PUT);

        if (tx == NULL) {
                CERROR("Can't allocate %s tx for %s\n",
                       type == PTLLND_MSG_TYPE_GET ? "GET" : "PUT/REPLY",
                       libcfs_id2str(peer->plp_id));
                return -ENOMEM;
        }

        rc = ptllnd_set_txiov(tx, niov, iov, offset, len);
        if (rc != 0) {
                CERROR ("Can't allocate iov %d for %s\n",
                        niov, libcfs_id2str(peer->plp_id));
                rc = -ENOMEM;
                goto failed;
        }

        md.user_ptr = ptllnd_obj2eventarg(tx, PTLLND_EVENTARG_TYPE_TX);
        md.eq_handle = plni->plni_eqh;
        md.threshold = 1;
        md.max_size = 0;
        md.options = PTLLND_MD_OPTIONS;
        if(type == PTLLND_MSG_TYPE_GET)
                md.options |= PTL_MD_OP_PUT | PTL_MD_ACK_DISABLE;
        else
                md.options |= PTL_MD_OP_GET;
        ptllnd_set_md_buffer(&md, tx);

        start = cfs_time_current_sec();
        w = PTLLND_WARN_LONG_WAIT;

        while (!peer->plp_recvd_hello) {        /* wait to validate plp_match */
                if (peer->plp_closing) {
                        rc = -EIO;
                        goto failed;
                }
                if (cfs_time_current_sec() > start + w) {
                        CWARN("Waited %ds to connect to %s\n",
                              w, libcfs_id2str(peer->plp_id));
                        w *= 2;
                }
                ptllnd_wait(ni, w*1000);
        }

        if (peer->plp_match < PTL_RESERVED_MATCHBITS)
                peer->plp_match = PTL_RESERVED_MATCHBITS;
        matchbits = peer->plp_match++;
        CDEBUG(D_NET, "matchbits " LPX64 " %s\n", matchbits,
               ptllnd_ptlid2str(peer->plp_ptlid));

        rc = PtlMEAttach(plni->plni_nih, plni->plni_portal, peer->plp_ptlid,
                         matchbits, 0, PTL_UNLINK, PTL_INS_BEFORE, &meh);
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach for %s failed: %d\n",
                       libcfs_id2str(peer->plp_id), rc);
                rc = -EIO;
                goto failed;
        }

        CDEBUG(D_NET, "md.start=%p\n",md.start);
        CDEBUG(D_NET, "md.length=%d\n",md.length);
        CDEBUG(D_NET, "md.threshold=%d\n",md.threshold);
        CDEBUG(D_NET, "md.max_size=%d\n",md.max_size);
        CDEBUG(D_NET, "md.options=0x%x\n",md.options);
        CDEBUG(D_NET, "md.user_ptr=%p\n",md.user_ptr);

        PTLLND_DBGT_STAMP(tx->tx_bulk_posted);

        rc = PtlMDAttach(meh, md, LNET_UNLINK, &mdh);
        if (rc != PTL_OK) {
                CERROR("PtlMDAttach for %s failed: %d\n",
                       libcfs_id2str(peer->plp_id), rc);
                rc2 = PtlMEUnlink(meh);
                LASSERT (rc2 == PTL_OK);
                rc = -EIO;
                goto failed;
        }
        tx->tx_bulkmdh = mdh;

        /*
         * We need to set the stamp here because it
         * we could have received a HELLO above that set
         * peer->plp_stamp
         */
        tx->tx_msg.ptlm_dststamp = peer->plp_stamp;

        tx->tx_msg.ptlm_u.rdma.kptlrm_hdr = msg->msg_hdr;
        tx->tx_msg.ptlm_u.rdma.kptlrm_matchbits = matchbits;

        if (type == PTLLND_MSG_TYPE_GET) {
                tx->tx_lnetreplymsg = lnet_create_reply_msg(ni, msg);
                if (tx->tx_lnetreplymsg == NULL) {
                        CERROR("Can't create reply for GET to %s\n",
                               libcfs_id2str(msg->msg_target));
                        rc = -ENOMEM;
                        goto failed;
                }
        }

        tx->tx_lnetmsg = msg;
        ptllnd_post_tx(tx);
        return 0;

 failed:
        ptllnd_tx_done(tx);
        return rc;
}

int
ptllnd_active_rdma(ptllnd_peer_t *peer, int type,
                   lnet_msg_t *msg, __u64 matchbits,
                   unsigned int niov, struct iovec *iov,
                   unsigned int offset, unsigned int len)
{
        lnet_ni_t       *ni = peer->plp_ni;
        ptllnd_ni_t     *plni = ni->ni_data;
        ptllnd_tx_t     *tx = ptllnd_new_tx(peer, type, 0);
        ptl_md_t         md;
        ptl_handle_md_t  mdh;
        int              rc;

        LASSERT (type == PTLLND_RDMA_READ ||
                 type == PTLLND_RDMA_WRITE);

        if (tx == NULL) {
                CERROR("Can't allocate tx for RDMA %s with %s\n",
                       (type == PTLLND_RDMA_WRITE) ? "write" : "read",
                       libcfs_id2str(peer->plp_id));
                ptllnd_close_peer(peer, -ENOMEM);
                return -ENOMEM;
        }

        rc = ptllnd_set_txiov(tx, niov, iov, offset, len);
        if (rc != 0) {
                CERROR ("Can't allocate iov %d for %s\n",
                        niov, libcfs_id2str(peer->plp_id));
                rc = -ENOMEM;
                goto failed;
        }

        md.user_ptr = ptllnd_obj2eventarg(tx, PTLLND_EVENTARG_TYPE_TX);
        md.eq_handle = plni->plni_eqh;
        md.max_size = 0;
        md.options = PTLLND_MD_OPTIONS;
        md.threshold = (type == PTLLND_RDMA_READ) ? 2 : 1;

        ptllnd_set_md_buffer(&md, tx);

        rc = PtlMDBind(plni->plni_nih, md, LNET_UNLINK, &mdh);
        if (rc != PTL_OK) {
                CERROR("PtlMDBind for %s failed: %d\n",
                       libcfs_id2str(peer->plp_id), rc);
                rc = -EIO;
                goto failed;
        }

        tx->tx_bulkmdh = mdh;
        tx->tx_lnetmsg = msg;

        list_add_tail(&tx->tx_list, &peer->plp_activeq);
        PTLLND_DBGT_STAMP(tx->tx_bulk_posted);

        if (type == PTLLND_RDMA_READ)
                rc = PtlGet(mdh, peer->plp_ptlid,
                            plni->plni_portal, 0, matchbits, 0);
        else
                rc = PtlPut(mdh, PTL_NOACK_REQ, peer->plp_ptlid,
                            plni->plni_portal, 0, matchbits, 0, 
                            (msg == NULL) ? PTLLND_RDMA_FAIL : PTLLND_RDMA_OK);

        if (rc == PTL_OK)
                return 0;

        CERROR("Can't initiate RDMA with %s: %d\n",
               libcfs_id2str(peer->plp_id), rc);

        tx->tx_lnetmsg = NULL;
 failed:
        tx->tx_status = rc;
        ptllnd_tx_done(tx);    /* this will close peer */
        return rc;
}

int
ptllnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *msg)
{
        ptllnd_ni_t    *plni = ni->ni_data;
        ptllnd_peer_t  *plp;
        ptllnd_tx_t    *tx;
        int             nob;
        int             rc;

        LASSERT (!msg->msg_routing);
        LASSERT (msg->msg_kiov == NULL);

        LASSERT (msg->msg_niov <= PTL_MD_MAX_IOV); /* !!! */

        CDEBUG(D_NET, "%s [%d]+%d,%d -> %s%s\n", 
               lnet_msgtyp2str(msg->msg_type),
               msg->msg_niov, msg->msg_offset, msg->msg_len,
               libcfs_nid2str(msg->msg_target.nid),
               msg->msg_target_is_router ? "(rtr)" : "");

        if ((msg->msg_target.pid & LNET_PID_USERFLAG) != 0) {
                CERROR("Can't send to non-kernel peer %s\n",
                       libcfs_id2str(msg->msg_target));
                return -EHOSTUNREACH;
        }
        
        plp = ptllnd_find_peer(ni, msg->msg_target, 1);
        if (plp == NULL)
                return -ENOMEM;

        switch (msg->msg_type) {
        default:
                LBUG();

        case LNET_MSG_ACK:
                CDEBUG(D_NET, "LNET_MSG_ACK\n");

                LASSERT (msg->msg_len == 0);
                break;                          /* send IMMEDIATE */

        case LNET_MSG_GET:
                CDEBUG(D_NET, "LNET_MSG_GET nob=%d\n",msg->msg_md->md_length);

                if (msg->msg_target_is_router)
                        break;                  /* send IMMEDIATE */

                nob = msg->msg_md->md_length;
                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[nob]);
                if (nob <= plni->plni_max_msg_size)
                        break;

                LASSERT ((msg->msg_md->md_options & LNET_MD_KIOV) == 0);
                rc = ptllnd_passive_rdma(plp, PTLLND_MSG_TYPE_GET, msg,
                                         msg->msg_md->md_niov,
                                         msg->msg_md->md_iov.iov,
                                         0, msg->msg_md->md_length);
                ptllnd_peer_decref(plp);
                return rc;

        case LNET_MSG_REPLY:
        case LNET_MSG_PUT:
                CDEBUG(D_NET, "LNET_MSG_PUT nob=%d\n",msg->msg_len);
                nob = msg->msg_len;
                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[nob]);
                CDEBUG(D_NET, "msg_size=%d max=%d\n",msg->msg_len,plp->plp_max_msg_size);
                if (nob <= plp->plp_max_msg_size)
                        break;                  /* send IMMEDIATE */

                rc = ptllnd_passive_rdma(plp, PTLLND_MSG_TYPE_PUT, msg,
                                         msg->msg_niov, msg->msg_iov,
                                         msg->msg_offset, msg->msg_len);
                ptllnd_peer_decref(plp);
                return rc;
        }

        /* send IMMEDIATE
         * NB copy the payload so we don't have to do a fragmented send */

        CDEBUG(D_NET, "IMMEDIATE len=%d\n", msg->msg_len);
        tx = ptllnd_new_tx(plp, PTLLND_MSG_TYPE_IMMEDIATE, msg->msg_len);
        if (tx == NULL) {
                CERROR("Can't allocate tx for lnet type %d to %s\n",
                       msg->msg_type, libcfs_id2str(msg->msg_target));
                ptllnd_peer_decref(plp);
                return -ENOMEM;
        }

        lnet_copy_iov2flat(tx->tx_msgsize, &tx->tx_msg,
                           offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload),
                           msg->msg_niov, msg->msg_iov, msg->msg_offset,
                           msg->msg_len);
        tx->tx_msg.ptlm_u.immediate.kptlim_hdr = msg->msg_hdr;

        tx->tx_lnetmsg = msg;
        ptllnd_post_tx(tx);
        ptllnd_peer_decref(plp);
        return 0;
}

void
ptllnd_rx_done(ptllnd_rx_t *rx)
{
        ptllnd_peer_t *plp = rx->rx_peer;
        lnet_ni_t     *ni = plp->plp_ni;
        ptllnd_ni_t   *plni = ni->ni_data;

        CDEBUG(D_NET, "rx=%p\n", rx);

        plp->plp_outstanding_credits++;
        ptllnd_check_sends(rx->rx_peer);

        LASSERT (plni->plni_nrxs > 0);
        plni->plni_nrxs--;
}

int
ptllnd_eager_recv(lnet_ni_t *ni, void *private, lnet_msg_t *msg,
                  void **new_privatep)
{
        /* Shouldn't get here; recvs only block for router buffers */
        LBUG();
        return 0;
}

int
ptllnd_recv(lnet_ni_t *ni, void *private, lnet_msg_t *msg,
            int delayed, unsigned int niov,
            struct iovec *iov, lnet_kiov_t *kiov,
            unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        ptllnd_rx_t    *rx = private;
        int             rc = 0;
        int             nob;

        LASSERT (kiov == NULL);
        LASSERT (niov <= PTL_MD_MAX_IOV);       /* !!! */

        switch (rx->rx_msg->ptlm_type) {
        default:
                LBUG();

        case PTLLND_MSG_TYPE_IMMEDIATE:
                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[mlen]);
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_IMMEDIATE nob=%d\n",nob);
                if (nob > rx->rx_nob) {
                        CERROR("Immediate message from %s too big: %d(%d)\n",
                               libcfs_id2str(rx->rx_peer->plp_id),
                               nob, rx->rx_nob);
                        rc = -EPROTO;
                        break;
                }
                lnet_copy_flat2iov(niov, iov, offset,
                                   rx->rx_nob, rx->rx_msg,
                                   offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload),
                                   mlen);
                lnet_finalize(ni, msg, 0);
                break;

        case PTLLND_MSG_TYPE_PUT:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_PUT offset=%d mlen=%d\n",offset,mlen);
                rc = ptllnd_active_rdma(rx->rx_peer, PTLLND_RDMA_READ, msg,
                                        rx->rx_msg->ptlm_u.rdma.kptlrm_matchbits,
                                        niov, iov, offset, mlen);
                break;

        case PTLLND_MSG_TYPE_GET:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_GET\n");
                if (msg != NULL)
                        rc = ptllnd_active_rdma(rx->rx_peer, PTLLND_RDMA_WRITE, msg,
                                                rx->rx_msg->ptlm_u.rdma.kptlrm_matchbits,
                                                msg->msg_niov, msg->msg_iov,
                                                msg->msg_offset, msg->msg_len);
                else
                        rc = ptllnd_active_rdma(rx->rx_peer, PTLLND_RDMA_WRITE, NULL,
                                                rx->rx_msg->ptlm_u.rdma.kptlrm_matchbits,
                                                0, NULL, 0, 0);
                break;
        }

        ptllnd_rx_done(rx);
        return rc;
}

void
ptllnd_abort_on_nak(lnet_ni_t *ni)
{
        ptllnd_ni_t      *plni = ni->ni_data;

        if (plni->plni_abort_on_nak)
                abort();
}

void
ptllnd_parse_request(lnet_ni_t *ni, ptl_process_id_t initiator,
                     kptl_msg_t *msg, unsigned int nob)
{
        ptllnd_ni_t      *plni = ni->ni_data;
        const int         basenob = offsetof(kptl_msg_t, ptlm_u);
        lnet_process_id_t srcid;
        ptllnd_rx_t       rx;
        int               flip;
        __u16             msg_version;
        __u32             msg_cksum;
        ptllnd_peer_t    *plp;
        int               rc;

        if (nob < 6) {
                CERROR("Very short receive from %s\n",
                       ptllnd_ptlid2str(initiator));
                return;
        }

        /* I can at least read MAGIC/VERSION */

        flip = msg->ptlm_magic == __swab32(PTLLND_MSG_MAGIC);
        if (!flip && msg->ptlm_magic != PTLLND_MSG_MAGIC) {
                CERROR("Bad protocol magic %08x from %s\n", 
                       msg->ptlm_magic, ptllnd_ptlid2str(initiator));
                return;
        }

        msg_version = flip ? __swab16(msg->ptlm_version) : msg->ptlm_version;

        if (msg_version != PTLLND_MSG_VERSION) {
                CERROR("Bad protocol version %04x from %s\n", 
                       (__u32)msg_version, ptllnd_ptlid2str(initiator));
                ptllnd_abort_on_nak(ni);
                return;
        }

        if (nob < basenob) {
                CERROR("Short receive from %s: got %d, wanted at least %d\n",
                       ptllnd_ptlid2str(initiator), nob, basenob);
                return;
        }

        /* checksum must be computed with
         * 1) ptlm_cksum zero and
         * 2) BEFORE anything gets modified/flipped
         */
        msg_cksum = flip ? __swab32(msg->ptlm_cksum) : msg->ptlm_cksum;
        msg->ptlm_cksum = 0;
        if (msg_cksum != 0 &&
            msg_cksum != ptllnd_cksum(msg, offsetof(kptl_msg_t, ptlm_u))) {
                CERROR("Bad checksum from %s\n", ptllnd_ptlid2str(initiator));
                return;
        }

        msg->ptlm_version = msg_version;
        msg->ptlm_cksum = msg_cksum;
        
        if (flip) {
                /* NB stamps are opaque cookies */
                __swab32s(&msg->ptlm_nob);
                __swab64s(&msg->ptlm_srcnid);
                __swab64s(&msg->ptlm_dstnid);
                __swab32s(&msg->ptlm_srcpid);
                __swab32s(&msg->ptlm_dstpid);
        }
        
        srcid.nid = msg->ptlm_srcnid;
        srcid.pid = msg->ptlm_srcpid;

        if (LNET_NIDNET(msg->ptlm_srcnid) != LNET_NIDNET(ni->ni_nid)) {
                CERROR("Bad source id %s from %s\n",
                       libcfs_id2str(srcid),
                       ptllnd_ptlid2str(initiator));
                return;
        }

        if (msg->ptlm_type == PTLLND_MSG_TYPE_NAK) {
                CERROR("NAK from %s (%s)\n", 
                       libcfs_id2str(srcid),
                       ptllnd_ptlid2str(initiator));
                ptllnd_abort_on_nak(ni);
                return;
        }
        
        if (msg->ptlm_dstnid != ni->ni_nid ||
            msg->ptlm_dstpid != the_lnet.ln_pid) {
                CERROR("Bad dstid %s (%s expected) from %s\n",
                       libcfs_id2str((lnet_process_id_t) {
                               .nid = msg->ptlm_dstnid,
                               .pid = msg->ptlm_dstpid}),
                       libcfs_id2str((lnet_process_id_t) {
                               .nid = ni->ni_nid,
                               .pid = the_lnet.ln_pid}),
                       libcfs_id2str(srcid));
                return;
        }

        if (msg->ptlm_dststamp != plni->plni_stamp) {
                CERROR("Bad dststamp "LPX64"("LPX64" expected) from %s\n",
                       msg->ptlm_dststamp, plni->plni_stamp,
                       libcfs_id2str(srcid));
                return;
        }
       
        switch (msg->ptlm_type) {
        case PTLLND_MSG_TYPE_PUT:
        case PTLLND_MSG_TYPE_GET:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_%s\n",
                        msg->ptlm_type==PTLLND_MSG_TYPE_PUT ? "PUT" : "GET");
                if (nob < basenob + sizeof(kptl_rdma_msg_t)) {
                        CERROR("Short rdma request from %s(%s)\n",
                               libcfs_id2str(srcid),
                               ptllnd_ptlid2str(initiator));
                        return;
                }
                if (flip)
                        __swab64s(&msg->ptlm_u.rdma.kptlrm_matchbits);
                break;

        case PTLLND_MSG_TYPE_IMMEDIATE:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_IMMEDIATE\n");
                if (nob < offsetof(kptl_msg_t,
                                   ptlm_u.immediate.kptlim_payload)) {
                        CERROR("Short immediate from %s(%s)\n",
                               libcfs_id2str(srcid),
                               ptllnd_ptlid2str(initiator));
                        return;
                }
                break;

        case PTLLND_MSG_TYPE_HELLO:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_HELLO from %s(%s)\n",
                               libcfs_id2str(srcid),
                               ptllnd_ptlid2str(initiator));
                if (nob < basenob + sizeof(kptl_hello_msg_t)) {
                        CERROR("Short hello from %s(%s)\n",
                               libcfs_id2str(srcid),
                               ptllnd_ptlid2str(initiator));
                        return;
                }
                if(flip){
                        __swab64s(&msg->ptlm_u.hello.kptlhm_matchbits);
                        __swab32s(&msg->ptlm_u.hello.kptlhm_max_msg_size);
                }
                break;
                
        case PTLLND_MSG_TYPE_NOOP:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_NOOP from %s(%s)\n",
                               libcfs_id2str(srcid),
                               ptllnd_ptlid2str(initiator));        
                break;

        default:
                CERROR("Bad message type %d from %s(%s)\n", msg->ptlm_type,
                       libcfs_id2str(srcid),
                       ptllnd_ptlid2str(initiator));
                return;
        }

        plp = ptllnd_find_peer(ni, srcid,
                               msg->ptlm_type == PTLLND_MSG_TYPE_HELLO);
        if (plp == NULL) {
                CERROR("Can't find peer %s\n", libcfs_id2str(srcid));
                return;
        }

        if (msg->ptlm_type == PTLLND_MSG_TYPE_HELLO) {
                if (plp->plp_recvd_hello) {
                        CERROR("Unexpected HELLO from %s\n",
                               libcfs_id2str(srcid));
                        ptllnd_peer_decref(plp);
                        return;
                }

                CDEBUG(D_NET, "maxsz %d match "LPX64" stamp "LPX64"\n",
                       msg->ptlm_u.hello.kptlhm_max_msg_size,
                       msg->ptlm_u.hello.kptlhm_matchbits,
                       msg->ptlm_srcstamp);

                plp->plp_max_msg_size = MAX(plni->plni_max_msg_size,
                        msg->ptlm_u.hello.kptlhm_max_msg_size);
                plp->plp_match = msg->ptlm_u.hello.kptlhm_matchbits;
                plp->plp_stamp = msg->ptlm_srcstamp;
                plp->plp_max_credits += msg->ptlm_credits;
                plp->plp_recvd_hello = 1;

                CDEBUG(D_NET, "plp_max_msg_size=%d\n",plp->plp_max_msg_size);

        } else if (!plp->plp_recvd_hello) {

                CERROR("Bad message type %d (HELLO expected) from %s\n",
                       msg->ptlm_type, libcfs_id2str(srcid));
                ptllnd_peer_decref(plp);
                return;

        } else if (msg->ptlm_srcstamp != plp->plp_stamp) {

                CERROR("Bad srcstamp "LPX64"("LPX64" expected) from %s\n",
                       msg->ptlm_srcstamp, plp->plp_stamp,
                       libcfs_id2str(srcid));
                ptllnd_peer_decref(plp);
                return;
        }

        if (msg->ptlm_credits > 0) {
                CDEBUG(D_NET, "Getting back %d credits from peer\n",msg->ptlm_credits);
                if (plp->plp_credits + msg->ptlm_credits >
                    plp->plp_max_credits) {
                        CWARN("Too many credits from %s: %d + %d > %d\n",
                              libcfs_id2str(srcid),
                              plp->plp_credits, msg->ptlm_credits,
                              plp->plp_max_credits);
                        plp->plp_credits = plp->plp_max_credits;
                } else {
                        plp->plp_credits += msg->ptlm_credits;
                }
                ptllnd_check_sends(plp);
        }

        /* All OK so far; assume the message is good... */

        rx.rx_peer      = plp;
        rx.rx_msg       = msg;
        rx.rx_nob       = nob;
        plni->plni_nrxs++;

        CDEBUG(D_NET, "rx=%p type=%d\n",&rx,msg->ptlm_type);

        switch (msg->ptlm_type) {
        default: /* message types have been checked already */
                ptllnd_rx_done(&rx);
                break;

        case PTLLND_MSG_TYPE_PUT:
        case PTLLND_MSG_TYPE_GET:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_%s\n",
                        msg->ptlm_type==PTLLND_MSG_TYPE_PUT ? "PUT" : "GET");
                rc = lnet_parse(ni, &msg->ptlm_u.rdma.kptlrm_hdr,
                                msg->ptlm_srcnid, &rx, 1);
                CDEBUG(D_NET, "lnet_parse rc=%d\n",rc);
                if (rc < 0)
                        ptllnd_rx_done(&rx);
                break;

        case PTLLND_MSG_TYPE_IMMEDIATE:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_IMMEDIATE\n");
                rc = lnet_parse(ni, &msg->ptlm_u.immediate.kptlim_hdr,
                                msg->ptlm_srcnid, &rx, 0);
                CDEBUG(D_NET, "lnet_parse rc=%d\n",rc);
                if (rc < 0)
                        ptllnd_rx_done(&rx);
                break;
        }

        ptllnd_peer_decref(plp);
}

void
ptllnd_buf_event (lnet_ni_t *ni, ptl_event_t *event)
{
        ptllnd_buffer_t *buf = ptllnd_eventarg2obj(event->md.user_ptr);
        ptllnd_ni_t     *plni = ni->ni_data;
        char            *msg = &buf->plb_buffer[event->offset];
        int              repost;
        int              unlinked = event->type == PTL_EVENT_UNLINK;

        LASSERT (buf->plb_ni == ni);
        LASSERT (event->type == PTL_EVENT_PUT_END ||
                 event->type == PTL_EVENT_UNLINK);

        CDEBUG(D_NET, "buf=%p event=%d\n",buf,event->type);

        if (event->ni_fail_type != PTL_NI_OK) {

                CERROR("event type %d, status %d from %s\n",
                       event->type, event->ni_fail_type,
                       ptllnd_ptlid2str(event->initiator));

        } else if (event->type == PTL_EVENT_PUT_END) {
#if (PTL_MD_LOCAL_ALIGN8 == 0)
                /* Portals can't force message alignment - someone sending an
                 * odd-length message could misalign subsequent messages */
                if ((event->mlength & 7) != 0) {
                        CERROR("Message from %s has odd length %d: "
                               "probable version incompatibility\n",
                               ptllnd_ptlid2str(event->initiator),
                               event->mlength);
                        LBUG();
                }
#endif
                LASSERT ((event->offset & 7) == 0);

                ptllnd_parse_request(ni, event->initiator,
                                     (kptl_msg_t *)msg, event->mlength);
        }

#ifdef LUSTRE_PORTALS_UNLINK_SEMANTICS
        /* UNLINK event only on explicit unlink */
        repost = (event->unlinked && event->type != PTL_EVENT_UNLINK);
        if (event->unlinked)
                unlinked = 1;
#else
        /* UNLINK event only on implicit unlink */
        repost = (event->type == PTL_EVENT_UNLINK);
#endif

        CDEBUG(D_NET, "repost=%d unlinked=%d\n",repost,unlinked);

        if (unlinked) {
                LASSERT(buf->plb_posted);
                buf->plb_posted = 0;
                plni->plni_nposted_buffers--;
        }

        if (repost)
                (void) ptllnd_post_buffer(buf);
}

void
ptllnd_tx_event (lnet_ni_t *ni, ptl_event_t *event)
{
        ptllnd_ni_t *plni = ni->ni_data;
        ptllnd_tx_t *tx = ptllnd_eventarg2obj(event->md.user_ptr);
        int          error = (event->ni_fail_type != PTL_NI_OK);
        int          isreq;
        int          isbulk;
#ifdef LUSTRE_PORTALS_UNLINK_SEMANTICS
        int          unlinked = event->unlinked;
#else
        int          unlinked = (event->type == PTL_EVENT_UNLINK);
#endif

        if (error)
                CERROR("Error event type %d for %s for %s\n",
                       event->type, ptllnd_msgtype2str(tx->tx_type),
                       libcfs_id2str(tx->tx_peer->plp_id));

        LASSERT (!PtlHandleIsEqual(event->md_handle, PTL_INVALID_HANDLE));

        CDEBUG(D_NET, "tx=%p type=%s (%d)\n",tx,
                ptllnd_msgtype2str(tx->tx_type),tx->tx_type);
        CDEBUG(D_NET, "unlinked=%d\n",unlinked);
        CDEBUG(D_NET, "error=%d\n",error);

        isreq = PtlHandleIsEqual(event->md_handle, tx->tx_reqmdh);
        CDEBUG(D_NET, "isreq=%d\n",isreq);
        if (isreq) {
                LASSERT (event->md.start == (void *)&tx->tx_msg);
                if (unlinked) {
                        tx->tx_reqmdh = PTL_INVALID_HANDLE;
                        PTLLND_DBGT_STAMP(tx->tx_req_done);
                }
        }

        isbulk = PtlHandleIsEqual(event->md_handle, tx->tx_bulkmdh);
        CDEBUG(D_NET, "isbulk=%d\n",isbulk);
        if ( isbulk && unlinked ) {
                tx->tx_bulkmdh = PTL_INVALID_HANDLE;
                PTLLND_DBGT_STAMP(tx->tx_bulk_done);
        }

        LASSERT (!isreq != !isbulk);            /* always one and only 1 match */

        switch (tx->tx_type) {
        default:
                LBUG();

        case PTLLND_MSG_TYPE_NOOP:
        case PTLLND_MSG_TYPE_HELLO:
        case PTLLND_MSG_TYPE_IMMEDIATE:
                LASSERT (event->type == PTL_EVENT_UNLINK ||
                         event->type == PTL_EVENT_SEND_END);
                LASSERT (isreq);
                break;

        case PTLLND_MSG_TYPE_GET:
                LASSERT (event->type == PTL_EVENT_UNLINK ||
                         (isreq && event->type == PTL_EVENT_SEND_END) ||
                         (isbulk && event->type == PTL_EVENT_PUT_END));

                if (isbulk && !error && event->type == PTL_EVENT_PUT_END) {
                        /* Check GET matched */
                        if (event->hdr_data == PTLLND_RDMA_OK) {
                                lnet_set_reply_msg_len(ni, 
                                                       tx->tx_lnetreplymsg,
                                                       event->mlength);
                        } else {
                                CERROR ("Unmatched GET with %s\n",
                                        libcfs_id2str(tx->tx_peer->plp_id));
                                tx->tx_status = -EIO;
                        }
                }
                break;

        case PTLLND_MSG_TYPE_PUT:
                LASSERT (event->type == PTL_EVENT_UNLINK ||
                         (isreq && event->type == PTL_EVENT_SEND_END) ||
                         (isbulk && event->type == PTL_EVENT_GET_END));
                break;

        case PTLLND_RDMA_READ:
                LASSERT (event->type == PTL_EVENT_UNLINK ||
                         event->type == PTL_EVENT_SEND_END ||
                         event->type == PTL_EVENT_REPLY_END);
                LASSERT (isbulk);
                break;

        case PTLLND_RDMA_WRITE:
                LASSERT (event->type == PTL_EVENT_UNLINK ||
                         event->type == PTL_EVENT_SEND_END);
                LASSERT (isbulk);
        }

        /* Schedule ptllnd_tx_done() on error or last completion event */
        if (error ||
            (PtlHandleIsEqual(tx->tx_bulkmdh, PTL_INVALID_HANDLE) &&
             PtlHandleIsEqual(tx->tx_reqmdh, PTL_INVALID_HANDLE))) {
                if (error)
                        tx->tx_status = -EIO;
                list_del(&tx->tx_list);
                list_add_tail(&tx->tx_list, &plni->plni_zombie_txs);
                CDEBUG(D_NET, "tx=%p ONTO ZOMBIE LIST\n",tx);
        }
}

void
ptllnd_wait (lnet_ni_t *ni, int milliseconds)
{
        ptllnd_ni_t   *plni = ni->ni_data;
        ptllnd_tx_t   *tx;
        ptl_event_t    event;
        int            which;
        int            rc;
        int            blocked = 0;
        int            found = 0;
        int            timeout = 0;

        /* Handle any currently queued events, returning immediately if any.
         * Otherwise block for the timeout and handle all events queued
         * then. */

        for (;;) {
                time_t  then = cfs_time_current_sec();

                CDEBUG(D_NET, "Poll(%d)\n", timeout);
                
                rc = PtlEQPoll(&plni->plni_eqh, 1,
                               (timeout < 0) ? PTL_TIME_FOREVER : timeout,
                               &event, &which);

                if (timeout >= 0 &&
                    (cfs_time_current_sec() - then)*1000 > timeout + 1000) {
                        /* 1000 mS grace.............................^ */
                        CERROR("SLOW PtlEQPoll(%d): %d seconds\n", timeout,
                               (int)(cfs_time_current_sec() - then));
                }
                
                CDEBUG(D_NET, "PtlEQPoll rc=%d\n",rc);
                timeout = 0;

                if (rc == PTL_EQ_EMPTY) {
                        if (found ||            /* handled some events */
                            milliseconds == 0 || /* just checking */
                            blocked)            /* blocked already */
                                break;

                        blocked = 1;
                        timeout = milliseconds;
                        continue;
                }

                LASSERT (rc == PTL_OK || rc == PTL_EQ_DROPPED);

                if (rc == PTL_EQ_DROPPED)
                        CERROR("Event queue: size %d is too small\n",
                               plni->plni_eq_size);

                CDEBUG(D_NET, "event.type=%s(%d)\n",
                       ptllnd_evtype2str(event.type),event.type);

                found = 1;
                switch (ptllnd_eventarg2type(event.md.user_ptr)) {
                default:
                        LBUG();

                case PTLLND_EVENTARG_TYPE_TX:
                        ptllnd_tx_event(ni, &event);
                        break;

                case PTLLND_EVENTARG_TYPE_BUF:
                        ptllnd_buf_event(ni, &event);
                        break;
                }
        }

        while (!list_empty(&plni->plni_zombie_txs)) {
                tx = list_entry(plni->plni_zombie_txs.next,
                                ptllnd_tx_t, tx_list);
                CDEBUG(D_NET, "Process ZOMBIE tx=%p\n",tx);
                ptllnd_tx_done(tx);
        }
}
