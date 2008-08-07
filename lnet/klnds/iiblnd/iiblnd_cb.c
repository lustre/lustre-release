/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/iiblnd/iiblnd_cb.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "iiblnd.h"

void
hexdump(char *string, void *ptr, int len)
{
        unsigned char *c = ptr;
        int i;

        return;

        if (len < 0 || len > 2048)  {
                printk("XXX what the hell? %d\n",len);
                return;
        }

        printk("%d bytes of '%s' from 0x%p\n", len, string, ptr);

        for (i = 0; i < len;) {
                printk("%02x",*(c++));
                i++;
                if (!(i & 15)) {
                        printk("\n");
                } else if (!(i&1)) {
                        printk(" ");
                }
        }

        if(len & 15) {
                printk("\n");
        }
}

void
kibnal_tx_done (kib_tx_t *tx)
{
        lnet_msg_t *lntmsg[2];
        int         rc = tx->tx_status;
        int         i;

        LASSERT (!in_interrupt());
        LASSERT (!tx->tx_queued);               /* mustn't be queued for sending */
        LASSERT (tx->tx_sending == 0);          /* mustn't be awaiting sent callback */
        LASSERT (!tx->tx_waiting);              /* mustn't be awaiting peer response */

#if IBNAL_USE_FMR
        /* Handle unmapping if required */
#endif
        /* tx may have up to 2 lnet msgs to finalise */
        lntmsg[0] = tx->tx_lntmsg[0]; tx->tx_lntmsg[0] = NULL;
        lntmsg[1] = tx->tx_lntmsg[1]; tx->tx_lntmsg[1] = NULL;
        
        if (tx->tx_conn != NULL) {
                kibnal_conn_decref(tx->tx_conn);
                tx->tx_conn = NULL;
        }

        tx->tx_nwrq = 0;
        tx->tx_status = 0;

        spin_lock(&kibnal_data.kib_tx_lock);

        list_add (&tx->tx_list, &kibnal_data.kib_idle_txs);

        spin_unlock(&kibnal_data.kib_tx_lock);

        /* delay finalize until my descs have been freed */
        for (i = 0; i < 2; i++) {
                if (lntmsg[i] == NULL)
                        continue;

                lnet_finalize (kibnal_data.kib_ni, lntmsg[i], rc);
        }
}

kib_tx_t *
kibnal_get_idle_tx (void) 
{
        kib_tx_t      *tx;
        
        spin_lock(&kibnal_data.kib_tx_lock);

        if (list_empty (&kibnal_data.kib_idle_txs)) {
                spin_unlock(&kibnal_data.kib_tx_lock);
                return NULL;
        }

        tx = list_entry (kibnal_data.kib_idle_txs.next, kib_tx_t, tx_list);
        list_del (&tx->tx_list);

        /* Allocate a new completion cookie.  It might not be needed,
         * but we've got a lock right now and we're unlikely to
         * wrap... */
        tx->tx_cookie = kibnal_data.kib_next_tx_cookie++;

        spin_unlock(&kibnal_data.kib_tx_lock);

        LASSERT (tx->tx_nwrq == 0);
        LASSERT (!tx->tx_queued);
        LASSERT (tx->tx_sending == 0);
        LASSERT (!tx->tx_waiting);
        LASSERT (tx->tx_status == 0);
        LASSERT (tx->tx_conn == NULL);
        LASSERT (tx->tx_lntmsg[0] == NULL);
        LASSERT (tx->tx_lntmsg[1] == NULL);
        
        return tx;
}

int
kibnal_post_rx (kib_rx_t *rx, int credit, int rsrvd_credit)
{
        kib_conn_t   *conn = rx->rx_conn;
        int           rc = 0;
        FSTATUS       frc;

        LASSERT (!in_interrupt());
        /* old peers don't reserve rxs for RDMA replies */
        LASSERT (!rsrvd_credit ||
                 conn->ibc_version != IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD);
        
        rx->rx_gl = (IB_LOCAL_DATASEGMENT) {
                .Address = rx->rx_hca_msg,
                .Lkey    = kibnal_data.kib_whole_mem.md_lkey,
                .Length  = IBNAL_MSG_SIZE,
        };

        rx->rx_wrq = (IB_WORK_REQ2) {
                .Next          = NULL,
                .WorkReqId     = kibnal_ptr2wreqid(rx, IBNAL_WID_RX),
                .MessageLen    = IBNAL_MSG_SIZE,
                .DSList        = &rx->rx_gl,
                .DSListDepth   = 1,
                .Operation     = WROpRecv,
        };

        LASSERT (conn->ibc_state >= IBNAL_CONN_CONNECTING);
        LASSERT (rx->rx_nob >= 0);              /* not posted */

        CDEBUG(D_NET, "posting rx [%d %x "LPX64"]\n", 
               rx->rx_wrq.DSList->Length,
               rx->rx_wrq.DSList->Lkey,
               rx->rx_wrq.DSList->Address);

        if (conn->ibc_state > IBNAL_CONN_ESTABLISHED) {
                /* No more posts for this rx; so lose its ref */
                kibnal_conn_decref(conn);
                return 0;
        }
        
        rx->rx_nob = -1;                        /* flag posted */
        mb();

        frc = iba_post_recv2(conn->ibc_qp, &rx->rx_wrq, NULL);
        if (frc == FSUCCESS) {
                if (credit || rsrvd_credit) {
                        spin_lock(&conn->ibc_lock);

                        if (credit)
                                conn->ibc_outstanding_credits++;
                        if (rsrvd_credit)
                                conn->ibc_reserved_credits++;

                        spin_unlock(&conn->ibc_lock);

                        kibnal_check_sends(conn);
                }
                return 0;
        }
        
        CERROR ("post rx -> %s failed %d\n", 
                libcfs_nid2str(conn->ibc_peer->ibp_nid), frc);
        rc = -EIO;
        kibnal_close_conn(rx->rx_conn, rc);
        /* No more posts for this rx; so lose its ref */
        kibnal_conn_decref(conn);
        return rc;
}

int
kibnal_post_receives (kib_conn_t *conn)
{
        int    i;
        int    rc;

        LASSERT (conn->ibc_state == IBNAL_CONN_CONNECTING);

        for (i = 0; i < IBNAL_RX_MSGS; i++) {
                /* +1 ref for rx desc.  This ref remains until kibnal_post_rx
                 * fails (i.e. actual failure or we're disconnecting) */
                kibnal_conn_addref(conn);
                rc = kibnal_post_rx (&conn->ibc_rxs[i], 0, 0);
                if (rc != 0)
                        return rc;
        }

        return 0;
}

kib_tx_t *
kibnal_find_waiting_tx_locked(kib_conn_t *conn, int txtype, __u64 cookie)
{
        struct list_head   *tmp;
        
        list_for_each(tmp, &conn->ibc_active_txs) {
                kib_tx_t *tx = list_entry(tmp, kib_tx_t, tx_list);
                
                LASSERT (!tx->tx_queued);
                LASSERT (tx->tx_sending != 0 || tx->tx_waiting);

                if (tx->tx_cookie != cookie)
                        continue;

                if (tx->tx_waiting &&
                    tx->tx_msg->ibm_type == txtype)
                        return tx;

                CWARN("Bad completion: %swaiting, type %x (wanted %x)\n",
                      tx->tx_waiting ? "" : "NOT ",
                      tx->tx_msg->ibm_type, txtype);
        }
        return NULL;
}

void
kibnal_handle_completion(kib_conn_t *conn, int txtype, int status, __u64 cookie)
{
        kib_tx_t    *tx;
        int          idle;

        spin_lock(&conn->ibc_lock);

        tx = kibnal_find_waiting_tx_locked(conn, txtype, cookie);
        if (tx == NULL) {
                spin_unlock(&conn->ibc_lock);

                CWARN("Unmatched completion type %x cookie "LPX64" from %s\n",
                      txtype, cookie, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                kibnal_close_conn (conn, -EPROTO);
                return;
        }

        if (tx->tx_status == 0) {               /* success so far */
                if (status < 0) {               /* failed? */
                        tx->tx_status = status;
                } else if (txtype == IBNAL_MSG_GET_REQ) {
                        lnet_set_reply_msg_len(kibnal_data.kib_ni,
                                               tx->tx_lntmsg[1], status);
                }
        }
        
        tx->tx_waiting = 0;

        idle = !tx->tx_queued && (tx->tx_sending == 0);
        if (idle)
                list_del(&tx->tx_list);

        spin_unlock(&conn->ibc_lock);
        
        if (idle)
                kibnal_tx_done(tx);
}

void
kibnal_send_completion (kib_conn_t *conn, int type, int status, __u64 cookie) 
{
        kib_tx_t    *tx = kibnal_get_idle_tx();
        
        if (tx == NULL) {
                CERROR("Can't get tx for completion %x for %s\n",
                       type, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                return;
        }
        
        tx->tx_msg->ibm_u.completion.ibcm_status = status;
        tx->tx_msg->ibm_u.completion.ibcm_cookie = cookie;
        kibnal_init_tx_msg(tx, type, sizeof(kib_completion_msg_t));
        
        kibnal_queue_tx(tx, conn);
}

void
kibnal_handle_rx (kib_rx_t *rx)
{
        kib_msg_t    *msg = rx->rx_msg;
        kib_conn_t   *conn = rx->rx_conn;
        int           credits = msg->ibm_credits;
        kib_tx_t     *tx;
        int           rc = 0;
        int           repost = 1;
        int           rsrvd_credit = 0;
        int           rc2;

        LASSERT (conn->ibc_state >= IBNAL_CONN_ESTABLISHED);

        CDEBUG (D_NET, "Received %x[%d] from %s\n",
                msg->ibm_type, credits, libcfs_nid2str(conn->ibc_peer->ibp_nid));
        
        if (credits != 0) {
                /* Have I received credits that will let me send? */
                spin_lock(&conn->ibc_lock);
                conn->ibc_credits += credits;
                spin_unlock(&conn->ibc_lock);

                kibnal_check_sends(conn);
        }

        switch (msg->ibm_type) {
        default:
                CERROR("Bad IBNAL message type %x from %s\n",
                       msg->ibm_type, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                rc = -EPROTO;
                break;

        case IBNAL_MSG_NOOP:
                break;

        case IBNAL_MSG_IMMEDIATE:
                rc = lnet_parse(kibnal_data.kib_ni, &msg->ibm_u.immediate.ibim_hdr,
                                msg->ibm_srcnid, rx, 0);
                repost = rc < 0;                /* repost on error */
                break;
                
        case IBNAL_MSG_PUT_REQ:
                rc = lnet_parse(kibnal_data.kib_ni, &msg->ibm_u.putreq.ibprm_hdr,
                                msg->ibm_srcnid, rx, 1);
                repost = rc < 0;                /* repost on error */
                break;

        case IBNAL_MSG_PUT_NAK:
                rsrvd_credit = 1;               /* rdma reply (was pre-reserved) */

                CWARN ("PUT_NACK from %s\n", libcfs_nid2str(conn->ibc_peer->ibp_nid));
                kibnal_handle_completion(conn, IBNAL_MSG_PUT_REQ, 
                                         msg->ibm_u.completion.ibcm_status,
                                         msg->ibm_u.completion.ibcm_cookie);
                break;

        case IBNAL_MSG_PUT_ACK:
                rsrvd_credit = 1;               /* rdma reply (was pre-reserved) */

                spin_lock(&conn->ibc_lock);
                tx = kibnal_find_waiting_tx_locked(conn, IBNAL_MSG_PUT_REQ,
                                                   msg->ibm_u.putack.ibpam_src_cookie);
                if (tx != NULL)
                        list_del(&tx->tx_list);
                spin_unlock(&conn->ibc_lock);

                if (tx == NULL) {
                        CERROR("Unmatched PUT_ACK from %s\n",
                               libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        rc = -EPROTO;
                        break;
                }

                LASSERT (tx->tx_waiting);
                /* CAVEAT EMPTOR: I could be racing with tx_complete, but...
                 * (a) I can overwrite tx_msg since my peer has received it!
                 * (b) tx_waiting set tells tx_complete() it's not done. */

                tx->tx_nwrq = 0;                /* overwrite PUT_REQ */

                rc2 = kibnal_init_rdma(tx, IBNAL_MSG_PUT_DONE, 
                                       kibnal_rd_size(&msg->ibm_u.putack.ibpam_rd),
                                       &msg->ibm_u.putack.ibpam_rd,
                                       msg->ibm_u.putack.ibpam_dst_cookie);
                if (rc2 < 0)
                        CERROR("Can't setup rdma for PUT to %s: %d\n",
                               libcfs_nid2str(conn->ibc_peer->ibp_nid), rc2);

                spin_lock(&conn->ibc_lock);
                if (tx->tx_status == 0 && rc2 < 0)
                        tx->tx_status = rc2;
                tx->tx_waiting = 0;             /* clear waiting and queue atomically */
                kibnal_queue_tx_locked(tx, conn);
                spin_unlock(&conn->ibc_lock);
                break;
                
        case IBNAL_MSG_PUT_DONE:
                /* This buffer was pre-reserved by not returning the credit
                 * when the PUT_REQ's buffer was reposted, so I just return it
                 * now */
                kibnal_handle_completion(conn, IBNAL_MSG_PUT_ACK,
                                         msg->ibm_u.completion.ibcm_status,
                                         msg->ibm_u.completion.ibcm_cookie);
                break;

        case IBNAL_MSG_GET_REQ:
                rc = lnet_parse(kibnal_data.kib_ni, &msg->ibm_u.get.ibgm_hdr,
                                msg->ibm_srcnid, rx, 1);
                repost = rc < 0;                /* repost on error */
                break;

        case IBNAL_MSG_GET_DONE:
                rsrvd_credit = 1;               /* rdma reply (was pre-reserved) */

                kibnal_handle_completion(conn, IBNAL_MSG_GET_REQ,
                                         msg->ibm_u.completion.ibcm_status,
                                         msg->ibm_u.completion.ibcm_cookie);
                break;
        }

        if (rc < 0)                             /* protocol error */
                kibnal_close_conn(conn, rc);

        if (repost) {
                if (conn->ibc_version == IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD)
                        rsrvd_credit = 0;       /* peer isn't pre-reserving */

                kibnal_post_rx(rx, !rsrvd_credit, rsrvd_credit);
        }
}

void
kibnal_rx_complete (IB_WORK_COMPLETION *wc, __u64 rxseq)
{
        kib_rx_t     *rx = (kib_rx_t *)kibnal_wreqid2ptr(wc->WorkReqId);
        int           nob = wc->Length;
        kib_msg_t    *msg = rx->rx_msg;
        kib_conn_t   *conn = rx->rx_conn;
        unsigned long flags;
        int           rc;
        int           err = -EIO;

        LASSERT (rx->rx_nob < 0);               /* was posted */
        rx->rx_nob = 0;                         /* isn't now */
        mb();

        /* receives complete with error in any case after we've started
         * disconnecting */
        if (conn->ibc_state > IBNAL_CONN_ESTABLISHED)
                goto ignore;

        if (wc->Status != WRStatusSuccess) {
                CERROR("Rx from %s failed: %d\n", 
                       libcfs_nid2str(conn->ibc_peer->ibp_nid), wc->Status);
                goto failed;
        }

        rc = kibnal_unpack_msg(msg, conn->ibc_version, nob);
        if (rc != 0) {
                CERROR ("Error %d unpacking rx from %s\n",
                        rc, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                goto failed;
        }

        rx->rx_nob = nob;                       /* Now I know nob > 0 */
        mb();

        if (msg->ibm_srcnid != conn->ibc_peer->ibp_nid ||
            msg->ibm_dstnid != kibnal_data.kib_ni->ni_nid ||
            msg->ibm_srcstamp != conn->ibc_incarnation ||
            msg->ibm_dststamp != kibnal_data.kib_incarnation) {
                CERROR ("Stale rx from %s\n",
                        libcfs_nid2str(conn->ibc_peer->ibp_nid));
                err = -ESTALE;
                goto failed;
        }

        if (msg->ibm_seq != rxseq) {
                CERROR ("Out-of-sequence rx from %s"
                        ": got "LPD64" but expected "LPD64"\n",
                        libcfs_nid2str(conn->ibc_peer->ibp_nid),
                        msg->ibm_seq, rxseq);
                goto failed;
        }

        /* set time last known alive */
        kibnal_peer_alive(conn->ibc_peer);

        /* racing with connection establishment/teardown! */

        if (conn->ibc_state < IBNAL_CONN_ESTABLISHED) {
                write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
                /* must check holding global lock to eliminate race */
                if (conn->ibc_state < IBNAL_CONN_ESTABLISHED) {
                        list_add_tail(&rx->rx_list, &conn->ibc_early_rxs);
                        write_unlock_irqrestore(&kibnal_data.kib_global_lock, 
                                                flags);
                        return;
                }
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, 
                                        flags);
        }
        kibnal_handle_rx(rx);
        return;
        
 failed:
        kibnal_close_conn(conn, err);
 ignore:
        /* Don't re-post rx & drop its ref on conn */
        kibnal_conn_decref(conn);
}

struct page *
kibnal_kvaddr_to_page (unsigned long vaddr)
{
        struct page *page;

        if (vaddr >= VMALLOC_START &&
            vaddr < VMALLOC_END) {
                page = vmalloc_to_page ((void *)vaddr);
                LASSERT (page != NULL);
                return page;
        }
#ifdef CONFIG_HIGHMEM
        if (vaddr >= PKMAP_BASE &&
            vaddr < (PKMAP_BASE + LAST_PKMAP * PAGE_SIZE)) {
                /* No highmem pages only used for bulk (kiov) I/O */
                CERROR("find page for address in highmem\n");
                LBUG();
        }
#endif
        page = virt_to_page (vaddr);
        LASSERT (page != NULL);
        return page;
}

#if !IBNAL_USE_FMR
int
kibnal_append_rdfrag(kib_rdma_desc_t *rd, int active, struct page *page, 
                     unsigned long page_offset, unsigned long len)
{
        kib_rdma_frag_t *frag = &rd->rd_frags[rd->rd_nfrag];

        if (rd->rd_nfrag >= IBNAL_MAX_RDMA_FRAGS) {
                CERROR ("Too many RDMA fragments\n");
                return -EMSGSIZE;
        }

        if (active) {
                if (rd->rd_nfrag == 0)
                        rd->rd_key = kibnal_data.kib_whole_mem.md_lkey;
        } else {
                if (rd->rd_nfrag == 0)
                        rd->rd_key = kibnal_data.kib_whole_mem.md_rkey;
        }

        frag->rf_nob  = len;
        frag->rf_addr = kibnal_data.kib_whole_mem.md_addr +
                        lnet_page2phys(page) + page_offset;

        CDEBUG(D_NET,"map key %x frag [%d]["LPX64" for %d]\n", 
               rd->rd_key, rd->rd_nfrag, frag->rf_addr, frag->rf_nob);

        rd->rd_nfrag++;
        return 0;
}

int
kibnal_setup_rd_iov(kib_tx_t *tx, kib_rdma_desc_t *rd, int active,
                    unsigned int niov, struct iovec *iov, int offset, int nob)
                 
{
        int           fragnob;
        int           rc;
        unsigned long vaddr;
        struct page  *page;
        int           page_offset;

        LASSERT (nob > 0);
        LASSERT (niov > 0);
        LASSERT ((rd != tx->tx_rd) == !active);

        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                niov--;
                iov++;
                LASSERT (niov > 0);
        }

        rd->rd_nfrag = 0;
        do {
                LASSERT (niov > 0);

                vaddr = ((unsigned long)iov->iov_base) + offset;
                page_offset = vaddr & (PAGE_SIZE - 1);
                page = kibnal_kvaddr_to_page(vaddr);
                if (page == NULL) {
                        CERROR ("Can't find page\n");
                        return -EFAULT;
                }

                fragnob = min((int)(iov->iov_len - offset), nob);
                fragnob = min(fragnob, (int)PAGE_SIZE - page_offset);

                rc = kibnal_append_rdfrag(rd, active, page, 
                                          page_offset, fragnob);
                if (rc != 0)
                        return rc;

                if (offset + fragnob < iov->iov_len) {
                        offset += fragnob;
                } else {
                        offset = 0;
                        iov++;
                        niov--;
                }
                nob -= fragnob;
        } while (nob > 0);
        
        return 0;
}

int
kibnal_setup_rd_kiov (kib_tx_t *tx, kib_rdma_desc_t *rd, int active,
                      int nkiov, lnet_kiov_t *kiov, int offset, int nob)
{
        int            fragnob;
        int            rc;

        CDEBUG(D_NET, "niov %d offset %d nob %d\n", nkiov, offset, nob);

        LASSERT (nob > 0);
        LASSERT (nkiov > 0);
        LASSERT ((rd != tx->tx_rd) == !active);

        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                nkiov--;
                kiov++;
                LASSERT (nkiov > 0);
        }

        rd->rd_nfrag = 0;
        do {
                LASSERT (nkiov > 0);
                fragnob = min((int)(kiov->kiov_len - offset), nob);
                
                rc = kibnal_append_rdfrag(rd, active, kiov->kiov_page,
                                          kiov->kiov_offset + offset,
                                          fragnob);
                if (rc != 0)
                        return rc;

                offset = 0;
                kiov++;
                nkiov--;
                nob -= fragnob;
        } while (nob > 0);

        return 0;
}
#else
int
kibnal_map_tx (kib_tx_t *tx, kib_rdma_desc_t *rd, int active,
               int npages, unsigned long page_offset, int nob)
{
        IB_ACCESS_CONTROL access = {0,};
        FSTATUS           frc;

        LASSERT ((rd != tx->tx_rd) == !active);
        LASSERT (!tx->tx_md.md_active);
        LASSERT (tx->tx_md.md_fmrcount > 0);
        LASSERT (page_offset < PAGE_SIZE);
        LASSERT (npages >= (1 + ((page_offset + nob - 1)>>PAGE_SHIFT)));
        LASSERT (npages <= LNET_MAX_IOV);

        if (!active) {
                // access.s.MWBindable = 1;
                access.s.LocalWrite = 1;
                access.s.RdmaWrite = 1;
        }

        /* Map the memory described by tx->tx_pages
        frc = iibt_register_physical_memory(kibnal_data.kib_hca,
                                            IBNAL_RDMA_BASE,
                                            tx->tx_pages, npages,
                                            page_offset,
                                            kibnal_data.kib_pd,
                                            access,
                                            &tx->tx_md.md_handle,
                                            &tx->tx_md.md_addr,
                                            &tx->tx_md.md_lkey,
                                            &tx->tx_md.md_rkey);
        */
        return -EINVAL;
}

int
kibnal_setup_rd_iov (kib_tx_t *tx, kib_rdma_desc_t *rd, int active,
                     unsigned int niov, struct iovec *iov, int offset, int nob)
                 
{
        int           resid;
        int           fragnob;
        struct page  *page;
        int           npages;
        unsigned long page_offset;
        unsigned long vaddr;

        LASSERT (nob > 0);
        LASSERT (niov > 0);

        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                niov--;
                iov++;
                LASSERT (niov > 0);
        }

        if (nob > iov->iov_len - offset) {
                CERROR ("Can't map multiple vaddr fragments\n");
                return (-EMSGSIZE);
        }

        vaddr = ((unsigned long)iov->iov_base) + offset;
        
        page_offset = vaddr & (PAGE_SIZE - 1);
        resid = nob;
        npages = 0;

        do {
                LASSERT (npages < LNET_MAX_IOV);

                page = kibnal_kvaddr_to_page(vaddr);
                if (page == NULL) {
                        CERROR("Can't find page for %lu\n", vaddr);
                        return -EFAULT;
                }

                tx->tx_pages[npages++] = lnet_page2phys(page);

                fragnob = PAGE_SIZE - (vaddr & (PAGE_SIZE - 1));
                vaddr += fragnob;
                resid -= fragnob;

        } while (resid > 0);

        return kibnal_map_tx(tx, rd, active, npages, page_offset, nob);
}

int
kibnal_setup_rd_kiov (kib_tx_t *tx, kib_rdma_desc_t *rd, int active,
                      int nkiov, lnet_kiov_t *kiov, int offset, int nob)
{
        int            resid;
        int            npages;
        unsigned long  page_offset;
        
        CDEBUG(D_NET, "niov %d offset %d nob %d\n", nkiov, offset, nob);

        LASSERT (nob > 0);
        LASSERT (nkiov > 0);
        LASSERT (nkiov <= LNET_MAX_IOV);
        LASSERT (!tx->tx_md.md_active);
        LASSERT ((rd != tx->tx_rd) == !active);

        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                nkiov--;
                kiov++;
                LASSERT (nkiov > 0);
        }

        page_offset = kiov->kiov_offset + offset;
        
        resid = offset + nob;
        npages = 0;

        do {
                LASSERT (npages < LNET_MAX_IOV);
                LASSERT (nkiov > 0);

                if ((npages > 0 && kiov->kiov_offset != 0) ||
                    (resid > kiov->kiov_len && 
                     (kiov->kiov_offset + kiov->kiov_len) != PAGE_SIZE)) {
                        /* Can't have gaps */
                        CERROR ("Can't make payload contiguous in I/O VM:"
                                "page %d, offset %d, len %d \n",
                                npages, kiov->kiov_offset, kiov->kiov_len);
                        
                        return -EINVAL;
                }

                tx->tx_pages[npages++] = lnet_page2phys(kiov->kiov_page);
                resid -= kiov->kiov_len;
                kiov++;
                nkiov--;
        } while (resid > 0);

        return kibnal_map_tx(tx, rd, active, npages, page_offset, nob);
}
#endif

kib_conn_t *
kibnal_find_conn_locked (kib_peer_t *peer)
{
        struct list_head *tmp;

        /* just return the first connection */
        list_for_each (tmp, &peer->ibp_conns) {
                return (list_entry(tmp, kib_conn_t, ibc_list));
        }

        return (NULL);
}

void
kibnal_check_sends (kib_conn_t *conn)
{
        kib_tx_t       *tx;
        FSTATUS         frc;
        int             rc;
        int             consume_cred;
        int             done;

        LASSERT (conn->ibc_state >= IBNAL_CONN_ESTABLISHED);
        
        spin_lock(&conn->ibc_lock);

        LASSERT (conn->ibc_nsends_posted <=
                *kibnal_tunables.kib_concurrent_sends);
        LASSERT (conn->ibc_reserved_credits >= 0);
        
        while (conn->ibc_reserved_credits > 0 &&
               !list_empty(&conn->ibc_tx_queue_rsrvd)) {
                LASSERT (conn->ibc_version != 
                         IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD);
                tx = list_entry(conn->ibc_tx_queue_rsrvd.next,
                                kib_tx_t, tx_list);
                list_del(&tx->tx_list);
                list_add_tail(&tx->tx_list, &conn->ibc_tx_queue);
                conn->ibc_reserved_credits--;
        }

        if (list_empty(&conn->ibc_tx_queue) &&
            list_empty(&conn->ibc_tx_queue_nocred) &&
            (conn->ibc_outstanding_credits >= IBNAL_CREDIT_HIGHWATER ||
             kibnal_send_keepalive(conn))) {
                spin_unlock(&conn->ibc_lock);
                
                tx = kibnal_get_idle_tx();
                if (tx != NULL)
                        kibnal_init_tx_msg(tx, IBNAL_MSG_NOOP, 0);

                spin_lock(&conn->ibc_lock);
                
                if (tx != NULL)
                        kibnal_queue_tx_locked(tx, conn);
        }

        for (;;) {
                if (!list_empty(&conn->ibc_tx_queue_nocred)) {
                        LASSERT (conn->ibc_version != 
                                 IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD);
                        tx = list_entry (conn->ibc_tx_queue_nocred.next, 
                                         kib_tx_t, tx_list);
                        consume_cred = 0;
                } else if (!list_empty (&conn->ibc_tx_queue)) {
                        tx = list_entry (conn->ibc_tx_queue.next, 
                                         kib_tx_t, tx_list);
                        consume_cred = 1;
                } else {
                        /* nothing waiting */
                        break;
                }

                LASSERT (tx->tx_queued);
                /* We rely on this for QP sizing */
                LASSERT (tx->tx_nwrq > 0 && tx->tx_nwrq <= 1 + IBNAL_MAX_RDMA_FRAGS);

                LASSERT (conn->ibc_outstanding_credits >= 0);
                LASSERT (conn->ibc_outstanding_credits <= IBNAL_MSG_QUEUE_SIZE);
                LASSERT (conn->ibc_credits >= 0);
                LASSERT (conn->ibc_credits <= IBNAL_MSG_QUEUE_SIZE);

                if (conn->ibc_nsends_posted ==
                    *kibnal_tunables.kib_concurrent_sends) {
                        /* We've got some tx completions outstanding... */
                        CDEBUG(D_NET, "%s: posted enough\n",
                               libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        break;
                }

                if (consume_cred) {
                        if (conn->ibc_credits == 0) {   /* no credits */
                                CDEBUG(D_NET, "%s: no credits\n",
                                       libcfs_nid2str(conn->ibc_peer->ibp_nid));
                                break;
                        }
                        
                        if (conn->ibc_credits == 1 &&   /* last credit reserved for */
                            conn->ibc_outstanding_credits == 0) { /* giving back credits */
                                CDEBUG(D_NET, "%s: not using last credit\n",
                                       libcfs_nid2str(conn->ibc_peer->ibp_nid));
                                break;
                        }
                }
                
                list_del (&tx->tx_list);
                tx->tx_queued = 0;

                /* NB don't drop ibc_lock before bumping tx_sending */

                if (tx->tx_msg->ibm_type == IBNAL_MSG_NOOP &&
                    (!list_empty(&conn->ibc_tx_queue) ||
                     !list_empty(&conn->ibc_tx_queue_nocred) ||
                     (conn->ibc_outstanding_credits < IBNAL_CREDIT_HIGHWATER &&
                      !kibnal_send_keepalive(conn)))) {
                        /* redundant NOOP */
                        spin_unlock(&conn->ibc_lock);
                        kibnal_tx_done(tx);
                        spin_lock(&conn->ibc_lock);
                        CDEBUG(D_NET, "%s: redundant noop\n",
                               libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        continue;
                }

                kibnal_pack_msg(tx->tx_msg, conn->ibc_version,
                                conn->ibc_outstanding_credits,
                                conn->ibc_peer->ibp_nid, conn->ibc_incarnation,
                                conn->ibc_txseq);

                conn->ibc_txseq++;
                conn->ibc_outstanding_credits = 0;
                conn->ibc_nsends_posted++;
                if (consume_cred)
                        conn->ibc_credits--;

                /* CAVEAT EMPTOR!  This tx could be the PUT_DONE of an RDMA
                 * PUT.  If so, it was first queued here as a PUT_REQ, sent and
                 * stashed on ibc_active_txs, matched by an incoming PUT_ACK,
                 * and then re-queued here.  It's (just) possible that
                 * tx_sending is non-zero if we've not done the tx_complete() from
                 * the first send; hence the ++ rather than = below. */
                tx->tx_sending++;

                list_add (&tx->tx_list, &conn->ibc_active_txs);

                LASSERT (tx->tx_nwrq > 0);

                rc = 0;
                frc = FSUCCESS;
                if (conn->ibc_state != IBNAL_CONN_ESTABLISHED) {
                        rc = -ECONNABORTED;
                } else {
                        frc = iba_post_send2(conn->ibc_qp, tx->tx_wrq, NULL);
                        if (frc != FSUCCESS)
                                rc = -EIO;
                }

                conn->ibc_last_send = jiffies;

                if (rc != 0) {
                        /* NB credits are transferred in the actual
                         * message, which can only be the last work item */
                        conn->ibc_outstanding_credits += tx->tx_msg->ibm_credits;
                        if (consume_cred)
                                conn->ibc_credits++;
                        conn->ibc_nsends_posted--;

                        tx->tx_status = rc;
                        tx->tx_waiting = 0;
                        tx->tx_sending--;
                        
                        done = (tx->tx_sending == 0);
                        if (done)
                                list_del (&tx->tx_list);
                        
                        spin_unlock(&conn->ibc_lock);
                        
                        if (conn->ibc_state == IBNAL_CONN_ESTABLISHED)
                                CERROR ("Error %d posting transmit to %s\n", 
                                        frc, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        else
                                CDEBUG (D_NET, "Error %d posting transmit to %s\n",
                                        rc, libcfs_nid2str(conn->ibc_peer->ibp_nid));

                        kibnal_close_conn (conn, rc);

                        if (done)
                                kibnal_tx_done (tx);
                        return;
                }
        }

        spin_unlock(&conn->ibc_lock);
}

void
kibnal_tx_complete (IB_WORK_COMPLETION *wc)
{
        kib_tx_t     *tx = (kib_tx_t *)kibnal_wreqid2ptr(wc->WorkReqId);
        kib_conn_t   *conn = tx->tx_conn;
        int           failed = wc->Status != WRStatusSuccess;
        int           idle;

        CDEBUG(D_NET, "%s: sending %d nwrq %d status %d\n", 
               libcfs_nid2str(conn->ibc_peer->ibp_nid),
               tx->tx_sending, tx->tx_nwrq, wc->Status);

        LASSERT (tx->tx_sending > 0);

        if (failed &&
            tx->tx_status == 0 &&
            conn->ibc_state == IBNAL_CONN_ESTABLISHED) {
#if KIBLND_DETAILED_DEBUG
                int                   i;
                IB_WORK_REQ2         *wrq = &tx->tx_wrq[0];
                IB_LOCAL_DATASEGMENT *gl = &tx->tx_gl[0];
                lnet_msg_t           *lntmsg = tx->tx_lntmsg[0];
#endif
                CDEBUG(D_NETERROR, "tx -> %s type %x cookie "LPX64
                       " sending %d waiting %d failed %d nwrk %d\n", 
                       libcfs_nid2str(conn->ibc_peer->ibp_nid),
                       tx->tx_msg->ibm_type, tx->tx_cookie,
                       tx->tx_sending, tx->tx_waiting, wc->Status,
                       tx->tx_nwrq);
#if KIBLND_DETAILED_DEBUG
                for (i = 0; i < tx->tx_nwrq; i++, wrq++, gl++) {
                        switch (wrq->Operation) {
                        default:
                                CDEBUG(D_NETERROR, "    [%3d] Addr %p Next %p OP %d "
                                       "DSList %p(%p)/%d: "LPX64"/%d K %x\n",
                                       i, wrq, wrq->Next, wrq->Operation,
                                       wrq->DSList, gl, wrq->DSListDepth,
                                       gl->Address, gl->Length, gl->Lkey);
                                break;
                        case WROpSend:
                                CDEBUG(D_NETERROR, "    [%3d] Addr %p Next %p SEND "
                                       "DSList %p(%p)/%d: "LPX64"/%d K %x\n",
                                       i, wrq, wrq->Next, 
                                       wrq->DSList, gl, wrq->DSListDepth,
                                       gl->Address, gl->Length, gl->Lkey);
                                break;
                        case WROpRdmaWrite:
                                CDEBUG(D_NETERROR, "    [%3d] Addr %p Next %p DMA "
                                       "DSList: %p(%p)/%d "LPX64"/%d K %x -> "
                                       LPX64" K %x\n",
                                       i, wrq, wrq->Next, 
                                       wrq->DSList, gl, wrq->DSListDepth,
                                       gl->Address, gl->Length, gl->Lkey,
                                       wrq->Req.SendRC.RemoteDS.Address,
                                       wrq->Req.SendRC.RemoteDS.Rkey);
                                break;
                        }
                }
                
                switch (tx->tx_msg->ibm_type) {
                default:
                        CDEBUG(D_NETERROR, "  msg type %x %p/%d, No RDMA\n", 
                               tx->tx_msg->ibm_type, 
                               tx->tx_msg, tx->tx_msg->ibm_nob);
                        break;

                case IBNAL_MSG_PUT_DONE:
                case IBNAL_MSG_GET_DONE:
                        CDEBUG(D_NETERROR, "  msg type %x %p/%d, RDMA key %x frags %d...\n", 
                               tx->tx_msg->ibm_type, 
                               tx->tx_msg, tx->tx_msg->ibm_nob,
                               tx->tx_rd->rd_key, tx->tx_rd->rd_nfrag);
                        for (i = 0; i < tx->tx_rd->rd_nfrag; i++)
                                CDEBUG(D_NETERROR, "    [%d] "LPX64"/%d\n", i,
                                       tx->tx_rd->rd_frags[i].rf_addr,
                                       tx->tx_rd->rd_frags[i].rf_nob);
                        if (lntmsg == NULL) {
                                CDEBUG(D_NETERROR, "  No lntmsg\n");
                        } else if (lntmsg->msg_iov != NULL) {
                                CDEBUG(D_NETERROR, "  lntmsg in %d VIRT frags...\n", 
                                       lntmsg->msg_niov);
                                for (i = 0; i < lntmsg->msg_niov; i++)
                                        CDEBUG(D_NETERROR, "    [%d] %p/%d\n", i,
                                               lntmsg->msg_iov[i].iov_base,
                                               lntmsg->msg_iov[i].iov_len);
                        } else if (lntmsg->msg_kiov != NULL) {
                                CDEBUG(D_NETERROR, "  lntmsg in %d PAGE frags...\n", 
                                       lntmsg->msg_niov);
                                for (i = 0; i < lntmsg->msg_niov; i++)
                                        CDEBUG(D_NETERROR, "    [%d] %p+%d/%d\n", i,
                                               lntmsg->msg_kiov[i].kiov_page,
                                               lntmsg->msg_kiov[i].kiov_offset,
                                               lntmsg->msg_kiov[i].kiov_len);
                        } else {
                                CDEBUG(D_NETERROR, "  lntmsg in %d frags\n", 
                                       lntmsg->msg_niov);
                        }
                        
                        break;
                }
#endif
        }
        
        spin_lock(&conn->ibc_lock);

        /* I could be racing with rdma completion.  Whoever makes 'tx' idle
         * gets to free it, which also drops its ref on 'conn'. */

        tx->tx_sending--;
        conn->ibc_nsends_posted--;

        if (failed) {
                tx->tx_waiting = 0;
                tx->tx_status = -EIO;
        }
        
        idle = (tx->tx_sending == 0) &&         /* This is the final callback */
               !tx->tx_waiting &&               /* Not waiting for peer */
               !tx->tx_queued;                  /* Not re-queued (PUT_DONE) */
        if (idle)
                list_del(&tx->tx_list);

        kibnal_conn_addref(conn);               /* 1 ref for me.... */

        spin_unlock(&conn->ibc_lock);

        if (idle)
                kibnal_tx_done (tx);

        if (failed) {
                kibnal_close_conn (conn, -EIO);
        } else {
                kibnal_peer_alive(conn->ibc_peer);
                kibnal_check_sends(conn);
        }

        kibnal_conn_decref(conn);               /* ...until here */
}

void
kibnal_init_tx_msg (kib_tx_t *tx, int type, int body_nob)
{
        IB_LOCAL_DATASEGMENT *gl = &tx->tx_gl[tx->tx_nwrq];
        IB_WORK_REQ2         *wrq = &tx->tx_wrq[tx->tx_nwrq];
        int                   nob = offsetof (kib_msg_t, ibm_u) + body_nob;

        LASSERT (tx->tx_nwrq >= 0 && 
                 tx->tx_nwrq < (1 + IBNAL_MAX_RDMA_FRAGS));
        LASSERT (nob <= IBNAL_MSG_SIZE);

        kibnal_init_msg(tx->tx_msg, type, body_nob);

        *gl = (IB_LOCAL_DATASEGMENT) {
                .Address = tx->tx_hca_msg,
                .Length  = IBNAL_MSG_SIZE,
                .Lkey    = kibnal_data.kib_whole_mem.md_lkey,
        };

        wrq->Next           = NULL;             /* This is the last one */

        wrq->WorkReqId      = kibnal_ptr2wreqid(tx, IBNAL_WID_TX);
        wrq->Operation      = WROpSend;
        wrq->DSList         = gl;
        wrq->DSListDepth    = 1;
        wrq->MessageLen     = nob;
        wrq->Req.SendRC.ImmediateData  = 0;
        wrq->Req.SendRC.Options.s.SolicitedEvent         = 1;
        wrq->Req.SendRC.Options.s.SignaledCompletion     = 1;
        wrq->Req.SendRC.Options.s.ImmediateData          = 0;
        wrq->Req.SendRC.Options.s.Fence                  = 0; 
        /* fence only needed on RDMA reads */
        
        tx->tx_nwrq++;
}

int
kibnal_init_rdma (kib_tx_t *tx, int type, int nob,
                  kib_rdma_desc_t *dstrd, __u64 dstcookie)
{
        kib_msg_t            *ibmsg = tx->tx_msg;
        kib_rdma_desc_t      *srcrd = tx->tx_rd;
        IB_LOCAL_DATASEGMENT *gl;
        IB_WORK_REQ2         *wrq;
        int                   rc;

#if IBNAL_USE_FMR
        LASSERT (tx->tx_nwrq == 0);

        gl = &tx->tx_gl[0];
        gl->Length  = nob;
        gl->Address = srcrd->rd_addr;
        gl->Lkey    = srcrd->rd_key;

        wrq = &tx->tx_wrq[0];

        wrq->Next           = wrq + 1;
        wrq->WorkReqId      = kibnal_ptr2wreqid(tx, IBNAL_WID_RDMA);
        wrq->Operation      = WROpRdmaWrite;
        wrq->DSList         = gl;
        wrq->DSListDepth    = 1;
        wrq->MessageLen     = nob;

        wrq->Req.SendRC.ImmediateData                = 0;
        wrq->Req.SendRC.Options.s.SolicitedEvent     = 0;
        wrq->Req.SendRC.Options.s.SignaledCompletion = 0;
        wrq->Req.SendRC.Options.s.ImmediateData      = 0;
        wrq->Req.SendRC.Options.s.Fence              = 0; 

        wrq->Req.SendRC.RemoteDS.Address = dstrd->rd_addr;
        wrq->Req.SendRC.RemoteDS.Rkey    = dstrd->rd_key;

        tx->tx_nwrq = 1;
        rc = nob;
#else
        /* CAVEAT EMPTOR: this 'consumes' the frags in 'dstrd' */
        int              resid = nob;
        kib_rdma_frag_t *srcfrag;
        int              srcidx;
        kib_rdma_frag_t *dstfrag;
        int              dstidx;
        int              wrknob;

        /* Called by scheduler */
        LASSERT (!in_interrupt());

        LASSERT (type == IBNAL_MSG_GET_DONE ||
                 type == IBNAL_MSG_PUT_DONE);

        srcidx = dstidx = 0;
        srcfrag = &srcrd->rd_frags[0];
        dstfrag = &dstrd->rd_frags[0];
        rc = resid;

        while (resid > 0) {
                if (srcidx >= srcrd->rd_nfrag) {
                        CERROR("Src buffer exhausted: %d frags\n", srcidx);
                        rc = -EPROTO;
                        break;
                }
                
                if (dstidx == dstrd->rd_nfrag) {
                        CERROR("Dst buffer exhausted: %d frags\n", dstidx);
                        rc = -EPROTO;
                        break;
                }

                if (tx->tx_nwrq == IBNAL_MAX_RDMA_FRAGS) {
                        CERROR("RDMA too fragmented: %d/%d src %d/%d dst frags\n",
                               srcidx, srcrd->rd_nfrag,
                               dstidx, dstrd->rd_nfrag);
                        rc = -EMSGSIZE;
                        break;
                }

                wrknob = MIN(MIN(srcfrag->rf_nob, dstfrag->rf_nob), resid);

                gl = &tx->tx_gl[tx->tx_nwrq];
                gl->Length  = wrknob;
                gl->Address = srcfrag->rf_addr;
                gl->Lkey    = srcrd->rd_key;

                wrq = &tx->tx_wrq[tx->tx_nwrq];

                wrq->Next           = wrq + 1;
                wrq->WorkReqId      = kibnal_ptr2wreqid(tx, IBNAL_WID_RDMA);
                wrq->Operation      = WROpRdmaWrite;
                wrq->DSList         = gl;
                wrq->DSListDepth    = 1;
                wrq->MessageLen     = nob;

                wrq->Req.SendRC.ImmediateData                = 0;
                wrq->Req.SendRC.Options.s.SolicitedEvent     = 0;
                wrq->Req.SendRC.Options.s.SignaledCompletion = 0;
                wrq->Req.SendRC.Options.s.ImmediateData      = 0;
                wrq->Req.SendRC.Options.s.Fence              = 0; 

                wrq->Req.SendRC.RemoteDS.Address = dstfrag->rf_addr;
                wrq->Req.SendRC.RemoteDS.Rkey    = dstrd->rd_key;

                resid -= wrknob;
                if (wrknob < srcfrag->rf_nob) {
                        srcfrag->rf_addr += wrknob;
                        srcfrag->rf_nob -= wrknob;
                } else {
                        srcfrag++;
                        srcidx++;
                }
                
                if (wrknob < dstfrag->rf_nob) {
                        dstfrag->rf_addr += wrknob;
                        dstfrag->rf_nob -= wrknob;
                } else {
                        dstfrag++;
                        dstidx++;
                }
                
                tx->tx_nwrq++;
        }

        if (rc < 0)                             /* no RDMA if completing with failure */
                tx->tx_nwrq = 0;
#endif
        
        ibmsg->ibm_u.completion.ibcm_status = rc;
        ibmsg->ibm_u.completion.ibcm_cookie = dstcookie;
        kibnal_init_tx_msg(tx, type, sizeof (kib_completion_msg_t));

        return rc;
}

void
kibnal_queue_tx (kib_tx_t *tx, kib_conn_t *conn)
{
        spin_lock(&conn->ibc_lock);
        kibnal_queue_tx_locked (tx, conn);
        spin_unlock(&conn->ibc_lock);
        
        kibnal_check_sends(conn);
}

void
kibnal_schedule_active_connect_locked (kib_peer_t *peer, int proto_version)
{
        /* Called holding kib_global_lock exclusive with IRQs disabled */

        peer->ibp_version = proto_version;      /* proto version for new conn */
        peer->ibp_connecting++;                 /* I'm connecting */
        kibnal_peer_addref(peer);               /* extra ref for connd */

        spin_lock(&kibnal_data.kib_connd_lock);

        list_add_tail (&peer->ibp_connd_list, &kibnal_data.kib_connd_peers);
        wake_up (&kibnal_data.kib_connd_waitq);

        spin_unlock(&kibnal_data.kib_connd_lock);
}

void
kibnal_schedule_active_connect (kib_peer_t *peer, int proto_version)
{
        unsigned long flags;

        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        kibnal_schedule_active_connect_locked(peer, proto_version);

        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
}

void
kibnal_launch_tx (kib_tx_t *tx, lnet_nid_t nid)
{
        kib_peer_t      *peer;
        kib_conn_t      *conn;
        unsigned long    flags;
        rwlock_t        *g_lock = &kibnal_data.kib_global_lock;
        int              retry;
        int              rc;

        /* If I get here, I've committed to send, so I complete the tx with
         * failure on any problems */
        
        LASSERT (tx->tx_conn == NULL);          /* only set when assigned a conn */
        LASSERT (tx->tx_nwrq > 0);              /* work items have been set up */

        for (retry = 0; ; retry = 1) {
                read_lock_irqsave(g_lock, flags);
        
                peer = kibnal_find_peer_locked (nid);
                if (peer != NULL) {
                        conn = kibnal_find_conn_locked (peer);
                        if (conn != NULL) {
                                kibnal_conn_addref(conn); /* 1 ref for me... */
                                read_unlock_irqrestore(g_lock, flags);

                                kibnal_queue_tx (tx, conn);
                                kibnal_conn_decref(conn); /* ...to here */
                                return;
                        }
                }
                
                /* Making one or more connections; I'll need a write lock... */
                read_unlock(g_lock);
                write_lock(g_lock);

                peer = kibnal_find_peer_locked (nid);
                if (peer != NULL)
                        break;

                write_unlock_irqrestore(g_lock, flags);

                if (retry) {
                        CERROR("Can't find peer %s\n", libcfs_nid2str(nid));

                        tx->tx_status = -EHOSTUNREACH;
                        tx->tx_waiting = 0;
                        kibnal_tx_done (tx);
                        return;
                }

                rc = kibnal_add_persistent_peer(nid);
                if (rc != 0) {
                        CERROR("Can't add peer %s: %d\n",
                               libcfs_nid2str(nid), rc);
                        
                        tx->tx_status = -EHOSTUNREACH;
                        tx->tx_waiting = 0;
                        kibnal_tx_done (tx);
                        return;
                }
        }

        conn = kibnal_find_conn_locked (peer);
        if (conn != NULL) {
                /* Connection exists; queue message on it */
                kibnal_conn_addref(conn);       /* 1 ref for me... */
                write_unlock_irqrestore(g_lock, flags);
                
                kibnal_queue_tx (tx, conn);
                kibnal_conn_decref(conn);       /* ...until here */
                return;
        }

        if (!kibnal_peer_connecting(peer)) {
                if (!(peer->ibp_reconnect_interval == 0 || /* first attempt */
                      time_after_eq(jiffies, peer->ibp_reconnect_time))) {
                        write_unlock_irqrestore(g_lock, flags);
                        tx->tx_status = -EHOSTUNREACH;
                        tx->tx_waiting = 0;
                        kibnal_tx_done (tx);
                        return;
                }

                kibnal_schedule_active_connect_locked(peer, IBNAL_MSG_VERSION);
        }
        
        /* A connection is being established; queue the message... */
        list_add_tail (&tx->tx_list, &peer->ibp_tx_queue);

        write_unlock_irqrestore(g_lock, flags);
}

void
kibnal_txlist_done (struct list_head *txlist, int status)
{
        kib_tx_t *tx;

        while (!list_empty (txlist)) {
                tx = list_entry (txlist->next, kib_tx_t, tx_list);

                list_del (&tx->tx_list);
                /* complete now */
                tx->tx_waiting = 0;
                tx->tx_status = status;
                kibnal_tx_done (tx);
        }
}

int
kibnal_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
        lnet_hdr_t       *hdr = &lntmsg->msg_hdr; 
        int               type = lntmsg->msg_type; 
        lnet_process_id_t target = lntmsg->msg_target;
        int               target_is_router = lntmsg->msg_target_is_router;
        int               routing = lntmsg->msg_routing;
        unsigned int      payload_niov = lntmsg->msg_niov; 
        struct iovec     *payload_iov = lntmsg->msg_iov; 
        lnet_kiov_t      *payload_kiov = lntmsg->msg_kiov;
        unsigned int      payload_offset = lntmsg->msg_offset;
        unsigned int      payload_nob = lntmsg->msg_len;
        kib_msg_t        *ibmsg;
        kib_tx_t         *tx;
        int               nob;
        int               rc;

        /* NB 'private' is different depending on what we're sending.... */

        CDEBUG(D_NET, "sending %d bytes in %d frags to %s\n",
               payload_nob, payload_niov, libcfs_id2str(target));

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= LNET_MAX_IOV);

        /* Thread context */
        LASSERT (!in_interrupt());
        /* payload is either all vaddrs or all pages */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));

        switch (type) {
        default:
                LBUG();
                return (-EIO);
                
        case LNET_MSG_ACK:
                LASSERT (payload_nob == 0);
                break;

        case LNET_MSG_GET:
                if (routing || target_is_router)
                        break;                  /* send IMMEDIATE */
                
                /* is the REPLY message too small for RDMA? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[lntmsg->msg_md->md_length]);
                if (nob <= IBNAL_MSG_SIZE)
                        break;                  /* send IMMEDIATE */

                tx = kibnal_get_idle_tx();
                if (tx == NULL) {
                        CERROR("Can allocate txd for GET to %s: \n",
                               libcfs_nid2str(target.nid));
                        return -ENOMEM;
                }
                
                ibmsg = tx->tx_msg;
                ibmsg->ibm_u.get.ibgm_hdr = *hdr;
                ibmsg->ibm_u.get.ibgm_cookie = tx->tx_cookie;

                if ((lntmsg->msg_md->md_options & LNET_MD_KIOV) == 0)
                        rc = kibnal_setup_rd_iov(tx, &ibmsg->ibm_u.get.ibgm_rd,
                                                 0,
                                                 lntmsg->msg_md->md_niov,
                                                 lntmsg->msg_md->md_iov.iov,
                                                 0, lntmsg->msg_md->md_length);
                else
                        rc = kibnal_setup_rd_kiov(tx, &ibmsg->ibm_u.get.ibgm_rd,
                                                  0,
                                                  lntmsg->msg_md->md_niov,
                                                  lntmsg->msg_md->md_iov.kiov,
                                                  0, lntmsg->msg_md->md_length);
                if (rc != 0) {
                        CERROR("Can't setup GET sink for %s: %d\n",
                               libcfs_nid2str(target.nid), rc);
                        kibnal_tx_done(tx);
                        return -EIO;
                }

#if IBNAL_USE_FMR
                nob = sizeof(kib_get_msg_t);
#else
                {
                        int n = ibmsg->ibm_u.get.ibgm_rd.rd_nfrag;
                        
                        nob = offsetof(kib_get_msg_t, ibgm_rd.rd_frags[n]);
                }
#endif
                kibnal_init_tx_msg(tx, IBNAL_MSG_GET_REQ, nob);

                tx->tx_lntmsg[1] = lnet_create_reply_msg(kibnal_data.kib_ni,
                                                         lntmsg);
                if (tx->tx_lntmsg[1] == NULL) {
                        CERROR("Can't create reply for GET -> %s\n",
                               libcfs_nid2str(target.nid));
                        kibnal_tx_done(tx);
                        return -EIO;
                }

                tx->tx_lntmsg[0] = lntmsg;      /* finalise lntmsg[0,1] on completion */
                tx->tx_waiting = 1;             /* waiting for GET_DONE */
                kibnal_launch_tx(tx, target.nid);
                return 0;

        case LNET_MSG_REPLY: 
        case LNET_MSG_PUT:
                /* Is the payload small enough not to need RDMA? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob]);
                if (nob <= IBNAL_MSG_SIZE)
                        break;                  /* send IMMEDIATE */

                tx = kibnal_get_idle_tx();
                if (tx == NULL) {
                        CERROR("Can't allocate %s txd for %s\n",
                               type == LNET_MSG_PUT ? "PUT" : "REPLY",
                               libcfs_nid2str(target.nid));
                        return -ENOMEM;
                }

                if (payload_kiov == NULL)
                        rc = kibnal_setup_rd_iov(tx, tx->tx_rd, 1,
                                                 payload_niov, payload_iov,
                                                 payload_offset, payload_nob);
                else
                        rc = kibnal_setup_rd_kiov(tx, tx->tx_rd, 1,
                                                  payload_niov, payload_kiov,
                                                  payload_offset, payload_nob);
                if (rc != 0) {
                        CERROR("Can't setup PUT src for %s: %d\n",
                               libcfs_nid2str(target.nid), rc);
                        kibnal_tx_done(tx);
                        return -EIO;
                }

                ibmsg = tx->tx_msg;
                ibmsg->ibm_u.putreq.ibprm_hdr = *hdr;
                ibmsg->ibm_u.putreq.ibprm_cookie = tx->tx_cookie;
                kibnal_init_tx_msg(tx, IBNAL_MSG_PUT_REQ, sizeof(kib_putreq_msg_t));

                tx->tx_lntmsg[0] = lntmsg;      /* finalise lntmsg on completion */
                tx->tx_waiting = 1;             /* waiting for PUT_{ACK,NAK} */
                kibnal_launch_tx(tx, target.nid);
                return 0;
        }

        /* send IMMEDIATE */

        LASSERT (offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob])
                 <= IBNAL_MSG_SIZE);

        tx = kibnal_get_idle_tx();
        if (tx == NULL) {
                CERROR ("Can't send %d to %s: tx descs exhausted\n",
                        type, libcfs_nid2str(target.nid));
                return -ENOMEM;
        }

        ibmsg = tx->tx_msg;
        ibmsg->ibm_u.immediate.ibim_hdr = *hdr;

        if (payload_kiov != NULL)
                lnet_copy_kiov2flat(IBNAL_MSG_SIZE, ibmsg,
                                    offsetof(kib_msg_t, ibm_u.immediate.ibim_payload),
                                    payload_niov, payload_kiov,
                                    payload_offset, payload_nob);
        else
                lnet_copy_iov2flat(IBNAL_MSG_SIZE, ibmsg,
                                   offsetof(kib_msg_t, ibm_u.immediate.ibim_payload),
                                   payload_niov, payload_iov,
                                   payload_offset, payload_nob);

        nob = offsetof(kib_immediate_msg_t, ibim_payload[payload_nob]);
        kibnal_init_tx_msg (tx, IBNAL_MSG_IMMEDIATE, nob);

        tx->tx_lntmsg[0] = lntmsg;              /* finalise lntmsg on completion */
        kibnal_launch_tx(tx, target.nid);
        return 0;
}

void
kibnal_reply(lnet_ni_t *ni, kib_rx_t *rx, lnet_msg_t *lntmsg)
{
        lnet_process_id_t target = lntmsg->msg_target;
        unsigned int      niov = lntmsg->msg_niov; 
        struct iovec     *iov = lntmsg->msg_iov; 
        lnet_kiov_t      *kiov = lntmsg->msg_kiov;
        unsigned int      offset = lntmsg->msg_offset;
        unsigned int      nob = lntmsg->msg_len;
        kib_tx_t         *tx;
        int               rc;
        
        tx = kibnal_get_idle_tx();
        if (tx == NULL) {
                CERROR("Can't get tx for REPLY to %s\n",
                       libcfs_nid2str(target.nid));
                goto failed_0;
        }

        if (nob == 0)
                rc = 0;
        else if (kiov == NULL)
                rc = kibnal_setup_rd_iov(tx, tx->tx_rd, 1, 
                                         niov, iov, offset, nob);
        else
                rc = kibnal_setup_rd_kiov(tx, tx->tx_rd, 1, 
                                          niov, kiov, offset, nob);

        if (rc != 0) {
                CERROR("Can't setup GET src for %s: %d\n",
                       libcfs_nid2str(target.nid), rc);
                goto failed_1;
        }
        
        rc = kibnal_init_rdma(tx, IBNAL_MSG_GET_DONE, nob,
                              &rx->rx_msg->ibm_u.get.ibgm_rd,
                              rx->rx_msg->ibm_u.get.ibgm_cookie);
        if (rc < 0) {
                CERROR("Can't setup rdma for GET from %s: %d\n", 
                       libcfs_nid2str(target.nid), rc);
                goto failed_1;
        }
        
        if (rc == 0) {
                /* No RDMA: local completion may happen now! */
                lnet_finalize(ni, lntmsg, 0);
        } else {
                /* RDMA: lnet_finalize(lntmsg) when it
                 * completes */
                tx->tx_lntmsg[0] = lntmsg;
        }
        
        kibnal_queue_tx(tx, rx->rx_conn);
        return;
        
 failed_1:
        kibnal_tx_done(tx);
 failed_0:
        lnet_finalize(ni, lntmsg, -EIO);
}

int
kibnal_eager_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
                   void **new_private)
{
        kib_rx_t    *rx = private;
        kib_conn_t  *conn = rx->rx_conn;

        if (conn->ibc_version == IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD) {
                /* Can't block if RDMA completions need normal credits */
                LCONSOLE_ERROR_MSG(0x12d,  "Dropping message from %s: no "
                                   "buffers free. %s is running an old version"
                                   " of LNET that may deadlock if messages "
                                   "wait for buffers)\n",
                                   libcfs_nid2str(conn->ibc_peer->ibp_nid),
                                   libcfs_nid2str(conn->ibc_peer->ibp_nid));
                return -EDEADLK;
        }
        
        *new_private = private;
        return 0;
}

int
kibnal_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, int delayed,
             unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
             unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        kib_rx_t    *rx = private;
        kib_msg_t   *rxmsg = rx->rx_msg;
        kib_conn_t  *conn = rx->rx_conn;
        kib_tx_t    *tx;
        kib_msg_t   *txmsg;
        int          nob;
        int          post_cred = 1;
        int          rc = 0;
        
        LASSERT (mlen <= rlen);
        LASSERT (!in_interrupt());
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));

        switch (rxmsg->ibm_type) {
        default:
                LBUG();
                
        case IBNAL_MSG_IMMEDIATE:
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[rlen]);
                if (nob > rx->rx_nob) {
                        CERROR ("Immediate message from %s too big: %d(%d)\n",
                                libcfs_nid2str(rxmsg->ibm_u.immediate.ibim_hdr.src_nid),
                                nob, rx->rx_nob);
                        rc = -EPROTO;
                        break;
                }

                if (kiov != NULL)
                        lnet_copy_flat2kiov(niov, kiov, offset,
                                            IBNAL_MSG_SIZE, rxmsg,
                                            offsetof(kib_msg_t, ibm_u.immediate.ibim_payload),
                                            mlen);
                else
                        lnet_copy_flat2iov(niov, iov, offset,
                                           IBNAL_MSG_SIZE, rxmsg,
                                           offsetof(kib_msg_t, ibm_u.immediate.ibim_payload),
                                           mlen);
                lnet_finalize (ni, lntmsg, 0);
                break;

        case IBNAL_MSG_PUT_REQ:
                if (mlen == 0) {
                        lnet_finalize(ni, lntmsg, 0);
                        kibnal_send_completion(rx->rx_conn, IBNAL_MSG_PUT_NAK, 0,
                                               rxmsg->ibm_u.putreq.ibprm_cookie);
                        break;
                }
                
                tx = kibnal_get_idle_tx();
                if (tx == NULL) {
                        CERROR("Can't allocate tx for %s\n",
                               libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        /* Not replying will break the connection */
                        rc = -ENOMEM;
                        break;
                }

                txmsg = tx->tx_msg;
                if (kiov == NULL)
                        rc = kibnal_setup_rd_iov(tx, 
                                                 &txmsg->ibm_u.putack.ibpam_rd,
                                                 0,
                                                 niov, iov, offset, mlen);
                else
                        rc = kibnal_setup_rd_kiov(tx,
                                                  &txmsg->ibm_u.putack.ibpam_rd,
                                                  0,
                                                  niov, kiov, offset, mlen);
                if (rc != 0) {
                        CERROR("Can't setup PUT sink for %s: %d\n",
                               libcfs_nid2str(conn->ibc_peer->ibp_nid), rc);
                        kibnal_tx_done(tx);
                        /* tell peer it's over */
                        kibnal_send_completion(rx->rx_conn, IBNAL_MSG_PUT_NAK, rc,
                                               rxmsg->ibm_u.putreq.ibprm_cookie);
                        break;
                }

                txmsg->ibm_u.putack.ibpam_src_cookie = rxmsg->ibm_u.putreq.ibprm_cookie;
                txmsg->ibm_u.putack.ibpam_dst_cookie = tx->tx_cookie;
#if IBNAL_USE_FMR
                nob = sizeof(kib_putack_msg_t);
#else
                {
                        int n = tx->tx_msg->ibm_u.putack.ibpam_rd.rd_nfrag;

                        nob = offsetof(kib_putack_msg_t, ibpam_rd.rd_frags[n]);
                }
#endif
                kibnal_init_tx_msg(tx, IBNAL_MSG_PUT_ACK, nob);

                tx->tx_lntmsg[0] = lntmsg;      /* finalise lntmsg on completion */
                tx->tx_waiting = 1;             /* waiting for PUT_DONE */
                kibnal_queue_tx(tx, conn);

                if (conn->ibc_version != IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD)
                        post_cred = 0; /* peer still owns 'rx' for sending PUT_DONE */
                break;

        case IBNAL_MSG_GET_REQ:
                if (lntmsg != NULL) {
                        /* Optimized GET; RDMA lntmsg's payload */
                        kibnal_reply(ni, rx, lntmsg);
                } else {
                        /* GET didn't match anything */
                        kibnal_send_completion(rx->rx_conn, IBNAL_MSG_GET_DONE, 
                                               -ENODATA,
                                               rxmsg->ibm_u.get.ibgm_cookie);
                }
                break;
        }

        kibnal_post_rx(rx, post_cred, 0);
        return rc;
}

int
kibnal_thread_start (int (*fn)(void *arg), void *arg)
{
        long    pid = kernel_thread (fn, arg, 0);

        if (pid < 0)
                return ((int)pid);

        atomic_inc (&kibnal_data.kib_nthreads);
        return (0);
}

void
kibnal_thread_fini (void)
{
        atomic_dec (&kibnal_data.kib_nthreads);
}

void
kibnal_peer_alive (kib_peer_t *peer)
{
        /* This is racy, but everyone's only writing cfs_time_current() */
        peer->ibp_last_alive = cfs_time_current();
        mb();
}

void
kibnal_peer_notify (kib_peer_t *peer)
{
        time_t        last_alive = 0;
        int           error = 0;
        unsigned long flags;
        
        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        if (list_empty(&peer->ibp_conns) &&
            peer->ibp_accepting == 0 &&
            peer->ibp_connecting == 0 &&
            peer->ibp_error != 0) {
                error = peer->ibp_error;
                peer->ibp_error = 0;
                last_alive = cfs_time_current_sec() -
                             cfs_duration_sec(cfs_time_current() -
                                              peer->ibp_last_alive);
        }
        
        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
        
        if (error != 0)
                lnet_notify(kibnal_data.kib_ni, peer->ibp_nid, 0, last_alive);
}

void
kibnal_schedule_conn (kib_conn_t *conn)
{
        unsigned long flags;

        kibnal_conn_addref(conn);               /* ++ref for connd */
        
        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);

        list_add_tail (&conn->ibc_list, &kibnal_data.kib_connd_conns);
        wake_up (&kibnal_data.kib_connd_waitq);
                
        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
}

void
kibnal_close_conn_locked (kib_conn_t *conn, int error)
{
        /* This just does the immediate housekeeping to start shutdown of an
         * established connection.  'error' is zero for a normal shutdown.
         * Caller holds kib_global_lock exclusively in irq context */
        kib_peer_t       *peer = conn->ibc_peer;
        
        LASSERT (conn->ibc_state >= IBNAL_CONN_ESTABLISHED);

        if (conn->ibc_state != IBNAL_CONN_ESTABLISHED)
                return; /* already being handled  */
        
        /* NB Can't take ibc_lock here (could be in IRQ context), without
         * risking deadlock, so access to ibc_{tx_queue,active_txs} is racey */

        if (error == 0 &&
            list_empty(&conn->ibc_tx_queue) &&
            list_empty(&conn->ibc_tx_queue_rsrvd) &&
            list_empty(&conn->ibc_tx_queue_nocred) &&
            list_empty(&conn->ibc_active_txs)) {
                CDEBUG(D_NET, "closing conn to %s"
                       " rx# "LPD64" tx# "LPD64"\n", 
                       libcfs_nid2str(peer->ibp_nid),
                       conn->ibc_txseq, conn->ibc_rxseq);
        } else {
                CDEBUG(D_NETERROR, "Closing conn to %s: error %d%s%s%s%s"
                       " rx# "LPD64" tx# "LPD64"\n",
                       libcfs_nid2str(peer->ibp_nid), error,
                       list_empty(&conn->ibc_tx_queue) ? "" : "(sending)",
                       list_empty(&conn->ibc_tx_queue_rsrvd) ? "" : "(sending_rsrvd)",
                       list_empty(&conn->ibc_tx_queue_nocred) ? "" : "(sending_nocred)",
                       list_empty(&conn->ibc_active_txs) ? "" : "(waiting)",
                       conn->ibc_txseq, conn->ibc_rxseq);
#if 0
                /* can't skip down the queue without holding ibc_lock (see above) */
                list_for_each(tmp, &conn->ibc_tx_queue) {
                        kib_tx_t *tx = list_entry(tmp, kib_tx_t, tx_list);
                        
                        CERROR("   queued tx type %x cookie "LPX64
                               " sending %d waiting %d ticks %ld/%d\n", 
                               tx->tx_msg->ibm_type, tx->tx_cookie, 
                               tx->tx_sending, tx->tx_waiting,
                               (long)(tx->tx_deadline - jiffies), HZ);
                }

                list_for_each(tmp, &conn->ibc_active_txs) {
                        kib_tx_t *tx = list_entry(tmp, kib_tx_t, tx_list);
                        
                        CERROR("   active tx type %x cookie "LPX64
                               " sending %d waiting %d ticks %ld/%d\n", 
                               tx->tx_msg->ibm_type, tx->tx_cookie, 
                               tx->tx_sending, tx->tx_waiting,
                               (long)(tx->tx_deadline - jiffies), HZ);
                }
#endif
        }

        list_del (&conn->ibc_list);

        if (list_empty (&peer->ibp_conns)) {   /* no more conns */
                if (peer->ibp_persistence == 0 && /* non-persistent peer */
                    kibnal_peer_active(peer))     /* still in peer table */
                        kibnal_unlink_peer_locked (peer);

                peer->ibp_error = error; /* set/clear error on last conn */
        }

        kibnal_set_conn_state(conn, IBNAL_CONN_DISCONNECTING);

        kibnal_schedule_conn(conn);
        kibnal_conn_decref(conn);               /* lose ibc_list's ref */
}

void
kibnal_close_conn (kib_conn_t *conn, int error)
{
        unsigned long flags;
        
        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        kibnal_close_conn_locked (conn, error);
        
        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
}

void
kibnal_handle_early_rxs(kib_conn_t *conn)
{
        unsigned long    flags;
        kib_rx_t        *rx;

        LASSERT (!in_interrupt());
        LASSERT (conn->ibc_state >= IBNAL_CONN_ESTABLISHED);
        
        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
        while (!list_empty(&conn->ibc_early_rxs)) {
                rx = list_entry(conn->ibc_early_rxs.next,
                                kib_rx_t, rx_list);
                list_del(&rx->rx_list);
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                
                kibnal_handle_rx(rx);
                
                write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
        }
        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
}

void
kibnal_abort_txs(kib_conn_t *conn, struct list_head *txs)
{
        LIST_HEAD           (zombies); 
        struct list_head    *tmp;
        struct list_head    *nxt;
        kib_tx_t            *tx;

        spin_lock(&conn->ibc_lock);

        list_for_each_safe (tmp, nxt, txs) {
                tx = list_entry (tmp, kib_tx_t, tx_list);

                if (txs == &conn->ibc_active_txs) {
                        LASSERT (!tx->tx_queued);
                        LASSERT (tx->tx_waiting || tx->tx_sending != 0);
                } else {
                        LASSERT (tx->tx_queued);
                }
                
                tx->tx_status = -ECONNABORTED;
                tx->tx_queued = 0;
                tx->tx_waiting = 0;
                
                if (tx->tx_sending == 0) {
                        list_del (&tx->tx_list);
                        list_add (&tx->tx_list, &zombies);
                }
        }

        spin_unlock(&conn->ibc_lock);

        kibnal_txlist_done(&zombies, -ECONNABORTED);
}

void
kibnal_conn_disconnected(kib_conn_t *conn)
{
        static IB_QP_ATTRIBUTES_MODIFY qpam = {.RequestState = QPStateError};

        FSTATUS           frc;

        LASSERT (conn->ibc_state >= IBNAL_CONN_INIT_QP);

        kibnal_set_conn_state(conn, IBNAL_CONN_DISCONNECTED);

        /* move QP to error state to make posted work items complete */
        frc = iba_modify_qp(conn->ibc_qp, &qpam, NULL);
        if (frc != FSUCCESS)
                CERROR("can't move qp state to error: %d\n", frc);

        /* Complete all tx descs not waiting for sends to complete.
         * NB we should be safe from RDMA now that the QP has changed state */

        kibnal_abort_txs(conn, &conn->ibc_tx_queue);
        kibnal_abort_txs(conn, &conn->ibc_tx_queue_rsrvd);
        kibnal_abort_txs(conn, &conn->ibc_tx_queue);
        kibnal_abort_txs(conn, &conn->ibc_active_txs);

        kibnal_handle_early_rxs(conn);
}

void
kibnal_peer_connect_failed (kib_peer_t *peer, int type, int error)
{
        LIST_HEAD        (zombies);
        unsigned long     flags;

        LASSERT (error != 0);
        LASSERT (!in_interrupt());

        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        LASSERT (kibnal_peer_connecting(peer));

        switch (type) {
        case IBNAL_CONN_ACTIVE:
                LASSERT (peer->ibp_connecting > 0);
                peer->ibp_connecting--;
                break;
                
        case IBNAL_CONN_PASSIVE:
                LASSERT (peer->ibp_accepting > 0);
                peer->ibp_accepting--;
                break;
                
        case IBNAL_CONN_WAITING:
                /* Can't assert; I might be racing with a successful connection
                 * which clears passivewait */
                peer->ibp_passivewait = 0;
                break;
        default:
                LBUG();
        }

        if (kibnal_peer_connecting(peer) ||     /* another attempt underway */
            !list_empty(&peer->ibp_conns)) {    /* got connected */
                write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
                return;
        }

        /* Say when active connection can be re-attempted */
        peer->ibp_reconnect_interval *= 2;
        peer->ibp_reconnect_interval =
                MAX(peer->ibp_reconnect_interval,
                    *kibnal_tunables.kib_min_reconnect_interval);
        peer->ibp_reconnect_interval =
                MIN(peer->ibp_reconnect_interval,
                    *kibnal_tunables.kib_max_reconnect_interval);
        
        peer->ibp_reconnect_time = jiffies + peer->ibp_reconnect_interval * HZ;

        /* Take peer's blocked transmits to complete with error */
        list_add(&zombies, &peer->ibp_tx_queue);
        list_del_init(&peer->ibp_tx_queue);
                
        if (kibnal_peer_active(peer) &&
            peer->ibp_persistence == 0) {
                /* failed connection attempt on non-persistent peer */
                kibnal_unlink_peer_locked (peer);
        }

        peer->ibp_error = error;
        
        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        kibnal_peer_notify(peer);

        if (list_empty (&zombies))
                return;
        
        CDEBUG (D_NETERROR, "Deleting messages for %s: connection failed\n",
                libcfs_nid2str(peer->ibp_nid));

        kibnal_txlist_done (&zombies, -EHOSTUNREACH);
}

void
kibnal_connreq_done (kib_conn_t *conn, int type, int status)
{
        kib_peer_t       *peer = conn->ibc_peer;
        struct list_head  txs;
        kib_tx_t         *tx;
        unsigned long     flags;

        LASSERT (!in_interrupt());
        LASSERT (type == IBNAL_CONN_ACTIVE || type == IBNAL_CONN_PASSIVE);
        LASSERT (conn->ibc_state >= IBNAL_CONN_INIT_QP);
        LASSERT (conn->ibc_state < IBNAL_CONN_ESTABLISHED);
        LASSERT (kibnal_peer_connecting(peer));

        LIBCFS_FREE(conn->ibc_cvars, sizeof(*conn->ibc_cvars));
        conn->ibc_cvars = NULL;

        if (status != 0) {
                /* failed to establish connection */
                kibnal_peer_connect_failed(conn->ibc_peer, type, status);
                kibnal_conn_disconnected(conn);
                kibnal_conn_decref(conn);       /* Lose CM's ref */
                return;
        }

        /* connection established */
        LASSERT(conn->ibc_state == IBNAL_CONN_CONNECTING);

        conn->ibc_last_send = jiffies;
        kibnal_set_conn_state(conn, IBNAL_CONN_ESTABLISHED);
        kibnal_peer_alive(peer);

        CDEBUG(D_NET, "Connection %s ESTABLISHED\n",
               libcfs_nid2str(conn->ibc_peer->ibp_nid));

        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        peer->ibp_passivewait = 0;              /* not waiting (got conn now) */
        kibnal_conn_addref(conn);               /* +1 ref for ibc_list */
        list_add_tail(&conn->ibc_list, &peer->ibp_conns);
        
        if (!kibnal_peer_active(peer)) {
                /* peer has been deleted */
                kibnal_close_conn_locked(conn, -ECONNABORTED);
                write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

                kibnal_peer_connect_failed(conn->ibc_peer, type, -ECONNABORTED);
                kibnal_conn_decref(conn);       /* lose CM's ref */
                return;
        }
        
        switch (type) {
        case IBNAL_CONN_ACTIVE:
                LASSERT (peer->ibp_connecting > 0);
                peer->ibp_connecting--;
                break;

        case IBNAL_CONN_PASSIVE:
                LASSERT (peer->ibp_accepting > 0);
                peer->ibp_accepting--;
                break;
        default:
                LBUG();
        }
        
        peer->ibp_reconnect_interval = 0;       /* OK to reconnect at any time */

        /* Nuke any dangling conns from a different peer instance... */
        kibnal_close_stale_conns_locked(peer, conn->ibc_incarnation);

        /* grab txs blocking for a conn */
        list_add(&txs, &peer->ibp_tx_queue);
        list_del_init(&peer->ibp_tx_queue);

        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
        
        /* Schedule blocked txs */
        spin_lock (&conn->ibc_lock);
        while (!list_empty (&txs)) {
                tx = list_entry (txs.next, kib_tx_t, tx_list);
                list_del (&tx->tx_list);

                kibnal_queue_tx_locked (tx, conn);
        }
        spin_unlock (&conn->ibc_lock);
        kibnal_check_sends (conn);
}

void
kibnal_reject (lnet_nid_t nid, IB_HANDLE cep, int why)
{
        static CM_REJECT_INFO  msgs[3];
        CM_REJECT_INFO        *msg = &msgs[why];
        FSTATUS                frc;

        LASSERT (why >= 0 && why < sizeof(msgs)/sizeof(msgs[0]));

        /* If I wasn't so lazy, I'd initialise this only once; it's effectively
         * read-only... */
        msg->Reason         = RC_USER_REJ;
        msg->PrivateData[0] = (IBNAL_MSG_MAGIC) & 0xff;
        msg->PrivateData[1] = (IBNAL_MSG_MAGIC >> 8) & 0xff;
        msg->PrivateData[2] = (IBNAL_MSG_MAGIC >> 16) & 0xff;
        msg->PrivateData[3] = (IBNAL_MSG_MAGIC >> 24) & 0xff;
        msg->PrivateData[4] = (IBNAL_MSG_VERSION) & 0xff;
        msg->PrivateData[5] = (IBNAL_MSG_VERSION >> 8) & 0xff;
        msg->PrivateData[6] = why;

        frc = iba_cm_reject(cep, msg);
        if (frc != FSUCCESS)
                CERROR("Error %d rejecting %s\n", frc, libcfs_nid2str(nid));
}

void
kibnal_check_connreject(kib_conn_t *conn, int type, CM_REJECT_INFO *rej)
{
        kib_peer_t    *peer = conn->ibc_peer;
        unsigned long  flags;
        int            magic;
        int            version;
        int            why;

        LASSERT (type == IBNAL_CONN_ACTIVE ||
                 type == IBNAL_CONN_PASSIVE);

        CDEBUG(D_NET, "%s connection with %s rejected: %d\n",
               (type == IBNAL_CONN_ACTIVE) ? "Active" : "Passive",
               libcfs_nid2str(peer->ibp_nid), rej->Reason);

        switch (rej->Reason) {
        case RC_STALE_CONN:
                if (type == IBNAL_CONN_PASSIVE) {
                        CERROR("Connection to %s rejected (stale QP)\n",
                               libcfs_nid2str(peer->ibp_nid));
                } else {
                        CWARN("Connection from %s rejected (stale QP): "
                              "retrying...\n", libcfs_nid2str(peer->ibp_nid));

                        /* retry from scratch to allocate a new conn 
                         * which will use a different QP */
                        kibnal_schedule_active_connect(peer, peer->ibp_version);
                }

                /* An FCM_DISCONNECTED callback is still outstanding: give it a
                 * ref since kibnal_connreq_done() drops the CM's ref on conn
                 * on failure */
                kibnal_conn_addref(conn);
                break;

        case RC_USER_REJ:
                magic   = (rej->PrivateData[0]) |
                          (rej->PrivateData[1] << 8) |
                          (rej->PrivateData[2] << 16) |
                          (rej->PrivateData[3] << 24);
                version = (rej->PrivateData[4]) |
                          (rej->PrivateData[5] << 8);
                why     = (rej->PrivateData[6]);

                /* retry with old proto version */
                if (magic == IBNAL_MSG_MAGIC &&
                    version == IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD &&
                    conn->ibc_version == IBNAL_MSG_VERSION &&
                    type != IBNAL_CONN_PASSIVE) {
                        /* retry with a new conn */
                        CWARN ("Connection to %s refused: "
                               "retrying with old protocol version 0x%x\n", 
                               libcfs_nid2str(peer->ibp_nid), version);
                        kibnal_schedule_active_connect(peer, version);
                        break;
                }

                if (magic != IBNAL_MSG_MAGIC ||
                    version != IBNAL_MSG_VERSION) {
                        CERROR("%s connection with %s rejected "
                               "(magic/ver %08x/%d why %d): "
                               "incompatible protocol\n",
                               (type == IBNAL_CONN_ACTIVE) ?
                               "Active" : "Passive",
                               libcfs_nid2str(peer->ibp_nid),
                               magic, version, why);
                        break;
                }

                if (type == IBNAL_CONN_ACTIVE && 
                    why == IBNAL_REJECT_CONN_RACE) {
                        /* lost connection race */
                        CWARN("Connection to %s rejected: "
                              "lost connection race\n",
                              libcfs_nid2str(peer->ibp_nid));

                        write_lock_irqsave(&kibnal_data.kib_global_lock, 
                                           flags);

                        if (list_empty(&peer->ibp_conns)) {
                                peer->ibp_passivewait = 1;
                                peer->ibp_passivewait_deadline =
                                        jiffies + 
                                        (*kibnal_tunables.kib_timeout * HZ);
                        }
                        write_unlock_irqrestore(&kibnal_data.kib_global_lock, 
                                                flags);
                        break;
                }

                CERROR("%s connection with %s rejected: %d\n",
                       (type == IBNAL_CONN_ACTIVE) ? "Active" : "Passive",
                       libcfs_nid2str(peer->ibp_nid), why);
                break;

        default:
                CERROR("%s connection with %s rejected: %d\n",
                       (type == IBNAL_CONN_ACTIVE) ? "Active" : "Passive",
                       libcfs_nid2str(peer->ibp_nid), rej->Reason);
        }
        
        kibnal_connreq_done(conn, type, -ECONNREFUSED);
}

void
kibnal_cm_disconnect_callback(kib_conn_t *conn, CM_CONN_INFO *info)
{
        CDEBUG(D_NET, "%s: state %d, status 0x%x\n", 
               libcfs_nid2str(conn->ibc_peer->ibp_nid),
               conn->ibc_state, info->Status);
        
        LASSERT (conn->ibc_state >= IBNAL_CONN_ESTABLISHED);

        switch (info->Status) {
        default:
                LBUG();
                break;

        case FCM_DISCONNECT_REQUEST:
                /* Schedule conn to iba_cm_disconnect() if it wasn't already */
                kibnal_close_conn (conn, 0);
                break;

        case FCM_DISCONNECT_REPLY:              /* peer acks my disconnect req */
        case FCM_DISCONNECTED:                  /* end of TIME_WAIT */
                CDEBUG(D_NET, "Connection %s disconnected.\n",
                       libcfs_nid2str(conn->ibc_peer->ibp_nid));
                kibnal_conn_decref(conn);       /* Lose CM's ref */
                break;
        }
}

void
kibnal_cm_passive_callback(IB_HANDLE cep, CM_CONN_INFO *info, void *arg)
{
        kib_conn_t       *conn = arg;

        CDEBUG(D_NET, "status 0x%x\n", info->Status);

        /* Established Connection Notifier */
        switch (info->Status) {
        default:
                CERROR("Unexpected status %d on Connection %s\n",
                       info->Status, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                LBUG();
                break;

        case FCM_CONNECT_TIMEOUT:
                kibnal_connreq_done(conn, IBNAL_CONN_PASSIVE, -ETIMEDOUT);
                break;
                
        case FCM_CONNECT_REJECT:
                kibnal_check_connreject(conn, IBNAL_CONN_PASSIVE, 
                                        &info->Info.Reject);
                break;

        case FCM_CONNECT_ESTABLISHED:
                kibnal_connreq_done(conn, IBNAL_CONN_PASSIVE, 0);
                break;

        case FCM_DISCONNECT_REQUEST:
        case FCM_DISCONNECT_REPLY:
        case FCM_DISCONNECTED:
                kibnal_cm_disconnect_callback(conn, info);
                break;
        }
}

int
kibnal_accept (kib_conn_t **connp, IB_HANDLE cep, kib_msg_t *msg, int nob)
{
        lnet_nid_t     nid;
        kib_conn_t    *conn;
        kib_peer_t    *peer;
        kib_peer_t    *peer2;
        unsigned long  flags;
        int            rc;

        rc = kibnal_unpack_msg(msg, 0, nob);
        if (rc != 0) {
                /* SILENT! kibnal_unpack_msg() complains if required */
                kibnal_reject(LNET_NID_ANY, cep, IBNAL_REJECT_FATAL);
                return -EPROTO;
        }

        nid = msg->ibm_srcnid;

        if (msg->ibm_version != IBNAL_MSG_VERSION)
                CWARN("Connection from %s: old protocol version 0x%x\n",
                      libcfs_nid2str(nid), msg->ibm_version);

        if (msg->ibm_type != IBNAL_MSG_CONNREQ) {
                CERROR("Can't accept %s: bad request type %d (%d expected)\n",
                       libcfs_nid2str(nid), msg->ibm_type, IBNAL_MSG_CONNREQ);
                kibnal_reject(nid, cep, IBNAL_REJECT_FATAL);
                return -EPROTO;
        }
        
        if (msg->ibm_dstnid != kibnal_data.kib_ni->ni_nid) {
                CERROR("Can't accept %s: bad dst NID %s (%s expected)\n",
                       libcfs_nid2str(nid), 
                       libcfs_nid2str(msg->ibm_dstnid), 
                       libcfs_nid2str(kibnal_data.kib_ni->ni_nid));
                kibnal_reject(nid, cep, IBNAL_REJECT_FATAL);
                return -EPROTO;
        }
        
        if (msg->ibm_u.connparams.ibcp_queue_depth != IBNAL_MSG_QUEUE_SIZE ||
            msg->ibm_u.connparams.ibcp_max_msg_size > IBNAL_MSG_SIZE ||
            msg->ibm_u.connparams.ibcp_max_frags > IBNAL_MAX_RDMA_FRAGS) {
                CERROR("Reject %s: q %d sz %d frag %d, (%d %d %d expected)\n",
                       libcfs_nid2str(nid), 
                       msg->ibm_u.connparams.ibcp_queue_depth,
                       msg->ibm_u.connparams.ibcp_max_msg_size,
                       msg->ibm_u.connparams.ibcp_max_frags,
                       IBNAL_MSG_QUEUE_SIZE,
                       IBNAL_MSG_SIZE,
                       IBNAL_MAX_RDMA_FRAGS);
                kibnal_reject(nid, cep, IBNAL_REJECT_FATAL);
                return -EPROTO;
        }

        conn = kibnal_create_conn(nid, msg->ibm_version);
        if (conn == NULL) {
                kibnal_reject(nid, cep, IBNAL_REJECT_NO_RESOURCES);
                return -ENOMEM;
        }
        
        /* assume 'nid' is a new peer */
        rc = kibnal_create_peer(&peer, nid);
        if (rc != 0) {
                kibnal_conn_decref(conn);
                kibnal_reject(nid, cep, IBNAL_REJECT_NO_RESOURCES);
                return -ENOMEM;
        }
        
        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (kibnal_data.kib_listener_cep == NULL) { /* shutdown started */
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

                kibnal_peer_decref(peer);
                kibnal_conn_decref(conn);
                kibnal_reject(nid, cep, IBNAL_REJECT_NO_RESOURCES);
                return -ESHUTDOWN;
        }

        peer2 = kibnal_find_peer_locked(nid);
        if (peer2 == NULL) {
                /* peer table takes my ref on peer */
                list_add_tail (&peer->ibp_list, kibnal_nid2peerlist(nid));
                LASSERT (peer->ibp_connecting == 0);
        } else {
                kibnal_peer_decref(peer);
                peer = peer2;

                if (peer->ibp_connecting != 0 &&
                    peer->ibp_nid < kibnal_data.kib_ni->ni_nid) {
                        /* Resolve concurrent connection attempts in favour of
                         * the higher NID */
                        write_unlock_irqrestore(&kibnal_data.kib_global_lock, 
                                                flags);
                        kibnal_conn_decref(conn);
                        kibnal_reject(nid, cep, IBNAL_REJECT_CONN_RACE);
                        return -EALREADY;
                }
        }

        kibnal_peer_addref(peer); /* +1 ref for conn */
        peer->ibp_accepting++;

        kibnal_set_conn_state(conn, IBNAL_CONN_CONNECTING);
        conn->ibc_peer = peer;
        conn->ibc_incarnation = msg->ibm_srcstamp;
        conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;
        conn->ibc_reserved_credits = IBNAL_MSG_QUEUE_SIZE;
        LASSERT (conn->ibc_credits + conn->ibc_reserved_credits
                 <= IBNAL_RX_MSGS);

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        *connp = conn;
        return 0;
}

void
kibnal_listen_callback(IB_HANDLE cep, CM_CONN_INFO *info, void *arg)
{

        CM_REQUEST_INFO  *req = &info->Info.Request;
        CM_REPLY_INFO    *rep;
        kib_conn_t       *conn;
        FSTATUS           frc;
        int               rc;
        
        LASSERT(arg == NULL); /* no conn yet for passive */

        CDEBUG(D_NET, "%x\n", info->Status);
        
        if (info->Status == FCM_CONNECT_CANCEL) {
                up(&kibnal_data.kib_listener_signal);
                return;
        }
        
        LASSERT (info->Status == FCM_CONNECT_REQUEST);

        rc = kibnal_accept(&conn, cep, (kib_msg_t *)req->PrivateData, 
                           CM_REQUEST_INFO_USER_LEN);
        if (rc != 0)                   /* kibnal_accept has rejected */
                return;

        conn->ibc_cvars->cv_path = req->PathInfo.Path;
        
        rc = kibnal_conn_rts(conn, 
                             req->CEPInfo.QPN, 
                             req->CEPInfo.OfferedInitiatorDepth,
                             req->CEPInfo.OfferedResponderResources,
                             req->CEPInfo.StartingPSN);
        if (rc != 0) {
                kibnal_reject(conn->ibc_peer->ibp_nid, cep, 
                              IBNAL_REJECT_NO_RESOURCES);
                kibnal_connreq_done(conn, IBNAL_CONN_PASSIVE, -ECONNABORTED);
                return;
        }

        memset(&conn->ibc_cvars->cv_cmci, 0, sizeof(conn->ibc_cvars->cv_cmci));
        rep = &conn->ibc_cvars->cv_cmci.Info.Reply;

        rep->QPN                   = conn->ibc_cvars->cv_qpattrs.QPNumber;
        rep->QKey                  = conn->ibc_cvars->cv_qpattrs.Qkey;
        rep->StartingPSN           = conn->ibc_cvars->cv_qpattrs.RecvPSN;
        rep->EndToEndFlowControl   = conn->ibc_cvars->cv_qpattrs.FlowControl;
        rep->ArbInitiatorDepth     = conn->ibc_cvars->cv_qpattrs.InitiatorDepth;
        rep->ArbResponderResources = conn->ibc_cvars->cv_qpattrs.ResponderResources;
        rep->TargetAckDelay        = kibnal_data.kib_hca_attrs.LocalCaAckDelay;
        rep->FailoverAccepted      = IBNAL_FAILOVER_ACCEPTED;
        rep->RnRRetryCount         = req->CEPInfo.RnrRetryCount;
        
        CLASSERT (CM_REPLY_INFO_USER_LEN >=
                  offsetof(kib_msg_t, ibm_u) + sizeof(kib_connparams_t));

        kibnal_pack_connmsg((kib_msg_t *)rep->PrivateData,
                            conn->ibc_version,
                            CM_REPLY_INFO_USER_LEN,
                            IBNAL_MSG_CONNACK,
                            conn->ibc_peer->ibp_nid, conn->ibc_incarnation);

        LASSERT (conn->ibc_cep == NULL);
        kibnal_set_conn_state(conn, IBNAL_CONN_CONNECTING);

        frc = iba_cm_accept(cep, 
                            &conn->ibc_cvars->cv_cmci,
                            NULL,
                            kibnal_cm_passive_callback, conn, 
                            &conn->ibc_cep);

        if (frc == FSUCCESS || frc == FPENDING)
                return;
        
        CERROR("iba_cm_accept(%s) failed: %d\n", 
               libcfs_nid2str(conn->ibc_peer->ibp_nid), frc);
        kibnal_connreq_done(conn, IBNAL_CONN_PASSIVE, -ECONNABORTED);
}

void
kibnal_check_connreply(kib_conn_t *conn, CM_REPLY_INFO *rep)
{
        kib_msg_t   *msg = (kib_msg_t *)rep->PrivateData;
        lnet_nid_t   nid = conn->ibc_peer->ibp_nid;
        FSTATUS      frc;
        int          rc;

        rc = kibnal_unpack_msg(msg, conn->ibc_version, CM_REPLY_INFO_USER_LEN);
        if (rc != 0) {
                CERROR ("Error %d unpacking connack from %s\n",
                        rc, libcfs_nid2str(nid));
                kibnal_reject(nid, conn->ibc_cep, IBNAL_REJECT_FATAL);
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EPROTO);
                return;
        }
                        
        if (msg->ibm_type != IBNAL_MSG_CONNACK) {
                CERROR("Bad connack request type %d (%d expected) from %s\n",
                       msg->ibm_type, IBNAL_MSG_CONNREQ,
                       libcfs_nid2str(msg->ibm_srcnid));
                kibnal_reject(nid, conn->ibc_cep, IBNAL_REJECT_FATAL);
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EPROTO);
                return;
        }

        if (msg->ibm_srcnid != conn->ibc_peer->ibp_nid ||
            msg->ibm_dstnid != kibnal_data.kib_ni->ni_nid ||
            msg->ibm_dststamp != kibnal_data.kib_incarnation) {
                CERROR("Stale connack from %s(%s): %s(%s), "LPX64"("LPX64")\n",
                       libcfs_nid2str(msg->ibm_srcnid), 
                       libcfs_nid2str(conn->ibc_peer->ibp_nid),
                       libcfs_nid2str(msg->ibm_dstnid),
                       libcfs_nid2str(kibnal_data.kib_ni->ni_nid),
                       msg->ibm_dststamp, kibnal_data.kib_incarnation);
                kibnal_reject(nid, conn->ibc_cep, IBNAL_REJECT_FATAL);
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -ESTALE);
                return;
        }
        
        if (msg->ibm_u.connparams.ibcp_queue_depth != IBNAL_MSG_QUEUE_SIZE ||
            msg->ibm_u.connparams.ibcp_max_msg_size > IBNAL_MSG_SIZE ||
            msg->ibm_u.connparams.ibcp_max_frags > IBNAL_MAX_RDMA_FRAGS) {
                CERROR("Reject %s: q %d sz %d frag %d, (%d %d %d expected)\n",
                       libcfs_nid2str(msg->ibm_srcnid), 
                       msg->ibm_u.connparams.ibcp_queue_depth,
                       msg->ibm_u.connparams.ibcp_max_msg_size,
                       msg->ibm_u.connparams.ibcp_max_frags,
                       IBNAL_MSG_QUEUE_SIZE,
                       IBNAL_MSG_SIZE,
                       IBNAL_MAX_RDMA_FRAGS);
                kibnal_reject(nid, conn->ibc_cep, IBNAL_REJECT_FATAL);
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EPROTO);
                return;
        }
                        
        CDEBUG(D_NET, "Connection %s REP_RECEIVED.\n",
               libcfs_nid2str(conn->ibc_peer->ibp_nid));

        conn->ibc_incarnation = msg->ibm_srcstamp;
        conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;
        conn->ibc_reserved_credits = IBNAL_MSG_QUEUE_SIZE;
        LASSERT (conn->ibc_credits + conn->ibc_reserved_credits
                 <= IBNAL_RX_MSGS);

        rc = kibnal_conn_rts(conn, 
                             rep->QPN,
                             rep->ArbInitiatorDepth,
                             rep->ArbResponderResources,
                             rep->StartingPSN);
        if (rc != 0) {
                kibnal_reject(nid, conn->ibc_cep, IBNAL_REJECT_NO_RESOURCES);
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EIO);
                return;
        }

        memset(&conn->ibc_cvars->cv_cmci, 0, sizeof(conn->ibc_cvars->cv_cmci));
        
        frc = iba_cm_accept(conn->ibc_cep, 
                            &conn->ibc_cvars->cv_cmci, 
                            NULL, NULL, NULL, NULL);

        if (frc == FCM_CONNECT_ESTABLISHED) {
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, 0);
                return;
        }
        
        CERROR("Connection %s CMAccept failed: %d\n",
               libcfs_nid2str(conn->ibc_peer->ibp_nid), frc);
        kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -ECONNABORTED);
}

void
kibnal_cm_active_callback(IB_HANDLE cep, CM_CONN_INFO *info, void *arg)
{
        kib_conn_t       *conn = arg;

        CDEBUG(D_NET, "status 0x%x\n", info->Status);

        switch (info->Status) {
        default:
                CERROR("unknown status %d on Connection %s\n", 
                       info->Status, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                LBUG();
                break;

        case FCM_CONNECT_TIMEOUT:
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -ETIMEDOUT);
                break;
                
        case FCM_CONNECT_REJECT:
                kibnal_check_connreject(conn, IBNAL_CONN_ACTIVE,
                                        &info->Info.Reject);
                break;

        case FCM_CONNECT_REPLY:
                kibnal_check_connreply(conn, &info->Info.Reply);
                break;

        case FCM_DISCONNECT_REQUEST:
        case FCM_DISCONNECT_REPLY:
        case FCM_DISCONNECTED:
                kibnal_cm_disconnect_callback(conn, info);
                break;
        }
}

void
dump_path_records(PATH_RESULTS *results)
{
        IB_PATH_RECORD *path;
        int i;

        for (i = 0; i < results->NumPathRecords; i++) {
                path = &results->PathRecords[i];
                CDEBUG(D_NET, "%d: sgid "LPX64":"LPX64" dgid "
                       LPX64":"LPX64" pkey %x\n",
                       i,
                       path->SGID.Type.Global.SubnetPrefix,
                       path->SGID.Type.Global.InterfaceID,
                       path->DGID.Type.Global.SubnetPrefix,
                       path->DGID.Type.Global.InterfaceID,
                       path->P_Key);
        }
}

void
kibnal_pathreq_callback (void *arg, QUERY *qry, 
                         QUERY_RESULT_VALUES *qrslt)
{
        IB_CA_ATTRIBUTES  *ca_attr = &kibnal_data.kib_hca_attrs;
        kib_conn_t        *conn = arg;
        CM_REQUEST_INFO   *req = &conn->ibc_cvars->cv_cmci.Info.Request;
        PATH_RESULTS      *path = (PATH_RESULTS *)qrslt->QueryResult;
        FSTATUS            frc;
        
        if (qrslt->Status != FSUCCESS || 
            qrslt->ResultDataSize < sizeof(*path)) {
                CDEBUG (D_NETERROR, "pathreq %s failed: status %d data size %d\n", 
                        libcfs_nid2str(conn->ibc_peer->ibp_nid),
                        qrslt->Status, qrslt->ResultDataSize);
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EHOSTUNREACH);
                return;
        }

        if (path->NumPathRecords < 1) {
                CDEBUG (D_NETERROR, "pathreq %s failed: no path records\n",
                        libcfs_nid2str(conn->ibc_peer->ibp_nid));
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EHOSTUNREACH);
                return;
        }

        //dump_path_records(path);
        conn->ibc_cvars->cv_path = path->PathRecords[0];

        LASSERT (conn->ibc_cep == NULL);

        conn->ibc_cep = kibnal_create_cep(conn->ibc_peer->ibp_nid);
        if (conn->ibc_cep == NULL) {
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -ENOMEM);
                return;
        }

        memset(req, 0, sizeof(*req));
        req->SID                               = conn->ibc_cvars->cv_svcrec.RID.ServiceID;
        req->CEPInfo.CaGUID                    = kibnal_data.kib_hca_guids[kibnal_data.kib_hca_idx];
        req->CEPInfo.EndToEndFlowControl       = IBNAL_EE_FLOW;
        req->CEPInfo.PortGUID                  = conn->ibc_cvars->cv_path.SGID.Type.Global.InterfaceID;
        req->CEPInfo.RetryCount                = IBNAL_RETRY;
        req->CEPInfo.RnrRetryCount             = IBNAL_RNR_RETRY;
        req->CEPInfo.AckTimeout                = IBNAL_ACK_TIMEOUT;
        req->CEPInfo.StartingPSN               = IBNAL_STARTING_PSN;
        req->CEPInfo.QPN                       = conn->ibc_cvars->cv_qpattrs.QPNumber;
        req->CEPInfo.QKey                      = conn->ibc_cvars->cv_qpattrs.Qkey;
        req->CEPInfo.OfferedResponderResources = ca_attr->MaxQPResponderResources;
        req->CEPInfo.OfferedInitiatorDepth     = ca_attr->MaxQPInitiatorDepth;
        req->PathInfo.bSubnetLocal             = IBNAL_LOCAL_SUB;
        req->PathInfo.Path                     = conn->ibc_cvars->cv_path;

        CLASSERT (CM_REQUEST_INFO_USER_LEN >=
                  offsetof(kib_msg_t, ibm_u) + sizeof(kib_connparams_t));

        kibnal_pack_connmsg((kib_msg_t *)req->PrivateData, 
                            conn->ibc_version,
                            CM_REQUEST_INFO_USER_LEN,
                            IBNAL_MSG_CONNREQ, 
                            conn->ibc_peer->ibp_nid, 0);

        if (the_lnet.ln_testprotocompat != 0) {
                /* single-shot proto test */
                LNET_LOCK();
                if ((the_lnet.ln_testprotocompat & 1) != 0) {
                        ((kib_msg_t *)req->PrivateData)->ibm_version++;
                        the_lnet.ln_testprotocompat &= ~1;
                }
                if ((the_lnet.ln_testprotocompat & 2) != 0) {
                        ((kib_msg_t *)req->PrivateData)->ibm_magic =
                                LNET_PROTO_MAGIC;
                        the_lnet.ln_testprotocompat &= ~2;
                }
                LNET_UNLOCK();
        }

        /* Flag I'm getting involved with the CM... */
        kibnal_set_conn_state(conn, IBNAL_CONN_CONNECTING);

        /* cm callback gets my conn ref */
        frc = iba_cm_connect(conn->ibc_cep, req, 
                             kibnal_cm_active_callback, conn);
        if (frc == FPENDING || frc == FSUCCESS)
                return;
        
        CERROR ("Connect %s failed: %d\n", 
                libcfs_nid2str(conn->ibc_peer->ibp_nid), frc);
        kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EHOSTUNREACH);
}

void
kibnal_dump_service_records(SERVICE_RECORD_RESULTS *results)
{
        IB_SERVICE_RECORD *svc;
        int i;

        for (i = 0; i < results->NumServiceRecords; i++) {
                svc = &results->ServiceRecords[i];
                CDEBUG(D_NET, "%d: sid "LPX64" gid "LPX64":"LPX64" pkey %x\n",
                       i,
                       svc->RID.ServiceID,
                       svc->RID.ServiceGID.Type.Global.SubnetPrefix,
                       svc->RID.ServiceGID.Type.Global.InterfaceID,
                       svc->RID.ServiceP_Key);
        }
}

void
kibnal_service_get_callback (void *arg, QUERY *qry, 
                             QUERY_RESULT_VALUES *qrslt)
{
        kib_conn_t              *conn = arg;
        SERVICE_RECORD_RESULTS  *svc;
        FSTATUS                  frc;

        if (qrslt->Status != FSUCCESS || 
            qrslt->ResultDataSize < sizeof(*svc)) {
                CDEBUG (D_NETERROR, "Lookup %s failed: status %d data size %d\n", 
                        libcfs_nid2str(conn->ibc_peer->ibp_nid),
                        qrslt->Status, qrslt->ResultDataSize);
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EHOSTUNREACH);
                return;
        }

        svc = (SERVICE_RECORD_RESULTS *)qrslt->QueryResult;
        if (svc->NumServiceRecords < 1) {
                CDEBUG (D_NETERROR, "lookup %s failed: no service records\n",
                        libcfs_nid2str(conn->ibc_peer->ibp_nid));
                kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EHOSTUNREACH);
                return;
        }

        //kibnal_dump_service_records(svc);
        conn->ibc_cvars->cv_svcrec = svc->ServiceRecords[0];

        qry = &conn->ibc_cvars->cv_query;
        memset(qry, 0, sizeof(*qry));

        qry->OutputType = OutputTypePathRecord;
        qry->InputType = InputTypePortGuidPair;

        qry->InputValue.PortGuidPair.SourcePortGuid = 
                kibnal_data.kib_port_guid;
        qry->InputValue.PortGuidPair.DestPortGuid  = 
                conn->ibc_cvars->cv_svcrec.RID.ServiceGID.Type.Global.InterfaceID;

        /* kibnal_pathreq_callback gets my conn ref */
        frc = iba_sd_query_port_fabric_info(kibnal_data.kib_sd,
                                            kibnal_data.kib_port_guid,
                                            qry, 
                                            kibnal_pathreq_callback,
                                            &kibnal_data.kib_sdretry,
                                            conn);
        if (frc == FPENDING)
                return;

        CERROR ("pathreq %s failed: %d\n", 
                libcfs_nid2str(conn->ibc_peer->ibp_nid), frc);
        kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EHOSTUNREACH);
}

void
kibnal_connect_peer (kib_peer_t *peer)
{
        QUERY                     *qry;
        FSTATUS                    frc;
        kib_conn_t                *conn;

        LASSERT (peer->ibp_connecting != 0);

        conn = kibnal_create_conn(peer->ibp_nid, peer->ibp_version);
        if (conn == NULL) {
                CERROR ("Can't allocate conn\n");
                kibnal_peer_connect_failed(peer, IBNAL_CONN_ACTIVE, -ENOMEM);
                return;
        }

        conn->ibc_peer = peer;
        kibnal_peer_addref(peer);

        qry = &conn->ibc_cvars->cv_query;
        memset(qry, 0, sizeof(*qry));

        qry->OutputType = OutputTypeServiceRecord;
        qry->InputType = InputTypeServiceRecord;

        qry->InputValue.ServiceRecordValue.ComponentMask = 
                KIBNAL_SERVICE_KEY_MASK;
        kibnal_set_service_keys(
                &qry->InputValue.ServiceRecordValue.ServiceRecord, 
                peer->ibp_nid);

        /* kibnal_service_get_callback gets my conn ref */
        frc = iba_sd_query_port_fabric_info(kibnal_data.kib_sd,
                                            kibnal_data.kib_port_guid,
                                            qry,
                                            kibnal_service_get_callback,
                                            &kibnal_data.kib_sdretry, 
                                            conn);
        if (frc == FPENDING)
                return;

        CERROR("Lookup %s failed: %d\n", libcfs_nid2str(peer->ibp_nid), frc);
        kibnal_connreq_done(conn, IBNAL_CONN_ACTIVE, -EHOSTUNREACH);
}

int
kibnal_check_txs (kib_conn_t *conn, struct list_head *txs)
{
        kib_tx_t          *tx;
        struct list_head  *ttmp;
        int                timed_out = 0;

        spin_lock(&conn->ibc_lock);

        list_for_each (ttmp, txs) {
                tx = list_entry (ttmp, kib_tx_t, tx_list);

                if (txs == &conn->ibc_active_txs) {
                        LASSERT (!tx->tx_queued);
                        LASSERT (tx->tx_waiting || tx->tx_sending != 0);
                } else {
                        LASSERT (tx->tx_queued);
                }

                if (time_after_eq (jiffies, tx->tx_deadline)) {
                        timed_out = 1;
                        break;
                }
        }

        spin_unlock(&conn->ibc_lock);
        return timed_out;
}

int
kibnal_conn_timed_out (kib_conn_t *conn)
{
        return  kibnal_check_txs(conn, &conn->ibc_tx_queue) ||
                kibnal_check_txs(conn, &conn->ibc_tx_queue_rsrvd) ||
                kibnal_check_txs(conn, &conn->ibc_tx_queue_nocred) ||
                kibnal_check_txs(conn, &conn->ibc_active_txs);
}

void
kibnal_check_peers (int idx)
{
        rwlock_t          *rwlock = &kibnal_data.kib_global_lock;
        struct list_head  *peers = &kibnal_data.kib_peers[idx];
        struct list_head  *ptmp;
        kib_peer_t        *peer;
        kib_conn_t        *conn;
        struct list_head  *ctmp;
        unsigned long      flags;

 again:
        /* NB. We expect to have a look at all the peers and not find any
         * rdmas to time out, so we just use a shared lock while we
         * take a look... */
        read_lock_irqsave(rwlock, flags);

        list_for_each (ptmp, peers) {
                peer = list_entry (ptmp, kib_peer_t, ibp_list);

                if (peer->ibp_passivewait) {
                        LASSERT (list_empty(&peer->ibp_conns));
                        
                        if (!time_after_eq(jiffies, 
                                           peer->ibp_passivewait_deadline))
                                continue;
                        
                        kibnal_peer_addref(peer); /* ++ ref for me... */
                        read_unlock_irqrestore(rwlock, flags);

                        kibnal_peer_connect_failed(peer, IBNAL_CONN_WAITING,
                                                   -ETIMEDOUT);
                        kibnal_peer_decref(peer); /* ...until here */
                        
                        /* start again now I've dropped the lock */
                        goto again;
                }

                list_for_each (ctmp, &peer->ibp_conns) {
                        conn = list_entry (ctmp, kib_conn_t, ibc_list);

                        LASSERT (conn->ibc_state == IBNAL_CONN_ESTABLISHED);

                        /* In case we have enough credits to return via a
                         * NOOP, but there were no non-blocking tx descs
                         * free to do it last time... */
                        kibnal_check_sends(conn);

                        if (!kibnal_conn_timed_out(conn))
                                continue;

                        /* Handle timeout by closing the whole connection.  We
                         * can only be sure RDMA activity has ceased once the
                         * QP has been modified. */
                        
                        kibnal_conn_addref(conn); /* 1 ref for me... */

                        read_unlock_irqrestore(rwlock, flags);

                        CERROR("Timed out RDMA with %s\n",
                               libcfs_nid2str(peer->ibp_nid));

                        kibnal_close_conn (conn, -ETIMEDOUT);
                        kibnal_conn_decref(conn); /* ...until here */

                        /* start again now I've dropped the lock */
                        goto again;
                }
        }

        read_unlock_irqrestore(rwlock, flags);
}

void
kibnal_disconnect_conn (kib_conn_t *conn)
{
        FSTATUS       frc;

        LASSERT (conn->ibc_state == IBNAL_CONN_DISCONNECTING);

        kibnal_conn_disconnected(conn);
                
        frc = iba_cm_disconnect(conn->ibc_cep, NULL, NULL);
        switch (frc) {
        case FSUCCESS:
                break;
                
        case FINSUFFICIENT_RESOURCES:
                CERROR("ENOMEM disconnecting %s\n",
                       libcfs_nid2str(conn->ibc_peer->ibp_nid));
                /* This might cause the module to become unloadable since the
                 * FCM_DISCONNECTED callback is still outstanding */
                break;
                
        default:
                CERROR("Unexpected error disconnecting %s: %d\n",
                       libcfs_nid2str(conn->ibc_peer->ibp_nid), frc);
                LBUG();
        }

        kibnal_peer_notify(conn->ibc_peer);
}

int
kibnal_connd (void *arg)
{
        wait_queue_t       wait;
        unsigned long      flags;
        kib_conn_t        *conn;
        kib_peer_t        *peer;
        int                timeout;
        int                i;
        int                did_something;
        int                peer_index = 0;
        unsigned long      deadline = jiffies;
        
        cfs_daemonize ("kibnal_connd");
        cfs_block_allsigs ();

        init_waitqueue_entry (&wait, current);

        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);

        while (!kibnal_data.kib_shutdown) {
                did_something = 0;

                if (!list_empty (&kibnal_data.kib_connd_zombies)) {
                        conn = list_entry (kibnal_data.kib_connd_zombies.next,
                                           kib_conn_t, ibc_list);
                        list_del (&conn->ibc_list);
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);
                        did_something = 1;

                        kibnal_destroy_conn(conn);

                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                }

                if (!list_empty (&kibnal_data.kib_connd_conns)) {
                        conn = list_entry (kibnal_data.kib_connd_conns.next,
                                           kib_conn_t, ibc_list);
                        list_del (&conn->ibc_list);
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);
                        did_something = 1;

                        kibnal_disconnect_conn(conn);
                        kibnal_conn_decref(conn);
                        
                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                }

                if (!list_empty (&kibnal_data.kib_connd_peers)) {
                        peer = list_entry (kibnal_data.kib_connd_peers.next,
                                           kib_peer_t, ibp_connd_list);
                        
                        list_del_init (&peer->ibp_connd_list);
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);
                        did_something = 1;

                        kibnal_connect_peer (peer);
                        kibnal_peer_decref (peer);

                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                }

                /* careful with the jiffy wrap... */
                while ((timeout = (int)(deadline - jiffies)) <= 0) {
                        const int n = 4;
                        const int p = 1;
                        int       chunk = kibnal_data.kib_peer_hash_size;
                        
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

                        /* Time to check for RDMA timeouts on a few more
                         * peers: I do checks every 'p' seconds on a
                         * proportion of the peer table and I need to check
                         * every connection 'n' times within a timeout
                         * interval, to ensure I detect a timeout on any
                         * connection within (n+1)/n times the timeout
                         * interval. */

                        if (*kibnal_tunables.kib_timeout > n * p)
                                chunk = (chunk * n * p) / 
                                        *kibnal_tunables.kib_timeout;
                        if (chunk == 0)
                                chunk = 1;

                        for (i = 0; i < chunk; i++) {
                                kibnal_check_peers (peer_index);
                                peer_index = (peer_index + 1) % 
                                             kibnal_data.kib_peer_hash_size;
                        }

                        deadline += p * HZ;
                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                        did_something = 1;
                }

                if (did_something)
                        continue;

                spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

                set_current_state (TASK_INTERRUPTIBLE);
                add_wait_queue (&kibnal_data.kib_connd_waitq, &wait);

                if (!kibnal_data.kib_shutdown &&
                    list_empty (&kibnal_data.kib_connd_conns) &&
                    list_empty (&kibnal_data.kib_connd_peers))
                        schedule_timeout (timeout);

                set_current_state (TASK_RUNNING);
                remove_wait_queue (&kibnal_data.kib_connd_waitq, &wait);

                spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
        }

        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

        kibnal_thread_fini ();
        return (0);
}


void 
kibnal_hca_async_callback (void *hca_arg, IB_EVENT_RECORD *ev)
{
        /* XXX flesh out.  this seems largely for async errors */
        CERROR("type: %d code: %u\n", ev->EventType, ev->EventCode);
}

void
kibnal_hca_callback (void *hca_arg, void *cq_arg)
{
        unsigned long flags;

        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
        kibnal_data.kib_ready = 1;
        wake_up(&kibnal_data.kib_sched_waitq);
        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock, flags);
}

int
kibnal_scheduler(void *arg)
{
        long               id = (long)arg;
        wait_queue_t       wait;
        char               name[16];
        FSTATUS            frc;
        FSTATUS            frc2;
        IB_WORK_COMPLETION wc;
        kib_rx_t          *rx;
        unsigned long      flags;
        __u64              rxseq = 0;
        int                busy_loops = 0;

        snprintf(name, sizeof(name), "kibnal_sd_%02ld", id);
        cfs_daemonize(name);
        cfs_block_allsigs();

        init_waitqueue_entry(&wait, current);

        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);

        while (!kibnal_data.kib_shutdown) {
                if (busy_loops++ >= IBNAL_RESCHED) {
                        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock,
                                               flags);

                        our_cond_resched();
                        busy_loops = 0;
                        
                        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
                }

                if (kibnal_data.kib_ready &&
                    !kibnal_data.kib_checking_cq) {
                        /* take ownership of completion polling */
                        kibnal_data.kib_checking_cq = 1;
                        /* Assume I'll exhaust the CQ */
                        kibnal_data.kib_ready = 0;
                        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock,
                                               flags);
                        
                        frc = iba_poll_cq(kibnal_data.kib_cq, &wc);
                        if (frc == FNOT_DONE) {
                                /* CQ empty */
                                frc2 = iba_rearm_cq(kibnal_data.kib_cq,
                                                    CQEventSelNextWC);
                                LASSERT (frc2 == FSUCCESS);
                        }
                        
                        if (frc == FSUCCESS &&
                            kibnal_wreqid2type(wc.WorkReqId) == IBNAL_WID_RX) {
                                rx = (kib_rx_t *)kibnal_wreqid2ptr(wc.WorkReqId);
                                
                                /* Grab the RX sequence number NOW before
                                 * anyone else can get an RX completion */
                                rxseq = rx->rx_conn->ibc_rxseq++;
                        }
                                
                        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
                        /* give up ownership of completion polling */
                        kibnal_data.kib_checking_cq = 0;

                        if (frc == FNOT_DONE)
                                continue;

                        LASSERT (frc == FSUCCESS);
                        /* Assume there's more: get another scheduler to check
                         * while I handle this completion... */

                        kibnal_data.kib_ready = 1;
                        wake_up(&kibnal_data.kib_sched_waitq);

                        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock,
                                               flags);

                        switch (kibnal_wreqid2type(wc.WorkReqId)) {
                        case IBNAL_WID_RX:
                                kibnal_rx_complete(&wc, rxseq);
                                break;
                                
                        case IBNAL_WID_TX:
                                kibnal_tx_complete(&wc);
                                break;
                                
                        case IBNAL_WID_RDMA:
                                /* We only get RDMA completion notification if
                                 * it fails.  So we just ignore them completely
                                 * because...
                                 *
                                 * 1) If an RDMA fails, all subsequent work
                                 * items, including the final SEND will fail
                                 * too, so I'm still guaranteed to notice that
                                 * this connection is hosed.
                                 *
                                 * 2) It's positively dangerous to look inside
                                 * the tx descriptor obtained from an RDMA work
                                 * item.  As soon as I drop the kib_sched_lock,
                                 * I give a scheduler on another CPU a chance
                                 * to get the final SEND completion, so the tx
                                 * descriptor can get freed as I inspect it. */
                                CERROR ("RDMA failed: %d\n", wc.Status);
                                break;

                        default:
                                LBUG();
                        }
                        
                        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
                        continue;
                }

                /* Nothing to do; sleep... */

                set_current_state(TASK_INTERRUPTIBLE);
                add_wait_queue_exclusive(&kibnal_data.kib_sched_waitq, &wait);
                spin_unlock_irqrestore(&kibnal_data.kib_sched_lock,
                                       flags);

                schedule();

                remove_wait_queue(&kibnal_data.kib_sched_waitq, &wait);
                set_current_state(TASK_RUNNING);
                spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
        }

        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock, flags);

        kibnal_thread_fini();
        return (0);
}
