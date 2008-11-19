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
 * lnet/klnds/openiblnd/openiblnd_cb.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "openiblnd.h"

/*
 *  LIB functions follow
 *
 */
void
kibnal_schedule_tx_done (kib_tx_t *tx)
{
        unsigned long flags;

        spin_lock_irqsave (&kibnal_data.kib_sched_lock, flags);

        list_add_tail(&tx->tx_list, &kibnal_data.kib_sched_txq);
        wake_up (&kibnal_data.kib_sched_waitq);

        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock, flags);
}

void
kibnal_tx_done (kib_tx_t *tx)
{
        lnet_msg_t      *lntmsg[2];
        unsigned long    flags;
        int              i;
        int              rc;

        LASSERT (tx->tx_sending == 0);          /* mustn't be awaiting callback */
        LASSERT (!tx->tx_passive_rdma_wait);    /* mustn't be awaiting RDMA */

        if (in_interrupt()) {
                /* can't deregister memory/flush FMAs/finalize in IRQ context... */
                kibnal_schedule_tx_done(tx);
                return;
        }

        switch (tx->tx_mapped) {
        default:
                LBUG();

        case KIB_TX_UNMAPPED:
                break;
                
        case KIB_TX_MAPPED:
                rc = ib_memory_deregister(tx->tx_md.md_handle.mr);
                LASSERT (rc == 0);
                tx->tx_mapped = KIB_TX_UNMAPPED;
                break;

#if IBNAL_FMR
        case KIB_TX_MAPPED_FMR:
                rc = ib_fmr_deregister(tx->tx_md.md_handle.fmr);
                LASSERT (rc == 0);

#ifndef USING_TSAPI
                /* Somewhat belt-and-braces since the tx's conn has closed if
                 * this was a passive RDMA waiting to complete... */
                if (tx->tx_status != 0)
                        ib_fmr_pool_force_flush(kibnal_data.kib_fmr_pool);
#endif
                tx->tx_mapped = KIB_TX_UNMAPPED;
                break;
#endif
        }

        /* tx may have up to 2 ptlmsgs to finalise */
        lntmsg[0] = tx->tx_lntmsg[0]; tx->tx_lntmsg[0] = NULL;
        lntmsg[1] = tx->tx_lntmsg[1]; tx->tx_lntmsg[1] = NULL;
        rc = tx->tx_status;

        if (tx->tx_conn != NULL) {
                kibnal_conn_decref(tx->tx_conn);
                tx->tx_conn = NULL;
        }

        tx->tx_nsp = 0;
        tx->tx_passive_rdma = 0;
        tx->tx_status = 0;

        spin_lock_irqsave (&kibnal_data.kib_tx_lock, flags);

        list_add_tail (&tx->tx_list, &kibnal_data.kib_idle_txs);

        spin_unlock_irqrestore (&kibnal_data.kib_tx_lock, flags);

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
        unsigned long  flags;
        kib_tx_t      *tx;
        
        spin_lock_irqsave (&kibnal_data.kib_tx_lock, flags);

        if (list_empty (&kibnal_data.kib_idle_txs)) {
                spin_unlock_irqrestore (&kibnal_data.kib_tx_lock, flags);
                return NULL;
        }

        tx = list_entry (kibnal_data.kib_idle_txs.next, kib_tx_t, tx_list);
        list_del (&tx->tx_list);

        /* Allocate a new passive RDMA completion cookie.  It might not be
         * needed, but we've got a lock right now and we're unlikely to
         * wrap... */
        tx->tx_passive_rdma_cookie = kibnal_data.kib_next_tx_cookie++;

        spin_unlock_irqrestore (&kibnal_data.kib_tx_lock, flags);

        LASSERT (tx->tx_mapped == KIB_TX_UNMAPPED);
        LASSERT (tx->tx_nsp == 0);
        LASSERT (tx->tx_sending == 0);
        LASSERT (tx->tx_status == 0);
        LASSERT (tx->tx_conn == NULL);
        LASSERT (!tx->tx_passive_rdma);
        LASSERT (!tx->tx_passive_rdma_wait);
        LASSERT (tx->tx_lntmsg[0] == NULL);
        LASSERT (tx->tx_lntmsg[1] == NULL);

        return tx;
}

void
kibnal_complete_passive_rdma(kib_conn_t *conn, __u64 cookie, int status)
{
        struct list_head *ttmp;
        unsigned long     flags;
        int               idle;

        spin_lock_irqsave (&conn->ibc_lock, flags);

        list_for_each (ttmp, &conn->ibc_active_txs) {
                kib_tx_t *tx = list_entry(ttmp, kib_tx_t, tx_list);

                LASSERT (tx->tx_passive_rdma ||
                         !tx->tx_passive_rdma_wait);

                LASSERT (tx->tx_passive_rdma_wait ||
                         tx->tx_sending != 0);

                if (!tx->tx_passive_rdma_wait ||
                    tx->tx_passive_rdma_cookie != cookie)
                        continue;

                CDEBUG(D_NET, "Complete %p "LPD64": %d\n", tx, cookie, status);

                /* XXX Set mlength of reply here */

                tx->tx_status = status;
                tx->tx_passive_rdma_wait = 0;
                idle = (tx->tx_sending == 0);

                if (idle)
                        list_del (&tx->tx_list);

                spin_unlock_irqrestore (&conn->ibc_lock, flags);

                /* I could be racing with tx callbacks.  It's whoever
                 * _makes_ tx idle that frees it */
                if (idle)
                        kibnal_tx_done (tx);
                return;
        }
                
        spin_unlock_irqrestore (&conn->ibc_lock, flags);

        CERROR ("Unmatched (late?) RDMA completion "LPX64" from %s\n",
                cookie, libcfs_nid2str(conn->ibc_peer->ibp_nid));
}

void
kibnal_post_rx (kib_rx_t *rx, int credit, int rsrvd_credit)
{
        kib_conn_t   *conn = rx->rx_conn;
        int           rc;
        unsigned long flags;

        LASSERT(!rsrvd_credit ||
                conn->ibc_version != IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD);

        rx->rx_gl = (struct ib_gather_scatter) {
                .address = rx->rx_vaddr,
                .length  = IBNAL_MSG_SIZE,
                .key     = conn->ibc_rx_pages->ibp_lkey,
        };

        rx->rx_sp = (struct ib_receive_param) {
                .work_request_id        = kibnal_ptr2wreqid(rx, 1),
                .scatter_list           = &rx->rx_gl,
                .num_scatter_entries    = 1,
                .device_specific        = NULL,
                .signaled               = 1,
        };

        LASSERT (conn->ibc_state >= IBNAL_CONN_ESTABLISHED);
        LASSERT (rx->rx_nob >= 0);              /* not posted */
        rx->rx_nob = -1;                        /* is now */
        mb();

        if (conn->ibc_state != IBNAL_CONN_ESTABLISHED)
                rc = -ECONNABORTED;
        else
                rc = kibnal_ib_receive(conn->ibc_qp, &rx->rx_sp);

        if (rc == 0) {
                if (credit || rsrvd_credit) {
                        spin_lock_irqsave(&conn->ibc_lock, flags);

                        if (credit)
                                conn->ibc_outstanding_credits++;
                        if (rsrvd_credit)
                                conn->ibc_reserved_credits++;
                        
                        spin_unlock_irqrestore(&conn->ibc_lock, flags);

                        kibnal_check_sends(conn);
                }
                return;
        }

        if (conn->ibc_state == IBNAL_CONN_ESTABLISHED) {
                CERROR ("Error posting receive -> %s: %d\n",
                        libcfs_nid2str(conn->ibc_peer->ibp_nid), rc);
                kibnal_close_conn (rx->rx_conn, rc);
        } else {
                CDEBUG (D_NET, "Error posting receive -> %s: %d\n",
                        libcfs_nid2str(conn->ibc_peer->ibp_nid), rc);
        }

        /* Drop rx's ref */
        kibnal_conn_decref(conn);
}

void
kibnal_rx_callback (struct ib_cq_entry *e)
{
        kib_rx_t     *rx = (kib_rx_t *)kibnal_wreqid2ptr(e->work_request_id);
        kib_msg_t    *msg = rx->rx_msg;
        kib_conn_t   *conn = rx->rx_conn;
        int           credits;
        unsigned long flags;
        int           rc;
        int           err = -ECONNABORTED;

        CDEBUG (D_NET, "rx %p conn %p\n", rx, conn);
        LASSERT (rx->rx_nob < 0);               /* was posted */
        rx->rx_nob = 0;                         /* isn't now */
        mb();

        /* receives complete with error in any case after we've started
         * closing the QP */
        if (conn->ibc_state >= IBNAL_CONN_DEATHROW)
                goto failed;

        /* We don't post receives until the conn is established */
        LASSERT (conn->ibc_state == IBNAL_CONN_ESTABLISHED);

        if (e->status != IB_COMPLETION_STATUS_SUCCESS) {
                CERROR("Rx from %s failed: %d\n", 
                       libcfs_nid2str(conn->ibc_peer->ibp_nid), e->status);
                goto failed;
        }

        LASSERT (e->bytes_transferred >= 0);
        rx->rx_nob = e->bytes_transferred;
        mb();

        rc = kibnal_unpack_msg(msg, conn->ibc_version, rx->rx_nob);
        if (rc != 0) {
                CERROR ("Error %d unpacking rx from %s\n",
                        rc, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                goto failed;
        }

        if (!lnet_ptlcompat_matchnid(conn->ibc_peer->ibp_nid,
                                     msg->ibm_srcnid) ||
            !lnet_ptlcompat_matchnid(kibnal_data.kib_ni->ni_nid,
                                     msg->ibm_dstnid) ||
            msg->ibm_srcstamp != conn->ibc_incarnation ||
            msg->ibm_dststamp != kibnal_data.kib_incarnation) {
                CERROR ("Stale rx from %s\n",
                        libcfs_nid2str(conn->ibc_peer->ibp_nid));
                err = -ESTALE;
                goto failed;
        }

        /* Have I received credits that will let me send? */
        credits = msg->ibm_credits;
        if (credits != 0) {
                spin_lock_irqsave(&conn->ibc_lock, flags);
                conn->ibc_credits += credits;
                spin_unlock_irqrestore(&conn->ibc_lock, flags);
                
                kibnal_check_sends(conn);
        }

        switch (msg->ibm_type) {
        case IBNAL_MSG_NOOP:
                kibnal_post_rx (rx, 1, 0);
                return;

        case IBNAL_MSG_IMMEDIATE:
                break;
                
        case IBNAL_MSG_PUT_RDMA:
        case IBNAL_MSG_GET_RDMA:
                CDEBUG(D_NET, "%d RDMA: cookie "LPX64", key %x, addr "LPX64", nob %d\n",
                       msg->ibm_type, msg->ibm_u.rdma.ibrm_cookie,
                       msg->ibm_u.rdma.ibrm_desc.rd_key,
                       msg->ibm_u.rdma.ibrm_desc.rd_addr,
                       msg->ibm_u.rdma.ibrm_desc.rd_nob);
                break;
                
        case IBNAL_MSG_PUT_DONE:
        case IBNAL_MSG_GET_DONE:
                CDEBUG(D_NET, "%d DONE: cookie "LPX64", status %d\n",
                       msg->ibm_type, msg->ibm_u.completion.ibcm_cookie,
                       msg->ibm_u.completion.ibcm_status);

                kibnal_complete_passive_rdma (conn, 
                                              msg->ibm_u.completion.ibcm_cookie,
                                              msg->ibm_u.completion.ibcm_status);

                if (conn->ibc_version == IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD) {
                        kibnal_post_rx (rx, 1, 0);
                } else {
                        /* this reply buffer was pre-reserved */
                        kibnal_post_rx (rx, 0, 1);
                }
                return;
                        
        default:
                CERROR ("Bad msg type %x from %s\n",
                        msg->ibm_type, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                goto failed;
        }

        kibnal_peer_alive(conn->ibc_peer);

        /* schedule for kibnal_rx() in thread context */
        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
        
        list_add_tail (&rx->rx_list, &kibnal_data.kib_sched_rxq);
        wake_up (&kibnal_data.kib_sched_waitq);
        
        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock, flags);
        return;
        
 failed:
        CDEBUG(D_NET, "rx %p conn %p\n", rx, conn);
        kibnal_close_conn(conn, err);

        /* Don't re-post rx & drop its ref on conn */
        kibnal_conn_decref(conn);
}

void
kibnal_rx (kib_rx_t *rx)
{
        int          rc = 0;
        kib_msg_t   *msg = rx->rx_msg;

        switch (msg->ibm_type) {
        case IBNAL_MSG_GET_RDMA:
                rc = lnet_parse(kibnal_data.kib_ni, &msg->ibm_u.rdma.ibrm_hdr,
                                msg->ibm_srcnid, rx, 1);
                break;
                
        case IBNAL_MSG_PUT_RDMA:
                rc = lnet_parse(kibnal_data.kib_ni, &msg->ibm_u.rdma.ibrm_hdr,
                                msg->ibm_srcnid, rx, 1);
                break;

        case IBNAL_MSG_IMMEDIATE:
                rc = lnet_parse(kibnal_data.kib_ni, &msg->ibm_u.immediate.ibim_hdr,
                                msg->ibm_srcnid, rx, 0);
                break;

        default:
                LBUG();
                break;
        }

        if (rc < 0) {
                kibnal_close_conn(rx->rx_conn, rc);
                kibnal_post_rx (rx, 1, 0);
        }
}

#if 0
int
kibnal_kvaddr_to_phys (unsigned long vaddr, __u64 *physp)
{
        struct page *page;

        if (vaddr >= VMALLOC_START &&
            vaddr < VMALLOC_END)
                page = vmalloc_to_page ((void *)vaddr);
#ifdef CONFIG_HIGHMEM
        else if (vaddr >= PKMAP_BASE &&
                 vaddr < (PKMAP_BASE + LAST_PKMAP * PAGE_SIZE))
                page = vmalloc_to_page ((void *)vaddr);
        /* in 2.4 ^ just walks the page tables */
#endif
        else
                page = virt_to_page (vaddr);

        if (page == NULL ||
            !VALID_PAGE (page))
                return (-EFAULT);

        *physp = lnet_page2phys(page) + (vaddr & (PAGE_SIZE - 1));
        return (0);
}
#endif

int
kibnal_map_iov (kib_tx_t *tx, int access,
                unsigned int niov, struct iovec *iov, int offset, int nob)
                 
{
        void   *vaddr;
        int     rc;

        LASSERT (nob > 0);
        LASSERT (niov > 0);
        LASSERT (tx->tx_mapped == KIB_TX_UNMAPPED);

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

        vaddr = (void *)(((unsigned long)iov->iov_base) + offset);
        tx->tx_md.md_addr = (__u64)((unsigned long)vaddr);

        rc = ib_memory_register (kibnal_data.kib_pd,
                                 vaddr, nob,
                                 access,
                                 &tx->tx_md.md_handle.mr,
                                 &tx->tx_md.md_lkey,
                                 &tx->tx_md.md_rkey);
        
        if (rc != 0) {
                CERROR ("Can't map vaddr: %d\n", rc);
                return (rc);
        }

        tx->tx_mapped = KIB_TX_MAPPED;
        return (0);
}

int
kibnal_map_kiov (kib_tx_t *tx, int access,
                  int nkiov, lnet_kiov_t *kiov,
                  int offset, int nob)
{
#if IBNAL_FMR
        __u64                      *phys;
        const int                   mapped = KIB_TX_MAPPED_FMR;
#else
        struct ib_physical_buffer  *phys;
        const int                   mapped = KIB_TX_MAPPED;
#endif
        int                         page_offset;
        int                         nphys;
        int                         resid;
        int                         phys_size;
        int                         rc;

        CDEBUG(D_NET, "niov %d offset %d nob %d\n", nkiov, offset, nob);

        LASSERT (nob > 0);
        LASSERT (nkiov > 0);
        LASSERT (tx->tx_mapped == KIB_TX_UNMAPPED);

        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                nkiov--;
                kiov++;
                LASSERT (nkiov > 0);
        }

        phys_size = nkiov * sizeof (*phys);
        LIBCFS_ALLOC(phys, phys_size);
        if (phys == NULL) {
                CERROR ("Can't allocate tmp phys\n");
                return (-ENOMEM);
        }

        page_offset = kiov->kiov_offset + offset;
#if IBNAL_FMR
        phys[0] = lnet_page2phys(kiov->kiov_page);
#else
        phys[0].address = lnet_page2phys(kiov->kiov_page);
        phys[0].size = PAGE_SIZE;
#endif
        nphys = 1;
        resid = nob - (kiov->kiov_len - offset);

        while (resid > 0) {
                kiov++;
                nkiov--;
                LASSERT (nkiov > 0);

                if (kiov->kiov_offset != 0 ||
                    ((resid > PAGE_SIZE) && 
                     kiov->kiov_len < PAGE_SIZE)) {
                        int i;
                        /* Can't have gaps */
                        CERROR ("Can't make payload contiguous in I/O VM:"
                                "page %d, offset %d, len %d \n", nphys, 
                                kiov->kiov_offset, kiov->kiov_len);

                        for (i = -nphys; i < nkiov; i++) 
                        {
                                CERROR("kiov[%d] %p +%d for %d\n",
                                       i, kiov[i].kiov_page, kiov[i].kiov_offset, kiov[i].kiov_len);
                        }
                        
                        rc = -EINVAL;
                        goto out;
                }

                if (nphys == LNET_MAX_IOV) {
                        CERROR ("payload too big (%d)\n", nphys);
                        rc = -EMSGSIZE;
                        goto out;
                }

                LASSERT (nphys * sizeof (*phys) < phys_size);
#if IBNAL_FMR
                phys[nphys] = lnet_page2phys(kiov->kiov_page);
#else
                phys[nphys].address = lnet_page2phys(kiov->kiov_page);
                phys[nphys].size = PAGE_SIZE;
#endif
                nphys++;

                resid -= PAGE_SIZE;
        }

        tx->tx_md.md_addr = IBNAL_RDMA_BASE;

#if IBNAL_FMR
        rc = ib_fmr_register_physical (kibnal_data.kib_fmr_pool,
                                       phys, nphys,
                                       &tx->tx_md.md_addr,
                                       page_offset,
                                       &tx->tx_md.md_handle.fmr,
                                       &tx->tx_md.md_lkey,
                                       &tx->tx_md.md_rkey);
#else
        rc = ib_memory_register_physical (kibnal_data.kib_pd,
                                          phys, nphys,
                                          &tx->tx_md.md_addr,
                                          nob, page_offset,
                                          access,
                                          &tx->tx_md.md_handle.mr,
                                          &tx->tx_md.md_lkey,
                                          &tx->tx_md.md_rkey);
#endif
        if (rc == 0) {
                CDEBUG(D_NET, "Mapped %d pages %d bytes @ offset %d: lkey %x, rkey %x\n",
                       nphys, nob, page_offset, tx->tx_md.md_lkey, tx->tx_md.md_rkey);
                tx->tx_mapped = mapped;
        } else {
                CERROR ("Can't map phys: %d\n", rc);
                rc = -EFAULT;
        }

 out:
        LIBCFS_FREE(phys, phys_size);
        return (rc);
}

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
        unsigned long   flags;
        kib_tx_t       *tx;
        int             rc;
        int             i;
        int             consume_credit;
        int             done;
        int             nwork;

        spin_lock_irqsave (&conn->ibc_lock, flags);

        LASSERT (conn->ibc_nsends_posted <= IBNAL_RX_MSGS);
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
                spin_unlock_irqrestore(&conn->ibc_lock, flags);
                
                tx = kibnal_get_idle_tx();
                if (tx != NULL)
                        kibnal_init_tx_msg(tx, IBNAL_MSG_NOOP, 0);

                spin_lock_irqsave(&conn->ibc_lock, flags);
                
                if (tx != NULL)
                        kibnal_queue_tx_locked(tx, conn);
        }

        for (;;) {
                if (!list_empty(&conn->ibc_tx_queue_nocred)) {
                        LASSERT (conn->ibc_version !=
                                 IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD);
                        tx = list_entry(conn->ibc_tx_queue_nocred.next,
                                        kib_tx_t, tx_list);
                        consume_credit = 0;
                } else if (!list_empty (&conn->ibc_tx_queue)) {
                        tx = list_entry (conn->ibc_tx_queue.next, 
                                         kib_tx_t, tx_list);
                        consume_credit = 1;
                } else {
                        /* nothing waiting */
                        break;
                }

                /* We rely on this for QP sizing */
                LASSERT (tx->tx_nsp > 0 && tx->tx_nsp <= 2);

                LASSERT (conn->ibc_outstanding_credits >= 0);
                LASSERT (conn->ibc_outstanding_credits <= IBNAL_MSG_QUEUE_SIZE);
                LASSERT (conn->ibc_credits >= 0);
                LASSERT (conn->ibc_credits <= IBNAL_MSG_QUEUE_SIZE);

                /* Not on ibc_rdma_queue */
                LASSERT (!tx->tx_passive_rdma_wait);

                if (conn->ibc_nsends_posted == IBNAL_RX_MSGS)
                        break;

                if (consume_credit) {
                        if (conn->ibc_credits == 0)     /* no credits */
                                break;
                
                        if (conn->ibc_credits == 1 &&   /* last credit reserved for */
                            conn->ibc_outstanding_credits == 0) /* giving back credits */
                                break;
                }
                
                list_del (&tx->tx_list);

                if (tx->tx_msg->ibm_type == IBNAL_MSG_NOOP &&
                    (!list_empty(&conn->ibc_tx_queue) ||
                     !list_empty(&conn->ibc_tx_queue_nocred) ||
                     (conn->ibc_outstanding_credits < IBNAL_CREDIT_HIGHWATER &&
                      !kibnal_send_keepalive(conn)))) {
                        /* redundant NOOP */
                        spin_unlock_irqrestore(&conn->ibc_lock, flags);
                        kibnal_tx_done(tx);
                        spin_lock_irqsave(&conn->ibc_lock, flags);
                        continue;
                }

                kibnal_pack_msg(tx->tx_msg, conn->ibc_version,
                                conn->ibc_outstanding_credits,
                                conn->ibc_peer->ibp_nid, conn->ibc_incarnation);

                conn->ibc_outstanding_credits = 0;
                conn->ibc_nsends_posted++;
                if (consume_credit)
                        conn->ibc_credits--;

                tx->tx_sending = tx->tx_nsp;
                tx->tx_passive_rdma_wait = tx->tx_passive_rdma;
                list_add (&tx->tx_list, &conn->ibc_active_txs);

                spin_unlock_irqrestore (&conn->ibc_lock, flags);

                /* NB the gap between removing tx from the queue and sending it
                 * allows message re-ordering to occur */

                LASSERT (tx->tx_nsp > 0);

                rc = -ECONNABORTED;
                nwork = 0;
                if (conn->ibc_state == IBNAL_CONN_ESTABLISHED) {
                        tx->tx_status = 0;
                        /* Driver only accepts 1 item at a time */
                        for (i = 0; i < tx->tx_nsp; i++) {
                                rc = kibnal_ib_send(conn->ibc_qp, &tx->tx_sp[i]);
                                if (rc != 0)
                                        break;
                                nwork++;
                        }
                }

                conn->ibc_last_send = jiffies;

                spin_lock_irqsave (&conn->ibc_lock, flags);
                if (rc != 0) {
                        /* NB credits are transferred in the actual
                         * message, which can only be the last work item */
                        conn->ibc_outstanding_credits += tx->tx_msg->ibm_credits;
                        if (consume_credit)
                                conn->ibc_credits++;
                        conn->ibc_nsends_posted--;

                        tx->tx_status = rc;
                        tx->tx_passive_rdma_wait = 0;
                        tx->tx_sending -= tx->tx_nsp - nwork;

                        done = (tx->tx_sending == 0);
                        if (done)
                                list_del (&tx->tx_list);
                        
                        spin_unlock_irqrestore (&conn->ibc_lock, flags);
                        
                        if (conn->ibc_state == IBNAL_CONN_ESTABLISHED)
                                CERROR ("Error %d posting transmit to %s\n", 
                                        rc, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        else
                                CDEBUG (D_NET, "Error %d posting transmit to %s\n",
                                        rc, libcfs_nid2str(conn->ibc_peer->ibp_nid));

                        kibnal_close_conn (conn, rc);

                        if (done)
                                kibnal_tx_done (tx);
                        return;
                }
                
        }

        spin_unlock_irqrestore (&conn->ibc_lock, flags);
}

void
kibnal_tx_callback (struct ib_cq_entry *e)
{
        kib_tx_t     *tx = (kib_tx_t *)kibnal_wreqid2ptr(e->work_request_id);
        kib_conn_t   *conn;
        unsigned long flags;
        int           idle;

        conn = tx->tx_conn;
        LASSERT (conn != NULL);
        LASSERT (tx->tx_sending != 0);

        spin_lock_irqsave(&conn->ibc_lock, flags);

        CDEBUG(D_NET, "conn %p tx %p [%d/%d]: %d\n", conn, tx,
               tx->tx_nsp - tx->tx_sending, tx->tx_nsp,
               e->status);

        /* I could be racing with rdma completion.  Whoever makes 'tx' idle
         * gets to free it, which also drops its ref on 'conn'.  If it's
         * not me, then I take an extra ref on conn so it can't disappear
         * under me. */

        tx->tx_sending--;
        idle = (tx->tx_sending == 0) &&         /* This is the final callback */
               (!tx->tx_passive_rdma_wait);     /* Not waiting for RDMA completion */
        if (idle)
                list_del(&tx->tx_list);

        kibnal_conn_addref(conn);

        if (tx->tx_sending == 0)
                conn->ibc_nsends_posted--;

        if (e->status != IB_COMPLETION_STATUS_SUCCESS &&
            tx->tx_status == 0)
                tx->tx_status = -ECONNABORTED;
                
        spin_unlock_irqrestore(&conn->ibc_lock, flags);

        if (idle)
                kibnal_tx_done (tx);

        if (e->status != IB_COMPLETION_STATUS_SUCCESS) {
                CDEBUG (D_NETERROR, "Tx completion to %s failed: %d\n", 
                        libcfs_nid2str(conn->ibc_peer->ibp_nid), e->status);
                kibnal_close_conn (conn, -ENETDOWN);
        } else {
                kibnal_peer_alive(conn->ibc_peer);
                /* can I shovel some more sends out the door? */
                kibnal_check_sends(conn);
        }

        kibnal_conn_decref(conn);
}

void
kibnal_callback (ib_cq_t *cq, struct ib_cq_entry *e, void *arg)
{
        if (kibnal_wreqid_is_rx(e->work_request_id))
                kibnal_rx_callback (e);
        else
                kibnal_tx_callback (e);
}

void
kibnal_init_tx_msg (kib_tx_t *tx, int type, int body_nob)
{
        struct ib_gather_scatter *gl = &tx->tx_gl[tx->tx_nsp];
        struct ib_send_param     *sp = &tx->tx_sp[tx->tx_nsp];
        int                       fence;
        int                       nob = offsetof (kib_msg_t, ibm_u) + body_nob;

        LASSERT (tx->tx_nsp >= 0 && 
                 tx->tx_nsp < sizeof(tx->tx_sp)/sizeof(tx->tx_sp[0]));
        LASSERT (nob <= IBNAL_MSG_SIZE);

        kibnal_init_msg(tx->tx_msg, type, body_nob);

        /* Fence the message if it's bundled with an RDMA read */
        fence = (tx->tx_nsp > 0) &&
                (type == IBNAL_MSG_PUT_DONE);

        *gl = (struct ib_gather_scatter) {
                .address = tx->tx_vaddr,
                .length  = nob,
                .key     = kibnal_data.kib_tx_pages->ibp_lkey,
        };

        /* NB If this is an RDMA read, the completion message must wait for
         * the RDMA to complete.  Sends wait for previous RDMA writes
         * anyway... */
        *sp = (struct ib_send_param) {
                .work_request_id      = kibnal_ptr2wreqid(tx, 0),
                .op                   = IB_OP_SEND,
                .gather_list          = gl,
                .num_gather_entries   = 1,
                .device_specific      = NULL,
                .solicited_event      = 1,
                .signaled             = 1,
                .immediate_data_valid = 0,
                .fence                = fence,
                .inline_data          = 0,
        };

        tx->tx_nsp++;
}

void
kibnal_queue_tx (kib_tx_t *tx, kib_conn_t *conn)
{
        unsigned long         flags;

        spin_lock_irqsave(&conn->ibc_lock, flags);

        kibnal_queue_tx_locked (tx, conn);
        
        spin_unlock_irqrestore(&conn->ibc_lock, flags);
        
        kibnal_check_sends(conn);
}

void
kibnal_schedule_active_connect_locked (kib_peer_t *peer)
{
        /* Called with exclusive kib_global_lock */

        peer->ibp_connecting++;
        kibnal_peer_addref(peer); /* extra ref for connd */
        
        spin_lock (&kibnal_data.kib_connd_lock);
        
        LASSERT (list_empty(&peer->ibp_connd_list));
        list_add_tail (&peer->ibp_connd_list,
                       &kibnal_data.kib_connd_peers);
        wake_up (&kibnal_data.kib_connd_waitq);
        
        spin_unlock (&kibnal_data.kib_connd_lock);
}

void
kibnal_launch_tx (kib_tx_t *tx, lnet_nid_t nid)
{
        unsigned long    flags;
        kib_peer_t      *peer;
        kib_conn_t      *conn;
        int              retry;
        int              rc;
        rwlock_t        *g_lock = &kibnal_data.kib_global_lock;

        /* If I get here, I've committed to send, so I complete the tx with
         * failure on any problems */
        
        LASSERT (tx->tx_conn == NULL);          /* only set when assigned a conn */
        LASSERT (tx->tx_nsp > 0);               /* work items have been set up */

        for (retry = 0; ; retry = 1) {
                read_lock_irqsave(g_lock, flags);
        
                peer = kibnal_find_peer_locked (nid);
                if (peer != NULL) {
                        conn = kibnal_find_conn_locked (peer);
                        if (conn != NULL) {
                                kibnal_conn_addref(conn); /* 1 ref for me...*/
                                read_unlock_irqrestore(g_lock, flags);
                
                                kibnal_queue_tx (tx, conn);
                                kibnal_conn_decref(conn); /* ...until here */
                                return;
                        }
                }
                
                /* Making one or more connections; I'll need a write lock... */
                read_unlock(g_lock);
                write_lock(g_lock);

                peer = kibnal_find_peer_locked (nid);
                if (peer != NULL)
                        break;
                
                write_unlock_irqrestore (g_lock, flags);

                if (retry) {
                        CERROR("Can't find peer %s\n", libcfs_nid2str(nid));
                        tx->tx_status = -EHOSTUNREACH;
                        kibnal_tx_done (tx);
                        return;
                }

                rc = kibnal_add_persistent_peer(nid, LNET_NIDADDR(nid),
                                                lnet_acceptor_port());
                if (rc != 0) {
                        CERROR("Can't add peer %s: %d\n",
                               libcfs_nid2str(nid), rc);
                        tx->tx_status = rc;
                        kibnal_tx_done(tx);
                        return;
                }
        }

        conn = kibnal_find_conn_locked (peer);
        if (conn != NULL) {
                /* Connection exists; queue message on it */
                kibnal_conn_addref(conn);       /* +1 ref from me... */
                write_unlock_irqrestore (g_lock, flags);
                
                kibnal_queue_tx (tx, conn);
                kibnal_conn_decref(conn);       /* ...until here */
                return;
        }

        if (peer->ibp_connecting == 0 &&
            peer->ibp_accepting == 0) {
                if (!(peer->ibp_reconnect_interval == 0 || /* first attempt */
                      time_after_eq(jiffies, peer->ibp_reconnect_time))) {
                        write_unlock_irqrestore (g_lock, flags);
                        tx->tx_status = -EHOSTUNREACH;
                        kibnal_tx_done (tx);
                        return;
                }
        
                kibnal_schedule_active_connect_locked(peer);
        }
        
        /* A connection is being established; queue the message... */
        list_add_tail (&tx->tx_list, &peer->ibp_tx_queue);

        write_unlock_irqrestore (g_lock, flags);
}

void
kibnal_txlist_done (struct list_head *txlist, int status)
{
        kib_tx_t *tx;

        while (!list_empty(txlist)) {
                tx = list_entry (txlist->next, kib_tx_t, tx_list);

                list_del (&tx->tx_list);
                /* complete now */
                tx->tx_status = status;
                kibnal_tx_done (tx);
        }
}

int
kibnal_start_passive_rdma (int type, lnet_msg_t *lntmsg,
                           int niov, struct iovec *iov, lnet_kiov_t *kiov,
                           int nob)
{
        lnet_nid_t  nid = lntmsg->msg_target.nid;
        kib_tx_t   *tx;
        kib_msg_t  *ibmsg;
        int         rc;
        int         access;
        
        LASSERT (type == IBNAL_MSG_PUT_RDMA || 
                 type == IBNAL_MSG_GET_RDMA);
        LASSERT (nob > 0);
        LASSERT (!in_interrupt());              /* Mapping could block */

        if (type == IBNAL_MSG_PUT_RDMA) {
                access = IB_ACCESS_REMOTE_READ;
        } else {
                access = IB_ACCESS_REMOTE_WRITE |
                         IB_ACCESS_LOCAL_WRITE;
        }

        tx = kibnal_get_idle_tx ();
        if (tx == NULL) {
                CERROR("Can't allocate %s txd for %s\n",
                       (type == IBNAL_MSG_PUT_RDMA) ? "PUT/REPLY" : "GET",
                       libcfs_nid2str(nid));
                return -ENOMEM;
        }

        
        if (iov != NULL) 
                rc = kibnal_map_iov (tx, access, niov, iov, 0, nob);
        else
                rc = kibnal_map_kiov (tx, access, niov, kiov, 0, nob);

        if (rc != 0) {
                CERROR ("Can't map RDMA for %s: %d\n", 
                        libcfs_nid2str(nid), rc);
                goto failed;
        }
        
        if (type == IBNAL_MSG_GET_RDMA) {
                /* reply gets finalized when tx completes */
                tx->tx_lntmsg[1] = lnet_create_reply_msg(kibnal_data.kib_ni, 
                                                         lntmsg);
                if (tx->tx_lntmsg[1] == NULL) {
                        CERROR ("Can't create reply for GET -> %s\n",
                                libcfs_nid2str(nid));
                        rc = -ENOMEM;
                        goto failed;
                }
        }
        
        tx->tx_passive_rdma = 1;

        ibmsg = tx->tx_msg;

        ibmsg->ibm_u.rdma.ibrm_hdr = lntmsg->msg_hdr;
        ibmsg->ibm_u.rdma.ibrm_cookie = tx->tx_passive_rdma_cookie;
        ibmsg->ibm_u.rdma.ibrm_desc.rd_key = tx->tx_md.md_rkey;
        ibmsg->ibm_u.rdma.ibrm_desc.rd_addr = tx->tx_md.md_addr;
        ibmsg->ibm_u.rdma.ibrm_desc.rd_nob = nob;

        kibnal_init_tx_msg (tx, type, sizeof (kib_rdma_msg_t));

        CDEBUG(D_NET, "Passive: %p cookie "LPX64", key %x, addr "
               LPX64", nob %d\n",
               tx, tx->tx_passive_rdma_cookie, tx->tx_md.md_rkey,
               tx->tx_md.md_addr, nob);
        
        /* lntmsg gets finalized when tx completes. */
        tx->tx_lntmsg[0] = lntmsg;

        kibnal_launch_tx(tx, nid);
        return (0);

 failed:
        tx->tx_status = rc;
        kibnal_tx_done (tx);
        return (-EIO);
}

void
kibnal_start_active_rdma (int type, int status,
                          kib_rx_t *rx, lnet_msg_t *lntmsg, 
                          unsigned int niov,
                          struct iovec *iov, lnet_kiov_t *kiov,
                          int offset, int nob)
{
        kib_msg_t    *rxmsg = rx->rx_msg;
        kib_msg_t    *txmsg;
        kib_tx_t     *tx;
        int           access;
        int           rdma_op;
        int           rc;

        CDEBUG(D_NET, "type %d, status %d, niov %d, offset %d, nob %d\n",
               type, status, niov, offset, nob);

        /* Called by scheduler */
        LASSERT (!in_interrupt ());

        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));

        /* No data if we're completing with failure */
        LASSERT (status == 0 || nob == 0);

        LASSERT (type == IBNAL_MSG_GET_DONE ||
                 type == IBNAL_MSG_PUT_DONE);

        if (type == IBNAL_MSG_GET_DONE) {
                access   = 0;
                rdma_op  = IB_OP_RDMA_WRITE;
                LASSERT (rxmsg->ibm_type == IBNAL_MSG_GET_RDMA);
        } else {
                access   = IB_ACCESS_LOCAL_WRITE;
                rdma_op  = IB_OP_RDMA_READ;
                LASSERT (rxmsg->ibm_type == IBNAL_MSG_PUT_RDMA);
        }

        tx = kibnal_get_idle_tx ();
        if (tx == NULL) {
                CERROR ("tx descs exhausted on RDMA from %s"
                        " completing locally with failure\n",
                        libcfs_nid2str(rx->rx_conn->ibc_peer->ibp_nid));
                lnet_finalize (kibnal_data.kib_ni, lntmsg, -ENOMEM);
                return;
        }
        LASSERT (tx->tx_nsp == 0);
                        
        if (nob != 0) {
                /* We actually need to transfer some data (the transfer
                 * size could get truncated to zero when the incoming
                 * message is matched) */

                if (kiov != NULL)
                        rc = kibnal_map_kiov (tx, access,
                                              niov, kiov, offset, nob);
                else
                        rc = kibnal_map_iov (tx, access,
                                             niov, iov, offset, nob);
                
                if (rc != 0) {
                        CERROR ("Can't map RDMA -> %s: %d\n", 
                                libcfs_nid2str(rx->rx_conn->ibc_peer->ibp_nid), 
                                rc);
                        /* We'll skip the RDMA and complete with failure. */
                        status = rc;
                        nob = 0;
                } else {
                        tx->tx_gl[0] = (struct ib_gather_scatter) {
                                .address = tx->tx_md.md_addr,
                                .length  = nob,
                                .key     = tx->tx_md.md_lkey,
                        };
                
                        tx->tx_sp[0] = (struct ib_send_param) {
                                .work_request_id      = kibnal_ptr2wreqid(tx, 0),
                                .op                   = rdma_op,
                                .gather_list          = &tx->tx_gl[0],
                                .num_gather_entries   = 1,
                                .remote_address       = rxmsg->ibm_u.rdma.ibrm_desc.rd_addr,
                                .rkey                 = rxmsg->ibm_u.rdma.ibrm_desc.rd_key,
                                .device_specific      = NULL,
                                .solicited_event      = 0,
                                .signaled             = 1,
                                .immediate_data_valid = 0,
                                .fence                = 0,
                                .inline_data          = 0,
                        };

                        tx->tx_nsp = 1;
                }
        }

        txmsg = tx->tx_msg;

        txmsg->ibm_u.completion.ibcm_cookie = rxmsg->ibm_u.rdma.ibrm_cookie;
        txmsg->ibm_u.completion.ibcm_status = status;
        
        kibnal_init_tx_msg(tx, type, sizeof (kib_completion_msg_t));

        if (status == 0 && nob != 0) {
                LASSERT (tx->tx_nsp > 1);
                /* RDMA: lntmsg gets finalized when the tx completes.  This
                 * is after the completion message has been sent, which in
                 * turn is after the RDMA has finished. */
                tx->tx_lntmsg[0] = lntmsg;
        } else {
                LASSERT (tx->tx_nsp == 1);
                /* No RDMA: local completion happens now! */
                CDEBUG(D_NET, "No data: immediate completion\n");
                lnet_finalize (kibnal_data.kib_ni, lntmsg,
                              status == 0 ? 0 : -EIO);
        }

        kibnal_queue_tx(tx, rx->rx_conn);
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

        /* NB 'private' is different depending on what we're sending.... */

        CDEBUG(D_NET, "sending %d bytes in %d frags to %s\n",
               payload_nob, payload_niov, libcfs_id2str(target));

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= LNET_MAX_IOV);

        /* Thread context if we're sending payload */
        LASSERT (!in_interrupt() || payload_niov == 0);
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

                if ((lntmsg->msg_md->md_options & LNET_MD_KIOV) == 0)
                        return kibnal_start_passive_rdma(IBNAL_MSG_GET_RDMA, lntmsg, 
                                                         lntmsg->msg_md->md_niov, 
                                                         lntmsg->msg_md->md_iov.iov, NULL,
                                                         lntmsg->msg_md->md_length);

                return kibnal_start_passive_rdma(IBNAL_MSG_GET_RDMA, lntmsg, 
                                                 lntmsg->msg_md->md_niov, 
                                                 NULL, lntmsg->msg_md->md_iov.kiov,
                                                 lntmsg->msg_md->md_length);

        case LNET_MSG_REPLY:
        case LNET_MSG_PUT:
                /* Is the payload small enough not to need RDMA? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob]);
                if (nob <= IBNAL_MSG_SIZE)
                        break;                  /* send IMMEDIATE */
                
                return kibnal_start_passive_rdma(IBNAL_MSG_PUT_RDMA, lntmsg,
                                                 payload_niov,
                                                 payload_iov, payload_kiov,
                                                 payload_nob);
        }

        /* Send IMMEDIATE */

        tx = kibnal_get_idle_tx();
        if (tx == NULL) {
                CERROR ("Can't send %d to %s: tx descs exhausted%s\n", 
                        type, libcfs_nid2str(target.nid), 
                        in_interrupt() ? " (intr)" : "");
                return (-ENOMEM);
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

        kibnal_init_tx_msg (tx, IBNAL_MSG_IMMEDIATE,
                            offsetof(kib_immediate_msg_t, 
                                     ibim_payload[payload_nob]));

        /* lntmsg gets finalized when tx completes */
        tx->tx_lntmsg[0] = lntmsg;

        kibnal_launch_tx(tx, target.nid);
        return (0);
}

int
kibnal_eager_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
                   void **new_private)
{
        kib_rx_t    *rx = private;
        kib_conn_t  *conn = rx->rx_conn;

        if (conn->ibc_version == IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD) {
                /* Can't block if RDMA completions need normal credits */
                LCONSOLE_ERROR_MSG(0x12a, 
                               "Dropping message from %s: no buffers free. "
                               "%s is running an old version of LNET that may "
                               "deadlock if messages wait for buffers)\n",
                               libcfs_nid2str(conn->ibc_peer->ibp_nid),
                               libcfs_nid2str(conn->ibc_peer->ibp_nid));
                return -EDEADLK;
        }
        
        *new_private = private;
        return 0;
}

int
kibnal_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
             int delayed, unsigned int niov,
             struct iovec *iov, lnet_kiov_t *kiov,
             unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        kib_rx_t    *rx = private;
        kib_msg_t   *rxmsg = rx->rx_msg;
        int          msg_nob;
        int          rc = 0;
        
        LASSERT (mlen <= rlen);
        LASSERT (!in_interrupt ());
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));

        switch (rxmsg->ibm_type) {
        default:
                LBUG();

        case IBNAL_MSG_IMMEDIATE:
                msg_nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[rlen]);
                if (msg_nob > rx->rx_nob) {
                        CERROR ("Immediate message from %s too big: %d(%d)\n",
                                libcfs_nid2str(rxmsg->ibm_u.immediate.ibim_hdr.src_nid),
                                msg_nob, rx->rx_nob);
                        rc = -EPROTO;
                        break;
                }

                if (kiov != NULL)
                        lnet_copy_flat2kiov(
                                niov, kiov, offset, 
                                IBNAL_MSG_SIZE, rxmsg,
                                offsetof(kib_msg_t, ibm_u.immediate.ibim_payload),
                                mlen);
                else
                        lnet_copy_flat2iov(
                                niov, iov, offset,
                                IBNAL_MSG_SIZE, rxmsg,
                                offsetof(kib_msg_t, ibm_u.immediate.ibim_payload),
                                mlen);

                lnet_finalize (ni, lntmsg, 0);
                break;

        case IBNAL_MSG_GET_RDMA:
                if (lntmsg != NULL) {
                        /* GET matched: RDMA lntmsg's payload */
                        kibnal_start_active_rdma(IBNAL_MSG_GET_DONE, 0,
                                                 rx, lntmsg, 
                                                 lntmsg->msg_niov, 
                                                 lntmsg->msg_iov, 
                                                 lntmsg->msg_kiov,
                                                 lntmsg->msg_offset, 
                                                 lntmsg->msg_len);
                } else {
                        /* GET didn't match anything */
                        kibnal_start_active_rdma (IBNAL_MSG_GET_DONE, -ENODATA,
                                                  rx, NULL, 0, NULL, NULL, 0, 0);
                }
                break;

        case IBNAL_MSG_PUT_RDMA:
                kibnal_start_active_rdma (IBNAL_MSG_PUT_DONE, 0, rx, lntmsg,
                                          niov, iov, kiov, offset, mlen);
                break;
        }

        kibnal_post_rx(rx, 1, 0);
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
kibnal_close_conn_locked (kib_conn_t *conn, int error)
{
        /* This just does the immmediate housekeeping, and schedules the
         * connection for the reaper to finish off.
         * Caller holds kib_global_lock exclusively in irq context */
        kib_peer_t   *peer = conn->ibc_peer;

        CDEBUG (error == 0 ? D_NET : D_NETERROR,
                "closing conn to %s: error %d\n", 
                libcfs_nid2str(peer->ibp_nid), error);
        
        LASSERT (conn->ibc_state == IBNAL_CONN_ESTABLISHED ||
                 conn->ibc_state == IBNAL_CONN_CONNECTING);

        if (conn->ibc_state == IBNAL_CONN_ESTABLISHED) {
                /* kib_reaper_conns takes ibc_list's ref */
                list_del (&conn->ibc_list);
        } else {
                /* new ref for kib_reaper_conns */
                kibnal_conn_addref(conn);
        }
        
        if (list_empty (&peer->ibp_conns)) {   /* no more conns */
                if (peer->ibp_persistence == 0 && /* non-persistent peer */
                    kibnal_peer_active(peer))     /* still in peer table */
                        kibnal_unlink_peer_locked (peer);

                peer->ibp_error = error; /* set/clear error on last conn */
        }

        conn->ibc_state = IBNAL_CONN_DEATHROW;

        /* Schedule conn for closing/destruction */
        spin_lock (&kibnal_data.kib_reaper_lock);

        list_add_tail (&conn->ibc_list, &kibnal_data.kib_reaper_conns);
        wake_up (&kibnal_data.kib_reaper_waitq);
                
        spin_unlock (&kibnal_data.kib_reaper_lock);
}

int
kibnal_close_conn (kib_conn_t *conn, int why)
{
        unsigned long     flags;
        int               count = 0;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        LASSERT (conn->ibc_state >= IBNAL_CONN_CONNECTING);
        
        if (conn->ibc_state <= IBNAL_CONN_ESTABLISHED) {
                count = 1;
                kibnal_close_conn_locked (conn, why);
        }
        
        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
        return (count);
}

void
kibnal_peer_connect_failed (kib_peer_t *peer, int active, int error)
{
        LIST_HEAD        (zombies);
        unsigned long     flags;

        LASSERT(error != 0);

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (active) {
                LASSERT (peer->ibp_connecting != 0);
                peer->ibp_connecting--;
        } else {
                LASSERT (peer->ibp_accepting != 0);
                peer->ibp_accepting--;
        }

        if (peer->ibp_connecting != 0 ||
            peer->ibp_accepting != 0) {
                /* another connection attempt under way... */
                write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
                return;
        }

        if (list_empty(&peer->ibp_conns)) {
                /* Say when active connection can be re-attempted */
                peer->ibp_reconnect_interval *= 2;
                peer->ibp_reconnect_interval =
                        MAX(peer->ibp_reconnect_interval,
                            *kibnal_tunables.kib_min_reconnect_interval);
                peer->ibp_reconnect_interval =
                        MIN(peer->ibp_reconnect_interval,
                            *kibnal_tunables.kib_max_reconnect_interval);
                
                peer->ibp_reconnect_time = jiffies + 
                                           peer->ibp_reconnect_interval * HZ;
        
                /* Take peer's blocked transmits; I'll complete
                 * them with error */
                list_add(&zombies, &peer->ibp_tx_queue);
                list_del_init(&peer->ibp_tx_queue);
                
                if (kibnal_peer_active(peer) &&
                    (peer->ibp_persistence == 0)) {
                        /* failed connection attempt on non-persistent peer */
                        kibnal_unlink_peer_locked (peer);
                }

                peer->ibp_error = error;
        } else {
                /* Can't have blocked transmits if there are connections */
                LASSERT (list_empty(&peer->ibp_tx_queue));
        }
        
        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        kibnal_peer_notify(peer);
        
        if (!list_empty (&zombies))
                CDEBUG (D_NETERROR, "Deleting messages for %s: connection failed\n",
                        libcfs_nid2str(peer->ibp_nid));

        kibnal_txlist_done(&zombies, -EHOSTUNREACH);
}

void
kibnal_connreq_done (kib_conn_t *conn, int active, int status)
{
        int               state = conn->ibc_state;
        kib_peer_t       *peer = conn->ibc_peer;
        kib_tx_t         *tx;
        unsigned long     flags;
        int               rc;
        int               i;

        if (conn->ibc_connreq != NULL) {
                LIBCFS_FREE (conn->ibc_connreq, sizeof (*conn->ibc_connreq));
                conn->ibc_connreq = NULL;
        }

        switch (state) {
        case IBNAL_CONN_CONNECTING:
                /* conn has a CM comm_id */
                if (status == 0) {
                        /* Install common (active/passive) callback for
                         * disconnect/idle notification */
                        rc = tsIbCmCallbackModify(conn->ibc_comm_id, 
                                                  kibnal_conn_callback,
                                                  conn);
                        LASSERT (rc == 0);
                } else {
                        /* LASSERT (no more CM callbacks) */
                        rc = tsIbCmCallbackModify(conn->ibc_comm_id,
                                                  kibnal_bad_conn_callback,
                                                  conn);
                        LASSERT (rc == 0);
                }
                break;
                
        case IBNAL_CONN_INIT_QP:
                LASSERT (status != 0);
                break;
                
        default:
                LBUG();
        }
        
        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (active)
                LASSERT (peer->ibp_connecting != 0);
        else
                LASSERT (peer->ibp_accepting != 0);
        
        if (status == 0 &&                      /* connection established */
            kibnal_peer_active(peer)) {         /* peer not deleted */

                if (active)
                        peer->ibp_connecting--;
                else
                        peer->ibp_accepting--;

                conn->ibc_last_send = jiffies;
                conn->ibc_state = IBNAL_CONN_ESTABLISHED;
                kibnal_peer_alive(peer);

                /* +1 ref for ibc_list; caller(== CM)'s ref remains until
                 * the IB_CM_IDLE callback */
                kibnal_conn_addref(conn);
                list_add (&conn->ibc_list, &peer->ibp_conns);

                peer->ibp_reconnect_interval = 0; /* OK to reconnect at any time */

                /* post blocked sends to the new connection */
                spin_lock (&conn->ibc_lock);
                
                while (!list_empty (&peer->ibp_tx_queue)) {
                        tx = list_entry (peer->ibp_tx_queue.next, 
                                         kib_tx_t, tx_list);
                        
                        list_del (&tx->tx_list);

                        kibnal_queue_tx_locked (tx, conn);
                }
                
                spin_unlock (&conn->ibc_lock);

                /* Nuke any dangling conns from a different peer instance... */
                kibnal_close_stale_conns_locked (conn->ibc_peer,
                                                 conn->ibc_incarnation);

                write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

                /* queue up all the receives */
                for (i = 0; i < IBNAL_RX_MSGS; i++) {
                        /* +1 ref for rx desc */
                        kibnal_conn_addref(conn);

                        CDEBUG(D_NET, "RX[%d] %p->%p - "LPX64"\n",
                               i, &conn->ibc_rxs[i], conn->ibc_rxs[i].rx_msg,
                               conn->ibc_rxs[i].rx_vaddr);

                        kibnal_post_rx (&conn->ibc_rxs[i], 0, 0);
                }

                kibnal_check_sends (conn);
                return;
        }

        if (status == 0) {
                /* connection established, but peer was deleted.  Schedule for
                 * reaper to cm_disconnect... */
                status = -ECONNABORTED;
                kibnal_close_conn_locked (conn, status);
        } else {
                /* just waiting for refs to drain */
                conn->ibc_state = IBNAL_CONN_ZOMBIE;
        } 

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        kibnal_peer_connect_failed (conn->ibc_peer, active, status);
}

int
kibnal_accept_connreq (kib_conn_t **connp, tTS_IB_CM_COMM_ID cid,
                       kib_msg_t *msg, int nob)
{
        kib_conn_t    *conn;
        kib_peer_t    *peer;
        kib_peer_t    *peer2;
        unsigned long  flags;
        int            rc;

        rc = kibnal_unpack_msg(msg, 0, nob);
        if (rc != 0) {
                CERROR("Can't unpack connreq msg: %d\n", rc);
                return -EPROTO;
        }

        CDEBUG(D_NET, "connreq from %s\n", libcfs_nid2str(msg->ibm_srcnid));

        if (msg->ibm_type != IBNAL_MSG_CONNREQ) {
                CERROR("Unexpected connreq msg type: %x from %s\n",
                       msg->ibm_type, libcfs_nid2str(msg->ibm_srcnid));
                return -EPROTO;
        }
                
        if (msg->ibm_u.connparams.ibcp_queue_depth != IBNAL_MSG_QUEUE_SIZE) {
                CERROR("Can't accept %s: bad queue depth %d (%d expected)\n",
                       libcfs_nid2str(msg->ibm_srcnid), 
                       msg->ibm_u.connparams.ibcp_queue_depth, 
                       IBNAL_MSG_QUEUE_SIZE);
                return (-EPROTO);
        }
        
        conn = kibnal_create_conn();
        if (conn == NULL)
                return (-ENOMEM);

        /* assume 'nid' is a new peer */
        rc = kibnal_create_peer(&peer, msg->ibm_srcnid);
        if (rc != 0) {
                kibnal_conn_decref(conn);
                return (-ENOMEM);
        }
        
        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (kibnal_data.kib_nonewpeers) {
                write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
                
                CERROR ("Shutdown has started, drop connreq from %s\n",
                        libcfs_nid2str(msg->ibm_srcnid));
                kibnal_conn_decref(conn);
                kibnal_peer_decref(peer);
                return -ESHUTDOWN;
        }

        /* Check I'm the same instance that gave the connection parameters.  
         * NB If my incarnation changes after this, the peer will get nuked and
         * we'll spot that when the connection is finally added into the peer's
         * connlist */
        if (!lnet_ptlcompat_matchnid(kibnal_data.kib_ni->ni_nid,
                                     msg->ibm_dstnid) ||
            msg->ibm_dststamp != kibnal_data.kib_incarnation) {
                write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
                
                CERROR("Stale connection params from %s\n",
                       libcfs_nid2str(msg->ibm_srcnid));
                kibnal_conn_decref(conn);
                kibnal_peer_decref(peer);
                return -ESTALE;
        }

        peer2 = kibnal_find_peer_locked(msg->ibm_srcnid);
        if (peer2 == NULL) {
                /* Brand new peer */
                LASSERT (peer->ibp_accepting == 0);

                /* peer table takes my ref on peer */
                list_add_tail (&peer->ibp_list,
                               kibnal_nid2peerlist(msg->ibm_srcnid));
        } else {
                /* tie-break connection race in favour of the higher NID */                
                if (peer2->ibp_connecting != 0 &&
                    msg->ibm_srcnid < kibnal_data.kib_ni->ni_nid) {
                        write_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                                flags);
                        CWARN("Conn race %s\n",
                              libcfs_nid2str(peer2->ibp_nid));

                        kibnal_conn_decref(conn);
                        kibnal_peer_decref(peer);
                        return -EALREADY;
                }

                kibnal_peer_decref(peer);
                peer = peer2;
        }

        /* +1 ref for conn */
        kibnal_peer_addref(peer);
        peer->ibp_accepting++;

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        conn->ibc_peer = peer;
        conn->ibc_state = IBNAL_CONN_CONNECTING;
        conn->ibc_comm_id = cid;
        conn->ibc_incarnation = msg->ibm_srcstamp;
        conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;
        conn->ibc_reserved_credits = IBNAL_MSG_QUEUE_SIZE;
        conn->ibc_version = msg->ibm_version;

        *connp = conn;
        return (0);
}

tTS_IB_CM_CALLBACK_RETURN
kibnal_bad_conn_callback (tTS_IB_CM_EVENT event,
                          tTS_IB_CM_COMM_ID cid,
                          void *param,
                          void *arg)
{
        CERROR ("Unexpected event %d: conn %p\n", event, arg);
        LBUG ();
        return TS_IB_CM_CALLBACK_PROCEED;
}

void
kibnal_abort_txs (kib_conn_t *conn, struct list_head *txs)
{
        LIST_HEAD        (zombies); 
        struct list_head *tmp;
        struct list_head *nxt;
        kib_tx_t         *tx;
        unsigned long     flags;

        spin_lock_irqsave (&conn->ibc_lock, flags);

        list_for_each_safe (tmp, nxt, txs) {
                tx = list_entry (tmp, kib_tx_t, tx_list);

                if (txs == &conn->ibc_active_txs) {
                        LASSERT (tx->tx_passive_rdma ||
                                 !tx->tx_passive_rdma_wait);

                        LASSERT (tx->tx_passive_rdma_wait ||
                                 tx->tx_sending != 0);
                } else {
                        LASSERT (!tx->tx_passive_rdma_wait);
                        LASSERT (tx->tx_sending == 0);
                }

                tx->tx_status = -ECONNABORTED;
                tx->tx_passive_rdma_wait = 0;

                if (tx->tx_sending == 0) {
                        list_del (&tx->tx_list);
                        list_add (&tx->tx_list, &zombies);
                }
        }
        
        spin_unlock_irqrestore (&conn->ibc_lock, flags);

        kibnal_txlist_done (&zombies, -ECONNABORTED);
}

tTS_IB_CM_CALLBACK_RETURN
kibnal_conn_callback (tTS_IB_CM_EVENT event,
                      tTS_IB_CM_COMM_ID cid,
                      void *param,
                      void *arg)
{
        kib_conn_t       *conn = arg;
        int               rc;

        /* Established Connection Notifier */

        switch (event) {
        default:
                CDEBUG(D_NETERROR, "Connection %p -> %s ERROR %d\n",
                       conn, libcfs_nid2str(conn->ibc_peer->ibp_nid), event);
                kibnal_close_conn (conn, -ECONNABORTED);
                break;
                
        case TS_IB_CM_DISCONNECTED:
                CDEBUG(D_NETERROR, "Connection %p -> %s DISCONNECTED.\n",
                       conn, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                kibnal_close_conn (conn, 0);
                break;

        case TS_IB_CM_IDLE:
                CDEBUG(D_NET, "Connection %p -> %s IDLE.\n",
                       conn, libcfs_nid2str(conn->ibc_peer->ibp_nid));

                /* LASSERT (no further callbacks) */
                rc = tsIbCmCallbackModify(cid, kibnal_bad_conn_callback, conn);
                LASSERT (rc == 0);

                /* NB we wait until the connection has closed before
                 * completing outstanding passive RDMAs so we can be sure
                 * the network can't touch the mapped memory any more. */

                kibnal_abort_txs(conn, &conn->ibc_tx_queue);
                kibnal_abort_txs(conn, &conn->ibc_tx_queue_rsrvd);
                kibnal_abort_txs(conn, &conn->ibc_tx_queue_nocred);
                kibnal_abort_txs(conn, &conn->ibc_active_txs);
                
                kibnal_conn_decref(conn);        /* Lose CM's ref */
                break;
        }

        return TS_IB_CM_CALLBACK_PROCEED;
}

tTS_IB_CM_CALLBACK_RETURN
kibnal_passive_conn_callback (tTS_IB_CM_EVENT event,
                              tTS_IB_CM_COMM_ID cid,
                              void *param,
                              void *arg)
{
        kib_conn_t  *conn = arg;
        int          rc;
        
        switch (event) {
        default:
                if (conn == NULL) {
                        /* no connection yet */
                        CERROR ("Unexpected event: %d\n", event);
                        return TS_IB_CM_CALLBACK_ABORT;
                }
                
                CERROR ("%s event %p -> %s: %d\n",
                        (event == TS_IB_CM_IDLE) ? "IDLE" : "Unexpected",
                        conn, libcfs_nid2str(conn->ibc_peer->ibp_nid), event);
                kibnal_connreq_done(conn, 0, -ECONNABORTED);
                kibnal_conn_decref(conn); /* drop CM's ref */
                return TS_IB_CM_CALLBACK_ABORT;
                
        case TS_IB_CM_REQ_RECEIVED: {
                struct ib_cm_req_received_param *req = param;
                kib_msg_t                       *msg = req->remote_private_data;

                LASSERT (conn == NULL);

                /* Don't really know srcnid until successful unpack */
                CDEBUG(D_NET, "REQ from ?%s?\n", libcfs_nid2str(msg->ibm_srcnid));

                rc = kibnal_accept_connreq(&conn, cid, msg, 
                                           req->remote_private_data_len);
                if (rc != 0) {
                        CERROR ("Can't accept ?%s?: %d\n",
                                libcfs_nid2str(msg->ibm_srcnid), rc);
                        return TS_IB_CM_CALLBACK_ABORT;
                }

                /* update 'arg' for next callback */
                rc = tsIbCmCallbackModify(cid, kibnal_passive_conn_callback, conn);
                LASSERT (rc == 0);

                msg = req->accept_param.reply_private_data;
                kibnal_init_msg(msg, IBNAL_MSG_CONNACK,
                                sizeof(msg->ibm_u.connparams));

                msg->ibm_u.connparams.ibcp_queue_depth = IBNAL_MSG_QUEUE_SIZE;

                kibnal_pack_msg(msg, conn->ibc_version, 0, 
                                conn->ibc_peer->ibp_nid, 
                                conn->ibc_incarnation);

                req->accept_param.qp                     = conn->ibc_qp;
                req->accept_param.reply_private_data_len = msg->ibm_nob;
                req->accept_param.responder_resources    = IBNAL_RESPONDER_RESOURCES;
                req->accept_param.initiator_depth        = IBNAL_RESPONDER_RESOURCES;
                req->accept_param.rnr_retry_count        = IBNAL_RNR_RETRY;
                req->accept_param.flow_control           = IBNAL_FLOW_CONTROL;

                CDEBUG(D_NET, "Proceeding\n");
                return TS_IB_CM_CALLBACK_PROCEED; /* CM takes my ref on conn */
        }

        case TS_IB_CM_ESTABLISHED:
                LASSERT (conn != NULL);
                CWARN("Connection %p -> %s ESTABLISHED.\n",
                       conn, libcfs_nid2str(conn->ibc_peer->ibp_nid));

                kibnal_connreq_done(conn, 0, 0);
                return TS_IB_CM_CALLBACK_PROCEED;
        }
}

tTS_IB_CM_CALLBACK_RETURN
kibnal_active_conn_callback (tTS_IB_CM_EVENT event,
                             tTS_IB_CM_COMM_ID cid,
                             void *param,
                             void *arg)
{
        kib_conn_t    *conn = arg;
        unsigned long  flags;

        switch (event) {
        case TS_IB_CM_REP_RECEIVED: {
                struct ib_cm_rep_received_param *rep = param;
                kib_msg_t                       *msg = rep->remote_private_data;
                int                              nob = rep->remote_private_data_len;
                int                              rc;

                rc = kibnal_unpack_msg(msg, conn->ibc_version, nob);
                if (rc != 0) {
                        CERROR ("Error %d unpacking conn ack from %s\n",
                                rc, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        kibnal_connreq_done(conn, 1, rc);
                        kibnal_conn_decref(conn); /* drop CM's ref */
                        return TS_IB_CM_CALLBACK_ABORT;
                }

                if (msg->ibm_type != IBNAL_MSG_CONNACK) {
                        CERROR ("Unexpected conn ack type %d from %s\n",
                                msg->ibm_type, 
                                libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        kibnal_conn_decref(conn); /* drop CM's ref */
                        return TS_IB_CM_CALLBACK_ABORT;
                }

                if (!lnet_ptlcompat_matchnid(conn->ibc_peer->ibp_nid,
                                             msg->ibm_srcnid) ||
                    !lnet_ptlcompat_matchnid(kibnal_data.kib_ni->ni_nid,
                                             msg->ibm_dstnid) ||
                    msg->ibm_srcstamp != conn->ibc_incarnation ||
                    msg->ibm_dststamp != kibnal_data.kib_incarnation) {
                        CERROR("Stale conn ack from %s\n",
                               libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        kibnal_connreq_done(conn, 1, -ESTALE);
                        kibnal_conn_decref(conn); /* drop CM's ref */
                        return TS_IB_CM_CALLBACK_ABORT;
                }

                if (msg->ibm_u.connparams.ibcp_queue_depth != IBNAL_MSG_QUEUE_SIZE) {
                        CERROR ("Bad queue depth %d from %s\n",
                                msg->ibm_u.connparams.ibcp_queue_depth,
                                libcfs_nid2str(conn->ibc_peer->ibp_nid));
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        kibnal_conn_decref(conn); /* drop CM's ref */
                        return TS_IB_CM_CALLBACK_ABORT;
                }
                                
                CDEBUG(D_NET, "Connection %p -> %s REP_RECEIVED.\n",
                       conn, libcfs_nid2str(conn->ibc_peer->ibp_nid));

                conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;
                conn->ibc_reserved_credits = IBNAL_MSG_QUEUE_SIZE;
                return TS_IB_CM_CALLBACK_PROCEED;
        }

        case TS_IB_CM_ESTABLISHED:
                CWARN("Connection %p -> %s ESTABLISHED\n",
                       conn, libcfs_nid2str(conn->ibc_peer->ibp_nid));

                kibnal_connreq_done(conn, 1, 0);
                return TS_IB_CM_CALLBACK_PROCEED;

        case TS_IB_CM_IDLE:
                CDEBUG(D_NETERROR, "Connection %p -> %s IDLE\n",
                       conn, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                /* I assume this connection attempt was rejected because the
                 * peer found a stale QP; I'll just try again */
                write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
                kibnal_schedule_active_connect_locked(conn->ibc_peer);
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

                kibnal_connreq_done(conn, 1, -ECONNABORTED);
                kibnal_conn_decref(conn); /* drop CM's ref */
                return TS_IB_CM_CALLBACK_ABORT;

        default:
                CDEBUG(D_NETERROR, "Connection %p -> %s ERROR %d\n",
                       conn, libcfs_nid2str(conn->ibc_peer->ibp_nid), event);
                kibnal_connreq_done(conn, 1, -ECONNABORTED);
                kibnal_conn_decref(conn); /* drop CM's ref */
                return TS_IB_CM_CALLBACK_ABORT;
        }
}

int
kibnal_pathreq_callback (tTS_IB_CLIENT_QUERY_TID tid, int status,
                          struct ib_path_record *resp, int remaining,
                          void *arg)
{
        kib_conn_t *conn = arg;
        kib_peer_t *peer = conn->ibc_peer;
        kib_msg_t  *msg = &conn->ibc_connreq->cr_msg;

        if (status != 0) {
                CDEBUG (D_NETERROR, "Pathreq %p -> %s failed: %d\n",
                        conn, libcfs_nid2str(peer->ibp_nid), status);
                kibnal_connreq_done(conn, 1, status);
                kibnal_conn_decref(conn); /* drop callback's ref */
                return 1;    /* non-zero prevents further callbacks */
        }

        conn->ibc_connreq->cr_path = *resp;

        kibnal_init_msg(msg, IBNAL_MSG_CONNREQ, sizeof(msg->ibm_u.connparams));
        msg->ibm_u.connparams.ibcp_queue_depth = IBNAL_MSG_QUEUE_SIZE;
        kibnal_pack_msg(msg, conn->ibc_version, 0, 
                        peer->ibp_nid, conn->ibc_incarnation);

        conn->ibc_connreq->cr_connparam = (struct ib_cm_active_param) {
                .qp                   = conn->ibc_qp,
                .req_private_data     = msg,
                .req_private_data_len = msg->ibm_nob,
                .responder_resources  = IBNAL_RESPONDER_RESOURCES,
                .initiator_depth      = IBNAL_RESPONDER_RESOURCES,
                .retry_count          = IBNAL_RETRY,
                .rnr_retry_count      = IBNAL_RNR_RETRY,
                .cm_response_timeout  = *kibnal_tunables.kib_timeout,
                .max_cm_retries       = IBNAL_CM_RETRY,
                .flow_control         = IBNAL_FLOW_CONTROL,
        };

        /* XXX set timeout just like SDP!!!*/
        conn->ibc_connreq->cr_path.packet_life = 13;
        
        /* Flag I'm getting involved with the CM... */
        conn->ibc_state = IBNAL_CONN_CONNECTING;

        CDEBUG(D_NET, "Connecting to, service id "LPX64", on %s\n",
               conn->ibc_connreq->cr_svcrsp.ibsr_svc_id, 
               libcfs_nid2str(peer->ibp_nid));

        /* kibnal_connect_callback gets my conn ref */
        status = ib_cm_connect (&conn->ibc_connreq->cr_connparam, 
                                &conn->ibc_connreq->cr_path, NULL,
                                conn->ibc_connreq->cr_svcrsp.ibsr_svc_id, 0,
                                kibnal_active_conn_callback, conn,
                                &conn->ibc_comm_id);
        if (status != 0) {
                CERROR ("Connect %p -> %s failed: %d\n",
                        conn, libcfs_nid2str(conn->ibc_peer->ibp_nid), status);
                /* Back out state change: I've not got a CM comm_id yet... */
                conn->ibc_state = IBNAL_CONN_INIT_QP;
                kibnal_connreq_done(conn, 1, status);
                kibnal_conn_decref(conn); /* Drop callback's ref */
        }
        
        return 1;    /* non-zero to prevent further callbacks */
}

void
kibnal_connect_peer (kib_peer_t *peer)
{
        kib_conn_t  *conn;
        int          rc;

        conn = kibnal_create_conn();
        if (conn == NULL) {
                CERROR ("Can't allocate conn\n");
                kibnal_peer_connect_failed (peer, 1, -ENOMEM);
                return;
        }

        conn->ibc_peer = peer;
        kibnal_peer_addref(peer);

        LIBCFS_ALLOC (conn->ibc_connreq, sizeof (*conn->ibc_connreq));
        if (conn->ibc_connreq == NULL) {
                CERROR ("Can't allocate connreq\n");
                kibnal_connreq_done(conn, 1, -ENOMEM);
                kibnal_conn_decref(conn); /* drop my ref */
                return;
        }

        memset(conn->ibc_connreq, 0, sizeof (*conn->ibc_connreq));

        rc = kibnal_make_svcqry(conn);
        if (rc != 0) {
                kibnal_connreq_done (conn, 1, rc);
                kibnal_conn_decref(conn); /* drop my ref */
                return;
        }

        rc = ib_cached_gid_get(kibnal_data.kib_device,
                               kibnal_data.kib_port, 0,
                               conn->ibc_connreq->cr_gid);
        LASSERT (rc == 0);

        /* kibnal_pathreq_callback gets my conn ref */
        rc = tsIbPathRecordRequest (kibnal_data.kib_device,
                                    kibnal_data.kib_port,
                                    conn->ibc_connreq->cr_gid,
                                    conn->ibc_connreq->cr_svcrsp.ibsr_svc_gid,
                                    conn->ibc_connreq->cr_svcrsp.ibsr_svc_pkey,
                                    0,
                                    *kibnal_tunables.kib_timeout * HZ,
                                    0,
                                    kibnal_pathreq_callback, conn, 
                                    &conn->ibc_connreq->cr_tid);
        if (rc == 0)
                return; /* callback now has my ref on conn */

        CERROR ("Path record request %p -> %s failed: %d\n",
                conn, libcfs_nid2str(conn->ibc_peer->ibp_nid), rc);
        kibnal_connreq_done(conn, 1, rc);
        kibnal_conn_decref(conn); /* drop my ref */
}

int
kibnal_check_txs (kib_conn_t *conn, struct list_head *txs)
{
        kib_tx_t          *tx;
        struct list_head  *ttmp;
        unsigned long      flags;
        int                timed_out = 0;

        spin_lock_irqsave (&conn->ibc_lock, flags);

        list_for_each (ttmp, txs) {
                tx = list_entry (ttmp, kib_tx_t, tx_list);

                if (txs == &conn->ibc_active_txs) {
                        LASSERT (tx->tx_passive_rdma ||
                                 !tx->tx_passive_rdma_wait);

                        LASSERT (tx->tx_passive_rdma_wait ||
                                 tx->tx_sending != 0);
                } else {
                        LASSERT (!tx->tx_passive_rdma_wait);
                        LASSERT (tx->tx_sending == 0);
                }
                
                if (time_after_eq (jiffies, tx->tx_deadline)) {
                        timed_out = 1;
                        break;
                }
        }

        spin_unlock_irqrestore (&conn->ibc_lock, flags);
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
kibnal_check_conns (int idx)
{
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
        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        list_for_each (ptmp, peers) {
                peer = list_entry (ptmp, kib_peer_t, ibp_list);

                list_for_each (ctmp, &peer->ibp_conns) {
                        conn = list_entry (ctmp, kib_conn_t, ibc_list);

                        LASSERT (conn->ibc_state == IBNAL_CONN_ESTABLISHED);


                        /* In case we have enough credits to return via a
                         * NOOP, but there were no non-blocking tx descs
                         * free to do it last time... */
                        kibnal_check_sends(conn);

                        if (!kibnal_conn_timed_out(conn))
                                continue;
                        
                        kibnal_conn_addref(conn);

                        read_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                               flags);

                        CERROR("Timed out RDMA with %s\n",
                               libcfs_nid2str(peer->ibp_nid));

                        kibnal_close_conn (conn, -ETIMEDOUT);
                        kibnal_conn_decref(conn);

                        /* start again now I've dropped the lock */
                        goto again;
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
}

void
kibnal_terminate_conn (kib_conn_t *conn)
{
        int           rc;

        CDEBUG(D_NET, "conn %p\n", conn);
        LASSERT (conn->ibc_state == IBNAL_CONN_DEATHROW);
        conn->ibc_state = IBNAL_CONN_ZOMBIE;

        rc = ib_cm_disconnect (conn->ibc_comm_id);
        if (rc != 0)
                CERROR ("Error %d disconnecting conn %p -> %s\n",
                        rc, conn, libcfs_nid2str(conn->ibc_peer->ibp_nid));

        kibnal_peer_notify(conn->ibc_peer);
}

int
kibnal_reaper (void *arg)
{
        wait_queue_t       wait;
        unsigned long      flags;
        kib_conn_t        *conn;
        int                timeout;
        int                i;
        int                peer_index = 0;
        unsigned long      deadline = jiffies;
        
        cfs_daemonize ("kibnal_reaper");
        cfs_block_allsigs ();

        init_waitqueue_entry (&wait, current);

        spin_lock_irqsave (&kibnal_data.kib_reaper_lock, flags);

        while (!kibnal_data.kib_shutdown) {
                if (!list_empty (&kibnal_data.kib_reaper_conns)) {
                        conn = list_entry (kibnal_data.kib_reaper_conns.next,
                                           kib_conn_t, ibc_list);
                        list_del (&conn->ibc_list);
                        
                        spin_unlock_irqrestore (&kibnal_data.kib_reaper_lock, flags);

                        switch (conn->ibc_state) {
                        case IBNAL_CONN_DEATHROW:
                                LASSERT (conn->ibc_comm_id != TS_IB_CM_COMM_ID_INVALID);
                                /* Disconnect: conn becomes a zombie in the
                                 * callback and last ref reschedules it
                                 * here... */
                                kibnal_terminate_conn(conn);
                                kibnal_conn_decref(conn);
                                break;

                        case IBNAL_CONN_INIT_QP:
                        case IBNAL_CONN_ZOMBIE:
                                kibnal_destroy_conn (conn);
                                break;
                                
                        default:
                                CERROR ("Bad conn %p state: %d\n",
                                        conn, conn->ibc_state);
                                LBUG();
                        }

                        spin_lock_irqsave (&kibnal_data.kib_reaper_lock, flags);
                        continue;
                }

                spin_unlock_irqrestore (&kibnal_data.kib_reaper_lock, flags);

                /* careful with the jiffy wrap... */
                while ((timeout = (int)(deadline - jiffies)) <= 0) {
                        const int n = 4;
                        const int p = 1;
                        int       chunk = kibnal_data.kib_peer_hash_size;
                        
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
                                kibnal_check_conns (peer_index);
                                peer_index = (peer_index + 1) % 
                                             kibnal_data.kib_peer_hash_size;
                        }

                        deadline += p * HZ;
                }

                kibnal_data.kib_reaper_waketime = jiffies + timeout;

                set_current_state (TASK_INTERRUPTIBLE);
                add_wait_queue (&kibnal_data.kib_reaper_waitq, &wait);

                schedule_timeout (timeout);

                set_current_state (TASK_RUNNING);
                remove_wait_queue (&kibnal_data.kib_reaper_waitq, &wait);

                spin_lock_irqsave (&kibnal_data.kib_reaper_lock, flags);
        }

        spin_unlock_irqrestore (&kibnal_data.kib_reaper_lock, flags);

        kibnal_thread_fini ();
        return (0);
}

int
kibnal_connd (void *arg)
{
        long               id = (long)arg;
        char               name[16];
        wait_queue_t       wait;
        unsigned long      flags;
        kib_peer_t        *peer;
        kib_acceptsock_t  *as;
        int                did_something;

        snprintf(name, sizeof(name), "kibnal_connd_%02ld", id);
        cfs_daemonize(name);
        cfs_block_allsigs();

        init_waitqueue_entry (&wait, current);

        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);

        while (!kibnal_data.kib_shutdown) {
                did_something = 0;

                if (!list_empty (&kibnal_data.kib_connd_acceptq)) {
                        as = list_entry (kibnal_data.kib_connd_acceptq.next,
                                         kib_acceptsock_t, ibas_list);
                        list_del (&as->ibas_list);
                        
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

                        kibnal_handle_svcqry(as->ibas_sock);
                        kibnal_free_acceptsock(as);
                        
                        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
                        did_something = 1;
                }
                        
                /* Only handle an outgoing connection request if there is someone left
                 * to handle an incoming svcqry */
                if (!list_empty (&kibnal_data.kib_connd_peers) &&
                    ((kibnal_data.kib_connd_connecting + 1) < 
                     *kibnal_tunables.kib_n_connd)) {
                        peer = list_entry (kibnal_data.kib_connd_peers.next,
                                           kib_peer_t, ibp_connd_list);
                        
                        list_del_init (&peer->ibp_connd_list);
                        kibnal_data.kib_connd_connecting++;
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

                        kibnal_connect_peer (peer);
                        kibnal_peer_decref(peer);

                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                        did_something = 1;
                        kibnal_data.kib_connd_connecting--;
                }

                if (did_something)
                        continue;

                set_current_state (TASK_INTERRUPTIBLE);
                add_wait_queue_exclusive(&kibnal_data.kib_connd_waitq, &wait);

                spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

                schedule();

                set_current_state (TASK_RUNNING);
                remove_wait_queue (&kibnal_data.kib_connd_waitq, &wait);

                spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
        }

        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

        kibnal_thread_fini ();
        return (0);
}

int
kibnal_scheduler(void *arg)
{
        long            id = (long)arg;
        char            name[16];
        kib_rx_t       *rx;
        kib_tx_t       *tx;
        unsigned long   flags;
        int             rc;
        int             counter = 0;
        int             did_something;

        snprintf(name, sizeof(name), "kibnal_sd_%02ld", id);
        cfs_daemonize(name);
        cfs_block_allsigs();

        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);

        while (!kibnal_data.kib_shutdown) {
                did_something = 0;

                while (!list_empty(&kibnal_data.kib_sched_txq)) {
                        tx = list_entry(kibnal_data.kib_sched_txq.next,
                                        kib_tx_t, tx_list);
                        list_del(&tx->tx_list);
                        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock,
                                               flags);
                        kibnal_tx_done(tx);

                        spin_lock_irqsave(&kibnal_data.kib_sched_lock,
                                          flags);
                }

                if (!list_empty(&kibnal_data.kib_sched_rxq)) {
                        rx = list_entry(kibnal_data.kib_sched_rxq.next,
                                        kib_rx_t, rx_list);
                        list_del(&rx->rx_list);
                        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock,
                                               flags);

                        kibnal_rx(rx);

                        did_something = 1;
                        spin_lock_irqsave(&kibnal_data.kib_sched_lock,
                                          flags);
                }

                /* nothing to do or hogging CPU */
                if (!did_something || counter++ == IBNAL_RESCHED) {
                        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock,
                                               flags);
                        counter = 0;

                        if (!did_something) {
                                rc = wait_event_interruptible_exclusive(
                                        kibnal_data.kib_sched_waitq,
                                        !list_empty(&kibnal_data.kib_sched_txq) || 
                                        !list_empty(&kibnal_data.kib_sched_rxq) || 
                                        kibnal_data.kib_shutdown);
                        } else {
                                our_cond_resched();
                        }

                        spin_lock_irqsave(&kibnal_data.kib_sched_lock,
                                          flags);
                }
        }

        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock, flags);

        kibnal_thread_fini();
        return (0);
}
