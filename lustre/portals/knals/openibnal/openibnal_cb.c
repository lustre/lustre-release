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

/*
 *  LIB functions follow
 *
 */
void
koibnal_schedule_tx_done (koib_tx_t *tx)
{
        unsigned long flags;

        spin_lock_irqsave (&koibnal_data.koib_sched_lock, flags);

        list_add_tail(&tx->tx_list, &koibnal_data.koib_sched_txq);
        wake_up (&koibnal_data.koib_sched_waitq);

        spin_unlock_irqrestore(&koibnal_data.koib_sched_lock, flags);
}

void
koibnal_tx_done (koib_tx_t *tx)
{
        ptl_err_t        ptlrc = (tx->tx_status == 0) ? PTL_OK : PTL_FAIL;
        unsigned long    flags;
        int              i;
        int              rc;

        LASSERT (tx->tx_sending == 0);          /* mustn't be awaiting callback */
        LASSERT (!tx->tx_passive_rdma_wait);    /* mustn't be on ibc_rdma_queue */

        switch (tx->tx_mapped) {
        default:
                LBUG();

        case KOIB_TX_UNMAPPED:
                break;
                
        case KOIB_TX_MAPPED:
                if (in_interrupt()) {
                        /* can't deregister memory in IRQ context... */
                        koibnal_schedule_tx_done(tx);
                        return;
                }
                rc = ib_memory_deregister(tx->tx_md.md_handle.mr);
                LASSERT (rc == 0);
                tx->tx_mapped = KOIB_TX_UNMAPPED;
                break;

#if OPENIBNAL_FMR
        case KOIB_TX_MAPPED_FMR:
                if (in_interrupt() && tx->tx_status != 0) {
                        /* can't flush FMRs in IRQ context... */
                        koibnal_schedule_tx_done(tx);
                        return;
                }              

                rc = ib_fmr_deregister(tx->tx_md.md_handle.fmr);
                LASSERT (rc == 0);

                if (tx->tx_status != 0)
                        ib_fmr_pool_force_flush(koibnal_data.koib_fmr_pool);
                tx->tx_mapped = KOIB_TX_UNMAPPED;
                break;
#endif
        }

        for (i = 0; i < 2; i++) {
                /* tx may have up to 2 libmsgs to finalise */
                if (tx->tx_libmsg[i] == NULL)
                        continue;

                lib_finalize (&koibnal_lib, NULL, tx->tx_libmsg[i], ptlrc);
                tx->tx_libmsg[i] = NULL;
        }
        
        if (tx->tx_conn != NULL) {
                koibnal_put_conn (tx->tx_conn);
                tx->tx_conn = NULL;
        }

        tx->tx_nsp = 0;
        tx->tx_passive_rdma = 0;
        tx->tx_status = 0;

        spin_lock_irqsave (&koibnal_data.koib_tx_lock, flags);

        if (tx->tx_isnblk) {
                list_add_tail (&tx->tx_list, &koibnal_data.koib_idle_nblk_txs);
        } else {
                list_add_tail (&tx->tx_list, &koibnal_data.koib_idle_txs);
                wake_up (&koibnal_data.koib_idle_tx_waitq);
        }

        spin_unlock_irqrestore (&koibnal_data.koib_tx_lock, flags);
}

koib_tx_t *
koibnal_get_idle_tx (int may_block) 
{
        unsigned long    flags;
        koib_tx_t    *tx = NULL;
        
        for (;;) {
                spin_lock_irqsave (&koibnal_data.koib_tx_lock, flags);

                /* "normal" descriptor is free */
                if (!list_empty (&koibnal_data.koib_idle_txs)) {
                        tx = list_entry (koibnal_data.koib_idle_txs.next,
                                         koib_tx_t, tx_list);
                        break;
                }

                if (!may_block) {
                        /* may dip into reserve pool */
                        if (list_empty (&koibnal_data.koib_idle_nblk_txs)) {
                                CERROR ("reserved tx desc pool exhausted\n");
                                break;
                        }

                        tx = list_entry (koibnal_data.koib_idle_nblk_txs.next,
                                         koib_tx_t, tx_list);
                        break;
                }

                /* block for idle tx */
                spin_unlock_irqrestore (&koibnal_data.koib_tx_lock, flags);

                wait_event (koibnal_data.koib_idle_tx_waitq,
                            !list_empty (&koibnal_data.koib_idle_txs) ||
                            koibnal_data.koib_shutdown);
        }

        if (tx != NULL) {
                list_del (&tx->tx_list);

                /* Allocate a new passive RDMA completion cookie.  It might
                 * not be needed, but we've got a lock right now and we're
                 * unlikely to wrap... */
                tx->tx_passive_rdma_cookie = koibnal_data.koib_next_tx_cookie++;

                LASSERT (tx->tx_mapped == KOIB_TX_UNMAPPED);
                LASSERT (tx->tx_nsp == 0);
                LASSERT (tx->tx_sending == 0);
                LASSERT (tx->tx_status == 0);
                LASSERT (tx->tx_conn == NULL);
                LASSERT (!tx->tx_passive_rdma);
                LASSERT (!tx->tx_passive_rdma_wait);
                LASSERT (tx->tx_libmsg[0] == NULL);
                LASSERT (tx->tx_libmsg[1] == NULL);
        }

        spin_unlock_irqrestore (&koibnal_data.koib_tx_lock, flags);
        
        return (tx);
}

int
koibnal_dist(lib_nal_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        /* I would guess that if koibnal_get_peer (nid) == NULL,
           and we're not routing, then 'nid' is very distant :) */
        if ( nal->libnal_ni.ni_pid.nid == nid ) {
                *dist = 0;
        } else {
                *dist = 1;
        }

        return 0;
}

void
koibnal_complete_passive_rdma(koib_conn_t *conn, __u64 cookie, int status)
{
        struct list_head *ttmp;
        unsigned long     flags;
        int               idle;

        spin_lock_irqsave (&conn->ibc_lock, flags);

        list_for_each (ttmp, &conn->ibc_rdma_queue) {
                koib_tx_t *tx = list_entry(ttmp, koib_tx_t, tx_list);
                
                LASSERT (tx->tx_passive_rdma);
                LASSERT (tx->tx_passive_rdma_wait);

                if (tx->tx_passive_rdma_cookie != cookie)
                        continue;

                CDEBUG(D_NET, "Complete %p "LPD64"\n", tx, cookie);

                list_del (&tx->tx_list);

                tx->tx_passive_rdma_wait = 0;
                idle = (tx->tx_sending == 0);

                tx->tx_status = status;

                spin_unlock_irqrestore (&conn->ibc_lock, flags);

                /* I could be racing with tx callbacks.  It's whoever
                 * _makes_ tx idle that frees it */
                if (idle)
                        koibnal_tx_done (tx);
                return;
        }
                
        spin_unlock_irqrestore (&conn->ibc_lock, flags);

        CERROR ("Unmatched (late?) RDMA completion "LPX64" from "LPX64"\n",
                cookie, conn->ibc_peer->ibp_nid);
}

void
koibnal_post_rx (koib_rx_t *rx, int do_credits)
{
        koib_conn_t  *conn = rx->rx_conn;
        int           rc;
        unsigned long flags;

        rx->rx_gl = (struct ib_gather_scatter) {
                .address = rx->rx_vaddr,
                .length  = OPENIBNAL_MSG_SIZE,
                .key     = conn->ibc_rx_pages->oibp_lkey,
        };
        
        rx->rx_sp = (struct ib_receive_param) {
                .work_request_id        = (__u64)(unsigned long)rx,
                .scatter_list           = &rx->rx_gl,
                .num_scatter_entries    = 1,
                .device_specific        = NULL,
                .signaled               = 1,
        };

        LASSERT (conn->ibc_state >= OPENIBNAL_CONN_ESTABLISHED);
        LASSERT (!rx->rx_posted);
        rx->rx_posted = 1;
        mb();

        if (conn->ibc_state != OPENIBNAL_CONN_ESTABLISHED)
                rc = -ECONNABORTED;
        else
                rc = ib_receive (conn->ibc_qp, &rx->rx_sp, 1);

        if (rc == 0) {
                if (do_credits) {
                        spin_lock_irqsave(&conn->ibc_lock, flags);
                        conn->ibc_outstanding_credits++;
                        spin_unlock_irqrestore(&conn->ibc_lock, flags);

                        koibnal_check_sends(conn);
                }
                return;
        }

        if (conn->ibc_state == OPENIBNAL_CONN_ESTABLISHED) {
                CERROR ("Error posting receive -> "LPX64": %d\n",
                        conn->ibc_peer->ibp_nid, rc);
                koibnal_close_conn (rx->rx_conn, rc);
        } else {
                CDEBUG (D_NET, "Error posting receive -> "LPX64": %d\n",
                        conn->ibc_peer->ibp_nid, rc);
        }

        /* Drop rx's ref */
        koibnal_put_conn (conn);
}

#if OPENIBNAL_CKSUM
__u32 koibnal_cksum (void *ptr, int nob)
{
        char  *c  = ptr;
        __u32  sum = 0;

        while (nob-- > 0)
                sum = ((sum << 1) | (sum >> 31)) + *c++;
        
        return (sum);
}
#endif

void
koibnal_rx_callback (struct ib_cq *cq, struct ib_cq_entry *e, void *arg)
{
        koib_rx_t    *rx = (koib_rx_t *)((unsigned long)e->work_request_id);
        koib_msg_t   *msg = rx->rx_msg;
        koib_conn_t  *conn = rx->rx_conn;
        int           nob = e->bytes_transferred;
        const int     base_nob = offsetof(koib_msg_t, oibm_u);
        int           credits;
        int           flipped;
        unsigned long flags;
#if OPENIBNAL_CKSUM
        __u32         msg_cksum;
        __u32         computed_cksum;
#endif

        CDEBUG (D_NET, "rx %p conn %p\n", rx, conn);
        LASSERT (rx->rx_posted);
        rx->rx_posted = 0;
        mb();

        /* receives complete with error in any case after we've started
         * closing the QP */
        if (conn->ibc_state >= OPENIBNAL_CONN_DEATHROW)
                goto failed;

        /* We don't post receives until the conn is established */
        LASSERT (conn->ibc_state == OPENIBNAL_CONN_ESTABLISHED);

        if (e->status != IB_COMPLETION_STATUS_SUCCESS) {
                CERROR("Rx from "LPX64" failed: %d\n", 
                       conn->ibc_peer->ibp_nid, e->status);
                goto failed;
        }

        if (nob < base_nob) {
                CERROR ("Short rx from "LPX64": %d\n",
                        conn->ibc_peer->ibp_nid, nob);
                goto failed;
        }

        /* Receiver does any byte flipping if necessary... */

        if (msg->oibm_magic == OPENIBNAL_MSG_MAGIC) {
                flipped = 0;
        } else {
                if (msg->oibm_magic != __swab32(OPENIBNAL_MSG_MAGIC)) {
                        CERROR ("Unrecognised magic: %08x from "LPX64"\n", 
                                msg->oibm_magic, conn->ibc_peer->ibp_nid);
                        goto failed;
                }
                flipped = 1;
                __swab16s (&msg->oibm_version);
                LASSERT (sizeof(msg->oibm_type) == 1);
                LASSERT (sizeof(msg->oibm_credits) == 1);
        }

        if (msg->oibm_version != OPENIBNAL_MSG_VERSION) {
                CERROR ("Incompatible msg version %d (%d expected)\n",
                        msg->oibm_version, OPENIBNAL_MSG_VERSION);
                goto failed;
        }

#if OPENIBNAL_CKSUM
        if (nob != msg->oibm_nob) {
                CERROR ("Unexpected # bytes %d (%d expected)\n", nob, msg->oibm_nob);
                goto failed;
        }

        msg_cksum = le32_to_cpu(msg->oibm_cksum);
        msg->oibm_cksum = 0;
        computed_cksum = koibnal_cksum (msg, nob);
        
        if (msg_cksum != computed_cksum) {
                CERROR ("Checksum failure %d: (%d expected)\n",
                        computed_cksum, msg_cksum);
                goto failed;
        }
        CDEBUG(D_NET, "cksum %x, nob %d\n", computed_cksum, nob);
#endif

        /* Have I received credits that will let me send? */
        credits = msg->oibm_credits;
        if (credits != 0) {
                spin_lock_irqsave(&conn->ibc_lock, flags);
                conn->ibc_credits += credits;
                spin_unlock_irqrestore(&conn->ibc_lock, flags);
                
                koibnal_check_sends(conn);
        }

        switch (msg->oibm_type) {
        case OPENIBNAL_MSG_NOOP:
                koibnal_post_rx (rx, 1);
                return;

        case OPENIBNAL_MSG_IMMEDIATE:
                if (nob < base_nob + sizeof (koib_immediate_msg_t)) {
                        CERROR ("Short IMMEDIATE from "LPX64": %d\n",
                                conn->ibc_peer->ibp_nid, nob);
                        goto failed;
                }
                break;
                
        case OPENIBNAL_MSG_PUT_RDMA:
        case OPENIBNAL_MSG_GET_RDMA:
                if (nob < base_nob + sizeof (koib_rdma_msg_t)) {
                        CERROR ("Short RDMA msg from "LPX64": %d\n",
                                conn->ibc_peer->ibp_nid, nob);
                        goto failed;
                }
                if (flipped) {
                        __swab32s(&msg->oibm_u.rdma.oibrm_desc.rd_key);
                        __swab32s(&msg->oibm_u.rdma.oibrm_desc.rd_nob);
                        __swab64s(&msg->oibm_u.rdma.oibrm_desc.rd_addr);
                }
                CDEBUG(D_NET, "%d RDMA: cookie "LPX64", key %x, addr "LPX64", nob %d\n",
                       msg->oibm_type, msg->oibm_u.rdma.oibrm_cookie,
                       msg->oibm_u.rdma.oibrm_desc.rd_key,
                       msg->oibm_u.rdma.oibrm_desc.rd_addr,
                       msg->oibm_u.rdma.oibrm_desc.rd_nob);
                break;
                
        case OPENIBNAL_MSG_PUT_DONE:
        case OPENIBNAL_MSG_GET_DONE:
                if (nob < base_nob + sizeof (koib_completion_msg_t)) {
                        CERROR ("Short COMPLETION msg from "LPX64": %d\n",
                                conn->ibc_peer->ibp_nid, nob);
                        goto failed;
                }
                if (flipped)
                        __swab32s(&msg->oibm_u.completion.oibcm_status);
                
                CDEBUG(D_NET, "%d DONE: cookie "LPX64", status %d\n",
                       msg->oibm_type, msg->oibm_u.completion.oibcm_cookie,
                       msg->oibm_u.completion.oibcm_status);

                koibnal_complete_passive_rdma (conn, 
                                               msg->oibm_u.completion.oibcm_cookie,
                                               msg->oibm_u.completion.oibcm_status);
                koibnal_post_rx (rx, 1);
                return;
                        
        default:
                CERROR ("Can't parse type from "LPX64": %d\n",
                        conn->ibc_peer->ibp_nid, msg->oibm_type);
                goto failed;
        }

        /* schedule for koibnal_rx() in thread context */
        spin_lock_irqsave(&koibnal_data.koib_sched_lock, flags);
        
        list_add_tail (&rx->rx_list, &koibnal_data.koib_sched_rxq);
        wake_up (&koibnal_data.koib_sched_waitq);
        
        spin_unlock_irqrestore(&koibnal_data.koib_sched_lock, flags);
        return;
        
 failed:
        CDEBUG(D_NET, "rx %p conn %p\n", rx, conn);
        koibnal_close_conn(conn, -ECONNABORTED);

        /* Don't re-post rx & drop its ref on conn */
        koibnal_put_conn(conn);
}

void
koibnal_rx (koib_rx_t *rx)
{
        koib_msg_t   *msg = rx->rx_msg;

        /* Clear flag so I can detect if I've sent an RDMA completion */
        rx->rx_rdma = 0;

        switch (msg->oibm_type) {
        case OPENIBNAL_MSG_GET_RDMA:
                lib_parse(&koibnal_lib, &msg->oibm_u.rdma.oibrm_hdr, rx);
                /* If the incoming get was matched, I'll have initiated the
                 * RDMA and the completion message... */
                if (rx->rx_rdma)
                        break;

                /* Otherwise, I'll send a failed completion now to prevent
                 * the peer's GET blocking for the full timeout. */
                CERROR ("Completing unmatched RDMA GET from "LPX64"\n",
                        rx->rx_conn->ibc_peer->ibp_nid);
                koibnal_start_active_rdma (OPENIBNAL_MSG_GET_DONE, -EIO,
                                           rx, NULL, 0, NULL, NULL, 0, 0);
                break;
                
        case OPENIBNAL_MSG_PUT_RDMA:
                lib_parse(&koibnal_lib, &msg->oibm_u.rdma.oibrm_hdr, rx);
                if (rx->rx_rdma)
                        break;
                /* This is most unusual, since even if lib_parse() didn't
                 * match anything, it should have asked us to read (and
                 * discard) the payload.  The portals header must be
                 * inconsistent with this message type, so it's the
                 * sender's fault for sending garbage and she can time
                 * herself out... */
                CERROR ("Uncompleted RMDA PUT from "LPX64"\n",
                        rx->rx_conn->ibc_peer->ibp_nid);
                break;

        case OPENIBNAL_MSG_IMMEDIATE:
                lib_parse(&koibnal_lib, &msg->oibm_u.immediate.oibim_hdr, rx);
                LASSERT (!rx->rx_rdma);
                break;
                
        default:
                LBUG();
                break;
        }

        koibnal_post_rx (rx, 1);
}

#if 0
int
koibnal_kvaddr_to_phys (unsigned long vaddr, __u64 *physp)
{
        struct page *page;

        if (vaddr >= VMALLOC_START &&
            vaddr < VMALLOC_END)
                page = vmalloc_to_page ((void *)vaddr);
#if CONFIG_HIGHMEM
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

        *physp = koibnal_page2phys(page) + (vaddr & (PAGE_SIZE - 1));
        return (0);
}
#endif

int
koibnal_map_iov (koib_tx_t *tx, enum ib_memory_access access,
                 int niov, struct iovec *iov, int offset, int nob)
                 
{
        void   *vaddr;
        int     rc;

        LASSERT (nob > 0);
        LASSERT (niov > 0);
        LASSERT (tx->tx_mapped == KOIB_TX_UNMAPPED);

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

        rc = ib_memory_register (koibnal_data.koib_pd,
                                 vaddr, nob,
                                 access,
                                 &tx->tx_md.md_handle.mr,
                                 &tx->tx_md.md_lkey,
                                 &tx->tx_md.md_rkey);
        
        if (rc != 0) {
                CERROR ("Can't map vaddr: %d\n", rc);
                return (rc);
        }

        tx->tx_mapped = KOIB_TX_MAPPED;
        return (0);
}

int
koibnal_map_kiov (koib_tx_t *tx, enum ib_memory_access access,
                  int nkiov, ptl_kiov_t *kiov,
                  int offset, int nob)
{
#if OPENIBNAL_FMR
        __u64                      *phys;
        const int                   mapped = KOIB_TX_MAPPED_FMR;
#else
        struct ib_physical_buffer  *phys;
        const int                   mapped = KOIB_TX_MAPPED;
#endif
        int                         page_offset;
        int                         nphys;
        int                         resid;
        int                         phys_size;
        int                         rc;

        CDEBUG(D_NET, "niov %d offset %d nob %d\n", nkiov, offset, nob);

        LASSERT (nob > 0);
        LASSERT (nkiov > 0);
        LASSERT (tx->tx_mapped == KOIB_TX_UNMAPPED);

        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                nkiov--;
                kiov++;
                LASSERT (nkiov > 0);
        }

        phys_size = nkiov * sizeof (*phys);
        PORTAL_ALLOC(phys, phys_size);
        if (phys == NULL) {
                CERROR ("Can't allocate tmp phys\n");
                return (-ENOMEM);
        }

        page_offset = kiov->kiov_offset + offset;
#if OPENIBNAL_FMR
        phys[0] = koibnal_page2phys(kiov->kiov_page);
#else
        phys[0].address = koibnal_page2phys(kiov->kiov_page);
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

                if (nphys == PTL_MD_MAX_IOV) {
                        CERROR ("payload too big (%d)\n", nphys);
                        rc = -EMSGSIZE;
                        goto out;
                }

                LASSERT (nphys * sizeof (*phys) < phys_size);
#if OPENIBNAL_FMR
                phys[nphys] = koibnal_page2phys(kiov->kiov_page);
#else
                phys[nphys].address = koibnal_page2phys(kiov->kiov_page);
                phys[nphys].size = PAGE_SIZE;
#endif
                nphys++;

                resid -= PAGE_SIZE;
        }

#if 0
        CWARN ("nphys %d, nob %d, page_offset %d\n", nphys, nob, page_offset);
        for (rc = 0; rc < nphys; rc++)
                CWARN ("   [%d] "LPX64" / %d\n", rc, phys[rc].address, phys[rc].size);
#endif
        tx->tx_md.md_addr = OPENIBNAL_RDMA_BASE;

#if OPENIBNAL_FMR
        rc = ib_fmr_register_physical (koibnal_data.koib_fmr_pool,
                                       phys, nphys,
                                       &tx->tx_md.md_addr,
                                       page_offset,
                                       &tx->tx_md.md_handle.fmr,
                                       &tx->tx_md.md_lkey,
                                       &tx->tx_md.md_rkey);
#else
        rc = ib_memory_register_physical (koibnal_data.koib_pd,
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
        PORTAL_FREE(phys, phys_size);
        return (rc);
}

koib_conn_t *
koibnal_find_conn_locked (koib_peer_t *peer)
{
        struct list_head *tmp;

        /* just return the first connection */
        list_for_each (tmp, &peer->ibp_conns) {
                return (list_entry(tmp, koib_conn_t, ibc_list));
        }

        return (NULL);
}

void
koibnal_check_sends (koib_conn_t *conn)
{
        unsigned long   flags;
        koib_tx_t      *tx;
        int             rc;
        int             i;
        int             done;
        int             nwork;

        spin_lock_irqsave (&conn->ibc_lock, flags);

        if (list_empty(&conn->ibc_tx_queue) &&
            conn->ibc_outstanding_credits >= OPENIBNAL_CREDIT_HIGHWATER) {
                spin_unlock_irqrestore(&conn->ibc_lock, flags);

                tx = koibnal_get_idle_tx(0);     /* don't block */
                if (tx != NULL)
                        koibnal_init_tx_msg(tx, OPENIBNAL_MSG_NOOP, 0);

                spin_lock_irqsave(&conn->ibc_lock, flags);

                if (tx != NULL) {
                        atomic_inc(&conn->ibc_refcount);
                        koibnal_queue_tx_locked(tx, conn);
                }
        }

        LASSERT (conn->ibc_nsends_posted <= OPENIBNAL_MSG_QUEUE_SIZE);

        while (!list_empty (&conn->ibc_tx_queue)) {
                tx = list_entry (conn->ibc_tx_queue.next, koib_tx_t, tx_list);

                /* We rely on this for QP sizing */
                LASSERT (tx->tx_nsp > 0 && tx->tx_nsp <= 2);

                LASSERT (conn->ibc_outstanding_credits >= 0);
                LASSERT (conn->ibc_outstanding_credits <= OPENIBNAL_MSG_QUEUE_SIZE);
                LASSERT (conn->ibc_credits >= 0);
                LASSERT (conn->ibc_credits <= OPENIBNAL_MSG_QUEUE_SIZE);

                /* Not on ibc_rdma_queue */
                LASSERT (!tx->tx_passive_rdma_wait);

                if (conn->ibc_nsends_posted == OPENIBNAL_MSG_QUEUE_SIZE)
                        break;

                if (conn->ibc_credits == 0)     /* no credits */
                        break;
                
                if (conn->ibc_credits == 1 &&   /* last credit reserved for */
                    conn->ibc_outstanding_credits == 0) /* giving back credits */
                        break;

                list_del (&tx->tx_list);

                if (tx->tx_msg->oibm_type == OPENIBNAL_MSG_NOOP &&
                    (!list_empty(&conn->ibc_tx_queue) ||
                     conn->ibc_outstanding_credits < OPENIBNAL_CREDIT_HIGHWATER)) {
                        /* Redundant NOOP */
                        spin_unlock_irqrestore(&conn->ibc_lock, flags);
                        koibnal_tx_done(tx);
                        spin_lock_irqsave(&conn->ibc_lock, flags);
                        continue;
                }
                
                /* incoming RDMA completion can find this one now */
                if (tx->tx_passive_rdma) {
                        list_add (&tx->tx_list, &conn->ibc_rdma_queue);
                        tx->tx_passive_rdma_wait = 1;
                        tx->tx_passive_rdma_deadline = 
                                jiffies + koibnal_tunables.koib_io_timeout * HZ;
                }

                tx->tx_msg->oibm_credits = conn->ibc_outstanding_credits;
                conn->ibc_outstanding_credits = 0;

                /* use the free memory barrier when we unlock to ensure
                 * sending set before we can get the tx callback. */
                conn->ibc_nsends_posted++;
                conn->ibc_credits--;
                tx->tx_sending = tx->tx_nsp;

#if OPENIBNAL_CKSUM
                tx->tx_msg->oibm_cksum = 0;
                tx->tx_msg->oibm_cksum = koibnal_cksum(tx->tx_msg, tx->tx_msg->oibm_nob);
                CDEBUG(D_NET, "cksum %x, nob %d\n", tx->tx_msg->oibm_cksum, tx->tx_msg->oibm_nob);
#endif
                spin_unlock_irqrestore (&conn->ibc_lock, flags);

                /* NB the gap between removing tx from the queue and sending it
                 * allows message re-ordering to occur */

                LASSERT (tx->tx_nsp > 0);

                rc = -ECONNABORTED;
                nwork = 0;
                if (conn->ibc_state == OPENIBNAL_CONN_ESTABLISHED) {
                        tx->tx_status = 0;
                        /* Driver only accepts 1 item at a time */
                        for (i = 0; i < tx->tx_nsp; i++) {
                                rc = ib_send (conn->ibc_qp, &tx->tx_sp[i], 1);
                                if (rc != 0)
                                        break;
                                nwork++;
                        }
                }

                spin_lock_irqsave (&conn->ibc_lock, flags);
                if (rc != 0) {
                        /* NB credits are transferred in the actual
                         * message, which can only be the last work item */
                        conn->ibc_outstanding_credits += tx->tx_msg->oibm_credits;
                        conn->ibc_credits++;
                        conn->ibc_nsends_posted--;
                        tx->tx_sending -= tx->tx_nsp - nwork;
                        tx->tx_status = rc;
                        done = (tx->tx_sending == 0);
                        
                        if (tx->tx_passive_rdma) {
                                tx->tx_passive_rdma_wait = 0;
                                list_del (&tx->tx_list);
                        }
                        
                        spin_unlock_irqrestore (&conn->ibc_lock, flags);
                        
                        if (conn->ibc_state == OPENIBNAL_CONN_ESTABLISHED)
                                CERROR ("Error %d posting transmit to "LPX64"\n", 
                                        rc, conn->ibc_peer->ibp_nid);
                        else
                                CDEBUG (D_NET, "Error %d posting transmit to "
                                        LPX64"\n", rc, conn->ibc_peer->ibp_nid);

                        koibnal_close_conn (conn, rc);

                        if (done)
                                koibnal_tx_done (tx);
                        return;
                }
                
        }

        spin_unlock_irqrestore (&conn->ibc_lock, flags);
}

void
koibnal_tx_callback (struct ib_cq *cq, struct ib_cq_entry *e, void *arg)
{
        koib_tx_t    *tx = (koib_tx_t *)((unsigned long)e->work_request_id);
        koib_conn_t  *conn;
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

        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
               conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
               atomic_read (&conn->ibc_refcount));
        atomic_inc (&conn->ibc_refcount);

        if (tx->tx_sending == 0)
                conn->ibc_nsends_posted--;

        if (e->status != IB_COMPLETION_STATUS_SUCCESS &&
            tx->tx_status == 0)
                tx->tx_status = -ECONNABORTED;
                
        spin_unlock_irqrestore(&conn->ibc_lock, flags);

        if (idle)
                koibnal_tx_done (tx);

        if (e->status != IB_COMPLETION_STATUS_SUCCESS) {
                CERROR ("Tx completion to "LPX64" failed: %d\n", 
                        conn->ibc_peer->ibp_nid, e->status);
                koibnal_close_conn (conn, -ENETDOWN);
        } else {
                /* can I shovel some more sends out the door? */
                koibnal_check_sends(conn);
        }

        koibnal_put_conn (conn);
}

void
koibnal_init_tx_msg (koib_tx_t *tx, int type, int body_nob)
{
        struct ib_gather_scatter *gl = &tx->tx_gl[tx->tx_nsp];
        struct ib_send_param     *sp = &tx->tx_sp[tx->tx_nsp];
        int                       fence;
        int                       nob = offsetof (koib_msg_t, oibm_u) + body_nob;

        LASSERT (tx->tx_nsp >= 0 && 
                 tx->tx_nsp < sizeof(tx->tx_sp)/sizeof(tx->tx_sp[0]));
        LASSERT (nob <= OPENIBNAL_MSG_SIZE);
        
        tx->tx_msg->oibm_magic = OPENIBNAL_MSG_MAGIC;
        tx->tx_msg->oibm_version = OPENIBNAL_MSG_VERSION;
        tx->tx_msg->oibm_type = type;
#if OPENIBNAL_CKSUM
        tx->tx_msg->oibm_nob = nob;
#endif
        /* Fence the message if it's bundled with an RDMA read */
        fence = (tx->tx_nsp > 0) &&
                (type == OPENIBNAL_MSG_PUT_DONE);

        *gl = (struct ib_gather_scatter) {
                .address = tx->tx_vaddr,
                .length  = nob,
                .key     = koibnal_data.koib_tx_pages->oibp_lkey,
        };

        /* NB If this is an RDMA read, the completion message must wait for
         * the RDMA to complete.  Sends wait for previous RDMA writes
         * anyway... */
        *sp = (struct ib_send_param) {
                .work_request_id      = (__u64)((unsigned long)tx),
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
koibnal_queue_tx (koib_tx_t *tx, koib_conn_t *conn)
{
        unsigned long         flags;

        spin_lock_irqsave(&conn->ibc_lock, flags);

        koibnal_queue_tx_locked (tx, conn);
        
        spin_unlock_irqrestore(&conn->ibc_lock, flags);
        
        koibnal_check_sends(conn);
}

void
koibnal_launch_tx (koib_tx_t *tx, ptl_nid_t nid)
{
        unsigned long    flags;
        koib_peer_t     *peer;
        koib_conn_t     *conn;
        rwlock_t        *g_lock = &koibnal_data.koib_global_lock;

        /* If I get here, I've committed to send, so I complete the tx with
         * failure on any problems */
        
        LASSERT (tx->tx_conn == NULL);          /* only set when assigned a conn */
        LASSERT (tx->tx_nsp > 0);               /* work items have been set up */

        read_lock (g_lock);
        
        peer = koibnal_find_peer_locked (nid);
        if (peer == NULL) {
                read_unlock (g_lock);
                tx->tx_status = -EHOSTUNREACH;
                koibnal_tx_done (tx);
                return;
        }

        conn = koibnal_find_conn_locked (peer);
        if (conn != NULL) {
                CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                       atomic_read (&conn->ibc_refcount));
                atomic_inc (&conn->ibc_refcount); /* 1 ref for the tx */
                read_unlock (g_lock);
                
                koibnal_queue_tx (tx, conn);
                return;
        }
        
        /* Making one or more connections; I'll need a write lock... */
        read_unlock (g_lock);
        write_lock_irqsave (g_lock, flags);

        peer = koibnal_find_peer_locked (nid);
        if (peer == NULL) {
                write_unlock_irqrestore (g_lock, flags);
                tx->tx_status = -EHOSTUNREACH;
                koibnal_tx_done (tx);
                return;
        }

        conn = koibnal_find_conn_locked (peer);
        if (conn != NULL) {
                /* Connection exists; queue message on it */
                CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                       atomic_read (&conn->ibc_refcount));
                atomic_inc (&conn->ibc_refcount); /* 1 ref for the tx */
                write_unlock_irqrestore (g_lock, flags);
                
                koibnal_queue_tx (tx, conn);
                return;
        }

        if (peer->ibp_connecting == 0) {
                if (!time_after_eq(jiffies, peer->ibp_reconnect_time)) {
                        write_unlock_irqrestore (g_lock, flags);
                        tx->tx_status = -EHOSTUNREACH;
                        koibnal_tx_done (tx);
                        return;
                }
        
                peer->ibp_connecting = 1;
                atomic_inc (&peer->ibp_refcount); /* extra ref for connd */
        
                spin_lock (&koibnal_data.koib_connd_lock);
        
                list_add_tail (&peer->ibp_connd_list,
                               &koibnal_data.koib_connd_peers);
                wake_up (&koibnal_data.koib_connd_waitq);
        
                spin_unlock (&koibnal_data.koib_connd_lock);
        }
        
        /* A connection is being established; queue the message... */
        list_add_tail (&tx->tx_list, &peer->ibp_tx_queue);

        write_unlock_irqrestore (g_lock, flags);
}

ptl_err_t
koibnal_start_passive_rdma (int type, ptl_nid_t nid,
                            lib_msg_t *libmsg, ptl_hdr_t *hdr)
{
        int         nob = libmsg->md->length;
        koib_tx_t  *tx;
        koib_msg_t *oibmsg;
        int         rc;
        int         access;
        
        LASSERT (type == OPENIBNAL_MSG_PUT_RDMA || 
                 type == OPENIBNAL_MSG_GET_RDMA);
        LASSERT (nob > 0);
        LASSERT (!in_interrupt());              /* Mapping could block */

        if (type == OPENIBNAL_MSG_PUT_RDMA) {
                access = IB_ACCESS_REMOTE_READ;
        } else {
                access = IB_ACCESS_REMOTE_WRITE |
                         IB_ACCESS_LOCAL_WRITE;
        }

        tx = koibnal_get_idle_tx (1);           /* May block; caller is an app thread */
        LASSERT (tx != NULL);

        if ((libmsg->md->options & PTL_MD_KIOV) == 0) 
                rc = koibnal_map_iov (tx, access,
                                      libmsg->md->md_niov,
                                      libmsg->md->md_iov.iov,
                                      0, nob);
        else
                rc = koibnal_map_kiov (tx, access,
                                       libmsg->md->md_niov, 
                                       libmsg->md->md_iov.kiov,
                                       0, nob);

        if (rc != 0) {
                CERROR ("Can't map RDMA for "LPX64": %d\n", nid, rc);
                goto failed;
        }
        
        if (type == OPENIBNAL_MSG_GET_RDMA) {
                /* reply gets finalized when tx completes */
                tx->tx_libmsg[1] = lib_create_reply_msg(&koibnal_lib, 
                                                        nid, libmsg);
                if (tx->tx_libmsg[1] == NULL) {
                        CERROR ("Can't create reply for GET -> "LPX64"\n",
                                nid);
                        rc = -ENOMEM;
                        goto failed;
                }
        }
        
        tx->tx_passive_rdma = 1;

        oibmsg = tx->tx_msg;

        oibmsg->oibm_u.rdma.oibrm_hdr = *hdr;
        oibmsg->oibm_u.rdma.oibrm_cookie = tx->tx_passive_rdma_cookie;
        oibmsg->oibm_u.rdma.oibrm_desc.rd_key = tx->tx_md.md_rkey;
        oibmsg->oibm_u.rdma.oibrm_desc.rd_addr = tx->tx_md.md_addr;
        oibmsg->oibm_u.rdma.oibrm_desc.rd_nob = nob;

        koibnal_init_tx_msg (tx, type, sizeof (koib_rdma_msg_t));

        CDEBUG(D_NET, "Passive: %p cookie "LPX64", key %x, addr "
               LPX64", nob %d\n",
               tx, tx->tx_passive_rdma_cookie, tx->tx_md.md_rkey,
               tx->tx_md.md_addr, nob);
        
        /* libmsg gets finalized when tx completes. */
        tx->tx_libmsg[0] = libmsg;

        koibnal_launch_tx(tx, nid);
        return (PTL_OK);

 failed:
        tx->tx_status = rc;
        koibnal_tx_done (tx);
        return (PTL_FAIL);
}

void
koibnal_start_active_rdma (int type, int status,
                           koib_rx_t *rx, lib_msg_t *libmsg, 
                           unsigned int niov,
                           struct iovec *iov, ptl_kiov_t *kiov,
                           size_t offset, size_t nob)
{
        koib_msg_t   *rxmsg = rx->rx_msg;
        koib_msg_t   *txmsg;
        koib_tx_t    *tx;
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

        LASSERT (type == OPENIBNAL_MSG_GET_DONE ||
                 type == OPENIBNAL_MSG_PUT_DONE);

        /* Flag I'm completing the RDMA.  Even if I fail to send the
         * completion message, I will have tried my best so further
         * attempts shouldn't be tried. */
        LASSERT (!rx->rx_rdma);
        rx->rx_rdma = 1;

        if (type == OPENIBNAL_MSG_GET_DONE) {
                access   = 0;
                rdma_op  = IB_OP_RDMA_WRITE;
                LASSERT (rxmsg->oibm_type == OPENIBNAL_MSG_GET_RDMA);
        } else {
                access   = IB_ACCESS_LOCAL_WRITE;
                rdma_op  = IB_OP_RDMA_READ;
                LASSERT (rxmsg->oibm_type == OPENIBNAL_MSG_PUT_RDMA);
        }

        tx = koibnal_get_idle_tx (0);           /* Mustn't block */
        if (tx == NULL) {
                CERROR ("tx descs exhausted on RDMA from "LPX64
                        " completing locally with failure\n",
                         rx->rx_conn->ibc_peer->ibp_nid);
                lib_finalize (&koibnal_lib, NULL, libmsg, PTL_NO_SPACE);
                return;
        }
        LASSERT (tx->tx_nsp == 0);
                        
        if (nob != 0) {
                /* We actually need to transfer some data (the transfer
                 * size could get truncated to zero when the incoming
                 * message is matched) */

                if (kiov != NULL)
                        rc = koibnal_map_kiov (tx, access,
                                               niov, kiov, offset, nob);
                else
                        rc = koibnal_map_iov (tx, access,
                                              niov, iov, offset, nob);
                
                if (rc != 0) {
                        CERROR ("Can't map RDMA -> "LPX64": %d\n", 
                                rx->rx_conn->ibc_peer->ibp_nid, rc);
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
                                .work_request_id      = (__u64)((unsigned long)tx),
                                .op                   = rdma_op,
                                .gather_list          = &tx->tx_gl[0],
                                .num_gather_entries   = 1,
                                .remote_address       = rxmsg->oibm_u.rdma.oibrm_desc.rd_addr,
                                .rkey                 = rxmsg->oibm_u.rdma.oibrm_desc.rd_key,
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

        txmsg->oibm_u.completion.oibcm_cookie = rxmsg->oibm_u.rdma.oibrm_cookie;
        txmsg->oibm_u.completion.oibcm_status = status;
        
        koibnal_init_tx_msg(tx, type, sizeof (koib_completion_msg_t));

        if (status == 0 && nob != 0) {
                LASSERT (tx->tx_nsp > 1);
                /* RDMA: libmsg gets finalized when the tx completes.  This
                 * is after the completion message has been sent, which in
                 * turn is after the RDMA has finished. */
                tx->tx_libmsg[0] = libmsg;
        } else {
                LASSERT (tx->tx_nsp == 1);
                /* No RDMA: local completion happens now! */
                CDEBUG(D_WARNING,"No data: immediate completion\n");
                lib_finalize (&koibnal_lib, NULL, libmsg,
                              status == 0 ? PTL_OK : PTL_FAIL);
        }

        /* +1 ref for this tx... */
        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
               rx->rx_conn, rx->rx_conn->ibc_state, 
               rx->rx_conn->ibc_peer->ibp_nid,
               atomic_read (&rx->rx_conn->ibc_refcount));
        atomic_inc (&rx->rx_conn->ibc_refcount);
        /* ...and queue it up */
        koibnal_queue_tx(tx, rx->rx_conn);
}

ptl_err_t
koibnal_sendmsg(lib_nal_t    *nal, 
                void         *private,
                lib_msg_t    *libmsg,
                ptl_hdr_t    *hdr, 
                int           type, 
                ptl_nid_t     nid, 
                ptl_pid_t     pid,
                unsigned int  payload_niov, 
                struct iovec *payload_iov, 
                ptl_kiov_t   *payload_kiov,
                size_t        payload_offset,
                size_t        payload_nob)
{
        koib_msg_t *oibmsg;
        koib_tx_t  *tx;
        int         nob;

        /* NB 'private' is different depending on what we're sending.... */

        CDEBUG(D_NET, "sending "LPSZ" bytes in %d frags to nid:"LPX64
               " pid %d\n", payload_nob, payload_niov, nid , pid);

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV);

        /* Thread context if we're sending payload */
        LASSERT (!in_interrupt() || payload_niov == 0);
        /* payload is either all vaddrs or all pages */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));

        switch (type) {
        default:
                LBUG();
                return (PTL_FAIL);
                
        case PTL_MSG_REPLY: {
                /* reply's 'private' is the incoming receive */
                koib_rx_t *rx = private;

                /* RDMA reply expected? */
                if (rx->rx_msg->oibm_type == OPENIBNAL_MSG_GET_RDMA) {
                        koibnal_start_active_rdma(OPENIBNAL_MSG_GET_DONE, 0,
                                                  rx, libmsg, payload_niov, 
                                                  payload_iov, payload_kiov,
                                                  payload_offset, payload_nob);
                        return (PTL_OK);
                }
                
                /* Incoming message consistent with immediate reply? */
                if (rx->rx_msg->oibm_type != OPENIBNAL_MSG_IMMEDIATE) {
                        CERROR ("REPLY to "LPX64" bad opbm type %d!!!\n",
                                nid, rx->rx_msg->oibm_type);
                        return (PTL_FAIL);
                }

                /* Will it fit in a message? */
                nob = offsetof(koib_msg_t, oibm_u.immediate.oibim_payload[payload_nob]);
                if (nob >= OPENIBNAL_MSG_SIZE) {
                        CERROR("REPLY for "LPX64" too big (RDMA not requested): %d\n", 
                               nid, payload_nob);
                        return (PTL_FAIL);
                }
                break;
        }

        case PTL_MSG_GET:
                /* might the REPLY message be big enough to need RDMA? */
                nob = offsetof(koib_msg_t, oibm_u.immediate.oibim_payload[libmsg->md->length]);
                if (nob > OPENIBNAL_MSG_SIZE)
                        return (koibnal_start_passive_rdma(OPENIBNAL_MSG_GET_RDMA, 
                                                           nid, libmsg, hdr));
                break;

        case PTL_MSG_ACK:
                LASSERT (payload_nob == 0);
                break;

        case PTL_MSG_PUT:
                /* Is the payload big enough to need RDMA? */
                nob = offsetof(koib_msg_t, oibm_u.immediate.oibim_payload[payload_nob]);
                if (nob > OPENIBNAL_MSG_SIZE)
                        return (koibnal_start_passive_rdma(OPENIBNAL_MSG_PUT_RDMA,
                                                           nid, libmsg, hdr));
                
                break;
        }

        tx = koibnal_get_idle_tx(!(type == PTL_MSG_ACK ||
                                   type == PTL_MSG_REPLY ||
                                   in_interrupt()));
        if (tx == NULL) {
                CERROR ("Can't send %d to "LPX64": tx descs exhausted%s\n", 
                        type, nid, in_interrupt() ? " (intr)" : "");
                return (PTL_NO_SPACE);
        }

        oibmsg = tx->tx_msg;
        oibmsg->oibm_u.immediate.oibim_hdr = *hdr;

        if (payload_nob > 0) {
                if (payload_kiov != NULL)
                        lib_copy_kiov2buf(oibmsg->oibm_u.immediate.oibim_payload,
                                          payload_niov, payload_kiov,
                                          payload_offset, payload_nob);
                else
                        lib_copy_iov2buf(oibmsg->oibm_u.immediate.oibim_payload,
                                         payload_niov, payload_iov,
                                         payload_offset, payload_nob);
        }

        koibnal_init_tx_msg (tx, OPENIBNAL_MSG_IMMEDIATE,
                             offsetof(koib_immediate_msg_t, 
                                      oibim_payload[payload_nob]));

        /* libmsg gets finalized when tx completes */
        tx->tx_libmsg[0] = libmsg;

        koibnal_launch_tx(tx, nid);
        return (PTL_OK);
}

ptl_err_t
koibnal_send (lib_nal_t *nal, void *private, lib_msg_t *cookie,
               ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
               unsigned int payload_niov, struct iovec *payload_iov,
               size_t payload_offset, size_t payload_len)
{
        return (koibnal_sendmsg(nal, private, cookie,
                                 hdr, type, nid, pid,
                                 payload_niov, payload_iov, NULL,
                                 payload_offset, payload_len));
}

ptl_err_t
koibnal_send_pages (lib_nal_t *nal, void *private, lib_msg_t *cookie, 
                     ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
                     unsigned int payload_niov, ptl_kiov_t *payload_kiov, 
                     size_t payload_offset, size_t payload_len)
{
        return (koibnal_sendmsg(nal, private, cookie,
                                 hdr, type, nid, pid,
                                 payload_niov, NULL, payload_kiov,
                                 payload_offset, payload_len));
}

ptl_err_t
koibnal_recvmsg (lib_nal_t *nal, void *private, lib_msg_t *libmsg,
                 unsigned int niov, struct iovec *iov, ptl_kiov_t *kiov,
                 size_t offset, size_t mlen, size_t rlen)
{
        koib_rx_t                *rx = private;
        koib_msg_t               *rxmsg = rx->rx_msg;
        int                       msg_nob;
        
        LASSERT (mlen <= rlen);
        LASSERT (!in_interrupt ());
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));

        switch (rxmsg->oibm_type) {
        default:
                LBUG();
                return (PTL_FAIL);
                
        case OPENIBNAL_MSG_IMMEDIATE:
                msg_nob = offsetof(koib_msg_t, oibm_u.immediate.oibim_payload[rlen]);
                if (msg_nob > OPENIBNAL_MSG_SIZE) {
                        CERROR ("Immediate message from "LPX64" too big: %d\n",
                                rxmsg->oibm_u.immediate.oibim_hdr.src_nid, rlen);
                        return (PTL_FAIL);
                }

                if (kiov != NULL)
                        lib_copy_buf2kiov(niov, kiov, offset,
                                          rxmsg->oibm_u.immediate.oibim_payload,
                                          mlen);
                else
                        lib_copy_buf2iov(niov, iov, offset,
                                         rxmsg->oibm_u.immediate.oibim_payload,
                                         mlen);

                lib_finalize (nal, NULL, libmsg, PTL_OK);
                return (PTL_OK);

        case OPENIBNAL_MSG_GET_RDMA:
                /* We get called here just to discard any junk after the
                 * GET hdr. */
                LASSERT (libmsg == NULL);
                lib_finalize (nal, NULL, libmsg, PTL_OK);
                return (PTL_OK);

        case OPENIBNAL_MSG_PUT_RDMA:
                koibnal_start_active_rdma (OPENIBNAL_MSG_PUT_DONE, 0,
                                           rx, libmsg, 
                                           niov, iov, kiov, offset, mlen);
                return (PTL_OK);
        }
}

ptl_err_t
koibnal_recv (lib_nal_t *nal, void *private, lib_msg_t *msg,
              unsigned int niov, struct iovec *iov, 
              size_t offset, size_t mlen, size_t rlen)
{
        return (koibnal_recvmsg (nal, private, msg, niov, iov, NULL,
                                 offset, mlen, rlen));
}

ptl_err_t
koibnal_recv_pages (lib_nal_t *nal, void *private, lib_msg_t *msg,
                     unsigned int niov, ptl_kiov_t *kiov, 
                     size_t offset, size_t mlen, size_t rlen)
{
        return (koibnal_recvmsg (nal, private, msg, niov, NULL, kiov,
                                 offset, mlen, rlen));
}

int
koibnal_thread_start (int (*fn)(void *arg), void *arg)
{
        long    pid = kernel_thread (fn, arg, 0);

        if (pid < 0)
                return ((int)pid);

        atomic_inc (&koibnal_data.koib_nthreads);
        return (0);
}

void
koibnal_thread_fini (void)
{
        atomic_dec (&koibnal_data.koib_nthreads);
}

void
koibnal_close_conn_locked (koib_conn_t *conn, int error)
{
        /* This just does the immmediate housekeeping, and schedules the
         * connection for the connd to finish off.
         * Caller holds koib_global_lock exclusively in irq context */
        koib_peer_t   *peer = conn->ibc_peer;

        CDEBUG (error == 0 ? D_NET : D_ERROR,
                "closing conn to "LPX64": error %d\n", peer->ibp_nid, error);
        
        LASSERT (conn->ibc_state == OPENIBNAL_CONN_ESTABLISHED ||
                 conn->ibc_state == OPENIBNAL_CONN_CONNECTING);

        if (conn->ibc_state == OPENIBNAL_CONN_ESTABLISHED) {
                /* koib_connd_conns takes ibc_list's ref */
                list_del (&conn->ibc_list);
        } else {
                /* new ref for koib_connd_conns */
                CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                       atomic_read (&conn->ibc_refcount));
                atomic_inc (&conn->ibc_refcount);
        }
        
        if (list_empty (&peer->ibp_conns) &&
            peer->ibp_persistence == 0) {
                /* Non-persistent peer with no more conns... */
                koibnal_unlink_peer_locked (peer);
        }

        conn->ibc_state = OPENIBNAL_CONN_DEATHROW;

        /* Schedule conn for closing/destruction */
        spin_lock (&koibnal_data.koib_connd_lock);

        list_add_tail (&conn->ibc_list, &koibnal_data.koib_connd_conns);
        wake_up (&koibnal_data.koib_connd_waitq);
                
        spin_unlock (&koibnal_data.koib_connd_lock);
}

int
koibnal_close_conn (koib_conn_t *conn, int why)
{
        unsigned long     flags;
        int               count = 0;

        write_lock_irqsave (&koibnal_data.koib_global_lock, flags);

        LASSERT (conn->ibc_state >= OPENIBNAL_CONN_CONNECTING);
        
        if (conn->ibc_state <= OPENIBNAL_CONN_ESTABLISHED) {
                count = 1;
                koibnal_close_conn_locked (conn, why);
        }
        
        write_unlock_irqrestore (&koibnal_data.koib_global_lock, flags);
        return (count);
}

void
koibnal_peer_connect_failed (koib_peer_t *peer, int active, int rc)
{
        LIST_HEAD        (zombies);
        koib_tx_t        *tx;
        unsigned long     flags;

        LASSERT (rc != 0);
        LASSERT (peer->ibp_reconnect_interval >= OPENIBNAL_MIN_RECONNECT_INTERVAL);

        write_lock_irqsave (&koibnal_data.koib_global_lock, flags);

        LASSERT (peer->ibp_connecting != 0);
        peer->ibp_connecting--;

        if (peer->ibp_connecting != 0) {
                /* another connection attempt under way (loopback?)... */
                write_unlock_irqrestore (&koibnal_data.koib_global_lock, flags);
                return;
        }

        if (list_empty(&peer->ibp_conns)) {
                /* Say when active connection can be re-attempted */
                peer->ibp_reconnect_time = jiffies + peer->ibp_reconnect_interval;
                /* Increase reconnection interval */
                peer->ibp_reconnect_interval = MIN (peer->ibp_reconnect_interval * 2,
                                                    OPENIBNAL_MAX_RECONNECT_INTERVAL);
        
                /* Take peer's blocked blocked transmits; I'll complete
                 * them with error */
                while (!list_empty (&peer->ibp_tx_queue)) {
                        tx = list_entry (peer->ibp_tx_queue.next,
                                         koib_tx_t, tx_list);
                        
                        list_del (&tx->tx_list);
                        list_add_tail (&tx->tx_list, &zombies);
                }
                
                if (koibnal_peer_active(peer) &&
                    (peer->ibp_persistence == 0)) {
                        /* failed connection attempt on non-persistent peer */
                        koibnal_unlink_peer_locked (peer);
                }
        } else {
                /* Can't have blocked transmits if there are connections */
                LASSERT (list_empty(&peer->ibp_tx_queue));
        }
        
        write_unlock_irqrestore (&koibnal_data.koib_global_lock, flags);

        if (!list_empty (&zombies))
                CERROR ("Deleting messages for "LPX64": connection failed\n",
                        peer->ibp_nid);

        while (!list_empty (&zombies)) {
                tx = list_entry (zombies.next, koib_tx_t, tx_list);

                list_del (&tx->tx_list);
                /* complete now */
                tx->tx_status = -EHOSTUNREACH;
                koibnal_tx_done (tx);
        }
}

void
koibnal_connreq_done (koib_conn_t *conn, int active, int status)
{
        int               state = conn->ibc_state;
        koib_peer_t      *peer = conn->ibc_peer;
        koib_tx_t        *tx;
        unsigned long     flags;
        int               rc;
        int               i;

        /* passive connection has no connreq & vice versa */
        LASSERT (!active == !(conn->ibc_connreq != NULL));
        if (active) {
                PORTAL_FREE (conn->ibc_connreq, sizeof (*conn->ibc_connreq));
                conn->ibc_connreq = NULL;
        }

        if (state == OPENIBNAL_CONN_CONNECTING) {
                /* Install common (active/passive) callback for
                 * disconnect/idle notification if I got as far as getting
                 * a CM comm_id */
                rc = tsIbCmCallbackModify(conn->ibc_comm_id, 
                                          koibnal_conn_callback, conn);
                LASSERT (rc == 0);
        }
        
        write_lock_irqsave (&koibnal_data.koib_global_lock, flags);

        LASSERT (peer->ibp_connecting != 0);
        
        if (status == 0) {                         
                /* connection established... */
                LASSERT (state == OPENIBNAL_CONN_CONNECTING);
                conn->ibc_state = OPENIBNAL_CONN_ESTABLISHED;

                if (!koibnal_peer_active(peer)) {
                        /* ...but peer deleted meantime */
                        status = -ECONNABORTED;
                }
        } else {
                LASSERT (state == OPENIBNAL_CONN_INIT_QP ||
                         state == OPENIBNAL_CONN_CONNECTING);
        }

        if (status == 0) {
                /* Everything worked! */

                peer->ibp_connecting--;

                /* +1 ref for ibc_list; caller(== CM)'s ref remains until
                 * the IB_CM_IDLE callback */
                CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                       atomic_read (&conn->ibc_refcount));
                atomic_inc (&conn->ibc_refcount);
                list_add (&conn->ibc_list, &peer->ibp_conns);
                
                /* reset reconnect interval for next attempt */
                peer->ibp_reconnect_interval = OPENIBNAL_MIN_RECONNECT_INTERVAL;

                /* post blocked sends to the new connection */
                spin_lock (&conn->ibc_lock);
                
                while (!list_empty (&peer->ibp_tx_queue)) {
                        tx = list_entry (peer->ibp_tx_queue.next, 
                                         koib_tx_t, tx_list);
                        
                        list_del (&tx->tx_list);

                        /* +1 ref for each tx */
                        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                               conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                               atomic_read (&conn->ibc_refcount));
                        atomic_inc (&conn->ibc_refcount);
                        koibnal_queue_tx_locked (tx, conn);
                }
                
                spin_unlock (&conn->ibc_lock);

                /* Nuke any dangling conns from a different peer instance... */
                koibnal_close_stale_conns_locked (conn->ibc_peer,
                                                  conn->ibc_incarnation);

                write_unlock_irqrestore (&koibnal_data.koib_global_lock, flags);

                /* queue up all the receives */
                for (i = 0; i < OPENIBNAL_RX_MSGS; i++) {
                        /* +1 ref for rx desc */
                        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                               conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                               atomic_read (&conn->ibc_refcount));
                        atomic_inc (&conn->ibc_refcount);

                        CDEBUG(D_NET, "RX[%d] %p->%p - "LPX64"\n",
                               i, &conn->ibc_rxs[i], conn->ibc_rxs[i].rx_msg,
                               conn->ibc_rxs[i].rx_vaddr);

                        koibnal_post_rx (&conn->ibc_rxs[i], 0);
                }

                koibnal_check_sends (conn);
                return;
        }

        /* connection failed */
        if (state == OPENIBNAL_CONN_CONNECTING) {
                /* schedule for connd to close */
                koibnal_close_conn_locked (conn, status);
        } else {
                /* Don't have a CM comm_id; just wait for refs to drain */
                conn->ibc_state = OPENIBNAL_CONN_ZOMBIE;
        } 

        write_unlock_irqrestore (&koibnal_data.koib_global_lock, flags);

        koibnal_peer_connect_failed (conn->ibc_peer, active, status);

        if (state != OPENIBNAL_CONN_CONNECTING) {
                /* drop caller's ref if we're not waiting for the
                 * IB_CM_IDLE callback */
                koibnal_put_conn (conn);
        }
}

int
koibnal_accept (koib_conn_t **connp, tTS_IB_CM_COMM_ID cid,
                ptl_nid_t nid, __u64 incarnation, int queue_depth)
{
        koib_conn_t   *conn = koibnal_create_conn();
        koib_peer_t   *peer;
        koib_peer_t   *peer2;
        unsigned long  flags;

        if (conn == NULL)
                return (-ENOMEM);

        if (queue_depth != OPENIBNAL_MSG_QUEUE_SIZE) {
                CERROR("Can't accept "LPX64": bad queue depth %d (%d expected)\n",
                       nid, queue_depth, OPENIBNAL_MSG_QUEUE_SIZE);
                return (-EPROTO);
        }
        
        /* assume 'nid' is a new peer */
        peer = koibnal_create_peer (nid);
        if (peer == NULL) {
                CDEBUG(D_NET, "--conn[%p] state %d -> "LPX64" (%d)\n",
                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                       atomic_read (&conn->ibc_refcount));
                atomic_dec (&conn->ibc_refcount);
                koibnal_destroy_conn(conn);
                return (-ENOMEM);
        }
        
        write_lock_irqsave (&koibnal_data.koib_global_lock, flags);

        peer2 = koibnal_find_peer_locked(nid);
        if (peer2 == NULL) {
                /* peer table takes my ref on peer */
                list_add_tail (&peer->ibp_list,
                               koibnal_nid2peerlist(nid));
        } else {
                koibnal_put_peer (peer);
                peer = peer2;
        }

        /* +1 ref for conn */
        atomic_inc (&peer->ibp_refcount);
        peer->ibp_connecting++;

        write_unlock_irqrestore (&koibnal_data.koib_global_lock, flags);

        conn->ibc_peer = peer;
        conn->ibc_state = OPENIBNAL_CONN_CONNECTING;
        conn->ibc_comm_id = cid;
        conn->ibc_incarnation = incarnation;
        conn->ibc_credits = OPENIBNAL_MSG_QUEUE_SIZE;

        *connp = conn;
        return (0);
}

tTS_IB_CM_CALLBACK_RETURN
koibnal_idle_conn_callback (tTS_IB_CM_EVENT event,
                            tTS_IB_CM_COMM_ID cid,
                            void *param,
                            void *arg)
{
        /* Shouldn't ever get a callback after TS_IB_CM_IDLE */
        CERROR ("Unexpected event %d: conn %p\n", event, arg);
        LBUG ();
        return TS_IB_CM_CALLBACK_PROCEED;
}

tTS_IB_CM_CALLBACK_RETURN
koibnal_conn_callback (tTS_IB_CM_EVENT event,
                       tTS_IB_CM_COMM_ID cid,
                       void *param,
                       void *arg)
{
        koib_conn_t *conn = arg;
        int          rc;

        /* Established Connection Notifier */

        switch (event) {
        default:
                CERROR("Connection %p -> "LPX64" ERROR %d\n",
                       conn, conn->ibc_peer->ibp_nid, event);
                koibnal_close_conn (conn, -ECONNABORTED);
                break;
                
        case TS_IB_CM_DISCONNECTED:
                CDEBUG(D_WARNING, "Connection %p -> "LPX64" DISCONNECTED.\n",
                       conn, conn->ibc_peer->ibp_nid);
                koibnal_close_conn (conn, 0);
                break;

        case TS_IB_CM_IDLE:
                CDEBUG(D_NET, "Connection %p -> "LPX64" IDLE.\n",
                       conn, conn->ibc_peer->ibp_nid);
                koibnal_put_conn (conn);        /* Lose CM's ref */

                /* LASSERT (no further callbacks) */
                rc = tsIbCmCallbackModify(cid, 
                                          koibnal_idle_conn_callback, conn);
                LASSERT (rc == 0);
                break;
        }

        return TS_IB_CM_CALLBACK_PROCEED;
}

tTS_IB_CM_CALLBACK_RETURN
koibnal_passive_conn_callback (tTS_IB_CM_EVENT event,
                               tTS_IB_CM_COMM_ID cid,
                               void *param,
                               void *arg)
{
        koib_conn_t *conn = arg;
        int          rc;
        
        switch (event) {
        default:
                if (conn == NULL) {
                        /* no connection yet */
                        CERROR ("Unexpected event: %d\n", event);
                        return TS_IB_CM_CALLBACK_ABORT;
                }
                
                CERROR ("Unexpected event %p -> "LPX64": %d\n", 
                        conn, conn->ibc_peer->ibp_nid, event);
                koibnal_connreq_done (conn, 0, -ECONNABORTED);
                break;
                
        case TS_IB_CM_REQ_RECEIVED: {
                struct ib_cm_req_received_param *req = param;
                koib_wire_connreq_t             *wcr = req->remote_private_data;

                LASSERT (conn == NULL);

                CDEBUG(D_NET, "REQ from "LPX64"\n", le64_to_cpu(wcr->wcr_nid));

                if (req->remote_private_data_len < sizeof (*wcr)) {
                        CERROR("Connect from remote LID %04x: too short %d\n",
                               req->dlid, req->remote_private_data_len);
                        return TS_IB_CM_CALLBACK_ABORT;
                }

                if (wcr->wcr_magic != cpu_to_le32(OPENIBNAL_MSG_MAGIC)) {
                        CERROR ("Can't accept LID %04x: bad magic %08x\n",
                                req->dlid, le32_to_cpu(wcr->wcr_magic));
                        return TS_IB_CM_CALLBACK_ABORT;
                }
                
                if (wcr->wcr_version != cpu_to_le16(OPENIBNAL_MSG_VERSION)) {
                        CERROR ("Can't accept LID %04x: bad version %d\n",
                                req->dlid, le16_to_cpu(wcr->wcr_magic));
                        return TS_IB_CM_CALLBACK_ABORT;
                }
                                
                rc = koibnal_accept(&conn,
                                    cid,
                                    le64_to_cpu(wcr->wcr_nid),
                                    le64_to_cpu(wcr->wcr_incarnation),
                                    le16_to_cpu(wcr->wcr_queue_depth));
                if (rc != 0) {
                        CERROR ("Can't accept "LPX64": %d\n",
                                le64_to_cpu(wcr->wcr_nid), rc);
                        return TS_IB_CM_CALLBACK_ABORT;
                }

                /* update 'arg' for next callback */
                rc = tsIbCmCallbackModify(cid, 
                                          koibnal_passive_conn_callback, conn);
                LASSERT (rc == 0);

                req->accept_param.qp                     = conn->ibc_qp;
                *((koib_wire_connreq_t *)req->accept_param.reply_private_data)
                        = (koib_wire_connreq_t) {
                                .wcr_magic       = cpu_to_le32(OPENIBNAL_MSG_MAGIC),
                                .wcr_version     = cpu_to_le16(OPENIBNAL_MSG_VERSION),
                                .wcr_queue_depth = cpu_to_le32(OPENIBNAL_MSG_QUEUE_SIZE),
                                .wcr_nid         = cpu_to_le64(koibnal_data.koib_nid),
                                .wcr_incarnation = cpu_to_le64(koibnal_data.koib_incarnation),
                        };
                req->accept_param.reply_private_data_len = sizeof(koib_wire_connreq_t);
                req->accept_param.responder_resources    = OPENIBNAL_RESPONDER_RESOURCES;
                req->accept_param.initiator_depth        = OPENIBNAL_RESPONDER_RESOURCES;
                req->accept_param.rnr_retry_count        = OPENIBNAL_RNR_RETRY;
                req->accept_param.flow_control           = OPENIBNAL_FLOW_CONTROL;

                CDEBUG(D_NET, "Proceeding\n");
                break;
        }

        case TS_IB_CM_ESTABLISHED:
                LASSERT (conn != NULL);
                CDEBUG(D_WARNING, "Connection %p -> "LPX64" ESTABLISHED.\n",
                       conn, conn->ibc_peer->ibp_nid);

                koibnal_connreq_done (conn, 0, 0);
                break;
        }

        /* NB if the connreq is done, we switch to koibnal_conn_callback */
        return TS_IB_CM_CALLBACK_PROCEED;
}

tTS_IB_CM_CALLBACK_RETURN
koibnal_active_conn_callback (tTS_IB_CM_EVENT event,
                              tTS_IB_CM_COMM_ID cid,
                              void *param,
                              void *arg)
{
        koib_conn_t *conn = arg;

        switch (event) {
        case TS_IB_CM_REP_RECEIVED: {
                struct ib_cm_rep_received_param *rep = param;
                koib_wire_connreq_t             *wcr = rep->remote_private_data;

                if (rep->remote_private_data_len < sizeof (*wcr)) {
                        CERROR ("Short reply from "LPX64": %d\n",
                                conn->ibc_peer->ibp_nid,
                                rep->remote_private_data_len);
                        koibnal_connreq_done (conn, 1, -EPROTO);
                        break;
                }

                if (wcr->wcr_magic != cpu_to_le32(OPENIBNAL_MSG_MAGIC)) {
                        CERROR ("Can't connect "LPX64": bad magic %08x\n",
                                conn->ibc_peer->ibp_nid, le32_to_cpu(wcr->wcr_magic));
                        koibnal_connreq_done (conn, 1, -EPROTO);
                        break;
                }
                
                if (wcr->wcr_version != cpu_to_le16(OPENIBNAL_MSG_VERSION)) {
                        CERROR ("Can't connect "LPX64": bad version %d\n",
                                conn->ibc_peer->ibp_nid, le16_to_cpu(wcr->wcr_magic));
                        koibnal_connreq_done (conn, 1, -EPROTO);
                        break;
                }
                                
                if (wcr->wcr_queue_depth != cpu_to_le16(OPENIBNAL_MSG_QUEUE_SIZE)) {
                        CERROR ("Can't connect "LPX64": bad queue depth %d\n",
                                conn->ibc_peer->ibp_nid, le16_to_cpu(wcr->wcr_queue_depth));
                        koibnal_connreq_done (conn, 1, -EPROTO);
                        break;
                }
                                
                if (le64_to_cpu(wcr->wcr_nid) != conn->ibc_peer->ibp_nid) {
                        CERROR ("Unexpected NID "LPX64" from "LPX64"\n",
                                le64_to_cpu(wcr->wcr_nid), conn->ibc_peer->ibp_nid);
                        koibnal_connreq_done (conn, 1, -EPROTO);
                        break;
                }

                CDEBUG(D_NET, "Connection %p -> "LPX64" REP_RECEIVED.\n",
                       conn, conn->ibc_peer->ibp_nid);

                conn->ibc_incarnation = le64_to_cpu(wcr->wcr_incarnation);
                conn->ibc_credits = OPENIBNAL_MSG_QUEUE_SIZE;
                break;
        }

        case TS_IB_CM_ESTABLISHED:
                CDEBUG(D_WARNING, "Connection %p -> "LPX64" Established\n",
                       conn, conn->ibc_peer->ibp_nid);

                koibnal_connreq_done (conn, 1, 0);
                break;

        case TS_IB_CM_IDLE:
                CERROR("Connection %p -> "LPX64" IDLE\n",
                       conn, conn->ibc_peer->ibp_nid);
                /* Back out state change: I'm disengaged from CM */
                conn->ibc_state = OPENIBNAL_CONN_INIT_QP;
                
                koibnal_connreq_done (conn, 1, -ECONNABORTED);
                break;

        default:
                CERROR("Connection %p -> "LPX64" ERROR %d\n",
                       conn, conn->ibc_peer->ibp_nid, event);
                koibnal_connreq_done (conn, 1, -ECONNABORTED);
                break;
        }

        /* NB if the connreq is done, we switch to koibnal_conn_callback */
        return TS_IB_CM_CALLBACK_PROCEED;
}

int
koibnal_pathreq_callback (tTS_IB_CLIENT_QUERY_TID tid, int status,
                          struct ib_path_record *resp, int remaining,
                          void *arg)
{
        koib_conn_t *conn = arg;
        
        if (status != 0) {
                CERROR ("status %d\n", status);
                koibnal_connreq_done (conn, 1, status);
                goto out;
        }

        conn->ibc_connreq->cr_path = *resp;

        conn->ibc_connreq->cr_wcr = (koib_wire_connreq_t) {
                .wcr_magic       = cpu_to_le32(OPENIBNAL_MSG_MAGIC),
                .wcr_version     = cpu_to_le16(OPENIBNAL_MSG_VERSION),
                .wcr_queue_depth = cpu_to_le16(OPENIBNAL_MSG_QUEUE_SIZE),
                .wcr_nid         = cpu_to_le64(koibnal_data.koib_nid),
                .wcr_incarnation = cpu_to_le64(koibnal_data.koib_incarnation),
        };

        conn->ibc_connreq->cr_connparam = (struct ib_cm_active_param) {
                .qp                   = conn->ibc_qp,
                .req_private_data     = &conn->ibc_connreq->cr_wcr,
                .req_private_data_len = sizeof(conn->ibc_connreq->cr_wcr),
                .responder_resources  = OPENIBNAL_RESPONDER_RESOURCES,
                .initiator_depth      = OPENIBNAL_RESPONDER_RESOURCES,
                .retry_count          = OPENIBNAL_RETRY,
                .rnr_retry_count      = OPENIBNAL_RNR_RETRY,
                .cm_response_timeout  = koibnal_tunables.koib_io_timeout,
                .max_cm_retries       = OPENIBNAL_CM_RETRY,
                .flow_control         = OPENIBNAL_FLOW_CONTROL,
        };

        /* XXX set timeout just like SDP!!!*/
        conn->ibc_connreq->cr_path.packet_life = 13;
        
        /* Flag I'm getting involved with the CM... */
        conn->ibc_state = OPENIBNAL_CONN_CONNECTING;

        CDEBUG(D_NET, "Connecting to, service id "LPX64", on "LPX64"\n",
               conn->ibc_connreq->cr_service.service_id, 
               *koibnal_service_nid_field(&conn->ibc_connreq->cr_service));

        /* koibnal_connect_callback gets my conn ref */
        status = ib_cm_connect (&conn->ibc_connreq->cr_connparam, 
                                &conn->ibc_connreq->cr_path, NULL,
                                conn->ibc_connreq->cr_service.service_id, 0,
                                koibnal_active_conn_callback, conn,
                                &conn->ibc_comm_id);
        if (status != 0) {
                CERROR ("Connect: %d\n", status);
                /* Back out state change: I've not got a CM comm_id yet... */
                conn->ibc_state = OPENIBNAL_CONN_INIT_QP;
                koibnal_connreq_done (conn, 1, status);
        }
        
 out:
        /* return non-zero to prevent further callbacks */
        return 1;
}

void
koibnal_service_get_callback (tTS_IB_CLIENT_QUERY_TID tid, int status,
                              struct ib_common_attrib_service *resp, void *arg)
{
        koib_conn_t *conn = arg;
        
        if (status != 0) {
                CERROR ("status %d\n", status);
                koibnal_connreq_done (conn, 1, status);
                return;
        }

        CDEBUG(D_NET, "Got status %d, service id "LPX64", on "LPX64"\n",
               status, resp->service_id, 
               *koibnal_service_nid_field(resp));

        conn->ibc_connreq->cr_service = *resp;

        status = ib_cached_gid_get(koibnal_data.koib_device,
                                   koibnal_data.koib_port, 0,
                                   conn->ibc_connreq->cr_gid);
        LASSERT (status == 0);

        /* koibnal_pathreq_callback gets my conn ref */
        status = tsIbPathRecordRequest (koibnal_data.koib_device,
                                        koibnal_data.koib_port,
                                        conn->ibc_connreq->cr_gid,
                                        conn->ibc_connreq->cr_service.service_gid,
                                        conn->ibc_connreq->cr_service.service_pkey,
                                        0,
                                        koibnal_tunables.koib_io_timeout * HZ,
                                        0,
                                        koibnal_pathreq_callback, conn, 
                                        &conn->ibc_connreq->cr_tid);

        if (status == 0)
                return;

        CERROR ("Path record request: %d\n", status);
        koibnal_connreq_done (conn, 1, status);
}

void
koibnal_connect_peer (koib_peer_t *peer)
{
        koib_conn_t *conn = koibnal_create_conn();
        int          rc;

        LASSERT (peer->ibp_connecting != 0);

        if (conn == NULL) {
                CERROR ("Can't allocate conn\n");
                koibnal_peer_connect_failed (peer, 1, -ENOMEM);
                return;
        }

        conn->ibc_peer = peer;
        atomic_inc (&peer->ibp_refcount);

        PORTAL_ALLOC (conn->ibc_connreq, sizeof (*conn->ibc_connreq));
        if (conn->ibc_connreq == NULL) {
                CERROR ("Can't allocate connreq\n");
                koibnal_connreq_done (conn, 1, -ENOMEM);
                return;
        }

        memset(conn->ibc_connreq, 0, sizeof (*conn->ibc_connreq));

        koibnal_set_service_keys(&conn->ibc_connreq->cr_service, peer->ibp_nid);

        /* koibnal_service_get_callback gets my conn ref */
        rc = ib_service_get (koibnal_data.koib_device, 
                             koibnal_data.koib_port,
                             &conn->ibc_connreq->cr_service,
                             KOIBNAL_SERVICE_KEY_MASK,
                             koibnal_tunables.koib_io_timeout * HZ,
                             koibnal_service_get_callback, conn, 
                             &conn->ibc_connreq->cr_tid);
        
        if (rc == 0)
                return;

        CERROR ("ib_service_get: %d\n", rc);
        koibnal_connreq_done (conn, 1, rc);
}

int
koibnal_conn_timed_out (koib_conn_t *conn)
{
        koib_tx_t         *tx;
        struct list_head  *ttmp;
        unsigned long      flags;
        int                rc = 0;

        spin_lock_irqsave (&conn->ibc_lock, flags);

        list_for_each (ttmp, &conn->ibc_rdma_queue) {
                tx = list_entry (ttmp, koib_tx_t, tx_list);

                LASSERT (tx->tx_passive_rdma);
                LASSERT (tx->tx_passive_rdma_wait);

                if (time_after_eq (jiffies, tx->tx_passive_rdma_deadline)) {
                        rc = 1;
                        break;
                }
        }
        spin_unlock_irqrestore (&conn->ibc_lock, flags);

        return rc;
}

void
koibnal_check_conns (int idx)
{
        struct list_head  *peers = &koibnal_data.koib_peers[idx];
        struct list_head  *ptmp;
        koib_peer_t       *peer;
        koib_conn_t       *conn;
        struct list_head  *ctmp;

 again:
        /* NB. We expect to have a look at all the peers and not find any
         * rdmas to time out, so we just use a shared lock while we
         * take a look... */
        read_lock (&koibnal_data.koib_global_lock);

        list_for_each (ptmp, peers) {
                peer = list_entry (ptmp, koib_peer_t, ibp_list);

                list_for_each (ctmp, &peer->ibp_conns) {
                        conn = list_entry (ctmp, koib_conn_t, ibc_list);

                        LASSERT (conn->ibc_state == OPENIBNAL_CONN_ESTABLISHED);

                        /* In case we have enough credits to return via a
                         * NOOP, but there were no non-blocking tx descs
                         * free to do it last time... */
                        koibnal_check_sends(conn);

                        if (!koibnal_conn_timed_out(conn))
                                continue;
                        
                        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                               conn, conn->ibc_state, peer->ibp_nid,
                               atomic_read (&conn->ibc_refcount));

                        atomic_inc (&conn->ibc_refcount);
                        read_unlock (&koibnal_data.koib_global_lock);

                        CERROR("Timed out RDMA with "LPX64"\n",
                               peer->ibp_nid);

                        koibnal_close_conn (conn, -ETIMEDOUT);
                        koibnal_put_conn (conn);

                        /* start again now I've dropped the lock */
                        goto again;
                }
        }

        read_unlock (&koibnal_data.koib_global_lock);
}

void
koibnal_terminate_conn (koib_conn_t *conn)
{
        unsigned long flags;
        int           rc;
        int           done;

        CDEBUG(D_NET, "conn %p\n", conn);
        LASSERT (conn->ibc_state == OPENIBNAL_CONN_DEATHROW);
        conn->ibc_state = OPENIBNAL_CONN_ZOMBIE;

        rc = ib_cm_disconnect (conn->ibc_comm_id);
        if (rc != 0)
                CERROR ("Error %d disconnecting conn %p -> "LPX64"\n",
                        rc, conn, conn->ibc_peer->ibp_nid);

        /* complete blocked passive RDMAs */
        spin_lock_irqsave (&conn->ibc_lock, flags);
        
        while (!list_empty (&conn->ibc_rdma_queue)) {
                koib_tx_t *tx = list_entry (conn->ibc_rdma_queue.next,
                                            koib_tx_t, tx_list);

                LASSERT (tx->tx_passive_rdma);
                LASSERT (tx->tx_passive_rdma_wait);
                
                list_del (&tx->tx_list);

                tx->tx_passive_rdma_wait = 0;
                done = (tx->tx_sending == 0);
                
                tx->tx_status = -ECONNABORTED;

                spin_unlock_irqrestore (&conn->ibc_lock, flags);

                if (done)
                        koibnal_tx_done (tx);

                spin_lock_irqsave (&conn->ibc_lock, flags);
        }
        
        spin_unlock_irqrestore (&conn->ibc_lock, flags);

        /* Complete all blocked transmits */
        koibnal_check_sends(conn);
}

int
koibnal_connd (void *arg)
{
        wait_queue_t       wait;
        unsigned long      flags;
        koib_conn_t       *conn;
        koib_peer_t       *peer;
        int                timeout;
        int                i;
        int                peer_index = 0;
        unsigned long      deadline = jiffies;
        
        kportal_daemonize ("koibnal_connd");
        kportal_blockallsigs ();

        init_waitqueue_entry (&wait, current);

        spin_lock_irqsave (&koibnal_data.koib_connd_lock, flags);

        for (;;) {
                if (!list_empty (&koibnal_data.koib_connd_conns)) {
                        conn = list_entry (koibnal_data.koib_connd_conns.next,
                                           koib_conn_t, ibc_list);
                        list_del (&conn->ibc_list);
                        
                        spin_unlock_irqrestore (&koibnal_data.koib_connd_lock, flags);

                        switch (conn->ibc_state) {
                        case OPENIBNAL_CONN_DEATHROW:
                                LASSERT (conn->ibc_comm_id != TS_IB_CM_COMM_ID_INVALID);
                                /* Disconnect: conn becomes a zombie in the
                                 * callback and last ref reschedules it
                                 * here... */
                                koibnal_terminate_conn(conn);
                                koibnal_put_conn (conn);
                                break;
                                
                        case OPENIBNAL_CONN_ZOMBIE:
                                koibnal_destroy_conn (conn);
                                break;
                                
                        default:
                                CERROR ("Bad conn %p state: %d\n",
                                        conn, conn->ibc_state);
                                LBUG();
                        }

                        spin_lock_irqsave (&koibnal_data.koib_connd_lock, flags);
                        continue;
                }

                if (!list_empty (&koibnal_data.koib_connd_peers)) {
                        peer = list_entry (koibnal_data.koib_connd_peers.next,
                                           koib_peer_t, ibp_connd_list);
                        
                        list_del_init (&peer->ibp_connd_list);
                        spin_unlock_irqrestore (&koibnal_data.koib_connd_lock, flags);

                        koibnal_connect_peer (peer);
                        koibnal_put_peer (peer);

                        spin_lock_irqsave (&koibnal_data.koib_connd_lock, flags);
                }

                /* shut down and nobody left to reap... */
                if (koibnal_data.koib_shutdown &&
                    atomic_read(&koibnal_data.koib_nconns) == 0)
                        break;

                spin_unlock_irqrestore (&koibnal_data.koib_connd_lock, flags);

                /* careful with the jiffy wrap... */
                while ((timeout = (int)(deadline - jiffies)) <= 0) {
                        const int n = 4;
                        const int p = 1;
                        int       chunk = koibnal_data.koib_peer_hash_size;
                        
                        /* Time to check for RDMA timeouts on a few more
                         * peers: I do checks every 'p' seconds on a
                         * proportion of the peer table and I need to check
                         * every connection 'n' times within a timeout
                         * interval, to ensure I detect a timeout on any
                         * connection within (n+1)/n times the timeout
                         * interval. */

                        if (koibnal_tunables.koib_io_timeout > n * p)
                                chunk = (chunk * n * p) / 
                                        koibnal_tunables.koib_io_timeout;
                        if (chunk == 0)
                                chunk = 1;

                        for (i = 0; i < chunk; i++) {
                                koibnal_check_conns (peer_index);
                                peer_index = (peer_index + 1) % 
                                             koibnal_data.koib_peer_hash_size;
                        }

                        deadline += p * HZ;
                }

                koibnal_data.koib_connd_waketime = jiffies + timeout;

                set_current_state (TASK_INTERRUPTIBLE);
                add_wait_queue (&koibnal_data.koib_connd_waitq, &wait);

                if (!koibnal_data.koib_shutdown &&
                    list_empty (&koibnal_data.koib_connd_conns) &&
                    list_empty (&koibnal_data.koib_connd_peers))
                        schedule_timeout (timeout);

                set_current_state (TASK_RUNNING);
                remove_wait_queue (&koibnal_data.koib_connd_waitq, &wait);

                spin_lock_irqsave (&koibnal_data.koib_connd_lock, flags);
        }

        spin_unlock_irqrestore (&koibnal_data.koib_connd_lock, flags);

        koibnal_thread_fini ();
        return (0);
}

int
koibnal_scheduler(void *arg)
{
        long            id = (long)arg;
        char            name[16];
        koib_rx_t      *rx;
        koib_tx_t      *tx;
        unsigned long   flags;
        int             rc;
        int             counter = 0;
        int             did_something;

        snprintf(name, sizeof(name), "koibnal_sd_%02ld", id);
        kportal_daemonize(name);
        kportal_blockallsigs();

        spin_lock_irqsave(&koibnal_data.koib_sched_lock, flags);

        for (;;) {
                did_something = 0;

                while (!list_empty(&koibnal_data.koib_sched_txq)) {
                        tx = list_entry(koibnal_data.koib_sched_txq.next,
                                        koib_tx_t, tx_list);
                        list_del(&tx->tx_list);
                        spin_unlock_irqrestore(&koibnal_data.koib_sched_lock,
                                               flags);
                        koibnal_tx_done(tx);

                        spin_lock_irqsave(&koibnal_data.koib_sched_lock,
                                          flags);
                }

                if (!list_empty(&koibnal_data.koib_sched_rxq)) {
                        rx = list_entry(koibnal_data.koib_sched_rxq.next,
                                        koib_rx_t, rx_list);
                        list_del(&rx->rx_list);
                        spin_unlock_irqrestore(&koibnal_data.koib_sched_lock,
                                               flags);

                        koibnal_rx(rx);

                        did_something = 1;
                        spin_lock_irqsave(&koibnal_data.koib_sched_lock,
                                          flags);
                }

                /* shut down and no receives to complete... */
                if (koibnal_data.koib_shutdown &&
                    atomic_read(&koibnal_data.koib_nconns) == 0)
                        break;

                /* nothing to do or hogging CPU */
                if (!did_something || counter++ == OPENIBNAL_RESCHED) {
                        spin_unlock_irqrestore(&koibnal_data.koib_sched_lock,
                                               flags);
                        counter = 0;

                        if (!did_something) {
                                rc = wait_event_interruptible(
                                        koibnal_data.koib_sched_waitq,
                                        !list_empty(&koibnal_data.koib_sched_txq) || 
                                        !list_empty(&koibnal_data.koib_sched_rxq) || 
                                        (koibnal_data.koib_shutdown &&
                                         atomic_read (&koibnal_data.koib_nconns) == 0));
                        } else {
                                our_cond_resched();
                        }

                        spin_lock_irqsave(&koibnal_data.koib_sched_lock,
                                          flags);
                }
        }

        spin_unlock_irqrestore(&koibnal_data.koib_sched_lock, flags);

        koibnal_thread_fini();
        return (0);
}


lib_nal_t koibnal_lib = {
        libnal_data:        &koibnal_data,      /* NAL private data */
        libnal_send:         koibnal_send,
        libnal_send_pages:   koibnal_send_pages,
        libnal_recv:         koibnal_recv,
        libnal_recv_pages:   koibnal_recv_pages,
        libnal_dist:         koibnal_dist
};
