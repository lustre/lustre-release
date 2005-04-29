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

#include "iibnal.h"

/*
 *  LIB functions follow
 *
 */
static void
kibnal_schedule_tx_done (kib_tx_t *tx)
{
        unsigned long flags;

        spin_lock_irqsave (&kibnal_data.kib_sched_lock, flags);

        list_add_tail(&tx->tx_list, &kibnal_data.kib_sched_txq);
        wake_up (&kibnal_data.kib_sched_waitq);

        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock, flags);
}

static void
kibnal_tx_done (kib_tx_t *tx)
{
        ptl_err_t        ptlrc = (tx->tx_status == 0) ? PTL_OK : PTL_FAIL;
        unsigned long    flags;
        int              i;
        FSTATUS          frc;

        LASSERT (tx->tx_sending == 0);          /* mustn't be awaiting callback */
        LASSERT (!tx->tx_passive_rdma_wait);    /* mustn't be awaiting RDMA */

        switch (tx->tx_mapped) {
        default:
                LBUG();

        case KIB_TX_UNMAPPED:
                break;

        case KIB_TX_MAPPED:
                if (in_interrupt()) {
                        /* can't deregister memory in IRQ context... */
                        kibnal_schedule_tx_done(tx);
                        return;
                }
                frc = iibt_deregister_memory(tx->tx_md.md_handle);
                LASSERT (frc == FSUCCESS);
                tx->tx_mapped = KIB_TX_UNMAPPED;
                break;

#if IBNAL_FMR
        case KIB_TX_MAPPED_FMR:
                if (in_interrupt() && tx->tx_status != 0) {
                        /* can't flush FMRs in IRQ context... */
                        kibnal_schedule_tx_done(tx);
                        return;
                }              

                rc = ib_fmr_deregister(tx->tx_md.md_handle.fmr);
                LASSERT (rc == 0);

                if (tx->tx_status != 0)
                        ib_fmr_pool_force_flush(kibnal_data.kib_fmr_pool);
                tx->tx_mapped = KIB_TX_UNMAPPED;
                break;
#endif
        }

        for (i = 0; i < 2; i++) {
                /* tx may have up to 2 ptlmsgs to finalise */
                if (tx->tx_ptlmsg[i] == NULL)
                        continue;

                ptl_finalize (kibnal_data.kib_ni, NULL, tx->tx_ptlmsg[i], ptlrc);
                tx->tx_ptlmsg[i] = NULL;
        }
        
        if (tx->tx_conn != NULL) {
                kibnal_put_conn (tx->tx_conn);
                tx->tx_conn = NULL;
        }

        tx->tx_nsp = 0;
        tx->tx_passive_rdma = 0;
        tx->tx_status = 0;

        spin_lock_irqsave (&kibnal_data.kib_tx_lock, flags);

        if (tx->tx_isnblk) {
                list_add_tail (&tx->tx_list, &kibnal_data.kib_idle_nblk_txs);
        } else {
                list_add_tail (&tx->tx_list, &kibnal_data.kib_idle_txs);
                wake_up (&kibnal_data.kib_idle_tx_waitq);
        }

        spin_unlock_irqrestore (&kibnal_data.kib_tx_lock, flags);
}

static kib_tx_t *
kibnal_get_idle_tx (int may_block) 
{
        unsigned long  flags;
        kib_tx_t      *tx = NULL;
        ENTRY;
        
        for (;;) {
                spin_lock_irqsave (&kibnal_data.kib_tx_lock, flags);

                /* "normal" descriptor is free */
                if (!list_empty (&kibnal_data.kib_idle_txs)) {
                        tx = list_entry (kibnal_data.kib_idle_txs.next,
                                         kib_tx_t, tx_list);
                        break;
                }

                if (!may_block) {
                        /* may dip into reserve pool */
                        if (list_empty (&kibnal_data.kib_idle_nblk_txs)) {
                                CERROR ("reserved tx desc pool exhausted\n");
                                break;
                        }

                        tx = list_entry (kibnal_data.kib_idle_nblk_txs.next,
                                         kib_tx_t, tx_list);
                        break;
                }

                /* block for idle tx */
                spin_unlock_irqrestore (&kibnal_data.kib_tx_lock, flags);

                wait_event (kibnal_data.kib_idle_tx_waitq,
                            !list_empty (&kibnal_data.kib_idle_txs) ||
                            kibnal_data.kib_shutdown);
        }

        if (tx != NULL) {
                list_del (&tx->tx_list);

                /* Allocate a new passive RDMA completion cookie.  It might
                 * not be needed, but we've got a lock right now and we're
                 * unlikely to wrap... */
                tx->tx_passive_rdma_cookie = kibnal_data.kib_next_tx_cookie++;

                LASSERT (tx->tx_mapped == KIB_TX_UNMAPPED);
                LASSERT (tx->tx_nsp == 0);
                LASSERT (tx->tx_sending == 0);
                LASSERT (tx->tx_status == 0);
                LASSERT (tx->tx_conn == NULL);
                LASSERT (!tx->tx_passive_rdma);
                LASSERT (!tx->tx_passive_rdma_wait);
                LASSERT (tx->tx_ptlmsg[0] == NULL);
                LASSERT (tx->tx_ptlmsg[1] == NULL);
        }

        spin_unlock_irqrestore (&kibnal_data.kib_tx_lock, flags);
        
        RETURN(tx);
}

static void
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

        CERROR ("Unmatched (late?) RDMA completion "LPX64" from "LPX64"\n",
                cookie, conn->ibc_peer->ibp_nid);
}

static __u32
kibnal_lkey(kib_pages_t *ibp)
{
        if (kibnal_whole_mem())
                return kibnal_data.kib_md.md_lkey;

        return ibp->ibp_lkey;
}

static void
kibnal_post_rx (kib_rx_t *rx, int do_credits)
{
        kib_conn_t   *conn = rx->rx_conn;
        int           rc = 0;
        unsigned long flags;
        FSTATUS       frc;
        ENTRY;

        rx->rx_gl = (IB_LOCAL_DATASEGMENT) {
                .Address = rx->rx_vaddr,
                .Length  = IBNAL_MSG_SIZE,
                .Lkey    = kibnal_lkey(conn->ibc_rx_pages),
        };

        rx->rx_wrq = (IB_WORK_REQ) {
                .Operation              = WROpRecv,
                .DSListDepth            = 1,
                .MessageLen             = IBNAL_MSG_SIZE,
                .WorkReqId              = kibnal_ptr2wreqid(rx, 1),
                .DSList                 = &rx->rx_gl,
        };

        KIB_ASSERT_CONN_STATE_RANGE(conn, IBNAL_CONN_ESTABLISHED,
                                    IBNAL_CONN_DREP);
        LASSERT (!rx->rx_posted);
        rx->rx_posted = 1;
        mb();

        if (conn->ibc_state != IBNAL_CONN_ESTABLISHED)
                rc = -ECONNABORTED;
        else {
                frc = iibt_postrecv(conn->ibc_qp, &rx->rx_wrq);
                if (frc != FSUCCESS) {
                        CDEBUG(D_NET, "post failed %d\n", frc);
                        rc = -EINVAL;
                }
                CDEBUG(D_NET, "posted rx %p\n", &rx->rx_wrq);
        }

        if (rc == 0) {
                if (do_credits) {
                        spin_lock_irqsave(&conn->ibc_lock, flags);
                        conn->ibc_outstanding_credits++;
                        spin_unlock_irqrestore(&conn->ibc_lock, flags);

                        kibnal_check_sends(conn);
                }
                EXIT;
                return;
        }

        if (conn->ibc_state == IBNAL_CONN_ESTABLISHED) {
                CERROR ("Error posting receive -> "LPX64": %d\n",
                        conn->ibc_peer->ibp_nid, rc);
                kibnal_close_conn (rx->rx_conn, rc);
        } else {
                CDEBUG (D_NET, "Error posting receive -> "LPX64": %d\n",
                        conn->ibc_peer->ibp_nid, rc);
        }

        /* Drop rx's ref */
        kibnal_put_conn (conn);
        EXIT;
}

#if IBNAL_CKSUM
static inline __u32 kibnal_cksum (void *ptr, int nob)
{
        char  *c  = ptr;
        __u32  sum = 0;

        while (nob-- > 0)
                sum = ((sum << 1) | (sum >> 31)) + *c++;
        
        return (sum);
}
#endif

static void hexdump(char *string, void *ptr, int len)
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

static void
kibnal_rx_callback (IB_WORK_COMPLETION *wc)
{
        kib_rx_t     *rx = (kib_rx_t *)kibnal_wreqid2ptr(wc->WorkReqId);
        kib_msg_t    *msg = rx->rx_msg;
        kib_conn_t   *conn = rx->rx_conn;
        int           nob = wc->Length;
        const int     base_nob = offsetof(kib_msg_t, ibm_u);
        int           credits;
        int           flipped;
        unsigned long flags;
        __u32         i;
#if IBNAL_CKSUM
        __u32         msg_cksum;
        __u32         computed_cksum;
#endif

        /* we set the QP to erroring after we've finished disconnecting, 
         * maybe we should do so sooner. */
        KIB_ASSERT_CONN_STATE_RANGE(conn, IBNAL_CONN_ESTABLISHED, 
                                    IBNAL_CONN_DISCONNECTED);

        CDEBUG(D_NET, "rx %p conn %p\n", rx, conn);
        LASSERT (rx->rx_posted);
        rx->rx_posted = 0;
        mb();

        /* receives complete with error in any case after we've started
         * disconnecting */
        if (conn->ibc_state > IBNAL_CONN_ESTABLISHED)
                goto failed;

        if (wc->Status != WRStatusSuccess) {
                CERROR("Rx from "LPX64" failed: %d\n", 
                       conn->ibc_peer->ibp_nid, wc->Status);
                goto failed;
        }

        if (nob < base_nob) {
                CERROR ("Short rx from "LPX64": %d < expected %d\n",
                        conn->ibc_peer->ibp_nid, nob, base_nob);
                goto failed;
        }

        hexdump("rx", rx->rx_msg, sizeof(kib_msg_t));

        /* Receiver does any byte flipping if necessary... */

        if (msg->ibm_magic == IBNAL_MSG_MAGIC) {
                flipped = 0;
        } else {
                if (msg->ibm_magic != __swab32(IBNAL_MSG_MAGIC)) {
                        CERROR ("Unrecognised magic: %08x from "LPX64"\n", 
                                msg->ibm_magic, conn->ibc_peer->ibp_nid);
                        goto failed;
                }
                flipped = 1;
                __swab16s (&msg->ibm_version);
                LASSERT (sizeof(msg->ibm_type) == 1);
                LASSERT (sizeof(msg->ibm_credits) == 1);
        }

        if (msg->ibm_version != IBNAL_MSG_VERSION) {
                CERROR ("Incompatible msg version %d (%d expected)\n",
                        msg->ibm_version, IBNAL_MSG_VERSION);
                goto failed;
        }

#if IBNAL_CKSUM
        if (nob != msg->ibm_nob) {
                CERROR ("Unexpected # bytes %d (%d expected)\n", nob, msg->ibm_nob);
                goto failed;
        }

        msg_cksum = le32_to_cpu(msg->ibm_cksum);
        msg->ibm_cksum = 0;
        computed_cksum = kibnal_cksum (msg, nob);
        
        if (msg_cksum != computed_cksum) {
                CERROR ("Checksum failure %d: (%d expected)\n",
                        computed_cksum, msg_cksum);
//                goto failed;
        }
        CDEBUG(D_NET, "cksum %x, nob %d\n", computed_cksum, nob);
#endif

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
                kibnal_post_rx (rx, 1);
                return;

        case IBNAL_MSG_IMMEDIATE:
                if (nob < base_nob + sizeof (kib_immediate_msg_t)) {
                        CERROR ("Short IMMEDIATE from "LPX64": %d\n",
                                conn->ibc_peer->ibp_nid, nob);
                        goto failed;
                }
                break;
                
        case IBNAL_MSG_PUT_RDMA:
        case IBNAL_MSG_GET_RDMA:
                if (nob < base_nob + sizeof (kib_rdma_msg_t)) {
                        CERROR ("Short RDMA msg from "LPX64": %d\n",
                                conn->ibc_peer->ibp_nid, nob);
                        goto failed;
                }
                if (flipped) 
                        __swab32(msg->ibm_u.rdma.ibrm_num_descs);

                CDEBUG(D_NET, "%d RDMA: cookie "LPX64":\n",
                       msg->ibm_type, msg->ibm_u.rdma.ibrm_cookie);

                if ((msg->ibm_u.rdma.ibrm_num_descs > PTL_MD_MAX_IOV) ||
                    (kib_rdma_msg_len(msg->ibm_u.rdma.ibrm_num_descs) > 
                     min(nob, IBNAL_MSG_SIZE))) {
                        CERROR ("num_descs %d too large\n", 
                                msg->ibm_u.rdma.ibrm_num_descs);
                        goto failed;
                }

                if (flipped) {
                        __swab32(msg->ibm_u.rdma.rd_key);
                }

                for(i = 0; i < msg->ibm_u.rdma.ibrm_num_descs; i++) {
                        kib_rdma_desc_t *desc = &msg->ibm_u.rdma.ibrm_desc[i];

                        if (flipped) {
                                __swab32(desc->rd_nob);
                                __swab64(desc->rd_addr);
                        }

                        CDEBUG(D_NET, "  key %x, " "addr "LPX64", nob %u\n",
                               msg->ibm_u.rdma.rd_key, desc->rd_addr, desc->rd_nob);
                }
                break;
                        
        case IBNAL_MSG_PUT_DONE:
        case IBNAL_MSG_GET_DONE:
                if (nob < base_nob + sizeof (kib_completion_msg_t)) {
                        CERROR ("Short COMPLETION msg from "LPX64": %d\n",
                                conn->ibc_peer->ibp_nid, nob);
                        goto failed;
                }
                if (flipped)
                        __swab32s(&msg->ibm_u.completion.ibcm_status);
                
                CDEBUG(D_NET, "%d DONE: cookie "LPX64", status %d\n",
                       msg->ibm_type, msg->ibm_u.completion.ibcm_cookie,
                       msg->ibm_u.completion.ibcm_status);

                kibnal_complete_passive_rdma (conn, 
                                              msg->ibm_u.completion.ibcm_cookie,
                                              msg->ibm_u.completion.ibcm_status);
                kibnal_post_rx (rx, 1);
                return;
                        
        default:
                CERROR ("Can't parse type from "LPX64": %d\n",
                        conn->ibc_peer->ibp_nid, msg->ibm_type);
                goto failed;
        }

        /* schedule for kibnal_rx() in thread context */
        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
        
        list_add_tail (&rx->rx_list, &kibnal_data.kib_sched_rxq);
        wake_up (&kibnal_data.kib_sched_waitq);
        
        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock, flags);
        return;
        
 failed:
        CDEBUG(D_NET, "rx %p conn %p\n", rx, conn);
        kibnal_close_conn(conn, -ECONNABORTED);

        /* Don't re-post rx & drop its ref on conn */
        kibnal_put_conn(conn);
}

void
kibnal_rx (kib_rx_t *rx)
{
        kib_msg_t   *msg = rx->rx_msg;

        /* Clear flag so I can detect if I've sent an RDMA completion */
        rx->rx_rdma = 0;

        switch (msg->ibm_type) {
        case IBNAL_MSG_GET_RDMA:
                ptl_parse(kibnal_data.kib_ni, &msg->ibm_u.rdma.ibrm_hdr, rx);
                /* If the incoming get was matched, I'll have initiated the
                 * RDMA and the completion message... */
                if (rx->rx_rdma)
                        break;

                /* Otherwise, I'll send a failed completion now to prevent
                 * the peer's GET blocking for the full timeout. */
                CERROR ("Completing unmatched RDMA GET from "LPX64"\n",
                        rx->rx_conn->ibc_peer->ibp_nid);
                kibnal_start_active_rdma (IBNAL_MSG_GET_DONE, -EIO,
                                          rx, NULL, 0, NULL, NULL, 0, 0);
                break;
                
        case IBNAL_MSG_PUT_RDMA:
                ptl_parse(kibnal_data.kib_ni, &msg->ibm_u.rdma.ibrm_hdr, rx);
                if (rx->rx_rdma)
                        break;
                /* This is most unusual, since even if ptl_parse() didn't
                 * match anything, it should have asked us to read (and
                 * discard) the payload.  The portals header must be
                 * inconsistent with this message type, so it's the
                 * sender's fault for sending garbage and she can time
                 * herself out... */
                CERROR ("Uncompleted RMDA PUT from "LPX64"\n",
                        rx->rx_conn->ibc_peer->ibp_nid);
                break;

        case IBNAL_MSG_IMMEDIATE:
                ptl_parse(kibnal_data.kib_ni, &msg->ibm_u.immediate.ibim_hdr, rx);
                LASSERT (!rx->rx_rdma);
                break;
                
        default:
                LBUG();
                break;
        }

        kibnal_post_rx (rx, 1);
}

static struct page *
kibnal_kvaddr_to_page (unsigned long vaddr)
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

        if (!VALID_PAGE (page))
                page = NULL;

        return page;
}

static void
kibnal_fill_ibrm(kib_tx_t *tx, struct page *page, unsigned long page_offset,
                 unsigned long len, int active)
{
        kib_rdma_msg_t *ibrm = &tx->tx_msg->ibm_u.rdma;
        kib_rdma_desc_t *desc;

        LASSERTF(ibrm->ibrm_num_descs < PTL_MD_MAX_IOV, "%u\n", 
                 ibrm->ibrm_num_descs);

        desc = &ibrm->ibrm_desc[ibrm->ibrm_num_descs];
        if (active)
                ibrm->rd_key = kibnal_data.kib_md.md_lkey;
        else
                ibrm->rd_key = kibnal_data.kib_md.md_rkey;
        desc->rd_nob = len; /*PAGE_SIZE - kiov->kiov_offset; */
        desc->rd_addr = kibnal_page2phys(page) + page_offset +
                        kibnal_data.kib_md.md_addr;

        ibrm->ibrm_num_descs++;
}

static int
kibnal_map_rdma_iov(kib_tx_t *tx, unsigned long vaddr, int nob, int active)
{
        struct page *page;
        int page_offset, len;

        while (nob > 0) {
                page = kibnal_kvaddr_to_page(vaddr);
                if (page == NULL)
                        return -EFAULT;

                page_offset = vaddr & (PAGE_SIZE - 1);
                len = min(nob, (int)PAGE_SIZE - page_offset);
                
                kibnal_fill_ibrm(tx, page, page_offset, len, active);
                nob -= len;
                vaddr += len;
        }
        return 0;
}

static int
kibnal_map_iov (kib_tx_t *tx, IB_ACCESS_CONTROL access,
                 int niov, struct iovec *iov, int offset, int nob, int active)
                 
{
        void   *vaddr;
        FSTATUS frc;

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

        /* our large contiguous iov could be backed by multiple physical
         * pages. */
        if (kibnal_whole_mem()) {
                int rc;
                tx->tx_msg->ibm_u.rdma.ibrm_num_descs = 0;
                rc = kibnal_map_rdma_iov(tx, (unsigned long)iov->iov_base + 
                                         offset, nob, active);
                if (rc != 0) {
                        CERROR ("Can't map iov: %d\n", rc);
                        return rc;
                }
                return 0;
        }

        vaddr = (void *)(((unsigned long)iov->iov_base) + offset);
        tx->tx_md.md_addr = (__u64)((unsigned long)vaddr);

        frc = iibt_register_memory(kibnal_data.kib_hca, vaddr, nob,
                                   kibnal_data.kib_pd, access,
                                   &tx->tx_md.md_handle, &tx->tx_md.md_lkey,
                                   &tx->tx_md.md_rkey);
        if (frc != 0) {
                CERROR ("Can't map vaddr %p: %d\n", vaddr, frc);
                return -EINVAL;
        }

        tx->tx_mapped = KIB_TX_MAPPED;
        return (0);
}

static int
kibnal_map_kiov (kib_tx_t *tx, IB_ACCESS_CONTROL access,
                  int nkiov, ptl_kiov_t *kiov,
                  int offset, int nob, int active)
{
        __u64                      *phys = NULL;
        int                         page_offset;
        int                         nphys;
        int                         resid;
        int                         phys_size = 0;
        FSTATUS                     frc;
        int                         i, rc = 0;

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

        page_offset = kiov->kiov_offset + offset;
        nphys = 1;

        if (!kibnal_whole_mem()) {
                phys_size = nkiov * sizeof (*phys);
                PORTAL_ALLOC(phys, phys_size);
                if (phys == NULL) {
                        CERROR ("Can't allocate tmp phys\n");
                        return (-ENOMEM);
                }

                phys[0] = kibnal_page2phys(kiov->kiov_page);
        } else {
                tx->tx_msg->ibm_u.rdma.ibrm_num_descs = 0;
                kibnal_fill_ibrm(tx, kiov->kiov_page, kiov->kiov_offset, 
                                 kiov->kiov_len, active);
        }

        resid = nob - (kiov->kiov_len - offset);

        while (resid > 0) {
                kiov++;
                nkiov--;
                LASSERT (nkiov > 0);

                if (kiov->kiov_offset != 0 ||
                    ((resid > PAGE_SIZE) && 
                     kiov->kiov_len < PAGE_SIZE)) {
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

                if (!kibnal_whole_mem()) {
                        LASSERT (nphys * sizeof (*phys) < phys_size);
                        phys[nphys] = kibnal_page2phys(kiov->kiov_page);
                } else {
                        if (kib_rdma_msg_len(nphys) > IBNAL_MSG_SIZE) {
                                CERROR ("payload too big (%d)\n", nphys);
                                rc = -EMSGSIZE;
                                goto out;
                        }
                        kibnal_fill_ibrm(tx, kiov->kiov_page, 
                                         kiov->kiov_offset, kiov->kiov_len,
                                         active);
                }

                nphys ++;
                resid -= PAGE_SIZE;
        }

        if (kibnal_whole_mem())
                goto out;

#if 0
        CWARN ("nphys %d, nob %d, page_offset %d\n", nphys, nob, page_offset);
        for (i = 0; i < nphys; i++)
                CWARN ("   [%d] "LPX64"\n", i, phys[i]);
#endif

#if IBNAL_FMR
#error "iibnal hasn't learned about FMR yet"
        rc = ib_fmr_register_physical (kibnal_data.kib_fmr_pool,
                                       phys, nphys,
                                       &tx->tx_md.md_addr,
                                       page_offset,
                                       &tx->tx_md.md_handle.fmr,
                                       &tx->tx_md.md_lkey,
                                       &tx->tx_md.md_rkey);
#else
        frc = iibt_register_physical_memory(kibnal_data.kib_hca,
                                            IBNAL_RDMA_BASE,
                                            phys, nphys,
                                            0,          /* offset */
                                            kibnal_data.kib_pd,
                                            access,
                                            &tx->tx_md.md_handle,
                                            &tx->tx_md.md_addr,
                                            &tx->tx_md.md_lkey,
                                            &tx->tx_md.md_rkey);
#endif
        if (frc == FSUCCESS) {
                CDEBUG(D_NET, "Mapped %d pages %d bytes @ offset %d: lkey %x, rkey %x\n",
                       nphys, nob, page_offset, tx->tx_md.md_lkey, tx->tx_md.md_rkey);
#if IBNAL_FMR
                tx->tx_mapped = KIB_TX_MAPPED_FMR;
#else
                tx->tx_mapped = KIB_TX_MAPPED;
#endif
        } else {
                CERROR ("Can't map phys: %d\n", frc);
                rc = -EFAULT;
        }

 out:
        if (phys != NULL)
                PORTAL_FREE(phys, phys_size);
        return (rc);
}

static kib_conn_t *
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
        int             done;
        int             nwork;
        ENTRY;

        spin_lock_irqsave (&conn->ibc_lock, flags);

        LASSERT (conn->ibc_nsends_posted <= IBNAL_MSG_QUEUE_SIZE);

        if (list_empty(&conn->ibc_tx_queue) &&
            conn->ibc_outstanding_credits >= IBNAL_CREDIT_HIGHWATER) {
                spin_unlock_irqrestore(&conn->ibc_lock, flags);
                
                tx = kibnal_get_idle_tx(0);     /* don't block */
                if (tx != NULL)
                        kibnal_init_tx_msg(tx, IBNAL_MSG_NOOP, 0);

                spin_lock_irqsave(&conn->ibc_lock, flags);
                
                if (tx != NULL) {
                        atomic_inc(&conn->ibc_refcount);
                        kibnal_queue_tx_locked(tx, conn);
                }
        }

        while (!list_empty (&conn->ibc_tx_queue)) {
                tx = list_entry (conn->ibc_tx_queue.next, kib_tx_t, tx_list);

                /* We rely on this for QP sizing */
                LASSERT (tx->tx_nsp > 0 && tx->tx_nsp <= IBNAL_TX_MAX_SG);

                LASSERT (conn->ibc_outstanding_credits >= 0);
                LASSERT (conn->ibc_outstanding_credits <= IBNAL_MSG_QUEUE_SIZE);
                LASSERT (conn->ibc_credits >= 0);
                LASSERT (conn->ibc_credits <= IBNAL_MSG_QUEUE_SIZE);

                /* Not on ibc_rdma_queue */
                LASSERT (!tx->tx_passive_rdma_wait);

                if (conn->ibc_nsends_posted == IBNAL_MSG_QUEUE_SIZE)
                        GOTO(out, 0);

                if (conn->ibc_credits == 0)     /* no credits */
                        GOTO(out, 1);
                
                if (conn->ibc_credits == 1 &&   /* last credit reserved for */
                    conn->ibc_outstanding_credits == 0) /* giving back credits */
                        GOTO(out, 2);

                list_del (&tx->tx_list);

                if (tx->tx_msg->ibm_type == IBNAL_MSG_NOOP &&
                    (!list_empty(&conn->ibc_tx_queue) ||
                     conn->ibc_outstanding_credits < IBNAL_CREDIT_HIGHWATER)) {
                        /* redundant NOOP */
                        spin_unlock_irqrestore(&conn->ibc_lock, flags);
                        kibnal_tx_done(tx);
                        spin_lock_irqsave(&conn->ibc_lock, flags);
                        continue;
                }

                tx->tx_msg->ibm_credits = conn->ibc_outstanding_credits;
                conn->ibc_outstanding_credits = 0;

                conn->ibc_nsends_posted++;
                conn->ibc_credits--;

                /* we only get a tx completion for the final rdma op */ 
                tx->tx_sending = min(tx->tx_nsp, 2);
                tx->tx_passive_rdma_wait = tx->tx_passive_rdma;
                list_add (&tx->tx_list, &conn->ibc_active_txs);
#if IBNAL_CKSUM
                tx->tx_msg->ibm_cksum = 0;
                tx->tx_msg->ibm_cksum = kibnal_cksum(tx->tx_msg, tx->tx_msg->ibm_nob);
                CDEBUG(D_NET, "cksum %x, nob %d\n", tx->tx_msg->ibm_cksum, tx->tx_msg->ibm_nob);
#endif
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
                                hexdump("tx", tx->tx_msg, sizeof(kib_msg_t));
                                rc = iibt_postsend(conn->ibc_qp, 
                                                   &tx->tx_wrq[i]);
                                if (rc != 0)
                                        break;
                                if (wrq_signals_completion(&tx->tx_wrq[i]))
                                        nwork++;
                                CDEBUG(D_NET, "posted tx wrq %p\n", 
                                       &tx->tx_wrq[i]);
                        }
                }

                spin_lock_irqsave (&conn->ibc_lock, flags);
                if (rc != 0) {
                        /* NB credits are transferred in the actual
                         * message, which can only be the last work item */
                        conn->ibc_outstanding_credits += tx->tx_msg->ibm_credits;
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
                                CERROR ("Error %d posting transmit to "LPX64"\n", 
                                        rc, conn->ibc_peer->ibp_nid);
                        else
                                CDEBUG (D_NET, "Error %d posting transmit to "
                                        LPX64"\n", rc, conn->ibc_peer->ibp_nid);

                        kibnal_close_conn (conn, rc);

                        if (done)
                                kibnal_tx_done (tx);
                        return;
                }
                
        }

        EXIT;
out:
        spin_unlock_irqrestore (&conn->ibc_lock, flags);
}

static void
kibnal_tx_callback (IB_WORK_COMPLETION *wc)
{
        kib_tx_t     *tx = (kib_tx_t *)kibnal_wreqid2ptr(wc->WorkReqId);
        kib_conn_t   *conn;
        unsigned long flags;
        int           idle;

        conn = tx->tx_conn;
        LASSERT (conn != NULL);
        LASSERT (tx->tx_sending != 0);

        spin_lock_irqsave(&conn->ibc_lock, flags);

        CDEBUG(D_NET, "conn %p tx %p [%d/%d]: %d\n", conn, tx,
               tx->tx_sending, tx->tx_nsp, wc->Status);

        /* I could be racing with rdma completion.  Whoever makes 'tx' idle
         * gets to free it, which also drops its ref on 'conn'.  If it's
         * not me, then I take an extra ref on conn so it can't disappear
         * under me. */

        tx->tx_sending--;
        idle = (tx->tx_sending == 0) &&         /* This is the final callback */
               (!tx->tx_passive_rdma_wait);     /* Not waiting for RDMA completion */
        if (idle)
                list_del(&tx->tx_list);

        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
               conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
               atomic_read (&conn->ibc_refcount));
        atomic_inc (&conn->ibc_refcount);

        if (tx->tx_sending == 0)
                conn->ibc_nsends_posted--;

        if (wc->Status != WRStatusSuccess &&
            tx->tx_status == 0)
                tx->tx_status = -ECONNABORTED;
                
        spin_unlock_irqrestore(&conn->ibc_lock, flags);

        if (idle)
                kibnal_tx_done (tx);

        if (wc->Status != WRStatusSuccess) {
                CERROR ("Tx completion to "LPX64" failed: %d\n", 
                        conn->ibc_peer->ibp_nid, wc->Status);
                kibnal_close_conn (conn, -ENETDOWN);
        } else {
                /* can I shovel some more sends out the door? */
                kibnal_check_sends(conn);
        }

        kibnal_put_conn (conn);
}

void 
kibnal_ca_async_callback (void *ca_arg, IB_EVENT_RECORD *ev)
{
        /* XXX flesh out.  this seems largely for async errors */
        CERROR("type: %d code: %u\n", ev->EventType, ev->EventCode);
}

void
kibnal_ca_callback (void *ca_arg, void *cq_arg)
{
        IB_HANDLE cq = *(IB_HANDLE *)cq_arg;
        IB_HANDLE ca = *(IB_HANDLE *)ca_arg;
        IB_WORK_COMPLETION wc;
        int armed = 0;

        CDEBUG(D_NET, "ca %p cq %p\n", ca, cq);

        for(;;) {
                while (iibt_cq_poll(cq, &wc) == FSUCCESS) {

                        /* We will need to rearm the CQ to avoid a potential race. */
                        armed = 0;
                        
                        if (kibnal_wreqid_is_rx(wc.WorkReqId))
                                kibnal_rx_callback(&wc);
                        else
                                kibnal_tx_callback(&wc);
                }
                if (armed)
                        return;
                if (iibt_cq_rearm(cq, CQEventSelNextWC) != FSUCCESS) {
                        CERROR("rearm failed?\n");
                        return;
                }
                armed = 1;
        }
}

void
kibnal_init_tx_msg (kib_tx_t *tx, int type, int body_nob)
{
        IB_LOCAL_DATASEGMENT *gl = &tx->tx_gl[tx->tx_nsp];
        IB_WORK_REQ         *wrq = &tx->tx_wrq[tx->tx_nsp];
        int                       fence;
        int                       nob = offsetof (kib_msg_t, ibm_u) + body_nob;

        LASSERT (tx->tx_nsp >= 0 && 
                 tx->tx_nsp < sizeof(tx->tx_wrq)/sizeof(tx->tx_wrq[0]));
        LASSERT (nob <= IBNAL_MSG_SIZE);
        
        tx->tx_msg->ibm_magic = IBNAL_MSG_MAGIC;
        tx->tx_msg->ibm_version = IBNAL_MSG_VERSION;
        tx->tx_msg->ibm_type = type;
#if IBNAL_CKSUM
        tx->tx_msg->ibm_nob = nob;
#endif
        /* Fence the message if it's bundled with an RDMA read */
        fence = (tx->tx_nsp > 0) &&
                (type == IBNAL_MSG_PUT_DONE);

        *gl = (IB_LOCAL_DATASEGMENT) {
                .Address = tx->tx_vaddr,
                .Length  = IBNAL_MSG_SIZE,
                .Lkey    = kibnal_lkey(kibnal_data.kib_tx_pages),
        };

        wrq->WorkReqId      = kibnal_ptr2wreqid(tx, 0);
        wrq->Operation      = WROpSend;
        wrq->DSList         = gl;
        wrq->DSListDepth    = 1;
        wrq->MessageLen     = nob;
        wrq->Req.SendRC.ImmediateData  = 0;
        wrq->Req.SendRC.Options.s.SolicitedEvent         = 1;
        wrq->Req.SendRC.Options.s.SignaledCompletion     = 1;
        wrq->Req.SendRC.Options.s.ImmediateData          = 0;
        wrq->Req.SendRC.Options.s.Fence                  = fence;

        tx->tx_nsp++;
}

static void
kibnal_queue_tx (kib_tx_t *tx, kib_conn_t *conn)
{
        unsigned long         flags;

        spin_lock_irqsave(&conn->ibc_lock, flags);

        kibnal_queue_tx_locked (tx, conn);
        
        spin_unlock_irqrestore(&conn->ibc_lock, flags);
        
        kibnal_check_sends(conn);
}

static void
kibnal_launch_tx (kib_tx_t *tx, ptl_nid_t nid)
{
        unsigned long    flags;
        kib_peer_t      *peer;
        kib_conn_t      *conn;
        rwlock_t        *g_lock = &kibnal_data.kib_global_lock;

        /* If I get here, I've committed to send, so I complete the tx with
         * failure on any problems */
        
        LASSERT (tx->tx_conn == NULL);          /* only set when assigned a conn */
        LASSERT (tx->tx_nsp > 0);               /* work items have been set up */

        read_lock_irqsave(g_lock, flags);
        
        peer = kibnal_find_peer_locked (nid);
        if (peer == NULL) {
                read_unlock_irqrestore(g_lock, flags);
                tx->tx_status = -EHOSTUNREACH;
                kibnal_tx_done (tx);
                return;
        }

        conn = kibnal_find_conn_locked (peer);
        if (conn != NULL) {
                CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                       atomic_read (&conn->ibc_refcount));
                atomic_inc (&conn->ibc_refcount); /* 1 ref for the tx */
                read_unlock_irqrestore(g_lock, flags);
                
                kibnal_queue_tx (tx, conn);
                return;
        }
        
        /* Making one or more connections; I'll need a write lock... */
        read_unlock(g_lock);
        write_lock(g_lock);

        peer = kibnal_find_peer_locked (nid);
        if (peer == NULL) {
                write_unlock_irqrestore (g_lock, flags);
                tx->tx_status = -EHOSTUNREACH;
                kibnal_tx_done (tx);
                return;
        }

        conn = kibnal_find_conn_locked (peer);
        if (conn != NULL) {
                /* Connection exists; queue message on it */
                CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                       atomic_read (&conn->ibc_refcount));
                atomic_inc (&conn->ibc_refcount); /* 1 ref for the tx */
                write_unlock_irqrestore (g_lock, flags);
                
                kibnal_queue_tx (tx, conn);
                return;
        }

        if (peer->ibp_connecting == 0) {
                if (!time_after_eq(jiffies, peer->ibp_reconnect_time)) {
                        write_unlock_irqrestore (g_lock, flags);
                        tx->tx_status = -EHOSTUNREACH;
                        kibnal_tx_done (tx);
                        return;
                }
        
                peer->ibp_connecting = 1;
                kib_peer_addref(peer); /* extra ref for connd */
        
                spin_lock (&kibnal_data.kib_connd_lock);
        
                list_add_tail (&peer->ibp_connd_list,
                               &kibnal_data.kib_connd_peers);
                wake_up (&kibnal_data.kib_connd_waitq);
        
                spin_unlock (&kibnal_data.kib_connd_lock);
        }
        
        /* A connection is being established; queue the message... */
        list_add_tail (&tx->tx_list, &peer->ibp_tx_queue);

        write_unlock_irqrestore (g_lock, flags);
}

static ptl_err_t
kibnal_start_passive_rdma (int type, ptl_nid_t nid,
                            ptl_msg_t *ptlmsg, ptl_hdr_t *hdr)
{
        int         nob = ptlmsg->msg_md->md_length;
        kib_tx_t   *tx;
        kib_msg_t  *ibmsg;
        int         rc;
        IB_ACCESS_CONTROL         access = {0,};
        
        LASSERT (type == IBNAL_MSG_PUT_RDMA || type == IBNAL_MSG_GET_RDMA);
        LASSERT (nob > 0);
        LASSERT (!in_interrupt());              /* Mapping could block */

        access.s.MWBindable = 1;
        access.s.LocalWrite = 1;
        access.s.RdmaRead = 1;
        access.s.RdmaWrite = 1;

        tx = kibnal_get_idle_tx (1);           /* May block; caller is an app thread */
        LASSERT (tx != NULL);

        if ((ptlmsg->msg_md->md_options & PTL_MD_KIOV) == 0) 
                rc = kibnal_map_iov (tx, access,
                                     ptlmsg->msg_md->md_niov,
                                     ptlmsg->msg_md->md_iov.iov,
                                     0, nob, 0);
        else
                rc = kibnal_map_kiov (tx, access,
                                      ptlmsg->msg_md->md_niov, 
                                      ptlmsg->msg_md->md_iov.kiov,
                                      0, nob, 0);

        if (rc != 0) {
                CERROR ("Can't map RDMA for "LPX64": %d\n", nid, rc);
                goto failed;
        }
        
        if (type == IBNAL_MSG_GET_RDMA) {
                /* reply gets finalized when tx completes */
                tx->tx_ptlmsg[1] = ptl_create_reply_msg(kibnal_data.kib_ni, 
                                                        nid, ptlmsg);
                if (tx->tx_ptlmsg[1] == NULL) {
                        CERROR ("Can't create reply for GET -> "LPX64"\n",
                                nid);
                        rc = -ENOMEM;
                        goto failed;
                }
        }
        
        tx->tx_passive_rdma = 1;

        ibmsg = tx->tx_msg;

        ibmsg->ibm_u.rdma.ibrm_hdr = *hdr;
        ibmsg->ibm_u.rdma.ibrm_cookie = tx->tx_passive_rdma_cookie;
        /* map_kiov alrady filled the rdma descs for the whole_mem case */
        if (!kibnal_whole_mem()) {
                ibmsg->ibm_u.rdma.rd_key = tx->tx_md.md_rkey;
                ibmsg->ibm_u.rdma.ibrm_desc[0].rd_addr = tx->tx_md.md_addr;
                ibmsg->ibm_u.rdma.ibrm_desc[0].rd_nob = nob;
                ibmsg->ibm_u.rdma.ibrm_num_descs = 1;
        }

        kibnal_init_tx_msg (tx, type, 
                            kib_rdma_msg_len(ibmsg->ibm_u.rdma.ibrm_num_descs));

        CDEBUG(D_NET, "Passive: %p cookie "LPX64", key %x, addr "
               LPX64", nob %d\n",
               tx, tx->tx_passive_rdma_cookie, tx->tx_md.md_rkey,
               tx->tx_md.md_addr, nob);
        
        /* ptlmsg gets finalized when tx completes. */
        tx->tx_ptlmsg[0] = ptlmsg;

        kibnal_launch_tx(tx, nid);
        return (PTL_OK);

 failed:
        tx->tx_status = rc;
        kibnal_tx_done (tx);
        return (PTL_FAIL);
}

void
kibnal_start_active_rdma (int type, int status,
                           kib_rx_t *rx, ptl_msg_t *ptlmsg, 
                           unsigned int niov,
                           struct iovec *iov, ptl_kiov_t *kiov,
                           size_t offset, size_t nob)
{
        kib_msg_t    *rxmsg = rx->rx_msg;
        kib_msg_t    *txmsg;
        kib_tx_t     *tx;
        IB_ACCESS_CONTROL access = {0,};
        IB_WR_OP      rdma_op;
        int           rc;
        __u32         i;

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

        /* Flag I'm completing the RDMA.  Even if I fail to send the
         * completion message, I will have tried my best so further
         * attempts shouldn't be tried. */
        LASSERT (!rx->rx_rdma);
        rx->rx_rdma = 1;

        if (type == IBNAL_MSG_GET_DONE) {
                rdma_op  = WROpRdmaWrite;
                LASSERT (rxmsg->ibm_type == IBNAL_MSG_GET_RDMA);
        } else {
                access.s.LocalWrite = 1;
                rdma_op  = WROpRdmaRead;
                LASSERT (rxmsg->ibm_type == IBNAL_MSG_PUT_RDMA);
        }

        tx = kibnal_get_idle_tx (0);           /* Mustn't block */
        if (tx == NULL) {
                CERROR ("tx descs exhausted on RDMA from "LPX64
                        " completing locally with failure\n",
                        rx->rx_conn->ibc_peer->ibp_nid);
                ptl_finalize (kibnal_data.kib_ni, NULL, ptlmsg, PTL_NO_SPACE);
                return;
        }
        LASSERT (tx->tx_nsp == 0);
                        
        if (nob == 0) 
                GOTO(init_tx, 0);

        /* We actually need to transfer some data (the transfer
         * size could get truncated to zero when the incoming
         * message is matched) */
        if (kiov != NULL)
                rc = kibnal_map_kiov (tx, access, niov, kiov, offset, nob, 1);
        else
                rc = kibnal_map_iov (tx, access, niov, iov, offset, nob, 1);
        
        if (rc != 0) {
                CERROR ("Can't map RDMA -> "LPX64": %d\n", 
                        rx->rx_conn->ibc_peer->ibp_nid, rc);
                /* We'll skip the RDMA and complete with failure. */
                status = rc;
                nob = 0;
                GOTO(init_tx, rc);
        } 

        if (!kibnal_whole_mem()) {
                tx->tx_msg->ibm_u.rdma.rd_key = tx->tx_md.md_lkey;
                tx->tx_msg->ibm_u.rdma.ibrm_desc[0].rd_addr = tx->tx_md.md_addr;
                tx->tx_msg->ibm_u.rdma.ibrm_desc[0].rd_nob = nob;
                tx->tx_msg->ibm_u.rdma.ibrm_num_descs = 1;
        }

        /* XXX ugh.  different page-sized hosts. */ 
        if (tx->tx_msg->ibm_u.rdma.ibrm_num_descs !=
            rxmsg->ibm_u.rdma.ibrm_num_descs) {
                CERROR("tx descs (%u) != rx descs (%u)\n", 
                       tx->tx_msg->ibm_u.rdma.ibrm_num_descs,
                       rxmsg->ibm_u.rdma.ibrm_num_descs);
                /* We'll skip the RDMA and complete with failure. */
                status = rc;
                nob = 0;
                GOTO(init_tx, rc);
        }

        /* map_kiov filled in the rdma descs which describe our side of the
         * rdma transfer. */
        /* ibrm_num_descs was verified in rx_callback */
        for(i = 0; i < rxmsg->ibm_u.rdma.ibrm_num_descs; i++) {
                kib_rdma_desc_t *ldesc, *rdesc; /* local, remote */
                IB_LOCAL_DATASEGMENT *ds = &tx->tx_gl[i];
                IB_WORK_REQ  *wrq = &tx->tx_wrq[i];

                ldesc = &tx->tx_msg->ibm_u.rdma.ibrm_desc[i];
                rdesc = &rxmsg->ibm_u.rdma.ibrm_desc[i];

                ds->Address = ldesc->rd_addr;
                ds->Length  = ldesc->rd_nob;
                ds->Lkey    = tx->tx_msg->ibm_u.rdma.rd_key;

                memset(wrq, 0, sizeof(*wrq));
                wrq->WorkReqId      = kibnal_ptr2wreqid(tx, 0);
                wrq->Operation      = rdma_op;
                wrq->DSList         = ds;
                wrq->DSListDepth    = 1;
                wrq->MessageLen     = ds->Length;
                wrq->Req.SendRC.ImmediateData  = 0;
                wrq->Req.SendRC.Options.s.SolicitedEvent         = 0;
                wrq->Req.SendRC.Options.s.SignaledCompletion     = 0;
                wrq->Req.SendRC.Options.s.ImmediateData          = 0;
                wrq->Req.SendRC.Options.s.Fence                  = 0;
                wrq->Req.SendRC.RemoteDS.Address = rdesc->rd_addr;
                wrq->Req.SendRC.RemoteDS.Rkey = rxmsg->ibm_u.rdma.rd_key;

                /* only the last rdma post triggers tx completion */
                if (i == rxmsg->ibm_u.rdma.ibrm_num_descs - 1)
                        wrq->Req.SendRC.Options.s.SignaledCompletion = 1;

                tx->tx_nsp++;
        }

init_tx:
        txmsg = tx->tx_msg;

        txmsg->ibm_u.completion.ibcm_cookie = rxmsg->ibm_u.rdma.ibrm_cookie;
        txmsg->ibm_u.completion.ibcm_status = status;
        
        kibnal_init_tx_msg(tx, type, sizeof (kib_completion_msg_t));

        if (status == 0 && nob != 0) {
                LASSERT (tx->tx_nsp > 1);
                /* RDMA: ptlmsg gets finalized when the tx completes.  This
                 * is after the completion message has been sent, which in
                 * turn is after the RDMA has finished. */
                tx->tx_ptlmsg[0] = ptlmsg;
        } else {
                LASSERT (tx->tx_nsp == 1);
                /* No RDMA: local completion happens now! */
                CDEBUG(D_WARNING,"No data: immediate completion\n");
                ptl_finalize (kibnal_data.kib_ni, NULL, ptlmsg,
                              status == 0 ? PTL_OK : PTL_FAIL);
        }

        /* +1 ref for this tx... */
        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
               rx->rx_conn, rx->rx_conn->ibc_state, 
               rx->rx_conn->ibc_peer->ibp_nid,
               atomic_read (&rx->rx_conn->ibc_refcount));
        atomic_inc (&rx->rx_conn->ibc_refcount);
        /* ...and queue it up */
        kibnal_queue_tx(tx, rx->rx_conn);
}

static ptl_err_t
kibnal_sendmsg(ptl_ni_t        *ni, 
               void            *private,
               ptl_msg_t       *ptlmsg,
               ptl_hdr_t       *hdr, 
               int              type, 
               ptl_process_id_t target,
               int              routing,
               unsigned int     payload_niov, 
               struct iovec    *payload_iov, 
               ptl_kiov_t      *payload_kiov,
               size_t           payload_offset,
               size_t           payload_nob)
{
        kib_msg_t  *ibmsg;
        kib_tx_t   *tx;
        int         nob;

        /* NB 'private' is different depending on what we're sending.... */

        CDEBUG(D_NET, "sending "LPSZ" bytes in %d frags to %s\n", 
               payload_nob, payload_niov, libcfs_id2str(target));

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV);

        /* Thread context if we're sending payload */
        LASSERT (!in_interrupt() || payload_niov == 0);
        /* payload is either all vaddrs or all pages */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));

        if (routing) {
                CERROR ("Can't route\n");
                return PTL_FAIL;
        }
        
        switch (type) {
        default:
                LBUG();
                return (PTL_FAIL);
                
        case PTL_MSG_REPLY: {
                /* reply's 'private' is the incoming receive */
                kib_rx_t *rx = private;

                /* RDMA reply expected? */
                if (rx->rx_msg->ibm_type == IBNAL_MSG_GET_RDMA) {
                        kibnal_start_active_rdma(IBNAL_MSG_GET_DONE, 0,
                                                 rx, ptlmsg, payload_niov, 
                                                 payload_iov, payload_kiov,
                                                 payload_offset, payload_nob);
                        return (PTL_OK);
                }
                
                /* Incoming message consistent with immediate reply? */
                if (rx->rx_msg->ibm_type != IBNAL_MSG_IMMEDIATE) {
                        CERROR ("REPLY to "LPX64" bad opbm type %d!!!\n",
                                target.nid, rx->rx_msg->ibm_type);
                        return (PTL_FAIL);
                }

                /* Will it fit in a message? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob]);
                if (nob >= IBNAL_MSG_SIZE) {
                        CERROR("REPLY for "LPX64" too big (RDMA not requested): %d\n", 
                               target.nid, payload_nob);
                        return (PTL_FAIL);
                }
                break;
        }

        case PTL_MSG_GET:
                /* might the REPLY message be big enough to need RDMA? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[ptlmsg->msg_md->md_length]);
                if (nob > IBNAL_MSG_SIZE)
                        return (kibnal_start_passive_rdma(IBNAL_MSG_GET_RDMA, 
                                                          target.nid, ptlmsg, hdr));
                break;

        case PTL_MSG_ACK:
                LASSERT (payload_nob == 0);
                break;

        case PTL_MSG_PUT:
                /* Is the payload big enough to need RDMA? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob]);
                if (nob > IBNAL_MSG_SIZE)
                        return (kibnal_start_passive_rdma(IBNAL_MSG_PUT_RDMA,
                                                          target.nid, ptlmsg, hdr));
                
                break;
        }

        tx = kibnal_get_idle_tx(!(type == PTL_MSG_ACK ||
                                  type == PTL_MSG_REPLY ||
                                  in_interrupt()));
        if (tx == NULL) {
                CERROR ("Can't send %d to "LPX64": tx descs exhausted%s\n", 
                        type, target.nid, in_interrupt() ? " (intr)" : "");
                return (PTL_NO_SPACE);
        }

        ibmsg = tx->tx_msg;
        ibmsg->ibm_u.immediate.ibim_hdr = *hdr;

        if (payload_nob > 0) {
                if (payload_kiov != NULL)
                        ptl_copy_kiov2buf(ibmsg->ibm_u.immediate.ibim_payload,
                                          payload_niov, payload_kiov,
                                          payload_offset, payload_nob);
                else
                        ptl_copy_iov2buf(ibmsg->ibm_u.immediate.ibim_payload,
                                         payload_niov, payload_iov,
                                         payload_offset, payload_nob);
        }

        kibnal_init_tx_msg (tx, IBNAL_MSG_IMMEDIATE,
                            offsetof(kib_immediate_msg_t, 
                                     ibim_payload[payload_nob]));

        /* ptlmsg gets finalized when tx completes */
        tx->tx_ptlmsg[0] = ptlmsg;

        kibnal_launch_tx(tx, target.nid);
        return (PTL_OK);
}

ptl_err_t
kibnal_send (ptl_ni_t *ni, void *private, ptl_msg_t *cookie,
             ptl_hdr_t *hdr, int type, ptl_process_id_t tgt, int routing, 
             unsigned int payload_niov, struct iovec *payload_iov,
             size_t payload_offset, size_t payload_len)
{
        return (kibnal_sendmsg(ni, private, cookie,
                               hdr, type, tgt, routing,
                               payload_niov, payload_iov, NULL,
                               payload_offset, payload_len));
}

ptl_err_t
kibnal_send_pages (ptl_ni_t *ni, void *private, ptl_msg_t *cookie, 
                   ptl_hdr_t *hdr, int type, ptl_process_id_t tgt, int routing,
                   unsigned int payload_niov, ptl_kiov_t *payload_kiov, 
                   size_t payload_offset, size_t payload_len)
{
        return (kibnal_sendmsg(ni, private, cookie,
                               hdr, type, tgt, routing,
                               payload_niov, NULL, payload_kiov,
                               payload_offset, payload_len));
}

static ptl_err_t
kibnal_recvmsg (ptl_ni_t *ni, void *private, ptl_msg_t *ptlmsg,
                unsigned int niov, struct iovec *iov, ptl_kiov_t *kiov,
                size_t offset, size_t mlen, size_t rlen)
{
        kib_rx_t    *rx = private;
        kib_msg_t   *rxmsg = rx->rx_msg;
        int          msg_nob;
        
        LASSERT (mlen <= rlen);
        LASSERT (!in_interrupt ());
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));

        switch (rxmsg->ibm_type) {
        default:
                LBUG();
                return (PTL_FAIL);
                
        case IBNAL_MSG_IMMEDIATE:
                msg_nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[rlen]);
                if (msg_nob > IBNAL_MSG_SIZE) {
                        CERROR ("Immediate message from "LPX64" too big: %d\n",
                                rxmsg->ibm_u.immediate.ibim_hdr.src_nid, rlen);
                        return (PTL_FAIL);
                }

                if (kiov != NULL)
                        ptl_copy_buf2kiov(niov, kiov, offset,
                                          rxmsg->ibm_u.immediate.ibim_payload,
                                          mlen);
                else
                        ptl_copy_buf2iov(niov, iov, offset,
                                         rxmsg->ibm_u.immediate.ibim_payload,
                                         mlen);

                ptl_finalize (ni, NULL, ptlmsg, PTL_OK);
                return (PTL_OK);

        case IBNAL_MSG_GET_RDMA:
                /* We get called here just to discard any junk after the
                 * GET hdr. */
                LASSERT (ptlmsg == NULL);
                ptl_finalize (ni, NULL, ptlmsg, PTL_OK);
                return (PTL_OK);

        case IBNAL_MSG_PUT_RDMA:
                kibnal_start_active_rdma (IBNAL_MSG_PUT_DONE, 0,
                                          rx, ptlmsg, 
                                          niov, iov, kiov, offset, mlen);
                return (PTL_OK);
        }
}

ptl_err_t
kibnal_recv (ptl_ni_t *ni, void *private, ptl_msg_t *msg,
             unsigned int niov, struct iovec *iov, 
             size_t offset, size_t mlen, size_t rlen)
{
        return (kibnal_recvmsg (ni, private, msg, niov, iov, NULL,
                                offset, mlen, rlen));
}

ptl_err_t
kibnal_recv_pages (ptl_ni_t *ni, void *private, ptl_msg_t *msg,
                   unsigned int niov, ptl_kiov_t *kiov, 
                   size_t offset, size_t mlen, size_t rlen)
{
        return (kibnal_recvmsg (ni, private, msg, niov, NULL, kiov,
                                offset, mlen, rlen));
}

/*****************************************************************************
 * the rest of this file concerns connection management.  active connetions
 * start with connect_peer, passive connections start with passive_callback.
 * active disconnects start with conn_close, cm_callback starts passive
 * disconnects and contains the guts of how the disconnect state machine
 * progresses. 
 *****************************************************************************/

int
kibnal_thread_start (int (*fn)(void *arg), void *arg)
{
        long    pid = kernel_thread (fn, arg, 0);

        if (pid < 0)
                return ((int)pid);

        atomic_inc (&kibnal_data.kib_nthreads);
        return (0);
}

static void
kibnal_thread_fini (void)
{
        atomic_dec (&kibnal_data.kib_nthreads);
}

/* this can be called by anyone at any time to close a connection.  if
 * the connection is still established it heads to the connd to start
 * the disconnection in a safe context.  It has no effect if called
 * on a connection that is already disconnecting */
void
kibnal_close_conn_locked (kib_conn_t *conn, int error)
{
        /* This just does the immmediate housekeeping, and schedules the
         * connection for the connd to finish off.
         * Caller holds kib_global_lock exclusively in irq context */
        kib_peer_t   *peer = conn->ibc_peer;

        KIB_ASSERT_CONN_STATE_RANGE(conn, IBNAL_CONN_CONNECTING,
                                    IBNAL_CONN_DISCONNECTED);

        if (conn->ibc_state > IBNAL_CONN_ESTABLISHED)
                return; /* already disconnecting */

        CDEBUG (error == 0 ? D_NET : D_ERROR,
                "closing conn to "LPX64": error %d\n", peer->ibp_nid, error);

        if (conn->ibc_state == IBNAL_CONN_ESTABLISHED) {
                /* kib_connd_conns takes ibc_list's ref */
                list_del (&conn->ibc_list);
        } else {
                /* new ref for kib_connd_conns */
                CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                       atomic_read (&conn->ibc_refcount));
                atomic_inc (&conn->ibc_refcount);
        }
        
        if (list_empty (&peer->ibp_conns) &&    /* no more conns */
            peer->ibp_persistence == 0 &&       /* non-persistent peer */
            kibnal_peer_active(peer)) {         /* still in peer table */
                kibnal_unlink_peer_locked (peer);
        }

        conn->ibc_state = IBNAL_CONN_SEND_DREQ;

        spin_lock (&kibnal_data.kib_connd_lock);

        list_add_tail (&conn->ibc_list, &kibnal_data.kib_connd_conns);
        wake_up (&kibnal_data.kib_connd_waitq);
                
        spin_unlock (&kibnal_data.kib_connd_lock);
}

void
kibnal_close_conn (kib_conn_t *conn, int error)
{
        unsigned long     flags;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        kibnal_close_conn_locked (conn, error);
        
        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
}

static void
kibnal_peer_connect_failed (kib_peer_t *peer, int active, int rc)
{
        LIST_HEAD        (zombies);
        kib_tx_t         *tx;
        unsigned long     flags;

        LASSERT (rc != 0);
        LASSERT (peer->ibp_reconnect_interval >= IBNAL_MIN_RECONNECT_INTERVAL);

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        LASSERT (peer->ibp_connecting != 0);
        peer->ibp_connecting--;

        if (peer->ibp_connecting != 0) {
                /* another connection attempt under way (loopback?)... */
                write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
                return;
        }

        if (list_empty(&peer->ibp_conns)) {
                /* Say when active connection can be re-attempted */
                peer->ibp_reconnect_time = jiffies + peer->ibp_reconnect_interval;
                /* Increase reconnection interval */
                peer->ibp_reconnect_interval = MIN (peer->ibp_reconnect_interval * 2,
                                                    IBNAL_MAX_RECONNECT_INTERVAL);
        
                /* Take peer's blocked blocked transmits; I'll complete
                 * them with error */
                while (!list_empty (&peer->ibp_tx_queue)) {
                        tx = list_entry (peer->ibp_tx_queue.next,
                                         kib_tx_t, tx_list);
                        
                        list_del (&tx->tx_list);
                        list_add_tail (&tx->tx_list, &zombies);
                }
                
                if (kibnal_peer_active(peer) &&
                    (peer->ibp_persistence == 0)) {
                        /* failed connection attempt on non-persistent peer */
                        kibnal_unlink_peer_locked (peer);
                }
        } else {
                /* Can't have blocked transmits if there are connections */
                LASSERT (list_empty(&peer->ibp_tx_queue));
        }
        
        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        if (!list_empty (&zombies))
                CERROR ("Deleting messages for "LPX64": connection failed\n",
                        peer->ibp_nid);

        while (!list_empty (&zombies)) {
                tx = list_entry (zombies.next, kib_tx_t, tx_list);

                list_del (&tx->tx_list);
                /* complete now */
                tx->tx_status = -EHOSTUNREACH;
                kibnal_tx_done (tx);
        }
}

static void
kibnal_connreq_done (kib_conn_t *conn, int active, int status)
{
        int               state = conn->ibc_state;
        kib_peer_t       *peer = conn->ibc_peer;
        kib_tx_t         *tx;
        unsigned long     flags;
        int               i;

        /* passive connection has no connreq & vice versa */
        LASSERTF(!active == !(conn->ibc_connreq != NULL),
                 "%d %p\n", active, conn->ibc_connreq);
        if (active) {
                PORTAL_FREE (conn->ibc_connreq, sizeof (*conn->ibc_connreq));
                conn->ibc_connreq = NULL;
        }

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        LASSERT (peer->ibp_connecting != 0);
        
        if (status == 0) {                         
                /* connection established... */
                KIB_ASSERT_CONN_STATE(conn, IBNAL_CONN_CONNECTING);
                conn->ibc_state = IBNAL_CONN_ESTABLISHED;

                if (!kibnal_peer_active(peer)) {
                        /* ...but peer deleted meantime */
                        status = -ECONNABORTED;
                }
        } else {
                KIB_ASSERT_CONN_STATE_RANGE(conn, IBNAL_CONN_INIT_QP,
                                            IBNAL_CONN_CONNECTING);
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
                peer->ibp_reconnect_interval = IBNAL_MIN_RECONNECT_INTERVAL;

                /* post blocked sends to the new connection */
                spin_lock (&conn->ibc_lock);
                
                while (!list_empty (&peer->ibp_tx_queue)) {
                        tx = list_entry (peer->ibp_tx_queue.next, 
                                         kib_tx_t, tx_list);
                        
                        list_del (&tx->tx_list);

                        /* +1 ref for each tx */
                        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                               conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                               atomic_read (&conn->ibc_refcount));
                        atomic_inc (&conn->ibc_refcount);
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
                        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                               conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                               atomic_read (&conn->ibc_refcount));
                        atomic_inc (&conn->ibc_refcount);

                        CDEBUG(D_NET, "RX[%d] %p->%p - "LPX64"\n",
                               i, &conn->ibc_rxs[i], conn->ibc_rxs[i].rx_msg,
                               conn->ibc_rxs[i].rx_vaddr);

                        kibnal_post_rx (&conn->ibc_rxs[i], 0);
                }

                kibnal_check_sends (conn);
                return;
        }

        /* connection failed */
        if (state == IBNAL_CONN_CONNECTING) {
                /* schedule for connd to close */
                kibnal_close_conn_locked (conn, status);
        } else {
                /* Don't have a CM comm_id; just wait for refs to drain */
                conn->ibc_state = IBNAL_CONN_DISCONNECTED;
        } 

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        kibnal_peer_connect_failed (conn->ibc_peer, active, status);

        /* If we didn't establish the connection we don't have to pass
         * through the disconnect protocol before dropping the CM ref */
        if (state < IBNAL_CONN_CONNECTING) 
                kibnal_put_conn (conn);
}

static int
kibnal_accept (kib_conn_t **connp, IB_HANDLE *cep,
                ptl_nid_t nid, __u64 incarnation, int queue_depth)
{
        kib_conn_t    *conn = kibnal_create_conn();
        kib_peer_t    *peer;
        kib_peer_t    *peer2;
        unsigned long  flags;

        if (conn == NULL)
                return (-ENOMEM);

        if (queue_depth != IBNAL_MSG_QUEUE_SIZE) {
                CERROR("Can't accept "LPX64": bad queue depth %d (%d expected)\n",
                       nid, queue_depth, IBNAL_MSG_QUEUE_SIZE);
                atomic_dec (&conn->ibc_refcount);
                kibnal_destroy_conn(conn);
                return (-EPROTO);
        }
        
        /* assume 'nid' is a new peer */
        peer = kibnal_create_peer (nid);
        if (peer == NULL) {
                CDEBUG(D_NET, "--conn[%p] state %d -> "LPX64" (%d)\n",
                       conn, conn->ibc_state, conn->ibc_peer->ibp_nid,
                       atomic_read (&conn->ibc_refcount));
                atomic_dec (&conn->ibc_refcount);
                kibnal_destroy_conn(conn);
                return (-ENOMEM);
        }
        
        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        peer2 = kibnal_find_peer_locked(nid);
        if (peer2 == NULL) {
                /* peer table takes my ref on peer */
                list_add_tail (&peer->ibp_list, kibnal_nid2peerlist(nid));
        } else {
                kib_peer_decref (peer);
                peer = peer2;
        }

        kib_peer_addref(peer); /* +1 ref for conn */
        peer->ibp_connecting++;

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        conn->ibc_peer = peer;
        conn->ibc_state = IBNAL_CONN_CONNECTING;
        /* conn->ibc_cep is set when cm_accept is called */
        conn->ibc_incarnation = incarnation;
        conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;

        *connp = conn;
        return (0);
}

static void kibnal_set_qp_state(IB_HANDLE *qp, IB_QP_STATE state)
{
        IB_QP_ATTRIBUTES_MODIFY modify_attr = {0,};
        FSTATUS frc;

        modify_attr.RequestState = state;

        frc = iibt_qp_modify(qp, &modify_attr, NULL);
        if (frc != FSUCCESS)
                CERROR("couldn't set qp state to %d, error %d\n", state, frc);
}

static void kibnal_flush_pending(kib_conn_t *conn)
{
        LIST_HEAD        (zombies); 
        struct list_head *tmp;
        struct list_head *nxt;
        kib_tx_t         *tx;
        unsigned long     flags;
        int               done;

        /* NB we wait until the connection has closed before completing
         * outstanding passive RDMAs so we can be sure the network can't 
         * touch the mapped memory any more. */
        KIB_ASSERT_CONN_STATE(conn, IBNAL_CONN_DISCONNECTED);

        /* set the QP to the error state so that we get flush callbacks
         * on our posted receives which can then drop their conn refs */
        kibnal_set_qp_state(conn->ibc_qp, QPStateError);

        spin_lock_irqsave (&conn->ibc_lock, flags);

        /* grab passive RDMAs not waiting for the tx callback */
        list_for_each_safe (tmp, nxt, &conn->ibc_active_txs) {
                tx = list_entry (tmp, kib_tx_t, tx_list);

                LASSERT (tx->tx_passive_rdma ||
                         !tx->tx_passive_rdma_wait);

                LASSERT (tx->tx_passive_rdma_wait ||
                         tx->tx_sending != 0);

                /* still waiting for tx callback? */
                if (!tx->tx_passive_rdma_wait)
                        continue;

                tx->tx_status = -ECONNABORTED;
                tx->tx_passive_rdma_wait = 0;
                done = (tx->tx_sending == 0);

                if (!done)
                        continue;

                list_del (&tx->tx_list);
                list_add (&tx->tx_list, &zombies);
        }

        /* grab all blocked transmits */
        list_for_each_safe (tmp, nxt, &conn->ibc_tx_queue) {
                tx = list_entry (tmp, kib_tx_t, tx_list);
                
                list_del (&tx->tx_list);
                list_add (&tx->tx_list, &zombies);
        }
        
        spin_unlock_irqrestore (&conn->ibc_lock, flags);

        while (!list_empty(&zombies)) {
                tx = list_entry (zombies.next, kib_tx_t, tx_list);

                list_del(&tx->tx_list);
                kibnal_tx_done (tx);
        }
}

static void
kibnal_reject (IB_HANDLE cep, uint16_t reason)
{
        CM_REJECT_INFO *rej;

        PORTAL_ALLOC(rej, sizeof(*rej));
        if (rej == NULL) /* PORTAL_ALLOC() will CERROR on failure */
                return;  

        rej->Reason = reason;
        iibt_cm_reject(cep, rej);
        PORTAL_FREE(rej, sizeof(*rej));
}

static FSTATUS
kibnal_qp_rts(IB_HANDLE qp_handle, __u32 qpn, __u8 resp_res, 
              IB_PATH_RECORD *path, __u8 init_depth, __u32 send_psn)
{
        IB_QP_ATTRIBUTES_MODIFY modify_attr;
        FSTATUS frc;
        ENTRY;

        modify_attr = (IB_QP_ATTRIBUTES_MODIFY) {
                .RequestState           = QPStateReadyToRecv,
                .RecvPSN                = IBNAL_STARTING_PSN,
                .DestQPNumber           = qpn,
                .ResponderResources     = resp_res,
                .MinRnrTimer            = UsecToRnrNakTimer(2000), /* 20 ms */
                .Attrs                  = (IB_QP_ATTR_RECVPSN |
                                           IB_QP_ATTR_DESTQPNUMBER | 
                                           IB_QP_ATTR_RESPONDERRESOURCES | 
                                           IB_QP_ATTR_DESTAV | 
                                           IB_QP_ATTR_PATHMTU | 
                                           IB_QP_ATTR_MINRNRTIMER),
        };
        GetAVFromPath(0, path, &modify_attr.PathMTU, NULL, 
                      &modify_attr.DestAV);

        frc = iibt_qp_modify(qp_handle, &modify_attr, NULL);
        if (frc != FSUCCESS) 
                RETURN(frc);

        modify_attr = (IB_QP_ATTRIBUTES_MODIFY) {
                .RequestState           = QPStateReadyToSend,
                .FlowControl            = TRUE,
                .InitiatorDepth         = init_depth,
                .SendPSN                = send_psn,
                .LocalAckTimeout        = path->PktLifeTime + 2, /* 2 or 1? */
                .RetryCount             = IBNAL_RETRY,
                .RnrRetryCount          = IBNAL_RNR_RETRY,
                .Attrs                  = (IB_QP_ATTR_FLOWCONTROL | 
                                           IB_QP_ATTR_INITIATORDEPTH | 
                                           IB_QP_ATTR_SENDPSN | 
                                           IB_QP_ATTR_LOCALACKTIMEOUT | 
                                           IB_QP_ATTR_RETRYCOUNT | 
                                           IB_QP_ATTR_RNRRETRYCOUNT),
        };

        frc = iibt_qp_modify(qp_handle, &modify_attr, NULL);
        RETURN(frc);
}

static void
kibnal_connect_reply (IB_HANDLE cep, CM_CONN_INFO *info, void *arg)
{
        IB_CA_ATTRIBUTES *ca_attr = &kibnal_data.kib_hca_attrs;
        kib_conn_t *conn = arg;
        kib_wire_connreq_t *wcr;
        CM_REPLY_INFO *rep = &info->Info.Reply;
        uint16_t reason;
        FSTATUS frc;

        wcr = (kib_wire_connreq_t *)info->Info.Reply.PrivateData;

        if (wcr->wcr_magic != cpu_to_le32(IBNAL_MSG_MAGIC)) {
                CERROR ("Can't connect "LPX64": bad magic %08x\n",
                        conn->ibc_peer->ibp_nid, le32_to_cpu(wcr->wcr_magic));
                GOTO(reject, reason = RC_USER_REJ);
        }
        
        if (wcr->wcr_version != cpu_to_le16(IBNAL_MSG_VERSION)) {
                CERROR ("Can't connect "LPX64": bad version %d\n",
                        conn->ibc_peer->ibp_nid, le16_to_cpu(wcr->wcr_magic));
                GOTO(reject, reason = RC_USER_REJ);
        }
                        
        if (wcr->wcr_queue_depth != cpu_to_le16(IBNAL_MSG_QUEUE_SIZE)) {
                CERROR ("Can't connect "LPX64": bad queue depth %d\n",
                        conn->ibc_peer->ibp_nid, 
                        le16_to_cpu(wcr->wcr_queue_depth));
                GOTO(reject, reason = RC_USER_REJ);
        }
                        
        if (le64_to_cpu(wcr->wcr_nid) != conn->ibc_peer->ibp_nid) {
                CERROR ("Unexpected NID "LPX64" from "LPX64"\n",
                        le64_to_cpu(wcr->wcr_nid), conn->ibc_peer->ibp_nid);
                GOTO(reject, reason = RC_USER_REJ);
        }

        CDEBUG(D_NET, "Connection %p -> "LPX64" REP_RECEIVED.\n",
               conn, conn->ibc_peer->ibp_nid);

        conn->ibc_incarnation = le64_to_cpu(wcr->wcr_incarnation);
        conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;

        frc = kibnal_qp_rts(conn->ibc_qp, rep->QPN, 
                            min_t(__u8, rep->ArbInitiatorDepth,
                                  ca_attr->MaxQPResponderResources),
                            &conn->ibc_connreq->cr_path, 
                            min_t(__u8, rep->ArbResponderResources,
                                  ca_attr->MaxQPInitiatorDepth),
                            rep->StartingPSN);
        if (frc != FSUCCESS) {
                CERROR("Connection %p -> "LPX64" QP RTS/RTR failed: %d\n",
                       conn, conn->ibc_peer->ibp_nid, frc);
                GOTO(reject, reason = RC_NO_QP);
        }

        /* the callback arguments are ignored for an active accept */
        conn->ibc_connreq->cr_discarded.Status = FSUCCESS;
        frc = iibt_cm_accept(cep, &conn->ibc_connreq->cr_discarded, 
                             NULL, NULL, NULL, NULL);
        if (frc != FCM_CONNECT_ESTABLISHED) {
                CERROR("Connection %p -> "LPX64" CMAccept failed: %d\n",
                       conn, conn->ibc_peer->ibp_nid, frc);
                kibnal_connreq_done (conn, 1, -ECONNABORTED);
                /* XXX don't call reject after accept fails? */
                return;
        }

        CDEBUG(D_NET, "Connection %p -> "LPX64" Established\n",
               conn, conn->ibc_peer->ibp_nid);

        kibnal_connreq_done (conn, 1, 0);
        return;

reject:
        kibnal_reject(cep, reason);
        kibnal_connreq_done (conn, 1, -EPROTO);
}

/* ib_cm.h has a wealth of information on the CM procedures */
static void
kibnal_cm_callback(IB_HANDLE cep, CM_CONN_INFO *info, void *arg)
{
        kib_conn_t       *conn = arg;

        CDEBUG(D_NET, "status 0x%x\n", info->Status);

        /* Established Connection Notifier */
        switch (info->Status) {
        default:
                CERROR("unknown status %d on Connection %p -> "LPX64"\n",
                       info->Status, conn, conn->ibc_peer->ibp_nid);
                LBUG();
                break;

        case FCM_CONNECT_REPLY:
                kibnal_connect_reply(cep, info, arg);
                break;

        case FCM_DISCONNECT_REQUEST:
                /* XXX lock around these state management bits? */
                if (conn->ibc_state == IBNAL_CONN_ESTABLISHED)
                        kibnal_close_conn (conn, 0);
                conn->ibc_state = IBNAL_CONN_DREP;
                iibt_cm_disconnect(conn->ibc_cep, NULL, NULL);
                break;

        /* these both guarantee that no more cm callbacks will occur */
        case FCM_DISCONNECTED: /* aka FCM_DISCONNECT_TIMEOUT */
        case FCM_DISCONNECT_REPLY:
                CDEBUG(D_NET, "Connection %p -> "LPX64" disconnect done.\n",
                       conn, conn->ibc_peer->ibp_nid);

                conn->ibc_state = IBNAL_CONN_DISCONNECTED;
                kibnal_flush_pending(conn);
                kibnal_put_conn(conn);        /* Lose CM's ref */
                break;
        }

        return;
}

static int
kibnal_set_cm_flags(IB_HANDLE cep)
{
        FSTATUS frc;
        uint32 value = 1;

        frc = iibt_cm_modify_cep(cep, CM_FLAG_TIMEWAIT_CALLBACK,
                                 (char *)&value, sizeof(value), 0);
        if (frc != FSUCCESS) {
                CERROR("error setting timeout callback: %d\n", frc);
                return -1;
        }

#if 0
        frc = iibt_cm_modify_cep(cep, CM_FLAG_ASYNC_ACCEPT, (char *)&value,
                                 sizeof(value), 0);
        if (frc != FSUCCESS) {
                CERROR("error setting async accept: %d\n", frc);
                return -1;
        }
#endif

        return 0;
}

void
kibnal_listen_callback(IB_HANDLE cep, CM_CONN_INFO *info, void *arg)
{
        IB_CA_ATTRIBUTES *ca_attr = &kibnal_data.kib_hca_attrs;
        IB_QP_ATTRIBUTES_QUERY *query;
        CM_REQUEST_INFO    *req;
        CM_CONN_INFO       *rep = NULL, *rcv = NULL;
        kib_wire_connreq_t *wcr;
        kib_conn_t         *conn = NULL;
        uint16_t            reason = 0;
        FSTATUS             frc;
        int                 rc = 0;
        
        LASSERT(cep);
        LASSERT(info);
        LASSERT(arg == NULL); /* no conn yet for passive */

        CDEBUG(D_NET, "status 0x%x\n", info->Status);

        req = &info->Info.Request;
        wcr = (kib_wire_connreq_t *)req->PrivateData;

        CDEBUG(D_NET, "%d from "LPX64"\n", info->Status, 
               le64_to_cpu(wcr->wcr_nid));
        
        if (info->Status == FCM_CONNECT_CANCEL)
                return;
        
        LASSERT (info->Status == FCM_CONNECT_REQUEST);
        
        if (wcr->wcr_magic != cpu_to_le32(IBNAL_MSG_MAGIC)) {
                CERROR ("Can't accept: bad magic %08x\n",
                        le32_to_cpu(wcr->wcr_magic));
                GOTO(out, reason = RC_USER_REJ);
        }

        if (wcr->wcr_version != cpu_to_le16(IBNAL_MSG_VERSION)) {
                CERROR ("Can't accept: bad version %d\n",
                        le16_to_cpu(wcr->wcr_magic));
                GOTO(out, reason = RC_USER_REJ);
        }

        rc = kibnal_accept(&conn, cep,
                           le64_to_cpu(wcr->wcr_nid),
                           le64_to_cpu(wcr->wcr_incarnation),
                           le16_to_cpu(wcr->wcr_queue_depth));
        if (rc != 0) {
                CERROR ("Can't accept "LPX64": %d\n",
                        le64_to_cpu(wcr->wcr_nid), rc);
                GOTO(out, reason = RC_NO_RESOURCES);
        }

        frc = kibnal_qp_rts(conn->ibc_qp, req->CEPInfo.QPN,
                            min_t(__u8, req->CEPInfo.OfferedInitiatorDepth, 
                                  ca_attr->MaxQPResponderResources),
                            &req->PathInfo.Path,
                            min_t(__u8, req->CEPInfo.OfferedResponderResources, 
                                  ca_attr->MaxQPInitiatorDepth),
                            req->CEPInfo.StartingPSN);

        if (frc != FSUCCESS) {
                CERROR ("Can't mark QP RTS/RTR  "LPX64": %d\n",
                        le64_to_cpu(wcr->wcr_nid), frc);
                GOTO(out, reason = RC_NO_QP);
        }

        frc = iibt_qp_query(conn->ibc_qp, &conn->ibc_qp_attrs, NULL);
        if (frc != FSUCCESS) {
                CERROR ("Couldn't query qp attributes "LPX64": %d\n",
                        le64_to_cpu(wcr->wcr_nid), frc);
                GOTO(out, reason = RC_NO_QP);
        }
        query = &conn->ibc_qp_attrs;

        PORTAL_ALLOC(rep, sizeof(*rep));
        PORTAL_ALLOC(rcv, sizeof(*rcv));
        if (rep == NULL || rcv == NULL) {
                if (rep) PORTAL_FREE(rep, sizeof(*rep));
                if (rcv) PORTAL_FREE(rcv, sizeof(*rcv));
                CERROR ("can't allocate reply and receive buffers\n");
                GOTO(out, reason = RC_INSUFFICIENT_RESP_RES);
        }

        /* don't try to deref this into the incoming wcr :) */
        wcr = (kib_wire_connreq_t *)rep->Info.Reply.PrivateData;

        rep->Info.Reply = (CM_REPLY_INFO) {
                .QPN = query->QPNumber,
                .QKey = query->Qkey,
                .StartingPSN = query->RecvPSN,
                .EndToEndFlowControl = query->FlowControl,
                /* XXX Hmm. */
                .ArbInitiatorDepth = query->InitiatorDepth,
                .ArbResponderResources = query->ResponderResources,
                .TargetAckDelay = 0,
                .FailoverAccepted = 0,
                .RnRRetryCount = req->CEPInfo.RnrRetryCount,
        };
                
        *wcr = (kib_wire_connreq_t) {
                .wcr_magic       = cpu_to_le32(IBNAL_MSG_MAGIC),
                .wcr_version     = cpu_to_le16(IBNAL_MSG_VERSION),
                .wcr_queue_depth = cpu_to_le32(IBNAL_MSG_QUEUE_SIZE),
                .wcr_nid         = cpu_to_le64(kibnal_data.kib_ni->ni_nid),
                .wcr_incarnation = cpu_to_le64(kibnal_data.kib_incarnation),
        };

        frc = iibt_cm_accept(cep, rep, rcv, kibnal_cm_callback, conn, 
                             &conn->ibc_cep);

        PORTAL_FREE(rep, sizeof(*rep));
        PORTAL_FREE(rcv, sizeof(*rcv));

        if (frc != FCM_CONNECT_ESTABLISHED) {
                /* XXX it seems we don't call reject after this point? */
                CERROR("iibt_cm_accept() failed: %d, aborting\n", frc);
                rc = -ECONNABORTED;
                goto out;
        }

        if (kibnal_set_cm_flags(conn->ibc_cep)) {
                rc = -ECONNABORTED;
                goto out;
        }

        CDEBUG(D_WARNING, "Connection %p -> "LPX64" ESTABLISHED.\n",
               conn, conn->ibc_peer->ibp_nid);

out:
        if (reason) {
                kibnal_reject(cep, reason);
                rc = -ECONNABORTED;
        }
        if (conn != NULL) 
                kibnal_connreq_done(conn, 0, rc);

        return;
}

static void
dump_path_records(PATH_RESULTS *results)
{
        IB_PATH_RECORD *path;
        int i;

        for(i = 0; i < results->NumPathRecords; i++) {
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

static void
kibnal_pathreq_callback (void *arg, QUERY *query, 
                         QUERY_RESULT_VALUES *query_res)
{
        IB_CA_ATTRIBUTES *ca_attr = &kibnal_data.kib_hca_attrs;
        kib_conn_t *conn = arg;
        PATH_RESULTS *path;
        FSTATUS frc;
        
        if (query_res->Status != FSUCCESS || query_res->ResultDataSize == 0) {
                CERROR ("status %d data size %d\n", query_res->Status,
                        query_res->ResultDataSize);
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }

        path = (PATH_RESULTS *)query_res->QueryResult;

        if (path->NumPathRecords < 1) {
                CERROR ("expected path records: %d\n", path->NumPathRecords);
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }

        dump_path_records(path);

        /* just using the first.  this is probably a horrible idea. */
        conn->ibc_connreq->cr_path = path->PathRecords[0];

        conn->ibc_cep = iibt_cm_create_cep(CM_RC_TYPE);
        if (conn->ibc_cep == NULL) {
                CERROR ("Can't create CEP\n");
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }

        if (kibnal_set_cm_flags(conn->ibc_cep)) {
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }

        conn->ibc_connreq->cr_wcr = (kib_wire_connreq_t) {
                .wcr_magic       = cpu_to_le32(IBNAL_MSG_MAGIC),
                .wcr_version     = cpu_to_le16(IBNAL_MSG_VERSION),
                .wcr_queue_depth = cpu_to_le16(IBNAL_MSG_QUEUE_SIZE),
                .wcr_nid         = cpu_to_le64(kibnal_data.kib_ni->ni_nid),
                .wcr_incarnation = cpu_to_le64(kibnal_data.kib_incarnation),
        };

        conn->ibc_connreq->cr_cmreq = (CM_REQUEST_INFO) {
                .SID = conn->ibc_connreq->cr_service.RID.ServiceID,
                .CEPInfo = (CM_CEP_INFO) { 
                        .CaGUID = kibnal_data.kib_hca_guids[0],
                        .EndToEndFlowControl = FALSE,
                        .PortGUID = conn->ibc_connreq->cr_path.SGID.Type.Global.InterfaceID,
                        .RetryCount = IBNAL_RETRY,
                        .RnrRetryCount = IBNAL_RNR_RETRY,
                        .AckTimeout = IBNAL_ACK_TIMEOUT,
                        .StartingPSN = IBNAL_STARTING_PSN,
                        .QPN = conn->ibc_qp_attrs.QPNumber,
                        .QKey = conn->ibc_qp_attrs.Qkey,
                        .OfferedResponderResources = ca_attr->MaxQPResponderResources,
                        .OfferedInitiatorDepth = ca_attr->MaxQPInitiatorDepth,
                },
                .PathInfo = (CM_CEP_PATHINFO) {
                        .bSubnetLocal = TRUE,
                        .Path = conn->ibc_connreq->cr_path,
                },
        };

#if 0
        /* XXX set timeout just like SDP!!!*/
        conn->ibc_connreq->cr_path.packet_life = 13;
#endif
        /* Flag I'm getting involved with the CM... */
        conn->ibc_state = IBNAL_CONN_CONNECTING;

        CDEBUG(D_NET, "Connecting to, service id "LPX64", on "LPX64"\n",
               conn->ibc_connreq->cr_service.RID.ServiceID, 
               *kibnal_service_nid_field(&conn->ibc_connreq->cr_service));

        memset(conn->ibc_connreq->cr_cmreq.PrivateData, 0, 
               CM_REQUEST_INFO_USER_LEN);
        memcpy(conn->ibc_connreq->cr_cmreq.PrivateData, 
               &conn->ibc_connreq->cr_wcr, sizeof(conn->ibc_connreq->cr_wcr));

        /* kibnal_cm_callback gets my conn ref */
        frc = iibt_cm_connect(conn->ibc_cep, &conn->ibc_connreq->cr_cmreq,
                              kibnal_cm_callback, conn);
        if (frc != FPENDING && frc != FSUCCESS) {
                CERROR ("Connect: %d\n", frc);
                /* Back out state change as connect failed */
                conn->ibc_state = IBNAL_CONN_INIT_QP;
                kibnal_connreq_done (conn, 1, -EINVAL);
        }
}

static void
dump_service_records(SERVICE_RECORD_RESULTS *results)
{
        IB_SERVICE_RECORD *svc;
        int i;

        for(i = 0; i < results->NumServiceRecords; i++) {
                svc = &results->ServiceRecords[i];
                CDEBUG(D_NET, "%d: sid "LPX64" gid "LPX64":"LPX64" pkey %x\n",
                       i,
                       svc->RID.ServiceID,
                       svc->RID.ServiceGID.Type.Global.SubnetPrefix,
                       svc->RID.ServiceGID.Type.Global.InterfaceID,
                       svc->RID.ServiceP_Key);
        }
}


static void
kibnal_service_get_callback (void *arg, QUERY *query, 
                             QUERY_RESULT_VALUES *query_res)
{
        kib_conn_t *conn = arg;
        SERVICE_RECORD_RESULTS *svc;
        COMMAND_CONTROL_PARAMETERS sd_params;
        QUERY   path_query;
        FSTATUS frc;
        
        if (query_res->Status != FSUCCESS || query_res->ResultDataSize == 0) {
                CERROR ("status %d data size %d\n", query_res->Status,
                        query_res->ResultDataSize);
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }

        svc = (SERVICE_RECORD_RESULTS *)query_res->QueryResult;

        if (svc->NumServiceRecords < 1) {
                CERROR ("%d service records\n", svc->NumServiceRecords);
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }

        dump_service_records(svc);

        conn->ibc_connreq->cr_service = svc->ServiceRecords[0];

        CDEBUG(D_NET, "Got status %d, service id "LPX64", on "LPX64"\n",
               query_res->Status , conn->ibc_connreq->cr_service.RID.ServiceID, 
               *kibnal_service_nid_field(&conn->ibc_connreq->cr_service));

        memset(&path_query, 0, sizeof(path_query));
        path_query.InputType = InputTypePortGuidPair;
        path_query.OutputType = OutputTypePathRecord;
        path_query.InputValue.PortGuidPair.SourcePortGuid = kibnal_data.kib_port_guid;
        path_query.InputValue.PortGuidPair.DestPortGuid  = conn->ibc_connreq->cr_service.RID.ServiceGID.Type.Global.InterfaceID;

        memset(&sd_params, 0, sizeof(sd_params));
        sd_params.RetryCount = IBNAL_RETRY;
        sd_params.Timeout = 10 * 1000;   /* wait 10 seconds */

        /* kibnal_service_get_callback gets my conn ref */

        frc = iibt_sd_query_port_fabric_information(kibnal_data.kib_sd,
                                                    kibnal_data.kib_port_guid,
                                                    &path_query, 
                                                    kibnal_pathreq_callback,
                                                    &sd_params, conn);
        if (frc == FPENDING)
                return;

        CERROR ("Path record request failed: %d\n", frc);
        kibnal_connreq_done (conn, 1, -EINVAL);
}

static void
kibnal_connect_peer (kib_peer_t *peer)
{
        COMMAND_CONTROL_PARAMETERS sd_params;
        QUERY   query;
        FSTATUS frc;
        kib_conn_t  *conn = kibnal_create_conn();

        LASSERT (peer->ibp_connecting != 0);

        if (conn == NULL) {
                CERROR ("Can't allocate conn\n");
                kibnal_peer_connect_failed (peer, 1, -ENOMEM);
                return;
        }

        conn->ibc_peer = peer;
        kib_peer_addref(peer);

        PORTAL_ALLOC (conn->ibc_connreq, sizeof (*conn->ibc_connreq));
        if (conn->ibc_connreq == NULL) {
                CERROR ("Can't allocate connreq\n");
                kibnal_connreq_done (conn, 1, -ENOMEM);
                return;
        }

        memset(conn->ibc_connreq, 0, sizeof (*conn->ibc_connreq));

        kibnal_set_service_keys(&conn->ibc_connreq->cr_service, peer->ibp_nid);

        memset(&query, 0, sizeof(query));
        query.InputType = InputTypeServiceRecord;
        query.OutputType = OutputTypeServiceRecord;
        query.InputValue.ServiceRecordValue.ServiceRecord = conn->ibc_connreq->cr_service;
        query.InputValue.ServiceRecordValue.ComponentMask = KIBNAL_SERVICE_KEY_MASK;

        memset(&sd_params, 0, sizeof(sd_params));
        sd_params.RetryCount = IBNAL_RETRY;
        sd_params.Timeout = 10 * 1000;   /* wait 10 seconds */

        /* kibnal_service_get_callback gets my conn ref */
        frc = iibt_sd_query_port_fabric_information(kibnal_data.kib_sd,
                                                    kibnal_data.kib_port_guid,
                                                    &query, 
                                                kibnal_service_get_callback, 
                                                    &sd_params, conn);
        if (frc == FPENDING)
                return;

        CERROR ("iibt_sd_query_port_fabric_information(): %d\n", frc);
        kibnal_connreq_done (conn, 1, frc);
}

static int
kibnal_conn_timed_out (kib_conn_t *conn)
{
        kib_tx_t          *tx;
        struct list_head  *ttmp;
        unsigned long      flags;

        spin_lock_irqsave (&conn->ibc_lock, flags);

        list_for_each (ttmp, &conn->ibc_tx_queue) {
                tx = list_entry (ttmp, kib_tx_t, tx_list);

                LASSERT (!tx->tx_passive_rdma_wait);
                LASSERT (tx->tx_sending == 0);

                if (time_after_eq (jiffies, tx->tx_deadline)) {
                        spin_unlock_irqrestore (&conn->ibc_lock, flags);
                        return 1;
                }
        }

        list_for_each (ttmp, &conn->ibc_active_txs) {
                tx = list_entry (ttmp, kib_tx_t, tx_list);

                LASSERT (tx->tx_passive_rdma ||
                         !tx->tx_passive_rdma_wait);

                LASSERT (tx->tx_passive_rdma_wait ||
                         tx->tx_sending != 0);

                if (time_after_eq (jiffies, tx->tx_deadline)) {
                        spin_unlock_irqrestore (&conn->ibc_lock, flags);
                        return 1;
                }
        }

        spin_unlock_irqrestore (&conn->ibc_lock, flags);

        return 0;
}

static void
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

                        KIB_ASSERT_CONN_STATE(conn, IBNAL_CONN_ESTABLISHED);

                        /* In case we have enough credits to return via a
                         * NOOP, but there were no non-blocking tx descs
                         * free to do it last time... */
                        kibnal_check_sends(conn);

                        if (!kibnal_conn_timed_out(conn))
                                continue;
                        
                        CDEBUG(D_NET, "++conn[%p] state %d -> "LPX64" (%d)\n",
                               conn, conn->ibc_state, peer->ibp_nid,
                               atomic_read (&conn->ibc_refcount));

                        atomic_inc (&conn->ibc_refcount);
                        read_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                               flags);

                        CERROR("Timed out RDMA with "LPX64"\n",
                               peer->ibp_nid);

                        kibnal_close_conn (conn, -ETIMEDOUT);
                        kibnal_put_conn (conn);

                        /* start again now I've dropped the lock */
                        goto again;
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
}

static void
kib_connd_handle_state(kib_conn_t *conn)
{
        FSTATUS frc;

        switch (conn->ibc_state) {
                /* all refs have gone, free and be done with it */ 
                case IBNAL_CONN_DISCONNECTED:
                        kibnal_destroy_conn (conn);
                        return; /* avoid put_conn */

                case IBNAL_CONN_SEND_DREQ:
                        frc = iibt_cm_disconnect(conn->ibc_cep, NULL, NULL);
                        if (frc != FSUCCESS) /* XXX do real things */
                                CERROR("disconnect failed: %d\n", frc);
                        conn->ibc_state = IBNAL_CONN_DREQ;
                        break;

                /* a callback got to the conn before we did */ 
                case IBNAL_CONN_DREP:
                        break;
                                
                default:
                        CERROR ("Bad conn %p state: %d\n", conn, 
                                conn->ibc_state);
                        LBUG();
                        break;
        }

        /* drop ref from close_conn */
        kibnal_put_conn(conn);
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
        int                peer_index = 0;
        unsigned long      deadline = jiffies;
        
        kportal_daemonize ("kibnal_connd");
        kportal_blockallsigs ();

        init_waitqueue_entry (&wait, current);

        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);

        for (;;) {
                if (!list_empty (&kibnal_data.kib_connd_conns)) {
                        conn = list_entry (kibnal_data.kib_connd_conns.next,
                                           kib_conn_t, ibc_list);
                        list_del (&conn->ibc_list);
                        
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);
                        kib_connd_handle_state(conn);

                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                        continue;
                }

                if (!list_empty (&kibnal_data.kib_connd_peers)) {
                        peer = list_entry (kibnal_data.kib_connd_peers.next,
                                           kib_peer_t, ibp_connd_list);
                        
                        list_del_init (&peer->ibp_connd_list);
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

                        kibnal_connect_peer (peer);
                        kib_peer_decref (peer);

                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                }

                /* shut down and nobody left to reap... */
                if (kibnal_data.kib_shutdown &&
                    atomic_read(&kibnal_data.kib_nconns) == 0)
                        break;

                spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

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

                        if (kibnal_tunables.kib_io_timeout > n * p)
                                chunk = (chunk * n * p) / 
                                        kibnal_tunables.kib_io_timeout;
                        if (chunk == 0)
                                chunk = 1;

                        for (i = 0; i < chunk; i++) {
                                kibnal_check_conns (peer_index);
                                peer_index = (peer_index + 1) % 
                                             kibnal_data.kib_peer_hash_size;
                        }

                        deadline += p * HZ;
                }

                kibnal_data.kib_connd_waketime = jiffies + timeout;

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
        kportal_daemonize(name);
        kportal_blockallsigs();

        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);

        for (;;) {
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

                /* shut down and no receives to complete... */
                if (kibnal_data.kib_shutdown &&
                    atomic_read(&kibnal_data.kib_nconns) == 0)
                        break;

                /* nothing to do or hogging CPU */
                if (!did_something || counter++ == IBNAL_RESCHED) {
                        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock,
                                               flags);
                        counter = 0;

                        if (!did_something) {
                                rc = wait_event_interruptible(
                                        kibnal_data.kib_sched_waitq,
                                        !list_empty(&kibnal_data.kib_sched_txq) || 
                                        !list_empty(&kibnal_data.kib_sched_rxq) || 
                                        (kibnal_data.kib_shutdown &&
                                         atomic_read (&kibnal_data.kib_nconns) == 0));
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
