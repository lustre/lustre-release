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

static void kibnal_cm_callback(cm_cep_handle_t cep, cm_conn_data_t *info, void *arg);

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
        vv_return_t retval;

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
                retval = vv_mem_region_destroy(kibnal_data.kib_hca, tx->tx_md.md_handle);
                LASSERT (retval == vv_return_ok);
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
                /* tx may have up to 2 libmsgs to finalise */
                if (tx->tx_libmsg[i] == NULL)
                        continue;

                lib_finalize (&kibnal_lib, NULL, tx->tx_libmsg[i], ptlrc);
                tx->tx_libmsg[i] = NULL;
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
                LASSERT (tx->tx_libmsg[0] == NULL);
                LASSERT (tx->tx_libmsg[1] == NULL);
        }

        spin_unlock_irqrestore (&kibnal_data.kib_tx_lock, flags);
        
        RETURN(tx);
}

static int
kibnal_dist(lib_nal_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        /* I would guess that if kibnal_get_peer (nid) == NULL,
           and we're not routing, then 'nid' is very distant :) */
        if ( nal->libnal_ni.ni_pid.nid == nid ) {
                *dist = 0;
        } else {
                *dist = 1;
        }

        return 0;
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

static void
kibnal_post_rx (kib_rx_t *rx, int do_credits)
{
        kib_conn_t   *conn = rx->rx_conn;
        int           rc = 0;
        unsigned long flags;
        vv_return_t retval;

        ENTRY;
        
        rx->rx_gl = (vv_scatgat_t) {
                .v_address = (void *)rx->rx_msg,
                .length    = IBNAL_MSG_SIZE,
                .l_key     = rx->l_key,
        };

        rx->rx_wrq = (vv_wr_t) {
                .wr_id                   = kibnal_ptr2wreqid(rx, 1),
                .completion_notification = 1,
                .scatgat_list            = &rx->rx_gl,
                .num_of_data_segments    = 1,
                .wr_type                 = vv_wr_receive,
        };

        KIB_ASSERT_CONN_STATE_RANGE(conn, IBNAL_CONN_ESTABLISHED,
                                    IBNAL_CONN_DREP);
        LASSERT (!rx->rx_posted);
        rx->rx_posted = 1;
        mb();

        if (conn->ibc_state != IBNAL_CONN_ESTABLISHED)
                rc = -ECONNABORTED;
        else {
                retval = vv_post_receive(kibnal_data.kib_hca, conn->ibc_qp, &rx->rx_wrq);

                if (retval) {
                        CDEBUG(D_NET, "post failed %d\n", retval);
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

static void
kibnal_rx_callback (vv_wc_t *wc)
{
        kib_rx_t     *rx = (kib_rx_t *)kibnal_wreqid2ptr(wc->wr_id);
        kib_msg_t    *msg = rx->rx_msg;
        kib_conn_t   *conn = rx->rx_conn;
        int           nob = wc->num_bytes_transfered;
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

        CDEBUG(D_NET, "rx %p conn %p, nob=%d\n", rx, conn, nob);

        LASSERT (rx->rx_posted);
        rx->rx_posted = 0;
        mb();

        /* receives complete with error in any case after we've started
         * disconnecting */
        if (conn->ibc_state > IBNAL_CONN_ESTABLISHED)
                goto failed;

        if (wc->completion_status != vv_comp_status_success) {
                CERROR("Rx from "LPX64" failed: %d\n", 
                       conn->ibc_peer->ibp_nid, wc->completion_status);
                goto failed;
        }

        if (nob < base_nob) {
                CERROR ("Short rx from "LPX64": %d < expected %d\n",
                        conn->ibc_peer->ibp_nid, nob, base_nob);
                goto failed;
        }

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

static void
kibnal_rx (kib_rx_t *rx)
{
        kib_msg_t   *msg = rx->rx_msg;

        /* Clear flag so I can detect if I've sent an RDMA completion */
        rx->rx_rdma = 0;

        switch (msg->ibm_type) {
        case IBNAL_MSG_GET_RDMA:
                lib_parse(&kibnal_lib, &msg->ibm_u.rdma.ibrm_hdr, rx);
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
                lib_parse(&kibnal_lib, &msg->ibm_u.rdma.ibrm_hdr, rx);
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

        case IBNAL_MSG_IMMEDIATE:
                lib_parse(&kibnal_lib, &msg->ibm_u.immediate.ibim_hdr, rx);
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
        vv_l_key_t l_key;
        vv_r_key_t r_key;
        void *addr;
        vv_mem_reg_h_t mem_h;
        vv_return_t retval;

        LASSERTF(ibrm->ibrm_num_descs < PTL_MD_MAX_IOV, "%u\n", 
                 ibrm->ibrm_num_descs);

        desc = &ibrm->ibrm_desc[ibrm->ibrm_num_descs];

        addr = page_address(page) + page_offset;

        /* TODO: This next step is only needed to get either the lkey
         * or the rkey. However they should be the same than for the
         * tx buffer, so we might as well use it. */
        retval = vv_get_gen_mr_attrib(kibnal_data.kib_hca,
                                      addr,
                                      len,
                                      &mem_h,
                                      &l_key,
                                      &r_key);
        if (retval) {
                CERROR("vv_get_gen_mr_attrib failed: %d", retval);
                /* TODO: this shouldn't really fail, but what if? */
                return;
        }

        if (active) {
                ibrm->rd_key = l_key;
        } else {
                ibrm->rd_key = r_key;

                vv_va2advertise_addr(kibnal_data.kib_hca, addr, &addr);
        }

        desc->rd_addr = (__u64)(unsigned long)addr;
        desc->rd_nob = len; /*PAGE_SIZE - kiov->kiov_offset; */

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
kibnal_map_iov (kib_tx_t *tx, vv_access_con_bit_mask_t access,
                 int niov, struct iovec *iov, int offset, int nob, int active)
                 
{
        void   *vaddr;
        vv_return_t retval;

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

        retval = vv_mem_region_register(kibnal_data.kib_hca, vaddr, nob,
                                   kibnal_data.kib_pd, access,
                                   &tx->tx_md.md_handle, &tx->tx_md.md_lkey,
                                   &tx->tx_md.md_rkey);
        if (retval != 0) {
                CERROR ("Can't map vaddr %p: %d\n", vaddr, retval);
                return -EINVAL;
        }

        tx->tx_mapped = KIB_TX_MAPPED;
        return (0);
}

static int
kibnal_map_kiov (kib_tx_t *tx, vv_access_con_bit_mask_t access,
                  int nkiov, ptl_kiov_t *kiov,
                  int offset, int nob, int active)
{
        vv_phy_list_t  phys_pages;
        vv_phy_buf_t  *phys_buf = NULL;
        int            page_offset;
        int            nphys;
        int            resid;
        int            phys_size = 0;
        int            i, rc = 0;
        vv_return_t    retval;

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
                phys_size = nkiov * sizeof(vv_phy_buf_t);
                PORTAL_ALLOC(phys_buf, phys_size);

                if (phys_buf == NULL) {
                        CERROR ("Can't allocate phys_buf\n");
                        return (-ENOMEM);
                }

                phys_buf[0].start = kibnal_page2phys(kiov->kiov_page);
                phys_buf[0].size = PAGE_SIZE;

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
                        LASSERT (nphys * sizeof (vv_phy_buf_t) < phys_size);
                        phys_buf[nphys].start = kibnal_page2phys(kiov->kiov_page);
                        phys_buf[nphys].size = PAGE_SIZE;

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
#error "vibnal hasn't learned about FMR yet"
        rc = ib_fmr_register_physical (kibnal_data.kib_fmr_pool,
                                       phys_pages, nphys,
                                       &tx->tx_md.md_addr,
                                       page_offset,
                                       &tx->tx_md.md_handle.fmr,
                                       &tx->tx_md.md_lkey,
                                       &tx->tx_md.md_rkey);
#else
        retval = vv_phy_mem_region_register(kibnal_data.kib_hca,
                                            &phys_pages,
                                            IBNAL_RDMA_BASE,
                                            nphys,
                                            0,          /* offset */
                                            kibnal_data.kib_pd,
                                            vv_acc_l_mem_write | vv_acc_r_mem_write | vv_acc_r_mem_read | vv_acc_mem_bind, /* TODO: translated as-is, but seems incorrect or too much */
                                            &tx->tx_md.md_handle,
                                            &tx->tx_md.md_addr,
                                            &tx->tx_md.md_lkey,
                                            &tx->tx_md.md_rkey);
#endif
        if (retval == vv_return_ok) {
                CDEBUG(D_NET, "Mapped %d pages %d bytes @ offset %d: lkey %x, rkey %x\n",
                       nphys, nob, page_offset, tx->tx_md.md_lkey, tx->tx_md.md_rkey);
#if IBNAL_FMR
                tx->tx_mapped = KIB_TX_MAPPED_FMR;
#else
                tx->tx_mapped = KIB_TX_MAPPED;
#endif
        } else {
                CERROR ("Can't map phys_pages: %d\n", retval);
                rc = -EFAULT;
        }

 out:
        if (phys_buf != NULL)
                PORTAL_FREE(phys_buf, phys_size);

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
                tx->tx_sending = 0;
                tx->tx_passive_rdma_wait = tx->tx_passive_rdma;
                list_add (&tx->tx_list, &conn->ibc_active_txs);
#if IBNAL_CKSUM
                tx->tx_msg->ibm_cksum = 0;
                tx->tx_msg->ibm_cksum = kibnal_cksum(tx->tx_msg, tx->tx_msg->ibm_nob);
                CDEBUG(D_NET, "cksum %x, nob %d\n", tx->tx_msg->ibm_cksum, tx->tx_msg->ibm_nob);
#endif
                /* NB the gap between removing tx from the queue and sending it
                 * allows message re-ordering to occur */

                LASSERT (tx->tx_nsp > 0);

                rc = -ECONNABORTED;
                nwork = 0;
                if (conn->ibc_state == IBNAL_CONN_ESTABLISHED) {
                        vv_return_t retval;                        

                        tx->tx_status = 0;
                        rc = 0;

                        retval = vv_post_send_list(kibnal_data.kib_hca, conn->ibc_qp, tx->tx_nsp, tx->tx_wrq, vv_operation_type_send_rc);

                        if (retval != 0) {
                                CERROR("post send failed with %d\n", retval);
                                rc = -ECONNABORTED;
                                break;
                        }
                        
                        tx->tx_sending = tx->tx_nsp;
                }

                if (rc != 0) {
                        /* NB credits are transferred in the actual
                         * message, which can only be the last work item */
                        conn->ibc_outstanding_credits += tx->tx_msg->ibm_credits;
                        conn->ibc_credits++;
                        conn->ibc_nsends_posted--;

                        tx->tx_status = rc;
                        tx->tx_passive_rdma_wait = 0;

                        /* TODO: I think this is buggy if vv_post_send_list failed. */
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
kibnal_tx_callback (vv_wc_t *wc)
{
        kib_tx_t     *tx = (kib_tx_t *)kibnal_wreqid2ptr(wc->wr_id);
        kib_conn_t   *conn;
        unsigned long flags;
        int           idle;

        conn = tx->tx_conn;
        LASSERT (conn != NULL);
        LASSERT (tx->tx_sending != 0);

        CDEBUG(D_NET, "conn %p tx %p [%d/%d]: %d\n", conn, tx,
               tx->tx_sending, tx->tx_nsp, wc->completion_status);

        spin_lock_irqsave(&conn->ibc_lock, flags);

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

        if (wc->completion_status != vv_comp_status_success &&
            tx->tx_status == 0)
                tx->tx_status = -ECONNABORTED;

        spin_unlock_irqrestore(&conn->ibc_lock, flags);

        if (idle)
                kibnal_tx_done (tx);

        if (wc->completion_status != vv_comp_status_success) {
                CERROR ("Tx completion to "LPX64" failed: %d\n", 
                        conn->ibc_peer->ibp_nid, wc->completion_status);
                kibnal_close_conn (conn, -ENETDOWN);
        } else {
                /* can I shovel some more sends out the door? */
                kibnal_check_sends(conn);
        }

        kibnal_put_conn (conn);
}

void 
kibnal_ca_async_callback(vv_event_record_t ev)
{
        /* XXX flesh out.  this seems largely for async errors */
        CERROR("type: %d, port: %d, data: "LPX64"\n", ev.event_type, ev.port_num, ev.type.data);
}

void
kibnal_ca_callback (unsigned long unused_context)
{
        vv_wc_t wc;
        int armed = 0;
        vv_return_t retval;

        for(;;) {

                while (vv_poll_for_completion(kibnal_data.kib_hca, kibnal_data.kib_cq, &wc) == vv_return_ok) {

                        /* We will need to rearm the CQ to avoid a potential race. */
                        armed = 0;

                        if (kibnal_wreqid_is_rx(wc.wr_id))
                                kibnal_rx_callback(&wc);
                        else
                                kibnal_tx_callback(&wc);
                }

                if (armed)
                        return;
                
                retval = vv_request_completion_notification(kibnal_data.kib_hca, kibnal_data.kib_cq, vv_next_solicit_unsolicit_event);
                if (retval != 0) {
                        CERROR ("Failed to re-arm completion queue: %d\n", retval);
                        return;
                }

                armed = 1;
        }
}

void
kibnal_init_tx_msg (kib_tx_t *tx, int type, int body_nob)
{
        vv_scatgat_t *gl = &tx->tx_gl[tx->tx_nsp];
        vv_wr_t      *wrq = &tx->tx_wrq[tx->tx_nsp];
        int           fence;
        int           nob = offsetof (kib_msg_t, ibm_u) + body_nob;

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

        *gl = (vv_scatgat_t) {
                .v_address = (void *)tx->tx_msg,
                .length    = nob,
                .l_key     = tx->l_key,
        };

        wrq->wr_id =  kibnal_ptr2wreqid(tx, 0);
        wrq->completion_notification = 1;
        wrq->scatgat_list = gl;
        wrq->num_of_data_segments = 1;
        wrq->wr_type = vv_wr_send;

        wrq->type.send.solicited_event = 1;

        wrq->type.send.send_qp_type.rc_type.fance_indicator = fence;

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
                            lib_msg_t *libmsg, ptl_hdr_t *hdr)
{
        int         nob = libmsg->md->length;
        kib_tx_t   *tx;
        kib_msg_t  *ibmsg;
        int         rc;
        vv_access_con_bit_mask_t access;
        
        LASSERT (type == IBNAL_MSG_PUT_RDMA || type == IBNAL_MSG_GET_RDMA);
        LASSERT (nob > 0);
        LASSERT (!in_interrupt());              /* Mapping could block */

        access = vv_acc_l_mem_write | vv_acc_r_mem_write | vv_acc_r_mem_read | vv_acc_mem_bind;

        tx = kibnal_get_idle_tx (1);           /* May block; caller is an app thread */
        LASSERT (tx != NULL);

        if ((libmsg->md->options & PTL_MD_KIOV) == 0) 
                rc = kibnal_map_iov (tx, access,
                                     libmsg->md->md_niov,
                                     libmsg->md->md_iov.iov,
                                     0, nob, 0);
        else
                rc = kibnal_map_kiov (tx, access,
                                      libmsg->md->md_niov, 
                                      libmsg->md->md_iov.kiov,
                                      0, nob, 0);

        if (rc != 0) {
                CERROR ("Can't map RDMA for "LPX64": %d\n", nid, rc);
                goto failed;
        }
        
        if (type == IBNAL_MSG_GET_RDMA) {
                /* reply gets finalized when tx completes */
                tx->tx_libmsg[1] = lib_create_reply_msg(&kibnal_lib, 
                                                        nid, libmsg);
                if (tx->tx_libmsg[1] == NULL) {
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
        
        /* libmsg gets finalized when tx completes. */
        tx->tx_libmsg[0] = libmsg;

        kibnal_launch_tx(tx, nid);
        return (PTL_OK);

 failed:
        tx->tx_status = rc;
        kibnal_tx_done (tx);
        return (PTL_FAIL);
}

void
kibnal_start_active_rdma (int type, int status,
                           kib_rx_t *rx, lib_msg_t *libmsg, 
                           unsigned int niov,
                           struct iovec *iov, ptl_kiov_t *kiov,
                           size_t offset, size_t nob)
{
        kib_msg_t    *rxmsg = rx->rx_msg;
        kib_msg_t    *txmsg;
        kib_tx_t     *tx;
        vv_access_con_bit_mask_t access;
        vv_wr_operation_t rdma_op;
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
                access = 0;
                rdma_op  = vv_wr_rdma_write;
                LASSERT (rxmsg->ibm_type == IBNAL_MSG_GET_RDMA);
        } else {
                access = vv_acc_l_mem_write;
                rdma_op  = vv_wr_rdma_read;
                LASSERT (rxmsg->ibm_type == IBNAL_MSG_PUT_RDMA);
        }

        tx = kibnal_get_idle_tx (0);           /* Mustn't block */
        if (tx == NULL) {
                CERROR ("tx descs exhausted on RDMA from "LPX64
                        " completing locally with failure\n",
                        rx->rx_conn->ibc_peer->ibp_nid);
                lib_finalize (&kibnal_lib, NULL, libmsg, PTL_NO_SPACE);
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
                vv_scatgat_t *ds = &tx->tx_gl[i];
                vv_wr_t *wrq = &tx->tx_wrq[i];

                ldesc = &tx->tx_msg->ibm_u.rdma.ibrm_desc[i];
                rdesc = &rxmsg->ibm_u.rdma.ibrm_desc[i];

                ds->v_address = (void *)(unsigned long)ldesc->rd_addr;
                ds->length    = ldesc->rd_nob;
                ds->l_key     = tx->tx_msg->ibm_u.rdma.rd_key;

                wrq->wr_id = kibnal_ptr2wreqid(tx, 0);

#if 0
                /* only the last rdma post triggers tx completion */
                if (i == rxmsg->ibm_u.rdma.ibrm_num_descs - 1)
                        wrq->completion_notification = 1;
                else
                        wrq->completion_notification = 0;

#else
                /* TODO: hack. Right now complete everything, else the
                 * driver will deadlock. This is less efficient than
                 * requestion a notification for only a few of the
                 * WQE. */
                wrq->completion_notification = 1;
#endif

                wrq->scatgat_list = ds;
                wrq->num_of_data_segments = 1;
                wrq->wr_type = rdma_op;

                wrq->type.send.solicited_event = 0;

                wrq->type.send.send_qp_type.rc_type.fance_indicator = 0;
                wrq->type.send.send_qp_type.rc_type.r_addr = rdesc->rd_addr;
                wrq->type.send.send_qp_type.rc_type.r_r_key = rxmsg->ibm_u.rdma.rd_key;

                CDEBUG(D_NET, "prepared RDMA with r_addr=%llx r_key=%x\n",
                       wrq->type.send.send_qp_type.rc_type.r_addr,
                       wrq->type.send.send_qp_type.rc_type.r_r_key);

                tx->tx_nsp++;
        }

init_tx:
        txmsg = tx->tx_msg;

        txmsg->ibm_u.completion.ibcm_cookie = rxmsg->ibm_u.rdma.ibrm_cookie;
        txmsg->ibm_u.completion.ibcm_status = status;
        
        kibnal_init_tx_msg(tx, type, sizeof (kib_completion_msg_t));

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
                lib_finalize (&kibnal_lib, NULL, libmsg,
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
kibnal_sendmsg(lib_nal_t    *nal, 
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
        kib_msg_t  *ibmsg;
        kib_tx_t   *tx;
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
                kib_rx_t *rx = private;

                /* RDMA reply expected? */
                if (rx->rx_msg->ibm_type == IBNAL_MSG_GET_RDMA) {
                        kibnal_start_active_rdma(IBNAL_MSG_GET_DONE, 0,
                                                 rx, libmsg, payload_niov, 
                                                 payload_iov, payload_kiov,
                                                 payload_offset, payload_nob);
                        return (PTL_OK);
                }
                
                /* Incoming message consistent with immediate reply? */
                if (rx->rx_msg->ibm_type != IBNAL_MSG_IMMEDIATE) {
                        CERROR ("REPLY to "LPX64" bad opbm type %d!!!\n",
                                nid, rx->rx_msg->ibm_type);
                        return (PTL_FAIL);
                }

                /* Will it fit in a message? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob]);
                if (nob > IBNAL_MSG_SIZE) {
                        CERROR("REPLY for "LPX64" too big (RDMA not requested): %d (max for message is %d)\n", 
                               nid, payload_nob, IBNAL_MSG_SIZE);
                        return (PTL_FAIL);
                }
                break;
        }

        case PTL_MSG_GET:
                /* might the REPLY message be big enough to need RDMA? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[libmsg->md->length]);
                if (nob > IBNAL_MSG_SIZE)
                        return (kibnal_start_passive_rdma(IBNAL_MSG_GET_RDMA, 
                                                          nid, libmsg, hdr));
                break;

        case PTL_MSG_ACK:
                LASSERT (payload_nob == 0);
                break;

        case PTL_MSG_PUT:
                /* Is the payload big enough to need RDMA? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob]);
                if (nob > IBNAL_MSG_SIZE)
                        return (kibnal_start_passive_rdma(IBNAL_MSG_PUT_RDMA,
                                                          nid, libmsg, hdr));
                
                break;
        }

        tx = kibnal_get_idle_tx(!(type == PTL_MSG_ACK ||
                                  type == PTL_MSG_REPLY ||
                                  in_interrupt()));
        if (tx == NULL) {
                CERROR ("Can't send %d to "LPX64": tx descs exhausted%s\n", 
                        type, nid, in_interrupt() ? " (intr)" : "");
                return (PTL_NO_SPACE);
        }

        ibmsg = tx->tx_msg;
        ibmsg->ibm_u.immediate.ibim_hdr = *hdr;

        if (payload_nob > 0) {
                if (payload_kiov != NULL)
                        lib_copy_kiov2buf(ibmsg->ibm_u.immediate.ibim_payload,
                                          payload_niov, payload_kiov,
                                          payload_offset, payload_nob);
                else
                        lib_copy_iov2buf(ibmsg->ibm_u.immediate.ibim_payload,
                                         payload_niov, payload_iov,
                                         payload_offset, payload_nob);
        }

        kibnal_init_tx_msg (tx, IBNAL_MSG_IMMEDIATE,
                            offsetof(kib_immediate_msg_t, 
                                     ibim_payload[payload_nob]));

        /* libmsg gets finalized when tx completes */
        tx->tx_libmsg[0] = libmsg;

        kibnal_launch_tx(tx, nid);
        return (PTL_OK);
}

static ptl_err_t
kibnal_send (lib_nal_t *nal, void *private, lib_msg_t *cookie,
               ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
               unsigned int payload_niov, struct iovec *payload_iov,
               size_t payload_offset, size_t payload_len)
{
        CDEBUG(D_NET, "  pid = %d, nid="LPU64"\n",
               pid, nid);
        return (kibnal_sendmsg(nal, private, cookie,
                               hdr, type, nid, pid,
                               payload_niov, payload_iov, NULL,
                               payload_offset, payload_len));
}

static ptl_err_t
kibnal_send_pages (lib_nal_t *nal, void *private, lib_msg_t *cookie, 
                     ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
                     unsigned int payload_niov, ptl_kiov_t *payload_kiov, 
                     size_t payload_offset, size_t payload_len)
{
        return (kibnal_sendmsg(nal, private, cookie,
                               hdr, type, nid, pid,
                               payload_niov, NULL, payload_kiov,
                               payload_offset, payload_len));
}

static ptl_err_t
kibnal_recvmsg (lib_nal_t *nal, void *private, lib_msg_t *libmsg,
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
                        lib_copy_buf2kiov(niov, kiov, offset,
                                          rxmsg->ibm_u.immediate.ibim_payload,
                                          mlen);
                else
                        lib_copy_buf2iov(niov, iov, offset,
                                         rxmsg->ibm_u.immediate.ibim_payload,
                                         mlen);

                lib_finalize (nal, NULL, libmsg, PTL_OK);
                return (PTL_OK);

        case IBNAL_MSG_GET_RDMA:
                /* We get called here just to discard any junk after the
                 * GET hdr. */
                LASSERT (libmsg == NULL);
                lib_finalize (nal, NULL, libmsg, PTL_OK);
                return (PTL_OK);

        case IBNAL_MSG_PUT_RDMA:
                kibnal_start_active_rdma (IBNAL_MSG_PUT_DONE, 0,
                                          rx, libmsg, 
                                          niov, iov, kiov, offset, mlen);
                return (PTL_OK);
        }
}

static ptl_err_t
kibnal_recv (lib_nal_t *nal, void *private, lib_msg_t *msg,
              unsigned int niov, struct iovec *iov, 
              size_t offset, size_t mlen, size_t rlen)
{
        return (kibnal_recvmsg (nal, private, msg, niov, iov, NULL,
                                offset, mlen, rlen));
}

static ptl_err_t
kibnal_recv_pages (lib_nal_t *nal, void *private, lib_msg_t *msg,
                     unsigned int niov, ptl_kiov_t *kiov, 
                     size_t offset, size_t mlen, size_t rlen)
{
        return (kibnal_recvmsg (nal, private, msg, niov, NULL, kiov,
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
        
        if (list_empty (&peer->ibp_conns) &&
            peer->ibp_persistence == 0) {
                /* Non-persistent peer with no more conns... */
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

        CDEBUG(D_NET, "Enter kibnal_connreq_done for conn=%p, active=%d, status=%d\n",
               conn, active, status);

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

                        CDEBUG(D_NET, "RX[%d] %p->%p\n",
                               i, &conn->ibc_rxs[i], conn->ibc_rxs[i].rx_msg);

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
kibnal_accept (kib_conn_t **connp, cm_cep_handle_t *cep,
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

static void kibnal_move_qp_to_error(kib_conn_t *conn)
{
        vv_qp_attr_t qp_attr;
        vv_return_t retval;

        qp_attr.modify.qp_modify_into_state = vv_qp_state_error;
        qp_attr.modify.vv_qp_attr_mask      = VV_QP_AT_STATE;
        qp_attr.modify.qp_type              = vv_qp_type_r_conn;

        retval = vv_qp_modify(kibnal_data.kib_hca, conn->ibc_qp, &qp_attr, &conn->ibc_qp_attrs);
        if (retval)
                CERROR("couldn't move qp into error state, error %d\n", retval);
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
        kibnal_move_qp_to_error(conn);

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
kibnal_reject (cm_cep_handle_t cep, cm_rej_code_t reason)
{
        cm_reject_data_t *rej;

        PORTAL_ALLOC(rej, sizeof(*rej));
        if (rej == NULL) /* PORTAL_ALLOC() will CERROR on failure */
                return;  

        rej->reason = reason;
        cm_reject(cep, rej);
        PORTAL_FREE(rej, sizeof(*rej));
}

static void get_av_from_path(ib_path_record_v2_t *path, vv_add_vec_t *av)
{
        av->service_level = path->sl;
        av->grh_flag = 0;       /* TODO: correct? */
        av->dlid = path->dlid;
        av->pmtu = path->mtu;

        /* From sdp-hca-params.h. */
        switch(path->rate) {
        case 2:
                av->max_static_rate = 1;
                break;
        case 3:
        case 4:
        default:
                av->max_static_rate = 0;
                break;
        }

        av->l_ack_timeout = IBNAL_ACK_TIMEOUT;
        av->retry_count = IBNAL_RETRY;
        av->rnr_retry_count = IBNAL_RNR_RETRY; 
        av->source_path_bit = 0;

        av->global_dest.flow_lable = path->flow_label;
        av->global_dest.hope_limit = path->hop_limut;
        av->global_dest.traffic_class = path->traffic_class;
        av->global_dest.s_gid_index = 0;
        av->global_dest.d_gid = path->dgid;
};

static vv_return_t
kibnal_qp_rts(vv_qp_h_t qp_handle, __u32 qpn, __u8 resp_res, 
              ib_path_record_v2_t *path, __u8 init_depth, __u32 send_psn)
{
        vv_qp_attr_t qp_attr;
        vv_return_t retval;

        ENTRY;

#if 1
        /* TODO - Hack. I don't know whether I get bad values from the
         * stack or if I'm using the wrong names. */
        resp_res = 8;
        init_depth = 8;
#endif

        /* RTR */
        qp_attr.modify.qp_modify_into_state = vv_qp_state_rtr;
        qp_attr.modify.vv_qp_attr_mask =
                VV_QP_AT_STATE | 
                VV_QP_AT_ADD_VEC |
                VV_QP_AT_DEST_QP |
                VV_QP_AT_R_PSN |
                VV_QP_AT_RESP_RDMA_ATOM_OUT_NUM |
                VV_QP_AT_MIN_RNR_NAK_T | VV_QP_AT_OP_F;

        qp_attr.modify.qp_type = vv_qp_type_r_conn;

        get_av_from_path(path, &qp_attr.modify.params.rtr.remote_add_vec);
        qp_attr.modify.params.rtr.destanation_qp = qpn;
        qp_attr.modify.params.rtr.receive_psn = IBNAL_STARTING_PSN;
        qp_attr.modify.params.rtr.responder_rdma_r_atom_num = resp_res;
        qp_attr.modify.params.rtr.opt_min_rnr_nak_timer = 16; /* 20 ms */

        /* For now, force MTU to 1KB (Voltaire's advice). */
        qp_attr.modify.params.rtr.remote_add_vec.pmtu = vv_mtu_1024;

        retval = vv_qp_modify(kibnal_data.kib_hca, qp_handle, &qp_attr, NULL);
        if (retval) {
                CERROR("Cannot modify QP to RTR: %d\n", retval);
                RETURN(retval);
        }

        /* RTS */
        qp_attr.modify.qp_modify_into_state = vv_qp_state_rts;
        qp_attr.modify.vv_qp_attr_mask = 
                VV_QP_AT_STATE |
                VV_QP_AT_L_ACK_T |
                VV_QP_AT_RETRY_NUM |
                VV_QP_AT_RNR_NUM |
                VV_QP_AT_S_PSN |
                VV_QP_AT_DEST_RDMA_ATOM_OUT_NUM;
        qp_attr.modify.qp_type = vv_qp_type_r_conn;             

        qp_attr.modify.params.rts.local_ack_timeout = path->pkt_life_time + 2; /* 2 or 1? */ 
        qp_attr.modify.params.rts.retry_num = IBNAL_RETRY;
        qp_attr.modify.params.rts.rnr_num = IBNAL_RNR_RETRY;
        qp_attr.modify.params.rts.send_psn = send_psn;
        qp_attr.modify.params.rts.dest_out_rdma_r_atom_num = init_depth;
        qp_attr.modify.params.rts.flow_control = 1; /* Stack does not use it. */

        retval = vv_qp_modify(kibnal_data.kib_hca, qp_handle, &qp_attr, NULL);
        if (retval) {
                CERROR("Cannot modify QP to RTS: %d\n", retval);
        }

        RETURN(retval);
}

static void
kibnal_connect_reply (cm_cep_handle_t cep, cm_conn_data_t *info, kib_conn_t *conn)
{
        vv_hca_attrib_t *ca_attr = &kibnal_data.kib_hca_attrs;
        kib_wire_connreq_t *wcr;
        cm_reply_data_t *rep = &info->data.reply;
        cm_rej_code_t reason;
        vv_return_t retval;

        wcr = (kib_wire_connreq_t *)info->data.reply.priv_data;

        if (wcr->wcr_magic != cpu_to_le32(IBNAL_MSG_MAGIC)) {
                CERROR ("Can't connect "LPX64": bad magic %08x\n",
                        conn->ibc_peer->ibp_nid, le32_to_cpu(wcr->wcr_magic));
                GOTO(reject, reason = cm_rej_code_usr_rej);
        }
        
        if (wcr->wcr_version != cpu_to_le16(IBNAL_MSG_VERSION)) {
                CERROR ("Can't connect "LPX64": bad version %d\n",
                        conn->ibc_peer->ibp_nid, le16_to_cpu(wcr->wcr_magic));
                GOTO(reject, reason = cm_rej_code_usr_rej);
        }
                        
        if (wcr->wcr_queue_depth != cpu_to_le16(IBNAL_MSG_QUEUE_SIZE)) {
                CERROR ("Can't connect "LPX64": bad queue depth %d\n",
                        conn->ibc_peer->ibp_nid, 
                        le16_to_cpu(wcr->wcr_queue_depth));
                GOTO(reject, reason = cm_rej_code_usr_rej);
        }
                        
        if (le64_to_cpu(wcr->wcr_nid) != conn->ibc_peer->ibp_nid) {
                CERROR ("Unexpected NID "LPX64" from "LPX64"\n",
                        le64_to_cpu(wcr->wcr_nid), conn->ibc_peer->ibp_nid);
                GOTO(reject, reason = cm_rej_code_usr_rej);
        }

        CDEBUG(D_NET, "Connection %p -> "LPX64" REP_RECEIVED.\n",
               conn, conn->ibc_peer->ibp_nid);

        conn->ibc_incarnation = le64_to_cpu(wcr->wcr_incarnation);
        conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;

        retval = kibnal_qp_rts(conn->ibc_qp, rep->qpn, 
                            min_t(__u8, rep->arb_initiator_depth,
                                  ca_attr->max_read_atom_qp_outstanding),
                            &conn->ibc_connreq->cr_path, 
                            min_t(__u8, rep->arb_resp_res,
                                  ca_attr->max_qp_depth_for_init_read_atom),
                            rep->start_psn);

        if (retval) {
                CERROR("Connection %p -> "LPX64" QP RTS/RTR failed: %d\n",
                       conn, conn->ibc_peer->ibp_nid, retval);
                GOTO(reject, reason = cm_rej_code_no_qp);
        }

        dump_qp(conn);

        /* the callback arguments are ignored for an active accept */
        /* TODO: memset cmrtu? */
        retval = cm_accept(cep, NULL, &conn->ibc_connreq->cr_cm_rtu, kibnal_cm_callback, conn);
        if (retval) {
                CERROR("Connection %p -> "LPX64" CMAccept RTU failed: %d\n",
                       conn, conn->ibc_peer->ibp_nid, retval);
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

/* Off level CM callback */
static void
_kibnal_cm_callback(void * arg)
{
        struct cm_off_level *cm_tq = arg;
        cm_cep_handle_t cep = cm_tq->cep;
        cm_conn_data_t *info = cm_tq->info;
        kib_conn_t *conn = cm_tq->conn;
        vv_return_t retval;

        CDEBUG(D_NET, "CM event 0x%x for CEP %p\n", info->status, cep);

        PORTAL_FREE(cm_tq, sizeof(*cm_tq));

        /* Established Connection Notifier */
        switch (info->status) {
        case cm_event_connected:
                CDEBUG(D_NET, "Connection %p -> "LPX64" Established\n",
                       conn, conn->ibc_peer->ibp_nid);
                kibnal_connreq_done (conn, 0, 0);
                break;

        case cm_event_conn_timeout:
        case cm_event_conn_reject:
                /* TODO: be sure this is called only if REQ times out. */
                CERROR("connection timed out\n");
                LASSERT(conn->ibc_state == IBNAL_CONN_CONNECTING);
                conn->ibc_state = IBNAL_CONN_INIT_QP;
                kibnal_connreq_done (conn, 1, -EINVAL);
                break;

        case cm_event_conn_reply:
                kibnal_connect_reply(cep, info, conn);
                break;

        case cm_event_disconn_request:
                /* XXX lock around these state management bits? */
                if (conn->ibc_state == IBNAL_CONN_ESTABLISHED)
                        kibnal_close_conn (conn, 0);
                conn->ibc_state = IBNAL_CONN_DREP;
                
                retval = cm_disconnect(conn->ibc_cep, NULL, &kibnal_data.cm_data.drep_data);
                if (retval)
                        CERROR("disconnect rep failed: %d\n", retval);

                /* Fall through ... */

        /* these both guarantee that no more cm callbacks will occur */
        case cm_event_disconnected: /* aka cm_event_disconn_timeout */
        case cm_event_disconn_reply:
                CDEBUG(D_NET, "Connection %p -> "LPX64" disconnect done.\n",
                       conn, conn->ibc_peer->ibp_nid);

                conn->ibc_state = IBNAL_CONN_DISCONNECTED;
                kibnal_flush_pending(conn);
                kibnal_put_conn(conn);        /* Lose CM's ref */
                break;

        default:
                CERROR("unknown status %d on Connection %p -> "LPX64"\n",
                       info->status, conn, conn->ibc_peer->ibp_nid);
                LBUG();
                break;
        }

        return;
}

static void
kibnal_cm_callback(cm_cep_handle_t cep, cm_conn_data_t *info, void *arg)
{
        struct cm_off_level *cm_tq;

        LASSERT(cep);
        LASSERT(info);

        CDEBUG(D_NET, "CM event 0x%x for CEP %p\n", info->status, cep);

        PORTAL_ALLOC_ATOMIC(cm_tq, sizeof(*cm_tq));
        if (cm_tq == NULL) {
                CERROR("Failed to allocate a CM off level structure\n");
                return;
        }

        cm_tq->tq.sync = 0;
        cm_tq->tq.routine = _kibnal_cm_callback;
        cm_tq->tq.data = cm_tq;

        cm_tq->cep = cep;
        cm_tq->info = info;
        cm_tq->conn = (kib_conn_t *)arg;

        schedule_task(&cm_tq->tq);
}

static int
kibnal_set_cm_flags(cm_cep_handle_t cep)
{
#ifdef TODO
voltaire cm doesnot appear to have that functionnality
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
#endif

        return 0;
}

/* Off level listen callback */
static void
_kibnal_listen_callback(void *arg)
{
        struct cm_off_level *cm_tq = arg;
        cm_cep_handle_t cep = cm_tq->cep;
        cm_conn_data_t *info = cm_tq->info;
        vv_hca_attrib_t *ca_attr = &kibnal_data.kib_hca_attrs;
        cm_request_data_t  *req;
        cm_reply_data_t    *rep = NULL;
        kib_wire_connreq_t *wcr;
        kib_conn_t         *conn = NULL;
        cm_rej_code_t       reason = 0;
        int                 rc = 0;
        vv_return_t         retval;
        vv_qp_attr_t       *query;
        void               *qp_context;

        LASSERT(cep);
        LASSERT(info);

        CDEBUG(D_NET, "LISTEN status 0x%x for CEP %p\n", info->status, cep);

        PORTAL_FREE(cm_tq, sizeof(*cm_tq));

        req = &info->data.request;
        wcr = (kib_wire_connreq_t *)req->priv_data;

        CDEBUG(D_NET, "%d from "LPX64"\n", info->status, 
               le64_to_cpu(wcr->wcr_nid));
        
#ifdef TODO
        is there an equivalent?
        if (info->status == FCM_CONNECT_CANCEL)
                return;
#endif
        
        LASSERT (info->status == cm_event_conn_request);
        
        if (wcr->wcr_magic != cpu_to_le32(IBNAL_MSG_MAGIC)) {
                CERROR ("Can't accept: bad magic %08x\n",
                        le32_to_cpu(wcr->wcr_magic));
                GOTO(out, reason = cm_rej_code_usr_rej);
        }

        if (wcr->wcr_version != cpu_to_le16(IBNAL_MSG_VERSION)) {
                CERROR ("Can't accept: bad version %d\n",
                        le16_to_cpu(wcr->wcr_magic));
                GOTO(out, reason = cm_rej_code_usr_rej);
        }

        rc = kibnal_accept(&conn, cep,
                           le64_to_cpu(wcr->wcr_nid),
                           le64_to_cpu(wcr->wcr_incarnation),
                           le16_to_cpu(wcr->wcr_queue_depth));
        if (rc != 0) {
                CERROR ("Can't accept "LPX64": %d\n",
                        le64_to_cpu(wcr->wcr_nid), rc);
                GOTO(out, reason = cm_rej_code_no_res);
        }

        /* TODO: I hope I got the ca_attr names correctly. */
        retval = kibnal_qp_rts(conn->ibc_qp, req->cep_data.qpn,
                            min_t(__u8, req->cep_data.offered_initiator_depth, 
                                  ca_attr->max_read_atom_qp_outstanding),
                            &req->path_data.path,
                            min_t(__u8, req->cep_data.offered_resp_res, 
                                  ca_attr->max_qp_depth_for_init_read_atom),
                            req->cep_data.start_psn);

        if (retval) {
                CERROR ("Can't mark QP RTS/RTR  "LPX64": %d\n",
                        le64_to_cpu(wcr->wcr_nid), retval);
                GOTO(out, reason = cm_rej_code_no_qp);
        }

        dump_qp(conn);

        retval = vv_qp_query(kibnal_data.kib_hca, conn->ibc_qp, &qp_context, &conn->ibc_qp_attrs);
        if (retval) {
                CERROR ("Couldn't query qp attributes "LPX64": %d\n",
                        le64_to_cpu(wcr->wcr_nid), retval);
                GOTO(out, reason = cm_rej_code_no_qp);
        }
        query = &conn->ibc_qp_attrs;

        PORTAL_ALLOC(rep, sizeof(*rep));
        if (rep == NULL) {
                CERROR ("can't reply and receive buffers\n");
                GOTO(out, reason = cm_rej_code_insuff_resp_res);
        }

        /* don't try to deref this into the incoming wcr :) */
        wcr = (kib_wire_connreq_t *)rep->priv_data;

        *rep = (cm_reply_data_t) {
                .qpn = query->query.qp_num,
                .start_psn = query->query.receve_psn,
                .arb_resp_res = query->query.rdma_r_atom_outstand_num,
                .arb_initiator_depth = query->query.rdma_r_atom_outstand_num,
                .targ_ack_delay = 0,
                .failover_accepted = 0,
                .end_to_end_flow_ctrl = 1, /* (query->query.flow_control is never set) */
                .rnr_retry_count = req->cep_data.rtr_retry_cnt,
        };

        *wcr = (kib_wire_connreq_t) {
                .wcr_magic       = cpu_to_le32(IBNAL_MSG_MAGIC),
                .wcr_version     = cpu_to_le16(IBNAL_MSG_VERSION),
                .wcr_queue_depth = cpu_to_le32(IBNAL_MSG_QUEUE_SIZE),
                .wcr_nid         = cpu_to_le64(kibnal_data.kib_nid),
                .wcr_incarnation = cpu_to_le64(kibnal_data.kib_incarnation),
        };

        retval = cm_accept(cep, rep, NULL, kibnal_cm_callback, conn);

        PORTAL_FREE(rep, sizeof(*rep));

        if (retval) {
                /* XXX it seems we don't call reject after this point? */
                CERROR("cm_accept() failed: %d, aborting\n", retval);
                rc = -ECONNABORTED;
                goto out;
        }

        if (kibnal_set_cm_flags(conn->ibc_cep)) {
                rc = -ECONNABORTED;
                goto out;
        }

        conn->ibc_cep = cep;

        CDEBUG(D_WARNING, "Connection %p -> "LPX64" ESTABLISHED.\n",
               conn, conn->ibc_peer->ibp_nid);

out:
        if (reason) {
                kibnal_reject(cep, reason);
                rc = -ECONNABORTED;
        }

        return;
}

void
kibnal_listen_callback(cm_cep_handle_t cep, cm_conn_data_t *info, void *arg)
{
        struct cm_off_level *cm_tq;

        LASSERT(cep);
        LASSERT(info);
        LASSERT(arg == NULL); /* no conn yet for passive */

        PORTAL_ALLOC_ATOMIC(cm_tq, sizeof(*cm_tq));
        if (cm_tq == NULL) {
                CERROR("Failed to allocate a CM off level structure\n");
                return;
        }

        cm_tq->tq.sync = 0;
        cm_tq->tq.routine = _kibnal_listen_callback;
        cm_tq->tq.data = cm_tq;

        cm_tq->cep = cep;
        cm_tq->info = info;
        cm_tq->conn = NULL;

        schedule_task(&cm_tq->tq);
}

static void
kibnal_pathreq_callback (struct sa_request *request)
{
        vv_hca_attrib_t *ca_attr = &kibnal_data.kib_hca_attrs;
        kib_conn_t *conn = request->context;
        gsi_dtgrm_t *dtgrm;
        sa_mad_v2_t *mad;
        ib_path_record_v2_t *path;
        u64 component_mask;
        cm_return_t cmret;

        if (request->status) {
                CERROR ("status %d\n", request->status);
                free_sa_request(request);
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }

        dtgrm = request->dtgrm_resp;
        mad = (sa_mad_v2_t *) dtgrm->mad;
        path = (ib_path_record_v2_t *) mad->payload;

        /* Put the path record in host order for that stack. */
        gid_swap(&path->sgid);
        gid_swap(&path->dgid);
        path->slid = be16_to_cpu(path->slid);
        path->dlid = be16_to_cpu(path->dlid);
        path->flow_label = be32_to_cpu(path->flow_label);
        path->pkey = be16_to_cpu(path->pkey);
        path->sl = be16_to_cpu(path->sl);

        CDEBUG(D_NET, "sgid "LPX64":"LPX64" dgid "
               LPX64":"LPX64" pkey %x\n",
               path->sgid.scope.g.subnet,
               path->sgid.scope.g.eui64,
               path->dgid.scope.g.subnet,
               path->dgid.scope.g.eui64,
               path->pkey);

#if TODO
        component_mask = be64_to_cpu(mad->component_mask);
        if ((component_mask && (1ull << 1)) == 0) {
                CERROR ("no servivce GID in SR: "LPX64"\n", component_mask);
                free_sa_request(request);
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }
#endif

        conn->ibc_connreq->cr_path = *path;

        free_sa_request(request);    

        conn->ibc_cep = cm_create_cep(cm_cep_transp_rc);
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
                .wcr_nid         = cpu_to_le64(kibnal_data.kib_nid),
                .wcr_incarnation = cpu_to_le64(kibnal_data.kib_incarnation),
        };

        conn->ibc_connreq->cr_cm_req = (cm_request_data_t) {
                .sid = kibnal_data.kib_service_id,
                .cep_data = (cm_cep_data_t) { 
                        .ca_guid = kibnal_data.kib_hca_attrs.guid,
                        .end_to_end_flow_ctrl = 1,
                        .port_guid = kibnal_data.kib_port_gid.scope.g.eui64,
                        .local_port_num = kibnal_data.kib_port,
                        .start_psn = IBNAL_STARTING_PSN,
                        .qpn = conn->ibc_qp_attrs.query.qp_num,
                        .retry_cnt = IBNAL_RETRY,
                        .rtr_retry_cnt = IBNAL_RNR_RETRY,
                        .ack_timeout = IBNAL_ACK_TIMEOUT,
                        .offered_resp_res = ca_attr->max_read_atom_qp_outstanding,
                        .offered_initiator_depth = ca_attr->max_qp_depth_for_init_read_atom,
                },
                .path_data = (cm_cep_path_data_t) {
                        .subn_local = TRUE,
                        .path = conn->ibc_connreq->cr_path,
                },
        };

#if 0
        /* XXX set timeout just like SDP!!!*/
        conn->ibc_connreq->cr_path.packet_life = 13;
#endif
        /* Flag I'm getting involved with the CM... */
        conn->ibc_state = IBNAL_CONN_CONNECTING;

#if 0
        CDEBUG(D_NET, "Connecting to, service id "LPX64", on "LPX64"\n",
               conn->ibc_connreq->cr_service.RID.ServiceID, 
               *kibnal_service_nid_field(&conn->ibc_connreq->cr_service));
#endif

        memset(conn->ibc_connreq->cr_cm_req.priv_data, 0, 
               cm_REQ_priv_data_len);
        memcpy(conn->ibc_connreq->cr_cm_req.priv_data, 
               &conn->ibc_connreq->cr_wcr, sizeof(conn->ibc_connreq->cr_wcr));

        /* kibnal_cm_callback gets my conn ref */
        cmret = cm_connect(conn->ibc_cep, &conn->ibc_connreq->cr_cm_req,
                              kibnal_cm_callback, conn);

        if (cmret) {
                CERROR ("Connect failed: %d\n", cmret);
                /* Back out state change as connect failed */
                conn->ibc_state = IBNAL_CONN_INIT_QP;
                kibnal_connreq_done (conn, 1, -EINVAL);
        }

        CDEBUG(D_NET, "connection REQ sent\n");
}

static void
kibnal_service_get_callback (struct sa_request *request)
{
        kib_conn_t *conn = request->context;
        gsi_dtgrm_t *dtgrm;
        sa_mad_v2_t *mad;
        ib_service_record_v2_t *sr;
        u64 component_mask;
        int ret;

        if (request->status) {
                CERROR ("status %d\n", request->status);
                free_sa_request(request);
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }

        dtgrm = request->dtgrm_resp;
        mad = (sa_mad_v2_t *) dtgrm->mad;
        sr = (ib_service_record_v2_t *) mad->payload;

        CDEBUG(D_NET, "sid "LPX64" gid "LPX64":"LPX64" pkey %x\n",
               sr->service_id,
               sr->service_gid.scope.g.subnet,
               sr->service_gid.scope.g.eui64,
               sr->service_pkey);

        component_mask = be64_to_cpu(mad->component_mask);
        if ((component_mask && (1ull << 1)) == 0) {
                CERROR ("no service GID in SR: "LPX64"\n", component_mask);
                free_sa_request(request);
                kibnal_connreq_done (conn, 1, -EINVAL);
                return;
        }

        //conn->ibc_connreq->cr_service = sr;

        /* Return the response datagram to its pool. We don't need it anymore. */
        gsi_dtgrm_pool_put(request->dtgrm_resp);
        request->dtgrm_resp = NULL;

        /* kibnal_pathreq_callback gets my conn ref */
        ret = kibnal_pathrecord_op(request, sr->service_gid, kibnal_pathreq_callback, conn);
        if (ret) {
                CERROR ("Path record request failed: %d\n", ret);
                kibnal_connreq_done (conn, 1, -EINVAL);
        }

        return;
}

static void
kibnal_connect_peer (kib_peer_t *peer)
{
        kib_conn_t  *conn = kibnal_create_conn();
        struct sa_request *request;
        int ret;

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

        /* kibnal_service_get_callback gets my conn ref */
        ret = kibnal_advertize_op(peer->ibp_nid, SUBN_ADM_GET, kibnal_service_get_callback, conn);

        if (ret) {
                CERROR("kibnal_advertize_op failed for op %d NID "LPX64"\n", SUBN_ADM_GET, peer->ibp_nid);
                /* TODO: I'm unsure yet whether ret contains a
                 * consistent error type, so I return -EIO in the
                 * meantime. */
                kibnal_connreq_done (conn, 1, -EIO);
        }

        return;
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
        vv_return_t retval;

        switch (conn->ibc_state) {
                /* all refs have gone, free and be done with it */ 
                case IBNAL_CONN_DISCONNECTED:
                        kibnal_destroy_conn (conn);
                        return; /* avoid put_conn */

                case IBNAL_CONN_SEND_DREQ:
                        
                        retval = cm_disconnect(conn->ibc_cep, &kibnal_data.cm_data.dreq_data, NULL);
                        if (retval) /* XXX do real things */
                                CERROR("disconnect failed: %d\n", retval);
                        
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


lib_nal_t kibnal_lib = {
        .libnal_data = &kibnal_data,      /* NAL private data */
        .libnal_send = kibnal_send,
        .libnal_send_pages = kibnal_send_pages,
        .libnal_recv = kibnal_recv,
        .libnal_recv_pages = kibnal_recv_pages,
        .libnal_dist = kibnal_dist
};
