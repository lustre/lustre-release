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

void
kibnal_tx_done (kib_tx_t *tx)
{
        ptl_err_t        ptlrc = (tx->tx_status == 0) ? PTL_OK : PTL_FAIL;
        int              i;

        LASSERT (!in_interrupt());
        LASSERT (!tx->tx_queued);               /* mustn't be queued for sending */
        LASSERT (tx->tx_sending == 0);          /* mustn't be awaiting sent callback */
        LASSERT (!tx->tx_waiting);              /* mustn't be awaiting peer response */

#if !IBNAL_WHOLE_MEM
        switch (tx->tx_mapped) {
        default:
                LBUG();

        case KIB_TX_UNMAPPED:
                break;

        case KIB_TX_MAPPED: {
                vv_return_t      vvrc;

                vvrc = vv_mem_region_destroy(kibnal_data.kib_hca,
                                             tx->tx_md.md_handle);
                LASSERT (vvrc == vv_return_ok);
                tx->tx_mapped = KIB_TX_UNMAPPED;
                break;
        }
        }
#endif
        for (i = 0; i < 2; i++) {
                /* tx may have up to 2 libmsgs to finalise */
                if (tx->tx_libmsg[i] == NULL)
                        continue;

                lib_finalize (&kibnal_lib, NULL, tx->tx_libmsg[i], ptlrc);
                tx->tx_libmsg[i] = NULL;
        }
        
        if (tx->tx_conn != NULL) {
                kibnal_conn_decref(tx->tx_conn);
                tx->tx_conn = NULL;
        }

        tx->tx_nwrq = 0;
        tx->tx_status = 0;

        spin_lock(&kibnal_data.kib_tx_lock);

        if (tx->tx_isnblk) {
                list_add_tail (&tx->tx_list, &kibnal_data.kib_idle_nblk_txs);
        } else {
                list_add_tail (&tx->tx_list, &kibnal_data.kib_idle_txs);
                wake_up (&kibnal_data.kib_idle_tx_waitq);
        }

        spin_unlock(&kibnal_data.kib_tx_lock);
}

kib_tx_t *
kibnal_get_idle_tx (int may_block) 
{
        kib_tx_t      *tx = NULL;
        ENTRY;
        
        for (;;) {
                spin_lock(&kibnal_data.kib_tx_lock);

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
                spin_unlock(&kibnal_data.kib_tx_lock);

                wait_event (kibnal_data.kib_idle_tx_waitq,
                            !list_empty (&kibnal_data.kib_idle_txs) ||
                            kibnal_data.kib_shutdown);
        }

        if (tx != NULL) {
                list_del (&tx->tx_list);

                /* Allocate a new completion cookie.  It might not be needed,
                 * but we've got a lock right now and we're unlikely to
                 * wrap... */
                tx->tx_cookie = kibnal_data.kib_next_tx_cookie++;
#if IBNAL_WHOLE_MEM
                LASSERT (tx->tx_mapped == KIB_TX_UNMAPPED);
#endif
                LASSERT (tx->tx_nwrq == 0);
                LASSERT (!tx->tx_queued);
                LASSERT (tx->tx_sending == 0);
                LASSERT (!tx->tx_waiting);
                LASSERT (tx->tx_status == 0);
                LASSERT (tx->tx_conn == NULL);
                LASSERT (tx->tx_libmsg[0] == NULL);
                LASSERT (tx->tx_libmsg[1] == NULL);
        }

        spin_unlock(&kibnal_data.kib_tx_lock);
        
        RETURN(tx);
}

int
kibnal_post_rx (kib_rx_t *rx, int credit)
{
        kib_conn_t   *conn = rx->rx_conn;
        int           rc = 0;
        vv_return_t   vvrc;

        LASSERT (!in_interrupt());
        
        rx->rx_gl = (vv_scatgat_t) {
                .v_address = (void *)((unsigned long)KIBNAL_RX_VADDR(rx)),
                .l_key     = KIBNAL_RX_LKEY(rx),
                .length    = IBNAL_MSG_SIZE,
        };

        rx->rx_wrq = (vv_wr_t) {
                .wr_id                   = kibnal_ptr2wreqid(rx, IBNAL_WID_RX),
                .completion_notification = 1,
                .scatgat_list            = &rx->rx_gl,
                .num_of_data_segments    = 1,
                .wr_type                 = vv_wr_receive,
        };

        LASSERT (conn->ibc_state >= IBNAL_CONN_INIT);
        LASSERT (!rx->rx_posted);

        CDEBUG(D_NET, "posting rx [%d %x %p]\n", 
               rx->rx_wrq.scatgat_list->length,
               rx->rx_wrq.scatgat_list->l_key,
               rx->rx_wrq.scatgat_list->v_address);

        if (conn->ibc_state > IBNAL_CONN_ESTABLISHED) {
                /* No more posts for this rx; so lose its ref */
                kibnal_conn_decref(conn);
                return 0;
        }
        
        rx->rx_posted = 1;

        spin_lock(&conn->ibc_lock);
        /* Serialise vv_post_receive; it's not re-entrant on the same QP */
        vvrc = vv_post_receive(kibnal_data.kib_hca,
                               conn->ibc_qp, &rx->rx_wrq);
        spin_unlock(&conn->ibc_lock);

        if (vvrc == 0) {
                if (credit) {
                        spin_lock(&conn->ibc_lock);
                        conn->ibc_outstanding_credits++;
                        spin_unlock(&conn->ibc_lock);

                        kibnal_check_sends(conn);
                }
                return 0;
        }
        
        CERROR ("post rx -> "LPX64" failed %d\n", 
                conn->ibc_peer->ibp_nid, vvrc);
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

        LASSERT (conn->ibc_state < IBNAL_CONN_ESTABLISHED);
        LASSERT (conn->ibc_comms_error == 0);

        for (i = 0; i < IBNAL_RX_MSGS; i++) {
                /* +1 ref for rx desc.  This ref remains until kibnal_post_rx
                 * fails (i.e. actual failure or we're disconnecting) */
                kibnal_conn_addref(conn);
                rc = kibnal_post_rx (&conn->ibc_rxs[i], 0);
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

                CWARN("Unmatched completion type %x cookie "LPX64
                      " from "LPX64"\n",
                      txtype, cookie, conn->ibc_peer->ibp_nid);
                kibnal_close_conn (conn, -EPROTO);
                return;
        }

        if (tx->tx_status == 0) {               /* success so far */
                if (status < 0) {               /* failed? */
                        tx->tx_status = status;
                } else if (txtype == IBNAL_MSG_GET_REQ) { 
                        /* XXX layering violation: set REPLY data length */
                        LASSERT (tx->tx_libmsg[1] != NULL);
                        LASSERT (tx->tx_libmsg[1]->ev.type == 
                                 PTL_EVENT_REPLY_END);

                        tx->tx_libmsg[1]->ev.mlength = status;
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
        kib_tx_t    *tx = kibnal_get_idle_tx(0);
        
        if (tx == NULL) {
                CERROR("Can't get tx for completion %x for "LPX64"\n",
                       type, conn->ibc_peer->ibp_nid);
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
        int           rc;

        LASSERT (conn->ibc_state >= IBNAL_CONN_ESTABLISHED);

        CDEBUG (D_NET, "Received %x[%d] from "LPX64"\n",
                msg->ibm_type, credits, conn->ibc_peer->ibp_nid);
        
        if (credits != 0) {
                /* Have I received credits that will let me send? */
                spin_lock(&conn->ibc_lock);
                conn->ibc_credits += credits;
                spin_unlock(&conn->ibc_lock);

                kibnal_check_sends(conn);
        }

        switch (msg->ibm_type) {
        default:
                CERROR("Bad IBNAL message type %x from "LPX64"\n",
                       msg->ibm_type, conn->ibc_peer->ibp_nid);
                break;

        case IBNAL_MSG_NOOP:
                break;

        case IBNAL_MSG_IMMEDIATE:
                lib_parse(&kibnal_lib, &msg->ibm_u.immediate.ibim_hdr, rx);
                break;
                
        case IBNAL_MSG_PUT_REQ:
                rx->rx_responded = 0;
                lib_parse(&kibnal_lib, &msg->ibm_u.putreq.ibprm_hdr, rx);
                if (rx->rx_responded)
                        break;

                /* I wasn't asked to transfer any payload data.  This happens
                 * if the PUT didn't match, or got truncated. */
                kibnal_send_completion(rx->rx_conn, IBNAL_MSG_PUT_NAK, 0,
                                       msg->ibm_u.putreq.ibprm_cookie);
                break;

        case IBNAL_MSG_PUT_NAK:
                CWARN ("PUT_NACK from "LPX64"\n", conn->ibc_peer->ibp_nid);
                kibnal_handle_completion(conn, IBNAL_MSG_PUT_REQ, 
                                         msg->ibm_u.completion.ibcm_status,
                                         msg->ibm_u.completion.ibcm_cookie);
                break;

        case IBNAL_MSG_PUT_ACK:
                spin_lock(&conn->ibc_lock);
                tx = kibnal_find_waiting_tx_locked(conn, IBNAL_MSG_PUT_REQ,
                                                   msg->ibm_u.putack.ibpam_src_cookie);
                if (tx != NULL)
                        list_del(&tx->tx_list);
                spin_unlock(&conn->ibc_lock);

                if (tx == NULL) {
                        CERROR("Unmatched PUT_ACK from "LPX64"\n",
                               conn->ibc_peer->ibp_nid);
                        kibnal_close_conn(conn, -EPROTO);
                        break;
                }

                LASSERT (tx->tx_waiting);
                /* CAVEAT EMPTOR: I could be racing with tx_complete, but...
                 * (a) I can overwrite tx_msg since my peer has received it!
                 * (b) tx_waiting set tells tx_complete() it's not done. */

                tx->tx_nwrq = 0;                /* overwrite PUT_REQ */

                rc = kibnal_init_rdma(tx, IBNAL_MSG_PUT_DONE, 
                                      kibnal_rd_size(&msg->ibm_u.putack.ibpam_rd),
                                      &msg->ibm_u.putack.ibpam_rd,
                                      msg->ibm_u.putack.ibpam_dst_cookie);
                if (rc < 0)
                        CERROR("Can't setup rdma for PUT to "LPX64": %d\n",
                               conn->ibc_peer->ibp_nid, rc);

                spin_lock(&conn->ibc_lock);
                if (tx->tx_status == 0 && rc < 0)
                        tx->tx_status = rc;
                tx->tx_waiting = 0;             /* clear waiting and queue atomically */
                kibnal_queue_tx_locked(tx, conn);
                spin_unlock(&conn->ibc_lock);
                break;
                
        case IBNAL_MSG_PUT_DONE:
                kibnal_handle_completion(conn, IBNAL_MSG_PUT_ACK,
                                         msg->ibm_u.completion.ibcm_status,
                                         msg->ibm_u.completion.ibcm_cookie);
                break;

        case IBNAL_MSG_GET_REQ:
                rx->rx_responded = 0;
                lib_parse(&kibnal_lib, &msg->ibm_u.get.ibgm_hdr, rx);
                if (rx->rx_responded)           /* I responded to the GET_REQ */
                        break;
                /* NB GET didn't match (I'd have responded even with no payload
                 * data) */
                kibnal_send_completion(rx->rx_conn, IBNAL_MSG_GET_DONE, -ENODATA,
                                       msg->ibm_u.get.ibgm_cookie);
                break;

        case IBNAL_MSG_GET_DONE:
                kibnal_handle_completion(conn, IBNAL_MSG_GET_REQ,
                                         msg->ibm_u.completion.ibcm_status,
                                         msg->ibm_u.completion.ibcm_cookie);
                break;
        }

        kibnal_post_rx(rx, 1);
}

void
kibnal_rx_complete (kib_rx_t *rx, vv_comp_status_t vvrc, int nob, __u64 rxseq)
{
        kib_msg_t    *msg = rx->rx_msg;
        kib_conn_t   *conn = rx->rx_conn;
        unsigned long flags;
        int           rc;

        CDEBUG (D_NET, "rx %p conn %p\n", rx, conn);
        LASSERT (rx->rx_posted);
        rx->rx_posted = 0;

        if (conn->ibc_state > IBNAL_CONN_ESTABLISHED)
                goto ignore;

        if (vvrc != vv_comp_status_success) {
                CERROR("Rx from "LPX64" failed: %d\n", 
                       conn->ibc_peer->ibp_nid, vvrc);
                goto failed;
        }

        rc = kibnal_unpack_msg(msg, nob);
        if (rc != 0) {
                CERROR ("Error %d unpacking rx from "LPX64"\n",
                        rc, conn->ibc_peer->ibp_nid);
                goto failed;
        }

        if (msg->ibm_srcnid != conn->ibc_peer->ibp_nid ||
            msg->ibm_srcstamp != conn->ibc_incarnation ||
            msg->ibm_dstnid != kibnal_lib.libnal_ni.ni_pid.nid ||
            msg->ibm_dststamp != kibnal_data.kib_incarnation) {
                CERROR ("Stale rx from "LPX64"\n",
                        conn->ibc_peer->ibp_nid);
                goto failed;
        }

        if (msg->ibm_seq != rxseq) {
                CERROR ("Out-of-sequence rx from "LPX64
                        ": got "LPD64" but expected "LPD64"\n",
                        conn->ibc_peer->ibp_nid, msg->ibm_seq, rxseq);
                goto failed;
        }

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
        CDEBUG(D_NET, "rx %p conn %p\n", rx, conn);
        kibnal_close_conn(conn, -EIO);
 ignore:
        /* Don't re-post rx & drop its ref on conn */
        kibnal_conn_decref(conn);
}

#if IBNAL_WHOLE_MEM
int
kibnal_append_rdfrag(kib_rdma_desc_t *rd, int active, struct page *page, 
                     unsigned long page_offset, unsigned long len)
{
        kib_rdma_frag_t *frag = &rd->rd_frags[rd->rd_nfrag];
        vv_l_key_t       l_key;
        vv_r_key_t       r_key;
        __u64            addr;
        __u64            frag_addr;
        void            *ptr;
        vv_mem_reg_h_t   mem_h;
        vv_return_t      vvrc;

        if (rd->rd_nfrag >= IBNAL_MAX_RDMA_FRAGS) {
                CERROR ("Too many RDMA fragments\n");
                return -EMSGSIZE;
        }

#if CONFIG_HIGHMEM
# error "This probably doesn't work because of over/underflow when casting between __u64 and void *..."
#endif
        /* Try to create an address that adapter-tavor will munge into a valid
         * network address, given how it maps all phys mem into 1 region */
        addr = page_to_phys(page) + page_offset + PAGE_OFFSET;

        vvrc = vv_get_gen_mr_attrib(kibnal_data.kib_hca, 
                                    (void *)((unsigned long)addr),
                                    len, &mem_h, &l_key, &r_key);
        LASSERT (vvrc == vv_return_ok);

        if (active) {
                if (rd->rd_nfrag == 0) {
                        rd->rd_key = l_key;
                } else if (l_key != rd->rd_key) {
                        CERROR ("> 1 key for single RDMA desc\n");
                        return -EINVAL;
                }
                frag_addr = addr;
        } else {
                if (rd->rd_nfrag == 0) {
                        rd->rd_key = r_key;
                } else if (r_key != rd->rd_key) {
                        CERROR ("> 1 key for single RDMA desc\n");
                        return -EINVAL;
                }
                vv_va2advertise_addr(kibnal_data.kib_hca, 
                                     (void *)((unsigned long)addr), &ptr);
                frag_addr = (unsigned long)ptr;
        }

        kibnal_rf_set(frag, frag_addr, len);

        CDEBUG(D_NET,"map frag [%d][%d %x %08x%08x] "LPX64"\n", 
               rd->rd_nfrag, frag->rf_nob, rd->rd_key, 
               frag->rf_addr_hi, frag->rf_addr_lo, frag_addr);

        rd->rd_nfrag++;
        return 0;
}

struct page *
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

        return VALID_PAGE(page) ? page : NULL;
}

int
kibnal_setup_rd_iov(kib_tx_t *tx, kib_rdma_desc_t *rd, 
                    vv_access_con_bit_mask_t access,
                    int niov, struct iovec *iov, int offset, int nob)
                 
{
        /* active if I'm sending */
        int           active = ((access & vv_acc_r_mem_write) == 0);
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
kibnal_setup_rd_kiov (kib_tx_t *tx, kib_rdma_desc_t *rd, 
                      vv_access_con_bit_mask_t access,
                      int nkiov, ptl_kiov_t *kiov, int offset, int nob)
{
        /* active if I'm sending */
        int            active = ((access & vv_acc_r_mem_write) == 0);
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
kibnal_setup_rd_iov (kib_tx_t *tx, kib_rdma_desc_t *rd,
                     vv_access_con_bit_mask_t access,
                     int niov, struct iovec *iov, int offset, int nob)
                 
{
        /* active if I'm sending */
        int         active = ((access & vv_acc_r_mem_write) == 0);
        void       *vaddr;
        vv_return_t vvrc;

        LASSERT (nob > 0);
        LASSERT (niov > 0);
        LASSERT (tx->tx_mapped == KIB_TX_UNMAPPED);
        LASSERT ((rd != tx->tx_rd) == !active);

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

        vvrc = vv_mem_region_register(kibnal_data.kib_hca, vaddr, nob,
                                      kibnal_data.kib_pd, access,
                                      &tx->tx_md.md_handle, 
                                      &tx->tx_md.md_lkey,
                                      &tx->tx_md.md_rkey);
        if (vvrc != vv_return_ok) {
                CERROR ("Can't map vaddr %p: %d\n", vaddr, vvrc);
                return -EFAULT;
        }

        tx->tx_mapped = KIB_TX_MAPPED;

        rd->rd_key = active ? tx->tx_md.md_lkey : tx->tx_md.md_rkey;
        rd->rd_nfrag = 1;
        kibnal_rf_set(&rd->rd_frags[0], tx->tx_md.md_addr, nob);
        
        return (0);
}

int
kibnal_setup_rd_kiov (kib_tx_t *tx, kib_rdma_desc_t *rd,
                      vv_access_con_bit_mask_t access,
                      int nkiov, ptl_kiov_t *kiov, int offset, int nob)
{
        /* active if I'm sending */
        int            active = ((access & vv_acc_r_mem_write) == 0);
        vv_return_t    vvrc;
        vv_phy_list_t  phys_pages;
        vv_phy_buf_t  *phys;
        int            page_offset;
        int            nphys;
        int            resid;
        int            phys_size;
        int            rc;

        CDEBUG(D_NET, "niov %d offset %d nob %d\n", nkiov, offset, nob);

        LASSERT (nob > 0);
        LASSERT (nkiov > 0);
        LASSERT (tx->tx_mapped == KIB_TX_UNMAPPED);
        LASSERT ((rd != tx->tx_rd) == !active);

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

        phys[0].start = kibnal_page2phys(kiov->kiov_page);
        phys[0].size = PAGE_SIZE;

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
                                CERROR("kiov[%d] %p +%d for %d\n",
                                       i, kiov[i].kiov_page, 
                                       kiov[i].kiov_offset, 
                                       kiov[i].kiov_len);
                        
                        rc = -EINVAL;
                        goto out;
                }

                LASSERT (nphys * sizeof (*phys) < phys_size);
                phys[nphys].start = kibnal_page2phys(kiov->kiov_page);
                phys[nphys].size = PAGE_SIZE;

                nphys++;
                resid -= PAGE_SIZE;
        }

#if 0
        CWARN ("nphys %d, nob %d, page_offset %d\n", nphys, nob, page_offset);
        for (i = 0; i < nphys; i++)
                CWARN ("   [%d] "LPX64"\n", i, phys[i]);
#endif

        vvrc = vv_phy_mem_region_register(kibnal_data.kib_hca,
                                          &phys_pages,
                                          IBNAL_RDMA_BASE,
                                          nphys,
                                          page_offset,
                                          kibnal_data.kib_pd,
                                          access,
                                          &tx->tx_md.md_handle,
                                          &tx->tx_md.md_addr,
                                          &tx->tx_md.md_lkey,
                                          &tx->tx_md.md_rkey);

        if (vvrc != vv_return_ok) {
                CERROR ("Can't map phys: %d\n", vvrc);
                rc = -EFAULT;
                goto out;
        }

        CDEBUG(D_NET, "Mapped %d pages %d bytes @ offset %d: "
               "lkey %x, rkey %x, addr "LPX64"\n",
               nphys, nob, page_offset, tx->tx_md.md_lkey, tx->tx_md.md_rkey,
               tx->tx_md.md_addr);

        tx->tx_mapped = KIB_TX_MAPPED;
        rc = 0;

        rd->rd_key = active ? tx->tx_md.md_lkey : tx->tx_md.md_rkey;
        rd->rd_nfrag = 1;
        kibnal_rf_set(&rd->rd_frags[0], tx->tx_md.md_addr, nob);
        
 out:
        PORTAL_FREE(phys, phys_size);
        return (rc);
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
        vv_return_t     vvrc;                        
        int             rc;
        int             i;
        int             done;

        /* Don't send anything until after the connection is established */
        if (conn->ibc_state < IBNAL_CONN_ESTABLISHED) {
                CDEBUG(D_NET, LPX64"too soon\n", conn->ibc_peer->ibp_nid);
                return;
        }
        
        spin_lock(&conn->ibc_lock);

        LASSERT (conn->ibc_nsends_posted <= IBNAL_MSG_QUEUE_SIZE);

        if (list_empty(&conn->ibc_tx_queue) &&
            conn->ibc_outstanding_credits >= IBNAL_CREDIT_HIGHWATER) {
                spin_unlock(&conn->ibc_lock);
                
                tx = kibnal_get_idle_tx(0);     /* don't block */
                if (tx != NULL)
                        kibnal_init_tx_msg(tx, IBNAL_MSG_NOOP, 0);

                spin_lock(&conn->ibc_lock);
                
                if (tx != NULL)
                        kibnal_queue_tx_locked(tx, conn);
        }

        while (!list_empty (&conn->ibc_tx_queue)) {
                tx = list_entry (conn->ibc_tx_queue.next, kib_tx_t, tx_list);

                LASSERT (tx->tx_queued);
                /* We rely on this for QP sizing */
                LASSERT (tx->tx_nwrq > 0 && tx->tx_nwrq <= 1 + IBNAL_MAX_RDMA_FRAGS);

                LASSERT (conn->ibc_outstanding_credits >= 0);
                LASSERT (conn->ibc_outstanding_credits <= IBNAL_MSG_QUEUE_SIZE);
                LASSERT (conn->ibc_credits >= 0);
                LASSERT (conn->ibc_credits <= IBNAL_MSG_QUEUE_SIZE);

                if (conn->ibc_nsends_posted == IBNAL_MSG_QUEUE_SIZE) {
                        CDEBUG(D_NET, LPX64": posted enough\n",
                               conn->ibc_peer->ibp_nid);
                        break;
                }
                
                if (conn->ibc_credits == 0) {   /* no credits */
                        CDEBUG(D_NET, LPX64": no credits\n",
                               conn->ibc_peer->ibp_nid);
                        break;
                }
                
                if (conn->ibc_credits == 1 &&   /* last credit reserved for */
                    conn->ibc_outstanding_credits == 0) { /* giving back credits */
                        CDEBUG(D_NET, LPX64": not using last credit\n",
                               conn->ibc_peer->ibp_nid);
                        break;
                }
                
                list_del (&tx->tx_list);
                tx->tx_queued = 0;

                /* NB don't drop ibc_lock before bumping tx_sending */

                if (tx->tx_msg->ibm_type == IBNAL_MSG_NOOP &&
                    (!list_empty(&conn->ibc_tx_queue) ||
                     conn->ibc_outstanding_credits < IBNAL_CREDIT_HIGHWATER)) {
                        /* redundant NOOP */
                        spin_unlock(&conn->ibc_lock);
                        kibnal_tx_done(tx);
                        spin_lock(&conn->ibc_lock);
                        CDEBUG(D_NET, LPX64": redundant noop\n",
                               conn->ibc_peer->ibp_nid);
                        continue;
                }

                kibnal_pack_msg(tx->tx_msg, conn->ibc_outstanding_credits,
                                conn->ibc_peer->ibp_nid, conn->ibc_incarnation,
                                conn->ibc_txseq);

                conn->ibc_txseq++;
                conn->ibc_outstanding_credits = 0;
                conn->ibc_nsends_posted++;
                conn->ibc_credits--;

                /* CAVEAT EMPTOR!  This tx could be the PUT_DONE of an RDMA
                 * PUT.  If so, it was first queued here as a PUT_REQ, sent and
                 * stashed on ibc_active_txs, matched by an incoming PUT_ACK,
                 * and then re-queued here.  It's (just) possible that
                 * tx_sending is non-zero if we've not done the tx_complete() from
                 * the first send; hence the ++ rather than = below. */
                tx->tx_sending++;

                list_add (&tx->tx_list, &conn->ibc_active_txs);

                /* Keep holding ibc_lock while posting sends on this
                 * connection; vv_post_send() isn't re-entrant on the same
                 * QP!! */

                LASSERT (tx->tx_nwrq > 0);

                rc = -ECONNABORTED;
                vvrc = vv_return_ok;
                if (conn->ibc_state == IBNAL_CONN_ESTABLISHED) {
                        tx->tx_status = 0;
                        vvrc = vv_post_send_list(kibnal_data.kib_hca,
                                                 conn->ibc_qp,
                                                 tx->tx_nwrq,
                                                 tx->tx_wrq,
                                                 vv_operation_type_send_rc);
                        rc = (vvrc == vv_return_ok) ? 0 : -EIO;
                }

                if (rc != 0) {
                        /* NB credits are transferred in the actual
                         * message, which can only be the last work item */
                        conn->ibc_outstanding_credits += tx->tx_msg->ibm_credits;
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
                                CERROR ("Error %d posting transmit to "LPX64"\n", 
                                        vvrc, conn->ibc_peer->ibp_nid);
                        else
                                CDEBUG (D_NET, "Error %d posting transmit to "
                                        LPX64"\n", rc, conn->ibc_peer->ibp_nid);

                        kibnal_close_conn (conn, rc);

                        if (done)
                                kibnal_tx_done (tx);
                        return;
                }
        }

        spin_unlock(&conn->ibc_lock);
}

void
kibnal_tx_complete (kib_tx_t *tx, vv_comp_status_t vvrc)
{
        kib_conn_t   *conn = tx->tx_conn;
        int           failed = (vvrc != vv_comp_status_success);
        int           idle;

        CDEBUG(D_NET, "tx %p conn %p sending %d nwrq %d vvrc %d\n", 
               tx, conn, tx->tx_sending, tx->tx_nwrq, vvrc);

        LASSERT (tx->tx_sending > 0);

        if (failed &&
            tx->tx_status == 0 &&
            conn->ibc_state == IBNAL_CONN_ESTABLISHED)
                CERROR("tx -> "LPX64" type %x cookie "LPX64
                       "sending %d waiting %d: failed %d\n", 
                       conn->ibc_peer->ibp_nid, tx->tx_msg->ibm_type, 
                       tx->tx_cookie, tx->tx_sending, tx->tx_waiting, vvrc);

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

        if (failed)
                kibnal_close_conn (conn, -EIO);
        else
                kibnal_check_sends(conn);

        kibnal_conn_decref(conn);               /* ...until here */
}

void
kibnal_init_tx_msg (kib_tx_t *tx, int type, int body_nob)
{
        vv_scatgat_t *gl = &tx->tx_gl[tx->tx_nwrq];
        vv_wr_t      *wrq = &tx->tx_wrq[tx->tx_nwrq];
        int           nob = offsetof (kib_msg_t, ibm_u) + body_nob;

        LASSERT (tx->tx_nwrq >= 0 && 
                 tx->tx_nwrq < (1 + IBNAL_MAX_RDMA_FRAGS));
        LASSERT (nob <= IBNAL_MSG_SIZE);

        kibnal_init_msg(tx->tx_msg, type, body_nob);

        *gl = (vv_scatgat_t) {
                .v_address = (void *)((unsigned long)KIBNAL_TX_VADDR(tx)),
                .l_key     = KIBNAL_TX_LKEY(tx),
                .length    = nob,
        };

        memset(wrq, 0, sizeof(*wrq));

        wrq->wr_id = kibnal_ptr2wreqid(tx, IBNAL_WID_TX);
        wrq->wr_type = vv_wr_send;
        wrq->scatgat_list = gl;
        wrq->num_of_data_segments = 1;
        wrq->completion_notification = 1;
        wrq->type.send.solicited_event = 1;
        wrq->type.send.immidiate_data_indicator = 0;
        wrq->type.send.send_qp_type.rc_type.fance_indicator = 0;
        
        tx->tx_nwrq++;
}

int
kibnal_init_rdma (kib_tx_t *tx, int type, int nob,
                  kib_rdma_desc_t *dstrd, __u64 dstcookie)
{
        /* CAVEAT EMPTOR: this 'consumes' the frags in 'dstrd' */
        int              resid = nob;
        kib_msg_t       *ibmsg = tx->tx_msg;
        kib_rdma_desc_t *srcrd = tx->tx_rd;
        kib_rdma_frag_t *srcfrag;
        int              srcidx;
        kib_rdma_frag_t *dstfrag;
        int              dstidx;
        vv_scatgat_t    *gl;
        vv_wr_t         *wrq;
        int              wrknob;
        int              rc;

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
                gl->v_address = (void *)((unsigned long)kibnal_rf_addr(srcfrag));
                gl->length    = wrknob;
                gl->l_key     = srcrd->rd_key;

                wrq = &tx->tx_wrq[tx->tx_nwrq];

                wrq->wr_id = kibnal_ptr2wreqid(tx, IBNAL_WID_RDMA);
                wrq->completion_notification = 0;
                wrq->scatgat_list = gl;
                wrq->num_of_data_segments = 1;
                wrq->wr_type = vv_wr_rdma_write;
                wrq->type.send.solicited_event = 0;
                wrq->type.send.send_qp_type.rc_type.fance_indicator = 0;
                wrq->type.send.send_qp_type.rc_type.r_addr = kibnal_rf_addr(dstfrag);
                wrq->type.send.send_qp_type.rc_type.r_r_key = dstrd->rd_key;

                resid -= wrknob;
                if (wrknob < srcfrag->rf_nob) {
                        kibnal_rf_set(srcfrag, 
                                      kibnal_rf_addr(srcfrag) + resid, 
                                      srcfrag->rf_nob - wrknob);
                } else {
                        srcfrag++;
                        srcidx++;
                }
                
                if (wrknob < dstfrag->rf_nob) {
                        kibnal_rf_set(dstfrag,
                                      kibnal_rf_addr(dstfrag) + resid,
                                      dstfrag->rf_nob - wrknob);
                } else {
                        dstfrag++;
                        dstidx++;
                }
                
                tx->tx_nwrq++;
        }

        if (rc < 0)                             /* no RDMA if completing with failure */
                tx->tx_nwrq = 0;
        
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
kibnal_launch_tx (kib_tx_t *tx, ptl_nid_t nid)
{
        kib_peer_t      *peer;
        kib_conn_t      *conn;
        unsigned long    flags;
        rwlock_t        *g_lock = &kibnal_data.kib_global_lock;

        /* If I get here, I've committed to send, so I complete the tx with
         * failure on any problems */
        
        LASSERT (tx->tx_conn == NULL);          /* only set when assigned a conn */
        LASSERT (tx->tx_nwrq > 0);              /* work items have been set up */

        read_lock_irqsave(g_lock, flags);
        
        peer = kibnal_find_peer_locked (nid);
        if (peer == NULL) {
                read_unlock_irqrestore(g_lock, flags);
                tx->tx_status = -EHOSTUNREACH;
                tx->tx_waiting = 0;
                kibnal_tx_done (tx);
                return;
        }

        conn = kibnal_find_conn_locked (peer);
        if (conn != NULL) {
                kibnal_conn_addref(conn);       /* 1 ref for me... */
                read_unlock_irqrestore(g_lock, flags);
                
                kibnal_queue_tx (tx, conn);
                kibnal_conn_decref(conn);       /* ...to here */
                return;
        }
        
        /* Making one or more connections; I'll need a write lock... */
        read_unlock(g_lock);
        write_lock(g_lock);

        peer = kibnal_find_peer_locked (nid);
        if (peer == NULL) {
                write_unlock_irqrestore(g_lock, flags);
                tx->tx_status = -EHOSTUNREACH;
                tx->tx_waiting = 0;
                kibnal_tx_done (tx);
                return;
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

        if (peer->ibp_connecting == 0) {
                if (!time_after_eq(jiffies, peer->ibp_reconnect_time)) {
                        write_unlock_irqrestore(g_lock, flags);
                        tx->tx_status = -EHOSTUNREACH;
                        tx->tx_waiting = 0;
                        kibnal_tx_done (tx);
                        return;
                }
        
                peer->ibp_connecting = 1;
                kibnal_peer_addref(peer); /* extra ref for connd */
        
                spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
        
                list_add_tail (&peer->ibp_connd_list,
                               &kibnal_data.kib_connd_peers);
                wake_up (&kibnal_data.kib_connd_waitq);
        
                spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
        }
        
        /* A connection is being established; queue the message... */
        list_add_tail (&tx->tx_list, &peer->ibp_tx_queue);

        write_unlock_irqrestore(g_lock, flags);
}

int
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

ptl_err_t
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
               int           payload_offset,
               int           payload_nob)
{
        kib_msg_t  *ibmsg;
        kib_tx_t   *tx;
        int         nob;
        int         rc;
        int         n;

        /* NB 'private' is different depending on what we're sending.... */

        CDEBUG(D_NET, "sending %d bytes in %d frags to nid:"LPX64
               " pid %d\n", payload_nob, payload_niov, nid , pid);

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV);

        /* Thread context */
        LASSERT (!in_interrupt());
        /* payload is either all vaddrs or all pages */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));

        switch (type) {
        default:
                LBUG();
                return (PTL_FAIL);
                
        case PTL_MSG_REPLY: {
                /* reply's 'private' is the incoming receive */
                kib_rx_t *rx = private;

                LASSERT(rx != NULL);

                if (rx->rx_msg->ibm_type == IBNAL_MSG_IMMEDIATE) {
                        /* RDMA not expected */
                        nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob]);
                        if (nob > IBNAL_MSG_SIZE) {
                                CERROR("REPLY for "LPX64" too big (RDMA not requested):"
                                       "%d (max for message is %d)\n", 
                                       nid, payload_nob, IBNAL_MSG_SIZE);
                                CERROR("Can't REPLY IMMEDIATE %d to "LPX64"\n",
                                       nob, nid);
                                return PTL_FAIL;
                        }
                        break;
                }

                /* Incoming message consistent with RDMA? */
                if (rx->rx_msg->ibm_type != IBNAL_MSG_GET_REQ) {
                        CERROR("REPLY to "LPX64" bad msg type %x!!!\n",
                               nid, rx->rx_msg->ibm_type);
                        return PTL_FAIL;
                }

                /* NB rx_complete() will send GET_NAK when I return to it from
                 * here, unless I set rx_responded! */

                tx = kibnal_get_idle_tx(0);
                if (tx == NULL) {
                        CERROR("Can't get tx for REPLY to "LPX64"\n", nid);
                        return PTL_FAIL;
                }

                if (payload_nob == 0)
                        rc = 0;
                else if (payload_kiov == NULL)
                        rc = kibnal_setup_rd_iov(tx, tx->tx_rd, 0, 
                                                 payload_niov, payload_iov, 
                                                 payload_offset, payload_nob);
                else
                        rc = kibnal_setup_rd_kiov(tx, tx->tx_rd, 0,
                                                  payload_niov, payload_kiov,
                                                  payload_offset, payload_nob);
                if (rc != 0) {
                        CERROR("Can't setup GET src for "LPX64": %d\n", nid, rc);
                        kibnal_tx_done(tx);
                        return PTL_FAIL;
                }
                
                rc = kibnal_init_rdma(tx, IBNAL_MSG_GET_DONE, payload_nob,
                                      &rx->rx_msg->ibm_u.get.ibgm_rd,
                                      rx->rx_msg->ibm_u.get.ibgm_cookie);
                if (rc < 0) {
                        CERROR("Can't setup rdma for GET from "LPX64": %d\n", 
                               nid, rc);
                } else if (rc == 0) {
                        /* No RDMA: local completion may happen now! */
                        lib_finalize (&kibnal_lib, NULL, libmsg, PTL_OK);
                } else {
                        /* RDMA: lib_finalize(libmsg) when it completes */
                        tx->tx_libmsg[0] = libmsg;
                }

                kibnal_queue_tx(tx, rx->rx_conn);
                rx->rx_responded = 1;
                return (rc >= 0) ? PTL_OK : PTL_FAIL;
        }

        case PTL_MSG_GET:
                /* will the REPLY message be small enough not to need RDMA? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[libmsg->md->length]);
                if (nob <= IBNAL_MSG_SIZE)
                        break;

                tx = kibnal_get_idle_tx(1);     /* may block; caller is an app thread */
                LASSERT (tx != NULL);

                ibmsg = tx->tx_msg;
                ibmsg->ibm_u.get.ibgm_hdr = *hdr;
                ibmsg->ibm_u.get.ibgm_cookie = tx->tx_cookie;

                if ((libmsg->md->options & PTL_MD_KIOV) == 0)
                        rc = kibnal_setup_rd_iov(tx, &ibmsg->ibm_u.get.ibgm_rd,
                                                 vv_acc_r_mem_write,
                                                 libmsg->md->md_niov,
                                                 libmsg->md->md_iov.iov,
                                                 0, libmsg->md->length);
                else
                        rc = kibnal_setup_rd_kiov(tx, &ibmsg->ibm_u.get.ibgm_rd,
                                                  vv_acc_r_mem_write,
                                                  libmsg->md->md_niov,
                                                  libmsg->md->md_iov.kiov,
                                                  0, libmsg->md->length);
                if (rc != 0) {
                        CERROR("Can't setup GET sink for "LPX64": %d\n", nid, rc);
                        kibnal_tx_done(tx);
                        return PTL_FAIL;
                }

                n = ibmsg->ibm_u.get.ibgm_rd.rd_nfrag;
                nob = offsetof(kib_get_msg_t, ibgm_rd.rd_frags[n]);
                kibnal_init_tx_msg(tx, IBNAL_MSG_GET_REQ, nob);

                tx->tx_libmsg[1] = lib_create_reply_msg(&kibnal_lib, nid, libmsg);
                if (tx->tx_libmsg[1] == NULL) {
                        CERROR("Can't create reply for GET -> "LPX64"\n", nid);
                        kibnal_tx_done(tx);
                        return PTL_FAIL;
                }

                tx->tx_libmsg[0] = libmsg;      /* finalise libmsg[0,1] on completion */
                tx->tx_waiting = 1;             /* waiting for GET_DONE */
                kibnal_launch_tx(tx, nid);
                return PTL_OK;

        case PTL_MSG_ACK:
                LASSERT (payload_nob == 0);
                break;

        case PTL_MSG_PUT:
                /* Is the payload small enough not to need RDMA? */
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob]);
                if (nob <= IBNAL_MSG_SIZE)
                        break;

                tx = kibnal_get_idle_tx(1);     /* may block: caller is app thread */
                LASSERT (tx != NULL);

                if (payload_kiov == NULL)
                        rc = kibnal_setup_rd_iov(tx, tx->tx_rd, 0,
                                                 payload_niov, payload_iov,
                                                 payload_offset, payload_nob);
                else
                        rc = kibnal_setup_rd_kiov(tx, tx->tx_rd, 0,
                                                  payload_niov, payload_kiov,
                                                  payload_offset, payload_nob);
                if (rc != 0) {
                        CERROR("Can't setup PUT src for "LPX64": %d\n", nid, rc);
                        kibnal_tx_done(tx);
                        return PTL_FAIL;
                }

                ibmsg = tx->tx_msg;
                ibmsg->ibm_u.putreq.ibprm_hdr = *hdr;
                ibmsg->ibm_u.putreq.ibprm_cookie = tx->tx_cookie;
                kibnal_init_tx_msg(tx, IBNAL_MSG_PUT_REQ, sizeof(kib_putreq_msg_t));

                tx->tx_libmsg[0] = libmsg;      /* finalise libmsg on completion */
                tx->tx_waiting = 1;             /* waiting for PUT_{ACK,NAK} */
                kibnal_launch_tx(tx, nid);
                return PTL_OK;
        }

        LASSERT (offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[payload_nob])
                 <= IBNAL_MSG_SIZE);

        tx = kibnal_get_idle_tx(!(type == PTL_MSG_ACK ||
                                  type == PTL_MSG_REPLY));
        if (tx == NULL) {
                CERROR ("Can't send %d to "LPX64": tx descs exhausted\n", type, nid);
                return PTL_NO_SPACE;
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

        nob = offsetof(kib_immediate_msg_t, ibim_payload[payload_nob]);
        kibnal_init_tx_msg (tx, IBNAL_MSG_IMMEDIATE, nob);

        tx->tx_libmsg[0] = libmsg;              /* finalise libmsg on completion */
        kibnal_launch_tx(tx, nid);
        return PTL_OK;
}

ptl_err_t
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

ptl_err_t
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

ptl_err_t
kibnal_recvmsg (lib_nal_t *nal, void *private, lib_msg_t *libmsg,
                 unsigned int niov, struct iovec *iov, ptl_kiov_t *kiov,
                 size_t offset, int mlen, int rlen)
{
        kib_rx_t    *rx = private;
        kib_msg_t   *rxmsg = rx->rx_msg;
        kib_conn_t  *conn = rx->rx_conn;
        kib_tx_t    *tx;
        kib_msg_t   *txmsg;
        int          nob;
        int          rc;
        int          n;
        
        LASSERT (mlen <= rlen);
        LASSERT (mlen >= 0);
        LASSERT (!in_interrupt());
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));

        switch (rxmsg->ibm_type) {
        default:
                LBUG();
                
        case IBNAL_MSG_IMMEDIATE:
                nob = offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[rlen]);
                if (nob > IBNAL_MSG_SIZE) {
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

        case IBNAL_MSG_PUT_REQ:
                /* NB rx_complete() will send PUT_NAK when I return to it from
                 * here, unless I set rx_responded!  */

                if (mlen == 0) { /* No payload to RDMA */
                        lib_finalize(nal, NULL, libmsg, PTL_OK);
                        return PTL_OK;
                }

                tx = kibnal_get_idle_tx(0);
                if (tx == NULL) {
                        CERROR("Can't allocate tx for "LPX64"\n",
                               conn->ibc_peer->ibp_nid);
                        return PTL_FAIL;
                }

                txmsg = tx->tx_msg;
                if (kiov == NULL)
                        rc = kibnal_setup_rd_iov(tx, 
                                                 &txmsg->ibm_u.putack.ibpam_rd,
                                                 vv_acc_r_mem_write,
                                                 niov, iov, offset, mlen);
                else
                        rc = kibnal_setup_rd_kiov(tx,
                                                  &txmsg->ibm_u.putack.ibpam_rd,
                                                  vv_acc_r_mem_write,
                                                  niov, kiov, offset, mlen);
                if (rc != 0) {
                        CERROR("Can't setup PUT sink for "LPX64": %d\n",
                               conn->ibc_peer->ibp_nid, rc);
                        kibnal_tx_done(tx);
                        return PTL_FAIL;
                }

                txmsg->ibm_u.putack.ibpam_src_cookie = rxmsg->ibm_u.putreq.ibprm_cookie;
                txmsg->ibm_u.putack.ibpam_dst_cookie = tx->tx_cookie;

                n = tx->tx_msg->ibm_u.putack.ibpam_rd.rd_nfrag;
                nob = offsetof(kib_putack_msg_t, ibpam_rd.rd_frags[n]);
                kibnal_init_tx_msg(tx, IBNAL_MSG_PUT_ACK, nob);

                tx->tx_libmsg[0] = libmsg;      /* finalise libmsg on completion */
                tx->tx_waiting = 1;             /* waiting for PUT_DONE */
                kibnal_queue_tx(tx, conn);

                LASSERT (!rx->rx_responded);
                rx->rx_responded = 1;
                return PTL_OK;

        case IBNAL_MSG_GET_REQ:
                /* We get called here just to discard any junk after the
                 * GET hdr. */
                LASSERT (libmsg == NULL);
                lib_finalize (nal, NULL, libmsg, PTL_OK);
                return (PTL_OK);
        }
}

ptl_err_t
kibnal_recv (lib_nal_t *nal, void *private, lib_msg_t *msg,
              unsigned int niov, struct iovec *iov, 
              size_t offset, size_t mlen, size_t rlen)
{
        return (kibnal_recvmsg (nal, private, msg, niov, iov, NULL,
                                offset, mlen, rlen));
}

ptl_err_t
kibnal_recv_pages (lib_nal_t *nal, void *private, lib_msg_t *msg,
                     unsigned int niov, ptl_kiov_t *kiov, 
                     size_t offset, size_t mlen, size_t rlen)
{
        return (kibnal_recvmsg (nal, private, msg, niov, NULL, kiov,
                                offset, mlen, rlen));
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
kibnal_close_conn_locked (kib_conn_t *conn, int error)
{
        /* This just does the immmediate housekeeping.  'error' is zero for a
         * normal shutdown which can happen only after the connection has been
         * established.  If the connection is established, schedule the
         * connection to be finished off by the connd.  Otherwise the connd is
         * already dealing with it (either to set it up or tear it down).
         * Caller holds kib_global_lock exclusively in irq context */
        kib_peer_t       *peer = conn->ibc_peer;
        struct list_head *tmp;
        
        LASSERT (error != 0 || conn->ibc_state >= IBNAL_CONN_ESTABLISHED);

        if (error != 0 && conn->ibc_comms_error == 0)
                conn->ibc_comms_error = error;

        if (conn->ibc_state != IBNAL_CONN_ESTABLISHED)
                return; /* already being handled  */

        spin_lock(&conn->ibc_lock);
        
        if (error == 0 &&
            list_empty(&conn->ibc_tx_queue) &&
            list_empty(&conn->ibc_active_txs)) {
                CDEBUG(D_NET, "closing conn to "LPX64
                       " rx# "LPD64" tx# "LPD64"\n", 
                       peer->ibp_nid, conn->ibc_txseq, conn->ibc_rxseq);
        } else {
                CERROR("Closing conn to "LPX64": error %d%s%s"
                       " rx# "LPD64" tx# "LPD64"\n",
                       peer->ibp_nid, error,
                       list_empty(&conn->ibc_tx_queue) ? "" : "(sending)",
                       list_empty(&conn->ibc_active_txs) ? "" : "(waiting)",
                       conn->ibc_txseq, conn->ibc_rxseq);

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
        }

        spin_unlock(&conn->ibc_lock);

        /* connd takes ibc_list's ref */
        list_del (&conn->ibc_list);
        
        if (list_empty (&peer->ibp_conns) &&
            peer->ibp_persistence == 0) {
                /* Non-persistent peer with no more conns... */
                kibnal_unlink_peer_locked (peer);
        }

        kibnal_set_conn_state(conn, IBNAL_CONN_DISCONNECT1);

        spin_lock(&kibnal_data.kib_connd_lock);

        list_add_tail (&conn->ibc_list, &kibnal_data.kib_connd_conns);
        wake_up (&kibnal_data.kib_connd_waitq);
                
        spin_unlock(&kibnal_data.kib_connd_lock);
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
kibnal_conn_disconnected(kib_conn_t *conn)
{
        LIST_HEAD        (zombies); 
        struct list_head *tmp;
        struct list_head *nxt;
        kib_tx_t         *tx;

        /* I'm the connd */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (conn->ibc_state >= IBNAL_CONN_INIT);
        
        kibnal_set_conn_state(conn, IBNAL_CONN_DISCONNECTED);

        /* move QP to error state to make posted work items complete */
        kibnal_set_qp_state(conn, vv_qp_state_error);

        spin_lock(&conn->ibc_lock);

        /* Complete all tx descs not waiting for sends to complete.
         * NB we should be safe from RDMA now that the QP has changed state */

        list_for_each_safe (tmp, nxt, &conn->ibc_tx_queue) {
                tx = list_entry (tmp, kib_tx_t, tx_list);

                LASSERT (tx->tx_queued);

                tx->tx_status = -ECONNABORTED;
                tx->tx_queued = 0;
                tx->tx_waiting = 0;
                
                if (tx->tx_sending != 0)
                        continue;

                list_del (&tx->tx_list);
                list_add (&tx->tx_list, &zombies);
        }

        list_for_each_safe (tmp, nxt, &conn->ibc_active_txs) {
                tx = list_entry (tmp, kib_tx_t, tx_list);

                LASSERT (!tx->tx_queued);
                LASSERT (tx->tx_waiting ||
                         tx->tx_sending != 0);

                tx->tx_status = -ECONNABORTED;
                tx->tx_waiting = 0;
                
                if (tx->tx_sending != 0)
                        continue;

                list_del (&tx->tx_list);
                list_add (&tx->tx_list, &zombies);
        }
        
        spin_unlock(&conn->ibc_lock);

        while (!list_empty(&zombies)) {
                tx = list_entry (zombies.next, kib_tx_t, tx_list);

                list_del(&tx->tx_list);
                kibnal_tx_done (tx);
        }

        kibnal_handle_early_rxs(conn);
}

void
kibnal_peer_connect_failed (kib_peer_t *peer, int active)
{
        struct list_head  zombies;
        kib_tx_t         *tx;
        unsigned long     flags;

        /* Only the connd creates conns => single threaded */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (peer->ibp_reconnect_interval >= IBNAL_MIN_RECONNECT_INTERVAL);

        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        if (active) {
                LASSERT (peer->ibp_connecting != 0);
                peer->ibp_connecting--;
        } else {
                LASSERT (!kibnal_peer_active(peer));
        }
        
        if (peer->ibp_connecting != 0) {
                /* another connection attempt under way (loopback?)... */
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                return;
        }

        if (list_empty(&peer->ibp_conns)) {
                /* Say when active connection can be re-attempted */
                peer->ibp_reconnect_time = jiffies + peer->ibp_reconnect_interval;
                /* Increase reconnection interval */
                peer->ibp_reconnect_interval = MIN (peer->ibp_reconnect_interval * 2,
                                                    IBNAL_MAX_RECONNECT_INTERVAL);
        
                /* Take peer's blocked transmits to complete with error */
                list_add(&zombies, &peer->ibp_tx_queue);
                list_del_init(&peer->ibp_tx_queue);
                
                if (kibnal_peer_active(peer) &&
                    (peer->ibp_persistence == 0)) {
                        /* failed connection attempt on non-persistent peer */
                        kibnal_unlink_peer_locked (peer);
                }
        } else {
                /* Can't have blocked transmits if there are connections */
                LASSERT (list_empty(&peer->ibp_tx_queue));
        }
        
        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        if (list_empty (&zombies)) 
                return;
        
        CERROR ("Deleting messages for "LPX64": connection failed\n", peer->ibp_nid);
        do {
                tx = list_entry (zombies.next, kib_tx_t, tx_list);

                list_del (&tx->tx_list);
                /* complete now */
                tx->tx_status = -EHOSTUNREACH;
                kibnal_tx_done (tx);
        } while (!list_empty (&zombies));
}

void
kibnal_connreq_done(kib_conn_t *conn, int active, int status)
{
        static cm_reject_data_t   rej;

        struct list_head   txs;
        kib_peer_t        *peer = conn->ibc_peer;
        kib_peer_t        *peer2;
        unsigned long      flags;
        kib_tx_t          *tx;

        /* Only the connd creates conns => single threaded */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (conn->ibc_state < IBNAL_CONN_ESTABLISHED);

        if (active) {
                LASSERT (peer->ibp_connecting > 0);
        } else {
                LASSERT (!kibnal_peer_active(peer));
        }
        
        PORTAL_FREE(conn->ibc_connvars, sizeof(*conn->ibc_connvars));
        conn->ibc_connvars = NULL;

        if (status != 0) {
                /* failed to establish connection */
                switch (conn->ibc_state) {
                default:
                        LBUG();
                case IBNAL_CONN_ACTIVE_CHECK_REPLY:
                        /* got a connection reply but failed checks */
                        LASSERT (active);
                        memset(&rej, 0, sizeof(rej));
                        rej.reason = cm_rej_code_usr_rej;
                        cm_reject(conn->ibc_cep, &rej);
                        break;

                case IBNAL_CONN_ACTIVE_CONNECT:
                        LASSERT (active);
                        cm_cancel(conn->ibc_cep);
                        kibnal_pause(HZ/10);
                        /* cm_connect() failed immediately or
                         * callback returned failure */
                        break;

                case IBNAL_CONN_ACTIVE_ARP:
                        LASSERT (active);
                        /* ibat_get_ib_data() failed immediately 
                         * or callback returned failure */
                        break;

                case IBNAL_CONN_INIT:
                        break;

                case IBNAL_CONN_PASSIVE_WAIT:
                        LASSERT (!active);
                        /* cm_accept callback returned failure */
                        break;
                }

                kibnal_peer_connect_failed(conn->ibc_peer, active);
                kibnal_conn_disconnected(conn);
                return;
        }

        /* connection established */
        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        if (active) {
                LASSERT(conn->ibc_state == IBNAL_CONN_ACTIVE_RTU);
        } else {
                LASSERT(conn->ibc_state == IBNAL_CONN_PASSIVE_WAIT);
        }
        
        kibnal_set_conn_state(conn, IBNAL_CONN_ESTABLISHED);

        if (!active) {
                peer2 = kibnal_find_peer_locked(peer->ibp_nid);
                if (peer2 != NULL) {
                        /* already in the peer table; swap */
                        conn->ibc_peer = peer2;
                        kibnal_peer_addref(peer2);
                        kibnal_peer_decref(peer);
                        peer = conn->ibc_peer;
                } else {
                        /* add 'peer' to the peer table */
                        kibnal_peer_addref(peer);
                        list_add_tail(&peer->ibp_list,
                                      kibnal_nid2peerlist(peer->ibp_nid));
                }
        }
        
        /* Add conn to peer's list and nuke any dangling conns from a different
         * peer instance... */
        kibnal_conn_addref(conn);               /* +1 ref for ibc_list */
        list_add(&conn->ibc_list, &peer->ibp_conns);
        kibnal_close_stale_conns_locked (conn->ibc_peer,
                                         conn->ibc_incarnation);

        if (!kibnal_peer_active(peer) ||        /* peer has been deleted */
            conn->ibc_comms_error != 0 ||       /* comms error */
            conn->ibc_disconnect) {             /* need to disconnect */
                
                /* start to shut down connection */
                kibnal_close_conn_locked(conn, -ECONNABORTED);

                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                kibnal_peer_connect_failed(peer, active);
                return;
        }

        if (active)
                peer->ibp_connecting--;

        /* grab pending txs while I have the lock */
        list_add(&txs, &peer->ibp_tx_queue);
        list_del_init(&peer->ibp_tx_queue);
        
        /* reset reconnect interval for next attempt */
        peer->ibp_reconnect_interval = IBNAL_MIN_RECONNECT_INTERVAL;
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

        /* schedule blocked rxs */
        kibnal_handle_early_rxs(conn);
}

void
kibnal_cm_callback(cm_cep_handle_t cep, cm_conn_data_t *cmdata, void *arg)
{
        static cm_dreply_data_t drep;           /* just zeroed space */
        
        kib_conn_t             *conn = (kib_conn_t *)arg;
        unsigned long           flags;
        
        /* CAVEAT EMPTOR: tasklet context */

        switch (cmdata->status) {
        default:
                LBUG();
                
        case cm_event_disconn_request:
                /* IBNAL_CONN_ACTIVE_RTU:  gets closed in kibnal_connreq_done
                 * IBNAL_CONN_ESTABLISHED: I start it closing
                 * otherwise:              it's closing anyway */
                cm_disconnect(conn->ibc_cep, NULL, &drep);
                cm_cancel(conn->ibc_cep);

                write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
                LASSERT (!conn->ibc_disconnect);
                conn->ibc_disconnect = 1;

                switch (conn->ibc_state) {
                default:
                        LBUG();

                case IBNAL_CONN_ACTIVE_RTU:
                        /* kibnal_connreq_done is getting there; It'll see
                         * ibc_disconnect set... */
                        kibnal_conn_decref(conn); /* lose my ref */
                        break;

                case IBNAL_CONN_ESTABLISHED:
                        /* kibnal_connreq_done got there already; get
                         * disconnect going... */
                        kibnal_close_conn_locked(conn, 0);
                        kibnal_conn_decref(conn); /* lose my ref */
                        break;

                case IBNAL_CONN_DISCONNECT1:
                        /* kibnal_terminate_conn is getting there; It'll see
                         * ibc_disconnect set... */
                        kibnal_conn_decref(conn); /* lose my ref */
                        break;

                case IBNAL_CONN_DISCONNECT2:
                        /* kibnal_terminate_conn got there already; complete
                         * the disconnect.  NB kib_connd_conns takes my ref */
                        spin_lock(&kibnal_data.kib_connd_lock);
                        list_add_tail(&conn->ibc_list, &kibnal_data.kib_connd_conns);
                        wake_up(&kibnal_data.kib_connd_waitq);
                        spin_unlock(&kibnal_data.kib_connd_lock);
                        break;
                }
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                return;
                
        case cm_event_disconn_timeout:
        case cm_event_disconn_reply:
                write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
                LASSERT (conn->ibc_state == IBNAL_CONN_DISCONNECT2);
                LASSERT (!conn->ibc_disconnect);
                conn->ibc_disconnect = 1;

                /* kibnal_terminate_conn sent the disconnect request.  
                 * NB kib_connd_conns takes my ref */
                spin_lock(&kibnal_data.kib_connd_lock);
                list_add_tail(&conn->ibc_list, &kibnal_data.kib_connd_conns);
                wake_up(&kibnal_data.kib_connd_waitq);
                spin_unlock(&kibnal_data.kib_connd_lock);

                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                break;
                
        case cm_event_connected:
        case cm_event_conn_timeout:
        case cm_event_conn_reject:
                LASSERT (conn->ibc_state == IBNAL_CONN_PASSIVE_WAIT);
                conn->ibc_connvars->cv_conndata = *cmdata;
                
                spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
                list_add_tail(&conn->ibc_list, &kibnal_data.kib_connd_conns);
                wake_up(&kibnal_data.kib_connd_waitq);
                spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
                break;
        }
}

void
kibnal_check_passive_wait(kib_conn_t *conn)
{
        int     rc;

        switch (conn->ibc_connvars->cv_conndata.status) {
        default:
                LBUG();
                
        case cm_event_connected:
                kibnal_conn_addref(conn); /* ++ ref for CM callback */
                rc = kibnal_set_qp_state(conn, vv_qp_state_rts);
                if (rc != 0)
                        conn->ibc_comms_error = rc;
                /* connection _has_ been established; it's just that we've had
                 * an error immediately... */
                kibnal_connreq_done(conn, 0, 0);
                break;
                
        case cm_event_conn_timeout:
                kibnal_connreq_done(conn, 0, -ETIMEDOUT);
                break;
                
        case cm_event_conn_reject:
                kibnal_connreq_done(conn, 0, -ECONNRESET);
                break;
        }
}

void
kibnal_recv_connreq(cm_cep_handle_t *cep, cm_request_data_t *cmreq)
{
        static cm_reply_data_t  reply;
        static cm_reject_data_t reject;

        kib_msg_t          *rxmsg = (kib_msg_t *)cmreq->priv_data;
        kib_msg_t          *txmsg;
        kib_conn_t         *conn = NULL;
        int                 rc = 0;
        kib_connvars_t     *cv;
        kib_peer_t         *tmp_peer;
        cm_return_t         cmrc;
        vv_return_t         vvrc;
        
        /* I'm the connd executing in thread context
         * No concurrency problems with static data! */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);

        if (cmreq->sid != IBNAL_SERVICE_NUMBER) {
                CERROR(LPX64" != IBNAL_SERVICE_NUMBER("LPX64")\n",
                       cmreq->sid, (__u64)IBNAL_SERVICE_NUMBER);
                goto reject;
        }

        rc = kibnal_unpack_msg(rxmsg, cm_REQ_priv_data_len);
        if (rc != 0) {
                CERROR("Can't parse connection request: %d\n", rc);
                goto reject;
        }

        if (rxmsg->ibm_type != IBNAL_MSG_CONNREQ) {
                CERROR("Unexpected connreq msg type: %x from "LPX64"\n",
                       rxmsg->ibm_type, rxmsg->ibm_srcnid);
                goto reject;
        }

        if (rxmsg->ibm_dstnid != kibnal_lib.libnal_ni.ni_pid.nid) {
                CERROR("Can't accept "LPX64": bad dst nid "LPX64"\n",
                       rxmsg->ibm_srcnid, rxmsg->ibm_dstnid);
                goto reject;
        }

        if (rxmsg->ibm_u.connparams.ibcp_queue_depth != IBNAL_MSG_QUEUE_SIZE) {
                CERROR("Can't accept "LPX64": incompatible queue depth %d (%d wanted)\n",
                       rxmsg->ibm_srcnid, rxmsg->ibm_u.connparams.ibcp_queue_depth, 
                       IBNAL_MSG_QUEUE_SIZE);
                goto reject;
        }

        if (rxmsg->ibm_u.connparams.ibcp_max_msg_size > IBNAL_MSG_SIZE) {
                CERROR("Can't accept "LPX64": message size %d too big (%d max)\n",
                       rxmsg->ibm_srcnid, rxmsg->ibm_u.connparams.ibcp_max_msg_size, 
                       IBNAL_MSG_SIZE);
                goto reject;
        }
                
        if (rxmsg->ibm_u.connparams.ibcp_max_frags > IBNAL_MAX_RDMA_FRAGS) {
                CERROR("Can't accept "LPX64": max frags %d too big (%d max)\n",
                       rxmsg->ibm_srcnid, rxmsg->ibm_u.connparams.ibcp_max_frags, 
                       IBNAL_MAX_RDMA_FRAGS);
                goto reject;
        }
                
        conn = kibnal_create_conn(cep);
        if (conn == NULL) {
                CERROR("Can't create conn for "LPX64"\n", rxmsg->ibm_srcnid);
                goto reject;
        }
        
        /* assume 'rxmsg->ibm_srcnid' is a new peer */
        tmp_peer = kibnal_create_peer (rxmsg->ibm_srcnid);
        if (tmp_peer == NULL) {
                CERROR("Can't create tmp peer for "LPX64"\n", rxmsg->ibm_srcnid);
                kibnal_conn_decref(conn);
                conn = NULL;
                goto reject;
        }

        conn->ibc_peer = tmp_peer;              /* conn takes over my ref */
        conn->ibc_incarnation = rxmsg->ibm_srcstamp;
        conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;

        cv = conn->ibc_connvars;

        cv->cv_txpsn          = cmreq->cep_data.start_psn;
        cv->cv_remote_qpn     = cmreq->cep_data.qpn;
        cv->cv_path           = cmreq->path_data.path;
        cv->cv_rnr_count      = cmreq->cep_data.rtr_retry_cnt;
        // XXX                  cmreq->cep_data.retry_cnt;
        cv->cv_port           = cmreq->cep_data.local_port_num;

        vvrc = gid2gid_index(kibnal_data.kib_hca, cv->cv_port,
                             &cv->cv_path.sgid, &cv->cv_sgid_index);
        LASSERT (vvrc == vv_return_ok);
        
        vvrc = pkey2pkey_index(kibnal_data.kib_hca, cv->cv_port,
                               cv->cv_path.pkey, &cv->cv_pkey_index);
        LASSERT (vvrc == vv_return_ok);

        rc = kibnal_set_qp_state(conn, vv_qp_state_init);
        if (rc != 0)
                goto reject;

        rc = kibnal_post_receives(conn);
        if (rc != 0) {
                CERROR("Can't post receives for "LPX64"\n", rxmsg->ibm_srcnid);
                goto reject;
        }

        rc = kibnal_set_qp_state(conn, vv_qp_state_rtr);
        if (rc != 0)
                goto reject;
        
        memset(&reply, 0, sizeof(reply));
        reply.qpn                 = cv->cv_local_qpn;
        reply.qkey                = IBNAL_QKEY;
        reply.start_psn           = cv->cv_rxpsn;
        reply.arb_initiator_depth = IBNAL_ARB_INITIATOR_DEPTH;
        reply.arb_resp_res        = IBNAL_ARB_RESP_RES;
        reply.failover_accepted   = IBNAL_FAILOVER_ACCEPTED;
        reply.rnr_retry_count     = cv->cv_rnr_count;
        reply.targ_ack_delay      = kibnal_data.kib_hca_attrs.ack_delay;
        
        txmsg = (kib_msg_t *)&reply.priv_data;
        kibnal_init_msg(txmsg, IBNAL_MSG_CONNACK, 
                        sizeof(txmsg->ibm_u.connparams));
        LASSERT (txmsg->ibm_nob <= cm_REP_priv_data_len);
        txmsg->ibm_u.connparams.ibcp_queue_depth = IBNAL_MSG_QUEUE_SIZE;
        txmsg->ibm_u.connparams.ibcp_max_msg_size = IBNAL_MSG_SIZE;
        txmsg->ibm_u.connparams.ibcp_max_frags = IBNAL_MAX_RDMA_FRAGS;
        kibnal_pack_msg(txmsg, 0, rxmsg->ibm_srcnid, rxmsg->ibm_srcstamp, 0);
        
        kibnal_set_conn_state(conn, IBNAL_CONN_PASSIVE_WAIT);
        
        cmrc = cm_accept(conn->ibc_cep, &reply, NULL,
                         kibnal_cm_callback, conn);

        if (cmrc == cm_stat_success)
                return;                         /* callback has got my ref on conn */

        /* back out state change (no callback happening) */
        kibnal_set_conn_state(conn, IBNAL_CONN_INIT);
        rc = -EIO;
                
 reject:
        CERROR("Rejected connreq from "LPX64"\n", rxmsg->ibm_srcnid);

        memset(&reject, 0, sizeof(reject));
        reject.reason = cm_rej_code_usr_rej;
        cm_reject(cep, &reject);

        if (conn != NULL) {
                LASSERT (rc != 0);
                kibnal_connreq_done(conn, 0, rc);
        } else {
                cm_destroy_cep(cep);
        }
}

void
kibnal_listen_callback(cm_cep_handle_t cep, cm_conn_data_t *data, void *arg)
{
        cm_request_data_t  *cmreq = &data->data.request;
        kib_pcreq_t        *pcr;
        unsigned long       flags;
        
        LASSERT (arg == NULL);

        if (data->status != cm_event_conn_request) {
                CERROR("status %d is not cm_event_conn_request\n",
                       data->status);
                return;
        }

        PORTAL_ALLOC_ATOMIC(pcr, sizeof(*pcr));
        if (pcr == NULL) {
                CERROR("Can't allocate passive connreq\n");

                cm_reject(cep, &((cm_reject_data_t) /* NB RO struct */
                                 {.reason = cm_rej_code_no_res,}));
                cm_destroy_cep(cep);
                return;
        }

        pcr->pcr_cep = cep;
        pcr->pcr_cmreq = *cmreq;
        
        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);

        list_add_tail(&pcr->pcr_list, &kibnal_data.kib_connd_pcreqs);
        wake_up(&kibnal_data.kib_connd_waitq);
        
        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
}


void
kibnal_active_connect_callback (cm_cep_handle_t cep, cm_conn_data_t *cd, 
                                void *arg)
{
        /* CAVEAT EMPTOR: tasklet context */
        kib_conn_t       *conn = (kib_conn_t *)arg;
        kib_connvars_t   *cv = conn->ibc_connvars;
        unsigned long     flags;

        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_CONNECT);
        cv->cv_conndata = *cd;

        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
        /* connd takes my ref */
        list_add_tail(&conn->ibc_list, &kibnal_data.kib_connd_conns);
        wake_up(&kibnal_data.kib_connd_waitq);
        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
}

void
kibnal_connect_conn (kib_conn_t *conn)
{
        static cm_request_data_t  cmreq;
        kib_msg_t                *msg = (kib_msg_t *)&cmreq.priv_data;
        kib_connvars_t           *cv = conn->ibc_connvars;
        kib_peer_t               *peer = conn->ibc_peer;
        cm_return_t               cmrc;
        
        /* Only called by connd => statics OK */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_ARP);

        memset(&cmreq, 0, sizeof(cmreq));
        
        cmreq.sid = IBNAL_SERVICE_NUMBER;

        cmreq.cep_data.ca_guid              = kibnal_data.kib_hca_attrs.guid;
        cmreq.cep_data.qpn                  = cv->cv_local_qpn;
        cmreq.cep_data.retry_cnt            = IBNAL_RETRY_CNT;
        cmreq.cep_data.rtr_retry_cnt        = IBNAL_RNR_CNT;
        cmreq.cep_data.start_psn            = cv->cv_rxpsn;
        cmreq.cep_data.end_to_end_flow_ctrl = IBNAL_EE_FLOW_CNT;
        // XXX ack_timeout?
        // offered_resp_res
        // offered_initiator_depth

        cmreq.path_data.subn_local  = IBNAL_LOCAL_SUB;
        cmreq.path_data.path        = cv->cv_path;
        
        kibnal_init_msg(msg, IBNAL_MSG_CONNREQ, sizeof(msg->ibm_u.connparams));
        LASSERT(msg->ibm_nob <= cm_REQ_priv_data_len);
        msg->ibm_u.connparams.ibcp_queue_depth = IBNAL_MSG_QUEUE_SIZE;
        msg->ibm_u.connparams.ibcp_max_msg_size = IBNAL_MSG_SIZE;
        msg->ibm_u.connparams.ibcp_max_frags = IBNAL_MAX_RDMA_FRAGS;
        kibnal_pack_msg(msg, 0, peer->ibp_nid, 0, 0);
        
        CDEBUG(D_NET, "Connecting %p to "LPX64"\n", conn, peer->ibp_nid);

        kibnal_conn_addref(conn);               /* ++ref for CM callback */
        kibnal_set_conn_state(conn, IBNAL_CONN_ACTIVE_CONNECT);

        cmrc = cm_connect(conn->ibc_cep, &cmreq, 
                          kibnal_active_connect_callback, conn);
        if (cmrc == cm_stat_success) {
                CDEBUG(D_NET, "connection REQ sent to "LPX64"\n",
                       peer->ibp_nid);
                return;
        }

        CERROR ("Connect "LPX64" failed: %d\n", peer->ibp_nid, cmrc);
        kibnal_conn_decref(conn);       /* drop callback's ref */
        kibnal_connreq_done(conn, 1, -EHOSTUNREACH);
}

void
kibnal_check_connreply (kib_conn_t *conn)
{
        static cm_rtu_data_t  rtu;

        kib_connvars_t   *cv = conn->ibc_connvars;
        cm_reply_data_t  *reply = &cv->cv_conndata.data.reply;
        kib_msg_t        *msg = (kib_msg_t *)&reply->priv_data;
        kib_peer_t       *peer = conn->ibc_peer;
        cm_return_t       cmrc;
        cm_cep_handle_t   cep;
        unsigned long     flags;
        int               rc;

        /* Only called by connd => statics OK */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_CONNECT);

        if (cv->cv_conndata.status == cm_event_conn_reply) {
                cv->cv_remote_qpn = reply->qpn;
                cv->cv_txpsn      = reply->start_psn;
                // XXX              reply->targ_ack_delay;
                cv->cv_rnr_count  = reply->rnr_retry_count;

                kibnal_set_conn_state(conn, IBNAL_CONN_ACTIVE_CHECK_REPLY);

                rc = kibnal_unpack_msg(msg, cm_REP_priv_data_len);
                if (rc != 0) {
                        CERROR("Can't unpack reply from "LPX64"\n",
                               peer->ibp_nid);
                        kibnal_connreq_done(conn, 1, rc);
                        return;
                }

                if (msg->ibm_type != IBNAL_MSG_CONNACK ) {
                        CERROR("Unexpected message type %d from "LPX64"\n",
                               msg->ibm_type, peer->ibp_nid);
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        return;
                }

                if (msg->ibm_u.connparams.ibcp_queue_depth != IBNAL_MSG_QUEUE_SIZE) {
                        CERROR(LPX64" has incompatible queue depth %d(%d wanted)\n",
                               peer->ibp_nid, msg->ibm_u.connparams.ibcp_queue_depth,
                               IBNAL_MSG_QUEUE_SIZE);
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        return;
                }
                
                if (msg->ibm_u.connparams.ibcp_max_msg_size > IBNAL_MSG_SIZE) {
                        CERROR(LPX64" max message size %d too big (%d max)\n",
                               peer->ibp_nid, msg->ibm_u.connparams.ibcp_max_msg_size, 
                               IBNAL_MSG_SIZE);
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        return;
                }

                if (msg->ibm_u.connparams.ibcp_max_frags > IBNAL_MAX_RDMA_FRAGS) {
                        CERROR(LPX64" max frags %d too big (%d max)\n",
                               peer->ibp_nid, msg->ibm_u.connparams.ibcp_max_frags, 
                               IBNAL_MAX_RDMA_FRAGS);
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        return;
                }
                
                read_lock_irqsave(&kibnal_data.kib_global_lock, flags);
                rc = (msg->ibm_dstnid != kibnal_lib.libnal_ni.ni_pid.nid ||
                      msg->ibm_dststamp != kibnal_data.kib_incarnation) ?
                     -ESTALE : 0;
                read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                if (rc != 0) {
                        CERROR("Stale connection reply from "LPX64"\n",
                               peer->ibp_nid);
                        kibnal_connreq_done(conn, 1, rc);
                        return;
                }

                conn->ibc_incarnation = msg->ibm_srcstamp;
                conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;
                
                rc = kibnal_post_receives(conn);
                if (rc != 0) {
                        CERROR("Can't post receives for "LPX64"\n",
                               peer->ibp_nid);
                        kibnal_connreq_done(conn, 1, rc);
                        return;
                }
                
                rc = kibnal_set_qp_state(conn, vv_qp_state_rtr);
                if (rc != 0) {
                        kibnal_connreq_done(conn, 1, rc);
                        return;
                }
                
                rc = kibnal_set_qp_state(conn, vv_qp_state_rts);
                if (rc != 0) {
                        kibnal_connreq_done(conn, 1, rc);
                        return;
                }
                
                kibnal_set_conn_state(conn, IBNAL_CONN_ACTIVE_RTU);
                kibnal_conn_addref(conn);       /* ++for CM callback */
                
                memset(&rtu, 0, sizeof(rtu));
                cmrc = cm_accept(conn->ibc_cep, NULL, &rtu,
                                 kibnal_cm_callback, conn);
                if (cmrc == cm_stat_success) {
                        /* Now I'm racing with disconnect signalled by
                         * kibnal_cm_callback */
                        kibnal_connreq_done(conn, 1, 0);
                        return;
                }

                CERROR("cm_accept "LPX64" failed: %d\n", peer->ibp_nid, cmrc);
                /* Back out of RTU: no callback coming */
                kibnal_set_conn_state(conn, IBNAL_CONN_ACTIVE_CHECK_REPLY);
                kibnal_conn_decref(conn);
                kibnal_connreq_done(conn, 1, -EIO);
                return;
        }

        if (cv->cv_conndata.status == cm_event_conn_reject) {

                if (cv->cv_conndata.data.reject.reason != cm_rej_code_stale_conn) {
                        CERROR("conn -> "LPX64" rejected: %d\n", peer->ibp_nid,
                               cv->cv_conndata.data.reject.reason);
                        kibnal_connreq_done(conn, 1, -ECONNREFUSED);
                        return;
                }

                CWARN ("conn -> "LPX64" stale: retrying\n", peer->ibp_nid);

                cep = cm_create_cep(cm_cep_transp_rc);
                if (cep == NULL) {
                        CERROR("Can't create new CEP\n");
                        kibnal_connreq_done(conn, 1, -ENOMEM);
                        return;
                }

                cmrc = cm_cancel(conn->ibc_cep);
                LASSERT (cmrc == cm_stat_success);
                cmrc = cm_destroy_cep(conn->ibc_cep);
                LASSERT (cmrc == cm_stat_success);

                conn->ibc_cep = cep;

                /* retry connect */
                kibnal_set_conn_state(conn, IBNAL_CONN_ACTIVE_ARP);
                kibnal_connect_conn(conn);
                return;
        }

        CERROR("conn -> "LPX64" failed: %d\n", peer->ibp_nid,
               cv->cv_conndata.status);
        kibnal_connreq_done(conn, 1, -ECONNABORTED);
}

void
kibnal_send_connreq (kib_conn_t *conn)
{
        kib_peer_t           *peer = conn->ibc_peer;
        kib_connvars_t       *cv = conn->ibc_connvars;
        ibat_arp_data_t      *arp = &cv->cv_arp;
        ib_path_record_v2_t  *path = &cv->cv_path;
        vv_return_t           vvrc;
        int                   rc;

        /* Only called by connd => statics OK */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_ARP);
        
        if (cv->cv_arprc != ibat_stat_ok) {
                CERROR("Can't Arp "LPX64"@%u.%u.%u.%u: %d\n", peer->ibp_nid,
                       HIPQUAD(peer->ibp_ip), cv->cv_arprc);
                kibnal_connreq_done(conn, 1, -ENETUNREACH);
                return;
        }

        if ((arp->mask & IBAT_PRI_PATH_VALID) != 0) {
                CDEBUG(D_NET, "Got valid path for "LPX64"\n", peer->ibp_nid);

                *path = *arp->primary_path;

                vvrc = base_gid2port_num(kibnal_data.kib_hca, &path->sgid,
                                         &cv->cv_port);
                LASSERT (vvrc == vv_return_ok);

                vvrc = gid2gid_index(kibnal_data.kib_hca, cv->cv_port,
                                     &path->sgid, &cv->cv_sgid_index);
                LASSERT (vvrc == vv_return_ok);

                vvrc = pkey2pkey_index(kibnal_data.kib_hca, cv->cv_port,
                                       path->pkey, &cv->cv_pkey_index);
                LASSERT (vvrc == vv_return_ok);

                path->mtu = IBNAL_IB_MTU;

        } else if ((arp->mask & IBAT_LID_VALID) != 0) {
                CWARN("Creating new path record for "LPX64"@%u.%u.%u.%u\n",
                      peer->ibp_nid, HIPQUAD(peer->ibp_ip));

                cv->cv_pkey_index = IBNAL_PKEY_IDX;
                cv->cv_sgid_index = IBNAL_SGID_IDX;
                cv->cv_port = arp->local_port_num;

                memset(path, 0, sizeof(*path));

                vvrc = port_num2base_gid(kibnal_data.kib_hca, cv->cv_port,
                                         &path->sgid);
                LASSERT (vvrc == vv_return_ok);

                vvrc = port_num2base_lid(kibnal_data.kib_hca, cv->cv_port,
                                         &path->slid);
                LASSERT (vvrc == vv_return_ok);

                path->dgid          = arp->gid;
                path->sl            = IBNAL_SERVICE_LEVEL;
                path->dlid          = arp->lid;
                path->mtu           = IBNAL_IB_MTU;
                path->rate          = IBNAL_STATIC_RATE;
                path->pkt_life_time = IBNAL_PKT_LIFETIME;
                path->pkey          = IBNAL_PKEY;
                path->traffic_class = IBNAL_TRAFFIC_CLASS;
        } else {
                CERROR("Can't Arp "LPX64"@%u.%u.%u.%u: no PATH or LID\n", 
                       peer->ibp_nid, HIPQUAD(peer->ibp_ip));
                kibnal_connreq_done(conn, 1, -ENETUNREACH);
                return;
        }

        rc = kibnal_set_qp_state(conn, vv_qp_state_init);
        if (rc != 0) {
                kibnal_connreq_done(conn, 1, rc);
        }

        /* do the actual connection request */
        kibnal_connect_conn(conn);
}

void
kibnal_arp_callback (ibat_stat_t arprc, ibat_arp_data_t *arp_data, void *arg)
{
        /* CAVEAT EMPTOR: tasklet context */
        kib_conn_t      *conn = (kib_conn_t *)arg;
        kib_peer_t      *peer = conn->ibc_peer;
        unsigned long    flags;

        CDEBUG(D_NET, "Arp "LPX64"@%u.%u.%u.%u rc %d LID %s PATH %s\n",
               peer->ibp_nid, HIPQUAD(peer->ibp_ip), arprc,
               (arp_data->mask & IBAT_LID_VALID) == 0 ? "invalid" : "valid",
               (arp_data->mask & IBAT_PRI_PATH_VALID) == 0 ? "invalid" : "valid");
        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_ARP);

        conn->ibc_connvars->cv_arprc = arprc;
        if (arprc == ibat_stat_ok)
                conn->ibc_connvars->cv_arp = *arp_data;
        
        /* connd takes over my ref on conn */
        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
        
        list_add_tail(&conn->ibc_list, &kibnal_data.kib_connd_conns);
        wake_up(&kibnal_data.kib_connd_waitq);
        
        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
}

void
kibnal_arp_peer (kib_peer_t *peer)
{
        cm_cep_handle_t  cep;
        kib_conn_t      *conn;
        int              ibatrc;

        /* Only the connd does this (i.e. single threaded) */
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (peer->ibp_connecting != 0);

        cep = cm_create_cep(cm_cep_transp_rc);
        if (cep == NULL) {
                CERROR ("Can't create cep for conn->"LPX64"\n",
                        peer->ibp_nid);
                kibnal_peer_connect_failed(peer, 1);
                return;
        }

        conn = kibnal_create_conn(cep);
        if (conn == NULL) {
                CERROR ("Can't allocate conn->"LPX64"\n",
                        peer->ibp_nid);
                cm_destroy_cep(cep);
                kibnal_peer_connect_failed(peer, 1);
                return;
        }

        conn->ibc_peer = peer;
        kibnal_peer_addref(peer);

        kibnal_set_conn_state(conn, IBNAL_CONN_ACTIVE_ARP);

        ibatrc = ibat_get_ib_data(htonl(peer->ibp_ip), INADDR_ANY, 
                                  ibat_paths_primary,
                                  &conn->ibc_connvars->cv_arp, 
                                  kibnal_arp_callback, conn, 0);
        CDEBUG(D_NET,"ibatrc %d\n", ibatrc);
        switch (ibatrc) {
        default:
                LBUG();
                
        case ibat_stat_pending:
                /* NB callback has my ref on conn */
                break;
                
        case ibat_stat_ok:
                /* Immediate return (ARP cache hit) == no callback. */
                kibnal_send_connreq(conn);
                kibnal_conn_decref(conn);
                break;

        case ibat_stat_error:
        case ibat_stat_timeout:
        case ibat_stat_not_found:
                CERROR("Arp "LPX64"@%u.%u.%u.%u failed: %d\n", peer->ibp_nid,
                       HIPQUAD(peer->ibp_ip), ibatrc);
                kibnal_connreq_done(conn, 1, -ENETUNREACH);
                kibnal_conn_decref(conn);
                break;
        }
}

int
kibnal_conn_timed_out (kib_conn_t *conn)
{
        kib_tx_t          *tx;
        struct list_head  *ttmp;

        spin_lock(&conn->ibc_lock);

        list_for_each (ttmp, &conn->ibc_tx_queue) {
                tx = list_entry (ttmp, kib_tx_t, tx_list);

                LASSERT (tx->tx_queued);

                if (time_after_eq (jiffies, tx->tx_deadline)) {
                        spin_unlock(&conn->ibc_lock);
                        return 1;
                }
        }

        list_for_each (ttmp, &conn->ibc_active_txs) {
                tx = list_entry (ttmp, kib_tx_t, tx_list);

                LASSERT (!tx->tx_queued);
                LASSERT (tx->tx_waiting ||
                         tx->tx_sending != 0);

                if (time_after_eq (jiffies, tx->tx_deadline)) {
                        spin_unlock(&conn->ibc_lock);
                        return 1;
                }
        }

        spin_unlock(&conn->ibc_lock);
        return 0;
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

                        /* Handle timeout by closing the whole connection.  We
                         * can only be sure RDMA activity has ceased once the
                         * QP has been modified. */
                        
                        kibnal_conn_addref(conn); /* 1 ref for me... */

                        read_unlock_irqrestore(&kibnal_data.kib_global_lock, 
                                               flags);

                        CERROR("Timed out RDMA with "LPX64"\n",
                               peer->ibp_nid);

                        kibnal_close_conn (conn, -ETIMEDOUT);
                        kibnal_conn_decref(conn); /* ...until here */

                        /* start again now I've dropped the lock */
                        goto again;
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
}

void
kibnal_disconnect_conn (kib_conn_t *conn)
{
        static cm_drequest_data_t dreq;         /* just for the space */
        
        cm_return_t    cmrc;
        unsigned long  flags;

        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        
        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        if (conn->ibc_disconnect) {
                /* Had the CM callback already */
                write_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                        flags);
                kibnal_conn_disconnected(conn);
                return;
        }
                
        LASSERT (conn->ibc_state == IBNAL_CONN_DISCONNECT1);

        /* active disconnect */
        cmrc = cm_disconnect(conn->ibc_cep, &dreq, NULL);
        if (cmrc == cm_stat_success) {
                /* waiting for CM */
                conn->ibc_state = IBNAL_CONN_DISCONNECT2;
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                return;
        }

        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        cm_cancel(conn->ibc_cep);
        kibnal_pause(HZ/10);

        if (!conn->ibc_disconnect)              /* CM callback will never happen now */
                kibnal_conn_decref(conn);
        
        LASSERT (atomic_read(&conn->ibc_refcount) > 0);
        LASSERT (conn->ibc_state == IBNAL_CONN_DISCONNECT1);

        kibnal_conn_disconnected(conn);
}

int
kibnal_connd (void *arg)
{
        wait_queue_t       wait;
        unsigned long      flags;
        kib_pcreq_t       *pcr;
        kib_conn_t        *conn;
        kib_peer_t        *peer;
        int                timeout;
        int                i;
        int                dropped_lock;
        int                peer_index = 0;
        unsigned long      deadline = jiffies;
        
        kportal_daemonize ("kibnal_connd");
        kportal_blockallsigs ();

        init_waitqueue_entry (&wait, current);
        kibnal_data.kib_connd = current;

        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);

        while (!kibnal_data.kib_shutdown) {

                dropped_lock = 0;

                if (!list_empty (&kibnal_data.kib_connd_zombies)) {
                        conn = list_entry (kibnal_data.kib_connd_zombies.next,
                                           kib_conn_t, ibc_list);
                        list_del (&conn->ibc_list);
                        
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);
                        dropped_lock = 1;

                        kibnal_destroy_conn(conn);

                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                }

                if (!list_empty (&kibnal_data.kib_connd_pcreqs)) {
                        pcr = list_entry(kibnal_data.kib_connd_pcreqs.next,
                                         kib_pcreq_t, pcr_list);
                        list_del(&pcr->pcr_list);
                        
                        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
                        dropped_lock = 1;

                        kibnal_recv_connreq(pcr->pcr_cep, &pcr->pcr_cmreq);
                        PORTAL_FREE(pcr, sizeof(*pcr));

                        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
                }
                        
                if (!list_empty (&kibnal_data.kib_connd_peers)) {
                        peer = list_entry (kibnal_data.kib_connd_peers.next,
                                           kib_peer_t, ibp_connd_list);
                        
                        list_del_init (&peer->ibp_connd_list);
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);
                        dropped_lock = 1;

                        kibnal_arp_peer (peer);
                        kibnal_peer_decref (peer);

                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                }

                if (!list_empty (&kibnal_data.kib_connd_conns)) {
                        conn = list_entry (kibnal_data.kib_connd_conns.next,
                                           kib_conn_t, ibc_list);
                        list_del (&conn->ibc_list);
                        
                        spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);
                        dropped_lock = 1;

                        switch (conn->ibc_state) {
                        default:
                                LBUG();
                                
                        case IBNAL_CONN_ACTIVE_ARP:
                                kibnal_send_connreq(conn);
                                break;

                        case IBNAL_CONN_ACTIVE_CONNECT:
                                kibnal_check_connreply(conn);
                                break;

                        case IBNAL_CONN_PASSIVE_WAIT:
                                kibnal_check_passive_wait(conn);
                                break;

                        case IBNAL_CONN_DISCONNECT1:
                        case IBNAL_CONN_DISCONNECT2:
                                kibnal_disconnect_conn(conn);
                                break;
                        }
                        kibnal_conn_decref(conn);

                        spin_lock_irqsave (&kibnal_data.kib_connd_lock, flags);
                }

                /* careful with the jiffy wrap... */
                timeout = (int)(deadline - jiffies);
                if (timeout <= 0) {
                        const int n = 4;
                        const int p = 1;
                        int       chunk = kibnal_data.kib_peer_hash_size;
                        
                        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
                        dropped_lock = 1;

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
                        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
                }

                if (dropped_lock)
                        continue;
                
                /* Nothing to do for 'timeout'  */
                set_current_state (TASK_INTERRUPTIBLE);
                add_wait_queue (&kibnal_data.kib_connd_waitq, &wait);
                spin_unlock_irqrestore (&kibnal_data.kib_connd_lock, flags);

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
kibnal_async_callback(vv_event_record_t ev)
{
        CERROR("type: %d, port: %d, data: "LPX64"\n", 
               ev.event_type, ev.port_num, ev.type.data);
}

void
kibnal_cq_callback (unsigned long unused_context)
{
        unsigned long    flags;

        CDEBUG(D_NET, "!!\n");

        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
        kibnal_data.kib_ready = 1;
        wake_up(&kibnal_data.kib_sched_waitq);
        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock, flags);
}

int
kibnal_scheduler(void *arg)
{
        long            id = (long)arg;
        wait_queue_t    wait;
        char            name[16];
        vv_wc_t         wc;
        vv_return_t     vvrc;
        vv_return_t     vvrc2;
        unsigned long   flags;
        kib_rx_t       *rx;
        __u64           rxseq = 0;
        int             busy_loops = 0;

        snprintf(name, sizeof(name), "kibnal_sd_%02ld", id);
        kportal_daemonize(name);
        kportal_blockallsigs();

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
                        
                        vvrc = vv_poll_for_completion(kibnal_data.kib_hca, 
                                                      kibnal_data.kib_cq, &wc);
                        if (vvrc == vv_return_err_cq_empty) {
                                vvrc2 = vv_request_completion_notification(
                                        kibnal_data.kib_hca, 
                                        kibnal_data.kib_cq, 
                                        vv_next_solicit_unsolicit_event);
                                LASSERT (vvrc2 == vv_return_ok);
                        }

                        if (vvrc == vv_return_ok &&
                            kibnal_wreqid2type(wc.wr_id) == IBNAL_WID_RX) {
                                rx = (kib_rx_t *)kibnal_wreqid2ptr(wc.wr_id);

                                /* Grab the RX sequence number NOW before
                                 * anyone else can get an RX completion */
                                rxseq = rx->rx_conn->ibc_rxseq++;
                        }

                        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
                        /* give up ownership of completion polling */
                        kibnal_data.kib_checking_cq = 0;

                        if (vvrc == vv_return_err_cq_empty)
                                continue;

                        LASSERT (vvrc == vv_return_ok);
                        /* Assume there's more: get another scheduler to check
                         * while I handle this completion... */

                        kibnal_data.kib_ready = 1;
                        wake_up(&kibnal_data.kib_sched_waitq);

                        spin_unlock_irqrestore(&kibnal_data.kib_sched_lock,
                                               flags);

                        switch (kibnal_wreqid2type(wc.wr_id)) {
                        case IBNAL_WID_RX:
                                kibnal_rx_complete(
                                        (kib_rx_t *)kibnal_wreqid2ptr(wc.wr_id),
                                        wc.completion_status,
                                        wc.num_bytes_transfered,
                                        rxseq);
                                break;

                        case IBNAL_WID_TX:
                                kibnal_tx_complete(
                                        (kib_tx_t *)kibnal_wreqid2ptr(wc.wr_id),
                                        wc.completion_status);
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
                                CERROR ("RDMA failed: %d\n", 
                                        wc.completion_status);
                                break;

                        default:
                                LBUG();
                        }
                        
                        spin_lock_irqsave(&kibnal_data.kib_sched_lock, flags);
                        continue;
                }

                /* Nothing to do; sleep... */

                set_current_state(TASK_INTERRUPTIBLE);
                add_wait_queue(&kibnal_data.kib_sched_waitq, &wait);
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


lib_nal_t kibnal_lib = {
        .libnal_data = &kibnal_data,      /* NAL private data */
        .libnal_send = kibnal_send,
        .libnal_send_pages = kibnal_send_pages,
        .libnal_recv = kibnal_recv,
        .libnal_recv_pages = kibnal_recv_pages,
        .libnal_dist = kibnal_dist
};
