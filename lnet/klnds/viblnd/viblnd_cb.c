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
 * lnet/klnds/viblnd/viblnd_cb.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 * Author: Frank Zago <fzago@systemfabricworks.com>
 */

#include "viblnd.h"

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
        if (tx->tx_md.md_fmrcount == 0 ||
            (rc != 0 && tx->tx_md.md_active)) {
                vv_return_t      vvrc;

                /* mapping must be active (it dropped fmrcount to 0) */
                LASSERT (tx->tx_md.md_active);

                vvrc = vv_unmap_fmr(kibnal_data.kib_hca,
                                    1, &tx->tx_md.md_fmrhandle);
                LASSERT (vvrc == vv_return_ok);

                tx->tx_md.md_fmrcount = *kibnal_tunables.kib_fmr_remaps;
        }
        tx->tx_md.md_active = 0;
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
        __u64         addr = (__u64)((unsigned long)((rx)->rx_msg));
        vv_return_t   vvrc;

        LASSERT (!in_interrupt());
        /* old peers don't reserve rxs for RDMA replies */
        LASSERT (!rsrvd_credit ||
                 conn->ibc_version != IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD);

        rx->rx_gl = (vv_scatgat_t) {
                .v_address = KIBNAL_ADDR2SG(addr),
                .l_key     = rx->rx_lkey,
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
        LASSERT (rx->rx_nob >= 0);              /* not posted */

        CDEBUG(D_NET, "posting rx [%d %x "LPX64"]\n",
               rx->rx_wrq.scatgat_list->length,
               rx->rx_wrq.scatgat_list->l_key,
               KIBNAL_SG2ADDR(rx->rx_wrq.scatgat_list->v_address));

        if (conn->ibc_state > IBNAL_CONN_ESTABLISHED) {
                /* No more posts for this rx; so lose its ref */
                kibnal_conn_decref(conn);
                return 0;
        }

        rx->rx_nob = -1;                        /* flag posted */

        spin_lock(&conn->ibc_lock);
        /* Serialise vv_post_receive; it's not re-entrant on the same QP */
        vvrc = vv_post_receive(kibnal_data.kib_hca,
                               conn->ibc_qp, &rx->rx_wrq);

        if (vvrc == vv_return_ok) {
                if (credit)
                        conn->ibc_outstanding_credits++;
                if (rsrvd_credit)
                        conn->ibc_reserved_credits++;

                spin_unlock(&conn->ibc_lock);

                if (credit || rsrvd_credit)
                        kibnal_check_sends(conn);

                return 0;
        }

        spin_unlock(&conn->ibc_lock);

        CERROR ("post rx -> %s failed %d\n",
                libcfs_nid2str(conn->ibc_peer->ibp_nid), vvrc);
        rc = -EIO;
        kibnal_close_conn(conn, rc);
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
kibnal_rx_complete (kib_rx_t *rx, vv_comp_status_t vvrc, int nob, __u64 rxseq)
{
        kib_msg_t    *msg = rx->rx_msg;
        kib_conn_t   *conn = rx->rx_conn;
        unsigned long flags;
        int           rc;

        CDEBUG(D_NET, "rx %p conn %p\n", rx, conn);
        LASSERT (rx->rx_nob < 0);               /* was posted */
        rx->rx_nob = 0;                         /* isn't now */

        if (conn->ibc_state > IBNAL_CONN_ESTABLISHED)
                goto ignore;

        if (vvrc != vv_comp_status_success) {
                CERROR("Rx from %s failed: %d\n",
                       libcfs_nid2str(conn->ibc_peer->ibp_nid), vvrc);
                goto failed;
        }

        rc = kibnal_unpack_msg(msg, conn->ibc_version, nob);
        if (rc != 0) {
                CERROR ("Error %d unpacking rx from %s\n",
                        rc, libcfs_nid2str(conn->ibc_peer->ibp_nid));
                goto failed;
        }

        rx->rx_nob = nob;                       /* Can trust 'nob' now */

        if (conn->ibc_peer->ibp_nid != msg->ibm_srcnid ||
            kibnal_data.kib_ni->ni_nid != msg->ibm_dstnid ||
            msg->ibm_srcstamp != conn->ibc_incarnation ||
            msg->ibm_dststamp != kibnal_data.kib_incarnation) {
                CERROR ("Stale rx from %s\n",
                        libcfs_nid2str(conn->ibc_peer->ibp_nid));
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
        CDEBUG(D_NET, "rx %p conn %p\n", rx, conn);
        kibnal_close_conn(conn, -EIO);
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
        vv_l_key_t       l_key;
        vv_r_key_t       r_key;
        __u64            addr;
        __u64            frag_addr;
        vv_mem_reg_h_t   mem_h;
        vv_return_t      vvrc;

        if (rd->rd_nfrag >= IBNAL_MAX_RDMA_FRAGS) {
                CERROR ("Too many RDMA fragments\n");
                return -EMSGSIZE;
        }

        /* Try to create an address that adaptor-tavor will munge into a valid
         * network address, given how it maps all phys mem into 1 region */
        addr = lnet_page2phys(page) + page_offset + PAGE_OFFSET;

        /* NB this relies entirely on there being a single region for the whole
         * of memory, since "high" memory will wrap in the (void *) cast! */
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

                frag_addr = kibnal_addr2net(addr);
        }

        kibnal_rf_set(frag, frag_addr, len);

        CDEBUG(D_NET,"map frag [%d][%d %x %08x%08x] "LPX64"\n",
               rd->rd_nfrag, frag->rf_nob, rd->rd_key,
               frag->rf_addr_hi, frag->rf_addr_lo, frag_addr);

        rd->rd_nfrag++;
        return 0;
}

int
kibnal_setup_rd_iov(kib_tx_t *tx, kib_rdma_desc_t *rd,
                    vv_access_con_bit_mask_t access,
                    unsigned int niov, struct iovec *iov, int offset, int nob)
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
                      int nkiov, lnet_kiov_t *kiov, int offset, int nob)
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
kibnal_map_tx (kib_tx_t *tx, kib_rdma_desc_t *rd, int active,
               int npages, unsigned long page_offset, int nob)
{
        vv_return_t   vvrc;
        vv_fmr_map_t  map_props;

        LASSERT ((rd != tx->tx_rd) == !active);
        LASSERT (!tx->tx_md.md_active);
        LASSERT (tx->tx_md.md_fmrcount > 0);
        LASSERT (page_offset < PAGE_SIZE);
        LASSERT (npages >= (1 + ((page_offset + nob - 1)>>PAGE_SHIFT)));
        LASSERT (npages <= LNET_MAX_IOV);

        memset(&map_props, 0, sizeof(map_props));

        map_props.start          = (void *)page_offset;
        map_props.size           = nob;
        map_props.page_array_len = npages;
        map_props.page_array     = tx->tx_pages;

        vvrc = vv_map_fmr(kibnal_data.kib_hca, tx->tx_md.md_fmrhandle,
                          &map_props, &tx->tx_md.md_lkey, &tx->tx_md.md_rkey);
        if (vvrc != vv_return_ok) {
                CERROR ("Can't map vaddr %p for %d in %d pages: %d\n",
                        map_props.start, nob, npages, vvrc);
                return -EFAULT;
        }

        tx->tx_md.md_addr = (unsigned long)map_props.start;
        tx->tx_md.md_active = 1;
        tx->tx_md.md_fmrcount--;

        rd->rd_key = active ? tx->tx_md.md_lkey : tx->tx_md.md_rkey;
        rd->rd_nob = nob;
        rd->rd_addr = tx->tx_md.md_addr;

        /* Compensate for adaptor-tavor's munging of gatherlist addresses */
        if (active)
                rd->rd_addr += PAGE_OFFSET;

        return 0;
}

int
kibnal_setup_rd_iov (kib_tx_t *tx, kib_rdma_desc_t *rd,
                     vv_access_con_bit_mask_t access,
                     unsigned int niov, struct iovec *iov, int offset, int nob)
{
        /* active if I'm sending */
        int           active = ((access & vv_acc_r_mem_write) == 0);
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
kibnal_setup_rd_kiov (kib_tx_t *tx, kib_rdma_desc_t *rd,
                      vv_access_con_bit_mask_t access,
                      int nkiov, lnet_kiov_t *kiov, int offset, int nob)
{
        /* active if I'm sending */
        int            active = ((access & vv_acc_r_mem_write) == 0);
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
        vv_return_t     vvrc;
        int             rc;
        int             consume_cred;
        int             done;

        /* Don't send anything until after the connection is established */
        if (conn->ibc_state < IBNAL_CONN_ESTABLISHED) {
                CDEBUG(D_NET, "%s too soon\n",
                       libcfs_nid2str(conn->ibc_peer->ibp_nid));
                return;
        }

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

                /* Keep holding ibc_lock while posting sends on this
                 * connection; vv_post_send() isn't re-entrant on the same
                 * QP!! */

                LASSERT (tx->tx_nwrq > 0);
#if 0
                if (tx->tx_wrq[0].wr_type == vv_wr_rdma_write) 
                        CDEBUG(D_NET, "WORK[0]: RDMA gl %p for %d k %x -> "LPX64" k %x\n",
                               tx->tx_wrq[0].scatgat_list->v_address,
                               tx->tx_wrq[0].scatgat_list->length,
                               tx->tx_wrq[0].scatgat_list->l_key,
                               tx->tx_wrq[0].type.send.send_qp_type.rc_type.r_addr,
                               tx->tx_wrq[0].type.send.send_qp_type.rc_type.r_r_key);
                else
                        CDEBUG(D_NET, "WORK[0]: %s gl %p for %d k %x\n",
                               tx->tx_wrq[0].wr_type == vv_wr_send ? "SEND" : "????",
                               tx->tx_wrq[0].scatgat_list->v_address,
                               tx->tx_wrq[0].scatgat_list->length,
                               tx->tx_wrq[0].scatgat_list->l_key);

                if (tx->tx_nwrq > 1) {
                        if (tx->tx_wrq[1].wr_type == vv_wr_rdma_write) 
                                CDEBUG(D_NET, "WORK[1]: RDMA gl %p for %d k %x -> "LPX64" k %x\n",
                                       tx->tx_wrq[1].scatgat_list->v_address,
                                       tx->tx_wrq[1].scatgat_list->length,
                                       tx->tx_wrq[1].scatgat_list->l_key,
                                       tx->tx_wrq[1].type.send.send_qp_type.rc_type.r_addr,
                                       tx->tx_wrq[1].type.send.send_qp_type.rc_type.r_r_key);
                        else
                                CDEBUG(D_NET, "WORK[1]: %s gl %p for %d k %x\n",
                                       tx->tx_wrq[1].wr_type == vv_wr_send ? "SEND" : "????",
                                       tx->tx_wrq[1].scatgat_list->v_address,
                                       tx->tx_wrq[1].scatgat_list->length,
                                       tx->tx_wrq[1].scatgat_list->l_key);
                }
#endif           
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
                                        vvrc, libcfs_nid2str(conn->ibc_peer->ibp_nid));
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
                CDEBUG(D_NETERROR, "tx -> %s type %x cookie "LPX64
                       "sending %d waiting %d: failed %d\n", 
                       libcfs_nid2str(conn->ibc_peer->ibp_nid),
                       tx->tx_msg->ibm_type, tx->tx_cookie,
                       tx->tx_sending, tx->tx_waiting, vvrc);

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
        vv_scatgat_t *gl = &tx->tx_gl[tx->tx_nwrq];
        vv_wr_t      *wrq = &tx->tx_wrq[tx->tx_nwrq];
        int           nob = offsetof (kib_msg_t, ibm_u) + body_nob;
        __u64         addr = (__u64)((unsigned long)((tx)->tx_msg));

        LASSERT (tx->tx_nwrq >= 0 &&
                 tx->tx_nwrq < (1 + IBNAL_MAX_RDMA_FRAGS));
        LASSERT (nob <= IBNAL_MSG_SIZE);

        kibnal_init_msg(tx->tx_msg, type, body_nob);

        *gl = (vv_scatgat_t) {
                .v_address = KIBNAL_ADDR2SG(addr),
                .l_key     = tx->tx_lkey,
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
        kib_msg_t       *ibmsg = tx->tx_msg;
        kib_rdma_desc_t *srcrd = tx->tx_rd;
        vv_scatgat_t    *gl;
        vv_wr_t         *wrq;
        int              rc;

#if IBNAL_USE_FMR
        LASSERT (tx->tx_nwrq == 0);

        gl = &tx->tx_gl[0];
        gl->length    = nob;
        gl->v_address = KIBNAL_ADDR2SG(srcrd->rd_addr);
        gl->l_key     = srcrd->rd_key;

        wrq = &tx->tx_wrq[0];

        wrq->wr_id = kibnal_ptr2wreqid(tx, IBNAL_WID_RDMA);
        wrq->completion_notification = 0;
        wrq->scatgat_list = gl;
        wrq->num_of_data_segments = 1;
        wrq->wr_type = vv_wr_rdma_write;
        wrq->type.send.solicited_event = 0;
        wrq->type.send.send_qp_type.rc_type.fance_indicator = 0;
        wrq->type.send.send_qp_type.rc_type.r_addr = dstrd->rd_addr;
        wrq->type.send.send_qp_type.rc_type.r_r_key = dstrd->rd_key;

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
                gl->v_address = KIBNAL_ADDR2SG(kibnal_rf_addr(srcfrag));
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
                                      kibnal_rf_addr(srcfrag) + wrknob,
                                      srcfrag->rf_nob - wrknob);
                } else {
                        srcfrag++;
                        srcidx++;
                }

                if (wrknob < dstfrag->rf_nob) {
                        kibnal_rf_set(dstfrag,
                                      kibnal_rf_addr(dstfrag) + wrknob,
                                      dstfrag->rf_nob - wrknob);
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
kibnal_schedule_peer_arp (kib_peer_t *peer)
{
        unsigned long flags;

        LASSERT (peer->ibp_connecting != 0);
        LASSERT (peer->ibp_arp_count > 0);

        kibnal_peer_addref(peer); /* extra ref for connd */

        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);

        list_add_tail (&peer->ibp_connd_list, &kibnal_data.kib_connd_peers);
        wake_up (&kibnal_data.kib_connd_waitq);

        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
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

                rc = kibnal_add_persistent_peer(nid, LNET_NIDADDR(nid));
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

        if (peer->ibp_connecting == 0 &&
            peer->ibp_accepting == 0) {
                if (!(peer->ibp_reconnect_interval == 0 || /* first attempt */
                      time_after_eq(jiffies, peer->ibp_reconnect_time))) {
                        write_unlock_irqrestore(g_lock, flags);
                        tx->tx_status = -EHOSTUNREACH;
                        tx->tx_waiting = 0;
                        kibnal_tx_done (tx);
                        return;
                }

                peer->ibp_connecting = 1;
                peer->ibp_arp_count = 1 + *kibnal_tunables.kib_arp_retries;
                kibnal_schedule_peer_arp(peer);
        }

        /* A connection is being established; queue the message... */
        list_add_tail (&tx->tx_list, &peer->ibp_tx_queue);

        write_unlock_irqrestore(g_lock, flags);
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
                                                 vv_acc_r_mem_write,
                                                 lntmsg->msg_md->md_niov,
                                                 lntmsg->msg_md->md_iov.iov,
                                                 0, lntmsg->msg_md->md_length);
                else
                        rc = kibnal_setup_rd_kiov(tx, &ibmsg->ibm_u.get.ibgm_rd,
                                                  vv_acc_r_mem_write,
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
                        rc = kibnal_setup_rd_iov(tx, tx->tx_rd, 0,
                                                 payload_niov, payload_iov,
                                                 payload_offset, payload_nob);
                else
                        rc = kibnal_setup_rd_kiov(tx, tx->tx_rd, 0,
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
kibnal_reply (lnet_ni_t *ni, kib_rx_t *rx, lnet_msg_t *lntmsg)
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
                rc = kibnal_setup_rd_iov(tx, tx->tx_rd, 0,
                                         niov, iov, offset, nob);
        else
                rc = kibnal_setup_rd_kiov(tx, tx->tx_rd, 0,
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
                LCONSOLE_ERROR_MSG(0x129, "Dropping message from %s: no buffers"
                                   " free. %s is running an old version of LNET "
                                   "that may deadlock if messages wait for"
                                   "buffers) \n",
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
                        kibnal_send_completion(conn, IBNAL_MSG_PUT_NAK, 0,
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
                                                 vv_acc_r_mem_write,
                                                 niov, iov, offset, mlen);
                else
                        rc = kibnal_setup_rd_kiov(tx,
                                                  &txmsg->ibm_u.putack.ibpam_rd,
                                                  vv_acc_r_mem_write,
                                                  niov, kiov, offset, mlen);
                if (rc != 0) {
                        CERROR("Can't setup PUT sink for %s: %d\n",
                               libcfs_nid2str(conn->ibc_peer->ibp_nid), rc);
                        kibnal_tx_done(tx);
                        /* tell peer it's over */
                        kibnal_send_completion(conn, IBNAL_MSG_PUT_NAK, rc,
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
                        kibnal_send_completion(conn, IBNAL_MSG_GET_DONE, -ENODATA,
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
        /* This just does the immediate housekeeping.  'error' is zero for a
         * normal shutdown which can happen only after the connection has been
         * established.  If the connection is established, schedule the
         * connection to be finished off by the connd.  Otherwise the connd is
         * already dealing with it (either to set it up or tear it down).
         * Caller holds kib_global_lock exclusively in irq context */
        kib_peer_t       *peer = conn->ibc_peer;

        LASSERT (error != 0 || conn->ibc_state >= IBNAL_CONN_ESTABLISHED);

        if (error != 0 && conn->ibc_comms_error == 0)
                conn->ibc_comms_error = error;

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
        }

        list_del (&conn->ibc_list);

        if (list_empty (&peer->ibp_conns)) {   /* no more conns */
                if (peer->ibp_persistence == 0 && /* non-persistent peer */
                    kibnal_peer_active(peer))     /* still in peer table */
                        kibnal_unlink_peer_locked (peer);

                /* set/clear error on last conn */
                peer->ibp_error = conn->ibc_comms_error;
        }

        kibnal_set_conn_state(conn, IBNAL_CONN_DISCONNECT1);

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
        /* I'm the connd */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (conn->ibc_state >= IBNAL_CONN_INIT);

        kibnal_set_conn_state(conn, IBNAL_CONN_DISCONNECTED);

        /* move QP to error state to make posted work items complete */
        kibnal_set_qp_state(conn, vv_qp_state_error);

        /* Complete all tx descs not waiting for sends to complete.
         * NB we should be safe from RDMA now that the QP has changed state */

        kibnal_abort_txs(conn, &conn->ibc_tx_queue);
        kibnal_abort_txs(conn, &conn->ibc_tx_queue_rsrvd);
        kibnal_abort_txs(conn, &conn->ibc_tx_queue_nocred);
        kibnal_abort_txs(conn, &conn->ibc_active_txs);

        kibnal_handle_early_rxs(conn);

        kibnal_peer_notify(conn->ibc_peer);
}

void
kibnal_peer_connect_failed (kib_peer_t *peer, int active, int error)
{
        LIST_HEAD        (zombies);
        unsigned long     flags;

        /* Only the connd creates conns => single threaded */
        LASSERT (error != 0);
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);

        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        if (active) {
                LASSERT (peer->ibp_connecting != 0);
                peer->ibp_connecting--;
        } else {
                LASSERT (peer->ibp_accepting != 0);
                peer->ibp_accepting--;
        }

        if (peer->ibp_connecting != 0 ||
            peer->ibp_accepting != 0) {
                /* another connection attempt under way (loopback?)... */
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
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

                /* Take peer's blocked transmits to complete with error */
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

        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        kibnal_peer_notify(peer);

        if (list_empty (&zombies))
                return;

        CDEBUG (D_NETERROR, "Deleting messages for %s: connection failed\n",
                libcfs_nid2str(peer->ibp_nid));

        kibnal_txlist_done(&zombies, -EHOSTUNREACH);
}

void
kibnal_reject(cm_cep_handle_t cep, int why)
{
        static cm_reject_data_t   rejs[3];
        cm_reject_data_t         *rej = &rejs[why];

        LASSERT (why >= 0 && why < sizeof(rejs)/sizeof(rejs[0]));

        /* If I wasn't so lazy, I'd initialise this only once; it's effective
         * read-only */
        rej->reason = cm_rej_code_usr_rej;
        rej->priv_data[0] = (IBNAL_MSG_MAGIC) & 0xff;
        rej->priv_data[1] = (IBNAL_MSG_MAGIC >> 8) & 0xff;
        rej->priv_data[2] = (IBNAL_MSG_MAGIC >> 16) & 0xff;
        rej->priv_data[3] = (IBNAL_MSG_MAGIC >> 24) & 0xff;
        rej->priv_data[4] = (IBNAL_MSG_VERSION) & 0xff;
        rej->priv_data[5] = (IBNAL_MSG_VERSION >> 8) & 0xff;
        rej->priv_data[6] = why;

        cm_reject(cep, rej);
}

void
kibnal_connreq_done(kib_conn_t *conn, int active, int status)
{
        struct list_head   txs;
        kib_peer_t        *peer = conn->ibc_peer;
        unsigned long      flags;
        kib_tx_t          *tx;

        CDEBUG(D_NET,"%d\n", status);

        /* Only the connd creates conns => single threaded */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (conn->ibc_state < IBNAL_CONN_ESTABLISHED);

        if (active) {
                LASSERT (peer->ibp_connecting > 0);
        } else {
                LASSERT (peer->ibp_accepting > 0);
        }

        LIBCFS_FREE(conn->ibc_connvars, sizeof(*conn->ibc_connvars));
        conn->ibc_connvars = NULL;

        if (status != 0) {
                /* failed to establish connection */
                switch (conn->ibc_state) {
                default:
                        LBUG();

                case IBNAL_CONN_ACTIVE_CHECK_REPLY:
                        /* got a connection reply but failed checks */
                        LASSERT (active);
                        kibnal_reject(conn->ibc_cep, IBNAL_REJECT_FATAL);
                        break;

                case IBNAL_CONN_ACTIVE_CONNECT:
                        LASSERT (active);
                        cm_cancel(conn->ibc_cep);
                        cfs_pause(cfs_time_seconds(1)/10);
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

                kibnal_peer_connect_failed(peer, active, status);
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

        conn->ibc_last_send = jiffies;
        kibnal_set_conn_state(conn, IBNAL_CONN_ESTABLISHED);
        kibnal_peer_alive(peer);

        /* Add conn to peer's list and nuke any dangling conns from a different
         * peer instance... */
        kibnal_conn_addref(conn);               /* +1 ref for ibc_list */
        list_add(&conn->ibc_list, &peer->ibp_conns);
        kibnal_close_stale_conns_locked (peer, conn->ibc_incarnation);

        if (!kibnal_peer_active(peer) ||        /* peer has been deleted */
            conn->ibc_comms_error != 0 ||       /* comms error */
            conn->ibc_disconnect) {             /* need to disconnect */

                /* start to shut down connection */
                kibnal_close_conn_locked(conn, -ECONNABORTED);

                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                kibnal_peer_connect_failed(peer, active, -ECONNABORTED);
                return;
        }

        if (active)
                peer->ibp_connecting--;
        else
                peer->ibp_accepting--;

        /* grab pending txs while I have the lock */
        list_add(&txs, &peer->ibp_tx_queue);
        list_del_init(&peer->ibp_tx_queue);

        peer->ibp_reconnect_interval = 0;       /* OK to reconnect at any time */

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
                        break;

                case IBNAL_CONN_ESTABLISHED:
                        /* kibnal_connreq_done got there already; get
                         * disconnect going... */
                        kibnal_close_conn_locked(conn, 0);
                        break;

                case IBNAL_CONN_DISCONNECT1:
                        /* kibnal_disconnect_conn is getting there; It'll see
                         * ibc_disconnect set... */
                        break;

                case IBNAL_CONN_DISCONNECT2:
                        /* kibnal_disconnect_conn got there already; complete
                         * the disconnect. */
                        kibnal_schedule_conn(conn);
                        break;
                }
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                break;

        case cm_event_disconn_timeout:
        case cm_event_disconn_reply:
                write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
                LASSERT (conn->ibc_state == IBNAL_CONN_DISCONNECT2);
                LASSERT (!conn->ibc_disconnect);
                conn->ibc_disconnect = 1;

                /* kibnal_disconnect_conn sent the disconnect request. */
                kibnal_schedule_conn(conn);

                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                break;

        case cm_event_connected:
        case cm_event_conn_timeout:
        case cm_event_conn_reject:
                LASSERT (conn->ibc_state == IBNAL_CONN_PASSIVE_WAIT);
                conn->ibc_connvars->cv_conndata = *cmdata;

                kibnal_schedule_conn(conn);
                break;
        }

        kibnal_conn_decref(conn); /* lose my ref */
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
        static kib_msg_t        txmsg;
        static kib_msg_t        rxmsg;
        static cm_reply_data_t  reply;

        kib_conn_t         *conn = NULL;
        int                 rc = 0;
        int                 reason;
        int                 rxmsgnob;
        rwlock_t           *g_lock = &kibnal_data.kib_global_lock;
        kib_peer_t         *peer;
        kib_peer_t         *peer2;
        unsigned long       flags;
        kib_connvars_t     *cv;
        cm_return_t         cmrc;
        vv_return_t         vvrc;

        /* I'm the connd executing in thread context
         * No concurrency problems with static data! */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);

        if (cmreq->sid != (__u64)(*kibnal_tunables.kib_service_number)) {
                CERROR(LPX64" != IBNAL_SERVICE_NUMBER("LPX64")\n",
                       cmreq->sid, (__u64)(*kibnal_tunables.kib_service_number));
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        /* copy into rxmsg to avoid alignment issues */
        rxmsgnob = MIN(cm_REQ_priv_data_len, sizeof(rxmsg));
        memcpy(&rxmsg, cmreq->priv_data, rxmsgnob);

        rc = kibnal_unpack_msg(&rxmsg, 0, rxmsgnob);
        if (rc != 0) {
                /* SILENT! kibnal_unpack_msg() complains if required */
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        if (rxmsg.ibm_version != IBNAL_MSG_VERSION)
                CWARN("Connection from %s: old protocol version 0x%x\n",
                      libcfs_nid2str(rxmsg.ibm_srcnid), rxmsg.ibm_version);

        if (rxmsg.ibm_type != IBNAL_MSG_CONNREQ) {
                CERROR("Unexpected connreq msg type: %x from %s\n",
                       rxmsg.ibm_type, libcfs_nid2str(rxmsg.ibm_srcnid));
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        if (kibnal_data.kib_ni->ni_nid != rxmsg.ibm_dstnid) {
                CERROR("Can't accept %s: bad dst nid %s\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid),
                       libcfs_nid2str(rxmsg.ibm_dstnid));
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        if (rxmsg.ibm_u.connparams.ibcp_queue_depth != IBNAL_MSG_QUEUE_SIZE) {
                CERROR("Can't accept %s: incompatible queue depth %d (%d wanted)\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid),
                       rxmsg.ibm_u.connparams.ibcp_queue_depth,
                       IBNAL_MSG_QUEUE_SIZE);
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        if (rxmsg.ibm_u.connparams.ibcp_max_msg_size > IBNAL_MSG_SIZE) {
                CERROR("Can't accept %s: message size %d too big (%d max)\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid),
                       rxmsg.ibm_u.connparams.ibcp_max_msg_size,
                       IBNAL_MSG_SIZE);
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        if (rxmsg.ibm_u.connparams.ibcp_max_frags > IBNAL_MAX_RDMA_FRAGS) {
                CERROR("Can't accept %s: max frags %d too big (%d max)\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid),
                       rxmsg.ibm_u.connparams.ibcp_max_frags,
                       IBNAL_MAX_RDMA_FRAGS);
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        /* assume 'rxmsg.ibm_srcnid' is a new peer; create */
        rc = kibnal_create_peer (&peer, rxmsg.ibm_srcnid);
        if (rc != 0) {
                CERROR("Can't create peer for %s\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid));
                reason = IBNAL_REJECT_NO_RESOURCES;
                goto reject;
        }

        write_lock_irqsave(g_lock, flags);

        if (kibnal_data.kib_listen_handle == NULL) {
                write_unlock_irqrestore(g_lock, flags);

                CWARN ("Shutdown has started, rejecting connreq from %s\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid));
                kibnal_peer_decref(peer);
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        peer2 = kibnal_find_peer_locked(rxmsg.ibm_srcnid);
        if (peer2 != NULL) {
                /* tie-break connection race in favour of the higher NID */
                if (peer2->ibp_connecting != 0 &&
                    rxmsg.ibm_srcnid < kibnal_data.kib_ni->ni_nid) {
                        write_unlock_irqrestore(g_lock, flags);

                        CWARN("Conn race %s\n",
                              libcfs_nid2str(rxmsg.ibm_srcnid));

                        kibnal_peer_decref(peer);
                        reason = IBNAL_REJECT_CONN_RACE;
                        goto reject;
                }

                peer2->ibp_accepting++;
                kibnal_peer_addref(peer2);

                write_unlock_irqrestore(g_lock, flags);
                kibnal_peer_decref(peer);
                peer = peer2;
        } else {
                /* Brand new peer */
                LASSERT (peer->ibp_accepting == 0);
                peer->ibp_accepting = 1;

                kibnal_peer_addref(peer);
                list_add_tail(&peer->ibp_list, kibnal_nid2peerlist(rxmsg.ibm_srcnid));

                write_unlock_irqrestore(g_lock, flags);
        }

        conn = kibnal_create_conn(cep);
        if (conn == NULL) {
                CERROR("Can't create conn for %s\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid));
                kibnal_peer_connect_failed(peer, 0, -ENOMEM);
                kibnal_peer_decref(peer);
                reason = IBNAL_REJECT_NO_RESOURCES;
                goto reject;
        }

        conn->ibc_version = rxmsg.ibm_version;

        conn->ibc_peer = peer;              /* conn takes over my ref */
        conn->ibc_incarnation = rxmsg.ibm_srcstamp;
        conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;
        conn->ibc_reserved_credits = IBNAL_MSG_QUEUE_SIZE;
        LASSERT (conn->ibc_credits + conn->ibc_reserved_credits
                 <= IBNAL_RX_MSGS);

        cv = conn->ibc_connvars;

        cv->cv_txpsn          = cmreq->cep_data.start_psn;
        cv->cv_remote_qpn     = cmreq->cep_data.qpn;
        cv->cv_path           = cmreq->path_data.path;
        cv->cv_rnr_count      = cmreq->cep_data.rtr_retry_cnt;
        // XXX                  cmreq->cep_data.retry_cnt;
        cv->cv_port           = cmreq->cep_data.local_port_num;

        vvrc = gid2gid_index(kibnal_data.kib_hca, cv->cv_port,
                             &cv->cv_path.sgid, &cv->cv_sgid_index);
        if (vvrc != vv_return_ok) {
                CERROR("gid2gid_index failed for %s: %d\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid), vvrc);
                rc = -EIO;
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        vvrc = pkey2pkey_index(kibnal_data.kib_hca, cv->cv_port,
                               cv->cv_path.pkey, &cv->cv_pkey_index);
        if (vvrc != vv_return_ok) {
                CERROR("pkey2pkey_index failed for %s: %d\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid), vvrc);
                rc = -EIO;
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        rc = kibnal_set_qp_state(conn, vv_qp_state_init);
        if (rc != 0) {
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        rc = kibnal_post_receives(conn);
        if (rc != 0) {
                CERROR("Can't post receives for %s\n",
                       libcfs_nid2str(rxmsg.ibm_srcnid));
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        rc = kibnal_set_qp_state(conn, vv_qp_state_rtr);
        if (rc != 0) {
                reason = IBNAL_REJECT_FATAL;
                goto reject;
        }

        memset(&reply, 0, sizeof(reply));
        reply.qpn                 = cv->cv_local_qpn;
        reply.qkey                = IBNAL_QKEY;
        reply.start_psn           = cv->cv_rxpsn;
        reply.arb_initiator_depth = IBNAL_ARB_INITIATOR_DEPTH;
        reply.arb_resp_res        = IBNAL_ARB_RESP_RES;
        reply.failover_accepted   = IBNAL_FAILOVER_ACCEPTED;
        reply.rnr_retry_count     = cv->cv_rnr_count;
        reply.targ_ack_delay      = kibnal_data.kib_hca_attrs.ack_delay;

        /* setup txmsg... */
        memset(&txmsg, 0, sizeof(txmsg));
        kibnal_init_msg(&txmsg, IBNAL_MSG_CONNACK,
                        sizeof(txmsg.ibm_u.connparams));
        LASSERT (txmsg.ibm_nob <= cm_REP_priv_data_len);
        txmsg.ibm_u.connparams.ibcp_queue_depth = IBNAL_MSG_QUEUE_SIZE;
        txmsg.ibm_u.connparams.ibcp_max_msg_size = IBNAL_MSG_SIZE;
        txmsg.ibm_u.connparams.ibcp_max_frags = IBNAL_MAX_RDMA_FRAGS;
        kibnal_pack_msg(&txmsg, conn->ibc_version,
                        0, rxmsg.ibm_srcnid, rxmsg.ibm_srcstamp, 0);

        /* ...and copy into reply to avoid alignment issues */
        memcpy(&reply.priv_data, &txmsg, txmsg.ibm_nob);

        kibnal_set_conn_state(conn, IBNAL_CONN_PASSIVE_WAIT);

        cmrc = cm_accept(conn->ibc_cep, &reply, NULL,
                         kibnal_cm_callback, conn);

        if (cmrc == cm_stat_success)
                return;                         /* callback has got my ref on conn */

        /* back out state change (no callback happening) */
        kibnal_set_conn_state(conn, IBNAL_CONN_INIT);
        rc = -EIO;
        reason = IBNAL_REJECT_FATAL;

 reject:
        CDEBUG(D_NET, "Rejecting connreq from %s\n",
               libcfs_nid2str(rxmsg.ibm_srcnid));

        kibnal_reject(cep, reason);

        if (conn != NULL) {
                LASSERT (rc != 0);
                kibnal_connreq_done(conn, 0, rc);
                kibnal_conn_decref(conn);
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

        LIBCFS_ALLOC_ATOMIC(pcr, sizeof(*pcr));
        if (pcr == NULL) {
                CERROR("Can't allocate passive connreq\n");

                kibnal_reject(cep, IBNAL_REJECT_NO_RESOURCES);
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

        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_CONNECT);
        cv->cv_conndata = *cd;

        kibnal_schedule_conn(conn);
        kibnal_conn_decref(conn);
}

void
kibnal_connect_conn (kib_conn_t *conn)
{
        static cm_request_data_t  cmreq;
        static kib_msg_t          msg;

        kib_connvars_t           *cv = conn->ibc_connvars;
        kib_peer_t               *peer = conn->ibc_peer;
        cm_return_t               cmrc;

        /* Only called by connd => statics OK */
        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_ARP);

        memset(&cmreq, 0, sizeof(cmreq));

        cmreq.sid = (__u64)(*kibnal_tunables.kib_service_number);

        cmreq.cep_data.ca_guid              = kibnal_data.kib_hca_attrs.guid;
        cmreq.cep_data.qpn                  = cv->cv_local_qpn;
        cmreq.cep_data.retry_cnt            = *kibnal_tunables.kib_retry_cnt;
        cmreq.cep_data.rtr_retry_cnt        = *kibnal_tunables.kib_rnr_cnt;
        cmreq.cep_data.start_psn            = cv->cv_rxpsn;
        cmreq.cep_data.end_to_end_flow_ctrl = IBNAL_EE_FLOW_CNT;
        // XXX ack_timeout?
        // offered_resp_res
        // offered_initiator_depth

        cmreq.path_data.subn_local  = IBNAL_LOCAL_SUB;
        cmreq.path_data.path        = cv->cv_path;

        /* setup msg... */
        memset(&msg, 0, sizeof(msg));
        kibnal_init_msg(&msg, IBNAL_MSG_CONNREQ, sizeof(msg.ibm_u.connparams));
        LASSERT(msg.ibm_nob <= cm_REQ_priv_data_len);
        msg.ibm_u.connparams.ibcp_queue_depth = IBNAL_MSG_QUEUE_SIZE;
        msg.ibm_u.connparams.ibcp_max_msg_size = IBNAL_MSG_SIZE;
        msg.ibm_u.connparams.ibcp_max_frags = IBNAL_MAX_RDMA_FRAGS;
        kibnal_pack_msg(&msg, conn->ibc_version, 0, peer->ibp_nid, 0, 0);

        if (the_lnet.ln_testprotocompat != 0) {
                /* single-shot proto check */
                LNET_LOCK();
                if ((the_lnet.ln_testprotocompat & 1) != 0) {
                        msg.ibm_version++;
                        the_lnet.ln_testprotocompat &= ~1;
                }
                if ((the_lnet.ln_testprotocompat & 2) != 0) {
                        msg.ibm_magic = LNET_PROTO_MAGIC;
                        the_lnet.ln_testprotocompat &= ~2;
                }
                LNET_UNLOCK();
        }

        /* ...and copy into cmreq to avoid alignment issues */
        memcpy(&cmreq.priv_data, &msg, msg.ibm_nob);

        CDEBUG(D_NET, "Connecting %p to %s\n", conn,
               libcfs_nid2str(peer->ibp_nid));

        kibnal_conn_addref(conn);               /* ++ref for CM callback */
        kibnal_set_conn_state(conn, IBNAL_CONN_ACTIVE_CONNECT);

        cmrc = cm_connect(conn->ibc_cep, &cmreq,
                          kibnal_active_connect_callback, conn);
        if (cmrc == cm_stat_success) {
                CDEBUG(D_NET, "connection REQ sent to %s\n",
                       libcfs_nid2str(peer->ibp_nid));
                return;
        }

        CERROR ("Connect %s failed: %d\n", libcfs_nid2str(peer->ibp_nid), cmrc);
        kibnal_conn_decref(conn);       /* drop callback's ref */
        kibnal_connreq_done(conn, 1, -EHOSTUNREACH);
}

void
kibnal_reconnect (kib_conn_t *conn, int why)
{
        kib_peer_t      *peer = conn->ibc_peer;
        int              retry;
        unsigned long    flags;
        cm_return_t      cmrc;
        cm_cep_handle_t  cep;

        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_CONNECT);

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        LASSERT (peer->ibp_connecting > 0);          /* 'conn' at least */

        /* retry connection if it's still needed and no other connection
         * attempts (active or passive) are in progress.
         * Immediate reconnect is required, so I don't even look at the
         * reconnection timeout etc */

        retry = (!list_empty(&peer->ibp_tx_queue) &&
                 peer->ibp_connecting == 1 &&
                 peer->ibp_accepting == 0);

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        if (!retry) {
                kibnal_connreq_done(conn, 1, why);
                return;
        }

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

        /* reuse conn; no need to peer->ibp_connecting++ */
        kibnal_set_conn_state(conn, IBNAL_CONN_ACTIVE_ARP);
        kibnal_connect_conn(conn);
}

void
kibnal_check_connreply (kib_conn_t *conn)
{
        static cm_rtu_data_t  rtu;
        static kib_msg_t      msg;

        kib_connvars_t   *cv = conn->ibc_connvars;
        cm_reply_data_t  *reply = &cv->cv_conndata.data.reply;
        kib_peer_t       *peer = conn->ibc_peer;
        int               msgnob;
        cm_return_t       cmrc;
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

                /* copy into msg to avoid alignment issues */
                msgnob = MIN(cm_REP_priv_data_len, sizeof(msg));
                memcpy(&msg, &reply->priv_data, msgnob);

                rc = kibnal_unpack_msg(&msg, conn->ibc_version, msgnob);
                if (rc != 0) {
                        CERROR("Can't unpack reply from %s\n",
                               libcfs_nid2str(peer->ibp_nid));
                        kibnal_connreq_done(conn, 1, rc);
                        return;
                }

                if (msg.ibm_type != IBNAL_MSG_CONNACK ) {
                        CERROR("Unexpected message type %d from %s\n",
                               msg.ibm_type, libcfs_nid2str(peer->ibp_nid));
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        return;
                }

                if (msg.ibm_u.connparams.ibcp_queue_depth != IBNAL_MSG_QUEUE_SIZE) {
                        CERROR("%s has incompatible queue depth %d(%d wanted)\n",
                               libcfs_nid2str(peer->ibp_nid),
                               msg.ibm_u.connparams.ibcp_queue_depth,
                               IBNAL_MSG_QUEUE_SIZE);
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        return;
                }

                if (msg.ibm_u.connparams.ibcp_max_msg_size > IBNAL_MSG_SIZE) {
                        CERROR("%s max message size %d too big (%d max)\n",
                               libcfs_nid2str(peer->ibp_nid),
                               msg.ibm_u.connparams.ibcp_max_msg_size,
                               IBNAL_MSG_SIZE);
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        return;
                }

                if (msg.ibm_u.connparams.ibcp_max_frags > IBNAL_MAX_RDMA_FRAGS) {
                        CERROR("%s max frags %d too big (%d max)\n",
                               libcfs_nid2str(peer->ibp_nid),
                               msg.ibm_u.connparams.ibcp_max_frags,
                               IBNAL_MAX_RDMA_FRAGS);
                        kibnal_connreq_done(conn, 1, -EPROTO);
                        return;
                }

                read_lock_irqsave(&kibnal_data.kib_global_lock, flags);
                if (kibnal_data.kib_ni->ni_nid == msg.ibm_dstnid &&
                    msg.ibm_dststamp == kibnal_data.kib_incarnation)
                        rc = 0;
                else
                        rc = -ESTALE;
                read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
                if (rc != 0) {
                        CERROR("Stale connection reply from %s\n",
                               libcfs_nid2str(peer->ibp_nid));
                        kibnal_connreq_done(conn, 1, rc);
                        return;
                }

                conn->ibc_incarnation = msg.ibm_srcstamp;
                conn->ibc_credits = IBNAL_MSG_QUEUE_SIZE;
                conn->ibc_reserved_credits = IBNAL_MSG_QUEUE_SIZE;
                LASSERT (conn->ibc_credits + conn->ibc_reserved_credits
                         <= IBNAL_RX_MSGS);

                rc = kibnal_post_receives(conn);
                if (rc != 0) {
                        CERROR("Can't post receives for %s\n",
                               libcfs_nid2str(peer->ibp_nid));
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

                CERROR("cm_accept %s failed: %d\n",
                       libcfs_nid2str(peer->ibp_nid), cmrc);
                /* Back out of RTU: no callback coming */
                kibnal_set_conn_state(conn, IBNAL_CONN_ACTIVE_CHECK_REPLY);
                kibnal_conn_decref(conn);
                kibnal_connreq_done(conn, 1, -EIO);
                return;
        }

        if (cv->cv_conndata.status == cm_event_conn_reject) {

                if (cv->cv_conndata.data.reject.reason == cm_rej_code_usr_rej) {
                        unsigned char *bytes =
                                cv->cv_conndata.data.reject.priv_data;
                        int   magic   = (bytes[0]) |
                                        (bytes[1] << 8) |
                                        (bytes[2] << 16) |
                                        (bytes[3] << 24);
                        int   version = (bytes[4]) |
                                        (bytes[5] << 8);
                        int   why     = (bytes[6]);

                        /* Expected proto/version: she just doesn't like me (or
                         * ran out of resources) */
                        if (magic == IBNAL_MSG_MAGIC &&
                            version == conn->ibc_version) {
                                CERROR("conn -> %s rejected: fatal error %d\n",
                                       libcfs_nid2str(peer->ibp_nid), why);

                                if (why == IBNAL_REJECT_CONN_RACE)
                                        kibnal_reconnect(conn, -EALREADY);
                                else
                                        kibnal_connreq_done(conn, 1, -ECONNREFUSED);
                                return;
                        }

                        /* Fail unless it's worth retrying with an old proto
                         * version */
                        if (!(magic == IBNAL_MSG_MAGIC &&
                              version == IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD &&
                              conn->ibc_version == IBNAL_MSG_VERSION)) {
                                CERROR("conn -> %s rejected: bad protocol "
                                       "magic/ver %08x/%x why %d\n",
                                       libcfs_nid2str(peer->ibp_nid),
                                       magic, version, why);

                                kibnal_connreq_done(conn, 1, -ECONNREFUSED);
                                return;
                        }

                        conn->ibc_version = version;
                        CWARN ("Connection to %s refused: "
                               "retrying with old protocol version 0x%x\n",
                               libcfs_nid2str(peer->ibp_nid), version);

                        kibnal_reconnect(conn, -ECONNREFUSED);
                        return;
                } else if (cv->cv_conndata.data.reject.reason ==
                           cm_rej_code_stale_conn) {

                        CWARN ("conn -> %s stale: retrying\n",
                               libcfs_nid2str(peer->ibp_nid));

                        kibnal_reconnect(conn, -ESTALE);
                        return;
                } else {
                        CDEBUG(D_NETERROR, "conn -> %s rejected: reason %d\n",
                               libcfs_nid2str(peer->ibp_nid),
                               cv->cv_conndata.data.reject.reason);
                        kibnal_connreq_done(conn, 1, -ECONNREFUSED);
                        return;
                }
                /* NOT REACHED */
        }

        CDEBUG(D_NETERROR, "conn -> %s failed: %d\n",
               libcfs_nid2str(peer->ibp_nid), cv->cv_conndata.status);
        kibnal_connreq_done(conn, 1, -ECONNABORTED);
}

void
kibnal_arp_done (kib_conn_t *conn)
{
        kib_peer_t           *peer = conn->ibc_peer;
        kib_connvars_t       *cv = conn->ibc_connvars;
        ibat_arp_data_t      *arp = &cv->cv_arp;
        ib_path_record_v2_t  *path = &cv->cv_path;
        vv_return_t           vvrc;
        int                   rc;
        unsigned long         flags;

        LASSERT (!in_interrupt());
        LASSERT (current == kibnal_data.kib_connd);
        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_ARP);
        LASSERT (peer->ibp_arp_count > 0);

        if (cv->cv_arprc != ibat_stat_ok) {
                CDEBUG(D_NETERROR, "Arp %s @ %u.%u.%u.%u failed: %d\n",
                       libcfs_nid2str(peer->ibp_nid), HIPQUAD(peer->ibp_ip),
                       cv->cv_arprc);
                goto failed;
        }

        if ((arp->mask & IBAT_PRI_PATH_VALID) != 0) {
                CDEBUG(D_NET, "Got valid path for %s\n",
                       libcfs_nid2str(peer->ibp_nid));

                *path = *arp->primary_path;

                vvrc = base_gid2port_num(kibnal_data.kib_hca, &path->sgid,
                                         &cv->cv_port);
                if (vvrc != vv_return_ok) {
                        CWARN("base_gid2port_num failed for %s @ %u.%u.%u.%u: %d\n",
                              libcfs_nid2str(peer->ibp_nid),
                              HIPQUAD(peer->ibp_ip), vvrc);
                        goto failed;
                }

                vvrc = gid2gid_index(kibnal_data.kib_hca, cv->cv_port,
                                     &path->sgid, &cv->cv_sgid_index);
                if (vvrc != vv_return_ok) {
                        CWARN("gid2gid_index failed for %s @ %u.%u.%u.%u: %d\n",
                              libcfs_nid2str(peer->ibp_nid),
                              HIPQUAD(peer->ibp_ip), vvrc);
                        goto failed;
                }

                vvrc = pkey2pkey_index(kibnal_data.kib_hca, cv->cv_port,
                                       path->pkey, &cv->cv_pkey_index);
                if (vvrc != vv_return_ok) {
                        CWARN("pkey2pkey_index failed for %s @ %u.%u.%u.%u: %d\n",
                              libcfs_nid2str(peer->ibp_nid),
                              HIPQUAD(peer->ibp_ip), vvrc);
                        goto failed;
                }

                path->mtu = IBNAL_IB_MTU;

        } else if ((arp->mask & IBAT_LID_VALID) != 0) {
                CWARN("Creating new path record for %s @ %u.%u.%u.%u\n",
                      libcfs_nid2str(peer->ibp_nid), HIPQUAD(peer->ibp_ip));

                cv->cv_pkey_index = IBNAL_PKEY_IDX;
                cv->cv_sgid_index = IBNAL_SGID_IDX;
                cv->cv_port = arp->local_port_num;

                memset(path, 0, sizeof(*path));

                vvrc = port_num2base_gid(kibnal_data.kib_hca, cv->cv_port,
                                         &path->sgid);
                if (vvrc != vv_return_ok) {
                        CWARN("port_num2base_gid failed for %s @ %u.%u.%u.%u: %d\n",
                              libcfs_nid2str(peer->ibp_ip),
                              HIPQUAD(peer->ibp_ip), vvrc);
                        goto failed;
                }

                vvrc = port_num2base_lid(kibnal_data.kib_hca, cv->cv_port,
                                         &path->slid);
                if (vvrc != vv_return_ok) {
                        CWARN("port_num2base_lid failed for %s @ %u.%u.%u.%u: %d\n",
                              libcfs_nid2str(peer->ibp_ip),
                              HIPQUAD(peer->ibp_ip), vvrc);
                        goto failed;
                }

                path->dgid          = arp->gid;
                path->sl            = IBNAL_SERVICE_LEVEL;
                path->dlid          = arp->lid;
                path->mtu           = IBNAL_IB_MTU;
                path->rate          = IBNAL_STATIC_RATE;
                path->pkt_life_time = IBNAL_PKT_LIFETIME;
                path->pkey          = IBNAL_PKEY;
                path->traffic_class = IBNAL_TRAFFIC_CLASS;
        } else {
                CWARN("Arp for %s @ %u.%u.%u.%u returned neither PATH nor LID\n",
                      libcfs_nid2str(peer->ibp_nid), HIPQUAD(peer->ibp_ip));
                goto failed;
        }

        rc = kibnal_set_qp_state(conn, vv_qp_state_init);
        if (rc != 0) {
                kibnal_connreq_done(conn, 1, rc);
        }

        /* do the actual connection request */
        kibnal_connect_conn(conn);
        return;

 failed:
        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
        peer->ibp_arp_count--;
        if (peer->ibp_arp_count == 0) {
                /* final ARP attempt failed */
                write_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                        flags);
                CDEBUG(D_NETERROR, "Arp %s @ %u.%u.%u.%u failed (final attempt)\n",
                       libcfs_nid2str(peer->ibp_nid), HIPQUAD(peer->ibp_ip));
        } else {
                /* Retry ARP: ibp_connecting++ so terminating conn
                 * doesn't end peer's connection attempt */
                peer->ibp_connecting++;
                write_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                        flags);
                CDEBUG(D_NETERROR, "Arp %s @ %u.%u.%u.%u failed (%d attempts left)\n",
                       libcfs_nid2str(peer->ibp_nid), HIPQUAD(peer->ibp_ip),
                       peer->ibp_arp_count);

                kibnal_schedule_peer_arp(peer);
        }
        kibnal_connreq_done(conn, 1, -ENETUNREACH);
}

void
kibnal_arp_callback (ibat_stat_t arprc, ibat_arp_data_t *arp_data, void *arg)
{
        /* CAVEAT EMPTOR: tasklet context */
        kib_peer_t *peer;
        kib_conn_t *conn = (kib_conn_t *)arg;

        LASSERT (conn != NULL);
        LASSERT (conn->ibc_state == IBNAL_CONN_ACTIVE_ARP);

        peer = conn->ibc_peer;

        if (arprc != ibat_stat_ok)
                CDEBUG(D_NETERROR, "Arp %s at %u.%u.%u.%u failed: %d\n",
                       libcfs_nid2str(peer->ibp_nid), HIPQUAD(peer->ibp_ip), arprc);
        else
                CDEBUG(D_NET, "Arp %s at %u.%u.%u.%u OK: LID %s PATH %s\n",
                       libcfs_nid2str(peer->ibp_nid), HIPQUAD(peer->ibp_ip),
                       (arp_data->mask & IBAT_LID_VALID) == 0 ? "invalid" : "valid",
                       (arp_data->mask & IBAT_PRI_PATH_VALID) == 0 ? "invalid" : "valid");

        conn->ibc_connvars->cv_arprc = arprc;
        if (arprc == ibat_stat_ok)
                conn->ibc_connvars->cv_arp = *arp_data;

        kibnal_schedule_conn(conn);
        kibnal_conn_decref(conn);
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
        LASSERT (peer->ibp_arp_count > 0);

        cep = cm_create_cep(cm_cep_transp_rc);
        if (cep == NULL) {
                CERROR ("Can't create cep for conn->%s\n",
                        libcfs_nid2str(peer->ibp_nid));
                kibnal_peer_connect_failed(peer, 1, -ENOMEM);
                return;
        }

        conn = kibnal_create_conn(cep);
        if (conn == NULL) {
                CERROR ("Can't allocate conn->%s\n",
                        libcfs_nid2str(peer->ibp_nid));
                cm_destroy_cep(cep);
                kibnal_peer_connect_failed(peer, 1, -ENOMEM);
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
        case ibat_stat_error:
        case ibat_stat_timeout:
        case ibat_stat_not_found:
                /* Immediate return (ARP cache hit or failure) == no callback. 
                 * Do the next stage directly... */
                conn->ibc_connvars->cv_arprc = ibatrc;
                kibnal_arp_done(conn);
                kibnal_conn_decref(conn);
                break;
        }
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

                        CERROR("Timed out RDMA with %s\n",
                               libcfs_nid2str(peer->ibp_nid));

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
        cfs_pause(cfs_time_seconds(1)/10);

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

        cfs_daemonize ("kibnal_connd");
        cfs_block_allsigs ();

        init_waitqueue_entry (&wait, current);
        kibnal_data.kib_connd = current;

        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);

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
                        LIBCFS_FREE(pcr, sizeof(*pcr));

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
                                kibnal_arp_done(conn);
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
                                CDEBUG(D_NETERROR, "RDMA failed: %d\n",
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
