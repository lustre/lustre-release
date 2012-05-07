/*
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/ulnds/ptllnd/ptllnd_cb.c
 *
 * Author: Eric Barton <eeb@bartonsoftware.com>
 */

#include "ptllnd.h"

void
ptllnd_set_tx_deadline(ptllnd_tx_t *tx)
{
        ptllnd_peer_t  *peer = tx->tx_peer;
        lnet_ni_t      *ni = peer->plp_ni;
        ptllnd_ni_t    *plni = ni->ni_data;

        tx->tx_deadline = cfs_time_current_sec() + plni->plni_timeout;
}

void
ptllnd_post_tx(ptllnd_tx_t *tx)
{
        ptllnd_peer_t  *peer = tx->tx_peer;

        LASSERT (tx->tx_type != PTLLND_MSG_TYPE_NOOP);

        ptllnd_set_tx_deadline(tx);
        cfs_list_add_tail(&tx->tx_list, &peer->plp_txq);
        ptllnd_check_sends(peer);
}

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
        int                nmsg = peer->plp_lazy_credits +
                                  plni->plni_peer_credits;

        ptllnd_size_buffers(ni, -nmsg);

        LASSERT (peer->plp_closing);
        LASSERT (plni->plni_npeers > 0);
        LASSERT (cfs_list_empty(&peer->plp_txq));
        LASSERT (cfs_list_empty(&peer->plp_noopq));
        LASSERT (cfs_list_empty(&peer->plp_activeq));
        plni->plni_npeers--;
        LIBCFS_FREE(peer, sizeof(*peer));
}

void
ptllnd_abort_txs(ptllnd_ni_t *plni, cfs_list_t *q)
{
        while (!cfs_list_empty(q)) {
                ptllnd_tx_t *tx = cfs_list_entry(q->next, ptllnd_tx_t, tx_list);

                tx->tx_status = -ESHUTDOWN;
                cfs_list_del(&tx->tx_list);
                cfs_list_add_tail(&tx->tx_list, &plni->plni_zombie_txs);
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

        if (!cfs_list_empty(&peer->plp_txq) ||
            !cfs_list_empty(&peer->plp_noopq) ||
            !cfs_list_empty(&peer->plp_activeq) ||
            error != 0) {
                CWARN("Closing %s: %d\n", libcfs_id2str(peer->plp_id), error);
                if (plni->plni_debug)
                        ptllnd_dump_debug(ni, peer->plp_id);
        }

        ptllnd_abort_txs(plni, &peer->plp_txq);
        ptllnd_abort_txs(plni, &peer->plp_noopq);
        ptllnd_abort_txs(plni, &peer->plp_activeq);

        cfs_list_del(&peer->plp_list);
        ptllnd_peer_decref(peer);
}

ptllnd_peer_t *
ptllnd_find_peer(lnet_ni_t *ni, lnet_process_id_t id, int create)
{
        ptllnd_ni_t       *plni = ni->ni_data;
        unsigned int       hash = LNET_NIDADDR(id.nid) % plni->plni_peer_hash_size;
        ptllnd_peer_t     *plp;
        ptllnd_tx_t       *tx;
        int                rc;

        LASSERT (LNET_NIDNET(id.nid) == LNET_NIDNET(ni->ni_nid));

        cfs_list_for_each_entry (plp, &plni->plni_peer_hash[hash], plp_list) {
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
        rc = ptllnd_size_buffers(ni, plni->plni_peer_credits);
        if (rc != 0) {
                plni->plni_npeers--;
                return NULL;
        }

        LIBCFS_ALLOC(plp, sizeof(*plp));
        if (plp == NULL) {
                CERROR("Can't allocate new peer %s\n", libcfs_id2str(id));
                plni->plni_npeers--;
                ptllnd_size_buffers(ni, -plni->plni_peer_credits);
                return NULL;
        }

        plp->plp_ni = ni;
        plp->plp_id = id;
        plp->plp_ptlid.nid = LNET_NIDADDR(id.nid);
        plp->plp_ptlid.pid = plni->plni_ptllnd_pid;
        plp->plp_credits = 1; /* add more later when she gives me credits */
        plp->plp_max_msg_size = plni->plni_max_msg_size; /* until I hear from her */
        plp->plp_sent_credits = 1;              /* Implicit credit for HELLO */
        plp->plp_outstanding_credits = plni->plni_peer_credits - 1;
        plp->plp_lazy_credits = 0;
        plp->plp_extra_lazy_credits = 0;
        plp->plp_match = 0;
        plp->plp_stamp = 0;
        plp->plp_sent_hello = 0;
        plp->plp_recvd_hello = 0;
        plp->plp_closing = 0;
        plp->plp_refcount = 1;
        CFS_INIT_LIST_HEAD(&plp->plp_list);
        CFS_INIT_LIST_HEAD(&plp->plp_txq);
        CFS_INIT_LIST_HEAD(&plp->plp_noopq);
        CFS_INIT_LIST_HEAD(&plp->plp_activeq);

        ptllnd_peer_addref(plp);
        cfs_list_add_tail(&plp->plp_list, &plni->plni_peer_hash[hash]);

        tx = ptllnd_new_tx(plp, PTLLND_MSG_TYPE_HELLO, 0);
        if (tx == NULL) {
                CERROR("Can't send HELLO to %s\n", libcfs_id2str(id));
                ptllnd_close_peer(plp, -ENOMEM);
                ptllnd_peer_decref(plp);
                return NULL;
        }

        tx->tx_msg.ptlm_u.hello.kptlhm_matchbits = PTL_RESERVED_MATCHBITS;
        tx->tx_msg.ptlm_u.hello.kptlhm_max_msg_size = plni->plni_max_msg_size;

        PTLLND_HISTORY("%s[%d/%d+%d(%d)]: post hello %p", libcfs_id2str(id),
                       tx->tx_peer->plp_credits,
                       tx->tx_peer->plp_outstanding_credits,
                       tx->tx_peer->plp_sent_credits,
                       plni->plni_peer_credits + 
                       tx->tx_peer->plp_lazy_credits, tx);
        ptllnd_post_tx(tx);

        return plp;
}

int
ptllnd_count_q(cfs_list_t *q)
{
        cfs_list_t *e;
        int         n = 0;

        cfs_list_for_each(e, q) {
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
        CDEBUG(D_WARNING, "%s %s b %ld.%06ld/%ld.%06ld"
               " r %ld.%06ld/%ld.%06ld status %d\n",
               ptllnd_tx_typestr(tx->tx_type),
               libcfs_id2str(tx->tx_peer->plp_id),
               tx->tx_bulk_posted.tv_sec, tx->tx_bulk_posted.tv_usec,
               tx->tx_bulk_done.tv_sec, tx->tx_bulk_done.tv_usec,
               tx->tx_req_posted.tv_sec, tx->tx_req_posted.tv_usec,
               tx->tx_req_done.tv_sec, tx->tx_req_done.tv_usec,
               tx->tx_status);
}

void
ptllnd_debug_peer(lnet_ni_t *ni, lnet_process_id_t id)
{
        ptllnd_peer_t    *plp = ptllnd_find_peer(ni, id, 0);
        ptllnd_ni_t      *plni = ni->ni_data;
        ptllnd_tx_t      *tx;

        if (plp == NULL) {
                CDEBUG(D_WARNING, "No peer %s\n", libcfs_id2str(id));
                return;
        }

        CWARN("%s %s%s [%d] "LPU64".%06d m "LPU64" q %d/%d/%d c %d/%d+%d(%d)\n",
              libcfs_id2str(id),
              plp->plp_recvd_hello ? "H" : "_",
              plp->plp_closing     ? "C" : "_",
              plp->plp_refcount,
              plp->plp_stamp / 1000000, (int)(plp->plp_stamp % 1000000),
              plp->plp_match,
              ptllnd_count_q(&plp->plp_txq),
              ptllnd_count_q(&plp->plp_noopq),
              ptllnd_count_q(&plp->plp_activeq),
              plp->plp_credits, plp->plp_outstanding_credits, plp->plp_sent_credits,
              plni->plni_peer_credits + plp->plp_lazy_credits);

        CDEBUG(D_WARNING, "txq:\n");
        cfs_list_for_each_entry (tx, &plp->plp_txq, tx_list) {
                ptllnd_debug_tx(tx);
        }

        CDEBUG(D_WARNING, "noopq:\n");
        cfs_list_for_each_entry (tx, &plp->plp_noopq, tx_list) {
                ptllnd_debug_tx(tx);
        }

        CDEBUG(D_WARNING, "activeq:\n");
        cfs_list_for_each_entry (tx, &plp->plp_activeq, tx_list) {
                ptllnd_debug_tx(tx);
        }

        CDEBUG(D_WARNING, "zombies:\n");
        cfs_list_for_each_entry (tx, &plni->plni_zombie_txs, tx_list) {
                if (tx->tx_peer->plp_id.nid == id.nid &&
                    tx->tx_peer->plp_id.pid == id.pid)
                        ptllnd_debug_tx(tx);
        }

        CDEBUG(D_WARNING, "history:\n");
        cfs_list_for_each_entry (tx, &plni->plni_tx_history, tx_list) {
                if (tx->tx_peer->plp_id.nid == id.nid &&
                    tx->tx_peer->plp_id.pid == id.pid)
                        ptllnd_debug_tx(tx);
        }

        ptllnd_peer_decref(plp);
}

void
ptllnd_dump_debug(lnet_ni_t *ni, lnet_process_id_t id)
{
        ptllnd_debug_peer(ni, id);
        ptllnd_dump_history();
}

int
ptllnd_setasync(lnet_ni_t *ni, lnet_process_id_t id, int nasync)
{
        ptllnd_peer_t *peer = ptllnd_find_peer(ni, id, nasync > 0);
        int            rc;

        if (peer == NULL)
                return -ENOMEM;

        LASSERT (peer->plp_lazy_credits >= 0);
        LASSERT (peer->plp_extra_lazy_credits >= 0);

        /* If nasync < 0, we're being told we can reduce the total message
         * headroom.  We can't do this right now because our peer might already
         * have credits for the extra buffers, so we just account the extra
         * headroom in case we need it later and only destroy buffers when the
         * peer closes.
         *
         * Note that the following condition handles this case, where it
         * actually increases the extra lazy credit counter. */

        if (nasync <= peer->plp_extra_lazy_credits) {
                peer->plp_extra_lazy_credits -= nasync;
                return 0;
        }

        LASSERT (nasync > 0);

        nasync -= peer->plp_extra_lazy_credits;
        peer->plp_extra_lazy_credits = 0;

        rc = ptllnd_size_buffers(ni, nasync);
        if (rc == 0) {
                peer->plp_lazy_credits += nasync;
                peer->plp_outstanding_credits += nasync;
        }

        return rc;
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

        CDEBUG(D_NET, "peer=%p type=%d payload=%d\n", peer, type, payload_nob);

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

        memset(&tx->tx_bulk_posted, 0, sizeof(tx->tx_bulk_posted));
        memset(&tx->tx_bulk_done, 0, sizeof(tx->tx_bulk_done));
        memset(&tx->tx_req_posted, 0, sizeof(tx->tx_req_posted));
        memset(&tx->tx_req_done, 0, sizeof(tx->tx_req_done));

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

        CDEBUG(D_NET, "tx=%p\n", tx);

        return tx;
}

void
ptllnd_abort_tx(ptllnd_tx_t *tx, ptl_handle_md_t *mdh)
{
        ptllnd_peer_t   *peer = tx->tx_peer;
        lnet_ni_t       *ni = peer->plp_ni;
        int              rc;
        time_t           start = cfs_time_current_sec();
        ptllnd_ni_t     *plni = ni->ni_data;
        int              w = plni->plni_long_wait;

        while (!PtlHandleIsEqual(*mdh, PTL_INVALID_HANDLE)) {
                rc = PtlMDUnlink(*mdh);
#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                if (rc == PTL_OK) /* unlink successful => no unlinked event */
                        return;
                LASSERT (rc == PTL_MD_IN_USE);
#endif
                if (w > 0 && cfs_time_current_sec() > start + w/1000) {
                        CWARN("Waited %ds to abort tx to %s\n",
                              (int)(cfs_time_current_sec() - start),
                              libcfs_id2str(peer->plp_id));
                        w *= 2;
                }
                /* Wait for ptllnd_tx_event() to invalidate */
                ptllnd_wait(ni, w);
        }
}

void
ptllnd_cull_tx_history(ptllnd_ni_t *plni)
{
        int max = plni->plni_max_tx_history;

        while (plni->plni_ntx_history > max) {
                ptllnd_tx_t *tx = cfs_list_entry(plni->plni_tx_history.next,
                                                 ptllnd_tx_t, tx_list);
                cfs_list_del(&tx->tx_list);

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

        if (!cfs_list_empty(&tx->tx_list))
                cfs_list_del_init(&tx->tx_list);

        if (tx->tx_status != 0) {
                if (plni->plni_debug) {
                        CERROR("Completing tx for %s with error %d\n",
                               libcfs_id2str(peer->plp_id), tx->tx_status);
                        ptllnd_debug_tx(tx);
                }
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
        cfs_list_add_tail(&tx->tx_list, &plni->plni_tx_history);

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

        for (;;) {
                int temp_offset = offset;
                int resid = len;
                LIBCFS_ALLOC(piov, niov * sizeof(*piov));
                if (piov == NULL)
                        return -ENOMEM;

                for (npiov = 0;; npiov++) {
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
                CERROR("PtlMEAttach failed: %s(%d)\n",
                       ptllnd_errtype2str(rc), rc);
                return -ENOMEM;
        }

        buf->plb_posted = 1;
        plni->plni_nposted_buffers++;

        rc = PtlMDAttach(meh, md, LNET_UNLINK, &buf->plb_md);
        if (rc == PTL_OK)
                return 0;

        CERROR("PtlMDAttach failed: %s(%d)\n",
               ptllnd_errtype2str(rc), rc);

        buf->plb_posted = 0;
        plni->plni_nposted_buffers--;

        rc = PtlMEUnlink(meh);
        LASSERT (rc == PTL_OK);

        return -ENOMEM;
}

static inline int
ptllnd_peer_send_noop (ptllnd_peer_t *peer)
{
        ptllnd_ni_t *plni = peer->plp_ni->ni_data;

        if (!peer->plp_sent_hello ||
            peer->plp_credits == 0 ||
            !cfs_list_empty(&peer->plp_noopq) ||
            peer->plp_outstanding_credits < PTLLND_CREDIT_HIGHWATER(plni))
                return 0;

        /* No tx to piggyback NOOP onto or no credit to send a tx */
        return (cfs_list_empty(&peer->plp_txq) || peer->plp_credits == 1);
}

void
ptllnd_check_sends(ptllnd_peer_t *peer)
{
        ptllnd_ni_t    *plni = peer->plp_ni->ni_data;
        ptllnd_tx_t    *tx;
        ptl_md_t        md;
        ptl_handle_md_t mdh;
        int             rc;

        CDEBUG(D_NET, "%s: [%d/%d+%d(%d)\n",
               libcfs_id2str(peer->plp_id), peer->plp_credits,
               peer->plp_outstanding_credits, peer->plp_sent_credits,
               plni->plni_peer_credits + peer->plp_lazy_credits);

        if (ptllnd_peer_send_noop(peer)) {
                tx = ptllnd_new_tx(peer, PTLLND_MSG_TYPE_NOOP, 0);
                CDEBUG(D_NET, "NOOP tx=%p\n",tx);
                if (tx == NULL) {
                        CERROR("Can't return credits to %s\n",
                               libcfs_id2str(peer->plp_id));
                } else {
                        ptllnd_set_tx_deadline(tx);
                        cfs_list_add_tail(&tx->tx_list, &peer->plp_noopq);
                }
        }

        for (;;) {
                if (!cfs_list_empty(&peer->plp_noopq)) {
                        LASSERT (peer->plp_sent_hello);
                        tx = cfs_list_entry(peer->plp_noopq.next,
                                            ptllnd_tx_t, tx_list);
                } else if (!cfs_list_empty(&peer->plp_txq)) {
                        tx = cfs_list_entry(peer->plp_txq.next,
                                            ptllnd_tx_t, tx_list);
                } else {
                        /* nothing to send right now */
                        break;
                }

                LASSERT (tx->tx_msgsize > 0);

                LASSERT (peer->plp_outstanding_credits >= 0);
                LASSERT (peer->plp_sent_credits >= 0);
                LASSERT (peer->plp_outstanding_credits + peer->plp_sent_credits
                         <= plni->plni_peer_credits + peer->plp_lazy_credits);
                LASSERT (peer->plp_credits >= 0);

                /* say HELLO first */
                if (!peer->plp_sent_hello) {
                        LASSERT (cfs_list_empty(&peer->plp_noopq));
                        LASSERT (tx->tx_type == PTLLND_MSG_TYPE_HELLO);

                        peer->plp_sent_hello = 1;
                }

                if (peer->plp_credits == 0) {   /* no credits */
                        PTLLND_HISTORY("%s[%d/%d+%d(%d)]: no creds for %p",
                                       libcfs_id2str(peer->plp_id),
                                       peer->plp_credits,
                                       peer->plp_outstanding_credits,
                                       peer->plp_sent_credits,
                                       plni->plni_peer_credits +
                                       peer->plp_lazy_credits, tx);
                        break;
                }

                /* Last/Initial credit reserved for NOOP/HELLO */
                if (peer->plp_credits == 1 &&
                    tx->tx_type != PTLLND_MSG_TYPE_NOOP &&
                    tx->tx_type != PTLLND_MSG_TYPE_HELLO) {
                        PTLLND_HISTORY("%s[%d/%d+%d(%d)]: too few creds for %p",
                                       libcfs_id2str(peer->plp_id),
                                       peer->plp_credits,
                                       peer->plp_outstanding_credits,
                                       peer->plp_sent_credits,
                                       plni->plni_peer_credits +
                                       peer->plp_lazy_credits, tx);
                        break;
                }

                cfs_list_del(&tx->tx_list);
                cfs_list_add_tail(&tx->tx_list, &peer->plp_activeq);

                CDEBUG(D_NET, "Sending at TX=%p type=%s (%d)\n",tx,
                       ptllnd_msgtype2str(tx->tx_type),tx->tx_type);

                if (tx->tx_type == PTLLND_MSG_TYPE_NOOP &&
                    !ptllnd_peer_send_noop(peer)) {
                        /* redundant NOOP */
                        ptllnd_tx_done(tx);
                        continue;
                }

                /* Set stamp at the last minute; on a new peer, I don't know it
                 * until I receive the HELLO back */
                tx->tx_msg.ptlm_dststamp = peer->plp_stamp;

                /*
                 * Return all the credits we have
                 */
                tx->tx_msg.ptlm_credits = MIN(PTLLND_MSG_MAX_CREDITS,
                                              peer->plp_outstanding_credits);
                peer->plp_sent_credits += tx->tx_msg.ptlm_credits;
                peer->plp_outstanding_credits -= tx->tx_msg.ptlm_credits;

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
                        CERROR("PtlMDBind for %s failed: %s(%d)\n",
                               libcfs_id2str(peer->plp_id),
                               ptllnd_errtype2str(rc), rc);
                        tx->tx_status = -EIO;
                        ptllnd_tx_done(tx);
                        break;
                }

                LASSERT (tx->tx_type != PTLLND_RDMA_WRITE &&
                         tx->tx_type != PTLLND_RDMA_READ);

                tx->tx_reqmdh = mdh;
                gettimeofday(&tx->tx_req_posted, NULL);

                PTLLND_HISTORY("%s[%d/%d+%d(%d)]: %s %p c %d",
                               libcfs_id2str(peer->plp_id),
                               peer->plp_credits,
                               peer->plp_outstanding_credits,
                               peer->plp_sent_credits,
                               plni->plni_peer_credits +
                               peer->plp_lazy_credits,
                               ptllnd_msgtype2str(tx->tx_type), tx,
                               tx->tx_msg.ptlm_credits);

                rc = PtlPut(mdh, PTL_NOACK_REQ, peer->plp_ptlid,
                            plni->plni_portal, 0, LNET_MSG_MATCHBITS, 0, 0);
                if (rc != PTL_OK) {
                        CERROR("PtlPut for %s failed: %s(%d)\n",
                               libcfs_id2str(peer->plp_id),
                               ptllnd_errtype2str(rc), rc);
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
                       ptllnd_msgtype2str(type), libcfs_id2str(peer->plp_id));
                return -ENOMEM;
        }

        rc = ptllnd_set_txiov(tx, niov, iov, offset, len);
        if (rc != 0) {
                CERROR("Can't allocate iov %d for %s\n",
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
        w = plni->plni_long_wait;
        ptllnd_set_tx_deadline(tx);

        while (!peer->plp_recvd_hello) {    /* wait to validate plp_match */
                if (peer->plp_closing) {
                        rc = -EIO;
                        goto failed;
                }

                /* NB must check here to avoid unbounded wait - tx not yet
                 * on peer->plp_txq, so ptllnd_watchdog can't expire it */
                if (tx->tx_deadline < cfs_time_current_sec()) {
                        CERROR("%s tx for %s timed out\n",
                               ptllnd_msgtype2str(type),
                               libcfs_id2str(peer->plp_id));
                        rc = -ETIMEDOUT;
                        goto failed;
                }

                if (w > 0 && cfs_time_current_sec() > start + w/1000) {
                        CWARN("Waited %ds to connect to %s\n",
                              (int)(cfs_time_current_sec() - start),
                              libcfs_id2str(peer->plp_id));
                        w *= 2;
                }
                ptllnd_wait(ni, w);
        }

        if (peer->plp_match < PTL_RESERVED_MATCHBITS)
                peer->plp_match = PTL_RESERVED_MATCHBITS;
        matchbits = peer->plp_match++;

        rc = PtlMEAttach(plni->plni_nih, plni->plni_portal, peer->plp_ptlid,
                         matchbits, 0, PTL_UNLINK, PTL_INS_BEFORE, &meh);
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach for %s failed: %s(%d)\n",
                       libcfs_id2str(peer->plp_id),
                       ptllnd_errtype2str(rc), rc);
                rc = -EIO;
                goto failed;
        }

        gettimeofday(&tx->tx_bulk_posted, NULL);

        rc = PtlMDAttach(meh, md, LNET_UNLINK, &mdh);
        if (rc != PTL_OK) {
                CERROR("PtlMDAttach for %s failed: %s(%d)\n",
                       libcfs_id2str(peer->plp_id),
                       ptllnd_errtype2str(rc), rc);
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
        PTLLND_HISTORY("%s[%d/%d+%d(%d)]: post passive %s p %d %p",
                       libcfs_id2str(msg->msg_target),
                       peer->plp_credits, peer->plp_outstanding_credits,
                       peer->plp_sent_credits,
                       plni->plni_peer_credits + peer->plp_lazy_credits,
                       lnet_msgtyp2str(msg->msg_type),
                       (le32_to_cpu(msg->msg_type) == LNET_MSG_PUT) ? 
                       le32_to_cpu(msg->msg_hdr.msg.put.ptl_index) :
                       (le32_to_cpu(msg->msg_type) == LNET_MSG_GET) ? 
                       le32_to_cpu(msg->msg_hdr.msg.get.ptl_index) : -1,
                       tx);
        ptllnd_post_tx(tx);
        return 0;

 failed:
        tx->tx_status = rc;
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
                CERROR("Can't allocate iov %d for %s\n",
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
                CERROR("PtlMDBind for %s failed: %s(%d)\n",
                       libcfs_id2str(peer->plp_id),
                       ptllnd_errtype2str(rc), rc);
                rc = -EIO;
                goto failed;
        }

        tx->tx_bulkmdh = mdh;
        tx->tx_lnetmsg = msg;

        ptllnd_set_tx_deadline(tx);
        cfs_list_add_tail(&tx->tx_list, &peer->plp_activeq);
        gettimeofday(&tx->tx_bulk_posted, NULL);

        if (type == PTLLND_RDMA_READ)
                rc = PtlGet(mdh, peer->plp_ptlid,
                            plni->plni_portal, 0, matchbits, 0);
        else
                rc = PtlPut(mdh, PTL_NOACK_REQ, peer->plp_ptlid,
                            plni->plni_portal, 0, matchbits, 0, 
                            (msg == NULL) ? PTLLND_RDMA_FAIL : PTLLND_RDMA_OK);

        if (rc == PTL_OK)
                return 0;

        CERROR("Can't initiate RDMA with %s: %s(%d)\n",
               libcfs_id2str(peer->plp_id),
               ptllnd_errtype2str(rc), rc);

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
                LASSERT (msg->msg_len == 0);
                break;                          /* send IMMEDIATE */

        case LNET_MSG_GET:
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
                nob = msg->msg_len;
                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[nob]);
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
        PTLLND_HISTORY("%s[%d/%d+%d(%d)]: post immediate %s p %d %p",
                       libcfs_id2str(msg->msg_target),
                       plp->plp_credits, plp->plp_outstanding_credits,
                       plp->plp_sent_credits,
                       plni->plni_peer_credits + plp->plp_lazy_credits,
                       lnet_msgtyp2str(msg->msg_type),
                       (le32_to_cpu(msg->msg_type) == LNET_MSG_PUT) ? 
                       le32_to_cpu(msg->msg_hdr.msg.put.ptl_index) :
                       (le32_to_cpu(msg->msg_type) == LNET_MSG_GET) ? 
                       le32_to_cpu(msg->msg_hdr.msg.get.ptl_index) : -1,
                       tx);
        ptllnd_post_tx(tx);
        ptllnd_peer_decref(plp);
        return 0;
}

void
ptllnd_rx_done(ptllnd_rx_t *rx)
{
        ptllnd_peer_t *plp = rx->rx_peer;
        ptllnd_ni_t   *plni = plp->plp_ni->ni_data;

        plp->plp_outstanding_credits++;

        PTLLND_HISTORY("%s[%d/%d+%d(%d)]: rx=%p done\n",
                       libcfs_id2str(plp->plp_id),
                       plp->plp_credits, plp->plp_outstanding_credits, 
                       plp->plp_sent_credits,
                       plni->plni_peer_credits + plp->plp_lazy_credits, rx);

        ptllnd_check_sends(plp);

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
                rc = ptllnd_active_rdma(rx->rx_peer, PTLLND_RDMA_READ, msg,
                                        rx->rx_msg->ptlm_u.rdma.kptlrm_matchbits,
                                        niov, iov, offset, mlen);
                break;

        case PTLLND_MSG_TYPE_GET:
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
                CERROR("Bad protocol version %04x from %s: %04x expected\n",
                       (__u32)msg_version, ptllnd_ptlid2str(initiator), PTLLND_MSG_VERSION);

                if (plni->plni_abort_on_protocol_mismatch)
                        abort();

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

                if (plni->plni_dump_on_nak)
                        ptllnd_dump_debug(ni, srcid);

                if (plni->plni_abort_on_nak)
                        abort();

                plp = ptllnd_find_peer(ni, srcid, 0);
                if (plp == NULL) {
                        CERROR("Ignore NAK from %s: no peer\n", libcfs_id2str(srcid));
                        return;
                }
                ptllnd_close_peer(plp, -EPROTO);
                ptllnd_peer_decref(plp);
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

        PTLLND_HISTORY("RX %s: %s %d %p", libcfs_id2str(srcid), 
                       ptllnd_msgtype2str(msg->ptlm_type),
                       msg->ptlm_credits, &rx);

        switch (msg->ptlm_type) {
        case PTLLND_MSG_TYPE_PUT:
        case PTLLND_MSG_TYPE_GET:
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
                if (nob < offsetof(kptl_msg_t,
                                   ptlm_u.immediate.kptlim_payload)) {
                        CERROR("Short immediate from %s(%s)\n",
                               libcfs_id2str(srcid),
                               ptllnd_ptlid2str(initiator));
                        return;
                }
                break;

        case PTLLND_MSG_TYPE_HELLO:
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
                break;

        default:
                CERROR("Bad message type %d from %s(%s)\n", msg->ptlm_type,
                       libcfs_id2str(srcid),
                       ptllnd_ptlid2str(initiator));
                return;
        }

        plp = ptllnd_find_peer(ni, srcid, 0);
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

                plp->plp_max_msg_size = msg->ptlm_u.hello.kptlhm_max_msg_size;
                plp->plp_match = msg->ptlm_u.hello.kptlhm_matchbits;
                plp->plp_stamp = msg->ptlm_srcstamp;
                plp->plp_recvd_hello = 1;

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

        /* Check peer only sends when I've sent her credits */
        if (plp->plp_sent_credits == 0) {
                CERROR("%s[%d/%d+%d(%d)]: unexpected message\n",
                       libcfs_id2str(plp->plp_id),
                       plp->plp_credits, plp->plp_outstanding_credits,
                       plp->plp_sent_credits,
                       plni->plni_peer_credits + plp->plp_lazy_credits);
                return;
        }
        plp->plp_sent_credits--;

        /* No check for credit overflow - the peer may post new buffers after
         * the startup handshake. */
        plp->plp_credits += msg->ptlm_credits;

        /* All OK so far; assume the message is good... */

        rx.rx_peer      = plp;
        rx.rx_msg       = msg;
        rx.rx_nob       = nob;
        plni->plni_nrxs++;

        switch (msg->ptlm_type) {
        default: /* message types have been checked already */
                ptllnd_rx_done(&rx);
                break;

        case PTLLND_MSG_TYPE_PUT:
        case PTLLND_MSG_TYPE_GET:
                rc = lnet_parse(ni, &msg->ptlm_u.rdma.kptlrm_hdr,
                                msg->ptlm_srcnid, &rx, 1);
                if (rc < 0)
                        ptllnd_rx_done(&rx);
                break;

        case PTLLND_MSG_TYPE_IMMEDIATE:
                rc = lnet_parse(ni, &msg->ptlm_u.immediate.kptlim_hdr,
                                msg->ptlm_srcnid, &rx, 0);
                if (rc < 0)
                        ptllnd_rx_done(&rx);
                break;
        }

        if (msg->ptlm_credits > 0)
                ptllnd_check_sends(plp);

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

        if (event->ni_fail_type != PTL_NI_OK) {

                CERROR("event type %s(%d), status %s(%d) from %s\n",
                       ptllnd_evtype2str(event->type), event->type,
                       ptllnd_errtype2str(event->ni_fail_type), 
                       event->ni_fail_type,
                       ptllnd_ptlid2str(event->initiator));

        } else if (event->type == PTL_EVENT_PUT_END) {
#if (PTL_MD_LOCAL_ALIGN8 == 0)
                /* Portals can't force message alignment - someone sending an
                 * odd-length message could misalign subsequent messages */
                if ((event->mlength & 7) != 0) {
                        CERROR("Message from %s has odd length "LPU64
                               " probable version incompatibility\n",
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
                CERROR("Error %s(%d) event %s(%d) unlinked %d, %s(%d) for %s\n",
                       ptllnd_errtype2str(event->ni_fail_type),
                       event->ni_fail_type,
                       ptllnd_evtype2str(event->type), event->type,
                       unlinked, ptllnd_msgtype2str(tx->tx_type), tx->tx_type,
                       libcfs_id2str(tx->tx_peer->plp_id));

        LASSERT (!PtlHandleIsEqual(event->md_handle, PTL_INVALID_HANDLE));

        isreq = PtlHandleIsEqual(event->md_handle, tx->tx_reqmdh);
        if (isreq) {
                LASSERT (event->md.start == (void *)&tx->tx_msg);
                if (unlinked) {
                        tx->tx_reqmdh = PTL_INVALID_HANDLE;
                        gettimeofday(&tx->tx_req_done, NULL);
                }
        }

        isbulk = PtlHandleIsEqual(event->md_handle, tx->tx_bulkmdh);
        if ( isbulk && unlinked ) {
                tx->tx_bulkmdh = PTL_INVALID_HANDLE;
                gettimeofday(&tx->tx_bulk_done, NULL);
        }

        LASSERT (!isreq != !isbulk);            /* always one and only 1 match */

        PTLLND_HISTORY("%s[%d/%d+%d(%d)]: TX done %p %s%s",
                       libcfs_id2str(tx->tx_peer->plp_id),
                       tx->tx_peer->plp_credits,
                       tx->tx_peer->plp_outstanding_credits,
                       tx->tx_peer->plp_sent_credits,
                       plni->plni_peer_credits + tx->tx_peer->plp_lazy_credits,
                       tx, isreq ? "REQ" : "BULK", unlinked ? "(unlinked)" : "");

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
                cfs_list_del(&tx->tx_list);
                cfs_list_add_tail(&tx->tx_list, &plni->plni_zombie_txs);
        }
}

ptllnd_tx_t *
ptllnd_find_timed_out_tx(ptllnd_peer_t *peer)
{
        time_t            now = cfs_time_current_sec();
        ptllnd_tx_t *tx;

        cfs_list_for_each_entry (tx, &peer->plp_txq, tx_list) {
                if (tx->tx_deadline < now)
                        return tx;
        }

        cfs_list_for_each_entry (tx, &peer->plp_noopq, tx_list) {
                if (tx->tx_deadline < now)
                        return tx;
        }

        cfs_list_for_each_entry (tx, &peer->plp_activeq, tx_list) {
                if (tx->tx_deadline < now)
                        return tx;
        }

        return NULL;
}

void
ptllnd_check_peer(ptllnd_peer_t *peer)
{
        ptllnd_tx_t *tx = ptllnd_find_timed_out_tx(peer);

        if (tx == NULL)
                return;

        CERROR("%s (sent %d recvd %d, credits %d/%d/%d/%d/%d): timed out %p %p\n",
               libcfs_id2str(peer->plp_id), peer->plp_sent_hello, peer->plp_recvd_hello,
               peer->plp_credits, peer->plp_outstanding_credits,
               peer->plp_sent_credits, peer->plp_lazy_credits,
               peer->plp_extra_lazy_credits, tx, tx->tx_lnetmsg);
        ptllnd_debug_tx(tx);
        ptllnd_close_peer(peer, -ETIMEDOUT);
}

void
ptllnd_watchdog (lnet_ni_t *ni, time_t now)
{
        ptllnd_ni_t      *plni = ni->ni_data;
        const int         n = 4;
        int               p = plni->plni_watchdog_interval;
        int               chunk = plni->plni_peer_hash_size;
        int               interval = now - (plni->plni_watchdog_nextt - p);
        int               i;
        cfs_list_t       *hashlist;
        cfs_list_t       *tmp;
        cfs_list_t       *nxt;

        /* Time to check for RDMA timeouts on a few more peers:
         * I try to do checks every 'p' seconds on a proportion of the peer
         * table and I need to check every connection 'n' times within a
         * timeout interval, to ensure I detect a timeout on any connection
         * within (n+1)/n times the timeout interval. */

        LASSERT (now >= plni->plni_watchdog_nextt);

        if (plni->plni_timeout > n * interval) { /* Scan less than the whole table? */
                chunk = (chunk * n * interval) / plni->plni_timeout;
                if (chunk == 0)
                        chunk = 1;
        }

        for (i = 0; i < chunk; i++) {
                hashlist = &plni->plni_peer_hash[plni->plni_watchdog_peeridx];

                cfs_list_for_each_safe(tmp, nxt, hashlist) {
                        ptllnd_check_peer(cfs_list_entry(tmp, ptllnd_peer_t,
                                          plp_list));
                }

                plni->plni_watchdog_peeridx = (plni->plni_watchdog_peeridx + 1) %
                                              plni->plni_peer_hash_size;
        }

        plni->plni_watchdog_nextt = now + p;
}

void
ptllnd_wait (lnet_ni_t *ni, int milliseconds)
{
        static struct timeval  prevt;
        static int             prevt_count;
        static int             call_count;

        struct timeval         start;
        struct timeval         then;
        struct timeval         now;
        struct timeval         deadline;

        ptllnd_ni_t   *plni = ni->ni_data;
        ptllnd_tx_t   *tx;
        ptl_event_t    event;
        int            which;
        int            rc;
        int            found = 0;
        int            timeout = 0;

        /* Handle any currently queued events, returning immediately if any.
         * Otherwise block for the timeout and handle all events queued
         * then. */

        gettimeofday(&start, NULL);
        call_count++;

        if (milliseconds <= 0) {
                deadline = start;
        } else {
                deadline.tv_sec  = start.tv_sec  +  milliseconds/1000;
                deadline.tv_usec = start.tv_usec + (milliseconds % 1000)*1000;

                if (deadline.tv_usec >= 1000000) {
                        start.tv_usec -= 1000000;
                        start.tv_sec++;
                }
        }

        for (;;) {
                gettimeofday(&then, NULL);

                rc = PtlEQPoll(&plni->plni_eqh, 1, timeout, &event, &which);

                gettimeofday(&now, NULL);

                if ((now.tv_sec*1000 + now.tv_usec/1000) - 
                    (then.tv_sec*1000 + then.tv_usec/1000) > timeout + 1000) {
                        /* 1000 mS grace...........................^ */
                        CERROR("SLOW PtlEQPoll(%d): %dmS elapsed\n", timeout,
                               (int)(now.tv_sec*1000 + now.tv_usec/1000) - 
                               (int)(then.tv_sec*1000 + then.tv_usec/1000));
                }

                if (rc == PTL_EQ_EMPTY) {
                        if (found)              /* handled some events */
                                break;

                        if (now.tv_sec >= plni->plni_watchdog_nextt) { /* check timeouts? */
                                ptllnd_watchdog(ni, now.tv_sec);
                                LASSERT (now.tv_sec < plni->plni_watchdog_nextt);
                        }

                        if (now.tv_sec > deadline.tv_sec || /* timeout expired */
                            (now.tv_sec == deadline.tv_sec &&
                             now.tv_usec >= deadline.tv_usec))
                                break;

                        if (milliseconds < 0 ||
                            plni->plni_watchdog_nextt <= deadline.tv_sec)  {
                                timeout = (plni->plni_watchdog_nextt - now.tv_sec)*1000;
                        } else {
                                timeout = (deadline.tv_sec - now.tv_sec)*1000 +
                                          (deadline.tv_usec - now.tv_usec)/1000;
                        }

                        continue;
                }

                LASSERT (rc == PTL_OK || rc == PTL_EQ_DROPPED);

                if (rc == PTL_EQ_DROPPED)
                        CERROR("Event queue: size %d is too small\n",
                               plni->plni_eq_size);

                timeout = 0;
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

        while (!cfs_list_empty(&plni->plni_zombie_txs)) {
                tx = cfs_list_entry(plni->plni_zombie_txs.next,
                                ptllnd_tx_t, tx_list);
                cfs_list_del_init(&tx->tx_list);
                ptllnd_tx_done(tx);
        }

        if (prevt.tv_sec == 0 ||
            prevt.tv_sec != now.tv_sec) {
                PTLLND_HISTORY("%d wait entered at %d.%06d - prev %d %d.%06d", 
                               call_count, (int)start.tv_sec, (int)start.tv_usec,
                               prevt_count, (int)prevt.tv_sec, (int)prevt.tv_usec);
                prevt = now;
        }
}
