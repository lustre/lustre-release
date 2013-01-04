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
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/ptllnd/ptllnd_peer.c
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 * Author: E Barton <eeb@bartonsoftware.com>
 */

#include "ptllnd.h"
#include <libcfs/list.h>

static int
kptllnd_count_queue(cfs_list_t *q)
{
        cfs_list_t *e;
        int         n = 0;

        cfs_list_for_each(e, q) {
                n++;
        }

        return n;
}

int
kptllnd_get_peer_info(int index,
                      lnet_process_id_t *id,
                      int *state, int *sent_hello,
                      int *refcount, __u64 *incarnation,
                      __u64 *next_matchbits, __u64 *last_matchbits_seen,
                      int *nsendq, int *nactiveq,
                      int *credits, int *outstanding_credits)
{
	rwlock_t     *g_lock = &kptllnd_data.kptl_peer_rw_lock;
        unsigned long     flags;
        cfs_list_t       *ptmp;
        kptl_peer_t      *peer;
        int               i;
        int               rc = -ENOENT;

	read_lock_irqsave(g_lock, flags);

        for (i = 0; i < kptllnd_data.kptl_peer_hash_size; i++) {
                cfs_list_for_each (ptmp, &kptllnd_data.kptl_peers[i]) {
                        peer = cfs_list_entry(ptmp, kptl_peer_t, peer_list);

                        if (index-- > 0)
                                continue;

                        *id          = peer->peer_id;
                        *state       = peer->peer_state;
                        *sent_hello  = peer->peer_sent_hello;
                        *refcount    = cfs_atomic_read(&peer->peer_refcount);
                        *incarnation = peer->peer_incarnation;

			spin_lock(&peer->peer_lock);

                        *next_matchbits      = peer->peer_next_matchbits;
                        *last_matchbits_seen = peer->peer_last_matchbits_seen;
                        *credits             = peer->peer_credits;
                        *outstanding_credits = peer->peer_outstanding_credits;

                        *nsendq   = kptllnd_count_queue(&peer->peer_sendq);
                        *nactiveq = kptllnd_count_queue(&peer->peer_activeq);

			spin_unlock(&peer->peer_lock);

                        rc = 0;
                        goto out;
                }
        }

 out:
	read_unlock_irqrestore(g_lock, flags);
        return rc;
}

void
kptllnd_peer_add_peertable_locked (kptl_peer_t *peer)
{
        LASSERT (kptllnd_data.kptl_n_active_peers <
                 kptllnd_data.kptl_expected_peers);

        LASSERT (peer->peer_state == PEER_STATE_WAITING_HELLO ||
                 peer->peer_state == PEER_STATE_ACTIVE);

        kptllnd_data.kptl_n_active_peers++;
        cfs_atomic_inc(&peer->peer_refcount);       /* +1 ref for the list */

        /* NB add to HEAD of peer list for MRU order!
         * (see kptllnd_cull_peertable) */
        cfs_list_add(&peer->peer_list, kptllnd_nid2peerlist(peer->peer_id.nid));
}

void
kptllnd_cull_peertable_locked (lnet_process_id_t pid)
{
        /* I'm about to add a new peer with this portals ID to the peer table,
         * so (a) this peer should not exist already and (b) I want to leave at
         * most (max_procs_per_nid - 1) peers with this NID in the table. */
        cfs_list_t   *peers = kptllnd_nid2peerlist(pid.nid);
        int           cull_count = *kptllnd_tunables.kptl_max_procs_per_node;
        int           count;
        cfs_list_t   *tmp;
        cfs_list_t   *nxt;
        kptl_peer_t  *peer;

        count = 0;
        cfs_list_for_each_safe (tmp, nxt, peers) {
                /* NB I rely on kptllnd_peer_add_peertable_locked to add peers
                 * in MRU order */
                peer = cfs_list_entry(tmp, kptl_peer_t, peer_list);
                        
                if (LNET_NIDADDR(peer->peer_id.nid) != LNET_NIDADDR(pid.nid))
                        continue;

                LASSERT (peer->peer_id.pid != pid.pid);
                        
                count++;

                if (count < cull_count) /* recent (don't cull) */
                        continue;

                CDEBUG(D_NET, "Cull %s(%s)\n",
                       libcfs_id2str(peer->peer_id),
                       kptllnd_ptlid2str(peer->peer_ptlid));
                
                kptllnd_peer_close_locked(peer, 0);
        }
}

kptl_peer_t *
kptllnd_peer_allocate (kptl_net_t *net, lnet_process_id_t lpid, ptl_process_id_t ppid)
{
        unsigned long    flags;
        kptl_peer_t     *peer;

        LIBCFS_ALLOC(peer, sizeof (*peer));
        if (peer == NULL) {
                CERROR("Can't create peer %s (%s)\n",
                       libcfs_id2str(lpid), 
                       kptllnd_ptlid2str(ppid));
                return NULL;
        }

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        CFS_INIT_LIST_HEAD (&peer->peer_noops);
        CFS_INIT_LIST_HEAD (&peer->peer_sendq);
        CFS_INIT_LIST_HEAD (&peer->peer_activeq);
	spin_lock_init(&peer->peer_lock);

        peer->peer_state = PEER_STATE_ALLOCATED;
        peer->peer_error = 0;
        peer->peer_last_alive = 0;
        peer->peer_id = lpid;
        peer->peer_ptlid = ppid;
        peer->peer_credits = 1;                 /* enough for HELLO */
        peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;
        peer->peer_outstanding_credits = *kptllnd_tunables.kptl_peertxcredits - 1;
        peer->peer_sent_credits = 1;           /* HELLO credit is implicit */
        peer->peer_max_msg_size = PTLLND_MIN_BUFFER_SIZE; /* until we know better */

        cfs_atomic_set(&peer->peer_refcount, 1);    /* 1 ref for caller */

	write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        peer->peer_myincarnation = kptllnd_data.kptl_incarnation;

        /* Only increase # peers under lock, to guarantee we dont grow it
         * during shutdown */
        if (net->net_shutdown) {
		write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock,
                                            flags);
                LIBCFS_FREE(peer, sizeof(*peer));
                return NULL;
        }

        kptllnd_data.kptl_npeers++;
	write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);
        return peer;
}

void
kptllnd_peer_destroy (kptl_peer_t *peer)
{
        unsigned long flags;

        CDEBUG(D_NET, "Peer=%p\n", peer);

        LASSERT (!cfs_in_interrupt());
        LASSERT (cfs_atomic_read(&peer->peer_refcount) == 0);
        LASSERT (peer->peer_state == PEER_STATE_ALLOCATED ||
                 peer->peer_state == PEER_STATE_ZOMBIE);
        LASSERT (cfs_list_empty(&peer->peer_noops));
        LASSERT (cfs_list_empty(&peer->peer_sendq));
        LASSERT (cfs_list_empty(&peer->peer_activeq));

	write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        if (peer->peer_state == PEER_STATE_ZOMBIE)
                cfs_list_del(&peer->peer_list);

        kptllnd_data.kptl_npeers--;

	write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        LIBCFS_FREE (peer, sizeof (*peer));
}

void
kptllnd_cancel_txlist (cfs_list_t *peerq, cfs_list_t *txs)
{
        cfs_list_t  *tmp;
        cfs_list_t  *nxt;
        kptl_tx_t   *tx;

        cfs_list_for_each_safe (tmp, nxt, peerq) {
                tx = cfs_list_entry(tmp, kptl_tx_t, tx_list);

                cfs_list_del(&tx->tx_list);
                cfs_list_add_tail(&tx->tx_list, txs);

                tx->tx_status = -EIO;
                tx->tx_active = 0;
        }
}

void
kptllnd_peer_cancel_txs(kptl_peer_t *peer, cfs_list_t *txs)
{
        unsigned long   flags;

	spin_lock_irqsave(&peer->peer_lock, flags);

        kptllnd_cancel_txlist(&peer->peer_noops, txs);
        kptllnd_cancel_txlist(&peer->peer_sendq, txs);
        kptllnd_cancel_txlist(&peer->peer_activeq, txs);
                
	spin_unlock_irqrestore(&peer->peer_lock, flags);
}

void
kptllnd_peer_alive (kptl_peer_t *peer)
{
        /* This is racy, but everyone's only writing cfs_time_current() */
        peer->peer_last_alive = cfs_time_current();
        cfs_mb();
}

void
kptllnd_peer_notify (kptl_peer_t *peer)
{
        unsigned long flags;
        kptl_net_t   *net;
        kptl_net_t  **nets;
        int           i = 0;
        int           nnets = 0;
        int           error = 0;
        cfs_time_t    last_alive = 0;

	spin_lock_irqsave(&peer->peer_lock, flags);

        if (peer->peer_error != 0) {
                error = peer->peer_error;
                peer->peer_error = 0;
                last_alive = peer->peer_last_alive;
        }

	spin_unlock_irqrestore(&peer->peer_lock, flags);

        if (error == 0)
                return;

	read_lock(&kptllnd_data.kptl_net_rw_lock);
        cfs_list_for_each_entry (net, &kptllnd_data.kptl_nets, net_list)
                nnets++;
	read_unlock(&kptllnd_data.kptl_net_rw_lock);

        if (nnets == 0) /* shutdown in progress */
                return;

        LIBCFS_ALLOC(nets, nnets * sizeof(*nets));
        if (nets == NULL) {
                CERROR("Failed to allocate nets[%d]\n", nnets);
                return;
        }
        memset(nets, 0, nnets * sizeof(*nets));

	read_lock(&kptllnd_data.kptl_net_rw_lock);
        i = 0;
        cfs_list_for_each_entry (net, &kptllnd_data.kptl_nets, net_list) {
                LASSERT (i < nnets);
                nets[i] = net;
                kptllnd_net_addref(net);
                i++;
        }
	read_unlock(&kptllnd_data.kptl_net_rw_lock);

        for (i = 0; i < nnets; i++) {
                lnet_nid_t peer_nid;

                net = nets[i];
                if (net == NULL)
                        break;

                if (!net->net_shutdown) {
                        peer_nid = kptllnd_ptl2lnetnid(net->net_ni->ni_nid,
                                                       peer->peer_ptlid.nid);
                        lnet_notify(net->net_ni, peer_nid, 0, last_alive);
                }

                kptllnd_net_decref(net);
        }

        LIBCFS_FREE(nets, nnets * sizeof(*nets));
}

void
kptllnd_handle_closing_peers ()
{
        unsigned long           flags;
        cfs_list_t              txs;
        kptl_peer_t            *peer;
        cfs_list_t             *tmp;
        cfs_list_t             *nxt;
        kptl_tx_t              *tx;
        int                     idle;

        /* Check with a read lock first to avoid blocking anyone */

	read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        idle = cfs_list_empty(&kptllnd_data.kptl_closing_peers) &&
               cfs_list_empty(&kptllnd_data.kptl_zombie_peers);
	read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        if (idle)
                return;

        CFS_INIT_LIST_HEAD(&txs);

	write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        /* Cancel txs on all zombie peers.  NB anyone dropping the last peer
         * ref removes it from this list, so I musn't drop the lock while
         * scanning it. */
        cfs_list_for_each (tmp, &kptllnd_data.kptl_zombie_peers) {
                peer = cfs_list_entry (tmp, kptl_peer_t, peer_list);

                LASSERT (peer->peer_state == PEER_STATE_ZOMBIE);

                kptllnd_peer_cancel_txs(peer, &txs);
        }

        /* Notify LNET and cancel txs on closing (i.e. newly closed) peers.  NB
         * I'm the only one removing from this list, but peers can be added on
         * the end any time I drop the lock. */

        cfs_list_for_each_safe (tmp, nxt, &kptllnd_data.kptl_closing_peers) {
                peer = cfs_list_entry (tmp, kptl_peer_t, peer_list);

                LASSERT (peer->peer_state == PEER_STATE_CLOSING);

                cfs_list_del(&peer->peer_list);
                cfs_list_add_tail(&peer->peer_list,
                                  &kptllnd_data.kptl_zombie_peers);
                peer->peer_state = PEER_STATE_ZOMBIE;

		write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock,
                                            flags);

                kptllnd_peer_notify(peer);
                kptllnd_peer_cancel_txs(peer, &txs);
                kptllnd_peer_decref(peer);

		write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        }

	write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        /* Drop peer's ref on all cancelled txs.  This will get
         * kptllnd_tx_fini() to abort outstanding comms if necessary. */

        cfs_list_for_each_safe (tmp, nxt, &txs) {
                tx = cfs_list_entry(tmp, kptl_tx_t, tx_list);
                cfs_list_del(&tx->tx_list);
                kptllnd_tx_decref(tx);
        }
}

void
kptllnd_peer_close_locked(kptl_peer_t *peer, int why)
{
        switch (peer->peer_state) {
        default:
                LBUG();

        case PEER_STATE_WAITING_HELLO:
        case PEER_STATE_ACTIVE:
                /* Ensure new peers see a new incarnation of me */
                LASSERT(peer->peer_myincarnation <= kptllnd_data.kptl_incarnation);
                if (peer->peer_myincarnation == kptllnd_data.kptl_incarnation)
                        kptllnd_data.kptl_incarnation++;

                /* Removing from peer table */
                kptllnd_data.kptl_n_active_peers--;
                LASSERT (kptllnd_data.kptl_n_active_peers >= 0);

                cfs_list_del(&peer->peer_list);
                kptllnd_peer_unreserve_buffers();

                peer->peer_error = why; /* stash 'why' only on first close */
                peer->peer_state = PEER_STATE_CLOSING;

                /* Schedule for immediate attention, taking peer table's ref */
                cfs_list_add_tail(&peer->peer_list,
                                 &kptllnd_data.kptl_closing_peers);
                cfs_waitq_signal(&kptllnd_data.kptl_watchdog_waitq);
                break;

        case PEER_STATE_ZOMBIE:
        case PEER_STATE_CLOSING:
                break;
        }
}

void
kptllnd_peer_close(kptl_peer_t *peer, int why)
{
        unsigned long      flags;

	write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        kptllnd_peer_close_locked(peer, why);
	write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);
}

int
kptllnd_peer_del(lnet_process_id_t id)
{
        cfs_list_t        *ptmp;
        cfs_list_t        *pnxt;
        kptl_peer_t       *peer;
        int                lo;
        int                hi;
        int                i;
        unsigned long      flags;
        int                rc = -ENOENT;

        /*
         * Find the single bucket we are supposed to look at or if nid is a
         * wildcard (LNET_NID_ANY) then look at all of the buckets
         */
        if (id.nid != LNET_NID_ANY) {
                cfs_list_t *l = kptllnd_nid2peerlist(id.nid);

                lo = hi =  l - kptllnd_data.kptl_peers;
        } else {
                if (id.pid != LNET_PID_ANY)
                        return -EINVAL;

                lo = 0;
                hi = kptllnd_data.kptl_peer_hash_size - 1;
        }

again:
	read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        for (i = lo; i <= hi; i++) {
                cfs_list_for_each_safe (ptmp, pnxt,
                                        &kptllnd_data.kptl_peers[i]) {
                        peer = cfs_list_entry (ptmp, kptl_peer_t, peer_list);

                        if (!(id.nid == LNET_NID_ANY || 
                              (LNET_NIDADDR(peer->peer_id.nid) == LNET_NIDADDR(id.nid) &&
                               (id.pid == LNET_PID_ANY || 
                                peer->peer_id.pid == id.pid))))
                                continue;

                        kptllnd_peer_addref(peer); /* 1 ref for me... */

			read_unlock_irqrestore(&kptllnd_data. \
                                                   kptl_peer_rw_lock,
                                                   flags);

                        kptllnd_peer_close(peer, 0);
                        kptllnd_peer_decref(peer); /* ...until here */

                        rc = 0;         /* matched something */

                        /* start again now I've dropped the lock */
                        goto again;
                }
        }

	read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        return (rc);
}

void
kptllnd_queue_tx(kptl_peer_t *peer, kptl_tx_t *tx)
{
        /* CAVEAT EMPTOR: I take over caller's ref on 'tx' */
        unsigned long flags;

	spin_lock_irqsave(&peer->peer_lock, flags);

        /* Ensure HELLO is sent first */
        if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_NOOP)
                cfs_list_add(&tx->tx_list, &peer->peer_noops);
        else if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_HELLO)
                cfs_list_add(&tx->tx_list, &peer->peer_sendq);
        else
                cfs_list_add_tail(&tx->tx_list, &peer->peer_sendq);

	spin_unlock_irqrestore(&peer->peer_lock, flags);
}


void
kptllnd_post_tx(kptl_peer_t *peer, kptl_tx_t *tx, int nfrag)
{
        /* CAVEAT EMPTOR: I take over caller's ref on 'tx' */
        ptl_handle_md_t  msg_mdh;
        ptl_md_t         md;
        ptl_err_t        prc;

        LASSERT (!tx->tx_idle);
        LASSERT (!tx->tx_active);
        LASSERT (PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));
        LASSERT (PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));
        LASSERT (tx->tx_type == TX_TYPE_SMALL_MESSAGE ||
                 tx->tx_type == TX_TYPE_PUT_REQUEST ||
                 tx->tx_type == TX_TYPE_GET_REQUEST);

        kptllnd_set_tx_peer(tx, peer);

        memset(&md, 0, sizeof(md));

        md.threshold = tx->tx_acked ? 2 : 1;    /* SEND END + ACK? */
        md.options = PTL_MD_OP_PUT |
                     PTL_MD_LUSTRE_COMPLETION_SEMANTICS |
                     PTL_MD_EVENT_START_DISABLE;
        md.user_ptr = &tx->tx_msg_eventarg;
        md.eq_handle = kptllnd_data.kptl_eqh;

        if (nfrag == 0) {
                md.start = tx->tx_msg;
                md.length = tx->tx_msg->ptlm_nob;
        } else {
                LASSERT (nfrag > 1);
                LASSERT (tx->tx_frags->iov[0].iov_base == (void *)tx->tx_msg);

                md.start = tx->tx_frags;
                md.length = nfrag;
                md.options |= PTL_MD_IOVEC;
        }

        prc = PtlMDBind(kptllnd_data.kptl_nih, md, PTL_UNLINK, &msg_mdh);
        if (prc != PTL_OK) {
                CERROR("PtlMDBind(%s) failed: %s(%d)\n",
                       libcfs_id2str(peer->peer_id),
                       kptllnd_errtype2str(prc), prc);
                tx->tx_status = -EIO;
                kptllnd_tx_decref(tx);
                return;
        }


        tx->tx_deadline = jiffies + (*kptllnd_tunables.kptl_timeout * CFS_HZ);
        tx->tx_active = 1;
        tx->tx_msg_mdh = msg_mdh;
        kptllnd_queue_tx(peer, tx);
}

/* NB "restarts" comes from peer_sendq of a single peer */
void
kptllnd_restart_txs (kptl_net_t *net, lnet_process_id_t target,
                     cfs_list_t *restarts)
{
        kptl_tx_t   *tx;
        kptl_tx_t   *tmp;
        kptl_peer_t *peer;

        LASSERT (!cfs_list_empty(restarts));

        if (kptllnd_find_target(net, target, &peer) != 0)
                peer = NULL;

        cfs_list_for_each_entry_safe (tx, tmp, restarts, tx_list) {
                LASSERT (tx->tx_peer != NULL);
                LASSERT (tx->tx_type == TX_TYPE_GET_REQUEST ||
                         tx->tx_type == TX_TYPE_PUT_REQUEST ||
                         tx->tx_type == TX_TYPE_SMALL_MESSAGE);

                cfs_list_del_init(&tx->tx_list);

                if (peer == NULL ||
                    tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_HELLO) {
                        kptllnd_tx_decref(tx);
                        continue;
                }

                LASSERT (tx->tx_msg->ptlm_type != PTLLND_MSG_TYPE_NOOP);
                tx->tx_status = 0;
                tx->tx_active = 1;
                kptllnd_peer_decref(tx->tx_peer);
                tx->tx_peer = NULL;
                kptllnd_set_tx_peer(tx, peer);
                kptllnd_queue_tx(peer, tx); /* takes over my ref on tx */
        }

        if (peer == NULL)
                return;

        kptllnd_peer_check_sends(peer);
        kptllnd_peer_decref(peer);
}

static inline int
kptllnd_peer_send_noop (kptl_peer_t *peer)
{
        if (!peer->peer_sent_hello ||
            peer->peer_credits == 0 ||
            !cfs_list_empty(&peer->peer_noops) ||
            peer->peer_outstanding_credits < PTLLND_CREDIT_HIGHWATER)
                return 0;

        /* No tx to piggyback NOOP onto or no credit to send a tx */
        return (cfs_list_empty(&peer->peer_sendq) || peer->peer_credits == 1);
}

void
kptllnd_peer_check_sends (kptl_peer_t *peer)
{
        ptl_handle_me_t  meh;
        kptl_tx_t       *tx;
        int              rc;
        int              msg_type;
        unsigned long    flags;

        LASSERT(!cfs_in_interrupt());

	spin_lock_irqsave(&peer->peer_lock, flags);

        peer->peer_retry_noop = 0;

        if (kptllnd_peer_send_noop(peer)) {
                /* post a NOOP to return credits */
		spin_unlock_irqrestore(&peer->peer_lock, flags);

                tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
                if (tx == NULL) {
                        CERROR("Can't return credits to %s: can't allocate descriptor\n",
                               libcfs_id2str(peer->peer_id));
                } else {
                        kptllnd_init_msg(tx->tx_msg, PTLLND_MSG_TYPE_NOOP,
                                         peer->peer_id, 0);
                        kptllnd_post_tx(peer, tx, 0);
                }

		spin_lock_irqsave(&peer->peer_lock, flags);
                peer->peer_retry_noop = (tx == NULL);
        }

        for (;;) {
                if (!cfs_list_empty(&peer->peer_noops)) {
                        LASSERT (peer->peer_sent_hello);
                        tx = cfs_list_entry(peer->peer_noops.next,
                                            kptl_tx_t, tx_list);
                } else if (!cfs_list_empty(&peer->peer_sendq)) {
                        tx = cfs_list_entry(peer->peer_sendq.next,
                                            kptl_tx_t, tx_list);
                } else {
                        /* nothing to send right now */
                        break;
                }

                LASSERT (tx->tx_active);
                LASSERT (!PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));
                LASSERT (PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));

                LASSERT (peer->peer_outstanding_credits >= 0);
                LASSERT (peer->peer_sent_credits >= 0);
                LASSERT (peer->peer_sent_credits +
                         peer->peer_outstanding_credits <=
                         *kptllnd_tunables.kptl_peertxcredits);
                LASSERT (peer->peer_credits >= 0);

                msg_type = tx->tx_msg->ptlm_type;

                /* Ensure HELLO is sent first */
                if (!peer->peer_sent_hello) {
                        LASSERT (cfs_list_empty(&peer->peer_noops));
                        if (msg_type != PTLLND_MSG_TYPE_HELLO)
                                break;
                        peer->peer_sent_hello = 1;
                }

                if (peer->peer_credits == 0) {
                        CDEBUG(D_NETTRACE, "%s[%d/%d+%d]: no credits for %s[%p]\n",
                               libcfs_id2str(peer->peer_id), 
                               peer->peer_credits,
                               peer->peer_outstanding_credits, 
                               peer->peer_sent_credits, 
                               kptllnd_msgtype2str(msg_type), tx);
                        break;
                }

                /* Last/Initial credit reserved for NOOP/HELLO */
                if (peer->peer_credits == 1 &&
                    msg_type != PTLLND_MSG_TYPE_HELLO &&
                    msg_type != PTLLND_MSG_TYPE_NOOP) {
                        CDEBUG(D_NETTRACE, "%s[%d/%d+%d]: "
                               "not using last credit for %s[%p]\n",
                               libcfs_id2str(peer->peer_id), 
                               peer->peer_credits,
                               peer->peer_outstanding_credits,
                               peer->peer_sent_credits,
                               kptllnd_msgtype2str(msg_type), tx);
                        break;
                }

                cfs_list_del(&tx->tx_list);

                /* Discard any NOOP I queued if I'm not at the high-water mark
                 * any more or more messages have been queued */
                if (msg_type == PTLLND_MSG_TYPE_NOOP &&
                    !kptllnd_peer_send_noop(peer)) {
                        tx->tx_active = 0;

			spin_unlock_irqrestore(&peer->peer_lock, flags);

                        CDEBUG(D_NET, "%s: redundant noop\n", 
                               libcfs_id2str(peer->peer_id));
                        kptllnd_tx_decref(tx);

			spin_lock_irqsave(&peer->peer_lock, flags);
                        continue;
                }

                /* fill last-minute msg fields */
                kptllnd_msg_pack(tx->tx_msg, peer);

                if (tx->tx_type == TX_TYPE_PUT_REQUEST ||
                    tx->tx_type == TX_TYPE_GET_REQUEST) {
                        /* peer_next_matchbits must be known good */
                        LASSERT (peer->peer_state >= PEER_STATE_ACTIVE);
                        /* Assume 64-bit matchbits can't wrap */
                        LASSERT (peer->peer_next_matchbits >= PTL_RESERVED_MATCHBITS);
                        tx->tx_msg->ptlm_u.rdma.kptlrm_matchbits =
                                peer->peer_next_matchbits++;
                }

                peer->peer_sent_credits += peer->peer_outstanding_credits;
                peer->peer_outstanding_credits = 0;
                peer->peer_credits--;

                CDEBUG(D_NETTRACE, "%s[%d/%d+%d]: %s tx=%p nob=%d cred=%d\n",
                       libcfs_id2str(peer->peer_id), peer->peer_credits,
                       peer->peer_outstanding_credits, peer->peer_sent_credits,
                       kptllnd_msgtype2str(msg_type), tx, tx->tx_msg->ptlm_nob,
                       tx->tx_msg->ptlm_credits);

                cfs_list_add_tail(&tx->tx_list, &peer->peer_activeq);

                kptllnd_tx_addref(tx);          /* 1 ref for me... */

		spin_unlock_irqrestore(&peer->peer_lock, flags);

                if (tx->tx_type == TX_TYPE_PUT_REQUEST ||
                    tx->tx_type == TX_TYPE_GET_REQUEST) {
                        /* Post bulk now we have safe matchbits */
                        rc = PtlMEAttach(kptllnd_data.kptl_nih,
                                         *kptllnd_tunables.kptl_portal,
                                         peer->peer_ptlid,
                                         tx->tx_msg->ptlm_u.rdma.kptlrm_matchbits,
                                         0,             /* ignore bits */
                                         PTL_UNLINK,
                                         PTL_INS_BEFORE,
                                         &meh);
                        if (rc != PTL_OK) {
                                CERROR("PtlMEAttach(%s) failed: %s(%d)\n",
                                       libcfs_id2str(peer->peer_id),
                                       kptllnd_errtype2str(rc), rc);
                                goto failed;
                        }

                        rc = PtlMDAttach(meh, tx->tx_rdma_md, PTL_UNLINK,
                                         &tx->tx_rdma_mdh);
                        if (rc != PTL_OK) {
                                CERROR("PtlMDAttach(%s) failed: %s(%d)\n",
                                       libcfs_id2str(tx->tx_peer->peer_id),
                                       kptllnd_errtype2str(rc), rc);
                                rc = PtlMEUnlink(meh);
                                LASSERT(rc == PTL_OK);
                                tx->tx_rdma_mdh = PTL_INVALID_HANDLE;
                                goto failed;
                        }
                        /* I'm not racing with the event callback here.  It's a
                         * bug if there's an event on the MD I just attached
                         * before I actually send the RDMA request message -
                         * probably matchbits re-used in error. */
                }

                tx->tx_tposted = jiffies;       /* going on the wire */

                rc = PtlPut (tx->tx_msg_mdh,
                             tx->tx_acked ? PTL_ACK_REQ : PTL_NOACK_REQ,
                             peer->peer_ptlid,
                             *kptllnd_tunables.kptl_portal,
                             0,                 /* acl cookie */
                             LNET_MSG_MATCHBITS,
                             0,                 /* offset */
                             0);                /* header data */
                if (rc != PTL_OK) {
                        CERROR("PtlPut %s error %s(%d)\n",
                               libcfs_id2str(peer->peer_id),
                               kptllnd_errtype2str(rc), rc);
                        goto failed;
                }

                kptllnd_tx_decref(tx);          /* drop my ref */

		spin_lock_irqsave(&peer->peer_lock, flags);
        }

	spin_unlock_irqrestore(&peer->peer_lock, flags);
        return;

 failed:
        /* Nuke everything (including tx we were trying) */
        kptllnd_peer_close(peer, -EIO);
        kptllnd_tx_decref(tx);
}

kptl_tx_t *
kptllnd_find_timed_out_tx(kptl_peer_t *peer)
{
        kptl_tx_t         *tx;
        cfs_list_t        *ele;

        cfs_list_for_each(ele, &peer->peer_sendq) {
                tx = cfs_list_entry(ele, kptl_tx_t, tx_list);

                if (cfs_time_aftereq(jiffies, tx->tx_deadline)) {
                        kptllnd_tx_addref(tx);
                        return tx;
                }
        }

        cfs_list_for_each(ele, &peer->peer_activeq) {
                tx = cfs_list_entry(ele, kptl_tx_t, tx_list);

                if (cfs_time_aftereq(jiffies, tx->tx_deadline)) {
                        kptllnd_tx_addref(tx);
                        return tx;
                }
        }

        return NULL;
}


void
kptllnd_peer_check_bucket (int idx, int stamp)
{
        cfs_list_t        *peers = &kptllnd_data.kptl_peers[idx];
        kptl_peer_t       *peer;
        unsigned long      flags;

        CDEBUG(D_NET, "Bucket=%d, stamp=%d\n", idx, stamp);

 again:
        /* NB. Shared lock while I just look */
	read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        cfs_list_for_each_entry (peer, peers, peer_list) {
                kptl_tx_t *tx;
                int        check_sends;
                int        c = -1, oc = -1, sc = -1;
                int        nsend = -1, nactive = -1;
                int        sent_hello = -1, state = -1;

                CDEBUG(D_NET, "Peer=%s Credits=%d Outstanding=%d Send=%d\n",
                       libcfs_id2str(peer->peer_id), peer->peer_credits, 
                       peer->peer_outstanding_credits, peer->peer_sent_credits);

		spin_lock(&peer->peer_lock);

                if (peer->peer_check_stamp == stamp) {
                        /* checked already this pass */
			spin_unlock(&peer->peer_lock);
                        continue;
                }

                peer->peer_check_stamp = stamp;
                tx = kptllnd_find_timed_out_tx(peer);
                check_sends = peer->peer_retry_noop;

                if (tx != NULL) {
                        c  = peer->peer_credits;
                        sc = peer->peer_sent_credits;
                        oc = peer->peer_outstanding_credits;
                        state      = peer->peer_state;
                        sent_hello = peer->peer_sent_hello;
                        nsend   = kptllnd_count_queue(&peer->peer_sendq);
                        nactive = kptllnd_count_queue(&peer->peer_activeq);
                }

		spin_unlock(&peer->peer_lock);

                if (tx == NULL && !check_sends)
                        continue;

                kptllnd_peer_addref(peer); /* 1 ref for me... */

		read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock,
                                           flags);

                if (tx == NULL) { /* nothing timed out */
                        kptllnd_peer_check_sends(peer);
                        kptllnd_peer_decref(peer); /* ...until here or... */

                        /* rescan after dropping the lock */
                        goto again;
                }

                LCONSOLE_ERROR_MSG(0x126, "Timing out %s: %s\n",
                                   libcfs_id2str(peer->peer_id),
                                   (tx->tx_tposted == 0) ?
                                   "no free peer buffers" :
                                   "please check Portals");

		if (tx->tx_tposted) {
			CERROR("Could not send to %s after %ds (sent %lds ago); "
				"check Portals for possible issues\n",
				libcfs_id2str(peer->peer_id),
				*kptllnd_tunables.kptl_timeout,
				cfs_duration_sec(jiffies - tx->tx_tposted));
                } else if (state < PEER_STATE_ACTIVE) {
                        CERROR("Could not connect %s (%d) after %ds; "
                               "peer might be down\n",
                               libcfs_id2str(peer->peer_id), state,
                               *kptllnd_tunables.kptl_timeout);
		} else {
			CERROR("Could not get credits for %s after %ds; "
				"possible Lustre networking issues\n",
			libcfs_id2str(peer->peer_id),
			*kptllnd_tunables.kptl_timeout);
		}

                CERROR("%s timed out: cred %d outstanding %d, sent %d, "
                       "state %d, sent_hello %d, sendq %d, activeq %d "
                       "Tx %p %s %s (%s%s%s) status %d %sposted %lu T/O %ds\n",
                       libcfs_id2str(peer->peer_id), c, oc, sc,
                       state, sent_hello, nsend, nactive,
                       tx, kptllnd_tx_typestr(tx->tx_type),
                       kptllnd_msgtype2str(tx->tx_msg->ptlm_type),
                       tx->tx_active ? "A" : "",
                       PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE) ?
                       "" : "M",
                       PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE) ?
                       "" : "D",
                       tx->tx_status,
                       (tx->tx_tposted == 0) ? "not " : "",
                       (tx->tx_tposted == 0) ? 0UL : (jiffies - tx->tx_tposted),
                       *kptllnd_tunables.kptl_timeout);

                kptllnd_tx_decref(tx);

                kptllnd_peer_close(peer, -ETIMEDOUT);
                kptllnd_peer_decref(peer); /* ...until here */

                /* start again now I've dropped the lock */
                goto again;
        }

	read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);
}

kptl_peer_t *
kptllnd_id2peer_locked (lnet_process_id_t id)
{
        cfs_list_t       *peers = kptllnd_nid2peerlist(id.nid);
        cfs_list_t       *tmp;
        kptl_peer_t      *peer;

        cfs_list_for_each (tmp, peers) {
                peer = cfs_list_entry (tmp, kptl_peer_t, peer_list);

                LASSERT(peer->peer_state == PEER_STATE_WAITING_HELLO ||
                        peer->peer_state == PEER_STATE_ACTIVE);

                /* NB logical LNet peers share one kptl_peer_t */
                if (peer->peer_id.pid != id.pid ||
                    LNET_NIDADDR(id.nid) != LNET_NIDADDR(peer->peer_id.nid))
                        continue;

                kptllnd_peer_addref(peer);

                CDEBUG(D_NET, "%s -> %s (%d)\n",
                       libcfs_id2str(id),
                       kptllnd_ptlid2str(peer->peer_ptlid),
                       cfs_atomic_read (&peer->peer_refcount));
                return peer;
        }

        return NULL;
}

void
kptllnd_peertable_overflow_msg(char *str, lnet_process_id_t id)
{
        LCONSOLE_ERROR_MSG(0x127, "%s %s overflows the peer table[%d]: "
                           "messages may be dropped\n",
                           str, libcfs_id2str(id),
                           kptllnd_data.kptl_n_active_peers);
        LCONSOLE_ERROR_MSG(0x128, "Please correct by increasing "
                           "'max_nodes' or 'max_procs_per_node'\n");
}

__u64
kptllnd_get_last_seen_matchbits_locked(lnet_process_id_t lpid)
{
        kptl_peer_t  *peer;
        cfs_list_t   *tmp;

        /* Find the last matchbits I saw this new peer using.  Note..
           A. This peer cannot be in the peer table - she's new!
           B. If I can't find the peer in the closing/zombie peers, all
              matchbits are safe because all refs to the (old) peer have gone
              so all txs have completed so there's no risk of matchbit
              collision!
         */

        LASSERT(kptllnd_id2peer_locked(lpid) == NULL);

        /* peer's last matchbits can't change after it comes out of the peer
         * table, so first match is fine */

        cfs_list_for_each (tmp, &kptllnd_data.kptl_closing_peers) {
                peer = cfs_list_entry (tmp, kptl_peer_t, peer_list);

                if (LNET_NIDADDR(peer->peer_id.nid) == LNET_NIDADDR(lpid.nid) &&
                    peer->peer_id.pid == lpid.pid)
                        return peer->peer_last_matchbits_seen;
        }

        cfs_list_for_each (tmp, &kptllnd_data.kptl_zombie_peers) {
                peer = cfs_list_entry (tmp, kptl_peer_t, peer_list);

                if (LNET_NIDADDR(peer->peer_id.nid) == LNET_NIDADDR(lpid.nid) &&
                    peer->peer_id.pid == lpid.pid)
                        return peer->peer_last_matchbits_seen;
        }

        return PTL_RESERVED_MATCHBITS;
}

kptl_peer_t *
kptllnd_peer_handle_hello (kptl_net_t *net,
                           ptl_process_id_t initiator, kptl_msg_t *msg)
{
	rwlock_t		*g_lock = &kptllnd_data.kptl_peer_rw_lock;
        kptl_peer_t        *peer;
        kptl_peer_t        *new_peer;
        lnet_process_id_t   lpid;
        unsigned long       flags;
        kptl_tx_t          *hello_tx;
        int                 rc;
        __u64               safe_matchbits;
        __u64               last_matchbits_seen;

        lpid.nid = msg->ptlm_srcnid;
        lpid.pid = msg->ptlm_srcpid;

        CDEBUG(D_NET, "hello from %s(%s)\n",
               libcfs_id2str(lpid), kptllnd_ptlid2str(initiator));

        if (initiator.pid != kptllnd_data.kptl_portals_id.pid &&
            (msg->ptlm_srcpid & LNET_PID_USERFLAG) == 0) {
                /* If the peer's PID isn't _the_ ptllnd kernel pid, she must be
                 * userspace.  Refuse the connection if she hasn't set the
                 * correct flag in her PID... */
                CERROR("Userflag not set in hello from %s (%s)\n",
                       libcfs_id2str(lpid), kptllnd_ptlid2str(initiator));
                return NULL;
        }
        
        /* kptlhm_matchbits are the highest matchbits my peer may have used to
         * RDMA to me.  I ensure I never register buffers for RDMA that could
         * match any she used */
        safe_matchbits = msg->ptlm_u.hello.kptlhm_matchbits + 1;

        if (safe_matchbits < PTL_RESERVED_MATCHBITS) {
                CERROR("Illegal matchbits "LPX64" in HELLO from %s\n",
		       safe_matchbits, libcfs_id2str(lpid));
		return NULL;
	}
	
        if (msg->ptlm_u.hello.kptlhm_max_msg_size < PTLLND_MIN_BUFFER_SIZE) {
                CERROR("%s: max message size %d < MIN %d",
                       libcfs_id2str(lpid),
                       msg->ptlm_u.hello.kptlhm_max_msg_size,
                       PTLLND_MIN_BUFFER_SIZE);
                return NULL;
        }

        if (msg->ptlm_credits <= 1) {
                CERROR("Need more than 1+%d credits from %s\n",
                       msg->ptlm_credits, libcfs_id2str(lpid));
                return NULL;
        }
        
	write_lock_irqsave(g_lock, flags);

        peer = kptllnd_id2peer_locked(lpid);
        if (peer != NULL) {
                if (peer->peer_state == PEER_STATE_WAITING_HELLO) {
                        /* Completing HELLO handshake */
                        LASSERT(peer->peer_incarnation == 0);

                        if (msg->ptlm_dststamp != 0 &&
                            msg->ptlm_dststamp != peer->peer_myincarnation) {
				write_unlock_irqrestore(g_lock, flags);

                                CERROR("Ignoring HELLO from %s: unexpected "
                                       "dststamp "LPX64" ("LPX64" wanted)\n",
                                       libcfs_id2str(lpid),
                                       msg->ptlm_dststamp,
                                       peer->peer_myincarnation);
                                kptllnd_peer_decref(peer);
                                return NULL;
                        }
                        
                        /* Concurrent initiation or response to my HELLO */
                        peer->peer_state = PEER_STATE_ACTIVE;
                        peer->peer_incarnation = msg->ptlm_srcstamp;
                        peer->peer_next_matchbits = safe_matchbits;
                        peer->peer_max_msg_size =
                                msg->ptlm_u.hello.kptlhm_max_msg_size;
                        
			write_unlock_irqrestore(g_lock, flags);
                        return peer;
                }

                if (msg->ptlm_dststamp != 0 &&
                    msg->ptlm_dststamp <= peer->peer_myincarnation) {
			write_unlock_irqrestore(g_lock, flags);

                        CERROR("Ignoring stale HELLO from %s: "
                               "dststamp "LPX64" (current "LPX64")\n",
                               libcfs_id2str(lpid),
                               msg->ptlm_dststamp,
                               peer->peer_myincarnation);
                        kptllnd_peer_decref(peer);
                        return NULL;
                }

                /* Brand new connection attempt: remove old incarnation */
                kptllnd_peer_close_locked(peer, 0);
        }

        kptllnd_cull_peertable_locked(lpid);

	write_unlock_irqrestore(g_lock, flags);

        if (peer != NULL) {
                CDEBUG(D_NET, "Peer %s (%s) reconnecting:"
                       " stamp "LPX64"("LPX64")\n",
                       libcfs_id2str(lpid), kptllnd_ptlid2str(initiator),
                       msg->ptlm_srcstamp, peer->peer_incarnation);

                kptllnd_peer_decref(peer);
                peer = NULL;
        }

        hello_tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
        if (hello_tx == NULL) {
                CERROR("Unable to allocate HELLO message for %s\n",
                       libcfs_id2str(lpid));
                return NULL;
        }

        kptllnd_init_msg(hello_tx->tx_msg, PTLLND_MSG_TYPE_HELLO,
                         lpid, sizeof(kptl_hello_msg_t));

        new_peer = kptllnd_peer_allocate(net, lpid, initiator);
        if (new_peer == NULL) {
                kptllnd_tx_decref(hello_tx);
                return NULL;
        }

        rc = kptllnd_peer_reserve_buffers();
        if (rc != 0) {
                kptllnd_peer_decref(new_peer);
                kptllnd_tx_decref(hello_tx);

                CERROR("Failed to reserve buffers for %s\n",
                       libcfs_id2str(lpid));
                return NULL;
        }

	write_lock_irqsave(g_lock, flags);

 again:
        if (net->net_shutdown) {
		write_unlock_irqrestore(g_lock, flags);

                CERROR ("Shutdown started, refusing connection from %s\n",
                        libcfs_id2str(lpid));
                kptllnd_peer_unreserve_buffers();
                kptllnd_peer_decref(new_peer);
                kptllnd_tx_decref(hello_tx);
                return NULL;
        }

        peer = kptllnd_id2peer_locked(lpid);
        if (peer != NULL) {
                if (peer->peer_state == PEER_STATE_WAITING_HELLO) {
                        /* An outgoing message instantiated 'peer' for me */
                        LASSERT(peer->peer_incarnation == 0);

                        peer->peer_state = PEER_STATE_ACTIVE;
                        peer->peer_incarnation = msg->ptlm_srcstamp;
                        peer->peer_next_matchbits = safe_matchbits;
                        peer->peer_max_msg_size =
                                msg->ptlm_u.hello.kptlhm_max_msg_size;

			write_unlock_irqrestore(g_lock, flags);

                        CWARN("Outgoing instantiated peer %s\n",
                              libcfs_id2str(lpid));
		} else {
			LASSERT (peer->peer_state == PEER_STATE_ACTIVE);

			write_unlock_irqrestore(g_lock, flags);

			/* WOW!  Somehow this peer completed the HELLO
			 * handshake while I slept.  I guess I could have slept
			 * while it rebooted and sent a new HELLO, so I'll fail
			 * this one... */
                        CWARN("Wow! peer %s\n", libcfs_id2str(lpid));
			kptllnd_peer_decref(peer);
			peer = NULL;
		}

                kptllnd_peer_unreserve_buffers();
                kptllnd_peer_decref(new_peer);
                kptllnd_tx_decref(hello_tx);
                return peer;
        }

        if (kptllnd_data.kptl_n_active_peers ==
            kptllnd_data.kptl_expected_peers) {
                /* peer table full */
		write_unlock_irqrestore(g_lock, flags);

                kptllnd_peertable_overflow_msg("Connection from ", lpid);

                rc = kptllnd_reserve_buffers(1); /* HELLO headroom */
                if (rc != 0) {
                        CERROR("Refusing connection from %s\n",
                               libcfs_id2str(lpid));
                        kptllnd_peer_unreserve_buffers();
                        kptllnd_peer_decref(new_peer);
                        kptllnd_tx_decref(hello_tx);
                        return NULL;
                }
                
		write_lock_irqsave(g_lock, flags);
                kptllnd_data.kptl_expected_peers++;
                goto again;
        }

        last_matchbits_seen = kptllnd_get_last_seen_matchbits_locked(lpid);

        hello_tx->tx_msg->ptlm_u.hello.kptlhm_matchbits = last_matchbits_seen;
        hello_tx->tx_msg->ptlm_u.hello.kptlhm_max_msg_size =
                *kptllnd_tunables.kptl_max_msg_size;

        new_peer->peer_state = PEER_STATE_ACTIVE;
        new_peer->peer_incarnation = msg->ptlm_srcstamp;
        new_peer->peer_next_matchbits = safe_matchbits;
        new_peer->peer_last_matchbits_seen = last_matchbits_seen;
        new_peer->peer_max_msg_size = msg->ptlm_u.hello.kptlhm_max_msg_size;

        LASSERT (!net->net_shutdown);
        kptllnd_peer_add_peertable_locked(new_peer);

	write_unlock_irqrestore(g_lock, flags);

	/* NB someone else could get in now and post a message before I post
	 * the HELLO, but post_tx/check_sends take care of that! */

        CDEBUG(D_NETTRACE, "%s: post response hello %p\n",
               libcfs_id2str(new_peer->peer_id), hello_tx);

        kptllnd_post_tx(new_peer, hello_tx, 0);
        kptllnd_peer_check_sends(new_peer);

        return new_peer;
}

void
kptllnd_tx_launch(kptl_peer_t *peer, kptl_tx_t *tx, int nfrag)
{
        kptllnd_post_tx(peer, tx, nfrag);
        kptllnd_peer_check_sends(peer);
}

int
kptllnd_find_target(kptl_net_t *net, lnet_process_id_t target,
                    kptl_peer_t **peerp)
{
	rwlock_t     *g_lock = &kptllnd_data.kptl_peer_rw_lock;
        ptl_process_id_t  ptl_id;
        kptl_peer_t      *new_peer;
        kptl_tx_t        *hello_tx;
        unsigned long     flags;
        int               rc;
        __u64             last_matchbits_seen;

        /* I expect to find the peer, so I only take a read lock... */
	read_lock_irqsave(g_lock, flags);
        *peerp = kptllnd_id2peer_locked(target);
	read_unlock_irqrestore(g_lock, flags);

        if (*peerp != NULL)
                return 0;

        if ((target.pid & LNET_PID_USERFLAG) != 0) {
                CWARN("Refusing to create a new connection to %s "
                      "(non-kernel peer)\n", libcfs_id2str(target));
                return -EHOSTUNREACH;
        }

        /* The new peer is a kernel ptllnd, and kernel ptllnds all have the
         * same portals PID, which has nothing to do with LUSTRE_SRV_LNET_PID */
        ptl_id.nid = kptllnd_lnet2ptlnid(target.nid);
        ptl_id.pid = kptllnd_data.kptl_portals_id.pid;

        hello_tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
        if (hello_tx == NULL) {
                CERROR("Unable to allocate connect message for %s\n",
                       libcfs_id2str(target));
                return -ENOMEM;
        }

        hello_tx->tx_acked = 1;
        kptllnd_init_msg(hello_tx->tx_msg, PTLLND_MSG_TYPE_HELLO,
                         target, sizeof(kptl_hello_msg_t));

        new_peer = kptllnd_peer_allocate(net, target, ptl_id);
        if (new_peer == NULL) {
                rc = -ENOMEM;
                goto unwind_0;
        }

        rc = kptllnd_peer_reserve_buffers();
        if (rc != 0)
                goto unwind_1;

	write_lock_irqsave(g_lock, flags);
 again:
        /* Called only in lnd_send which can't happen after lnd_shutdown */
        LASSERT (!net->net_shutdown);

        *peerp = kptllnd_id2peer_locked(target);
        if (*peerp != NULL) {
		write_unlock_irqrestore(g_lock, flags);
                goto unwind_2;
        }

        kptllnd_cull_peertable_locked(target);

        if (kptllnd_data.kptl_n_active_peers ==
            kptllnd_data.kptl_expected_peers) {
                /* peer table full */
		write_unlock_irqrestore(g_lock, flags);

                kptllnd_peertable_overflow_msg("Connection to ", target);

                rc = kptllnd_reserve_buffers(1); /* HELLO headroom */
                if (rc != 0) {
                        CERROR("Can't create connection to %s\n",
                               libcfs_id2str(target));
                        rc = -ENOMEM;
                        goto unwind_2;
                }
		write_lock_irqsave(g_lock, flags);
                kptllnd_data.kptl_expected_peers++;
                goto again;
        }

        last_matchbits_seen = kptllnd_get_last_seen_matchbits_locked(target);

        hello_tx->tx_msg->ptlm_u.hello.kptlhm_matchbits = last_matchbits_seen;
        hello_tx->tx_msg->ptlm_u.hello.kptlhm_max_msg_size =
                *kptllnd_tunables.kptl_max_msg_size;

        new_peer->peer_state = PEER_STATE_WAITING_HELLO;
        new_peer->peer_last_matchbits_seen = last_matchbits_seen;

        kptllnd_peer_add_peertable_locked(new_peer);

	write_unlock_irqrestore(g_lock, flags);

        /* NB someone else could get in now and post a message before I post
         * the HELLO, but post_tx/check_sends take care of that! */

        CDEBUG(D_NETTRACE, "%s: post initial hello %p\n",
               libcfs_id2str(new_peer->peer_id), hello_tx);

        kptllnd_post_tx(new_peer, hello_tx, 0);
        kptllnd_peer_check_sends(new_peer);

        *peerp = new_peer;
        return 0;

 unwind_2:
        kptllnd_peer_unreserve_buffers();
 unwind_1:
        kptllnd_peer_decref(new_peer);
 unwind_0:
        kptllnd_tx_decref(hello_tx);

        return rc;
}
