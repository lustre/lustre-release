/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *           E Barton <eeb@bartonsoftware.com>
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
#include <libcfs/list.h>

static int
kptllnd_count_queue(struct list_head *q)
{
        struct list_head *e;
        int               n = 0;
        
        list_for_each(e, q) {
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
        rwlock_t         *g_lock = &kptllnd_data.kptl_peer_rw_lock;
        unsigned long     flags;
        struct list_head *ptmp;
        kptl_peer_t      *peer;
        int               i;
        int               rc = -ENOENT;

        read_lock_irqsave(g_lock, flags);

        for (i = 0; i < kptllnd_data.kptl_peer_hash_size; i++) {
                
                list_for_each (ptmp, &kptllnd_data.kptl_peers[i]) {
                        peer = list_entry(ptmp, kptl_peer_t, peer_list);

                        if (index-- > 0)
                                continue;
                        
                        *id          = peer->peer_id;
                        *state       = peer->peer_state;
                        *sent_hello  = peer->peer_sent_hello;
                        *refcount    = atomic_read(&peer->peer_refcount);
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
        atomic_inc(&peer->peer_refcount);       /* +1 ref for the list */

        /* NB add to HEAD of peer list for MRU order!
         * (see kptllnd_cull_peertable) */
        list_add(&peer->peer_list, kptllnd_nid2peerlist(peer->peer_id.nid));
}

void
kptllnd_cull_peertable_locked (lnet_process_id_t pid)
{
        /* I'm about to add a new peer with this portals ID to the peer table,
         * so (a) this peer should not exist already and (b) I want to leave at
         * most (max_procs_per_nid - 1) peers with this NID in the table. */
        struct list_head  *peers = kptllnd_nid2peerlist(pid.nid);
        int                cull_count = *kptllnd_tunables.kptl_max_procs_per_node;
        int                count;
        struct list_head  *tmp;
        struct list_head  *nxt;
        kptl_peer_t       *peer;
        
        count = 0;
        list_for_each_safe (tmp, nxt, peers) {
                /* NB I rely on kptllnd_peer_add_peertable_locked to add peers
                 * in MRU order */
                peer = list_entry(tmp, kptl_peer_t, peer_list);
                        
                if (peer->peer_id.nid != pid.nid)
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
kptllnd_peer_allocate (lnet_process_id_t lpid, ptl_process_id_t ppid)
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

        INIT_LIST_HEAD (&peer->peer_sendq);
        INIT_LIST_HEAD (&peer->peer_activeq);
        spin_lock_init (&peer->peer_lock);

        peer->peer_state = PEER_STATE_ALLOCATED;
        peer->peer_error = 0;
        peer->peer_last_alive = cfs_time_current();
        peer->peer_id = lpid;
        peer->peer_ptlid = ppid;
        peer->peer_credits = 1;                 /* enough for HELLO */
        peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;
        peer->peer_outstanding_credits = *kptllnd_tunables.kptl_peercredits - 1;

        atomic_set(&peer->peer_refcount, 1);    /* 1 ref for caller */

        write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        /* Only increase # peers under lock, to guarantee we dont grow it
         * during shutdown */
        if (kptllnd_data.kptl_shutdown) {
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

        LASSERT (!in_interrupt());
        LASSERT (atomic_read(&peer->peer_refcount) == 0);
        LASSERT (peer->peer_state == PEER_STATE_ALLOCATED ||
                 peer->peer_state == PEER_STATE_ZOMBIE);
        LASSERT (list_empty(&peer->peer_sendq));
        LASSERT (list_empty(&peer->peer_activeq));

        write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        if (peer->peer_state == PEER_STATE_ZOMBIE)
                list_del(&peer->peer_list);

        kptllnd_data.kptl_npeers--;

        write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        LIBCFS_FREE (peer, sizeof (*peer));
}

void
kptllnd_peer_cancel_txs(kptl_peer_t *peer)
{
        struct list_head   sendq;
        struct list_head   activeq;
        struct list_head  *tmp;
        struct list_head  *nxt;
        kptl_tx_t         *tx;
        unsigned long      flags;

        /* atomically grab all the peer's tx-es... */

        spin_lock_irqsave(&peer->peer_lock, flags);

        list_add(&sendq, &peer->peer_sendq);
        list_del_init(&peer->peer_sendq);
        list_for_each (tmp, &sendq) {
                tx = list_entry(tmp, kptl_tx_t, tx_list);
                tx->tx_active = 0;
        }

        list_add(&activeq, &peer->peer_activeq);
        list_del_init(&peer->peer_activeq);
        list_for_each (tmp, &activeq) {
                tx = list_entry(tmp, kptl_tx_t, tx_list);
                tx->tx_active = 0;
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);

        /* ...then drop the peer's ref on them at leasure.  This will get
         * kptllnd_tx_fini() to abort outstanding comms if necessary. */

        list_for_each_safe (tmp, nxt, &sendq) {
                tx = list_entry(tmp, kptl_tx_t, tx_list);
                list_del(&tx->tx_list);
                tx->tx_status = -EIO;
                kptllnd_tx_decref(tx);
        }

        list_for_each_safe (tmp, nxt, &activeq) {
                tx = list_entry(tmp, kptl_tx_t, tx_list);
                list_del(&tx->tx_list);
                tx->tx_status = -EIO;
                kptllnd_tx_decref(tx);
        }
}

void
kptllnd_peer_alive (kptl_peer_t *peer)
{
        /* This is racy, but everyone's only writing cfs_time_current() */
        peer->peer_last_alive = cfs_time_current();
        mb();
}

void
kptllnd_peer_notify (kptl_peer_t *peer)
{
        unsigned long flags;
        time_t        last_alive = 0;
        int           error = 0;
        
        spin_lock_irqsave(&peer->peer_lock, flags);

        if (peer->peer_error != 0) {
                error = peer->peer_error;
                peer->peer_error = 0;
                
                last_alive = cfs_time_current_sec() - 
                             cfs_duration_sec(cfs_time_current() - 
                                              peer->peer_last_alive);
        }
        
        spin_unlock_irqrestore(&peer->peer_lock, flags);

        if (error != 0)
                lnet_notify (kptllnd_data.kptl_ni, peer->peer_id.nid, 0,
                             last_alive);
}

void
kptllnd_handle_closing_peers ()
{
        unsigned long           flags;
        kptl_peer_t            *peer;
        struct list_head       *tmp;
        struct list_head       *nxt;
        int                     idle;

        /* Check with a read lock first to avoid blocking anyone */

        read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        idle = list_empty(&kptllnd_data.kptl_closing_peers);
        read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        if (idle)
                return;

        /* Scan the closing peers and cancel their txs.
         * NB only safe while there is only a single watchdog */

        write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        list_for_each_safe (tmp, nxt, &kptllnd_data.kptl_closing_peers) {
                peer = list_entry (tmp, kptl_peer_t, peer_list);

                LASSERT (peer->peer_state == PEER_STATE_CLOSING);

                list_del(&peer->peer_list);
                list_add_tail(&peer->peer_list,
                              &kptllnd_data.kptl_zombie_peers);
                peer->peer_state = PEER_STATE_ZOMBIE;

                write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

                kptllnd_peer_notify(peer);
                kptllnd_peer_cancel_txs(peer);
                kptllnd_peer_decref(peer);

                write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        }

        write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);
}

void
kptllnd_peer_close_locked(kptl_peer_t *peer, int why)
{
        switch (peer->peer_state) {
        default:
                LBUG();

        case PEER_STATE_WAITING_HELLO:
        case PEER_STATE_ACTIVE:
                /* Removing from peer table */
                kptllnd_data.kptl_n_active_peers--;
                LASSERT (kptllnd_data.kptl_n_active_peers >= 0);

                list_del(&peer->peer_list);
                kptllnd_peer_unreserve_buffers();

                peer->peer_error = why; /* stash 'why' only on first close */

                /* Schedule for immediate attention, taking peer table's ref */
                list_add_tail(&peer->peer_list, 
                              &kptllnd_data.kptl_closing_peers);
                wake_up(&kptllnd_data.kptl_watchdog_waitq);
                break;

        case PEER_STATE_ZOMBIE:
                /* Schedule for attention at next timeout */
                kptllnd_peer_addref(peer);
                list_del(&peer->peer_list);
                list_add_tail(&peer->peer_list, 
                              &kptllnd_data.kptl_closing_peers);
                break;
                
        case PEER_STATE_CLOSING:
                break;
        }

        peer->peer_state = PEER_STATE_CLOSING;
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
        struct list_head  *ptmp;
        struct list_head  *pnxt;
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
                struct list_head *l = kptllnd_nid2peerlist(id.nid);
                
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
                list_for_each_safe (ptmp, pnxt, &kptllnd_data.kptl_peers[i]) {
                        peer = list_entry (ptmp, kptl_peer_t, peer_list);

                        if (!(id.nid == LNET_NID_ANY || 
                              (peer->peer_id.nid == id.nid &&
                               (id.pid == LNET_PID_ANY || 
                                peer->peer_id.pid == id.pid))))
                                continue;

                        kptllnd_peer_addref(peer); /* 1 ref for me... */

                        read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock,
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
kptllnd_post_tx(kptl_peer_t *peer, kptl_tx_t *tx)
{
        /* CAVEAT EMPTOR: I take over caller's ref on 'tx' */
        ptl_handle_md_t  rdma_mdh = PTL_INVALID_HANDLE;
        ptl_handle_md_t  msg_mdh = PTL_INVALID_HANDLE;
        ptl_handle_me_t  meh;
        ptl_md_t         md;
        ptl_err_t        prc;
        unsigned long    flags;

        LASSERT (!tx->tx_idle);
        LASSERT (!tx->tx_active);
        LASSERT (PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));
        LASSERT (PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));
        LASSERT (tx->tx_type == TX_TYPE_SMALL_MESSAGE ||
                 tx->tx_type == TX_TYPE_PUT_REQUEST ||
                 tx->tx_type == TX_TYPE_GET_REQUEST);

        kptllnd_set_tx_peer(tx, peer);

        if (tx->tx_type == TX_TYPE_PUT_REQUEST ||
            tx->tx_type == TX_TYPE_GET_REQUEST) {

                spin_lock_irqsave(&peer->peer_lock, flags);

                /* Assume 64-bit matchbits can't wrap */
                LASSERT (peer->peer_next_matchbits >= PTL_RESERVED_MATCHBITS);
                tx->tx_msg->ptlm_u.rdma.kptlrm_matchbits =
                        peer->peer_next_matchbits++;
                        
                spin_unlock_irqrestore(&peer->peer_lock, flags);

                prc = PtlMEAttach(kptllnd_data.kptl_nih,
                                  *kptllnd_tunables.kptl_portal,
                                  peer->peer_ptlid,
                                  tx->tx_msg->ptlm_u.rdma.kptlrm_matchbits,
                                  0,             /* ignore bits */
                                  PTL_UNLINK,
                                  PTL_INS_BEFORE,
                                  &meh);
                if (prc != PTL_OK) {
                        CERROR("PtlMEAttach(%s) failed: %d\n",
                               libcfs_id2str(peer->peer_id), prc);
                        goto failed;
                }

                prc = PtlMDAttach(meh, tx->tx_rdma_md, PTL_UNLINK, &rdma_mdh);
                if (prc != PTL_OK) {
                        CERROR("PtlMDAttach(%s) failed: %d\n",
                               libcfs_id2str(tx->tx_peer->peer_id), prc);
                        prc = PtlMEUnlink(meh);
                        LASSERT(prc == PTL_OK);
                        rdma_mdh = PTL_INVALID_HANDLE;
                        goto failed;
                }

                /* I'm not racing with the event callback here.  It's a bug if
                 * there's an event on the MD I just attached before I actually
                 * send the RDMA request message which the event callback
                 * catches by asserting 'rdma_mdh' is valid. */
        }

        memset(&md, 0, sizeof(md));
        
        md.start = tx->tx_msg;
        md.length = tx->tx_msg->ptlm_nob;
        md.threshold = 1;
        md.options = PTL_MD_OP_PUT |
                     PTL_MD_LUSTRE_COMPLETION_SEMANTICS |
                     PTL_MD_EVENT_START_DISABLE;
        md.user_ptr = &tx->tx_msg_eventarg;
        md.eq_handle = kptllnd_data.kptl_eqh;

        prc = PtlMDBind(kptllnd_data.kptl_nih, md, PTL_UNLINK, &msg_mdh);
        if (prc != PTL_OK) {
                msg_mdh = PTL_INVALID_HANDLE;
                goto failed;
        }
        
        spin_lock_irqsave(&peer->peer_lock, flags);

        tx->tx_deadline = jiffies + (*kptllnd_tunables.kptl_timeout * HZ);
        tx->tx_active = 1;
        tx->tx_rdma_mdh = rdma_mdh;
        tx->tx_msg_mdh = msg_mdh;

	/* Ensure HELLO is sent first */
	if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_HELLO)
		list_add(&tx->tx_list, &peer->peer_sendq);
	else
		list_add_tail(&tx->tx_list, &peer->peer_sendq);

        spin_unlock_irqrestore(&peer->peer_lock, flags);
        return;
        
 failed:
        spin_lock_irqsave(&peer->peer_lock, flags);

        tx->tx_status = -EIO;
        tx->tx_rdma_mdh = rdma_mdh;
        tx->tx_msg_mdh = msg_mdh;

        spin_unlock_irqrestore(&peer->peer_lock, flags);

        kptllnd_tx_decref(tx);
}

void
kptllnd_peer_check_sends (kptl_peer_t *peer)
{

        kptl_tx_t       *tx;
        int              rc;
        unsigned long    flags;

        LASSERT(!in_interrupt());

        spin_lock_irqsave(&peer->peer_lock, flags);

        if (list_empty(&peer->peer_sendq) &&
            peer->peer_outstanding_credits >= PTLLND_CREDIT_HIGHWATER &&
            peer->peer_credits != 0) {

                /* post a NOOP to return credits */
                spin_unlock_irqrestore(&peer->peer_lock, flags);

                tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
                if (tx == NULL) {
                        CERROR("Can't return credits to %s: can't allocate descriptor\n",
                               libcfs_id2str(peer->peer_id));
                } else {
                        kptllnd_init_msg(tx->tx_msg, PTLLND_MSG_TYPE_NOOP, 0);
                        kptllnd_post_tx(peer, tx);
                }

                spin_lock_irqsave(&peer->peer_lock, flags);
        }

        while (!list_empty(&peer->peer_sendq)) {
                tx = list_entry (peer->peer_sendq.next, kptl_tx_t, tx_list);

                LASSERT (tx->tx_active);
                LASSERT (!PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));
                LASSERT (tx->tx_type == TX_TYPE_SMALL_MESSAGE ||
                         !PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));

                LASSERT (peer->peer_outstanding_credits >= 0);
                LASSERT (peer->peer_outstanding_credits <= 
                         *kptllnd_tunables.kptl_peercredits);
                LASSERT (peer->peer_credits >= 0);
                LASSERT (peer->peer_credits <= 
                         *kptllnd_tunables.kptl_peercredits);

		/* Ensure HELLO is sent first */
		if (!peer->peer_sent_hello) {
			if (tx->tx_msg->ptlm_type != PTLLND_MSG_TYPE_HELLO)
				break;
			peer->peer_sent_hello = 1;
		}

                if (peer->peer_credits == 0) {
                        CDEBUG(D_NETTRACE, "%s[%d/%d]: no credits for %p\n",
                               libcfs_id2str(peer->peer_id),
                               peer->peer_credits, peer->peer_outstanding_credits, tx);
                        break;
                }

                /* Don't use the last credit unless I've got credits to
                 * return */
                if (peer->peer_credits == 1 &&
                    peer->peer_outstanding_credits == 0) {
                        CDEBUG(D_NETTRACE, "%s[%d/%d]: not using last credit for %p\n",
                               libcfs_id2str(peer->peer_id),
                               peer->peer_credits, peer->peer_outstanding_credits, tx);
                        break;
                }

                list_del(&tx->tx_list);

                /* Discard any NOOP I queued if I'm not at the high-water mark
                 * any more or more messages have been queued */
                if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_NOOP &&
                    (!list_empty(&peer->peer_sendq) ||
                     peer->peer_outstanding_credits < PTLLND_CREDIT_HIGHWATER)) {

                        tx->tx_active = 0;

                        spin_unlock_irqrestore(&peer->peer_lock, flags);

                        CDEBUG(D_NET, "%s: redundant noop\n", 
                               libcfs_id2str(peer->peer_id));
                        kptllnd_tx_decref(tx);

                        spin_lock_irqsave(&peer->peer_lock, flags);
                        continue;
                }

                /* fill last-minute msg header fields */
                kptllnd_msg_pack(tx->tx_msg, peer);

                peer->peer_outstanding_credits = 0;
                peer->peer_credits--;

                CDEBUG(D_NETTRACE, "%s[%d/%d]: %s tx=%p nob=%d cred=%d\n",
                       libcfs_id2str(peer->peer_id),
                       peer->peer_credits, peer->peer_outstanding_credits,
                       kptllnd_msgtype2str(tx->tx_msg->ptlm_type),
                       tx, tx->tx_msg->ptlm_nob,
                       tx->tx_msg->ptlm_credits);

                list_add_tail(&tx->tx_list, &peer->peer_activeq);

                kptllnd_tx_addref(tx);          /* 1 ref for me... */

                spin_unlock_irqrestore(&peer->peer_lock, flags);

                rc = PtlPut (tx->tx_msg_mdh,
                             PTL_NOACK_REQ,
                             peer->peer_ptlid,
                             *kptllnd_tunables.kptl_portal,
                             0,                 /* acl cookie */
                             LNET_MSG_MATCHBITS,
                             0,                 /* offset */
                             0);                /* header data */
                if (rc != PTL_OK) {
                        CERROR("PtlPut %s error %d\n",
                               libcfs_id2str(peer->peer_id), rc);

                        /* Nuke everything (including this tx) */
                        kptllnd_peer_close(peer, -EIO);
                        return;
                }

                kptllnd_tx_decref(tx);          /* drop my ref */

                spin_lock_irqsave(&peer->peer_lock, flags);
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);
}

kptl_tx_t *
kptllnd_find_timed_out_tx(kptl_peer_t *peer)
{
        kptl_tx_t         *tx;
        struct list_head  *tmp;
        unsigned long      flags;

        spin_lock_irqsave(&peer->peer_lock, flags);

        list_for_each(tmp, &peer->peer_sendq) {
                tx = list_entry(peer->peer_sendq.next, kptl_tx_t, tx_list);

                if (time_after_eq(jiffies, tx->tx_deadline)) {
                        kptllnd_tx_addref(tx);
                        spin_unlock_irqrestore(&peer->peer_lock, flags);
                        return tx;
                }
        }

        list_for_each(tmp, &peer->peer_activeq) {
                tx = list_entry(peer->peer_activeq.next, kptl_tx_t, tx_list);

                if (time_after_eq(jiffies, tx->tx_deadline)) {
                        kptllnd_tx_addref(tx);
                        spin_unlock_irqrestore(&peer->peer_lock, flags);
                        return tx;
                }
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);
        return NULL;
}


void
kptllnd_peer_check_bucket (int idx)
{
        struct list_head  *peers = &kptllnd_data.kptl_peers[idx];
        struct list_head  *ptmp;
        kptl_peer_t       *peer;
        kptl_tx_t         *tx;
        unsigned long      flags;
        int                nsend;
        int                nactive;

        CDEBUG(D_NET, "Bucket=%d\n", idx);

 again:
        /* NB. Shared lock while I just look */
        read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        list_for_each (ptmp, peers) {
                peer = list_entry (ptmp, kptl_peer_t, peer_list);

                CDEBUG(D_NET, "Peer=%s Credits=%d Outstanding=%d\n",
                       libcfs_id2str(peer->peer_id),
                       peer->peer_credits, peer->peer_outstanding_credits);

                /* In case we have enough credits to return via a
                 * NOOP, but there were no non-blocking tx descs
                 * free to do it last time... */
                kptllnd_peer_check_sends(peer);

                tx = kptllnd_find_timed_out_tx(peer);
                if (tx == NULL)
                        continue;

                kptllnd_peer_addref(peer); /* 1 ref for me... */

                read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock,
                                       flags);

                spin_lock_irqsave(&peer->peer_lock, flags);
                nsend = kptllnd_count_queue(&peer->peer_sendq);
                nactive = kptllnd_count_queue(&peer->peer_activeq);
                spin_unlock_irqrestore(&peer->peer_lock, flags);

                LCONSOLE_ERROR("Timing out %s: please check Portals\n",
                               libcfs_id2str(peer->peer_id));

                CERROR("%s timed out: cred %d outstanding %d sendq %d "
                       "activeq %d Tx %s (%s%s%s) status %d T/O %ds\n",
                       libcfs_id2str(peer->peer_id),
                       peer->peer_credits, peer->peer_outstanding_credits,
                       nsend, nactive, kptllnd_tx_typestr(tx->tx_type),
                       tx->tx_active ? "A" : "",
                       PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE) ?
                       "" : "M",
                       PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE) ?
                       "" : "D",
                       tx->tx_status, *kptllnd_tunables.kptl_timeout);

                kptllnd_dump_ptltrace();

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
        struct list_head *peers = kptllnd_nid2peerlist(id.nid);
        struct list_head *tmp;
        kptl_peer_t      *peer;

        list_for_each (tmp, peers) {

                peer = list_entry (tmp, kptl_peer_t, peer_list);

                LASSERT(peer->peer_state == PEER_STATE_WAITING_HELLO ||
                        peer->peer_state == PEER_STATE_ACTIVE);
                
                if (peer->peer_id.nid != id.nid ||
                    peer->peer_id.pid != id.pid)
                        continue;

                kptllnd_peer_addref(peer);

                CDEBUG(D_NET, "%s -> %s (%d)\n",
                       libcfs_id2str(id), 
                       kptllnd_ptlid2str(peer->peer_ptlid),
                       atomic_read (&peer->peer_refcount));
                return peer;
        }

        return NULL;
}

void
kptllnd_peertable_overflow_msg(char *str, lnet_process_id_t id)
{
        LCONSOLE_ERROR("%s %s overflows the peer table[%d]: "
                       "messages may be dropped\n",
                       str, libcfs_id2str(id),
                       kptllnd_data.kptl_n_active_peers);
        LCONSOLE_ERROR("Please correct by increasing "
                       "'max_nodes' or 'max_procs_per_node'\n");
}

__u64
kptllnd_get_last_seen_matchbits_locked(lnet_process_id_t lpid)
{
        kptl_peer_t            *peer;
        struct list_head       *tmp;

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

        list_for_each (tmp, &kptllnd_data.kptl_closing_peers) {
                peer = list_entry (tmp, kptl_peer_t, peer_list);

                if (peer->peer_id.nid == lpid.nid &&
                    peer->peer_id.pid == lpid.pid)
                        return peer->peer_last_matchbits_seen;
        }
        
        list_for_each (tmp, &kptllnd_data.kptl_zombie_peers) {
                peer = list_entry (tmp, kptl_peer_t, peer_list);

                if (peer->peer_id.nid == lpid.nid &&
                    peer->peer_id.pid == lpid.pid)
                        return peer->peer_last_matchbits_seen;
        }
        
        return PTL_RESERVED_MATCHBITS;
}

kptl_peer_t *
kptllnd_peer_handle_hello (ptl_process_id_t  initiator,
                           kptl_msg_t       *msg)
{
        rwlock_t           *g_lock = &kptllnd_data.kptl_peer_rw_lock;
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
	
        if (msg->ptlm_u.hello.kptlhm_max_msg_size !=
            *kptllnd_tunables.kptl_max_msg_size) {
                CERROR("max message size MUST be equal for all peers: "
                       "got %d expected %d from %s\n",
                       msg->ptlm_u.hello.kptlhm_max_msg_size,
                       *kptllnd_tunables.kptl_max_msg_size,
                       libcfs_id2str(lpid));
                return NULL;
        }

        if (msg->ptlm_credits + 1 != *kptllnd_tunables.kptl_peercredits) {
                CERROR("peercredits MUST be equal on all peers: "
                       "got %d expected %d from %s\n",
                       msg->ptlm_credits + 1,
                       *kptllnd_tunables.kptl_peercredits,
                       libcfs_id2str(lpid));
                return NULL;
        }
        
        write_lock_irqsave(g_lock, flags);

        peer = kptllnd_id2peer_locked(lpid);
        if (peer != NULL) {
                if (peer->peer_state == PEER_STATE_WAITING_HELLO) {
                        /* Completing HELLO handshake */
                        LASSERT(peer->peer_incarnation == 0);

                        peer->peer_state = PEER_STATE_ACTIVE;
                        peer->peer_incarnation = msg->ptlm_srcstamp;
                        peer->peer_next_matchbits = safe_matchbits;

                        write_unlock_irqrestore(g_lock, flags);
                        return peer;
                }

                /* remove old incarnation of this peer */
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
        }

        hello_tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
        if (hello_tx == NULL) {
                CERROR("Unable to allocate HELLO message for %s\n",
                       libcfs_id2str(lpid));
                return NULL;
        }

        kptllnd_init_msg(hello_tx->tx_msg, PTLLND_MSG_TYPE_HELLO,
                         sizeof(kptl_hello_msg_t));

        new_peer = kptllnd_peer_allocate(lpid, initiator);
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

        peer = kptllnd_id2peer_locked(lpid);
        if (peer != NULL) {
                if (peer->peer_state == PEER_STATE_WAITING_HELLO) {
                        /* An outgoing message instantiated 'peer' for me and
			 * presumably provoked this reply */
                        CWARN("Outgoing instantiated peer %s\n", libcfs_id2str(lpid));
                        LASSERT(peer->peer_incarnation == 0);

                        peer->peer_state = PEER_STATE_ACTIVE;
                        peer->peer_incarnation = msg->ptlm_srcstamp;
                        peer->peer_next_matchbits = safe_matchbits;
		} else {
			LASSERT (peer->peer_state == PEER_STATE_ACTIVE);
			/* WOW!  Somehow this peer completed the HELLO
			 * handshake while I slept.  I guess I could have slept
			 * while it rebooted and sent a new HELLO, so I'll fail
			 * this one... */
                        CWARN("Wow! peer %s\n", libcfs_id2str(lpid));
			kptllnd_peer_decref(peer);
			peer = NULL;
		}
		
                write_unlock_irqrestore(g_lock, flags);

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
        }

        last_matchbits_seen = kptllnd_get_last_seen_matchbits_locked(lpid);

        hello_tx->tx_msg->ptlm_u.hello.kptlhm_matchbits = last_matchbits_seen;
        hello_tx->tx_msg->ptlm_u.hello.kptlhm_max_msg_size =
                *kptllnd_tunables.kptl_max_msg_size;

        new_peer->peer_state = PEER_STATE_ACTIVE;
        new_peer->peer_incarnation = msg->ptlm_srcstamp;
        new_peer->peer_next_matchbits = safe_matchbits;
        new_peer->peer_last_matchbits_seen = last_matchbits_seen;

        kptllnd_peer_add_peertable_locked(new_peer);

        write_unlock_irqrestore(g_lock, flags);

	/* NB someone else could get in now and post a message before I post
	 * the HELLO, but post_tx/check_sends take care of that! */

        CDEBUG(D_NETTRACE, "%s: post response hello %p\n",
               libcfs_id2str(new_peer->peer_id), hello_tx);

        kptllnd_post_tx(new_peer, hello_tx);
        kptllnd_peer_check_sends(new_peer);

        return new_peer;
}

void
kptllnd_tx_launch(kptl_tx_t *tx, lnet_process_id_t target)
{
        rwlock_t         *g_lock = &kptllnd_data.kptl_peer_rw_lock;
        ptl_process_id_t  ptl_id;
        kptl_peer_t      *peer;
        kptl_peer_t      *new_peer = NULL;
        kptl_tx_t        *hello_tx = NULL;
        unsigned long     flags;
        int               rc;
        __u64             last_matchbits_seen;

        LASSERT (tx->tx_lnet_msg != NULL);
        LASSERT (tx->tx_peer == NULL);

        /* I expect to find the peer, so I only take a read lock... */
        read_lock_irqsave(g_lock, flags);
        peer = kptllnd_id2peer_locked(target);
        read_unlock_irqrestore(g_lock, flags);

        if (peer != NULL) {
                goto post;
        }
        
        if ((target.pid & LNET_PID_USERFLAG) != 0) {
                CWARN("Refusing to create a new connection to %s "
                      "(non-kernel peer)\n", libcfs_id2str(target));
                tx->tx_status = -EHOSTUNREACH;
                goto failed;
        }

        /* The new peer is a kernel ptllnd, and kernel ptllnds all have
         * the same portals PID */
        ptl_id.nid = kptllnd_lnet2ptlnid(target.nid);
        ptl_id.pid = kptllnd_data.kptl_portals_id.pid;

        write_lock_irqsave(g_lock, flags);

        peer = kptllnd_id2peer_locked(target);
        if (peer != NULL) {
                write_unlock_irqrestore(g_lock, flags);
                goto post;
        }
        
        kptllnd_cull_peertable_locked(target);

        write_unlock_irqrestore(g_lock, flags);
                
        hello_tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
        if (hello_tx == NULL) {
                CERROR("Unable to allocate connect message for %s\n",
                       libcfs_id2str(target));
                tx->tx_status = -ENOMEM;
                goto failed;
        }

        kptllnd_init_msg(hello_tx->tx_msg, PTLLND_MSG_TYPE_HELLO,
                         sizeof(kptl_hello_msg_t));

        new_peer = kptllnd_peer_allocate(target, ptl_id);
        if (new_peer == NULL) {
                tx->tx_status = -ENOMEM;
                goto failed;
        }

        rc = kptllnd_peer_reserve_buffers();
        if (rc != 0) {
                tx->tx_status = rc;
                goto failed;
        }

        write_lock_irqsave(g_lock, flags);

        peer = kptllnd_id2peer_locked(target);
        if (peer != NULL) {                     /* someone else beat me to it */
                write_unlock_irqrestore(g_lock, flags);

                kptllnd_peer_unreserve_buffers();
                kptllnd_peer_decref(new_peer);
                kptllnd_tx_decref(hello_tx);
                goto post;
        }
                
        if (kptllnd_data.kptl_n_active_peers ==
            kptllnd_data.kptl_expected_peers) {
                /* peer table full */
                write_unlock_irqrestore(g_lock, flags);

                kptllnd_peertable_overflow_msg("Connection to ", target);

                rc = kptllnd_reserve_buffers(1); /* HELLO headroom */
                if (rc != 0) {
                        CERROR("Can't create connection to %s\n",
                               libcfs_id2str(target));
                        kptllnd_peer_unreserve_buffers();
                        tx->tx_status = -ENOMEM;
                        goto failed;
                }
                write_lock_irqsave(g_lock, flags);
                kptllnd_data.kptl_expected_peers++;
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

        peer = new_peer;
        kptllnd_post_tx(peer, hello_tx);

 post:
        kptllnd_post_tx(peer, tx);
        kptllnd_peer_check_sends(peer);
        kptllnd_peer_decref(peer);
        return;
        
 failed:
        if (hello_tx != NULL)
                kptllnd_tx_decref(hello_tx);

        if (new_peer != NULL)
                kptllnd_peer_decref(new_peer);

        LASSERT (tx->tx_status != 0);
        kptllnd_tx_decref(tx);
        
}
