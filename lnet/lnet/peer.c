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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/lnet/peer.c
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/sched.h>
#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/signal.h>
#endif
#include <linux/uaccess.h>

#include <lnet/udsp.h>
#include <lnet/lib-lnet.h>
#include <uapi/linux/lnet/lnet-dlc.h>

/* Value indicating that recovery needs to re-check a peer immediately. */
#define LNET_REDISCOVER_PEER	(1)

static int lnet_peer_queue_for_discovery(struct lnet_peer *lp);

static void
lnet_peer_remove_from_remote_list(struct lnet_peer_ni *lpni)
{
	if (!list_empty(&lpni->lpni_on_remote_peer_ni_list)) {
		list_del_init(&lpni->lpni_on_remote_peer_ni_list);
		lnet_peer_ni_decref_locked(lpni);
	}
}

void
lnet_peer_net_added(struct lnet_net *net)
{
	struct lnet_peer_ni *lpni, *tmp;

	list_for_each_entry_safe(lpni, tmp, &the_lnet.ln_remote_peer_ni_list,
				 lpni_on_remote_peer_ni_list) {

		if (LNET_NIDNET(lpni->lpni_nid) == net->net_id) {
			lpni->lpni_net = net;

			spin_lock(&lpni->lpni_lock);
			lpni->lpni_txcredits =
				lpni->lpni_net->net_tunables.lct_peer_tx_credits;
			lpni->lpni_mintxcredits = lpni->lpni_txcredits;
			lpni->lpni_rtrcredits =
				lnet_peer_buffer_credits(lpni->lpni_net);
			lpni->lpni_minrtrcredits = lpni->lpni_rtrcredits;
			spin_unlock(&lpni->lpni_lock);

			lnet_peer_remove_from_remote_list(lpni);
		}
	}
}

static void
lnet_peer_tables_destroy(void)
{
	struct lnet_peer_table	*ptable;
	struct list_head	*hash;
	int			i;
	int			j;

	if (!the_lnet.ln_peer_tables)
		return;

	cfs_percpt_for_each(ptable, i, the_lnet.ln_peer_tables) {
		hash = ptable->pt_hash;
		if (!hash) /* not intialized */
			break;

		LASSERT(list_empty(&ptable->pt_zombie_list));

		ptable->pt_hash = NULL;
		for (j = 0; j < LNET_PEER_HASH_SIZE; j++)
			LASSERT(list_empty(&hash[j]));

		CFS_FREE_PTR_ARRAY(hash, LNET_PEER_HASH_SIZE);
	}

	cfs_percpt_free(the_lnet.ln_peer_tables);
	the_lnet.ln_peer_tables = NULL;
}

int
lnet_peer_tables_create(void)
{
	struct lnet_peer_table	*ptable;
	struct list_head	*hash;
	int			i;
	int			j;

	the_lnet.ln_peer_tables = cfs_percpt_alloc(lnet_cpt_table(),
						   sizeof(*ptable));
	if (the_lnet.ln_peer_tables == NULL) {
		CERROR("Failed to allocate cpu-partition peer tables\n");
		return -ENOMEM;
	}

	cfs_percpt_for_each(ptable, i, the_lnet.ln_peer_tables) {
		LIBCFS_CPT_ALLOC(hash, lnet_cpt_table(), i,
				 LNET_PEER_HASH_SIZE * sizeof(*hash));
		if (hash == NULL) {
			CERROR("Failed to create peer hash table\n");
			lnet_peer_tables_destroy();
			return -ENOMEM;
		}

		spin_lock_init(&ptable->pt_zombie_lock);
		INIT_LIST_HEAD(&ptable->pt_zombie_list);

		INIT_LIST_HEAD(&ptable->pt_peer_list);

		for (j = 0; j < LNET_PEER_HASH_SIZE; j++)
			INIT_LIST_HEAD(&hash[j]);
		ptable->pt_hash = hash; /* sign of initialization */
	}

	return 0;
}

static struct lnet_peer_ni *
lnet_peer_ni_alloc(lnet_nid_t nid)
{
	struct lnet_peer_ni *lpni;
	struct lnet_net *net;
	int cpt;

	cpt = lnet_nid_cpt_hash(nid, LNET_CPT_NUMBER);

	LIBCFS_CPT_ALLOC(lpni, lnet_cpt_table(), cpt, sizeof(*lpni));
	if (!lpni)
		return NULL;

	INIT_LIST_HEAD(&lpni->lpni_txq);
	INIT_LIST_HEAD(&lpni->lpni_hashlist);
	INIT_LIST_HEAD(&lpni->lpni_peer_nis);
	INIT_LIST_HEAD(&lpni->lpni_recovery);
	INIT_LIST_HEAD(&lpni->lpni_on_remote_peer_ni_list);
	INIT_LIST_HEAD(&lpni->lpni_rtr_pref_nids);
	LNetInvalidateMDHandle(&lpni->lpni_recovery_ping_mdh);
	kref_init(&lpni->lpni_kref);
	lpni->lpni_sel_priority = LNET_MAX_SELECTION_PRIORITY;

	spin_lock_init(&lpni->lpni_lock);

	if (lnet_peers_start_down())
		lpni->lpni_ns_status = LNET_NI_STATUS_DOWN;
	else
		lpni->lpni_ns_status = LNET_NI_STATUS_UP;
	lpni->lpni_ping_feats = LNET_PING_FEAT_INVAL;
	lpni->lpni_nid = nid;
	lpni->lpni_cpt = cpt;
	atomic_set(&lpni->lpni_healthv, LNET_MAX_HEALTH_VALUE);

	net = lnet_get_net_locked(LNET_NIDNET(nid));
	lpni->lpni_net = net;
	if (net) {
		lpni->lpni_txcredits = net->net_tunables.lct_peer_tx_credits;
		lpni->lpni_mintxcredits = lpni->lpni_txcredits;
		lpni->lpni_rtrcredits = lnet_peer_buffer_credits(net);
		lpni->lpni_minrtrcredits = lpni->lpni_rtrcredits;
	} else {
		/*
		 * This peer_ni is not on a local network, so we
		 * cannot add the credits here. In case the net is
		 * added later, add the peer_ni to the remote peer ni
		 * list so it can be easily found and revisited.
		 */
		/* FIXME: per-net implementation instead? */
		lnet_peer_ni_addref_locked(lpni);
		list_add_tail(&lpni->lpni_on_remote_peer_ni_list,
			      &the_lnet.ln_remote_peer_ni_list);
	}

	CDEBUG(D_NET, "%p nid %s\n", lpni, libcfs_nid2str(lpni->lpni_nid));

	return lpni;
}

static struct lnet_peer_net *
lnet_peer_net_alloc(__u32 net_id)
{
	struct lnet_peer_net *lpn;

	LIBCFS_CPT_ALLOC(lpn, lnet_cpt_table(), CFS_CPT_ANY, sizeof(*lpn));
	if (!lpn)
		return NULL;

	INIT_LIST_HEAD(&lpn->lpn_peer_nets);
	INIT_LIST_HEAD(&lpn->lpn_peer_nis);
	lpn->lpn_net_id = net_id;
	lpn->lpn_sel_priority = LNET_MAX_SELECTION_PRIORITY;

	CDEBUG(D_NET, "%p net %s\n", lpn, libcfs_net2str(lpn->lpn_net_id));

	return lpn;
}

void
lnet_destroy_peer_net_locked(struct lnet_peer_net *lpn)
{
	struct lnet_peer *lp;

	CDEBUG(D_NET, "%p net %s\n", lpn, libcfs_net2str(lpn->lpn_net_id));

	LASSERT(atomic_read(&lpn->lpn_refcount) == 0);
	LASSERT(list_empty(&lpn->lpn_peer_nis));
	LASSERT(list_empty(&lpn->lpn_peer_nets));
	lp = lpn->lpn_peer;
	lpn->lpn_peer = NULL;
	LIBCFS_FREE(lpn, sizeof(*lpn));

	lnet_peer_decref_locked(lp);
}

static struct lnet_peer *
lnet_peer_alloc(lnet_nid_t nid)
{
	struct lnet_peer *lp;

	LIBCFS_CPT_ALLOC(lp, lnet_cpt_table(), CFS_CPT_ANY, sizeof(*lp));
	if (!lp)
		return NULL;

	INIT_LIST_HEAD(&lp->lp_rtrq);
	INIT_LIST_HEAD(&lp->lp_routes);
	INIT_LIST_HEAD(&lp->lp_peer_list);
	INIT_LIST_HEAD(&lp->lp_peer_nets);
	INIT_LIST_HEAD(&lp->lp_dc_list);
	INIT_LIST_HEAD(&lp->lp_dc_pendq);
	INIT_LIST_HEAD(&lp->lp_rtr_list);
	init_waitqueue_head(&lp->lp_dc_waitq);
	spin_lock_init(&lp->lp_lock);
	lp->lp_primary_nid = nid;
	lp->lp_disc_src_nid = LNET_NID_ANY;
	if (lnet_peers_start_down())
		lp->lp_alive = false;
	else
		lp->lp_alive = true;

	/*
	 * all peers created on a router should have health on
	 * if it's not already on.
	 */
	if (the_lnet.ln_routing && !lnet_health_sensitivity)
		lp->lp_health_sensitivity = 1;

	/*
	 * Turn off discovery for loopback peer. If you're creating a peer
	 * for the loopback interface then that was initiated when we
	 * attempted to send a message over the loopback. There is no need
	 * to ever use a different interface when sending messages to
	 * myself.
	 */
	if (nid == LNET_NID_LO_0)
		lp->lp_state = LNET_PEER_NO_DISCOVERY;
	lp->lp_cpt = lnet_nid_cpt_hash(nid, LNET_CPT_NUMBER);

	CDEBUG(D_NET, "%p nid %s\n", lp, libcfs_nid2str(lp->lp_primary_nid));

	return lp;
}

void
lnet_destroy_peer_locked(struct lnet_peer *lp)
{
	CDEBUG(D_NET, "%p nid %s\n", lp, libcfs_nid2str(lp->lp_primary_nid));

	LASSERT(atomic_read(&lp->lp_refcount) == 0);
	LASSERT(lp->lp_rtr_refcount == 0);
	LASSERT(list_empty(&lp->lp_peer_nets));
	LASSERT(list_empty(&lp->lp_peer_list));
	LASSERT(list_empty(&lp->lp_dc_list));

	if (lp->lp_data)
		lnet_ping_buffer_decref(lp->lp_data);

	/*
	 * if there are messages still on the pending queue, then make
	 * sure to queue them on the ln_msg_resend list so they can be
	 * resent at a later point if the discovery thread is still
	 * running.
	 * If the discovery thread has stopped, then the wakeup will be a
	 * no-op, and it is expected the lnet_shutdown_lndnets() will
	 * eventually be called, which will traverse this list and
	 * finalize the messages on the list.
	 * We can not resend them now because we're holding the cpt lock.
	 * Releasing the lock can cause an inconsistent state
	 */
	spin_lock(&the_lnet.ln_msg_resend_lock);
	spin_lock(&lp->lp_lock);
	list_splice(&lp->lp_dc_pendq, &the_lnet.ln_msg_resend);
	spin_unlock(&lp->lp_lock);
	spin_unlock(&the_lnet.ln_msg_resend_lock);
	wake_up(&the_lnet.ln_dc_waitq);

	LIBCFS_FREE(lp, sizeof(*lp));
}

/*
 * Detach a peer_ni from its peer_net. If this was the last peer_ni on
 * that peer_net, detach the peer_net from the peer.
 *
 * Call with lnet_net_lock/EX held
 */
static void
lnet_peer_detach_peer_ni_locked(struct lnet_peer_ni *lpni)
{
	struct lnet_peer_table *ptable;
	struct lnet_peer_net *lpn;
	struct lnet_peer *lp;

	/*
	 * Belts and suspenders: gracefully handle teardown of a
	 * partially connected peer_ni.
	 */
	lpn = lpni->lpni_peer_net;

	list_del_init(&lpni->lpni_peer_nis);
	/*
	 * If there are no lpni's left, we detach lpn from
	 * lp_peer_nets, so it cannot be found anymore.
	 */
	if (list_empty(&lpn->lpn_peer_nis))
		list_del_init(&lpn->lpn_peer_nets);

	/* Update peer NID count. */
	lp = lpn->lpn_peer;
	lp->lp_nnis--;

	/*
	 * If there are no more peer nets, make the peer unfindable
	 * via the peer_tables.
	 *
	 * Otherwise, if the peer is DISCOVERED, tell discovery to
	 * take another look at it. This is a no-op if discovery for
	 * this peer did the detaching.
	 */
	if (list_empty(&lp->lp_peer_nets)) {
		list_del_init(&lp->lp_peer_list);
		ptable = the_lnet.ln_peer_tables[lp->lp_cpt];
		ptable->pt_peers--;
	} else if (the_lnet.ln_dc_state != LNET_DC_STATE_RUNNING) {
		/* Discovery isn't running, nothing to do here. */
	} else if (lp->lp_state & LNET_PEER_DISCOVERED) {
		lnet_peer_queue_for_discovery(lp);
		wake_up(&the_lnet.ln_dc_waitq);
	}
	CDEBUG(D_NET, "peer %s NID %s\n",
		libcfs_nid2str(lp->lp_primary_nid),
		libcfs_nid2str(lpni->lpni_nid));
}

/* called with lnet_net_lock LNET_LOCK_EX held */
static int
lnet_peer_ni_del_locked(struct lnet_peer_ni *lpni, bool force)
{
	struct lnet_peer_table *ptable = NULL;

	/* don't remove a peer_ni if it's also a gateway */
	if (lnet_isrouter(lpni) && !force) {
		CERROR("Peer NI %s is a gateway. Can not delete it\n",
		       libcfs_nid2str(lpni->lpni_nid));
		return -EBUSY;
	}

	lnet_peer_remove_from_remote_list(lpni);

	/* remove peer ni from the hash list. */
	list_del_init(&lpni->lpni_hashlist);

	/*
	 * indicate the peer is being deleted so the monitor thread can
	 * remove it from the recovery queue.
	 */
	spin_lock(&lpni->lpni_lock);
	lpni->lpni_state |= LNET_PEER_NI_DELETING;
	spin_unlock(&lpni->lpni_lock);

	/* decrement the ref count on the peer table */
	ptable = the_lnet.ln_peer_tables[lpni->lpni_cpt];

	/*
	 * The peer_ni can no longer be found with a lookup. But there
	 * can be current users, so keep track of it on the zombie
	 * list until the reference count has gone to zero.
	 *
	 * The last reference may be lost in a place where the
	 * lnet_net_lock locks only a single cpt, and that cpt may not
	 * be lpni->lpni_cpt. So the zombie list of lnet_peer_table
	 * has its own lock.
	 */
	spin_lock(&ptable->pt_zombie_lock);
	list_add(&lpni->lpni_hashlist, &ptable->pt_zombie_list);
	ptable->pt_zombies++;
	spin_unlock(&ptable->pt_zombie_lock);

	/* no need to keep this peer_ni on the hierarchy anymore */
	lnet_peer_detach_peer_ni_locked(lpni);

	/* remove hashlist reference on peer_ni */
	lnet_peer_ni_decref_locked(lpni);

	return 0;
}

void lnet_peer_uninit(void)
{
	struct lnet_peer_ni *lpni, *tmp;

	lnet_net_lock(LNET_LOCK_EX);

	/* remove all peer_nis from the remote peer and the hash list */
	list_for_each_entry_safe(lpni, tmp, &the_lnet.ln_remote_peer_ni_list,
				 lpni_on_remote_peer_ni_list)
		lnet_peer_ni_del_locked(lpni, false);

	lnet_peer_tables_destroy();

	lnet_net_unlock(LNET_LOCK_EX);
}

static int
lnet_peer_del_locked(struct lnet_peer *peer)
{
	struct lnet_peer_ni *lpni = NULL, *lpni2;
	int rc = 0, rc2 = 0;

	CDEBUG(D_NET, "peer %s\n", libcfs_nid2str(peer->lp_primary_nid));

	spin_lock(&peer->lp_lock);
	peer->lp_state |= LNET_PEER_MARK_DELETED;
	spin_unlock(&peer->lp_lock);

	lpni = lnet_get_next_peer_ni_locked(peer, NULL, lpni);
	while (lpni != NULL) {
		lpni2 = lnet_get_next_peer_ni_locked(peer, NULL, lpni);
		rc = lnet_peer_ni_del_locked(lpni, false);
		if (rc != 0)
			rc2 = rc;
		lpni = lpni2;
	}

	return rc2;
}

/*
 * Discovering this peer is taking too long. Cancel any Ping or Push
 * that discovery is waiting on by unlinking the relevant MDs. The
 * lnet_discovery_event_handler() will proceed from here and complete
 * the cleanup.
 */
static void lnet_peer_cancel_discovery(struct lnet_peer *lp)
{
	struct lnet_handle_md ping_mdh;
	struct lnet_handle_md push_mdh;

	LNetInvalidateMDHandle(&ping_mdh);
	LNetInvalidateMDHandle(&push_mdh);

	spin_lock(&lp->lp_lock);
	if (lp->lp_state & LNET_PEER_PING_SENT) {
		ping_mdh = lp->lp_ping_mdh;
		LNetInvalidateMDHandle(&lp->lp_ping_mdh);
	}
	if (lp->lp_state & LNET_PEER_PUSH_SENT) {
		push_mdh = lp->lp_push_mdh;
		LNetInvalidateMDHandle(&lp->lp_push_mdh);
	}
	spin_unlock(&lp->lp_lock);

	if (!LNetMDHandleIsInvalid(ping_mdh))
		LNetMDUnlink(ping_mdh);
	if (!LNetMDHandleIsInvalid(push_mdh))
		LNetMDUnlink(push_mdh);
}

static int
lnet_peer_del(struct lnet_peer *peer)
{
	lnet_peer_cancel_discovery(peer);
	lnet_net_lock(LNET_LOCK_EX);
	lnet_peer_del_locked(peer);
	lnet_net_unlock(LNET_LOCK_EX);

	return 0;
}

/*
 * Delete a NID from a peer. Call with ln_api_mutex held.
 *
 * Error codes:
 *  -EPERM:  Non-DLC deletion from DLC-configured peer.
 *  -ENOENT: No lnet_peer_ni corresponding to the nid.
 *  -ECHILD: The lnet_peer_ni isn't connected to the peer.
 *  -EBUSY:  The lnet_peer_ni is the primary, and not the only peer_ni.
 */
static int
lnet_peer_del_nid(struct lnet_peer *lp, lnet_nid_t nid, unsigned flags)
{
	struct lnet_peer_ni *lpni;
	lnet_nid_t primary_nid = lp->lp_primary_nid;
	int rc = 0;
	bool force = (flags & LNET_PEER_RTR_NI_FORCE_DEL) ? true : false;

	if (!(flags & LNET_PEER_CONFIGURED)) {
		if (lp->lp_state & LNET_PEER_CONFIGURED) {
			rc = -EPERM;
			goto out;
		}
	}
	lpni = lnet_find_peer_ni_locked(nid);
	if (!lpni) {
		rc = -ENOENT;
		goto out;
	}
	lnet_peer_ni_decref_locked(lpni);
	if (lp != lpni->lpni_peer_net->lpn_peer) {
		rc = -ECHILD;
		goto out;
	}

	/*
	 * This function only allows deletion of the primary NID if it
	 * is the only NID.
	 */
	if (nid == lp->lp_primary_nid && lp->lp_nnis != 1 && !force) {
		rc = -EBUSY;
		goto out;
	}

	lnet_net_lock(LNET_LOCK_EX);

	if (nid == lp->lp_primary_nid && lp->lp_nnis != 1 && force) {
		struct lnet_peer_ni *lpni2;
		/* assign the next peer_ni to be the primary */
		lpni2 = lnet_get_next_peer_ni_locked(lp, NULL, lpni);
		LASSERT(lpni2);
		lp->lp_primary_nid = lpni2->lpni_nid;
	}
	rc = lnet_peer_ni_del_locked(lpni, force);

	lnet_net_unlock(LNET_LOCK_EX);

out:
	CDEBUG(D_NET, "peer %s NID %s flags %#x: %d\n",
	       libcfs_nid2str(primary_nid), libcfs_nid2str(nid), flags, rc);

	return rc;
}

static void
lnet_peer_table_cleanup_locked(struct lnet_net *net,
			       struct lnet_peer_table *ptable)
{
	int			 i;
	struct lnet_peer_ni	*next;
	struct lnet_peer_ni	*lpni;
	struct lnet_peer	*peer;

	for (i = 0; i < LNET_PEER_HASH_SIZE; i++) {
		list_for_each_entry_safe(lpni, next, &ptable->pt_hash[i],
					 lpni_hashlist) {
			if (net != NULL && net != lpni->lpni_net)
				continue;

			peer = lpni->lpni_peer_net->lpn_peer;
			if (peer->lp_primary_nid != lpni->lpni_nid) {
				lnet_peer_ni_del_locked(lpni, false);
				continue;
			}
			/*
			 * Removing the primary NID implies removing
			 * the entire peer. Advance next beyond any
			 * peer_ni that belongs to the same peer.
			 */
			list_for_each_entry_from(next, &ptable->pt_hash[i],
						 lpni_hashlist) {
				if (next->lpni_peer_net->lpn_peer != peer)
					break;
			}
			lnet_peer_del_locked(peer);
		}
	}
}

static void
lnet_peer_ni_finalize_wait(struct lnet_peer_table *ptable)
{
	wait_var_event_warning(&ptable->pt_zombies,
			       ptable->pt_zombies == 0,
			       "Waiting for %d zombies on peer table\n",
			       ptable->pt_zombies);
}

static void
lnet_peer_table_del_rtrs_locked(struct lnet_net *net,
				struct lnet_peer_table *ptable)
{
	struct lnet_peer_ni	*lp;
	struct lnet_peer_ni	*tmp;
	lnet_nid_t		gw_nid;
	int			i;

	for (i = 0; i < LNET_PEER_HASH_SIZE; i++) {
		list_for_each_entry_safe(lp, tmp, &ptable->pt_hash[i],
					 lpni_hashlist) {
			if (net != lp->lpni_net)
				continue;

			if (!lnet_isrouter(lp))
				continue;

			gw_nid = lp->lpni_peer_net->lpn_peer->lp_primary_nid;

			lnet_net_unlock(LNET_LOCK_EX);
			lnet_del_route(LNET_NET_ANY, gw_nid);
			lnet_net_lock(LNET_LOCK_EX);
		}
	}
}

void
lnet_peer_tables_cleanup(struct lnet_net *net)
{
	int i;
	struct lnet_peer_table *ptable;

	LASSERT(the_lnet.ln_state != LNET_STATE_SHUTDOWN || net != NULL);
	/* If just deleting the peers for a NI, get rid of any routes these
	 * peers are gateways for. */
	cfs_percpt_for_each(ptable, i, the_lnet.ln_peer_tables) {
		lnet_net_lock(LNET_LOCK_EX);
		lnet_peer_table_del_rtrs_locked(net, ptable);
		lnet_net_unlock(LNET_LOCK_EX);
	}

	/* Start the cleanup process */
	cfs_percpt_for_each(ptable, i, the_lnet.ln_peer_tables) {
		lnet_net_lock(LNET_LOCK_EX);
		lnet_peer_table_cleanup_locked(net, ptable);
		lnet_net_unlock(LNET_LOCK_EX);
	}

	cfs_percpt_for_each(ptable, i, the_lnet.ln_peer_tables)
		lnet_peer_ni_finalize_wait(ptable);
}

static struct lnet_peer_ni *
lnet_get_peer_ni_locked(struct lnet_peer_table *ptable, lnet_nid_t nid)
{
	struct list_head	*peers;
	struct lnet_peer_ni	*lp;

	if (the_lnet.ln_state != LNET_STATE_RUNNING)
		return NULL;

	peers = &ptable->pt_hash[lnet_nid2peerhash(nid)];
	list_for_each_entry(lp, peers, lpni_hashlist) {
		if (lp->lpni_nid == nid) {
			lnet_peer_ni_addref_locked(lp);
			return lp;
		}
	}

	return NULL;
}

struct lnet_peer_ni *
lnet_find_peer_ni_locked(lnet_nid_t nid)
{
	struct lnet_peer_ni *lpni;
	struct lnet_peer_table *ptable;
	int cpt;

	cpt = lnet_nid_cpt_hash(nid, LNET_CPT_NUMBER);

	ptable = the_lnet.ln_peer_tables[cpt];
	lpni = lnet_get_peer_ni_locked(ptable, nid);

	return lpni;
}

struct lnet_peer_ni *
lnet_peer_get_ni_locked(struct lnet_peer *lp, lnet_nid_t nid)
{
	struct lnet_peer_net *lpn;
	struct lnet_peer_ni *lpni;

	lpn = lnet_peer_get_net_locked(lp, LNET_NIDNET(nid));
	if (!lpn)
		return NULL;

	list_for_each_entry(lpni, &lpn->lpn_peer_nis, lpni_peer_nis) {
		if (lpni->lpni_nid == nid)
			return lpni;
	}

	return NULL;
}

struct lnet_peer *
lnet_find_peer(lnet_nid_t nid)
{
	struct lnet_peer_ni *lpni;
	struct lnet_peer *lp = NULL;
	int cpt;

	cpt = lnet_net_lock_current();
	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni) {
		lp = lpni->lpni_peer_net->lpn_peer;
		lnet_peer_addref_locked(lp);
		lnet_peer_ni_decref_locked(lpni);
	}
	lnet_net_unlock(cpt);

	return lp;
}

struct lnet_peer_net *
lnet_get_next_peer_net_locked(struct lnet_peer *lp, __u32 prev_lpn_id)
{
	struct lnet_peer_net *net;

	if (!prev_lpn_id) {
		/* no net id provided return the first net */
		net = list_first_entry_or_null(&lp->lp_peer_nets,
					       struct lnet_peer_net,
					       lpn_peer_nets);

		return net;
	}

	/* find the net after the one provided */
	list_for_each_entry(net, &lp->lp_peer_nets, lpn_peer_nets) {
		if (net->lpn_net_id == prev_lpn_id) {
			/*
			 * if we reached the end of the list loop to the
			 * beginning.
			 */
			if (net->lpn_peer_nets.next == &lp->lp_peer_nets)
				return list_first_entry_or_null(&lp->lp_peer_nets,
								struct lnet_peer_net,
								lpn_peer_nets);
			else
				return list_next_entry(net, lpn_peer_nets);
		}
	}

	return NULL;
}

struct lnet_peer_ni *
lnet_get_next_peer_ni_locked(struct lnet_peer *peer,
			     struct lnet_peer_net *peer_net,
			     struct lnet_peer_ni *prev)
{
	struct lnet_peer_ni *lpni;
	struct lnet_peer_net *net = peer_net;

	if (!prev) {
		if (!net) {
			if (list_empty(&peer->lp_peer_nets))
				return NULL;

			net = list_entry(peer->lp_peer_nets.next,
					 struct lnet_peer_net,
					 lpn_peer_nets);
		}
		lpni = list_entry(net->lpn_peer_nis.next, struct lnet_peer_ni,
				  lpni_peer_nis);

		return lpni;
	}

	if (prev->lpni_peer_nis.next == &prev->lpni_peer_net->lpn_peer_nis) {
		/*
		 * if you reached the end of the peer ni list and the peer
		 * net is specified then there are no more peer nis in that
		 * net.
		 */
		if (net)
			return NULL;

		/*
		 * we reached the end of this net ni list. move to the
		 * next net
		 */
		if (prev->lpni_peer_net->lpn_peer_nets.next ==
		    &peer->lp_peer_nets)
			/* no more nets and no more NIs. */
			return NULL;

		/* get the next net */
		net = list_entry(prev->lpni_peer_net->lpn_peer_nets.next,
				 struct lnet_peer_net,
				 lpn_peer_nets);
		/* get the ni on it */
		lpni = list_entry(net->lpn_peer_nis.next, struct lnet_peer_ni,
				  lpni_peer_nis);

		return lpni;
	}

	/* there are more nis left */
	lpni = list_entry(prev->lpni_peer_nis.next,
			  struct lnet_peer_ni, lpni_peer_nis);

	return lpni;
}

/* Call with the ln_api_mutex held */
int lnet_get_peer_list(u32 *countp, u32 *sizep, struct lnet_process_id __user *ids)
{
	struct lnet_process_id id;
	struct lnet_peer_table *ptable;
	struct lnet_peer *lp;
	__u32 count = 0;
	__u32 size = 0;
	int lncpt;
	int cpt;
	__u32 i;
	int rc;

	rc = -ESHUTDOWN;
	if (the_lnet.ln_state != LNET_STATE_RUNNING)
		goto done;

	lncpt = cfs_percpt_number(the_lnet.ln_peer_tables);

	/*
	 * Count the number of peers, and return E2BIG if the buffer
	 * is too small. We'll also return the desired size.
	 */
	rc = -E2BIG;
	for (cpt = 0; cpt < lncpt; cpt++) {
		ptable = the_lnet.ln_peer_tables[cpt];
		count += ptable->pt_peers;
	}
	size = count * sizeof(*ids);
	if (size > *sizep)
		goto done;

	/*
	 * Walk the peer lists and copy out the primary nids.
	 * This is safe because the peer lists are only modified
	 * while the ln_api_mutex is held. So we don't need to
	 * hold the lnet_net_lock as well, and can therefore
	 * directly call copy_to_user().
	 */
	rc = -EFAULT;
	memset(&id, 0, sizeof(id));
	id.pid = LNET_PID_LUSTRE;
	i = 0;
	for (cpt = 0; cpt < lncpt; cpt++) {
		ptable = the_lnet.ln_peer_tables[cpt];
		list_for_each_entry(lp, &ptable->pt_peer_list, lp_peer_list) {
			if (i >= count)
				goto done;
			id.nid = lp->lp_primary_nid;
			if (copy_to_user(&ids[i], &id, sizeof(id)))
				goto done;
			i++;
		}
	}
	rc = 0;
done:
	*countp = count;
	*sizep = size;
	return rc;
}

/*
 * Start pushes to peers that need to be updated for a configuration
 * change on this node.
 */
void
lnet_push_update_to_peers(int force)
{
	struct lnet_peer_table *ptable;
	struct lnet_peer *lp;
	int lncpt;
	int cpt;

	lnet_net_lock(LNET_LOCK_EX);
	if (lnet_peer_discovery_disabled)
		force = 0;
	lncpt = cfs_percpt_number(the_lnet.ln_peer_tables);
	for (cpt = 0; cpt < lncpt; cpt++) {
		ptable = the_lnet.ln_peer_tables[cpt];
		list_for_each_entry(lp, &ptable->pt_peer_list, lp_peer_list) {
			if (force) {
				spin_lock(&lp->lp_lock);
				if (lp->lp_state & LNET_PEER_MULTI_RAIL)
					lp->lp_state |= LNET_PEER_FORCE_PUSH;
				spin_unlock(&lp->lp_lock);
			}
			if (lnet_peer_needs_push(lp))
				lnet_peer_queue_for_discovery(lp);
		}
	}
	lnet_net_unlock(LNET_LOCK_EX);
	wake_up(&the_lnet.ln_dc_waitq);
}

/* find the NID in the preferred gateways for the remote peer
 * return:
 *	false: list is not empty and NID is not preferred
 *	false: list is empty
 *	true: nid is found in the list
 */
bool
lnet_peer_is_pref_rtr_locked(struct lnet_peer_ni *lpni,
			     lnet_nid_t gw_nid)
{
	struct lnet_nid_list *ne;

	CDEBUG(D_NET, "%s: rtr pref emtpy: %d\n",
	       libcfs_nid2str(lpni->lpni_nid),
	       list_empty(&lpni->lpni_rtr_pref_nids));

	if (list_empty(&lpni->lpni_rtr_pref_nids))
		return false;

	/* iterate through all the preferred NIDs and see if any of them
	 * matches the provided gw_nid
	 */
	list_for_each_entry(ne, &lpni->lpni_rtr_pref_nids, nl_list) {
		CDEBUG(D_NET, "Comparing pref %s with gw %s\n",
		       libcfs_nid2str(ne->nl_nid),
		       libcfs_nid2str(gw_nid));
		if (ne->nl_nid == gw_nid)
			return true;
	}

	return false;
}

void
lnet_peer_clr_pref_rtrs(struct lnet_peer_ni *lpni)
{
	struct list_head zombies;
	struct lnet_nid_list *ne;
	struct lnet_nid_list *tmp;
	int cpt = lpni->lpni_cpt;

	INIT_LIST_HEAD(&zombies);

	lnet_net_lock(cpt);
	list_splice_init(&lpni->lpni_rtr_pref_nids, &zombies);
	lnet_net_unlock(cpt);

	list_for_each_entry_safe(ne, tmp, &zombies, nl_list) {
		list_del(&ne->nl_list);
		LIBCFS_FREE(ne, sizeof(*ne));
	}
}

int
lnet_peer_add_pref_rtr(struct lnet_peer_ni *lpni,
		       lnet_nid_t gw_nid)
{
	int cpt = lpni->lpni_cpt;
	struct lnet_nid_list *ne = NULL;

	/* This function is called with api_mutex held. When the api_mutex
	 * is held the list can not be modified, as it is only modified as
	 * a result of applying a UDSP and that happens under api_mutex
	 * lock.
	 */
	__must_hold(&the_lnet.ln_api_mutex);

	list_for_each_entry(ne, &lpni->lpni_rtr_pref_nids, nl_list) {
		if (ne->nl_nid == gw_nid)
			return -EEXIST;
	}

	LIBCFS_CPT_ALLOC(ne, lnet_cpt_table(), cpt, sizeof(*ne));
	if (!ne)
		return -ENOMEM;

	ne->nl_nid = gw_nid;

	/* Lock the cpt to protect against addition and checks in the
	 * selection algorithm
	 */
	lnet_net_lock(cpt);
	list_add(&ne->nl_list, &lpni->lpni_rtr_pref_nids);
	lnet_net_unlock(cpt);

	return 0;
}

/*
 * Test whether a ni is a preferred ni for this peer_ni, e.g, whether
 * this is a preferred point-to-point path. Call with lnet_net_lock in
 * shared mmode.
 */
bool
lnet_peer_is_pref_nid_locked(struct lnet_peer_ni *lpni, lnet_nid_t nid)
{
	struct lnet_nid_list *ne;

	if (lpni->lpni_pref_nnids == 0)
		return false;
	if (lpni->lpni_pref_nnids == 1)
		return lpni->lpni_pref.nid == nid;
	list_for_each_entry(ne, &lpni->lpni_pref.nids, nl_list) {
		if (ne->nl_nid == nid)
			return true;
	}
	return false;
}

/*
 * Set a single ni as preferred, provided no preferred ni is already
 * defined. Only to be used for non-multi-rail peer_ni.
 */
int
lnet_peer_ni_set_non_mr_pref_nid(struct lnet_peer_ni *lpni, lnet_nid_t nid)
{
	int rc = 0;

	spin_lock(&lpni->lpni_lock);
	if (nid == LNET_NID_ANY) {
		rc = -EINVAL;
	} else if (lpni->lpni_pref_nnids > 0) {
		rc = -EPERM;
	} else if (lpni->lpni_pref_nnids == 0) {
		lpni->lpni_pref.nid = nid;
		lpni->lpni_pref_nnids = 1;
		lpni->lpni_state |= LNET_PEER_NI_NON_MR_PREF;
	}
	spin_unlock(&lpni->lpni_lock);

	CDEBUG(D_NET, "peer %s nid %s: %d\n",
	       libcfs_nid2str(lpni->lpni_nid), libcfs_nid2str(nid), rc);
	return rc;
}

/*
 * Clear the preferred NID from a non-multi-rail peer_ni, provided
 * this preference was set by lnet_peer_ni_set_non_mr_pref_nid().
 */
int
lnet_peer_ni_clr_non_mr_pref_nid(struct lnet_peer_ni *lpni)
{
	int rc = 0;

	spin_lock(&lpni->lpni_lock);
	if (lpni->lpni_state & LNET_PEER_NI_NON_MR_PREF) {
		lpni->lpni_pref_nnids = 0;
		lpni->lpni_state &= ~LNET_PEER_NI_NON_MR_PREF;
	} else if (lpni->lpni_pref_nnids == 0) {
		rc = -ENOENT;
	} else {
		rc = -EPERM;
	}
	spin_unlock(&lpni->lpni_lock);

	CDEBUG(D_NET, "peer %s: %d\n",
	       libcfs_nid2str(lpni->lpni_nid), rc);
	return rc;
}

void
lnet_peer_ni_set_selection_priority(struct lnet_peer_ni *lpni, __u32 priority)
{
	lpni->lpni_sel_priority = priority;
}

/*
 * Clear the preferred NIDs from a non-multi-rail peer.
 */
void
lnet_peer_clr_non_mr_pref_nids(struct lnet_peer *lp)
{
	struct lnet_peer_ni *lpni = NULL;

	while ((lpni = lnet_get_next_peer_ni_locked(lp, NULL, lpni)) != NULL)
		lnet_peer_ni_clr_non_mr_pref_nid(lpni);
}

int
lnet_peer_add_pref_nid(struct lnet_peer_ni *lpni, lnet_nid_t nid)
{
	struct lnet_peer *lp = lpni->lpni_peer_net->lpn_peer;
	struct lnet_nid_list *ne1 = NULL;
	struct lnet_nid_list *ne2 = NULL;
	lnet_nid_t tmp_nid = LNET_NID_ANY;
	int rc = 0;

	if (nid == LNET_NID_ANY) {
		rc = -EINVAL;
		goto out;
	}

	if (lpni->lpni_pref_nnids == 1 && lpni->lpni_pref.nid == nid) {
		rc = -EEXIST;
		goto out;
	}

	/* A non-MR node may have only one preferred NI per peer_ni */
	if (lpni->lpni_pref_nnids > 0 &&
	    !(lp->lp_state & LNET_PEER_MULTI_RAIL)) {
		rc = -EPERM;
		goto out;
	}

	/* add the new preferred nid to the list of preferred nids */
	if (lpni->lpni_pref_nnids != 0) {
		size_t alloc_size = sizeof(*ne1);

		if (lpni->lpni_pref_nnids == 1) {
			tmp_nid = lpni->lpni_pref.nid;
			INIT_LIST_HEAD(&lpni->lpni_pref.nids);
		}

		list_for_each_entry(ne1, &lpni->lpni_pref.nids, nl_list) {
			if (ne1->nl_nid == nid) {
				rc = -EEXIST;
				goto out;
			}
		}

		LIBCFS_CPT_ALLOC(ne1, lnet_cpt_table(), lpni->lpni_cpt,
				 alloc_size);
		if (!ne1) {
			rc = -ENOMEM;
			goto out;
		}

		/* move the originally stored nid to the list */
		if (lpni->lpni_pref_nnids == 1) {
			LIBCFS_CPT_ALLOC(ne2, lnet_cpt_table(),
				lpni->lpni_cpt, alloc_size);
			if (!ne2) {
				rc = -ENOMEM;
				goto out;
			}
			INIT_LIST_HEAD(&ne2->nl_list);
			ne2->nl_nid = tmp_nid;
		}
		ne1->nl_nid = nid;
	}

	lnet_net_lock(LNET_LOCK_EX);
	spin_lock(&lpni->lpni_lock);
	if (lpni->lpni_pref_nnids == 0) {
		lpni->lpni_pref.nid = nid;
	} else {
		if (ne2)
			list_add_tail(&ne2->nl_list, &lpni->lpni_pref.nids);
		list_add_tail(&ne1->nl_list, &lpni->lpni_pref.nids);
	}
	lpni->lpni_pref_nnids++;
	lpni->lpni_state &= ~LNET_PEER_NI_NON_MR_PREF;
	spin_unlock(&lpni->lpni_lock);
	lnet_net_unlock(LNET_LOCK_EX);

out:
	if (rc == -EEXIST && (lpni->lpni_state & LNET_PEER_NI_NON_MR_PREF)) {
		spin_lock(&lpni->lpni_lock);
		lpni->lpni_state &= ~LNET_PEER_NI_NON_MR_PREF;
		spin_unlock(&lpni->lpni_lock);
	}
	CDEBUG(D_NET, "peer %s nid %s: %d\n",
	       libcfs_nid2str(lp->lp_primary_nid), libcfs_nid2str(nid), rc);
	return rc;
}

int
lnet_peer_del_pref_nid(struct lnet_peer_ni *lpni, lnet_nid_t nid)
{
	struct lnet_peer *lp = lpni->lpni_peer_net->lpn_peer;
	struct lnet_nid_list *ne = NULL;
	int rc = 0;

	if (lpni->lpni_pref_nnids == 0) {
		rc = -ENOENT;
		goto out;
	}

	if (lpni->lpni_pref_nnids == 1) {
		if (lpni->lpni_pref.nid != nid) {
			rc = -ENOENT;
			goto out;
		}
	} else {
		list_for_each_entry(ne, &lpni->lpni_pref.nids, nl_list) {
			if (ne->nl_nid == nid)
				goto remove_nid_entry;
		}
		rc = -ENOENT;
		ne = NULL;
		goto out;
	}

remove_nid_entry:
	lnet_net_lock(LNET_LOCK_EX);
	spin_lock(&lpni->lpni_lock);
	if (lpni->lpni_pref_nnids == 1)
		lpni->lpni_pref.nid = LNET_NID_ANY;
	else {
		list_del_init(&ne->nl_list);
		if (lpni->lpni_pref_nnids == 2) {
			struct lnet_nid_list *ne, *tmp;

			list_for_each_entry_safe(ne, tmp,
						 &lpni->lpni_pref.nids,
						 nl_list) {
				lpni->lpni_pref.nid = ne->nl_nid;
				list_del_init(&ne->nl_list);
				LIBCFS_FREE(ne, sizeof(*ne));
			}
		}
	}
	lpni->lpni_pref_nnids--;
	lpni->lpni_state &= ~LNET_PEER_NI_NON_MR_PREF;
	spin_unlock(&lpni->lpni_lock);
	lnet_net_unlock(LNET_LOCK_EX);

	if (ne)
		LIBCFS_FREE(ne, sizeof(*ne));
out:
	CDEBUG(D_NET, "peer %s nid %s: %d\n",
	       libcfs_nid2str(lp->lp_primary_nid), libcfs_nid2str(nid), rc);
	return rc;
}

void
lnet_peer_clr_pref_nids(struct lnet_peer_ni *lpni)
{
	struct list_head zombies;
	struct lnet_nid_list *ne;
	struct lnet_nid_list *tmp;

	INIT_LIST_HEAD(&zombies);

	lnet_net_lock(LNET_LOCK_EX);
	if (lpni->lpni_pref_nnids == 1)
		lpni->lpni_pref.nid = LNET_NID_ANY;
	else if (lpni->lpni_pref_nnids > 1)
		list_splice_init(&lpni->lpni_pref.nids, &zombies);
	lpni->lpni_pref_nnids = 0;
	lnet_net_unlock(LNET_LOCK_EX);

	list_for_each_entry_safe(ne, tmp, &zombies, nl_list) {
		list_del_init(&ne->nl_list);
		LIBCFS_FREE(ne, sizeof(*ne));
	}
}

lnet_nid_t
lnet_peer_primary_nid_locked(lnet_nid_t nid)
{
	struct lnet_peer_ni *lpni;
	lnet_nid_t primary_nid = nid;

	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni) {
		primary_nid = lpni->lpni_peer_net->lpn_peer->lp_primary_nid;
		lnet_peer_ni_decref_locked(lpni);
	}

	return primary_nid;
}

bool
lnet_is_discovery_disabled_locked(struct lnet_peer *lp)
__must_hold(&lp->lp_lock)
{
	if (lnet_peer_discovery_disabled)
		return true;

	if (!(lp->lp_state & LNET_PEER_MULTI_RAIL) ||
	    (lp->lp_state & LNET_PEER_NO_DISCOVERY)) {
		return true;
	}

	return false;
}

/*
 * Peer Discovery
 */
bool
lnet_is_discovery_disabled(struct lnet_peer *lp)
{
	bool rc = false;

	spin_lock(&lp->lp_lock);
	rc = lnet_is_discovery_disabled_locked(lp);
	spin_unlock(&lp->lp_lock);

	return rc;
}

lnet_nid_t
LNetPrimaryNID(lnet_nid_t nid)
{
	struct lnet_peer *lp;
	struct lnet_peer_ni *lpni;
	lnet_nid_t primary_nid = nid;
	int rc = 0;
	int cpt;

	if (nid == LNET_NID_LO_0)
		return LNET_NID_LO_0;

	cpt = lnet_net_lock_current();
	lpni = lnet_nid2peerni_locked(nid, LNET_NID_ANY, cpt);
	if (IS_ERR(lpni)) {
		rc = PTR_ERR(lpni);
		goto out_unlock;
	}
	lp = lpni->lpni_peer_net->lpn_peer;

	/* If discovery is disabled locally then we needn't bother running
	 * discovery here because discovery will not modify whatever
	 * primary NID is currently set for this peer. If the specified peer is
	 * down then this discovery can introduce long delays into the mount
	 * process, so skip it if it isn't necessary.
	 */
	while (!lnet_peer_discovery_disabled && !lnet_peer_is_uptodate(lp)) {
		spin_lock(&lp->lp_lock);
		/* force a full discovery cycle */
		lp->lp_state |= LNET_PEER_FORCE_PING | LNET_PEER_FORCE_PUSH;
		spin_unlock(&lp->lp_lock);

		rc = lnet_discover_peer_locked(lpni, cpt, true);
		if (rc)
			goto out_decref;
		/* The lpni (or lp) for this NID may have changed and our ref is
		 * the only thing keeping the old one around. Release the ref
		 * and lookup the lpni again
		 */
		lnet_peer_ni_decref_locked(lpni);
		lpni = lnet_find_peer_ni_locked(nid);
		if (!lpni) {
			rc = -ENOENT;
			goto out_unlock;
		}
		lp = lpni->lpni_peer_net->lpn_peer;

		/* If we find that the peer has discovery disabled then we will
		 * not modify whatever primary NID is currently set for this
		 * peer. Thus, we can break out of this loop even if the peer
		 * is not fully up to date.
		 */
		if (lnet_is_discovery_disabled(lp))
			break;
	}
	primary_nid = lp->lp_primary_nid;
out_decref:
	lnet_peer_ni_decref_locked(lpni);
out_unlock:
	lnet_net_unlock(cpt);

	CDEBUG(D_NET, "NID %s primary NID %s rc %d\n", libcfs_nid2str(nid),
	       libcfs_nid2str(primary_nid), rc);
	return primary_nid;
}
EXPORT_SYMBOL(LNetPrimaryNID);

struct lnet_peer_net *
lnet_peer_get_net_locked(struct lnet_peer *peer, __u32 net_id)
{
	struct lnet_peer_net *peer_net;
	list_for_each_entry(peer_net, &peer->lp_peer_nets, lpn_peer_nets) {
		if (peer_net->lpn_net_id == net_id)
			return peer_net;
	}
	return NULL;
}

/*
 * Attach a peer_ni to a peer_net and peer. This function assumes
 * peer_ni is not already attached to the peer_net/peer. The peer_ni
 * may be attached to a different peer, in which case it will be
 * properly detached first. The whole operation is done atomically.
 *
 * This function consumes the reference on lpni and Always returns 0.
 * This is the last function called from functions that do return an
 * int, so returning 0 here allows the compiler to do a tail call.
 */
static int
lnet_peer_attach_peer_ni(struct lnet_peer *lp,
				struct lnet_peer_net *lpn,
				struct lnet_peer_ni *lpni,
				unsigned flags)
{
	struct lnet_peer_table *ptable;
	bool new_lpn = false;
	int rc;

	/* Install the new peer_ni */
	lnet_net_lock(LNET_LOCK_EX);
	/* Add peer_ni to global peer table hash, if necessary. */
	if (list_empty(&lpni->lpni_hashlist)) {
		int hash = lnet_nid2peerhash(lpni->lpni_nid);

		ptable = the_lnet.ln_peer_tables[lpni->lpni_cpt];
		list_add_tail(&lpni->lpni_hashlist, &ptable->pt_hash[hash]);
		ptable->pt_version++;
		lnet_peer_ni_addref_locked(lpni);
	}

	/* Detach the peer_ni from an existing peer, if necessary. */
	if (lpni->lpni_peer_net) {
		LASSERT(lpni->lpni_peer_net != lpn);
		LASSERT(lpni->lpni_peer_net->lpn_peer != lp);
		lnet_peer_detach_peer_ni_locked(lpni);
		lnet_peer_net_decref_locked(lpni->lpni_peer_net);
		lpni->lpni_peer_net = NULL;
	}

	/* Add peer_ni to peer_net */
	lpni->lpni_peer_net = lpn;
	if (lp->lp_primary_nid == lpni->lpni_nid)
		list_add(&lpni->lpni_peer_nis, &lpn->lpn_peer_nis);
	else
		list_add_tail(&lpni->lpni_peer_nis, &lpn->lpn_peer_nis);
	lnet_update_peer_net_healthv(lpni);
	lnet_peer_net_addref_locked(lpn);

	/* Add peer_net to peer */
	if (!lpn->lpn_peer) {
		new_lpn = true;
		lpn->lpn_peer = lp;
		if (lp->lp_primary_nid == lpni->lpni_nid)
			list_add(&lpn->lpn_peer_nets, &lp->lp_peer_nets);
		else
			list_add_tail(&lpn->lpn_peer_nets, &lp->lp_peer_nets);
		lnet_peer_addref_locked(lp);
	}

	/* Add peer to global peer list, if necessary */
	ptable = the_lnet.ln_peer_tables[lp->lp_cpt];
	if (list_empty(&lp->lp_peer_list)) {
		list_add_tail(&lp->lp_peer_list, &ptable->pt_peer_list);
		ptable->pt_peers++;
	}


	/* Update peer state */
	spin_lock(&lp->lp_lock);
	if (flags & LNET_PEER_CONFIGURED) {
		if (!(lp->lp_state & LNET_PEER_CONFIGURED))
			lp->lp_state |= LNET_PEER_CONFIGURED;
	}
	if (flags & LNET_PEER_MULTI_RAIL) {
		if (!(lp->lp_state & LNET_PEER_MULTI_RAIL)) {
			lp->lp_state |= LNET_PEER_MULTI_RAIL;
			lnet_peer_clr_non_mr_pref_nids(lp);
		}
	}
	spin_unlock(&lp->lp_lock);

	lp->lp_nnis++;

	/* apply UDSPs */
	if (new_lpn) {
		rc = lnet_udsp_apply_policies_on_lpn(lpn);
		if (rc)
			CERROR("Failed to apply UDSPs on lpn %s\n",
			       libcfs_net2str(lpn->lpn_net_id));
	}
	rc = lnet_udsp_apply_policies_on_lpni(lpni);
	if (rc)
		CERROR("Failed to apply UDSPs on lpni %s\n",
		       libcfs_nid2str(lpni->lpni_nid));

	CDEBUG(D_NET, "peer %s NID %s flags %#x\n",
	       libcfs_nid2str(lp->lp_primary_nid),
	       libcfs_nid2str(lpni->lpni_nid), flags);
	lnet_peer_ni_decref_locked(lpni);
	lnet_net_unlock(LNET_LOCK_EX);

	return 0;
}

/*
 * Create a new peer, with nid as its primary nid.
 *
 * Call with the lnet_api_mutex held.
 */
static int
lnet_peer_add(lnet_nid_t nid, unsigned flags)
{
	struct lnet_peer *lp;
	struct lnet_peer_net *lpn;
	struct lnet_peer_ni *lpni;
	int rc = 0;

	LASSERT(nid != LNET_NID_ANY);

	/*
	 * No need for the lnet_net_lock here, because the
	 * lnet_api_mutex is held.
	 */
	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni) {
		/* A peer with this NID already exists. */
		lp = lpni->lpni_peer_net->lpn_peer;
		lnet_peer_ni_decref_locked(lpni);
		/*
		 * This is an error if the peer was configured and the
		 * primary NID differs or an attempt is made to change
		 * the Multi-Rail flag. Otherwise the assumption is
		 * that an existing peer is being modified.
		 */
		if (lp->lp_state & LNET_PEER_CONFIGURED) {
			if (lp->lp_primary_nid != nid)
				rc = -EEXIST;
			else if ((lp->lp_state ^ flags) & LNET_PEER_MULTI_RAIL)
				rc = -EPERM;
			goto out;
		}
		/* Delete and recreate as a configured peer. */
		lnet_peer_del(lp);
	}

	/* Create peer, peer_net, and peer_ni. */
	rc = -ENOMEM;
	lp = lnet_peer_alloc(nid);
	if (!lp)
		goto out;
	lpn = lnet_peer_net_alloc(LNET_NIDNET(nid));
	if (!lpn)
		goto out_free_lp;
	lpni = lnet_peer_ni_alloc(nid);
	if (!lpni)
		goto out_free_lpn;

	return lnet_peer_attach_peer_ni(lp, lpn, lpni, flags);

out_free_lpn:
	LIBCFS_FREE(lpn, sizeof(*lpn));
out_free_lp:
	LIBCFS_FREE(lp, sizeof(*lp));
out:
	CDEBUG(D_NET, "peer %s NID flags %#x: %d\n",
	       libcfs_nid2str(nid), flags, rc);
	return rc;
}

/*
 * Add a NID to a peer. Call with ln_api_mutex held.
 *
 * Error codes:
 *  -EPERM:    Non-DLC addition to a DLC-configured peer.
 *  -EEXIST:   The NID was configured by DLC for a different peer.
 *  -ENOMEM:   Out of memory.
 *  -ENOTUNIQ: Adding a second peer NID on a single network on a
 *             non-multi-rail peer.
 */
static int
lnet_peer_add_nid(struct lnet_peer *lp, lnet_nid_t nid, unsigned flags)
{
	struct lnet_peer_net *lpn;
	struct lnet_peer_ni *lpni;
	int rc = 0;

	LASSERT(lp);
	LASSERT(nid != LNET_NID_ANY);

	/* A configured peer can only be updated through configuration. */
	if (!(flags & LNET_PEER_CONFIGURED)) {
		if (lp->lp_state & LNET_PEER_CONFIGURED) {
			rc = -EPERM;
			goto out;
		}
	}

	/*
	 * The MULTI_RAIL flag can be set but not cleared, because
	 * that would leave the peer struct in an invalid state.
	 */
	if (flags & LNET_PEER_MULTI_RAIL) {
		spin_lock(&lp->lp_lock);
		if (!(lp->lp_state & LNET_PEER_MULTI_RAIL)) {
			lp->lp_state |= LNET_PEER_MULTI_RAIL;
			lnet_peer_clr_non_mr_pref_nids(lp);
		}
		spin_unlock(&lp->lp_lock);
	} else if (lp->lp_state & LNET_PEER_MULTI_RAIL) {
		rc = -EPERM;
		goto out;
	}

	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni) {
		/*
		 * A peer_ni already exists. This is only a problem if
		 * it is not connected to this peer and was configured
		 * by DLC.
		 */
		if (lpni->lpni_peer_net->lpn_peer == lp)
			goto out_free_lpni;
		if (lnet_peer_ni_is_configured(lpni)) {
			rc = -EEXIST;
			goto out_free_lpni;
		}
		/* If this is the primary NID, destroy the peer. */
		if (lnet_peer_ni_is_primary(lpni)) {
			struct lnet_peer *rtr_lp =
				lpni->lpni_peer_net->lpn_peer;
			int rtr_refcount = rtr_lp->lp_rtr_refcount;
			/*
			 * if we're trying to delete a router it means
			 * we're moving this peer NI to a new peer so must
			 * transfer router properties to the new peer
			 */
			if (rtr_refcount > 0) {
				flags |= LNET_PEER_RTR_NI_FORCE_DEL;
				lnet_rtr_transfer_to_peer(rtr_lp, lp);
			}
			lnet_peer_del(lpni->lpni_peer_net->lpn_peer);
			lnet_peer_ni_decref_locked(lpni);
			lpni = lnet_peer_ni_alloc(nid);
			if (!lpni) {
				rc = -ENOMEM;
				goto out_free_lpni;
			}
		}
	} else {
		lpni = lnet_peer_ni_alloc(nid);
		if (!lpni) {
			rc = -ENOMEM;
			goto out_free_lpni;
		}
	}

	/*
	 * Get the peer_net. Check that we're not adding a second
	 * peer_ni on a peer_net of a non-multi-rail peer.
	 */
	lpn = lnet_peer_get_net_locked(lp, LNET_NIDNET(nid));
	if (!lpn) {
		lpn = lnet_peer_net_alloc(LNET_NIDNET(nid));
		if (!lpn) {
			rc = -ENOMEM;
			goto out_free_lpni;
		}
	} else if (!(lp->lp_state & LNET_PEER_MULTI_RAIL)) {
		rc = -ENOTUNIQ;
		goto out_free_lpni;
	}

	return lnet_peer_attach_peer_ni(lp, lpn, lpni, flags);

out_free_lpni:
	lnet_peer_ni_decref_locked(lpni);
out:
	CDEBUG(D_NET, "peer %s NID %s flags %#x: %d\n",
	       libcfs_nid2str(lp->lp_primary_nid), libcfs_nid2str(nid),
	       flags, rc);
	return rc;
}

/*
 * Update the primary NID of a peer, if possible.
 *
 * Call with the lnet_api_mutex held.
 */
static int
lnet_peer_set_primary_nid(struct lnet_peer *lp, lnet_nid_t nid, unsigned flags)
{
	lnet_nid_t old = lp->lp_primary_nid;
	int rc = 0;

	if (lp->lp_primary_nid == nid)
		goto out;

	lp->lp_primary_nid = nid;

	rc = lnet_peer_add_nid(lp, nid, flags);
	if (rc) {
		lp->lp_primary_nid = old;
		goto out;
	}
out:
	CDEBUG(D_NET, "peer %s NID %s: %d\n",
	       libcfs_nid2str(old), libcfs_nid2str(nid), rc);
	return rc;
}

/*
 * lpni creation initiated due to traffic either sending or receiving.
 */
static int
lnet_peer_ni_traffic_add(lnet_nid_t nid, lnet_nid_t pref)
{
	struct lnet_peer *lp;
	struct lnet_peer_net *lpn;
	struct lnet_peer_ni *lpni;
	unsigned flags = 0;
	int rc = 0;

	if (nid == LNET_NID_ANY) {
		rc = -EINVAL;
		goto out;
	}

	/* lnet_net_lock is not needed here because ln_api_lock is held */
	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni) {
		/*
		 * We must have raced with another thread. Since we
		 * know next to nothing about a peer_ni created by
		 * traffic, we just assume everything is ok and
		 * return.
		 */
		lnet_peer_ni_decref_locked(lpni);
		goto out;
	}

	/* Create peer, peer_net, and peer_ni. */
	rc = -ENOMEM;
	lp = lnet_peer_alloc(nid);
	if (!lp)
		goto out;
	lpn = lnet_peer_net_alloc(LNET_NIDNET(nid));
	if (!lpn)
		goto out_free_lp;
	lpni = lnet_peer_ni_alloc(nid);
	if (!lpni)
		goto out_free_lpn;
	if (pref != LNET_NID_ANY)
		lnet_peer_ni_set_non_mr_pref_nid(lpni, pref);

	return lnet_peer_attach_peer_ni(lp, lpn, lpni, flags);

out_free_lpn:
	LIBCFS_FREE(lpn, sizeof(*lpn));
out_free_lp:
	LIBCFS_FREE(lp, sizeof(*lp));
out:
	CDEBUG(D_NET, "peer %s: %d\n", libcfs_nid2str(nid), rc);
	return rc;
}

/*
 * Implementation of IOC_LIBCFS_ADD_PEER_NI.
 *
 * This API handles the following combinations:
 *   Create a peer with its primary NI if only the prim_nid is provided
 *   Add a NID to a peer identified by the prim_nid. The peer identified
 *   by the prim_nid must already exist.
 *   The peer being created may be non-MR.
 *
 * The caller must hold ln_api_mutex. This prevents the peer from
 * being created/modified/deleted by a different thread.
 */
int
lnet_add_peer_ni(lnet_nid_t prim_nid, lnet_nid_t nid, bool mr)
{
	struct lnet_peer *lp = NULL;
	struct lnet_peer_ni *lpni;
	unsigned flags;

	/* The prim_nid must always be specified */
	if (prim_nid == LNET_NID_ANY)
		return -EINVAL;

	flags = LNET_PEER_CONFIGURED;
	if (mr)
		flags |= LNET_PEER_MULTI_RAIL;

	/*
	 * If nid isn't specified, we must create a new peer with
	 * prim_nid as its primary nid.
	 */
	if (nid == LNET_NID_ANY)
		return lnet_peer_add(prim_nid, flags);

	/* Look up the prim_nid, which must exist. */
	lpni = lnet_find_peer_ni_locked(prim_nid);
	if (!lpni)
		return -ENOENT;
	lnet_peer_ni_decref_locked(lpni);
	lp = lpni->lpni_peer_net->lpn_peer;

	/* Peer must have been configured. */
	if (!(lp->lp_state & LNET_PEER_CONFIGURED)) {
		CDEBUG(D_NET, "peer %s was not configured\n",
		       libcfs_nid2str(prim_nid));
		return -ENOENT;
	}

	/* Primary NID must match */
	if (lp->lp_primary_nid != prim_nid) {
		CDEBUG(D_NET, "prim_nid %s is not primary for peer %s\n",
		       libcfs_nid2str(prim_nid),
		       libcfs_nid2str(lp->lp_primary_nid));
		return -ENODEV;
	}

	/* Multi-Rail flag must match. */
	if ((lp->lp_state ^ flags) & LNET_PEER_MULTI_RAIL) {
		CDEBUG(D_NET, "multi-rail state mismatch for peer %s\n",
		       libcfs_nid2str(prim_nid));
		return -EPERM;
	}

	return lnet_peer_add_nid(lp, nid, flags);
}

/*
 * Implementation of IOC_LIBCFS_DEL_PEER_NI.
 *
 * This API handles the following combinations:
 *   Delete a NI from a peer if both prim_nid and nid are provided.
 *   Delete a peer if only prim_nid is provided.
 *   Delete a peer if its primary nid is provided.
 *
 * The caller must hold ln_api_mutex. This prevents the peer from
 * being modified/deleted by a different thread.
 */
int
lnet_del_peer_ni(lnet_nid_t prim_nid, lnet_nid_t nid)
{
	struct lnet_peer *lp;
	struct lnet_peer_ni *lpni;
	unsigned flags;

	if (prim_nid == LNET_NID_ANY)
		return -EINVAL;

	lpni = lnet_find_peer_ni_locked(prim_nid);
	if (!lpni)
		return -ENOENT;
	lnet_peer_ni_decref_locked(lpni);
	lp = lpni->lpni_peer_net->lpn_peer;

	if (prim_nid != lp->lp_primary_nid) {
		CDEBUG(D_NET, "prim_nid %s is not primary for peer %s\n",
		       libcfs_nid2str(prim_nid),
		       libcfs_nid2str(lp->lp_primary_nid));
		return -ENODEV;
	}

	lnet_net_lock(LNET_LOCK_EX);
	if (lp->lp_rtr_refcount > 0) {
		lnet_net_unlock(LNET_LOCK_EX);
		CERROR("%s is a router. Can not be deleted\n",
		       libcfs_nid2str(prim_nid));
		return -EBUSY;
	}
	lnet_net_unlock(LNET_LOCK_EX);

	if (nid == LNET_NID_ANY || nid == lp->lp_primary_nid)
		return lnet_peer_del(lp);

	flags = LNET_PEER_CONFIGURED;
	if (lp->lp_state & LNET_PEER_MULTI_RAIL)
		flags |= LNET_PEER_MULTI_RAIL;

	return lnet_peer_del_nid(lp, nid, flags);
}

void
lnet_destroy_peer_ni_locked(struct kref *ref)
{
	struct lnet_peer_ni *lpni = container_of(ref, struct lnet_peer_ni,
						 lpni_kref);
	struct lnet_peer_table *ptable;
	struct lnet_peer_net *lpn;

	CDEBUG(D_NET, "%p nid %s\n", lpni, libcfs_nid2str(lpni->lpni_nid));

	LASSERT(kref_read(&lpni->lpni_kref) == 0);
	LASSERT(list_empty(&lpni->lpni_txq));
	LASSERT(lpni->lpni_txqnob == 0);
	LASSERT(list_empty(&lpni->lpni_peer_nis));
	LASSERT(list_empty(&lpni->lpni_on_remote_peer_ni_list));

	lpn = lpni->lpni_peer_net;
	lpni->lpni_peer_net = NULL;
	lpni->lpni_net = NULL;

	if (!list_empty(&lpni->lpni_hashlist)) {
		/* remove the peer ni from the zombie list */
		ptable = the_lnet.ln_peer_tables[lpni->lpni_cpt];
		spin_lock(&ptable->pt_zombie_lock);
		list_del_init(&lpni->lpni_hashlist);
		ptable->pt_zombies--;
		spin_unlock(&ptable->pt_zombie_lock);
	}

	if (lpni->lpni_pref_nnids > 1) {
		struct lnet_nid_list *ne, *tmp;

		list_for_each_entry_safe(ne, tmp, &lpni->lpni_pref.nids,
					 nl_list) {
			list_del_init(&ne->nl_list);
			LIBCFS_FREE(ne, sizeof(*ne));
		}
	}
	LIBCFS_FREE(lpni, sizeof(*lpni));

	if (lpn)
		lnet_peer_net_decref_locked(lpn);
}

struct lnet_peer_ni *
lnet_nid2peerni_ex(lnet_nid_t nid, int cpt)
{
	struct lnet_peer_ni *lpni = NULL;
	int rc;

	if (the_lnet.ln_state != LNET_STATE_RUNNING)
		return ERR_PTR(-ESHUTDOWN);

	/*
	 * find if a peer_ni already exists.
	 * If so then just return that.
	 */
	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni)
		return lpni;

	lnet_net_unlock(cpt);

	rc = lnet_peer_ni_traffic_add(nid, LNET_NID_ANY);
	if (rc) {
		lpni = ERR_PTR(rc);
		goto out_net_relock;
	}

	lpni = lnet_find_peer_ni_locked(nid);
	LASSERT(lpni);

out_net_relock:
	lnet_net_lock(cpt);

	return lpni;
}

/*
 * Get a peer_ni for the given nid, create it if necessary. Takes a
 * hold on the peer_ni.
 */
struct lnet_peer_ni *
lnet_nid2peerni_locked(lnet_nid_t nid, lnet_nid_t pref, int cpt)
{
	struct lnet_peer_ni *lpni = NULL;
	int rc;

	if (the_lnet.ln_state != LNET_STATE_RUNNING)
		return ERR_PTR(-ESHUTDOWN);

	/*
	 * find if a peer_ni already exists.
	 * If so then just return that.
	 */
	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni)
		return lpni;

	/*
	 * Slow path:
	 * use the lnet_api_mutex to serialize the creation of the peer_ni
	 * and the creation/deletion of the local ni/net. When a local ni is
	 * created, if there exists a set of peer_nis on that network,
	 * they need to be traversed and updated. When a local NI is
	 * deleted, which could result in a network being deleted, then
	 * all peer nis on that network need to be removed as well.
	 *
	 * Creation through traffic should also be serialized with
	 * creation through DLC.
	 */
	lnet_net_unlock(cpt);
	mutex_lock(&the_lnet.ln_api_mutex);
	/*
	 * Shutdown is only set under the ln_api_lock, so a single
	 * check here is sufficent.
	 */
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		lpni = ERR_PTR(-ESHUTDOWN);
		goto out_mutex_unlock;
	}

	rc = lnet_peer_ni_traffic_add(nid, pref);
	if (rc) {
		lpni = ERR_PTR(rc);
		goto out_mutex_unlock;
	}

	lpni = lnet_find_peer_ni_locked(nid);
	LASSERT(lpni);

out_mutex_unlock:
	mutex_unlock(&the_lnet.ln_api_mutex);
	lnet_net_lock(cpt);

	/* Lock has been dropped, check again for shutdown. */
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		if (!IS_ERR(lpni))
			lnet_peer_ni_decref_locked(lpni);
		lpni = ERR_PTR(-ESHUTDOWN);
	}

	return lpni;
}

bool
lnet_peer_gw_discovery(struct lnet_peer *lp)
{
	bool rc = false;

	spin_lock(&lp->lp_lock);
	if (lp->lp_state & LNET_PEER_RTR_DISCOVERY)
		rc = true;
	spin_unlock(&lp->lp_lock);

	return rc;
}

bool
lnet_peer_is_uptodate(struct lnet_peer *lp)
{
	bool rc;

	spin_lock(&lp->lp_lock);
	rc = lnet_peer_is_uptodate_locked(lp);
	spin_unlock(&lp->lp_lock);
	return rc;
}

/*
 * Is a peer uptodate from the point of view of discovery?
 *
 * If it is currently being processed, obviously not.
 * A forced Ping or Push is also handled by the discovery thread.
 *
 * Otherwise look at whether the peer needs rediscovering.
 */
bool
lnet_peer_is_uptodate_locked(struct lnet_peer *lp)
__must_hold(&lp->lp_lock)
{
	bool rc;

	if (lp->lp_state & (LNET_PEER_DISCOVERING |
			    LNET_PEER_FORCE_PING |
			    LNET_PEER_FORCE_PUSH)) {
		rc = false;
	} else if (lp->lp_state & LNET_PEER_REDISCOVER) {
		rc = false;
	} else if (lnet_peer_needs_push(lp)) {
		rc = false;
	} else if (lp->lp_state & LNET_PEER_DISCOVERED) {
		if (lp->lp_state & LNET_PEER_NIDS_UPTODATE)
			rc = true;
		else
			rc = false;
	} else {
		rc = false;
	}

	return rc;
}

/* Add the message to the peer's lp_dc_pendq and queue the peer for discovery */
void
lnet_peer_queue_message(struct lnet_peer *lp, struct lnet_msg *msg)
{
	/* The discovery thread holds net_lock/EX and lp_lock when it splices
	 * the lp_dc_pendq onto a local list for resending. Thus, we do the same
	 * when adding to the list and queuing the peer to ensure that we do not
	 * strand any messages on the lp_dc_pendq. This scheme ensures the
	 * message will be resent even if the peer is already being discovered.
	 * Therefore we needn't check the return value of
	 * lnet_peer_queue_for_discovery(lp).
	 */
	lnet_net_lock(LNET_LOCK_EX);
	spin_lock(&lp->lp_lock);
	list_add_tail(&msg->msg_list, &lp->lp_dc_pendq);
	spin_unlock(&lp->lp_lock);
	lnet_peer_queue_for_discovery(lp);
	lnet_net_unlock(LNET_LOCK_EX);
}

/*
 * Queue a peer for the attention of the discovery thread.  Call with
 * lnet_net_lock/EX held. Returns 0 if the peer was queued, and
 * -EALREADY if the peer was already queued.
 */
static int lnet_peer_queue_for_discovery(struct lnet_peer *lp)
{
	int rc;

	spin_lock(&lp->lp_lock);
	if (!(lp->lp_state & LNET_PEER_DISCOVERING))
		lp->lp_state |= LNET_PEER_DISCOVERING;
	spin_unlock(&lp->lp_lock);
	if (list_empty(&lp->lp_dc_list)) {
		lnet_peer_addref_locked(lp);
		list_add_tail(&lp->lp_dc_list, &the_lnet.ln_dc_request);
		wake_up(&the_lnet.ln_dc_waitq);
		rc = 0;
	} else {
		rc = -EALREADY;
	}

	CDEBUG(D_NET, "Queue peer %s: %d\n",
	       libcfs_nid2str(lp->lp_primary_nid), rc);

	return rc;
}

/*
 * Discovery of a peer is complete. Wake all waiters on the peer.
 * Call with lnet_net_lock/EX held.
 */
static void lnet_peer_discovery_complete(struct lnet_peer *lp)
{
	struct lnet_msg *msg, *tmp;
	int rc = 0;
	LIST_HEAD(pending_msgs);

	CDEBUG(D_NET, "Discovery complete. Dequeue peer %s\n",
	       libcfs_nid2str(lp->lp_primary_nid));

	list_del_init(&lp->lp_dc_list);
	spin_lock(&lp->lp_lock);
	list_splice_init(&lp->lp_dc_pendq, &pending_msgs);
	spin_unlock(&lp->lp_lock);
	wake_up(&lp->lp_dc_waitq);

	if (lp->lp_rtr_refcount > 0)
		lnet_router_discovery_complete(lp);

	lnet_net_unlock(LNET_LOCK_EX);

	/* iterate through all pending messages and send them again */
	list_for_each_entry_safe(msg, tmp, &pending_msgs, msg_list) {
		list_del_init(&msg->msg_list);
		if (lp->lp_dc_error) {
			lnet_finalize(msg, lp->lp_dc_error);
			continue;
		}

		CDEBUG(D_NET, "sending pending message %s to target %s\n",
		       lnet_msgtyp2str(msg->msg_type),
		       libcfs_id2str(msg->msg_target));
		rc = lnet_send(msg->msg_src_nid_param, msg,
			       msg->msg_rtr_nid_param);
		if (rc < 0) {
			CNETERR("Error sending %s to %s: %d\n",
			       lnet_msgtyp2str(msg->msg_type),
			       libcfs_id2str(msg->msg_target), rc);
			lnet_finalize(msg, rc);
		}
	}
	lnet_net_lock(LNET_LOCK_EX);
	lnet_peer_decref_locked(lp);
}

/*
 * Handle inbound push.
 * Like any event handler, called with lnet_res_lock/CPT held.
 */
void lnet_peer_push_event(struct lnet_event *ev)
{
	struct lnet_ping_buffer *pbuf;
	struct lnet_peer *lp;

	pbuf = LNET_PING_INFO_TO_BUFFER(ev->md_start + ev->offset);

	/* lnet_find_peer() adds a refcount */
	lp = lnet_find_peer(ev->source.nid);
	if (!lp) {
		CDEBUG(D_NET, "Push Put from unknown %s (source %s). Ignoring...\n",
		       libcfs_nid2str(ev->initiator.nid),
		       libcfs_nid2str(ev->source.nid));
		pbuf->pb_needs_post = true;
		return;
	}

	/* Ensure peer state remains consistent while we modify it. */
	spin_lock(&lp->lp_lock);

	/*
	 * If some kind of error happened the contents of the message
	 * cannot be used. Clear the NIDS_UPTODATE and set the
	 * FORCE_PING flag to trigger a ping.
	 */
	if (ev->status) {
		lp->lp_state &= ~LNET_PEER_NIDS_UPTODATE;
		lp->lp_state |= LNET_PEER_FORCE_PING;
		CDEBUG(D_NET, "Push Put error %d from %s (source %s)\n",
		       ev->status,
		       libcfs_nid2str(lp->lp_primary_nid),
		       libcfs_nid2str(ev->source.nid));
		goto out;
	}

	/*
	 * A push with invalid or corrupted info. Clear the UPTODATE
	 * flag to trigger a ping.
	 */
	if (lnet_ping_info_validate(&pbuf->pb_info)) {
		lp->lp_state &= ~LNET_PEER_NIDS_UPTODATE;
		lp->lp_state |= LNET_PEER_FORCE_PING;
		CDEBUG(D_NET, "Corrupted Push from %s\n",
		       libcfs_nid2str(lp->lp_primary_nid));
		goto out;
	}

	/*
	 * Make sure we'll allocate the correct size ping buffer when
	 * pinging the peer.
	 */
	if (lp->lp_data_nnis < pbuf->pb_info.pi_nnis)
		lp->lp_data_nnis = pbuf->pb_info.pi_nnis;

	/*
	 * A non-Multi-Rail peer is not supposed to be capable of
	 * sending a push.
	 */
	if (!(pbuf->pb_info.pi_features & LNET_PING_FEAT_MULTI_RAIL)) {
		CERROR("Push from non-Multi-Rail peer %s dropped\n",
		       libcfs_nid2str(lp->lp_primary_nid));
		goto out;
	}

	/*
	 * The peer may have discovery disabled at its end. Set
	 * NO_DISCOVERY as appropriate.
	 */
	if (!(pbuf->pb_info.pi_features & LNET_PING_FEAT_DISCOVERY)) {
		CDEBUG(D_NET, "Peer %s has discovery disabled\n",
		       libcfs_nid2str(lp->lp_primary_nid));
		/*
		 * Mark the peer for deletion if we already know about it
		 * and it's going from discovery set to no discovery set
		 */
		if (!(lp->lp_state & (LNET_PEER_NO_DISCOVERY |
				      LNET_PEER_DISCOVERING)) &&
		     lp->lp_state & LNET_PEER_DISCOVERED) {
			CDEBUG(D_NET, "Marking %s:0x%x for deletion\n",
			       libcfs_nid2str(lp->lp_primary_nid),
			       lp->lp_state);
			lp->lp_state |= LNET_PEER_MARK_DELETION;
		}
		lp->lp_state |= LNET_PEER_NO_DISCOVERY;
	} else if (lp->lp_state & LNET_PEER_NO_DISCOVERY) {
		CDEBUG(D_NET, "Peer %s has discovery enabled\n",
		       libcfs_nid2str(lp->lp_primary_nid));
		lp->lp_state &= ~LNET_PEER_NO_DISCOVERY;
	}

	/*
	 * Update the MULTI_RAIL flag based on the push. If the peer
	 * was configured with DLC then the setting should match what
	 * DLC put in.
	 * NB: We verified above that the MR feature bit is set in pi_features
	 */
	if (lp->lp_state & LNET_PEER_MULTI_RAIL) {
		CDEBUG(D_NET, "peer %s(%p) is MR\n",
		       libcfs_nid2str(lp->lp_primary_nid), lp);
	} else if (lp->lp_state & LNET_PEER_CONFIGURED) {
		CWARN("Push says %s is Multi-Rail, DLC says not\n",
		      libcfs_nid2str(lp->lp_primary_nid));
	} else if (lnet_peer_discovery_disabled) {
		CDEBUG(D_NET, "peer %s(%p) not MR: DD disabled locally\n",
		       libcfs_nid2str(lp->lp_primary_nid), lp);
	} else if (lp->lp_state & LNET_PEER_NO_DISCOVERY) {
		CDEBUG(D_NET, "peer %s(%p) not MR: DD disabled remotely\n",
		       libcfs_nid2str(lp->lp_primary_nid), lp);
	} else {
		CDEBUG(D_NET, "peer %s(%p) is MR capable\n",
		       libcfs_nid2str(lp->lp_primary_nid), lp);
		lp->lp_state |= LNET_PEER_MULTI_RAIL;
		lnet_peer_clr_non_mr_pref_nids(lp);
	}

	/*
	 * Check for truncation of the Put message. Clear the
	 * NIDS_UPTODATE flag and set FORCE_PING to trigger a ping,
	 * and tell discovery to allocate a bigger buffer.
	 */
	if (ev->mlength < ev->rlength) {
		if (the_lnet.ln_push_target_nnis < pbuf->pb_info.pi_nnis)
			the_lnet.ln_push_target_nnis = pbuf->pb_info.pi_nnis;
		lp->lp_state &= ~LNET_PEER_NIDS_UPTODATE;
		lp->lp_state |= LNET_PEER_FORCE_PING;
		CDEBUG(D_NET, "Truncated Push from %s (%d nids)\n",
		       libcfs_nid2str(lp->lp_primary_nid),
		       pbuf->pb_info.pi_nnis);
		goto out;
	}

	/* always assume new data */
	lp->lp_peer_seqno = LNET_PING_BUFFER_SEQNO(pbuf);
	lp->lp_state &= ~LNET_PEER_NIDS_UPTODATE;

	/*
	 * If there is data present that hasn't been processed yet,
	 * we'll replace it if the Put contained newer data and it
	 * fits. We're racing with a Ping or earlier Push in this
	 * case.
	 */
	if (lp->lp_state & LNET_PEER_DATA_PRESENT) {
		if (LNET_PING_BUFFER_SEQNO(pbuf) >
			LNET_PING_BUFFER_SEQNO(lp->lp_data) &&
		    pbuf->pb_info.pi_nnis <= lp->lp_data->pb_nnis) {
			memcpy(&lp->lp_data->pb_info, &pbuf->pb_info,
			       LNET_PING_INFO_SIZE(pbuf->pb_info.pi_nnis));
			CDEBUG(D_NET, "Ping/Push race from %s: %u vs %u\n",
			      libcfs_nid2str(lp->lp_primary_nid),
			      LNET_PING_BUFFER_SEQNO(pbuf),
			      LNET_PING_BUFFER_SEQNO(lp->lp_data));
		}
		goto out;
	}

	/*
	 * Allocate a buffer to copy the data. On a failure we drop
	 * the Push and set FORCE_PING to force the discovery
	 * thread to fix the problem by pinging the peer.
	 */
	lp->lp_data = lnet_ping_buffer_alloc(lp->lp_data_nnis, GFP_ATOMIC);
	if (!lp->lp_data) {
		lp->lp_state |= LNET_PEER_FORCE_PING;
		CDEBUG(D_NET, "Cannot allocate Push buffer for %s %u\n",
		       libcfs_nid2str(lp->lp_primary_nid),
		       LNET_PING_BUFFER_SEQNO(pbuf));
		goto out;
	}

	/* Success */
	memcpy(&lp->lp_data->pb_info, &pbuf->pb_info,
	       LNET_PING_INFO_SIZE(pbuf->pb_info.pi_nnis));
	lp->lp_state |= LNET_PEER_DATA_PRESENT;
	CDEBUG(D_NET, "Received Push %s %u\n",
	       libcfs_nid2str(lp->lp_primary_nid),
	       LNET_PING_BUFFER_SEQNO(pbuf));

out:
	/* We've processed this buffer. It can be reposted */
	pbuf->pb_needs_post = true;

	/*
	 * Queue the peer for discovery if not done, force it on the request
	 * queue and wake the discovery thread if the peer was already queued,
	 * because its status changed.
	 */
	spin_unlock(&lp->lp_lock);
	lnet_net_lock(LNET_LOCK_EX);
	if (!lnet_peer_is_uptodate(lp) && lnet_peer_queue_for_discovery(lp)) {
		list_move(&lp->lp_dc_list, &the_lnet.ln_dc_request);
		wake_up(&the_lnet.ln_dc_waitq);
	}
	/* Drop refcount from lookup */
	lnet_peer_decref_locked(lp);
	lnet_net_unlock(LNET_LOCK_EX);
}

/*
 * Clear the discovery error state, unless we're already discovering
 * this peer, in which case the error is current.
 */
static void lnet_peer_clear_discovery_error(struct lnet_peer *lp)
{
	spin_lock(&lp->lp_lock);
	if (!(lp->lp_state & LNET_PEER_DISCOVERING))
		lp->lp_dc_error = 0;
	spin_unlock(&lp->lp_lock);
}

/*
 * Peer discovery slow path. The ln_api_mutex is held on entry, and
 * dropped/retaken within this function. An lnet_peer_ni is passed in
 * because discovery could tear down an lnet_peer.
 */
int
lnet_discover_peer_locked(struct lnet_peer_ni *lpni, int cpt, bool block)
{
	DEFINE_WAIT(wait);
	struct lnet_peer *lp;
	int rc = 0;
	int count = 0;

again:
	lnet_net_unlock(cpt);
	lnet_net_lock(LNET_LOCK_EX);
	lp = lpni->lpni_peer_net->lpn_peer;
	lnet_peer_clear_discovery_error(lp);

	/*
	 * We're willing to be interrupted. The lpni can become a
	 * zombie if we race with DLC, so we must check for that.
	 */
	for (;;) {
		/* Keep lp alive when the lnet_net_lock is unlocked */
		lnet_peer_addref_locked(lp);
		prepare_to_wait(&lp->lp_dc_waitq, &wait, TASK_INTERRUPTIBLE);
		if (signal_pending(current))
			break;
		if (the_lnet.ln_dc_state != LNET_DC_STATE_RUNNING)
			break;
		/*
		 * Don't repeat discovery if discovery is disabled. This is
		 * done to ensure we can use discovery as a standard ping as
		 * well for backwards compatibility with routers which do not
		 * have discovery or have discovery disabled
		 */
		if (lnet_is_discovery_disabled(lp) && count > 0)
			break;
		if (lp->lp_dc_error)
			break;
		if (lnet_peer_is_uptodate(lp))
			break;
		lnet_peer_queue_for_discovery(lp);
		count++;
		CDEBUG(D_NET, "Discovery attempt # %d\n", count);

		/*
		 * If caller requested a non-blocking operation then
		 * return immediately. Once discovery is complete any
		 * pending messages that were stopped due to discovery
		 * will be transmitted.
		 */
		if (!block)
			break;

		lnet_net_unlock(LNET_LOCK_EX);
		schedule();
		finish_wait(&lp->lp_dc_waitq, &wait);
		lnet_net_lock(LNET_LOCK_EX);
		lnet_peer_decref_locked(lp);
		/* Peer may have changed */
		lp = lpni->lpni_peer_net->lpn_peer;
	}
	finish_wait(&lp->lp_dc_waitq, &wait);

	lnet_net_unlock(LNET_LOCK_EX);
	lnet_net_lock(cpt);
	lnet_peer_decref_locked(lp);
	/*
	 * The peer may have changed, so re-check and rediscover if that turns
	 * out to have been the case. The reference count on lp ensured that
	 * even if it was unlinked from lpni the memory could not be recycled.
	 * Thus the check below is sufficient to determine whether the peer
	 * changed. If the peer changed, then lp must not be dereferenced.
	 */
	if (lp != lpni->lpni_peer_net->lpn_peer)
		goto again;

	if (signal_pending(current))
		rc = -EINTR;
	else if (the_lnet.ln_dc_state != LNET_DC_STATE_RUNNING)
		rc = -ESHUTDOWN;
	else if (lp->lp_dc_error)
		rc = lp->lp_dc_error;
	else if (!block)
		CDEBUG(D_NET, "non-blocking discovery\n");
	else if (!lnet_peer_is_uptodate(lp) && !lnet_is_discovery_disabled(lp))
		goto again;

	CDEBUG(D_NET, "peer %s NID %s: %d. %s\n",
	       (lp ? libcfs_nid2str(lp->lp_primary_nid) : "(none)"),
	       libcfs_nid2str(lpni->lpni_nid), rc,
	       (!block) ? "pending discovery" : "discovery complete");

	return rc;
}

/* Handle an incoming ack for a push. */
static void
lnet_discovery_event_ack(struct lnet_peer *lp, struct lnet_event *ev)
{
	struct lnet_ping_buffer *pbuf;

	pbuf = LNET_PING_INFO_TO_BUFFER(ev->md_start);
	spin_lock(&lp->lp_lock);
	lp->lp_state &= ~LNET_PEER_PUSH_SENT;
	lp->lp_push_error = ev->status;
	if (ev->status)
		lp->lp_state |= LNET_PEER_PUSH_FAILED;
	else
		lp->lp_node_seqno = LNET_PING_BUFFER_SEQNO(pbuf);
	spin_unlock(&lp->lp_lock);

	CDEBUG(D_NET, "peer %s ev->status %d\n",
	       libcfs_nid2str(lp->lp_primary_nid), ev->status);
}

/* Handle a Reply message. This is the reply to a Ping message. */
static void
lnet_discovery_event_reply(struct lnet_peer *lp, struct lnet_event *ev)
{
	struct lnet_ping_buffer *pbuf;
	int rc;

	spin_lock(&lp->lp_lock);

	lp->lp_disc_src_nid = ev->target.nid;

	/*
	 * If some kind of error happened the contents of message
	 * cannot be used. Set PING_FAILED to trigger a retry.
	 */
	if (ev->status) {
		lp->lp_state |= LNET_PEER_PING_FAILED;
		lp->lp_ping_error = ev->status;
		CDEBUG(D_NET, "Ping Reply error %d from %s (source %s)\n",
		       ev->status,
		       libcfs_nid2str(lp->lp_primary_nid),
		       libcfs_nid2str(ev->source.nid));
		goto out;
	}

	pbuf = LNET_PING_INFO_TO_BUFFER(ev->md_start);
	if (pbuf->pb_info.pi_magic == __swab32(LNET_PROTO_PING_MAGIC))
		lnet_swap_pinginfo(pbuf);

	/*
	 * A reply with invalid or corrupted info. Set PING_FAILED to
	 * trigger a retry.
	 */
	rc = lnet_ping_info_validate(&pbuf->pb_info);
	if (rc) {
		lp->lp_state |= LNET_PEER_PING_FAILED;
		lp->lp_ping_error = 0;
		CDEBUG(D_NET, "Corrupted Ping Reply from %s: %d\n",
		       libcfs_nid2str(lp->lp_primary_nid), rc);
		goto out;
	}


	/*
	 * The peer may have discovery disabled at its end. Set
	 * NO_DISCOVERY as appropriate.
	 */
	if ((pbuf->pb_info.pi_features & LNET_PING_FEAT_DISCOVERY) &&
	    !lnet_peer_discovery_disabled) {
		CDEBUG(D_NET, "Peer %s has discovery enabled\n",
		       libcfs_nid2str(lp->lp_primary_nid));
		lp->lp_state &= ~LNET_PEER_NO_DISCOVERY;
	} else {
		CDEBUG(D_NET, "Peer %s has discovery disabled\n",
		       libcfs_nid2str(lp->lp_primary_nid));
		lp->lp_state |= LNET_PEER_NO_DISCOVERY;
	}

	/*
	 * Update the MULTI_RAIL flag based on the reply. If the peer
	 * was configured with DLC then the setting should match what
	 * DLC put in.
	 */
	if (pbuf->pb_info.pi_features & LNET_PING_FEAT_MULTI_RAIL) {
		if (lp->lp_state & LNET_PEER_MULTI_RAIL) {
			CDEBUG(D_NET, "peer %s(%p) is MR\n",
			       libcfs_nid2str(lp->lp_primary_nid), lp);
		} else if (lp->lp_state & LNET_PEER_CONFIGURED) {
			CWARN("Reply says %s is Multi-Rail, DLC says not\n",
			      libcfs_nid2str(lp->lp_primary_nid));
		} else if (lnet_peer_discovery_disabled) {
			CDEBUG(D_NET,
			       "peer %s(%p) not MR: DD disabled locally\n",
			       libcfs_nid2str(lp->lp_primary_nid), lp);
		} else if (lp->lp_state & LNET_PEER_NO_DISCOVERY) {
			CDEBUG(D_NET,
			       "peer %s(%p) not MR: DD disabled remotely\n",
			       libcfs_nid2str(lp->lp_primary_nid), lp);
		} else {
			CDEBUG(D_NET, "peer %s(%p) is MR capable\n",
			       libcfs_nid2str(lp->lp_primary_nid), lp);
			lp->lp_state |= LNET_PEER_MULTI_RAIL;
			lnet_peer_clr_non_mr_pref_nids(lp);
		}
	} else if (lp->lp_state & LNET_PEER_MULTI_RAIL) {
		if (lp->lp_state & LNET_PEER_CONFIGURED) {
			CWARN("DLC says %s is Multi-Rail, Reply says not\n",
			      libcfs_nid2str(lp->lp_primary_nid));
		} else {
			CERROR("Multi-Rail state vanished from %s\n",
			       libcfs_nid2str(lp->lp_primary_nid));
			lp->lp_state &= ~LNET_PEER_MULTI_RAIL;
		}
	}

	/*
	 * Make sure we'll allocate the correct size ping buffer when
	 * pinging the peer.
	 */
	if (lp->lp_data_nnis < pbuf->pb_info.pi_nnis)
		lp->lp_data_nnis = pbuf->pb_info.pi_nnis;

	/*
	 * Check for truncation of the Reply. Clear PING_SENT and set
	 * PING_FAILED to trigger a retry.
	 */
	if (pbuf->pb_nnis < pbuf->pb_info.pi_nnis) {
		if (the_lnet.ln_push_target_nnis < pbuf->pb_info.pi_nnis)
			the_lnet.ln_push_target_nnis = pbuf->pb_info.pi_nnis;
		lp->lp_state |= LNET_PEER_PING_FAILED;
		lp->lp_ping_error = 0;
		CDEBUG(D_NET, "Truncated Reply from %s (%d nids)\n",
		       libcfs_nid2str(lp->lp_primary_nid),
		       pbuf->pb_info.pi_nnis);
		goto out;
	}

	/*
	 * Check the sequence numbers in the reply. These are only
	 * available if the reply came from a Multi-Rail peer.
	 */
	if (pbuf->pb_info.pi_features & LNET_PING_FEAT_MULTI_RAIL &&
	    pbuf->pb_info.pi_nnis > 1 &&
	    lp->lp_primary_nid == pbuf->pb_info.pi_ni[1].ns_nid) {
		if (LNET_PING_BUFFER_SEQNO(pbuf) < lp->lp_peer_seqno)
			CDEBUG(D_NET, "peer %s: seq# got %u have %u. peer rebooted?\n",
				libcfs_nid2str(lp->lp_primary_nid),
				LNET_PING_BUFFER_SEQNO(pbuf),
				lp->lp_peer_seqno);

		lp->lp_peer_seqno = LNET_PING_BUFFER_SEQNO(pbuf);
	}

	/* We're happy with the state of the data in the buffer. */
	CDEBUG(D_NET, "peer %s data present %u. state = 0x%x\n",
	       libcfs_nid2str(lp->lp_primary_nid), lp->lp_peer_seqno, lp->lp_state);
	if (lp->lp_state & LNET_PEER_DATA_PRESENT)
		lnet_ping_buffer_decref(lp->lp_data);
	else
		lp->lp_state |= LNET_PEER_DATA_PRESENT;
	lnet_ping_buffer_addref(pbuf);
	lp->lp_data = pbuf;
out:
	lp->lp_state &= ~LNET_PEER_PING_SENT;
	spin_unlock(&lp->lp_lock);

	lnet_net_lock(LNET_LOCK_EX);
	/*
	 * If this peer is a gateway, call the routing callback to
	 * handle the ping reply
	 */
	if (lp->lp_rtr_refcount > 0)
		lnet_router_discovery_ping_reply(lp);
	lnet_net_unlock(LNET_LOCK_EX);
}

/*
 * Send event handling. Only matters for error cases, where we clean
 * up state on the peer and peer_ni that would otherwise be updated in
 * the REPLY event handler for a successful Ping, and the ACK event
 * handler for a successful Push.
 */
static int
lnet_discovery_event_send(struct lnet_peer *lp, struct lnet_event *ev)
{
	int rc = 0;

	if (!ev->status)
		goto out;

	spin_lock(&lp->lp_lock);
	if (ev->msg_type == LNET_MSG_GET) {
		lp->lp_state &= ~LNET_PEER_PING_SENT;
		lp->lp_state |= LNET_PEER_PING_FAILED;
		lp->lp_ping_error = ev->status;
	} else { /* ev->msg_type == LNET_MSG_PUT */
		lp->lp_state &= ~LNET_PEER_PUSH_SENT;
		lp->lp_state |= LNET_PEER_PUSH_FAILED;
		lp->lp_push_error = ev->status;
	}
	spin_unlock(&lp->lp_lock);
	rc = LNET_REDISCOVER_PEER;
out:
	CDEBUG(D_NET, "%s Send to %s: %d\n",
		(ev->msg_type == LNET_MSG_GET ? "Ping" : "Push"),
		libcfs_nid2str(ev->target.nid), rc);
	return rc;
}

/*
 * Unlink event handling. This event is only seen if a call to
 * LNetMDUnlink() caused the event to be unlinked. If this call was
 * made after the event was set up in LNetGet() or LNetPut() then we
 * assume the Ping or Push timed out.
 */
static void
lnet_discovery_event_unlink(struct lnet_peer *lp, struct lnet_event *ev)
{
	spin_lock(&lp->lp_lock);
	/* We've passed through LNetGet() */
	if (lp->lp_state & LNET_PEER_PING_SENT) {
		lp->lp_state &= ~LNET_PEER_PING_SENT;
		lp->lp_state |= LNET_PEER_PING_FAILED;
		lp->lp_ping_error = -ETIMEDOUT;
		CDEBUG(D_NET, "Ping Unlink for message to peer %s\n",
			libcfs_nid2str(lp->lp_primary_nid));
	}
	/* We've passed through LNetPut() */
	if (lp->lp_state & LNET_PEER_PUSH_SENT) {
		lp->lp_state &= ~LNET_PEER_PUSH_SENT;
		lp->lp_state |= LNET_PEER_PUSH_FAILED;
		lp->lp_push_error = -ETIMEDOUT;
		CDEBUG(D_NET, "Push Unlink for message to peer %s\n",
			libcfs_nid2str(lp->lp_primary_nid));
	}
	spin_unlock(&lp->lp_lock);
}

/*
 * Event handler for the discovery EQ.
 *
 * Called with lnet_res_lock(cpt) held. The cpt is the
 * lnet_cpt_of_cookie() of the md handle cookie.
 */
static void lnet_discovery_event_handler(struct lnet_event *event)
{
	struct lnet_peer *lp = event->md_user_ptr;
	struct lnet_ping_buffer *pbuf;
	int rc;

	/* discovery needs to take another look */
	rc = LNET_REDISCOVER_PEER;

	CDEBUG(D_NET, "Received event: %d\n", event->type);

	switch (event->type) {
	case LNET_EVENT_ACK:
		lnet_discovery_event_ack(lp, event);
		break;
	case LNET_EVENT_REPLY:
		lnet_discovery_event_reply(lp, event);
		break;
	case LNET_EVENT_SEND:
		/* Only send failure triggers a retry. */
		rc = lnet_discovery_event_send(lp, event);
		break;
	case LNET_EVENT_UNLINK:
		/* LNetMDUnlink() was called */
		lnet_discovery_event_unlink(lp, event);
		break;
	default:
		/* Invalid events. */
		LBUG();
	}
	lnet_net_lock(LNET_LOCK_EX);
	if (event->unlinked) {
		pbuf = LNET_PING_INFO_TO_BUFFER(event->md_start);
		lnet_ping_buffer_decref(pbuf);
		lnet_peer_decref_locked(lp);
	}

	/* put peer back at end of request queue, if discovery not already
	 * done */
	if (rc == LNET_REDISCOVER_PEER && !lnet_peer_is_uptodate(lp)) {
		list_move_tail(&lp->lp_dc_list, &the_lnet.ln_dc_request);
		wake_up(&the_lnet.ln_dc_waitq);
	}
	lnet_net_unlock(LNET_LOCK_EX);
}

/*
 * Build a peer from incoming data.
 *
 * The NIDs in the incoming data are supposed to be structured as follows:
 *  - loopback
 *  - primary NID
 *  - other NIDs in same net
 *  - NIDs in second net
 *  - NIDs in third net
 *  - ...
 * This due to the way the list of NIDs in the data is created.
 *
 * Note that this function will mark the peer uptodate unless an
 * ENOMEM is encontered. All other errors are due to a conflict
 * between the DLC configuration and what discovery sees. We treat DLC
 * as binding, and therefore set the NIDS_UPTODATE flag to prevent the
 * peer from becoming stuck in discovery.
 */
static int lnet_peer_merge_data(struct lnet_peer *lp,
				struct lnet_ping_buffer *pbuf)
{
	struct lnet_peer_net *lpn;
	struct lnet_peer_ni *lpni;
	lnet_nid_t *curnis = NULL;
	struct lnet_ni_status *addnis = NULL;
	lnet_nid_t *delnis = NULL;
	unsigned flags;
	int ncurnis;
	int naddnis;
	int ndelnis;
	int nnis = 0;
	int i;
	int j;
	int rc;

	flags = LNET_PEER_DISCOVERED;
	if (pbuf->pb_info.pi_features & LNET_PING_FEAT_MULTI_RAIL)
		flags |= LNET_PEER_MULTI_RAIL;

	/*
	 * Cache the routing feature for the peer; whether it is enabled
	 * for disabled as reported by the remote peer.
	 */
	spin_lock(&lp->lp_lock);
	if (!(pbuf->pb_info.pi_features & LNET_PING_FEAT_RTE_DISABLED))
		lp->lp_state |= LNET_PEER_ROUTER_ENABLED;
	else
		lp->lp_state &= ~LNET_PEER_ROUTER_ENABLED;
	spin_unlock(&lp->lp_lock);

	nnis = max_t(int, lp->lp_nnis, pbuf->pb_info.pi_nnis);
	CFS_ALLOC_PTR_ARRAY(curnis, nnis);
	CFS_ALLOC_PTR_ARRAY(addnis, nnis);
	CFS_ALLOC_PTR_ARRAY(delnis, nnis);
	if (!curnis || !addnis || !delnis) {
		rc = -ENOMEM;
		goto out;
	}
	ncurnis = 0;
	naddnis = 0;
	ndelnis = 0;

	/* Construct the list of NIDs present in peer. */
	lpni = NULL;
	while ((lpni = lnet_get_next_peer_ni_locked(lp, NULL, lpni)) != NULL)
		curnis[ncurnis++] = lpni->lpni_nid;

	/*
	 * Check for NIDs in pbuf not present in curnis[].
	 * The loop starts at 1 to skip the loopback NID.
	 */
	for (i = 1; i < pbuf->pb_info.pi_nnis; i++) {
		for (j = 0; j < ncurnis; j++)
			if (pbuf->pb_info.pi_ni[i].ns_nid == curnis[j])
				break;
		if (j == ncurnis)
			addnis[naddnis++] = pbuf->pb_info.pi_ni[i];
	}
	/*
	 * Check for NIDs in curnis[] not present in pbuf.
	 * The nested loop starts at 1 to skip the loopback NID.
	 *
	 * But never add the loopback NID to delnis[]: if it is
	 * present in curnis[] then this peer is for this node.
	 */
	for (i = 0; i < ncurnis; i++) {
		if (curnis[i] == LNET_NID_LO_0)
			continue;
		for (j = 1; j < pbuf->pb_info.pi_nnis; j++) {
			if (curnis[i] == pbuf->pb_info.pi_ni[j].ns_nid) {
				/*
				 * update the information we cache for the
				 * peer with the latest information we
				 * received
				 */
				lpni = lnet_find_peer_ni_locked(curnis[i]);
				if (lpni) {
					lpni->lpni_ns_status = pbuf->pb_info.pi_ni[j].ns_status;
					lnet_peer_ni_decref_locked(lpni);
				}
				break;
			}
		}
		if (j == pbuf->pb_info.pi_nnis)
			delnis[ndelnis++] = curnis[i];
	}

	/*
	 * If we get here and the discovery is disabled then we don't want
	 * to add or delete any NIs. We just updated the ones we have some
	 * information on, and call it a day
	 */
	rc = 0;
	if (lnet_is_discovery_disabled(lp))
		goto out;

	for (i = 0; i < naddnis; i++) {
		rc = lnet_peer_add_nid(lp, addnis[i].ns_nid, flags);
		if (rc) {
			CERROR("Error adding NID %s to peer %s: %d\n",
			       libcfs_nid2str(addnis[i].ns_nid),
			       libcfs_nid2str(lp->lp_primary_nid), rc);
			if (rc == -ENOMEM)
				goto out;
		}
		lpni = lnet_find_peer_ni_locked(addnis[i].ns_nid);
		if (lpni) {
			lpni->lpni_ns_status = addnis[i].ns_status;
			lnet_peer_ni_decref_locked(lpni);
		}
	}

	for (i = 0; i < ndelnis; i++) {
		/*
		 * for routers it's okay to delete the primary_nid because
		 * the upper layers don't really rely on it. So if we're
		 * being told that the router changed its primary_nid
		 * then it's okay to delete it.
		 */
		if (lp->lp_rtr_refcount > 0)
			flags |= LNET_PEER_RTR_NI_FORCE_DEL;
		rc = lnet_peer_del_nid(lp, delnis[i], flags);
		if (rc) {
			CERROR("Error deleting NID %s from peer %s: %d\n",
			       libcfs_nid2str(delnis[i]),
			       libcfs_nid2str(lp->lp_primary_nid), rc);
			if (rc == -ENOMEM)
				goto out;
		}
	}

	/* The peer net for the primary NID should be the first entry in the
	 * peer's lp_peer_nets list, and the peer NI for the primary NID should
	 * be the first entry in its peer net's lpn_peer_nis list.
	 */
	lpni = lnet_find_peer_ni_locked(pbuf->pb_info.pi_ni[1].ns_nid);
	if (!lpni) {
		CERROR("Internal error: Failed to lookup peer NI for primary NID: %s\n",
		       libcfs_nid2str(pbuf->pb_info.pi_ni[1].ns_nid));
		goto out;
	}

	lnet_peer_ni_decref_locked(lpni);

	lpn = lpni->lpni_peer_net;
	if (lpn->lpn_peer_nets.prev != &lp->lp_peer_nets)
		list_move(&lpn->lpn_peer_nets, &lp->lp_peer_nets);

	if (lpni->lpni_peer_nis.prev != &lpni->lpni_peer_net->lpn_peer_nis)
		list_move(&lpni->lpni_peer_nis,
			  &lpni->lpni_peer_net->lpn_peer_nis);

	/*
	 * Errors other than -ENOMEM are due to peers having been
	 * configured with DLC. Ignore these because DLC overrides
	 * Discovery.
	 */
	rc = 0;
out:
	CFS_FREE_PTR_ARRAY(curnis, nnis);
	CFS_FREE_PTR_ARRAY(addnis, nnis);
	CFS_FREE_PTR_ARRAY(delnis, nnis);
	lnet_ping_buffer_decref(pbuf);
	CDEBUG(D_NET, "peer %s (%p): %d\n", libcfs_nid2str(lp->lp_primary_nid), lp, rc);

	if (rc) {
		spin_lock(&lp->lp_lock);
		lp->lp_state &= ~LNET_PEER_NIDS_UPTODATE;
		lp->lp_state |= LNET_PEER_FORCE_PING;
		spin_unlock(&lp->lp_lock);
	}
	return rc;
}

/*
 * The data in pbuf says lp is its primary peer, but the data was
 * received by a different peer. Try to update lp with the data.
 */
static int
lnet_peer_set_primary_data(struct lnet_peer *lp, struct lnet_ping_buffer *pbuf)
{
	struct lnet_handle_md mdh;

	/* Queue lp for discovery, and force it on the request queue. */
	lnet_net_lock(LNET_LOCK_EX);
	if (lnet_peer_queue_for_discovery(lp))
		list_move(&lp->lp_dc_list, &the_lnet.ln_dc_request);
	lnet_net_unlock(LNET_LOCK_EX);

	LNetInvalidateMDHandle(&mdh);

	/*
	 * Decide whether we can move the peer to the DATA_PRESENT state.
	 *
	 * We replace stale data for a multi-rail peer, repair PING_FAILED
	 * status, and preempt FORCE_PING.
	 *
	 * If after that we have DATA_PRESENT, we merge it into this peer.
	 */
	spin_lock(&lp->lp_lock);
	if (lp->lp_state & LNET_PEER_MULTI_RAIL) {
		if (lp->lp_peer_seqno < LNET_PING_BUFFER_SEQNO(pbuf)) {
			lp->lp_peer_seqno = LNET_PING_BUFFER_SEQNO(pbuf);
		} else if (lp->lp_state & LNET_PEER_DATA_PRESENT) {
			lp->lp_state &= ~LNET_PEER_DATA_PRESENT;
			lnet_ping_buffer_decref(pbuf);
			pbuf = lp->lp_data;
			lp->lp_data = NULL;
		}
	}
	if (lp->lp_state & LNET_PEER_DATA_PRESENT) {
		lnet_ping_buffer_decref(lp->lp_data);
		lp->lp_data = NULL;
		lp->lp_state &= ~LNET_PEER_DATA_PRESENT;
	}
	if (lp->lp_state & LNET_PEER_PING_FAILED) {
		mdh = lp->lp_ping_mdh;
		LNetInvalidateMDHandle(&lp->lp_ping_mdh);
		lp->lp_state &= ~LNET_PEER_PING_FAILED;
		lp->lp_ping_error = 0;
	}
	if (lp->lp_state & LNET_PEER_FORCE_PING)
		lp->lp_state &= ~LNET_PEER_FORCE_PING;
	lp->lp_state |= LNET_PEER_NIDS_UPTODATE;
	spin_unlock(&lp->lp_lock);

	if (!LNetMDHandleIsInvalid(mdh))
		LNetMDUnlink(mdh);

	if (pbuf)
		return lnet_peer_merge_data(lp, pbuf);

	CDEBUG(D_NET, "peer %s\n", libcfs_nid2str(lp->lp_primary_nid));
	return 0;
}

static bool lnet_is_nid_in_ping_info(lnet_nid_t nid, struct lnet_ping_info *pinfo)
{
	int i;

	for (i = 0; i < pinfo->pi_nnis; i++) {
		if (pinfo->pi_ni[i].ns_nid == nid)
			return true;
	}

	return false;
}

/* Delete a peer that has been marked for deletion. NB: when this peer was added
 * to the discovery queue a reference was taken that will prevent the peer from
 * actually being freed by this function. After this function exits the
 * discovery thread should call lnet_peer_discovery_complete() which will
 * drop that reference as well as wake any waiters that may also be holding a
 * ref on the peer
 */
static int lnet_peer_deletion(struct lnet_peer *lp)
__must_hold(&lp->lp_lock)
{
	struct list_head rlist;
	struct lnet_route *route, *tmp;
	int sensitivity = lp->lp_health_sensitivity;

	INIT_LIST_HEAD(&rlist);

	lp->lp_state &= ~(LNET_PEER_DISCOVERING | LNET_PEER_FORCE_PING |
			  LNET_PEER_FORCE_PUSH);
	CDEBUG(D_NET, "peer %s(%p) state %#x\n",
	       libcfs_nid2str(lp->lp_primary_nid), lp, lp->lp_state);

	/* no-op if lnet_peer_del() has already been called on this peer */
	if (lp->lp_state & LNET_PEER_MARK_DELETED)
		return 0;

	if (the_lnet.ln_dc_state != LNET_DC_STATE_RUNNING)
		return -ESHUTDOWN;

	spin_unlock(&lp->lp_lock);

	mutex_lock(&the_lnet.ln_api_mutex);

	lnet_net_lock(LNET_LOCK_EX);
	/* remove the peer from the discovery work
	 * queue if it's on there in preparation
	 * of deleting it.
	 */
	if (!list_empty(&lp->lp_dc_list))
		list_del(&lp->lp_dc_list);
	list_for_each_entry_safe(route, tmp,
				 &lp->lp_routes,
				 lr_gwlist)
		lnet_move_route(route, NULL, &rlist);
	lnet_net_unlock(LNET_LOCK_EX);

	/* lnet_peer_del() deletes all the peer NIs owned by this peer */
	lnet_peer_del(lp);

	list_for_each_entry_safe(route, tmp,
				 &rlist, lr_list) {
		/* re-add these routes */
		lnet_add_route(route->lr_net,
			       route->lr_hops,
			       route->lr_nid,
			       route->lr_priority,
			       sensitivity);
		LIBCFS_FREE(route, sizeof(*route));
	}

	mutex_unlock(&the_lnet.ln_api_mutex);

	spin_lock(&lp->lp_lock);

	return 0;
}

/*
 * Update a peer using the data received.
 */
static int lnet_peer_data_present(struct lnet_peer *lp)
__must_hold(&lp->lp_lock)
{
	struct lnet_ping_buffer *pbuf;
	struct lnet_peer_ni *lpni;
	lnet_nid_t nid = LNET_NID_ANY;
	unsigned flags;
	int rc = 0;

	pbuf = lp->lp_data;
	lp->lp_data = NULL;
	lp->lp_state &= ~LNET_PEER_DATA_PRESENT;
	lp->lp_state |= LNET_PEER_NIDS_UPTODATE;
	spin_unlock(&lp->lp_lock);

	/*
	 * Modifications of peer structures are done while holding the
	 * ln_api_mutex. A global lock is required because we may be
	 * modifying multiple peer structures, and a mutex greatly
	 * simplifies memory management.
	 *
	 * The actual changes to the data structures must also protect
	 * against concurrent lookups, for which the lnet_net_lock in
	 * LNET_LOCK_EX mode is used.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ESHUTDOWN;
		goto out;
	}

	/*
	 * If this peer is not on the peer list then it is being torn
	 * down, and our reference count may be all that is keeping it
	 * alive. Don't do any work on it.
	 */
	if (list_empty(&lp->lp_peer_list))
		goto out;

	flags = LNET_PEER_DISCOVERED;
	if (pbuf->pb_info.pi_features & LNET_PING_FEAT_MULTI_RAIL)
		flags |= LNET_PEER_MULTI_RAIL;

	/*
	 * Check whether the primary NID in the message matches the
	 * primary NID of the peer. If it does, update the peer, if
	 * it it does not, check whether there is already a peer with
	 * that primary NID. If no such peer exists, try to update
	 * the primary NID of the current peer (allowed if it was
	 * created due to message traffic) and complete the update.
	 * If the peer did exist, hand off the data to it.
	 *
	 * The peer for the loopback interface is a special case: this
	 * is the peer for the local node, and we want to set its
	 * primary NID to the correct value here. Moreover, this peer
	 * can show up with only the loopback NID in the ping buffer.
	 */
	if (pbuf->pb_info.pi_nnis <= 1)
		goto out;
	nid = pbuf->pb_info.pi_ni[1].ns_nid;
	if (lp->lp_primary_nid == LNET_NID_LO_0) {
		rc = lnet_peer_set_primary_nid(lp, nid, flags);
		if (!rc)
			rc = lnet_peer_merge_data(lp, pbuf);
	/*
	 * if the primary nid of the peer is present in the ping info returned
	 * from the peer, but it's not the local primary peer we have
	 * cached and discovery is disabled, then we don't want to update
	 * our local peer info, by adding or removing NIDs, we just want
	 * to update the status of the nids that we currently have
	 * recorded in that peer.
	 */
	} else if (lp->lp_primary_nid == nid ||
		   (lnet_is_nid_in_ping_info(lp->lp_primary_nid, &pbuf->pb_info) &&
		    lnet_is_discovery_disabled(lp))) {
		rc = lnet_peer_merge_data(lp, pbuf);
	} else {
		lpni = lnet_find_peer_ni_locked(nid);
		if (!lpni || lp == lpni->lpni_peer_net->lpn_peer) {
			rc = lnet_peer_set_primary_nid(lp, nid, flags);
			if (rc) {
				CERROR("Primary NID error %s versus %s: %d\n",
				       libcfs_nid2str(lp->lp_primary_nid),
				       libcfs_nid2str(nid), rc);
			} else {
				rc = lnet_peer_merge_data(lp, pbuf);
			}
			if (lpni)
				lnet_peer_ni_decref_locked(lpni);
		} else {
			struct lnet_peer *new_lp;
			new_lp = lpni->lpni_peer_net->lpn_peer;
			/*
			 * if lp has discovery/MR enabled that means new_lp
			 * should have discovery/MR enabled as well, since
			 * it's the same peer, which we're about to merge
			 */
			spin_lock(&lp->lp_lock);
			spin_lock(&new_lp->lp_lock);
			if (!(lp->lp_state & LNET_PEER_NO_DISCOVERY))
				new_lp->lp_state &= ~LNET_PEER_NO_DISCOVERY;
			if (lp->lp_state & LNET_PEER_MULTI_RAIL)
				new_lp->lp_state |= LNET_PEER_MULTI_RAIL;
			/* If we're processing a ping reply then we may be
			 * about to send a push to the peer that we ping'd.
			 * Since the ping reply that we're processing was
			 * received by lp, we need to set the discovery source
			 * NID for new_lp to the NID stored in lp.
			 */
			if (lp->lp_disc_src_nid != LNET_NID_ANY)
				new_lp->lp_disc_src_nid = lp->lp_disc_src_nid;
			spin_unlock(&new_lp->lp_lock);
			spin_unlock(&lp->lp_lock);

			rc = lnet_peer_set_primary_data(new_lp, pbuf);
			lnet_consolidate_routes_locked(lp, new_lp);
			lnet_peer_ni_decref_locked(lpni);
		}
	}
out:
	CDEBUG(D_NET, "peer %s(%p): %d. state = 0x%x\n", libcfs_nid2str(lp->lp_primary_nid), lp, rc,
	       lp->lp_state);
	mutex_unlock(&the_lnet.ln_api_mutex);

	spin_lock(&lp->lp_lock);
	/* Tell discovery to re-check the peer immediately. */
	if (!rc)
		rc = LNET_REDISCOVER_PEER;
	return rc;
}

/*
 * A ping failed. Clear the PING_FAILED state and set the
 * FORCE_PING state, to ensure a retry even if discovery is
 * disabled. This avoids being left with incorrect state.
 */
static int lnet_peer_ping_failed(struct lnet_peer *lp)
__must_hold(&lp->lp_lock)
{
	struct lnet_handle_md mdh;
	int rc;

	mdh = lp->lp_ping_mdh;
	LNetInvalidateMDHandle(&lp->lp_ping_mdh);
	lp->lp_state &= ~LNET_PEER_PING_FAILED;
	lp->lp_state |= LNET_PEER_FORCE_PING;
	rc = lp->lp_ping_error;
	lp->lp_ping_error = 0;
	spin_unlock(&lp->lp_lock);

	if (!LNetMDHandleIsInvalid(mdh))
		LNetMDUnlink(mdh);

	CDEBUG(D_NET, "peer %s:%d\n",
	       libcfs_nid2str(lp->lp_primary_nid), rc);

	spin_lock(&lp->lp_lock);
	return rc ? rc : LNET_REDISCOVER_PEER;
}

/*
 * Select NID to send a Ping or Push to.
 */
static lnet_nid_t lnet_peer_select_nid(struct lnet_peer *lp)
{
	struct lnet_peer_ni *lpni;

	/* Look for a direct-connected NID for this peer. */
	lpni = NULL;
	while ((lpni = lnet_get_next_peer_ni_locked(lp, NULL, lpni)) != NULL) {
		if (!lnet_get_net_locked(lpni->lpni_peer_net->lpn_net_id))
			continue;
		break;
	}
	if (lpni)
		return lpni->lpni_nid;

	/* Look for a routed-connected NID for this peer. */
	lpni = NULL;
	while ((lpni = lnet_get_next_peer_ni_locked(lp, NULL, lpni)) != NULL) {
		if (!lnet_find_rnet_locked(lpni->lpni_peer_net->lpn_net_id))
			continue;
		break;
	}
	if (lpni)
		return lpni->lpni_nid;

	return LNET_NID_ANY;
}

/* Active side of ping. */
static int lnet_peer_send_ping(struct lnet_peer *lp)
__must_hold(&lp->lp_lock)
{
	lnet_nid_t pnid;
	int nnis;
	int rc;
	int cpt;

	lp->lp_state |= LNET_PEER_PING_SENT;
	lp->lp_state &= ~LNET_PEER_FORCE_PING;
	spin_unlock(&lp->lp_lock);

	cpt = lnet_net_lock_current();
	/* Refcount for MD. */
	lnet_peer_addref_locked(lp);
	pnid = lnet_peer_select_nid(lp);
	lnet_net_unlock(cpt);

	nnis = max(lp->lp_data_nnis, LNET_INTERFACES_MIN);

	rc = lnet_send_ping(pnid, &lp->lp_ping_mdh, nnis, lp,
			    the_lnet.ln_dc_handler, false);

	/*
	 * if LNetMDBind in lnet_send_ping fails we need to decrement the
	 * refcount on the peer, otherwise LNetMDUnlink will be called
	 * which will eventually do that.
	 */
	if (rc > 0) {
		lnet_net_lock(cpt);
		lnet_peer_decref_locked(lp);
		lnet_net_unlock(cpt);
		rc = -rc; /* change the rc to negative value */
		goto fail_error;
	} else if (rc < 0) {
		goto fail_error;
	}

	CDEBUG(D_NET, "peer %s\n", libcfs_nid2str(lp->lp_primary_nid));

	spin_lock(&lp->lp_lock);
	return 0;

fail_error:
	CDEBUG(D_NET, "peer %s: %d\n", libcfs_nid2str(lp->lp_primary_nid), rc);
	/*
	 * The errors that get us here are considered hard errors and
	 * cause Discovery to terminate. So we clear PING_SENT, but do
	 * not set either PING_FAILED or FORCE_PING. In fact we need
	 * to clear PING_FAILED, because the unlink event handler will
	 * have set it if we called LNetMDUnlink() above.
	 */
	spin_lock(&lp->lp_lock);
	lp->lp_state &= ~(LNET_PEER_PING_SENT | LNET_PEER_PING_FAILED);
	return rc;
}

/*
 * This function exists because you cannot call LNetMDUnlink() from an
 * event handler.
 */
static int lnet_peer_push_failed(struct lnet_peer *lp)
__must_hold(&lp->lp_lock)
{
	struct lnet_handle_md mdh;
	int rc;

	mdh = lp->lp_push_mdh;
	LNetInvalidateMDHandle(&lp->lp_push_mdh);
	lp->lp_state &= ~LNET_PEER_PUSH_FAILED;
	rc = lp->lp_push_error;
	lp->lp_push_error = 0;
	spin_unlock(&lp->lp_lock);

	if (!LNetMDHandleIsInvalid(mdh))
		LNetMDUnlink(mdh);

	CDEBUG(D_NET, "peer %s\n", libcfs_nid2str(lp->lp_primary_nid));
	spin_lock(&lp->lp_lock);
	return rc ? rc : LNET_REDISCOVER_PEER;
}

/*
 * Mark the peer as discovered.
 */
static int lnet_peer_discovered(struct lnet_peer *lp)
__must_hold(&lp->lp_lock)
{
	lp->lp_state |= LNET_PEER_DISCOVERED;
	lp->lp_state &= ~(LNET_PEER_DISCOVERING |
			  LNET_PEER_REDISCOVER);

	lp->lp_dc_error = 0;

	CDEBUG(D_NET, "peer %s\n", libcfs_nid2str(lp->lp_primary_nid));

	return 0;
}

/* Active side of push. */
static int lnet_peer_send_push(struct lnet_peer *lp)
__must_hold(&lp->lp_lock)
{
	struct lnet_ping_buffer *pbuf;
	struct lnet_process_id id;
	struct lnet_md md;
	int cpt;
	int rc;

	/* Don't push to a non-multi-rail peer. */
	if (!(lp->lp_state & LNET_PEER_MULTI_RAIL)) {
		lp->lp_state &= ~LNET_PEER_FORCE_PUSH;
		/* if peer's NIDs are uptodate then peer is discovered */
		if (lp->lp_state & LNET_PEER_NIDS_UPTODATE) {
			rc = lnet_peer_discovered(lp);
			return rc;
		}

		return 0;
	}

	lp->lp_state |= LNET_PEER_PUSH_SENT;
	lp->lp_state &= ~LNET_PEER_FORCE_PUSH;
	spin_unlock(&lp->lp_lock);

	cpt = lnet_net_lock_current();
	pbuf = the_lnet.ln_ping_target;
	lnet_ping_buffer_addref(pbuf);
	lnet_net_unlock(cpt);

	/* Push source MD */
	md.start     = &pbuf->pb_info;
	md.length    = LNET_PING_INFO_SIZE(pbuf->pb_nnis);
	md.threshold = 2; /* Put/Ack */
	md.max_size  = 0;
	md.options   = LNET_MD_TRACK_RESPONSE;
	md.handler   = the_lnet.ln_dc_handler;
	md.user_ptr  = lp;

	rc = LNetMDBind(&md, LNET_UNLINK, &lp->lp_push_mdh);
	if (rc) {
		lnet_ping_buffer_decref(pbuf);
		CERROR("Can't bind push source MD: %d\n", rc);
		goto fail_error;
	}
	cpt = lnet_net_lock_current();
	/* Refcount for MD. */
	lnet_peer_addref_locked(lp);
	id.pid = LNET_PID_LUSTRE;
	id.nid = lnet_peer_select_nid(lp);
	lnet_net_unlock(cpt);

	if (id.nid == LNET_NID_ANY) {
		rc = -EHOSTUNREACH;
		goto fail_unlink;
	}

	rc = LNetPut(lp->lp_disc_src_nid, lp->lp_push_mdh,
		     LNET_ACK_REQ, id, LNET_RESERVED_PORTAL,
		     LNET_PROTO_PING_MATCHBITS, 0, 0);

	/*
	 * reset the discovery nid. There is no need to restrict sending
	 * from that source, if we call lnet_push_update_to_peers(). It'll
	 * get set to a specific NID, if we initiate discovery from the
	 * scratch
	 */
	lp->lp_disc_src_nid = LNET_NID_ANY;

	if (rc)
		goto fail_unlink;

	CDEBUG(D_NET, "peer %s\n", libcfs_nid2str(lp->lp_primary_nid));

	spin_lock(&lp->lp_lock);
	return 0;

fail_unlink:
	LNetMDUnlink(lp->lp_push_mdh);
	LNetInvalidateMDHandle(&lp->lp_push_mdh);
fail_error:
	CDEBUG(D_NET, "peer %s(%p): %d\n", libcfs_nid2str(lp->lp_primary_nid), lp, rc);
	/*
	 * The errors that get us here are considered hard errors and
	 * cause Discovery to terminate. So we clear PUSH_SENT, but do
	 * not set PUSH_FAILED. In fact we need to clear PUSH_FAILED,
	 * because the unlink event handler will have set it if we
	 * called LNetMDUnlink() above.
	 */
	spin_lock(&lp->lp_lock);
	lp->lp_state &= ~(LNET_PEER_PUSH_SENT | LNET_PEER_PUSH_FAILED);
	return rc;
}

/*
 * An unrecoverable error was encountered during discovery.
 * Set error status in peer and abort discovery.
 */
static void lnet_peer_discovery_error(struct lnet_peer *lp, int error)
{
	CDEBUG(D_NET, "Discovery error %s: %d\n",
	       libcfs_nid2str(lp->lp_primary_nid), error);

	spin_lock(&lp->lp_lock);
	lp->lp_dc_error = error;
	lp->lp_state &= ~LNET_PEER_DISCOVERING;
	lp->lp_state |= LNET_PEER_REDISCOVER;
	spin_unlock(&lp->lp_lock);
}

/*
 * Wait for work to be queued or some other change that must be
 * attended to. Returns non-zero if the discovery thread should shut
 * down.
 */
static int lnet_peer_discovery_wait_for_work(void)
{
	int cpt;
	int rc = 0;

	DEFINE_WAIT(wait);

	cpt = lnet_net_lock_current();
	for (;;) {
		prepare_to_wait(&the_lnet.ln_dc_waitq, &wait,
				TASK_INTERRUPTIBLE);
		if (the_lnet.ln_dc_state == LNET_DC_STATE_STOPPING)
			break;
		if (lnet_push_target_resize_needed() ||
		    the_lnet.ln_push_target->pb_needs_post)
			break;
		if (!list_empty(&the_lnet.ln_dc_request))
			break;
		if (!list_empty(&the_lnet.ln_msg_resend))
			break;
		lnet_net_unlock(cpt);

		/*
		 * wakeup max every second to check if there are peers that
		 * have been stuck on the working queue for greater than
		 * the peer timeout.
		 */
		schedule_timeout(cfs_time_seconds(1));
		finish_wait(&the_lnet.ln_dc_waitq, &wait);
		cpt = lnet_net_lock_current();
	}
	finish_wait(&the_lnet.ln_dc_waitq, &wait);

	if (the_lnet.ln_dc_state == LNET_DC_STATE_STOPPING)
		rc = -ESHUTDOWN;

	lnet_net_unlock(cpt);

	CDEBUG(D_NET, "woken: %d\n", rc);

	return rc;
}

/*
 * Messages that were pending on a destroyed peer will be put on a global
 * resend list. The message resend list will be checked by
 * the discovery thread when it wakes up, and will resend messages. These
 * messages can still be sendable in the case the lpni which was the initial
 * cause of the message re-queue was transfered to another peer.
 *
 * It is possible that LNet could be shutdown while we're iterating
 * through the list. lnet_shudown_lndnets() will attempt to access the
 * resend list, but will have to wait until the spinlock is released, by
 * which time there shouldn't be any more messages on the resend list.
 * During shutdown lnet_send() will fail and lnet_finalize() will be called
 * for the messages so they can be released. The other case is that
 * lnet_shudown_lndnets() can finalize all the messages before this
 * function can visit the resend list, in which case this function will be
 * a no-op.
 */
static void lnet_resend_msgs(void)
{
	struct lnet_msg *msg, *tmp;
	LIST_HEAD(resend);
	int rc;

	spin_lock(&the_lnet.ln_msg_resend_lock);
	list_splice(&the_lnet.ln_msg_resend, &resend);
	spin_unlock(&the_lnet.ln_msg_resend_lock);

	list_for_each_entry_safe(msg, tmp, &resend, msg_list) {
		list_del_init(&msg->msg_list);
		rc = lnet_send(msg->msg_src_nid_param, msg,
			       msg->msg_rtr_nid_param);
		if (rc < 0) {
			CNETERR("Error sending %s to %s: %d\n",
			       lnet_msgtyp2str(msg->msg_type),
			       libcfs_id2str(msg->msg_target), rc);
			lnet_finalize(msg, rc);
		}
	}
}

/* The discovery thread. */
static int lnet_peer_discovery(void *arg)
{
	struct lnet_peer *lp;
	int rc;

	wait_for_completion(&the_lnet.ln_started);

	CDEBUG(D_NET, "started\n");

	for (;;) {
		if (lnet_peer_discovery_wait_for_work())
			break;

		if (lnet_push_target_resize_needed())
			lnet_push_target_resize();
		else if (the_lnet.ln_push_target->pb_needs_post)
			lnet_push_target_post(the_lnet.ln_push_target,
					      &the_lnet.ln_push_target_md);

		lnet_resend_msgs();

		lnet_net_lock(LNET_LOCK_EX);
		if (the_lnet.ln_dc_state == LNET_DC_STATE_STOPPING) {
			lnet_net_unlock(LNET_LOCK_EX);
			break;
		}

		/*
		 * Process all incoming discovery work requests.  When
		 * discovery must wait on a peer to change state, it
		 * is added to the tail of the ln_dc_working queue. A
		 * timestamp keeps track of when the peer was added,
		 * so we can time out discovery requests that take too
		 * long.
		 */
		while (!list_empty(&the_lnet.ln_dc_request)) {
			lp = list_first_entry(&the_lnet.ln_dc_request,
					      struct lnet_peer, lp_dc_list);
			list_move(&lp->lp_dc_list, &the_lnet.ln_dc_working);
			/*
			 * set the time the peer was put on the dc_working
			 * queue. It shouldn't remain on the queue
			 * forever, in case the GET message (for ping)
			 * doesn't get a REPLY or the PUT message (for
			 * push) doesn't get an ACK.
			 */
			lp->lp_last_queued = ktime_get_real_seconds();
			lnet_net_unlock(LNET_LOCK_EX);

			if (lnet_push_target_resize_needed())
				lnet_push_target_resize();
			else if (the_lnet.ln_push_target->pb_needs_post)
				lnet_push_target_post(the_lnet.ln_push_target,
						      &the_lnet.ln_push_target_md);

			/*
			 * Select an action depending on the state of
			 * the peer and whether discovery is disabled.
			 * The check whether discovery is disabled is
			 * done after the code that handles processing
			 * for arrived data, cleanup for failures, and
			 * forcing a Ping or Push.
			 */
			spin_lock(&lp->lp_lock);
			CDEBUG(D_NET, "peer %s(%p) state %#x\n",
				libcfs_nid2str(lp->lp_primary_nid), lp,
				lp->lp_state);
			if (lp->lp_state & (LNET_PEER_MARK_DELETION |
					    LNET_PEER_MARK_DELETED))
				rc = lnet_peer_deletion(lp);
			else if (lp->lp_state & LNET_PEER_DATA_PRESENT)
				rc = lnet_peer_data_present(lp);
			else if (lp->lp_state & LNET_PEER_PING_FAILED)
				rc = lnet_peer_ping_failed(lp);
			else if (lp->lp_state & LNET_PEER_PUSH_FAILED)
				rc = lnet_peer_push_failed(lp);
			else if (lp->lp_state & LNET_PEER_FORCE_PING)
				rc = lnet_peer_send_ping(lp);
			else if (lp->lp_state & LNET_PEER_FORCE_PUSH)
				rc = lnet_peer_send_push(lp);
			else if (!(lp->lp_state & LNET_PEER_NIDS_UPTODATE))
				rc = lnet_peer_send_ping(lp);
			else if (lnet_peer_needs_push(lp))
				rc = lnet_peer_send_push(lp);
			else
				rc = lnet_peer_discovered(lp);
			CDEBUG(D_NET, "peer %s(%p) state %#x rc %d\n",
				libcfs_nid2str(lp->lp_primary_nid), lp,
				lp->lp_state, rc);
			spin_unlock(&lp->lp_lock);

			lnet_net_lock(LNET_LOCK_EX);
			if (rc == LNET_REDISCOVER_PEER) {
				list_move(&lp->lp_dc_list,
					  &the_lnet.ln_dc_request);
			} else if (rc) {
				lnet_peer_discovery_error(lp, rc);
			}
			if (!(lp->lp_state & LNET_PEER_DISCOVERING))
				lnet_peer_discovery_complete(lp);
			if (the_lnet.ln_dc_state == LNET_DC_STATE_STOPPING)
				break;

		}

		lnet_net_unlock(LNET_LOCK_EX);
	}

	CDEBUG(D_NET, "stopping\n");
	/*
	 * Clean up before telling lnet_peer_discovery_stop() that
	 * we're done. Use wake_up() below to somewhat reduce the
	 * size of the thundering herd if there are multiple threads
	 * waiting on discovery of a single peer.
	 */

	/* Queue cleanup 1: stop all pending pings and pushes. */
	lnet_net_lock(LNET_LOCK_EX);
	while (!list_empty(&the_lnet.ln_dc_working)) {
		lp = list_first_entry(&the_lnet.ln_dc_working,
				      struct lnet_peer, lp_dc_list);
		list_move(&lp->lp_dc_list, &the_lnet.ln_dc_expired);
		lnet_net_unlock(LNET_LOCK_EX);
		lnet_peer_cancel_discovery(lp);
		lnet_net_lock(LNET_LOCK_EX);
	}
	lnet_net_unlock(LNET_LOCK_EX);

	/* Queue cleanup 2: wait for the expired queue to clear. */
	while (!list_empty(&the_lnet.ln_dc_expired))
		schedule_timeout_uninterruptible(cfs_time_seconds(1));

	/* Queue cleanup 3: clear the request queue. */
	lnet_net_lock(LNET_LOCK_EX);
	while (!list_empty(&the_lnet.ln_dc_request)) {
		lp = list_first_entry(&the_lnet.ln_dc_request,
				      struct lnet_peer, lp_dc_list);
		lnet_peer_discovery_error(lp, -ESHUTDOWN);
		lnet_peer_discovery_complete(lp);
	}
	lnet_net_unlock(LNET_LOCK_EX);

	lnet_assert_handler_unused(the_lnet.ln_dc_handler);
	the_lnet.ln_dc_handler = NULL;

	the_lnet.ln_dc_state = LNET_DC_STATE_SHUTDOWN;
	wake_up(&the_lnet.ln_dc_waitq);

	CDEBUG(D_NET, "stopped\n");

	return 0;
}

/* ln_api_mutex is held on entry. */
int lnet_peer_discovery_start(void)
{
	struct task_struct *task;
	int rc = 0;

	if (the_lnet.ln_dc_state != LNET_DC_STATE_SHUTDOWN)
		return -EALREADY;

	the_lnet.ln_dc_handler = lnet_discovery_event_handler;
	the_lnet.ln_dc_state = LNET_DC_STATE_RUNNING;
	task = kthread_run(lnet_peer_discovery, NULL, "lnet_discovery");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("Can't start peer discovery thread: %d\n", rc);

		the_lnet.ln_dc_handler = NULL;

		the_lnet.ln_dc_state = LNET_DC_STATE_SHUTDOWN;
	}

	CDEBUG(D_NET, "discovery start: %d\n", rc);

	return rc;
}

/* ln_api_mutex is held on entry. */
void lnet_peer_discovery_stop(void)
{
	if (the_lnet.ln_dc_state == LNET_DC_STATE_SHUTDOWN)
		return;

	LASSERT(the_lnet.ln_dc_state == LNET_DC_STATE_RUNNING);
	the_lnet.ln_dc_state = LNET_DC_STATE_STOPPING;

	/* In the LNetNIInit() path we may be stopping discovery before it
	 * entered its work loop
	 */
	if (!completion_done(&the_lnet.ln_started))
		complete(&the_lnet.ln_started);
	else
		wake_up(&the_lnet.ln_dc_waitq);

	wait_event(the_lnet.ln_dc_waitq,
		   the_lnet.ln_dc_state == LNET_DC_STATE_SHUTDOWN);

	LASSERT(list_empty(&the_lnet.ln_dc_request));
	LASSERT(list_empty(&the_lnet.ln_dc_working));
	LASSERT(list_empty(&the_lnet.ln_dc_expired));

	CDEBUG(D_NET, "discovery stopped\n");
}

/* Debugging */

void
lnet_debug_peer(lnet_nid_t nid)
{
	char			*aliveness = "NA";
	struct lnet_peer_ni	*lp;
	int			cpt;

	cpt = lnet_cpt_of_nid(nid, NULL);
	lnet_net_lock(cpt);

	lp = lnet_nid2peerni_locked(nid, LNET_NID_ANY, cpt);
	if (IS_ERR(lp)) {
		lnet_net_unlock(cpt);
		CDEBUG(D_WARNING, "No peer %s\n", libcfs_nid2str(nid));
		return;
	}

	if (lnet_isrouter(lp) || lnet_peer_aliveness_enabled(lp))
		aliveness = (lnet_is_peer_ni_alive(lp)) ? "up" : "down";

	CDEBUG(D_WARNING, "%-24s %4d %5s %5d %5d %5d %5d %5d %ld\n",
	       libcfs_nid2str(lp->lpni_nid), kref_read(&lp->lpni_kref),
	       aliveness, lp->lpni_net->net_tunables.lct_peer_tx_credits,
	       lp->lpni_rtrcredits, lp->lpni_minrtrcredits,
	       lp->lpni_txcredits, lp->lpni_mintxcredits, lp->lpni_txqnob);

	lnet_peer_ni_decref_locked(lp);

	lnet_net_unlock(cpt);
}

/* Gathering information for userspace. */

int lnet_get_peer_ni_info(__u32 peer_index, __u64 *nid,
			  char aliveness[LNET_MAX_STR_LEN],
			  __u32 *cpt_iter, __u32 *refcount,
			  __u32 *ni_peer_tx_credits, __u32 *peer_tx_credits,
			  __u32 *peer_rtr_credits, __u32 *peer_min_rtr_credits,
			  __u32 *peer_tx_qnob)
{
	struct lnet_peer_table		*peer_table;
	struct lnet_peer_ni		*lp;
	int				j;
	int				lncpt;
	bool				found = false;

	/* get the number of CPTs */
	lncpt = cfs_percpt_number(the_lnet.ln_peer_tables);

	/* if the cpt number to be examined is >= the number of cpts in
	 * the system then indicate that there are no more cpts to examin
	 */
	if (*cpt_iter >= lncpt)
		return -ENOENT;

	/* get the current table */
	peer_table = the_lnet.ln_peer_tables[*cpt_iter];
	/* if the ptable is NULL then there are no more cpts to examine */
	if (peer_table == NULL)
		return -ENOENT;

	lnet_net_lock(*cpt_iter);

	for (j = 0; j < LNET_PEER_HASH_SIZE && !found; j++) {
		struct list_head *peers = &peer_table->pt_hash[j];

		list_for_each_entry(lp, peers, lpni_hashlist) {
			if (peer_index-- > 0)
				continue;

			snprintf(aliveness, LNET_MAX_STR_LEN, "NA");
			if (lnet_isrouter(lp) ||
				lnet_peer_aliveness_enabled(lp))
				snprintf(aliveness, LNET_MAX_STR_LEN,
					 lnet_is_peer_ni_alive(lp) ? "up" : "down");

			*nid = lp->lpni_nid;
			*refcount = kref_read(&lp->lpni_kref);
			*ni_peer_tx_credits =
				lp->lpni_net->net_tunables.lct_peer_tx_credits;
			*peer_tx_credits = lp->lpni_txcredits;
			*peer_rtr_credits = lp->lpni_rtrcredits;
			*peer_min_rtr_credits = lp->lpni_mintxcredits;
			*peer_tx_qnob = lp->lpni_txqnob;

			found = true;
		}

	}
	lnet_net_unlock(*cpt_iter);

	*cpt_iter = lncpt;

	return found ? 0 : -ENOENT;
}

/* ln_api_mutex is held, which keeps the peer list stable */
int lnet_get_peer_info(struct lnet_ioctl_peer_cfg *cfg, void __user *bulk)
{
	struct lnet_ioctl_element_stats *lpni_stats;
	struct lnet_ioctl_element_msg_stats *lpni_msg_stats;
	struct lnet_ioctl_peer_ni_hstats *lpni_hstats;
	struct lnet_peer_ni_credit_info *lpni_info;
	struct lnet_peer_ni *lpni;
	struct lnet_peer *lp;
	lnet_nid_t nid;
	__u32 size;
	int rc;

	lp = lnet_find_peer(cfg->prcfg_prim_nid);

	if (!lp) {
		rc = -ENOENT;
		goto out;
	}

	size = sizeof(nid) + sizeof(*lpni_info) + sizeof(*lpni_stats)
		+ sizeof(*lpni_msg_stats) + sizeof(*lpni_hstats);
	size *= lp->lp_nnis;
	if (size > cfg->prcfg_size) {
		cfg->prcfg_size = size;
		rc = -E2BIG;
		goto out_lp_decref;
	}

	cfg->prcfg_prim_nid = lp->lp_primary_nid;
	cfg->prcfg_mr = lnet_peer_is_multi_rail(lp);
	cfg->prcfg_cfg_nid = lp->lp_primary_nid;
	cfg->prcfg_count = lp->lp_nnis;
	cfg->prcfg_size = size;
	cfg->prcfg_state = lp->lp_state;

	/* Allocate helper buffers. */
	rc = -ENOMEM;
	LIBCFS_ALLOC(lpni_info, sizeof(*lpni_info));
	if (!lpni_info)
		goto out_lp_decref;
	LIBCFS_ALLOC(lpni_stats, sizeof(*lpni_stats));
	if (!lpni_stats)
		goto out_free_info;
	LIBCFS_ALLOC(lpni_msg_stats, sizeof(*lpni_msg_stats));
	if (!lpni_msg_stats)
		goto out_free_stats;
	LIBCFS_ALLOC(lpni_hstats, sizeof(*lpni_hstats));
	if (!lpni_hstats)
		goto out_free_msg_stats;


	lpni = NULL;
	rc = -EFAULT;
	while ((lpni = lnet_get_next_peer_ni_locked(lp, NULL, lpni)) != NULL) {
		nid = lpni->lpni_nid;
		if (copy_to_user(bulk, &nid, sizeof(nid)))
			goto out_free_hstats;
		bulk += sizeof(nid);

		memset(lpni_info, 0, sizeof(*lpni_info));
		snprintf(lpni_info->cr_aliveness, LNET_MAX_STR_LEN, "NA");
		if (lnet_isrouter(lpni) ||
			lnet_peer_aliveness_enabled(lpni))
			snprintf(lpni_info->cr_aliveness, LNET_MAX_STR_LEN,
				lnet_is_peer_ni_alive(lpni) ? "up" : "down");

		lpni_info->cr_refcount = kref_read(&lpni->lpni_kref);
		lpni_info->cr_ni_peer_tx_credits = (lpni->lpni_net != NULL) ?
			lpni->lpni_net->net_tunables.lct_peer_tx_credits : 0;
		lpni_info->cr_peer_tx_credits = lpni->lpni_txcredits;
		lpni_info->cr_peer_rtr_credits = lpni->lpni_rtrcredits;
		lpni_info->cr_peer_min_rtr_credits = lpni->lpni_minrtrcredits;
		lpni_info->cr_peer_min_tx_credits = lpni->lpni_mintxcredits;
		lpni_info->cr_peer_tx_qnob = lpni->lpni_txqnob;
		if (copy_to_user(bulk, lpni_info, sizeof(*lpni_info)))
			goto out_free_hstats;
		bulk += sizeof(*lpni_info);

		memset(lpni_stats, 0, sizeof(*lpni_stats));
		lpni_stats->iel_send_count = lnet_sum_stats(&lpni->lpni_stats,
							    LNET_STATS_TYPE_SEND);
		lpni_stats->iel_recv_count = lnet_sum_stats(&lpni->lpni_stats,
							    LNET_STATS_TYPE_RECV);
		lpni_stats->iel_drop_count = lnet_sum_stats(&lpni->lpni_stats,
							    LNET_STATS_TYPE_DROP);
		if (copy_to_user(bulk, lpni_stats, sizeof(*lpni_stats)))
			goto out_free_hstats;
		bulk += sizeof(*lpni_stats);
		lnet_usr_translate_stats(lpni_msg_stats, &lpni->lpni_stats);
		if (copy_to_user(bulk, lpni_msg_stats, sizeof(*lpni_msg_stats)))
			goto out_free_hstats;
		bulk += sizeof(*lpni_msg_stats);
		lpni_hstats->hlpni_network_timeout =
		  atomic_read(&lpni->lpni_hstats.hlt_network_timeout);
		lpni_hstats->hlpni_remote_dropped =
		  atomic_read(&lpni->lpni_hstats.hlt_remote_dropped);
		lpni_hstats->hlpni_remote_timeout =
		  atomic_read(&lpni->lpni_hstats.hlt_remote_timeout);
		lpni_hstats->hlpni_remote_error =
		  atomic_read(&lpni->lpni_hstats.hlt_remote_error);
		lpni_hstats->hlpni_health_value =
		  atomic_read(&lpni->lpni_healthv);
		if (copy_to_user(bulk, lpni_hstats, sizeof(*lpni_hstats)))
			goto out_free_hstats;
		bulk += sizeof(*lpni_hstats);
	}
	rc = 0;

out_free_hstats:
	LIBCFS_FREE(lpni_hstats, sizeof(*lpni_hstats));
out_free_msg_stats:
	LIBCFS_FREE(lpni_msg_stats, sizeof(*lpni_msg_stats));
out_free_stats:
	LIBCFS_FREE(lpni_stats, sizeof(*lpni_stats));
out_free_info:
	LIBCFS_FREE(lpni_info, sizeof(*lpni_info));
out_lp_decref:
	lnet_peer_decref_locked(lp);
out:
	return rc;
}

/* must hold net_lock/0 */
void
lnet_peer_ni_add_to_recoveryq_locked(struct lnet_peer_ni *lpni,
				     struct list_head *recovery_queue,
				     time64_t now)
{
	/* the mt could've shutdown and cleaned up the queues */
	if (the_lnet.ln_mt_state != LNET_MT_STATE_RUNNING)
		return;

	if (!list_empty(&lpni->lpni_recovery))
		return;

	if (atomic_read(&lpni->lpni_healthv) == LNET_MAX_HEALTH_VALUE)
		return;

	if (!lpni->lpni_last_alive) {
		CDEBUG(D_NET,
		       "lpni %s(%p) not eligible for recovery last alive %lld\n",
		       libcfs_nid2str(lpni->lpni_nid), lpni,
		       lpni->lpni_last_alive);
		return;
	}

	if (now > lpni->lpni_last_alive + lnet_recovery_limit) {
		CDEBUG(D_NET, "lpni %s aged out last alive %lld\n",
		       libcfs_nid2str(lpni->lpni_nid),
		       lpni->lpni_last_alive);
		/* Reset the ping count so that if this peer NI is added back to
		 * the recovery queue we will send the first ping right away.
		 */
		lpni->lpni_ping_count = 0;
		return;
	}

	/* This peer NI is going on the recovery queue, so take a ref on it */
	lnet_peer_ni_addref_locked(lpni);

	lnet_peer_ni_set_next_ping(lpni, now);

	CDEBUG(D_NET, "%s added to recovery queue. ping count: %u next ping: %lld last alive: %lld health: %d\n",
	       libcfs_nid2str(lpni->lpni_nid),
	       lpni->lpni_ping_count,
	       lpni->lpni_next_ping,
	       lpni->lpni_last_alive,
	       atomic_read(&lpni->lpni_healthv));

	list_add_tail(&lpni->lpni_recovery, recovery_queue);
}

/* Call with the ln_api_mutex held */
void
lnet_peer_ni_set_healthv(lnet_nid_t nid, int value, bool all)
{
	struct lnet_peer_table *ptable;
	struct lnet_peer *lp;
	struct lnet_peer_net *lpn;
	struct lnet_peer_ni *lpni;
	int lncpt;
	int cpt;
	time64_t now;

	if (the_lnet.ln_state != LNET_STATE_RUNNING)
		return;

	now = ktime_get_seconds();

	if (!all) {
		lnet_net_lock(LNET_LOCK_EX);
		lpni = lnet_find_peer_ni_locked(nid);
		if (!lpni) {
			lnet_net_unlock(LNET_LOCK_EX);
			return;
		}
		atomic_set(&lpni->lpni_healthv, value);
		lnet_peer_ni_add_to_recoveryq_locked(lpni,
					     &the_lnet.ln_mt_peerNIRecovq, now);
		lnet_peer_ni_decref_locked(lpni);
		lnet_net_unlock(LNET_LOCK_EX);
		return;
	}

	lncpt = cfs_percpt_number(the_lnet.ln_peer_tables);

	/*
	 * Walk all the peers and reset the health value for each one to the
	 * specified value.
	 */
	lnet_net_lock(LNET_LOCK_EX);
	for (cpt = 0; cpt < lncpt; cpt++) {
		ptable = the_lnet.ln_peer_tables[cpt];
		list_for_each_entry(lp, &ptable->pt_peer_list, lp_peer_list) {
			list_for_each_entry(lpn, &lp->lp_peer_nets, lpn_peer_nets) {
				list_for_each_entry(lpni, &lpn->lpn_peer_nis,
						    lpni_peer_nis) {
					atomic_set(&lpni->lpni_healthv, value);
					lnet_peer_ni_add_to_recoveryq_locked(lpni,
					     &the_lnet.ln_mt_peerNIRecovq, now);
				}
			}
		}
	}
	lnet_net_unlock(LNET_LOCK_EX);
}

