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
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/lnet/peer.c
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lib-lnet.h>
#include <uapi/linux/lnet/lnet-dlc.h>

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

		LIBCFS_FREE(hash, LNET_PEER_HASH_SIZE * sizeof(*hash));
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
	INIT_LIST_HEAD(&lpni->lpni_rtrq);
	INIT_LIST_HEAD(&lpni->lpni_routes);
	INIT_LIST_HEAD(&lpni->lpni_hashlist);
	INIT_LIST_HEAD(&lpni->lpni_peer_nis);
	INIT_LIST_HEAD(&lpni->lpni_on_remote_peer_ni_list);

	spin_lock_init(&lpni->lpni_lock);

	lpni->lpni_alive = !lnet_peers_start_down(); /* 1 bit!! */
	lpni->lpni_last_alive = cfs_time_current(); /* assumes alive */
	lpni->lpni_ping_feats = LNET_PING_FEAT_INVAL;
	lpni->lpni_nid = nid;
	lpni->lpni_cpt = cpt;
	lnet_set_peer_ni_health_locked(lpni, true);

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
		atomic_inc(&lpni->lpni_refcount);
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

	INIT_LIST_HEAD(&lp->lp_peer_list);
	INIT_LIST_HEAD(&lp->lp_peer_nets);
	INIT_LIST_HEAD(&lp->lp_dc_list);
	init_waitqueue_head(&lp->lp_dc_waitq);
	spin_lock_init(&lp->lp_lock);
	lp->lp_primary_nid = nid;
	lp->lp_cpt = lnet_nid_cpt_hash(nid, LNET_CPT_NUMBER);

	CDEBUG(D_NET, "%p nid %s\n", lp, libcfs_nid2str(lp->lp_primary_nid));

	return lp;
}

void
lnet_destroy_peer_locked(struct lnet_peer *lp)
{
	CDEBUG(D_NET, "%p nid %s\n", lp, libcfs_nid2str(lp->lp_primary_nid));

	LASSERT(atomic_read(&lp->lp_refcount) == 0);
	LASSERT(list_empty(&lp->lp_peer_nets));
	LASSERT(list_empty(&lp->lp_peer_list));

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
	ptable = the_lnet.ln_peer_tables[lp->lp_cpt];
	lp->lp_nnis--;
	ptable->pt_peer_nnids--;

	/*
	 * If there are no more peer nets, make the peer unfindable
	 * via the peer_tables.
	 */
	if (list_empty(&lp->lp_peer_nets)) {
		list_del_init(&lp->lp_peer_list);
		ptable->pt_peers--;
	}
	CDEBUG(D_NET, "peer %s NID %s\n",
		libcfs_nid2str(lp->lp_primary_nid),
		libcfs_nid2str(lpni->lpni_nid));
}

/* called with lnet_net_lock LNET_LOCK_EX held */
static int
lnet_peer_ni_del_locked(struct lnet_peer_ni *lpni)
{
	struct lnet_peer_table *ptable = NULL;

	/* don't remove a peer_ni if it's also a gateway */
	if (lpni->lpni_rtr_refcount > 0) {
		CERROR("Peer NI %s is a gateway. Can not delete it\n",
		       libcfs_nid2str(lpni->lpni_nid));
		return -EBUSY;
	}

	lnet_peer_remove_from_remote_list(lpni);

	/* remove peer ni from the hash list. */
	list_del_init(&lpni->lpni_hashlist);

	/* decrement the ref count on the peer table */
	ptable = the_lnet.ln_peer_tables[lpni->lpni_cpt];
	LASSERT(ptable->pt_number > 0);
	ptable->pt_number--;

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
		lnet_peer_ni_del_locked(lpni);

	lnet_peer_tables_destroy();

	lnet_net_unlock(LNET_LOCK_EX);
}

static int
lnet_peer_del_locked(struct lnet_peer *peer)
{
	struct lnet_peer_ni *lpni = NULL, *lpni2;
	int rc = 0, rc2 = 0;

	CDEBUG(D_NET, "peer %s\n", libcfs_nid2str(peer->lp_primary_nid));

	lpni = lnet_get_next_peer_ni_locked(peer, NULL, lpni);
	while (lpni != NULL) {
		lpni2 = lnet_get_next_peer_ni_locked(peer, NULL, lpni);
		rc = lnet_peer_ni_del_locked(lpni);
		if (rc != 0)
			rc2 = rc;
		lpni = lpni2;
	}

	return rc2;
}

static int
lnet_peer_del(struct lnet_peer *peer)
{
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
	if (nid == lp->lp_primary_nid && lp->lp_nnis != 1) {
		rc = -EBUSY;
		goto out;
	}

	lnet_net_lock(LNET_LOCK_EX);
	lnet_peer_ni_del_locked(lpni);
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
				lnet_peer_ni_del_locked(lpni);
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
	int	i = 3;

	spin_lock(&ptable->pt_zombie_lock);
	while (ptable->pt_zombies) {
		spin_unlock(&ptable->pt_zombie_lock);

		if (is_power_of_2(i)) {
			CDEBUG(D_WARNING,
			       "Waiting for %d zombies on peer table\n",
			       ptable->pt_zombies);
		}
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1) >> 1);
		spin_lock(&ptable->pt_zombie_lock);
	}
	spin_unlock(&ptable->pt_zombie_lock);
}

static void
lnet_peer_table_del_rtrs_locked(struct lnet_net *net,
				struct lnet_peer_table *ptable)
{
	struct lnet_peer_ni	*lp;
	struct lnet_peer_ni	*tmp;
	lnet_nid_t		lpni_nid;
	int			i;

	for (i = 0; i < LNET_PEER_HASH_SIZE; i++) {
		list_for_each_entry_safe(lp, tmp, &ptable->pt_hash[i],
					 lpni_hashlist) {
			if (net != lp->lpni_net)
				continue;

			if (lp->lpni_rtr_refcount == 0)
				continue;

			lpni_nid = lp->lpni_nid;

			lnet_net_unlock(LNET_LOCK_EX);
			lnet_del_route(LNET_NIDNET(LNET_NID_ANY), lpni_nid);
			lnet_net_lock(LNET_LOCK_EX);
		}
	}
}

void
lnet_peer_tables_cleanup(struct lnet_net *net)
{
	int				i;
	struct lnet_peer_table		*ptable;

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

	LASSERT(the_lnet.ln_state == LNET_STATE_RUNNING);

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
lnet_get_peer_ni_idx_locked(int idx, struct lnet_peer_net **lpn,
			    struct lnet_peer **lp)
{
	struct lnet_peer_table	*ptable;
	struct lnet_peer_ni	*lpni;
	int			lncpt;
	int			cpt;

	lncpt = cfs_percpt_number(the_lnet.ln_peer_tables);

	for (cpt = 0; cpt < lncpt; cpt++) {
		ptable = the_lnet.ln_peer_tables[cpt];
		if (ptable->pt_peer_nnids > idx)
			break;
		idx -= ptable->pt_peer_nnids;
	}
	if (cpt >= lncpt)
		return NULL;

	list_for_each_entry((*lp), &ptable->pt_peer_list, lp_peer_list) {
		if ((*lp)->lp_nnis <= idx) {
			idx -= (*lp)->lp_nnis;
			continue;
		}
		list_for_each_entry((*lpn), &((*lp)->lp_peer_nets),
				    lpn_peer_nets) {
			list_for_each_entry(lpni, &((*lpn)->lpn_peer_nis),
					    lpni_peer_nis) {
				if (idx-- == 0)
					return lpni;
			}
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

/*
 * Test whether a ni is a preferred ni for this peer_ni, e.g, whether
 * this is a preferred point-to-point path. Call with lnet_net_lock in
 * shared mmode.
 */
bool
lnet_peer_is_pref_nid_locked(struct lnet_peer_ni *lpni, lnet_nid_t nid)
{
	int i;

	if (lpni->lpni_pref_nnids == 0)
		return false;
	if (lpni->lpni_pref_nnids == 1)
		return lpni->lpni_pref.nid == nid;
	for (i = 0; i < lpni->lpni_pref_nnids; i++) {
		if (lpni->lpni_pref.nids[i] == nid)
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
	lnet_nid_t *nids = NULL;
	lnet_nid_t *oldnids = NULL;
	struct lnet_peer *lp = lpni->lpni_peer_net->lpn_peer;
	int size;
	int i;
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
	if (lpni->lpni_pref_nnids > 0) {
		if (!(lp->lp_state & LNET_PEER_MULTI_RAIL)) {
			rc = -EPERM;
			goto out;
		}
	}

	if (lpni->lpni_pref_nnids != 0) {
		size = sizeof(*nids) * (lpni->lpni_pref_nnids + 1);
		LIBCFS_CPT_ALLOC(nids, lnet_cpt_table(), lpni->lpni_cpt, size);
		if (!nids) {
			rc = -ENOMEM;
			goto out;
		}
		for (i = 0; i < lpni->lpni_pref_nnids; i++) {
			if (lpni->lpni_pref.nids[i] == nid) {
				LIBCFS_FREE(nids, size);
				rc = -EEXIST;
				goto out;
			}
			nids[i] = lpni->lpni_pref.nids[i];
		}
		nids[i] = nid;
	}

	lnet_net_lock(LNET_LOCK_EX);
	spin_lock(&lpni->lpni_lock);
	if (lpni->lpni_pref_nnids == 0) {
		lpni->lpni_pref.nid = nid;
	} else {
		oldnids = lpni->lpni_pref.nids;
		lpni->lpni_pref.nids = nids;
	}
	lpni->lpni_pref_nnids++;
	lpni->lpni_state &= ~LNET_PEER_NI_NON_MR_PREF;
	spin_unlock(&lpni->lpni_lock);
	lnet_net_unlock(LNET_LOCK_EX);

	if (oldnids) {
		size = sizeof(*nids) * (lpni->lpni_pref_nnids - 1);
		LIBCFS_FREE(oldnids, sizeof(*oldnids) * size);
	}
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
	lnet_nid_t *nids = NULL;
	lnet_nid_t *oldnids = NULL;
	struct lnet_peer *lp = lpni->lpni_peer_net->lpn_peer;
	int size;
	int i, j;
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
	} else if (lpni->lpni_pref_nnids == 2) {
		if (lpni->lpni_pref.nids[0] != nid &&
		    lpni->lpni_pref.nids[1] != nid) {
			rc = -ENOENT;
			goto out;
		}
	} else {
		size = sizeof(*nids) * (lpni->lpni_pref_nnids - 1);
		LIBCFS_CPT_ALLOC(nids, lnet_cpt_table(), lpni->lpni_cpt, size);
		if (!nids) {
			rc = -ENOMEM;
			goto out;
		}
		for (i = 0, j = 0; i < lpni->lpni_pref_nnids; i++) {
			if (lpni->lpni_pref.nids[i] != nid)
				continue;
			nids[j++] = lpni->lpni_pref.nids[i];
		}
		/* Check if we actually removed a nid. */
		if (j == lpni->lpni_pref_nnids) {
			LIBCFS_FREE(nids, size);
			rc = -ENOENT;
			goto out;
		}
	}

	lnet_net_lock(LNET_LOCK_EX);
	spin_lock(&lpni->lpni_lock);
	if (lpni->lpni_pref_nnids == 1) {
		lpni->lpni_pref.nid = LNET_NID_ANY;
	} else if (lpni->lpni_pref_nnids == 2) {
		oldnids = lpni->lpni_pref.nids;
		if (oldnids[0] == nid)
			lpni->lpni_pref.nid = oldnids[1];
		else
			lpni->lpni_pref.nid = oldnids[2];
	} else {
		oldnids = lpni->lpni_pref.nids;
		lpni->lpni_pref.nids = nids;
	}
	lpni->lpni_pref_nnids--;
	lpni->lpni_state &= ~LNET_PEER_NI_NON_MR_PREF;
	spin_unlock(&lpni->lpni_lock);
	lnet_net_unlock(LNET_LOCK_EX);

	if (oldnids) {
		size = sizeof(*nids) * (lpni->lpni_pref_nnids + 1);
		LIBCFS_FREE(oldnids, sizeof(*oldnids) * size);
	}
out:
	CDEBUG(D_NET, "peer %s nid %s: %d\n",
	       libcfs_nid2str(lp->lp_primary_nid), libcfs_nid2str(nid), rc);
	return rc;
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

lnet_nid_t
LNetPrimaryNID(lnet_nid_t nid)
{
	struct lnet_peer_ni *lpni;
	lnet_nid_t primary_nid = nid;
	int rc = 0;
	int cpt;

	cpt = lnet_net_lock_current();
	lpni = lnet_nid2peerni_locked(nid, LNET_NID_ANY, cpt);
	if (IS_ERR(lpni)) {
		rc = PTR_ERR(lpni);
		goto out_unlock;
	}
	primary_nid = lpni->lpni_peer_net->lpn_peer->lp_primary_nid;
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
 * Always returns 0.  This is the last function called from functions
 * that do return an int, so returning 0 here allows the compiler to
 * do a tail call.
 */
static int
lnet_peer_attach_peer_ni(struct lnet_peer *lp,
				struct lnet_peer_net *lpn,
				struct lnet_peer_ni *lpni,
				unsigned flags)
{
	struct lnet_peer_table *ptable;

	/* Install the new peer_ni */
	lnet_net_lock(LNET_LOCK_EX);
	/* Add peer_ni to global peer table hash, if necessary. */
	if (list_empty(&lpni->lpni_hashlist)) {
		int hash = lnet_nid2peerhash(lpni->lpni_nid);

		ptable = the_lnet.ln_peer_tables[lpni->lpni_cpt];
		list_add_tail(&lpni->lpni_hashlist, &ptable->pt_hash[hash]);
		ptable->pt_version++;
		ptable->pt_number++;
		/* This is the 1st refcount on lpni. */
		atomic_inc(&lpni->lpni_refcount);
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
	list_add_tail(&lpni->lpni_peer_nis, &lpn->lpn_peer_nis);
	lnet_peer_net_addref_locked(lpn);

	/* Add peer_net to peer */
	if (!lpn->lpn_peer) {
		lpn->lpn_peer = lp;
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
	the_lnet.ln_peer_tables[lp->lp_cpt]->pt_peer_nnids++;
	lnet_net_unlock(LNET_LOCK_EX);

	CDEBUG(D_NET, "peer %s NID %s flags %#x\n",
	       libcfs_nid2str(lp->lp_primary_nid),
	       libcfs_nid2str(lpni->lpni_nid), flags);

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
		lnet_peer_ni_decref_locked(lpni);
		if (lpni->lpni_peer_net->lpn_peer == lp)
			goto out;
		if (lnet_peer_ni_is_configured(lpni)) {
			rc = -EEXIST;
			goto out;
		}
		/* If this is the primary NID, destroy the peer. */
		if (lnet_peer_ni_is_primary(lpni)) {
			lnet_peer_del(lpni->lpni_peer_net->lpn_peer);
			lpni = lnet_peer_ni_alloc(nid);
			if (!lpni) {
				rc = -ENOMEM;
				goto out;
			}
		}
	} else {
		lpni = lnet_peer_ni_alloc(nid);
		if (!lpni) {
			rc = -ENOMEM;
			goto out;
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
	/* If the peer_ni was allocated above its peer_net pointer is NULL */
	if (!lpni->lpni_peer_net)
		LIBCFS_FREE(lpni, sizeof(*lpni));
out:
	CDEBUG(D_NET, "peer %s NID %s flags %#x: %d\n",
	       libcfs_nid2str(lp->lp_primary_nid), libcfs_nid2str(nid),
	       flags, rc);
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

	if (nid == LNET_NID_ANY || nid == lp->lp_primary_nid)
		return lnet_peer_del(lp);

	flags = LNET_PEER_CONFIGURED;
	if (lp->lp_state & LNET_PEER_MULTI_RAIL)
		flags |= LNET_PEER_MULTI_RAIL;

	return lnet_peer_del_nid(lp, nid, flags);
}

void
lnet_destroy_peer_ni_locked(struct lnet_peer_ni *lpni)
{
	struct lnet_peer_table *ptable;
	struct lnet_peer_net *lpn;

	CDEBUG(D_NET, "%p nid %s\n", lpni, libcfs_nid2str(lpni->lpni_nid));

	LASSERT(atomic_read(&lpni->lpni_refcount) == 0);
	LASSERT(lpni->lpni_rtr_refcount == 0);
	LASSERT(list_empty(&lpni->lpni_txq));
	LASSERT(lpni->lpni_txqnob == 0);

	lpn = lpni->lpni_peer_net;
	lpni->lpni_peer_net = NULL;
	lpni->lpni_net = NULL;

	/* remove the peer ni from the zombie list */
	ptable = the_lnet.ln_peer_tables[lpni->lpni_cpt];
	spin_lock(&ptable->pt_zombie_lock);
	list_del_init(&lpni->lpni_hashlist);
	ptable->pt_zombies--;
	spin_unlock(&ptable->pt_zombie_lock);

	if (lpni->lpni_pref_nnids > 1) {
		LIBCFS_FREE(lpni->lpni_pref.nids,
			sizeof(*lpni->lpni_pref.nids) * lpni->lpni_pref_nnids);
	}
	LIBCFS_FREE(lpni, sizeof(*lpni));

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

/*
 * Peer Discovery
 */

/*
 * Is a peer uptodate from the point of view of discovery?
 *
 * If it is currently being processed, obviously not.
 * A forced Ping or Push is also handled by the discovery thread.
 *
 * Otherwise look at whether the peer needs rediscovering.
 */
bool
lnet_peer_is_uptodate(struct lnet_peer *lp)
{
	bool rc;

	spin_lock(&lp->lp_lock);
	if (lp->lp_state & (LNET_PEER_DISCOVERING |
			    LNET_PEER_FORCE_PING |
			    LNET_PEER_FORCE_PUSH)) {
		rc = false;
	} else if (lp->lp_state & LNET_PEER_REDISCOVER) {
		if (lnet_peer_discovery_disabled)
			rc = true;
		else
			rc = false;
	} else if (lp->lp_state & LNET_PEER_DISCOVERED) {
		if (lp->lp_state & LNET_PEER_NIDS_UPTODATE)
			rc = true;
		else
			rc = false;
	} else {
		rc = false;
	}
	spin_unlock(&lp->lp_lock);

	return rc;
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

	return rc;
}

/*
 * Discovery of a peer is complete. Wake all waiters on the peer.
 * Call with lnet_net_lock/EX held.
 */
static void lnet_peer_discovery_complete(struct lnet_peer *lp)
{
	list_del_init(&lp->lp_dc_list);
	wake_up_all(&lp->lp_dc_waitq);
	lnet_peer_decref_locked(lp);
}

/*
 * Peer discovery slow path. The ln_api_mutex is held on entry, and
 * dropped/retaken within this function. An lnet_peer_ni is passed in
 * because discovery could tear down an lnet_peer.
 */
int
lnet_discover_peer_locked(struct lnet_peer_ni *lpni, int cpt)
{
	DEFINE_WAIT(wait);
	struct lnet_peer *lp;
	int rc = 0;

again:
	lnet_net_unlock(cpt);
	lnet_net_lock(LNET_LOCK_EX);

	/* We're willing to be interrupted. */
	for (;;) {
		lp = lpni->lpni_peer_net->lpn_peer;
		prepare_to_wait(&lp->lp_dc_waitq, &wait, TASK_INTERRUPTIBLE);
		if (signal_pending(current))
			break;
		if (the_lnet.ln_dc_state != LNET_DC_STATE_RUNNING)
			break;
		if (lnet_peer_is_uptodate(lp))
			break;
		lnet_peer_queue_for_discovery(lp);
		lnet_peer_addref_locked(lp);
		lnet_net_unlock(LNET_LOCK_EX);
		schedule();
		finish_wait(&lp->lp_dc_waitq, &wait);
		lnet_net_lock(LNET_LOCK_EX);
		lnet_peer_decref_locked(lp);
		/* Do not use lp beyond this point. */
	}
	finish_wait(&lp->lp_dc_waitq, &wait);

	lnet_net_unlock(LNET_LOCK_EX);
	lnet_net_lock(cpt);

	if (signal_pending(current))
		rc = -EINTR;
	else if (the_lnet.ln_dc_state != LNET_DC_STATE_RUNNING)
		rc = -ESHUTDOWN;
	else if (!lnet_peer_is_uptodate(lp))
		goto again;

	return rc;
}

/*
 * Event handler for the discovery EQ.
 *
 * Called with lnet_res_lock(cpt) held. The cpt is the
 * lnet_cpt_of_cookie() of the md handle cookie.
 */
static void lnet_discovery_event_handler(lnet_event_t *event)
{
	wake_up(&the_lnet.ln_dc_waitq);
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
		if (lnet_push_target_resize_needed())
			break;
		if (!list_empty(&the_lnet.ln_dc_request))
			break;
		lnet_net_unlock(cpt);
		schedule();
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

/* The discovery thread. */
static int lnet_peer_discovery(void *arg)
{
	struct lnet_peer *lp;

	CDEBUG(D_NET, "started\n");
	cfs_block_allsigs();

	for (;;) {
		if (lnet_peer_discovery_wait_for_work())
			break;

		if (lnet_push_target_resize_needed())
			lnet_push_target_resize();

		lnet_net_lock(LNET_LOCK_EX);
		if (the_lnet.ln_dc_state == LNET_DC_STATE_STOPPING)
			break;
		while (!list_empty(&the_lnet.ln_dc_request)) {
			lp = list_first_entry(&the_lnet.ln_dc_request,
					      struct lnet_peer, lp_dc_list);
			list_move(&lp->lp_dc_list, &the_lnet.ln_dc_working);
			lnet_net_unlock(LNET_LOCK_EX);

			/* Just tag and release for now. */
			spin_lock(&lp->lp_lock);
			if (lnet_peer_discovery_disabled) {
				lp->lp_state |= LNET_PEER_REDISCOVER;
				lp->lp_state &= ~(LNET_PEER_DISCOVERED |
						  LNET_PEER_NIDS_UPTODATE |
						  LNET_PEER_DISCOVERING);
			} else {
				lp->lp_state |= (LNET_PEER_DISCOVERED |
						 LNET_PEER_NIDS_UPTODATE);
				lp->lp_state &= ~(LNET_PEER_REDISCOVER |
						  LNET_PEER_DISCOVERING);
			}
			spin_unlock(&lp->lp_lock);

			lnet_net_lock(LNET_LOCK_EX);
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
	LNetEQFree(the_lnet.ln_dc_eqh);
	LNetInvalidateEQHandle(&the_lnet.ln_dc_eqh);

	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry(lp, &the_lnet.ln_dc_request, lp_dc_list) {
		spin_lock(&lp->lp_lock);
		lp->lp_state |= LNET_PEER_REDISCOVER;
		lp->lp_state &= ~(LNET_PEER_DISCOVERED |
				  LNET_PEER_DISCOVERING |
				  LNET_PEER_NIDS_UPTODATE);
		spin_unlock(&lp->lp_lock);
		lnet_peer_discovery_complete(lp);
	}
	list_for_each_entry(lp, &the_lnet.ln_dc_working, lp_dc_list) {
		spin_lock(&lp->lp_lock);
		lp->lp_state |= LNET_PEER_REDISCOVER;
		lp->lp_state &= ~(LNET_PEER_DISCOVERED |
				  LNET_PEER_DISCOVERING |
				  LNET_PEER_NIDS_UPTODATE);
		spin_unlock(&lp->lp_lock);
		lnet_peer_discovery_complete(lp);
	}
	lnet_net_unlock(LNET_LOCK_EX);

	the_lnet.ln_dc_state = LNET_DC_STATE_SHUTDOWN;
	wake_up(&the_lnet.ln_dc_waitq);

	CDEBUG(D_NET, "stopped\n");

	return 0;
}

/* ln_api_mutex is held on entry. */
int lnet_peer_discovery_start(void)
{
	struct task_struct *task;
	int rc;

	if (the_lnet.ln_dc_state != LNET_DC_STATE_SHUTDOWN)
		return -EALREADY;

	INIT_LIST_HEAD(&the_lnet.ln_dc_request);
	INIT_LIST_HEAD(&the_lnet.ln_dc_working);
	init_waitqueue_head(&the_lnet.ln_dc_waitq);

	rc = LNetEQAlloc(0, lnet_discovery_event_handler, &the_lnet.ln_dc_eqh);
	if (rc != 0) {
		CERROR("Can't allocate discovery EQ: %d\n", rc);
		return rc;
	}

	the_lnet.ln_dc_state = LNET_DC_STATE_RUNNING;
	task = kthread_run(lnet_peer_discovery, NULL, "lnet_discovery");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("Can't start peer discovery thread: %d\n", rc);

		LNetEQFree(the_lnet.ln_dc_eqh);
		LNetInvalidateEQHandle(&the_lnet.ln_dc_eqh);

		the_lnet.ln_dc_state = LNET_DC_STATE_SHUTDOWN;
	}

	return rc;
}

/* ln_api_mutex is held on entry. */
void lnet_peer_discovery_stop(void)
{
	if (the_lnet.ln_dc_state == LNET_DC_STATE_SHUTDOWN)
		return;

	LASSERT(the_lnet.ln_dc_state == LNET_DC_STATE_RUNNING);
	the_lnet.ln_dc_state = LNET_DC_STATE_STOPPING;
	wake_up(&the_lnet.ln_dc_waitq);

	wait_event(the_lnet.ln_dc_waitq,
		   the_lnet.ln_dc_state == LNET_DC_STATE_SHUTDOWN);

	LASSERT(list_empty(&the_lnet.ln_dc_request));
	LASSERT(list_empty(&the_lnet.ln_dc_working));
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
		aliveness = lp->lpni_alive ? "up" : "down";

	CDEBUG(D_WARNING, "%-24s %4d %5s %5d %5d %5d %5d %5d %ld\n",
	       libcfs_nid2str(lp->lpni_nid), atomic_read(&lp->lpni_refcount),
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
					 lp->lpni_alive ? "up" : "down");

			*nid = lp->lpni_nid;
			*refcount = atomic_read(&lp->lpni_refcount);
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
int lnet_get_peer_info(__u32 idx, lnet_nid_t *primary_nid, lnet_nid_t *nid,
		       bool *mr,
		       struct lnet_peer_ni_credit_info __user *peer_ni_info,
		       struct lnet_ioctl_element_stats __user *peer_ni_stats)
{
	struct lnet_peer_ni *lpni = NULL;
	struct lnet_peer_net *lpn = NULL;
	struct lnet_peer *lp = NULL;
	struct lnet_peer_ni_credit_info ni_info;
	struct lnet_ioctl_element_stats ni_stats;
	int rc;

	lpni = lnet_get_peer_ni_idx_locked(idx, &lpn, &lp);

	if (!lpni)
		return -ENOENT;

	*primary_nid = lp->lp_primary_nid;
	*mr = lnet_peer_is_multi_rail(lp);
	*nid = lpni->lpni_nid;
	snprintf(ni_info.cr_aliveness, LNET_MAX_STR_LEN, "NA");
	if (lnet_isrouter(lpni) ||
		lnet_peer_aliveness_enabled(lpni))
		snprintf(ni_info.cr_aliveness, LNET_MAX_STR_LEN,
			 lpni->lpni_alive ? "up" : "down");

	ni_info.cr_refcount = atomic_read(&lpni->lpni_refcount);
	ni_info.cr_ni_peer_tx_credits = (lpni->lpni_net != NULL) ?
		lpni->lpni_net->net_tunables.lct_peer_tx_credits : 0;
	ni_info.cr_peer_tx_credits = lpni->lpni_txcredits;
	ni_info.cr_peer_rtr_credits = lpni->lpni_rtrcredits;
	ni_info.cr_peer_min_rtr_credits = lpni->lpni_minrtrcredits;
	ni_info.cr_peer_min_tx_credits = lpni->lpni_mintxcredits;
	ni_info.cr_peer_tx_qnob = lpni->lpni_txqnob;
	ni_info.cr_ncpt = lpni->lpni_cpt;

	ni_stats.iel_send_count = atomic_read(&lpni->lpni_stats.send_count);
	ni_stats.iel_recv_count = atomic_read(&lpni->lpni_stats.recv_count);
	ni_stats.iel_drop_count = atomic_read(&lpni->lpni_stats.drop_count);

	/* If copy_to_user fails */
	rc = -EFAULT;
	if (copy_to_user(peer_ni_info, &ni_info, sizeof(ni_info)))
		goto copy_failed;

	if (copy_to_user(peer_ni_stats, &ni_stats, sizeof(ni_stats)))
		goto copy_failed;

	rc = 0;

copy_failed:
	return rc;
}
