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
#include <lnet/lib-dlc.h>

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
	INIT_LIST_HEAD(&lpni->lpni_on_peer_net_list);
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

	/* TODO: update flags */

	return lpni;
}

static struct lnet_peer_net *
lnet_peer_net_alloc(__u32 net_id)
{
	struct lnet_peer_net *lpn;

	LIBCFS_CPT_ALLOC(lpn, lnet_cpt_table(), CFS_CPT_ANY, sizeof(*lpn));
	if (!lpn)
		return NULL;

	INIT_LIST_HEAD(&lpn->lpn_on_peer_list);
	INIT_LIST_HEAD(&lpn->lpn_peer_nis);
	lpn->lpn_net_id = net_id;

	return lpn;
}

static struct lnet_peer *
lnet_peer_alloc(lnet_nid_t nid)
{
	struct lnet_peer *lp;

	LIBCFS_CPT_ALLOC(lp, lnet_cpt_table(), CFS_CPT_ANY, sizeof(*lp));
	if (!lp)
		return NULL;

	INIT_LIST_HEAD(&lp->lp_on_lnet_peer_list);
	INIT_LIST_HEAD(&lp->lp_peer_nets);
	lp->lp_primary_nid = nid;

	/* TODO: update flags */

	return lp;
}


static void
lnet_try_destroy_peer_hierarchy_locked(struct lnet_peer_ni *lpni)
{
	struct lnet_peer_net *peer_net;
	struct lnet_peer *peer;

	/* TODO: could the below situation happen? accessing an already
	 * destroyed peer? */
	if (lpni->lpni_peer_net == NULL ||
	    lpni->lpni_peer_net->lpn_peer == NULL)
		return;

	peer_net = lpni->lpni_peer_net;
	peer = lpni->lpni_peer_net->lpn_peer;

	list_del_init(&lpni->lpni_on_peer_net_list);
	lpni->lpni_peer_net = NULL;

	/* if peer_net is empty, then remove it from the peer */
	if (list_empty(&peer_net->lpn_peer_nis)) {
		list_del_init(&peer_net->lpn_on_peer_list);
		peer_net->lpn_peer = NULL;
		LIBCFS_FREE(peer_net, sizeof(*peer_net));

		/* if the peer is empty then remove it from the
		 * the_lnet.ln_peers */
		if (list_empty(&peer->lp_peer_nets)) {
			list_del_init(&peer->lp_on_lnet_peer_list);
			LIBCFS_FREE(peer, sizeof(*peer));
		}
	}
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
	LASSERT(atomic_read(&ptable->pt_number) > 0);
	atomic_dec(&ptable->pt_number);

	/*
	 * The peer_ni can no longer be found with a lookup. But there
	 * can be current users, so keep track of it on the zombie
	 * list until the reference count has gone to zero.
	 *
	 * The last reference may be lost in a place where the
	 * lnet_net_lock locks only a single cpt, and that cpt may not
	 * be lpni->lpni_cpt. So the zombie list of this peer_table
	 * has its own lock.
	 */
	spin_lock(&ptable->pt_zombie_lock);
	list_add(&lpni->lpni_hashlist, &ptable->pt_zombie_list);
	ptable->pt_zombies++;
	spin_unlock(&ptable->pt_zombie_lock);

	/* no need to keep this peer on the hierarchy anymore */
	lnet_try_destroy_peer_hierarchy_locked(lpni);

	/* decrement reference on peer */
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

struct lnet_peer *
lnet_find_or_create_peer_locked(lnet_nid_t dst_nid, int cpt)
{
	struct lnet_peer_ni *lpni;
	struct lnet_peer *lp;

	lpni = lnet_find_peer_ni_locked(dst_nid);
	if (!lpni) {
		lpni = lnet_nid2peerni_locked(dst_nid, cpt);
		if (IS_ERR(lpni))
			return ERR_CAST(lpni);
	}

	lp = lpni->lpni_peer_net->lpn_peer;
	lnet_peer_ni_decref_locked(lpni);

	return lp;
}

struct lnet_peer_ni *
lnet_get_peer_ni_idx_locked(int idx, struct lnet_peer_net **lpn,
			    struct lnet_peer **lp)
{
	struct lnet_peer_ni	*lpni;

	list_for_each_entry((*lp), &the_lnet.ln_peers, lp_on_lnet_peer_list) {
		list_for_each_entry((*lpn), &((*lp)->lp_peer_nets), lpn_on_peer_list) {
			list_for_each_entry(lpni, &((*lpn)->lpn_peer_nis),
					    lpni_on_peer_net_list)
				if (idx-- == 0)
					return lpni;
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
		if (!net)
			net = list_entry(peer->lp_peer_nets.next,
					 struct lnet_peer_net,
					 lpn_on_peer_list);
		lpni = list_entry(net->lpn_peer_nis.next, struct lnet_peer_ni,
				  lpni_on_peer_net_list);

		return lpni;
	}

	if (prev->lpni_on_peer_net_list.next ==
	    &prev->lpni_peer_net->lpn_peer_nis) {
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
		if (prev->lpni_peer_net->lpn_on_peer_list.next ==
		    &peer->lp_peer_nets)
			/* no more nets and no more NIs. */
			return NULL;

		/* get the next net */
		net = list_entry(prev->lpni_peer_net->lpn_on_peer_list.next,
				 struct lnet_peer_net,
				 lpn_on_peer_list);
		/* get the ni on it */
		lpni = list_entry(net->lpn_peer_nis.next, struct lnet_peer_ni,
				  lpni_on_peer_net_list);

		return lpni;
	}

	/* there are more nis left */
	lpni = list_entry(prev->lpni_on_peer_net_list.next,
			  struct lnet_peer_ni, lpni_on_peer_net_list);

	return lpni;
}

bool
lnet_peer_is_ni_pref_locked(struct lnet_peer_ni *lpni, struct lnet_ni *ni)
{
	int i;

	for (i = 0; i < lpni->lpni_pref_nnids; i++) {
		if (lpni->lpni_pref_nids[i] == ni->ni_nid)
			return true;
	}
	return false;
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
	lpni = lnet_nid2peerni_locked(nid, cpt);
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
	list_for_each_entry(peer_net, &peer->lp_peer_nets, lpn_on_peer_list) {
		if (peer_net->lpn_net_id == net_id)
			return peer_net;
	}
	return NULL;
}

static int
lnet_peer_setup_hierarchy(struct lnet_peer *lp, struct lnet_peer_ni *lpni,
			  lnet_nid_t nid)
{
	struct lnet_peer_net *lpn = NULL;
	struct lnet_peer_table *ptable;
        __u32 net_id = LNET_NIDNET(nid);

	/*
	 * Create the peer_ni, peer_net, and peer if they don't exist
	 * yet.
	 */
	if (lp) {
		lpn = lnet_peer_get_net_locked(lp, net_id);
	} else {
		lp = lnet_peer_alloc(nid);
		if (!lp)
			goto out_enomem;
	}

	if (!lpn) {
		lpn = lnet_peer_net_alloc(net_id);
		if (!lpn)
			goto out_maybe_free_lp;
	}

	if (!lpni) {
		lpni = lnet_peer_ni_alloc(nid);
		if (!lpni)
			goto out_maybe_free_lpn;
	}

	/* Install the new peer_ni */
	lnet_net_lock(LNET_LOCK_EX);
	/* Add peer_ni to global peer table hash, if necessary. */
	if (list_empty(&lpni->lpni_hashlist)) {
		ptable = the_lnet.ln_peer_tables[lpni->lpni_cpt];
		list_add_tail(&lpni->lpni_hashlist,
			      &ptable->pt_hash[lnet_nid2peerhash(nid)]);
		ptable->pt_version++;
		atomic_inc(&ptable->pt_number);
		atomic_inc(&lpni->lpni_refcount);
	}

	/* Detach the peer_ni from an existing peer, if necessary. */
	if (lpni->lpni_peer_net && lpni->lpni_peer_net->lpn_peer != lp)
		lnet_try_destroy_peer_hierarchy_locked(lpni);

	/* Add peer_ni to peer_net */
	lpni->lpni_peer_net = lpn;
	list_add_tail(&lpni->lpni_on_peer_net_list, &lpn->lpn_peer_nis);

	/* Add peer_net to peer */
	if (!lpn->lpn_peer) {
		lpn->lpn_peer = lp;
		list_add_tail(&lpn->lpn_on_peer_list, &lp->lp_peer_nets);
	}

	/* Add peer to global peer list */
	if (list_empty(&lp->lp_on_lnet_peer_list))
		list_add_tail(&lp->lp_on_lnet_peer_list, &the_lnet.ln_peers);
	lnet_net_unlock(LNET_LOCK_EX);

	return 0;

out_maybe_free_lpn:
	if (list_empty(&lpn->lpn_on_peer_list))
		LIBCFS_FREE(lpn, sizeof(*lpn));
out_maybe_free_lp:
	if (list_empty(&lp->lp_on_lnet_peer_list))
		LIBCFS_FREE(lp, sizeof(*lp));
out_enomem:
	return -ENOMEM;
}

static int
lnet_add_prim_lpni(lnet_nid_t nid)
{
	int rc = 0;
	struct lnet_peer *peer;
	struct lnet_peer_ni *lpni;

	LASSERT(nid != LNET_NID_ANY);

	/*
	 * lookup the NID and its peer
	 *  if the peer doesn't exist, create it.
	 *  if this is a non-MR peer then change its state to MR and exit.
	 *  if this is an MR peer and it's a primary NI: NO-OP.
	 *  if this is an MR peer and it's not a primary NI. Operation not
	 *     allowed.
	 *
	 * The adding and deleting of peer nis is being serialized through
	 * the api_mutex. So we can look up peers with the mutex locked
	 * safely. Only when we need to change the ptable, do we need to
	 * exclusively lock the lnet_net_lock()
	 */
	lpni = lnet_find_peer_ni_locked(nid);
	if (!lpni) {
		rc = lnet_peer_setup_hierarchy(NULL, NULL, nid);
		if (rc != 0)
			return rc;
		lpni = lnet_find_peer_ni_locked(nid);
	}

	LASSERT(lpni);

	lnet_peer_ni_decref_locked(lpni);

	peer = lpni->lpni_peer_net->lpn_peer;

	/*
	 * If we found a lpni with the same nid as the NID we're trying to
	 * create, then we're trying to create an already existing lpni 
	 * that belongs to a different peer
	 */
	if (peer->lp_primary_nid != nid)
		return -EEXIST;

	/*
	 * if we found an lpni that is not a multi-rail, which could occur
	 * if lpni is already created as a non-mr lpni or we just created
	 * it, then make sure you indicate that this lpni is a primary mr
	 * capable peer.
	 *
	 * TODO: update flags if necessary
	 */
	if (!peer->lp_multi_rail && peer->lp_primary_nid == nid)
		peer->lp_multi_rail = true;

	return rc;
}

static int
lnet_add_peer_ni_to_prim_lpni(lnet_nid_t prim_nid, lnet_nid_t nid)
{
	struct lnet_peer *peer, *primary_peer;
	struct lnet_peer_ni *lpni = NULL, *klpni = NULL;

	LASSERT(prim_nid != LNET_NID_ANY && nid != LNET_NID_ANY);

	/*
	 * key nid must be created by this point. If not then this
	 * operation is not permitted
	 */
	klpni = lnet_find_peer_ni_locked(prim_nid);
	if (!klpni)
		return -ENOENT;

	lnet_peer_ni_decref_locked(klpni);

	primary_peer = klpni->lpni_peer_net->lpn_peer;

	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni) {
		lnet_peer_ni_decref_locked(lpni);

		peer = lpni->lpni_peer_net->lpn_peer;
		/*
		 * lpni already exists in the system but it belongs to
		 * a different peer. We can't re-added it
		 */
		if (peer->lp_primary_nid != prim_nid && peer->lp_multi_rail) {
			CERROR("Cannot add NID %s owned by peer %s to peer %s\n",
			       libcfs_nid2str(lpni->lpni_nid),
			       libcfs_nid2str(peer->lp_primary_nid),
			       libcfs_nid2str(prim_nid));
			return -EEXIST;
		} else if (peer->lp_primary_nid == prim_nid) {
			/*
			 * found a peer_ni that is already part of the
			 * peer. This is a no-op operation.
			 */
			return 0;
		}

		/*
		 * TODO: else if (peer->lp_primary_nid != prim_nid &&
		 *		  !peer->lp_multi_rail)
		 * peer is not an MR peer and it will be moved in the next
		 * step to klpni, so update its flags accordingly.
		 * lnet_move_peer_ni()
		 */

		/*
		 * TODO: call lnet_update_peer() from here to update the
		 * flags. This is the case when the lpni you're trying to
		 * add is already part of the peer. This could've been
		 * added by the DD previously, so go ahead and do any
		 * updates to the state if necessary
		 */

	}

	/*
	 * When we get here we either have found an existing lpni, which
	 * we can switch to the new peer. Or we need to create one and
	 * add it to the new peer
	 */
	return lnet_peer_setup_hierarchy(primary_peer, lpni, nid);
}

/*
 * lpni creation initiated due to traffic either sending or receiving.
 */
static int
lnet_peer_ni_traffic_add(lnet_nid_t nid)
{
	struct lnet_peer_ni *lpni;
	int rc = 0;

	if (nid == LNET_NID_ANY)
		return -EINVAL;

	/* lnet_net_lock is not needed here because ln_api_lock is held */
	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni) {
		/*
		 * TODO: lnet_update_primary_nid() but not all of it
		 * only indicate if we're converting this to MR capable
		 * Can happen due to DD
		 */
		lnet_peer_ni_decref_locked(lpni);
	} else {
		rc = lnet_peer_setup_hierarchy(NULL, NULL, nid);
	}

	return rc;

}

static int
lnet_peer_ni_add_non_mr(lnet_nid_t nid)
{
	struct lnet_peer_ni *lpni;

	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni) {
		CERROR("Cannot add %s as non-mr when it already exists\n",
		       libcfs_nid2str(nid));
		lnet_peer_ni_decref_locked(lpni);
		return -EEXIST;
	}

	return lnet_peer_setup_hierarchy(NULL, NULL, nid);
}

/*
 * This API handles the following combinations:
 *	Create a primary NI if only the prim_nid is provided
 *	Create or add an lpni to a primary NI. Primary NI must've already
 *	been created
 *	Create a non-MR peer.
 */
int
lnet_add_peer_ni_to_peer(lnet_nid_t prim_nid, lnet_nid_t nid, bool mr)
{
	/*
	 * Caller trying to setup an MR like peer hierarchy but
	 * specifying it to be non-MR. This is not allowed.
	 */
	if (prim_nid != LNET_NID_ANY &&
	    nid != LNET_NID_ANY && !mr)
		return -EPERM;

	/* Add the primary NID of a peer */
	if (prim_nid != LNET_NID_ANY &&
	    nid == LNET_NID_ANY && mr)
		return lnet_add_prim_lpni(prim_nid);

	/* Add a NID to an existing peer */
	if (prim_nid != LNET_NID_ANY &&
	    nid != LNET_NID_ANY && mr)
		return lnet_add_peer_ni_to_prim_lpni(prim_nid, nid);

	/* Add a non-MR peer NI */
	if (((prim_nid != LNET_NID_ANY &&
	      nid == LNET_NID_ANY) ||
	     (prim_nid == LNET_NID_ANY &&
	      nid != LNET_NID_ANY)) && !mr)
		return lnet_peer_ni_add_non_mr(prim_nid != LNET_NID_ANY ?
							 prim_nid : nid);

	return 0;
}

int
lnet_del_peer_ni_from_peer(lnet_nid_t prim_nid, lnet_nid_t nid)
{
	lnet_nid_t local_nid;
	struct lnet_peer *peer;
	struct lnet_peer_ni *lpni;
	int rc;

	if (prim_nid == LNET_NID_ANY)
		return -EINVAL;

	local_nid = (nid != LNET_NID_ANY) ? nid : prim_nid;

	lpni = lnet_find_peer_ni_locked(local_nid);
	if (!lpni)
		return -EINVAL;
	lnet_peer_ni_decref_locked(lpni);

	peer = lpni->lpni_peer_net->lpn_peer;
	LASSERT(peer != NULL);

	if (peer->lp_primary_nid == lpni->lpni_nid) {
		/*
		 * deleting the primary ni is equivalent to deleting the
		 * entire peer
		 */
		lnet_net_lock(LNET_LOCK_EX);
		rc = lnet_peer_del_locked(peer);
		lnet_net_unlock(LNET_LOCK_EX);

		return rc;
	}

	lnet_net_lock(LNET_LOCK_EX);
	rc = lnet_peer_ni_del_locked(lpni);
	lnet_net_unlock(LNET_LOCK_EX);

	return rc;
}

void
lnet_destroy_peer_ni_locked(struct lnet_peer_ni *lpni)
{
	struct lnet_peer_table *ptable;

	LASSERT(atomic_read(&lpni->lpni_refcount) == 0);
	LASSERT(lpni->lpni_rtr_refcount == 0);
	LASSERT(list_empty(&lpni->lpni_txq));
	LASSERT(lpni->lpni_txqnob == 0);

	lpni->lpni_net = NULL;

	/* remove the peer ni from the zombie list */
	ptable = the_lnet.ln_peer_tables[lpni->lpni_cpt];
	spin_lock(&ptable->pt_zombie_lock);
	list_del_init(&lpni->lpni_hashlist);
	ptable->pt_zombies--;
	spin_unlock(&ptable->pt_zombie_lock);

	LIBCFS_FREE(lpni, sizeof(*lpni));
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

	rc = lnet_peer_ni_traffic_add(nid);
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

struct lnet_peer_ni *
lnet_nid2peerni_locked(lnet_nid_t nid, int cpt)
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

	rc = lnet_peer_ni_traffic_add(nid);
	if (rc) {
		lpni = ERR_PTR(rc);
		goto out_mutex_unlock;
	}

	lpni = lnet_find_peer_ni_locked(nid);
	LASSERT(lpni);

out_mutex_unlock:
	mutex_unlock(&the_lnet.ln_api_mutex);
	lnet_net_lock(cpt);

	return lpni;
}

void
lnet_debug_peer(lnet_nid_t nid)
{
	char			*aliveness = "NA";
	struct lnet_peer_ni	*lp;
	int			cpt;

	cpt = lnet_cpt_of_nid(nid, NULL);
	lnet_net_lock(cpt);

	lp = lnet_nid2peerni_locked(nid, cpt);
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
	*mr = lp->lp_multi_rail;
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
