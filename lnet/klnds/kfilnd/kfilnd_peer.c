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
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * kfilnd peer management implementation.
 */
#include "kfilnd_peer.h"
#include "kfilnd_dev.h"

static const struct rhashtable_params peer_cache_params = {
	.head_offset = offsetof(struct kfilnd_peer, node),
	.key_offset = offsetof(struct kfilnd_peer, nid),
	.key_len = sizeof_field(struct kfilnd_peer, nid),
	.automatic_shrinking = true,
};

/**
 * kfilnd_peer_free() - RCU safe way to free a peer.
 * @ptr: Pointer to peer.
 * @arg: Unused.
 */
static void kfilnd_peer_free(void *ptr, void *arg)
{
	struct kfilnd_peer *peer = ptr;

	CDEBUG(D_NET, "%s(0x%llx) peer entry freed\n",
	       libcfs_nid2str(peer->nid), peer->addr);

	kfi_av_remove(peer->dev->kfd_av, &peer->addr, 1, 0);

	kfree_rcu(peer, rcu_head);
}

/**
 * kfilnd_peer_down() - Mark a peer as down.
 * @peer: Peer to be downed.
 */
void kfilnd_peer_down(struct kfilnd_peer *peer)
{
	if (atomic_cmpxchg(&peer->remove_peer, 0, 1) == 0) {
		CDEBUG(D_NET, "%s(0x%llx) marked for removal from peer cache\n",
		       libcfs_nid2str(peer->nid), peer->addr);

		lnet_notify(peer->dev->kfd_ni, peer->nid, false, false,
			    peer->last_alive);
	}
}

/**
 * kfilnd_peer_put() - Return a reference for a peer.
 * @peer: Peer where the reference should be returned.
 */
void kfilnd_peer_put(struct kfilnd_peer *peer)
{
	rcu_read_lock();

	/* Return allocation reference if the peer was marked for removal. */
	if (atomic_cmpxchg(&peer->remove_peer, 1, 2) == 1) {
		rhashtable_remove_fast(&peer->dev->peer_cache, &peer->node,
				       peer_cache_params);
		refcount_dec(&peer->cnt);

		CDEBUG(D_NET, "%s(0x%llx) removed from peer cache\n",
		       libcfs_nid2str(peer->nid), peer->addr);
	}

	if (refcount_dec_and_test(&peer->cnt))
		kfilnd_peer_free(peer, NULL);

	rcu_read_unlock();
}

u16 kfilnd_peer_target_rx_base(struct kfilnd_peer *peer)
{
	int cpt = lnet_cpt_of_nid(peer->nid, peer->dev->kfd_ni);
	struct kfilnd_ep *ep = peer->dev->cpt_to_endpoint[cpt];

	return ep->end_context_id;
}

/**
 * kfilnd_peer_get() - Get a reference for a peer.
 * @dev: Device used to lookup peer.
 * @nid: LNet NID of peer.
 *
 * Return: On success, pointer to a valid peer structed. Else, ERR_PTR.
 */
struct kfilnd_peer *kfilnd_peer_get(struct kfilnd_dev *dev, lnet_nid_t nid)
{
	char *node;
	char *service;
	int rc;
	u32 nid_addr = LNET_NIDADDR(nid);
	u32 net_num = LNET_NETNUM(LNET_NIDNET(nid));
	struct kfilnd_peer *peer;
	struct kfilnd_peer *clash_peer;

again:
	/* Check the cache for a match. */
	rcu_read_lock();
	peer = rhashtable_lookup_fast(&dev->peer_cache, &nid,
				      peer_cache_params);
	if (peer && !refcount_inc_not_zero(&peer->cnt))
		peer = NULL;
	rcu_read_unlock();

	if (peer)
		return peer;

	/* Allocate a new peer for the cache. */
	peer = kzalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer) {
		rc = -ENOMEM;
		goto err;
	}

	node = kasprintf(GFP_KERNEL, "%#x", nid_addr);
	if (!node) {
		rc = -ENOMEM;
		goto err_free_peer;
	}

	service = kasprintf(GFP_KERNEL, "%u", net_num);
	if (!service) {
		rc = -ENOMEM;
		goto err_free_node_str;
	}

	/* Use the KFI address vector to translate node and service string into
	 * a KFI address handle.
	 */
	rc = kfi_av_insertsvc(dev->kfd_av, node, service, &peer->addr, 0, dev);

	kfree(service);
	kfree(node);

	if (rc < 0) {
		goto err_free_peer;
	} else if (rc != 1) {
		rc = -ECONNABORTED;
		goto err_free_peer;
	}

	peer->dev = dev;
	peer->nid = nid;
	atomic_set(&peer->rx_base, 0);
	atomic_set(&peer->remove_peer, 0);
	peer->local_session_key = kfilnd_dev_get_session_key(dev);

	/* One reference for the allocation and another for get operation
	 * performed for this peer. The allocation reference is returned when
	 * the entry is marked for removal.
	 */
	refcount_set(&peer->cnt, 2);

	clash_peer = rhashtable_lookup_get_insert_fast(&dev->peer_cache,
						       &peer->node,
						       peer_cache_params);

	if (clash_peer) {
		kfi_av_remove(dev->kfd_av, &peer->addr, 1, 0);
		kfree(peer);

		if (IS_ERR(clash_peer)) {
			rc = PTR_ERR(clash_peer);
			goto err;
		} else {
			goto again;
		}
	}

	kfilnd_peer_alive(peer);

	CDEBUG(D_NET, "%s(0x%llx) peer entry allocated\n",
	       libcfs_nid2str(peer->nid), peer->addr);

	return peer;

err_free_node_str:
	kfree(node);
err_free_peer:
	kfree(peer);
err:
	return ERR_PTR(rc);
}

/**
 * kfilnd_peer_get_kfi_addr() - Return kfi_addr_t used for eager untagged send
 * kfi operations.
 * @peer: Peer struct.
 *
 * The returned kfi_addr_t is updated to target a specific RX context. The
 * address return by this function should not be used if a specific RX context
 * needs to be targeted (i/e the response RX context for a bulk transfer
 * operation).
 *
 * Return: kfi_addr_t.
 */
kfi_addr_t kfilnd_peer_get_kfi_addr(struct kfilnd_peer *peer)
{
	/* TODO: Support RX count by round-robining the generated kfi_addr_t's
	 * across multiple RX contexts using RX base and RX count.
	 */
	return kfi_rx_addr(KFILND_BASE_ADDR(peer->addr),
			   atomic_read(&peer->rx_base), KFILND_FAB_RX_CTX_BITS);
}

/**
 * kfilnd_peer_update_rx_contexts() - Update the RX context for a peer.
 * @peer: Peer to be updated.
 * @rx_base: New RX base for peer.
 * @rx_count: New RX count for peer.
 */
void kfilnd_peer_update_rx_contexts(struct kfilnd_peer *peer,
				    unsigned int rx_base, unsigned int rx_count)
{
	/* TODO: Support RX count. */
	LASSERT(rx_count > 0);
	atomic_set(&peer->rx_base, rx_base);
}

/**
 * kfilnd_peer_alive() - Update when the peer was last alive.
 * @peer: Peer to be updated.
 */
void kfilnd_peer_alive(struct kfilnd_peer *peer)
{
	peer->last_alive = ktime_get_seconds();

	/* Ensure timestamp is committed to memory before used. */
	smp_mb();
}

/**
 * kfilnd_peer_destroy() - Destroy peer cache.
 * @dev: Device peer cache to be destroyed.
 */
void kfilnd_peer_destroy(struct kfilnd_dev *dev)
{
	rhashtable_free_and_destroy(&dev->peer_cache, kfilnd_peer_free, NULL);
}

/**
 * kfilnd_peer_init() - Initialize peer cache.
 * @dev: Device peer cache to be initialized.
 */
void kfilnd_peer_init(struct kfilnd_dev *dev)
{
	rhashtable_init(&dev->peer_cache, &peer_cache_params);
}
