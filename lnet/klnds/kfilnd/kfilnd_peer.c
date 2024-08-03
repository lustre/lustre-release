// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * kfilnd peer management implementation.
 */

#include "kfilnd_peer.h"
#include "kfilnd_dev.h"

static const struct rhashtable_params peer_cache_params = {
	.head_offset = offsetof(struct kfilnd_peer, kp_node),
	.key_offset = offsetof(struct kfilnd_peer, kp_nid),
	.key_len = sizeof_field(struct kfilnd_peer, kp_nid),
	.automatic_shrinking = true,
};

/**
 * kfilnd_peer_free() - RCU safe way to free a peer.
 * @ptr: Pointer to peer.
 * @arg: Unused.
 */
static void kfilnd_peer_free(void *ptr, void *arg)
{
	struct kfilnd_peer *kp = ptr;

	CDEBUG(D_NET, "%s(%p):0x%llx peer entry freed\n",
	       libcfs_nid2str(kp->kp_nid), kp, kp->kp_addr);

	kfi_av_remove(kp->kp_dev->kfd_av, &kp->kp_addr, 1, 0);

	kfree_rcu(kp, kp_rcu_head);
}

/**
 * kfilnd_peer_del() - Delete a peer from the peer cache. kp_remove_peer is used
 * to prevent more than one thread from deleting the peer at once, and it
 * informs threads on the allocation path that this peer is being deleted. When
 * the peer is removed from the peer cache its allocation reference is returned
 * and lnet is notified that this peer is down.
 * @kp: Peer to be deleted
 */
static void kfilnd_peer_del(struct kfilnd_peer *kp)
{

	rcu_read_lock();

	if (atomic_cmpxchg(&kp->kp_remove_peer, 0, 1) == 0) {
		struct lnet_nid peer_nid;

		rhashtable_remove_fast(&kp->kp_dev->peer_cache, &kp->kp_node,
				       peer_cache_params);
		/* Return allocation reference */
		refcount_dec(&kp->kp_cnt);

		rcu_read_unlock();

		lnet_nid4_to_nid(kp->kp_nid, &peer_nid);
		CDEBUG(D_NET, "%s(%p):0x%llx removed from peer cache\n",
		       libcfs_nidstr(&peer_nid), kp, kp->kp_addr);

		lnet_notify(kp->kp_dev->kfd_ni, &peer_nid, false, false,
			    kp->kp_last_alive);
	} else {
		rcu_read_unlock();
	}
}

/**
 * kfilnd_peer_purge_old_peer() - Delete the specified peer from the cache
 * if we haven't heard from it within 5x LND timeouts.
 * @kp: The peer to be checked or purged
 */
static void kfilnd_peer_purge_old_peer(struct kfilnd_peer *kp)
{
	if (ktime_after(ktime_get_seconds(),
			kp->kp_last_alive + (lnet_get_lnd_timeout() * 5))) {
		CDEBUG(D_NET,
		       "Haven't heard from %s(%p):0x%llx in %lld seconds\n",
		       libcfs_nid2str(kp->kp_nid), kp, kp->kp_addr,
		       ktime_sub(ktime_get_seconds(), kp->kp_last_alive));
		kfilnd_peer_del(kp);
	}
}

/**
 * kfilnd_peer_stale() - Mark a peer as stale. If the peer is already stale then
 * check whether it should be deleted.
 * @kp: Peer to be marked stale
 * Note: only "up-to-date" peers can be marked stale.
 */
static void kfilnd_peer_stale(struct kfilnd_peer *kp)
{
	if (atomic_cmpxchg(&kp->kp_state,
			   KP_STATE_UPTODATE,
			   KP_STATE_STALE) == KP_STATE_UPTODATE) {
		CDEBUG(D_NET, "%s(%p):0x%llx uptodate -> stale\n",
		       libcfs_nid2str(kp->kp_nid), kp, kp->kp_addr);
	} else {
		kfilnd_peer_purge_old_peer(kp);
	}
}

/**
 * kfilnd_peer_down() - Mark a peer as down. If the peer is already down then
 * check whether it should be deleted.
 * @kp: Peer to be marked down
 * Note: Only peers that are "up-to-date" or "stale" can be marked down.
 */
static void kfilnd_peer_down(struct kfilnd_peer *kp)
{
	if (atomic_read(&kp->kp_state) == KP_STATE_DOWN) {
		kfilnd_peer_purge_old_peer(kp);
	} else if (atomic_cmpxchg(&kp->kp_state,
				  KP_STATE_UPTODATE,
				  KP_STATE_DOWN) == KP_STATE_UPTODATE) {
		CDEBUG(D_NET, "%s(%p):0x%llx uptodate -> down\n",
		       libcfs_nid2str(kp->kp_nid), kp, kp->kp_addr);
	} else if (atomic_cmpxchg(&kp->kp_state,
				  KP_STATE_STALE,
				  KP_STATE_DOWN) == KP_STATE_STALE) {
		CDEBUG(D_NET, "%s(%p):0x%llx stale -> down\n",
		       libcfs_nid2str(kp->kp_nid), kp, kp->kp_addr);
	}
}

/**
 * kfilnd_peer_tn_failed() - A transaction with this peer has failed. Mark the
 * peer as either stale or down depending on the provided error value. If
 * @delete is true we also delete the peer from the cache.
 * @kp: The peer to be marked down, stale, or deleted.
 * @error: An errno indicating why the transaction failed.
 * @delete: Whether to delete the peer
 * Note: We currently only consider EHOSTUNREACH which corresponds to
 * C_RC_UNDELIVERABLE, and ENOTCONN which corresponds to C_RC_VNI_NOT_FOUND.
 */
void kfilnd_peer_tn_failed(struct kfilnd_peer *kp, int error, bool delete)
{
	if (error == -EHOSTUNREACH || error == -ENOTCONN)
		kfilnd_peer_down(kp);
	else
		kfilnd_peer_stale(kp);

	if (delete)
		kfilnd_peer_del(kp);
}

/**
 * kfilnd_peer_put() - Return a reference for a peer.
 * @kp: Peer where the reference should be returned.
 */
void kfilnd_peer_put(struct kfilnd_peer *kp)
{
	if (refcount_dec_and_test(&kp->kp_cnt))
		kfilnd_peer_free(kp, NULL);
}

u16 kfilnd_peer_target_rx_base(struct kfilnd_peer *kp)
{
	int cpt = lnet_cpt_of_nid(kp->kp_nid, kp->kp_dev->kfd_ni);
	struct kfilnd_ep *ep = kp->kp_dev->cpt_to_endpoint[cpt];

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
	struct kfilnd_peer *kp;
	struct kfilnd_peer *clash_peer;

again:
	/* Check the cache for a match. */
	rcu_read_lock();
	kp = rhashtable_lookup_fast(&dev->peer_cache, &nid,
				      peer_cache_params);
	if (kp && !refcount_inc_not_zero(&kp->kp_cnt))
		kp = NULL;
	rcu_read_unlock();

	if (kp) {
		if (atomic_read(&kp->kp_remove_peer)) {
			kfilnd_peer_put(kp);
			goto again;
		}

		return kp;
	}

	/* Allocate a new peer for the cache. */
	kp = kzalloc(sizeof(*kp), GFP_KERNEL);
	if (!kp) {
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
	rc = kfi_av_insertsvc(dev->kfd_av, node, service, &kp->kp_addr, 0, dev);

	kfree(service);
	kfree(node);

	if (rc < 0) {
		goto err_free_peer;
	} else if (rc != 1) {
		rc = -ECONNABORTED;
		goto err_free_peer;
	}

	kp->kp_dev = dev;
	kp->kp_nid = nid;
	atomic_set(&kp->kp_rx_base, 0);
	atomic_set(&kp->kp_remove_peer, 0);
	atomic_set(&kp->kp_hello_state, KP_HELLO_NONE);
	atomic_set(&kp->kp_state, KP_STATE_NEW);
	kp->kp_local_session_key = kfilnd_dev_get_session_key(dev);
	kp->kp_hello_ts = ktime_get_seconds();

	/* One reference for the allocation and another for get operation
	 * performed for this peer. The allocation reference is returned when
	 * the entry is marked for removal.
	 */
	refcount_set(&kp->kp_cnt, 2);

	clash_peer = rhashtable_lookup_get_insert_fast(&dev->peer_cache,
						       &kp->kp_node,
						       peer_cache_params);

	if (clash_peer) {
		kfi_av_remove(dev->kfd_av, &kp->kp_addr, 1, 0);
		kfree(kp);

		if (IS_ERR(clash_peer)) {
			rc = PTR_ERR(clash_peer);
			goto err;
		} else {
			goto again;
		}
	}

	kfilnd_peer_alive(kp);

	CDEBUG(D_NET, "%s(%p):0x%llx peer entry allocated\n",
	       libcfs_nid2str(kp->kp_nid), kp, kp->kp_addr);

	return kp;

err_free_node_str:
	kfree(node);
err_free_peer:
	kfree(kp);
err:
	return ERR_PTR(rc);
}

/**
 * kfilnd_peer_get_kfi_addr() - Return kfi_addr_t used for eager untagged send
 * kfi operations.
 * @kp: Peer struct.
 *
 * The returned kfi_addr_t is updated to target a specific RX context. The
 * address return by this function should not be used if a specific RX context
 * needs to be targeted (i/e the response RX context for a bulk transfer
 * operation).
 *
 * Return: kfi_addr_t.
 */
kfi_addr_t kfilnd_peer_get_kfi_addr(struct kfilnd_peer *kp)
{
	/* TODO: Support RX count by round-robining the generated kfi_addr_t's
	 * across multiple RX contexts using RX base and RX count.
	 */
	return kfi_rx_addr(KFILND_BASE_ADDR(kp->kp_addr),
			   atomic_read(&kp->kp_rx_base),
				       KFILND_FAB_RX_CTX_BITS);
}

/**
 * kfilnd_peer_alive() - Update when the peer was last alive.
 * @kp: Peer to be updated.
 */
void kfilnd_peer_alive(struct kfilnd_peer *kp)
{
	kp->kp_last_alive = ktime_get_seconds();

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

void kfilnd_peer_process_hello(struct kfilnd_peer *kp, struct kfilnd_msg *msg)
{
	/* TODO: Support RX count. */
	LASSERT(msg->proto.hello.rx_count > 0);
	atomic_set(&kp->kp_rx_base, msg->proto.hello.rx_base);

	kp->kp_remote_session_key = msg->proto.hello.session_key;

	/* If processing an incoming hello request, then negotiate kfilnd
	 * version to the minimum implemented kfilnd version.
	 */
	if (msg->type == KFILND_MSG_HELLO_REQ) {
		kp->kp_version = min_t(__u16, KFILND_MSG_VERSION,
				       msg->proto.hello.version);
		CDEBUG(D_NET,
		       "Peer %s(%p):0x%llx version: %u; local version %u; negotiated version: %u\n",
		       libcfs_nid2str(kp->kp_nid), kp, kp->kp_addr,
		       msg->proto.hello.version, KFILND_MSG_VERSION,
		       kp->kp_version);
		if (atomic_cmpxchg(&kp->kp_state, KP_STATE_NEW,
				   KP_STATE_WAIT_RSP) == KP_STATE_NEW)
			CDEBUG(D_NET, "Peer %s(%p):0x%llx new -> wait response\n",
			       libcfs_nid2str(kp->kp_nid), kp, kp->kp_addr);
	} else if (msg->type == KFILND_MSG_HELLO_RSP) {
		struct lnet_nid nid;

		kp->kp_version = msg->proto.hello.version;
		atomic_set(&kp->kp_state, KP_STATE_UPTODATE);
		CDEBUG(D_NET,
		       "Peer %s(%p):0x%llx is up-to-date negotiated version: %u\n",
		       libcfs_nid2str(kp->kp_nid), kp, kp->kp_addr,
		       msg->proto.hello.version);
		kfilnd_peer_clear_hello_state(kp);

		lnet_nid4_to_nid(kp->kp_nid, &nid);
		lnet_notify(kp->kp_dev->kfd_ni, &nid, true, false,
			    kp->kp_last_alive);
	}
}
