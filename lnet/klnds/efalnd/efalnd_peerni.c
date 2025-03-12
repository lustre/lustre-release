// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2023-2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * EFA GID/QP Discovery via TCP
 *
 * For IPv4 NIDs the EFA LND automatically discovers remote EFA NIs GID and
 * manager QP data by doing a TCP LNET ping. This allows instances to
 * communicate over EFA without needing large NID support and without
 * needing the GID to be provided manually.
 *
 * The GIDs and manager QP data for all remote NIs for a particular
 * node are passed via the LNET ping REPLY packet. Since a node will
 * only send the GIDs and QP data of its own NIs, a ping must be
 * performed with each node in a cluster.
 *
 * We implement the LNET callback lnd_get_nid_metadata to enable
 * LNET to query the LND for NID related metadata to send alongside
 * the ping REPLY. Of course, this is implemented by the EFA LND to
 * transmit the GIDs and manager QP data for local NIs.
 *
 * The NID format is designed to generate unique NID without
 * need a centralized name/number server. The NIDs are created by
 * taking IP of the primary ethernet interface, discarding the
 * subnet mask, and appending the PCI bus/devfn number for the device.
 *
 * For example, a node with TCP NID 172.86.23.4@tcp would have EFA
 * NIDs such as: 23.4.0.79@efa, 23.4.0.96@efa, 23.4.0.131@efa.
 *
 * We define a kefa_peer_ni struct to track metadata about remote
 * NIs. These kefa_peer_ni objects are kref'ed and stored in a glboal
 * rhashtable protected by RCU. Access to each individual kefa_peer_ni
 * is protected by a rw_lock_t.
 *
 * A kefa_dev holds a reference to it's own kefa_peer_ni. A
 * kefa_conn holds a reference to at least the kefa_peer_ni it's
 * initiating a connection to. If kefa_conn is the first connection,
 * then it holds a reference on each kefa_peer_ni available on the
 * remote node.
 *
 * Author: Timothy Day <timday@amazon.com>
 * Author: Yonatan Nachum <ynachum@amazon.com>
 */

#include <linux/delay.h>
#include <linux/dmapool.h>
#include <linux/ethtool.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/smp.h>

#include <rdma/ib_verbs.h>

#include "kcompat.h"
#include "efalnd.h"

#define EFALND_TCP_PING_TIMEOUT	30

static void efa_nid_to_tcp_nid(__be32 local_ip, lnet_nid_t efa_nid4,
			       struct lnet_nid *tcp_nid)
{
	u32 local_ip_le = __swab32(local_ip);
	lnet_nid_t tcp_nid4;
	u32 remote_ip;

	remote_ip = local_ip_le & ~0xffff;
	remote_ip = remote_ip | (LNET_NIDADDR(efa_nid4) >> 16);
	remote_ip = le32_to_cpu(remote_ip);
	tcp_nid4 = LNET_MKNID(LNET_MKNET(SOCKLND, 0), remote_ip);
	lnet_nid4_to_nid(tcp_nid4, tcp_nid);
}

static void peer_ni_free(struct kref *ref)
{
	struct kefa_peer_ni *peer_ni = container_of(ref, struct kefa_peer_ni,
						    refcount);

	rcu_read_lock();

	if (!kefalnd.shutdown)
		rhashtable_remove_fast(&kefalnd.peer_ni, &peer_ni->linkage,
				       peer_ni_params);

	atomic_dec(&kefalnd.peer_ni_count);
	LIBCFS_FREE_PRE(peer_ni, sizeof(*peer_ni), "kfreed");
	kfree_rcu(peer_ni, rcu_read);
	rcu_read_unlock();
}

static struct kefa_peer_ni *get_peer_ni(u32 nid_addr)
{
	struct kefa_peer_ni *peer_ni;

	rcu_read_lock();
	if (kefalnd.shutdown || kefalnd.init_state == EFALND_INIT_NONE) {
		rcu_read_unlock();
		return NULL;
	}

	peer_ni = rhashtable_lookup_fast(&kefalnd.peer_ni, &nid_addr,
					 peer_ni_params);
	if (!peer_ni) {
		rcu_read_unlock();
		return NULL;
	}

	if (!kref_get_unless_zero(&peer_ni->refcount)) {
		rcu_read_unlock();
		return NULL;
	}

	rcu_read_unlock();
	return peer_ni;
}

struct kefa_peer_ni *
kefalnd_lookup_or_create_peer_ni(lnet_nid_t nid, union ib_gid *gid, u16 cm_qpn,
				 u32 cm_qkey)
{
	struct kefa_peer_ni *new_peer_ni, *old_peer_ni;

	CFS_ALLOC_PTR(new_peer_ni);
	if (!new_peer_ni)
		return ERR_PTR(-ENOMEM);

	new_peer_ni->remote_nid_addr = LNET_NIDADDR(nid);
	new_peer_ni->gid = *gid;
	new_peer_ni->cm_qp.qp_num = cm_qpn;
	new_peer_ni->cm_qp.qkey = cm_qkey;
	kref_init(&new_peer_ni->refcount);
	rwlock_init(&new_peer_ni->peer_ni_lock);

	rcu_read_lock();
	if (kefalnd.shutdown || kefalnd.init_state == EFALND_INIT_NONE) {
		rcu_read_unlock();
		CFS_FREE_PTR(new_peer_ni);
		return ERR_PTR(-ENODEV);
	}

	old_peer_ni = rhashtable_lookup_get_insert_fast(&kefalnd.peer_ni,
							&new_peer_ni->linkage,
							peer_ni_params);

	if (IS_ERR(old_peer_ni)) {
		CDEBUG(EFALND_CD, "Failed to insert mapping for peer NI[%s]\n",
		       libcfs_nid2str(nid));

		rcu_read_unlock();
		CFS_FREE_PTR(new_peer_ni);
		return old_peer_ni;
	}

	if (old_peer_ni) {
		CDEBUG(EFALND_CD,
		       "Found pre-existing mapping for peer NI[%s]\n",
		       libcfs_nid2str(nid));

		if (!kref_get_unless_zero(&old_peer_ni->refcount))
			old_peer_ni =  ERR_PTR(-ENODEV);

		rcu_read_unlock();
		CFS_FREE_PTR(new_peer_ni);
		return old_peer_ni;
	}

	rcu_read_unlock();
	atomic_inc(&kefalnd.peer_ni_count);
	return new_peer_ni;
}

void kefalnd_put_peer_ni(struct kefa_peer_ni *peer_ni)
{
	kref_put(&peer_ni->refcount, peer_ni_free);
}

void kefalnd_update_peer_ni(struct kefa_peer_ni *peer_ni, union ib_gid *gid,
			    u16 cm_qpn, u32 cm_qkey)
{
	unsigned long flags;

	rcu_read_lock();
	if (kefalnd.shutdown || kefalnd.init_state == EFALND_INIT_NONE) {
		rcu_read_unlock();
		return;
	}

	write_lock_irqsave(&peer_ni->peer_ni_lock, flags);
	peer_ni->cm_qp.qp_num = cm_qpn;
	peer_ni->cm_qp.qkey = cm_qkey;
	peer_ni->gid = *gid;
	write_unlock_irqrestore(&peer_ni->peer_ni_lock, flags);

	rcu_read_unlock();
}

/**
 * kefalnd_find_remote_peer_ni() - Either get cached peer NI or ping over TCP.
 * @efa_dev: EFA interface that needs the connection.
 * @efa_nid: The remote NID to search.
 *
 * Return: peer NI if found or error.
 */
struct kefa_peer_ni *
kefalnd_find_remote_peer_ni(struct kefa_dev *efa_dev, struct lnet_nid *efa_nid)
{
	int mapping_size = offsetof(struct lnet_nid_metadata,
				    nid_mappings[lnet_interfaces_max]);
	struct kefa_peer_ni *peer_ni = NULL;
	struct lnet_nid_metadata *mapping;
	struct lnet_processid id;
	struct lnet_nid tcp_nid;
	lnet_nid_t efa_nid4;
	union ib_gid gid;
	u32 nid_addr;
	int rc = 0;
	int i = 0;

	ENTRY;

	LASSERTF(nid_is_nid4(efa_nid), "NID[%s] is not a small NID\n",
		 libcfs_nidstr(efa_nid));

	EFA_DEV_DEBUG(efa_dev, "Attempting to find peer NI for NI[%s]\n",
		      libcfs_nidstr(efa_nid));

	efa_nid4 = lnet_nid_to_nid4(efa_nid);
	nid_addr = LNET_NIDADDR(efa_nid4);
	peer_ni = get_peer_ni(nid_addr);
	if (peer_ni) {
		EFA_DEV_DEBUG(efa_dev, "Successfully found peer NI[%s]\n",
			      libcfs_nidstr(efa_nid));
		RETURN(peer_ni);
	}

	LIBCFS_CPT_ALLOC(mapping, lnet_cpt_table(), efa_dev->cpt, mapping_size);
	if (!mapping)
		GOTO(out_error, rc = -ENOMEM);

	efa_nid_to_tcp_nid(efa_dev->ifip, efa_nid4, &tcp_nid);
	EFA_DEV_DEBUG(efa_dev, "Attempting to ping TCP peer NI[%s]\n",
		      libcfs_nidstr(&tcp_nid));

	id.nid = tcp_nid;
	id.pid = LNET_PID_LUSTRE;
	rc = lnet_discover_nid_metadata(&id, EFALND_TCP_PING_TIMEOUT, mapping);
	if (rc) {
		EFA_DEV_DEBUG(efa_dev, "Failed to ping TCP peer NI[%s]\n",
			libcfs_nidstr(&tcp_nid));
		GOTO(out_mapping, rc);
	}

	EFA_DEV_DEBUG(efa_dev, "Found %i mappings from TCP peer NI[%s]\n",
		      mapping->num_nid_mappings,
		      libcfs_nidstr(&tcp_nid));

	peer_ni = NULL;

	for (i = 0; i < mapping->num_nid_mappings; i++) {
		struct kefa_nid_md_entry *kefa_nid_md;
		struct kefa_peer_ni *new_peer_ni;

		if (LNET_NETTYP(LNET_NIDNET(mapping->nid_mappings[i].nid)) != EFALND)
			continue;

		if (LNET_NIDADDR(mapping->nid_mappings[i].nid) != nid_addr)
			continue;

		kefa_nid_md = (struct kefa_nid_md_entry *)&mapping->nid_mappings[i];
		memcpy(gid.raw, &kefa_nid_md->gid, sizeof(kefa_nid_md->gid));

		new_peer_ni = kefalnd_lookup_or_create_peer_ni(kefa_nid_md->nid,
							       &gid, kefa_nid_md->qp_num,
							       kefa_nid_md->qkey);

		if (IS_ERR_OR_NULL(new_peer_ni))
			GOTO(out_mapping, rc = PTR_ERR(new_peer_ni));

		peer_ni = new_peer_ni;
		GOTO(out_success, rc);
	}

	/* We couldn't find the mapping we're looking for */
	if (!peer_ni)
		GOTO(out_mapping, rc = -ENODEV);

out_success:
	LIBCFS_FREE(mapping, mapping_size);

	EFA_DEV_DEBUG(efa_dev,
		      "Completed ping and found GID[0x%016llx] from TCP peer NI[%s]\n",
		      cpu_to_be64(peer_ni->gid.global.interface_id),
		      libcfs_nidstr(&tcp_nid));

	RETURN(peer_ni);

out_mapping:
	LIBCFS_FREE(mapping, mapping_size);

out_error:
	RETURN(ERR_PTR(rc));
}

/**
 * kefalnd_get_nid_metadata() - Get NIs GID and manager QP data.
 * @ni: LNET NI associated with EFA NI.
 * @md_entry: Mapping object - for EFA, contains device identifier
 *            that is needed to communicate with EFA devices and
 *            manager QP data.
 *
 * Return: have we found a valid mapping?
 */
int kefalnd_get_nid_metadata(struct lnet_ni *ni,
			     struct lnet_nid_md_entry *md_entry)
{
	struct kefa_nid_md_entry *kefa_ni_md = (struct kefa_nid_md_entry *)md_entry;
	struct kefa_ni *efa_ni = ni->ni_data;
	struct kefa_dev *efa_dev = efa_ni->efa_dev;

	if (kefalnd.shutdown || kefalnd.init_state == EFALND_INIT_NONE)
		return -ENODEV;

	memcpy(&kefa_ni_md->gid, efa_dev->gid.raw, sizeof(efa_dev->gid.raw));
	kefa_ni_md->qp_num = efa_dev->cm_qp->ib_qp->qp_num;
	kefa_ni_md->qkey = efa_dev->cm_qp->qkey;

	EFA_DEV_DEBUG(efa_dev, "Mapped local NID[%s] to GID[0x%016llx]\n",
		      libcfs_nidstr(&ni->ni_nid),
		      cpu_to_be64(efa_dev->gid.global.interface_id));

	return 0;
}
