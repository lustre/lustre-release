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
 * kfilnd main interface.
 */

#include <linux/delay.h>
#include "kfilnd.h"
#include "kfilnd_tn.h"
#include "kfilnd_dev.h"

/* These are temp constants to get stuff to compile */
#define KFILND_DEFAULT_DEVICE "eth0"

/* Some constants which should be turned into tunables */
#define KFILND_MAX_WORKER_THREADS 4
#define KFILND_MAX_EVENT_QUEUE 100

#define KFILND_WQ_FLAGS (WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_SYSFS)
struct workqueue_struct *kfilnd_wq;
struct dentry *kfilnd_debug_dir;

static void kfilnd_shutdown(struct lnet_ni *ni)
{
	struct kfilnd_dev *dev = ni->ni_data;

	kfilnd_dev_free(dev);
}

static int kfilnd_send_cpt(struct kfilnd_dev *dev, lnet_nid_t nid)
{
	int cpt;

	/* If the current CPT has is within the LNet NI CPTs, use that CPT. */
	cpt = lnet_cpt_current();
	if (dev->cpt_to_endpoint[cpt])
		return cpt;

	/* Hash to a LNet NI CPT based on target NID. */
	return  dev->kfd_endpoints[nid % dev->kfd_ni->ni_ncpts]->end_cpt;
}

int kfilnd_send_hello_request(struct kfilnd_dev *dev, int cpt,
			      struct kfilnd_peer *kp)
{
	struct kfilnd_transaction *tn;
	int rc;

	if (kfilnd_peer_set_check_hello_pending(kp)) {
		CDEBUG(D_NET, "Hello already pending to peer %s(%px)\n",
		       libcfs_nid2str(kp->kp_nid), kp);
		return 0;
	}

	tn = kfilnd_tn_alloc_for_peer(dev, cpt, kp, true, true, false);
	if (IS_ERR(tn)) {
		rc = PTR_ERR(tn);
		CERROR("Failed to allocate transaction struct: rc=%d\n", rc);
		kfilnd_peer_clear_hello_pending(kp);
		return rc;
	}

	/* +1 for tn->tn_kp. This ref is dropped when this transaction is
	 * finalized
	 */
	refcount_inc(&kp->kp_cnt);

	tn->msg_type = KFILND_MSG_HELLO_REQ;

	kp->kp_hello_ts = ktime_get_seconds();

	kfilnd_tn_event_handler(tn, TN_EVENT_TX_HELLO, 0);

	return 0;
}

static int kfilnd_send(struct lnet_ni *ni, void *private, struct lnet_msg *msg)
{
	int type = msg->msg_type;
	struct lnet_processid *target = &msg->msg_target;
	struct kfilnd_transaction *tn;
	int nob;
	struct kfilnd_dev *dev = ni->ni_data;
	enum kfilnd_msg_type lnd_msg_type;
	int cpt;
	enum tn_events event = TN_EVENT_INVALID;
	int rc;
	bool tn_key = false;
	lnet_nid_t tgt_nid4;

	switch (type) {
	default:
		return -EIO;

	case LNET_MSG_ACK:
		if (msg->msg_len != 0)
			return -EINVAL;
		lnd_msg_type = KFILND_MSG_IMMEDIATE;
		break;

	case LNET_MSG_GET:
		if (msg->msg_routing || msg->msg_target_is_router) {
			lnd_msg_type = KFILND_MSG_IMMEDIATE;
			break;
		}

		nob = offsetof(struct kfilnd_msg,
			       proto.immed.payload[msg->msg_md->md_length]);
		if (nob <= KFILND_IMMEDIATE_MSG_SIZE) {
			lnd_msg_type = KFILND_MSG_IMMEDIATE;
			break;
		}

		lnd_msg_type = KFILND_MSG_BULK_GET_REQ;
		tn_key = true;
		break;

	case LNET_MSG_REPLY:
	case LNET_MSG_PUT:
		nob = offsetof(struct kfilnd_msg,
			       proto.immed.payload[msg->msg_len]);
		if (nob <= KFILND_IMMEDIATE_MSG_SIZE) {
			lnd_msg_type = KFILND_MSG_IMMEDIATE;
			break;
		}

		lnd_msg_type = KFILND_MSG_BULK_PUT_REQ;
		tn_key = true;
		break;
	}

	tgt_nid4 = lnet_nid_to_nid4(&target->nid);

	cpt = kfilnd_send_cpt(dev, tgt_nid4);
	tn = kfilnd_tn_alloc(dev, cpt, tgt_nid4, true, true, tn_key);
	if (IS_ERR(tn)) {
		rc = PTR_ERR(tn);
		CERROR("Failed to allocate transaction struct: rc=%d\n", rc);
		return rc;
	}

	if (kfilnd_peer_needs_hello(tn->tn_kp, true)) {
		rc = kfilnd_send_hello_request(dev, cpt, tn->tn_kp);
		if (rc && kfilnd_peer_is_new_peer(tn->tn_kp)) {
			/* Only fail the send if this is a new peer. Otherwise
			 * attempt the send using our stale peer information
			 */
			kfilnd_tn_free(tn);
			return rc;
		}
	}

	switch (lnd_msg_type) {
	case KFILND_MSG_IMMEDIATE:
		rc = kfilnd_tn_set_kiov_buf(tn, msg->msg_kiov, msg->msg_niov,
					    msg->msg_offset, msg->msg_len);
		if (rc) {
			CERROR("Failed to setup immediate buffer rc %d\n", rc);
			kfilnd_tn_free(tn);
			return rc;
		}

		event = TN_EVENT_INIT_IMMEDIATE;
		break;

	case KFILND_MSG_BULK_PUT_REQ:
		tn->sink_buffer = false;
		rc = kfilnd_tn_set_kiov_buf(tn, msg->msg_kiov, msg->msg_niov,
					    msg->msg_offset, msg->msg_len);
		if (rc) {
			CERROR("Failed to setup PUT source buffer rc %d\n", rc);
			kfilnd_tn_free(tn);
			return rc;
		}

		event = TN_EVENT_INIT_BULK;
		break;

	case KFILND_MSG_BULK_GET_REQ:
		/* We need to create a reply message to inform LNet our
		 * optimized GET is done.
		 */
		tn->tn_getreply = lnet_create_reply_msg(ni, msg);
		if (!tn->tn_getreply) {
			CERROR("Can't create reply for GET -> %s\n",
			       libcfs_nidstr(&target->nid));
			kfilnd_tn_free(tn);
			return -EIO;
		}

		tn->sink_buffer = true;
		rc = kfilnd_tn_set_kiov_buf(tn, msg->msg_md->md_kiov,
					    msg->msg_md->md_niov,
					    msg->msg_md->md_offset,
					    msg->msg_md->md_length);
		if (rc) {
			CERROR("Failed to setup GET sink buffer rc %d\n", rc);
			kfilnd_tn_free(tn);
			return rc;
		}
		event = TN_EVENT_INIT_BULK;
		break;

	default:
		kfilnd_tn_free(tn);
		return -EIO;
	}

	tn->msg_type = lnd_msg_type;
	tn->tn_lntmsg = msg;	/* finalise msg on completion */
	tn->lnet_msg_len = tn->tn_nob;

	KFILND_TN_DEBUG(tn, "%s in %u bytes in %u frags",
			msg_type_to_str(lnd_msg_type), tn->tn_nob,
			tn->tn_num_iovec);

	/* Start the state machine processing this transaction */
	kfilnd_tn_event_handler(tn, event, 0);

	return 0;
}

static int kfilnd_recv(struct lnet_ni *ni, void *private, struct lnet_msg *msg,
		       int delayed, unsigned int niov,
		       struct bio_vec *kiov,
		       unsigned int offset, unsigned int mlen,
		       unsigned int rlen)
{
	struct kfilnd_transaction *tn = private;
	struct kfilnd_msg *rxmsg = tn->tn_rx_msg.msg;
	int nob;
	int rc = 0;
	int status = 0;
	enum tn_events event;

	if (mlen > rlen)
		return -EINVAL;

	/* Transaction must be in receive state */
	if (tn->tn_state != TN_STATE_IMM_RECV)
		return -EINVAL;

	tn->tn_lntmsg = msg;
	tn->lnet_msg_len = rlen;

	switch (rxmsg->type) {
	case KFILND_MSG_IMMEDIATE:
		nob = offsetof(struct kfilnd_msg, proto.immed.payload[rlen]);
		if (nob > tn->tn_rx_msg.length) {
			CERROR("Immediate message from %s too big: %d(%lu)\n",
			       libcfs_nidstr(&msg->msg_hdr.src_nid),
			       nob, tn->tn_rx_msg.length);
			return -EPROTO;
		}
		tn->tn_nob = nob;

		lnet_copy_flat2kiov(niov, kiov, offset,
				    KFILND_IMMEDIATE_MSG_SIZE, rxmsg,
				    offsetof(struct kfilnd_msg,
					     proto.immed.payload),
				    mlen);

		kfilnd_tn_event_handler(tn, TN_EVENT_RX_OK, 0);
		return 0;

	case KFILND_MSG_BULK_PUT_REQ:
		if (mlen == 0) {
			event = TN_EVENT_SKIP_TAG_RMA;
		} else {
			/* Post the buffer given us as a sink  */
			tn->sink_buffer = true;
			rc = kfilnd_tn_set_kiov_buf(tn, kiov, niov, offset,
						    mlen);
			if (rc) {
				CERROR("Failed to setup PUT sink buffer rc %d\n", rc);
				kfilnd_tn_free(tn);
				return rc;
			}
			event = TN_EVENT_INIT_TAG_RMA;
		}
		break;

	case KFILND_MSG_BULK_GET_REQ:
		if (!msg) {
			event = TN_EVENT_SKIP_TAG_RMA;
			status = -ENODATA;
		} else {
			/* Post the buffer given to us as a source  */
			tn->sink_buffer = false;
			rc = kfilnd_tn_set_kiov_buf(tn, msg->msg_kiov,
						    msg->msg_niov,
						    msg->msg_offset,
						    msg->msg_len);
			if (rc) {
				CERROR("Failed to setup GET source buffer rc %d\n", rc);
				kfilnd_tn_free(tn);
				return rc;
			}
			event = TN_EVENT_INIT_TAG_RMA;
		}
		break;

	default:
		/* TODO: TN leaks here. */
		CERROR("Invalid message type = %d\n", rxmsg->type);
		return -EINVAL;
	}

	/* Store relevant fields to generate a bulk response. */
	tn->tn_response_mr_key = rxmsg->proto.bulk_req.key;
	tn->tn_response_rx = rxmsg->proto.bulk_req.response_rx;

#if 0
	tn->tn_tx_msg.length = kfilnd_init_proto(tn->tn_tx_msg.msg,
						 KFILND_MSG_BULK_RSP,
						 sizeof(struct kfilnd_bulk_rsp),
						 ni);
#endif

	KFILND_TN_DEBUG(tn, "%s in %u bytes in %u frags",
			msg_type_to_str(rxmsg->type), tn->tn_nob,
			tn->tn_num_iovec);

	kfilnd_tn_event_handler(tn, event, status);

	return rc;
}

static const struct ln_key_list kfilnd_tunables_keys = {
	.lkl_maxattr                    = LNET_NET_KFILND_TUNABLES_ATTR_MAX,
	.lkl_list                       = {
		[LNET_NET_KFILND_TUNABLES_ATTR_PROV_MAJOR]	= {
			.lkp_value	= "prov_major_version",
			.lkp_data_type	= NLA_S32
		},
		[LNET_NET_KFILND_TUNABLES_ATTR_PROV_MINOR]  = {
			.lkp_value	= "prov_minor_version",
			.lkp_data_type	= NLA_S32
		},
		[LNET_NET_KFILND_TUNABLES_ATTR_AUTH_KEY]  = {
			.lkp_value	= "auth_key",
			.lkp_data_type	= NLA_S32
		},
	},
};

static int
kfilnd_nl_set(int cmd, struct nlattr *attr, int type, void *data)
{
	struct lnet_lnd_tunables *tunables = data;
	int rc = 0;

	if (cmd != LNET_CMD_NETS)
		return -EOPNOTSUPP;

	switch (type) {
	case LNET_NET_KFILND_TUNABLES_ATTR_PROV_MAJOR:
		tunables->lnd_tun_u.lnd_kfi.lnd_prov_major_version = nla_get_s64(attr);
		break;
	case LNET_NET_KFILND_TUNABLES_ATTR_PROV_MINOR:
		tunables->lnd_tun_u.lnd_kfi.lnd_prov_minor_version = nla_get_s64(attr);
		break;
	case LNET_NET_KFILND_TUNABLES_ATTR_AUTH_KEY:
		tunables->lnd_tun_u.lnd_kfi.lnd_auth_key = nla_get_s64(attr);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int kfilnd_startup(struct lnet_ni *ni);

static const struct lnet_lnd the_kfilnd = {
	.lnd_type	= KFILND,
	.lnd_startup	= kfilnd_startup,
	.lnd_shutdown	= kfilnd_shutdown,
	.lnd_send	= kfilnd_send,
	.lnd_recv	= kfilnd_recv,
	.lnd_nl_set	= kfilnd_nl_set,
	.lnd_keys	= &kfilnd_tunables_keys,
};

static int kfilnd_startup(struct lnet_ni *ni)
{
	const char *node;
	int rc;
	struct kfilnd_dev *kfdev;

	if (!ni)
		return -EINVAL;

	if (ni->ni_net->net_lnd != &the_kfilnd) {
		CERROR("Wrong lnd type\n");
		return -EINVAL;
	}

	kfilnd_tunables_setup(ni);

	/* Only a single interface is supported. */
	if (!ni->ni_interface) {
		rc = -ENODEV;
		CERROR("No LNet network interface address defined\n");
		goto err;
	}

	node = ni->ni_interface;

	kfdev = kfilnd_dev_alloc(ni, node);
	if (IS_ERR(kfdev)) {
		rc = PTR_ERR(kfdev);
		CERROR("Failed to allocate KFILND device for %s: rc=%d\n", node,
		       rc);
		goto err;
	}

	ni->ni_data = kfdev;
	ni->ni_nid.nid_addr[0] = cpu_to_be32(LNET_NIDADDR(kfdev->nic_addr));

	/* Post a series of immediate receive buffers */
	rc = kfilnd_dev_post_imm_buffers(kfdev);
	if (rc) {
		CERROR("Can't post buffers, rc = %d\n", rc);
		goto err_free_dev;
	}

	return 0;

err_free_dev:
	kfilnd_dev_free(kfdev);
err:
	return rc;
}

static void __exit kfilnd_exit(void)
{
	destroy_workqueue(kfilnd_wq);

	kfilnd_tn_cleanup();

	lnet_unregister_lnd(&the_kfilnd);

	debugfs_remove_recursive(kfilnd_debug_dir);
}

static int __init kfilnd_init(void)
{
	int rc;

	kfilnd_debug_dir = debugfs_create_dir("kfilnd", NULL);

	rc = kfilnd_tunables_init();
	if (rc)
		goto err;

	/* Do any initialization of the transaction system */
	rc = kfilnd_tn_init();
	if (rc) {
		CERROR("Cannot initialize transaction system\n");
		goto err;
	}

	kfilnd_wq = alloc_workqueue("kfilnd_wq", KFILND_WQ_FLAGS,
				    WQ_MAX_ACTIVE);
	if (!kfilnd_wq) {
		rc = -ENOMEM;
		CERROR("Failed to allocated kfilnd work queue\n");
		goto err_tn_cleanup;
	}

	lnet_register_lnd(&the_kfilnd);

	return 0;

err_tn_cleanup:
	kfilnd_tn_cleanup();
err:
	return rc;
}

MODULE_AUTHOR("Cray Inc.");
MODULE_DESCRIPTION("Kfabric Lustre Network Driver");
MODULE_VERSION(KFILND_VERSION);
MODULE_LICENSE("GPL");

module_init(kfilnd_init);
module_exit(kfilnd_exit);
