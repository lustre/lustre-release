// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * kfilnd transaction and state machine processing.
 */

#include "kfilnd_tn.h"
#include "kfilnd_ep.h"
#include "kfilnd_dev.h"
#include "kfilnd_dom.h"
#include "kfilnd_peer.h"
#include <asm/checksum.h>

static struct kmem_cache *tn_cache;
static struct kmem_cache *imm_buf_cache;

static __sum16 kfilnd_tn_cksum(void *ptr, int nob)
{
	if (cksum)
		return csum_fold(csum_partial(ptr, nob, 0));
	return NO_CHECKSUM;
}

static int kfilnd_tn_msgtype2size(struct kfilnd_msg *msg)
{
	const int hdr_size = offsetof(struct kfilnd_msg, proto);

	switch (msg->type) {
	case KFILND_MSG_IMMEDIATE:
		return offsetof(struct kfilnd_msg, proto.immed.payload[0]);

	case KFILND_MSG_BULK_PUT_REQ:
	case KFILND_MSG_BULK_GET_REQ:
		if (msg->version == KFILND_MSG_VERSION_1)
			return hdr_size + sizeof(struct kfilnd_bulk_req_msg);
		else if (msg->version == KFILND_MSG_VERSION_2)
			return hdr_size + sizeof(struct kfilnd_bulk_req_msg_v2);
		fallthrough;
	default:
		return -1;
	}
}

static void kfilnd_tn_pack_hello_req(struct kfilnd_transaction *tn)
{
	struct kfilnd_msg *msg = tn->tn_tx_msg.msg;

	/* Pack the protocol header and payload. */
	msg->proto.hello.version = KFILND_MSG_VERSION;
	msg->proto.hello.rx_base = kfilnd_peer_target_rx_base(tn->tn_kp);
	msg->proto.hello.session_key = tn->tn_kp->kp_local_session_key;

	/* TODO: Support multiple RX contexts per peer. */
	msg->proto.hello.rx_count = 1;

	/* Pack the transport header. */
	msg->magic = KFILND_MSG_MAGIC;

	/* Mesage version zero is only valid for hello requests. */
	msg->version = 0;
	msg->type = KFILND_MSG_HELLO_REQ;
	msg->nob = sizeof(struct kfilnd_hello_msg) +
		offsetof(struct kfilnd_msg, proto);
	msg->cksum = NO_CHECKSUM;
	msg->srcnid = lnet_nid_to_nid4(&tn->tn_ep->end_dev->kfd_ni->ni_nid);
	msg->dstnid = tn->tn_kp->kp_nid;

	/* Checksum entire message. */
	msg->cksum = kfilnd_tn_cksum(msg, msg->nob);

	tn->tn_tx_msg.length = msg->nob;
}

static void kfilnd_tn_pack_hello_rsp(struct kfilnd_transaction *tn)
{
	struct kfilnd_msg *msg = tn->tn_tx_msg.msg;

	/* Pack the protocol header and payload. */
	msg->proto.hello.version = tn->tn_kp->kp_version;
	msg->proto.hello.rx_base = kfilnd_peer_target_rx_base(tn->tn_kp);
	msg->proto.hello.session_key = tn->tn_kp->kp_local_session_key;

	/* TODO: Support multiple RX contexts per peer. */
	msg->proto.hello.rx_count = 1;

	/* Pack the transport header. */
	msg->magic = KFILND_MSG_MAGIC;

	/* Mesage version zero is only valid for hello requests. */
	msg->version = 0;
	msg->type = KFILND_MSG_HELLO_RSP;
	msg->nob = sizeof(struct kfilnd_hello_msg) +
		offsetof(struct kfilnd_msg, proto);
	msg->cksum = NO_CHECKSUM;
	msg->srcnid = lnet_nid_to_nid4(&tn->tn_ep->end_dev->kfd_ni->ni_nid);
	msg->dstnid = tn->tn_kp->kp_nid;

	/* Checksum entire message. */
	msg->cksum = kfilnd_tn_cksum(msg, msg->nob);

	tn->tn_tx_msg.length = msg->nob;
}

static void kfilnd_tn_pack_bulk_req(struct kfilnd_transaction *tn)
{
	struct kfilnd_msg *msg = tn->tn_tx_msg.msg;

	/* Pack the transport header. */
	msg->magic = KFILND_MSG_MAGIC;
	msg->version = tn->tn_kp->kp_version;
	msg->type = tn->msg_type;
	msg->cksum = NO_CHECKSUM;
	msg->srcnid = lnet_nid_to_nid4(&tn->tn_ep->end_dev->kfd_ni->ni_nid);
	msg->dstnid = tn->tn_kp->kp_nid;

	if (msg->version == KFILND_MSG_VERSION_1) {
		msg->nob = sizeof(struct kfilnd_bulk_req_msg) +
			offsetof(struct kfilnd_msg, proto);

		/* Pack the protocol header and payload. */
		lnet_hdr_to_nid4(&tn->tn_lntmsg->msg_hdr,
				 &msg->proto.bulk_req.hdr);
		msg->proto.bulk_req.key = tn->tn_mr_key;
		msg->proto.bulk_req.response_rx = tn->tn_response_rx;
	} else {
		msg->nob = sizeof(struct kfilnd_bulk_req_msg_v2) +
			offsetof(struct kfilnd_msg, proto);

		/* Pack the protocol header and payload. */
		lnet_hdr_to_nid4(&tn->tn_lntmsg->msg_hdr,
				 &msg->proto.bulk_req_v2.kbrm2_hdr);
		msg->proto.bulk_req_v2.kbrm2_key = tn->tn_mr_key;
		msg->proto.bulk_req_v2.kbrm2_response_rx = tn->tn_response_rx;
		msg->proto.bulk_req_v2.kbrm2_session_key =
						tn->tn_kp->kp_local_session_key;
	}

	/* Checksum entire message. */
	msg->cksum = kfilnd_tn_cksum(msg, msg->nob);

	tn->tn_tx_msg.length = msg->nob;
}

static void kfilnd_tn_pack_immed_msg(struct kfilnd_transaction *tn)
{
	struct kfilnd_msg *msg = tn->tn_tx_msg.msg;

	/* Pack the protocol header and payload. */
	lnet_hdr_to_nid4(&tn->tn_lntmsg->msg_hdr, &msg->proto.immed.hdr);

	lnet_copy_kiov2flat(KFILND_IMMEDIATE_MSG_SIZE,
			    msg,
			    offsetof(struct kfilnd_msg,
				     proto.immed.payload),
			    tn->tn_num_iovec, tn->tn_kiov, 0,
			    tn->tn_nob);

	/* Pack the transport header. */
	msg->magic = KFILND_MSG_MAGIC;
	msg->version = tn->tn_kp->kp_version;
	msg->type = tn->msg_type;
	msg->nob = offsetof(struct kfilnd_msg, proto.immed.payload[tn->tn_nob]);
	msg->cksum = NO_CHECKSUM;
	msg->srcnid = lnet_nid_to_nid4(&tn->tn_ep->end_dev->kfd_ni->ni_nid);
	msg->dstnid = tn->tn_kp->kp_nid;

	/* Checksum entire message. */
	msg->cksum = kfilnd_tn_cksum(msg, msg->nob);

	tn->tn_tx_msg.length = msg->nob;
}

static int kfilnd_tn_unpack_msg(struct kfilnd_ep *ep, struct kfilnd_msg *msg,
				unsigned int nob)
{
	const unsigned int hdr_size = offsetof(struct kfilnd_msg, proto);

	if (nob < hdr_size) {
		KFILND_EP_ERROR(ep, "Short message: %u", nob);
		return -EPROTO;
	}

	/* TODO: Support byte swapping on mixed endian systems. */
	if (msg->magic != KFILND_MSG_MAGIC) {
		KFILND_EP_ERROR(ep, "Bad magic: %#x", msg->magic);
		return -EPROTO;
	}

	/* TODO: Allow for older versions. */
	if (msg->version > KFILND_MSG_VERSION) {
		KFILND_EP_ERROR(ep, "Bad version: %#x", msg->version);
		return -EPROTO;
	}

	if (msg->nob > nob) {
		KFILND_EP_ERROR(ep, "Short message: got=%u, expected=%u", nob,
				msg->nob);
		return -EPROTO;
	}

	/* If kfilnd_tn_cksum() returns a non-zero value, checksum is bad. */
	if (msg->cksum != NO_CHECKSUM && kfilnd_tn_cksum(msg, msg->nob)) {
		KFILND_EP_ERROR(ep, "Bad checksum");
		return -EPROTO;
	}

	if (msg->dstnid != lnet_nid_to_nid4(&ep->end_dev->kfd_ni->ni_nid)) {
		KFILND_EP_ERROR(ep, "Bad destination nid: %s",
				libcfs_nid2str(msg->dstnid));
		return -EPROTO;
	}

	if (msg->srcnid == LNET_NID_ANY) {
		KFILND_EP_ERROR(ep, "Bad source nid: %s",
				libcfs_nid2str(msg->srcnid));
		return -EPROTO;
	}

	if (msg->nob < kfilnd_tn_msgtype2size(msg)) {
		KFILND_EP_ERROR(ep, "Short %s: %d(%d)\n",
				msg_type_to_str(msg->type),
				msg->nob, kfilnd_tn_msgtype2size(msg));
		return -EPROTO;
	}

	switch ((enum kfilnd_msg_type)msg->type) {
	case KFILND_MSG_IMMEDIATE:
	case KFILND_MSG_BULK_PUT_REQ:
	case KFILND_MSG_BULK_GET_REQ:
		if (msg->version == 0) {
			KFILND_EP_ERROR(ep,
					"Bad message type and version: type=%s version=%u",
					msg_type_to_str(msg->type),
					msg->version);
			return -EPROTO;
		}
		break;

	case KFILND_MSG_HELLO_REQ:
	case KFILND_MSG_HELLO_RSP:
		if (msg->version != 0) {
			KFILND_EP_ERROR(ep,
					"Bad message type and version: type=%s version=%u",
					msg_type_to_str(msg->type),
					msg->version);
			return -EPROTO;
		}
		break;

	default:
		CERROR("Unknown message type %x\n", msg->type);
		return -EPROTO;
	}
	return 0;
}

static void kfilnd_tn_record_state_change(struct kfilnd_transaction *tn)
{
	unsigned int data_size_bucket =
		kfilnd_msg_len_to_data_size_bucket(tn->lnet_msg_len);
	struct kfilnd_tn_duration_stat *stat;
	s64 time;
	s64 cur;

	if (tn->is_initiator)
		stat = &tn->tn_ep->end_dev->initiator_state_stats.state[tn->tn_state].data_size[data_size_bucket];
	else
		stat = &tn->tn_ep->end_dev->target_state_stats.state[tn->tn_state].data_size[data_size_bucket];

	time = ktime_to_ns(ktime_sub(ktime_get(), tn->tn_state_ts));
	atomic64_add(time, &stat->accumulated_duration);
	atomic_inc(&stat->accumulated_count);

	do {
		cur = atomic64_read(&stat->max_duration);
		if (time <= cur)
			break;
	} while (atomic64_cmpxchg(&stat->max_duration, cur, time) != cur);

	do {
		cur = atomic64_read(&stat->min_duration);
		if (time >= cur)
			break;
	} while (atomic64_cmpxchg(&stat->min_duration, cur, time) != cur);
}

static void kfilnd_tn_state_change(struct kfilnd_transaction *tn,
				   enum tn_states new_state)
{
	KFILND_TN_DEBUG(tn, "%s -> %s state change",
			tn_state_to_str(tn->tn_state),
			tn_state_to_str(new_state));

	kfilnd_tn_record_state_change(tn);

	tn->tn_state = new_state;
	tn->tn_state_ts = ktime_get();
}

static void kfilnd_tn_status_update(struct kfilnd_transaction *tn, int status,
				    enum lnet_msg_hstatus hstatus)
{
	/* Only the first non-ok status will take. */
	if (tn->tn_status == 0) {
		KFILND_TN_DEBUG(tn, "%d -> %d status change", tn->tn_status,
				status);
		tn->tn_status = status;
	}

	if (tn->hstatus == LNET_MSG_STATUS_OK) {
		KFILND_TN_DEBUG(tn, "%d -> %d health status change",
				tn->hstatus, hstatus);
		tn->hstatus = hstatus;
	}
}

static bool kfilnd_tn_has_failed(struct kfilnd_transaction *tn)
{
	return tn->tn_status != 0;
}

/**
 * kfilnd_tn_process_rx_event() - Process an immediate receive event.
 *
 * For each immediate receive, a transaction structure needs to be allocated to
 * process the receive.
 */
void kfilnd_tn_process_rx_event(struct kfilnd_immediate_buffer *bufdesc,
				struct kfilnd_msg *rx_msg, int msg_size)
{
	struct kfilnd_transaction *tn;
	struct kfilnd_ep *ep = bufdesc->immed_end;
	bool alloc_msg = true;
	int rc;
	enum tn_events event = TN_EVENT_RX_HELLO;
	enum kfilnd_msg_type msg_type;

	/* Increment buf ref count for this work */
	atomic_inc(&bufdesc->immed_ref);

	/* Unpack the message */
	rc = kfilnd_tn_unpack_msg(ep, rx_msg, msg_size);
	if (rc || CFS_FAIL_CHECK(CFS_KFI_FAIL_MSG_UNPACK)) {
		kfilnd_ep_imm_buffer_put(bufdesc);
		KFILND_EP_ERROR(ep, "Failed to unpack message %d", rc);
		return;
	}

	msg_type = (enum kfilnd_msg_type)rx_msg->type;

	switch (msg_type) {
	case KFILND_MSG_IMMEDIATE:
	case KFILND_MSG_BULK_PUT_REQ:
	case KFILND_MSG_BULK_GET_REQ:
		event = TN_EVENT_RX_OK;
		fallthrough;
	case KFILND_MSG_HELLO_RSP:
		alloc_msg = false;
		fallthrough;
	case KFILND_MSG_HELLO_REQ:
		/* Context points to a received buffer and status is the length.
		 * Allocate a Tn structure, set its values, then launch the
		 * receive.
		 */
		tn = kfilnd_tn_alloc(ep->end_dev, ep->end_cpt,
				     rx_msg->srcnid, alloc_msg, false,
				     false);
		if (IS_ERR(tn)) {
			kfilnd_ep_imm_buffer_put(bufdesc);
			KFILND_EP_ERROR(ep,
				"Failed to allocate transaction struct: rc=%ld",
					PTR_ERR(tn));
			return;
		}

		tn->tn_rx_msg.msg = rx_msg;
		tn->tn_rx_msg.length = msg_size;
		tn->tn_posted_buf = bufdesc;
		tn->msg_type = msg_type;

		KFILND_EP_DEBUG(ep, "%s TN %p tmk %u",
				msg_type_to_str(tn->msg_type), tn,
				tn->tn_mr_key);
		break;

	default:
		KFILND_EP_ERROR(ep, "Unhandled kfilnd message type: %d",
				msg_type);
		LBUG();
	};

	kfilnd_tn_event_handler(tn, event, 0);
}

static void kfilnd_tn_record_duration(struct kfilnd_transaction *tn)
{
	unsigned int data_size_bucket =
		kfilnd_msg_len_to_data_size_bucket(tn->lnet_msg_len);
	struct kfilnd_tn_duration_stat *stat;
	s64 time;
	s64 cur;

	if (tn->is_initiator)
		stat = &tn->tn_ep->end_dev->initiator_stats.data_size[data_size_bucket];
	else
		stat = &tn->tn_ep->end_dev->target_stats.data_size[data_size_bucket];

	time = ktime_to_ns(ktime_sub(ktime_get(), tn->tn_alloc_ts));
	atomic64_add(time, &stat->accumulated_duration);
	atomic_inc(&stat->accumulated_count);

	do {
		cur = atomic64_read(&stat->max_duration);
		if (time <= cur)
			break;
	} while (atomic64_cmpxchg(&stat->max_duration, cur, time) != cur);

	do {
		cur = atomic64_read(&stat->min_duration);
		if (time >= cur)
			break;
	} while (atomic64_cmpxchg(&stat->min_duration, cur, time) != cur);
}

/**
 * kfilnd_tn_finalize() - Cleanup resources and finalize LNet operation.
 *
 * All state machine functions should call kfilnd_tn_finalize() instead of
 * kfilnd_tn_free(). Once all expected asynchronous events have been received,
 * if the transaction lock has not been released, it will now be released,
 * transaction resources cleaned up, and LNet finalized will be called.
 */
static void kfilnd_tn_finalize(struct kfilnd_transaction *tn, bool *tn_released)
{
	if (!*tn_released) {
		mutex_unlock(&tn->tn_lock);
		*tn_released = true;
	}

	/* Release the reference on the multi-receive buffer. */
	if (tn->tn_posted_buf)
		kfilnd_ep_imm_buffer_put(tn->tn_posted_buf);

	/* Finalize LNet operation. */
	if (tn->tn_lntmsg) {
		tn->tn_lntmsg->msg_health_status = tn->hstatus;
		lnet_finalize(tn->tn_lntmsg, tn->tn_status);
	}

	if (tn->tn_getreply) {
		tn->tn_getreply->msg_health_status = tn->hstatus;
		lnet_set_reply_msg_len(tn->tn_ep->end_dev->kfd_ni,
				       tn->tn_getreply,
				       tn->tn_status ? 0 : tn->tn_nob);
		lnet_finalize(tn->tn_getreply, tn->tn_status);
	}

	if (KFILND_TN_PEER_VALID(tn))
		kfilnd_peer_put(tn->tn_kp);

	kfilnd_tn_record_state_change(tn);
	kfilnd_tn_record_duration(tn);

	kfilnd_tn_free(tn);
}

/**
 * kfilnd_tn_cancel_tag_recv() - Attempt to cancel a tagged receive.
 * @tn: Transaction to have tagged received cancelled.
 *
 * Return: 0 on success. Else, negative errno. If an error occurs, resources may
 * be leaked.
 */
static int kfilnd_tn_cancel_tag_recv(struct kfilnd_transaction *tn)
{
	int rc;

	/* Issue a cancel. A return code of zero means the operation issued an
	 * async cancel. A return code of -ENOENT means the tagged receive was
	 * not found. The assumption here is that a tagged send landed thus
	 * removing the tagged receive buffer from hardware. For both cases,
	 * async events should occur.
	 */
	rc = kfilnd_ep_cancel_tagged_recv(tn->tn_ep, tn);
	if (rc != 0 && rc != -ENOENT) {
		KFILND_TN_ERROR(tn, "Failed to cancel tag receive. Resources may leak.");
		return rc;
	}

	return 0;
}

static void kfilnd_tn_timeout_work(struct work_struct *work)
{
	struct kfilnd_transaction *tn =
		container_of(work, struct kfilnd_transaction, timeout_work);

	KFILND_TN_ERROR(tn, "Bulk operation timeout");
	kfilnd_tn_event_handler(tn, TN_EVENT_TIMEOUT, 0);
}

static void kfilnd_tn_timeout(cfs_timer_cb_arg_t data)
{
	struct kfilnd_transaction *tn = cfs_from_timer(tn, data, timeout_timer);

	queue_work(kfilnd_wq, &tn->timeout_work);
}

static bool kfilnd_tn_timeout_cancel(struct kfilnd_transaction *tn)
{
	return timer_delete(&tn->timeout_timer);
}

static void kfilnd_tn_timeout_enable(struct kfilnd_transaction *tn)
{
	ktime_t remaining_time = max_t(ktime_t, 0,
				       tn->deadline - ktime_get_seconds());
	unsigned long expires = remaining_time * HZ + jiffies;

	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_BULK_TIMEOUT))
		expires = jiffies;

	cfs_timer_setup(&tn->timeout_timer, kfilnd_tn_timeout,
			(unsigned long)tn, 0);
	mod_timer(&tn->timeout_timer, expires);
}

/*  The following are the state machine routines for the transactions. */
static int kfilnd_tn_state_send_failed(struct kfilnd_transaction *tn,
				       enum tn_events event, int status,
				       bool *tn_released)
{
	int rc;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_INIT_BULK:
		/* Need to cancel the tagged receive to prevent resources from
		 * being leaked.
		 */
		rc = kfilnd_tn_cancel_tag_recv(tn);

		switch (rc) {
		/* Async event will progress transaction. */
		case 0:
			kfilnd_tn_state_change(tn, TN_STATE_FAIL);
			return 0;

		/* Need to replay TN_EVENT_INIT_BULK event while in the
		 * TN_STATE_SEND_FAILED state.
		 */
		case -EAGAIN:
			KFILND_TN_DEBUG(tn,
					"Need to replay cancel tagged recv");
			return -EAGAIN;

		default:
			KFILND_TN_ERROR(tn,
					"Unexpected error during cancel tagged receive: rc=%d",
					rc);
			LBUG();
		}
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}
}

static int kfilnd_tn_state_tagged_recv_posted(struct kfilnd_transaction *tn,
					      enum tn_events event, int status,
					      bool *tn_released)
{
	int rc;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_INIT_BULK:
		tn->tn_target_addr = kfilnd_peer_get_kfi_addr(tn->tn_kp);
		KFILND_TN_DEBUG(tn, "Using peer %s(%#llx)",
				libcfs_nid2str(tn->tn_kp->kp_nid),
				tn->tn_target_addr);

		kfilnd_tn_pack_bulk_req(tn);

		rc = kfilnd_ep_post_send(tn->tn_ep, tn);
		switch (rc) {
		/* Async event will progress immediate send. */
		case 0:
			kfilnd_tn_state_change(tn, TN_STATE_WAIT_COMP);
			return 0;

		/* Need to replay TN_EVENT_INIT_BULK event while in the
		 * TN_STATE_TAGGED_RECV_POSTED state.
		 */
		case -EAGAIN:
			KFILND_TN_DEBUG(tn,
					"Need to replay post send to %s(%#llx)",
					libcfs_nid2str(tn->tn_kp->kp_nid),
					tn->tn_target_addr);
			return -EAGAIN;

		/* Need to transition to the TN_STATE_SEND_FAILED to cleanup
		 * posted tagged receive buffer.
		 */
		default:
			KFILND_TN_ERROR(tn,
					"Failed to post send to %s(%#llx): rc=%d",
					libcfs_nid2str(tn->tn_kp->kp_nid),
					tn->tn_target_addr, rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
			kfilnd_tn_state_change(tn, TN_STATE_SEND_FAILED);

			/* Propogate TN_EVENT_INIT_BULK event to
			 * TN_STATE_SEND_FAILED handler.
			 */
			return kfilnd_tn_state_send_failed(tn, event, rc,
							   tn_released);
		}

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}
}

static int kfilnd_tn_state_idle(struct kfilnd_transaction *tn,
				enum tn_events event, int status,
				bool *tn_released)
{
	struct kfilnd_msg *msg;
	int rc = 0;
	bool finalize = false;
	struct lnet_hdr hdr;
	struct lnet_nid srcnid;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	/* For new peers, send a hello request message and queue the true LNet
	 * message for replay.
	 */
	if (kfilnd_peer_needs_throttle(tn->tn_kp) &&
	    (event == TN_EVENT_INIT_IMMEDIATE || event == TN_EVENT_INIT_BULK)) {
		if (kfilnd_peer_deleted(tn->tn_kp)) {
			/* We'll assign a NETWORK_TIMEOUT message health status
			 * below because we don't know why this peer was marked
			 * for removal
			 */
			rc = -ESTALE;
			KFILND_TN_DEBUG(tn, "Drop message to deleted peer");
		} else if (kfilnd_peer_needs_hello(tn->tn_kp, false)) {
			/* We're throttling transactions to this peer until
			 * a handshake can be completed, but there is no HELLO
			 * currently in flight. This implies the HELLO has
			 * failed, and we should cancel this TN. Otherwise we
			 * are stuck waiting for the TN deadline.
			 *
			 * We assign NETWORK_TIMEOUT health status below because
			 * we do not know why the HELLO failed.
			 */
			rc = -ECANCELED;
			KFILND_TN_DEBUG(tn, "Cancel throttled TN");
		} else if (ktime_before(ktime_get_seconds(),
					tn->tn_replay_deadline)) {
			/* If the transaction replay deadline has not been met,
			 * then return -EAGAIN. This will cause this transaction
			 * event to be replayed. During this time, an async
			 * hello message from the peer should occur at which
			 * point we can resume sending new messages to this peer
			 */
			KFILND_TN_DEBUG(tn, "hello response pending");
			return -EAGAIN;
		} else {
			rc = -ETIMEDOUT;
		}

		kfilnd_tn_status_update(tn, rc,
					LNET_MSG_STATUS_NETWORK_TIMEOUT);
		rc = 0;
		goto out;
	}

	if ((event == TN_EVENT_INIT_IMMEDIATE || event == TN_EVENT_INIT_BULK) &&
	    ktime_after(ktime_get_seconds(), tn->tn_replay_deadline)) {
		kfilnd_tn_status_update(tn, -ETIMEDOUT,
					LNET_MSG_STATUS_NETWORK_TIMEOUT);
		rc = 0;
		goto out;
	}

	if (CFS_FAIL_CHECK_VALUE(CFS_KFI_REPLAY_IDLE_EVENT, event))
		return -EAGAIN;

	switch (event) {
	case TN_EVENT_INIT_IMMEDIATE:
	case TN_EVENT_TX_HELLO:
		tn->tn_target_addr = kfilnd_peer_get_kfi_addr(tn->tn_kp);
		KFILND_TN_DEBUG(tn, "Using peer %s(%#llx)",
				libcfs_nid2str(tn->tn_kp->kp_nid),
				tn->tn_target_addr);

		if (event == TN_EVENT_INIT_IMMEDIATE)
			kfilnd_tn_pack_immed_msg(tn);
		else
			kfilnd_tn_pack_hello_req(tn);

		/* Send immediate message. */
		rc = kfilnd_ep_post_send(tn->tn_ep, tn);
		switch (rc) {
		/* Async event will progress immediate send. */
		case 0:
			kfilnd_tn_state_change(tn, TN_STATE_IMM_SEND);
			return 0;

		/* Need to TN_EVENT_INIT_IMMEDIATE event while in TN_STATE_IDLE
		 * state.
		 */
		case -EAGAIN:
			KFILND_TN_DEBUG(tn, "Need to replay send to %s(%#llx)",
					libcfs_nid2str(tn->tn_kp->kp_nid),
					tn->tn_target_addr);
			return -EAGAIN;

		default:
			KFILND_TN_ERROR(tn,
					"Failed to post send to %s(%#llx): rc=%d",
					libcfs_nid2str(tn->tn_kp->kp_nid),
					tn->tn_target_addr, rc);
			if (event == TN_EVENT_TX_HELLO)
				kfilnd_peer_clear_hello_state(tn->tn_kp);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
		}
		break;

	case TN_EVENT_INIT_BULK:
		/* Post tagged receive buffer used to land bulk response. */
		rc = kfilnd_ep_post_tagged_recv(tn->tn_ep, tn);

		switch (rc) {
		/* Transition to TN_STATE_TAGGED_RECV_POSTED on success. */
		case 0:
			kfilnd_tn_state_change(tn, TN_STATE_TAGGED_RECV_POSTED);

			/* Propogate TN_EVENT_INIT_BULK event to
			 * TN_STATE_TAGGED_RECV_POSTED handler.
			 */
			return kfilnd_tn_state_tagged_recv_posted(tn, event,
								  rc,
								  tn_released);

		/* Need to replay TN_EVENT_INIT_BULK event in the TN_STATE_IDLE
		 * state.
		 */
		case -EAGAIN:
			KFILND_TN_DEBUG(tn, "Need to replay tagged recv");
			return -EAGAIN;

		default:
			KFILND_TN_ERROR(tn, "Failed to post tagged recv %d",
					rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
		}
		break;

	case TN_EVENT_RX_OK:
		if (kfilnd_peer_needs_hello(tn->tn_kp, false)) {
			rc = kfilnd_send_hello_request(tn->tn_ep->end_dev,
						       tn->tn_ep->end_cpt,
						       tn->tn_kp);
			if (rc)
				KFILND_TN_ERROR(tn,
						"Failed to send hello request: rc=%d",
						rc);
			rc = 0;
		}

		/* If this is a new peer then we cannot progress the transaction
		 * and must drop it
		 */
		if (kfilnd_peer_is_new_peer(tn->tn_kp)) {
			KFILND_TN_ERROR(tn,
					"Dropping message from %s due to stale peer",
					libcfs_nid2str(tn->tn_kp->kp_nid));
			kfilnd_tn_status_update(tn, -EPROTO,
						LNET_MSG_STATUS_LOCAL_DROPPED);
			rc = 0;
			goto out;
		}

		LASSERT(kfilnd_peer_is_new_peer(tn->tn_kp) == false);
		msg = tn->tn_rx_msg.msg;

		/* Update the NID address with the new preferred RX context. */
		kfilnd_peer_alive(tn->tn_kp);

		/* Pass message up to LNet
		 * The TN will be reused in this call chain so we need to
		 * release the lock on the TN before proceeding.
		 */
		KFILND_TN_DEBUG(tn, "%s -> TN_STATE_IMM_RECV state change",
				tn_state_to_str(tn->tn_state));

		/* TODO: Do not manually update this state change. */
		tn->tn_state = TN_STATE_IMM_RECV;
		mutex_unlock(&tn->tn_lock);
		*tn_released = true;
		lnet_nid4_to_nid(msg->srcnid, &srcnid);
		if (msg->type == KFILND_MSG_IMMEDIATE) {
			lnet_hdr_from_nid4(&hdr, &msg->proto.immed.hdr);
			rc = lnet_parse(tn->tn_ep->end_dev->kfd_ni,
					&hdr, &srcnid, tn, 0);
		} else {
			if (msg->version == KFILND_MSG_VERSION_1)
				lnet_hdr_from_nid4(&hdr, &msg->proto.bulk_req.hdr);
			else
				lnet_hdr_from_nid4(&hdr, &msg->proto.bulk_req_v2.kbrm2_hdr);
			rc = lnet_parse(tn->tn_ep->end_dev->kfd_ni,
					&hdr, &srcnid, tn, 1);
		}

		/* If successful, transaction has been accepted by LNet and we
		 * cannot process the transaction anymore within this context.
		 */
		if (!rc)
			return 0;

		KFILND_TN_ERROR(tn, "Failed to parse LNet message: rc=%d", rc);
		kfilnd_tn_status_update(tn, rc, LNET_MSG_STATUS_LOCAL_ERROR);
		break;

	case TN_EVENT_RX_HELLO:
		msg = tn->tn_rx_msg.msg;

		kfilnd_peer_alive(tn->tn_kp);

		switch (msg->type) {
		case KFILND_MSG_HELLO_REQ:
			if (CFS_FAIL_CHECK(CFS_KFI_REPLAY_RX_HELLO_REQ)) {
				CDEBUG(D_NET, "Replay RX HELLO_REQ\n");
				return -EAGAIN;
			}

			if (kfilnd_peer_is_new_peer(tn->tn_kp)) {
				rc = kfilnd_send_hello_request(tn->tn_ep->end_dev,
							       tn->tn_ep->end_cpt,
							       tn->tn_kp);
				if (rc)
					KFILND_TN_ERROR(tn,
							"Failed to send hello request: rc=%d",
							rc);
				rc = 0;
			}

			kfilnd_peer_process_hello(tn->tn_kp, msg);
			tn->tn_target_addr = kfilnd_peer_get_kfi_addr(tn->tn_kp);
			KFILND_TN_DEBUG(tn, "Using peer %s(%#llx)",
					libcfs_nid2str(tn->tn_kp->kp_nid),
					tn->tn_target_addr);

			kfilnd_tn_pack_hello_rsp(tn);

			/* Send immediate message. */
			rc = kfilnd_ep_post_send(tn->tn_ep, tn);
			switch (rc) {
			case 0:
				kfilnd_tn_state_change(tn, TN_STATE_IMM_SEND);
				return 0;

			case -EAGAIN:
				KFILND_TN_DEBUG(tn, "Need to replay send to %s(%#llx)",
						libcfs_nid2str(tn->tn_kp->kp_nid),
						tn->tn_target_addr);
				return -EAGAIN;

			default:
				KFILND_TN_ERROR(tn,
						"Failed to post send to %s(%#llx): rc=%d",
						libcfs_nid2str(tn->tn_kp->kp_nid),
						tn->tn_target_addr, rc);
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			}
			break;

		case KFILND_MSG_HELLO_RSP:
			rc = 0;
			kfilnd_peer_process_hello(tn->tn_kp, msg);
			finalize = true;
			break;

		default:
			KFILND_TN_ERROR(tn, "Invalid message type: %s",
					msg_type_to_str(msg->type));
			LBUG();
		}
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

out:
	if (kfilnd_tn_has_failed(tn))
		finalize = true;

	if (finalize)
		kfilnd_tn_finalize(tn, tn_released);

	return rc;
}

static int kfilnd_tn_state_imm_send(struct kfilnd_transaction *tn,
				    enum tn_events event, int status,
				    bool *tn_released)
{
	enum lnet_msg_hstatus hstatus;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TX_FAIL:
		if (status == -ETIMEDOUT || status == -EIO)
			hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		else
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;

		kfilnd_tn_status_update(tn, status, hstatus);
		/* RKEY is not involved in immediate sends, so no need to
		 * delete peer
		 */
		kfilnd_peer_tn_failed(tn->tn_kp, status, false);
		if (tn->msg_type == KFILND_MSG_HELLO_REQ)
			kfilnd_peer_clear_hello_state(tn->tn_kp);
		break;

	case TN_EVENT_TX_OK:
		kfilnd_peer_alive(tn->tn_kp);
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);

	return 0;
}

static int kfilnd_tn_state_imm_recv(struct kfilnd_transaction *tn,
				    enum tn_events event, int status,
				    bool *tn_released)
{
	int rc = 0;
	bool finalize = false;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_INIT_TAG_RMA:
	case TN_EVENT_SKIP_TAG_RMA:
		/* Release the buffer we received the request on. All relevant
		 * information to perform the RMA operation is stored in the
		 * transaction structure. This should be done before the RMA
		 * operation to prevent two contexts from potentially processing
		 * the same transaction.
		 *
		 * TODO: Prevent this from returning -EAGAIN.
		 */
		if (tn->tn_posted_buf) {
			kfilnd_ep_imm_buffer_put(tn->tn_posted_buf);
			tn->tn_posted_buf = NULL;
		}

		/* Update the KFI address to use the response RX context. */
		tn->tn_target_addr =
			kfi_rx_addr(KFILND_BASE_ADDR(tn->tn_kp->kp_addr),
				    tn->tn_response_rx, KFILND_FAB_RX_CTX_BITS);
		KFILND_TN_DEBUG(tn, "Using peer %s(0x%llx)",
				libcfs_nid2str(tn->tn_kp->kp_nid),
				tn->tn_target_addr);

		/* Initiate the RMA operation to push/pull the LNet payload or
		 * send a tagged message to finalize the bulk operation if the
		 * RMA operation should be skipped.
		 */
		if (event == TN_EVENT_INIT_TAG_RMA) {
			if (tn->sink_buffer)
				rc = kfilnd_ep_post_read(tn->tn_ep, tn);
			else
				rc = kfilnd_ep_post_write(tn->tn_ep, tn);

			switch (rc) {
			/* Async tagged RMA event will progress transaction. */
			case 0:
				kfilnd_tn_state_change(tn,
						       TN_STATE_WAIT_TAG_RMA_COMP);
				return 0;

			/* Need to replay TN_EVENT_INIT_TAG_RMA event while in
			 * the TN_STATE_IMM_RECV state.
			 */
			case -EAGAIN:
				KFILND_TN_DEBUG(tn,
						"Need to replay tagged %s to %s(%#llx)",
						tn->sink_buffer ? "read" : "write",
						libcfs_nid2str(tn->tn_kp->kp_nid),
						tn->tn_target_addr);
				return -EAGAIN;

			default:
				KFILND_TN_ERROR(tn,
						"Failed to post tagged %s to %s(%#llx): rc=%d",
						tn->sink_buffer ? "read" : "write",
						libcfs_nid2str(tn->tn_kp->kp_nid),
						tn->tn_target_addr, rc);
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			}
		} else {
			kfilnd_tn_status_update(tn, status,
						LNET_MSG_STATUS_OK);

			/* Since the LNet initiator has posted a unique tagged
			 * buffer specific for this LNet transaction and the
			 * LNet target has decide not to push/pull to/for the
			 * LNet initiator tagged buffer, a noop operation is
			 * done to this tagged buffer (i/e payload transfer size
			 * is zero). But, immediate data, which contains the
			 * LNet target status for the transaction, is sent to
			 * the LNet initiator. Immediate data only appears in
			 * the completion event at the LNet initiator and not in
			 * the tagged buffer.
			 */
			tn->tagged_data = cpu_to_be64(abs(tn->tn_status));

			rc = kfilnd_ep_post_tagged_send(tn->tn_ep, tn);
			switch (rc) {
			/* Async tagged RMA event will progress transaction. */
			case 0:
				kfilnd_tn_state_change(tn,
						       TN_STATE_WAIT_TAG_COMP);
				return 0;

			/* Need to replay TN_EVENT_SKIP_TAG_RMA event while in
			 * the TN_STATE_IMM_RECV state.
			 */
			case -EAGAIN:
				KFILND_TN_DEBUG(tn,
						"Need to replay tagged send to %s(%#llx)",
						libcfs_nid2str(tn->tn_kp->kp_nid),
						tn->tn_target_addr);
				return -EAGAIN;

			default:
				KFILND_TN_ERROR(tn,
						"Failed to post tagged send to %s(%#llx): rc=%d",
						libcfs_nid2str(tn->tn_kp->kp_nid),
						tn->tn_target_addr, rc);
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			}
		}
		break;

	case TN_EVENT_RX_OK:
		finalize = true;
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	if (kfilnd_tn_has_failed(tn))
		finalize = true;

	if (finalize)
		kfilnd_tn_finalize(tn, tn_released);

	return rc;
}

static int kfilnd_tn_state_wait_comp(struct kfilnd_transaction *tn,
				     enum tn_events event, int status,
				     bool *tn_released)
{
	int rc;
	enum lnet_msg_hstatus hstatus;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TX_OK:
		if (unlikely(tn->msg_type == KFILND_MSG_BULK_PUT_REQ) &&
		    CFS_FAIL_CHECK_RESET(CFS_KFI_FAIL_WAIT_SEND_COMP1,
					 CFS_KFI_FAIL_WAIT_SEND_COMP2 |
					 CFS_FAIL_ONCE))
			break;
		if (unlikely(tn->msg_type == KFILND_MSG_BULK_PUT_REQ ||
			     tn->msg_type == KFILND_MSG_BULK_GET_REQ) &&
		    CFS_FAIL_CHECK(CFS_KFI_FAIL_WAIT_SEND_COMP3)) {
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;
			kfilnd_tn_status_update(tn, -EIO, hstatus);
			/* Don't delete peer on debug/test path */
			kfilnd_peer_tn_failed(tn->tn_kp, -EIO, false);
			kfilnd_tn_state_change(tn, TN_STATE_FAIL);
			break;
		}
		kfilnd_peer_alive(tn->tn_kp);
		kfilnd_tn_timeout_enable(tn);
		kfilnd_tn_state_change(tn, TN_STATE_WAIT_TAG_COMP);
		break;

	case TN_EVENT_TAG_RX_OK:
		if (status)
			kfilnd_tn_status_update(tn, status, LNET_MSG_STATUS_OK);

		kfilnd_tn_state_change(tn, TN_STATE_WAIT_SEND_COMP);
		if (unlikely(tn->msg_type == KFILND_MSG_BULK_PUT_REQ) &&
		    CFS_FAIL_CHECK(CFS_KFI_FAIL_WAIT_SEND_COMP2)) {
			struct kfi_cq_err_entry fake_error = {
				.op_context = tn,
				.flags = KFI_MSG | KFI_SEND,
				.err = EIO,
			};

			kfilnd_ep_gen_fake_err(tn->tn_ep, &fake_error);
		}
		break;

	case TN_EVENT_TX_FAIL:
		if (status == -ETIMEDOUT)
			hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		else
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;

		kfilnd_tn_status_update(tn, status, hstatus);
		/* The bulk request message failed, however, there is an edge
		 * case where the last request packet of a message is received
		 * at the target successfully, but the corresponding response
		 * packet is repeatedly dropped. This results in the target
		 * generating a success completion event but the initiator
		 * generating an error completion event. Due to this, we have to
		 * delete the peer here to protect the RKEY.
		 */
		kfilnd_peer_tn_failed(tn->tn_kp, status, true);

		/* Need to cancel the tagged receive to prevent resources from
		 * being leaked.
		 */
		rc = kfilnd_tn_cancel_tag_recv(tn);

		switch (rc) {
		/* Async cancel event will progress transaction. */
		case 0:
			kfilnd_tn_status_update(tn, status,
						LNET_MSG_STATUS_LOCAL_ERROR);
			kfilnd_tn_state_change(tn, TN_STATE_FAIL);
			return 0;

		/* Need to replay TN_EVENT_INIT_BULK event while in the
		 * TN_STATE_SEND_FAILED state.
		 */
		case -EAGAIN:
			KFILND_TN_DEBUG(tn,
					"Need to replay cancel tagged recv");
			return -EAGAIN;

		default:
			KFILND_TN_ERROR(tn,
					"Unexpected error during cancel tagged receive: rc=%d",
					rc);
			LBUG();
		}
		break;

	case TN_EVENT_TAG_RX_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_LOCAL_ERROR);
		/* The target may hold a reference to the RKEY, so we need to
		 * delete the peer to protect it
		 */
		kfilnd_peer_tn_failed(tn->tn_kp, status, true);
		kfilnd_tn_state_change(tn, TN_STATE_FAIL);
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	return 0;
}

static int kfilnd_tn_state_wait_send_comp(struct kfilnd_transaction *tn,
					  enum tn_events event, int status,
					  bool *tn_released)
{
	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TX_OK:
		kfilnd_peer_alive(tn->tn_kp);
		break;
	case TN_EVENT_TX_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_NETWORK_TIMEOUT);
		/* The bulk request message was never queued so we do not need
		 * to delete the peer
		 */
		kfilnd_peer_tn_failed(tn->tn_kp, status, false);
		break;
	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);

	return 0;
}

static int kfilnd_tn_state_wait_tag_rma_comp(struct kfilnd_transaction *tn,
					     enum tn_events event, int status,
					     bool *tn_released)
{
	enum lnet_msg_hstatus hstatus;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TAG_TX_OK:
		kfilnd_peer_alive(tn->tn_kp);
		break;

	case TN_EVENT_TAG_TX_FAIL:
		if (status == -ETIMEDOUT)
			hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		else
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;

		kfilnd_tn_status_update(tn, status, hstatus);
		/* This event occurrs at the target of a bulk LNetPut/Get.
		 * Since the target did not generate the RKEY, we needn't
		 * delete the peer.
		 */
		kfilnd_peer_tn_failed(tn->tn_kp, status, false);
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);

	return 0;
}

static int kfilnd_tn_state_wait_tag_comp(struct kfilnd_transaction *tn,
					 enum tn_events event, int status,
					 bool *tn_released)
{
	int rc;
	enum lnet_msg_hstatus hstatus;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TAG_RX_FAIL:
	case TN_EVENT_TAG_RX_OK:
		/* Status can be set for both TN_EVENT_TAG_RX_FAIL and
		 * TN_EVENT_TAG_RX_OK. For TN_EVENT_TAG_RX_OK, if status is set,
		 * LNet target returned -ENODATA.
		 */
		if (status) {
			if (event == TN_EVENT_TAG_RX_FAIL)
				kfilnd_tn_status_update(tn, status,
							LNET_MSG_STATUS_LOCAL_ERROR);
			else
				kfilnd_tn_status_update(tn, status,
							LNET_MSG_STATUS_OK);
		}

		if (!kfilnd_tn_timeout_cancel(tn)) {
			kfilnd_tn_state_change(tn, TN_STATE_WAIT_TIMEOUT_COMP);
			return 0;
		}
		break;

	case TN_EVENT_TIMEOUT:
		/* Need to cancel the tagged receive to prevent resources from
		 * being leaked.
		 */
		rc = kfilnd_tn_cancel_tag_recv(tn);

		switch (rc) {
		/* Async cancel event will progress transaction. */
		case 0:
			kfilnd_tn_state_change(tn,
					       TN_STATE_WAIT_TIMEOUT_TAG_COMP);
			return 0;

		/* Need to replay TN_EVENT_INIT_BULK event while in the
		 * TN_STATE_WAIT_TAG_COMP state.
		 */
		case -EAGAIN:
			KFILND_TN_DEBUG(tn,
					"Need to replay cancel tagged recv");
			return -EAGAIN;

		default:
			KFILND_TN_ERROR(tn,
					"Unexpected error during cancel tagged receive: rc=%d",
					rc);
			LBUG();
		}
		break;

	case TN_EVENT_TAG_TX_FAIL:
		if (status == -ETIMEDOUT)
			hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		else
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;

		kfilnd_tn_status_update(tn, status, hstatus);
		/* This event occurrs at the target of a bulk LNetPut/Get.
		 * Since the target did not generate the RKEY, we needn't
		 * delete the peer.
		 */
		kfilnd_peer_tn_failed(tn->tn_kp, status, false);
		break;

	case TN_EVENT_TAG_TX_OK:
		kfilnd_peer_alive(tn->tn_kp);
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);

	return 0;
}

static int kfilnd_tn_state_fail(struct kfilnd_transaction *tn,
				enum tn_events event, int status,
				bool *tn_released)
{
	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TX_FAIL:
		/* Prior TN states will have deleted the peer if necessary */
		kfilnd_peer_tn_failed(tn->tn_kp, status, false);
		break;

	case TN_EVENT_TX_OK:
		kfilnd_peer_alive(tn->tn_kp);
		break;

	case TN_EVENT_TAG_RX_OK:
		kfilnd_peer_alive(tn->tn_kp);
		if (tn->tn_status != status) {
			KFILND_TN_DEBUG(tn, "%d -> %d status change",
					tn->tn_status, status);
			tn->tn_status = status;
		}
		if (tn->hstatus != LNET_MSG_STATUS_OK) {
			KFILND_TN_DEBUG(tn, "%d -> %d health status change",
					tn->hstatus, LNET_MSG_STATUS_OK);
			tn->hstatus = LNET_MSG_STATUS_OK;
		}
		break;

	case TN_EVENT_TAG_RX_FAIL:
	case TN_EVENT_TAG_RX_CANCEL:
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);

	return 0;
}

static int kfilnd_tn_state_wait_timeout_tag_comp(struct kfilnd_transaction *tn,
						 enum tn_events event,
						 int status, bool *tn_released)
{
	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TAG_RX_CANCEL:
		kfilnd_tn_status_update(tn, -ETIMEDOUT,
					LNET_MSG_STATUS_NETWORK_TIMEOUT);
		/* We've cancelled locally, but the target may still have a ref
		 * on the RKEY. Delete the peer to protect it.
		 */
		kfilnd_peer_tn_failed(tn->tn_kp, -ETIMEDOUT, true);
		break;

	case TN_EVENT_TAG_RX_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_LOCAL_ERROR);
		/* The initiator of a bulk LNetPut/Get eagerly sends the bulk
		 * request message to the target without ensuring the tagged
		 * receive buffer is posted. Thus, the target could be issuing
		 * kfi_write/read operations using the tagged receive buffer
		 * RKEY, and we need to delete this peer to protect the it.
		 */
		kfilnd_peer_tn_failed(tn->tn_kp, status, true);
		break;

	case TN_EVENT_TAG_RX_OK:
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);

	return 0;
}

static int kfilnd_tn_state_wait_timeout_comp(struct kfilnd_transaction *tn,
					     enum tn_events event, int status,
					     bool *tn_released)
{
	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	if (event == TN_EVENT_TIMEOUT) {
		kfilnd_tn_finalize(tn, tn_released);
	} else {
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	return 0;
}

static int
(* const kfilnd_tn_state_dispatch_table[TN_STATE_MAX])(struct kfilnd_transaction *tn,
						       enum tn_events event,
						       int status,
						       bool *tn_released) = {
	[TN_STATE_IDLE] = kfilnd_tn_state_idle,
	[TN_STATE_WAIT_TAG_COMP] = kfilnd_tn_state_wait_tag_comp,
	[TN_STATE_IMM_SEND] = kfilnd_tn_state_imm_send,
	[TN_STATE_TAGGED_RECV_POSTED] = kfilnd_tn_state_tagged_recv_posted,
	[TN_STATE_SEND_FAILED] = kfilnd_tn_state_send_failed,
	[TN_STATE_WAIT_COMP] = kfilnd_tn_state_wait_comp,
	[TN_STATE_WAIT_TIMEOUT_COMP] = kfilnd_tn_state_wait_timeout_comp,
	[TN_STATE_WAIT_SEND_COMP] = kfilnd_tn_state_wait_send_comp,
	[TN_STATE_WAIT_TIMEOUT_TAG_COMP] =
		kfilnd_tn_state_wait_timeout_tag_comp,
	[TN_STATE_FAIL] = kfilnd_tn_state_fail,
	[TN_STATE_IMM_RECV] = kfilnd_tn_state_imm_recv,
	[TN_STATE_WAIT_TAG_RMA_COMP] = kfilnd_tn_state_wait_tag_rma_comp,
};

/**
 * kfilnd_tn_event_handler() - Update transaction state machine with an event.
 * @tn: Transaction to be updated.
 * @event: Transaction event.
 * @status: Errno status associated with the event.
 *
 * When the transaction event handler is first called on a new transaction, the
 * transaction is now own by the transaction system. This means that will be
 * freed by the system as the transaction is progressed through the state
 * machine.
 */
void kfilnd_tn_event_handler(struct kfilnd_transaction *tn,
			     enum tn_events event, int status)
{
	bool tn_released = false;
	int rc;

	if (!tn)
		return;

	mutex_lock(&tn->tn_lock);
	rc = kfilnd_tn_state_dispatch_table[tn->tn_state](tn, event, status,
							  &tn_released);
	if (rc == -EAGAIN) {
		tn->replay_event = event;
		tn->replay_status = status;
		kfilnd_ep_queue_tn_replay(tn->tn_ep, tn);
	}

	if (!tn_released)
		mutex_unlock(&tn->tn_lock);
}

/**
 * kfilnd_tn_free() - Free a transaction.
 */
void kfilnd_tn_free(struct kfilnd_transaction *tn)
{
	spin_lock(&tn->tn_ep->tn_list_lock);
	list_del(&tn->tn_entry);
	spin_unlock(&tn->tn_ep->tn_list_lock);

	KFILND_TN_DEBUG(tn, "Transaction freed");

	if (tn->tn_mr_key)
		kfilnd_ep_put_key(tn->tn_ep, tn->tn_mr_key);

	/* Free send message buffer if needed. */
	if (tn->tn_tx_msg.msg)
		kmem_cache_free(imm_buf_cache, tn->tn_tx_msg.msg);

	kmem_cache_free(tn_cache, tn);
}

/*
 * Allocation logic common to kfilnd_tn_alloc() and kfilnd_tn_alloc_for_hello().
 * @ep: The KFI LND endpoint to associate with the transaction.
 * @kp: The kfilnd peer to associate with the transaction.
 * See kfilnd_tn_alloc() for a description of the other fields
 * Note: Caller must have a reference on @kp
 */
static struct kfilnd_transaction *kfilnd_tn_alloc_common(struct kfilnd_ep *ep,
							 struct kfilnd_peer *kp,
							 bool alloc_msg,
							 bool is_initiator,
							 u16 key)
{
	struct kfilnd_transaction *tn;
	int rc;
	ktime_t tn_alloc_ts;

	tn_alloc_ts = ktime_get();

	tn = kmem_cache_zalloc(tn_cache, GFP_KERNEL);
	if (!tn) {
		rc = -ENOMEM;
		goto err;
	}

	if (alloc_msg) {
		tn->tn_tx_msg.msg = kmem_cache_alloc(imm_buf_cache, GFP_KERNEL);
		if (!tn->tn_tx_msg.msg) {
			rc = -ENOMEM;
			goto err_free_tn;
		}
	}

	tn->tn_mr_key = key;

	tn->tn_kp = kp;

	mutex_init(&tn->tn_lock);
	tn->tn_ep = ep;
	tn->tn_response_rx = ep->end_context_id;
	tn->tn_state = TN_STATE_IDLE;
	tn->hstatus = LNET_MSG_STATUS_OK;
	tn->deadline = ktime_get_seconds() + lnet_get_lnd_timeout();
	tn->tn_replay_deadline = ktime_sub(tn->deadline,
					   (lnet_get_lnd_timeout() / 2));
	tn->is_initiator = is_initiator;
	INIT_WORK(&tn->timeout_work, kfilnd_tn_timeout_work);

	/* Add the transaction to an endpoint.  This is like
	 * incrementing a ref counter.
	 */
	spin_lock(&ep->tn_list_lock);
	list_add_tail(&tn->tn_entry, &ep->tn_list);
	spin_unlock(&ep->tn_list_lock);

	tn->tn_alloc_ts = tn_alloc_ts;
	tn->tn_state_ts = ktime_get();

	KFILND_EP_DEBUG(ep, "TN %p allocated with tmk %u", tn, tn->tn_mr_key);

	return tn;

err_free_tn:
	if (tn->tn_tx_msg.msg)
		kmem_cache_free(imm_buf_cache, tn->tn_tx_msg.msg);
	kmem_cache_free(tn_cache, tn);
err:
	return ERR_PTR(rc);
}

static struct kfilnd_ep *kfilnd_dev_to_ep(struct kfilnd_dev *dev, int cpt)
{
	struct kfilnd_ep *ep;

	if (!dev)
		return ERR_PTR(-EINVAL);

	ep = dev->cpt_to_endpoint[cpt];
	if (!ep) {
		CWARN("%s used invalid cpt=%d\n",
		      libcfs_nidstr(&dev->kfd_ni->ni_nid), cpt);
		ep = dev->kfd_endpoints[0];
	}

	return ep;
}

/**
 * kfilnd_tn_alloc() - Allocate a new KFI LND transaction.
 * @dev: KFI LND device used to look the KFI LND endpoint to associate with the
 * transaction.
 * @cpt: CPT of the transaction.
 * @target_nid: Target NID of the transaction.
 * @alloc_msg: Allocate an immediate message for the transaction.
 * @is_initiator: Is initiator of LNet transaction.
 * @need_key: Is transaction memory region key needed.
 *
 * During transaction allocation, each transaction is associated with a KFI LND
 * endpoint use to post data transfer operations. The CPT argument is used to
 * lookup the KFI LND endpoint within the KFI LND device.
 *
 * Return: On success, valid pointer. Else, negative errno pointer.
 */
struct kfilnd_transaction *kfilnd_tn_alloc(struct kfilnd_dev *dev, int cpt,
					   lnet_nid_t target_nid,
					   bool alloc_msg, bool is_initiator,
					   bool need_key)
{
	struct kfilnd_transaction *tn;
	struct kfilnd_ep *ep;
	struct kfilnd_peer *kp;
	int rc;
	u16 key = 0;

	ep = kfilnd_dev_to_ep(dev, cpt);
	if (IS_ERR(ep)) {
		rc = PTR_ERR(ep);
		goto err;
	}

	/* Consider the following:
	 * Thread 1: Posts tagged receive with RKEY based on
	 *           peerA::kp_local_session_key X and tn_mr_key Y
	 * Thread 2: Fetches peerA with kp_local_session_key X
	 * Thread 1: Cancels tagged receive, marks peerA for removal, and
	 *	     releases tn_mr_key Y
	 * Thread 2: allocates tn_mr_key Y
	 * At this point, thread 2 has the same RKEY used by thread 1.
	 * Thus, we always allocate the tn_mr_key before looking up the peer,
	 * and we always mark peers for removal before releasing tn_mr_key.
	 */
	if (need_key) {
		rc = kfilnd_ep_get_key(ep);
		if (rc < 0)
			goto err;
		key = rc;
	}

	kp = kfilnd_peer_get(dev, target_nid);
	if (IS_ERR(kp)) {
		rc = PTR_ERR(kp);
		goto err_put_key;
	}

	tn = kfilnd_tn_alloc_common(ep, kp, alloc_msg, is_initiator, key);
	if (IS_ERR(tn)) {
		rc = PTR_ERR(tn);
		kfilnd_peer_put(kp);
		goto err_put_key;
	}

	return tn;

err_put_key:
	if (need_key)
		kfilnd_ep_put_key(ep, key);
err:
	return ERR_PTR(rc);
}

/* Like kfilnd_tn_alloc(), but caller already looked up the kfilnd_peer.
 * Used only to allocate a TN for a hello request.
 * See kfilnd_tn_alloc()/kfilnd_tn_alloc_comm()
 * Note: Caller must have a reference on @kp
 */
struct kfilnd_transaction *kfilnd_tn_alloc_for_hello(struct kfilnd_dev *dev, int cpt,
						     struct kfilnd_peer *kp)
{
	struct kfilnd_transaction *tn;
	struct kfilnd_ep *ep;
	int rc;

	ep = kfilnd_dev_to_ep(dev, cpt);
	if (IS_ERR(ep)) {
		rc = PTR_ERR(ep);
		goto err;
	}

	tn = kfilnd_tn_alloc_common(ep, kp, true, true, 0);
	if (IS_ERR(tn)) {
		rc = PTR_ERR(tn);
		goto err;
	}

	return tn;

err:
	return ERR_PTR(rc);
}

/**
 * kfilnd_tn_cleanup() - Cleanup KFI LND transaction system.
 *
 * This function should only be called when there are no outstanding
 * transactions.
 */
void kfilnd_tn_cleanup(void)
{
	kmem_cache_destroy(imm_buf_cache);
	kmem_cache_destroy(tn_cache);
}

/**
 * kfilnd_tn_init() - Initialize KFI LND transaction system.
 *
 * Return: On success, zero. Else, negative errno.
 */
int kfilnd_tn_init(void)
{
	tn_cache = kmem_cache_create("kfilnd_tn",
				     sizeof(struct kfilnd_transaction), 0,
				     SLAB_HWCACHE_ALIGN, NULL);
	if (!tn_cache)
		goto err;

	imm_buf_cache = kmem_cache_create("kfilnd_imm_buf",
					  KFILND_IMMEDIATE_MSG_SIZE, 0,
					  SLAB_HWCACHE_ALIGN, NULL);
	if (!imm_buf_cache)
		goto err_tn_cache_destroy;

	return 0;

err_tn_cache_destroy:
	kmem_cache_destroy(tn_cache);
err:
	return -ENOMEM;
}

/**
 * kfilnd_tn_set_kiov_buf() - Set the buffer used for a transaction.
 * @tn: Transaction to have buffer set.
 * @kiov: LNet KIOV buffer.
 * @num_iov: Number of IOVs.
 * @offset: Offset into IOVs where the buffer starts.
 * @len: Length of the buffer.
 *
 * This function takes the user provided IOV, offset, and len, and sets the
 * transaction buffer. The user provided IOV is an LNet KIOV. When the
 * transaction buffer is configured, the user provided offset is applied
 * when the transaction buffer is configured (i.e. the transaction buffer
 * offset is zero).
 */
int kfilnd_tn_set_kiov_buf(struct kfilnd_transaction *tn,
			   struct bio_vec *kiov, size_t num_iov,
			   size_t offset, size_t len)
{
	size_t i;
	size_t cur_len = 0;
	size_t cur_offset = offset;
	size_t cur_iov = 0;
	size_t tmp_len;
	size_t tmp_offset;

	for (i = 0; (i < num_iov) && (cur_len < len); i++) {
		/* Skip KIOVs until a KIOV with a length less than the current
		 * offset is found.
		 */
		if (kiov[i].bv_len <= cur_offset) {
			cur_offset -= kiov[i].bv_len;
			continue;
		}

		tmp_len = kiov[i].bv_len - cur_offset;
		tmp_offset = kiov[i].bv_len - tmp_len + kiov[i].bv_offset;

		if (tmp_len + cur_len > len)
			tmp_len = len - cur_len;

		/* tn_kiov is an array of size LNET_MAX_IOV */
		if (cur_iov >= LNET_MAX_IOV)
			return -EINVAL;

		tn->tn_kiov[cur_iov].bv_page = kiov[i].bv_page;
		tn->tn_kiov[cur_iov].bv_len = tmp_len;
		tn->tn_kiov[cur_iov].bv_offset = tmp_offset;

		cur_iov++;
		cur_len += tmp_len;
		cur_offset = 0;
	}

	tn->tn_num_iovec = cur_iov;
	tn->tn_nob = cur_len;

	return 0;
}
