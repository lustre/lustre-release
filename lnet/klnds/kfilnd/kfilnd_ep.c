// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * kfilnd endpoint implementation.
 */

#include "kfilnd_ep.h"
#include "kfilnd_dev.h"
#include "kfilnd_tn.h"
#include "kfilnd_cq.h"

/**
 * kfilnd_ep_post_recv() - Post a single receive buffer.
 * @ep: KFI LND endpoint to have receive buffers posted on.
 * @buf: Receive buffer to be posted.
 *
 * Return: On succes, zero. Else, negative errno.
 */
static int kfilnd_ep_post_recv(struct kfilnd_ep *ep,
			       struct kfilnd_immediate_buffer *buf)
{
	int rc;

	if (!ep || !buf)
		return -EINVAL;

	if (buf->immed_no_repost)
		return 0;

	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_RECV))
		return -EIO;
	else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_RECV_EAGAIN))
		return -EAGAIN;

	atomic_inc(&buf->immed_ref);
	rc = kfi_recv(ep->end_rx, buf->immed_buf, buf->immed_buf_size, NULL,
		      KFI_ADDR_UNSPEC, buf);
	if (rc)
		atomic_dec(&buf->immed_ref);

	return rc;
}

#define KFILND_EP_REPLAY_TIMER_MSEC (100U)

/**
 * kfilnd_ep_imm_buffer_put() - Decrement the immediate buffer count reference
 * counter.
 * @buf: Immediate buffer to have reference count decremented.
 *
 * If the immediate buffer's reference count reaches zero, the buffer will
 * automatically be reposted.
 */
void kfilnd_ep_imm_buffer_put(struct kfilnd_immediate_buffer *buf)
{
	unsigned long expires;
	int rc;

	if (!buf)
		return;

	if (atomic_sub_return(1, &buf->immed_ref) != 0)
		return;

	rc = kfilnd_ep_post_recv(buf->immed_end, buf);
	switch (rc) {
	case 0:
		break;

	/* Return the buffer reference and queue the immediate buffer put to be
	 * replayed.
	 */
	case -EAGAIN:
		expires = msecs_to_jiffies(KFILND_EP_REPLAY_TIMER_MSEC) +
			jiffies;
		atomic_inc(&buf->immed_ref);

		spin_lock(&buf->immed_end->replay_lock);
		list_add_tail(&buf->replay_entry,
			      &buf->immed_end->imm_buffer_replay);
		atomic_inc(&buf->immed_end->replay_count);
		spin_unlock(&buf->immed_end->replay_lock);

		if (!timer_pending(&buf->immed_end->replay_timer))
			mod_timer(&buf->immed_end->replay_timer, expires);
		break;

	/* Unexpected error resulting in immediate buffer not being able to be
	 * posted. Since immediate buffers are used to sink incoming messages,
	 * failure to post immediate buffers means failure to communicate.
	 *
	 * TODO: Prevent LNet NI from doing sends/recvs?
	 */
	default:
		KFILND_EP_ERROR(buf->immed_end,
				"Failed to post immediate receive buffer: rc=%d",
				rc);
	}
}

/**
 * kfilnd_ep_post_imm_buffers() - Post all immediate receive buffers.
 * @ep: KFI LND endpoint to have receive buffers posted on.
 *
 * This function should be called only during KFI LND device initialization.
 *
 * Return: On success, zero. Else, negative errno.
 */
int kfilnd_ep_post_imm_buffers(struct kfilnd_ep *ep)
{
	int rc = 0;
	int i;

	if (!ep)
		return -EINVAL;

	for (i = 0; i < immediate_rx_buf_count; i++) {
		rc = kfilnd_ep_post_recv(ep, &ep->end_immed_bufs[i]);
		if (rc)
			goto out;
	}

out:
	return rc;
}

/**
 * kfilnd_ep_cancel_imm_buffers() - Cancel all immediate receive buffers.
 * @ep: KFI LND endpoint to have receive buffers canceled.
 */
void kfilnd_ep_cancel_imm_buffers(struct kfilnd_ep *ep)
{
	int i;

	if (!ep)
		return;

	for (i = 0; i < immediate_rx_buf_count; i++) {
		ep->end_immed_bufs[i].immed_no_repost = true;

		/* Since this is called during LNet NI teardown, no need to
		 * pipeline retries. Just spin until -EAGAIN is not returned.
		 */
		while (kfi_cancel(&ep->end_rx->fid, &ep->end_immed_bufs[i]) ==
		       -EAGAIN)
			schedule();
	}
}

static void kfilnd_ep_err_fail_loc_work(struct work_struct *work)
{
	struct kfilnd_ep_err_fail_loc_work *err =
		container_of(work, struct kfilnd_ep_err_fail_loc_work, work);

	kfilnd_cq_process_error(err->ep, &err->err);
	kfree(err);
}

int kfilnd_ep_gen_fake_err(struct kfilnd_ep *ep,
			   const struct kfi_cq_err_entry *err)
{
	struct kfilnd_ep_err_fail_loc_work *fake_err;

	fake_err = kmalloc(sizeof(*fake_err), GFP_KERNEL);
	if (!fake_err)
		return -ENOMEM;

	fake_err->ep = ep;
	fake_err->err = *err;
	INIT_WORK(&fake_err->work, kfilnd_ep_err_fail_loc_work);
	queue_work(kfilnd_wq, &fake_err->work);

	return 0;
}

static uint64_t gen_init_tag_bits(struct kfilnd_transaction *tn)
{
	return (tn->tn_response_session_key << KFILND_EP_KEY_BITS) |
		tn->tn_response_mr_key;
}

static bool tn_session_key_is_valid(struct kfilnd_transaction *tn)
{
	if (tn->tn_response_session_key == tn->tn_kp->kp_remote_session_key)
		return true;

	KFILND_TN_DEBUG(tn, "Detected session key mismatch %u != %u\n",
			tn->tn_response_session_key,
			tn->tn_kp->kp_remote_session_key);
	return false;
}

/**
 * kfilnd_ep_post_tagged_send() - Post a tagged send operation.
 * @ep: KFI LND endpoint used to post the tagged receivce operation.
 * @tn: Transaction structure containing the send buffer to be posted.
 *
 * The tag for the post tagged send operation is the response memory region key
 * associated with the transaction.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_tagged_send(struct kfilnd_ep *ep,
			       struct kfilnd_transaction *tn)
{
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_TAGGED | KFI_SEND,
		.err = EIO,
	};
	int rc;

	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	if (!tn_session_key_is_valid(tn))
		return -EINVAL;

	/* Progress transaction to failure if send should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_SEND_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_SEND)) {
		return -EIO;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_SEND_EAGAIN)) {
		return -EAGAIN;
	}

	KFILND_TN_DEBUG(tn, "tagged_data: %llu tn_status: %d\n",
			tn->tagged_data, tn->tn_status);

	rc = kfi_tsenddata(ep->end_tx, NULL, 0, NULL, tn->tagged_data,
			   tn->tn_target_addr, gen_init_tag_bits(tn), tn);
	switch (rc) {
	case 0:
	case -EAGAIN:
		KFILND_EP_DEBUG(ep,
				"TN %p: %s tagged send of with tag 0x%x to peer 0x%llx: rc=%d",
				tn, rc ? "Failed to post" : "Posted",
				tn->tn_response_mr_key, tn->tn_target_addr, rc);
		break;

	default:
		KFILND_EP_ERROR(ep,
				"TN %p: Failed to post tagged send with tag 0x%x to peer 0x%llx: rc=%d",
				tn, tn->tn_response_mr_key,
				tn->tn_target_addr, rc);
	}

	return rc;
}

/**
 * kfilnd_ep_cancel_tagged_recv() - Cancel a tagged recv.
 * @ep: KFI LND endpoint used to cancel the tagged receivce operation.
 * @tn: Transaction structure containing the receive buffer to be cancelled.
 *
 * The tagged receive buffer context pointer is used to cancel a tagged receive
 * operation. The context pointer is always the transaction pointer.
 *
 * Return: 0 on success. -ENOENT if the tagged receive buffer is not found. The
 * tagged receive buffer may not be found due to a tagged send operation already
 * landing or the tagged receive buffer never being posted. Negative errno value
 * on error.
 */
int kfilnd_ep_cancel_tagged_recv(struct kfilnd_ep *ep,
				 struct kfilnd_transaction *tn)
{
	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_RECV_CANCEL_EAGAIN))
		return -EAGAIN;

	/* The async event count is not decremented for a cancel operation since
	 * it was incremented for the post tagged receive.
	 */
	return kfi_cancel(&ep->end_rx->fid, tn);
}

static uint64_t gen_target_tag_bits(struct kfilnd_transaction *tn)
{
	return (tn->tn_kp->kp_local_session_key << KFILND_EP_KEY_BITS) |
		tn->tn_mr_key;
}

/**
 * kfilnd_ep_post_tagged_recv() - Post a tagged receive operation.
 * @ep: KFI LND endpoint used to post the tagged receivce operation.
 * @tn: Transaction structure containing the receive buffer to be posted.
 *
 * The tag for the post tagged receive operation is the memory region key
 * associated with the transaction.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_tagged_recv(struct kfilnd_ep *ep,
			       struct kfilnd_transaction *tn)
{
	struct kfi_msg_tagged msg = {
		.tag = gen_target_tag_bits(tn),
		.context = tn,
		.addr = tn->tn_kp->kp_addr,
	};
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_TAGGED | KFI_RECV,
		.err = EIO,
	};
	int rc;

	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Progress transaction to failure if send should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_RECV_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_RECV)) {
		return -EIO;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_RECV_EAGAIN)) {
		return -EAGAIN;
	}

	msg.iov_count = tn->tn_num_iovec;
	msg.type = KFI_BVEC;
	msg.msg_biov = tn->tn_kiov;

	rc = kfi_trecvmsg(ep->end_rx, &msg, KFI_COMPLETION);
	switch (rc) {
	case 0:
	case -EAGAIN:
		KFILND_EP_DEBUG(ep,
				"TN %p: %s tagged recv of %u bytes (%u frags) with tag 0x%llx: rc=%d",
				tn, rc ? "Failed to post" : "Posted",
				tn->tn_nob, tn->tn_num_iovec, msg.tag, rc);
		break;

	default:
		KFILND_EP_ERROR(ep,
				"TN %p: Failed to post tagged recv of %u bytes (%u frags) with tag 0x%llx: rc=%d",
				tn, tn->tn_nob, tn->tn_num_iovec, msg.tag, rc);
	}

	return rc;
}

/**
 * kfilnd_ep_post_send() - Post a send operation.
 * @ep: KFI LND endpoint used to post the send operation.
 * @tn: Transaction structure containing the buffer to be sent.
 *
 * The target of the send operation is based on the target LNet NID field within
 * the transaction structure. A lookup of LNet NID to KFI address is performed.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_send(struct kfilnd_ep *ep, struct kfilnd_transaction *tn)
{
	size_t len;
	void *buf;
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_MSG | KFI_SEND,
		.err = EIO,
	};
	int rc;

	if (!ep || !tn)
		return -EINVAL;

	buf = tn->tn_tx_msg.msg;
	len = tn->tn_tx_msg.length;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Progress transaction to failure if send should fail. */
	if (CFS_FAIL_CHECK_VALUE(CFS_KFI_FAIL_MSG_TYPE,
				 tn->tn_tx_msg.msg->type) ||
	    CFS_FAIL_CHECK(CFS_KFI_FAIL_SEND_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_SEND)) {
		return -EIO;
	} else if (CFS_FAIL_CHECK_VALUE(CFS_KFI_FAIL_MSG_TYPE_EAGAIN,
					 tn->tn_tx_msg.msg->type) ||
		   CFS_FAIL_CHECK(CFS_KFI_FAIL_SEND_EAGAIN)) {
		return -EAGAIN;
	}

	rc = kfi_send(ep->end_tx, buf, len, NULL, tn->tn_target_addr, tn);
	switch (rc) {
	case 0:
	case -EAGAIN:
		KFILND_EP_DEBUG(ep,
				"TN %p: %s send of %lu bytes to peer 0x%llx: rc=%d",
				tn, rc ? "Failed to post" : "Posted",
				len, tn->tn_target_addr, rc);
		break;

	default:
		KFILND_EP_ERROR(ep,
				"TN %p: Failed to post send of %lu bytes to peer 0x%llx: rc=%d",
				tn, len, tn->tn_target_addr, rc);
	}

	return rc;
}

/**
 * kfilnd_ep_post_write() - Post a write operation.
 * @ep: KFI LND endpoint used to post the write operation.
 * @tn: Transaction structure containing the buffer to be read from.
 *
 * The target of the write operation is based on the target LNet NID field
 * within the transaction structure. A lookup of LNet NID to KFI address is
 * performed.
 *
 * The transaction cookie is used as the remote key for the target memory
 * region.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_write(struct kfilnd_ep *ep, struct kfilnd_transaction *tn)
{
	int rc;
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_TAGGED | KFI_RMA | KFI_WRITE | KFI_SEND,
		.err = EIO,
	};
	struct kfi_rma_iov rma_iov = {
		.len = tn->tn_nob,
		.key = gen_init_tag_bits(tn),
	};
	struct kfi_msg_rma rma = {
		.addr = tn->tn_target_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = tn,
	};

	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	if (!tn_session_key_is_valid(tn))
		return -EINVAL;

	/* Progress transaction to failure if read should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_WRITE_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_WRITE)) {
		return -EIO;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_WRITE_EAGAIN)) {
		return -EAGAIN;
	}

	rma.iov_count = tn->tn_num_iovec;
	rma.type = KFI_BVEC;
	rma.msg_biov = tn->tn_kiov;

	rc = kfi_writemsg(ep->end_tx, &rma, KFI_TAGGED | KFI_COMPLETION);
	switch (rc) {
	case 0:
	case -EAGAIN:
		KFILND_EP_DEBUG(ep,
				"TN ID %p: %s write of %u bytes in %u frags kp %s(%p) rma_iov.key %llu: rc=%d",
				tn, rc ? "Failed to post" : "Posted",
				tn->tn_nob, tn->tn_num_iovec,
				libcfs_nid2str(tn->tn_kp->kp_nid), tn->tn_kp,
				rma_iov.key, rc);
		break;

	default:
		KFILND_EP_ERROR(ep,
				"TN %p: Failed to post write of %u bytes in %u frags kp %s(%p) rma_iov.key %llu: rc=%d",
				tn, tn->tn_nob, tn->tn_num_iovec,
				libcfs_nid2str(tn->tn_kp->kp_nid), tn->tn_kp,
				rma_iov.key, rc);
	}

	return rc;
}

/**
 * kfilnd_ep_post_read() - Post a read operation.
 * @ep: KFI LND endpoint used to post the read operation.
 * @tn: Transaction structure containing the buffer to be read into.
 *
 * The target of the read operation is based on the target LNet NID field within
 * the transaction structure. A lookup of LNet NID to KFI address is performed.
 *
 * The transaction cookie is used as the remote key for the target memory
 * region.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_read(struct kfilnd_ep *ep, struct kfilnd_transaction *tn)
{
	int rc;
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_TAGGED | KFI_RMA | KFI_READ | KFI_SEND,
		.err = EIO,
	};
	struct kfi_rma_iov rma_iov = {
		.len = tn->tn_nob,
		.key = gen_init_tag_bits(tn),
	};
	struct kfi_msg_rma rma = {
		.addr = tn->tn_target_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = tn,
	};

	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	if (!tn_session_key_is_valid(tn))
		return -EINVAL;

	/* Progress transaction to failure if read should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_READ_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_READ)) {
		return -EIO;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_READ_EAGAIN)) {
		return -EAGAIN;
	}

	rma.iov_count = tn->tn_num_iovec;
	rma.type = KFI_BVEC;
	rma.msg_biov = tn->tn_kiov;

	rc = kfi_readmsg(ep->end_tx, &rma, KFI_TAGGED | KFI_COMPLETION);
	switch (rc) {
	case 0:
	case -EAGAIN:
		KFILND_EP_DEBUG(ep,
				"TN %p: %s read of %u bytes in %u frags kp %s(%p) rma_iov.key %llu: rc=%d",
				tn, rc ? "Failed to post" : "Posted",
				tn->tn_nob, tn->tn_num_iovec,
				libcfs_nid2str(tn->tn_kp->kp_nid), tn->tn_kp,
				rma_iov.key, rc);
		break;

	default:
		KFILND_EP_ERROR(ep,
				"TN %p: Failed to post read of %u bytes in %u frags kp %s(%p) rma_iov.key %llu: rc=%d",
				tn, tn->tn_nob, tn->tn_num_iovec,
				libcfs_nid2str(tn->tn_kp->kp_nid), tn->tn_kp,
				rma_iov.key, rc);
	}

	return rc;
}

void kfilnd_ep_queue_tn_replay(struct kfilnd_ep *ep,
			       struct kfilnd_transaction *tn)
{
	unsigned long expires = msecs_to_jiffies(KFILND_EP_REPLAY_TIMER_MSEC) +
		jiffies;

	spin_lock(&ep->replay_lock);
	list_add_tail(&tn->replay_entry, &ep->tn_replay);
	atomic_inc(&ep->replay_count);
	spin_unlock(&ep->replay_lock);

	if (!timer_pending(&ep->replay_timer))
		mod_timer(&ep->replay_timer, expires);
}

void kfilnd_ep_flush_replay_queue(struct kfilnd_ep *ep)
{
	LIST_HEAD(tn_replay);
	LIST_HEAD(imm_buf_replay);
	struct kfilnd_transaction *tn_first;
	struct kfilnd_transaction *tn_last;
	struct kfilnd_immediate_buffer *buf_first;
	struct kfilnd_immediate_buffer *buf_last;

	/* Since the endpoint replay lists can be manipulated while
	 * attempting to do replays, the entire replay list is moved to a
	 * temporary list.
	 */
	spin_lock(&ep->replay_lock);

	tn_first = list_first_entry_or_null(&ep->tn_replay,
					    struct kfilnd_transaction,
					    replay_entry);
	if (tn_first) {
		tn_last = list_last_entry(&ep->tn_replay,
					  struct kfilnd_transaction,
					  replay_entry);
		list_bulk_move_tail(&tn_replay, &tn_first->replay_entry,
				    &tn_last->replay_entry);
		LASSERT(list_empty(&ep->tn_replay));
	}

	buf_first = list_first_entry_or_null(&ep->imm_buffer_replay,
					     struct kfilnd_immediate_buffer,
					     replay_entry);
	if (buf_first) {
		buf_last = list_last_entry(&ep->imm_buffer_replay,
					   struct kfilnd_immediate_buffer,
					   replay_entry);
		list_bulk_move_tail(&imm_buf_replay, &buf_first->replay_entry,
				    &buf_last->replay_entry);
		LASSERT(list_empty(&ep->imm_buffer_replay));
	}

	spin_unlock(&ep->replay_lock);

	/* Replay all queued transactions. */
	list_for_each_entry_safe(tn_first, tn_last, &tn_replay, replay_entry) {
		list_del(&tn_first->replay_entry);
		atomic_dec(&ep->replay_count);
		kfilnd_tn_event_handler(tn_first, tn_first->replay_event,
					tn_first->replay_status);
	}

	list_for_each_entry_safe(buf_first, buf_last, &imm_buf_replay,
				 replay_entry) {
		list_del(&buf_first->replay_entry);
		atomic_dec(&ep->replay_count);
		kfilnd_ep_imm_buffer_put(buf_first);
	}
}

static void kfilnd_ep_replay_work(struct work_struct *work)
{
	struct kfilnd_ep *ep =
		container_of(work, struct kfilnd_ep, replay_work);

	kfilnd_ep_flush_replay_queue(ep);
}

static void kfilnd_ep_replay_timer(cfs_timer_cb_arg_t data)
{
	struct kfilnd_ep *ep = cfs_from_timer(ep, data, replay_timer);
	unsigned int cpu =
		cpumask_first(*cfs_cpt_cpumask(lnet_cpt_table(), ep->end_cpt));

	queue_work_on(cpu, kfilnd_wq, &ep->replay_work);
}

#define KFILND_EP_ALLOC_SIZE \
	(sizeof(struct kfilnd_ep) + \
	 (sizeof(struct kfilnd_immediate_buffer) * immediate_rx_buf_count))

/**
 * kfilnd_ep_free() - Free a KFI LND endpoint.
 * @ep: KFI LND endpoint to be freed.
 *
 * Safe to call on NULL or error pointer.
 */
void kfilnd_ep_free(struct kfilnd_ep *ep)
{
	int i;
	int k = 2;

	if (IS_ERR_OR_NULL(ep))
		return;

	while (atomic_read(&ep->replay_count)) {
		k++;
		CDEBUG(((k & (-k)) == k) ? D_WARNING : D_NET,
			"Waiting for replay count %d not zero\n",
			atomic_read(&ep->replay_count));
		schedule_timeout_uninterruptible(HZ);
	}

	/* Cancel any outstanding immediate receive buffers. */
	kfilnd_ep_cancel_imm_buffers(ep);

	/* Wait for RX buffers to no longer be used and then free them. */
	for (i = 0; i < immediate_rx_buf_count; i++) {
		k = 2;
		while (atomic_read(&ep->end_immed_bufs[i].immed_ref)) {
			k++;
			CDEBUG(((k & (-k)) == k) ? D_WARNING : D_NET,
			       "Waiting for RX buffer %d to release\n", i);
			schedule_timeout_uninterruptible(HZ);
		}
	}

	/* Wait for all transactions to complete. */
	k = 2;
	spin_lock(&ep->tn_list_lock);
	while (!list_empty(&ep->tn_list)) {
		spin_unlock(&ep->tn_list_lock);
		k++;
		CDEBUG(((k & (-k)) == k) ? D_WARNING : D_NET,
		       "Waiting for transactions to complete\n");
		schedule_timeout_uninterruptible(HZ);
		spin_lock(&ep->tn_list_lock);
	}
	spin_unlock(&ep->tn_list_lock);

	/* Free all immediate buffers. */
	for (i = 0; i < immediate_rx_buf_count; i++)
		__free_pages(ep->end_immed_bufs[i].immed_buf_page,
			     order_base_2(ep->end_immed_bufs[i].immed_buf_size / PAGE_SIZE));

	kfi_close(&ep->end_tx->fid);
	kfi_close(&ep->end_rx->fid);
	kfilnd_cq_free(ep->end_tx_cq);
	kfilnd_cq_free(ep->end_rx_cq);
	ida_destroy(&ep->keys);
	LIBCFS_FREE(ep, KFILND_EP_ALLOC_SIZE);
}

/**
 * kfilnd_ep_alloc() - Allocate a new KFI LND endpoint.
 * @dev: KFI LND device used to allocate endpoints.
 * @context_id: Context ID associated with the endpoint.
 * @cpt: CPT KFI LND endpoint should be associated with.
 *
 * An KFI LND endpoint consists of unique transmit/receive command queues
 * (contexts) and completion queues. The underlying completion queue interrupt
 * vector is associated with a core within the CPT.
 *
 * Return: On success, valid pointer. Else, negative errno pointer.
 */
struct kfilnd_ep *kfilnd_ep_alloc(struct kfilnd_dev *dev,
				  unsigned int context_id, unsigned int cpt,
				  size_t nrx, size_t rx_size)
{
	int rc;
	struct kfi_cq_attr cq_attr = {};
	struct kfi_rx_attr rx_attr = {};
	struct kfi_tx_attr tx_attr = {};
	int ncpts;
	size_t min_multi_recv = KFILND_IMMEDIATE_MSG_SIZE;
	struct kfilnd_ep *ep;
	int i;
	size_t rx_buf_size;

	if (!dev || !nrx || !rx_size) {
		rc = -EINVAL;
		goto err;
	}

	ncpts = dev->kfd_ni->ni_ncpts;

	LIBCFS_CPT_ALLOC(ep, lnet_cpt_table(), cpt, KFILND_EP_ALLOC_SIZE);
	if (!ep) {
		rc = -ENOMEM;
		goto err;
	}

	ep->end_dev = dev;
	ep->end_cpt = cpt;
	ep->end_context_id = context_id;
	INIT_LIST_HEAD(&ep->tn_list);
	spin_lock_init(&ep->tn_list_lock);
	INIT_LIST_HEAD(&ep->tn_replay);
	INIT_LIST_HEAD(&ep->imm_buffer_replay);
	spin_lock_init(&ep->replay_lock);
	cfs_timer_setup(&ep->replay_timer, kfilnd_ep_replay_timer,
			(unsigned long)ep, 0);
	INIT_WORK(&ep->replay_work, kfilnd_ep_replay_work);
	atomic_set(&ep->replay_count, 0);
	ida_init(&ep->keys);

	/* Create a CQ for this CPT */
	cq_attr.flags = KFI_AFFINITY;
	cq_attr.format = KFI_CQ_FORMAT_DATA;
	cq_attr.wait_cond = KFI_CQ_COND_NONE;
	cq_attr.wait_obj = KFI_WAIT_NONE;

	/* Vector is set to first core in the CPT */
	cq_attr.signaling_vector =
		cpumask_first(*cfs_cpt_cpumask(lnet_cpt_table(), cpt));

	cq_attr.size = dev->kfd_ni->ni_net->net_tunables.lct_max_tx_credits *
		rx_cq_scale_factor;
	ep->end_rx_cq = kfilnd_cq_alloc(ep, &cq_attr);
	if (IS_ERR(ep->end_rx_cq)) {
		rc = PTR_ERR(ep->end_rx_cq);
		CERROR("Failed to allocated KFILND RX CQ: rc=%d\n", rc);
		goto err_free_ep;
	}

	cq_attr.size = dev->kfd_ni->ni_net->net_tunables.lct_max_tx_credits *
		tx_cq_scale_factor;
	ep->end_tx_cq = kfilnd_cq_alloc(ep, &cq_attr);
	if (IS_ERR(ep->end_tx_cq)) {
		rc = PTR_ERR(ep->end_tx_cq);
		CERROR("Failed to allocated KFILND TX CQ: rc=%d\n", rc);
		goto err_free_rx_cq;
	}

	/* Initialize the RX/TX contexts for the given CPT */
	rx_attr.op_flags = KFI_COMPLETION | KFI_MULTI_RECV;
	rx_attr.msg_order = KFI_ORDER_NONE;
	rx_attr.comp_order = KFI_ORDER_NONE;
	rx_attr.size = dev->kfd_ni->ni_net->net_tunables.lct_max_tx_credits +
		immediate_rx_buf_count;
	rx_attr.iov_limit = LNET_MAX_IOV;
	rc = kfi_rx_context(dev->kfd_sep, context_id, &rx_attr, &ep->end_rx,
			    ep);
	if (rc) {
		CERROR("Could not create RX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_cq;
	}

	/* Set the lower limit for multi-receive buffers */
	rc = kfi_setopt(&ep->end_rx->fid, KFI_OPT_ENDPOINT,
			KFI_OPT_MIN_MULTI_RECV, &min_multi_recv,
			sizeof(min_multi_recv));
	if (rc) {
		CERROR("Could not set min_multi_recv on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_rx_context;
	}

	tx_attr.op_flags = KFI_COMPLETION | KFI_TRANSMIT_COMPLETE;
	tx_attr.msg_order = KFI_ORDER_NONE;
	tx_attr.comp_order = KFI_ORDER_NONE;
	tx_attr.size = dev->kfd_ni->ni_net->net_tunables.lct_max_tx_credits *
		tx_scale_factor;
	tx_attr.iov_limit = LNET_MAX_IOV;
	tx_attr.rma_iov_limit = LNET_MAX_IOV;
	tx_attr.tclass =
		dev->kfd_ni->ni_lnd_tunables.lnd_tun_u.lnd_kfi.lnd_traffic_class;
	rc = kfi_tx_context(dev->kfd_sep, context_id, &tx_attr, &ep->end_tx,
			    ep);
	if (rc) {
		CERROR("Could not create TX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_rx_context;
	}

	/* Bind these two contexts to the CPT's CQ */
	rc = kfi_ep_bind(ep->end_rx, &ep->end_rx_cq->cq->fid, 0);
	if (rc) {
		CERROR("Could not bind RX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	rc = kfi_ep_bind(ep->end_tx, &ep->end_tx_cq->cq->fid, 0);
	if (rc) {
		CERROR("Could not bind TX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	/* Enable both endpoints */
	rc = kfi_enable(ep->end_rx);
	if (rc) {
		CERROR("Could not enable RX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	rc = kfi_enable(ep->end_tx);
	if (rc) {
		CERROR("Could not enable TX context on CPT %d, rc=%d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	/* The nrx value is the max number of immediate messages any one peer
	 * can send us.  Given that compute nodes are RPC-based, we should not
	 * see any more incoming messages than we are able to send.  A such, nrx
	 * is a good size for each multi-receive buffer.  However, if we are
	 * a server or LNet router, we need a multiplier of this value. For
	 * now, we will just have nrx drive the buffer size per CPT.  Then,
	 * LNet routers and servers can just define more CPTs to get a better
	 * spread of buffers to receive messages from multiple peers.  A better
	 * way should be devised in the future.
	 */
	rx_buf_size = roundup_pow_of_two(max(nrx * rx_size, PAGE_SIZE));

	for (i = 0; i < immediate_rx_buf_count; i++) {

		/* Using physically contiguous allocations can allow for
		 * underlying kfabric providers to use untranslated addressing
		 * instead of having to setup NIC memory mappings. This
		 * typically leads to improved performance.
		 */
		ep->end_immed_bufs[i].immed_buf_page =
			alloc_pages_node(cfs_cpt_spread_node(lnet_cpt_table(), cpt),
					 GFP_KERNEL | __GFP_NOWARN,
					 order_base_2(rx_buf_size / PAGE_SIZE));
		if (!ep->end_immed_bufs[i].immed_buf_page) {
			rc = -ENOMEM;
			goto err_free_rx_buffers;
		}

		atomic_set(&ep->end_immed_bufs[i].immed_ref, 0);
		ep->end_immed_bufs[i].immed_buf =
			page_address(ep->end_immed_bufs[i].immed_buf_page);
		ep->end_immed_bufs[i].immed_buf_size = rx_buf_size;
		ep->end_immed_bufs[i].immed_end = ep;
	}

	return ep;

err_free_rx_buffers:
	for (i = 0; i < immediate_rx_buf_count; i++) {
		if (ep->end_immed_bufs[i].immed_buf_page)
			__free_pages(ep->end_immed_bufs[i].immed_buf_page,
				     order_base_2(ep->end_immed_bufs[i].immed_buf_size / PAGE_SIZE));
	}

err_free_tx_context:
	kfi_close(&ep->end_tx->fid);
err_free_rx_context:
	kfi_close(&ep->end_rx->fid);
err_free_tx_cq:
	kfilnd_cq_free(ep->end_tx_cq);
err_free_rx_cq:
	kfilnd_cq_free(ep->end_rx_cq);
err_free_ep:
	LIBCFS_FREE(ep, KFILND_EP_ALLOC_SIZE);
err:
	return ERR_PTR(rc);
}

int kfilnd_ep_get_key(struct kfilnd_ep *ep)
{
	return ida_simple_get(&ep->keys, 1, KFILND_EP_KEY_MAX, GFP_KERNEL);
}

void kfilnd_ep_put_key(struct kfilnd_ep *ep, unsigned int key)
{
	ida_simple_remove(&ep->keys, key);
}
