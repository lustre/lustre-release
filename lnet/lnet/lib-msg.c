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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/lnet/lib-msg.c
 *
 * Message decoding, parsing and finalizing routines
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lib-lnet.h>

void
lnet_build_unlink_event(struct lnet_libmd *md, struct lnet_event *ev)
{
	ENTRY;

	memset(ev, 0, sizeof(*ev));

	ev->status   = 0;
	ev->unlinked = 1;
	ev->type     = LNET_EVENT_UNLINK;
	lnet_md_deconstruct(md, ev);
	lnet_md2handle(&ev->md_handle, md);
	EXIT;
}

/*
 * Don't need any lock, must be called after lnet_commit_md
 */
void
lnet_build_msg_event(struct lnet_msg *msg, enum lnet_event_kind ev_type)
{
	struct lnet_hdr	*hdr = &msg->msg_hdr;
	struct lnet_event *ev = &msg->msg_ev;

	LASSERT(!msg->msg_routing);

	ev->type = ev_type;
	ev->msg_type = msg->msg_type;

	if (ev_type == LNET_EVENT_SEND) {
		/* event for active message */
		ev->target.nid	  = le64_to_cpu(hdr->dest_nid);
		ev->target.pid	  = le32_to_cpu(hdr->dest_pid);
		ev->initiator.nid = LNET_NID_ANY;
		ev->initiator.pid = the_lnet.ln_pid;
		ev->source.nid	  = LNET_NID_ANY;
		ev->source.pid    = the_lnet.ln_pid;
		ev->sender	  = LNET_NID_ANY;
	} else {
		/* event for passive message */
		ev->target.pid	  = hdr->dest_pid;
		ev->target.nid	  = hdr->dest_nid;
		ev->initiator.pid = hdr->src_pid;
		/* Multi-Rail: resolve src_nid to "primary" peer NID */
		ev->initiator.nid = msg->msg_initiator;
		/* Multi-Rail: track source NID. */
		ev->source.pid	  = hdr->src_pid;
		ev->source.nid	  = hdr->src_nid;
		ev->rlength       = hdr->payload_length;
		ev->sender	  = msg->msg_from;
		ev->mlength	  = msg->msg_wanted;
		ev->offset	  = msg->msg_offset;
	}

	switch (ev_type) {
	default:
		LBUG();

	case LNET_EVENT_PUT: /* passive PUT */
		ev->pt_index   = hdr->msg.put.ptl_index;
		ev->match_bits = hdr->msg.put.match_bits;
		ev->hdr_data   = hdr->msg.put.hdr_data;
		return;

	case LNET_EVENT_GET: /* passive GET */
		ev->pt_index   = hdr->msg.get.ptl_index;
		ev->match_bits = hdr->msg.get.match_bits;
		ev->hdr_data   = 0;
		return;

	case LNET_EVENT_ACK: /* ACK */
		ev->match_bits = hdr->msg.ack.match_bits;
		ev->mlength    = hdr->msg.ack.mlength;
		return;

	case LNET_EVENT_REPLY: /* REPLY */
		return;

	case LNET_EVENT_SEND: /* active message */
		if (msg->msg_type == LNET_MSG_PUT) {
			ev->pt_index   = le32_to_cpu(hdr->msg.put.ptl_index);
			ev->match_bits = le64_to_cpu(hdr->msg.put.match_bits);
			ev->offset     = le32_to_cpu(hdr->msg.put.offset);
			ev->mlength    =
			ev->rlength    = le32_to_cpu(hdr->payload_length);
			ev->hdr_data   = le64_to_cpu(hdr->msg.put.hdr_data);

		} else {
			LASSERT(msg->msg_type == LNET_MSG_GET);
			ev->pt_index   = le32_to_cpu(hdr->msg.get.ptl_index);
			ev->match_bits = le64_to_cpu(hdr->msg.get.match_bits);
			ev->mlength    =
			ev->rlength    = le32_to_cpu(hdr->msg.get.sink_length);
			ev->offset     = le32_to_cpu(hdr->msg.get.src_offset);
			ev->hdr_data   = 0;
		}
		return;
	}
}

void
lnet_msg_commit(struct lnet_msg *msg, int cpt)
{
	struct lnet_msg_container *container = the_lnet.ln_msg_containers[cpt];
	struct lnet_counters_common *common;
	s64 timeout_ns;

	/* set the message deadline */
	timeout_ns = lnet_transaction_timeout * NSEC_PER_SEC;
	msg->msg_deadline = ktime_add_ns(ktime_get(), timeout_ns);

	/* routed message can be committed for both receiving and sending */
	LASSERT(!msg->msg_tx_committed);

	if (msg->msg_sending) {
		LASSERT(!msg->msg_receiving);
		msg->msg_tx_cpt = cpt;
		msg->msg_tx_committed = 1;
		if (msg->msg_rx_committed) { /* routed message REPLY */
			LASSERT(msg->msg_onactivelist);
			return;
		}
	} else {
		LASSERT(!msg->msg_sending);
		msg->msg_rx_cpt = cpt;
		msg->msg_rx_committed = 1;
	}

	LASSERT(!msg->msg_onactivelist);

	msg->msg_onactivelist = 1;
	list_add_tail(&msg->msg_activelist, &container->msc_active);

	common = &the_lnet.ln_counters[cpt]->lct_common;
	common->lcc_msgs_alloc++;
	if (common->lcc_msgs_alloc > common->lcc_msgs_max)
		common->lcc_msgs_max = common->lcc_msgs_alloc;
}

static void
lnet_msg_decommit_tx(struct lnet_msg *msg, int status)
{
	struct lnet_counters_common *common;
	struct lnet_event *ev = &msg->msg_ev;

	LASSERT(msg->msg_tx_committed);
	if (status != 0)
		goto out;

	common = &(the_lnet.ln_counters[msg->msg_tx_cpt]->lct_common);
	switch (ev->type) {
	default: /* routed message */
		LASSERT(msg->msg_routing);
		LASSERT(msg->msg_rx_committed);
		LASSERT(ev->type == 0);

		common->lcc_route_length += msg->msg_len;
		common->lcc_route_count++;
		goto incr_stats;

	case LNET_EVENT_PUT:
		/* should have been decommitted */
		LASSERT(!msg->msg_rx_committed);
		/* overwritten while sending ACK */
		LASSERT(msg->msg_type == LNET_MSG_ACK);
		msg->msg_type = LNET_MSG_PUT; /* fix type */
		break;

	case LNET_EVENT_SEND:
		LASSERT(!msg->msg_rx_committed);
		if (msg->msg_type == LNET_MSG_PUT)
			common->lcc_send_length += msg->msg_len;
		break;

	case LNET_EVENT_GET:
		LASSERT(msg->msg_rx_committed);
		/* overwritten while sending reply, we should never be
		 * here for optimized GET */
		LASSERT(msg->msg_type == LNET_MSG_REPLY);
		msg->msg_type = LNET_MSG_GET; /* fix type */
		break;
	}

	common->lcc_send_count++;

incr_stats:
	if (msg->msg_txpeer)
		lnet_incr_stats(&msg->msg_txpeer->lpni_stats,
				msg->msg_type,
				LNET_STATS_TYPE_SEND);
	if (msg->msg_txni)
		lnet_incr_stats(&msg->msg_txni->ni_stats,
				msg->msg_type,
				LNET_STATS_TYPE_SEND);
 out:
	lnet_return_tx_credits_locked(msg);
	msg->msg_tx_committed = 0;
}

static void
lnet_msg_decommit_rx(struct lnet_msg *msg, int status)
{
	struct lnet_counters_common *common;
	struct lnet_event *ev = &msg->msg_ev;

	LASSERT(!msg->msg_tx_committed); /* decommitted or never committed */
	LASSERT(msg->msg_rx_committed);

	if (status != 0)
		goto out;

	common = &(the_lnet.ln_counters[msg->msg_rx_cpt]->lct_common);
	switch (ev->type) {
	default:
		LASSERT(ev->type == 0);
		LASSERT(msg->msg_routing);
		goto incr_stats;

	case LNET_EVENT_ACK:
		LASSERT(msg->msg_type == LNET_MSG_ACK);
		break;

	case LNET_EVENT_GET:
		/* type is "REPLY" if it's an optimized GET on passive side,
		 * because optimized GET will never be committed for sending,
		 * so message type wouldn't be changed back to "GET" by
		 * lnet_msg_decommit_tx(), see details in lnet_parse_get() */
		LASSERT(msg->msg_type == LNET_MSG_REPLY ||
			msg->msg_type == LNET_MSG_GET);
		common->lcc_send_length += msg->msg_wanted;
		break;

	case LNET_EVENT_PUT:
		LASSERT(msg->msg_type == LNET_MSG_PUT);
		break;

	case LNET_EVENT_REPLY:
		/* type is "GET" if it's an optimized GET on active side,
		 * see details in lnet_create_reply_msg() */
		LASSERT(msg->msg_type == LNET_MSG_GET ||
			msg->msg_type == LNET_MSG_REPLY);
		break;
	}

	common->lcc_recv_count++;

incr_stats:
	if (msg->msg_rxpeer)
		lnet_incr_stats(&msg->msg_rxpeer->lpni_stats,
				msg->msg_type,
				LNET_STATS_TYPE_RECV);
	if (msg->msg_rxni)
		lnet_incr_stats(&msg->msg_rxni->ni_stats,
				msg->msg_type,
				LNET_STATS_TYPE_RECV);
	if (ev->type == LNET_EVENT_PUT || ev->type == LNET_EVENT_REPLY)
		common->lcc_recv_length += msg->msg_wanted;

 out:
	lnet_return_rx_credits_locked(msg);
	msg->msg_rx_committed = 0;
}

void
lnet_msg_decommit(struct lnet_msg *msg, int cpt, int status)
{
	int	cpt2 = cpt;

	LASSERT(msg->msg_tx_committed || msg->msg_rx_committed);
	LASSERT(msg->msg_onactivelist);

	if (msg->msg_tx_committed) { /* always decommit for sending first */
		LASSERT(cpt == msg->msg_tx_cpt);
		lnet_msg_decommit_tx(msg, status);
	}

	if (msg->msg_rx_committed) {
		/* forwarding msg committed for both receiving and sending */
		if (cpt != msg->msg_rx_cpt) {
			lnet_net_unlock(cpt);
			cpt2 = msg->msg_rx_cpt;
			lnet_net_lock(cpt2);
		}
		lnet_msg_decommit_rx(msg, status);
	}

	list_del(&msg->msg_activelist);
	msg->msg_onactivelist = 0;

	the_lnet.ln_counters[cpt2]->lct_common.lcc_msgs_alloc--;

	if (cpt2 != cpt) {
		lnet_net_unlock(cpt2);
		lnet_net_lock(cpt);
	}
}

void
lnet_msg_attach_md(struct lnet_msg *msg, struct lnet_libmd *md,
		   unsigned int offset, unsigned int mlen)
{
	/* NB: @offset and @len are only useful for receiving */
	/* Here, we attach the MD on lnet_msg and mark it busy and
	 * decrementing its threshold. Come what may, the lnet_msg "owns"
	 * the MD until a call to lnet_msg_detach_md or lnet_finalize()
	 * signals completion. */
	LASSERT(!msg->msg_routing);

	msg->msg_md = md;
	if (msg->msg_receiving) { /* committed for receiving */
		msg->msg_offset = offset;
		msg->msg_wanted = mlen;
	}

	md->md_refcount++;
	if (md->md_threshold != LNET_MD_THRESH_INF) {
		LASSERT(md->md_threshold > 0);
		md->md_threshold--;
	}

	/* build umd in event */
	lnet_md2handle(&msg->msg_ev.md_handle, md);
	lnet_md_deconstruct(md, &msg->msg_ev);
}

static int
lnet_complete_msg_locked(struct lnet_msg *msg, int cpt)
{
	struct lnet_handle_wire ack_wmd;
	int		   rc;
	int		   status = msg->msg_ev.status;

	LASSERT(msg->msg_onactivelist);

	if (status == 0 && msg->msg_ack) {
		/* Only send an ACK if the PUT completed successfully */

		lnet_msg_decommit(msg, cpt, 0);

		msg->msg_ack = 0;
		lnet_net_unlock(cpt);

		LASSERT(msg->msg_ev.type == LNET_EVENT_PUT);
		LASSERT(!msg->msg_routing);

		ack_wmd = msg->msg_hdr.msg.put.ack_wmd;

		lnet_prep_send(msg, LNET_MSG_ACK, msg->msg_ev.source, 0, 0);

		msg->msg_hdr.msg.ack.dst_wmd = ack_wmd;
		msg->msg_hdr.msg.ack.match_bits = msg->msg_ev.match_bits;
		msg->msg_hdr.msg.ack.mlength = cpu_to_le32(msg->msg_ev.mlength);

		rc = lnet_send(msg->msg_ev.target.nid, msg, msg->msg_from);

		lnet_net_lock(cpt);
		/*
		 * NB: message is committed for sending, we should return
		 * on success because LND will finalize this message later.
		 *
		 * Also, there is possibility that message is committed for
		 * sending and also failed before delivering to LND,
		 * i.e: ENOMEM, in that case we can't fall through either
		 * because CPT for sending can be different with CPT for
		 * receiving, so we should return back to lnet_finalize()
		 * to make sure we are locking the correct partition.
		 */
		return rc;

	} else if (status == 0 &&	/* OK so far */
		   (msg->msg_routing && !msg->msg_sending)) {
		/* not forwarded */
		LASSERT(!msg->msg_receiving);	/* called back recv already */
		lnet_net_unlock(cpt);

		rc = lnet_send(LNET_NID_ANY, msg, LNET_NID_ANY);

		lnet_net_lock(cpt);
		/*
		 * NB: message is committed for sending, we should return
		 * on success because LND will finalize this message later.
		 *
		 * Also, there is possibility that message is committed for
		 * sending and also failed before delivering to LND,
		 * i.e: ENOMEM, in that case we can't fall through either:
		 * - The rule is message must decommit for sending first if
		 *   the it's committed for both sending and receiving
		 * - CPT for sending can be different with CPT for receiving,
		 *   so we should return back to lnet_finalize() to make
		 *   sure we are locking the correct partition.
		 */
		return rc;
	}

	lnet_msg_decommit(msg, cpt, status);
	lnet_msg_free(msg);
	return 0;
}

static void
lnet_dec_healthv_locked(atomic_t *healthv, int sensitivity)
{
	int h = atomic_read(healthv);

	if (h < sensitivity) {
		atomic_set(healthv, 0);
	} else {
		h -= sensitivity;
		atomic_set(healthv, h);
	}
}

/* must hold net_lock/0 */
void
lnet_ni_add_to_recoveryq_locked(struct lnet_ni *ni,
				struct list_head *recovery_queue, time64_t now)
{
	if (!list_empty(&ni->ni_recovery))
		return;

	if (atomic_read(&ni->ni_healthv) == LNET_MAX_HEALTH_VALUE)
		return;

	/* This NI is going on the recovery queue, so take a ref on it */
	lnet_ni_addref_locked(ni, 0);

	lnet_ni_set_next_ping(ni, now);

	CDEBUG(D_NET, "%s added to recovery queue. ping count: %u next ping: %lld health :%d\n",
	       libcfs_nid2str(ni->ni_nid),
	       ni->ni_ping_count,
	       ni->ni_next_ping,
	       atomic_read(&ni->ni_healthv));

	list_add_tail(&ni->ni_recovery, recovery_queue);
}

static void
lnet_handle_local_failure(struct lnet_ni *local_ni)
{
	/*
	 * the lnet_net_lock(0) is used to protect the addref on the ni
	 * and the recovery queue.
	 */
	lnet_net_lock(0);
	/* the mt could've shutdown and cleaned up the queues */
	if (the_lnet.ln_mt_state != LNET_MT_STATE_RUNNING) {
		lnet_net_unlock(0);
		return;
	}

	lnet_dec_healthv_locked(&local_ni->ni_healthv, lnet_health_sensitivity);
	lnet_ni_add_to_recoveryq_locked(local_ni, &the_lnet.ln_mt_localNIRecovq,
					ktime_get_seconds());
	lnet_net_unlock(0);
}

/* must hold net_lock/0 */
void
lnet_handle_remote_failure_locked(struct lnet_peer_ni *lpni)
{
	__u32 sensitivity = lnet_health_sensitivity;
	__u32 lp_sensitivity;

	/*
	 * If there is a health sensitivity in the peer then use that
	 * instead of the globally set one.
	 */
	lp_sensitivity = lpni->lpni_peer_net->lpn_peer->lp_health_sensitivity;
	if (lp_sensitivity)
		sensitivity = lp_sensitivity;

	lnet_dec_healthv_locked(&lpni->lpni_healthv, sensitivity);

	/* update the peer_net's health value */
	lnet_update_peer_net_healthv(lpni);

	/*
	 * add the peer NI to the recovery queue if it's not already there
	 * and it's health value is actually below the maximum. It's
	 * possible that the sensitivity might be set to 0, and the health
	 * value will not be reduced. In this case, there is no reason to
	 * invoke recovery
	 */
	lnet_peer_ni_add_to_recoveryq_locked(lpni,
					     &the_lnet.ln_mt_peerNIRecovq,
					     ktime_get_seconds());
}

static void
lnet_handle_remote_failure(struct lnet_peer_ni *lpni)
{
	/* lpni could be NULL if we're in the LOLND case */
	if (!lpni)
		return;

	lnet_net_lock(0);
	/* the mt could've shutdown and cleaned up the queues */
	if (the_lnet.ln_mt_state != LNET_MT_STATE_RUNNING) {
		lnet_net_unlock(0);
		return;
	}
	lnet_handle_remote_failure_locked(lpni);
	lnet_net_unlock(0);
}

static void
lnet_incr_hstats(struct lnet_ni *ni, struct lnet_peer_ni *lpni,
		 enum lnet_msg_hstatus hstatus)
{
	struct lnet_counters_health *health;

	health = &the_lnet.ln_counters[0]->lct_health;

	switch (hstatus) {
	case LNET_MSG_STATUS_LOCAL_INTERRUPT:
		atomic_inc(&ni->ni_hstats.hlt_local_interrupt);
		health->lch_local_interrupt_count++;
		break;
	case LNET_MSG_STATUS_LOCAL_DROPPED:
		atomic_inc(&ni->ni_hstats.hlt_local_dropped);
		health->lch_local_dropped_count++;
		break;
	case LNET_MSG_STATUS_LOCAL_ABORTED:
		atomic_inc(&ni->ni_hstats.hlt_local_aborted);
		health->lch_local_aborted_count++;
		break;
	case LNET_MSG_STATUS_LOCAL_NO_ROUTE:
		atomic_inc(&ni->ni_hstats.hlt_local_no_route);
		health->lch_local_no_route_count++;
		break;
	case LNET_MSG_STATUS_LOCAL_TIMEOUT:
		atomic_inc(&ni->ni_hstats.hlt_local_timeout);
		health->lch_local_timeout_count++;
		break;
	case LNET_MSG_STATUS_LOCAL_ERROR:
		atomic_inc(&ni->ni_hstats.hlt_local_error);
		health->lch_local_error_count++;
		break;
	case LNET_MSG_STATUS_REMOTE_DROPPED:
		if (lpni)
			atomic_inc(&lpni->lpni_hstats.hlt_remote_dropped);
		health->lch_remote_dropped_count++;
		break;
	case LNET_MSG_STATUS_REMOTE_ERROR:
		if (lpni)
			atomic_inc(&lpni->lpni_hstats.hlt_remote_error);
		health->lch_remote_error_count++;
		break;
	case LNET_MSG_STATUS_REMOTE_TIMEOUT:
		if (lpni)
			atomic_inc(&lpni->lpni_hstats.hlt_remote_timeout);
		health->lch_remote_timeout_count++;
		break;
	case LNET_MSG_STATUS_NETWORK_TIMEOUT:
		if (lpni)
			atomic_inc(&lpni->lpni_hstats.hlt_network_timeout);
		health->lch_network_timeout_count++;
		break;
	case LNET_MSG_STATUS_OK:
		break;
	default:
		LBUG();
	}
}

static void
lnet_resend_msg_locked(struct lnet_msg *msg)
{
	msg->msg_retry_count++;

	/*
	 * remove message from the active list and reset it to prepare
	 * for a resend. Two exceptions to this
	 *
	 * 1. the router case. When a message is being routed it is
	 * committed for rx when received and committed for tx when
	 * forwarded. We don't want to remove it from the active list, since
	 * code which handles receiving expects it to remain on the active
	 * list.
	 *
	 * 2. The REPLY case. Reply messages use the same message
	 * structure for the GET that was received.
	 */
	if (!msg->msg_routing && msg->msg_type != LNET_MSG_REPLY) {
		list_del_init(&msg->msg_activelist);
		msg->msg_onactivelist = 0;
	}
	/*
	 * The msg_target.nid which was originally set
	 * when calling LNetGet() or LNetPut() might've
	 * been overwritten if we're routing this message.
	 * Call lnet_msg_decommit_tx() to return the credit
	 * this message consumed. The message will
	 * consume another credit when it gets resent.
	 */
	msg->msg_target.nid = msg->msg_hdr.dest_nid;
	lnet_msg_decommit_tx(msg, -EAGAIN);
	msg->msg_sending = 0;
	msg->msg_receiving = 0;
	msg->msg_target_is_router = 0;

	CDEBUG(D_NET, "%s->%s:%s:%s - queuing msg (%p) for resend\n",
	       libcfs_nid2str(msg->msg_hdr.src_nid),
	       libcfs_nid2str(msg->msg_hdr.dest_nid),
	       lnet_msgtyp2str(msg->msg_type),
	       lnet_health_error2str(msg->msg_health_status), msg);

	list_add_tail(&msg->msg_list, the_lnet.ln_mt_resendqs[msg->msg_tx_cpt]);

	complete(&the_lnet.ln_mt_wait_complete);
}

int
lnet_check_finalize_recursion_locked(struct lnet_msg *msg,
				     struct list_head *containerq,
				     int nworkers, void **workers)
{
	int my_slot = -1;
	int i;

	list_add_tail(&msg->msg_list, containerq);

	for (i = 0; i < nworkers; i++) {
		if (workers[i] == current)
			break;

		if (my_slot < 0 && workers[i] == NULL)
			my_slot = i;
	}

	if (i < nworkers || my_slot < 0)
		return -1;

	workers[my_slot] = current;

	return my_slot;
}

int
lnet_attempt_msg_resend(struct lnet_msg *msg)
{
	struct lnet_msg_container *container;
	int my_slot;
	int cpt;

	/* we can only resend tx_committed messages */
	LASSERT(msg->msg_tx_committed);

	/* don't resend recovery messages */
	if (msg->msg_recovery) {
		CDEBUG(D_NET, "msg %s->%s is a recovery ping. retry# %d\n",
			libcfs_nid2str(msg->msg_from),
			libcfs_nid2str(msg->msg_target.nid),
			msg->msg_retry_count);
		return -ENOTRECOVERABLE;
	}

	/*
	 * if we explicitly indicated we don't want to resend then just
	 * return
	 */
	if (msg->msg_no_resend) {
		CDEBUG(D_NET, "msg %s->%s requested no resend. retry# %d\n",
			libcfs_nid2str(msg->msg_from),
			libcfs_nid2str(msg->msg_target.nid),
			msg->msg_retry_count);
		return -ENOTRECOVERABLE;
	}

	/* check if the message has exceeded the number of retries */
	if (msg->msg_retry_count >= lnet_retry_count) {
		CNETERR("msg %s->%s exceeded retry count %d\n",
			libcfs_nid2str(msg->msg_from),
			libcfs_nid2str(msg->msg_target.nid),
			msg->msg_retry_count);
		return -ENOTRECOVERABLE;
	}

	cpt = msg->msg_tx_cpt;
	lnet_net_lock(cpt);

	/* check again under lock */
	if (the_lnet.ln_mt_state != LNET_MT_STATE_RUNNING) {
		lnet_net_unlock(cpt);
		return -ESHUTDOWN;
	}

	container = the_lnet.ln_msg_containers[cpt];
	my_slot =
		lnet_check_finalize_recursion_locked(msg,
					&container->msc_resending,
					container->msc_nfinalizers,
					container->msc_resenders);

	/* enough threads are resending */
	if (my_slot == -1) {
		lnet_net_unlock(cpt);
		return 0;
	}

	while (!list_empty(&container->msc_resending)) {
		msg = list_entry(container->msc_resending.next,
					struct lnet_msg, msg_list);
		list_del(&msg->msg_list);

		/*
		 * resending the message will require us to call
		 * lnet_msg_decommit_tx() which will return the credit
		 * which this message holds. This could trigger another
		 * queued message to be sent. If that message fails and
		 * requires a resend we will recurse.
		 * But since at this point the slot is taken, the message
		 * will be queued in the container and dealt with
		 * later. This breaks the recursion.
		 */
		lnet_resend_msg_locked(msg);
	}

	/*
	 * msc_resenders is an array of process pointers. Each entry holds
	 * a pointer to the current process operating on the message. An
	 * array entry is created per CPT. If the array slot is already
	 * set, then it means that there is a thread on the CPT currently
	 * resending a message.
	 * Once the thread finishes clear the slot to enable the thread to
	 * take on more resend work.
	 */
	container->msc_resenders[my_slot] = NULL;
	lnet_net_unlock(cpt);

	return 0;
}

/*
 * Do a health check on the message:
 * return -1 if we're not going to handle the error or
 *   if we've reached the maximum number of retries.
 *   success case will return -1 as well
 * return 0 if it the message is requeued for send
 */
static int
lnet_health_check(struct lnet_msg *msg)
{
	enum lnet_msg_hstatus hstatus = msg->msg_health_status;
	struct lnet_peer_ni *lpni;
	struct lnet_ni *ni;
	bool lo = false;
	bool attempt_local_resend;
	bool attempt_remote_resend;
	bool handle_local_health;
	bool handle_remote_health;

	/* if we're shutting down no point in handling health. */
	if (the_lnet.ln_mt_state != LNET_MT_STATE_RUNNING)
		return -1;

	LASSERT(msg->msg_tx_committed || msg->msg_rx_committed);

	/*
	 * if we're sending to the LOLND then the msg_txpeer will not be
	 * set. So no need to sanity check it.
	 */
	if (msg->msg_tx_committed && msg->msg_txni->ni_nid != LNET_NID_LO_0)
		LASSERT(msg->msg_txpeer);
	else if (msg->msg_tx_committed &&
		 msg->msg_txni->ni_nid == LNET_NID_LO_0)
		lo = true;

	if (hstatus != LNET_MSG_STATUS_OK &&
	    ktime_compare(ktime_get(), msg->msg_deadline) >= 0)
		return -1;

	/*
	 * always prefer txni/txpeer if they message is committed for both
	 * directions.
	 */
	if (msg->msg_tx_committed) {
		ni = msg->msg_txni;
		lpni = msg->msg_txpeer;
		attempt_local_resend = attempt_remote_resend = true;
	} else {
		ni = msg->msg_rxni;
		lpni = msg->msg_rxpeer;
		attempt_local_resend = attempt_remote_resend = false;
	}

	/* Don't further decrement the health value if a recovery message
	 * failed.
	 */
	if (msg->msg_recovery)
		handle_local_health = handle_remote_health = false;
	else
		handle_local_health = handle_remote_health = true;

	/* For local failures, health/recovery/resends are not needed if I only
	 * have a single (non-lolnd) interface. NB: pb_nnis includes the lolnd
	 * interface, so a single-rail node would have pb_nnis == 2.
	 */
	if (the_lnet.ln_ping_target->pb_nnis <= 2) {
		handle_local_health = false;
		attempt_local_resend = false;
	}

	/* For remote failures, health/recovery/resends are not needed if the
	 * peer only has a single interface. Special case for routers where we
	 * rely on health feature to manage route aliveness. NB: unlike pb_nnis
	 * above, lp_nnis does _not_ include the lolnd, so a single-rail node
	 * would have lp_nnis == 1.
	 */
	if (lpni && lpni->lpni_peer_net->lpn_peer->lp_nnis <= 1) {
		attempt_remote_resend = false;
		if (!lnet_isrouter(lpni))
			handle_remote_health = false;
	}

	if (!lo)
		LASSERT(ni && lpni);
	else
		LASSERT(ni);

	CDEBUG(D_NET, "health check: %s->%s: %s: %s\n",
	       libcfs_nid2str(ni->ni_nid),
	       (lo) ? "self" : libcfs_nid2str(lpni->lpni_nid),
	       lnet_msgtyp2str(msg->msg_type),
	       lnet_health_error2str(hstatus));

	/*
	 * stats are only incremented for errors so avoid wasting time
	 * incrementing statistics if there is no error.
	 */
	if (hstatus != LNET_MSG_STATUS_OK) {
		lnet_net_lock(0);
		lnet_incr_hstats(ni, lpni, hstatus);
		lnet_net_unlock(0);
	}

	switch (hstatus) {
	case LNET_MSG_STATUS_OK:
		/*
		 * increment the local ni health whether we successfully
		 * received or sent a message on it.
		 *
		 * Ping counts are reset to 0 as appropriate to allow for
		 * faster recovery.
		 */
		lnet_inc_healthv(&ni->ni_healthv, lnet_health_sensitivity);
		lnet_net_lock(0);
		ni->ni_ping_count = 0;
		/*
		 * It's possible msg_txpeer is NULL in the LOLND
		 * case. Only increment the peer's health if we're
		 * receiving a message from it. It's the only sure way to
		 * know that a remote interface is up.
		 * If this interface is part of a router, then take that
		 * as indication that the router is fully healthy.
		 */
		if (lpni && msg->msg_rx_committed) {
			lpni->lpni_ping_count = 0;
			/*
			 * If we're receiving a message from the router or
			 * I'm a router, then set that lpni's health to
			 * maximum so we can commence communication
			 */
			if (lnet_isrouter(lpni) || the_lnet.ln_routing) {
				lnet_set_lpni_healthv_locked(lpni,
					LNET_MAX_HEALTH_VALUE);
			} else {
				__u32 sensitivity = lpni->lpni_peer_net->
					lpn_peer->lp_health_sensitivity;

				lnet_inc_lpni_healthv_locked(lpni,
					(sensitivity) ? sensitivity :
					lnet_health_sensitivity);
				/* This peer NI may have previously aged out
				 * of recovery. Now that we've received a
				 * message from it, we can continue recovery
				 * if its health value is still below the
				 * maximum.
				 */
				lnet_peer_ni_add_to_recoveryq_locked(lpni,
						&the_lnet.ln_mt_peerNIRecovq,
						ktime_get_seconds());
			}
		}
		lnet_net_unlock(0);

		/* we can finalize this message */
		return -1;
	case LNET_MSG_STATUS_LOCAL_INTERRUPT:
	case LNET_MSG_STATUS_LOCAL_DROPPED:
	case LNET_MSG_STATUS_LOCAL_ABORTED:
	case LNET_MSG_STATUS_LOCAL_NO_ROUTE:
	case LNET_MSG_STATUS_LOCAL_TIMEOUT:
		if (handle_local_health)
			lnet_handle_local_failure(ni);
		if (attempt_local_resend)
			return lnet_attempt_msg_resend(msg);
		break;
	case LNET_MSG_STATUS_LOCAL_ERROR:
		if (handle_local_health)
			lnet_handle_local_failure(ni);
		return -1;
	case LNET_MSG_STATUS_REMOTE_DROPPED:
		if (handle_remote_health)
			lnet_handle_remote_failure(lpni);
		if (attempt_remote_resend)
			return lnet_attempt_msg_resend(msg);
		break;
	case LNET_MSG_STATUS_REMOTE_ERROR:
	case LNET_MSG_STATUS_REMOTE_TIMEOUT:
		if (handle_remote_health)
			lnet_handle_remote_failure(lpni);
		return -1;
	case LNET_MSG_STATUS_NETWORK_TIMEOUT:
		if (handle_remote_health)
			lnet_handle_remote_failure(lpni);
		if (handle_local_health)
			lnet_handle_local_failure(ni);
		return -1;
	default:
		LBUG();
	}

	/* no resend is needed */
	return -1;
}

static void
lnet_msg_detach_md(struct lnet_msg *msg, int status)
{
	struct lnet_libmd *md = msg->msg_md;
	lnet_handler_t handler = NULL;
	int cpt = lnet_cpt_of_cookie(md->md_lh.lh_cookie);
	int unlink;

	lnet_res_lock(cpt);
	while (md->md_flags & LNET_MD_FLAG_HANDLING)
		/* An event handler is running - wait for it to
		 * complete to avoid races.
		 */
		lnet_md_wait_handling(md, cpt);

	/* Now it's safe to drop my caller's ref */
	md->md_refcount--;
	LASSERT(md->md_refcount >= 0);

	unlink = lnet_md_unlinkable(md);
	if (md->md_handler) {
		if ((md->md_flags & LNET_MD_FLAG_ABORTED) && !status) {
			msg->msg_ev.status   = -ETIMEDOUT;
			CDEBUG(D_NET, "md 0x%p already unlinked\n", md);
		} else {
			msg->msg_ev.status   = status;
		}
		msg->msg_ev.unlinked = unlink;
		handler = md->md_handler;
		if (!unlink)
			md->md_flags |= LNET_MD_FLAG_HANDLING;
	}

	if (unlink || (md->md_refcount == 0 &&
		       md->md_threshold == LNET_MD_THRESH_INF))
		lnet_detach_rsp_tracker(md, cpt);

	msg->msg_md = NULL;
	if (unlink)
		lnet_md_unlink(md);

	lnet_res_unlock(cpt);

	if (handler) {
		handler(&msg->msg_ev);
		if (!unlink) {
			lnet_res_lock(cpt);
			md->md_flags &= ~LNET_MD_FLAG_HANDLING;
			wake_up_var(md);
			lnet_res_unlock(cpt);
		}
	}
}

static bool
lnet_is_health_check(struct lnet_msg *msg)
{
	bool hc = true;
	int status = msg->msg_ev.status;

	if ((!msg->msg_tx_committed && !msg->msg_rx_committed) ||
	    !msg->msg_onactivelist) {
		CDEBUG(D_NET, "msg %p not committed for send or receive\n",
		       msg);
		return false;
	}

	if ((msg->msg_tx_committed && !msg->msg_txpeer) ||
	    (msg->msg_rx_committed && !msg->msg_rxpeer)) {
		/* The optimized GET case does not set msg_rxpeer, but status
		 * could be zero. Only print the error message if we have a
		 * non-zero status.
		 */
		if (status)
			CDEBUG(D_NET, "msg %p status %d cannot retry\n", msg,
			       status);
		return false;
	}

	/* Check for status inconsistencies */
	if ((!status && msg->msg_health_status != LNET_MSG_STATUS_OK) ||
	     (status && msg->msg_health_status == LNET_MSG_STATUS_OK)) {
		CDEBUG(D_NET, "Msg %p is in inconsistent state, don't perform health "
		       "checking (%d, %d)\n", msg, status,
		       msg->msg_health_status);
		hc = false;
	}

	CDEBUG(D_NET, "health check = %d, status = %d, hstatus = %d\n",
	       hc, status, msg->msg_health_status);

	return hc;
}

char *
lnet_health_error2str(enum lnet_msg_hstatus hstatus)
{
	switch (hstatus) {
	case LNET_MSG_STATUS_LOCAL_INTERRUPT:
		return "LOCAL_INTERRUPT";
	case LNET_MSG_STATUS_LOCAL_DROPPED:
		return "LOCAL_DROPPED";
	case LNET_MSG_STATUS_LOCAL_ABORTED:
		return "LOCAL_ABORTED";
	case LNET_MSG_STATUS_LOCAL_NO_ROUTE:
		return "LOCAL_NO_ROUTE";
	case LNET_MSG_STATUS_LOCAL_TIMEOUT:
		return "LOCAL_TIMEOUT";
	case LNET_MSG_STATUS_LOCAL_ERROR:
		return "LOCAL_ERROR";
	case LNET_MSG_STATUS_REMOTE_DROPPED:
		return "REMOTE_DROPPED";
	case LNET_MSG_STATUS_REMOTE_ERROR:
		return "REMOTE_ERROR";
	case LNET_MSG_STATUS_REMOTE_TIMEOUT:
		return "REMOTE_TIMEOUT";
	case LNET_MSG_STATUS_NETWORK_TIMEOUT:
		return "NETWORK_TIMEOUT";
	case LNET_MSG_STATUS_OK:
		return "OK";
	default:
		return "<UNKNOWN>";
	}
}

bool
lnet_send_error_simulation(struct lnet_msg *msg,
			   enum lnet_msg_hstatus *hstatus)
{
	if (!msg)
		return false;

	if (list_empty(&the_lnet.ln_drop_rules))
	    return false;

	/* match only health rules */
	if (!lnet_drop_rule_match(&msg->msg_hdr, LNET_NID_ANY,
				  hstatus))
		return false;

	CDEBUG(D_NET, "src %s(%s)->dst %s: %s simulate health error: %s\n",
		libcfs_nid2str(msg->msg_hdr.src_nid),
		libcfs_nid2str(msg->msg_txni->ni_nid),
		libcfs_nid2str(msg->msg_hdr.dest_nid),
		lnet_msgtyp2str(msg->msg_type),
		lnet_health_error2str(*hstatus));

	return true;
}
EXPORT_SYMBOL(lnet_send_error_simulation);

void
lnet_finalize(struct lnet_msg *msg, int status)
{
	struct lnet_msg_container *container;
	int my_slot;
	int cpt;
	int rc;

	LASSERT(!in_interrupt());

	if (msg == NULL)
		return;

	msg->msg_ev.status = status;

	if (lnet_is_health_check(msg)) {
		/*
		 * Check the health status of the message. If it has one
		 * of the errors that we're supposed to handle, and it has
		 * not timed out, then
		 *	1. Decrement the appropriate health_value
		 *	2. queue the message on the resend queue

		 * if the message send is success, timed out or failed in the
		 * health check for any reason then we'll just finalize the
		 * message. Otherwise just return since the message has been
		 * put on the resend queue.
		 */
		if (!lnet_health_check(msg))
			return;
	}

	/*
	 * We're not going to resend this message so detach its MD and invoke
	 * the appropriate callbacks
	 */
	if (msg->msg_md != NULL)
		lnet_msg_detach_md(msg, status);

again:
	if (!msg->msg_tx_committed && !msg->msg_rx_committed) {
		/* not committed to network yet */
		LASSERT(!msg->msg_onactivelist);
		lnet_msg_free(msg);
		return;
	}

	/*
	 * NB: routed message can be committed for both receiving and sending,
	 * we should finalize in LIFO order and keep counters correct.
	 * (finalize sending first then finalize receiving)
	 */
	cpt = msg->msg_tx_committed ? msg->msg_tx_cpt : msg->msg_rx_cpt;
	lnet_net_lock(cpt);

	container = the_lnet.ln_msg_containers[cpt];

	/* Recursion breaker.  Don't complete the message here if I am (or
	 * enough other threads are) already completing messages */
	my_slot = lnet_check_finalize_recursion_locked(msg,
						&container->msc_finalizing,
						container->msc_nfinalizers,
						container->msc_finalizers);

	/* enough threads are resending */
	if (my_slot == -1) {
		lnet_net_unlock(cpt);
		return;
	}

	rc = 0;
	while (!list_empty(&container->msc_finalizing)) {
		msg = list_entry(container->msc_finalizing.next,
				 struct lnet_msg, msg_list);

		list_del_init(&msg->msg_list);

		/* NB drops and regains the lnet lock if it actually does
		 * anything, so my finalizing friends can chomp along too */
		rc = lnet_complete_msg_locked(msg, cpt);
		if (rc != 0)
			break;
	}

	if (unlikely(!list_empty(&the_lnet.ln_delay_rules))) {
		lnet_net_unlock(cpt);
		lnet_delay_rule_check();
		lnet_net_lock(cpt);
	}

	container->msc_finalizers[my_slot] = NULL;
	lnet_net_unlock(cpt);

	if (rc != 0)
		goto again;
}
EXPORT_SYMBOL(lnet_finalize);

void
lnet_msg_container_cleanup(struct lnet_msg_container *container)
{
	int	count = 0;

	if (container->msc_init == 0)
		return;

	while (!list_empty(&container->msc_active)) {
		struct lnet_msg *msg;

		msg  = list_entry(container->msc_active.next,
				  struct lnet_msg, msg_activelist);
		LASSERT(msg->msg_onactivelist);
		msg->msg_onactivelist = 0;
		list_del_init(&msg->msg_activelist);
		lnet_msg_free(msg);
		count++;
	}

	if (count > 0)
		CERROR("%d active msg on exit\n", count);

	if (container->msc_finalizers != NULL) {
		CFS_FREE_PTR_ARRAY(container->msc_finalizers,
				   container->msc_nfinalizers);
		container->msc_finalizers = NULL;
	}

	if (container->msc_resenders != NULL) {
		CFS_FREE_PTR_ARRAY(container->msc_resenders,
				   container->msc_nfinalizers);
		container->msc_resenders = NULL;
	}
	container->msc_init = 0;
}

int
lnet_msg_container_setup(struct lnet_msg_container *container, int cpt)
{
	int rc = 0;

	container->msc_init = 1;

	INIT_LIST_HEAD(&container->msc_active);
	INIT_LIST_HEAD(&container->msc_finalizing);
	INIT_LIST_HEAD(&container->msc_resending);

	/* number of CPUs */
	container->msc_nfinalizers = cfs_cpt_weight(lnet_cpt_table(), cpt);
	if (container->msc_nfinalizers == 0)
		container->msc_nfinalizers = 1;

	LIBCFS_CPT_ALLOC(container->msc_finalizers, lnet_cpt_table(), cpt,
			 container->msc_nfinalizers *
			 sizeof(*container->msc_finalizers));

	if (container->msc_finalizers == NULL) {
		CERROR("Failed to allocate message finalizers\n");
		lnet_msg_container_cleanup(container);
		return -ENOMEM;
	}

	LIBCFS_CPT_ALLOC(container->msc_resenders, lnet_cpt_table(), cpt,
			 container->msc_nfinalizers *
			 sizeof(*container->msc_resenders));

	if (container->msc_resenders == NULL) {
		CERROR("Failed to allocate message resenders\n");
		lnet_msg_container_cleanup(container);
		return -ENOMEM;
	}

	return rc;
}

void
lnet_msg_containers_destroy(void)
{
	struct lnet_msg_container *container;
	int	i;

	if (the_lnet.ln_msg_containers == NULL)
		return;

	cfs_percpt_for_each(container, i, the_lnet.ln_msg_containers)
		lnet_msg_container_cleanup(container);

	cfs_percpt_free(the_lnet.ln_msg_containers);
	the_lnet.ln_msg_containers = NULL;
}

int
lnet_msg_containers_create(void)
{
	struct lnet_msg_container *container;
	int	rc;
	int	i;

	the_lnet.ln_msg_containers = cfs_percpt_alloc(lnet_cpt_table(),
						      sizeof(*container));

	if (the_lnet.ln_msg_containers == NULL) {
		CERROR("Failed to allocate cpu-partition data for network\n");
		return -ENOMEM;
	}

	cfs_percpt_for_each(container, i, the_lnet.ln_msg_containers) {
		rc = lnet_msg_container_setup(container, i);
		if (rc != 0) {
			lnet_msg_containers_destroy();
			return rc;
		}
	}

	return 0;
}
