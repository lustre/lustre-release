// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC
#include <libcfs/linux/linux-mem.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_lib.h>
#include <obd.h>
#include <obd_class.h>
#include "ptlrpc_internal.h"
#include <lnet/lib-lnet.h> /* for CFS_FAIL_PTLRPC_OST_BULK_CB2 */

/* whether we should use PM-QoS to lower CPUs resume latency during I/O */
bool ptlrpc_enable_pmqos = true;

/* max CPUs power resume latency to be used during I/O */
int ptlrpc_pmqos_latency_max_usec = CPU_MAX_RESUME_LATENCY_US;

/* default timeout to end CPUs resume latency constraint */
u64 ptlrpc_pmqos_default_duration_usec = DEFAULT_CPU_LATENCY_TIMEOUT_US;

/* whether we should use OBD stats to determine best low latency duration */
bool ptlrpc_pmqos_use_stats_for_duration = true;

/**
 * ptl_send_buf() - Helper function. Sends @len bytes from @base at
 * offset @offset over @conn connection to @portal
 * @mdh: pointer to struct lnet_handle_md (mem descriptor handle)
 * @base: pointer to buffer
 * @len: length of buffer
 * @ack: If acknowledgement is required or not
 * @cbid: Callback id
 * @self: Source NID (network identifier)
 * @peer_id: Destination ID
 * @portal: Destination where bulk is to be sent
 * @xid: Transaction ID
 * @offset: start offset of buffer
 * @bulk_cookie: cookie
 *
 * Returns 0 on success or error code.
 */
static int ptl_send_buf(struct lnet_handle_md *mdh, void *base, int len,
			enum lnet_ack_req ack, struct ptlrpc_cb_id *cbid,
			struct lnet_nid *self, struct lnet_processid *peer_id,
			int portal, __u64 xid, unsigned int offset,
			struct lnet_handle_md *bulk_cookie)
{
	int rc;
	struct lnet_md md = {
		.umd_start     = base,
		.umd_length    = len,
		.umd_threshold = (ack == LNET_ACK_REQ) ? 2 : 1,
		.umd_options   = PTLRPC_MD_OPTIONS,
		.umd_user_ptr  = cbid,
		.umd_handler   = ptlrpc_handler,
	};

	ENTRY;

	LASSERT(portal != 0);
	CDEBUG(D_INFO, "peer_id %s\n", libcfs_idstr(peer_id));
	LNetInvalidateMDHandle(&md.umd_bulk_handle);

	if (bulk_cookie) {
		md.umd_bulk_handle = *bulk_cookie;
		md.umd_options |= LNET_MD_BULK_HANDLE;
	}

	if (CFS_FAIL_CHECK_ORSET(OBD_FAIL_PTLRPC_ACK, CFS_FAIL_ONCE) &&
	    ack == LNET_ACK_REQ) {
		/* don't ask for the ack to simulate failing client */
		ack = LNET_NOACK_REQ;
	}

	rc = LNetMDBind(&md, LNET_UNLINK, mdh);
	if (unlikely(rc != 0)) {
		CERROR("LNetMDBind failed: %d\n", rc);
		LASSERT(rc == -ENOMEM);
		RETURN(-ENOMEM);
	}

	CDEBUG(D_NET, "Sending %d bytes to portal %d, xid %lld, offset %u\n",
	       len, portal, xid, offset);

	percpu_ref_get(&ptlrpc_pending);

	rc = LNetPut(self, *mdh, ack,
		     peer_id, portal, xid, offset, 0);
	if (unlikely(rc != 0)) {
		int rc2;
		/* Will get UNLINK event when unlink below, which will complete
		 * like any other failed send, fall through and return success
		 */
		CERROR("LNetPut(%s, %d, %lld) failed: %d\n",
		       libcfs_idstr(peer_id), portal, xid, rc);
		rc2 = LNetMDUnlink(*mdh);
		LASSERTF(rc2 == 0, "rc2 = %d\n", rc2);
	}

	RETURN(0);
}

static void mdunlink_iterate_helper(struct lnet_handle_md *bd_mds, int count)
{
	int i;

	for (i = 0; i < count; i++)
		LNetMDUnlink(bd_mds[i]);
}

#ifdef HAVE_SERVER_SUPPORT
/**
 * ptlrpc_prep_bulk_exp() - Prepare bulk descriptor for specified incoming @req
 * @req: PTLRPC request linked to bulk buffer
 * @nfrags: Count of fragments (in pages)
 * @max_brw: Max size (in pages)
 * @type: operation type (read/write)
 * @portal: Destination where bulk is to be sent
 * @ops: callback
 *
 * Used on server-side after request was already received.
 *
 * Returns pointer to newly allocatrd initialized bulk descriptor or NULL on
 * error.
 */
struct ptlrpc_bulk_desc *ptlrpc_prep_bulk_exp(struct ptlrpc_request *req,
			 unsigned int nfrags, unsigned int max_brw,
			 unsigned int type, unsigned int portal,
			 const struct ptlrpc_bulk_frag_ops *ops)
{
	struct obd_export *exp = req->rq_export;
	struct ptlrpc_bulk_desc *desc;

	ENTRY;
	LASSERT(ptlrpc_is_bulk_op_active(type));

	desc = ptlrpc_new_bulk(nfrags, max_brw, type, portal, ops);
	if (desc == NULL)
		RETURN(NULL);

	desc->bd_export = class_export_get(exp);
	desc->bd_req = req;

	desc->bd_cbid.cbid_fn  = server_bulk_callback;
	desc->bd_cbid.cbid_arg = desc;

	/* NB we don't assign rq_bulk here; server-side requests are
	 * re-used, and the handler frees the bulk desc explicitly.
	 */

	return desc;
}
EXPORT_SYMBOL(ptlrpc_prep_bulk_exp);

/**
 * ptlrpc_start_bulk_transfer() - Start bulk transfer for @desc on the server
 * @desc: bulk data layout descriptor
 *
 * Returns 0 on success or error code.
 */
int ptlrpc_start_bulk_transfer(struct ptlrpc_bulk_desc *desc)
{
	struct obd_export *exp = desc->bd_export;
	struct lnet_nid self_nid;
	struct lnet_processid peer_id;
	int rc = 0;
	__u64 mbits;
	int posted_md;
	int total_md;
	struct lnet_md md = { NULL };

	ENTRY;

	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_BULK_PUT_NET))
		RETURN(0);

	/* NB no locking required until desc is on the network */
	LASSERT(ptlrpc_is_bulk_op_active(desc->bd_type));

	LASSERT(desc->bd_cbid.cbid_fn == server_bulk_callback);
	LASSERT(desc->bd_cbid.cbid_arg == desc);

	/* Multi-Rail: get the preferred self and peer NIDs from the
	 * request, so they are based on the route taken by the message.
	 */
	self_nid = desc->bd_req->rq_self;
	peer_id = desc->bd_req->rq_source;

	/* NB total length may be 0 for a read past EOF, so we send 0
	 * length bulks, since the client expects bulk events.
	 *
	 * The client may not need all of the bulk mbits for the RPC. The RPC
	 * used the mbits of the highest bulk mbits needed, and the server masks
	 * off high bits to get bulk count for this RPC. LU-1431
	 */
	mbits = desc->bd_req->rq_mbits & ~((__u64)desc->bd_md_max_brw - 1);
	total_md = desc->bd_req->rq_mbits - mbits + 1;
	desc->bd_refs = total_md;
	desc->bd_failure = 0;

	md.umd_user_ptr = &desc->bd_cbid;
	md.umd_handler = ptlrpc_handler;
	md.umd_threshold = 2; /* SENT and ACK/REPLY */

	for (posted_md = 0; posted_md < total_md; mbits++) {
		md.umd_options = PTLRPC_MD_OPTIONS;

		/* Note. source and sink buf frags are page-aligned. Else send
		 * client bulk sizes over and split server buffer accordingly
		 */
		ptlrpc_fill_bulk_md(&md, desc, posted_md);
		rc = LNetMDBind(&md, LNET_UNLINK, &desc->bd_mds[posted_md]);
		if (rc != 0) {
			CERROR("%s: LNetMDBind failed for MD %u: rc = %d\n",
			       exp->exp_obd->obd_name, posted_md, rc);
			LASSERT(rc == -ENOMEM);
			if (posted_md == 0) {
				desc->bd_md_count = 0;
				RETURN(-ENOMEM);
			}
			break;
		}
		percpu_ref_get(&ptlrpc_pending);

		/* sanity.sh 224c: lets skip last md */
		if (posted_md == desc->bd_md_max_brw - 1)
			CFS_FAIL_CHECK_RESET(OBD_FAIL_PTLRPC_CLIENT_BULK_CB3,
					     CFS_FAIL_PTLRPC_OST_BULK_CB2);

		/* Network is about to get at the memory */
		if (ptlrpc_is_bulk_put_source(desc->bd_type))
			rc = LNetPut(&self_nid, desc->bd_mds[posted_md],
				     LNET_ACK_REQ, &peer_id,
				     desc->bd_portal, mbits, 0, 0);
		else
			rc = LNetGet(&self_nid, desc->bd_mds[posted_md],
				     &peer_id, desc->bd_portal,
				     mbits, 0, false);

		posted_md++;
		if (rc != 0) {
			CERROR("%s: failed bulk transfer with %s:%u x%llu: rc = %d\n",
			       exp->exp_obd->obd_name,
			       libcfs_idstr(&peer_id), desc->bd_portal,
			       mbits, rc);
			break;
		}
	}

	if (rc != 0) {
		/* Can't send, so we unlink the MD bound above.  The UNLINK
		 * event this creates will signal completion with failure,
		 * so we return SUCCESS here!
		 */
		spin_lock(&desc->bd_lock);
		desc->bd_refs -= total_md - posted_md;
		spin_unlock(&desc->bd_lock);
		LASSERT(desc->bd_refs >= 0);

		mdunlink_iterate_helper(desc->bd_mds, posted_md);
		RETURN(0);
	}

	CDEBUG(D_NET, "Transferring %u pages %u bytes via portal %d id %s mbits %#llx-%#llx\n",
	       desc->bd_iov_count,
	       desc->bd_nob, desc->bd_portal, libcfs_idstr(&peer_id),
	       mbits - posted_md, mbits - 1);

	RETURN(0);
}

/**
 * ptlrpc_abort_bulk() - Server side bulk abort
 * @desc: pointer to bulk data layout
 *
 * Server side bulk abort. Idempotent. Not thread-safe (i.e. only
 * serialises with completion callback)
 */
void ptlrpc_abort_bulk(struct ptlrpc_bulk_desc *desc)
{
	LASSERT(!in_interrupt());               /* might sleep */

	if (!ptlrpc_server_bulk_active(desc))   /* completed or */
		return;                         /* never started */

	/* We used to poison the pages with 0xab here because we did not want to
	 * send any meaningful data over the wire for evicted clients (bug 9297)
	 * However, this is no longer safe now that we use the page cache on the
	 * OSS (bug 20560) */

	/* The unlink ensures the callback happens ASAP and is the last
	 * one.  If it fails, it must be because completion just happened,
	 * but we must still wait_event_idle_timeout() in this case, to give
	 * us a chance to run server_bulk_callback()
	 */
	mdunlink_iterate_helper(desc->bd_mds, desc->bd_md_max_brw);

	for (;;) {
		/* Network access will complete in finite time but the HUGE
		 * timeout lets us CWARN for visibility of sluggish NALs
		 */
		int seconds = PTLRPC_REQ_LONG_UNLINK;

		while (seconds > 0 &&
		       wait_event_idle_timeout(desc->bd_waitq,
					       !ptlrpc_server_bulk_active(desc),
					       cfs_time_seconds(1)) == 0)
			seconds -= 1;
		if (seconds > 0)
			return;

		CWARN("Unexpectedly long timeout: desc %p\n", desc);
	}
}
#endif /* HAVE_SERVER_SUPPORT */

/**
 * ptlrpc_register_bulk() - Register bulk at the sender for later transfer.
 * @req: Request where to register bulk buffer
 *
 * Returns 0 on success or error code.
 */
int ptlrpc_register_bulk(struct ptlrpc_request *req)
{
	struct ptlrpc_bulk_desc *desc = req->rq_bulk;
	struct lnet_processid peer;
	int rc = 0;
	int posted_md;
	int total_md;
	__u64 mbits;
	struct lnet_me *me;
	struct lnet_md md = { NULL };

	ENTRY;

	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_BULK_GET_NET))
		RETURN(0);

	/* NB no locking required until desc is on the network */
	LASSERT(desc->bd_nob > 0);
	LASSERT(desc->bd_md_max_brw <= PTLRPC_BULK_OPS_COUNT);
	LASSERT(desc->bd_iov_count <= PTLRPC_MAX_BRW_PAGES);
	LASSERT(desc->bd_req != NULL);
	LASSERT(ptlrpc_is_bulk_op_passive(desc->bd_type));

	/* cleanup the state of the bulk for it will be reused */
	if (req->rq_resend || req->rq_send_state == LUSTRE_IMP_REPLAY)
		desc->bd_nob_transferred = 0;
	else if (desc->bd_nob_transferred != 0)
		/* If network failed after RPC was sent, this condition could
		 * happen. Rather than assert (was here before), return EIO err
		 */
		RETURN(-EIO);

	desc->bd_failure = 0;

	peer = desc->bd_import->imp_connection->c_peer;

	LASSERT(desc->bd_cbid.cbid_fn == client_bulk_callback);
	LASSERT(desc->bd_cbid.cbid_arg == desc);

	total_md = desc->bd_md_count;
	/* rq_mbits is matchbits of the final bulk */
	mbits = req->rq_mbits - desc->bd_md_count + 1;

	LASSERTF(mbits == (req->rq_mbits & PTLRPC_BULK_OPS_MASK),
		 "first mbits = x%llu, last mbits = x%llu\n",
		 mbits, req->rq_mbits);
	LASSERTF(!(desc->bd_registered &&
		   req->rq_send_state != LUSTRE_IMP_REPLAY) ||
		 mbits != desc->bd_last_mbits,
		 "registered: %d  rq_mbits: %llu bd_last_mbits: %llu\n",
		 desc->bd_registered, mbits, desc->bd_last_mbits);

	desc->bd_registered = 1;
	desc->bd_last_mbits = mbits;
	desc->bd_refs = total_md;
	md.umd_user_ptr = &desc->bd_cbid;
	md.umd_handler = ptlrpc_handler;
	md.umd_threshold = 1;                       /* PUT or GET */

	for (posted_md = 0; posted_md < desc->bd_md_count;
	     posted_md++, mbits++) {
		md.umd_options = PTLRPC_MD_OPTIONS |
			     (ptlrpc_is_bulk_op_get(desc->bd_type) ?
			      LNET_MD_OP_GET : LNET_MD_OP_PUT);
		ptlrpc_fill_bulk_md(&md, desc, posted_md);

		if (posted_md > 0 && posted_md + 1 == desc->bd_md_count &&
		    CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_BULK_ATTACH)) {
			rc = -ENOMEM;
		} else {
			me = LNetMEAttach(desc->bd_portal, &peer, mbits, 0,
				  LNET_UNLINK, LNET_INS_AFTER);
			rc = PTR_ERR_OR_ZERO(me);
		}
		if (rc != 0) {
			CERROR("%s: LNetMEAttach failed x%llu/%d: rc = %d\n",
			       desc->bd_import->imp_obd->obd_name, mbits,
			       posted_md, rc);
			break;
		}
		percpu_ref_get(&ptlrpc_pending);

		/* About to let the network at it... */
		rc = LNetMDAttach(me, &md, LNET_UNLINK,
				  &desc->bd_mds[posted_md]);
		if (rc != 0) {
			CERROR("%s: LNetMDAttach failed x%llu/%d: rc = %d\n",
			       desc->bd_import->imp_obd->obd_name, mbits,
			       posted_md, rc);
			break;
		}
	}

	if (rc != 0) {
		LASSERT(rc == -ENOMEM);
		spin_lock(&desc->bd_lock);
		desc->bd_refs -= total_md - posted_md;
		spin_unlock(&desc->bd_lock);
		LASSERT(desc->bd_refs >= 0);
		mdunlink_iterate_helper(desc->bd_mds, desc->bd_md_max_brw);
		req->rq_status = -ENOMEM;
		desc->bd_registered = 0;
		RETURN(-ENOMEM);
	}

	spin_lock(&desc->bd_lock);
	/* Holler if peer manages to touch buffers before he knows the mbits */
	if (desc->bd_refs != total_md)
		CWARN("%s: Peer %s touched %d buffers while I registered\n",
		      desc->bd_import->imp_obd->obd_name, libcfs_idstr(&peer),
		      total_md - desc->bd_refs);
	spin_unlock(&desc->bd_lock);

	CDEBUG(D_NET,
	       "Setup %u bulk %s buffers: %u pages %u bytes, mbits x%#llx-%#llx, portal %u\n",
	       desc->bd_refs,
	       ptlrpc_is_bulk_op_get(desc->bd_type) ? "get-source" : "put-sink",
	       desc->bd_iov_count, desc->bd_nob,
	       desc->bd_last_mbits, req->rq_mbits, desc->bd_portal);

	RETURN(0);
}

/**
 * ptlrpc_unregister_bulk() - Unregister bulk buffers linked to @req
 * @req: Request to unlink bulk buffers
 * @async: If 0 do any sync unregister. Else do a async unregister
 *
 * Disconnect a bulk desc from the network. Idempotent. Not
 * thread-safe (i.e. only interlocks with completion callback).
 *
 * Returns 1 on success or 0 if network unregistration failed for whatever
 * reason.
 */
int ptlrpc_unregister_bulk(struct ptlrpc_request *req, int async)
{
	struct ptlrpc_bulk_desc *desc = req->rq_bulk;

	ENTRY;

	LASSERT(!in_interrupt());     /* might sleep */

	if (desc)
		desc->bd_registered = 0;

	/* Let's setup deadline for reply unlink. */
	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_LONG_BULK_UNLINK) &&
	    async && req->rq_bulk_deadline == 0 && cfs_fail_val == 0)
		req->rq_bulk_deadline = ktime_get_real_seconds() +
					PTLRPC_REQ_LONG_UNLINK;

	if (ptlrpc_client_bulk_active(req) == 0)	/* completed or */
		RETURN(1);				/* never registered */

	LASSERT(desc->bd_req == req);  /* bd_req NULL until registered */

	/* the unlink ensures the callback happens ASAP and is the last
	 * one.  If it fails, it must be because completion just happened,
	 * but we must still wait_event_idle_timeout() in this case to give
	 * us a chance to run client_bulk_callback()
	 */
	mdunlink_iterate_helper(desc->bd_mds, desc->bd_md_max_brw);

	if (ptlrpc_client_bulk_active(req) == 0)	/* completed or */
		RETURN(1);				/* never registered */

	/* Move to "Unregistering" phase as bulk was not unlinked yet. */
	ptlrpc_rqphase_move(req, RQ_PHASE_UNREG_BULK);

	/* Do not wait for unlink to finish. */
	if (async)
		RETURN(0);

	for (;;) {
		/* The wq argument is ignored by user-space wait_event macros */
		wait_queue_head_t *wq = (req->rq_set != NULL) ?
					&req->rq_set->set_waitq :
					&req->rq_reply_waitq;
		/*
		 * Network access will complete in finite time but the HUGE
		 * timeout lets us CWARN for visibility of sluggish NALs.
		 */
		int seconds = PTLRPC_REQ_LONG_UNLINK;

		while (seconds > 0 &&
		       wait_event_idle_timeout(*wq,
					       !ptlrpc_client_bulk_active(req),
					       cfs_time_seconds(1)) == 0)
			seconds -= 1;
		if (seconds > 0) {
			ptlrpc_rqphase_move(req, req->rq_next_phase);
			RETURN(1);
		}

		DEBUG_REQ(D_WARNING, req, "Unexpectedly long timeout: desc %p",
			  desc);
	}
	RETURN(0);
}

static void ptlrpc_at_set_reply(struct ptlrpc_request *req, int flags)
{
	struct ptlrpc_service_part	*svcpt = req->rq_rqbd->rqbd_svcpt;
	struct ptlrpc_service		*svc = svcpt->scp_service;
	timeout_t service_timeout;
	struct obd_device *obd = NULL;

	if (req->rq_export)
		obd = req->rq_export->exp_obd;

	service_timeout = obd_at_off(obd) ?
			  obd_timeout * 3 / 2 : obd_get_at_max(obd);
	service_timeout = clamp_t(timeout_t, ktime_get_real_seconds() -
				  req->rq_arrival_time.tv_sec, 1,
				  service_timeout);
	if (!(flags & PTLRPC_REPLY_EARLY) &&
	    (req->rq_type != PTL_RPC_MSG_ERR) &&
	    (req->rq_reqmsg != NULL) &&
	    !(lustre_msg_get_flags(req->rq_reqmsg) &
	      (MSG_RESENT | MSG_REPLAY |
	       MSG_REQ_REPLAY_DONE | MSG_LOCK_REPLAY_DONE))) {
		/* early replies, errors and recovery requests don't count
		 * toward our service time estimate
		 */
		timeout_t oldse = obd_at_measure(obd, &svcpt->scp_at_estimate,
						 service_timeout);

		if (oldse != 0) {
			DEBUG_REQ(D_ADAPTTO, req,
				  "svc %s changed estimate from %d to %d",
				  svc->srv_name, oldse,
				  obd_at_get(obd, &svcpt->scp_at_estimate));
		}
	}
	/* Report actual service time for client latency calc */
	lustre_msg_set_service_timeout(req->rq_repmsg, service_timeout);
	/* Report service time estimate for future client reqs, but report 0
	 * (to be ignored by client) if it's an error reply during recovery.
	 * b=15815
	 */
	if (req->rq_type == PTL_RPC_MSG_ERR &&
	    (req->rq_export == NULL || test_bit(OBDF_RECOVERING, obd->obd_flags))) {
		lustre_msg_set_timeout(req->rq_repmsg, 0);
	} else {
		timeout_t timeout;

		if (req->rq_export && req->rq_reqmsg != NULL &&
		    (flags & PTLRPC_REPLY_EARLY) &&
		    lustre_msg_get_flags(req->rq_reqmsg) &
		    (MSG_REPLAY | MSG_REQ_REPLAY_DONE | MSG_LOCK_REPLAY_DONE)) {
			timeout = ktime_get_real_seconds() -
				  req->rq_arrival_time.tv_sec +
				  min_t(timeout_t, at_extra,
					obd->obd_recovery_timeout / 4);
		} else {
			timeout = obd_at_get(obd, &svcpt->scp_at_estimate);
		}
		lustre_msg_set_timeout(req->rq_repmsg, timeout);
	}

	if (req->rq_reqmsg &&
	    !(lustre_msghdr_get_flags(req->rq_reqmsg) & MSGHDR_AT_SUPPORT)) {
		CDEBUG(D_ADAPTTO, "No early reply support: flags=%#x req_flags=%#x magic=%x/%x len=%d\n",
		       flags, lustre_msg_get_flags(req->rq_reqmsg),
		       lustre_msg_get_magic(req->rq_reqmsg),
		       lustre_msg_get_magic(req->rq_repmsg), req->rq_replen);
	}
}

/* lower CPU latency on all logical CPUs in the cpt partition that will
 * handle replies from the target NID server
 */
static void kick_cpu_latency(struct ptlrpc_connection *conn,
			     struct obd_device *obd)
{
	cpumask_t *cpt_cpumask;
	int cpu;
	struct cpu_latency_qos *latency_qos;
	u64 time = 0;

	if (unlikely(ptlrpc_enable_pmqos == false) ||
	    unlikely(cpus_latency_qos == NULL))
		return;

#ifdef CONFIG_PROC_FS
	if (ptlrpc_pmqos_use_stats_for_duration == true && obd != NULL) {
		/* prevent racing with OBD cleanup (umount !) */
		spin_lock(&obd->obd_dev_lock);
		if (!obd->obd_stopping && obd->obd_svc_stats != NULL) {
			struct lprocfs_counter ret;

			lprocfs_stats_collect(obd->obd_svc_stats,
					      PTLRPC_REQWAIT_CNTR, &ret);
			/* use 125% of average wait time (lc_sum/lc_count)
			 * instead of lc_max
			 */
			if (ret.lc_count != 0)
				time = (ret.lc_sum / ret.lc_count) * 5 / 4;
			CDEBUG(D_INFO, "%s: using a timeout of %llu usecs (%lu jiffies)\n",
			       obd->obd_name, time, usecs_to_jiffies(time));
		}
		spin_unlock(&obd->obd_dev_lock);
	}
#endif

	cpt_cpumask = *cfs_cpt_cpumask(lnet_cpt_table(),
				       lnet_cpt_of_nid(lnet_nid_to_nid4(&conn->c_peer.nid),
				       NULL));
	for_each_cpu(cpu, cpt_cpumask) {
		u64 this_cpu_time, new_deadline;
		bool new_work = true;

		latency_qos = &cpus_latency_qos[cpu];

		if (ptlrpc_pmqos_use_stats_for_duration == false) {
			/* XXX should we use latency_qos->max_time if greater ? */
			this_cpu_time = ptlrpc_pmqos_default_duration_usec;
		} else if (time == 0) {
			this_cpu_time = latency_qos->max_time;
		} else {
			this_cpu_time = time;
			if (time > latency_qos->max_time)
				latency_qos->max_time = time;
		}

		new_deadline = jiffies_64 + usecs_to_jiffies(this_cpu_time);
		CDEBUG(D_TRACE, "%s: PM QoS new deadline estimation for cpu %d is %llu\n",
		       obd->obd_name, cpu, new_deadline);
		mutex_lock(&latency_qos->lock);
		if (latency_qos->pm_qos_req == NULL) {
			OBD_ALLOC_PTR(latency_qos->pm_qos_req);
			if (latency_qos->pm_qos_req == NULL) {
				CWARN("%s: Failed to allocate a PM-QoS request for cpu %d\n",
				      obd->obd_name, cpu);
				return;
			}
			dev_pm_qos_add_request(get_cpu_device(cpu),
					       latency_qos->pm_qos_req,
					       DEV_PM_QOS_RESUME_LATENCY,
					       ptlrpc_pmqos_latency_max_usec);
			latency_qos->deadline = new_deadline;
			CDEBUG(D_TRACE, "%s: PM QoS request now active for cpu %d\n",
			       obd->obd_name, cpu);
		} else if (dev_pm_qos_request_active(latency_qos->pm_qos_req)) {
			if (new_deadline > latency_qos->deadline) {
				cancel_delayed_work(&latency_qos->delayed_work);
				CDEBUG(D_TRACE,
				       "%s: PM QoS request active for cpu %d, simply extend its deadline from %llu\n",
				       obd->obd_name, cpu,
				       latency_qos->deadline);
				latency_qos->deadline = new_deadline;
			} else {
				new_work = false;
				CDEBUG(D_TRACE,
				       "%s: PM QoS request active for cpu %d, keep current deadline %llu\n",
				       obd->obd_name, cpu,
				       latency_qos->deadline);
			}
		} else {
			/* should not happen ? */
			CDEBUG(D_INFO,
			       "%s: Inactive PM QoS request for cpu %d, has been found unexpectedly...\n",
			       obd->obd_name, cpu);
		}
		if (new_work == true)
			schedule_delayed_work_on(cpu,
						 &latency_qos->delayed_work,
						 usecs_to_jiffies(this_cpu_time));
		mutex_unlock(&latency_qos->lock);
	}
}

/**
 * ptlrpc_send_reply() - Send request reply from request @req reply buffer.
 * @req: PTLRPC request
 * @flags: defines reply types
 *
 * Returns 0 on success or error code
 */
int ptlrpc_send_reply(struct ptlrpc_request *req, int flags)
{
	struct ptlrpc_reply_state *rs = req->rq_reply_state;
	struct ptlrpc_connection  *conn;
	int                        rc;

	/* We must already have a reply buffer (only ptlrpc_error() may be
	 * called without one). The reply generated by sptlrpc layer (e.g.
	 * error notify, etc.) might have NULL rq->reqmsg; Otherwise we must
	 * have a request buffer which is either the actual (swabbed) incoming
	 * request, or a saved copy if this is a req saved in
	 * target_queue_final_reply().
	 */
	LASSERT(req->rq_no_reply == 0);
	LASSERT(req->rq_reqbuf != NULL);
	LASSERT(rs != NULL);
	LASSERT((flags & PTLRPC_REPLY_MAYBE_DIFFICULT) || !rs->rs_difficult);
	LASSERT(req->rq_repmsg != NULL);
	LASSERT(req->rq_repmsg == rs->rs_msg);
	LASSERT(rs->rs_cb_id.cbid_fn == reply_out_callback);
	LASSERT(rs->rs_cb_id.cbid_arg == rs);

	/* There may be no rq_export during failover */

	if (unlikely(req->rq_export && req->rq_export->exp_obd &&
		     req->rq_export->exp_obd->obd_fail)) {
		/* Failed obd's only send ENODEV */
		req->rq_type = PTL_RPC_MSG_ERR;
		req->rq_status = -ENODEV;
		CDEBUG(D_HA, "sending ENODEV from failed obd %d\n",
		       req->rq_export->exp_obd->obd_minor);
	}

	if (req->rq_type != PTL_RPC_MSG_ERR)
		req->rq_type = PTL_RPC_MSG_REPLY;

	lustre_msg_set_type(req->rq_repmsg, req->rq_type);
	lustre_msg_set_status(req->rq_repmsg,
			      ptlrpc_status_hton(req->rq_status));
	lustre_msg_set_opc(req->rq_repmsg,
		req->rq_reqmsg ? lustre_msg_get_opc(req->rq_reqmsg) : 0);

	target_pack_pool_reply(req);

	ptlrpc_at_set_reply(req, flags);

	if (req->rq_export == NULL || req->rq_export->exp_connection == NULL)
		conn = ptlrpc_connection_get(&req->rq_peer, &req->rq_self,
					     NULL);
	else
		conn = ptlrpc_connection_addref(req->rq_export->exp_connection);

	if (unlikely(conn == NULL)) {
		CERROR("not replying on NULL connection\n"); /* bug 9635 */
		return -ENOTCONN;
	}
	kref_get(&rs->rs_refcount); /* +1 ref for the network */

	rc = sptlrpc_svc_wrap_reply(req);
	if (unlikely(rc))
		goto out;

	/*
	 * remove from the export list so quick
	 * resend won't find the original one.
	 */
	ptlrpc_del_exp_list(req);

	req->rq_sent = ktime_get_real_seconds();

	rc = ptl_send_buf(&rs->rs_md_h, rs->rs_repbuf, rs->rs_repdata_len,
			  (rs->rs_difficult && !rs->rs_no_ack) ?
			  LNET_ACK_REQ : LNET_NOACK_REQ,
			  &rs->rs_cb_id, &req->rq_self,
			  &req->rq_source,
			  ptlrpc_req2svc(req)->srv_rep_portal,
			  req->rq_rep_mbits ? req->rq_rep_mbits : req->rq_xid,
			  req->rq_reply_off, NULL);
out:
	if (unlikely(rc != 0))
		ptlrpc_req_drop_rs(req);
	ptlrpc_connection_put(conn);
	return rc;
}

int ptlrpc_reply(struct ptlrpc_request *req)
{
	if (req->rq_no_reply)
		return 0;
	else
		return (ptlrpc_send_reply(req, 0));
}

/*
 * For request @req send an error reply back. Create empty
 * reply buffers if necessary.
 */
int ptlrpc_send_error(struct ptlrpc_request *req, int may_be_difficult)
{
	int rc;

	ENTRY;

	if (req->rq_no_reply)
		RETURN(0);

	if (!req->rq_repmsg) {
		rc = lustre_pack_reply(req, 1, NULL, NULL);
		if (rc)
			RETURN(rc);
	}

	if (req->rq_status != -ENOSPC && req->rq_status != -EACCES &&
	    req->rq_status != -EPERM && req->rq_status != -ENOENT &&
	    req->rq_status != -EINPROGRESS && req->rq_status != -EDQUOT &&
	    req->rq_status != -EROFS)
		req->rq_type = PTL_RPC_MSG_ERR;

	rc = ptlrpc_send_reply(req, may_be_difficult);
	RETURN(rc);
}

int ptlrpc_error(struct ptlrpc_request *req)
{
	return ptlrpc_send_error(req, 0);
}

/**
 * ptl_send_rpc() - Send request @request.
 * @request: Request to send
 * @noreply: If set, don't expect any reply back and don't set up reply buffers
 *
 * Returns 0 on success or error code.
 */
int ptl_send_rpc(struct ptlrpc_request *request, int noreply)
{
	int rc;
	__u32 opc;
	int mpflag = 0;
	bool rep_mbits = false;
	struct lnet_handle_md bulk_cookie;
	struct lnet_processid peer;
	struct ptlrpc_connection *connection;
	struct lnet_me *reply_me = NULL;
	struct lnet_md reply_md;
	struct obd_import *imp = request->rq_import;
	struct obd_device *obd = imp->imp_obd;

	ENTRY;

	LNetInvalidateMDHandle(&bulk_cookie);

	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_DROP_RPC)) {
		request->rq_sent = ktime_get_real_seconds();
		RETURN(0);
	}

	if (unlikely(CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_DELAY_RECOV) &&
		     lustre_msg_get_opc(request->rq_reqmsg) == MDS_CONNECT &&
		     strcmp(obd->obd_type->typ_name, LUSTRE_OSP_NAME) == 0)) {
		RETURN(0);
	}

	if (unlikely(CFS_FAIL_TIMEOUT(OBD_FAIL_PTLRPC_DROP_MGS, cfs_fail_val) &&
		     lustre_msg_get_opc(request->rq_reqmsg) == MGS_CONNECT)) {
		DEBUG_REQ(D_INFO, request, "Simulate MGS connect failure");
		RETURN(0);
	}


	LASSERT(request->rq_type == PTL_RPC_MSG_REQUEST);
	LASSERT(request->rq_wait_ctx == 0);

	/* If this is re-transmit, disengaged cleanly from previous attempt */
	LASSERT(!request->rq_receiving_reply);
	LASSERT(!((lustre_msg_get_flags(request->rq_reqmsg) & MSG_REPLAY) &&
		  (imp->imp_state == LUSTRE_IMP_FULL)));

	if (unlikely(obd != NULL && obd->obd_fail)) {
		CDEBUG(D_HA, "muting rpc for failed imp obd %s\n",
		       obd->obd_name);
		/* this prevents us from waiting in ptlrpc_queue_wait */
		spin_lock(&request->rq_lock);
		request->rq_err = 1;
		spin_unlock(&request->rq_lock);
		request->rq_status = -ENODEV;
		RETURN(-ENODEV);
	}

	/* drop request over non-uptodate peers at connection stage,
	 * otherwise LNet peer discovery may pin request for much longer
	 * time than own ptlrpc expiration timeout. LU-17906
	 */
	spin_lock(&imp->imp_lock);
	if (imp->imp_conn_current && imp->imp_conn_current->oic_uptodate <= 0 &&
	    imp->imp_state == LUSTRE_IMP_CONNECTING) {
		spin_unlock(&imp->imp_lock);
		request->rq_sent = ktime_get_real_seconds();
		request->rq_timeout = 1;
		request->rq_deadline = request->rq_sent + 1;
		RETURN(0);
	}
	spin_unlock(&imp->imp_lock);

	connection = imp->imp_connection;

	lustre_msg_set_handle(request->rq_reqmsg,
			      &imp->imp_remote_handle);
	lustre_msg_set_type(request->rq_reqmsg, PTL_RPC_MSG_REQUEST);
	lustre_msg_set_conn_cnt(request->rq_reqmsg,
				imp->imp_conn_cnt);
	lustre_msghdr_set_flags(request->rq_reqmsg,
				imp->imp_msghdr_flags);

	/* First time to resend request for EINPROGRESS, need to allocate new
	 * XID(see after_reply()), it's different from resend for reply timeout
	 */
	if (request->rq_nr_resend != 0 &&
	    list_empty(&request->rq_unreplied_list)) {
		__u64 min_xid = 0;
		/* resend for EINPROGRESS, allocate new xid to avoid reply
		 * reconstruction
		 */
		spin_lock(&imp->imp_lock);
		ptlrpc_assign_next_xid_nolock(request);
		min_xid = ptlrpc_known_replied_xid(imp);
		spin_unlock(&imp->imp_lock);

		lustre_msg_set_last_xid(request->rq_reqmsg, min_xid);
		DEBUG_REQ(D_RPCTRACE, request,
			  "Allocating new XID for resend on EINPROGRESS");
	}

	opc = lustre_msg_get_opc(request->rq_reqmsg);
	if (opc != OST_CONNECT && opc != MDS_CONNECT &&
	    opc != MGS_CONNECT && OCD_HAS_FLAG(&imp->imp_connect_data, FLAGS2))
		rep_mbits = imp->imp_connect_data.ocd_connect_flags2 &
			OBD_CONNECT2_REP_MBITS;

	if ((request->rq_bulk != NULL) || rep_mbits) {
		ptlrpc_set_mbits(request);
		lustre_msg_set_mbits(request->rq_reqmsg, request->rq_mbits);
	}

	if (list_empty(&request->rq_unreplied_list) ||
	    request->rq_xid <= imp->imp_known_replied_xid) {
		DEBUG_REQ(D_ERROR, request,
			  "xid=%llu, replied=%llu, list_empty=%d",
			  request->rq_xid, imp->imp_known_replied_xid,
			  list_empty(&request->rq_unreplied_list));
		LBUG();
	}

	/**
	 * For enabled AT all request should have AT_SUPPORT in the
	 * FULL import state when OBD_CONNECT_AT is set.
	 * This check has a race with ptlrpc_connect_import_locked()
	 * with low chance, don't panic, only report.
	 */
	if (!(obd_at_off(obd) || imp->imp_state != LUSTRE_IMP_FULL ||
	    (imp->imp_msghdr_flags & MSGHDR_AT_SUPPORT) ||
	    !(imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_AT))) {
		DEBUG_REQ(D_HA, request, "Wrong state of import detected, AT=%d, imp=%d, msghdr=%d, conn=%d\n",
			  obd_at_off(obd), imp->imp_state != LUSTRE_IMP_FULL,
			  (imp->imp_msghdr_flags & MSGHDR_AT_SUPPORT),
			  !(imp->imp_connect_data.ocd_connect_flags &
			    OBD_CONNECT_AT));
	}
	if (request->rq_resend) {
		lustre_msg_add_flags(request->rq_reqmsg, MSG_RESENT);
		if (request->rq_resend_cb != NULL)
			request->rq_resend_cb(request, &request->rq_async_args);
	}
	if (request->rq_memalloc)
		mpflag = memalloc_noreclaim_save();

	rc = sptlrpc_cli_wrap_request(request);
	if (rc)
		GOTO(out, rc);

	/* bulk register should be done after wrap_request() */
	if (request->rq_bulk != NULL) {
		rc = ptlrpc_register_bulk(request);
		if (rc != 0)
			GOTO(cleanup_bulk, rc);
		/*
		 * All the mds in the request will have the same cpt
		 * encoded in the cookie. So we can just get the first
		 * one.
		 */
		bulk_cookie = request->rq_bulk->bd_mds[0];
	}

	if (!noreply) {
		LASSERT(request->rq_replen != 0);
		if (request->rq_repbuf == NULL) {
			LASSERT(request->rq_repdata == NULL);
			LASSERT(request->rq_repmsg == NULL);
			rc = sptlrpc_cli_alloc_repbuf(request,
						      request->rq_replen);
			if (rc) {
				/* prevent from looping in ptlrpc_queue_wait */
				spin_lock(&request->rq_lock);
				request->rq_err = 1;
				spin_unlock(&request->rq_lock);
				request->rq_status = rc;
				GOTO(cleanup_bulk, rc);
			}
		} else {
			request->rq_repdata = NULL;
			request->rq_repmsg = NULL;
		}

		peer = connection->c_peer;
		if (request->rq_bulk &&
		    CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_BULK_REPLY_ATTACH)) {
			reply_me = ERR_PTR(-ENOMEM);
		} else {
			reply_me = LNetMEAttach(request->rq_reply_portal,
						&peer,
						rep_mbits ? request->rq_mbits :
						request->rq_xid,
						0, LNET_UNLINK, LNET_INS_AFTER);
		}

		if (IS_ERR(reply_me)) {
			rc = PTR_ERR(reply_me);
			CERROR("LNetMEAttach failed: %d\n", rc);
			LASSERT(rc == -ENOMEM);
			GOTO(cleanup_bulk, rc = -ENOMEM);
		}
	}

	spin_lock(&request->rq_lock);
	/* We are responsible for unlinking the reply buffer */
	request->rq_reply_unlinked = noreply;
	request->rq_receiving_reply = !noreply;
	/* Clear any flags that may be present from previous sends. */
	request->rq_req_unlinked = 0;
	request->rq_replied = 0;
	request->rq_err = 0;
	request->rq_timedout = 0;
	request->rq_net_err = 0;
	request->rq_resend = 0;
	request->rq_restart = 0;
	request->rq_reply_truncated = 0;
	spin_unlock(&request->rq_lock);

	if (!noreply) {
		reply_md.umd_start = request->rq_repbuf;
		reply_md.umd_length = request->rq_repbuf_len;
		/* Allow multiple early replies */
		reply_md.umd_threshold = LNET_MD_THRESH_INF;
		/* Manage remote for early replies */
		reply_md.umd_options = PTLRPC_MD_OPTIONS | LNET_MD_OP_PUT |
			LNET_MD_MANAGE_REMOTE |
			LNET_MD_TRUNCATE; /* allow to make EOVERFLOW error */;
		reply_md.umd_user_ptr = &request->rq_reply_cbid;
		reply_md.umd_handler = ptlrpc_handler;

		/* We must see the unlink callback to set rq_reply_unlinked,
		 * so we can't auto-unlink
		 */
		rc = LNetMDAttach(reply_me, &reply_md, LNET_RETAIN,
				  &request->rq_reply_md_h);
		if (rc != 0) {
			CERROR("LNetMDAttach failed: %d\n", rc);
			LASSERT(rc == -ENOMEM);
			spin_lock(&request->rq_lock);
			/* ...but the MD attach didn't succeed... */
			request->rq_receiving_reply = 0;
			spin_unlock(&request->rq_lock);
			GOTO(cleanup_bulk, rc = -ENOMEM);
		}
		percpu_ref_get(&ptlrpc_pending);

		CDEBUG(D_NET,
		       "Setup reply buffer: %u bytes, xid %llu, portal %u\n",
		       request->rq_repbuf_len, request->rq_xid,
		       request->rq_reply_portal);
	}

	/* add references on request for request_out_callback */
	ptlrpc_request_addref(request);
	if (obd != NULL && obd->obd_svc_stats != NULL)
		lprocfs_counter_add(obd->obd_svc_stats, PTLRPC_REQACTIVE_CNTR,
				    atomic_read(&imp->imp_inflight));

	CFS_FAIL_TIMEOUT(OBD_FAIL_PTLRPC_DELAY_SEND, request->rq_timeout + 5);

	request->rq_sent_ns = ktime_get_real();
	request->rq_sent = ktime_get_real_seconds();
	/* We give the server rq_timeout secs to process the req, and
	 * add the network latency for our local timeout.
	 */
	request->rq_deadline = request->rq_sent + request->rq_timeout +
		ptlrpc_at_get_net_latency(request);

	DEBUG_REQ(D_INFO, request, "send flags=%x",
		  lustre_msg_get_flags(request->rq_reqmsg));

	if (unlikely(opc == OBD_PING &&
	    CFS_FAIL_TIMEOUT(OBD_FAIL_PTLRPC_DELAY_SEND_FAIL, cfs_fail_val))) {
		DEBUG_REQ(D_INFO, request, "Simulate delay send failure");
		GOTO(skip_send, rc);
	}

	rc = ptl_send_buf(&request->rq_req_md_h,
			  request->rq_reqbuf, request->rq_reqdata_len,
			  LNET_NOACK_REQ, &request->rq_req_cbid,
			  NULL,
			  &connection->c_peer,
			  request->rq_request_portal,
			  request->rq_xid, 0, &bulk_cookie);
	if (likely(rc == 0)) {
		/* lower CPU latency when in-flight RPCs */
		kick_cpu_latency(connection, obd);
		GOTO(out, rc);
	}

skip_send:
	request->rq_req_unlinked = 1;
	ptlrpc_req_put(request);
	if (noreply)
		GOTO(out, rc);

	LNetMDUnlink(request->rq_reply_md_h);

	/* UNLINKED callback called synchronously */
	LASSERT(!request->rq_receiving_reply);

 cleanup_bulk:
	/* We do sync unlink here as there was no real transfer here so
	 * the chance to have long unlink to sluggish net is smaller here.
	 */
	ptlrpc_unregister_bulk(request, 0);
 out:
	if (rc == -ENOMEM) {
		/* set rq_sent so that this request is treated
		 * as a delayed send in the upper layers
		 */
		request->rq_sent = ktime_get_real_seconds();
	}

	if (request->rq_memalloc)
		memalloc_noreclaim_restore(mpflag);

	return rc;
}
EXPORT_SYMBOL(ptl_send_rpc);

/* Register request buffer descriptor for request receiving. */
int ptlrpc_register_rqbd(struct ptlrpc_request_buffer_desc *rqbd)
{
	struct ptlrpc_service *service = rqbd->rqbd_svcpt->scp_service;
	static struct lnet_processid match_id = {
		.nid = LNET_ANY_NID,
		.pid = LNET_PID_ANY
	};
	struct lnet_md md = {
		.umd_start     = rqbd->rqbd_buffer,
		.umd_length    = service->srv_buf_size,
		.umd_max_size  = service->srv_max_req_size,
		.umd_threshold = LNET_MD_THRESH_INF,
		.umd_options   = PTLRPC_MD_OPTIONS | LNET_MD_OP_PUT |
		             LNET_MD_MAX_SIZE,
		.umd_user_ptr  = &rqbd->rqbd_cbid,
		.umd_handler   = ptlrpc_handler,
	};
	int rc;
	struct lnet_me *me;

	CDEBUG(D_NET, "%s: registering portal %d\n", service->srv_name,
	       service->srv_req_portal);

	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_RQBD))
		return -ENOMEM;

	/* NB: CPT affinity service should use new LNet flag LNET_INS_LOCAL,
	 * which means buffer can only be attached on local CPT, and LND
	 * threads can find it by grabbing a local lock
	 */
	me = LNetMEAttach(service->srv_req_portal,
			  &match_id, 0, ~0, LNET_UNLINK,
			  rqbd->rqbd_svcpt->scp_cpt >= 0 ?
			  LNET_INS_LOCAL : LNET_INS_AFTER);
	if (IS_ERR(me)) {
		CERROR("%s: LNetMEAttach failed: rc = %ld\n",
		       service->srv_name, PTR_ERR(me));
		return PTR_ERR(me);
	}

	LASSERT(rqbd->rqbd_refcount == 0);
	rqbd->rqbd_refcount = 1;

	rc = LNetMDAttach(me, &md, LNET_UNLINK, &rqbd->rqbd_md_h);
	if (rc == 0) {
		percpu_ref_get(&ptlrpc_pending);
		return 0;
	}

	CERROR("%s: LNetMDAttach failed: rc = %d\n", service->srv_name, rc);
	LASSERT(rc == -ENOMEM);
	rqbd->rqbd_refcount = 0;

	return rc;
}
