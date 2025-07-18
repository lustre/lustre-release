// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 *
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Isaac Huang <isaac@clusterfs.com>
 * Author: Liang Zhen  <liangzhen@clusterfs.com>
 *
 */

#define DEBUG_SUBSYSTEM S_LNET

#include "selftest.h"

struct lst_session_id LST_INVALID_SID = { .ses_nid = LNET_ANY_NID, .ses_stamp = -1};

static int session_timeout = 100;
module_param(session_timeout, int, 0444);
MODULE_PARM_DESC(session_timeout, "test session timeout in seconds (100 by default, 0 == never)");

static int rpc_timeout = 64;
module_param(rpc_timeout, int, 0644);
MODULE_PARM_DESC(rpc_timeout, "rpc timeout in seconds (64 by default, 0 == never)");

#define sfw_unpack_id(id)               \
do {                                    \
	__swab64s(&(id).nid);           \
	__swab32s(&(id).pid);           \
} while (0)

#define sfw_unpack_sid(sid)             \
do {                                    \
	__swab64s(&(sid).ses_nid);      \
	__swab64s(&(sid).ses_stamp);    \
} while (0)

#define sfw_unpack_fw_counters(fc)        \
do {                                      \
	__swab32s(&(fc).running_ms);      \
	__swab32s(&(fc).active_batches);  \
	__swab32s(&(fc).zombie_sessions); \
	__swab32s(&(fc).brw_errors);      \
	__swab32s(&(fc).ping_errors);     \
} while (0)

#define sfw_unpack_rpc_counters(rc)     \
do {                                    \
	__swab32s(&(rc).errors);        \
	__swab32s(&(rc).rpcs_sent);     \
	__swab32s(&(rc).rpcs_rcvd);     \
	__swab32s(&(rc).rpcs_dropped);  \
	__swab32s(&(rc).rpcs_expired);  \
	__swab64s(&(rc).bulk_get);      \
	__swab64s(&(rc).bulk_put);      \
} while (0)

#define sfw_unpack_lnet_counters(lc)    \
do {                                    \
	__swab32s(&(lc).lcc_errors);        \
	__swab32s(&(lc).lcc_msgs_max);      \
	__swab32s(&(lc).lcc_msgs_alloc);    \
	__swab32s(&(lc).lcc_send_count);    \
	__swab32s(&(lc).lcc_recv_count);    \
	__swab32s(&(lc).lcc_drop_count);    \
	__swab32s(&(lc).lcc_route_count);   \
	__swab64s(&(lc).lcc_send_length);   \
	__swab64s(&(lc).lcc_recv_length);   \
	__swab64s(&(lc).lcc_drop_length);   \
	__swab64s(&(lc).lcc_route_length);  \
} while (0)

#define sfw_test_active(t)      (atomic_read(&(t)->tsi_nactive) != 0)
#define sfw_batch_active(b)     (atomic_read(&(b)->bat_nactive) != 0)

static struct smoketest_framework {
	/* RPCs to be recycled */
	struct list_head	fw_zombie_rpcs;
	/* stopping sessions */
	struct list_head	fw_zombie_sessions;
	/* registered test cases */
	struct list_head	fw_tests;
	/* # zombie sessions */
	atomic_t		fw_nzombies;
	/* serialise */
	spinlock_t		fw_lock;
	/* _the_ session */
	struct sfw_session	*fw_session;
	/* shutdown in progress */
	int			fw_shuttingdown;
	/* running RPC */
	struct srpc_server_rpc	*fw_active_srpc;
} sfw_data;

static struct srpc_service sfw_services[] = {
	{ .sv_id = SRPC_SERVICE_DEBUG,		.sv_name = "debug", },
	{ .sv_id = SRPC_SERVICE_QUERY_STAT,	.sv_name = "query stats", },
	{ .sv_id = SRPC_SERVICE_MAKE_SESSION,	.sv_name = "make session", },
	{ .sv_id = SRPC_SERVICE_REMOVE_SESSION,	.sv_name = "remove session", },
	{ .sv_id = SRPC_SERVICE_BATCH,		.sv_name = "batch service", },
	{ .sv_id = SRPC_SERVICE_TEST,		.sv_name = "test service", },
	{ .sv_id = 0, }
};

/* forward ref's */
static int sfw_stop_batch(struct sfw_batch *tsb, int force);
static void sfw_destroy_session(struct sfw_session *sn);

static inline struct sfw_test_case *
sfw_find_test_case(int id)
{
	struct sfw_test_case *tsc;

	LASSERT(id <= SRPC_SERVICE_MAX_ID);
	LASSERT(id > SRPC_FRAMEWORK_SERVICE_MAX_ID);

	list_for_each_entry(tsc, &sfw_data.fw_tests, tsc_list) {
		if (tsc->tsc_srv_service->sv_id == id)
			return tsc;
	}

	return NULL;
}

static int
sfw_register_test(struct srpc_service *service,
		  struct sfw_test_client_ops *cliops)
{
	struct sfw_test_case *tsc;

	if (sfw_find_test_case(service->sv_id) != NULL) {
		CERROR("Failed to register test %s (%d): rc = %d\n",
		       service->sv_name, service->sv_id, -EEXIST);
		return -EEXIST;
	}

	LIBCFS_ALLOC(tsc, sizeof(*tsc));
	if (tsc == NULL)
		return -ENOMEM;

	tsc->tsc_cli_ops     = cliops;
	tsc->tsc_srv_service = service;

	list_add_tail(&tsc->tsc_list, &sfw_data.fw_tests);
	return 0;
}

static void
sfw_add_session_timer(void)
{
	struct sfw_session *sn = sfw_data.fw_session;
	struct stt_timer *timer = &sn->sn_timer;

	LASSERT(!sfw_data.fw_shuttingdown);

	if (sn == NULL || sn->sn_timeout == 0)
		return;

	LASSERT(!sn->sn_timer_active);

	sn->sn_timer_active = 1;
	timer->stt_expires = ktime_get_real_seconds() + sn->sn_timeout;
	stt_add_timer(timer);
}

static int
sfw_del_session_timer(void)
{
	struct sfw_session *sn = sfw_data.fw_session;

	if (sn == NULL || !sn->sn_timer_active)
		return 0;

	LASSERT(sn->sn_timeout != 0);

	if (stt_del_timer(&sn->sn_timer)) { /* timer defused */
		sn->sn_timer_active = 0;
		return 0;
	}

	return -EBUSY; /* racing with sfw_session_expired() */
}

/* called with sfw_data.fw_lock held */
static void
sfw_deactivate_session(void)
__must_hold(&sfw_data.fw_lock)
{
	struct sfw_session *sn = sfw_data.fw_session;
	int            nactive = 0;
	struct sfw_batch *tsb;
	struct sfw_test_case *tsc;

	if (sn == NULL)
		return;

	LASSERT(!sn->sn_timer_active);

	sfw_data.fw_session = NULL;
	atomic_inc(&sfw_data.fw_nzombies);
	list_add(&sn->sn_list, &sfw_data.fw_zombie_sessions);

	spin_unlock(&sfw_data.fw_lock);

	list_for_each_entry(tsc, &sfw_data.fw_tests, tsc_list) {
		srpc_abort_service(tsc->tsc_srv_service);
	}

	spin_lock(&sfw_data.fw_lock);

	list_for_each_entry(tsb, &sn->sn_batches, bat_list) {
		if (sfw_batch_active(tsb)) {
			nactive++;
			sfw_stop_batch(tsb, 1);
		}
	}

	if (nactive != 0)
		return;	/* wait for active batches to stop */

	list_del_init(&sn->sn_list);
	spin_unlock(&sfw_data.fw_lock);

	sfw_destroy_session(sn);

	spin_lock(&sfw_data.fw_lock);
}

static void
sfw_session_expired(void *data)
{
	struct sfw_session *sn = data;

	spin_lock(&sfw_data.fw_lock);

	LASSERT(sn->sn_timer_active);
	LASSERT(sn == sfw_data.fw_session);

	CWARN("Session expired! sid: %s-%llu, name: %s\n",
	      libcfs_nidstr(&sn->sn_id.ses_nid),
	      sn->sn_id.ses_stamp, &sn->sn_name[0]);

	sn->sn_timer_active = 0;
	sfw_deactivate_session();

	spin_unlock(&sfw_data.fw_lock);
}

static inline void
sfw_init_session(struct sfw_session *sn, struct lst_sid sid,
		 unsigned features, const char *name)
{
	struct stt_timer *timer = &sn->sn_timer;

	memset(sn, 0, sizeof(struct sfw_session));
	INIT_LIST_HEAD(&sn->sn_list);
	INIT_LIST_HEAD(&sn->sn_batches);
	refcount_set(&sn->sn_refcount, 1); /* +1 for caller */
	atomic_set(&sn->sn_brw_errors, 0);
	atomic_set(&sn->sn_ping_errors, 0);
	strscpy(&sn->sn_name[0], name, sizeof(sn->sn_name));

	sn->sn_timer_active = 0;
	sn->sn_id.ses_stamp = sid.ses_stamp;
	lnet_nid4_to_nid(sid.ses_nid, &sn->sn_id.ses_nid);
	sn->sn_features = features;
	sn->sn_timeout = session_timeout;
	sn->sn_started = ktime_get();

	timer->stt_data = sn;
	timer->stt_func = sfw_session_expired;
	INIT_LIST_HEAD(&timer->stt_list);
}

/* completion handler for incoming framework RPCs */
static void
sfw_server_rpc_done(struct srpc_server_rpc *rpc)
{
	struct srpc_service	*sv	= rpc->srpc_scd->scd_svc;
	int			status	= rpc->srpc_status;

	CDEBUG(D_NET,
	       "Incoming framework RPC done: service %s, peer %s, status %s:%d\n",
	       sv->sv_name, libcfs_id2str(rpc->srpc_peer),
	       swi_state2str(rpc->srpc_wi.swi_state), status);

	if (rpc->srpc_bulk) {
		srpc_free_bulk(rpc->srpc_bulk);
		rpc->srpc_bulk = NULL;
	}
}

static void
sfw_client_rpc_fini(struct srpc_client_rpc *rpc)
{
	LASSERT(rpc->crpc_bulk.bk_niov == 0);
	LASSERT(list_empty(&rpc->crpc_list));

	CDEBUG(D_NET, "Outgoing framework RPC done: "
	       "service %d, peer %s, status %s:%d:%d\n",
	       rpc->crpc_service, libcfs_id2str(rpc->crpc_dest),
	       swi_state2str(rpc->crpc_wi.swi_state),
	       rpc->crpc_aborted, rpc->crpc_status);

	spin_lock(&sfw_data.fw_lock);

	/* my callers must finish all RPCs before shutting me down */
	LASSERT(!sfw_data.fw_shuttingdown);
	list_add(&rpc->crpc_list, &sfw_data.fw_zombie_rpcs);

	spin_unlock(&sfw_data.fw_lock);
}

static struct sfw_batch *
sfw_find_batch(struct lst_bid bid)
{
	struct sfw_session *sn = sfw_data.fw_session;
	struct sfw_batch *bat;

	LASSERT(sn != NULL);

	list_for_each_entry(bat, &sn->sn_batches, bat_list) {
		if (bat->bat_id.bat_id == bid.bat_id)
			return bat;
	}

	return NULL;
}

static struct sfw_batch *
sfw_bid2batch(struct lst_bid bid)
{
	struct sfw_session *sn = sfw_data.fw_session;
	struct sfw_batch *bat;

	LASSERT(sn != NULL);

	bat = sfw_find_batch(bid);
	if (bat != NULL)
		return bat;

	LIBCFS_ALLOC(bat, sizeof(*bat));
	if (bat == NULL)
		return NULL;

	bat->bat_error	 = 0;
	bat->bat_session = sn;
	bat->bat_id	 = bid;
	atomic_set(&bat->bat_nactive, 0);
	INIT_LIST_HEAD(&bat->bat_tests);

	list_add_tail(&bat->bat_list, &sn->sn_batches);
	return bat;
}

static struct lst_sid get_old_sid(struct sfw_session *sn)
{
	struct lst_sid sid = { .ses_nid = LNET_NID_ANY, .ses_stamp = -1 };

	if (sn) {
		sid.ses_stamp = sn->sn_id.ses_stamp;
		sid.ses_nid = lnet_nid_to_nid4(&sn->sn_id.ses_nid);
	}

	return sid;
}

static int
sfw_get_stats(struct srpc_stat_reqst *request, struct srpc_stat_reply *reply)
{
	struct sfw_session *sn = sfw_data.fw_session;
	struct sfw_counters *cnt = &reply->str_fw;
	struct sfw_batch *bat;

	reply->str_sid = get_old_sid(sn);

	if (request->str_sid.ses_nid == LNET_NID_ANY) {
		reply->str_status = EINVAL;
		return 0;
	}

	if (sn == NULL || !sfw_sid_equal(request->str_sid, sn->sn_id)) {
		reply->str_status = ESRCH;
		return 0;
	}

	lnet_counters_get_common(&reply->str_lnet);
	srpc_get_counters(&reply->str_rpc);

	/* send over the msecs since the session was started
	 * - with 32 bits to send, this is ~49 days */
	cnt->running_ms = ktime_ms_delta(ktime_get(), sn->sn_started);
	cnt->brw_errors = atomic_read(&sn->sn_brw_errors);
	cnt->ping_errors = atomic_read(&sn->sn_ping_errors);
	cnt->zombie_sessions = atomic_read(&sfw_data.fw_nzombies);

	cnt->active_batches = 0;
	list_for_each_entry(bat, &sn->sn_batches, bat_list) {
		if (atomic_read(&bat->bat_nactive) > 0)
			cnt->active_batches++;
	}

	reply->str_status = 0;
	return 0;
}

int
sfw_make_session(struct srpc_mksn_reqst *request, struct srpc_mksn_reply *reply)
{
	struct sfw_session *sn = sfw_data.fw_session;
	struct srpc_msg *msg = container_of(request, struct srpc_msg,
					    msg_body.mksn_reqst);
	int cplen = 0;

	if (request->mksn_sid.ses_nid == LNET_NID_ANY) {
		reply->mksn_sid = get_old_sid(sn);
		reply->mksn_status = EINVAL;
		return 0;
	}

	if (sn != NULL) {
		reply->mksn_status  = 0;
		reply->mksn_sid = get_old_sid(sn);
		reply->mksn_timeout = sn->sn_timeout;

		if (sfw_sid_equal(request->mksn_sid, sn->sn_id)) {
			refcount_inc(&sn->sn_refcount);
			return 0;
		}

		if (!request->mksn_force) {
			reply->mksn_status = EBUSY;
			cplen = strscpy(&reply->mksn_name[0], &sn->sn_name[0],
					sizeof(reply->mksn_name));
			if (cplen < 0)
				return cplen;
			return 0;
		}
	}

	/* reject the request if it requires unknown features
	 * NB: old version will always accept all features because it's not
	 * aware of struct srpc_msg::msg_ses_feats, it's a defect but it's also
	 * harmless because it will return zero feature to console, and it's
	 * console's responsibility to make sure all nodes in a session have
	 * same feature mask. */
	if ((msg->msg_ses_feats & ~LST_FEATS_MASK) != 0) {
		reply->mksn_status = EPROTO;
		return 0;
	}

	/* brand new or create by force */
	LIBCFS_ALLOC(sn, sizeof(*sn));
	if (sn == NULL) {
		CERROR("dropping RPC mksn under memory pressure: rc = %d\n",
		       -ENOMEM);
		return -ENOMEM;
	}

	sfw_init_session(sn, request->mksn_sid,
			 msg->msg_ses_feats, &request->mksn_name[0]);

	spin_lock(&sfw_data.fw_lock);

	sfw_deactivate_session();
	LASSERT(sfw_data.fw_session == NULL);
	sfw_data.fw_session = sn;

	spin_unlock(&sfw_data.fw_lock);

	reply->mksn_status  = 0;
	reply->mksn_sid = get_old_sid(sn);
	reply->mksn_timeout = sn->sn_timeout;
	return 0;
}

static int
sfw_remove_session(struct srpc_rmsn_reqst *request,
		   struct srpc_rmsn_reply *reply)
{
	struct sfw_session *sn = sfw_data.fw_session;

	reply->rmsn_sid = get_old_sid(sn);

	if (request->rmsn_sid.ses_nid == LNET_NID_ANY) {
		reply->rmsn_status = EINVAL;
		return 0;
	}

	if (sn == NULL || !sfw_sid_equal(request->rmsn_sid, sn->sn_id)) {
		reply->rmsn_status = (sn == NULL) ? ESRCH : EBUSY;
		return 0;
	}

	if (!refcount_dec_and_test(&sn->sn_refcount)) {
		reply->rmsn_status = 0;
		return 0;
	}

	spin_lock(&sfw_data.fw_lock);
	sfw_deactivate_session();
	spin_unlock(&sfw_data.fw_lock);

	reply->rmsn_status = 0;
	reply->rmsn_sid = get_old_sid(NULL);
	LASSERT(sfw_data.fw_session == NULL);
	return 0;
}

static int
sfw_debug_session(struct srpc_debug_reqst *request,
		  struct srpc_debug_reply *reply)
{
	struct sfw_session *sn = sfw_data.fw_session;
	int cplen;

	if (sn == NULL) {
		reply->dbg_status = ESRCH;
		reply->dbg_sid = get_old_sid(NULL);
		return 0;
	}

	reply->dbg_status  = 0;
	reply->dbg_sid = get_old_sid(sn);
	reply->dbg_timeout = sn->sn_timeout;
	cplen = strscpy(reply->dbg_name, &sn->sn_name[0],
		    sizeof(reply->dbg_name));
	if (cplen < 0)
		return cplen;

	return 0;
}

static void
sfw_test_rpc_fini(struct srpc_client_rpc *rpc)
{
	struct sfw_test_unit *tsu = rpc->crpc_priv;
	struct sfw_test_instance *tsi = tsu->tsu_instance;

	/* Called with hold of tsi->tsi_lock */
	LASSERT(list_empty(&rpc->crpc_list));
	rpc->crpc_wi.swi_state = SWI_STATE_DONE;
	list_add(&rpc->crpc_list, &tsi->tsi_free_rpcs);
}

static inline int
sfw_test_buffers(struct sfw_test_instance *tsi)
{
	struct sfw_test_case	*tsc;
	struct srpc_service	*svc;
	int			nbuf;

	LASSERT(tsi != NULL);
	tsc = sfw_find_test_case(tsi->tsi_service);
	LASSERT(tsc != NULL);
	svc = tsc->tsc_srv_service;
	LASSERT(svc != NULL);

	nbuf = min(svc->sv_wi_total, tsi->tsi_loop) / svc->sv_ncpts;
	return max(SFW_TEST_WI_MIN, nbuf + SFW_TEST_WI_EXTRA);
}

static int
sfw_load_test(struct sfw_test_instance *tsi)
{
	struct sfw_test_case	*tsc;
	struct srpc_service	*svc;
	int			nbuf;
	int			rc;

	LASSERT(tsi != NULL);
	tsc = sfw_find_test_case(tsi->tsi_service);
	nbuf = sfw_test_buffers(tsi);
	LASSERT(tsc != NULL);
	svc = tsc->tsc_srv_service;

	if (tsi->tsi_is_client) {
		tsi->tsi_ops = tsc->tsc_cli_ops;
		return 0;
	}

	rc = srpc_service_add_buffers(svc, nbuf);
	if (rc != 0) {
		CWARN("Failed to reserve enough buffers: "
		      "service %s, %d needed: %d\n", svc->sv_name, nbuf, rc);
		/* NB: this error handler is not strictly correct, because
		 * it may release more buffers than already allocated,
		 * but it doesn't matter because request portal should
		 * be lazy portal and will grow buffers if necessary. */
		srpc_service_remove_buffers(svc, nbuf);
		return -ENOMEM;
	}

	CDEBUG(D_NET, "Reserved %d buffers for test %s\n",
	       nbuf * (srpc_serv_is_framework(svc) ?
		       1 : cfs_cpt_number(cfs_cpt_tab)), svc->sv_name);
	return 0;
}

static void
sfw_unload_test(struct sfw_test_instance *tsi)
{
	struct sfw_test_case *tsc;

	LASSERT(tsi != NULL);
	tsc = sfw_find_test_case(tsi->tsi_service);
	LASSERT(tsc != NULL);

	if (tsi->tsi_is_client)
		return;

	/* shrink buffers, because request portal is lazy portal
	 * which can grow buffers at runtime so we may leave
	 * some buffers behind, but never mind... */
	srpc_service_remove_buffers(tsc->tsc_srv_service,
				    sfw_test_buffers(tsi));
}

static void
sfw_destroy_test_instance(struct sfw_test_instance *tsi)
{
	struct srpc_client_rpc *rpc;
	struct sfw_test_unit *tsu;

	if (!tsi->tsi_is_client)
		goto clean;

	tsi->tsi_ops->tso_fini(tsi);

	LASSERT(!tsi->tsi_stopping);
	LASSERT(list_empty(&tsi->tsi_active_rpcs));
	LASSERT(!sfw_test_active(tsi));

	while (!list_empty(&tsi->tsi_units)) {
		tsu = list_first_entry(&tsi->tsi_units,
				       struct sfw_test_unit, tsu_list);
		list_del(&tsu->tsu_list);
		LIBCFS_FREE(tsu, sizeof(*tsu));
	}

	while (!list_empty(&tsi->tsi_free_rpcs)) {
		rpc = list_first_entry(&tsi->tsi_free_rpcs,
				       struct srpc_client_rpc, crpc_list);
		list_del(&rpc->crpc_list);
		swi_cancel_workitem(&rpc->crpc_wi);
		LIBCFS_FREE(rpc, srpc_client_rpc_size(rpc));
	}

clean:
	sfw_unload_test(tsi);
	LIBCFS_FREE(tsi, sizeof(*tsi));
}

static void
sfw_destroy_batch(struct sfw_batch *tsb)
{
	struct sfw_test_instance *tsi;

	LASSERT(!sfw_batch_active(tsb));
	LASSERT(list_empty(&tsb->bat_list));

	while (!list_empty(&tsb->bat_tests)) {
		tsi = list_first_entry(&tsb->bat_tests,
				       struct sfw_test_instance, tsi_list);
		list_del_init(&tsi->tsi_list);
		sfw_destroy_test_instance(tsi);
	}

	LIBCFS_FREE(tsb, sizeof(*tsb));
}

static void
sfw_destroy_session(struct sfw_session *sn)
{
	struct sfw_batch *batch;

	LASSERT(list_empty(&sn->sn_list));
	LASSERT(sn != sfw_data.fw_session);

	while (!list_empty(&sn->sn_batches)) {
		batch = list_first_entry(&sn->sn_batches,
					 struct sfw_batch, bat_list);
		list_del_init(&batch->bat_list);
		sfw_destroy_batch(batch);
	}

	LIBCFS_FREE(sn, sizeof(*sn));
	atomic_dec(&sfw_data.fw_nzombies);
}

static void
sfw_unpack_addtest_req(struct srpc_msg *msg)
{
	struct srpc_test_reqst *req = &msg->msg_body.tes_reqst;

	LASSERT(msg->msg_type == SRPC_MSG_TEST_REQST);
	LASSERT(req->tsr_is_client);

	if (msg->msg_magic == SRPC_MSG_MAGIC)
		return; /* no flipping needed */

	LASSERT(msg->msg_magic == __swab32(SRPC_MSG_MAGIC));

	if (req->tsr_service == SRPC_SERVICE_BRW) {
		if ((msg->msg_ses_feats & LST_FEAT_BULK_LEN) == 0) {
			struct test_bulk_req *bulk = &req->tsr_u.bulk_v0;

			__swab32s(&bulk->blk_opc);
			__swab32s(&bulk->blk_npg);
			__swab32s(&bulk->blk_flags);

		} else {
			struct test_bulk_req_v1 *bulk = &req->tsr_u.bulk_v1;

			__swab16s(&bulk->blk_opc);
			__swab16s(&bulk->blk_flags);
			__swab32s(&bulk->blk_offset);
			__swab32s(&bulk->blk_len);
		}

		return;
	}

	if (req->tsr_service == SRPC_SERVICE_PING) {
		struct test_ping_req *ping = &req->tsr_u.ping;

		__swab32s(&ping->png_size);
		__swab32s(&ping->png_flags);
		return;
	}

	LBUG();
}

static int
sfw_add_test_instance(struct sfw_batch *tsb, struct srpc_server_rpc *rpc)
{
	struct srpc_msg *msg = &rpc->srpc_reqstbuf->buf_msg;
	struct srpc_test_reqst *req = &msg->msg_body.tes_reqst;
	struct srpc_bulk *bk = rpc->srpc_bulk;
	int ndest = req->tsr_ndest;
	struct sfw_test_unit *tsu;
	struct sfw_test_instance *tsi;
	int i;
	int rc;

	LIBCFS_ALLOC(tsi, sizeof(*tsi));
	if (tsi == NULL) {
		CERROR("Can't allocate test instance for batch: %llu: rc = %d\n",
		       tsb->bat_id.bat_id, -ENOMEM);
		return -ENOMEM;
	}

	spin_lock_init(&tsi->tsi_lock);
	atomic_set(&tsi->tsi_nactive, 0);
	INIT_LIST_HEAD(&tsi->tsi_units);
	INIT_LIST_HEAD(&tsi->tsi_free_rpcs);
	INIT_LIST_HEAD(&tsi->tsi_active_rpcs);

	tsi->tsi_stopping      = 0;
	tsi->tsi_batch         = tsb;
	tsi->tsi_loop          = req->tsr_loop;
	tsi->tsi_concur        = req->tsr_concur;
	tsi->tsi_service       = req->tsr_service;
	tsi->tsi_is_client     = !!(req->tsr_is_client);
	tsi->tsi_stoptsu_onerr = !!(req->tsr_stop_onerr);

	rc = sfw_load_test(tsi);
	if (rc != 0) {
		LIBCFS_FREE(tsi, sizeof(*tsi));
		return rc;
	}

	LASSERT(!sfw_batch_active(tsb));

	if (!tsi->tsi_is_client) {
		/* it's test server, just add it to tsb */
		list_add_tail(&tsi->tsi_list, &tsb->bat_tests);
		return 0;
	}

	LASSERT(bk != NULL);
	LASSERT(bk->bk_niov * SFW_ID_PER_PAGE >= (unsigned int)ndest);
	LASSERT((unsigned int)bk->bk_len >=
		sizeof(struct lnet_process_id_packed) * ndest);

	sfw_unpack_addtest_req(msg);
	memcpy(&tsi->tsi_u, &req->tsr_u, sizeof(tsi->tsi_u));

	for (i = 0; i < ndest; i++) {
		struct lnet_process_id_packed *dests;
		struct lnet_process_id_packed  id;
		int j;

		dests = page_address(bk->bk_iovs[i / SFW_ID_PER_PAGE].bv_page);
		LASSERT(dests != NULL);  /* my pages are within KVM always */
		id = dests[i % SFW_ID_PER_PAGE];
		if (msg->msg_magic != SRPC_MSG_MAGIC)
			sfw_unpack_id(id);

		for (j = 0; j < tsi->tsi_concur; j++) {
			LIBCFS_ALLOC(tsu, sizeof(*tsu));
			if (tsu == NULL) {
				rc = -ENOMEM;
				CERROR("Can't allocate tsu for %d: rc = %d\n",
				       tsi->tsi_service, rc);
				goto error;
			}

			tsu->tsu_dest.nid = id.nid;
			tsu->tsu_dest.pid = id.pid;
			tsu->tsu_instance = tsi;
			tsu->tsu_private  = NULL;
			list_add_tail(&tsu->tsu_list, &tsi->tsi_units);
		}
	}

	rc = tsi->tsi_ops->tso_init(tsi);
	if (rc == 0) {
		list_add_tail(&tsi->tsi_list, &tsb->bat_tests);
		return 0;
	}

error:
	LASSERT(rc != 0);
	sfw_destroy_test_instance(tsi);
	return rc;
}

static void
sfw_test_unit_done(struct sfw_test_unit *tsu)
{
	struct sfw_test_instance *tsi = tsu->tsu_instance;
	struct sfw_batch *tsb = tsi->tsi_batch;
	struct sfw_session *sn = tsb->bat_session;

	LASSERT(sfw_test_active(tsi));

	if (!atomic_dec_and_test(&tsi->tsi_nactive))
		return;

	/* the test instance is done */
	spin_lock(&tsi->tsi_lock);

	tsi->tsi_stopping = 0;

	spin_unlock(&tsi->tsi_lock);

	spin_lock(&sfw_data.fw_lock);

	if (!atomic_dec_and_test(&tsb->bat_nactive) ||/* tsb still active */
	    sn == sfw_data.fw_session) {		  /* sn also active */
		spin_unlock(&sfw_data.fw_lock);
		return;
	}

	LASSERT(!list_empty(&sn->sn_list)); /* I'm a zombie! */

	list_for_each_entry(tsb, &sn->sn_batches, bat_list) {
		if (sfw_batch_active(tsb)) {
			spin_unlock(&sfw_data.fw_lock);
			return;
		}
	}

	list_del_init(&sn->sn_list);
	spin_unlock(&sfw_data.fw_lock);

	sfw_destroy_session(sn);
}

static void
sfw_test_rpc_done(struct srpc_client_rpc *rpc)
{
	struct sfw_test_unit *tsu = rpc->crpc_priv;
	struct sfw_test_instance *tsi = tsu->tsu_instance;
	int done = 0;

	tsi->tsi_ops->tso_done_rpc(tsu, rpc);

	spin_lock(&tsi->tsi_lock);

	LASSERT(sfw_test_active(tsi));
	LASSERT(!list_empty(&rpc->crpc_list));

	list_del_init(&rpc->crpc_list);

	/* batch is stopping or loop is done or get error */
	if (tsi->tsi_stopping || tsu->tsu_loop == 0 ||
	    (rpc->crpc_status != 0 && tsi->tsi_stoptsu_onerr))
		done = 1;

	/* dec ref for poster */
	srpc_client_rpc_decref(rpc);

	spin_unlock(&tsi->tsi_lock);

	if (!done) {
		swi_schedule_workitem(&tsu->tsu_worker);
		return;
	}

	sfw_test_unit_done(tsu);
}

int
sfw_create_test_rpc(struct sfw_test_unit *tsu, struct lnet_process_id peer,
		    unsigned features, int nblk, int blklen,
		    struct srpc_client_rpc **rpcpp)
{
	struct srpc_client_rpc *rpc = NULL;
	struct sfw_test_instance *tsi = tsu->tsu_instance;

	spin_lock(&tsi->tsi_lock);

	LASSERT(sfw_test_active(tsi));

	if (!list_empty(&tsi->tsi_free_rpcs)) {
		/* pick request from buffer */
		rpc = list_first_entry(&tsi->tsi_free_rpcs,
				       struct srpc_client_rpc, crpc_list);
		LASSERT(nblk == rpc->crpc_bulk.bk_niov);
		list_del_init(&rpc->crpc_list);
	}

	spin_unlock(&tsi->tsi_lock);

	if (rpc == NULL) {
		rpc = srpc_create_client_rpc(peer, tsi->tsi_service, nblk,
					     blklen, sfw_test_rpc_done,
					     sfw_test_rpc_fini, tsu);
	} else {
		swi_cancel_workitem(&rpc->crpc_wi);
		srpc_init_client_rpc(rpc, peer, tsi->tsi_service, nblk,
				     blklen, sfw_test_rpc_done,
				     sfw_test_rpc_fini, tsu);
	}

	if (rpc == NULL) {
		CERROR("Can't create rpc for test %d: rc = %d\n",
		       tsi->tsi_service, -ENOMEM);
		return -ENOMEM;
	}

	rpc->crpc_reqstmsg.msg_ses_feats = features;
	*rpcpp = rpc;

	return 0;
}

static void
sfw_run_test(struct swi_workitem *wi)
{
	struct sfw_test_unit *tsu = container_of(wi, struct sfw_test_unit,
						 tsu_worker);
	struct sfw_test_instance *tsi = tsu->tsu_instance;
	struct srpc_client_rpc *rpc = NULL;

	if (tsi->tsi_ops->tso_prep_rpc(tsu, tsu->tsu_dest, &rpc) != 0) {
		LASSERT(rpc == NULL);
		wi->swi_state = SWI_STATE_DONE;
		goto test_done;
	}

	LASSERT(rpc != NULL);

	spin_lock(&tsi->tsi_lock);
	if (wi->swi_state == SWI_STATE_DONE) {
		spin_unlock(&tsi->tsi_lock);
		return;
	}

	if (tsi->tsi_stopping) {
		wi->swi_state = SWI_STATE_DONE;
		list_add(&rpc->crpc_list, &tsi->tsi_free_rpcs);
		spin_unlock(&tsi->tsi_lock);
		goto test_done;
	}

	if (tsu->tsu_loop > 0)
		tsu->tsu_loop--;

	list_add_tail(&rpc->crpc_list, &tsi->tsi_active_rpcs);
	wi->swi_state = SWI_STATE_RUNNING;
	spin_unlock(&tsi->tsi_lock);

	spin_lock(&rpc->crpc_lock);
	rpc->crpc_timeout = rpc_timeout;
	srpc_post_rpc(rpc);
	spin_unlock(&rpc->crpc_lock);
	return;

test_done:
	/*
	 * No one can schedule me now since:
	 * - previous RPC, if any, has done and
	 * - no new RPC is initiated.
	 * - my batch is still active; no one can run it again now.
	 * Cancel pending schedules and prevent future schedule attempts:
	 */
	sfw_test_unit_done(tsu);
}

static int
sfw_run_batch(struct sfw_batch *tsb)
{
	struct swi_workitem *wi;
	struct sfw_test_unit *tsu;
	struct sfw_test_instance *tsi;

	if (sfw_batch_active(tsb)) {
		CDEBUG(D_NET, "Batch already active: %llu (%d)\n",
		       tsb->bat_id.bat_id, atomic_read(&tsb->bat_nactive));
		return 0;
	}

	list_for_each_entry(tsi, &tsb->bat_tests, tsi_list) {
		if (!tsi->tsi_is_client)	/* skip server instances */
			continue;

		LASSERT(!tsi->tsi_stopping);
		LASSERT(!sfw_test_active(tsi));

		atomic_inc(&tsb->bat_nactive);

		list_for_each_entry(tsu, &tsi->tsi_units, tsu_list) {
			atomic_inc(&tsi->tsi_nactive);
			tsu->tsu_loop = tsi->tsi_loop;
			wi = &tsu->tsu_worker;
			swi_init_workitem(wi, sfw_run_test,
					  lst_test_wq[lnet_cpt_of_nid(
							      tsu->tsu_dest.nid,
							      NULL)]);
			swi_schedule_workitem(wi);
		}
	}

	return 0;
}

static int
sfw_stop_batch(struct sfw_batch *tsb, int force)
{
	struct sfw_test_instance *tsi;
	struct srpc_client_rpc *rpc;

	if (!sfw_batch_active(tsb)) {
		CDEBUG(D_NET, "Batch %llu inactive\n", tsb->bat_id.bat_id);
		return 0;
	}

	list_for_each_entry(tsi, &tsb->bat_tests, tsi_list) {
		spin_lock(&tsi->tsi_lock);

		if (!tsi->tsi_is_client ||
		    !sfw_test_active(tsi) || tsi->tsi_stopping) {
			spin_unlock(&tsi->tsi_lock);
			continue;
		}

		tsi->tsi_stopping = 1;

		if (!force) {
			spin_unlock(&tsi->tsi_lock);
			continue;
		}

		/* abort launched rpcs in the test */
		list_for_each_entry(rpc, &tsi->tsi_active_rpcs, crpc_list) {
			spin_lock(&rpc->crpc_lock);

			srpc_abort_rpc(rpc, -EINTR);

			spin_unlock(&rpc->crpc_lock);
		}

		spin_unlock(&tsi->tsi_lock);
	}

	return 0;
}

static int
sfw_query_batch(struct sfw_batch *tsb, int testidx,
		struct srpc_batch_reply *reply)
{
	struct sfw_test_instance *tsi;

	if (testidx < 0)
		return -EINVAL;

	if (testidx == 0) {
		reply->bar_active = atomic_read(&tsb->bat_nactive);
		return 0;
	}

	list_for_each_entry(tsi, &tsb->bat_tests, tsi_list) {
		if (testidx-- > 1)
			continue;

		reply->bar_active = atomic_read(&tsi->tsi_nactive);
		return 0;
	}

	return -ENOENT;
}

int
sfw_alloc_pages(struct srpc_server_rpc *rpc, int cpt, int len,
		int sink)
{
	LASSERT(rpc->srpc_bulk == NULL);
	LASSERT(len > 0 && len <= LNET_MTU);

	rpc->srpc_bulk = srpc_alloc_bulk(cpt, len);
	if (rpc->srpc_bulk == NULL)
		return -ENOMEM;

	srpc_init_bulk(rpc->srpc_bulk, 0, len, sink);

	return 0;
}

static int
sfw_add_test(struct srpc_server_rpc *rpc)
{
	struct sfw_session *sn = sfw_data.fw_session;
	struct srpc_test_reply *reply = &rpc->srpc_replymsg.msg_body.tes_reply;
	struct srpc_test_reqst *request;
	int rc;
	struct sfw_batch *bat;

	request = &rpc->srpc_reqstbuf->buf_msg.msg_body.tes_reqst;
	reply->tsr_sid = get_old_sid(sn);

	if (request->tsr_loop == 0 || request->tsr_concur == 0 ||
	    request->tsr_sid.ses_nid == LNET_NID_ANY ||
	    request->tsr_ndest > SFW_MAX_NDESTS ||
	    (request->tsr_is_client && request->tsr_ndest == 0) ||
	    request->tsr_concur > SFW_MAX_CONCUR ||
	    request->tsr_service > SRPC_SERVICE_MAX_ID ||
	    request->tsr_service <= SRPC_FRAMEWORK_SERVICE_MAX_ID) {
		reply->tsr_status = EINVAL;
		return 0;
	}

	if (sn == NULL || !sfw_sid_equal(request->tsr_sid, sn->sn_id) ||
	    sfw_find_test_case(request->tsr_service) == NULL) {
		reply->tsr_status = ENOENT;
		return 0;
	}

	bat = sfw_bid2batch(request->tsr_bid);
	if (bat == NULL) {
		CERROR("dropping RPC %s from %s under memory pressure: rc = %d\n",
			rpc->srpc_scd->scd_svc->sv_name,
			libcfs_id2str(rpc->srpc_peer), -ENOMEM);
		return -ENOMEM;
	}

	if (sfw_batch_active(bat)) {
		reply->tsr_status = EBUSY;
		return 0;
	}

	if (request->tsr_is_client && rpc->srpc_bulk == NULL) {
		/* rpc will be resumed later in sfw_bulk_ready */
		int	len;

		len = sizeof(struct lnet_process_id_packed) *
			      request->tsr_ndest;

		return sfw_alloc_pages(rpc, CFS_CPT_ANY, len, 1);
        }

	rc = sfw_add_test_instance(bat, rpc);
	CDEBUG(rc == 0 ? D_NET : D_WARNING,
	       "%s test: sv %d %s, loop %d, concur %d, ndest %d\n",
	       rc == 0 ? "Added" : "Failed to add", request->tsr_service,
	       request->tsr_is_client ? "client" : "server",
	       request->tsr_loop, request->tsr_concur, request->tsr_ndest);

	reply->tsr_status = (rc < 0) ? -rc : rc;
	return 0;
}

static int
sfw_control_batch(struct srpc_batch_reqst *request,
		  struct srpc_batch_reply *reply)
{
	struct sfw_session *sn = sfw_data.fw_session;
	struct sfw_batch *bat;
	int rc = 0;

	reply->bar_sid = get_old_sid(sn);

	if (sn == NULL || !sfw_sid_equal(request->bar_sid, sn->sn_id)) {
		reply->bar_status = ESRCH;
		return 0;
	}

	bat = sfw_find_batch(request->bar_bid);
	if (bat == NULL) {
		reply->bar_status = ENOENT;
		return 0;
	}

	switch (request->bar_opc) {
	case SRPC_BATCH_OPC_RUN:
		rc = sfw_run_batch(bat);
		break;

	case SRPC_BATCH_OPC_STOP:
		rc = sfw_stop_batch(bat, request->bar_arg);
		break;

	case SRPC_BATCH_OPC_QUERY:
		rc = sfw_query_batch(bat, request->bar_testidx, reply);
		break;

	default:
		return -EINVAL; /* drop it */
	}

	reply->bar_status = (rc < 0) ? -rc : rc;
	return 0;
}

static int
sfw_handle_server_rpc(struct srpc_server_rpc *rpc)
{
	struct srpc_service	*sv = rpc->srpc_scd->scd_svc;
	struct srpc_msg     *reply	= &rpc->srpc_replymsg;
	struct srpc_msg     *request	= &rpc->srpc_reqstbuf->buf_msg;
	unsigned	features = LST_FEATS_MASK;
	int		rc = 0;

	LASSERT(sfw_data.fw_active_srpc == NULL);
	LASSERT(sv->sv_id <= SRPC_FRAMEWORK_SERVICE_MAX_ID);

	spin_lock(&sfw_data.fw_lock);

	if (sfw_data.fw_shuttingdown) {
		spin_unlock(&sfw_data.fw_lock);
		return -ESHUTDOWN;
	}

	/* Remove timer to avoid racing with it or expiring active session */
	if (sfw_del_session_timer() != 0) {
		CERROR("dropping RPC %s from %s: racing with expiry timer: rc = %d\n",
		       sv->sv_name, libcfs_id2str(rpc->srpc_peer), -EAGAIN);
		spin_unlock(&sfw_data.fw_lock);
		return -EAGAIN;
	}

	sfw_data.fw_active_srpc = rpc;
	spin_unlock(&sfw_data.fw_lock);

	sfw_unpack_message(request);
	LASSERT(request->msg_type == srpc_service2request(sv->sv_id));

	/* rpc module should have checked this */
	LASSERT(request->msg_version == SRPC_MSG_VERSION);

	if (sv->sv_id != SRPC_SERVICE_MAKE_SESSION &&
	    sv->sv_id != SRPC_SERVICE_DEBUG) {
		struct sfw_session *sn = sfw_data.fw_session;

		if (sn != NULL &&
		    sn->sn_features != request->msg_ses_feats) {
			CNETERR("Features of framework RPC don't match features of current session: %x/%x\n",
				request->msg_ses_feats, sn->sn_features);
			reply->msg_body.reply.status = EPROTO;
			reply->msg_body.reply.sid.ses_stamp = sn->sn_id.ses_stamp;
			reply->msg_body.reply.sid.ses_nid =
				lnet_nid_to_nid4(&sn->sn_id.ses_nid);
			goto out;
		}

	} else if ((request->msg_ses_feats & ~LST_FEATS_MASK) != 0) {
		/* NB: at this point, old version will ignore features and
		 * create new session anyway, so console should be able
		 * to handle this */
		reply->msg_body.reply.status = EPROTO;
		goto out;
	}

	switch (sv->sv_id) {
	case SRPC_SERVICE_TEST:
		rc = sfw_add_test(rpc);
		break;

	case SRPC_SERVICE_BATCH:
		rc = sfw_control_batch(&request->msg_body.bat_reqst,
				       &reply->msg_body.bat_reply);
		break;

	case SRPC_SERVICE_QUERY_STAT:
		rc = sfw_get_stats(&request->msg_body.stat_reqst,
				   &reply->msg_body.stat_reply);
		break;

	case SRPC_SERVICE_DEBUG:
		rc = sfw_debug_session(&request->msg_body.dbg_reqst,
				       &reply->msg_body.dbg_reply);
		break;

	case SRPC_SERVICE_MAKE_SESSION:
		rc = sfw_make_session(&request->msg_body.mksn_reqst,
				      &reply->msg_body.mksn_reply);
		break;

	case SRPC_SERVICE_REMOVE_SESSION:
		rc = sfw_remove_session(&request->msg_body.rmsn_reqst,
					&reply->msg_body.rmsn_reply);
		break;
	default:
		LASSERTF(0, "sv_id bad %u\n", sv->sv_id);
	}

	if (sfw_data.fw_session != NULL)
		features = sfw_data.fw_session->sn_features;
 out:
	reply->msg_ses_feats = features;
	rpc->srpc_done = sfw_server_rpc_done;
	spin_lock(&sfw_data.fw_lock);

	if (!sfw_data.fw_shuttingdown)
		sfw_add_session_timer();

	sfw_data.fw_active_srpc = NULL;
	spin_unlock(&sfw_data.fw_lock);
	return rc;
}

static int
sfw_bulk_ready(struct srpc_server_rpc *rpc, int status)
{
	struct srpc_service	*sv = rpc->srpc_scd->scd_svc;
	int			rc;

	LASSERT(rpc->srpc_bulk != NULL);
	LASSERT(sv->sv_id == SRPC_SERVICE_TEST);
	LASSERT(sfw_data.fw_active_srpc == NULL);
	LASSERT(rpc->srpc_reqstbuf->buf_msg.msg_body.tes_reqst.tsr_is_client);

	spin_lock(&sfw_data.fw_lock);

	if (status != 0) {
		CERROR("Bulk transfer failed for RPC: service %s, peer %s, status %d: rc = %d\n",
		       sv->sv_name, libcfs_id2str(rpc->srpc_peer), status, -EIO);
		spin_unlock(&sfw_data.fw_lock);
		return -EIO;
	}

	if (sfw_data.fw_shuttingdown) {
		spin_unlock(&sfw_data.fw_lock);
		return -ESHUTDOWN;
	}

	if (sfw_del_session_timer() != 0) {
		CERROR("dropping RPC %s from %s: racing with expiry timer: rc = %d\n",
		       sv->sv_name, libcfs_id2str(rpc->srpc_peer), -EAGAIN);
		spin_unlock(&sfw_data.fw_lock);
		return -EAGAIN;
	}

	sfw_data.fw_active_srpc = rpc;
	spin_unlock(&sfw_data.fw_lock);

	rc = sfw_add_test(rpc);

	spin_lock(&sfw_data.fw_lock);

	if (!sfw_data.fw_shuttingdown)
		sfw_add_session_timer();

	sfw_data.fw_active_srpc = NULL;
	spin_unlock(&sfw_data.fw_lock);
	return rc;
}

struct srpc_client_rpc *
sfw_create_rpc(struct lnet_process_id peer, int service,
	       unsigned features, int nbulkiov, int bulklen,
	       void (*done)(struct srpc_client_rpc *), void *priv)
{
	struct srpc_client_rpc *rpc = NULL;

	spin_lock(&sfw_data.fw_lock);

	LASSERT(!sfw_data.fw_shuttingdown);
	LASSERT(service <= SRPC_FRAMEWORK_SERVICE_MAX_ID);

	if (nbulkiov == 0 && !list_empty(&sfw_data.fw_zombie_rpcs)) {
		rpc = list_first_entry(&sfw_data.fw_zombie_rpcs,
				       struct srpc_client_rpc, crpc_list);
		list_del(&rpc->crpc_list);
	}
	spin_unlock(&sfw_data.fw_lock);

	if (rpc) {
		/* Ensure that rpc is done */
		swi_cancel_workitem(&rpc->crpc_wi);
		srpc_init_client_rpc(rpc, peer, service, 0, 0,
				     done, sfw_client_rpc_fini, priv);
	} else {
		rpc = srpc_create_client_rpc(peer, service,
					     nbulkiov, bulklen, done,
					     nbulkiov != 0 ?  NULL :
					     sfw_client_rpc_fini,
					     priv);
	}

	if (rpc != NULL) /* "session" is concept in framework */
		rpc->crpc_reqstmsg.msg_ses_feats = features;

	return rpc;
}

void
sfw_unpack_message(struct srpc_msg *msg)
{
	if (msg->msg_magic == SRPC_MSG_MAGIC)
		return; /* no flipping needed */

	/* srpc module should guarantee I wouldn't get crap */
	LASSERT(msg->msg_magic == __swab32(SRPC_MSG_MAGIC));

	if (msg->msg_type == SRPC_MSG_STAT_REQST) {
		struct srpc_stat_reqst *req = &msg->msg_body.stat_reqst;

		__swab32s(&req->str_type);
		__swab64s(&req->str_rpyid);
		sfw_unpack_sid(req->str_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_STAT_REPLY) {
		struct srpc_stat_reply *rep = &msg->msg_body.stat_reply;

		__swab32s(&rep->str_status);
		sfw_unpack_sid(rep->str_sid);
		sfw_unpack_fw_counters(rep->str_fw);
		sfw_unpack_rpc_counters(rep->str_rpc);
		sfw_unpack_lnet_counters(rep->str_lnet);
		return;
	}

	if (msg->msg_type == SRPC_MSG_MKSN_REQST) {
		struct srpc_mksn_reqst *req = &msg->msg_body.mksn_reqst;

		__swab64s(&req->mksn_rpyid);
		__swab32s(&req->mksn_force);
		sfw_unpack_sid(req->mksn_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_MKSN_REPLY) {
		struct srpc_mksn_reply *rep = &msg->msg_body.mksn_reply;

		__swab32s(&rep->mksn_status);
		__swab32s(&rep->mksn_timeout);
		sfw_unpack_sid(rep->mksn_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_RMSN_REQST) {
		struct srpc_rmsn_reqst *req = &msg->msg_body.rmsn_reqst;

		__swab64s(&req->rmsn_rpyid);
		sfw_unpack_sid(req->rmsn_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_RMSN_REPLY) {
		struct srpc_rmsn_reply *rep = &msg->msg_body.rmsn_reply;

		__swab32s(&rep->rmsn_status);
		sfw_unpack_sid(rep->rmsn_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_DEBUG_REQST) {
		struct srpc_debug_reqst *req = &msg->msg_body.dbg_reqst;

		__swab64s(&req->dbg_rpyid);
		__swab32s(&req->dbg_flags);
		sfw_unpack_sid(req->dbg_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_DEBUG_REPLY) {
		struct srpc_debug_reply *rep = &msg->msg_body.dbg_reply;

		__swab32s(&rep->dbg_nbatch);
		__swab32s(&rep->dbg_timeout);
		sfw_unpack_sid(rep->dbg_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_BATCH_REQST) {
		struct srpc_batch_reqst *req = &msg->msg_body.bat_reqst;

		__swab32s(&req->bar_opc);
		__swab64s(&req->bar_rpyid);
		__swab32s(&req->bar_testidx);
		__swab32s(&req->bar_arg);
		sfw_unpack_sid(req->bar_sid);
		__swab64s(&req->bar_bid.bat_id);
		return;
	}

	if (msg->msg_type == SRPC_MSG_BATCH_REPLY) {
		struct srpc_batch_reply *rep = &msg->msg_body.bat_reply;

		__swab32s(&rep->bar_status);
		sfw_unpack_sid(rep->bar_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_TEST_REQST) {
		struct srpc_test_reqst *req = &msg->msg_body.tes_reqst;

		__swab64s(&req->tsr_rpyid);
		__swab64s(&req->tsr_bulkid);
		__swab32s(&req->tsr_loop);
		__swab32s(&req->tsr_ndest);
		__swab32s(&req->tsr_concur);
		__swab32s(&req->tsr_service);
		sfw_unpack_sid(req->tsr_sid);
		__swab64s(&req->tsr_bid.bat_id);
		return;
	}

	if (msg->msg_type == SRPC_MSG_TEST_REPLY) {
		struct srpc_test_reply *rep = &msg->msg_body.tes_reply;

		__swab32s(&rep->tsr_status);
		sfw_unpack_sid(rep->tsr_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_JOIN_REQST) {
		struct srpc_join_reqst *req = &msg->msg_body.join_reqst;

		__swab64s(&req->join_rpyid);
		sfw_unpack_sid(req->join_sid);
		return;
	}

	if (msg->msg_type == SRPC_MSG_JOIN_REPLY) {
		struct srpc_join_reply *rep = &msg->msg_body.join_reply;

		__swab32s(&rep->join_status);
		__swab32s(&rep->join_timeout);
		sfw_unpack_sid(rep->join_sid);
		return;
	}

	LBUG();
}

void
sfw_abort_rpc(struct srpc_client_rpc *rpc)
{
	LASSERT(rpc->crpc_service <= SRPC_FRAMEWORK_SERVICE_MAX_ID);

	spin_lock(&rpc->crpc_lock);
	srpc_abort_rpc(rpc, -EINTR);
	spin_unlock(&rpc->crpc_lock);
}

void
sfw_post_rpc(struct srpc_client_rpc *rpc)
{
	spin_lock(&rpc->crpc_lock);

	LASSERT(!rpc->crpc_closed);
	LASSERT(!rpc->crpc_aborted);
	LASSERT(list_empty(&rpc->crpc_list));
	LASSERT(!sfw_data.fw_shuttingdown);

	rpc->crpc_timeout = rpc_timeout;
	srpc_post_rpc(rpc);

	spin_unlock(&rpc->crpc_lock);
}

#if 0
static struct srpc_service sfw_services[] = {
	{ .sv_id = SRPC_SERVICE_DEBUG,		.sv_name = "debug", },
	{ .sv_id = SRPC_SERVICE_QUERY_STAT,	.sv_name = "query stats", },
	{ .sv_id = SRPC_SERVICE_MAKE_SESSION,	.sv_name = "make session", },
	{ .sv_id = SRPC_SERVICE_REMOVE_SESSION,	.sv_name = "remove session", },
	{ .sv_id = SRPC_SERVICE_BATCH,		.sv_name = "batch service", },
	{ .sv_id = SRPC_SERVICE_TEST,		.sv_name = "test service", },
	{ .sv_id = 0, } };
#endif

int
sfw_startup(void)
{
	struct srpc_service *sv;
	struct sfw_test_case *tsc;
	int i, rc, error;

	if (session_timeout < 0) {
		CERROR("Session timeout must be non-negative: %d: rc = %d\n",
		       session_timeout, -EINVAL);
		return -EINVAL;
	}

	if (rpc_timeout < 0) {
		CERROR("RPC timeout must be non-negative: %d: rc = %d\n",
		       rpc_timeout, -EINVAL);
		return -EINVAL;
	}

	if (session_timeout == 0)
		CWARN("Zero session_timeout specified - test sessions never expire.\n");

	if (rpc_timeout == 0)
		CWARN("Zero rpc_timeout specified - test RPC never expire.\n");

	memset(&sfw_data, 0, sizeof(struct smoketest_framework));

	sfw_data.fw_session     = NULL;
	sfw_data.fw_active_srpc = NULL;
	spin_lock_init(&sfw_data.fw_lock);
	atomic_set(&sfw_data.fw_nzombies, 0);
	INIT_LIST_HEAD(&sfw_data.fw_tests);
	INIT_LIST_HEAD(&sfw_data.fw_zombie_rpcs);
	INIT_LIST_HEAD(&sfw_data.fw_zombie_sessions);

	brw_init_test_service();
	rc = sfw_register_test(&brw_test_service, &brw_test_client);
	LASSERT(rc == 0);

	ping_init_test_client();
	ping_init_test_service();
	rc = sfw_register_test(&ping_test_service, &ping_test_client);
	LASSERT(rc == 0);

	error = 0;
	list_for_each_entry(tsc, &sfw_data.fw_tests, tsc_list) {
		sv = tsc->tsc_srv_service;

		rc = srpc_add_service(sv);
		LASSERT(rc != -EBUSY);
		if (rc != 0) {
			CWARN("Failed to add %s service: %d\n",
			      sv->sv_name, rc);
			error = rc;
		}
	}

	for (i = 0; ; i++) {
		sv = &sfw_services[i];
		if (sv->sv_name == NULL)
			break;

		sv->sv_bulk_ready = NULL;
		sv->sv_handler    = sfw_handle_server_rpc;
		sv->sv_wi_total   = SFW_FRWK_WI_MAX;
		if (sv->sv_id == SRPC_SERVICE_TEST)
			sv->sv_bulk_ready = sfw_bulk_ready;

		rc = srpc_add_service(sv);
		LASSERT(rc != -EBUSY);
		if (rc != 0) {
			CWARN("Failed to add %s service: %d\n", sv->sv_name,
			      rc);
			error = rc;
		}

		/* about to sfw_shutdown, no need to add buffer */
		if (error)
			continue;

		rc = srpc_service_add_buffers(sv, sv->sv_wi_total);
		if (rc != 0) {
			CWARN("Failed to reserve enough buffers: service %s, %d needed: %d\n",
			      sv->sv_name, sv->sv_wi_total, rc);
			error = -ENOMEM;
		}
	}

	if (error != 0)
		sfw_shutdown();
	return error;
}

void
sfw_shutdown(void)
{
	struct srpc_service *sv;
	struct sfw_test_case *tsc;
	int i;

	spin_lock(&sfw_data.fw_lock);

	sfw_data.fw_shuttingdown = 1;
	lst_wait_until(sfw_data.fw_active_srpc == NULL, sfw_data.fw_lock,
		       "waiting for active RPC to finish.\n");

	if (sfw_del_session_timer() != 0)
		lst_wait_until(sfw_data.fw_session == NULL, sfw_data.fw_lock,
			       "waiting for session timer to explode.\n");

	sfw_deactivate_session();
	lst_wait_until(atomic_read(&sfw_data.fw_nzombies) == 0,
		       sfw_data.fw_lock,
		       "waiting for %d zombie sessions to die.\n",
		       atomic_read(&sfw_data.fw_nzombies));

	spin_unlock(&sfw_data.fw_lock);

	for (i = 0; ; i++) {
		sv = &sfw_services[i];
		if (sv->sv_name == NULL)
			break;

		srpc_shutdown_service(sv);
		srpc_remove_service(sv);
	}

	list_for_each_entry(tsc, &sfw_data.fw_tests, tsc_list) {
		sv = tsc->tsc_srv_service;
		srpc_shutdown_service(sv);
		srpc_remove_service(sv);
	}

	while (!list_empty(&sfw_data.fw_zombie_rpcs)) {
		struct srpc_client_rpc *rpc;

		rpc = list_first_entry(&sfw_data.fw_zombie_rpcs,
				       struct srpc_client_rpc, crpc_list);
		list_del(&rpc->crpc_list);

		LIBCFS_FREE(rpc, srpc_client_rpc_size(rpc));
	}

	for (i = 0; ; i++) {
		sv = &sfw_services[i];
		if (sv->sv_name == NULL)
			break;

		srpc_wait_service_shutdown(sv);
	}

	while (!list_empty(&sfw_data.fw_tests)) {
		tsc = list_first_entry(&sfw_data.fw_tests,
				       struct sfw_test_case, tsc_list);

		srpc_wait_service_shutdown(tsc->tsc_srv_service);

		list_del(&tsc->tsc_list);
		LIBCFS_FREE(tsc, sizeof(*tsc));
	}
}
