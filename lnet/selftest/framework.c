/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/selftest/framework.c
 *
 * Author: Isaac Huang <isaac@clusterfs.com>
 * Author: Liang Zhen  <liangzhen@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include "selftest.h"

int brw_inject_errors = 0;
CFS_MODULE_PARM(brw_inject_errors, "i", int, 0644,
                "# data errors to inject randomly, zero by default");

static int session_timeout = 100;
CFS_MODULE_PARM(session_timeout, "i", int, 0444,
                "test session timeout in seconds (100 by default, 0 == never)");

#define SFW_TEST_CONCURRENCY     128
#define SFW_TEST_RPC_TIMEOUT     64
#define SFW_CLIENT_RPC_TIMEOUT   64  /* in seconds */
#define SFW_EXTRA_TEST_BUFFERS   8 /* tolerate buggy peers with extra buffers */

#define sfw_test_buffers(tsi)    ((tsi)->tsi_loop + SFW_EXTRA_TEST_BUFFERS)

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
        __swab32s(&(fc).brw_errors);      \
        __swab32s(&(fc).ping_errors);     \
        __swab32s(&(fc).active_tests);    \
        __swab32s(&(fc).active_batches);  \
        __swab32s(&(fc).zombie_sessions); \
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
        __swab32s(&(lc).errors);        \
        __swab32s(&(lc).msgs_max);      \
        __swab32s(&(lc).msgs_alloc);    \
        __swab32s(&(lc).send_count);    \
        __swab32s(&(lc).recv_count);    \
        __swab32s(&(lc).drop_count);    \
        __swab32s(&(lc).route_count);   \
        __swab64s(&(lc).send_length);   \
        __swab64s(&(lc).recv_length);   \
        __swab64s(&(lc).drop_length);   \
        __swab64s(&(lc).route_length);  \
} while (0)

#define sfw_test_active(t)      (atomic_read(&(t)->tsi_nactive) != 0)
#define sfw_batch_active(b)     (atomic_read(&(b)->bat_nactive) != 0)

struct smoketest_framework {
        struct list_head   fw_zombie_rpcs;     /* RPCs to be recycled */
        struct list_head   fw_zombie_sessions; /* stopping sessions */
        struct list_head   fw_tests;           /* registered test cases */
        atomic_t           fw_nzombies;        /* # zombie sessions */
        spinlock_t         fw_lock;            /* serialise */
        sfw_session_t     *fw_session;         /* _the_ session */
        int                fw_shuttingdown;    /* shutdown in progress */
        srpc_server_rpc_t *fw_active_srpc;     /* running RPC */
} sfw_data;

/* forward ref's */
int sfw_stop_batch (sfw_batch_t *tsb, int force);
void sfw_destroy_session (sfw_session_t *sn);

static inline sfw_test_case_t *
sfw_find_test_case(int id)
{
        sfw_test_case_t *tsc;

        LASSERT (id <= SRPC_SERVICE_MAX_ID);
        LASSERT (id > SRPC_FRAMEWORK_SERVICE_MAX_ID);

        list_for_each_entry (tsc, &sfw_data.fw_tests, tsc_list) {
                if (tsc->tsc_srv_service->sv_id == id)
                        return tsc;
        }

        return NULL;
}

static int
sfw_register_test (srpc_service_t *service, sfw_test_client_ops_t *cliops)
{
        sfw_test_case_t *tsc;

        if (sfw_find_test_case(service->sv_id) != NULL) {
                CERROR ("Failed to register test %s (%d)\n",
                        service->sv_name, service->sv_id);
                return -EEXIST;
        }

        LIBCFS_ALLOC(tsc, sizeof(sfw_test_case_t));
        if (tsc == NULL)
                return -ENOMEM;

        memset(tsc, 0, sizeof(sfw_test_case_t));
        tsc->tsc_cli_ops     = cliops;
        tsc->tsc_srv_service = service;

        list_add_tail(&tsc->tsc_list, &sfw_data.fw_tests);
        return 0;
}

void
sfw_add_session_timer (void)
{
        sfw_session_t *sn = sfw_data.fw_session;
        stt_timer_t   *timer = &sn->sn_timer;

        LASSERT (!sfw_data.fw_shuttingdown);

        if (sn == NULL || sn->sn_timeout == 0)
                return;

        LASSERT (!sn->sn_timer_active);

        sn->sn_timer_active = 1;
        timer->stt_expires = cfs_time_add(sn->sn_timeout,
                                          cfs_time_current_sec());
        stt_add_timer(timer);
        return;
}

int
sfw_del_session_timer (void)
{
        sfw_session_t *sn = sfw_data.fw_session;

        if (sn == NULL || !sn->sn_timer_active)
                return 0;

        LASSERT (sn->sn_timeout != 0);

        if (stt_del_timer(&sn->sn_timer)) { /* timer defused */
                sn->sn_timer_active = 0;
                return 0;
        }

#ifndef __KERNEL__
        /* Racing is impossible in single-threaded userland selftest */
        LBUG();
#endif
        return EBUSY; /* racing with sfw_session_expired() */
}

/* called with sfw_data.fw_lock held */
static void
sfw_deactivate_session (void)
{
        sfw_session_t *sn = sfw_data.fw_session;
        int            nactive = 0;
        sfw_batch_t   *tsb;

        if (sn == NULL) return;

        LASSERT (!sn->sn_timer_active);

        sfw_data.fw_session = NULL;
        atomic_inc(&sfw_data.fw_nzombies);
        list_add(&sn->sn_list, &sfw_data.fw_zombie_sessions);

        list_for_each_entry (tsb, &sn->sn_batches, bat_list) {
                if (sfw_batch_active(tsb)) {
                        nactive++;
                        sfw_stop_batch(tsb, 1);
                }
        }

        if (nactive != 0)
                return;   /* wait for active batches to stop */

        list_del_init(&sn->sn_list);
        spin_unlock(&sfw_data.fw_lock);

        sfw_destroy_session(sn);

        spin_lock(&sfw_data.fw_lock);
        return;
}

#ifndef __KERNEL__

int
sfw_session_removed (void)
{
        return (sfw_data.fw_session == NULL) ? 1 : 0;
}

#endif

void
sfw_session_expired (void *data)
{
        sfw_session_t *sn = data;

        spin_lock(&sfw_data.fw_lock);

        LASSERT (sn->sn_timer_active);
        LASSERT (sn == sfw_data.fw_session);

        CWARN ("Session expired! sid: %s-"LPU64", name: %s\n",
               libcfs_nid2str(sn->sn_id.ses_nid),
               sn->sn_id.ses_stamp, &sn->sn_name[0]);

        sn->sn_timer_active = 0;
        sfw_deactivate_session();

        spin_unlock(&sfw_data.fw_lock);
        return;
}

static inline void
sfw_init_session (sfw_session_t *sn, lst_sid_t sid, const char *name)
{
        stt_timer_t *timer = &sn->sn_timer;

        memset(sn, 0, sizeof(sfw_session_t));
        CFS_INIT_LIST_HEAD(&sn->sn_list);
        CFS_INIT_LIST_HEAD(&sn->sn_batches);
        atomic_set(&sn->sn_brw_errors, 0);
        atomic_set(&sn->sn_ping_errors, 0);
        strncpy(&sn->sn_name[0], name, LST_NAME_SIZE);

        sn->sn_timer_active = 0;
        sn->sn_id           = sid;
        sn->sn_timeout      = session_timeout;

        timer->stt_data = sn;
        timer->stt_func = sfw_session_expired;
        CFS_INIT_LIST_HEAD(&timer->stt_list);
}

/* completion handler for incoming framework RPCs */
void
sfw_server_rpc_done (srpc_server_rpc_t *rpc)
{
        srpc_service_t *sv = rpc->srpc_service;
        int             status = rpc->srpc_status;

        CDEBUG (D_NET,
                "Incoming framework RPC done: "
                "service %s, peer %s, status %s:%d\n",
                sv->sv_name, libcfs_id2str(rpc->srpc_peer),
                swi_state2str(rpc->srpc_wi.wi_state),
                status);

        if (rpc->srpc_bulk != NULL)
                sfw_free_pages(rpc);
        return;
}

void
sfw_client_rpc_fini (srpc_client_rpc_t *rpc)
{
        LASSERT (rpc->crpc_bulk.bk_niov == 0);
        LASSERT (list_empty(&rpc->crpc_list));
        LASSERT (atomic_read(&rpc->crpc_refcount) == 0);
#ifndef __KERNEL__
        LASSERT (rpc->crpc_bulk.bk_pages == NULL);
#endif

        CDEBUG (D_NET,
                "Outgoing framework RPC done: "
                "service %d, peer %s, status %s:%d:%d\n",
                rpc->crpc_service, libcfs_id2str(rpc->crpc_dest),
                swi_state2str(rpc->crpc_wi.wi_state),
                rpc->crpc_aborted, rpc->crpc_status);

        spin_lock(&sfw_data.fw_lock);

        /* my callers must finish all RPCs before shutting me down */
        LASSERT (!sfw_data.fw_shuttingdown);
        list_add(&rpc->crpc_list, &sfw_data.fw_zombie_rpcs);

        spin_unlock(&sfw_data.fw_lock);
        return;
}

sfw_batch_t *
sfw_find_batch (lst_bid_t bid)
{
        sfw_session_t *sn = sfw_data.fw_session;
        sfw_batch_t   *bat;

        LASSERT (sn != NULL);

        list_for_each_entry (bat, &sn->sn_batches, bat_list) {
                if (bat->bat_id.bat_id == bid.bat_id)
                        return bat;
        }

        return NULL;
}

sfw_batch_t *
sfw_bid2batch (lst_bid_t bid)
{
        sfw_session_t *sn = sfw_data.fw_session;
        sfw_batch_t   *bat;

        LASSERT (sn != NULL);

        bat = sfw_find_batch(bid);
        if (bat != NULL)
                return bat;

        LIBCFS_ALLOC(bat, sizeof(sfw_batch_t));
        if (bat == NULL) 
                return NULL;

        bat->bat_error    = 0;
        bat->bat_session  = sn;
        bat->bat_id       = bid;
        atomic_set(&bat->bat_nactive, 0);
        CFS_INIT_LIST_HEAD(&bat->bat_tests);

        list_add_tail(&bat->bat_list, &sn->sn_batches);
        return bat;
}

int
sfw_get_stats (srpc_stat_reqst_t *request, srpc_stat_reply_t *reply)
{
        sfw_session_t  *sn = sfw_data.fw_session;
        sfw_counters_t *cnt = &reply->str_fw;
        sfw_batch_t    *bat;

        reply->str_sid = (sn == NULL) ? LST_INVALID_SID : sn->sn_id;

        if (request->str_sid.ses_nid == LNET_NID_ANY) {
                reply->str_status = EINVAL;
                return 0;
        }

        if (sn == NULL || !sfw_sid_equal(request->str_sid, sn->sn_id)) {
                reply->str_status = ESRCH;
                return 0;
        }

        LNET_LOCK();
        reply->str_lnet = the_lnet.ln_counters;
        LNET_UNLOCK();

        srpc_get_counters(&reply->str_rpc);

        cnt->brw_errors      = atomic_read(&sn->sn_brw_errors);
        cnt->ping_errors     = atomic_read(&sn->sn_ping_errors);
        cnt->zombie_sessions = atomic_read(&sfw_data.fw_nzombies);

        cnt->active_tests = cnt->active_batches = 0;
        list_for_each_entry (bat, &sn->sn_batches, bat_list) {
                int n = atomic_read(&bat->bat_nactive);

                if (n > 0) {
                        cnt->active_batches++;
                        cnt->active_tests += n;
                }
        }

        reply->str_status = 0;
        return 0;
}

int
sfw_make_session (srpc_mksn_reqst_t *request, srpc_mksn_reply_t *reply)
{
        sfw_session_t *sn = sfw_data.fw_session;

        if (request->mksn_sid.ses_nid == LNET_NID_ANY) {
                reply->mksn_sid = (sn == NULL) ? LST_INVALID_SID : sn->sn_id;
                reply->mksn_status = EINVAL;
                return 0;
        }

        if (sn != NULL && !request->mksn_force) {
                reply->mksn_sid    = sn->sn_id;
                reply->mksn_status = EBUSY;
                strncpy(&reply->mksn_name[0], &sn->sn_name[0], LST_NAME_SIZE);
                return 0;
        }
        
        LIBCFS_ALLOC(sn, sizeof(sfw_session_t));
        if (sn == NULL) {
                CERROR ("Dropping RPC (mksn) under memory pressure.\n");
                return -ENOMEM;
        }

        sfw_init_session(sn, request->mksn_sid, &request->mksn_name[0]);

        spin_lock(&sfw_data.fw_lock);

        sfw_deactivate_session();
        LASSERT (sfw_data.fw_session == NULL);
        sfw_data.fw_session = sn;

        spin_unlock(&sfw_data.fw_lock);

        reply->mksn_status  = 0;
        reply->mksn_sid     = sn->sn_id;
        reply->mksn_timeout = sn->sn_timeout;
        return 0;
}

int
sfw_remove_session (srpc_rmsn_reqst_t *request, srpc_rmsn_reply_t *reply)
{
        sfw_session_t *sn = sfw_data.fw_session;

        reply->rmsn_sid = (sn == NULL) ? LST_INVALID_SID : sn->sn_id;

        if (request->rmsn_sid.ses_nid == LNET_NID_ANY) {
                reply->rmsn_status = EINVAL;
                return 0;
        }

        if (sn == NULL || !sfw_sid_equal(request->rmsn_sid, sn->sn_id)) {
                reply->rmsn_status = (sn == NULL) ? ESRCH : EBUSY;
                return 0;
        }

        spin_lock(&sfw_data.fw_lock);
        sfw_deactivate_session();
        spin_unlock(&sfw_data.fw_lock);

        reply->rmsn_status = 0;
        reply->rmsn_sid    = LST_INVALID_SID;
        LASSERT (sfw_data.fw_session == NULL);
        return 0;
}

int
sfw_debug_session (srpc_debug_reqst_t *request, srpc_debug_reply_t *reply)
{
        sfw_session_t *sn = sfw_data.fw_session;

        if (sn == NULL) {
                reply->dbg_status = ESRCH;
                reply->dbg_sid    = LST_INVALID_SID;
                return 0;
        } 

        reply->dbg_status  = 0;
        reply->dbg_sid     = sn->sn_id;      
        reply->dbg_timeout = sn->sn_timeout;
        strncpy(reply->dbg_name, &sn->sn_name[0], LST_NAME_SIZE);

        return 0;
}

void
sfw_test_rpc_fini (srpc_client_rpc_t *rpc)
{
        sfw_test_unit_t     *tsu = rpc->crpc_priv;
        sfw_test_instance_t *tsi = tsu->tsu_instance;

        /* Called with hold of tsi->tsi_lock */
        LASSERT (list_empty(&rpc->crpc_list));
        list_add(&rpc->crpc_list, &tsi->tsi_free_rpcs);
}

int
sfw_load_test (sfw_test_instance_t *tsi)
{
        sfw_test_case_t *tsc = sfw_find_test_case(tsi->tsi_service);
        int              nrequired = sfw_test_buffers(tsi);
        int              nposted;

        LASSERT (tsc != NULL);

        if (tsi->tsi_is_client) {
                tsi->tsi_ops = tsc->tsc_cli_ops;
                return 0;
        }

        nposted = srpc_service_add_buffers(tsc->tsc_srv_service, nrequired);
        if (nposted != nrequired) {
                CWARN ("Failed to reserve enough buffers: "
                       "service %s, %d needed, %d reserved\n",
                       tsc->tsc_srv_service->sv_name, nrequired, nposted);
                srpc_service_remove_buffers(tsc->tsc_srv_service, nposted);
                return -ENOMEM;
        }

        CDEBUG (D_NET, "Reserved %d buffers for test %s\n",
                nposted, tsc->tsc_srv_service->sv_name);
        return 0;
}

void
sfw_unload_test (sfw_test_instance_t *tsi)
{
        sfw_test_case_t *tsc = sfw_find_test_case(tsi->tsi_service);

        LASSERT (tsc != NULL);

        if (!tsi->tsi_is_client)
                srpc_service_remove_buffers(tsc->tsc_srv_service,
                                            sfw_test_buffers(tsi));
        return;
}

void
sfw_destroy_test_instance (sfw_test_instance_t *tsi)
{
        srpc_client_rpc_t *rpc;
        sfw_test_unit_t   *tsu;

        if (!tsi->tsi_is_client) goto clean;

        tsi->tsi_ops->tso_fini(tsi);

        LASSERT (!tsi->tsi_stopping);
        LASSERT (list_empty(&tsi->tsi_active_rpcs));
        LASSERT (!sfw_test_active(tsi));

        while (!list_empty(&tsi->tsi_units)) {
                tsu = list_entry(tsi->tsi_units.next,
                                 sfw_test_unit_t, tsu_list);
                list_del(&tsu->tsu_list);
                LIBCFS_FREE(tsu, sizeof(*tsu));
        }

        while (!list_empty(&tsi->tsi_free_rpcs)) {
                rpc = list_entry(tsi->tsi_free_rpcs.next,
                                 srpc_client_rpc_t, crpc_list);
                list_del(&rpc->crpc_list);
                LIBCFS_FREE(rpc, srpc_client_rpc_size(rpc));
        }

clean:
        sfw_unload_test(tsi);
        LIBCFS_FREE(tsi, sizeof(*tsi));
        return;
}

void
sfw_destroy_batch (sfw_batch_t *tsb)
{
        sfw_test_instance_t *tsi;

        LASSERT (!sfw_batch_active(tsb));
        LASSERT (list_empty(&tsb->bat_list));

        while (!list_empty(&tsb->bat_tests)) {
                tsi = list_entry(tsb->bat_tests.next,
                                 sfw_test_instance_t, tsi_list);
                list_del_init(&tsi->tsi_list);
                sfw_destroy_test_instance(tsi);
        }

        LIBCFS_FREE(tsb, sizeof(sfw_batch_t));
        return;
}

void
sfw_destroy_session (sfw_session_t *sn)
{
        sfw_batch_t *batch;

        LASSERT (list_empty(&sn->sn_list));
        LASSERT (sn != sfw_data.fw_session);

        while (!list_empty(&sn->sn_batches)) {
                batch = list_entry(sn->sn_batches.next,
                                   sfw_batch_t, bat_list);
                list_del_init(&batch->bat_list);
                sfw_destroy_batch(batch);
        }

        LIBCFS_FREE(sn, sizeof(*sn));
        atomic_dec(&sfw_data.fw_nzombies);
        return;
}

void
sfw_unpack_test_req (srpc_msg_t *msg)
{
        srpc_test_reqst_t *req = &msg->msg_body.tes_reqst;

        LASSERT (msg->msg_type == SRPC_MSG_TEST_REQST);
        LASSERT (req->tsr_is_client);

        if (msg->msg_magic == SRPC_MSG_MAGIC)
                return; /* no flipping needed */

        LASSERT (msg->msg_magic == __swab32(SRPC_MSG_MAGIC));

        if (req->tsr_service == SRPC_SERVICE_BRW) {
                test_bulk_req_t *bulk = &req->tsr_u.bulk;

                __swab32s(&bulk->blk_opc);
                __swab32s(&bulk->blk_npg);
                __swab32s(&bulk->blk_flags);
                return;
        }

        if (req->tsr_service == SRPC_SERVICE_PING) {
                test_ping_req_t *ping = &req->tsr_u.ping;

                __swab32s(&ping->png_size);
                __swab32s(&ping->png_flags);
                return;
        }

        LBUG ();
        return;
}

int
sfw_add_test_instance (sfw_batch_t *tsb, srpc_server_rpc_t *rpc)
{
        srpc_msg_t          *msg = &rpc->srpc_reqstbuf->buf_msg;
        srpc_test_reqst_t   *req = &msg->msg_body.tes_reqst;
        srpc_bulk_t         *bk = rpc->srpc_bulk;
        int                  ndest = req->tsr_ndest;
        sfw_test_unit_t     *tsu;
        sfw_test_instance_t *tsi;
        int                  i;
        int                  rc;

        LIBCFS_ALLOC(tsi, sizeof(*tsi));
        if (tsi == NULL) {
                CERROR ("Can't allocate test instance for batch: "LPU64"\n",
                        tsb->bat_id.bat_id);
                return -ENOMEM;
        }

        memset(tsi, 0, sizeof(*tsi));
        spin_lock_init(&tsi->tsi_lock);
        atomic_set(&tsi->tsi_nactive, 0);
        CFS_INIT_LIST_HEAD(&tsi->tsi_units);
        CFS_INIT_LIST_HEAD(&tsi->tsi_free_rpcs);
        CFS_INIT_LIST_HEAD(&tsi->tsi_active_rpcs);

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

        LASSERT (!sfw_batch_active(tsb));

        if (!tsi->tsi_is_client) {
                /* it's test server, just add it to tsb */
                list_add_tail(&tsi->tsi_list, &tsb->bat_tests);
                return 0;
        }

        LASSERT (bk != NULL);
#ifndef __KERNEL__
        LASSERT (bk->bk_pages != NULL);
#endif
        LASSERT (bk->bk_niov * SFW_ID_PER_PAGE >= ndest);
        LASSERT (bk->bk_len >= sizeof(lnet_process_id_t) * ndest);

        sfw_unpack_test_req(msg);
        memcpy(&tsi->tsi_u, &req->tsr_u, sizeof(tsi->tsi_u));

        for (i = 0; i < ndest; i++) {
                lnet_process_id_t *dests;
                lnet_process_id_t  id;
                int                j;

#ifdef __KERNEL__
                dests = cfs_page_address(bk->bk_iovs[i / SFW_ID_PER_PAGE].kiov_page);
                LASSERT (dests != NULL);  /* my pages are within KVM always */
#else
                dests = cfs_page_address(bk->bk_pages[i / SFW_ID_PER_PAGE]);
#endif
                id = dests[i % SFW_ID_PER_PAGE];
                if (msg->msg_magic != SRPC_MSG_MAGIC)
                        sfw_unpack_id(id);

                for (j = 0; j < tsi->tsi_concur; j++) {
                        LIBCFS_ALLOC(tsu, sizeof(sfw_test_unit_t));
                        if (tsu == NULL) {
                                rc = -ENOMEM;
                                CERROR ("Can't allocate tsu for %d\n",
                                        tsi->tsi_service);
                                goto error;
                        }

                        tsu->tsu_dest     = id;
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
        LASSERT (rc != 0);
        sfw_destroy_test_instance(tsi);
        return rc;
}

static void
sfw_test_unit_done (sfw_test_unit_t *tsu)
{
        sfw_test_instance_t *tsi = tsu->tsu_instance;
        sfw_batch_t         *tsb = tsi->tsi_batch;
        sfw_session_t       *sn = tsb->bat_session;

        LASSERT (sfw_test_active(tsi));

        if (!atomic_dec_and_test(&tsi->tsi_nactive))
                return;
        
        /* the test instance is done */
        spin_lock(&tsi->tsi_lock);

        tsi->tsi_stopping = 0;

        spin_unlock(&tsi->tsi_lock);

        spin_lock(&sfw_data.fw_lock);

        if (!atomic_dec_and_test(&tsb->bat_nactive) || /* tsb still active */
            sn == sfw_data.fw_session) {               /* sn also active */
                spin_unlock(&sfw_data.fw_lock);
                return;
        }
        
        LASSERT (!list_empty(&sn->sn_list)); /* I'm a zombie! */

        list_for_each_entry (tsb, &sn->sn_batches, bat_list) {
                if (sfw_batch_active(tsb)) {
                        spin_unlock(&sfw_data.fw_lock);
                        return;
                }
        }

        list_del_init(&sn->sn_list);
        spin_unlock(&sfw_data.fw_lock);

        sfw_destroy_session(sn);
        return;
}

void
sfw_test_rpc_done (srpc_client_rpc_t *rpc)
{
        sfw_test_unit_t     *tsu = rpc->crpc_priv;
        sfw_test_instance_t *tsi = tsu->tsu_instance;
        int                  done = 0;

        tsi->tsi_ops->tso_done_rpc(tsu, rpc);
                      
        spin_lock(&tsi->tsi_lock);

        LASSERT (sfw_test_active(tsi));
        LASSERT (!list_empty(&rpc->crpc_list));

        list_del_init(&rpc->crpc_list);

        /* batch is stopping or loop is done or get error */
        if (tsi->tsi_stopping ||
            tsu->tsu_loop == 0 ||
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
        return;
}

int
sfw_create_test_rpc (sfw_test_unit_t *tsu, lnet_process_id_t peer,
                     int nblk, int blklen, srpc_client_rpc_t **rpcpp)
{
        srpc_client_rpc_t   *rpc = NULL;
        sfw_test_instance_t *tsi = tsu->tsu_instance;
        
        spin_lock(&tsi->tsi_lock);

        LASSERT (sfw_test_active(tsi));

        if (!list_empty(&tsi->tsi_free_rpcs)) {
                /* pick request from buffer */
                rpc = list_entry(tsi->tsi_free_rpcs.next,
                                 srpc_client_rpc_t, crpc_list);
                LASSERT (nblk == rpc->crpc_bulk.bk_niov);
                list_del_init(&rpc->crpc_list);

                srpc_init_client_rpc(rpc, peer, tsi->tsi_service, nblk,
                                     blklen, sfw_test_rpc_done,
                                     sfw_test_rpc_fini, tsu);
        }

        spin_unlock(&tsi->tsi_lock);
        
        if (rpc == NULL)
                rpc = srpc_create_client_rpc(peer, tsi->tsi_service, nblk,
                                             blklen, sfw_test_rpc_done, 
                                             sfw_test_rpc_fini, tsu);
        if (rpc == NULL) {
                CERROR ("Can't create rpc for test %d\n", tsi->tsi_service);
                return -ENOMEM;
        }

        *rpcpp = rpc;
        return 0;
}

int
sfw_run_test (swi_workitem_t *wi)
{
        sfw_test_unit_t     *tsu = wi->wi_data;
        sfw_test_instance_t *tsi = tsu->tsu_instance;
        srpc_client_rpc_t   *rpc = NULL;

        LASSERT (wi == &tsu->tsu_worker);

        if (tsi->tsi_ops->tso_prep_rpc(tsu, tsu->tsu_dest, &rpc) != 0) {
                LASSERT (rpc == NULL);
                goto test_done;
        }

        LASSERT (rpc != NULL);

        spin_lock(&tsi->tsi_lock);

        if (tsi->tsi_stopping) {
                list_add(&rpc->crpc_list, &tsi->tsi_free_rpcs);
                spin_unlock(&tsi->tsi_lock);
                goto test_done;
        }

        if (tsu->tsu_loop > 0)
                tsu->tsu_loop--;

        list_add_tail(&rpc->crpc_list, &tsi->tsi_active_rpcs);
        spin_unlock(&tsi->tsi_lock);

        rpc->crpc_timeout = SFW_TEST_RPC_TIMEOUT;

        spin_lock(&rpc->crpc_lock);
        srpc_post_rpc(rpc);
        spin_unlock(&rpc->crpc_lock);
        return 0;

test_done:
        /*
         * No one can schedule me now since:
         * - previous RPC, if any, has done and
         * - no new RPC is initiated.
         * - my batch is still active; no one can run it again now.
         * Cancel pending schedules and prevent future schedule attempts:
         */
        swi_kill_workitem(wi);
        sfw_test_unit_done(tsu);
        return 1;
}

int
sfw_run_batch (sfw_batch_t *tsb)
{
        swi_workitem_t      *wi;
        sfw_test_unit_t     *tsu;
        sfw_test_instance_t *tsi;

        if (sfw_batch_active(tsb)) {
                CDEBUG (D_NET, "Can't start active batch: "LPU64" (%d)\n",
                        tsb->bat_id.bat_id, atomic_read(&tsb->bat_nactive));
                return -EPERM;
        }

        list_for_each_entry (tsi, &tsb->bat_tests, tsi_list) {
                if (!tsi->tsi_is_client) /* skip server instances */
                        continue;

                LASSERT (!tsi->tsi_stopping);
                LASSERT (!sfw_test_active(tsi));

                atomic_inc(&tsb->bat_nactive);

                list_for_each_entry (tsu, &tsi->tsi_units, tsu_list) {
                        atomic_inc(&tsi->tsi_nactive);
                        tsu->tsu_loop = tsi->tsi_loop;
                        wi = &tsu->tsu_worker;
                        swi_init_workitem(wi, tsu, sfw_run_test);
                        swi_schedule_workitem(wi);
                }
        }

        return 0;
}

int
sfw_stop_batch (sfw_batch_t *tsb, int force)
{
        sfw_test_instance_t *tsi;
        srpc_client_rpc_t   *rpc;

        if (!sfw_batch_active(tsb))
                return -EPERM;

        list_for_each_entry (tsi, &tsb->bat_tests, tsi_list) {
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
                list_for_each_entry (rpc, &tsi->tsi_active_rpcs, crpc_list) {
                        spin_lock(&rpc->crpc_lock);

                        srpc_abort_rpc(rpc, -EINTR);

                        spin_unlock(&rpc->crpc_lock);
                }

                spin_unlock(&tsi->tsi_lock);
        }

        return 0;
}

int
sfw_query_batch (sfw_batch_t *tsb, int testidx, srpc_batch_reply_t *reply)
{
        sfw_test_instance_t *tsi;

        if (testidx < 0)
                return -EINVAL;

        if (testidx == 0) {
                reply->bar_active = atomic_read(&tsb->bat_nactive);
                return 0;
        }

        list_for_each_entry (tsi, &tsb->bat_tests, tsi_list) {
                if (testidx-- > 1)
                        continue;

                reply->bar_active = atomic_read(&tsi->tsi_nactive);
                return 0;
        }

        return -ENOENT;
}

void
sfw_free_pages (srpc_server_rpc_t *rpc)
{
        srpc_free_bulk(rpc->srpc_bulk);
        rpc->srpc_bulk = NULL;
}

int
sfw_alloc_pages (srpc_server_rpc_t *rpc, int npages, int sink)
{
        LASSERT (rpc->srpc_bulk == NULL);
        LASSERT (npages > 0 && npages <= LNET_MAX_IOV);

        rpc->srpc_bulk = srpc_alloc_bulk(npages, sink);
        if (rpc->srpc_bulk == NULL) return -ENOMEM;

        return 0;
}

int
sfw_add_test (srpc_server_rpc_t *rpc)
{
        sfw_session_t     *sn = sfw_data.fw_session;
        srpc_test_reply_t *reply = &rpc->srpc_replymsg.msg_body.tes_reply;
        srpc_test_reqst_t *request;
        int                rc;
        sfw_batch_t       *bat;

        request = &rpc->srpc_reqstbuf->buf_msg.msg_body.tes_reqst;
        reply->tsr_sid = (sn == NULL) ? LST_INVALID_SID : sn->sn_id;

        if (request->tsr_loop == 0 ||
            request->tsr_concur == 0 ||
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
                CERROR ("Dropping RPC (%s) from %s under memory pressure.\n",
                        rpc->srpc_service->sv_name,
                        libcfs_id2str(rpc->srpc_peer));
                return -ENOMEM;
        }

        if (sfw_batch_active(bat)) {
                reply->tsr_status = EBUSY;
                return 0;
        }

        if (request->tsr_is_client && rpc->srpc_bulk == NULL) {
                /* rpc will be resumed later in sfw_bulk_ready */
                return sfw_alloc_pages(rpc,
                                       sfw_id_pages(request->tsr_ndest), 1);
        }

        rc = sfw_add_test_instance(bat, rpc);
        CDEBUG (rc == 0 ? D_NET : D_WARNING,
                "%s test: sv %d %s, loop %d, concur %d, ndest %d\n",
                rc == 0 ? "Added" : "Failed to add", request->tsr_service,
                request->tsr_is_client ? "client" : "server",
                request->tsr_loop, request->tsr_concur, request->tsr_ndest);

        reply->tsr_status = (rc < 0) ? -rc : rc;
        return 0;
}

int
sfw_control_batch (srpc_batch_reqst_t *request, srpc_batch_reply_t *reply)
{
        sfw_session_t *sn = sfw_data.fw_session;
        int            rc = 0;
        sfw_batch_t   *bat;

        reply->bar_sid = (sn == NULL) ? LST_INVALID_SID : sn->sn_id;

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

int
sfw_handle_server_rpc (srpc_server_rpc_t *rpc)
{
        srpc_service_t *sv = rpc->srpc_service;
        srpc_msg_t     *reply = &rpc->srpc_replymsg;
        srpc_msg_t     *request = &rpc->srpc_reqstbuf->buf_msg;
        int             rc = 0;

        LASSERT (sfw_data.fw_active_srpc == NULL);
        LASSERT (sv->sv_id <= SRPC_FRAMEWORK_SERVICE_MAX_ID);

        spin_lock(&sfw_data.fw_lock);

        if (sfw_data.fw_shuttingdown) {
                spin_unlock(&sfw_data.fw_lock);
                return -ESHUTDOWN;
        }

        /* Remove timer to avoid racing with it or expiring active session */
        if (sfw_del_session_timer() != 0) {
                CERROR ("Dropping RPC (%s) from %s: racing with expiry timer.",
                        sv->sv_name, libcfs_id2str(rpc->srpc_peer));
                spin_unlock(&sfw_data.fw_lock);
                return -EAGAIN;
        }

        sfw_data.fw_active_srpc = rpc;
        spin_unlock(&sfw_data.fw_lock);

        sfw_unpack_message(request);
        LASSERT (request->msg_type == srpc_service2request(sv->sv_id));

        switch(sv->sv_id) {
        default:
                LBUG ();
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
        }

        rpc->srpc_done = sfw_server_rpc_done;
        spin_lock(&sfw_data.fw_lock);

#ifdef __KERNEL__
        if (!sfw_data.fw_shuttingdown)
                sfw_add_session_timer();
#else
        LASSERT (!sfw_data.fw_shuttingdown);
        sfw_add_session_timer();
#endif

        sfw_data.fw_active_srpc = NULL;
        spin_unlock(&sfw_data.fw_lock);
        return rc;
}

int
sfw_bulk_ready (srpc_server_rpc_t *rpc, int status)
{
        srpc_service_t *sv = rpc->srpc_service;
        int             rc;

        LASSERT (rpc->srpc_bulk != NULL);
        LASSERT (sv->sv_id == SRPC_SERVICE_TEST);
        LASSERT (sfw_data.fw_active_srpc == NULL);
        LASSERT (rpc->srpc_reqstbuf->buf_msg.msg_body.tes_reqst.tsr_is_client);

        spin_lock(&sfw_data.fw_lock);

        if (status != 0) {
                CERROR ("Bulk transfer failed for RPC: "
                        "service %s, peer %s, status %d\n",
                        sv->sv_name, libcfs_id2str(rpc->srpc_peer), status);
                spin_unlock(&sfw_data.fw_lock);
                return -EIO;
        }

        if (sfw_data.fw_shuttingdown) {
                spin_unlock(&sfw_data.fw_lock);
                return -ESHUTDOWN;
        }

        if (sfw_del_session_timer() != 0) {
                CERROR ("Dropping RPC (%s) from %s: racing with expiry timer",
                        sv->sv_name, libcfs_id2str(rpc->srpc_peer));
                spin_unlock(&sfw_data.fw_lock);
                return -EAGAIN;
        }

        sfw_data.fw_active_srpc = rpc;
        spin_unlock(&sfw_data.fw_lock);

        rc = sfw_add_test(rpc);

        spin_lock(&sfw_data.fw_lock);

#ifdef __KERNEL__
        if (!sfw_data.fw_shuttingdown)
                sfw_add_session_timer();
#else
        LASSERT (!sfw_data.fw_shuttingdown);
        sfw_add_session_timer();
#endif

        sfw_data.fw_active_srpc = NULL;
        spin_unlock(&sfw_data.fw_lock);
        return rc;
}

srpc_client_rpc_t *
sfw_create_rpc (lnet_process_id_t peer, int service,
                int nbulkiov, int bulklen,
                void (*done) (srpc_client_rpc_t *), void *priv)
{
        srpc_client_rpc_t *rpc;

        spin_lock(&sfw_data.fw_lock);

        LASSERT (!sfw_data.fw_shuttingdown);
        LASSERT (service <= SRPC_FRAMEWORK_SERVICE_MAX_ID);

        if (nbulkiov == 0 && !list_empty(&sfw_data.fw_zombie_rpcs)) {
                rpc = list_entry(sfw_data.fw_zombie_rpcs.next,
                                 srpc_client_rpc_t, crpc_list);
                list_del(&rpc->crpc_list);
                spin_unlock(&sfw_data.fw_lock);

                srpc_init_client_rpc(rpc, peer, service, 0, 0,
                                     done, sfw_client_rpc_fini, priv);
                return rpc;
        }

        spin_unlock(&sfw_data.fw_lock);

        rpc = srpc_create_client_rpc(peer, service, nbulkiov, bulklen, done,
                                     nbulkiov != 0 ? NULL : sfw_client_rpc_fini,
                                     priv);
        return rpc;
}

void
sfw_unpack_message (srpc_msg_t *msg)
{
        if (msg->msg_magic == SRPC_MSG_MAGIC)
                return; /* no flipping needed */

        LASSERT (msg->msg_magic == __swab32(SRPC_MSG_MAGIC));

        __swab32s(&msg->msg_type);

        if (msg->msg_type == SRPC_MSG_STAT_REQST) {
                srpc_stat_reqst_t *req = &msg->msg_body.stat_reqst;

                __swab32s(&req->str_type);
                __swab64s(&req->str_rpyid);
                sfw_unpack_sid(req->str_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_STAT_REPLY) {
                srpc_stat_reply_t *rep = &msg->msg_body.stat_reply;

                __swab32s(&rep->str_status);
                sfw_unpack_sid(rep->str_sid);
                sfw_unpack_fw_counters(rep->str_fw);
                sfw_unpack_rpc_counters(rep->str_rpc);
                sfw_unpack_lnet_counters(rep->str_lnet);
                return;
        }

        if (msg->msg_type == SRPC_MSG_MKSN_REQST) {
                srpc_mksn_reqst_t *req = &msg->msg_body.mksn_reqst;

                __swab64s(&req->mksn_rpyid);
                __swab32s(&req->mksn_force);
                sfw_unpack_sid(req->mksn_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_MKSN_REPLY) {
                srpc_mksn_reply_t *rep = &msg->msg_body.mksn_reply;

                __swab32s(&rep->mksn_status);
                __swab32s(&rep->mksn_timeout);
                sfw_unpack_sid(rep->mksn_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_RMSN_REQST) {
                srpc_rmsn_reqst_t *req = &msg->msg_body.rmsn_reqst;

                __swab64s(&req->rmsn_rpyid);
                sfw_unpack_sid(req->rmsn_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_RMSN_REPLY) {
                srpc_rmsn_reply_t *rep = &msg->msg_body.rmsn_reply;

                __swab32s(&rep->rmsn_status);
                sfw_unpack_sid(rep->rmsn_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_DEBUG_REQST) {
                srpc_debug_reqst_t *req = &msg->msg_body.dbg_reqst;

                __swab64s(&req->dbg_rpyid);
                __swab32s(&req->dbg_flags);
                sfw_unpack_sid(req->dbg_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_DEBUG_REPLY) {
                srpc_debug_reply_t *rep = &msg->msg_body.dbg_reply;

                __swab32s(&rep->dbg_nbatch);
                __swab32s(&rep->dbg_timeout);
                sfw_unpack_sid(rep->dbg_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_BATCH_REQST) {
                srpc_batch_reqst_t *req = &msg->msg_body.bat_reqst;

                __swab32s(&req->bar_opc);
                __swab64s(&req->bar_rpyid);
                __swab32s(&req->bar_testidx);
                __swab32s(&req->bar_arg);
                sfw_unpack_sid(req->bar_sid);
                __swab64s(&req->bar_bid.bat_id);
                return;
        }

        if (msg->msg_type == SRPC_MSG_BATCH_REPLY) {
                srpc_batch_reply_t *rep = &msg->msg_body.bat_reply;

                __swab32s(&rep->bar_status);
                sfw_unpack_sid(rep->bar_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_TEST_REQST) {
                srpc_test_reqst_t *req = &msg->msg_body.tes_reqst;

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
                srpc_test_reply_t *rep = &msg->msg_body.tes_reply;

                __swab32s(&rep->tsr_status);
                sfw_unpack_sid(rep->tsr_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_JOIN_REQST) {
                srpc_join_reqst_t *req = &msg->msg_body.join_reqst;

                __swab64s(&req->join_rpyid);
                sfw_unpack_sid(req->join_sid);
                return;
        }

        if (msg->msg_type == SRPC_MSG_JOIN_REPLY) {
                srpc_join_reply_t *rep = &msg->msg_body.join_reply;

                __swab32s(&rep->join_status);
                __swab32s(&rep->join_timeout);
                sfw_unpack_sid(rep->join_sid);
                return;
        }

        LBUG ();
        return;
}

void
sfw_abort_rpc (srpc_client_rpc_t *rpc)
{
        LASSERT (atomic_read(&rpc->crpc_refcount) > 0);
        LASSERT (rpc->crpc_service <= SRPC_FRAMEWORK_SERVICE_MAX_ID);

        spin_lock(&rpc->crpc_lock);
        srpc_abort_rpc(rpc, -EINTR);
        spin_unlock(&rpc->crpc_lock);
        return;
}

void
sfw_post_rpc (srpc_client_rpc_t *rpc)
{
        spin_lock(&rpc->crpc_lock);

        LASSERT (!rpc->crpc_closed);
        LASSERT (!rpc->crpc_aborted);
        LASSERT (list_empty(&rpc->crpc_list));
        LASSERT (!sfw_data.fw_shuttingdown);

        rpc->crpc_timeout = SFW_CLIENT_RPC_TIMEOUT;
        srpc_post_rpc(rpc);

        spin_unlock(&rpc->crpc_lock);
        return;
}

static srpc_service_t sfw_services[] = 
{
        {
                .sv_name = "debug",
                .sv_id   = SRPC_SERVICE_DEBUG,
        },
        {
                .sv_name = "query stats",
                .sv_id   = SRPC_SERVICE_QUERY_STAT,
        },
        {
                .sv_name = "make sessin",
                .sv_id   = SRPC_SERVICE_MAKE_SESSION,
        },
        {
                .sv_name = "remove session",
                .sv_id   = SRPC_SERVICE_REMOVE_SESSION,
        },
        {
                .sv_name = "batch service",
                .sv_id   = SRPC_SERVICE_BATCH,
        },
        {
                .sv_name = "test service",
                .sv_id   = SRPC_SERVICE_TEST,
        },
        {       .sv_name = NULL, }
};

extern sfw_test_client_ops_t ping_test_client;
extern srpc_service_t        ping_test_service;

extern sfw_test_client_ops_t brw_test_client;
extern srpc_service_t        brw_test_service;

int
sfw_startup (void)
{
        int              i;
        int              rc;
        int              error;
        srpc_service_t  *sv;
        sfw_test_case_t *tsc;

#ifndef __KERNEL__
        char *s;

        s = getenv("SESSION_TIMEOUT");
        session_timeout = s != NULL ? atoi(s) : session_timeout;

        s = getenv("BRW_INJECT_ERRORS");
        brw_inject_errors = s != NULL ? atoi(s) : brw_inject_errors;
#endif

        if (session_timeout < 0) {
                CERROR ("Session timeout must be non-negative: %d\n",
                        session_timeout);
                return -EINVAL;
        }

        if (session_timeout == 0)
                CWARN ("Zero session_timeout specified "
                       "- test sessions never expire.\n");

        memset(&sfw_data, 0, sizeof(struct smoketest_framework));

        sfw_data.fw_session     = NULL;
        sfw_data.fw_active_srpc = NULL;
        spin_lock_init(&sfw_data.fw_lock);
        atomic_set(&sfw_data.fw_nzombies, 0);
        CFS_INIT_LIST_HEAD(&sfw_data.fw_tests);
        CFS_INIT_LIST_HEAD(&sfw_data.fw_zombie_rpcs);
        CFS_INIT_LIST_HEAD(&sfw_data.fw_zombie_sessions);

        rc = sfw_register_test(&brw_test_service, &brw_test_client);
        LASSERT (rc == 0);
        rc = sfw_register_test(&ping_test_service, &ping_test_client);
        LASSERT (rc == 0);

        error = 0;
        list_for_each_entry (tsc, &sfw_data.fw_tests, tsc_list) {
                sv = tsc->tsc_srv_service;
                sv->sv_concur = SFW_TEST_CONCURRENCY;

                rc = srpc_add_service(sv);
                LASSERT (rc != -EBUSY);
                if (rc != 0) {
                        CWARN ("Failed to add %s service: %d\n",
                               sv->sv_name, rc);
                        error = rc;
                }
        }

        for (i = 0; ; i++) {
                sv = &sfw_services[i];
                if (sv->sv_name == NULL) break;

                sv->sv_bulk_ready = NULL;
                sv->sv_handler    = sfw_handle_server_rpc;
                sv->sv_concur     = SFW_SERVICE_CONCURRENCY;
                if (sv->sv_id == SRPC_SERVICE_TEST)
                        sv->sv_bulk_ready = sfw_bulk_ready;

                rc = srpc_add_service(sv);
                LASSERT (rc != -EBUSY);
                if (rc != 0) {
                        CWARN ("Failed to add %s service: %d\n",
                               sv->sv_name, rc);
                        error = rc;
                }

                /* about to sfw_shutdown, no need to add buffer */
                if (error) continue; 

                rc = srpc_service_add_buffers(sv, SFW_POST_BUFFERS);
                if (rc != SFW_POST_BUFFERS) {
                        CWARN ("Failed to reserve enough buffers: "
                               "service %s, %d needed, %d reserved\n",
                               sv->sv_name, SFW_POST_BUFFERS, rc);
                        error = -ENOMEM;
                }
        }

        if (error != 0)
                sfw_shutdown();
        return error;
}

void
sfw_shutdown (void)
{
        srpc_service_t  *sv;
        sfw_test_case_t *tsc;
        int              i;

        spin_lock(&sfw_data.fw_lock);

        sfw_data.fw_shuttingdown = 1;
#ifdef __KERNEL__
        lst_wait_until(sfw_data.fw_active_srpc == NULL, sfw_data.fw_lock,
                       "waiting for active RPC to finish.\n");
#else
        LASSERT (sfw_data.fw_active_srpc == NULL);
#endif

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

        list_for_each_entry (tsc, &sfw_data.fw_tests, tsc_list) {
                sv = tsc->tsc_srv_service;
                srpc_shutdown_service(sv);
                srpc_remove_service(sv);
        }

        while (!list_empty(&sfw_data.fw_zombie_rpcs)) {
                srpc_client_rpc_t *rpc;

                rpc = list_entry(sfw_data.fw_zombie_rpcs.next, 
                                 srpc_client_rpc_t, crpc_list);
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
                tsc = list_entry(sfw_data.fw_tests.next,
                                 sfw_test_case_t, tsc_list);
                
                srpc_wait_service_shutdown(tsc->tsc_srv_service);

                list_del(&tsc->tsc_list);
                LIBCFS_FREE(tsc, sizeof(*tsc));
        }

        return;
}
