/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifndef __KERNEL__
#include <liblustre.h>
#endif
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lu_object.h>
#include <lnet/types.h>
#include "ptlrpc_internal.h"

int test_req_buffer_pressure = 0;
CFS_MODULE_PARM(test_req_buffer_pressure, "i", int, 0444,
                "set non-zero to put pressure on request buffer pools");

/* forward ref */
static int ptlrpc_server_post_idle_rqbds (struct ptlrpc_service *svc);

static CFS_LIST_HEAD(ptlrpc_all_services);
spinlock_t ptlrpc_all_services_lock;

static char *
ptlrpc_alloc_request_buffer (int size)
{
        char *ptr;

        if (size > SVC_BUF_VMALLOC_THRESHOLD)
                OBD_VMALLOC(ptr, size);
        else
                OBD_ALLOC(ptr, size);

        return (ptr);
}

static void
ptlrpc_free_request_buffer (char *ptr, int size)
{
        if (size > SVC_BUF_VMALLOC_THRESHOLD)
                OBD_VFREE(ptr, size);
        else
                OBD_FREE(ptr, size);
}

struct ptlrpc_request_buffer_desc *
ptlrpc_alloc_rqbd (struct ptlrpc_service *svc)
{
        struct ptlrpc_request_buffer_desc *rqbd;

        OBD_ALLOC_PTR(rqbd);
        if (rqbd == NULL)
                return (NULL);

        rqbd->rqbd_service = svc;
        rqbd->rqbd_refcount = 0;
        rqbd->rqbd_cbid.cbid_fn = request_in_callback;
        rqbd->rqbd_cbid.cbid_arg = rqbd;
        CFS_INIT_LIST_HEAD(&rqbd->rqbd_reqs);
        rqbd->rqbd_buffer = ptlrpc_alloc_request_buffer(svc->srv_buf_size);

        if (rqbd->rqbd_buffer == NULL) {
                OBD_FREE_PTR(rqbd);
                return (NULL);
        }

        spin_lock(&svc->srv_lock);
        list_add(&rqbd->rqbd_list, &svc->srv_idle_rqbds);
        svc->srv_nbufs++;
        spin_unlock(&svc->srv_lock);

        return (rqbd);
}

void
ptlrpc_free_rqbd (struct ptlrpc_request_buffer_desc *rqbd)
{
        struct ptlrpc_service *svc = rqbd->rqbd_service;

        LASSERT (rqbd->rqbd_refcount == 0);
        LASSERT (list_empty(&rqbd->rqbd_reqs));

        spin_lock(&svc->srv_lock);
        list_del(&rqbd->rqbd_list);
        svc->srv_nbufs--;
        spin_unlock(&svc->srv_lock);

        ptlrpc_free_request_buffer (rqbd->rqbd_buffer, svc->srv_buf_size);
        OBD_FREE_PTR(rqbd);
}

int
ptlrpc_grow_req_bufs(struct ptlrpc_service *svc)
{
        struct ptlrpc_request_buffer_desc *rqbd;
        int                                i;

        CDEBUG(D_RPCTRACE, "%s: allocate %d new %d-byte reqbufs (%d/%d left)\n",
               svc->srv_name, svc->srv_nbuf_per_group, svc->srv_buf_size,
               svc->srv_nrqbd_receiving, svc->srv_nbufs);
        for (i = 0; i < svc->srv_nbuf_per_group; i++) {
                rqbd = ptlrpc_alloc_rqbd(svc);

                if (rqbd == NULL) {
                        CERROR ("%s: Can't allocate request buffer\n",
                                svc->srv_name);
                        return (-ENOMEM);
                }

                if (ptlrpc_server_post_idle_rqbds(svc) < 0)
                        return (-EAGAIN);
        }

        return (0);
}

void
ptlrpc_save_lock (struct ptlrpc_request *req,
                  struct lustre_handle *lock, int mode)
{
        struct ptlrpc_reply_state *rs = req->rq_reply_state;
        int                        idx;

        LASSERT(rs != NULL);
        LASSERT(rs->rs_nlocks < RS_MAX_LOCKS);

        idx = rs->rs_nlocks++;
        rs->rs_locks[idx] = *lock;
        rs->rs_modes[idx] = mode;
        rs->rs_difficult = 1;
}

void
ptlrpc_schedule_difficult_reply (struct ptlrpc_reply_state *rs)
{
        struct ptlrpc_service *svc = rs->rs_service;

#ifdef CONFIG_SMP
        LASSERT (spin_is_locked (&svc->srv_lock));
#endif
        LASSERT (rs->rs_difficult);
        rs->rs_scheduled_ever = 1;              /* flag any notification attempt */

        if (rs->rs_scheduled)                   /* being set up or already notified */
                return;

        rs->rs_scheduled = 1;
        list_del (&rs->rs_list);
        list_add (&rs->rs_list, &svc->srv_reply_queue);
        cfs_waitq_signal (&svc->srv_waitq);
}

void
ptlrpc_commit_replies (struct obd_device *obd)
{
        struct list_head   *tmp;
        struct list_head   *nxt;

        /* Find any replies that have been committed and get their service
         * to attend to complete them. */

        /* CAVEAT EMPTOR: spinlock ordering!!! */
        spin_lock(&obd->obd_uncommitted_replies_lock);

        list_for_each_safe (tmp, nxt, &obd->obd_uncommitted_replies) {
                struct ptlrpc_reply_state *rs =
                        list_entry(tmp, struct ptlrpc_reply_state, rs_obd_list);

                LASSERT (rs->rs_difficult);

                if (rs->rs_transno <= obd->obd_last_committed) {
                        struct ptlrpc_service *svc = rs->rs_service;

                        spin_lock (&svc->srv_lock);
                        list_del_init (&rs->rs_obd_list);
                        ptlrpc_schedule_difficult_reply (rs);
                        spin_unlock (&svc->srv_lock);
                }
        }

        spin_unlock(&obd->obd_uncommitted_replies_lock);
}

static int
ptlrpc_server_post_idle_rqbds (struct ptlrpc_service *svc)
{
        struct ptlrpc_request_buffer_desc *rqbd;
        int                                rc;
        int                                posted = 0;

        for (;;) {
                spin_lock(&svc->srv_lock);

                if (list_empty (&svc->srv_idle_rqbds)) {
                        spin_unlock(&svc->srv_lock);
                        return (posted);
                }

                rqbd = list_entry(svc->srv_idle_rqbds.next,
                                  struct ptlrpc_request_buffer_desc,
                                  rqbd_list);
                list_del (&rqbd->rqbd_list);

                /* assume we will post successfully */
                svc->srv_nrqbd_receiving++;
                list_add (&rqbd->rqbd_list, &svc->srv_active_rqbds);

                spin_unlock(&svc->srv_lock);

                rc = ptlrpc_register_rqbd(rqbd);
                if (rc != 0)
                        break;

                posted = 1;
        }

        spin_lock(&svc->srv_lock);

        svc->srv_nrqbd_receiving--;
        list_del(&rqbd->rqbd_list);
        list_add_tail(&rqbd->rqbd_list, &svc->srv_idle_rqbds);

        /* Don't complain if no request buffers are posted right now; LNET
         * won't drop requests because we set the portal lazy! */

        spin_unlock(&svc->srv_lock);

        return (-1);
}

struct ptlrpc_service *ptlrpc_init_svc_conf(struct ptlrpc_service_conf *c,
                                            svc_handler_t h, char *name,
                                            struct proc_dir_entry *proc_entry,
                                            svcreq_printfn_t prntfn,
                                            char *threadname)
{
        return ptlrpc_init_svc(c->psc_nbufs, c->psc_bufsize,
                               c->psc_max_req_size, c->psc_max_reply_size,
                               c->psc_req_portal, c->psc_rep_portal,
                               c->psc_watchdog_timeout,
                               h, name, proc_entry,
                               prntfn, c->psc_min_threads, c->psc_max_threads,
                               threadname, c->psc_ctx_tags);
}
EXPORT_SYMBOL(ptlrpc_init_svc_conf);

/* @threadname should be 11 characters or less - 3 will be added on */
struct ptlrpc_service *
ptlrpc_init_svc(int nbufs, int bufsize, int max_req_size, int max_reply_size,
                int req_portal, int rep_portal, int watchdog_timeout,
                svc_handler_t handler, char *name,
                cfs_proc_dir_entry_t *proc_entry,
                svcreq_printfn_t svcreq_printfn,
                int min_threads, int max_threads,
                char *threadname, __u32 ctx_tags)
{
        int                    rc;
        struct ptlrpc_service *service;
        ENTRY;

        LASSERT (nbufs > 0);
        LASSERT (bufsize >= max_req_size + SPTLRPC_MAX_PAYLOAD);
        LASSERT (ctx_tags != 0);

        OBD_ALLOC_PTR(service);
        if (service == NULL)
                RETURN(NULL);

        /* First initialise enough for early teardown */

        service->srv_name = name;
        spin_lock_init(&service->srv_lock);
        CFS_INIT_LIST_HEAD(&service->srv_threads);
        cfs_waitq_init(&service->srv_waitq);

        service->srv_nbuf_per_group = test_req_buffer_pressure ? 1 : nbufs;
        service->srv_max_req_size = max_req_size + SPTLRPC_MAX_PAYLOAD;
        service->srv_buf_size = bufsize;
        service->srv_rep_portal = rep_portal;
        service->srv_req_portal = req_portal;
        service->srv_watchdog_timeout = watchdog_timeout;
        service->srv_handler = handler;
        service->srv_request_history_print_fn = svcreq_printfn;
        service->srv_request_seq = 1;           /* valid seq #s start at 1 */
        service->srv_request_max_cull_seq = 0;
        service->srv_threads_min = min_threads;
        service->srv_threads_max = max_threads;
        service->srv_thread_name = threadname;
        service->srv_ctx_tags = ctx_tags;

        rc = LNetSetLazyPortal(service->srv_req_portal);
        LASSERT (rc == 0);

        CFS_INIT_LIST_HEAD(&service->srv_request_queue);
        CFS_INIT_LIST_HEAD(&service->srv_idle_rqbds);
        CFS_INIT_LIST_HEAD(&service->srv_active_rqbds);
        CFS_INIT_LIST_HEAD(&service->srv_history_rqbds);
        CFS_INIT_LIST_HEAD(&service->srv_request_history);
        CFS_INIT_LIST_HEAD(&service->srv_active_replies);
        CFS_INIT_LIST_HEAD(&service->srv_reply_queue);
        CFS_INIT_LIST_HEAD(&service->srv_free_rs_list);
        cfs_waitq_init(&service->srv_free_rs_waitq);

        spin_lock (&ptlrpc_all_services_lock);
        list_add (&service->srv_list, &ptlrpc_all_services);
        spin_unlock (&ptlrpc_all_services_lock);

        /* Now allocate the request buffers */
        rc = ptlrpc_grow_req_bufs(service);
        /* We shouldn't be under memory pressure at startup, so
         * fail if we can't post all our buffers at this time. */
        if (rc != 0)
                GOTO(failed, NULL);

        /* Now allocate pool of reply buffers */
        /* Increase max reply size to next power of two */
        service->srv_max_reply_size = 1;
        while (service->srv_max_reply_size <
               max_reply_size + SPTLRPC_MAX_PAYLOAD)
                service->srv_max_reply_size <<= 1;

        if (proc_entry != NULL)
                ptlrpc_lprocfs_register_service(proc_entry, service);

        CDEBUG(D_NET, "%s: Started, listening on portal %d\n",
               service->srv_name, service->srv_req_portal);

        RETURN(service);
failed:
        ptlrpc_unregister_service(service);
        return NULL;
}

static void __ptlrpc_server_free_request(struct ptlrpc_request *req)
{
        struct ptlrpc_request_buffer_desc *rqbd = req->rq_rqbd;

        list_del(&req->rq_list);

        if (req->rq_reply_state != NULL) {
                ptlrpc_rs_decref(req->rq_reply_state);
                req->rq_reply_state = NULL;
        }

        sptlrpc_svc_ctx_decref(req);

        if (req != &rqbd->rqbd_req) {
                /* NB request buffers use an embedded
                 * req if the incoming req unlinked the
                 * MD; this isn't one of them! */
                OBD_FREE(req, sizeof(*req));
        }
}

static void
ptlrpc_server_free_request(struct ptlrpc_request *req)
{
        struct ptlrpc_request_buffer_desc *rqbd = req->rq_rqbd;
        struct ptlrpc_service             *svc = rqbd->rqbd_service;
        int                                refcount;
        struct list_head                  *tmp;
        struct list_head                  *nxt;

        spin_lock(&svc->srv_lock);

        svc->srv_n_active_reqs--;
        list_add(&req->rq_list, &rqbd->rqbd_reqs);

        refcount = --(rqbd->rqbd_refcount);
        if (refcount == 0) {
                /* request buffer is now idle: add to history */
                list_del(&rqbd->rqbd_list);
                list_add_tail(&rqbd->rqbd_list, &svc->srv_history_rqbds);
                svc->srv_n_history_rqbds++;

                /* cull some history?
                 * I expect only about 1 or 2 rqbds need to be recycled here */
                while (svc->srv_n_history_rqbds > svc->srv_max_history_rqbds) {
                        rqbd = list_entry(svc->srv_history_rqbds.next,
                                          struct ptlrpc_request_buffer_desc,
                                          rqbd_list);

                        list_del(&rqbd->rqbd_list);
                        svc->srv_n_history_rqbds--;

                        /* remove rqbd's reqs from svc's req history while
                         * I've got the service lock */
                        list_for_each(tmp, &rqbd->rqbd_reqs) {
                                req = list_entry(tmp, struct ptlrpc_request,
                                                 rq_list);
                                /* Track the highest culled req seq */
                                if (req->rq_history_seq >
                                    svc->srv_request_max_cull_seq)
                                        svc->srv_request_max_cull_seq =
                                                req->rq_history_seq;
                                list_del(&req->rq_history_list);
                        }

                        spin_unlock(&svc->srv_lock);

                        list_for_each_safe(tmp, nxt, &rqbd->rqbd_reqs) {
                                req = list_entry(rqbd->rqbd_reqs.next,
                                                 struct ptlrpc_request,
                                                 rq_list);
                                __ptlrpc_server_free_request(req);
                        }

                        spin_lock(&svc->srv_lock);

                        /* schedule request buffer for re-use.
                         * NB I can only do this after I've disposed of their
                         * reqs; particularly the embedded req */
                        list_add_tail(&rqbd->rqbd_list, &svc->srv_idle_rqbds);
                }
        } else if (req->rq_reply_state && req->rq_reply_state->rs_prealloc) {
                 /* If we are low on memory, we are not interested in
                    history */
                list_del(&req->rq_history_list);
                __ptlrpc_server_free_request(req);
        }

        spin_unlock(&svc->srv_lock);

}

/* This function makes sure dead exports are evicted in a timely manner.
   This function is only called when some export receives a message (i.e.,
   the network is up.) */
static void ptlrpc_update_export_timer(struct obd_export *exp, long extra_delay)
{
        struct obd_export *oldest_exp;
        time_t oldest_time;

        ENTRY;

        LASSERT(exp);

        /* Compensate for slow machines, etc, by faking our request time
           into the future.  Although this can break the strict time-ordering
           of the list, we can be really lazy here - we don't have to evict
           at the exact right moment.  Eventually, all silent exports
           will make it to the top of the list. */
        exp->exp_last_request_time = max(exp->exp_last_request_time,
                                         cfs_time_current_sec() + extra_delay);

        CDEBUG(D_HA, "updating export %s at "CFS_TIME_T" exp %p\n",
               exp->exp_client_uuid.uuid,
               exp->exp_last_request_time, exp);

        /* exports may get disconnected from the chain even though the
           export has references, so we must keep the spin lock while
           manipulating the lists */
        spin_lock(&exp->exp_obd->obd_dev_lock);

        if (list_empty(&exp->exp_obd_chain_timed)) {
                /* this one is not timed */
                spin_unlock(&exp->exp_obd->obd_dev_lock);
                EXIT;
                return;
        }

        list_move_tail(&exp->exp_obd_chain_timed,
                       &exp->exp_obd->obd_exports_timed);

        oldest_exp = list_entry(exp->exp_obd->obd_exports_timed.next,
                                struct obd_export, exp_obd_chain_timed);
        oldest_time = oldest_exp->exp_last_request_time;
        spin_unlock(&exp->exp_obd->obd_dev_lock);

        if (exp->exp_obd->obd_recovering) {
                /* be nice to everyone during recovery */
                EXIT;
                return;
        }

        /* Note - racing to start/reset the obd_eviction timer is safe */
        if (exp->exp_obd->obd_eviction_timer == 0) {
                /* Check if the oldest entry is expired. */
                if (cfs_time_current_sec() > (oldest_time +
                                       (3 * obd_timeout / 2) + extra_delay)) {
                        /* We need a second timer, in case the net was down and
                         * it just came back. Since the pinger may skip every
                         * other PING_INTERVAL (see note in ptlrpc_pinger_main),
                         * we better wait for 3. */
                        exp->exp_obd->obd_eviction_timer = cfs_time_current_sec() +
                                3 * PING_INTERVAL;
                        CDEBUG(D_HA, "%s: Think about evicting %s from "CFS_TIME_T"\n",
                               exp->exp_obd->obd_name, obd_export_nid2str(exp),
                               oldest_time);
                }
        } else {
                if (cfs_time_current_sec() > (exp->exp_obd->obd_eviction_timer +
                                       extra_delay)) {
                        /* The evictor won't evict anyone who we've heard from
                         * recently, so we don't have to check before we start
                         * it. */
                        if (!ping_evictor_wake(exp))
                                exp->exp_obd->obd_eviction_timer = 0;
                }
        }

        EXIT;
}

#ifndef __KERNEL__
int lu_context_init(struct lu_context *ctx, __u32 tags)
{
        return 0;
}

void lu_context_fini(struct lu_context *ctx)
{
}

void lu_context_enter(struct lu_context *ctx)
{
}

void lu_context_exit(struct lu_context *ctx)
{
}

#endif

static int
ptlrpc_server_handle_request(struct ptlrpc_service *svc,
                             struct ptlrpc_thread *thread)
{
        struct obd_export     *export = NULL;
        struct ptlrpc_request *request;
        struct timeval         work_start;
        struct timeval         work_end;
        long                   timediff;
        int                    rc, reply;
        ENTRY;

        LASSERT(svc);

        spin_lock(&svc->srv_lock);
        if (unlikely(list_empty (&svc->srv_request_queue) ||
                     (svc->srv_n_difficult_replies != 0 &&
                      svc->srv_n_active_reqs >= (svc->srv_threads_running - 1)))) {
                /* If all the other threads are handling requests, I must
                 * remain free to handle any 'difficult' reply that might
                 * block them */
                spin_unlock(&svc->srv_lock);
                RETURN(0);
        }

        request = list_entry (svc->srv_request_queue.next,
                              struct ptlrpc_request, rq_list);
        list_del_init (&request->rq_list);
        svc->srv_n_queued_reqs--;
        svc->srv_n_active_reqs++;

        spin_unlock(&svc->srv_lock);

        do_gettimeofday(&work_start);
        timediff = cfs_timeval_sub(&work_start, &request->rq_arrival_time,NULL);
        if (likely(svc->srv_stats != NULL)) {
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQWAIT_CNTR,
                                    timediff);
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQQDEPTH_CNTR,
                                    svc->srv_n_queued_reqs);
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQACTIVE_CNTR,
                                    svc->srv_n_active_reqs);
        }

        /* go through security check/transform */
        rc = sptlrpc_svc_unwrap_request(request);
        switch (rc) {
        case SECSVC_OK:
                break;
        case SECSVC_COMPLETE:
                target_send_reply(request, 0, OBD_FAIL_MDS_ALL_REPLY_NET);
                goto out_stat;
        case SECSVC_DROP:
                goto out_req;
        default:
                LBUG();
        }

        /* Clear request swab mask; this is a new request */
        request->rq_req_swab_mask = 0;

        rc = lustre_unpack_msg(request->rq_reqmsg, request->rq_reqlen);
        if (rc != 0) {
                CERROR ("error unpacking request: ptl %d from %s"
                        " xid "LPU64"\n", svc->srv_req_portal,
                        libcfs_id2str(request->rq_peer), request->rq_xid);
                goto out_req;
        }

        rc = lustre_unpack_req_ptlrpc_body(request, MSG_PTLRPC_BODY_OFF);
        if (rc) {
                CERROR ("error unpacking ptlrpc body: ptl %d from %s"
                        " xid "LPU64"\n", svc->srv_req_portal,
                        libcfs_id2str(request->rq_peer), request->rq_xid);
                goto out_req;
        }

        rc = -EINVAL;
        if (lustre_msg_get_type(request->rq_reqmsg) != PTL_RPC_MSG_REQUEST) {
                CERROR("wrong packet type received (type=%u) from %s\n",
                       lustre_msg_get_type(request->rq_reqmsg),
                       libcfs_id2str(request->rq_peer));
                goto out_req;
        }

        rc = lu_context_init(&request->rq_session, LCT_SESSION);
        if (rc) {
                CERROR("Failure to initialize session: %d\n", rc);
                goto out_req;
        }
        request->rq_session.lc_thread = thread;
        lu_context_enter(&request->rq_session);

        CDEBUG(D_NET, "got req "LPD64"\n", request->rq_xid);

        request->rq_svc_thread = thread;
        if (thread)
                request->rq_svc_thread->t_env->le_ses = &request->rq_session;

        request->rq_export = class_conn2export(
                                     lustre_msg_get_handle(request->rq_reqmsg));

        if (likely(request->rq_export)) {
                if (unlikely(lustre_msg_get_conn_cnt(request->rq_reqmsg) <
                             request->rq_export->exp_conn_cnt)) {
                        DEBUG_REQ(D_ERROR, request,
                                  "DROPPING req from old connection %d < %d",
                                  lustre_msg_get_conn_cnt(request->rq_reqmsg),
                                  request->rq_export->exp_conn_cnt);
                        goto put_conn;
                }
                if (unlikely(request->rq_export->exp_obd &&
                             request->rq_export->exp_obd->obd_fail)) {
                        /* Failing over, don't handle any more reqs, send
                           error response instead. */
                        CDEBUG(D_RPCTRACE,"Dropping req %p for failed obd %s\n",
                               request, request->rq_export->exp_obd->obd_name);
                        request->rq_status = -ENODEV;
                        ptlrpc_error(request);
                        goto put_conn;
                }

                rc = sptlrpc_target_export_check(request->rq_export, request);
                if (unlikely(rc)) {
                        DEBUG_REQ(D_ERROR, request,
                                  "DROPPING req with illegal security flavor,");
                        goto put_conn;
                }

                ptlrpc_update_export_timer(request->rq_export, timediff/500000);
                export = class_export_rpc_get(request->rq_export);
        }

        /* Discard requests queued for longer than my timeout.  If the
         * client's timeout is similar to mine, she'll be timing out this
         * REQ anyway (bug 1502) */
        if (unlikely(timediff / 1000000 > (long)obd_timeout)) {
                CERROR("Dropping timed-out opc %d request from %s"
                       ": %ld seconds old\n",
                       lustre_msg_get_opc(request->rq_reqmsg),
                       libcfs_id2str(request->rq_peer),
                       timediff / 1000000);
                goto put_rpc_export;
        }

        request->rq_phase = RQ_PHASE_INTERPRET;

        CDEBUG(D_RPCTRACE, "Handling RPC pname:cluuid+ref:pid:xid:nid:opc "
               "%s:%s+%d:%d:"LPU64":%s:%d\n", cfs_curproc_comm(),
               (request->rq_export ?
                (char *)request->rq_export->exp_client_uuid.uuid : "0"),
               (request->rq_export ?
                atomic_read(&request->rq_export->exp_refcount) : -99),
               lustre_msg_get_status(request->rq_reqmsg), request->rq_xid,
               libcfs_id2str(request->rq_peer),
               lustre_msg_get_opc(request->rq_reqmsg));

        rc = svc->srv_handler(request);

        request->rq_phase = RQ_PHASE_COMPLETE;

        CDEBUG(D_RPCTRACE, "Handled RPC pname:cluuid+ref:pid:xid:nid:opc "
               "%s:%s+%d:%d:"LPU64":%s:%d\n", cfs_curproc_comm(),
               (request->rq_export ?
                (char *)request->rq_export->exp_client_uuid.uuid : "0"),
               (request->rq_export ?
                atomic_read(&request->rq_export->exp_refcount) : -99),
               lustre_msg_get_status(request->rq_reqmsg), request->rq_xid,
               libcfs_id2str(request->rq_peer),
               lustre_msg_get_opc(request->rq_reqmsg));

put_rpc_export:
        if (export != NULL)
                class_export_rpc_put(export);
put_conn:
        if (likely(request->rq_export != NULL))
                class_export_put(request->rq_export);

        lu_context_exit(&request->rq_session);
        lu_context_fini(&request->rq_session);
out_stat:
        reply = request->rq_reply_state && request->rq_repmsg;  /* bug 11169 */

        do_gettimeofday(&work_end);

        timediff = cfs_timeval_sub(&work_end, &work_start, NULL);

        if (unlikely(timediff / 1000000 > (long)obd_timeout))
                CERROR("request "LPU64" opc %u from %s processed in %lds "
                       "trans "LPU64" rc %d/%d\n",
                       request->rq_xid,
                       request->rq_reqmsg ?
                                lustre_msg_get_opc(request->rq_reqmsg) : 0,
                       libcfs_id2str(request->rq_peer),
                       cfs_timeval_sub(&work_end, &request->rq_arrival_time,
                                       NULL) / 1000000,
                       reply ? lustre_msg_get_transno(request->rq_repmsg) :
                               request->rq_transno, request->rq_status,
                       reply ? lustre_msg_get_status(request->rq_repmsg) : -999);
        else
                CDEBUG(D_RPCTRACE,"request "LPU64" opc %u from %s processed in "
                       "%ldus (%ldus total) trans "LPU64" rc %d/%d\n",
                       request->rq_xid,
                       request->rq_reqmsg ?
                                lustre_msg_get_opc(request->rq_reqmsg) : 0,
                       libcfs_id2str(request->rq_peer), timediff,
                       cfs_timeval_sub(&work_end, &request->rq_arrival_time,
                                       NULL),
                       request->rq_transno, request->rq_status,
                       reply ? lustre_msg_get_status(request->rq_repmsg) : -999);

        if (likely(svc->srv_stats != NULL && request->rq_reqmsg != NULL)) {
                __u32 op = lustre_msg_get_opc(request->rq_reqmsg);
                int opc = opcode_offset(op);
                if (opc > 0 && !(op == LDLM_ENQUEUE || op == MDS_REINT)) {
                        LASSERT(opc < LUSTRE_MAX_OPCODES);
                        lprocfs_counter_add(svc->srv_stats,
                                            opc + EXTRA_MAX_OPCODES,
                                            timediff);
                }
        }

out_req:
        ptlrpc_server_free_request(request);

        RETURN(1);
}

static int
ptlrpc_server_handle_reply (struct ptlrpc_service *svc)
{
        struct ptlrpc_reply_state *rs;
        struct obd_export         *exp;
        struct obd_device         *obd;
        int                        nlocks;
        int                        been_handled;
        ENTRY;

        spin_lock(&svc->srv_lock);
        if (list_empty (&svc->srv_reply_queue)) {
                spin_unlock(&svc->srv_lock);
                RETURN(0);
        }

        rs = list_entry (svc->srv_reply_queue.next,
                         struct ptlrpc_reply_state, rs_list);

        exp = rs->rs_export;
        obd = exp->exp_obd;

        LASSERT (rs->rs_difficult);
        LASSERT (rs->rs_scheduled);

        list_del_init (&rs->rs_list);

        /* Disengage from notifiers carefully (lock order - irqrestore below!)*/
        spin_unlock(&svc->srv_lock);

        spin_lock (&obd->obd_uncommitted_replies_lock);
        /* Noop if removed already */
        list_del_init (&rs->rs_obd_list);
        spin_unlock (&obd->obd_uncommitted_replies_lock);

        spin_lock (&exp->exp_lock);
        /* Noop if removed already */
        list_del_init (&rs->rs_exp_list);
        spin_unlock (&exp->exp_lock);

        spin_lock(&svc->srv_lock);

        been_handled = rs->rs_handled;
        rs->rs_handled = 1;

        nlocks = rs->rs_nlocks;                 /* atomic "steal", but */
        rs->rs_nlocks = 0;                      /* locks still on rs_locks! */

        if (nlocks == 0 && !been_handled) {
                /* If we see this, we should already have seen the warning
                 * in mds_steal_ack_locks()  */
                CWARN("All locks stolen from rs %p x"LPD64".t"LPD64
                      " o%d NID %s\n",
                      rs,
                      rs->rs_xid, rs->rs_transno,
                      lustre_msg_get_opc(rs->rs_msg),
                      libcfs_nid2str(exp->exp_connection->c_peer.nid));
        }

        if ((!been_handled && rs->rs_on_net) || nlocks > 0) {
                spin_unlock(&svc->srv_lock);

                if (!been_handled && rs->rs_on_net) {
                        LNetMDUnlink(rs->rs_md_h);
                        /* Ignore return code; we're racing with
                         * completion... */
                }

                while (nlocks-- > 0)
                        ldlm_lock_decref(&rs->rs_locks[nlocks],
                                         rs->rs_modes[nlocks]);

                spin_lock(&svc->srv_lock);
        }

        rs->rs_scheduled = 0;

        if (!rs->rs_on_net) {
                /* Off the net */
                svc->srv_n_difficult_replies--;
                spin_unlock(&svc->srv_lock);

                class_export_put (exp);
                rs->rs_export = NULL;
                ptlrpc_rs_decref (rs);
                atomic_dec (&svc->srv_outstanding_replies);
                RETURN(1);
        }

        /* still on the net; callback will schedule */
        spin_unlock(&svc->srv_lock);
        RETURN(1);
}

#ifndef __KERNEL__
/* FIXME make use of timeout later */
int
liblustre_check_services (void *arg)
{
        int  did_something = 0;
        int  rc;
        struct list_head *tmp, *nxt;
        ENTRY;

        /* I'm relying on being single threaded, not to have to lock
         * ptlrpc_all_services etc */
        list_for_each_safe (tmp, nxt, &ptlrpc_all_services) {
                struct ptlrpc_service *svc =
                        list_entry (tmp, struct ptlrpc_service, srv_list);

                if (svc->srv_threads_running != 0)     /* I've recursed */
                        continue;

                /* service threads can block for bulk, so this limits us
                 * (arbitrarily) to recursing 1 stack frame per service.
                 * Note that the problem with recursion is that we have to
                 * unwind completely before our caller can resume. */

                svc->srv_threads_running++;

                do {
                        rc = ptlrpc_server_handle_reply(svc);
                        rc |= ptlrpc_server_handle_request(svc, NULL);
                        rc |= (ptlrpc_server_post_idle_rqbds(svc) > 0);
                        did_something |= rc;
                } while (rc);

                svc->srv_threads_running--;
        }

        RETURN(did_something);
}
#define ptlrpc_stop_all_threads(s) do {} while (0)

#else /* __KERNEL__ */

/* Don't use daemonize, it removes fs struct from new thread (bug 418) */
void ptlrpc_daemonize(char *name)
{
        struct fs_struct *fs = current->fs;

        atomic_inc(&fs->count);
        cfs_daemonize(name);
        exit_fs(cfs_current());
        current->fs = fs;
        ll_set_fs_pwd(current->fs, init_task.fs->pwdmnt, init_task.fs->pwd);
}

static void
ptlrpc_check_rqbd_pool(struct ptlrpc_service *svc)
{
        int avail = svc->srv_nrqbd_receiving;
        int low_water = test_req_buffer_pressure ? 0 :
                        svc->srv_nbuf_per_group/2;

        /* NB I'm not locking; just looking. */

        /* CAVEAT EMPTOR: We might be allocating buffers here because we've
         * allowed the request history to grow out of control.  We could put a
         * sanity check on that here and cull some history if we need the
         * space. */

        if (avail <= low_water)
                ptlrpc_grow_req_bufs(svc);

        if (svc->srv_stats)
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQBUF_AVAIL_CNTR,
                                    avail);
}

static int
ptlrpc_retry_rqbds(void *arg)
{
        struct ptlrpc_service *svc = (struct ptlrpc_service *)arg;

        svc->srv_rqbd_timeout = 0;
        return (-ETIMEDOUT);
}

static int ptlrpc_main(void *arg)
{
        struct ptlrpc_svc_data *data = (struct ptlrpc_svc_data *)arg;
        struct ptlrpc_service  *svc = data->svc;
        struct ptlrpc_thread   *thread = data->thread;
        struct obd_device      *dev = data->dev;
        struct ptlrpc_reply_state *rs;
        struct lc_watchdog     *watchdog;
#ifdef WITH_GROUP_INFO
        struct group_info *ginfo = NULL;
#endif
        struct lu_env env;
        int rc = 0;
        ENTRY;

        ptlrpc_daemonize(data->name);

#if defined(HAVE_NODE_TO_CPUMASK) && defined(CONFIG_NUMA)
        /* we need to do this before any per-thread allocation is done so that
         * we get the per-thread allocations on local node.  bug 7342 */
        if (svc->srv_cpu_affinity) {
                int cpu, num_cpu;

                for (cpu = 0, num_cpu = 0; cpu < num_possible_cpus(); cpu++) {
                        if (!cpu_online(cpu))
                                continue;
                        if (num_cpu == thread->t_id % num_online_cpus())
                                break;
                        num_cpu++;
                }
                set_cpus_allowed(cfs_current(), node_to_cpumask(cpu_to_node(cpu)));
        }
#endif

#ifdef WITH_GROUP_INFO
        ginfo = groups_alloc(0);
        if (!ginfo) {
                rc = -ENOMEM;
                goto out;
        }

        set_current_groups(ginfo);
        put_group_info(ginfo);
#endif

        if (svc->srv_init != NULL) {
                rc = svc->srv_init(thread);
                if (rc)
                        goto out;
        }

        rc = lu_context_init(&env.le_ctx, svc->srv_ctx_tags);
        if (rc)
                goto out_srv_fini;

        thread->t_env = &env;
        env.le_ctx.lc_thread = thread;

        /* Alloc reply state structure for this one */
        OBD_ALLOC_GFP(rs, svc->srv_max_reply_size, CFS_ALLOC_STD);
        if (!rs) {
                rc = -ENOMEM;
                goto out_srv_fini;
        }

        /* Record that the thread is running */
        thread->t_flags = SVC_RUNNING;
        /*
         * wake up our creator. Note: @data is invalid after this point,
         * because it's allocated on ptlrpc_start_thread() stack.
         */
        cfs_waitq_signal(&thread->t_ctl_waitq);

        watchdog = lc_watchdog_add(svc->srv_watchdog_timeout, NULL, NULL);

        spin_lock(&svc->srv_lock);
        svc->srv_threads_running++;
        list_add(&rs->rs_list, &svc->srv_free_rs_list);
        spin_unlock(&svc->srv_lock);
        cfs_waitq_signal(&svc->srv_free_rs_waitq);

        CDEBUG(D_NET, "service thread %d (#%d)started\n", thread->t_id,
              svc->srv_threads_running);

        /* XXX maintain a list of all managed devices: insert here */

        while ((thread->t_flags & SVC_STOPPING) == 0 ||
               svc->srv_n_difficult_replies != 0) {
                /* Don't exit while there are replies to be handled */
                struct l_wait_info lwi = LWI_TIMEOUT(svc->srv_rqbd_timeout,
                                                     ptlrpc_retry_rqbds, svc);

                lc_watchdog_disable(watchdog);

                cond_resched();

                l_wait_event_exclusive (svc->srv_waitq,
                              ((thread->t_flags & SVC_STOPPING) != 0 &&
                               svc->srv_n_difficult_replies == 0) ||
                              (!list_empty(&svc->srv_idle_rqbds) &&
                               svc->srv_rqbd_timeout == 0) ||
                              !list_empty (&svc->srv_reply_queue) ||
                              (!list_empty (&svc->srv_request_queue) &&
                               (svc->srv_n_difficult_replies == 0 ||
                                svc->srv_n_active_reqs <
                                (svc->srv_threads_running - 1))),
                              &lwi);

                lc_watchdog_touch(watchdog);

                ptlrpc_check_rqbd_pool(svc);

                if ((svc->srv_threads_started < svc->srv_threads_max) &&
                    (svc->srv_n_active_reqs >= (svc->srv_threads_started - 1))){
                        /* Ignore return code - we tried... */
                        ptlrpc_start_thread(dev, svc);
                }

                if (!list_empty (&svc->srv_reply_queue))
                        ptlrpc_server_handle_reply (svc);

                /* only handle requests if there are no difficult replies
                 * outstanding, or I'm not the last thread handling
                 * requests */
                if (!list_empty (&svc->srv_request_queue) &&
                    (svc->srv_n_difficult_replies == 0 ||
                     svc->srv_n_active_reqs < (svc->srv_threads_running - 1))) {
                        lu_context_enter(&env.le_ctx);
                        ptlrpc_server_handle_request(svc, thread);
                        lu_context_exit(&env.le_ctx);
                }

                if (!list_empty(&svc->srv_idle_rqbds) &&
                    ptlrpc_server_post_idle_rqbds(svc) < 0) {
                        /* I just failed to repost request buffers.  Wait
                         * for a timeout (unless something else happens)
                         * before I try again */
                        svc->srv_rqbd_timeout = cfs_time_seconds(1)/10;
                        CDEBUG(D_RPCTRACE,"Posted buffers: %d\n",
                               svc->srv_nrqbd_receiving);
                }
        }

        lc_watchdog_delete(watchdog);

out_srv_fini:
        /*
         * deconstruct service specific state created by ptlrpc_start_thread()
         */
        if (svc->srv_done != NULL)
                svc->srv_done(thread);

        lu_context_fini(&env.le_ctx);
out:
        CDEBUG(D_NET, "service thread %d exiting: rc %d\n", thread->t_id, rc);

        spin_lock(&svc->srv_lock);
        svc->srv_threads_running--; /* must know immediately */
        thread->t_id = rc;
        thread->t_flags = SVC_STOPPED;

        cfs_waitq_signal(&thread->t_ctl_waitq);
        spin_unlock(&svc->srv_lock);

        return rc;
}

static void ptlrpc_stop_thread(struct ptlrpc_service *svc,
                               struct ptlrpc_thread *thread)
{
        struct l_wait_info lwi = { 0 };

        spin_lock(&svc->srv_lock);
        thread->t_flags = SVC_STOPPING;
        spin_unlock(&svc->srv_lock);

        cfs_waitq_broadcast(&svc->srv_waitq);
        l_wait_event(thread->t_ctl_waitq, (thread->t_flags & SVC_STOPPED),
                     &lwi);

        spin_lock(&svc->srv_lock);
        list_del(&thread->t_link);
        spin_unlock(&svc->srv_lock);

        OBD_FREE_PTR(thread);
}

void ptlrpc_stop_all_threads(struct ptlrpc_service *svc)
{
        struct ptlrpc_thread *thread;

        spin_lock(&svc->srv_lock);
        while (!list_empty(&svc->srv_threads)) {
                thread = list_entry(svc->srv_threads.next,
                                    struct ptlrpc_thread, t_link);

                spin_unlock(&svc->srv_lock);
                ptlrpc_stop_thread(svc, thread);
                spin_lock(&svc->srv_lock);
        }

        spin_unlock(&svc->srv_lock);
}

int ptlrpc_start_threads(struct obd_device *dev, struct ptlrpc_service *svc)
{
        int i, rc = 0;
        ENTRY;

        LASSERT(svc->srv_threads_min > 0);
        for (i = 0; i < svc->srv_threads_min; i++) {
                rc = ptlrpc_start_thread(dev, svc);
                /* We have enough threads, don't start more.  b=15759 */
                if (rc == -EMFILE)
                        break;
                if (rc) {
                        CERROR("cannot start %s thread #%d: rc %d\n", 
                               svc->srv_thread_name, i, rc);
                        ptlrpc_stop_all_threads(svc);
                }
        }
        RETURN(rc);
}

int ptlrpc_start_thread(struct obd_device *dev, struct ptlrpc_service *svc)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_svc_data d;
        struct ptlrpc_thread *thread;
        char name[32];
        int id, rc;
        ENTRY;

        CDEBUG(D_RPCTRACE, "%s started %d min %d max %d running %d\n",
               svc->srv_name, svc->srv_threads_started, svc->srv_threads_min,
               svc->srv_threads_max, svc->srv_threads_running);
        if (unlikely(svc->srv_threads_started >= svc->srv_threads_max) ||
            (OBD_FAIL_CHECK(OBD_FAIL_TGT_TOOMANY_THREADS) &&
             svc->srv_threads_started == svc->srv_threads_min - 1))
                RETURN(-EMFILE);

        OBD_ALLOC_PTR(thread);
        if (thread == NULL)
                RETURN(-ENOMEM);
        cfs_waitq_init(&thread->t_ctl_waitq);

        spin_lock(&svc->srv_lock);
        if (svc->srv_threads_started >= svc->srv_threads_max) {
                spin_unlock(&svc->srv_lock);
                OBD_FREE_PTR(thread);
                RETURN(-EMFILE);
        }
        list_add(&thread->t_link, &svc->srv_threads);
        id = svc->srv_threads_started++;
        spin_unlock(&svc->srv_lock);

        thread->t_id = id;
        sprintf(name, "%s_%02d", svc->srv_thread_name, id);
        d.dev = dev;
        d.svc = svc;
        d.name = name;
        d.thread = thread;

        CDEBUG(D_RPCTRACE, "starting thread '%s'\n", name);
        
          /* CLONE_VM and CLONE_FILES just avoid a needless copy, because we
         * just drop the VM and FILES in ptlrpc_daemonize() right away.
         */
        rc = cfs_kernel_thread(ptlrpc_main, &d, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread '%s': rc %d\n", name, rc);

                spin_lock(&svc->srv_lock);
                list_del(&thread->t_link);
                --svc->srv_threads_started;
                spin_unlock(&svc->srv_lock);

                OBD_FREE(thread, sizeof(*thread));
                RETURN(rc);
        }
        l_wait_event(thread->t_ctl_waitq,
                     thread->t_flags & (SVC_RUNNING | SVC_STOPPED), &lwi);

        rc = (thread->t_flags & SVC_STOPPED) ? thread->t_id : 0;
        RETURN(rc);
}
#endif

int ptlrpc_unregister_service(struct ptlrpc_service *service)
{
        int                   rc;
        struct l_wait_info    lwi;
        struct list_head     *tmp;
        struct ptlrpc_reply_state *rs, *t;

        ptlrpc_stop_all_threads(service);
        LASSERT(list_empty(&service->srv_threads));

        spin_lock (&ptlrpc_all_services_lock);
        list_del_init (&service->srv_list);
        spin_unlock (&ptlrpc_all_services_lock);

        ptlrpc_lprocfs_unregister_service(service);

        /* All history will be culled when the next request buffer is
         * freed */
        service->srv_max_history_rqbds = 0;

        CDEBUG(D_NET, "%s: tearing down\n", service->srv_name);

        rc = LNetClearLazyPortal(service->srv_req_portal);
        LASSERT (rc == 0);

        /* Unlink all the request buffers.  This forces a 'final' event with
         * its 'unlink' flag set for each posted rqbd */
        list_for_each(tmp, &service->srv_active_rqbds) {
                struct ptlrpc_request_buffer_desc *rqbd =
                        list_entry(tmp, struct ptlrpc_request_buffer_desc,
                                   rqbd_list);

                rc = LNetMDUnlink(rqbd->rqbd_md_h);
                LASSERT (rc == 0 || rc == -ENOENT);
        }

        /* Wait for the network to release any buffers it's currently
         * filling */
        for (;;) {
                spin_lock(&service->srv_lock);
                rc = service->srv_nrqbd_receiving;
                spin_unlock(&service->srv_lock);

                if (rc == 0)
                        break;

                /* Network access will complete in finite time but the HUGE
                 * timeout lets us CWARN for visibility of sluggish NALs */
                lwi = LWI_TIMEOUT(cfs_time_seconds(300), NULL, NULL);
                rc = l_wait_event(service->srv_waitq,
                                  service->srv_nrqbd_receiving == 0,
                                  &lwi);
                if (rc == -ETIMEDOUT)
                        CWARN("Service %s waiting for request buffers\n",
                              service->srv_name);
        }

        /* schedule all outstanding replies to terminate them */
        spin_lock(&service->srv_lock);
        while (!list_empty(&service->srv_active_replies)) {
                struct ptlrpc_reply_state *rs =
                        list_entry(service->srv_active_replies.next,
                                   struct ptlrpc_reply_state, rs_list);
                ptlrpc_schedule_difficult_reply(rs);
        }
        spin_unlock(&service->srv_lock);

        /* purge the request queue.  NB No new replies (rqbds all unlinked)
         * and no service threads, so I'm the only thread noodling the
         * request queue now */
        while (!list_empty(&service->srv_request_queue)) {
                struct ptlrpc_request *req =
                        list_entry(service->srv_request_queue.next,
                                   struct ptlrpc_request,
                                   rq_list);

                list_del(&req->rq_list);
                service->srv_n_queued_reqs--;
                service->srv_n_active_reqs++;

                ptlrpc_server_free_request(req);
        }
        LASSERT(service->srv_n_queued_reqs == 0);
        LASSERT(service->srv_n_active_reqs == 0);
        LASSERT(service->srv_n_history_rqbds == 0);
        LASSERT(list_empty(&service->srv_active_rqbds));

        /* Now free all the request buffers since nothing references them
         * any more... */
        while (!list_empty(&service->srv_idle_rqbds)) {
                struct ptlrpc_request_buffer_desc *rqbd =
                        list_entry(service->srv_idle_rqbds.next,
                                   struct ptlrpc_request_buffer_desc,
                                   rqbd_list);

                ptlrpc_free_rqbd(rqbd);
        }

        /* wait for all outstanding replies to complete (they were
         * scheduled having been flagged to abort above) */
        while (atomic_read(&service->srv_outstanding_replies) != 0) {
                struct l_wait_info lwi = LWI_TIMEOUT(cfs_time_seconds(10), NULL, NULL);

                rc = l_wait_event(service->srv_waitq,
                                  !list_empty(&service->srv_reply_queue), &lwi);
                LASSERT(rc == 0 || rc == -ETIMEDOUT);

                if (rc == 0) {
                        ptlrpc_server_handle_reply(service);
                        continue;
                }
                CWARN("Unexpectedly long timeout %p\n", service);
        }

        list_for_each_entry_safe(rs, t, &service->srv_free_rs_list, rs_list) {
                list_del(&rs->rs_list);
                OBD_FREE(rs, service->srv_max_reply_size);
        }

        OBD_FREE_PTR(service);
        return 0;
}

/* Returns 0 if the service is healthy.
 *
 * Right now, it just checks to make sure that requests aren't languishing
 * in the queue.  We'll use this health check to govern whether a node needs
 * to be shot, so it's intentionally non-aggressive. */
int ptlrpc_service_health_check(struct ptlrpc_service *svc)
{
        struct ptlrpc_request *request;
        struct timeval         right_now;
        long                   timediff, cutoff;
        int                    rc = 0;

        if (svc == NULL)
                return 0;

        spin_lock(&svc->srv_lock);

        if (list_empty(&svc->srv_request_queue))
                goto out;

        request = list_entry(svc->srv_request_queue.next,
                             struct ptlrpc_request, rq_list);

        do_gettimeofday(&right_now);
        timediff = cfs_timeval_sub(&right_now, &request->rq_arrival_time, NULL);

        cutoff = obd_health_check_timeout;

        if (timediff / 1000000 > cutoff) {
                rc = -1;
                goto out;
        }

 out:
        spin_unlock(&svc->srv_lock);
        return rc;
}
