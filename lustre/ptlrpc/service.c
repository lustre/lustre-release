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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011 Whamcloud, Inc.
 *
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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

/* The following are visible and mutable through /sys/module/ptlrpc */
int test_req_buffer_pressure = 0;
CFS_MODULE_PARM(test_req_buffer_pressure, "i", int, 0444,
                "set non-zero to put pressure on request buffer pools");
CFS_MODULE_PARM(at_min, "i", int, 0644,
                "Adaptive timeout minimum (sec)");
CFS_MODULE_PARM(at_max, "i", int, 0644,
                "Adaptive timeout maximum (sec)");
CFS_MODULE_PARM(at_history, "i", int, 0644,
                "Adaptive timeouts remember the slowest event that took place "
                "within this period (sec)");
CFS_MODULE_PARM(at_early_margin, "i", int, 0644,
                "How soon before an RPC deadline to send an early reply");
CFS_MODULE_PARM(at_extra, "i", int, 0644,
                "How much extra time to give with each early reply");


/* forward ref */
static int ptlrpc_server_post_idle_rqbds (struct ptlrpc_service *svc);

static CFS_LIST_HEAD(ptlrpc_all_services);
cfs_spinlock_t ptlrpc_all_services_lock;

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
        OBD_ALLOC_LARGE(rqbd->rqbd_buffer, svc->srv_buf_size);

        if (rqbd->rqbd_buffer == NULL) {
                OBD_FREE_PTR(rqbd);
                return (NULL);
        }

        cfs_spin_lock(&svc->srv_lock);
        cfs_list_add(&rqbd->rqbd_list, &svc->srv_idle_rqbds);
        svc->srv_nbufs++;
        cfs_spin_unlock(&svc->srv_lock);

        return (rqbd);
}

void
ptlrpc_free_rqbd (struct ptlrpc_request_buffer_desc *rqbd)
{
        struct ptlrpc_service *svc = rqbd->rqbd_service;

        LASSERT (rqbd->rqbd_refcount == 0);
        LASSERT (cfs_list_empty(&rqbd->rqbd_reqs));

        cfs_spin_lock(&svc->srv_lock);
        cfs_list_del(&rqbd->rqbd_list);
        svc->srv_nbufs--;
        cfs_spin_unlock(&svc->srv_lock);

        OBD_FREE_LARGE(rqbd->rqbd_buffer, svc->srv_buf_size);
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

/**
 * Part of Rep-Ack logic.
 * Puts a lock and its mode into reply state assotiated to request reply.
 */
void
ptlrpc_save_lock(struct ptlrpc_request *req,
                 struct lustre_handle *lock, int mode, int no_ack)
{
        struct ptlrpc_reply_state *rs = req->rq_reply_state;
        int                        idx;

        LASSERT(rs != NULL);
        LASSERT(rs->rs_nlocks < RS_MAX_LOCKS);

        if (req->rq_export->exp_disconnected) {
                ldlm_lock_decref(lock, mode);
        } else {
                idx = rs->rs_nlocks++;
                rs->rs_locks[idx] = *lock;
                rs->rs_modes[idx] = mode;
                rs->rs_difficult = 1;
                rs->rs_no_ack = !!no_ack;
        }
}

#ifdef __KERNEL__

#define HRT_RUNNING 0
#define HRT_STOPPING 1

struct ptlrpc_hr_thread {
        cfs_spinlock_t        hrt_lock;
        unsigned long         hrt_flags;
        cfs_waitq_t           hrt_wait;
        cfs_list_t            hrt_queue;
        cfs_completion_t      hrt_completion;
};

struct ptlrpc_hr_service {
        int                     hr_index;
        int                     hr_n_threads;
        int                     hr_size;
        struct ptlrpc_hr_thread hr_threads[0];
};

struct rs_batch {
        cfs_list_t              rsb_replies;
        struct ptlrpc_service  *rsb_svc;
        unsigned int            rsb_n_replies;
};

/**
 *  A pointer to per-node reply handling service.
 */
static struct ptlrpc_hr_service *ptlrpc_hr = NULL;

/**
 * maximum mumber of replies scheduled in one batch
 */
#define MAX_SCHEDULED 256

/**
 * Initialize a reply batch.
 *
 * \param b batch
 */
static void rs_batch_init(struct rs_batch *b)
{
        memset(b, 0, sizeof *b);
        CFS_INIT_LIST_HEAD(&b->rsb_replies);
}

/**
 * Choose an hr thread to dispatch requests to.
 */
static unsigned int get_hr_thread_index(struct ptlrpc_hr_service *hr)
{
        unsigned int idx;

        /* Concurrent modification of hr_index w/o any spinlock
           protection is harmless as long as the result fits
           [0..(hr_n_threads-1)] range and each thread gets near equal
           load. */
        idx = hr->hr_index;
        hr->hr_index = (idx >= hr->hr_n_threads - 1) ? 0 : idx + 1;
        return idx;
}

/**
 * Dispatch all replies accumulated in the batch to one from
 * dedicated reply handling threads.
 *
 * \param b batch
 */
static void rs_batch_dispatch(struct rs_batch *b)
{
        if (b->rsb_n_replies != 0) {
                struct ptlrpc_hr_service *hr = ptlrpc_hr;
                int idx;

                idx = get_hr_thread_index(hr);

                cfs_spin_lock(&hr->hr_threads[idx].hrt_lock);
                cfs_list_splice_init(&b->rsb_replies,
                                     &hr->hr_threads[idx].hrt_queue);
                cfs_spin_unlock(&hr->hr_threads[idx].hrt_lock);
                cfs_waitq_signal(&hr->hr_threads[idx].hrt_wait);
                b->rsb_n_replies = 0;
        }
}

/**
 * Add a reply to a batch.
 * Add one reply object to a batch, schedule batched replies if overload.
 *
 * \param b batch
 * \param rs reply
 */
static void rs_batch_add(struct rs_batch *b, struct ptlrpc_reply_state *rs)
{
        struct ptlrpc_service *svc = rs->rs_service;

        if (svc != b->rsb_svc || b->rsb_n_replies >= MAX_SCHEDULED) {
                if (b->rsb_svc != NULL) {
                        rs_batch_dispatch(b);
                        cfs_spin_unlock(&b->rsb_svc->srv_rs_lock);
                }
                cfs_spin_lock(&svc->srv_rs_lock);
                b->rsb_svc = svc;
        }
        cfs_spin_lock(&rs->rs_lock);
        rs->rs_scheduled_ever = 1;
        if (rs->rs_scheduled == 0) {
                cfs_list_move(&rs->rs_list, &b->rsb_replies);
                rs->rs_scheduled = 1;
                b->rsb_n_replies++;
        }
        rs->rs_committed = 1;
        cfs_spin_unlock(&rs->rs_lock);
}

/**
 * Reply batch finalization.
 * Dispatch remaining replies from the batch
 * and release remaining spinlock.
 *
 * \param b batch
 */
static void rs_batch_fini(struct rs_batch *b)
{
        if (b->rsb_svc != 0) {
                rs_batch_dispatch(b);
                cfs_spin_unlock(&b->rsb_svc->srv_rs_lock);
        }
}

#define DECLARE_RS_BATCH(b)     struct rs_batch b

#else /* __KERNEL__ */

#define rs_batch_init(b)        do{}while(0)
#define rs_batch_fini(b)        do{}while(0)
#define rs_batch_add(b, r)      ptlrpc_schedule_difficult_reply(r)
#define DECLARE_RS_BATCH(b)

#endif /* __KERNEL__ */

/**
 * Put reply state into a queue for processing because we received
 * ACK from the client
 */
void ptlrpc_dispatch_difficult_reply(struct ptlrpc_reply_state *rs)
{
#ifdef __KERNEL__
        struct ptlrpc_hr_service *hr = ptlrpc_hr;
        int idx;
        ENTRY;

        LASSERT(cfs_list_empty(&rs->rs_list));

        idx = get_hr_thread_index(hr);
        cfs_spin_lock(&hr->hr_threads[idx].hrt_lock);
        cfs_list_add_tail(&rs->rs_list, &hr->hr_threads[idx].hrt_queue);
        cfs_spin_unlock(&hr->hr_threads[idx].hrt_lock);
        cfs_waitq_signal(&hr->hr_threads[idx].hrt_wait);
        EXIT;
#else
        cfs_list_add_tail(&rs->rs_list, &rs->rs_service->srv_reply_queue);
#endif
}

void
ptlrpc_schedule_difficult_reply (struct ptlrpc_reply_state *rs)
{
        ENTRY;

        LASSERT_SPIN_LOCKED(&rs->rs_service->srv_rs_lock);
        LASSERT_SPIN_LOCKED(&rs->rs_lock);
        LASSERT (rs->rs_difficult);
        rs->rs_scheduled_ever = 1;  /* flag any notification attempt */

        if (rs->rs_scheduled) {     /* being set up or already notified */
                EXIT;
                return;
        }

        rs->rs_scheduled = 1;
        cfs_list_del_init(&rs->rs_list);
        ptlrpc_dispatch_difficult_reply(rs);
        EXIT;
}

void ptlrpc_commit_replies(struct obd_export *exp)
{
        struct ptlrpc_reply_state *rs, *nxt;
        DECLARE_RS_BATCH(batch);
        ENTRY;

        rs_batch_init(&batch);
        /* Find any replies that have been committed and get their service
         * to attend to complete them. */

        /* CAVEAT EMPTOR: spinlock ordering!!! */
        cfs_spin_lock(&exp->exp_uncommitted_replies_lock);
        cfs_list_for_each_entry_safe(rs, nxt, &exp->exp_uncommitted_replies,
                                     rs_obd_list) {
                LASSERT (rs->rs_difficult);
                /* VBR: per-export last_committed */
                LASSERT(rs->rs_export);
                if (rs->rs_transno <= exp->exp_last_committed) {
                        cfs_list_del_init(&rs->rs_obd_list);
                        rs_batch_add(&batch, rs);
                }
        }
        cfs_spin_unlock(&exp->exp_uncommitted_replies_lock);
        rs_batch_fini(&batch);
        EXIT;
}

static int
ptlrpc_server_post_idle_rqbds (struct ptlrpc_service *svc)
{
        struct ptlrpc_request_buffer_desc *rqbd;
        int                                rc;
        int                                posted = 0;

        for (;;) {
                cfs_spin_lock(&svc->srv_lock);

                if (cfs_list_empty (&svc->srv_idle_rqbds)) {
                        cfs_spin_unlock(&svc->srv_lock);
                        return (posted);
                }

                rqbd = cfs_list_entry(svc->srv_idle_rqbds.next,
                                      struct ptlrpc_request_buffer_desc,
                                      rqbd_list);
                cfs_list_del (&rqbd->rqbd_list);

                /* assume we will post successfully */
                svc->srv_nrqbd_receiving++;
                cfs_list_add (&rqbd->rqbd_list, &svc->srv_active_rqbds);

                cfs_spin_unlock(&svc->srv_lock);

                rc = ptlrpc_register_rqbd(rqbd);
                if (rc != 0)
                        break;

                posted = 1;
        }

        cfs_spin_lock(&svc->srv_lock);

        svc->srv_nrqbd_receiving--;
        cfs_list_del(&rqbd->rqbd_list);
        cfs_list_add_tail(&rqbd->rqbd_list, &svc->srv_idle_rqbds);

        /* Don't complain if no request buffers are posted right now; LNET
         * won't drop requests because we set the portal lazy! */

        cfs_spin_unlock(&svc->srv_lock);

        return (-1);
}

/**
 * Start a service with parameters from struct ptlrpc_service_conf \a c
 * as opposed to directly calling ptlrpc_init_svc with tons of arguments.
 */
struct ptlrpc_service *ptlrpc_init_svc_conf(struct ptlrpc_service_conf *c,
                                            svc_handler_t h, char *name,
                                            struct proc_dir_entry *proc_entry,
                                            svc_req_printfn_t prntfn,
                                            char *threadname)
{
        return ptlrpc_init_svc(c->psc_nbufs, c->psc_bufsize,
                               c->psc_max_req_size, c->psc_max_reply_size,
                               c->psc_req_portal, c->psc_rep_portal,
                               c->psc_watchdog_factor,
                               h, name, proc_entry,
                               prntfn, c->psc_min_threads, c->psc_max_threads,
                               threadname, c->psc_ctx_tags, NULL);
}
EXPORT_SYMBOL(ptlrpc_init_svc_conf);

static void ptlrpc_at_timer(unsigned long castmeharder)
{
        struct ptlrpc_service *svc = (struct ptlrpc_service *)castmeharder;
        svc->srv_at_check = 1;
        svc->srv_at_checktime = cfs_time_current();
        cfs_waitq_signal(&svc->srv_waitq);
}

/**
 * Initialize service on a given portal.
 * This includes starting serving threads , allocating and posting rqbds and
 * so on.
 * \a nbufs is how many buffers to post
 * \a bufsize is buffer size to post
 * \a max_req_size - maximum request size to be accepted for this service
 * \a max_reply_size maximum reply size this service can ever send
 * \a req_portal - portal to listed for requests on
 * \a rep_portal - portal of where to send replies to
 * \a watchdog_factor soft watchdog timeout multiplifier to print stuck service traces.
 * \a handler - function to process every new request
 * \a name - service name
 * \a proc_entry - entry in the /proc tree for sttistics reporting
 * \a min_threads \a max_threads - min/max number of service threads to start.
 * \a threadname should be 11 characters or less - 3 will be added on
 * \a hp_handler - function to determine priority of the request, also called
 *                 on every new request.
 */
struct ptlrpc_service *
ptlrpc_init_svc(int nbufs, int bufsize, int max_req_size, int max_reply_size,
                int req_portal, int rep_portal, int watchdog_factor,
                svc_handler_t handler, char *name,
                cfs_proc_dir_entry_t *proc_entry,
                svc_req_printfn_t svcreq_printfn,
                int min_threads, int max_threads,
                char *threadname, __u32 ctx_tags,
                svc_hpreq_handler_t hp_handler)
{
        int                     rc;
        struct ptlrpc_at_array *array;
        struct ptlrpc_service  *service;
        unsigned int            size, index;
        ENTRY;

        LASSERT (nbufs > 0);
        LASSERT (bufsize >= max_req_size + SPTLRPC_MAX_PAYLOAD);
        LASSERT (ctx_tags != 0);

        OBD_ALLOC_PTR(service);
        if (service == NULL)
                RETURN(NULL);

        /* First initialise enough for early teardown */

        service->srv_name = name;
        cfs_spin_lock_init(&service->srv_lock);
        cfs_spin_lock_init(&service->srv_rq_lock);
        cfs_spin_lock_init(&service->srv_rs_lock);
        CFS_INIT_LIST_HEAD(&service->srv_threads);
        cfs_waitq_init(&service->srv_waitq);

        service->srv_nbuf_per_group = test_req_buffer_pressure ? 1 : nbufs;
        service->srv_max_req_size = max_req_size + SPTLRPC_MAX_PAYLOAD;
        service->srv_buf_size = bufsize;
        service->srv_rep_portal = rep_portal;
        service->srv_req_portal = req_portal;
        service->srv_watchdog_factor = watchdog_factor;
        service->srv_handler = handler;
        service->srv_req_printfn = svcreq_printfn;
        service->srv_request_seq = 1;           /* valid seq #s start at 1 */
        service->srv_request_max_cull_seq = 0;
        service->srv_threads_min = min_threads;
        service->srv_threads_max = max_threads;
        service->srv_thread_name = threadname;
        service->srv_ctx_tags = ctx_tags;
        service->srv_hpreq_handler = hp_handler;
        service->srv_hpreq_ratio = PTLRPC_SVC_HP_RATIO;
        service->srv_hpreq_count = 0;
        service->srv_n_active_hpreq = 0;

        rc = LNetSetLazyPortal(service->srv_req_portal);
        LASSERT (rc == 0);

        CFS_INIT_LIST_HEAD(&service->srv_request_queue);
        CFS_INIT_LIST_HEAD(&service->srv_request_hpq);
        CFS_INIT_LIST_HEAD(&service->srv_idle_rqbds);
        CFS_INIT_LIST_HEAD(&service->srv_active_rqbds);
        CFS_INIT_LIST_HEAD(&service->srv_history_rqbds);
        CFS_INIT_LIST_HEAD(&service->srv_request_history);
        CFS_INIT_LIST_HEAD(&service->srv_active_replies);
#ifndef __KERNEL__
        CFS_INIT_LIST_HEAD(&service->srv_reply_queue);
#endif
        CFS_INIT_LIST_HEAD(&service->srv_free_rs_list);
        cfs_waitq_init(&service->srv_free_rs_waitq);
        cfs_atomic_set(&service->srv_n_difficult_replies, 0);

        cfs_spin_lock_init(&service->srv_at_lock);
        CFS_INIT_LIST_HEAD(&service->srv_req_in_queue);

        array = &service->srv_at_array;
        size = at_est2timeout(at_max);
        array->paa_size = size;
        array->paa_count = 0;
        array->paa_deadline = -1;

        /* allocate memory for srv_at_array (ptlrpc_at_array) */
        OBD_ALLOC(array->paa_reqs_array, sizeof(cfs_list_t) * size);
        if (array->paa_reqs_array == NULL)
                GOTO(failed, NULL);

        for (index = 0; index < size; index++)
                CFS_INIT_LIST_HEAD(&array->paa_reqs_array[index]);

        OBD_ALLOC(array->paa_reqs_count, sizeof(__u32) * size);
        if (array->paa_reqs_count == NULL)
                GOTO(failed, NULL);

        cfs_timer_init(&service->srv_at_timer, ptlrpc_at_timer, service);
        /* At SOW, service time should be quick; 10s seems generous. If client
           timeout is less than this, we'll be sending an early reply. */
        at_init(&service->srv_at_estimate, 10, 0);

        cfs_spin_lock (&ptlrpc_all_services_lock);
        cfs_list_add (&service->srv_list, &ptlrpc_all_services);
        cfs_spin_unlock (&ptlrpc_all_services_lock);

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

/**
 * to actually free the request, must be called without holding svc_lock.
 * note it's caller's responsibility to unlink req->rq_list.
 */
static void ptlrpc_server_free_request(struct ptlrpc_request *req)
{
        LASSERT(cfs_atomic_read(&req->rq_refcount) == 0);
        LASSERT(cfs_list_empty(&req->rq_timed_list));

         /* DEBUG_REQ() assumes the reply state of a request with a valid
          * ref will not be destroyed until that reference is dropped. */
        ptlrpc_req_drop_rs(req);

        sptlrpc_svc_ctx_decref(req);

        if (req != &req->rq_rqbd->rqbd_req) {
                /* NB request buffers use an embedded
                 * req if the incoming req unlinked the
                 * MD; this isn't one of them! */
                OBD_FREE(req, sizeof(*req));
        }
}

/**
 * drop a reference count of the request. if it reaches 0, we either
 * put it into history list, or free it immediately.
 */
void ptlrpc_server_drop_request(struct ptlrpc_request *req)
{
        struct ptlrpc_request_buffer_desc *rqbd = req->rq_rqbd;
        struct ptlrpc_service             *svc = rqbd->rqbd_service;
        int                                refcount;
        cfs_list_t                        *tmp;
        cfs_list_t                        *nxt;

        if (!cfs_atomic_dec_and_test(&req->rq_refcount))
                return;

        cfs_spin_lock(&svc->srv_at_lock);
        if (req->rq_at_linked) {
                struct ptlrpc_at_array *array = &svc->srv_at_array;
                __u32 index = req->rq_at_index;

                LASSERT(!cfs_list_empty(&req->rq_timed_list));
                cfs_list_del_init(&req->rq_timed_list);
                cfs_spin_lock(&req->rq_lock);
                req->rq_at_linked = 0;
                cfs_spin_unlock(&req->rq_lock);
                array->paa_reqs_count[index]--;
                array->paa_count--;
        } else
                LASSERT(cfs_list_empty(&req->rq_timed_list));
        cfs_spin_unlock(&svc->srv_at_lock);

        /* finalize request */
        if (req->rq_export) {
                class_export_put(req->rq_export);
                req->rq_export = NULL;
        }

        cfs_spin_lock(&svc->srv_lock);

        cfs_list_add(&req->rq_list, &rqbd->rqbd_reqs);

        refcount = --(rqbd->rqbd_refcount);
        if (refcount == 0) {
                /* request buffer is now idle: add to history */
                cfs_list_del(&rqbd->rqbd_list);
                cfs_list_add_tail(&rqbd->rqbd_list, &svc->srv_history_rqbds);
                svc->srv_n_history_rqbds++;

                /* cull some history?
                 * I expect only about 1 or 2 rqbds need to be recycled here */
                while (svc->srv_n_history_rqbds > svc->srv_max_history_rqbds) {
                        rqbd = cfs_list_entry(svc->srv_history_rqbds.next,
                                              struct ptlrpc_request_buffer_desc,
                                              rqbd_list);

                        cfs_list_del(&rqbd->rqbd_list);
                        svc->srv_n_history_rqbds--;

                        /* remove rqbd's reqs from svc's req history while
                         * I've got the service lock */
                        cfs_list_for_each(tmp, &rqbd->rqbd_reqs) {
                                req = cfs_list_entry(tmp, struct ptlrpc_request,
                                                     rq_list);
                                /* Track the highest culled req seq */
                                if (req->rq_history_seq >
                                    svc->srv_request_max_cull_seq)
                                        svc->srv_request_max_cull_seq =
                                                req->rq_history_seq;
                                cfs_list_del(&req->rq_history_list);
                        }

                        cfs_spin_unlock(&svc->srv_lock);

                        cfs_list_for_each_safe(tmp, nxt, &rqbd->rqbd_reqs) {
                                req = cfs_list_entry(rqbd->rqbd_reqs.next,
                                                     struct ptlrpc_request,
                                                     rq_list);
                                cfs_list_del(&req->rq_list);
                                ptlrpc_server_free_request(req);
                        }

                        cfs_spin_lock(&svc->srv_lock);
                        /*
                         * now all reqs including the embedded req has been
                         * disposed, schedule request buffer for re-use.
                         */
                        LASSERT(cfs_atomic_read(&rqbd->rqbd_req.rq_refcount) ==
                                0);
                        cfs_list_add_tail(&rqbd->rqbd_list,
                                          &svc->srv_idle_rqbds);
                }

                cfs_spin_unlock(&svc->srv_lock);
        } else if (req->rq_reply_state && req->rq_reply_state->rs_prealloc) {
                /* If we are low on memory, we are not interested in history */
                cfs_list_del(&req->rq_list);
                cfs_list_del_init(&req->rq_history_list);
                cfs_spin_unlock(&svc->srv_lock);

                ptlrpc_server_free_request(req);
        } else {
                cfs_spin_unlock(&svc->srv_lock);
        }
}

/**
 * to finish a request: stop sending more early replies, and release
 * the request. should be called after we finished handling the request.
 */
static void ptlrpc_server_finish_request(struct ptlrpc_service *svc,
                                         struct ptlrpc_request *req)
{
        cfs_spin_lock(&svc->srv_rq_lock);
        svc->srv_n_active_reqs--;
        if (req->rq_hp)
                svc->srv_n_active_hpreq--;
        cfs_spin_unlock(&svc->srv_rq_lock);

        ptlrpc_server_drop_request(req);
}

/**
 * This function makes sure dead exports are evicted in a timely manner.
 * This function is only called when some export receives a message (i.e.,
 * the network is up.)
 */
static void ptlrpc_update_export_timer(struct obd_export *exp, long extra_delay)
{
        struct obd_export *oldest_exp;
        time_t oldest_time, new_time;

        ENTRY;

        LASSERT(exp);

        /* Compensate for slow machines, etc, by faking our request time
           into the future.  Although this can break the strict time-ordering
           of the list, we can be really lazy here - we don't have to evict
           at the exact right moment.  Eventually, all silent exports
           will make it to the top of the list. */

        /* Do not pay attention on 1sec or smaller renewals. */
        new_time = cfs_time_current_sec() + extra_delay;
        if (exp->exp_last_request_time + 1 /*second */ >= new_time)
                RETURN_EXIT;

        exp->exp_last_request_time = new_time;
        CDEBUG(D_HA, "updating export %s at "CFS_TIME_T" exp %p\n",
               exp->exp_client_uuid.uuid,
               exp->exp_last_request_time, exp);

        /* exports may get disconnected from the chain even though the
           export has references, so we must keep the spin lock while
           manipulating the lists */
        cfs_spin_lock(&exp->exp_obd->obd_dev_lock);

        if (cfs_list_empty(&exp->exp_obd_chain_timed)) {
                /* this one is not timed */
                cfs_spin_unlock(&exp->exp_obd->obd_dev_lock);
                RETURN_EXIT;
        }

        cfs_list_move_tail(&exp->exp_obd_chain_timed,
                           &exp->exp_obd->obd_exports_timed);

        oldest_exp = cfs_list_entry(exp->exp_obd->obd_exports_timed.next,
                                    struct obd_export, exp_obd_chain_timed);
        oldest_time = oldest_exp->exp_last_request_time;
        cfs_spin_unlock(&exp->exp_obd->obd_dev_lock);

        if (exp->exp_obd->obd_recovering) {
                /* be nice to everyone during recovery */
                EXIT;
                return;
        }

        /* Note - racing to start/reset the obd_eviction timer is safe */
        if (exp->exp_obd->obd_eviction_timer == 0) {
                /* Check if the oldest entry is expired. */
                if (cfs_time_current_sec() > (oldest_time + PING_EVICT_TIMEOUT +
                                              extra_delay)) {
                        /* We need a second timer, in case the net was down and
                         * it just came back. Since the pinger may skip every
                         * other PING_INTERVAL (see note in ptlrpc_pinger_main),
                         * we better wait for 3. */
                        exp->exp_obd->obd_eviction_timer =
                                cfs_time_current_sec() + 3 * PING_INTERVAL;
                        CDEBUG(D_HA, "%s: Think about evicting %s from "CFS_TIME_T"\n",
                               exp->exp_obd->obd_name, 
                               obd_export_nid2str(oldest_exp), oldest_time);
                }
        } else {
                if (cfs_time_current_sec() >
                    (exp->exp_obd->obd_eviction_timer + extra_delay)) {
                        /* The evictor won't evict anyone who we've heard from
                         * recently, so we don't have to check before we start
                         * it. */
                        if (!ping_evictor_wake(exp))
                                exp->exp_obd->obd_eviction_timer = 0;
                }
        }

        EXIT;
}

/**
 * Sanity check request \a req.
 * Return 0 if all is ok, error code otherwise.
 */
static int ptlrpc_check_req(struct ptlrpc_request *req)
{
        int rc = 0;

        if (unlikely(lustre_msg_get_conn_cnt(req->rq_reqmsg) <
                     req->rq_export->exp_conn_cnt)) {
                DEBUG_REQ(D_ERROR, req,
                          "DROPPING req from old connection %d < %d",
                          lustre_msg_get_conn_cnt(req->rq_reqmsg),
                          req->rq_export->exp_conn_cnt);
                return -EEXIST;
        }
        if (unlikely(req->rq_export->exp_obd &&
                     req->rq_export->exp_obd->obd_fail)) {
             /* Failing over, don't handle any more reqs, send
                error response instead. */
                CDEBUG(D_RPCTRACE, "Dropping req %p for failed obd %s\n",
                       req, req->rq_export->exp_obd->obd_name);
                rc = -ENODEV;
        } else if (lustre_msg_get_flags(req->rq_reqmsg) &
                   (MSG_REPLAY | MSG_REQ_REPLAY_DONE) &&
                   !(req->rq_export->exp_obd->obd_recovering)) {
                        DEBUG_REQ(D_ERROR, req,
                                  "Invalid replay without recovery");
                        class_fail_export(req->rq_export);
                        rc = -ENODEV;
        } else if (lustre_msg_get_transno(req->rq_reqmsg) != 0 &&
                   !(req->rq_export->exp_obd->obd_recovering)) {
                        DEBUG_REQ(D_ERROR, req, "Invalid req with transno "
                                  LPU64" without recovery",
                                  lustre_msg_get_transno(req->rq_reqmsg));
                        class_fail_export(req->rq_export);
                        rc = -ENODEV;
        }

        if (unlikely(rc < 0)) {
                req->rq_status = rc;
                ptlrpc_error(req);
        }
        return rc;
}

static void ptlrpc_at_set_timer(struct ptlrpc_service *svc)
{
        struct ptlrpc_at_array *array = &svc->srv_at_array;
        __s32 next;

        cfs_spin_lock(&svc->srv_at_lock);
        if (array->paa_count == 0) {
                cfs_timer_disarm(&svc->srv_at_timer);
                cfs_spin_unlock(&svc->srv_at_lock);
                return;
        }

        /* Set timer for closest deadline */
        next = (__s32)(array->paa_deadline - cfs_time_current_sec() -
                       at_early_margin);
        if (next <= 0)
                ptlrpc_at_timer((unsigned long)svc);
        else
                cfs_timer_arm(&svc->srv_at_timer, cfs_time_shift(next));
        cfs_spin_unlock(&svc->srv_at_lock);
        CDEBUG(D_INFO, "armed %s at %+ds\n", svc->srv_name, next);
}

/* Add rpc to early reply check list */
static int ptlrpc_at_add_timed(struct ptlrpc_request *req)
{
        struct ptlrpc_service *svc = req->rq_rqbd->rqbd_service;
        struct ptlrpc_request *rq = NULL;
        struct ptlrpc_at_array *array = &svc->srv_at_array;
        __u32 index;
        int found = 0;

        if (AT_OFF)
                return(0);

        if (req->rq_no_reply)
                return 0;

        if ((lustre_msghdr_get_flags(req->rq_reqmsg) & MSGHDR_AT_SUPPORT) == 0)
                return(-ENOSYS);

        cfs_spin_lock(&svc->srv_at_lock);
        LASSERT(cfs_list_empty(&req->rq_timed_list));

        index = (unsigned long)req->rq_deadline % array->paa_size;
        if (array->paa_reqs_count[index] > 0) {
                /* latest rpcs will have the latest deadlines in the list,
                 * so search backward. */
                cfs_list_for_each_entry_reverse(rq,
                                                &array->paa_reqs_array[index],
                                                rq_timed_list) {
                        if (req->rq_deadline >= rq->rq_deadline) {
                                cfs_list_add(&req->rq_timed_list,
                                             &rq->rq_timed_list);
                                break;
                        }
                }
        }

        /* Add the request at the head of the list */
        if (cfs_list_empty(&req->rq_timed_list))
                cfs_list_add(&req->rq_timed_list,
                             &array->paa_reqs_array[index]);

        cfs_spin_lock(&req->rq_lock);
        req->rq_at_linked = 1;
        cfs_spin_unlock(&req->rq_lock);
        req->rq_at_index = index;
        array->paa_reqs_count[index]++;
        array->paa_count++;
        if (array->paa_count == 1 || array->paa_deadline > req->rq_deadline) {
                array->paa_deadline = req->rq_deadline;
                found = 1;
        }
        cfs_spin_unlock(&svc->srv_at_lock);

        if (found)
                ptlrpc_at_set_timer(svc);

        return 0;
}

static int ptlrpc_at_send_early_reply(struct ptlrpc_request *req)
{
        struct ptlrpc_service *svc = req->rq_rqbd->rqbd_service;
        struct ptlrpc_request *reqcopy;
        struct lustre_msg *reqmsg;
        cfs_duration_t olddl = req->rq_deadline - cfs_time_current_sec();
        time_t newdl;
        int rc;
        ENTRY;

        /* deadline is when the client expects us to reply, margin is the
           difference between clients' and servers' expectations */
        DEBUG_REQ(D_ADAPTTO, req,
                  "%ssending early reply (deadline %+lds, margin %+lds) for "
                  "%d+%d", AT_OFF ? "AT off - not " : "",
                  olddl, olddl - at_get(&svc->srv_at_estimate),
                  at_get(&svc->srv_at_estimate), at_extra);

        if (AT_OFF)
                RETURN(0);

        if (olddl < 0) {
                DEBUG_REQ(D_WARNING, req, "Already past deadline (%+lds), "
                          "not sending early reply. Consider increasing "
                          "at_early_margin (%d)?", olddl, at_early_margin);

                /* Return an error so we're not re-added to the timed list. */
                RETURN(-ETIMEDOUT);
        }

        if ((lustre_msghdr_get_flags(req->rq_reqmsg) & MSGHDR_AT_SUPPORT) == 0){
                DEBUG_REQ(D_INFO, req, "Wanted to ask client for more time, "
                          "but no AT support");
                RETURN(-ENOSYS);
        }

        if (req->rq_export &&
            lustre_msg_get_flags(req->rq_reqmsg) &
            (MSG_REPLAY | MSG_REQ_REPLAY_DONE | MSG_LOCK_REPLAY_DONE)) {
                /* During recovery, we don't want to send too many early
                 * replies, but on the other hand we want to make sure the
                 * client has enough time to resend if the rpc is lost. So
                 * during the recovery period send at least 4 early replies,
                 * spacing them every at_extra if we can. at_estimate should
                 * always equal this fixed value during recovery. */
                at_measured(&svc->srv_at_estimate, min(at_extra,
                            req->rq_export->exp_obd->obd_recovery_timeout / 4));
        } else {
                /* Fake our processing time into the future to ask the clients
                 * for some extra amount of time */
                at_measured(&svc->srv_at_estimate, at_extra +
                            cfs_time_current_sec() -
                            req->rq_arrival_time.tv_sec);

                /* Check to see if we've actually increased the deadline -
                 * we may be past adaptive_max */
                if (req->rq_deadline >= req->rq_arrival_time.tv_sec +
                    at_get(&svc->srv_at_estimate)) {
                        DEBUG_REQ(D_WARNING, req, "Couldn't add any time "
                                  "(%ld/%ld), not sending early reply\n",
                                  olddl, req->rq_arrival_time.tv_sec +
                                  at_get(&svc->srv_at_estimate) -
                                  cfs_time_current_sec());
                        RETURN(-ETIMEDOUT);
                }
        }
        newdl = cfs_time_current_sec() + at_get(&svc->srv_at_estimate);

        OBD_ALLOC(reqcopy, sizeof *reqcopy);
        if (reqcopy == NULL)
                RETURN(-ENOMEM);
        OBD_ALLOC_LARGE(reqmsg, req->rq_reqlen);
        if (!reqmsg) {
                OBD_FREE(reqcopy, sizeof *reqcopy);
                RETURN(-ENOMEM);
        }

        *reqcopy = *req;
        reqcopy->rq_reply_state = NULL;
        reqcopy->rq_rep_swab_mask = 0;
        reqcopy->rq_pack_bulk = 0;
        reqcopy->rq_pack_udesc = 0;
        reqcopy->rq_packed_final = 0;
        sptlrpc_svc_ctx_addref(reqcopy);
        /* We only need the reqmsg for the magic */
        reqcopy->rq_reqmsg = reqmsg;
        memcpy(reqmsg, req->rq_reqmsg, req->rq_reqlen);

        LASSERT(cfs_atomic_read(&req->rq_refcount));
        /** if it is last refcount then early reply isn't needed */
        if (cfs_atomic_read(&req->rq_refcount) == 1) {
                DEBUG_REQ(D_ADAPTTO, reqcopy, "Normal reply already sent out, "
                          "abort sending early reply\n");
                GOTO(out, rc = -EINVAL);
        }

        /* Connection ref */
        reqcopy->rq_export = class_conn2export(
                                     lustre_msg_get_handle(reqcopy->rq_reqmsg));
        if (reqcopy->rq_export == NULL)
                GOTO(out, rc = -ENODEV);

        /* RPC ref */
        class_export_rpc_get(reqcopy->rq_export);
        if (reqcopy->rq_export->exp_obd &&
            reqcopy->rq_export->exp_obd->obd_fail)
                GOTO(out_put, rc = -ENODEV);

        rc = lustre_pack_reply_flags(reqcopy, 1, NULL, NULL, LPRFL_EARLY_REPLY);
        if (rc)
                GOTO(out_put, rc);

        rc = ptlrpc_send_reply(reqcopy, PTLRPC_REPLY_EARLY);

        if (!rc) {
                /* Adjust our own deadline to what we told the client */
                req->rq_deadline = newdl;
                req->rq_early_count++; /* number sent, server side */
        } else {
                DEBUG_REQ(D_ERROR, req, "Early reply send failed %d", rc);
        }

        /* Free the (early) reply state from lustre_pack_reply.
           (ptlrpc_send_reply takes it's own rs ref, so this is safe here) */
        ptlrpc_req_drop_rs(reqcopy);

out_put:
        class_export_rpc_put(reqcopy->rq_export);
        class_export_put(reqcopy->rq_export);
out:
        sptlrpc_svc_ctx_decref(reqcopy);
        OBD_FREE_LARGE(reqmsg, req->rq_reqlen);
        OBD_FREE(reqcopy, sizeof *reqcopy);
        RETURN(rc);
}

/* Send early replies to everybody expiring within at_early_margin
   asking for at_extra time */
static int ptlrpc_at_check_timed(struct ptlrpc_service *svc)
{
        struct ptlrpc_request *rq, *n;
        cfs_list_t work_list;
        struct ptlrpc_at_array *array = &svc->srv_at_array;
        __u32  index, count;
        time_t deadline;
        time_t now = cfs_time_current_sec();
        cfs_duration_t delay;
        int first, counter = 0;
        ENTRY;

        cfs_spin_lock(&svc->srv_at_lock);
        if (svc->srv_at_check == 0) {
                cfs_spin_unlock(&svc->srv_at_lock);
                RETURN(0);
        }
        delay = cfs_time_sub(cfs_time_current(), svc->srv_at_checktime);
        svc->srv_at_check = 0;

        if (array->paa_count == 0) {
                cfs_spin_unlock(&svc->srv_at_lock);
                RETURN(0);
        }

        /* The timer went off, but maybe the nearest rpc already completed. */
        first = array->paa_deadline - now;
        if (first > at_early_margin) {
                /* We've still got plenty of time.  Reset the timer. */
                cfs_spin_unlock(&svc->srv_at_lock);
                ptlrpc_at_set_timer(svc);
                RETURN(0);
        }

        /* We're close to a timeout, and we don't know how much longer the
           server will take. Send early replies to everyone expiring soon. */
        CFS_INIT_LIST_HEAD(&work_list);
        deadline = -1;
        index = (unsigned long)array->paa_deadline % array->paa_size;
        count = array->paa_count;
        while (count > 0) {
                count -= array->paa_reqs_count[index];
                cfs_list_for_each_entry_safe(rq, n,
                                             &array->paa_reqs_array[index],
                                             rq_timed_list) {
                        if (rq->rq_deadline <= now + at_early_margin) {
                                cfs_list_del_init(&rq->rq_timed_list);
                                /**
                                 * ptlrpc_server_drop_request() may drop
                                 * refcount to 0 already. Let's check this and
                                 * don't add entry to work_list
                                 */
                                if (likely(cfs_atomic_inc_not_zero(&rq->rq_refcount)))
                                        cfs_list_add(&rq->rq_timed_list, &work_list);
                                counter++;
                                array->paa_reqs_count[index]--;
                                array->paa_count--;
                                cfs_spin_lock(&rq->rq_lock);
                                rq->rq_at_linked = 0;
                                cfs_spin_unlock(&rq->rq_lock);
                                continue;
                        }

                        /* update the earliest deadline */
                        if (deadline == -1 || rq->rq_deadline < deadline)
                                deadline = rq->rq_deadline;

                        break;
                }

                if (++index >= array->paa_size)
                        index = 0;
        }
        array->paa_deadline = deadline;
        cfs_spin_unlock(&svc->srv_at_lock);

        /* we have a new earliest deadline, restart the timer */
        ptlrpc_at_set_timer(svc);

        CDEBUG(D_ADAPTTO, "timeout in %+ds, asking for %d secs on %d early "
               "replies\n", first, at_extra, counter);
        if (first < 0) {
                /* We're already past request deadlines before we even get a
                   chance to send early replies */
                LCONSOLE_WARN("%s: This server is not able to keep up with "
                              "request traffic (cpu-bound).\n", svc->srv_name);
                CWARN("earlyQ=%d reqQ=%d recA=%d, svcEst=%d, "
                      "delay="CFS_DURATION_T"(jiff)\n",
                      counter, svc->srv_n_queued_reqs, svc->srv_n_active_reqs,
                      at_get(&svc->srv_at_estimate), delay);
        }

        /* we took additional refcount so entries can't be deleted from list, no
         * locking is needed */
        while (!cfs_list_empty(&work_list)) {
                rq = cfs_list_entry(work_list.next, struct ptlrpc_request,
                                    rq_timed_list);
                cfs_list_del_init(&rq->rq_timed_list);

                if (ptlrpc_at_send_early_reply(rq) == 0)
                        ptlrpc_at_add_timed(rq);

                ptlrpc_server_drop_request(rq);
        }

        RETURN(0);
}

/**
 * Put the request to the export list if the request may become
 * a high priority one.
 */
static int ptlrpc_hpreq_init(struct ptlrpc_service *svc,
                             struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        if (svc->srv_hpreq_handler) {
                rc = svc->srv_hpreq_handler(req);
                if (rc)
                        RETURN(rc);
        }
        if (req->rq_export && req->rq_ops) {
                cfs_spin_lock_bh(&req->rq_export->exp_rpc_lock);
                cfs_list_add(&req->rq_exp_list,
                             &req->rq_export->exp_queued_rpc);
                cfs_spin_unlock_bh(&req->rq_export->exp_rpc_lock);
        }

        RETURN(0);
}

/** Remove the request from the export list. */
static void ptlrpc_hpreq_fini(struct ptlrpc_request *req)
{
        ENTRY;
        if (req->rq_export && req->rq_ops) {
                cfs_spin_lock_bh(&req->rq_export->exp_rpc_lock);
                cfs_list_del_init(&req->rq_exp_list);
                cfs_spin_unlock_bh(&req->rq_export->exp_rpc_lock);
        }
        EXIT;
}

/**
 * Make the request a high priority one.
 *
 * All the high priority requests are queued in a separate FIFO
 * ptlrpc_service::srv_request_hpq list which is parallel to
 * ptlrpc_service::srv_request_queue list but has a higher priority
 * for handling.
 *
 * \see ptlrpc_server_handle_request().
 */
static void ptlrpc_hpreq_reorder_nolock(struct ptlrpc_service *svc,
                                        struct ptlrpc_request *req)
{
        ENTRY;
        LASSERT(svc != NULL);
        cfs_spin_lock(&req->rq_lock);
        if (req->rq_hp == 0) {
                int opc = lustre_msg_get_opc(req->rq_reqmsg);

                /* Add to the high priority queue. */
                cfs_list_move_tail(&req->rq_list, &svc->srv_request_hpq);
                req->rq_hp = 1;
                if (opc != OBD_PING)
                        DEBUG_REQ(D_NET, req, "high priority req");
        }
        cfs_spin_unlock(&req->rq_lock);
        EXIT;
}

/**
 * \see ptlrpc_hpreq_reorder_nolock
 */
void ptlrpc_hpreq_reorder(struct ptlrpc_request *req)
{
        struct ptlrpc_service *svc = req->rq_rqbd->rqbd_service;
        ENTRY;

        cfs_spin_lock(&svc->srv_rq_lock);
        /* It may happen that the request is already taken for the processing
         * but still in the export list, do not re-add it into the HP list. */
        if (req->rq_phase == RQ_PHASE_NEW)
                ptlrpc_hpreq_reorder_nolock(svc, req);
        cfs_spin_unlock(&svc->srv_rq_lock);
        EXIT;
}

/** Check if the request is a high priority one. */
static int ptlrpc_server_hpreq_check(struct ptlrpc_request *req)
{
        int opc, rc = 0;
        ENTRY;

        /* Check by request opc. */
        opc = lustre_msg_get_opc(req->rq_reqmsg);
        if (opc == OBD_PING)
                RETURN(1);

        /* Perform request specific check. */
        if (req->rq_ops && req->rq_ops->hpreq_check)
                rc = req->rq_ops->hpreq_check(req);
        RETURN(rc);
}

/** Check if a request is a high priority one. */
static int ptlrpc_server_request_add(struct ptlrpc_service *svc,
                                     struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = ptlrpc_server_hpreq_check(req);
        if (rc < 0)
                RETURN(rc);

        cfs_spin_lock(&svc->srv_rq_lock);
        /* Before inserting the request into the queue, check if it is not
         * inserted yet, or even already handled -- it may happen due to
         * a racing ldlm_server_blocking_ast(). */
        if (req->rq_phase == RQ_PHASE_NEW && cfs_list_empty(&req->rq_list)) {
                if (rc)
                        ptlrpc_hpreq_reorder_nolock(svc, req);
                else
                        cfs_list_add_tail(&req->rq_list,
                                          &svc->srv_request_queue);
        }
        cfs_spin_unlock(&svc->srv_rq_lock);

        RETURN(0);
}

/**
 * Allow to handle high priority request
 * User can call it w/o any lock but need to hold ptlrpc_service::srv_rq_lock
 * to get reliable result
 */
static int ptlrpc_server_allow_high(struct ptlrpc_service *svc, int force)
{
        if (force)
                return 1;

        if (svc->srv_n_active_reqs >= svc->srv_threads_running - 1)
                return 0;

        return cfs_list_empty(&svc->srv_request_queue) ||
               svc->srv_hpreq_count < svc->srv_hpreq_ratio;
}

static int ptlrpc_server_high_pending(struct ptlrpc_service *svc, int force)
{
        return ptlrpc_server_allow_high(svc, force) &&
               !cfs_list_empty(&svc->srv_request_hpq);
}

/**
 * Only allow normal priority requests on a service that has a high-priority
 * queue if forced (i.e. cleanup), if there are other high priority requests
 * already being processed (i.e. those threads can service more high-priority
 * requests), or if there are enough idle threads that a later thread can do
 * a high priority request.
 * User can call it w/o any lock but need to hold ptlrpc_service::srv_rq_lock
 * to get reliable result
 */
static int ptlrpc_server_allow_normal(struct ptlrpc_service *svc, int force)
{
#ifndef __KERNEL__
        if (1) /* always allow to handle normal request for liblustre */
                return 1;
#endif
        if (force ||
            svc->srv_n_active_reqs < svc->srv_threads_running - 2)
                return 1;

        if (svc->srv_n_active_reqs >= svc->srv_threads_running - 1)
                return 0;

        return svc->srv_n_active_hpreq > 0 || svc->srv_hpreq_handler == NULL;
}

static int ptlrpc_server_normal_pending(struct ptlrpc_service *svc, int force)
{
        return ptlrpc_server_allow_normal(svc, force) &&
               !cfs_list_empty(&svc->srv_request_queue);
}

/**
 * Returns true if there are requests available in incoming
 * request queue for processing and it is allowed to fetch them.
 * User can call it w/o any lock but need to hold ptlrpc_service::srv_rq_lock
 * to get reliable result
 * \see ptlrpc_server_allow_normal
 * \see ptlrpc_server_allow high
 */
static inline int
ptlrpc_server_request_pending(struct ptlrpc_service *svc, int force)
{
        return ptlrpc_server_high_pending(svc, force) ||
               ptlrpc_server_normal_pending(svc, force);
}

/**
 * Fetch a request for processing from queue of unprocessed requests.
 * Favors high-priority requests.
 * Returns a pointer to fetched request.
 */
static struct ptlrpc_request *
ptlrpc_server_request_get(struct ptlrpc_service *svc, int force)
{
        struct ptlrpc_request *req;
        ENTRY;

        if (ptlrpc_server_high_pending(svc, force)) {
                req = cfs_list_entry(svc->srv_request_hpq.next,
                                     struct ptlrpc_request, rq_list);
                svc->srv_hpreq_count++;
                RETURN(req);

        }

        if (ptlrpc_server_normal_pending(svc, force)) {
                req = cfs_list_entry(svc->srv_request_queue.next,
                                     struct ptlrpc_request, rq_list);
                svc->srv_hpreq_count = 0;
                RETURN(req);
        }
        RETURN(NULL);
}

/**
 * Handle freshly incoming reqs, add to timed early reply list,
 * pass on to regular request queue.
 * All incoming requests pass through here before getting into
 * ptlrpc_server_handle_req later on.
 */
static int
ptlrpc_server_handle_req_in(struct ptlrpc_service *svc)
{
        struct ptlrpc_request *req;
        __u32                  deadline;
        int                    rc;
        ENTRY;

        LASSERT(svc);

        cfs_spin_lock(&svc->srv_lock);
        if (cfs_list_empty(&svc->srv_req_in_queue)) {
                cfs_spin_unlock(&svc->srv_lock);
                RETURN(0);
        }

        req = cfs_list_entry(svc->srv_req_in_queue.next,
                             struct ptlrpc_request, rq_list);
        cfs_list_del_init (&req->rq_list);
        svc->srv_n_queued_reqs--;
        /* Consider this still a "queued" request as far as stats are
           concerned */
        /* ptlrpc_hpreq_init() inserts it to the export list and by the time
         * of ptlrpc_server_request_add() it could be already handled and
         * released. To not lose request in between, take an extra reference
         * on the request. */
        ptlrpc_request_addref(req);
        cfs_spin_unlock(&svc->srv_lock);

        /* go through security check/transform */
        rc = sptlrpc_svc_unwrap_request(req);
        switch (rc) {
        case SECSVC_OK:
                break;
        case SECSVC_COMPLETE:
                target_send_reply(req, 0, OBD_FAIL_MDS_ALL_REPLY_NET);
                goto err_req;
        case SECSVC_DROP:
                goto err_req;
        default:
                LBUG();
        }

        /*
         * for null-flavored rpc, msg has been unpacked by sptlrpc, although
         * redo it wouldn't be harmful.
         */
        if (SPTLRPC_FLVR_POLICY(req->rq_flvr.sf_rpc) != SPTLRPC_POLICY_NULL) {
                rc = ptlrpc_unpack_req_msg(req, req->rq_reqlen);
                if (rc != 0) {
                        CERROR("error unpacking request: ptl %d from %s "
                               "x"LPU64"\n", svc->srv_req_portal,
                               libcfs_id2str(req->rq_peer), req->rq_xid);
                        goto err_req;
                }
        }

        rc = lustre_unpack_req_ptlrpc_body(req, MSG_PTLRPC_BODY_OFF);
        if (rc) {
                CERROR ("error unpacking ptlrpc body: ptl %d from %s x"
                        LPU64"\n", svc->srv_req_portal,
                        libcfs_id2str(req->rq_peer), req->rq_xid);
                goto err_req;
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_DROP_REQ_OPC) &&
            lustre_msg_get_opc(req->rq_reqmsg) == cfs_fail_val) {
                CERROR("drop incoming rpc opc %u, x"LPU64"\n",
                       cfs_fail_val, req->rq_xid);
                goto err_req;
        }

        rc = -EINVAL;
        if (lustre_msg_get_type(req->rq_reqmsg) != PTL_RPC_MSG_REQUEST) {
                CERROR("wrong packet type received (type=%u) from %s\n",
                       lustre_msg_get_type(req->rq_reqmsg),
                       libcfs_id2str(req->rq_peer));
                goto err_req;
        }

        switch(lustre_msg_get_opc(req->rq_reqmsg)) {
        case MDS_WRITEPAGE:
        case OST_WRITE:
                req->rq_bulk_write = 1;
                break;
        case MDS_READPAGE:
        case OST_READ:
                req->rq_bulk_read = 1;
                break;
        }

        CDEBUG(D_NET, "got req "LPU64"\n", req->rq_xid);

        req->rq_export = class_conn2export(
                lustre_msg_get_handle(req->rq_reqmsg));
        if (req->rq_export) {
                rc = ptlrpc_check_req(req);
                if (rc == 0) {
                        rc = sptlrpc_target_export_check(req->rq_export, req);
                        if (rc)
                                DEBUG_REQ(D_ERROR, req, "DROPPING req with "
                                          "illegal security flavor,");
                }

                if (rc)
                        goto err_req;
                ptlrpc_update_export_timer(req->rq_export, 0);
        }

        /* req_in handling should/must be fast */
        if (cfs_time_current_sec() - req->rq_arrival_time.tv_sec > 5)
                DEBUG_REQ(D_WARNING, req, "Slow req_in handling "CFS_DURATION_T"s",
                          cfs_time_sub(cfs_time_current_sec(),
                                       req->rq_arrival_time.tv_sec));

        /* Set rpc server deadline and add it to the timed list */
        deadline = (lustre_msghdr_get_flags(req->rq_reqmsg) &
                    MSGHDR_AT_SUPPORT) ?
                   /* The max time the client expects us to take */
                   lustre_msg_get_timeout(req->rq_reqmsg) : obd_timeout;
        req->rq_deadline = req->rq_arrival_time.tv_sec + deadline;
        if (unlikely(deadline == 0)) {
                DEBUG_REQ(D_ERROR, req, "Dropping request with 0 timeout");
                goto err_req;
        }

        ptlrpc_at_add_timed(req);
        rc = ptlrpc_hpreq_init(svc, req);
        if (rc)
                GOTO(err_req, rc);

        /* Move it over to the request processing queue */
        rc = ptlrpc_server_request_add(svc, req);
        if (rc)
                GOTO(err_req, rc);
        cfs_waitq_signal(&svc->srv_waitq);
        ptlrpc_server_drop_request(req);
        RETURN(1);

err_req:
        ptlrpc_server_drop_request(req);
        cfs_spin_lock(&svc->srv_rq_lock);
        svc->srv_n_active_reqs++;
        cfs_spin_unlock(&svc->srv_rq_lock);
        ptlrpc_server_finish_request(svc, req);

        RETURN(1);
}

/**
 * Main incoming request handling logic.
 * Calls handler function from service to do actual processing.
 */
static int
ptlrpc_server_handle_request(struct ptlrpc_service *svc,
                             struct ptlrpc_thread *thread)
{
        struct obd_export     *export = NULL;
        struct ptlrpc_request *request;
        struct timeval         work_start;
        struct timeval         work_end;
        long                   timediff;
        int                    opc, rc;
        int                    fail_opc = 0;
        ENTRY;

        LASSERT(svc);

        cfs_spin_lock(&svc->srv_rq_lock);
#ifndef __KERNEL__
        /* !@%$# liblustre only has 1 thread */
        if (cfs_atomic_read(&svc->srv_n_difficult_replies) != 0) {
                cfs_spin_unlock(&svc->srv_rq_lock);
                RETURN(0);
        }
#endif
        request = ptlrpc_server_request_get(svc, 0);
        if  (request == NULL) {
                cfs_spin_unlock(&svc->srv_rq_lock);
                RETURN(0);
        }

        opc = lustre_msg_get_opc(request->rq_reqmsg);
        if (OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_HPREQ_NOTIMEOUT))
                fail_opc = OBD_FAIL_PTLRPC_HPREQ_NOTIMEOUT;
        else if (OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_HPREQ_TIMEOUT))
                fail_opc = OBD_FAIL_PTLRPC_HPREQ_TIMEOUT;

        if (unlikely(fail_opc)) {
                if (request->rq_export && request->rq_ops) {
                        cfs_spin_unlock(&svc->srv_rq_lock);
                        OBD_FAIL_TIMEOUT(fail_opc, 4);
                        cfs_spin_lock(&svc->srv_rq_lock);
                        request = ptlrpc_server_request_get(svc, 0);
                        if  (request == NULL) {
                                cfs_spin_unlock(&svc->srv_rq_lock);
                                RETURN(0);
                        }
                }
        }

        cfs_list_del_init(&request->rq_list);
        svc->srv_n_active_reqs++;
        if (request->rq_hp)
                svc->srv_n_active_hpreq++;

        /* The phase is changed under the lock here because we need to know
         * the request is under processing (see ptlrpc_hpreq_reorder()). */
        ptlrpc_rqphase_move(request, RQ_PHASE_INTERPRET);
        cfs_spin_unlock(&svc->srv_rq_lock);

        ptlrpc_hpreq_fini(request);

        if(OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_DUMP_LOG))
                libcfs_debug_dumplog();

        cfs_gettimeofday(&work_start);
        timediff = cfs_timeval_sub(&work_start, &request->rq_arrival_time,NULL);
        if (likely(svc->srv_stats != NULL)) {
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQWAIT_CNTR,
                                    timediff);
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQQDEPTH_CNTR,
                                    svc->srv_n_queued_reqs);
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQACTIVE_CNTR,
                                    svc->srv_n_active_reqs);
                lprocfs_counter_add(svc->srv_stats, PTLRPC_TIMEOUT,
                                    at_get(&svc->srv_at_estimate));
        }

        rc = lu_context_init(&request->rq_session,
                             LCT_SESSION|LCT_REMEMBER|LCT_NOREF);
        if (rc) {
                CERROR("Failure to initialize session: %d\n", rc);
                goto out_req;
        }
        request->rq_session.lc_thread = thread;
        request->rq_session.lc_cookie = 0x5;
        lu_context_enter(&request->rq_session);

        CDEBUG(D_NET, "got req "LPU64"\n", request->rq_xid);

        request->rq_svc_thread = thread;
        if (thread)
                request->rq_svc_thread->t_env->le_ses = &request->rq_session;

        if (likely(request->rq_export)) {
                if (unlikely(ptlrpc_check_req(request)))
                        goto put_conn;
                ptlrpc_update_export_timer(request->rq_export, timediff >> 19);
                export = class_export_rpc_get(request->rq_export);
        }

        /* Discard requests queued for longer than the deadline.
           The deadline is increased if we send an early reply. */
        if (cfs_time_current_sec() > request->rq_deadline) {
                DEBUG_REQ(D_ERROR, request, "Dropping timed-out request from %s"
                          ": deadline "CFS_DURATION_T":"CFS_DURATION_T"s ago\n",
                          libcfs_id2str(request->rq_peer),
                          cfs_time_sub(request->rq_deadline,
                          request->rq_arrival_time.tv_sec),
                          cfs_time_sub(cfs_time_current_sec(),
                          request->rq_deadline));
                goto put_rpc_export;
        }

        CDEBUG(D_RPCTRACE, "Handling RPC pname:cluuid+ref:pid:xid:nid:opc "
               "%s:%s+%d:%d:x"LPU64":%s:%d\n", cfs_curproc_comm(),
               (request->rq_export ?
                (char *)request->rq_export->exp_client_uuid.uuid : "0"),
               (request->rq_export ?
                cfs_atomic_read(&request->rq_export->exp_refcount) : -99),
               lustre_msg_get_status(request->rq_reqmsg), request->rq_xid,
               libcfs_id2str(request->rq_peer),
               lustre_msg_get_opc(request->rq_reqmsg));

        if (lustre_msg_get_opc(request->rq_reqmsg) != OBD_PING)
                CFS_FAIL_TIMEOUT_MS(OBD_FAIL_PTLRPC_PAUSE_REQ, cfs_fail_val);

        rc = svc->srv_handler(request);

        ptlrpc_rqphase_move(request, RQ_PHASE_COMPLETE);

put_rpc_export:
        if (export != NULL)
                class_export_rpc_put(export);
put_conn:
        lu_context_exit(&request->rq_session);
        lu_context_fini(&request->rq_session);

        if (unlikely(cfs_time_current_sec() > request->rq_deadline)) {
                DEBUG_REQ(D_WARNING, request, "Request x"LPU64" took longer "
                          "than estimated ("CFS_DURATION_T":"CFS_DURATION_T"s);"
                          " client may timeout.",
                          request->rq_xid, cfs_time_sub(request->rq_deadline,
                          request->rq_arrival_time.tv_sec),
                          cfs_time_sub(cfs_time_current_sec(),
                          request->rq_deadline));
        }

        cfs_gettimeofday(&work_end);
        timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
        CDEBUG(D_RPCTRACE, "Handled RPC pname:cluuid+ref:pid:xid:nid:opc "
               "%s:%s+%d:%d:x"LPU64":%s:%d Request procesed in "
               "%ldus (%ldus total) trans "LPU64" rc %d/%d\n",
                cfs_curproc_comm(),
                (request->rq_export ?
                 (char *)request->rq_export->exp_client_uuid.uuid : "0"),
                (request->rq_export ?
                 cfs_atomic_read(&request->rq_export->exp_refcount) : -99),
                lustre_msg_get_status(request->rq_reqmsg),
                request->rq_xid,
                libcfs_id2str(request->rq_peer),
                lustre_msg_get_opc(request->rq_reqmsg),
                timediff,
                cfs_timeval_sub(&work_end, &request->rq_arrival_time, NULL),
                (request->rq_repmsg ?
                 lustre_msg_get_transno(request->rq_repmsg) :
                 request->rq_transno),
                request->rq_status,
                (request->rq_repmsg ?
                 lustre_msg_get_status(request->rq_repmsg) : -999));
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
        if (unlikely(request->rq_early_count)) {
                DEBUG_REQ(D_ADAPTTO, request,
                          "sent %d early replies before finishing in "
                          CFS_DURATION_T"s",
                          request->rq_early_count,
                          cfs_time_sub(work_end.tv_sec,
                          request->rq_arrival_time.tv_sec));
        }

out_req:
        ptlrpc_server_finish_request(svc, request);

        RETURN(1);
}

/**
 * An internal function to process a single reply state object.
 */
static int
ptlrpc_handle_rs (struct ptlrpc_reply_state *rs)
{
        struct ptlrpc_service     *svc = rs->rs_service;
        struct obd_export         *exp;
        struct obd_device         *obd;
        int                        nlocks;
        int                        been_handled;
        ENTRY;

        exp = rs->rs_export;
        obd = exp->exp_obd;

        LASSERT (rs->rs_difficult);
        LASSERT (rs->rs_scheduled);
        LASSERT (cfs_list_empty(&rs->rs_list));

        cfs_spin_lock (&exp->exp_lock);
        /* Noop if removed already */
        cfs_list_del_init (&rs->rs_exp_list);
        cfs_spin_unlock (&exp->exp_lock);

        /* The disk commit callback holds exp_uncommitted_replies_lock while it
         * iterates over newly committed replies, removing them from
         * exp_uncommitted_replies.  It then drops this lock and schedules the
         * replies it found for handling here.
         *
         * We can avoid contention for exp_uncommitted_replies_lock between the
         * HRT threads and further commit callbacks by checking rs_committed
         * which is set in the commit callback while it holds both
         * rs_lock and exp_uncommitted_reples.
         *
         * If we see rs_committed clear, the commit callback _may_ not have
         * handled this reply yet and we race with it to grab
         * exp_uncommitted_replies_lock before removing the reply from
         * exp_uncommitted_replies.  Note that if we lose the race and the
         * reply has already been removed, list_del_init() is a noop.
         *
         * If we see rs_committed set, we know the commit callback is handling,
         * or has handled this reply since store reordering might allow us to
         * see rs_committed set out of sequence.  But since this is done
         * holding rs_lock, we can be sure it has all completed once we hold
         * rs_lock, which we do right next.
         */
        if (!rs->rs_committed) {
                cfs_spin_lock(&exp->exp_uncommitted_replies_lock);
                cfs_list_del_init(&rs->rs_obd_list);
                cfs_spin_unlock(&exp->exp_uncommitted_replies_lock);
        }

        cfs_spin_lock(&rs->rs_lock);

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
                      rs->rs_xid, rs->rs_transno, rs->rs_opc,
                      libcfs_nid2str(exp->exp_connection->c_peer.nid));
        }

        if ((!been_handled && rs->rs_on_net) || nlocks > 0) {
                cfs_spin_unlock(&rs->rs_lock);

                if (!been_handled && rs->rs_on_net) {
                        LNetMDUnlink(rs->rs_md_h);
                        /* Ignore return code; we're racing with
                         * completion... */
                }

                while (nlocks-- > 0)
                        ldlm_lock_decref(&rs->rs_locks[nlocks],
                                         rs->rs_modes[nlocks]);

                cfs_spin_lock(&rs->rs_lock);
        }

        rs->rs_scheduled = 0;

        if (!rs->rs_on_net) {
                /* Off the net */
                cfs_spin_unlock(&rs->rs_lock);

                class_export_put (exp);
                rs->rs_export = NULL;
                ptlrpc_rs_decref (rs);
                if (cfs_atomic_dec_and_test(&svc->srv_n_difficult_replies) &&
                    svc->srv_is_stopping)
                        cfs_waitq_broadcast(&svc->srv_waitq);
                RETURN(1);
        }

        /* still on the net; callback will schedule */
        cfs_spin_unlock(&rs->rs_lock);
        RETURN(1);
}

#ifndef __KERNEL__

/**
 * Check whether given service has a reply available for processing
 * and process it.
 *
 * \param svc a ptlrpc service
 * \retval 0 no replies processed
 * \retval 1 one reply processed
 */
static int
ptlrpc_server_handle_reply(struct ptlrpc_service *svc)
{
        struct ptlrpc_reply_state *rs = NULL;
        ENTRY;

        cfs_spin_lock(&svc->srv_rs_lock);
        if (!cfs_list_empty(&svc->srv_reply_queue)) {
                rs = cfs_list_entry(svc->srv_reply_queue.prev,
                                    struct ptlrpc_reply_state,
                                    rs_list);
                cfs_list_del_init(&rs->rs_list);
        }
        cfs_spin_unlock(&svc->srv_rs_lock);
        if (rs != NULL)
                ptlrpc_handle_rs(rs);
        RETURN(rs != NULL);
}

/* FIXME make use of timeout later */
int
liblustre_check_services (void *arg)
{
        int  did_something = 0;
        int  rc;
        cfs_list_t *tmp, *nxt;
        ENTRY;

        /* I'm relying on being single threaded, not to have to lock
         * ptlrpc_all_services etc */
        cfs_list_for_each_safe (tmp, nxt, &ptlrpc_all_services) {
                struct ptlrpc_service *svc =
                        cfs_list_entry (tmp, struct ptlrpc_service, srv_list);

                if (svc->srv_threads_running != 0)     /* I've recursed */
                        continue;

                /* service threads can block for bulk, so this limits us
                 * (arbitrarily) to recursing 1 stack frame per service.
                 * Note that the problem with recursion is that we have to
                 * unwind completely before our caller can resume. */

                svc->srv_threads_running++;

                do {
                        rc = ptlrpc_server_handle_req_in(svc);
                        rc |= ptlrpc_server_handle_reply(svc);
                        rc |= ptlrpc_at_check_timed(svc);
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

static inline int
ptlrpc_threads_enough(struct ptlrpc_service *svc)
{
        return svc->srv_n_active_reqs <
               svc->srv_threads_running - 1 - (svc->srv_hpreq_handler != NULL);
}

/**
 * allowed to create more threads
 * user can call it w/o any lock but need to hold ptlrpc_service::srv_lock to
 * get reliable result
 */
static inline int
ptlrpc_threads_increasable(struct ptlrpc_service *svc)
{
        return svc->srv_threads_running +
               svc->srv_threads_starting < svc->srv_threads_max;
}

/**
 * too many requests and allowed to create more threads
 */
static inline int
ptlrpc_threads_need_create(struct ptlrpc_service *svc)
{
        return !ptlrpc_threads_enough(svc) && ptlrpc_threads_increasable(svc);
}

static inline int
ptlrpc_thread_stopping(struct ptlrpc_thread *thread)
{
        return (thread->t_flags & SVC_STOPPING) != 0 ||
                thread->t_svc->srv_is_stopping;
}

static inline int
ptlrpc_rqbd_pending(struct ptlrpc_service *svc)
{
        return !cfs_list_empty(&svc->srv_idle_rqbds) &&
               svc->srv_rqbd_timeout == 0;
}

static inline int
ptlrpc_at_check(struct ptlrpc_service *svc)
{
        return svc->srv_at_check;
}

/**
 * requests wait on preprocessing
 * user can call it w/o any lock but need to hold ptlrpc_service::srv_lock to
 * get reliable result
 */
static inline int
ptlrpc_server_request_waiting(struct ptlrpc_service *svc)
{
        return !cfs_list_empty(&svc->srv_req_in_queue);
}

static __attribute__((__noinline__)) int
ptlrpc_wait_event(struct ptlrpc_service *svc,
                  struct ptlrpc_thread *thread)
{
        /* Don't exit while there are replies to be handled */
        struct l_wait_info lwi = LWI_TIMEOUT(svc->srv_rqbd_timeout,
                                             ptlrpc_retry_rqbds, svc);

        lc_watchdog_disable(thread->t_watchdog);

        cfs_cond_resched();

        l_wait_event_exclusive_head(svc->srv_waitq,
                               ptlrpc_thread_stopping(thread) ||
                               ptlrpc_server_request_waiting(svc) ||
                               ptlrpc_server_request_pending(svc, 0) ||
                               ptlrpc_rqbd_pending(svc) ||
                               ptlrpc_at_check(svc), &lwi);

        if (ptlrpc_thread_stopping(thread))
                return -EINTR;

        lc_watchdog_touch(thread->t_watchdog, CFS_GET_TIMEOUT(svc));

        return 0;
}

/**
 * Main thread body for service threads.
 * Waits in a loop waiting for new requests to process to appear.
 * Every time an incoming requests is added to its queue, a waitq
 * is woken up and one of the threads will handle it.
 */
static int ptlrpc_main(void *arg)
{
        struct ptlrpc_svc_data *data = (struct ptlrpc_svc_data *)arg;
        struct ptlrpc_service  *svc = data->svc;
        struct ptlrpc_thread   *thread = data->thread;
        struct ptlrpc_reply_state *rs;
#ifdef WITH_GROUP_INFO
        cfs_group_info_t *ginfo = NULL;
#endif
        struct lu_env env;
        int counter = 0, rc = 0;
        ENTRY;

        thread->t_pid = cfs_curproc_pid();
        cfs_daemonize_ctxt(data->name);

#if defined(HAVE_NODE_TO_CPUMASK) && defined(CONFIG_NUMA)
        /* we need to do this before any per-thread allocation is done so that
         * we get the per-thread allocations on local node.  bug 7342 */
        if (svc->srv_cpu_affinity) {
                int cpu, num_cpu;

                for (cpu = 0, num_cpu = 0; cpu < cfs_num_possible_cpus();
                     cpu++) {
                        if (!cfs_cpu_online(cpu))
                                continue;
                        if (num_cpu == thread->t_id % cfs_num_online_cpus())
                                break;
                        num_cpu++;
                }
                cfs_set_cpus_allowed(cfs_current(),
                                     node_to_cpumask(cpu_to_node(cpu)));
        }
#endif

#ifdef WITH_GROUP_INFO
        ginfo = cfs_groups_alloc(0);
        if (!ginfo) {
                rc = -ENOMEM;
                goto out;
        }

        cfs_set_current_groups(ginfo);
        cfs_put_group_info(ginfo);
#endif

        if (svc->srv_init != NULL) {
                rc = svc->srv_init(thread);
                if (rc)
                        goto out;
        }

        rc = lu_context_init(&env.le_ctx,
                             svc->srv_ctx_tags|LCT_REMEMBER|LCT_NOREF);
        if (rc)
                goto out_srv_fini;

        thread->t_env = &env;
        env.le_ctx.lc_thread = thread;
        env.le_ctx.lc_cookie = 0x6;

        /* Alloc reply state structure for this one */
        OBD_ALLOC_LARGE(rs, svc->srv_max_reply_size);
        if (!rs) {
                rc = -ENOMEM;
                goto out_srv_fini;
        }

        cfs_spin_lock(&svc->srv_lock);

        LASSERT((thread->t_flags & SVC_STARTING) != 0);
        thread->t_flags &= ~SVC_STARTING;
        svc->srv_threads_starting--;

        /* SVC_STOPPING may already be set here if someone else is trying
         * to stop the service while this new thread has been dynamically
         * forked. We still set SVC_RUNNING to let our creator know that
         * we are now running, however we will exit as soon as possible */
        thread->t_flags |= SVC_RUNNING;
        svc->srv_threads_running++;
        cfs_spin_unlock(&svc->srv_lock);

        /*
         * wake up our creator. Note: @data is invalid after this point,
         * because it's allocated on ptlrpc_start_thread() stack.
         */
        cfs_waitq_signal(&thread->t_ctl_waitq);

        thread->t_watchdog = lc_watchdog_add(CFS_GET_TIMEOUT(svc), NULL, NULL);

        cfs_spin_lock(&svc->srv_rs_lock);
        cfs_list_add(&rs->rs_list, &svc->srv_free_rs_list);
        cfs_waitq_signal(&svc->srv_free_rs_waitq);
        cfs_spin_unlock(&svc->srv_rs_lock);

        CDEBUG(D_NET, "service thread %d (#%d) started\n", thread->t_id,
               svc->srv_threads_running);

        /* XXX maintain a list of all managed devices: insert here */
        while (!ptlrpc_thread_stopping(thread)) {
                if (ptlrpc_wait_event(svc, thread))
                        break;

                ptlrpc_check_rqbd_pool(svc);

                if (ptlrpc_threads_need_create(svc)) {
                        /* Ignore return code - we tried... */
                        ptlrpc_start_thread(svc);
                }

                /* Process all incoming reqs before handling any */
                if (ptlrpc_server_request_waiting(svc)) {
                        ptlrpc_server_handle_req_in(svc);
                        /* but limit ourselves in case of flood */
                        if (counter++ < 100)
                                continue;
                        counter = 0;
                }

                if (ptlrpc_at_check(svc))
                        ptlrpc_at_check_timed(svc);

                if (ptlrpc_server_request_pending(svc, 0)) {
                        lu_context_enter(&env.le_ctx);
                        ptlrpc_server_handle_request(svc, thread);
                        lu_context_exit(&env.le_ctx);
                }

                if (ptlrpc_rqbd_pending(svc) &&
                    ptlrpc_server_post_idle_rqbds(svc) < 0) {
                        /* I just failed to repost request buffers.
                         * Wait for a timeout (unless something else
                         * happens) before I try again */
                        svc->srv_rqbd_timeout = cfs_time_seconds(1)/10;
                        CDEBUG(D_RPCTRACE,"Posted buffers: %d\n",
                               svc->srv_nrqbd_receiving);
                }
        }

        lc_watchdog_delete(thread->t_watchdog);
        thread->t_watchdog = NULL;

out_srv_fini:
        /*
         * deconstruct service specific state created by ptlrpc_start_thread()
         */
        if (svc->srv_done != NULL)
                svc->srv_done(thread);

        lu_context_fini(&env.le_ctx);
out:
        CDEBUG(D_RPCTRACE, "service thread [ %p : %u ] %d exiting: rc %d\n",
               thread, thread->t_pid, thread->t_id, rc);

        cfs_spin_lock(&svc->srv_lock);
        if ((thread->t_flags & SVC_STARTING) != 0) {
                svc->srv_threads_starting--;
                thread->t_flags &= ~SVC_STARTING;
        }

        if ((thread->t_flags & SVC_RUNNING) != 0) {
                /* must know immediately */
                svc->srv_threads_running--;
                thread->t_flags &= ~SVC_RUNNING;
        }

        thread->t_id    = rc;
        thread->t_flags |= SVC_STOPPED;

        cfs_waitq_signal(&thread->t_ctl_waitq);
        cfs_spin_unlock(&svc->srv_lock);

        return rc;
}

struct ptlrpc_hr_args {
        int                       thread_index;
        int                       cpu_index;
        struct ptlrpc_hr_service *hrs;
};

static int hrt_dont_sleep(struct ptlrpc_hr_thread *t,
                          cfs_list_t *replies)
{
        int result;

        cfs_spin_lock(&t->hrt_lock);
        cfs_list_splice_init(&t->hrt_queue, replies);
        result = cfs_test_bit(HRT_STOPPING, &t->hrt_flags) ||
                !cfs_list_empty(replies);
        cfs_spin_unlock(&t->hrt_lock);
        return result;
}

/**
 * Main body of "handle reply" function.
 * It processes acked reply states
 */
static int ptlrpc_hr_main(void *arg)
{
        struct ptlrpc_hr_args * hr_args = arg;
        struct ptlrpc_hr_service *hr = hr_args->hrs;
        struct ptlrpc_hr_thread *t = &hr->hr_threads[hr_args->thread_index];
        char threadname[20];
        CFS_LIST_HEAD(replies);

        snprintf(threadname, sizeof(threadname),
                 "ptlrpc_hr_%d", hr_args->thread_index);

        cfs_daemonize_ctxt(threadname);
#if defined(CONFIG_SMP) && defined(HAVE_NODE_TO_CPUMASK)
        cfs_set_cpus_allowed(cfs_current(),
                             node_to_cpumask(cpu_to_node(hr_args->cpu_index)));
#endif
        cfs_set_bit(HRT_RUNNING, &t->hrt_flags);
        cfs_waitq_signal(&t->hrt_wait);

        while (!cfs_test_bit(HRT_STOPPING, &t->hrt_flags)) {

                l_wait_condition(t->hrt_wait, hrt_dont_sleep(t, &replies));
                while (!cfs_list_empty(&replies)) {
                        struct ptlrpc_reply_state *rs;

                        rs = cfs_list_entry(replies.prev,
                                            struct ptlrpc_reply_state,
                                            rs_list);
                        cfs_list_del_init(&rs->rs_list);
                        ptlrpc_handle_rs(rs);
                }
        }

        cfs_clear_bit(HRT_RUNNING, &t->hrt_flags);
        cfs_complete(&t->hrt_completion);

        return 0;
}

static int ptlrpc_start_hr_thread(struct ptlrpc_hr_service *hr, int n, int cpu)
{
        struct ptlrpc_hr_thread *t = &hr->hr_threads[n];
        struct ptlrpc_hr_args args;
        int rc;
        ENTRY;

        args.thread_index = n;
        args.cpu_index = cpu;
        args.hrs = hr;

        rc = cfs_create_thread(ptlrpc_hr_main, (void*)&args, CFS_DAEMON_FLAGS);
        if (rc < 0) {
                cfs_complete(&t->hrt_completion);
                GOTO(out, rc);
        }
        l_wait_condition(t->hrt_wait, cfs_test_bit(HRT_RUNNING, &t->hrt_flags));
        RETURN(0);
 out:
        return rc;
}

static void ptlrpc_stop_hr_thread(struct ptlrpc_hr_thread *t)
{
        ENTRY;

        cfs_set_bit(HRT_STOPPING, &t->hrt_flags);
        cfs_waitq_signal(&t->hrt_wait);
        cfs_wait_for_completion(&t->hrt_completion);

        EXIT;
}

static void ptlrpc_stop_hr_threads(struct ptlrpc_hr_service *hrs)
{
        int n;
        ENTRY;

        for (n = 0; n < hrs->hr_n_threads; n++)
                ptlrpc_stop_hr_thread(&hrs->hr_threads[n]);

        EXIT;
}

static int ptlrpc_start_hr_threads(struct ptlrpc_hr_service *hr)
{
        int rc = -ENOMEM;
        int n, cpu, threads_started = 0;
        ENTRY;

        LASSERT(hr != NULL);
        LASSERT(hr->hr_n_threads > 0);

        for (n = 0, cpu = 0; n < hr->hr_n_threads; n++) {
#if defined(CONFIG_SMP) && defined(HAVE_NODE_TO_CPUMASK)
                while(!cfs_cpu_online(cpu)) {
                        cpu++;
                        if (cpu >= cfs_num_possible_cpus())
                                cpu = 0;
                }
#endif
                rc = ptlrpc_start_hr_thread(hr, n, cpu);
                if (rc != 0)
                        break;
                threads_started++;
                cpu++;
        }
        if (threads_started == 0) {
                CERROR("No reply handling threads started\n");
                RETURN(-ESRCH);
        }
        if (threads_started < hr->hr_n_threads) {
                CWARN("Started only %d reply handling threads from %d\n",
                      threads_started, hr->hr_n_threads);
                hr->hr_n_threads = threads_started;
        }
        RETURN(0);
}

static void ptlrpc_stop_thread(struct ptlrpc_service *svc,
                               struct ptlrpc_thread *thread)
{
        struct l_wait_info lwi = { 0 };
        ENTRY;

        CDEBUG(D_RPCTRACE, "Stopping thread [ %p : %u ]\n",
               thread, thread->t_pid);

        cfs_spin_lock(&svc->srv_lock);
        /* let the thread know that we would like it to stop asap */
        thread->t_flags |= SVC_STOPPING;
        cfs_spin_unlock(&svc->srv_lock);

        cfs_waitq_broadcast(&svc->srv_waitq);
        l_wait_event(thread->t_ctl_waitq,
                     (thread->t_flags & SVC_STOPPED), &lwi);

        cfs_spin_lock(&svc->srv_lock);
        cfs_list_del(&thread->t_link);
        cfs_spin_unlock(&svc->srv_lock);

        OBD_FREE_PTR(thread);
        EXIT;
}

/**
 * Stops all threads of a particular service \a svc
 */
void ptlrpc_stop_all_threads(struct ptlrpc_service *svc)
{
        struct ptlrpc_thread *thread;
        ENTRY;

        cfs_spin_lock(&svc->srv_lock);
        while (!cfs_list_empty(&svc->srv_threads)) {
                thread = cfs_list_entry(svc->srv_threads.next,
                                        struct ptlrpc_thread, t_link);

                cfs_spin_unlock(&svc->srv_lock);
                ptlrpc_stop_thread(svc, thread);
                cfs_spin_lock(&svc->srv_lock);
        }

        cfs_spin_unlock(&svc->srv_lock);
        EXIT;
}

int ptlrpc_start_threads(struct ptlrpc_service *svc)
{
        int i, rc = 0;
        ENTRY;

        /* We require 2 threads min - see note in
           ptlrpc_server_handle_request */
        LASSERT(svc->srv_threads_min >= 2);
        for (i = 0; i < svc->srv_threads_min; i++) {
                rc = ptlrpc_start_thread(svc);
                /* We have enough threads, don't start more.  b=15759 */
                if (rc == -EMFILE) {
                        rc = 0;
                        break;
                }
                if (rc) {
                        CERROR("cannot start %s thread #%d: rc %d\n",
                               svc->srv_thread_name, i, rc);
                        ptlrpc_stop_all_threads(svc);
                        break;
                }
        }
        RETURN(rc);
}

int ptlrpc_start_thread(struct ptlrpc_service *svc)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_svc_data d;
        struct ptlrpc_thread *thread;
        char name[32];
        int rc;
        ENTRY;

        CDEBUG(D_RPCTRACE, "%s started %d min %d max %d running %d\n",
               svc->srv_name, svc->srv_threads_running, svc->srv_threads_min,
               svc->srv_threads_max, svc->srv_threads_running);

        if (unlikely(svc->srv_is_stopping))
                RETURN(-ESRCH);

        if (!ptlrpc_threads_increasable(svc) ||
            (OBD_FAIL_CHECK(OBD_FAIL_TGT_TOOMANY_THREADS) &&
             svc->srv_threads_running == svc->srv_threads_min - 1))
                RETURN(-EMFILE);

        OBD_ALLOC_PTR(thread);
        if (thread == NULL)
                RETURN(-ENOMEM);
        cfs_waitq_init(&thread->t_ctl_waitq);

        cfs_spin_lock(&svc->srv_lock);
        if (!ptlrpc_threads_increasable(svc)) {
                cfs_spin_unlock(&svc->srv_lock);
                OBD_FREE_PTR(thread);
                RETURN(-EMFILE);
        }

        svc->srv_threads_starting++;
        thread->t_id    = svc->srv_threads_next_id++;
        thread->t_flags |= SVC_STARTING;
        thread->t_svc   = svc;

        cfs_list_add(&thread->t_link, &svc->srv_threads);
        cfs_spin_unlock(&svc->srv_lock);

        sprintf(name, "%s_%02d", svc->srv_thread_name, thread->t_id);
        d.svc = svc;
        d.name = name;
        d.thread = thread;

        CDEBUG(D_RPCTRACE, "starting thread '%s'\n", name);

        /* CLONE_VM and CLONE_FILES just avoid a needless copy, because we
         * just drop the VM and FILES in cfs_daemonize_ctxt() right away.
         */
        rc = cfs_create_thread(ptlrpc_main, &d, CFS_DAEMON_FLAGS);
        if (rc < 0) {
                CERROR("cannot start thread '%s': rc %d\n", name, rc);

                cfs_spin_lock(&svc->srv_lock);
                cfs_list_del(&thread->t_link);
                --svc->srv_threads_starting;
                cfs_spin_unlock(&svc->srv_lock);

                OBD_FREE(thread, sizeof(*thread));
                RETURN(rc);
        }
        l_wait_event(thread->t_ctl_waitq,
                     thread->t_flags & (SVC_RUNNING | SVC_STOPPED), &lwi);

        rc = (thread->t_flags & SVC_STOPPED) ? thread->t_id : 0;
        RETURN(rc);
}


int ptlrpc_hr_init(void)
{
        int i;
        int n_cpus = cfs_num_online_cpus();
        struct ptlrpc_hr_service *hr;
        int size;
        int rc;
        ENTRY;

        LASSERT(ptlrpc_hr == NULL);

        size = offsetof(struct ptlrpc_hr_service, hr_threads[n_cpus]);
        OBD_ALLOC(hr, size);
        if (hr == NULL)
                RETURN(-ENOMEM);
        for (i = 0; i < n_cpus; i++) {
                struct ptlrpc_hr_thread *t = &hr->hr_threads[i];

                cfs_spin_lock_init(&t->hrt_lock);
                cfs_waitq_init(&t->hrt_wait);
                CFS_INIT_LIST_HEAD(&t->hrt_queue);
                cfs_init_completion(&t->hrt_completion);
        }
        hr->hr_n_threads = n_cpus;
        hr->hr_size = size;
        ptlrpc_hr = hr;

        rc = ptlrpc_start_hr_threads(hr);
        if (rc) {
                OBD_FREE(hr, hr->hr_size);
                ptlrpc_hr = NULL;
        }
        RETURN(rc);
}

void ptlrpc_hr_fini(void)
{
        if (ptlrpc_hr != NULL) {
                ptlrpc_stop_hr_threads(ptlrpc_hr);
                OBD_FREE(ptlrpc_hr, ptlrpc_hr->hr_size);
                ptlrpc_hr = NULL;
        }
}

#endif /* __KERNEL__ */

/**
 * Wait until all already scheduled replies are processed.
 */
static void ptlrpc_wait_replies(struct ptlrpc_service *svc)
{
        while (1) {
                int rc;
                struct l_wait_info lwi = LWI_TIMEOUT(cfs_time_seconds(10),
                                                     NULL, NULL);
                rc = l_wait_event(svc->srv_waitq, cfs_atomic_read(&svc-> \
                                  srv_n_difficult_replies) == 0,
                                  &lwi);
                if (rc == 0)
                        break;
                CWARN("Unexpectedly long timeout %p\n", svc);
        }
}

int ptlrpc_unregister_service(struct ptlrpc_service *service)
{
        int                   rc;
        struct l_wait_info    lwi;
        cfs_list_t           *tmp;
        struct ptlrpc_reply_state *rs, *t;
        struct ptlrpc_at_array *array = &service->srv_at_array;
        ENTRY;

        service->srv_is_stopping = 1;
        cfs_timer_disarm(&service->srv_at_timer);

        ptlrpc_stop_all_threads(service);
        LASSERT(cfs_list_empty(&service->srv_threads));

        cfs_spin_lock (&ptlrpc_all_services_lock);
        cfs_list_del_init (&service->srv_list);
        cfs_spin_unlock (&ptlrpc_all_services_lock);

        ptlrpc_lprocfs_unregister_service(service);

        /* All history will be culled when the next request buffer is
         * freed */
        service->srv_max_history_rqbds = 0;

        CDEBUG(D_NET, "%s: tearing down\n", service->srv_name);

        rc = LNetClearLazyPortal(service->srv_req_portal);
        LASSERT (rc == 0);

        /* Unlink all the request buffers.  This forces a 'final' event with
         * its 'unlink' flag set for each posted rqbd */
        cfs_list_for_each(tmp, &service->srv_active_rqbds) {
                struct ptlrpc_request_buffer_desc *rqbd =
                        cfs_list_entry(tmp, struct ptlrpc_request_buffer_desc,
                                       rqbd_list);

                rc = LNetMDUnlink(rqbd->rqbd_md_h);
                LASSERT (rc == 0 || rc == -ENOENT);
        }

        /* Wait for the network to release any buffers it's currently
         * filling */
        for (;;) {
                cfs_spin_lock(&service->srv_lock);
                rc = service->srv_nrqbd_receiving;
                cfs_spin_unlock(&service->srv_lock);

                if (rc == 0)
                        break;

                /* Network access will complete in finite time but the HUGE
                 * timeout lets us CWARN for visibility of sluggish NALs */
                lwi = LWI_TIMEOUT_INTERVAL(cfs_time_seconds(LONG_UNLINK),
                                           cfs_time_seconds(1), NULL, NULL);
                rc = l_wait_event(service->srv_waitq,
                                  service->srv_nrqbd_receiving == 0,
                                  &lwi);
                if (rc == -ETIMEDOUT)
                        CWARN("Service %s waiting for request buffers\n",
                              service->srv_name);
        }

        /* schedule all outstanding replies to terminate them */
        cfs_spin_lock(&service->srv_rs_lock);
        while (!cfs_list_empty(&service->srv_active_replies)) {
                struct ptlrpc_reply_state *rs =
                        cfs_list_entry(service->srv_active_replies.next,
                                       struct ptlrpc_reply_state, rs_list);
                cfs_spin_lock(&rs->rs_lock);
                ptlrpc_schedule_difficult_reply(rs);
                cfs_spin_unlock(&rs->rs_lock);
        }
        cfs_spin_unlock(&service->srv_rs_lock);

        /* purge the request queue.  NB No new replies (rqbds all unlinked)
         * and no service threads, so I'm the only thread noodling the
         * request queue now */
        while (!cfs_list_empty(&service->srv_req_in_queue)) {
                struct ptlrpc_request *req =
                        cfs_list_entry(service->srv_req_in_queue.next,
                                       struct ptlrpc_request,
                                       rq_list);

                cfs_list_del(&req->rq_list);
                service->srv_n_queued_reqs--;
                service->srv_n_active_reqs++;
                ptlrpc_server_finish_request(service, req);
        }
        while (ptlrpc_server_request_pending(service, 1)) {
                struct ptlrpc_request *req;

                req = ptlrpc_server_request_get(service, 1);
                cfs_list_del(&req->rq_list);
                service->srv_n_active_reqs++;
                ptlrpc_hpreq_fini(req);
                ptlrpc_server_finish_request(service, req);
        }
        LASSERT(service->srv_n_queued_reqs == 0);
        LASSERT(service->srv_n_active_reqs == 0);
        LASSERT(service->srv_n_history_rqbds == 0);
        LASSERT(cfs_list_empty(&service->srv_active_rqbds));

        /* Now free all the request buffers since nothing references them
         * any more... */
        while (!cfs_list_empty(&service->srv_idle_rqbds)) {
                struct ptlrpc_request_buffer_desc *rqbd =
                        cfs_list_entry(service->srv_idle_rqbds.next,
                                       struct ptlrpc_request_buffer_desc,
                                       rqbd_list);

                ptlrpc_free_rqbd(rqbd);
        }

        ptlrpc_wait_replies(service);

        cfs_list_for_each_entry_safe(rs, t, &service->srv_free_rs_list,
                                     rs_list) {
                cfs_list_del(&rs->rs_list);
                OBD_FREE_LARGE(rs, service->srv_max_reply_size);
        }

        /* In case somebody rearmed this in the meantime */
        cfs_timer_disarm(&service->srv_at_timer);

        if (array->paa_reqs_array != NULL) {
                OBD_FREE(array->paa_reqs_array,
                         sizeof(cfs_list_t) * array->paa_size);
                array->paa_reqs_array = NULL;
        }

        if (array->paa_reqs_count != NULL) {
                OBD_FREE(array->paa_reqs_count,
                         sizeof(__u32) * array->paa_size);
                array->paa_reqs_count= NULL;
        }

        OBD_FREE_PTR(service);
        RETURN(0);
}

/**
 * Returns 0 if the service is healthy.
 *
 * Right now, it just checks to make sure that requests aren't languishing
 * in the queue.  We'll use this health check to govern whether a node needs
 * to be shot, so it's intentionally non-aggressive. */
int ptlrpc_service_health_check(struct ptlrpc_service *svc)
{
        struct ptlrpc_request *request;
        struct timeval         right_now;
        long                   timediff;

        if (svc == NULL)
                return 0;

        cfs_gettimeofday(&right_now);

        cfs_spin_lock(&svc->srv_rq_lock);
        if (!ptlrpc_server_request_pending(svc, 1)) {
                cfs_spin_unlock(&svc->srv_rq_lock);
                return 0;
        }

        /* How long has the next entry been waiting? */
        if (cfs_list_empty(&svc->srv_request_queue))
                request = cfs_list_entry(svc->srv_request_hpq.next,
                                         struct ptlrpc_request, rq_list);
        else
                request = cfs_list_entry(svc->srv_request_queue.next,
                                         struct ptlrpc_request, rq_list);
        timediff = cfs_timeval_sub(&right_now, &request->rq_arrival_time, NULL);
        cfs_spin_unlock(&svc->srv_rq_lock);

        if ((timediff / ONE_MILLION) > (AT_OFF ? obd_timeout * 3/2 :
                                        at_max)) {
                CERROR("%s: unhealthy - request has been waiting %lds\n",
                       svc->srv_name, timediff / ONE_MILLION);
                return (-1);
        }

        return 0;
}
