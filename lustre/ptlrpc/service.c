/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifndef __KERNEL__
#include <liblustre.h>
#include <linux/kp30.h>
#endif
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <portals/types.h>
#include "ptlrpc_internal.h"

static LIST_HEAD (ptlrpc_all_services);
static spinlock_t ptlrpc_all_services_lock = SPIN_LOCK_UNLOCKED;

static void
ptlrpc_free_server_req (struct ptlrpc_request *req)
{
        /* The last request to be received into a request buffer uses space
         * in the request buffer descriptor, otherwise requests are
         * allocated dynamically in the incoming reply event handler */
        if (req == &req->rq_rqbd->rqbd_req)
                return;

        OBD_FREE(req, sizeof(*req));
}
        
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
ptlrpc_alloc_rqbd (struct ptlrpc_srv_ni *srv_ni)
{
        struct ptlrpc_service             *svc = srv_ni->sni_service;
        unsigned long                      flags;
        struct ptlrpc_request_buffer_desc *rqbd;

        OBD_ALLOC(rqbd, sizeof (*rqbd));
        if (rqbd == NULL)
                return (NULL);

        rqbd->rqbd_srv_ni = srv_ni;
        rqbd->rqbd_refcount = 0;
        rqbd->rqbd_cbid.cbid_fn = request_in_callback;
        rqbd->rqbd_cbid.cbid_arg = rqbd;
        rqbd->rqbd_buffer = ptlrpc_alloc_request_buffer(svc->srv_buf_size);

        if (rqbd->rqbd_buffer == NULL) {
                OBD_FREE(rqbd, sizeof (*rqbd));
                return (NULL);
        }

        spin_lock_irqsave (&svc->srv_lock, flags);
        list_add(&rqbd->rqbd_list, &svc->srv_idle_rqbds);
        svc->srv_nbufs++;
        spin_unlock_irqrestore (&svc->srv_lock, flags);

        return (rqbd);
}

void
ptlrpc_free_rqbd (struct ptlrpc_request_buffer_desc *rqbd) 
{
        struct ptlrpc_srv_ni  *sni = rqbd->rqbd_srv_ni;
        struct ptlrpc_service *svc = sni->sni_service;
        unsigned long          flags;
        
        LASSERT (rqbd->rqbd_refcount == 0);

        spin_lock_irqsave(&svc->srv_lock, flags);
        list_del(&rqbd->rqbd_list);
        svc->srv_nbufs--;
        spin_unlock_irqrestore(&svc->srv_lock, flags);

        ptlrpc_free_request_buffer (rqbd->rqbd_buffer, svc->srv_buf_size);
        OBD_FREE (rqbd, sizeof (*rqbd));
}

void
ptlrpc_save_lock (struct ptlrpc_request *req, 
                  struct lustre_handle *lock, int mode)
{
        struct ptlrpc_reply_state *rs = req->rq_reply_state;
        int                        idx;

        LASSERT (rs != NULL);
        LASSERT (rs->rs_nlocks < RS_MAX_LOCKS);

        idx = rs->rs_nlocks++;
        rs->rs_locks[idx] = *lock;
        rs->rs_modes[idx] = mode;
        rs->rs_difficult = 1;
}

void
ptlrpc_schedule_difficult_reply (struct ptlrpc_reply_state *rs)
{
        struct ptlrpc_service *svc = rs->rs_srv_ni->sni_service;

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
        wake_up (&svc->srv_waitq);
}

void 
ptlrpc_commit_replies (struct obd_device *obd)
{
        struct list_head   *tmp;
        struct list_head   *nxt;
        unsigned long       flags;
        
        /* Find any replies that have been committed and get their service
         * to attend to complete them. */

        /* CAVEAT EMPTOR: spinlock ordering!!! */
        spin_lock_irqsave (&obd->obd_uncommitted_replies_lock, flags);

        list_for_each_safe (tmp, nxt, &obd->obd_uncommitted_replies) {
                struct ptlrpc_reply_state *rs =
                        list_entry (tmp, struct ptlrpc_reply_state, rs_obd_list);

                LASSERT (rs->rs_difficult);

                if (rs->rs_transno <= obd->obd_last_committed) {
                        struct ptlrpc_service *svc = rs->rs_srv_ni->sni_service;

                        spin_lock (&svc->srv_lock);
                        list_del_init (&rs->rs_obd_list);
                        ptlrpc_schedule_difficult_reply (rs);
                        spin_unlock (&svc->srv_lock);
                }
        }
        
        spin_unlock_irqrestore (&obd->obd_uncommitted_replies_lock, flags);
}

static long
timeval_sub(struct timeval *large, struct timeval *small)
{
        return (large->tv_sec - small->tv_sec) * 1000000 +
                (large->tv_usec - small->tv_usec);
}

static int
ptlrpc_server_post_idle_rqbds (struct ptlrpc_service *svc)
{
        struct ptlrpc_srv_ni              *srv_ni;
        struct ptlrpc_request_buffer_desc *rqbd;
        unsigned long                      flags;
        int                                rc;

        spin_lock_irqsave(&svc->srv_lock, flags);
        if (list_empty (&svc->srv_idle_rqbds)) {
                spin_unlock_irqrestore(&svc->srv_lock, flags);
                return (0);
        }

        rqbd = list_entry(svc->srv_idle_rqbds.next,
                          struct ptlrpc_request_buffer_desc,
                          rqbd_list);
        list_del (&rqbd->rqbd_list);

        /* assume we will post successfully */
        srv_ni = rqbd->rqbd_srv_ni;
        srv_ni->sni_nrqbd_receiving++;
        list_add (&rqbd->rqbd_list, &srv_ni->sni_active_rqbds);

        spin_unlock_irqrestore(&svc->srv_lock, flags);

        rc = ptlrpc_register_rqbd(rqbd);
        if (rc == 0)
                return (1);

        spin_lock_irqsave(&svc->srv_lock, flags);

        srv_ni->sni_nrqbd_receiving--;
        list_del(&rqbd->rqbd_list);
        list_add_tail(&rqbd->rqbd_list, &svc->srv_idle_rqbds);

        if (srv_ni->sni_nrqbd_receiving == 0) {
                /* This service is off-air on this interface because all
                 * its request buffers are busy.  Portals will have started
                 * dropping incoming requests until more buffers get
                 * posted */
                CERROR("All %s %s request buffers busy\n",
                       svc->srv_name, srv_ni->sni_ni->pni_name);
        }

        spin_unlock_irqrestore (&svc->srv_lock, flags);

        return (-1);
}

struct ptlrpc_service *
ptlrpc_init_svc(int nbufs, int bufsize, int max_req_size,
                int req_portal, int rep_portal, 
                svc_handler_t handler, char *name,
                struct proc_dir_entry *proc_entry)
{
        int                                i;
        int                                j;
        int                                ssize;
        struct ptlrpc_service             *service;
        struct ptlrpc_srv_ni              *srv_ni;
        struct ptlrpc_request_buffer_desc *rqbd;
        ENTRY;

        LASSERT (ptlrpc_ninterfaces > 0);
        LASSERT (nbufs > 0);
        LASSERT (bufsize >= max_req_size);
        
        ssize = offsetof (struct ptlrpc_service,
                          srv_interfaces[ptlrpc_ninterfaces]);
        OBD_ALLOC(service, ssize);
        if (service == NULL)
                RETURN(NULL);

        service->srv_name = name;
        spin_lock_init(&service->srv_lock);
        INIT_LIST_HEAD(&service->srv_threads);
        init_waitqueue_head(&service->srv_waitq);

        service->srv_max_req_size = max_req_size;
        service->srv_buf_size = bufsize;
        service->srv_rep_portal = rep_portal;
        service->srv_req_portal = req_portal;
        service->srv_handler = handler;

        INIT_LIST_HEAD(&service->srv_request_queue);
        INIT_LIST_HEAD(&service->srv_idle_rqbds);
        INIT_LIST_HEAD(&service->srv_reply_queue);

        /* First initialise enough for early teardown */
        for (i = 0; i < ptlrpc_ninterfaces; i++) {
                srv_ni = &service->srv_interfaces[i];

                srv_ni->sni_service = service;
                srv_ni->sni_ni = &ptlrpc_interfaces[i];
                INIT_LIST_HEAD(&srv_ni->sni_active_rqbds);
                INIT_LIST_HEAD(&srv_ni->sni_active_replies);
        }

        spin_lock (&ptlrpc_all_services_lock);
        list_add (&service->srv_list, &ptlrpc_all_services);
        spin_unlock (&ptlrpc_all_services_lock);
        
        /* Now allocate the request buffers, assuming all interfaces require
         * the same number. */
        for (i = 0; i < ptlrpc_ninterfaces; i++) {
                srv_ni = &service->srv_interfaces[i];
                CDEBUG (D_NET, "%s: initialising interface %s\n", name,
                        srv_ni->sni_ni->pni_name);

                for (j = 0; j < nbufs; j++) {
                        rqbd = ptlrpc_alloc_rqbd (srv_ni);
                        
                        if (rqbd == NULL) {
                                CERROR ("%s.%d: Can't allocate request %d "
                                        "on %s\n", name, i, j, 
                                        srv_ni->sni_ni->pni_name);
                                GOTO(failed, NULL);
                        }

                        /* We shouldn't be under memory pressure at
                         * startup, so fail if we can't post all our
                         * buffers at this time. */
                        if (ptlrpc_server_post_idle_rqbds(service) <= 0)
                                GOTO(failed, NULL);
                }
        }

        if (proc_entry != NULL)
                ptlrpc_lprocfs_register_service(proc_entry, service);

        CDEBUG(D_NET, "%s: Started on %d interfaces, listening on portal %d\n",
               service->srv_name, ptlrpc_ninterfaces, service->srv_req_portal);

        RETURN(service);
failed:
        ptlrpc_unregister_service(service);
        return NULL;
}

static void
ptlrpc_server_free_request(struct ptlrpc_service *svc, struct ptlrpc_request *req)
{
        unsigned long  flags;
        int            refcount;
        
        spin_lock_irqsave(&svc->srv_lock, flags);
        svc->srv_n_active_reqs--;
        refcount = --(req->rq_rqbd->rqbd_refcount);
        if (refcount == 0) {
                /* request buffer is now idle */
                list_del(&req->rq_rqbd->rqbd_list);
                list_add_tail(&req->rq_rqbd->rqbd_list,
                              &svc->srv_idle_rqbds);
        }
        spin_unlock_irqrestore(&svc->srv_lock, flags);

        ptlrpc_free_server_req(req);
}

static int 
ptlrpc_server_handle_request (struct ptlrpc_service *svc)
{
        struct ptlrpc_request *request;
        unsigned long          flags;
        struct timeval         work_start;
        struct timeval         work_end;
        long                   timediff;
        int                    rc;
        ENTRY;

        spin_lock_irqsave (&svc->srv_lock, flags);
        if (list_empty (&svc->srv_request_queue) ||
            (svc->srv_n_difficult_replies != 0 &&
             svc->srv_n_active_reqs >= (svc->srv_nthreads - 1))) {
                /* If all the other threads are handling requests, I must
                 * remain free to handle any 'difficult' reply that might
                 * block them */
                spin_unlock_irqrestore (&svc->srv_lock, flags);
                RETURN(0);
        }

        request = list_entry (svc->srv_request_queue.next,
                              struct ptlrpc_request, rq_list);
        list_del_init (&request->rq_list);
        svc->srv_n_queued_reqs--;
        svc->srv_n_active_reqs++;

        spin_unlock_irqrestore (&svc->srv_lock, flags);

        do_gettimeofday(&work_start);
        timediff = timeval_sub(&work_start, &request->rq_arrival_time);
        if (svc->srv_stats != NULL) {
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQWAIT_CNTR,
                                    timediff);
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQQDEPTH_CNTR,
                                    svc->srv_n_queued_reqs);
                lprocfs_counter_add(svc->srv_stats, PTLRPC_REQACTIVE_CNTR,
                                    svc->srv_n_active_reqs);
        }

#if SWAB_PARANOIA
        /* Clear request swab mask; this is a new request */
        request->rq_req_swab_mask = 0;
#endif
        rc = lustre_unpack_msg (request->rq_reqmsg, request->rq_reqlen);
        if (rc != 0) {
                CERROR ("error unpacking request: ptl %d from "LPX64
                        " xid "LPU64"\n", svc->srv_req_portal,
                       request->rq_peer.peer_nid, request->rq_xid);
                goto out;
        }

        rc = -EINVAL;
        if (request->rq_reqmsg->type != PTL_RPC_MSG_REQUEST) {
                CERROR("wrong packet type received (type=%u) from "
                       LPX64"\n", request->rq_reqmsg->type,
                       request->rq_peer.peer_nid);
                goto out;
        }

        CDEBUG(D_NET, "got req "LPD64"\n", request->rq_xid);

        /* Discard requests queued for longer than my timeout.  If the
         * client's timeout is similar to mine, she'll be timing out this
         * REQ anyway (bug 1502) */
        if (timediff / 1000000 > (long)obd_timeout) {
                CERROR("Dropping timed-out request from "LPX64
                       ": %ld seconds old\n",
                       request->rq_peer.peer_nid, timediff / 1000000);
                goto out;
        }

        request->rq_export = class_conn2export(&request->rq_reqmsg->handle);

        if (request->rq_export) {
                if (request->rq_reqmsg->conn_cnt <
                    request->rq_export->exp_conn_cnt) {
                        DEBUG_REQ(D_ERROR, request,
                                  "DROPPING req from old connection %d < %d",
                                  request->rq_reqmsg->conn_cnt,
                                  request->rq_export->exp_conn_cnt);
                        goto put_conn;
                }

                request->rq_export->exp_last_request_time =
                        LTIME_S(CURRENT_TIME);
        }

        CDEBUG(D_RPCTRACE, "Handling RPC pname:cluuid+ref:pid:xid:ni:nid:opc "
               "%s:%s+%d:%d:"LPU64":%s:"LPX64":%d\n", current->comm,
               (request->rq_export ?
                (char *)request->rq_export->exp_client_uuid.uuid : "0"),
               (request->rq_export ?
                atomic_read(&request->rq_export->exp_refcount) : -99),
               request->rq_reqmsg->status, request->rq_xid,
               request->rq_peer.peer_ni->pni_name,
               request->rq_peer.peer_nid,
               request->rq_reqmsg->opc);

        rc = svc->srv_handler(request);
        CDEBUG(D_RPCTRACE, "Handled RPC pname:cluuid+ref:pid:xid:ni:nid:opc "
               "%s:%s+%d:%d:"LPU64":%s:"LPX64":%d\n", current->comm,
               (request->rq_export ?
                (char *)request->rq_export->exp_client_uuid.uuid : "0"),
               (request->rq_export ?
                atomic_read(&request->rq_export->exp_refcount) : -99),
               request->rq_reqmsg->status, request->rq_xid,
               request->rq_peer.peer_ni->pni_name,
               request->rq_peer.peer_nid,
               request->rq_reqmsg->opc);

put_conn:
        if (request->rq_export != NULL)
                class_export_put(request->rq_export);

 out:
        do_gettimeofday(&work_end);

        timediff = timeval_sub(&work_end, &work_start);

        CDEBUG((timediff / 1000000 > (long)obd_timeout) ? D_ERROR : D_HA,
               "request "LPU64" opc %u from NID "LPX64" processed in %ldus "
               "(%ldus total)\n", request->rq_xid, request->rq_reqmsg->opc,
               request->rq_peer.peer_nid,
               timediff, timeval_sub(&work_end, &request->rq_arrival_time));

        if (svc->srv_stats != NULL) {
                int opc = opcode_offset(request->rq_reqmsg->opc);
                if (opc > 0) {
                        LASSERT(opc < LUSTRE_MAX_OPCODES);
                        lprocfs_counter_add(svc->srv_stats,
                                            opc + PTLRPC_LAST_CNTR,
                                            timediff);
                }
        }

        ptlrpc_server_free_request(svc, request);
        
        RETURN(1);
}

static int
ptlrpc_server_handle_reply (struct ptlrpc_service *svc) 
{
        struct ptlrpc_reply_state *rs;
        unsigned long              flags;
        struct obd_export         *exp;
        struct obd_device         *obd;
        int                        nlocks;
        int                        been_handled;
        ENTRY;

        spin_lock_irqsave (&svc->srv_lock, flags);
        if (list_empty (&svc->srv_reply_queue)) {
                spin_unlock_irqrestore (&svc->srv_lock, flags);
                RETURN(0);
        }
        
        rs = list_entry (svc->srv_reply_queue.next,
                         struct ptlrpc_reply_state, rs_list);

        exp = rs->rs_export;
        obd = exp->exp_obd;

        LASSERT (rs->rs_difficult);
        LASSERT (rs->rs_scheduled);

        list_del_init (&rs->rs_list);

        /* Disengage from notifiers carefully (lock ordering!) */
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
                      " o%d NID"LPX64"\n",
                      rs, 
                      rs->rs_xid, rs->rs_transno,
                      rs->rs_msg.opc, exp->exp_connection->c_peer.peer_nid);
        }

        if ((!been_handled && rs->rs_on_net) || 
            nlocks > 0) {
                spin_unlock_irqrestore(&svc->srv_lock, flags);
                
                if (!been_handled && rs->rs_on_net) {
                        PtlMDUnlink(rs->rs_md_h);
                        /* Ignore return code; we're racing with
                         * completion... */
                }

                while (nlocks-- > 0)
                        ldlm_lock_decref(&rs->rs_locks[nlocks], 
                                         rs->rs_modes[nlocks]);

                spin_lock_irqsave(&svc->srv_lock, flags);
        }

        rs->rs_scheduled = 0;

        if (!rs->rs_on_net) {
                /* Off the net */
                svc->srv_n_difficult_replies--;
                spin_unlock_irqrestore(&svc->srv_lock, flags);
                
                class_export_put (exp);
                rs->rs_export = NULL;
                lustre_free_reply_state (rs);
                atomic_dec (&svc->srv_outstanding_replies);
                RETURN(1);
        }
        
        /* still on the net; callback will schedule */
        spin_unlock_irqrestore (&svc->srv_lock, flags);
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
                
                if (svc->srv_nthreads != 0)     /* I've recursed */
                        continue;

                /* service threads can block for bulk, so this limits us
                 * (arbitrarily) to recursing 1 stack frame per service.
                 * Note that the problem with recursion is that we have to
                 * unwind completely before our caller can resume. */
                
                svc->srv_nthreads++;
                
                do {
                        rc = ptlrpc_server_handle_reply(svc);
                        rc |= ptlrpc_server_handle_request(svc);
                        rc |= (ptlrpc_server_post_idle_rqbds(svc) > 0);
                        did_something |= rc;
                } while (rc);
                
                svc->srv_nthreads--;
        }

        RETURN(did_something);
}

#else /* __KERNEL__ */

/* Don't use daemonize, it removes fs struct from new thread (bug 418) */
void ptlrpc_daemonize(void)
{
        exit_mm(current);
        lustre_daemonize_helper();
        exit_files(current);
        reparent_to_init();
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
        unsigned long           flags;
        ENTRY;

        lock_kernel();
        ptlrpc_daemonize();

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        THREAD_NAME(current->comm, "%s", data->name);
        unlock_kernel();

        /* Record that the thread is running */
        thread->t_flags = SVC_RUNNING;
        wake_up(&thread->t_ctl_waitq);

        spin_lock_irqsave(&svc->srv_lock, flags);
        svc->srv_nthreads++;
        spin_unlock_irqrestore(&svc->srv_lock, flags);

        /* XXX maintain a list of all managed devices: insert here */

        while ((thread->t_flags & SVC_STOPPING) == 0 ||
               svc->srv_n_difficult_replies != 0) {
                /* Don't exit while there are replies to be handled */
                struct l_wait_info lwi = LWI_TIMEOUT(svc->srv_rqbd_timeout,
                                                     ptlrpc_retry_rqbds, svc);

                l_wait_event_exclusive (svc->srv_waitq,
                              ((thread->t_flags & SVC_STOPPING) != 0 &&
                               svc->srv_n_difficult_replies == 0) ||
                              (!list_empty(&svc->srv_idle_rqbds) &&
                               svc->srv_rqbd_timeout == 0) ||
                              !list_empty (&svc->srv_reply_queue) ||
                              (!list_empty (&svc->srv_request_queue) &&
                               (svc->srv_n_difficult_replies == 0 ||
                                svc->srv_n_active_reqs <
                                (svc->srv_nthreads - 1))),
                              &lwi);

                if (!list_empty (&svc->srv_reply_queue))
                        ptlrpc_server_handle_reply (svc);

                /* only handle requests if there are no difficult replies
                 * outstanding, or I'm not the last thread handling
                 * requests */
                if (!list_empty (&svc->srv_request_queue) &&
                    (svc->srv_n_difficult_replies == 0 ||
                     svc->srv_n_active_reqs < (svc->srv_nthreads - 1)))
                        ptlrpc_server_handle_request (svc);

                if (!list_empty(&svc->srv_idle_rqbds) &&
                    ptlrpc_server_post_idle_rqbds(svc) < 0) {
                        /* I just failed to repost request buffers.  Wait
                         * for a timeout (unless something else happens)
                         * before I try again */
                        svc->srv_rqbd_timeout = HZ/10;
                }
        }

        spin_lock_irqsave(&svc->srv_lock, flags);

        svc->srv_nthreads--;                    /* must know immediately */
        thread->t_flags = SVC_STOPPED;
        wake_up(&thread->t_ctl_waitq);

        spin_unlock_irqrestore(&svc->srv_lock, flags);

        CDEBUG(D_NET, "service thread exiting, process %d\n", current->pid);
        return 0;
}

static void ptlrpc_stop_thread(struct ptlrpc_service *svc,
                               struct ptlrpc_thread *thread)
{
        struct l_wait_info lwi = { 0 };
        unsigned long      flags;

        spin_lock_irqsave(&svc->srv_lock, flags);
        thread->t_flags = SVC_STOPPING;
        spin_unlock_irqrestore(&svc->srv_lock, flags);

        wake_up_all(&svc->srv_waitq);
        l_wait_event(thread->t_ctl_waitq, (thread->t_flags & SVC_STOPPED),
                     &lwi);

        spin_lock_irqsave(&svc->srv_lock, flags);
        list_del(&thread->t_link);
        spin_unlock_irqrestore(&svc->srv_lock, flags);
        
        OBD_FREE(thread, sizeof(*thread));
}

void ptlrpc_stop_all_threads(struct ptlrpc_service *svc)
{
        unsigned long flags;
        struct ptlrpc_thread *thread;

        spin_lock_irqsave(&svc->srv_lock, flags);
        while (!list_empty(&svc->srv_threads)) {
                thread = list_entry(svc->srv_threads.next, 
                                    struct ptlrpc_thread, t_link);

                spin_unlock_irqrestore(&svc->srv_lock, flags);
                ptlrpc_stop_thread(svc, thread);
                spin_lock_irqsave(&svc->srv_lock, flags);
        }

        spin_unlock_irqrestore(&svc->srv_lock, flags);
}

int ptlrpc_start_n_threads(struct obd_device *dev, struct ptlrpc_service *svc,
                           int num_threads, char *base_name)
{
        int i, rc = 0;
        ENTRY;

        for (i = 0; i < num_threads; i++) {
                char name[32];
                sprintf(name, "%s_%02d", base_name, i);
                rc = ptlrpc_start_thread(dev, svc, name);
                if (rc) {
                        CERROR("cannot start %s thread #%d: rc %d\n", base_name,
                               i, rc);
                        ptlrpc_stop_all_threads(svc);
                }
        }
        RETURN(rc);
}

int ptlrpc_start_thread(struct obd_device *dev, struct ptlrpc_service *svc,
                        char *name)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_svc_data d;
        struct ptlrpc_thread *thread;
        unsigned long flags;
        int rc;
        ENTRY;

        OBD_ALLOC(thread, sizeof(*thread));
        if (thread == NULL)
                RETURN(-ENOMEM);
        init_waitqueue_head(&thread->t_ctl_waitq);
        
        d.dev = dev;
        d.svc = svc;
        d.name = name;
        d.thread = thread;

        spin_lock_irqsave(&svc->srv_lock, flags);
        list_add(&thread->t_link, &svc->srv_threads);
        spin_unlock_irqrestore(&svc->srv_lock, flags);

        /* CLONE_VM and CLONE_FILES just avoid a needless copy, because we
         * just drop the VM and FILES in ptlrpc_daemonize() right away.
         */
        rc = kernel_thread(ptlrpc_main, &d, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread: %d\n", rc);
                OBD_FREE(thread, sizeof(*thread));
                RETURN(rc);
        }
        l_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_RUNNING, &lwi);

        RETURN(0);
}
#endif

int ptlrpc_unregister_service(struct ptlrpc_service *service)
{
        int                   i;
        int                   rc;
        unsigned long         flags;
        struct ptlrpc_srv_ni *srv_ni;
        struct l_wait_info    lwi;
        struct list_head     *tmp;

        LASSERT(list_empty(&service->srv_threads));

        spin_lock (&ptlrpc_all_services_lock);
        list_del_init (&service->srv_list);
        spin_unlock (&ptlrpc_all_services_lock);

        ptlrpc_lprocfs_unregister_service(service);

        for (i = 0; i < ptlrpc_ninterfaces; i++) {
                srv_ni = &service->srv_interfaces[i];
                CDEBUG(D_NET, "%s: tearing down interface %s\n",
                       service->srv_name, srv_ni->sni_ni->pni_name);

                /* Unlink all the request buffers.  This forces a 'final'
                 * event with its 'unlink' flag set for each posted rqbd */
                list_for_each(tmp, &srv_ni->sni_active_rqbds) {
                        struct ptlrpc_request_buffer_desc *rqbd =
                                list_entry(tmp, struct ptlrpc_request_buffer_desc, 
                                           rqbd_list);

                        rc = PtlMDUnlink(rqbd->rqbd_md_h);
                        LASSERT (rc == PTL_OK || rc == PTL_MD_INVALID);
                }

                /* Wait for the network to release any buffers it's
                 * currently filling */
                for (;;) {
                        spin_lock_irqsave(&service->srv_lock, flags);
                        rc = srv_ni->sni_nrqbd_receiving;
                        spin_unlock_irqrestore(&service->srv_lock, flags);

                        if (rc == 0)
                                break;
                        
                        /* Network access will complete in finite time but
                         * the HUGE timeout lets us CWARN for visibility of
                         * sluggish NALs */
                        lwi = LWI_TIMEOUT(300 * HZ, NULL, NULL);
                        rc = l_wait_event(service->srv_waitq,
                                          srv_ni->sni_nrqbd_receiving == 0,
                                          &lwi);
                        if (rc == -ETIMEDOUT)
                                CWARN("Waiting for request buffers on "
                                      "service %s on interface %s ",
                                      service->srv_name, srv_ni->sni_ni->pni_name);
                }

                /* schedule all outstanding replies to terminate them */
                spin_lock_irqsave(&service->srv_lock, flags);
                while (!list_empty(&srv_ni->sni_active_replies)) {
                        struct ptlrpc_reply_state *rs =
                                list_entry(srv_ni->sni_active_replies.next,
                                           struct ptlrpc_reply_state,
                                           rs_list);
                        ptlrpc_schedule_difficult_reply(rs);
                }
                spin_unlock_irqrestore(&service->srv_lock, flags);
        }

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

                ptlrpc_server_free_request(service, req);
        }
        LASSERT(service->srv_n_queued_reqs == 0);
        LASSERT(service->srv_n_active_reqs == 0);

        for (i = 0; i < ptlrpc_ninterfaces; i++) {
                srv_ni = &service->srv_interfaces[i];
                LASSERT(list_empty(&srv_ni->sni_active_rqbds));
        }

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
                struct l_wait_info lwi = LWI_TIMEOUT(10 * HZ, NULL, NULL);

                rc = l_wait_event(service->srv_waitq,
                                  !list_empty(&service->srv_reply_queue), &lwi);
                LASSERT(rc == 0 || rc == -ETIMEDOUT);

                if (rc == 0) {
                        ptlrpc_server_handle_reply(service);
                        continue;
                }
                CWARN("Unexpectedly long timeout %p\n", service);
        }

        OBD_FREE(service,
                 offsetof(struct ptlrpc_service,
                          srv_interfaces[ptlrpc_ninterfaces]));
        return 0;
}
