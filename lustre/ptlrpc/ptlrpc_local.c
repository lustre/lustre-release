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

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#ifndef __KERNEL__
#include <liblustre.h>
#include <linux/kp30.h>
#endif
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <portals/types.h>
#include "ptlrpc_internal.h"


struct ptlrpc_local_cs *ost_local_svc = NULL;
struct ptlrpc_local_cs *mdt_local_svc = NULL;

static int local_handle(struct ptlrpc_request *req, svc_handler_t handler)
{
        int rc = 0;
        unsigned long flags;
        ENTRY;
/*
        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
*/
        req->rq_export = class_conn2export(&req->rq_reqmsg->handle);
        if (req->rq_export) {
                req->rq_connection = req->rq_export->exp_connection;
                ptlrpc_connection_addref(req->rq_connection);
                if (req->rq_reqmsg->conn_cnt < 
                    req->rq_export->exp_conn_cnt) {
                        DEBUG_REQ(D_ERROR, req,
                                  "DROPPING req from old connection %d < %d",
                                  req->rq_reqmsg->conn_cnt,
                                  req->rq_export->exp_conn_cnt);
                        rc = -EINVAL;
                        goto out_putconn;
                }

                req->rq_export->exp_last_request_time =
                        LTIME_S(CURRENT_TIME);
        } else {
                /* create a (hopefully temporary) connection that will be used
                 * to send the reply if this call doesn't create an export.
                 * XXX revisit this when we revamp ptlrpc */
                LBUG();
                req->rq_connection =
                        ptlrpc_get_connection(&req->rq_peer, NULL);
        }

        rc = handler(req);

        spin_lock_irqsave(&req->rq_lock, flags);
        memset(req->rq_ack_locks, 0, sizeof(req->rq_ack_locks));
        if (req->rq_bulk)
                req->rq_bulk->bd_complete = 1;
        req->rq_repmsg->type = (req->rq_type == PTL_LOCAL_MSG_ERR) ?
                PTL_RPC_MSG_ERR : PTL_RPC_MSG_REPLY;
        req->rq_repmsg->status = req->rq_status;
        req->rq_repmsg->opc = req->rq_reqmsg->opc;
        req->rq_receiving_reply = 0;
        req->rq_replied = 1;
        spin_unlock_irqrestore(&req->rq_lock, flags);

out_putconn:
        ptlrpc_put_connection(req->rq_connection);
        if (req->rq_export != NULL) {
                class_export_put(req->rq_export);
                req->rq_export = NULL;
        }
        
        RETURN(rc);

}

static int localrpc_main(void *arg)
{
        struct ptlrpc_local_cs *svc = arg;
        struct ptlrpc_thread *thread = svc->svc_thread;
        svc_handler_t handler = svc->srv_handler;
        unsigned long flags;
        int rc;
        
        lock_kernel();
        ptlrpc_daemonize();

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        THREAD_NAME(current->comm, "%s", "localrpc");
        unlock_kernel();

        thread->t_flags = SVC_RUNNING;
        wake_up(&thread->t_ctl_waitq);

        while (1) {
                struct ptlrpc_request *req;
                struct l_wait_info lwi = { 0 };
                
                l_wait_event(svc->req_waitq, 
                             !list_empty(&svc->req_list) || 
                             thread->t_flags & SVC_STOPPING, 
                             &lwi);

                if (thread->t_flags & SVC_STOPPING) {
                        struct list_head *tmp, *n;
                        list_for_each_safe(tmp, n, &svc->req_list) {
                                req = list_entry(tmp, struct ptlrpc_request, 
                                                 rq_list);
                                list_del_init(&req->rq_list);
                        }
                        break;
                }
                
                spin_lock_irqsave(&svc->req_lock, flags);
                req = list_entry(svc->req_list.next, struct ptlrpc_request, rq_list);
                list_del_init(&req->rq_list);
                spin_unlock_irqrestore(&svc->req_lock, flags);

                rc = local_handle(req, handler);
                wake_up(&req->rq_reply_waitq);
        
        }
        thread->t_flags = SVC_STOPPED;
        wake_up(&thread->t_ctl_waitq);
        RETURN(0);

}       

static int localrpc_start_thread(struct ptlrpc_local_cs *svc)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_thread *thread;
        int rc;
        ENTRY;

        OBD_ALLOC(thread, sizeof(*thread));
        if (thread == NULL) 
                RETURN(-ENOMEM);
        init_waitqueue_head(&thread->t_ctl_waitq);

        svc->svc_thread = thread;

        /* CLONE_VM and CLONE_FILES just avoid a needless copy, because we
         * just drop the VM and FILES in ptlrpc_daemonize() right away.
         */
        rc = kernel_thread(localrpc_main, svc, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread: %d\n", rc);
                GOTO(out_free, rc);
        }
        l_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_RUNNING, &lwi);
        
        RETURN(0);
out_free:
        OBD_FREE(thread, sizeof(*thread));
        RETURN(rc);
}

static int local_svc_available(struct ptlrpc_request *req)
{
        int req_portal = req->rq_request_portal;
        int req_opc = req->rq_reqmsg->opc;
        int av_portal = 0, av_opc = 1;

        av_portal =  (req_portal == MDS_REQUEST_PORTAL ||
                      req_portal == MDS_SETATTR_PORTAL ||
                      req_portal == MDS_READPAGE_PORTAL ||
                      req_portal == OST_REQUEST_PORTAL ||
                      req_portal == OST_CREATE_PORTAL) ? 1 : 0;
        
        /* XXX For debug: only LDLM_ENQUEUE available for local rpc */
        av_opc = (req_opc == LDLM_ENQUEUE) ? 1 : 0;
        
        return av_portal & av_opc;

}

static int _local_rpc_init(struct ptlrpc_local_cs **local_svc, 
                           svc_handler_t handler)
{
        int rc = 0;
        struct ptlrpc_local_cs *svc = NULL;
        
        OBD_ALLOC(svc, sizeof(*svc));
        if (svc == NULL)
                RETURN( -ENOMEM);
 
        svc->srv_handler = handler;
        INIT_LIST_HEAD(&svc->req_list);
        spin_lock_init(&svc->req_lock);
        init_waitqueue_head(&svc->req_waitq);
        
        rc = localrpc_start_thread(svc);
        if (rc) {
                OBD_FREE(svc, sizeof(*svc));
                RETURN(rc);
        }

        *local_svc = svc;
        RETURN(rc);
}

int local_rpc_init(char *type, struct ptlrpc_local_cs **svc, 
                   svc_handler_t handler)
{
        int rc = 0;

        if (strcmp(type, "ost") == 0) {
                if (ost_local_svc == NULL)
                        rc = _local_rpc_init(&ost_local_svc, handler);
                *svc = ost_local_svc;
        
        } else if (strcmp(type, "mdt") == 0) {
                if (mdt_local_svc == NULL)
                        rc = _local_rpc_init(&mdt_local_svc, handler);
                *svc = mdt_local_svc;
        } else {
                LBUG();
        }

        RETURN(rc);
}

static void _local_rpc_cleanup(struct ptlrpc_local_cs *svc)
{
        unsigned long flags;
        struct l_wait_info lw = { 0 };
        
        spin_lock_irqsave(&svc->req_lock, flags);
        svc->svc_thread->t_flags = SVC_STOPPING;
        spin_unlock_irqrestore(&svc->req_lock, flags);
        wake_up(&svc->req_waitq);
        
        l_wait_event(svc->svc_thread->t_ctl_waitq,
                     svc->svc_thread->t_flags & SVC_STOPPED,
                     &lw);
        
        OBD_FREE(svc->svc_thread, sizeof(*svc->svc_thread));
        OBD_FREE(svc, sizeof(*svc));
}

void local_rpc_cleanup(char *type)
{
        if (strcmp(type, "ost") == 0 && ost_local_svc != NULL) {
                _local_rpc_cleanup(ost_local_svc);
                ost_local_svc = NULL;
        } else if (strcmp(type, "mdt") == 0 && mdt_local_svc != NULL) {
                _local_rpc_cleanup(mdt_local_svc);
                mdt_local_svc = NULL;
        }
}

#define SAME_THREAD
int local_send_rpc(struct ptlrpc_request *req)
{
        struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
        int rc;
        unsigned long flags;
        struct l_wait_info lwi = { 0 };
        struct obd_ucred ucred;
        void *journal_info;
        int ngroups;
        ENTRY;
        
        /* XXX tight restriction for debug */
        if (local_svc_available(req) && cli->local_rpc != NULL &&
            req->rq_bulk == NULL) {
                struct ptlrpc_local_cs *svc = cli->local_rpc;
                
                req->rq_reqmsg->handle = req->rq_import->imp_remote_handle;
                req->rq_reqmsg->conn_cnt = req->rq_import->imp_conn_cnt;
                
                LASSERT (req->rq_replen != 0);
               
                spin_lock_irqsave (&req->rq_lock, flags);
                req->rq_receiving_reply = 1;
                req->rq_replied = 0;
                req->rq_err = 0;
                req->rq_timedout = 0;
                req->rq_resend = 0;
                req->rq_restart = 0;
                spin_unlock_irqrestore (&request->rq_lock, flags);
                
                req->rq_sent = LTIME_S(CURRENT_TIME);
//              ptlrpc_pinger_sending_on_import(req->rq_import);
                req->rq_type = PTL_LOCAL_MSG_REQUEST;

#ifndef SAME_THREAD        
                spin_lock_irqsave(&svc->req_lock, flags);
                list_del_init(&req->rq_list);
                list_add_tail(&req->rq_list, &svc->req_list);
                spin_unlock_irqrestore(&svc->req_lock, flags);
                wake_up(&svc->req_waitq);
                
                l_wait_event(req->rq_reply_waitq, req->rq_replied, &lwi);
#else

/*
                // for nesting journal
                journal_info = current->journal_info;
                current->journal_info = NULL;
*/                
                ucred.ouc_fsuid = current->fsuid;
                ucred.ouc_fsgid = current->fsgid;
                ucred.ouc_cap = current->cap_effective;
                ngroups = current->ngroups;
                current->fsuid = current->fsgid = 0;
                current->ngroups = 0;
                current->cap_effective = -1;
                
                rc = local_handle(req, svc->srv_handler);
                
                current->fsuid = ucred.ouc_fsuid;
                current->fsgid = ucred.ouc_fsgid;
                current->cap_effective = ucred.ouc_cap;
                current->ngroups = ngroups;
                
//              current->journal_info = journal_info;
#endif //SAME_THREAD
                ptlrpc_lprocfs_rpc_sent(req);

        } else {
                rc = -EOPNOTSUPP;
        }

        RETURN(rc);
}

int local_reply(struct ptlrpc_request *req)
{
        unsigned long flags;
        ENTRY;
        
        switch (req->rq_type) {
        case PTL_LOCAL_MSG_REQUEST:
                req->rq_type = PTL_LOCAL_MSG_REPLY;
        case PTL_LOCAL_MSG_REPLY:
        case PTL_LOCAL_MSG_ERR:
                spin_lock_irqsave(&req->rq_lock, flags);
                req->rq_want_ack = 0;
                spin_unlock_irqrestore(&req->rq_lock, flags);
                break;
        default:
                LBUG();
                break;
        }
        RETURN(0);
}

int local_error(struct ptlrpc_request *req)
{
        ENTRY;

        switch (req->rq_type) {
        case PTL_LOCAL_MSG_REQUEST:
        case PTL_LOCAL_MSG_REPLY:
                req->rq_type = PTL_LOCAL_MSG_ERR;
        case PTL_LOCAL_MSG_ERR:
                break;
        default:
                LBUG();
                break;
        }
        EXIT;

        return local_reply(req);
}

int local_bulk_move(struct ptlrpc_bulk_desc *desc)
{        
        struct ptlrpc_bulk_desc *source, *dest;
        struct ptlrpc_bulk_page *src_pg, *dst_pg;
        struct list_head *src, *dst;
        char *src_addr, *dst_addr;
        int len, i;
        unsigned long flags;

        if (desc->bd_type == BULK_GET_SINK) {
                source = desc->bd_req->rq_bulk;
                dest = desc;
        } else if (desc->bd_type == BULK_PUT_SOURCE) {
                source = desc;
                dest = desc->bd_req->rq_bulk;
        } else {
                LBUG();
        }

        LASSERT(source);
        LASSERT(dest);
        /* XXX need more investigation for sparse file case */
        if (source->bd_page_count != dest->bd_page_count)
                goto done;

        src = source->bd_page_list.next;
        dst = dest->bd_page_list.next;
        for (i = 0; i < dest->bd_page_count; i++) {
                src_pg = list_entry(src, struct ptlrpc_bulk_page, bp_link);
                dst_pg = list_entry(dst, struct ptlrpc_bulk_page, bp_link);

                len = MIN(src_pg->bp_buflen, dst_pg->bp_buflen);
                src_addr = kmap(src_pg->bp_page) + src_pg->bp_pageoffset;
                dst_addr = kmap(dst_pg->bp_page) + dst_pg->bp_pageoffset;
                memcpy(dst_addr, src_addr, len);
                kunmap(dst_pg->bp_page);
                kunmap(src_pg->bp_page);

                src = src->next;
                dst = dst->next;
        }
done:
        spin_lock_irqsave(&desc->bd_lock, flags);
        desc->bd_network_rw = 0;
        desc->bd_complete = 1;
        spin_unlock_irqrestore(&desc->bd_lock, flags);
/*        
        if (desc->bd_req->rq_set != NULL)
                wake_up (&desc->bd_req->rq_set->set_waitq);
        else
                wake_up (&desc->bd_req->rq_reply_waitq);
*/
        RETURN(0);
        
}


