/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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
#include <errno.h>
#include <signal.h>
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_import.h>

void ptlrpc_init_client(int req_portal, int rep_portal, char *name,
                        struct ptlrpc_client *cl)
{
        cl->cli_request_portal = req_portal;
        cl->cli_reply_portal   = rep_portal;
        cl->cli_name           = name;
}

struct obd_uuid *ptlrpc_req_to_uuid(struct ptlrpc_request *req)
{
        return &req->rq_connection->c_remote_uuid;
}

struct ptlrpc_connection *ptlrpc_uuid_to_connection(struct obd_uuid *uuid)
{
        struct ptlrpc_connection *c;
        struct ptlrpc_peer peer;
        int err;

        err = ptlrpc_uuid_to_peer(uuid, &peer);
        if (err != 0) {
                CERROR("cannot find peer %s!\n", uuid->uuid);
                return NULL;
        }

        c = ptlrpc_get_connection(&peer, uuid);
        if (c) {
                memcpy(c->c_remote_uuid.uuid,
                       uuid->uuid, sizeof(c->c_remote_uuid.uuid));
                c->c_epoch++;
        }

        CDEBUG(D_INFO, "%s -> %p\n", uuid->uuid, c);

        return c;
}

void ptlrpc_readdress_connection(struct ptlrpc_connection *conn,struct obd_uuid *uuid)
{
        struct ptlrpc_peer peer;
        int err;

        err = ptlrpc_uuid_to_peer (uuid, &peer);
        if (err != 0) {
                CERROR("cannot find peer %s!\n", uuid->uuid);
                return;
        }

        memcpy (&conn->c_peer, &peer, sizeof (peer));
        return;
}

struct ptlrpc_bulk_desc *ptlrpc_prep_bulk(struct ptlrpc_connection *conn)
{
        struct ptlrpc_bulk_desc *desc;

        OBD_ALLOC(desc, sizeof(*desc));
        if (desc != NULL) {
                desc->bd_connection = ptlrpc_connection_addref(conn);
                atomic_set(&desc->bd_refcount, 1);
                init_waitqueue_head(&desc->bd_waitq);
                INIT_LIST_HEAD(&desc->bd_page_list);
                INIT_LIST_HEAD(&desc->bd_set_chain);
                ptl_set_inv_handle(&desc->bd_md_h);
                ptl_set_inv_handle(&desc->bd_me_h);
        }

        return desc;
}

int ptlrpc_bulk_error(struct ptlrpc_bulk_desc *desc)
{
        int rc = 0;
        if (desc->bd_flags & PTL_RPC_FL_TIMEOUT) {
                rc = (desc->bd_flags & PTL_RPC_FL_INTR ? -ERESTARTSYS :
                      -ETIMEDOUT);
        }
        return rc;
}

struct ptlrpc_bulk_page *ptlrpc_prep_bulk_page(struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_bulk_page *bulk;

        OBD_ALLOC(bulk, sizeof(*bulk));
        if (bulk != NULL) {
                bulk->bp_desc = desc;
                list_add_tail(&bulk->bp_link, &desc->bd_page_list);
                desc->bd_page_count++;
        }
        return bulk;
}

void ptlrpc_free_bulk(struct ptlrpc_bulk_desc *desc)
{
        struct list_head *tmp, *next;
        ENTRY;
        if (desc == NULL) {
                EXIT;
                return;
        }

        LASSERT(list_empty(&desc->bd_set_chain));

        if (atomic_read(&desc->bd_refcount) != 0)
                CERROR("freeing desc %p with refcount %d!\n", desc,
                       atomic_read(&desc->bd_refcount));

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);
                ptlrpc_free_bulk_page(bulk);
        }

        ptlrpc_put_connection(desc->bd_connection);

        OBD_FREE(desc, sizeof(*desc));
        EXIT;
}

void ptlrpc_free_bulk_page(struct ptlrpc_bulk_page *bulk)
{
        ENTRY;
        if (bulk == NULL) {
                EXIT;
                return;
        }

        list_del(&bulk->bp_link);
        bulk->bp_desc->bd_page_count--;
        OBD_FREE(bulk, sizeof(*bulk));
        EXIT;
}

static int ll_sync_brw_timeout(void *data)
{
        struct obd_brw_set *set = data;
        struct list_head *tmp;
        int failed = 0;
        ENTRY;

        LASSERT(set);

        set->brw_flags |= PTL_RPC_FL_TIMEOUT;

        list_for_each(tmp, &set->brw_desc_head) {
                struct ptlrpc_bulk_desc *desc =
                        list_entry(tmp, struct ptlrpc_bulk_desc, bd_set_chain);

                /* Skip descriptors that were completed successfully. */
                if (desc->bd_flags & (PTL_BULK_FL_RCVD | PTL_BULK_FL_SENT))
                        continue;

                LASSERT(desc->bd_connection);

                /* If PtlMDUnlink succeeds, then bulk I/O on the MD hasn't
                 * even started yet.  XXX where do we kunmup the thing?
                 *
                 * If it fail with PTL_MD_BUSY, then the network is still
                 * reading/writing the buffers and we must wait for it to
                 * complete (which it will within finite time, most
                 * probably with failure; we really need portals error
                 * events to detect that).
                 *
                 * Otherwise (PTL_INV_MD) it completed after the bd_flags
                 * test above!
                 */
                if (PtlMDUnlink(desc->bd_md_h) != PTL_OK) {
                        CERROR("Near-miss on OST %s -- need to adjust "
                               "obd_timeout?\n",
                               desc->bd_connection->c_remote_uuid.uuid);
                        continue;
                }

                CERROR("IO of %d pages to/from %s:%d (conn %p) timed out\n",
                       desc->bd_page_count,
                       desc->bd_connection->c_remote_uuid.uuid,
                       desc->bd_portal, desc->bd_connection);

                /* This one will "never" arrive, don't wait for it. */
                if (atomic_dec_and_test(&set->brw_refcount))
                        wake_up(&set->brw_waitq);

                if (class_signal_connection_failure)
                        class_signal_connection_failure(desc->bd_connection);
                else
                        failed = 1;
        }

        /* 0 = We go back to sleep, until we're resumed or interrupted */
        /* 1 = We can't be recovered, just abort the syscall with -ETIMEDOUT */
        RETURN(failed);
}

static int ll_sync_brw_intr(void *data)
{
        struct obd_brw_set *set = data;

        ENTRY;
        set->brw_flags |= PTL_RPC_FL_INTR;
        RETURN(1); /* ignored, as of this writing */
}

int ll_brw_sync_wait(struct obd_brw_set *set, int phase)
{
        struct l_wait_info lwi;
        struct list_head *tmp, *next;
        int rc = 0;
        ENTRY;

        obd_brw_set_addref(set);
        switch(phase) {
        case CB_PHASE_START:
                lwi = LWI_TIMEOUT_INTR(obd_timeout * HZ, ll_sync_brw_timeout,
                                       ll_sync_brw_intr, set);
                rc = l_wait_event(set->brw_waitq,
                                  atomic_read(&set->brw_desc_count) == 0, &lwi);

                list_for_each_safe(tmp, next, &set->brw_desc_head) {
                        struct ptlrpc_bulk_desc *desc =
                                list_entry(tmp, struct ptlrpc_bulk_desc,
                                           bd_set_chain);
                        list_del_init(&desc->bd_set_chain);
                        ptlrpc_bulk_decref(desc);
                }
                break;
        case CB_PHASE_FINISH:
                if (atomic_dec_and_test(&set->brw_desc_count))
                        wake_up(&set->brw_waitq);
                break;
        default:
                LBUG();
        }
        obd_brw_set_decref(set);

        RETURN(rc);
}

struct ptlrpc_request *ptlrpc_prep_req(struct obd_import *imp, int opcode,
                                       int count, int *lengths, char **bufs)
{
        struct ptlrpc_connection *conn;
        struct ptlrpc_request *request;
        int rc;
        ENTRY;

        LASSERT((unsigned long)imp > 0x1000);
        conn = imp->imp_connection;

        OBD_ALLOC(request, sizeof(*request));
        if (!request) {
                CERROR("request allocation out of memory\n");
                RETURN(NULL);
        }

        rc = lustre_pack_msg(count, lengths, bufs,
                             &request->rq_reqlen, &request->rq_reqmsg);
        if (rc) {
                CERROR("cannot pack request %d\n", rc);
                OBD_FREE(request, sizeof(*request));
                RETURN(NULL);
        }

        request->rq_timeout = obd_timeout;
        request->rq_level = LUSTRE_CONN_FULL;
        request->rq_type = PTL_RPC_MSG_REQUEST;
        request->rq_import = imp;

        /* XXX FIXME bug 625069, now 249 */
        request->rq_request_portal = imp->imp_client->cli_request_portal;
        request->rq_reply_portal = imp->imp_client->cli_reply_portal;

        request->rq_connection = ptlrpc_connection_addref(conn);

        INIT_LIST_HEAD(&request->rq_list);
        atomic_set(&request->rq_refcount, 1);

        request->rq_reqmsg->magic = PTLRPC_MSG_MAGIC;
        request->rq_reqmsg->version = PTLRPC_MSG_VERSION;
        request->rq_reqmsg->opc = HTON__u32(opcode);
        request->rq_reqmsg->flags = 0;

        ptlrpc_hdl2req(request, &imp->imp_handle);
        RETURN(request);
}

static void __ptlrpc_free_req(struct ptlrpc_request *request, int locked)
{
        ENTRY;
        if (request == NULL) {
                EXIT;
                return;
        }

        /* We must take it off the imp_replay_list first.  Otherwise, we'll set
         * request->rq_reqmsg to NULL while osc_close is dereferencing it. */
        if (request->rq_import) {
                unsigned long flags = 0;
                if (!locked)
                        spin_lock_irqsave(&request->rq_import->imp_lock, flags);
                list_del_init(&request->rq_list);
                if (!locked)
                        spin_unlock_irqrestore(&request->rq_import->imp_lock,
                                               flags);
        }

        if (atomic_read(&request->rq_refcount) != 0) {
                CERROR("freeing request %p (%d->%s:%d) with refcount %d\n",
                       request, request->rq_reqmsg->opc,
                       request->rq_connection->c_remote_uuid.uuid,
                       request->rq_import->imp_client->cli_request_portal,
                       atomic_read (&request->rq_refcount));
                LBUG();
        }

        if (request->rq_repmsg != NULL) {
                OBD_FREE(request->rq_repmsg, request->rq_replen);
                request->rq_repmsg = NULL;
                request->rq_reply_md.start = NULL;
        }
        if (request->rq_reqmsg != NULL) {
                OBD_FREE(request->rq_reqmsg, request->rq_reqlen);
                request->rq_reqmsg = NULL;
        }

        ptlrpc_put_connection(request->rq_connection);
        OBD_FREE(request, sizeof(*request));
        EXIT;
}

void ptlrpc_free_req(struct ptlrpc_request *request)
{
        __ptlrpc_free_req(request, 0);
}

static int __ptlrpc_req_finished(struct ptlrpc_request *request, int locked)
{
        ENTRY;
        if (request == NULL)
                RETURN(1);

        if (request == (void *)(long)(0x5a5a5a5a5a5a5a5a)) {
                CERROR("dereferencing freed request (bug 575)\n");
                LBUG();
                RETURN(1);
        }

        DEBUG_REQ(D_INFO, request, "refcount now %u",
                  atomic_read(&request->rq_refcount) - 1);

        if (atomic_dec_and_test(&request->rq_refcount)) {
                __ptlrpc_free_req(request, locked);
                RETURN(1);
        }

        RETURN(0);
}

void ptlrpc_req_finished(struct ptlrpc_request *request)
{
        __ptlrpc_req_finished(request, 0);
}

static int ptlrpc_check_reply(struct ptlrpc_request *req)
{
        int rc = 0;

        ENTRY;
        if (req->rq_repmsg != NULL) {
                req->rq_transno = NTOH__u64(req->rq_repmsg->transno);
                /* Store transno in reqmsg for replay. */
                req->rq_reqmsg->transno = req->rq_repmsg->transno;
                req->rq_flags |= PTL_RPC_FL_REPLIED;
                GOTO(out, rc = 1);
        }

        if (req->rq_flags & PTL_RPC_FL_RESEND) {
                DEBUG_REQ(D_ERROR, req, "RESEND:");
                GOTO(out, rc = 1);
        }

        if (req->rq_flags & PTL_RPC_FL_ERR) {
                ENTRY;
                DEBUG_REQ(D_ERROR, req, "ABORTED:");
                GOTO(out, rc = 1);
        }

        if (req->rq_flags & PTL_RPC_FL_RESTART) {
                DEBUG_REQ(D_ERROR, req, "RESTART:");
                GOTO(out, rc = 1);
        }
        EXIT;
 out:
        DEBUG_REQ(D_NET, req, "rc = %d for", rc);
        return rc;
}

static int ptlrpc_check_status(struct ptlrpc_request *req)
{
        int err;
        ENTRY;

        err = req->rq_repmsg->status;
        if (req->rq_repmsg->type == NTOH__u32(PTL_RPC_MSG_ERR)) {
                DEBUG_REQ(D_ERROR, req, "type == PTL_RPC_MSG_ERR (%d)", err);
                RETURN(err ? err : -EINVAL);
        }

        if (err < 0) {
                DEBUG_REQ(D_INFO, req, "status is %d", err);
        } else if (err > 0) {
                /* XXX: translate this error from net to host */
                DEBUG_REQ(D_INFO, req, "status is %d", err);
        }

        RETURN(err);
}

static void ptlrpc_cleanup_request_buf(struct ptlrpc_request *request)
{
        OBD_FREE(request->rq_reqmsg, request->rq_reqlen);
        request->rq_reqmsg = NULL;
        request->rq_reqlen = 0;
}

/* Abort this request and cleanup any resources associated with it. */
int ptlrpc_abort(struct ptlrpc_request *request)
{
        /* First remove the ME for the reply; in theory, this means
         * that we can tear down the buffer safely. */
        if (PtlMEUnlink(request->rq_reply_me_h) != PTL_OK)
                RETURN(0);
        OBD_FREE(request->rq_reply_md.start, request->rq_replen);

        memset(&request->rq_reply_me_h, 0, sizeof(request->rq_reply_me_h));
        request->rq_reply_md.start = NULL;
        request->rq_repmsg = NULL;
        return 0;
}

/* caller must hold imp->imp_lock */
void ptlrpc_free_committed(struct obd_import *imp)
{
        struct list_head *tmp, *saved;
        struct ptlrpc_request *req;
        ENTRY;

        LASSERT(imp != NULL);

#ifdef CONFIG_SMP
        LASSERT(spin_is_locked(&imp->imp_lock));
#endif

        CDEBUG(D_HA, "%s: committing for last_committed "LPU64"\n",
               imp->imp_obd->obd_name, imp->imp_peer_committed_transno);

        list_for_each_safe(tmp, saved, &imp->imp_replay_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                if (req->rq_flags & PTL_RPC_FL_REPLAY) {
                        DEBUG_REQ(D_HA, req, "keeping (FL_REPLAY)");
                        continue;
                }

                /* not yet committed */
                if (req->rq_transno > imp->imp_peer_committed_transno) {
                        DEBUG_REQ(D_HA, req, "stopping search");
                        break;
                }

                DEBUG_REQ(D_HA, req, "committing (last_committed "LPU64")",
                          imp->imp_peer_committed_transno);
                list_del_init(&req->rq_list);
                __ptlrpc_req_finished(req, 1);
        }

        EXIT;
        return;
}

void ptlrpc_cleanup_client(struct obd_import *imp)
{
        struct list_head *tmp, *saved;
        struct ptlrpc_request *req;
        struct ptlrpc_connection *conn = imp->imp_connection;
        unsigned long flags;
        ENTRY;

        LASSERT(conn);

        spin_lock_irqsave(&imp->imp_lock, flags);
        list_for_each_safe(tmp, saved, &imp->imp_replay_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                /* XXX we should make sure that nobody's sleeping on these! */
                DEBUG_REQ(D_HA, req, "cleaning up from sending list");
                list_del_init(&req->rq_list);
                req->rq_import = NULL;
                __ptlrpc_req_finished(req, 0);
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        EXIT;
        return;
}

void ptlrpc_continue_req(struct ptlrpc_request *req)
{
        DEBUG_REQ(D_HA, req, "continuing delayed request");
        req->rq_reqmsg->addr = req->rq_import->imp_handle.addr;
        req->rq_reqmsg->cookie = req->rq_import->imp_handle.cookie;
        wake_up(&req->rq_wait_for_rep);
}

void ptlrpc_resend_req(struct ptlrpc_request *req)
{
        DEBUG_REQ(D_HA, req, "resending");
        req->rq_reqmsg->addr = req->rq_import->imp_handle.addr;
        req->rq_reqmsg->cookie = req->rq_import->imp_handle.cookie;
        req->rq_status = -EAGAIN;
        req->rq_level = LUSTRE_CONN_RECOVD;
        req->rq_flags |= PTL_RPC_FL_RESEND;
        req->rq_flags &= ~PTL_RPC_FL_TIMEOUT;
        wake_up(&req->rq_wait_for_rep);
}

void ptlrpc_restart_req(struct ptlrpc_request *req)
{
        DEBUG_REQ(D_HA, req, "restarting (possibly-)completed request");
        req->rq_status = -ERESTARTSYS;
        req->rq_flags |= PTL_RPC_FL_RESTART;
        req->rq_flags &= ~PTL_RPC_FL_TIMEOUT;
        wake_up(&req->rq_wait_for_rep);
}

static int expired_request(void *data)
{
        struct ptlrpc_request *req = data;

        ENTRY;
        if (!req) {
                CERROR("NULL req!");
                LBUG();
                RETURN(0);
        }

        DEBUG_REQ(D_ERROR, req, "timeout");
        ptlrpc_abort(req);
        req->rq_flags |= PTL_RPC_FL_TIMEOUT;

        if (!req->rq_import) {
                DEBUG_REQ(D_HA, req, "NULL import; already cleaned up?");
                RETURN(1);
        }

        if (!req->rq_import->imp_connection) {
                DEBUG_REQ(D_ERROR, req, "NULL connection");
                LBUG();
                RETURN(0);
        }

        if (!req->rq_import->imp_connection->c_recovd_data.rd_recovd)
                RETURN(1);

        recovd_conn_fail(req->rq_import->imp_connection);

        /* If this request is for recovery or other primordial tasks,
         * don't go back to sleep.
         */
        if (req->rq_level < LUSTRE_CONN_FULL)
                RETURN(1);
        RETURN(0);
}

static int interrupted_request(void *data)
{
        struct ptlrpc_request *req = data;
        ENTRY;
        req->rq_flags |= PTL_RPC_FL_INTR;
        RETURN(1); /* ignored, as of this writing */
}

struct ptlrpc_request *ptlrpc_request_addref(struct ptlrpc_request *req)
{
        ENTRY;
        atomic_inc(&req->rq_refcount);
        RETURN(req);
}

void ptlrpc_retain_replayable_request(struct ptlrpc_request *req,
                                      struct obd_import *imp)
{
        struct list_head *tmp;

#ifdef CONFIG_SMP
        LASSERT(spin_is_locked(&imp->imp_lock));
#endif

        LASSERT(imp->imp_flags & IMP_REPLAYABLE);
        /* Balanced in ptlrpc_free_committed, usually. */
        ptlrpc_request_addref(req);
        list_for_each_prev(tmp, &imp->imp_replay_list) {
                struct ptlrpc_request *iter =
                        list_entry(tmp, struct ptlrpc_request, rq_list);

                /* We may have duplicate transnos if we create and then
                 * open a file, or for closes retained if to match creating
                 * opens, so use req->rq_xid as a secondary key.
                 * (See bugs 684, 685, and 428.)
                 */
                if (iter->rq_transno > req->rq_transno)
                        continue;

                if (iter->rq_transno == req->rq_transno) {
                        LASSERT(iter->rq_xid != req->rq_xid);
                        if (iter->rq_xid > req->rq_xid)
                                continue;
                }

                list_add(&req->rq_list, &iter->rq_list);
                return;
        }

        list_add_tail(&req->rq_list, &imp->imp_replay_list);
}

int ptlrpc_queue_wait(struct ptlrpc_request *req)
{
        int rc = 0;
        struct l_wait_info lwi;
        struct obd_import *imp = req->rq_import;
        struct ptlrpc_connection *conn = imp->imp_connection;
        unsigned int flags;
        ENTRY;

        init_waitqueue_head(&req->rq_wait_for_rep);

        req->rq_xid = HTON__u32(ptlrpc_next_xid());

        /* for distributed debugging */
        req->rq_reqmsg->status = HTON__u32(current->pid);
        CDEBUG(D_RPCTRACE, "Sending RPC pid:xid:nid:opc %d:"LPU64":%s:"LPX64
               ":%d\n", NTOH__u32(req->rq_reqmsg->status), req->rq_xid,
               conn->c_peer.peer_ni->pni_name, conn->c_peer.peer_nid,
               NTOH__u32(req->rq_reqmsg->opc));

        spin_lock_irqsave(&imp->imp_lock, flags);

        /*
         * If the import has been invalidated (such as by an OST failure), the
         * request must fail with -EIO.
         */
        if (req->rq_import->imp_flags & IMP_INVALID) {
                DEBUG_REQ(D_ERROR, req, "IMP_INVALID:");
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                RETURN(-EIO);
        }

        if (req->rq_level > imp->imp_level) {
                list_del(&req->rq_list);
                list_add_tail(&req->rq_list, &imp->imp_delayed_list);
                spin_unlock_irqrestore(&imp->imp_lock, flags);

                DEBUG_REQ(D_HA, req, "\"%s\" waiting for recovery: (%d < %d)",
                          current->comm, req->rq_level, imp->imp_level);
                lwi = LWI_INTR(NULL, NULL);
                rc = l_wait_event(req->rq_wait_for_rep,
                                  (req->rq_level <= imp->imp_level) ||
                                  (req->rq_flags & PTL_RPC_FL_ERR), &lwi);

                if (req->rq_flags & PTL_RPC_FL_ERR)
                        rc = -EIO;

                if (!req->rq_import)
                        RETURN(rc);

                spin_lock_irqsave(&imp->imp_lock, flags);
                list_del_init(&req->rq_list);

                if (rc) {
                        spin_unlock_irqrestore(&imp->imp_lock, flags);
                        RETURN(rc);
                }

                CERROR("process %d resumed\n", current->pid);
        }
 resend:

        LASSERT(list_empty(&req->rq_list));
        list_add_tail(&req->rq_list, &imp->imp_sending_list);
        spin_unlock_irqrestore(&imp->imp_lock, flags);
        rc = ptl_send_rpc(req);
        if (rc) {
                CDEBUG(D_HA, "error %d, opcode %d, need recovery\n", rc,
                       req->rq_reqmsg->opc);
                /* sleep for a jiffy, then trigger recovery */
                lwi = LWI_TIMEOUT_INTR(1, expired_request,
                                       interrupted_request, req);
        } else {
                DEBUG_REQ(D_NET, req, "-- sleeping");
                lwi = LWI_TIMEOUT_INTR(req->rq_timeout * HZ, expired_request,
                                       interrupted_request, req);
        }
#ifdef __KERNEL__
        l_wait_event(req->rq_wait_for_rep, ptlrpc_check_reply(req), &lwi);
#else 
        { 
                extern int reply_in_callback(ptl_event_t *ev);
                ptl_event_t reply_ev;
                PtlEQWait(req->rq_connection->c_peer.peer_ni->pni_reply_in_eq_h, &reply_ev);
                reply_in_callback(&reply_ev); 
        }
#endif 

        DEBUG_REQ(D_NET, req, "-- done sleeping");

        spin_lock_irqsave(&imp->imp_lock, flags);
        list_del_init(&req->rq_list);
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        if (req->rq_flags & PTL_RPC_FL_ERR) {
                ptlrpc_abort(req);
                GOTO(out, rc = -EIO);
        }

        /* Don't resend if we were interrupted. */
        if ((req->rq_flags & (PTL_RPC_FL_RESEND | PTL_RPC_FL_INTR)) ==
            PTL_RPC_FL_RESEND) {
                if (req->rq_flags & PTL_RPC_FL_NO_RESEND) {
                        ptlrpc_abort(req); /* clean up reply buffers */
                        req->rq_flags &= ~PTL_RPC_FL_NO_RESEND;
                        GOTO(out, rc = -ETIMEDOUT);
                }
                req->rq_flags &= ~PTL_RPC_FL_RESEND;
                lustre_msg_add_flags(req->rq_reqmsg, MSG_RESENT);
                DEBUG_REQ(D_HA, req, "resending: ");
                spin_lock_irqsave(&imp->imp_lock, flags);
                goto resend;
        }

        if (req->rq_flags & PTL_RPC_FL_INTR) {
                if (!(req->rq_flags & PTL_RPC_FL_TIMEOUT))
                        LBUG(); /* should only be interrupted if we timed out */
                /* Clean up the dangling reply buffers */
                ptlrpc_abort(req);
                GOTO(out, rc = -EINTR);
        }

        if (req->rq_flags & PTL_RPC_FL_TIMEOUT)
                GOTO(out, rc = -ETIMEDOUT);

        if (!(req->rq_flags & PTL_RPC_FL_REPLIED))
                GOTO(out, rc = req->rq_status);

        rc = lustre_unpack_msg(req->rq_repmsg, req->rq_replen);
        if (rc) {
                CERROR("unpack_rep failed: %d\n", rc);
                GOTO(out, rc);
        }
#if 0
        /* FIXME: Enable when BlueArc makes new release */
        if (req->rq_repmsg->type != PTL_RPC_MSG_REPLY &&
            req->rq_repmsg->type != PTL_RPC_MSG_ERR) {
                CERROR("invalid packet type received (type=%u)\n",
                       req->rq_repmsg->type);
                LBUG();
                GOTO(out, rc = -EINVAL);
        }
#endif
        DEBUG_REQ(D_NET, req, "status %d", req->rq_repmsg->status);

        /* We're a rejected connection, need to invalidate and rebuild. */
        if (req->rq_repmsg->status == -ENOTCONN) {
                spin_lock_irqsave(&imp->imp_lock, flags);
                /* If someone else is reconnecting us (CONN_RECOVD) or has
                 * already completed it (handle mismatch), then we just need
                 * to get out.
                 */
                if (imp->imp_level == LUSTRE_CONN_RECOVD ||
                    imp->imp_handle.addr != req->rq_reqmsg->addr ||
                    imp->imp_handle.cookie != req->rq_reqmsg->cookie) {
                        spin_unlock_irqrestore(&imp->imp_lock, flags);
                        GOTO(out, rc = -EIO);
                }
                imp->imp_level = LUSTRE_CONN_RECOVD;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                if (imp->imp_recover != NULL) {
                        rc = imp->imp_recover(imp, PTLRPC_RECOVD_PHASE_NOTCONN);
                        if (rc)
                                LBUG();
                }
                GOTO(out, rc = -EIO);
        }

        rc = ptlrpc_check_status(req);

        if (req->rq_import->imp_flags & IMP_REPLAYABLE) {
                spin_lock_irqsave(&imp->imp_lock, flags);
                if ((req->rq_flags & PTL_RPC_FL_REPLAY || req->rq_transno != 0)
                    && rc >= 0) {
                        ptlrpc_retain_replayable_request(req, imp);
                }

                if (req->rq_transno > imp->imp_max_transno) {
                        imp->imp_max_transno = req->rq_transno;
                }

                /* Replay-enabled imports return commit-status information. */
                if (req->rq_repmsg->last_committed) {
                        imp->imp_peer_committed_transno =
                                req->rq_repmsg->last_committed;
                }
                ptlrpc_free_committed(imp);
                spin_unlock_irqrestore(&imp->imp_lock, flags);
        }

        EXIT;
 out:
        return rc;
}

int ptlrpc_replay_req(struct ptlrpc_request *req)
{
        int rc = 0, old_level, old_status = 0;
        // struct ptlrpc_client *cli = req->rq_import->imp_client;
        struct l_wait_info lwi;
        ENTRY;

        init_waitqueue_head(&req->rq_wait_for_rep);
        DEBUG_REQ(D_NET, req, "");

        req->rq_reqmsg->addr = req->rq_import->imp_handle.addr;
        req->rq_reqmsg->cookie = req->rq_import->imp_handle.cookie;

        /* temporarily set request to RECOVD level (reset at out:) */
        old_level = req->rq_level;
        if (req->rq_flags & PTL_RPC_FL_REPLIED)
                old_status = req->rq_repmsg->status;
        req->rq_level = LUSTRE_CONN_RECOVD;
        rc = ptl_send_rpc(req);
        if (rc) {
                CERROR("error %d, opcode %d\n", rc, req->rq_reqmsg->opc);
                ptlrpc_cleanup_request_buf(req);
                // up(&cli->cli_rpc_sem);
                GOTO(out, rc = -rc);
        }

        CDEBUG(D_OTHER, "-- sleeping\n");
        lwi = LWI_INTR(NULL, NULL); /* XXX needs timeout, nested recovery */
        l_wait_event(req->rq_wait_for_rep, ptlrpc_check_reply(req), &lwi);
        CDEBUG(D_OTHER, "-- done\n");

        // up(&cli->cli_rpc_sem);

        if (!(req->rq_flags & PTL_RPC_FL_REPLIED)) {
                CERROR("Unknown reason for wakeup\n");
                /* XXX Phil - I end up here when I kill obdctl */
                ptlrpc_abort(req);
                GOTO(out, rc = -EINTR);
        }

        rc = lustre_unpack_msg(req->rq_repmsg, req->rq_replen);
        if (rc) {
                CERROR("unpack_rep failed: %d\n", rc);
                GOTO(out, rc);
        }

        CDEBUG(D_NET, "got rep "LPD64"\n", req->rq_xid);

        /* let the callback do fixups, possibly including in the request */
        if (req->rq_replay_cb)
                req->rq_replay_cb(req);

        if ((req->rq_flags & PTL_RPC_FL_REPLIED) &&
            req->rq_repmsg->status != old_status) {
                DEBUG_REQ(D_HA, req, "status %d, old was %d",
                          req->rq_repmsg->status, old_status);
        }

 out:
        req->rq_level = old_level;
        RETURN(rc);
}

/* XXX looks a lot like super.c:invalidate_request_list, don't it? */
void ptlrpc_abort_inflight(struct obd_import *imp, int dying_import)
{
        unsigned long flags;
        struct list_head *tmp, *n;
        ENTRY;

        /* Make sure that no new requests get processed for this import.
         * ptlrpc_queue_wait must (and does) hold imp_lock while testing this
         * flag and then putting requests on sending_list or delayed_list.
         */
        if ((imp->imp_flags & IMP_REPLAYABLE) == 0) {
                spin_lock_irqsave(&imp->imp_lock, flags);
                imp->imp_flags |= IMP_INVALID;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
        }

        list_for_each_safe(tmp, n, &imp->imp_sending_list) {
                struct ptlrpc_request *req =
                        list_entry(tmp, struct ptlrpc_request, rq_list);

                DEBUG_REQ(D_HA, req, "inflight");
                req->rq_flags |= PTL_RPC_FL_ERR;
                if (dying_import)
                        req->rq_import = NULL;
                wake_up(&req->rq_wait_for_rep);
        }

        list_for_each_safe(tmp, n, &imp->imp_delayed_list) {
                struct ptlrpc_request *req =
                        list_entry(tmp, struct ptlrpc_request, rq_list);

                DEBUG_REQ(D_HA, req, "aborting waiting req");
                req->rq_flags |= PTL_RPC_FL_ERR;
                if (dying_import)
                        req->rq_import = NULL;
                wake_up(&req->rq_wait_for_rep);
        }
        EXIT;
}
