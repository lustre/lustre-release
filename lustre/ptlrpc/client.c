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

__u8 *ptlrpc_req_to_uuid(struct ptlrpc_request *req)
{
        return req->rq_connection->c_remote_uuid;
}

struct ptlrpc_connection *ptlrpc_uuid_to_connection(obd_uuid_t uuid)
{
        struct ptlrpc_connection *c;
        struct lustre_peer peer;
        int err;

        err = kportal_uuid_to_peer(uuid, &peer);
        if (err != 0) {
                CERROR("cannot find peer %s!\n", uuid);
                return NULL;
        }

        c = ptlrpc_get_connection(&peer, uuid);
        if (c) {
                memcpy(c->c_remote_uuid, uuid, sizeof(c->c_remote_uuid));
                c->c_epoch++;
        }

        CDEBUG(D_INFO, "%s -> %p\n", uuid, c);

        return c;
}

void ptlrpc_readdress_connection(struct ptlrpc_connection *conn,obd_uuid_t uuid)
{
        struct lustre_peer peer;
        int err;

        err = kportal_uuid_to_peer(uuid, &peer);
        if (err != 0) {
                CERROR("cannot find peer %s!\n", uuid);
                return;
        }

        memcpy(&conn->c_peer, &peer, sizeof(peer));
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

                /* If PtlMDUnlink succeeds, then it hasn't completed yet.  If it
                 * fails, the bulk finished _just_ in time (after the timeout
                 * fired but before we got this far) and we'll let it live.
                 */
                if (PtlMDUnlink(desc->bd_md_h) != 0) {
                        CERROR("Near-miss on OST %s -- need to adjust "
                               "obd_timeout?\n",
                               desc->bd_connection->c_remote_uuid);
                        continue;
                }

                CERROR("IO of %d pages to/from %s:%d (conn %p) timed out\n",
                       desc->bd_page_count, desc->bd_connection->c_remote_uuid,
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

        switch(phase) {
        case CB_PHASE_START:
                lwi = LWI_TIMEOUT_INTR(obd_timeout * HZ, ll_sync_brw_timeout,
                                       ll_sync_brw_intr, set);
                rc = l_wait_event(set->brw_waitq,
                                  atomic_read(&set->brw_refcount) == 0, &lwi);

                list_for_each_safe(tmp, next, &set->brw_desc_head) {
                        struct ptlrpc_bulk_desc *desc =
                                list_entry(tmp, struct ptlrpc_bulk_desc,
                                           bd_set_chain);
                        list_del_init(&desc->bd_set_chain);
                        ptlrpc_bulk_decref(desc);
                }
                break;
        case CB_PHASE_FINISH:
                if (atomic_dec_and_test(&set->brw_refcount))
                        wake_up(&set->brw_waitq);
                break;
        default:
                LBUG();
        }

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

        request->rq_level = LUSTRE_CONN_FULL;
        request->rq_type = PTL_RPC_MSG_REQUEST;
        request->rq_import = imp;

        /* XXX FIXME bug 625069 */
        request->rq_request_portal = imp->imp_client->cli_request_portal;
        request->rq_reply_portal = imp->imp_client->cli_reply_portal;

        request->rq_connection = ptlrpc_connection_addref(conn);

        INIT_LIST_HEAD(&request->rq_list);
        atomic_set(&request->rq_refcount, 1);

        spin_lock(&imp->imp_lock);
        request->rq_xid = HTON__u32(++imp->imp_last_xid);
        spin_unlock(&imp->imp_lock);

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

        if (atomic_read(&request->rq_refcount) != 0) {
                CERROR("freeing request %p (%d->%s:%d) with refcount %d\n",
                       request, request->rq_reqmsg->opc,
                       request->rq_connection->c_remote_uuid,
                       request->rq_import->imp_client->cli_request_portal,
                       request->rq_refcount);
                /* LBUG(); */
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

        if (request->rq_import) {
                if (!locked)
                        spin_lock(&request->rq_import->imp_lock);
                list_del_init(&request->rq_list);
                if (!locked)
                        spin_unlock(&request->rq_import->imp_lock);
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
                req->rq_flags |= PTL_RPC_FL_REPLIED;
                GOTO(out, rc = 1);
        }

        if (req->rq_flags & PTL_RPC_FL_RESEND) {
                ENTRY;
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
                DEBUG_REQ(D_ERROR, req, "type == PTL_RPC_MSG_ERR (%d)\n", err);
                RETURN(err ? err : -EINVAL);
        }

        if (err < 0) {
                DEBUG_REQ(D_ERROR, req, "status is %d", err);
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
static int ptlrpc_abort(struct ptlrpc_request *request)
{
        /* First remove the ME for the reply; in theory, this means
         * that we can tear down the buffer safely. */
        PtlMEUnlink(request->rq_reply_me_h);
        OBD_FREE(request->rq_reply_md.start, request->rq_replen);
        request->rq_repmsg = NULL;
        request->rq_replen = 0;
        return 0;
}

/* caller must hold imp->imp_lock */
void ptlrpc_free_committed(struct obd_import *imp)
{
        struct list_head *tmp, *saved;
        struct ptlrpc_request *req;
        ENTRY;

#ifdef CONFIG_SMP
        LASSERT(spin_is_locked(&imp->imp_lock));
#endif

        CDEBUG(D_HA, "committing for xid "LPU64", last_committed "LPU64"\n",
               imp->imp_peer_last_xid, imp->imp_peer_committed_transno);

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
        ENTRY;

        LASSERT(conn);

        spin_lock(&imp->imp_lock);
        list_for_each_safe(tmp, saved, &imp->imp_replay_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                /* XXX we should make sure that nobody's sleeping on these! */
                DEBUG_REQ(D_HA, req, "cleaning up from sending list");
                list_del_init(&req->rq_list);
                req->rq_import = NULL;
                __ptlrpc_req_finished(req, 0);
        }
        spin_unlock(&imp->imp_lock);
        
        EXIT;
        return;
}

void ptlrpc_continue_req(struct ptlrpc_request *req)
{
        ENTRY;
        DEBUG_REQ(D_HA, req, "continuing delayed request");
        req->rq_reqmsg->addr = req->rq_import->imp_handle.addr;
        req->rq_reqmsg->cookie = req->rq_import->imp_handle.cookie;
        wake_up(&req->rq_wait_for_rep);
        EXIT;
}

void ptlrpc_resend_req(struct ptlrpc_request *req)
{
        ENTRY;
        DEBUG_REQ(D_HA, req, "resending");
        req->rq_reqmsg->addr = req->rq_import->imp_handle.addr;
        req->rq_reqmsg->cookie = req->rq_import->imp_handle.cookie;
        req->rq_status = -EAGAIN;
        req->rq_level = LUSTRE_CONN_RECOVD;
        req->rq_flags |= PTL_RPC_FL_RESEND;
        req->rq_flags &= ~PTL_RPC_FL_TIMEOUT;
        wake_up(&req->rq_wait_for_rep);
        EXIT;
}

void ptlrpc_restart_req(struct ptlrpc_request *req)
{
        ENTRY;
        DEBUG_REQ(D_HA, req, "restarting (possibly-)completed request");
        req->rq_status = -ERESTARTSYS;
        req->rq_flags |= PTL_RPC_FL_RESTART;
        req->rq_flags &= ~PTL_RPC_FL_TIMEOUT;
        wake_up(&req->rq_wait_for_rep);
        EXIT;
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
        req->rq_flags |= PTL_RPC_FL_TIMEOUT;

        if (!req->rq_import) {
                DEBUG_REQ(D_ERROR, req, "NULL import");
                LBUG();
                RETURN(0);
        }

        if (!req->rq_import->imp_connection) {
                DEBUG_REQ(D_ERROR, req, "NULL connection");
                LBUG();
                RETURN(0);
        }

        if (!req->rq_import->imp_connection->c_recovd_data.rd_recovd)
                RETURN(1);

        req->rq_timeout = 0;
        recovd_conn_fail(req->rq_import->imp_connection);

#if 0
        /* If this request is for recovery or other primordial tasks,
         * don't go back to sleep.
         */
        if (req->rq_level < LUSTRE_CONN_FULL)
                RETURN(1);
#endif
        RETURN(0);
}

static int interrupted_request(void *data)
{
        struct ptlrpc_request *req = data;
        ENTRY;
        req->rq_flags |= PTL_RPC_FL_INTR;
        RETURN(1); /* ignored, as of this writing */
}

/* If the import has been invalidated (such as by an OST failure), the
 * request must fail with -EIO.
 *
 * Must be called with imp_lock held, will drop it if it returns -EIO.
 */
#define EIO_IF_INVALID(req)                                                   \
if (req->rq_import->imp_flags & IMP_INVALID) {                                \
        DEBUG_REQ(D_ERROR, req, "IMP_INVALID:");                              \
        spin_unlock(&imp->imp_lock);                                          \
        RETURN(-EIO);                                                         \
}

int ptlrpc_queue_wait(struct ptlrpc_request *req)
{
        int rc = 0;
        struct l_wait_info lwi;
        struct obd_import *imp = req->rq_import;
        struct ptlrpc_connection *conn = imp->imp_connection;
        ENTRY;

        init_waitqueue_head(&req->rq_wait_for_rep);

        /* for distributed debugging */
        req->rq_reqmsg->status = HTON__u32(current->pid); 
        CDEBUG(D_RPCTRACE, "Sending RPC pid:xid:nid:opc %d:"LPU64":%x:%d\n",
               NTOH__u32(req->rq_reqmsg->status), req->rq_xid,
               conn->c_peer.peer_nid, NTOH__u32(req->rq_reqmsg->opc));

        if (req->rq_level > imp->imp_level) {
                spin_lock(&imp->imp_lock);
                EIO_IF_INVALID(req);
                list_del(&req->rq_list);
                list_add_tail(&req->rq_list, &imp->imp_delayed_list);
                spin_unlock(&imp->imp_lock);

                DEBUG_REQ(D_HA, req, "\"%s\" waiting for recovery: (%d < %d)",
                          current->comm, req->rq_level, imp->imp_level);
                lwi = LWI_INTR(NULL, NULL);
                rc = l_wait_event(req->rq_wait_for_rep,
                                  (req->rq_level <= imp->imp_level) ||
                                  (req->rq_flags & PTL_RPC_FL_ERR), &lwi);

                spin_lock(&imp->imp_lock);
                list_del_init(&req->rq_list);
                spin_unlock(&imp->imp_lock);

                if (req->rq_flags & PTL_RPC_FL_ERR)
                        RETURN(-EIO);

                if (rc)
                        RETURN(rc);

                CERROR("process %d resumed\n", current->pid);
        }
 resend:
        req->rq_timeout = obd_timeout;
        spin_lock(&imp->imp_lock);
        EIO_IF_INVALID(req);

        LASSERT(list_empty(&req->rq_list));
        list_add_tail(&req->rq_list, &imp->imp_sending_list);
        spin_unlock(&imp->imp_lock);
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
        l_wait_event(req->rq_wait_for_rep, ptlrpc_check_reply(req), &lwi);
        DEBUG_REQ(D_NET, req, "-- done sleeping");

        spin_lock(&imp->imp_lock);
        list_del_init(&req->rq_list);
        spin_unlock(&imp->imp_lock);

        if (req->rq_flags & PTL_RPC_FL_ERR) {
                ptlrpc_abort(req);
                GOTO(out, rc = -EIO);
        }

        /* Don't resend if we were interrupted. */
        if ((req->rq_flags & (PTL_RPC_FL_RESEND | PTL_RPC_FL_INTR)) ==
            PTL_RPC_FL_RESEND) {
                req->rq_flags &= ~PTL_RPC_FL_RESEND;
                lustre_msg_add_flags(req->rq_reqmsg, MSG_RESENT);
                DEBUG_REQ(D_HA, req, "resending: ");
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
        CDEBUG(D_NET, "got rep "LPU64"\n", req->rq_xid);
        if (req->rq_repmsg->status == 0)
                CDEBUG(D_NET, "--> buf %p len %d status %d\n", req->rq_repmsg,
                       req->rq_replen, req->rq_repmsg->status);


        if (req->rq_import->imp_flags & IMP_REPLAYABLE) {
                spin_lock(&imp->imp_lock);
                if (req->rq_flags & PTL_RPC_FL_REPLAY || req->rq_transno != 0) {
                        /* Balanced in ptlrpc_free_committed, usually. */
                        atomic_inc(&req->rq_refcount);
                        list_add_tail(&req->rq_list, &imp->imp_replay_list);
                }

                if (req->rq_transno > imp->imp_max_transno) {
                        imp->imp_max_transno = req->rq_transno;
                } else if (req->rq_transno != 0 &&
                           imp->imp_level == LUSTRE_CONN_FULL) {
                        CDEBUG(D_HA, "got transno "LPD64" after "LPD64
                               ": recovery may not work\n", req->rq_transno,
                               imp->imp_max_transno);
                }

                /* Replay-enabled imports return commit-status information. */
                imp->imp_peer_last_xid = req->rq_repmsg->last_xid;
                imp->imp_peer_committed_transno =
                        req->rq_repmsg->last_committed;
                ptlrpc_free_committed(imp);
                spin_unlock(&imp->imp_lock);
        }

        rc = ptlrpc_check_status(req);

        EXIT;
 out:
        return rc;
}

#undef EIO_IF_INVALID

int ptlrpc_replay_req(struct ptlrpc_request *req)
{
        int rc = 0, old_level, old_status = 0;
        // struct ptlrpc_client *cli = req->rq_import->imp_client;
        struct l_wait_info lwi;
        ENTRY;

        init_waitqueue_head(&req->rq_wait_for_rep);
        DEBUG_REQ(D_NET, req, "");

        req->rq_timeout = obd_timeout;
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
