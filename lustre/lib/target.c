/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
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
 * Target-common OBD method implementations and utility functions.
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OST /* XXX WRONG */

#include <linux/module.h>
#include <linux/obd_ost.h>
#include <linux/lustre_net.h>
#include <linux/lustre_dlm.h>

int target_handle_reconnect(struct lustre_handle *conn, struct obd_export *exp,
                            struct obd_uuid *cluuid)
{
        if (exp->exp_connection) {
                struct lustre_handle *hdl;
                hdl = &exp->exp_ldlm_data.led_import.imp_handle;
                /* Might be a re-connect after a partition. */
                if (!memcmp(conn, hdl, sizeof *conn)) {
                        CERROR("%s reconnecting\n", cluuid->uuid);
                        conn->addr = (__u64) (unsigned long)exp;
                        conn->cookie = exp->exp_cookie;
                        RETURN(EALREADY);
                } else {
                        CERROR("%s reconnecting from %s, "
                               "handle mismatch (ours "LPX64"/"LPX64", "
                               "theirs "LPX64"/"LPX64")\n", cluuid->uuid,
                               exp->exp_connection->c_remote_uuid.uuid,
                               hdl->addr,
                               hdl->cookie, conn->addr, conn->cookie);
                        /* XXX disconnect them here? */
                        memset(conn, 0, sizeof *conn);
                        /* This is a little scary, but right now we build this
                         * file separately into each server module, so I won't
                         * go _immediately_ to hell.
                         */
                        RETURN(-EALREADY);
                }
        }

        conn->addr = (__u64) (unsigned long)exp;
        conn->cookie = exp->exp_cookie;
        CDEBUG(D_INFO, "existing export for UUID '%s' at %p\n", cluuid->uuid, exp);
        CDEBUG(D_IOCTL,"connect: addr %Lx cookie %Lx\n",
               (long long)conn->addr, (long long)conn->cookie);
        RETURN(0);
}


int target_handle_connect(struct ptlrpc_request *req, svc_handler_t handler)
{
        struct obd_device *target;
        struct obd_export *export = NULL;
        struct obd_import *dlmimp;
        struct lustre_handle conn;
        struct obd_uuid tgtuuid;
        struct obd_uuid cluuid;
        struct list_head *p;
        int rc, i;
        ENTRY;

        if (req->rq_reqmsg->buflens[0] > 37) {
                CERROR("bad target UUID for connect\n");
                GOTO(out, rc = -EINVAL);
        }
        obd_str2uuid(&tgtuuid, lustre_msg_buf(req->rq_reqmsg, 0));

        if (req->rq_reqmsg->buflens[1] > 37) {
                CERROR("bad client UUID for connect\n");
                GOTO(out, rc = -EINVAL);
        }
        obd_str2uuid(&cluuid, lustre_msg_buf(req->rq_reqmsg, 1));

        i = class_uuid2dev(&tgtuuid);
        if (i == -1) {
                CERROR("UUID '%s' not found for connect\n", tgtuuid.uuid);
                GOTO(out, rc = -ENODEV);
        }

        target = &obd_dev[i];
        if (!target)
                GOTO(out, rc = -ENODEV);

        spin_lock_bh(&target->obd_processing_task_lock);
        if (target->obd_flags & OBD_ABORT_RECOVERY)
                target_abort_recovery(target);
        spin_unlock_bh(&target->obd_processing_task_lock);

        conn.addr = req->rq_reqmsg->addr;
        conn.cookie = req->rq_reqmsg->cookie;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                GOTO(out, rc);

        /* lctl gets a backstage, all-access pass. */
        if (!strcmp(cluuid.uuid, "OBD_CLASS_UUID"))
                goto dont_check_exports;

        spin_lock(&target->obd_dev_lock);
        list_for_each(p, &target->obd_exports) {
                export = list_entry(p, struct obd_export, exp_obd_chain);
                if (!memcmp(&cluuid, &export->exp_client_uuid,
                            sizeof(export->exp_client_uuid))) {
                        spin_unlock(&target->obd_dev_lock);
                        LASSERT(export->exp_obd == target);

                        rc = target_handle_reconnect(&conn, export, &cluuid);
                        break;
                }
                export = NULL;
        }
        /* If we found an export, we already unlocked. */
        if (!export)
                spin_unlock(&target->obd_dev_lock);

        /* Tell the client if we're in recovery. */
        /* If this is the first client, start the recovery timer */
        if (target->obd_flags & OBD_RECOVERING) {
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECOVERING);
                target_start_recovery_timer(target, handler);
        }

        /* Tell the client if we support replayable requests */
        if (target->obd_flags & OBD_REPLAYABLE)
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_REPLAYABLE);

        if (!export) {
                if (target->obd_flags & OBD_RECOVERING) {
                        CERROR("denying connection for new client %s: "
                               "in recovery\n", cluuid.uuid);
                        rc = -EBUSY;
                } else {
 dont_check_exports:
                        rc = obd_connect(&conn, target, &cluuid, ptlrpc_recovd,
                                         target_revoke_connection);
                }
        }

        /* If all else goes well, this is our RPC return code. */
        req->rq_status = 0;

        if (rc && rc != EALREADY)
                GOTO(out, rc);

        req->rq_repmsg->addr = conn.addr;
        req->rq_repmsg->cookie = conn.cookie;

        export = class_conn2export(&conn);
        LASSERT(export);

        req->rq_export = export;
        export->exp_connection = ptlrpc_get_connection(&req->rq_peer, &cluuid);
        if (req->rq_connection != NULL)
                ptlrpc_put_connection(req->rq_connection);
        req->rq_connection = ptlrpc_connection_addref(export->exp_connection);

        if (rc == EALREADY) {
                /* We indicate the reconnection in a flag, not an error code. */
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECONNECT);
                GOTO(out, rc = 0);
        }

        spin_lock(&export->exp_connection->c_lock);
        list_add(&export->exp_conn_chain, &export->exp_connection->c_exports);
        spin_unlock(&export->exp_connection->c_lock);
        recovd_conn_manage(export->exp_connection, ptlrpc_recovd,
                           target_revoke_connection);

        dlmimp = &export->exp_ldlm_data.led_import;
        dlmimp->imp_connection = req->rq_connection;
        dlmimp->imp_client = &export->exp_obd->obd_ldlm_client;
        dlmimp->imp_handle.addr = req->rq_reqmsg->addr;
        dlmimp->imp_handle.cookie = req->rq_reqmsg->cookie;
        dlmimp->imp_obd = target;
        dlmimp->imp_recover = NULL;
        INIT_LIST_HEAD(&dlmimp->imp_replay_list);
        INIT_LIST_HEAD(&dlmimp->imp_sending_list);
        INIT_LIST_HEAD(&dlmimp->imp_delayed_list);
        spin_lock_init(&dlmimp->imp_lock);
        dlmimp->imp_level = LUSTRE_CONN_FULL;
out:
        if (rc)
                req->rq_status = rc;
        RETURN(rc);
}

int target_handle_disconnect(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        int rc;
        ENTRY;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_disconnect(conn);
        req->rq_export = NULL;
        RETURN(0);
}

static int target_disconnect_client(struct ptlrpc_connection *conn)
{
        struct list_head *expiter, *n;
        struct lustre_handle hdl;
        struct obd_export *exp;
        int rc;
        ENTRY;

        list_for_each_safe(expiter, n, &conn->c_exports) {
                exp = list_entry(expiter, struct obd_export, exp_conn_chain);

                CDEBUG(D_HA, "disconnecting export %p/%s\n",
                       exp, exp->exp_client_uuid.uuid);
                hdl.addr = (__u64)(unsigned long)exp;
                hdl.cookie = exp->exp_cookie;
                rc = obd_disconnect(&hdl);
                if (rc)
                        CERROR("disconnecting export %p failed: %d\n", exp, rc);
        }

        /* XXX spank the connection (it's frozen in _RECOVD for now!) */
        RETURN(0);
}

static int target_fence_failed_connection(struct ptlrpc_connection *conn)
{
        ENTRY;

        conn->c_recovd_data.rd_phase = RD_PREPARED;

        RETURN(0);
}

int target_revoke_connection(struct recovd_data *rd, int phase)
{
        struct ptlrpc_connection *conn = class_rd2conn(rd);

        LASSERT(conn);
        ENTRY;

        switch (phase) {
            case PTLRPC_RECOVD_PHASE_PREPARE:
                RETURN(target_fence_failed_connection(conn));
            case PTLRPC_RECOVD_PHASE_RECOVER:
                RETURN(target_disconnect_client(conn));
            case PTLRPC_RECOVD_PHASE_FAILURE:
                LBUG();
                RETURN(0);
        }

        LBUG();
        RETURN(-ENOSYS);
}

/*
 * Recovery functions 
 */

static void abort_delayed_replies(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        struct list_head *tmp, *n;
        list_for_each_safe(tmp, n, &obd->obd_delayed_reply_queue) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_ERROR, req, "aborted:");
                req->rq_status = -ENOTCONN;
                req->rq_type = PTL_RPC_MSG_ERR;
                ptlrpc_reply(req->rq_svc, req);
                list_del(&req->rq_list);
                OBD_FREE(req, sizeof *req);
        }
}

void target_abort_recovery(void *data)
{
        struct obd_device *obd = data;
        CERROR("disconnecting clients and aborting recovery\n");
        obd->obd_recoverable_clients = 0;
        obd->obd_flags &= ~(OBD_RECOVERING | OBD_ABORT_RECOVERY);
        abort_delayed_replies(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);
        class_disconnect_all(obd);
        spin_lock_bh(&obd->obd_processing_task_lock);
}

static void target_recovery_expired(unsigned long castmeharder)
{
        struct obd_device *obd = (struct obd_device *)castmeharder;
        CERROR("recovery timed out, aborting\n");
        spin_lock_bh(&obd->obd_processing_task_lock);
        obd->obd_flags |= OBD_ABORT_RECOVERY;
        wake_up(&obd->obd_next_transno_waitq);
        spin_unlock_bh(&obd->obd_processing_task_lock);
}

static void reset_recovery_timer(struct obd_device *obd)
{
        CDEBUG(D_ERROR, "timer will expire in %ld seconds\n",
               OBD_RECOVERY_TIMEOUT / HZ);
        mod_timer(&obd->obd_recovery_timer, jiffies + OBD_RECOVERY_TIMEOUT);
}


/* Only start it the first time called */
void target_start_recovery_timer(struct obd_device *obd, svc_handler_t handler)
{
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovery_handler) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return;
        }
        CERROR("%s: starting recovery timer\n", obd->obd_name);
        obd->obd_recovery_handler = handler;
        obd->obd_recovery_timer.function = target_recovery_expired;
        obd->obd_recovery_timer.data = (unsigned long)obd;
        init_timer(&obd->obd_recovery_timer);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        reset_recovery_timer(obd);
}

static void cancel_recovery_timer(struct obd_device *obd)
{
        del_timer(&obd->obd_recovery_timer);
}

static int check_for_next_transno(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        req = list_entry(obd->obd_recovery_queue.next,
                         struct ptlrpc_request, rq_list);
        LASSERT(req->rq_reqmsg->transno >= obd->obd_next_recovery_transno);

        return req->rq_reqmsg->transno == obd->obd_next_recovery_transno ||
                (obd->obd_flags & OBD_RECOVERING) == 0;
}

static void process_recovery_queue(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        int aborted = 0;
        ENTRY;

        for (;;) {
                spin_lock_bh(&obd->obd_processing_task_lock);
                LASSERT(obd->obd_processing_task == current->pid);
                req = list_entry(obd->obd_recovery_queue.next,
                                 struct ptlrpc_request, rq_list);

                if (req->rq_reqmsg->transno != obd->obd_next_recovery_transno) {
                        struct l_wait_info lwi = { 0 };
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        CDEBUG(D_HA, "Waiting for transno "LPD64" (1st is "
                               LPD64")\n",
                               obd->obd_next_recovery_transno,
                               req->rq_reqmsg->transno);
                        l_wait_event(obd->obd_next_transno_waitq,
                                     check_for_next_transno(obd), &lwi);
                        spin_lock_bh(&obd->obd_processing_task_lock);
                        if (obd->obd_flags & OBD_ABORT_RECOVERY) {
                                target_abort_recovery(obd);
                                aborted = 1;
                        }
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        if (aborted)
                                return;
                        continue;
                }
                list_del_init(&req->rq_list);
                spin_unlock_bh(&obd->obd_processing_task_lock);

                DEBUG_REQ(D_ERROR, req, "processing: ");
                (void)obd->obd_recovery_handler(req);
                reset_recovery_timer(obd);
#warning FIXME: mds_fsync_super(mds->mds_sb);
                OBD_FREE(req, sizeof *req);
                spin_lock_bh(&obd->obd_processing_task_lock);
                obd->obd_next_recovery_transno++;
                if (list_empty(&obd->obd_recovery_queue)) {
                        obd->obd_processing_task = 0;
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        break;
                }
                spin_unlock_bh(&obd->obd_processing_task_lock);
        }
        EXIT;
}

int target_queue_recovery_request(struct ptlrpc_request *req,
                                  struct obd_device *obd)
{
        struct list_head *tmp;
        int inserted = 0;
        __u64 transno = req->rq_reqmsg->transno;
        struct ptlrpc_request *saved_req;

        if (!transno) {
                INIT_LIST_HEAD(&req->rq_list);
                DEBUG_REQ(D_HA, req, "not queueing");
                return 1;
        }

        spin_lock_bh(&obd->obd_processing_task_lock);

        if (obd->obd_processing_task == current->pid) {
                /* Processing the queue right now, don't re-add. */
                LASSERT(list_empty(&req->rq_list));
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return 1;
        }

        OBD_ALLOC(saved_req, sizeof *saved_req);
        if (!saved_req)
                LBUG();
        memcpy(saved_req, req, sizeof *req);
        req = saved_req;
        INIT_LIST_HEAD(&req->rq_list);

        /* XXX O(n^2) */
        list_for_each(tmp, &obd->obd_recovery_queue) {
                struct ptlrpc_request *reqiter =
                        list_entry(tmp, struct ptlrpc_request, rq_list);

                if (reqiter->rq_reqmsg->transno > transno) {
                        list_add_tail(&req->rq_list, &reqiter->rq_list);
                        inserted = 1;
                        break;
                }
        }

        if (!inserted) {
                list_add_tail(&req->rq_list, &obd->obd_recovery_queue);
        }

        if (obd->obd_processing_task != 0) {
                /* Someone else is processing this queue, we'll leave it to
                 * them.
                 */
                if (transno == obd->obd_next_recovery_transno)
                        wake_up(&obd->obd_next_transno_waitq);
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return 0;
        }

        /* Nobody is processing, and we know there's (at least) one to process
         * now, so we'll do the honours.
         */
        obd->obd_processing_task = current->pid;
        spin_unlock_bh(&obd->obd_processing_task_lock);

        process_recovery_queue(obd);
        return 0;
}

struct obd_device * target_req2obd(struct ptlrpc_request *req)
{
        return req->rq_export->exp_obd;
}

int target_queue_final_reply(struct ptlrpc_request *req, int rc)
{
        struct obd_device *obd = target_req2obd(req);
        struct ptlrpc_request *saved_req;

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (rc) {
                /* Just like ptlrpc_error, but without the sending. */
                lustre_pack_msg(0, NULL, NULL, &req->rq_replen,
                                &req->rq_repmsg);
                req->rq_type = PTL_RPC_MSG_ERR;
        }

        LASSERT(list_empty(&req->rq_list));
        OBD_ALLOC(saved_req, sizeof *saved_req);
        memcpy(saved_req, req, sizeof *saved_req);
        req = saved_req;
        list_add(&req->rq_list, &obd->obd_delayed_reply_queue);
        if (--obd->obd_recoverable_clients == 0) {
                struct list_head *tmp, *n;
                ldlm_reprocess_all_ns(req->rq_export->exp_obd->obd_namespace);
                CDEBUG(D_ERROR,
                       "all clients recovered, sending delayed replies\n");
                obd->obd_flags &= ~OBD_RECOVERING;
                list_for_each_safe(tmp, n, &obd->obd_delayed_reply_queue) {
                        req = list_entry(tmp, struct ptlrpc_request, rq_list);
                        DEBUG_REQ(D_ERROR, req, "delayed:");
                        ptlrpc_reply(req->rq_svc, req);
                        list_del(&req->rq_list);
                        OBD_FREE(req, sizeof *req);
                }
                cancel_recovery_timer(obd);
        } else {
                CERROR("%d recoverable clients remain\n",
                       obd->obd_recoverable_clients);
        }

        spin_unlock_bh(&obd->obd_processing_task_lock);
        return 1;
}
