/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Portal-RPC reconnection and replay operations, for use in recovery.
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifdef __KERNEL__
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kmod.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_net.h>
#include <linux/lustre_import.h>
#include <linux/lustre_export.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h> /* for IOC_LOV_SET_OSC_ACTIVE */

#include "ptlrpc_internal.h"

int ptlrpc_reconnect_import(struct obd_import *imp,
                            struct ptlrpc_request **reqptr)
{
        struct obd_device *obd = imp->imp_obd;
        int flags, rc, size[] = {sizeof(imp->imp_target_uuid),
                                 sizeof(obd->obd_uuid),
                                 sizeof(imp->imp_dlm_handle)};
        char *tmp[] = {imp->imp_target_uuid.uuid,
                       obd->obd_uuid.uuid,
                       (char *)&imp->imp_dlm_handle};
        struct ptlrpc_connection *conn = imp->imp_connection;
        struct ptlrpc_request *req;
        struct lustre_handle old_hdl;

        spin_lock_irqsave(&imp->imp_lock, flags);
        imp->imp_generation++;
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        CERROR("reconnect handle "LPX64"\n", 
               imp->imp_dlm_handle.cookie);

        req = ptlrpc_prep_req(imp, imp->imp_connect_op, 3, size, tmp);
        if (!req)
                RETURN(-ENOMEM);
        req->rq_level = LUSTRE_CONN_NEW;
        req->rq_replen = lustre_msg_size(0, NULL);
        rc = ptlrpc_queue_wait(req);
        if (rc) {
                CERROR("cannot connect to %s@%s: rc = %d\n",
                       imp->imp_target_uuid.uuid, conn->c_remote_uuid.uuid, rc);
                GOTO(out_disc, rc);
        }

        if (lustre_msg_get_op_flags(req->rq_repmsg) & MSG_CONNECT_RECONNECT) {
                memset(&old_hdl, 0, sizeof(old_hdl));
                if (!memcmp(&old_hdl, &req->rq_repmsg->handle,
                            sizeof (old_hdl))) {
                        CERROR("%s@%s didn't like our handle "LPX64
                               ", failed\n", imp->imp_target_uuid.uuid,
                               conn->c_remote_uuid.uuid,
                               imp->imp_dlm_handle.cookie);
                        GOTO(out_disc, rc = -ENOTCONN);
                }

                if (memcmp(&imp->imp_remote_handle, &req->rq_repmsg->handle, 
                           sizeof(imp->imp_remote_handle))) {
                        CERROR("%s@%s changed handle from "LPX64" to "LPX64
                               "; copying, but this may foreshadow disaster\n",
                               imp->imp_target_uuid.uuid,
                               conn->c_remote_uuid.uuid,
                               imp->imp_remote_handle.cookie,
                               req->rq_repmsg->handle.cookie);
                        imp->imp_remote_handle = req->rq_repmsg->handle;
                        GOTO(out_disc, rc = 0);
                }

                CERROR("reconnected to %s@%s after partition\n",
                       imp->imp_target_uuid.uuid, conn->c_remote_uuid.uuid);
                GOTO(out_disc, rc = 0);
        }

        old_hdl = imp->imp_remote_handle;
        imp->imp_remote_handle = req->rq_repmsg->handle;
        CERROR("reconnected to %s@%s ("LPX64", was "LPX64")!\n",
               imp->imp_target_uuid.uuid, conn->c_remote_uuid.uuid,
               imp->imp_remote_handle.cookie, old_hdl.cookie);
        GOTO(out_disc, rc = 0);

 out_disc:
        *reqptr = req;
        return rc;
}

void ptlrpc_run_recovery_over_upcall(struct obd_device *obd)
{
        char *argv[4];
        char *envp[3];
        int rc;

        ENTRY;
        argv[0] = obd_lustre_upcall;
        argv[1] = "RECOVERY_OVER";
        argv[2] = obd->obd_uuid.uuid;
        argv[3] = NULL;

        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp[2] = NULL;

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("Error invoking recovery upcall %s %s %s: %d; check "
                       "/proc/sys/lustre/upcall\n",                
                       argv[0], argv[1], argv[2], rc);
                
        } else {
                CERROR("Invoked upcall %s %s %s",
                       argv[0], argv[1], argv[2]);
        }
}

void ptlrpc_run_failed_import_upcall(struct obd_import* imp)
{
        char *argv[6];
        char *envp[3];
        int rc;

        ENTRY;
        argv[0] = obd_lustre_upcall;
        argv[1] = "FAILED_IMPORT";
        argv[2] = imp->imp_target_uuid.uuid;
        argv[3] = imp->imp_obd->obd_uuid.uuid;
        argv[4] = imp->imp_connection->c_remote_uuid.uuid;
        argv[5] = NULL;

        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp[2] = NULL;

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("Error invoking recovery upcall %s %s %s %s %s: %d; check "
                       "/proc/sys/lustre/lustre_upcall\n",                
                       argv[0], argv[1], argv[2], argv[3], argv[4],rc);
                
        } else {
                CERROR("Invoked upcall %s %s %s %s %s\n",
                       argv[0], argv[1], argv[2], argv[3], argv[4]);
        }
}

int ptlrpc_replay(struct obd_import *imp)
{
        int rc = 0;
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        unsigned long flags;
        __u64 committed = imp->imp_peer_committed_transno;
        ENTRY;

        /* It might have committed some after we last spoke, so make sure we
         * get rid of them now.
         */
        spin_lock_irqsave(&imp->imp_lock, flags);
        ptlrpc_free_committed(imp);
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        CDEBUG(D_HA, "import %p from %s has committed "LPD64"\n",
               imp, imp->imp_target_uuid.uuid, committed);

        list_for_each(tmp, &imp->imp_replay_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_HA, req, "RETAINED: ");
        }

        /* Do I need to hold a lock across this iteration?  We shouldn't be
         * racing with any additions to the list, because we're in recovery
         * and are therefore not processing additional requests to add.  Calls
         * to ptlrpc_free_committed might commit requests, but nothing "newer"
         * than the one we're replaying (it can't be committed until it's
         * replayed, and we're doing that here).  l_f_e_safe protects against
         * problems with the current request being committed, in the unlikely
         * event of that race.  So, in conclusion, I think that it's safe to 
         * perform this list-walk without the imp_lock held.
         *
         * But, the {mdc,osc}_replay_open callbacks both iterate
         * request lists, and have comments saying they assume the
         * imp_lock is being held by ptlrpc_replay, but it's not. it's
         * just a little race...
         */
        list_for_each_safe(tmp, pos, &imp->imp_replay_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                DEBUG_REQ(D_HA, req, "REPLAY:");

                rc = ptlrpc_replay_req(req);
        
                if (rc) {
                        CERROR("recovery replay error %d for req "LPD64"\n",
                               rc, req->rq_xid);
                        RETURN(rc);
                }
        }

        RETURN(0);
}

int ptlrpc_resend(struct obd_import *imp)
{
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        unsigned long flags;

        ENTRY;

        /* As long as we're in recovery, nothing should be added to the sending
         * list, so we don't need to hold the lock during this iteration and
         * resend process.
         */
        spin_lock_irqsave(&imp->imp_lock, flags);
        LASSERT(imp->imp_level < LUSTRE_CONN_FULL);
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        list_for_each_safe(tmp, pos, &imp->imp_sending_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                ptlrpc_resend_req(req);
        }

        RETURN(0);
}

void ptlrpc_wake_delayed(struct obd_import *imp)
{
        unsigned long flags;
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;

        spin_lock_irqsave(&imp->imp_lock, flags);
        list_for_each_safe(tmp, pos, &imp->imp_delayed_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                ptlrpc_put_connection(req->rq_connection);
                req->rq_connection =
                       ptlrpc_connection_addref(req->rq_import->imp_connection);

                if (req->rq_set) {
                        DEBUG_REQ(D_HA, req, "waking (set %p):", req->rq_set);
                        wake_up(&req->rq_set->set_waitq);
                } else {
                        DEBUG_REQ(D_HA, req, "waking:");
                        wake_up(&req->rq_wait_for_rep);
                }
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);
}

inline void ptlrpc_invalidate_import_state(struct obd_import *imp)
{
        struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
        if (ptlrpc_ldlm_namespace_cleanup == NULL)
                CERROR("ptlrpc/ldlm hook is NULL!  Please tell phil\n");
        else
                ptlrpc_ldlm_namespace_cleanup(ns, 1 /* no network ops */);
        ptlrpc_abort_inflight(imp);
}

int ptlrpc_request_handle_eviction(struct ptlrpc_request *failed_req)
{
        int rc = 0, in_recovery = 0;
        struct obd_import *imp= failed_req->rq_import;
        unsigned long flags;
        struct ptlrpc_request *req;

        spin_lock_irqsave(&imp->imp_lock, flags);

        if (imp->imp_level == LUSTRE_CONN_NOTCONN)
                in_recovery = 1;

        if (failed_req->rq_import_generation == imp->imp_generation)
                imp->imp_level = LUSTRE_CONN_NOTCONN;
        else
                in_recovery = 1;

        spin_unlock_irqrestore(&imp->imp_lock, flags);

        if (in_recovery) {
                ptlrpc_resend_req(failed_req);
                RETURN(rc);
        }

        CDEBUG(D_HA, "import %s of %s@%s evicted: reconnecting\n",
               imp->imp_obd->obd_name,
               imp->imp_target_uuid.uuid,
               imp->imp_connection->c_remote_uuid.uuid);
        rc = ptlrpc_reconnect_import(imp, &req);
        if (rc) {
                ptlrpc_resend_req(failed_req);
                ptlrpc_fail_import(imp, imp->imp_generation);
        } else {
                spin_lock_irqsave (&failed_req->rq_lock, flags);
                failed_req->rq_err = 1;
                spin_unlock_irqrestore (&failed_req->rq_lock, flags);
                spin_lock_irqsave(&imp->imp_lock, flags);
                imp->imp_level = LUSTRE_CONN_FULL;
                imp->imp_invalid = 0;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                ptlrpc_invalidate_import_state(imp/*, req->rq_import_generation*/);
        }
        ptlrpc_req_finished(req);
        RETURN(rc);
}

int ptlrpc_set_import_active(struct obd_import *imp, int active)
{
        struct obd_device *notify_obd;
        unsigned long flags;
        int rc;

        LASSERT(imp->imp_obd);

        notify_obd = imp->imp_obd->u.cli.cl_containing_lov;

        /* When deactivating, mark import invalid, and 
           abort in-flight requests. */
        if (!active) {
                spin_lock_irqsave(&imp->imp_lock, flags);
                imp->imp_invalid = 1;
                spin_unlock_irqrestore(&imp->imp_lock, flags);

                ptlrpc_abort_inflight(imp);
        } 

        imp->imp_invalid = !active;

        if (notify_obd == NULL)
                GOTO(out, rc = 0);

        /* How gross is _this_? */
        if (!list_empty(&notify_obd->obd_exports)) {
                struct lustre_handle fakeconn;
                struct obd_ioctl_data ioc_data = { 0 };
                struct obd_export *exp =
                        list_entry(notify_obd->obd_exports.next,
                                   struct obd_export, exp_obd_chain);

                fakeconn.cookie = exp->exp_handle.h_cookie;
                ioc_data.ioc_inlbuf1 = (char *)&imp->imp_target_uuid;
                ioc_data.ioc_offset = active;
                rc = obd_iocontrol(IOC_LOV_SET_OSC_ACTIVE, &fakeconn,
                                   sizeof ioc_data, &ioc_data, NULL);
                if (rc)
                        CERROR("error %sabling %s on LOV %p/%s: %d\n",
                               active ? "en" : "dis",
                               imp->imp_target_uuid.uuid, notify_obd,
                               notify_obd->obd_uuid.uuid, rc);
        } else {
                CDEBUG(D_HA, "No exports for obd %p/%s, can't notify about "
                       "%p\n", notify_obd, notify_obd->obd_uuid.uuid,
                       imp->imp_obd->obd_uuid.uuid);
                rc = -ENOENT;
        }

out:
        /* When activating, mark import valid */
        if (active) {
                spin_lock_irqsave(&imp->imp_lock, flags);
                imp->imp_invalid = 0;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
        }

        RETURN(rc);
}

void ptlrpc_fail_import(struct obd_import *imp, int generation)
{
        unsigned long flags;
        int in_recovery = 0;
        ENTRY;

        LASSERT (!imp->imp_dlm_fake);
        
        /* If we were already in recovery, or if the import's connection to its
         * service is newer than the failing operation's original attempt, then
         * we don't want to recover again. */
        spin_lock_irqsave(&imp->imp_lock, flags);

        if (imp->imp_level == LUSTRE_CONN_RECOVD)
                in_recovery = 1;

        if (generation == imp->imp_generation) {
                imp->imp_level = LUSTRE_CONN_RECOVD;
                imp->imp_generation++;
        } else {
                in_recovery = 1;
        }

        spin_unlock_irqrestore(&imp->imp_lock, flags);

        if (in_recovery) {
                EXIT;
                return;
        }

        if (!imp->imp_replayable) {
                CDEBUG(D_HA,
                       "import %s@%s for %s not replayable, deactivating\n",
                       imp->imp_target_uuid.uuid,
                       imp->imp_connection->c_remote_uuid.uuid,
                       imp->imp_obd->obd_name);
                ptlrpc_set_import_active(imp, 0);
        }

        ptlrpc_run_failed_import_upcall(imp);
        EXIT;
}

static int signal_completed_replay(struct obd_import *imp)
{
        struct ptlrpc_request *req;
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(imp, OBD_PING, 0, NULL, NULL);
        if (!req)
                RETURN(-ENOMEM);

        req->rq_replen = lustre_msg_size(0, NULL);
        req->rq_level = LUSTRE_CONN_RECOVD;
        req->rq_reqmsg->flags |= MSG_LAST_REPLAY;

        rc = ptlrpc_queue_wait(req);

        ptlrpc_req_finished(req);
        RETURN(rc);
}

int ptlrpc_recover_import(struct obd_import *imp, char *new_uuid)
{
        int msg_flags = 0, rc;
        unsigned long flags;
        struct ptlrpc_request *req;
        ENTRY;

        spin_lock_irqsave(&imp->imp_lock, flags);
        if (imp->imp_level == LUSTRE_CONN_FULL) {
                imp->imp_level = LUSTRE_CONN_RECOVD;
                imp->imp_generation++;
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        if (new_uuid) {
                struct ptlrpc_connection *conn;
                struct obd_uuid uuid;
                struct ptlrpc_peer peer;
                struct obd_export *dlmexp;

                obd_str2uuid(&uuid, new_uuid);
                if (ptlrpc_uuid_to_peer(&uuid, &peer)) {
                        CERROR("no connection found for UUID %s\n", new_uuid);
                        RETURN(-EINVAL);
                }

                conn = ptlrpc_get_connection(&peer, &uuid);
                if (!conn)
                        RETURN(-ENOMEM);

                CDEBUG(D_HA, "switching import %s/%s from %s to %s\n",
                       imp->imp_target_uuid.uuid, imp->imp_obd->obd_name,
                       imp->imp_connection->c_remote_uuid.uuid,
                       conn->c_remote_uuid.uuid);

                /* Switch the import's connection and the DLM export's
                 * connection (which are almost certainly the same, but we
                 * keep distinct refs just to make things clearer. I think. */
                if (imp->imp_connection)
                        ptlrpc_put_connection(imp->imp_connection);
                /* We hand off the ref from ptlrpc_get_connection. */
                imp->imp_connection = conn;

                dlmexp = class_conn2export(&imp->imp_dlm_handle);
                if (dlmexp->exp_connection)
                        ptlrpc_put_connection(dlmexp->exp_connection);
                dlmexp->exp_connection = ptlrpc_connection_addref(conn);
                class_export_put(dlmexp);

        }

        rc = ptlrpc_reconnect_import(imp, &req);

        if (rc) {
                CERROR("failed to reconnect to %s@%s: %d\n",
                       imp->imp_target_uuid.uuid,
                       imp->imp_connection->c_remote_uuid.uuid, rc);
                RETURN(rc);
        }

        if (req->rq_repmsg)
                msg_flags = lustre_msg_get_op_flags(req->rq_repmsg);

        if (msg_flags & MSG_CONNECT_RECOVERING) {
                CDEBUG(D_HA, "replay requested by %s\n",
                       imp->imp_target_uuid.uuid);
                rc = ptlrpc_replay(imp);
                if (rc)
                        GOTO(out, rc);

                if (ptlrpc_ldlm_replay_locks == NULL)
                        CERROR("ptlrpc/ldlm hook is NULL!  Please tell phil\n");
                else
                        rc = ptlrpc_ldlm_replay_locks(imp);
                if (rc)
                        GOTO(out, rc);

                rc = signal_completed_replay(imp);
                if (rc)
                        GOTO(out, rc);
        } else if (msg_flags & MSG_CONNECT_RECONNECT) {
                CDEBUG(D_HA, "reconnected to %s@%s\n",
                       imp->imp_target_uuid.uuid,
                       imp->imp_connection->c_remote_uuid.uuid);
        } else {
                CDEBUG(D_HA, "evicted from %s@%s; invalidating\n",
                       imp->imp_target_uuid.uuid,
                       imp->imp_connection->c_remote_uuid.uuid);
                ptlrpc_invalidate_import_state(imp);
        }

        rc = ptlrpc_resend(imp);

        spin_lock_irqsave(&imp->imp_lock, flags);
        imp->imp_level = LUSTRE_CONN_FULL;
        imp->imp_invalid = 0;
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        ptlrpc_wake_delayed(imp);
        EXIT;
 out:
        ptlrpc_req_finished(req);
        return rc;
}

void ptlrpc_fail_export(struct obd_export *exp)
{
        int rc, already_failed;
        struct lustre_handle hdl;
        unsigned long flags;

        spin_lock_irqsave(&exp->exp_lock, flags);
        already_failed = exp->exp_failed;
        exp->exp_failed = 1;
        spin_unlock_irqrestore(&exp->exp_lock, flags);

        if (already_failed) {
                CDEBUG(D_HA, "disconnecting dead export %p/%s; skipping\n",
                       exp, exp->exp_client_uuid.uuid);
                return;
        }

        CDEBUG(D_HA, "disconnecting export %p/%s\n",
               exp, exp->exp_client_uuid.uuid);
        hdl.cookie = exp->exp_handle.h_cookie;
        rc = obd_disconnect(&hdl, 0);
        if (rc)
                CERROR("disconnecting export %p failed: %d\n", exp, rc);
}
