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
# include <linux/config.h>
# include <linux/module.h>
# include <linux/kmod.h>
#else
# include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_net.h>
#include <linux/lustre_import.h>
#include <linux/lustre_export.h>
#include <linux/obd.h>
#include <linux/obd_ost.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h> /* for IOC_LOV_SET_OSC_ACTIVE */

#include "ptlrpc_internal.h"

static int ptlrpc_recover_import_no_retry(struct obd_import *, char *);

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
#ifdef __KERNEL__
        char *argv[7];
        char *envp[3];
        int rc;

        ENTRY;
        argv[0] = obd_lustre_upcall;
        argv[1] = "FAILED_IMPORT";
        argv[2] = imp->imp_target_uuid.uuid;
        argv[3] = imp->imp_obd->obd_name;
        argv[4] = imp->imp_connection->c_remote_uuid.uuid;
        argv[5] = imp->imp_obd->obd_uuid.uuid;
        argv[6] = NULL;

        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp[2] = NULL;

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("Error invoking recovery upcall %s %s %s %s %s: %d; "
                       "check /proc/sys/lustre/lustre_upcall\n",
                       argv[0], argv[1], argv[2], argv[3], argv[4],rc);

        } else {
                CERROR("Invoked upcall %s %s %s %s %s\n",
                       argv[0], argv[1], argv[2], argv[3], argv[4]);
        }
#else
        ptlrpc_recover_import(imp, NULL);
#endif
}

int ptlrpc_replay(struct obd_import *imp)
{
        int rc = 0;
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        unsigned long flags;
        ENTRY;

        /* It might have committed some after we last spoke, so make sure we
         * get rid of them now.
         */
        spin_lock_irqsave(&imp->imp_lock, flags);
        ptlrpc_free_committed(imp);
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        CDEBUG(D_HA, "import %p from %s has committed "LPD64"\n",
               imp, imp->imp_target_uuid.uuid, imp->imp_peer_committed_transno);

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
        /* Well... what if lctl recover is called twice at the same time?
         */
        spin_lock_irqsave(&imp->imp_lock, flags);
        LASSERT(imp->imp_state == LUSTRE_IMP_RECOVER);
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
                        wake_up(&req->rq_reply_waitq);
                }
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);
}

inline void ptlrpc_invalidate_import_state(struct obd_import *imp)
{
        struct obd_device *obd = imp->imp_obd;
        struct ldlm_namespace *ns = obd->obd_namespace;

        ptlrpc_abort_inflight(imp);

#if 0
        obd_invalidate_import(obd, imp);
#endif

        ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);
}

void ptlrpc_handle_failed_import(struct obd_import *imp)
{
        ENTRY;
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

void ptlrpc_request_handle_notconn(struct ptlrpc_request *failed_req)
{
        int rc;
        struct obd_import *imp= failed_req->rq_import;
        unsigned long flags;
        ENTRY;

        CDEBUG(D_HA, "import %s of %s@%s abruptly disconnected: reconnecting\n",
               imp->imp_obd->obd_name,
               imp->imp_target_uuid.uuid,
               imp->imp_connection->c_remote_uuid.uuid);

        rc = ptlrpc_recover_import_no_retry(imp, NULL);

        if (failed_req->rq_import_generation != imp->imp_generation) {
                spin_lock_irqsave (&failed_req->rq_lock, flags);
                failed_req->rq_err = 1;
                spin_unlock_irqrestore (&failed_req->rq_lock, flags);
        }
        else {
                ptlrpc_resend_req(failed_req);
                if (rc && rc != -EALREADY)
                        ptlrpc_handle_failed_import(imp);
                        
        }
        EXIT;
}

int ptlrpc_set_import_active(struct obd_import *imp, int active)
{
        struct obd_device *obd = imp->imp_obd;
        unsigned long flags;

        LASSERT(obd);

        /* When deactivating, mark import invalid, and abort in-flight
         * requests. */
        if (!active) {
                spin_lock_irqsave(&imp->imp_lock, flags);
                /* This is a bit of a hack, but invalidating replayable
                 * imports makes a temporary reconnect failure into a much more
                 * ugly -- and hard to remedy -- situation. */
                if (!imp->imp_replayable) {
                        CDEBUG(D_HA, "setting import %s INVALID\n",
                               imp->imp_target_uuid.uuid);
                        imp->imp_invalid = 1;
                }
                imp->imp_generation++;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                ptlrpc_invalidate_import_state(imp);
        }

        /* When activating, mark import valid */
        if (active) {
                CDEBUG(D_HA, "setting import %s VALID\n",
                       imp->imp_target_uuid.uuid);
                spin_lock_irqsave(&imp->imp_lock, flags);
                imp->imp_invalid = 0;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
        }

        if (obd->obd_observer)
                RETURN(obd_notify(obd->obd_observer, obd, active));

        RETURN(0);
}

void ptlrpc_fail_import(struct obd_import *imp, int generation)
{
        unsigned long flags;
        int in_recovery = 0;
        ENTRY;

        LASSERT (!imp->imp_dlm_fake);

        spin_lock_irqsave(&imp->imp_lock, flags);
        if (imp->imp_state != LUSTRE_IMP_FULL) {
                in_recovery = 1;
        } else {
                CDEBUG(D_HA, "%s: new state: DISCON\n", 
                       imp->imp_client->cli_name);
                imp->imp_state = LUSTRE_IMP_DISCON;
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        if (in_recovery) {
                EXIT;
                return;
        }

        ptlrpc_handle_failed_import(imp);
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
        req->rq_send_state = LUSTRE_IMP_REPLAY;
        req->rq_reqmsg->flags |= MSG_LAST_REPLAY;
        req->rq_timeout *= 3; 

        rc = ptlrpc_queue_wait(req);

        ptlrpc_req_finished(req);
        RETURN(rc);
}

int ptlrpc_recover_import(struct obd_import *imp, char *new_uuid)
{
        int rc;
        ENTRY;
        
        rc = ptlrpc_recover_import_no_retry(imp, new_uuid);

        if (rc && rc != -EALREADY) {
                unsigned long flags;
                CDEBUG(D_HA, "recovery of %s on %s failed (%d); restarting\n",
                       imp->imp_target_uuid.uuid,
                       new_uuid ? new_uuid :
                       (char *)imp->imp_connection->c_remote_uuid.uuid, rc);
                spin_lock_irqsave(&imp->imp_lock, flags);
                imp->imp_state = LUSTRE_IMP_FULL;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                ptlrpc_fail_import(imp, imp->imp_generation);
        }
        RETURN(rc);
}

static int ptlrpc_recover_import_no_retry(struct obd_import *imp,
                                          char *new_uuid)
{
        int rc;
        unsigned long flags;
        int in_recovery = 0;
        int was_invalid = 0;
        ENTRY;

        spin_lock_irqsave(&imp->imp_lock, flags);
        if (imp->imp_state == LUSTRE_IMP_FULL) {
                CDEBUG(D_HA, "%s: new state: DISCON\n", 
                       imp->imp_client->cli_name);
                imp->imp_state = LUSTRE_IMP_DISCON;
        } 
        
        if (imp->imp_state != LUSTRE_IMP_DISCON) {
                in_recovery = 1;
        } else if (imp->imp_invalid) {
                imp->imp_invalid = 0;
                was_invalid = 1;
        }

        spin_unlock_irqrestore(&imp->imp_lock, flags);

        if (in_recovery == 1)
                RETURN(-EALREADY);

        down(&imp->imp_recovery_sem);
        /* If recovery happened while we waited, we're done. */
        if (imp->imp_state == LUSTRE_IMP_FULL)
                GOTO(out, rc = 0);

        LASSERT (imp->imp_state == LUSTRE_IMP_DISCON);

        if (new_uuid) {
                struct ptlrpc_connection *conn;
                struct obd_uuid uuid;
                struct ptlrpc_peer peer;
                struct obd_export *dlmexp;

                obd_str2uuid(&uuid, new_uuid);
                if (ptlrpc_uuid_to_peer(&uuid, &peer)) {
                        CERROR("no connection found for UUID %s\n", new_uuid);
                        GOTO(out, rc = -EINVAL);
                }

                conn = ptlrpc_get_connection(&peer, &uuid);
                if (!conn)
                        GOTO(out, rc = -ENOMEM);

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

 connect:
        rc = ptlrpc_connect_import(imp);

        if (rc < 0) {
                CERROR("failed to reconnect to %s@%s: %d\n",
                       imp->imp_target_uuid.uuid,
                       imp->imp_connection->c_remote_uuid.uuid, rc);
                GOTO(out, rc);
        } 

        if (imp->imp_state == LUSTRE_IMP_EVICTED) {
                CDEBUG(D_HA, "evicted from %s@%s; invalidating\n",
                       imp->imp_target_uuid.uuid,
                       imp->imp_connection->c_remote_uuid.uuid);
                ptlrpc_set_import_active(imp, 0);
                CDEBUG(D_HA, "%s: new state: RECOVER\n", 
                       imp->imp_client->cli_name);
                imp->imp_state = LUSTRE_IMP_RECOVER;
        } 
        
        if (imp->imp_state == LUSTRE_IMP_REPLAY) {
                CDEBUG(D_HA, "replay requested by %s\n",
                       imp->imp_target_uuid.uuid);
                rc = ptlrpc_replay(imp);
                if (rc)
                        GOTO(out, rc);

                rc = ldlm_replay_locks(imp);
                if (rc)
                        GOTO(out, rc);

                rc = signal_completed_replay(imp);
                if (rc)
                        GOTO(out, rc);
                CDEBUG(D_HA, "%s: new state: RECOVER\n", 
                       imp->imp_client->cli_name);
                imp->imp_state = LUSTRE_IMP_RECOVER;
        } 

        if (imp->imp_state == LUSTRE_IMP_RECOVER) {
                CDEBUG(D_HA, "reconnected to %s@%s\n",
                       imp->imp_target_uuid.uuid,
                       imp->imp_connection->c_remote_uuid.uuid);

                ptlrpc_set_import_active(imp, 1);
                ptlrpc_resend(imp);
                spin_lock_irqsave(&imp->imp_lock, flags);
                CDEBUG(D_HA, "%s: new state: FULL\n", 
                       imp->imp_client->cli_name);
                imp->imp_state = LUSTRE_IMP_FULL;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                ptlrpc_wake_delayed(imp);
        } 


        LASSERT(imp->imp_state == LUSTRE_IMP_FULL);

 out:
        if (rc != 0) {
                spin_lock_irqsave(&imp->imp_lock, flags);
                imp->imp_state = LUSTRE_IMP_DISCON;
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                
                if (rc == -ENOTCONN) {
                        CDEBUG(D_HA, "evicted/aborted by %s@%s during recovery;"
                               "invalidating and reconnecting\n",
                               imp->imp_target_uuid.uuid,
                               imp->imp_connection->c_remote_uuid.uuid);
                        GOTO(connect, -ENOTCONN);
                } else if (was_invalid) {
                        ptlrpc_set_import_active(imp, 0);
                }
        }
        up(&imp->imp_recovery_sem);
        RETURN(rc);
}

void ptlrpc_fail_export(struct obd_export *exp)
{
        int rc, already_failed;
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

        /* Most callers into obd_disconnect are removing their own reference
         * (request, for example) in addition to the one from the hash table.
         * We don't have such a reference here, so make one. */
        class_export_get(exp);
        rc = obd_disconnect(exp, 0);
        if (rc)
                CERROR("disconnecting export %p failed: %d\n", exp, rc);
}
