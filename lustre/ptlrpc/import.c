/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
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
#include <linux/obd_class.h>

#include "ptlrpc_internal.h"

struct ptlrpc_connect_async_args {
         __u64 pcaa_peer_committed;
        int pcaa_initial_connect;
        int pcaa_was_invalid;
};

/* A CLOSED import should remain so. */
#define IMPORT_SET_STATE_NOLOCK(imp, state)                                    \
do {                                                                           \
        if (imp->imp_state != LUSTRE_IMP_CLOSED) {                             \
               CDEBUG(D_HA, "%p %s: changing import state from %s to %s\n",    \
                      imp, imp->imp_target_uuid.uuid,                          \
                      ptlrpc_import_state_name(imp->imp_state),                \
                      ptlrpc_import_state_name(state));                        \
               imp->imp_state = state;                                         \
        }                                                                      \
} while(0)

#define IMPORT_SET_STATE(imp, state)                    \
do {                                                    \
        unsigned long flags;                            \
                                                        \
        spin_lock_irqsave(&imp->imp_lock, flags);       \
        IMPORT_SET_STATE_NOLOCK(imp, state);            \
        spin_unlock_irqrestore(&imp->imp_lock, flags);  \
} while(0)


static int ptlrpc_connect_interpret(struct ptlrpc_request *request,
                                    void * data, int rc);
int ptlrpc_import_recovery_state_machine(struct obd_import *imp);

/* Only this function is allowed to change the import state when it is
 * CLOSED. I would rather refcount the import and free it after
 * disconnection like we do with exports. To do that, the client_obd
 * will need to save the peer info somewhere other than in the import,
 * though. */
int ptlrpc_init_import(struct obd_import *imp)
{
        unsigned long flags;
        
        spin_lock_irqsave(&imp->imp_lock, flags);

        imp->imp_generation++;
        imp->imp_state =  LUSTRE_IMP_NEW;

        spin_unlock_irqrestore(&imp->imp_lock, flags);

        return 0;
}

/* Returns true if import was FULL, false if import was already not
 * connected.
 */
int ptlrpc_set_import_discon(struct obd_import *imp)
{
        unsigned long flags;
        int rc = 0;
        
        spin_lock_irqsave(&imp->imp_lock, flags);

        if (imp->imp_state == LUSTRE_IMP_FULL) {
                IMPORT_SET_STATE_NOLOCK(imp, LUSTRE_IMP_DISCON);
                rc = 1;
        } else {
                CDEBUG(D_HA, "%p %s: import already not connected: %s\n",
                       imp,imp->imp_client->cli_name, 
                       ptlrpc_import_state_name(imp->imp_state));
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        return rc;
}

void ptlrpc_fail_import(struct obd_import *imp, int generation)
{
        ENTRY;

        LASSERT (!imp->imp_dlm_fake);

        if (ptlrpc_set_import_discon(imp))
                ptlrpc_handle_failed_import(imp);

        EXIT;
}

int ptlrpc_connect_import(struct obd_import *imp, char * new_uuid)
{
        struct obd_device *obd = imp->imp_obd;
        int initial_connect = 0;
        int rc;
        __u64 committed_before_reconnect = 0;
        int was_invalid = 0;
        struct ptlrpc_request *request;
        int size[] = {sizeof(imp->imp_target_uuid),
                                 sizeof(obd->obd_uuid),
                                 sizeof(imp->imp_dlm_handle)};
        char *tmp[] = {imp->imp_target_uuid.uuid,
                       obd->obd_uuid.uuid,
                       (char *)&imp->imp_dlm_handle};
        struct ptlrpc_connect_async_args *aa;
        unsigned long flags;

        spin_lock_irqsave(&imp->imp_lock, flags);
        if (imp->imp_state == LUSTRE_IMP_CLOSED) {
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                CERROR("can't connect to a closed import\n");
                RETURN(-EINVAL);
        } else if (imp->imp_state == LUSTRE_IMP_FULL) {
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                CERROR("already connected\n");
                RETURN(0);
        } else if (imp->imp_state == LUSTRE_IMP_CONNECTING) {
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                CERROR("already connecting\n");
                RETURN(-EALREADY);
        }

        IMPORT_SET_STATE_NOLOCK(imp, LUSTRE_IMP_CONNECTING);

        imp->imp_conn_cnt++; 
        imp->imp_last_replay_transno = 0;

        if (imp->imp_remote_handle.cookie == 0) {
                initial_connect = 1;
        } else {
                committed_before_reconnect = imp->imp_peer_committed_transno;;

        }

        if (imp->imp_invalid) {
                imp->imp_invalid = 0;
                was_invalid = 1;
        }

        spin_unlock_irqrestore(&imp->imp_lock, flags);

        if (new_uuid) {
                struct ptlrpc_connection *conn;
                struct obd_uuid uuid;
                struct obd_export *dlmexp;

                obd_str2uuid(&uuid, new_uuid);

                conn = ptlrpc_uuid_to_connection(&uuid);
                if (!conn)
                        GOTO(out, rc = -ENOENT);

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
                
                LASSERT(dlmexp != NULL);

                if (dlmexp->exp_connection)
                        ptlrpc_put_connection(dlmexp->exp_connection);
                dlmexp->exp_connection = ptlrpc_connection_addref(conn);
                class_export_put(dlmexp);

        }

        request = ptlrpc_prep_req(imp, imp->imp_connect_op, 3, size, tmp);
        if (!request)
                GOTO(out, rc = -ENOMEM);

#ifndef __KERNEL__
        lustre_msg_add_op_flags(request->rq_reqmsg, MSG_CONNECT_LIBCLIENT);
#endif

        request->rq_send_state = LUSTRE_IMP_CONNECTING;
        request->rq_replen = lustre_msg_size(0, NULL);
        request->rq_interpret_reply = ptlrpc_connect_interpret;

        LASSERT (sizeof (*aa) <= sizeof (request->rq_async_args));
        aa = (struct ptlrpc_connect_async_args *)&request->rq_async_args;
        memset(aa, 0, sizeof *aa);

        aa->pcaa_peer_committed = committed_before_reconnect;
        aa->pcaa_initial_connect = initial_connect;
        aa->pcaa_was_invalid = was_invalid;

        if (aa->pcaa_initial_connect)
                imp->imp_replayable = 1;

        ptlrpcd_add_req(request);
        rc = 0;
out:
        if (rc != 0) {
                IMPORT_SET_STATE(imp, LUSTRE_IMP_DISCON);
        }

        RETURN(rc);
}

static int ptlrpc_connect_interpret(struct ptlrpc_request *request,
                                    void * data, int rc)
{
        struct ptlrpc_connect_async_args *aa = data;
        struct obd_import *imp = request->rq_import;
        struct lustre_handle old_hdl;
        unsigned long flags;
        int msg_flags;
        ENTRY;
        
        spin_lock_irqsave(&imp->imp_lock, flags);
        if (imp->imp_state == LUSTRE_IMP_CLOSED) {
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                RETURN(0);
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        if (rc)
                GOTO(out, rc);

        msg_flags = lustre_msg_get_op_flags(request->rq_repmsg);

        if (aa->pcaa_initial_connect) {
                if (msg_flags & MSG_CONNECT_REPLAYABLE) {
                        CDEBUG(D_HA, "connected to replayable target: %s\n",
                               imp->imp_target_uuid.uuid);
                        imp->imp_replayable = 1;
                } else {
                        imp->imp_replayable = 0;
                }
                imp->imp_remote_handle = request->rq_repmsg->handle;
                IMPORT_SET_STATE(imp, LUSTRE_IMP_FULL);
                ptlrpc_pinger_add_import(imp);
                GOTO(finish, rc = 0);
        }

        /* Determine what recovery state to move the import to. */
        if (MSG_CONNECT_RECONNECT & msg_flags) {
                memset(&old_hdl, 0, sizeof(old_hdl));
                if (!memcmp(&old_hdl, &request->rq_repmsg->handle,
                            sizeof (old_hdl))) {
                        CERROR("%s@%s didn't like our handle "LPX64
                               ", failed\n", imp->imp_target_uuid.uuid,
                               imp->imp_connection->c_remote_uuid.uuid,
                               imp->imp_dlm_handle.cookie);
                        GOTO(out, rc = -ENOTCONN);
                }

                if (memcmp(&imp->imp_remote_handle, &request->rq_repmsg->handle,
                           sizeof(imp->imp_remote_handle))) {
                        CERROR("%s@%s changed handle from "LPX64" to "LPX64
                               "; copying, but this may foreshadow disaster\n",
                               imp->imp_target_uuid.uuid,
                               imp->imp_connection->c_remote_uuid.uuid,
                               imp->imp_remote_handle.cookie,
                               request->rq_repmsg->handle.cookie);
                        imp->imp_remote_handle = request->rq_repmsg->handle;
                } else {
                        CERROR("reconnected to %s@%s after partition\n",
                               imp->imp_target_uuid.uuid, 
                               imp->imp_connection->c_remote_uuid.uuid);
                }
                IMPORT_SET_STATE(imp, LUSTRE_IMP_RECOVER);
        } 
        else if (MSG_CONNECT_RECOVERING & msg_flags) {
                LASSERT(imp->imp_replayable);
                imp->imp_state = LUSTRE_IMP_RECOVER;
                imp->imp_remote_handle = request->rq_repmsg->handle;
                IMPORT_SET_STATE(imp, LUSTRE_IMP_REPLAY);
        } 
        else {
                imp->imp_remote_handle = request->rq_repmsg->handle;
                IMPORT_SET_STATE(imp, LUSTRE_IMP_EVICTED);
        }
        
        /* Sanity checks for a reconnected import. */
        if (!(imp->imp_replayable) != 
             !(msg_flags & MSG_CONNECT_REPLAYABLE)) {
                CERROR("imp_replayable flag does not match server "
                       "after reconnect. We should LBUG right here.\n");
        }

        if (request->rq_repmsg->last_committed < aa->pcaa_peer_committed) {
                CERROR("%s went back in time (transno "LPD64
                       " was previously committed, server now claims "LPD64
                       ")! is shared storage not coherent?\n",
                       imp->imp_target_uuid.uuid,
                       aa->pcaa_peer_committed,
                       request->rq_repmsg->last_committed);
        }

finish:
        rc = ptlrpc_import_recovery_state_machine(imp);
        if (rc != 0) {
                if (aa->pcaa_was_invalid) {
                        ptlrpc_set_import_active(imp, 0);
                }                

                if (rc == -ENOTCONN) {
                        CDEBUG(D_HA, "evicted/aborted by %s@%s during recovery;"
                               "invalidating and reconnecting\n",
                               imp->imp_target_uuid.uuid,
                               imp->imp_connection->c_remote_uuid.uuid);
                        ptlrpc_connect_import(imp, NULL);
                        RETURN(0);
                } 
        }
 out:
        if (rc != 0) {
                IMPORT_SET_STATE(imp, LUSTRE_IMP_DISCON);
                if (aa->pcaa_initial_connect && !imp->imp_initial_recov) {
                        ptlrpc_set_import_active(imp, 0);
                        GOTO(norecov, rc);
                }
                CDEBUG(D_ERROR, 
                       "recovery of %s on %s failed (%d); restarting\n",
                       imp->imp_target_uuid.uuid,
                       (char *)imp->imp_connection->c_remote_uuid.uuid, rc);
                ptlrpc_handle_failed_import(imp);
        }

norecov:
        wake_up(&imp->imp_recovery_waitq);
        RETURN(rc);
}

static int completed_replay_interpret(struct ptlrpc_request *req,
                                    void * data, int rc)
{
        atomic_dec(&req->rq_import->imp_replay_inflight);
        ptlrpc_import_recovery_state_machine(req->rq_import);
        RETURN(0);
}

static int signal_completed_replay(struct obd_import *imp)
 {
        struct ptlrpc_request *req;
        ENTRY;

        LASSERT(atomic_read(&imp->imp_replay_inflight) == 0);
        atomic_inc(&imp->imp_replay_inflight);

        req = ptlrpc_prep_req(imp, OBD_PING, 0, NULL, NULL);
        if (!req)
                RETURN(-ENOMEM);

        req->rq_replen = lustre_msg_size(0, NULL);
        req->rq_send_state = LUSTRE_IMP_REPLAY_WAIT;
        req->rq_reqmsg->flags |= MSG_LAST_REPLAY;
        req->rq_timeout *= 3; 
        req->rq_interpret_reply = completed_replay_interpret;

        ptlrpcd_add_req(req);
        RETURN(0);
}


int ptlrpc_import_recovery_state_machine(struct obd_import *imp)
{
        int rc = 0;
        int inflight;

        if (imp->imp_state == LUSTRE_IMP_EVICTED) {
                CDEBUG(D_HA, "evicted from %s@%s; invalidating\n",
                       imp->imp_target_uuid.uuid,
                       imp->imp_connection->c_remote_uuid.uuid);
                ptlrpc_set_import_active(imp, 0);
                IMPORT_SET_STATE(imp, LUSTRE_IMP_RECOVER);
        } 
        
        if (imp->imp_state == LUSTRE_IMP_REPLAY) {
                CDEBUG(D_HA, "replay requested by %s\n",
                       imp->imp_target_uuid.uuid);
                rc = ptlrpc_replay_next(imp, &inflight);
                if (inflight == 0 && 
                    atomic_read(&imp->imp_replay_inflight) == 0) {
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_REPLAY_LOCKS);
                        rc = ldlm_replay_locks(imp);
                        if (rc)
                                GOTO(out, rc);
                }
                rc = 0;
        }

        if (imp->imp_state == LUSTRE_IMP_REPLAY_LOCKS) {
                if (atomic_read(&imp->imp_replay_inflight) == 0) {
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_REPLAY_WAIT);
                        rc = signal_completed_replay(imp);
                        if (rc)
                                GOTO(out, rc);
                }

        }

        if (imp->imp_state == LUSTRE_IMP_REPLAY_WAIT) {
                if (atomic_read(&imp->imp_replay_inflight) == 0) {
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_RECOVER);
                }
        }

        if (imp->imp_state == LUSTRE_IMP_RECOVER) {
                CDEBUG(D_HA, "reconnected to %s@%s\n",
                       imp->imp_target_uuid.uuid,
                       imp->imp_connection->c_remote_uuid.uuid);

                ptlrpc_set_import_active(imp, 1);
                rc = ptlrpc_resend(imp);
                if (rc)
                        GOTO(out, rc);
                IMPORT_SET_STATE(imp, LUSTRE_IMP_FULL);
        } 

        if (imp->imp_state == LUSTRE_IMP_FULL) {
                wake_up(&imp->imp_recovery_waitq);
                ptlrpc_wake_delayed(imp);
        }

 out:
        RETURN(rc);
}

static int back_to_sleep(void *unused) 
{
	return 0;
}

int ptlrpc_disconnect_import(struct obd_import *imp)
{
        struct ptlrpc_request *request;
        int rq_opc;
        int rc = 0;
        unsigned long flags;
        ENTRY;

        switch (imp->imp_connect_op) {
        case OST_CONNECT: rq_opc = OST_DISCONNECT; break;
        case MDS_CONNECT: rq_opc = MDS_DISCONNECT; break;
        case MGMT_CONNECT:rq_opc = MGMT_DISCONNECT;break;
        default:
                CERROR("don't know how to disconnect from %s (connect_op %d)\n",
                       imp->imp_target_uuid.uuid, imp->imp_connect_op);
                RETURN(-EINVAL);
        }


        if (ptlrpc_import_in_recovery(imp)) {
                struct l_wait_info lwi;
                lwi = LWI_TIMEOUT_INTR(MAX(obd_timeout * HZ, 1), back_to_sleep, 
                                       NULL, NULL);
                rc = l_wait_event(imp->imp_recovery_waitq, 
                                  !ptlrpc_import_in_recovery(imp), &lwi);

        }

        spin_lock_irqsave(&imp->imp_lock, flags);
        if (imp->imp_state != LUSTRE_IMP_FULL) {
                GOTO(out, 0);
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        request = ptlrpc_prep_req(imp, rq_opc, 0, NULL, NULL);
        if (request) {
                /* For non-replayable connections, don't attempt
                   reconnect if this fails */
                if (!imp->imp_replayable) {
                        request->rq_no_resend = 1;
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_CONNECTING);
                        request->rq_send_state =  LUSTRE_IMP_CONNECTING;
                }
                request->rq_replen = lustre_msg_size(0, NULL);
                rc = ptlrpc_queue_wait(request);
                ptlrpc_req_finished(request);
        }

        spin_lock_irqsave(&imp->imp_lock, flags);
out:
        IMPORT_SET_STATE_NOLOCK(imp, LUSTRE_IMP_CLOSED);
        memset(&imp->imp_remote_handle, 0, sizeof(imp->imp_remote_handle));
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        RETURN(rc);
}

