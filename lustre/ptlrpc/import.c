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

/* should this take an imp_sem to ensure connect is single threaded? */
int ptlrpc_connect_import(struct obd_import *imp)
{
        struct obd_device *obd = imp->imp_obd;
        int msg_flags;
        int initial_connect = 0;
        int rc;
        __u64 committed_before_reconnect = 0;
        struct ptlrpc_request *request;
        struct lustre_handle old_hdl;
        int size[] = {sizeof(imp->imp_target_uuid),
                                 sizeof(obd->obd_uuid),
                                 sizeof(imp->imp_dlm_handle)};
        char *tmp[] = {imp->imp_target_uuid.uuid,
                       obd->obd_uuid.uuid,
                       (char *)&imp->imp_dlm_handle};
        unsigned long flags;

        spin_lock_irqsave(&imp->imp_lock, flags);
        if (imp->imp_state == LUSTRE_IMP_CONNECTING) {
                spin_unlock_irqrestore(&imp->imp_lock, flags);
                RETURN(-EALREADY);
        } else {
                LASSERT(imp->imp_state == LUSTRE_IMP_DISCON);
        }
        CDEBUG(D_HA, "%s: new state: CONNECTING\n", 
               imp->imp_client->cli_name);
        imp->imp_state = LUSTRE_IMP_CONNECTING;
        imp->imp_conn_cnt++; 
        if (imp->imp_remote_handle.cookie == 0) {
                initial_connect = 1;
        } else {
                committed_before_reconnect = imp->imp_peer_committed_transno;
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);

        request = ptlrpc_prep_req(imp, imp->imp_connect_op, 3, size, tmp);
        if (!request)
                GOTO(out, rc = -ENOMEM);

        request->rq_send_state = LUSTRE_IMP_CONNECTING;
        request->rq_replen = lustre_msg_size(0, NULL);

        // lustre_msg_add_op_flags(request->rq_reqmsg, MSG_CONNECT_PEER);

        rc = ptlrpc_queue_wait(request);
        if (rc) {
                GOTO(free_req, rc);
        }

        msg_flags = lustre_msg_get_op_flags(request->rq_repmsg);

        if (initial_connect) {
                CDEBUG(D_HA, "%s: new state: FULL\n", 
                       imp->imp_client->cli_name);
                if (msg_flags & MSG_CONNECT_REPLAYABLE)
                        imp->imp_replayable = 1;
                imp->imp_remote_handle = request->rq_repmsg->handle;
                imp->imp_state = LUSTRE_IMP_FULL;
                GOTO(free_req, rc = 0);
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
                        GOTO(free_req, rc = -ENOTCONN);
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
                CDEBUG(D_HA, "%s: new state: RECOVER\n", 
                       imp->imp_client->cli_name);
                imp->imp_state = LUSTRE_IMP_RECOVER;
        } 
        else if (MSG_CONNECT_RECOVERING & msg_flags) {
                CDEBUG(D_HA, "%s: new state: REPLAY\n", 
                       imp->imp_client->cli_name);
                LASSERT(imp->imp_replayable);
                imp->imp_state = LUSTRE_IMP_RECOVER;
                imp->imp_remote_handle = request->rq_repmsg->handle;
                imp->imp_state = LUSTRE_IMP_REPLAY;
        } 
        else {
                CDEBUG(D_HA, "%s: new state: EVICTED\n", 
                       imp->imp_client->cli_name);
                imp->imp_remote_handle = request->rq_repmsg->handle;
                imp->imp_state = LUSTRE_IMP_EVICTED;
        }
        
        /* Sanity checks for a reconnected import. */
        if (!(imp->imp_replayable) != 
             !(msg_flags & MSG_CONNECT_REPLAYABLE)) {
                CERROR("imp_replayable flag does not match server "
                       "after reconnect. We should LBUG right here.\n");
        }

        if (request->rq_repmsg->last_committed < committed_before_reconnect) {
                CERROR("%s went back in time (transno "LPD64
                       " was previously committed, server now claims "LPD64
                       ")! is shared storage not coherent?\n",
                       imp->imp_target_uuid.uuid,
                       committed_before_reconnect,
                       request->rq_repmsg->last_committed);
        }

 free_req:
        ptlrpc_req_finished(request);

 out:
        if (rc != 0)
                imp->imp_state = LUSTRE_IMP_DISCON;
        RETURN(rc);
}



int ptlrpc_disconnect_import(struct obd_import *imp)
{
        struct ptlrpc_request *request;
        int rq_opc;
        int rc = 0;
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

        request = ptlrpc_prep_req(imp, rq_opc, 0, NULL, NULL);
        if (request) {
                /* For non-replayable connections, don't attempt
                   reconnect if this fails */
                if (!imp->imp_obd->obd_replayable) {
                        imp->imp_state = LUSTRE_IMP_DISCON;
                        request->rq_send_state =  LUSTRE_IMP_DISCON;
                }
                request->rq_replen = lustre_msg_size(0, NULL);
                rc = ptlrpc_queue_wait(request);
                ptlrpc_req_finished(request);
        }

        imp->imp_state = LUSTRE_IMP_DISCON;
        memset(&imp->imp_remote_handle, 0, sizeof(imp->imp_remote_handle));
        RETURN(rc);
}

