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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kmod.h>

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/lustre_ha.h>
#include <linux/lustre_net.h>
#include <linux/obd.h>

int ptlrpc_reconnect_import(struct obd_import *imp, int rq_opc,
                            struct ptlrpc_request **reqptr)
{
        struct obd_device *obd = imp->imp_obd;
        struct client_obd *cli = &obd->u.cli;
        int size[] = { sizeof(cli->cl_target_uuid), sizeof(obd->obd_uuid) };
        char *tmp[] = {cli->cl_target_uuid.uuid, obd->obd_uuid.uuid};
        struct ptlrpc_connection *conn = imp->imp_connection;
        struct ptlrpc_request *req;
        struct obd_export *ldlmexp;
        struct lustre_handle old_hdl;
        int rc;

        req = ptlrpc_prep_req(imp, rq_opc, 2, size, tmp);
        if (!req)
                RETURN(-ENOMEM);
        req->rq_level = LUSTRE_CONN_NEW;
        req->rq_replen = lustre_msg_size(0, NULL);
        /*
         * This address is the export that represents our client-side LDLM
         * service (for ASTs).  We should only have one on this list, so we
         * just grab the first one.
         *
         * XXX tear down export, call class_obd_connect?
         */
        ldlmexp = list_entry(obd->obd_exports.next, struct obd_export,
                             exp_obd_chain);
        req->rq_reqmsg->addr = (__u64)(unsigned long)ldlmexp;
        req->rq_reqmsg->cookie = ldlmexp->exp_cookie;
        rc = ptlrpc_queue_wait(req);
        if (rc) {
                CERROR("cannot connect to %s@%s: rc = %d\n",
                       cli->cl_target_uuid.uuid, conn->c_remote_uuid.uuid, rc);
                GOTO(out_disc, rc);
        }
        if (lustre_msg_get_op_flags(req->rq_repmsg) & MSG_CONNECT_RECONNECT) {
                memset(&old_hdl, 0, sizeof(old_hdl));
                if (!memcmp(&old_hdl.addr, &req->rq_repmsg->addr,
                            sizeof (old_hdl.addr)) &&
                    !memcmp(&old_hdl.cookie, &req->rq_repmsg->cookie,
                            sizeof (old_hdl.cookie))) {
                        CERROR("%s@%s didn't like our handle "LPX64"/"LPX64
                               ", failed\n", cli->cl_target_uuid.uuid,
                               conn->c_remote_uuid.uuid,
                               (__u64)(unsigned long)ldlmexp,
                               ldlmexp->exp_cookie);
                        GOTO(out_disc, rc = -ENOTCONN);
                }

                old_hdl.addr = req->rq_repmsg->addr;
                old_hdl.cookie = req->rq_repmsg->cookie;
                if (memcmp(&imp->imp_handle, &old_hdl, sizeof(old_hdl))) {
                        CERROR("%s@%s changed handle from "LPX64"/"LPX64
                               " to "LPX64"/"LPX64"; "
                               "copying, but this may foreshadow disaster\n",
                               cli->cl_target_uuid.uuid, 
                               conn->c_remote_uuid.uuid,
                               old_hdl.addr, old_hdl.cookie,
                               imp->imp_handle.addr, imp->imp_handle.cookie);
                        imp->imp_handle.addr = req->rq_repmsg->addr;
                        imp->imp_handle.cookie = req->rq_repmsg->cookie;
                        GOTO(out_disc, rc = 0);
                }

                CERROR("reconnected to %s@%s after partition\n",
                       cli->cl_target_uuid.uuid, conn->c_remote_uuid.uuid);
                GOTO(out_disc, rc = 0);
        }

        old_hdl = imp->imp_handle;
        imp->imp_handle.addr = req->rq_repmsg->addr;
        imp->imp_handle.cookie = req->rq_repmsg->cookie;
        CERROR("reconnected to %s@%s ("LPX64"/"LPX64", was "LPX64"/"
               LPX64")!\n", cli->cl_target_uuid.uuid, conn->c_remote_uuid.uuid,
               imp->imp_handle.addr, imp->imp_handle.cookie,
               old_hdl.addr, old_hdl.cookie);
        GOTO(out_disc, rc = 0);

 out_disc:
        *reqptr = req;
        return rc;
}

int ptlrpc_run_recovery_upcall(struct ptlrpc_connection *conn)
{
        char *argv[3];
        char *envp[3];
        int rc;

        ENTRY;
        argv[0] = obd_recovery_upcall;
        argv[1] = conn->c_remote_uuid.uuid;
        argv[2] = NULL;

        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp[2] = NULL;

        rc = call_usermodehelper(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("Error invoking recovery upcall %s for %s: %d\n",
                       argv[0], argv[1], rc);
                CERROR("Check /proc/sys/lustre/recovery_upcall?\n");
        } else {
                CERROR("Invoked upcall %s for connection %s\n",
                       argv[0], argv[1]);
        }

        /*
         * We don't want to make this a "failed" recovery, because the system
         * administrator -- or, perhaps, tester -- may well be able to rescue
         * things by running the correct upcall.
         */
        RETURN(0);
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

        CDEBUG(D_HA, "import %p from %s has committed "LPD64"\n",
               imp, imp->imp_obd->u.cli.cl_target_uuid.uuid, committed);

        list_for_each(tmp, &imp->imp_replay_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_HA, req, "RETAINED: ");
        }

        list_for_each_safe(tmp, pos, &imp->imp_replay_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                DEBUG_REQ(D_HA, req, "REPLAY:");

                /* XXX locking WRT failure during replay? */
                rc = ptlrpc_replay_req(req);

                if (rc) {
                        CERROR("recovery replay error %d for req "LPD64"\n",
                               rc, req->rq_xid);
                        GOTO(out, rc);
                }
        }

 out:
        spin_unlock_irqrestore(&imp->imp_lock, flags);
        return rc;
}

#define NO_RESEND     0 /* No action required. */
#define RESEND        1 /* Resend required. */
#define RESEND_IGNORE 2 /* Resend, ignore the reply (already saw it). */
#define RESTART       3 /* Have to restart the call, sorry! */

static int resend_type(struct ptlrpc_request *req, __u64 committed)
{
        if (req->rq_transno && req->rq_transno < committed) {
                if (req->rq_flags & PTL_RPC_FL_REPLIED) {
                        /* Saw the reply and it was committed, no biggie. */
                        DEBUG_REQ(D_HA, req, "NO_RESEND");
                        return NO_RESEND;
                }
                /* Request committed, but no reply: have to restart. */
                return RESTART;
        }

        if (req->rq_flags & PTL_RPC_FL_REPLIED) {
                /* Saw reply, so resend and ignore new reply. */
                return RESEND_IGNORE;
        }

        /* Didn't see reply either, so resend. */
        return RESEND;

}

int ptlrpc_resend(struct obd_import *imp)
{
        int rc = 0;
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        unsigned long flags;
        __u64 committed = imp->imp_peer_committed_transno;

        ENTRY;

        spin_lock_irqsave(&imp->imp_lock, flags);
        list_for_each(tmp, &imp->imp_sending_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_HA, req, "SENDING: ");
        }

        list_for_each_safe(tmp, pos, &imp->imp_sending_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                switch(resend_type(req, committed)) {
                    case NO_RESEND:
                        break;

                    case RESTART:
                        DEBUG_REQ(D_HA, req, "RESTART:");
                        ptlrpc_restart_req(req);
                        break;

                    case RESEND_IGNORE:
                        DEBUG_REQ(D_HA, req, "RESEND_IGNORE:");
                        rc = ptlrpc_replay_req(req);
                        if (rc) {
                                DEBUG_REQ(D_ERROR, req, "error %d resending:",
                                          rc);
                                ptlrpc_restart_req(req); /* might as well */
                        }
                        break;

                    case RESEND:
                        DEBUG_REQ(D_HA, req, "RESEND:");
                        ptlrpc_resend_req(req);
                        break;

                    default:
                        LBUG();
                }
        }

        spin_unlock_irqrestore(&imp->imp_lock, flags);
        RETURN(rc);
}

void ptlrpc_wake_delayed(struct obd_import *imp)
{
        unsigned long flags;
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;

        spin_lock_irqsave(&imp->imp_lock, flags);
        list_for_each_safe(tmp, pos, &imp->imp_delayed_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_HA, req, "waking:");
                wake_up(&req->rq_wait_for_rep);
        }
        spin_unlock_irqrestore(&imp->imp_lock, flags);
}
