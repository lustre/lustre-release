/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Portal-RPC reconnection and replay operations, for use in recovery.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copyright (C) 1996 Peter J. Braam <braam@stelias.com>
 * Copyright (C) 1999 Stelias Computing Inc. <braam@stelias.com>
 * Copyright (C) 1999 Seagate Technology Inc.
 * Copyright (C) 2001 Mountain View Data, Inc.
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kmod.h>

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/lustre_ha.h>
#include <linux/lustre_net.h>
#include <linux/obd.h>

int ptlrpc_reconnect_import(struct obd_import *imp, int rq_opc)
{
        struct obd_device *obd = imp->imp_obd;
        struct client_obd *cli = &obd->u.cli;
        int size[] = { sizeof(cli->cl_target_uuid), sizeof(obd->obd_uuid) };
        char *tmp[] = {cli->cl_target_uuid, obd->obd_uuid };
        struct ptlrpc_connection *conn = imp->imp_connection;
        struct lustre_handle old_hdl;
        struct ptlrpc_request *request; 
        struct obd_export *ldlmexp;
        int rc;

        request = ptlrpc_prep_req(imp, rq_opc, 2, size, tmp);
        request->rq_level = LUSTRE_CONN_NEW;
        request->rq_replen = lustre_msg_size(0, NULL);
        /*
         * This address is the export that represents our client-side LDLM
         * service (for ASTs).  We should only have one on this list, so we
         * just grab the first one.
         *
         * XXX tear down export, call class_obd_connect?
         */
        ldlmexp = list_entry(obd->obd_exports.next, struct obd_export,
                             exp_obd_chain);
        request->rq_reqmsg->addr = (__u64)(unsigned long)ldlmexp;
        request->rq_reqmsg->cookie = ldlmexp->exp_cookie;
        rc = ptlrpc_queue_wait(request);
        switch (rc) {
            case EALREADY:
            case -EALREADY:
                /* already connected! */
                memset(&old_hdl, 0, sizeof(old_hdl));
                if (!memcmp(&old_hdl.addr, &request->rq_repmsg->addr,
                            sizeof (old_hdl.addr)) &&
                    !memcmp(&old_hdl.cookie, &request->rq_repmsg->cookie,
                            sizeof (old_hdl.cookie))) {
                        CERROR("%s@%s didn't like our handle %Lx/%Lx, failed\n",
                               cli->cl_target_uuid, conn->c_remote_uuid,
                               (__u64)(unsigned long)ldlmexp,
                               ldlmexp->exp_cookie);
                        GOTO(out_disc, rc = -ENOTCONN);
                }

                old_hdl.addr = request->rq_repmsg->addr;
                old_hdl.cookie = request->rq_repmsg->cookie;
                if (memcmp(&imp->imp_handle, &old_hdl, sizeof(old_hdl))) {
                        CERROR("%s@%s changed handle from %Lx/%Lx to %Lx/%Lx; "
                               "copying, but this may foreshadow disaster\n",
                               cli->cl_target_uuid, conn->c_remote_uuid,
                               old_hdl.addr, old_hdl.cookie,
                               imp->imp_handle.addr, imp->imp_handle.cookie);
                        imp->imp_handle.addr = request->rq_repmsg->addr;
                        imp->imp_handle.cookie = request->rq_repmsg->cookie;
                        GOTO(out_disc, rc = EALREADY);
                }
                
                CERROR("reconnected to %s@%s after partition\n",
                       cli->cl_target_uuid, conn->c_remote_uuid);
                GOTO(out_disc, rc = EALREADY);
            case 0:
                old_hdl = imp->imp_handle;
                imp->imp_handle.addr = request->rq_repmsg->addr;
                imp->imp_handle.cookie = request->rq_repmsg->cookie;
                CERROR("now connected to %s@%s (%Lx/%Lx, was %Lx/%Lx)!\n",
                       cli->cl_target_uuid, conn->c_remote_uuid,
                       imp->imp_handle.addr, imp->imp_handle.cookie,
                       old_hdl.addr, old_hdl.cookie);
                GOTO(out_disc, rc = 0);
            default:
                CERROR("cannot connect to %s@%s: rc = %d\n",
                       cli->cl_target_uuid, conn->c_remote_uuid, rc);
                GOTO(out_disc, rc = -ENOTCONN); /* XXX preserve rc? */
        }

 out_disc:
        ptlrpc_req_finished(request);
        return rc;
}

int ptlrpc_run_recovery_upcall(struct ptlrpc_connection *conn)
{
        char *argv[3];
        char *envp[3];
        int rc;

        ENTRY;
        argv[0] = obd_recovery_upcall;
        argv[1] = conn->c_remote_uuid;
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

int ptlrpc_replay(struct obd_import *imp, int send_last_flag)
{
        int rc = 0;
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        __u64 committed = imp->imp_peer_committed_transno;
        ENTRY;

        /* It might have committed some after we last spoke, so make sure we
         * get rid of them now.
         */
        ptlrpc_free_committed(imp);

        spin_lock(&imp->imp_lock);

        CDEBUG(D_HA, "import %p from %s has committed "LPD64"\n",
               imp, imp->imp_obd->u.cli.cl_target_uuid, committed);

        list_for_each(tmp, &imp->imp_replay_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_HA, req, "RETAINED: ");
        }

        list_for_each_safe(tmp, pos, &imp->imp_replay_list) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                if (req->rq_transno == imp->imp_max_transno &&
                    send_last_flag) {
                        req->rq_reqmsg->flags |= MSG_LAST_REPLAY;
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY:");
                } else {
                        DEBUG_REQ(D_HA, req, "REPLAY:");
                }

                rc = ptlrpc_replay_req(req);
                req->rq_reqmsg->flags &= ~MSG_LAST_REPLAY;

                if (rc) {
                        CERROR("recovery replay error %d for req %Ld\n",
                               rc, req->rq_xid);
                        GOTO(out, rc);
                }
        }

 out:
        spin_unlock(&imp->imp_lock);
        return rc;
}

#define NO_RESEND     0 /* No action required. */
#define RESEND        1 /* Resend required. */
#define RESEND_IGNORE 2 /* Resend, ignore the reply (already saw it). */
#define RESTART       3 /* Have to restart the call, sorry! */

static int resend_type(struct ptlrpc_request *req, __u64 committed)
{
        if (req->rq_transno < committed) {
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
        __u64 committed = imp->imp_peer_committed_transno;

        ENTRY;

        spin_lock(&imp->imp_lock);
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
        RETURN(rc);
}

void ptlrpc_wake_delayed(struct obd_import *imp)
{
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;

        spin_lock(&imp->imp_lock);
        list_for_each_safe(tmp, pos, &imp->imp_delayed_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_HA, req, "waking:");
                wake_up(&req->rq_wait_for_rep);
        }
        spin_unlock(&imp->imp_lock);
}
