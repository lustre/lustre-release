/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Portal-RPC reconnection and replay operations, for use in recovery.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copryright (C) 1996 Peter J. Braam <braam@stelias.com>
 * Copryright (C) 1999 Stelias Computing Inc. <braam@stelias.com>
 * Copryright (C) 1999 Seagate Technology Inc.
 * Copryright (C) 2001 Mountain View Data, Inc.
 * Copryright (C) 2002 Cluster File Systems, Inc.
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
        rc = ptlrpc_check_status(request, rc);
        if (rc) {
                CERROR("cannot connect to %s@%s: rc = %d\n",
                       cli->cl_target_uuid, conn->c_remote_uuid, rc);
                ptlrpc_free_req(request);
                GOTO(out_disc, rc = -ENOTCONN);
        }
        
        old_hdl = imp->imp_handle;
        imp->imp_handle.addr = request->rq_repmsg->addr;
        imp->imp_handle.cookie = request->rq_repmsg->cookie;
        CERROR("reconnected to %s@%s (%Lx/%Lx, was %Lx/%Lx)!\n",
               cli->cl_target_uuid, conn->c_remote_uuid,
               imp->imp_handle.addr, imp->imp_handle.cookie,
               old_hdl.addr, old_hdl.cookie);
        ptlrpc_req_finished(request);

 out_disc:
        return rc;
}

int ptlrpc_run_recovery_upcall(struct ptlrpc_connection *conn)
{
        char *argv[3];
        char *envp[3];
        int rc;

        ENTRY;
        conn->c_level = LUSTRE_CONN_RECOVD;

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

#define REPLAY_COMMITTED     0 /* Fully processed (commit + reply). */
#define REPLAY_REPLAY        1 /* Forced-replay (e.g. open). */
#define REPLAY_RESEND        2 /* Resend required. */
#define REPLAY_RESEND_IGNORE 3 /* Resend, ignore the reply (already saw it). */
#define REPLAY_RESTART       4 /* Have to restart the call, sorry! */

static int replay_state(struct ptlrpc_request *req, __u64 committed)
{
        /* This request must always be replayed. */
        if (req->rq_flags & PTL_RPC_FL_REPLAY)
                return REPLAY_REPLAY;

        /* Uncommitted request */
        if (req->rq_transno > committed) {
                if (req->rq_flags & PTL_RPC_FL_REPLIED) {
                        /* Saw reply, so resend and ignore new reply. */
                        return REPLAY_RESEND_IGNORE;
                }

                /* Didn't see reply either, so resend. */
                return REPLAY_RESEND;
        }

        /* This request has been committed and we saw the reply.  Goodbye! */
        if (req->rq_flags & PTL_RPC_FL_REPLIED)
                return REPLAY_COMMITTED;

        /* Request committed, but we didn't see the reply: have to restart. */
        return REPLAY_RESTART;
}

static char *replay_state2str(int state) {
        static char *state_strings[] = {
                "COMMITTED", "REPLAY", "RESEND", "RESEND_IGNORE", "RESTART",
        };
        static char *unknown_state = "UNKNOWN";

        if (state < 0 || 
            state > (sizeof(state_strings) / sizeof(state_strings[0]))) {
                return unknown_state;
        }

        return state_strings[state];
}

int ptlrpc_replay(struct obd_import *imp)
{
        int rc = 0, state;
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        struct ptlrpc_connection *conn = imp->imp_connection;
        __u64 committed = imp->imp_peer_committed_transno;
        ENTRY;

        spin_lock(&imp->imp_lock);

        CDEBUG(D_HA, "import %p from %s has committed "LPD64"\n",
               imp, imp->imp_obd->u.cli.cl_target_uuid, committed);

        list_for_each(tmp, &imp->imp_request_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                state = replay_state(req, committed);
                DEBUG_REQ(D_HA, req, "SENDING: %s: ", replay_state2str(state));
        }

        list_for_each(tmp, &conn->c_delayed_head) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                state = replay_state(req, committed);
                DEBUG_REQ(D_HA, req, "DELAYED: %s: ", replay_state2str(state));
        }

        list_for_each_safe(tmp, pos, &imp->imp_request_list) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                state = replay_state(req, committed);

                if (req->rq_transno == imp->imp_max_transno) {
                        req->rq_reqmsg->flags |= MSG_LAST_REPLAY;
                        DEBUG_REQ(D_HA, req, "last for replay");
                        LASSERT(state != REPLAY_COMMITTED);
                }
                
                switch (state) {
                    case REPLAY_REPLAY:
                        DEBUG_REQ(D_HA, req, "REPLAY:");
                        rc = ptlrpc_replay_req(req);
#if 0
#error We should not hold a spinlock over such a lengthy operation.
#error If necessary, drop spinlock, do operation, re-get spinlock, restart loop.
#error If we need to avoid re-processint items, then delete them from the list
#error as they are replayed and re-add at the tail of this list, so the next
#error item to process will always be at the head of the list.
#endif
                        if (rc) {
                                CERROR("recovery replay error %d for req %Ld\n",
                                       rc, req->rq_xid);
                                GOTO(out, rc);
                        }
                        break;

                    case REPLAY_COMMITTED:
                        DEBUG_REQ(D_ERROR, req, "COMMITTED:");
                        /* XXX commit now? */
                        break;

                    case REPLAY_RESEND_IGNORE:
                        DEBUG_REQ(D_HA, req, "RESEND_IGNORE:");
                        rc = ptlrpc_replay_req(req); 
                        if (rc) {
                                CERROR("request resend error %d for req %Ld\n",
                                       rc, req->rq_xid); 
                                GOTO(out, rc);
                        }
                        break;

                    case REPLAY_RESTART:
                        DEBUG_REQ(D_HA, req, "RESTART:");
                        ptlrpc_restart_req(req);
                        break;

                    case REPLAY_RESEND:
                        DEBUG_REQ(D_HA, req, "RESEND:");
                        ptlrpc_resend_req(req);
                        break;

                    default:
                        LBUG();
                }

        }

        conn->c_level = LUSTRE_CONN_FULL;
        recovd_conn_fixed(conn);

        CERROR("recovery complete on conn %p(%s), waking delayed reqs\n",
               conn, conn->c_remote_uuid);
        /* Finally, continue processing requests that blocked for recovery. */
        list_for_each_safe(tmp, pos, &conn->c_delayed_head) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_HA, req, "WAKING: ");
                ptlrpc_continue_req(req);
        }

        EXIT;
 out:
        spin_unlock(&conn->c_lock);
        return rc;
}
