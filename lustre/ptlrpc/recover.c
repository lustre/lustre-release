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

int ptlrpc_replay(struct ptlrpc_connection *conn)
{
        int rc = 0;
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        ENTRY;

        spin_lock(&conn->c_lock);

        CDEBUG(D_HA, "connection %p to %s has last_xid "LPD64"\n",
               conn, conn->c_remote_uuid, conn->c_last_xid);

        list_for_each_safe(tmp, pos, &conn->c_sending_head) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                
                /* replay what needs to be replayed */
                if (req->rq_flags & PTL_RPC_FL_REPLAY) {
                        CDEBUG(D_HA, "FL_REPLAY: xid "LPD64" transno "LPD64" op %d @ %d\n",
                               req->rq_xid, req->rq_repmsg->transno, req->rq_reqmsg->opc,
                               req->rq_import->imp_client->cli_request_portal);
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
                }

                /* server has seen req, we have reply: skip */
                if ((req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                    req->rq_xid <= conn->c_last_xid) { 
                        CDEBUG(D_HA, "REPLIED SKIP: xid "LPD64" transno "
                               LPD64" op %d @ %d\n",
                               req->rq_xid, req->rq_repmsg->transno, 
                               req->rq_reqmsg->opc,
                               req->rq_import->imp_client->cli_request_portal);
                        continue;
                }

                /* server has lost req, we have reply: resend, ign reply */
                if ((req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                    req->rq_xid > conn->c_last_xid) { 
                        CDEBUG(D_HA, "REPLIED RESEND: xid "LPD64" transno "
                               LPD64" op %d @ %d\n",
                               req->rq_xid, req->rq_repmsg->transno,
                               req->rq_reqmsg->opc,
                               req->rq_import->imp_client->cli_request_portal);
                        rc = ptlrpc_replay_req(req); 
                        if (rc) {
                                CERROR("request resend error %d for req %Ld\n",
                                       rc, req->rq_xid); 
                                GOTO(out, rc);
                        }
                }

                /* server has seen req, we have lost reply: -ERESTARTSYS */
                if ( !(req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                     req->rq_xid <= conn->c_last_xid) { 
                        CDEBUG(D_HA, "RESTARTSYS: xid "LPD64" op %d @ %d\n",
                               req->rq_xid, req->rq_reqmsg->opc,
                               req->rq_import->imp_client->cli_request_portal);
                        ptlrpc_restart_req(req);
                }

                /* service has not seen req, no reply: resend */
                if ( !(req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                     req->rq_xid > conn->c_last_xid) {
                        CDEBUG(D_HA, "RESEND: xid "LPD64" transno "LPD64
                               " op %d @ %d\n", req->rq_xid,
                               req->rq_repmsg ? req->rq_repmsg->transno : 0,
                               req->rq_reqmsg->opc,
                               req->rq_import->imp_client->cli_request_portal);
                        ptlrpc_resend_req(req);
                }

        }

        conn->c_level = LUSTRE_CONN_FULL;
        recovd_conn_fixed(conn);

        CERROR("recovery complete on conn %p(%s), waking delayed reqs\n",
               conn, conn->c_remote_uuid);
        /* Finally, continue what we delayed since recovery started */
        list_for_each_safe(tmp, pos, &conn->c_delayed_head) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                ptlrpc_continue_req(req);
        }

        EXIT;
 out:
        spin_unlock(&conn->c_lock);
        return rc;
}
