/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
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

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>

int ll_reconnect(struct ptlrpc_connection *conn) 
{
        struct ptlrpc_request *request; 
        struct list_head *tmp;
        int rc = -EINVAL;

        /* XXX c_lock semantics! */
        conn->c_level = LUSTRE_CONN_CON;

        /* XXX this code MUST be shared with class_obd_connect! */
        list_for_each(tmp, &conn->c_imports) {
                struct obd_import *imp = list_entry(tmp, struct obd_import,
                                                    imp_chain);
                struct obd_device *obd = imp->imp_obd;
                struct client_obd *cli = &obd->u.cli;
                int rq_opc = (obd->obd_type->typ_ops->o_brw)
                        ? OST_CONNECT : MDS_CONNECT;
                int size[] = { sizeof(cli->cl_target_uuid),
                               sizeof(obd->obd_uuid) };
                char *tmp[] = {cli->cl_target_uuid, obd->obd_uuid };
                struct lustre_handle old_hdl;

                LASSERT(imp->imp_connection == conn);
                request = ptlrpc_prep_req(imp, rq_opc, 2, size, tmp);
                request->rq_level = LUSTRE_CONN_NEW;
                request->rq_replen = lustre_msg_size(0, NULL);
                /* XXX are (addr, cookie) right? */
                request->rq_reqmsg->addr = imp->imp_handle.addr;
                request->rq_reqmsg->cookie = imp->imp_handle.cookie;
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
                CDEBUG(D_HA, "reconnected to %s@%s (%Lx/%Lx, was %Lx/%Lx)!\n",
                       cli->cl_target_uuid, conn->c_remote_uuid,
                       imp->imp_handle.addr, imp->imp_handle.cookie,
                       old_hdl.addr, old_hdl.cookie);
                ptlrpc_free_req(request);
        }
        conn->c_level = LUSTRE_CONN_RECOVD;

 out_disc:
        return rc;
}

static int ll_recover_upcall(struct ptlrpc_connection *conn)
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
                /*
                 * Tragically, this will never be run, because call_umh doesn't
                 * report errors like -ENOENT to its caller.
                 */
                CERROR("Error invoking recovery upcall (%s): %d\n",
                       obd_recovery_upcall, rc);
                CERROR("Check /proc/sys/lustre/recovery_upcall?\n");
        } else {
                CDEBUG(D_HA, "Invoked upcall %s for connection %s\n",
                       argv[0], argv[1]);
        }
        RETURN(rc);
}

static int ll_recover_reconnect(struct ptlrpc_connection *conn)
{
        int rc = 0;
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        ENTRY;

        /* 1. reconnect */
        rc = ll_reconnect(conn);
        if (rc)
                RETURN(rc);
        
        /* 2. walk the request list */
        spin_lock(&conn->c_lock);

        CDEBUG(D_HA, "connection %p to %s has last_xid "LPD64"\n",
               conn, conn->c_remote_uuid, conn->c_last_xid);

        list_for_each_safe(tmp, pos, &conn->c_sending_head) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                
                /* replay what needs to be replayed */
                if (req->rq_flags & PTL_RPC_FL_REPLAY) {
                        CDEBUG(D_HA, "FL_REPLAY: xid "LPD64" op %d @ %d\n",
                               req->rq_xid, req->rq_reqmsg->opc,
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
                        CDEBUG(D_HA, "REPLIED SKIP: xid "LPD64" op %d @ %d\n",
                               req->rq_xid, req->rq_reqmsg->opc,
                               req->rq_import->imp_client->cli_request_portal);
                        continue;
                }

                /* server has lost req, we have reply: resend, ign reply */
                if ((req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                    req->rq_xid > conn->c_last_xid) { 
                        CDEBUG(D_HA, "REPLIED RESEND: xid "LPD64" op %d @ %d\n",
                               req->rq_xid, req->rq_reqmsg->opc,
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
                        CDEBUG(D_HA, "RESEND: xid "LPD64" op %d @ %d\n",
                               req->rq_xid, req->rq_reqmsg->opc,
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

static int ll_retry_recovery(struct ptlrpc_connection *conn)
{
        CDEBUG(D_HA, "Recovery has failed on conn %p\n", conn);
#if 0
        /* XXX use a timer, sideshow bob */
        recovd_conn_fail(conn);
        /* XXX this is disabled until I fix it so that we don't just keep
         * XXX retrying in the case of a missing upcall.
         */
#endif
        return 0;
}

int ll_recover(struct recovd_data *rd, int phase)
{
        struct ptlrpc_connection *conn = class_rd2conn(rd);

        LASSERT(conn);
        ENTRY;

        switch (phase) {
            case PTLRPC_RECOVD_PHASE_PREPARE:
                RETURN(ll_recover_upcall(conn));
            case PTLRPC_RECOVD_PHASE_RECOVER:
                RETURN(ll_recover_reconnect(conn));
            case PTLRPC_RECOVD_PHASE_FAILURE:
                RETURN(ll_retry_recovery(conn));
        }

        LBUG();
        RETURN(-ENOSYS);
}
