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

#if 0
/* FIXME: reference to mdc_getstatus causes dependency problems */
static int ll_reconnect(struct ll_sb_info *sbi)
{
        struct ll_fid rootfid;
        __u64 last_committed;
        __u64 last_xid;
        int err;
        struct ptlrpc_request *request; 
        struct ptlrpc_connection *conn = sbi2mdc(sbi)->cl_import.imp_connection;

        ptlrpc_readdress_connection(conn, "mds");

        conn->c_level = LUSTRE_CONN_CON;

        /* XXX: need to store the last_* values somewhere */
        err = mdc_getstatus(&sbi->ll_mdc_conn, &rootfid, &last_committed,
                            &last_xid, &request);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_disc, err = -ENOTCONN);
        }
        conn->c_last_xid = last_xid;
        conn->c_level = LUSTRE_CONN_RECOVD;

 out_disc:
        return err;
}
#endif

static int ll_recover_upcall(struct ptlrpc_connection *conn)
{
        char *argv[3];
        char *envp[3];

        ENTRY;
        conn->c_level = LUSTRE_CONN_RECOVD;

        argv[0] = obd_recovery_upcall;
        argv[1] = conn->c_remote_uuid;
        argv[2] = NULL;

        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp[2] = NULL;

        RETURN(call_usermodehelper(argv[0], argv, envp));
}

static int ll_recover_reconnect(struct ptlrpc_connection *conn)
{
        RETURN(-ENOSYS);
#if 0
        /* XXXshaver this code needs to know about connection-driven recovery! */

        struct ptlrpc_request *req;
        struct list_head *tmp, *pos;
        struct ll_sb_info *sbi = cli->cli_data;
        struct ptlrpc_connection *conn = cli->cli_connection;
        int rc = 0;
        ENTRY;

        /* 1. reconnect */
        ll_reconnect(sbi);
        
        /* 2. walk the request list */
        spin_lock(&conn->c_lock);
        list_for_each_safe(tmp, pos, &conn->c_sending_head) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                
                /* replay what needs to be replayed */
                if (req->rq_flags & PTL_RPC_FL_REPLAY) {
                        CDEBUG(D_INODE, "req %Ld needs replay [last rcvd %Ld]\n",
                               req->rq_xid, conn->c_last_xid);
#error We should not hold a spinlock over such a lengthy operation.
#error If necessary, drop spinlock, do operation, re-get spinlock, restart loop.
#error If we need to avoid re-processint items, then delete them from the list
#error as they are replayed and re-add at the tail of this list, so the next
#error item to process will always be at the head of the list.
                        rc = ptlrpc_replay_req(req);
                        if (rc) {
                                CERROR("recovery replay error %d for req %Ld\n",
                                       rc, req->rq_xid);
                                GOTO(out, rc);
                        }
                }

                /* server has seen req, we have reply: skip */
                if ((req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                    req->rq_xid <= conn->c_last_xid) { 
                        CDEBUG(D_INODE,
                               "req %Ld was complete: skip [last rcvd %Ld]\n", 
                               req->rq_xid, conn->c_last_xid);
                        continue;
                }

                /* server has lost req, we have reply: resend, ign reply */
                if ((req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                    req->rq_xid > conn->c_last_xid) { 
                        CDEBUG(D_INODE, "lost req %Ld have rep: replay [last "
                               "rcvd %Ld]\n", req->rq_xid, conn->c_last_xid);
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
                        CDEBUG(D_INODE, "lost rep %Ld srv did req: restart "
                               "[last rcvd %Ld]\n", 
                               req->rq_xid, conn->c_last_xid);
                        ptlrpc_restart_req(req);
                }

                /* service has not seen req, no reply: resend */
                if ( !(req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                     req->rq_xid > conn->c_last_xid) {
                        CDEBUG(D_INODE,
                               "lost rep/req %Ld: resend [last rcvd %Ld]\n", 
                               req->rq_xid, conn->c_last_xid);
                        ptlrpc_resend_req(req);
                }

        }

        sbi2mdc(sbi)->cl_conn->c_level = LUSTRE_CONN_FULL;
        recovd_conn_fixed(conn);

        /* Finally, continue what we delayed since recovery started */
        list_for_each_safe(tmp, pos, &conn->c_delayed_head) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                ptlrpc_continue_req(req);
        }

        EXIT;
 out:
        spin_unlock(&conn->c_lock);
        return rc;
#endif
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
                fixme();
                RETURN(0);
        }

        LBUG();
        RETURN(-ENOSYS);
}
