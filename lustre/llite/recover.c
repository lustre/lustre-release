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

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>

static int ll_reconnect(struct ll_sb_info *sbi)
{
        struct ll_fid rootfid;
        __u64 last_committed, last_rcvd;
        __u32 last_xid;
        int err;
        struct ptlrpc_request *request; 

        ptlrpc_readdress_connection(sbi->ll_mds_conn, "mds");

        err = connmgr_connect(ptlrpc_connmgr, sbi->ll_mds_conn);
        if (err) {
                CERROR("cannot connect to MDS: rc = %d\n", err);
                ptlrpc_put_connection(sbi->ll_mds_conn);
                GOTO(out_disc, err = -ENOTCONN);
        }
        sbi->ll_mds_conn->c_level = LUSTRE_CONN_CON;

        /* XXX: need to store the last_* values somewhere */
        err = mdc_connect(&sbi->ll_mds_client, sbi->ll_mds_conn,
                          &rootfid, &last_committed, 
                          &last_rcvd,
                          &last_xid,
                          &request);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_disc, err = -ENOTCONN);
        }
        sbi->ll_mds_client.cli_last_rcvd = last_xid;
        sbi->ll_mds_conn->c_level = LUSTRE_CONN_RECOVD;

 out_disc:
        return err;
}


int ll_recover(struct ptlrpc_client *cli)
{
        struct ptlrpc_request *req;
        struct list_head *tmp, *pos;
        struct ll_sb_info *sbi = cli->cli_data;
        int rc = 0;
        ENTRY;

        /* 1. reconnect */
        ll_reconnect(sbi);
        
        /* 2. walk the request list */
        spin_lock(&cli->cli_lock);
        list_for_each_safe(tmp, pos, &cli->cli_sending_head) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                
                /* replay what needs to be replayed */
                if (req->rq_flags & PTL_RPC_FL_REPLAY) {
                        CDEBUG(D_INODE, "req %Ld needs replay [last rcvd %Ld]\n", 
                               req->rq_xid, cli->cli_last_rcvd);
                        rc = ptlrpc_replay_req(req); 
                        if (rc) { 
                                CERROR("recovery replay error %d for request %Ld\n", 
                                       rc, req->rq_xid); 
                                GOTO(out, rc);
                        }
                }

                /* server has seen req, we have reply: skip */
                if ((req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                    req->rq_xid <= cli->cli_last_rcvd) { 
                        CDEBUG(D_INODE, "req %Ld was complete: skip [last rcvd %Ld]\n", 
                               req->rq_xid, cli->cli_last_rcvd);
                        continue;
                }

                /* server has lost req, we have reply: resend, ign reply */
                if ((req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                    req->rq_xid > cli->cli_last_rcvd) { 
                        CDEBUG(D_INODE, "lost req %Ld have rep: replay [last rcvd %Ld]\n", 
                               req->rq_xid, cli->cli_last_rcvd);
                        rc = ptlrpc_replay_req(req); 
                        if (rc) {
                                CERROR("request resend error %d for request %Ld\n", 
                                       rc, req->rq_xid); 
                                GOTO(out, rc);
                        }
                }

                /* server has seen req, we have lost reply: -ERESTARTSYS */
                if ( !(req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                     req->rq_xid <= cli->cli_last_rcvd) { 
                        CDEBUG(D_INODE, "lost rep %Ld srv did req: restart [last rcvd %Ld]\n", 
                               req->rq_xid, cli->cli_last_rcvd);
                        ptlrpc_restart_req(req);
                }

                /* service has not seen req, no reply: resend */
                if ( !(req->rq_flags & PTL_RPC_FL_REPLIED)  &&
                     req->rq_xid > cli->cli_last_rcvd) {
                        CDEBUG(D_INODE, "lost rep/req %Ld: resend [last rcvd %Ld]\n", 
                               req->rq_xid, cli->cli_last_rcvd);
                        ptlrpc_resend_req(req);
                }

        }

        sbi->ll_mds_conn->c_level = LUSTRE_CONN_FULL;
        recovd_cli_fixed(cli);

        /* Finally, continue what we delayed since recovery started */
        list_for_each_safe(tmp, pos, &cli->cli_delayed_head) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                ptlrpc_continue_req(req);
        }

        EXIT;
 out:
        spin_unlock(&cli->cli_lock);
        return rc;
}
