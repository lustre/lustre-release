/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  obd/rpc/recovd.c
 *
 *  Lustre High Availability Daemon
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  by Peter Braam <braam@clusterfs.com>
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_RPC

#include <linux/kmod.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>

struct recovd_obd *ptlrpc_connmgr;

void connmgr_cli_manage(struct recovd_obd *recovd, struct ptlrpc_client *cli)
{
        ENTRY;
        cli->cli_recovd = recovd;
        spin_lock(&recovd->recovd_lock);
        list_add(&cli->cli_ha_item, &recovd->recovd_connections_lh);
        spin_unlock(&recovd->recovd_lock);
        EXIT;
}

void connmgr_cli_fail(struct ptlrpc_client *cli)
{
        ENTRY;
        spin_lock(&cli->cli_recovd->recovd_lock);
        cli->cli_recovd->recovd_flags |= SVC_HA_EVENT;
        list_del(&cli->cli_ha_item);
        list_add(&cli->cli_ha_item, &cli->cli_recovd->recovd_troubled_lh);
        spin_unlock(&cli->cli_recovd->recovd_lock);
        wake_up(&cli->cli_recovd->recovd_waitq);
        EXIT;
}

static int connmgr_upcall(void)
{
        char *argv[2];
        char *envp[3];

        argv[0] = "/usr/src/obd/utils/ha_assist.sh";
        argv[1] = NULL;

        envp [0] = "HOME=/";
        envp [1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp [2] = NULL;

        return call_usermodehelper(argv[0], argv, envp);
}

static void connmgr_unpack_body(struct ptlrpc_request *req)
{
        struct connmgr_body *b = lustre_msg_buf(req->rq_repmsg, 0);
        if (b == NULL)
                LBUG();

        b->generation = NTOH__u32(b->generation);
}

int connmgr_connect(struct recovd_obd *recovd, struct ptlrpc_connection *conn)
{
        struct ptlrpc_request *req;
        struct ptlrpc_client *cl;
        struct connmgr_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!recovd) {
                CERROR("no manager\n");
                LBUG();
        }
        cl = recovd->recovd_client;

        req = ptlrpc_prep_req(cl, conn, CONNMGR_CONNECT, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        body->generation = HTON__u32(conn->c_generation);
        body->conn = (__u64)(unsigned long)conn;
        body->conn_token = conn->c_token;

        req->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        if (!rc) {
                connmgr_unpack_body(req);
                body = lustre_msg_buf(req->rq_repmsg, 0);
                CDEBUG(D_NET, "remote generation: %o\n", body->generation);
                conn->c_level = LUSTRE_CONN_CON;
                conn->c_remote_conn = body->conn;
                conn->c_remote_token = body->conn_token;
        }

        ptlrpc_free_req(req);
        EXIT;
 out:
        return rc;
}

static int connmgr_handle_connect(struct ptlrpc_request *req)
{
        struct connmgr_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("connmgr: out of memory\n");
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        connmgr_unpack_body(req);

        req->rq_connection->c_remote_conn = body->conn;
        req->rq_connection->c_remote_token = body->conn_token;

        CERROR("incoming generation %d\n", body->generation);
        body = lustre_msg_buf(req->rq_repmsg, 0);
        body->generation = 4711;
        body->conn = (__u64)(unsigned long)req->rq_connection;
        body->conn_token = req->rq_connection->c_token;

        req->rq_connection->c_level = LUSTRE_CONN_CON;
        RETURN(0);
}

int connmgr_handle(struct obd_device *dev, struct ptlrpc_service *svc,
                   struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc) {
                CERROR("Invalid request\n");
                GOTO(out, rc);
        }

        if (req->rq_reqmsg->type != NTOH__u32(PTL_RPC_MSG_REQUEST)) {
                CERROR("wrong packet type sent %d\n",
                       req->rq_reqmsg->type);
                GOTO(out, rc = -EINVAL);
        }

        switch (req->rq_reqmsg->opc) {
        case CONNMGR_CONNECT:
                CDEBUG(D_INODE, "connmgr connect\n");
                rc = connmgr_handle_connect(req);
                break;

        default:
                rc = ptlrpc_error(svc, req);
                RETURN(rc);
        }

        EXIT;
out:
        if (rc) {
                ptlrpc_error(svc, req);
        } else {
                CDEBUG(D_NET, "sending reply\n");
                ptlrpc_reply(svc, req);
        }

        return 0;
}

static int recovd_check_event(struct recovd_obd *recovd)
{
        int rc = 0;
        ENTRY;

        spin_lock(&recovd->recovd_lock);

        if (!(recovd->recovd_flags & MGR_WORKING) &&
            !list_empty(&recovd->recovd_troubled_lh)) {

                CERROR("connection in trouble - state: WORKING, upcall\n");
                recovd->recovd_flags = MGR_WORKING;

                recovd->recovd_waketime = CURRENT_TIME;
                recovd->recovd_timeout = 5 * HZ;
                schedule_timeout(recovd->recovd_timeout);
        }

        if (recovd->recovd_flags & MGR_WORKING &&
            CURRENT_TIME <= recovd->recovd_waketime + recovd->recovd_timeout) {
                CERROR("WORKING: new event\n");

                recovd->recovd_waketime = CURRENT_TIME;
                schedule_timeout(recovd->recovd_timeout);
        }

        if (recovd->recovd_flags & MGR_STOPPING) {
                CERROR("ha mgr stopping\n");
                rc = 1;
        }

        spin_unlock(&recovd->recovd_lock);
        RETURN(rc);
}

static int recovd_handle_event(struct recovd_obd *recovd)
{
        spin_lock(&recovd->recovd_lock);

        if (!(recovd->recovd_flags & MGR_WORKING) &&
            !list_empty(&recovd->recovd_troubled_lh)) {

                CERROR("connection in trouble - state: WORKING, upcall\n");
                recovd->recovd_flags = MGR_WORKING;


                connmgr_upcall();
                recovd->recovd_waketime = CURRENT_TIME;
                recovd->recovd_timeout = 5 * HZ;
                schedule_timeout(recovd->recovd_timeout);
        }

        if (recovd->recovd_flags & MGR_WORKING &&
            CURRENT_TIME <= recovd->recovd_waketime + recovd->recovd_timeout) {
                CERROR("WORKING: new event\n");

                recovd->recovd_waketime = CURRENT_TIME;
                schedule_timeout(recovd->recovd_timeout);
        }

        spin_unlock(&recovd->recovd_lock);
        return 0;
}

static int recovd_main(void *arg)
{
        struct recovd_obd *recovd = (struct recovd_obd *)arg;

        ENTRY;

        lock_kernel();
        daemonize();
        spin_lock_irq(&current->sigmask_lock);
        sigfillset(&current->blocked);
        recalc_sigpending(current);
        spin_unlock_irq(&current->sigmask_lock);

        sprintf(current->comm, "lustre_recovd");

        /* Record that the  thread is running */
        recovd->recovd_thread = current;
        recovd->recovd_flags = MGR_RUNNING;
        wake_up(&recovd->recovd_ctl_waitq);

        /* And now, loop forever on requests */
        while (1) {
                wait_event_interruptible(recovd->recovd_waitq,
                                         recovd_check_event(recovd));

                spin_lock(&recovd->recovd_lock);
                if (recovd->recovd_flags & MGR_STOPPING) {
                        spin_unlock(&recovd->recovd_lock);
                        CERROR("lustre_hamgr quitting\n");
                        EXIT;
                        break;
                }

                recovd_handle_event(recovd);
                spin_unlock(&recovd->recovd_lock);
        }

        recovd->recovd_thread = NULL;
        recovd->recovd_flags = MGR_STOPPED;
        wake_up(&recovd->recovd_ctl_waitq);
        CDEBUG(D_NET, "mgr exiting process %d\n", current->pid);
        RETURN(0);
}

int recovd_setup(struct recovd_obd *recovd)
{
        int rc;
        ENTRY;

        INIT_LIST_HEAD(&recovd->recovd_connections_lh);
        INIT_LIST_HEAD(&recovd->recovd_troubled_lh);
        spin_lock_init(&recovd->recovd_lock);

        init_waitqueue_head(&recovd->recovd_waitq);
        init_waitqueue_head(&recovd->recovd_recovery_waitq);
        init_waitqueue_head(&recovd->recovd_ctl_waitq);

        rc = kernel_thread(recovd_main, (void *)recovd,
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread\n");
                RETURN(-EINVAL);
        }
        wait_event(recovd->recovd_ctl_waitq, recovd->recovd_flags & MGR_RUNNING);

        RETURN(0);
}

int recovd_cleanup(struct recovd_obd *recovd)
{
        recovd->recovd_flags = MGR_STOPPING;

        wake_up(&recovd->recovd_waitq);
        wait_event_interruptible(recovd->recovd_ctl_waitq,
                                 (recovd->recovd_flags & MGR_STOPPED));
        RETURN(0);
}
