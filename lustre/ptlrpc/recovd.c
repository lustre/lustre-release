/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/handler.c
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/kmod.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>

struct connmgr_obd *ptlrpc_connmgr; 

void connmgr_cli_manage(struct connmgr_obd *mgr, struct ptlrpc_client *cli)
{
        ENTRY;
        cli->cli_ha_mgr = mgr;
        spin_lock(&mgr->mgr_lock);
        list_add(&cli->cli_ha_item, &mgr->mgr_connections_lh); 
        spin_unlock(&mgr->mgr_lock); 
        EXIT;
}


void connmgr_cli_fail(struct ptlrpc_client *cli)
{
        ENTRY;
        spin_lock(&cli->cli_ha_mgr->mgr_lock); 
        cli->cli_ha_mgr->mgr_flags |= SVC_HA_EVENT;
        list_del(&cli->cli_ha_item);
        list_add(&cli->cli_ha_item, &cli->cli_ha_mgr->mgr_troubled_lh); 
        spin_unlock(&cli->cli_ha_mgr->mgr_lock); 
        wake_up(&cli->cli_ha_mgr->mgr_waitq);
        EXIT;
}

int connmgr_upcall(void)
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

int connmgr_connect(struct connmgr_obd *mgr, 
                    struct ptlrpc_connection *conn)
{
        struct ptlrpc_request *req;
        struct ptlrpc_client *cl;
        struct connmgr_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!mgr) { 
                CERROR("no manager\n"); 
                LBUG();
        }
        cl = mgr->mgr_client;

        req = ptlrpc_prep_req(cl, conn, CONNMGR_CONNECT, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        body->generation = HTON__u32(conn->c_generation);

        req->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

        if (!rc) {
                connmgr_unpack_body(req);
                body = lustre_msg_buf(req->rq_repmsg, 0);
                CDEBUG(D_NET, "mode: %o\n", body->generation);
        }

        EXIT;
 out:
        return rc;
}


int connmgr_handle_connect(struct ptlrpc_request *req)
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

        printk("incoming generation %d\n", body->generation);
        body = lustre_msg_buf(req->rq_repmsg, 0);
        body->generation = 4711;
        RETURN(0);
}

int connmgr_handle(struct obd_device *dev,
                   struct ptlrpc_service *svc,
                   struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc) { 
                CERROR("lustre_mds: Invalid request\n");
                GOTO(out, rc);
        }

        if (req->rq_reqmsg->type != PTL_RPC_REQUEST) {
                CERROR("lustre_mds: wrong packet type sent %d\n",
                       req->rq_reqmsg->type);
                GOTO(out, rc = -EINVAL);
        }

        switch (req->rq_reqmsg->opc) {
        case CONNMGR_CONNECT:
                CDEBUG(D_INODE, "getattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETATTR_NET, 0);
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


static int recovd_check_event(struct connmgr_obd *mgr)
{
        int rc = 0; 
        ENTRY;

        spin_lock(&mgr->mgr_lock);

        if (!(mgr->mgr_flags & MGR_WORKING) && 
            !list_empty(&mgr->mgr_troubled_lh) ) {

                CERROR("connection in trouble - state: WORKING, upcall\n"); 
                mgr->mgr_flags = MGR_WORKING;

                mgr->mgr_waketime = CURRENT_TIME; 
                mgr->mgr_timeout = 5 * HZ;
                schedule_timeout(mgr->mgr_timeout); 

        }

        if (mgr->mgr_flags & MGR_WORKING &&
            CURRENT_TIME <= mgr->mgr_waketime + mgr->mgr_timeout ) { 
                CERROR("WORKING: new event\n");

                mgr->mgr_waketime = CURRENT_TIME; 
                schedule_timeout(mgr->mgr_timeout); 
        }

        if (mgr->mgr_flags & MGR_STOPPING) { 
                CERROR("ha mgr stopping\n");
                rc = 1;
        }

        spin_unlock(&mgr->mgr_lock); 
        RETURN(rc);
}

int recovd_handle_event(struct connmgr_obd *mgr)
{

        spin_lock(&mgr->mgr_lock);

        if (!(mgr->mgr_flags & MGR_WORKING) && 
            !list_empty(&mgr->mgr_troubled_lh) ) {

                CERROR("connection in trouble - state: WORKING, upcall\n"); 
                mgr->mgr_flags = MGR_WORKING;


                connmgr_upcall();
                mgr->mgr_waketime = CURRENT_TIME; 
                mgr->mgr_timeout = 5 * HZ;
                schedule_timeout(mgr->mgr_timeout); 

        }

        if (mgr->mgr_flags & MGR_WORKING &&
            CURRENT_TIME <= mgr->mgr_waketime + mgr->mgr_timeout ) { 
                CERROR("WORKING: new event\n");

                mgr->mgr_waketime = CURRENT_TIME; 
                schedule_timeout(mgr->mgr_timeout); 
        }

        spin_unlock(&mgr->mgr_lock);
        return 0;
}

static int recovd_main(void *arg)
{
        struct connmgr_thread *data = (struct connmgr_thread *)arg;
        struct connmgr_obd *mgr = data->mgr;

        ENTRY;

        lock_kernel();
        daemonize();
        spin_lock_irq(&current->sigmask_lock);
        sigfillset(&current->blocked);
        recalc_sigpending(current);
        spin_unlock_irq(&current->sigmask_lock);

        sprintf(current->comm, data->name);

        /* Record that the  thread is running */
        mgr->mgr_thread = current;
        mgr->mgr_flags = MGR_RUNNING;
        wake_up(&mgr->mgr_ctl_waitq);

        /* And now, loop forever on requests */
        while (1) {
                wait_event_interruptible(mgr->mgr_waitq, 
                                         recovd_check_event(mgr));

                spin_lock(&mgr->mgr_lock);
                if (mgr->mgr_flags & MGR_STOPPING) {
                        spin_unlock(&mgr->mgr_lock);
                        CERROR("lustre_hamgr quitting\n"); 
                        EXIT;
                        break;
                }

                recovd_handle_event(mgr); 
                spin_unlock(&mgr->mgr_lock);
        }

        mgr->mgr_thread = NULL;
        mgr->mgr_flags = MGR_STOPPED;
        wake_up(&mgr->mgr_ctl_waitq);
        CDEBUG(D_NET, "mgr exiting process %d\n", current->pid);
        RETURN(0);
}

int recovd_setup(struct connmgr_obd *mgr)
{
        struct connmgr_thread d;
        int rc;
        ENTRY;

        INIT_LIST_HEAD(&mgr->mgr_connections_lh);
        INIT_LIST_HEAD(&mgr->mgr_troubled_lh);
        spin_lock_init(&mgr->mgr_lock); 

        d.mgr = mgr;
        d.name = "lustre_recovd";

        init_waitqueue_head(&mgr->mgr_waitq);
        init_waitqueue_head(&mgr->mgr_ctl_waitq);

        rc = kernel_thread(recovd_main, (void *) &d,
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread\n");
                RETURN(-EINVAL);
        }
        wait_event(mgr->mgr_ctl_waitq, mgr->mgr_flags & MGR_RUNNING);

        RETURN(0); 
}


int recovd_cleanup(struct connmgr_obd *mgr)
{
        mgr->mgr_flags = MGR_STOPPING;

        wake_up(&mgr->mgr_waitq);
        wait_event_interruptible(mgr->mgr_ctl_waitq,
                                 (mgr->mgr_flags & MGR_STOPPED));
        RETURN(0);
}
