/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite recovery infrastructure.
 *
 * Copyright (C) 2002 Cluster File Systems Inc.
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_idl.h>
#include <linux/obd_lov.h> /* for IOC_LOV_SET_OSC_ACTIVE */

static int ll_retry_recovery(struct ptlrpc_connection *conn)
{
    ENTRY;
    RETURN(0);
}

/* XXX looks a lot like super.c:invalidate_request_list, don't it? */
static void abort_inflight_for_import(struct obd_import *imp)
{
        struct list_head *tmp, *n;

        /* Make sure that no new requests get processed for this import.
         * ptlrpc_queue_wait must (and does) hold c_lock while testing this
         * flags and then putting requests on sending_head or delayed_head.
         */
        spin_lock(&imp->imp_connection->c_lock);
        imp->imp_flags |= IMP_INVALID;
        spin_unlock(&imp->imp_connection->c_lock);

        list_for_each_safe(tmp, n, &imp->imp_connection->c_sending_head) {
                struct ptlrpc_request *req =
                        list_entry(tmp, struct ptlrpc_request, rq_list);

                if (req->rq_import != imp)
                        continue;

                if (req->rq_flags & PTL_RPC_FL_REPLIED) {
                        /* no need to replay, just discard */
                        CERROR("uncommitted req xid "LPD64" op %d to OST %s\n",
                               (unsigned long long)req->rq_xid,
                               req->rq_reqmsg->opc,
                               imp->imp_obd->u.cli.cl_target_uuid);
                        ptlrpc_req_finished(req);
                } else {
                        CERROR("inflight req xid "LPD64" op %d to OST %s\n",
                               (unsigned long long)req->rq_xid,
                               req->rq_reqmsg->opc,
                               imp->imp_obd->u.cli.cl_target_uuid);

                        req->rq_flags |= PTL_RPC_FL_ERR;
                        wake_up(&req->rq_wait_for_rep);
                }
        }

        list_for_each_safe(tmp, n, &imp->imp_connection->c_delayed_head) {
                struct ptlrpc_request *req =
                        list_entry(tmp, struct ptlrpc_request, rq_list);
                CERROR("aborting waiting req xid "LPD64" op %d to OST %s\n",
                       (unsigned long long)req->rq_xid, req->rq_reqmsg->opc,
                       imp->imp_obd->u.cli.cl_target_uuid);
                req->rq_flags |= PTL_RPC_FL_ERR;
                wake_up(&req->rq_wait_for_rep);
        }
}

static void prepare_ost(struct obd_import *imp)
{
        int rc;
        struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
        struct obd_device *notify_obd = imp->imp_obd->u.cli.cl_containing_lov;

        CDEBUG(D_HA, "invalidating all locks for OST imp %p (to %s):\n",
               imp, imp->imp_connection->c_remote_uuid);
        ldlm_namespace_dump(ns);
        ldlm_namespace_cleanup(ns, 1 /* no network ops */);

        abort_inflight_for_import(imp);

        /* How gross is _this_? */
        if (!list_empty(&notify_obd->obd_exports)) {
                struct lustre_handle fakeconn;
                struct obd_ioctl_data ioc_data;
                struct obd_export *exp = 
                        list_entry(&notify_obd->obd_exports.next, 
                                   struct obd_export, exp_obd_chain);
                fakeconn.addr = (__u64)(unsigned long)exp;
                fakeconn.cookie = exp->exp_cookie;
                ioc_data.ioc_inlbuf1 = imp->imp_obd->obd_uuid;
                ioc_data.ioc_offset = 0; /* inactive */
                rc = obd_iocontrol(IOC_LOV_SET_OSC_ACTIVE, &fakeconn,
                                   sizeof ioc_data, &ioc_data, NULL);
                if (rc) 
                        CERROR("disabling %s on LOV %p/%s: %d\n", 
                               imp->imp_obd->obd_uuid, notify_obd,
                               notify_obd->obd_uuid, rc);
        } else {
                CDEBUG(D_HA, "No exports for obd %p/%s, can't notify about %p\n",
                       notify_obd, notify_obd->obd_uuid, imp->imp_obd->obd_uuid);
        }
}

static int ll_prepare_recovery(struct ptlrpc_connection *conn)
{
        struct list_head *tmp;

        list_for_each(tmp, &conn->c_imports) {
                struct obd_import *imp = list_entry(tmp, struct obd_import,
                                                    imp_chain);

                if (imp->imp_obd->obd_type->typ_ops->o_brw)
                        prepare_ost(imp);
        }

        return ptlrpc_run_recovery_upcall(conn);
}

static void reconnect_ost(struct obd_import *imp)
{
        (void)ptlrpc_reconnect_import(imp, OST_CONNECT);
}

static int ll_reconnect(struct ptlrpc_connection *conn)
{
        struct list_head *tmp;
        int need_replay = 0;

        ENTRY;

        /* XXX c_lock semantics! */
        conn->c_level = LUSTRE_CONN_CON;

        /* XXX this code MUST be shared with class_obd_connect! */
        list_for_each(tmp, &conn->c_imports) {
                struct obd_import *imp = list_entry(tmp, struct obd_import,
                                                    imp_chain);
                if (imp->imp_obd->obd_type->typ_ops->o_brw) {
                        /* XXX what to do if we fail? */
                        reconnect_ost(imp);
                } else {
                        int rc = ptlrpc_reconnect_import(imp, MDS_CONNECT);
                        if (!rc) {
                                need_replay = 1;
                                /* XXX obd_cancel_unused */
                        }
                        /* make sure we don't try to replay for dead imps?
                         *
                         * else imp->imp_connection = NULL;
                         *
                         */
                        
                }
        }

        if (!need_replay) {
                /* all done! */
                conn->c_level = LUSTRE_CONN_FULL;
                RETURN(0);
        }
        
        conn->c_level = LUSTRE_CONN_RECOVD;
        /* this will replay, up the c_level, recovd_conn_fixed and continue reqs.
         * also, makes a mean cup of coffee.
         */
        RETURN(ptlrpc_replay(conn));
}

int ll_recover(struct recovd_data *rd, int phase)
{
        struct ptlrpc_connection *conn = class_rd2conn(rd);

        LASSERT(conn);
        ENTRY;

        switch (phase) {
            case PTLRPC_RECOVD_PHASE_PREPARE:
                RETURN(ll_prepare_recovery(conn));
            case PTLRPC_RECOVD_PHASE_RECOVER:
                RETURN(ll_reconnect(conn));
            case PTLRPC_RECOVD_PHASE_FAILURE:
                RETURN(ll_retry_recovery(conn));
        }

        LBUG();
        RETURN(-ENOSYS);
}
