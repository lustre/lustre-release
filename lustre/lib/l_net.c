/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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
 *
 *  Storage Target Handling functions
 *  Lustre Object Server Module (OST)
 *
 *  This server is single threaded at present (but can easily be multi
 *  threaded). For testing and management it is treated as an
 *  obd_device, although it does not export a full OBD method table
 *  (the requests are coming in over the wire, so object target
 *  modules do not have a full method table.)
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OST

#include <linux/module.h>
#include <linux/obd_ost.h>
#include <linux/lustre_net.h>
#include <linux/lustre_dlm.h>

struct client_obd *client_conn2cli(struct lustre_handle *conn)
{
        struct obd_export *export = class_conn2export(conn);
        if (!export)
                LBUG();
        return &export->exp_obd->u.cli;
}

int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        int rq_portal, rp_portal;
        char *name;
        struct client_obd *cli = &obddev->u.cli;
        char server_uuid[37];
        ENTRY;

        if (obddev->obd_type->typ_ops->o_brw) {
                rq_portal = OST_REQUEST_PORTAL;
                rp_portal = OSC_REPLY_PORTAL;
                name = "osc";
        } else {
                rq_portal = MDS_REQUEST_PORTAL;
                rp_portal = MDC_REPLY_PORTAL;
                name = "mdc";
        }

        if (data->ioc_inllen1 < 1) {
                CERROR("requires a TARGET UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen1 > 37) {
                CERROR("client UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen2 < 1) {
                CERROR("setup requires a SERVER UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen2 > 37) {
                CERROR("target UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        sema_init(&cli->cl_sem, 1);
        cli->cl_conn_count = 0;
        memcpy(cli->cl_target_uuid, data->ioc_inlbuf1, data->ioc_inllen1);
        memcpy(server_uuid, data->ioc_inlbuf2, MIN(data->ioc_inllen2,
                                                   sizeof(server_uuid)));

        cli->cl_import.imp_connection = ptlrpc_uuid_to_connection(server_uuid);
        if (!cli->cl_import.imp_connection)
                RETURN(-ENOENT);

        ptlrpc_init_client(rq_portal, rp_portal, name,
                           &obddev->obd_ldlm_client);
        cli->cl_import.imp_client = &obddev->obd_ldlm_client;
        cli->cl_import.imp_obd = obddev;

        cli->cl_max_mdsize = sizeof(struct lov_mds_md);

        MOD_INC_USE_COUNT;
        RETURN(0);
}

int client_obd_cleanup(struct obd_device * obddev)
{
        struct client_obd *mdc = &obddev->u.cli;

        ptlrpc_cleanup_client(&mdc->cl_import);
        ptlrpc_put_connection(mdc->cl_import.imp_connection);

        MOD_DEC_USE_COUNT;
        return 0;
}

int client_obd_connect(struct lustre_handle *conn, struct obd_device *obd,
                       char *cluuid)
{
        struct client_obd *cli = &obd->u.cli;
        struct ptlrpc_request *request;
        int rc, size[] = {sizeof(cli->cl_target_uuid),
                          sizeof(obd->obd_uuid) };
        char *tmp[] = {cli->cl_target_uuid, obd->obd_uuid};
        int rq_opc = (obd->obd_type->typ_ops->o_brw) ? OST_CONNECT :MDS_CONNECT;
        struct ptlrpc_connection *c;

        ENTRY;
        down(&cli->cl_sem);
        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd, cluuid);
        if (rc) {
                MOD_DEC_USE_COUNT;
                GOTO(out_sem, rc);
        }
        cli->cl_conn_count++;
        if (cli->cl_conn_count > 1)
                GOTO(out_sem, rc);

        obd->obd_namespace = ldlm_namespace_new(obd->obd_name,
                                                LDLM_NAMESPACE_CLIENT);
        if (obd->obd_namespace == NULL)
                GOTO(out_disco, rc = -ENOMEM);

        request = ptlrpc_prep_req(&cli->cl_import, rq_opc, 2, size, tmp);
        if (!request)
                GOTO(out_ldlm, rc = -ENOMEM);

        request->rq_level = LUSTRE_CONN_NEW;
        request->rq_replen = lustre_msg_size(0, NULL);
        request->rq_reqmsg->addr = conn->addr;
        request->rq_reqmsg->cookie = conn->cookie;
        c = class_conn2export(conn)->exp_connection = request->rq_connection;

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out_req, rc);

        list_add(&cli->cl_import.imp_chain, &c->c_imports);
        c->c_level = LUSTRE_CONN_FULL;
        cli->cl_import.imp_handle.addr = request->rq_repmsg->addr;
        cli->cl_import.imp_handle.cookie = request->rq_repmsg->cookie;

        recovd_conn_manage(c, ptlrpc_recovd, ll_recover);


        EXIT;
out_req:
        ptlrpc_free_req(request);
        if (rc) {
out_ldlm:
                ldlm_namespace_free(obd->obd_namespace);
                obd->obd_namespace = NULL;
out_disco:
                class_disconnect(conn);
                MOD_DEC_USE_COUNT;
        }
out_sem:
        up(&cli->cl_sem);
        return rc;
}

int client_obd_disconnect(struct lustre_handle *conn)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct client_obd *cli = &obd->u.cli;
        int rq_opc = (obd->obd_type->typ_ops->o_brw) ? OST_DISCONNECT : MDS_DISCONNECT;
        struct ptlrpc_request *request = NULL;
        int rc, err;
        ENTRY;

        down(&cli->cl_sem);
        if (!cli->cl_conn_count) {
                CERROR("disconnecting disconnected device (%s)\n",
                       obd->obd_name);
                GOTO(out_sem, rc = -EINVAL);
        }

        cli->cl_conn_count--;
        if (cli->cl_conn_count)
                GOTO(out_disco, rc = 0);

        ldlm_namespace_free(obd->obd_namespace);
        obd->obd_namespace = NULL;
        request = ptlrpc_prep_req(&cli->cl_import, rq_opc, 0, NULL, NULL);
        if (!request)
                GOTO(out_disco, rc = -ENOMEM);

        request->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_req, rc);

        EXIT;
 out_req:
        if (request)
                ptlrpc_free_req(request);
 out_disco:
        err = class_disconnect(conn);
        if (!rc && err)
                rc = err;
        list_del_init(&cli->cl_import.imp_chain);
        MOD_DEC_USE_COUNT;
 out_sem:
        up(&cli->cl_sem);
        RETURN(rc);
}

int target_handle_connect(struct ptlrpc_request *req)
{
        struct obd_device *target;
        struct obd_export *export;
        struct obd_import *dlmimp;
        struct lustre_handle conn;
        char *tgtuuid, *cluuid;
        int rc, i;
        ENTRY;

        tgtuuid = lustre_msg_buf(req->rq_reqmsg, 0);
        if (req->rq_reqmsg->buflens[0] > 37) {
                CERROR("bad target UUID for connect\n");
                GOTO(out, rc = -EINVAL);
        }

        cluuid = lustre_msg_buf(req->rq_reqmsg, 1);
        if (req->rq_reqmsg->buflens[1] > 37) {
                CERROR("bad client UUID for connect\n");
                GOTO(out, rc = -EINVAL);
        }

        i = class_uuid2dev(tgtuuid);
        if (i == -1) {
                CERROR("UUID '%s' not found for connect\n", tgtuuid);
                GOTO(out, rc = -ENODEV);
        }

        target = &obd_dev[i];
        if (!target)
                GOTO(out, rc = -ENODEV);

        conn.addr = req->rq_reqmsg->addr;
        conn.cookie = req->rq_reqmsg->cookie;

        rc = obd_connect(&conn, target, cluuid);
        if (rc)
                GOTO(out, rc);

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                GOTO(out, rc);
        req->rq_repmsg->addr = conn.addr;
        req->rq_repmsg->cookie = conn.cookie;

        export = class_conn2export(&conn);
        LASSERT(export);

        req->rq_export = export;
        export->exp_connection = ptlrpc_get_connection(&req->rq_peer, cluuid);
        req->rq_connection = export->exp_connection;

        spin_lock(&export->exp_connection->c_lock);
        list_add(&export->exp_conn_chain, &export->exp_connection->c_exports);
        spin_unlock(&export->exp_connection->c_lock);

        recovd_conn_manage(export->exp_connection, ptlrpc_recovd,
                           target_revoke_connection);
        dlmimp = &export->exp_ldlm_data.led_import;
        dlmimp->imp_connection = req->rq_connection;
        dlmimp->imp_client = &export->exp_obd->obd_ldlm_client;
        dlmimp->imp_handle.addr = req->rq_reqmsg->addr;
        dlmimp->imp_handle.cookie = req->rq_reqmsg->cookie;
        dlmimp->imp_obd = /* LDLM! */ NULL;
        
#warning Peter: is this the right place to upgrade the server connection level?
        req->rq_connection->c_level = LUSTRE_CONN_FULL;
out:
        req->rq_status = rc;
        RETURN(rc);
}

int target_handle_disconnect(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        int rc;
        ENTRY;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_disconnect(conn);
        RETURN(0);
}

static int target_revoke_client_resources(struct ptlrpc_connection *conn)
{
        struct list_head *tmp, *pos;

        ENTRY;

        /* Cancel outstanding locks. */
        list_for_each_safe(tmp, pos, &conn->c_exports) {
        }

        RETURN(0);
}

static int target_fence_failed_connection(struct ptlrpc_connection *conn)
{
        ENTRY;

        conn->c_level = LUSTRE_CONN_RECOVD;

        RETURN(0);
}

int target_revoke_connection(struct recovd_data *rd, int phase)
{
        struct ptlrpc_connection *conn = class_rd2conn(rd);
        
        LASSERT(conn);
        ENTRY;

        switch (phase) {
            case PTLRPC_RECOVD_PHASE_PREPARE:
                RETURN(target_fence_failed_connection(conn));
            case PTLRPC_RECOVD_PHASE_RECOVER:
                RETURN(target_revoke_client_resources(conn));
            case PTLRPC_RECOVD_PHASE_FAILURE:
                LBUG();
                RETURN(0);
        }

        LBUG();
        RETURN(-ENOSYS);
}
