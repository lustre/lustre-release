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
extern struct recovd_obd *ptlrpc_connmgr;

int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        int rq_portal = (obddev->obd_type->typ_ops->o_getattr) ? OST_REQUEST_PORTAL : MDS_REQUEST_PORTAL;
        int rp_portal = (obddev->obd_type->typ_ops->o_getattr) ? OSC_REPLY_PORTAL : MDC_REPLY_PORTAL;
        struct client_obd *mdc = &obddev->u.cli;
        char server_uuid[37];
        int rc;
        ENTRY;

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

        sema_init(&mdc->cl_sem, 1);
        mdc->cl_conn_count = 0;
        memcpy(mdc->cl_target_uuid, data->ioc_inlbuf1, data->ioc_inllen1);
        memcpy(server_uuid, data->ioc_inlbuf2, MIN(data->ioc_inllen2,
                                                   sizeof(server_uuid)));

        mdc->cl_conn = ptlrpc_uuid_to_connection(server_uuid);
        if (!mdc->cl_conn)
                RETURN(-ENOENT); 

        OBD_ALLOC(mdc->cl_client, sizeof(*mdc->cl_client));
        if (mdc->cl_client == NULL)
                GOTO(out_conn, rc = -ENOMEM);

        OBD_ALLOC(mdc->cl_ldlm_client, sizeof(*mdc->cl_ldlm_client));
        if (mdc->cl_ldlm_client == NULL)
                GOTO(out_client, rc = -ENOMEM);

        /* XXX get recovery hooked in here again */
        //ptlrpc_init_client(ptlrpc_connmgr, ll_recover,...

        ptlrpc_init_client(NULL, NULL, rq_portal, rp_portal, mdc->cl_client);
        ptlrpc_init_client(NULL, NULL, LDLM_REQUEST_PORTAL, LDLM_REPLY_PORTAL,
                           mdc->cl_ldlm_client);
        mdc->cl_client->cli_name = "mdc";
        mdc->cl_ldlm_client->cli_name = "ldlm";
        mdc->cl_max_mdsize = sizeof(struct lov_stripe_md);

        MOD_INC_USE_COUNT;
        RETURN(0);

 out_client:
        OBD_FREE(mdc->cl_client, sizeof(*mdc->cl_client));
 out_conn:
        ptlrpc_put_connection(mdc->cl_conn);
        return rc;
}

int client_obd_cleanup(struct obd_device * obddev)
{
        struct client_obd *mdc = &obddev->u.cli;

        ptlrpc_cleanup_client(mdc->cl_client);
        OBD_FREE(mdc->cl_client, sizeof(*mdc->cl_client));
        ptlrpc_cleanup_client(mdc->cl_ldlm_client);
        OBD_FREE(mdc->cl_ldlm_client, sizeof(*mdc->cl_ldlm_client));
        ptlrpc_put_connection(mdc->cl_conn);

        MOD_DEC_USE_COUNT;
        return 0;
}

int client_obd_connect(struct lustre_handle *conn, struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;
        struct ptlrpc_request *request;
        int rc, size = sizeof(cli->cl_target_uuid);
        char *tmp = cli->cl_target_uuid;
        int rq_opc = (obd->obd_type->typ_ops->o_getattr) ? OST_CONNECT : MDS_CONNECT;

        ENTRY;
        down(&cli->cl_sem); 
        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd);
        if (!rc) 
                cli->cl_conn_count++;
        else { 
                MOD_DEC_USE_COUNT;
                up(&cli->cl_sem);
                RETURN(rc);
        }
                
        if (cli->cl_conn_count > 1) { 
                up(&cli->cl_sem);
                RETURN(0);
        }

        obd->obd_namespace =
                ldlm_namespace_new("cli", LDLM_NAMESPACE_CLIENT);
        if (obd->obd_namespace == NULL) { 
                up(&cli->cl_sem);
                RETURN(-ENOMEM);
        }

        request = ptlrpc_prep_req(cli->cl_client, cli->cl_conn, rq_opc, 1, &size, &tmp);
        if (!request)
                GOTO(out_disco, -ENOMEM);

        request->rq_level = LUSTRE_CONN_NEW;
        request->rq_replen = lustre_msg_size(0, NULL);
        /* Sending our local connection info breaks for local connections
        request->rq_reqmsg->addr = conn->addr;
        request->rq_reqmsg->cookie = conn->cookie;
         */

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                GOTO(out, rc);

        request->rq_connection->c_level = LUSTRE_CONN_FULL;
        cli->cl_exporth = *(struct lustre_handle *)request->rq_repmsg;

        EXIT;
 out:
        ptlrpc_free_req(request);
 out_disco:
        if (rc) {
                class_disconnect(conn);
                MOD_DEC_USE_COUNT;
        }
        up(&cli->cl_sem);
        return rc;
}

int client_obd_disconnect(struct lustre_handle *conn)
{
        struct obd_device *obd = class_conn2obd(conn);
        int rq_opc = (obd->obd_type->typ_ops->o_getattr) ? OST_DISCONNECT : MDS_DISCONNECT;
        struct ptlrpc_request *request = NULL;
        int rc;
        ENTRY;

        down(&obd->u.cli.cl_sem);
        if (!obd->u.cli.cl_conn_count) { 
                CERROR("disconnecting disconnected device (%s)\n", 
                       obd->obd_name); 
                RETURN(0);
        }

        obd->u.cli.cl_conn_count--; 
        if (obd->u.cli.cl_conn_count)
                GOTO(class_only, 0);

        ldlm_namespace_free(obd->obd_namespace);
        obd->obd_namespace = NULL; 
        request = ptlrpc_prep_req2(conn, rq_opc, 0, NULL, NULL);
        if (!request)
                RETURN(-ENOMEM);

        request->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(request);
        if (rc) 
                GOTO(out, rc);
 class_only:
        rc = class_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;
 out:
        if (request) 
                ptlrpc_free_req(request);
        up(&obd->u.cli.cl_sem);
        RETURN(rc);
}

int target_handle_connect(struct ptlrpc_request *req)
{
        struct obd_device *target;
        struct obd_export *export;
        struct lustre_handle conn;
        char *uuid;
        int rc, i;
        ENTRY;

        uuid = lustre_msg_buf(req->rq_reqmsg, 0);
        if (req->rq_reqmsg->buflens[0] > 37) {
                /* Invalid UUID */
                req->rq_status = -EINVAL;
                RETURN(-EINVAL);
        }

        i = class_uuid2dev(uuid);
        if (i == -1) {
                req->rq_status = -ENODEV;
                RETURN(-ENODEV);
        }

        target = &obd_dev[i];
        if (!target) {
                req->rq_status = -ENODEV;
                RETURN(-ENODEV);
        }

        conn.addr = req->rq_reqmsg->addr;
        conn.cookie = req->rq_reqmsg->cookie;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_connect(&conn, target);
        req->rq_repmsg->addr = conn.addr;
        req->rq_repmsg->cookie = conn.cookie;

        export = class_conn2export(&conn);
        if (!export)
                LBUG();

        req->rq_export = export;
        export->exp_connection = req->rq_connection;
#warning Peter: is this the right place to upgrade the server connection level?
        req->rq_connection->c_level = LUSTRE_CONN_FULL;
        RETURN(0);
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
