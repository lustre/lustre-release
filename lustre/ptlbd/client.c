/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@clusterfs.com>
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
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>

#define DEBUG_SUBSYSTEM S_PTLBD

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_debug.h>
#include <linux/lprocfs_status.h>
#include <linux/obd_ptlbd.h>

static int ptlbd_cl_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct ptlbd_obd *ptlbd = &obd->u.ptlbd;
        struct obd_import *imp;
        struct obd_ioctl_data* data = buf;
        ENTRY;

        if (ptlbd->bd_import != NULL)
                RETURN(-EALREADY);

        if (data->ioc_inllen1 < 1) {
                CERROR("requires a PTLBD server UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen1 > 37) {
                CERROR("PTLBD server UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        obd_str2uuid(&ptlbd->bd_server_uuid, data->ioc_inlbuf1);

        /*
         * from client_obd_connect.. *shrug*
         */
        imp = ptlbd->bd_import = class_new_import();
        imp->imp_connection = ptlrpc_uuid_to_connection(&ptlbd->bd_server_uuid);
        if (!imp->imp_connection) {
                class_destroy_import(imp);
                class_import_put(imp);
                RETURN(-ENOENT);
        }
        imp->imp_level = LUSTRE_CONN_FULL;

        ptlrpc_init_client(PTLBD_REQUEST_PORTAL, PTLBD_REPLY_PORTAL, 
                        "ptlbd", &ptlbd->bd_client);
        imp->imp_client = &ptlbd->bd_client;
        imp->imp_obd = obd;
        memcpy(imp->imp_target_uuid.uuid, data->ioc_inlbuf1, data->ioc_inllen1);
        ptlbd_blk_register(ptlbd);

        RETURN(0);
}

static int ptlbd_cl_cleanup(struct obd_device *obd, int force, int failover)
{
        struct ptlbd_obd *ptlbd = &obd->u.ptlbd;
        struct obd_import *imp;
        ENTRY;

        if ((!ptlbd) || (!(imp = ptlbd->bd_import)))
                RETURN(-ENOENT);

        if (!imp->imp_connection)
                RETURN(-ENOENT);

        ptlrpc_cleanup_client(imp);
        ptlrpc_put_connection(imp->imp_connection);

        class_destroy_import(imp);
        class_import_put(imp);

        RETURN(0);
}


/* modelled after ptlrpc_import_connect() */
int ptlbd_cl_connect(struct lustre_handle *conn,
                      struct obd_device *obd, 
                      struct obd_uuid *target_uuid)
{
        struct ptlbd_obd *ptlbd = &obd->u.ptlbd;
        struct obd_import *imp = ptlbd->bd_import;
        struct obd_export *exp;
        struct ptlrpc_request *request;
        int     rc, size[] = {sizeof(imp->imp_target_uuid),
                              sizeof(obd->obd_uuid),
                              sizeof(*conn)};
        char *tmp[] = {imp->imp_target_uuid.uuid, 
                       obd->obd_uuid.uuid,
                       (char*)conn};
        ENTRY;

        if (!conn || !obd || !target_uuid)
                RETURN(-EINVAL);

        rc = class_connect(conn, obd, target_uuid);
        if (rc)
                RETURN(rc);

        request = ptlrpc_prep_req(imp, PTLBD_CONNECT, 3, size, tmp);
        if (!request)
                GOTO(out_disco, rc = -ENOMEM);
        request->rq_level = LUSTRE_CONN_NEW;
        request->rq_replen = lustre_msg_size(0, NULL);

        imp->imp_dlm_handle = *conn;

        imp->imp_level = LUSTRE_CONN_CON;
        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_req, rc);

        exp = class_conn2export(conn);
        exp->exp_connection = ptlrpc_connection_addref(request->rq_connection);
        class_export_put(exp);

        imp->imp_level = LUSTRE_CONN_FULL;
        imp->imp_remote_handle = request->rq_repmsg->handle;
        
out_req:
        ptlrpc_req_finished(request);
out_disco:
        if (rc)
                class_disconnect(conn, 0);
        RETURN(rc);
}


/* modelled after ptlrpc_import_disconnect() */
int ptlbd_cl_disconnect(struct lustre_handle *conn, int failover)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct ptlbd_obd *ptlbd = &obd->u.ptlbd;
        struct obd_import *imp = ptlbd->bd_import;
        struct ptlrpc_request *request;
        int     rc, err;
        ENTRY;

        if (!obd)
                RETURN(-EINVAL);

        request = ptlrpc_prep_req(imp, PTLBD_DISCONNECT, 0, NULL, NULL);
        if (!request)
                GOTO(out_req, rc = -ENOMEM);

        request->rq_replen = lustre_msg_size(0, NULL);
        request->rq_level = LUSTRE_CONN_RECOVD;

        rc = ptlrpc_queue_wait(request);

out_req:
        if (request)
                ptlrpc_req_finished(request);
        err = class_disconnect(conn, 0);
        memset(&imp->imp_remote_handle, 0, sizeof(imp->imp_remote_handle));
        if (!rc && err)
                rc = err;
        RETURN(rc);
}


static struct obd_ops ptlbd_cl_obd_ops = {
        o_owner:        THIS_MODULE,
        o_setup:        ptlbd_cl_setup,
        o_cleanup:      ptlbd_cl_cleanup,
        o_connect:      ptlbd_cl_connect,
        o_disconnect:   ptlbd_cl_disconnect,
};

int ptlbd_cl_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(&lvars);
        return class_register_type(&ptlbd_cl_obd_ops, lvars.module_vars,
                                   OBD_PTLBD_CL_DEVICENAME);
}

void ptlbd_cl_exit(void)
{
        class_unregister_type(OBD_PTLBD_CL_DEVICENAME);
}



int ptlbd_do_connect(struct ptlbd_obd *ptlbd)
{
        int     rc;
        struct obd_device       *obd = ptlbd->bd_import->imp_obd;
        ENTRY;

        memset(&ptlbd->bd_connect_handle, 0, sizeof(ptlbd->bd_connect_handle));
        rc = obd_connect(&ptlbd->bd_connect_handle, obd, 
                         &ptlbd->bd_server_uuid);
        RETURN(rc);
}


int ptlbd_do_disconnect(struct ptlbd_obd *ptlbd)
{
        int     rc;
        ENTRY;

        rc = obd_disconnect(&ptlbd->bd_connect_handle, 0);
        RETURN(rc);
}

