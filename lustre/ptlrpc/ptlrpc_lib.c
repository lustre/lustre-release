/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_RPC

#ifdef __KERNEL__
# include <linux/module.h>
#else 
# include <liblustre.h>
#endif
#include <linux/obd.h>
#include <linux/obd_ost.h>
#include <linux/lustre_net.h>
#include <linux/lustre_dlm.h>

int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct ptlrpc_connection *conn;
        struct obd_ioctl_data* data = buf;
        struct client_obd *cli = &obddev->u.cli;
        struct obd_import *imp;
        struct obd_uuid server_uuid;
        int rq_portal, rp_portal, connect_op;
        char *name;
        ENTRY;

        if (obddev->obd_type->typ_ops->o_brw) {
                rq_portal = OST_REQUEST_PORTAL;
                rp_portal = OSC_REPLY_PORTAL;
                name = "osc";
                connect_op = OST_CONNECT;
        } else {
                rq_portal = MDS_REQUEST_PORTAL;
                rp_portal = MDC_REPLY_PORTAL;
                name = "mdc";
                connect_op = MDS_CONNECT;
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
        memcpy(server_uuid.uuid, data->ioc_inlbuf2, MIN(data->ioc_inllen2,
                                                        sizeof(server_uuid)));

        conn = ptlrpc_uuid_to_connection(&server_uuid);
        if (conn == NULL)
                RETURN(-ENOENT);

        ptlrpc_init_client(rq_portal, rp_portal, name,
                           &obddev->obd_ldlm_client);

        imp = class_new_import();
        if (imp == NULL) {
                ptlrpc_put_connection(conn);
                RETURN(-ENOMEM);
        }
        imp->imp_connection = conn;
        imp->imp_client = &obddev->obd_ldlm_client;
        imp->imp_obd = obddev;
        imp->imp_connect_op = connect_op;
        imp->imp_generation = 0;
        memcpy(imp->imp_target_uuid.uuid, data->ioc_inlbuf1, data->ioc_inllen1);
        class_import_put(imp);

        cli->cl_import = imp;
        cli->cl_max_mds_easize = sizeof(struct lov_mds_md);
        cli->cl_max_mds_cookiesize = sizeof(struct llog_cookie);
        cli->cl_sandev = to_kdev_t(0);

        RETURN(0);
}

int client_obd_cleanup(struct obd_device *obddev, int flags)
{
        struct client_obd *client = &obddev->u.cli;

        if (!client->cl_import)
                RETURN(-EINVAL);
        class_destroy_import(client->cl_import);
        client->cl_import = NULL;
        RETURN(0);
}
