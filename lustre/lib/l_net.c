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
