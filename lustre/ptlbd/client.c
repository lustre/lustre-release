/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cluster File Systems, Inc.
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

static int ptlbd_cl_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct ptlbd_obd *ptlbd = &obddev->u.ptlbd;
        struct obd_import *imp = &ptlbd->bd_import;
        struct obd_ioctl_data* data = buf;
        obd_uuid_t server_uuid;
        ENTRY;

        if ( ptlbd->bd_import.imp_connection != NULL )
                RETURN(-EALREADY);

        if (data->ioc_inllen1 < 1) {
                CERROR("requires a PTLBD server UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen1 > 37) {
                CERROR("PTLBD server UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        memcpy(server_uuid, data->ioc_inlbuf1, MIN(data->ioc_inllen1,
                                                   sizeof(server_uuid)));

        imp->imp_connection = ptlrpc_uuid_to_connection(server_uuid);
        if (!imp->imp_connection)
                RETURN(-ENOENT);

        INIT_LIST_HEAD(&imp->imp_replay_list);
        INIT_LIST_HEAD(&imp->imp_sending_list);
        INIT_LIST_HEAD(&imp->imp_delayed_list);
        spin_lock_init(&imp->imp_lock);
        /*
         * from client_obd_connect.. *shrug*
         */
        INIT_LIST_HEAD(&imp->imp_chain);
        imp->imp_last_xid = 0;
        imp->imp_max_transno = 0;
        imp->imp_peer_last_xid = 0;
        imp->imp_peer_committed_transno = 0;
        imp->imp_level = LUSTRE_CONN_FULL;

        ptlrpc_init_client(PTLBD_REQUEST_PORTAL, PTLBD_REPLY_PORTAL, 
                        "ptlbd", &ptlbd->bd_client);
        imp->imp_client = &ptlbd->bd_client;
        imp->imp_obd = obddev;

        ptlbd_blk_register(ptlbd);

        RETURN(0);
}

static int ptlbd_cl_cleanup(struct obd_device *obddev)
{
//        struct ptlbd_obd *ptlbd = &obddev->u.ptlbd;
        ENTRY;

        CERROR("I should be cleaning things up\n");

        RETURN(0);
}

#if 0
static int ptlbd_cl_connect(struct lustre_handle *conn, struct obd_device *obd,
                        obd_uuid_t cluuid, struct recovd_obd *recovd,
                        ptlrpc_recovery_cb_t recover)
{
        struct ptlbd_obd *ptlbd = &obd->u.ptlbd;
        struct obd_import *imp = &ptlbd->bd_import;
        int rc;
        ENTRY;

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        INIT_LIST_HEAD(&imp->imp_chain);
        imp->imp_last_xid = 0;
        imp->imp_max_transno = 0;
        imp->imp_peer_last_xid = 0;
        imp->imp_peer_committed_transno = 0;
        imp->imp_level = LUSTRE_CONN_FULL;

        RETURN(0);
}
#endif

static struct obd_ops ptlbd_cl_obd_ops = {
        o_owner:        THIS_MODULE,
        o_setup:        ptlbd_cl_setup,
        o_cleanup:      ptlbd_cl_cleanup,
#if 0
        o_connect:      ptlbd_cl_connect,
        o_disconnect:   class_disconnect
#endif
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
