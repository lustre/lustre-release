/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 */

#define EXPORT_SYMTAB

#include <linux/module.h>

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/lustre_ha.h>

extern int ptlrpc_init_portals(void);
extern void ptlrpc_exit_portals(void);

int connmgr_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct recovd_obd *recovd = &obddev->u.recovd;
        int err;
        ENTRY;

        memset(recovd, 0, sizeof(*recovd));

        OBD_ALLOC(recovd->recovd_client, sizeof(*recovd->recovd_client));
        if (!recovd)
                RETURN(-ENOMEM);

        err = recovd_setup(recovd);
        if (err)
                GOTO(err_free, err);

        recovd->recovd_service =
                ptlrpc_init_svc(128 * 1024,CONNMGR_REQUEST_PORTAL,
                                CONNMGR_REPLY_PORTAL, "self", connmgr_handle);
        if (!recovd->recovd_service) {
                CERROR("failed to start service\n");
                GOTO(err_recovd, err = -EINVAL);
        }

        ptlrpc_init_client(NULL, CONNMGR_REQUEST_PORTAL, 
                           CONNMGR_REPLY_PORTAL, recovd->recovd_client);

        err = ptlrpc_start_thread(obddev, recovd->recovd_service, "lustre_connmgr");
        if (err) {
                CERROR("cannot start thread\n");
                GOTO(err_svc, err);
        }

        MOD_INC_USE_COUNT;
        ptlrpc_connmgr = recovd;
        RETURN(0);

 err_svc: 
        rpc_unregister_service(recovd->recovd_service);
 err_recovd: 
        recovd_cleanup(recovd); 
 err_free:
        if (recovd->recovd_client)
                OBD_FREE(recovd->recovd_client, sizeof(*recovd->recovd_client));
        RETURN(err);
}

int connmgr_cleanup(struct obd_device *dev)
{
        struct recovd_obd *recovd = &dev->u.recovd;
        int err;

        err = recovd_cleanup(recovd); 
        if (err) 
                LBUG();

        ptlrpc_stop_thread(recovd->recovd_service);
        rpc_unregister_service(recovd->recovd_service);
        if (!list_empty(&recovd->recovd_service->srv_reqs)) {
                // XXX reply with errors and clean up
                CERROR("Request list not empty!\n");
        }

        OBD_FREE(recovd->recovd_service, sizeof(*recovd->recovd_service));
        recovd->recovd_flags = MGR_STOPPING;

        OBD_FREE(recovd->recovd_client, sizeof(*recovd->recovd_client));
        MOD_DEC_USE_COUNT;
        RETURN(0);
}

/* use obd ops to offer management infrastructure */
static struct obd_ops recovd_obd_ops = {
        o_setup:       connmgr_setup,
        o_cleanup:     connmgr_cleanup,
};

static int __init ptlrpc_init(void)
{
        int rc; 
        rc = ptlrpc_init_portals();
        if (rc) 
                RETURN(rc);
        ptlrpc_init_connection();
        obd_register_type(&recovd_obd_ops, LUSTRE_HA_NAME);
        return 0;
}

static void __exit ptlrpc_exit(void)
{
        obd_unregister_type(LUSTRE_HA_NAME);
        ptlrpc_exit_portals();
        ptlrpc_cleanup_connection();
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Request Processor v1.0");
MODULE_LICENSE("GPL"); 

module_init(ptlrpc_init);
module_exit(ptlrpc_exit);
