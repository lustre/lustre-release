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
        struct connmgr_obd *mgr = &obddev->u.mgr;
        int err;
        ENTRY;

        memset(mgr, 0, sizeof(*mgr));

        OBD_ALLOC(mgr->mgr_client, sizeof(*mgr->mgr_client));
        if (!mgr)
                RETURN(-ENOMEM);

        err = recovd_setup(mgr);
        if (err)
                GOTO(err_free, err);

        mgr->mgr_service =
                ptlrpc_init_svc(128 * 1024,CONNMGR_REQUEST_PORTAL,
                                CONNMGR_REPLY_PORTAL, "self", connmgr_handle);
        if (!mgr->mgr_service) {
                CERROR("failed to start service\n");
                GOTO(err_recovd, err = -EINVAL);
        }

        ptlrpc_init_client(NULL, CONNMGR_REQUEST_PORTAL, 
                           CONNMGR_REPLY_PORTAL, mgr->mgr_client);

        err = ptlrpc_start_thread(obddev, mgr->mgr_service, "lustre_connmgr");
        if (err) {
                CERROR("cannot start thread\n");
                GOTO(err_svc, err);
        }

        MOD_INC_USE_COUNT;
        ptlrpc_connmgr = mgr;
        RETURN(0);

 err_svc: 
        rpc_unregister_service(mgr->mgr_service);
 err_recovd: 
        recovd_cleanup(mgr); 
 err_free:
        if (mgr->mgr_client)
                OBD_FREE(mgr->mgr_client, sizeof(*mgr->mgr_client));
        RETURN(err);
}

int connmgr_cleanup(struct obd_device *dev)
{
        struct connmgr_obd *mgr = &dev->u.mgr;
        int err;

        err = recovd_cleanup(mgr); 
        if (err) 
                LBUG();

        ptlrpc_stop_thread(mgr->mgr_service);
        rpc_unregister_service(mgr->mgr_service);
        if (!list_empty(&mgr->mgr_service->srv_reqs)) {
                // XXX reply with errors and clean up
                CERROR("Request list not empty!\n");
        }

        OBD_FREE(mgr->mgr_service, sizeof(*mgr->mgr_service));
        mgr->mgr_flags = MGR_STOPPING;

        OBD_FREE(mgr->mgr_client, sizeof(*mgr->mgr_client));
        MOD_DEC_USE_COUNT;
        RETURN(0);
}

/* use obd ops to offer management infrastructure */
static struct obd_ops connmgr_obd_ops = {
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
        obd_register_type(&connmgr_obd_ops, LUSTRE_HA_NAME);
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
