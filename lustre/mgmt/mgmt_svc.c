/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Implementation of the management/health monitoring service.
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *   Author: Mike Shaver <shaver@clusterfs.com>
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MGMT
#include <linux/module.h>
#include <linux/init.h>

#include <linux/obd_class.h>
#include <linux/lustre_net.h>

#define MGMT_NEVENTS     1024UL
#define MGMT_NBUFS       128UL
#define MGMT_BUFSIZE     8192
#define MGMT_MAXREQSIZE  512
#define MGMT_NUM_THREADS 4
#define MGMT_DEVICE_NAME "mgmt"

static int mgmt_initialized;
static struct ptlrpc_service *mgmt_service;

static int mgmt_ping(struct ptlrpc_request *req)
{
        /* handle_incoming_request will have already updated the export's
         * last_request_time, so we don't need to do anything else.
         */
        return lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
}

static int mgmt_handler(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        switch (req->rq_reqmsg->opc) {
        case OBD_PING:
                DEBUG_REQ(D_RPCTRACE, req, "ping");
                rc = mgmt_ping(req);
                break;
        case MGMT_CONNECT:
                DEBUG_REQ(D_RPCTRACE, req, "connect");
                rc = target_handle_connect(req, NULL /* no recovery handler */);
                break;
        case MGMT_DISCONNECT:
                DEBUG_REQ(D_RPCTRACE, req, "disconnect");
                rc = target_handle_disconnect(req);
                break;
        default:
                DEBUG_REQ(D_RPCTRACE, req, "UNKNOWN OP");
                rc = -EINVAL;
        }

        if (rc)
                ptlrpc_error(req);
        else
                ptlrpc_reply(req);

        RETURN(0);
}

static int mgmt_setup(struct obd_device *obd, obd_count len, void *buf)
{
        int i, rc;
        ENTRY;

        if (mgmt_initialized)
                RETURN(-EALREADY);
        
        mgmt_service = ptlrpc_init_svc(MGMT_NEVENTS, MGMT_NBUFS, MGMT_BUFSIZE,
                                       MGMT_MAXREQSIZE, MGMT_REQUEST_PORTAL,
                                       MGMT_REPLY_PORTAL, mgmt_handler,
                                       "mgmt", obd);
        if (!mgmt_service) {
                CERROR("Failed to start mgmt service\n");
                RETURN(-ENOMEM);
        }

        for (i = 0; i < MGMT_NUM_THREADS; i++) {
                char name[32];
                sprintf(name, "mgmt_%02d", i);
                rc = ptlrpc_start_thread(obd, mgmt_service, name);
                if (rc) {
                        CERROR("failed to start mgmt thread %d: %d\n", i, rc);
                        LBUG();
                }
        }

        mgmt_initialized = 1;
        
        RETURN(0);
}

static int mgmt_cleanup(struct obd_device *obd, int flags)
{
        ENTRY;
        
        if (!mgmt_initialized)
                RETURN(-ENOENT);

        ptlrpc_stop_all_threads(mgmt_service);
        ptlrpc_unregister_service(mgmt_service);
        
        mgmt_initialized = 0;
        RETURN(0);
}

static struct obd_ops mgmt_obd_ops = {
        o_owner:      THIS_MODULE,
        o_setup:      mgmt_setup,
        o_cleanup:    mgmt_cleanup,
        o_connect:    class_connect,
        o_disconnect: class_disconnect
};

static int __init mgmt_init(void)
{
        int rc = class_register_type(&mgmt_obd_ops, 0, MGMT_DEVICE_NAME);

        return rc;
}

static void __exit mgmt_exit(void)
{
        class_unregister_type(MGMT_DEVICE_NAME);
}

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre monitoring service v0.1");
MODULE_LICENSE("GPL");

module_init(mgmt_init);
module_exit(mgmt_exit);
#endif
