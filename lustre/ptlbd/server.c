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

#if 0
static int ptlbd_sv_callback(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = ptlbd_parse_request(req);

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if ( rc )
                GOTO(out, rc);

        printk("callback got a friggin opc %d\n", req->rq_reqmsg->opc);

out:
        RETURN(rc);
}
#endif

static int ptlbd_sv_already_setup = 1;

static int ptlbd_sv_setup(struct obd_device *obddev, obd_count len, void *buf)
{
#if 0
        struct obd_ioctl_data* data = buf;
        obd_uuid_t server_uuid;
#endif
        struct ptlbd_obd *ptlbd = &obddev->u.ptlbd;
        int rc;
        ENTRY;

        MOD_INC_USE_COUNT;
#if 0
        if (data->ioc_inllen1 < 1) {
                CERROR("requires a PTLBD server UUID\n");
                GOTO(out_dec, rc = -EINVAL);
        }

        if (data->ioc_inllen1 > 37) {
                CERROR("PTLBD server UUID must be less than 38 characters\n");
                GOTO(out_dec, rc = -EINVAL);
        }

        memcpy(server_uuid, data->ioc_inlbuf1, MIN(data->ioc_inllen1,
                                                   sizeof(server_uuid)));

#endif
        ptlbd->ptlbd_service =
                ptlrpc_init_svc(PTLBD_NEVENTS, PTLBD_NBUFS, PTLBD_BUFSIZE,
                                PTLBD_MAXREQSIZE, PTLBD_REQUEST_PORTAL,
                                PTLBD_REPLY_PORTAL, "self", 
                                ptlbd_parse_req, "ptlbd_sv");

        if (!ptlbd->ptlbd_service) {
                CERROR("failed to start service\n");
                GOTO(out_dec, rc = -ENOMEM);
        }

        rc = ptlrpc_start_thread(obddev, ptlbd->ptlbd_service, "ptldb");
        if (rc) {
                CERROR("cannot start PTLBD thread: rc %d\n", rc);
                LBUG();
                GOTO(out_thread, rc);
        }

        ptlbd_sv_already_setup = 1;

        RETURN(0);

 out_thread:
        ptlrpc_stop_all_threads(ptlbd->ptlbd_service);
        ptlrpc_unregister_service(ptlbd->ptlbd_service);

 out_dec:
        MOD_DEC_USE_COUNT;
        return rc;
}

static int ptlbd_sv_cleanup(struct obd_device *obddev)
{
        struct ptlbd_obd *ptlbd = &obddev->u.ptlbd;
        ENTRY;

        /* XXX check for state */

        ptlrpc_stop_all_threads(ptlbd->ptlbd_service);
        ptlrpc_unregister_service(ptlbd->ptlbd_service);

        ptlbd_sv_already_setup = 0;
        MOD_DEC_USE_COUNT;
        RETURN(0);
}

#if 0
static int ptlbd_sv_connect(struct lustre_handle *conn, struct obd_device *src,
                        obd_uuid_t cluuid, struct recovd_obd *recovd,
                        ptlrpc_recovery_cb_t recover)
{
        return class_connect(conn, src, cluuid);
}
#endif

static struct obd_ops ptlbd_sv_obd_ops = {
/*        o_iocontrol:   ptlbd_iocontrol,*/
        o_setup:       ptlbd_sv_setup,
        o_cleanup:     ptlbd_sv_cleanup,
#if 0
        o_connect:     ptlbd_sv_connect,
        o_disconnect:  class_disconnect
#endif
};

int ptlbd_sv_init(void)
{
        extern struct lprocfs_vars status_class_var[];

        return class_register_type(&ptlbd_sv_obd_ops, status_class_var,
                                   OBD_PTLBD_SV_DEVICENAME);
}

void ptlbd_sv_exit(void)
{
        class_unregister_type(OBD_PTLBD_SV_DEVICENAME);
}
