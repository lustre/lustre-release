/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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
 *
 * Target-common OBD method implementations and utility functions.
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OST /* XXX WRONG */

#include <linux/module.h>
#include <linux/obd_ost.h>
#include <linux/lustre_net.h>
#include <linux/lustre_dlm.h>

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

        rc = obd_connect(&conn, target, cluuid, ptlrpc_recovd,
                         target_revoke_connection);
        /* EALREADY indicates a reconnection, send the reply normally. */
        if (rc && rc != EALREADY)
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
        if (req->rq_connection != NULL)
                ptlrpc_put_connection(req->rq_connection);
        req->rq_connection = ptlrpc_connection_addref(export->exp_connection);

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
        spin_lock_init(&dlmimp->imp_lock);
        dlmimp->imp_level = LUSTRE_CONN_FULL;
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

static int target_disconnect_client(struct ptlrpc_connection *conn)
{
        struct list_head *expiter, *n;
        struct lustre_handle hdl;
        struct obd_export *exp;
        int rc;
        ENTRY;

        list_for_each_safe(expiter, n, &conn->c_exports) {
                exp = list_entry(expiter, struct obd_export, exp_conn_chain);

                hdl.addr = (__u64)(unsigned long)exp;
                hdl.cookie = exp->exp_cookie;
                rc = obd_disconnect(&hdl);
                if (rc)
                        CERROR("disconnecting export %p failed: %d\n", exp, rc);
        }

        /* XXX spank the connection (it's frozen in _RECOVD for now!) */
        RETURN(0);
}

static int target_fence_failed_connection(struct ptlrpc_connection *conn)
{
        ENTRY;

        conn->c_recovd_data.rd_phase = RD_PREPARED;

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
                RETURN(target_disconnect_client(conn));
            case PTLRPC_RECOVD_PHASE_FAILURE:
                LBUG();
                RETURN(0);
        }

        LBUG();
        RETURN(-ENOSYS);
}
