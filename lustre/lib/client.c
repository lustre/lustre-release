/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
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
 * Client-common OBD method implementations and utility functions.
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OST /* XXX WRONG */

#ifdef __KERNEL__
#include <linux/module.h>
#else 
#include <liblustre.h>
#endif

#include <linux/obd.h>
#include <linux/obd_ost.h>
#include <linux/lustre_net.h>
#include <linux/lustre_dlm.h>

struct obd_device *client_tgtuuid2obd(struct obd_uuid *tgtuuid)
{
        int i;

        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_type == NULL)
                        continue;
                if ((strncmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME,
                             sizeof LUSTRE_OSC_NAME) == 0) ||
                    (strncmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME,
                             sizeof LUSTRE_MDC_NAME) == 0)) {
                        struct client_obd *cli = &obd->u.cli;
                        struct obd_import *imp = cli->cl_import;
                        if (strncmp(tgtuuid->uuid, imp->imp_target_uuid.uuid,
                                    sizeof(imp->imp_target_uuid)) == 0)
                                return obd;
                }
        }

        return NULL;
}

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
        cli->cl_sandev = to_kdev_t(0);

        RETURN(0);
}

int client_obd_cleanup(struct obd_device *obddev, int force, int failover)
{
        struct client_obd *client = &obddev->u.cli;

        if (!client->cl_import)
                RETURN(-EINVAL);
        class_destroy_import(client->cl_import);
        client->cl_import = NULL;
        RETURN(0);
}

#ifdef __KERNEL__
/* convert a pathname into a kdev_t */
static kdev_t path2dev(char *path)
{
        struct dentry *dentry;
        struct nameidata nd;
        kdev_t dev;
        KDEVT_VAL(dev, 0);

        if (!path_init(path, LOOKUP_FOLLOW, &nd))
                return 0;

        if (path_walk(path, &nd))
                return 0;

        dentry = nd.dentry;
        if (dentry->d_inode && !is_bad_inode(dentry->d_inode) &&
            S_ISBLK(dentry->d_inode->i_mode))
                dev = dentry->d_inode->i_rdev;
        path_release(&nd);

        return dev;
}

int client_sanobd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct client_obd *cli = &obddev->u.cli;
        ENTRY;

        if (data->ioc_inllen3 < 1) {
                CERROR("setup requires a SAN device pathname\n");
                RETURN(-EINVAL);
        }

        client_obd_setup(obddev, len, buf);

        cli->cl_sandev = path2dev(data->ioc_inlbuf3);
        if (!kdev_t_to_nr(cli->cl_sandev)) {
                CERROR("%s seems not a valid SAN device\n", data->ioc_inlbuf3);
                RETURN(-EINVAL);
        }

        RETURN(0);
}
#endif

int ptlrpc_import_connect(struct lustre_handle *conn, struct obd_device *obd,
                          struct obd_uuid *cluuid)
{
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
        struct obd_export *exp;
        struct ptlrpc_request *request;
        /* XXX maybe this is a good time to create a connect struct? */
        int rc, size[] = {sizeof(imp->imp_target_uuid),
                          sizeof(obd->obd_uuid),
                          sizeof(*conn)};
        char *tmp[] = {imp->imp_target_uuid.uuid,
                       obd->obd_uuid.uuid,
                       (char *)conn};
        int rq_opc = (obd->obd_type->typ_ops->o_brw) ? OST_CONNECT :MDS_CONNECT;
        int msg_flags;

        ENTRY;
        down(&cli->cl_sem);
        rc = class_connect(conn, obd, cluuid);
        if (rc)
                GOTO(out_sem, rc);

        cli->cl_conn_count++;
        if (cli->cl_conn_count > 1)
                GOTO(out_sem, rc);

        if (obd->obd_namespace != NULL)
                CERROR("already have namespace!\n");
        obd->obd_namespace = ldlm_namespace_new(obd->obd_name,
                                                LDLM_NAMESPACE_CLIENT);
        if (obd->obd_namespace == NULL)
                GOTO(out_disco, rc = -ENOMEM);

        request = ptlrpc_prep_req(imp, rq_opc, 3, size, tmp);
        if (!request)
                GOTO(out_ldlm, rc = -ENOMEM);

        request->rq_level = LUSTRE_CONN_NEW;
        request->rq_replen = lustre_msg_size(0, NULL);

        imp->imp_export = exp = class_conn2export(conn);
        exp->exp_connection = ptlrpc_connection_addref(request->rq_connection);

        imp->imp_level = LUSTRE_CONN_CON;
        rc = ptlrpc_queue_wait(request);
        if (rc) {
                class_export_put(imp->imp_export);
                imp->imp_export = exp = NULL;
                GOTO(out_req, rc);
        }

        msg_flags = lustre_msg_get_op_flags(request->rq_repmsg);
        if (rq_opc == MDS_CONNECT || msg_flags & MSG_CONNECT_REPLAYABLE) {
                imp->imp_replayable = 1;
                CDEBUG(D_HA, "connected to replayable target: %s\n",
                       imp->imp_target_uuid.uuid);
        }
        imp->imp_level = LUSTRE_CONN_FULL;
        imp->imp_remote_handle = request->rq_repmsg->handle;
        CDEBUG(D_HA, "local import: %p, remote handle: "LPX64"\n", imp,
               imp->imp_remote_handle.cookie);

        EXIT;
out_req:
        ptlrpc_req_finished(request);
        if (rc) {
out_ldlm:
                ldlm_namespace_free(obd->obd_namespace);
                obd->obd_namespace = NULL;
out_disco:
                cli->cl_conn_count--;
                class_disconnect(conn, 0);
        }
out_sem:
        up(&cli->cl_sem);
        return rc;
}

int ptlrpc_import_disconnect(struct lustre_handle *conn, int failover)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
        struct ptlrpc_request *request = NULL;
        int rc = 0, err, rq_opc;
        ENTRY;

        if (!obd) {
                CERROR("invalid connection for disconnect: cookie "LPX64"\n",
                       conn ? conn->cookie : -1UL);
                RETURN(-EINVAL);
        }

        rq_opc = obd->obd_type->typ_ops->o_brw ? OST_DISCONNECT:MDS_DISCONNECT;
        down(&cli->cl_sem);
        if (!cli->cl_conn_count) {
                CERROR("disconnecting disconnected device (%s)\n",
                       obd->obd_name);
                GOTO(out_sem, rc = -EINVAL);
        }

        cli->cl_conn_count--;
        if (cli->cl_conn_count)
                GOTO(out_no_disconnect, rc = 0);

        if (obd->obd_namespace != NULL) {
                /* obd_no_recov == local only */
                ldlm_cli_cancel_unused(obd->obd_namespace, NULL,
                                       obd->obd_no_recov);
                ldlm_namespace_free(obd->obd_namespace);
                obd->obd_namespace = NULL;
        }

        /* Yeah, obd_no_recov also (mainly) means "forced shutdown". */
        if (obd->obd_no_recov && imp->imp_level != LUSTRE_CONN_FULL) {
                ptlrpc_abort_inflight(imp);
        } else {
                request = ptlrpc_prep_req(imp, rq_opc, 0, NULL, NULL);
                if (!request)
                        GOTO(out_req, rc = -ENOMEM);
                
                request->rq_replen = lustre_msg_size(0, NULL);
                
                /* Process disconnects even if we're waiting for recovery. */
                request->rq_level = LUSTRE_CONN_RECOVD;
                
                rc = ptlrpc_queue_wait(request);
                if (rc)
                        GOTO(out_req, rc);
        }
        if (imp->imp_export) {
                class_export_put(imp->imp_export);
                imp->imp_export = NULL;
        }
        EXIT;
 out_req:
        if (request)
                ptlrpc_req_finished(request);
 out_no_disconnect:
        err = class_disconnect(conn, 0);
        if (!rc && err)
                rc = err;
 out_sem:
        up(&cli->cl_sem);
        RETURN(rc);
}
