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

struct client_obd *client_conn2cli(struct lustre_handle *conn)
{
        struct obd_export *export = class_conn2export(conn);
        if (!export)
                LBUG();
        return &export->exp_obd->u.cli;
}

struct obd_device *client_tgtuuid2obd(struct obd_uuid *tgtuuid)
{
        int i;

        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if ((strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) == 0) ||
                    (strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) == 0)) {
                        struct client_obd *cli = &obd->u.cli;
                        if (strncmp(tgtuuid->uuid, cli->cl_target_uuid.uuid,
                                    sizeof(cli->cl_target_uuid.uuid)) == 0)
                                return obd;
                }
        }

        return NULL;
}

int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        int rq_portal, rp_portal;
        char *name;
        struct client_obd *cli = &obddev->u.cli;
        struct obd_import *imp = &cli->cl_import;
        struct obd_uuid server_uuid;
        ENTRY;

        if (obddev->obd_type->typ_ops->o_brw) {
                rq_portal = OST_REQUEST_PORTAL;
                rp_portal = OSC_REPLY_PORTAL;
                name = "osc";
        } else {
                rq_portal = MDS_REQUEST_PORTAL;
                rp_portal = MDC_REPLY_PORTAL;
                name = "mdc";
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
        memcpy(cli->cl_target_uuid.uuid, data->ioc_inlbuf1, data->ioc_inllen1);
        memcpy(server_uuid.uuid, data->ioc_inlbuf2, MIN(data->ioc_inllen2,
                                                   sizeof(server_uuid)));

        imp->imp_connection = ptlrpc_uuid_to_connection(&server_uuid);
        if (!imp->imp_connection)
                RETURN(-ENOENT);

        INIT_LIST_HEAD(&imp->imp_replay_list);
        INIT_LIST_HEAD(&imp->imp_sending_list);
        INIT_LIST_HEAD(&imp->imp_delayed_list);
        spin_lock_init(&imp->imp_lock);

        ptlrpc_init_client(rq_portal, rp_portal, name,
                           &obddev->obd_ldlm_client);
        imp->imp_client = &obddev->obd_ldlm_client;
        imp->imp_obd = obddev;

        cli->cl_max_mds_easize = sizeof(struct lov_mds_md);
#if !defined(__KERNEL__) || (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        cli->cl_sandev = 0;
#else
        cli->cl_sandev.value = 0;
#endif

        RETURN(0);
}

#ifdef __KERNEL__
/* convert a pathname into a kdev_t */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static kdev_t path2dev(char *path)
{
        struct dentry *dentry;
        struct nameidata nd;
        kdev_t dev = 0;

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
#else
static int path2dev(char *path)
{
        struct dentry *dentry;
        struct nameidata nd;
        int dev = 0;

        if (!path_init(path, LOOKUP_FOLLOW, &nd))
                return 0;

        if (path_walk(path, &nd))
                return 0;

        dentry = nd.dentry;
        if (dentry->d_inode && !is_bad_inode(dentry->d_inode) &&
            S_ISBLK(dentry->d_inode->i_mode))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                dev = dentry->d_inode->i_rdev;
#else
                dev = dentry->d_inode->i_rdev.value;
#endif
        path_release(&nd);

        return dev;
}
#endif

int client_sanobd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct client_obd *cli = &obddev->u.cli;
        struct obd_import *imp = &cli->cl_import;
        struct obd_uuid server_uuid;
        ENTRY;

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

        if (data->ioc_inllen3 < 1) {
                CERROR("setup requires a SAN device pathname\n");
                RETURN(-EINVAL);
        }

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        cli->cl_sandev = path2dev(data->ioc_inlbuf3);
        if (!cli->cl_sandev) {
                CERROR("%s seems not a valid SAN device\n", data->ioc_inlbuf3);
                RETURN(-EINVAL);
        }
#else
        cli->cl_sandev.value = path2dev(data->ioc_inlbuf3);
        if (!cli->cl_sandev.value) {
                CERROR("%s seems not a valid SAN device\n", data->ioc_inlbuf3);
                RETURN(-EINVAL);
        }
#endif

        sema_init(&cli->cl_sem, 1);
        cli->cl_conn_count = 0;
        memcpy(cli->cl_target_uuid.uuid, data->ioc_inlbuf1, data->ioc_inllen1);
        memcpy(server_uuid.uuid, data->ioc_inlbuf2, MIN(data->ioc_inllen2,
                                                   sizeof(server_uuid)));

        imp->imp_connection = ptlrpc_uuid_to_connection(&server_uuid);
        if (!imp->imp_connection)
                RETURN(-ENOENT);
        
        INIT_LIST_HEAD(&imp->imp_replay_list);
        INIT_LIST_HEAD(&imp->imp_sending_list);
        INIT_LIST_HEAD(&imp->imp_delayed_list);
        spin_lock_init(&imp->imp_lock);

        ptlrpc_init_client(OST_REQUEST_PORTAL, OSC_REPLY_PORTAL,
                           "sanosc", &obddev->obd_ldlm_client);
        imp->imp_client = &obddev->obd_ldlm_client;
        imp->imp_obd = obddev;

        cli->cl_max_mds_easize = sizeof(struct lov_mds_md);

        RETURN(0);
}
#endif

int client_obd_cleanup(struct obd_device * obddev)
{
        struct client_obd *obd = &obddev->u.cli;

        ptlrpc_cleanup_client(&obd->cl_import);
        ptlrpc_put_connection(obd->cl_import.imp_connection);

        return 0;
}

int client_obd_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct recovd_obd *recovd,
                       ptlrpc_recovery_cb_t recover)
{
        struct client_obd *cli = &obd->u.cli;
        struct ptlrpc_request *request;
        int rc, size[] = {sizeof(cli->cl_target_uuid),
                          sizeof(obd->obd_uuid) };
        char *tmp[] = {cli->cl_target_uuid.uuid, obd->obd_uuid.uuid};
        int rq_opc = (obd->obd_type->typ_ops->o_brw) ? OST_CONNECT :MDS_CONNECT;
        struct ptlrpc_connection *c;
        struct obd_import *imp = &cli->cl_import;
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

        INIT_LIST_HEAD(&imp->imp_chain);
        imp->imp_max_transno = 0;
        imp->imp_peer_committed_transno = 0;

        request = ptlrpc_prep_req(&cli->cl_import, rq_opc, 2, size, tmp);
        if (!request)
                GOTO(out_ldlm, rc = -ENOMEM);

        request->rq_level = LUSTRE_CONN_NEW;
        request->rq_replen = lustre_msg_size(0, NULL);
        request->rq_reqmsg->addr = conn->addr;
        request->rq_reqmsg->cookie = conn->cookie;
        c = class_conn2export(conn)->exp_connection =
                ptlrpc_connection_addref(request->rq_connection);
        list_add(&imp->imp_chain, &c->c_imports);
        recovd_conn_manage(c, recovd, recover);

        imp->imp_level = LUSTRE_CONN_CON;
        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_req, rc);

        msg_flags = lustre_msg_get_op_flags(request->rq_repmsg);
        if (rq_opc == MDS_CONNECT || msg_flags & MSG_CONNECT_REPLAYABLE) {
                imp->imp_flags |= IMP_REPLAYABLE;
                CDEBUG(D_HA, "connected to replayable target: %s\n", cli->cl_target_uuid.uuid);
        }
        imp->imp_level = LUSTRE_CONN_FULL;
        imp->imp_handle.addr = request->rq_repmsg->addr;
        imp->imp_handle.cookie = request->rq_repmsg->cookie;

        EXIT;
out_req:
        ptlrpc_req_finished(request);
        if (rc) {
out_ldlm:
                ldlm_namespace_free(obd->obd_namespace);
                obd->obd_namespace = NULL;
out_disco:
                cli->cl_conn_count--;
                class_disconnect(conn);
        }
out_sem:
        up(&cli->cl_sem);
        return rc;
}

int client_obd_disconnect(struct lustre_handle *conn)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct client_obd *cli = &obd->u.cli;
        int rq_opc;
        struct ptlrpc_request *request = NULL;
        int rc, err;
        ENTRY;

        if (!obd) {
                CERROR("invalid connection for disconnect: addr "LPX64
                       ", cookie "LPX64"\n", conn ? conn->addr : -1UL,
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
                ldlm_cli_cancel_unused(obd->obd_namespace, NULL, 0);
                ldlm_namespace_free(obd->obd_namespace);
                obd->obd_namespace = NULL;
        }
        request = ptlrpc_prep_req(&cli->cl_import, rq_opc, 0, NULL, NULL);
        if (!request)
                GOTO(out_req, rc = -ENOMEM);

        request->rq_replen = lustre_msg_size(0, NULL);

        /* Process disconnects even if we're waiting for recovery. */
        request->rq_level = LUSTRE_CONN_RECOVD;

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_req, rc);

        EXIT;
 out_req:
        if (request)
                ptlrpc_req_finished(request);
        list_del_init(&cli->cl_import.imp_chain);
 out_no_disconnect:
        err = class_disconnect(conn);
        if (!rc && err)
                rc = err;
 out_sem:
        up(&cli->cl_sem);
        RETURN(rc);
}
