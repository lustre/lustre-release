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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_RPC

#ifdef __KERNEL__
# include <linux/module.h>
#else
# include <liblustre.h>
#endif
#include <linux/obd.h>
#include <linux/obd_ost.h>
#include <linux/lustre_mgmt.h>
#include <linux/lustre_net.h>
#include <linux/lustre_dlm.h>

int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct ptlrpc_connection *conn;
        struct lustre_cfg* lcfg = buf;
        struct client_obd *cli = &obddev->u.cli;
        struct obd_import *imp;
        struct obd_uuid server_uuid;
        int rq_portal, rp_portal, connect_op;
        char *name = obddev->obd_type->typ_name;
        char *mgmt_name = lcfg->lcfg_inlbuf3;
        int rc;
        struct obd_device *mgmt_obd;
        mgmtcli_register_for_events_t register_f;
        ENTRY;

        /* In a more perfect world, we would hang a ptlrpc_client off of
         * obd_type and just use the values from there. */
        if (!strcmp(name, LUSTRE_OSC_NAME)) {
                rq_portal = OST_REQUEST_PORTAL;
                rp_portal = OSC_REPLY_PORTAL;
                connect_op = OST_CONNECT;
        } else if (!strcmp(name, LUSTRE_MDC_NAME)) {
                rq_portal = MDS_REQUEST_PORTAL;
                rp_portal = MDC_REPLY_PORTAL;
                connect_op = MDS_CONNECT;
        } else if (!strcmp(name, LUSTRE_MGMTCLI_NAME)) {
                rq_portal = MGMT_REQUEST_PORTAL;
                rp_portal = MGMT_REPLY_PORTAL;
                connect_op = MGMT_CONNECT;
        } else {
                CERROR("unknown client OBD type \"%s\", can't setup\n",
                       name);
                RETURN(-EINVAL);
        }

        if (lcfg->lcfg_inllen1 < 1) {
                CERROR("requires a TARGET UUID\n");
                RETURN(-EINVAL);
        }

        if (lcfg->lcfg_inllen1 > 37) {
                CERROR("client UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        if (lcfg->lcfg_inllen2 < 1) {
                CERROR("setup requires a SERVER UUID\n");
                RETURN(-EINVAL);
        }

        if (lcfg->lcfg_inllen2 > 37) {
                CERROR("target UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        sema_init(&cli->cl_sem, 1);
        cli->cl_conn_count = 0;
        memcpy(server_uuid.uuid, lcfg->lcfg_inlbuf2, MIN(lcfg->lcfg_inllen2,
                                                        sizeof(server_uuid)));

        init_MUTEX(&cli->cl_dirty_sem);
        cli->cl_dirty = 0;
        cli->cl_dirty_granted = 0;
        cli->cl_dirty_max = 64*1024*1024; /* some default */
        cli->cl_ost_can_grant = 1;
        INIT_LIST_HEAD(&cli->cl_cache_waiters);
        INIT_LIST_HEAD(&cli->cl_loi_ready_list);
        spin_lock_init(&cli->cl_loi_list_lock);
        cli->cl_brw_in_flight = 0;
        spin_lock_init(&cli->cl_rpc_concurrency_oh.oh_lock);
        spin_lock_init(&cli->cl_pages_per_rpc_oh.oh_lock);
        cli->cl_max_pages_per_rpc = PTL_MD_MAX_PAGES;
        cli->cl_max_rpcs_in_flight = 8;

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
        INIT_LIST_HEAD(&imp->imp_pinger_chain);
        memcpy(imp->imp_target_uuid.uuid, lcfg->lcfg_inlbuf1,
               lcfg->lcfg_inllen1);
        class_import_put(imp);

        cli->cl_import = imp;
        cli->cl_max_mds_easize = sizeof(struct lov_mds_md);
        cli->cl_max_mds_cookiesize = sizeof(struct llog_cookie);
        cli->cl_sandev = to_kdev_t(0);
     
        if (lcfg->lcfg_inllen3 == 0)
                RETURN(0);

        if (!strcmp(lcfg->lcfg_inlbuf3, "inactive")) {
                CDEBUG(D_HA, "marking %s %s->%s as inactive\n",
                       name, obddev->obd_name, imp->imp_target_uuid.uuid);
                imp->imp_invalid = 1;
                
                if (lcfg->lcfg_inllen4 == 0)
                        RETURN(0);
                
                mgmt_name = lcfg->lcfg_inlbuf4;
        } else {
                mgmt_name = lcfg->lcfg_inlbuf3;
        }
        
        /* Register with management client if we need to. */
        CDEBUG(D_HA, "%s registering with %s for events about %s\n",
               obddev->obd_name, mgmt_name, server_uuid.uuid);
        
        mgmt_obd = class_name2obd(mgmt_name);
        if (!mgmt_obd) {
                CERROR("can't find mgmtcli %s to register\n",
                       mgmt_name);
                class_destroy_import(imp);
                RETURN(-ENOENT);
        }
        
        register_f = inter_module_get("mgmtcli_register_for_events");
        if (!register_f) {
                CERROR("can't i_m_g mgmtcli_register_for_events\n");
                class_destroy_import(imp);
                RETURN(-ENOSYS);
        }
        
        rc = register_f(mgmt_obd, obddev, &imp->imp_target_uuid);
        inter_module_put("mgmtcli_register_for_events");
        
        if (!rc)
                cli->cl_mgmtcli_obd = mgmt_obd;
        
        RETURN(rc);
}

int client_obd_cleanup(struct obd_device *obddev, int flags)
{
        struct client_obd *cli = &obddev->u.cli;

        if (!cli->cl_import)
                RETURN(-EINVAL);
        if (cli->cl_mgmtcli_obd) {
                mgmtcli_deregister_for_events_t dereg_f;
                
                dereg_f = inter_module_get("mgmtcli_deregister_for_events");
                dereg_f(cli->cl_mgmtcli_obd, obddev);
                inter_module_put("mgmtcli_deregister_for_events");
        }
        class_destroy_import(cli->cl_import);
        cli->cl_import = NULL;
        RETURN(0);
}
