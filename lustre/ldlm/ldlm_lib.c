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
#define DEBUG_SUBSYSTEM S_LDLM

#ifdef __KERNEL__
# include <linux/module.h>
#else
# include <liblustre.h>
#endif
#include <linux/obd.h>
#include <linux/obd_ost.h> /* for LUSTRE_OSC_NAME */
#include <linux/lustre_mds.h> /* for LUSTRE_MDC_NAME */
#include <linux/lustre_mgmt.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_net.h>
#include <linux/lustre_sec.h>
#include <linux/lustre_gs.h>

/* @priority: if non-zero, move the selected to the list head
 * @nocreate: if non-zero, only search in existed connections
 */
static int import_set_conn(struct obd_import *imp, struct obd_uuid *uuid,
                           int priority, int nocreate)
{
        struct ptlrpc_connection *ptlrpc_conn;
        struct obd_import_conn *imp_conn = NULL, *item;
        int rc = 0;
        ENTRY;

        LASSERT(!(nocreate && !priority));

        ptlrpc_conn = ptlrpc_uuid_to_connection(uuid);
        if (!ptlrpc_conn) {
                CERROR("can't find connection %s\n", uuid->uuid);
                RETURN (-EINVAL);
        }

        if (!nocreate) {
                OBD_ALLOC(imp_conn, sizeof(*imp_conn));
                if (!imp_conn) {
                        CERROR("fail to alloc memory\n");
                        GOTO(out_put, rc = -ENOMEM);
                }
        }

        spin_lock(&imp->imp_lock);
        list_for_each_entry(item, &imp->imp_conn_list, oic_item) {
                if (obd_uuid_equals(uuid, &item->oic_uuid)) {
                        if (priority) {
                                list_del(&item->oic_item);
                                list_add(&item->oic_item, &imp->imp_conn_list);
                                item->oic_last_attempt = 0;
                        }
                        CDEBUG(D_HA, "imp %p@%s: find existed conn %s%s\n",
                               imp, imp->imp_obd->obd_name, uuid->uuid,
                               (priority ? ", move to head." : ""));
                        spin_unlock(&imp->imp_lock);
                        GOTO(out_free, rc = 0);
                }
        }
        /* not found */
        if (!nocreate) {
                imp_conn->oic_conn = ptlrpc_conn;
                imp_conn->oic_uuid = *uuid;
                imp_conn->oic_last_attempt = 0;
                if (priority)
                        list_add(&imp_conn->oic_item, &imp->imp_conn_list);
                else
                        list_add_tail(&imp_conn->oic_item, &imp->imp_conn_list);
                CDEBUG(D_HA, "imp %p@%s: add connection %s at %s\n",
                       imp, imp->imp_obd->obd_name, uuid->uuid,
                       (priority ? "head" : "tail"));
        } else
                rc = -ENOENT;

        spin_unlock(&imp->imp_lock);
        RETURN(0);
out_free:
        if (imp_conn)
                OBD_FREE(imp_conn, sizeof(*imp_conn));
out_put:
        ptlrpc_put_connection(ptlrpc_conn);
        RETURN(rc);
}

int import_set_conn_priority(struct obd_import *imp, struct obd_uuid *uuid)
{
        return import_set_conn(imp, uuid, 1, 1);
}

int client_import_add_conn(struct obd_import *imp, struct obd_uuid *uuid,
                           int priority)
{
        return import_set_conn(imp, uuid, priority, 0);
}

int client_import_del_conn(struct obd_import *imp, struct obd_uuid *uuid)
{
        struct obd_import_conn *imp_conn;
        struct obd_export *dlmexp;
        int rc = -ENOENT;
        ENTRY;

        spin_lock(&imp->imp_lock);
        if (list_empty(&imp->imp_conn_list)) {
                LASSERT(!imp->imp_conn_current);
                LASSERT(!imp->imp_connection);
                GOTO(out, rc);
        }

        list_for_each_entry(imp_conn, &imp->imp_conn_list, oic_item) {
                if (!obd_uuid_equals(uuid, &imp_conn->oic_uuid))
                        continue;
                LASSERT(imp_conn->oic_conn);

                /* is current conn? */
                if (imp_conn == imp->imp_conn_current) {
                        LASSERT(imp_conn->oic_conn == imp->imp_connection);

                        if (imp->imp_state != LUSTRE_IMP_CLOSED &&
                            imp->imp_state != LUSTRE_IMP_DISCON) {
                                CERROR("can't remove current connection\n");
                                GOTO(out, rc = -EBUSY);
                        }

                        ptlrpc_put_connection(imp->imp_connection);
                        imp->imp_connection = NULL;

                        dlmexp = class_conn2export(&imp->imp_dlm_handle);
                        if (dlmexp && dlmexp->exp_connection) {
                                LASSERT(dlmexp->exp_connection ==
                                        imp_conn->oic_conn);
                                ptlrpc_put_connection(dlmexp->exp_connection);
                                dlmexp->exp_connection = NULL;
                        }
                }

                list_del(&imp_conn->oic_item);
                ptlrpc_put_connection(imp_conn->oic_conn);
                OBD_FREE(imp_conn, sizeof(*imp_conn));
                CDEBUG(D_HA, "imp %p@%s: remove connection %s\n",
                       imp, imp->imp_obd->obd_name, uuid->uuid);
                rc = 0;
                break;
        }
out:
        spin_unlock(&imp->imp_lock);
        if (rc == -ENOENT)
                CERROR("connection %s not found\n", uuid->uuid);
        RETURN(rc);
}

int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct lustre_cfg* lcfg = buf;
        struct client_obd *cli = &obddev->u.cli;
        struct obd_import *imp;
        struct obd_uuid server_uuid;
        int rq_portal, rp_portal, connect_op;
        char *name = obddev->obd_type->typ_name;
        char *mgmt_name = NULL;
        int rc;
        ENTRY;

        /* In a more perfect world, we would hang a ptlrpc_client off of
         * obd_type and just use the values from there. */
        if (!strcmp(name, OBD_OSC_DEVICENAME)) {
                rq_portal = OST_REQUEST_PORTAL;
                rp_portal = OSC_REPLY_PORTAL;
                connect_op = OST_CONNECT;
        } else if (!strcmp(name, OBD_MDC_DEVICENAME)) {
                rq_portal = MDS_REQUEST_PORTAL;
                rp_portal = MDC_REPLY_PORTAL;
                connect_op = MDS_CONNECT;
        } else if (!strcmp(name, OBD_MGMTCLI_DEVICENAME)) {
                rq_portal = MGMT_REQUEST_PORTAL;
                rp_portal = MGMT_REPLY_PORTAL;
                connect_op = MGMT_CONNECT;
        } else if (!strcmp(name, LUSTRE_GKC_NAME)) {
                rq_portal = GKS_REQUEST_PORTAL;
                rp_portal = GKC_REPLY_PORTAL;
                connect_op = GKS_CONNECT;

        } else {
                CERROR("unknown client OBD type \"%s\", can't setup\n",
                       name);
                RETURN(-EINVAL);
        }


        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
                CERROR("requires a TARGET UUID\n");
                RETURN(-EINVAL);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) > 37) {
                CERROR("client UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 2) < 1) {
                CERROR("setup requires a SERVER UUID\n");
                RETURN(-EINVAL);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 2) > 37) {
                CERROR("target UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        sema_init(&cli->cl_sem, 1);
        cli->cl_conn_count = 0;
        memcpy(server_uuid.uuid,  lustre_cfg_buf(lcfg, 2),
               min_t(unsigned int, LUSTRE_CFG_BUFLEN(lcfg, 2), 
               sizeof(server_uuid)));

        cli->cl_dirty = 0;
        cli->cl_avail_grant = 0;
        /* FIXME: should limit this for the sum of all cl_dirty_max */
        cli->cl_dirty_max = OSC_MAX_DIRTY_DEFAULT * 1024 * 1024;
        if (cli->cl_dirty_max >> PAGE_SHIFT > num_physpages / 8)
                cli->cl_dirty_max = num_physpages << (PAGE_SHIFT - 3);
        INIT_LIST_HEAD(&cli->cl_cache_waiters);
        INIT_LIST_HEAD(&cli->cl_loi_ready_list);
        INIT_LIST_HEAD(&cli->cl_loi_write_list);
        INIT_LIST_HEAD(&cli->cl_loi_read_list);
        spin_lock_init(&cli->cl_loi_list_lock);
        cli->cl_r_in_flight = 0;
        cli->cl_w_in_flight = 0;
        spin_lock_init(&cli->cl_read_rpc_hist.oh_lock);
        spin_lock_init(&cli->cl_write_rpc_hist.oh_lock);
        spin_lock_init(&cli->cl_read_page_hist.oh_lock);
        spin_lock_init(&cli->cl_write_page_hist.oh_lock);

        if (num_physpages >> (20 - PAGE_SHIFT) <= 128) { /* <= 128 MB */
                cli->cl_max_pages_per_rpc = PTLRPC_MAX_BRW_PAGES / 4;
                cli->cl_max_rpcs_in_flight = OSC_MAX_RIF_DEFAULT / 4;
#if 0
        } else if (num_physpages >> (20 - PAGE_SHIFT) <= 512) { /* <= 512 MB */
                cli->cl_max_pages_per_rpc = PTLRPC_MAX_BRW_PAGES / 2;
                cli->cl_max_rpcs_in_flight = OSC_MAX_RIF_DEFAULT / 2;
#endif
        } else {
                cli->cl_max_pages_per_rpc = PTLRPC_MAX_BRW_PAGES;
                cli->cl_max_rpcs_in_flight = OSC_MAX_RIF_DEFAULT;
        }

        rc = ldlm_get_ref();
        if (rc) {
                CERROR("ldlm_get_ref failed: %d\n", rc);
                GOTO(err, rc);
        }

        ptlrpc_init_client(rq_portal, rp_portal, name,
                           &obddev->obd_ldlm_client);

        imp = class_new_import();
        if (imp == NULL) 
                GOTO(err_ldlm, rc = -ENOENT);
        imp->imp_client = &obddev->obd_ldlm_client;
        imp->imp_obd = obddev;
        imp->imp_connect_op = connect_op;
        imp->imp_generation = 0;
        imp->imp_initial_recov = 1;
        INIT_LIST_HEAD(&imp->imp_pinger_chain);
        memcpy(imp->imp_target_uuid.uuid, lustre_cfg_buf(lcfg, 1),
               LUSTRE_CFG_BUFLEN(lcfg, 1));
        class_import_put(imp);

        rc = client_import_add_conn(imp, &server_uuid, 1);
        if (rc) {
                CERROR("can't add initial connection\n");
                GOTO(err_import, rc);
        }

        cli->cl_import = imp;
        cli->cl_max_mds_easize = sizeof(struct lov_mds_md);
        cli->cl_max_mds_cookiesize = sizeof(struct llog_cookie);
        cli->cl_sandev = to_kdev_t(0);

        if (LUSTRE_CFG_BUFLEN(lcfg, 3) > 0) {
                if (!strcmp(lustre_cfg_string(lcfg, 3), "inactive")) {
                        CDEBUG(D_HA, "marking %s %s->%s as inactive\n",
                               name, obddev->obd_name,
                               imp->imp_target_uuid.uuid);
                        imp->imp_invalid = 1;

                        if (LUSTRE_CFG_BUFLEN(lcfg, 4) > 0)
                                mgmt_name = lustre_cfg_string(lcfg, 4);
                } else {
                        mgmt_name = lustre_cfg_string(lcfg, 3);
                }
        }
#if 0
        if (mgmt_name != NULL) {
                /* Register with management client if we need to. */
                CDEBUG(D_HA, "%s registering with %s for events about %s\n",
                       obddev->obd_name, mgmt_name, server_uuid.uuid);

                mgmt_obd = class_name2obd(mgmt_name);
                if (!mgmt_obd) {
                        CERROR("can't find mgmtcli %s to register\n",
                               mgmt_name);
                        GOTO(err_import, rc = -ENOSYS);
                }

                register_f = (mgmtcli_register_for_events_t)symbol_get("mgmtcli_register_for_events");
                if (!register_f) {
                        CERROR("can't i_m_g mgmtcli_register_for_events\n");
                        GOTO(err_import, rc = -ENOSYS);
                }

                rc = register_f(mgmt_obd, obddev, &imp->imp_target_uuid);
                symbol_put("mgmtcli_register_for_events");

                if (!rc)
                        cli->cl_mgmtcli_obd = mgmt_obd;
        }
#endif
        RETURN(rc);

err_import:
        class_destroy_import(imp);
err_ldlm:
        ldlm_put_ref(0);
err:
        RETURN(rc);

}

int client_obd_cleanup(struct obd_device *obddev, int flags)
{
        struct client_obd *cli = &obddev->u.cli;
        ENTRY;

        if (!cli->cl_import)
                RETURN(-EINVAL);
        if (cli->cl_mgmtcli_obd) {
                mgmtcli_deregister_for_events_t dereg_f;

                dereg_f = (mgmtcli_deregister_for_events_t)symbol_get("mgmtcli_deregister_for_events");
                dereg_f(cli->cl_mgmtcli_obd, obddev);
                symbol_put("mgmtcli_deregister_for_events");
        }

        /* Here we try to drop the security structure after destroy import,
         * to avoid issue of "sleep in spinlock".
         */
        class_import_get(cli->cl_import);
        class_destroy_import(cli->cl_import);
        ptlrpcs_import_drop_sec(cli->cl_import);
        class_import_put(cli->cl_import);
        cli->cl_import = NULL;

        ldlm_put_ref(flags & OBD_OPT_FORCE);

        RETURN(0);
}

int client_connect_import(struct lustre_handle *dlm_handle,
                          struct obd_device *obd,
                          struct obd_uuid *cluuid,
                          struct obd_connect_data *conn_data,
                          unsigned long connect_flags)
{
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
        struct obd_export *exp;
        int rc;
        ENTRY;

        down(&cli->cl_sem);
        rc = class_connect(dlm_handle, obd, cluuid);
        if (rc)
                GOTO(out_sem, rc);

        cli->cl_conn_count++;
        if (cli->cl_conn_count > 1)
                GOTO(out_sem, rc);
        exp = class_conn2export(dlm_handle);

        if (obd->obd_namespace != NULL)
                CERROR("already have namespace!\n");
        obd->obd_namespace = ldlm_namespace_new(obd->obd_name,
                                                LDLM_NAMESPACE_CLIENT);
        if (obd->obd_namespace == NULL)
                GOTO(out_disco, rc = -ENOMEM);

        rc = ptlrpcs_import_get_sec(imp);
        if (rc != 0)
                GOTO(out_ldlm, rc);

        imp->imp_dlm_handle = *dlm_handle;
        rc = ptlrpc_init_import(imp);
        if (rc != 0) 
                GOTO(out_ldlm, rc);

        imp->imp_connect_flags = connect_flags;
        if (conn_data)
                memcpy(&imp->imp_connect_data, conn_data, sizeof(*conn_data));

        rc = ptlrpc_connect_import(imp, NULL);
        if (rc != 0) {
                LASSERT (imp->imp_state == LUSTRE_IMP_DISCON);
                GOTO(out_ldlm, rc);
        }
        LASSERT(exp->exp_connection);
        ptlrpc_pinger_add_import(imp);
        EXIT;

        if (rc) {
out_ldlm:
                ldlm_namespace_free(obd->obd_namespace, 0);
                obd->obd_namespace = NULL;
out_disco:
                cli->cl_conn_count--;
                class_disconnect(exp, 0);
        } else {
                class_export_put(exp);
        }
out_sem:
        up(&cli->cl_sem);
        return rc;
}

int client_disconnect_export(struct obd_export *exp, unsigned long flags)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
        int rc = 0, err;
        ENTRY;

        if (!obd) {
                CERROR("invalid export for disconnect: exp %p cookie "LPX64"\n",
                       exp, exp ? exp->exp_handle.h_cookie : -1);
                RETURN(-EINVAL);
        }

        down(&cli->cl_sem);
        if (!cli->cl_conn_count) {
                CERROR("disconnecting disconnected device (%s)\n",
                       obd->obd_name);
                GOTO(out_sem, rc = -EINVAL);
        }

        cli->cl_conn_count--;
        if (cli->cl_conn_count)
                GOTO(out_no_disconnect, rc = 0);

        /* Some non-replayable imports (MDS's OSCs) are pinged, so just
         * delete it regardless.  (It's safe to delete an import that was
         * never added.) */
        (void)ptlrpc_pinger_del_import(imp);

        if (obd->obd_namespace != NULL) {
                /* obd_no_recov == local only */
                ldlm_cli_cancel_unused(obd->obd_namespace, NULL,
                                       obd->obd_no_recov, NULL);
                ldlm_namespace_free(obd->obd_namespace, obd->obd_no_recov);
                obd->obd_namespace = NULL;
        }

        /* 
         * Yeah, obd_no_recov also (mainly) means "forced shutdown".
         */
        if (obd->obd_no_recov)
                ptlrpc_invalidate_import(imp, 0);
        else
                rc = ptlrpc_disconnect_import(imp);

        EXIT;
 out_no_disconnect:
        err = class_disconnect(exp, 0);
        if (!rc && err)
                rc = err;
 out_sem:
        up(&cli->cl_sem);
        RETURN(rc);
}

/* --------------------------------------------------------------------------
 * from old lib/target.c
 * -------------------------------------------------------------------------- */

int target_handle_reconnect(struct lustre_handle *conn, struct obd_export *exp,
                            struct obd_uuid *cluuid, int initial_conn)
{
        if (exp->exp_connection && !initial_conn) {
                struct lustre_handle *hdl;
                hdl = &exp->exp_imp_reverse->imp_remote_handle;
                /* Might be a re-connect after a partition. */
                if (!memcmp(&conn->cookie, &hdl->cookie, sizeof conn->cookie)) {
                        CERROR("%s reconnecting\n", cluuid->uuid);
                        conn->cookie = exp->exp_handle.h_cookie;
                        RETURN(EALREADY);
                } else {
                        CERROR("%s reconnecting from %s, "
                               "handle mismatch (ours "LPX64", theirs "
                               LPX64")\n", cluuid->uuid,
                               exp->exp_connection->c_remote_uuid.uuid,
                               hdl->cookie, conn->cookie);
                        memset(conn, 0, sizeof *conn);
                        RETURN(-EALREADY);
                }
        }

        conn->cookie = exp->exp_handle.h_cookie;
        CDEBUG(D_INFO, "existing export for UUID '%s' at %p\n",
               cluuid->uuid, exp);
        CDEBUG(D_IOCTL,"connect: cookie "LPX64"\n", conn->cookie);
        RETURN(0);
}

static inline int ptlrpc_peer_is_local(struct ptlrpc_peer *peer)
{
        ptl_process_id_t myid;

        PtlGetId(peer->peer_ni->pni_ni_h, &myid);
        return (memcmp(&peer->peer_id, &myid, sizeof(myid)) == 0);
}

/* To check whether the p_flavor is in deny list or not
 * rc:
 *      0           not found, pass
 *      EPERM       found, refuse
 */

static int check_deny_list(struct list_head *head, __u32 flavor)
{
        deny_sec_t *p_deny_sec = NULL;
        deny_sec_t *n_deny_sec = NULL;

        list_for_each_entry_safe(p_deny_sec, n_deny_sec, head, list) {
                if (p_deny_sec->flavor == flavor)
                        return -EPERM;
        }
        return 0;
}

int target_check_deny_sec(struct obd_device *target, struct ptlrpc_request *req)
{
        __u32 flavor;
        int rc = 0;

        flavor = req->rq_req_secflvr;

        if (!strcmp(target->obd_type->typ_name, OBD_MDS_DEVICENAME)) {
                spin_lock(&target->u.mds.mds_denylist_lock);
                rc = check_deny_list(&target->u.mds.mds_denylist, flavor);
                spin_unlock(&target->u.mds.mds_denylist_lock);
        } else if (!strcmp(target->obd_type->typ_name, "obdfilter")) {
                spin_lock(&target->u.filter.fo_denylist_lock);
                rc = check_deny_list(&target->u.filter.fo_denylist, flavor);
                spin_unlock(&target->u.filter.fo_denylist_lock);
        }

        return rc;
}

int target_handle_connect(struct ptlrpc_request *req)
{
        unsigned long connect_flags = 0, *cfp;
        struct obd_device *target;
        struct obd_export *export = NULL;
        struct obd_import *revimp;
        struct lustre_handle conn;
        struct obd_uuid tgtuuid;
        struct obd_uuid cluuid;
        struct obd_uuid remote_uuid;
        struct list_head *p;
        struct obd_connect_data *conn_data;
        int conn_data_size = sizeof(*conn_data);
        char *str, *tmp;
        int rc = 0;
        unsigned long flags;
        int initial_conn = 0;
        char peer_str[PTL_NALFMT_SIZE];
        const int offset = 1;
        ENTRY;

        OBD_RACE(OBD_FAIL_TGT_CONN_RACE); 

        LASSERT_REQSWAB (req, offset + 0);
        str = lustre_msg_string(req->rq_reqmsg, offset + 0,
                                sizeof(tgtuuid) - 1);
        if (str == NULL) {
                CERROR("bad target UUID for connect\n");
                GOTO(out, rc = -EINVAL);
        }

        obd_str2uuid (&tgtuuid, str);
        target = class_uuid2obd(&tgtuuid);
        if (!target)
                target = class_name2obd(str);
        
        if (!target || target->obd_stopping || !target->obd_set_up) {
                CERROR("UUID '%s' is not available for connect from %s\n",
                       str, req->rq_peerstr);
                GOTO(out, rc = -ENODEV);
        }

        /* check the secure deny list of mds/ost */
        rc = target_check_deny_sec(target, req);
        if (rc != 0)
                GOTO(out, rc);

        LASSERT_REQSWAB (req, offset + 1);
        str = lustre_msg_string(req->rq_reqmsg, offset + 1, sizeof(cluuid) - 1);
        if (str == NULL) {
                CERROR("bad client UUID for connect\n");
                GOTO(out, rc = -EINVAL);
        }

        obd_str2uuid (&cluuid, str);

        /* XXX extract a nettype and format accordingly */
        switch (sizeof(ptl_nid_t)) {
                /* NB the casts only avoid compiler warnings */
        case 8:
                snprintf((char *)remote_uuid.uuid, sizeof(remote_uuid),
                         "NET_"LPX64"_UUID", (__u64)req->rq_peer.peer_id.nid);
                break;
        case 4:
                snprintf((char *)remote_uuid.uuid, sizeof(remote_uuid),
                         "NET_%x_UUID", (__u32)req->rq_peer.peer_id.nid);
                break;
        default:
                LBUG();
        }

        tmp = lustre_msg_buf(req->rq_reqmsg, offset + 2, sizeof(conn));
        if (tmp == NULL)
                GOTO(out, rc = -EPROTO);

        memcpy(&conn, tmp, sizeof conn);

        cfp = lustre_msg_buf(req->rq_reqmsg, offset + 3, sizeof(unsigned long));
        LASSERT(cfp != NULL);
        connect_flags = *cfp;

        conn_data = lustre_swab_reqbuf(req, offset + 4, sizeof(*conn_data),
                                       lustre_swab_connect);
        if (!conn_data)
                GOTO(out, rc = -EPROTO);

        rc = lustre_pack_reply(req, 1, &conn_data_size, NULL);
        if (rc)
                GOTO(out, rc);
        
        if (lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_INITIAL)
                initial_conn = 1;
        
        /* lctl gets a backstage, all-access pass. */
        if (obd_uuid_equals(&cluuid, &target->obd_uuid))
                goto dont_check_exports;

        spin_lock(&target->obd_dev_lock);
        list_for_each(p, &target->obd_exports) {
                export = list_entry(p, struct obd_export, exp_obd_chain);
                if (obd_uuid_equals(&cluuid, &export->exp_client_uuid)) {
                        spin_unlock(&target->obd_dev_lock);
                        LASSERT(export->exp_obd == target);

                        rc = target_handle_reconnect(&conn, export, &cluuid,
                                                     initial_conn);
                        break;
                }
                export = NULL;
        }
        /* If we found an export, we already unlocked. */
        if (!export) {
                spin_unlock(&target->obd_dev_lock);
        } else if (req->rq_export == NULL && 
                   atomic_read(&export->exp_rpc_count) > 0) {
                CWARN("%s: refuse connection from %s/%s to 0x%p/%d\n",
                      target->obd_name, cluuid.uuid,
                      ptlrpc_peernid2str(&req->rq_peer, peer_str),
                      export, atomic_read(&export->exp_refcount));
                GOTO(out, rc = -EBUSY);
        } else if (req->rq_export != NULL &&
                   atomic_read(&export->exp_rpc_count) > 1) {
                CWARN("%s: refuse reconnection from %s@%s to 0x%p/%d\n",
                      target->obd_name, cluuid.uuid,
                      ptlrpc_peernid2str(&req->rq_peer, peer_str),
                      export, atomic_read(&export->exp_rpc_count));
                GOTO(out, rc = -EBUSY);
        } else if (req->rq_reqmsg->conn_cnt == 1 && !initial_conn) {
                CERROR("%s reconnected with 1 conn_cnt; cookies not random?\n",
                       cluuid.uuid);
                GOTO(out, rc = -EALREADY);
        }

        /* Tell the client if we're in recovery. */
        /* If this is the first client, start the recovery timer */
        CWARN("%s: connection from %s@%s/%lu %st"LPU64"\n", target->obd_name,
              cluuid.uuid, ptlrpc_peernid2str(&req->rq_peer, peer_str), *cfp,
              target->obd_recovering ? "recovering/" : "", conn_data->transno);

        if (target->obd_recovering) {
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECOVERING);
                target_start_recovery_timer(target);
        }

#if 0
        /* Tell the client if we support replayable requests */
        if (target->obd_replayable)
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_REPLAYABLE);
#endif

        if (export == NULL) {
                if (target->obd_recovering) {
                        CERROR("%s denying connection for new client %s@%s: "
                               "%d clients in recovery for %lds\n", target->obd_name, 
                               cluuid.uuid,
                               ptlrpc_peernid2str(&req->rq_peer, peer_str),
                               target->obd_recoverable_clients,
                               (target->obd_recovery_timer.expires-jiffies)/HZ);
                        rc = -EBUSY;
                } else {
 dont_check_exports:
                        rc = obd_connect(&conn, target, &cluuid, conn_data,
                                         connect_flags);
                }
        }

        /* Return only the parts of obd_connect_data that we understand, so the
         * client knows that we don't understand the rest. */
        conn_data->ocd_connect_flags &= OBD_CONNECT_SUPPORTED;
        memcpy(lustre_msg_buf(req->rq_repmsg, 0, sizeof(*conn_data)), conn_data,
               sizeof(*conn_data));

        /* Tell the client if we support replayable requests */
        if (target->obd_replayable)
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_REPLAYABLE);

        /* If all else goes well, this is our RPC return code. */
        req->rq_status = 0;

        if (rc && rc != EALREADY)
                GOTO(out, rc);

        req->rq_repmsg->handle = conn;

        /* If the client and the server are the same node, we will already
         * have an export that really points to the client's DLM export,
         * because we have a shared handles table.
         *
         * XXX this will go away when shaver stops sending the "connect" handle
         * in the real "remote handle" field of the request --phik 24 Apr 2003
         */
        if (req->rq_export != NULL)
                class_export_put(req->rq_export);

        /* ownership of this export ref transfers to the request */
        export = req->rq_export = class_conn2export(&conn);
        LASSERT(export != NULL);

        spin_lock_irqsave(&export->exp_lock, flags);
        if (initial_conn) {
                req->rq_repmsg->conn_cnt = export->exp_conn_cnt + 1;
        } else if (export->exp_conn_cnt >= req->rq_reqmsg->conn_cnt) {
                CERROR("%s@%s: already connected at a higher conn_cnt: %d > %d\n",
                       cluuid.uuid, ptlrpc_peernid2str(&req->rq_peer, peer_str),
                       export->exp_conn_cnt, 
                       req->rq_reqmsg->conn_cnt);
                spin_unlock_irqrestore(&export->exp_lock, flags);
                GOTO(out, rc = -EALREADY);
        } 
        export->exp_conn_cnt = req->rq_reqmsg->conn_cnt;
        spin_unlock_irqrestore(&export->exp_lock, flags);

        /* request from liblustre? */
        if (lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_LIBCLIENT)
                export->exp_libclient = 1;

        if (!(lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_ASYNC) &&
            ptlrpc_peer_is_local(&req->rq_peer)) {
                CWARN("%s: exp %p set sync\n", target->obd_name, export);
                export->exp_sync = 1;
        } else {
                CDEBUG(D_HA, "%s: exp %p set async\n",target->obd_name,export);
                export->exp_sync = 0;
        }

        if (export->exp_connection != NULL)
                ptlrpc_put_connection(export->exp_connection);
        export->exp_connection = ptlrpc_get_connection(&req->rq_peer,
                                                       &remote_uuid);

        if (rc == EALREADY) {
                /* We indicate the reconnection in a flag, not an error code. */
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECONNECT);
                GOTO(out, rc = 0);
        }

        spin_lock_bh(&target->obd_processing_task_lock);
        if (target->obd_recovering && export->exp_connected == 0) {
                __u64 t = conn_data->transno;
                export->exp_connected = 1;
                if ((lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_TRANSNO)
                                && t < target->obd_next_recovery_transno)
                        target->obd_next_recovery_transno = t;
                target->obd_connected_clients++;
                if (target->obd_connected_clients == target->obd_max_recoverable_clients)
                        wake_up(&target->obd_next_transno_waitq);
        }
        spin_unlock_bh(&target->obd_processing_task_lock);

        memcpy(&conn, lustre_msg_buf(req->rq_reqmsg, offset + 2, sizeof(conn)),
               sizeof(conn));

        if (export->exp_imp_reverse != NULL) {
                /* same logic as client_obd_cleanup */
                class_import_get(export->exp_imp_reverse);
                class_destroy_import(export->exp_imp_reverse);
                ptlrpcs_import_drop_sec(export->exp_imp_reverse);
                class_import_put(export->exp_imp_reverse);
        }

        /* for the rest part, we return -ENOTCONN in case of errors
         * in order to let client initialize connection again.
         */
        revimp = export->exp_imp_reverse = class_new_import();
        if (!revimp) {
                CERROR("fail to alloc new reverse import.\n");
                GOTO(out, rc = -ENOTCONN);
        }

        revimp->imp_connection = ptlrpc_connection_addref(export->exp_connection);
        revimp->imp_client = &export->exp_obd->obd_ldlm_client;
        revimp->imp_remote_handle = conn;
        revimp->imp_obd = target;
        revimp->imp_dlm_fake = 1;
        revimp->imp_state = LUSTRE_IMP_FULL;

        rc = ptlrpcs_import_get_sec(revimp);
        if (rc) {
                CERROR("reverse import can not get sec: %d\n", rc);
                class_destroy_import(revimp);
                export->exp_imp_reverse = NULL;
                GOTO(out, rc = -ENOTCONN);
        }

        class_import_put(revimp);

        rc = obd_connect_post(export, initial_conn, connect_flags);
out:
        if (rc)
                req->rq_status = rc;
        RETURN(rc);
}

int target_handle_disconnect(struct ptlrpc_request *req)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        rc = lustre_pack_reply(req, 0, NULL, NULL);
        if (rc)
                RETURN(rc);

        /* keep the rq_export around so we can send the reply */
        exp = class_export_get(req->rq_export);
        req->rq_status = obd_disconnect(exp, 0);
        RETURN(0);
}

void target_destroy_export(struct obd_export *exp)
{
        /* exports created from last_rcvd data, and "fake"
           exports created by lctl don't have an import */
        if (exp->exp_imp_reverse != NULL) {
                ptlrpcs_import_drop_sec(exp->exp_imp_reverse);
                class_destroy_import(exp->exp_imp_reverse);
        }

        /* We cancel locks at disconnect time, but this will catch any locks
         * granted in a race with recovery-induced disconnect. */
        if (exp->exp_obd->obd_namespace != NULL)
                ldlm_cancel_locks_for_export(exp);
}

/*
 * Recovery functions
 */

struct ptlrpc_request *
ptlrpc_clone_req( struct ptlrpc_request *orig_req) 
{
        struct ptlrpc_request *copy_req;
        struct lustre_msg *copy_reqmsg;

        OBD_ALLOC(copy_req, sizeof *copy_req);
        if (!copy_req)
                return NULL;
        OBD_ALLOC(copy_reqmsg, orig_req->rq_reqlen);
        if (!copy_reqmsg){
                OBD_FREE(copy_req, sizeof *copy_req);
                return NULL;
        }

        memcpy(copy_req, orig_req, sizeof *copy_req);
        memcpy(copy_reqmsg, orig_req->rq_reqmsg, orig_req->rq_reqlen);
        /* the copied req takes over the reply state and security data */
        orig_req->rq_reply_state = NULL;
        orig_req->rq_svcsec_data = NULL;

        copy_req->rq_reqmsg = copy_reqmsg;
        class_export_get(copy_req->rq_export);
        INIT_LIST_HEAD(&copy_req->rq_list);

        return copy_req;
}

void ptlrpc_free_clone( struct ptlrpc_request *req) 
{
        if (req->rq_svcsec)
                svcsec_cleanup_req(req);

        class_export_put(req->rq_export);
        list_del(&req->rq_list);
        OBD_FREE(req->rq_reqmsg, req->rq_reqlen);
        OBD_FREE(req, sizeof *req);
}

static void target_release_saved_req(struct ptlrpc_request *req)
{
        if (req->rq_svcsec)
                svcsec_cleanup_req(req);

        class_export_put(req->rq_export);
        OBD_FREE(req->rq_reqmsg, req->rq_reqlen);
        OBD_FREE(req, sizeof *req);
}

static void target_finish_recovery(struct obd_device *obd)
{
        int rc;

        ldlm_reprocess_all_ns(obd->obd_namespace);

        /* when recovery finished, cleanup orphans on mds and ost */
        if (OBT(obd) && OBP(obd, postrecov)) {
                rc = OBP(obd, postrecov)(obd);
                if (rc >= 0)
                        CWARN("%s: all clients recovered, %d MDS "
                              "orphans deleted\n", obd->obd_name, rc);
                else
                        CERROR("postrecov failed %d\n", rc);
        }

        obd->obd_recovery_end = LTIME_S(CURRENT_TIME);
        return;
}

static void abort_req_replay_queue(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        struct list_head *tmp, *n;
        int rc;

        list_for_each_safe(tmp, n, &obd->obd_req_replay_queue) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                list_del(&req->rq_list);
                DEBUG_REQ(D_ERROR, req, "aborted:");
                req->rq_status = -ENOTCONN;
                req->rq_type = PTL_RPC_MSG_ERR;
                rc = lustre_pack_reply(req, 0, NULL, NULL);
                if (rc == 0) {
                        ptlrpc_reply(req);
                } else {
                        DEBUG_REQ(D_ERROR, req,
                                  "packing failed for abort-reply; skipping");
                }
                target_release_saved_req(req);
        }
}

static void abort_lock_replay_queue(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        struct list_head *tmp, *n;
        int rc;

        list_for_each_safe(tmp, n, &obd->obd_lock_replay_queue) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                list_del(&req->rq_list);
                DEBUG_REQ(D_ERROR, req, "aborted:");
                req->rq_status = -ENOTCONN;
                req->rq_type = PTL_RPC_MSG_ERR;
                rc = lustre_pack_reply(req, 0, NULL, NULL);
                if (rc == 0) {
                        ptlrpc_reply(req);
                } else {
                        DEBUG_REQ(D_ERROR, req,
                                  "packing failed for abort-reply; skipping");
                }
                target_release_saved_req(req);
        }
}

/* Called from a cleanup function if the device is being cleaned up
   forcefully.  The exports should all have been disconnected already,
   the only thing left to do is
     - clear the recovery flags
     - cancel the timer
     - free queued requests and replies, but don't send replies
   Because the obd_stopping flag is set, no new requests should be received.

*/
void target_cleanup_recovery(struct obd_device *obd)
{
        struct list_head *tmp, *n;
        struct ptlrpc_request *req;

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!obd->obd_recovering) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                EXIT;
                return;
        }
        obd->obd_recovering = obd->obd_abort_recovery = 0;
        target_cancel_recovery_timer(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        list_for_each_safe(tmp, n, &obd->obd_req_replay_queue) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                list_del(&req->rq_list);
                LASSERT (req->rq_reply_state == 0);
                target_release_saved_req(req);
        }
        list_for_each_safe(tmp, n, &obd->obd_lock_replay_queue) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                list_del(&req->rq_list);
                LASSERT (req->rq_reply_state == 0);
                target_release_saved_req(req);
        }
        list_for_each_safe(tmp, n, &obd->obd_final_req_queue) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                list_del(&req->rq_list);
                LASSERT (req->rq_reply_state == 0);
                target_release_saved_req(req);
        }
}

#if 0
static void target_abort_recovery(void *data)
{
        struct obd_device *obd = data;

        LASSERT(!obd->obd_recovering);

        class_disconnect_stale_exports(obd, 0);

        CERROR("%s: recovery period over; disconnecting unfinished clients.\n",
               obd->obd_name);

        abort_recovery_queue(obd);
        target_finish_recovery(obd);
        ptlrpc_run_recovery_over_upcall(obd);
}
#endif

static void target_recovery_expired(unsigned long castmeharder)
{
        struct obd_device *obd = (struct obd_device *)castmeharder;
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovering)
                obd->obd_abort_recovery = 1;

        wake_up(&obd->obd_next_transno_waitq);
        spin_unlock_bh(&obd->obd_processing_task_lock);
}


/* obd_processing_task_lock should be held */
void target_cancel_recovery_timer(struct obd_device *obd)
{
        CDEBUG(D_HA, "%s: cancel recovery timer\n", obd->obd_name);
        del_timer(&obd->obd_recovery_timer);
}

#ifdef __KERNEL__
static void reset_recovery_timer(struct obd_device *obd)
{
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!obd->obd_recovering) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return;
        }                
        CDEBUG(D_HA, "timer will expire in %u seconds\n",
               OBD_RECOVERY_TIMEOUT / HZ);
        mod_timer(&obd->obd_recovery_timer, jiffies + OBD_RECOVERY_TIMEOUT);
        spin_unlock_bh(&obd->obd_processing_task_lock);
}
#endif

/* Only start it the first time called */
void target_start_recovery_timer(struct obd_device *obd)
{
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!obd->obd_recovering || timer_pending(&obd->obd_recovery_timer)) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return;
        }
        CWARN("%s: starting recovery timer (%us)\n", obd->obd_name,
               OBD_RECOVERY_TIMEOUT / HZ);
        obd->obd_recovery_timer.function = target_recovery_expired;
        obd->obd_recovery_timer.data = (unsigned long)obd;
        mod_timer(&obd->obd_recovery_timer, jiffies + OBD_RECOVERY_TIMEOUT);
        spin_unlock_bh(&obd->obd_processing_task_lock);
}

#ifdef __KERNEL__
static int check_for_next_transno(struct obd_device *obd)
{
        struct ptlrpc_request *req = NULL;
        int wake_up = 0, connected, completed, queue_len, max;
        __u64 next_transno, req_transno;

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!list_empty(&obd->obd_req_replay_queue)) {
                req = list_entry(obd->obd_req_replay_queue.next,
                                 struct ptlrpc_request, rq_list);
                req_transno = req->rq_reqmsg->transno;
        } else {
                req_transno = 0;
        }

        max = obd->obd_max_recoverable_clients;
        connected = obd->obd_connected_clients;
        completed = max - obd->obd_recoverable_clients;
        queue_len = obd->obd_requests_queued_for_recovery;
        next_transno = obd->obd_next_recovery_transno;

        CDEBUG(D_HA,"max: %d, connected: %d, completed: %d, queue_len: %d, "
               "req_transno: "LPU64", next_transno: "LPU64"\n",
               max, connected, completed, queue_len, req_transno, next_transno);
        if (obd->obd_abort_recovery) {
                CDEBUG(D_HA, "waking for aborted recovery\n");
                wake_up = 1;
        } else if (atomic_read(&obd->obd_req_replay_clients) == 0) {
                CDEBUG(D_HA, "waking for completed recovery\n");
                wake_up = 1;
        } else if (req_transno == next_transno) {
                CDEBUG(D_HA, "waking for next ("LPD64")\n", next_transno);
                wake_up = 1;
        } else if (queue_len + completed == max) {
                LASSERT(req->rq_reqmsg->transno >= next_transno);
                CDEBUG(req_transno > obd->obd_last_committed ? D_ERROR : D_HA,
                       "waking for skipped transno (skip: "LPD64
                       ", ql: %d, comp: %d, conn: %d, next: "LPD64")\n",
                       next_transno, queue_len, completed, max, req_transno);
                obd->obd_next_recovery_transno = req_transno;
                wake_up = 1;
        } else if (queue_len == atomic_read(&obd->obd_req_replay_clients)) {
                /* some clients haven't connected in time, but we can try
                 * to replay requests that demand on already committed ones
                 * also, we can replay first non-committed transation */
                LASSERT(req_transno != 0);
                if (req_transno == obd->obd_last_committed + 1) {
                        obd->obd_next_recovery_transno = req_transno;
                } else if (req_transno > obd->obd_last_committed) {
                        /* can't continue recovery: have no needed transno */
                        obd->obd_abort_recovery = 1;
                        CDEBUG(D_ERROR, "abort due to missed clients. max: %d, "
                               "connected: %d, completed: %d, queue_len: %d, "
                               "req_transno: "LPU64", next_transno: "LPU64"\n",
                               max, connected, completed, queue_len,
                               req_transno, next_transno);
                }
                wake_up = 1;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);
        
        return wake_up;
}

static struct ptlrpc_request *
target_next_replay_req(struct obd_device *obd)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_request *req;

        CDEBUG(D_HA, "Waiting for transno "LPD64"\n",
               obd->obd_next_recovery_transno);
        l_wait_event(obd->obd_next_transno_waitq,
                     check_for_next_transno(obd), &lwi);
        
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_abort_recovery) {
                req = NULL;
        } else if (!list_empty(&obd->obd_req_replay_queue)) {
                req = list_entry(obd->obd_req_replay_queue.next,
                                 struct ptlrpc_request, rq_list);
                list_del_init(&req->rq_list);
                obd->obd_requests_queued_for_recovery--;
        } else {
                req = NULL;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);
        return req;
}

static int check_for_next_lock(struct obd_device *obd)
{
        struct ptlrpc_request *req = NULL;
        int wake_up = 0;

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!list_empty(&obd->obd_lock_replay_queue)) {
                req = list_entry(obd->obd_lock_replay_queue.next,
                                 struct ptlrpc_request, rq_list);
                CDEBUG(D_HA, "waking for next lock\n");
                wake_up = 1;
        } else if (atomic_read(&obd->obd_lock_replay_clients) == 0) {
                CDEBUG(D_HA, "waking for completed lock replay\n");
                wake_up = 1;
        } else if (obd->obd_abort_recovery) {
                CDEBUG(D_HA, "waking for aborted recovery\n");
                wake_up = 1;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);
        
        return wake_up;
}

static struct ptlrpc_request *
target_next_replay_lock(struct obd_device *obd)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_request *req;

        CDEBUG(D_HA, "Waiting for lock\n");
        l_wait_event(obd->obd_next_transno_waitq,
                     check_for_next_lock(obd), &lwi);
        
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_abort_recovery) {
                req = NULL;
        } else if (!list_empty(&obd->obd_lock_replay_queue)) {
                req = list_entry(obd->obd_lock_replay_queue.next,
                                 struct ptlrpc_request, rq_list);
                list_del_init(&req->rq_list);
        } else {
                req = NULL;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);
        return req;
}

static struct ptlrpc_request *
target_next_final_ping(struct obd_device *obd)
{
        struct ptlrpc_request *req;

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!list_empty(&obd->obd_final_req_queue)) {
                req = list_entry(obd->obd_final_req_queue.next,
                                 struct ptlrpc_request, rq_list);
                list_del_init(&req->rq_list);
        } else {
                req = NULL;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);
        return req;
}

static int req_replay_done(struct obd_export *exp)
{
        if (exp->exp_req_replay_needed)
                return 0;
        return 1;
}

static int lock_replay_done(struct obd_export *exp)
{
        if (exp->exp_lock_replay_needed)
                return 0;
        return 1;
}

static int connect_done(struct obd_export *exp)
{
        if (exp->exp_connected)
                return 1;
        return 0;
}

static int check_for_clients(struct obd_device *obd)
{
        if (obd->obd_abort_recovery)
                return 1;
        LASSERT(obd->obd_connected_clients <= obd->obd_max_recoverable_clients);
        if (obd->obd_connected_clients == obd->obd_max_recoverable_clients)
                return 1;
        return 0;
}

static int target_recovery_thread(void *arg)
{
        struct obd_device *obd = arg;
        struct ptlrpc_request *req;
        struct target_recovery_data *trd = &obd->obd_recovery_data;
        char peer_str[PTL_NALFMT_SIZE];
        struct l_wait_info lwi = { 0 };
        unsigned long flags;
        ENTRY;

        kportal_daemonize("tgt-recov");

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        CERROR("%s: started recovery thread pid %d\n", obd->obd_name, 
               current->pid);
        trd->trd_processing_task = current->pid;

        obd->obd_recovering = 1;
        complete(&trd->trd_starting);

        /* first of all, we have to know the first transno to replay */
        obd->obd_abort_recovery = 0;
        l_wait_event(obd->obd_next_transno_waitq,
                     check_for_clients(obd), &lwi);
        
        spin_lock_bh(&obd->obd_processing_task_lock);
        target_cancel_recovery_timer(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        /* If some clients haven't connected in time, evict them */
        if (obd->obd_abort_recovery) {
                int stale;
                CDEBUG(D_ERROR, "few clients haven't connect in time (%d/%d),"
                       "evict them ...\n", obd->obd_connected_clients,
                       obd->obd_max_recoverable_clients);
                obd->obd_abort_recovery = 0;
                stale = class_disconnect_stale_exports(obd, connect_done, 0);
                atomic_sub(stale, &obd->obd_req_replay_clients);
                atomic_sub(stale, &obd->obd_lock_replay_clients);
        }

        /* next stage: replay requests */
        CDEBUG(D_ERROR, "1: request replay stage - %d clients from t"LPU64"\n",
              atomic_read(&obd->obd_req_replay_clients),
              obd->obd_next_recovery_transno);
        while ((req = target_next_replay_req(obd))) {
                LASSERT(trd->trd_processing_task == current->pid);
                DEBUG_REQ(D_HA, req, "processing t"LPD64" from %s: ", 
                          req->rq_reqmsg->transno, 
                          ptlrpc_peernid2str(&req->rq_peer, peer_str));
                (void)trd->trd_recovery_handler(req);
                obd->obd_replayed_requests++;
                reset_recovery_timer(obd);
                /* bug 1580: decide how to properly sync() in recovery*/
                //mds_fsync_super(mds->mds_sb);
                ptlrpc_free_clone(req);
                spin_lock_bh(&obd->obd_processing_task_lock);
                obd->obd_next_recovery_transno++;
                spin_unlock_bh(&obd->obd_processing_task_lock);
        }

        spin_lock_bh(&obd->obd_processing_task_lock);
        target_cancel_recovery_timer(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        /* If some clients haven't replayed requests in time, evict them */
        if (obd->obd_abort_recovery) {
                int stale;
                CDEBUG(D_ERROR, "req replay timed out, aborting ...\n");
                obd->obd_abort_recovery = 0;
                stale = class_disconnect_stale_exports(obd, req_replay_done, 0);
                atomic_sub(stale, &obd->obd_lock_replay_clients);
                abort_req_replay_queue(obd);
                LBUG();
        }

        /* The second stage: replay locks */
        CDEBUG(D_ERROR, "2: lock replay stage - %d clients\n",
              atomic_read(&obd->obd_lock_replay_clients));
        while ((req = target_next_replay_lock(obd))) {
                LASSERT(trd->trd_processing_task == current->pid);
                DEBUG_REQ(D_HA, req, "processing lock from %s: ", 
                          ptlrpc_peernid2str(&req->rq_peer, peer_str));
                (void)trd->trd_recovery_handler(req);
                reset_recovery_timer(obd);
                ptlrpc_free_clone(req);
                obd->obd_replayed_locks++;
        }
        
        spin_lock_bh(&obd->obd_processing_task_lock);
        target_cancel_recovery_timer(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        /* If some clients haven't replayed requests in time, evict them */
        if (obd->obd_abort_recovery) {
                int stale;
                CERROR("lock replay timed out, aborting ...\n");
                obd->obd_abort_recovery = 0;
                stale = class_disconnect_stale_exports(obd, lock_replay_done, 0);
                abort_lock_replay_queue(obd);
        }

        /* We drop recoverying flag to forward all new requests
         * to regular mds_handle() since now */
        spin_lock_bh(&obd->obd_processing_task_lock);
        obd->obd_recovering = 0;
        spin_unlock_bh(&obd->obd_processing_task_lock);

        /* The third stage: reply on final pings */
        CWARN("3: final stage - process recovery completion pings\n");
        while ((req = target_next_final_ping(obd))) {
                LASSERT(trd->trd_processing_task == current->pid);
                DEBUG_REQ(D_HA, req, "processing final ping from %s: ", 
                          ptlrpc_peernid2str(&req->rq_peer, peer_str));
                (void)trd->trd_recovery_handler(req);
                ptlrpc_free_clone(req);
        }
        
        CWARN("4: recovery completed - %d/%d reqs/locks replayed\n",
              obd->obd_replayed_requests, obd->obd_replayed_locks);
        target_finish_recovery(obd);

        trd->trd_processing_task = 0;
        complete(&trd->trd_finishing);
        return 0;
}

int target_start_recovery_thread(struct obd_device *obd, svc_handler_t handler)
{
        int rc = 0;
        struct target_recovery_data *trd = &obd->obd_recovery_data;

        memset(trd, 0, sizeof(*trd));
        init_completion(&trd->trd_starting);
        init_completion(&trd->trd_finishing);
        trd->trd_recovery_handler = handler;

        if (kernel_thread(target_recovery_thread, obd, 0) > 0) {
                wait_for_completion(&trd->trd_starting);
                LASSERT(obd->obd_recovering != 0);
        } else
                rc = -ECHILD;

        return rc;
}

void target_stop_recovery_thread(struct obd_device *obd)
{
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovery_data.trd_processing_task > 0) {
                struct target_recovery_data *trd = &obd->obd_recovery_data;
                CERROR("%s: aborting recovery\n", obd->obd_name);
                obd->obd_abort_recovery = 1;
                wake_up(&obd->obd_next_transno_waitq);
                spin_unlock_bh(&obd->obd_processing_task_lock);
                wait_for_completion(&trd->trd_finishing);
        } else {
                spin_unlock_bh(&obd->obd_processing_task_lock);
        }
}
#endif

int target_process_req_flags(struct obd_device *obd, struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        LASSERT(exp != NULL);
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REQ_REPLAY_DONE) {
                /* client declares he's ready to replay locks */
                spin_lock_bh(&obd->obd_processing_task_lock);
                if (exp->exp_req_replay_needed) {
                        LASSERT(atomic_read(&obd->obd_req_replay_clients) > 0);
                        exp->exp_req_replay_needed = 0;
                        atomic_dec(&obd->obd_req_replay_clients);
                        obd->obd_recoverable_clients--;
                        if (atomic_read(&obd->obd_req_replay_clients) == 0)
                                CDEBUG(D_HA, "all clients have replayed reqs\n");
                        wake_up(&obd->obd_next_transno_waitq);
                }
                spin_unlock_bh(&obd->obd_processing_task_lock);
        }
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LOCK_REPLAY_DONE) {
                /* client declares he's ready to complete recovery 
                 * so, we put the request on th final queue */
                spin_lock_bh(&obd->obd_processing_task_lock);
                if (exp->exp_lock_replay_needed) {
                        LASSERT(atomic_read(&obd->obd_lock_replay_clients) > 0);
                        exp->exp_lock_replay_needed = 0;
                        atomic_dec(&obd->obd_lock_replay_clients);
                        if (atomic_read(&obd->obd_lock_replay_clients) == 0)
                                CDEBUG(D_HA, "all clients have replayed locks\n");
                        wake_up(&obd->obd_next_transno_waitq);
                }
                spin_unlock_bh(&obd->obd_processing_task_lock);
        }

        return 0;
}

int target_queue_recovery_request(struct ptlrpc_request *req,
                                  struct obd_device *obd)
{
        struct list_head *tmp;
        int inserted = 0;
        __u64 transno = req->rq_reqmsg->transno;

        if (obd->obd_recovery_data.trd_processing_task == current->pid) {
                /* Processing the queue right now, don't re-add. */
                return 1;
        }

        target_process_req_flags(obd, req);

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LOCK_REPLAY_DONE) {
                /* client declares he's ready to complete recovery 
                 * so, we put the request on th final queue */
                req = ptlrpc_clone_req(req);
                if (req == NULL)
                        return -ENOMEM;
                DEBUG_REQ(D_HA, req, "queue final req");
                spin_lock_bh(&obd->obd_processing_task_lock);
                list_add_tail(&req->rq_list, &obd->obd_final_req_queue);
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return 0;
        }
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REQ_REPLAY_DONE) {
                /* client declares he's ready to replay locks */
                req = ptlrpc_clone_req(req);
                if (req == NULL)
                        return -ENOMEM;
                DEBUG_REQ(D_HA, req, "queue lock replay req");
                spin_lock_bh(&obd->obd_processing_task_lock);
                list_add_tail(&req->rq_list, &obd->obd_lock_replay_queue);
                spin_unlock_bh(&obd->obd_processing_task_lock);
                wake_up(&obd->obd_next_transno_waitq);
                return 0;
        }


        /* CAVEAT EMPTOR: The incoming request message has been swabbed
         * (i.e. buflens etc are in my own byte order), but type-dependent
         * buffers (eg mds_body, ost_body etc) have NOT been swabbed. */

        if (!transno) {
                INIT_LIST_HEAD(&req->rq_list);
                DEBUG_REQ(D_HA, req, "not queueing");
                return 1;
        }


        /* If we're processing the queue, we want don't want to queue this
         * message.
         *
         * Also, if this request has a transno less than the one we're waiting
         * for, we should process it now.  It could (and currently always will)
         * be an open request for a descriptor that was opened some time ago.
         *
         * Also, a resent, replayed request that has already been
         * handled will pass through here and be processed immediately.
         */
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (transno < obd->obd_next_recovery_transno && check_for_clients(obd)) {
                /* Processing the queue right now, don't re-add. */
                LASSERT(list_empty(&req->rq_list));
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return 1;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);

        /* A resent, replayed request that is still on the queue; just drop it.
           The queued request will handle this. */
        if ((lustre_msg_get_flags(req->rq_reqmsg) & (MSG_RESENT | MSG_REPLAY))
            == (MSG_RESENT | MSG_REPLAY)) {
                DEBUG_REQ(D_ERROR, req, "dropping resent queued req");
                return 0;
        }

        req = ptlrpc_clone_req(req);
        if (req == NULL)
                return -ENOMEM;

        spin_lock_bh(&obd->obd_processing_task_lock);

        /* XXX O(n^2) */
        list_for_each(tmp, &obd->obd_req_replay_queue) {
                struct ptlrpc_request *reqiter =
                        list_entry(tmp, struct ptlrpc_request, rq_list);

                if (reqiter->rq_reqmsg->transno > transno) {
                        list_add_tail(&req->rq_list, &reqiter->rq_list);
                        inserted = 1;
                        break;
                }
        }

        if (!inserted)
                list_add_tail(&req->rq_list, &obd->obd_req_replay_queue);

        obd->obd_requests_queued_for_recovery++;
        wake_up(&obd->obd_next_transno_waitq);
        spin_unlock_bh(&obd->obd_processing_task_lock);
        return 0;
}

struct obd_device * target_req2obd(struct ptlrpc_request *req)
{
        return req->rq_export->exp_obd;
}

int
target_send_reply_msg (struct ptlrpc_request *req, int rc, int fail_id)
{
        if (OBD_FAIL_CHECK(fail_id | OBD_FAIL_ONCE)) {
                obd_fail_loc |= OBD_FAIL_ONCE | OBD_FAILED;
                DEBUG_REQ(D_ERROR, req, "dropping reply");
                /* NB this does _not_ send with ACK disabled, to simulate
                 * sending OK, but timing out for the ACK */
                if (req->rq_reply_state != NULL) {
                        if (!req->rq_reply_state->rs_difficult) {
                                lustre_free_reply_state (req->rq_reply_state);
                                req->rq_reply_state = NULL;
                        } else {
                                struct ptlrpc_service *svc =
                                        req->rq_rqbd->rqbd_srv_ni->sni_service;
                                atomic_inc(&svc->srv_outstanding_replies);
                        }
                }
                return (-ECOMM);
        }

        if (rc) {
                req->rq_status = rc;
                return (ptlrpc_error(req));
        } else {
                DEBUG_REQ(D_NET, req, "sending reply");
        }
        
        return (ptlrpc_send_reply(req, 1));
}

void 
target_send_reply(struct ptlrpc_request *req, int rc, int fail_id)
{
        int                        netrc;
        unsigned long              flags;
        struct ptlrpc_reply_state *rs;
        struct obd_device         *obd;
        struct obd_export         *exp;
        struct ptlrpc_srv_ni      *sni;
        struct ptlrpc_service     *svc;

        sni = req->rq_rqbd->rqbd_srv_ni;
        svc = sni->sni_service;
        
        rs = req->rq_reply_state;
        if (rs == NULL || !rs->rs_difficult) {
                /* The easy case; no notifiers and reply_out_callback()
                 * cleans up (i.e. we can't look inside rs after a
                 * successful send) */
                netrc = target_send_reply_msg (req, rc, fail_id);

                LASSERT (netrc == 0 || req->rq_reply_state == NULL);
                return;
        }

        /* must be an export if locks saved */
        LASSERT (req->rq_export != NULL);
        /* req/reply consistent */
        LASSERT (rs->rs_srv_ni == sni);

        /* "fresh" reply */
        LASSERT (!rs->rs_scheduled);
        LASSERT (!rs->rs_scheduled_ever);
        LASSERT (!rs->rs_handled);
        LASSERT (!rs->rs_on_net);
        LASSERT (rs->rs_export == NULL);
        LASSERT (list_empty(&rs->rs_obd_list));
        LASSERT (list_empty(&rs->rs_exp_list));

        exp = class_export_get (req->rq_export);
        obd = exp->exp_obd;

        /* disable reply scheduling onto srv_reply_queue while I'm setting up */
        rs->rs_scheduled = 1;
        rs->rs_on_net    = 1;
        rs->rs_xid       = req->rq_xid;
        rs->rs_transno   = req->rq_transno;
        rs->rs_export    = exp;
        
        spin_lock_irqsave (&obd->obd_uncommitted_replies_lock, flags);

        if (rs->rs_transno > obd->obd_last_committed) {
                /* not committed already */ 
                list_add_tail (&rs->rs_obd_list, 
                               &obd->obd_uncommitted_replies);
        }

        spin_unlock (&obd->obd_uncommitted_replies_lock);
        spin_lock (&exp->exp_lock);

        list_add_tail (&rs->rs_exp_list, &exp->exp_outstanding_replies);

        spin_unlock_irqrestore (&exp->exp_lock, flags);

        netrc = target_send_reply_msg (req, rc, fail_id);

        spin_lock_irqsave (&svc->srv_lock, flags);

        svc->srv_n_difficult_replies++;

        if (netrc != 0) /* error sending: reply is off the net */
                rs->rs_on_net = 0;

        if (!rs->rs_on_net ||                   /* some notifier */
            list_empty(&rs->rs_exp_list) ||     /* completed already */
            list_empty(&rs->rs_obd_list)) {
                list_add_tail (&rs->rs_list, &svc->srv_reply_queue);
                wake_up (&svc->srv_waitq);
        } else {
                list_add (&rs->rs_list, &sni->sni_active_replies);
                rs->rs_scheduled = 0;           /* allow notifier to schedule */
        }

        spin_unlock_irqrestore (&svc->srv_lock, flags);
}

int target_handle_ping(struct ptlrpc_request *req)
{
        return lustre_pack_reply(req, 0, NULL, NULL);
}
