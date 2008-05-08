/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LDLM

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else
# include <liblustre.h>
#endif
#include <obd.h>
#include <lustre_mds.h>
#include <lustre_dlm.h>
#include <lustre_net.h>
#include <lustre_sec.h>
#include "ldlm_internal.h"


/* @priority: if non-zero, move the selected to the list head
 * @create: if zero, only search in existed connections
 */
static int import_set_conn(struct obd_import *imp, struct obd_uuid *uuid,
                           int priority, int create)
{
        struct ptlrpc_connection *ptlrpc_conn;
        struct obd_import_conn *imp_conn = NULL, *item;
        int rc = 0;
        ENTRY;

        if (!create && !priority) {
                CDEBUG(D_HA, "Nothing to do\n");
                RETURN(-EINVAL);
        }

        ptlrpc_conn = ptlrpc_uuid_to_connection(uuid);
        if (!ptlrpc_conn) {
                CDEBUG(D_HA, "can't find connection %s\n", uuid->uuid);
                RETURN (-ENOENT);
        }

        if (create) {
                OBD_ALLOC(imp_conn, sizeof(*imp_conn));
                if (!imp_conn) {
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
                        CDEBUG(D_HA, "imp %p@%s: found existing conn %s%s\n",
                               imp, imp->imp_obd->obd_name, uuid->uuid,
                               (priority ? ", moved to head" : ""));
                        spin_unlock(&imp->imp_lock);
                        GOTO(out_free, rc = 0);
                }
        }
        /* not found */
        if (create) {
                imp_conn->oic_conn = ptlrpc_conn;
                imp_conn->oic_uuid = *uuid;
                item->oic_last_attempt = 0;
                if (priority)
                        list_add(&imp_conn->oic_item, &imp->imp_conn_list);
                else
                        list_add_tail(&imp_conn->oic_item, &imp->imp_conn_list);
                CDEBUG(D_HA, "imp %p@%s: add connection %s at %s\n",
                       imp, imp->imp_obd->obd_name, uuid->uuid,
                       (priority ? "head" : "tail"));
        } else {
                spin_unlock(&imp->imp_lock);
                GOTO(out_free, rc = -ENOENT);
        }

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
        return import_set_conn(imp, uuid, 1, 0);
}

int client_import_add_conn(struct obd_import *imp, struct obd_uuid *uuid,
                           int priority)
{
        return import_set_conn(imp, uuid, priority, 1);
}

int client_import_del_conn(struct obd_import *imp, struct obd_uuid *uuid)
{
        struct obd_import_conn *imp_conn;
        struct obd_export *dlmexp;
        int rc = -ENOENT;
        ENTRY;

        spin_lock(&imp->imp_lock);
        if (list_empty(&imp->imp_conn_list)) {
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

static void destroy_import(struct obd_import *imp)
{
        /* drop security policy instance after all rpc finished/aborted
         * to let all busy contexts be released. */
        class_import_get(imp);
        class_destroy_import(imp);
        sptlrpc_import_sec_put(imp);
        class_import_put(imp);
}

/* configure an RPC client OBD device
 *
 * lcfg parameters:
 * 1 - client UUID
 * 2 - server UUID
 * 3 - inactive-on-startup
 */
int client_obd_setup(struct obd_device *obddev, struct lustre_cfg *lcfg)
{
        struct client_obd *cli = &obddev->u.cli;
        struct obd_import *imp;
        struct obd_uuid server_uuid;
        int rq_portal, rp_portal, connect_op;
        char *name = obddev->obd_type->typ_name;
        int rc;
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
        } else if (!strcmp(name, LUSTRE_MGC_NAME)) {
                rq_portal = MGS_REQUEST_PORTAL;
                rp_portal = MGC_REPLY_PORTAL;
                connect_op = MGS_CONNECT;
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
        sema_init(&cli->cl_mgc_sem, 1);
        sptlrpc_rule_set_init(&cli->cl_sptlrpc_rset);
        cli->cl_sec_part = LUSTRE_SP_ANY;
        cli->cl_conn_count = 0;
        memcpy(server_uuid.uuid, lustre_cfg_buf(lcfg, 2),
               min_t(unsigned int, LUSTRE_CFG_BUFLEN(lcfg, 2),
                     sizeof(server_uuid)));

        cli->cl_dirty = 0;
        cli->cl_avail_grant = 0;
        /* FIXME: should limit this for the sum of all cl_dirty_max */
        cli->cl_dirty_max = OSC_MAX_DIRTY_DEFAULT * 1024 * 1024;
        if (cli->cl_dirty_max >> CFS_PAGE_SHIFT > num_physpages / 8)
                cli->cl_dirty_max = num_physpages << (CFS_PAGE_SHIFT - 3);
        CFS_INIT_LIST_HEAD(&cli->cl_cache_waiters);
        CFS_INIT_LIST_HEAD(&cli->cl_loi_ready_list);
        CFS_INIT_LIST_HEAD(&cli->cl_loi_write_list);
        CFS_INIT_LIST_HEAD(&cli->cl_loi_read_list);
        client_obd_list_lock_init(&cli->cl_loi_list_lock);
        cli->cl_r_in_flight = 0;
        cli->cl_w_in_flight = 0;

        spin_lock_init(&cli->cl_read_rpc_hist.oh_lock);
        spin_lock_init(&cli->cl_write_rpc_hist.oh_lock);
        spin_lock_init(&cli->cl_read_page_hist.oh_lock);
        spin_lock_init(&cli->cl_write_page_hist.oh_lock);
        spin_lock_init(&cli->cl_read_offset_hist.oh_lock);
        spin_lock_init(&cli->cl_write_offset_hist.oh_lock);
        cfs_waitq_init(&cli->cl_destroy_waitq);
        atomic_set(&cli->cl_destroy_in_flight, 0);
#ifdef ENABLE_CHECKSUM
        /* Turn on checksumming by default. */
        cli->cl_checksum = 1;
        /*
         * The supported checksum types will be worked out at connect time
         * Set cl_chksum* to CRC32 for now to avoid returning screwed info
         * through procfs.
         */
        cli->cl_cksum_type = cli->cl_supp_cksum_types = OBD_CKSUM_CRC32;
#endif
        atomic_set(&cli->cl_resends, OSC_DEFAULT_RESENDS);

        /* This value may be changed at connect time in
           ptlrpc_connect_interpret. */
        cli->cl_max_pages_per_rpc = min((int)PTLRPC_MAX_BRW_PAGES,
                                        (int)(1024 * 1024 >> CFS_PAGE_SHIFT));

        if (!strcmp(name, LUSTRE_MDC_NAME)) {
                cli->cl_max_rpcs_in_flight = MDC_MAX_RIF_DEFAULT;
        } else if (num_physpages >> (20 - CFS_PAGE_SHIFT) <= 128 /* MB */) {
                cli->cl_max_rpcs_in_flight = 2;
        } else if (num_physpages >> (20 - CFS_PAGE_SHIFT) <= 256 /* MB */) {
                cli->cl_max_rpcs_in_flight = 3;
        } else if (num_physpages >> (20 - CFS_PAGE_SHIFT) <= 512 /* MB */) {
                cli->cl_max_rpcs_in_flight = 4;
        } else {
                cli->cl_max_rpcs_in_flight = OSC_MAX_RIF_DEFAULT;
        }

        rc = ldlm_get_ref();
        if (rc) {
                CERROR("ldlm_get_ref failed: %d\n", rc);
                GOTO(err, rc);
        }

        ptlrpc_init_client(rq_portal, rp_portal, name,
                           &obddev->obd_ldlm_client);

        imp = class_new_import(obddev);
        if (imp == NULL)
                GOTO(err_ldlm, rc = -ENOENT);
        imp->imp_client = &obddev->obd_ldlm_client;
        imp->imp_connect_op = connect_op;
        imp->imp_initial_recov = 1;
        imp->imp_initial_recov_bk = 0;
        CFS_INIT_LIST_HEAD(&imp->imp_pinger_chain);
        memcpy(cli->cl_target_uuid.uuid, lustre_cfg_buf(lcfg, 1),
               LUSTRE_CFG_BUFLEN(lcfg, 1));
        class_import_put(imp);

        rc = client_import_add_conn(imp, &server_uuid, 1);
        if (rc) {
                CERROR("can't add initial connection\n");
                GOTO(err_import, rc);
        }

        cli->cl_import = imp;
        /* cli->cl_max_mds_{easize,cookiesize} updated by mdc_init_ea_size() */
        cli->cl_max_mds_easize = sizeof(struct lov_mds_md);
        cli->cl_max_mds_cookiesize = sizeof(struct llog_cookie);

        if (LUSTRE_CFG_BUFLEN(lcfg, 3) > 0) {
                if (!strcmp(lustre_cfg_string(lcfg, 3), "inactive")) {
                        CDEBUG(D_HA, "marking %s %s->%s as inactive\n",
                               name, obddev->obd_name,
                               cli->cl_target_uuid.uuid);
                        spin_lock(&imp->imp_lock);
                        imp->imp_invalid = 1;
                        spin_unlock(&imp->imp_lock);
                }
        }

        cli->cl_qchk_stat = CL_NOT_QUOTACHECKED;

        RETURN(rc);

err_import:
        class_destroy_import(imp);
err_ldlm:
        ldlm_put_ref(0);
err:
        RETURN(rc);

}

int client_obd_cleanup(struct obd_device *obddev)
{
        ENTRY;
        sptlrpc_rule_set_free(&obddev->u.cli.cl_sptlrpc_rset);
        ldlm_put_ref(obddev->obd_force);
        RETURN(0);
}

/* ->o_connect() method for client side (OSC and MDC and MGC) */
int client_connect_import(const struct lu_env *env,
                          struct lustre_handle *dlm_handle,
                          struct obd_device *obd, struct obd_uuid *cluuid,
                          struct obd_connect_data *data, void *localdata)
{
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
        struct obd_export *exp;
        struct obd_connect_data *ocd;
        struct ldlm_namespace *to_be_freed = NULL;
        int rc;
        ENTRY;

        mutex_down(&cli->cl_sem);
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
                                                LDLM_NAMESPACE_CLIENT,
                                                LDLM_NAMESPACE_GREEDY);
        if (obd->obd_namespace == NULL)
                GOTO(out_disco, rc = -ENOMEM);

        imp->imp_dlm_handle = *dlm_handle;
        rc = ptlrpc_init_import(imp);
        if (rc != 0)
                GOTO(out_ldlm, rc);

        ocd = &imp->imp_connect_data;
        if (data) {
                *ocd = *data;
                imp->imp_connect_flags_orig = data->ocd_connect_flags;
        }

        rc = ptlrpc_connect_import(imp, NULL);
        if (rc != 0) {
                LASSERT (imp->imp_state == LUSTRE_IMP_DISCON);
                GOTO(out_ldlm, rc);
        }
        LASSERT(exp->exp_connection);

        if (data) {
                LASSERTF((ocd->ocd_connect_flags & data->ocd_connect_flags) ==
                         ocd->ocd_connect_flags, "old "LPX64", new "LPX64"\n",
                         data->ocd_connect_flags, ocd->ocd_connect_flags);
                data->ocd_connect_flags = ocd->ocd_connect_flags;
        }

        ptlrpc_pinger_add_import(imp);

        EXIT;

        if (rc) {
out_ldlm:
                ldlm_namespace_free_prior(obd->obd_namespace);
                to_be_freed = obd->obd_namespace;
                obd->obd_namespace = NULL;
out_disco:
                cli->cl_conn_count--;
                class_disconnect(exp);
        } else {
                class_export_put(exp);
        }
out_sem:
        mutex_up(&cli->cl_sem);
        if (to_be_freed)
                ldlm_namespace_free_post(to_be_freed, 1);

        return rc;
}

int client_disconnect_export(struct obd_export *exp)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct client_obd *cli;
        struct obd_import *imp;
        int rc = 0, err;
        struct ldlm_namespace *to_be_freed = NULL;
        ENTRY;

        if (!obd) {
                CERROR("invalid export for disconnect: exp %p cookie "LPX64"\n",
                       exp, exp ? exp->exp_handle.h_cookie : -1);
                RETURN(-EINVAL);
        }

        cli = &obd->u.cli;
        imp = cli->cl_import;

        mutex_down(&cli->cl_sem);
        if (!cli->cl_conn_count) {
                CERROR("disconnecting disconnected device (%s)\n",
                       obd->obd_name);
                GOTO(out_sem, rc = -EINVAL);
        }

        cli->cl_conn_count--;
        if (cli->cl_conn_count)
                GOTO(out_no_disconnect, rc = 0);

        /* Mark import deactivated now, so we don't try to reconnect if any
         * of the cleanup RPCs fails (e.g. ldlm cancel, etc).  We don't
         * fully deactivate the import, or that would drop all requests. */
        spin_lock(&imp->imp_lock);
        imp->imp_deactive = 1;
        spin_unlock(&imp->imp_lock);

        /* Some non-replayable imports (MDS's OSCs) are pinged, so just
         * delete it regardless.  (It's safe to delete an import that was
         * never added.) */
        (void)ptlrpc_pinger_del_import(imp);

        if (obd->obd_namespace != NULL) {
                /* obd_force == local only */
                ldlm_cli_cancel_unused(obd->obd_namespace, NULL,
                                       obd->obd_force ? LDLM_FL_LOCAL_ONLY:0,
                                       NULL);
                ldlm_namespace_free_prior(obd->obd_namespace);
                to_be_freed = obd->obd_namespace;
        }

        rc = ptlrpc_disconnect_import(imp, 0);

        ptlrpc_invalidate_import(imp);
        /* set obd_namespace to NULL only after invalidate, because we can have
         * some connect requests in flight, and his need store a connect flags
         * in obd_namespace. bug 14260 */
        obd->obd_namespace = NULL;

        ptlrpc_free_rq_pool(imp->imp_rq_pool);
        destroy_import(imp);
        cli->cl_import = NULL;

        EXIT;
 out_no_disconnect:
        err = class_disconnect(exp);
        if (!rc && err)
                rc = err;
 out_sem:
        mutex_up(&cli->cl_sem);
        if (to_be_freed)
                ldlm_namespace_free_post(to_be_freed, obd->obd_force);

        RETURN(rc);
}

/* --------------------------------------------------------------------------
 * from old lib/target.c
 * -------------------------------------------------------------------------- */

int target_handle_reconnect(struct lustre_handle *conn, struct obd_export *exp,
                            struct obd_uuid *cluuid, int initial_conn)
{
        ENTRY;
        if (exp->exp_connection && exp->exp_imp_reverse && !initial_conn) {
                struct lustre_handle *hdl;
                hdl = &exp->exp_imp_reverse->imp_remote_handle;
                /* Might be a re-connect after a partition. */
                if (!memcmp(&conn->cookie, &hdl->cookie, sizeof conn->cookie)) {
                        CWARN("%s: %s reconnecting\n", exp->exp_obd->obd_name,
                              cluuid->uuid);
                        conn->cookie = exp->exp_handle.h_cookie;
                        /* target_handle_connect() treats EALREADY and
                         * -EALREADY differently.  EALREADY means we are
                         * doing a valid reconnect from the same client. */
                        RETURN(EALREADY);
                } else {
                        CERROR("%s reconnecting from %s, "
                               "handle mismatch (ours "LPX64", theirs "
                               LPX64")\n", cluuid->uuid,
                               exp->exp_connection->c_remote_uuid.uuid,
                               hdl->cookie, conn->cookie);
                        memset(conn, 0, sizeof *conn);
                        /* target_handle_connect() treats EALREADY and
                         * -EALREADY differently.  -EALREADY is an error
                         * (same UUID, different handle). */
                        RETURN(-EALREADY);
                }
        }

        conn->cookie = exp->exp_handle.h_cookie;
        CDEBUG(D_HA, "connect export for UUID '%s' at %p, cookie "LPX64"\n",
               cluuid->uuid, exp, conn->cookie);
        RETURN(0);
}

void target_client_add_cb(struct obd_device *obd, __u64 transno, void *cb_data,
                          int error)
{
        struct obd_export *exp = cb_data;

        CDEBUG(D_RPCTRACE, "%s: committing for initial connect of %s\n",
               obd->obd_name, exp->exp_client_uuid.uuid);

        spin_lock(&exp->exp_lock);
        exp->exp_need_sync = 0;
        spin_unlock(&exp->exp_lock);
}
EXPORT_SYMBOL(target_client_add_cb);

int target_handle_connect(struct ptlrpc_request *req)
{
        struct obd_device *target, *targref = NULL;
        struct obd_export *export = NULL;
        struct obd_import *revimp;
        struct lustre_handle conn;
        struct lustre_handle *tmp;
        struct obd_uuid tgtuuid;
        struct obd_uuid cluuid;
        struct obd_uuid remote_uuid;
        char *str;
        int rc = 0;
        int initial_conn = 0;
        struct obd_connect_data *data, *tmpdata;
        lnet_nid_t *client_nid = NULL;
        ENTRY;

        OBD_RACE(OBD_FAIL_TGT_CONN_RACE);

        str = req_capsule_client_get(&req->rq_pill, &RMF_TGTUUID);
        if (str == NULL) {
                DEBUG_REQ(D_ERROR, req, "bad target UUID for connect");
                GOTO(out, rc = -EINVAL);
        }

        obd_str2uuid(&tgtuuid, str);
        target = class_uuid2obd(&tgtuuid);
        if (!target)
                target = class_name2obd(str);

        if (!target || target->obd_stopping || !target->obd_set_up) {
                LCONSOLE_ERROR_MSG(0x137, "UUID '%s' is not available "
                                   " for connect (%s)\n", str,
                                   !target ? "no target" :
                                   (target->obd_stopping ? "stopping" :
                                   "not set up"));
                GOTO(out, rc = -ENODEV);
        }

        if (target->obd_no_conn) {
                LCONSOLE_WARN("%s: temporarily refusing client connection "
                              "from %s\n", target->obd_name,
                              libcfs_nid2str(req->rq_peer.nid));
                GOTO(out, rc = -EAGAIN);
        }

        /* Make sure the target isn't cleaned up while we're here. Yes,
           there's still a race between the above check and our incref here.
           Really, class_uuid2obd should take the ref. */
        targref = class_incref(target);


        str = req_capsule_client_get(&req->rq_pill, &RMF_CLUUID);
        if (str == NULL) {
                DEBUG_REQ(D_ERROR, req, "bad client UUID for connect");
                GOTO(out, rc = -EINVAL);
        }

        obd_str2uuid(&cluuid, str);

        /* XXX extract a nettype and format accordingly */
        switch (sizeof(lnet_nid_t)) {
                /* NB the casts only avoid compiler warnings */
        case 8:
                snprintf(remote_uuid.uuid, sizeof remote_uuid,
                         "NET_"LPX64"_UUID", (__u64)req->rq_peer.nid);
                break;
        case 4:
                snprintf(remote_uuid.uuid, sizeof remote_uuid,
                         "NET_%x_UUID", (__u32)req->rq_peer.nid);
                break;
        default:
                LBUG();
        }

        tmp = req_capsule_client_get(&req->rq_pill, &RMF_CONN);
        if (tmp == NULL)
                GOTO(out, rc = -EPROTO);

        conn = *tmp;

        data = req_capsule_client_get(&req->rq_pill, &RMF_CONNECT_DATA);
        if (!data)
                GOTO(out, rc = -EPROTO);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                GOTO(out, rc);

        if (lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_LIBCLIENT) {
                if (!data) {
                        DEBUG_REQ(D_WARNING, req, "Refusing old (unversioned) "
                                  "libclient connection attempt");
                        GOTO(out, rc = -EPROTO);
                } else if (data->ocd_version < LUSTRE_VERSION_CODE -
                                               LUSTRE_VERSION_ALLOWED_OFFSET ||
                           data->ocd_version > LUSTRE_VERSION_CODE +
                                               LUSTRE_VERSION_ALLOWED_OFFSET) {
                        DEBUG_REQ(D_WARNING, req, "Refusing %s (%d.%d.%d.%d) "
                                  "libclient connection attempt",
                                  data->ocd_version < LUSTRE_VERSION_CODE ?
                                  "old" : "new",
                                  OBD_OCD_VERSION_MAJOR(data->ocd_version),
                                  OBD_OCD_VERSION_MINOR(data->ocd_version),
                                  OBD_OCD_VERSION_PATCH(data->ocd_version),
                                  OBD_OCD_VERSION_FIX(data->ocd_version));
                        data = req_capsule_server_sized_get(&req->rq_pill,
                                                        &RMF_CONNECT_DATA,
                                    offsetof(typeof(*data), ocd_version) +
                                             sizeof(data->ocd_version));
                        if (data) {
                                data->ocd_connect_flags = OBD_CONNECT_VERSION;
                                data->ocd_version = LUSTRE_VERSION_CODE;
                        }
                        GOTO(out, rc = -EPROTO);
                }
        }

        if (lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_INITIAL)
                initial_conn = 1;

        /* lctl gets a backstage, all-access pass. */
        if (obd_uuid_equals(&cluuid, &target->obd_uuid))
                goto dont_check_exports;

        spin_lock(&target->obd_dev_lock);
        export = lustre_hash_get_object_by_key(target->obd_uuid_hash_body, &cluuid);

        if (export != NULL && export->exp_connecting) { /* bug 9635, et. al. */
                CWARN("%s: exp %p already connecting\n",
                      export->exp_obd->obd_name, export);
                class_export_put(export);
                export = NULL;
                rc = -EALREADY;
        } else if (export != NULL && export->exp_connection != NULL &&
                   req->rq_peer.nid != export->exp_connection->c_peer.nid) {
                /* make darn sure this is coming from the same peer
                 * if the UUIDs matched */
                  CWARN("%s: cookie %s seen on new NID %s when "
                          "existing NID %s is already connected\n",
                        target->obd_name, cluuid.uuid,
                  libcfs_nid2str(req->rq_peer.nid),
                  libcfs_nid2str(export->exp_connection->c_peer.nid));
                  class_export_put(export);
                  export = NULL;
                  rc = -EALREADY;
        } else if (export != NULL) {
                spin_lock(&export->exp_lock);
                export->exp_connecting = 1;
                spin_unlock(&export->exp_lock);
                class_export_put(export);
                spin_unlock(&target->obd_dev_lock);
                LASSERT(export->exp_obd == target);

                rc = target_handle_reconnect(&conn, export, &cluuid, initial_conn);
        }

        /* If we found an export, we already unlocked. */
        if (!export) {
                spin_unlock(&target->obd_dev_lock);
                OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_DELAY_CONNECT, 2 * obd_timeout);
        } else if (req->rq_export == NULL &&
                   atomic_read(&export->exp_rpc_count) > 0) {
                CWARN("%s: refuse connection from %s/%s to 0x%p/%d\n",
                      target->obd_name, cluuid.uuid,
                      libcfs_nid2str(req->rq_peer.nid),
                      export, atomic_read(&export->exp_refcount));
                GOTO(out, rc = -EBUSY);
        } else if (req->rq_export != NULL &&
                   (atomic_read(&export->exp_rpc_count) > 1)) {
                CWARN("%s: refuse reconnection from %s@%s to 0x%p/%d\n",
                      target->obd_name, cluuid.uuid,
                      libcfs_nid2str(req->rq_peer.nid),
                      export, atomic_read(&export->exp_rpc_count));
                GOTO(out, rc = -EBUSY);
        } else if (lustre_msg_get_conn_cnt(req->rq_reqmsg) == 1 &&
                   !initial_conn) {
                CERROR("%s: NID %s (%s) reconnected with 1 conn_cnt; "
                       "cookies not random?\n", target->obd_name,
                       libcfs_nid2str(req->rq_peer.nid), cluuid.uuid);
                GOTO(out, rc = -EALREADY);
        } else {
                OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_DELAY_RECONNECT, 2 * obd_timeout);
                if (req->rq_export == NULL && initial_conn)
                       export->exp_last_request_time =
                               max(export->exp_last_request_time,
                                   (time_t)CURRENT_SECONDS);
        }

        /* We want to handle EALREADY but *not* -EALREADY from
         * target_handle_reconnect(), return reconnection state in a flag */
        if (rc == EALREADY) {
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECONNECT);
                rc = 0;
        } else if (rc) {
                GOTO(out, rc);
        }
        /* Tell the client if we're in recovery. */
        /* If this is the first client, start the recovery timer */
        CWARN("%s: connection from %s@%s %st"LPU64" exp %p cur %ld last %ld\n",
               target->obd_name, cluuid.uuid, libcfs_nid2str(req->rq_peer.nid),
              target->obd_recovering ? "recovering/" : "", data->ocd_transno,
              export, (long)CURRENT_SECONDS,
              export ? (long)export->exp_last_request_time : 0);


        if (target->obd_recovering) {
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECOVERING);
                target_start_recovery_timer(target);
        }

        /* Tell the client if we support replayable requests */
        if (target->obd_replayable)
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_REPLAYABLE);
        client_nid = &req->rq_peer.nid;

        if (export == NULL) {
                if (target->obd_recovering) {
                        cfs_time_t t;

                        t = cfs_timer_deadline(&target->obd_recovery_timer);
                        t = cfs_time_sub(t, cfs_time_current());
                        CERROR("%s: denying connection for new client %s (%s): "
                               "%d clients in recovery for %lds\n",
                               target->obd_name,
                               libcfs_nid2str(req->rq_peer.nid), cluuid.uuid,
                               target->obd_recoverable_clients,
                               cfs_duration_sec(t));
                        rc = -EBUSY;
                } else {
dont_check_exports:
                        rc = obd_connect(req->rq_svc_thread->t_env,
                                         &conn, target, &cluuid, data,
                                         client_nid);
                }
        } else {
                rc = obd_reconnect(req->rq_svc_thread->t_env,
                                   export, target, &cluuid, data);
        }
        if (rc)
                GOTO(out, rc);
        /* Return only the parts of obd_connect_data that we understand, so the
         * client knows that we don't understand the rest. */
        if (data) {
                 tmpdata = req_capsule_server_get(&req->rq_pill,
                                                  &RMF_CONNECT_DATA);
                  //data->ocd_connect_flags &= OBD_CONNECT_SUPPORTED;
                 *tmpdata = *data;
        }
                  
        /* If all else goes well, this is our RPC return code. */
        req->rq_status = 0;

        lustre_msg_set_handle(req->rq_repmsg, &conn);

        /* ownership of this export ref transfers to the request AFTER we
         * drop any previous reference the request had, but we don't want
         * that to go to zero before we get our new export reference. */
        export = class_conn2export(&conn);
        if (!export) {
                DEBUG_REQ(D_ERROR, req, "Missing export!");
                GOTO(out, rc = -ENODEV);
        }

        /* If the client and the server are the same node, we will already
         * have an export that really points to the client's DLM export,
         * because we have a shared handles table.
         *
         * XXX this will go away when shaver stops sending the "connect" handle
         * in the real "remote handle" field of the request --phik 24 Apr 2003
         */
        if (req->rq_export != NULL)
                class_export_put(req->rq_export);

        req->rq_export = export;

        spin_lock(&export->exp_lock);
        if (initial_conn) {
                lustre_msg_set_conn_cnt(req->rq_repmsg, export->exp_conn_cnt + 1);
        } else if (export->exp_conn_cnt >= lustre_msg_get_conn_cnt(req->rq_reqmsg)) {
                spin_unlock(&export->exp_lock);
                CERROR("%s: %s already connected at higher conn_cnt: %d > %d\n",
                       cluuid.uuid, libcfs_nid2str(req->rq_peer.nid),
                       export->exp_conn_cnt,
                       lustre_msg_get_conn_cnt(req->rq_reqmsg));

                GOTO(out, rc = -EALREADY);
        }
        export->exp_conn_cnt = lustre_msg_get_conn_cnt(req->rq_reqmsg);

        /* request from liblustre?  Don't evict it for not pinging. */
        if (lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_LIBCLIENT) {
                export->exp_libclient = 1;
                spin_unlock(&export->exp_lock);

                spin_lock(&target->obd_dev_lock);
                list_del_init(&export->exp_obd_chain_timed);
                spin_unlock(&target->obd_dev_lock);
        } else {
                spin_unlock(&export->exp_lock);
        }

        if (export->exp_connection != NULL)
                ptlrpc_put_connection(export->exp_connection);
        export->exp_connection = ptlrpc_get_connection(req->rq_peer,
                                                       req->rq_self,
                                                       &remote_uuid);

        spin_lock(&target->obd_dev_lock);
        /* Export might be hashed already, e.g. if this is reconnect */
        if (hlist_unhashed(&export->exp_nid_hash))
                lustre_hash_additem(export->exp_obd->obd_nid_hash_body,
                                    &export->exp_connection->c_peer.nid,
                                    &export->exp_nid_hash);
        spin_unlock(&target->obd_dev_lock);

        spin_lock_bh(&target->obd_processing_task_lock);
        if (target->obd_recovering && !export->exp_in_recovery) {
                spin_lock(&export->exp_lock);
                export->exp_in_recovery = 1;
                export->exp_req_replay_needed = 1;
                export->exp_lock_replay_needed = 1;
                spin_unlock(&export->exp_lock);
                if ((lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_TRANSNO)
                     && (data->ocd_transno == 0))
                        CWARN("Connect with zero transno!\n");

                if ((lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_TRANSNO)
                     && data->ocd_transno < target->obd_next_recovery_transno)
                        target->obd_next_recovery_transno = data->ocd_transno;
                target->obd_connected_clients++;
                /* each connected client is counted as recoverable */
                target->obd_recoverable_clients++;
                atomic_inc(&target->obd_req_replay_clients);
                atomic_inc(&target->obd_lock_replay_clients);
                if (target->obd_connected_clients ==
                    target->obd_max_recoverable_clients)
                        wake_up(&target->obd_next_transno_waitq);
        }
        spin_unlock_bh(&target->obd_processing_task_lock);
        tmp = req_capsule_client_get(&req->rq_pill, &RMF_CONN);
        conn = *tmp;

        if (export->exp_imp_reverse != NULL) {
                /* destroyed import can be still referenced in ctxt */
                obd_set_info_async(export, strlen(KEY_REVIMP_UPD),
                                   KEY_REVIMP_UPD, 0, NULL, NULL);

                /* in some recovery senarios, previous ctx init rpc handled
                 * in sptlrpc_target_export_check() might be used to install
                 * a reverse ctx in this reverse import, and later OBD_CONNECT
                 * using the same gss ctx could reach here and following new
                 * reverse import. note all reverse ctx in new/old import are
                 * actually based on the same gss ctx. so we invalidate ctx
                 * here before destroy import, otherwise flush old import will
                 * lead to remote reverse ctx be destroied, thus the reverse
                 * ctx of new import will lost its peer.
                 * there might be a better way to deal with this???
                 */
                sptlrpc_import_inval_all_ctx(export->exp_imp_reverse);

                destroy_import(export->exp_imp_reverse);
        }

        /* for the rest part, we return -ENOTCONN in case of errors
         * in order to let client initialize connection again.
         */
        revimp = export->exp_imp_reverse = class_new_import(target);
        if (!revimp) {
                CERROR("fail to alloc new reverse import.\n");
                GOTO(out, rc = -ENOTCONN);
        }

        revimp->imp_connection = ptlrpc_connection_addref(export->exp_connection);
        revimp->imp_client = &export->exp_obd->obd_ldlm_client;
        revimp->imp_remote_handle = conn;
        revimp->imp_dlm_fake = 1;
        revimp->imp_state = LUSTRE_IMP_FULL;

        if (req->rq_reqmsg->lm_magic == LUSTRE_MSG_MAGIC_V1 &&
            lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_NEXT_VER) {
                revimp->imp_msg_magic = LUSTRE_MSG_MAGIC_V2;
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_NEXT_VER);
        } else {
                /* unknown magic has been filtered out by unpack */
                revimp->imp_msg_magic = req->rq_reqmsg->lm_magic;
        }

        rc = sptlrpc_import_sec_adapt(revimp, req->rq_svc_ctx,
                                      req->rq_flvr.sf_rpc);
        if (rc) {
                CERROR("Failed to get sec for reverse import: %d\n", rc);
                export->exp_imp_reverse = NULL;
                class_destroy_import(revimp);
        }

        class_import_put(revimp);
out:
        if (export) {
                spin_lock(&export->exp_lock);
                export->exp_connecting = 0;
                spin_unlock(&export->exp_lock);
        }
        if (targref)
                class_decref(targref);
        if (rc)
                req->rq_status = rc;
        RETURN(rc);
}

int target_handle_disconnect(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        /* keep the rq_export around so we can send the reply */
        req->rq_status = obd_disconnect(class_export_get(req->rq_export));

        RETURN(0);
}

void target_destroy_export(struct obd_export *exp)
{
        /* exports created from last_rcvd data, and "fake"
           exports created by lctl don't have an import */
        if (exp->exp_imp_reverse != NULL)
                destroy_import(exp->exp_imp_reverse);

        /* We cancel locks at disconnect time, but this will catch any locks
         * granted in a race with recovery-induced disconnect. */
        if (exp->exp_obd->obd_namespace != NULL)
                ldlm_cancel_locks_for_export(exp);
}

/*
 * Recovery functions
 */

struct ptlrpc_request *ptlrpc_clone_req( struct ptlrpc_request *orig_req)
{
        struct ptlrpc_request *copy_req;
        struct lustre_msg *copy_reqmsg;
        struct ptlrpc_user_desc *udesc = NULL;

        OBD_ALLOC_PTR(copy_req);
        if (!copy_req)
                return NULL;
        OBD_ALLOC(copy_reqmsg, orig_req->rq_reqlen);
        if (!copy_reqmsg){
                OBD_FREE_PTR(copy_req);
                return NULL;
        }

        if (orig_req->rq_user_desc) {
                int ngroups = orig_req->rq_user_desc->pud_ngroups;

                OBD_ALLOC(udesc, sptlrpc_user_desc_size(ngroups));
                if (!udesc) {
                        OBD_FREE(copy_reqmsg, orig_req->rq_reqlen);
                        OBD_FREE_PTR(copy_req);
                        return NULL;
                }
                memcpy(udesc, orig_req->rq_user_desc,
                       sptlrpc_user_desc_size(ngroups));
        }

        *copy_req = *orig_req;
        memcpy(copy_reqmsg, orig_req->rq_reqmsg, orig_req->rq_reqlen);
        copy_req->rq_reqmsg = copy_reqmsg;
        copy_req->rq_user_desc = udesc;

        class_export_get(copy_req->rq_export);
        CFS_INIT_LIST_HEAD(&copy_req->rq_list);
        sptlrpc_svc_ctx_addref(copy_req);

        if (copy_req->rq_reply_state) {
                /* the copied req takes over the reply state */
                orig_req->rq_reply_state = NULL;
                /* to catch further access */
                orig_req->rq_repmsg = NULL;
                orig_req->rq_replen = 0;
        }

        return copy_req;
}

void ptlrpc_free_clone( struct ptlrpc_request *req)
{
        if (req->rq_reply_state) {
                ptlrpc_rs_decref(req->rq_reply_state);
                req->rq_reply_state = NULL;
        }

        sptlrpc_svc_ctx_decref(req);
        class_export_put(req->rq_export);
        list_del(&req->rq_list);

        if (req->rq_user_desc) {
                int ngroups = req->rq_user_desc->pud_ngroups;
                OBD_FREE(req->rq_user_desc, sptlrpc_user_desc_size(ngroups));
        }
        OBD_FREE(req->rq_reqmsg, req->rq_reqlen);
        OBD_FREE_PTR(req);
}

#ifdef __KERNEL__
static void target_finish_recovery(struct obd_device *obd)
{
        ENTRY;
        LCONSOLE_INFO("%s: sending delayed replies to recovered clients\n",
                      obd->obd_name);

        ldlm_reprocess_all_ns(obd->obd_namespace);

        /* when recovery finished, cleanup orphans on mds and ost */
        if (OBT(obd) && OBP(obd, postrecov)) {
                int rc = OBP(obd, postrecov)(obd);
                LCONSOLE_WARN("%s: recovery %s: rc %d\n", obd->obd_name,
                              rc < 0 ? "failed" : "complete", rc);
        }

        obd->obd_recovery_end = CURRENT_SECONDS;
        EXIT;
}

static void abort_req_replay_queue(struct obd_device *obd)
{
        struct ptlrpc_request *req, *n;

        list_for_each_entry_safe(req, n, &obd->obd_req_replay_queue, rq_list) {
                DEBUG_REQ(D_WARNING, req, "aborted:");
                req->rq_status = -ENOTCONN;
                if (ptlrpc_error(req)) {
                        DEBUG_REQ(D_ERROR, req,
                                  "failed abort_req_reply; skipping");
                }
                ptlrpc_free_clone(req);
        }
}

static void abort_lock_replay_queue(struct obd_device *obd)
{
        struct ptlrpc_request *req, *n;

        list_for_each_entry_safe(req, n, &obd->obd_lock_replay_queue, rq_list){
                DEBUG_REQ(D_ERROR, req, "aborted:");
                req->rq_status = -ENOTCONN;
                if (ptlrpc_error(req)) {
                        DEBUG_REQ(D_ERROR, req,
                                  "failed abort_lock_reply; skipping");
                }
                ptlrpc_free_clone(req);
        }
}
#endif

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
        struct ptlrpc_request *req, *n;
        ENTRY;

        LASSERT(obd->obd_stopping);

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!obd->obd_recovering) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                EXIT;
                return;
        }
        obd->obd_recovering = obd->obd_abort_recovery = 0;
        target_cancel_recovery_timer(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        list_for_each_entry_safe(req, n, &obd->obd_req_replay_queue, rq_list) {
                LASSERT (req->rq_reply_state == 0);
                ptlrpc_free_clone(req);
        }
        list_for_each_entry_safe(req, n, &obd->obd_lock_replay_queue, rq_list){
                LASSERT (req->rq_reply_state == 0);
                ptlrpc_free_clone(req);
        }
        list_for_each_entry_safe(req, n, &obd->obd_final_req_queue, rq_list) {
                LASSERT (req->rq_reply_state == 0);
                ptlrpc_free_clone(req);
        }

        EXIT;
}

static void target_recovery_expired(unsigned long castmeharder)
{
        struct obd_device *obd = (struct obd_device *)castmeharder;
        CERROR("%s: recovery timed out, aborting\n", obd->obd_name);
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovering)
                obd->obd_abort_recovery = 1;
        cfs_waitq_signal(&obd->obd_next_transno_waitq);
        spin_unlock_bh(&obd->obd_processing_task_lock);
}


/* obd_processing_task_lock should be held */
void target_cancel_recovery_timer(struct obd_device *obd)
{
        CDEBUG(D_HA, "%s: cancel recovery timer\n", obd->obd_name);
        cfs_timer_disarm(&obd->obd_recovery_timer);
}

static void reset_recovery_timer(struct obd_device *obd)
{
        time_t timeout_shift = OBD_RECOVERY_TIMEOUT;
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!obd->obd_recovering) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return;
        }
        if (cfs_time_current_sec() + OBD_RECOVERY_TIMEOUT > 
            obd->obd_recovery_start + obd->obd_recovery_max_time)
                timeout_shift = obd->obd_recovery_start + 
                        obd->obd_recovery_max_time - cfs_time_current_sec();
        cfs_timer_arm(&obd->obd_recovery_timer, cfs_time_shift(timeout_shift));
        spin_unlock_bh(&obd->obd_processing_task_lock);
        CDEBUG(D_HA, "%s: timer will expire in %u seconds\n", obd->obd_name,
               (unsigned int)timeout_shift);
        /* Only used for lprocfs_status */
        obd->obd_recovery_end = CURRENT_SECONDS + timeout_shift;
}


/* Only start it the first time called */
void target_start_recovery_timer(struct obd_device *obd)
{
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovery_handler
            || timer_pending((struct timer_list *)&obd->obd_recovery_timer)) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return;
        }
        CWARN("%s: starting recovery timer (%us)\n", obd->obd_name,
              OBD_RECOVERY_TIMEOUT);
        cfs_timer_init(&obd->obd_recovery_timer, target_recovery_expired, obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        reset_recovery_timer(obd);
}

#ifdef __KERNEL__
static int check_for_next_transno(struct obd_device *obd)
{
        struct ptlrpc_request *req = NULL;
        int wake_up = 0, connected, completed, queue_len, max;
        __u64 next_transno, req_transno;
        ENTRY;
        spin_lock_bh(&obd->obd_processing_task_lock);

        if (!list_empty(&obd->obd_req_replay_queue)) {
                req = list_entry(obd->obd_req_replay_queue.next,
                                 struct ptlrpc_request, rq_list);
                req_transno = lustre_msg_get_transno(req->rq_reqmsg);
        } else {
                req_transno = 0;
        }

        max = obd->obd_max_recoverable_clients;
        connected = obd->obd_connected_clients;
        completed = connected - obd->obd_recoverable_clients;
        queue_len = obd->obd_requests_queued_for_recovery;
        next_transno = obd->obd_next_recovery_transno;

        CDEBUG(D_HA, "max: %d, connected: %d, completed: %d, queue_len: %d, "
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
                /* handle gaps occured due to lost reply. It is allowed gaps
                 * because all clients are connected and there will be resend
                 * for missed transaction */
                LASSERTF(req_transno >= next_transno,
                         "req_transno: "LPU64", next_transno: "LPU64"\n",
                         req_transno, next_transno);

                CDEBUG(req_transno > obd->obd_last_committed ? D_ERROR : D_HA,
                       "waking for skipped transno (skip: "LPD64
                       ", ql: %d, comp: %d, conn: %d, next: "LPD64")\n",
                       next_transno, queue_len, completed, connected, req_transno);
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

static struct ptlrpc_request *target_next_replay_req(struct obd_device *obd)
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
        RETURN(req);
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

static struct ptlrpc_request *target_next_replay_lock(struct obd_device *obd)
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

static struct ptlrpc_request *target_next_final_ping(struct obd_device *obd)
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

static inline int req_replay_done(struct obd_export *exp)
{
        return (exp->exp_req_replay_needed == 0);
}

static inline int lock_replay_done(struct obd_export *exp)
{
        return (exp->exp_lock_replay_needed == 0);
}

static inline int connect_done(struct obd_export *exp)
{
        return (exp->exp_in_recovery != 0);
}

static int check_for_clients(struct obd_device *obd)
{
        if (obd->obd_abort_recovery)
                return 1;
        LASSERT(obd->obd_connected_clients <= obd->obd_max_recoverable_clients);
        if (obd->obd_no_conn == 0 &&
            obd->obd_connected_clients == obd->obd_max_recoverable_clients)
                return 1;
        return 0;
}

static int handle_recovery_req(struct ptlrpc_thread *thread,
                               struct ptlrpc_request *req,
                               svc_handler_t handler)
{
        int rc;
        ENTRY;

        rc = lu_context_init(&req->rq_session, LCT_SESSION);
        if (rc) {
                CERROR("Failure to initialize session: %d\n", rc);
                return rc;
        }
        req->rq_session.lc_thread = thread;
        lu_context_enter(&req->rq_session);
        req->rq_svc_thread = thread;
        req->rq_svc_thread->t_env->le_ses = &req->rq_session;

        /* thread context */
        lu_context_enter(&thread->t_env->le_ctx);
        (void)handler(req);
        lu_context_exit(&thread->t_env->le_ctx);

        lu_context_exit(&req->rq_session);
        lu_context_fini(&req->rq_session);
        /* don't reset timer for final stage */
        if (!req_replay_done(req->rq_export) ||
            !lock_replay_done(req->rq_export))
                reset_recovery_timer(class_exp2obd(req->rq_export));
        ptlrpc_free_clone(req);
        RETURN(0);
}

static int target_recovery_thread(void *arg)
{
        struct obd_device *obd = arg;
        struct ptlrpc_request *req;
        struct target_recovery_data *trd = &obd->obd_recovery_data;
        struct l_wait_info lwi = { 0 };
        unsigned long delta;
        unsigned long flags;
        struct lu_env env;
        struct ptlrpc_thread fake_svc_thread, *thread = &fake_svc_thread;
        __u32 recov_ctx_tags = LCT_MD_THREAD;
        int rc = 0;
        ENTRY;

        cfs_daemonize("tgt_recov");

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        rc = lu_context_init(&env.le_ctx, recov_ctx_tags);
        if (rc)
                RETURN(rc);

        thread->t_env = &env;
        env.le_ctx.lc_thread = thread;

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
                CWARN("Some clients haven't connect in time (%d/%d),"
                       "evict them\n", obd->obd_connected_clients,
                       obd->obd_max_recoverable_clients);
                obd->obd_abort_recovery = obd->obd_stopping;
                class_disconnect_stale_exports(obd, connect_done);
        }
        /* next stage: replay requests */
        delta = jiffies;
        obd->obd_req_replaying = 1;
        CDEBUG(D_INFO, "1: request replay stage - %d clients from t"LPU64"\n",
              atomic_read(&obd->obd_req_replay_clients),
              obd->obd_next_recovery_transno);
        while ((req = target_next_replay_req(obd))) {
                LASSERT(trd->trd_processing_task == current->pid);
                DEBUG_REQ(D_HA, req, "processing t"LPD64" from %s",
                          lustre_msg_get_transno(req->rq_reqmsg),
                          libcfs_nid2str(req->rq_peer.nid));
                handle_recovery_req(thread, req,
                                    trd->trd_recovery_handler);
                obd->obd_replayed_requests++;
                spin_lock_bh(&obd->obd_processing_task_lock);
                obd->obd_next_recovery_transno++;
                spin_unlock_bh(&obd->obd_processing_task_lock);
        }

        spin_lock_bh(&obd->obd_processing_task_lock);
        target_cancel_recovery_timer(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        /* If some clients haven't replayed requests in time, evict them */
        if (obd->obd_abort_recovery) {
                CDEBUG(D_ERROR, "req replay timed out, aborting ...\n");
                obd->obd_abort_recovery = obd->obd_stopping;
                class_disconnect_stale_exports(obd, req_replay_done);
                abort_req_replay_queue(obd);
        }
        /* The second stage: replay locks */
        CDEBUG(D_INFO, "2: lock replay stage - %d clients\n",
               atomic_read(&obd->obd_lock_replay_clients));
        while ((req = target_next_replay_lock(obd))) {
                LASSERT(trd->trd_processing_task == current->pid);
                DEBUG_REQ(D_HA|D_WARNING, req, "processing lock from %s: ",
                          libcfs_nid2str(req->rq_peer.nid));
                handle_recovery_req(thread, req,
                                    trd->trd_recovery_handler);
                obd->obd_replayed_locks++;
        }

        spin_lock_bh(&obd->obd_processing_task_lock);
        target_cancel_recovery_timer(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);
        /* If some clients haven't replayed requests in time, evict them */
        if (obd->obd_abort_recovery) {
                int stale;
                CERROR("lock replay timed out, aborting ...\n");
                obd->obd_abort_recovery = obd->obd_stopping;
                stale = class_disconnect_stale_exports(obd, lock_replay_done);
                abort_lock_replay_queue(obd);
        }

        /* We drop recoverying flag to forward all new requests
         * to regular mds_handle() since now */
        spin_lock_bh(&obd->obd_processing_task_lock);
        obd->obd_recovering = obd->obd_abort_recovery = 0;
        spin_unlock_bh(&obd->obd_processing_task_lock);
        /* The third stage: reply on final pings */
        CDEBUG(D_INFO, "3: final stage - process recovery completion pings\n");
        while ((req = target_next_final_ping(obd))) {
                LASSERT(trd->trd_processing_task == current->pid);
                DEBUG_REQ(D_HA, req, "processing final ping from %s: ",
                          libcfs_nid2str(req->rq_peer.nid));
                handle_recovery_req(thread, req,
                                    trd->trd_recovery_handler);
        }

        delta = (jiffies - delta) / HZ;
        CDEBUG(D_INFO,"4: recovery completed in %lus - %d/%d reqs/locks\n",
              delta, obd->obd_replayed_requests, obd->obd_replayed_locks);
        LASSERT(atomic_read(&obd->obd_req_replay_clients) == 0);
        LASSERT(atomic_read(&obd->obd_lock_replay_clients) == 0);
        if (delta > obd_timeout * 2) {
                CWARN("too long recovery - read logs\n");
                libcfs_debug_dumplog();
        }

        target_finish_recovery(obd);

        lu_context_fini(&env.le_ctx);
        trd->trd_processing_task = 0;
        complete(&trd->trd_finishing);
        RETURN(rc);
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
                CERROR("%s: Aborting recovery\n", obd->obd_name);
                obd->obd_abort_recovery = 1;
                wake_up(&obd->obd_next_transno_waitq);
                spin_unlock_bh(&obd->obd_processing_task_lock);
                wait_for_completion(&trd->trd_finishing);
        } else {
                spin_unlock_bh(&obd->obd_processing_task_lock);
        }
}

void target_recovery_fini(struct obd_device *obd)
{
        class_disconnect_exports(obd);
        target_stop_recovery_thread(obd);
        target_cleanup_recovery(obd);
}
EXPORT_SYMBOL(target_recovery_fini);

void target_recovery_init(struct obd_device *obd, svc_handler_t handler)
{
        if (obd->obd_max_recoverable_clients == 0)
                return;

        CWARN("RECOVERY: service %s, %d recoverable clients, "
              "last_transno "LPU64"\n", obd->obd_name,
              obd->obd_max_recoverable_clients, obd->obd_last_committed);
        obd->obd_next_recovery_transno = obd->obd_last_committed + 1;
        target_start_recovery_thread(obd, handler);
        obd->obd_recovery_start = CURRENT_SECONDS;
        /* Only used for lprocfs_status */
        obd->obd_recovery_end = obd->obd_recovery_start + OBD_RECOVERY_TIMEOUT;
        /* bz13079: this should be set to desired value for ost but not for mds */
        obd->obd_recovery_max_time = OBD_RECOVERY_MAX_TIME;
}
EXPORT_SYMBOL(target_recovery_init);

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
                        spin_lock(&exp->exp_lock);
                        exp->exp_req_replay_needed = 0;
                        spin_unlock(&exp->exp_lock);
                        atomic_dec(&obd->obd_req_replay_clients);
                        LASSERT(obd->obd_recoverable_clients > 0);
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
                        spin_lock(&exp->exp_lock);
                        exp->exp_lock_replay_needed = 0;
                        spin_unlock(&exp->exp_lock);
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
        __u64 transno = lustre_msg_get_transno(req->rq_reqmsg);

        ENTRY;

        if (obd->obd_recovery_data.trd_processing_task == cfs_curproc_pid()) {
                /* Processing the queue right now, don't re-add. */
                RETURN(1);
        }

        target_process_req_flags(obd, req);

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LOCK_REPLAY_DONE) {
                /* client declares he's ready to complete recovery
                 * so, we put the request on th final queue */
                req = ptlrpc_clone_req(req);
                if (req == NULL)
                        RETURN(-ENOMEM);
                DEBUG_REQ(D_HA, req, "queue final req");
                spin_lock_bh(&obd->obd_processing_task_lock);
                if (obd->obd_recovering)
                        list_add_tail(&req->rq_list, &obd->obd_final_req_queue);
                else {
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        ptlrpc_free_clone(req);
                        if (obd->obd_stopping) {
                                RETURN(-ENOTCONN);
                        } else {
                                RETURN(1);
                        }
                }
                spin_unlock_bh(&obd->obd_processing_task_lock);
                RETURN(0);
        }
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REQ_REPLAY_DONE) {
                /* client declares he's ready to replay locks */
                req = ptlrpc_clone_req(req);
                if (req == NULL)
                        RETURN(-ENOMEM);
                DEBUG_REQ(D_HA, req, "queue lock replay req");
                spin_lock_bh(&obd->obd_processing_task_lock);
                LASSERT(obd->obd_recovering);
                /* usually due to recovery abort */
                if (!req->rq_export->exp_in_recovery) {
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        ptlrpc_free_clone(req);
                        RETURN(-ENOTCONN);
                }
                LASSERT(req->rq_export->exp_lock_replay_needed);
                list_add_tail(&req->rq_list, &obd->obd_lock_replay_queue);
                spin_unlock_bh(&obd->obd_processing_task_lock);
                wake_up(&obd->obd_next_transno_waitq);
                RETURN(0);
        }

        /* CAVEAT EMPTOR: The incoming request message has been swabbed
         * (i.e. buflens etc are in my own byte order), but type-dependent
         * buffers (eg mds_body, ost_body etc) have NOT been swabbed. */

        if (!transno) {
                CFS_INIT_LIST_HEAD(&req->rq_list);
                DEBUG_REQ(D_HA, req, "not queueing");
                RETURN(1);
        }

        spin_lock_bh(&obd->obd_processing_task_lock);

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
        CWARN("Next recovery transno: "LPU64", current: "LPU64", replaying: %i\n",
              obd->obd_next_recovery_transno, transno, obd->obd_req_replaying);
        if (transno < obd->obd_next_recovery_transno && obd->obd_req_replaying) {
                /* Processing the queue right now, don't re-add. */
                LASSERT(list_empty(&req->rq_list));
                spin_unlock_bh(&obd->obd_processing_task_lock);
                RETURN(1);
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);

        /* A resent, replayed request that is still on the queue; just drop it.
           The queued request will handle this. */
        if ((lustre_msg_get_flags(req->rq_reqmsg) & (MSG_RESENT|MSG_REPLAY)) ==
            (MSG_RESENT | MSG_REPLAY)) {
                DEBUG_REQ(D_ERROR, req, "dropping resent queued req");
                RETURN(0);
        }

        req = ptlrpc_clone_req(req);
        if (req == NULL)
                RETURN(-ENOMEM);

        spin_lock_bh(&obd->obd_processing_task_lock);
        LASSERT(obd->obd_recovering);
        if (!req->rq_export->exp_in_recovery) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                ptlrpc_free_clone(req);
                RETURN(-ENOTCONN);
        }
        LASSERT(req->rq_export->exp_req_replay_needed);

        /* XXX O(n^2) */
        list_for_each(tmp, &obd->obd_req_replay_queue) {
                struct ptlrpc_request *reqiter =
                        list_entry(tmp, struct ptlrpc_request, rq_list);

                if (lustre_msg_get_transno(reqiter->rq_reqmsg) > transno) {
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
        RETURN(0);

}

struct obd_device * target_req2obd(struct ptlrpc_request *req)
{
        return req->rq_export->exp_obd;
}

static inline struct ldlm_pool *ldlm_exp2pl(struct obd_export *exp)
{
        LASSERT(exp != NULL);
        return &exp->exp_obd->obd_namespace->ns_pool;
}

int target_pack_pool_reply(struct ptlrpc_request *req)
{
        struct ldlm_pool *pl;
        ENTRY;
   
        if (!req->rq_export || !req->rq_export->exp_obd ||
            !exp_connect_lru_resize(req->rq_export)) {
                lustre_msg_set_slv(req->rq_repmsg, 0);
                lustre_msg_set_limit(req->rq_repmsg, 0);
                RETURN(0);
        }

        pl = ldlm_exp2pl(req->rq_export);

        spin_lock(&pl->pl_lock);
        LASSERT(ldlm_pool_get_slv(pl) != 0 && ldlm_pool_get_limit(pl) != 0);
        lustre_msg_set_slv(req->rq_repmsg, ldlm_pool_get_slv(pl));
        lustre_msg_set_limit(req->rq_repmsg, ldlm_pool_get_limit(pl));
        spin_unlock(&pl->pl_lock);

        RETURN(0);
}

int target_send_reply_msg(struct ptlrpc_request *req, int rc, int fail_id)
{
        if (OBD_FAIL_CHECK_ORSET(fail_id & ~OBD_FAIL_ONCE, OBD_FAIL_ONCE)) {
                DEBUG_REQ(D_ERROR, req, "dropping reply");
                return (-ECOMM);
        }

        if (unlikely(rc)) {
                DEBUG_REQ(D_ERROR, req, "processing error (%d)", rc);
                req->rq_status = rc;
                return (ptlrpc_error(req));
        } else {
                DEBUG_REQ(D_NET, req, "sending reply");
        }

        return (ptlrpc_send_reply(req, 1));
}

void target_send_reply(struct ptlrpc_request *req, int rc, int fail_id)
{
        int                        netrc;
        struct ptlrpc_reply_state *rs;
        struct obd_device         *obd;
        struct obd_export         *exp;
        struct ptlrpc_service     *svc;

        if (req->rq_no_reply)
                return;

        svc = req->rq_rqbd->rqbd_service;
        rs = req->rq_reply_state;
        if (rs == NULL || !rs->rs_difficult) {
                /* no notifiers */
                target_send_reply_msg (req, rc, fail_id);
                return;
        }

        /* must be an export if locks saved */
        LASSERT (req->rq_export != NULL);
        /* req/reply consistent */
        LASSERT (rs->rs_service == svc);

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

        spin_lock(&obd->obd_uncommitted_replies_lock);

        if (rs->rs_transno > obd->obd_last_committed) {
                /* not committed already */
                list_add_tail (&rs->rs_obd_list,
                               &obd->obd_uncommitted_replies);
        }

        spin_unlock (&obd->obd_uncommitted_replies_lock);
        spin_lock (&exp->exp_lock);

        list_add_tail (&rs->rs_exp_list, &exp->exp_outstanding_replies);

        spin_unlock(&exp->exp_lock);

        netrc = target_send_reply_msg (req, rc, fail_id);

        spin_lock(&svc->srv_lock);

        svc->srv_n_difficult_replies++;

        if (netrc != 0) {
                /* error sending: reply is off the net.  Also we need +1
                 * reply ref until ptlrpc_server_handle_reply() is done
                 * with the reply state (if the send was successful, there
                 * would have been +1 ref for the net, which
                 * reply_out_callback leaves alone) */
                rs->rs_on_net = 0;
                ptlrpc_rs_addref(rs);
                atomic_inc (&svc->srv_outstanding_replies);
        }

        if (!rs->rs_on_net ||                   /* some notifier */
            list_empty(&rs->rs_exp_list) ||     /* completed already */
            list_empty(&rs->rs_obd_list)) {
                list_add_tail (&rs->rs_list, &svc->srv_reply_queue);
                cfs_waitq_signal (&svc->srv_waitq);
        } else {
                list_add (&rs->rs_list, &svc->srv_active_replies);
                rs->rs_scheduled = 0;           /* allow notifier to schedule */
        }

        spin_unlock(&svc->srv_lock);
}

int target_handle_ping(struct ptlrpc_request *req)
{
        obd_ping(req->rq_export);
        return req_capsule_server_pack(&req->rq_pill);
}

void target_committed_to_req(struct ptlrpc_request *req)
{
        struct obd_device *obd;

        if (req == NULL || req->rq_export == NULL)
                return;

        obd = req->rq_export->exp_obd;
        if (obd == NULL)
                return;

        if (!obd->obd_no_transno && req->rq_repmsg != NULL)
                lustre_msg_set_last_committed(req->rq_repmsg,
                                              obd->obd_last_committed);
        else
                DEBUG_REQ(D_IOCTL, req, "not sending last_committed update");

        CDEBUG(D_INFO, "last_committed "LPU64", transno "LPU64", xid "LPU64"\n",
               obd->obd_last_committed, req->rq_transno, req->rq_xid);
}

EXPORT_SYMBOL(target_committed_to_req);

#ifdef HAVE_QUOTA_SUPPORT
int target_handle_qc_callback(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl;
        struct client_obd *cli = &req->rq_export->exp_obd->u.cli;

        oqctl = req_capsule_client_get(&req->rq_pill, &RMF_OBD_QUOTACTL);
        if (oqctl == NULL)
                RETURN(-EPROTO);

        cli->cl_qchk_stat = oqctl->qc_stat;

        return 0;
}

int target_handle_dqacq_callback(struct ptlrpc_request *req)
{
#ifdef __KERNEL__
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_device *master_obd;
        struct lustre_quota_ctxt *qctxt;
        struct qunit_data *qdata;
        void* rep;
        struct qunit_data_old *qdata_old;
        int rc = 0;
        ENTRY;

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc) {
                CERROR("packing reply failed!: rc = %d\n", rc);
                RETURN(rc);
        }

        LASSERT(req->rq_export);

        /* fixed for bug10707 */
        if ((req->rq_export->exp_connect_flags & OBD_CONNECT_QUOTA64) &&
            !OBD_FAIL_CHECK(OBD_FAIL_QUOTA_QD_COUNT_32BIT)) {
                CDEBUG(D_QUOTA, "qd_count is 64bit!\n");
                rep = req_capsule_server_get(&req->rq_pill,
                                             &RMF_QUNIT_DATA);
                LASSERT(rep);
                qdata = req_capsule_client_swab_get(&req->rq_pill,
                                                    &RMF_QUNIT_DATA,
                                          (void*)lustre_swab_qdata);
        } else {
                CDEBUG(D_QUOTA, "qd_count is 32bit!\n");
                rep = req_capsule_server_get(&req->rq_pill, &RMF_QUNIT_DATA);
                LASSERT(rep);
                qdata_old = req_capsule_client_swab_get(&req->rq_pill,
                                                        &RMF_QUNIT_DATA,
                                           (void*)lustre_swab_qdata_old);
                qdata = lustre_quota_old_to_new(qdata_old);
        }

        if (qdata == NULL)
                RETURN(-EPROTO);

        /* we use the observer */
        LASSERT(obd->obd_observer && obd->obd_observer->obd_observer);
        master_obd = obd->obd_observer->obd_observer;
        qctxt = &master_obd->u.obt.obt_qctxt;

        LASSERT(qctxt->lqc_handler);
        rc = qctxt->lqc_handler(master_obd, qdata,
                                lustre_msg_get_opc(req->rq_reqmsg));
        if (rc && rc != -EDQUOT)
                CDEBUG(rc == -EBUSY  ? D_QUOTA : D_ERROR,
                       "dqacq failed! (rc:%d)\n", rc);

        /* the qd_count might be changed in lqc_handler */
        if ((req->rq_export->exp_connect_flags & OBD_CONNECT_QUOTA64) &&
            !OBD_FAIL_CHECK(OBD_FAIL_QUOTA_QD_COUNT_32BIT)) {
                memcpy(rep, qdata, sizeof(*qdata));
        } else {
                qdata_old = lustre_quota_new_to_old(qdata);
                memcpy(rep, qdata_old, sizeof(*qdata_old));
        }
        req->rq_status = rc;
        rc = ptlrpc_reply(req);

        RETURN(rc);
#else
        return 0;
#endif /* !__KERNEL__ */
}
#endif /* HAVE_QUOTA_SUPPORT */

ldlm_mode_t lck_compat_array[] = {
        [LCK_EX] LCK_COMPAT_EX,
        [LCK_PW] LCK_COMPAT_PW,
        [LCK_PR] LCK_COMPAT_PR,
        [LCK_CW] LCK_COMPAT_CW,
        [LCK_CR] LCK_COMPAT_CR,
        [LCK_NL] LCK_COMPAT_NL,
        [LCK_GROUP] LCK_COMPAT_GROUP
};
