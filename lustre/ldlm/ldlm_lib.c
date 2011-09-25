/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
                imp_conn->oic_last_attempt = 0;
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
        ptlrpc_connection_put(ptlrpc_conn);
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

                        ptlrpc_connection_put(imp->imp_connection);
                        imp->imp_connection = NULL;

                        dlmexp = class_conn2export(&imp->imp_dlm_handle);
                        if (dlmexp && dlmexp->exp_connection) {
                                LASSERT(dlmexp->exp_connection ==
                                        imp_conn->oic_conn);
                                ptlrpc_connection_put(dlmexp->exp_connection);
                                dlmexp->exp_connection = NULL;
                        }
                }

                list_del(&imp_conn->oic_item);
                ptlrpc_connection_put(imp_conn->oic_conn);
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

/* configure an RPC client OBD device
 *
 * lcfg parameters:
 * 1 - client UUID
 * 2 - server UUID
 * 3 - inactive-on-startup
 */
int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct lustre_cfg* lcfg = buf;
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

        init_rwsem(&cli->cl_sem);
        sema_init(&cli->cl_mgc_sem, 1);
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
        CFS_INIT_LIST_HEAD(&cli->cl_loi_hp_ready_list);
        CFS_INIT_LIST_HEAD(&cli->cl_loi_write_list);
        CFS_INIT_LIST_HEAD(&cli->cl_loi_read_list);
        client_obd_list_lock_init(&cli->cl_loi_list_lock);
        cli->cl_r_in_flight = 0;
        cli->cl_w_in_flight = 0;
        cli->cl_dio_r_in_flight = 0;
        cli->cl_dio_w_in_flight = 0;
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
        cli->cl_max_mds_easize = sizeof(struct lov_mds_md_v3);
        cli->cl_max_mds_cookiesize = sizeof(struct llog_cookie);

        if (LUSTRE_CFG_BUFLEN(lcfg, 3) > 0) {
                if (!strcmp(lustre_cfg_string(lcfg, 3), "inactive")) {
                        CDEBUG(D_HA, "marking %s %s->%s as inactive\n",
                               name, obddev->obd_name,
                               cli->cl_target_uuid.uuid);
                        spin_lock(&imp->imp_lock);
                        imp->imp_deactive = 1;
                        spin_unlock(&imp->imp_lock);
                }
        }

        obddev->obd_namespace = ldlm_namespace_new(obddev, obddev->obd_name,
                                                   LDLM_NAMESPACE_CLIENT,
                                                   LDLM_NAMESPACE_GREEDY);
        if (obddev->obd_namespace == NULL) {
                CERROR("Unable to create client namespace - %s\n",
                       obddev->obd_name);
                GOTO(err_import, rc = -ENOMEM);
        }

        cli->cl_qchk_stat = CL_NOT_QUOTACHECKED;

        RETURN(rc);

err_import:
        class_destroy_import(imp);
err_ldlm:
        ldlm_put_ref();
err:
        RETURN(rc);

}

int client_obd_cleanup(struct obd_device *obddev)
{
        ENTRY;

        ldlm_namespace_free_post(obddev->obd_namespace);
        obddev->obd_namespace = NULL;

        ldlm_put_ref();
        RETURN(0);
}

/* ->o_connect() method for client side (OSC and MDC and MGC) */
int client_connect_import(struct lustre_handle *dlm_handle,
                          struct obd_device *obd, struct obd_uuid *cluuid,
                          struct obd_connect_data *data, void *localdata)
{
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
        struct obd_export **exp = localdata;
        struct obd_connect_data *ocd;
        int rc;
        ENTRY;

        down_write(&cli->cl_sem);
        CDEBUG(D_INFO, "connect %s - %d\n", obd->obd_name,
               cli->cl_conn_count);

        if (cli->cl_conn_count > 0)
                GOTO(out_sem, rc = -EALREADY);

        rc = class_connect(dlm_handle, obd, cluuid);
        if (rc)
                GOTO(out_sem, rc);

        cli->cl_conn_count++;
        *exp = class_conn2export(dlm_handle);

        LASSERT(obd->obd_namespace);

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
        LASSERT((*exp)->exp_connection);

        if (data) {
                LASSERT((ocd->ocd_connect_flags & data->ocd_connect_flags) ==
                        ocd->ocd_connect_flags);
                data->ocd_connect_flags = ocd->ocd_connect_flags;
        }

        ptlrpc_pinger_add_import(imp);
        EXIT;

        if (rc) {
out_ldlm:
                cli->cl_conn_count--;
                class_disconnect(*exp);
                *exp = NULL;
        }
out_sem:
        up_write(&cli->cl_sem);
        return rc;
}

int client_disconnect_export(struct obd_export *exp)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct client_obd *cli;
        struct obd_import *imp;
        int rc = 0, err;
        ENTRY;

        if (!obd) {
                CERROR("invalid export for disconnect: exp %p cookie "LPX64"\n",
                       exp, exp ? exp->exp_handle.h_cookie : -1);
                RETURN(-EINVAL);
        }

        cli = &obd->u.cli;
        imp = cli->cl_import;

        down_write(&cli->cl_sem);
        CDEBUG(D_INFO, "disconnect %s - %d\n", obd->obd_name,
               cli->cl_conn_count);

        if (!cli->cl_conn_count) {
                CERROR("disconnecting disconnected device (%s)\n",
                       obd->obd_name);
                GOTO(out_disconnect, rc = -EINVAL);
        }

        cli->cl_conn_count--;
        if (cli->cl_conn_count)
                GOTO(out_disconnect, rc = 0);

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
                ldlm_namespace_free_prior(obd->obd_namespace, imp,
                                          obd->obd_force);
        }

        rc = ptlrpc_disconnect_import(imp, 0);

        ptlrpc_invalidate_import(imp);

        if (imp->imp_rq_pool) {
                ptlrpc_free_rq_pool(imp->imp_rq_pool);
                imp->imp_rq_pool = NULL;
        }
        class_destroy_import(imp);
        cli->cl_import = NULL;

        EXIT;

 out_disconnect:
        /* use server style - class_disconnect should be always called for
         * o_disconnect */
        err = class_disconnect(exp);
        if (!rc && err)
                rc = err;
        up_write(&cli->cl_sem);

        RETURN(rc);
}

int server_disconnect_export(struct obd_export *exp)
{
        int rc;
        ENTRY;

        /* Disconnect early so that clients can't keep using export */
        rc = class_disconnect(exp);

        /* close import for avoid sending any requests */
        if (exp->exp_imp_reverse)
                ptlrpc_cleanup_imp(exp->exp_imp_reverse);

        if (exp->exp_obd->obd_namespace != NULL)
                ldlm_cancel_locks_for_export(exp);

        /* complete all outstanding replies */
        spin_lock(&exp->exp_lock);
        while (!list_empty(&exp->exp_outstanding_replies)) {
                struct ptlrpc_reply_state *rs =
                        list_entry(exp->exp_outstanding_replies.next,
                                   struct ptlrpc_reply_state, rs_exp_list);
                struct ptlrpc_service *svc = rs->rs_service;

                spin_lock(&svc->srv_lock);
                list_del_init(&rs->rs_exp_list);
                ptlrpc_schedule_difficult_reply(rs);
                spin_unlock(&svc->srv_lock);
        }
        spin_unlock(&exp->exp_lock);

        RETURN(rc);
}

/* --------------------------------------------------------------------------
 * from old lib/target.c
 * -------------------------------------------------------------------------- */

static int target_handle_reconnect(struct lustre_handle *conn,
                                   struct obd_export *exp,
                                   struct obd_uuid *cluuid)
{
        ENTRY;
        if (exp->exp_connection && exp->exp_imp_reverse) {
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

static void
target_start_and_reset_recovery_timer(struct obd_device *obd,
                                      svc_handler_t handler,
                                      struct ptlrpc_request *req,
                                      int new_client);
void target_stop_recovery(void *, int);
static void reset_recovery_timer(struct obd_device *obd, int duration,
                                 int extend);
int target_recovery_check_and_stop(struct obd_device *obd)
{
        int abort_recovery = 0;

        if (obd->obd_stopping || !obd->obd_recovering)
                return 1;

        spin_lock_bh(&obd->obd_processing_task_lock);
        abort_recovery = obd->obd_abort_recovery;
        obd->obd_abort_recovery = 0;
        spin_unlock_bh(&obd->obd_processing_task_lock);
        if (!abort_recovery)
                return 0;
        /** check if fs version-capable */
        if (target_fs_version_capable(obd)) {
                class_handle_stale_exports(obd);
        } else {
                CWARN("Versions are not supported by ldiskfs, VBR is OFF\n");
                class_disconnect_stale_exports(obd, exp_flags_from_obd(obd));
        }
        /* VBR: no clients are remained to replay, stop recovery */
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovering && obd->obd_recoverable_clients == 0) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                target_stop_recovery(obd, 0);
                return 1;
        }
        /* always check versions now */
        obd->obd_version_recov = 1;
        cfs_waitq_signal(&obd->obd_next_transno_waitq);
        spin_unlock_bh(&obd->obd_processing_task_lock);
        /* reset timer, recovery will proceed with versions now */
        reset_recovery_timer(obd, OBD_RECOVERY_TIME_SOFT, 1);
        return 0;
}
EXPORT_SYMBOL(target_recovery_check_and_stop);

int target_handle_connect(struct ptlrpc_request *req, svc_handler_t handler)
{
        struct obd_device *target, *targref = NULL;
        struct obd_export *export = NULL;
        struct obd_import *revimp;
        struct lustre_handle conn;
        struct obd_uuid tgtuuid;
        struct obd_uuid cluuid;
        struct obd_uuid remote_uuid;
        char *str, *tmp;
        int rc = 0;
        struct obd_connect_data *data;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*data) };
        lnet_nid_t *client_nid = NULL;
        int mds_conn = 0;
        ENTRY;

        OBD_RACE(OBD_FAIL_TGT_CONN_RACE);

        lustre_set_req_swabbed(req, REQ_REC_OFF);
        str = lustre_msg_string(req->rq_reqmsg, REQ_REC_OFF, sizeof(tgtuuid)-1);
        if (str == NULL) {
                DEBUG_REQ(D_ERROR, req, "bad target UUID for connect");
                GOTO(out, rc = -EINVAL);
        }

        obd_str2uuid (&tgtuuid, str);
        target = class_uuid2obd(&tgtuuid);
        /* COMPAT_146 */
        /* old (pre 1.6) lustre_process_log tries to connect to mdsname
           (eg. mdsA) instead of uuid. */
        if (!target) {
                snprintf((char *)tgtuuid.uuid, sizeof(tgtuuid), "%s_UUID", str);
                target = class_uuid2obd(&tgtuuid);
        }
        if (!target)
                target = class_name2obd(str);
        /* end COMPAT_146 */

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

        lustre_set_req_swabbed(req, REQ_REC_OFF + 1);
        str = lustre_msg_string(req->rq_reqmsg, REQ_REC_OFF + 1,
                                sizeof(cluuid) - 1);
        if (str == NULL) {
                DEBUG_REQ(D_ERROR, req, "bad client UUID for connect");
                GOTO(out, rc = -EINVAL);
        }

        obd_str2uuid (&cluuid, str);

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

        target_recovery_check_and_stop(target);

        tmp = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 2, sizeof conn);
        if (tmp == NULL)
                GOTO(out, rc = -EPROTO);

        memcpy(&conn, tmp, sizeof conn);

        data = lustre_swab_reqbuf(req, REQ_REC_OFF + 3, sizeof(*data),
                                  lustre_swab_connect);
        rc = lustre_pack_reply(req, 2, size, NULL);
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
                        data = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                              offsetof(typeof(*data),
                                                       ocd_version) +
                                              sizeof(data->ocd_version));
                        if (data) {
                                data->ocd_connect_flags = OBD_CONNECT_VERSION;
                                data->ocd_version = LUSTRE_VERSION_CODE;
                        }
                        GOTO(out, rc = -EPROTO);
                }
        }

        if ((lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_INITIAL) &&
            (data->ocd_connect_flags & OBD_CONNECT_MDS))
                mds_conn = 1;

        /* lctl gets a backstage, all-access pass. */
        if (obd_uuid_equals(&cluuid, &target->obd_uuid))
                goto dont_check_exports;

        export = lustre_hash_lookup(target->obd_uuid_hash, &cluuid);
        if (!export)
                goto no_export;

        /* we've found an export in the hash */
        if (export->exp_connecting) {
                /* bug 9635, et. al. */
                CWARN("%s: exp %p already connecting\n",
                      export->exp_obd->obd_name, export);
                class_export_put(export);
                export = NULL;
                rc = -EALREADY;
        } else if (mds_conn && export->exp_connection) {
                if (req->rq_peer.nid != export->exp_connection->c_peer.nid)
                        /* mds reconnected after failover */
                        CWARN("%s: received MDS connection from NID %s,"
                              " removing former export from NID %s\n",
                            target->obd_name, libcfs_nid2str(req->rq_peer.nid),
                            libcfs_nid2str(export->exp_connection->c_peer.nid));
                else
                        /* new mds connection from the same nid */
                        CWARN("%s: received new MDS connection from NID %s,"
                              " removing former export from same NID\n",
                            target->obd_name, libcfs_nid2str(req->rq_peer.nid));
                class_fail_export(export);
                class_export_put(export);
                export = NULL;
                rc = 0;
        } else if (export->exp_connection &&
                   req->rq_peer.nid != export->exp_connection->c_peer.nid &&
                   (lustre_msg_get_op_flags(req->rq_reqmsg) &
                    MSG_CONNECT_INITIAL)) {
                CWARN("%s: cookie %s seen on new NID %s when "
                      "existing NID %s is already connected\n",
                      target->obd_name, cluuid.uuid,
                      libcfs_nid2str(req->rq_peer.nid),
                      libcfs_nid2str(export->exp_connection->c_peer.nid));
                rc = -EALREADY;
                class_export_put(export);
                export = NULL;
        } else if (export->exp_failed) { /* bug 11327 */
                CDEBUG(D_HA, "%s: exp %p evict in progress - new cookie needed "
                      "for connect\n", export->exp_obd->obd_name, export);
                class_export_put(export);
                export = NULL;
                rc = -ENODEV;
        } else if (export->exp_delayed &&
                   !(data && data->ocd_connect_flags & OBD_CONNECT_VBR)) {
                class_fail_export(export);
                class_export_put(export);
                export = NULL;
                GOTO(out, rc = -ENODEV);
        } else {
                spin_lock(&export->exp_lock);
                export->exp_connecting = 1;
                spin_unlock(&export->exp_lock);
                class_export_put(export);
                LASSERT(export->exp_obd == target);

                rc = target_handle_reconnect(&conn, export, &cluuid);
        }

        /* If we found an export, we already unlocked. */
        if (!export) {
no_export:
                OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_DELAY_CONNECT, 2 * obd_timeout);
        } else if (req->rq_export == NULL &&
                   atomic_read(&export->exp_rpc_count) > 0) {
                CWARN("%s: refuse connection from %s/%s to 0x%p; still busy "
                      "with %d references\n", target->obd_name, cluuid.uuid,
                      libcfs_nid2str(req->rq_peer.nid),
                      export, atomic_read(&export->exp_refcount));
                GOTO(out, rc = -EBUSY);
        } else if (req->rq_export != NULL &&
                   atomic_read(&export->exp_rpc_count) > 1) {
                /* the current connect rpc has increased exp_rpc_count */
                CWARN("%s: refuse reconnection from %s@%s to 0x%p; still busy "
                      "with %d active RPCs\n", target->obd_name, cluuid.uuid,
                      libcfs_nid2str(req->rq_peer.nid),
                      export, atomic_read(&export->exp_rpc_count) - 1);
                spin_lock(&export->exp_lock);
                if (req->rq_export->exp_conn_cnt <
                    lustre_msg_get_conn_cnt(req->rq_reqmsg))
                        /* try to abort active requests */
                        req->rq_export->exp_abort_active_req = 1;
                spin_unlock(&export->exp_lock);
                GOTO(out, rc = -EBUSY);
        } else if (lustre_msg_get_conn_cnt(req->rq_reqmsg) == 1) {
                CERROR("%s: NID %s (%s) reconnected with 1 conn_cnt; "
                       "cookies not random?\n", target->obd_name,
                       libcfs_nid2str(req->rq_peer.nid), cluuid.uuid);
                GOTO(out, rc = -EALREADY);
        } else if (export->exp_delayed && target->obd_recovering) {
                /* VBR: don't allow delayed connection during recovery */
                CWARN("%s: NID %s (%s) export was already marked as delayed "
                      "and will wait for end of recovery\n", target->obd_name,
                       libcfs_nid2str(req->rq_peer.nid), cluuid.uuid);
                GOTO(out, rc = -EBUSY);
        } else {
                OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_DELAY_RECONNECT, 2 * obd_timeout);
        }

        if (rc < 0)
                GOTO(out, rc);

        /* Tell the client if we're in recovery. */
        if (target->obd_recovering) {
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECOVERING);
                /* If this is the first time a client connects,
                   reset the recovery timer */
                if (rc == 0)
                        target_start_and_reset_recovery_timer(target, handler,
                                                              req, !export);
        }

        /* We want to handle EALREADY but *not* -EALREADY from
         * target_handle_reconnect(), return reconnection state in a flag */
        if (rc == EALREADY) {
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECONNECT);
                rc = 0;
        } else {
                LASSERT(rc == 0);
        }

        /* Tell the client if we support replayable requests */
        if (target->obd_replayable)
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_REPLAYABLE);
        client_nid = &req->rq_peer.nid;

        /* VBR: for delayed connections we start recovery */
        if (export && export->exp_delayed && !export->exp_in_recovery) {
                LASSERT(!target->obd_recovering);
                LASSERT(data && data->ocd_connect_flags & OBD_CONNECT_VBR);
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_DELAYED |
                                        MSG_CONNECT_RECOVERING);
                spin_lock_bh(&target->obd_processing_task_lock);
                target->obd_version_recov = 1;
                spin_unlock_bh(&target->obd_processing_task_lock);
                target_start_and_reset_recovery_timer(target, handler, req, 1);
        }

        if (export == NULL) {
                if (target->obd_recovering) {
                        CERROR("%s: denying connection for new client %s (%s): "
                               "%d clients in recovery for %lds\n",
                               target->obd_name,
                               libcfs_nid2str(req->rq_peer.nid), cluuid.uuid,
                               target->obd_recoverable_clients,
                               cfs_duration_sec(cfs_time_sub(cfs_timer_deadline(&target->obd_recovery_timer),
                                                             cfs_time_current())));
                        rc = -EBUSY;
                } else {
 dont_check_exports:
                        rc = obd_connect(&conn, target, &cluuid, data,
                                         client_nid);
                }
        } else {
                rc = obd_reconnect(export, target, &cluuid, data, client_nid);
        }

        if (rc)
                GOTO(out, rc);

        /* Return only the parts of obd_connect_data that we understand, so the
         * client knows that we don't understand the rest. */
        if (data)
                memcpy(lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*data)),
                       data, sizeof(*data));

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
        if (export->exp_conn_cnt >= lustre_msg_get_conn_cnt(req->rq_reqmsg)) {
                CERROR("%s: %s already connected at higher conn_cnt: %d > %d\n",
                       cluuid.uuid, libcfs_nid2str(req->rq_peer.nid),
                       export->exp_conn_cnt,
                       lustre_msg_get_conn_cnt(req->rq_reqmsg));

                spin_unlock(&export->exp_lock);
                GOTO(out, rc = -EALREADY);
        }
        LASSERT(lustre_msg_get_conn_cnt(req->rq_reqmsg) > 0);
        export->exp_conn_cnt = lustre_msg_get_conn_cnt(req->rq_reqmsg);
        export->exp_abort_active_req = 0;

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

        if (export->exp_connection != NULL) {
                /* Check to see if connection came from another NID */
                if ((export->exp_connection->c_peer.nid != req->rq_peer.nid) &&
                    !hlist_unhashed(&export->exp_nid_hash))
                        lustre_hash_del(export->exp_obd->obd_nid_hash,
                                        &export->exp_connection->c_peer.nid,
                                        &export->exp_nid_hash);

                ptlrpc_connection_put(export->exp_connection);
        }

        export->exp_connection = ptlrpc_connection_get(req->rq_peer,
                                                       req->rq_self,
                                                       &remote_uuid);

        if (hlist_unhashed(&export->exp_nid_hash)) {
                lustre_hash_add(export->exp_obd->obd_nid_hash,
                                &export->exp_connection->c_peer.nid,
                                &export->exp_nid_hash);
        }

        if (lustre_msg_get_op_flags(req->rq_repmsg) & MSG_CONNECT_RECONNECT) {
                revimp = class_import_get(export->exp_imp_reverse);
                ptlrpc_connection_put(revimp->imp_connection);
                revimp->imp_connection = NULL;
                GOTO(set_flags, rc = 0);
        }

        if (target->obd_recovering && !export->exp_in_recovery) {
                spin_lock(&export->exp_lock);
                export->exp_in_recovery = 1;
                spin_unlock(&export->exp_lock);
                target->obd_connected_clients++;
        }
        memcpy(&conn,
               lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 2, sizeof conn),
               sizeof conn);

        if (export->exp_imp_reverse != NULL)
                class_destroy_import(export->exp_imp_reverse);
        revimp = export->exp_imp_reverse = class_new_import(target);
        revimp->imp_client = &export->exp_obd->obd_ldlm_client;
        revimp->imp_remote_handle = conn;
        revimp->imp_dlm_fake = 1;
        revimp->imp_state = LUSTRE_IMP_FULL;

set_flags:
        revimp->imp_connection = ptlrpc_connection_addref(export->exp_connection);
        if (req->rq_reqmsg->lm_magic == LUSTRE_MSG_MAGIC_V1 &&
            lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_NEXT_VER) {
                revimp->imp_msg_magic = LUSTRE_MSG_MAGIC_V2;
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_NEXT_VER);
        } else {
                /* unknown versions will be caught in
                 * ptlrpc_handle_server_req_in->lustre_unpack_msg() */
                revimp->imp_msg_magic = req->rq_reqmsg->lm_magic;
        }

        if (revimp->imp_msg_magic != LUSTRE_MSG_MAGIC_V1) {
                if (export->exp_connect_flags & OBD_CONNECT_AT)
                        revimp->imp_msghdr_flags |= MSGHDR_AT_SUPPORT;
                else
                        revimp->imp_msghdr_flags &= ~MSGHDR_AT_SUPPORT;
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

        rc = lustre_pack_reply(req, 1, NULL, NULL);
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
                class_destroy_import(exp->exp_imp_reverse);

        /* We cancel locks at disconnect time, but this will catch any locks
         * granted in a race with recovery-induced disconnect. */
        if (exp->exp_obd->obd_namespace != NULL)
                ldlm_cancel_locks_for_export(exp);
}

/*
 * Recovery functions
 */

static int target_exp_enqueue_req_replay(struct ptlrpc_request *req)
{
        __u64                  transno = lustre_msg_get_transno(req->rq_reqmsg);
        struct obd_export     *exp = req->rq_export;
        struct ptlrpc_request *reqiter;
        int                    dup = 0;

        LASSERT(exp);

        spin_lock(&exp->exp_lock);
        list_for_each_entry(reqiter, &exp->exp_req_replay_queue,
                            rq_replay_list) {
                if (lustre_msg_get_transno(reqiter->rq_reqmsg) == transno) {
                        dup = 1;
                        break;
                }
        }

        if (dup) {
                /* we expect it with RESENT and REPLAY flags */
                if ((lustre_msg_get_flags(req->rq_reqmsg) &
                     (MSG_RESENT | MSG_REPLAY)) != (MSG_RESENT | MSG_REPLAY))
                        CERROR("invalid flags %x of resent replay\n",
                               lustre_msg_get_flags(req->rq_reqmsg));
        } else {
                list_add_tail(&req->rq_replay_list, &exp->exp_req_replay_queue);
        }

        spin_unlock(&exp->exp_lock);
        return dup;
}

static void target_exp_dequeue_req_replay(struct ptlrpc_request *req)
{
        LASSERT(!list_empty(&req->rq_replay_list));
        LASSERT(req->rq_export);

        spin_lock(&req->rq_export->exp_lock);
        list_del_init(&req->rq_replay_list);
        spin_unlock(&req->rq_export->exp_lock);
}

static void target_request_copy_get(struct ptlrpc_request *req)
{
        /* mark that request is in recovery queue, so request handler will not
         * drop rpc count in export, bug 19870*/
        LASSERT(!req->rq_copy_queued);
        spin_lock(&req->rq_lock);
        req->rq_copy_queued = 1;
        spin_unlock(&req->rq_lock);
        /* increase refcount to keep request in queue */
        atomic_inc(&req->rq_refcount);
        /* release service thread while request is queued
         * we are moving the request from active processing
         * to waiting on the replay queue */
        ptlrpc_server_active_request_dec(req);
}

static void target_request_copy_put(struct ptlrpc_request *req)
{
        LASSERTF(list_empty(&req->rq_replay_list), "next: %p, prev: %p\n",
                 req->rq_replay_list.next, req->rq_replay_list.prev);
        /* class_export_rpc_get was done before handling request,
         * drop it early to allow new requests, see bug 19870.
         */
        LASSERT(req->rq_copy_queued);
        class_export_rpc_put(req->rq_export);
        /* ptlrpc_server_drop_request() assumes the request is active */
        ptlrpc_server_active_request_inc(req);
        ptlrpc_server_drop_request(req);
}

static void target_send_delayed_replies(struct obd_device *obd)
{
        int max_clients = obd->obd_max_recoverable_clients;
        struct ptlrpc_request *req, *tmp;
        time_t elapsed_time = max_t(time_t, 1, cfs_time_current_sec() -
                                    obd->obd_recovery_start);

        LCONSOLE_INFO("%s: Recovery period over after %d:%.02d, of %d clients "
                      "%d recovered and %d %s evicted.\n", obd->obd_name,
                      (int)elapsed_time/60, (int)elapsed_time%60, max_clients,
                      obd->obd_connected_clients,
                      obd->obd_stale_clients,
                      obd->obd_stale_clients == 1 ? "was" : "were");

        LCONSOLE_INFO("%s: sending delayed replies to recovered clients\n",
                      obd->obd_name);

        list_for_each_entry_safe(req, tmp, &obd->obd_delayed_reply_queue,
                                 rq_list) {
                list_del_init(&req->rq_list);
                DEBUG_REQ(D_HA, req, "delayed:");
                ptlrpc_reply(req);
                target_request_copy_put(req);
        }
        obd->obd_recovery_end = cfs_time_current_sec();
}

static void target_finish_recovery(struct obd_device *obd)
{
        OBD_RACE(OBD_FAIL_TGT_REPLAY_DELAY);

        ldlm_reprocess_all_ns(obd->obd_namespace);
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (list_empty(&obd->obd_recovery_queue)) {
                obd->obd_recovery_thread = NULL;
                obd->obd_processing_task = 0;
        } else {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                CERROR("%s: Recovery queue isn't empty\n", obd->obd_name);
                LBUG();
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);
                ;
        /* when recovery finished, cleanup orphans on mds and ost */
        if (OBT(obd) && OBP(obd, postrecov)) {
                int rc = OBP(obd, postrecov)(obd);
                if (rc < 0)
                        LCONSOLE_WARN("%s: Post recovery failed, rc %d\n",
                                      obd->obd_name, rc);
        }
        target_send_delayed_replies(obd);
}

static void abort_recovery_queue(struct obd_device *obd)
{
        struct ptlrpc_request *req, *n;
        struct list_head abort_list;
        int rc;

        CFS_INIT_LIST_HEAD(&abort_list);
        spin_lock_bh(&obd->obd_processing_task_lock);
        list_splice_init(&obd->obd_recovery_queue, &abort_list);
        spin_unlock_bh(&obd->obd_processing_task_lock);
        /* process abort list unlocked */
        list_for_each_entry_safe(req, n, &abort_list, rq_list) {
                target_exp_dequeue_req_replay(req);
                list_del_init(&req->rq_list);
                DEBUG_REQ(D_ERROR, req, "%s: aborted:", obd->obd_name);
                req->rq_status = -ENOTCONN;
                req->rq_type = PTL_RPC_MSG_ERR;
                rc = lustre_pack_reply(req, 1, NULL, NULL);
                if (rc == 0)
                        ptlrpc_reply(req);
                else
                        DEBUG_REQ(D_ERROR, req,
                                  "packing failed for abort-reply; skipping");
                target_request_copy_put(req);
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
        struct list_head clean_list;
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

        list_for_each_safe(tmp, n, &obd->obd_delayed_reply_queue) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                list_del(&req->rq_list);
                target_request_copy_put(req);
        }

        CFS_INIT_LIST_HEAD(&clean_list);
        spin_lock_bh(&obd->obd_processing_task_lock);
        list_splice_init(&obd->obd_recovery_queue, &clean_list);
        cfs_waitq_signal(&obd->obd_next_transno_waitq);
        spin_unlock_bh(&obd->obd_processing_task_lock);
        list_for_each_safe(tmp, n, &clean_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                target_exp_dequeue_req_replay(req);
                list_del_init(&req->rq_list);
                target_request_copy_put(req);
        }
        EXIT;
}

void target_stop_recovery(void *data, int abort)
{
        struct obd_device *obd = data;
        enum obd_option flags;
        ENTRY;

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!obd->obd_recovering) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                EXIT;
                return;
        }
        flags = exp_flags_from_obd(obd) | OBD_OPT_ABORT_RECOV;
        obd->obd_recovering = 0;
        obd->obd_abort_recovery = 0;
        obd->obd_processing_task = 0;
        if (abort == 0)
                LASSERT(obd->obd_recoverable_clients == 0);

        target_cancel_recovery_timer(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        if (abort) {
                LCONSOLE_WARN("%s: recovery is aborted by administrative "
                              "request; %d clients are not recovered "
                              "(%d clients did)\n", obd->obd_name,
                              obd->obd_recoverable_clients,
                              obd->obd_connected_clients);
                class_disconnect_stale_exports(obd, flags);
        }
        abort_recovery_queue(obd);
        target_finish_recovery(obd);
        CDEBUG(D_HA, "%s: recovery complete\n", obd_uuid2str(&obd->obd_uuid));
        EXIT;
}

void target_abort_recovery(void *data)
{
        target_stop_recovery(data, 1);
}

static void reset_recovery_timer(struct obd_device *, int, int);
static void target_recovery_expired(unsigned long castmeharder)
{
        struct obd_device *obd = (struct obd_device *)castmeharder;
        CDEBUG(D_HA, "%s: recovery period over; %d clients never reconnected "
               "after %lds (%d clients did)\n", obd->obd_name,
               obd->obd_recoverable_clients,
               cfs_time_current_sec() - obd->obd_recovery_start,
               obd->obd_connected_clients);

        spin_lock_bh(&obd->obd_processing_task_lock);
        obd->obd_abort_recovery = 1;
        cfs_waitq_signal(&obd->obd_next_transno_waitq);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        /* bug 18948:
         * The recovery timer expired and target_check_and_stop_recovery()
         * must be called.  We cannot call it directly because we are in
         * interrupt context, so we need to wake up another thread to call it.
         * This may happen if there are obd->obd_next_transno_waitq waiters,
         * or if we happen to handle a connect request.  However, we cannot
         * count on either of those things so we wake up the ping evictor
         * and leverage it's context to complete recovery.
         *
         * Note: HEAD has a separate recovery thread and handle this.
         */
        spin_lock(&obd->obd_dev_lock);
        ping_evictor_wake(obd->obd_self_export);
        spin_unlock(&obd->obd_dev_lock);
}

/* obd_processing_task_lock should be held */
void target_cancel_recovery_timer(struct obd_device *obd)
{
        CDEBUG(D_HA, "%s: cancel recovery timer\n", obd->obd_name);
        cfs_timer_disarm(&obd->obd_recovery_timer);
}

/* extend = 1 means require at least "duration" seconds left in the timer,
   extend = 0 means set the total duration (start_recovery_timer) */
static void reset_recovery_timer(struct obd_device *obd, int duration,
                                 int extend)
{
        cfs_time_t now = cfs_time_current_sec();
        cfs_duration_t left;

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!obd->obd_recovering) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return;
        }

        left = cfs_time_sub(obd->obd_recovery_end, now);

        if (extend && (duration > left))
                obd->obd_recovery_timeout += duration - left;
        else if (!extend && (duration > obd->obd_recovery_timeout))
                /* Track the client's largest expected replay time */
                obd->obd_recovery_timeout = duration;

        /* Hard limit of obd_recovery_time_hard which should not happen */
        if(obd->obd_recovery_timeout > obd->obd_recovery_time_hard)
                obd->obd_recovery_timeout = obd->obd_recovery_time_hard;

        obd->obd_recovery_end = obd->obd_recovery_start +
                                obd->obd_recovery_timeout;
        if (cfs_time_before(now, obd->obd_recovery_end)) {
                left = cfs_time_sub(obd->obd_recovery_end, now);
                cfs_timer_arm(&obd->obd_recovery_timer, cfs_time_shift(left));
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);
        CDEBUG(D_HA, "%s: recovery timer will expire in %u seconds\n",
               obd->obd_name, (unsigned)left);
}

static void check_and_start_recovery_timer(struct obd_device *obd,
                                           svc_handler_t handler)
{
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovery_handler) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return;
        }
        CDEBUG(D_HA, "%s: starting recovery timer\n", obd->obd_name);
        obd->obd_recovery_start = cfs_time_current_sec();
        obd->obd_recovery_handler = handler;
        cfs_timer_init(&obd->obd_recovery_timer, target_recovery_expired, obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        reset_recovery_timer(obd, obd->obd_recovery_timeout, 0);
}

/* Reset the timer with each new client connection */
/*
 * This timer is actually reconnect_timer, which is for making sure
 * the total recovery window is at least as big as my reconnect
 * attempt timing. So the initial recovery time_out will be set to
 * OBD_RECOVERY_FACTOR * obd_timeout. If the timeout coming
 * from client is bigger than this, then the recovery time_out will
 * be extend to make sure the client could be reconnected, in the
 * process, the timeout from the new client should be ignored.
 */

static void
target_start_and_reset_recovery_timer(struct obd_device *obd,
                                      svc_handler_t handler,
                                      struct ptlrpc_request *req,
                                      int new_client)
{
        int service_time = lustre_msg_get_service_time(req->rq_reqmsg);

        if (!new_client && service_time)
                /* Teach server about old server's estimates, as first guess
                   at how long new requests will take. */
                at_measured(&req->rq_rqbd->rqbd_service->srv_at_estimate,
                            service_time);

        check_and_start_recovery_timer(obd, handler);

        /* convert the service time to rpc timeout,
         * reuse service_time to limit stack usage */
        service_time = at_est2timeout(service_time);

        /* We expect other clients to timeout within service_time, then try
         * to reconnect, then try the failover server.  The max delay between
         * connect attempts is SWITCH_MAX + SWITCH_INC + INITIAL */
        service_time += 2 * (CONNECTION_SWITCH_MAX + CONNECTION_SWITCH_INC +
                             INITIAL_CONNECT_TIMEOUT);
        if (service_time > obd->obd_recovery_timeout && !new_client)
                reset_recovery_timer(obd, service_time, 0);
}

static int check_for_next_transno(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        int wake_up = 0, connected, completed, queue_len, max;
        __u64 next_transno, req_transno;

        if (obd->obd_stopping) {
                CDEBUG(D_HA, "waking for stopping device\n");
                return 1;
        }

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_abort_recovery) {
                CDEBUG(D_HA, "waking for aborted recovery\n");
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return 1;
        } else if (!obd->obd_recovering) {
                CDEBUG(D_HA, "waking for completed recovery (?)\n");
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return 1;
        }

        LASSERT(!list_empty(&obd->obd_recovery_queue));
        req = list_entry(obd->obd_recovery_queue.next,
                         struct ptlrpc_request, rq_list);
        max = obd->obd_max_recoverable_clients;
        req_transno = lustre_msg_get_transno(req->rq_reqmsg);
        connected = obd->obd_connected_clients;
        completed = max - obd->obd_recoverable_clients -
                    obd->obd_delayed_clients;
        queue_len = obd->obd_requests_queued_for_recovery;
        next_transno = obd->obd_next_recovery_transno;

        CDEBUG(D_HA,"max: %d, connected: %d, delayed %d, completed: %d, "
               "queue_len: %d, req_transno: "LPU64", next_transno: "LPU64"\n",
               max, connected, obd->obd_delayed_clients, completed, queue_len,
               req_transno, next_transno);
        if (req_transno == next_transno) {
                CDEBUG(D_HA, "waking for next ("LPD64")\n", next_transno);
                wake_up = 1;
        } else if (queue_len == obd->obd_recoverable_clients) {
                CDEBUG(D_ERROR,
                       "%s: waking for skipped transno (skip: "LPD64
                       ", ql: %d, comp: %d, conn: %d, next: "LPD64")\n",
                       obd->obd_name, next_transno, queue_len, completed, max,
                       req_transno);
                obd->obd_next_recovery_transno = req_transno;
                wake_up = 1;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);
        LASSERT(lustre_msg_get_transno(req->rq_reqmsg) >= next_transno);
        return wake_up;
}

static void process_recovery_queue(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        struct l_wait_info lwi = { 0 };
        ENTRY;

        for (;;) {
                spin_lock_bh(&obd->obd_processing_task_lock);

                if (!obd->obd_recovering) {
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        EXIT;
                        return;
                }

                LASSERTF(obd->obd_processing_task == cfs_curproc_pid(),
                         "%s: invalid pid in obd_processing_task (%d != %d)\n",
                         obd->obd_name, obd->obd_processing_task,
                         cfs_curproc_pid());
                req = list_entry(obd->obd_recovery_queue.next,
                                 struct ptlrpc_request, rq_list);

                if (lustre_msg_get_transno(req->rq_reqmsg) !=
                    obd->obd_next_recovery_transno) {
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        CDEBUG(D_HA, "%s: waiting for transno "LPD64" (1st is "
                               LPD64", x"LPU64")\n", obd->obd_name,
                               obd->obd_next_recovery_transno,
                               lustre_msg_get_transno(req->rq_reqmsg),
                               req->rq_xid);
                        l_wait_event(obd->obd_next_transno_waitq,
                                     check_for_next_transno(obd), &lwi);
                        if (target_recovery_check_and_stop(obd)) {
                                EXIT;
                                return;
                        }
                        continue;
                }
                list_del_init(&req->rq_list);
                LASSERT(obd->obd_recovery_thread);
                /* replace request initial thread with current one, bug #18221 */
                req->rq_svc_thread = obd->obd_recovery_thread;
                obd->obd_requests_queued_for_recovery--;
                spin_unlock_bh(&obd->obd_processing_task_lock);

                DEBUG_REQ(D_HA, req, "processing: ");
                (void)obd->obd_recovery_handler(req);
                obd->obd_replayed_requests++;
                /* Extend the recovery timer enough to complete the next
                 * replayed rpc */
                reset_recovery_timer(obd, AT_OFF ? obd_timeout :
                       at_get(&req->rq_rqbd->rqbd_service->srv_at_estimate), 1);
                /* bug 1580: decide how to properly sync() in recovery */
                //mds_fsync_super(obd->u.obt.obt_sb);
                spin_lock_bh(&obd->obd_processing_task_lock);
                obd->obd_next_recovery_transno++;
                spin_unlock_bh(&obd->obd_processing_task_lock);
                target_exp_dequeue_req_replay(req);
                target_request_copy_put(req);
                OBD_RACE(OBD_FAIL_TGT_REPLAY_DELAY);
                spin_lock_bh(&obd->obd_processing_task_lock);
                if (list_empty(&obd->obd_recovery_queue)) {
                        obd->obd_processing_task = 0;
                        obd->obd_recovery_thread = NULL;
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        break;
                }
                spin_unlock_bh(&obd->obd_processing_task_lock);
        }
        EXIT;
}

int target_queue_recovery_request(struct ptlrpc_request *req,
                                  struct obd_device *obd)
{
        struct list_head *tmp;
        int inserted = 0;
        __u64 transno = lustre_msg_get_transno(req->rq_reqmsg);
        ENTRY;
        /* CAVEAT EMPTOR: The incoming request message has been swabbed
         * (i.e. buflens etc are in my own byte order), but type-dependent
         * buffers (eg mds_body, ost_body etc) have NOT been swabbed. */

        if (!transno) {
                CFS_INIT_LIST_HEAD(&req->rq_list);
                DEBUG_REQ(D_HA, req, "not queueing");
                RETURN(1);
        }

        spin_lock_bh(&obd->obd_processing_task_lock);

        if (!obd->obd_recovering) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                RETURN(0);
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
        if (obd->obd_processing_task == cfs_curproc_pid() ||
            transno < obd->obd_next_recovery_transno) {
                /* Processing the queue right now, don't re-add. */
                LASSERT(list_empty(&req->rq_list));
                spin_unlock_bh(&obd->obd_processing_task_lock);
                RETURN(1);
        }

        if (unlikely(OBD_FAIL_CHECK(OBD_FAIL_TGT_REPLAY_DROP))) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                RETURN(0);
        }

        if (target_exp_enqueue_req_replay(req)) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                DEBUG_REQ(D_ERROR, req, "%s: dropping resent queued req",
                                        obd->obd_name);
                RETURN(0);
        }

        /* XXX O(n^2) */
        list_for_each(tmp, &obd->obd_recovery_queue) {
                struct ptlrpc_request *reqiter =
                        list_entry(tmp, struct ptlrpc_request, rq_list);

                if (lustre_msg_get_transno(reqiter->rq_reqmsg) > transno) {
                        list_add_tail(&req->rq_list, &reqiter->rq_list);
                        inserted = 1;
                        break;
                }

                if (unlikely(lustre_msg_get_transno(reqiter->rq_reqmsg) ==
                             transno)) {
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        DEBUG_REQ(D_ERROR, req, "%s: dropping replay: transno "
                                  "has been claimed by another client",
                                  obd->obd_name);
                        target_exp_dequeue_req_replay(req);
                        RETURN(0);
                }
        }

        if (!inserted) {
                list_add_tail(&req->rq_list, &obd->obd_recovery_queue);
        }

        target_request_copy_get(req);
        obd->obd_requests_queued_for_recovery++;

        if (obd->obd_processing_task != 0) {
                /* Someone else is processing this queue, we'll leave it to
                 * them.
                 */
                cfs_waitq_signal(&obd->obd_next_transno_waitq);
                spin_unlock_bh(&obd->obd_processing_task_lock);
                RETURN(0);
        }

        /* Nobody is processing, and we know there's (at least) one to process
         * now, so we'll do the honours.
         */
        obd->obd_processing_task = cfs_curproc_pid();
        /* save thread that handle recovery queue */
        obd->obd_recovery_thread = req->rq_svc_thread;
        spin_unlock_bh(&obd->obd_processing_task_lock);

        process_recovery_queue(obd);
        RETURN(0);
}

struct obd_device * target_req2obd(struct ptlrpc_request *req)
{
        return req->rq_export->exp_obd;
}

int target_queue_last_replay_reply(struct ptlrpc_request *req, int rc)
{
        struct obd_device *obd = target_req2obd(req);
        struct obd_export *exp = req->rq_export;
        int recovery_done = 0, delayed_done = 0;

        LASSERT ((rc == 0) == req->rq_packed_final);

        if (!req->rq_packed_final) {
                /* Just like ptlrpc_error, but without the sending. */
                rc = lustre_pack_reply(req, 1, NULL, NULL);
                if (rc)
                        return rc;
                req->rq_type = PTL_RPC_MSG_ERR;
        }

        LASSERT(!req->rq_reply_state->rs_difficult);
        LASSERT(list_empty(&req->rq_list));

        /* Don't race cleanup */
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_stopping) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                goto out_noconn;
        }

        if (!exp->exp_vbr_failed) {
                target_request_copy_get(req);
                list_add(&req->rq_list, &obd->obd_delayed_reply_queue);
        }

        /* only count the first "replay over" request from each
           export */
        if (exp->exp_replay_needed) {
                spin_lock(&exp->exp_lock);
                exp->exp_replay_needed = 0;
                spin_unlock(&exp->exp_lock);

                if (!exp->exp_delayed) {
                        --obd->obd_recoverable_clients;
                } else {
                        spin_lock(&exp->exp_lock);
                        exp->exp_delayed = 0;
                        spin_unlock(&exp->exp_lock);
                        delayed_done = 1;
                        if (obd->obd_delayed_clients == 0) {
                                spin_unlock_bh(&obd->obd_processing_task_lock);
                                LBUG();
                        }
                        --obd->obd_delayed_clients;
                }
        }
        recovery_done = (obd->obd_recoverable_clients == 0);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        if (delayed_done) {
                /* start pinging export */
                spin_lock(&obd->obd_dev_lock);
                list_add_tail(&exp->exp_obd_chain_timed,
                              &obd->obd_exports_timed);
                list_move_tail(&exp->exp_obd_chain, &obd->obd_exports);
                spin_unlock(&obd->obd_dev_lock);
                target_send_delayed_replies(obd);
        }

        OBD_RACE(OBD_FAIL_LDLM_RECOV_CLIENTS);
        if (recovery_done) {
                spin_lock_bh(&obd->obd_processing_task_lock);
                obd->obd_recovering = 0;
                obd->obd_version_recov = 0;
                obd->obd_abort_recovery = 0;
                target_cancel_recovery_timer(obd);
                spin_unlock_bh(&obd->obd_processing_task_lock);

                if (!delayed_done)
                        target_finish_recovery(obd);
                CDEBUG(D_HA, "%s: recovery complete\n",
                       obd_uuid2str(&obd->obd_uuid));
        } else {
                CWARN("%s: %d recoverable clients remain\n",
                      obd->obd_name, obd->obd_recoverable_clients);
                cfs_waitq_signal(&obd->obd_next_transno_waitq);
        }

        /* VBR: disconnect export with failed recovery */
        if (exp->exp_vbr_failed) {
                CWARN("%s: disconnect export %s\n", obd->obd_name,
                      exp->exp_client_uuid.uuid);
                class_fail_export(exp);
                req->rq_status = 0;
                ptlrpc_send_reply(req, 0);
        }

        return 1;

out_noconn:
        req->rq_status = -ENOTCONN;
        /* rv is ignored anyhow */
        return -ENOTCONN;
}

int target_handle_reply(struct ptlrpc_request *req, int rc, int fail)
{
        struct obd_device *obd = NULL;

        if (req->rq_export)
                obd = target_req2obd(req);

        /* handle replay reply for version recovery */
        if (obd && obd->obd_version_recov &&
            (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY)) {
                LASSERT(req->rq_repmsg);
                lustre_msg_add_flags(req->rq_repmsg, MSG_VERSION_REPLAY);
        }

        /* handle last replay */
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                if (obd &&
                    lustre_msg_get_flags(req->rq_reqmsg) & MSG_DELAY_REPLAY) {
                        DEBUG_REQ(D_HA, req,
                                  "delayed LAST_REPLAY, queuing reply");
                        rc = target_queue_last_replay_reply(req, rc);
                        LASSERT(req->rq_export->exp_delayed == 0);
                        return rc;
                }

                if (obd && obd->obd_recovering) { /* normal recovery */
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        rc = target_queue_last_replay_reply(req, rc);
                        return rc;
                }

                /* Lost a race with recovery; let the error path DTRT. */
                rc = req->rq_status = -ENOTCONN;
        }
        target_send_reply(req, rc, fail);
        return 0;
}

static inline struct ldlm_pool *ldlm_exp2pl(struct obd_export *exp)
{
        LASSERT(exp != NULL);
        return &exp->exp_obd->obd_namespace->ns_pool;
}

int target_pack_pool_reply(struct ptlrpc_request *req)
{
        struct obd_device *obd;
        ENTRY;

        /*
         * Check that we still have all structures alive as this may
         * be some late rpc in shutdown time.
         */
        if (unlikely(!req->rq_export || !req->rq_export->exp_obd ||
                     !exp_connect_lru_resize(req->rq_export))) {
                lustre_msg_set_slv(req->rq_repmsg, 0);
                lustre_msg_set_limit(req->rq_repmsg, 0);
                RETURN(0);
        }

        /*
         * OBD is alive here as export is alive, which we checked above.
         */
        obd = req->rq_export->exp_obd;

        read_lock(&obd->obd_pool_lock);
        lustre_msg_set_slv(req->rq_repmsg, obd->obd_pool_slv);
        lustre_msg_set_limit(req->rq_repmsg, obd->obd_pool_limit);
        read_unlock(&obd->obd_pool_lock);

        RETURN(0);
}

int
target_send_reply_msg (struct ptlrpc_request *req, int rc, int fail_id)
{
        if (OBD_FAIL_CHECK(fail_id | OBD_FAIL_ONCE)) {
                obd_fail_loc |= OBD_FAIL_ONCE | OBD_FAILED;
                DEBUG_REQ(D_ERROR, req, "dropping reply");
                return (-ECOMM);
        }

        if (rc) {
                DEBUG_REQ(D_ERROR, req, "processing error (%d)", rc);
                req->rq_status = rc;
                return (ptlrpc_send_error(req, 1));
        } else {
                DEBUG_REQ(D_NET, req, "sending reply");
        }

        return (ptlrpc_send_reply(req, PTLRPC_REPLY_MAYBE_DIFFICULT));
}

void
target_send_reply(struct ptlrpc_request *req, int rc, int fail_id)
{
        int                        netrc;
        struct ptlrpc_reply_state *rs;
        struct obd_device         *obd;
        struct obd_export         *exp;
        struct ptlrpc_service     *svc;

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

        exp = class_export_get(req->rq_export);
        obd = exp->exp_obd;

        /* disable reply scheduling onto srv_reply_queue while I'm setting up */
        rs->rs_scheduled = 1;
        rs->rs_on_net    = 1;
        rs->rs_xid       = req->rq_xid;
        rs->rs_transno   = req->rq_transno;
        rs->rs_export    = exp;

        spin_lock(&exp->exp_uncommitted_replies_lock);

        /* VBR: use exp_last_committed */
        if (rs->rs_transno > exp->exp_last_committed) {
                /* not committed already */
                list_add_tail (&rs->rs_obd_list,
                               &exp->exp_uncommitted_replies);
        }

        spin_unlock (&exp->exp_uncommitted_replies_lock);
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
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY &&
            req->rq_export->exp_in_recovery) {
                spin_lock(&req->rq_export->exp_lock);
                req->rq_export->exp_in_recovery = 0;
                spin_unlock(&req->rq_export->exp_lock);
        }
        obd_ping(req->rq_export);
        return lustre_pack_reply(req, 1, NULL, NULL);
}

void target_committed_to_req(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        if (!exp->exp_obd->obd_no_transno && req->rq_repmsg != NULL) {
                lustre_msg_set_last_committed(req->rq_repmsg,
                                              exp->exp_last_committed);
        } else {
                DEBUG_REQ(D_IOCTL, req, "not sending last_committed update (%d/"
                          "%d)", exp->exp_obd->obd_no_transno,
                          req->rq_repmsg == NULL);
        }
        CDEBUG(D_INFO, "last_committed x"LPU64", this req x"LPU64"\n",
               exp->exp_obd->obd_last_committed, req->rq_xid);
}

EXPORT_SYMBOL(target_committed_to_req);

int target_handle_qc_callback(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl;
        struct client_obd *cli = &req->rq_export->exp_obd->u.cli;

        oqctl = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*oqctl),
                                   lustre_swab_obd_quotactl);
        if (oqctl == NULL) {
                CERROR("Can't unpack obd_quatactl\n");
                RETURN(-EPROTO);
        }

        cli->cl_qchk_stat = oqctl->qc_stat;

        return 0;
}

#ifdef HAVE_QUOTA_SUPPORT
int target_handle_dqacq_callback(struct ptlrpc_request *req)
{
#ifdef __KERNEL__
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_device *master_obd = NULL, *lov_obd = NULL;
        struct lustre_quota_ctxt *qctxt;
        struct qunit_data *qdata = NULL;
        int rc = 0;
        int repsize[2] = { sizeof(struct ptlrpc_body), 0 };
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_DROP_QUOTA_REQ))
                RETURN(rc);

        repsize[1] = quota_get_qunit_data_size(req->rq_export->
                                               exp_connect_flags);

        rc = lustre_pack_reply(req, 2, repsize, NULL);
        if (rc)
                RETURN(rc);

        LASSERT(req->rq_export);

        /* there are three forms of qunit(historic causes), so we need to
         * adjust qunits from slaves to the same form here */
        OBD_ALLOC(qdata, sizeof(struct qunit_data));
        if (!qdata)
                RETURN(-ENOMEM);
        rc = quota_get_qdata(req, qdata, QUOTA_REQUEST, QUOTA_EXPORT);
        if (rc < 0) {
                CDEBUG(D_ERROR, "Can't unpack qunit_data(rc: %d)\n", rc);
                GOTO(out, rc);
        }

        /* we use the observer */
        if (obd_pin_observer(obd, &lov_obd) ||
            obd_pin_observer(lov_obd, &master_obd)) {
                CERROR("Can't find the observer, it is recovering\n");
                req->rq_status = -EAGAIN;
                GOTO(send_reply, rc = -EAGAIN);
        }

        qctxt = &master_obd->u.obt.obt_qctxt;

        if (!qctxt->lqc_setup) {
                /* quota_type has not been processed yet, return EAGAIN
                 * until we know whether or not quotas are supposed to
                 * be enabled */
                CDEBUG(D_QUOTA, "quota_type not processed yet, return "
                                "-EAGAIN\n");
                req->rq_status = -EAGAIN;
                rc = ptlrpc_reply(req);
                GOTO(out, rc);
        }

        LASSERT(qctxt->lqc_handler);
        rc = qctxt->lqc_handler(master_obd, qdata,
                                lustre_msg_get_opc(req->rq_reqmsg));
        if (rc && rc != -EDQUOT)
                CDEBUG(rc == -EBUSY  ? D_QUOTA : D_ERROR,
                       "dqacq failed! (rc:%d)\n", rc);
        req->rq_status = rc;

        /* there are three forms of qunit(historic causes), so we need to
         * adjust the same form to different forms slaves needed */
        rc = quota_copy_qdata(req, qdata, QUOTA_REPLY, QUOTA_EXPORT);
        if (rc < 0) {
                CDEBUG(D_ERROR, "Can't pack qunit_data(rc: %d)\n", rc);
                GOTO(out, rc);
        }

        /* Block the quota req. b=14840 */
        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_BLOCK_QUOTA_REQ, obd_timeout);
 send_reply:
        rc = ptlrpc_reply(req);
out:
        if (master_obd)
                obd_unpin_observer(lov_obd);
        if (lov_obd)
                obd_unpin_observer(obd);
        OBD_FREE(qdata, sizeof(struct qunit_data));
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
