/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

/**
 * This file deals with various client/target related logic including recovery.
 *
 * TODO: This code more logically belongs in the ptlrpc module than in ldlm and
 * should be moved.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/kthread.h>
#include <libcfs/libcfs.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_dlm.h>
#include <lustre_net.h>
#include <lustre_sec.h>
#include "ldlm_internal.h"

/* @priority: If non-zero, move the selected connection to the list head.
 * @create: If zero, only search in existing connections.
 */
static int import_set_conn(struct obd_import *imp, struct obd_uuid *uuid,
                           int priority, int create)
{
	struct ptlrpc_connection *ptlrpc_conn;
	struct obd_import_conn *imp_conn = NULL, *item;
	lnet_nid_t nid4refnet = LNET_NID_ANY;
	int rc = 0;
	ENTRY;

	if (!create && !priority) {
		CDEBUG(D_HA, "Nothing to do\n");
		RETURN(-EINVAL);
	}

	if (imp->imp_connection &&
	    imp->imp_connection->c_remote_uuid.uuid[0] == 0)
		/* nid4refnet is used to restrict network connections */
		nid4refnet = imp->imp_connection->c_self;
	ptlrpc_conn = ptlrpc_uuid_to_connection(uuid, nid4refnet);
	if (!ptlrpc_conn) {
		CDEBUG(D_HA, "can't find connection %s\n", uuid->uuid);
		RETURN(-ENOENT);
	}

	if (create) {
		OBD_ALLOC(imp_conn, sizeof(*imp_conn));
		if (!imp_conn)
			GOTO(out_put, rc = -ENOMEM);
	}

	spin_lock(&imp->imp_lock);
	list_for_each_entry(item, &imp->imp_conn_list, oic_item) {
		if (obd_uuid_equals(uuid, &item->oic_uuid)) {
			if (priority) {
				list_del(&item->oic_item);
				list_add(&item->oic_item,
					 &imp->imp_conn_list);
				item->oic_last_attempt = 0;
			}
			CDEBUG(D_HA, "imp %p@%s: found existing conn %s%s\n",
			       imp, imp->imp_obd->obd_name, uuid->uuid,
			       (priority ? ", moved to head" : ""));
			spin_unlock(&imp->imp_lock);
			GOTO(out_free, rc = 0);
		}
	}
	/* No existing import connection found for \a uuid. */
	if (create) {
		imp_conn->oic_conn = ptlrpc_conn;
		imp_conn->oic_uuid = *uuid;
		imp_conn->oic_last_attempt = 0;
		if (priority)
			list_add(&imp_conn->oic_item, &imp->imp_conn_list);
		else
			list_add_tail(&imp_conn->oic_item,
				      &imp->imp_conn_list);
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
EXPORT_SYMBOL(client_import_add_conn);

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

			if (dlmexp != NULL)
				class_export_put(dlmexp);
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
EXPORT_SYMBOL(client_import_del_conn);

/**
 * Find conn UUID by peer NID. \a peer is a server NID. This function is used
 * to find a conn uuid of \a imp which can reach \a peer.
 */
int client_import_find_conn(struct obd_import *imp, lnet_nid_t peer,
			    struct obd_uuid *uuid)
{
	struct obd_import_conn *conn;
	int rc = -ENOENT;
	ENTRY;

	spin_lock(&imp->imp_lock);
	list_for_each_entry(conn, &imp->imp_conn_list, oic_item) {
		/* Check if conn UUID does have this peer NID. */
                if (class_check_uuid(&conn->oic_uuid, peer)) {
                        *uuid = conn->oic_uuid;
                        rc = 0;
                        break;
                }
        }
	spin_unlock(&imp->imp_lock);
	RETURN(rc);
}
EXPORT_SYMBOL(client_import_find_conn);

void client_destroy_import(struct obd_import *imp)
{
	/* Drop security policy instance after all RPCs have finished/aborted
	 * to let all busy contexts be released. */
        class_import_get(imp);
        class_destroy_import(imp);
        sptlrpc_import_sec_put(imp);
        class_import_put(imp);
}
EXPORT_SYMBOL(client_destroy_import);

/**
 * Check whether or not the OSC is on MDT.
 * In the config log,
 * osc on MDT
 *	setup 0:{fsname}-OSTxxxx-osc[-MDTxxxx] 1:lustre-OST0000_UUID 2:NID
 * osc on client
 *	setup 0:{fsname}-OSTxxxx-osc 1:lustre-OST0000_UUID 2:NID
 *
 **/
static int osc_on_mdt(char *obdname)
{
	char *ptr;

	ptr = strrchr(obdname, '-');
	if (ptr == NULL)
		return 0;

	if (strncmp(ptr + 1, "MDT", 3) == 0)
		return 1;

	return 0;
}

/* Configure an RPC client OBD device.
 *
 * lcfg parameters:
 * 1 - client UUID
 * 2 - server UUID
 * 3 - inactive-on-startup
 * 4 - restrictive net
 */
int client_obd_setup(struct obd_device *obddev, struct lustre_cfg *lcfg)
{
	struct client_obd *cli = &obddev->u.cli;
	struct obd_import *imp;
	struct obd_uuid server_uuid;
	int rq_portal, rp_portal, connect_op;
	char *name = obddev->obd_type->typ_name;
	enum ldlm_ns_type ns_type = LDLM_NS_TYPE_UNKNOWN;
	char *cli_name = lustre_cfg_buf(lcfg, 0);
	struct ptlrpc_connection fake_conn = { .c_self = 0,
					       .c_remote_uuid.uuid[0] = 0 };
	int rc;
	ENTRY;

	/* In a more perfect world, we would hang a ptlrpc_client off of
	 * obd_type and just use the values from there. */
	if (!strcmp(name, LUSTRE_OSC_NAME)) {
		rq_portal = OST_REQUEST_PORTAL;
		rp_portal = OSC_REPLY_PORTAL;
		connect_op = OST_CONNECT;
		cli->cl_sp_me = LUSTRE_SP_CLI;
		cli->cl_sp_to = LUSTRE_SP_OST;
		ns_type = LDLM_NS_TYPE_OSC;
	} else if (!strcmp(name, LUSTRE_MDC_NAME) ||
		   !strcmp(name, LUSTRE_LWP_NAME)) {
		rq_portal = MDS_REQUEST_PORTAL;
		rp_portal = MDC_REPLY_PORTAL;
		connect_op = MDS_CONNECT;
		if (is_lwp_on_ost(cli_name))
			cli->cl_sp_me = LUSTRE_SP_OST;
		else if (is_lwp_on_mdt(cli_name))
			cli->cl_sp_me = LUSTRE_SP_MDT;
		else
			cli->cl_sp_me = LUSTRE_SP_CLI;
		cli->cl_sp_to = LUSTRE_SP_MDT;
		ns_type = LDLM_NS_TYPE_MDC;
	} else if (!strcmp(name, LUSTRE_OSP_NAME)) {
		if (strstr(lustre_cfg_buf(lcfg, 1), "OST") == NULL) {
			/* OSP_on_MDT for other MDTs */
			connect_op = MDS_CONNECT;
			cli->cl_sp_to = LUSTRE_SP_MDT;
			ns_type = LDLM_NS_TYPE_MDC;
			rq_portal = OUT_PORTAL;
		} else {
			/* OSP on MDT for OST */
			connect_op = OST_CONNECT;
			cli->cl_sp_to = LUSTRE_SP_OST;
			ns_type = LDLM_NS_TYPE_OSC;
			rq_portal = OST_REQUEST_PORTAL;
		}
		rp_portal = OSC_REPLY_PORTAL;
		cli->cl_sp_me = LUSTRE_SP_MDT;
        } else if (!strcmp(name, LUSTRE_MGC_NAME)) {
                rq_portal = MGS_REQUEST_PORTAL;
                rp_portal = MGC_REPLY_PORTAL;
                connect_op = MGS_CONNECT;
                cli->cl_sp_me = LUSTRE_SP_MGC;
                cli->cl_sp_to = LUSTRE_SP_MGS;
                cli->cl_flvr_mgc.sf_rpc = SPTLRPC_FLVR_INVALID;
                ns_type = LDLM_NS_TYPE_MGC;
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
	mutex_init(&cli->cl_mgc_mutex);
	cli->cl_seq = NULL;
	init_rwsem(&cli->cl_seq_rwsem);
	cli->cl_conn_count = 0;
	memcpy(server_uuid.uuid, lustre_cfg_buf(lcfg, 2),
	       min_t(unsigned int, LUSTRE_CFG_BUFLEN(lcfg, 2),
		     sizeof(server_uuid)));

	cli->cl_dirty_pages = 0;
	cli->cl_avail_grant = 0;
	/* FIXME: Should limit this for the sum of all cl_dirty_max_pages. */
	/* cl_dirty_max_pages may be changed at connect time in
	 * ptlrpc_connect_interpret(). */
	client_adjust_max_dirty(cli);
	INIT_LIST_HEAD(&cli->cl_cache_waiters);
	INIT_LIST_HEAD(&cli->cl_loi_ready_list);
	INIT_LIST_HEAD(&cli->cl_loi_hp_ready_list);
	INIT_LIST_HEAD(&cli->cl_loi_write_list);
	INIT_LIST_HEAD(&cli->cl_loi_read_list);
	spin_lock_init(&cli->cl_loi_list_lock);
	atomic_set(&cli->cl_pending_w_pages, 0);
	atomic_set(&cli->cl_pending_r_pages, 0);
	cli->cl_r_in_flight = 0;
	cli->cl_w_in_flight = 0;

	spin_lock_init(&cli->cl_read_rpc_hist.oh_lock);
	spin_lock_init(&cli->cl_write_rpc_hist.oh_lock);
	spin_lock_init(&cli->cl_read_page_hist.oh_lock);
	spin_lock_init(&cli->cl_write_page_hist.oh_lock);
	spin_lock_init(&cli->cl_read_offset_hist.oh_lock);
	spin_lock_init(&cli->cl_write_offset_hist.oh_lock);

	/* lru for osc. */
	INIT_LIST_HEAD(&cli->cl_lru_osc);
	atomic_set(&cli->cl_lru_shrinkers, 0);
	atomic_long_set(&cli->cl_lru_busy, 0);
	atomic_long_set(&cli->cl_lru_in_list, 0);
	INIT_LIST_HEAD(&cli->cl_lru_list);
	spin_lock_init(&cli->cl_lru_list_lock);
	atomic_long_set(&cli->cl_unstable_count, 0);
	INIT_LIST_HEAD(&cli->cl_shrink_list);

	init_waitqueue_head(&cli->cl_destroy_waitq);
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

	/* Set it to possible maximum size. It may be reduced by ocd_brw_size
	 * from OFD after connecting. */
	cli->cl_max_pages_per_rpc = PTLRPC_MAX_BRW_PAGES;

	/* set cl_chunkbits default value to PAGE_SHIFT,
	 * it will be updated at OSC connection time. */
	cli->cl_chunkbits = PAGE_SHIFT;

	if (!strcmp(name, LUSTRE_MDC_NAME)) {
		cli->cl_max_rpcs_in_flight = OBD_MAX_RIF_DEFAULT;
	} else if (totalram_pages >> (20 - PAGE_SHIFT) <= 128 /* MB */) {
		cli->cl_max_rpcs_in_flight = 2;
	} else if (totalram_pages >> (20 - PAGE_SHIFT) <= 256 /* MB */) {
		cli->cl_max_rpcs_in_flight = 3;
	} else if (totalram_pages >> (20 - PAGE_SHIFT) <= 512 /* MB */) {
		cli->cl_max_rpcs_in_flight = 4;
	} else {
		if (osc_on_mdt(obddev->obd_name))
			cli->cl_max_rpcs_in_flight = OBD_MAX_RIF_MAX;
		else
			cli->cl_max_rpcs_in_flight = OBD_MAX_RIF_DEFAULT;
        }

	spin_lock_init(&cli->cl_mod_rpcs_lock);
	spin_lock_init(&cli->cl_mod_rpcs_hist.oh_lock);
	cli->cl_max_mod_rpcs_in_flight = 0;
	cli->cl_mod_rpcs_in_flight = 0;
	cli->cl_close_rpcs_in_flight = 0;
	init_waitqueue_head(&cli->cl_mod_rpcs_waitq);
	cli->cl_mod_tag_bitmap = NULL;

	INIT_LIST_HEAD(&cli->cl_chg_dev_linkage);

	if (connect_op == MDS_CONNECT) {
		cli->cl_max_mod_rpcs_in_flight = cli->cl_max_rpcs_in_flight - 1;
		OBD_ALLOC(cli->cl_mod_tag_bitmap,
			  BITS_TO_LONGS(OBD_MAX_RIF_MAX) * sizeof(long));
		if (cli->cl_mod_tag_bitmap == NULL)
			GOTO(err, rc = -ENOMEM);
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
        memcpy(cli->cl_target_uuid.uuid, lustre_cfg_buf(lcfg, 1),
               LUSTRE_CFG_BUFLEN(lcfg, 1));
        class_import_put(imp);

	if (lustre_cfg_buf(lcfg, 4)) {
		__u32 refnet = libcfs_str2net(lustre_cfg_string(lcfg, 4));

		if (refnet == LNET_NIDNET(LNET_NID_ANY)) {
			rc = -EINVAL;
			CERROR("%s: bad mount option 'network=%s': rc = %d\n",
			       obddev->obd_name, lustre_cfg_string(lcfg, 4),
			       rc);
			GOTO(err_import, rc);
		}
		fake_conn.c_self = LNET_MKNID(refnet, 0);
		imp->imp_connection = &fake_conn;
	}

	rc = client_import_add_conn(imp, &server_uuid, 1);
	if (rc) {
		CERROR("can't add initial connection\n");
		GOTO(err_import, rc);
	}
	imp->imp_connection = NULL;

	cli->cl_import = imp;
	/* cli->cl_max_mds_easize updated by mdc_init_ea_size() */
	cli->cl_max_mds_easize = sizeof(struct lov_mds_md_v3);

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
                                                   LDLM_NAMESPACE_GREEDY,
                                                   ns_type);
        if (obddev->obd_namespace == NULL) {
                CERROR("Unable to create client namespace - %s\n",
                       obddev->obd_name);
                GOTO(err_import, rc = -ENOMEM);
        }

        RETURN(rc);

err_import:
        class_destroy_import(imp);
err_ldlm:
        ldlm_put_ref();
err:
	if (cli->cl_mod_tag_bitmap != NULL)
		OBD_FREE(cli->cl_mod_tag_bitmap,
			 BITS_TO_LONGS(OBD_MAX_RIF_MAX) * sizeof(long));
	cli->cl_mod_tag_bitmap = NULL;
        RETURN(rc);

}
EXPORT_SYMBOL(client_obd_setup);

int client_obd_cleanup(struct obd_device *obddev)
{
	struct client_obd *cli = &obddev->u.cli;
	ENTRY;

	ldlm_namespace_free_post(obddev->obd_namespace);
	obddev->obd_namespace = NULL;

	obd_cleanup_client_import(obddev);
	LASSERT(obddev->u.cli.cl_import == NULL);

	ldlm_put_ref();

	if (cli->cl_mod_tag_bitmap != NULL)
		OBD_FREE(cli->cl_mod_tag_bitmap,
			 BITS_TO_LONGS(OBD_MAX_RIF_MAX) * sizeof(long));
	cli->cl_mod_tag_bitmap = NULL;

	RETURN(0);
}
EXPORT_SYMBOL(client_obd_cleanup);

/* ->o_connect() method for client side (OSC and MDC and MGC) */
int client_connect_import(const struct lu_env *env,
                          struct obd_export **exp,
                          struct obd_device *obd, struct obd_uuid *cluuid,
                          struct obd_connect_data *data, void *localdata)
{
	struct client_obd       *cli    = &obd->u.cli;
	struct obd_import       *imp    = cli->cl_import;
	struct obd_connect_data *ocd;
	struct lustre_handle    conn    = { 0 };
	int                     rc;
	ENTRY;

	*exp = NULL;
	down_write(&cli->cl_sem);
	if (cli->cl_conn_count > 0)
                GOTO(out_sem, rc = -EALREADY);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		GOTO(out_sem, rc);

	cli->cl_conn_count++;
	*exp = class_conn2export(&conn);

	LASSERT(obd->obd_namespace);

	imp->imp_dlm_handle = conn;
	rc = ptlrpc_init_import(imp);
	if (rc != 0)
		GOTO(out_ldlm, rc);

	ocd = &imp->imp_connect_data;
	if (data) {
		*ocd = *data;
		imp->imp_connect_flags_orig = data->ocd_connect_flags;
		imp->imp_connect_flags2_orig = data->ocd_connect_flags2;
	}

	rc = ptlrpc_connect_import(imp);
	if (rc != 0) {
		LASSERT(imp->imp_state == LUSTRE_IMP_DISCON);
		GOTO(out_ldlm, rc);
	}
	LASSERT(*exp != NULL && (*exp)->exp_connection);

	if (data) {
		LASSERTF((ocd->ocd_connect_flags & data->ocd_connect_flags) ==
			 ocd->ocd_connect_flags, "old %#llx, new %#llx\n",
			 data->ocd_connect_flags, ocd->ocd_connect_flags);
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
EXPORT_SYMBOL(client_connect_import);

int client_disconnect_export(struct obd_export *exp)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct client_obd *cli;
        struct obd_import *imp;
        int rc = 0, err;
        ENTRY;

        if (!obd) {
		CERROR("invalid export for disconnect: exp %p cookie %#llx\n",
                       exp, exp ? exp->exp_handle.h_cookie : -1);
                RETURN(-EINVAL);
        }

        cli = &obd->u.cli;
        imp = cli->cl_import;

	down_write(&cli->cl_sem);
	CDEBUG(D_INFO, "disconnect %s - %zu\n", obd->obd_name,
		cli->cl_conn_count);

	if (cli->cl_conn_count == 0) {
                CERROR("disconnecting disconnected device (%s)\n",
                       obd->obd_name);
                GOTO(out_disconnect, rc = -EINVAL);
        }

        cli->cl_conn_count--;
	if (cli->cl_conn_count != 0)
                GOTO(out_disconnect, rc = 0);

	/* Mark import deactivated now, so we don't try to reconnect if any
	 * of the cleanup RPCs fails (e.g. LDLM cancel, etc).  We don't
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
                                       obd->obd_force ? LCF_LOCAL : 0, NULL);
                ldlm_namespace_free_prior(obd->obd_namespace, imp, obd->obd_force);
        }

	/* There's no need to hold sem while disconnecting an import,
	 * and it may actually cause deadlock in GSS. */
	up_write(&cli->cl_sem);
	rc = ptlrpc_disconnect_import(imp, 0);
	down_write(&cli->cl_sem);

        ptlrpc_invalidate_import(imp);

        EXIT;

out_disconnect:
	/* Use server style - class_disconnect should be always called for
	 * o_disconnect. */
        err = class_disconnect(exp);
        if (!rc && err)
                rc = err;

	up_write(&cli->cl_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(client_disconnect_export);

#ifdef HAVE_SERVER_SUPPORT
int server_disconnect_export(struct obd_export *exp)
{
        int rc;
        ENTRY;

	/* Disconnect early so that clients can't keep using export. */
	rc = class_disconnect(exp);
	/* Close import to avoid sending any requests. */
	if (exp->exp_imp_reverse)
		ptlrpc_cleanup_imp(exp->exp_imp_reverse);

	ldlm_bl_thread_wakeup();

        /* complete all outstanding replies */
	spin_lock(&exp->exp_lock);
	while (!list_empty(&exp->exp_outstanding_replies)) {
		struct ptlrpc_reply_state *rs =
			list_entry(exp->exp_outstanding_replies.next,
				       struct ptlrpc_reply_state, rs_exp_list);
		struct ptlrpc_service_part *svcpt = rs->rs_svcpt;

		spin_lock(&svcpt->scp_rep_lock);

		list_del_init(&rs->rs_exp_list);

		spin_lock(&rs->rs_lock);
		/* clear rs_convert_lock to make sure rs is handled and put */
		rs->rs_convert_lock = 0;
		ptlrpc_schedule_difficult_reply(rs);
		spin_unlock(&rs->rs_lock);

		spin_unlock(&svcpt->scp_rep_lock);
	}
	spin_unlock(&exp->exp_lock);

	RETURN(rc);
}
EXPORT_SYMBOL(server_disconnect_export);

/* --------------------------------------------------------------------------
 * from old lib/target.c
 * -------------------------------------------------------------------------- */

static int target_handle_reconnect(struct lustre_handle *conn,
                                   struct obd_export *exp,
                                   struct obd_uuid *cluuid)
{
	struct obd_device *target;
	struct lustre_handle *hdl;
	cfs_time_t now;
	cfs_time_t deadline;
	int timeout;
	int rc = 0;
	ENTRY;

	hdl = &exp->exp_imp_reverse->imp_remote_handle;
	if (!exp->exp_connection || !lustre_handle_is_used(hdl)) {
		conn->cookie = exp->exp_handle.h_cookie;
		CDEBUG(D_HA, "connect export for UUID '%s' at %p,"
		       " cookie %#llx\n", cluuid->uuid, exp, conn->cookie);
		RETURN(0);
	}

	target = exp->exp_obd;

	/* Might be a re-connect after a partition. */
	if (memcmp(&conn->cookie, &hdl->cookie, sizeof conn->cookie)) {
		LCONSOLE_WARN("%s: already connected client %s (at %s) "
			      "with handle %#llx. Rejecting client "
			      "with the same UUID trying to reconnect "
			      "with handle %#llx\n", target->obd_name,
			      obd_uuid2str(&exp->exp_client_uuid),
			      obd_export_nid2str(exp),
			      hdl->cookie, conn->cookie);
		memset(conn, 0, sizeof *conn);
		/* target_handle_connect() treats EALREADY and
		 * -EALREADY differently.  -EALREADY is an error
		 * (same UUID, different handle). */
		RETURN(-EALREADY);
	}

	if (!target->obd_recovering) {
		LCONSOLE_WARN("%s: Client %s (at %s) reconnecting\n",
			target->obd_name, obd_uuid2str(&exp->exp_client_uuid),
			obd_export_nid2str(exp));
		GOTO(out_already, rc);
	}

	now = cfs_time_current();
	deadline = target->obd_recovery_timer.expires;
	if (cfs_time_before(now, deadline)) {
		struct target_distribute_txn_data *tdtd =
					class_exp2tgt(exp)->lut_tdtd;
		int size = 0;
		int count = 0;
		char *buf = NULL;

		timeout = cfs_duration_sec(cfs_time_sub(deadline, now));
		if (tdtd && tdtd->tdtd_show_update_logs_retrievers)
			buf = tdtd->tdtd_show_update_logs_retrievers(
				tdtd->tdtd_show_retrievers_cbdata,
				&size, &count);

		if (count > 0)
			LCONSOLE_WARN("%s: Recovery already passed deadline "
				      "%d:%.02d. It is due to DNE recovery "
				      "failed/stuck on the %d MDT(s):%s. "
				      "Please wait until all MDTs recovered "
				      "or abort the recovery by force.\n",
				      target->obd_name, timeout / 60,
				      timeout % 60, count,
				      buf ? buf : "unknown (not enough RAM)");
		else
			LCONSOLE_WARN("%s: Recovery already passed deadline "
				      "%d:%.02d. If you do not want to wait "
				      "more, please abort the recovery by "
				      "force.\n", target->obd_name,
				      timeout / 60, timeout % 60);

		if (buf != NULL)
			OBD_FREE(buf, size);
	} else {
		timeout = cfs_duration_sec(cfs_time_sub(now, deadline));
		LCONSOLE_WARN("%s: Recovery already passed deadline"
			" %d:%.02d, It is most likely due to DNE"
			" recovery is failed or stuck, please wait a"
			" few more minutes or abort the recovery.\n",
			target->obd_name, timeout / 60, timeout % 60);
	}

out_already:
	conn->cookie = exp->exp_handle.h_cookie;
	/* target_handle_connect() treats EALREADY and
	 * -EALREADY differently.  EALREADY means we are
	 * doing a valid reconnect from the same client. */
	RETURN(EALREADY);
}

static void
check_and_start_recovery_timer(struct obd_device *obd,
                               struct ptlrpc_request *req, int new_client);

/**
 * update flags for import during reconnect process
 */
static int rev_import_flags_update(struct obd_import *revimp,
				   struct ptlrpc_request *req)
{
	int rc;
	struct obd_connect_data *data;

	data = req_capsule_client_get(&req->rq_pill, &RMF_CONNECT_DATA);

	if (data->ocd_connect_flags & OBD_CONNECT_AT)
		revimp->imp_msghdr_flags |= MSGHDR_AT_SUPPORT;
	else
		revimp->imp_msghdr_flags &= ~MSGHDR_AT_SUPPORT;

	revimp->imp_msghdr_flags |= MSGHDR_CKSUM_INCOMPAT18;

	rc = sptlrpc_import_sec_adapt(revimp, req->rq_svc_ctx, &req->rq_flvr);
	if (rc) {
		CERROR("%s: cannot get reverse import %s security: rc = %d\n",
			revimp->imp_client->cli_name,
			libcfs_id2str(req->rq_peer), rc);
		return rc;
	}

	return 0;
}

/**
 * Allocate a new reverse import for an export.
 *
 * \retval -errno in case error hit
 * \retval 0 if reverse import correctly init
 **/
int rev_import_init(struct obd_export *export)
{
	struct obd_device *obd = export->exp_obd;
	struct obd_import *revimp;

	LASSERT(export->exp_imp_reverse == NULL);

	revimp = class_new_import(obd);
	if (revimp == NULL)
		return -ENOMEM;

	revimp->imp_remote_handle.cookie = 0ULL;
	revimp->imp_client = &obd->obd_ldlm_client;
	revimp->imp_dlm_fake = 1;

	/* it is safe to connect import in new state as no sends possible */
	spin_lock(&export->exp_lock);
	export->exp_imp_reverse = revimp;
	spin_unlock(&export->exp_lock);
	class_import_put(revimp);

	return 0;
}
EXPORT_SYMBOL(rev_import_init);

/**
 * Handle reconnect for an export.
 *
 * \param exp export to handle reconnect process
 * \param req client reconnect request
 *
 * \retval -rc in case securitfy flavor can't be changed
 * \retval 0 in case none problems
 */
static int rev_import_reconnect(struct obd_export *exp,
				struct ptlrpc_request *req)
{
	struct obd_import *revimp = exp->exp_imp_reverse;
	struct lustre_handle *lh;
	int rc;

	/* avoid sending a request until import flags are changed */
	ptlrpc_import_enter_resend(revimp);

	if (revimp->imp_connection != NULL)
		ptlrpc_connection_put(revimp->imp_connection);

	/*
	 * client from recovery don't have a handle so we need to take from
	 * request. it may produce situation when wrong client connected
	 * to recovery as we trust a client uuid
	 */
	lh = req_capsule_client_get(&req->rq_pill, &RMF_CONN);
	revimp->imp_remote_handle = *lh;

	/* unknown versions will be caught in
	 * ptlrpc_handle_server_req_in->lustre_unpack_msg() */
	revimp->imp_msg_magic = req->rq_reqmsg->lm_magic;

	revimp->imp_connection = ptlrpc_connection_addref(exp->exp_connection);

	rc = rev_import_flags_update(revimp, req);
	if (rc != 0) {
		/* it is safe to still be in RECOVERY phase as we are not able
		 * to setup correct security flavor so requests are not able to
		 * be delivered correctly */
		return rc;
	}

	/* resend all rpc's via new connection */
	return ptlrpc_import_recovery_state_machine(revimp);
}

int target_handle_connect(struct ptlrpc_request *req)
{
	struct obd_device *target = NULL;
	struct obd_export *export = NULL;
	/* connect handle - filled from target_handle_reconnect in
	 * reconnect case */
	struct lustre_handle conn;
	struct lustre_handle *tmp;
        struct obd_uuid cluuid;
        char *str;
        int rc = 0;
        char *target_start;
        int target_len;
	bool	 mds_conn = false, lw_client = false, initial_conn = false;
	bool	 mds_mds_conn = false;
	bool	 new_mds_mds_conn = false;
        struct obd_connect_data *data, *tmpdata;
        int size, tmpsize;
        lnet_nid_t *client_nid = NULL;
	ENTRY;

        OBD_RACE(OBD_FAIL_TGT_CONN_RACE);

        str = req_capsule_client_get(&req->rq_pill, &RMF_TGTUUID);
        if (str == NULL) {
                DEBUG_REQ(D_ERROR, req, "bad target UUID for connect");
                GOTO(out, rc = -EINVAL);
        }

	target = class_dev_by_str(str);
	if (!target) {
		deuuidify(str, NULL, &target_start, &target_len);
		LCONSOLE_ERROR_MSG(0x137, "%s: not available for connect "
				   "from %s (no target). If you are running "
				   "an HA pair check that the target is "
				   "mounted on the other server.\n", str,
				   libcfs_nid2str(req->rq_peer.nid));
		GOTO(out, rc = -ENODEV);
	}

	spin_lock(&target->obd_dev_lock);

	target->obd_conn_inprogress++;

	if (target->obd_stopping || !target->obd_set_up) {
		spin_unlock(&target->obd_dev_lock);

		deuuidify(str, NULL, &target_start, &target_len);
		LCONSOLE_INFO("%.*s: Not available for connect from %s (%s)\n",
			      target_len, target_start,
			      libcfs_nid2str(req->rq_peer.nid),
			      (target->obd_stopping ?
			       "stopping" : "not set up"));
		GOTO(out, rc = -ENODEV);
	}

        if (target->obd_no_conn) {
		spin_unlock(&target->obd_dev_lock);

		CDEBUG(D_INFO, "%s: Temporarily refusing client connection "
			       "from %s\n", target->obd_name,
			       libcfs_nid2str(req->rq_peer.nid));
		GOTO(out, rc = -EAGAIN);
	}

	spin_unlock(&target->obd_dev_lock);

        str = req_capsule_client_get(&req->rq_pill, &RMF_CLUUID);
        if (str == NULL) {
                DEBUG_REQ(D_ERROR, req, "bad client UUID for connect");
                GOTO(out, rc = -EINVAL);
        }

        obd_str2uuid(&cluuid, str);

        tmp = req_capsule_client_get(&req->rq_pill, &RMF_CONN);
        if (tmp == NULL)
                GOTO(out, rc = -EPROTO);

        conn = *tmp;

        size = req_capsule_get_size(&req->rq_pill, &RMF_CONNECT_DATA,
                                    RCL_CLIENT);
        data = req_capsule_client_get(&req->rq_pill, &RMF_CONNECT_DATA);
        if (!data)
                GOTO(out, rc = -EPROTO);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                GOTO(out, rc);

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	/* Don't allow clients to connect that are using old 1.8 format
	 * protocol conventions (LUSTRE_MSG_MAGIC_v1, !MSGHDR_CKSUM_INCOMPAT18,
	 * ldlm_flock_policy_wire format, MDT_ATTR_xTIME_SET, etc).  The
	 * FULL20 flag should be set on all connections since 2.0, but no
	 * longer affects behaviour.
	 *
	 * Later this check will be disabled and the flag can be retired
	 * completely once interop with 3.0 is no longer needed.
	 */
	if (!(data->ocd_connect_flags & OBD_CONNECT_FULL20))
		GOTO(out, rc = -EPROTO);
#endif

	if (lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_LIBCLIENT) {
		if (data->ocd_version < LUSTRE_VERSION_CODE -
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

	/* Note: lw_client is needed in MDS-MDS failover during update log
	 * processing, so we needs to allow lw_client to be connected at
	 * anytime, instead of only the initial connection */
	lw_client = (data->ocd_connect_flags & OBD_CONNECT_LIGHTWEIGHT) != 0;

	if (lustre_msg_get_op_flags(req->rq_reqmsg) & MSG_CONNECT_INITIAL) {
		initial_conn = true;
		mds_conn = (data->ocd_connect_flags & OBD_CONNECT_MDS) != 0;
		mds_mds_conn = (data->ocd_connect_flags &
				OBD_CONNECT_MDS_MDS) != 0;

		/* OBD_CONNECT_MNE_SWAB is defined as OBD_CONNECT_MDS_MDS
		 * for Imperative Recovery connection from MGC to MGS.
		 *
		 * Via check OBD_CONNECT_FID, we can distinguish whether
		 * the OBD_CONNECT_MDS_MDS/OBD_CONNECT_MNE_SWAB is from
		 * MGC or MDT. */
		if (!lw_client &&
		    (data->ocd_connect_flags & OBD_CONNECT_MDS_MDS) &&
		    (data->ocd_connect_flags & OBD_CONNECT_FID) &&
		    (data->ocd_connect_flags & OBD_CONNECT_VERSION)) {
			__u32 major = OBD_OCD_VERSION_MAJOR(data->ocd_version);
			__u32 minor = OBD_OCD_VERSION_MINOR(data->ocd_version);
			__u32 patch = OBD_OCD_VERSION_PATCH(data->ocd_version);

			/* We do not support the MDT-MDT interoperations with
			 * different version MDT because of protocol changes. */
			if (unlikely(major != LUSTRE_MAJOR ||
				     minor != LUSTRE_MINOR ||
				     abs(patch - LUSTRE_PATCH) > 3)) {
				LCONSOLE_WARN("%s (%u.%u.%u.%u) refused the "
					"connection from different version MDT "
					"(%d.%d.%d.%d) %s %s\n",
					target->obd_name, LUSTRE_MAJOR,
					LUSTRE_MINOR, LUSTRE_PATCH, LUSTRE_FIX,
					major, minor, patch,
					OBD_OCD_VERSION_FIX(data->ocd_version),
					libcfs_nid2str(req->rq_peer.nid), str);

				GOTO(out, rc = -EPROTO);
			}
		}
	}

        /* lctl gets a backstage, all-access pass. */
        if (obd_uuid_equals(&cluuid, &target->obd_uuid))
                goto dont_check_exports;

        export = cfs_hash_lookup(target->obd_uuid_hash, &cluuid);
        if (!export)
                goto no_export;

	/* We've found an export in the hash. */

	spin_lock(&export->exp_lock);

	if (export->exp_connecting) { /* bug 9635, et. al. */
		spin_unlock(&export->exp_lock);
		LCONSOLE_WARN("%s: Export %p already connecting from %s\n",
			      export->exp_obd->obd_name, export,
			      libcfs_nid2str(req->rq_peer.nid));
		class_export_put(export);
		export = NULL;
		rc = -EALREADY;
	} else if ((mds_conn || (lw_client && initial_conn) ||
		   data->ocd_connect_flags & OBD_CONNECT_MDS_MDS) &&
		   export->exp_connection != NULL) {
		spin_unlock(&export->exp_lock);
		if (req->rq_peer.nid != export->exp_connection->c_peer.nid) {
			/* MDS or LWP reconnected after failover. */
			LCONSOLE_WARN("%s: Received %s connection from "
			    "%s, removing former export from %s\n",
			    target->obd_name, mds_conn ? "MDS" : "LWP",
			    libcfs_nid2str(req->rq_peer.nid),
			    libcfs_nid2str(export->exp_connection->c_peer.nid));
		} else {
			/* New MDS connection from the same NID. */
			LCONSOLE_WARN("%s: Received new %s connection from "
				"%s, removing former export from same NID\n",
				target->obd_name, mds_conn ? "MDS" : "LWP",
				libcfs_nid2str(req->rq_peer.nid));
		}

		if (req->rq_peer.nid == export->exp_connection->c_peer.nid &&
		    data->ocd_connect_flags & OBD_CONNECT_MDS_MDS) {
			/* Because exports between MDTs will always be
			 * kept, let's do not fail such export if they
			 * come from the same NID, otherwise it might
			 * cause eviction between MDTs, which might
			 * cause namespace inconsistency */
			spin_lock(&export->exp_lock);
			export->exp_connecting = 1;
			spin_unlock(&export->exp_lock);
			conn.cookie = export->exp_handle.h_cookie;
			rc = EALREADY;
		} else {
			class_fail_export(export);
			class_export_put(export);
			export = NULL;
			rc = 0;
		}
	} else if (export->exp_connection != NULL && initial_conn &&
		   req->rq_peer.nid != export->exp_connection->c_peer.nid) {
		spin_unlock(&export->exp_lock);
		/* In MDS failover we have static UUID but NID can change. */
                LCONSOLE_WARN("%s: Client %s seen on new nid %s when "
                              "existing nid %s is already connected\n",
                              target->obd_name, cluuid.uuid,
                              libcfs_nid2str(req->rq_peer.nid),
                              libcfs_nid2str(
                                      export->exp_connection->c_peer.nid));
                rc = -EALREADY;
                class_export_put(export);
                export = NULL;
        } else {
		export->exp_connecting = 1;
		spin_unlock(&export->exp_lock);
		LASSERT(export->exp_obd == target);

		rc = target_handle_reconnect(&conn, export, &cluuid);
	}

        /* If we found an export, we already unlocked. */
        if (!export) {
no_export:
                OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_DELAY_CONNECT, 2 * obd_timeout);
        } else if (req->rq_export == NULL &&
		   atomic_read(&export->exp_rpc_count) > 0) {
                LCONSOLE_WARN("%s: Client %s (at %s) refused connection, "
                              "still busy with %d references\n",
                              target->obd_name, cluuid.uuid,
                              libcfs_nid2str(req->rq_peer.nid),
			      atomic_read(&export->exp_refcount));
                GOTO(out, rc = -EBUSY);
        } else if (lustre_msg_get_conn_cnt(req->rq_reqmsg) == 1) {
                if (!strstr(cluuid.uuid, "mdt"))
                        LCONSOLE_WARN("%s: Rejecting reconnect from the "
                                      "known client %s (at %s) because it "
                                      "is indicating it is a new client",
                                      target->obd_name, cluuid.uuid,
                                      libcfs_nid2str(req->rq_peer.nid));
                GOTO(out, rc = -EALREADY);
        } else {
                OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_DELAY_RECONNECT, 2 * obd_timeout);
        }

        if (rc < 0) {
                GOTO(out, rc);
        }

	CDEBUG(D_HA, "%s: connection from %s@%s %st%llu exp %p cur %ld last %ld\n",
               target->obd_name, cluuid.uuid, libcfs_nid2str(req->rq_peer.nid),
              target->obd_recovering ? "recovering/" : "", data->ocd_transno,
              export, (long)cfs_time_current_sec(),
              export ? (long)export->exp_last_request_time : 0);

	/* If this is the first time a client connects, reset the recovery
	 * timer. Discard lightweight connections which might be local. */
	if (!lw_client && rc == 0 && target->obd_recovering)
		check_and_start_recovery_timer(target, req, export == NULL);

	/* We want to handle EALREADY but *not* -EALREADY from
	 * target_handle_reconnect(), return reconnection state in a flag. */
        if (rc == EALREADY) {
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECONNECT);
                rc = 0;
        } else {
                LASSERT(rc == 0);
        }

	/* Tell the client if we support replayable requests. */
        if (target->obd_replayable)
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_REPLAYABLE);
        client_nid = &req->rq_peer.nid;

        if (export == NULL) {
		/* allow lightweight connections during recovery */
		/* allow "new" MDT to be connected during recovery, since we
		 * need retrieve recovery update records from it */
		if (target->obd_recovering && !lw_client && !mds_mds_conn) {
                        cfs_time_t t;
			int	c; /* connected */
			int	i; /* in progress */
			int	k; /* known */
			int	s; /* stale/evicted */

			c = atomic_read(&target->obd_connected_clients);
			i = atomic_read(&target->obd_lock_replay_clients);
			k = target->obd_max_recoverable_clients;
			s = target->obd_stale_clients;
			t = target->obd_recovery_timer.expires;
			t = cfs_time_sub(t, cfs_time_current());
			t = cfs_duration_sec(t);
			LCONSOLE_WARN("%s: Denying connection for new client %s"
				      "(at %s), waiting for %d known clients "
				      "(%d recovered, %d in progress, and %d "
				      "evicted) to recover in %d:%.02d\n",
				      target->obd_name, cluuid.uuid,
				      libcfs_nid2str(req->rq_peer.nid), k,
				      c - i, i, s, (int)t / 60,
				      (int)t % 60);
			rc = -EBUSY;
		} else {
dont_check_exports:
			rc = obd_connect(req->rq_svc_thread->t_env,
					 &export, target, &cluuid, data,
					 client_nid);
			if (mds_conn && OBD_FAIL_CHECK(OBD_FAIL_TGT_RCVG_FLAG))
				lustre_msg_add_op_flags(req->rq_repmsg,
							MSG_CONNECT_RECOVERING);
			if (rc == 0) {
				conn.cookie = export->exp_handle.h_cookie;
				rc = rev_import_init(export);
			}

			if (mds_mds_conn)
				new_mds_mds_conn = true;
		}
	} else {
		rc = obd_reconnect(req->rq_svc_thread->t_env,
				   export, target, &cluuid, data, client_nid);
	}
	if (rc)
		GOTO(out, rc);

	LASSERT(target->u.obt.obt_magic == OBT_MAGIC);
	data->ocd_instance = target->u.obt.obt_instance;

        /* Return only the parts of obd_connect_data that we understand, so the
         * client knows that we don't understand the rest. */
        if (data) {
                tmpsize = req_capsule_get_size(&req->rq_pill, &RMF_CONNECT_DATA,
                                               RCL_SERVER);
                tmpdata = req_capsule_server_get(&req->rq_pill,
                                                 &RMF_CONNECT_DATA);
                /* Don't use struct assignment here, because the client reply
                 * buffer may be smaller/larger than the local struct
                 * obd_connect_data. */
                memcpy(tmpdata, data, min(tmpsize, size));
        }

        /* If the client and the server are the same node, we will already
         * have an export that really points to the client's DLM export,
         * because we have a shared handles table.
         *
         * XXX this will go away when shaver stops sending the "connect" handle
         * in the real "remote handle" field of the request --phik 24 Apr 2003
         */
	ptlrpc_request_change_export(req, export);

	spin_lock(&export->exp_lock);
	if (export->exp_conn_cnt >= lustre_msg_get_conn_cnt(req->rq_reqmsg)) {
		spin_unlock(&export->exp_lock);
		CDEBUG(D_RPCTRACE, "%s: %s already connected at greater "
		       "or equal conn_cnt: %d >= %d\n",
                       cluuid.uuid, libcfs_nid2str(req->rq_peer.nid),
                       export->exp_conn_cnt,
                       lustre_msg_get_conn_cnt(req->rq_reqmsg));

                GOTO(out, rc = -EALREADY);
        }
        LASSERT(lustre_msg_get_conn_cnt(req->rq_reqmsg) > 0);
        export->exp_conn_cnt = lustre_msg_get_conn_cnt(req->rq_reqmsg);

	/* Don't evict liblustre clients for not pinging. */
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
		/* Check to see if connection came from another NID. */
                if ((export->exp_connection->c_peer.nid != req->rq_peer.nid) &&
		    !hlist_unhashed(&export->exp_nid_hash))
                        cfs_hash_del(export->exp_obd->obd_nid_hash,
                                     &export->exp_connection->c_peer.nid,
                                     &export->exp_nid_hash);

                ptlrpc_connection_put(export->exp_connection);
        }

	export->exp_connection = ptlrpc_connection_get(req->rq_peer,
						       req->rq_self,
						       &cluuid);
	if (hlist_unhashed(&export->exp_nid_hash))
		cfs_hash_add(export->exp_obd->obd_nid_hash,
			     &export->exp_connection->c_peer.nid,
			     &export->exp_nid_hash);

	lustre_msg_set_handle(req->rq_repmsg, &conn);

	rc = rev_import_reconnect(export, req);
	if (rc != 0)
		GOTO(out, rc);

	if (target->obd_recovering && !export->exp_in_recovery && !lw_client) {
                int has_transno;
                __u64 transno = data->ocd_transno;

		spin_lock(&export->exp_lock);
		/* possible race with class_disconnect_stale_exports,
		 * export may be already in the eviction process */
		if (export->exp_failed) {
			spin_unlock(&export->exp_lock);
			GOTO(out, rc = -ENODEV);
		}
		export->exp_in_recovery = 1;
		export->exp_req_replay_needed = 1;
		export->exp_lock_replay_needed = 1;
		spin_unlock(&export->exp_lock);

                has_transno = !!(lustre_msg_get_op_flags(req->rq_reqmsg) &
                                 MSG_CONNECT_TRANSNO);
                if (has_transno && transno == 0)
                        CWARN("Connect with zero transno!\n");

                if (has_transno && transno > 0 &&
                    transno < target->obd_next_recovery_transno &&
                    transno > target->obd_last_committed) {
			/* Another way is to use cmpxchg() to be lock-free. */
			spin_lock(&target->obd_recovery_task_lock);
			if (transno < target->obd_next_recovery_transno)
				target->obd_next_recovery_transno = transno;
			spin_unlock(&target->obd_recovery_task_lock);
                }

		atomic_inc(&target->obd_req_replay_clients);
		atomic_inc(&target->obd_lock_replay_clients);
		/* Note: MDS-MDS connection is allowed to be connected during
		 * recovery, no matter if the exports needs to be recoveried.
		 * Because we need retrieve updates logs from all other MDTs.
		 * So if the MDS-MDS export is new, obd_max_recoverable_clients
		 * also needs to be increased to match other recovery checking
		 * condition. */
		if (new_mds_mds_conn)
			target->obd_max_recoverable_clients++;
		if (atomic_inc_return(&target->obd_connected_clients) ==
		    target->obd_max_recoverable_clients)
			wake_up(&target->obd_next_transno_waitq);
	}

        /* Tell the client we're in recovery, when client is involved in it. */
	if (target->obd_recovering && !lw_client)
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECOVERING);

out:
	if (export) {
		spin_lock(&export->exp_lock);
		export->exp_connecting = 0;
		spin_unlock(&export->exp_lock);

		class_export_put(export);
	}
	if (target != NULL) {
		spin_lock(&target->obd_dev_lock);
		target->obd_conn_inprogress--;
		spin_unlock(&target->obd_dev_lock);
		class_decref(target, "find", current);
	}
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

	/* Keep the rq_export around so we can send the reply. */
        req->rq_status = obd_disconnect(class_export_get(req->rq_export));

        RETURN(0);
}

void target_destroy_export(struct obd_export *exp)
{
	struct obd_import	*imp = NULL;
	/* exports created from last_rcvd data, and "fake"
	   exports created by lctl don't have an import */
	spin_lock(&exp->exp_lock);
	if (exp->exp_imp_reverse != NULL) {
		imp = exp->exp_imp_reverse;
		exp->exp_imp_reverse = NULL;
	}
	spin_unlock(&exp->exp_lock);
	if (imp != NULL)
		client_destroy_import(imp);

	LASSERT_ATOMIC_ZERO(&exp->exp_locks_count);
	LASSERT_ATOMIC_ZERO(&exp->exp_rpc_count);
	LASSERT_ATOMIC_ZERO(&exp->exp_cb_count);
	LASSERT_ATOMIC_ZERO(&exp->exp_replay_count);
}
EXPORT_SYMBOL(target_destroy_export);

/*
 * Recovery functions
 */
static void target_request_copy_get(struct ptlrpc_request *req)
{
	class_export_rpc_inc(req->rq_export);
	LASSERT(list_empty(&req->rq_list));
	INIT_LIST_HEAD(&req->rq_replay_list);

	/* Increase refcount to keep request in queue. */
	atomic_inc(&req->rq_refcount);
	/* Let export know it has replays to be handled. */
	atomic_inc(&req->rq_export->exp_replay_count);
}

static void target_request_copy_put(struct ptlrpc_request *req)
{
	LASSERT(list_empty(&req->rq_replay_list));
	LASSERT_ATOMIC_POS(&req->rq_export->exp_replay_count);

	atomic_dec(&req->rq_export->exp_replay_count);
	class_export_rpc_dec(req->rq_export);
	ptlrpc_server_drop_request(req);
}

static int target_exp_enqueue_req_replay(struct ptlrpc_request *req)
{
        __u64                  transno = lustre_msg_get_transno(req->rq_reqmsg);
        struct obd_export     *exp = req->rq_export;
        struct ptlrpc_request *reqiter;
	struct ptlrpc_request *dup_req = NULL;
        int                    dup = 0;

        LASSERT(exp);

	spin_lock(&exp->exp_lock);
	list_for_each_entry(reqiter, &exp->exp_req_replay_queue,
                                rq_replay_list) {
                if (lustre_msg_get_transno(reqiter->rq_reqmsg) == transno) {
			dup_req = reqiter;
                        dup = 1;
                        break;
                }
        }

        if (dup) {
		/* We expect it with RESENT and REPLAY flags. */
                if ((lustre_msg_get_flags(req->rq_reqmsg) &
                     (MSG_RESENT | MSG_REPLAY)) != (MSG_RESENT | MSG_REPLAY))
                        CERROR("invalid flags %x of resent replay\n",
                               lustre_msg_get_flags(req->rq_reqmsg));

		if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
			__u32 new_conn;

			new_conn = lustre_msg_get_conn_cnt(req->rq_reqmsg);
			if (new_conn >
			    lustre_msg_get_conn_cnt(dup_req->rq_reqmsg))
				lustre_msg_set_conn_cnt(dup_req->rq_reqmsg,
							new_conn);
		}
        } else {
		list_add_tail(&req->rq_replay_list,
                                  &exp->exp_req_replay_queue);
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

static void target_finish_recovery(struct lu_target *lut)
{
	struct obd_device *obd = lut->lut_obd;
        ENTRY;

	/* Only log a recovery message when recovery has occurred. */
	if (obd->obd_recovery_start) {
		time64_t now = ktime_get_real_seconds();
		time64_t elapsed_time;

		elapsed_time = max_t(time64_t, now - obd->obd_recovery_start, 1);
		LCONSOLE_INFO("%s: Recovery over after %lld:%.02lld, of %d clients "
			"%d recovered and %d %s evicted.\n", obd->obd_name,
			(s64)elapsed_time / 60, (s64)elapsed_time % 60,
			obd->obd_max_recoverable_clients,
			atomic_read(&obd->obd_connected_clients),
			obd->obd_stale_clients,
			obd->obd_stale_clients == 1 ? "was" : "were");
	}

	ldlm_reprocess_recovery_done(obd->obd_namespace);
	spin_lock(&obd->obd_recovery_task_lock);
	if (!list_empty(&obd->obd_req_replay_queue) ||
	    !list_empty(&obd->obd_lock_replay_queue) ||
	    !list_empty(&obd->obd_final_req_queue)) {
                CERROR("%s: Recovery queues ( %s%s%s) are not empty\n",
                       obd->obd_name,
		       list_empty(&obd->obd_req_replay_queue) ? "" : "req ",
		       list_empty(&obd->obd_lock_replay_queue) ? \
                               "" : "lock ",
		       list_empty(&obd->obd_final_req_queue) ? \
                               "" : "final ");
		spin_unlock(&obd->obd_recovery_task_lock);
		LBUG();
	}
	spin_unlock(&obd->obd_recovery_task_lock);

	obd->obd_recovery_end = ktime_get_real_seconds();

	/* When recovery finished, cleanup orphans on MDS and OST. */
        if (OBT(obd) && OBP(obd, postrecov)) {
                int rc = OBP(obd, postrecov)(obd);
                if (rc < 0)
                        LCONSOLE_WARN("%s: Post recovery failed, rc %d\n",
                                      obd->obd_name, rc);
        }
        EXIT;
}

static void abort_req_replay_queue(struct obd_device *obd)
{
	struct ptlrpc_request *req, *n;
	struct list_head abort_list;

	INIT_LIST_HEAD(&abort_list);
	spin_lock(&obd->obd_recovery_task_lock);
	list_splice_init(&obd->obd_req_replay_queue, &abort_list);
	spin_unlock(&obd->obd_recovery_task_lock);
	list_for_each_entry_safe(req, n, &abort_list, rq_list) {
                DEBUG_REQ(D_WARNING, req, "aborted:");
                req->rq_status = -ENOTCONN;
                if (ptlrpc_error(req)) {
                        DEBUG_REQ(D_ERROR, req,
                                  "failed abort_req_reply; skipping");
                }
                target_exp_dequeue_req_replay(req);
                target_request_copy_put(req);
        }
}

static void abort_lock_replay_queue(struct obd_device *obd)
{
	struct ptlrpc_request *req, *n;
	struct list_head abort_list;

	INIT_LIST_HEAD(&abort_list);
	spin_lock(&obd->obd_recovery_task_lock);
	list_splice_init(&obd->obd_lock_replay_queue, &abort_list);
	spin_unlock(&obd->obd_recovery_task_lock);
	list_for_each_entry_safe(req, n, &abort_list, rq_list) {
                DEBUG_REQ(D_ERROR, req, "aborted:");
                req->rq_status = -ENOTCONN;
                if (ptlrpc_error(req)) {
                        DEBUG_REQ(D_ERROR, req,
                                  "failed abort_lock_reply; skipping");
                }
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
        struct ptlrpc_request *req, *n;
	struct list_head clean_list;

	INIT_LIST_HEAD(&clean_list);
	spin_lock(&obd->obd_dev_lock);
	if (!obd->obd_recovering) {
		spin_unlock(&obd->obd_dev_lock);
		EXIT;
		return;
	}
	obd->obd_recovering = obd->obd_abort_recovery = 0;
	spin_unlock(&obd->obd_dev_lock);

	spin_lock(&obd->obd_recovery_task_lock);
	target_cancel_recovery_timer(obd);
	list_splice_init(&obd->obd_req_replay_queue, &clean_list);
	spin_unlock(&obd->obd_recovery_task_lock);

	list_for_each_entry_safe(req, n, &clean_list, rq_list) {
		LASSERT(req->rq_reply_state == NULL);
		target_exp_dequeue_req_replay(req);
		target_request_copy_put(req);
	}

	spin_lock(&obd->obd_recovery_task_lock);
	list_splice_init(&obd->obd_lock_replay_queue, &clean_list);
	list_splice_init(&obd->obd_final_req_queue, &clean_list);
	spin_unlock(&obd->obd_recovery_task_lock);

	list_for_each_entry_safe(req, n, &clean_list, rq_list) {
		LASSERT(req->rq_reply_state == NULL);
                target_request_copy_put(req);
        }

        EXIT;
}
EXPORT_SYMBOL(target_cleanup_recovery);

/* obd_recovery_task_lock should be held */
void target_cancel_recovery_timer(struct obd_device *obd)
{
        CDEBUG(D_HA, "%s: cancel recovery timer\n", obd->obd_name);
	del_timer(&obd->obd_recovery_timer);
}

static void target_start_recovery_timer(struct obd_device *obd)
{
	if (obd->obd_recovery_start != 0)
		return;

	spin_lock(&obd->obd_dev_lock);
	if (!obd->obd_recovering || obd->obd_abort_recovery) {
		spin_unlock(&obd->obd_dev_lock);
		return;
	}

	LASSERT(obd->obd_recovery_timeout != 0);

	if (obd->obd_recovery_start != 0) {
		spin_unlock(&obd->obd_dev_lock);
		return;
	}

	mod_timer(&obd->obd_recovery_timer,
		  cfs_time_shift(obd->obd_recovery_timeout));
	obd->obd_recovery_start = ktime_get_real_seconds();
	spin_unlock(&obd->obd_dev_lock);

	LCONSOLE_WARN("%s: Will be in recovery for at least %llu:%02llu, or until %d client%s reconnect%s\n",
		      obd->obd_name,
		      obd->obd_recovery_timeout / 60,
		      obd->obd_recovery_timeout % 60,
		      obd->obd_max_recoverable_clients,
		      (obd->obd_max_recoverable_clients == 1) ? "" : "s",
		      (obd->obd_max_recoverable_clients == 1) ? "s": "");
}

/**
 * extend recovery window.
 *
 * if @extend is true, extend recovery window to have @drt remaining at least;
 * otherwise, make sure the recovery timeout value is not less than @drt.
 */
static void extend_recovery_timer(struct obd_device *obd, int drt,
				  bool extend)
{
	time64_t now;
	time64_t end;
	time64_t left;
	time64_t to;

	spin_lock(&obd->obd_dev_lock);
	if (!obd->obd_recovering || obd->obd_abort_recovery) {
		spin_unlock(&obd->obd_dev_lock);
		return;
	}
	LASSERT(obd->obd_recovery_start != 0);

	now = ktime_get_real_seconds();
	to = obd->obd_recovery_timeout;
	end = obd->obd_recovery_start + to;
	left = end - now;

        if (extend && (drt > left)) {
                to += drt - left;
        } else if (!extend && (drt > to)) {
                to = drt;
        }

	if (to > obd->obd_recovery_time_hard) {
		to = obd->obd_recovery_time_hard;
		CWARN("%s: extended recovery timer reaching hard limit: %lld, extend: %d\n",
		      obd->obd_name, to, extend);
	}

	if (obd->obd_recovery_timeout < to) {
                obd->obd_recovery_timeout = to;
		end = obd->obd_recovery_start + to;
		mod_timer(&obd->obd_recovery_timer,
			  cfs_time_shift(end - now));
        }
	spin_unlock(&obd->obd_dev_lock);

	CDEBUG(D_HA, "%s: recovery timer will expire in %lld seconds\n",
		obd->obd_name, (s64)(end - now));
}

/* Reset the timer with each new client connection */
/*
 * This timer is actually reconnect_timer, which is for making sure
 * the total recovery window is at least as big as my reconnect
 * attempt timing. So the initial recovery time_out will be set to
 * OBD_RECOVERY_FACTOR * obd_timeout. If the timeout coming
 * from client is bigger than this, then the recovery time_out will
 * be extended to make sure the client could be reconnected, in the
 * process, the timeout from the new client should be ignored.
 */

static void
check_and_start_recovery_timer(struct obd_device *obd,
                               struct ptlrpc_request *req,
                               int new_client)
{
        int service_time = lustre_msg_get_service_time(req->rq_reqmsg);
        struct obd_device_target *obt = &obd->u.obt;

        if (!new_client && service_time)
                /* Teach server about old server's estimates, as first guess
                 * at how long new requests will take. */
		at_measured(&req->rq_rqbd->rqbd_svcpt->scp_at_estimate,
                            service_time);

        target_start_recovery_timer(obd);

	/* Convert the service time to RPC timeout,
	 * and reuse service_time to limit stack usage. */
	service_time = at_est2timeout(service_time);

	if (OBD_FAIL_CHECK(OBD_FAIL_TGT_SLUGGISH_NET) &&
	    service_time < at_extra)
		service_time = at_extra;

	/* We expect other clients to timeout within service_time, then try
	 * to reconnect, then try the failover server.  The max delay between
	 * connect attempts is SWITCH_MAX + SWITCH_INC + INITIAL. */
        service_time += 2 * INITIAL_CONNECT_TIMEOUT;

        LASSERT(obt->obt_magic == OBT_MAGIC);
	service_time += 2 * (CONNECTION_SWITCH_MAX + CONNECTION_SWITCH_INC);
	if (service_time > obd->obd_recovery_timeout && !new_client)
		extend_recovery_timer(obd, service_time, false);
}

/** Health checking routines */
static inline int exp_connect_healthy(struct obd_export *exp)
{
        return (exp->exp_in_recovery);
}

/** if export done req_replay or has replay in queue */
static inline int exp_req_replay_healthy(struct obd_export *exp)
{
	return (!exp->exp_req_replay_needed ||
		atomic_read(&exp->exp_replay_count) > 0);
}


static inline int exp_req_replay_healthy_or_from_mdt(struct obd_export *exp)
{
	return (exp_connect_flags(exp) & OBD_CONNECT_MDS_MDS) ||
	       exp_req_replay_healthy(exp);
}

/** if export done lock_replay or has replay in queue */
static inline int exp_lock_replay_healthy(struct obd_export *exp)
{
	return (!exp->exp_lock_replay_needed ||
		atomic_read(&exp->exp_replay_count) > 0);
}

static inline int exp_vbr_healthy(struct obd_export *exp)
{
        return (!exp->exp_vbr_failed);
}

static inline int exp_finished(struct obd_export *exp)
{
        return (exp->exp_in_recovery && !exp->exp_lock_replay_needed);
}

static inline int exp_finished_or_from_mdt(struct obd_export *exp)
{
	return (exp_connect_flags(exp) & OBD_CONNECT_MDS_MDS) ||
		exp_finished(exp);
}

static int check_for_next_transno(struct lu_target *lut)
{
	struct ptlrpc_request *req = NULL;
	struct obd_device *obd = lut->lut_obd;
	struct target_distribute_txn_data *tdtd = lut->lut_tdtd;
	int wake_up = 0, connected, completed, queue_len;
	__u64 req_transno = 0;
	__u64 update_transno = 0;
	__u64 next_transno = 0;
	ENTRY;

	spin_lock(&obd->obd_recovery_task_lock);
	if (!list_empty(&obd->obd_req_replay_queue)) {
		req = list_entry(obd->obd_req_replay_queue.next,
				     struct ptlrpc_request, rq_list);
		req_transno = lustre_msg_get_transno(req->rq_reqmsg);
	}

	if (tdtd != NULL)
		update_transno = distribute_txn_get_next_transno(tdtd);

	connected = atomic_read(&obd->obd_connected_clients);
	completed = connected - atomic_read(&obd->obd_req_replay_clients);
	queue_len = obd->obd_requests_queued_for_recovery;
	next_transno = obd->obd_next_recovery_transno;

	CDEBUG(D_HA, "max: %d, connected: %d, completed: %d, queue_len: %d, "
	       "req_transno: %llu, next_transno: %llu\n",
	       obd->obd_max_recoverable_clients, connected, completed,
	       queue_len, req_transno, next_transno);

	if (obd->obd_abort_recovery) {
		CDEBUG(D_HA, "waking for aborted recovery\n");
		wake_up = 1;
	} else if (obd->obd_recovery_expired) {
		CDEBUG(D_HA, "waking for expired recovery\n");
		wake_up = 1;
	} else if (tdtd != NULL && req != NULL &&
		   is_req_replayed_by_update(req)) {
		LASSERTF(req_transno < next_transno, "req_transno %llu"
			 "next_transno%llu\n", req_transno, next_transno);
		CDEBUG(D_HA, "waking for duplicate req (%llu)\n",
		       req_transno);
		wake_up = 1;
	} else if (req_transno == next_transno ||
		   (update_transno != 0 && update_transno <= next_transno)) {
		CDEBUG(D_HA, "waking for next (%lld)\n", next_transno);
		wake_up = 1;
	} else if (queue_len > 0 &&
		   queue_len == atomic_read(&obd->obd_req_replay_clients)) {
		/** handle gaps occured due to lost reply or VBR */
		LASSERTF(req_transno >= next_transno,
			 "req_transno: %llu, next_transno: %llu\n",
			 req_transno, next_transno);
		CDEBUG(D_HA,
		       "%s: waking for gap in transno, VBR is %s (skip: "
		       "%lld, ql: %d, comp: %d, conn: %d, next: %lld"
		       ", next_update %lld last_committed: %lld)\n",
		       obd->obd_name, obd->obd_version_recov ? "ON" : "OFF",
		       next_transno, queue_len, completed, connected,
		       req_transno, update_transno, obd->obd_last_committed);
		obd->obd_next_recovery_transno = req_transno;
		wake_up = 1;
	} else if (atomic_read(&obd->obd_req_replay_clients) == 0) {
		CDEBUG(D_HA, "waking for completed recovery\n");
		wake_up = 1;
	} else if (OBD_FAIL_CHECK(OBD_FAIL_MDS_RECOVERY_ACCEPTS_GAPS)) {
		CDEBUG(D_HA, "accepting transno gaps is explicitly allowed"
		       " by fail_lock, waking up (%lld)\n", next_transno);
		obd->obd_next_recovery_transno = req_transno;
		wake_up = 1;
	}
	spin_unlock(&obd->obd_recovery_task_lock);
	return wake_up;
}

static int check_for_next_lock(struct lu_target *lut)
{
	struct obd_device *obd = lut->lut_obd;
	int wake_up = 0;

	spin_lock(&obd->obd_recovery_task_lock);
	if (!list_empty(&obd->obd_lock_replay_queue)) {
		CDEBUG(D_HA, "waking for next lock\n");
		wake_up = 1;
	} else if (atomic_read(&obd->obd_lock_replay_clients) == 0) {
		CDEBUG(D_HA, "waking for completed lock replay\n");
		wake_up = 1;
	} else if (obd->obd_abort_recovery) {
		CDEBUG(D_HA, "waking for aborted recovery\n");
		wake_up = 1;
	} else if (obd->obd_recovery_expired) {
		CDEBUG(D_HA, "waking for expired recovery\n");
		wake_up = 1;
	}
	spin_unlock(&obd->obd_recovery_task_lock);

	return wake_up;
}

/**
 * wait for recovery events,
 * check its status with help of check_routine
 * evict dead clients via health_check
 */
static int target_recovery_overseer(struct lu_target *lut,
				    int (*check_routine)(struct lu_target *),
				    int (*health_check)(struct obd_export *))
{
	struct obd_device	*obd = lut->lut_obd;
	struct target_distribute_txn_data *tdtd;
	time64_t last = 0;
	time64_t now;
repeat:
	if (obd->obd_recovering && obd->obd_recovery_start == 0) {
		now = ktime_get_seconds();
		if (now - last > 600) {
			LCONSOLE_INFO("%s: in recovery but waiting for "
				      "the first client to connect\n",
				      obd->obd_name);
			last = now;
		}
	}
	if (obd->obd_recovery_start != 0 && ktime_get_real_seconds() >=
	      (obd->obd_recovery_start + obd->obd_recovery_time_hard)) {
		__u64 next_update_transno = 0;

		/* Only abort the recovery if there are no update recovery
		 * left in the queue */
		spin_lock(&obd->obd_recovery_task_lock);
		if (lut->lut_tdtd != NULL) {
			next_update_transno =
				distribute_txn_get_next_transno(lut->lut_tdtd);

			tdtd = lut->lut_tdtd;
			/* If next_update_transno == 0, it probably because
			 * updatelog retrieve threads did not get any records
			 * yet, let's wait those threads stopped */
			if (next_update_transno == 0) {
				struct l_wait_info lwi = { 0 };

				l_wait_event(tdtd->tdtd_recovery_threads_waitq,
				       atomic_read(
				       &tdtd->tdtd_recovery_threads_count) == 0,
				       &lwi);

				next_update_transno =
					distribute_txn_get_next_transno(
								lut->lut_tdtd);
			}
		}

		if (next_update_transno != 0 && !obd->obd_abort_recovery) {
			obd->obd_next_recovery_transno = next_update_transno;
			spin_unlock(&obd->obd_recovery_task_lock);
			/* Disconnect unfinished exports from clients, and
			 * keep connection from MDT to make sure the update
			 * recovery will still keep trying until some one
			 * manually abort the recovery */
			class_disconnect_stale_exports(obd,
						exp_finished_or_from_mdt);
			/* Abort all of replay and replay lock req from
			 * clients */
			abort_req_replay_queue(obd);
			abort_lock_replay_queue(obd);
			CDEBUG(D_HA, "%s: there are still update replay (%#llx"
			       ")in the queue.\n", obd->obd_name,
			       next_update_transno);
		} else {
			obd->obd_abort_recovery = 1;
			spin_unlock(&obd->obd_recovery_task_lock);
			CWARN("%s recovery is aborted by hard timeout\n",
			      obd->obd_name);
		}
	}

	while (wait_event_timeout(obd->obd_next_transno_waitq,
				  check_routine(lut),
				  msecs_to_jiffies(60 * MSEC_PER_SEC)) == 0)
		/* wait indefinitely for event, but don't trigger watchdog */;

	if (obd->obd_abort_recovery) {
		CWARN("recovery is aborted, evict exports in recovery\n");
		if (lut->lut_tdtd != NULL) {
			struct l_wait_info lwi = { 0 };

			tdtd = lut->lut_tdtd;
			/* Let's wait all of the update log recovery thread
			 * finished */
			l_wait_event(tdtd->tdtd_recovery_threads_waitq,
			 atomic_read(&tdtd->tdtd_recovery_threads_count) == 0,
			     &lwi);
			/* Then abort the update recovery list */
			dtrq_list_destroy(lut->lut_tdtd);
		}

		/** evict exports which didn't finish recovery yet */
		class_disconnect_stale_exports(obd, exp_finished);
		return 1;
	} else if (obd->obd_recovery_expired) {
		obd->obd_recovery_expired = 0;
		/** If some clients died being recovered, evict them */
		LCONSOLE_WARN("%s: recovery is timed out, "
			      "evict stale exports\n", obd->obd_name);
		/** evict cexports with no replay in queue, they are stalled */
		class_disconnect_stale_exports(obd, health_check);

		/** continue with VBR */
		spin_lock(&obd->obd_dev_lock);
		obd->obd_version_recov = 1;
		spin_unlock(&obd->obd_dev_lock);
		/**
		 * reset timer, recovery will proceed with versions now,
		 * timeout is set just to handle reconnection delays
		 */
		extend_recovery_timer(obd, RECONNECT_DELAY_MAX, true);
		/** Wait for recovery events again, after evicting bad clients */
		goto repeat;
	}
	return 0;
}

static struct ptlrpc_request *target_next_replay_lock(struct lu_target *lut)
{
	struct obd_device	*obd = lut->lut_obd;
	struct ptlrpc_request *req = NULL;

	CDEBUG(D_HA, "Waiting for lock\n");
	if (target_recovery_overseer(lut, check_for_next_lock,
				     exp_lock_replay_healthy))
		abort_lock_replay_queue(obd);

	spin_lock(&obd->obd_recovery_task_lock);
	if (!list_empty(&obd->obd_lock_replay_queue)) {
		req = list_entry(obd->obd_lock_replay_queue.next,
				     struct ptlrpc_request, rq_list);
		list_del_init(&req->rq_list);
		spin_unlock(&obd->obd_recovery_task_lock);
	} else {
		spin_unlock(&obd->obd_recovery_task_lock);
		LASSERT(list_empty(&obd->obd_lock_replay_queue));
		LASSERT(atomic_read(&obd->obd_lock_replay_clients) == 0);
		/** evict exports failed VBR */
		class_disconnect_stale_exports(obd, exp_vbr_healthy);
	}
	return req;
}

static struct ptlrpc_request *target_next_final_ping(struct obd_device *obd)
{
	struct ptlrpc_request *req = NULL;

	spin_lock(&obd->obd_recovery_task_lock);
	if (!list_empty(&obd->obd_final_req_queue)) {
		req = list_entry(obd->obd_final_req_queue.next,
				     struct ptlrpc_request, rq_list);
		list_del_init(&req->rq_list);
		spin_unlock(&obd->obd_recovery_task_lock);
		if (req->rq_export->exp_in_recovery) {
			spin_lock(&req->rq_export->exp_lock);
			req->rq_export->exp_in_recovery = 0;
			spin_unlock(&req->rq_export->exp_lock);
		}
	} else {
		spin_unlock(&obd->obd_recovery_task_lock);
	}
	return req;
}

static void handle_recovery_req(struct ptlrpc_thread *thread,
				struct ptlrpc_request *req,
				svc_handler_t handler)
{
	ENTRY;

	/**
	 * export can be evicted during recovery, no need to handle replays for
	 * it after that, discard such request silently
	 */
	if (req->rq_export->exp_disconnected)
		RETURN_EXIT;

	req->rq_session.lc_thread = thread;
	req->rq_svc_thread = thread;
	req->rq_svc_thread->t_env->le_ses = &req->rq_session;

        /* thread context */
        lu_context_enter(&thread->t_env->le_ctx);
        (void)handler(req);
        lu_context_exit(&thread->t_env->le_ctx);

        /* don't reset timer for final stage */
        if (!exp_finished(req->rq_export)) {
                int to = obd_timeout;

                /**
                 * Add request timeout to the recovery time so next request from
                 * this client may come in recovery time
                 */
                if (!AT_OFF) {
			struct ptlrpc_service_part *svcpt;

			svcpt = req->rq_rqbd->rqbd_svcpt;
			/* If the server sent early reply for this request,
			 * the client will recalculate the timeout according to
			 * current server estimate service time, so we will
			 * use the maxium timeout here for waiting the client
			 * sending the next req */
			to = max((int)at_est2timeout(
				 at_get(&svcpt->scp_at_estimate)),
				 (int)lustre_msg_get_timeout(req->rq_reqmsg));
			/* Add 2 net_latency, one for balance rq_deadline
			 * (see ptl_send_rpc), one for resend the req to server,
			 * Note: client will pack net_latency in replay req
			 * (see ptlrpc_replay_req) */
			to += 2 * lustre_msg_get_service_time(req->rq_reqmsg);
                }
                extend_recovery_timer(class_exp2obd(req->rq_export), to, true);
        }
	EXIT;
}

/** Checking routines for recovery */
static int check_for_recovery_ready(struct lu_target *lut)
{
	struct obd_device *obd = lut->lut_obd;
	unsigned int clnts = atomic_read(&obd->obd_connected_clients);

	CDEBUG(D_HA, "connected %d stale %d max_recoverable_clients %d"
	       " abort %d expired %d\n", clnts, obd->obd_stale_clients,
	       obd->obd_max_recoverable_clients, obd->obd_abort_recovery,
	       obd->obd_recovery_expired);

	if (!obd->obd_abort_recovery && !obd->obd_recovery_expired) {
		LASSERT(clnts <= obd->obd_max_recoverable_clients);
		if (clnts + obd->obd_stale_clients <
		    obd->obd_max_recoverable_clients)
			return 0;
	}

	if (lut->lut_tdtd != NULL) {
		if (!lut->lut_tdtd->tdtd_replay_ready &&
		    !obd->obd_abort_recovery) {
			/* Let's extend recovery timer, in case the recovery
			 * timer expired, and some clients got evicted */
			extend_recovery_timer(obd, obd->obd_recovery_timeout,
					      true);
			CDEBUG(D_HA, "%s update recovery is not ready, extend recovery %llu\n",
			       obd->obd_name, obd->obd_recovery_timeout);
			return 0;
		}
	}

	return 1;
}

enum {
	REQUEST_RECOVERY = 1,
	UPDATE_RECOVERY = 2,
};

static __u64 get_next_replay_req_transno(struct obd_device *obd)
{
	__u64 transno = 0;

	if (!list_empty(&obd->obd_req_replay_queue)) {
		struct ptlrpc_request *req;

		req = list_entry(obd->obd_req_replay_queue.next,
				 struct ptlrpc_request, rq_list);
		transno = lustre_msg_get_transno(req->rq_reqmsg);
	}

	return transno;
}

static __u64 get_next_transno(struct lu_target *lut, int *type)
{
	struct obd_device *obd = lut->lut_obd;
	struct target_distribute_txn_data *tdtd = lut->lut_tdtd;
	__u64 transno = 0;
	__u64 update_transno;
	ENTRY;

	transno = get_next_replay_req_transno(obd);
	if (type != NULL)
		*type = REQUEST_RECOVERY;

	if (tdtd == NULL)
		RETURN(transno);

	update_transno = distribute_txn_get_next_transno(tdtd);
	if (transno == 0 || (transno >= update_transno &&
			     update_transno != 0)) {
		transno = update_transno;
		if (type != NULL)
			*type = UPDATE_RECOVERY;
	}

	RETURN(transno);
}

/**
 * drop duplicate replay request
 *
 * Because the operation has been replayed by update recovery, the request
 * with the same transno will be dropped and also notify the client to send
 * next replay request.
 *
 * \param[in] env	execution environment
 * \param[in] obd	failover obd device
 * \param[in] req	request to be dropped
 */
static void drop_duplicate_replay_req(struct lu_env *env,
				      struct obd_device *obd,
				      struct ptlrpc_request *req)
{
	DEBUG_REQ(D_HA, req, "remove t%lld from %s because of duplicate"
		  " update records are found.\n",
		  lustre_msg_get_transno(req->rq_reqmsg),
		  libcfs_nid2str(req->rq_peer.nid));

	/* Right now, only for MDS reint operation update replay and
	 * normal request replay can have the same transno */
	if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_REINT) {
		req_capsule_set(&req->rq_pill, &RQF_MDS_REINT);
		req->rq_status = req_capsule_server_pack(&req->rq_pill);
		if (likely(req->rq_export))
			target_committed_to_req(req);
		lustre_msg_set_transno(req->rq_repmsg, req->rq_transno);
		target_send_reply(req, req->rq_status, 0);
	} else {
		DEBUG_REQ(D_ERROR, req, "wrong opc" "from %s\n",
		libcfs_nid2str(req->rq_peer.nid));
	}
	target_exp_dequeue_req_replay(req);
	target_request_copy_put(req);
	obd->obd_replayed_requests++;
}

static void replay_request_or_update(struct lu_env *env,
				     struct lu_target *lut,
				     struct target_recovery_data *trd,
				     struct ptlrpc_thread *thread)
{
	struct obd_device *obd = lut->lut_obd;
	struct ptlrpc_request *req = NULL;
	int			type;
	__u64			transno;
	ENTRY;

	CDEBUG(D_HA, "Waiting for transno %lld\n",
	       obd->obd_next_recovery_transno);

	/* Replay all of request and update by transno */
	do {
		struct target_distribute_txn_data *tdtd = lut->lut_tdtd;

		CFS_FAIL_TIMEOUT(OBD_FAIL_TGT_REPLAY_DELAY2, cfs_fail_val);

		/** It is needed to extend recovery window above
		 *  recovery_time_soft. Extending is possible only in the
		 *  end of recovery window (see more details in
		 *  handle_recovery_req()).
		 */
		CFS_FAIL_TIMEOUT_MS(OBD_FAIL_TGT_REPLAY_DELAY, 300);

		if (target_recovery_overseer(lut, check_for_next_transno,
					exp_req_replay_healthy_or_from_mdt)) {
			abort_req_replay_queue(obd);
			abort_lock_replay_queue(obd);
			goto abort;
		}

		spin_lock(&obd->obd_recovery_task_lock);
		transno = get_next_transno(lut, &type);
		if (type == REQUEST_RECOVERY && transno != 0) {
			/* Drop replay request from client side, if the
			 * replay has been executed by update with the
			 * same transno */
			req = list_entry(obd->obd_req_replay_queue.next,
					struct ptlrpc_request, rq_list);

			list_del_init(&req->rq_list);
			obd->obd_requests_queued_for_recovery--;
			spin_unlock(&obd->obd_recovery_task_lock);

			/* Let's check if the request has been redone by
			 * update replay */
			if (is_req_replayed_by_update(req)) {
				struct distribute_txn_replay_req *dtrq;

				dtrq = distribute_txn_lookup_finish_list(tdtd,
								   req->rq_xid);
				LASSERT(dtrq != NULL);
				spin_lock(&tdtd->tdtd_replay_list_lock);
				list_del_init(&dtrq->dtrq_list);
				spin_unlock(&tdtd->tdtd_replay_list_lock);
				dtrq_destroy(dtrq);

				drop_duplicate_replay_req(env, obd, req);

				continue;
			}

			LASSERT(trd->trd_processing_task == current_pid());
			DEBUG_REQ(D_HA, req, "processing t%lld from %s",
				  lustre_msg_get_transno(req->rq_reqmsg),
				  libcfs_nid2str(req->rq_peer.nid));

			handle_recovery_req(thread, req,
					    trd->trd_recovery_handler);
			/**
			 * bz18031: increase next_recovery_transno before
			 * target_request_copy_put() will drop exp_rpc reference
			 */
			spin_lock(&obd->obd_recovery_task_lock);
			obd->obd_next_recovery_transno++;
			spin_unlock(&obd->obd_recovery_task_lock);
			target_exp_dequeue_req_replay(req);
			target_request_copy_put(req);
			obd->obd_replayed_requests++;
		} else if (type == UPDATE_RECOVERY && transno != 0) {
			struct distribute_txn_replay_req *dtrq;
			int rc;

			spin_unlock(&obd->obd_recovery_task_lock);

			LASSERT(tdtd != NULL);
			dtrq = distribute_txn_get_next_req(tdtd);
			lu_context_enter(&thread->t_env->le_ctx);
			rc = tdtd->tdtd_replay_handler(env, tdtd, dtrq);
			lu_context_exit(&thread->t_env->le_ctx);
			extend_recovery_timer(obd, obd_timeout, true);

			if (rc == 0 && dtrq->dtrq_xid != 0) {
				CDEBUG(D_HA, "Move x%llu t%llu"
				       " to finish list\n", dtrq->dtrq_xid,
				       dtrq->dtrq_master_transno);

				/* Add it to the replay finish list */
				spin_lock(&tdtd->tdtd_replay_list_lock);
				list_add(&dtrq->dtrq_list,
					 &tdtd->tdtd_replay_finish_list);
				spin_unlock(&tdtd->tdtd_replay_list_lock);

				spin_lock(&obd->obd_recovery_task_lock);
				if (transno == obd->obd_next_recovery_transno)
					obd->obd_next_recovery_transno++;
				else if (transno >
					 obd->obd_next_recovery_transno)
					obd->obd_next_recovery_transno =
								transno + 1;
				spin_unlock(&obd->obd_recovery_task_lock);
			} else {
				dtrq_destroy(dtrq);
			}
		} else {
			spin_unlock(&obd->obd_recovery_task_lock);
abort:
			LASSERT(list_empty(&obd->obd_req_replay_queue));
			LASSERT(atomic_read(&obd->obd_req_replay_clients) == 0);
			/** evict exports failed VBR */
			class_disconnect_stale_exports(obd, exp_vbr_healthy);
			break;
		}
	} while (1);
}

static int target_recovery_thread(void *arg)
{
        struct lu_target *lut = arg;
        struct obd_device *obd = lut->lut_obd;
        struct ptlrpc_request *req;
        struct target_recovery_data *trd = &obd->obd_recovery_data;
        unsigned long delta;
        struct lu_env *env;
        struct ptlrpc_thread *thread = NULL;
        int rc = 0;
        ENTRY;

	unshare_fs_struct();
        OBD_ALLOC_PTR(thread);
        if (thread == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC_PTR(env);
        if (env == NULL) {
                OBD_FREE_PTR(thread);
                RETURN(-ENOMEM);
        }

        rc = lu_context_init(&env->le_ctx, LCT_MD_THREAD | LCT_DT_THREAD);
        if (rc) {
                OBD_FREE_PTR(thread);
                OBD_FREE_PTR(env);
                RETURN(rc);
        }

        thread->t_env = env;
        thread->t_id = -1; /* force filter_iobuf_get/put to use local buffers */
        env->le_ctx.lc_thread = thread;
	tgt_io_thread_init(thread); /* init thread_big_cache for IO requests */
	thread->t_watchdog = NULL;

	CDEBUG(D_HA, "%s: started recovery thread pid %d\n", obd->obd_name,
	       current_pid());
	trd->trd_processing_task = current_pid();

	spin_lock(&obd->obd_dev_lock);
	obd->obd_recovering = 1;
	spin_unlock(&obd->obd_dev_lock);
	complete(&trd->trd_starting);

	/* first of all, we have to know the first transno to replay */
	if (target_recovery_overseer(lut, check_for_recovery_ready,
				     exp_connect_healthy)) {
		abort_req_replay_queue(obd);
		abort_lock_replay_queue(obd);
		if (lut->lut_tdtd != NULL)
			dtrq_list_destroy(lut->lut_tdtd);
	}

	/* next stage: replay requests or update */
	delta = jiffies;
	CDEBUG(D_INFO, "1: request replay stage - %d clients from t%llu\n",
	       atomic_read(&obd->obd_req_replay_clients),
	       obd->obd_next_recovery_transno);
	replay_request_or_update(env, lut, trd, thread);

	/**
	 * The second stage: replay locks
	 */
	CDEBUG(D_INFO, "2: lock replay stage - %d clients\n",
	       atomic_read(&obd->obd_lock_replay_clients));
	while ((req = target_next_replay_lock(lut))) {
		LASSERT(trd->trd_processing_task == current_pid());
		DEBUG_REQ(D_HA, req, "processing lock from %s: ",
			  libcfs_nid2str(req->rq_peer.nid));
		handle_recovery_req(thread, req,
				    trd->trd_recovery_handler);
		target_request_copy_put(req);
		obd->obd_replayed_locks++;
	}

        /**
         * The third stage: reply on final pings, at this moment all clients
         * must have request in final queue
         */
	CFS_FAIL_TIMEOUT(OBD_FAIL_TGT_REPLAY_RECONNECT, cfs_fail_val);
        CDEBUG(D_INFO, "3: final stage - process recovery completion pings\n");
        /** Update server last boot epoch */
        tgt_boot_epoch_update(lut);
        /* We drop recoverying flag to forward all new requests
         * to regular mds_handle() since now */
	spin_lock(&obd->obd_dev_lock);
	obd->obd_recovering = obd->obd_abort_recovery = 0;
	spin_unlock(&obd->obd_dev_lock);
	spin_lock(&obd->obd_recovery_task_lock);
	target_cancel_recovery_timer(obd);
	spin_unlock(&obd->obd_recovery_task_lock);
	while ((req = target_next_final_ping(obd))) {
		LASSERT(trd->trd_processing_task == current_pid());
		DEBUG_REQ(D_HA, req, "processing final ping from %s: ",
			  libcfs_nid2str(req->rq_peer.nid));
                handle_recovery_req(thread, req,
                                    trd->trd_recovery_handler);
		/* Because the waiting client can not send ping to server,
		 * so we need refresh the last_request_time, to avoid the
		 * export is being evicted */
		ptlrpc_update_export_timer(req->rq_export, 0);
		target_request_copy_put(req);
	}

	delta = jiffies_to_msecs(jiffies - delta) / MSEC_PER_SEC;
	CDEBUG(D_INFO,"4: recovery completed in %lus - %d/%d reqs/locks\n",
	      delta, obd->obd_replayed_requests, obd->obd_replayed_locks);
	if (delta > OBD_RECOVERY_TIME_SOFT) {
		CWARN("too long recovery - read logs\n");
		libcfs_debug_dumplog();
	}

	target_finish_recovery(lut);

        lu_context_fini(&env->le_ctx);
        trd->trd_processing_task = 0;
	complete(&trd->trd_finishing);

	tgt_io_thread_done(thread);
	OBD_FREE_PTR(thread);
	OBD_FREE_PTR(env);
	RETURN(rc);
}

static int target_start_recovery_thread(struct lu_target *lut,
                                        svc_handler_t handler)
{
	struct obd_device *obd = lut->lut_obd;
	int rc = 0;
	struct target_recovery_data *trd = &obd->obd_recovery_data;
	int index;

	memset(trd, 0, sizeof(*trd));
	init_completion(&trd->trd_starting);
	init_completion(&trd->trd_finishing);
	trd->trd_recovery_handler = handler;

	rc = server_name2index(obd->obd_name, &index, NULL);
	if (rc < 0)
		return rc;

	if (!IS_ERR(kthread_run(target_recovery_thread,
				lut, "tgt_recover_%d", index))) {
		wait_for_completion(&trd->trd_starting);
		LASSERT(obd->obd_recovering != 0);
	} else {
		rc = -ECHILD;
	}

	return rc;
}

void target_stop_recovery_thread(struct obd_device *obd)
{
	if (obd->obd_recovery_data.trd_processing_task > 0) {
		struct target_recovery_data *trd = &obd->obd_recovery_data;
		/** recovery can be done but postrecovery is not yet */
		spin_lock(&obd->obd_dev_lock);
		if (obd->obd_recovering) {
			CERROR("%s: Aborting recovery\n", obd->obd_name);
			obd->obd_abort_recovery = 1;
			wake_up(&obd->obd_next_transno_waitq);
		}
		spin_unlock(&obd->obd_dev_lock);
		wait_for_completion(&trd->trd_finishing);
	}
}
EXPORT_SYMBOL(target_stop_recovery_thread);

void target_recovery_fini(struct obd_device *obd)
{
        class_disconnect_exports(obd);
        target_stop_recovery_thread(obd);
        target_cleanup_recovery(obd);
}
EXPORT_SYMBOL(target_recovery_fini);

static void target_recovery_expired(unsigned long castmeharder)
{
	struct obd_device *obd = (struct obd_device *)castmeharder;
	CDEBUG(D_HA, "%s: recovery timed out; %d clients are still in recovery"
	       " after %llus (%d clients connected)\n",
	       obd->obd_name, atomic_read(&obd->obd_lock_replay_clients),
	       (s64)(ktime_get_real_seconds() - obd->obd_recovery_start),
	       atomic_read(&obd->obd_connected_clients));

	obd->obd_recovery_expired = 1;
	wake_up(&obd->obd_next_transno_waitq);
}

void target_recovery_init(struct lu_target *lut, svc_handler_t handler)
{
	struct obd_device *obd = lut->lut_obd;

	if (lut->lut_bottom->dd_rdonly)
		return;

	if (obd->obd_max_recoverable_clients == 0) {
		/** Update server last boot epoch */
		tgt_boot_epoch_update(lut);
		return;
	}

	CDEBUG(D_HA, "RECOVERY: service %s, %d recoverable clients, "
	       "last_transno %llu\n", obd->obd_name,
	       obd->obd_max_recoverable_clients, obd->obd_last_committed);
        LASSERT(obd->obd_stopping == 0);
        obd->obd_next_recovery_transno = obd->obd_last_committed + 1;
        obd->obd_recovery_start = 0;
        obd->obd_recovery_end = 0;

	setup_timer(&obd->obd_recovery_timer, target_recovery_expired,
		    (unsigned long)obd);
	target_start_recovery_thread(lut, handler);
}
EXPORT_SYMBOL(target_recovery_init);

static int target_process_req_flags(struct obd_device *obd,
                                    struct ptlrpc_request *req)
{
	struct obd_export *exp = req->rq_export;
	LASSERT(exp != NULL);
	if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REQ_REPLAY_DONE) {
		/* client declares he's ready to replay locks */
		spin_lock(&exp->exp_lock);
		if (exp->exp_req_replay_needed) {
			exp->exp_req_replay_needed = 0;
			spin_unlock(&exp->exp_lock);

			LASSERT_ATOMIC_POS(&obd->obd_req_replay_clients);
			atomic_dec(&obd->obd_req_replay_clients);
		} else {
			spin_unlock(&exp->exp_lock);
		}
	}
	if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LOCK_REPLAY_DONE) {
		/* client declares he's ready to complete recovery
		 * so, we put the request on th final queue */
		spin_lock(&exp->exp_lock);
		if (exp->exp_lock_replay_needed) {
			exp->exp_lock_replay_needed = 0;
			spin_unlock(&exp->exp_lock);

			LASSERT_ATOMIC_POS(&obd->obd_lock_replay_clients);
			atomic_dec(&obd->obd_lock_replay_clients);
		} else {
			spin_unlock(&exp->exp_lock);
		}
	}
	return 0;
}

int target_queue_recovery_request(struct ptlrpc_request *req,
                                  struct obd_device *obd)
{
        __u64 transno = lustre_msg_get_transno(req->rq_reqmsg);
	struct ptlrpc_request *reqiter;
	int inserted = 0;
	ENTRY;

	if (obd->obd_recovery_data.trd_processing_task == current_pid()) {
		/* Processing the queue right now, don't re-add. */
		RETURN(1);
	}

        target_process_req_flags(obd, req);

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LOCK_REPLAY_DONE) {
                /* client declares he's ready to complete recovery
                 * so, we put the request on th final queue */
		target_request_copy_get(req);
		DEBUG_REQ(D_HA, req, "queue final req");
		wake_up(&obd->obd_next_transno_waitq);
		spin_lock(&obd->obd_recovery_task_lock);
		if (obd->obd_recovering) {
			struct ptlrpc_request *tmp;
			struct ptlrpc_request *duplicate = NULL;

			if (likely(!req->rq_export->exp_replay_done)) {
				req->rq_export->exp_replay_done = 1;
				list_add_tail(&req->rq_list,
					      &obd->obd_final_req_queue);
				spin_unlock(&obd->obd_recovery_task_lock);
				RETURN(0);
			}

			/* XXX O(n), but only happens if final ping is
			 * timed out, probably reorganize the list as
			 * a hash list later */
			list_for_each_entry_safe(reqiter, tmp,
						 &obd->obd_final_req_queue,
						 rq_list) {
				if (reqiter->rq_export == req->rq_export) {
					list_del_init(&reqiter->rq_list);
					duplicate = reqiter;
					break;
				}
			}

			list_add_tail(&req->rq_list,
				      &obd->obd_final_req_queue);
			req->rq_export->exp_replay_done = 1;
			spin_unlock(&obd->obd_recovery_task_lock);

			if (duplicate != NULL) {
				DEBUG_REQ(D_HA, duplicate,
					  "put prev final req\n");
				target_request_copy_put(duplicate);
			}
			RETURN(0);
		} else {
			spin_unlock(&obd->obd_recovery_task_lock);
			target_request_copy_put(req);
			RETURN(obd->obd_stopping ? -ENOTCONN : 1);
		}
	}
	if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REQ_REPLAY_DONE) {
		/* client declares he's ready to replay locks */
		target_request_copy_get(req);
		DEBUG_REQ(D_HA, req, "queue lock replay req");
		wake_up(&obd->obd_next_transno_waitq);
		spin_lock(&obd->obd_recovery_task_lock);
		LASSERT(obd->obd_recovering);
		/* usually due to recovery abort */
		if (!req->rq_export->exp_in_recovery) {
			spin_unlock(&obd->obd_recovery_task_lock);
			target_request_copy_put(req);
			RETURN(-ENOTCONN);
		}
		LASSERT(req->rq_export->exp_lock_replay_needed);
		list_add_tail(&req->rq_list, &obd->obd_lock_replay_queue);
		spin_unlock(&obd->obd_recovery_task_lock);
		RETURN(0);
	}

        /* CAVEAT EMPTOR: The incoming request message has been swabbed
         * (i.e. buflens etc are in my own byte order), but type-dependent
         * buffers (eg mdt_body, ost_body etc) have NOT been swabbed. */

        if (!transno) {
		INIT_LIST_HEAD(&req->rq_list);
                DEBUG_REQ(D_HA, req, "not queueing");
                RETURN(1);
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
	CDEBUG(D_HA, "Next recovery transno: %llu"
	       ", current: %llu, replaying\n",
               obd->obd_next_recovery_transno, transno);

	/* If the request has been replayed by update replay, then sends this
	 * request to the recovery thread (replay_request_or_update()), where
	 * it will be handled */
	spin_lock(&obd->obd_recovery_task_lock);
	if (transno < obd->obd_next_recovery_transno &&
	    !is_req_replayed_by_update(req)) {
		/* Processing the queue right now, don't re-add. */
		LASSERT(list_empty(&req->rq_list));
		spin_unlock(&obd->obd_recovery_task_lock);
		RETURN(1);
	}
	spin_unlock(&obd->obd_recovery_task_lock);

        if (OBD_FAIL_CHECK(OBD_FAIL_TGT_REPLAY_DROP))
                RETURN(0);

        target_request_copy_get(req);
        if (!req->rq_export->exp_in_recovery) {
                target_request_copy_put(req);
                RETURN(-ENOTCONN);
        }
        LASSERT(req->rq_export->exp_req_replay_needed);

        if (target_exp_enqueue_req_replay(req)) {
                DEBUG_REQ(D_ERROR, req, "dropping resent queued req");
                target_request_copy_put(req);
                RETURN(0);
        }

	/* XXX O(n^2) */
	spin_lock(&obd->obd_recovery_task_lock);
	LASSERT(obd->obd_recovering);
	list_for_each_entry(reqiter, &obd->obd_req_replay_queue, rq_list) {
		if (lustre_msg_get_transno(reqiter->rq_reqmsg) > transno) {
			list_add_tail(&req->rq_list, &reqiter->rq_list);
			inserted = 1;
			goto added;
		}

                if (unlikely(lustre_msg_get_transno(reqiter->rq_reqmsg) ==
                             transno)) {
                        DEBUG_REQ(D_ERROR, req, "dropping replay: transno "
                                  "has been claimed by another client");
			spin_unlock(&obd->obd_recovery_task_lock);
                        target_exp_dequeue_req_replay(req);
                        target_request_copy_put(req);
                        RETURN(0);
                }
        }
added:
        if (!inserted)
		list_add_tail(&req->rq_list, &obd->obd_req_replay_queue);

        obd->obd_requests_queued_for_recovery++;
	spin_unlock(&obd->obd_recovery_task_lock);
	wake_up(&obd->obd_next_transno_waitq);
	RETURN(0);
}

int target_handle_ping(struct ptlrpc_request *req)
{
        obd_ping(req->rq_svc_thread->t_env, req->rq_export);
        return req_capsule_server_pack(&req->rq_pill);
}

void target_committed_to_req(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;

        if (!exp->exp_obd->obd_no_transno && req->rq_repmsg != NULL)
                lustre_msg_set_last_committed(req->rq_repmsg,
                                              exp->exp_last_committed);
        else
                DEBUG_REQ(D_IOCTL, req, "not sending last_committed update (%d/"
                          "%d)", exp->exp_obd->obd_no_transno,
                          req->rq_repmsg == NULL);

	CDEBUG(D_INFO, "last_committed %llu, transno %llu, xid %llu\n",
               exp->exp_last_committed, req->rq_transno, req->rq_xid);
}

#endif /* HAVE_SERVER_SUPPORT */

/**
 * Packs current SLV and Limit into \a req.
 */
int target_pack_pool_reply(struct ptlrpc_request *req)
{
        struct obd_device *obd;
        ENTRY;

	/* Check that we still have all structures alive as this may
	 * be some late RPC at shutdown time. */
        if (unlikely(!req->rq_export || !req->rq_export->exp_obd ||
                     !exp_connect_lru_resize(req->rq_export))) {
                lustre_msg_set_slv(req->rq_repmsg, 0);
                lustre_msg_set_limit(req->rq_repmsg, 0);
                RETURN(0);
        }

	/* OBD is alive here as export is alive, which we checked above. */
        obd = req->rq_export->exp_obd;

	read_lock(&obd->obd_pool_lock);
        lustre_msg_set_slv(req->rq_repmsg, obd->obd_pool_slv);
        lustre_msg_set_limit(req->rq_repmsg, obd->obd_pool_limit);
	read_unlock(&obd->obd_pool_lock);

        RETURN(0);
}

static int target_send_reply_msg(struct ptlrpc_request *req,
				 int rc, int fail_id)
{
	if (OBD_FAIL_CHECK_ORSET(fail_id & ~OBD_FAIL_ONCE, OBD_FAIL_ONCE)) {
		DEBUG_REQ(D_ERROR, req, "dropping reply");
		return -ECOMM;
	}
	/* We can have a null rq_reqmsg in the event of bad signature or
	 * no context when unwrapping */
	if (req->rq_reqmsg &&
	    unlikely(lustre_msg_get_opc(req->rq_reqmsg) == MDS_REINT &&
	    OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_MULTI_NET_REP)))
		return -ECOMM;

	if (unlikely(rc)) {
		DEBUG_REQ(D_NET, req, "processing error (%d)", rc);
		req->rq_status = rc;
		return ptlrpc_send_error(req, 1);
	} else {
		DEBUG_REQ(D_NET, req, "sending reply");
	}

	return ptlrpc_send_reply(req, PTLRPC_REPLY_MAYBE_DIFFICULT);
}

void target_send_reply(struct ptlrpc_request *req, int rc, int fail_id)
{
	struct ptlrpc_service_part *svcpt;
        int                        netrc;
        struct ptlrpc_reply_state *rs;
        struct obd_export         *exp;
        ENTRY;

        if (req->rq_no_reply) {
                EXIT;
                return;
        }

	svcpt = req->rq_rqbd->rqbd_svcpt;
        rs = req->rq_reply_state;
        if (rs == NULL || !rs->rs_difficult) {
                /* no notifiers */
                target_send_reply_msg (req, rc, fail_id);
                EXIT;
                return;
        }

        /* must be an export if locks saved */
	LASSERT(req->rq_export != NULL);
        /* req/reply consistent */
	LASSERT(rs->rs_svcpt == svcpt);

        /* "fresh" reply */
	LASSERT(!rs->rs_scheduled);
	LASSERT(!rs->rs_scheduled_ever);
	LASSERT(!rs->rs_handled);
	LASSERT(!rs->rs_on_net);
	LASSERT(rs->rs_export == NULL);
	LASSERT(list_empty(&rs->rs_obd_list));
	LASSERT(list_empty(&rs->rs_exp_list));

	exp = class_export_get(req->rq_export);

        /* disable reply scheduling while I'm setting up */
        rs->rs_scheduled = 1;
        rs->rs_on_net    = 1;
        rs->rs_xid       = req->rq_xid;
        rs->rs_transno   = req->rq_transno;
        rs->rs_export    = exp;
        rs->rs_opc       = lustre_msg_get_opc(req->rq_reqmsg);

	spin_lock(&exp->exp_uncommitted_replies_lock);
	CDEBUG(D_NET, "rs transno = %llu, last committed = %llu\n",
	       rs->rs_transno, exp->exp_last_committed);
	if (rs->rs_transno > exp->exp_last_committed) {
		/* not committed already */
		list_add_tail(&rs->rs_obd_list,
				  &exp->exp_uncommitted_replies);
	}
	spin_unlock(&exp->exp_uncommitted_replies_lock);

	spin_lock(&exp->exp_lock);
	list_add_tail(&rs->rs_exp_list, &exp->exp_outstanding_replies);
	spin_unlock(&exp->exp_lock);

	netrc = target_send_reply_msg(req, rc, fail_id);

	spin_lock(&svcpt->scp_rep_lock);

	atomic_inc(&svcpt->scp_nreps_difficult);

	if (netrc != 0) {
		/* error sending: reply is off the net.  Also we need +1
		 * reply ref until ptlrpc_handle_rs() is done
		 * with the reply state (if the send was successful, there
		 * would have been +1 ref for the net, which
		 * reply_out_callback leaves alone) */
		rs->rs_on_net = 0;
		ptlrpc_rs_addref(rs);
	}

	spin_lock(&rs->rs_lock);
	if (rs->rs_transno <= exp->exp_last_committed ||
	    (!rs->rs_on_net && !rs->rs_no_ack) ||
	    list_empty(&rs->rs_exp_list) ||     /* completed already */
	    list_empty(&rs->rs_obd_list)) {
		CDEBUG(D_HA, "Schedule reply immediately\n");
		ptlrpc_dispatch_difficult_reply(rs);
	} else {
		list_add(&rs->rs_list, &svcpt->scp_rep_active);
		rs->rs_scheduled = 0;	/* allow notifier to schedule */
	}
	spin_unlock(&rs->rs_lock);
	spin_unlock(&svcpt->scp_rep_lock);
	EXIT;
}

enum ldlm_mode lck_compat_array[] = {
	[LCK_EX]    = LCK_COMPAT_EX,
	[LCK_PW]    = LCK_COMPAT_PW,
	[LCK_PR]    = LCK_COMPAT_PR,
	[LCK_CW]    = LCK_COMPAT_CW,
	[LCK_CR]    = LCK_COMPAT_CR,
	[LCK_NL]    = LCK_COMPAT_NL,
	[LCK_GROUP] = LCK_COMPAT_GROUP,
	[LCK_COS]   = LCK_COMPAT_COS,
};

/**
 * Rather arbitrary mapping from LDLM error codes to errno values. This should
 * not escape to the user level.
 */
int ldlm_error2errno(enum ldlm_error error)
{
	int result;

	switch (error) {
	case ELDLM_OK:
	case ELDLM_LOCK_MATCHED:
                result = 0;
                break;
        case ELDLM_LOCK_CHANGED:
                result = -ESTALE;
                break;
        case ELDLM_LOCK_ABORTED:
                result = -ENAVAIL;
                break;
        case ELDLM_LOCK_REPLACED:
                result = -ESRCH;
                break;
        case ELDLM_NO_LOCK_DATA:
                result = -ENOENT;
                break;
        case ELDLM_NAMESPACE_EXISTS:
                result = -EEXIST;
                break;
        case ELDLM_BAD_NAMESPACE:
                result = -EBADF;
                break;
	default:
		if (((int)error) < 0) { /* cast to signed type */
			result = error; /* as ldlm_error can be unsigned */
		} else {
			CERROR("Invalid DLM result code: %d\n", error);
			result = -EPROTO;
		}
	}
	return result;
}
EXPORT_SYMBOL(ldlm_error2errno);

/**
 * Dual to ldlm_error2errno(): maps errno values back to enum ldlm_error.
 */
enum ldlm_error ldlm_errno2error(int err_no)
{
        int error;

        switch (err_no) {
        case 0:
                error = ELDLM_OK;
                break;
        case -ESTALE:
                error = ELDLM_LOCK_CHANGED;
                break;
        case -ENAVAIL:
                error = ELDLM_LOCK_ABORTED;
                break;
        case -ESRCH:
                error = ELDLM_LOCK_REPLACED;
                break;
        case -ENOENT:
                error = ELDLM_NO_LOCK_DATA;
                break;
        case -EEXIST:
                error = ELDLM_NAMESPACE_EXISTS;
                break;
        case -EBADF:
                error = ELDLM_BAD_NAMESPACE;
                break;
        default:
                error = err_no;
        }
        return error;
}

#if LUSTRE_TRACKS_LOCK_EXP_REFS
void ldlm_dump_export_locks(struct obd_export *exp)
{
	spin_lock(&exp->exp_locks_list_guard);
	if (!list_empty(&exp->exp_locks_list)) {
		struct ldlm_lock *lock;

		CERROR("dumping locks for export %p,"
		       "ignore if the unmount doesn't hang\n", exp);
		list_for_each_entry(lock, &exp->exp_locks_list,
					l_exp_refs_link)
			LDLM_ERROR(lock, "lock:");
	}
	spin_unlock(&exp->exp_locks_list_guard);
}
#endif

#ifdef HAVE_SERVER_SUPPORT
static int target_bulk_timeout(void *data)
{
        ENTRY;
        /* We don't fail the connection here, because having the export
         * killed makes the (vital) call to commitrw very sad.
         */
        RETURN(1);
}

static inline const char *bulk2type(struct ptlrpc_request *req)
{
	if (req->rq_bulk_read)
		return "READ";
	if (req->rq_bulk_write)
		return "WRITE";
	return "UNKNOWN";
}

int target_bulk_io(struct obd_export *exp, struct ptlrpc_bulk_desc *desc,
                   struct l_wait_info *lwi)
{
	struct ptlrpc_request	*req = desc->bd_req;
	time_t			 start = cfs_time_current_sec();
	time_t			 deadline;
	int			 rc = 0;

	ENTRY;

	/* If there is eviction in progress, wait for it to finish. */
	if (unlikely(atomic_read(&exp->exp_obd->obd_evict_inprogress))) {
		*lwi = LWI_INTR(NULL, NULL);
		rc = l_wait_event(exp->exp_obd->obd_evict_inprogress_waitq,
				  !atomic_read(&exp->exp_obd->
						   obd_evict_inprogress),
				  lwi);
	}

	/* Check if client was evicted or reconnected already. */
	if (exp->exp_failed ||
	    exp->exp_conn_cnt > lustre_msg_get_conn_cnt(req->rq_reqmsg)) {
		rc = -ENOTCONN;
	} else {
		if (req->rq_bulk_read)
			rc = sptlrpc_svc_wrap_bulk(req, desc);

		if (OCD_HAS_FLAG(&exp->exp_connect_data, BULK_MBITS))
			req->rq_mbits = lustre_msg_get_mbits(req->rq_reqmsg);
		else /* old version, bulk matchbits is rq_xid */
			req->rq_mbits = req->rq_xid;

		if (rc == 0)
			rc = ptlrpc_start_bulk_transfer(desc);
	}

	if (rc < 0) {
		DEBUG_REQ(D_ERROR, req, "bulk %s failed: rc %d",
			  bulk2type(req), rc);
		RETURN(rc);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE)) {
		ptlrpc_abort_bulk(desc);
		RETURN(0);
	}

	/* limit actual bulk transfer to bulk_timeout seconds */
	deadline = start + bulk_timeout;
	if (deadline > req->rq_deadline)
		deadline = req->rq_deadline;

	do {
		long timeoutl = deadline - cfs_time_current_sec();
		cfs_duration_t timeout = timeoutl <= 0 ?
					 CFS_TICK : cfs_time_seconds(timeoutl);
		time_t	rq_deadline;

		*lwi = LWI_TIMEOUT_INTERVAL(timeout, cfs_time_seconds(1),
					    target_bulk_timeout, desc);
		rc = l_wait_event(desc->bd_waitq,
				  !ptlrpc_server_bulk_active(desc) ||
				  exp->exp_failed ||
				  exp->exp_conn_cnt >
				  lustre_msg_get_conn_cnt(req->rq_reqmsg),
				  lwi);
		LASSERT(rc == 0 || rc == -ETIMEDOUT);
		/* Wait again if we changed rq_deadline. */
		rq_deadline = ACCESS_ONCE(req->rq_deadline);
		deadline = start + bulk_timeout;
		if (deadline > rq_deadline)
			deadline = rq_deadline;
	} while ((rc == -ETIMEDOUT) &&
		 (deadline > cfs_time_current_sec()));

	if (rc == -ETIMEDOUT) {
		DEBUG_REQ(D_ERROR, req, "timeout on bulk %s after %ld%+lds",
			  bulk2type(req), deadline - start,
			  cfs_time_current_sec() - deadline);
		ptlrpc_abort_bulk(desc);
	} else if (exp->exp_failed) {
		DEBUG_REQ(D_ERROR, req, "Eviction on bulk %s",
			  bulk2type(req));
		rc = -ENOTCONN;
		ptlrpc_abort_bulk(desc);
	} else if (exp->exp_conn_cnt >
		   lustre_msg_get_conn_cnt(req->rq_reqmsg)) {
		DEBUG_REQ(D_ERROR, req, "Reconnect on bulk %s",
			  bulk2type(req));
		/* We don't reply anyway. */
		rc = -ETIMEDOUT;
		ptlrpc_abort_bulk(desc);
	} else if (desc->bd_failure) {
		DEBUG_REQ(D_ERROR, req, "network error on bulk %s",
			  bulk2type(req));
		/* XXX should this be a different errno? */
		rc = -ETIMEDOUT;
	} else {
		if (req->rq_bulk_write)
			rc = sptlrpc_svc_unwrap_bulk(req, desc);
		if (rc == 0 && desc->bd_nob_transferred != desc->bd_nob) {
			DEBUG_REQ(D_ERROR, req, "truncated bulk %s %d(%d)",
				  bulk2type(req), desc->bd_nob_transferred,
				  desc->bd_nob);
			/* XXX should this be a different errno? */
			rc = -ETIMEDOUT;
		}
	}

	RETURN(rc);
}
EXPORT_SYMBOL(target_bulk_io);

#endif /* HAVE_SERVER_SUPPORT */
