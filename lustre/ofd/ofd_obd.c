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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_obd.c
 *
 * Author: Andreas Dilger <adilger@whamcloud.com>
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"
#include <obd_cksum.h>

static int ofd_parse_connect_data(const struct lu_env *env,
				  struct obd_export *exp,
				  struct obd_connect_data *data)
{
	struct ofd_device *ofd = ofd_exp(exp);

	if (!data)
		RETURN(0);

	CDEBUG(D_RPCTRACE, "%s: cli %s/%p ocd_connect_flags: "LPX64
	       " ocd_version: %x ocd_grant: %d ocd_index: %u\n",
	       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
	       data->ocd_connect_flags, data->ocd_version,
	       data->ocd_grant, data->ocd_index);

	data->ocd_connect_flags &= OST_CONNECT_SUPPORTED;
	exp->exp_connect_flags = data->ocd_connect_flags;
	data->ocd_version = LUSTRE_VERSION_CODE;

	/* Kindly make sure the SKIP_ORPHAN flag is from MDS. */
	if (data->ocd_connect_flags & OBD_CONNECT_MDS)
		CDEBUG(D_HA, "%s: Received MDS connection for group %u\n",
		       exp->exp_obd->obd_name, data->ocd_group);
	else if (data->ocd_connect_flags & OBD_CONNECT_SKIP_ORPHAN)
		RETURN(-EPROTO);

	if (data->ocd_connect_flags & OBD_CONNECT_INDEX) {
		struct lr_server_data *lsd = &ofd->ofd_lut.lut_lsd;
		int		       index = lsd->lsd_ost_index;

		if (!(lsd->lsd_feature_compat & OBD_COMPAT_OST)) {
			/* this will only happen on the first connect */
			lsd->lsd_ost_index = data->ocd_index;
			lsd->lsd_feature_compat |= OBD_COMPAT_OST;
			/* sync is not needed here as lut_client_add will
			 * set exp_need_sync flag */
			lut_server_data_update(env, &ofd->ofd_lut, 0);
		} else if (index != data->ocd_index) {
			LCONSOLE_ERROR_MSG(0x136, "Connection from %s to index"
					   " %u doesn't match actual OST index"
					   " %u in last_rcvd file, bad "
					   "configuration?\n",
					   obd_export_nid2str(exp), index,
					   data->ocd_index);
			RETURN(-EBADF);
		}
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_SIZE)) {
		data->ocd_brw_size = 65536;
	} else if (data->ocd_connect_flags & OBD_CONNECT_BRW_SIZE) {
		data->ocd_brw_size = min(data->ocd_brw_size,
			      (__u32)(PTLRPC_MAX_BRW_PAGES << CFS_PAGE_SHIFT));
		if (data->ocd_brw_size == 0) {
			CERROR("%s: cli %s/%p ocd_connect_flags: "LPX64
			       " ocd_version: %x ocd_grant: %d ocd_index: %u "
			       "ocd_brw_size is unexpectedly zero, "
			       "network data corruption?"
			       "Refusing connection of this client\n",
			       exp->exp_obd->obd_name,
			       exp->exp_client_uuid.uuid,
			       exp, data->ocd_connect_flags, data->ocd_version,
			       data->ocd_grant, data->ocd_index);
			RETURN(-EPROTO);
		}
	}

	if (data->ocd_connect_flags & OBD_CONNECT_CKSUM) {
		__u32 cksum_types = data->ocd_cksum_types;

		/* The client set in ocd_cksum_types the checksum types it
		 * supports. We have to mask off the algorithms that we don't
		 * support */
		data->ocd_cksum_types &= cksum_types_supported();

		if (unlikely(data->ocd_cksum_types == 0)) {
			CERROR("%s: Connect with checksum support but no "
			       "ocd_cksum_types is set\n",
			       exp->exp_obd->obd_name);
			RETURN(-EPROTO);
		}

		CDEBUG(D_RPCTRACE, "%s: cli %s supports cksum type %x, return "
		       "%x\n", exp->exp_obd->obd_name, obd_export_nid2str(exp),
		       cksum_types, data->ocd_cksum_types);
	} else {
		/* This client does not support OBD_CONNECT_CKSUM
		 * fall back to CRC32 */
		CDEBUG(D_RPCTRACE, "%s: cli %s does not support "
		       "OBD_CONNECT_CKSUM, CRC32 will be used\n",
		       exp->exp_obd->obd_name, obd_export_nid2str(exp));
	}

	if (data->ocd_connect_flags & OBD_CONNECT_MAXBYTES)
		data->ocd_maxbytes = ofd->ofd_dt_conf.ddp_maxbytes;

        RETURN(0);
}

static int ofd_obd_reconnect(const struct lu_env *env, struct obd_export *exp,
			     struct obd_device *obd, struct obd_uuid *cluuid,
			     struct obd_connect_data *data, void *localdata)
{
	int rc;

	ENTRY;

	if (exp == NULL || obd == NULL || cluuid == NULL)
		RETURN(-EINVAL);

	rc = lu_env_refill((struct lu_env *)env);
	if (rc != 0) {
		CERROR("Failure to refill session: '%d'\n", rc);
		RETURN(rc);
	}

	ofd_info_init(env, exp);
	rc = ofd_parse_connect_data(env, exp, data);

	RETURN(rc);
}

static int ofd_obd_connect(const struct lu_env *env, struct obd_export **_exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct obd_export	*exp;
	struct ofd_device	*ofd;
	struct lustre_handle	 conn = { 0 };
	int			 rc, group;

	ENTRY;

	if (_exp == NULL || obd == NULL || cluuid == NULL)
		RETURN(-EINVAL);

	ofd = ofd_dev(obd->obd_lu_dev);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	exp = class_conn2export(&conn);
	LASSERT(exp != NULL);

	rc = lu_env_refill((struct lu_env *)env);
	if (rc != 0) {
		CERROR("Failure to refill session: '%d'\n", rc);
		GOTO(out, rc);
	}

	ofd_info_init(env, exp);

	rc = ofd_parse_connect_data(env, exp, data);
	if (rc)
		GOTO(out, rc);

	ofd_export_stats_init(ofd, exp, localdata);
	group = data->ocd_group;
	if (obd->obd_replayable) {
		struct tg_export_data *ted = &exp->exp_target_data;

		memcpy(ted->ted_lcd->lcd_uuid, cluuid,
		       sizeof(ted->ted_lcd->lcd_uuid));
		rc = lut_client_new(env, exp);
		if (rc != 0)
			GOTO(out, rc);
	}
	if (group == 0)
		GOTO(out, rc = 0);

	/* init new group */
	if (group > ofd->ofd_max_group) {
		ofd->ofd_max_group = group;
		rc = ofd_group_load(env, ofd, group);
	}
out:
	if (rc != 0) {
		class_disconnect(exp);
		*_exp = NULL;
	} else {
		*_exp = exp;
	}
	RETURN(rc);
}

static int ofd_obd_disconnect(struct obd_export *exp)
{
	struct lu_env	env;
	int		rc;

	ENTRY;

	LASSERT(exp);
	class_export_get(exp);

	rc = server_disconnect_export(exp);

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);

	/* Do not erase record for recoverable client. */
	if (exp->exp_obd->obd_replayable &&
	    (!exp->exp_obd->obd_fail || exp->exp_failed))
		lut_client_del(&env, exp);
	lu_env_fini(&env);

	class_export_put(exp);
	RETURN(rc);
}

static int ofd_init_export(struct obd_export *exp)
{
	int rc;

	cfs_spin_lock_init(&exp->exp_filter_data.fed_lock);
	CFS_INIT_LIST_HEAD(&exp->exp_filter_data.fed_mod_list);
	cfs_spin_lock(&exp->exp_lock);
	exp->exp_connecting = 1;
	cfs_spin_unlock(&exp->exp_lock);

	/* self-export doesn't need client data and ldlm initialization */
	if (unlikely(obd_uuid_equals(&exp->exp_obd->obd_uuid,
				     &exp->exp_client_uuid)))
		return 0;

	rc = lut_client_alloc(exp);
	if (rc == 0)
		ldlm_init_export(exp);
	if (rc)
		CERROR("%s: Can't initialize export: rc %d\n",
		       exp->exp_obd->obd_name, rc);
	return rc;
}

static int ofd_destroy_export(struct obd_export *exp)
{
	if (exp->exp_filter_data.fed_pending)
		CERROR("%s: cli %s/%p has %lu pending on destroyed export"
		       "\n", exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
		       exp, exp->exp_filter_data.fed_pending);

	target_destroy_export(exp);

	if (unlikely(obd_uuid_equals(&exp->exp_obd->obd_uuid,
				     &exp->exp_client_uuid)))
		return 0;

	ldlm_destroy_export(exp);
	lut_client_free(exp);

	LASSERT(cfs_list_empty(&exp->exp_filter_data.fed_mod_list));
	return 0;
}

int ofd_obd_postrecov(struct obd_device *obd)
{
	struct lu_env		 env;
	struct lu_device	*ldev = obd->obd_lu_dev;
	int			 rc;

	ENTRY;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);
	ofd_info_init(&env, obd->obd_self_export);

	rc = ldev->ld_ops->ldo_recovery_complete(&env, ldev);
	lu_env_fini(&env);
	RETURN(rc);
}

static int ofd_obd_notify(struct obd_device *obd, struct obd_device *unused,
			  enum obd_notify_event ev, void *data)
{
	switch (ev) {
	case OBD_NOTIFY_CONFIG:
		LASSERT(obd->obd_no_conn);
		cfs_spin_lock(&obd->obd_dev_lock);
		obd->obd_no_conn = 0;
		cfs_spin_unlock(&obd->obd_dev_lock);
		break;
	default:
		CDEBUG(D_INFO, "%s: Unhandled notification %#x\n",
		       obd->obd_name, ev);
	}
	return 0;
}

struct obd_ops ofd_obd_ops = {
	.o_owner		= THIS_MODULE,
	.o_connect		= ofd_obd_connect,
	.o_reconnect		= ofd_obd_reconnect,
	.o_disconnect		= ofd_obd_disconnect,
	.o_init_export		= ofd_init_export,
	.o_destroy_export	= ofd_destroy_export,
	.o_postrecov		= ofd_obd_postrecov,
	.o_notify		= ofd_obd_notify,
};
