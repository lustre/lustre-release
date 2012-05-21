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

static int ofd_export_stats_init(struct ofd_device *ofd,
				 struct obd_export *exp, void *client_nid)
{
	struct obd_device	*obd = ofd_obd(ofd);
	struct nid_stat		*stats;
	int			 num_stats, i;
	int			 rc, newnid = 0;

	ENTRY;

	if (obd_uuid_equals(&exp->exp_client_uuid, &obd->obd_uuid))
		/* Self-export gets no proc entry */
		RETURN(0);

	rc = lprocfs_exp_setup(exp, client_nid, &newnid);
	if (rc) {
		/* Mask error for already created
		 * /proc entries */
		if (rc == -EALREADY)
			rc = 0;
		RETURN(rc);
	}

	if (newnid == 0)
		RETURN(0);

	stats = exp->exp_nid_stats;
	LASSERT(stats != NULL);

	OBD_ALLOC(stats->nid_brw_stats, sizeof(struct brw_stats));
	if (stats->nid_brw_stats == NULL)
		GOTO(clean, rc = -ENOMEM);

	for (i = 0; i < BRW_LAST; i++)
		cfs_spin_lock_init(&stats->nid_brw_stats->hist[i].oh_lock);

	rc = lprocfs_seq_create(stats->nid_proc, "brw_stats", 0644,
				&ofd_per_nid_stats_fops, stats);
	if (rc)
		CWARN("Error adding the brw_stats file\n");

	num_stats = (sizeof(*obd->obd_type->typ_dt_ops) / sizeof(void *)) +
		     LPROC_OFD_LAST - 1;

	stats->nid_stats = lprocfs_alloc_stats(num_stats,
					       LPROCFS_STATS_FLAG_NOPERCPU);
	if (stats->nid_stats == NULL)
		return -ENOMEM;

	lprocfs_init_ops_stats(LPROC_OFD_LAST, stats->nid_stats);
	lprocfs_counter_init(stats->nid_stats, LPROC_OFD_READ_BYTES,
			     LPROCFS_CNTR_AVGMINMAX, "read_bytes", "bytes");
	lprocfs_counter_init(stats->nid_stats, LPROC_OFD_WRITE_BYTES,
			     LPROCFS_CNTR_AVGMINMAX, "write_bytes", "bytes");

	rc = lprocfs_register_stats(stats->nid_proc, "stats",
				    stats->nid_stats);
	if (rc)
		GOTO(clean, rc);

	rc = lprocfs_nid_ldlm_stats_init(stats);
	if (rc) {
		lprocfs_free_stats(&stats->nid_stats);
		GOTO(clean, rc);
	}

	RETURN(0);
clean:
	return rc;
}

static int ofd_parse_connect_data(const struct lu_env *env,
				  struct obd_export *exp,
				  struct obd_connect_data *data)
{
	struct ofd_device		 *ofd = ofd_exp(exp);
	struct filter_export_data	 *fed = &exp->exp_filter_data;

	if (!data)
		RETURN(0);

	CDEBUG(D_RPCTRACE, "%s: cli %s/%p ocd_connect_flags: "LPX64
	       " ocd_version: %x ocd_grant: %d ocd_index: %u\n",
	       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
	       data->ocd_connect_flags, data->ocd_version,
	       data->ocd_grant, data->ocd_index);

	if (fed->fed_group != 0 && fed->fed_group != data->ocd_group) {
		CWARN("!!! This export (nid %s) used object group %d "
		      "earlier; now it's trying to use group %d!  This could "
		      "be a bug in the MDS. Please report to "
		      "http://bugs.whamcloud.com/\n",
		      obd_export_nid2str(exp), fed->fed_group,
		      data->ocd_group);
		RETURN(-EPROTO);
	}
	fed->fed_group = data->ocd_group;

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
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 rc;

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
	if (rc == 0)
		ofd_export_stats_init(ofd, exp, localdata);

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

	group = data->ocd_group;
	if (obd->obd_replayable) {
		struct tg_export_data *ted = &exp->exp_target_data;

		memcpy(ted->ted_lcd->lcd_uuid, cluuid,
		       sizeof(ted->ted_lcd->lcd_uuid));
		rc = lut_client_new(env, exp);
		if (rc != 0)
			GOTO(out, rc);
		ofd_export_stats_init(ofd, exp, localdata);
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

static int ofd_set_mds_conn(struct obd_export *exp, void *val)
{
	int rc = 0;

	ENTRY;

	LCONSOLE_WARN("%s: received MDS connection from %s\n",
		      exp->exp_obd->obd_name, obd_export_nid2str(exp));
	RETURN(rc);
}

static int ofd_set_info_async(const struct lu_env *env, struct obd_export *exp,
			      __u32 keylen, void *key, __u32 vallen, void *val,
			      struct ptlrpc_request_set *set)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	int			 rc = 0;

	ENTRY;

	if (exp->exp_obd == NULL) {
		CDEBUG(D_IOCTL, "invalid export %p\n", exp);
		RETURN(-EINVAL);
	}

	if (KEY_IS(KEY_CAPA_KEY)) {
		rc = ofd_update_capa_key(ofd, val);
		if (rc)
			CERROR("ofd update capability key failed: %d\n", rc);
	} else if (KEY_IS(KEY_MDS_CONN)) {
		rc = ofd_set_mds_conn(exp, val);
	} else {
		CERROR("%s: Unsupported key %s\n",
		       exp->exp_obd->obd_name, (char*)key);
		rc = -EOPNOTSUPP;
	}

	RETURN(rc);
}

static int ofd_get_info(const struct lu_env *env, struct obd_export *exp,
			__u32 keylen, void *key, __u32 *vallen, void *val,
			struct lov_stripe_md *lsm)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	int			 rc = 0;

	ENTRY;

	if (exp->exp_obd == NULL) {
		CDEBUG(D_IOCTL, "invalid client export %p\n", exp);
		RETURN(-EINVAL);
	}

	if (KEY_IS(KEY_BLOCKSIZE)) {
		__u32 *blocksize = val;
		if (blocksize) {
			if (*vallen < sizeof(*blocksize))
				RETURN(-EOVERFLOW);
			*blocksize = 1 << ofd->ofd_dt_conf.ddp_block_shift;
		}
		*vallen = sizeof(*blocksize);
	} else if (KEY_IS(KEY_BLOCKSIZE_BITS)) {
		__u32 *blocksize_bits = val;
		if (blocksize_bits) {
			if (*vallen < sizeof(*blocksize_bits))
				RETURN(-EOVERFLOW);
			*blocksize_bits = ofd->ofd_dt_conf.ddp_block_shift;
		}
		*vallen = sizeof(*blocksize_bits);
	} else if (KEY_IS(KEY_LAST_ID)) {
		obd_id *last_id = val;
		if (last_id) {
			if (*vallen < sizeof(*last_id))
				RETURN(-EOVERFLOW);
			*last_id = ofd_last_id(ofd,
					       exp->exp_filter_data.fed_group);
		}
		*vallen = sizeof(*last_id);
	} else {
		CERROR("Not supported key %s\n", (char*)key);
		rc = -EOPNOTSUPP;
	}

	RETURN(rc);
}

/** helper function for statfs, also used by grant code */
int ofd_statfs_internal(const struct lu_env *env, struct ofd_device *ofd,
                        struct obd_statfs *osfs, __u64 max_age, int *from_cache)
{
	int rc;

	rc = dt_statfs(env, ofd->ofd_osd, osfs);
	if (unlikely(rc))
		return rc;

	return 0;
}

static int ofd_statfs(const struct lu_env *env,  struct obd_export *exp,
		      struct obd_statfs *osfs, __u64 max_age, __u32 flags)
{
	struct ofd_device	*ofd = ofd_dev(exp->exp_obd->obd_lu_dev);
	int			 rc;

	ENTRY;

	rc = ofd_statfs_internal(env, ofd, osfs, max_age, NULL);
	if (unlikely(rc))
		GOTO(out, rc);

	if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOSPC,
				 ofd->ofd_lut.lut_lsd.lsd_ost_index))
		osfs->os_bfree = osfs->os_bavail = 2;

	if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOINO,
				 ofd->ofd_lut.lut_lsd.lsd_ost_index))
		osfs->os_ffree = 0;

	/* OS_STATE_READONLY can be set by OSD already */
	if (ofd->ofd_raid_degraded)
		osfs->os_state |= OS_STATE_DEGRADED;
	EXIT;
out:
	return rc;
}

static int ofd_sync(const struct lu_env *env, struct obd_export *exp,
		    struct obd_info *oinfo, obd_size start, obd_size end,
		    struct ptlrpc_request_set *set)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	int			 rc = 0;

	ENTRY;

	/* if no objid is specified, it means "sync whole filesystem" */
	if (oinfo->oi_oa == NULL || !(oinfo->oi_oa->o_valid & OBD_MD_FLID)) {
		rc = dt_sync(env, ofd->ofd_osd);
		GOTO(out, rc);
	}

	EXIT;
out:
	return rc;
}

int ofd_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
		  void *karg, void *uarg)
{
	struct lu_env		 env;
	struct ofd_device	*ofd = ofd_exp(exp);
	struct obd_device	*obd = ofd_obd(ofd);
	int			 rc;

	ENTRY;

	CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);
	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		RETURN(rc);

	switch (cmd) {
	case OBD_IOC_ABORT_RECOVERY:
		CERROR("aborting recovery for device %s\n", obd->obd_name);
		target_stop_recovery_thread(obd);
		break;
	case OBD_IOC_SYNC:
		CDEBUG(D_RPCTRACE, "syncing ost %s\n", obd->obd_name);
		rc = dt_sync(&env, ofd->ofd_osd);
		break;
	case OBD_IOC_SET_READONLY:
		rc = dt_sync(&env, ofd->ofd_osd);
		if (rc == 0)
			rc = dt_ro(&env, ofd->ofd_osd);
		break;
	default:
		CERROR("Not supported cmd = %d for device %s\n",
		       cmd, obd->obd_name);
		rc = -ENOTTY;
	}

	lu_env_fini(&env);
	RETURN(rc);
}

static int ofd_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
	int rc = 0;

	ENTRY;

	switch(stage) {
	case OBD_CLEANUP_EARLY:
		break;
	case OBD_CLEANUP_EXPORTS:
		target_cleanup_recovery(obd);
		break;
	}
	RETURN(rc);
}

static int ofd_ping(const struct lu_env *env, struct obd_export *exp)
{
	return 0;
}

static int ofd_health_check(const struct lu_env *env, struct obd_device *obd)
{
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	struct ofd_thread_info	*info;
#ifdef USE_HEALTH_CHECK_WRITE
	struct thandle		*th;
#endif
	int			 rc = 0;

	info = ofd_info_init(env, NULL);
	rc = dt_statfs(env, ofd->ofd_osd, &info->fti_u.osfs);
	if (unlikely(rc))
		GOTO(out, rc);

	if (info->fti_u.osfs.os_state == OS_STATE_READONLY)
		GOTO(out, rc = -EROFS);

#ifdef USE_HEALTH_CHECK_WRITE
	OBD_ALLOC(info->fti_buf.lb_buf, CFS_PAGE_SIZE);
	if (info->fti_buf.lb_buf == NULL)
		GOTO(out, rc = -ENOMEM);

	info->fti_buf.lb_len = CFS_PAGE_SIZE;
	info->fti_off = 0;

	th = dt_trans_create(env, ofd->ofd_osd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_record_write(env, ofd->ofd_health_check_file,
				     info->fti_buf.lb_len, info->fti_off, th);
	if (rc == 0) {
		th->th_sync = 1; /* sync IO is needed */
		rc = dt_trans_start_local(env, ofd->ofd_osd, th);
		if (rc == 0)
			rc = dt_record_write(env, ofd->ofd_health_check_file,
					     &info->fti_buf, &info->fti_off,
					     th);
	}
	dt_trans_stop(env, ofd->ofd_osd, th);

	OBD_FREE(info->fti_buf.lb_buf, CFS_PAGE_SIZE);

	CDEBUG(D_INFO, "write 1 page synchronously for checking io rc %d\n",rc);
#endif
out:
	return !!rc;
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
	.o_set_info_async	= ofd_set_info_async,
	.o_get_info		= ofd_get_info,
	.o_statfs		= ofd_statfs,
	.o_init_export		= ofd_init_export,
	.o_destroy_export	= ofd_destroy_export,
	.o_postrecov		= ofd_obd_postrecov,
	.o_sync			= ofd_sync,
	.o_iocontrol		= ofd_iocontrol,
	.o_precleanup		= ofd_precleanup,
	.o_ping			= ofd_ping,
	.o_health_check		= ofd_health_check,
	.o_notify		= ofd_obd_notify,
};
