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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ofd/ofd_obd.c
 *
 * This file contains OBD API methods for OBD Filter Device (OFD) which are
 * used for export handling, configuration purposes and recovery.
 * Several methods are used by ECHO client only since it still uses OBD API.
 * Such methods have _echo_ prefix in name.
 *
 * Author: Andreas Dilger <andreas.dilger@intel.com>
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"
#include <obd_cksum.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_quota.h>
#include <lustre_lfsck.h>
#include <lustre_nodemap.h>

/**
 * Initialize OFD per-export statistics.
 *
 * This function sets up procfs entries for various OFD export counters. These
 * counters are for per-client statistics tracked on the server.
 *
 * \param[in] ofd	 OFD device
 * \param[in] exp	 OBD export
 * \param[in] client_nid NID of client
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_export_stats_init(struct ofd_device *ofd,
				 struct obd_export *exp,
				 lnet_nid_t *client_nid)
{
	struct obd_device	*obd = ofd_obd(ofd);
	struct nid_stat		*stats;
	int			 rc;

	ENTRY;

	if (obd_uuid_equals(&exp->exp_client_uuid, &obd->obd_uuid))
		/* Self-export gets no proc entry */
		RETURN(0);

	rc = lprocfs_exp_setup(exp, client_nid);
	if (rc != 0)
		/* Mask error for already created /proc entries */
		RETURN(rc == -EALREADY ? 0 : rc);

	stats = exp->exp_nid_stats;
	stats->nid_stats = lprocfs_alloc_stats(LPROC_OFD_STATS_LAST,
					       LPROCFS_STATS_FLAG_NOPERCPU);
	if (!stats->nid_stats)
		RETURN(-ENOMEM);

	ofd_stats_counter_init(stats->nid_stats, 0);

	rc = lprocfs_register_stats(stats->nid_proc, "stats", stats->nid_stats);
	if (rc != 0) {
		lprocfs_free_stats(&stats->nid_stats);
		GOTO(out, rc);
	}

	rc = lprocfs_nid_ldlm_stats_init(stats);
	if (rc != 0)
		GOTO(out, rc);

out:
	RETURN(rc);
}

/**
 * Match client and OST server connection feature flags.
 *
 * Compute the compatibility flags for a connection request based on
 * features mutually supported by client and server.
 *
 * The obd_export::exp_connect_data.ocd_connect_flags field in \a exp
 * must not be updated here, otherwise a partially initialized value may
 * be exposed. After the connection request is successfully processed,
 * the top-level tgt_connect() request handler atomically updates the export
 * connect flags from the obd_connect_data::ocd_connect_flags field of the
 * reply. \see tgt_connect().
 *
 * Before 2.7.50 clients will send a struct obd_connect_data_v1 rather than a
 * full struct obd_connect_data. So care must be taken when accessing fields
 * that are not present in struct obd_connect_data_v1. See LU-16.
 *
 * \param[in] env		execution environment
 * \param[in] exp		the obd_export associated with this
 *				client/target pair
 * \param[in] data		stores data for this connect request
 * \param[in] new_connection	is this connection new or not
 *
 * \retval		0 if success
 * \retval		-EPROTO client and server feature requirements are
 *			incompatible
 * \retval		-EBADF  OST index in connect request doesn't match
 *			real OST index
 */
static int ofd_parse_connect_data(const struct lu_env *env,
				  struct obd_export *exp,
				  struct obd_connect_data *data,
				  bool new_connection)
{
	struct ofd_device *ofd = ofd_exp(exp);
	struct filter_export_data *fed = &exp->exp_filter_data;

	if (!data)
		RETURN(0);

	CDEBUG(D_RPCTRACE,
	       "%s: cli %s/%p ocd_connect_flags: %#llx ocd_version: %x ocd_grant: %d ocd_index: %u ocd_group %u\n",
	       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
	       data->ocd_connect_flags, data->ocd_version,
	       data->ocd_grant, data->ocd_index, data->ocd_group);

	if (fed->fed_group != 0 && fed->fed_group != data->ocd_group) {
		CWARN("!!! This export (nid %s) used object group %d earlier; now it's trying to use group %d!  This could be a bug in the MDS. Please report to https://jira.whamcloud.com/\n",
		      obd_export_nid2str(exp), fed->fed_group,
		      data->ocd_group);
		RETURN(-EPROTO);
	}
	fed->fed_group = data->ocd_group;

	data->ocd_connect_flags &= OST_CONNECT_SUPPORTED;

	if (data->ocd_connect_flags & OBD_CONNECT_FLAGS2)
		data->ocd_connect_flags2 &= OST_CONNECT_SUPPORTED2;

	/* Kindly make sure the SKIP_ORPHAN flag is from MDS. */
	if (data->ocd_connect_flags & OBD_CONNECT_MDS)
		CDEBUG(D_HA, "%s: Received MDS connection for group %u\n",
		       exp->exp_obd->obd_name, data->ocd_group);
	else if (data->ocd_connect_flags & OBD_CONNECT_SKIP_ORPHAN)
		RETURN(-EPROTO);

	/* Determine optimal brw size before calculating grant */
	if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_SIZE)) {
		data->ocd_brw_size = 65536;
	} else if (OCD_HAS_FLAG(data, BRW_SIZE)) {
		if (data->ocd_brw_size > ofd->ofd_brw_size)
			data->ocd_brw_size = ofd->ofd_brw_size;
		if (data->ocd_brw_size == 0) {
			CERROR("%s: cli %s/%p ocd_connect_flags: %#llx ocd_version: %x ocd_grant: %d ocd_index: %u ocd_brw_size is unexpectedly zero, network data corruption? Refusing connection of this client\n",
			       exp->exp_obd->obd_name,
			       exp->exp_client_uuid.uuid,
			       exp, data->ocd_connect_flags, data->ocd_version,
			       data->ocd_grant, data->ocd_index);
			RETURN(-EPROTO);
		}
	}

	if (OCD_HAS_FLAG(data, GRANT_PARAM)) {
		struct dt_device_param *ddp = &ofd->ofd_lut.lut_dt_conf;

		/* client is reporting its page size, for future use */
		exp->exp_target_data.ted_pagebits = data->ocd_grant_blkbits;
		data->ocd_grant_blkbits  = ofd->ofd_lut.lut_tgd.tgd_blockbits;
		/*
		 * ddp_inodespace may not be power-of-two value, eg. for ldiskfs
		 * it's LDISKFS_DIR_REC_LEN(20) = 28.
		 */
		data->ocd_grant_inobits = fls(ddp->ddp_inodespace - 1);
		/* ocd_grant_tax_kb is in 1K byte blocks */
		data->ocd_grant_tax_kb = ddp->ddp_extent_tax >> 10;
		data->ocd_grant_max_blks = ddp->ddp_max_extent_blks;
	}

	/*
	 * Save connect_data we have so far because tgt_grant_connect()
	 * uses it to calculate grant, and we want to save the client
	 * version before it is overwritten by LUSTRE_VERSION_CODE.
	 */
	exp->exp_connect_data = *data;
	if (OCD_HAS_FLAG(data, GRANT))
		tgt_grant_connect(env, exp, data, new_connection);

	if (data->ocd_connect_flags & OBD_CONNECT_INDEX) {
		struct lr_server_data *lsd = &ofd->ofd_lut.lut_lsd;
		int		       index = lsd->lsd_osd_index;

		if (index != data->ocd_index) {
			LCONSOLE_ERROR_MSG(0x136,
					   "Connection from %s to index %u doesn't match actual OST index %u in last_rcvd file, bad configuration?\n",
					   obd_export_nid2str(exp), index,
					   data->ocd_index);
			RETURN(-EBADF);
		}
		if (!(lsd->lsd_feature_compat & OBD_COMPAT_OST)) {
			/* this will only happen on the first connect */
			lsd->lsd_feature_compat |= OBD_COMPAT_OST;
			/*
			 * sync is not needed here as tgt_client_new will
			 * set exp_need_sync flag
			 */
			tgt_server_data_update(env, &ofd->ofd_lut, 0);
		}
	}

	if (data->ocd_connect_flags & OBD_CONNECT_CKSUM) {
		__u32 cksum_types = data->ocd_cksum_types;

		tgt_mask_cksum_types(&ofd->ofd_lut, &data->ocd_cksum_types);

		if (unlikely(data->ocd_cksum_types == 0)) {
			CERROR("%s: Connect with checksum support but no ocd_cksum_types is set\n",
			       exp->exp_obd->obd_name);
			RETURN(-EPROTO);
		}

		CDEBUG(D_RPCTRACE,
		       "%s: cli %s supports cksum type %x, return %x\n",
		       exp->exp_obd->obd_name, obd_export_nid2str(exp),
		       cksum_types, data->ocd_cksum_types);
	} else {
		/*
		 * This client does not support OBD_CONNECT_CKSUM.
		 * Report failure to negotiate checksum at connect
		 */
		CDEBUG(D_RPCTRACE,
		       "%s: cli %s does not support OBD_CONNECT_CKSUM\n",
		       exp->exp_obd->obd_name, obd_export_nid2str(exp));
	}

	if (data->ocd_connect_flags & OBD_CONNECT_MAXBYTES)
		data->ocd_maxbytes = ofd->ofd_lut.lut_dt_conf.ddp_maxbytes;

	data->ocd_version = LUSTRE_VERSION_CODE;

	if (OCD_HAS_FLAG(data, PINGLESS)) {
		if (ptlrpc_pinger_suppress_pings()) {
			spin_lock(&exp->exp_obd->obd_dev_lock);
			list_del_init(&exp->exp_obd_chain_timed);
			spin_unlock(&exp->exp_obd->obd_dev_lock);
		} else {
			data->ocd_connect_flags &= ~OBD_CONNECT_PINGLESS;
		}
	}

	if (!ofd->ofd_lut.lut_dt_conf.ddp_has_lseek_data_hole)
		data->ocd_connect_flags2 &= ~OBD_CONNECT2_LSEEK;

	RETURN(0);
}

/**
 * Re-initialize export upon client reconnection.
 *
 * This function parses connection data from reconnect and resets
 * export statistics.
 *
 * \param[in] env	execution environment
 * \param[in] exp	OBD export
 * \param[in] obd	OFD device
 * \param[in] cluuid	NID of client
 * \param[in] data	connection data from request
 * \param[in] localdata	client NID
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_obd_reconnect(const struct lu_env *env, struct obd_export *exp,
			     struct obd_device *obd, struct obd_uuid *cluuid,
			     struct obd_connect_data *data,
			     void *client_nid)
{
	struct ofd_device *ofd;
	int rc;

	ENTRY;

	if (!exp || !obd || !cluuid)
		RETURN(-EINVAL);

	rc = nodemap_add_member(*(lnet_nid_t *)client_nid, exp);
	if (rc != 0 && rc != -EEXIST)
		RETURN(rc);

	ofd = ofd_dev(obd->obd_lu_dev);

	rc = ofd_parse_connect_data(env, exp, data, false);
	if (rc == 0)
		ofd_export_stats_init(ofd, exp, client_nid);
	else
		nodemap_del_member(exp);

	RETURN(rc);
}

/**
 * Initialize new client connection.
 *
 * This function handles new connection to the OFD. The new export is
 * created (in context of class_connect()) and persistent client data is
 * initialized on storage.
 *
 * \param[in] env	execution environment
 * \param[out] _exp	stores pointer to new export
 * \param[in] obd	OFD device
 * \param[in] cluuid	client UUID
 * \param[in] data	connection data from request
 * \param[in] localdata	client NID
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_obd_connect(const struct lu_env *env, struct obd_export **_exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct obd_export *exp;
	struct ofd_device *ofd;
	struct lustre_handle conn = { 0 };
	int rc;

	ENTRY;

	if (!_exp || !obd || !cluuid)
		RETURN(-EINVAL);

	ofd = ofd_dev(obd->obd_lu_dev);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	exp = class_conn2export(&conn);
	LASSERT(exp != NULL);

	if (localdata) {
		rc = nodemap_add_member(*(lnet_nid_t *)localdata, exp);
		if (rc != 0 && rc != -EEXIST)
			GOTO(out, rc);
	} else {
		CDEBUG(D_HA,
		       "%s: cannot find nodemap for client %s: nid is null\n",
		       obd->obd_name, cluuid->uuid);
	}

	rc = ofd_parse_connect_data(env, exp, data, true);
	if (rc)
		GOTO(out, rc);

	if (obd->obd_replayable) {
		struct tg_export_data *ted = &exp->exp_target_data;

		memcpy(ted->ted_lcd->lcd_uuid, cluuid,
		       sizeof(ted->ted_lcd->lcd_uuid));
		rc = tgt_client_new(env, exp);
		if (rc != 0)
			GOTO(out, rc);
		ofd_export_stats_init(ofd, exp, localdata);
	}

	CDEBUG(D_HA, "%s: get connection from MDS %d\n", obd->obd_name,
	       data ? data->ocd_group : -1);

out:
	if (rc != 0) {
		class_disconnect(exp);
		nodemap_del_member(exp);
		*_exp = NULL;
	} else {
		*_exp = exp;
	}
	RETURN(rc);
}

/**
 * Disconnect a connected client.
 *
 * This function terminates the client connection. The client export is
 * disconnected (cleaned up) and client data on persistent storage is removed.
 *
 * \param[in] exp	OBD export
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_obd_disconnect(struct obd_export *exp)
{
	struct ofd_device *ofd = ofd_exp(exp);
	struct lu_env env;
	int rc;

	ENTRY;

	LASSERT(exp);
	class_export_get(exp);

	if (!(exp->exp_flags & OBD_OPT_FORCE))
		tgt_grant_sanity_check(ofd_obd(ofd), __func__);

	rc = server_disconnect_export(exp);

	tgt_grant_discard(exp);

	/* Do not erase record for recoverable client. */
	if (exp->exp_obd->obd_replayable &&
	    (!exp->exp_obd->obd_fail || exp->exp_failed)) {
		rc = lu_env_init(&env, LCT_DT_THREAD);
		if (rc)
			GOTO(out, rc);

		tgt_client_del(&env, exp);
		lu_env_fini(&env);
	}
out:
	nodemap_del_member(exp);
	class_export_put(exp);
	RETURN(rc);
}

/**
 * Implementation of obd_ops::o_init_export.
 *
 * This function is called from class_new_export() and initializes
 * the OFD-specific data for new export.
 *
 * \param[in] exp	OBD export
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_init_export(struct obd_export *exp)
{
	int rc;

	atomic_set(&exp->exp_filter_data.fed_soft_sync_count, 0);
	spin_lock(&exp->exp_lock);
	exp->exp_connecting = 1;
	spin_unlock(&exp->exp_lock);

	/* self-export doesn't need client data and ldlm initialization */
	if (unlikely(obd_uuid_equals(&exp->exp_obd->obd_uuid,
				     &exp->exp_client_uuid)))
		return 0;

	rc = tgt_client_alloc(exp);
	if (rc == 0)
		ldlm_init_export(exp);
	if (rc)
		CERROR("%s: Can't initialize export: rc %d\n",
		       exp->exp_obd->obd_name, rc);
	return rc;
}

/**
 * Implementation of obd_ops::o_destroy_export.
 *
 * This function is called from class_export_destroy() to cleanup
 * the OFD-specific data for export being destroyed.
 *
 * \param[in] exp	OBD export
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_destroy_export(struct obd_export *exp)
{
	struct ofd_device *ofd = ofd_exp(exp);

	if (exp->exp_target_data.ted_pending)
		CERROR("%s: cli %s/%p has %lu pending on destroyed export\n",
		       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
		       exp, exp->exp_target_data.ted_pending);

	target_destroy_export(exp);

	if (unlikely(obd_uuid_equals(&exp->exp_obd->obd_uuid,
				     &exp->exp_client_uuid)))
		return 0;

	ldlm_destroy_export(exp);
	tgt_client_free(exp);

	/*
	 * discard grants once we're sure no more
	 * interaction with the client is possible
	 */
	tgt_grant_discard(exp);

	if (exp_connect_flags(exp) & OBD_CONNECT_GRANT)
		ofd->ofd_lut.lut_tgd.tgd_tot_granted_clients--;

	if (!(exp->exp_flags & OBD_OPT_FORCE))
		tgt_grant_sanity_check(exp->exp_obd, __func__);

	return 0;
}

/**
 * Notify all devices in server stack about recovery completion.
 *
 * This function calls ldo_recovery_complete() for all lower devices in the
 * server stack so they will be prepared for normal operations.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_postrecov(const struct lu_env *env, struct ofd_device *ofd)
{
	struct lu_device *ldev = &ofd->ofd_dt_dev.dd_lu_dev;
	int rc;

	CDEBUG(D_HA, "%s: recovery is over\n", ofd_name(ofd));

	if (!ofd->ofd_skip_lfsck && !ofd->ofd_osd->dd_rdonly) {
		struct lfsck_start_param lsp;

		lsp.lsp_start = NULL;
		lsp.lsp_index_valid = 0;
		rc = lfsck_start(env, ofd->ofd_osd, &lsp);
		if (rc != 0 && rc != -EALREADY)
			CWARN("%s: auto trigger paused LFSCK failed: rc = %d\n",
			      ofd_name(ofd), rc);
	}

	return ldev->ld_ops->ldo_recovery_complete(env, ldev);
}

/**
 * Implementation of obd_ops::o_postrecov.
 *
 * This function is called from target_finish_recovery() upon recovery
 * completion.
 *
 * \param[in] obd	OBD device of OFD
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_obd_postrecov(struct obd_device *obd)
{
	struct lu_env env;
	struct lu_device *ldev = obd->obd_lu_dev;
	int rc;

	ENTRY;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);
	ofd_info_init(&env, obd->obd_self_export);

	rc = ofd_postrecov(&env, ofd_dev(ldev));

	lu_env_fini(&env);
	RETURN(rc);
}

/**
 * Implementation of obd_ops::o_set_info_async.
 *
 * This function is not called from request handler, it is only used by
 * class_notify_sptlrpc_conf() locally by direct obd_set_info_async() call.
 * \see  ofd_set_info_hdl() for request handler function.
 *
 * \param[in] env	execution environment
 * \param[in] exp	OBD export of OFD device
 * \param[in] keylen	length of \a key
 * \param[in] key	key name
 * \param[in] vallen	length of \a val
 * \param[in] val	the \a key value
 * \param[in] set	not used in OFD
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_set_info_async(const struct lu_env *env, struct obd_export *exp,
			      __u32 keylen, void *key, __u32 vallen, void *val,
			      struct ptlrpc_request_set *set)
{
	int rc = 0;

	ENTRY;

	if (!exp->exp_obd) {
		CDEBUG(D_IOCTL, "invalid export %p\n", exp);
		RETURN(-EINVAL);
	}

	if (KEY_IS(KEY_SPTLRPC_CONF)) {
		rc = tgt_adapt_sptlrpc_conf(class_exp2tgt(exp));
	} else {
		CERROR("%s: Unsupported key %s\n",
		       exp->exp_obd->obd_name, (char *)key);
		rc = -EOPNOTSUPP;
	}
	RETURN(rc);
}

/**
 * Implementation of obd_ops::o_get_info.
 *
 * This function is not called from request handler, it is only used by
 * direct call from nrs_orr_range_fill_physical() in ptlrpc, see LU-3239.
 *
 * \see  ofd_get_info_hdl() for request handler function.
 *
 * \param[in]  env	execution environment
 * \param[in]  exp	OBD export of OFD device
 * \param[in]  keylen	length of \a key
 * \param[in]  key	key name
 * \param[out] vallen	length of key value
 * \param[out] val	the key value to return
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_get_info(const struct lu_env *env, struct obd_export *exp,
			__u32 keylen, void *key, __u32 *vallen, void *val)
{
	struct ofd_thread_info *info;
	struct ofd_device *ofd;
	struct ll_fiemap_info_key *fm_key = key;
	struct fiemap *fiemap = val;
	int rc = 0;

	ENTRY;

	if (!exp->exp_obd) {
		CDEBUG(D_IOCTL, "invalid client export %p\n", exp);
		RETURN(-EINVAL);
	}

	ofd = ofd_exp(exp);

	if (KEY_IS(KEY_FIEMAP)) {
		info = ofd_info_init(env, exp);

		rc = ostid_to_fid(&info->fti_fid, &fm_key->lfik_oa.o_oi,
				  ofd->ofd_lut.lut_lsd.lsd_osd_index);
		if (rc != 0)
			RETURN(rc);

		rc = ofd_fiemap_get(env, ofd, &info->fti_fid, fiemap);
	} else {
		CERROR("%s: not supported key %s\n",
		       ofd_name(ofd), (char *)key);
		rc = -EOPNOTSUPP;
	}

	RETURN(rc);
}

/**
 * Implementation of obd_ops::o_statfs.
 *
 * This function returns information about a storage file system.
 * It is called from several places by using the OBD API as well as
 * by direct call, e.g. from request handler.
 *
 * \see  ofd_statfs_hdl() for request handler function.
 *
 * Report also the state of the OST to the caller in osfs->os_state
 * (OS_STATFS_READONLY, OS_STATFS_DEGRADED).
 *
 * \param[in]  env	execution environment
 * \param[in]  exp	OBD export of OFD device
 * \param[out] osfs	statistic data to return
 * \param[in]  max_age	maximum age for cached data
 * \param[in]  flags	not used in OFD
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_statfs(const struct lu_env *env,  struct obd_export *exp,
	       struct obd_statfs *osfs, time64_t max_age, __u32 flags)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct ofd_device *ofd = ofd_exp(exp);
	struct tg_grants_data *tgd = &ofd->ofd_lut.lut_tgd;
	int current_blockbits;
	int rc;

	ENTRY;

	rc = tgt_statfs_internal(env, &ofd->ofd_lut, osfs, max_age, NULL);
	if (unlikely(rc))
		GOTO(out, rc);

	/* tgd_blockbit is recordsize bits set during mkfs.
	 * This once set does not change. However, 'zfs set'
	 * can be used to change the OST blocksize. Instead
	 * of using cached value of 'tgd_blockbit' always
	 * calculate the blocksize bits which may have
	 * changed.
	 */
	current_blockbits = fls64(osfs->os_bsize) - 1;

	/*
	 * at least try to account for cached pages.  its still racy and
	 * might be under-reporting if clients haven't announced their
	 * caches with brw recently
	 */
	CDEBUG(D_SUPER | D_CACHE,
	       "blocks cached %llu granted %llu pending %llu free %llu avail %llu\n",
	       tgd->tgd_tot_dirty, tgd->tgd_tot_granted,
	       tgd->tgd_tot_pending,
	       osfs->os_bfree << current_blockbits,
	       osfs->os_bavail << current_blockbits);

	osfs->os_bavail -= min_t(u64, osfs->os_bavail,
				 ((tgd->tgd_tot_dirty + tgd->tgd_tot_pending +
				   osfs->os_bsize - 1) >> current_blockbits));

	/*
	 * The QoS code on the MDS does not care about space reserved for
	 * precreate, so take it out.
	 */
	if (exp_connect_flags(exp) & OBD_CONNECT_MDS) {
		struct tg_export_data *ted;

		ted = &obd->obd_self_export->exp_target_data;
		osfs->os_granted = min_t(u64, osfs->os_bavail,
					  ted->ted_grant >> current_blockbits);
		osfs->os_bavail -= osfs->os_granted;
	}

	tgt_grant_sanity_check(obd, __func__);
	CDEBUG(D_CACHE, "%llu blocks: %llu free, %llu avail; "
	       "%llu objects: %llu free; state %x\n",
	       osfs->os_blocks, osfs->os_bfree, osfs->os_bavail,
	       osfs->os_files, osfs->os_ffree, osfs->os_state);

	if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOINO,
				 ofd->ofd_lut.lut_lsd.lsd_osd_index)) {
		/* Reduce free inode count to zero, but keep "used" intact */
		osfs->os_files -= osfs->os_ffree;
		osfs->os_ffree -= osfs->os_ffree;
	}

	/* OS_STATFS_READONLY can be set by OSD already */
	if (ofd->ofd_raid_degraded)
		osfs->os_state |= OS_STATFS_DEGRADED;

	if (ofd->ofd_no_precreate)
		osfs->os_state |= OS_STATFS_NOPRECREATE;

	if (obd->obd_self_export != exp && !exp_grant_param_supp(exp) &&
	    current_blockbits > COMPAT_BSIZE_SHIFT) {
		/*
		 * clients which don't support OBD_CONNECT_GRANT_PARAM
		 * should not see a block size > page size, otherwise
		 * cl_lost_grant goes mad. Therefore, we emulate a 4KB (=2^12)
		 * block size which is the biggest block size known to work
		 * with all client's page size.
		 */
		osfs->os_blocks <<= current_blockbits - COMPAT_BSIZE_SHIFT;
		osfs->os_bfree  <<= current_blockbits - COMPAT_BSIZE_SHIFT;
		osfs->os_bavail <<= current_blockbits - COMPAT_BSIZE_SHIFT;
		osfs->os_granted <<= current_blockbits - COMPAT_BSIZE_SHIFT;
		osfs->os_bsize    = 1 << COMPAT_BSIZE_SHIFT;
	}

	if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOSPC,
				 ofd->ofd_lut.lut_lsd.lsd_osd_index)) {
		/* Reduce free blocks count near zero, but keep "used" intact */
		osfs->os_bavail -= osfs->os_bavail - 2;
		osfs->os_blocks -= osfs->os_bfree - 2;
		osfs->os_bfree -= osfs->os_bfree - 2;
	}

	EXIT;
out:
	return rc;
}

/**
 * Implementation of obd_ops::o_setattr.
 *
 * This function is only used by ECHO client when it is run on top of OFD,
 * \see  ofd_setattr_hdl() for request handler function.

 * \param[in] env	execution environment
 * \param[in] exp	OBD export of OFD device
 * \param[in] oa	setattr parameters
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_echo_setattr(const struct lu_env *env, struct obd_export *exp,
			    struct obdo *oa)
{
	struct ofd_thread_info *info;
	struct ofd_device *ofd = ofd_exp(exp);
	struct ldlm_namespace *ns = ofd->ofd_namespace;
	struct ldlm_resource *res;
	struct ofd_object *fo;
	struct lu_fid *fid = &oa->o_oi.oi_fid;
	ktime_t kstart = ktime_get();
	int rc = 0;

	ENTRY;

	info = ofd_info_init(env, exp);

	ost_fid_build_resid(fid, &info->fti_resid);

	/*
	 * This would be very bad - accidentally truncating a file when
	 * changing the time or similar - bug 12203.
	 */
	if (oa->o_valid & OBD_MD_FLSIZE) {
		static char mdsinum[48];

		if (oa->o_valid & OBD_MD_FLFID)
			snprintf(mdsinum, sizeof(mdsinum) - 1,
				 "of parent "DFID, oa->o_parent_seq,
				 oa->o_parent_oid, 0);
		else
			mdsinum[0] = '\0';

		CERROR("%s: setattr from %s trying to truncate object "DFID
		       " %s\n", ofd_name(ofd), obd_export_nid2str(exp),
		       PFID(fid), mdsinum);
		GOTO(out, rc = -EPERM);
	}

	fo = ofd_object_find_exists(env, ofd, fid);
	if (IS_ERR(fo)) {
		CERROR("%s: can't find object "DFID"\n",
		       ofd_name(ofd), PFID(fid));
		GOTO(out, rc = PTR_ERR(fo));
	}

	la_from_obdo(&info->fti_attr, oa, oa->o_valid);
	info->fti_attr.la_valid &= ~LA_TYPE;

	/* setting objects attributes (including owner/group) */
	rc = ofd_attr_set(env, fo, &info->fti_attr, oa);
	if (rc)
		GOTO(out_unlock, rc);

	ofd_counter_incr(exp, LPROC_OFD_STATS_SETATTR, NULL,
			 ktime_us_delta(ktime_get(), kstart));
	EXIT;
out_unlock:
	ofd_object_put(env, fo);
out:
	if (rc == 0) {
		/*
		 * we do not call this before to avoid lu_object_find() in
		 *  ->lvbo_update() holding another reference on the object.
		 * otherwise concurrent destroy can make the object unavailable
		 * for 2nd lu_object_find() waiting for the first reference
		 * to go... deadlock!
		 */
		res = ldlm_resource_get(ns, NULL, &info->fti_resid,
					LDLM_EXTENT, 0);
		if (!IS_ERR(res)) {
			ldlm_res_lvbo_update(res, NULL, 0);
			ldlm_resource_putref(res);
		}
	}

	return rc;
}

/**
 * Destroy OFD object by its FID.
 *
 * Supplemental function to destroy object by FID, it is used by request
 * handler and by ofd_echo_destroy() below to find object by FID, lock it
 * and call ofd_destroy() finally.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] fid	FID of object
 * \param[in] orphan	set if object being destroyed is an orphan
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_destroy_by_fid(const struct lu_env *env, struct ofd_device *ofd,
		       const struct lu_fid *fid, int orphan)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct lustre_handle lockh;
	union ldlm_policy_data policy = { .l_extent = { 0, OBD_OBJECT_EOF } };
	struct ofd_object *fo;
	__u64 flags = LDLM_FL_AST_DISCARD_DATA;
	__u64 rc = 0;

	ENTRY;

	fo = ofd_object_find_exists(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));

	/*
	 * Tell the clients that the object is gone now and that they should
	 * throw away any cached pages.
	 */
	ost_fid_build_resid(fid, &info->fti_resid);
	rc = ldlm_cli_enqueue_local(env, ofd->ofd_namespace, &info->fti_resid,
				    LDLM_EXTENT, &policy, LCK_PW, &flags,
				    ldlm_blocking_ast, ldlm_completion_ast,
				    NULL, NULL, 0, LVB_T_NONE, NULL, &lockh);

	/* We only care about the side-effects, just drop the lock. */
	if (rc == ELDLM_OK)
		ldlm_lock_decref(&lockh, LCK_PW);

	LASSERT(fo != NULL);

	rc = ofd_destroy(env, fo, orphan);
	EXIT;

	ofd_object_put(env, fo);
	RETURN(rc);
}

/**
 * Implementation of obd_ops::o_destroy.
 *
 * This function is only used by ECHO client when it is run on top of OFD,
 * \see  ofd_destroy_hdl() for request handler function.

 * \param[in] env	execution environment
 * \param[in] exp	OBD export of OFD device
 * \param[in] oa	obdo structure with FID
 *
 * Note: this is OBD API method which is common API for server OBDs and
 * client OBDs. Thus some parameters used in client OBDs may not be used
 * on server OBDs and vice versa.
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_echo_destroy(const struct lu_env *env, struct obd_export *exp,
			    struct obdo *oa)
{
	struct ofd_device *ofd = ofd_exp(exp);
	struct lu_fid *fid = &oa->o_oi.oi_fid;
	int rc = 0;

	ENTRY;

	ofd_info_init(env, exp);

	rc = ofd_validate_seq(exp, ostid_seq(&oa->o_oi));
	if (rc != 0)
		RETURN(rc);

	CDEBUG(D_HA, "%s: Destroy object "DFID"\n", ofd_name(ofd), PFID(fid));

	rc = ofd_destroy_by_fid(env, ofd, fid, 0);
	if (rc == -ENOENT) {
		CDEBUG(D_INODE, "%s: destroying non-existent object "DFID"\n",
		       ofd_name(ofd), PFID(fid));
		GOTO(out, rc);
	} else if (rc != 0) {
		CERROR("%s: error destroying object "DFID": %d\n",
		       ofd_name(ofd), PFID(fid), rc);
		GOTO(out, rc);
	}
	EXIT;
out:
	return rc;
}

/**
 * Implementation of obd_ops::o_create.
 *
 * This function is only used by ECHO client when it is run on top of OFD
 * and just creates an object.
 * \see  ofd_create_hdl() for request handler function.
 *
 * \param[in]  env	execution environment
 * \param[in]  exp	OBD export of OFD device
 * \param[in]  oa	obdo structure with FID sequence to use
 *
 * Note: this is OBD API method which is common API for server OBDs and
 * client OBDs. Thus some parameters used in client OBDs may not be used
 * on server OBDs and vice versa.
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_echo_create(const struct lu_env *env, struct obd_export *exp,
			   struct obdo *oa)
{
	struct ofd_device *ofd = ofd_exp(exp);
	u64 seq = ostid_seq(&oa->o_oi);
	struct ofd_seq *oseq;
	long granted;
	u64 next_id;
	s64 diff = 1;
	int rc = 0;
	int count;

	ENTRY;

	if (ofd->ofd_no_precreate)
		return -EPERM;

	ofd_info_init(env, exp);

	LASSERT(seq == FID_SEQ_ECHO);
	LASSERT(oa->o_valid & OBD_MD_FLGROUP);

	CDEBUG(D_INFO, "ofd_create("DOSTID")\n", POSTID(&oa->o_oi));

	down_read(&ofd->ofd_lastid_rwsem);
	/*
	 * Currently, for safe, we do not distinguish which LAST_ID is broken,
	 * we may do that in the future.
	 * Return -ENOSPC until the LAST_ID rebuilt.
	 */
	if (unlikely(ofd->ofd_lastid_rebuilding))
		GOTO(out_sem, rc = -ENOSPC);

	rc = ofd_validate_seq(exp, seq);
	if (rc != 0)
		RETURN(rc);

	oseq = ofd_seq_load(env, ofd, seq);
	if (IS_ERR(oseq)) {
		CERROR("%s: Can't find FID Sequence %#llx: rc = %ld\n",
		       ofd_name(ofd), seq, PTR_ERR(oseq));
		GOTO(out_sem, rc = -EINVAL);
	}

	mutex_lock(&oseq->os_create_lock);
	granted = tgt_grant_create(env, ofd_obd(ofd)->obd_self_export, &diff);
	if (granted < 0) {
		rc = granted;
		granted = 0;
		CDEBUG(D_HA,
		       "%s: failed to acquire grant space for precreate (%lld): rc = %d\n",
		       ofd_name(ofd), diff, rc);
		diff = 0;
		GOTO(out, rc);
	}

	next_id = ofd_seq_last_oid(oseq) + 1;
	count = ofd_precreate_batch(ofd, (int)diff);

	rc = ofd_precreate_objects(env, ofd, next_id, oseq, count, 0);
	if (rc < 0) {
		CERROR("%s: unable to precreate: rc = %d\n",
		       ofd_name(ofd), rc);
	} else {
		rc = ostid_set_id(&oa->o_oi, ofd_seq_last_oid(oseq));
		if (rc) {
			CERROR("%s: Bad %llu to set " DOSTID " : rc %d\n",
			       ofd_name(ofd),
			       (unsigned long long)ofd_seq_last_oid(oseq),
			       POSTID(&oa->o_oi), rc);
		}
		oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP;
	}

	tgt_grant_commit(ofd_obd(ofd)->obd_self_export, granted, rc);
out:
	mutex_unlock(&oseq->os_create_lock);
	ofd_seq_put(env, oseq);

out_sem:
	up_read(&ofd->ofd_lastid_rwsem);
	RETURN(rc);
}

/**
 * Implementation of obd_ops::o_getattr.
 *
 * This function is only used by ECHO client when it is run on top of OFD
 * and returns attributes of object.
 * \see  ofd_getattr_hdl() for request handler function.
 *
 * \param[in]	  env	execution environment
 * \param[in]	  exp	OBD export of OFD device
 * \param[in,out] oa	contains FID of object to get attributes from and
 *			is used to return attributes back
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_echo_getattr(const struct lu_env *env, struct obd_export *exp,
			    struct obdo *oa)
{
	struct ofd_device *ofd = ofd_exp(exp);
	struct ofd_thread_info *info;
	struct lu_fid *fid = &oa->o_oi.oi_fid;
	struct ofd_object *fo;
	int rc = 0;

	ENTRY;

	info = ofd_info_init(env, exp);

	fo = ofd_object_find_exists(env, ofd, fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));

	LASSERT(fo != NULL);
	rc = ofd_attr_get(env, fo, &info->fti_attr);
	oa->o_valid = OBD_MD_FLID;
	if (rc == 0) {
		__u64 curr_version;

		obdo_from_la(oa, &info->fti_attr,
			     OFD_VALID_FLAGS | LA_UID | LA_GID | LA_PROJID);

		/* Store object version in reply */
		curr_version = dt_version_get(env, ofd_object_child(fo));
		if ((__s64)curr_version != -EOPNOTSUPP) {
			oa->o_valid |= OBD_MD_FLDATAVERSION;
			oa->o_data_version = curr_version;
		}
	}

	ofd_object_put(env, fo);
out:
	RETURN(rc);
}

/**
 * Get object version for OBD_IOC_GET_OBJ_VERSION ioctl.
 *
 * This is supplemental function for ofd_iocontrol() to return object
 * version for lctl tool.
 *
 * \param[in]  env	execution environment
 * \param[in]  ofd	OFD device
 * \param[out] karg	ioctl data
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_ioc_get_obj_version(const struct lu_env *env,
				   struct ofd_device *ofd, void *karg)
{
	struct obd_ioctl_data *data = karg;
	struct lu_fid fid;
	struct ofd_object *fo;
	dt_obj_version_t version;
	int rc = 0;

	ENTRY;

	if (!data->ioc_inlbuf2 || data->ioc_inllen2 != sizeof(version))
		GOTO(out, rc = -EINVAL);

	if (data->ioc_inlbuf1 && data->ioc_inllen1 == sizeof(fid)) {
		fid = *(struct lu_fid *)data->ioc_inlbuf1;
	} else if (data->ioc_inlbuf3 &&
		   data->ioc_inllen3 == sizeof(__u64) &&
		   data->ioc_inlbuf4 &&
		   data->ioc_inllen4 == sizeof(__u64)) {
		struct ost_id ostid = { };

		ostid_set_seq(&ostid, *(__u64 *)data->ioc_inlbuf4);
		rc = ostid_set_id(&ostid, *(__u64 *)data->ioc_inlbuf3);
		if (rc)
			GOTO(out, rc);
		rc = ostid_to_fid(&fid, &ostid,
				  ofd->ofd_lut.lut_lsd.lsd_osd_index);
		if (rc != 0)
			GOTO(out, rc);
	} else {
		GOTO(out, rc = -EINVAL);
	}

	if (!fid_is_sane(&fid))
		GOTO(out, rc = -EINVAL);

	fo = ofd_object_find(env, ofd, &fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));

	if (!ofd_object_exists(fo))
		GOTO(out_fo, rc = -ENOENT);

	if (lu_object_remote(&fo->ofo_obj.do_lu))
		GOTO(out_fo, rc = -EREMOTE);

	version = dt_version_get(env, ofd_object_child(fo));
	if (version == 0)
		GOTO(out_fo, rc = -EIO);

	*(dt_obj_version_t *)data->ioc_inlbuf2 = version;

	EXIT;
out_fo:
	ofd_object_put(env, fo);
out:
	return rc;
}

/**
 * Implementation of obd_ops::o_iocontrol.
 *
 * This is OFD ioctl handling function which is primary interface for
 * Lustre tools like lfs, lctl and lfsck.
 *
 * \param[in]	  cmd	ioctl command
 * \param[in]	  exp	OBD export of OFD
 * \param[in]	  len	not used
 * \param[in,out] karg	buffer with data
 * \param[in]	  uarg	not used
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
			 void *karg, void __user *uarg)
{
	struct lu_env env;
	struct ofd_device *ofd = ofd_exp(exp);
	struct obd_device *obd = ofd_obd(ofd);
	int rc;

	ENTRY;

	CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);
	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);

	switch (cmd) {
	case OBD_IOC_ABORT_RECOVERY:
		CERROR("%s: aborting recovery\n", obd->obd_name);
		obd->obd_abort_recovery = 1;
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
	case OBD_IOC_START_LFSCK: {
		struct obd_ioctl_data *data = karg;
		struct lfsck_start_param lsp;

		if (unlikely(!data)) {
			rc = -EINVAL;
			break;
		}

		lsp.lsp_start = (struct lfsck_start *)(data->ioc_inlbuf1);
		lsp.lsp_index_valid = 0;
		rc = lfsck_start(&env, ofd->ofd_osd, &lsp);
		break;
	}
	case OBD_IOC_STOP_LFSCK: {
		struct obd_ioctl_data *data = karg;
		struct lfsck_stop      stop;

		stop.ls_status = LS_STOPPED;
		/* Old lfsck utils may pass NULL @stop. */
		if (!data->ioc_inlbuf1)
			stop.ls_flags = 0;
		else
			stop.ls_flags =
			((struct lfsck_stop *)(data->ioc_inlbuf1))->ls_flags;

		rc = lfsck_stop(&env, ofd->ofd_osd, &stop);
		break;
	}
	case OBD_IOC_GET_OBJ_VERSION:
		rc = ofd_ioc_get_obj_version(&env, ofd, karg);
		break;
	default:
		CERROR("%s: not supported cmd = %#x\n", obd->obd_name, cmd);
		rc = -ENOTTY;
	}

	lu_env_fini(&env);
	RETURN(rc);
}

/**
 * Implementation of obd_ops::o_precleanup.
 *
 * This function stops device activity before shutting it down. It is called
 * from a cleanup function upon forceful device cleanup. For OFD there are no
 * special actions, it just invokes target_recovery_cleanup().
 *
 * \param[in] obd	OBD device of OFD
 *
 * \retval		0
 */
static int ofd_precleanup(struct obd_device *obd)
{
	ENTRY;
	target_cleanup_recovery(obd);
	RETURN(0);
}

/**
 * Implementation of obd_ops::o_health_check.
 *
 * This function checks the OFD device health - ability to respond on
 * incoming requests. There are two health_check methods:
 * - get statfs from the OSD. It checks just responsiveness of
 *   bottom device
 * - do write attempt on bottom device to check it is fully operational and
 *   is not stuck. This is expensive method and requires special configuration
 *   option --enable-health-write while building Lustre, it is turned off
 *   by default.
 *
 * \param[in] nul	not used
 * \param[in] obd	OBD device of OFD
 *
 * \retval		0 if successful
 * \retval		negative value in case of error
 */
static int ofd_health_check(const struct lu_env *nul, struct obd_device *obd)
{
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	struct ofd_thread_info *info;
	struct lu_env env;
#ifdef USE_HEALTH_CHECK_WRITE
	struct thandle *th;
#endif
	int rc = 0;

	/* obd_proc_read_health pass NULL env, we need real one */
	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);

	info = ofd_info_init(&env, NULL);
	rc = dt_statfs(&env, ofd->ofd_osd, &info->fti_u.osfs);
	if (unlikely(rc))
		GOTO(out, rc);

	if (info->fti_u.osfs.os_state & OS_STATFS_READONLY)
		GOTO(out, rc = -EROFS);

#ifdef USE_HEALTH_CHECK_WRITE
	OBD_ALLOC(info->fti_buf.lb_buf, PAGE_SIZE);
	if (!info->fti_buf.lb_buf)
		GOTO(out, rc = -ENOMEM);

	info->fti_buf.lb_len = PAGE_SIZE;
	info->fti_off = 0;

	th = dt_trans_create(&env, ofd->ofd_osd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_record_write(&env, ofd->ofd_health_check_file,
				     &info->fti_buf, info->fti_off, th);
	if (rc == 0) {
		th->th_sync = 1; /* sync IO is needed */
		rc = dt_trans_start_local(&env, ofd->ofd_osd, th);
		if (rc == 0)
			rc = dt_record_write(&env, ofd->ofd_health_check_file,
					     &info->fti_buf, &info->fti_off,
					     th);
	}
	dt_trans_stop(&env, ofd->ofd_osd, th);

	OBD_FREE(info->fti_buf.lb_buf, PAGE_SIZE);

	CDEBUG(D_INFO, "write 1 page synchronously for checking io rc %d\n",
	       rc);
#endif
out:
	lu_env_fini(&env);
	return !!rc;
}

const struct obd_ops ofd_obd_ops = {
	.o_owner		= THIS_MODULE,
	.o_connect		= ofd_obd_connect,
	.o_reconnect		= ofd_obd_reconnect,
	.o_disconnect		= ofd_obd_disconnect,
	.o_create		= ofd_echo_create,
	.o_statfs		= ofd_statfs,
	.o_setattr		= ofd_echo_setattr,
	.o_preprw		= ofd_preprw,
	.o_commitrw		= ofd_commitrw,
	.o_destroy		= ofd_echo_destroy,
	.o_init_export		= ofd_init_export,
	.o_destroy_export	= ofd_destroy_export,
	.o_postrecov		= ofd_obd_postrecov,
	.o_getattr		= ofd_echo_getattr,
	.o_iocontrol		= ofd_iocontrol,
	.o_precleanup		= ofd_precleanup,
	.o_health_check		= ofd_health_check,
	.o_set_info_async	= ofd_set_info_async,
	.o_get_info		= ofd_get_info,
};
