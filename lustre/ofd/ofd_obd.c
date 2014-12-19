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
 * Copyright (c) 2012, 2014 Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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

#include <lustre/lustre_idl.h>
#include "ofd_internal.h"
#include <obd_cksum.h>
#include <lustre_ioctl.h>
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
	int			 num_stats;
	int			 rc, newnid = 0;

	ENTRY;

	LASSERT(obd->obd_uses_nid_stats);

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

	num_stats = NUM_OBD_STATS + LPROC_OFD_STATS_LAST;

	stats->nid_stats = lprocfs_alloc_stats(num_stats,
					       LPROCFS_STATS_FLAG_NOPERCPU);
	if (stats->nid_stats == NULL)
		return -ENOMEM;

	lprocfs_init_ops_stats(LPROC_OFD_STATS_LAST, stats->nid_stats);
	ofd_stats_counter_init(stats->nid_stats);
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
	struct ofd_device		 *ofd = ofd_exp(exp);
	struct filter_export_data	 *fed = &exp->exp_filter_data;

	if (!data)
		RETURN(0);

	CDEBUG(D_RPCTRACE, "%s: cli %s/%p ocd_connect_flags: "LPX64
	       " ocd_version: %x ocd_grant: %d ocd_index: %u"
	       " ocd_group %u\n",
	       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
	       data->ocd_connect_flags, data->ocd_version,
	       data->ocd_grant, data->ocd_index, data->ocd_group);

	if (fed->fed_group != 0 && fed->fed_group != data->ocd_group) {
		CWARN("!!! This export (nid %s) used object group %d "
		      "earlier; now it's trying to use group %d!  This could "
		      "be a bug in the MDS. Please report to "
		      "https://jira.hpdd.intel.com/\n",
		      obd_export_nid2str(exp), fed->fed_group,
		      data->ocd_group);
		RETURN(-EPROTO);
	}
	fed->fed_group = data->ocd_group;

	data->ocd_connect_flags &= OST_CONNECT_SUPPORTED;
	data->ocd_version = LUSTRE_VERSION_CODE;

	/* Kindly make sure the SKIP_ORPHAN flag is from MDS. */
	if (data->ocd_connect_flags & OBD_CONNECT_MDS)
		CDEBUG(D_HA, "%s: Received MDS connection for group %u\n",
		       exp->exp_obd->obd_name, data->ocd_group);
	else if (data->ocd_connect_flags & OBD_CONNECT_SKIP_ORPHAN)
		RETURN(-EPROTO);

	if (ofd_grant_param_supp(exp)) {
		exp->exp_filter_data.fed_pagesize = data->ocd_blocksize;
		/* ocd_{blocksize,inodespace} are log2 values */
		data->ocd_blocksize  = ofd->ofd_blockbits;
		data->ocd_inodespace = ofd->ofd_dt_conf.ddp_inodespace;
		/* ocd_grant_extent is in 1K blocks */
		data->ocd_grant_extent = ofd->ofd_dt_conf.ddp_grant_frag >> 10;
	}

	if (data->ocd_connect_flags & OBD_CONNECT_GRANT)
		data->ocd_grant = ofd_grant_connect(env, exp, data->ocd_grant,
						    new_connection);

	if (data->ocd_connect_flags & OBD_CONNECT_INDEX) {
		struct lr_server_data *lsd = &ofd->ofd_lut.lut_lsd;
		int		       index = lsd->lsd_osd_index;

		if (index != data->ocd_index) {
			LCONSOLE_ERROR_MSG(0x136, "Connection from %s to index"
					   " %u doesn't match actual OST index"
					   " %u in last_rcvd file, bad "
					   "configuration?\n",
					   obd_export_nid2str(exp), index,
					   data->ocd_index);
			RETURN(-EBADF);
		}
		if (!(lsd->lsd_feature_compat & OBD_COMPAT_OST)) {
			/* this will only happen on the first connect */
			lsd->lsd_feature_compat |= OBD_COMPAT_OST;
			/* sync is not needed here as lut_client_add will
			 * set exp_need_sync flag */
			tgt_server_data_update(env, &ofd->ofd_lut, 0);
		}
	}
	if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_SIZE)) {
		data->ocd_brw_size = 65536;
	} else if (data->ocd_connect_flags & OBD_CONNECT_BRW_SIZE) {
		data->ocd_brw_size = min(data->ocd_brw_size,
					 (__u32)DT_MAX_BRW_SIZE);
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
		data->ocd_cksum_types &= cksum_types_supported_server();

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

	if (OCD_HAS_FLAG(data, PINGLESS)) {
		if (ptlrpc_pinger_suppress_pings()) {
			spin_lock(&exp->exp_obd->obd_dev_lock);
			list_del_init(&exp->exp_obd_chain_timed);
			spin_unlock(&exp->exp_obd->obd_dev_lock);
		} else {
			data->ocd_connect_flags &= ~OBD_CONNECT_PINGLESS;
		}
	}

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
	struct ofd_device	*ofd;
	int			 rc;

	ENTRY;

	if (exp == NULL || obd == NULL || cluuid == NULL)
		RETURN(-EINVAL);

	ofd = ofd_dev(obd->obd_lu_dev);

	rc = ofd_parse_connect_data(env, exp, data, false);
	if (rc == 0)
		ofd_export_stats_init(ofd, exp, client_nid);

	nodemap_add_member(*(lnet_nid_t *)client_nid, exp);

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
	struct obd_export	*exp;
	struct ofd_device	*ofd;
	struct lustre_handle	 conn = { 0 };
	int			 rc;
	lnet_nid_t		*client_nid;
	ENTRY;

	if (_exp == NULL || obd == NULL || cluuid == NULL)
		RETURN(-EINVAL);

	ofd = ofd_dev(obd->obd_lu_dev);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	exp = class_conn2export(&conn);
	LASSERT(exp != NULL);

	rc = ofd_parse_connect_data(env, exp, data, true);
	if (rc)
		GOTO(out, rc);

	if (localdata != NULL) {
		client_nid = localdata;
		nodemap_add_member(*client_nid, exp);
	}

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
		nodemap_del_member(exp);
		class_disconnect(exp);
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
	struct ofd_device	*ofd = ofd_exp(exp);
	struct lu_env		 env;
	int			 rc;

	ENTRY;

	LASSERT(exp);
	class_export_get(exp);

	if (!(exp->exp_flags & OBD_OPT_FORCE))
		ofd_grant_sanity_check(ofd_obd(ofd), __FUNCTION__);

	nodemap_del_member(exp);
	rc = server_disconnect_export(exp);

	ofd_grant_discard(exp);

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

	spin_lock_init(&exp->exp_filter_data.fed_lock);
	INIT_LIST_HEAD(&exp->exp_filter_data.fed_mod_list);
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

	if (exp->exp_filter_data.fed_pending)
		CERROR("%s: cli %s/%p has %lu pending on destroyed export"
		       "\n", exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
		       exp, exp->exp_filter_data.fed_pending);

	target_destroy_export(exp);

	if (unlikely(obd_uuid_equals(&exp->exp_obd->obd_uuid,
				     &exp->exp_client_uuid)))
		return 0;

	ldlm_destroy_export(exp);
	tgt_client_free(exp);

	ofd_fmd_cleanup(exp);

	/*
	 * discard grants once we're sure no more
	 * interaction with the client is possible
	 */
	ofd_grant_discard(exp);
	ofd_fmd_cleanup(exp);

	if (exp_connect_flags(exp) & OBD_CONNECT_GRANT_SHRINK) {
		if (ofd->ofd_tot_granted_clients > 0)
			ofd->ofd_tot_granted_clients --;
	}

	if (!(exp->exp_flags & OBD_OPT_FORCE))
		ofd_grant_sanity_check(exp->exp_obd, __FUNCTION__);

	LASSERT(list_empty(&exp->exp_filter_data.fed_mod_list));
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
	struct lfsck_start_param lsp;
	int rc;

	CDEBUG(D_HA, "%s: recovery is over\n", ofd_name(ofd));

	lsp.lsp_start = NULL;
	lsp.lsp_index_valid = 0;
	rc = lfsck_start(env, ofd->ofd_osd, &lsp);
	if (rc != 0 && rc != -EALREADY)
		CWARN("%s: auto trigger paused LFSCK failed: rc = %d\n",
		      ofd_name(ofd), rc);

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
	struct lu_env		 env;
	struct lu_device	*ldev = obd->obd_lu_dev;
	int			 rc;

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

	if (exp->exp_obd == NULL) {
		CDEBUG(D_IOCTL, "invalid export %p\n", exp);
		RETURN(-EINVAL);
	}

	if (KEY_IS(KEY_SPTLRPC_CONF)) {
		rc = tgt_adapt_sptlrpc_conf(class_exp2tgt(exp), 0);
	} else {
		CERROR("%s: Unsupported key %s\n",
		       exp->exp_obd->obd_name, (char*)key);
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
 * \param[in]  lsm	not used in OFD
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_get_info(const struct lu_env *env, struct obd_export *exp,
			__u32 keylen, void *key, __u32 *vallen, void *val,
			struct lov_stripe_md *lsm)
{
	struct ofd_thread_info		*info;
	struct ofd_device		*ofd;
	struct ll_fiemap_info_key	*fm_key = key;
	struct ll_user_fiemap		*fiemap = val;
	int				 rc = 0;

	ENTRY;

	if (exp->exp_obd == NULL) {
		CDEBUG(D_IOCTL, "invalid client export %p\n", exp);
		RETURN(-EINVAL);
	}

	ofd = ofd_exp(exp);

	if (KEY_IS(KEY_FIEMAP)) {
		info = ofd_info_init(env, exp);

		rc = ostid_to_fid(&info->fti_fid, &fm_key->oa.o_oi,
				  ofd->ofd_lut.lut_lsd.lsd_osd_index);
		if (rc != 0)
			RETURN(rc);

		rc = ofd_fiemap_get(env, ofd, &info->fti_fid, fiemap);
	} else {
		CERROR("%s: not supported key %s\n", ofd_name(ofd), (char*)key);
		rc = -EOPNOTSUPP;
	}

	RETURN(rc);
}

/**
 * Get file system statistics of OST server.
 *
 * Helper function for ofd_statfs(), also used by grant code.
 * Implements caching for statistics to avoid calling OSD device each time.
 *
 * \param[in]  env	  execution environment
 * \param[in]  ofd	  OFD device
 * \param[out] osfs	  statistic data to return
 * \param[in]  max_age	  maximum age for cached data
 * \param[in]  from_cache show that data was get from cache or not
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_statfs_internal(const struct lu_env *env, struct ofd_device *ofd,
                        struct obd_statfs *osfs, __u64 max_age, int *from_cache)
{
	int rc = 0;
	ENTRY;

	down_read(&ofd->ofd_lastid_rwsem);
	/* Currently, for safe, we do not distinguish which LAST_ID is broken,
	 * we may do that in the future.
	 * Return -ENOSPC until the LAST_ID rebuilt. */
	if (unlikely(ofd->ofd_lastid_rebuilding))
		GOTO(out, rc = -ENOSPC);

	spin_lock(&ofd->ofd_osfs_lock);
	if (cfs_time_before_64(ofd->ofd_osfs_age, max_age) || max_age == 0) {
		u64 unstable;

		/* statfs data are too old, get up-to-date one.
		 * we must be cautious here since multiple threads might be
		 * willing to update statfs data concurrently and we must
		 * grant that cached statfs data are always consistent */

		if (ofd->ofd_statfs_inflight == 0)
			/* clear inflight counter if no users, although it would
			 * take a while to overflow this 64-bit counter ... */
			ofd->ofd_osfs_inflight = 0;
		/* notify ofd_grant_commit() that we want to track writes
		 * completed as of now */
		ofd->ofd_statfs_inflight++;
		/* record value of inflight counter before running statfs to
		 * compute the diff once statfs is completed */
		unstable = ofd->ofd_osfs_inflight;
		spin_unlock(&ofd->ofd_osfs_lock);

		/* statfs can sleep ... hopefully not for too long since we can
		 * call it fairly often as space fills up */
		rc = dt_statfs(env, ofd->ofd_osd, osfs);
		if (unlikely(rc))
			GOTO(out, rc);

		spin_lock(&ofd->ofd_grant_lock);
		spin_lock(&ofd->ofd_osfs_lock);
		/* calculate how much space was written while we released the
		 * ofd_osfs_lock */
		unstable = ofd->ofd_osfs_inflight - unstable;
		ofd->ofd_osfs_unstable = 0;
		if (unstable) {
			/* some writes completed while we were running statfs
			 * w/o the ofd_osfs_lock. Those ones got added to
			 * the cached statfs data that we are about to crunch.
			 * Take them into account in the new statfs data */
			osfs->os_bavail -= min_t(u64, osfs->os_bavail,
					       unstable >> ofd->ofd_blockbits);
			/* However, we don't really know if those writes got
			 * accounted in the statfs call, so tell
			 * ofd_grant_space_left() there is some uncertainty
			 * on the accounting of those writes.
			 * The purpose is to prevent spurious error messages in
			 * ofd_grant_space_left() since those writes might be
			 * accounted twice. */
			ofd->ofd_osfs_unstable += unstable;
		}
		/* similarly, there is some uncertainty on write requests
		 * between prepare & commit */
		ofd->ofd_osfs_unstable += ofd->ofd_tot_pending;
		spin_unlock(&ofd->ofd_grant_lock);

		/* finally udpate cached statfs data */
		ofd->ofd_osfs = *osfs;
		ofd->ofd_osfs_age = cfs_time_current_64();

		ofd->ofd_statfs_inflight--; /* stop tracking */
		if (ofd->ofd_statfs_inflight == 0)
			ofd->ofd_osfs_inflight = 0;
		spin_unlock(&ofd->ofd_osfs_lock);

		if (from_cache)
			*from_cache = 0;
	} else {
		/* use cached statfs data */
		*osfs = ofd->ofd_osfs;
		spin_unlock(&ofd->ofd_osfs_lock);
		if (from_cache)
			*from_cache = 1;
	}

	GOTO(out, rc);

out:
	up_read(&ofd->ofd_lastid_rwsem);

	return rc;
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
 * (OS_STATE_READONLY, OS_STATE_DEGRADED).
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
	       struct obd_statfs *osfs, __u64 max_age, __u32 flags)
{
        struct obd_device	*obd = class_exp2obd(exp);
	struct ofd_device	*ofd = ofd_exp(exp);
	int			 rc;

	ENTRY;

	rc = ofd_statfs_internal(env, ofd, osfs, max_age, NULL);
	if (unlikely(rc))
		GOTO(out, rc);

	/* at least try to account for cached pages.  its still racy and
	 * might be under-reporting if clients haven't announced their
	 * caches with brw recently */

	CDEBUG(D_SUPER | D_CACHE, "blocks cached "LPU64" granted "LPU64
	       " pending "LPU64" free "LPU64" avail "LPU64"\n",
	       ofd->ofd_tot_dirty, ofd->ofd_tot_granted, ofd->ofd_tot_pending,
	       osfs->os_bfree << ofd->ofd_blockbits,
	       osfs->os_bavail << ofd->ofd_blockbits);

	osfs->os_bavail -= min_t(u64, osfs->os_bavail,
				 ((ofd->ofd_tot_dirty + ofd->ofd_tot_pending +
				   osfs->os_bsize - 1) >> ofd->ofd_blockbits));

	/* The QoS code on the MDS does not care about space reserved for
	 * precreate, so take it out. */
	if (exp_connect_flags(exp) & OBD_CONNECT_MDS) {
		struct filter_export_data *fed;

		fed = &obd->obd_self_export->exp_filter_data;
		osfs->os_bavail -= min_t(u64, osfs->os_bavail,
					 fed->fed_grant >> ofd->ofd_blockbits);
	}

	ofd_grant_sanity_check(obd, __FUNCTION__);
	CDEBUG(D_CACHE, LPU64" blocks: "LPU64" free, "LPU64" avail; "
	       LPU64" objects: "LPU64" free; state %x\n",
	       osfs->os_blocks, osfs->os_bfree, osfs->os_bavail,
	       osfs->os_files, osfs->os_ffree, osfs->os_state);

	if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOINO,
				 ofd->ofd_lut.lut_lsd.lsd_osd_index))
		osfs->os_ffree = 0;

	/* OS_STATE_READONLY can be set by OSD already */
	if (ofd->ofd_raid_degraded)
		osfs->os_state |= OS_STATE_DEGRADED;

	if (obd->obd_self_export != exp && ofd_grant_compat(exp, ofd)) {
		/* clients which don't support OBD_CONNECT_GRANT_PARAM
		 * should not see a block size > page size, otherwise
		 * cl_lost_grant goes mad. Therefore, we emulate a 4KB (=2^12)
		 * block size which is the biggest block size known to work
		 * with all client's page size. */
		osfs->os_blocks <<= ofd->ofd_blockbits - COMPAT_BSIZE_SHIFT;
		osfs->os_bfree  <<= ofd->ofd_blockbits - COMPAT_BSIZE_SHIFT;
		osfs->os_bavail <<= ofd->ofd_blockbits - COMPAT_BSIZE_SHIFT;
		osfs->os_bsize    = 1 << COMPAT_BSIZE_SHIFT;
	}

	if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOSPC,
				 ofd->ofd_lut.lut_lsd.lsd_osd_index))
		osfs->os_bfree = osfs->os_bavail = 2;

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
 * \param[in] oinfo	obd_info with setattr parameters
 * \param[in] oti	not used in OFD
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_echo_setattr(const struct lu_env *env, struct obd_export *exp,
			    struct obd_info *oinfo, struct obd_trans_info *oti)
{
	struct ofd_thread_info	*info;
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ldlm_namespace	*ns = ofd->ofd_namespace;
	struct ldlm_resource	*res;
	struct ofd_object	*fo;
	struct obdo		*oa = oinfo->oi_oa;
	struct lu_fid		*fid = &oa->o_oi.oi_fid;
	struct filter_fid	*ff = NULL;
	int			 rc = 0;

	ENTRY;

	info = ofd_info_init(env, exp);

	ost_fid_build_resid(fid, &info->fti_resid);

	/* This would be very bad - accidentally truncating a file when
	 * changing the time or similar - bug 12203. */
	if (oa->o_valid & OBD_MD_FLSIZE &&
	    oinfo->oi_policy.l_extent.end != OBD_OBJECT_EOF) {
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

	if (oa->o_valid & OBD_MD_FLFID) {
		ff = &info->fti_mds_fid;
		ofd_prepare_fidea(ff, oa);
	}

	/* setting objects attributes (including owner/group) */
	rc = ofd_attr_set(env, fo, &info->fti_attr, ff);
	if (rc)
		GOTO(out_unlock, rc);

	ofd_counter_incr(exp, LPROC_OFD_STATS_SETATTR, NULL, 1);
	EXIT;
out_unlock:
	ofd_object_put(env, fo);
out:
	if (rc == 0) {
		/* we do not call this before to avoid lu_object_find() in
		 *  ->lvbo_update() holding another reference on the object.
		 * otherwise concurrent destroy can make the object unavailable
		 * for 2nd lu_object_find() waiting for the first reference
		 * to go... deadlock! */
		res = ldlm_resource_get(ns, NULL, &info->fti_resid, LDLM_EXTENT, 0);
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
 * and call ofd_object_destroy() finally.
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
	struct ofd_thread_info	*info = ofd_info(env);
	struct lustre_handle	 lockh;
	__u64			 flags = LDLM_FL_AST_DISCARD_DATA;
	__u64			 rc = 0;
	ldlm_policy_data_t	 policy = {
					.l_extent = { 0, OBD_OBJECT_EOF }
				 };
	struct ofd_object	*fo;

	ENTRY;

	fo = ofd_object_find_exists(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));

	/* Tell the clients that the object is gone now and that they should
	 * throw away any cached pages. */
	ost_fid_build_resid(fid, &info->fti_resid);
	rc = ldlm_cli_enqueue_local(ofd->ofd_namespace, &info->fti_resid,
				    LDLM_EXTENT, &policy, LCK_PW, &flags,
				    ldlm_blocking_ast, ldlm_completion_ast,
				    NULL, NULL, 0, LVB_T_NONE, NULL, &lockh);

	/* We only care about the side-effects, just drop the lock. */
	if (rc == ELDLM_OK)
		ldlm_lock_decref(&lockh, LCK_PW);

	LASSERT(fo != NULL);

	rc = ofd_object_destroy(env, fo, orphan);
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
 * \param[in] oti	not used in OFD
 *
 * Note: this is OBD API method which is common API for server OBDs and
 * client OBDs. Thus some parameters used in client OBDs may not be used
 * on server OBDs and vice versa.
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_echo_destroy(const struct lu_env *env, struct obd_export *exp,
			    struct obdo *oa, struct obd_trans_info *oti)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct lu_fid		*fid = &oa->o_oi.oi_fid;
	int			 rc = 0;

	ENTRY;

	ofd_info_init(env, exp);

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
 * \param[out] ea	contains object ID/SEQ to return
 * \param[in]  oti	not used in OFD
 *
 * Note: this is OBD API method which is common API for server OBDs and
 * client OBDs. Thus some parameters used in client OBDs may not be used
 * on server OBDs and vice versa.
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_echo_create(const struct lu_env *env, struct obd_export *exp,
			   struct obdo *oa, struct obd_trans_info *oti)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	u64			 seq = ostid_seq(&oa->o_oi);
	struct ofd_seq		*oseq;
	int			 rc = 0, diff = 1;
	u64			 next_id;
	int			 count;

	ENTRY;

	info = ofd_info_init(env, exp);

	LASSERT(seq == FID_SEQ_ECHO);
	LASSERT(oa->o_valid & OBD_MD_FLGROUP);

	CDEBUG(D_INFO, "ofd_create("DOSTID")\n", POSTID(&oa->o_oi));

	down_read(&ofd->ofd_lastid_rwsem);
	/* Currently, for safe, we do not distinguish which LAST_ID is broken,
	 * we may do that in the future.
	 * Return -ENOSPC until the LAST_ID rebuilt. */
	if (unlikely(ofd->ofd_lastid_rebuilding))
		GOTO(out_sem, rc = -ENOSPC);

	oseq = ofd_seq_load(env, ofd, seq);
	if (IS_ERR(oseq)) {
		CERROR("%s: Can't find FID Sequence "LPX64": rc = %ld\n",
		       ofd_name(ofd), seq, PTR_ERR(oseq));
		GOTO(out_sem, rc = -EINVAL);
	}

	mutex_lock(&oseq->os_create_lock);
	rc = ofd_grant_create(env, ofd_obd(ofd)->obd_self_export, &diff);
	if (rc < 0) {
		CDEBUG(D_HA, "%s: failed to acquire grant space for "
		       "precreate (%d): rc = %d\n", ofd_name(ofd), diff, rc);
		diff = 0;
		GOTO(out, rc);
	}

	next_id = ofd_seq_last_oid(oseq) + 1;
	count = ofd_precreate_batch(ofd, diff);

	rc = ofd_precreate_objects(env, ofd, next_id, oseq, count, 0);
	if (rc < 0) {
		CERROR("%s: unable to precreate: rc = %d\n",
		       ofd_name(ofd), rc);
	} else {
		ostid_set_id(&oa->o_oi, ofd_seq_last_oid(oseq));
		oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP;
		rc = 0;
	}

	ofd_grant_commit(env, ofd_obd(ofd)->obd_self_export, rc);
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
 * \param[in,out] oinfo	contains FID of object to get attributes from and
 *			is used to return attributes back
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int ofd_echo_getattr(const struct lu_env *env, struct obd_export *exp,
			    struct obd_info *oinfo)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	struct lu_fid		*fid = &oinfo->oi_oa->o_oi.oi_fid;
	struct ofd_object	*fo;
	int			 rc = 0;

	ENTRY;

	info = ofd_info_init(env, exp);

	fo = ofd_object_find_exists(env, ofd, fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));

	LASSERT(fo != NULL);
	rc = ofd_attr_get(env, fo, &info->fti_attr);
	oinfo->oi_oa->o_valid = OBD_MD_FLID;
	if (rc == 0) {
		__u64 curr_version;

		obdo_from_la(oinfo->oi_oa, &info->fti_attr,
			     OFD_VALID_FLAGS | LA_UID | LA_GID);

		/* Store object version in reply */
		curr_version = dt_version_get(env, ofd_object_child(fo));
		if ((__s64)curr_version != -EOPNOTSUPP) {
			oinfo->oi_oa->o_valid |= OBD_MD_FLDATAVERSION;
			oinfo->oi_oa->o_data_version = curr_version;
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
	struct lu_fid	       fid;
	struct ofd_object     *fo;
	dt_obj_version_t       version;
	int		       rc = 0;

	ENTRY;

	if (data->ioc_inlbuf2 == NULL || data->ioc_inllen2 != sizeof(version))
		GOTO(out, rc = -EINVAL);

	if (data->ioc_inlbuf1 != NULL && data->ioc_inllen1 == sizeof(fid)) {
		fid = *(struct lu_fid *)data->ioc_inlbuf1;
	} else if (data->ioc_inlbuf3 != NULL &&
		   data->ioc_inllen3 == sizeof(__u64) &&
		   data->ioc_inlbuf4 != NULL &&
		   data->ioc_inllen4 == sizeof(__u64)) {
		struct ost_id ostid;

		ostid_set_seq(&ostid, *(__u64 *)data->ioc_inlbuf4);
		ostid_set_id(&ostid, *(__u64 *)data->ioc_inlbuf3);
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
			 void *karg, void *uarg)
{
	struct lu_env		 env;
	struct ofd_device	*ofd = ofd_exp(exp);
	struct obd_device	*obd = ofd_obd(ofd);
	int			 rc;

	ENTRY;

	CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);
	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);

	switch (cmd) {
	case OBD_IOC_ABORT_RECOVERY:
		CERROR("%s: aborting recovery\n", obd->obd_name);
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

		if (unlikely(data == NULL)) {
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
		if (data->ioc_inlbuf1 == NULL)
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
 * \param[in] stage	cleanup stage
 *
 * \retval		0
 */
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

/**
 * Implementation of obd_ops::o_ping.
 *
 * This is OFD-specific part of OBD_PING request handling.
 * It controls Filter Modification Data (FMD) expiration each time PING is
 * received.
 *
 * \see  ofd_fmd_expire() and ofd_fmd.c for details
 *
 * \param[in] env	execution environment
 * \param[in] exp	OBD export of client
 *
 * \retval		0
 */
static int ofd_ping(const struct lu_env *env, struct obd_export *exp)
{
	ofd_fmd_expire(exp);
	return 0;
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
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	struct ofd_thread_info	*info;
	struct lu_env		 env;
#ifdef USE_HEALTH_CHECK_WRITE
	struct thandle		*th;
#endif
	int			 rc = 0;

	/* obd_proc_read_health pass NULL env, we need real one */
	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);

	info = ofd_info_init(&env, NULL);
	rc = dt_statfs(&env, ofd->ofd_osd, &info->fti_u.osfs);
	if (unlikely(rc))
		GOTO(out, rc);

	if (info->fti_u.osfs.os_state == OS_STATE_READONLY)
		GOTO(out, rc = -EROFS);

#ifdef USE_HEALTH_CHECK_WRITE
	OBD_ALLOC(info->fti_buf.lb_buf, PAGE_CACHE_SIZE);
	if (info->fti_buf.lb_buf == NULL)
		GOTO(out, rc = -ENOMEM);

	info->fti_buf.lb_len = PAGE_CACHE_SIZE;
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

	OBD_FREE(info->fti_buf.lb_buf, PAGE_CACHE_SIZE);

	CDEBUG(D_INFO, "write 1 page synchronously for checking io rc %d\n",rc);
#endif
out:
	lu_env_fini(&env);
	return !!rc;
}

struct obd_ops ofd_obd_ops = {
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
	.o_ping			= ofd_ping,
	.o_health_check		= ofd_health_check,
	.o_set_info_async	= ofd_set_info_async,
	.o_get_info		= ofd_get_info,
};
