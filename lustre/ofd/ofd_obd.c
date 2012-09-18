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
 * Copyright (c) 2012, Intel Corporation.
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
#include <lquota.h>

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

	if (ofd_grant_param_supp(exp)) {
		exp->exp_filter_data.fed_pagesize = data->ocd_blocksize;
		/* ocd_{blocksize,inodespace} are log2 values */
		data->ocd_blocksize  = ofd->ofd_blockbits;
		data->ocd_inodespace = ofd->ofd_dt_conf.ddp_inodespace;
		/* ocd_grant_extent is in 1K blocks */
		data->ocd_grant_extent = ofd->ofd_dt_conf.ddp_grant_frag >> 10;
	}

	if (exp->exp_connect_flags & OBD_CONNECT_GRANT)
		data->ocd_grant = ofd_grant_connect(env, exp, data->ocd_grant);

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
	struct ofd_device	*ofd = ofd_dev(exp->exp_obd->obd_lu_dev);
	struct lu_env		 env;
	int			 rc;

	ENTRY;

	LASSERT(exp);
	class_export_get(exp);

	if (!(exp->exp_flags & OBD_OPT_FORCE))
		ofd_grant_sanity_check(ofd_obd(ofd), __FUNCTION__);

	rc = server_disconnect_export(exp);

	ofd_grant_discard(exp);

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
	struct ofd_device *ofd = ofd_dev(exp->exp_obd->obd_lu_dev);

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

	ofd_fmd_cleanup(exp);

	/*
	 * discard grants once we're sure no more
	 * interaction with the client is possible
	 */
	ofd_grant_discard(exp);
	ofd_fmd_cleanup(exp);

	if (exp->exp_connect_flags & OBD_CONNECT_GRANT_SHRINK) {
		if (ofd->ofd_tot_granted_clients > 0)
			ofd->ofd_tot_granted_clients --;
	}

	if (!(exp->exp_flags & OBD_OPT_FORCE))
		ofd_grant_sanity_check(exp->exp_obd, __FUNCTION__);

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

static int ofd_adapt_sptlrpc_conf(const struct lu_env *env,
				  struct obd_device *obd, int initial)
{
	struct filter_obd	*fo = &obd->u.filter;
	struct sptlrpc_rule_set	 tmp_rset;
	int			 rc;

	sptlrpc_rule_set_init(&tmp_rset);
	rc = sptlrpc_conf_target_get_rules(obd, &tmp_rset, initial);
	if (rc) {
		CERROR("%s: failed get sptlrpc rules: rc = %d\n",
		       obd->obd_name, rc);
		return rc;
	}

	sptlrpc_target_update_exp_flavor(obd, &tmp_rset);

	cfs_write_lock(&fo->fo_sptlrpc_lock);
	sptlrpc_rule_set_free(&fo->fo_sptlrpc_rset);
	fo->fo_sptlrpc_rset = tmp_rset;
	cfs_write_unlock(&fo->fo_sptlrpc_lock);

	return 0;
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
			CERROR("%s: update capability key failed: rc = %d\n",
			       exp->exp_obd->obd_name, rc);
	} else if (KEY_IS(KEY_SPTLRPC_CONF)) {
		ofd_adapt_sptlrpc_conf(env, exp->exp_obd, 0);
	} else if (KEY_IS(KEY_MDS_CONN)) {
		rc = ofd_set_mds_conn(exp, val);
	} else if (KEY_IS(KEY_GRANT_SHRINK)) {
		struct ost_body *body = val;

		/** handle grant shrink, similar to a read request */
		ofd_grant_prepare_read(env, exp, &body->oa);
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
	} else if (KEY_IS(KEY_FIEMAP)) {
		struct ofd_thread_info		*info;
		struct ofd_device		*ofd = ofd_exp(exp);
		struct ofd_object		*fo;
		struct ll_fiemap_info_key	*fm_key = key;

		if (val == NULL) {
			*vallen = fiemap_count_to_size(
					       fm_key->fiemap.fm_extent_count);
			RETURN(0);
		}

		info = ofd_info_init(env, exp);

		fid_ostid_unpack(&info->fti_fid, &fm_key->oa.o_oi, 0);

		CDEBUG(D_INODE, "get FIEMAP of object "DFID"\n",
		       PFID(&info->fti_fid));

		fo = ofd_object_find(env, ofd, &info->fti_fid);
		if (IS_ERR(fo)) {
			CERROR("%s: error finding object "DFID"\n",
			       exp->exp_obd->obd_name, PFID(&info->fti_fid));
			rc = PTR_ERR(fo);
		} else {
			struct ll_user_fiemap *fiemap = val;

			ofd_read_lock(env, fo);
			if (ofd_object_exists(fo)) {
				*fiemap = fm_key->fiemap;
				rc = dt_fiemap_get(env,
						   ofd_object_child(fo),
						   fiemap);
			} else {
				rc = -ENOENT;
			}
			ofd_read_unlock(env, fo);
			ofd_object_put(env, fo);
		}
	} else if (KEY_IS(KEY_SYNC_LOCK_CANCEL)) {
		*((__u32 *) val) = ofd->ofd_sync_lock_cancel;
		*vallen = sizeof(__u32);
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

	cfs_spin_lock(&ofd->ofd_osfs_lock);
	if (cfs_time_before_64(ofd->ofd_osfs_age, max_age) || max_age == 0) {
		obd_size unstable;

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
		cfs_spin_unlock(&ofd->ofd_osfs_lock);

		/* statfs can sleep ... hopefully not for too long since we can
		 * call it fairly often as space fills up */
		rc = dt_statfs(env, ofd->ofd_osd, osfs);
		if (unlikely(rc))
			return rc;

		cfs_spin_lock(&ofd->ofd_grant_lock);
		cfs_spin_lock(&ofd->ofd_osfs_lock);
		/* calculate how much space was written while we released the
		 * ofd_osfs_lock */
		unstable = ofd->ofd_osfs_inflight - unstable;
		ofd->ofd_osfs_unstable = 0;
		if (unstable) {
			/* some writes completed while we were running statfs
			 * w/o the ofd_osfs_lock. Those ones got added to
			 * the cached statfs data that we are about to crunch.
			 * Take them into account in the new statfs data */
			osfs->os_bavail -= min_t(obd_size, osfs->os_bavail,
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
		cfs_spin_unlock(&ofd->ofd_grant_lock);

		/* finally udpate cached statfs data */
		ofd->ofd_osfs = *osfs;
		ofd->ofd_osfs_age = cfs_time_current_64();

		ofd->ofd_statfs_inflight--; /* stop tracking */
		if (ofd->ofd_statfs_inflight == 0)
			ofd->ofd_osfs_inflight = 0;
		cfs_spin_unlock(&ofd->ofd_osfs_lock);

		if (from_cache)
			*from_cache = 0;
	} else {
		/* use cached statfs data */
		*osfs = ofd->ofd_osfs;
		cfs_spin_unlock(&ofd->ofd_osfs_lock);
		if (from_cache)
			*from_cache = 1;
	}
	return 0;
}

static int ofd_statfs(const struct lu_env *env,  struct obd_export *exp,
		      struct obd_statfs *osfs, __u64 max_age, __u32 flags)
{
        struct obd_device	*obd = class_exp2obd(exp);
	struct ofd_device	*ofd = ofd_dev(exp->exp_obd->obd_lu_dev);
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

	osfs->os_bavail -= min_t(obd_size, osfs->os_bavail,
				 ((ofd->ofd_tot_dirty + ofd->ofd_tot_pending +
				   osfs->os_bsize - 1) >> ofd->ofd_blockbits));

	/* The QoS code on the MDS does not care about space reserved for
	 * precreate, so take it out. */
	if (exp->exp_connect_flags & OBD_CONNECT_MDS) {
		struct filter_export_data *fed;

		fed = &obd->obd_self_export->exp_filter_data;
		osfs->os_bavail -= min_t(obd_size, osfs->os_bavail,
					 fed->fed_grant >> ofd->ofd_blockbits);
	}

	ofd_grant_sanity_check(obd, __FUNCTION__);
	CDEBUG(D_CACHE, LPU64" blocks: "LPU64" free, "LPU64" avail; "
	       LPU64" objects: "LPU64" free; state %x\n",
	       osfs->os_blocks, osfs->os_bfree, osfs->os_bavail,
	       osfs->os_files, osfs->os_ffree, osfs->os_state);

	if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOSPC,
				 ofd->ofd_lut.lut_lsd.lsd_ost_index))
		osfs->os_bfree = osfs->os_bavail = 2;

	if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOINO,
				 ofd->ofd_lut.lut_lsd.lsd_ost_index))
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

	EXIT;
out:
	return rc;
}

int ofd_setattr(const struct lu_env *env, struct obd_export *exp,
		struct obd_info *oinfo, struct obd_trans_info *oti)
{
	struct ofd_thread_info	*info;
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ldlm_namespace	*ns = ofd->ofd_namespace;
	struct ldlm_resource	*res;
	struct ofd_object	*fo;
	struct obdo		*oa = oinfo->oi_oa;
	struct filter_fid	*ff = NULL;
	int			 rc = 0;

	ENTRY;

	info = ofd_info_init(env, exp);
	ofd_oti2info(info, oti);

	fid_ostid_unpack(&info->fti_fid, &oinfo->oi_oa->o_oi, 0);
	ofd_build_resid(&info->fti_fid, &info->fti_resid);

	rc = ofd_auth_capa(exp, &info->fti_fid, oa->o_seq,
			   oinfo_capa(oinfo), CAPA_OPC_META_WRITE);
	if (rc)
		GOTO(out, rc);

	/* This would be very bad - accidentally truncating a file when
	 * changing the time or similar - bug 12203. */
	if (oinfo->oi_oa->o_valid & OBD_MD_FLSIZE &&
	    oinfo->oi_policy.l_extent.end != OBD_OBJECT_EOF) {
		static char mdsinum[48];

		if (oinfo->oi_oa->o_valid & OBD_MD_FLFID)
			snprintf(mdsinum, sizeof(mdsinum) - 1,
				 "of parent "DFID, oinfo->oi_oa->o_parent_seq,
				 oinfo->oi_oa->o_parent_oid, 0);
		else
			mdsinum[0] = '\0';

		CERROR("%s: setattr from %s trying to truncate object "DFID
		       " %s\n", exp->exp_obd->obd_name,
		       obd_export_nid2str(exp), PFID(&info->fti_fid), mdsinum);
		GOTO(out, rc = -EPERM);
	}

	fo = ofd_object_find(env, ofd, &info->fti_fid);
	if (IS_ERR(fo)) {
		CERROR("%s: can't find object "DFID"\n",
		       exp->exp_obd->obd_name, PFID(&info->fti_fid));
		GOTO(out, rc = PTR_ERR(fo));
	}

	la_from_obdo(&info->fti_attr, oinfo->oi_oa, oinfo->oi_oa->o_valid);
	info->fti_attr.la_valid &= ~LA_TYPE;

	if (oa->o_valid & OBD_MD_FLFID) {
		ff = &info->fti_mds_fid;
		ofd_prepare_fidea(ff, oa);
	}

	/* setting objects attributes (including owner/group) */
	rc = ofd_attr_set(env, fo, &info->fti_attr, ff);
	if (rc)
		GOTO(out_unlock, rc);

	res = ldlm_resource_get(ns, NULL, &info->fti_resid, LDLM_EXTENT, 0);
	if (res != NULL) {
		ldlm_res_lvbo_update(res, NULL, 0);
		ldlm_resource_putref(res);
	}

	oinfo->oi_oa->o_valid = OBD_MD_FLID;

	/* Quota release needs uid/gid info */
	rc = ofd_attr_get(env, fo, &info->fti_attr);
	obdo_from_la(oinfo->oi_oa, &info->fti_attr,
		     OFD_VALID_FLAGS | LA_UID | LA_GID);
	ofd_info2oti(info, oti);
out_unlock:
	ofd_object_put(env, fo);
out:
	RETURN(rc);
}

static int ofd_punch(const struct lu_env *env, struct obd_export *exp,
		     struct obd_info *oinfo, struct obd_trans_info *oti,
		     struct ptlrpc_request_set *rqset)
{
	struct ofd_thread_info	*info;
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ldlm_namespace	*ns = ofd->ofd_namespace;
	struct ldlm_resource	*res;
	struct ofd_object	*fo;
	struct filter_fid	*ff = NULL;
	int			 rc = 0;

	ENTRY;

	info = ofd_info_init(env, exp);
	ofd_oti2info(info, oti);

	fid_ostid_unpack(&info->fti_fid, &oinfo->oi_oa->o_oi, 0);
	ofd_build_resid(&info->fti_fid, &info->fti_resid);

	CDEBUG(D_INODE, "calling punch for object "DFID", valid = "LPX64
	       ", start = "LPD64", end = "LPD64"\n", PFID(&info->fti_fid),
	       oinfo->oi_oa->o_valid, oinfo->oi_policy.l_extent.start,
	       oinfo->oi_policy.l_extent.end);

	rc = ofd_auth_capa(exp, &info->fti_fid, oinfo->oi_oa->o_seq,
			   oinfo_capa(oinfo), CAPA_OPC_OSS_TRUNC);
	if (rc)
		GOTO(out_env, rc);

	fo = ofd_object_find(env, ofd, &info->fti_fid);
	if (IS_ERR(fo)) {
		CERROR("%s: error finding object "DFID": rc = %ld\n",
		       exp->exp_obd->obd_name, PFID(&info->fti_fid),
		       PTR_ERR(fo));
		GOTO(out_env, rc = PTR_ERR(fo));
	}

	LASSERT(oinfo->oi_policy.l_extent.end == OBD_OBJECT_EOF);
	if (oinfo->oi_policy.l_extent.end == OBD_OBJECT_EOF) {
		/* Truncate case */
		oinfo->oi_oa->o_size = oinfo->oi_policy.l_extent.start;
	} else if (oinfo->oi_policy.l_extent.end >= oinfo->oi_oa->o_size) {
		oinfo->oi_oa->o_size = oinfo->oi_policy.l_extent.end;
	}

	la_from_obdo(&info->fti_attr, oinfo->oi_oa,
		     OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME);
	info->fti_attr.la_valid &= ~LA_TYPE;
	info->fti_attr.la_size = oinfo->oi_policy.l_extent.start;
	info->fti_attr.la_valid |= LA_SIZE;

	if (oinfo->oi_oa->o_valid & OBD_MD_FLFID) {
		ff = &info->fti_mds_fid;
		ofd_prepare_fidea(ff, oinfo->oi_oa);
	}

	rc = ofd_object_punch(env, fo, oinfo->oi_policy.l_extent.start,
			      oinfo->oi_policy.l_extent.end, &info->fti_attr,
			      ff);
	if (rc)
		GOTO(out, rc);

	res = ldlm_resource_get(ns, NULL, &info->fti_resid, LDLM_EXTENT, 0);
	if (res != NULL) {
		ldlm_res_lvbo_update(res, NULL, 0);
		ldlm_resource_putref(res);
	}

	oinfo->oi_oa->o_valid = OBD_MD_FLID;
	/* Quota release needs uid/gid info */
	rc = ofd_attr_get(env, fo, &info->fti_attr);
	obdo_from_la(oinfo->oi_oa, &info->fti_attr,
		     OFD_VALID_FLAGS | LA_UID | LA_GID);
	ofd_info2oti(info, oti);
out:
	ofd_object_put(env, fo);
out_env:
	RETURN(rc);
}

static int ofd_destroy_by_fid(const struct lu_env *env,
			      struct ofd_device *ofd,
			      const struct lu_fid *fid, int orphan)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct lustre_handle	 lockh;
	int			 flags = LDLM_AST_DISCARD_DATA, rc = 0;
	ldlm_policy_data_t	 policy = {
					.l_extent = { 0, OBD_OBJECT_EOF }
				 };
	struct ofd_object	*fo;

	ENTRY;

	/* Tell the clients that the object is gone now and that they should
	 * throw away any cached pages. */
	ofd_build_resid(fid, &info->fti_resid);
	rc = ldlm_cli_enqueue_local(ofd->ofd_namespace, &info->fti_resid,
				    LDLM_EXTENT, &policy, LCK_PW, &flags,
				    ldlm_blocking_ast, ldlm_completion_ast,
				    NULL, NULL, 0, NULL, &lockh);

	/* We only care about the side-effects, just drop the lock. */
	if (rc == ELDLM_OK)
		ldlm_lock_decref(&lockh, LCK_PW);

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));
	LASSERT(fo != NULL);

	rc = ofd_object_destroy(env, fo, orphan);

	ofd_object_put(env, fo);
	RETURN(rc);
}

int ofd_destroy(const struct lu_env *env, struct obd_export *exp,
		struct obdo *oa, struct lov_stripe_md *md,
		struct obd_trans_info *oti, struct obd_export *md_exp,
		void *capa)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	obd_count		 count;
	int			 rc = 0;

	ENTRY;

	info = ofd_info_init(env, exp);
	ofd_oti2info(info, oti);

	if (!(oa->o_valid & OBD_MD_FLGROUP))
		oa->o_seq = 0;

	/* check that o_misc makes sense */
	if (oa->o_valid & OBD_MD_FLOBJCOUNT)
		count = oa->o_misc;
	else
		count = 1; /* default case - single destroy */

	/**
	 * There can be sequence of objects to destroy. Therefore this request
	 * may have multiple transaction involved in. It is OK, we need only
	 * the highest used transno to be reported back in reply but not for
	 * replays, they must report their transno
	 */
	if (info->fti_transno == 0) /* not replay */
		info->fti_mult_trans = 1;
	while (count > 0) {
		int lrc;

		fid_ostid_unpack(&info->fti_fid, &oa->o_oi, 0);
		lrc = ofd_destroy_by_fid(env, ofd, &info->fti_fid, 0);
		if (lrc == -ENOENT) {
			CDEBUG(D_INODE,
			       "destroying non-existent object "LPU64"\n",
			       oa->o_id);
			/* rewrite rc with -ENOENT only if it is 0 */
			if (rc == 0)
				rc = lrc;
		} else if (lrc != 0) {
			CEMERG("error destroying object "LPU64": %d\n",
			       oa->o_id, rc);
			rc = lrc;
		}
		count--;
		oa->o_id++;
	}

	/* if we have transaction then there were some deletions, we don't
	 * need to return ENOENT in that case because it will not wait
	 * for commit of these deletions. The ENOENT must be returned only
	 * if there were no transations.
	 */
	if (rc == -ENOENT) {
		if (info->fti_transno != 0)
			rc = 0;
	} else if (rc != 0) {
		/*
		 * If we have at least one transaction then llog record
		 * on server will be removed upon commit, so for rc != 0
		 * we return no transno and llog record will be reprocessed.
		 */
		info->fti_transno = 0;
	}
	ofd_info2oti(info, oti);
	RETURN(rc);
}

static int ofd_orphans_destroy(const struct lu_env *env,
			       struct obd_export *exp, struct ofd_device *ofd,
			       struct obdo *oa)
{
	struct ofd_thread_info	*info = ofd_info(env);
	obd_id			 last;
	int			 skip_orphan;
	int			 rc = 0;
	struct ost_id		 oi = oa->o_oi;

	ENTRY;

	LASSERT(exp != NULL);
	skip_orphan = !!(exp->exp_connect_flags & OBD_CONNECT_SKIP_ORPHAN);

	last = ofd_last_id(ofd, oa->o_seq);
	CWARN("%s: deleting orphan objects from "LPU64" to "LPU64"\n",
	      ofd_obd(ofd)->obd_name, oa->o_id + 1, last);

	for (oi.oi_id = last; oi.oi_id > oa->o_id; oi.oi_id--) {
		fid_ostid_unpack(&info->fti_fid, &oi, 0);
		rc = ofd_destroy_by_fid(env, ofd, &info->fti_fid, 1);
		if (rc && rc != -ENOENT) /* this is pretty fatal... */
			CEMERG("error destroying precreated id "LPU64": %d\n",
			       oi.oi_id, rc);
		if (!skip_orphan) {
			ofd_last_id_set(ofd, oi.oi_id - 1, oa->o_seq);
			/* update last_id on disk periodically so that if we
			 * restart * we don't need to re-scan all of the just
			 * deleted objects. */
			if ((oi.oi_id & 511) == 0)
				ofd_last_id_write(env, ofd, oa->o_seq);
		}
	}
	CDEBUG(D_HA, "%s: after destroy: set last_objids["LPU64"] = "LPU64"\n",
	       ofd_obd(ofd)->obd_name, oa->o_seq, oa->o_id);
	if (!skip_orphan) {
		rc = ofd_last_id_write(env, ofd, oa->o_seq);
	} else {
		/* don't reuse orphan object, return last used objid */
		oa->o_id = last;
		rc = 0;
	}
	RETURN(rc);
}

int ofd_create(const struct lu_env *env, struct obd_export *exp,
	       struct obdo *oa, struct lov_stripe_md **ea,
	       struct obd_trans_info *oti)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	int			 rc = 0, diff;

	ENTRY;

	info = ofd_info_init(env, exp);
	ofd_oti2info(info, oti);

	LASSERT(oa->o_seq >= FID_SEQ_OST_MDT0);
	LASSERT(oa->o_valid & OBD_MD_FLGROUP);

	CDEBUG(D_INFO, "ofd_create(oa->o_seq="LPU64",oa->o_id="LPU64")\n",
	       oa->o_seq, oa->o_id);

	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_RECREATE_OBJS)) {
		if (!ofd_obd(ofd)->obd_recovering ||
		    oa->o_id > ofd_last_id(ofd, oa->o_seq)) {
			CERROR("recreate objid "LPU64" > last id "LPU64"\n",
					oa->o_id, ofd_last_id(ofd, oa->o_seq));
			GOTO(out, rc = -EINVAL);
		}
		/* do nothing because we create objects during first write */
		GOTO(out, rc = 0);
	}
	/* former ofd_handle_precreate */
	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_DELORPHAN)) {
		/* destroy orphans */
		if (oti->oti_conn_cnt < exp->exp_conn_cnt) {
			CERROR("%s: dropping old orphan cleanup request\n",
			       ofd_obd(ofd)->obd_name);
			GOTO(out, rc = 0);
		}
		/* This causes inflight precreates to abort and drop lock */
		cfs_set_bit(oa->o_seq, &ofd->ofd_destroys_in_progress);
		cfs_mutex_lock(&ofd->ofd_create_locks[oa->o_seq]);
		if (!cfs_test_bit(oa->o_seq, &ofd->ofd_destroys_in_progress)) {
			CERROR("%s:["LPU64"] destroys_in_progress already cleared\n",
			       exp->exp_obd->obd_name, oa->o_seq);
			GOTO(out, rc = 0);
		}
		diff = oa->o_id - ofd_last_id(ofd, oa->o_seq);
		CDEBUG(D_HA, "ofd_last_id() = "LPU64" -> diff = %d\n",
		       ofd_last_id(ofd, oa->o_seq), diff);
		if (-diff > OST_MAX_PRECREATE) {
			/* FIXME: should reset precreate_next_id on MDS */
			rc = 0;
		} else if (diff < 0) {
			rc = ofd_orphans_destroy(env, exp, ofd, oa);
			cfs_clear_bit(oa->o_seq, &ofd->ofd_destroys_in_progress);
		} else {
			/* XXX: Used by MDS for the first time! */
			cfs_clear_bit(oa->o_seq, &ofd->ofd_destroys_in_progress);
		}
	} else {
		cfs_mutex_lock(&ofd->ofd_create_locks[oa->o_seq]);
		if (oti->oti_conn_cnt < exp->exp_conn_cnt) {
			CERROR("%s: dropping old precreate request\n",
			       ofd_obd(ofd)->obd_name);
			GOTO(out, rc = 0);
		}
		/* only precreate if group == 0 and o_id is specfied */
		if (!fid_seq_is_mdt(oa->o_seq) || oa->o_id == 0) {
			diff = 1; /* shouldn't we create this right now? */
		} else {
			diff = oa->o_id - ofd_last_id(ofd, oa->o_seq);
		}
	}
	if (diff > 0) {
		obd_id next_id = ofd_last_id(ofd, oa->o_seq) + 1;
		int i;

		if (!(oa->o_valid & OBD_MD_FLFLAGS) ||
		    !(oa->o_flags & OBD_FL_DELORPHAN)) {
			/* don't enforce grant during orphan recovery */
			rc = ofd_grant_create(env,
					      ofd_obd(ofd)->obd_self_export,
					      &diff);
			if (rc) {
				CDEBUG(D_HA, "%s: failed to acquire grant space"
				       "for precreate (%d)\n",
				       ofd_obd(ofd)->obd_name, diff);
				diff = 0;
			}
		}

		CDEBUG(D_HA,
		       "%s: reserve %d objects in group "LPU64" at "LPU64"\n",
		       ofd_obd(ofd)->obd_name, diff, oa->o_seq, next_id);
		for (i = 0; i < diff; i++) {
			rc = ofd_precreate_object(env, ofd, next_id + i,
						  oa->o_seq);
			if (rc)
				break;
		}
		if (i > 0) {
			/* some objects got created, we can return
			 * them, even if last creation failed */
			oa->o_id = ofd_last_id(ofd, oa->o_seq);
			rc = 0;
		} else {
			CERROR("unable to precreate: %d\n", rc);
			oa->o_id = ofd_last_id(ofd, oa->o_seq);
		}

		oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP;

		if (!(oa->o_valid & OBD_MD_FLFLAGS) ||
		    !(oa->o_flags & OBD_FL_DELORPHAN))
			ofd_grant_commit(env, ofd_obd(ofd)->obd_self_export,
					 rc);
	}

	ofd_info2oti(info, oti);
out:
	cfs_mutex_unlock(&ofd->ofd_create_locks[oa->o_seq]);
	if (rc == 0 && ea != NULL) {
		struct lov_stripe_md *lsm = *ea;

		lsm->lsm_object_id = oa->o_id;
	}
	return rc;
}

int ofd_getattr(const struct lu_env *env, struct obd_export *exp,
		struct obd_info *oinfo)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	struct ofd_object	*fo;
	__u64			 curr_version;
	int			 rc = 0;

	ENTRY;

	info = ofd_info_init(env, exp);

	fid_ostid_unpack(&info->fti_fid, &oinfo->oi_oa->o_oi, 0);
	rc = ofd_auth_capa(exp, &info->fti_fid, oinfo->oi_oa->o_seq,
			   oinfo_capa(oinfo), CAPA_OPC_META_READ);
	if (rc)
		GOTO(out, rc);

	fo = ofd_object_find(env, ofd, &info->fti_fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));
	LASSERT(fo != NULL);
	rc = ofd_attr_get(env, fo, &info->fti_attr);
	oinfo->oi_oa->o_valid = OBD_MD_FLID;
	if (rc == 0)
		obdo_from_la(oinfo->oi_oa, &info->fti_attr,
			     OFD_VALID_FLAGS | LA_UID | LA_GID);

	/* Store object version in reply */
	curr_version = dt_version_get(env, ofd_object_child(fo));
	if ((__s64)curr_version != -EOPNOTSUPP) {
		oinfo->oi_oa->o_valid |= OBD_MD_FLDATAVERSION;
		oinfo->oi_oa->o_data_version = curr_version;
	}
	ofd_object_put(env, fo);
out:
	RETURN(rc);
}

static int ofd_sync(const struct lu_env *env, struct obd_export *exp,
		    struct obd_info *oinfo, obd_size start, obd_size end,
		    struct ptlrpc_request_set *set)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
        struct ofd_object	*fo;
	int			 rc = 0;

	ENTRY;

	/* if no objid is specified, it means "sync whole filesystem" */
	if (oinfo->oi_oa == NULL || !(oinfo->oi_oa->o_valid & OBD_MD_FLID)) {
		rc = dt_sync(env, ofd->ofd_osd);
		GOTO(out, rc);
	}

	info = ofd_info_init(env, exp);
	fid_ostid_unpack(&info->fti_fid, &oinfo->oi_oa->o_oi, 0);

	rc = ofd_auth_capa(exp, &info->fti_fid, oinfo->oi_oa->o_seq,
			   oinfo_capa(oinfo), CAPA_OPC_OSS_TRUNC);
	if (rc)
		GOTO(out, rc);

	fo = ofd_object_find(env, ofd, &info->fti_fid);
	if (IS_ERR(fo)) {
		CERROR("%s: error finding object "DFID": rc = %ld\n",
		       exp->exp_obd->obd_name, PFID(&info->fti_fid),
		       PTR_ERR(fo));
		GOTO(out, rc = PTR_ERR(fo));
	}

	ofd_write_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	rc = dt_object_sync(env, ofd_object_child(fo));
	if (rc)
		GOTO(unlock, rc);

	oinfo->oi_oa->o_valid = OBD_MD_FLID;
	rc = ofd_attr_get(env, fo, &info->fti_attr);
	obdo_from_la(oinfo->oi_oa, &info->fti_attr, OFD_VALID_FLAGS);
	EXIT;
unlock:
	ofd_write_unlock(env, fo);
	ofd_object_put(env, fo);
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
	default:
		CERROR("%s: not supported cmd = %d\n", obd->obd_name, cmd);
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

/*
 * Handle quotacheck requests.
 * Although in-kernel quotacheck isn't supported any more, we still emulate it
 * in order to interoperate with current MDT stack which needs proper
 * quotacheck support, even for space accounting.
 *
 * \param obd - is the obd device associated with the ofd
 * \param exp - is the client's export
 * \param oqctl - is the obd_quotactl request to be processed
 */
static int ofd_quotacheck(struct obd_device *obd, struct obd_export *exp,
			  struct obd_quotactl *oqctl)
{
	struct ptlrpc_request	*req;
	struct obd_quotactl	*body;
	ENTRY;

	req = ptlrpc_request_alloc_pack(exp->exp_imp_reverse, &RQF_QC_CALLBACK,
					LUSTRE_OBD_VERSION, OBD_QC_CALLBACK);
	if (req == NULL)
		RETURN(-ENOMEM);

	body = req_capsule_client_get(&req->rq_pill, &RMF_OBD_QUOTACTL);
	oqctl->qc_stat = 0;
	memcpy(body, oqctl, sizeof(*body));

	ptlrpc_request_set_replen(req);
	ptlrpcd_add_req(req, PDL_POLICY_ROUND, -1);

	RETURN(0);
}

/*
 * Handle quota control requests to consult current usage/limit, but also
 * to configure quota enforcement
 *
 * \param obd - is the obd device associated with the ofd
 * \param exp - is the client's export
 * \param oqctl - is the obd_quotactl request to be processed
 */
static int ofd_quotactl(struct obd_device *obd, struct obd_export *exp,
			struct obd_quotactl *oqctl)
{
	struct ofd_device  *ofd = ofd_dev(obd->obd_lu_dev);
	struct lu_env       env;
	int                 rc;
	ENTRY;

	/* report success for quota on/off for interoperability with current MDT
	 * stack */
	if (oqctl->qc_cmd == Q_QUOTAON || oqctl->qc_cmd == Q_QUOTAOFF)
		RETURN(0);

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);

	rc = lquotactl_slv(&env, ofd->ofd_osd, oqctl);
	lu_env_fini(&env);

	RETURN(rc);
}

struct obd_ops ofd_obd_ops = {
	.o_owner		= THIS_MODULE,
	.o_connect		= ofd_obd_connect,
	.o_reconnect		= ofd_obd_reconnect,
	.o_disconnect		= ofd_obd_disconnect,
	.o_set_info_async	= ofd_set_info_async,
	.o_get_info		= ofd_get_info,
	.o_create		= ofd_create,
	.o_statfs		= ofd_statfs,
	.o_setattr		= ofd_setattr,
	.o_preprw		= ofd_preprw,
	.o_commitrw		= ofd_commitrw,
	.o_destroy		= ofd_destroy,
	.o_init_export		= ofd_init_export,
	.o_destroy_export	= ofd_destroy_export,
	.o_postrecov		= ofd_obd_postrecov,
	.o_punch		= ofd_punch,
	.o_getattr		= ofd_getattr,
	.o_sync			= ofd_sync,
	.o_iocontrol		= ofd_iocontrol,
	.o_precleanup		= ofd_precleanup,
	.o_ping			= ofd_ping,
	.o_health_check		= ofd_health_check,
	.o_notify		= ofd_obd_notify,
	.o_quotactl		= ofd_quotactl,
	.o_quotacheck		= ofd_quotacheck,
};
