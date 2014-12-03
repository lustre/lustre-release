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
 * Copyright (c) 2012, 2013, Intel Corporation.
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

#include <lustre/lustre_idl.h>
#include "ofd_internal.h"
#include <obd_cksum.h>
#include <lustre_quota.h>
#include <lustre_lfsck.h>

static int ofd_export_stats_init(struct ofd_device *ofd,
				 struct obd_export *exp, void *client_nid)
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

	num_stats = NUM_OBD_STATS + LPROC_OFD_LAST;
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
		      "http://bugs.whamcloud.com/\n",
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

static int ofd_obd_reconnect(const struct lu_env *env, struct obd_export *exp,
			     struct obd_device *obd, struct obd_uuid *cluuid,
			     struct obd_connect_data *data, void *localdata)
{
	struct ofd_device	*ofd;
	int			 rc;

	ENTRY;

	if (exp == NULL || obd == NULL || cluuid == NULL)
		RETURN(-EINVAL);

	ofd = ofd_dev(obd->obd_lu_dev);

	rc = lu_env_refill((struct lu_env *)env);
	if (rc != 0) {
		CERROR("Failure to refill session: '%d'\n", rc);
		RETURN(rc);
	}

	ofd_info_init(env, exp);
	rc = ofd_parse_connect_data(env, exp, data, false);
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
	int			 rc;
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
		tgt_client_del(&env, exp);
	lu_env_fini(&env);

	class_export_put(exp);
	RETURN(rc);
}

static int ofd_init_export(struct obd_export *exp)
{
	int rc;

	spin_lock_init(&exp->exp_filter_data.fed_lock);
	CFS_INIT_LIST_HEAD(&exp->exp_filter_data.fed_mod_list);
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

	LASSERT(cfs_list_empty(&exp->exp_filter_data.fed_mod_list));
	return 0;
}

int ofd_postrecov(const struct lu_env *env, struct ofd_device *ofd)
{
	struct lu_device *ldev = &ofd->ofd_dt_dev.dd_lu_dev;

	CDEBUG(D_HA, "%s: recovery is over\n", ofd_obd(ofd)->obd_name);
	return ldev->ld_ops->ldo_recovery_complete(env, ldev);
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

	rc = ofd_postrecov(&env, ofd_dev(ldev));

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

	write_lock(&fo->fo_sptlrpc_lock);
	sptlrpc_rule_set_free(&fo->fo_sptlrpc_rset);
	fo->fo_sptlrpc_rset = tmp_rset;
	write_unlock(&fo->fo_sptlrpc_lock);

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
	struct ofd_device	*ofd;
	int			 rc = 0;

	ENTRY;

	if (exp->exp_obd == NULL) {
		CDEBUG(D_IOCTL, "invalid export %p\n", exp);
		RETURN(-EINVAL);
	}

	ofd = ofd_exp(exp);

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

		ofd_info_init(env, exp);
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
	struct ofd_device	*ofd;
	int			rc = 0;

	ENTRY;

	if (exp->exp_obd == NULL) {
		CDEBUG(D_IOCTL, "invalid client export %p\n", exp);
		RETURN(-EINVAL);
	}

	/* Because ofd_get_info might be called from
	 * handle_request_in as well(see LU-3239), where env might
	 * not be initilaized correctly, and le_ses might be in
	 * an un-initialized state, so only refill le_ctx here */
	rc = lu_env_refill((struct lu_env *)env);
	if (rc != 0)
		RETURN(rc);

	ofd = ofd_exp(exp);

	if (KEY_IS(KEY_BLOCKSIZE)) {
		__u32 *blocksize = val;
		if (blocksize) {
			if (*vallen < sizeof(*blocksize))
				GOTO(out, rc = -EOVERFLOW);
			*blocksize = 1 << ofd->ofd_dt_conf.ddp_block_shift;
		}
		*vallen = sizeof(*blocksize);
	} else if (KEY_IS(KEY_BLOCKSIZE_BITS)) {
		__u32 *blocksize_bits = val;
		if (blocksize_bits) {
			if (*vallen < sizeof(*blocksize_bits))
				GOTO(out, rc = -EOVERFLOW);
			*blocksize_bits = ofd->ofd_dt_conf.ddp_block_shift;
		}
		*vallen = sizeof(*blocksize_bits);
	} else if (KEY_IS(KEY_LAST_ID)) {
		obd_id *last_id = val;
		struct ofd_seq *oseq;

		if (val == NULL) {
			*vallen = sizeof(obd_id);
			GOTO(out, rc = 0);
		}
		ofd_info_init(env, exp);
		oseq = ofd_seq_load(env, ofd,
				    (obd_seq)exp->exp_filter_data.fed_group);
		LASSERT(!IS_ERR(oseq));
		if (last_id) {
			if (*vallen < sizeof(*last_id)) {
				ofd_seq_put(env, oseq);
				GOTO(out, rc = -EOVERFLOW);
			}
			*last_id = ofd_seq_last_oid(oseq);
		}
		ofd_seq_put(env, oseq);
		*vallen = sizeof(*last_id);
	} else if (KEY_IS(KEY_FIEMAP)) {
		struct ofd_device		*ofd = ofd_exp(exp);
		struct ofd_object		*fo;
		struct ll_fiemap_info_key	*fm_key = key;
		struct lu_fid			 fid;

		if (val == NULL) {
			*vallen = fiemap_count_to_size(
					       fm_key->fiemap.fm_extent_count);
			GOTO(out, rc = 0);
		}

		rc = ostid_to_fid(&fid, &fm_key->oa.o_oi, 0);
		if (rc != 0)
			GOTO(out, rc);
		CDEBUG(D_INODE, "get FIEMAP of object "DFID"\n",
		       PFID(&fid));

		fo = ofd_object_find(env, ofd, &fid);
		if (IS_ERR(fo)) {
			CERROR("%s: error finding object "DFID"\n",
			       exp->exp_obd->obd_name, PFID(&fid));
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
	} else if (KEY_IS(KEY_LAST_FID)) {
		struct ofd_device	*ofd = ofd_exp(exp);
		struct ofd_seq		*oseq;
		struct lu_fid		*fid = val;
		int			rc;

		if (fid == NULL) {
			*vallen = sizeof(struct lu_fid);
			GOTO(out, rc = 0);
		}

		if (*vallen < sizeof(*fid))
			GOTO(out, rc = -EOVERFLOW);

		ofd_info_init(env, exp);

		fid_le_to_cpu(fid, fid);

		oseq = ofd_seq_load(env, ofd,
				    ostid_seq((struct ost_id *)fid));
		if (IS_ERR(oseq))
			GOTO(out, rc = PTR_ERR(oseq));

		rc = ostid_to_fid(fid, &oseq->os_oi,
			     ofd->ofd_lut.lut_lsd.lsd_osd_index);
		if (rc != 0)
			GOTO(out_put, rc);

		CDEBUG(D_HA, "%s: LAST FID is "DFID"\n", ofd_name(ofd),
		       PFID(fid));
		*vallen = sizeof(*fid);
out_put:
		ofd_seq_put(env, oseq);
	} else {
		CERROR("Not supported key %s\n", (char*)key);
		rc = -EOPNOTSUPP;
	}
out:
	RETURN(rc);
}

/** helper function for statfs, also used by grant code */
int ofd_statfs_internal(const struct lu_env *env, struct ofd_device *ofd,
                        struct obd_statfs *osfs, __u64 max_age, int *from_cache)
{
	int rc;

	spin_lock(&ofd->ofd_osfs_lock);
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
		spin_unlock(&ofd->ofd_osfs_lock);

		/* statfs can sleep ... hopefully not for too long since we can
		 * call it fairly often as space fills up */
		rc = dt_statfs(env, ofd->ofd_osd, osfs);
		if (unlikely(rc))
			return rc;

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
	if (exp_connect_flags(exp) & OBD_CONNECT_MDS) {
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

	rc = ostid_to_fid(&info->fti_fid, &oinfo->oi_oa->o_oi, 0);
	if (rc != 0)
		RETURN(rc);

	ost_fid_build_resid(&info->fti_fid, &info->fti_resid);
	rc = ofd_auth_capa(exp, &info->fti_fid, ostid_seq(&oa->o_oi),
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

	ofd_info2oti(info, oti);

	ofd_counter_incr(exp, LPROC_OFD_STATS_SETATTR, oti->oti_jobid, 1);
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
		if (res != NULL) {
			ldlm_res_lvbo_update(res, NULL, 0);
			ldlm_resource_putref(res);
		}
	}

	return rc;
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

	rc = ostid_to_fid(&info->fti_fid, &oinfo->oi_oa->o_oi, 0);
	if (rc != 0)
		RETURN(rc);
	ost_fid_build_resid(&info->fti_fid, &info->fti_resid);

	CDEBUG(D_INODE, "calling punch for object "DFID", valid = "LPX64
	       ", start = "LPD64", end = "LPD64"\n", PFID(&info->fti_fid),
	       oinfo->oi_oa->o_valid, oinfo->oi_policy.l_extent.start,
	       oinfo->oi_policy.l_extent.end);

	rc = ofd_auth_capa(exp, &info->fti_fid, ostid_seq(&oinfo->oi_oa->o_oi),
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

	ofd_counter_incr(exp, LPROC_OFD_STATS_PUNCH, oti->oti_jobid, 1);
	EXIT;
out:
	ofd_object_put(env, fo);
out_env:
	return rc;
}

static int ofd_destroy_by_fid(const struct lu_env *env,
			      struct ofd_device *ofd,
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

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));
	if (!ofd_object_exists(fo))
		GOTO(out, rc = -ENOENT);

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
out:
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
		ostid_set_seq_mdt0(&oa->o_oi);

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

	CDEBUG(D_HA, "%s: Destroy object "DOSTID" count %d\n", ofd_name(ofd),
	       POSTID(&oa->o_oi), count);
	while (count > 0) {
		int lrc;

		lrc = ostid_to_fid(&info->fti_fid, &oa->o_oi, 0);
		if (lrc != 0) {
			if (rc == 0)
				rc = lrc;
			GOTO(out, rc);
		}
		lrc = ofd_destroy_by_fid(env, ofd, &info->fti_fid, 0);
		if (lrc == -ENOENT) {
			CDEBUG(D_INODE,
			       "%s: destroying non-existent object "DFID"\n",
			       ofd_obd(ofd)->obd_name, PFID(&info->fti_fid));
			/* rewrite rc with -ENOENT only if it is 0 */
			if (rc == 0)
				rc = lrc;
		} else if (lrc != 0) {
			CERROR("%s: error destroying object "DFID": %d\n",
			       ofd_obd(ofd)->obd_name, PFID(&info->fti_fid),
			       lrc);
			rc = lrc;
		}
		count--;
		ostid_inc_id(&oa->o_oi);
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
out:
	RETURN(rc);
}

static int ofd_orphans_destroy(const struct lu_env *env,
			       struct obd_export *exp, struct ofd_device *ofd,
			       struct obdo *oa)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct lu_fid           *fid    = &info->fti_fid;
	obd_id			 last;
	int			 skip_orphan;
	int			 rc = 0;
	struct ost_id		 oi = oa->o_oi;
	__u64			 end_id = ostid_id(&oa->o_oi);
	struct ofd_seq		*oseq;

	ENTRY;

	oseq = ofd_seq_get(ofd, ostid_seq(&oa->o_oi));
	if (oseq == NULL) {
		CERROR("%s: Can not find seq for "DOSTID"\n",
		       ofd_name(ofd), POSTID(&oa->o_oi));
		RETURN(-EINVAL);
	}
	last = ofd_seq_last_oid(oseq);

	LASSERT(exp != NULL);
	skip_orphan = !!(exp_connect_flags(exp) & OBD_CONNECT_SKIP_ORPHAN);

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_NODESTROY))
		goto done;

	LCONSOLE(D_INFO, "%s: deleting orphan objects from "DOSTID
		 " to "DOSTID"\n", ofd_name(ofd), ostid_seq(&oa->o_oi),
		 end_id + 1, ostid_seq(&oa->o_oi), last);

	for (ostid_set_id(&oi, last); ostid_id(&oi) > end_id;
			  ostid_dec_id(&oi)) {
		rc = ostid_to_fid(fid, &oi, 0);
		if (rc != 0)
			GOTO(out_put, rc);
		rc = ofd_destroy_by_fid(env, ofd, fid, 1);
		if (rc != 0 && rc != -ENOENT && rc != -ESTALE &&
		    likely(rc != -EREMCHG && rc != -EINPROGRESS))
			/* this is pretty fatal... */
			CEMERG("%s: error destroying precreated id "
			       DFID": rc = %d\n",
			       ofd_name(ofd), PFID(fid), rc);
		if (!skip_orphan) {
			ofd_seq_last_oid_set(oseq, ostid_id(&oi) - 1);
			/* update last_id on disk periodically so that if we
			 * restart * we don't need to re-scan all of the just
			 * deleted objects. */
			if ((ostid_id(&oi) & 511) == 0)
				ofd_seq_last_oid_write(env, ofd, oseq);
		}
	}
	CDEBUG(D_HA, "%s: after destroy: set last_id to "DOSTID"\n",
	       ofd_obd(ofd)->obd_name, POSTID(&oa->o_oi));
done:
	if (!skip_orphan) {
		ofd_seq_last_oid_set(oseq, ostid_id(&oi) - 1);
		rc = ofd_seq_last_oid_write(env, ofd, oseq);
	} else {
		/* don't reuse orphan object, return last used objid */
		ostid_set_id(&oa->o_oi, last);
		rc = 0;
	}
out_put:
	ofd_seq_put(env, oseq);
	RETURN(rc);
}

int ofd_create(const struct lu_env *env, struct obd_export *exp,
	       struct obdo *oa, struct lov_stripe_md **ea,
	       struct obd_trans_info *oti)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	obd_seq			seq = ostid_seq(&oa->o_oi);
	struct ofd_seq		*oseq;
	int			rc = 0, diff;
	int			sync_trans = 0;

	ENTRY;

	info = ofd_info_init(env, exp);
	ofd_oti2info(info, oti);

	LASSERT(ostid_seq(&oa->o_oi) >= FID_SEQ_OST_MDT0);
	LASSERT(oa->o_valid & OBD_MD_FLGROUP);

	CDEBUG(D_INFO, "ofd_create("DOSTID")\n", POSTID(&oa->o_oi));

	oseq = ofd_seq_load(env, ofd, seq);
	if (IS_ERR(oseq)) {
		CERROR("%s: Can't find FID Sequence "LPX64": rc = %ld\n",
		       ofd_name(ofd), seq, PTR_ERR(oseq));
		RETURN(-EINVAL);
	}

	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_RECREATE_OBJS)) {
		if (!ofd_obd(ofd)->obd_recovering ||
		    ostid_id(&oa->o_oi) > ofd_seq_last_oid(oseq)) {
			CERROR("recreate objid "DOSTID" > last id "LPU64"\n",
			       POSTID(&oa->o_oi), ofd_seq_last_oid(oseq));
			GOTO(out_nolock, rc = -EINVAL);
		}
		/* do nothing because we create objects during first write */
		GOTO(out_nolock, rc = 0);
	}
	/* former ofd_handle_precreate */
	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_DELORPHAN)) {
		/* destroy orphans */
		if (oti->oti_conn_cnt < exp->exp_conn_cnt) {
			CERROR("%s: dropping old orphan cleanup request\n",
			       ofd_name(ofd));
			GOTO(out_nolock, rc = 0);
		}
		/* This causes inflight precreates to abort and drop lock */
		oseq->os_destroys_in_progress = 1;
		mutex_lock(&oseq->os_create_lock);
		if (!oseq->os_destroys_in_progress) {
			CERROR("%s:["LPU64"] destroys_in_progress already"
			       " cleared\n", exp->exp_obd->obd_name,
			       ostid_seq(&oa->o_oi));
			ostid_set_id(&oa->o_oi, ofd_seq_last_oid(oseq));
			GOTO(out, rc = 0);
		}
		diff = ostid_id(&oa->o_oi) - ofd_seq_last_oid(oseq);
		CDEBUG(D_HA, "ofd_last_id() = "LPU64" -> diff = %d\n",
			ofd_seq_last_oid(oseq), diff);
		if (-diff > OST_MAX_PRECREATE) {
			/* FIXME: should reset precreate_next_id on MDS */
			rc = 0;
		} else if (diff < 0) {
			rc = ofd_orphans_destroy(env, exp, ofd, oa);
			oseq->os_destroys_in_progress = 0;
		} else {
			/* XXX: Used by MDS for the first time! */
			oseq->os_destroys_in_progress = 0;
		}
	} else {
		mutex_lock(&oseq->os_create_lock);
		if (oti->oti_conn_cnt < exp->exp_conn_cnt) {
			CERROR("%s: dropping old precreate request\n",
				ofd_obd(ofd)->obd_name);
			GOTO(out, rc = 0);
		}
		/* only precreate if seq is 0, IDIF or normal and also o_id
		 * must be specfied */
		if ((!fid_seq_is_mdt(ostid_seq(&oa->o_oi)) &&
		     !fid_seq_is_norm(ostid_seq(&oa->o_oi)) &&
		     !fid_seq_is_idif(ostid_seq(&oa->o_oi))) ||
				ostid_id(&oa->o_oi) == 0) {
			diff = 1; /* shouldn't we create this right now? */
		} else {
			diff = ostid_id(&oa->o_oi) - ofd_seq_last_oid(oseq);
			/* Do sync create if the seq is about to used up */
			if (fid_seq_is_idif(ostid_seq(&oa->o_oi)) ||
			    fid_seq_is_mdt0(ostid_seq(&oa->o_oi))) {
				if (unlikely(ostid_id(&oa->o_oi) >= IDIF_MAX_OID - 1))
					sync_trans = 1;
			} else if (fid_seq_is_norm(ostid_seq(&oa->o_oi))) {
				if (unlikely(ostid_id(&oa->o_oi) >=
					     LUSTRE_DATA_SEQ_MAX_WIDTH - 1))
					sync_trans = 1;
			} else {
				CERROR("%s : invalid o_seq "DOSTID": rc = %d\n",
				       ofd_name(ofd), POSTID(&oa->o_oi), -EINVAL);
				GOTO(out, rc = -EINVAL);
			}
		}
	}
	if (diff > 0) {
		cfs_time_t	 enough_time = cfs_time_shift(DISK_TIMEOUT);
		obd_id		 next_id;
		int		 created = 0;
		int		 count;

		if (!(oa->o_valid & OBD_MD_FLFLAGS) ||
		    !(oa->o_flags & OBD_FL_DELORPHAN)) {
			/* don't enforce grant during orphan recovery */
			rc = ofd_grant_create(env,
					      ofd_obd(ofd)->obd_self_export,
					      &diff);
			if (rc) {
				CDEBUG(D_HA, "%s: failed to acquire grant "
				       "space for precreate (%d): rc = %d\n",
				       ofd_name(ofd), diff, rc);
				diff = 0;
			}
		}

		/* This can happen if a new OST is formatted and installed
		 * in place of an old one at the same index.  Instead of
		 * precreating potentially millions of deleted old objects
		 * (possibly filling the OST), only precreate the last batch.
		 * LFSCK will eventually clean up any orphans. LU-14 */
		if (diff > 5 * OST_MAX_PRECREATE) {
			diff = OST_MAX_PRECREATE / 2;
			LCONSOLE_WARN("%s: precreate FID "DOSTID" is over %u "
				      "larger than the LAST_ID "DOSTID", only "
				      "precreating the last %u objects.\n",
				      ofd_name(ofd), POSTID(&oa->o_oi),
				      5 * OST_MAX_PRECREATE,
				      POSTID(&oseq->os_oi), diff);
			ofd_seq_last_oid_set(oseq, ostid_id(&oa->o_oi) - diff);
		}

		while (diff > 0) {
			next_id = ofd_seq_last_oid(oseq) + 1;
			count = ofd_precreate_batch(ofd, diff);

			CDEBUG(D_HA, "%s: reserve %d objects in group "LPX64
			       " at "LPU64"\n", ofd_obd(ofd)->obd_name,
			       count, ostid_seq(&oa->o_oi), next_id);

			if (cfs_time_after(jiffies, enough_time)) {
				LCONSOLE_WARN("%s: Slow creates, %d/%d objects"
					      " created at a rate of %d/s\n",
					      ofd_obd(ofd)->obd_name,
					      created, diff + created,
					      created / DISK_TIMEOUT);
				break;
			}

			rc = ofd_precreate_objects(env, ofd, next_id,
						   oseq, count, sync_trans);
			if (rc > 0) {
				created += rc;
				diff -= rc;
			} else if (rc < 0) {
				break;
			}
		}
		if (created > 0)
			/* some objects got created, we can return
			 * them, even if last creation failed */
			rc = 0;
		else
			CERROR("%s: unable to precreate: rc = %d\n",
			       ofd_name(ofd), rc);

		ostid_set_id(&oa->o_oi, ofd_seq_last_oid(oseq));
		oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP;

		if (!(oa->o_valid & OBD_MD_FLFLAGS) ||
		    !(oa->o_flags & OBD_FL_DELORPHAN))
			ofd_grant_commit(env, ofd_obd(ofd)->obd_self_export,
					 rc);
	}

	ofd_info2oti(info, oti);
out:
	mutex_unlock(&oseq->os_create_lock);
out_nolock:
	if (rc == 0 && ea != NULL) {
		struct lov_stripe_md *lsm = *ea;

		lsm->lsm_oi = oa->o_oi;
	}
	ofd_seq_put(env, oseq);
	RETURN(rc);
}

int ofd_getattr(const struct lu_env *env, struct obd_export *exp,
		struct obd_info *oinfo)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	struct ofd_object	*fo;
	int			 rc = 0;

	ENTRY;

	info = ofd_info_init(env, exp);

	rc = ostid_to_fid(&info->fti_fid, &oinfo->oi_oa->o_oi, 0);
	if (rc != 0)
		GOTO(out, rc);
	rc = ofd_auth_capa(exp, &info->fti_fid, ostid_seq(&oinfo->oi_oa->o_oi),
			   oinfo_capa(oinfo), CAPA_OPC_META_READ);
	if (rc)
		GOTO(out, rc);

	fo = ofd_object_find(env, ofd, &info->fti_fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));
	if (!ofd_object_exists(fo))
		GOTO(out_put, rc = -ENOENT);

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

out_put:
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
	rc = ostid_to_fid(&info->fti_fid, &oinfo->oi_oa->o_oi, 0);
	if (rc != 0)
		GOTO(out, rc);

	rc = ofd_auth_capa(exp, &info->fti_fid, ostid_seq(&oinfo->oi_oa->o_oi),
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

	if (!ofd_object_exists(fo))
		GOTO(put, rc = -ENOENT);

	if (dt_version_get(env, ofd_object_child(fo)) >
	    ofd_obd(ofd)->obd_last_committed) {
		rc = dt_object_sync(env, ofd_object_child(fo));
		if (rc)
			GOTO(put, rc);
	}

	oinfo->oi_oa->o_valid = OBD_MD_FLID;
	rc = ofd_attr_get(env, fo, &info->fti_attr);
	obdo_from_la(oinfo->oi_oa, &info->fti_attr, OFD_VALID_FLAGS);

	ofd_counter_incr(exp, LPROC_OFD_STATS_SYNC, oinfo->oi_jobid, 1);
	EXIT;
put:
	ofd_object_put(env, fo);
out:
	return rc;
}

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
		rc = ostid_to_fid(&fid, &ostid, 0);
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

int ofd_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
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
		lsp.lsp_namespace = ofd->ofd_namespace;
		rc = lfsck_start(&env, ofd->ofd_osd, &lsp);
		break;
	}
	case OBD_IOC_STOP_LFSCK: {
		rc = lfsck_stop(&env, ofd->ofd_osd, false);
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
	ofd_fmd_expire(exp);
	return 0;
}

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
				     info->fti_buf.lb_len, info->fti_off, th);
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

/*
 * Handle quota control requests to consult current usage/limit.
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
	.o_quotactl		= ofd_quotactl,
};
