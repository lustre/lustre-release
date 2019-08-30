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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/mdt/mdt_reint.c
 *
 * Lustre Metadata Target (mdt) reintegration routines
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Huang Hua <huanghua@clusterfs.com>
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <lprocfs_status.h>
#include "mdt_internal.h"
#include <lustre_lmv.h>
#include <lustre_crypto.h>

static inline void mdt_reint_init_ma(struct mdt_thread_info *info,
				     struct md_attr *ma)
{
	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;
}

/**
 * Get version of object by fid.
 *
 * Return real version or ENOENT_VERSION if object doesn't exist
 */
static void mdt_obj_version_get(struct mdt_thread_info *info,
				struct mdt_object *o, __u64 *version)
{
	LASSERT(o);

	if (mdt_object_exists(o) && !mdt_object_remote(o) &&
	    !fid_is_obf(mdt_object_fid(o)))
		*version = dt_version_get(info->mti_env, mdt_obj2dt(o));
	else
		*version = ENOENT_VERSION;
	CDEBUG(D_INODE, "FID "DFID" version is %#llx\n",
	       PFID(mdt_object_fid(o)), *version);
}

/**
 * Check version is correct.
 *
 * Should be called only during replay.
 */
static int mdt_version_check(struct ptlrpc_request *req,
			     __u64 version, int idx)
{
	__u64 *pre_ver = lustre_msg_get_versions(req->rq_reqmsg);

	ENTRY;
	if (!exp_connect_vbr(req->rq_export))
		RETURN(0);

	LASSERT(req_is_replay(req));
	/** VBR: version is checked always because costs nothing */
	LASSERT(idx < PTLRPC_NUM_VERSIONS);
	/** Sanity check for malformed buffers */
	if (pre_ver == NULL) {
		CERROR("No versions in request buffer\n");
		spin_lock(&req->rq_export->exp_lock);
		req->rq_export->exp_vbr_failed = 1;
		spin_unlock(&req->rq_export->exp_lock);
		RETURN(-EOVERFLOW);
	} else if (pre_ver[idx] != version) {
		CDEBUG(D_INODE, "Version mismatch %#llx != %#llx\n",
		       pre_ver[idx], version);
		spin_lock(&req->rq_export->exp_lock);
		req->rq_export->exp_vbr_failed = 1;
		spin_unlock(&req->rq_export->exp_lock);
		RETURN(-EOVERFLOW);
	}
	RETURN(0);
}

/**
 * Save pre-versions in reply.
 */
static void mdt_version_save(struct ptlrpc_request *req, __u64 version,
			     int idx)
{
	__u64 *reply_ver;

	if (!exp_connect_vbr(req->rq_export))
		return;

	LASSERT(!req_is_replay(req));
	LASSERT(req->rq_repmsg != NULL);
	reply_ver = lustre_msg_get_versions(req->rq_repmsg);
	if (reply_ver)
		reply_ver[idx] = version;
}

/**
 * Save enoent version, it is needed when it is obvious that object doesn't
 * exist, e.g. child during create.
 */
static void mdt_enoent_version_save(struct mdt_thread_info *info, int idx)
{
	/* save version of file name for replay, it must be ENOENT here */
	if (!req_is_replay(mdt_info_req(info))) {
		info->mti_ver[idx] = ENOENT_VERSION;
		mdt_version_save(mdt_info_req(info), info->mti_ver[idx], idx);
	}
}

/**
 * Get version from disk and save in reply buffer.
 *
 * Versions are saved in reply only during normal operations not replays.
 */
void mdt_version_get_save(struct mdt_thread_info *info,
			  struct mdt_object *mto, int idx)
{
	/* don't save versions during replay */
	if (!req_is_replay(mdt_info_req(info))) {
		mdt_obj_version_get(info, mto, &info->mti_ver[idx]);
		mdt_version_save(mdt_info_req(info), info->mti_ver[idx], idx);
	}
}

/**
 * Get version from disk and check it, no save in reply.
 */
int mdt_version_get_check(struct mdt_thread_info *info,
			  struct mdt_object *mto, int idx)
{
	/* only check versions during replay */
	if (!req_is_replay(mdt_info_req(info)))
		return 0;

	mdt_obj_version_get(info, mto, &info->mti_ver[idx]);
	return mdt_version_check(mdt_info_req(info), info->mti_ver[idx], idx);
}

/**
 * Get version from disk and check if recovery or just save.
 */
int mdt_version_get_check_save(struct mdt_thread_info *info,
			       struct mdt_object *mto, int idx)
{
	int rc = 0;

	mdt_obj_version_get(info, mto, &info->mti_ver[idx]);
	if (req_is_replay(mdt_info_req(info)))
		rc = mdt_version_check(mdt_info_req(info), info->mti_ver[idx],
				       idx);
	else
		mdt_version_save(mdt_info_req(info), info->mti_ver[idx], idx);
	return rc;
}

/**
 * Lookup with version checking.
 *
 * This checks version of 'name'. Many reint functions uses 'name' for child not
 * FID, therefore we need to get object by name and check its version.
 */
int mdt_lookup_version_check(struct mdt_thread_info *info,
			     struct mdt_object *p,
			     const struct lu_name *lname,
			     struct lu_fid *fid, int idx)
{
	int rc, vbrc;

	rc = mdo_lookup(info->mti_env, mdt_object_child(p), lname, fid,
			&info->mti_spec);
	/* Check version only during replay */
	if (!req_is_replay(mdt_info_req(info)))
		return rc;

	info->mti_ver[idx] = ENOENT_VERSION;
	if (rc == 0) {
		struct mdt_object *child;

		child = mdt_object_find(info->mti_env, info->mti_mdt, fid);
		if (likely(!IS_ERR(child))) {
			mdt_obj_version_get(info, child, &info->mti_ver[idx]);
			mdt_object_put(info->mti_env, child);
		}
	}
	vbrc = mdt_version_check(mdt_info_req(info), info->mti_ver[idx], idx);
	return vbrc ? vbrc : rc;

}

static int mdt_unlock_slaves(struct mdt_thread_info *mti,
			     struct mdt_object *obj,
			     struct ldlm_enqueue_info *einfo,
			     int decref)
{
	union ldlm_policy_data *policy = &mti->mti_policy;
	struct mdt_lock_handle *lh = &mti->mti_lh[MDT_LH_LOCAL];
	struct lustre_handle_array *slave_locks = einfo->ei_cbdata;
	int i;

	LASSERT(S_ISDIR(obj->mot_header.loh_attr));
	LASSERT(slave_locks);

	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = einfo->ei_inodebits;
	mdt_lock_handle_init(lh);
	mdt_lock_reg_init(lh, einfo->ei_mode);
	for (i = 0; i < slave_locks->ha_count; i++) {
		if (test_bit(i, (void *)slave_locks->ha_map))
			lh->mlh_rreg_lh = slave_locks->ha_handles[i];
		else
			lh->mlh_reg_lh = slave_locks->ha_handles[i];
		mdt_object_unlock(mti, NULL, lh, decref);
		slave_locks->ha_handles[i].cookie = 0ull;
	}

	return mo_object_unlock(mti->mti_env, mdt_object_child(obj), einfo,
				policy);
}

static inline int mdt_object_striped(struct mdt_thread_info *mti,
				     struct mdt_object *obj)
{
	struct lu_device *bottom_dev;
	struct lu_object *bottom_obj;
	int rc;

	if (!S_ISDIR(obj->mot_header.loh_attr))
		return 0;

	/* getxattr from bottom obj to avoid reading in shard FIDs */
	bottom_dev = dt2lu_dev(mti->mti_mdt->mdt_bottom);
	bottom_obj = lu_object_find_slice(mti->mti_env, bottom_dev,
					  mdt_object_fid(obj), NULL);
	if (IS_ERR(bottom_obj))
		return PTR_ERR(bottom_obj);

	rc = dt_xattr_get(mti->mti_env, lu2dt(bottom_obj), &LU_BUF_NULL,
			  XATTR_NAME_LMV);
	lu_object_put(mti->mti_env, bottom_obj);

	return (rc > 0) ? 1 : (rc == -ENODATA) ? 0 : rc;
}

/**
 * Lock slave stripes if necessary, the lock handles of slave stripes
 * will be stored in einfo->ei_cbdata.
 **/
static int mdt_lock_slaves(struct mdt_thread_info *mti, struct mdt_object *obj,
			   enum ldlm_mode mode, __u64 ibits,
			   struct ldlm_enqueue_info *einfo)
{
	union ldlm_policy_data *policy = &mti->mti_policy;

	LASSERT(S_ISDIR(obj->mot_header.loh_attr));

	einfo->ei_type = LDLM_IBITS;
	einfo->ei_mode = mode;
	einfo->ei_cb_bl = mdt_remote_blocking_ast;
	einfo->ei_cb_local_bl = mdt_blocking_ast;
	einfo->ei_cb_cp = ldlm_completion_ast;
	einfo->ei_enq_slave = 1;
	einfo->ei_namespace = mti->mti_mdt->mdt_namespace;
	einfo->ei_inodebits = ibits;
	einfo->ei_req_slot = 1;
	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = ibits;

	return mo_object_lock(mti->mti_env, mdt_object_child(obj), NULL, einfo,
			      policy);
}

int mdt_reint_striped_lock(struct mdt_thread_info *info,
			   struct mdt_object *o,
			   struct mdt_lock_handle *lh,
			   __u64 ibits,
			   struct ldlm_enqueue_info *einfo,
			   bool cos_incompat)
{
	int rc;

	LASSERT(!mdt_object_remote(o));

	memset(einfo, 0, sizeof(*einfo));

	rc = mdt_reint_object_lock(info, o, lh, ibits, cos_incompat);
	if (rc)
		return rc;

	rc = mdt_object_striped(info, o);
	if (rc != 1) {
		if (rc < 0)
			mdt_object_unlock(info, o, lh, rc);
		return rc;
	}

	rc = mdt_lock_slaves(info, o, lh->mlh_reg_mode, ibits, einfo);
	if (rc) {
		mdt_object_unlock(info, o, lh, rc);
		if (rc == -EIO && OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_NAME))
			rc = 0;
	}

	return rc;
}

void mdt_reint_striped_unlock(struct mdt_thread_info *info,
			      struct mdt_object *o,
			      struct mdt_lock_handle *lh,
			      struct ldlm_enqueue_info *einfo, int decref)
{
	if (einfo->ei_cbdata)
		mdt_unlock_slaves(info, o, einfo, decref);
	mdt_object_unlock(info, o, lh, decref);
}

static int mdt_restripe(struct mdt_thread_info *info,
			struct mdt_object *parent,
			const struct lu_name *lname,
			const struct lu_fid *tfid,
			struct md_op_spec *spec,
			struct md_attr *ma)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct lu_fid *fid = &info->mti_tmp_fid2;
	struct ldlm_enqueue_info *einfo = &info->mti_einfo[0];
	struct lmv_user_md *lum = spec->u.sp_ea.eadata;
	struct lmv_mds_md_v1 *lmv;
	struct mdt_object *child;
	struct mdt_lock_handle *lhp;
	struct mdt_lock_handle *lhc;
	struct mdt_body *repbody;
	int rc;

	ENTRY;
	if (!mdt->mdt_enable_dir_restripe)
		RETURN(-EPERM);

	LASSERT(lum);
	lum->lum_hash_type |= cpu_to_le32(LMV_HASH_FLAG_FIXED);

	rc = mdt_version_get_check_save(info, parent, 0);
	if (rc)
		RETURN(rc);

	lhp = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_pdo_init(lhp, LCK_PW, lname);
	rc = mdt_reint_object_lock(info, parent, lhp, MDS_INODELOCK_UPDATE,
				   true);
	if (rc)
		RETURN(rc);

	rc = mdt_stripe_get(info, parent, ma, XATTR_NAME_LMV);
	if (rc)
		GOTO(unlock_parent, rc);

	if (ma->ma_valid & MA_LMV) {
		/* don't allow restripe if parent dir layout is changing */
		lmv = &ma->ma_lmv->lmv_md_v1;
		if (!lmv_is_sane2(lmv))
			GOTO(unlock_parent, rc = -EBADF);

		if (lmv_is_layout_changing(lmv))
			GOTO(unlock_parent, rc = -EBUSY);
	}

	fid_zero(fid);
	rc = mdt_lookup_version_check(info, parent, lname, fid, 1);
	if (rc)
		GOTO(unlock_parent, rc);

	child = mdt_object_find(info->mti_env, mdt, fid);
	if (IS_ERR(child))
		GOTO(unlock_parent, rc = PTR_ERR(child));

	if (!mdt_object_exists(child))
		GOTO(out_child, rc = -ENOENT);

	if (mdt_object_remote(child)) {
		struct mdt_body *repbody;

		repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		if (!repbody)
			GOTO(out_child, rc = -EPROTO);

		repbody->mbo_fid1 = *fid;
		repbody->mbo_valid |= (OBD_MD_FLID | OBD_MD_MDS);
		GOTO(out_child, rc = -EREMOTE);
	}

	if (!S_ISDIR(lu_object_attr(&child->mot_obj)))
		GOTO(out_child, rc = -ENOTDIR);

	rc = mdt_stripe_get(info, child, ma, XATTR_NAME_LMV);
	if (rc)
		GOTO(out_child, rc);

	/* race with migrate? */
	if ((ma->ma_valid & MA_LMV) &&
	     lmv_is_migrating(&ma->ma_lmv->lmv_md_v1))
		GOTO(out_child, rc = -EBUSY);

	/* lock object */
	lhc = &info->mti_lh[MDT_LH_CHILD];
	mdt_lock_reg_init(lhc, LCK_EX);

	/* enqueue object remote LOOKUP lock */
	if (mdt_object_remote(parent)) {
		rc = mdt_remote_object_lock(info, parent, fid,
					    &lhc->mlh_rreg_lh,
					    lhc->mlh_rreg_mode,
					    MDS_INODELOCK_LOOKUP, false);
		if (rc != ELDLM_OK)
			GOTO(out_child, rc);
	}

	rc = mdt_reint_striped_lock(info, child, lhc, MDS_INODELOCK_FULL, einfo,
				    true);
	if (rc)
		GOTO(unlock_child, rc);

	tgt_vbr_obj_set(info->mti_env, mdt_obj2dt(child));
	rc = mdt_version_get_check_save(info, child, 1);
	if (rc)
		GOTO(unlock_child, rc);

	spin_lock(&mdt->mdt_restriper.mdr_lock);
	if (child->mot_restriping) {
		/* race? */
		spin_unlock(&mdt->mdt_restriper.mdr_lock);
		GOTO(unlock_child, rc = -EBUSY);
	}
	child->mot_restriping = 1;
	spin_unlock(&mdt->mdt_restriper.mdr_lock);

	*fid = *tfid;
	rc = mdt_restripe_internal(info, parent, child, lname, fid, spec, ma);
	if (rc)
		GOTO(restriping_clear, rc);

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
	if (!repbody)
		GOTO(restriping_clear, rc = -EPROTO);

	mdt_pack_attr2body(info, repbody, &ma->ma_attr, fid);
	EXIT;

restriping_clear:
	child->mot_restriping = 0;
unlock_child:
	mdt_reint_striped_unlock(info, child, lhc, einfo, rc);
out_child:
	mdt_object_put(info->mti_env, child);
unlock_parent:
	mdt_object_unlock(info, parent, lhp, rc);

	return rc;
}

/*
 * VBR: we save three versions in reply:
 * 0 - parent. Check that parent version is the same during replay.
 * 1 - name. Version of 'name' if file exists with the same name or
 * ENOENT_VERSION, it is needed because file may appear due to missed replays.
 * 2 - child. Version of child by FID. Must be ENOENT. It is mostly sanity
 * check.
 */
static int mdt_create(struct mdt_thread_info *info)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_object *parent;
	struct mdt_object *child;
	struct mdt_lock_handle *lh;
	struct mdt_body *repbody;
	struct md_attr *ma = &info->mti_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct md_op_spec *spec = &info->mti_spec;
	bool restripe = false;
	int rc;

	ENTRY;
	DEBUG_REQ(D_INODE, mdt_info_req(info),
		  "Create ("DNAME"->"DFID") in "DFID,
		  PNAME(&rr->rr_name), PFID(rr->rr_fid2), PFID(rr->rr_fid1));

	if (!fid_is_md_operative(rr->rr_fid1))
		RETURN(-EPERM);

	if (S_ISDIR(ma->ma_attr.la_mode) &&
	    spec->u.sp_ea.eadata != NULL && spec->u.sp_ea.eadatalen != 0) {
		const struct lmv_user_md *lum = spec->u.sp_ea.eadata;
		struct lu_ucred	*uc = mdt_ucred(info);
		struct obd_export *exp = mdt_info_req(info)->rq_export;

		/* Only new clients can create remote dir( >= 2.4) and
		 * striped dir(>= 2.6), old client will return -ENOTSUPP
		 */
		if (!mdt_is_dne_client(exp))
			RETURN(-ENOTSUPP);

		if (le32_to_cpu(lum->lum_stripe_count) > 1) {
			if (!mdt_is_striped_client(exp))
				RETURN(-ENOTSUPP);

			if (!mdt->mdt_enable_striped_dir)
				RETURN(-EPERM);
		} else if (!mdt->mdt_enable_remote_dir) {
			RETURN(-EPERM);
		}

		if ((!(exp_connect_flags2(exp) & OBD_CONNECT2_CRUSH)) &&
		    (le32_to_cpu(lum->lum_hash_type) & LMV_HASH_TYPE_MASK) ==
		    LMV_HASH_TYPE_CRUSH)
			RETURN(-EPROTO);

		if (!cap_raised(uc->uc_cap, CAP_SYS_ADMIN) &&
		    uc->uc_gid != mdt->mdt_enable_remote_dir_gid &&
		    mdt->mdt_enable_remote_dir_gid != -1)
			RETURN(-EPERM);

		/* restripe if later found dir exists, MDS_OPEN_CREAT means
		 * this is create only, don't try restripe.
		 */
		if (mdt->mdt_enable_dir_restripe &&
		    le32_to_cpu(lum->lum_stripe_offset) == LMV_OFFSET_DEFAULT &&
		    !(spec->sp_cr_flags & MDS_OPEN_CREAT))
			restripe = true;
	}

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

	parent = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(parent))
		RETURN(PTR_ERR(parent));

	if (!mdt_object_exists(parent))
		GOTO(put_parent, rc = -ENOENT);

	/*
	 * LU-10235: check if name exists locklessly first to avoid massive
	 * lock recalls on existing directories.
	 */
	rc = mdt_lookup_version_check(info, parent, &rr->rr_name,
				      &info->mti_tmp_fid1, 1);
	if (rc == 0) {
		if (!restripe)
			GOTO(put_parent, rc = -EEXIST);

		rc = mdt_restripe(info, parent, &rr->rr_name, rr->rr_fid2, spec,
				  ma);
	}

	/* -ENOENT is expected here */
	if (rc != -ENOENT)
		GOTO(put_parent, rc);

	/* save version of file name for replay, it must be ENOENT here */
	mdt_enoent_version_save(info, 1);

	OBD_RACE(OBD_FAIL_MDS_CREATE_RACE);

	lh = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_pdo_init(lh, LCK_PW, &rr->rr_name);
	rc = mdt_object_lock(info, parent, lh, MDS_INODELOCK_UPDATE);
	if (rc)
		GOTO(put_parent, rc);

	if (!mdt_object_remote(parent)) {
		rc = mdt_version_get_check_save(info, parent, 0);
		if (rc)
			GOTO(unlock_parent, rc);
	}

	child = mdt_object_new(info->mti_env, mdt, rr->rr_fid2);
	if (unlikely(IS_ERR(child)))
		GOTO(unlock_parent, rc = PTR_ERR(child));

	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;

	mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
			OBD_FAIL_MDS_REINT_CREATE_WRITE);

	/* Version of child will be updated on disk. */
	tgt_vbr_obj_set(info->mti_env, mdt_obj2dt(child));
	rc = mdt_version_get_check_save(info, child, 2);
	if (rc)
		GOTO(put_child, rc);

	/*
	 * Do not perform lookup sanity check. We know that name does
	 * not exist.
	 */
	info->mti_spec.sp_cr_lookup = 0;
	info->mti_spec.sp_feat = &dt_directory_features;

	rc = mdo_create(info->mti_env, mdt_object_child(parent), &rr->rr_name,
			mdt_object_child(child), &info->mti_spec, ma);
	if (rc == 0)
		rc = mdt_attr_get_complex(info, child, ma);

	if (rc < 0)
		GOTO(put_child, rc);

	/*
	 * On DNE, we need to eliminate dependey between 'mkdir a' and
	 * 'mkdir a/b' if b is a striped directory, to achieve this, two
	 * things are done below:
	 * 1. save child and slaves lock.
	 * 2. if the child is a striped directory, relock parent so to
	 *    compare against with COS locks to ensure parent was
	 *    committed to disk.
	 */
	if (mdt_slc_is_enabled(mdt) && S_ISDIR(ma->ma_attr.la_mode)) {
		struct mdt_lock_handle *lhc;
		struct ldlm_enqueue_info *einfo = &info->mti_einfo[0];
		bool cos_incompat;

		rc = mdt_object_striped(info, child);
		if (rc < 0)
			GOTO(put_child, rc);

		cos_incompat = rc;
		if (cos_incompat) {
			if (!mdt_object_remote(parent)) {
				mdt_object_unlock(info, parent, lh, 1);
				mdt_lock_pdo_init(lh, LCK_PW, &rr->rr_name);
				rc = mdt_reint_object_lock(info, parent, lh,
							   MDS_INODELOCK_UPDATE,
							   true);
				if (rc)
					GOTO(put_child, rc);
			}
		}

		lhc = &info->mti_lh[MDT_LH_CHILD];
		mdt_lock_handle_init(lhc);
		mdt_lock_reg_init(lhc, LCK_PW);
		rc = mdt_reint_striped_lock(info, child, lhc,
					    MDS_INODELOCK_UPDATE, einfo,
					    cos_incompat);
		if (rc)
			GOTO(put_child, rc);

		mdt_reint_striped_unlock(info, child, lhc, einfo, rc);
	}

	/* Return fid & attr to client. */
	if (ma->ma_valid & MA_INODE)
		mdt_pack_attr2body(info, repbody, &ma->ma_attr,
				   mdt_object_fid(child));
	EXIT;
put_child:
	mdt_object_put(info->mti_env, child);
unlock_parent:
	mdt_object_unlock(info, parent, lh, rc);
put_parent:
	mdt_object_put(info->mti_env, parent);
	return rc;
}

static int mdt_attr_set(struct mdt_thread_info *info, struct mdt_object *mo,
			struct md_attr *ma)
{
	struct mdt_lock_handle  *lh;
	int do_vbr = ma->ma_attr.la_valid &
			(LA_MODE | LA_UID | LA_GID | LA_PROJID | LA_FLAGS);
	__u64 lockpart = MDS_INODELOCK_UPDATE;
	struct ldlm_enqueue_info *einfo = &info->mti_einfo[0];
	bool cos_incompat;
	int rc;

	ENTRY;
	rc = mdt_object_striped(info, mo);
	if (rc < 0)
		RETURN(rc);

	cos_incompat = rc;

	lh = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_reg_init(lh, LCK_PW);

	/* Even though the new MDT will grant PERM lock to the old
	 * client, but the old client will almost ignore that during
	 * So it needs to revoke both LOOKUP and PERM lock here, so
	 * both new and old client can cancel the dcache
	 */
	if (ma->ma_attr.la_valid & (LA_MODE|LA_UID|LA_GID))
		lockpart |= MDS_INODELOCK_LOOKUP | MDS_INODELOCK_PERM;

	rc = mdt_reint_striped_lock(info, mo, lh, lockpart, einfo,
				    cos_incompat);
	if (rc != 0)
		RETURN(rc);

	/* all attrs are packed into mti_attr in unpack_setattr */
	mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
		       OBD_FAIL_MDS_REINT_SETATTR_WRITE);

	/* VBR: update version if attr changed are important for recovery */
	if (do_vbr) {
		/* update on-disk version of changed object */
		tgt_vbr_obj_set(info->mti_env, mdt_obj2dt(mo));
		rc = mdt_version_get_check_save(info, mo, 0);
		if (rc)
			GOTO(out_unlock, rc);
	}

	/* Ensure constant striping during chown(). See LU-2789. */
	if (ma->ma_attr.la_valid & (LA_UID|LA_GID|LA_PROJID))
		mutex_lock(&mo->mot_lov_mutex);

	/* all attrs are packed into mti_attr in unpack_setattr */
	rc = mo_attr_set(info->mti_env, mdt_object_child(mo), ma);

	if (ma->ma_attr.la_valid & (LA_UID|LA_GID|LA_PROJID))
		mutex_unlock(&mo->mot_lov_mutex);

	if (rc != 0)
		GOTO(out_unlock, rc);
	mdt_dom_obj_lvb_update(info->mti_env, mo, NULL, false);
	EXIT;
out_unlock:
	mdt_reint_striped_unlock(info, mo, lh, einfo, rc);
	return rc;
}

/**
 * Check HSM flags and add HS_DIRTY flag if relevant.
 *
 * A file could be set dirty only if it has a copy in the backend (HS_EXISTS)
 * and is not RELEASED.
 */
int mdt_add_dirty_flag(struct mdt_thread_info *info, struct mdt_object *mo,
			struct md_attr *ma)
{
	struct lu_ucred *uc = mdt_ucred(info);
	kernel_cap_t cap_saved;
	int rc;

	ENTRY;
	/* If the file was modified, add the dirty flag */
	ma->ma_need = MA_HSM;
	rc = mdt_attr_get_complex(info, mo, ma);
	if (rc) {
		CERROR("file attribute read error for "DFID": %d.\n",
			PFID(mdt_object_fid(mo)), rc);
		RETURN(rc);
	}

	/* If an up2date copy exists in the backend, add dirty flag */
	if ((ma->ma_valid & MA_HSM) && (ma->ma_hsm.mh_flags & HS_EXISTS)
	    && !(ma->ma_hsm.mh_flags & (HS_DIRTY|HS_RELEASED))) {
		ma->ma_hsm.mh_flags |= HS_DIRTY;

		/* Bump cap so that closes from non-owner writers can
		 * set the HSM state to dirty.
		 */
		cap_saved = uc->uc_cap;
		cap_raise(uc->uc_cap, CAP_FOWNER);
		rc = mdt_hsm_attr_set(info, mo, &ma->ma_hsm);
		uc->uc_cap = cap_saved;
		if (rc)
			CERROR("file attribute change error for "DFID": %d\n",
				PFID(mdt_object_fid(mo)), rc);
	}

	RETURN(rc);
}

static int mdt_reint_setattr(struct mdt_thread_info *info,
			     struct mdt_lock_handle *lhc)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct md_attr *ma = &info->mti_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct ptlrpc_request *req = mdt_info_req(info);
	struct mdt_object *mo;
	struct mdt_body *repbody;
	ktime_t kstart = ktime_get();
	int rc, rc2;

	ENTRY;
	DEBUG_REQ(D_INODE, req, "setattr "DFID" %x", PFID(rr->rr_fid1),
		  (unsigned int)ma->ma_attr.la_valid);

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	OBD_RACE(OBD_FAIL_PTLRPC_RESEND_RACE);

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
	mo = mdt_object_find(info->mti_env, mdt, rr->rr_fid1);
	if (IS_ERR(mo))
		GOTO(out, rc = PTR_ERR(mo));

	if (!mdt_object_exists(mo))
		GOTO(out_put, rc = -ENOENT);

	if (mdt_object_remote(mo))
		GOTO(out_put, rc = -EREMOTE);

	ma->ma_enable_chprojid_gid = mdt->mdt_enable_chprojid_gid;
	/* revoke lease lock if size is going to be changed */
	if (unlikely(ma->ma_attr.la_valid & LA_SIZE &&
		     !(ma->ma_attr_flags & MDS_TRUNC_KEEP_LEASE) &&
		     atomic_read(&mo->mot_lease_count) > 0)) {
		down_read(&mo->mot_open_sem);

		if (atomic_read(&mo->mot_lease_count) > 0) { /* lease exists */
			lhc = &info->mti_lh[MDT_LH_LOCAL];
			mdt_lock_reg_init(lhc, LCK_CW);

			rc = mdt_object_lock(info, mo, lhc, MDS_INODELOCK_OPEN);
			if (rc != 0) {
				up_read(&mo->mot_open_sem);
				GOTO(out_put, rc);
			}

			/* revoke lease lock */
			mdt_object_unlock(info, mo, lhc, 1);
		}
		up_read(&mo->mot_open_sem);
	}

	if (ma->ma_attr.la_valid & LA_SIZE || rr->rr_flags & MRF_OPEN_TRUNC) {
		/* Check write access for the O_TRUNC case */
		if (mdt_write_read(mo) < 0)
			GOTO(out_put, rc = -ETXTBSY);

		/* LU-10286: compatibility check for FLR.
		 * Please check the comment in mdt_finish_open() for details
		 */
		if (!exp_connect_flr(info->mti_exp) ||
		    !exp_connect_overstriping(info->mti_exp)) {
			rc = mdt_big_xattr_get(info, mo, XATTR_NAME_LOV);
			if (rc < 0 && rc != -ENODATA)
				GOTO(out_put, rc);

			if (!exp_connect_flr(info->mti_exp)) {
				if (rc > 0 &&
				    mdt_lmm_is_flr(info->mti_big_lmm))
					GOTO(out_put, rc = -EOPNOTSUPP);
			}

			if (!exp_connect_overstriping(info->mti_exp)) {
				if (rc > 0 &&
				    mdt_lmm_is_overstriping(info->mti_big_lmm))
					GOTO(out_put, rc = -EOPNOTSUPP);
			}
		}

		/* For truncate, the file size sent from client
		 * is believable, but the blocks are incorrect,
		 * which makes the block size in LSOM attribute
		 * inconsisent with the real block size.
		 */
		rc = mdt_lsom_update(info, mo, true);
		if (rc)
			GOTO(out_put, rc);
	}

	if ((ma->ma_valid & MA_INODE) && ma->ma_attr.la_valid) {
		if (ma->ma_valid & MA_LOV)
			GOTO(out_put, rc = -EPROTO);

		/* MDT supports FMD for regular files due to Data-on-MDT */
		if (S_ISREG(lu_object_attr(&mo->mot_obj)) &&
		    ma->ma_attr.la_valid & (LA_ATIME | LA_MTIME | LA_CTIME)) {
			tgt_fmd_update(info->mti_exp, mdt_object_fid(mo),
				       req->rq_xid);

			if (ma->ma_attr.la_valid & LA_MTIME) {
				rc = mdt_attr_get_pfid(info, mo, &ma->ma_pfid);
				if (!rc)
					ma->ma_valid |= MA_PFID;
			}
		}

		rc = mdt_attr_set(info, mo, ma);
		if (rc)
			GOTO(out_put, rc);
	} else if ((ma->ma_valid & (MA_LOV | MA_LMV)) &&
		   (ma->ma_valid & MA_INODE)) {
		struct lu_buf *buf = &info->mti_buf;
		struct lu_ucred *uc = mdt_ucred(info);
		struct mdt_lock_handle *lh;
		const char *name;
		__u64 lockpart = MDS_INODELOCK_XATTR;

		/* reject if either remote or striped dir is disabled */
		if (ma->ma_valid & MA_LMV) {
			if (!mdt->mdt_enable_remote_dir ||
			    !mdt->mdt_enable_striped_dir)
				GOTO(out_put, rc = -EPERM);

			if (!cap_raised(uc->uc_cap, CAP_SYS_ADMIN) &&
			    uc->uc_gid != mdt->mdt_enable_remote_dir_gid &&
			    mdt->mdt_enable_remote_dir_gid != -1)
				GOTO(out_put, rc = -EPERM);
		}

		if (!S_ISDIR(lu_object_attr(&mo->mot_obj)))
			GOTO(out_put, rc = -ENOTDIR);

		if (ma->ma_attr.la_valid != 0)
			GOTO(out_put, rc = -EPROTO);

		lh = &info->mti_lh[MDT_LH_PARENT];
		mdt_lock_reg_init(lh, LCK_PW);

		if (ma->ma_valid & MA_LOV) {
			buf->lb_buf = ma->ma_lmm;
			buf->lb_len = ma->ma_lmm_size;
			name = XATTR_NAME_LOV;
		} else {
			struct lmv_user_md *lmu = &ma->ma_lmv->lmv_user_md;
			struct lu_fid *pfid = &info->mti_tmp_fid1;
			struct lu_name *pname = &info->mti_name;
			const char dotdot[] = "..";
			struct mdt_object *pobj;

			buf->lb_buf = lmu;
			buf->lb_len = ma->ma_lmv_size;
			name = XATTR_NAME_DEFAULT_LMV;

			if (fid_is_root(rr->rr_fid1)) {
				lockpart |= MDS_INODELOCK_LOOKUP;
			} else {
				/* force client to update dir default layout */
				fid_zero(pfid);
				pname->ln_name = dotdot;
				pname->ln_namelen = sizeof(dotdot);
				rc = mdo_lookup(info->mti_env,
						mdt_object_child(mo), pname,
						pfid, NULL);
				if (rc)
					GOTO(out_put, rc);

				pobj = mdt_object_find(info->mti_env, mdt,
						       pfid);
				if (IS_ERR(pobj))
					GOTO(out_put, rc = PTR_ERR(pobj));

				if (mdt_object_remote(pobj))
					rc = mdt_remote_object_lock(info, pobj,
						mdt_object_fid(mo),
						&lh->mlh_rreg_lh, LCK_EX,
						MDS_INODELOCK_LOOKUP, false);
				else
					lockpart |= MDS_INODELOCK_LOOKUP;

				mdt_object_put(info->mti_env, pobj);

				if (rc)
					GOTO(out_put, rc);
			}
		}

		rc = mdt_object_lock(info, mo, lh, lockpart);
		if (rc != 0)
			GOTO(out_put, rc);

		rc = mo_xattr_set(info->mti_env, mdt_object_child(mo), buf,
				  name, 0);

		mdt_object_unlock(info, mo, lh, rc);
		if (rc)
			GOTO(out_put, rc);
	} else {
		GOTO(out_put, rc = -EPROTO);
	}

	/* If file data is modified, add the dirty flag */
	if (ma->ma_attr_flags & MDS_DATA_MODIFIED)
		rc = mdt_add_dirty_flag(info, mo, ma);

	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;
	rc = mdt_attr_get_complex(info, mo, ma);
	if (rc != 0)
		GOTO(out_put, rc);

	mdt_pack_attr2body(info, repbody, &ma->ma_attr, mdt_object_fid(mo));

	EXIT;
out_put:
	mdt_object_put(info->mti_env, mo);
out:
	if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_SETATTR,
				 ktime_us_delta(ktime_get(), kstart));

	mdt_client_compatibility(info);
	rc2 = mdt_fix_reply(info);
	if (rc == 0)
		rc = rc2;
	return rc;
}

static int mdt_reint_create(struct mdt_thread_info *info,
			    struct mdt_lock_handle *lhc)
{
	struct ptlrpc_request   *req = mdt_info_req(info);
	ktime_t			kstart = ktime_get();
	int                     rc;

	ENTRY;
	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE))
		RETURN(err_serious(-ESTALE));

	if (info->mti_dlm_req)
		ldlm_request_cancel(mdt_info_req(info),
				    info->mti_dlm_req, 0, LATF_SKIP);

	if (!lu_name_is_valid(&info->mti_rr.rr_name))
		RETURN(-EPROTO);

	switch (info->mti_attr.ma_attr.la_mode & S_IFMT) {
	case S_IFDIR:
	case S_IFREG:
	case S_IFLNK:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		break;
	default:
		CERROR("%s: Unsupported mode %o\n",
		       mdt_obd_name(info->mti_mdt),
		       info->mti_attr.ma_attr.la_mode);
		RETURN(err_serious(-EOPNOTSUPP));
	}

	rc = mdt_create(info);
	if (rc == 0) {
		if ((info->mti_attr.ma_attr.la_mode & S_IFMT) == S_IFDIR)
			mdt_counter_incr(req, LPROC_MDT_MKDIR,
					 ktime_us_delta(ktime_get(), kstart));
		else
			/* Special file should stay on the same node as parent*/
			mdt_counter_incr(req, LPROC_MDT_MKNOD,
					 ktime_us_delta(ktime_get(), kstart));
	}

	RETURN(rc);
}

/*
 * VBR: save parent version in reply and child version getting by its name.
 * Version of child is getting and checking during its lookup. If
 */
static int mdt_reint_unlink(struct mdt_thread_info *info,
			    struct mdt_lock_handle *lhc)
{
	struct mdt_reint_record *rr = &info->mti_rr;
	struct ptlrpc_request *req = mdt_info_req(info);
	struct md_attr *ma = &info->mti_attr;
	struct lu_fid *child_fid = &info->mti_tmp_fid1;
	struct mdt_object *mp;
	struct mdt_object *mc;
	struct mdt_lock_handle *parent_lh;
	struct mdt_lock_handle *child_lh;
	struct ldlm_enqueue_info *einfo = &info->mti_einfo[0];
	__u64 lock_ibits;
	bool cos_incompat = false;
	int no_name = 0;
	ktime_t kstart = ktime_get();
	int rc;

	ENTRY;
	DEBUG_REQ(D_INODE, req, "unlink "DFID"/"DNAME"", PFID(rr->rr_fid1),
		  PNAME(&rr->rr_name));

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
		RETURN(err_serious(-ENOENT));

	if (!fid_is_md_operative(rr->rr_fid1))
		RETURN(-EPERM);

	mp = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(mp))
		RETURN(PTR_ERR(mp));

	if (mdt_object_remote(mp)) {
		cos_incompat = true;
	} else {
		rc = mdt_version_get_check_save(info, mp, 0);
		if (rc)
			GOTO(put_parent, rc);
	}

	OBD_RACE(OBD_FAIL_MDS_REINT_OPEN);
	OBD_RACE(OBD_FAIL_MDS_REINT_OPEN2);
relock:
	parent_lh = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_pdo_init(parent_lh, LCK_PW, &rr->rr_name);
	rc = mdt_reint_object_lock(info, mp, parent_lh, MDS_INODELOCK_UPDATE,
				   cos_incompat);
	if (rc != 0)
		GOTO(put_parent, rc);

	if (info->mti_spec.sp_cr_flags & MDS_OP_WITH_FID) {
		*child_fid = *rr->rr_fid2;
	} else {
		/* lookup child object along with version checking */
		fid_zero(child_fid);
		rc = mdt_lookup_version_check(info, mp, &rr->rr_name, child_fid,
					      1);
		if (rc != 0) {
			/* Name might not be able to find during resend of
			 * remote unlink, considering following case.
			 * dir_A is a remote directory, the name entry of
			 * dir_A is on MDT0, the directory is on MDT1,
			 *
			 * 1. client sends unlink req to MDT1.
			 * 2. MDT1 sends name delete update to MDT0.
			 * 3. name entry is being deleted in MDT0 synchronously.
			 * 4. MDT1 is restarted.
			 * 5. client resends unlink req to MDT1. So it can not
			 *    find the name entry on MDT0 anymore.
			 * In this case, MDT1 only needs to destory the local
			 * directory.
			 */
			if (mdt_object_remote(mp) && rc == -ENOENT &&
			    !fid_is_zero(rr->rr_fid2) &&
			    lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
				no_name = 1;
				*child_fid = *rr->rr_fid2;
			} else {
				GOTO(unlock_parent, rc);
			}
		}
	}

	if (!fid_is_md_operative(child_fid))
		GOTO(unlock_parent, rc = -EPERM);

	/* We will lock the child regardless it is local or remote. No harm. */
	mc = mdt_object_find(info->mti_env, info->mti_mdt, child_fid);
	if (IS_ERR(mc))
		GOTO(unlock_parent, rc = PTR_ERR(mc));

	if (info->mti_spec.sp_cr_flags & MDS_OP_WITH_FID) {
		/* In this case, child fid is embedded in the request, and we do
		 * not have a proper name as rr_name contains an encoded
		 * hash. So find name that matches provided hash.
		 */
		if (!find_name_matching_hash(info, &rr->rr_name,
					     NULL, mc, false))
			GOTO(put_child, rc = -ENOENT);
	}

	if (!cos_incompat) {
		rc = mdt_object_striped(info, mc);
		if (rc < 0)
			GOTO(put_child, rc);

		cos_incompat = rc;
		if (cos_incompat) {
			mdt_object_put(info->mti_env, mc);
			mdt_object_unlock(info, mp, parent_lh, -EAGAIN);
			goto relock;
		}
	}

	child_lh = &info->mti_lh[MDT_LH_CHILD];
	mdt_lock_reg_init(child_lh, LCK_EX);
	if (info->mti_spec.sp_rm_entry) {
		struct lu_ucred *uc  = mdt_ucred(info);

		if (!mdt_is_dne_client(req->rq_export))
			/* Return -ENOTSUPP for old client */
			GOTO(put_child, rc = -ENOTSUPP);

		if (!cap_raised(uc->uc_cap, CAP_SYS_ADMIN))
			GOTO(put_child, rc = -EPERM);

		ma->ma_need = MA_INODE;
		ma->ma_valid = 0;
		rc = mdo_unlink(info->mti_env, mdt_object_child(mp),
				NULL, &rr->rr_name, ma, no_name);
		GOTO(put_child, rc);
	}

	if (mdt_object_remote(mc)) {
		struct mdt_body	 *repbody;

		if (!fid_is_zero(rr->rr_fid2)) {
			CDEBUG(D_INFO, "%s: name "DNAME" cannot find "DFID"\n",
			       mdt_obd_name(info->mti_mdt),
			       PNAME(&rr->rr_name), PFID(mdt_object_fid(mc)));
			GOTO(put_child, rc = -ENOENT);
		}
		CDEBUG(D_INFO, "%s: name "DNAME": "DFID" is on another MDT\n",
		       mdt_obd_name(info->mti_mdt),
		       PNAME(&rr->rr_name), PFID(mdt_object_fid(mc)));

		if (!mdt_is_dne_client(req->rq_export))
			/* Return -ENOTSUPP for old client */
			GOTO(put_child, rc = -ENOTSUPP);

		/* Revoke the LOOKUP lock of the remote object granted by
		 * this MDT. Since the unlink will happen on another MDT,
		 * it will release the LOOKUP lock right away. Then What
		 * would happen if another client try to grab the LOOKUP
		 * lock at the same time with unlink XXX
		 */
		mdt_object_lock(info, mc, child_lh, MDS_INODELOCK_LOOKUP);
		repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		LASSERT(repbody != NULL);
		repbody->mbo_fid1 = *mdt_object_fid(mc);
		repbody->mbo_valid |= (OBD_MD_FLID | OBD_MD_MDS);
		GOTO(unlock_child, rc = -EREMOTE);
	}
	/* We used to acquire MDS_INODELOCK_FULL here but we can't do
	 * this now because a running HSM restore on the child (unlink
	 * victim) will hold the layout lock. See LU-4002.
	 */
	lock_ibits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE;
	if (mdt_object_remote(mp)) {
		/* Enqueue lookup lock from parent MDT */
		rc = mdt_remote_object_lock(info, mp, mdt_object_fid(mc),
					    &child_lh->mlh_rreg_lh,
					    child_lh->mlh_rreg_mode,
					    MDS_INODELOCK_LOOKUP, false);
		if (rc != ELDLM_OK)
			GOTO(put_child, rc);

		lock_ibits &= ~MDS_INODELOCK_LOOKUP;
	}

	rc = mdt_reint_striped_lock(info, mc, child_lh, lock_ibits, einfo,
				    cos_incompat);
	if (rc != 0)
		GOTO(put_child, rc);

	/*
	 * Now we can only make sure we need MA_INODE, in mdd layer, will check
	 * whether need MA_LOV and MA_COOKIE.
	 */
	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;

	mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
		       OBD_FAIL_MDS_REINT_UNLINK_WRITE);
	/* save version when object is locked */
	mdt_version_get_save(info, mc, 1);

	mutex_lock(&mc->mot_lov_mutex);

	rc = mdo_unlink(info->mti_env, mdt_object_child(mp),
			mdt_object_child(mc), &rr->rr_name, ma, no_name);

	mutex_unlock(&mc->mot_lov_mutex);
	if (rc != 0)
		GOTO(unlock_child, rc);

	if (!lu_object_is_dying(&mc->mot_header)) {
		rc = mdt_attr_get_complex(info, mc, ma);
		if (rc)
			GOTO(out_stat, rc);
	} else if (mdt_dom_check_for_discard(info, mc)) {
		mdt_dom_discard_data(info, mc);
	}
	mdt_handle_last_unlink(info, mc, ma);

out_stat:
	if (ma->ma_valid & MA_INODE) {
		switch (ma->ma_attr.la_mode & S_IFMT) {
		case S_IFDIR:
			mdt_counter_incr(req, LPROC_MDT_RMDIR,
					 ktime_us_delta(ktime_get(), kstart));
			break;
		case S_IFREG:
		case S_IFLNK:
		case S_IFCHR:
		case S_IFBLK:
		case S_IFIFO:
		case S_IFSOCK:
			mdt_counter_incr(req, LPROC_MDT_UNLINK,
					 ktime_us_delta(ktime_get(), kstart));
			break;
		default:
			LASSERTF(0, "bad file type %o unlinking\n",
				ma->ma_attr.la_mode);
		}
	}

	EXIT;

unlock_child:
	mdt_reint_striped_unlock(info, mc, child_lh, einfo, rc);
put_child:
	if (info->mti_spec.sp_cr_flags & MDS_OP_WITH_FID &&
	    info->mti_big_buf.lb_buf)
		lu_buf_free(&info->mti_big_buf);
	mdt_object_put(info->mti_env, mc);
unlock_parent:
	mdt_object_unlock(info, mp, parent_lh, rc);
put_parent:
	mdt_object_put(info->mti_env, mp);
	CFS_RACE_WAKEUP(OBD_FAIL_OBD_ZERO_NLINK_RACE);
	return rc;
}

/*
 * VBR: save versions in reply: 0 - parent; 1 - child by fid; 2 - target by
 * name.
 */
static int mdt_reint_link(struct mdt_thread_info *info,
			  struct mdt_lock_handle *lhc)
{
	struct mdt_reint_record *rr = &info->mti_rr;
	struct ptlrpc_request   *req = mdt_info_req(info);
	struct md_attr          *ma = &info->mti_attr;
	struct mdt_object       *ms;
	struct mdt_object       *mp;
	struct mdt_lock_handle  *lhs;
	struct mdt_lock_handle  *lhp;
	ktime_t kstart = ktime_get();
	bool cos_incompat;
	int rc;

	ENTRY;
	DEBUG_REQ(D_INODE, req, "link "DFID" to "DFID"/"DNAME,
		  PFID(rr->rr_fid1), PFID(rr->rr_fid2), PNAME(&rr->rr_name));

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK))
		RETURN(err_serious(-ENOENT));

	if (OBD_FAIL_PRECHECK(OBD_FAIL_PTLRPC_RESEND_RACE) ||
	    OBD_FAIL_PRECHECK(OBD_FAIL_PTLRPC_ENQ_RESEND)) {
		req->rq_no_reply = 1;
		RETURN(err_serious(-ENOENT));
	}

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	/* Invalid case so return error immediately instead of
	 * processing it
	 */
	if (lu_fid_eq(rr->rr_fid1, rr->rr_fid2))
		RETURN(-EPERM);

	if (!fid_is_md_operative(rr->rr_fid1) ||
	    !fid_is_md_operative(rr->rr_fid2))
		RETURN(-EPERM);

	/* step 1: find target parent dir */
	mp = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid2);
	if (IS_ERR(mp))
		RETURN(PTR_ERR(mp));

	rc = mdt_version_get_check_save(info, mp, 0);
	if (rc)
		GOTO(put_parent, rc);

	/* step 2: find source */
	ms = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(ms))
		GOTO(put_parent, rc = PTR_ERR(ms));

	if (!mdt_object_exists(ms)) {
		CDEBUG(D_INFO, "%s: "DFID" does not exist.\n",
		       mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1));
		GOTO(put_source, rc = -ENOENT);
	}

	cos_incompat = (mdt_object_remote(mp) || mdt_object_remote(ms));

	OBD_RACE(OBD_FAIL_MDS_LINK_RENAME_RACE);

	lhp = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_pdo_init(lhp, LCK_PW, &rr->rr_name);
	rc = mdt_reint_object_lock(info, mp, lhp, MDS_INODELOCK_UPDATE,
				   cos_incompat);
	if (rc != 0)
		GOTO(put_source, rc);

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME3, 5);

	lhs = &info->mti_lh[MDT_LH_CHILD];
	mdt_lock_reg_init(lhs, LCK_EX);
	rc = mdt_reint_object_lock(info, ms, lhs,
				   MDS_INODELOCK_UPDATE | MDS_INODELOCK_XATTR,
				   cos_incompat);
	if (rc != 0)
		GOTO(unlock_parent, rc);

	/* step 3: link it */
	mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
			OBD_FAIL_MDS_REINT_LINK_WRITE);

	tgt_vbr_obj_set(info->mti_env, mdt_obj2dt(ms));
	rc = mdt_version_get_check_save(info, ms, 1);
	if (rc)
		GOTO(unlock_source, rc);

	/** check target version by name during replay */
	rc = mdt_lookup_version_check(info, mp, &rr->rr_name,
				      &info->mti_tmp_fid1, 2);
	if (rc != 0 && rc != -ENOENT)
		GOTO(unlock_source, rc);
	/* save version of file name for replay, it must be ENOENT here */
	if (!req_is_replay(mdt_info_req(info))) {
		if (rc != -ENOENT) {
			CDEBUG(D_INFO, "link target "DNAME" existed!\n",
			       PNAME(&rr->rr_name));
			GOTO(unlock_source, rc = -EEXIST);
		}
		info->mti_ver[2] = ENOENT_VERSION;
		mdt_version_save(mdt_info_req(info), info->mti_ver[2], 2);
	}

	rc = mdo_link(info->mti_env, mdt_object_child(mp),
		      mdt_object_child(ms), &rr->rr_name, ma);

	if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_LINK,
				 ktime_us_delta(ktime_get(), kstart));

	EXIT;
unlock_source:
	mdt_object_unlock(info, ms, lhs, rc);
unlock_parent:
	mdt_object_unlock(info, mp, lhp, rc);
put_source:
	mdt_object_put(info->mti_env, ms);
put_parent:
	mdt_object_put(info->mti_env, mp);
	return rc;
}
/**
 * lock the part of the directory according to the hash of the name
 * (lh->mlh_pdo_hash) in parallel directory lock.
 */
static int mdt_pdir_hash_lock(struct mdt_thread_info *info,
			      struct mdt_lock_handle *lh,
			      struct mdt_object *obj, __u64 ibits,
			      bool cos_incompat)
{
	struct ldlm_res_id *res = &info->mti_res_id;
	struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
	union ldlm_policy_data *policy = &info->mti_policy;
	__u64 dlmflags = LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB;
	int rc;

	/*
	 * Finish res_id initializing by name hash marking part of
	 * directory which is taking modification.
	 */
	LASSERT(lh->mlh_pdo_hash != 0);
	fid_build_pdo_res_name(mdt_object_fid(obj), lh->mlh_pdo_hash, res);
	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = ibits;
	if (cos_incompat &&
	    (lh->mlh_reg_mode == LCK_PW || lh->mlh_reg_mode == LCK_EX))
		dlmflags |= LDLM_FL_COS_INCOMPAT;
	/*
	 * Use LDLM_FL_LOCAL_ONLY for this lock. We do not know yet if it is
	 * going to be sent to client. If it is - mdt_intent_policy() path will
	 * fix it up and turn FL_LOCAL flag off.
	 */
	rc = mdt_fid_lock(info->mti_env, ns, &lh->mlh_reg_lh, lh->mlh_reg_mode,
			  policy, res, dlmflags,
			  &info->mti_exp->exp_handle.h_cookie);
	return rc;
}

/**
 * Get BFL lock for rename or migrate process.
 **/
static int mdt_rename_lock(struct mdt_thread_info *info,
			   struct lustre_handle *lh)
{
	int	rc;

	ENTRY;
	if (mdt_seq_site(info->mti_mdt)->ss_node_id != 0) {
		struct lu_fid *fid = &info->mti_tmp_fid1;
		struct mdt_object *obj;

		/* XXX, right now, it has to use object API to
		 * enqueue lock cross MDT, so it will enqueue
		 * rename lock(with LUSTRE_BFL_FID) by root object
		 */
		lu_root_fid(fid);
		obj = mdt_object_find(info->mti_env, info->mti_mdt, fid);
		if (IS_ERR(obj))
			RETURN(PTR_ERR(obj));

		rc = mdt_remote_object_lock(info, obj,
					    &LUSTRE_BFL_FID, lh,
					    LCK_EX,
					    MDS_INODELOCK_UPDATE, false);
		mdt_object_put(info->mti_env, obj);
	} else {
		struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
		union ldlm_policy_data *policy = &info->mti_policy;
		struct ldlm_res_id *res_id = &info->mti_res_id;
		__u64 flags = 0;

		fid_build_reg_res_name(&LUSTRE_BFL_FID, res_id);
		memset(policy, 0, sizeof(*policy));
		policy->l_inodebits.bits = MDS_INODELOCK_UPDATE;
		flags = LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB;
		rc = ldlm_cli_enqueue_local(info->mti_env, ns, res_id,
					    LDLM_IBITS, policy, LCK_EX, &flags,
					    ldlm_blocking_ast,
					    ldlm_completion_ast, NULL, NULL, 0,
					    LVB_T_NONE,
					    &info->mti_exp->exp_handle.h_cookie,
					    lh);
		RETURN(rc);
	}
	RETURN(rc);
}

static void mdt_rename_unlock(struct lustre_handle *lh)
{
	ENTRY;
	LASSERT(lustre_handle_is_used(lh));
	/* Cancel the single rename lock right away */
	ldlm_lock_decref_and_cancel(lh, LCK_EX);
	EXIT;
}

static struct mdt_object *mdt_parent_find_check(struct mdt_thread_info *info,
						const struct lu_fid *fid,
						int idx)
{
	struct mdt_object *dir;
	int rc;

	ENTRY;
	dir = mdt_object_find(info->mti_env, info->mti_mdt, fid);
	if (IS_ERR(dir))
		RETURN(dir);

	/* check early, the real version will be saved after locking */
	rc = mdt_version_get_check(info, dir, idx);
	if (rc)
		GOTO(out_put, rc);

	if (!mdt_object_exists(dir))
		GOTO(out_put, rc = -ENOENT);

	if (!S_ISDIR(lu_object_attr(&dir->mot_obj)))
		GOTO(out_put, rc = -ENOTDIR);

	RETURN(dir);
out_put:
	mdt_object_put(info->mti_env, dir);
	return ERR_PTR(rc);
}

/*
 * in case obj is remote obj on its parent, revoke LOOKUP lock,
 * herein we don't really check it, just do revoke.
 */
int mdt_revoke_remote_lookup_lock(struct mdt_thread_info *info,
				  struct mdt_object *pobj,
				  struct mdt_object *obj)
{
	struct mdt_lock_handle *lh = &info->mti_lh[MDT_LH_LOCAL];
	int rc;

	mdt_lock_handle_init(lh);
	mdt_lock_reg_init(lh, LCK_EX);

	if (mdt_object_remote(pobj)) {
		/* don't bother to check if pobj and obj are on the same MDT. */
		rc = mdt_remote_object_lock(info, pobj, mdt_object_fid(obj),
					    &lh->mlh_rreg_lh, LCK_EX,
					    MDS_INODELOCK_LOOKUP, false);
	} else if (mdt_object_remote(obj)) {
		struct ldlm_res_id *res = &info->mti_res_id;
		union ldlm_policy_data *policy = &info->mti_policy;
		__u64 dlmflags = LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB |
				 LDLM_FL_COS_INCOMPAT;

		fid_build_reg_res_name(mdt_object_fid(obj), res);
		memset(policy, 0, sizeof(*policy));
		policy->l_inodebits.bits = MDS_INODELOCK_LOOKUP;
		rc = mdt_fid_lock(info->mti_env, info->mti_mdt->mdt_namespace,
				  &lh->mlh_reg_lh, LCK_EX, policy, res,
				  dlmflags, NULL);
	} else {
		/* do nothing if both are local */
		return 0;
	}

	if (rc != ELDLM_OK)
		return rc;

	/*
	 * TODO, currently we don't save this lock because there is no place to
	 * hold this lock handle, but to avoid race we need to save this lock.
	 */
	mdt_object_unlock(info, NULL, lh, 1);

	return 0;
}

/*
 * operation may takes locks of linkea, or directory stripes, group them in
 * different list.
 */
struct mdt_sub_lock {
	struct mdt_object *msl_obj;
	struct mdt_lock_handle msl_lh;
	struct list_head msl_linkage;
};

static void mdt_unlock_list(struct mdt_thread_info *info,
			    struct list_head *list, int decref)
{
	struct mdt_sub_lock *msl;
	struct mdt_sub_lock *tmp;

	list_for_each_entry_safe(msl, tmp, list, msl_linkage) {
		mdt_object_unlock_put(info, msl->msl_obj, &msl->msl_lh, decref);
		list_del(&msl->msl_linkage);
		OBD_FREE_PTR(msl);
	}
}

static inline void mdt_migrate_object_unlock(struct mdt_thread_info *info,
					     struct mdt_object *obj,
					     struct mdt_lock_handle *lh,
					     struct ldlm_enqueue_info *einfo,
					     struct list_head *slave_locks,
					     int decref)
{
	if (mdt_object_remote(obj)) {
		mdt_unlock_list(info, slave_locks, decref);
		mdt_object_unlock(info, obj, lh, decref);
	} else {
		mdt_reint_striped_unlock(info, obj, lh, einfo, decref);
	}
}

/*
 * lock parents of links, and also check whether total locks don't exceed
 * RS_MAX_LOCKS.
 *
 * \retval	0 on success, and locks can be saved in ptlrpc_reply_stat
 * \retval	1 on success, but total lock count may exceed RS_MAX_LOCKS
 * \retval	-ev negative errno upon error
 */
static int mdt_link_parents_lock(struct mdt_thread_info *info,
				 struct mdt_object *pobj,
				 const struct md_attr *ma,
				 struct mdt_object *obj,
				 struct mdt_lock_handle *lhp,
				 struct ldlm_enqueue_info *peinfo,
				 struct list_head *parent_slave_locks,
				 struct list_head *link_locks)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct lu_buf *buf = &info->mti_big_buf;
	struct lu_name *lname = &info->mti_name;
	struct linkea_data ldata = { NULL };
	bool blocked = false;
	int local_lnkp_cnt = 0;
	int rc;

	ENTRY;
	if (S_ISDIR(lu_object_attr(&obj->mot_obj)))
		RETURN(0);

	buf = lu_buf_check_and_alloc(buf, MAX_LINKEA_SIZE);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);

	ldata.ld_buf = buf;
	rc = mdt_links_read(info, obj, &ldata);
	if (rc) {
		if (rc == -ENOENT || rc == -ENODATA)
			rc = 0;
		RETURN(rc);
	}

	for (linkea_first_entry(&ldata); ldata.ld_lee && !rc;
	     linkea_next_entry(&ldata)) {
		struct mdt_object *lnkp;
		struct mdt_sub_lock *msl;
		struct lu_fid fid;
		__u64 ibits;

		linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen, lname,
				    &fid);

		/* check if it's also linked to parent */
		if (lu_fid_eq(mdt_object_fid(pobj), &fid)) {
			CDEBUG(D_INFO, "skip parent "DFID", reovke "DNAME"\n",
			       PFID(&fid), PNAME(lname));
			/* in case link is remote object, revoke LOOKUP lock */
			rc = mdt_revoke_remote_lookup_lock(info, pobj, obj);
			continue;
		}

		lnkp = NULL;

		/* check if it's linked to a stripe of parent */
		if (ma->ma_valid & MA_LMV) {
			struct lmv_mds_md_v1 *lmv = &ma->ma_lmv->lmv_md_v1;
			struct lu_fid *stripe_fid = &info->mti_tmp_fid1;
			int j = 0;

			for (; j < le32_to_cpu(lmv->lmv_stripe_count); j++) {
				fid_le_to_cpu(stripe_fid,
					      &lmv->lmv_stripe_fids[j]);
				if (lu_fid_eq(stripe_fid, &fid)) {
					CDEBUG(D_INFO, "skip stripe "DFID
					       ", reovke "DNAME"\n",
					       PFID(&fid), PNAME(lname));
					lnkp = mdt_object_find(info->mti_env,
							       mdt, &fid);
					if (IS_ERR(lnkp))
						GOTO(out, rc = PTR_ERR(lnkp));
					break;
				}
			}

			if (lnkp) {
				rc = mdt_revoke_remote_lookup_lock(info, lnkp,
								   obj);
				mdt_object_put(info->mti_env, lnkp);
				continue;
			}
		}

		/* Check if it's already locked */
		list_for_each_entry(msl, link_locks, msl_linkage) {
			if (lu_fid_eq(mdt_object_fid(msl->msl_obj), &fid)) {
				CDEBUG(D_INFO,
				       DFID" was locked, revoke "DNAME"\n",
				       PFID(&fid), PNAME(lname));
				lnkp = msl->msl_obj;
				break;
			}
		}

		if (lnkp) {
			rc = mdt_revoke_remote_lookup_lock(info, lnkp, obj);
			continue;
		}

		CDEBUG(D_INFO, "lock "DFID":"DNAME"\n",
		       PFID(&fid), PNAME(lname));

		lnkp = mdt_object_find(info->mti_env, mdt, &fid);
		if (IS_ERR(lnkp)) {
			CWARN("%s: cannot find obj "DFID": %ld\n",
			      mdt_obd_name(mdt), PFID(&fid), PTR_ERR(lnkp));
			continue;
		}

		if (!mdt_object_exists(lnkp)) {
			CDEBUG(D_INFO, DFID" doesn't exist, skip "DNAME"\n",
			      PFID(&fid), PNAME(lname));
			mdt_object_put(info->mti_env, lnkp);
			continue;
		}

		if (!mdt_object_remote(lnkp))
			local_lnkp_cnt++;

		OBD_ALLOC_PTR(msl);
		if (msl == NULL)
			GOTO(out, rc = -ENOMEM);

		/*
		 * we can't follow parent-child lock order like other MD
		 * operations, use lock_try here to avoid deadlock, if the lock
		 * cannot be taken, drop all locks taken, revoke the blocked
		 * one, and continue processing the remaining entries, and in
		 * the end of the loop restart from beginning.
		 */
		mdt_lock_pdo_init(&msl->msl_lh, LCK_PW, lname);
		ibits = 0;
		rc = mdt_object_lock_try(info, lnkp, &msl->msl_lh, &ibits,
					 MDS_INODELOCK_UPDATE, true);
		if (!(ibits & MDS_INODELOCK_UPDATE)) {

			CDEBUG(D_INFO, "busy lock on "DFID" "DNAME"\n",
			       PFID(&fid), PNAME(lname));

			mdt_unlock_list(info, link_locks, 1);
			/* also unlock parent locks to avoid deadlock */
			if (!blocked)
				mdt_migrate_object_unlock(info, pobj, lhp,
							  peinfo,
							  parent_slave_locks,
							  1);

			blocked = true;

			mdt_lock_pdo_init(&msl->msl_lh, LCK_PW, lname);
			rc = mdt_object_lock(info, lnkp, &msl->msl_lh,
					     MDS_INODELOCK_UPDATE);
			if (rc) {
				mdt_object_put(info->mti_env, lnkp);
				OBD_FREE_PTR(msl);
				GOTO(out, rc);
			}

			if (mdt_object_remote(lnkp)) {
				struct ldlm_lock *lock;

				/*
				 * for remote object, set lock cb_atomic,
				 * so lock can be released in blocking_ast()
				 * immediately, then the next lock_try will
				 * have better chance of success.
				 */
				lock = ldlm_handle2lock(
						&msl->msl_lh.mlh_rreg_lh);
				LASSERT(lock != NULL);
				lock_res_and_lock(lock);
				ldlm_set_atomic_cb(lock);
				unlock_res_and_lock(lock);
				LDLM_LOCK_PUT(lock);
			}

			mdt_object_unlock_put(info, lnkp, &msl->msl_lh, 1);
			OBD_FREE_PTR(msl);
			continue;
		}

		INIT_LIST_HEAD(&msl->msl_linkage);
		msl->msl_obj = lnkp;
		list_add_tail(&msl->msl_linkage, link_locks);

		rc = mdt_revoke_remote_lookup_lock(info, lnkp, obj);
	}

	if (blocked)
		GOTO(out, rc = -EBUSY);

	EXIT;
out:
	if (rc) {
		mdt_unlock_list(info, link_locks, rc);
	} else if (local_lnkp_cnt > RS_MAX_LOCKS - 5) {
		CDEBUG(D_INFO, "Too many links (%d), sync operations\n",
		       local_lnkp_cnt);
		/*
		 * parent may have 3 local objects: master object and 2 stripes
		 * (if it's being migrated too); source may have 1 local objects
		 * as regular file; target has 1 local object.
		 * Note, source may have 2 local locks if it is directory but it
		 * can't have hardlinks, so it is not considered here.
		 */
		rc = 1;
	}
	return rc;
}

static int mdt_lock_remote_slaves(struct mdt_thread_info *info,
				  struct mdt_object *obj,
				  const struct md_attr *ma,
				  struct list_head *slave_locks)
{
	struct mdt_device *mdt = info->mti_mdt;
	const struct lmv_mds_md_v1 *lmv = &ma->ma_lmv->lmv_md_v1;
	struct lu_fid *fid = &info->mti_tmp_fid1;
	struct mdt_object *slave;
	struct mdt_sub_lock *msl;
	int i;
	int rc;

	ENTRY;
	LASSERT(mdt_object_remote(obj));
	LASSERT(ma->ma_valid & MA_LMV);
	LASSERT(lmv);

	if (!lmv_is_sane(lmv))
		RETURN(-EINVAL);

	for (i = 0; i < le32_to_cpu(lmv->lmv_stripe_count); i++) {
		fid_le_to_cpu(fid, &lmv->lmv_stripe_fids[i]);

		if (!fid_is_sane(fid))
			continue;

		slave = mdt_object_find(info->mti_env, mdt, fid);
		if (IS_ERR(slave))
			GOTO(out, rc = PTR_ERR(slave));

		OBD_ALLOC_PTR(msl);
		if (!msl) {
			mdt_object_put(info->mti_env, slave);
			GOTO(out, rc = -ENOMEM);
		}

		mdt_lock_reg_init(&msl->msl_lh, LCK_EX);
		rc = mdt_reint_object_lock(info, slave, &msl->msl_lh,
					   MDS_INODELOCK_UPDATE, true);
		if (rc) {
			OBD_FREE_PTR(msl);
			mdt_object_put(info->mti_env, slave);
			GOTO(out, rc);
		}

		INIT_LIST_HEAD(&msl->msl_linkage);
		msl->msl_obj = slave;
		list_add_tail(&msl->msl_linkage, slave_locks);
	}
	EXIT;

out:
	if (rc)
		mdt_unlock_list(info, slave_locks, rc);
	return rc;
}

/* lock parent and its stripes */
static int mdt_migrate_parent_lock(struct mdt_thread_info *info,
				   struct mdt_object *obj,
				   const struct md_attr *ma,
				   struct mdt_lock_handle *lh,
				   struct ldlm_enqueue_info *einfo,
				   struct list_head *slave_locks)
{
	int rc;

	if (mdt_object_remote(obj)) {
		rc = mdt_remote_object_lock(info, obj, mdt_object_fid(obj),
					    &lh->mlh_rreg_lh, LCK_PW,
					    MDS_INODELOCK_UPDATE, false);
		if (rc != ELDLM_OK)
			return rc;

		/*
		 * if obj is remote and striped, lock its stripes explicitly
		 * because it's not striped in LOD layer on this MDT.
		 */
		if (ma->ma_valid & MA_LMV) {
			rc = mdt_lock_remote_slaves(info, obj, ma, slave_locks);
			if (rc)
				mdt_object_unlock(info, obj, lh, rc);
		}
	} else {
		rc = mdt_reint_striped_lock(info, obj, lh, MDS_INODELOCK_UPDATE,
					    einfo, true);
	}

	return rc;
}

/*
 * in migration, object may be remote, and we need take full lock of it and its
 * stripes if it's directory, besides, object may be a remote object on its
 * parent, revoke its LOOKUP lock on where its parent is located.
 */
static int mdt_migrate_object_lock(struct mdt_thread_info *info,
				   struct mdt_object *pobj,
				   struct mdt_object *obj,
				   struct mdt_lock_handle *lh,
				   struct ldlm_enqueue_info *einfo,
				   struct list_head *slave_locks)
{
	int rc;

	if (mdt_object_remote(obj)) {
		rc = mdt_revoke_remote_lookup_lock(info, pobj, obj);
		if (rc)
			return rc;

		rc = mdt_remote_object_lock(info, obj, mdt_object_fid(obj),
					    &lh->mlh_rreg_lh, LCK_EX,
					    MDS_INODELOCK_FULL, false);
		if (rc != ELDLM_OK)
			return rc;

		/*
		 * if obj is remote and striped, lock its stripes explicitly
		 * because it's not striped in LOD layer on this MDT.
		 */
		if (S_ISDIR(lu_object_attr(&obj->mot_obj))) {
			struct md_attr *ma = &info->mti_attr;

			rc = mdt_stripe_get(info, obj, ma, XATTR_NAME_LMV);
			if (rc) {
				mdt_object_unlock(info, obj, lh, rc);
				return rc;
			}

			if (ma->ma_valid & MA_LMV) {
				rc = mdt_lock_remote_slaves(info, obj, ma,
							    slave_locks);
				if (rc)
					mdt_object_unlock(info, obj, lh, rc);
			}
		}
	} else {
		if (mdt_object_remote(pobj)) {
			rc = mdt_revoke_remote_lookup_lock(info, pobj, obj);
			if (rc)
				return rc;
		}

		rc = mdt_reint_striped_lock(info, obj, lh, MDS_INODELOCK_FULL,
					    einfo, true);
	}

	return rc;
}

/*
 * lookup source by name, if parent is striped directory, we need to find the
 * corresponding stripe where source is located, and then lookup there.
 *
 * besides, if parent is migrating too, and file is already in target stripe,
 * this should be a redo of 'lfs migrate' on client side.
 */
static int mdt_migrate_lookup(struct mdt_thread_info *info,
			      struct mdt_object *pobj,
			      const struct md_attr *ma,
			      const struct lu_name *lname,
			      struct mdt_object **spobj,
			      struct mdt_object **sobj)
{
	const struct lu_env *env = info->mti_env;
	struct lu_fid *fid = &info->mti_tmp_fid1;
	struct mdt_object *stripe;
	int rc;

	if (ma->ma_valid & MA_LMV) {
		/* if parent is striped, lookup on corresponding stripe */
		struct lmv_mds_md_v1 *lmv = &ma->ma_lmv->lmv_md_v1;

		if (!lmv_is_sane(lmv))
			return -EBADF;

		rc = lmv_name_to_stripe_index_old(lmv, lname->ln_name,
						  lname->ln_namelen);
		if (rc < 0)
			return rc;

		fid_le_to_cpu(fid, &lmv->lmv_stripe_fids[rc]);

		stripe = mdt_object_find(env, info->mti_mdt, fid);
		if (IS_ERR(stripe))
			return PTR_ERR(stripe);

		fid_zero(fid);
		rc = mdo_lookup(env, mdt_object_child(stripe), lname, fid,
				&info->mti_spec);
		if (rc == -ENOENT && lmv_is_layout_changing(lmv)) {
			/*
			 * if parent layout is changeing, and lookup child
			 * failed on source stripe, lookup again on target
			 * stripe, if it exists, it means previous migration
			 * was interrupted, and current file was migrated
			 * already.
			 */
			mdt_object_put(env, stripe);

			rc = lmv_name_to_stripe_index(lmv, lname->ln_name,
						      lname->ln_namelen);
			if (rc < 0)
				return rc;

			fid_le_to_cpu(fid, &lmv->lmv_stripe_fids[rc]);

			stripe = mdt_object_find(env, info->mti_mdt, fid);
			if (IS_ERR(stripe))
				return PTR_ERR(stripe);

			fid_zero(fid);
			rc = mdo_lookup(env, mdt_object_child(stripe), lname,
					fid, &info->mti_spec);
			mdt_object_put(env, stripe);
			return rc ?: -EALREADY;
		} else if (rc) {
			mdt_object_put(env, stripe);
			return rc;
		}
	} else {
		fid_zero(fid);
		rc = mdo_lookup(env, mdt_object_child(pobj), lname, fid,
				&info->mti_spec);
		if (rc)
			return rc;

		stripe = pobj;
		mdt_object_get(env, stripe);
	}

	*spobj = stripe;

	*sobj = mdt_object_find(env, info->mti_mdt, fid);
	if (IS_ERR(*sobj)) {
		mdt_object_put(env, stripe);
		rc = PTR_ERR(*sobj);
		*spobj = NULL;
		*sobj = NULL;
	}

	return rc;
}

/* end lease and close file for regular file */
static int mdd_migrate_close(struct mdt_thread_info *info,
			     struct mdt_object *obj)
{
	struct close_data *data;
	struct mdt_body *repbody;
	struct ldlm_lock *lease;
	int rc;
	int rc2;

	rc = -EPROTO;
	if (!req_capsule_field_present(info->mti_pill, &RMF_MDT_EPOCH,
				      RCL_CLIENT) ||
	    !req_capsule_field_present(info->mti_pill, &RMF_CLOSE_DATA,
				      RCL_CLIENT))
		goto close;

	data = req_capsule_client_get(info->mti_pill, &RMF_CLOSE_DATA);
	if (!data)
		goto close;

	rc = -ESTALE;
	lease = ldlm_handle2lock(&data->cd_handle);
	if (!lease)
		goto close;

	/* check if the lease was already canceled */
	lock_res_and_lock(lease);
	rc = ldlm_is_cancel(lease);
	unlock_res_and_lock(lease);

	if (rc) {
		rc = -EAGAIN;
		LDLM_DEBUG(lease, DFID" lease broken",
			   PFID(mdt_object_fid(obj)));
	}

	/*
	 * cancel server side lease, client side counterpart should have been
	 * cancelled, it's okay to cancel it now as we've held mot_open_sem.
	 */
	ldlm_lock_cancel(lease);
	ldlm_reprocess_all(lease->l_resource,
			   lease->l_policy_data.l_inodebits.bits);
	LDLM_LOCK_PUT(lease);

close:
	rc2 = mdt_close_internal(info, mdt_info_req(info), NULL);
	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
	repbody->mbo_valid |= OBD_MD_CLOSE_INTENT_EXECED;

	return rc ?: rc2;
}

/*
 * migrate file in below steps:
 *  1. lock parent and its stripes
 *  2. lookup source by name
 *  3. lock parents of source links if source is not directory
 *  4. reject if source is in HSM
 *  5. take source open_sem and close file if source is regular file
 *  6. lock source and its stripes if it's directory
 *  7. lock target so subsequent change to it can trigger COS
 *  8. migrate file
 *  9. unlock above locks
 * 10. sync device if source has links
 */
int mdt_reint_migrate(struct mdt_thread_info *info,
		      struct mdt_lock_handle *unused)
{
	const struct lu_env *env = info->mti_env;
	struct mdt_device *mdt = info->mti_mdt;
	struct ptlrpc_request *req = mdt_info_req(info);
	struct mdt_reint_record *rr = &info->mti_rr;
	struct lu_ucred *uc = mdt_ucred(info);
	struct md_attr *ma = &info->mti_attr;
	struct ldlm_enqueue_info *peinfo = &info->mti_einfo[0];
	struct ldlm_enqueue_info *seinfo = &info->mti_einfo[1];
	struct mdt_object *pobj;
	struct mdt_object *spobj = NULL;
	struct mdt_object *sobj = NULL;
	struct mdt_object *tobj;
	struct lustre_handle rename_lh = { 0 };
	struct mdt_lock_handle *lhp;
	struct mdt_lock_handle *lhs;
	struct mdt_lock_handle *lht;
	LIST_HEAD(parent_slave_locks);
	LIST_HEAD(child_slave_locks);
	LIST_HEAD(link_locks);
	int lock_retries = 5;
	bool open_sem_locked = false;
	bool do_sync = false;
	int rc;

	ENTRY;
	CDEBUG(D_INODE, "migrate "DFID"/"DNAME" to "DFID"\n", PFID(rr->rr_fid1),
	       PNAME(&rr->rr_name), PFID(rr->rr_fid2));

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	if (!fid_is_md_operative(rr->rr_fid1) ||
	    !fid_is_md_operative(rr->rr_fid2))
		RETURN(-EPERM);

	/* don't allow migrate . or .. */
	if (lu_name_is_dot_or_dotdot(&rr->rr_name))
		RETURN(-EBUSY);

	if (!mdt->mdt_enable_remote_dir || !mdt->mdt_enable_dir_migration)
		RETURN(-EPERM);

	if (uc && !cap_raised(uc->uc_cap, CAP_SYS_ADMIN) &&
	    uc->uc_gid != mdt->mdt_enable_remote_dir_gid &&
	    mdt->mdt_enable_remote_dir_gid != -1)
		RETURN(-EPERM);

	/*
	 * Note: do not enqueue rename lock for replay request, because
	 * if other MDT holds rename lock, but being blocked to wait for
	 * this MDT to finish its recovery, and the failover MDT can not
	 * get rename lock, which will cause deadlock.
	 *
	 * req is NULL if this is called by directory auto-split.
	 */
	if (req && !req_is_replay(req)) {
		rc = mdt_rename_lock(info, &rename_lh);
		if (rc != 0) {
			CERROR("%s: can't lock FS for rename: rc = %d\n",
			       mdt_obd_name(info->mti_mdt), rc);
			RETURN(rc);
		}
	}

	/* pobj is master object of parent */
	pobj = mdt_object_find(env, mdt, rr->rr_fid1);
	if (IS_ERR(pobj))
		GOTO(unlock_rename, rc = PTR_ERR(pobj));

	if (req) {
		rc = mdt_version_get_check(info, pobj, 0);
		if (rc)
			GOTO(put_parent, rc);
	}

	if (!mdt_object_exists(pobj))
		GOTO(put_parent, rc = -ENOENT);

	if (!S_ISDIR(lu_object_attr(&pobj->mot_obj)))
		GOTO(put_parent, rc = -ENOTDIR);

	rc = mdt_stripe_get(info, pobj, ma, XATTR_NAME_LMV);
	if (rc)
		GOTO(put_parent, rc);

lock_parent:
	/* lock parent object */
	lhp = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_reg_init(lhp, LCK_PW);
	rc = mdt_migrate_parent_lock(info, pobj, ma, lhp, peinfo,
				     &parent_slave_locks);
	if (rc)
		GOTO(put_parent, rc);

	/*
	 * spobj is the corresponding stripe against name if pobj is striped
	 * directory, which is the real parent, and no need to lock, because
	 * we've taken full lock of pobj.
	 */
	rc = mdt_migrate_lookup(info, pobj, ma, &rr->rr_name, &spobj, &sobj);
	if (rc)
		GOTO(unlock_parent, rc);

	/* lock parents of source links, and revoke LOOKUP lock of links */
	rc = mdt_link_parents_lock(info, pobj, ma, sobj, lhp, peinfo,
				   &parent_slave_locks, &link_locks);
	if (rc == -EBUSY && lock_retries-- > 0) {
		mdt_object_put(env, sobj);
		mdt_object_put(env, spobj);
		goto lock_parent;
	}

	if (rc < 0)
		GOTO(put_source, rc);

	/*
	 * RS_MAX_LOCKS is the limit of number of locks that can be saved along
	 * with one request, if total lock count exceeds this limit, we will
	 * drop all locks after migration, and synchronous device in the end.
	 */
	do_sync = rc;

	/* TODO: DoM migration is not supported, migrate dirent only */
	if (S_ISREG(lu_object_attr(&sobj->mot_obj))) {
		rc = mdt_stripe_get(info, sobj, ma, XATTR_NAME_LOV);
		if (rc)
			GOTO(unlock_links, rc);

		if (ma->ma_valid & MA_LOV && mdt_lmm_dom_stripesize(ma->ma_lmm))
			info->mti_spec.sp_migrate_nsonly = 1;
	} else if (S_ISDIR(lu_object_attr(&sobj->mot_obj))) {
		rc = mdt_stripe_get(info, sobj, ma, XATTR_NAME_LMV);
		if (rc)
			GOTO(unlock_links, rc);

		/* race with restripe/auto-split? */
		if ((ma->ma_valid & MA_LMV) &&
		    lmv_is_restriping(&ma->ma_lmv->lmv_md_v1))
			GOTO(unlock_links, rc = -EBUSY);
	}

	/* if migration HSM is allowed */
	if (!mdt->mdt_opts.mo_migrate_hsm_allowed) {
		ma->ma_need = MA_HSM;
		ma->ma_valid = 0;
		rc = mdt_attr_get_complex(info, sobj, ma);
		if (rc)
			GOTO(unlock_links, rc);

		if ((ma->ma_valid & MA_HSM) && ma->ma_hsm.mh_flags != 0)
			GOTO(unlock_links, rc = -EOPNOTSUPP);
	}

	/* end lease and close file for regular file */
	if (info->mti_spec.sp_migrate_close) {
		/* try to hold open_sem so that nobody else can open the file */
		if (!down_write_trylock(&sobj->mot_open_sem)) {
			/* close anyway */
			mdd_migrate_close(info, sobj);
			GOTO(unlock_links, rc = -EBUSY);
		} else {
			open_sem_locked = true;
			rc = mdd_migrate_close(info, sobj);
			if (rc)
				GOTO(unlock_open_sem, rc);
		}
	}

	/* lock source */
	lhs = &info->mti_lh[MDT_LH_OLD];
	mdt_lock_reg_init(lhs, LCK_EX);
	rc = mdt_migrate_object_lock(info, spobj, sobj, lhs, seinfo,
				     &child_slave_locks);
	if (rc)
		GOTO(unlock_open_sem, rc);

	/* lock target */
	tobj = mdt_object_find(env, mdt, rr->rr_fid2);
	if (IS_ERR(tobj))
		GOTO(unlock_source, rc = PTR_ERR(tobj));

	lht = &info->mti_lh[MDT_LH_NEW];
	mdt_lock_reg_init(lht, LCK_EX);
	rc = mdt_reint_object_lock(info, tobj, lht, MDS_INODELOCK_FULL, true);
	if (rc)
		GOTO(put_target, rc);

	/* Don't do lookup sanity check. We know name doesn't exist. */
	info->mti_spec.sp_cr_lookup = 0;
	info->mti_spec.sp_feat = &dt_directory_features;

	rc = mdo_migrate(env, mdt_object_child(pobj),
			 mdt_object_child(sobj), &rr->rr_name,
			 mdt_object_child(tobj),
			 &info->mti_spec, ma);
	if (!rc)
		lprocfs_counter_incr(mdt->mdt_lu_dev.ld_obd->obd_md_stats,
				     LPROC_MDT_MIGRATE + LPROC_MD_LAST_OPC);
	EXIT;

	mdt_object_unlock(info, tobj, lht, rc);
put_target:
	mdt_object_put(env, tobj);
unlock_source:
	mdt_migrate_object_unlock(info, sobj, lhs, seinfo,
				  &child_slave_locks, rc);
unlock_open_sem:
	if (open_sem_locked)
		up_write(&sobj->mot_open_sem);
unlock_links:
	/* if we've got too many locks to save into RPC,
	 * then just commit before the locks are released
	 */
	if (!rc && do_sync)
		mdt_device_sync(env, mdt);
	mdt_unlock_list(info, &link_locks, do_sync ? 1 : rc);
put_source:
	mdt_object_put(env, sobj);
	mdt_object_put(env, spobj);
unlock_parent:
	mdt_migrate_object_unlock(info, pobj, lhp, peinfo,
				  &parent_slave_locks, rc);
put_parent:
	mdt_object_put(env, pobj);
unlock_rename:
	if (lustre_handle_is_used(&rename_lh))
		mdt_rename_unlock(&rename_lh);

	return rc;
}

static int mdt_object_lock_save(struct mdt_thread_info *info,
				struct mdt_object *dir,
				struct mdt_lock_handle *lh,
				int idx, bool cos_incompat)
{
	int rc;

	/* we lock the target dir if it is local */
	rc = mdt_reint_object_lock(info, dir, lh, MDS_INODELOCK_UPDATE,
				   cos_incompat);
	if (rc != 0)
		return rc;

	/* get and save correct version after locking */
	mdt_version_get_save(info, dir, idx);
	return 0;
}

/*
 * determine lock order of sobj and tobj
 *
 * there are two situations we need to lock tobj before sobj:
 * 1. sobj is child of tobj
 * 2. sobj and tobj are stripes of a directory, and stripe index of sobj is
 *    larger than that of tobj
 *
 * \retval	1 lock tobj before sobj
 * \retval	0 lock sobj before tobj
 * \retval	-ev negative errno upon error
 */
static int mdt_rename_determine_lock_order(struct mdt_thread_info *info,
					   struct mdt_object *sobj,
					   struct mdt_object *tobj)
{
	struct md_attr *ma = &info->mti_attr;
	struct lu_fid *spfid = &info->mti_tmp_fid1;
	struct lu_fid *tpfid = &info->mti_tmp_fid2;
	struct lmv_mds_md_v1 *lmv;
	__u32 sindex;
	__u32 tindex;
	int rc;

	/* sobj and tobj are the same */
	if (sobj == tobj)
		return 0;

	if (fid_is_root(mdt_object_fid(sobj)))
		return 0;

	if (fid_is_root(mdt_object_fid(tobj)))
		return 1;

	/* check whether sobj is child of tobj */
	rc = mdo_is_subdir(info->mti_env, mdt_object_child(sobj),
			   mdt_object_fid(tobj));
	if (rc < 0)
		return rc;

	if (rc == 1)
		return 1;

	/* check whether sobj and tobj are children of the same parent */
	rc = mdt_attr_get_pfid(info, sobj, spfid);
	if (rc)
		return rc;

	rc = mdt_attr_get_pfid(info, tobj, tpfid);
	if (rc)
		return rc;

	if (!lu_fid_eq(spfid, tpfid))
		return 0;

	/* check whether sobj and tobj are sibling stripes */
	rc = mdt_stripe_get(info, sobj, ma, XATTR_NAME_LMV);
	if (rc)
		return rc;

	if (!(ma->ma_valid & MA_LMV))
		return 0;

	lmv = &ma->ma_lmv->lmv_md_v1;
	if (!(le32_to_cpu(lmv->lmv_magic) & LMV_MAGIC_STRIPE))
		return 0;
	sindex = le32_to_cpu(lmv->lmv_master_mdt_index);

	ma->ma_valid = 0;
	rc = mdt_stripe_get(info, tobj, ma, XATTR_NAME_LMV);
	if (rc)
		return rc;

	if (!(ma->ma_valid & MA_LMV))
		return -ENODATA;

	lmv = &ma->ma_lmv->lmv_md_v1;
	if (!(le32_to_cpu(lmv->lmv_magic) & LMV_MAGIC_STRIPE))
		return -EINVAL;
	tindex = le32_to_cpu(lmv->lmv_master_mdt_index);

	/* check stripe index of sobj and tobj */
	if (sindex == tindex)
		return -EINVAL;

	return sindex < tindex ? 0 : 1;
}

/*
 * lock rename source object.
 *
 * Both source and source parent may be remote, and source may be a remote
 * object on source parent, to avoid overriding lock handle, store remote
 * LOOKUP lock separately in @lhr.
 *
 * \retval	0 on success
 * \retval	-ev negative errno upon error
 */
static int mdt_rename_source_lock(struct mdt_thread_info *info,
				  struct mdt_object *parent,
				  struct mdt_object *child,
				  struct mdt_lock_handle *lhc,
				  struct mdt_lock_handle *lhr,
				  __u64 ibits,
				  bool cos_incompat)
{
	int rc;

	rc = mdt_is_remote_object(info, parent, child);
	if (rc < 0)
		return rc;

	if (rc) {
		/* enqueue remote LOOKUP lock from the parent MDT */
		__u64 rmt_ibits = MDS_INODELOCK_LOOKUP;

		if (mdt_object_remote(parent)) {
			rc = mdt_remote_object_lock(info, parent,
						    mdt_object_fid(child),
						    &lhr->mlh_rreg_lh,
						    lhr->mlh_rreg_mode,
						    rmt_ibits, false);
			if (rc != ELDLM_OK)
				return rc;
		} else {
			LASSERT(mdt_object_remote(child));
			rc = mdt_object_local_lock(info, child, lhr,
						   &rmt_ibits, 0, true);
			if (rc < 0)
				return rc;
		}

		ibits &= ~MDS_INODELOCK_LOOKUP;
	}

	if (mdt_object_remote(child)) {
		rc = mdt_remote_object_lock(info, child, mdt_object_fid(child),
					    &lhc->mlh_rreg_lh,
					    lhc->mlh_rreg_mode,
					    ibits, false);
		if (rc == ELDLM_OK)
			rc = 0;
	} else {
		rc = mdt_reint_object_lock(info, child, lhc, ibits,
					   cos_incompat);
	}

	if (!rc)
		mdt_object_unlock(info, child, lhr, rc);

	return rc;
}

/*
 * VBR: rename versions in reply: 0 - srcdir parent; 1 - tgtdir parent;
 * 2 - srcdir child; 3 - tgtdir child.
 * Update on disk version of srcdir child.
 */
static int mdt_reint_rename(struct mdt_thread_info *info,
			    struct mdt_lock_handle *unused)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct md_attr *ma = &info->mti_attr;
	struct ptlrpc_request *req = mdt_info_req(info);
	struct mdt_object *msrcdir = NULL;
	struct mdt_object *mtgtdir = NULL;
	struct mdt_object *mold;
	struct mdt_object *mnew = NULL;
	struct lustre_handle rename_lh = { 0 };
	struct mdt_lock_handle *lh_srcdirp;
	struct mdt_lock_handle *lh_tgtdirp;
	struct mdt_lock_handle *lh_oldp = NULL;
	struct mdt_lock_handle *lh_rmt = NULL;
	struct mdt_lock_handle *lh_newp = NULL;
	struct lu_fid *old_fid = &info->mti_tmp_fid1;
	struct lu_fid *new_fid = &info->mti_tmp_fid2;
	__u64 lock_ibits;
	bool reverse = false, discard = false;
	bool cos_incompat;
	ktime_t kstart = ktime_get();
	int rc;

	ENTRY;
	DEBUG_REQ(D_INODE, req, "rename "DFID"/"DNAME" to "DFID"/"DNAME,
		  PFID(rr->rr_fid1), PNAME(&rr->rr_name),
		  PFID(rr->rr_fid2), PNAME(&rr->rr_tgt_name));

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	if (!fid_is_md_operative(rr->rr_fid1) ||
	    !fid_is_md_operative(rr->rr_fid2))
		RETURN(-EPERM);

	/* find both parents. */
	msrcdir = mdt_parent_find_check(info, rr->rr_fid1, 0);
	if (IS_ERR(msrcdir))
		RETURN(PTR_ERR(msrcdir));

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME3, 5);

	if (lu_fid_eq(rr->rr_fid1, rr->rr_fid2)) {
		mtgtdir = msrcdir;
		mdt_object_get(info->mti_env, mtgtdir);
	} else {
		mtgtdir = mdt_parent_find_check(info, rr->rr_fid2, 1);
		if (IS_ERR(mtgtdir))
			GOTO(out_put_srcdir, rc = PTR_ERR(mtgtdir));
	}

	/*
	 * Note: do not enqueue rename lock for replay request, because
	 * if other MDT holds rename lock, but being blocked to wait for
	 * this MDT to finish its recovery, and the failover MDT can not
	 * get rename lock, which will cause deadlock.
	 */
	if (!req_is_replay(req)) {
		/*
		 * Normally rename RPC is handled on the MDT with the target
		 * directory (if target exists, it's on the MDT with the
		 * target), if the source directory is remote, it's a hint that
		 * source is remote too (this may not be true, but it won't
		 * cause any issue), return -EXDEV early to avoid taking
		 * rename_lock.
		 */
		if (!mdt->mdt_enable_remote_rename &&
		    mdt_object_remote(msrcdir))
			GOTO(out_put_tgtdir, rc = -EXDEV);

		/* This might be further relaxed in the future for regular file
		 * renames in different source and target parents. Start with
		 * only same-directory renames for simplicity and because this
		 * is by far the most the common use case.
		 */
		if (msrcdir != mtgtdir) {
			rc = mdt_rename_lock(info, &rename_lh);
			if (rc != 0) {
				CERROR("%s: cannot lock for rename: rc = %d\n",
				       mdt_obd_name(mdt), rc);
				GOTO(out_put_tgtdir, rc);
			}
		} else {
			CDEBUG(D_INFO, "%s: samedir rename "DFID"/"DNAME"\n",
			       mdt_obd_name(mdt), PFID(rr->rr_fid1),
			       PNAME(&rr->rr_name));
		}
	}

	rc = mdt_rename_determine_lock_order(info, msrcdir, mtgtdir);
	if (rc < 0)
		GOTO(out_unlock_rename, rc);

	reverse = rc;

	/* source needs to be looked up after locking source parent, otherwise
	 * this rename may race with unlink source, and cause rename hang, see
	 * sanityn.sh 55b, so check parents first, if later we found source is
	 * remote, relock parents.
	 */
	cos_incompat = (mdt_object_remote(msrcdir) ||
			mdt_object_remote(mtgtdir));

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME4, 5);

	/* lock parents in the proper order. */
	lh_srcdirp = &info->mti_lh[MDT_LH_PARENT];
	lh_tgtdirp = &info->mti_lh[MDT_LH_CHILD];

	OBD_RACE(OBD_FAIL_MDS_REINT_OPEN);
	OBD_RACE(OBD_FAIL_MDS_REINT_OPEN2);
relock:
	mdt_lock_pdo_init(lh_srcdirp, LCK_PW, &rr->rr_name);
	mdt_lock_pdo_init(lh_tgtdirp, LCK_PW, &rr->rr_tgt_name);

	if (reverse) {
		rc = mdt_object_lock_save(info, mtgtdir, lh_tgtdirp, 1,
					  cos_incompat);
		if (rc)
			GOTO(out_unlock_rename, rc);

		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME, 5);

		rc = mdt_object_lock_save(info, msrcdir, lh_srcdirp, 0,
					  cos_incompat);
		if (rc != 0) {
			mdt_object_unlock(info, mtgtdir, lh_tgtdirp, rc);
			GOTO(out_unlock_rename, rc);
		}
	} else {
		rc = mdt_object_lock_save(info, msrcdir, lh_srcdirp, 0,
					  cos_incompat);
		if (rc)
			GOTO(out_unlock_rename, rc);

		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME, 5);

		if (mtgtdir != msrcdir) {
			rc = mdt_object_lock_save(info, mtgtdir, lh_tgtdirp, 1,
						  cos_incompat);
		} else if (!mdt_object_remote(mtgtdir) &&
			   lh_srcdirp->mlh_pdo_hash !=
			   lh_tgtdirp->mlh_pdo_hash) {
			rc = mdt_pdir_hash_lock(info, lh_tgtdirp, mtgtdir,
						MDS_INODELOCK_UPDATE,
						cos_incompat);
			OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_PDO_LOCK2, 10);
		}
		if (rc != 0) {
			mdt_object_unlock(info, msrcdir, lh_srcdirp, rc);
			GOTO(out_unlock_rename, rc);
		}
	}

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME4, 5);
	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME2, 5);

	/* find mold object. */
	fid_zero(old_fid);
	rc = mdt_lookup_version_check(info, msrcdir, &rr->rr_name, old_fid, 2);
	if (rc != 0)
		GOTO(out_unlock_parents, rc);

	if (lu_fid_eq(old_fid, rr->rr_fid1) || lu_fid_eq(old_fid, rr->rr_fid2))
		GOTO(out_unlock_parents, rc = -EINVAL);

	if (!fid_is_md_operative(old_fid))
		GOTO(out_unlock_parents, rc = -EPERM);

	mold = mdt_object_find(info->mti_env, info->mti_mdt, old_fid);
	if (IS_ERR(mold))
		GOTO(out_unlock_parents, rc = PTR_ERR(mold));

	if (!mdt_object_exists(mold)) {
		LU_OBJECT_DEBUG(D_INODE, info->mti_env,
				&mold->mot_obj,
				"object does not exist");
		GOTO(out_put_old, rc = -ENOENT);
	}

	if (mdt_object_remote(mold) && !mdt->mdt_enable_remote_rename)
		GOTO(out_put_old, rc = -EXDEV);

	/* Check if @mtgtdir is subdir of @mold, before locking child
	 * to avoid reverse locking.
	 */
	if (mtgtdir != msrcdir) {
		rc = mdo_is_subdir(info->mti_env, mdt_object_child(mtgtdir),
				   old_fid);
		if (rc) {
			if (rc == 1)
				rc = -EINVAL;
			GOTO(out_put_old, rc);
		}
	}

	tgt_vbr_obj_set(info->mti_env, mdt_obj2dt(mold));
	/* save version after locking */
	mdt_version_get_save(info, mold, 2);

	if (!cos_incompat && mdt_object_remote(mold)) {
		cos_incompat = true;
		mdt_object_put(info->mti_env, mold);
		mdt_object_unlock(info, mtgtdir, lh_tgtdirp, -EAGAIN);
		mdt_object_unlock(info, msrcdir, lh_srcdirp, -EAGAIN);
		goto relock;
	}

	/* find mnew object:
	 * mnew target object may not exist now
	 * lookup with version checking
	 */
	fid_zero(new_fid);
	rc = mdt_lookup_version_check(info, mtgtdir, &rr->rr_tgt_name, new_fid,
				      3);
	if (rc == 0) {
		/* the new_fid should have been filled at this moment */
		if (lu_fid_eq(old_fid, new_fid))
			GOTO(out_put_old, rc);

		if (lu_fid_eq(new_fid, rr->rr_fid1) ||
		    lu_fid_eq(new_fid, rr->rr_fid2))
			GOTO(out_put_old, rc = -EINVAL);

		if (!fid_is_md_operative(new_fid))
			GOTO(out_put_old, rc = -EPERM);

		mnew = mdt_object_find(info->mti_env, info->mti_mdt, new_fid);
		if (IS_ERR(mnew))
			GOTO(out_put_old, rc = PTR_ERR(mnew));

		if (!mdt_object_exists(mnew)) {
			LU_OBJECT_DEBUG(D_INODE, info->mti_env,
					&mnew->mot_obj,
					"object does not exist");
			GOTO(out_put_new, rc = -ENOENT);
		}

		if (mdt_object_remote(mnew)) {
			struct mdt_body	 *repbody;

			/* Always send rename req to the target child MDT */
			repbody = req_capsule_server_get(info->mti_pill,
							 &RMF_MDT_BODY);
			LASSERT(repbody != NULL);
			repbody->mbo_fid1 = *new_fid;
			repbody->mbo_valid |= (OBD_MD_FLID | OBD_MD_MDS);
			GOTO(out_put_new, rc = -EXDEV);
		}
		/* Before locking the target dir, check we do not replace
		 * a dir with a non-dir, otherwise it may deadlock with
		 * link op which tries to create a link in this dir
		 * back to this non-dir.
		 */
		if (S_ISDIR(lu_object_attr(&mnew->mot_obj)) &&
		    !S_ISDIR(lu_object_attr(&mold->mot_obj)))
			GOTO(out_put_new, rc = -EISDIR);

		lh_oldp = &info->mti_lh[MDT_LH_OLD];
		lh_rmt = &info->mti_lh[MDT_LH_RMT];
		mdt_lock_reg_init(lh_oldp, LCK_EX);
		mdt_lock_reg_init(lh_rmt, LCK_EX);
		lock_ibits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_XATTR;
		rc = mdt_rename_source_lock(info, msrcdir, mold, lh_oldp,
					    lh_rmt, lock_ibits, cos_incompat);
		if (rc < 0)
			GOTO(out_put_new, rc);

		/* Check if @msrcdir is subdir of @mnew, before locking child
		 * to avoid reverse locking.
		 */
		if (mtgtdir != msrcdir) {
			rc = mdo_is_subdir(info->mti_env,
					   mdt_object_child(msrcdir), new_fid);
			if (rc) {
				if (rc == 1)
					rc = -EINVAL;
				GOTO(out_unlock_old, rc);
			}
		}

		/* We used to acquire MDS_INODELOCK_FULL here but we
		 * can't do this now because a running HSM restore on
		 * the rename onto victim will hold the layout
		 * lock. See LU-4002.
		 */

		lh_newp = &info->mti_lh[MDT_LH_NEW];
		mdt_lock_reg_init(lh_newp, LCK_EX);
		lock_ibits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE;
		if (mdt_object_remote(mtgtdir)) {
			rc = mdt_remote_object_lock(info, mtgtdir,
						    mdt_object_fid(mnew),
						    &lh_newp->mlh_rreg_lh,
						    lh_newp->mlh_rreg_mode,
						    MDS_INODELOCK_LOOKUP,
						    false);
			if (rc != ELDLM_OK)
				GOTO(out_unlock_old, rc);

			lock_ibits &= ~MDS_INODELOCK_LOOKUP;
		}
		rc = mdt_reint_object_lock(info, mnew, lh_newp, lock_ibits,
					   cos_incompat);
		if (rc != 0)
			GOTO(out_unlock_new, rc);

		/* get and save version after locking */
		mdt_version_get_save(info, mnew, 3);
	} else if (rc != -ENOENT) {
		GOTO(out_put_old, rc);
	} else {
		lh_oldp = &info->mti_lh[MDT_LH_OLD];
		lh_rmt = &info->mti_lh[MDT_LH_RMT];
		mdt_lock_reg_init(lh_oldp, LCK_EX);
		mdt_lock_reg_init(lh_rmt, LCK_EX);
		lock_ibits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_XATTR;
		rc = mdt_rename_source_lock(info, msrcdir, mold, lh_oldp,
					    lh_rmt, lock_ibits, cos_incompat);
		if (rc != 0)
			GOTO(out_put_old, rc);

		mdt_enoent_version_save(info, 3);
	}

	/* step 5: rename it */
	mdt_reint_init_ma(info, ma);

	mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
		       OBD_FAIL_MDS_REINT_RENAME_WRITE);

	if (mnew != NULL)
		mutex_lock(&mnew->mot_lov_mutex);

	rc = mdo_rename(info->mti_env, mdt_object_child(msrcdir),
			mdt_object_child(mtgtdir), old_fid, &rr->rr_name,
			mnew != NULL ? mdt_object_child(mnew) : NULL,
			&rr->rr_tgt_name, ma);

	if (mnew != NULL)
		mutex_unlock(&mnew->mot_lov_mutex);

	/* handle last link of tgt object */
	if (rc == 0) {
		mdt_counter_incr(req, LPROC_MDT_RENAME,
				 ktime_us_delta(ktime_get(), kstart));
		if (mnew) {
			mdt_handle_last_unlink(info, mnew, ma);
			discard = mdt_dom_check_for_discard(info, mnew);
		}
		mdt_rename_counter_tally(info, info->mti_mdt, req,
					 msrcdir, mtgtdir,
					 ktime_us_delta(ktime_get(), kstart));
	}

	EXIT;
out_unlock_new:
	if (mnew != NULL)
		mdt_object_unlock(info, mnew, lh_newp, rc);
out_unlock_old:
	mdt_object_unlock(info, NULL, lh_rmt, rc);
	mdt_object_unlock(info, mold, lh_oldp, rc);
out_put_new:
	if (mnew && !discard)
		mdt_object_put(info->mti_env, mnew);
out_put_old:
	mdt_object_put(info->mti_env, mold);
out_unlock_parents:
	mdt_object_unlock(info, mtgtdir, lh_tgtdirp, rc);
	mdt_object_unlock(info, msrcdir, lh_srcdirp, rc);
out_unlock_rename:
	if (lustre_handle_is_used(&rename_lh))
		mdt_rename_unlock(&rename_lh);
out_put_tgtdir:
	mdt_object_put(info->mti_env, mtgtdir);
out_put_srcdir:
	mdt_object_put(info->mti_env, msrcdir);

	/* The DoM discard can be done right in the place above where it is
	 * assigned, meanwhile it is done here after rename unlock due to
	 * compatibility with old clients, for them the discard blocks
	 * the main thread until completion. Check LU-11359 for details.
	 */
	if (discard) {
		mdt_dom_discard_data(info, mnew);
		mdt_object_put(info->mti_env, mnew);
	}
	OBD_RACE(OBD_FAIL_MDS_LINK_RENAME_RACE);
	return rc;
}

static int mdt_reint_resync(struct mdt_thread_info *info,
			    struct mdt_lock_handle *lhc)
{
	struct mdt_reint_record	*rr = &info->mti_rr;
	struct ptlrpc_request *req = mdt_info_req(info);
	struct md_attr *ma = &info->mti_attr;
	struct mdt_object *mo;
	struct ldlm_lock *lease;
	struct mdt_body *repbody;
	struct md_layout_change layout = { .mlc_mirror_id = rr->rr_mirror_id };
	bool lease_broken;
	int rc, rc2;

	ENTRY;
	DEBUG_REQ(D_INODE, req, DFID", FLR file resync", PFID(rr->rr_fid1));

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	mo = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(mo))
		GOTO(out, rc = PTR_ERR(mo));

	if (!mdt_object_exists(mo))
		GOTO(out_obj, rc = -ENOENT);

	if (!S_ISREG(lu_object_attr(&mo->mot_obj)))
		GOTO(out_obj, rc = -EINVAL);

	if (mdt_object_remote(mo))
		GOTO(out_obj, rc = -EREMOTE);

	lease = ldlm_handle2lock(rr->rr_lease_handle);
	if (lease == NULL)
		GOTO(out_obj, rc = -ESTALE);

	/* It's really necessary to grab open_sem and check if the lease lock
	 * has been lost. There would exist a concurrent writer coming in and
	 * generating some dirty data in memory cache, the writeback would fail
	 * after the layout version is increased by MDS_REINT_RESYNC RPC.
	 */
	if (!down_write_trylock(&mo->mot_open_sem))
		GOTO(out_put_lease, rc = -EBUSY);

	lock_res_and_lock(lease);
	lease_broken = ldlm_is_cancel(lease);
	unlock_res_and_lock(lease);
	if (lease_broken)
		GOTO(out_unlock, rc = -EBUSY);

	/* the file has yet opened by anyone else after we took the lease. */
	layout.mlc_opc = MD_LAYOUT_RESYNC;
	lhc = &info->mti_lh[MDT_LH_LOCAL];
	rc = mdt_layout_change(info, mo, lhc, &layout);
	if (rc)
		GOTO(out_unlock, rc);

	mdt_object_unlock(info, mo, lhc, 0);

	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;
	rc = mdt_attr_get_complex(info, mo, ma);
	if (rc != 0)
		GOTO(out_unlock, rc);

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
	mdt_pack_attr2body(info, repbody, &ma->ma_attr, mdt_object_fid(mo));

	EXIT;
out_unlock:
	up_write(&mo->mot_open_sem);
out_put_lease:
	LDLM_LOCK_PUT(lease);
out_obj:
	mdt_object_put(info->mti_env, mo);
out:
	mdt_client_compatibility(info);
	rc2 = mdt_fix_reply(info);
	if (rc == 0)
		rc = rc2;
	return rc;
}

struct mdt_reinter {
	int (*mr_handler)(struct mdt_thread_info *, struct mdt_lock_handle *);
	enum lprocfs_extra_opc mr_extra_opc;
};

static const struct mdt_reinter mdt_reinters[] = {
	[REINT_SETATTR]	= {
		.mr_handler = &mdt_reint_setattr,
		.mr_extra_opc = MDS_REINT_SETATTR,
	},
	[REINT_CREATE] = {
		.mr_handler = &mdt_reint_create,
		.mr_extra_opc = MDS_REINT_CREATE,
	},
	[REINT_LINK] = {
		.mr_handler = &mdt_reint_link,
		.mr_extra_opc = MDS_REINT_LINK,
	},
	[REINT_UNLINK] = {
		.mr_handler = &mdt_reint_unlink,
		.mr_extra_opc = MDS_REINT_UNLINK,
	},
	[REINT_RENAME] = {
		.mr_handler = &mdt_reint_rename,
		.mr_extra_opc = MDS_REINT_RENAME,
	},
	[REINT_OPEN] = {
		.mr_handler = &mdt_reint_open,
		.mr_extra_opc = MDS_REINT_OPEN,
	},
	[REINT_SETXATTR] = {
		.mr_handler = &mdt_reint_setxattr,
		.mr_extra_opc = MDS_REINT_SETXATTR,
	},
	[REINT_RMENTRY] = {
		.mr_handler = &mdt_reint_unlink,
		.mr_extra_opc = MDS_REINT_UNLINK,
	},
	[REINT_MIGRATE] = {
		.mr_handler = &mdt_reint_migrate,
		.mr_extra_opc = MDS_REINT_RENAME,
	},
	[REINT_RESYNC] = {
		.mr_handler = &mdt_reint_resync,
		.mr_extra_opc = MDS_REINT_RESYNC,
	},
};

int mdt_reint_rec(struct mdt_thread_info *info,
		  struct mdt_lock_handle *lhc)
{
	const struct mdt_reinter *mr;
	int rc;

	ENTRY;
	if (!(info->mti_rr.rr_opcode < ARRAY_SIZE(mdt_reinters)))
		RETURN(-EPROTO);

	mr = &mdt_reinters[info->mti_rr.rr_opcode];
	if (mr->mr_handler == NULL)
		RETURN(-EPROTO);

	rc = (*mr->mr_handler)(info, lhc);

	lprocfs_counter_incr(ptlrpc_req2svc(mdt_info_req(info))->srv_stats,
			     PTLRPC_LAST_CNTR + mr->mr_extra_opc);

	RETURN(rc);
}
