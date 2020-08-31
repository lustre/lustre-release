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

static int mdt_stripes_unlock(struct mdt_thread_info *mti,
			      struct mdt_object *obj,
			      struct ldlm_enqueue_info *einfo,
			      int decref)
{
	union ldlm_policy_data *policy = &mti->mti_policy;
	struct mdt_lock_handle *lh = &mti->mti_lh[MDT_LH_LOCAL];
	struct lustre_handle_array *locks = einfo->ei_cbdata;
	int i;

	LASSERT(S_ISDIR(obj->mot_header.loh_attr));
	LASSERT(locks);

	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = einfo->ei_inodebits;
	mdt_lock_reg_init(lh, einfo->ei_mode);
	for (i = 0; i < locks->ha_count; i++) {
		if (test_bit(i, (void *)locks->ha_map))
			lh->mlh_rreg_lh = locks->ha_handles[i];
		else
			lh->mlh_reg_lh = locks->ha_handles[i];
		mdt_object_unlock(mti, NULL, lh, decref);
		locks->ha_handles[i].cookie = 0ull;
	}

	return mo_object_unlock(mti->mti_env, mdt_object_child(obj), einfo,
				policy);
}

/**
 * Lock slave stripes if necessary, the lock handles of slave stripes
 * will be stored in einfo->ei_cbdata.
 **/
static int mdt_stripes_lock(struct mdt_thread_info *mti, struct mdt_object *obj,
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
	policy->l_inodebits.li_initiator_id = mdt_node_id(mti->mti_mdt);

	return mo_object_lock(mti->mti_env, mdt_object_child(obj), NULL, einfo,
			      policy);
}

/** lock object, and stripes if it's a striped directory
 *
 * object should be local, this is called in operations which modify both object
 * and stripes.
 *
 * \param info		struct mdt_thread_info
 * \param parent	parent object, if it's NULL, find parent by mdo_lookup()
 * \param child		child object
 * \param lh		lock handle
 * \param einfo		struct ldlm_enqueue_info
 * \param ibits		MDS inode lock bits
 * \param mode		lock mode
 *
 * \retval		0 on success, -ev on error.
 */
int mdt_object_stripes_lock(struct mdt_thread_info *info,
			    struct mdt_object *parent,
			    struct mdt_object *child,
			    struct mdt_lock_handle *lh,
			    struct ldlm_enqueue_info *einfo, __u64 ibits,
			    enum ldlm_mode mode)
{
	int rc;

	ENTRY;
	/* according to the protocol, child should be local, is request sent to
	 * wrong MDT?
	 */
	if (mdt_object_remote(child)) {
		CERROR("%s: lock target "DFID", but it is on other MDT: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), PFID(mdt_object_fid(child)),
		       -EREMOTE);
		RETURN(-EREMOTE);
	}

	memset(einfo, 0, sizeof(*einfo));
	if (ibits & MDS_INODELOCK_LOOKUP) {
		LASSERT(parent);
		rc = mdt_object_check_lock(info, parent, child, lh, ibits,
					   mode);
	} else {
		rc = mdt_object_lock(info, child, lh, ibits, mode);
	}
	if (rc)
		RETURN(rc);

	if (!S_ISDIR(child->mot_header.loh_attr))
		RETURN(0);

	/* lock stripes for striped directory */
	rc = mdt_stripes_lock(info, child, lh->mlh_reg_mode, ibits, einfo);
	if (rc == -EIO && CFS_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_NAME))
		rc = 0;
	if (rc)
		mdt_object_unlock(info, child, lh, rc);

	RETURN(rc);
}

void mdt_object_stripes_unlock(struct mdt_thread_info *info,
			      struct mdt_object *obj,
			      struct mdt_lock_handle *lh,
			      struct ldlm_enqueue_info *einfo, int decref)
{
	if (einfo->ei_cbdata)
		mdt_stripes_unlock(info, obj, einfo, decref);
	mdt_object_unlock(info, obj, lh, decref);
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
	struct ldlm_enqueue_info *einfo = &info->mti_einfo;
	struct lmv_user_md *lum = spec->u.sp_ea.eadata;
	struct lu_ucred *uc = mdt_ucred(info);
	struct lmv_mds_md_v1 *lmv;
	struct mdt_object *child;
	struct mdt_lock_handle *lhp;
	struct mdt_lock_handle *lhc;
	struct mdt_body *repbody;
	int rc;

	ENTRY;

	/* we want rbac roles to have precedence over any other
	 * permission or capability checks
	 */
	if (!mdt->mdt_enable_dir_restripe && !uc->uc_rbac_dne_ops)
		RETURN(-EPERM);

	LASSERT(lum);
	lum->lum_hash_type |= cpu_to_le32(LMV_HASH_FLAG_FIXED);

	rc = mdt_version_get_check_save(info, parent, 0);
	if (rc)
		RETURN(rc);

	lhp = &info->mti_lh[MDT_LH_PARENT];
	rc = mdt_parent_lock(info, parent, lhp, lname, LCK_PW);
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
	rc = mdt_object_stripes_lock(info, parent, child, lhc, einfo,
				     MDS_INODELOCK_ELC, LCK_PW);
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
	mdt_object_stripes_unlock(info, child, lhc, einfo, rc);
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
static int mdt_create(struct mdt_thread_info *info, struct mdt_lock_handle *lhc)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_object *parent;
	struct mdt_object *child;
	struct mdt_lock_handle *lh;
	struct mdt_body *repbody;
	struct md_attr *ma = &info->mti_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct md_op_spec *spec = &info->mti_spec;
	struct lu_ucred *uc = mdt_ucred(info);
	struct ldlm_reply *dlmrep = NULL;
	bool restripe = false;
	bool recreate_obj = false;
	int rc;

	ENTRY;
	DEBUG_REQ(D_INODE, mdt_info_req(info),
		  "Create ("DNAME"->"DFID") in "DFID,
		  PNAME(&rr->rr_name), PFID(rr->rr_fid2), PFID(rr->rr_fid1));

	if (!fid_is_md_operative(rr->rr_fid1))
		RETURN(-EPERM);

	/* MDS_OPEN_DEFAULT_LMV means eadata is parent default LMV, which is set
	 * if client maintains inherited default LMV
	 */
	if (S_ISDIR(ma->ma_attr.la_mode) &&
	    spec->u.sp_ea.eadata != NULL && spec->u.sp_ea.eadatalen != 0 &&
	    !(spec->sp_cr_flags & MDS_OPEN_DEFAULT_LMV)) {
		const struct lmv_user_md *lum = spec->u.sp_ea.eadata;
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
		    (le32_to_cpu(lum->lum_hash_type) & LMV_HASH_TYPE_MASK) >=
		    LMV_HASH_TYPE_CRUSH)
			RETURN(-EPROTO);

		/* we want rbac roles to have precedence over any other
		 * permission or capability checks
		 */
		if (!uc->uc_rbac_dne_ops ||
		    (!cap_raised(uc->uc_cap, CAP_SYS_ADMIN) &&
		     uc->uc_gid != mdt->mdt_enable_remote_dir_gid &&
		     mdt->mdt_enable_remote_dir_gid != -1))
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
	/*
	 * TODO: rewrite ll_mknod(), ll_create_nd(), ll_symlink(),
	 * ll_dir_setdirstripe() to all use intent lock.
	 */
	if (info->mti_intent_lock) {
		dlmrep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
		mdt_set_disposition(info, dlmrep,
				    DISP_IT_EXECD | DISP_LOOKUP_EXECD);
	}

	parent = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(parent))
		RETURN(PTR_ERR(parent));

	if (!mdt_object_exists(parent))
		GOTO(put_parent, rc = -ENOENT);

	rc = mdt_check_enc(info, parent);
	if (rc)
		GOTO(put_parent, rc);

	if (!uc->uc_rbac_fscrypt_admin &&
	    parent->mot_obj.lo_header->loh_attr & LOHA_FSCRYPT_MD)
		GOTO(put_parent, rc = -EPERM);

	info->mti_spec.sp_replay = req_is_replay(mdt_info_req(info));

	/*
	 * LU-10235: check if name exists locklessly first to avoid massive
	 * lock recalls on existing directories.
	 */
	rc = mdo_lookup(info->mti_env, mdt_object_child(parent), &rr->rr_name,
			&info->mti_tmp_fid1, &info->mti_spec);
	if (rc == 0) {
		bool child_exists = false;

		if (unlikely(!info->mti_spec.sp_replay && !restripe))
			GOTO(put_parent, rc = -EEXIST);

		child = mdt_object_find(info->mti_env, info->mti_mdt,
					&info->mti_tmp_fid1);
		if (unlikely(IS_ERR(child)))
			GOTO(put_parent, rc = PTR_ERR(child));

		child_exists = mdt_object_exists(child);
		mdt_object_put(info->mti_env, child);
		if (child_exists) {
			if (restripe) {
				rc = mdt_restripe(info, parent, &rr->rr_name,
						  rr->rr_fid2, spec, ma);
			} else {
				LASSERT(info->mti_spec.sp_replay);
				mdt_obj_version_get(info, child,
						    &info->mti_ver[1]);
				rc = mdt_version_check(mdt_info_req(info),
						       info->mti_ver[1], 1);
			}
			GOTO(put_parent, rc);
		} else if (restripe) {
			/* restripe, dirent exists but inode not */
			GOTO(put_parent, rc = -EINVAL);
		} else if (!mdt_object_remote(parent)) {
			/* create, parent is on local MDT and dirent exists */
			LASSERT(info->mti_spec.sp_replay);
			GOTO(put_parent, rc = -EEXIST);
		}
		/* mkdir may be partially executed: name entry was successfully
		 * inserted into parent diretory on remote MDT, while target not
		 * created on local MDT. This happens when update log recovery
		 * is aborted, and mkdir is replayed by client request.
		 */
		LASSERT(info->mti_spec.sp_replay && !child_exists && !restripe);
		recreate_obj = true;
	} else if (rc != -ENOENT) {
		GOTO(put_parent, rc);
	}

	if (unlikely(info->mti_spec.sp_replay)) {
		/* check version only during replay */
		rc = mdt_version_check(mdt_info_req(info), ENOENT_VERSION, 1);
		if (rc)
			GOTO(put_parent, rc);
	} else {
		CFS_FAIL_TIMEOUT(OBD_FAIL_MDS_PAUSE_CREATE_AFTER_LOOKUP,
				 cfs_fail_val);

		/* save version of file name for replay, must be ENOENT here */
		mdt_enoent_version_save(info, 1);
	}

	CFS_RACE(OBD_FAIL_MDS_CREATE_RACE);

	lh = &info->mti_lh[MDT_LH_PARENT];
	rc = mdt_parent_lock(info, parent, lh, &rr->rr_name, LCK_PW);
	if (rc)
		GOTO(put_parent, rc);

	if (!mdt_object_remote(parent)) {
		rc = mdt_version_get_check_save(info, parent, 0);
		if (rc)
			GOTO(unlock_parent, rc);
	}

	/*
	 * now repeat the lookup having a LDLM lock on the parent dir,
	 * as another thread could create the same name. notice this
	 * lookup is supposed to hit cache in OSD and be cheap if the
	 * directory is not being modified concurrently.
	 */
	rc = mdo_lookup(info->mti_env, mdt_object_child(parent), &rr->rr_name,
			&info->mti_tmp_fid1, &info->mti_spec);
	if (unlikely(rc == 0 && !recreate_obj))
		GOTO(unlock_parent, rc = -EEXIST);

	if (info->mti_intent_lock)
		mdt_set_disposition(info, dlmrep, DISP_OPEN_CREATE);

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

	if (parent->mot_obj.lo_header->loh_attr & LOHA_FSCRYPT_MD ||
	    (rr->rr_name.ln_namelen == strlen(dot_fscrypt_name) &&
	     strncmp(rr->rr_name.ln_name, dot_fscrypt_name,
		     rr->rr_name.ln_namelen) == 0))
		child->mot_obj.lo_header->loh_attr |= LOHA_FSCRYPT_MD;

	/*
	 * Do not perform lookup sanity check. We know that name does
	 * not exist.
	 */
	info->mti_spec.sp_cr_lookup = 0;
	if (mdt_object_remote(parent))
		info->mti_spec.sp_cr_lookup = 1;
	info->mti_spec.sp_feat = &dt_directory_features;

	/* set jobid xattr name from sysfs parameter */
	strncpy(info->mti_spec.sp_cr_job_xattr, mdt->mdt_job_xattr,
		XATTR_JOB_MAX_LEN);

	rc = mdo_create(info->mti_env, mdt_object_child(parent), &rr->rr_name,
			mdt_object_child(child), &info->mti_spec, ma);
	if (rc < 0)
		GOTO(put_child, rc);

	if ((S_ISDIR(ma->ma_attr.la_mode) &&
	     (info->mti_spec.sp_cr_flags & MDS_MKDIR_LMV)) ||
	     info->mti_intent_lock)
		mdt_prep_ma_buf_from_rep(info, child, ma, 0);

	rc = mdt_attr_get_complex(info, child, ma);
	if (rc < 0)
		GOTO(put_child, rc);

	if (ma->ma_valid & MA_LOV) {
		LASSERT(ma->ma_lmm_size != 0);
		repbody->mbo_eadatasize = ma->ma_lmm_size;
		if (S_ISREG(ma->ma_attr.la_mode))
			repbody->mbo_valid |= OBD_MD_FLEASIZE;
		else if (S_ISDIR(ma->ma_attr.la_mode))
			repbody->mbo_valid |= OBD_MD_FLDIREA;
	}

	if (ma->ma_valid & MA_LMV) {
		mdt_dump_lmv(D_INFO, ma->ma_lmv);
		repbody->mbo_eadatasize = ma->ma_lmv_size;
		repbody->mbo_valid |= (OBD_MD_FLDIREA|OBD_MD_MEA);
	}

	if (ma->ma_valid & MA_LMV_DEF) {
		/* Return -EOPNOTSUPP for old client. */
		if (!mdt_is_striped_client(mdt_info_req(info)->rq_export))
			GOTO(put_child, rc = -EOPNOTSUPP);

		LASSERT(S_ISDIR(ma->ma_attr.la_mode));
		repbody->mbo_valid |= OBD_MD_FLDIREA | OBD_MD_DEFAULT_MEA;
	}

	/* save child locks to eliminate dependey between 'mkdir a' and
	 * 'mkdir a/b' if b is a remote directory
	 */
	if (mdt_slc_is_enabled(mdt) && S_ISDIR(ma->ma_attr.la_mode) &&
	    !info->mti_intent_lock) {
		struct mdt_lock_handle *lhc;
		struct ldlm_enqueue_info *einfo = &info->mti_einfo;

		lhc = &info->mti_lh[MDT_LH_CHILD];
		rc = mdt_object_stripes_lock(info, parent, child, lhc, einfo,
					     MDS_INODELOCK_UPDATE, LCK_PW);
		if (rc)
			GOTO(put_child, rc);

		mdt_object_stripes_unlock(info, child, lhc, einfo, rc);
	}

	/* Return fid & attr to client. */
	if (ma->ma_valid & MA_INODE)
		mdt_pack_attr2body(info, repbody, &ma->ma_attr,
				   mdt_object_fid(child));

	if (info->mti_intent_lock) {
		mdt_set_disposition(info, dlmrep, DISP_LOOKUP_NEG);
		rc = mdt_check_resent_lock(info, child, lhc);
		/*
		 * rc < 0 is error and we fall right back through,
		 * rc == 0 is the open lock might already be gotten in
		 * ldlm_handle_enqueue due to this being a resend.
		 */
		if (rc <= 0)
			GOTO(put_child, rc);

		/*
		 * For the normal intent create (mkdir):
		 * - Grant LOOKUP lock with CR mode to the client at
		 *   least.
		 * - Grant the lock similar to getattr():
		 *   lock mode: PR;
		 *   inodebits: LOOK | UPDATE | PERM [| LAYOUT].
		 * However, it can not grant LCK_CR to the client as during
		 * the setting of LMV layout for a directory from a client,
		 * it will acquire LCK_PW mode lock which is compat with LCK_CR
		 * lock mode, this may result that the cached LMV layout on a
		 * client will not be released when set (default) LMV layout on
		 * a directory.
		 * Due to the above reason, it grants a lock with LCK_PR mode to
		 * the client.
		 */
		rc = mdt_object_lock(info, child, lhc, MDS_INODELOCK_LOOKUP |
				     MDS_INODELOCK_UPDATE | MDS_INODELOCK_PERM,
				     LCK_PR);
	}

	EXIT;
put_child:
	mdt_object_put(info->mti_env, child);
unlock_parent:
	mdt_object_unlock(info, parent, lh, rc);
	if (rc && dlmrep)
		mdt_clear_disposition(info, dlmrep, DISP_OPEN_CREATE);
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
	struct ldlm_enqueue_info *einfo = &info->mti_einfo;
	int rc;

	ENTRY;
	if (ma->ma_attr.la_valid & (LA_MODE|LA_UID|LA_GID))
		lockpart |= MDS_INODELOCK_PERM;
	/* Clear xattr cache on clients, so the virtual project ID xattr
	 * can get the new project ID
	 */
	if (ma->ma_attr.la_valid & LA_PROJID)
		lockpart |= MDS_INODELOCK_XATTR;

	lh = &info->mti_lh[MDT_LH_PARENT];
	rc = mdt_object_stripes_lock(info, NULL, mo, lh, einfo, lockpart,
				     LCK_PW);
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
	mdt_object_stripes_unlock(info, mo, lh, einfo, rc);
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
	int rc;

	ENTRY;
	DEBUG_REQ(D_INODE, req, "setattr "DFID" %x", PFID(rr->rr_fid1),
		  (unsigned int)ma->ma_attr.la_valid);

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	CFS_RACE(OBD_FAIL_PTLRPC_RESEND_RACE);

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
			rc = mdt_object_lock(info, mo, lhc, MDS_INODELOCK_OPEN,
					     LCK_CW);
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
				    mdt_lmm_is_flr(info->mti_big_lov))
					GOTO(out_put, rc = -EOPNOTSUPP);
			}

			if (!exp_connect_overstriping(info->mti_exp)) {
				if (rc > 0 &&
				    mdt_lmm_is_overstriping(info->mti_big_lov))
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

		/* reject if either remote or striped dir is disabled */
		if (ma->ma_valid & MA_LMV) {
			if (!mdt->mdt_enable_remote_dir ||
			    !mdt->mdt_enable_striped_dir)
				GOTO(out_put, rc = -EPERM);

			/* we want rbac roles to have precedence over any other
			 * permission or capability checks
			 */
			if (!uc->uc_rbac_dne_ops ||
			    (!cap_raised(uc->uc_cap, CAP_SYS_ADMIN) &&
			     uc->uc_gid != mdt->mdt_enable_remote_dir_gid &&
			     mdt->mdt_enable_remote_dir_gid != -1))
				GOTO(out_put, rc = -EPERM);
		}

		if (!S_ISDIR(lu_object_attr(&mo->mot_obj)))
			GOTO(out_put, rc = -ENOTDIR);

		if (ma->ma_attr.la_valid != 0)
			GOTO(out_put, rc = -EPROTO);

		lh = &info->mti_lh[MDT_LH_PARENT];
		if (ma->ma_valid & MA_LOV) {
			buf->lb_buf = ma->ma_lmm;
			buf->lb_len = ma->ma_lmm_size;
			name = XATTR_NAME_LOV;
			rc = mdt_object_lock(info, mo, lh, MDS_INODELOCK_XATTR,
					     LCK_PW);
		} else {
			buf->lb_buf = &ma->ma_lmv->lmv_user_md;
			buf->lb_len = ma->ma_lmv_size;
			name = XATTR_NAME_DEFAULT_LMV;

			if (unlikely(fid_is_root(mdt_object_fid(mo)))) {
				rc = mdt_object_lock(info, mo, lh,
						     MDS_INODELOCK_XATTR |
						     MDS_INODELOCK_LOOKUP,
						     LCK_PW);
			} else {
				struct lu_fid *pfid = &info->mti_tmp_fid1;
				struct lu_name *pname = &info->mti_name;
				const char dotdot[] = "..";
				struct mdt_object *pobj;

				fid_zero(pfid);
				pname->ln_name = dotdot;
				pname->ln_namelen = sizeof(dotdot);
				rc = mdo_lookup(info->mti_env,
						mdt_object_child(mo), pname,
						pfid, NULL);
				if (rc)
					GOTO(out_put, rc);

				pobj = mdt_object_find(info->mti_env,
						       info->mti_mdt, pfid);
				if (IS_ERR(pobj))
					GOTO(out_put, rc = PTR_ERR(pobj));

				rc = mdt_object_check_lock(info, pobj, mo, lh,
							   MDS_INODELOCK_XATTR |
							   MDS_INODELOCK_LOOKUP,
							   LCK_PW);
				mdt_object_put(info->mti_env, pobj);
			}
		}

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
	return rc;
}

static int mdt_reint_create(struct mdt_thread_info *info,
			    struct mdt_lock_handle *lhc)
{
	struct ptlrpc_request   *req = mdt_info_req(info);
	ktime_t			kstart = ktime_get();
	int                     rc;

	ENTRY;
	if (CFS_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE))
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

	rc = mdt_create(info, lhc);
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
	struct ldlm_enqueue_info *einfo = &info->mti_einfo;
	struct lu_ucred *uc  = mdt_ucred(info);
	int no_name = 0;
	ktime_t kstart = ktime_get();
	int rc;

	ENTRY;
	DEBUG_REQ(D_INODE, req, "unlink "DFID"/"DNAME"", PFID(rr->rr_fid1),
		  PNAME(&rr->rr_name));

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	if (CFS_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
		RETURN(err_serious(-ENOENT));

	if (!fid_is_md_operative(rr->rr_fid1))
		RETURN(-EPERM);

	mp = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(mp))
		RETURN(PTR_ERR(mp));

	if (!uc->uc_rbac_fscrypt_admin &&
	    mp->mot_obj.lo_header->loh_attr & LOHA_FSCRYPT_MD)
		GOTO(put_parent, rc = -EPERM);

	CFS_RACE(OBD_FAIL_MDS_REINT_OPEN);
	CFS_RACE(OBD_FAIL_MDS_REINT_OPEN2);
	parent_lh = &info->mti_lh[MDT_LH_PARENT];
	rc = mdt_parent_lock(info, mp, parent_lh, &rr->rr_name, LCK_PW);
	if (rc != 0)
		GOTO(put_parent, rc);

	if (!mdt_object_remote(mp)) {
		rc = mdt_version_get_check_save(info, mp, 0);
		if (rc)
			GOTO(unlock_parent, rc);
	}

	if (info->mti_spec.sp_rm_entry) {
		if (!mdt_is_dne_client(req->rq_export))
			/* Return -ENOTSUPP for old client */
			GOTO(unlock_parent, rc = -ENOTSUPP);

		if (!cap_raised(uc->uc_cap, CAP_SYS_ADMIN))
			GOTO(unlock_parent, rc = -EPERM);

		ma->ma_need = MA_INODE;
		ma->ma_valid = 0;
		rc = mdo_unlink(info->mti_env, mdt_object_child(mp),
				NULL, &rr->rr_name, ma, no_name);
		GOTO(unlock_parent, rc);
	}

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
					     NULL, mc))
			GOTO(put_child, rc = -ENOENT);
	}

	child_lh = &info->mti_lh[MDT_LH_CHILD];
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
		rc = mdt_object_lookup_lock(info, NULL, mc, child_lh, LCK_EX);
		if (rc)
			GOTO(put_child, rc);

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
	rc = mdt_object_stripes_lock(info, mp, mc, child_lh, einfo,
				     MDS_INODELOCK_LOOKUP |
				     MDS_INODELOCK_UPDATE, LCK_EX);
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
	/* after unlink the object is gone, no need to keep lock */
	mdt_object_stripes_unlock(info, mc, child_lh, einfo, 1);
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
	int rc;

	ENTRY;
	DEBUG_REQ(D_INODE, req, "link "DFID" to "DFID"/"DNAME,
		  PFID(rr->rr_fid1), PFID(rr->rr_fid2), PNAME(&rr->rr_name));

	if (CFS_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK))
		RETURN(err_serious(-ENOENT));

	if (CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_RESEND_RACE) ||
	    CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_ENQ_RESEND)) {
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

	/* step 2: find source */
	ms = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(ms))
		GOTO(put_parent, rc = PTR_ERR(ms));

	if (!mdt_object_exists(ms)) {
		CDEBUG(D_INFO, "%s: "DFID" does not exist.\n",
		       mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1));
		GOTO(put_source, rc = -ENOENT);
	}

	CFS_RACE(OBD_FAIL_MDS_LINK_RENAME_RACE);

	lhp = &info->mti_lh[MDT_LH_PARENT];
	rc = mdt_parent_lock(info, mp, lhp, &rr->rr_name, LCK_PW);
	if (rc != 0)
		GOTO(put_source, rc);

	rc = mdt_version_get_check_save(info, mp, 0);
	if (rc)
		GOTO(unlock_parent, rc);

	rc = mdt_check_enc(info, mp);
	if (rc)
		GOTO(unlock_parent, rc);

	CFS_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME3, 5);

	lhs = &info->mti_lh[MDT_LH_CHILD];
	rc = mdt_object_lock(info, ms, lhs,
			     MDS_INODELOCK_UPDATE | MDS_INODELOCK_XATTR,
			     LCK_EX);
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
 * Get BFL lock for rename or migrate process.
 **/
static int mdt_rename_lock(struct mdt_thread_info *info,
			   struct mdt_lock_handle *lh)
{
	struct lu_fid *fid = &info->mti_tmp_fid1;
	struct mdt_object *obj;
	__u64 ibits = MDS_INODELOCK_UPDATE;
	int rc;

	ENTRY;
	lu_root_fid(fid);
	obj = mdt_object_find(info->mti_env, info->mti_mdt, fid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	mdt_lock_reg_init(lh, LCK_EX);
	rc = mdt_object_lock_internal(info, obj, &LUSTRE_BFL_FID, lh,
				      &ibits, 0, false);
	mdt_object_put(info->mti_env, obj);
	RETURN(rc);
}

static void mdt_rename_unlock(struct mdt_thread_info *info,
			      struct mdt_lock_handle *lh)
{
	ENTRY;
	/* Cancel the single rename lock right away */
	mdt_object_unlock(info, NULL, lh, 1);
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
 * lock rename source object.
 *
 * Both source and its parent object may be located on remote MDTs, and even on
 * different MDTs, which means source object is a remote object on parent.
 *
 * \retval	0 on success
 * \retval	-ev negative errno upon error
 */
static int mdt_rename_source_lock(struct mdt_thread_info *info,
				  struct mdt_object *parent,
				  struct mdt_object *child,
				  struct mdt_lock_handle *lh,
				  struct mdt_lock_handle *lh_lookup,
				  __u64 ibits)
{
	int rc;

	LASSERT(ibits & MDS_INODELOCK_LOOKUP);
	/* if @obj is remote object, LOOKUP lock needs to be taken from
	 * parent MDT.
	 */
	rc = mdt_is_remote_object(info, parent, child);
	if (rc < 0)
		return rc;

	if (rc == 1) {
		rc = mdt_object_lookup_lock(info, parent, child, lh_lookup,
					    LCK_EX);
		if (rc)
			return rc;

		ibits &= ~MDS_INODELOCK_LOOKUP;
	}

	rc = mdt_object_lock(info, child, lh, ibits, LCK_EX);
	if (unlikely(rc && !(ibits & MDS_INODELOCK_LOOKUP)))
		mdt_object_unlock(info, NULL, lh_lookup, rc);

	return 0;
}

static void mdt_rename_source_unlock(struct mdt_thread_info *info,
				     struct mdt_object *obj,
				     struct mdt_lock_handle *lh,
				     struct mdt_lock_handle *lh_lookup,
				     int decref)
{
	mdt_object_unlock(info, obj, lh, decref);
	mdt_object_unlock(info, NULL, lh_lookup, decref);
}

/* migration takes UPDATE lock of link parent, and LOOKUP lock of link */
struct mdt_link_lock {
	struct mdt_object *mll_obj;
	struct mdt_lock_handle mll_lh;
	struct list_head mll_linkage;
};

static inline int mdt_migrate_link_lock_add(struct mdt_thread_info *info,
					    struct mdt_object *o,
					    struct mdt_lock_handle *lh,
					    struct list_head *list)
{
	struct mdt_link_lock *mll;

	OBD_ALLOC_PTR(mll);
	if (mll == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&mll->mll_linkage);
	mdt_object_get(info->mti_env, o);
	mll->mll_obj = o;
	mll->mll_lh = *lh;
	memset(lh, 0, sizeof(*lh));
	list_add_tail(&mll->mll_linkage, list);

	return 0;
}

static inline void mdt_migrate_link_lock_del(struct mdt_thread_info *info,
					     struct mdt_link_lock *mll,
					     int decref)
{
	mdt_object_unlock(info, mll->mll_obj, &mll->mll_lh, decref);
	mdt_object_put(info->mti_env, mll->mll_obj);
	list_del(&mll->mll_linkage);
	OBD_FREE_PTR(mll);
}

static void mdt_migrate_links_unlock(struct mdt_thread_info *info,
				     struct list_head *list, int decref)
{
	struct mdt_link_lock *mll;
	struct mdt_link_lock *tmp;

	list_for_each_entry_safe(mll, tmp, list, mll_linkage)
		mdt_migrate_link_lock_del(info, mll, decref);
}

/* take link parent UPDATE lock.
 * \retval	0 \a lnkp is already locked, no lock taken.
 *		1 lock taken
 *		-ev negative errno.
 */
static int mdt_migrate_link_parent_lock(struct mdt_thread_info *info,
					struct mdt_object *lnkp,
					struct list_head *update_locks,
					bool *blocked)
{
	const struct lu_fid *fid = mdt_object_fid(lnkp);
	struct mdt_lock_handle *lhl = &info->mti_lh[MDT_LH_LOCAL];
	struct mdt_link_lock *entry;
	__u64 ibits = 0;
	int rc;

	ENTRY;

	/* check if it's already locked */
	list_for_each_entry(entry, update_locks, mll_linkage) {
		if (lu_fid_eq(mdt_object_fid(entry->mll_obj), fid)) {
			CDEBUG(D_INFO, "skip "DFID" lock\n", PFID(fid));
			RETURN(0);
		}
	}

	/* link parent UPDATE lock */
	CDEBUG(D_INFO, "lock "DFID"\n", PFID(fid));

	if (*blocked) {
		/* revoke lock instead of take in *blocked* mode */
		rc = mdt_object_lock(info, lnkp, lhl, MDS_INODELOCK_UPDATE,
				     LCK_PW);
		if (rc)
			RETURN(rc);

		if (mdt_object_remote(lnkp)) {
			struct ldlm_lock *lock;

			/*
			 * for remote object, set lock cb_atomic, so lock can be
			 * released in blocking_ast() immediately, then the next
			 * lock_try will have better chance of success.
			 */
			lock = ldlm_handle2lock(&lhl->mlh_rreg_lh);
			LASSERT(lock != NULL);
			lock_res_and_lock(lock);
			ldlm_set_atomic_cb(lock);
			unlock_res_and_lock(lock);
			ldlm_lock_put(lock);
		}

		mdt_object_unlock(info, lnkp, lhl, 1);
		RETURN(0);
	}

	/*
	 * we can't follow parent-child lock order like other MD
	 * operations, use lock_try here to avoid deadlock, if the lock
	 * cannot be taken, drop all locks taken, revoke the blocked
	 * one, and continue processing the remaining entries, and in
	 * the end of the loop restart from beginning.
	 *
	 * don't lock with PDO mode in case two links are under the same
	 * parent and their hash values are different.
	 */
	rc = mdt_object_lock_try(info, lnkp, lhl, &ibits, MDS_INODELOCK_UPDATE,
				 LCK_PW);
	if (rc < 0)
		RETURN(rc);

	if (!(ibits & MDS_INODELOCK_UPDATE)) {
		CDEBUG(D_INFO, "busy lock on "DFID"\n", PFID(fid));
		*blocked = true;
		RETURN(-EAGAIN);
	}

	rc = mdt_migrate_link_lock_add(info, lnkp, lhl, update_locks);
	if (rc) {
		mdt_object_unlock(info, lnkp, lhl, 1);
		RETURN(rc);
	}

	RETURN(1);
}

/* take link LOOKUP lock.
 * \retval	0 \a lnkp is already locked, no lock taken.
 *		1 lock taken.
 *		-ev negative errno.
 */
static int mdt_migrate_link_lock(struct mdt_thread_info *info,
				 struct mdt_object *lnkp,
				 struct mdt_object *spobj,
				 struct mdt_object *obj,
				 struct list_head *lookup_locks)
{
	const struct lu_fid *fid = mdt_object_fid(lnkp);
	struct mdt_lock_handle *lhl = &info->mti_lh[MDT_LH_LOCAL];
	struct mdt_link_lock *entry;
	int rc;

	ENTRY;

	/* check if it's already locked by source */
	rc = mdt_fids_different_target(info, fid, mdt_object_fid(spobj));
	if (rc <= 0) {
		CDEBUG(D_INFO, "skip lookup lock on source parent "DFID"\n",
		       PFID(fid));
		RETURN(rc);
	}

	/* check if it's already locked by other links */
	list_for_each_entry(entry, lookup_locks, mll_linkage) {
		rc = mdt_fids_different_target(info, fid,
					       mdt_object_fid(entry->mll_obj));
		if (rc <= 0) {
			CDEBUG(D_INFO, "skip lookup lock on parent "DFID"\n",
			       PFID(fid));
			RETURN(rc);
		}
	}

	rc = mdt_object_lookup_lock(info, lnkp, obj, lhl, LCK_EX);
	if (rc)
		RETURN(rc);

	/* don't take local LOOKUP lock, because later we will lock other ibits
	 * of sobj (which is on local MDT), and lock the same object twice may
	 * deadlock, just revoke this lock.
	 */
	if (!mdt_object_remote(lnkp))
		GOTO(unlock, rc = 0);

	rc = mdt_migrate_link_lock_add(info, lnkp, lhl, lookup_locks);
	if (rc)
		GOTO(unlock, rc);

	RETURN(1);
unlock:
	mdt_object_unlock(info, lnkp, lhl, 1);
	return rc;
}

/*
 * take UPDATE lock of link parents and LOOKUP lock of links, also check whether
 * total local lock count exceeds RS_MAX_LOCKS.
 *
 * \retval	0 on success, and locks can be saved in ptlrpc_reply_stat
 * \retval	1 on success, but total lock count may exceed RS_MAX_LOCKS
 * \retval	-ev negative errno upon error
 */
static int mdt_migrate_links_lock(struct mdt_thread_info *info,
				  struct mdt_object *spobj,
				  struct mdt_object *tpobj,
				  struct mdt_object *obj,
				  struct mdt_lock_handle *lhsp,
				  struct mdt_lock_handle *lhtp,
				  struct list_head *link_locks)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct lu_buf *buf = &info->mti_big_buf;
	struct lu_name *lname = &info->mti_name;
	struct linkea_data ldata = { NULL };
	int local_lock_cnt = 0;
	bool blocked = false;
	bool saved;
	struct mdt_object *lnkp;
	struct lu_fid fid;
	LIST_HEAD(update_locks);
	LIST_HEAD(lookup_locks);
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
		linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen, lname,
				    &fid);

		/* check if link parent is source parent too */
		if (lu_fid_eq(mdt_object_fid(spobj), &fid)) {
			CDEBUG(D_INFO,
			       "skip lock on source parent "DFID"/"DNAME"\n",
			       PFID(&fid), PNAME(lname));
			continue;
		}

		/* check if link parent is target parent too */
		if (tpobj != spobj && lu_fid_eq(mdt_object_fid(tpobj), &fid)) {
			CDEBUG(D_INFO,
			       "skip lock on target parent "DFID"/"DNAME"\n",
			       PFID(&fid), PNAME(lname));
			continue;
		}

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
relock:
		saved = blocked;
		rc = mdt_migrate_link_parent_lock(info, lnkp, &update_locks,
						  &blocked);
		if (!saved && blocked) {
			/* unlock all locks taken to avoid deadlock */
			mdt_migrate_links_unlock(info, &update_locks, 1);
			mdt_object_unlock(info, spobj, lhsp, 1);
			if (tpobj != spobj)
				mdt_object_unlock(info, tpobj, lhtp, 1);
			goto relock;
		}
		if (rc < 0) {
			mdt_object_put(info->mti_env, lnkp);
			GOTO(out, rc);
		}

		if (rc == 1 && !mdt_object_remote(lnkp))
			local_lock_cnt++;

		rc = mdt_migrate_link_lock(info, lnkp, spobj, obj,
					   &lookup_locks);
		if (rc < 0) {
			mdt_object_put(info->mti_env, lnkp);
			GOTO(out, rc);
		}
		if (rc == 1 && !mdt_object_remote(lnkp))
			local_lock_cnt++;
		mdt_object_put(info->mti_env, lnkp);
	}

	if (blocked)
		GOTO(out, rc = -EBUSY);

	EXIT;
out:
	list_splice(&update_locks, link_locks);
	list_splice(&lookup_locks, link_locks);
	if (rc < 0) {
		mdt_migrate_links_unlock(info, link_locks, rc);
	} else if (local_lock_cnt > RS_MAX_LOCKS - 5) {
		/*
		 * parent may have 3 local objects: master object and 2 stripes
		 * (if it's being migrated too); source may have 1 local objects
		 * as regular file; target has 1 local object.
		 * Note, source may have 2 local locks if it is directory but it
		 * can't have hardlinks, so it is not considered here.
		 */
		CDEBUG(D_INFO, "Too many local locks (%d), migrate in sync mode\n",
		       local_lock_cnt);
		rc = 1;
	}
	return rc;
}

/*
 * lookup source by name, if parent is striped directory, we need to find the
 * corresponding stripe where source is located, and then lookup there.
 *
 * besides, if parent is migrating too, and file is already in target stripe,
 * this should be a redo of 'lfs migrate' on client side.
 *
 * \retval 1 tpobj stripe index is less than spobj stripe index
 * \retval 0 tpobj stripe index is larger than or equal to spobj stripe index
 * \retval -ev negative errno upon error
 */
static int mdt_migrate_lookup(struct mdt_thread_info *info,
			      struct mdt_object *pobj,
			      const struct md_attr *ma,
			      const struct lu_name *lname,
			      struct mdt_object **spobj,
			      struct mdt_object **tpobj,
			      struct mdt_object **sobj)
{
	const struct lu_env *env = info->mti_env;
	struct lu_fid *fid = &info->mti_tmp_fid1;
	int spindex = -1;
	int tpindex = -1;
	int rc;

	if (ma->ma_valid & MA_LMV) {
		/* if parent is striped, lookup on corresponding stripe */
		struct lmv_mds_md_v1 *lmv = &ma->ma_lmv->lmv_md_v1;
		struct lu_fid *fid2 = &info->mti_tmp_fid2;

		if (!lmv_is_sane(lmv))
			return -EBADF;

		spindex = lmv_name_to_stripe_index_old(lmv, lname->ln_name,
						       lname->ln_namelen);
		if (spindex < 0)
			return spindex;

		fid_le_to_cpu(fid2, &lmv->lmv_stripe_fids[spindex]);

		*spobj = mdt_object_find(env, info->mti_mdt, fid2);
		if (IS_ERR(*spobj)) {
			rc = PTR_ERR(*spobj);
			*spobj = NULL;
			return rc;
		}

		if (!mdt_object_exists(*spobj))
			GOTO(spobj_put, rc = -ENOENT);

		fid_zero(fid);
		rc = mdo_lookup(env, mdt_object_child(*spobj), lname, fid,
				&info->mti_spec);
		if ((rc == -ENOENT || rc == 0) && lmv_is_layout_changing(lmv)) {
			/* fail check here to let top dir migration succeed. */
			if (CFS_FAIL_CHECK_RESET(OBD_FAIL_MIGRATE_ENTRIES, 0))
				GOTO(spobj_put, rc = -EIO);

			/*
			 * if parent layout is changeing, and lookup child
			 * failed on source stripe, lookup again on target
			 * stripe, if it exists, it means previous migration
			 * was interrupted, and current file was migrated
			 * already.
			 */
			tpindex = lmv_name_to_stripe_index(lmv, lname->ln_name,
							   lname->ln_namelen);
			if (tpindex < 0)
				GOTO(spobj_put, rc = tpindex);

			fid_le_to_cpu(fid2, &lmv->lmv_stripe_fids[tpindex]);

			*tpobj = mdt_object_find(env, info->mti_mdt, fid2);
			if (IS_ERR(*tpobj)) {
				rc = PTR_ERR(*tpobj);
				*tpobj = NULL;
				GOTO(spobj_put, rc);
			}

			if (!mdt_object_exists(*tpobj))
				GOTO(tpobj_put, rc = -ENOENT);

			if (rc == -ENOENT) {
				fid_zero(fid);
				rc = mdo_lookup(env, mdt_object_child(*tpobj),
						lname, fid, &info->mti_spec);
				GOTO(tpobj_put, rc = rc ?: -EALREADY);
			}
		} else if (rc) {
			GOTO(spobj_put, rc);
		} else {
			*tpobj = *spobj;
			tpindex = spindex;
			mdt_object_get(env, *tpobj);
		}
	} else {
		fid_zero(fid);
		rc = mdo_lookup(env, mdt_object_child(pobj), lname, fid,
				&info->mti_spec);
		if (rc)
			return rc;

		*spobj = pobj;
		*tpobj = pobj;
		mdt_object_get(env, pobj);
		mdt_object_get(env, pobj);
	}

	*sobj = mdt_object_find(env, info->mti_mdt, fid);
	if (IS_ERR(*sobj)) {
		rc = PTR_ERR(*sobj);
		*sobj = NULL;
		GOTO(tpobj_put, rc);
	}

	if (!mdt_object_exists(*sobj))
		GOTO(sobj_put, rc = -ENOENT);

	return (tpindex < spindex);

sobj_put:
	mdt_object_put(env, *sobj);
	*sobj = NULL;
tpobj_put:
	mdt_object_put(env, *tpobj);
	*tpobj = NULL;
spobj_put:
	mdt_object_put(env, *spobj);
	*spobj = NULL;

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
	ldlm_lock_put(lease);

close:
	rc2 = mdt_close_internal(info, mdt_info_req(info), NULL);
	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
	repbody->mbo_valid |= OBD_MD_CLOSE_INTENT_EXECED;

	return rc ?: rc2;
}

/* LFSCK used to clear hash type and MIGRATION flag upon migration failure */
static inline bool lmv_is_failed_migration(const struct lmv_mds_md_v1 *lmv)
{
	return le32_to_cpu(lmv->lmv_hash_type) ==
		(LMV_HASH_TYPE_UNKNOWN | LMV_HASH_FLAG_BAD_TYPE) &&
	       lmv_is_known_hash_type(le32_to_cpu(lmv->lmv_migrate_hash)) &&
	       le32_to_cpu(lmv->lmv_migrate_offset) > 0 &&
	       le32_to_cpu(lmv->lmv_migrate_offset) <
		le32_to_cpu(lmv->lmv_stripe_count);
}

/*
 * migrate file in below steps:
 *  1. lock source and target stripes
 *  2. lookup source by name
 *  3. lock parents of source links if source is not directory
 *  4. reject if source is in HSM
 *  5. take source open_sem and close file if source is regular file
 *  6. lock source, and its stripes if it's directory
 *  7. migrate file
 *  8. lock target so subsequent change to it can trigger COS
 *  9. unlock above locks
 * 10. sync device if source has too many links
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
	struct mdt_object *pobj;
	struct mdt_object *spobj;
	struct mdt_object *tpobj;
	struct mdt_object *sobj;
	struct mdt_object *tobj;
	struct mdt_lock_handle *rename_lh = &info->mti_lh[MDT_LH_RMT];
	struct mdt_lock_handle *lhsp;
	struct mdt_lock_handle *lhtp;
	struct mdt_lock_handle *lhs;
	struct mdt_lock_handle *lhl;
	LIST_HEAD(link_locks);
	int lock_retries = 5;
	bool reverse = false;
	bool open_sem_locked = false;
	bool do_sync = false;
	bool is_plain_dir = false;
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

	/* we want rbac roles to have precedence over any other
	 * permission or capability checks
	 */
	if (uc && (!uc->uc_rbac_dne_ops ||
		   (!cap_raised(uc->uc_cap, CAP_SYS_ADMIN) &&
		    uc->uc_gid != mdt->mdt_enable_remote_dir_gid &&
		    mdt->mdt_enable_remote_dir_gid != -1)))
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
		rc = mdt_rename_lock(info, rename_lh);
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

	rc = mdt_check_enc(info, pobj);
	if (rc)
		GOTO(put_parent, rc);

	rc = mdt_stripe_get(info, pobj, ma, XATTR_NAME_LMV);
	if (rc)
		GOTO(put_parent, rc);

	if (CFS_FAIL_CHECK(OBD_FAIL_MIGRATE_BAD_HASH) &&
	    (ma->ma_valid & MA_LMV) &&
	    lmv_is_migrating(&ma->ma_lmv->lmv_md_v1)) {
		struct lu_buf *buf = &info->mti_buf;
		struct lmv_mds_md_v1 *lmv = &ma->ma_lmv->lmv_md_v1;
		__u32 version = le32_to_cpu(lmv->lmv_layout_version);

		lmv->lmv_hash_type = cpu_to_le32(LMV_HASH_TYPE_UNKNOWN |
						 LMV_HASH_FLAG_BAD_TYPE);
		lmv->lmv_layout_version = cpu_to_le32(version + 1);
		buf->lb_buf = lmv;
		buf->lb_len = sizeof(*lmv);
		rc = mo_xattr_set(env, mdt_object_child(pobj), buf,
				  XATTR_NAME_LMV, LU_XATTR_REPLACE);
		mo_invalidate(env, mdt_object_child(pobj));
		GOTO(put_parent, rc);
	}

	/* @spobj is the parent stripe of @sobj if @pobj is striped directory,
	 * if @pobj is migrating too, tpobj is the target parent stripe.
	 */
	rc = mdt_migrate_lookup(info, pobj, ma, &rr->rr_name, &spobj, &tpobj,
				&sobj);
	if (rc < 0)
		GOTO(put_parent, rc);
	reverse = rc;

	/* parent unchanged, this happens in dir restripe */
	if (info->mti_spec.sp_migrate_nsonly && spobj == tpobj)
		GOTO(put_source, rc = -EALREADY);

lock_parent:
	LASSERT(spobj);
	LASSERT(tpobj);
	lhsp = &info->mti_lh[MDT_LH_PARENT];
	lhtp = &info->mti_lh[MDT_LH_CHILD];
	/* lock spobj and tpobj in stripe index order */
	if (reverse) {
		rc = mdt_parent_lock(info, tpobj, lhtp, &rr->rr_name, LCK_PW);
		if (rc)
			GOTO(put_source, rc);

		LASSERT(spobj != tpobj);
		rc = mdt_parent_lock(info, spobj, lhsp, &rr->rr_name, LCK_PW);
		if (rc)
			GOTO(unlock_parent, rc);
	} else {
		rc = mdt_parent_lock(info, spobj, lhsp, &rr->rr_name, LCK_PW);
		if (rc)
			GOTO(put_source, rc);

		if (tpobj != spobj) {
			rc = mdt_parent_lock(info, tpobj, lhtp, &rr->rr_name,
					     LCK_PW);
			if (rc)
				GOTO(unlock_parent, rc);
		}
	}

	/* if inode is not migrated, or is dir, no need to lock links */
	if (!info->mti_spec.sp_migrate_nsonly &&
	    !S_ISDIR(lu_object_attr(&sobj->mot_obj))) {
		/* lock link parents, and take LOOKUP lock of links */
		rc = mdt_migrate_links_lock(info, spobj, tpobj, sobj, lhsp,
					    lhtp, &link_locks);
		if (rc == -EBUSY && lock_retries-- > 0) {
			LASSERT(list_empty(&link_locks));
			goto lock_parent;
		}

		if (rc < 0)
			GOTO(put_source, rc);

		/*
		 * RS_MAX_LOCKS is the limit of number of locks that can be
		 * saved along with one request, if total lock count exceeds
		 * this limit, we will drop all locks after migration, and
		 * trigger commit in the end.
		 */
		do_sync = rc;
	}

	/* lock source */
	lhs = &info->mti_lh[MDT_LH_OLD];
	lhl = &info->mti_lh[MDT_LH_LOOKUP];
	rc = mdt_rename_source_lock(info, spobj, sobj, lhs, lhl,
				    MDS_INODELOCK_LOOKUP | MDS_INODELOCK_XATTR |
				    MDS_INODELOCK_OPEN);
	if (rc)
		GOTO(unlock_links, rc);

	if (mdt_object_remote(sobj)) {
		struct md_attr *ma2 = &info->mti_attr2;
		ma2->ma_need = MA_INODE;
		rc = mo_attr_get(env, mdt_object_child(sobj), ma2);
		if (rc)
			GOTO(unlock_source, rc);
	}

	if (S_ISREG(lu_object_attr(&sobj->mot_obj))) {
		/* TODO: DoM migration is not supported, migrate dirent only */
		rc = mdt_stripe_get(info, sobj, ma, XATTR_NAME_LOV);
		if (rc)
			GOTO(unlock_source, rc);

		if (ma->ma_valid & MA_LOV && mdt_lmm_dom_stripesize(ma->ma_lmm))
			info->mti_spec.sp_migrate_nsonly = 1;
	} else if (S_ISDIR(lu_object_attr(&sobj->mot_obj))) {
		rc = mdt_stripe_get(info, sobj, ma, XATTR_NAME_LMV);
		if (rc)
			GOTO(unlock_source, rc);

		if (!(ma->ma_valid & MA_LMV))
			is_plain_dir = true;
		else if (lmv_is_restriping(&ma->ma_lmv->lmv_md_v1))
			/* race with restripe/auto-split */
			GOTO(unlock_source, rc = -EBUSY);
		else if (lmv_is_failed_migration(&ma->ma_lmv->lmv_md_v1)) {
			struct lu_buf *buf = &info->mti_buf;
			struct lmv_mds_md_v1 *lmv = &ma->ma_lmv->lmv_md_v1;
			__u32 version = le32_to_cpu(lmv->lmv_layout_version);

			/* migration failed before, and LFSCK cleared hash type
			 * and flags, fake it to resume migration.
			 */
			lmv->lmv_hash_type =
				cpu_to_le32(LMV_HASH_TYPE_FNV_1A_64 |
					    LMV_HASH_FLAG_MIGRATION |
					    LMV_HASH_FLAG_BAD_TYPE |
					    LMV_HASH_FLAG_FIXED);
			lmv->lmv_layout_version = cpu_to_le32(version + 1);
			buf->lb_buf = lmv;
			buf->lb_len = sizeof(*lmv);
			rc = mo_xattr_set(env, mdt_object_child(sobj), buf,
					  XATTR_NAME_LMV, LU_XATTR_REPLACE);
			mo_invalidate(env, mdt_object_child(sobj));
			GOTO(unlock_source, rc = -EALREADY);
		}
	}

	/* if migration HSM is allowed */
	if (!mdt->mdt_migrate_hsm_allowed) {
		ma->ma_need = MA_HSM;
		ma->ma_valid = 0;
		rc = mdt_attr_get_complex(info, sobj, ma);
		if (rc)
			GOTO(unlock_source, rc);

		if ((ma->ma_valid & MA_HSM) && ma->ma_hsm.mh_flags != 0)
			GOTO(unlock_source, rc = -EOPNOTSUPP);
	}

	/* end lease and close file for regular file */
	if (info->mti_spec.sp_migrate_close) {
		/* try to hold open_sem so that nobody else can open the file */
		if (!down_write_trylock(&sobj->mot_open_sem)) {
			/* close anyway */
			mdd_migrate_close(info, sobj);
			GOTO(unlock_source, rc = -EBUSY);
		} else {
			open_sem_locked = true;
			rc = mdd_migrate_close(info, sobj);
			if (rc && rc != -ESTALE)
				GOTO(unlock_open_sem, rc);
		}
	}

	tobj = mdt_object_find(env, mdt, rr->rr_fid2);
	if (IS_ERR(tobj))
		GOTO(unlock_open_sem, rc = PTR_ERR(tobj));

	/* Don't do lookup sanity check. We know name doesn't exist. */
	info->mti_spec.sp_cr_lookup = 0;
	info->mti_spec.sp_feat = &dt_directory_features;

	rc = mdo_migrate(env, mdt_object_child(spobj),
			 mdt_object_child(tpobj), mdt_object_child(sobj),
			 mdt_object_child(tobj), &rr->rr_name,
			 &info->mti_spec, ma);
	if (rc)
		GOTO(put_target, rc);

	/* save target locks for directory */
	if (S_ISDIR(lu_object_attr(&sobj->mot_obj)) &&
	    !info->mti_spec.sp_migrate_nsonly) {
		struct mdt_lock_handle *lht = &info->mti_lh[MDT_LH_NEW];
		struct ldlm_enqueue_info *einfo = &info->mti_einfo;

		/* in case sobj becomes a stripe of tobj, unlock sobj here,
		 * otherwise stripes lock may deadlock.
		 */
		if (is_plain_dir)
			mdt_rename_source_unlock(info, sobj, lhs, lhl, 1);

		rc = mdt_object_stripes_lock(info, tpobj, tobj, lht, einfo,
					     MDS_INODELOCK_UPDATE, LCK_PW);
		if (rc)
			GOTO(put_target, rc);

		mdt_object_stripes_unlock(info, tobj, lht, einfo, 0);
	}

	lprocfs_counter_incr(mdt->mdt_lu_dev.ld_obd->obd_md_stats,
			     LPROC_MDT_MIGRATE + LPROC_MD_LAST_OPC);

	EXIT;
put_target:
	mdt_object_put(env, tobj);
unlock_open_sem:
	if (open_sem_locked)
		up_write(&sobj->mot_open_sem);
unlock_source:
	mdt_rename_source_unlock(info, sobj, lhs, lhl, rc);
unlock_links:
	/* if we've got too many locks to save into RPC,
	 * then just commit before the locks are released
	 */
	if (!rc && do_sync)
		mdt_device_sync(env, mdt);
	mdt_migrate_links_unlock(info, &link_locks, do_sync ? 1 : rc);
unlock_parent:
	mdt_object_unlock(info, spobj, lhsp, rc);
	mdt_object_unlock(info, tpobj, lhtp, rc);
put_source:
	mdt_object_put(env, sobj);
	mdt_object_put(env, spobj);
	mdt_object_put(env, tpobj);
put_parent:
	mo_invalidate(env, mdt_object_child(pobj));
	mdt_object_put(env, pobj);
unlock_rename:
	mdt_rename_unlock(info, rename_lh);

	if (rc)
		CERROR("%s: migrate "DFID"/"DNAME" failed: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
		       PNAME(&rr->rr_name), rc);

	return rc;
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

/* Helper function for mdt_reint_rename so we don't need to opencode
 * two different order lockings
 */
static int mdt_lock_two_dirs(struct mdt_thread_info *info,
			     struct mdt_object *mfirstdir,
			     struct mdt_lock_handle *lh_firstdirp,
			     const struct lu_name *firstname,
			     struct mdt_object *mseconddir,
			     struct mdt_lock_handle *lh_seconddirp,
			     const struct lu_name *secondname)
{
	int rc;

	rc = mdt_parent_lock(info, mfirstdir, lh_firstdirp, firstname, LCK_PW);
	if (rc)
		return rc;

	mdt_version_get_save(info, mfirstdir, 0);
	CFS_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME, 5);

	if (mfirstdir != mseconddir) {
		rc = mdt_parent_lock(info, mseconddir, lh_seconddirp,
				     secondname, LCK_PW);
	} else if (!mdt_object_remote(mseconddir)) {
		if (lh_firstdirp->mlh_pdo_hash !=
		    lh_seconddirp->mlh_pdo_hash) {
			rc = mdt_object_pdo_lock(info, mseconddir,
						 lh_seconddirp, secondname,
						 LCK_PW, false);
			CFS_FAIL_TIMEOUT(OBD_FAIL_MDS_PDO_LOCK2, 10);
		}
	}
	mdt_version_get_save(info, mseconddir, 1);

	if (rc != 0)
		mdt_object_unlock(info, mfirstdir, lh_firstdirp, rc);

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
	struct mdt_lock_handle *rename_lh = &info->mti_lh[MDT_LH_RMT];
	struct mdt_lock_handle *lh_srcdirp;
	struct mdt_lock_handle *lh_tgtdirp;
	struct mdt_lock_handle *lh_oldp = NULL;
	struct mdt_lock_handle *lh_lookup = NULL;
	struct mdt_lock_handle *lh_newp = NULL;
	struct lu_fid *old_fid = &info->mti_tmp_fid1;
	struct lu_fid *new_fid = &info->mti_tmp_fid2;
	struct lu_ucred *uc = mdt_ucred(info);
	bool reverse = false, discard = false;
	ktime_t kstart = ktime_get();
	enum mdt_stat_idx msi = 0;
	bool remote;
	bool bfl = false;
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

	rc = mdt_check_enc(info, msrcdir);
	if (rc)
		GOTO(out_put_srcdir, rc);

	remote = mdt_object_remote(msrcdir);
	CFS_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME3, 5);

	if (lu_fid_eq(rr->rr_fid1, rr->rr_fid2)) {
		mtgtdir = msrcdir;
		mdt_object_get(info->mti_env, mtgtdir);
	} else {
		mtgtdir = mdt_parent_find_check(info, rr->rr_fid2, 1);
		if (IS_ERR(mtgtdir))
			GOTO(out_put_srcdir, rc = PTR_ERR(mtgtdir));
	}

	rc = mdt_check_enc(info, mtgtdir);
	if (rc)
		GOTO(out_put_tgtdir, rc);

	if (!uc->uc_rbac_fscrypt_admin &&
	    mtgtdir->mot_obj.lo_header->loh_attr & LOHA_FSCRYPT_MD)
		GOTO(out_put_tgtdir, rc = -EPERM);

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
		if (!mdt->mdt_enable_remote_rename && remote)
			GOTO(out_put_tgtdir, rc = -EXDEV);

		if (remote ||
		    (S_ISDIR(ma->ma_attr.la_mode) &&
		     (msrcdir != mtgtdir ||
		      !mdt->mdt_enable_parallel_rename_dir)) ||
		    (!S_ISDIR(ma->ma_attr.la_mode) &&
		     (!mdt->mdt_enable_parallel_rename_file ||
		      (msrcdir != mtgtdir &&
		       !mdt->mdt_enable_parallel_rename_crossdir)))) {
			rc = mdt_rename_lock(info, rename_lh);
			if (rc != 0) {
				CERROR("%s: cannot lock for rename: rc = %d\n",
				       mdt_obd_name(mdt), rc);
				GOTO(out_put_tgtdir, rc);
			}
			bfl = true;
		} else {
			if (S_ISDIR(ma->ma_attr.la_mode))
				msi = LPROC_MDT_RENAME_PAR_DIR;
			else
				msi = LPROC_MDT_RENAME_PAR_FILE;

			CDEBUG(D_INFO,
			       "%s: %s %s parallel rename "DFID"/"DNAME"\n",
			       mdt_obd_name(mdt),
			       msrcdir == mtgtdir ? "samedir" : "crossdir",
			       S_ISDIR(ma->ma_attr.la_mode) ? "dir" : "file",
			       PFID(rr->rr_fid1), PNAME(&rr->rr_name));
		}
	}

lock_parents:
	rc = mdt_rename_determine_lock_order(info, msrcdir, mtgtdir);
	if (rc < 0)
		GOTO(out_unlock_rename, rc);
	reverse = rc;

	CFS_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME4, 5);
	CFS_RACE(OBD_FAIL_MDS_REINT_OPEN);
	CFS_RACE(OBD_FAIL_MDS_REINT_OPEN2);

	/* lock parents in the proper order. */
	lh_srcdirp = &info->mti_lh[MDT_LH_PARENT];
	lh_tgtdirp = &info->mti_lh[MDT_LH_CHILD];
	mdt_lock_pdo_init(lh_srcdirp, LCK_PW, &rr->rr_name);
	mdt_lock_pdo_init(lh_tgtdirp, LCK_PW, &rr->rr_tgt_name);

	/* In case of same dir local rename we must sort by the hash,
	 * otherwise a lock deadlock is possible when renaming
	 * a to b and b to a at the same time LU-15285
	 */
	if (!mdt_object_remote(mtgtdir) && mtgtdir == msrcdir)
		reverse = lh_srcdirp->mlh_pdo_hash > lh_tgtdirp->mlh_pdo_hash;
	if (unlikely(CFS_FAIL_PRECHECK(OBD_FAIL_MDS_PDO_LOCK)))
		reverse = 0;

	if (reverse)
		rc = mdt_lock_two_dirs(info, mtgtdir, lh_tgtdirp,
				       &rr->rr_tgt_name, msrcdir, lh_srcdirp,
				       &rr->rr_name);
	else
		rc = mdt_lock_two_dirs(info, msrcdir, lh_srcdirp, &rr->rr_name,
				       mtgtdir, lh_tgtdirp, &rr->rr_tgt_name);

	if (rc != 0)
		GOTO(out_unlock_rename, rc);

	CFS_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME4, 5);
	CFS_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME2, 5);

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

	/* we used msrcdir as a hint to take BFL, but it may be wrong */
	if (unlikely(!bfl && !req_is_replay(req) &&
		     !S_ISDIR(ma->ma_attr.la_mode) &&
		     mdt_object_remote(mold))) {
		LASSERT(!remote);
		mdt_object_put(info->mti_env, mold);
		mdt_object_unlock(info, mtgtdir, lh_tgtdirp, rc);
		mdt_object_unlock(info, msrcdir, lh_srcdirp, rc);

		rc = mdt_rename_lock(info, rename_lh);
		if (rc != 0) {
			CERROR("%s: cannot re-lock for rename: rc = %d\n",
			       mdt_obd_name(mdt), rc);
			GOTO(out_put_tgtdir, rc);
		}
		bfl = true;
		msi = 0;
		goto lock_parents;
	}

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

	/* find mnew object:
	 * mnew target object may not exist now
	 * lookup with version checking
	 */
	fid_zero(new_fid);
	rc = mdt_lookup_version_check(info, mtgtdir, &rr->rr_tgt_name, new_fid,
				      3);
	if (rc == 0) {
		bool child_reverse_lock = false;

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
		lh_newp = &info->mti_lh[MDT_LH_NEW];

		/* We will lock in child fid order here to avoid a
		 * deadlock related to hardlinks thats only possible with
		 * regular files. LU-15491
		 */
		if (!S_ISDIR(lu_object_attr(&mold->mot_obj)) &&
		    lu_fid_cmp(old_fid, new_fid) > 0) {
			child_reverse_lock = true;
			rc = mdt_object_check_lock(info, mtgtdir, mnew, lh_newp,
						   MDS_INODELOCK_LOOKUP |
						   MDS_INODELOCK_UPDATE,
						   LCK_EX);
			if (rc < 0)
				GOTO(out_unlock_new, rc);
		}

		lh_lookup = &info->mti_lh[MDT_LH_LOOKUP];
		rc = mdt_rename_source_lock(info, msrcdir, mold, lh_oldp,
					    lh_lookup,
					    MDS_INODELOCK_LOOKUP |
					    MDS_INODELOCK_XATTR);
		if (rc < 0)
			GOTO(out_unlock_new, rc);

		/* save version after locking */
		mdt_version_get_save(info, mold, 2);

		/* Check if @msrcdir is subdir of @mnew, before locking child
		 * to avoid reverse locking.
		 */
		if (mtgtdir != msrcdir) {
			rc = mdo_is_subdir(info->mti_env,
					   mdt_object_child(msrcdir), new_fid);
			if (rc) {
				if (rc == 1)
					rc = -EINVAL;
				GOTO(out_unlock_new, rc);
			}
		}

		/* We used to acquire MDS_INODELOCK_FULL here but we
		 * can't do this now because a running HSM restore on
		 * the rename onto victim will hold the layout
		 * lock. See LU-4002.
		 */

		if (!child_reverse_lock) {
			rc = mdt_object_check_lock(info, mtgtdir, mnew, lh_newp,
						   MDS_INODELOCK_LOOKUP |
						   MDS_INODELOCK_UPDATE,
						   LCK_EX);
			if (rc != 0)
				GOTO(out_unlock_new, rc);
		}

		/* get and save version after locking */
		mdt_version_get_save(info, mnew, 3);
	} else if (rc != -ENOENT) {
		GOTO(out_put_old, rc);
	} else {
		lh_oldp = &info->mti_lh[MDT_LH_OLD];
		lh_lookup = &info->mti_lh[MDT_LH_LOOKUP];
		rc = mdt_rename_source_lock(info, msrcdir, mold, lh_oldp,
					    lh_lookup,
					    MDS_INODELOCK_LOOKUP |
					    MDS_INODELOCK_XATTR);
		if (rc != 0)
			GOTO(out_put_old, rc);

		mdt_version_get_save(info, mold, 2);
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
		if (mnew) {
			mdt_handle_last_unlink(info, mnew, ma);
			discard = mdt_dom_check_for_discard(info, mnew);
		}
		mdt_rename_counter_tally(info, info->mti_mdt, req,
					 msrcdir, mtgtdir, msi,
					 ktime_us_delta(ktime_get(), kstart));
	}

	EXIT;
out_unlock_new:
	if (mnew != NULL)
		/* mnew is gone, no need to keep lock */
		mdt_object_unlock(info, mnew, lh_newp, 1);

	mdt_object_unlock(info, NULL, lh_lookup, rc);
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
	mdt_rename_unlock(info, rename_lh);
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
	CFS_RACE(OBD_FAIL_MDS_LINK_RENAME_RACE);
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
	int rc;

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
	ldlm_lock_put(lease);
out_obj:
	mdt_object_put(info->mti_env, mo);
out:
	mdt_client_compatibility(info);
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
