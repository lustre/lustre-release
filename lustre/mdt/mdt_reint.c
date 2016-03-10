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
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
static int mdt_lookup_version_check(struct mdt_thread_info *info,
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

static inline int mdt_remote_permission_check(struct mdt_thread_info *info)
{
	struct lu_ucred	*uc  = mdt_ucred(info);
	struct mdt_device *mdt = info->mti_mdt;

	if (!md_capable(uc, CFS_CAP_SYS_ADMIN)) {
		if (uc->uc_gid != mdt->mdt_enable_remote_dir_gid &&
		    mdt->mdt_enable_remote_dir_gid != -1)
			return -EPERM;
	}

	return 0;
}

/**
 * mdt_remote_permission: Check whether the remote operation is permitted,
 *
 * Only sysadmin can create remote directory / striped directory,
 * migrate directory and set default stripedEA on directory, unless
 *
 * lctl set_param mdt.*.enable_remote_dir_gid=allow_gid.
 *
 * param[in] info: mdt_thread_info.
 *
 * retval	= 0 remote operation is allowed.
 *              < 0 remote operation is denied.
 */
static int mdt_remote_permission(struct mdt_thread_info *info)
{
	struct md_op_spec *spec = &info->mti_spec;
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct obd_export *exp = mdt_info_req(info)->rq_export;
	int rc;

	if (info->mti_rr.rr_opcode == REINT_MIGRATE) {
		rc = mdt_remote_permission_check(info);
		if (rc != 0)
			return rc;
	}

	if (info->mti_rr.rr_opcode == REINT_CREATE &&
	    (S_ISDIR(attr->la_mode) && spec->u.sp_ea.eadata != NULL &&
	     spec->u.sp_ea.eadatalen != 0)) {
		const struct lmv_user_md *lum = spec->u.sp_ea.eadata;

		/* Only new clients can create remote dir( >= 2.4) and
		 * striped dir(>= 2.6), old client will return -ENOTSUPP */
		if (!mdt_is_dne_client(exp))
			return -ENOTSUPP;

		if (le32_to_cpu(lum->lum_stripe_count) > 1 &&
		    !mdt_is_striped_client(exp))
			return -ENOTSUPP;

		rc = mdt_remote_permission_check(info);
		if (rc != 0)
			return rc;
	}

	if (info->mti_rr.rr_opcode == REINT_SETATTR) {
		struct md_attr *ma = &info->mti_attr;

		if ((ma->ma_valid & MA_LMV)) {
			rc = mdt_remote_permission_check(info);
			if (rc != 0)
				return rc;
		}
	}

	return 0;
}

static int mdt_unlock_slaves(struct mdt_thread_info *mti,
			     struct mdt_object *obj, __u64 ibits,
			     struct mdt_lock_handle *s0_lh,
			     struct mdt_object *s0_obj,
			     struct ldlm_enqueue_info *einfo,
			     int decref)
{
	union ldlm_policy_data *policy = &mti->mti_policy;
	struct lustre_handle_array *slave_locks = einfo->ei_cbdata;
	int i;
	int rc;
	ENTRY;

	if (!S_ISDIR(obj->mot_header.loh_attr))
		RETURN(0);

	/* Unlock stripe 0 */
	if (s0_lh != NULL && lustre_handle_is_used(&s0_lh->mlh_reg_lh)) {
		LASSERT(s0_obj != NULL);
		mdt_object_unlock_put(mti, s0_obj, s0_lh, decref);
	}

	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = ibits;

	if (slave_locks != NULL) {
		LASSERT(s0_lh != NULL);
		for (i = 1; i < slave_locks->count; i++) {
			/* borrow s0_lh temporarily to do mdt unlock */
			mdt_lock_reg_init(s0_lh, einfo->ei_mode);
			s0_lh->mlh_rreg_lh = slave_locks->handles[i];
			mdt_object_unlock(mti, NULL, s0_lh, decref);
			slave_locks->handles[i].cookie = 0ull;
		}
	}

	rc = mo_object_unlock(mti->mti_env, mdt_object_child(obj), einfo,
			      policy);
	RETURN(rc);
}

static int mdt_init_slaves(struct mdt_thread_info *mti, struct mdt_object *obj,
			   struct lu_fid *fid)
{
	struct lu_buf *buf = &mti->mti_buf;
	struct lmv_mds_md_v1 *lmv;
	int rc;
	ENTRY;

	if (!S_ISDIR(obj->mot_header.loh_attr))
		RETURN(0);

	buf->lb_buf = mti->mti_xattr_buf;
	buf->lb_len = sizeof(mti->mti_xattr_buf);
	rc = mo_xattr_get(mti->mti_env, mdt_object_child(obj), buf,
			  XATTR_NAME_LMV);
	if (rc == -ERANGE) {
		rc = mdt_big_xattr_get(mti, obj, XATTR_NAME_LMV);
		if (rc > 0) {
			buf->lb_buf = mti->mti_big_lmm;
			buf->lb_len = mti->mti_big_lmmsize;
		}
	}

	if (rc == -ENODATA || rc == -ENOENT)
		RETURN(0);

	if (rc <= 0)
		RETURN(rc);

	lmv = buf->lb_buf;
	if (le32_to_cpu(lmv->lmv_magic) != LMV_MAGIC_V1)
		RETURN(-EINVAL);

	fid_le_to_cpu(fid, &lmv->lmv_stripe_fids[0]);

	RETURN(rc);
}

/**
 * Lock slave stripes if necessary, the lock handles of slave stripes
 * will be stored in einfo->ei_cbdata.
 **/
static int mdt_lock_slaves(struct mdt_thread_info *mti, struct mdt_object *obj,
			   enum ldlm_mode mode, __u64 ibits,
			   struct lu_fid *s0_fid,
			   struct mdt_lock_handle *s0_lh,
			   struct mdt_object **s0_objp,
			   struct ldlm_enqueue_info *einfo)
{
	union ldlm_policy_data *policy = &mti->mti_policy;
	int rc;
	ENTRY;

	memset(einfo, 0, sizeof(*einfo));

	rc = mdt_init_slaves(mti, obj, s0_fid);
	if (rc <= 0)
		RETURN(rc);

	LASSERT(S_ISDIR(obj->mot_header.loh_attr));

	if (!lu_fid_eq(s0_fid, mdt_object_fid(obj))) {
		/* Except migrating object, whose 0_stripe and master
		 * object are the same object, 0_stripe and master
		 * object are different, though they are in the same
		 * MDT, to avoid adding osd_object_lock here, so we
		 * will enqueue the stripe0 lock in MDT0 for now */
		*s0_objp = mdt_object_find(mti->mti_env, mti->mti_mdt, s0_fid);
		if (IS_ERR(*s0_objp))
			RETURN(PTR_ERR(*s0_objp));

		rc = mdt_reint_object_lock(mti, *s0_objp, s0_lh, ibits, true);
		if (rc < 0) {
			mdt_object_put(mti->mti_env, *s0_objp);
			RETURN(rc);
		}
	}

	einfo->ei_type = LDLM_IBITS;
	einfo->ei_mode = mode;
	einfo->ei_cb_bl = mdt_remote_blocking_ast;
	einfo->ei_cb_local_bl = mdt_blocking_ast;
	einfo->ei_cb_cp = ldlm_completion_ast;
	einfo->ei_enq_slave = 1;
	einfo->ei_namespace = mti->mti_mdt->mdt_namespace;
	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = ibits;

	rc = mo_object_lock(mti->mti_env, mdt_object_child(obj), NULL, einfo,
			    policy);
	RETURN(rc);
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
	struct mdt_device       *mdt = info->mti_mdt;
	struct mdt_object       *parent;
	struct mdt_object       *child;
	struct mdt_lock_handle  *lh;
	struct mdt_body         *repbody;
	struct md_attr          *ma = &info->mti_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	int rc;
	ENTRY;

	DEBUG_REQ(D_INODE, mdt_info_req(info), "Create  ("DNAME"->"DFID") "
		  "in "DFID,
		  PNAME(&rr->rr_name), PFID(rr->rr_fid2), PFID(rr->rr_fid1));

	if (!fid_is_md_operative(rr->rr_fid1))
		RETURN(-EPERM);

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

	parent = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(parent))
		RETURN(PTR_ERR(parent));

	if (!mdt_object_exists(parent))
		GOTO(put_parent, rc = -ENOENT);

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

	/*
	 * Check child name version during replay.
	 * During create replay a file may exist with same name.
	 */
	rc = mdt_lookup_version_check(info, parent, &rr->rr_name,
				      &info->mti_tmp_fid1, 1);
	if (rc == 0)
		GOTO(unlock_parent, rc = -EEXIST);

	/* -ENOENT is expected here */
	if (rc != -ENOENT)
		GOTO(unlock_parent, rc);

	/* save version of file name for replay, it must be ENOENT here */
	mdt_enoent_version_save(info, 1);

	child = mdt_object_new(info->mti_env, mdt, rr->rr_fid2);
	if (unlikely(IS_ERR(child)))
		GOTO(unlock_parent, rc = PTR_ERR(child));

	rc = mdt_remote_permission(info);
	if (rc != 0)
		GOTO(put_child, rc);

	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;

	mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
			OBD_FAIL_MDS_REINT_CREATE_WRITE);

	/* Version of child will be updated on disk. */
	tgt_vbr_obj_set(info->mti_env, mdt_obj2dt(child));
	rc = mdt_version_get_check_save(info, child, 2);
	if (rc)
		GOTO(put_child, rc);

	/* Let lower layer know current lock mode. */
	info->mti_spec.sp_cr_mode = mdt_dlm_mode2mdl_mode(lh->mlh_pdo_mode);

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
		struct mdt_lock_handle *s0_lh;
		struct mdt_object *s0_obj = NULL;
		struct ldlm_enqueue_info *einfo;
		struct lu_fid *s0_fid = &info->mti_tmp_fid1;
		bool cos_incompat = false;

		rc = mdt_init_slaves(info, child, s0_fid);
		if (rc > 0) {
			cos_incompat = true;
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

		einfo = &info->mti_einfo;
		lhc = &info->mti_lh[MDT_LH_CHILD];
		mdt_lock_handle_init(lhc);
		mdt_lock_reg_init(lhc, LCK_PW);
		rc = mdt_reint_object_lock(info, child, lhc,
					   MDS_INODELOCK_UPDATE,
					   cos_incompat);
		if (rc)
			GOTO(put_child, rc);
		mdt_object_unlock(info, child, lhc, rc);

		s0_lh = &info->mti_lh[MDT_LH_LOCAL];
		mdt_lock_handle_init(s0_lh);
		mdt_lock_reg_init(s0_lh, LCK_PW);
		rc = mdt_lock_slaves(info, child, LCK_PW, MDS_INODELOCK_UPDATE,
				     s0_fid, s0_lh, &s0_obj, einfo);
		mdt_unlock_slaves(info, child, MDS_INODELOCK_UPDATE, s0_lh,
				  s0_obj, einfo, rc);
		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_NAME) && rc == -EIO)
			rc = 0;
	}

	/* Return fid & attr to client. */
	if (ma->ma_valid & MA_INODE)
		mdt_pack_attr2body(info, repbody, &ma->ma_attr,
				   mdt_object_fid(child));
put_child:
	mdt_object_put(info->mti_env, child);
unlock_parent:
	mdt_object_unlock(info, parent, lh, rc);
put_parent:
	mdt_object_put(info->mti_env, parent);
	RETURN(rc);
}

static int mdt_attr_set(struct mdt_thread_info *info, struct mdt_object *mo,
			struct md_attr *ma)
{
	struct mdt_lock_handle  *lh;
	int do_vbr = ma->ma_attr.la_valid &
			(LA_MODE | LA_UID | LA_GID | LA_PROJID | LA_FLAGS);
	__u64 lockpart = MDS_INODELOCK_UPDATE;
	struct ldlm_enqueue_info *einfo = &info->mti_einfo;
	struct lu_fid *s0_fid = &info->mti_tmp_fid1;
	struct mdt_lock_handle *s0_lh = NULL;
	struct mdt_object *s0_obj = NULL;
	bool cos_incompat = false;
	int rc;
	ENTRY;

	rc = mdt_init_slaves(info, mo, s0_fid);
	if (rc > 0)
		cos_incompat = true;

        lh = &info->mti_lh[MDT_LH_PARENT];
        mdt_lock_reg_init(lh, LCK_PW);

	/* Even though the new MDT will grant PERM lock to the old
	 * client, but the old client will almost ignore that during
	 * So it needs to revoke both LOOKUP and PERM lock here, so
	 * both new and old client can cancel the dcache */
	if (ma->ma_attr.la_valid & (LA_MODE|LA_UID|LA_GID))
		lockpart |= MDS_INODELOCK_LOOKUP | MDS_INODELOCK_PERM;

	rc = mdt_reint_object_lock(info, mo, lh, lockpart, cos_incompat);
	if (rc != 0)
		RETURN(rc);

	s0_lh = &info->mti_lh[MDT_LH_LOCAL];
	mdt_lock_reg_init(s0_lh, LCK_PW);
	rc = mdt_lock_slaves(info, mo, LCK_PW, lockpart, s0_fid, s0_lh, &s0_obj,
			     einfo);
	if (rc != 0)
		GOTO(out_unlock, rc);

        /* all attrs are packed into mti_attr in unpack_setattr */
        mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_SETATTR_WRITE);

        /* This is only for set ctime when rename's source is on remote MDS. */
        if (unlikely(ma->ma_attr.la_valid == LA_CTIME))
                ma->ma_attr_flags |= MDS_VTX_BYPASS;

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

        EXIT;
out_unlock:
	mdt_unlock_slaves(info, mo, lockpart, s0_lh, s0_obj, einfo, rc);
        mdt_object_unlock(info, mo, lh, rc);
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

		rc = mdt_hsm_attr_set(info, mo, &ma->ma_hsm);
		if (rc)
			CERROR("file attribute change error for "DFID": %d\n",
				PFID(mdt_object_fid(mo)), rc);
	}

	RETURN(rc);
}

static int mdt_reint_setattr(struct mdt_thread_info *info,
                             struct mdt_lock_handle *lhc)
{
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_object       *mo;
        struct mdt_body         *repbody;
	int			 rc, rc2;
        ENTRY;

        DEBUG_REQ(D_INODE, req, "setattr "DFID" %x", PFID(rr->rr_fid1),
                  (unsigned int)ma->ma_attr.la_valid);

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        mo = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
        if (IS_ERR(mo))
                GOTO(out, rc = PTR_ERR(mo));

	if (!mdt_object_exists(mo))
		GOTO(out_put, rc = -ENOENT);

	if (mdt_object_remote(mo))
		GOTO(out_put, rc = -EREMOTE);

	if ((ma->ma_attr.la_valid & LA_SIZE) ||
	    (rr->rr_flags & MRF_OPEN_TRUNC)) {
		/* Check write access for the O_TRUNC case */
		if (mdt_write_read(mo) < 0)
			GOTO(out_put, rc = -ETXTBSY);
	}

	if ((ma->ma_valid & MA_INODE) && ma->ma_attr.la_valid) {
		if (ma->ma_valid & MA_LOV)
			GOTO(out_put, rc = -EPROTO);

		rc = mdt_attr_set(info, mo, ma);
		if (rc)
			GOTO(out_put, rc);
	} else if ((ma->ma_valid & (MA_LOV | MA_LMV)) &&
		   (ma->ma_valid & MA_INODE)) {
		struct lu_buf *buf  = &info->mti_buf;
		struct mdt_lock_handle  *lh;

		rc = mdt_remote_permission(info);
		if (rc < 0)
			GOTO(out_put, rc);

		if (ma->ma_attr.la_valid != 0)
			GOTO(out_put, rc = -EPROTO);

		lh = &info->mti_lh[MDT_LH_PARENT];
		mdt_lock_reg_init(lh, LCK_PW);

		rc = mdt_object_lock(info, mo, lh, MDS_INODELOCK_XATTR);
		if (rc != 0)
			GOTO(out_put, rc);

		if (ma->ma_valid & MA_LOV) {
			buf->lb_buf = ma->ma_lmm;
			buf->lb_len = ma->ma_lmm_size;
		} else {
			buf->lb_buf = ma->ma_lmv;
			buf->lb_len = ma->ma_lmv_size;
		}
		rc = mo_xattr_set(info->mti_env, mdt_object_child(mo), buf,
				  (ma->ma_valid & MA_LOV) ?
					XATTR_NAME_LOV : XATTR_NAME_DEFAULT_LMV,
				  0);

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
		mdt_counter_incr(req, LPROC_MDT_SETATTR);

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
		mdt_counter_incr(req, LPROC_MDT_MKDIR);
		break;
        case S_IFREG:
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
	case S_IFSOCK:
		/* Special file should stay on the same node as parent. */
		mdt_counter_incr(req, LPROC_MDT_MKNOD);
		break;
	default:
		CERROR("%s: Unsupported mode %o\n",
		       mdt_obd_name(info->mti_mdt),
		       info->mti_attr.ma_attr.la_mode);
		RETURN(err_serious(-EOPNOTSUPP));
	}

	rc = mdt_create(info);
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
	struct lu_fid *s0_fid = &info->mti_tmp_fid2;
	struct mdt_lock_handle *s0_lh = NULL;
	struct mdt_object *s0_obj = NULL;
	__u64 lock_ibits;
	bool cos_incompat = false;
	int no_name = 0;
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

relock:
	parent_lh = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_pdo_init(parent_lh, LCK_PW, &rr->rr_name);
	rc = mdt_reint_object_lock(info, mp, parent_lh, MDS_INODELOCK_UPDATE,
				   cos_incompat);
	if (rc != 0)
		GOTO(put_parent, rc);

	/* lookup child object along with version checking */
	fid_zero(child_fid);
	rc = mdt_lookup_version_check(info, mp, &rr->rr_name, child_fid, 1);
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
		 * */
		if (mdt_object_remote(mp) && rc == -ENOENT &&
		    !fid_is_zero(rr->rr_fid2) &&
		    lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
			no_name = 1;
			*child_fid = *rr->rr_fid2;
		 } else {
			GOTO(unlock_parent, rc);
		 }
	}

	if (!fid_is_md_operative(child_fid))
		GOTO(unlock_parent, rc = -EPERM);

	/* We will lock the child regardless it is local or remote. No harm. */
	mc = mdt_object_find(info->mti_env, info->mti_mdt, child_fid);
	if (IS_ERR(mc))
		GOTO(unlock_parent, rc = PTR_ERR(mc));

	if (!cos_incompat && mdt_init_slaves(info, mc, s0_fid) > 0) {
		cos_incompat = true;
		mdt_object_put(info->mti_env, mc);
		mdt_object_unlock(info, mp, parent_lh, -EAGAIN);
		goto relock;
	}

	child_lh = &info->mti_lh[MDT_LH_CHILD];
	mdt_lock_reg_init(child_lh, LCK_EX);
	if (info->mti_spec.sp_rm_entry) {
		struct lu_ucred *uc  = mdt_ucred(info);

		if (!mdt_is_dne_client(req->rq_export))
			/* Return -ENOTSUPP for old client */
			GOTO(put_child, rc = -ENOTSUPP);

		if (!md_capable(uc, CFS_CAP_SYS_ADMIN))
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
		 * lock at the same time with unlink XXX */
		mdt_object_lock(info, mc, child_lh, MDS_INODELOCK_LOOKUP);
		repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		LASSERT(repbody != NULL);
		repbody->mbo_fid1 = *mdt_object_fid(mc);
		repbody->mbo_valid |= (OBD_MD_FLID | OBD_MD_MDS);
		GOTO(unlock_child, rc = -EREMOTE);
	}
	/* We used to acquire MDS_INODELOCK_FULL here but we can't do
	 * this now because a running HSM restore on the child (unlink
	 * victim) will hold the layout lock. See LU-4002. */
	lock_ibits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE;
	if (mdt_object_remote(mp)) {
		/* Enqueue lookup lock from parent MDT */
		rc = mdt_remote_object_lock(info, mp, mdt_object_fid(mc),
					    &child_lh->mlh_rreg_lh,
					    child_lh->mlh_rreg_mode,
					    MDS_INODELOCK_LOOKUP, false, false);
		if (rc != ELDLM_OK)
			GOTO(put_child, rc);

		lock_ibits &= ~MDS_INODELOCK_LOOKUP;
	}

	rc = mdt_reint_object_lock(info, mc, child_lh, lock_ibits,
				   cos_incompat);
	if (rc != 0)
		GOTO(unlock_child, rc);

	/*
	 * Now we can only make sure we need MA_INODE, in mdd layer, will check
	 * whether need MA_LOV and MA_COOKIE.
	 */
	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;

	s0_lh = &info->mti_lh[MDT_LH_LOCAL];
	mdt_lock_reg_init(s0_lh, LCK_EX);
	rc = mdt_lock_slaves(info, mc, LCK_EX, MDS_INODELOCK_UPDATE, s0_fid,
			     s0_lh, &s0_obj, einfo);
	if (rc != 0)
		GOTO(unlock_child, rc);

	mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
		       OBD_FAIL_MDS_REINT_UNLINK_WRITE);
	/* save version when object is locked */
	mdt_version_get_save(info, mc, 1);

	mutex_lock(&mc->mot_lov_mutex);

	rc = mdo_unlink(info->mti_env, mdt_object_child(mp),
			mdt_object_child(mc), &rr->rr_name, ma, no_name);

	mutex_unlock(&mc->mot_lov_mutex);

	if (rc == 0 && !lu_object_is_dying(&mc->mot_header))
		rc = mdt_attr_get_complex(info, mc, ma);
	if (rc == 0)
		mdt_handle_last_unlink(info, mc, ma);

        if (ma->ma_valid & MA_INODE) {
                switch (ma->ma_attr.la_mode & S_IFMT) {
                case S_IFDIR:
			mdt_counter_incr(req, LPROC_MDT_RMDIR);
                        break;
                case S_IFREG:
                case S_IFLNK:
                case S_IFCHR:
                case S_IFBLK:
                case S_IFIFO:
                case S_IFSOCK:
			mdt_counter_incr(req, LPROC_MDT_UNLINK);
                        break;
                default:
                        LASSERTF(0, "bad file type %o unlinking\n",
                                 ma->ma_attr.la_mode);
                }
        }

        EXIT;

unlock_child:
	mdt_unlock_slaves(info, mc, MDS_INODELOCK_UPDATE, s0_lh, s0_obj, einfo,
			  rc);
	mdt_object_unlock(info, mc, child_lh, rc);
put_child:
	mdt_object_put(info->mti_env, mc);
unlock_parent:
	mdt_object_unlock(info, mp, parent_lh, rc);
put_parent:
	mdt_object_put(info->mti_env, mp);
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
	bool cos_incompat;
	int rc;
	ENTRY;

	DEBUG_REQ(D_INODE, req, "link "DFID" to "DFID"/"DNAME,
		  PFID(rr->rr_fid1), PFID(rr->rr_fid2), PNAME(&rr->rr_name));

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK))
		RETURN(err_serious(-ENOENT));

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	/* Invalid case so return error immediately instead of
	 * processing it */
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
		mdt_counter_incr(req, LPROC_MDT_LINK);

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
	rc = mdt_fid_lock(ns, &lh->mlh_reg_lh, lh->mlh_reg_mode, policy,
			  res, dlmflags, &info->mti_exp->exp_handle.h_cookie);
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
		 * rename lock(with LUSTRE_BFL_FID) by root object */
		lu_root_fid(fid);
		obj = mdt_object_find(info->mti_env, info->mti_mdt, fid);
		if (IS_ERR(obj))
			RETURN(PTR_ERR(obj));

		rc = mdt_remote_object_lock(info, obj,
					    &LUSTRE_BFL_FID, lh,
					    LCK_EX,
					    MDS_INODELOCK_UPDATE, false, false);
		mdt_object_put(info->mti_env, obj);
	} else {
		struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
		union ldlm_policy_data *policy = &info->mti_policy;
		struct ldlm_res_id *res_id = &info->mti_res_id;
		__u64 flags = 0;

		fid_build_reg_res_name(&LUSTRE_BFL_FID, res_id);
		memset(policy, 0, sizeof *policy);
		policy->l_inodebits.bits = MDS_INODELOCK_UPDATE;
		flags = LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB;
		rc = ldlm_cli_enqueue_local(ns, res_id, LDLM_IBITS, policy,
					   LCK_EX, &flags, ldlm_blocking_ast,
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

/*
 * This is is_subdir() variant, it is CMD if cmm forwards it to correct
 * target. Source should not be ancestor of target dir. May be other rename
 * checks can be moved here later.
 */
static int mdt_is_subdir(struct mdt_thread_info *info,
			 struct mdt_object *dir,
			 const struct lu_fid *fid)
{
	struct lu_fid dir_fid = dir->mot_header.loh_fid;
        int rc = 0;
        ENTRY;

	/* If the source and target are in the same directory, they can not
	 * be parent/child relationship, so subdir check is not needed */
	if (lu_fid_eq(&dir_fid, fid))
		return 0;

	if (!mdt_object_exists(dir))
		RETURN(-ENOENT);

	rc = mdo_is_subdir(info->mti_env, mdt_object_child(dir),
			   fid, &dir_fid);
	if (rc < 0) {
		CERROR("%s: failed subdir check in "DFID" for "DFID
		       ": rc = %d\n", mdt_obd_name(info->mti_mdt),
		       PFID(&dir_fid), PFID(fid), rc);
		/* Return EINVAL only if a parent is the @fid */
		if (rc == -EINVAL)
			rc = -EIO;
	} else {
		/* check the found fid */
		if (lu_fid_eq(&dir_fid, fid))
			rc = -EINVAL;
	}

        RETURN(rc);
}

/* Update object linkEA */
struct mdt_lock_list {
	struct mdt_object	*mll_obj;
	struct mdt_lock_handle	mll_lh;
	struct list_head	mll_list;
};

static void mdt_unlock_list(struct mdt_thread_info *info,
			    struct list_head *list, int rc)
{
	struct mdt_lock_list *mll;
	struct mdt_lock_list *mll2;

	list_for_each_entry_safe(mll, mll2, list, mll_list) {
		mdt_object_unlock_put(info, mll->mll_obj, &mll->mll_lh, rc);
		list_del(&mll->mll_list);
		OBD_FREE_PTR(mll);
	}
}

static int mdt_lock_objects_in_linkea(struct mdt_thread_info *info,
				      struct mdt_object *obj,
				      struct mdt_object *pobj,
				      struct list_head *lock_list)
{
	struct lu_buf		*buf = &info->mti_big_buf;
	struct linkea_data	ldata = { NULL };
	int			count;
	int			retry_count;
	int			rc;
	ENTRY;

	if (S_ISDIR(lu_object_attr(&obj->mot_obj)))
		RETURN(0);

	buf = lu_buf_check_and_alloc(buf, PATH_MAX);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);

	ldata.ld_buf = buf;
	rc = mdt_links_read(info, obj, &ldata);
	if (rc != 0) {
		if (rc == -ENOENT || rc == -ENODATA)
			rc = 0;
		RETURN(rc);
	}

	/* ignore the migrating parent(@pobj) */
	retry_count = ldata.ld_leh->leh_reccount - 1;

again:
	LASSERT(ldata.ld_leh != NULL);
	ldata.ld_lee = (struct link_ea_entry *)(ldata.ld_leh + 1);
	for (count = 0; count < ldata.ld_leh->leh_reccount; count++) {
		struct mdt_device *mdt = info->mti_mdt;
		struct mdt_object *mdt_pobj;
		struct mdt_lock_list *mll;
		struct lu_name name;
		struct lu_fid  fid;

		linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen,
				    &name, &fid);
		mdt_pobj = mdt_object_find(info->mti_env, mdt, &fid);
		if (IS_ERR(mdt_pobj)) {
			CWARN("%s: cannot find obj "DFID": rc = %ld\n",
			      mdt_obd_name(mdt), PFID(&fid), PTR_ERR(mdt_pobj));
			goto next;
		}

		if (!mdt_object_exists(mdt_pobj)) {
			CDEBUG(D_INFO, "%s: obj "DFID" does not exist\n",
			      mdt_obd_name(mdt), PFID(&fid));
			mdt_object_put(info->mti_env, mdt_pobj);
			goto next;
		}

		/* Check if the object already exists in the list */
		list_for_each_entry(mll, lock_list, mll_list) {
			if (mll->mll_obj == mdt_pobj) {
				mdt_object_put(info->mti_env, mdt_pobj);
				goto next;
			}
		}

		if (mdt_pobj == pobj) {
			CDEBUG(D_INFO, "%s: skipping parent obj "DFID"\n",
			       mdt_obd_name(mdt), PFID(&fid));
			mdt_object_put(info->mti_env, mdt_pobj);
			goto next;
		}

		OBD_ALLOC_PTR(mll);
		if (mll == NULL) {
			mdt_object_put(info->mti_env, mdt_pobj);
			GOTO(out, rc = -ENOMEM);
		}

		/* Since this needs to lock all of objects in linkea, to avoid
		 * deadlocks, because it does not follow parent-child order as
		 * other MDT operation, let's use try_lock here and if the lock
		 * cannot be gotten because of conflicting locks, then drop all
		 * current locks, send an AST to the client, and start again. */
		mdt_lock_pdo_init(&mll->mll_lh, LCK_PW, &name);
		rc = mdt_reint_object_lock_try(info, mdt_pobj, &mll->mll_lh,
						MDS_INODELOCK_UPDATE, true);
		if (rc == 0) {
			mdt_unlock_list(info, lock_list, rc);

			CDEBUG(D_INFO, "%s: busy lock on "DFID" %s retry %d\n",
			       mdt_obd_name(mdt), PFID(&fid), name.ln_name,
			       retry_count);

			if (retry_count == 0) {
				mdt_object_put(info->mti_env, mdt_pobj);
				OBD_FREE_PTR(mll);
				GOTO(out, rc = -EBUSY);
			}

			rc = mdt_object_lock(info, mdt_pobj, &mll->mll_lh,
					     MDS_INODELOCK_UPDATE);
			if (rc != 0) {
				mdt_object_put(info->mti_env, mdt_pobj);
				OBD_FREE_PTR(mll);
				GOTO(out, rc);
			}

			if (mdt_object_remote(mdt_pobj)) {
				struct ldlm_lock *lock;

				/* For remote object, Set lock to cb_atomic,
				 * so lock can be released in blocking_ast()
				 * immediately, then the next try_lock will
				 * have better chance to succeds */
				lock =
				ldlm_handle2lock(&mll->mll_lh.mlh_rreg_lh);
				LASSERT(lock != NULL);
				lock_res_and_lock(lock);
				ldlm_set_atomic_cb(lock);
				unlock_res_and_lock(lock);
				LDLM_LOCK_PUT(lock);
			}
			mdt_object_unlock_put(info, mdt_pobj, &mll->mll_lh, rc);
			OBD_FREE_PTR(mll);
			retry_count--;
			goto again;
		}
		rc = 0;
		INIT_LIST_HEAD(&mll->mll_list);
		mll->mll_obj = mdt_pobj;
		list_add_tail(&mll->mll_list, lock_list);
next:
		ldata.ld_lee = (struct link_ea_entry *)((char *)ldata.ld_lee +
							 ldata.ld_reclen);
	}
out:
	if (rc != 0)
		mdt_unlock_list(info, lock_list, rc);
	RETURN(rc);
}

/* migrate files from one MDT to another MDT */
static int mdt_reint_migrate_internal(struct mdt_thread_info *info,
				      struct mdt_lock_handle *lhc)
{
	struct mdt_reint_record *rr = &info->mti_rr;
	struct md_attr          *ma = &info->mti_attr;
	struct mdt_object       *msrcdir;
	struct mdt_object       *mold;
	struct mdt_object       *mnew = NULL;
	struct mdt_lock_handle  *lh_dirp;
	struct mdt_lock_handle  *lh_childp;
	struct mdt_lock_handle  *lh_tgtp = NULL;
	struct lu_fid           *old_fid = &info->mti_tmp_fid1;
	struct list_head	lock_list;
	__u64			lock_ibits;
	struct ldlm_lock	*lease = NULL;
	bool			lock_open_sem = false;
	int			rc;
	ENTRY;

	CDEBUG(D_INODE, "migrate "DFID"/"DNAME" to "DFID"\n", PFID(rr->rr_fid1),
	       PNAME(&rr->rr_name), PFID(rr->rr_fid2));

	/* 1: lock the source dir. */
	msrcdir = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid1);
	if (IS_ERR(msrcdir)) {
		CDEBUG(D_OTHER, "%s: cannot find source dir "DFID" : rc = %d\n",
			mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
			(int)PTR_ERR(msrcdir));
		RETURN(PTR_ERR(msrcdir));
	}

	lh_dirp = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_pdo_init(lh_dirp, LCK_PW, &rr->rr_name);
	rc = mdt_reint_object_lock(info, msrcdir, lh_dirp, MDS_INODELOCK_UPDATE,
				   true);
	if (rc)
		GOTO(out_put_parent, rc);

	if (!mdt_object_remote(msrcdir)) {
		rc = mdt_version_get_check_save(info, msrcdir, 0);
		if (rc)
			GOTO(out_unlock_parent, rc);
	}

	/* 2: sanity check and find the object to be migrated. */
	fid_zero(old_fid);
	rc = mdt_lookup_version_check(info, msrcdir, &rr->rr_name, old_fid, 2);
	if (rc != 0)
		GOTO(out_unlock_parent, rc);

	if (lu_fid_eq(old_fid, rr->rr_fid1) || lu_fid_eq(old_fid, rr->rr_fid2))
		GOTO(out_unlock_parent, rc = -EINVAL);

	if (!fid_is_md_operative(old_fid))
		GOTO(out_unlock_parent, rc = -EPERM);

	if (lu_fid_eq(old_fid, &info->mti_mdt->mdt_md_root_fid))
		GOTO(out_unlock_parent, rc = -EPERM);

	mold = mdt_object_find(info->mti_env, info->mti_mdt, old_fid);
	if (IS_ERR(mold))
		GOTO(out_unlock_parent, rc = PTR_ERR(mold));

	if (mdt_object_remote(mold)) {
		CDEBUG(D_OTHER, "%s: source "DFID" is on the remote MDT\n",
		       mdt_obd_name(info->mti_mdt), PFID(old_fid));
		GOTO(out_put_child, rc = -EREMOTE);
	}

	if (S_ISREG(lu_object_attr(&mold->mot_obj)) &&
	    !mdt_object_remote(msrcdir)) {
		CDEBUG(D_OTHER, "%s: parent "DFID" is still on the same"
		       " MDT, which should be migrated first:"
		       " rc = %d\n", mdt_obd_name(info->mti_mdt),
		       PFID(mdt_object_fid(msrcdir)), -EPERM);
		GOTO(out_put_child, rc = -EPERM);
	}

	rc = mdt_remote_permission(info);
	if (rc != 0)
		GOTO(out_put_child, rc);

	/* 3: iterate the linkea of the object and lock all of the objects */
	INIT_LIST_HEAD(&lock_list);
	rc = mdt_lock_objects_in_linkea(info, mold, msrcdir, &lock_list);
	if (rc != 0)
		GOTO(out_put_child, rc);

	if (info->mti_spec.sp_migrate_close) {
		struct close_data *data;
		struct mdt_body	 *repbody;
		bool lease_broken = false;

		if (!req_capsule_field_present(info->mti_pill, &RMF_MDT_EPOCH,
				      RCL_CLIENT) ||
		    !req_capsule_field_present(info->mti_pill, &RMF_CLOSE_DATA,
				      RCL_CLIENT))
			GOTO(out_lease, rc = -EPROTO);

		data = req_capsule_client_get(info->mti_pill, &RMF_CLOSE_DATA);
		if (data == NULL)
			GOTO(out_lease, rc = -EPROTO);

		lease = ldlm_handle2lock(&data->cd_handle);
		if (lease == NULL)
			GOTO(out_lease, rc = -ESTALE);

		/* try to hold open_sem so that nobody else can open the file */
		if (!down_write_trylock(&mold->mot_open_sem)) {
			ldlm_lock_cancel(lease);
			GOTO(out_lease, rc = -EBUSY);
		}

		lock_open_sem = true;
		/* Check if the lease open lease has already canceled */
		lock_res_and_lock(lease);
		lease_broken = ldlm_is_cancel(lease);
		unlock_res_and_lock(lease);

		LDLM_DEBUG(lease, DFID " lease broken? %d",
			   PFID(mdt_object_fid(mold)), lease_broken);

		/* Cancel server side lease. Client side counterpart should
		 * have been cancelled. It's okay to cancel it now as we've
		 * held mot_open_sem. */
		ldlm_lock_cancel(lease);

		if (lease_broken)
			GOTO(out_lease, rc = -EAGAIN);
out_lease:
		rc = mdt_close_internal(info, mdt_info_req(info), NULL);
		repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		repbody->mbo_valid |= OBD_MD_CLOSE_INTENT_EXECED;
		if (rc != 0)
			GOTO(out_unlock_list, rc);
	}

	/* 4: lock of the object migrated object */
	lh_childp = &info->mti_lh[MDT_LH_OLD];
	mdt_lock_reg_init(lh_childp, LCK_EX);
	lock_ibits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE |
		     MDS_INODELOCK_LAYOUT;
	if (mdt_object_remote(msrcdir)) {
		/* Enqueue lookup lock from the parent MDT */
		rc = mdt_remote_object_lock(info, msrcdir, mdt_object_fid(mold),
					    &lh_childp->mlh_rreg_lh,
					    lh_childp->mlh_rreg_mode,
					    MDS_INODELOCK_LOOKUP, false, false);
		if (rc != ELDLM_OK)
			GOTO(out_unlock_list, rc);

		lock_ibits &= ~MDS_INODELOCK_LOOKUP;
	}

	rc = mdt_reint_object_lock(info, mold, lh_childp, lock_ibits, true);
	if (rc != 0)
		GOTO(out_unlock_child, rc);

	/* Migration is incompatible with HSM. */
	ma->ma_need = MA_HSM;
	ma->ma_valid = 0;
	rc = mdt_attr_get_complex(info, mold, ma);
	if (rc != 0)
		GOTO(out_unlock_child, rc);

	if ((ma->ma_valid & MA_HSM) && ma->ma_hsm.mh_flags != 0) {
		rc = -ENOSYS;
		CDEBUG(D_OTHER,
		       "%s: cannot migrate HSM archived file "DFID": rc = %d\n",
		       mdt_obd_name(info->mti_mdt), PFID(old_fid), rc);
		GOTO(out_unlock_child, rc);
	}

	ma->ma_need = MA_LMV;
	ma->ma_valid = 0;
	ma->ma_lmv = (union lmv_mds_md *)info->mti_xattr_buf;
	ma->ma_lmv_size = sizeof(info->mti_xattr_buf);
	rc = mdt_stripe_get(info, mold, ma, XATTR_NAME_LMV);
	if (rc != 0)
		GOTO(out_unlock_child, rc);

	if ((ma->ma_valid & MA_LMV)) {
		struct lmv_mds_md_v1 *lmm1;

		lmv_le_to_cpu(ma->ma_lmv, ma->ma_lmv);
		lmm1 = &ma->ma_lmv->lmv_md_v1;
		if (!(lmm1->lmv_hash_type & LMV_HASH_FLAG_MIGRATION)) {
			CDEBUG(D_OTHER, "%s: can not migrate striped dir "DFID
			       ": rc = %d\n", mdt_obd_name(info->mti_mdt),
			       PFID(mdt_object_fid(mold)), -EPERM);
			GOTO(out_unlock_child, rc = -EPERM);
		}

		if (!fid_is_sane(&lmm1->lmv_stripe_fids[1]))
			GOTO(out_unlock_child, rc = -EINVAL);

		mnew = mdt_object_find(info->mti_env, info->mti_mdt,
				       &lmm1->lmv_stripe_fids[1]);
		if (IS_ERR(mnew))
			GOTO(out_unlock_child, rc = PTR_ERR(mnew));

		if (!mdt_object_remote(mnew)) {
			CDEBUG(D_OTHER,
			       "%s: "DFID" being migrated is on this MDT:"
			       " rc  = %d\n", mdt_obd_name(info->mti_mdt),
			       PFID(rr->rr_fid2), -EPERM);
			GOTO(out_put_new, rc = -EPERM);
		}

		lh_tgtp = &info->mti_lh[MDT_LH_CHILD];
		mdt_lock_reg_init(lh_tgtp, LCK_EX);
		rc = mdt_remote_object_lock(info, mnew,
					    mdt_object_fid(mnew),
					    &lh_tgtp->mlh_rreg_lh,
					    lh_tgtp->mlh_rreg_mode,
					    MDS_INODELOCK_UPDATE, false, false);
		if (rc != 0) {
			lh_tgtp = NULL;
			GOTO(out_put_new, rc);
		}
	} else {
		mnew = mdt_object_find(info->mti_env, info->mti_mdt,
				       rr->rr_fid2);
		if (IS_ERR(mnew))
			GOTO(out_unlock_child, rc = PTR_ERR(mnew));
		if (!mdt_object_remote(mnew)) {
			CDEBUG(D_OTHER, "%s: Migration "DFID" is on this MDT:"
			       " rc = %d\n", mdt_obd_name(info->mti_mdt),
			       PFID(rr->rr_fid2), -EXDEV);
			GOTO(out_put_new, rc = -EXDEV);
		}
	}

	/* 5: migrate it */
	mdt_reint_init_ma(info, ma);

	mdt_fail_write(info->mti_env, info->mti_mdt->mdt_bottom,
		       OBD_FAIL_MDS_REINT_RENAME_WRITE);

	rc = mdo_migrate(info->mti_env, mdt_object_child(msrcdir),
			 mdt_object_child(mold), &rr->rr_name,
			 mdt_object_child(mnew), ma);
	if (rc != 0)
		GOTO(out_unlock_new, rc);

out_unlock_new:
	if (lh_tgtp != NULL)
		mdt_object_unlock(info, mnew, lh_tgtp, rc);
out_put_new:
	if (mnew)
		mdt_object_put(info->mti_env, mnew);
out_unlock_child:
	mdt_object_unlock(info, mold, lh_childp, rc);
out_unlock_list:
	/* we don't really modify linkea objects, so we can safely decref these
	 * locks, and this can avoid saving them as COS locks, which may prevent
	 * subsequent migrate. */
	mdt_unlock_list(info, &lock_list, 1);
	if (lease != NULL) {
		ldlm_reprocess_all(lease->l_resource);
		LDLM_LOCK_PUT(lease);
	}

	if (lock_open_sem)
		up_write(&mold->mot_open_sem);
out_put_child:
	mdt_object_put(info->mti_env, mold);
out_unlock_parent:
	mdt_object_unlock(info, msrcdir, lh_dirp, rc);
out_put_parent:
	mdt_object_put(info->mti_env, msrcdir);

	RETURN(rc);
}

static struct mdt_object *mdt_object_find_check(struct mdt_thread_info *info,
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

	RETURN(dir);
out_put:
	mdt_object_put(info->mti_env, dir);
	return ERR_PTR(rc);
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
 * VBR: rename versions in reply: 0 - srcdir parent; 1 - tgtdir parent;
 * 2 - srcdir child; 3 - tgtdir child.
 * Update on disk version of srcdir child.
 */
/**
 * For DNE phase I, only these renames are allowed
 *	mv src_p/src_c tgt_p/tgt_c
 * 1. src_p/src_c/tgt_p/tgt_c are in the same MDT.
 * 2. src_p and tgt_p are same directory, and tgt_c does not
 *    exists. In this case, all of modification will happen
 *    in the MDT where ithesource parent is, only one remote
 *    update is needed, i.e. set c_time/m_time on the child.
 *    And tgt_c will be still in the same MDT as the original
 *    src_c.
 */
static int mdt_reint_rename_internal(struct mdt_thread_info *info,
				     struct mdt_lock_handle *lhc)
{
	struct mdt_reint_record *rr = &info->mti_rr;
	struct md_attr *ma = &info->mti_attr;
	struct ptlrpc_request *req = mdt_info_req(info);
	struct mdt_object *msrcdir = NULL;
	struct mdt_object *mtgtdir = NULL;
	struct mdt_object *mold;
	struct mdt_object *mnew = NULL;
	struct mdt_lock_handle *lh_srcdirp;
	struct mdt_lock_handle *lh_tgtdirp;
	struct mdt_lock_handle *lh_oldp = NULL;
	struct mdt_lock_handle *lh_newp = NULL;
	struct lu_fid *old_fid = &info->mti_tmp_fid1;
	struct lu_fid *new_fid = &info->mti_tmp_fid2;
	__u64 lock_ibits;
	bool reverse = false;
	bool cos_incompat;
	int rc;
	ENTRY;

	DEBUG_REQ(D_INODE, req, "rename "DFID"/"DNAME" to "DFID"/"DNAME,
		  PFID(rr->rr_fid1), PNAME(&rr->rr_name),
		  PFID(rr->rr_fid2), PNAME(&rr->rr_tgt_name));

	/* find both parents. */
	msrcdir = mdt_object_find_check(info, rr->rr_fid1, 0);
	if (IS_ERR(msrcdir))
		RETURN(PTR_ERR(msrcdir));

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME3, 5);

	if (lu_fid_eq(rr->rr_fid1, rr->rr_fid2)) {
		mtgtdir = msrcdir;
		mdt_object_get(info->mti_env, mtgtdir);
	} else {
		/* Check if the @msrcdir is not a child of the @mtgtdir,
		 * otherwise a reverse locking must take place. */
		rc = mdt_is_subdir(info, msrcdir, rr->rr_fid2);
		if (rc == -EINVAL)
			reverse = true;
		else if (rc)
			GOTO(out_put_srcdir, rc);

		mtgtdir = mdt_object_find_check(info, rr->rr_fid2, 1);
		if (IS_ERR(mtgtdir))
			GOTO(out_put_srcdir, rc = PTR_ERR(mtgtdir));
	}

	/* source needs to be looked up after locking source parent, otherwise
	 * this rename may race with unlink source, and cause rename hang, see
	 * sanityn.sh 55b, so check parents first, if later we found source is
	 * remote, relock parents. */
	cos_incompat = (mdt_object_remote(msrcdir) ||
			mdt_object_remote(mtgtdir));

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME4, 5);

	/* lock parents in the proper order. */
	lh_srcdirp = &info->mti_lh[MDT_LH_PARENT];
	lh_tgtdirp = &info->mti_lh[MDT_LH_CHILD];

relock:
	mdt_lock_pdo_init(lh_srcdirp, LCK_PW, &rr->rr_name);
	mdt_lock_pdo_init(lh_tgtdirp, LCK_PW, &rr->rr_tgt_name);

	if (reverse) {
		rc = mdt_object_lock_save(info, mtgtdir, lh_tgtdirp, 1,
					  cos_incompat);
		if (rc)
			GOTO(out_put_tgtdir, rc);

		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME, 5);

		rc = mdt_object_lock_save(info, msrcdir, lh_srcdirp, 0,
					  cos_incompat);
		if (rc != 0) {
			mdt_object_unlock(info, mtgtdir, lh_tgtdirp, rc);
			GOTO(out_put_tgtdir, rc);
		}
	} else {
		rc = mdt_object_lock_save(info, msrcdir, lh_srcdirp, 0,
					  cos_incompat);
		if (rc)
			GOTO(out_put_tgtdir, rc);

		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RENAME, 5);

		if (mtgtdir != msrcdir) {
			rc = mdt_object_lock_save(info, mtgtdir, lh_tgtdirp, 1,
						  cos_incompat);
		} else if (lh_srcdirp->mlh_pdo_hash !=
			   lh_tgtdirp->mlh_pdo_hash) {
			rc = mdt_pdir_hash_lock(info, lh_tgtdirp, mtgtdir,
						MDS_INODELOCK_UPDATE,
						cos_incompat);
			OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_PDO_LOCK2, 10);
		}
		if (rc != 0) {
			mdt_object_unlock(info, msrcdir, lh_srcdirp, rc);
			GOTO(out_put_tgtdir, rc);
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

	/* Check if @mtgtdir is subdir of @mold, before locking child
	 * to avoid reverse locking. */
	if (mtgtdir != msrcdir) {
		rc = mdt_is_subdir(info, mtgtdir, old_fid);
		if (rc)
			GOTO(out_put_old, rc);
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
	 * lookup with version checking */
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
		 * back to this non-dir. */
		if (S_ISDIR(lu_object_attr(&mnew->mot_obj)) &&
		    !S_ISDIR(lu_object_attr(&mold->mot_obj)))
			GOTO(out_put_new, rc = -EISDIR);

		lh_oldp = &info->mti_lh[MDT_LH_OLD];
		mdt_lock_reg_init(lh_oldp, LCK_EX);
		lock_ibits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_XATTR;
		if (mdt_object_remote(msrcdir)) {
			/* Enqueue lookup lock from the parent MDT */
			rc = mdt_remote_object_lock(info, msrcdir,
						    mdt_object_fid(mold),
						    &lh_oldp->mlh_rreg_lh,
						    lh_oldp->mlh_rreg_mode,
						    MDS_INODELOCK_LOOKUP,
						    false, false);
			if (rc != ELDLM_OK)
				GOTO(out_put_new, rc);

			lock_ibits &= ~MDS_INODELOCK_LOOKUP;
		}

		rc = mdt_reint_object_lock(info, mold, lh_oldp, lock_ibits,
					   cos_incompat);
		if (rc != 0)
			GOTO(out_unlock_old, rc);

		/* Check if @msrcdir is subdir of @mnew, before locking child
		 * to avoid reverse locking. */
		if (mtgtdir != msrcdir) {
			rc = mdt_is_subdir(info, msrcdir, new_fid);
			if (rc)
				GOTO(out_unlock_old, rc);
		}

		/* We used to acquire MDS_INODELOCK_FULL here but we
		 * can't do this now because a running HSM restore on
		 * the rename onto victim will hold the layout
		 * lock. See LU-4002. */

		lh_newp = &info->mti_lh[MDT_LH_NEW];
		mdt_lock_reg_init(lh_newp, LCK_EX);
		rc = mdt_reint_object_lock(info, mnew, lh_newp,
					   MDS_INODELOCK_LOOKUP |
					   MDS_INODELOCK_UPDATE,
					   cos_incompat);
		if (rc != 0)
			GOTO(out_unlock_old, rc);

		/* get and save version after locking */
		mdt_version_get_save(info, mnew, 3);
	} else if (rc != -EREMOTE && rc != -ENOENT) {
		GOTO(out_put_old, rc);
	} else {
		lh_oldp = &info->mti_lh[MDT_LH_OLD];
		mdt_lock_reg_init(lh_oldp, LCK_EX);
		lock_ibits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_XATTR;
		if (mdt_object_remote(msrcdir)) {
			/* Enqueue lookup lock from the parent MDT */
			rc = mdt_remote_object_lock(info, msrcdir,
						    mdt_object_fid(mold),
						    &lh_oldp->mlh_rreg_lh,
						    lh_oldp->mlh_rreg_mode,
						    MDS_INODELOCK_LOOKUP,
						    false, false);
			if (rc != ELDLM_OK)
				GOTO(out_put_old, rc);

			lock_ibits &= ~MDS_INODELOCK_LOOKUP;
		}

		rc = mdt_reint_object_lock(info, mold, lh_oldp, lock_ibits,
					   cos_incompat);
		if (rc != 0)
			GOTO(out_unlock_old, rc);

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
		mdt_counter_incr(req, LPROC_MDT_RENAME);
		if (mnew)
			mdt_handle_last_unlink(info, mnew, ma);

		mdt_rename_counter_tally(info, info->mti_mdt, req,
					 msrcdir, mtgtdir);
	}

	EXIT;
	if (mnew != NULL)
		mdt_object_unlock(info, mnew, lh_newp, rc);
out_unlock_old:
	mdt_object_unlock(info, mold, lh_oldp, rc);
out_put_new:
	if (mnew != NULL)
		mdt_object_put(info->mti_env, mnew);
out_put_old:
	mdt_object_put(info->mti_env, mold);
out_unlock_parents:
	mdt_object_unlock(info, mtgtdir, lh_tgtdirp, rc);
	mdt_object_unlock(info, msrcdir, lh_srcdirp, rc);
out_put_tgtdir:
	mdt_object_put(info->mti_env, mtgtdir);
out_put_srcdir:
	mdt_object_put(info->mti_env, msrcdir);
	return rc;
}

static int mdt_reint_rename_or_migrate(struct mdt_thread_info *info,
				       struct mdt_lock_handle *lhc, bool rename)
{
	struct mdt_reint_record *rr = &info->mti_rr;
	struct ptlrpc_request   *req = mdt_info_req(info);
	struct lustre_handle	rename_lh = { 0 };
	int			rc;
	ENTRY;

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	if (!fid_is_md_operative(rr->rr_fid1) ||
	    !fid_is_md_operative(rr->rr_fid2))
		RETURN(-EPERM);

	/* Note: do not enqueue rename lock for replay request, because
	 * if other MDT holds rename lock, but being blocked to wait for
	 * this MDT to finish its recovery, and the failover MDT can not
	 * get rename lock, which will cause deadlock. */
	if (!req_is_replay(req)) {
		rc = mdt_rename_lock(info, &rename_lh);
		if (rc != 0) {
			CERROR("%s: can't lock FS for rename: rc  = %d\n",
			       mdt_obd_name(info->mti_mdt), rc);
			RETURN(rc);
		}
	}

	if (rename)
		rc = mdt_reint_rename_internal(info, lhc);
	else
		rc = mdt_reint_migrate_internal(info, lhc);

	if (lustre_handle_is_used(&rename_lh))
		mdt_rename_unlock(&rename_lh);

	RETURN(rc);
}

static int mdt_reint_rename(struct mdt_thread_info *info,
			    struct mdt_lock_handle *lhc)
{
	return mdt_reint_rename_or_migrate(info, lhc, true);
}

static int mdt_reint_migrate(struct mdt_thread_info *info,
			    struct mdt_lock_handle *lhc)
{
	return mdt_reint_rename_or_migrate(info, lhc, false);
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
