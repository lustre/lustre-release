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
 * lustre/mdt/mdt_xattr.c
 *
 * Lustre Metadata Target (mdt) extended attributes management.
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Huang Hua <huanghua@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/xattr.h>
#include <obd_class.h>
#include <lustre_nodemap.h>
#include <lustre_acl.h>
#include <lustre_lmv.h>
#include "mdt_internal.h"


/* return EADATA length to the caller. negative value means error */
static int mdt_getxattr_pack_reply(struct mdt_thread_info *info)
{
	struct req_capsule *pill = info->mti_pill;
	struct ptlrpc_request *req = mdt_info_req(info);
	const char *xattr_name;
	u64 valid;
	static const char user_string[] = "user.";
	int size;
	int rc = 0;
	int rc2;
	ENTRY;

	valid = info->mti_body->mbo_valid & (OBD_MD_FLXATTR | OBD_MD_FLXATTRLS);

	/* Determine how many bytes we need */
	if (valid == OBD_MD_FLXATTR) {
		xattr_name = req_capsule_client_get(pill, &RMF_NAME);
		if (!xattr_name)
			RETURN(-EFAULT);

		if (!(exp_connect_flags(req->rq_export) & OBD_CONNECT_XATTR) &&
		    !strncmp(xattr_name, user_string, sizeof(user_string) - 1))
			RETURN(-EOPNOTSUPP);

		size = mo_xattr_get(info->mti_env,
				    mdt_object_child(info->mti_object),
				    &LU_BUF_NULL, xattr_name);
		if (size == -ENODATA) {
			/* XXX: Some client code will not handle -ENODATA
			 * for XATTR_NAME_LOV (trusted.lov) properly.
			 */
			if (strcmp(xattr_name, XATTR_NAME_LOV) == 0)
				rc = 0;
			else
				rc = -ENODATA;

			size = 0;
		}
	} else if (valid == OBD_MD_FLXATTRLS) {
		xattr_name = "list";
		size = mo_xattr_list(info->mti_env,
				     mdt_object_child(info->mti_object),
				     &LU_BUF_NULL);
	} else if (valid == OBD_MD_FLXATTRALL) {
		xattr_name = "all";
		/* N.B. eadatasize = 0 is not valid for FLXATTRALL */
		/* We could calculate accurate sizes, but this would
		 * introduce a lot of overhead, let's do it later...
		 */
		size = info->mti_body->mbo_eadatasize;
		if (size <= 0 || size > info->mti_mdt->mdt_max_ea_size ||
		    size & (sizeof(__u32) - 1)) {
			DEBUG_REQ(D_ERROR, req,
				  "%s: invalid EA size(%d) for FLXATTRALL\n",
				  mdt_obd_name(info->mti_mdt), size);
			RETURN(-EINVAL);
		}
		req_capsule_set_size(pill, &RMF_EAVALS, RCL_SERVER, size);
		req_capsule_set_size(pill, &RMF_EAVALS_LENS, RCL_SERVER, size);
	} else {
		CDEBUG(D_INFO, "Valid bits: %#llx\n",
		       info->mti_body->mbo_valid);
		RETURN(-EINVAL);
	}

	if (size < 0) {
		if (size != -EOPNOTSUPP && size != -ENOENT)
			CERROR("%s: error geting EA size for '%s': rc = %d\n",
			       mdt_obd_name(info->mti_mdt), xattr_name, size);
		RETURN(size);
	}

	if (req_capsule_has_field(pill, &RMF_ACL, RCL_SERVER))
		req_capsule_set_size(pill, &RMF_ACL, RCL_SERVER,
				     LUSTRE_POSIX_ACL_MAX_SIZE_OLD);

	req_capsule_set_size(pill, &RMF_EADATA, RCL_SERVER,
			     info->mti_body->mbo_eadatasize == 0 ? 0 : size);

	rc2 = req_capsule_server_pack(pill);
	if (rc2 < 0)
		RETURN(rc2);

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETXATTR_PACK))
		RETURN(-ENOMEM);

	RETURN(rc < 0 ? rc : size);
}

static int mdt_nodemap_map_acl(struct mdt_thread_info *info, void *buf,
			       size_t size, const char *name,
			       enum nodemap_tree_type tree_type)
{
	struct lu_nodemap      *nodemap;
	struct obd_export      *exp = info->mti_exp;
	int			rc = size;

	ENTRY;

	if (strcmp(name, XATTR_NAME_ACL_ACCESS) == 0 ||
	    strcmp(name, XATTR_NAME_ACL_DEFAULT) == 0) {
		if (size > info->mti_mdt->mdt_max_ea_size ||
		     (!exp_connect_large_acl(exp) &&
		      size > LUSTRE_POSIX_ACL_MAX_SIZE_OLD))
			GOTO(out, rc = -ERANGE);

		nodemap = nodemap_get_from_exp(exp);
		if (IS_ERR(nodemap))
			GOTO(out, rc = PTR_ERR(nodemap));

		rc = nodemap_map_acl(nodemap, buf, size, tree_type);
		nodemap_putref(nodemap);
		if (rc < 0)
			GOTO(out, rc);
	}
out:
	RETURN(rc);
}

static int mdt_getxattr_all(struct mdt_thread_info *info,
			    struct mdt_body *reqbody, struct mdt_body *repbody,
			    struct lu_buf *buf, struct md_object *next)
{
	const struct lu_env *env = info->mti_env;
	char *v, *b, *eadatahead, *eadatatail;
	__u32 *sizes;
	int eadatasize, eavallen = 0, eavallens = 0, rc;

	ENTRY;

	/*
	 * The format of the pill is the following:
	 * EADATA:      attr1\0attr2\0...attrn\0
	 * EAVALS:      val1val2...valn
	 * EAVALS_LENS: 4,4,...4
	 */

	eadatahead = buf->lb_buf;

	/* Fill out EADATA first */
	rc = mo_xattr_list(env, next, buf);
	if (rc < 0)
		GOTO(out_shrink, rc);

	eadatasize = rc;
	eadatatail = eadatahead + eadatasize;

	v = req_capsule_server_get(info->mti_pill, &RMF_EAVALS);
	sizes = req_capsule_server_get(info->mti_pill, &RMF_EAVALS_LENS);

	/* Fill out EAVALS and EAVALS_LENS */
	for (b = eadatahead; b < eadatatail; b += strlen(b) + 1, v += rc) {
		buf->lb_buf = v;
		buf->lb_len = reqbody->mbo_eadatasize - eavallen;
		rc = mo_xattr_get(env, next, buf, b);
		if (rc < 0)
			GOTO(out_shrink, rc);
		rc = mdt_nodemap_map_acl(info, buf->lb_buf, rc, b,
					 NODEMAP_FS_TO_CLIENT);
		if (rc < 0)
			GOTO(out_shrink, rc);
		sizes[eavallens] = rc;
		eavallens++;
		eavallen += rc;
	}

out_shrink:
	if (rc < 0) {
		eadatasize = 0;
		eavallens = 0;
		eavallen = 0;
	}
	repbody->mbo_aclsize = eavallen;
	repbody->mbo_max_mdsize = eavallens;

	req_capsule_shrink(info->mti_pill, &RMF_EAVALS, eavallen, RCL_SERVER);
	req_capsule_shrink(info->mti_pill, &RMF_EAVALS_LENS,
			   eavallens * sizeof(__u32), RCL_SERVER);
	req_capsule_shrink(info->mti_pill, &RMF_EADATA, eadatasize, RCL_SERVER);

	if (rc >= 0)
		RETURN(eadatasize);
	return rc;
}

int mdt_getxattr(struct mdt_thread_info *info)
{
	struct ptlrpc_request  *req = mdt_info_req(info);
	struct mdt_body        *reqbody;
	struct mdt_body        *repbody = NULL;
	struct md_object       *next;
	struct lu_buf          *buf;
	int                     easize, rc;
	u64			valid;
	ktime_t			kstart = ktime_get();
	ENTRY;

	LASSERT(info->mti_object != NULL);
	LASSERT(lu_object_assert_exists(&info->mti_object->mot_obj));

	CDEBUG(D_INODE, "getxattr "DFID"\n", PFID(&info->mti_body->mbo_fid1));

	rc = req_check_sepol(info->mti_pill);
	if (rc)
		RETURN(err_serious(rc));

	reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
	if (reqbody == NULL)
		RETURN(err_serious(-EFAULT));

	rc = mdt_init_ucred(info, reqbody);
	if (rc)
		RETURN(err_serious(rc));

	next = mdt_object_child(info->mti_object);
	easize = mdt_getxattr_pack_reply(info);
	if (easize == -ENODATA)
		GOTO(out, rc = easize);
	else if (easize < 0)
		GOTO(out, rc = err_serious(easize));

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
	LASSERT(repbody != NULL);

	/* No need further getxattr. */
	if (easize == 0 || reqbody->mbo_eadatasize == 0)
		GOTO(out, rc = easize);

	buf = &info->mti_buf;
	buf->lb_buf = req_capsule_server_get(info->mti_pill, &RMF_EADATA);
	buf->lb_len = easize;

	valid = info->mti_body->mbo_valid & (OBD_MD_FLXATTR | OBD_MD_FLXATTRLS);

	if (valid == OBD_MD_FLXATTR) {
		const char *xattr_name = req_capsule_client_get(info->mti_pill,
								&RMF_NAME);
		rc = mo_xattr_get(info->mti_env, next, buf, xattr_name);
		if (rc < 0)
			GOTO(out, rc);

		rc = mdt_nodemap_map_acl(info, buf->lb_buf, rc, xattr_name,
					 NODEMAP_FS_TO_CLIENT);
	} else if (valid == OBD_MD_FLXATTRLS) {
		CDEBUG(D_INODE, "listxattr\n");

		rc = mo_xattr_list(info->mti_env, next, buf);
		if (rc < 0)
			CDEBUG(D_INFO, "listxattr failed: %d\n", rc);
	} else if (valid == OBD_MD_FLXATTRALL) {
		rc = mdt_getxattr_all(info, reqbody, repbody,
				      buf, next);
	} else
		LBUG();

	EXIT;
out:
	if (rc >= 0) {
		mdt_counter_incr(req, LPROC_MDT_GETXATTR,
				 ktime_us_delta(ktime_get(), kstart));
		/* LU-11109: Set OBD_MD_FLXATTR on success so that
		 * newer clients can distinguish between nonexistent
		 * xattrs and zero length values.
		 */
		repbody->mbo_valid |= OBD_MD_FLXATTR;
		repbody->mbo_eadatasize = rc;
		rc = 0;
	}
	mdt_exit_ucred(info);
	return rc;
}

/* update dir layout after migration/restripe */
int mdt_dir_layout_update(struct mdt_thread_info *info)
{
	const struct lu_env *env = info->mti_env;
	struct mdt_device *mdt = info->mti_mdt;
	struct lu_ucred *uc = mdt_ucred(info);
	struct mdt_reint_record *rr = &info->mti_rr;
	struct lmv_user_md *lmu = rr->rr_eadata;
	__u32 lum_stripe_count = lmu->lum_stripe_count;
	struct md_layout_change *mlc = &info->mti_mlc;
	struct lmv_mds_md_v1 *lmv;
	struct md_attr *ma = &info->mti_attr;
	struct ldlm_enqueue_info *einfo = &info->mti_einfo[0];
	struct mdt_object *pobj = NULL;
	struct mdt_object *obj;
	struct mdt_lock_handle *lhp = NULL;
	struct mdt_lock_handle *lhc;
	bool shrink = false;
	int rc;

	ENTRY;

	if (!mdt->mdt_enable_dir_migration)
		RETURN(-EPERM);

	if (!md_capable(uc, CAP_SYS_ADMIN) &&
	    uc->uc_gid != mdt->mdt_enable_remote_dir_gid &&
	    mdt->mdt_enable_remote_dir_gid != -1)
		RETURN(-EPERM);

	obj = mdt_object_find(env, mdt, rr->rr_fid1);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	/* get parent from PFID */
	rc = mdt_attr_get_pfid(info, obj, &ma->ma_pfid);
	if (rc)
		GOTO(put_obj, rc);

	pobj = mdt_object_find(env, mdt, &ma->ma_pfid);
	if (IS_ERR(pobj))
		GOTO(put_obj, rc = PTR_ERR(pobj));

	/* revoke object remote LOOKUP lock */
	if (mdt_object_remote(pobj)) {
		rc = mdt_revoke_remote_lookup_lock(info, pobj, obj);
		if (rc)
			GOTO(put_pobj, rc);
	}

	/*
	 * lock parent if dir will be shrunk to 1 stripe, because dir will be
	 * converted to normal directory, as will change dir FID and update
	 * namespace of parent.
	 */
	lhp = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_reg_init(lhp, LCK_PW);

	if (le32_to_cpu(lmu->lum_stripe_count) < 2) {
		rc = mdt_reint_object_lock(info, pobj, lhp,
					   MDS_INODELOCK_UPDATE, true);
		if (rc)
			GOTO(put_pobj, rc);
	}

	/* lock object */
	lhc = &info->mti_lh[MDT_LH_CHILD];
	mdt_lock_reg_init(lhc, LCK_EX);
	rc = mdt_reint_striped_lock(info, obj, lhc, MDS_INODELOCK_FULL, einfo,
				    true);
	if (rc)
		GOTO(unlock_pobj, rc);

	rc = mdt_stripe_get(info, obj, ma, XATTR_NAME_LMV);
	if (rc)
		GOTO(unlock_obj, rc);

	/* user may run 'lfs migrate' multiple times, so it's shrunk already */
	if (!(ma->ma_valid & MA_LMV))
		GOTO(unlock_obj, rc = -EALREADY);

	lmv = &ma->ma_lmv->lmv_md_v1;
	if (!lmv_is_sane(lmv))
		GOTO(unlock_obj, rc = -EBADF);

	/* ditto */
	if (!lmv_is_layout_changing(lmv))
		GOTO(unlock_obj, rc = -EALREADY);

	lum_stripe_count = lmu->lum_stripe_count;
	if (!lum_stripe_count)
		lum_stripe_count = cpu_to_le32(1);

	if (lmv_is_migrating(lmv)) {
		if (lmv->lmv_migrate_offset != lum_stripe_count) {
			CERROR("%s: "DFID" migrate mdt count mismatch %u != %u\n",
				mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
				lmv->lmv_migrate_offset, lmu->lum_stripe_count);
			GOTO(unlock_obj, rc = -EINVAL);
		}

		if (lmu->lum_stripe_offset != lmv->lmv_master_mdt_index) {
			CERROR("%s: "DFID" migrate mdt index mismatch %u != %u\n",
				mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
				lmv->lmv_master_mdt_index,
				lmu->lum_stripe_offset);
			GOTO(unlock_obj, rc = -EINVAL);
		}

		if (lum_stripe_count > 1 && lmu->lum_hash_type &&
		    lmu->lum_hash_type !=
		    (lmv->lmv_hash_type & cpu_to_le32(LMV_HASH_TYPE_MASK))) {
			CERROR("%s: "DFID" migrate mdt hash mismatch %u != %u\n",
				mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
				lmv->lmv_hash_type, lmu->lum_hash_type);
			GOTO(unlock_obj, rc = -EINVAL);
		}

		shrink = true;
	} else if (lmv_is_splitting(lmv)) {
		if (lmv->lmv_stripe_count != lum_stripe_count) {
			CERROR("%s: "DFID" stripe count mismatch %u != %u\n",
				mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
				lmv->lmv_stripe_count, lmu->lum_stripe_count);
			GOTO(unlock_obj, rc = -EINVAL);
		}

		if (lmu->lum_stripe_offset != LMV_OFFSET_DEFAULT) {
			CERROR("%s: "DFID" dir split offset %u != -1\n",
				mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
				lmu->lum_stripe_offset);
			GOTO(unlock_obj, rc = -EINVAL);
		}

		if (lmu->lum_hash_type &&
		    lmu->lum_hash_type !=
		    (lmv->lmv_hash_type & cpu_to_le32(LMV_HASH_TYPE_MASK))) {
			CERROR("%s: "DFID" split hash mismatch %u != %u\n",
				mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
				lmv->lmv_hash_type, lmu->lum_hash_type);
			GOTO(unlock_obj, rc = -EINVAL);
		}
	} else if (lmv_is_merging(lmv)) {
		if (lmv->lmv_merge_offset != lum_stripe_count) {
			CERROR("%s: "DFID" stripe count mismatch %u != %u\n",
				mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
				lmv->lmv_merge_offset, lmu->lum_stripe_count);
			GOTO(unlock_obj, rc = -EINVAL);
		}

		if (lmu->lum_stripe_offset != LMV_OFFSET_DEFAULT) {
			CERROR("%s: "DFID" dir merge offset %u != -1\n",
				mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
				lmu->lum_stripe_offset);
			GOTO(unlock_obj, rc = -EINVAL);
		}

		if (lmu->lum_hash_type &&
		    lmu->lum_hash_type !=
		    (lmv->lmv_merge_hash & cpu_to_le32(LMV_HASH_TYPE_MASK))) {
			CERROR("%s: "DFID" merge hash mismatch %u != %u\n",
				mdt_obd_name(info->mti_mdt), PFID(rr->rr_fid1),
				lmv->lmv_merge_hash, lmu->lum_hash_type);
			GOTO(unlock_obj, rc = -EINVAL);
		}

		if (lum_stripe_count < lmv->lmv_stripe_count)
			shrink = true;
	}

	if (shrink) {
		mlc->mlc_opc = MD_LAYOUT_SHRINK;
		mlc->mlc_buf.lb_buf = rr->rr_eadata;
		mlc->mlc_buf.lb_len = rr->rr_eadatalen;
		rc = mo_layout_change(env, mdt_object_child(obj), mlc);
	} else {
		struct lu_buf *buf = &info->mti_buf;
		u32 version = le32_to_cpu(lmv->lmv_layout_version);

		lmv->lmv_hash_type &= ~LMV_HASH_FLAG_LAYOUT_CHANGE;
		lmv->lmv_layout_version = cpu_to_le32(++version);
		buf->lb_buf = lmv;
		buf->lb_len = sizeof(*lmv);
		rc = mo_xattr_set(env, mdt_object_child(obj), buf,
				  XATTR_NAME_LMV, LU_XATTR_REPLACE);
	}
	GOTO(unlock_obj, rc);

unlock_obj:
	mdt_reint_striped_unlock(info, obj, lhc, einfo, rc);
unlock_pobj:
	mdt_object_unlock(info, pobj, lhp, rc);
put_pobj:
	mdt_object_put(env, pobj);
put_obj:
	mdt_object_put(env, obj);

	return rc;
}

int mdt_reint_setxattr(struct mdt_thread_info *info,
		       struct mdt_lock_handle *unused)
{
	struct ptlrpc_request	*req = mdt_info_req(info);
	struct mdt_lock_handle	*lh;
	const struct lu_env	*env  = info->mti_env;
	struct lu_buf		*buf  = &info->mti_buf;
	struct mdt_reint_record	*rr   = &info->mti_rr;
	struct md_attr		*ma = &info->mti_attr;
	struct lu_attr		*attr = &info->mti_attr.ma_attr;
	struct mdt_object	*obj;
	struct md_object	*child;
	__u64			 valid = attr->la_valid;
	const char		*xattr_name = rr->rr_name.ln_name;
	int			 xattr_len = rr->rr_eadatalen;
	__u64			 lockpart = MDS_INODELOCK_UPDATE;
	ktime_t			 kstart = ktime_get();
	int			 rc;
	ENTRY;

	CDEBUG(D_INODE, "setxattr for "DFID": %s %s\n", PFID(rr->rr_fid1),
	       valid & OBD_MD_FLXATTR ? "set" : "remove", xattr_name);

	if (info->mti_dlm_req)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SETXATTR))
		RETURN(err_serious(-ENOMEM));

	rc = mdt_init_ucred_reint(info);
	if (rc != 0)
		RETURN(rc);

	if (strncmp(xattr_name, XATTR_USER_PREFIX,
		    sizeof(XATTR_USER_PREFIX) - 1) == 0) {
		if (!(exp_connect_flags(req->rq_export) & OBD_CONNECT_XATTR))
			GOTO(out, rc = -EOPNOTSUPP);
	} else if (strncmp(xattr_name, XATTR_TRUSTED_PREFIX,
		    sizeof(XATTR_TRUSTED_PREFIX) - 1) == 0) {

		/* setxattr(LMV) with lum is used to shrink dir layout */
		if (strcmp(xattr_name, XATTR_NAME_LMV) == 0) {
			__u32 *magic = rr->rr_eadata;

			/* we don't let to remove LMV? */
			if (!rr->rr_eadata)
				GOTO(out, rc = 0);

			if (le32_to_cpu(*magic) == LMV_USER_MAGIC ||
			    le32_to_cpu(*magic) == LMV_USER_MAGIC_SPECIFIC) {
				rc = mdt_dir_layout_update(info);
				GOTO(out, rc);
			}
		}

		if (!md_capable(mdt_ucred(info), CAP_SYS_ADMIN))
			GOTO(out, rc = -EPERM);

		if (strcmp(xattr_name, XATTR_NAME_LOV) == 0 ||
		    strcmp(xattr_name, XATTR_NAME_LMA) == 0 ||
		    strcmp(xattr_name, XATTR_NAME_LMV) == 0 ||
		    strcmp(xattr_name, XATTR_NAME_LINK) == 0 ||
		    strcmp(xattr_name, XATTR_NAME_FID) == 0 ||
		    strcmp(xattr_name, XATTR_NAME_VERSION) == 0 ||
		    strcmp(xattr_name, XATTR_NAME_SOM) == 0 ||
		    strcmp(xattr_name, XATTR_NAME_HSM) == 0 ||
		    strcmp(xattr_name, XATTR_NAME_LFSCK_NAMESPACE) == 0)
			GOTO(out, rc = 0);
	} else if ((valid & OBD_MD_FLXATTR) &&
		   (strcmp(xattr_name, XATTR_NAME_ACL_ACCESS) == 0 ||
		    strcmp(xattr_name, XATTR_NAME_ACL_DEFAULT) == 0)) {
		rc = mdt_nodemap_map_acl(info, rr->rr_eadata, xattr_len,
					 xattr_name, NODEMAP_CLIENT_TO_FS);
		if (rc < 0)
			GOTO(out, rc);
		/* ACLs were mapped out, return an error so the user knows */
		if (rc != xattr_len)
			GOTO(out, rc = -EPERM);
	} else if ((strlen(xattr_name) > sizeof(XATTR_LUSTRE_LOV)) &&
		   strncmp(xattr_name, XATTR_LUSTRE_LOV,
			   strlen(XATTR_LUSTRE_LOV)) == 0) {

		if (!allowed_lustre_lov(xattr_name)) {
			CERROR("%s: invalid xattr name: %s\n",
			       mdt_obd_name(info->mti_mdt), xattr_name);
			GOTO(out, rc = -EINVAL);
		}

		lockpart |= MDS_INODELOCK_LAYOUT;
	}

	/* Revoke all clients' lookup lock, since the access
	 * permissions for this inode is changed when ACL_ACCESS is
	 * set. This isn't needed for ACL_DEFAULT, since that does
	 * not change the access permissions of this inode, nor any
	 * other existing inodes. It is setting the ACLs inherited
	 * by new directories/files at create time.
	 */
	/* We need revoke both LOOKUP|PERM lock here, see mdt_attr_set. */
	if (!strcmp(xattr_name, XATTR_NAME_ACL_ACCESS))
		lockpart |= MDS_INODELOCK_PERM | MDS_INODELOCK_LOOKUP;
	/* We need to take the lock on behalf of old clients so that newer
	 * clients flush their xattr caches
	 */
	else
		lockpart |= MDS_INODELOCK_XATTR;

	lh = &info->mti_lh[MDT_LH_PARENT];
	/* ACLs were sent to clients under LCK_CR locks, so taking LCK_EX
	 * to cancel them.
	 */
	mdt_lock_reg_init(lh, LCK_EX);
	obj = mdt_object_find_lock(info, rr->rr_fid1, lh, lockpart);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	tgt_vbr_obj_set(env, mdt_obj2dt(obj));
	rc = mdt_version_get_check_save(info, obj, 0);
	if (rc)
		GOTO(out_unlock, rc);

	if (unlikely(!(valid & OBD_MD_FLCTIME))) {
		/* This isn't strictly an error, but all current clients
		 * should set OBD_MD_FLCTIME when setting attributes.
		 */
		CWARN("%s: client miss to set OBD_MD_FLCTIME when setxattr %s: [object "DFID"] [valid %llu]\n",
		      mdt_obd_name(info->mti_mdt), xattr_name,
		      PFID(rr->rr_fid1), valid);
		attr->la_ctime = ktime_get_real_seconds();
	}
	attr->la_valid = LA_CTIME;
	child = mdt_object_child(obj);
	if (valid & OBD_MD_FLXATTR) {
		int	flags = 0;

		if (attr->la_flags & XATTR_REPLACE)
			flags |= LU_XATTR_REPLACE;

		if (attr->la_flags & XATTR_CREATE)
			flags |= LU_XATTR_CREATE;

		mdt_fail_write(env, info->mti_mdt->mdt_bottom,
			       OBD_FAIL_MDS_SETXATTR_WRITE);

		buf->lb_buf = rr->rr_eadata;
		buf->lb_len = xattr_len;
		rc = mo_xattr_set(env, child, buf, xattr_name, flags);
		/* update ctime after xattr changed */
		if (rc == 0) {
			ma->ma_attr_flags |= MDS_PERM_BYPASS;
			mo_attr_set(env, child, ma);
		}
	} else if (valid & OBD_MD_FLXATTRRM) {
		rc = mo_xattr_del(env, child, xattr_name);
		/* update ctime after xattr changed */
		if (rc == 0) {
			ma->ma_attr_flags |= MDS_PERM_BYPASS;
			mo_attr_set(env, child, ma);
		}
	} else {
		CDEBUG(D_INFO, "valid bits: %#llx\n", valid);
		rc = -EINVAL;
	}

	if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_SETXATTR,
				 ktime_us_delta(ktime_get(), kstart));

	EXIT;
out_unlock:
	mdt_object_unlock_put(info, obj, lh, rc);
out:
	mdt_exit_ucred(info);
	return rc;
}
