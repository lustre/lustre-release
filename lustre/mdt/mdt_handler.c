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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdt/mdt_handler.c
 *
 * Lustre Metadata Target (mdt) request handler
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Mike Shaver <shaver@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Huang Hua <huanghua@clusterfs.com>
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

#include <dt_object.h>
#include <lustre_acl.h>
#include <lustre_export.h>
#include <lustre_ioctl.h>
#include <lustre_lfsck.h>
#include <lustre_log.h>
#include <lustre_net.h>
#include <lustre_nodemap.h>
#include <lustre_mds.h>
#include <lustre_param.h>
#include <lustre_quota.h>
#include <lustre_swab.h>
#include <obd.h>
#include <obd_support.h>

#include "mdt_internal.h"


static unsigned int max_mod_rpcs_per_client = 8;
CFS_MODULE_PARM(max_mod_rpcs_per_client, "i", uint, 0644,
		"maximum number of modify RPCs in flight allowed per client");

mdl_mode_t mdt_mdl_lock_modes[] = {
        [LCK_MINMODE] = MDL_MINMODE,
        [LCK_EX]      = MDL_EX,
        [LCK_PW]      = MDL_PW,
        [LCK_PR]      = MDL_PR,
        [LCK_CW]      = MDL_CW,
        [LCK_CR]      = MDL_CR,
        [LCK_NL]      = MDL_NL,
        [LCK_GROUP]   = MDL_GROUP
};

enum ldlm_mode mdt_dlm_lock_modes[] = {
	[MDL_MINMODE]	= LCK_MINMODE,
	[MDL_EX]	= LCK_EX,
	[MDL_PW]	= LCK_PW,
	[MDL_PR]	= LCK_PR,
	[MDL_CW]	= LCK_CW,
	[MDL_CR]	= LCK_CR,
	[MDL_NL]	= LCK_NL,
	[MDL_GROUP]	= LCK_GROUP
};

static struct mdt_device *mdt_dev(struct lu_device *d);
static int mdt_unpack_req_pack_rep(struct mdt_thread_info *info, __u32 flags);

static const struct lu_object_operations mdt_obj_ops;

/* Slab for MDT object allocation */
static struct kmem_cache *mdt_object_kmem;

/* For HSM restore handles */
struct kmem_cache *mdt_hsm_cdt_kmem;

/* For HSM request handles */
struct kmem_cache *mdt_hsm_car_kmem;

static struct lu_kmem_descr mdt_caches[] = {
	{
		.ckd_cache = &mdt_object_kmem,
		.ckd_name  = "mdt_obj",
		.ckd_size  = sizeof(struct mdt_object)
	},
	{
		.ckd_cache      = &mdt_hsm_cdt_kmem,
		.ckd_name       = "mdt_cdt_restore_handle",
		.ckd_size       = sizeof(struct cdt_restore_handle)
	},
	{
		.ckd_cache      = &mdt_hsm_car_kmem,
		.ckd_name       = "mdt_cdt_agent_req",
		.ckd_size       = sizeof(struct cdt_agent_req)
	},
	{
		.ckd_cache = NULL
	}
};

__u64 mdt_get_disposition(struct ldlm_reply *rep, __u64 op_flag)
{
	if (!rep)
		return 0;
	return rep->lock_policy_res1 & op_flag;
}

void mdt_clear_disposition(struct mdt_thread_info *info,
			   struct ldlm_reply *rep, __u64 op_flag)
{
	if (info) {
		info->mti_opdata &= ~op_flag;
		tgt_opdata_clear(info->mti_env, op_flag);
	}
	if (rep)
		rep->lock_policy_res1 &= ~op_flag;
}

void mdt_set_disposition(struct mdt_thread_info *info,
			 struct ldlm_reply *rep, __u64 op_flag)
{
	if (info) {
		info->mti_opdata |= op_flag;
		tgt_opdata_set(info->mti_env, op_flag);
	}
	if (rep)
		rep->lock_policy_res1 |= op_flag;
}

void mdt_lock_reg_init(struct mdt_lock_handle *lh, enum ldlm_mode lm)
{
	lh->mlh_pdo_hash = 0;
	lh->mlh_reg_mode = lm;
	lh->mlh_rreg_mode = lm;
	lh->mlh_type = MDT_REG_LOCK;
}

void mdt_lock_pdo_init(struct mdt_lock_handle *lh, enum ldlm_mode lock_mode,
		       const struct lu_name *lname)
{
	lh->mlh_reg_mode = lock_mode;
	lh->mlh_pdo_mode = LCK_MINMODE;
	lh->mlh_rreg_mode = lock_mode;
	lh->mlh_type = MDT_PDO_LOCK;

	if (lu_name_is_valid(lname)) {
		lh->mlh_pdo_hash = full_name_hash(lname->ln_name,
						  lname->ln_namelen);
		/* XXX Workaround for LU-2856
		 *
		 * Zero is a valid return value of full_name_hash, but
		 * several users of mlh_pdo_hash assume a non-zero
		 * hash value. We therefore map zero onto an
		 * arbitrary, but consistent value (1) to avoid
		 * problems further down the road. */
		if (unlikely(lh->mlh_pdo_hash == 0))
			lh->mlh_pdo_hash = 1;
	} else {
		lh->mlh_pdo_hash = 0;
	}
}

static void mdt_lock_pdo_mode(struct mdt_thread_info *info, struct mdt_object *o,
                              struct mdt_lock_handle *lh)
{
        mdl_mode_t mode;
        ENTRY;

        /*
         * Any dir access needs couple of locks:
         *
         * 1) on part of dir we gonna take lookup/modify;
         *
         * 2) on whole dir to protect it from concurrent splitting and/or to
         * flush client's cache for readdir().
         *
         * so, for a given mode and object this routine decides what lock mode
         * to use for lock #2:
         *
         * 1) if caller's gonna lookup in dir then we need to protect dir from
         * being splitted only - LCK_CR
         *
         * 2) if caller's gonna modify dir then we need to protect dir from
         * being splitted and to flush cache - LCK_CW
         *
         * 3) if caller's gonna modify dir and that dir seems ready for
         * splitting then we need to protect it from any type of access
         * (lookup/modify/split) - LCK_EX --bzzz
         */

        LASSERT(lh->mlh_reg_mode != LCK_MINMODE);
        LASSERT(lh->mlh_pdo_mode == LCK_MINMODE);

        /*
         * Ask underlaying level its opinion about preferable PDO lock mode
         * having access type passed as regular lock mode:
         *
         * - MDL_MINMODE means that lower layer does not want to specify lock
         * mode;
         *
         * - MDL_NL means that no PDO lock should be taken. This is used in some
         * cases. Say, for non-splittable directories no need to use PDO locks
         * at all.
         */
        mode = mdo_lock_mode(info->mti_env, mdt_object_child(o),
                             mdt_dlm_mode2mdl_mode(lh->mlh_reg_mode));

        if (mode != MDL_MINMODE) {
                lh->mlh_pdo_mode = mdt_mdl_mode2dlm_mode(mode);
        } else {
                /*
                 * Lower layer does not want to specify locking mode. We do it
                 * our selves. No special protection is needed, just flush
                 * client's cache on modification and allow concurrent
                 * mondification.
                 */
                switch (lh->mlh_reg_mode) {
                case LCK_EX:
                        lh->mlh_pdo_mode = LCK_EX;
                        break;
                case LCK_PR:
                        lh->mlh_pdo_mode = LCK_CR;
                        break;
                case LCK_PW:
                        lh->mlh_pdo_mode = LCK_CW;
                        break;
                default:
                        CERROR("Not expected lock type (0x%x)\n",
                               (int)lh->mlh_reg_mode);
                        LBUG();
                }
        }

        LASSERT(lh->mlh_pdo_mode != LCK_MINMODE);
        EXIT;
}

static int mdt_getstatus(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info = tsi2mdt_info(tsi);
	struct mdt_device	*mdt = info->mti_mdt;
	struct mdt_body		*repbody;
	int			 rc;

	ENTRY;

	rc = mdt_check_ucred(info);
	if (rc)
		GOTO(out, rc = err_serious(rc));

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK))
		GOTO(out, rc = err_serious(-ENOMEM));

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
	repbody->mbo_fid1 = mdt->mdt_md_root_fid;
	repbody->mbo_valid |= OBD_MD_FLID;

	EXIT;
out:
	mdt_thread_info_fini(info);
	return rc;
}

static int mdt_statfs(struct tgt_session_info *tsi)
{
	struct ptlrpc_request		*req = tgt_ses_req(tsi);
	struct mdt_thread_info		*info = tsi2mdt_info(tsi);
	struct md_device		*next = info->mti_mdt->mdt_child;
	struct ptlrpc_service_part	*svcpt;
	struct obd_statfs		*osfs;
	int				rc;

	ENTRY;

	svcpt = req->rq_rqbd->rqbd_svcpt;

	/* This will trigger a watchdog timeout */
	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_STATFS_LCW_SLEEP,
			 (MDT_SERVICE_WATCHDOG_FACTOR *
			  at_get(&svcpt->scp_at_estimate)) + 1);

	rc = mdt_check_ucred(info);
	if (rc)
		GOTO(out, rc = err_serious(rc));

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK))
		GOTO(out, rc = err_serious(-ENOMEM));

	osfs = req_capsule_server_get(info->mti_pill, &RMF_OBD_STATFS);
	if (!osfs)
		GOTO(out, rc = -EPROTO);

	/** statfs information are cached in the mdt_device */
	if (cfs_time_before_64(info->mti_mdt->mdt_osfs_age,
			       cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS))) {
		/** statfs data is too old, get up-to-date one */
		rc = next->md_ops->mdo_statfs(info->mti_env, next, osfs);
		if (rc)
			GOTO(out, rc);
		spin_lock(&info->mti_mdt->mdt_osfs_lock);
		info->mti_mdt->mdt_osfs = *osfs;
		info->mti_mdt->mdt_osfs_age = cfs_time_current_64();
		spin_unlock(&info->mti_mdt->mdt_osfs_lock);
	} else {
		/** use cached statfs data */
		spin_lock(&info->mti_mdt->mdt_osfs_lock);
		*osfs = info->mti_mdt->mdt_osfs;
		spin_unlock(&info->mti_mdt->mdt_osfs_lock);
	}

	if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_STATFS);
out:
	mdt_thread_info_fini(info);
	RETURN(rc);
}

#ifdef CONFIG_FS_POSIX_ACL
/*
 * Pack ACL data into the reply. UIDs/GIDs are mapped and filtered by nodemap.
 *
 * \param	info	thread info object
 * \param	repbody	reply to pack ACLs into
 * \param	o	mdt object of file to examine
 * \param	nodemap	nodemap of client to reply to
 * \retval	0	success
 * \retval	-errno	error getting or parsing ACL from disk
 */
int mdt_pack_acl2body(struct mdt_thread_info *info, struct mdt_body *repbody,
		      struct mdt_object *o, struct lu_nodemap *nodemap)
{
	const struct lu_env	*env = info->mti_env;
	struct md_object	*next = mdt_object_child(o);
	struct lu_buf		*buf = &info->mti_buf;
	int rc;

	buf->lb_buf = req_capsule_server_get(info->mti_pill, &RMF_ACL);
	buf->lb_len = req_capsule_get_size(info->mti_pill, &RMF_ACL,
					   RCL_SERVER);
	if (buf->lb_len == 0)
		return 0;

	rc = mo_xattr_get(env, next, buf, XATTR_NAME_ACL_ACCESS);
	if (rc < 0) {
		if (rc == -ENODATA) {
			repbody->mbo_aclsize = 0;
			repbody->mbo_valid |= OBD_MD_FLACL;
			rc = 0;
		} else if (rc == -EOPNOTSUPP) {
			rc = 0;
		} else {
			CERROR("%s: unable to read "DFID" ACL: rc = %d\n",
			       mdt_obd_name(info->mti_mdt),
			       PFID(mdt_object_fid(o)), rc);
		}
	} else {
		rc = nodemap_map_acl(nodemap, buf->lb_buf,
				     rc, NODEMAP_FS_TO_CLIENT);
		/* if all ACLs mapped out, rc is still >= 0 */
		if (rc < 0) {
			CERROR("%s: nodemap_map_acl unable to parse "DFID
			       " ACL: rc = %d\n", mdt_obd_name(info->mti_mdt),
			       PFID(mdt_object_fid(o)), rc);
		} else {
			repbody->mbo_aclsize = rc;
			repbody->mbo_valid |= OBD_MD_FLACL;
			rc = 0;
		}
	}
	return rc;
}
#endif

void mdt_pack_attr2body(struct mdt_thread_info *info, struct mdt_body *b,
                        const struct lu_attr *attr, const struct lu_fid *fid)
{
	struct md_attr		*ma = &info->mti_attr;
	struct obd_export	*exp = info->mti_exp;
	struct lu_nodemap	*nodemap = exp->exp_target_data.ted_nodemap;

	LASSERT(ma->ma_valid & MA_INODE);

	if (attr->la_valid & LA_ATIME) {
		b->mbo_atime = attr->la_atime;
		b->mbo_valid |= OBD_MD_FLATIME;
	}
	if (attr->la_valid & LA_MTIME) {
		b->mbo_mtime = attr->la_mtime;
		b->mbo_valid |= OBD_MD_FLMTIME;
	}
	if (attr->la_valid & LA_CTIME) {
		b->mbo_ctime = attr->la_ctime;
		b->mbo_valid |= OBD_MD_FLCTIME;
	}
	if (attr->la_valid & LA_FLAGS) {
		b->mbo_flags = attr->la_flags;
		b->mbo_valid |= OBD_MD_FLFLAGS;
	}
	if (attr->la_valid & LA_NLINK) {
		b->mbo_nlink = attr->la_nlink;
		b->mbo_valid |= OBD_MD_FLNLINK;
	}
	if (attr->la_valid & LA_UID) {
		b->mbo_uid = nodemap_map_id(nodemap, NODEMAP_UID,
					    NODEMAP_FS_TO_CLIENT,
					    attr->la_uid);
		b->mbo_valid |= OBD_MD_FLUID;
	}
	if (attr->la_valid & LA_GID) {
		b->mbo_gid = nodemap_map_id(nodemap, NODEMAP_GID,
					    NODEMAP_FS_TO_CLIENT,
					    attr->la_gid);
		b->mbo_valid |= OBD_MD_FLGID;
	}
	b->mbo_mode = attr->la_mode;
	if (attr->la_valid & LA_MODE)
		b->mbo_valid |= OBD_MD_FLMODE;
	if (attr->la_valid & LA_TYPE)
		b->mbo_valid |= OBD_MD_FLTYPE;

	if (fid != NULL) {
		b->mbo_fid1 = *fid;
		b->mbo_valid |= OBD_MD_FLID;
		CDEBUG(D_INODE, DFID": nlink=%d, mode=%o, valid="LPX64"\n",
		       PFID(fid), b->mbo_nlink, b->mbo_mode, b->mbo_valid);
	}

	if (info != NULL)
		mdt_body_reverse_idmap(info, b);

	if (!(attr->la_valid & LA_TYPE))
		return;

	b->mbo_rdev   = attr->la_rdev;
	b->mbo_size   = attr->la_size;
	b->mbo_blocks = attr->la_blocks;

	if (!S_ISREG(attr->la_mode)) {
		b->mbo_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLRDEV;
	} else if (ma->ma_need & MA_LOV && !(ma->ma_valid & MA_LOV)) {
		/* means no objects are allocated on osts. */
		LASSERT(!(ma->ma_valid & MA_LOV));
		/* just ignore blocks occupied by extend attributes on MDS */
		b->mbo_blocks = 0;
		/* if no object is allocated on osts, the size on mds is valid.
		 * b=22272 */
		b->mbo_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
	} else if ((ma->ma_valid & MA_LOV) && ma->ma_lmm != NULL &&
		   ma->ma_lmm->lmm_pattern & LOV_PATTERN_F_RELEASED) {
		/* A released file stores its size on MDS. */
		/* But return 1 block for released file, unless tools like tar
		 * will consider it fully sparse. (LU-3864)
		 */
		if (unlikely(b->mbo_size == 0))
			b->mbo_blocks = 0;
		else
			b->mbo_blocks = 1;
		b->mbo_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
	}

	if (fid != NULL && (b->mbo_valid & OBD_MD_FLSIZE))
		CDEBUG(D_VFSTRACE, DFID": returning size %llu\n",
		       PFID(fid), (unsigned long long)b->mbo_size);
}

static inline int mdt_body_has_lov(const struct lu_attr *la,
				   const struct mdt_body *body)
{
	return (S_ISREG(la->la_mode) && (body->mbo_valid & OBD_MD_FLEASIZE)) ||
	       (S_ISDIR(la->la_mode) && (body->mbo_valid & OBD_MD_FLDIREA));
}

void mdt_client_compatibility(struct mdt_thread_info *info)
{
        struct mdt_body       *body;
        struct ptlrpc_request *req = mdt_info_req(info);
        struct obd_export     *exp = req->rq_export;
        struct md_attr        *ma = &info->mti_attr;
        struct lu_attr        *la = &ma->ma_attr;
        ENTRY;

	if (exp_connect_layout(exp))
		/* the client can deal with 16-bit lmm_stripe_count */
		RETURN_EXIT;

        body = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        if (!mdt_body_has_lov(la, body))
                RETURN_EXIT;

        /* now we have a reply with a lov for a client not compatible with the
         * layout lock so we have to clean the layout generation number */
        if (S_ISREG(la->la_mode))
                ma->ma_lmm->lmm_layout_gen = 0;
        EXIT;
}

static int mdt_attr_get_eabuf_size(struct mdt_thread_info *info,
				   struct mdt_object *o)
{
	const struct lu_env *env = info->mti_env;
	int rc, rc2;

	rc = mo_xattr_get(env, mdt_object_child(o), &LU_BUF_NULL,
			  XATTR_NAME_LOV);

	if (rc == -ENODATA)
		rc = 0;

	if (rc < 0)
		goto out;

	/* Is it a directory? Let's check for the LMV as well */
	if (S_ISDIR(lu_object_attr(&mdt_object_child(o)->mo_lu))) {
		rc2 = mo_xattr_get(env, mdt_object_child(o), &LU_BUF_NULL,
				   XATTR_NAME_LMV);

		if (rc2 == -ENODATA)
			rc2 = mo_xattr_get(env, mdt_object_child(o),
					   &LU_BUF_NULL,
					   XATTR_NAME_DEFAULT_LMV);

		if ((rc2 < 0 && rc2 != -ENODATA) || (rc2 > rc))
			rc = rc2;
	}

out:
	return rc;
}

int mdt_big_xattr_get(struct mdt_thread_info *info, struct mdt_object *o,
		      const char *name)
{
	const struct lu_env *env = info->mti_env;
	int rc;
	ENTRY;

	LASSERT(info->mti_big_lmm_used == 0);
	rc = mo_xattr_get(env, mdt_object_child(o), &LU_BUF_NULL, name);
	if (rc < 0)
		RETURN(rc);

	/* big_lmm may need to be grown */
	if (info->mti_big_lmmsize < rc) {
		int size = size_roundup_power2(rc);

		if (info->mti_big_lmmsize > 0) {
			/* free old buffer */
			LASSERT(info->mti_big_lmm);
			OBD_FREE_LARGE(info->mti_big_lmm,
				       info->mti_big_lmmsize);
			info->mti_big_lmm = NULL;
			info->mti_big_lmmsize = 0;
		}

		OBD_ALLOC_LARGE(info->mti_big_lmm, size);
		if (info->mti_big_lmm == NULL)
			RETURN(-ENOMEM);
		info->mti_big_lmmsize = size;
	}
	LASSERT(info->mti_big_lmmsize >= rc);

	info->mti_buf.lb_buf = info->mti_big_lmm;
	info->mti_buf.lb_len = info->mti_big_lmmsize;
	rc = mo_xattr_get(env, mdt_object_child(o), &info->mti_buf, name);

	RETURN(rc);
}

int mdt_stripe_get(struct mdt_thread_info *info, struct mdt_object *o,
		   struct md_attr *ma, const char *name)
{
	struct md_object *next = mdt_object_child(o);
	struct lu_buf    *buf = &info->mti_buf;
	int rc;

	if (strcmp(name, XATTR_NAME_LOV) == 0) {
		buf->lb_buf = ma->ma_lmm;
		buf->lb_len = ma->ma_lmm_size;
		LASSERT(!(ma->ma_valid & MA_LOV));
	} else if (strcmp(name, XATTR_NAME_LMV) == 0) {
		buf->lb_buf = ma->ma_lmv;
		buf->lb_len = ma->ma_lmv_size;
		LASSERT(!(ma->ma_valid & MA_LMV));
	} else if (strcmp(name, XATTR_NAME_DEFAULT_LMV) == 0) {
		buf->lb_buf = ma->ma_lmv;
		buf->lb_len = ma->ma_lmv_size;
		LASSERT(!(ma->ma_valid & MA_LMV_DEF));
	} else {
		return -EINVAL;
	}

	rc = mo_xattr_get(info->mti_env, next, buf, name);
	if (rc > 0) {

got:
		if (strcmp(name, XATTR_NAME_LOV) == 0) {
			if (info->mti_big_lmm_used)
				ma->ma_lmm = info->mti_big_lmm;

			/* NOT return LOV EA with hole to old client. */
			if (unlikely(le32_to_cpu(ma->ma_lmm->lmm_pattern) &
				     LOV_PATTERN_F_HOLE) &&
			    !(exp_connect_flags(info->mti_exp) &
			      OBD_CONNECT_LFSCK)) {
				return -EIO;
			} else {
				ma->ma_lmm_size = rc;
				ma->ma_valid |= MA_LOV;
			}
		} else if (strcmp(name, XATTR_NAME_LMV) == 0) {
			if (info->mti_big_lmm_used)
				ma->ma_lmv = info->mti_big_lmm;

			ma->ma_lmv_size = rc;
			ma->ma_valid |= MA_LMV;
		} else if (strcmp(name, XATTR_NAME_DEFAULT_LMV) == 0) {
			ma->ma_lmv_size = rc;
			ma->ma_valid |= MA_LMV_DEF;
		}

		/* Update mdt_max_mdsize so all clients will be aware that */
		if (info->mti_mdt->mdt_max_mdsize < rc)
			info->mti_mdt->mdt_max_mdsize = rc;

		rc = 0;
	} else if (rc == -ENODATA) {
		/* no LOV EA */
		rc = 0;
	} else if (rc == -ERANGE) {
		/* Default LMV has fixed size, so it must be able to fit
		 * in the original buffer */
		if (strcmp(name, XATTR_NAME_DEFAULT_LMV) == 0)
			return rc;
		rc = mdt_big_xattr_get(info, o, name);
		if (rc > 0) {
			info->mti_big_lmm_used = 1;
			goto got;
		}
	}

	return rc;
}

static int mdt_attr_get_pfid(struct mdt_thread_info *info,
			     struct mdt_object *o, struct lu_fid *pfid)
{
	struct lu_buf		*buf = &info->mti_buf;
	struct link_ea_header	*leh;
	struct link_ea_entry	*lee;
	int			 rc;
	ENTRY;

	buf->lb_buf = info->mti_big_lmm;
	buf->lb_len = info->mti_big_lmmsize;
	rc = mo_xattr_get(info->mti_env, mdt_object_child(o),
			  buf, XATTR_NAME_LINK);
	/* ignore errors, MA_PFID won't be set and it is
	 * up to the caller to treat this as an error */
	if (rc == -ERANGE || buf->lb_len == 0) {
		rc = mdt_big_xattr_get(info, o, XATTR_NAME_LINK);
		buf->lb_buf = info->mti_big_lmm;
		buf->lb_len = info->mti_big_lmmsize;
	}

	if (rc < 0)
		RETURN(rc);
	if (rc < sizeof(*leh)) {
		CERROR("short LinkEA on "DFID": rc = %d\n",
		       PFID(mdt_object_fid(o)), rc);
		RETURN(-ENODATA);
	}

	leh = (struct link_ea_header *) buf->lb_buf;
	lee = (struct link_ea_entry *)(leh + 1);
	if (leh->leh_magic == __swab32(LINK_EA_MAGIC)) {
		leh->leh_magic = LINK_EA_MAGIC;
		leh->leh_reccount = __swab32(leh->leh_reccount);
		leh->leh_len = __swab64(leh->leh_len);
	}
	if (leh->leh_magic != LINK_EA_MAGIC)
		RETURN(-EINVAL);
	if (leh->leh_reccount == 0)
		RETURN(-ENODATA);

	memcpy(pfid, &lee->lee_parent_fid, sizeof(*pfid));
	fid_be_to_cpu(pfid, pfid);

	RETURN(0);
}

int mdt_attr_get_complex(struct mdt_thread_info *info,
			 struct mdt_object *o, struct md_attr *ma)
{
	const struct lu_env *env = info->mti_env;
	struct md_object    *next = mdt_object_child(o);
	struct lu_buf       *buf = &info->mti_buf;
	int                  need = ma->ma_need;
	int                  rc = 0, rc2;
	u32                  mode;
	ENTRY;

	ma->ma_valid = 0;

	if (mdt_object_exists(o) == 0)
		GOTO(out, rc = -ENOENT);
	mode = lu_object_attr(&next->mo_lu);

	if (need & MA_INODE) {
		ma->ma_need = MA_INODE;
		rc = mo_attr_get(env, next, ma);
		if (rc)
			GOTO(out, rc);
		ma->ma_valid |= MA_INODE;
	}

	if (need & MA_PFID) {
		rc = mdt_attr_get_pfid(info, o, &ma->ma_pfid);
		if (rc == 0)
			ma->ma_valid |= MA_PFID;
		/* ignore this error, parent fid is not mandatory */
		rc = 0;
	}

	if (need & MA_LOV && (S_ISREG(mode) || S_ISDIR(mode))) {
		rc = mdt_stripe_get(info, o, ma, XATTR_NAME_LOV);
		if (rc)
			GOTO(out, rc);
	}

	if (need & MA_LMV && S_ISDIR(mode)) {
		rc = mdt_stripe_get(info, o, ma, XATTR_NAME_LMV);
		if (rc != 0)
			GOTO(out, rc);
	}

	if (need & MA_LMV_DEF && S_ISDIR(mode)) {
		rc = mdt_stripe_get(info, o, ma, XATTR_NAME_DEFAULT_LMV);
		if (rc != 0)
			GOTO(out, rc);
	}

	if (need & MA_HSM && S_ISREG(mode)) {
		buf->lb_buf = info->mti_xattr_buf;
		buf->lb_len = sizeof(info->mti_xattr_buf);
		CLASSERT(sizeof(struct hsm_attrs) <=
			 sizeof(info->mti_xattr_buf));
		rc2 = mo_xattr_get(info->mti_env, next, buf, XATTR_NAME_HSM);
		rc2 = lustre_buf2hsm(info->mti_xattr_buf, rc2, &ma->ma_hsm);
		if (rc2 == 0)
			ma->ma_valid |= MA_HSM;
		else if (rc2 < 0 && rc2 != -ENODATA)
			GOTO(out, rc = rc2);
	}

#ifdef CONFIG_FS_POSIX_ACL
	if (need & MA_ACL_DEF && S_ISDIR(mode)) {
		buf->lb_buf = ma->ma_acl;
		buf->lb_len = ma->ma_acl_size;
		rc2 = mo_xattr_get(env, next, buf, XATTR_NAME_ACL_DEFAULT);
		if (rc2 > 0) {
			ma->ma_acl_size = rc2;
			ma->ma_valid |= MA_ACL_DEF;
		} else if (rc2 == -ENODATA) {
			/* no ACLs */
			ma->ma_acl_size = 0;
		} else
			GOTO(out, rc = rc2);
	}
#endif
out:
	ma->ma_need = need;
	CDEBUG(D_INODE, "after getattr rc = %d, ma_valid = "LPX64" ma_lmm=%p\n",
	       rc, ma->ma_valid, ma->ma_lmm);
	RETURN(rc);
}

static int mdt_getattr_internal(struct mdt_thread_info *info,
                                struct mdt_object *o, int ma_need)
{
	struct md_object	*next = mdt_object_child(o);
	const struct mdt_body	*reqbody = info->mti_body;
	struct ptlrpc_request	*req = mdt_info_req(info);
	struct md_attr		*ma = &info->mti_attr;
	struct lu_attr		*la = &ma->ma_attr;
	struct req_capsule	*pill = info->mti_pill;
	const struct lu_env	*env = info->mti_env;
	struct mdt_body		*repbody;
	struct lu_buf		*buffer = &info->mti_buf;
	struct obd_export	*exp = info->mti_exp;
	struct lu_nodemap	*nodemap = exp->exp_target_data.ted_nodemap;
	int			 rc;
	int			 is_root;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK))
		RETURN(err_serious(-ENOMEM));

	repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);

	ma->ma_valid = 0;

	if (mdt_object_remote(o)) {
		/* This object is located on remote node.*/
		/* Return -ENOTSUPP for old client */
		if (!mdt_is_dne_client(req->rq_export))
			GOTO(out, rc = -ENOTSUPP);

		repbody->mbo_fid1 = *mdt_object_fid(o);
		repbody->mbo_valid = OBD_MD_FLID | OBD_MD_MDS;
		GOTO(out, rc = 0);
	}

	if (reqbody->mbo_eadatasize > 0) {
		buffer->lb_buf = req_capsule_server_get(pill, &RMF_MDT_MD);
		if (buffer->lb_buf == NULL)
			GOTO(out, rc = -EPROTO);
		buffer->lb_len = req_capsule_get_size(pill, &RMF_MDT_MD,
						      RCL_SERVER);
	} else {
		buffer->lb_buf = NULL;
		buffer->lb_len = 0;
		ma_need &= ~(MA_LOV | MA_LMV);
		CDEBUG(D_INFO, "%s: RPC from %s: does not need LOVEA.\n",
		       mdt_obd_name(info->mti_mdt),
		       req->rq_export->exp_client_uuid.uuid);
	}

	/* If it is dir object and client require MEA, then we got MEA */
	if (S_ISDIR(lu_object_attr(&next->mo_lu)) &&
	    (reqbody->mbo_valid & (OBD_MD_MEA | OBD_MD_DEFAULT_MEA))) {
		/* Assumption: MDT_MD size is enough for lmv size. */
		ma->ma_lmv = buffer->lb_buf;
		ma->ma_lmv_size = buffer->lb_len;
		ma->ma_need = MA_INODE;
		if (ma->ma_lmv_size > 0) {
			if (reqbody->mbo_valid & OBD_MD_MEA)
				ma->ma_need |= MA_LMV;
			else if (reqbody->mbo_valid & OBD_MD_DEFAULT_MEA)
				ma->ma_need |= MA_LMV_DEF;
		}
	} else {
		ma->ma_lmm = buffer->lb_buf;
		ma->ma_lmm_size = buffer->lb_len;
		ma->ma_need = MA_INODE | MA_HSM;
		if (ma->ma_lmm_size > 0)
			ma->ma_need |= MA_LOV;
	}

        if (S_ISDIR(lu_object_attr(&next->mo_lu)) &&
	    reqbody->mbo_valid & OBD_MD_FLDIREA  &&
            lustre_msg_get_opc(req->rq_reqmsg) == MDS_GETATTR) {
                /* get default stripe info for this dir. */
                ma->ma_need |= MA_LOV_DEF;
        }
        ma->ma_need |= ma_need;

	rc = mdt_attr_get_complex(info, o, ma);
	if (unlikely(rc)) {
		CERROR("%s: getattr error for "DFID": rc = %d\n",
		       mdt_obd_name(info->mti_mdt),
		       PFID(mdt_object_fid(o)), rc);
		RETURN(rc);
	}

	/* if file is released, check if a restore is running */
	if (ma->ma_valid & MA_HSM) {
		repbody->mbo_valid |= OBD_MD_TSTATE;
		if ((ma->ma_hsm.mh_flags & HS_RELEASED) &&
		    mdt_hsm_restore_is_running(info, mdt_object_fid(o)))
			repbody->mbo_t_state = MS_RESTORE;
	}

	is_root = lu_fid_eq(mdt_object_fid(o), &info->mti_mdt->mdt_md_root_fid);

	/* the Lustre protocol supposes to return default striping
	 * on the user-visible root if explicitly requested */
	if ((ma->ma_valid & MA_LOV) == 0 && S_ISDIR(la->la_mode) &&
	    (ma->ma_need & MA_LOV_DEF && is_root) && ma->ma_need & MA_LOV) {
		struct lu_fid      rootfid;
		struct mdt_object *root;
		struct mdt_device *mdt = info->mti_mdt;

		rc = dt_root_get(env, mdt->mdt_bottom, &rootfid);
		if (rc)
			RETURN(rc);
		root = mdt_object_find(env, mdt, &rootfid);
		if (IS_ERR(root))
			RETURN(PTR_ERR(root));
		rc = mdt_stripe_get(info, root, ma, XATTR_NAME_LOV);
		mdt_object_put(info->mti_env, root);
		if (unlikely(rc)) {
			CERROR("%s: getattr error for "DFID": rc = %d\n",
			       mdt_obd_name(info->mti_mdt),
			       PFID(mdt_object_fid(o)), rc);
			RETURN(rc);
		}
	}

        if (likely(ma->ma_valid & MA_INODE))
                mdt_pack_attr2body(info, repbody, la, mdt_object_fid(o));
        else
                RETURN(-EFAULT);

        if (mdt_body_has_lov(la, reqbody)) {
                if (ma->ma_valid & MA_LOV) {
                        LASSERT(ma->ma_lmm_size);
			repbody->mbo_eadatasize = ma->ma_lmm_size;
			if (S_ISDIR(la->la_mode))
				repbody->mbo_valid |= OBD_MD_FLDIREA;
			else
				repbody->mbo_valid |= OBD_MD_FLEASIZE;
			mdt_dump_lmm(D_INFO, ma->ma_lmm, repbody->mbo_valid);
                }
		if (ma->ma_valid & MA_LMV) {
			/* Return -ENOTSUPP for old client */
			if (!mdt_is_striped_client(req->rq_export))
				RETURN(-ENOTSUPP);

			LASSERT(S_ISDIR(la->la_mode));
			mdt_dump_lmv(D_INFO, ma->ma_lmv);
			repbody->mbo_eadatasize = ma->ma_lmv_size;
			repbody->mbo_valid |= (OBD_MD_FLDIREA|OBD_MD_MEA);
		}
		if (ma->ma_valid & MA_LMV_DEF) {
			/* Return -ENOTSUPP for old client */
			if (!mdt_is_striped_client(req->rq_export))
				RETURN(-ENOTSUPP);
			LASSERT(S_ISDIR(la->la_mode));
			repbody->mbo_eadatasize = ma->ma_lmv_size;
			repbody->mbo_valid |= (OBD_MD_FLDIREA |
					       OBD_MD_DEFAULT_MEA);
		}
	} else if (S_ISLNK(la->la_mode) &&
		   reqbody->mbo_valid & OBD_MD_LINKNAME) {
		buffer->lb_buf = ma->ma_lmm;
		/* eadatasize from client includes NULL-terminator, so
		 * there is no need to read it */
		buffer->lb_len = reqbody->mbo_eadatasize - 1;
		rc = mo_readlink(env, next, buffer);
		if (unlikely(rc <= 0)) {
			CERROR("%s: readlink failed for "DFID": rc = %d\n",
			       mdt_obd_name(info->mti_mdt),
			       PFID(mdt_object_fid(o)), rc);
			rc = -EFAULT;
		} else {
			int print_limit = min_t(int, PAGE_CACHE_SIZE - 128, rc);

			if (OBD_FAIL_CHECK(OBD_FAIL_MDS_READLINK_EPROTO))
				rc -= 2;
			repbody->mbo_valid |= OBD_MD_LINKNAME;
			/* we need to report back size with NULL-terminator
			 * because client expects that */
			repbody->mbo_eadatasize = rc + 1;
			if (repbody->mbo_eadatasize != reqbody->mbo_eadatasize)
				CDEBUG(D_INODE, "%s: Read shorter symlink %d "
				       "on "DFID ", expected %d\n",
				       mdt_obd_name(info->mti_mdt),
				       rc, PFID(mdt_object_fid(o)),
				       reqbody->mbo_eadatasize - 1);
			/* NULL terminate */
			((char *)ma->ma_lmm)[rc] = 0;

			/* If the total CDEBUG() size is larger than a page, it
			 * will print a warning to the console, avoid this by
			 * printing just the last part of the symlink. */
			CDEBUG(D_INODE, "symlink dest %s%.*s, len = %d\n",
			       print_limit < rc ? "..." : "", print_limit,
			       (char *)ma->ma_lmm + rc - print_limit, rc);
			rc = 0;
                }
        }

	if (reqbody->mbo_valid & OBD_MD_FLMODEASIZE) {
		repbody->mbo_max_mdsize = info->mti_mdt->mdt_max_mdsize;
		repbody->mbo_valid |= OBD_MD_FLMODEASIZE;
		CDEBUG(D_INODE, "changing the max MD size to %u\n",
		       repbody->mbo_max_mdsize);
	}

	if (exp_connect_rmtclient(info->mti_exp) &&
	    reqbody->mbo_valid & OBD_MD_FLRMTPERM) {
		void *buf = req_capsule_server_get(pill, &RMF_ACL);

		/* mdt_getattr_lock only */
		rc = mdt_pack_remote_perm(info, o, buf);
		if (rc) {
			repbody->mbo_valid &= ~OBD_MD_FLRMTPERM;
			repbody->mbo_aclsize = 0;
			RETURN(rc);
		} else {
			repbody->mbo_valid |= OBD_MD_FLRMTPERM;
			repbody->mbo_aclsize = sizeof(struct mdt_remote_perm);
		}
	}
#ifdef CONFIG_FS_POSIX_ACL
	else if ((exp_connect_flags(req->rq_export) & OBD_CONNECT_ACL) &&
		 (reqbody->mbo_valid & OBD_MD_FLACL))
		rc = mdt_pack_acl2body(info, repbody, o, nodemap);
#endif

out:
        if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_GETATTR);

        RETURN(rc);
}

static int mdt_getattr(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info = tsi2mdt_info(tsi);
        struct mdt_object       *obj = info->mti_object;
        struct req_capsule      *pill = info->mti_pill;
        struct mdt_body         *reqbody;
        struct mdt_body         *repbody;
        int rc, rc2;
        ENTRY;

        reqbody = req_capsule_client_get(pill, &RMF_MDT_BODY);
        LASSERT(reqbody);
        LASSERT(obj != NULL);
	LASSERT(lu_object_assert_exists(&obj->mot_obj));

	/* Unlike intent case where we need to pre-fill out buffers early on
	 * in intent policy for ldlm reasons, here we can have a much better
	 * guess at EA size by just reading it from disk.
	 * Exceptions are readdir and (missing) directory striping */
	/* Readlink */
	if (reqbody->mbo_valid & OBD_MD_LINKNAME) {
		/* No easy way to know how long is the symlink, but it cannot
		 * be more than PATH_MAX, so we allocate +1 */
		rc = PATH_MAX + 1;

	/* A special case for fs ROOT: getattr there might fetch
	 * default EA for entire fs, not just for this dir!
	 */
	} else if (lu_fid_eq(mdt_object_fid(obj),
			     &info->mti_mdt->mdt_md_root_fid) &&
		   (reqbody->mbo_valid & OBD_MD_FLDIREA) &&
		   (lustre_msg_get_opc(mdt_info_req(info)->rq_reqmsg) ==
								 MDS_GETATTR)) {
		/* Should the default strping be bigger, mdt_fix_reply
		 * will reallocate */
		rc = DEF_REP_MD_SIZE;
	} else {
		/* Read the actual EA size from disk */
		rc = mdt_attr_get_eabuf_size(info, obj);
	}

	if (rc < 0)
		GOTO(out, rc = err_serious(rc));

	req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, rc);

	rc = req_capsule_server_pack(pill);
	if (unlikely(rc != 0))
		GOTO(out, rc = err_serious(rc));

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);
        LASSERT(repbody != NULL);
	repbody->mbo_eadatasize = 0;
	repbody->mbo_aclsize = 0;

	if (reqbody->mbo_valid & OBD_MD_FLRMTPERM)
		rc = mdt_init_ucred(info, reqbody);
	else
		rc = mdt_check_ucred(info);
	if (unlikely(rc))
		GOTO(out_shrink, rc);

	info->mti_cross_ref = !!(reqbody->mbo_valid & OBD_MD_FLCROSSREF);

	rc = mdt_getattr_internal(info, obj, 0);
	if (reqbody->mbo_valid & OBD_MD_FLRMTPERM)
                mdt_exit_ucred(info);
        EXIT;
out_shrink:
        mdt_client_compatibility(info);
        rc2 = mdt_fix_reply(info);
        if (rc == 0)
                rc = rc2;
out:
	mdt_thread_info_fini(info);
	return rc;
}

/**
 * Exchange MOF_LOV_CREATED flags between two objects after a
 * layout swap. No assumption is made on whether o1 or o2 have
 * created objects or not.
 *
 * \param[in,out] o1	First swap layout object
 * \param[in,out] o2	Second swap layout object
 */
static void mdt_swap_lov_flag(struct mdt_object *o1, struct mdt_object *o2)
{
	__u64	o1_flags;

	mutex_lock(&o1->mot_lov_mutex);
	mutex_lock(&o2->mot_lov_mutex);

	o1_flags = o1->mot_flags;
	o1->mot_flags = (o1->mot_flags & ~MOF_LOV_CREATED) |
			(o2->mot_flags & MOF_LOV_CREATED);

	o2->mot_flags = (o2->mot_flags & ~MOF_LOV_CREATED) |
			(o1_flags & MOF_LOV_CREATED);

	mutex_unlock(&o2->mot_lov_mutex);
	mutex_unlock(&o1->mot_lov_mutex);
}

static int mdt_swap_layouts(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info;
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct obd_export	*exp = req->rq_export;
	struct mdt_object	*o1, *o2, *o;
	struct mdt_lock_handle	*lh1, *lh2;
	struct mdc_swap_layouts *msl;
	int			 rc;
	ENTRY;

	/* client does not support layout lock, so layout swaping
	 * is disabled.
	 * FIXME: there is a problem for old clients which don't support
	 * layout lock yet. If those clients have already opened the file
	 * they won't be notified at all so that old layout may still be
	 * used to do IO. This can be fixed after file release is landed by
	 * doing exclusive open and taking full EX ibits lock. - Jinshan */
	if (!exp_connect_layout(exp))
		RETURN(-EOPNOTSUPP);

	info = tsi2mdt_info(tsi);

	if (info->mti_dlm_req != NULL)
		ldlm_request_cancel(req, info->mti_dlm_req, 0, LATF_SKIP);

	o1 = info->mti_object;
	o = o2 = mdt_object_find(info->mti_env, info->mti_mdt,
				&info->mti_body->mbo_fid2);
	if (IS_ERR(o))
		GOTO(out, rc = PTR_ERR(o));

	if (mdt_object_remote(o) || !mdt_object_exists(o)) /* remote object */
		GOTO(put, rc = -ENOENT);

	rc = lu_fid_cmp(&info->mti_body->mbo_fid1, &info->mti_body->mbo_fid2);
	if (unlikely(rc == 0)) /* same file, you kidding me? no-op. */
		GOTO(put, rc);

	if (rc < 0)
		swap(o1, o2);

	/* permission check. Make sure the calling process having permission
	 * to write both files. */
	rc = mo_permission(info->mti_env, NULL, mdt_object_child(o1), NULL,
				MAY_WRITE);
	if (rc < 0)
		GOTO(put, rc);

	rc = mo_permission(info->mti_env, NULL, mdt_object_child(o2), NULL,
				MAY_WRITE);
	if (rc < 0)
		GOTO(put, rc);

	msl = req_capsule_client_get(info->mti_pill, &RMF_SWAP_LAYOUTS);
	if (msl == NULL)
		GOTO(put, rc = -EPROTO);

	lh1 = &info->mti_lh[MDT_LH_NEW];
	mdt_lock_reg_init(lh1, LCK_EX);
	lh2 = &info->mti_lh[MDT_LH_OLD];
	mdt_lock_reg_init(lh2, LCK_EX);

	rc = mdt_object_lock(info, o1, lh1, MDS_INODELOCK_LAYOUT |
			     MDS_INODELOCK_XATTR);
	if (rc < 0)
		GOTO(put, rc);

	rc = mdt_object_lock(info, o2, lh2, MDS_INODELOCK_LAYOUT |
			     MDS_INODELOCK_XATTR);
	if (rc < 0)
		GOTO(unlock1, rc);

	rc = mo_swap_layouts(info->mti_env, mdt_object_child(o1),
			     mdt_object_child(o2), msl->msl_flags);
	if (rc < 0)
		GOTO(unlock2, rc);

	mdt_swap_lov_flag(o1, o2);

unlock2:
	mdt_object_unlock(info, o2, lh2, rc);
unlock1:
	mdt_object_unlock(info, o1, lh1, rc);
put:
	mdt_object_put(info->mti_env, o);
out:
	mdt_thread_info_fini(info);
	RETURN(rc);
}

static int mdt_raw_lookup(struct mdt_thread_info *info,
			  struct mdt_object *parent,
			  const struct lu_name *lname,
			  struct ldlm_reply *ldlm_rep)
{
	struct lu_fid	*child_fid = &info->mti_tmp_fid1;
	int		 rc;
	ENTRY;

	LASSERT(!info->mti_cross_ref);

	/* Only got the fid of this obj by name */
	fid_zero(child_fid);
	rc = mdo_lookup(info->mti_env, mdt_object_child(info->mti_object),
			lname, child_fid, &info->mti_spec);
	if (rc == 0) {
		struct mdt_body *repbody;

		repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		repbody->mbo_fid1 = *child_fid;
		repbody->mbo_valid = OBD_MD_FLID;
		mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
	} else if (rc == -ENOENT) {
		mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_NEG);
	}

	RETURN(rc);
}

/*
 * UPDATE lock should be taken against parent, and be released before exit;
 * child_bits lock should be taken against child, and be returned back:
 *            (1)normal request should release the child lock;
 *            (2)intent request will grant the lock to client.
 */
static int mdt_getattr_name_lock(struct mdt_thread_info *info,
                                 struct mdt_lock_handle *lhc,
                                 __u64 child_bits,
                                 struct ldlm_reply *ldlm_rep)
{
        struct ptlrpc_request  *req       = mdt_info_req(info);
        struct mdt_body        *reqbody   = NULL;
        struct mdt_object      *parent    = info->mti_object;
        struct mdt_object      *child;
        struct lu_fid          *child_fid = &info->mti_tmp_fid1;
        struct lu_name         *lname     = NULL;
        struct mdt_lock_handle *lhp       = NULL;
        struct ldlm_lock       *lock;
	bool			is_resent;
	bool			try_layout;
	int			ma_need = 0;
	int			rc;
	ENTRY;

	is_resent = lustre_handle_is_used(&lhc->mlh_reg_lh);
	LASSERT(ergo(is_resent,
		     lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT));

	if (parent == NULL)
		RETURN(-ENOENT);

	if (info->mti_cross_ref) {
		/* Only getattr on the child. Parent is on another node. */
		mdt_set_disposition(info, ldlm_rep,
				    DISP_LOOKUP_EXECD | DISP_LOOKUP_POS);
		child = parent;
		CDEBUG(D_INODE, "partial getattr_name child_fid = "DFID", "
		       "ldlm_rep = %p\n",
		       PFID(mdt_object_fid(child)), ldlm_rep);

		rc = mdt_check_resent_lock(info, child, lhc);
		if (rc < 0) {
			RETURN(rc);
		} else if (rc > 0) {
			mdt_lock_handle_init(lhc);
			mdt_lock_reg_init(lhc, LCK_PR);

			/*
			 * Object's name is on another MDS, no lookup or layout
			 * lock is needed here but update lock is.
			 */
			child_bits &= ~(MDS_INODELOCK_LOOKUP |
					MDS_INODELOCK_LAYOUT);
			child_bits |= MDS_INODELOCK_PERM | MDS_INODELOCK_UPDATE;

			rc = mdt_object_lock(info, child, lhc, child_bits);
			if (rc < 0)
				RETURN(rc);
		}

		/* Finally, we can get attr for child. */
		if (!mdt_object_exists(child)) {
			LU_OBJECT_DEBUG(D_INFO, info->mti_env,
					&child->mot_obj,
					"remote object doesn't exist.\n");
			mdt_object_unlock(info, child, lhc, 1);
			RETURN(-ENOENT);
		}

		rc = mdt_getattr_internal(info, child, 0);
		if (unlikely(rc != 0))
			mdt_object_unlock(info, child, lhc, 1);

                RETURN(rc);
        }

	lname = &info->mti_name;
	mdt_name_unpack(info->mti_pill, &RMF_NAME, lname, MNF_FIX_ANON);

	if (lu_name_is_valid(lname)) {
		CDEBUG(D_INODE, "getattr with lock for "DFID"/"DNAME", "
		       "ldlm_rep = %p\n", PFID(mdt_object_fid(parent)),
		       PNAME(lname), ldlm_rep);
	} else {
		reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
		if (unlikely(reqbody == NULL))
			RETURN(err_serious(-EPROTO));

		*child_fid = reqbody->mbo_fid2;

		if (unlikely(!fid_is_sane(child_fid)))
			RETURN(err_serious(-EINVAL));

		CDEBUG(D_INODE, "getattr with lock for "DFID"/"DFID", "
		       "ldlm_rep = %p\n",
		       PFID(mdt_object_fid(parent)),
		       PFID(&reqbody->mbo_fid2), ldlm_rep);
	}

	mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_EXECD);

	if (unlikely(!mdt_object_exists(parent)) && lu_name_is_valid(lname)) {
		LU_OBJECT_DEBUG(D_INODE, info->mti_env,
				&parent->mot_obj,
				"Parent doesn't exist!\n");
		RETURN(-ESTALE);
	}

	if (mdt_object_remote(parent)) {
		CERROR("%s: parent "DFID" is on remote target\n",
		       mdt_obd_name(info->mti_mdt),
		       PFID(mdt_object_fid(parent)));
		RETURN(-EIO);
	}

	if (lu_name_is_valid(lname)) {
		/* Always allow to lookup ".." */
		if (unlikely(lname->ln_namelen == 2 &&
			     lname->ln_name[0] == '.' &&
			     lname->ln_name[1] == '.'))
			info->mti_spec.sp_permitted = 1;

		if (info->mti_body->mbo_valid == OBD_MD_FLID) {
			rc = mdt_raw_lookup(info, parent, lname, ldlm_rep);

			RETURN(rc);
		}

		/* step 1: lock parent only if parent is a directory */
		if (S_ISDIR(lu_object_attr(&parent->mot_obj))) {
			lhp = &info->mti_lh[MDT_LH_PARENT];
			mdt_lock_pdo_init(lhp, LCK_PR, lname);
			rc = mdt_object_lock(info, parent, lhp,
					     MDS_INODELOCK_UPDATE);
			if (unlikely(rc != 0))
				RETURN(rc);
		}

                /* step 2: lookup child's fid by name */
                fid_zero(child_fid);
		rc = mdo_lookup(info->mti_env, mdt_object_child(parent), lname,
				child_fid, &info->mti_spec);
		if (rc == -ENOENT)
			mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_NEG);

		if (rc != 0)
			GOTO(out_parent, rc);
	}

	mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);

	/*
	 *step 3: find the child object by fid & lock it.
	 *        regardless if it is local or remote.
	 *
	 *Note: LU-3240 (commit 762f2114d282a98ebfa4dbbeea9298a8088ad24e)
	 *	set parent dir fid the same as child fid in getattr by fid case
	 *	we should not lu_object_find() the object again, could lead
	 *	to hung if there is a concurrent unlink destroyed the object.
	 */
	if (lu_fid_eq(mdt_object_fid(parent), child_fid)) {
		mdt_object_get(info->mti_env, parent);
		child = parent;
	} else {
		child = mdt_object_find(info->mti_env, info->mti_mdt,
					child_fid);
	}

	if (unlikely(IS_ERR(child)))
		GOTO(out_parent, rc = PTR_ERR(child));

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RESEND, obd_timeout * 2);
	if (!mdt_object_exists(child)) {
		LU_OBJECT_DEBUG(D_INODE, info->mti_env,
				&child->mot_obj,
				"Object doesn't exist!\n");
		GOTO(out_child, rc = -ENOENT);
	}

	rc = mdt_check_resent_lock(info, child, lhc);
	if (rc < 0) {
		GOTO(out_child, rc);
	} else if (rc > 0) {
                mdt_lock_handle_init(lhc);
		mdt_lock_reg_init(lhc, LCK_PR);
		try_layout = false;

		if (!(child_bits & MDS_INODELOCK_UPDATE) &&
		      mdt_object_exists(child) && !mdt_object_remote(child)) {
                        struct md_attr *ma = &info->mti_attr;

                        ma->ma_valid = 0;
                        ma->ma_need = MA_INODE;
			rc = mdt_attr_get_complex(info, child, ma);
                        if (unlikely(rc != 0))
                                GOTO(out_child, rc);

			/* If the file has not been changed for some time, we
			 * return not only a LOOKUP lock, but also an UPDATE
			 * lock and this might save us RPC on later STAT. For
			 * directories, it also let negative dentry cache start
			 * working for this dir. */
                        if (ma->ma_valid & MA_INODE &&
                            ma->ma_attr.la_valid & LA_CTIME &&
                            info->mti_mdt->mdt_namespace->ns_ctime_age_limit +
                                ma->ma_attr.la_ctime < cfs_time_current_sec())
                                child_bits |= MDS_INODELOCK_UPDATE;
                }

		/* layout lock must be granted in a best-effort way
		 * for IT operations */
		LASSERT(!(child_bits & MDS_INODELOCK_LAYOUT));
		if (!OBD_FAIL_CHECK(OBD_FAIL_MDS_NO_LL_GETATTR) &&
		    exp_connect_layout(info->mti_exp) &&
		    S_ISREG(lu_object_attr(&child->mot_obj)) &&
		    !mdt_object_remote(child) && ldlm_rep != NULL) {
			/* try to grant layout lock for regular file. */
			try_layout = true;
		}

		rc = 0;
		if (try_layout) {
			child_bits |= MDS_INODELOCK_LAYOUT;
			/* try layout lock, it may fail to be granted due to
			 * contention at LOOKUP or UPDATE */
			if (!mdt_object_lock_try(info, child, lhc,
						 child_bits)) {
				child_bits &= ~MDS_INODELOCK_LAYOUT;
				LASSERT(child_bits != 0);
				rc = mdt_object_lock(info, child, lhc,
						     child_bits);
			} else {
				ma_need |= MA_LOV;
			}
		} else {
			/* Do not enqueue the UPDATE lock from MDT(cross-MDT),
			 * client will enqueue the lock to the remote MDT */
			if (mdt_object_remote(child))
				child_bits &= ~MDS_INODELOCK_UPDATE;
			rc = mdt_object_lock(info, child, lhc, child_bits);
		}
                if (unlikely(rc != 0))
                        GOTO(out_child, rc);
        }

        lock = ldlm_handle2lock(&lhc->mlh_reg_lh);

        /* finally, we can get attr for child. */
        rc = mdt_getattr_internal(info, child, ma_need);
        if (unlikely(rc != 0)) {
                mdt_object_unlock(info, child, lhc, 1);
	} else if (lock) {
		/* Debugging code. */
		LDLM_DEBUG(lock, "Returning lock to client");
		LASSERTF(fid_res_name_eq(mdt_object_fid(child),
					 &lock->l_resource->lr_name),
			 "Lock res_id: "DLDLMRES", fid: "DFID"\n",
			 PLDLMRES(lock->l_resource),
			 PFID(mdt_object_fid(child)));
        }
        if (lock)
                LDLM_LOCK_PUT(lock);

        EXIT;
out_child:
        mdt_object_put(info->mti_env, child);
out_parent:
        if (lhp)
                mdt_object_unlock(info, parent, lhp, 1);
        return rc;
}

/* normal handler: should release the child lock */
static int mdt_getattr_name(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info = tsi2mdt_info(tsi);
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_CHILD];
        struct mdt_body        *reqbody;
        struct mdt_body        *repbody;
        int rc, rc2;
        ENTRY;

        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(reqbody != NULL);
        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(repbody != NULL);

	info->mti_cross_ref = !!(reqbody->mbo_valid & OBD_MD_FLCROSSREF);
	repbody->mbo_eadatasize = 0;
	repbody->mbo_aclsize = 0;

        rc = mdt_init_ucred_intent_getattr(info, reqbody);
        if (unlikely(rc))
                GOTO(out_shrink, rc);

        rc = mdt_getattr_name_lock(info, lhc, MDS_INODELOCK_UPDATE, NULL);
        if (lustre_handle_is_used(&lhc->mlh_reg_lh)) {
                ldlm_lock_decref(&lhc->mlh_reg_lh, lhc->mlh_reg_mode);
                lhc->mlh_reg_lh.cookie = 0;
        }
        mdt_exit_ucred(info);
        EXIT;
out_shrink:
        mdt_client_compatibility(info);
        rc2 = mdt_fix_reply(info);
        if (rc == 0)
                rc = rc2;
	mdt_thread_info_fini(info);
	return rc;
}

static int mdt_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
			 void *karg, void __user *uarg);

static int mdt_set_info(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	char			*key;
	void			*val;
	int			 keylen, vallen, rc = 0;

	ENTRY;

	key = req_capsule_client_get(tsi->tsi_pill, &RMF_SETINFO_KEY);
	if (key == NULL) {
		DEBUG_REQ(D_HA, req, "no set_info key");
		RETURN(err_serious(-EFAULT));
	}

	keylen = req_capsule_get_size(tsi->tsi_pill, &RMF_SETINFO_KEY,
				      RCL_CLIENT);

	val = req_capsule_client_get(tsi->tsi_pill, &RMF_SETINFO_VAL);
	if (val == NULL) {
		DEBUG_REQ(D_HA, req, "no set_info val");
		RETURN(err_serious(-EFAULT));
	}

	vallen = req_capsule_get_size(tsi->tsi_pill, &RMF_SETINFO_VAL,
				      RCL_CLIENT);

	/* Swab any part of val you need to here */
	if (KEY_IS(KEY_READ_ONLY)) {
		spin_lock(&req->rq_export->exp_lock);
		if (*(__u32 *)val)
			*exp_connect_flags_ptr(req->rq_export) |=
				OBD_CONNECT_RDONLY;
		else
			*exp_connect_flags_ptr(req->rq_export) &=
				~OBD_CONNECT_RDONLY;
		spin_unlock(&req->rq_export->exp_lock);
	} else if (KEY_IS(KEY_CHANGELOG_CLEAR)) {
		struct changelog_setinfo *cs = val;

		if (vallen != sizeof(*cs)) {
			CERROR("%s: bad changelog_clear setinfo size %d\n",
			       tgt_name(tsi->tsi_tgt), vallen);
			RETURN(-EINVAL);
		}
		if (ptlrpc_req_need_swab(req)) {
			__swab64s(&cs->cs_recno);
			__swab32s(&cs->cs_id);
		}

		rc = mdt_iocontrol(OBD_IOC_CHANGELOG_CLEAR, req->rq_export,
				   vallen, val, NULL);
	} else if (KEY_IS(KEY_EVICT_BY_NID)) {
		if (vallen > 0)
			obd_export_evict_by_nid(req->rq_export->exp_obd, val);
	} else {
		RETURN(-EINVAL);
	}
	RETURN(rc);
}

static int mdt_readpage(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info = mdt_th_info(tsi->tsi_env);
	struct mdt_object	*object = mdt_obj(tsi->tsi_corpus);
	struct lu_rdpg		*rdpg = &info->mti_u.rdpg.mti_rdpg;
	const struct mdt_body	*reqbody = tsi->tsi_mdt_body;
	struct mdt_body		*repbody;
	int			 rc;
	int			 i;

	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK))
		RETURN(err_serious(-ENOMEM));

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_MDT_BODY);
	if (repbody == NULL || reqbody == NULL)
                RETURN(err_serious(-EFAULT));

        /*
         * prepare @rdpg before calling lower layers and transfer itself. Here
         * reqbody->size contains offset of where to start to read and
         * reqbody->nlink contains number bytes to read.
         */
	rdpg->rp_hash = reqbody->mbo_size;
	if (rdpg->rp_hash != reqbody->mbo_size) {
		CERROR("Invalid hash: "LPX64" != "LPX64"\n",
		       rdpg->rp_hash, reqbody->mbo_size);
		RETURN(-EFAULT);
	}

	rdpg->rp_attrs = reqbody->mbo_mode;
	if (exp_connect_flags(tsi->tsi_exp) & OBD_CONNECT_64BITHASH)
		rdpg->rp_attrs |= LUDA_64BITHASH;
	rdpg->rp_count  = min_t(unsigned int, reqbody->mbo_nlink,
				exp_max_brw_size(tsi->tsi_exp));
	rdpg->rp_npages = (rdpg->rp_count + PAGE_CACHE_SIZE - 1) >>
			  PAGE_CACHE_SHIFT;
        OBD_ALLOC(rdpg->rp_pages, rdpg->rp_npages * sizeof rdpg->rp_pages[0]);
        if (rdpg->rp_pages == NULL)
                RETURN(-ENOMEM);

        for (i = 0; i < rdpg->rp_npages; ++i) {
		rdpg->rp_pages[i] = alloc_page(GFP_IOFS);
                if (rdpg->rp_pages[i] == NULL)
                        GOTO(free_rdpg, rc = -ENOMEM);
        }

        /* call lower layers to fill allocated pages with directory data */
	rc = mo_readpage(tsi->tsi_env, mdt_object_child(object), rdpg);
	if (rc < 0)
		GOTO(free_rdpg, rc);

	/* send pages to client */
	rc = tgt_sendpage(tsi, rdpg, rc);

	EXIT;
free_rdpg:

	for (i = 0; i < rdpg->rp_npages; i++)
		if (rdpg->rp_pages[i] != NULL)
			__free_page(rdpg->rp_pages[i]);
	OBD_FREE(rdpg->rp_pages, rdpg->rp_npages * sizeof rdpg->rp_pages[0]);

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE))
		RETURN(0);

	return rc;
}

static int mdt_reint_internal(struct mdt_thread_info *info,
                              struct mdt_lock_handle *lhc,
                              __u32 op)
{
	struct req_capsule	*pill = info->mti_pill;
	struct mdt_body		*repbody;
	int			 rc = 0, rc2;

	ENTRY;

        rc = mdt_reint_unpack(info, op);
        if (rc != 0) {
                CERROR("Can't unpack reint, rc %d\n", rc);
                RETURN(err_serious(rc));
        }

        /* for replay (no_create) lmm is not needed, client has it already */
        if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
                req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER,
				     DEF_REP_MD_SIZE);

	/* llog cookies are always 0, the field is kept for compatibility */
        if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
		req_capsule_set_size(pill, &RMF_LOGCOOKIES, RCL_SERVER, 0);

        rc = req_capsule_server_pack(pill);
        if (rc != 0) {
                CERROR("Can't pack response, rc %d\n", rc);
                RETURN(err_serious(rc));
        }

        if (req_capsule_has_field(pill, &RMF_MDT_BODY, RCL_SERVER)) {
                repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);
                LASSERT(repbody);
		repbody->mbo_eadatasize = 0;
		repbody->mbo_aclsize = 0;
        }

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_REINT_DELAY, 10);

        /* for replay no cookkie / lmm need, because client have this already */
        if (info->mti_spec.no_create)
                if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
                        req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, 0);

        rc = mdt_init_ucred_reint(info);
        if (rc)
                GOTO(out_shrink, rc);

        rc = mdt_fix_attr_ucred(info, op);
        if (rc != 0)
                GOTO(out_ucred, rc = err_serious(rc));

	rc = mdt_check_resent(info, mdt_reconstruct, lhc);
	if (rc < 0) {
		GOTO(out_ucred, rc);
	} else if (rc == 1) {
		DEBUG_REQ(D_INODE, mdt_info_req(info), "resent opt.");
		rc = lustre_msg_get_status(mdt_info_req(info)->rq_repmsg);
                GOTO(out_ucred, rc);
        }
        rc = mdt_reint_rec(info, lhc);
        EXIT;
out_ucred:
        mdt_exit_ucred(info);
out_shrink:
        mdt_client_compatibility(info);
        rc2 = mdt_fix_reply(info);
        if (rc == 0)
                rc = rc2;
        return rc;
}

static long mdt_reint_opcode(struct ptlrpc_request *req,
			     const struct req_format **fmt)
{
	struct mdt_device	*mdt;
	struct mdt_rec_reint	*rec;
	long			 opc;

	rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);
	if (rec != NULL) {
		opc = rec->rr_opcode;
		DEBUG_REQ(D_INODE, req, "reint opt = %ld", opc);
		if (opc < REINT_MAX && fmt[opc] != NULL)
			req_capsule_extend(&req->rq_pill, fmt[opc]);
		else {
			mdt = mdt_exp2dev(req->rq_export);
			CERROR("%s: Unsupported opcode '%ld' from client '%s':"
			       " rc = %d\n", req->rq_export->exp_obd->obd_name,
			       opc, mdt->mdt_ldlm_client->cli_name, -EFAULT);
			opc = err_serious(-EFAULT);
		}
	} else {
		opc = err_serious(-EFAULT);
	}
	return opc;
}

static int mdt_reint(struct tgt_session_info *tsi)
{
	long opc;
	int  rc;
	static const struct req_format *reint_fmts[REINT_MAX] = {
		[REINT_SETATTR]  = &RQF_MDS_REINT_SETATTR,
		[REINT_CREATE]   = &RQF_MDS_REINT_CREATE,
		[REINT_LINK]     = &RQF_MDS_REINT_LINK,
		[REINT_UNLINK]   = &RQF_MDS_REINT_UNLINK,
		[REINT_RENAME]   = &RQF_MDS_REINT_RENAME,
		[REINT_OPEN]     = &RQF_MDS_REINT_OPEN,
		[REINT_SETXATTR] = &RQF_MDS_REINT_SETXATTR,
		[REINT_RMENTRY]  = &RQF_MDS_REINT_UNLINK,
		[REINT_MIGRATE]  = &RQF_MDS_REINT_RENAME
	};

	ENTRY;

	opc = mdt_reint_opcode(tgt_ses_req(tsi), reint_fmts);
	if (opc >= 0) {
		struct mdt_thread_info *info = tsi2mdt_info(tsi);
		/*
		 * No lock possible here from client to pass it to reint code
		 * path.
		 */
		rc = mdt_reint_internal(info, NULL, opc);
		mdt_thread_info_fini(info);
	} else {
		rc = opc;
	}

	tsi->tsi_reply_fail_id = OBD_FAIL_MDS_REINT_NET_REP;
	RETURN(rc);
}

/* this should sync the whole device */
static int mdt_device_sync(const struct lu_env *env, struct mdt_device *mdt)
{
        struct dt_device *dt = mdt->mdt_bottom;
        int rc;
        ENTRY;

        rc = dt->dd_ops->dt_sync(env, dt);
        RETURN(rc);
}

/* this should sync this object */
static int mdt_object_sync(struct mdt_thread_info *info)
{
	struct md_object *next;
	int rc;
	ENTRY;

	if (!mdt_object_exists(info->mti_object)) {
		CWARN("%s: non existing object "DFID": rc = %d\n",
		      mdt_obd_name(info->mti_mdt),
		      PFID(mdt_object_fid(info->mti_object)), -ESTALE);
		RETURN(-ESTALE);
	}
	next = mdt_object_child(info->mti_object);
	rc = mo_object_sync(info->mti_env, next);

	RETURN(rc);
}

static int mdt_sync(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct req_capsule	*pill = tsi->tsi_pill;
	struct mdt_body		*body;
	int			 rc;

	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SYNC_PACK))
		RETURN(err_serious(-ENOMEM));

	if (fid_seq(&tsi->tsi_mdt_body->mbo_fid1) == 0) {
		rc = mdt_device_sync(tsi->tsi_env, mdt_exp2dev(tsi->tsi_exp));
	} else {
		struct mdt_thread_info *info = tsi2mdt_info(tsi);

		/* sync an object */
		rc = mdt_object_sync(info);
		if (rc == 0) {
			const struct lu_fid *fid;
			struct lu_attr *la = &info->mti_attr.ma_attr;

			info->mti_attr.ma_need = MA_INODE;
			info->mti_attr.ma_valid = 0;
			rc = mdt_attr_get_complex(info, info->mti_object,
						  &info->mti_attr);
			if (rc == 0) {
				body = req_capsule_server_get(pill,
							      &RMF_MDT_BODY);
				fid = mdt_object_fid(info->mti_object);
				mdt_pack_attr2body(info, body, la, fid);
			}
		}
		mdt_thread_info_fini(info);
	}
	if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_SYNC);

	RETURN(rc);
}

/*
 * Handle quota control requests to consult current usage/limit, but also
 * to configure quota enforcement
 */
static int mdt_quotactl(struct tgt_session_info *tsi)
{
	struct obd_export	*exp  = tsi->tsi_exp;
	struct req_capsule	*pill = tsi->tsi_pill;
	struct obd_quotactl	*oqctl, *repoqc;
	int			 id, rc;
	struct mdt_device	*mdt = mdt_exp2dev(exp);
	struct lu_device	*qmt = mdt->mdt_qmt_dev;
	struct lu_nodemap	*nodemap = exp->exp_target_data.ted_nodemap;
	ENTRY;

	oqctl = req_capsule_client_get(pill, &RMF_OBD_QUOTACTL);
	if (oqctl == NULL)
		RETURN(err_serious(-EPROTO));

	rc = req_capsule_server_pack(pill);
	if (rc)
		RETURN(err_serious(rc));

	switch (oqctl->qc_cmd) {
		/* master quotactl */
	case Q_SETINFO:
	case Q_SETQUOTA:
		if (!nodemap_can_setquota(nodemap))
			RETURN(-EPERM);
	case Q_GETINFO:
	case Q_GETQUOTA:
		if (qmt == NULL)
			RETURN(-EOPNOTSUPP);
		/* slave quotactl */
	case Q_GETOINFO:
	case Q_GETOQUOTA:
		break;
	default:
		CERROR("Unsupported quotactl command: %d\n", oqctl->qc_cmd);
		RETURN(-EFAULT);
	}

	/* map uid/gid for remote client */
	id = oqctl->qc_id;
	if (exp_connect_rmtclient(exp)) {
		struct lustre_idmap_table *idmap;

		idmap = exp->exp_mdt_data.med_idmap;

		if (unlikely(oqctl->qc_cmd != Q_GETQUOTA &&
			     oqctl->qc_cmd != Q_GETINFO))
			RETURN(-EPERM);

		if (oqctl->qc_type == USRQUOTA)
			id = lustre_idmap_lookup_uid(NULL, idmap, 0,
						     oqctl->qc_id);
		else if (oqctl->qc_type == GRPQUOTA)
			id = lustre_idmap_lookup_gid(NULL, idmap, 0,
						     oqctl->qc_id);
		else
			RETURN(-EINVAL);

		if (id == CFS_IDMAP_NOTFOUND) {
			CDEBUG(D_QUOTA, "no mapping for id %u\n", oqctl->qc_id);
			RETURN(-EACCES);
		}
	}

	if (oqctl->qc_type == USRQUOTA)
		id = nodemap_map_id(nodemap, NODEMAP_UID,
				    NODEMAP_CLIENT_TO_FS, id);
	else if (oqctl->qc_type == GRPQUOTA)
		id = nodemap_map_id(nodemap, NODEMAP_UID,
				    NODEMAP_CLIENT_TO_FS, id);

	repoqc = req_capsule_server_get(pill, &RMF_OBD_QUOTACTL);
	if (repoqc == NULL)
		RETURN(err_serious(-EFAULT));

	if (oqctl->qc_id != id)
		swap(oqctl->qc_id, id);

	switch (oqctl->qc_cmd) {

	case Q_GETINFO:
	case Q_SETINFO:
	case Q_SETQUOTA:
	case Q_GETQUOTA:
		/* forward quotactl request to QMT */
		rc = qmt_hdls.qmth_quotactl(tsi->tsi_env, qmt, oqctl);
		break;

	case Q_GETOINFO:
	case Q_GETOQUOTA:
		/* slave quotactl */
		rc = lquotactl_slv(tsi->tsi_env, tsi->tsi_tgt->lut_bottom,
				   oqctl);
		break;

	default:
		CERROR("Unsupported quotactl command: %d\n", oqctl->qc_cmd);
		RETURN(-EFAULT);
	}

	if (oqctl->qc_id != id)
		swap(oqctl->qc_id, id);

	*repoqc = *oqctl;
	RETURN(rc);
}

/** clone llog ctxt from child (mdd)
 * This allows remote llog (replicator) access.
 * We can either pass all llog RPCs (eg mdt_llog_create) on to child where the
 * context was originally set up, or we can handle them directly.
 * I choose the latter, but that means I need any llog
 * contexts set up by child to be accessable by the mdt.  So we clone the
 * context into our context list here.
 */
static int mdt_llog_ctxt_clone(const struct lu_env *env, struct mdt_device *mdt,
                               int idx)
{
        struct md_device  *next = mdt->mdt_child;
        struct llog_ctxt *ctxt;
        int rc;

        if (!llog_ctxt_null(mdt2obd_dev(mdt), idx))
                return 0;

        rc = next->md_ops->mdo_llog_ctxt_get(env, next, idx, (void **)&ctxt);
        if (rc || ctxt == NULL) {
		return 0;
        }

        rc = llog_group_set_ctxt(&mdt2obd_dev(mdt)->obd_olg, ctxt, idx);
        if (rc)
                CERROR("Can't set mdt ctxt %d\n", rc);

        return rc;
}

static int mdt_llog_ctxt_unclone(const struct lu_env *env,
                                 struct mdt_device *mdt, int idx)
{
        struct llog_ctxt *ctxt;

        ctxt = llog_get_context(mdt2obd_dev(mdt), idx);
        if (ctxt == NULL)
                return 0;
        /* Put once for the get we just did, and once for the clone */
        llog_ctxt_put(ctxt);
        llog_ctxt_put(ctxt);
        return 0;
}

/*
 * sec context handlers
 */
static int mdt_sec_ctx_handle(struct tgt_session_info *tsi)
{
	int rc;

	rc = mdt_handle_idmap(tsi);
	if (unlikely(rc)) {
		struct ptlrpc_request	*req = tgt_ses_req(tsi);
		__u32			 opc;

		opc = lustre_msg_get_opc(req->rq_reqmsg);
		if (opc == SEC_CTX_INIT || opc == SEC_CTX_INIT_CONT)
			sptlrpc_svc_ctx_invalidate(req);
	}

	CFS_FAIL_TIMEOUT(OBD_FAIL_SEC_CTX_HDL_PAUSE, cfs_fail_val);

	return rc;
}

/*
 * quota request handlers
 */
static int mdt_quota_dqacq(struct tgt_session_info *tsi)
{
	struct mdt_device	*mdt = mdt_exp2dev(tsi->tsi_exp);
	struct lu_device	*qmt = mdt->mdt_qmt_dev;
	int			 rc;
	ENTRY;

	if (qmt == NULL)
		RETURN(err_serious(-EOPNOTSUPP));

	rc = qmt_hdls.qmth_dqacq(tsi->tsi_env, qmt, tgt_ses_req(tsi));
	RETURN(rc);
}

struct mdt_object *mdt_object_new(const struct lu_env *env,
				  struct mdt_device *d,
				  const struct lu_fid *f)
{
	struct lu_object_conf conf = { .loc_flags = LOC_F_NEW };
	struct lu_object *o;
	struct mdt_object *m;
	ENTRY;

	CDEBUG(D_INFO, "Allocate object for "DFID"\n", PFID(f));
	o = lu_object_find(env, &d->mdt_lu_dev, f, &conf);
	if (unlikely(IS_ERR(o)))
		m = (struct mdt_object *)o;
	else
		m = mdt_obj(o);
	RETURN(m);
}

struct mdt_object *mdt_object_find(const struct lu_env *env,
				   struct mdt_device *d,
				   const struct lu_fid *f)
{
	struct lu_object *o;
	struct mdt_object *m;
	ENTRY;

	CDEBUG(D_INFO, "Find object for "DFID"\n", PFID(f));
	o = lu_object_find(env, &d->mdt_lu_dev, f, NULL);
	if (unlikely(IS_ERR(o)))
		m = (struct mdt_object *)o;
	else
		m = mdt_obj(o);

	RETURN(m);
}

/**
 * Asyncronous commit for mdt device.
 *
 * Pass asynchonous commit call down the MDS stack.
 *
 * \param env environment
 * \param mdt the mdt device
 */
static void mdt_device_commit_async(const struct lu_env *env,
                                    struct mdt_device *mdt)
{
	struct dt_device *dt = mdt->mdt_bottom;
	int rc;
	ENTRY;

	rc = dt->dd_ops->dt_commit_async(env, dt);
	if (unlikely(rc != 0))
		CWARN("%s: async commit start failed: rc = %d\n",
		      mdt_obd_name(mdt), rc);
	atomic_inc(&mdt->mdt_async_commit_count);
	EXIT;
}

/**
 * Mark the lock as "synchonous".
 *
 * Mark the lock to deffer transaction commit to the unlock time.
 *
 * \param lock the lock to mark as "synchonous"
 *
 * \see mdt_is_lock_sync
 * \see mdt_save_lock
 */
static inline void mdt_set_lock_sync(struct ldlm_lock *lock)
{
        lock->l_ast_data = (void*)1;
}

/**
 * Check whehter the lock "synchonous" or not.
 *
 * \param lock the lock to check
 * \retval 1 the lock is "synchonous"
 * \retval 0 the lock isn't "synchronous"
 *
 * \see mdt_set_lock_sync
 * \see mdt_save_lock
 */
static inline int mdt_is_lock_sync(struct ldlm_lock *lock)
{
        return lock->l_ast_data != NULL;
}

/**
 * Blocking AST for mdt locks.
 *
 * Starts transaction commit if in case of COS lock conflict or
 * deffers such a commit to the mdt_save_lock.
 *
 * \param lock the lock which blocks a request or cancelling lock
 * \param desc unused
 * \param data unused
 * \param flag indicates whether this cancelling or blocking callback
 * \retval 0
 * \see ldlm_blocking_ast_nocheck
 */
int mdt_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                     void *data, int flag)
{
        struct obd_device *obd = ldlm_lock_to_ns(lock)->ns_obd;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int rc;
        ENTRY;

        if (flag == LDLM_CB_CANCELING)
                RETURN(0);

        lock_res_and_lock(lock);
        if (lock->l_blocking_ast != mdt_blocking_ast) {
                unlock_res_and_lock(lock);
                RETURN(0);
        }
	if (lock->l_req_mode & (LCK_PW | LCK_EX) &&
	    lock->l_blocking_lock != NULL) {
		if (mdt_cos_is_enabled(mdt) &&
		    lock->l_client_cookie !=
		    lock->l_blocking_lock->l_client_cookie)
			mdt_set_lock_sync(lock);
		else if (mdt_slc_is_enabled(mdt) &&
			 ldlm_is_cos_incompat(lock->l_blocking_lock))
			mdt_set_lock_sync(lock);
	}
        rc = ldlm_blocking_ast_nocheck(lock);

        /* There is no lock conflict if l_blocking_lock == NULL,
         * it indicates a blocking ast sent from ldlm_lock_decref_internal
         * when the last reference to a local lock was released */
        if (lock->l_req_mode == LCK_COS && lock->l_blocking_lock != NULL) {
                struct lu_env env;

		rc = lu_env_init(&env, LCT_LOCAL);
		if (unlikely(rc != 0))
			CWARN("%s: lu_env initialization failed, cannot "
			      "start asynchronous commit: rc = %d\n",
			      obd->obd_name, rc);
                else
                        mdt_device_commit_async(&env, mdt);
                lu_env_fini(&env);
        }
        RETURN(rc);
}

/*
 * Blocking AST for cross-MDT lock
 *
 * Discard lock from uncommitted_slc_locks and cancel it.
 *
 * \param lock	the lock which blocks a request or cancelling lock
 * \param desc	unused
 * \param data	unused
 * \param flag	indicates whether this cancelling or blocking callback
 * \retval	0 on success
 * \retval	negative number on error
 */
int mdt_remote_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
			    void *data, int flag)
{
	struct lustre_handle lockh;
	int		  rc;
	ENTRY;

	switch (flag) {
	case LDLM_CB_BLOCKING:
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh,
			ldlm_is_atomic_cb(lock) ? 0 : LCF_ASYNC);
		if (rc < 0) {
			CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
			RETURN(rc);
		}
		break;
	case LDLM_CB_CANCELING:
		LDLM_DEBUG(lock, "Revoke remote lock\n");
		/* discard slc lock here so that it can be cleaned anytime,
		 * especially for cleanup_resource() */
		tgt_discard_slc_lock(lock);
		break;
	default:
		LBUG();
	}

	RETURN(0);
}

int mdt_check_resent_lock(struct mdt_thread_info *info,
			  struct mdt_object *mo,
			  struct mdt_lock_handle *lhc)
{
	/* the lock might already be gotten in ldlm_handle_enqueue() */
	if (unlikely(lustre_handle_is_used(&lhc->mlh_reg_lh))) {
		struct ptlrpc_request *req = mdt_info_req(info);
		struct ldlm_lock      *lock;

		lock = ldlm_handle2lock(&lhc->mlh_reg_lh);
		LASSERT(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT);
		if (lock == NULL) {
			/* Lock is pinned by ldlm_handle_enqueue0() as it is
			 * a resend case, however, it could be already destroyed
			 * due to client eviction or a raced cancel RPC. */
			LDLM_DEBUG_NOLOCK("Invalid lock handle "LPX64"\n",
					  lhc->mlh_reg_lh.cookie);
			RETURN(-ESTALE);
		}

		if (!fid_res_name_eq(mdt_object_fid(mo),
				     &lock->l_resource->lr_name)) {
			CWARN("%s: Although resent, but still not "
			      "get child lock:"DFID"\n",
			      info->mti_exp->exp_obd->obd_name,
			      PFID(mdt_object_fid(mo)));
			LDLM_LOCK_PUT(lock);
			RETURN(-EPROTO);
		}
		LDLM_LOCK_PUT(lock);
		return 0;
	}
	return 1;
}

int mdt_remote_object_lock(struct mdt_thread_info *mti, struct mdt_object *o,
			   const struct lu_fid *fid, struct lustre_handle *lh,
			   enum ldlm_mode mode, __u64 ibits, bool nonblock)
{
	struct ldlm_enqueue_info *einfo = &mti->mti_einfo;
	union ldlm_policy_data *policy = &mti->mti_policy;
	struct ldlm_res_id *res_id = &mti->mti_res_id;
	int rc = 0;
	ENTRY;

	LASSERT(mdt_object_remote(o));

	fid_build_reg_res_name(fid, res_id);

	memset(einfo, 0, sizeof(*einfo));
	einfo->ei_type = LDLM_IBITS;
	einfo->ei_mode = mode;
	einfo->ei_cb_bl = mdt_remote_blocking_ast;
	einfo->ei_cb_cp = ldlm_completion_ast;
	einfo->ei_enq_slave = 0;
	einfo->ei_res_id = res_id;
	if (nonblock)
		einfo->ei_nonblock = 1;

	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = ibits;

	rc = mo_object_lock(mti->mti_env, mdt_object_child(o), lh, einfo,
			    policy);
	RETURN(rc);
}

static int mdt_object_local_lock(struct mdt_thread_info *info,
				 struct mdt_object *o,
				 struct mdt_lock_handle *lh, __u64 ibits,
				 bool nonblock, bool cos_incompat)
{
	struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
	union ldlm_policy_data *policy = &info->mti_policy;
	struct ldlm_res_id *res_id = &info->mti_res_id;
	__u64 dlmflags = 0;
	int rc;
	ENTRY;

        LASSERT(!lustre_handle_is_used(&lh->mlh_reg_lh));
        LASSERT(!lustre_handle_is_used(&lh->mlh_pdo_lh));
        LASSERT(lh->mlh_reg_mode != LCK_MINMODE);
        LASSERT(lh->mlh_type != MDT_NUL_LOCK);

	if (cos_incompat) {
		LASSERT(lh->mlh_reg_mode == LCK_PW ||
			lh->mlh_reg_mode == LCK_EX);
		dlmflags |= LDLM_FL_COS_INCOMPAT;
	} else if (mdt_cos_is_enabled(info->mti_mdt)) {
		dlmflags |= LDLM_FL_COS_ENABLED;
	}

	/* Only enqueue LOOKUP lock for remote object */
	if (mdt_object_remote(o))
		LASSERT(ibits == MDS_INODELOCK_LOOKUP);

	if (lh->mlh_type == MDT_PDO_LOCK) {
                /* check for exists after object is locked */
                if (mdt_object_exists(o) == 0) {
                        /* Non-existent object shouldn't have PDO lock */
                        RETURN(-ESTALE);
                } else {
                        /* Non-dir object shouldn't have PDO lock */
			if (!S_ISDIR(lu_object_attr(&o->mot_obj)))
				RETURN(-ENOTDIR);
                }
        }

        memset(policy, 0, sizeof(*policy));
        fid_build_reg_res_name(mdt_object_fid(o), res_id);

	dlmflags |= LDLM_FL_ATOMIC_CB;
	if (nonblock)
		dlmflags |= LDLM_FL_BLOCK_NOWAIT;

        /*
         * Take PDO lock on whole directory and build correct @res_id for lock
         * on part of directory.
         */
        if (lh->mlh_pdo_hash != 0) {
                LASSERT(lh->mlh_type == MDT_PDO_LOCK);
                mdt_lock_pdo_mode(info, o, lh);
                if (lh->mlh_pdo_mode != LCK_NL) {
                        /*
                         * Do not use LDLM_FL_LOCAL_ONLY for parallel lock, it
                         * is never going to be sent to client and we do not
                         * want it slowed down due to possible cancels.
                         */
                        policy->l_inodebits.bits = MDS_INODELOCK_UPDATE;
			rc = mdt_fid_lock(ns, &lh->mlh_pdo_lh, lh->mlh_pdo_mode,
					  policy, res_id, dlmflags,
					  info->mti_exp == NULL ? NULL :
					  &info->mti_exp->exp_handle.h_cookie);
			if (unlikely(rc != 0))
				GOTO(out_unlock, rc);
                }

                /*
                 * Finish res_id initializing by name hash marking part of
                 * directory which is taking modification.
                 */
                res_id->name[LUSTRE_RES_ID_HSH_OFF] = lh->mlh_pdo_hash;
        }

        policy->l_inodebits.bits = ibits;

        /*
         * Use LDLM_FL_LOCAL_ONLY for this lock. We do not know yet if it is
         * going to be sent to client. If it is - mdt_intent_policy() path will
         * fix it up and turn FL_LOCAL flag off.
         */
	rc = mdt_fid_lock(ns, &lh->mlh_reg_lh, lh->mlh_reg_mode, policy,
			  res_id, LDLM_FL_LOCAL_ONLY | dlmflags,
			  info->mti_exp == NULL ? NULL :
			  &info->mti_exp->exp_handle.h_cookie);
out_unlock:
	if (rc != 0)
		mdt_object_unlock(info, o, lh, 1);
	else if (unlikely(OBD_FAIL_PRECHECK(OBD_FAIL_MDS_PDO_LOCK)) &&
		   lh->mlh_pdo_hash != 0 &&
		   (lh->mlh_reg_mode == LCK_PW || lh->mlh_reg_mode == LCK_EX))
		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_PDO_LOCK, 15);

	RETURN(rc);
}

static int
mdt_object_lock_internal(struct mdt_thread_info *info, struct mdt_object *o,
			 struct mdt_lock_handle *lh, __u64 ibits, bool nonblock,
			 bool cos_incompat)
{
	struct mdt_lock_handle *local_lh = NULL;
	int rc;
	ENTRY;

	if (!mdt_object_remote(o)) {
		rc = mdt_object_local_lock(info, o, lh, ibits, nonblock,
					   cos_incompat);
		RETURN(rc);
	}

	/* XXX do not support PERM/LAYOUT/XATTR lock for remote object yet */
	ibits &= ~(MDS_INODELOCK_PERM | MDS_INODELOCK_LAYOUT |
		   MDS_INODELOCK_XATTR);

	/* Only enqueue LOOKUP lock for remote object */
	if (ibits & MDS_INODELOCK_LOOKUP) {
		rc = mdt_object_local_lock(info, o, lh, MDS_INODELOCK_LOOKUP,
					   nonblock, cos_incompat);
		if (rc != ELDLM_OK)
			RETURN(rc);

		local_lh = lh;
	}

	if (ibits & MDS_INODELOCK_UPDATE) {
		/* Sigh, PDO needs to enqueue 2 locks right now, but
		 * enqueue RPC can only request 1 lock, to avoid extra
		 * RPC, so it will instead enqueue EX lock for remote
		 * object anyway XXX*/
		if (lh->mlh_type == MDT_PDO_LOCK &&
		    lh->mlh_pdo_hash != 0) {
			CDEBUG(D_INFO, "%s: "DFID" convert PDO lock to"
			       "EX lock.\n", mdt_obd_name(info->mti_mdt),
			       PFID(mdt_object_fid(o)));
			lh->mlh_pdo_hash = 0;
			lh->mlh_rreg_mode = LCK_EX;
			lh->mlh_type = MDT_REG_LOCK;
		}
		rc = mdt_remote_object_lock(info, o, mdt_object_fid(o),
					    &lh->mlh_rreg_lh,
					    lh->mlh_rreg_mode,
					    MDS_INODELOCK_UPDATE, nonblock);
		if (rc != ELDLM_OK) {
			if (local_lh != NULL)
				mdt_object_unlock(info, o, local_lh, rc);
			RETURN(rc);
		}
	}

	RETURN(0);
}

int mdt_object_lock(struct mdt_thread_info *info, struct mdt_object *o,
		    struct mdt_lock_handle *lh, __u64 ibits)
{
	return mdt_object_lock_internal(info, o, lh, ibits, false, false);
}

int mdt_reint_object_lock(struct mdt_thread_info *info, struct mdt_object *o,
			  struct mdt_lock_handle *lh, __u64 ibits,
			  bool cos_incompat)
{
	LASSERT(lh->mlh_reg_mode == LCK_PW || lh->mlh_reg_mode == LCK_EX);
	return mdt_object_lock_internal(info, o, lh, ibits, false,
					cos_incompat);
}

int mdt_object_lock_try(struct mdt_thread_info *info, struct mdt_object *o,
			struct mdt_lock_handle *lh, __u64 ibits)
{
	struct mdt_lock_handle tmp = *lh;
	int rc;

	rc = mdt_object_lock_internal(info, o, &tmp, ibits, true, false);
	if (rc == 0)
		*lh = tmp;

	return rc == 0;
}

int mdt_reint_object_lock_try(struct mdt_thread_info *info,
			      struct mdt_object *o, struct mdt_lock_handle *lh,
			      __u64 ibits, bool cos_incompat)
{
	struct mdt_lock_handle tmp = *lh;
	int rc;

	LASSERT(lh->mlh_reg_mode == LCK_PW || lh->mlh_reg_mode == LCK_EX);
	rc = mdt_object_lock_internal(info, o, &tmp, ibits, true, cos_incompat);
	if (rc == 0)
		*lh = tmp;

	return rc == 0;
}

/**
 * Save a lock within request object.
 *
 * Keep the lock referenced until whether client ACK or transaction
 * commit happens or release the lock immediately depending on input
 * parameters. If COS is ON, a write lock is converted to COS lock
 * before saving.
 *
 * \param info thead info object
 * \param h lock handle
 * \param mode lock mode
 * \param decref force immediate lock releasing
 */
static void mdt_save_lock(struct mdt_thread_info *info, struct lustre_handle *h,
			  enum ldlm_mode mode, int decref)
{
	ENTRY;

	if (lustre_handle_is_used(h)) {
		if (decref || !info->mti_has_trans ||
		    !(mode & (LCK_PW | LCK_EX))) {
			mdt_fid_unlock(h, mode);
		} else {
			struct mdt_device *mdt = info->mti_mdt;
			struct ldlm_lock *lock = ldlm_handle2lock(h);
			struct ptlrpc_request *req = mdt_info_req(info);
			int cos;

			cos = (mdt_cos_is_enabled(mdt) ||
			       mdt_slc_is_enabled(mdt));

			LASSERTF(lock != NULL, "no lock for cookie "LPX64"\n",
				 h->cookie);

			/* there is no request if mdt_object_unlock() is called
			 * from mdt_export_cleanup()->mdt_add_dirty_flag() */
			if (likely(req != NULL)) {
				CDEBUG(D_HA, "request = %p reply state = %p"
				       " transno = "LPD64"\n", req,
				       req->rq_reply_state, req->rq_transno);
				if (cos) {
					ldlm_lock_downgrade(lock, LCK_COS);
					mode = LCK_COS;
				}
				ptlrpc_save_lock(req, h, mode, cos);
			} else {
				mdt_fid_unlock(h, mode);
			}
                        if (mdt_is_lock_sync(lock)) {
                                CDEBUG(D_HA, "found sync-lock,"
                                       " async commit started\n");
                                mdt_device_commit_async(info->mti_env,
                                                        mdt);
                        }
                        LDLM_LOCK_PUT(lock);
                }
                h->cookie = 0ull;
        }

        EXIT;
}

/**
 * Save cross-MDT lock in uncommitted_slc_locks
 *
 * Keep the lock referenced until transaction commit happens or release the lock
 * immediately depending on input parameters.
 *
 * \param info thead info object
 * \param h lock handle
 * \param mode lock mode
 * \param decref force immediate lock releasing
 */
static void mdt_save_remote_lock(struct mdt_thread_info *info,
				 struct lustre_handle *h, enum ldlm_mode mode,
				 int decref)
{
	ENTRY;

	if (lustre_handle_is_used(h)) {
		if (decref || !info->mti_has_trans ||
		    !(mode & (LCK_PW | LCK_EX))) {
			ldlm_lock_decref_and_cancel(h, mode);
		} else {
			struct ldlm_lock *lock = ldlm_handle2lock(h);
			struct ptlrpc_request *req = mdt_info_req(info);

			LASSERT(req != NULL);
			tgt_save_slc_lock(lock, req->rq_transno);
			ldlm_lock_decref(h, mode);
		}
		h->cookie = 0ull;
	}

	EXIT;
}

/**
 * Unlock mdt object.
 *
 * Immeditely release the regular lock and the PDO lock or save the
 * lock in request and keep them referenced until client ACK or
 * transaction commit.
 *
 * \param info thread info object
 * \param o mdt object
 * \param lh mdt lock handle referencing regular and PDO locks
 * \param decref force immediate lock releasing
 */
void mdt_object_unlock(struct mdt_thread_info *info, struct mdt_object *o,
		       struct mdt_lock_handle *lh, int decref)
{
	ENTRY;

	mdt_save_lock(info, &lh->mlh_pdo_lh, lh->mlh_pdo_mode, decref);
	mdt_save_lock(info, &lh->mlh_reg_lh, lh->mlh_reg_mode, decref);
	mdt_save_remote_lock(info, &lh->mlh_rreg_lh, lh->mlh_rreg_mode, decref);

	EXIT;
}

struct mdt_object *mdt_object_find_lock(struct mdt_thread_info *info,
                                        const struct lu_fid *f,
                                        struct mdt_lock_handle *lh,
                                        __u64 ibits)
{
        struct mdt_object *o;

        o = mdt_object_find(info->mti_env, info->mti_mdt, f);
        if (!IS_ERR(o)) {
                int rc;

		rc = mdt_object_lock(info, o, lh, ibits);
                if (rc != 0) {
                        mdt_object_put(info->mti_env, o);
                        o = ERR_PTR(rc);
                }
        }
        return o;
}

void mdt_object_unlock_put(struct mdt_thread_info * info,
                           struct mdt_object * o,
                           struct mdt_lock_handle *lh,
                           int decref)
{
        mdt_object_unlock(info, o, lh, decref);
        mdt_object_put(info->mti_env, o);
}

/*
 * Generic code handling requests that have struct mdt_body passed in:
 *
 *  - extract mdt_body from request and save it in @info, if present;
 *
 *  - create lu_object, corresponding to the fid in mdt_body, and save it in
 *  @info;
 *
 *  - if HABEO_CORPUS flag is set for this request type check whether object
 *  actually exists on storage (lu_object_exists()).
 *
 */
static int mdt_body_unpack(struct mdt_thread_info *info, __u32 flags)
{
        const struct mdt_body    *body;
        struct mdt_object        *obj;
        const struct lu_env      *env;
        struct req_capsule       *pill;
        int                       rc;
        ENTRY;

        env = info->mti_env;
        pill = info->mti_pill;

        body = info->mti_body = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

	if (!(body->mbo_valid & OBD_MD_FLID))
		RETURN(0);

	if (!fid_is_sane(&body->mbo_fid1)) {
		CERROR("Invalid fid: "DFID"\n", PFID(&body->mbo_fid1));
                RETURN(-EINVAL);
        }

	obj = mdt_object_find(env, info->mti_mdt, &body->mbo_fid1);
	if (!IS_ERR(obj)) {
		if ((flags & HABEO_CORPUS) && !mdt_object_exists(obj)) {
			mdt_object_put(env, obj);
			rc = -ENOENT;
                } else {
                        info->mti_object = obj;
                        rc = 0;
                }
        } else
                rc = PTR_ERR(obj);

        RETURN(rc);
}

static int mdt_unpack_req_pack_rep(struct mdt_thread_info *info, __u32 flags)
{
        struct req_capsule *pill = info->mti_pill;
        int rc;
        ENTRY;

        if (req_capsule_has_field(pill, &RMF_MDT_BODY, RCL_CLIENT))
                rc = mdt_body_unpack(info, flags);
        else
                rc = 0;

        if (rc == 0 && (flags & HABEO_REFERO)) {
                /* Pack reply. */
                if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
                        req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER,
					     DEF_REP_MD_SIZE);
                if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
			req_capsule_set_size(pill, &RMF_LOGCOOKIES,
					     RCL_SERVER, 0);

                rc = req_capsule_server_pack(pill);
        }
        RETURN(rc);
}

void mdt_lock_handle_init(struct mdt_lock_handle *lh)
{
        lh->mlh_type = MDT_NUL_LOCK;
        lh->mlh_reg_lh.cookie = 0ull;
        lh->mlh_reg_mode = LCK_MINMODE;
        lh->mlh_pdo_lh.cookie = 0ull;
        lh->mlh_pdo_mode = LCK_MINMODE;
	lh->mlh_rreg_lh.cookie = 0ull;
	lh->mlh_rreg_mode = LCK_MINMODE;
}

void mdt_lock_handle_fini(struct mdt_lock_handle *lh)
{
        LASSERT(!lustre_handle_is_used(&lh->mlh_reg_lh));
        LASSERT(!lustre_handle_is_used(&lh->mlh_pdo_lh));
}

/*
 * Initialize fields of struct mdt_thread_info. Other fields are left in
 * uninitialized state, because it's too expensive to zero out whole
 * mdt_thread_info (> 1K) on each request arrival.
 */
void mdt_thread_info_init(struct ptlrpc_request *req,
			  struct mdt_thread_info *info)
{
        int i;

        info->mti_pill = &req->rq_pill;

        /* lock handle */
        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_init(&info->mti_lh[i]);

        /* mdt device: it can be NULL while CONNECT */
        if (req->rq_export) {
                info->mti_mdt = mdt_dev(req->rq_export->exp_obd->obd_lu_dev);
                info->mti_exp = req->rq_export;
        } else
                info->mti_mdt = NULL;
	info->mti_env = req->rq_svc_thread->t_env;
	info->mti_transno = lustre_msg_get_transno(req->rq_reqmsg);

        memset(&info->mti_attr, 0, sizeof(info->mti_attr));
	info->mti_big_buf = LU_BUF_NULL;
	info->mti_body = NULL;
        info->mti_object = NULL;
        info->mti_dlm_req = NULL;
        info->mti_has_trans = 0;
        info->mti_cross_ref = 0;
        info->mti_opdata = 0;
	info->mti_big_lmm_used = 0;

        info->mti_spec.no_create = 0;
	info->mti_spec.sp_rm_entry = 0;
	info->mti_spec.sp_permitted = 0;
	info->mti_spec.sp_migrate_close = 0;

	info->mti_spec.u.sp_ea.eadata = NULL;
	info->mti_spec.u.sp_ea.eadatalen = 0;
}

void mdt_thread_info_fini(struct mdt_thread_info *info)
{
	int i;

	if (info->mti_object != NULL) {
		mdt_object_put(info->mti_env, info->mti_object);
		info->mti_object = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
		mdt_lock_handle_fini(&info->mti_lh[i]);
	info->mti_env = NULL;
	info->mti_pill = NULL;
	info->mti_exp = NULL;

	if (unlikely(info->mti_big_buf.lb_buf != NULL))
		lu_buf_free(&info->mti_big_buf);
}

struct mdt_thread_info *tsi2mdt_info(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*mti;

	mti = mdt_th_info(tsi->tsi_env);
	LASSERT(mti != NULL);

	mdt_thread_info_init(tgt_ses_req(tsi), mti);
	if (tsi->tsi_corpus != NULL) {
		mti->mti_object = mdt_obj(tsi->tsi_corpus);
		lu_object_get(tsi->tsi_corpus);
	}
	mti->mti_body = tsi->tsi_mdt_body;
	mti->mti_dlm_req = tsi->tsi_dlm_req;

	return mti;
}

static int mdt_tgt_connect(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	int			 rc;

	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_TGT_DELAY_CONDITIONAL) &&
	    cfs_fail_val ==
	    tsi2mdt_info(tsi)->mti_mdt->mdt_seq_site.ss_node_id) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(3 * MSEC_PER_SEC));
	}

	rc = tgt_connect(tsi);
	if (rc != 0)
		RETURN(rc);

	rc = mdt_init_idmap(tsi);
	if (rc != 0)
		GOTO(err, rc);
	RETURN(0);
err:
	obd_disconnect(class_export_get(req->rq_export));
	return rc;
}

enum mdt_it_code {
        MDT_IT_OPEN,
        MDT_IT_OCREAT,
        MDT_IT_CREATE,
        MDT_IT_GETATTR,
        MDT_IT_READDIR,
        MDT_IT_LOOKUP,
        MDT_IT_UNLINK,
        MDT_IT_TRUNC,
        MDT_IT_GETXATTR,
        MDT_IT_LAYOUT,
	MDT_IT_QUOTA,
        MDT_IT_NR
};

static int mdt_intent_getattr(enum mdt_it_code opcode,
                              struct mdt_thread_info *info,
                              struct ldlm_lock **,
			      __u64);

static int mdt_intent_getxattr(enum mdt_it_code opcode,
				struct mdt_thread_info *info,
				struct ldlm_lock **lockp,
				__u64 flags);

static int mdt_intent_layout(enum mdt_it_code opcode,
			     struct mdt_thread_info *info,
			     struct ldlm_lock **,
			     __u64);
static int mdt_intent_reint(enum mdt_it_code opcode,
                            struct mdt_thread_info *info,
                            struct ldlm_lock **,
			    __u64);

static struct mdt_it_flavor {
        const struct req_format *it_fmt;
        __u32                    it_flags;
        int                    (*it_act)(enum mdt_it_code ,
                                         struct mdt_thread_info *,
                                         struct ldlm_lock **,
					 __u64);
        long                     it_reint;
} mdt_it_flavor[] = {
        [MDT_IT_OPEN]     = {
                .it_fmt   = &RQF_LDLM_INTENT,
                /*.it_flags = HABEO_REFERO,*/
                .it_flags = 0,
                .it_act   = mdt_intent_reint,
                .it_reint = REINT_OPEN
        },
        [MDT_IT_OCREAT]   = {
                .it_fmt   = &RQF_LDLM_INTENT,
		/*
		 * OCREAT is not a MUTABOR request as if the file
		 * already exists.
		 * We do the extra check of OBD_CONNECT_RDONLY in
		 * mdt_reint_open() when we really need to create
		 * the object.
		 */
		.it_flags = 0,
                .it_act   = mdt_intent_reint,
                .it_reint = REINT_OPEN
        },
        [MDT_IT_CREATE]   = {
                .it_fmt   = &RQF_LDLM_INTENT,
                .it_flags = MUTABOR,
                .it_act   = mdt_intent_reint,
                .it_reint = REINT_CREATE
        },
        [MDT_IT_GETATTR]  = {
                .it_fmt   = &RQF_LDLM_INTENT_GETATTR,
                .it_flags = HABEO_REFERO,
                .it_act   = mdt_intent_getattr
        },
        [MDT_IT_READDIR]  = {
                .it_fmt   = NULL,
                .it_flags = 0,
                .it_act   = NULL
        },
        [MDT_IT_LOOKUP]   = {
                .it_fmt   = &RQF_LDLM_INTENT_GETATTR,
                .it_flags = HABEO_REFERO,
                .it_act   = mdt_intent_getattr
        },
        [MDT_IT_UNLINK]   = {
                .it_fmt   = &RQF_LDLM_INTENT_UNLINK,
                .it_flags = MUTABOR,
                .it_act   = NULL,
                .it_reint = REINT_UNLINK
        },
        [MDT_IT_TRUNC]    = {
                .it_fmt   = NULL,
                .it_flags = MUTABOR,
                .it_act   = NULL
        },
        [MDT_IT_GETXATTR] = {
		.it_fmt   = &RQF_LDLM_INTENT_GETXATTR,
		.it_flags = HABEO_CORPUS,
		.it_act   = mdt_intent_getxattr
        },
	[MDT_IT_LAYOUT] = {
		.it_fmt   = &RQF_LDLM_INTENT_LAYOUT,
		.it_flags = 0,
		.it_act   = mdt_intent_layout
	}
};

static int
mdt_intent_lock_replace(struct mdt_thread_info *info,
			struct ldlm_lock **lockp,
			struct mdt_lock_handle *lh,
			__u64 flags)
{
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct ldlm_lock       *lock = *lockp;
	struct ldlm_lock       *new_lock;

	/* If possible resent found a lock, @lh is set to its handle */
	new_lock = ldlm_handle2lock_long(&lh->mlh_reg_lh, 0);

        if (new_lock == NULL && (flags & LDLM_FL_INTENT_ONLY)) {
                lh->mlh_reg_lh.cookie = 0;
                RETURN(0);
        }

        LASSERTF(new_lock != NULL,
                 "lockh "LPX64"\n", lh->mlh_reg_lh.cookie);

        /*
         * If we've already given this lock to a client once, then we should
         * have no readers or writers.  Otherwise, we should have one reader
         * _or_ writer ref (which will be zeroed below) before returning the
         * lock to a client.
         */
        if (new_lock->l_export == req->rq_export) {
                LASSERT(new_lock->l_readers + new_lock->l_writers == 0);
        } else {
                LASSERT(new_lock->l_export == NULL);
                LASSERT(new_lock->l_readers + new_lock->l_writers == 1);
        }

        *lockp = new_lock;

        if (new_lock->l_export == req->rq_export) {
                /*
                 * Already gave this to the client, which means that we
                 * reconstructed a reply.
                 */
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) &
                        MSG_RESENT);

		LDLM_LOCK_RELEASE(new_lock);
                lh->mlh_reg_lh.cookie = 0;
                RETURN(ELDLM_LOCK_REPLACED);
        }

        /*
         * Fixup the lock to be given to the client.
         */
        lock_res_and_lock(new_lock);
        /* Zero new_lock->l_readers and new_lock->l_writers without triggering
         * possible blocking AST. */
        while (new_lock->l_readers > 0) {
                lu_ref_del(&new_lock->l_reference, "reader", new_lock);
                lu_ref_del(&new_lock->l_reference, "user", new_lock);
                new_lock->l_readers--;
        }
        while (new_lock->l_writers > 0) {
                lu_ref_del(&new_lock->l_reference, "writer", new_lock);
                lu_ref_del(&new_lock->l_reference, "user", new_lock);
                new_lock->l_writers--;
        }

        new_lock->l_export = class_export_lock_get(req->rq_export, new_lock);
        new_lock->l_blocking_ast = lock->l_blocking_ast;
        new_lock->l_completion_ast = lock->l_completion_ast;
        new_lock->l_remote_handle = lock->l_remote_handle;
        new_lock->l_flags &= ~LDLM_FL_LOCAL;

        unlock_res_and_lock(new_lock);

        cfs_hash_add(new_lock->l_export->exp_lock_hash,
                     &new_lock->l_remote_handle,
                     &new_lock->l_exp_hash);

        LDLM_LOCK_RELEASE(new_lock);
        lh->mlh_reg_lh.cookie = 0;

        RETURN(ELDLM_LOCK_REPLACED);
}

static void mdt_intent_fixup_resent(struct mdt_thread_info *info,
				    struct ldlm_lock *new_lock,
				    struct mdt_lock_handle *lh,
				    __u64 flags)
{
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct ldlm_request    *dlmreq;

        if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT))
                return;

        dlmreq = req_capsule_client_get(info->mti_pill, &RMF_DLM_REQ);

	/* Check if this is a resend case (MSG_RESENT is set on RPC) and a
	 * lock was found by ldlm_handle_enqueue(); if so @lh must be
	 * initialized. */
	if (flags & LDLM_FL_RESENT) {
		lh->mlh_reg_lh.cookie = new_lock->l_handle.h_cookie;
		lh->mlh_reg_mode = new_lock->l_granted_mode;

		LDLM_DEBUG(new_lock, "Restoring lock cookie");
		DEBUG_REQ(D_DLMTRACE, req, "restoring lock cookie "LPX64,
			  lh->mlh_reg_lh.cookie);
		return;
	}

	/*
	 * If the xid matches, then we know this is a resent request, and allow
	 * it. (It's probably an OPEN, for which we don't send a lock.
	 */
	if (req_can_reconstruct(req, NULL))
		return;

        /*
         * This remote handle isn't enqueued, so we never received or processed
         * this request.  Clear MSG_RESENT, because it can be handled like any
         * normal request now.
         */
        lustre_msg_clear_flags(req->rq_reqmsg, MSG_RESENT);

	DEBUG_REQ(D_DLMTRACE, req, "no existing lock with rhandle "LPX64,
		  dlmreq->lock_handle[0].cookie);
}

static int mdt_intent_getxattr(enum mdt_it_code opcode,
				struct mdt_thread_info *info,
				struct ldlm_lock **lockp,
				__u64 flags)
{
	struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_RMT];
	struct ldlm_reply      *ldlm_rep = NULL;
	int rc, grc;

	/*
	 * Initialize lhc->mlh_reg_lh either from a previously granted lock
	 * (for the resend case) or a new lock. Below we will use it to
	 * replace the original lock.
	 */
	mdt_intent_fixup_resent(info, *lockp, lhc, flags);
	if (!lustre_handle_is_used(&lhc->mlh_reg_lh)) {
		mdt_lock_reg_init(lhc, (*lockp)->l_req_mode);
		rc = mdt_object_lock(info, info->mti_object, lhc,
				     MDS_INODELOCK_XATTR);
		if (rc)
			return rc;
	}

	grc = mdt_getxattr(info);

	rc = mdt_intent_lock_replace(info, lockp, lhc, flags);

	if (mdt_info_req(info)->rq_repmsg != NULL)
		ldlm_rep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
	if (ldlm_rep == NULL)
		RETURN(err_serious(-EFAULT));

	ldlm_rep->lock_policy_res2 = grc;

	return rc;
}

static int mdt_intent_getattr(enum mdt_it_code opcode,
                              struct mdt_thread_info *info,
                              struct ldlm_lock **lockp,
			      __u64 flags)
{
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_RMT];
        __u64                   child_bits;
        struct ldlm_reply      *ldlm_rep;
        struct mdt_body        *reqbody;
        struct mdt_body        *repbody;
        int                     rc, rc2;
        ENTRY;

        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(reqbody);

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(repbody);

	info->mti_cross_ref = !!(reqbody->mbo_valid & OBD_MD_FLCROSSREF);
	repbody->mbo_eadatasize = 0;
	repbody->mbo_aclsize = 0;

        switch (opcode) {
        case MDT_IT_LOOKUP:
		child_bits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_PERM;
                break;
        case MDT_IT_GETATTR:
		child_bits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE |
			     MDS_INODELOCK_PERM;
                break;
        default:
                CERROR("Unsupported intent (%d)\n", opcode);
                GOTO(out_shrink, rc = -EINVAL);
        }

	rc = mdt_init_ucred_intent_getattr(info, reqbody);
	if (rc)
		GOTO(out_shrink, rc);

        ldlm_rep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
        mdt_set_disposition(info, ldlm_rep, DISP_IT_EXECD);

	/* Get lock from request for possible resent case. */
	mdt_intent_fixup_resent(info, *lockp, lhc, flags);

	rc = mdt_getattr_name_lock(info, lhc, child_bits, ldlm_rep);
	ldlm_rep->lock_policy_res2 = clear_serious(rc);

        if (mdt_get_disposition(ldlm_rep, DISP_LOOKUP_NEG))
                ldlm_rep->lock_policy_res2 = 0;
        if (!mdt_get_disposition(ldlm_rep, DISP_LOOKUP_POS) ||
            ldlm_rep->lock_policy_res2) {
                lhc->mlh_reg_lh.cookie = 0ull;
                GOTO(out_ucred, rc = ELDLM_LOCK_ABORTED);
        }

	rc = mdt_intent_lock_replace(info, lockp, lhc, flags);
        EXIT;
out_ucred:
        mdt_exit_ucred(info);
out_shrink:
        mdt_client_compatibility(info);
        rc2 = mdt_fix_reply(info);
        if (rc == 0)
                rc = rc2;
        return rc;
}

static int mdt_intent_layout(enum mdt_it_code opcode,
			     struct mdt_thread_info *info,
			     struct ldlm_lock **lockp,
			     __u64 flags)
{
	struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_LAYOUT];
	struct layout_intent *layout;
	struct lu_fid *fid;
	struct mdt_object *obj = NULL;
	int layout_size = 0;
	int rc = 0;
	ENTRY;

	if (opcode != MDT_IT_LAYOUT) {
		CERROR("%s: Unknown intent (%d)\n", mdt_obd_name(info->mti_mdt),
			opcode);
		RETURN(-EINVAL);
	}

	layout = req_capsule_client_get(info->mti_pill, &RMF_LAYOUT_INTENT);
	if (layout == NULL)
		RETURN(-EPROTO);

	if (layout->li_opc != LAYOUT_INTENT_ACCESS) {
		CERROR("%s: Unsupported layout intent opc %d\n",
		       mdt_obd_name(info->mti_mdt), layout->li_opc);
		RETURN(-EINVAL);
	}

	fid = &info->mti_tmp_fid2;
	fid_extract_from_res_name(fid, &(*lockp)->l_resource->lr_name);

	/* Get lock from request for possible resent case. */
	mdt_intent_fixup_resent(info, *lockp, lhc, flags);

	obj = mdt_object_find(info->mti_env, info->mti_mdt, fid);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	if (mdt_object_exists(obj) && !mdt_object_remote(obj)) {
		layout_size = mdt_attr_get_eabuf_size(info, obj);
		if (layout_size < 0)
			GOTO(out_obj, rc = layout_size);

		if (layout_size > info->mti_mdt->mdt_max_mdsize)
			info->mti_mdt->mdt_max_mdsize = layout_size;
	}

	(*lockp)->l_lvb_type = LVB_T_LAYOUT;
	req_capsule_set_size(info->mti_pill, &RMF_DLM_LVB, RCL_SERVER,
			     layout_size);
	rc = req_capsule_server_pack(info->mti_pill);
	GOTO(out_obj, rc);

out_obj:
	mdt_object_put(info->mti_env, obj);

	if (rc == 0 && lustre_handle_is_used(&lhc->mlh_reg_lh))
		rc = mdt_intent_lock_replace(info, lockp, lhc, flags);

out:
	lhc->mlh_reg_lh.cookie = 0;

	return rc;
}

static int mdt_intent_reint(enum mdt_it_code opcode,
                            struct mdt_thread_info *info,
                            struct ldlm_lock **lockp,
			    __u64 flags)
{
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_RMT];
        struct ldlm_reply      *rep = NULL;
        long                    opc;
        int                     rc;

        static const struct req_format *intent_fmts[REINT_MAX] = {
                [REINT_CREATE]  = &RQF_LDLM_INTENT_CREATE,
                [REINT_OPEN]    = &RQF_LDLM_INTENT_OPEN
        };

        ENTRY;

	opc = mdt_reint_opcode(mdt_info_req(info), intent_fmts);
        if (opc < 0)
                RETURN(opc);

        if (mdt_it_flavor[opcode].it_reint != opc) {
                CERROR("Reint code %ld doesn't match intent: %d\n",
                       opc, opcode);
                RETURN(err_serious(-EPROTO));
        }

	/* Get lock from request for possible resent case. */
	mdt_intent_fixup_resent(info, *lockp, lhc, flags);

        rc = mdt_reint_internal(info, lhc, opc);

        /* Check whether the reply has been packed successfully. */
        if (mdt_info_req(info)->rq_repmsg != NULL)
                rep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
        if (rep == NULL)
                RETURN(err_serious(-EFAULT));

        /* MDC expects this in any case */
        if (rc != 0)
                mdt_set_disposition(info, rep, DISP_LOOKUP_EXECD);

	/* the open lock or the lock for cross-ref object should be
	 * returned to the client */
	if (lustre_handle_is_used(&lhc->mlh_reg_lh) &&
	    (rc == 0 || rc == -MDT_EREMOTE_OPEN)) {
		rep->lock_policy_res2 = 0;
		rc = mdt_intent_lock_replace(info, lockp, lhc, flags);
		RETURN(rc);
	}

	rep->lock_policy_res2 = clear_serious(rc);

        if (rep->lock_policy_res2 == -ENOENT &&
	    mdt_get_disposition(rep, DISP_LOOKUP_NEG) &&
	    !mdt_get_disposition(rep, DISP_OPEN_CREATE))
		rep->lock_policy_res2 = 0;

	lhc->mlh_reg_lh.cookie = 0ull;
        if (rc == -ENOTCONN || rc == -ENODEV ||
            rc == -EOVERFLOW) { /**< if VBR failure then return error */
                /*
                 * If it is the disconnect error (ENODEV & ENOCONN), the error
                 * will be returned by rq_status, and client at ptlrpc layer
                 * will detect this, then disconnect, reconnect the import
                 * immediately, instead of impacting the following the rpc.
                 */
                RETURN(rc);
        }
	/*
	 * For other cases, the error will be returned by intent, and client
	 * will retrieve the result from intent.
	 */
	RETURN(ELDLM_LOCK_ABORTED);
}

static int mdt_intent_code(enum ldlm_intent_flags itcode)
{
	int rc;

	switch (itcode) {
	case IT_OPEN:
		rc = MDT_IT_OPEN;
		break;
	case IT_OPEN|IT_CREAT:
		rc = MDT_IT_OCREAT;
		break;
	case IT_CREAT:
		rc = MDT_IT_CREATE;
		break;
	case IT_READDIR:
		rc = MDT_IT_READDIR;
		break;
	case IT_GETATTR:
		rc = MDT_IT_GETATTR;
		break;
	case IT_LOOKUP:
		rc = MDT_IT_LOOKUP;
		break;
	case IT_UNLINK:
		rc = MDT_IT_UNLINK;
		break;
	case IT_TRUNC:
		rc = MDT_IT_TRUNC;
		break;
	case IT_GETXATTR:
		rc = MDT_IT_GETXATTR;
		break;
	case IT_LAYOUT:
		rc = MDT_IT_LAYOUT;
		break;
	case IT_QUOTA_DQACQ:
	case IT_QUOTA_CONN:
		rc = MDT_IT_QUOTA;
		break;
	default:
		CERROR("Unknown intent opcode: 0x%08x\n", itcode);
		rc = -EINVAL;
		break;
	}
	return rc;
}

static int mdt_intent_opc(enum ldlm_intent_flags itopc,
			  struct mdt_thread_info *info,
			  struct ldlm_lock **lockp, __u64 flags)
{
	struct req_capsule	*pill = info->mti_pill;
	struct ptlrpc_request	*req = mdt_info_req(info);
	struct mdt_it_flavor	*flv;
	int opc;
	int rc;
	ENTRY;

	opc = mdt_intent_code(itopc);
	if (opc < 0)
		RETURN(-EINVAL);

	if (opc == MDT_IT_QUOTA) {
		struct lu_device *qmt = info->mti_mdt->mdt_qmt_dev;

		if (qmt == NULL)
			RETURN(-EOPNOTSUPP);

		(*lockp)->l_lvb_type = LVB_T_LQUOTA;
		/* pass the request to quota master */
		rc = qmt_hdls.qmth_intent_policy(info->mti_env, qmt,
						 mdt_info_req(info), lockp,
						 flags);
		RETURN(rc);
	}

	flv = &mdt_it_flavor[opc];
	if (flv->it_fmt != NULL)
		req_capsule_extend(pill, flv->it_fmt);

	rc = mdt_unpack_req_pack_rep(info, flv->it_flags);
	if (rc < 0)
		RETURN(rc);

	if (flv->it_flags & MUTABOR &&
	    exp_connect_flags(req->rq_export) & OBD_CONNECT_RDONLY)
		RETURN(-EROFS);

	if (flv->it_act != NULL) {
		struct ldlm_reply *rep;

		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_INTENT_DELAY, 10);

		/* execute policy */
		rc = flv->it_act(opc, info, lockp, flags);

		/* Check whether the reply has been packed successfully. */
		if (req->rq_repmsg != NULL) {
			rep = req_capsule_server_get(info->mti_pill,
						     &RMF_DLM_REP);
			rep->lock_policy_res2 =
				ptlrpc_status_hton(rep->lock_policy_res2);
		}
	}

	RETURN(rc);
}

static int mdt_intent_policy(struct ldlm_namespace *ns,
			     struct ldlm_lock **lockp, void *req_cookie,
			     enum ldlm_mode mode, __u64 flags, void *data)
{
	struct tgt_session_info	*tsi;
	struct mdt_thread_info	*info;
	struct ptlrpc_request	*req  =  req_cookie;
	struct ldlm_intent	*it;
	struct req_capsule	*pill;
	int rc;

	ENTRY;

	LASSERT(req != NULL);

	tsi = tgt_ses_info(req->rq_svc_thread->t_env);

	info = tsi2mdt_info(tsi);
        LASSERT(info != NULL);
        pill = info->mti_pill;
        LASSERT(pill->rc_req == req);

        if (req->rq_reqmsg->lm_bufcount > DLM_INTENT_IT_OFF) {
		req_capsule_extend(pill, &RQF_LDLM_INTENT_BASIC);
                it = req_capsule_client_get(pill, &RMF_LDLM_INTENT);
                if (it != NULL) {
                        rc = mdt_intent_opc(it->opc, info, lockp, flags);
                        if (rc == 0)
                                rc = ELDLM_OK;

                        /* Lock without inodebits makes no sense and will oops
                         * later in ldlm. Let's check it now to see if we have
                         * ibits corrupted somewhere in mdt_intent_opc().
                         * The case for client miss to set ibits has been
                         * processed by others. */
                        LASSERT(ergo(info->mti_dlm_req->lock_desc.l_resource.\
                                        lr_type == LDLM_IBITS,
                                     info->mti_dlm_req->lock_desc.\
                                        l_policy_data.l_inodebits.bits != 0));
                } else
                        rc = err_serious(-EFAULT);
        } else {
                /* No intent was provided */
                LASSERT(pill->rc_fmt == &RQF_LDLM_ENQUEUE);
		req_capsule_set_size(pill, &RMF_DLM_LVB, RCL_SERVER, 0);
                rc = req_capsule_server_pack(pill);
                if (rc)
                        rc = err_serious(rc);
        }
	mdt_thread_info_fini(info);
	RETURN(rc);
}

static void mdt_deregister_seq_exp(struct mdt_device *mdt)
{
	struct seq_server_site	*ss = mdt_seq_site(mdt);

	if (ss->ss_node_id == 0)
		return;

	if (ss->ss_client_seq != NULL) {
		lustre_deregister_lwp_item(&ss->ss_client_seq->lcs_exp);
		ss->ss_client_seq->lcs_exp = NULL;
	}

	if (ss->ss_server_fld != NULL) {
		lustre_deregister_lwp_item(&ss->ss_server_fld->lsf_control_exp);
		ss->ss_server_fld->lsf_control_exp = NULL;
	}
}

static void mdt_seq_fini_cli(struct mdt_device *mdt)
{
	struct seq_server_site *ss = mdt_seq_site(mdt);

	if (ss == NULL)
		return;

	if (ss->ss_server_seq != NULL)
		seq_server_set_cli(NULL, ss->ss_server_seq, NULL);
}

static int mdt_seq_fini(const struct lu_env *env, struct mdt_device *mdt)
{
	mdt_seq_fini_cli(mdt);
	mdt_deregister_seq_exp(mdt);

	return seq_site_fini(env, mdt_seq_site(mdt));
}

/**
 * It will retrieve its FLDB entries from MDT0, and it only happens
 * when upgrading existent FS to 2.6 or when local FLDB is corrupted,
 * and it needs to refresh FLDB from the MDT0.
 **/
static int mdt_register_lwp_callback(void *data)
{
	struct lu_env		env;
	struct mdt_device	*mdt = data;
	struct lu_server_fld	*fld = mdt_seq_site(mdt)->ss_server_fld;
	int			rc;
	ENTRY;

	LASSERT(mdt_seq_site(mdt)->ss_node_id != 0);

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc < 0) {
		CERROR("%s: cannot init env: rc = %d\n", mdt_obd_name(mdt), rc);
		RETURN(rc);
	}

	/* Allocate new sequence now to avoid creating local transaction
	 * in the normal transaction process */
	rc = seq_server_check_and_alloc_super(&env,
					      mdt_seq_site(mdt)->ss_server_seq);
	if (rc < 0)
		GOTO(out, rc);

	if (fld->lsf_new) {
		rc = fld_update_from_controller(&env, fld);
		if (rc != 0) {
			CERROR("%s: cannot update controller: rc = %d\n",
			       mdt_obd_name(mdt), rc);
			GOTO(out, rc);
		}
	}
out:
	lu_env_fini(&env);
	RETURN(rc);
}

static int mdt_register_seq_exp(struct mdt_device *mdt)
{
	struct seq_server_site	*ss = mdt_seq_site(mdt);
	char			*lwp_name = NULL;
	int			rc;

	if (ss->ss_node_id == 0)
		return 0;

	OBD_ALLOC(lwp_name, MAX_OBD_NAME);
	if (lwp_name == NULL)
		GOTO(out_free, rc = -ENOMEM);

	rc = tgt_name2lwp_name(mdt_obd_name(mdt), lwp_name, MAX_OBD_NAME, 0);
	if (rc != 0)
		GOTO(out_free, rc);

	rc = lustre_register_lwp_item(lwp_name, &ss->ss_client_seq->lcs_exp,
				      NULL, NULL);
	if (rc != 0)
		GOTO(out_free, rc);

	rc = lustre_register_lwp_item(lwp_name,
				      &ss->ss_server_fld->lsf_control_exp,
				      mdt_register_lwp_callback, mdt);
	if (rc != 0) {
		lustre_deregister_lwp_item(&ss->ss_client_seq->lcs_exp);
		ss->ss_client_seq->lcs_exp = NULL;
		GOTO(out_free, rc);
	}
out_free:
	if (lwp_name != NULL)
		OBD_FREE(lwp_name, MAX_OBD_NAME);

	return rc;
}

/*
 * Init client sequence manager which is used by local MDS to talk to sequence
 * controller on remote node.
 */
static int mdt_seq_init_cli(const struct lu_env *env, struct mdt_device *mdt)
{
	struct seq_server_site	*ss = mdt_seq_site(mdt);
	int			rc;
	char			*prefix;
	ENTRY;

	/* check if this is adding the first MDC and controller is not yet
	 * initialized. */
	OBD_ALLOC_PTR(ss->ss_client_seq);
	if (ss->ss_client_seq == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
	if (prefix == NULL) {
		OBD_FREE_PTR(ss->ss_client_seq);
		ss->ss_client_seq = NULL;
		RETURN(-ENOMEM);
	}

	/* Note: seq_client_fini will be called in seq_site_fini */
	snprintf(prefix, MAX_OBD_NAME + 5, "ctl-%s", mdt_obd_name(mdt));
	rc = seq_client_init(ss->ss_client_seq, NULL, LUSTRE_SEQ_METADATA,
			     prefix, ss->ss_node_id == 0 ?  ss->ss_control_seq :
							    NULL);
	OBD_FREE(prefix, MAX_OBD_NAME + 5);
	if (rc != 0) {
		OBD_FREE_PTR(ss->ss_client_seq);
		ss->ss_client_seq = NULL;
		RETURN(rc);
	}

	rc = seq_server_set_cli(env, ss->ss_server_seq, ss->ss_client_seq);

	RETURN(rc);
}

static int mdt_seq_init(const struct lu_env *env, struct mdt_device *mdt)
{
	struct seq_server_site	*ss;
	int			rc;
	ENTRY;

	ss = mdt_seq_site(mdt);
	/* init sequence controller server(MDT0) */
	if (ss->ss_node_id == 0) {
		OBD_ALLOC_PTR(ss->ss_control_seq);
		if (ss->ss_control_seq == NULL)
			RETURN(-ENOMEM);

		rc = seq_server_init(env, ss->ss_control_seq, mdt->mdt_bottom,
				     mdt_obd_name(mdt), LUSTRE_SEQ_CONTROLLER,
				     ss);
		if (rc)
			GOTO(out_seq_fini, rc);
	}

	/* Init normal sequence server */
	OBD_ALLOC_PTR(ss->ss_server_seq);
	if (ss->ss_server_seq == NULL)
		GOTO(out_seq_fini, rc = -ENOMEM);

	rc = seq_server_init(env, ss->ss_server_seq, mdt->mdt_bottom,
			     mdt_obd_name(mdt), LUSTRE_SEQ_SERVER, ss);
	if (rc)
		GOTO(out_seq_fini, rc);

	/* init seq client for seq server to talk to seq controller(MDT0) */
	rc = mdt_seq_init_cli(env, mdt);
	if (rc != 0)
		GOTO(out_seq_fini, rc);

	if (ss->ss_node_id != 0)
		/* register controller export through lwp */
		rc = mdt_register_seq_exp(mdt);

	EXIT;
out_seq_fini:
	if (rc)
		mdt_seq_fini(env, mdt);

	return rc;
}

/*
 * FLD wrappers
 */
static int mdt_fld_fini(const struct lu_env *env,
                        struct mdt_device *m)
{
	struct seq_server_site *ss = mdt_seq_site(m);
	ENTRY;

	if (ss && ss->ss_server_fld) {
		fld_server_fini(env, ss->ss_server_fld);
		OBD_FREE_PTR(ss->ss_server_fld);
		ss->ss_server_fld = NULL;
	}

	RETURN(0);
}

static int mdt_fld_init(const struct lu_env *env,
                        const char *uuid,
                        struct mdt_device *m)
{
	struct seq_server_site *ss;
	int rc;
	ENTRY;

	ss = mdt_seq_site(m);

	OBD_ALLOC_PTR(ss->ss_server_fld);
	if (ss->ss_server_fld == NULL)
		RETURN(rc = -ENOMEM);

	rc = fld_server_init(env, ss->ss_server_fld, m->mdt_bottom, uuid,
			     LU_SEQ_RANGE_MDT);
	if (rc) {
		OBD_FREE_PTR(ss->ss_server_fld);
		ss->ss_server_fld = NULL;
		RETURN(rc);
	}

	RETURN(0);
}

static void mdt_stack_pre_fini(const struct lu_env *env,
			   struct mdt_device *m, struct lu_device *top)
{
	struct lustre_cfg_bufs  *bufs;
	struct lustre_cfg       *lcfg;
	struct mdt_thread_info  *info;
	ENTRY;

	LASSERT(top);

	info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
	LASSERT(info != NULL);

	bufs = &info->mti_u.bufs;

	LASSERT(m->mdt_child_exp);
	LASSERT(m->mdt_child_exp->exp_obd);

	/* process cleanup, pass mdt obd name to get obd umount flags */
	/* XXX: this is needed because all layers are referenced by
	 * objects (some of them are pinned by osd, for example *
	 * the proper solution should be a model where object used
	 * by osd only doesn't have mdt/mdd slices -bzzz */
	lustre_cfg_bufs_reset(bufs, mdt_obd_name(m));
	lustre_cfg_bufs_set_string(bufs, 1, NULL);
	lcfg = lustre_cfg_new(LCFG_PRE_CLEANUP, bufs);
	if (lcfg == NULL)
		RETURN_EXIT;

	top->ld_ops->ldo_process_config(env, top, lcfg);
	lustre_cfg_free(lcfg);
	EXIT;
}

static void mdt_stack_fini(const struct lu_env *env,
			   struct mdt_device *m, struct lu_device *top)
{
	struct obd_device	*obd = mdt2obd_dev(m);
	struct lustre_cfg_bufs	*bufs;
	struct lustre_cfg	*lcfg;
	struct mdt_thread_info	*info;
	char			 flags[3] = "";
	ENTRY;

	info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
	LASSERT(info != NULL);

	lu_dev_del_linkage(top->ld_site, top);

	lu_site_purge(env, top->ld_site, -1);

	bufs = &info->mti_u.bufs;
	/* process cleanup, pass mdt obd name to get obd umount flags */
	/* another purpose is to let all layers to release their objects */
	lustre_cfg_bufs_reset(bufs, mdt_obd_name(m));
	if (obd->obd_force)
		strcat(flags, "F");
	if (obd->obd_fail)
		strcat(flags, "A");
	lustre_cfg_bufs_set_string(bufs, 1, flags);
	lcfg = lustre_cfg_new(LCFG_CLEANUP, bufs);
	if (lcfg == NULL)
		RETURN_EXIT;

	LASSERT(top);
	top->ld_ops->ldo_process_config(env, top, lcfg);
	lustre_cfg_free(lcfg);

	lu_site_purge(env, top->ld_site, -1);

	m->mdt_child = NULL;
	m->mdt_bottom = NULL;

	obd_disconnect(m->mdt_child_exp);
	m->mdt_child_exp = NULL;

	obd_disconnect(m->mdt_bottom_exp);
	m->mdt_child_exp = NULL;
}

static int mdt_connect_to_next(const struct lu_env *env, struct mdt_device *m,
			       const char *next, struct obd_export **exp)
{
	struct obd_connect_data *data = NULL;
	struct obd_device	*obd;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		GOTO(out, rc = -ENOMEM);

	obd = class_name2obd(next);
	if (obd == NULL) {
		CERROR("%s: can't locate next device: %s\n",
		       mdt_obd_name(m), next);
		GOTO(out, rc = -ENOTCONN);
	}

	data->ocd_connect_flags = OBD_CONNECT_VERSION;
	data->ocd_version = LUSTRE_VERSION_CODE;

	rc = obd_connect(NULL, exp, obd, &obd->obd_uuid, data, NULL);
	if (rc) {
		CERROR("%s: cannot connect to next dev %s (%d)\n",
		       mdt_obd_name(m), next, rc);
		GOTO(out, rc);
	}

out:
	if (data)
		OBD_FREE_PTR(data);
	RETURN(rc);
}

static int mdt_stack_init(const struct lu_env *env, struct mdt_device *mdt,
			  struct lustre_cfg *cfg)
{
	char		       *dev = lustre_cfg_string(cfg, 0);
	int			rc, name_size, uuid_size;
	char		       *name, *uuid, *p;
	struct lustre_cfg_bufs *bufs;
	struct lustre_cfg      *lcfg;
	struct obd_device      *obd;
	struct lustre_profile  *lprof;
	struct lu_site	       *site;
        ENTRY;

	/* in 1.8 we had the only device in the stack - MDS.
	 * 2.0 introduces MDT, MDD, OSD; MDT starts others internally.
	 * in 2.3 OSD is instantiated by obd_mount.c, so we need
	 * to generate names and setup MDT, MDD. MDT will be using
	 * generated name to connect to MDD. for MDD the next device
	 * will be LOD with name taken from so called "profile" which
	 * is generated by mount_option line
	 *
	 * 1.8 MGS generates config. commands like this:
	 *   #06 (104)mount_option 0:  1:lustre-MDT0000  2:lustre-mdtlov
	 *   #08 (120)setup   0:lustre-MDT0000  1:dev 2:type 3:lustre-MDT0000
	 * 2.0 MGS generates config. commands like this:
	 *   #07 (112)mount_option 0:  1:lustre-MDT0000  2:lustre-MDT0000-mdtlov
	 *   #08 (160)setup   0:lustre-MDT0000  1:lustre-MDT0000_UUID  2:0
	 *                    3:lustre-MDT0000-mdtlov  4:f
	 *
	 * we generate MDD name from MDT one, just replacing T with D
	 *
	 * after all the preparations, the logical equivalent will be
	 *   #01 (160)setup   0:lustre-MDD0000  1:lustre-MDD0000_UUID  2:0
	 *                    3:lustre-MDT0000-mdtlov  4:f
	 *   #02 (160)setup   0:lustre-MDT0000  1:lustre-MDT0000_UUID  2:0
	 *                    3:lustre-MDD0000  4:f
	 *
	 *  notice we build the stack from down to top: MDD first, then MDT */

	name_size = MAX_OBD_NAME;
	uuid_size = MAX_OBD_NAME;

	OBD_ALLOC(name, name_size);
	OBD_ALLOC(uuid, uuid_size);
	if (name == NULL || uuid == NULL)
		GOTO(cleanup_mem, rc = -ENOMEM);

	OBD_ALLOC_PTR(bufs);
	if (!bufs)
		GOTO(cleanup_mem, rc = -ENOMEM);

	strcpy(name, dev);
	p = strstr(name, "-MDT");
	if (p == NULL)
		GOTO(free_bufs, rc = -ENOMEM);
	p[3] = 'D';

	snprintf(uuid, MAX_OBD_NAME, "%s_UUID", name);

	lprof = class_get_profile(lustre_cfg_string(cfg, 0));
	if (lprof == NULL || lprof->lp_dt == NULL) {
		CERROR("can't find the profile: %s\n",
		       lustre_cfg_string(cfg, 0));
		GOTO(free_bufs, rc = -EINVAL);
	}

	lustre_cfg_bufs_reset(bufs, name);
	lustre_cfg_bufs_set_string(bufs, 1, LUSTRE_MDD_NAME);
	lustre_cfg_bufs_set_string(bufs, 2, uuid);
	lustre_cfg_bufs_set_string(bufs, 3, lprof->lp_dt);

	lcfg = lustre_cfg_new(LCFG_ATTACH, bufs);
	if (lcfg == NULL)
		GOTO(put_profile, rc = -ENOMEM);

	rc = class_attach(lcfg);
	if (rc)
		GOTO(lcfg_cleanup, rc);

	obd = class_name2obd(name);
	if (!obd) {
		CERROR("Can not find obd %s (%s in config)\n",
		       MDD_OBD_NAME, lustre_cfg_string(cfg, 0));
		GOTO(lcfg_cleanup, rc = -EINVAL);
	}

	lustre_cfg_free(lcfg);

	lustre_cfg_bufs_reset(bufs, name);
	lustre_cfg_bufs_set_string(bufs, 1, uuid);
	lustre_cfg_bufs_set_string(bufs, 2, dev);
	lustre_cfg_bufs_set_string(bufs, 3, lprof->lp_dt);

	lcfg = lustre_cfg_new(LCFG_SETUP, bufs);
	if (lcfg == NULL)
		GOTO(class_detach, rc = -ENOMEM);

	rc = class_setup(obd, lcfg);
	if (rc)
		GOTO(class_detach, rc);

	/* connect to MDD we just setup */
	rc = mdt_connect_to_next(env, mdt, name, &mdt->mdt_child_exp);
	if (rc)
		GOTO(class_detach, rc);

	site = mdt->mdt_child_exp->exp_obd->obd_lu_dev->ld_site;
	LASSERT(site);
	LASSERT(mdt_lu_site(mdt) == NULL);
	mdt->mdt_lu_dev.ld_site = site;
	site->ls_top_dev = &mdt->mdt_lu_dev;
	mdt->mdt_child = lu2md_dev(mdt->mdt_child_exp->exp_obd->obd_lu_dev);

	/* now connect to bottom OSD */
	snprintf(name, MAX_OBD_NAME, "%s-osd", dev);
	rc = mdt_connect_to_next(env, mdt, name, &mdt->mdt_bottom_exp);
	if (rc)
		GOTO(class_detach, rc);
	mdt->mdt_bottom =
		lu2dt_dev(mdt->mdt_bottom_exp->exp_obd->obd_lu_dev);

	rc = lu_env_refill((struct lu_env *)env);
	if (rc != 0)
		CERROR("Failure to refill session: '%d'\n", rc);

	lu_dev_add_linkage(site, &mdt->mdt_lu_dev);

	EXIT;
class_detach:
	if (rc)
		class_detach(obd, lcfg);
lcfg_cleanup:
	lustre_cfg_free(lcfg);
put_profile:
	class_put_profile(lprof);
free_bufs:
	OBD_FREE_PTR(bufs);
cleanup_mem:
	if (name)
		OBD_FREE(name, name_size);
	if (uuid)
		OBD_FREE(uuid, uuid_size);
	RETURN(rc);
}

/* setup quota master target on MDT0 */
static int mdt_quota_init(const struct lu_env *env, struct mdt_device *mdt,
			  struct lustre_cfg *cfg)
{
	struct obd_device	*obd;
	char			*dev = lustre_cfg_string(cfg, 0);
	char			*qmtname, *uuid, *p;
	struct lustre_cfg_bufs	*bufs;
	struct lustre_cfg	*lcfg;
	struct lustre_profile	*lprof;
	struct obd_connect_data	*data;
	int			 rc;
	ENTRY;

	LASSERT(mdt->mdt_qmt_exp == NULL);
	LASSERT(mdt->mdt_qmt_dev == NULL);

	/* quota master is on MDT0 only for now */
	if (mdt->mdt_seq_site.ss_node_id != 0)
		RETURN(0);

	/* MGS generates config commands which look as follows:
	 *   #01 (160)setup   0:lustre-MDT0000  1:lustre-MDT0000_UUID  2:0
	 *                    3:lustre-MDT0000-mdtlov  4:f
	 *
	 * We generate the QMT name from the MDT one, just replacing MD with QM
	 * after all the preparations, the logical equivalent will be:
	 *   #01 (160)setup   0:lustre-QMT0000  1:lustre-QMT0000_UUID  2:0
	 *                    3:lustre-MDT0000-osd  4:f */
	OBD_ALLOC(qmtname, MAX_OBD_NAME);
	OBD_ALLOC(uuid, UUID_MAX);
	OBD_ALLOC_PTR(bufs);
	OBD_ALLOC_PTR(data);
	if (qmtname == NULL || uuid == NULL || bufs == NULL || data == NULL)
		GOTO(cleanup_mem, rc = -ENOMEM);

	strcpy(qmtname, dev);
	p = strstr(qmtname, "-MDT");
	if (p == NULL)
		GOTO(cleanup_mem, rc = -ENOMEM);
	/* replace MD with QM */
	p[1] = 'Q';
	p[2] = 'M';

	snprintf(uuid, UUID_MAX, "%s_UUID", qmtname);

	lprof = class_get_profile(lustre_cfg_string(cfg, 0));
	if (lprof == NULL || lprof->lp_dt == NULL) {
		CERROR("can't find profile for %s\n",
		       lustre_cfg_string(cfg, 0));
		GOTO(cleanup_mem, rc = -EINVAL);
	}

	lustre_cfg_bufs_reset(bufs, qmtname);
	lustre_cfg_bufs_set_string(bufs, 1, LUSTRE_QMT_NAME);
	lustre_cfg_bufs_set_string(bufs, 2, uuid);
	lustre_cfg_bufs_set_string(bufs, 3, lprof->lp_dt);

	lcfg = lustre_cfg_new(LCFG_ATTACH, bufs);
	if (lcfg == NULL)
		GOTO(put_profile, rc = -ENOMEM);

	rc = class_attach(lcfg);
	if (rc)
		GOTO(lcfg_cleanup, rc);

	obd = class_name2obd(qmtname);
	if (!obd) {
		CERROR("Can not find obd %s (%s in config)\n", qmtname,
		       lustre_cfg_string(cfg, 0));
		GOTO(lcfg_cleanup, rc = -EINVAL);
	}

	lustre_cfg_free(lcfg);

	lustre_cfg_bufs_reset(bufs, qmtname);
	lustre_cfg_bufs_set_string(bufs, 1, uuid);
	lustre_cfg_bufs_set_string(bufs, 2, dev);

	/* for quota, the next device should be the OSD device */
	lustre_cfg_bufs_set_string(bufs, 3,
				   mdt->mdt_bottom->dd_lu_dev.ld_obd->obd_name);

	lcfg = lustre_cfg_new(LCFG_SETUP, bufs);
	if (lcfg == NULL)
		GOTO(class_detach, rc = -ENOMEM);

	rc = class_setup(obd, lcfg);
	if (rc)
		GOTO(class_detach, rc);

	mdt->mdt_qmt_dev = obd->obd_lu_dev;

	/* configure local quota objects */
	rc = mdt->mdt_qmt_dev->ld_ops->ldo_prepare(env,
						   &mdt->mdt_lu_dev,
						   mdt->mdt_qmt_dev);
	if (rc)
		GOTO(class_cleanup, rc);

	/* connect to quota master target */
	data->ocd_connect_flags = OBD_CONNECT_VERSION;
	data->ocd_version = LUSTRE_VERSION_CODE;
	rc = obd_connect(NULL, &mdt->mdt_qmt_exp, obd, &obd->obd_uuid,
			 data, NULL);
	if (rc) {
		CERROR("cannot connect to quota master device %s (%d)\n",
		       qmtname, rc);
		GOTO(class_cleanup, rc);
	}

	EXIT;
class_cleanup:
	if (rc) {
		class_manual_cleanup(obd);
		mdt->mdt_qmt_dev = NULL;
	}
class_detach:
	if (rc)
		class_detach(obd, lcfg);
lcfg_cleanup:
	lustre_cfg_free(lcfg);
put_profile:
	class_put_profile(lprof);
cleanup_mem:
	if (bufs)
		OBD_FREE_PTR(bufs);
	if (qmtname)
		OBD_FREE(qmtname, MAX_OBD_NAME);
	if (uuid)
		OBD_FREE(uuid, UUID_MAX);
	if (data)
		OBD_FREE_PTR(data);
	return rc;
}

/* Shutdown quota master target associated with mdt */
static void mdt_quota_fini(const struct lu_env *env, struct mdt_device *mdt)
{
	ENTRY;

	if (mdt->mdt_qmt_exp == NULL)
		RETURN_EXIT;
	LASSERT(mdt->mdt_qmt_dev != NULL);

	/* the qmt automatically shuts down when the mdt disconnects */
	obd_disconnect(mdt->mdt_qmt_exp);
	mdt->mdt_qmt_exp = NULL;
	mdt->mdt_qmt_dev = NULL;
	EXIT;
}

/* mdt_getxattr() is used from mdt_intent_getxattr(), use this wrapper
 * for now. This will be removed along with converting rest of MDT code
 * to use tgt_session_info */
static int mdt_tgt_getxattr(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info = tsi2mdt_info(tsi);
	int			 rc;

	rc = mdt_getxattr(info);

	mdt_thread_info_fini(info);
	return rc;
}

static struct tgt_handler mdt_tgt_handlers[] = {
TGT_RPC_HANDLER(MDS_FIRST_OPC,
		0,			MDS_CONNECT,	mdt_tgt_connect,
		&RQF_CONNECT, LUSTRE_OBD_VERSION),
TGT_RPC_HANDLER(MDS_FIRST_OPC,
		0,			MDS_DISCONNECT,	tgt_disconnect,
		&RQF_MDS_DISCONNECT, LUSTRE_OBD_VERSION),
TGT_RPC_HANDLER(MDS_FIRST_OPC,
		HABEO_REFERO,		MDS_SET_INFO,	mdt_set_info,
		&RQF_OBD_SET_INFO, LUSTRE_MDS_VERSION),
TGT_MDT_HDL(0,				MDS_GET_INFO,	mdt_get_info),
TGT_MDT_HDL(0		| HABEO_REFERO,	MDS_GETSTATUS,	mdt_getstatus),
TGT_MDT_HDL(HABEO_CORPUS,		MDS_GETATTR,	mdt_getattr),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO,	MDS_GETATTR_NAME,
							mdt_getattr_name),
TGT_MDT_HDL(HABEO_CORPUS,		MDS_GETXATTR,	mdt_tgt_getxattr),
TGT_MDT_HDL(0		| HABEO_REFERO,	MDS_STATFS,	mdt_statfs),
TGT_MDT_HDL(0		| MUTABOR,	MDS_REINT,	mdt_reint),
TGT_MDT_HDL(HABEO_CORPUS,		MDS_CLOSE,	mdt_close),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO,	MDS_READPAGE,	mdt_readpage),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO,	MDS_SYNC,	mdt_sync),
TGT_MDT_HDL(0,				MDS_QUOTACTL,	mdt_quotactl),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO | MUTABOR, MDS_HSM_PROGRESS,
							mdt_hsm_progress),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO | MUTABOR, MDS_HSM_CT_REGISTER,
							mdt_hsm_ct_register),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO | MUTABOR, MDS_HSM_CT_UNREGISTER,
							mdt_hsm_ct_unregister),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO, MDS_HSM_STATE_GET,
							mdt_hsm_state_get),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO | MUTABOR, MDS_HSM_STATE_SET,
							mdt_hsm_state_set),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO, MDS_HSM_ACTION,	mdt_hsm_action),
TGT_MDT_HDL(HABEO_CORPUS| HABEO_REFERO, MDS_HSM_REQUEST,
							mdt_hsm_request),
TGT_MDT_HDL(HABEO_CLAVIS | HABEO_CORPUS | HABEO_REFERO | MUTABOR,
	    MDS_SWAP_LAYOUTS,
	    mdt_swap_layouts),
};

static struct tgt_handler mdt_sec_ctx_ops[] = {
TGT_SEC_HDL_VAR(0,			SEC_CTX_INIT,	  mdt_sec_ctx_handle),
TGT_SEC_HDL_VAR(0,			SEC_CTX_INIT_CONT,mdt_sec_ctx_handle),
TGT_SEC_HDL_VAR(0,			SEC_CTX_FINI,	  mdt_sec_ctx_handle)
};

static struct tgt_handler mdt_quota_ops[] = {
TGT_QUOTA_HDL(HABEO_REFERO,		QUOTA_DQACQ,	  mdt_quota_dqacq),
};

static struct tgt_opc_slice mdt_common_slice[] = {
	{
		.tos_opc_start	= MDS_FIRST_OPC,
		.tos_opc_end	= MDS_LAST_OPC,
		.tos_hs		= mdt_tgt_handlers
	},
	{
		.tos_opc_start	= OBD_FIRST_OPC,
		.tos_opc_end	= OBD_LAST_OPC,
		.tos_hs		= tgt_obd_handlers
	},
	{
		.tos_opc_start	= LDLM_FIRST_OPC,
		.tos_opc_end	= LDLM_LAST_OPC,
		.tos_hs		= tgt_dlm_handlers
	},
	{
		.tos_opc_start	= SEC_FIRST_OPC,
		.tos_opc_end	= SEC_LAST_OPC,
		.tos_hs		= mdt_sec_ctx_ops
	},
	{
		.tos_opc_start	= OUT_UPDATE_FIRST_OPC,
		.tos_opc_end	= OUT_UPDATE_LAST_OPC,
		.tos_hs		= tgt_out_handlers
	},
	{
		.tos_opc_start	= FLD_FIRST_OPC,
		.tos_opc_end	= FLD_LAST_OPC,
		.tos_hs		= fld_handlers
	},
	{
		.tos_opc_start	= SEQ_FIRST_OPC,
		.tos_opc_end	= SEQ_LAST_OPC,
		.tos_hs		= seq_handlers
	},
	{
		.tos_opc_start	= QUOTA_DQACQ,
		.tos_opc_end	= QUOTA_LAST_OPC,
		.tos_hs		= mdt_quota_ops
	},
	{
		.tos_opc_start	= LLOG_FIRST_OPC,
		.tos_opc_end	= LLOG_LAST_OPC,
		.tos_hs		= tgt_llog_handlers
	},
	{
		.tos_opc_start	= LFSCK_FIRST_OPC,
		.tos_opc_end	= LFSCK_LAST_OPC,
		.tos_hs		= tgt_lfsck_handlers
	},

	{
		.tos_hs		= NULL
	}
};

static void mdt_fini(const struct lu_env *env, struct mdt_device *m)
{
	struct md_device	*next = m->mdt_child;
	struct lu_device	*d    = &m->mdt_lu_dev;
	struct obd_device	*obd  = mdt2obd_dev(m);
	struct lfsck_stop	 stop;
	ENTRY;

	stop.ls_status = LS_PAUSED;
	stop.ls_flags = 0;
	next->md_ops->mdo_iocontrol(env, next, OBD_IOC_STOP_LFSCK, 0, &stop);

	mdt_stack_pre_fini(env, m, md2lu_dev(m->mdt_child));
	target_recovery_fini(obd);
	ping_evictor_stop();

	if (m->mdt_opts.mo_coordinator)
		mdt_hsm_cdt_stop(m);

	mdt_hsm_cdt_fini(m);

	mdt_llog_ctxt_unclone(env, m, LLOG_AGENT_ORIG_CTXT);
        mdt_llog_ctxt_unclone(env, m, LLOG_CHANGELOG_ORIG_CTXT);

	if (m->mdt_namespace != NULL)
		ldlm_namespace_free_prior(m->mdt_namespace, NULL,
					  d->ld_obd->obd_force);

        obd_exports_barrier(obd);
        obd_zombie_barrier();

        mdt_procfs_fini(m);

        tgt_fini(env, &m->mdt_lut);
        mdt_fs_cleanup(env, m);
        upcall_cache_cleanup(m->mdt_identity_cache);
        m->mdt_identity_cache = NULL;

	if (m->mdt_namespace != NULL) {
		ldlm_namespace_free_post(m->mdt_namespace);
		d->ld_obd->obd_namespace = m->mdt_namespace = NULL;
	}

	mdt_quota_fini(env, m);

	cfs_free_nidlist(&m->mdt_squash.rsi_nosquash_nids);

        mdt_seq_fini(env, m);
        mdt_fld_fini(env, m);

	/*
	 * Finish the stack
	 */
	mdt_stack_fini(env, m, md2lu_dev(m->mdt_child));

	LASSERT(atomic_read(&d->ld_ref) == 0);

	server_put_mount(mdt_obd_name(m), true);

	EXIT;
}

static int mdt_postrecov(const struct lu_env *, struct mdt_device *);

static int mdt_init0(const struct lu_env *env, struct mdt_device *m,
                     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
        struct mdt_thread_info    *info;
        struct obd_device         *obd;
        const char                *dev = lustre_cfg_string(cfg, 0);
        const char                *num = lustre_cfg_string(cfg, 2);
        struct lustre_mount_info  *lmi = NULL;
        struct lustre_sb_info     *lsi;
        struct lu_site            *s;
	struct seq_server_site	  *ss_site;
        const char                *identity_upcall = "NONE";
        struct md_device          *next;
        int                        rc;
	long                       node_id;
        mntopt_t                   mntopts;
        ENTRY;

	lu_device_init(&m->mdt_lu_dev, ldt);
        /*
         * Environment (env) might be missing mdt_thread_key values at that
         * point, if device is allocated when mdt_thread_key is in QUIESCENT
         * mode.
         *
         * Usually device allocation path doesn't use module key values, but
         * mdt has to do a lot of work here, so allocate key value.
         */
        rc = lu_env_refill((struct lu_env *)env);
        if (rc != 0)
                RETURN(rc);

        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        obd = class_name2obd(dev);
        LASSERT(obd != NULL);

        m->mdt_max_mdsize = MAX_MD_SIZE; /* 4 stripes */
	m->mdt_opts.mo_evict_tgt_nids = 1;
        m->mdt_opts.mo_cos = MDT_COS_DEFAULT;

	/* default is coordinator off, it is started through conf_param
	 * or /proc */
	m->mdt_opts.mo_coordinator = 0;

	lmi = server_get_mount(dev);
        if (lmi == NULL) {
                CERROR("Cannot get mount info for %s!\n", dev);
                RETURN(-EFAULT);
        } else {
                lsi = s2lsi(lmi->lmi_sb);
                /* CMD is supported only in IAM mode */
                LASSERT(num);
                node_id = simple_strtol(num, NULL, 10);
		obd->u.obt.obt_magic = OBT_MAGIC;
		if (lsi->lsi_lmd != NULL &&
		    lsi->lsi_lmd->lmd_flags & LMD_FLG_SKIP_LFSCK)
			m->mdt_skip_lfsck = 1;
	}

	m->mdt_squash.rsi_uid = 0;
	m->mdt_squash.rsi_gid = 0;
	INIT_LIST_HEAD(&m->mdt_squash.rsi_nosquash_nids);
	init_rwsem(&m->mdt_squash.rsi_sem);
	spin_lock_init(&m->mdt_osfs_lock);
	m->mdt_osfs_age = cfs_time_shift_64(-1000);
	m->mdt_enable_remote_dir = 0;
	m->mdt_enable_remote_dir_gid = 0;

	atomic_set(&m->mdt_mds_mds_conns, 0);
	atomic_set(&m->mdt_async_commit_count, 0);

	m->mdt_lu_dev.ld_ops = &mdt_lu_ops;
	m->mdt_lu_dev.ld_obd = obd;
	/* Set this lu_device to obd for error handling purposes. */
	obd->obd_lu_dev = &m->mdt_lu_dev;

	/* init the stack */
	rc = mdt_stack_init((struct lu_env *)env, m, cfg);
	if (rc) {
		CERROR("%s: Can't init device stack, rc %d\n",
		       mdt_obd_name(m), rc);
		GOTO(err_lmi, rc);
	}

	s = mdt_lu_site(m);
	ss_site = mdt_seq_site(m);
	s->ld_seq_site = ss_site;
	ss_site->ss_lu = s;

        /* set server index */
	ss_site->ss_node_id = node_id;

	/* failover is the default
	 * FIXME: we do not failout mds0/mgs, which may cause some problems.
	 * assumed whose ss_node_id == 0 XXX
	 * */
        obd->obd_replayable = 1;
        /* No connection accepted until configurations will finish */
        obd->obd_no_conn = 1;

	if (cfg->lcfg_bufcount > 4 && LUSTRE_CFG_BUFLEN(cfg, 4) > 0) {
		char *str = lustre_cfg_string(cfg, 4);
		if (strchr(str, 'n')) {
			CWARN("%s: recovery disabled\n", mdt_obd_name(m));
			obd->obd_replayable = 0;
		}
	}

	rc = mdt_fld_init(env, mdt_obd_name(m), m);
	if (rc)
		GOTO(err_fini_stack, rc);

	rc = mdt_seq_init(env, m);
	if (rc)
		GOTO(err_fini_fld, rc);

	snprintf(info->mti_u.ns_name, sizeof(info->mti_u.ns_name), "%s-%s",
		 LUSTRE_MDT_NAME, obd->obd_uuid.uuid);
        m->mdt_namespace = ldlm_namespace_new(obd, info->mti_u.ns_name,
                                              LDLM_NAMESPACE_SERVER,
                                              LDLM_NAMESPACE_GREEDY,
                                              LDLM_NS_TYPE_MDT);
        if (m->mdt_namespace == NULL)
                GOTO(err_fini_seq, rc = -ENOMEM);

	m->mdt_namespace->ns_lvbp = m;
	m->mdt_namespace->ns_lvbo = &mdt_lvbo;

        ldlm_register_intent(m->mdt_namespace, mdt_intent_policy);
        /* set obd_namespace for compatibility with old code */
        obd->obd_namespace = m->mdt_namespace;

	rc = mdt_hsm_cdt_init(m);
	if (rc != 0) {
		CERROR("%s: error initializing coordinator, rc %d\n",
		       mdt_obd_name(m), rc);
                GOTO(err_free_ns, rc);
	}

	rc = tgt_init(env, &m->mdt_lut, obd, m->mdt_bottom, mdt_common_slice,
		      OBD_FAIL_MDS_ALL_REQUEST_NET,
		      OBD_FAIL_MDS_ALL_REPLY_NET);
	if (rc)
		GOTO(err_free_hsm, rc);

	rc = mdt_fs_setup(env, m, obd, lsi);
	if (rc)
		GOTO(err_tgt, rc);

	tgt_adapt_sptlrpc_conf(&m->mdt_lut, 1);

        next = m->mdt_child;
        rc = next->md_ops->mdo_iocontrol(env, next, OBD_IOC_GET_MNTOPT, 0,
                                         &mntopts);
        if (rc)
		GOTO(err_fs_cleanup, rc);

        if (mntopts & MNTOPT_USERXATTR)
                m->mdt_opts.mo_user_xattr = 1;
        else
                m->mdt_opts.mo_user_xattr = 0;

	rc = next->md_ops->mdo_maxeasize_get(env, next, &m->mdt_max_ea_size);
	if (rc)
		GOTO(err_fs_cleanup, rc);

        if (mntopts & MNTOPT_ACL)
                m->mdt_opts.mo_acl = 1;
        else
                m->mdt_opts.mo_acl = 0;

	/* XXX: to support suppgid for ACL, we enable identity_upcall
	 * by default, otherwise, maybe got unexpected -EACCESS. */
	if (m->mdt_opts.mo_acl)
		identity_upcall = MDT_IDENTITY_UPCALL_PATH;

	m->mdt_identity_cache = upcall_cache_init(mdt_obd_name(m),
						identity_upcall,
						&mdt_identity_upcall_cache_ops);
	if (IS_ERR(m->mdt_identity_cache)) {
		rc = PTR_ERR(m->mdt_identity_cache);
		m->mdt_identity_cache = NULL;
		GOTO(err_fs_cleanup, rc);
	}

        rc = mdt_procfs_init(m, dev);
        if (rc) {
                CERROR("Can't init MDT lprocfs, rc %d\n", rc);
                GOTO(err_recovery, rc);
        }

	rc = mdt_quota_init(env, m, cfg);
	if (rc)
		GOTO(err_procfs, rc);

	m->mdt_ldlm_client = &mdt2obd_dev(m)->obd_ldlm_client;
	ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
			   "mdt_ldlm_client", m->mdt_ldlm_client);

	ping_evictor_start();

	/* recovery will be started upon mdt_prepare()
	 * when the whole stack is complete and ready
	 * to serve the requests */

        /* Reduce the initial timeout on an MDS because it doesn't need such
         * a long timeout as an OST does. Adaptive timeouts will adjust this
         * value appropriately. */
        if (ldlm_timeout == LDLM_TIMEOUT_DEFAULT)
                ldlm_timeout = MDS_LDLM_TIMEOUT_DEFAULT;

        RETURN(0);
err_procfs:
	mdt_procfs_fini(m);
err_recovery:
	target_recovery_fini(obd);
	upcall_cache_cleanup(m->mdt_identity_cache);
	m->mdt_identity_cache = NULL;
err_fs_cleanup:
	mdt_fs_cleanup(env, m);
err_tgt:
	tgt_fini(env, &m->mdt_lut);
err_free_hsm:
	mdt_hsm_cdt_fini(m);
err_free_ns:
	ldlm_namespace_free(m->mdt_namespace, NULL, 0);
	obd->obd_namespace = m->mdt_namespace = NULL;
err_fini_seq:
	mdt_seq_fini(env, m);
err_fini_fld:
	mdt_fld_fini(env, m);
err_fini_stack:
	mdt_stack_fini(env, m, md2lu_dev(m->mdt_child));
err_lmi:
	if (lmi)
		server_put_mount(dev, true);
	return(rc);
}

/* For interoperability, the left element is old parameter, the right one
 * is the new version of the parameter, if some parameter is deprecated,
 * the new version should be set as NULL. */
static struct cfg_interop_param mdt_interop_param[] = {
	{ "mdt.group_upcall",	NULL },
	{ "mdt.quota_type",	NULL },
	{ "mdd.quota_type",	NULL },
	{ "mdt.rootsquash",	"mdt.root_squash" },
	{ "mdt.nosquash_nid",	"mdt.nosquash_nids" },
	{ NULL }
};

/* used by MGS to process specific configurations */
static int mdt_process_config(const struct lu_env *env,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct mdt_device *m = mdt_dev(d);
        struct md_device *md_next = m->mdt_child;
        struct lu_device *next = md2lu_dev(md_next);
        int rc;
        ENTRY;

	switch (cfg->lcfg_command) {
	case LCFG_PARAM: {
		struct obd_device	   *obd = d->ld_obd;

		/* For interoperability */
		struct cfg_interop_param   *ptr = NULL;
		struct lustre_cfg	   *old_cfg = NULL;
		char			   *param = NULL;

		param = lustre_cfg_string(cfg, 1);
		if (param == NULL) {
			CERROR("param is empty\n");
			rc = -EINVAL;
			break;
		}

		ptr = class_find_old_param(param, mdt_interop_param);
		if (ptr != NULL) {
			if (ptr->new_param == NULL) {
				rc = 0;
				CWARN("For interoperability, skip this %s."
				      " It is obsolete.\n", ptr->old_param);
				break;
			}

			CWARN("Found old param %s, changed it to %s.\n",
			      ptr->old_param, ptr->new_param);

			old_cfg = cfg;
			cfg = lustre_cfg_rename(old_cfg, ptr->new_param);
			if (IS_ERR(cfg)) {
				rc = PTR_ERR(cfg);
				break;
			}
		}

		rc = class_process_proc_param(PARAM_MDT, obd->obd_vars,
					      cfg, obd);
		if (rc > 0 || rc == -ENOSYS) {
			/* is it an HSM var ? */
			rc = class_process_proc_param(PARAM_HSM,
						      hsm_cdt_get_proc_vars(),
						      cfg, obd);
			if (rc > 0 || rc == -ENOSYS)
				/* we don't understand; pass it on */
				rc = next->ld_ops->ldo_process_config(env, next,
								      cfg);
		}

		if (old_cfg != NULL)
			lustre_cfg_free(cfg);

		break;
	}
        default:
                /* others are passed further */
                rc = next->ld_ops->ldo_process_config(env, next, cfg);
                break;
        }
        RETURN(rc);
}

static struct lu_object *mdt_object_alloc(const struct lu_env *env,
					  const struct lu_object_header *hdr,
					  struct lu_device *d)
{
	struct mdt_object *mo;

	ENTRY;

	OBD_SLAB_ALLOC_PTR_GFP(mo, mdt_object_kmem, GFP_NOFS);
	if (mo != NULL) {
		struct lu_object *o;
		struct lu_object_header *h;

		o = &mo->mot_obj;
		h = &mo->mot_header;
		lu_object_header_init(h);
		lu_object_init(o, h, d);
		lu_object_add_top(h, o);
		o->lo_ops = &mdt_obj_ops;
		spin_lock_init(&mo->mot_write_lock);
		mutex_init(&mo->mot_lov_mutex);
		init_rwsem(&mo->mot_open_sem);
		RETURN(o);
	}
	RETURN(NULL);
}

static int mdt_object_init(const struct lu_env *env, struct lu_object *o,
                           const struct lu_object_conf *unused)
{
        struct mdt_device *d = mdt_dev(o->lo_dev);
        struct lu_device  *under;
        struct lu_object  *below;
        int                rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "object init, fid = "DFID"\n",
               PFID(lu_object_fid(o)));

        under = &d->mdt_child->md_lu_dev;
        below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
        if (below != NULL) {
                lu_object_add(o, below);
        } else
                rc = -ENOMEM;

        RETURN(rc);
}

static void mdt_object_free(const struct lu_env *env, struct lu_object *o)
{
        struct mdt_object *mo = mdt_obj(o);
        struct lu_object_header *h;
        ENTRY;

        h = o->lo_header;
        CDEBUG(D_INFO, "object free, fid = "DFID"\n",
               PFID(lu_object_fid(o)));

	LASSERT(atomic_read(&mo->mot_open_count) == 0);
	LASSERT(atomic_read(&mo->mot_lease_count) == 0);

	lu_object_fini(o);
	lu_object_header_fini(h);
	OBD_SLAB_FREE_PTR(mo, mdt_object_kmem);

	EXIT;
}

static int mdt_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *o)
{
	struct mdt_object *mdto = mdt_obj((struct lu_object *)o);

	return (*p)(env, cookie,
		    LUSTRE_MDT_NAME"-object@%p(flags=%d, writecount=%d)",
		    mdto, mdto->mot_flags, mdto->mot_write_count);
}

static int mdt_prepare(const struct lu_env *env,
		struct lu_device *pdev,
		struct lu_device *cdev)
{
	struct mdt_device *mdt = mdt_dev(cdev);
	struct lu_device *next = &mdt->mdt_child->md_lu_dev;
	struct obd_device *obd = cdev->ld_obd;
	int rc;

	ENTRY;

	LASSERT(obd);

	rc = next->ld_ops->ldo_prepare(env, cdev, next);
	if (rc)
		RETURN(rc);

	rc = mdt_llog_ctxt_clone(env, mdt, LLOG_CHANGELOG_ORIG_CTXT);
	if (rc)
		RETURN(rc);

	rc = mdt_llog_ctxt_clone(env, mdt, LLOG_AGENT_ORIG_CTXT);
	if (rc)
		RETURN(rc);

	rc = lfsck_register_namespace(env, mdt->mdt_bottom, mdt->mdt_namespace);
	/* The LFSCK instance is registered just now, so it must be there when
	 * register the namespace to such instance. */
	LASSERTF(rc == 0, "register namespace failed: rc = %d\n", rc);

	if (mdt->mdt_seq_site.ss_node_id == 0) {
		rc = mdt->mdt_child->md_ops->mdo_root_get(env, mdt->mdt_child,
							 &mdt->mdt_md_root_fid);
		if (rc)
			RETURN(rc);
	}

	LASSERT(!test_bit(MDT_FL_CFGLOG, &mdt->mdt_state));

	target_recovery_init(&mdt->mdt_lut, tgt_request_handle);
	set_bit(MDT_FL_CFGLOG, &mdt->mdt_state);
	LASSERT(obd->obd_no_conn);
	spin_lock(&obd->obd_dev_lock);
	obd->obd_no_conn = 0;
	spin_unlock(&obd->obd_dev_lock);

	if (obd->obd_recovering == 0)
		mdt_postrecov(env, mdt);

	RETURN(rc);
}

const struct lu_device_operations mdt_lu_ops = {
        .ldo_object_alloc   = mdt_object_alloc,
        .ldo_process_config = mdt_process_config,
	.ldo_prepare	    = mdt_prepare,
};

static const struct lu_object_operations mdt_obj_ops = {
        .loo_object_init    = mdt_object_init,
        .loo_object_free    = mdt_object_free,
        .loo_object_print   = mdt_object_print
};

static int mdt_obd_set_info_async(const struct lu_env *env,
                                  struct obd_export *exp,
                                  __u32 keylen, void *key,
                                  __u32 vallen, void *val,
                                  struct ptlrpc_request_set *set)
{
	int rc;

	ENTRY;

	if (KEY_IS(KEY_SPTLRPC_CONF)) {
		rc = tgt_adapt_sptlrpc_conf(class_exp2tgt(exp), 0);
		RETURN(rc);
	}

	RETURN(0);
}

/**
 * Match client and server connection feature flags.
 *
 * Compute the compatibility flags for a connection request based on
 * features mutually supported by client and server.
 *
 * The obd_export::exp_connect_data.ocd_connect_flags field in \a exp
 * must not be updated here, otherwise a partially initialized value may
 * be exposed. After the connection request is successfully processed,
 * the top-level MDT connect request handler atomically updates the export
 * connect flags from the obd_connect_data::ocd_connect_flags field of the
 * reply. \see mdt_connect().
 *
 * \param exp   the obd_export associated with this client/target pair
 * \param mdt   the target device for the connection
 * \param data  stores data for this connect request
 *
 * \retval 0       success
 * \retval -EPROTO \a data unexpectedly has zero obd_connect_data::ocd_brw_size
 * \retval -EBADE  client and server feature requirements are incompatible
 */
static int mdt_connect_internal(struct obd_export *exp,
				struct mdt_device *mdt,
				struct obd_connect_data *data)
{
	LASSERT(data != NULL);

	data->ocd_connect_flags &= MDT_CONNECT_SUPPORTED;
	data->ocd_ibits_known &= MDS_INODELOCK_FULL;

	if (!(data->ocd_connect_flags & OBD_CONNECT_MDS_MDS) &&
	    !(data->ocd_connect_flags & OBD_CONNECT_IBITS)) {
		CWARN("%s: client %s does not support ibits lock, either "
		      "very old or an invalid client: flags "LPX64"\n",
		      mdt_obd_name(mdt), exp->exp_client_uuid.uuid,
		      data->ocd_connect_flags);
		return -EBADE;
	}

	if (!mdt->mdt_opts.mo_acl)
		data->ocd_connect_flags &= ~OBD_CONNECT_ACL;

	if (!mdt->mdt_opts.mo_user_xattr)
		data->ocd_connect_flags &= ~OBD_CONNECT_XATTR;

	if (data->ocd_connect_flags & OBD_CONNECT_BRW_SIZE) {
		data->ocd_brw_size = min(data->ocd_brw_size,
					 (__u32)MD_MAX_BRW_SIZE);
		if (data->ocd_brw_size == 0) {
			CERROR("%s: cli %s/%p ocd_connect_flags: "LPX64
			       " ocd_version: %x ocd_grant: %d "
			       "ocd_index: %u ocd_brw_size is "
			       "unexpectedly zero, network data "
			       "corruption? Refusing connection of this"
			       " client\n",
			       mdt_obd_name(mdt),
			       exp->exp_client_uuid.uuid,
			       exp, data->ocd_connect_flags, data->ocd_version,
			       data->ocd_grant, data->ocd_index);
			return -EPROTO;
		}
	}

	/* NB: Disregard the rule against updating
	 * exp_connect_data.ocd_connect_flags in this case, since
	 * tgt_client_new() needs to know if this is a lightweight
	 * connection, and it is safe to expose this flag before
	 * connection processing completes. */
	if (data->ocd_connect_flags & OBD_CONNECT_LIGHTWEIGHT) {
		spin_lock(&exp->exp_lock);
		*exp_connect_flags_ptr(exp) |= OBD_CONNECT_LIGHTWEIGHT;
		spin_unlock(&exp->exp_lock);
	}

	data->ocd_version = LUSTRE_VERSION_CODE;

	if ((data->ocd_connect_flags & OBD_CONNECT_FID) == 0) {
		CWARN("%s: MDS requires FID support, but client not\n",
		      mdt_obd_name(mdt));
		return -EBADE;
	}

	if (OCD_HAS_FLAG(data, PINGLESS)) {
		if (ptlrpc_pinger_suppress_pings()) {
			spin_lock(&exp->exp_obd->obd_dev_lock);
			list_del_init(&exp->exp_obd_chain_timed);
			spin_unlock(&exp->exp_obd->obd_dev_lock);
		} else {
			data->ocd_connect_flags &= ~OBD_CONNECT_PINGLESS;
		}
	}

	data->ocd_max_easize = mdt->mdt_max_ea_size;

	/* NB: Disregard the rule against updating
	 * exp_connect_data.ocd_connect_flags in this case, since
	 * tgt_client_new() needs to know if this is client supports
	 * multiple modify RPCs, and it is safe to expose this flag before
	 * connection processing completes. */
	if (data->ocd_connect_flags & OBD_CONNECT_MULTIMODRPCS) {
		data->ocd_maxmodrpcs = max_mod_rpcs_per_client;
		spin_lock(&exp->exp_lock);
		*exp_connect_flags_ptr(exp) |= OBD_CONNECT_MULTIMODRPCS;
		spin_unlock(&exp->exp_lock);
	}

	return 0;
}

static int mdt_ctxt_add_dirty_flag(struct lu_env *env,
				   struct mdt_thread_info *info,
				   struct mdt_file_data *mfd)
{
	struct lu_context ses;
	int rc;
	ENTRY;

	rc = lu_context_init(&ses, LCT_SERVER_SESSION);
	if (rc)
		RETURN(rc);

	env->le_ses = &ses;
	lu_context_enter(&ses);

	mdt_ucred(info)->uc_valid = UCRED_OLD;
	rc = mdt_add_dirty_flag(info, mfd->mfd_object, &info->mti_attr);

	lu_context_exit(&ses);
	lu_context_fini(&ses);
	env->le_ses = NULL;

	RETURN(rc);
}

static int mdt_export_cleanup(struct obd_export *exp)
{
	struct list_head	 closing_list;
	struct mdt_export_data	*med = &exp->exp_mdt_data;
	struct obd_device	*obd = exp->exp_obd;
	struct mdt_device	*mdt;
	struct mdt_thread_info	*info;
	struct lu_env		 env;
	struct mdt_file_data	*mfd, *n;
	int rc = 0;
	ENTRY;

	INIT_LIST_HEAD(&closing_list);
	spin_lock(&med->med_open_lock);
	while (!list_empty(&med->med_open_head)) {
		struct list_head *tmp = med->med_open_head.next;
		mfd = list_entry(tmp, struct mdt_file_data, mfd_list);

		/* Remove mfd handle so it can't be found again.
		 * We are consuming the mfd_list reference here. */
		class_handle_unhash(&mfd->mfd_handle);
		list_move_tail(&mfd->mfd_list, &closing_list);
	}
	spin_unlock(&med->med_open_lock);
        mdt = mdt_dev(obd->obd_lu_dev);
        LASSERT(mdt != NULL);

        rc = lu_env_init(&env, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);

        info = lu_context_key_get(&env.le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);
        memset(info, 0, sizeof *info);
        info->mti_env = &env;
        info->mti_mdt = mdt;
        info->mti_exp = exp;

	if (!list_empty(&closing_list)) {
		struct md_attr *ma = &info->mti_attr;

		/* Close any open files (which may also cause orphan
		 * unlinking). */
		list_for_each_entry_safe(mfd, n, &closing_list, mfd_list) {
			list_del_init(&mfd->mfd_list);
			ma->ma_need = ma->ma_valid = 0;

			/* This file is being closed due to an eviction, it
			 * could have been modified and now dirty regarding to
			 * HSM archive, check this!
			 * The logic here is to mark a file dirty if there's a
			 * chance it was dirtied before the client was evicted,
			 * so that we don't have to wait for a release attempt
			 * before finding out the file was actually dirty and
			 * fail the release. Aggressively marking it dirty here
			 * will cause the policy engine to attempt to
			 * re-archive it; when rearchiving, we can compare the
			 * current version to the HSM data_version and make the
			 * archive request into a noop if it's not actually
			 * dirty.
			 */
			if (mfd->mfd_mode & FMODE_WRITE)
				rc = mdt_ctxt_add_dirty_flag(&env, info, mfd);

			/* Don't unlink orphan on failover umount, LU-184 */
			if (exp->exp_flags & OBD_OPT_FAILOVER) {
				ma->ma_valid = MA_FLAGS;
				ma->ma_attr_flags |= MDS_KEEP_ORPHAN;
			}
                        mdt_mfd_close(info, mfd);
                }
        }
        info->mti_mdt = NULL;
        /* cleanup client slot early */
        /* Do not erase record for recoverable client. */
        if (!(exp->exp_flags & OBD_OPT_FAILOVER) || exp->exp_failed)
		tgt_client_del(&env, exp);
        lu_env_fini(&env);

        RETURN(rc);
}

static inline void mdt_enable_slc(struct mdt_device *mdt)
{
	if (mdt->mdt_lut.lut_sync_lock_cancel == NEVER_SYNC_ON_CANCEL)
		mdt->mdt_lut.lut_sync_lock_cancel = BLOCKING_SYNC_ON_CANCEL;
}

static inline void mdt_disable_slc(struct mdt_device *mdt)
{
	if (mdt->mdt_lut.lut_sync_lock_cancel == BLOCKING_SYNC_ON_CANCEL)
		mdt->mdt_lut.lut_sync_lock_cancel = NEVER_SYNC_ON_CANCEL;
}

static int mdt_obd_disconnect(struct obd_export *exp)
{
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

	if ((exp_connect_flags(exp) & OBD_CONNECT_MDS_MDS) &&
	    !(exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT)) {
		struct mdt_device *mdt = mdt_dev(exp->exp_obd->obd_lu_dev);

		if (atomic_dec_and_test(&mdt->mdt_mds_mds_conns))
			mdt_disable_slc(mdt);
	}

	rc = server_disconnect_export(exp);
	if (rc != 0)
		CDEBUG(D_IOCTL, "server disconnect error: rc = %d\n", rc);

	rc = mdt_export_cleanup(exp);
	nodemap_del_member(exp);
	class_export_put(exp);
	RETURN(rc);
}

/* mds_connect copy */
static int mdt_obd_connect(const struct lu_env *env,
			   struct obd_export **exp, struct obd_device *obd,
			   struct obd_uuid *cluuid,
			   struct obd_connect_data *data,
			   void *localdata)
{
	struct obd_export	*lexp;
	struct lustre_handle	conn = { 0 };
	struct mdt_device	*mdt;
	int			 rc;
	lnet_nid_t		*client_nid = localdata;
	ENTRY;

	LASSERT(env != NULL);
	if (!exp || !obd || !cluuid)
		RETURN(-EINVAL);

	mdt = mdt_dev(obd->obd_lu_dev);

	if ((data->ocd_connect_flags & OBD_CONNECT_MDS_MDS) &&
	    !(data->ocd_connect_flags & OBD_CONNECT_LIGHTWEIGHT)) {
		atomic_inc(&mdt->mdt_mds_mds_conns);
		mdt_enable_slc(mdt);
	}

	/*
	 * first, check whether the stack is ready to handle requests
	 * XXX: probably not very appropriate method is used now
	 *      at some point we should find a better one
	 */
	if (!test_bit(MDT_FL_SYNCED, &mdt->mdt_state) && data != NULL &&
	    !(data->ocd_connect_flags & OBD_CONNECT_LIGHTWEIGHT) &&
	    !(data->ocd_connect_flags & OBD_CONNECT_MDS_MDS)) {
		rc = obd_get_info(env, mdt->mdt_child_exp,
				  sizeof(KEY_OSP_CONNECTED),
				  KEY_OSP_CONNECTED, NULL, NULL);
		if (rc)
			RETURN(-EAGAIN);
		set_bit(MDT_FL_SYNCED, &mdt->mdt_state);
	}

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	lexp = class_conn2export(&conn);
	LASSERT(lexp != NULL);

	rc = nodemap_add_member(*client_nid, lexp);
	if (rc != 0 && rc != -EEXIST)
		GOTO(out, rc);

	rc = mdt_connect_internal(lexp, mdt, data);
	if (rc == 0) {
		struct lsd_client_data *lcd = lexp->exp_target_data.ted_lcd;

		LASSERT(lcd);
		memcpy(lcd->lcd_uuid, cluuid, sizeof lcd->lcd_uuid);
		rc = tgt_client_new(env, lexp);
		if (rc == 0)
			mdt_export_stats_init(obd, lexp, localdata);
	}
out:
	if (rc != 0) {
		class_disconnect(lexp);
		nodemap_del_member(lexp);
		*exp = NULL;
	} else {
		*exp = lexp;
	}

	RETURN(rc);
}

static int mdt_obd_reconnect(const struct lu_env *env,
			     struct obd_export *exp, struct obd_device *obd,
			     struct obd_uuid *cluuid,
			     struct obd_connect_data *data,
			     void *localdata)
{
	lnet_nid_t	       *client_nid = localdata;
	int                     rc;
	ENTRY;

	if (exp == NULL || obd == NULL || cluuid == NULL)
		RETURN(-EINVAL);

	rc = nodemap_add_member(*client_nid, exp);
	if (rc != 0 && rc != -EEXIST)
		RETURN(rc);

	rc = mdt_connect_internal(exp, mdt_dev(obd->obd_lu_dev), data);
	if (rc == 0)
		mdt_export_stats_init(obd, exp, localdata);
	else
		nodemap_del_member(exp);

	RETURN(rc);
}

/* FIXME: Can we avoid using these two interfaces? */
static int mdt_init_export(struct obd_export *exp)
{
	struct mdt_export_data *med = &exp->exp_mdt_data;
	int			rc;
	ENTRY;

	INIT_LIST_HEAD(&med->med_open_head);
	spin_lock_init(&med->med_open_lock);
	mutex_init(&med->med_idmap_mutex);
	med->med_idmap = NULL;
	spin_lock(&exp->exp_lock);
	exp->exp_connecting = 1;
	spin_unlock(&exp->exp_lock);

        /* self-export doesn't need client data and ldlm initialization */
        if (unlikely(obd_uuid_equals(&exp->exp_obd->obd_uuid,
                                     &exp->exp_client_uuid)))
                RETURN(0);

        rc = tgt_client_alloc(exp);
        if (rc)
		GOTO(err, rc);

	rc = ldlm_init_export(exp);
	if (rc)
		GOTO(err_free, rc);

        RETURN(rc);

err_free:
	tgt_client_free(exp);
err:
	CERROR("%s: Failed to initialize export: rc = %d\n",
	       exp->exp_obd->obd_name, rc);
	return rc;
}

static int mdt_destroy_export(struct obd_export *exp)
{
        ENTRY;

        if (exp_connect_rmtclient(exp))
                mdt_cleanup_idmap(&exp->exp_mdt_data);

        target_destroy_export(exp);
        /* destroy can be called from failed obd_setup, so
         * checking uuid is safer than obd_self_export */
        if (unlikely(obd_uuid_equals(&exp->exp_obd->obd_uuid,
                                     &exp->exp_client_uuid)))
                RETURN(0);

	ldlm_destroy_export(exp);
	tgt_client_free(exp);

	LASSERT(list_empty(&exp->exp_outstanding_replies));
	LASSERT(list_empty(&exp->exp_mdt_data.med_open_head));

	RETURN(0);
}

int mdt_links_read(struct mdt_thread_info *info, struct mdt_object *mdt_obj,
		   struct linkea_data *ldata)
{
	int rc;

	LASSERT(ldata->ld_buf->lb_buf != NULL);

	if (!mdt_object_exists(mdt_obj))
		return -ENODATA;

	rc = mo_xattr_get(info->mti_env, mdt_object_child(mdt_obj),
			  ldata->ld_buf, XATTR_NAME_LINK);
	if (rc == -ERANGE) {
		/* Buf was too small, figure out what we need. */
		lu_buf_free(ldata->ld_buf);
		rc = mo_xattr_get(info->mti_env, mdt_object_child(mdt_obj),
				  ldata->ld_buf, XATTR_NAME_LINK);
		if (rc < 0)
			return rc;
		ldata->ld_buf = lu_buf_check_and_alloc(ldata->ld_buf, rc);
		if (ldata->ld_buf->lb_buf == NULL)
			return -ENOMEM;
		rc = mo_xattr_get(info->mti_env, mdt_object_child(mdt_obj),
				  ldata->ld_buf, XATTR_NAME_LINK);
	}
	if (rc < 0)
		return rc;

	return linkea_init(ldata);
}

/**
 * Given an MDT object, try to look up the full path to the object.
 * Part of the MDT layer implementation of lfs fid2path.
 *
 * \param[in]     info  Per-thread common data shared by MDT level handlers.
 * \param[in]     obj   Object to do path lookup of
 * \param[in,out] fp    User-provided struct to store path information
 *
 * \retval 0 Lookup successful, path information stored in fp
 * \retval -EAGAIN Lookup failed, usually because object is being moved
 * \retval negative errno if there was a problem
 */
static int mdt_path_current(struct mdt_thread_info *info,
			    struct mdt_object *obj,
			    struct getinfo_fid2path *fp)
{
	struct mdt_device	*mdt = info->mti_mdt;
	struct mdt_object	*mdt_obj;
	struct link_ea_header	*leh;
	struct link_ea_entry	*lee;
	struct lu_name		*tmpname = &info->mti_name;
	struct lu_fid		*tmpfid = &info->mti_tmp_fid1;
	struct lu_buf		*buf = &info->mti_big_buf;
	char			*ptr;
	int			reclen;
	struct linkea_data	ldata = { NULL };
	int			rc = 0;
	bool			first = true;
	ENTRY;

	/* temp buffer for path element, the buffer will be finally freed
	 * in mdt_thread_info_fini */
	buf = lu_buf_check_and_alloc(buf, PATH_MAX);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);

	ldata.ld_buf = buf;
	ptr = fp->gf_path + fp->gf_pathlen - 1;
	*ptr = 0;
	--ptr;
	*tmpfid = fp->gf_fid = *mdt_object_fid(obj);

	/* root FID only exists on MDT0, and fid2path should also ends at MDT0,
	 * so checking root_fid can only happen on MDT0. */
	while (!lu_fid_eq(&mdt->mdt_md_root_fid, &fp->gf_fid)) {
		struct lu_buf		lmv_buf;

		mdt_obj = mdt_object_find(info->mti_env, mdt, tmpfid);
		if (IS_ERR(mdt_obj))
			GOTO(out, rc = PTR_ERR(mdt_obj));

		if (!mdt_object_exists(mdt_obj)) {
			mdt_object_put(info->mti_env, mdt_obj);
			GOTO(out, rc = -ENOENT);
		}

		if (mdt_object_remote(mdt_obj)) {
			mdt_object_put(info->mti_env, mdt_obj);
			GOTO(remote_out, rc = -EREMOTE);
		}

		rc = mdt_links_read(info, mdt_obj, &ldata);
		if (rc != 0) {
			mdt_object_put(info->mti_env, mdt_obj);
			GOTO(out, rc);
		}

		leh = buf->lb_buf;
		lee = (struct link_ea_entry *)(leh + 1); /* link #0 */
		linkea_entry_unpack(lee, &reclen, tmpname, tmpfid);
		/* If set, use link #linkno for path lookup, otherwise use
		   link #0.  Only do this for the final path element. */
		if (first && fp->gf_linkno < leh->leh_reccount) {
			int count;
			for (count = 0; count < fp->gf_linkno; count++) {
				lee = (struct link_ea_entry *)
				     ((char *)lee + reclen);
				linkea_entry_unpack(lee, &reclen, tmpname,
						    tmpfid);
			}
			if (fp->gf_linkno < leh->leh_reccount - 1)
				/* indicate to user there are more links */
				fp->gf_linkno++;
		}

		lmv_buf.lb_buf = info->mti_xattr_buf;
		lmv_buf.lb_len = sizeof(info->mti_xattr_buf);
		/* Check if it is slave stripes */
		rc = mo_xattr_get(info->mti_env, mdt_object_child(mdt_obj),
				  &lmv_buf, XATTR_NAME_LMV);
		mdt_object_put(info->mti_env, mdt_obj);
		if (rc > 0) {
			union lmv_mds_md *lmm = lmv_buf.lb_buf;

			/* For slave stripes, get its master */
			if (le32_to_cpu(lmm->lmv_magic) == LMV_MAGIC_STRIPE) {
				fp->gf_fid = *tmpfid;
				continue;
			}
		} else if (rc < 0 && rc != -ENODATA) {
			GOTO(out, rc);
		}

		rc = 0;

		/* Pack the name in the end of the buffer */
		ptr -= tmpname->ln_namelen;
		if (ptr - 1 <= fp->gf_path)
			GOTO(out, rc = -EOVERFLOW);
		strncpy(ptr, tmpname->ln_name, tmpname->ln_namelen);
		*(--ptr) = '/';

		/* keep the last resolved fid to the client, so the
		 * client will build the left path on another MDT for
		 * remote object */
		fp->gf_fid = *tmpfid;

		first = false;
	}

remote_out:
	ptr++; /* skip leading / */
	memmove(fp->gf_path, ptr, fp->gf_path + fp->gf_pathlen - ptr);

out:
	RETURN(rc);
}

/**
 * Given an MDT object, use mdt_path_current to get the path.
 * Essentially a wrapper to retry mdt_path_current a set number of times
 * if -EAGAIN is returned (usually because an object is being moved).
 *
 * Part of the MDT layer implementation of lfs fid2path.
 *
 * \param[in]     info  Per-thread common data shared by mdt level handlers.
 * \param[in]     obj   Object to do path lookup of
 * \param[in,out] fp    User-provided struct for arguments and to store path
 * 			information
 *
 * \retval 0 Lookup successful, path information stored in fp
 * \retval negative errno if there was a problem
 */
static int mdt_path(struct mdt_thread_info *info, struct mdt_object *obj,
		    struct getinfo_fid2path *fp)
{
	struct mdt_device	*mdt = info->mti_mdt;
	int			tries = 3;
	int			rc = -EAGAIN;
	ENTRY;

	if (fp->gf_pathlen < 3)
		RETURN(-EOVERFLOW);

	if (lu_fid_eq(&mdt->mdt_md_root_fid, mdt_object_fid(obj))) {
		fp->gf_path[0] = '\0';
		RETURN(0);
	}

	/* Retry multiple times in case file is being moved */
	while (tries-- && rc == -EAGAIN)
		rc = mdt_path_current(info, obj, fp);

	RETURN(rc);
}

/**
 * Get the full path of the provided FID, as of changelog record recno.
 *
 * This checks sanity and looks up object for user provided FID
 * before calling the actual path lookup code.
 *
 * Part of the MDT layer implementation of lfs fid2path.
 *
 * \param[in]     info  Per-thread common data shared by mdt level handlers.
 * \param[in,out] fp    User-provided struct for arguments and to store path
 * 			information
 *
 * \retval 0 Lookup successful, path information and recno stored in fp
 * \retval -ENOENT, object does not exist
 * \retval negative errno if there was a problem
 */
static int mdt_fid2path(struct mdt_thread_info *info,
			struct getinfo_fid2path *fp)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_object *obj;
	int    rc;
	ENTRY;

	CDEBUG(D_IOCTL, "path get "DFID" from "LPU64" #%d\n",
		PFID(&fp->gf_fid), fp->gf_recno, fp->gf_linkno);

	if (!fid_is_sane(&fp->gf_fid))
		RETURN(-EINVAL);

	if (!fid_is_namespace_visible(&fp->gf_fid)) {
		CWARN("%s: "DFID" is invalid, sequence should be "
		      ">= "LPX64"\n", mdt_obd_name(mdt),
		      PFID(&fp->gf_fid), (__u64)FID_SEQ_NORMAL);
		RETURN(-EINVAL);
	}

	obj = mdt_object_find(info->mti_env, mdt, &fp->gf_fid);
	if (IS_ERR(obj)) {
		rc = PTR_ERR(obj);
		CDEBUG(D_IOCTL, "cannot find "DFID": rc = %d\n",
		       PFID(&fp->gf_fid), rc);
		RETURN(rc);
	}

	if (mdt_object_remote(obj))
		rc = -EREMOTE;
	else if (!mdt_object_exists(obj))
		rc = -ENOENT;
	else
		rc = 0;

	if (rc < 0) {
		mdt_object_put(info->mti_env, obj);
		CDEBUG(D_IOCTL, "nonlocal object "DFID": rc = %d\n",
		       PFID(&fp->gf_fid), rc);
		RETURN(rc);
	}

	rc = mdt_path(info, obj, fp);

	CDEBUG(D_INFO, "fid "DFID", path %s recno "LPX64" linkno %u\n",
	       PFID(&fp->gf_fid), fp->gf_path, fp->gf_recno, fp->gf_linkno);

	mdt_object_put(info->mti_env, obj);

	RETURN(rc);
}

static int mdt_rpc_fid2path(struct mdt_thread_info *info, void *key,
			    void *val, int vallen)
{
	struct getinfo_fid2path *fpout, *fpin;
	int rc = 0;

	fpin = key + cfs_size_round(sizeof(KEY_FID2PATH));
	fpout = val;

	if (ptlrpc_req_need_swab(info->mti_pill->rc_req))
		lustre_swab_fid2path(fpin);

	memcpy(fpout, fpin, sizeof(*fpin));
	if (fpout->gf_pathlen != vallen - sizeof(*fpin))
		RETURN(-EINVAL);

	rc = mdt_fid2path(info, fpout);
	RETURN(rc);
}

int mdt_get_info(struct tgt_session_info *tsi)
{
	char	*key;
	int	 keylen;
	__u32	*vallen;
	void	*valout;
	int	 rc;

	ENTRY;

	key = req_capsule_client_get(tsi->tsi_pill, &RMF_GETINFO_KEY);
	if (key == NULL) {
		CDEBUG(D_IOCTL, "No GETINFO key\n");
		RETURN(err_serious(-EFAULT));
	}
	keylen = req_capsule_get_size(tsi->tsi_pill, &RMF_GETINFO_KEY,
				      RCL_CLIENT);

	vallen = req_capsule_client_get(tsi->tsi_pill, &RMF_GETINFO_VALLEN);
	if (vallen == NULL) {
		CDEBUG(D_IOCTL, "%s: cannot get RMF_GETINFO_VALLEN buffer\n",
				tgt_name(tsi->tsi_tgt));
		RETURN(err_serious(-EFAULT));
	}

	req_capsule_set_size(tsi->tsi_pill, &RMF_GETINFO_VAL, RCL_SERVER,
			     *vallen);
	rc = req_capsule_server_pack(tsi->tsi_pill);
	if (rc)
		RETURN(err_serious(rc));

	valout = req_capsule_server_get(tsi->tsi_pill, &RMF_GETINFO_VAL);
	if (valout == NULL) {
		CDEBUG(D_IOCTL, "%s: cannot get get-info RPC out buffer\n",
				tgt_name(tsi->tsi_tgt));
		RETURN(err_serious(-EFAULT));
	}

	if (KEY_IS(KEY_FID2PATH)) {
		struct mdt_thread_info	*info = tsi2mdt_info(tsi);

		rc = mdt_rpc_fid2path(info, key, valout, *vallen);
		mdt_thread_info_fini(info);
	} else {
		rc = -EINVAL;
	}
	RETURN(rc);
}

/* Pass the ioc down */
static int mdt_ioc_child(struct lu_env *env, struct mdt_device *mdt,
			 unsigned int cmd, int len, void *data)
{
	struct lu_context ioctl_session;
	struct md_device *next = mdt->mdt_child;
	int rc;
	ENTRY;

        rc = lu_context_init(&ioctl_session, LCT_SERVER_SESSION);
	if (rc)
		RETURN(rc);
	ioctl_session.lc_thread = (struct ptlrpc_thread *)current;
	lu_context_enter(&ioctl_session);
	env->le_ses = &ioctl_session;

	LASSERT(next->md_ops->mdo_iocontrol);
	rc = next->md_ops->mdo_iocontrol(env, next, cmd, len, data);

	lu_context_exit(&ioctl_session);
	lu_context_fini(&ioctl_session);
	RETURN(rc);
}

static int mdt_ioc_version_get(struct mdt_thread_info *mti, void *karg)
{
	struct obd_ioctl_data *data = karg;
	struct lu_fid *fid;
	__u64 version;
	struct mdt_object *obj;
	struct mdt_lock_handle  *lh;
	int rc;
	ENTRY;

	if (data->ioc_inlbuf1 == NULL || data->ioc_inllen1 != sizeof(*fid) ||
	    data->ioc_inlbuf2 == NULL || data->ioc_inllen2 != sizeof(version))
		RETURN(-EINVAL);

	fid = (struct lu_fid *)data->ioc_inlbuf1;

	if (!fid_is_sane(fid))
		RETURN(-EINVAL);

	CDEBUG(D_IOCTL, "getting version for "DFID"\n", PFID(fid));

        lh = &mti->mti_lh[MDT_LH_PARENT];
        mdt_lock_reg_init(lh, LCK_CR);

        obj = mdt_object_find_lock(mti, fid, lh, MDS_INODELOCK_UPDATE);
        if (IS_ERR(obj))
                RETURN(PTR_ERR(obj));

	if (mdt_object_remote(obj)) {
		rc = -EREMOTE;
		/**
		 * before calling version get the correct MDS should be
		 * fid, this is error to find remote object here
		 */
		CERROR("nonlocal object "DFID"\n", PFID(fid));
	} else if (!mdt_object_exists(obj)) {
		*(__u64 *)data->ioc_inlbuf2 = ENOENT_VERSION;
		rc = -ENOENT;
	} else {
		version = dt_version_get(mti->mti_env, mdt_obj2dt(obj));
	       *(__u64 *)data->ioc_inlbuf2 = version;
		rc = 0;
	}
	mdt_object_unlock_put(mti, obj, lh, 1);
	RETURN(rc);
}

/* ioctls on obd dev */
static int mdt_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
			 void *karg, void __user *uarg)
{
        struct lu_env      env;
        struct obd_device *obd = exp->exp_obd;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct dt_device  *dt = mdt->mdt_bottom;
        int rc;

        ENTRY;
        CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);
        rc = lu_env_init(&env, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);

        switch (cmd) {
        case OBD_IOC_SYNC:
                rc = mdt_device_sync(&env, mdt);
                break;
        case OBD_IOC_SET_READONLY:
                rc = dt->dd_ops->dt_ro(&env, dt);
                break;
	case OBD_IOC_ABORT_RECOVERY:
		CERROR("%s: Aborting recovery for device\n", mdt_obd_name(mdt));
		obd->obd_abort_recovery = 1;
		target_stop_recovery_thread(obd);
		rc = 0;
		break;
        case OBD_IOC_CHANGELOG_REG:
        case OBD_IOC_CHANGELOG_DEREG:
        case OBD_IOC_CHANGELOG_CLEAR:
                rc = mdt_ioc_child(&env, mdt, cmd, len, karg);
                break;
	case OBD_IOC_START_LFSCK: {
		struct md_device *next = mdt->mdt_child;
		struct obd_ioctl_data *data = karg;
		struct lfsck_start_param lsp;

		if (unlikely(data == NULL)) {
			rc = -EINVAL;
			break;
		}

		lsp.lsp_start = (struct lfsck_start *)(data->ioc_inlbuf1);
		lsp.lsp_index_valid = 0;
		rc = next->md_ops->mdo_iocontrol(&env, next, cmd, 0, &lsp);
		break;
	}
	case OBD_IOC_STOP_LFSCK: {
		struct md_device	*next = mdt->mdt_child;
		struct obd_ioctl_data	*data = karg;
		struct lfsck_stop	 stop;

		stop.ls_status = LS_STOPPED;
		/* Old lfsck utils may pass NULL @stop. */
		if (data->ioc_inlbuf1 == NULL)
			stop.ls_flags = 0;
		else
			stop.ls_flags =
			((struct lfsck_stop *)(data->ioc_inlbuf1))->ls_flags;

		rc = next->md_ops->mdo_iocontrol(&env, next, cmd, 0, &stop);
		break;
	}
        case OBD_IOC_GET_OBJ_VERSION: {
                struct mdt_thread_info *mti;
                mti = lu_context_key_get(&env.le_ctx, &mdt_thread_key);
                memset(mti, 0, sizeof *mti);
                mti->mti_env = &env;
                mti->mti_mdt = mdt;
                mti->mti_exp = exp;

                rc = mdt_ioc_version_get(mti, karg);
                break;
        }
	case OBD_IOC_CATLOGLIST: {
		struct mdt_thread_info *mti;

		mti = lu_context_key_get(&env.le_ctx, &mdt_thread_key);
		lu_local_obj_fid(&mti->mti_tmp_fid1, LLOG_CATALOGS_OID);
		rc = llog_catalog_list(&env, mdt->mdt_bottom, 0, karg,
				       &mti->mti_tmp_fid1);
		break;
	 }
	default:
		rc = -EOPNOTSUPP;
		CERROR("%s: Not supported cmd = %d, rc = %d\n",
			mdt_obd_name(mdt), cmd, rc);
	}

        lu_env_fini(&env);
        RETURN(rc);
}

static int mdt_postrecov(const struct lu_env *env, struct mdt_device *mdt)
{
	struct lu_device *ld = md2lu_dev(mdt->mdt_child);
	int rc;
	ENTRY;

	if (!mdt->mdt_skip_lfsck) {
		struct lfsck_start_param lsp;

		lsp.lsp_start = NULL;
		lsp.lsp_index_valid = 0;
		rc = mdt->mdt_child->md_ops->mdo_iocontrol(env, mdt->mdt_child,
							   OBD_IOC_START_LFSCK,
							   0, &lsp);
		if (rc != 0 && rc != -EALREADY)
			CWARN("%s: auto trigger paused LFSCK failed: rc = %d\n",
			      mdt_obd_name(mdt), rc);
	}

	rc = ld->ld_ops->ldo_recovery_complete(env, ld);
	RETURN(rc);
}

static int mdt_obd_postrecov(struct obd_device *obd)
{
        struct lu_env env;
        int rc;

        rc = lu_env_init(&env, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);
        rc = mdt_postrecov(&env, mdt_dev(obd->obd_lu_dev));
        lu_env_fini(&env);
        return rc;
}

static struct obd_ops mdt_obd_device_ops = {
        .o_owner          = THIS_MODULE,
        .o_set_info_async = mdt_obd_set_info_async,
        .o_connect        = mdt_obd_connect,
        .o_reconnect      = mdt_obd_reconnect,
        .o_disconnect     = mdt_obd_disconnect,
        .o_init_export    = mdt_init_export,
        .o_destroy_export = mdt_destroy_export,
        .o_iocontrol      = mdt_iocontrol,
        .o_postrecov      = mdt_obd_postrecov,
};

static struct lu_device* mdt_device_fini(const struct lu_env *env,
                                         struct lu_device *d)
{
        struct mdt_device *m = mdt_dev(d);
        ENTRY;

        mdt_fini(env, m);
        RETURN(NULL);
}

static struct lu_device *mdt_device_free(const struct lu_env *env,
                                         struct lu_device *d)
{
	struct mdt_device *m = mdt_dev(d);
	ENTRY;

	lu_device_fini(&m->mdt_lu_dev);
	OBD_FREE_PTR(m);

	RETURN(NULL);
}

static struct lu_device *mdt_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct mdt_device *m;

        OBD_ALLOC_PTR(m);
        if (m != NULL) {
                int rc;

		l = &m->mdt_lu_dev;
                rc = mdt_init0(env, m, t, cfg);
                if (rc != 0) {
                        mdt_device_free(env, l);
                        l = ERR_PTR(rc);
                        return l;
                }
        } else
                l = ERR_PTR(-ENOMEM);
        return l;
}

/* context key constructor/destructor: mdt_key_init, mdt_key_fini */
LU_KEY_INIT(mdt, struct mdt_thread_info);

static void mdt_key_fini(const struct lu_context *ctx,
			 struct lu_context_key *key, void* data)
{
	struct mdt_thread_info *info = data;

	if (info->mti_big_lmm) {
		OBD_FREE_LARGE(info->mti_big_lmm, info->mti_big_lmmsize);
		info->mti_big_lmm = NULL;
		info->mti_big_lmmsize = 0;
	}
	OBD_FREE_PTR(info);
}

/* context key: mdt_thread_key */
LU_CONTEXT_KEY_DEFINE(mdt, LCT_MD_THREAD);

struct lu_ucred *mdt_ucred(const struct mdt_thread_info *info)
{
	return lu_ucred(info->mti_env);
}

struct lu_ucred *mdt_ucred_check(const struct mdt_thread_info *info)
{
	return lu_ucred_check(info->mti_env);
}

/**
 * Enable/disable COS (Commit On Sharing).
 *
 * Set/Clear the COS flag in mdt options.
 *
 * \param mdt mdt device
 * \param val 0 disables COS, other values enable COS
 */
void mdt_enable_cos(struct mdt_device *mdt, int val)
{
        struct lu_env env;
        int rc;

        mdt->mdt_opts.mo_cos = !!val;
        rc = lu_env_init(&env, LCT_LOCAL);
	if (unlikely(rc != 0)) {
		CWARN("%s: lu_env initialization failed, cannot "
		      "sync: rc = %d\n", mdt_obd_name(mdt), rc);
		return;
	}
	mdt_device_sync(&env, mdt);
	lu_env_fini(&env);
}

/**
 * Check COS (Commit On Sharing) status.
 *
 * Return COS flag status.
 *
 * \param mdt mdt device
 */
int mdt_cos_is_enabled(struct mdt_device *mdt)
{
        return mdt->mdt_opts.mo_cos != 0;
}

static struct lu_device_type_operations mdt_device_type_ops = {
        .ldto_device_alloc = mdt_device_alloc,
        .ldto_device_free  = mdt_device_free,
        .ldto_device_fini  = mdt_device_fini
};

static struct lu_device_type mdt_device_type = {
        .ldt_tags     = LU_DEVICE_MD,
        .ldt_name     = LUSTRE_MDT_NAME,
        .ldt_ops      = &mdt_device_type_ops,
        .ldt_ctx_tags = LCT_MD_THREAD
};

static int __init mdt_init(void)
{
	int rc;

	CLASSERT(sizeof("0x0123456789ABCDEF:0x01234567:0x01234567") ==
		 FID_NOBRACE_LEN + 1);
	CLASSERT(sizeof("[0x0123456789ABCDEF:0x01234567:0x01234567]") ==
		 FID_LEN + 1);
	rc = lu_kmem_init(mdt_caches);
	if (rc)
		return rc;

	rc = mds_mod_init();
	if (rc)
		GOTO(lu_fini, rc);

	rc = class_register_type(&mdt_obd_device_ops, NULL, true, NULL,
				 LUSTRE_MDT_NAME, &mdt_device_type);
	if (rc)
		GOTO(mds_fini, rc);
lu_fini:
	if (rc)
		lu_kmem_fini(mdt_caches);
mds_fini:
	if (rc)
		mds_mod_exit();
	return rc;
}

static void __exit mdt_exit(void)
{
	class_unregister_type(LUSTRE_MDT_NAME);
	mds_mod_exit();
	lu_kmem_fini(mdt_caches);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Metadata Target ("LUSTRE_MDT_NAME")");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(mdt_init);
module_exit(mdt_exit);
