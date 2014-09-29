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
 * Copyright (c) 2010, 2013, Intel Corporation.
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
/*
 * struct OBD_{ALLOC,FREE}*()
 */
#include <obd_support.h>
/* struct ptlrpc_request */
#include <lustre_net.h>
/* struct obd_export */
#include <lustre_export.h>
/* struct obd_device */
#include <obd.h>
/* lu2dt_dev() */
#include <dt_object.h>
#include <lustre_mds.h>
#include <lustre_log.h>
#include "mdt_internal.h"
#include <lustre_acl.h>
#include <lustre_param.h>
#include <lustre_quota.h>
#include <lustre_linkea.h>
#include <lustre_lfsck.h>

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

ldlm_mode_t mdt_dlm_lock_modes[] = {
        [MDL_MINMODE] = LCK_MINMODE,
        [MDL_EX]      = LCK_EX,
        [MDL_PW]      = LCK_PW,
        [MDL_PR]      = LCK_PR,
        [MDL_CW]      = LCK_CW,
        [MDL_CR]      = LCK_CR,
        [MDL_NL]      = LCK_NL,
        [MDL_GROUP]   = LCK_GROUP
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

int mdt_get_disposition(struct ldlm_reply *rep, int flag)
{
        if (!rep)
                return 0;
        return (rep->lock_policy_res1 & flag);
}

void mdt_clear_disposition(struct mdt_thread_info *info,
                           struct ldlm_reply *rep, int flag)
{
        if (info)
                info->mti_opdata &= ~flag;
        if (rep)
                rep->lock_policy_res1 &= ~flag;
}

void mdt_set_disposition(struct mdt_thread_info *info,
                         struct ldlm_reply *rep, int flag)
{
        if (info)
                info->mti_opdata |= flag;
        if (rep)
                rep->lock_policy_res1 |= flag;
}

void mdt_lock_reg_init(struct mdt_lock_handle *lh, ldlm_mode_t lm)
{
        lh->mlh_pdo_hash = 0;
        lh->mlh_reg_mode = lm;
	lh->mlh_rreg_mode = lm;
        lh->mlh_type = MDT_REG_LOCK;
}

void mdt_lock_pdo_init(struct mdt_lock_handle *lh, ldlm_mode_t lm,
                       const char *name, int namelen)
{
        lh->mlh_reg_mode = lm;
	lh->mlh_rreg_mode = lm;
        lh->mlh_type = MDT_PDO_LOCK;

        if (name != NULL && (name[0] != '\0')) {
                LASSERT(namelen > 0);
                lh->mlh_pdo_hash = full_name_hash(name, namelen);
		/* XXX Workaround for LU-2856
		 * Zero is a valid return value of full_name_hash, but several
		 * users of mlh_pdo_hash assume a non-zero hash value. We
		 * therefore map zero onto an arbitrary, but consistent
		 * value (1) to avoid problems further down the road. */
		if (unlikely(!lh->mlh_pdo_hash))
			lh->mlh_pdo_hash = 1;
        } else {
                LASSERT(namelen == 0);
                lh->mlh_pdo_hash = 0ull;
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

int mdt_getstatus(struct mdt_thread_info *info)
{
	struct mdt_device	*mdt  = info->mti_mdt;
	struct mdt_body		*repbody;
	int			rc;
	ENTRY;

        rc = mdt_check_ucred(info);
        if (rc)
                RETURN(err_serious(rc));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK))
                RETURN(err_serious(-ENOMEM));

	repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
	repbody->fid1 = mdt->mdt_md_root_fid;
        repbody->valid |= OBD_MD_FLID;

        if (mdt->mdt_opts.mo_mds_capa &&
	    exp_connect_flags(info->mti_exp) & OBD_CONNECT_MDS_CAPA) {
                struct mdt_object  *root;
                struct lustre_capa *capa;

                root = mdt_object_find(info->mti_env, mdt, &repbody->fid1);
                if (IS_ERR(root))
                        RETURN(PTR_ERR(root));

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA1);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_MDS_DEFAULT;
                rc = mo_capa_get(info->mti_env, mdt_object_child(root), capa,
                                 0);
                mdt_object_put(info->mti_env, root);
                if (rc == 0)
                        repbody->valid |= OBD_MD_FLMDSCAPA;
        }

        RETURN(rc);
}

int mdt_statfs(struct mdt_thread_info *info)
{
	struct ptlrpc_request		*req = mdt_info_req(info);
	struct md_device		*next = info->mti_mdt->mdt_child;
	struct ptlrpc_service_part	*svcpt;
	struct obd_statfs		*osfs;
	int				rc;

	ENTRY;

	svcpt = info->mti_pill->rc_req->rq_rqbd->rqbd_svcpt;

	/* This will trigger a watchdog timeout */
	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_STATFS_LCW_SLEEP,
			 (MDT_SERVICE_WATCHDOG_FACTOR *
			  at_get(&svcpt->scp_at_estimate)) + 1);

        rc = mdt_check_ucred(info);
        if (rc)
                RETURN(err_serious(rc));

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK))
		RETURN(err_serious(-ENOMEM));

	osfs = req_capsule_server_get(info->mti_pill, &RMF_OBD_STATFS);
	if (!osfs)
		RETURN(-EPROTO);

	/** statfs information are cached in the mdt_device */
	if (cfs_time_before_64(info->mti_mdt->mdt_osfs_age,
			       cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS))) {
		/** statfs data is too old, get up-to-date one */
		rc = next->md_ops->mdo_statfs(info->mti_env, next, osfs);
		if (rc)
			RETURN(rc);
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

	RETURN(rc);
}

/**
 * Pack SOM attributes into the reply.
 * Call under a DLM UPDATE lock.
 */
static void mdt_pack_size2body(struct mdt_thread_info *info,
                               struct mdt_object *mo)
{
        struct mdt_body *b;
        struct md_attr *ma = &info->mti_attr;

        LASSERT(ma->ma_attr.la_valid & LA_MODE);
        b = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        /* Check if Size-on-MDS is supported, if this is a regular file,
         * if SOM is enabled on the object and if SOM cache exists and valid.
         * Otherwise do not pack Size-on-MDS attributes to the reply. */
        if (!(mdt_conn_flags(info) & OBD_CONNECT_SOM) ||
            !S_ISREG(ma->ma_attr.la_mode) ||
            !mdt_object_is_som_enabled(mo) ||
            !(ma->ma_valid & MA_SOM))
                return;

        b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        b->size = ma->ma_som->msd_size;
        b->blocks = ma->ma_som->msd_blocks;
}

void mdt_pack_attr2body(struct mdt_thread_info *info, struct mdt_body *b,
                        const struct lu_attr *attr, const struct lu_fid *fid)
{
        struct md_attr *ma = &info->mti_attr;

        LASSERT(ma->ma_valid & MA_INODE);

        b->atime      = attr->la_atime;
        b->mtime      = attr->la_mtime;
        b->ctime      = attr->la_ctime;
        b->mode       = attr->la_mode;
        b->size       = attr->la_size;
        b->blocks     = attr->la_blocks;
        b->uid        = attr->la_uid;
        b->gid        = attr->la_gid;
        b->flags      = attr->la_flags;
        b->nlink      = attr->la_nlink;
        b->rdev       = attr->la_rdev;

        /*XXX should pack the reply body according to lu_valid*/
        b->valid |= OBD_MD_FLCTIME | OBD_MD_FLUID   |
                    OBD_MD_FLGID   | OBD_MD_FLTYPE  |
                    OBD_MD_FLMODE  | OBD_MD_FLNLINK | OBD_MD_FLFLAGS |
                    OBD_MD_FLATIME | OBD_MD_FLMTIME ;

        if (!S_ISREG(attr->la_mode)) {
                b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLRDEV;
	} else if (ma->ma_need & MA_LOV && !(ma->ma_valid & MA_LOV)) {
                /* means no objects are allocated on osts. */
                LASSERT(!(ma->ma_valid & MA_LOV));
                /* just ignore blocks occupied by extend attributes on MDS */
                b->blocks = 0;
                /* if no object is allocated on osts, the size on mds is valid. b=22272 */
                b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
	} else if ((ma->ma_valid & MA_LOV) && ma->ma_lmm != NULL &&
		   ma->ma_lmm->lmm_pattern & LOV_PATTERN_F_RELEASED) {
		/* A released file stores its size on MDS. */
		/* But return 1 block for released file, unless tools like tar
		 * will consider it fully sparse. (LU-3864)
		 */
		if (unlikely(b->size == 0))
			b->blocks = 0;
		else
			b->blocks = 1;
		b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
	}

        if (fid) {
                b->fid1 = *fid;
                b->valid |= OBD_MD_FLID;
                CDEBUG(D_INODE, DFID": nlink=%d, mode=%o, size="LPU64"\n",
                                PFID(fid), b->nlink, b->mode, b->size);
        }

        if (info)
                mdt_body_reverse_idmap(info, b);

	if (fid != NULL && (b->valid & OBD_MD_FLSIZE))
                CDEBUG(D_VFSTRACE, DFID": returning size %llu\n",
                       PFID(fid), (unsigned long long)b->size);
}

static inline int mdt_body_has_lov(const struct lu_attr *la,
                                   const struct mdt_body *body)
{
        return ((S_ISREG(la->la_mode) && (body->valid & OBD_MD_FLEASIZE)) ||
                (S_ISDIR(la->la_mode) && (body->valid & OBD_MD_FLDIREA )) );
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

int mdt_attr_get_eabuf_size(struct mdt_thread_info *info, struct mdt_object *o)
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
		if ((rc2 < 0 && rc2 != -ENODATA) || (rc2 > rc))
			rc = rc2;
	}

out:
	return rc;
}

static int mdt_big_xattr_get(struct mdt_thread_info *info, struct mdt_object *o,
			     char *name)
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

int mdt_attr_get_lov(struct mdt_thread_info *info,
		     struct mdt_object *o, struct md_attr *ma)
{
	struct md_object *next = mdt_object_child(o);
	struct lu_buf    *buf = &info->mti_buf;
	int rc;

	buf->lb_buf = ma->ma_lmm;
	buf->lb_len = ma->ma_lmm_size;
	rc = mo_xattr_get(info->mti_env, next, buf, XATTR_NAME_LOV);
	if (rc > 0) {
		ma->ma_lmm_size = rc;
		ma->ma_valid |= MA_LOV;
		rc = 0;
	} else if (rc == -ENODATA) {
		/* no LOV EA */
		rc = 0;
	} else if (rc == -ERANGE) {
		rc = mdt_big_xattr_get(info, o, XATTR_NAME_LOV);
		if (rc > 0) {
			info->mti_big_lmm_used = 1;
			ma->ma_valid |= MA_LOV;
			ma->ma_lmm = info->mti_big_lmm;
			ma->ma_lmm_size = rc;
			/* update mdt_max_mdsize so all clients
			 * will be aware about that */
			if (info->mti_mdt->mdt_max_mdsize < rc)
				info->mti_mdt->mdt_max_mdsize = rc;
			rc = 0;
		}
	}

	return rc;
}

int mdt_attr_get_pfid(struct mdt_thread_info *info,
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
		rc = mdt_attr_get_lov(info, o, ma);
		if (rc)
			GOTO(out, rc);
	}

	if (need & MA_LMV && S_ISDIR(mode)) {
		buf->lb_buf = ma->ma_lmv;
		buf->lb_len = ma->ma_lmv_size;
		rc2 = mo_xattr_get(env, next, buf, XATTR_NAME_LMV);
		if (rc2 > 0) {
			ma->ma_lmv_size = rc2;
			ma->ma_valid |= MA_LMV;
		} else if (rc2 == -ENODATA) {
			/* no LMV EA */
			ma->ma_lmv_size = 0;
		} else
			GOTO(out, rc = rc2);
	}

	if (need & MA_SOM && S_ISREG(mode)) {
		buf->lb_buf = info->mti_xattr_buf;
		buf->lb_len = sizeof(info->mti_xattr_buf);
		CLASSERT(sizeof(struct som_attrs) <=
			 sizeof(info->mti_xattr_buf));
		rc2 = mo_xattr_get(info->mti_env, next, buf, XATTR_NAME_SOM);
		rc2 = lustre_buf2som(info->mti_xattr_buf, rc2, ma->ma_som);
		if (rc2 == 0)
			ma->ma_valid |= MA_SOM;
		else if (rc2 < 0 && rc2 != -ENODATA)
			GOTO(out, rc = rc2);
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
        struct md_object        *next = mdt_object_child(o);
        const struct mdt_body   *reqbody = info->mti_body;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_attr          *ma = &info->mti_attr;
        struct lu_attr          *la = &ma->ma_attr;
        struct req_capsule      *pill = info->mti_pill;
        const struct lu_env     *env = info->mti_env;
        struct mdt_body         *repbody;
        struct lu_buf           *buffer = &info->mti_buf;
        int                     rc;
	int			is_root;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK))
                RETURN(err_serious(-ENOMEM));

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);

        ma->ma_valid = 0;

	if (mdt_object_remote(o)) {
		/* This object is located on remote node.*/
		/* Return -EIO for old client */
		if (!mdt_is_dne_client(req->rq_export))
			GOTO(out, rc = -EIO);

		repbody->fid1 = *mdt_object_fid(o);
		repbody->valid = OBD_MD_FLID | OBD_MD_MDS;
		GOTO(out, rc = 0);
	}

	if (reqbody->eadatasize > 0) {
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
	    reqbody->valid & OBD_MD_MEA) {
		/* Assumption: MDT_MD size is enough for lmv size. */
		ma->ma_lmv = buffer->lb_buf;
		ma->ma_lmv_size = buffer->lb_len;
		ma->ma_need = MA_INODE;
		if (ma->ma_lmm_size > 0)
			ma->ma_need |= MA_LMV;
	} else {
		ma->ma_lmm = buffer->lb_buf;
		ma->ma_lmm_size = buffer->lb_len;
		ma->ma_need = MA_INODE | MA_HSM;
		if (ma->ma_lmm_size > 0)
			ma->ma_need |= MA_LOV;
	}

        if (S_ISDIR(lu_object_attr(&next->mo_lu)) &&
            reqbody->valid & OBD_MD_FLDIREA  &&
            lustre_msg_get_opc(req->rq_reqmsg) == MDS_GETATTR) {
                /* get default stripe info for this dir. */
                ma->ma_need |= MA_LOV_DEF;
        }
        ma->ma_need |= ma_need;
        if (ma->ma_need & MA_SOM)
                ma->ma_som = &info->mti_u.som.data;

	rc = mdt_attr_get_complex(info, o, ma);
	if (unlikely(rc)) {
		CERROR("%s: getattr error for "DFID": rc = %d\n",
		       mdt_obd_name(info->mti_mdt),
		       PFID(mdt_object_fid(o)), rc);
		RETURN(rc);
	}

	/* if file is released, check if a restore is running */
	if ((ma->ma_valid & MA_HSM) && (ma->ma_hsm.mh_flags & HS_RELEASED) &&
	    mdt_hsm_restore_is_running(info, mdt_object_fid(o))) {
		repbody->t_state = MS_RESTORE;
		repbody->valid |= OBD_MD_TSTATE;
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
		rc = mdt_attr_get_lov(info, root, ma);
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
                        repbody->eadatasize = ma->ma_lmm_size;
                        if (S_ISDIR(la->la_mode))
                                repbody->valid |= OBD_MD_FLDIREA;
                        else
				repbody->valid |= OBD_MD_FLEASIZE;
			mdt_dump_lmm(D_INFO, ma->ma_lmm, repbody->valid);
		}
                if (ma->ma_valid & MA_LMV) {
                        LASSERT(S_ISDIR(la->la_mode));
                        repbody->eadatasize = ma->ma_lmv_size;
                        repbody->valid |= (OBD_MD_FLDIREA|OBD_MD_MEA);
                }
	} else if (S_ISLNK(la->la_mode) &&
		   reqbody->valid & OBD_MD_LINKNAME) {
		buffer->lb_buf = ma->ma_lmm;
		/* eadatasize from client includes NULL-terminator, so
		 * there is no need to read it */
		buffer->lb_len = reqbody->eadatasize - 1;
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
			repbody->valid |= OBD_MD_LINKNAME;
			/* we need to report back size with NULL-terminator
			 * because client expects that */
			repbody->eadatasize = rc + 1;
			if (repbody->eadatasize != reqbody->eadatasize)
				CDEBUG(D_INODE, "%s: Read shorter symlink %d "
				       "on "DFID ", expected %d\n",
				       mdt_obd_name(info->mti_mdt),
				       rc, PFID(mdt_object_fid(o)),
				       reqbody->eadatasize - 1);
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

        if (reqbody->valid & OBD_MD_FLMODEASIZE) {
		repbody->max_cookiesize = 0;
                repbody->max_mdsize = info->mti_mdt->mdt_max_mdsize;
                repbody->valid |= OBD_MD_FLMODEASIZE;
                CDEBUG(D_INODE, "I am going to change the MAX_MD_SIZE & "
                       "MAX_COOKIE to : %d:%d\n", repbody->max_mdsize,
                       repbody->max_cookiesize);
        }

        if (exp_connect_rmtclient(info->mti_exp) &&
            reqbody->valid & OBD_MD_FLRMTPERM) {
                void *buf = req_capsule_server_get(pill, &RMF_ACL);

                /* mdt_getattr_lock only */
                rc = mdt_pack_remote_perm(info, o, buf);
                if (rc) {
                        repbody->valid &= ~OBD_MD_FLRMTPERM;
                        repbody->aclsize = 0;
                        RETURN(rc);
                } else {
                        repbody->valid |= OBD_MD_FLRMTPERM;
                        repbody->aclsize = sizeof(struct mdt_remote_perm);
                }
        }
#ifdef CONFIG_FS_POSIX_ACL
	else if ((exp_connect_flags(req->rq_export) & OBD_CONNECT_ACL) &&
		 (reqbody->valid & OBD_MD_FLACL)) {
                buffer->lb_buf = req_capsule_server_get(pill, &RMF_ACL);
                buffer->lb_len = req_capsule_get_size(pill,
                                                      &RMF_ACL, RCL_SERVER);
                if (buffer->lb_len > 0) {
                        rc = mo_xattr_get(env, next, buffer,
                                          XATTR_NAME_ACL_ACCESS);
                        if (rc < 0) {
                                if (rc == -ENODATA) {
                                        repbody->aclsize = 0;
                                        repbody->valid |= OBD_MD_FLACL;
                                        rc = 0;
                                } else if (rc == -EOPNOTSUPP) {
                                        rc = 0;
				} else {
					CERROR("%s: unable to read "DFID
					       " ACL: rc = %d\n",
					       mdt_obd_name(info->mti_mdt),
					       PFID(mdt_object_fid(o)), rc);
				}
                        } else {
                                repbody->aclsize = rc;
                                repbody->valid |= OBD_MD_FLACL;
                                rc = 0;
                        }
                }
        }
#endif

	if (reqbody->valid & OBD_MD_FLMDSCAPA &&
	    info->mti_mdt->mdt_opts.mo_mds_capa &&
	    exp_connect_flags(info->mti_exp) & OBD_CONNECT_MDS_CAPA) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(pill, &RMF_CAPA1);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_MDS_DEFAULT;
                rc = mo_capa_get(env, next, capa, 0);
                if (rc)
                        RETURN(rc);
                repbody->valid |= OBD_MD_FLMDSCAPA;
        }

out:
        if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_GETATTR);

        RETURN(rc);
}

static int mdt_renew_capa(struct mdt_thread_info *info)
{
        struct mdt_object  *obj = info->mti_object;
        struct mdt_body    *body;
        struct lustre_capa *capa, *c;
        int rc;
        ENTRY;

        /* if object doesn't exist, or server has disabled capability,
         * return directly, client will find body->valid OBD_MD_FLOSSCAPA
         * flag not set.
         */
	if (!obj || !info->mti_mdt->mdt_opts.mo_oss_capa ||
	    !(exp_connect_flags(info->mti_exp) & OBD_CONNECT_OSS_CAPA))
		RETURN(0);

        body = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        c = req_capsule_client_get(info->mti_pill, &RMF_CAPA1);
        LASSERT(c);

        capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA2);
        LASSERT(capa);

        *capa = *c;
        rc = mo_capa_get(info->mti_env, mdt_object_child(obj), capa, 1);
        if (rc == 0)
                body->valid |= OBD_MD_FLOSSCAPA;
        RETURN(rc);
}

int mdt_getattr(struct mdt_thread_info *info)
{
        struct mdt_object       *obj = info->mti_object;
        struct req_capsule      *pill = info->mti_pill;
        struct mdt_body         *reqbody;
        struct mdt_body         *repbody;
        mode_t                   mode;
        int rc, rc2;
        ENTRY;

        reqbody = req_capsule_client_get(pill, &RMF_MDT_BODY);
        LASSERT(reqbody);

        if (reqbody->valid & OBD_MD_FLOSSCAPA) {
                rc = req_capsule_server_pack(pill);
                if (unlikely(rc))
                        RETURN(err_serious(rc));
                rc = mdt_renew_capa(info);
                GOTO(out_shrink, rc);
        }

        LASSERT(obj != NULL);
	LASSERT(lu_object_assert_exists(&obj->mot_obj));

	mode = lu_object_attr(&obj->mot_obj);

	/* Readlink */
	if (reqbody->valid & OBD_MD_LINKNAME) {
		/* No easy way to know how long is the symlink, but it cannot
		 * be more than PATH_MAX, so we allocate +1 */
		rc = PATH_MAX + 1;

	/* A special case for fs ROOT: getattr there might fetch
	 * default EA for entire fs, not just for this dir!
	 */
	} else if (lu_fid_eq(mdt_object_fid(obj),
			     &info->mti_mdt->mdt_md_root_fid) &&
		   (reqbody->valid & OBD_MD_FLDIREA) &&
		   (lustre_msg_get_opc(mdt_info_req(info)->rq_reqmsg) ==
								 MDS_GETATTR)) {
		/* Should the default strping be bigger, mdt_fix_reply
		 * will reallocate */
		rc = DEF_REP_MD_SIZE;
	} else {
		/* Hopefully no race in EA change for either file or directory?
		 */
		rc = mdt_attr_get_eabuf_size(info, obj);
	}

	if (rc < 0)
		GOTO(out_shrink, rc);

	/* old clients may not report needed easize, use max value then */
	req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, rc);

        rc = req_capsule_server_pack(pill);
        if (unlikely(rc != 0))
                RETURN(err_serious(rc));

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);
        LASSERT(repbody != NULL);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        if (reqbody->valid & OBD_MD_FLRMTPERM)
                rc = mdt_init_ucred(info, reqbody);
        else
                rc = mdt_check_ucred(info);
        if (unlikely(rc))
                GOTO(out_shrink, rc);

        info->mti_cross_ref = !!(reqbody->valid & OBD_MD_FLCROSSREF);

        /*
         * Don't check capability at all, because rename might getattr for
         * remote obj, and at that time no capability is available.
         */
        mdt_set_capainfo(info, 1, &reqbody->fid1, BYPASS_CAPA);
        rc = mdt_getattr_internal(info, obj, 0);
        if (reqbody->valid & OBD_MD_FLRMTPERM)
                mdt_exit_ucred(info);
        EXIT;
out_shrink:
        mdt_client_compatibility(info);
        rc2 = mdt_fix_reply(info);
        if (rc == 0)
                rc = rc2;
        return rc;
}

int mdt_is_subdir(struct mdt_thread_info *info)
{
        struct mdt_object     *o = info->mti_object;
        struct req_capsule    *pill = info->mti_pill;
        const struct mdt_body *body = info->mti_body;
        struct mdt_body       *repbody;
        int                    rc;
        ENTRY;

        LASSERT(o != NULL);

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);

	/*
	 * We save last checked parent fid to @repbody->fid1 for remote
	 * directory case.
	 */
	LASSERT(fid_is_sane(&body->fid2));
	LASSERT(mdt_object_exists(o) && !mdt_object_remote(o));
	rc = mdo_is_subdir(info->mti_env, mdt_object_child(o),
			   &body->fid2, &repbody->fid1);
	if (rc == 0 || rc == -EREMOTE)
		repbody->valid |= OBD_MD_FLID;

	RETURN(rc);
}

int mdt_swap_layouts(struct mdt_thread_info *info)
{
	struct ptlrpc_request	*req = mdt_info_req(info);
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

	if (req_capsule_get_size(info->mti_pill, &RMF_CAPA1, RCL_CLIENT))
		mdt_set_capainfo(info, 0, &info->mti_body->fid1,
				 req_capsule_client_get(info->mti_pill,
							&RMF_CAPA1));

	if (req_capsule_get_size(info->mti_pill, &RMF_CAPA2, RCL_CLIENT))
		mdt_set_capainfo(info, 1, &info->mti_body->fid2,
				 req_capsule_client_get(info->mti_pill,
							&RMF_CAPA2));

	o1 = info->mti_object;
	o = o2 = mdt_object_find(info->mti_env, info->mti_mdt,
				&info->mti_body->fid2);
	if (IS_ERR(o))
		GOTO(out, rc = PTR_ERR(o));

	if (mdt_object_remote(o) || !mdt_object_exists(o)) /* remote object */
		GOTO(put, rc = -ENOENT);

	rc = lu_fid_cmp(&info->mti_body->fid1, &info->mti_body->fid2);
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
			     MDS_INODELOCK_XATTR, MDT_LOCAL_LOCK);
	if (rc < 0)
		GOTO(put, rc);

	rc = mdt_object_lock(info, o2, lh2, MDS_INODELOCK_LAYOUT |
			     MDS_INODELOCK_XATTR, MDT_LOCAL_LOCK);
	if (rc < 0)
		GOTO(unlock1, rc);

	rc = mo_swap_layouts(info->mti_env, mdt_object_child(o1),
			     mdt_object_child(o2), msl->msl_flags);
	GOTO(unlock2, rc);
unlock2:
	mdt_object_unlock(info, o2, lh2, rc);
unlock1:
	mdt_object_unlock(info, o1, lh1, rc);
put:
	mdt_object_put(info->mti_env, o);
out:
	RETURN(rc);
}

static int mdt_raw_lookup(struct mdt_thread_info *info,
                          struct mdt_object *parent,
                          const struct lu_name *lname,
                          struct ldlm_reply *ldlm_rep)
{
        struct md_object *next = mdt_object_child(info->mti_object);
        const struct mdt_body *reqbody = info->mti_body;
        struct lu_fid *child_fid = &info->mti_tmp_fid1;
        struct mdt_body *repbody;
        int rc;
        ENTRY;

        if (reqbody->valid != OBD_MD_FLID)
                RETURN(0);

        LASSERT(!info->mti_cross_ref);

        /* Only got the fid of this obj by name */
        fid_zero(child_fid);
        rc = mdo_lookup(info->mti_env, next, lname, child_fid,
                        &info->mti_spec);
#if 0
        /* XXX is raw_lookup possible as intent operation? */
        if (rc != 0) {
                if (rc == -ENOENT)
                        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_NEG);
                RETURN(rc);
        } else
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
#endif
        if (rc == 0) {
                repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
                repbody->fid1 = *child_fid;
                repbody->valid = OBD_MD_FLID;
        }
        RETURN(1);
}

/*
 * UPDATE lock should be taken against parent, and be release before exit;
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
        struct md_object       *next      = mdt_object_child(parent);
        struct lu_fid          *child_fid = &info->mti_tmp_fid1;
        struct lu_name         *lname     = NULL;
        const char             *name      = NULL;
        int                     namelen   = 0;
        struct mdt_lock_handle *lhp       = NULL;
        struct ldlm_lock       *lock;
        struct ldlm_res_id     *res_id;
        int                     is_resent;
        int                     ma_need = 0;
        int                     rc;

        ENTRY;

        is_resent = lustre_handle_is_used(&lhc->mlh_reg_lh);
        LASSERT(ergo(is_resent,
                     lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT));

        LASSERT(parent != NULL);
        name = req_capsule_client_get(info->mti_pill, &RMF_NAME);
        if (name == NULL)
                RETURN(err_serious(-EFAULT));

        namelen = req_capsule_get_size(info->mti_pill, &RMF_NAME,
                                       RCL_CLIENT) - 1;
        if (!info->mti_cross_ref) {
                /*
                 * XXX: Check for "namelen == 0" is for getattr by fid
                 * (OBD_CONNECT_ATTRFID), otherwise do not allow empty name,
                 * that is the name must contain at least one character and
                 * the terminating '\0'
                 */
                if (namelen == 0) {
                        reqbody = req_capsule_client_get(info->mti_pill,
                                                         &RMF_MDT_BODY);
                        if (unlikely(reqbody == NULL))
                                RETURN(err_serious(-EFAULT));

                        if (unlikely(!fid_is_sane(&reqbody->fid2)))
                                RETURN(err_serious(-EINVAL));

                        name = NULL;
                        CDEBUG(D_INODE, "getattr with lock for "DFID"/"DFID", "
                               "ldlm_rep = %p\n",
                               PFID(mdt_object_fid(parent)),
                               PFID(&reqbody->fid2), ldlm_rep);
                } else {
                        lname = mdt_name(info->mti_env, (char *)name, namelen);
                        CDEBUG(D_INODE, "getattr with lock for "DFID"/%s, "
                               "ldlm_rep = %p\n", PFID(mdt_object_fid(parent)),
                               name, ldlm_rep);
                }
        }
        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_EXECD);

	if (unlikely(!mdt_object_exists(parent)) && lname) {
		LU_OBJECT_DEBUG(D_INODE, info->mti_env,
				&parent->mot_obj,
				"Parent doesn't exist!\n");
		RETURN(-ESTALE);
	} else if (!info->mti_cross_ref) {
		LASSERTF(!mdt_object_remote(parent),
			 "Parent "DFID" is on remote server\n",
			 PFID(mdt_object_fid(parent)));
	}
        if (lname) {
                rc = mdt_raw_lookup(info, parent, lname, ldlm_rep);
                if (rc != 0) {
                        if (rc > 0)
                                rc = 0;
                        RETURN(rc);
                }
        }

        if (info->mti_cross_ref) {
                /* Only getattr on the child. Parent is on another node. */
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
                child = parent;
                CDEBUG(D_INODE, "partial getattr_name child_fid = "DFID", "
                       "ldlm_rep=%p\n", PFID(mdt_object_fid(child)), ldlm_rep);

		rc = mdt_check_resent_lock(info, child, lhc);
		if (rc < 0) {
			RETURN(rc);
		} else if (rc > 0) {
                        mdt_lock_handle_init(lhc);
                        mdt_lock_reg_init(lhc, LCK_PR);

                        /*
                         * Object's name is on another MDS, no lookup lock is
                         * needed here but update is.
                         */
                        child_bits &= ~MDS_INODELOCK_LOOKUP;
			child_bits |= MDS_INODELOCK_PERM | MDS_INODELOCK_UPDATE;

			rc = mdt_object_lock(info, child, lhc, child_bits,
                                             MDT_LOCAL_LOCK);
                }
                if (rc == 0) {
                        /* Finally, we can get attr for child. */
			if (!mdt_object_exists(child)) {
				LU_OBJECT_DEBUG(D_INFO, info->mti_env,
						&child->mot_obj,
					     "remote object doesn't exist.\n");
                                mdt_object_unlock(info, child, lhc, 1);
				RETURN(-ENOENT);
			}

                        mdt_set_capainfo(info, 0, mdt_object_fid(child),
                                         BYPASS_CAPA);
                        rc = mdt_getattr_internal(info, child, 0);
                        if (unlikely(rc != 0))
                                mdt_object_unlock(info, child, lhc, 1);
                }
                RETURN(rc);
        }

        if (lname) {
                /* step 1: lock parent only if parent is a directory */
		if (S_ISDIR(lu_object_attr(&parent->mot_obj))) {
                        lhp = &info->mti_lh[MDT_LH_PARENT];
                        mdt_lock_pdo_init(lhp, LCK_PR, name, namelen);
                        rc = mdt_object_lock(info, parent, lhp,
                                             MDS_INODELOCK_UPDATE,
                                             MDT_LOCAL_LOCK);
                        if (unlikely(rc != 0))
                                RETURN(rc);
                }

                /* step 2: lookup child's fid by name */
                fid_zero(child_fid);
                rc = mdo_lookup(info->mti_env, next, lname, child_fid,
                                &info->mti_spec);

                if (rc != 0) {
                        if (rc == -ENOENT)
                                mdt_set_disposition(info, ldlm_rep,
                                                    DISP_LOOKUP_NEG);
                        GOTO(out_parent, rc);
                } else
                        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
        } else {
                *child_fid = reqbody->fid2;
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
        }

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

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RESEND, obd_timeout*2);
	rc = mdt_check_resent_lock(info, child, lhc);
	if (rc < 0) {
		GOTO(out_child, rc);
	} else if (rc > 0) {
		bool try_layout = false;

		mdt_lock_handle_init(lhc);
		mdt_lock_reg_init(lhc, LCK_PR);

		if (!mdt_object_exists(child)) {
			LU_OBJECT_DEBUG(D_INODE, info->mti_env,
					&child->mot_obj,
					"Object doesn't exist!\n");
			GOTO(out_child, rc = -ENOENT);
		}

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
		    ldlm_rep != NULL) {
			/* try to grant layout lock for regular file. */
			try_layout = true;
		}

		rc = 0;
		if (try_layout) {
			child_bits |= MDS_INODELOCK_LAYOUT;
			/* try layout lock, it may fail to be granted due to
			 * contention at LOOKUP or UPDATE */
			if (!mdt_object_lock_try(info, child, lhc, child_bits,
						 MDT_CROSS_LOCK)) {
				child_bits &= ~MDS_INODELOCK_LAYOUT;
				LASSERT(child_bits != 0);
				rc = mdt_object_lock(info, child, lhc,
						child_bits, MDT_CROSS_LOCK);
			} else {
				ma_need |= MA_LOV;
			}
		} else {
			rc = mdt_object_lock(info, child, lhc, child_bits,
						MDT_CROSS_LOCK);
		}
                if (unlikely(rc != 0))
                        GOTO(out_child, rc);
        }

        lock = ldlm_handle2lock(&lhc->mlh_reg_lh);
        /* Get MA_SOM attributes if update lock is given. */
        if (lock &&
            lock->l_policy_data.l_inodebits.bits & MDS_INODELOCK_UPDATE &&
            S_ISREG(lu_object_attr(&mdt_object_child(child)->mo_lu)))
                ma_need |= MA_SOM;

        /* finally, we can get attr for child. */
        mdt_set_capainfo(info, 1, child_fid, BYPASS_CAPA);
        rc = mdt_getattr_internal(info, child, ma_need);
        if (unlikely(rc != 0)) {
                mdt_object_unlock(info, child, lhc, 1);
	} else if (lock) {
		/* Debugging code. */
		res_id = &lock->l_resource->lr_name;
		LDLM_DEBUG(lock, "Returning lock to client");
		LASSERTF(fid_res_name_eq(mdt_object_fid(child),
					 &lock->l_resource->lr_name),
			 "Lock res_id: "DLDLMRES", fid: "DFID"\n",
			 PLDLMRES(lock->l_resource),
			 PFID(mdt_object_fid(child)));
		if (mdt_object_exists(child) && !mdt_object_remote(child))
			mdt_pack_size2body(info, child);
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
int mdt_getattr_name(struct mdt_thread_info *info)
{
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_CHILD];
        struct mdt_body        *reqbody;
        struct mdt_body        *repbody;
        int rc, rc2;
        ENTRY;

        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(reqbody != NULL);
        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(repbody != NULL);

        info->mti_cross_ref = !!(reqbody->valid & OBD_MD_FLCROSSREF);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        rc = mdt_init_ucred(info, reqbody);
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
        return rc;
}

static int mdt_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg);

int mdt_set_info(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        char *key;
        void *val;
        int keylen, vallen, rc = 0;
        ENTRY;

        rc = req_capsule_server_pack(info->mti_pill);
        if (rc)
                RETURN(rc);

        key = req_capsule_client_get(info->mti_pill, &RMF_SETINFO_KEY);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }

        keylen = req_capsule_get_size(info->mti_pill, &RMF_SETINFO_KEY,
                                      RCL_CLIENT);

        val = req_capsule_client_get(info->mti_pill, &RMF_SETINFO_VAL);
        if (val == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info val");
                RETURN(-EFAULT);
        }

        vallen = req_capsule_get_size(info->mti_pill, &RMF_SETINFO_VAL,
                                      RCL_CLIENT);

        /* Swab any part of val you need to here */
        if (KEY_IS(KEY_READ_ONLY)) {
                req->rq_status = 0;
                lustre_msg_set_status(req->rq_repmsg, 0);

		spin_lock(&req->rq_export->exp_lock);
		if (*(__u32 *)val)
			*exp_connect_flags_ptr(req->rq_export) |=
				OBD_CONNECT_RDONLY;
		else
			*exp_connect_flags_ptr(req->rq_export) &=
				~OBD_CONNECT_RDONLY;
		spin_unlock(&req->rq_export->exp_lock);

        } else if (KEY_IS(KEY_CHANGELOG_CLEAR)) {
                struct changelog_setinfo *cs =
                        (struct changelog_setinfo *)val;
                if (vallen != sizeof(*cs)) {
                        CERROR("Bad changelog_clear setinfo size %d\n", vallen);
                        RETURN(-EINVAL);
                }
                if (ptlrpc_req_need_swab(req)) {
                        __swab64s(&cs->cs_recno);
                        __swab32s(&cs->cs_id);
                }

                rc = mdt_iocontrol(OBD_IOC_CHANGELOG_CLEAR, info->mti_exp,
                                   vallen, val, NULL);
                lustre_msg_set_status(req->rq_repmsg, rc);

        } else {
                RETURN(-EINVAL);
        }
        RETURN(0);
}

int mdt_connect_check_sptlrpc(struct mdt_device *mdt, struct obd_export *exp,
			      struct ptlrpc_request *req);

/**
 * Top-level handler for MDT connection requests.
 */
int mdt_connect(struct mdt_thread_info *info)
{
	int rc;
	struct obd_connect_data *reply;
	struct obd_export *exp;
	struct ptlrpc_request *req = mdt_info_req(info);

	ENTRY;

	rc = target_handle_connect(req);
	if (rc != 0)
		RETURN(err_serious(rc));

	LASSERT(req->rq_export != NULL);
	exp = req->rq_export;
	info->mti_exp = exp;
	info->mti_mdt = mdt_dev(exp->exp_obd->obd_lu_dev);
	rc = mdt_init_sec_level(info);
	if (rc != 0)
		GOTO(err, rc);

	rc = mdt_connect_check_sptlrpc(info->mti_mdt, exp, req);
	if (rc)
		GOTO(err, rc);

	/* To avoid exposing partially initialized connection flags, changes up
	 * to this point have been staged in reply->ocd_connect_flags. Now that
	 * connection handling has completed successfully, atomically update
	 * the connect flags in the shared export data structure. LU-1623 */
	reply = req_capsule_server_get(info->mti_pill, &RMF_CONNECT_DATA);
	spin_lock(&exp->exp_lock);
	*exp_connect_flags_ptr(exp) = reply->ocd_connect_flags;
	exp->exp_mdt_data.med_ibits_known = reply->ocd_ibits_known;
	exp->exp_connect_data.ocd_brw_size = reply->ocd_brw_size;
	spin_unlock(&exp->exp_lock);

	rc = mdt_init_idmap(info);
	if (rc != 0)
		GOTO(err, rc);
	RETURN(0);
err:
	obd_disconnect(class_export_get(req->rq_export));
	return rc;
}

int mdt_disconnect(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        rc = target_handle_disconnect(mdt_info_req(info));
        if (rc)
                rc = err_serious(rc);
        RETURN(rc);
}

static int mdt_sendpage(struct mdt_thread_info *info,
                        struct lu_rdpg *rdpg, int nob)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct obd_export       *exp = req->rq_export;
        struct ptlrpc_bulk_desc *desc;
        struct l_wait_info      *lwi = &info->mti_u.rdpg.mti_wait_info;
        int                      tmpcount;
        int                      tmpsize;
        int                      i;
        int                      rc;
        ENTRY;

	desc = ptlrpc_prep_bulk_exp(req, rdpg->rp_npages, 1, BULK_PUT_SOURCE,
				    MDS_BULK_PORTAL);
	if (desc == NULL)
		RETURN(-ENOMEM);

	if (!(exp_connect_flags(exp) & OBD_CONNECT_BRW_SIZE))
		/* old client requires reply size in it's PAGE_SIZE,
		 * which is rdpg->rp_count */
		nob = rdpg->rp_count;

	for (i = 0, tmpcount = nob; i < rdpg->rp_npages && tmpcount > 0;
	     i++, tmpcount -= tmpsize) {
		tmpsize = min_t(int, tmpcount, PAGE_CACHE_SIZE);
		ptlrpc_prep_bulk_page_pin(desc, rdpg->rp_pages[i], 0, tmpsize);
        }

        LASSERT(desc->bd_nob == nob);
        rc = target_bulk_io(exp, desc, lwi);
	ptlrpc_free_bulk_pin(desc);
        RETURN(rc);
}

int mdt_readpage(struct mdt_thread_info *info)
{
        struct mdt_object *object = info->mti_object;
        struct lu_rdpg    *rdpg = &info->mti_u.rdpg.mti_rdpg;
        struct mdt_body   *reqbody;
        struct mdt_body   *repbody;
        int                rc;
        int                i;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK))
                RETURN(err_serious(-ENOMEM));

        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL || repbody == NULL)
                RETURN(err_serious(-EFAULT));

        /*
         * prepare @rdpg before calling lower layers and transfer itself. Here
         * reqbody->size contains offset of where to start to read and
         * reqbody->nlink contains number bytes to read.
         */
        rdpg->rp_hash = reqbody->size;
        if (rdpg->rp_hash != reqbody->size) {
                CERROR("Invalid hash: "LPX64" != "LPX64"\n",
                       rdpg->rp_hash, reqbody->size);
                RETURN(-EFAULT);
        }

        rdpg->rp_attrs = reqbody->mode;
	if (exp_connect_flags(info->mti_exp) & OBD_CONNECT_64BITHASH)
		rdpg->rp_attrs |= LUDA_64BITHASH;
	rdpg->rp_count  = min_t(unsigned int, reqbody->nlink,
				exp_max_brw_size(info->mti_exp));
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
        rc = mo_readpage(info->mti_env, mdt_object_child(object), rdpg);
        if (rc < 0)
                GOTO(free_rdpg, rc);

        /* send pages to client */
        rc = mdt_sendpage(info, rdpg, rc);

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
        struct req_capsule      *pill = info->mti_pill;
        struct mdt_body         *repbody;
        int                      rc = 0, rc2;
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
                repbody->eadatasize = 0;
                repbody->aclsize = 0;
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

        if (mdt_check_resent(info, mdt_reconstruct, lhc)) {
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

static long mdt_reint_opcode(struct mdt_thread_info *info,
			     const struct req_format **fmt)
{
	struct mdt_rec_reint *rec;
	long opc;

	rec = req_capsule_client_get(info->mti_pill, &RMF_REC_REINT);
	if (rec != NULL) {
		opc = rec->rr_opcode;
		DEBUG_REQ(D_INODE, mdt_info_req(info), "reint opt = %ld", opc);
		if (opc < REINT_MAX && fmt[opc] != NULL)
			req_capsule_extend(info->mti_pill, fmt[opc]);
		else {
			CERROR("%s: Unsupported opcode '%ld' from client '%s': "
			       "rc = %d\n", mdt_obd_name(info->mti_mdt), opc,
			       info->mti_mdt->mdt_ldlm_client->cli_name,
			       -EFAULT);
			opc = err_serious(-EFAULT);
		}
	} else {
		opc = err_serious(-EFAULT);
	}
	return opc;
}

int mdt_reint(struct mdt_thread_info *info)
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
		[REINT_RMENTRY] = &RQF_MDS_REINT_UNLINK
	};

        ENTRY;

        opc = mdt_reint_opcode(info, reint_fmts);
        if (opc >= 0) {
                /*
                 * No lock possible here from client to pass it to reint code
                 * path.
                 */
                rc = mdt_reint_internal(info, NULL, opc);
        } else {
                rc = opc;
        }

        info->mti_fail_id = OBD_FAIL_MDS_REINT_NET_REP;
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
                CWARN("Non existing object  "DFID"!\n",
                      PFID(mdt_object_fid(info->mti_object)));
                RETURN(-ESTALE);
        }
        next = mdt_object_child(info->mti_object);
        rc = mo_object_sync(info->mti_env, next);

        RETURN(rc);
}

int mdt_sync(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct req_capsule *pill = info->mti_pill;
        struct mdt_body *body;
        int rc;
        ENTRY;

        /* The fid may be zero, so we req_capsule_set manually */
        req_capsule_set(pill, &RQF_MDS_SYNC);

        body = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (body == NULL)
                RETURN(err_serious(-EINVAL));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SYNC_PACK))
                RETURN(err_serious(-ENOMEM));

        if (fid_seq(&body->fid1) == 0) {
                /* sync the whole device */
                rc = req_capsule_server_pack(pill);
                if (rc == 0)
                        rc = mdt_device_sync(info->mti_env, info->mti_mdt);
                else
                        rc = err_serious(rc);
        } else {
                /* sync an object */
                rc = mdt_unpack_req_pack_rep(info, HABEO_CORPUS|HABEO_REFERO);
                if (rc == 0) {
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
                } else
                        rc = err_serious(rc);
        }
        if (rc == 0)
		mdt_counter_incr(req, LPROC_MDT_SYNC);

        RETURN(rc);
}

/*
 * Quotacheck handler.
 * in-kernel quotacheck isn't supported any more.
 */
int mdt_quotacheck(struct mdt_thread_info *info)
{
	struct obd_quotactl	*oqctl;
	int			 rc;
	ENTRY;

	oqctl = req_capsule_client_get(info->mti_pill, &RMF_OBD_QUOTACTL);
	if (oqctl == NULL)
		RETURN(err_serious(-EPROTO));

	rc = req_capsule_server_pack(info->mti_pill);
	if (rc)
		RETURN(err_serious(rc));

	/* deprecated, not used any more */
	RETURN(-EOPNOTSUPP);
}

/*
 * Handle quota control requests to consult current usage/limit, but also
 * to configure quota enforcement
 */
int mdt_quotactl(struct mdt_thread_info *info)
{
	struct obd_export	*exp  = info->mti_exp;
	struct req_capsule	*pill = info->mti_pill;
	struct obd_quotactl	*oqctl, *repoqc;
	int			 id, rc;
	struct lu_device	*qmt = info->mti_mdt->mdt_qmt_dev;
	ENTRY;

	oqctl = req_capsule_client_get(pill, &RMF_OBD_QUOTACTL);
	if (oqctl == NULL)
		RETURN(err_serious(-EPROTO));

	rc = req_capsule_server_pack(pill);
	if (rc)
		RETURN(err_serious(rc));

	switch (oqctl->qc_cmd) {
	case Q_QUOTACHECK:
	case LUSTRE_Q_INVALIDATE:
	case LUSTRE_Q_FINVALIDATE:
	case Q_QUOTAON:
	case Q_QUOTAOFF:
	case Q_INITQUOTA:
		/* deprecated, not used any more */
		RETURN(-EOPNOTSUPP);
		/* master quotactl */
	case Q_GETINFO:
	case Q_SETINFO:
	case Q_SETQUOTA:
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

		idmap = mdt_req2med(mdt_info_req(info))->med_idmap;

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
		rc = qmt_hdls.qmth_quotactl(info->mti_env, qmt, oqctl);
		break;

	case Q_GETOINFO:
	case Q_GETOQUOTA:
		/* slave quotactl */
		rc = lquotactl_slv(info->mti_env, info->mti_mdt->mdt_bottom,
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

/*
 * OBD PING and other handlers.
 */
int mdt_obd_ping(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        req_capsule_set(info->mti_pill, &RQF_OBD_PING);

        rc = target_handle_ping(mdt_info_req(info));
        if (rc < 0)
                rc = err_serious(rc);
        RETURN(rc);
}

/*
 * OBD_IDX_READ handler
 */
int mdt_obd_idx_read(struct mdt_thread_info *info)
{
	struct mdt_device	*mdt = info->mti_mdt;
	struct lu_rdpg		*rdpg = &info->mti_u.rdpg.mti_rdpg;
	struct idx_info		*req_ii, *rep_ii;
	int			 rc, i;
	ENTRY;

	memset(rdpg, 0, sizeof(*rdpg));
	req_capsule_set(info->mti_pill, &RQF_OBD_IDX_READ);

	/* extract idx_info buffer from request & reply */
	req_ii = req_capsule_client_get(info->mti_pill, &RMF_IDX_INFO);
	if (req_ii == NULL || req_ii->ii_magic != IDX_INFO_MAGIC)
		RETURN(err_serious(-EPROTO));

	rc = req_capsule_server_pack(info->mti_pill);
	if (rc)
		RETURN(err_serious(rc));

	rep_ii = req_capsule_server_get(info->mti_pill, &RMF_IDX_INFO);
	if (rep_ii == NULL)
		RETURN(err_serious(-EFAULT));
	rep_ii->ii_magic = IDX_INFO_MAGIC;

	/* extract hash to start with */
	rdpg->rp_hash = req_ii->ii_hash_start;

	/* extract requested attributes */
	rdpg->rp_attrs = req_ii->ii_attrs;

	/* check that fid packed in request is valid and supported */
	if (!fid_is_sane(&req_ii->ii_fid))
		RETURN(-EINVAL);
	rep_ii->ii_fid = req_ii->ii_fid;

	/* copy flags */
	rep_ii->ii_flags = req_ii->ii_flags;

	/* compute number of pages to allocate, ii_count is the number of 4KB
	 * containers */
	if (req_ii->ii_count <= 0)
		GOTO(out, rc = -EFAULT);
	rdpg->rp_count = min_t(unsigned int, req_ii->ii_count << LU_PAGE_SHIFT,
			       exp_max_brw_size(info->mti_exp));
	rdpg->rp_npages = (rdpg->rp_count + PAGE_CACHE_SIZE - 1) >>
				PAGE_CACHE_SHIFT;

	/* allocate pages to store the containers */
	OBD_ALLOC(rdpg->rp_pages, rdpg->rp_npages * sizeof(rdpg->rp_pages[0]));
	if (rdpg->rp_pages == NULL)
		GOTO(out, rc = -ENOMEM);
	for (i = 0; i < rdpg->rp_npages; i++) {
		rdpg->rp_pages[i] = alloc_page(GFP_IOFS);
		if (rdpg->rp_pages[i] == NULL)
			GOTO(out, rc = -ENOMEM);
	}

	/* populate pages with key/record pairs */
	rc = dt_index_read(info->mti_env, mdt->mdt_bottom, rep_ii, rdpg);
	if (rc < 0)
		GOTO(out, rc);

	LASSERTF(rc <= rdpg->rp_count, "dt_index_read() returned more than "
		 "asked %d > %d\n", rc, rdpg->rp_count);

	/* send pages to client */
	rc = mdt_sendpage(info, rdpg, rc);

	GOTO(out, rc);
out:
	if (rdpg->rp_pages) {
		for (i = 0; i < rdpg->rp_npages; i++)
			if (rdpg->rp_pages[i])
				__free_page(rdpg->rp_pages[i]);
		OBD_FREE(rdpg->rp_pages,
			 rdpg->rp_npages * sizeof(rdpg->rp_pages[0]));
	}
	return rc;
}

int mdt_obd_log_cancel(struct mdt_thread_info *info)
{
        return err_serious(-EOPNOTSUPP);
}

int mdt_obd_qc_callback(struct mdt_thread_info *info)
{
        return err_serious(-EOPNOTSUPP);
}

/*
 * LLOG handlers.
 */

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

int mdt_llog_create(struct mdt_thread_info *info)
{
	int rc;

	req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_CREATE);
	rc = llog_origin_handle_open(mdt_info_req(info));
	return (rc < 0 ? err_serious(rc) : rc);
}

int mdt_llog_destroy(struct mdt_thread_info *info)
{
        int rc;

        req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_DESTROY);
        rc = llog_origin_handle_destroy(mdt_info_req(info));
        return (rc < 0 ? err_serious(rc) : rc);
}

int mdt_llog_read_header(struct mdt_thread_info *info)
{
        int rc;

        req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_READ_HEADER);
        rc = llog_origin_handle_read_header(mdt_info_req(info));
        return (rc < 0 ? err_serious(rc) : rc);
}

int mdt_llog_next_block(struct mdt_thread_info *info)
{
        int rc;

        req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_NEXT_BLOCK);
        rc = llog_origin_handle_next_block(mdt_info_req(info));
        return (rc < 0 ? err_serious(rc) : rc);
}

int mdt_llog_prev_block(struct mdt_thread_info *info)
{
        int rc;

        req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_PREV_BLOCK);
        rc = llog_origin_handle_prev_block(mdt_info_req(info));
        return (rc < 0 ? err_serious(rc) : rc);
}


/*
 * DLM handlers.
 */

static struct ldlm_callback_suite cbs = {
	.lcs_completion	= ldlm_server_completion_ast,
	.lcs_blocking	= ldlm_server_blocking_ast,
	.lcs_glimpse	= ldlm_server_glimpse_ast
};

int mdt_enqueue(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req;
        int rc;

        /*
         * info->mti_dlm_req already contains swapped and (if necessary)
         * converted dlm request.
         */
        LASSERT(info->mti_dlm_req != NULL);

        req = mdt_info_req(info);
        rc = ldlm_handle_enqueue0(info->mti_mdt->mdt_namespace,
                                  req, info->mti_dlm_req, &cbs);
        info->mti_fail_id = OBD_FAIL_LDLM_REPLY;
        return rc ? err_serious(rc) : req->rq_status;
}

int mdt_convert(struct mdt_thread_info *info)
{
        int rc;
        struct ptlrpc_request *req;

        LASSERT(info->mti_dlm_req);
        req = mdt_info_req(info);
        rc = ldlm_handle_convert0(req, info->mti_dlm_req);
        return rc ? err_serious(rc) : req->rq_status;
}

int mdt_bl_callback(struct mdt_thread_info *info)
{
        CERROR("bl callbacks should not happen on MDS\n");
        LBUG();
        return err_serious(-EOPNOTSUPP);
}

int mdt_cp_callback(struct mdt_thread_info *info)
{
        CERROR("cp callbacks should not happen on MDS\n");
        LBUG();
        return err_serious(-EOPNOTSUPP);
}

/*
 * sec context handlers
 */
int mdt_sec_ctx_handle(struct mdt_thread_info *info)
{
        int rc;

        rc = mdt_handle_idmap(info);

        if (unlikely(rc)) {
                struct ptlrpc_request *req = mdt_info_req(info);
                __u32                  opc;

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
int mdt_quota_dqacq(struct mdt_thread_info *info)
{
	struct lu_device	*qmt = info->mti_mdt->mdt_qmt_dev;
	int			 rc;
	ENTRY;

	if (qmt == NULL)
		RETURN(err_serious(-EOPNOTSUPP));

	rc = qmt_hdls.qmth_dqacq(info->mti_env, qmt, mdt_info_req(info));
	RETURN(rc);
}

static struct mdt_object *mdt_obj(struct lu_object *o)
{
	LASSERT(lu_device_is_mdt(o->lo_dev));
	return container_of0(o, struct mdt_object, mot_obj);
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

        rc = dt->dd_ops->dt_commit_async(env, dt);
        if (unlikely(rc != 0))
                CWARN("async commit start failed with rc = %d", rc);
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
        if (mdt_cos_is_enabled(mdt) &&
            lock->l_req_mode & (LCK_PW | LCK_EX) &&
            lock->l_blocking_lock != NULL &&
            lock->l_client_cookie != lock->l_blocking_lock->l_client_cookie) {
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
                        CWARN("lu_env initialization failed with rc = %d,"
                              "cannot start asynchronous commit\n", rc);
                else
                        mdt_device_commit_async(&env, mdt);
                lu_env_fini(&env);
        }
        RETURN(rc);
}

int mdt_md_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
			void *data, int flag)
{
	struct lustre_handle lockh;
	int		  rc;

	switch (flag) {
	case LDLM_CB_BLOCKING:
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		if (rc < 0) {
			CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
			RETURN(rc);
		}
		break;
	case LDLM_CB_CANCELING:
		LDLM_DEBUG(lock, "Revoke remote lock\n");
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
	if (lustre_handle_is_used(&lhc->mlh_reg_lh)) {
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

int mdt_remote_object_lock(struct mdt_thread_info *mti,
			   struct mdt_object *o, struct lustre_handle *lh,
			   ldlm_mode_t mode, __u64 ibits)
{
	struct ldlm_enqueue_info *einfo = &mti->mti_einfo;
	ldlm_policy_data_t *policy = &mti->mti_policy;
	int rc = 0;
	ENTRY;

	LASSERT(mdt_object_remote(o));

	LASSERT(ibits & MDS_INODELOCK_UPDATE);

	memset(einfo, 0, sizeof(*einfo));
	einfo->ei_type = LDLM_IBITS;
	einfo->ei_mode = mode;
	einfo->ei_cb_bl = mdt_md_blocking_ast;
	einfo->ei_cb_cp = ldlm_completion_ast;

	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = ibits;

	rc = mo_object_lock(mti->mti_env, mdt_object_child(o), lh, einfo,
			    policy);
	RETURN(rc);
}

static int mdt_object_lock0(struct mdt_thread_info *info, struct mdt_object *o,
			    struct mdt_lock_handle *lh, __u64 ibits,
			    bool nonblock, int locality)
{
        struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
        ldlm_policy_data_t *policy = &info->mti_policy;
        struct ldlm_res_id *res_id = &info->mti_res_id;
	__u64 dlmflags;
        int rc;
        ENTRY;

        LASSERT(!lustre_handle_is_used(&lh->mlh_reg_lh));
        LASSERT(!lustre_handle_is_used(&lh->mlh_pdo_lh));
        LASSERT(lh->mlh_reg_mode != LCK_MINMODE);
        LASSERT(lh->mlh_type != MDT_NUL_LOCK);

	if (mdt_object_remote(o)) {
                if (locality == MDT_CROSS_LOCK) {
			ibits &= ~(MDS_INODELOCK_UPDATE | MDS_INODELOCK_PERM);
                        ibits |= MDS_INODELOCK_LOOKUP;
                } else {
			LASSERTF(!(ibits &
				  (MDS_INODELOCK_UPDATE | MDS_INODELOCK_PERM)),
				"%s: wrong bit "LPX64" for remote obj "DFID"\n",
				mdt_obd_name(info->mti_mdt), ibits,
				PFID(mdt_object_fid(o)));
                        LASSERT(ibits & MDS_INODELOCK_LOOKUP);
                }
                /* No PDO lock on remote object */
                LASSERT(lh->mlh_type != MDT_PDO_LOCK);
        }

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

	dlmflags = LDLM_FL_ATOMIC_CB;
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
                        if (unlikely(rc))
                                RETURN(rc);
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
        if (rc)
                mdt_object_unlock(info, o, lh, 1);
        else if (unlikely(OBD_FAIL_PRECHECK(OBD_FAIL_MDS_PDO_LOCK)) &&
                 lh->mlh_pdo_hash != 0 &&
                 (lh->mlh_reg_mode == LCK_PW || lh->mlh_reg_mode == LCK_EX)) {
                OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_PDO_LOCK, 15);
        }

        RETURN(rc);
}

int mdt_object_lock(struct mdt_thread_info *info, struct mdt_object *o,
		    struct mdt_lock_handle *lh, __u64 ibits, int locality)
{
	return mdt_object_lock0(info, o, lh, ibits, false, locality);
}

int mdt_object_lock_try(struct mdt_thread_info *info, struct mdt_object *o,
		        struct mdt_lock_handle *lh, __u64 ibits, int locality)
{
	struct mdt_lock_handle tmp = *lh;
	int rc;

	rc = mdt_object_lock0(info, o, &tmp, ibits, true, locality);
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
static
void mdt_save_lock(struct mdt_thread_info *info, struct lustre_handle *h,
                   ldlm_mode_t mode, int decref)
{
        ENTRY;

        if (lustre_handle_is_used(h)) {
                if (decref || !info->mti_has_trans ||
                    !(mode & (LCK_PW | LCK_EX))){
                        mdt_fid_unlock(h, mode);
                } else {
                        struct mdt_device *mdt = info->mti_mdt;
                        struct ldlm_lock *lock = ldlm_handle2lock(h);
                        struct ptlrpc_request *req = mdt_info_req(info);
                        int no_ack = 0;

                        LASSERTF(lock != NULL, "no lock for cookie "LPX64"\n",
                                 h->cookie);
			/* there is no request if mdt_object_unlock() is called
			 * from mdt_export_cleanup()->mdt_add_dirty_flag() */
			if (likely(req != NULL)) {
				CDEBUG(D_HA, "request = %p reply state = %p"
				       " transno = "LPD64"\n", req,
				       req->rq_reply_state, req->rq_transno);
				if (mdt_cos_is_enabled(mdt)) {
					no_ack = 1;
					ldlm_lock_downgrade(lock, LCK_COS);
					mode = LCK_COS;
				}
				ptlrpc_save_lock(req, h, mode, no_ack);
			} else {
				ldlm_lock_decref(h, mode);
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
 * Unlock mdt object.
 *
 * Immeditely release the regular lock and the PDO lock or save the
 * lock in reqeuest and keep them referenced until client ACK or
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

	if (lustre_handle_is_used(&lh->mlh_rreg_lh))
		ldlm_lock_decref(&lh->mlh_rreg_lh, lh->mlh_rreg_mode);

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

                rc = mdt_object_lock(info, o, lh, ibits,
                                     MDT_LOCAL_LOCK);
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

struct mdt_handler *mdt_handler_find(__u32 opc, struct mdt_opc_slice *supported)
{
        struct mdt_opc_slice *s;
        struct mdt_handler   *h;

        h = NULL;
        for (s = supported; s->mos_hs != NULL; s++) {
                if (s->mos_opc_start <= opc && opc < s->mos_opc_end) {
                        h = s->mos_hs + (opc - s->mos_opc_start);
                        if (likely(h->mh_opc != 0))
                                LASSERTF(h->mh_opc == opc,
                                         "opcode mismatch %d != %d\n",
                                         h->mh_opc, opc);
                        else
                                h = NULL; /* unsupported opc */
                        break;
                }
        }
        return h;
}

static int mdt_lock_resname_compat(struct mdt_device *m,
                                   struct ldlm_request *req)
{
        /* XXX something... later. */
        return 0;
}

static int mdt_lock_reply_compat(struct mdt_device *m, struct ldlm_reply *rep)
{
        /* XXX something... later. */
        return 0;
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

        if (!(body->valid & OBD_MD_FLID))
                RETURN(0);

        if (!fid_is_sane(&body->fid1)) {
                CERROR("Invalid fid: "DFID"\n", PFID(&body->fid1));
                RETURN(-EINVAL);
        }

        /*
         * Do not get size or any capa fields before we check that request
         * contains capa actually. There are some requests which do not, for
         * instance MDS_IS_SUBDIR.
         */
        if (req_capsule_has_field(pill, &RMF_CAPA1, RCL_CLIENT) &&
            req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, &body->fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));

        obj = mdt_object_find(env, info->mti_mdt, &body->fid1);
        if (!IS_ERR(obj)) {
                if ((flags & HABEO_CORPUS) &&
                    !mdt_object_exists(obj)) {
                        mdt_object_put(env, obj);
                        /* for capability renew ENOENT will be handled in
                         * mdt_renew_capa */
                        if (body->valid & OBD_MD_FLOSSCAPA)
                                rc = 0;
                        else
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

static int mdt_init_capa_ctxt(const struct lu_env *env, struct mdt_device *m)
{
        struct md_device *next = m->mdt_child;

        return next->md_ops->mdo_init_capa_ctxt(env, next,
                                                m->mdt_opts.mo_mds_capa,
                                                m->mdt_capa_timeout,
                                                m->mdt_capa_alg,
                                                m->mdt_capa_keys);
}

/*
 * Invoke handler for this request opc. Also do necessary preprocessing
 * (according to handler ->mh_flags), and post-processing (setting of
 * ->last_{xid,committed}).
 */
static int mdt_req_handle(struct mdt_thread_info *info,
                          struct mdt_handler *h, struct ptlrpc_request *req)
{
        int   rc, serious = 0;
        __u32 flags;

        ENTRY;

        LASSERT(h->mh_act != NULL);
        LASSERT(h->mh_opc == lustre_msg_get_opc(req->rq_reqmsg));
        LASSERT(current->journal_info == NULL);

        /*
         * Checking for various OBD_FAIL_$PREF_$OPC_NET codes. _Do_ not try
         * to put same checks into handlers like mdt_close(), mdt_reint(),
         * etc., without talking to mdt authors first. Checking same thing
         * there again is useless and returning 0 error without packing reply
         * is buggy! Handlers either pack reply or return error.
         *
         * We return 0 here and do not send any reply in order to emulate
         * network failure. Do not send any reply in case any of NET related
         * fail_id has occured.
         */
        if (OBD_FAIL_CHECK_ORSET(h->mh_fail_id, OBD_FAIL_ONCE))
                RETURN(0);

        rc = 0;
        flags = h->mh_flags;
        LASSERT(ergo(flags & (HABEO_CORPUS|HABEO_REFERO), h->mh_fmt != NULL));

        if (h->mh_fmt != NULL) {
                req_capsule_set(info->mti_pill, h->mh_fmt);
                rc = mdt_unpack_req_pack_rep(info, flags);
        }

	if (rc == 0 && flags & MUTABOR &&
	    exp_connect_flags(req->rq_export) & OBD_CONNECT_RDONLY)
		/* should it be rq_status? */
		rc = -EROFS;

        if (rc == 0 && flags & HABEO_CLAVIS) {
                struct ldlm_request *dlm_req;

                LASSERT(h->mh_fmt != NULL);

                dlm_req = req_capsule_client_get(info->mti_pill, &RMF_DLM_REQ);
                if (dlm_req != NULL) {
                        if (unlikely(dlm_req->lock_desc.l_resource.lr_type ==
                                        LDLM_IBITS &&
                                     dlm_req->lock_desc.l_policy_data.\
                                        l_inodebits.bits == 0)) {
                                /*
                                 * Lock without inodebits makes no sense and
                                 * will oops later in ldlm. If client miss to
                                 * set such bits, do not trigger ASSERTION.
                                 *
                                 * For liblustre flock case, it maybe zero.
                                 */
                                rc = -EPROTO;
                        } else {
				if (info->mti_mdt &&
				    info->mti_mdt->mdt_opts.mo_compat_resname)
                                        rc = mdt_lock_resname_compat(
                                                                info->mti_mdt,
                                                                dlm_req);
                                info->mti_dlm_req = dlm_req;
                        }
                } else {
                        rc = -EFAULT;
                }
        }

        /* capability setting changed via /proc, needs reinitialize ctxt */
        if (info->mti_mdt && info->mti_mdt->mdt_capa_conf) {
                mdt_init_capa_ctxt(info->mti_env, info->mti_mdt);
                info->mti_mdt->mdt_capa_conf = 0;
        }

        if (likely(rc == 0)) {
                /*
                 * Process request, there can be two types of rc:
                 * 1) errors with msg unpack/pack, other failures outside the
                 * operation itself. This is counted as serious errors;
                 * 2) errors during fs operation, should be placed in rq_status
                 * only
                 */
                rc = h->mh_act(info);
                if (rc == 0 &&
                    !req->rq_no_reply && req->rq_reply_state == NULL) {
                        DEBUG_REQ(D_ERROR, req, "MDT \"handler\" %s did not "
                                  "pack reply and returned 0 error\n",
                                  h->mh_name);
                        LBUG();
                }
                serious = is_serious(rc);
                rc = clear_serious(rc);
        } else
                serious = 1;

        req->rq_status = rc;

        /*
         * ELDLM_* codes which > 0 should be in rq_status only as well as
         * all non-serious errors.
         */
        if (rc > 0 || !serious)
                rc = 0;

        LASSERT(current->journal_info == NULL);

	if (rc == 0 && (flags & HABEO_CLAVIS) && info->mti_mdt &&
            info->mti_mdt->mdt_opts.mo_compat_resname) {
                struct ldlm_reply *dlmrep;

                dlmrep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
                if (dlmrep != NULL)
                        rc = mdt_lock_reply_compat(info->mti_mdt, dlmrep);
        }

        /* If we're DISCONNECTing, the mdt_export_data is already freed */
        if (likely(rc == 0 && req->rq_export && h->mh_opc != MDS_DISCONNECT))
                target_committed_to_req(req);

        if (unlikely(req_is_replay(req) &&
                     lustre_msg_get_transno(req->rq_reqmsg) == 0)) {
                DEBUG_REQ(D_ERROR, req, "transno is 0 during REPLAY");
                LBUG();
        }

        target_send_reply(req, rc, info->mti_fail_id);
        RETURN(0);
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
        info->mti_fail_id = OBD_FAIL_MDS_ALL_REPLY_NET;
        info->mti_transno = lustre_msg_get_transno(req->rq_reqmsg);
        info->mti_mos = NULL;

        memset(&info->mti_attr, 0, sizeof(info->mti_attr));
	info->mti_big_buf = LU_BUF_NULL;
	info->mti_body = NULL;
        info->mti_object = NULL;
        info->mti_dlm_req = NULL;
        info->mti_has_trans = 0;
        info->mti_cross_ref = 0;
        info->mti_opdata = 0;
	info->mti_big_lmm_used = 0;

        /* To not check for split by default. */
        info->mti_spec.no_create = 0;
	info->mti_spec.sp_rm_entry = 0;
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

int mdt_tgt_connect(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct mdt_thread_info	*mti;
	int			 rc;

	ENTRY;

	rc = tgt_connect(tsi);
	if (rc != 0)
		RETURN(rc);

	/* XXX: switch mdt_init_idmap() to use tgt_session_info */
	lu_env_refill((void *)tsi->tsi_env);
	mti = lu_context_key_get(&tsi->tsi_env->le_ctx, &mdt_thread_key);
	LASSERT(mti != NULL);

	mdt_thread_info_init(req, mti);
	rc = mdt_init_idmap(mti);
	mdt_thread_info_fini(mti);
	if (rc != 0)
		GOTO(err, rc);
	RETURN(0);
err:
	obd_disconnect(class_export_get(req->rq_export));
	return rc;
}

static int mdt_filter_recovery_request(struct ptlrpc_request *req,
                                       struct obd_device *obd, int *process)
{
        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case MDS_CONNECT: /* This will never get here, but for completeness. */
        case OST_CONNECT: /* This will never get here, but for completeness. */
        case MDS_DISCONNECT:
        case OST_DISCONNECT:
	case OBD_IDX_READ:
               *process = 1;
               RETURN(0);

        case MDS_CLOSE:
        case MDS_DONE_WRITING:
        case MDS_SYNC: /* used in unmounting */
        case OBD_PING:
        case MDS_REINT:
	case UPDATE_OBJ:
        case SEQ_QUERY:
        case FLD_QUERY:
        case LDLM_ENQUEUE:
                *process = target_queue_recovery_request(req, obd);
                RETURN(0);

        default:
                DEBUG_REQ(D_ERROR, req, "not permitted during recovery");
                *process = -EAGAIN;
                RETURN(0);
        }
}

/*
 * Handle recovery. Return:
 *        +1: continue request processing;
 *       -ve: abort immediately with the given error code;
 *         0: send reply with error code in req->rq_status;
 */
static int mdt_recovery(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct obd_device *obd;

        ENTRY;

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case MDS_CONNECT:
        case SEC_CTX_INIT:
        case SEC_CTX_INIT_CONT:
        case SEC_CTX_FINI:
                {
#if 0
                        int rc;

                        rc = mdt_handle_idmap(info);
                        if (rc)
                                RETURN(rc);
                        else
#endif
                                RETURN(+1);
                }
        }

        if (unlikely(!class_connected_export(req->rq_export))) {
		CDEBUG(D_HA, "operation %d on unconnected MDS from %s\n",
		       lustre_msg_get_opc(req->rq_reqmsg),
		       libcfs_id2str(req->rq_peer));
                /* FIXME: For CMD cleanup, when mds_B stop, the req from
                 * mds_A will get -ENOTCONN(especially for ping req),
                 * which will cause that mds_A deactive timeout, then when
                 * mds_A cleanup, the cleanup process will be suspended since
                 * deactive timeout is not zero.
                 */
                req->rq_status = -ENOTCONN;
                target_send_reply(req, -ENOTCONN, info->mti_fail_id);
                RETURN(0);
        }

        /* sanity check: if the xid matches, the request must be marked as a
         * resent or replayed */
        if (req_xid_is_last(req)) {
                if (!(lustre_msg_get_flags(req->rq_reqmsg) &
                      (MSG_RESENT | MSG_REPLAY))) {
                        DEBUG_REQ(D_WARNING, req, "rq_xid "LPU64" matches last_xid, "
                                  "expected REPLAY or RESENT flag (%x)", req->rq_xid,
                                  lustre_msg_get_flags(req->rq_reqmsg));
                        LBUG();
                        req->rq_status = -ENOTCONN;
                        RETURN(-ENOTCONN);
                }
        }

        /* else: note the opposite is not always true; a RESENT req after a
         * failover will usually not match the last_xid, since it was likely
         * never committed. A REPLAYed request will almost never match the
         * last xid, however it could for a committed, but still retained,
         * open. */

        obd = req->rq_export->exp_obd;

        /* Check for aborted recovery... */
        if (unlikely(obd->obd_recovering)) {
                int rc;
                int should_process;
                DEBUG_REQ(D_INFO, req, "Got new replay");
                rc = mdt_filter_recovery_request(req, obd, &should_process);
                if (rc != 0 || !should_process)
                        RETURN(rc);
                else if (should_process < 0) {
                        req->rq_status = should_process;
                        rc = ptlrpc_error(req);
                        RETURN(rc);
                }
        }
        RETURN(+1);
}

static int mdt_msg_check_version(struct lustre_msg *msg)
{
        int rc;

        switch (lustre_msg_get_opc(msg)) {
        case MDS_CONNECT:
        case MDS_DISCONNECT:
        case OBD_PING:
        case SEC_CTX_INIT:
        case SEC_CTX_INIT_CONT:
        case SEC_CTX_FINI:
	case OBD_IDX_READ:
                rc = lustre_msg_check_version(msg, LUSTRE_OBD_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_OBD_VERSION);
                break;
        case MDS_GETSTATUS:
        case MDS_GETATTR:
        case MDS_GETATTR_NAME:
        case MDS_STATFS:
        case MDS_READPAGE:
        case MDS_WRITEPAGE:
        case MDS_IS_SUBDIR:
        case MDS_REINT:
        case MDS_CLOSE:
        case MDS_DONE_WRITING:
        case MDS_PIN:
        case MDS_SYNC:
        case MDS_GETXATTR:
        case MDS_SETXATTR:
        case MDS_SET_INFO:
        case MDS_GET_INFO:
	case MDS_HSM_PROGRESS:
	case MDS_HSM_REQUEST:
	case MDS_HSM_CT_REGISTER:
	case MDS_HSM_CT_UNREGISTER:
	case MDS_HSM_STATE_GET:
	case MDS_HSM_STATE_SET:
	case MDS_HSM_ACTION:
        case MDS_QUOTACHECK:
        case MDS_QUOTACTL:
	case UPDATE_OBJ:
	case MDS_SWAP_LAYOUTS:
        case QUOTA_DQACQ:
        case QUOTA_DQREL:
        case SEQ_QUERY:
        case FLD_QUERY:
                rc = lustre_msg_check_version(msg, LUSTRE_MDS_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_MDS_VERSION);
                break;
        case LDLM_ENQUEUE:
        case LDLM_CONVERT:
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                rc = lustre_msg_check_version(msg, LUSTRE_DLM_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_DLM_VERSION);
                break;
        case OBD_LOG_CANCEL:
        case LLOG_ORIGIN_HANDLE_CREATE:
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
        case LLOG_ORIGIN_HANDLE_CLOSE:
        case LLOG_ORIGIN_HANDLE_DESTROY:
        case LLOG_ORIGIN_HANDLE_PREV_BLOCK:
        case LLOG_CATINFO:
                rc = lustre_msg_check_version(msg, LUSTRE_LOG_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_LOG_VERSION);
                break;
        default:
                CERROR("MDS unknown opcode %d\n", lustre_msg_get_opc(msg));
                rc = -ENOTSUPP;
        }
        return rc;
}

static int mdt_handle0(struct ptlrpc_request *req,
                       struct mdt_thread_info *info,
                       struct mdt_opc_slice *supported)
{
        struct mdt_handler *h;
        struct lustre_msg  *msg;
        int                 rc;

        ENTRY;

        if (OBD_FAIL_CHECK_ORSET(OBD_FAIL_MDS_ALL_REQUEST_NET, OBD_FAIL_ONCE))
                RETURN(0);

        LASSERT(current->journal_info == NULL);

        msg = req->rq_reqmsg;
        rc = mdt_msg_check_version(msg);
        if (likely(rc == 0)) {
                rc = mdt_recovery(info);
                if (likely(rc == +1)) {
                        h = mdt_handler_find(lustre_msg_get_opc(msg),
                                             supported);
                        if (likely(h != NULL)) {
                                rc = mdt_req_handle(info, h, req);
                        } else {
				CERROR("%s: opc unsupported: 0x%x\n",
					mdt_obd_name(info->mti_mdt),
					lustre_msg_get_opc(msg));
                                req->rq_status = -ENOTSUPP;
                                rc = ptlrpc_error(req);
                                RETURN(rc);
                        }
                }
	} else {
		CDEBUG(D_INFO, "%s: drops mal-formed request: rc = %d\n",
			mdt_obd_name(info->mti_mdt), rc);
		req->rq_status = rc;
		rc = ptlrpc_error(req);
	}
	RETURN(rc);
}

/*
 * MDT handler function called by ptlrpc service thread when request comes.
 *
 * XXX common "target" functionality should be factored into separate module
 * shared by mdt, ost and stand-alone services like fld.
 */
int mdt_handle_common(struct ptlrpc_request *req,
		      struct mdt_opc_slice *supported)
{
        struct lu_env          *env;
        struct mdt_thread_info *info;
        int                     rc;
        ENTRY;

        env = req->rq_svc_thread->t_env;
	LASSERT(env != NULL);
	/* Refill(initilize) the context(mdt_thread_info), in case it is
	 * not initialized yet. Usually it happens during start up, after
	 * MDS(ptlrpc threads) is start up, it gets the first CONNECT request,
	 * before MDT_thread_info is initialized */
	lu_env_refill(env);
        LASSERT(env->le_ses != NULL);
        LASSERT(env->le_ctx.lc_thread == req->rq_svc_thread);
        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);

	req_capsule_init(&req->rq_pill, req, RCL_SERVER);
        mdt_thread_info_init(req, info);

        rc = mdt_handle0(req, info, supported);

        mdt_thread_info_fini(info);
	req_capsule_fini(&req->rq_pill);
        RETURN(rc);
}

/*
 * This is called from recovery code as handler of _all_ RPC types, FLD and SEQ
 * as well.
 */
int mdt_recovery_handle(struct ptlrpc_request *req)
{
	int rc;

	ENTRY;

	rc = mdt_handle_common(req, mdt_regular_handlers);

	RETURN(rc);
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

int mdt_intent_lock_replace(struct mdt_thread_info *info,
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
				    __u64  flags)
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
        if (req_xid_is_last(req))
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
					MDS_INODELOCK_XATTR,
					MDT_LOCAL_LOCK);
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
        struct ptlrpc_request  *req;
        struct mdt_body        *reqbody;
        struct mdt_body        *repbody;
        int                     rc, rc2;
        ENTRY;

        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(reqbody);

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(repbody);

        info->mti_cross_ref = !!(reqbody->valid & OBD_MD_FLCROSSREF);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

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

        rc = mdt_init_ucred(info, reqbody);
        if (rc)
                GOTO(out_shrink, rc);

        req = info->mti_pill->rc_req;
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
	int rc = 0;
	ENTRY;

	if (opcode != MDT_IT_LAYOUT) {
		CERROR("%s: Unknown intent (%d)\n", mdt_obd_name(info->mti_mdt),
			opcode);
		RETURN(-EINVAL);
	}

	fid = &info->mti_tmp_fid2;
	fid_extract_from_res_name(fid, &(*lockp)->l_resource->lr_name);

	/* Get lock from request for possible resent case. */
	mdt_intent_fixup_resent(info, *lockp, lhc, flags);

	obj = mdt_object_find(info->mti_env, info->mti_mdt, fid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	if (mdt_object_exists(obj) && !mdt_object_remote(obj)) {
		/* get the length of lsm */
		rc = mdt_attr_get_eabuf_size(info, obj);
		if (rc < 0)
			RETURN(rc);

		if (rc > info->mti_mdt->mdt_max_mdsize)
			info->mti_mdt->mdt_max_mdsize = rc;
	}

	mdt_object_put(info->mti_env, obj);

	(*lockp)->l_lvb_type = LVB_T_LAYOUT;
	req_capsule_set_size(info->mti_pill, &RMF_DLM_LVB, RCL_SERVER, rc);
	rc = req_capsule_server_pack(info->mti_pill);
	if (rc != 0)
		RETURN(-EINVAL);

	if (lustre_handle_is_used(&lhc->mlh_reg_lh))
		rc = mdt_intent_lock_replace(info, lockp, lhc, flags);

	layout = req_capsule_client_get(info->mti_pill, &RMF_LAYOUT_INTENT);
	LASSERT(layout != NULL);
	if (layout->li_opc == LAYOUT_INTENT_ACCESS)
		/* return to normal/resent ldlm handling */
		RETURN(rc);

	CERROR("%s: Unsupported layout intent (%d)\n",
		mdt_obd_name(info->mti_mdt), layout->li_opc);
	RETURN(-EINVAL);
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

        opc = mdt_reint_opcode(info, intent_fmts);
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
	if (rc == -EREMOTE || mdt_get_disposition(rep, DISP_OPEN_LOCK)) {
		LASSERT(lustre_handle_is_used(&lhc->mlh_reg_lh));
		rep->lock_policy_res2 = 0;
		rc = mdt_intent_lock_replace(info, lockp, lhc, flags);
		RETURN(rc);
	}

	rep->lock_policy_res2 = clear_serious(rc);

        if (rep->lock_policy_res2 == -ENOENT &&
            mdt_get_disposition(rep, DISP_LOOKUP_NEG))
                rep->lock_policy_res2 = 0;

        if (rc == -ENOTCONN || rc == -ENODEV ||
            rc == -EOVERFLOW) { /**< if VBR failure then return error */
                /*
                 * If it is the disconnect error (ENODEV & ENOCONN), the error
                 * will be returned by rq_status, and client at ptlrpc layer
                 * will detect this, then disconnect, reconnect the import
                 * immediately, instead of impacting the following the rpc.
                 */
                lhc->mlh_reg_lh.cookie = 0ull;
                RETURN(rc);
        } else {
                /*
                 * For other cases, the error will be returned by intent.
                 * and client will retrieve the result from intent.
                 */
                 /*
                  * FIXME: when open lock is finished, that should be
                  * checked here.
                  */
                if (lustre_handle_is_used(&lhc->mlh_reg_lh)) {
                        LASSERTF(rc == 0, "Error occurred but lock handle "
                                 "is still in use, rc = %d\n", rc);
                        rep->lock_policy_res2 = 0;
			rc = mdt_intent_lock_replace(info, lockp, lhc, flags);
                        RETURN(rc);
                } else {
                        lhc->mlh_reg_lh.cookie = 0ull;
                        RETURN(ELDLM_LOCK_ABORTED);
                }
        }
}

static int mdt_intent_code(long itcode)
{
        int rc;

        switch(itcode) {
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
                CERROR("Unknown intent opcode: %ld\n", itcode);
                rc = -EINVAL;
                break;
        }
        return rc;
}

static int mdt_intent_opc(long itopc, struct mdt_thread_info *info,
			  struct ldlm_lock **lockp, __u64 flags)
{
        struct req_capsule   *pill;
        struct mdt_it_flavor *flv;
        int opc;
        int rc;
        ENTRY;

        opc = mdt_intent_code(itopc);
        if (opc < 0)
                RETURN(-EINVAL);

        pill = info->mti_pill;

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

	flv  = &mdt_it_flavor[opc];
        if (flv->it_fmt != NULL)
                req_capsule_extend(pill, flv->it_fmt);

        rc = mdt_unpack_req_pack_rep(info, flv->it_flags);
        if (rc == 0) {
                struct ptlrpc_request *req = mdt_info_req(info);
		if (flv->it_flags & MUTABOR &&
		    exp_connect_flags(req->rq_export) & OBD_CONNECT_RDONLY)
			RETURN(-EROFS);
        }
        if (rc == 0 && flv->it_act != NULL) {
		struct ldlm_reply *rep;

		/* execute policy */
		rc = flv->it_act(opc, info, lockp, flags);

		/* Check whether the reply has been packed successfully. */
		if (mdt_info_req(info)->rq_repmsg != NULL) {
			rep = req_capsule_server_get(info->mti_pill,
						     &RMF_DLM_REP);
			rep->lock_policy_res2 =
				ptlrpc_status_hton(rep->lock_policy_res2);
		}
	} else {
		rc = -EPROTO;
	}
	RETURN(rc);
}

static int mdt_intent_policy(struct ldlm_namespace *ns,
                             struct ldlm_lock **lockp, void *req_cookie,
			     ldlm_mode_t mode, __u64 flags, void *data)
{
        struct mdt_thread_info *info;
        struct ptlrpc_request  *req  =  req_cookie;
        struct ldlm_intent     *it;
        struct req_capsule     *pill;
        int rc;

        ENTRY;

        LASSERT(req != NULL);

        info = lu_context_key_get(&req->rq_svc_thread->t_env->le_ctx,
                                  &mdt_thread_key);
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
        RETURN(rc);
}

static int mdt_seq_fini(const struct lu_env *env,
                        struct mdt_device *m)
{
	return seq_site_fini(env, mdt_seq_site(m));
}

static int mdt_seq_init(const struct lu_env *env,
                        const char *uuid,
                        struct mdt_device *m)
{
	struct seq_server_site *ss;
	char *prefix;
	int rc;
	ENTRY;

	ss = mdt_seq_site(m);

	/*
	 * This is sequence-controller node. Init seq-controller server on local
	 * MDT.
	 */
	if (ss->ss_node_id == 0) {
		LASSERT(ss->ss_control_seq == NULL);

		OBD_ALLOC_PTR(ss->ss_control_seq);
		if (ss->ss_control_seq == NULL)
			RETURN(-ENOMEM);

		rc = seq_server_init(ss->ss_control_seq,
				     m->mdt_bottom, uuid,
				     LUSTRE_SEQ_CONTROLLER,
				     ss,
				     env);

		if (rc)
			GOTO(out_seq_fini, rc);

		OBD_ALLOC_PTR(ss->ss_client_seq);
		if (ss->ss_client_seq == NULL)
			GOTO(out_seq_fini, rc = -ENOMEM);

		OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
		if (prefix == NULL) {
			OBD_FREE_PTR(ss->ss_client_seq);
			GOTO(out_seq_fini, rc = -ENOMEM);
		}

		snprintf(prefix, MAX_OBD_NAME + 5, "ctl-%s",
			 uuid);

		/*
		 * Init seq-controller client after seq-controller server is
		 * ready. Pass ss->ss_control_seq to it for direct talking.
		 */
		rc = seq_client_init(ss->ss_client_seq, NULL,
				     LUSTRE_SEQ_METADATA, prefix,
				     ss->ss_control_seq);
		OBD_FREE(prefix, MAX_OBD_NAME + 5);

		if (rc)
			GOTO(out_seq_fini, rc);
	}

	/* Init seq-server on local MDT */
	LASSERT(ss->ss_server_seq == NULL);

	OBD_ALLOC_PTR(ss->ss_server_seq);
	if (ss->ss_server_seq == NULL)
		GOTO(out_seq_fini, rc = -ENOMEM);

	rc = seq_server_init(ss->ss_server_seq,
			     m->mdt_bottom, uuid,
			     LUSTRE_SEQ_SERVER,
			     ss,
			     env);
	if (rc)
		GOTO(out_seq_fini, rc = -ENOMEM);

	/* Assign seq-controller client to local seq-server. */
	if (ss->ss_node_id == 0) {
		LASSERT(ss->ss_client_seq != NULL);

		rc = seq_server_set_cli(ss->ss_server_seq,
					ss->ss_client_seq,
					env);
	}

	EXIT;
out_seq_fini:
	if (rc)
		mdt_seq_fini(env, m);

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
			     ss->ss_node_id, LU_SEQ_RANGE_MDT);
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
	struct obd_device       *obd;
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
	obd = m->mdt_child_exp->exp_obd;

	/* process cleanup, pass mdt obd name to get obd umount flags */
	/* XXX: this is needed because all layers are referenced by
	 * objects (some of them are pinned by osd, for example *
	 * the proper solution should be a model where object used
	 * by osd only doesn't have mdt/mdd slices -bzzz */
	lustre_cfg_bufs_reset(bufs, mdt_obd_name(m));
	lustre_cfg_bufs_set_string(bufs, 1, NULL);
	lcfg = lustre_cfg_new(LCFG_PRE_CLEANUP, bufs);
	if (!lcfg) {
		CERROR("%s:Cannot alloc lcfg!\n", mdt_obd_name(m));
		return;
	}
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
	if (!lcfg) {
		CERROR("Cannot alloc lcfg!\n");
		return;
	}
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
		GOTO(cleanup_mem, rc = -ENOMEM);
	p[3] = 'D';

	snprintf(uuid, MAX_OBD_NAME, "%s_UUID", name);

	lprof = class_get_profile(lustre_cfg_string(cfg, 0));
	if (lprof == NULL || lprof->lp_dt == NULL) {
		CERROR("can't find the profile: %s\n",
		       lustre_cfg_string(cfg, 0));
		GOTO(cleanup_mem, rc = -EINVAL);
	}

	lustre_cfg_bufs_reset(bufs, name);
	lustre_cfg_bufs_set_string(bufs, 1, LUSTRE_MDD_NAME);
	lustre_cfg_bufs_set_string(bufs, 2, uuid);
	lustre_cfg_bufs_set_string(bufs, 3, lprof->lp_dt);

	lcfg = lustre_cfg_new(LCFG_ATTACH, bufs);
	if (!lcfg)
		GOTO(free_bufs, rc = -ENOMEM);

	rc = class_attach(lcfg);
	if (rc)
		GOTO(lcfg_cleanup, rc);

	obd = class_name2obd(name);
	if (!obd) {
		CERROR("Can not find obd %s (%s in config)\n",
		       MDD_OBD_NAME, lustre_cfg_string(cfg, 0));
		GOTO(class_detach, rc = -EINVAL);
	}

	lustre_cfg_free(lcfg);

	lustre_cfg_bufs_reset(bufs, name);
	lustre_cfg_bufs_set_string(bufs, 1, uuid);
	lustre_cfg_bufs_set_string(bufs, 2, dev);
	lustre_cfg_bufs_set_string(bufs, 3, lprof->lp_dt);

	lcfg = lustre_cfg_new(LCFG_SETUP, bufs);

	rc = class_setup(obd, lcfg);
	if (rc)
		GOTO(class_detach, rc);

	/* connect to MDD we just setup */
	rc = mdt_connect_to_next(env, mdt, name, &mdt->mdt_child_exp);
	if (rc)
		RETURN(rc);

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
		RETURN(rc);
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
	if (!lcfg)
		GOTO(cleanup_mem, rc = -ENOMEM);

	rc = class_attach(lcfg);
	if (rc)
		GOTO(lcfg_cleanup, rc);

	obd = class_name2obd(qmtname);
	if (!obd) {
		CERROR("Can not find obd %s (%s in config)\n", qmtname,
		       lustre_cfg_string(cfg, 0));
		GOTO(class_detach, rc = -EINVAL);
	}

	lustre_cfg_free(lcfg);

	lustre_cfg_bufs_reset(bufs, qmtname);
	lustre_cfg_bufs_set_string(bufs, 1, uuid);
	lustre_cfg_bufs_set_string(bufs, 2, dev);

	/* for quota, the next device should be the OSD device */
	lustre_cfg_bufs_set_string(bufs, 3,
				   mdt->mdt_bottom->dd_lu_dev.ld_obd->obd_name);

	lcfg = lustre_cfg_new(LCFG_SETUP, bufs);

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

static struct tgt_handler mdt_tgt_handlers[] = {
TGT_RPC_HANDLER(MDS_FIRST_OPC,
		0,			MDS_CONNECT,	mdt_tgt_connect,
		&RQF_CONNECT, LUSTRE_OBD_VERSION),
TGT_RPC_HANDLER(MDS_FIRST_OPC,
		0,			MDS_DISCONNECT,	tgt_disconnect,
		&RQF_MDS_DISCONNECT, LUSTRE_OBD_VERSION),
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
		.tos_hs		= tgt_sec_ctx_handlers
	},
	{
		.tos_opc_start	= UPDATE_OBJ,
		.tos_opc_end	= UPDATE_LAST_OPC,
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
		.tos_hs		= NULL
	}
};

static void mdt_fini(const struct lu_env *env, struct mdt_device *m)
{
	struct md_device  *next = m->mdt_child;
	struct lu_device  *d    = &m->mdt_lu_dev;
        struct obd_device *obd = mdt2obd_dev(m);
        ENTRY;

        target_recovery_fini(obd);

        ping_evictor_stop();

	mdt_stack_pre_fini(env, m, md2lu_dev(m->mdt_child));

	if (m->mdt_opts.mo_coordinator)
		mdt_hsm_cdt_stop(m);

	mdt_hsm_cdt_fini(m);

	mdt_llog_ctxt_unclone(env, m, LLOG_AGENT_ORIG_CTXT);
        mdt_llog_ctxt_unclone(env, m, LLOG_CHANGELOG_ORIG_CTXT);
        obd_exports_barrier(obd);
        obd_zombie_barrier();

        mdt_procfs_fini(m);

        tgt_fini(env, &m->mdt_lut);
        mdt_fs_cleanup(env, m);
        upcall_cache_cleanup(m->mdt_identity_cache);
        m->mdt_identity_cache = NULL;

        if (m->mdt_namespace != NULL) {
                ldlm_namespace_free(m->mdt_namespace, NULL,
                                    d->ld_obd->obd_force);
                d->ld_obd->obd_namespace = m->mdt_namespace = NULL;
        }

	mdt_quota_fini(env, m);

        cfs_free_nidlist(&m->mdt_nosquash_nids);
        if (m->mdt_nosquash_str) {
                OBD_FREE(m->mdt_nosquash_str, m->mdt_nosquash_strlen);
                m->mdt_nosquash_str = NULL;
                m->mdt_nosquash_strlen = 0;
        }

	next->md_ops->mdo_iocontrol(env, next, OBD_IOC_PAUSE_LFSCK, 0, NULL);

        mdt_seq_fini(env, m);
        mdt_fld_fini(env, m);
        sptlrpc_rule_set_free(&m->mdt_sptlrpc_rset);

        next->md_ops->mdo_init_capa_ctxt(env, next, 0, 0, 0, NULL);
        cfs_timer_disarm(&m->mdt_ck_timer);
        mdt_ck_thread_stop(m);

	/*
	 * Finish the stack
	 */
	mdt_stack_fini(env, m, md2lu_dev(m->mdt_child));

	LASSERT(cfs_atomic_read(&d->ld_ref) == 0);

	server_put_mount(mdt_obd_name(m));

	EXIT;
}

static int mdt_adapt_sptlrpc_conf(struct obd_device *obd, int initial)
{
	struct mdt_device	*m = mdt_dev(obd->obd_lu_dev);
	struct sptlrpc_rule_set	 tmp_rset;
	int			 rc;

	sptlrpc_rule_set_init(&tmp_rset);
	rc = sptlrpc_conf_target_get_rules(obd, &tmp_rset, initial);
	if (rc) {
		CERROR("mdt %s: failed get sptlrpc rules: %d\n",
		       mdt_obd_name(m), rc);
		return rc;
	}

	sptlrpc_target_update_exp_flavor(obd, &tmp_rset);

	write_lock(&m->mdt_sptlrpc_lock);
	sptlrpc_rule_set_free(&m->mdt_sptlrpc_rset);
	m->mdt_sptlrpc_rset = tmp_rset;
	write_unlock(&m->mdt_sptlrpc_lock);

	return 0;
}

int mdt_postrecov(const struct lu_env *, struct mdt_device *);

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

        m->mdt_som_conf = 0;

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
        }

	rwlock_init(&m->mdt_sptlrpc_lock);
	sptlrpc_rule_set_init(&m->mdt_sptlrpc_rset);

	spin_lock_init(&m->mdt_ioepoch_lock);
        m->mdt_opts.mo_compat_resname = 0;
        m->mdt_opts.mo_mds_capa = 1;
        m->mdt_opts.mo_oss_capa = 1;
        m->mdt_capa_timeout = CAPA_TIMEOUT;
        m->mdt_capa_alg = CAPA_HMAC_ALG_SHA1;
        m->mdt_ck_timeout = CAPA_KEY_TIMEOUT;
        m->mdt_squash_uid = 0;
        m->mdt_squash_gid = 0;
        CFS_INIT_LIST_HEAD(&m->mdt_nosquash_nids);
        m->mdt_nosquash_str = NULL;
        m->mdt_nosquash_strlen = 0;
	init_rwsem(&m->mdt_squash_sem);
	spin_lock_init(&m->mdt_osfs_lock);
	m->mdt_osfs_age = cfs_time_shift_64(-1000);
	m->mdt_enable_remote_dir = 0;
	m->mdt_enable_remote_dir_gid = 0;

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

	rc = mdt_seq_init(env, mdt_obd_name(m), m);
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

        cfs_timer_init(&m->mdt_ck_timer, mdt_ck_timer_callback, m);

	rc = mdt_hsm_cdt_init(m);
	if (rc != 0) {
		CERROR("%s: error initializing coordinator, rc %d\n",
		       mdt_obd_name(m), rc);
                GOTO(err_free_ns, rc);
	}

        rc = mdt_ck_thread_start(m);
        if (rc)
                GOTO(err_free_hsm, rc);

	rc = tgt_init(env, &m->mdt_lut, obd, m->mdt_bottom, mdt_common_slice,
		      OBD_FAIL_MDS_ALL_REQUEST_NET,
		      OBD_FAIL_MDS_ALL_REPLY_NET);
	if (rc)
		GOTO(err_capa, rc);

	rc = mdt_fs_setup(env, m, obd, lsi);
	if (rc)
		GOTO(err_tgt, rc);

        mdt_adapt_sptlrpc_conf(obd, 1);

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

        mdt_init_capa_ctxt(env, m);

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
err_capa:
	cfs_timer_disarm(&m->mdt_ck_timer);
	mdt_ck_thread_stop(m);
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
		server_put_mount(dev);
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
		struct lprocfs_static_vars  lvars;
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

		lprocfs_mdt_init_vars(&lvars);
		rc = class_process_proc_param(PARAM_MDT, lvars.obd_vars,
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
		mutex_init(&mo->mot_ioepoch_mutex);
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
        return (*p)(env, cookie, LUSTRE_MDT_NAME"-object@%p(ioepoch="LPU64" "
                    "flags="LPX64", epochcount=%d, writecount=%d)",
                    mdto, mdto->mot_ioepoch, mdto->mot_flags,
                    mdto->mot_ioepoch_count, mdto->mot_writecount);
}

static int mdt_prepare(const struct lu_env *env,
		struct lu_device *pdev,
		struct lu_device *cdev)
{
	struct mdt_device *mdt = mdt_dev(cdev);
	struct lu_device *next = &mdt->mdt_child->md_lu_dev;
	struct obd_device *obd = cdev->ld_obd;
	struct lfsck_start_param lsp;
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

	lsp.lsp_start = NULL;
	lsp.lsp_namespace = mdt->mdt_namespace;
	rc = mdt->mdt_child->md_ops->mdo_iocontrol(env, mdt->mdt_child,
						   OBD_IOC_START_LFSCK,
						   0, &lsp);
	if (rc != 0) {
		CWARN("%s: auto trigger paused LFSCK failed: rc = %d\n",
		      mdt_obd_name(mdt), rc);
		rc = 0;
	}

	if (mdt->mdt_seq_site.ss_node_id == 0) {
		rc = mdt->mdt_child->md_ops->mdo_root_get(env, mdt->mdt_child,
							 &mdt->mdt_md_root_fid);
		if (rc)
			RETURN(rc);
	}

	LASSERT(!test_bit(MDT_FL_CFGLOG, &mdt->mdt_state));
	target_recovery_init(&mdt->mdt_lut, mdt_recovery_handle);
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
        struct obd_device     *obd = exp->exp_obd;
        int                    rc;
        ENTRY;

        LASSERT(obd);

        if (KEY_IS(KEY_SPTLRPC_CONF)) {
                rc = mdt_adapt_sptlrpc_conf(obd, 0);
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

	/* If no known bits (which should not happen, probably,
	   as everybody should support LOOKUP and UPDATE bits at least)
	   revert to compat mode with plain locks. */
	if (!data->ocd_ibits_known &&
	    data->ocd_connect_flags & OBD_CONNECT_IBITS)
		data->ocd_connect_flags &= ~OBD_CONNECT_IBITS;

	if (!mdt->mdt_opts.mo_acl)
		data->ocd_connect_flags &= ~OBD_CONNECT_ACL;

	if (!mdt->mdt_opts.mo_user_xattr)
		data->ocd_connect_flags &= ~OBD_CONNECT_XATTR;

	if (!mdt->mdt_som_conf)
		data->ocd_connect_flags &= ~OBD_CONNECT_SOM;

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

	if (mdt->mdt_som_conf &&
	    !(data->ocd_connect_flags & (OBD_CONNECT_LIGHTWEIGHT |
					 OBD_CONNECT_MDS_MDS |
					 OBD_CONNECT_SOM))) {
		CWARN("%s: MDS has SOM enabled, but client does not support "
		      "it\n", mdt_obd_name(mdt));
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

	return 0;
}

int mdt_connect_check_sptlrpc(struct mdt_device *mdt, struct obd_export *exp,
			      struct ptlrpc_request *req)
{
	struct sptlrpc_flavor   flvr;
	int                     rc = 0;

	if (exp->exp_flvr.sf_rpc == SPTLRPC_FLVR_INVALID) {
		read_lock(&mdt->mdt_sptlrpc_lock);
		sptlrpc_target_choose_flavor(&mdt->mdt_sptlrpc_rset,
					     req->rq_sp_from,
					     req->rq_peer.nid,
					     &flvr);
		read_unlock(&mdt->mdt_sptlrpc_lock);

		spin_lock(&exp->exp_lock);

                exp->exp_sp_peer = req->rq_sp_from;
                exp->exp_flvr = flvr;

                if (exp->exp_flvr.sf_rpc != SPTLRPC_FLVR_ANY &&
                    exp->exp_flvr.sf_rpc != req->rq_flvr.sf_rpc) {
                        CERROR("unauthorized rpc flavor %x from %s, "
                               "expect %x\n", req->rq_flvr.sf_rpc,
                               libcfs_nid2str(req->rq_peer.nid),
                               exp->exp_flvr.sf_rpc);
                        rc = -EACCES;
                }

		spin_unlock(&exp->exp_lock);
        } else {
                if (exp->exp_sp_peer != req->rq_sp_from) {
                        CERROR("RPC source %s doesn't match %s\n",
                               sptlrpc_part2name(req->rq_sp_from),
                               sptlrpc_part2name(exp->exp_sp_peer));
                        rc = -EACCES;
                } else {
                        rc = sptlrpc_target_export_check(exp, req);
                }
        }

        return rc;
}

/* mds_connect copy */
static int mdt_obd_connect(const struct lu_env *env,
                           struct obd_export **exp, struct obd_device *obd,
                           struct obd_uuid *cluuid,
                           struct obd_connect_data *data,
                           void *localdata)
{
        struct obd_export      *lexp;
        struct lustre_handle    conn = { 0 };
        struct mdt_device      *mdt;
        int                     rc;
        ENTRY;

        LASSERT(env != NULL);
        if (!exp || !obd || !cluuid)
                RETURN(-EINVAL);

	mdt = mdt_dev(obd->obd_lu_dev);

	/*
	 * first, check whether the stack is ready to handle requests
	 * XXX: probably not very appropriate method is used now
	 *      at some point we should find a better one
	 */
	if (!test_bit(MDT_FL_SYNCED, &mdt->mdt_state) && data != NULL &&
	    !(data->ocd_connect_flags & OBD_CONNECT_LIGHTWEIGHT)) {
		rc = obd_get_info(env, mdt->mdt_child_exp,
				  sizeof(KEY_OSP_CONNECTED),
				  KEY_OSP_CONNECTED, NULL, NULL, NULL);
		if (rc)
			RETURN(-EAGAIN);
		set_bit(MDT_FL_SYNCED, &mdt->mdt_state);
	}

        rc = class_connect(&conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        lexp = class_conn2export(&conn);
        LASSERT(lexp != NULL);

        rc = mdt_connect_internal(lexp, mdt, data);
        if (rc == 0) {
                struct lsd_client_data *lcd = lexp->exp_target_data.ted_lcd;

                LASSERT(lcd);
		memcpy(lcd->lcd_uuid, cluuid, sizeof lcd->lcd_uuid);
		rc = tgt_client_new(env, lexp);
                if (rc == 0)
                        mdt_export_stats_init(obd, lexp, localdata);
        }

        if (rc != 0) {
                class_disconnect(lexp);
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
        int                     rc;
        ENTRY;

        if (exp == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        rc = mdt_connect_internal(exp, mdt_dev(obd->obd_lu_dev), data);
        if (rc == 0)
                mdt_export_stats_init(obd, exp, localdata);

        RETURN(rc);
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
        struct mdt_export_data *med = &exp->exp_mdt_data;
        struct obd_device      *obd = exp->exp_obd;
        struct mdt_device      *mdt;
        struct mdt_thread_info *info;
        struct lu_env           env;
        CFS_LIST_HEAD(closing_list);
        struct mdt_file_data *mfd, *n;
        int rc = 0;
        ENTRY;

	spin_lock(&med->med_open_lock);
	while (!cfs_list_empty(&med->med_open_head)) {
		cfs_list_t *tmp = med->med_open_head.next;
		mfd = cfs_list_entry(tmp, struct mdt_file_data, mfd_list);

		/* Remove mfd handle so it can't be found again.
		 * We are consuming the mfd_list reference here. */
		class_handle_unhash(&mfd->mfd_handle);
		cfs_list_move_tail(&mfd->mfd_list, &closing_list);
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

        if (!cfs_list_empty(&closing_list)) {
                struct md_attr *ma = &info->mti_attr;

                /* Close any open files (which may also cause orphan unlinking). */
                cfs_list_for_each_entry_safe(mfd, n, &closing_list, mfd_list) {
                        cfs_list_del_init(&mfd->mfd_list);
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
			if (mfd->mfd_mode & (FMODE_WRITE|MDS_FMODE_TRUNC))
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

static int mdt_obd_disconnect(struct obd_export *exp)
{
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        rc = server_disconnect_export(exp);
        if (rc != 0)
                CDEBUG(D_IOCTL, "server disconnect error: %d\n", rc);

        rc = mdt_export_cleanup(exp);
        class_export_put(exp);
        RETURN(rc);
}

/* FIXME: Can we avoid using these two interfaces? */
static int mdt_init_export(struct obd_export *exp)
{
        struct mdt_export_data *med = &exp->exp_mdt_data;
        int                     rc;
        ENTRY;

        CFS_INIT_LIST_HEAD(&med->med_open_head);
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

        LASSERT(cfs_list_empty(&exp->exp_outstanding_replies));
        LASSERT(cfs_list_empty(&exp->exp_mdt_data.med_open_head));

        RETURN(0);
}

/** The maximum depth that fid2path() will search.
 * This is limited only because we want to store the fids for
 * historical path lookup purposes.
 */
#define MAX_PATH_DEPTH 100

/** mdt_path() lookup structure. */
struct path_lookup_info {
	__u64			pli_recno;	/**< history point */
	__u64			pli_currec;	/**< current record */
	struct lu_fid		pli_fid;
	struct lu_fid		pli_fids[MAX_PATH_DEPTH]; /**< path, in fids */
	struct mdt_object	*pli_mdt_obj;
	char			*pli_path;	/**< full path */
	int			pli_pathlen;
	int			pli_linkno;	/**< which hardlink to follow */
	int			pli_fidcount;	/**< number of \a pli_fids */
};

static int mdt_links_read(struct mdt_thread_info *info,
			  struct mdt_object *mdt_obj, struct linkea_data *ldata)
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

static int mdt_path_current(struct mdt_thread_info *info,
			    struct path_lookup_info *pli)
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
	struct linkea_data	ldata = { 0 };
	int			rc = 0;
	ENTRY;

	/* temp buffer for path element, the buffer will be finally freed
	 * in mdt_thread_info_fini */
	buf = lu_buf_check_and_alloc(buf, PATH_MAX);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);

	ldata.ld_buf = buf;
	ptr = pli->pli_path + pli->pli_pathlen - 1;
	*ptr = 0;
	--ptr;
	pli->pli_fidcount = 0;
	pli->pli_fids[0] = *(struct lu_fid *)mdt_object_fid(pli->pli_mdt_obj);

	/* root FID only exists on MDT0, and fid2path should also ends at MDT0,
	 * so checking root_fid can only happen on MDT0. */
	while (!lu_fid_eq(&mdt->mdt_md_root_fid,
			  &pli->pli_fids[pli->pli_fidcount])) {
		mdt_obj = mdt_object_find(info->mti_env, mdt,
					  &pli->pli_fids[pli->pli_fidcount]);
		if (IS_ERR(mdt_obj))
			GOTO(out, rc = PTR_ERR(mdt_obj));
		if (mdt_object_remote(mdt_obj)) {
			mdt_object_put(info->mti_env, mdt_obj);
			GOTO(remote_out, rc = -EREMOTE);
		}
		if (!mdt_object_exists(mdt_obj)) {
			mdt_object_put(info->mti_env, mdt_obj);
			GOTO(out, rc = -ENOENT);
		}

		rc = mdt_links_read(info, mdt_obj, &ldata);
		mdt_object_put(info->mti_env, mdt_obj);
		if (rc != 0)
			GOTO(out, rc);

		leh = buf->lb_buf;
		lee = (struct link_ea_entry *)(leh + 1); /* link #0 */
		linkea_entry_unpack(lee, &reclen, tmpname, tmpfid);
		/* If set, use link #linkno for path lookup, otherwise use
		   link #0.  Only do this for the final path element. */
		if (pli->pli_fidcount == 0 &&
		    pli->pli_linkno < leh->leh_reccount) {
			int count;
			for (count = 0; count < pli->pli_linkno; count++) {
				lee = (struct link_ea_entry *)
				     ((char *)lee + reclen);
				linkea_entry_unpack(lee, &reclen, tmpname,
						    tmpfid);
			}
			if (pli->pli_linkno < leh->leh_reccount - 1)
				/* indicate to user there are more links */
				pli->pli_linkno++;
		}

		/* Pack the name in the end of the buffer */
		ptr -= tmpname->ln_namelen;
		if (ptr - 1 <= pli->pli_path)
			GOTO(out, rc = -EOVERFLOW);
		strncpy(ptr, tmpname->ln_name, tmpname->ln_namelen);
		*(--ptr) = '/';

		/* Store the parent fid for historic lookup */
		if (++pli->pli_fidcount >= MAX_PATH_DEPTH)
			GOTO(out, rc = -EOVERFLOW);
		pli->pli_fids[pli->pli_fidcount] = *tmpfid;
	}

remote_out:
	ptr++; /* skip leading / */
	memmove(pli->pli_path, ptr, pli->pli_path + pli->pli_pathlen - ptr);

	EXIT;
out:
	return rc;
}

/* Returns the full path to this fid, as of changelog record recno. */
static int mdt_path(struct mdt_thread_info *info, struct mdt_object *obj,
		    char *path, int pathlen, __u64 *recno, int *linkno,
		    struct lu_fid *fid)
{
	struct mdt_device	*mdt = info->mti_mdt;
	struct path_lookup_info	*pli;
	int			tries = 3;
	int			rc = -EAGAIN;
	ENTRY;

	if (pathlen < 3)
		RETURN(-EOVERFLOW);

	if (lu_fid_eq(&mdt->mdt_md_root_fid, mdt_object_fid(obj))) {
		path[0] = '\0';
		RETURN(0);
	}

	OBD_ALLOC_PTR(pli);
	if (pli == NULL)
		RETURN(-ENOMEM);

	pli->pli_mdt_obj = obj;
	pli->pli_recno = *recno;
	pli->pli_path = path;
	pli->pli_pathlen = pathlen;
	pli->pli_linkno = *linkno;

	/* Retry multiple times in case file is being moved */
	while (tries-- && rc == -EAGAIN)
		rc = mdt_path_current(info, pli);

	/* return the last resolved fids to the client, so the client will
	 * build the left path on another MDT for remote object */
	*fid = pli->pli_fids[pli->pli_fidcount];

	*recno = pli->pli_currec;
	/* Return next link index to caller */
	*linkno = pli->pli_linkno;

	OBD_FREE_PTR(pli);

	RETURN(rc);
}

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
	if (obj == NULL || IS_ERR(obj)) {
		CDEBUG(D_IOCTL, "no object "DFID": %ld\n", PFID(&fp->gf_fid),
		       PTR_ERR(obj));
		RETURN(-EINVAL);
	}

	if (mdt_object_remote(obj))
		rc = -EREMOTE;
	else if (!mdt_object_exists(obj))
		rc = -ENOENT;
	else
		rc = 0;

	if (rc < 0) {
		mdt_object_put(info->mti_env, obj);
		CDEBUG(D_IOCTL, "nonlocal object "DFID": %d\n",
		       PFID(&fp->gf_fid), rc);
		RETURN(rc);
	}

	rc = mdt_path(info, obj, fp->gf_path, fp->gf_pathlen, &fp->gf_recno,
		      &fp->gf_linkno, &fp->gf_fid);

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

int mdt_get_info(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        char *key;
        int keylen;
        __u32 *vallen;
        void *valout;
        int rc;
        ENTRY;

        key = req_capsule_client_get(info->mti_pill, &RMF_GETINFO_KEY);
        if (key == NULL) {
                CDEBUG(D_IOCTL, "No GETINFO key");
                RETURN(-EFAULT);
        }
        keylen = req_capsule_get_size(info->mti_pill, &RMF_GETINFO_KEY,
                                      RCL_CLIENT);

        vallen = req_capsule_client_get(info->mti_pill, &RMF_GETINFO_VALLEN);
        if (vallen == NULL) {
                CDEBUG(D_IOCTL, "Unable to get RMF_GETINFO_VALLEN buffer");
                RETURN(-EFAULT);
        }

        req_capsule_set_size(info->mti_pill, &RMF_GETINFO_VAL, RCL_SERVER,
                             *vallen);
        rc = req_capsule_server_pack(info->mti_pill);
        valout = req_capsule_server_get(info->mti_pill, &RMF_GETINFO_VAL);
        if (valout == NULL) {
                CDEBUG(D_IOCTL, "Unable to get get-info RPC out buffer");
                RETURN(-EFAULT);
        }

        if (KEY_IS(KEY_FID2PATH))
                rc = mdt_rpc_fid2path(info, key, valout, *vallen);
        else
                rc = -EINVAL;

        lustre_msg_set_status(req->rq_repmsg, rc);

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
                         void *karg, void *uarg)
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
		lsp.lsp_namespace = mdt->mdt_namespace;
		rc = next->md_ops->mdo_iocontrol(&env, next, cmd, 0, &lsp);
		break;
	}
	case OBD_IOC_STOP_LFSCK: {
		struct md_device *next = mdt->mdt_child;

		rc = next->md_ops->mdo_iocontrol(&env, next, cmd, 0, NULL);
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
	default:
		rc = -EOPNOTSUPP;
		CERROR("%s: Not supported cmd = %d, rc = %d\n",
			mdt_obd_name(mdt), cmd, rc);
	}

        lu_env_fini(&env);
        RETURN(rc);
}

int mdt_postrecov(const struct lu_env *env, struct mdt_device *mdt)
{
        struct lu_device *ld = md2lu_dev(mdt->mdt_child);
        int rc;
        ENTRY;

        rc = ld->ld_ops->ldo_recovery_complete(env, ld);
        RETURN(rc);
}

int mdt_obd_postrecov(struct obd_device *obd)
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
                CWARN("lu_env initialization failed with rc = %d,"
                      "cannot sync\n", rc);
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

static int __init mdt_mod_init(void)
{
	struct lprocfs_static_vars lvars;
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

	lprocfs_mdt_init_vars(&lvars);
	rc = class_register_type(&mdt_obd_device_ops, NULL,
				 lvars.module_vars, LUSTRE_MDT_NAME,
				 &mdt_device_type);
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

static void __exit mdt_mod_exit(void)
{
	class_unregister_type(LUSTRE_MDT_NAME);
	mds_mod_exit();
	lu_kmem_fini(mdt_caches);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Metadata Target ("LUSTRE_MDT_NAME")");
MODULE_LICENSE("GPL");

cfs_module(mdt, LUSTRE_VERSION_STRING, mdt_mod_init, mdt_mod_exit);
