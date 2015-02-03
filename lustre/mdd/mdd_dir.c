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
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdd/mdd_dir.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: Wang Di <wangdi@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_class.h>
#include <obd_support.h>
#include <lustre_mds.h>
#include <lustre_fid.h>

#include "mdd_internal.h"

static const char dot[] = ".";
static const char dotdot[] = "..";

static struct lu_name lname_dotdot = {
        (char *) dotdot,
        sizeof(dotdot) - 1
};

static inline int
mdd_name_check(struct mdd_device *m, const struct lu_name *ln)
{
	if (!lu_name_is_valid(ln))
		return -EINVAL;
	else if (ln->ln_namelen > m->mdd_dt_conf.ddp_max_name_len)
		return -ENAMETOOLONG;
	else
		return 0;
}

/* Get FID from name and parent */
static int
__mdd_lookup(const struct lu_env *env, struct md_object *pobj,
	     const struct lu_attr *pattr, const struct lu_name *lname,
	     struct lu_fid* fid, int mask)
{
	const char *name		= lname->ln_name;
	const struct dt_key *key	= (const struct dt_key *)name;
	struct mdd_object *mdd_obj	= md2mdd_obj(pobj);
	struct mdd_device *m		= mdo2mdd(pobj);
	struct dt_object *dir		= mdd_object_child(mdd_obj);
        int rc;
	ENTRY;

	if (unlikely(mdd_is_dead_obj(mdd_obj)))
		RETURN(-ESTALE);

	if (mdd_object_remote(mdd_obj)) {
		CDEBUG(D_INFO, "%s: Object "DFID" locates on remote server\n",
		       mdd2obd_dev(m)->obd_name, PFID(mdo2fid(mdd_obj)));
	} else if (!mdd_object_exists(mdd_obj)) {
		RETURN(-ESTALE);
	}

	rc = mdd_permission_internal_locked(env, mdd_obj, pattr, mask,
					    MOR_TGT_PARENT);
	if (rc)
		RETURN(rc);

	if (likely(S_ISDIR(mdd_object_type(mdd_obj)) &&
		   dt_try_as_dir(env, dir)))
		rc = dt_lookup(env, dir, (struct dt_rec *)fid, key,
			       mdd_object_capa(env, mdd_obj));
	else
		rc = -ENOTDIR;

	RETURN(rc);
}

int mdd_lookup(const struct lu_env *env,
	       struct md_object *pobj, const struct lu_name *lname,
	       struct lu_fid *fid, struct md_op_spec *spec)
{
	struct lu_attr *pattr = MDD_ENV_VAR(env, pattr);
        int rc;
        ENTRY;

	rc = mdd_la_get(env, md2mdd_obj(pobj), pattr, BYPASS_CAPA);
	if (rc != 0)
		RETURN(rc);

	rc = __mdd_lookup(env, pobj, pattr, lname, fid,
			  (spec != NULL && spec->sp_permitted) ? 0 : MAY_EXEC);
        RETURN(rc);
}

static inline int mdd_parent_fid(const struct lu_env *env,
				 struct mdd_object *obj,
				 const struct lu_attr *attr,
				 struct lu_fid *fid)
{
	return __mdd_lookup(env, &obj->mod_obj, attr, &lname_dotdot, fid, 0);
}

/*
 * For root fid use special function, which does not compare version component
 * of fid. Version component is different for root fids on all MDTs.
 */
int mdd_is_root(struct mdd_device *mdd, const struct lu_fid *fid)
{
        return fid_seq(&mdd->mdd_root_fid) == fid_seq(fid) &&
                fid_oid(&mdd->mdd_root_fid) == fid_oid(fid);
}

/*
 * return 1: if lf is the fid of the ancestor of p1;
 * return 0: if not;
 *
 * return -EREMOTE: if remote object is found, in this
 * case fid of remote object is saved to @pf;
 *
 * otherwise: values < 0, errors.
 */
static int mdd_is_parent(const struct lu_env *env,
			struct mdd_device *mdd,
			struct mdd_object *p1,
			const struct lu_attr *attr,
			const struct lu_fid *lf,
			struct lu_fid *pf)
{
        struct mdd_object *parent = NULL;
        struct lu_fid *pfid;
        int rc;
        ENTRY;

        LASSERT(!lu_fid_eq(mdo2fid(p1), lf));
        pfid = &mdd_env_info(env)->mti_fid;

        /* Check for root first. */
        if (mdd_is_root(mdd, mdo2fid(p1)))
                RETURN(0);

        for(;;) {
		/* this is done recursively, bypass capa for each obj */
		mdd_set_capainfo(env, 4, p1, BYPASS_CAPA);
		rc = mdd_parent_fid(env, p1, attr, pfid);
		if (rc)
			GOTO(out, rc);
                if (mdd_is_root(mdd, pfid))
                        GOTO(out, rc = 0);
		if (lu_fid_eq(pfid, &mdd->mdd_local_root_fid))
			GOTO(out, rc = 0);
                if (lu_fid_eq(pfid, lf))
                        GOTO(out, rc = 1);
                if (parent)
                        mdd_object_put(env, parent);

		parent = mdd_object_find(env, mdd, pfid);
		if (IS_ERR(parent)) {
			GOTO(out, rc = PTR_ERR(parent));
		} else if (mdd_object_remote(parent)) {
			/*FIXME: Because of the restriction of rename in Phase I.
			 * If the parent is remote, we just assumed lf is not the
			 * parent of P1 for now */
			GOTO(out, rc = 0);
		}
		p1 = parent;
        }
        EXIT;
out:
        if (parent && !IS_ERR(parent))
                mdd_object_put(env, parent);
        return rc;
}

/*
 * No permission check is needed.
 *
 * returns 1: if fid is ancestor of @mo;
 * returns 0: if fid is not a ancestor of @mo;
 *
 * returns EREMOTE if remote object is found, fid of remote object is saved to
 * @fid;
 *
 * returns < 0: if error
 */
int mdd_is_subdir(const struct lu_env *env, struct md_object *mo,
		  const struct lu_fid *fid, struct lu_fid *sfid)
{
	struct mdd_device *mdd = mdo2mdd(mo);
	struct lu_attr *attr = MDD_ENV_VAR(env, cattr);
	int rc;
	ENTRY;

	if (!S_ISDIR(mdd_object_type(md2mdd_obj(mo))))
		RETURN(0);

	rc = mdd_la_get(env, md2mdd_obj(mo), attr, BYPASS_CAPA);
	if (rc != 0)
		RETURN(rc);

	rc = mdd_is_parent(env, mdd, md2mdd_obj(mo), attr, fid, sfid);
	if (rc == 0) {
		/* found root */
		fid_zero(sfid);
	} else if (rc == 1) {
		/* found @fid is parent */
		*sfid = *fid;
		rc = 0;
	}
	RETURN(rc);
}

/*
 * Check that @dir contains no entries except (possibly) dot and dotdot.
 *
 * Returns:
 *
 *             0        empty
 *      -ENOTDIR        not a directory object
 *    -ENOTEMPTY        not empty
 *           -ve        other error
 *
 */
static int mdd_dir_is_empty(const struct lu_env *env,
                            struct mdd_object *dir)
{
	struct dt_it     *it;
	struct dt_object *obj;
	const struct dt_it_ops *iops;
	int result;
	ENTRY;

	obj = mdd_object_child(dir);
	if (!dt_try_as_dir(env, obj))
		RETURN(-ENOTDIR);

	iops = &obj->do_index_ops->dio_it;
	it = iops->init(env, obj, LUDA_64BITHASH, BYPASS_CAPA);
	if (!IS_ERR(it)) {
		result = iops->get(env, it, (const struct dt_key *)"");
		if (result > 0) {
			int i;
			for (result = 0, i = 0; result == 0 && i < 3; ++i)
				result = iops->next(env, it);
			if (result == 0)
				result = -ENOTEMPTY;
			else if (result == 1)
				result = 0;
		} else if (result == 0)
			/*
			 * Huh? Index contains no zero key?
			 */
			result = -EIO;

		iops->put(env, it);
		iops->fini(env, it);
	} else
		result = PTR_ERR(it);
	RETURN(result);
}

/**
 * Determine if the target object can be hard linked, and right now it only
 * checks if the link count reach the maximum limit. Note: for ldiskfs, the
 * directory nlink count might exceed the maximum link count(see
 * osd_object_ref_add), so it only check nlink for non-directories.
 *
 * \param[in] env	thread environment
 * \param[in] obj	object being linked to
 * \param[in] la	attributes of \a obj
 *
 * \retval		0 if \a obj can be hard linked
 * \retval		negative error if \a obj is a directory or has too
 *			many links
 */
static int __mdd_may_link(const struct lu_env *env, struct mdd_object *obj,
			  const struct lu_attr *la)
{
	struct mdd_device *m = mdd_obj2mdd_dev(obj);
	ENTRY;

	LASSERT(la != NULL);

	/* Subdir count limitation can be broken through
	 * (see osd_object_ref_add), so only check non-directory here. */
	if (!S_ISDIR(la->la_mode) &&
	    la->la_nlink >= m->mdd_dt_conf.ddp_max_nlink)
		RETURN(-EMLINK);

	RETURN(0);
}

/**
 * Check whether it may create the cobj under the pobj.
 *
 * \param[in] env	execution environment
 * \param[in] pobj	the parent directory
 * \param[in] pattr	the attribute of the parent directory
 * \param[in] cobj	the child to be created
 * \param[in] check_perm	if check WRITE|EXEC permission for parent
 *
 * \retval		= 0 create the child under this dir is allowed
 * \retval              negative errno create the child under this dir is
 *                      not allowed
 */
int mdd_may_create(const struct lu_env *env, struct mdd_object *pobj,
		   const struct lu_attr *pattr, struct mdd_object *cobj,
		   bool check_perm)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct lu_buf	*xbuf;
	int rc = 0;
	ENTRY;

	if (cobj && mdd_object_exists(cobj))
		RETURN(-EEXIST);

	if (mdd_is_dead_obj(pobj))
		RETURN(-ENOENT);

	/* If the parent is a sub-stripe, check whether it is dead */
	xbuf = mdd_buf_get(env, info->mti_key, sizeof(info->mti_key));
	rc = mdo_xattr_get(env, pobj, xbuf, XATTR_NAME_LMV,
			   mdd_object_capa(env, pobj));
	if (unlikely(rc > 0)) {
		struct lmv_mds_md_v1  *lmv1 = xbuf->lb_buf;

		if (le32_to_cpu(lmv1->lmv_magic) == LMV_MAGIC_STRIPE &&
		    le32_to_cpu(lmv1->lmv_hash_type) & LMV_HASH_FLAG_DEAD)
			RETURN(-ESTALE);
	}
	rc = 0;

	if (check_perm)
		rc = mdd_permission_internal_locked(env, pobj, pattr,
						    MAY_WRITE | MAY_EXEC,
						    MOR_TGT_PARENT);
	RETURN(rc);
}

/*
 * Check whether can unlink from the pobj in the case of "cobj == NULL".
 */
int mdd_may_unlink(const struct lu_env *env, struct mdd_object *pobj,
		   const struct lu_attr *pattr, const struct lu_attr *attr)
{
	int rc;
	ENTRY;

	if (mdd_is_dead_obj(pobj))
		RETURN(-ENOENT);

	if (attr->la_flags & (LUSTRE_APPEND_FL | LUSTRE_IMMUTABLE_FL))
		RETURN(-EPERM);

	rc = mdd_permission_internal_locked(env, pobj, pattr,
					    MAY_WRITE | MAY_EXEC,
					    MOR_TGT_PARENT);
	if (rc != 0)
		RETURN(rc);

	if (pattr->la_flags & LUSTRE_APPEND_FL)
		RETURN(-EPERM);

	RETURN(rc);
}

/*
 * pobj == NULL is remote ops case, under such case, pobj's
 * VTX feature has been checked already, no need check again.
 */
static inline int mdd_is_sticky(const struct lu_env *env,
				struct mdd_object *pobj,
				const struct lu_attr *pattr,
				struct mdd_object *cobj,
				const struct lu_attr *cattr)
{
	struct lu_ucred *uc = lu_ucred_assert(env);

	if (pobj != NULL) {
		LASSERT(pattr != NULL);
		if (!(pattr->la_mode & S_ISVTX) ||
		    (pattr->la_uid == uc->uc_fsuid))
			return 0;
	}

	LASSERT(cattr != NULL);
	if (cattr->la_uid == uc->uc_fsuid)
		return 0;

	return !md_capable(uc, CFS_CAP_FOWNER);
}

static int mdd_may_delete_entry(const struct lu_env *env,
				struct mdd_object *pobj,
				const struct lu_attr *pattr,
				int check_perm)
{
	ENTRY;

	LASSERT(pobj != NULL);
	if (!mdd_object_exists(pobj))
		RETURN(-ENOENT);

	if (mdd_is_dead_obj(pobj))
		RETURN(-ENOENT);

	if (check_perm) {
		int rc;
		rc = mdd_permission_internal_locked(env, pobj, pattr,
					    MAY_WRITE | MAY_EXEC,
					    MOR_TGT_PARENT);
		if (rc)
			RETURN(rc);
	}

	if (pattr->la_flags & LUSTRE_APPEND_FL)
		RETURN(-EPERM);

	RETURN(0);
}

/*
 * Check whether it may delete the cobj from the pobj.
 * pobj maybe NULL
 */
int mdd_may_delete(const struct lu_env *env, struct mdd_object *tpobj,
		   const struct lu_attr *tpattr, struct mdd_object *tobj,
		   const struct lu_attr *tattr, const struct lu_attr *cattr,
		   int check_perm, int check_empty)
{
	int rc = 0;
	ENTRY;

	if (tpobj) {
		LASSERT(tpattr != NULL);
		rc = mdd_may_delete_entry(env, tpobj, tpattr, check_perm);
		if (rc != 0)
			RETURN(rc);
	}

	if (tobj == NULL)
		RETURN(0);

	if (!mdd_object_exists(tobj))
		RETURN(-ENOENT);

	if (mdd_is_dead_obj(tobj))
		RETURN(-ESTALE);

	if (mdd_is_sticky(env, tpobj, tpattr, tobj, tattr))
		RETURN(-EPERM);

	if (tattr->la_flags & (LUSTRE_APPEND_FL | LUSTRE_IMMUTABLE_FL))
		RETURN(-EPERM);

	/* additional check the rename case */
	if (cattr) {
		if (S_ISDIR(cattr->la_mode)) {
			struct mdd_device *mdd = mdo2mdd(&tobj->mod_obj);

			if (!S_ISDIR(tattr->la_mode))
				RETURN(-ENOTDIR);

			if (lu_fid_eq(mdo2fid(tobj), &mdd->mdd_root_fid))
				RETURN(-EBUSY);
		} else if (S_ISDIR(tattr->la_mode))
			RETURN(-EISDIR);
	}

	if (S_ISDIR(tattr->la_mode) && check_empty)
		rc = mdd_dir_is_empty(env, tobj);

	RETURN(rc);
}

/**
 * Check whether it can create the link file(linked to @src_obj) under
 * the target directory(@tgt_obj), and src_obj has been locked by
 * mdd_write_lock.
 *
 * \param[in] env	execution environment
 * \param[in] tgt_obj	the target directory
 * \param[in] tattr	attributes of target directory
 * \param[in] lname	the link name
 * \param[in] src_obj	source object for link
 * \param[in] cattr	attributes for source object
 *
 * \retval		= 0 it is allowed to create the link file under tgt_obj
 * \retval              negative error not allowed to create the link file
 */
static int mdd_link_sanity_check(const struct lu_env *env,
				 struct mdd_object *tgt_obj,
				 const struct lu_attr *tattr,
				 const struct lu_name *lname,
				 struct mdd_object *src_obj,
				 const struct lu_attr *cattr)
{
        struct mdd_device *m = mdd_obj2mdd_dev(src_obj);
        int rc = 0;
        ENTRY;

        if (!mdd_object_exists(src_obj))
                RETURN(-ENOENT);

        if (mdd_is_dead_obj(src_obj))
                RETURN(-ESTALE);

        /* Local ops, no lookup before link, check filename length here. */
	rc = mdd_name_check(m, lname);
	if (rc < 0)
		RETURN(rc);

	if (cattr->la_flags & (LUSTRE_IMMUTABLE_FL | LUSTRE_APPEND_FL))
		RETURN(-EPERM);

	if (S_ISDIR(mdd_object_type(src_obj)))
		RETURN(-EPERM);

	LASSERT(src_obj != tgt_obj);
	rc = mdd_may_create(env, tgt_obj, tattr, NULL, true);
	if (rc != 0)
		RETURN(rc);

	rc = __mdd_may_link(env, src_obj, cattr);

	RETURN(rc);
}

static int __mdd_index_delete_only(const struct lu_env *env, struct mdd_object *pobj,
				   const char *name, struct thandle *handle,
				   struct lustre_capa *capa)
{
	struct dt_object *next = mdd_object_child(pobj);
	int rc;
	ENTRY;

	if (dt_try_as_dir(env, next))
		rc = dt_delete(env, next, (struct dt_key *)name, handle, capa);
	else
		rc = -ENOTDIR;

	RETURN(rc);
}

static int __mdd_index_insert_only(const struct lu_env *env,
				   struct mdd_object *pobj,
				   const struct lu_fid *lf, __u32 type,
				   const char *name,
				   struct thandle *handle,
				   struct lustre_capa *capa)
{
	struct dt_object *next = mdd_object_child(pobj);
	int               rc;
	ENTRY;

	if (dt_try_as_dir(env, next)) {
		struct dt_insert_rec	*rec = &mdd_env_info(env)->mti_dt_rec;
		struct lu_ucred		*uc  = lu_ucred_check(env);
		int			 ignore_quota;

		rec->rec_fid = lf;
		rec->rec_type = type;
		ignore_quota = uc ? uc->uc_cap & CFS_CAP_SYS_RESOURCE_MASK : 1;
		rc = dt_insert(env, next, (const struct dt_rec *)rec,
			       (const struct dt_key *)name, handle, capa,
			       ignore_quota);
	} else {
		rc = -ENOTDIR;
	}
	RETURN(rc);
}

/* insert named index, add reference if isdir */
static int __mdd_index_insert(const struct lu_env *env, struct mdd_object *pobj,
			      const struct lu_fid *lf, __u32 type,
			      const char *name, struct thandle *handle,
			      struct lustre_capa *capa)
{
	int rc;
	ENTRY;

	rc = __mdd_index_insert_only(env, pobj, lf, type, name, handle, capa);
	if (rc == 0 && S_ISDIR(type)) {
		mdd_write_lock(env, pobj, MOR_TGT_PARENT);
		mdo_ref_add(env, pobj, handle);
		mdd_write_unlock(env, pobj);
	}

	RETURN(rc);
}

/* delete named index, drop reference if isdir */
static int __mdd_index_delete(const struct lu_env *env, struct mdd_object *pobj,
                              const char *name, int is_dir, struct thandle *handle,
                              struct lustre_capa *capa)
{
        int               rc;
        ENTRY;

        rc = __mdd_index_delete_only(env, pobj, name, handle, capa);
        if (rc == 0 && is_dir) {
                mdd_write_lock(env, pobj, MOR_TGT_PARENT);
                mdo_ref_del(env, pobj, handle);
                mdd_write_unlock(env, pobj);
        }

        RETURN(rc);
}

static int mdd_llog_record_calc_size(const struct lu_env *env,
				     const struct lu_name *tname,
				     const struct lu_name *sname)
{
	const struct lu_ucred	*uc = lu_ucred(env);
	enum changelog_rec_flags crf = 0;
	size_t			 hdr_size = sizeof(struct llog_changelog_rec) -
					    sizeof(struct changelog_rec);

	if (sname != NULL)
		crf |= CLF_RENAME;

	if (uc != NULL && uc->uc_jobid[0] != '\0')
		crf |= CLF_JOBID;

	return llog_data_len(hdr_size + changelog_rec_offset(crf) +
			     (tname != NULL ? tname->ln_namelen : 0) +
			     (sname != NULL ? 1 + sname->ln_namelen : 0));
}

int mdd_declare_changelog_store(const struct lu_env *env,
				struct mdd_device *mdd,
				const struct lu_name *tname,
				const struct lu_name *sname,
				struct thandle *handle)
{
	struct obd_device		*obd = mdd2obd_dev(mdd);
	struct llog_ctxt		*ctxt;
	struct llog_changelog_rec	*rec;
	struct lu_buf			*buf;
	int				 reclen;
	int				 rc;

	/* Not recording */
	if (!(mdd->mdd_cl.mc_flags & CLM_ON))
		return 0;

	reclen = mdd_llog_record_calc_size(env, tname, sname);
	buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mti_big_buf, reclen);
	if (buf->lb_buf == NULL)
		return -ENOMEM;

	rec = buf->lb_buf;
	rec->cr_hdr.lrh_len = reclen;
	rec->cr_hdr.lrh_type = CHANGELOG_REC;

	ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
	if (ctxt == NULL)
		return -ENXIO;

	rc = llog_declare_add(env, ctxt->loc_handle, &rec->cr_hdr, handle);
	llog_ctxt_put(ctxt);

	return rc;
}

/** Add a changelog entry \a rec to the changelog llog
 * \param mdd
 * \param rec
 * \param handle - currently ignored since llogs start their own transaction;
 *		this will hopefully be fixed in llog rewrite
 * \retval 0 ok
 */
int mdd_changelog_store(const struct lu_env *env, struct mdd_device *mdd,
			struct llog_changelog_rec *rec, struct thandle *th)
{
	struct obd_device	*obd = mdd2obd_dev(mdd);
	struct llog_ctxt	*ctxt;
	int			 rc;

	rec->cr_hdr.lrh_len = llog_data_len(sizeof(*rec) +
					    changelog_rec_varsize(&rec->cr));

	/* llog_lvfs_write_rec sets the llog tail len */
	rec->cr_hdr.lrh_type = CHANGELOG_REC;
	rec->cr.cr_time = cl_time();

	spin_lock(&mdd->mdd_cl.mc_lock);
	/* NB: I suppose it's possible llog_add adds out of order wrt cr_index,
	 * but as long as the MDD transactions are ordered correctly for e.g.
	 * rename conflicts, I don't think this should matter. */
	rec->cr.cr_index = ++mdd->mdd_cl.mc_index;
	spin_unlock(&mdd->mdd_cl.mc_lock);

	ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
	if (ctxt == NULL)
		return -ENXIO;

	/* nested journal transaction */
	rc = llog_add(env, ctxt->loc_handle, &rec->cr_hdr, NULL, th);
	llog_ctxt_put(ctxt);
	if (rc > 0)
		rc = 0;

	return rc;
}

static void mdd_changelog_rec_ext_rename(struct changelog_rec *rec,
					 const struct lu_fid *sfid,
					 const struct lu_fid *spfid,
					 const struct lu_name *sname)
{
	struct changelog_ext_rename	*rnm = changelog_rec_rename(rec);
	size_t				 extsize = sname->ln_namelen + 1;

	LASSERT(sfid != NULL);
	LASSERT(spfid != NULL);
	LASSERT(sname != NULL);

	rnm->cr_sfid = *sfid;
	rnm->cr_spfid = *spfid;

	changelog_rec_name(rec)[rec->cr_namelen] = '\0';
	strlcpy(changelog_rec_sname(rec), sname->ln_name, extsize);
	rec->cr_namelen += extsize;
}

void mdd_changelog_rec_ext_jobid(struct changelog_rec *rec, const char *jobid)
{
	struct changelog_ext_jobid	*jid = changelog_rec_jobid(rec);

	if (jobid == NULL || jobid[0] == '\0')
		return;

	strlcpy(jid->cr_jobid, jobid, sizeof(jid->cr_jobid));
}

/** Store a namespace change changelog record
 * If this fails, we must fail the whole transaction; we don't
 * want the change to commit without the log entry.
 * \param target - mdd_object of change
 * \param tpfid - target parent dir/object fid
 * \param sfid - source object fid
 * \param spfid - source parent fid
 * \param tname - target name string
 * \param sname - source name string
 * \param handle - transacion handle
 */
int mdd_changelog_ns_store(const struct lu_env *env,
			   struct mdd_device *mdd,
			   enum changelog_rec_type type,
			   enum changelog_rec_flags crf,
			   struct mdd_object *target,
			   const struct lu_fid *tpfid,
			   const struct lu_fid *sfid,
			   const struct lu_fid *spfid,
			   const struct lu_name *tname,
			   const struct lu_name *sname,
			   struct thandle *handle)
{
	const struct lu_ucred		*uc = lu_ucred(env);
	struct llog_changelog_rec	*rec;
	struct lu_buf			*buf;
	int				 reclen;
	int				 rc;
	ENTRY;

	/* Not recording */
	if (!(mdd->mdd_cl.mc_flags & CLM_ON))
		RETURN(0);

	if ((mdd->mdd_cl.mc_mask & (1 << type)) == 0)
		RETURN(0);

	LASSERT(tpfid != NULL);
	LASSERT(tname != NULL);
	LASSERT(handle != NULL);

	reclen = mdd_llog_record_calc_size(env, tname, sname);
	buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mti_big_buf, reclen);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);
	rec = buf->lb_buf;

	crf &= CLF_FLAGMASK;

	if (uc != NULL && uc->uc_jobid[0] != '\0')
		crf |= CLF_JOBID;

	if (sname != NULL)
		crf |= CLF_RENAME;
	else
		crf |= CLF_VERSION;

	rec->cr.cr_flags = crf;
	rec->cr.cr_type = (__u32)type;
	rec->cr.cr_pfid = *tpfid;
	rec->cr.cr_namelen = tname->ln_namelen;
	memcpy(changelog_rec_name(&rec->cr), tname->ln_name, tname->ln_namelen);

	if (crf & CLF_RENAME)
		mdd_changelog_rec_ext_rename(&rec->cr, sfid, spfid, sname);

	if (crf & CLF_JOBID)
		mdd_changelog_rec_ext_jobid(&rec->cr, uc->uc_jobid);

	if (likely(target != NULL)) {
		rec->cr.cr_tfid = *mdo2fid(target);
		target->mod_cltime = cfs_time_current_64();
	} else {
		fid_zero(&rec->cr.cr_tfid);
	}

	rc = mdd_changelog_store(env, mdd, rec, handle);
	if (rc < 0) {
		CERROR("changelog failed: rc=%d, op%d %s c"DFID" p"DFID"\n",
			rc, type, tname->ln_name, PFID(sfid), PFID(tpfid));
		return -EFAULT;
	}

	return 0;
}

static int __mdd_links_add(const struct lu_env *env,
			   struct mdd_object *mdd_obj,
			   struct linkea_data *ldata,
			   const struct lu_name *lname,
			   const struct lu_fid *pfid,
			   int first, int check)
{
	int rc;

	if (ldata->ld_leh == NULL) {
		rc = first ? -ENODATA : mdd_links_read(env, mdd_obj, ldata);
		if (rc) {
			if (rc != -ENODATA)
				return rc;
			rc = linkea_data_new(ldata,
					     &mdd_env_info(env)->mti_link_buf);
			if (rc)
				return rc;
		}
	}

	if (check) {
		rc = linkea_links_find(ldata, lname, pfid);
		if (rc && rc != -ENOENT)
			return rc;
		if (rc == 0)
			return -EEXIST;
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LINKEA_MORE)) {
		struct lu_fid *tfid = &mdd_env_info(env)->mti_fid2;

		*tfid = *pfid;
		tfid->f_ver = ~0;
		linkea_add_buf(ldata, lname, tfid);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LINKEA_MORE2))
		linkea_add_buf(ldata, lname, pfid);

	return linkea_add_buf(ldata, lname, pfid);
}

static int __mdd_links_del(const struct lu_env *env,
			   struct mdd_object *mdd_obj,
			   struct linkea_data *ldata,
			   const struct lu_name *lname,
			   const struct lu_fid *pfid)
{
	int rc;

	if (ldata->ld_leh == NULL) {
		rc = mdd_links_read(env, mdd_obj, ldata);
		if (rc)
			return rc;
	}

	rc = linkea_links_find(ldata, lname, pfid);
	if (rc)
		return rc;

	linkea_del_buf(ldata, lname);
	return 0;
}

static int mdd_linkea_prepare(const struct lu_env *env,
			      struct mdd_object *mdd_obj,
			      const struct lu_fid *oldpfid,
			      const struct lu_name *oldlname,
			      const struct lu_fid *newpfid,
			      const struct lu_name *newlname,
			      int first, int check,
			      struct linkea_data *ldata)
{
	int rc = 0;
	int rc2 = 0;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_FID_IGIF))
		return 0;

	LASSERT(oldpfid != NULL || newpfid != NULL);

	if (mdd_obj->mod_flags & DEAD_OBJ) {
		/* Prevent linkea to be updated which is NOT necessary. */
		ldata->ld_reclen = 0;
		/* No more links, don't bother */
		RETURN(0);
	}

	if (oldpfid != NULL) {
		rc = __mdd_links_del(env, mdd_obj, ldata, oldlname, oldpfid);
		if (rc) {
			if ((check == 1) ||
			    (rc != -ENODATA && rc != -ENOENT))
				RETURN(rc);
			/* No changes done. */
			rc = 0;
		}
	}

	/* If renaming, add the new record */
	if (newpfid != NULL) {
		/* even if the add fails, we still delete the out-of-date
		 * old link */
		rc2 = __mdd_links_add(env, mdd_obj, ldata, newlname, newpfid,
				      first, check);
	}

	rc = rc != 0 ? rc : rc2;

	RETURN(rc);
}

int mdd_links_rename(const struct lu_env *env,
		     struct mdd_object *mdd_obj,
		     const struct lu_fid *oldpfid,
		     const struct lu_name *oldlname,
		     const struct lu_fid *newpfid,
		     const struct lu_name *newlname,
		     struct thandle *handle,
		     struct linkea_data *ldata,
		     int first, int check)
{
	int rc = 0;
	ENTRY;

	if (ldata == NULL) {
		ldata = &mdd_env_info(env)->mti_link_data;
		memset(ldata, 0, sizeof(*ldata));
		rc = mdd_linkea_prepare(env, mdd_obj, oldpfid, oldlname,
					newpfid, newlname, first, check,
					ldata);
		if (rc != 0)
			GOTO(out, rc);
	}

	if (ldata->ld_reclen != 0)
		rc = mdd_links_write(env, mdd_obj, ldata, handle);
	EXIT;
out:
	if (rc != 0) {
		int error = 1;
		if (rc == -EOVERFLOW || rc == -ENOSPC)
			error = 0;
		if (oldpfid == NULL)
			CDEBUG(error ? D_ERROR : D_OTHER,
			       "link_ea add '%.*s' failed %d "DFID"\n",
			       newlname->ln_namelen, newlname->ln_name,
			       rc, PFID(mdd_object_fid(mdd_obj)));
		else if (newpfid == NULL)
			CDEBUG(error ? D_ERROR : D_OTHER,
			       "link_ea del '%.*s' failed %d "DFID"\n",
			       oldlname->ln_namelen, oldlname->ln_name,
			       rc, PFID(mdd_object_fid(mdd_obj)));
		else
			CDEBUG(error ? D_ERROR : D_OTHER,
			       "link_ea rename '%.*s'->'%.*s' failed %d "
			       DFID"\n",
			       oldlname->ln_namelen, oldlname->ln_name,
			       newlname->ln_namelen, newlname->ln_name,
			       rc, PFID(mdd_object_fid(mdd_obj)));
	}

	if (ldata->ld_buf && ldata->ld_buf->lb_len > OBD_ALLOC_BIG)
		/* if we vmalloced a large buffer drop it */
		lu_buf_free(ldata->ld_buf);

	return rc;
}

static inline int mdd_links_add(const struct lu_env *env,
				struct mdd_object *mdd_obj,
				const struct lu_fid *pfid,
				const struct lu_name *lname,
				struct thandle *handle,
				struct linkea_data *ldata, int first)
{
	return mdd_links_rename(env, mdd_obj, NULL, NULL,
				pfid, lname, handle, ldata, first, 0);
}

static inline int mdd_links_del(const struct lu_env *env,
				struct mdd_object *mdd_obj,
				const struct lu_fid *pfid,
				const struct lu_name *lname,
				struct thandle *handle)
{
	return mdd_links_rename(env, mdd_obj, pfid, lname,
				NULL, NULL, handle, NULL, 0, 0);
}

/** Read the link EA into a temp buffer.
 * Uses the mdd_thread_info::mti_big_buf since it is generally large.
 * A pointer to the buffer is stored in \a ldata::ld_buf.
 *
 * \retval 0 or error
 */
int mdd_links_read(const struct lu_env *env, struct mdd_object *mdd_obj,
		   struct linkea_data *ldata)
{
	int rc;

	if (!mdd_object_exists(mdd_obj))
		return -ENODATA;

	/* First try a small buf */
	LASSERT(env != NULL);
	ldata->ld_buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mti_link_buf,
					       PAGE_CACHE_SIZE);
	if (ldata->ld_buf->lb_buf == NULL)
		return -ENOMEM;

	rc = mdo_xattr_get(env, mdd_obj, ldata->ld_buf, XATTR_NAME_LINK,
			  BYPASS_CAPA);
	if (rc == -ERANGE) {
		/* Buf was too small, figure out what we need. */
		lu_buf_free(ldata->ld_buf);
		rc = mdo_xattr_get(env, mdd_obj, ldata->ld_buf,
				   XATTR_NAME_LINK, BYPASS_CAPA);
		if (rc < 0)
			return rc;
		ldata->ld_buf = lu_buf_check_and_alloc(ldata->ld_buf, rc);
		if (ldata->ld_buf->lb_buf == NULL)
			return -ENOMEM;
		rc = mdo_xattr_get(env, mdd_obj, ldata->ld_buf,
				  XATTR_NAME_LINK, BYPASS_CAPA);
	}
	if (rc < 0) {
		lu_buf_free(ldata->ld_buf);
		ldata->ld_buf = NULL;
		return rc;
	}

	return linkea_init(ldata);
}

/** Read the link EA into a temp buffer.
 * Uses the name_buf since it is generally large.
 * \retval IS_ERR err
 * \retval ptr to \a lu_buf (always \a mti_big_buf)
 */
struct lu_buf *mdd_links_get(const struct lu_env *env,
			     struct mdd_object *mdd_obj)
{
	struct linkea_data ldata = { NULL };
	int rc;

	rc = mdd_links_read(env, mdd_obj, &ldata);
	return rc ? ERR_PTR(rc) : ldata.ld_buf;
}

int mdd_links_write(const struct lu_env *env, struct mdd_object *mdd_obj,
		    struct linkea_data *ldata, struct thandle *handle)
{
	const struct lu_buf *buf = mdd_buf_get_const(env, ldata->ld_buf->lb_buf,
						     ldata->ld_leh->leh_len);
	int		    rc;

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_LINKEA))
		return 0;

	rc = mdo_xattr_set(env, mdd_obj, buf, XATTR_NAME_LINK, 0, handle,
			   mdd_object_capa(env, mdd_obj));
	if (unlikely(rc == -ENOSPC) && S_ISREG(mdd_object_type(mdd_obj)) &&
	    mdd_object_remote(mdd_obj) == 0) {
		struct lfsck_request *lr = &mdd_env_info(env)->mti_lr;

		/* XXX: If the linkEA is overflow, then we need to notify the
		 *	namespace LFSCK to skip "nlink" attribute verification
		 *	on this object to avoid the "nlink" to be shrinked by
		 *	wrong. It may be not good an interaction with LFSCK
		 *	like this. We will consider to replace it with other
		 *	mechanism in future. LU-5802. */
		lfsck_pack_rfa(lr, mdo2fid(mdd_obj), LE_SKIP_NLINK,
			       LFSCK_TYPE_NAMESPACE);
		lfsck_in_notify(env, mdo2mdd(&mdd_obj->mod_obj)->mdd_bottom,
				lr, handle);
	}

	return rc;
}

int mdd_declare_links_add(const struct lu_env *env, struct mdd_object *mdd_obj,
			  struct thandle *handle, struct linkea_data *ldata,
			  enum mdd_links_add_overflow overflow)
{
	int	rc;
	int	ea_len;
	void	*linkea;

	if (ldata != NULL && ldata->ld_leh != NULL) {
		ea_len = ldata->ld_leh->leh_len;
		linkea = ldata->ld_buf->lb_buf;
	} else {
		ea_len = DEFAULT_LINKEA_SIZE;
		linkea = NULL;
	}

	/* XXX: max size? */
	rc = mdo_declare_xattr_set(env, mdd_obj,
				   mdd_buf_get_const(env, linkea, ea_len),
				   XATTR_NAME_LINK, 0, handle);
	if (rc != 0)
		return rc;

	if (mdd_object_remote(mdd_obj) == 0 && overflow == MLAO_CHECK) {
		struct lfsck_request *lr = &mdd_env_info(env)->mti_lr;

		/* XXX: If the linkEA is overflow, then we need to notify the
		 *	namespace LFSCK to skip "nlink" attribute verification
		 *	on this object to avoid the "nlink" to be shrinked by
		 *	wrong. It may be not good an interaction with LFSCK
		 *	like this. We will consider to replace it with other
		 *	mechanism in future. LU-5802. */
		lfsck_pack_rfa(lr, mdo2fid(mdd_obj), LE_SKIP_NLINK_DECLARE,
			       LFSCK_TYPE_NAMESPACE);
		rc = lfsck_in_notify(env,
				     mdo2mdd(&mdd_obj->mod_obj)->mdd_bottom,
				     lr, handle);
	}

	return rc;
}

static inline int mdd_declare_links_del(const struct lu_env *env,
					struct mdd_object *c,
					struct thandle *handle)
{
	int rc = 0;

	/* For directory, the linkEA will be removed together
	 * with the object. */
	if (!S_ISDIR(mdd_object_type(c)))
		rc = mdd_declare_links_add(env, c, handle, NULL, MLAO_IGNORE);

	return rc;
}

static int mdd_declare_link(const struct lu_env *env,
			    struct mdd_device *mdd,
			    struct mdd_object *p,
			    struct mdd_object *c,
			    const struct lu_name *name,
			    struct thandle *handle,
			    struct lu_attr *la,
			    struct linkea_data *data)
{
	int rc;

	rc = mdo_declare_index_insert(env, p, mdo2fid(c), mdd_object_type(c),
				      name->ln_name, handle);
	if (rc != 0)
		return rc;

	rc = mdo_declare_ref_add(env, c, handle);
	if (rc != 0)
		return rc;

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_MORE_NLINK)) {
		rc = mdo_declare_ref_add(env, c, handle);
		if (rc != 0)
			return rc;
	}

	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdo_declare_attr_set(env, p, la, handle);
	if (rc != 0)
		return rc;

	la->la_valid = LA_CTIME;
	rc = mdo_declare_attr_set(env, c, la, handle);
	if (rc != 0)
		return rc;

	rc = mdd_declare_links_add(env, c, handle, data,
			S_ISREG(mdd_object_type(c)) ? MLAO_CHECK : MLAO_IGNORE);
	if (rc != 0)
		return rc;

	rc = mdd_declare_changelog_store(env, mdd, name, NULL, handle);

	return rc;
}

static int mdd_link(const struct lu_env *env, struct md_object *tgt_obj,
                    struct md_object *src_obj, const struct lu_name *lname,
                    struct md_attr *ma)
{
        const char *name = lname->ln_name;
        struct lu_attr    *la = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_tobj = md2mdd_obj(tgt_obj);
        struct mdd_object *mdd_sobj = md2mdd_obj(src_obj);
	struct lu_attr	  *cattr = MDD_ENV_VAR(env, cattr);
	struct lu_attr	  *tattr = MDD_ENV_VAR(env, tattr);
        struct mdd_device *mdd = mdo2mdd(src_obj);
        struct thandle *handle;
	struct linkea_data *ldata = &mdd_env_info(env)->mti_link_data;
	int rc;
	ENTRY;

	rc = mdd_la_get(env, mdd_sobj, cattr, BYPASS_CAPA);
	if (rc != 0)
		RETURN(rc);

	rc = mdd_la_get(env, mdd_tobj, tattr, BYPASS_CAPA);
	if (rc != 0)
		RETURN(rc);

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                GOTO(out_pending, rc = PTR_ERR(handle));

	memset(ldata, 0, sizeof(*ldata));

	LASSERT(ma->ma_attr.la_valid & LA_CTIME);
	la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

	rc = mdd_declare_link(env, mdd, mdd_tobj, mdd_sobj, lname, handle,
			      la, ldata);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

	mdd_write_lock(env, mdd_sobj, MOR_TGT_CHILD);
	rc = mdd_link_sanity_check(env, mdd_tobj, tattr, lname, mdd_sobj,
				   cattr);
	if (rc)
		GOTO(out_unlock, rc);

	if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LESS_NLINK)) {
		rc = mdo_ref_add(env, mdd_sobj, handle);
		if (rc != 0)
			GOTO(out_unlock, rc);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_MORE_NLINK)) {
		rc = mdo_ref_add(env, mdd_sobj, handle);
		if (rc != 0)
			GOTO(out_unlock, rc);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DANGLING3)) {
		struct lu_fid tfid = *mdo2fid(mdd_sobj);

		tfid.f_oid++;
		rc = __mdd_index_insert_only(env, mdd_tobj, &tfid,
					     mdd_object_type(mdd_sobj),
					     name, handle,
					     mdd_object_capa(env, mdd_tobj));
	} else {
		rc = __mdd_index_insert_only(env, mdd_tobj, mdo2fid(mdd_sobj),
					     mdd_object_type(mdd_sobj),
					     name, handle,
					     mdd_object_capa(env, mdd_tobj));
	}

	if (rc != 0) {
		mdo_ref_del(env, mdd_sobj, handle);
		GOTO(out_unlock, rc);
	}

	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdd_update_time(env, mdd_tobj, tattr, la, handle);
	if (rc)
		GOTO(out_unlock, rc);

	la->la_valid = LA_CTIME;
	rc = mdd_update_time(env, mdd_sobj, cattr, la, handle);
	if (rc == 0) {
		rc = mdd_linkea_prepare(env, mdd_sobj, NULL, NULL,
					mdo2fid(mdd_tobj), lname, 0, 0,
					ldata);
		if (rc == 0)
			mdd_links_add(env, mdd_sobj, mdo2fid(mdd_tobj),
				      lname, handle, ldata, 0);
		/* The failure of links_add should not cause the link
		 * failure, reset rc here */
		rc = 0;
	}
        EXIT;
out_unlock:
        mdd_write_unlock(env, mdd_sobj);
        if (rc == 0)
		rc = mdd_changelog_ns_store(env, mdd, CL_HARDLINK, 0, mdd_sobj,
					    mdo2fid(mdd_tobj), NULL, NULL,
					    lname, NULL, handle);
stop:
	mdd_trans_stop(env, mdd, rc, handle);

	if (ldata->ld_buf && ldata->ld_buf->lb_len > OBD_ALLOC_BIG)
		/* if we vmalloced a large buffer drop it */
		lu_buf_free(ldata->ld_buf);
out_pending:
        return rc;
}

static int mdd_mark_dead_object(const struct lu_env *env,
				struct mdd_object *obj, struct thandle *handle,
				bool declare)
{
	struct lu_attr *attr = MDD_ENV_VAR(env, la_for_start);
	int rc;

	if (!declare)
		obj->mod_flags |= DEAD_OBJ;

	if (!S_ISDIR(mdd_object_type(obj)))
		return 0;

	attr->la_valid = LA_FLAGS;
	attr->la_flags = LUSTRE_SLAVE_DEAD_FL;

	if (declare)
		rc = mdo_declare_attr_set(env, obj, attr, handle);
	else
		rc = mdo_attr_set(env, obj, attr, handle,
				  mdd_object_capa(env, obj));

	return rc;
}

static int mdd_declare_finish_unlink(const struct lu_env *env,
				     struct mdd_object *obj,
				     struct thandle *handle)
{
	int	rc;

	rc = mdd_mark_dead_object(env, obj, handle, true);
	if (rc != 0)
		return rc;

	rc = orph_declare_index_insert(env, obj, mdd_object_type(obj), handle);
	if (rc != 0)
		return rc;

	rc = mdo_declare_destroy(env, obj, handle);
	if (rc != 0)
		return rc;

	return mdd_declare_links_del(env, obj, handle);
}

/* caller should take a lock before calling */
int mdd_finish_unlink(const struct lu_env *env,
		      struct mdd_object *obj, struct md_attr *ma,
		      const struct mdd_object *pobj,
		      const struct lu_name *lname,
		      struct thandle *th)
{
	int rc = 0;
        int is_dir = S_ISDIR(ma->ma_attr.la_mode);
        ENTRY;

        LASSERT(mdd_write_locked(env, obj) != 0);

	if (ma->ma_attr.la_nlink == 0 || is_dir) {
		rc = mdd_mark_dead_object(env, obj, th, false);
		if (rc != 0)
			RETURN(rc);

                /* add new orphan and the object
                 * will be deleted during mdd_close() */
                if (obj->mod_count) {
                        rc = __mdd_orphan_add(env, obj, th);
                        if (rc == 0)
                                CDEBUG(D_HA, "Object "DFID" is inserted into "
                                        "orphan list, open count = %d\n",
                                        PFID(mdd_object_fid(obj)),
                                        obj->mod_count);
                        else
                                CERROR("Object "DFID" fail to be an orphan, "
                                       "open count = %d, maybe cause failed "
                                       "open replay\n",
                                        PFID(mdd_object_fid(obj)),
                                        obj->mod_count);
                } else {
			rc = mdo_destroy(env, obj, th);
                }
	} else if (!is_dir) {
		/* old files may not have link ea; ignore errors */
		mdd_links_del(env, obj, mdo2fid(pobj), lname, th);
	}

	RETURN(rc);
}

/*
 * pobj maybe NULL
 * has mdd_write_lock on cobj already, but not on pobj yet
 */
int mdd_unlink_sanity_check(const struct lu_env *env, struct mdd_object *pobj,
			    const struct lu_attr *pattr,
			    struct mdd_object *cobj,
			    const struct lu_attr *cattr)
{
	int rc;
	ENTRY;

	rc = mdd_may_delete(env, pobj, pattr, cobj, cattr, NULL, 1, 1);

	RETURN(rc);
}

static int mdd_declare_unlink(const struct lu_env *env, struct mdd_device *mdd,
			      struct mdd_object *p, struct mdd_object *c,
			      const struct lu_name *name, struct md_attr *ma,
			      struct thandle *handle, int no_name, int is_dir)
{
	struct lu_attr	*la = &mdd_env_info(env)->mti_la_for_fix;
	int		 rc;

	if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DANGLING2)) {
		if (likely(no_name == 0)) {
			rc = mdo_declare_index_delete(env, p, name->ln_name,
						      handle);
			if (rc != 0)
				return rc;
		}

		if (is_dir != 0) {
			rc = mdo_declare_ref_del(env, p, handle);
			if (rc != 0)
				return rc;
		}
	}

	LASSERT(ma->ma_attr.la_valid & LA_CTIME);
	la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;
	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdo_declare_attr_set(env, p, la, handle);
	if (rc)
		return rc;

	if (c != NULL) {
		rc = mdo_declare_ref_del(env, c, handle);
		if (rc)
			return rc;

		rc = mdo_declare_ref_del(env, c, handle);
		if (rc)
			return rc;

		la->la_valid = LA_CTIME;
		rc = mdo_declare_attr_set(env, c, la, handle);
		if (rc)
			return rc;

		rc = mdd_declare_finish_unlink(env, c, handle);
		if (rc)
			return rc;

		/* FIXME: need changelog for remove entry */
		rc = mdd_declare_changelog_store(env, mdd, name, NULL, handle);
	}

	return rc;
}

/*
 * test if a file has an HSM archive
 * if HSM attributes are not found in ma update them from
 * HSM xattr
 */
static bool mdd_hsm_archive_exists(const struct lu_env *env,
				   struct mdd_object *obj,
				   struct md_attr *ma)
{
	ENTRY;

	if (!(ma->ma_valid & MA_HSM)) {
		/* no HSM MD provided, read xattr */
		struct lu_buf	*hsm_buf;
		const size_t	 buflen = sizeof(struct hsm_attrs);
		int		 rc;

		hsm_buf = mdd_buf_get(env, NULL, 0);
		lu_buf_alloc(hsm_buf, buflen);
		rc = mdo_xattr_get(env, obj, hsm_buf, XATTR_NAME_HSM,
				   mdd_object_capa(env, obj));
		rc = lustre_buf2hsm(hsm_buf->lb_buf, rc, &ma->ma_hsm);
		lu_buf_free(hsm_buf);
		if (rc < 0)
			RETURN(false);

		ma->ma_valid = MA_HSM;
	}
	if (ma->ma_hsm.mh_flags & HS_EXISTS)
		RETURN(true);
	RETURN(false);
}

/**
 * Delete name entry and the object.
 * Note: no_name == 1 means it only destory the object, i.e. name_entry
 * does not exist for this object, and it could only happen during resending
 * of remote unlink. see the comments in mdt_reint_unlink. Unfortunately, lname
 * is also needed in this case(needed by changelog), so we have to add another
 * parameter(no_name)here. XXX: this is only needed in DNE phase I, on Phase II,
 * the ENOENT failure should be able to be fixed by redo mechanism.
 */
static int mdd_unlink(const struct lu_env *env, struct md_object *pobj,
		      struct md_object *cobj, const struct lu_name *lname,
		      struct md_attr *ma, int no_name)
{
	const char *name = lname->ln_name;
	struct lu_attr *pattr = MDD_ENV_VAR(env, pattr);
	struct lu_attr *cattr = MDD_ENV_VAR(env, cattr);
	struct lu_attr *la = &mdd_env_info(env)->mti_la_for_fix;
	struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
	struct mdd_object *mdd_cobj = NULL;
	struct mdd_device *mdd = mdo2mdd(pobj);
	struct thandle    *handle;
	int rc, is_dir = 0;
	ENTRY;

	/* cobj == NULL means only delete name entry */
	if (likely(cobj != NULL)) {
		mdd_cobj = md2mdd_obj(cobj);
		if (mdd_object_exists(mdd_cobj) == 0)
			RETURN(-ENOENT);
	}

	rc = mdd_la_get(env, mdd_pobj, pattr, BYPASS_CAPA);
	if (rc)
		RETURN(rc);

	if (likely(mdd_cobj != NULL)) {
		/* fetch cattr */
		rc = mdd_la_get(env, mdd_cobj, cattr, BYPASS_CAPA);
		if (rc)
			RETURN(rc);

		is_dir = S_ISDIR(cattr->la_mode);
	}

	rc = mdd_unlink_sanity_check(env, mdd_pobj, pattr, mdd_cobj, cattr);
	if (rc)
                RETURN(rc);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	rc = mdd_declare_unlink(env, mdd, mdd_pobj, mdd_cobj,
				lname, ma, handle, no_name, is_dir);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop, rc);

	if (likely(mdd_cobj != NULL))
		mdd_write_lock(env, mdd_cobj, MOR_TGT_CHILD);

	if (likely(no_name == 0) && !OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DANGLING2)) {
		rc = __mdd_index_delete(env, mdd_pobj, name, is_dir, handle,
					mdd_object_capa(env, mdd_pobj));
		if (rc)
			GOTO(cleanup, rc);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_MUL_REF) ||
	    OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_NAMEENTRY))
		GOTO(cleanup, rc = 0);

	if (likely(mdd_cobj != NULL)) {
		rc = mdo_ref_del(env, mdd_cobj, handle);
		if (rc != 0) {
			__mdd_index_insert_only(env, mdd_pobj,
						mdo2fid(mdd_cobj),
						mdd_object_type(mdd_cobj),
						name, handle,
						mdd_object_capa(env, mdd_pobj));
			GOTO(cleanup, rc);
		}

		if (is_dir)
			/* unlink dot */
			mdo_ref_del(env, mdd_cobj, handle);

		/* fetch updated nlink */
		rc = mdd_la_get(env, mdd_cobj, cattr, BYPASS_CAPA);
		if (rc)
			GOTO(cleanup, rc);
	}

	LASSERT(ma->ma_attr.la_valid & LA_CTIME);
	la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdd_update_time(env, mdd_pobj, pattr, la, handle);
	if (rc)
		GOTO(cleanup, rc);

	/* Enough for only unlink the entry */
	if (unlikely(mdd_cobj == NULL))
		GOTO(stop, rc);

	if (cattr->la_nlink > 0 || mdd_cobj->mod_count > 0) {
		/* update ctime of an unlinked file only if it is still
		 * opened or a link still exists */
		la->la_valid = LA_CTIME;
		rc = mdd_update_time(env, mdd_cobj, cattr, la, handle);
		if (rc)
			GOTO(cleanup, rc);
	}

	/* XXX: this transfer to ma will be removed with LOD/OSP */
	ma->ma_attr = *cattr;
	ma->ma_valid |= MA_INODE;
	rc = mdd_finish_unlink(env, mdd_cobj, ma, mdd_pobj, lname, handle);

	/* fetch updated nlink */
	if (rc == 0)
		rc = mdd_la_get(env, mdd_cobj, cattr, BYPASS_CAPA);

	/* if object is removed then we can't get its attrs, use last get */
	if (cattr->la_nlink == 0) {
		ma->ma_attr = *cattr;
		ma->ma_valid |= MA_INODE;
	}
	EXIT;
cleanup:
	if (likely(mdd_cobj != NULL))
		mdd_write_unlock(env, mdd_cobj);

	if (rc == 0) {
		int cl_flags = 0;

		if (cattr->la_nlink == 0) {
			cl_flags |= CLF_UNLINK_LAST;
			/* search for an existing archive */
			if (mdd_hsm_archive_exists(env, mdd_cobj, ma))
				cl_flags |= CLF_UNLINK_HSM_EXISTS;
		}

		rc = mdd_changelog_ns_store(env, mdd,
			is_dir ? CL_RMDIR : CL_UNLINK, cl_flags,
			mdd_cobj, mdo2fid(mdd_pobj), NULL, NULL, lname, NULL,
			handle);
	}

stop:
	mdd_trans_stop(env, mdd, rc, handle);

	return rc;
}

/*
 * The permission has been checked when obj created, no need check again.
 */
static int mdd_cd_sanity_check(const struct lu_env *env,
                               struct mdd_object *obj)
{
        ENTRY;

        /* EEXIST check */
        if (!obj || mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

        RETURN(0);
}

static int mdd_create_data(const struct lu_env *env, struct md_object *pobj,
                           struct md_object *cobj, const struct md_op_spec *spec,
                           struct md_attr *ma)
{
	struct mdd_device *mdd = mdo2mdd(cobj);
	struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
	struct mdd_object *son = md2mdd_obj(cobj);
	struct thandle    *handle;
	const struct lu_buf *buf;
	struct lu_attr    *attr = MDD_ENV_VAR(env, cattr);
	struct dt_allocation_hint *hint = &mdd_env_info(env)->mti_hint;
	int		   rc;
	ENTRY;

	rc = mdd_cd_sanity_check(env, son);
	if (rc)
		RETURN(rc);

	if (!md_should_create(spec->sp_cr_flags))
		RETURN(0);

	/*
	 * there are following use cases for this function:
	 * 1) late striping - file was created with MDS_OPEN_DELAY_CREATE
	 *    striping can be specified or not
	 * 2) CMD?
	 */
	rc = mdd_la_get(env, son, attr, BYPASS_CAPA);
	if (rc)
		RETURN(rc);

	/* calling ->ah_make_hint() is used to transfer information from parent */
	mdd_object_make_hint(env, mdd_pobj, son, attr, spec, hint);

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                GOTO(out_free, rc = PTR_ERR(handle));

        /*
         * XXX: Setting the lov ea is not locked but setting the attr is locked?
         * Should this be fixed?
         */
	CDEBUG(D_OTHER, "ea %p/%u, cr_flags "LPO64", no_create %u\n",
	       spec->u.sp_ea.eadata, spec->u.sp_ea.eadatalen,
	       spec->sp_cr_flags, spec->no_create);

	if (spec->no_create || (spec->sp_cr_flags & MDS_OPEN_HAS_EA)) {
		buf = mdd_buf_get_const(env, spec->u.sp_ea.eadata,
					spec->u.sp_ea.eadatalen);
	} else {
		buf = &LU_BUF_NULL;
	}

	rc = dt_declare_xattr_set(env, mdd_object_child(son), buf,
				  XATTR_NAME_LOV, 0, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_declare_changelog_store(env, mdd, NULL, NULL, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop, rc);

	rc = dt_xattr_set(env, mdd_object_child(son), buf, XATTR_NAME_LOV,
			  0, handle, mdd_object_capa(env, son));

	if (rc)
		GOTO(stop, rc);

	rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, son, handle);

stop:
	mdd_trans_stop(env, mdd, rc, handle);
out_free:
	RETURN(rc);
}

static int mdd_declare_object_initialize(const struct lu_env *env,
					 struct mdd_object *parent,
					 struct mdd_object *child,
					 struct lu_attr *attr,
					 struct thandle *handle)
{
	int rc;
	ENTRY;

	/*
	 * inode mode has been set in creation time, and it's based on umask,
	 * la_mode and acl, don't set here again! (which will go wrong
	 * because below function doesn't consider umask).
	 * I'd suggest set all object attributes in creation time, see above.
	 */
	LASSERT(attr->la_valid & (LA_MODE | LA_TYPE));
	attr->la_valid &= ~(LA_MODE | LA_TYPE);
	rc = mdo_declare_attr_set(env, child, attr, handle);
	attr->la_valid |= LA_MODE | LA_TYPE;
	if (rc != 0 || !S_ISDIR(attr->la_mode))
		RETURN(rc);

	rc = mdo_declare_index_insert(env, child, mdo2fid(child), S_IFDIR,
				      dot, handle);
	if (rc != 0)
		RETURN(rc);

	rc = mdo_declare_ref_add(env, child, handle);
	if (rc != 0)
		RETURN(rc);

	rc = mdo_declare_index_insert(env, child, mdo2fid(parent), S_IFDIR,
				      dotdot, handle);

	RETURN(rc);
}

static int mdd_object_initialize(const struct lu_env *env,
				 const struct lu_fid *pfid,
				 struct mdd_object *child,
				 struct lu_attr *attr, struct thandle *handle,
				 const struct md_op_spec *spec)
{
	int rc = 0;
	ENTRY;

	if (S_ISDIR(attr->la_mode)) {
                /* Add "." and ".." for newly created dir */
                mdo_ref_add(env, child, handle);
                rc = __mdd_index_insert_only(env, child, mdo2fid(child),
					     S_IFDIR, dot, handle, BYPASS_CAPA);
		if (rc == 0)
			rc = __mdd_index_insert_only(env, child, pfid, S_IFDIR,
						     dotdot, handle,
						     BYPASS_CAPA);
		if (rc != 0)
			mdo_ref_del(env, child, handle);
	}

	RETURN(rc);
}

/**
 * This function checks whether it can create a file/dir under the
 * directory(@pobj). The directory(@pobj) is not being locked by
 * mdd lock.
 *
 * \param[in] env	execution environment
 * \param[in] pobj	the directory to create files
 * \param[in] pattr	the attributes of the directory
 * \param[in] lname	the name of the created file/dir
 * \param[in] cattr	the attributes of the file/dir
 * \param[in] spec	create specification
 *
 * \retval		= 0 it is allowed to create file/dir under
 *                      the directory
 * \retval              negative error not allowed to create file/dir
 *                      under the directory
 */
static int mdd_create_sanity_check(const struct lu_env *env,
                                   struct md_object *pobj,
				   const struct lu_attr *pattr,
                                   const struct lu_name *lname,
				   struct lu_attr *cattr,
                                   struct md_op_spec *spec)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct lu_fid     *fid       = &info->mti_fid;
	struct mdd_object *obj       = md2mdd_obj(pobj);
	struct mdd_device *m         = mdo2mdd(pobj);
	bool		check_perm = true;
	int rc;
	ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

	/*
         * In some cases this lookup is not needed - we know before if name
         * exists or not because MDT performs lookup for it.
         * name length check is done in lookup.
         */
	if (spec->sp_cr_lookup) {
                /*
                 * Check if the name already exist, though it will be checked in
                 * _index_insert also, for avoiding rolling back if exists
                 * _index_insert.
                 */
		rc = __mdd_lookup(env, pobj, pattr, lname, fid,
				  MAY_WRITE | MAY_EXEC);
		if (rc != -ENOENT)
			RETURN(rc ? : -EEXIST);

		/* Permission is already being checked in mdd_lookup */
		check_perm = false;
	}

	rc = mdd_may_create(env, obj, pattr, NULL, check_perm);
	if (rc != 0)
		RETURN(rc);

        /* sgid check */
	if (pattr->la_mode & S_ISGID) {
		cattr->la_gid = pattr->la_gid;
		if (S_ISDIR(cattr->la_mode)) {
			cattr->la_mode |= S_ISGID;
			cattr->la_valid |= LA_MODE;
		}
	}

	rc = mdd_name_check(m, lname);
	if (rc < 0)
		RETURN(rc);

	switch (cattr->la_mode & S_IFMT) {
        case S_IFLNK: {
                unsigned int symlen = strlen(spec->u.sp_symname) + 1;

                if (symlen > (1 << m->mdd_dt_conf.ddp_block_shift))
                        RETURN(-ENAMETOOLONG);
                else
                        RETURN(0);
        }
        case S_IFDIR:
        case S_IFREG:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                rc = 0;
                break;
        default:
                rc = -EINVAL;
                break;
        }
        RETURN(rc);
}

static int mdd_declare_object_create(const struct lu_env *env,
				     struct mdd_device *mdd,
				     struct mdd_object *p, struct mdd_object *c,
				     struct lu_attr *attr,
				     struct thandle *handle,
				     const struct md_op_spec *spec,
				     struct lu_buf *def_acl_buf,
				     struct lu_buf *acl_buf,
				     struct dt_allocation_hint *hint)
{
	int rc;

	rc = mdd_declare_object_create_internal(env, p, c, attr, handle, spec,
						hint);
        if (rc)
                GOTO(out, rc);

#ifdef CONFIG_FS_POSIX_ACL
	if (def_acl_buf->lb_len > 0 && S_ISDIR(attr->la_mode)) {
		/* if dir, then can inherit default ACl */
		rc = mdo_declare_xattr_set(env, c, def_acl_buf,
					   XATTR_NAME_ACL_DEFAULT,
					   0, handle);
		if (rc)
			GOTO(out, rc);
	}

	if (acl_buf->lb_len > 0) {
		rc = mdo_declare_attr_set(env, c, attr, handle);
		if (rc)
			GOTO(out, rc);

		rc = mdo_declare_xattr_set(env, c, acl_buf,
					   XATTR_NAME_ACL_ACCESS, 0, handle);
		if (rc)
			GOTO(out, rc);
	}
#endif
	rc = mdd_declare_object_initialize(env, p, c, attr, handle);
	if (rc)
		GOTO(out, rc);

	/* replay case, create LOV EA from client data */
	if (spec->no_create ||
	    (spec->sp_cr_flags & MDS_OPEN_HAS_EA && S_ISREG(attr->la_mode))) {
		const struct lu_buf *buf;

		buf = mdd_buf_get_const(env, spec->u.sp_ea.eadata,
					spec->u.sp_ea.eadatalen);
		rc = mdo_declare_xattr_set(env, c, buf, XATTR_NAME_LOV, 0,
					   handle);
		if (rc)
			GOTO(out, rc);
	}

	if (S_ISLNK(attr->la_mode)) {
		const char *target_name = spec->u.sp_symname;
		int sym_len = strlen(target_name);
		const struct lu_buf *buf;

		buf = mdd_buf_get_const(env, target_name, sym_len);
                rc = dt_declare_record_write(env, mdd_object_child(c),
					     buf, 0, handle);
                if (rc)
                        GOTO(out, rc);
        }
out:
	return rc;
}

static int mdd_declare_create(const struct lu_env *env, struct mdd_device *mdd,
			      struct mdd_object *p, struct mdd_object *c,
			      const struct lu_name *name,
			      struct lu_attr *attr,
			      struct thandle *handle,
			      const struct md_op_spec *spec,
			      struct linkea_data *ldata,
			      struct lu_buf *def_acl_buf,
			      struct lu_buf *acl_buf,
			      struct dt_allocation_hint *hint)
{
	int rc;

	rc = mdd_declare_object_create(env, mdd, p, c, attr, handle, spec,
				       def_acl_buf, acl_buf, hint);
	if (rc)
		GOTO(out, rc);

	if (S_ISDIR(attr->la_mode)) {
		rc = mdo_declare_ref_add(env, p, handle);
		if (rc)
			GOTO(out, rc);
	}

	if (unlikely(spec->sp_cr_flags & MDS_OPEN_VOLATILE)) {
		rc = orph_declare_index_insert(env, c, attr->la_mode, handle);
		if (rc)
			GOTO(out, rc);
	} else {
		struct lu_attr	*la = &mdd_env_info(env)->mti_la_for_fix;

		rc = mdo_declare_index_insert(env, p, mdo2fid(c), attr->la_mode,
					      name->ln_name, handle);
		if (rc != 0)
			return rc;

		rc = mdd_declare_links_add(env, c, handle, ldata, MLAO_IGNORE);
		if (rc)
			return rc;

		*la = *attr;
		la->la_valid = LA_CTIME | LA_MTIME;
		rc = mdo_declare_attr_set(env, p, la, handle);
		if (rc)
			return rc;

		rc = mdd_declare_changelog_store(env, mdd, name, NULL, handle);
		if (rc)
			return rc;
	}

	/* XXX: For remote create, it should indicate the remote RPC
	 * will be sent after local transaction is finished, which
	 * is not very nice, but it will be removed once we fully support
	 * async update */
	if (mdd_object_remote(p) && handle->th_update != NULL)
		handle->th_update->tu_sent_after_local_trans = 1;
out:
	return rc;
}

static int mdd_acl_init(const struct lu_env *env, struct mdd_object *pobj,
			struct lu_attr *la, struct lu_buf *def_acl_buf,
			struct lu_buf *acl_buf)
{
	int	rc;
	ENTRY;

	if (S_ISLNK(la->la_mode)) {
		acl_buf->lb_len = 0;
		def_acl_buf->lb_len = 0;
		RETURN(0);
	}

	mdd_read_lock(env, pobj, MOR_TGT_PARENT);
	rc = mdo_xattr_get(env, pobj, def_acl_buf,
			   XATTR_NAME_ACL_DEFAULT, BYPASS_CAPA);
	mdd_read_unlock(env, pobj);
	if (rc > 0) {
		/* If there are default ACL, fix mode/ACL by default ACL */
		def_acl_buf->lb_len = rc;
		LASSERT(def_acl_buf->lb_len <= acl_buf->lb_len);
		memcpy(acl_buf->lb_buf, def_acl_buf->lb_buf, rc);
		acl_buf->lb_len = rc;
		rc = __mdd_fix_mode_acl(env, acl_buf, &la->la_mode);
		if (rc < 0)
			RETURN(rc);
	} else if (rc == -ENODATA || rc == -EOPNOTSUPP) {
		/* If there are no default ACL, fix mode by mask */
		struct lu_ucred *uc = lu_ucred(env);

		/* The create triggered by MDT internal events, such as
		 * LFSCK reset, will not contain valid "uc". */
		if (unlikely(uc != NULL))
			la->la_mode &= ~uc->uc_umask;
		rc = 0;
		acl_buf->lb_len = 0;
		def_acl_buf->lb_len = 0;
	}

	RETURN(rc);
}

/**
 * Create a metadata object and initialize it, set acl, xattr.
 **/
static int mdd_object_create(const struct lu_env *env, struct mdd_object *pobj,
			     struct mdd_object *son, struct lu_attr *attr,
			     struct md_op_spec *spec, struct lu_buf *acl_buf,
			     struct lu_buf *def_acl_buf,
			     struct dt_allocation_hint *hint,
			     struct thandle *handle)
{
	int			rc;

	mdd_write_lock(env, son, MOR_TGT_CHILD);
	rc = mdd_object_create_internal(env, NULL, son, attr, handle, spec,
					hint);
	if (rc)
		GOTO(unlock, rc);

	/* Note: In DNE phase I, for striped dir, though sub-stripes will be
	 * created in declare phase, they also needs to be added to master
	 * object as sub-directory entry. So it has to initialize the master
	 * object, then set dir striped EA.(in mdo_xattr_set) */
	rc = mdd_object_initialize(env, mdo2fid(pobj), son, attr, handle,
				   spec);
	if (rc != 0)
		GOTO(err_destroy, rc);

	/*
	 * in case of replay we just set LOVEA provided by the client
	 * XXX: I think it would be interesting to try "old" way where
	 *      MDT calls this xattr_set(LOV) in a different transaction.
	 *      probably this way we code can be made better.
	 */

	/* During creation, there are only a few cases we need do xattr_set to
	 * create stripes.
	 * 1. regular file: see comments above.
	 * 2. dir: inherit default striping or pool settings from parent.
	 * 3. create striped directory with provided stripeEA.
	 * 4. create striped directory because inherit default layout from the
	 * parent.
	 */
	if (spec->no_create ||
	    (S_ISREG(attr->la_mode) && spec->sp_cr_flags & MDS_OPEN_HAS_EA) ||
	    S_ISDIR(attr->la_mode)) {
		const struct lu_buf *buf;

		buf = mdd_buf_get_const(env, spec->u.sp_ea.eadata,
					spec->u.sp_ea.eadatalen);
		rc = mdo_xattr_set(env, son, buf,
				   S_ISDIR(attr->la_mode) ? XATTR_NAME_LMV :
							    XATTR_NAME_LOV, 0,
				   handle, BYPASS_CAPA);
		if (rc != 0)
			GOTO(err_destroy, rc);
	}

#ifdef CONFIG_FS_POSIX_ACL
	if (def_acl_buf != NULL && def_acl_buf->lb_len > 0 &&
	    S_ISDIR(attr->la_mode)) {
		/* set default acl */
		rc = mdo_xattr_set(env, son, def_acl_buf,
				   XATTR_NAME_ACL_DEFAULT, 0,
				   handle, BYPASS_CAPA);
		if (rc)
			GOTO(err_destroy, rc);
	}
	/* set its own acl */
	if (acl_buf != NULL && acl_buf->lb_len > 0) {
		rc = mdo_xattr_set(env, son, acl_buf,
				   XATTR_NAME_ACL_ACCESS,
				   0, handle, BYPASS_CAPA);
		if (rc)
			GOTO(err_destroy, rc);
	}
#endif

	if (S_ISLNK(attr->la_mode)) {
		struct lu_ucred  *uc = lu_ucred_assert(env);
		struct dt_object *dt = mdd_object_child(son);
		const char *target_name = spec->u.sp_symname;
		int sym_len = strlen(target_name);
		const struct lu_buf *buf;
		loff_t pos = 0;

		buf = mdd_buf_get_const(env, target_name, sym_len);
		rc = dt->do_body_ops->dbo_write(env, dt, buf, &pos, handle,
						mdd_object_capa(env, son),
						uc->uc_cap &
						CFS_CAP_SYS_RESOURCE_MASK);

		if (rc == sym_len)
			rc = 0;
		else
			GOTO(err_initlized, rc = -EFAULT);
	}

err_initlized:
	if (unlikely(rc != 0)) {
		int rc2;
		if (S_ISDIR(attr->la_mode)) {
			/* Drop the reference, no need to delete "."/"..",
			 * because the object to be destroied directly. */
			rc2 = mdo_ref_del(env, son, handle);
			if (rc2 != 0)
				GOTO(unlock, rc);
		}
		rc2 = mdo_ref_del(env, son, handle);
		if (rc2 != 0)
			GOTO(unlock, rc);
err_destroy:
		mdo_destroy(env, son, handle);
	}
unlock:
	mdd_write_unlock(env, son);
	RETURN(rc);
}

/*
 * Create object and insert it into namespace.
 */
static int mdd_create(const struct lu_env *env, struct md_object *pobj,
		      const struct lu_name *lname, struct md_object *child,
		      struct md_op_spec *spec, struct md_attr* ma)
{
	struct mdd_thread_info	*info = mdd_env_info(env);
	struct lu_attr		*la = &info->mti_la_for_fix;
	struct mdd_object	*mdd_pobj = md2mdd_obj(pobj);
	struct mdd_object	*son = md2mdd_obj(child);
	struct mdd_device	*mdd = mdo2mdd(pobj);
	struct lu_attr		*attr = &ma->ma_attr;
	struct thandle		*handle;
	struct lu_attr		*pattr = &info->mti_pattr;
	struct lu_buf		acl_buf;
	struct lu_buf		def_acl_buf;
	struct linkea_data	*ldata = &info->mti_link_data;
	const char		*name = lname->ln_name;
	struct dt_allocation_hint *hint = &mdd_env_info(env)->mti_hint;
	int			 rc;
	int			 rc2;
	ENTRY;

        /*
         * Two operations have to be performed:
         *
         *  - an allocation of a new object (->do_create()), and
         *
         *  - an insertion into a parent index (->dio_insert()).
         *
         * Due to locking, operation order is not important, when both are
         * successful, *but* error handling cases are quite different:
         *
         *  - if insertion is done first, and following object creation fails,
         *  insertion has to be rolled back, but this operation might fail
         *  also leaving us with dangling index entry.
         *
         *  - if creation is done first, is has to be undone if insertion
         *  fails, leaving us with leaked space, which is neither good, nor
         *  fatal.
         *
         * It seems that creation-first is simplest solution, but it is
         * sub-optimal in the frequent
         *
         *         $ mkdir foo
         *         $ mkdir foo
         *
         * case, because second mkdir is bound to create object, only to
         * destroy it immediately.
         *
         * To avoid this follow local file systems that do double lookup:
         *
         *     0. lookup -> -EEXIST (mdd_create_sanity_check())
         *
         *     1. create            (mdd_object_create_internal())
         *
         *     2. insert            (__mdd_index_insert(), lookup again)
         */

	rc = mdd_la_get(env, mdd_pobj, pattr, BYPASS_CAPA);
	if (rc != 0)
		RETURN(rc);

	/* Sanity checks before big job. */
	rc = mdd_create_sanity_check(env, pobj, pattr, lname, attr, spec);
	if (rc)
		RETURN(rc);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_DQACQ_NET))
		GOTO(out_free, rc = -EINPROGRESS);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		GOTO(out_free, rc = PTR_ERR(handle));

	acl_buf.lb_buf = info->mti_xattr_buf;
	acl_buf.lb_len = sizeof(info->mti_xattr_buf);
	def_acl_buf.lb_buf = info->mti_key;
	def_acl_buf.lb_len = sizeof(info->mti_key);
	rc = mdd_acl_init(env, mdd_pobj, attr, &def_acl_buf, &acl_buf);
	if (rc < 0)
		GOTO(out_stop, rc);

	mdd_object_make_hint(env, mdd_pobj, son, attr, spec, hint);

	memset(ldata, 0, sizeof(*ldata));
	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_PARENT)) {
		struct lu_fid tfid = *mdd_object_fid(mdd_pobj);

		tfid.f_oid--;
		rc = mdd_linkea_prepare(env, son, NULL, NULL,
					&tfid, lname, 1, 0, ldata);
	} else {
		rc = mdd_linkea_prepare(env, son, NULL, NULL,
					mdd_object_fid(mdd_pobj),
					lname, 1, 0, ldata);
	}

	rc = mdd_declare_create(env, mdd, mdd_pobj, son, lname, attr,
				handle, spec, ldata, &def_acl_buf, &acl_buf,
				hint);
        if (rc)
                GOTO(out_stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(out_stop, rc);

	rc = mdd_object_create(env, mdd_pobj, son, attr, spec, &acl_buf,
			       &def_acl_buf, hint, handle);
	if (rc != 0)
		GOTO(out_stop, rc);

	if (unlikely(spec->sp_cr_flags & MDS_OPEN_VOLATILE)) {
		mdd_write_lock(env, son, MOR_TGT_CHILD);
		rc = __mdd_orphan_add(env, son, handle);
		GOTO(out_volatile, rc);
	} else {
		rc = __mdd_index_insert(env, mdd_pobj, mdo2fid(son),
					attr->la_mode, name, handle,
					mdd_object_capa(env, mdd_pobj));
		if (rc != 0)
			GOTO(err_created, rc);

		mdd_links_add(env, son, mdo2fid(mdd_pobj), lname, handle,
			      ldata, 1);

		/* update parent directory mtime/ctime */
		*la = *attr;
		la->la_valid = LA_CTIME | LA_MTIME;
		rc = mdd_update_time(env, mdd_pobj, pattr, la, handle);
		if (rc)
			GOTO(err_insert, rc);
	}

	EXIT;
err_insert:
	if (rc != 0) {
		int rc2;

		if (spec->sp_cr_flags & MDS_OPEN_VOLATILE)
			rc2 = __mdd_orphan_del(env, son, handle);
		else
			rc2 = __mdd_index_delete(env, mdd_pobj, name,
						 S_ISDIR(attr->la_mode),
						 handle, BYPASS_CAPA);
		if (rc2 != 0)
			goto out_stop;

err_created:
		mdd_write_lock(env, son, MOR_TGT_CHILD);
		if (S_ISDIR(attr->la_mode)) {
			/* Drop the reference, no need to delete "."/"..",
			 * because the object is to be destroyed directly. */
			rc2 = mdo_ref_del(env, son, handle);
			if (rc2 != 0) {
				mdd_write_unlock(env, son);
				goto out_stop;
			}
		}
out_volatile:
		/* For volatile files drop one link immediately, since there is
		 * no filename in the namespace, and save any error returned. */
		rc2 = mdo_ref_del(env, son, handle);
		if (rc2 != 0) {
			mdd_write_unlock(env, son);
			if (unlikely(rc == 0))
				rc = rc2;
			goto out_stop;
		}

		/* Don't destroy the volatile object on success */
		if (likely(rc != 0))
			mdo_destroy(env, son, handle);
		mdd_write_unlock(env, son);
	}

	if (rc == 0 && fid_is_namespace_visible(mdo2fid(son)) &&
	    likely((spec->sp_cr_flags & MDS_OPEN_VOLATILE) == 0))
		rc = mdd_changelog_ns_store(env, mdd,
				S_ISDIR(attr->la_mode) ? CL_MKDIR :
				S_ISREG(attr->la_mode) ? CL_CREATE :
				S_ISLNK(attr->la_mode) ? CL_SOFTLINK : CL_MKNOD,
				0, son, mdo2fid(mdd_pobj), NULL, NULL, lname,
				NULL, handle);
out_stop:
	rc2 = mdd_trans_stop(env, mdd, rc, handle);
	if (rc == 0)
		rc = rc2;
out_free:
	if (ldata->ld_buf && ldata->ld_buf->lb_len > OBD_ALLOC_BIG)
		/* if we vmalloced a large buffer drop it */
		lu_buf_free(ldata->ld_buf);

	/* The child object shouldn't be cached anymore */
	if (rc)
		set_bit(LU_OBJECT_HEARD_BANSHEE,
			&child->mo_lu.lo_header->loh_flags);
	return rc;
}

/*
 * Get locks on parents in proper order
 * RETURN: < 0 - error, rename_order if successful
 */
enum rename_order {
        MDD_RN_SAME,
        MDD_RN_SRCTGT,
        MDD_RN_TGTSRC
};

static int mdd_rename_order(const struct lu_env *env,
                            struct mdd_device *mdd,
                            struct mdd_object *src_pobj,
			    const struct lu_attr *pattr,
                            struct mdd_object *tgt_pobj)
{
        /* order of locking, 1 - tgt-src, 0 - src-tgt*/
        int rc;
        ENTRY;

        if (src_pobj == tgt_pobj)
                RETURN(MDD_RN_SAME);

        /* compared the parent child relationship of src_p&tgt_p */
        if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(src_pobj))){
                rc = MDD_RN_SRCTGT;
        } else if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(tgt_pobj))) {
                rc = MDD_RN_TGTSRC;
        } else {
		rc = mdd_is_parent(env, mdd, src_pobj, pattr, mdo2fid(tgt_pobj),
				   NULL);
                if (rc == -EREMOTE)
                        rc = 0;

                if (rc == 1)
                        rc = MDD_RN_TGTSRC;
                else if (rc == 0)
                        rc = MDD_RN_SRCTGT;
        }

        RETURN(rc);
}

/* has not mdd_write{read}_lock on any obj yet. */
static int mdd_rename_sanity_check(const struct lu_env *env,
                                   struct mdd_object *src_pobj,
				   const struct lu_attr *pattr,
                                   struct mdd_object *tgt_pobj,
				   const struct lu_attr *tpattr,
                                   struct mdd_object *sobj,
				   const struct lu_attr *cattr,
                                   struct mdd_object *tobj,
				   const struct lu_attr *tattr)
{
	int rc = 0;
	ENTRY;

	/* XXX: when get here, sobj must NOT be NULL,
	 * the other case has been processed in cld_rename
	 * before mdd_rename and enable MDS_PERM_BYPASS. */
	LASSERT(sobj);

	rc = mdd_may_delete(env, src_pobj, pattr, sobj, cattr, NULL, 1, 0);
	if (rc)
		RETURN(rc);

	/* XXX: when get here, "tobj == NULL" means tobj must
	 * NOT exist (neither on remote MDS, such case has been
	 * processed in cld_rename before mdd_rename and enable
	 * MDS_PERM_BYPASS).
	 * So check may_create, but not check may_unlink. */
	if (tobj == NULL)
		rc = mdd_may_create(env, tgt_pobj, tpattr, NULL,
				    (src_pobj != tgt_pobj));
	else
		rc = mdd_may_delete(env, tgt_pobj, tpattr, tobj, tattr, cattr,
				    (src_pobj != tgt_pobj), 1);

	if (!rc && !tobj && (src_pobj != tgt_pobj) && S_ISDIR(cattr->la_mode))
		rc = __mdd_may_link(env, tgt_pobj, tpattr);

	RETURN(rc);
}

static int mdd_declare_rename(const struct lu_env *env,
			      struct mdd_device *mdd,
			      struct mdd_object *mdd_spobj,
			      struct mdd_object *mdd_tpobj,
			      struct mdd_object *mdd_sobj,
			      struct mdd_object *mdd_tobj,
			      const struct lu_name *tname,
			      const struct lu_name *sname,
			      struct md_attr *ma,
			      struct linkea_data *ldata,
			      struct thandle *handle)
{
	struct lu_attr    *la = &mdd_env_info(env)->mti_la_for_fix;
	int rc;

	LASSERT(ma->ma_attr.la_valid & LA_CTIME);
	la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

        LASSERT(mdd_spobj);
        LASSERT(mdd_tpobj);
        LASSERT(mdd_sobj);

        /* name from source dir */
        rc = mdo_declare_index_delete(env, mdd_spobj, sname->ln_name, handle);
        if (rc)
                return rc;

        /* .. from source child */
        if (S_ISDIR(mdd_object_type(mdd_sobj))) {
                /* source child can be directory,
                 * counted by source dir's nlink */
                rc = mdo_declare_ref_del(env, mdd_spobj, handle);
                if (rc)
                        return rc;
		if (mdd_spobj != mdd_tpobj) {
			rc = mdo_declare_index_delete(env, mdd_sobj, dotdot,
						      handle);
			if (rc != 0)
				return rc;

			rc = mdo_declare_index_insert(env, mdd_sobj,
						      mdo2fid(mdd_tpobj),
						      S_IFDIR, dotdot, handle);
			if (rc != 0)
				return rc;
		}

		/* new target child can be directory,
		 * counted by target dir's nlink */
		rc = mdo_declare_ref_add(env, mdd_tpobj, handle);
		if (rc != 0)
			return rc;
	}

	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdo_declare_attr_set(env, mdd_spobj, la, handle);
	if (rc != 0)
		return rc;

	rc = mdo_declare_attr_set(env, mdd_tpobj, la, handle);
	if (rc != 0)
		return rc;

	la->la_valid = LA_CTIME;
	rc = mdo_declare_attr_set(env, mdd_sobj, la, handle);
	if (rc)
		return rc;

	rc = mdd_declare_links_add(env, mdd_sobj, handle, ldata,
		S_ISREG(mdd_object_type(mdd_sobj)) ? MLAO_CHECK : MLAO_IGNORE);
	if (rc)
		return rc;

	/* new name */
	rc = mdo_declare_index_insert(env, mdd_tpobj, mdo2fid(mdd_sobj),
				      mdd_object_type(mdd_sobj),
				      tname->ln_name, handle);
	if (rc != 0)
		return rc;

        /* name from target dir (old name), we declare it unconditionally
         * as mdd_rename() calls delete unconditionally as well. so just
         * to balance declarations vs calls to change ... */
        rc = mdo_declare_index_delete(env, mdd_tpobj, tname->ln_name, handle);
        if (rc)
                return rc;

        if (mdd_tobj && mdd_object_exists(mdd_tobj)) {
                /* delete target child in target parent directory */
                rc = mdo_declare_ref_del(env, mdd_tobj, handle);
                if (rc)
                        return rc;

                if (S_ISDIR(mdd_object_type(mdd_tobj))) {
                        /* target child can be directory,
                         * delete "." reference in target child directory */
                        rc = mdo_declare_ref_del(env, mdd_tobj, handle);
                        if (rc)
                                return rc;

                        /* delete ".." reference in target parent directory */
                        rc = mdo_declare_ref_del(env, mdd_tpobj, handle);
                        if (rc)
                                return rc;
                }

		la->la_valid = LA_CTIME;
		rc = mdo_declare_attr_set(env, mdd_tobj, la, handle);
		if (rc)
			return rc;

		rc = mdd_declare_finish_unlink(env, mdd_tobj, handle);
		if (rc)
			return rc;
        }

	rc = mdd_declare_changelog_store(env, mdd, tname, sname, handle);
        if (rc)
                return rc;

        return rc;
}

/* src object can be remote that is why we use only fid and type of object */
static int mdd_rename(const struct lu_env *env,
                      struct md_object *src_pobj, struct md_object *tgt_pobj,
                      const struct lu_fid *lf, const struct lu_name *lsname,
                      struct md_object *tobj, const struct lu_name *ltname,
                      struct md_attr *ma)
{
	const char *sname = lsname->ln_name;
	const char *tname = ltname->ln_name;
	struct lu_attr    *la = &mdd_env_info(env)->mti_la_for_fix;
	struct mdd_object *mdd_spobj = md2mdd_obj(src_pobj); /* source parent */
	struct mdd_object *mdd_tpobj = md2mdd_obj(tgt_pobj);
	struct mdd_device *mdd = mdo2mdd(src_pobj);
	struct mdd_object *mdd_sobj = NULL;                  /* source object */
	struct mdd_object *mdd_tobj = NULL;
	struct lu_attr *cattr = MDD_ENV_VAR(env, cattr);
	struct lu_attr *pattr = MDD_ENV_VAR(env, pattr);
	struct lu_attr *tattr = MDD_ENV_VAR(env, tattr);
	struct lu_attr *tpattr = MDD_ENV_VAR(env, tpattr);
	struct thandle *handle;
	struct linkea_data  *ldata = &mdd_env_info(env)->mti_link_data;
	const struct lu_fid *tpobj_fid = mdo2fid(mdd_tpobj);
	const struct lu_fid *spobj_fid = mdo2fid(mdd_spobj);
	bool is_dir;
	bool tobj_ref = 0;
	bool tobj_locked = 0;
	unsigned cl_flags = 0;
	int rc, rc2;
	ENTRY;

	if (tobj)
		mdd_tobj = md2mdd_obj(tobj);

	mdd_sobj = mdd_object_find(env, mdd, lf);

	rc = mdd_la_get(env, mdd_sobj, cattr, BYPASS_CAPA);
	if (rc)
		GOTO(out_pending, rc);

	rc = mdd_la_get(env, mdd_spobj, pattr, BYPASS_CAPA);
	if (rc)
		GOTO(out_pending, rc);

	if (mdd_tobj) {
		rc = mdd_la_get(env, mdd_tobj, tattr, BYPASS_CAPA);
		if (rc)
			GOTO(out_pending, rc);
	}

	rc = mdd_la_get(env, mdd_tpobj, tpattr, BYPASS_CAPA);
	if (rc)
		GOTO(out_pending, rc);

	rc = mdd_rename_sanity_check(env, mdd_spobj, pattr, mdd_tpobj, tpattr,
				     mdd_sobj, cattr, mdd_tobj, tattr);
	if (rc)
		GOTO(out_pending, rc);

	rc = mdd_name_check(mdd, ltname);
	if (rc < 0)
		GOTO(out_pending, rc);

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                GOTO(out_pending, rc = PTR_ERR(handle));

	memset(ldata, 0, sizeof(*ldata));
	mdd_linkea_prepare(env, mdd_sobj, NULL, NULL, mdd_object_fid(mdd_tpobj),
			   ltname, 1, 0, ldata);
	rc = mdd_declare_rename(env, mdd, mdd_spobj, mdd_tpobj, mdd_sobj,
				mdd_tobj, lsname, ltname, ma, ldata, handle);
	if (rc)
		GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

        /* FIXME: Should consider tobj and sobj too in rename_lock. */
	rc = mdd_rename_order(env, mdd, mdd_spobj, pattr, mdd_tpobj);
	if (rc < 0)
		GOTO(cleanup_unlocked, rc);

	is_dir = S_ISDIR(cattr->la_mode);

        /* Remove source name from source directory */
        rc = __mdd_index_delete(env, mdd_spobj, sname, is_dir, handle,
                                mdd_object_capa(env, mdd_spobj));
        if (rc)
                GOTO(cleanup, rc);

        /* "mv dir1 dir2" needs "dir1/.." link update */
        if (is_dir && mdd_sobj && !lu_fid_eq(spobj_fid, tpobj_fid)) {
                rc = __mdd_index_delete_only(env, mdd_sobj, dotdot, handle,
                                        mdd_object_capa(env, mdd_sobj));
		if (rc != 0)
			GOTO(fixup_spobj2, rc);

		rc = __mdd_index_insert_only(env, mdd_sobj, tpobj_fid, S_IFDIR,
					     dotdot, handle,
					     mdd_object_capa(env, mdd_sobj));
		if (rc != 0)
                        GOTO(fixup_spobj, rc);
        }

        /* Remove target name from target directory
         * Here tobj can be remote one, so we do index_delete unconditionally
         * and -ENOENT is allowed.
         */
        rc = __mdd_index_delete(env, mdd_tpobj, tname, is_dir, handle,
                                mdd_object_capa(env, mdd_tpobj));
        if (rc != 0) {
                if (mdd_tobj) {
                        /* tname might been renamed to something else */
                        GOTO(fixup_spobj, rc);
                }
                if (rc != -ENOENT)
                        GOTO(fixup_spobj, rc);
        }

        /* Insert new fid with target name into target dir */
	rc = __mdd_index_insert(env, mdd_tpobj, lf, cattr->la_mode,
				tname, handle, mdd_object_capa(env, mdd_tpobj));
	if (rc != 0)
                GOTO(fixup_tpobj, rc);

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);
        la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

        /* XXX: mdd_sobj must be local one if it is NOT NULL. */
	if (mdd_sobj) {
		la->la_valid = LA_CTIME;
		rc = mdd_update_time(env, mdd_sobj, cattr, la, handle);
		if (rc)
			GOTO(fixup_tpobj, rc);
	}

        /* Remove old target object
         * For tobj is remote case cmm layer has processed
         * and set tobj to NULL then. So when tobj is NOT NULL,
         * it must be local one.
         */
        if (tobj && mdd_object_exists(mdd_tobj)) {
                mdd_write_lock(env, mdd_tobj, MOR_TGT_CHILD);
		tobj_locked = 1;
                if (mdd_is_dead_obj(mdd_tobj)) {
                        /* shld not be dead, something is wrong */
                        CERROR("tobj is dead, something is wrong\n");
                        rc = -EINVAL;
                        goto cleanup;
                }
                mdo_ref_del(env, mdd_tobj, handle);

                /* Remove dot reference. */
		if (S_ISDIR(tattr->la_mode))
                        mdo_ref_del(env, mdd_tobj, handle);
		tobj_ref = 1;

		/* fetch updated nlink */
		rc = mdd_la_get(env, mdd_tobj, tattr, BYPASS_CAPA);
		if (rc != 0) {
			CERROR("%s: Failed to get nlink for tobj "
				DFID": rc = %d\n",
				mdd2obd_dev(mdd)->obd_name,
				PFID(tpobj_fid), rc);
			GOTO(fixup_tpobj, rc);
		}

		la->la_valid = LA_CTIME;
		rc = mdd_update_time(env, mdd_tobj, tattr, la, handle);
		if (rc != 0) {
			CERROR("%s: Failed to set ctime for tobj "
				DFID": rc = %d\n",
				mdd2obd_dev(mdd)->obd_name,
				PFID(tpobj_fid), rc);
			GOTO(fixup_tpobj, rc);
		}

		/* XXX: this transfer to ma will be removed with LOD/OSP */
		ma->ma_attr = *tattr;
		ma->ma_valid |= MA_INODE;
		rc = mdd_finish_unlink(env, mdd_tobj, ma, mdd_tpobj, ltname,
				       handle);
		if (rc != 0) {
			CERROR("%s: Failed to unlink tobj "
				DFID": rc = %d\n",
				mdd2obd_dev(mdd)->obd_name,
				PFID(tpobj_fid), rc);
			GOTO(fixup_tpobj, rc);
		}

		/* fetch updated nlink */
		rc = mdd_la_get(env, mdd_tobj, tattr, BYPASS_CAPA);
		if (rc != 0) {
			CERROR("%s: Failed to get nlink for tobj "
				DFID": rc = %d\n",
				mdd2obd_dev(mdd)->obd_name,
				PFID(tpobj_fid), rc);
			GOTO(fixup_tpobj, rc);
		}
		/* XXX: this transfer to ma will be removed with LOD/OSP */
		ma->ma_attr = *tattr;
		ma->ma_valid |= MA_INODE;

		if (tattr->la_nlink == 0) {
			cl_flags |= CLF_RENAME_LAST;
			if (mdd_hsm_archive_exists(env, mdd_tobj, ma))
				cl_flags |= CLF_RENAME_LAST_EXISTS;
		}
        }

	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdd_update_time(env, mdd_spobj, pattr, la, handle);
	if (rc)
		GOTO(fixup_tpobj, rc);

	if (mdd_spobj != mdd_tpobj) {
		la->la_valid = LA_CTIME | LA_MTIME;
		rc = mdd_update_time(env, mdd_tpobj, tpattr, la, handle);
	}

	if (rc == 0 && mdd_sobj) {
		mdd_write_lock(env, mdd_sobj, MOR_SRC_CHILD);
		rc = mdd_links_rename(env, mdd_sobj, mdo2fid(mdd_spobj), lsname,
				      mdo2fid(mdd_tpobj), ltname, handle, NULL,
				      0, 0);
                if (rc == -ENOENT)
                        /* Old files might not have EA entry */
                        mdd_links_add(env, mdd_sobj, mdo2fid(mdd_spobj),
				      lsname, handle, NULL, 0);
                mdd_write_unlock(env, mdd_sobj);
                /* We don't fail the transaction if the link ea can't be
                   updated -- fid2path will use alternate lookup method. */
                rc = 0;
        }

        EXIT;

fixup_tpobj:
        if (rc) {
                rc2 = __mdd_index_delete(env, mdd_tpobj, tname, is_dir, handle,
                                         BYPASS_CAPA);
                if (rc2)
                        CWARN("tp obj fix error %d\n",rc2);

                if (mdd_tobj && mdd_object_exists(mdd_tobj) &&
                    !mdd_is_dead_obj(mdd_tobj)) {
			if (tobj_ref) {
				mdo_ref_add(env, mdd_tobj, handle);
				if (is_dir)
					mdo_ref_add(env, mdd_tobj, handle);
			}

			rc2 = __mdd_index_insert(env, mdd_tpobj,
						  mdo2fid(mdd_tobj),
						  mdd_object_type(mdd_tobj),
						  tname, handle, BYPASS_CAPA);
			if (rc2 != 0)
				CWARN("tp obj fix error: rc = %d\n", rc2);
		}
	}

fixup_spobj:
	if (rc && is_dir && mdd_sobj && mdd_spobj != mdd_tpobj) {
		rc2 = __mdd_index_delete_only(env, mdd_sobj, dotdot, handle,
					      BYPASS_CAPA);

		if (rc2)
			CWARN("%s: sp obj dotdot delete error: rc = %d\n",
			       mdd2obd_dev(mdd)->obd_name, rc2);


		rc2 = __mdd_index_insert_only(env, mdd_sobj, spobj_fid, S_IFDIR,
					      dotdot, handle, BYPASS_CAPA);
		if (rc2 != 0)
			CWARN("%s: sp obj dotdot insert error: rc = %d\n",
			      mdd2obd_dev(mdd)->obd_name, rc2);
	}

fixup_spobj2:
	if (rc != 0) {
		rc2 = __mdd_index_insert(env, mdd_spobj, lf,
					 mdd_object_type(mdd_sobj), sname,
					 handle, BYPASS_CAPA);
		if (rc2 != 0)
			CWARN("sp obj fix error: rc = %d\n", rc2);
	}

cleanup:
	if (tobj_locked)
		mdd_write_unlock(env, mdd_tobj);

cleanup_unlocked:
	if (rc == 0)
		rc = mdd_changelog_ns_store(env, mdd, CL_RENAME, cl_flags,
					    mdd_tobj, tpobj_fid, lf, spobj_fid,
					    ltname, lsname, handle);

stop:
	mdd_trans_stop(env, mdd, rc, handle);

out_pending:
	mdd_object_put(env, mdd_sobj);
	return rc;
}

/**
 * During migration once the parent FID has been changed,
 * we need update the parent FID in linkea.
 **/
static int mdd_linkea_update_child_internal(const struct lu_env *env,
					    struct mdd_object *parent,
					    struct mdd_object *child,
					    const char *name, int namelen,
					    struct thandle *handle,
					    bool declare)
{
	struct mdd_thread_info  *info = mdd_env_info(env);
	struct linkea_data	ldata = { NULL };
	struct lu_buf		*buf = &info->mti_link_buf;
	int			count;
	int			rc = 0;

	ENTRY;

	buf = lu_buf_check_and_alloc(buf, PATH_MAX);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);

	ldata.ld_buf = buf;
	rc = mdd_links_read(env, child, &ldata);
	if (rc != 0) {
		if (rc == -ENOENT || rc == -ENODATA)
			rc = 0;
		RETURN(rc);
	}

	LASSERT(ldata.ld_leh != NULL);
	ldata.ld_lee = (struct link_ea_entry *)(ldata.ld_leh + 1);
	for (count = 0; count < ldata.ld_leh->leh_reccount; count++) {
		struct mdd_device *mdd = mdo2mdd(&child->mod_obj);
		struct lu_name lname;
		struct lu_fid  fid;

		linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen,
				    &lname, &fid);

		if (strncmp(lname.ln_name, name, namelen) != 0 ||
		    lu_fid_eq(&fid, mdd_object_fid(parent))) {
			ldata.ld_lee = (struct link_ea_entry *)
				       ((char *)ldata.ld_lee +
					ldata.ld_reclen);
			continue;
		}

		CDEBUG(D_INFO, "%s: update "DFID" with %.*s:"DFID"\n",
		       mdd2obd_dev(mdd)->obd_name, PFID(mdd_object_fid(child)),
		       lname.ln_namelen, lname.ln_name,
		       PFID(mdd_object_fid(parent)));
		/* update to the new parent fid */
		linkea_entry_pack(ldata.ld_lee, &lname,
				  mdd_object_fid(parent));
		if (declare)
			rc = mdd_declare_links_add(env, child, handle, &ldata,
						   MLAO_IGNORE);
		else
			rc = mdd_links_write(env, child, &ldata, handle);
		break;
	}
	RETURN(rc);
}

static int mdd_linkea_declare_update_child(const struct lu_env *env,
					   struct mdd_object *parent,
					   struct mdd_object *child,
					   const char *name, int namelen,
					   struct thandle *handle)
{
	return mdd_linkea_update_child_internal(env, parent, child, name,
						namelen, handle, true);
}

static int mdd_linkea_update_child(const struct lu_env *env,
				   struct mdd_object *parent,
				   struct mdd_object *child,
				   const char *name, int namelen,
				   struct thandle *handle)
{
	return mdd_linkea_update_child_internal(env, parent, child, name,
						namelen, handle, false);
}

static int mdd_update_linkea_internal(const struct lu_env *env,
				      struct mdd_object *mdd_pobj,
				      struct mdd_object *mdd_sobj,
				      struct mdd_object *mdd_tobj,
				      const struct lu_name *child_name,
				      struct thandle *handle,
				      int declare)
{
	struct mdd_thread_info  *info = mdd_env_info(env);
	struct linkea_data	*ldata = &info->mti_link_data;
	int			count;
	int			rc = 0;
	ENTRY;

	rc = mdd_links_read(env, mdd_sobj, ldata);
	if (rc != 0) {
		if (rc == -ENOENT || rc == -ENODATA)
			rc = 0;
		RETURN(rc);
	}

	/* If it is mulitple links file, we need update the name entry for
	 * all parent */
	LASSERT(ldata->ld_leh != NULL);
	ldata->ld_lee = (struct link_ea_entry *)(ldata->ld_leh + 1);
	for (count = 0; count < ldata->ld_leh->leh_reccount; count++) {
		struct mdd_device	*mdd = mdo2mdd(&mdd_sobj->mod_obj);
		struct mdd_object	*pobj;
		struct lu_name		lname;
		struct lu_fid		fid;

		linkea_entry_unpack(ldata->ld_lee, &ldata->ld_reclen,
				    &lname, &fid);
		ldata->ld_lee = (struct link_ea_entry *)((char *)ldata->ld_lee +
							 ldata->ld_reclen);
		pobj = mdd_object_find(env, mdd, &fid);
		if (IS_ERR(pobj)) {
			CWARN("%s: cannot find obj "DFID": rc = %ld\n",
			      mdd2obd_dev(mdd)->obd_name, PFID(&fid),
			      PTR_ERR(pobj));
			continue;
		}

		if (!mdd_object_exists(pobj)) {
			CDEBUG(D_INFO, "%s: obj "DFID" does not exist\n",
			      mdd2obd_dev(mdd)->obd_name, PFID(&fid));
			GOTO(next_put, rc);
		}

		if (pobj == mdd_pobj &&
		    lname.ln_namelen == child_name->ln_namelen &&
		    strncmp(lname.ln_name, child_name->ln_name,
			    lname.ln_namelen) == 0) {
			CDEBUG(D_INFO, "%s: skip its own %s: "DFID"\n",
			      mdd2obd_dev(mdd)->obd_name, child_name->ln_name,
			      PFID(&fid));
			GOTO(next_put, rc);
		}

		CDEBUG(D_INFO, "%s: update "DFID" with "DNAME":"DFID"\n",
		       mdd2obd_dev(mdd)->obd_name, PFID(mdd_object_fid(pobj)),
		       PNAME(&lname), PFID(mdd_object_fid(mdd_tobj)));

		if (declare) {
			/* Remove source name from source directory */
			/* Insert new fid with target name into target dir */
			rc = mdo_declare_index_delete(env, pobj, lname.ln_name,
						      handle);
			if (rc != 0)
				GOTO(next_put, rc);

			rc = mdo_declare_index_insert(env, pobj,
					mdd_object_fid(mdd_tobj),
					mdd_object_type(mdd_tobj),
					lname.ln_name, handle);
			if (rc != 0)
				GOTO(next_put, rc);

			rc = mdo_declare_ref_add(env, mdd_tobj, handle);
			if (rc)
				GOTO(next_put, rc);

			rc = mdo_declare_ref_del(env, mdd_sobj, handle);
			if (rc)
				GOTO(next_put, rc);
		} else {
			rc = __mdd_index_delete(env, pobj, lname.ln_name,
						0, handle,
						mdd_object_capa(env, pobj));
			if (rc)
				GOTO(next_put, rc);

			rc = __mdd_index_insert(env, pobj,
					mdd_object_fid(mdd_tobj),
					mdd_object_type(mdd_tobj),
					lname.ln_name, handle,
					mdd_object_capa(env, pobj));
			if (rc != 0)
				GOTO(next_put, rc);

			mdd_write_lock(env, mdd_tobj, MOR_SRC_CHILD);
			rc = mdo_ref_add(env, mdd_tobj, handle);
			mdd_write_unlock(env, mdd_tobj);
			if (rc)
				GOTO(next_put, rc);

			mdd_write_lock(env, mdd_sobj, MOR_TGT_CHILD);
			mdo_ref_del(env, mdd_sobj, handle);
			mdd_write_unlock(env, mdd_sobj);
		}
next_put:
		mdd_object_put(env, pobj);
		if (rc != 0)
			break;
	}

	RETURN(rc);
}

static int mdd_migrate_xattrs(const struct lu_env *env,
			      struct mdd_object *mdd_sobj,
			      struct mdd_object *mdd_tobj)
{
	struct mdd_thread_info	*info = mdd_env_info(env);
	struct mdd_device	*mdd = mdo2mdd(&mdd_sobj->mod_obj);
	char			*xname;
	struct thandle		*handle;
	struct lu_buf		xbuf;
	int			xlen;
	int			rem;
	int			xsize;
	int			list_xsize;
	struct lu_buf		list_xbuf;
	int			rc;

	/* retrieve xattr list from the old object */
	list_xsize = mdo_xattr_list(env, mdd_sobj, &LU_BUF_NULL,
				    mdd_object_capa(env, mdd_sobj));
	if (list_xsize == -ENODATA)
		return 0;

	if (list_xsize < 0)
		return list_xsize;

	lu_buf_check_and_alloc(&info->mti_big_buf, list_xsize);
	if (info->mti_big_buf.lb_buf == NULL)
		return -ENOMEM;

	list_xbuf.lb_buf = info->mti_big_buf.lb_buf;
	list_xbuf.lb_len = list_xsize;
	rc = mdo_xattr_list(env, mdd_sobj, &list_xbuf,
			    mdd_object_capa(env, mdd_sobj));
	if (rc < 0)
		return rc;
	rc = 0;
	rem = list_xsize;
	xname = list_xbuf.lb_buf;
	while (rem > 0) {
		xlen = strnlen(xname, rem - 1) + 1;
		if (strcmp(XATTR_NAME_LINK, xname) == 0 ||
		    strcmp(XATTR_NAME_LMA, xname) == 0 ||
		    strcmp(XATTR_NAME_LMV, xname) == 0)
			goto next;

		/* For directory, if there are default layout, migrate here */
		if (strcmp(XATTR_NAME_LOV, xname) == 0 &&
		    !S_ISDIR(lu_object_attr(&mdd_sobj->mod_obj.mo_lu)))
			goto next;

		xsize = mdo_xattr_get(env, mdd_sobj, &LU_BUF_NULL,
				      xname,
				      mdd_object_capa(env, mdd_sobj));
		if (xsize == -ENODATA)
			goto next;
		if (xsize < 0)
			GOTO(out, rc);

		lu_buf_check_and_alloc(&info->mti_link_buf, xsize);
		if (info->mti_link_buf.lb_buf == NULL)
			GOTO(out, rc = -ENOMEM);

		xbuf.lb_len = xsize;
		xbuf.lb_buf = info->mti_link_buf.lb_buf;
		rc = mdo_xattr_get(env, mdd_sobj, &xbuf, xname,
				   mdd_object_capa(env, mdd_sobj));
		if (rc == -ENODATA)
			goto next;
		if (rc < 0)
			GOTO(out, rc);

		handle = mdd_trans_create(env, mdd);
		if (IS_ERR(handle))
			GOTO(out, rc = PTR_ERR(handle));

		rc = mdo_declare_xattr_set(env, mdd_tobj, &xbuf, xname, 0,
					   handle);
		if (rc != 0)
			GOTO(stop_trans, rc);
		/* Note: this transaction is part of migration, and it is not
		 * the last step of migration, so we set th_local = 1 to avoid
		 * update last rcvd for this transaction */
		handle->th_local = 1;
		rc = mdd_trans_start(env, mdd, handle);
		if (rc != 0)
			GOTO(stop_trans, rc);

		rc = mdo_xattr_set(env, mdd_tobj, &xbuf, xname, 0, handle,
				   mdd_object_capa(env, mdd_sobj));
		if (rc == -EEXIST)
			GOTO(stop_trans, rc = 0);

		if (rc != 0)
			GOTO(stop_trans, rc);
stop_trans:
		mdd_trans_stop(env, mdd, rc, handle);
		if (rc != 0)
			GOTO(out, rc);
next:
		rem -= xlen;
		memmove(xname, xname + xlen, rem);
	}
out:
	return rc;
}

static int mdd_declare_migrate_create(const struct lu_env *env,
				      struct mdd_object *mdd_pobj,
				      struct mdd_object *mdd_sobj,
				      struct mdd_object *mdd_tobj,
				      struct md_op_spec *spec,
				      struct lu_attr *la,
				      union lmv_mds_md *mgr_ea,
				      struct linkea_data *ldata,
				      struct thandle *handle)
{
	struct lu_attr		*la_flag = MDD_ENV_VAR(env, la_for_fix);
	const struct lu_buf	*buf;
	int			rc;
	int			mgr_easize;

	rc = mdd_declare_object_create_internal(env, mdd_pobj, mdd_tobj, la,
						handle, spec, NULL);
	if (rc != 0)
		return rc;

	rc = mdd_declare_object_initialize(env, mdd_pobj, mdd_tobj, la,
					   handle);
	if (rc != 0)
		return rc;

	if (S_ISLNK(la->la_mode)) {
		const char *target_name = spec->u.sp_symname;
		int sym_len = strlen(target_name);
		const struct lu_buf *buf;

		buf = mdd_buf_get_const(env, target_name, sym_len);
		rc = dt_declare_record_write(env, mdd_object_child(mdd_tobj),
					     buf, 0, handle);
		if (rc != 0)
			return rc;
	} else if (S_ISDIR(la->la_mode)) {
		rc = mdd_declare_links_add(env, mdd_tobj, handle, ldata,
					   MLAO_IGNORE);
		if (rc != 0)
			return rc;
	}

	if (spec->u.sp_ea.eadata != NULL && spec->u.sp_ea.eadatalen != 0) {
		buf = mdd_buf_get_const(env, spec->u.sp_ea.eadata,
					spec->u.sp_ea.eadatalen);
		rc = mdo_declare_xattr_set(env, mdd_tobj, buf, XATTR_NAME_LOV,
					   0, handle);
		if (rc)
			return rc;
	}

	mgr_easize = lmv_mds_md_size(2, LMV_MAGIC_V1);
	buf = mdd_buf_get_const(env, mgr_ea, mgr_easize);
	rc = mdo_declare_xattr_set(env, mdd_sobj, buf, XATTR_NAME_LMV,
				   0, handle);
	if (rc)
		return rc;

	la_flag->la_valid = LA_FLAGS;
	la_flag->la_flags = la->la_flags | LUSTRE_IMMUTABLE_FL;
	rc = mdo_declare_attr_set(env, mdd_sobj, la_flag, handle);

	return rc;
}

static int mdd_migrate_create(const struct lu_env *env,
			      struct mdd_object *mdd_pobj,
			      struct mdd_object *mdd_sobj,
			      struct mdd_object *mdd_tobj,
			      const struct lu_name *lname,
			      struct lu_attr *la)
{
	struct mdd_thread_info	*info = mdd_env_info(env);
	struct mdd_device       *mdd = mdo2mdd(&mdd_sobj->mod_obj);
	struct md_op_spec	*spec = &info->mti_spec;
	struct lu_buf		lmm_buf = { NULL };
	struct lu_buf		link_buf = { NULL };
	const struct lu_buf	*buf;
	struct thandle		*handle;
	struct lmv_mds_md_v1	*mgr_ea;
	struct lu_attr		*la_flag = MDD_ENV_VAR(env, la_for_fix);
	struct dt_allocation_hint *hint = &mdd_env_info(env)->mti_hint;
	int			mgr_easize;
	struct linkea_data	*ldata = &mdd_env_info(env)->mti_link_data;
	int			rc;
	ENTRY;

	/* prepare spec for create */
	memset(spec, 0, sizeof(*spec));
	spec->sp_cr_lookup = 0;
	spec->sp_feat = &dt_directory_features;
	if (S_ISLNK(la->la_mode)) {
		buf = lu_buf_check_and_alloc(
				&mdd_env_info(env)->mti_big_buf,
				la->la_size + 1);
		link_buf = *buf;
		link_buf.lb_len = la->la_size + 1;
		memset(link_buf.lb_buf, 0, link_buf.lb_len);
		rc = mdd_readlink(env, &mdd_sobj->mod_obj, &link_buf);
		if (rc <= 0) {
			rc = rc != 0 ? rc : -EFAULT;
			CERROR("%s: "DFID" readlink failed: rc = %d\n",
			       mdd2obd_dev(mdd)->obd_name,
			       PFID(mdd_object_fid(mdd_sobj)), rc);
			RETURN(rc);
		}
		spec->u.sp_symname = link_buf.lb_buf;
	} else if S_ISREG(la->la_mode) {
		/* retrieve lov of the old object */
		rc = mdd_get_lov_ea(env, mdd_sobj, &lmm_buf);
		if (rc != 0 && rc != -ENODATA)
			RETURN(rc);
		if (lmm_buf.lb_buf != NULL && lmm_buf.lb_len != 0) {
			spec->u.sp_ea.eadata = lmm_buf.lb_buf;
			spec->u.sp_ea.eadatalen = lmm_buf.lb_len;
			spec->sp_cr_flags |= MDS_OPEN_HAS_EA;
		}
	} else if (S_ISDIR(la->la_mode)) {
		rc = mdd_links_read(env, mdd_sobj, ldata);
		if (rc < 0 && rc != -ENODATA)
			RETURN(rc);
	}

	mgr_ea = (struct lmv_mds_md_v1 *)info->mti_xattr_buf;
	memset(mgr_ea, 0, sizeof(*mgr_ea));
	mgr_ea->lmv_magic = cpu_to_le32(LMV_MAGIC_V1);
	mgr_ea->lmv_stripe_count = cpu_to_le32(2);
	mgr_ea->lmv_master_mdt_index = mdd_seq_site(mdd)->ss_node_id;
	mgr_ea->lmv_hash_type = cpu_to_le32(LMV_HASH_FLAG_MIGRATION);
	fid_cpu_to_le(&mgr_ea->lmv_stripe_fids[0], mdd_object_fid(mdd_sobj));
	fid_cpu_to_le(&mgr_ea->lmv_stripe_fids[1], mdd_object_fid(mdd_tobj));

	mdd_object_make_hint(env, mdd_pobj, mdd_tobj, la, spec, hint);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		GOTO(out_free, rc = PTR_ERR(handle));

	/* Note: this transaction is part of migration, and it is not
	 * the last step of migration, so we set th_local = 1 to avoid
	 * update last rcvd for this transaction */
	handle->th_local = 1;
	rc = mdd_declare_migrate_create(env, mdd_pobj, mdd_sobj, mdd_tobj,
					spec, la,
					(union lmv_mds_md *)info->mti_xattr_buf,
					ldata, handle);
	if (rc != 0)
		GOTO(stop_trans, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc != 0)
		GOTO(stop_trans, rc);

	/* create the target object */
	rc = mdd_object_create(env, mdd_pobj, mdd_tobj, la, spec, NULL, NULL,
			       hint, handle);
	if (rc != 0)
		GOTO(stop_trans, rc);

	if (S_ISDIR(la->la_mode)) {
		rc = mdd_links_write(env, mdd_tobj, ldata, handle);
		if (rc != 0)
			GOTO(stop_trans, rc);
	}

	/* Set MIGRATE EA on the source inode, so once the migration needs
	 * to be re-done during failover, the re-do process can locate the
	 * target object which is already being created. */
	mgr_easize = lmv_mds_md_size(2, LMV_MAGIC_V1);
	buf = mdd_buf_get_const(env, mgr_ea, mgr_easize);
	rc = mdo_xattr_set(env, mdd_sobj, buf, XATTR_NAME_LMV, 0,
			   handle, mdd_object_capa(env, mdd_sobj));
	if (rc != 0)
		GOTO(stop_trans, rc);

	/* Set immutable flag, so any modification is disabled until
	 * the migration is done. Once the migration is interrupted,
	 * if the resume process find the migrating object has both
	 * IMMUTALBE flag and MIGRATE EA, it need to clear IMMUTABLE
	 * flag and approve the migration */
	la_flag->la_valid = LA_FLAGS;
	la_flag->la_flags = la->la_flags | LUSTRE_IMMUTABLE_FL;
	rc = mdo_attr_set(env, mdd_sobj, la_flag, handle,
			  mdd_object_capa(env, mdd_sobj));
stop_trans:
	if (handle != NULL)
		mdd_trans_stop(env, mdd, rc, handle);
out_free:
	if (lmm_buf.lb_buf != NULL)
		OBD_FREE(lmm_buf.lb_buf, lmm_buf.lb_len);
	RETURN(rc);
}

static int mdd_migrate_entries(const struct lu_env *env,
			       struct mdd_object *mdd_sobj,
			       struct mdd_object *mdd_tobj)
{
	struct dt_object        *next = mdd_object_child(mdd_sobj);
	struct mdd_device       *mdd = mdo2mdd(&mdd_sobj->mod_obj);
	struct dt_object	*dt_tobj = mdd_object_child(mdd_tobj);
	struct thandle		*handle;
	struct dt_it            *it;
	const struct dt_it_ops  *iops;
	int                      rc;
	int                      result;
	struct lu_dirent        *ent;
	ENTRY;

	OBD_ALLOC(ent, NAME_MAX + sizeof(*ent) + 1);
	if (ent == NULL)
		RETURN(-ENOMEM);

	if (!dt_try_as_dir(env, next))
		GOTO(out_ent, rc = -ENOTDIR);
	/*
	 * iterate directories
	 */
	iops = &next->do_index_ops->dio_it;
	it = iops->init(env, next, LUDA_FID | LUDA_TYPE,
			mdd_object_capa(env, mdd_sobj));
	if (IS_ERR(it))
		GOTO(out_ent, rc = PTR_ERR(it));

	rc = iops->load(env, it, 0);
	if (rc == 0)
		rc = iops->next(env, it);
	else if (rc > 0)
		rc = 0;
	/*
	 * At this point and across for-loop:
	 *
	 *  rc == 0 -> ok, proceed.
	 *  rc >  0 -> end of directory.
	 *  rc <  0 -> error.
	 */
	do {
		struct mdd_object	*child;
		char			*name = mdd_env_info(env)->mti_key;
		int			len;
		int			recsize;
		int			is_dir;
		bool			target_exist = false;

		len = iops->key_size(env, it);
		if (len == 0)
			goto next;

		result = iops->rec(env, it, (struct dt_rec *)ent,
				   LUDA_FID | LUDA_TYPE);
		if (result == -ESTALE)
			goto next;
		if (result != 0) {
			rc = result;
			goto out;
		}

		fid_le_to_cpu(&ent->lde_fid, &ent->lde_fid);
		recsize = le16_to_cpu(ent->lde_reclen);

		/* Insert new fid with target name into target dir */
		if ((ent->lde_namelen == 1 && ent->lde_name[0] == '.') ||
		    (ent->lde_namelen == 2 && ent->lde_name[0] == '.' &&
		     ent->lde_name[1] == '.'))
			goto next;

		child = mdd_object_find(env, mdd, &ent->lde_fid);
		if (IS_ERR(child))
			GOTO(out, rc = PTR_ERR(child));

		is_dir = S_ISDIR(mdd_object_type(child));

		snprintf(name, ent->lde_namelen + 1, "%s", ent->lde_name);

		/* Check whether the name has been inserted to the target */
		if (dt_try_as_dir(env, dt_tobj)) {
			struct lu_fid *fid = &mdd_env_info(env)->mti_fid2;

			rc = dt_lookup(env, dt_tobj, (struct dt_rec *)fid,
				       (struct dt_key *)name,
				       mdd_object_capa(env, mdd_tobj));
			if (unlikely(rc == 0))
				target_exist = true;
		}

		handle = mdd_trans_create(env, mdd);
		if (IS_ERR(handle))
			GOTO(out, rc = PTR_ERR(handle));

		/* Note: this transaction is part of migration, and it is not
		 * the last step of migration, so we set th_local = 1 to avoid
		 * updating last rcvd for this transaction */
		handle->th_local = 1;
		if (likely(!target_exist)) {
			rc = mdo_declare_index_insert(env, mdd_tobj,
						      &ent->lde_fid,
						      mdd_object_type(child),
						      name, handle);
			if (rc != 0)
				GOTO(out_put, rc);

			if (is_dir) {
				rc = mdo_declare_ref_add(env, mdd_tobj, handle);
				if (rc != 0)
					GOTO(out_put, rc);
			}
		}

		rc = mdo_declare_index_delete(env, mdd_sobj, name, handle);
		if (rc != 0)
			GOTO(out_put, rc);

		if (is_dir) {
			rc = mdo_declare_ref_del(env, mdd_sobj, handle);
			if (rc != 0)
				GOTO(out_put, rc);

			/* Update .. for child */
			rc = mdo_declare_index_delete(env, child, dotdot,
						      handle);
			if (rc != 0)
				GOTO(out_put, rc);

			rc = mdo_declare_index_insert(env, child,
						      mdd_object_fid(mdd_tobj),
						      S_IFDIR, dotdot, handle);
			if (rc != 0)
				GOTO(out_put, rc);
		}

		rc = mdd_linkea_declare_update_child(env, mdd_tobj,
						     child, name,
						     strlen(name),
						     handle);
		if (rc != 0)
			GOTO(out_put, rc);

		rc = mdd_trans_start(env, mdd, handle);
		if (rc != 0) {
			CERROR("%s: transaction start failed: rc = %d\n",
			       mdd2obd_dev(mdd)->obd_name, rc);
			GOTO(out_put, rc);
		}

		if (likely(!target_exist)) {
			rc = __mdd_index_insert(env, mdd_tobj, &ent->lde_fid,
						mdd_object_type(child),
						name, handle,
						mdd_object_capa(env, mdd_tobj));
			if (rc != 0)
				GOTO(out_put, rc);

			if (is_dir) {
				rc = mdo_ref_add(env, mdd_tobj, handle);
				if (rc != 0)
					GOTO(out_put, rc);

			}
		}

		rc = __mdd_index_delete(env, mdd_sobj, name, is_dir, handle,
					mdd_object_capa(env, mdd_sobj));
		if (rc != 0)
			GOTO(out_put, rc);

		if (is_dir) {
			rc = __mdd_index_delete_only(env, child, dotdot, handle,
						   mdd_object_capa(env, child));
			if (rc != 0)
				GOTO(out_put, rc);

			rc = __mdd_index_insert_only(env, child,
					 mdd_object_fid(mdd_tobj), S_IFDIR,
					 dotdot, handle,
					 mdd_object_capa(env, child));
			if (rc != 0)
				GOTO(out_put, rc);
		}

		rc = mdd_linkea_update_child(env, mdd_tobj, child, name,
					     strlen(name), handle);

out_put:
		mdd_object_put(env, child);
		mdd_trans_stop(env, mdd, rc, handle);
		if (rc != 0)
			GOTO(out, rc);
next:
		result = iops->next(env, it);
		if (OBD_FAIL_CHECK(OBD_FAIL_MIGRATE_ENTRIES))
			GOTO(out, rc = -EINTR);

		if (result == -ESTALE)
			goto next;
	} while (result == 0);
out:
	iops->put(env, it);
	iops->fini(env, it);
out_ent:
	OBD_FREE(ent, NAME_MAX + sizeof(*ent) + 1);
	RETURN(rc);
}

static int mdd_declare_update_linkea(const struct lu_env *env,
				     struct mdd_object *mdd_pobj,
				     struct mdd_object *mdd_sobj,
				     struct mdd_object *mdd_tobj,
				     struct thandle *handle,
				     const struct lu_name *child_name)
{
	return mdd_update_linkea_internal(env, mdd_pobj, mdd_sobj, mdd_tobj,
					  child_name, handle, 1);
}

static int mdd_update_linkea(const struct lu_env *env,
			     struct mdd_object *mdd_pobj,
			     struct mdd_object *mdd_sobj,
			     struct mdd_object *mdd_tobj,
			     struct thandle *handle,
			     const struct lu_name *child_name)
{
	return mdd_update_linkea_internal(env, mdd_pobj, mdd_sobj, mdd_tobj,
					  child_name, handle, 0);
}

static int mdd_declare_migrate_update_name(const struct lu_env *env,
					   struct mdd_object *mdd_pobj,
					   struct mdd_object *mdd_sobj,
					   struct mdd_object *mdd_tobj,
					   const struct lu_name *lname,
					   struct lu_attr *la,
					   struct lu_attr *parent_la,
					   struct thandle *handle)
{
	struct lu_attr	*la_flag = MDD_ENV_VAR(env, tattr);
	int		rc;

	/* Revert IMMUTABLE flag */
	la_flag->la_valid = LA_FLAGS;
	la_flag->la_flags = la->la_flags & ~LUSTRE_IMMUTABLE_FL;
	rc = mdo_declare_attr_set(env, mdd_sobj, la_flag, handle);
	if (rc != 0)
		return rc;

	/* delete entry from source dir */
	rc = mdo_declare_index_delete(env, mdd_pobj, lname->ln_name, handle);
	if (rc != 0)
		return rc;

	rc = mdd_declare_update_linkea(env, mdd_pobj, mdd_sobj,
				       mdd_tobj, handle, lname);
	if (rc != 0)
		return rc;

	if (S_ISREG(mdd_object_type(mdd_sobj))) {
		rc = mdo_declare_xattr_del(env, mdd_sobj, XATTR_NAME_LOV,
					   handle);
		if (rc != 0)
			return rc;
	}

	if (S_ISDIR(mdd_object_type(mdd_sobj))) {
		rc = mdo_declare_ref_del(env, mdd_pobj, handle);
		if (rc != 0)
			return rc;
	}

	/* new name */
	rc = mdo_declare_index_insert(env, mdd_pobj, mdo2fid(mdd_tobj),
				      mdd_object_type(mdd_tobj),
				      lname->ln_name, handle);
	if (rc != 0)
		return rc;

	if (S_ISDIR(mdd_object_type(mdd_sobj))) {
		rc = mdo_declare_ref_add(env, mdd_pobj, handle);
		if (rc != 0)
			return rc;
	}

	/* delete old object */
	rc = mdo_declare_ref_del(env, mdd_sobj, handle);
	if (rc != 0)
		return rc;

	if (S_ISDIR(mdd_object_type(mdd_sobj))) {
		/* delete old object */
		rc = mdo_declare_ref_del(env, mdd_sobj, handle);
		if (rc != 0)
			return rc;
		/* set nlink to 0 */
		rc = mdo_declare_attr_set(env, mdd_sobj, la, handle);
		if (rc != 0)
			return rc;
	}

	rc = mdd_declare_finish_unlink(env, mdd_sobj, handle);
	if (rc)
		return rc;

	rc = mdo_declare_attr_set(env, mdd_pobj, parent_la, handle);

	return rc;
}

static int mdd_migrate_update_name(const struct lu_env *env,
				   struct mdd_object *mdd_pobj,
				   struct mdd_object *mdd_sobj,
				   struct mdd_object *mdd_tobj,
				   const struct lu_name *lname,
				   struct md_attr *ma)
{
	struct lu_attr		*p_la = MDD_ENV_VAR(env, la_for_fix);
	struct lu_attr		*so_attr = MDD_ENV_VAR(env, cattr);
	struct lu_attr		*la_flag = MDD_ENV_VAR(env, tattr);
	struct mdd_device	*mdd = mdo2mdd(&mdd_sobj->mod_obj);
	struct thandle		*handle;
	int			is_dir = S_ISDIR(mdd_object_type(mdd_sobj));
	const char		*name = lname->ln_name;
	int			rc;
	ENTRY;

	/* update time for parent */
	LASSERT(ma->ma_attr.la_valid & LA_CTIME);
	p_la->la_ctime = p_la->la_mtime = ma->ma_attr.la_ctime;
	p_la->la_valid = LA_CTIME;

	rc = mdd_la_get(env, mdd_sobj, so_attr, mdd_object_capa(env, mdd_sobj));
	if (rc != 0)
		RETURN(rc);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	rc = mdd_declare_migrate_update_name(env, mdd_pobj, mdd_sobj, mdd_tobj,
					     lname, so_attr, p_la, handle);
	if (rc != 0) {
		/* If the migration can not be fit in one transaction, just
		 * leave it in the original MDT */
		if (rc == -E2BIG)
			GOTO(stop_trans, rc = 0);
		else
			GOTO(stop_trans, rc);
	}

	CDEBUG(D_INFO, "%s: update "DFID"/"DFID" with %s:"DFID"\n",
	       mdd2obd_dev(mdd)->obd_name, PFID(mdd_object_fid(mdd_pobj)),
	       PFID(mdd_object_fid(mdd_sobj)), lname->ln_name,
	       PFID(mdd_object_fid(mdd_tobj)));

	rc = mdd_trans_start(env, mdd, handle);
	if (rc != 0)
		GOTO(stop_trans, rc);

	/* Revert IMMUTABLE flag */
	la_flag->la_valid = LA_FLAGS;
	la_flag->la_flags = so_attr->la_flags & ~LUSTRE_IMMUTABLE_FL;
	rc = mdo_attr_set(env, mdd_sobj, la_flag, handle,
			  mdd_object_capa(env, mdd_pobj));
	if (rc != 0)
		GOTO(stop_trans, rc);

	/* Remove source name from source directory */
	rc = __mdd_index_delete(env, mdd_pobj, name, is_dir, handle,
				mdd_object_capa(env, mdd_pobj));
	if (rc != 0)
		GOTO(stop_trans, rc);

	rc = mdd_update_linkea(env, mdd_pobj, mdd_sobj, mdd_tobj,
			       handle, lname);
	if (rc != 0)
		GOTO(stop_trans, rc);

	if (S_ISREG(so_attr->la_mode)) {
		if (so_attr->la_nlink == 1) {
			rc = mdo_xattr_del(env, mdd_sobj, XATTR_NAME_LOV,
					   handle,
					   mdd_object_capa(env, mdd_sobj));
			if (rc != 0 && rc != -ENODATA)
				GOTO(stop_trans, rc);
		}
	}

	/* Insert new fid with target name into target dir */
	rc = __mdd_index_insert(env, mdd_pobj, mdd_object_fid(mdd_tobj),
				mdd_object_type(mdd_tobj), name,
				handle, mdd_object_capa(env, mdd_pobj));
	if (rc != 0)
		GOTO(stop_trans, rc);

	rc = mdd_links_add(env, mdd_tobj, mdo2fid(mdd_pobj), lname, handle,
			   NULL, 1);
	if (rc != 0)
		GOTO(stop_trans, rc);

	mdd_write_lock(env, mdd_sobj, MOR_SRC_CHILD);
	mdo_ref_del(env, mdd_sobj, handle);
	if (is_dir)
		mdo_ref_del(env, mdd_sobj, handle);

	/* Get the attr again after ref_del */
	rc = mdd_la_get(env, mdd_sobj, so_attr,
			mdd_object_capa(env, mdd_sobj));
	if (rc != 0)
		GOTO(out_unlock, rc);

	ma->ma_attr = *so_attr;
	ma->ma_valid |= MA_INODE;
	rc = mdd_finish_unlink(env, mdd_sobj, ma, mdd_pobj, lname, handle);
	if (rc != 0)
		GOTO(out_unlock, rc);

	rc = mdd_attr_set_internal(env, mdd_pobj, p_la, handle, 0);
	if (rc != 0)
		GOTO(out_unlock, rc);

out_unlock:
	mdd_write_unlock(env, mdd_sobj);

stop_trans:
	mdd_trans_stop(env, mdd, rc, handle);

	RETURN(rc);
}

/**
 * Check whether we should migrate the file/dir
 * return val
 * 	< 0  permission check failed or other error.
 * 	= 0  the file can be migrated.
 * 	> 0  the file does not need to be migrated, mostly
 * 	     for multiple link file
 **/
static int mdd_migrate_sanity_check(const struct lu_env *env,
				    struct mdd_object *pobj,
				    const struct lu_attr *pattr,
				    struct mdd_object *sobj,
				    struct lu_attr *sattr)
{
	struct mdd_thread_info  *info = mdd_env_info(env);
	struct linkea_data	*ldata = &info->mti_link_data;
	int			mgr_easize;
	struct lu_buf		*mgr_buf;
	int			count;
	int			rc;

	ENTRY;

	mgr_easize = lmv_mds_md_size(2, LMV_MAGIC_V1);
	mgr_buf = lu_buf_check_and_alloc(&info->mti_big_buf, mgr_easize);
	if (mgr_buf->lb_buf == NULL)
		RETURN(-ENOMEM);

	rc = mdo_xattr_get(env, sobj, mgr_buf, XATTR_NAME_LMV,
			   mdd_object_capa(env, sobj));
	if (rc > 0) {
		union lmv_mds_md *lmm = mgr_buf->lb_buf;

		/* If the object has migrateEA, it means IMMUTE flag
		 * is being set by previous migration process, so it
		 * needs to override the IMMUTE flag, otherwise the
		 * following sanity check will fail */
		if (le32_to_cpu(lmm->lmv_md_v1.lmv_hash_type) &
						LMV_HASH_FLAG_MIGRATION) {
			struct mdd_device *mdd = mdo2mdd(&sobj->mod_obj);

			sattr->la_flags &= ~LUSTRE_IMMUTABLE_FL;
			CDEBUG(D_HA, "%s: "DFID" override IMMUTE FLAG\n",
			       mdd2obd_dev(mdd)->obd_name,
			       PFID(mdd_object_fid(sobj)));
		}
	}

	rc = mdd_rename_sanity_check(env, pobj, pattr, pobj, pattr,
				     sobj, sattr, NULL, NULL);
	if (rc != 0)
		RETURN(rc);

	/* Then it will check if the file should be migrated. If the file
	 * has mulitple links, we only need migrate the file if all of its
	 * entries has been migrated to the remote MDT */
	if (!S_ISREG(sattr->la_mode) || sattr->la_nlink < 2)
		RETURN(0);

	rc = mdd_links_read(env, sobj, ldata);
	if (rc != 0) {
		/* For multiple links files, if there are no linkEA data at all,
		 * means the file might be created before linkEA is enabled, and
		 * all all of its links should not be migrated yet, otherwise
		 * it should have some linkEA there */
		if (rc == -ENOENT || rc == -ENODATA)
			RETURN(1);
		RETURN(rc);
	}

	/* If it is mulitple links file, we need update the name entry for
	 * all parent */
	LASSERT(ldata->ld_leh != NULL);
	ldata->ld_lee = (struct link_ea_entry *)(ldata->ld_leh + 1);
	for (count = 0; count < ldata->ld_leh->leh_reccount; count++) {
		struct mdd_device	*mdd = mdo2mdd(&sobj->mod_obj);
		struct mdd_object	*lpobj;
		struct lu_name		lname;
		struct lu_fid		fid;

		linkea_entry_unpack(ldata->ld_lee, &ldata->ld_reclen,
				    &lname, &fid);
		ldata->ld_lee = (struct link_ea_entry *)((char *)ldata->ld_lee +
							 ldata->ld_reclen);
		lpobj = mdd_object_find(env, mdd, &fid);
		if (IS_ERR(lpobj)) {
			CWARN("%s: cannot find obj "DFID": rc = %ld\n",
			      mdd2obd_dev(mdd)->obd_name, PFID(&fid),
			      PTR_ERR(lpobj));
			continue;
		}

		if (!mdd_object_exists(lpobj) || mdd_object_remote(lpobj)) {
			CDEBUG(D_INFO, DFID"%.*s: is on remote MDT.\n",
			       PFID(&fid), lname.ln_namelen, lname.ln_name);
			mdd_object_put(env, lpobj);
			continue;
		}

		CDEBUG(D_INFO, DFID"still has local entry %.*s "DFID"\n",
		       PFID(mdd_object_fid(sobj)), lname.ln_namelen,
		       lname.ln_name, PFID(&fid));
		mdd_object_put(env, lpobj);
		rc = 1;
		break;
	}

	RETURN(rc);
}

static int mdd_migrate(const struct lu_env *env, struct md_object *pobj,
		       struct md_object *sobj, const struct lu_name *lname,
		       struct md_object *tobj, struct md_attr *ma)
{
	struct mdd_object	*mdd_pobj = md2mdd_obj(pobj);
	struct mdd_device	*mdd = mdo2mdd(pobj);
	struct mdd_object	*mdd_sobj = md2mdd_obj(sobj);
	struct mdd_object	*mdd_tobj = NULL;
	struct lu_attr		*so_attr = MDD_ENV_VAR(env, cattr);
	struct lu_attr		*pattr = MDD_ENV_VAR(env, pattr);
	int			rc;

	ENTRY;
	/* If the file will being migrated, it will check whether
	 * the file is being opened by someone else right now */
	mdd_read_lock(env, mdd_sobj, MOR_SRC_CHILD);
	if (mdd_sobj->mod_count >= 1) {
		CERROR("%s: "DFID"%s is already opened count %d: rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name,
		       PFID(mdd_object_fid(mdd_sobj)), lname->ln_name,
		       mdd_sobj->mod_count, -EBUSY);
		mdd_read_unlock(env, mdd_sobj);
		GOTO(put, rc = -EBUSY);
	}
	mdd_read_unlock(env, mdd_sobj);

	rc = mdd_la_get(env, mdd_sobj, so_attr, mdd_object_capa(env, mdd_sobj));
	if (rc != 0)
		GOTO(put, rc);

	rc = mdd_la_get(env, mdd_pobj, pattr, BYPASS_CAPA);
	if (rc != 0)
		GOTO(put, rc);

	rc = mdd_migrate_sanity_check(env, mdd_pobj, pattr, mdd_sobj, so_attr);
	if (rc != 0) {
		if (rc > 0)
			rc = 0;
		GOTO(put, rc);
	}

	/* Sigh, it is impossible to finish all of migration in a single
	 * transaction, for example migrating big directory entries to the
	 * new MDT, it needs insert all of name entries of children in the
	 * new directory.
	 *
	 * So migration will be done in multiple steps and transactions.
	 *
	 * 1. create an orphan object on the remote MDT in one transaction.
	 * 2. migrate extend attributes to the new target file/directory.
	 * 3. For directory, migrate the entries to the new MDT and update
	 * linkEA of each children. Because we can not migrate all entries
	 * in a single transaction, so the migrating directory will become
	 * a striped directory during migration, so once the process is
	 * interrupted, the directory is still accessible. (During lookup,
	 * client will locate the name by searching both original and target
	 * object).
	 * 4. Finally, update the name/FID to point to the new file/directory
	 * in a separate transaction.
	 */

	/* step 1: Check whether the orphan object has been created, and create
	 * orphan object on the remote MDT if needed */
	mdd_tobj = md2mdd_obj(tobj);
	if (!mdd_object_exists(mdd_tobj)) {
		rc = mdd_migrate_create(env, mdd_pobj, mdd_sobj, mdd_tobj,
					lname, so_attr);
		if (rc != 0)
			GOTO(put, rc);
	}

	/* step 2: migrate xattr */
	rc = mdd_migrate_xattrs(env, mdd_sobj, mdd_tobj);
	if (rc != 0)
		GOTO(put, rc);

	/* step 3: migrate name entries to the orphan object */
	if (S_ISDIR(lu_object_attr(&mdd_sobj->mod_obj.mo_lu))) {
		rc = mdd_migrate_entries(env, mdd_sobj, mdd_tobj);
		if (rc != 0)
			GOTO(put, rc);
		if (unlikely(OBD_FAIL_CHECK_RESET(OBD_FAIL_MIGRATE_NET_REP,
						  OBD_FAIL_MDS_REINT_NET_REP)))
			GOTO(put, rc = 0);
	} else {
		OBD_FAIL_TIMEOUT(OBD_FAIL_MIGRATE_DELAY, cfs_fail_val);
	}

	/* step 4: update name entry to the new object */
	rc = mdd_migrate_update_name(env, mdd_pobj, mdd_sobj, mdd_tobj, lname,
				     ma);
	if (rc != 0)
		GOTO(put, rc);
put:
	RETURN(rc);
}

const struct md_dir_operations mdd_dir_ops = {
	.mdo_is_subdir     = mdd_is_subdir,
	.mdo_lookup        = mdd_lookup,
	.mdo_create        = mdd_create,
	.mdo_rename        = mdd_rename,
	.mdo_link          = mdd_link,
	.mdo_unlink        = mdd_unlink,
	.mdo_create_data   = mdd_create_data,
	.mdo_migrate	   = mdd_migrate,
};
