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
#include <lustre_lmv.h>
#include <lustre_idmap.h>

#include "mdd_internal.h"

static const char dot[] = ".";
static const char dotdot[] = "..";

static struct lu_name lname_dotdot = {
	.ln_name	= (char *) dotdot,
	.ln_namelen	= sizeof(dotdot) - 1,
};

static inline int
mdd_name_check(const struct lu_env *env, struct mdd_device *m,
	       const struct lu_name *ln)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	bool enc = info->mdi_pattr.la_valid & LA_FLAGS &&
		info->mdi_pattr.la_flags & LUSTRE_ENCRYPT_FL;

	if (!lu_name_is_valid(ln))
		return -EINVAL;
	else if (!enc && ln->ln_namelen > m->mdd_dt_conf.ddp_max_name_len)
		return -ENAMETOOLONG;
	else
		return 0;
}

/* Get FID from name and parent */
static int
__mdd_lookup(const struct lu_env *env, struct md_object *pobj,
	     const struct lu_attr *pattr, const struct lu_name *lname,
	     struct lu_fid *fid, unsigned int may_mask)
{
	const char *name = lname->ln_name;
	const struct dt_key *key = (const struct dt_key *)name;
	struct mdd_object *mdd_obj = md2mdd_obj(pobj);
	struct dt_object *dir = mdd_object_child(mdd_obj);
	int rc;

	ENTRY;

	if (unlikely(mdd_is_dead_obj(mdd_obj)))
		RETURN(-ESTALE);

	if (!mdd_object_exists(mdd_obj))
		RETURN(-ESTALE);

	if (mdd_object_remote(mdd_obj)) {
		CDEBUG(D_INFO, "%s: Object "DFID" located on remote server\n",
		       mdd_obj_dev_name(mdd_obj),
		       PFID(mdd_object_fid(mdd_obj)));
	}

	rc = mdd_permission_internal_locked(env, mdd_obj, pattr, may_mask,
					    DT_TGT_PARENT);
	if (rc)
		RETURN(rc);

	if (likely(S_ISDIR(mdd_object_type(mdd_obj)) &&
		   dt_try_as_dir(env, dir)))
		rc = dt_lookup(env, dir, (struct dt_rec *)fid, key);
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

	rc = mdd_la_get(env, md2mdd_obj(pobj), pattr);
	if (rc != 0)
		RETURN(rc);

	rc = __mdd_lookup(env, pobj, pattr, lname, fid,
			  (spec != NULL && spec->sp_permitted) ? 0 : MAY_EXEC);
        RETURN(rc);
}

/** Read the link EA into a temp buffer.
 * Uses the mdd_thread_info::mdi_link_buf since it is generally large.
 * A pointer to the buffer is stored in \a ldata::ld_buf.
 *
 * \retval 0 or error
 */
static int __mdd_links_read(const struct lu_env *env,
			    struct mdd_object *mdd_obj,
			    struct linkea_data *ldata)
{
	int rc;

	if (!mdd_object_exists(mdd_obj))
		return -ENODATA;

	/* First try a small buf */
	LASSERT(env != NULL);
	ldata->ld_buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mdi_link_buf,
					       PAGE_SIZE);
	if (ldata->ld_buf->lb_buf == NULL)
		return -ENOMEM;

	rc = mdo_xattr_get(env, mdd_obj, ldata->ld_buf, XATTR_NAME_LINK);
	if (rc == -ERANGE) {
		/* Buf was too small, figure out what we need. */
		lu_buf_free(ldata->ld_buf);
		rc = mdo_xattr_get(env, mdd_obj, ldata->ld_buf,
				   XATTR_NAME_LINK);
		if (rc < 0)
			return rc;
		ldata->ld_buf = lu_buf_check_and_alloc(ldata->ld_buf, rc);
		if (ldata->ld_buf->lb_buf == NULL)
			return -ENOMEM;
		rc = mdo_xattr_get(env, mdd_obj, ldata->ld_buf,
				  XATTR_NAME_LINK);
	}
	if (rc < 0) {
		lu_buf_free(ldata->ld_buf);
		ldata->ld_buf = NULL;
		return rc;
	}

	return linkea_init(ldata);
}

int mdd_links_read(const struct lu_env *env,
		   struct mdd_object *mdd_obj,
		   struct linkea_data *ldata)
{
	int rc;

	rc = __mdd_links_read(env, mdd_obj, ldata);
	if (!rc)
		rc = linkea_init(ldata);

	return rc;
}

static int mdd_links_read_with_rec(const struct lu_env *env,
				   struct mdd_object *mdd_obj,
				   struct linkea_data *ldata)
{
	int rc;

	rc = __mdd_links_read(env, mdd_obj, ldata);
	if (!rc)
		rc = linkea_init_with_rec(ldata);

	return rc;
}

/**
 * Get parent FID of the directory
 *
 * Read parent FID from linkEA, if that fails, then do lookup
 * dotdot to get the parent FID.
 *
 * \param[in] env	execution environment
 * \param[in] obj	object from which to find the parent FID
 * \param[in] attr	attribute of the object
 * \param[out] fid	fid to get the parent FID
 *
 * \retval		0 if getting the parent FID succeeds.
 * \retval		negative errno if getting the parent FID fails.
 **/
static inline int mdd_parent_fid(const struct lu_env *env,
				 struct mdd_object *obj,
				 const struct lu_attr *attr,
				 struct lu_fid *fid)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct linkea_data ldata = { NULL };
	struct lu_buf *buf = &info->mdi_link_buf;
	struct lu_name lname;
	int rc = 0;

	ENTRY;

	LASSERTF(S_ISDIR(mdd_object_type(obj)),
		 "%s: FID "DFID" is not a directory type = %o\n",
		 mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)),
		 mdd_object_type(obj));

	buf = lu_buf_check_and_alloc(buf, PATH_MAX);
	if (buf->lb_buf == NULL)
		GOTO(lookup, rc = 0);

	ldata.ld_buf = buf;
	rc = mdd_links_read_with_rec(env, obj, &ldata);
	if (rc != 0)
		GOTO(lookup, rc);

	/* the obj is not locked, don't cache attributes */
	mdd_invalidate(env, &obj->mod_obj);

	LASSERT(ldata.ld_leh != NULL);
	/* Directory should only have 1 parent */
	if (ldata.ld_leh->leh_reccount > 1)
		GOTO(lookup, rc);

	ldata.ld_lee = (struct link_ea_entry *)(ldata.ld_leh + 1);

	linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen, &lname, fid);
	if (likely(fid_is_sane(fid)))
		RETURN(0);
lookup:
	rc =  __mdd_lookup(env, &obj->mod_obj, attr, &lname_dotdot, fid, 0);
	RETURN(rc);
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
 * return 1: if \a tfid is the fid of the ancestor of \a mo;
 * return 0: if not;
 * otherwise: values < 0, errors.
 */
static int mdd_is_parent(const struct lu_env *env,
			struct mdd_device *mdd,
			struct mdd_object *mo,
			const struct lu_attr *attr,
			const struct lu_fid *tfid)
{
	struct mdd_object *mp;
	struct lu_fid *pfid;
	int rc;

	LASSERT(!lu_fid_eq(mdd_object_fid(mo), tfid));
	pfid = &mdd_env_info(env)->mdi_fid;

	if (mdd_is_root(mdd, mdd_object_fid(mo)))
		return 0;

	if (mdd_is_root(mdd, tfid))
		return 1;

	rc = mdd_parent_fid(env, mo, attr, pfid);
	if (rc)
		return rc;

	while (1) {
		if (lu_fid_eq(pfid, tfid))
			return 1;

		if (mdd_is_root(mdd, pfid))
			return 0;

		mp = mdd_object_find(env, mdd, pfid);
		if (IS_ERR(mp))
			return PTR_ERR(mp);

		if (!mdd_object_exists(mp)) {
			mdd_object_put(env, mp);
			return -ENOENT;
		}

		rc = mdd_parent_fid(env, mp, attr, pfid);
		mdd_object_put(env, mp);
		if (rc)
			return rc;
	}

	return 0;
}

/*
 * No permission check is needed.
 *
 * returns 1: if fid is ancestor of @mo;
 * returns 0: if fid is not an ancestor of @mo;
 * returns < 0: if error
 */
int mdd_is_subdir(const struct lu_env *env, struct md_object *mo,
		  const struct lu_fid *fid)
{
	struct mdd_device *mdd = mdo2mdd(mo);
	struct lu_attr *attr = MDD_ENV_VAR(env, cattr);
	int rc;
	ENTRY;

	if (!mdd_object_exists(md2mdd_obj(mo)))
		RETURN(-ENOENT);

	if (!S_ISDIR(mdd_object_type(md2mdd_obj(mo))))
		RETURN(-ENOTDIR);

	rc = mdd_la_get(env, md2mdd_obj(mo), attr);
	if (rc != 0)
		RETURN(rc);

	rc = mdd_is_parent(env, mdd, md2mdd_obj(mo), attr, fid);
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
int mdd_dir_is_empty(const struct lu_env *env, struct mdd_object *dir)
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
	it = iops->init(env, obj, LUDA_64BITHASH);
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
	} else {
		result = PTR_ERR(it);
		/* -ENODEV means no valid stripe */
		if (result == -ENODEV)
			RETURN(0);
	}
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
	int rc = 0;
	ENTRY;

	if (cobj && mdd_object_exists(cobj))
		RETURN(-EEXIST);

	if (mdd_is_dead_obj(pobj))
		RETURN(-ENOENT);

	if (check_perm)
		rc = mdd_permission_internal_locked(env, pobj, pattr,
						    MAY_WRITE | MAY_EXEC,
						    DT_TGT_PARENT);
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
					    DT_TGT_PARENT);
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

	return !cap_raised(uc->uc_cap, CAP_FOWNER);
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
					    DT_TGT_PARENT);
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
			if (!S_ISDIR(tattr->la_mode))
				RETURN(-ENOTDIR);

			if (mdd_is_root(mdo2mdd(&tobj->mod_obj),
					mdd_object_fid(tobj)))
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
	rc = mdd_name_check(env, m, lname);
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
				   const char *name, struct thandle *handle)
{
	struct dt_object *next = mdd_object_child(pobj);
	int rc;
	ENTRY;

	if (dt_try_as_dir(env, next))
		rc = dt_delete(env, next, (struct dt_key *)name, handle);
	else
		rc = -ENOTDIR;

	RETURN(rc);
}

static int __mdd_index_insert_only(const struct lu_env *env,
				   struct mdd_object *pobj,
				   const struct lu_fid *lf, __u32 type,
				   const char *name, struct thandle *handle)
{
	struct dt_object *next = mdd_object_child(pobj);
	int rc;
	ENTRY;

	if (dt_try_as_dir(env, next)) {
		struct dt_insert_rec *rec = &mdd_env_info(env)->mdi_dt_rec;

		rec->rec_fid = lf;
		rec->rec_type = type;
		rc = dt_insert(env, next, (const struct dt_rec *)rec,
			       (const struct dt_key *)name, handle);
	} else {
		rc = -ENOTDIR;
	}
	RETURN(rc);
}

/* insert named index, add reference if isdir */
static int __mdd_index_insert(const struct lu_env *env, struct mdd_object *pobj,
			      const struct lu_fid *lf, __u32 type,
			      const char *name, struct thandle *handle)
{
	int rc;
	ENTRY;

	rc = __mdd_index_insert_only(env, pobj, lf, type, name, handle);
	if (rc == 0 && S_ISDIR(type)) {
		mdd_write_lock(env, pobj, DT_TGT_PARENT);
		mdo_ref_add(env, pobj, handle);
		mdd_write_unlock(env, pobj);
	}

	RETURN(rc);
}

/* delete named index, drop reference if isdir */
static int __mdd_index_delete(const struct lu_env *env, struct mdd_object *pobj,
			      const char *name, int is_dir,
			      struct thandle *handle)
{
	int rc;
	ENTRY;

	rc = __mdd_index_delete_only(env, pobj, name, handle);
	if (rc == 0 && is_dir) {
		mdd_write_lock(env, pobj, DT_TGT_PARENT);
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
	enum changelog_rec_flags clf_flags = CLF_EXTRA_FLAGS;
	enum changelog_rec_extra_flags crfe = CLFE_UIDGID | CLFE_NID;

	if (sname != NULL)
		clf_flags |= CLF_RENAME;

	if (uc != NULL && uc->uc_jobid[0] != '\0')
		clf_flags |= CLF_JOBID;

	return llog_data_len(LLOG_CHANGELOG_HDR_SZ +
			     changelog_rec_offset(clf_flags, crfe) +
			     (tname != NULL ? tname->ln_namelen : 0) +
			     (sname != NULL ? 1 + sname->ln_namelen : 0));
}

int mdd_declare_changelog_store(const struct lu_env *env,
				struct mdd_device *mdd,
				enum changelog_rec_type type,
				const struct lu_name *tname,
				const struct lu_name *sname,
				struct thandle *handle)
{
	struct obd_device *obd = mdd2obd_dev(mdd);
	struct llog_ctxt *ctxt;
	struct llog_rec_hdr rec_hdr;
	struct thandle *llog_th;
	int rc;

	if (!mdd_changelog_enabled(env, mdd, type))
		return 0;

	rec_hdr.lrh_len = mdd_llog_record_calc_size(env, tname, sname);
	rec_hdr.lrh_type = CHANGELOG_REC;

	ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
	if (ctxt == NULL)
		return -ENXIO;

	llog_th = thandle_get_sub(env, handle, ctxt->loc_handle->lgh_obj);
	if (IS_ERR(llog_th))
		GOTO(out_put, rc = PTR_ERR(llog_th));

	rc = llog_declare_add(env, ctxt->loc_handle, &rec_hdr, llog_th);

out_put:
	llog_ctxt_put(ctxt);

	return rc;
}

int mdd_changelog_write_rec(const struct lu_env *env,
			    struct llog_handle *loghandle,
			    struct llog_rec_hdr *r,
			    struct llog_cookie *cookie,
			    int idx, struct thandle *th)
{
	int rc;

	if (r->lrh_type == CHANGELOG_REC) {
		struct mdd_device *mdd;
		struct llog_changelog_rec *rec;

		mdd = lu2mdd_dev(loghandle->lgh_ctxt->loc_obd->obd_lu_dev);
		rec = container_of(r, struct llog_changelog_rec, cr_hdr);

		spin_lock(&mdd->mdd_cl.mc_lock);
		rec->cr.cr_index = mdd->mdd_cl.mc_index + 1;
		spin_unlock(&mdd->mdd_cl.mc_lock);

		rc = llog_osd_ops.lop_write_rec(env, loghandle, r,
						cookie, idx, th);

		/*
		 * if current llog is full, we will generate a new
		 * llog, and since it's actually not an error, let's
		 * avoid increasing index so that userspace apps
		 * should not see a gap in the changelog sequence
		 */
		if (!(rc == -ENOSPC && llog_is_full(loghandle))) {
			spin_lock(&mdd->mdd_cl.mc_lock);
			++mdd->mdd_cl.mc_index;
			spin_unlock(&mdd->mdd_cl.mc_lock);
		}
	} else {
		rc = llog_osd_ops.lop_write_rec(env, loghandle, r,
						cookie, idx, th);
	}

	return rc;
}

bool mdd_changelog_need_gc(const struct lu_env *env, struct mdd_device *mdd,
			   struct llog_handle *lgh)
{
	unsigned long free_cat_entries = llog_cat_free_space(lgh);
	struct mdd_changelog *mc = &mdd->mdd_cl;

	return free_cat_entries <= mdd->mdd_changelog_min_free_cat_entries ||
	       mdd_changelog_is_too_idle(mdd, mc->mc_minrec, mc->mc_mintime) ||
	       OBD_FAIL_CHECK(OBD_FAIL_FORCE_GC_THREAD);
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
	struct obd_device *obd = mdd2obd_dev(mdd);
	struct llog_ctxt *ctxt;
	struct thandle *llog_th;
	int rc;
	bool need_gc;

	rec->cr_hdr.lrh_len = llog_data_len(sizeof(*rec) +
					    changelog_rec_varsize(&rec->cr));

	/* llog_lvfs_write_rec sets the llog tail len */
	rec->cr_hdr.lrh_type = CHANGELOG_REC;
	rec->cr.cr_time = cl_time();

	ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
	if (ctxt == NULL)
		return -ENXIO;

	llog_th = thandle_get_sub(env, th, ctxt->loc_handle->lgh_obj);
	if (IS_ERR(llog_th))
		GOTO(out_put, rc = PTR_ERR(llog_th));

	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_CHANGELOG_REORDER, cfs_fail_val);
	/* nested journal transaction */
	rc = llog_add(env, ctxt->loc_handle, &rec->cr_hdr, NULL, llog_th);

	/* time to recover some space ?? */
	if (likely(!mdd->mdd_changelog_gc ||
		   mdd->mdd_cl.mc_gc_task != MDD_CHLG_GC_NONE ||
		   mdd->mdd_changelog_min_gc_interval >=
			ktime_get_real_seconds() - mdd->mdd_cl.mc_gc_time))
		/* save a spin_lock trip */
		goto out_put;

	if (OBD_FAIL_PRECHECK(OBD_FAIL_MDS_CHANGELOG_IDX_PUMP)) {
		spin_lock(&mdd->mdd_cl.mc_lock);
		mdd->mdd_cl.mc_index += cfs_fail_val;
		spin_unlock(&mdd->mdd_cl.mc_lock);
	}

	need_gc = mdd_changelog_need_gc(env, mdd, ctxt->loc_handle);
	spin_lock(&mdd->mdd_cl.mc_lock);
	if (likely(mdd->mdd_changelog_gc &&
		     mdd->mdd_cl.mc_gc_task == MDD_CHLG_GC_NONE &&
		     ktime_get_real_seconds() - mdd->mdd_cl.mc_gc_time >
			mdd->mdd_changelog_min_gc_interval)) {
		if (unlikely(need_gc)) {
			CWARN("%s:%s starting changelog garbage collection\n",
			      obd->obd_name,
			      OBD_FAIL_CHECK(OBD_FAIL_FORCE_GC_THREAD) ?
			      " simulate" : "");
			/* indicate further kthread run will occur outside
			 * right after current journal transaction filling has
			 * completed
			 */
			mdd->mdd_cl.mc_gc_task = MDD_CHLG_GC_NEED;
		}
		/* next check in mdd_changelog_min_gc_interval anyway
		 */
		mdd->mdd_cl.mc_gc_time = ktime_get_real_seconds();
	}
	spin_unlock(&mdd->mdd_cl.mc_lock);
out_put:
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
	struct changelog_ext_rename *rnm = changelog_rec_rename(rec);
	size_t extsize;

	LASSERT(sfid != NULL);
	LASSERT(spfid != NULL);
	LASSERT(sname != NULL);

	extsize = sname->ln_namelen + 1;

	rnm->cr_sfid = *sfid;
	rnm->cr_spfid = *spfid;

	changelog_rec_name(rec)[rec->cr_namelen] = '\0';
	strlcpy(changelog_rec_sname(rec), sname->ln_name, extsize);
	rec->cr_namelen += extsize;
}

void mdd_changelog_rec_ext_jobid(struct changelog_rec *rec, const char *jobid)
{
	struct changelog_ext_jobid *jid = changelog_rec_jobid(rec);

	if (jobid == NULL || jobid[0] == '\0')
		return;

	strlcpy(jid->cr_jobid, jobid, sizeof(jid->cr_jobid));
}

void mdd_changelog_rec_ext_extra_flags(struct changelog_rec *rec, __u64 eflags)
{
	struct changelog_ext_extra_flags *ef = changelog_rec_extra_flags(rec);

	ef->cr_extra_flags = eflags;
}

void mdd_changelog_rec_extra_uidgid(struct changelog_rec *rec,
				    __u64 uid, __u64 gid)
{
	struct changelog_ext_uidgid *uidgid = changelog_rec_uidgid(rec);

	uidgid->cr_uid = uid;
	uidgid->cr_gid = gid;
}

void mdd_changelog_rec_extra_nid(struct changelog_rec *rec,
				 lnet_nid_t nid)
{
	struct changelog_ext_nid *clnid = changelog_rec_nid(rec);

	clnid->cr_nid = nid;
}

void mdd_changelog_rec_extra_omode(struct changelog_rec *rec, u32 flags)
{
	struct changelog_ext_openmode *omd = changelog_rec_openmode(rec);

	omd->cr_openflags = flags;
}

void mdd_changelog_rec_extra_xattr(struct changelog_rec *rec,
				   const char *xattr_name)
{
	struct changelog_ext_xattr *xattr = changelog_rec_xattr(rec);

	strlcpy(xattr->cr_xattr, xattr_name, sizeof(xattr->cr_xattr));
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
 * \param handle - transaction handle
 */
int mdd_changelog_ns_store(const struct lu_env *env,
			   struct mdd_device *mdd,
			   enum changelog_rec_type type,
			   enum changelog_rec_flags clf_flags,
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
	__u64				 xflags = CLFE_INVALID;
	int				 rc;
	ENTRY;

	if (!mdd_changelog_enabled(env, mdd, type))
		RETURN(0);

	LASSERT(tpfid != NULL);
	LASSERT(tname != NULL);
	LASSERT(handle != NULL);

	reclen = mdd_llog_record_calc_size(env, tname, sname);
	buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mdi_chlg_buf, reclen);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);
	rec = buf->lb_buf;

	clf_flags &= CLF_FLAGMASK;
	clf_flags |= CLF_EXTRA_FLAGS;

	if (uc) {
		if (uc->uc_jobid[0] != '\0')
			clf_flags |= CLF_JOBID;
		xflags |= CLFE_UIDGID;
		xflags |= CLFE_NID;
	}

	if (sname != NULL)
		clf_flags |= CLF_RENAME;
	else
		clf_flags |= CLF_VERSION;

	rec->cr.cr_flags = clf_flags;

	if (clf_flags & CLF_EXTRA_FLAGS) {
		mdd_changelog_rec_ext_extra_flags(&rec->cr, xflags);
		if (xflags & CLFE_UIDGID)
			mdd_changelog_rec_extra_uidgid(&rec->cr,
						       uc->uc_uid, uc->uc_gid);
		if (xflags & CLFE_NID)
			mdd_changelog_rec_extra_nid(&rec->cr, uc->uc_nid);
	}

	rec->cr.cr_type = (__u32)type;
	rec->cr.cr_pfid = *tpfid;
	rec->cr.cr_namelen = tname->ln_namelen;
	memcpy(changelog_rec_name(&rec->cr), tname->ln_name, tname->ln_namelen);

	if (clf_flags & CLF_RENAME)
		mdd_changelog_rec_ext_rename(&rec->cr, sfid, spfid, sname);

	if (clf_flags & CLF_JOBID)
		mdd_changelog_rec_ext_jobid(&rec->cr, uc->uc_jobid);

	if (likely(target != NULL)) {
		rec->cr.cr_tfid = *mdd_object_fid(target);
		target->mod_cltime = ktime_get();
	} else {
		fid_zero(&rec->cr.cr_tfid);
	}

	rc = mdd_changelog_store(env, mdd, rec, handle);
	if (rc < 0) {
		CERROR("%s: cannot store changelog record: type = %d, "
		       "name = '%s', t = "DFID", p = "DFID": rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name, type, tname->ln_name,
		       PFID(&rec->cr.cr_tfid), PFID(&rec->cr.cr_pfid), rc);
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
	/* cattr is set in mdd_link */
	struct lu_attr *cattr = MDD_ENV_VAR(env, cattr);
	int rc;

	if (ldata->ld_leh == NULL) {
		rc = first ? -ENODATA : mdd_links_read(env, mdd_obj, ldata);
		if (rc) {
			if (rc != -ENODATA)
				return rc;
			rc = linkea_data_new(ldata,
					     &mdd_env_info(env)->mdi_link_buf);
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
		struct lu_fid *tfid = &mdd_env_info(env)->mdi_fid2;

		*tfid = *pfid;
		tfid->f_ver = ~0;
		linkea_add_buf(ldata, lname, tfid, false);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LINKEA_MORE2))
		linkea_add_buf(ldata, lname, pfid, false);

	/* For encrypted file, we want to limit number of hard links to what
	 * linkEA can contain. So ask to return error in case of overflow.
	 * Currently linkEA stores 4KiB of links, that is 14 NAME_MAX links,
	 * or 119 16-byte names.
	 */
	return linkea_add_buf(ldata, lname, pfid,
			      cattr->la_valid & LA_FLAGS &&
			      cattr->la_flags & LUSTRE_ENCRYPT_FL);
}

static int __mdd_links_del(const struct lu_env *env,
			   struct mdd_object *mdd_obj,
			   struct linkea_data *ldata,
			   const struct lu_name *lname,
			   const struct lu_fid *pfid)
{
	/* cattr is set in mdd_link */
	struct lu_attr *cattr = MDD_ENV_VAR(env, cattr);
	int rc;

	if (ldata->ld_leh == NULL) {
		rc = mdd_links_read(env, mdd_obj, ldata);
		if (rc)
			return rc;
	}

	rc = linkea_links_find(ldata, lname, pfid);
	if (rc)
		return rc;

	linkea_del_buf(ldata, lname,
		       cattr->la_valid & LA_FLAGS &&
		       cattr->la_flags & LUSTRE_ENCRYPT_FL);
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
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_FID_IGIF))
		RETURN(0);

	LASSERT(oldpfid != NULL || newpfid != NULL);

	if (mdd_obj->mod_flags & DEAD_OBJ)
		/* Unnecessary to update linkEA for dead object.  */
		RETURN(0);

	if (oldpfid != NULL) {
		rc = __mdd_links_del(env, mdd_obj, ldata, oldlname, oldpfid);
		if (rc) {
			if ((check == 1) || (rc != -ENODATA && rc != -ENOENT))
				RETURN(rc);

			/* No changes done. */
			rc = 0;
		}
	}

	/* If renaming, add the new record */
	if (newpfid != NULL)
		rc = __mdd_links_add(env, mdd_obj, ldata, newlname, newpfid,
				     first, check);

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
		ldata = &mdd_env_info(env)->mdi_link_data;
		memset(ldata, 0, sizeof(*ldata));
		rc = mdd_linkea_prepare(env, mdd_obj, oldpfid, oldlname,
					newpfid, newlname, first, check, ldata);
		if (rc)
			GOTO(out, rc);
	}

	if (!(mdd_obj->mod_flags & DEAD_OBJ))
		rc = mdd_links_write(env, mdd_obj, ldata, handle);

	GOTO(out, rc);

out:
	if (rc != 0) {
		if (newlname == NULL)
			CERROR("link_ea add failed %d "DFID"\n",
			       rc, PFID(mdd_object_fid(mdd_obj)));
		else if (oldpfid == NULL)
			CERROR("link_ea add '%.*s' failed %d "DFID"\n",
			       newlname->ln_namelen, newlname->ln_name, rc,
			       PFID(mdd_object_fid(mdd_obj)));
		else if (newpfid == NULL)
			CERROR("link_ea del '%.*s' failed %d "DFID"\n",
			       oldlname->ln_namelen, oldlname->ln_name, rc,
			       PFID(mdd_object_fid(mdd_obj)));
		else
			CERROR("link_ea rename '%.*s'->'%.*s' failed %d "DFID
			       "\n", oldlname->ln_namelen, oldlname->ln_name,
			       newlname->ln_namelen, newlname->ln_name, rc,
			       PFID(mdd_object_fid(mdd_obj)));
	}

	if (is_vmalloc_addr(ldata->ld_buf))
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
 * Uses the name_buf since it is generally large.
 * \retval IS_ERR err
 * \retval ptr to \a lu_buf (always \a mdi_link_buf)
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
	const struct lu_buf *buf;
	int		    rc;

	if (ldata == NULL || ldata->ld_buf == NULL ||
	    ldata->ld_leh == NULL)
		return 0;

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_LINKEA))
		return 0;

again:
	buf = mdd_buf_get_const(env, ldata->ld_buf->lb_buf,
				ldata->ld_leh->leh_len);
	rc = mdo_xattr_set(env, mdd_obj, buf, XATTR_NAME_LINK, 0, handle);
	if (unlikely(rc == -ENOSPC)) {
		rc = linkea_overflow_shrink(ldata);
		if (likely(rc > 0))
			goto again;
	}

	return rc;
}

static int mdd_declare_links_add(const struct lu_env *env,
				 struct mdd_object *mdd_obj,
				 struct thandle *handle,
				 struct linkea_data *ldata)
{
	int	rc;
	int	ea_len;
	void	*linkea;

	if (ldata != NULL && ldata->ld_leh != NULL) {
		ea_len = ldata->ld_leh->leh_len;
		linkea = ldata->ld_buf->lb_buf;
	} else {
		ea_len = MAX_LINKEA_SIZE;
		linkea = NULL;
	}

	rc = mdo_declare_xattr_set(env, mdd_obj,
				   mdd_buf_get_const(env, linkea, ea_len),
				   XATTR_NAME_LINK, 0, handle);

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
		rc = mdd_declare_links_add(env, c, handle, NULL);

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
	struct lu_fid tfid = *mdd_object_fid(c);
	int rc;

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DANGLING3))
		tfid.f_oid = cfs_fail_val;

	rc = mdo_declare_index_insert(env, p, &tfid, mdd_object_type(c),
				      name->ln_name, handle);
	if (rc != 0)
		return rc;

	rc = mdo_declare_ref_add(env, c, handle);
	if (rc != 0)
		return rc;

	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdo_declare_attr_set(env, p, la, handle);
	if (rc != 0)
		return rc;

	la->la_valid = LA_CTIME;
	rc = mdo_declare_attr_set(env, c, la, handle);
	if (rc != 0)
		return rc;

	rc = mdd_declare_links_add(env, c, handle, data);
	if (rc != 0)
		return rc;

	rc = mdd_declare_changelog_store(env, mdd, CL_HARDLINK, name, NULL,
					 handle);

	return rc;
}

static int mdd_link(const struct lu_env *env, struct md_object *tgt_obj,
		    struct md_object *src_obj, const struct lu_name *lname,
		    struct md_attr *ma)
{
	const char *name = lname->ln_name;
	struct lu_attr *la = &mdd_env_info(env)->mdi_la_for_fix;
	struct mdd_object *mdd_tobj = md2mdd_obj(tgt_obj);
	struct mdd_object *mdd_sobj = md2mdd_obj(src_obj);
	struct lu_attr *cattr = MDD_ENV_VAR(env, cattr);
	struct lu_attr *tattr = MDD_ENV_VAR(env, tattr);
	struct mdd_device *mdd = mdo2mdd(src_obj);
	struct thandle *handle;
	struct lu_fid *tfid = &mdd_env_info(env)->mdi_fid2;
	struct linkea_data *ldata = &mdd_env_info(env)->mdi_link_data;
	int rc;
	ENTRY;

	rc = mdd_la_get(env, mdd_sobj, cattr);
	if (rc != 0)
		RETURN(rc);

	rc = mdd_la_get(env, mdd_tobj, tattr);
	if (rc != 0)
		RETURN(rc);

	/*
	 * If we are using project inheritance, we only allow hard link
	 * creation in our tree when the project IDs are the same;
	 * otherwise the tree quota mechanism could be circumvented.
	 */
	if ((tattr->la_flags & LUSTRE_PROJINHERIT_FL) &&
	    (tattr->la_projid != cattr->la_projid))
		RETURN(-EXDEV);

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                GOTO(out_pending, rc = PTR_ERR(handle));

	memset(ldata, 0, sizeof(*ldata));

	LASSERT(ma->ma_attr.la_valid & LA_CTIME);
	la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

	/* Note: even this function will change ldata, but it comes from
	 * thread_info, which is completely temporary and only seen in
	 * this function, so we do not need reset ldata once it fails.*/
	rc = mdd_linkea_prepare(env, mdd_sobj, NULL, NULL,
				mdd_object_fid(mdd_tobj), lname, 0, 0, ldata);
	if (rc != 0)
		GOTO(stop, rc);

	rc = mdd_declare_link(env, mdd, mdd_tobj, mdd_sobj, lname, handle,
			      la, ldata);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

	mdd_write_lock(env, mdd_sobj, DT_TGT_CHILD);
	rc = mdd_link_sanity_check(env, mdd_tobj, tattr, lname, mdd_sobj,
				   cattr);
	if (rc)
		GOTO(out_unlock, rc);

	if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LESS_NLINK)) {
		rc = mdo_ref_add(env, mdd_sobj, handle);
		if (rc != 0)
			GOTO(out_unlock, rc);
	}

	*tfid = *mdd_object_fid(mdd_sobj);
	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DANGLING3))
		tfid->f_oid = cfs_fail_val;

	rc = __mdd_index_insert_only(env, mdd_tobj, tfid,
				     mdd_object_type(mdd_sobj), name, handle);
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
	if (rc == 0)
		/* Note: The failure of links_add should not cause the
		 * link failure, so do not check return value. */
		mdd_links_add(env, mdd_sobj, mdd_object_fid(mdd_tobj),
			      lname, handle, ldata, 0);

	EXIT;
out_unlock:
	mdd_write_unlock(env, mdd_sobj);
	if (rc == 0)
		rc = mdd_changelog_ns_store(env, mdd, CL_HARDLINK, 0, mdd_sobj,
					    mdd_object_fid(mdd_tobj), NULL,
					    NULL, lname, NULL, handle);
stop:
	rc = mdd_trans_stop(env, mdd, rc, handle);
	if (is_vmalloc_addr(ldata->ld_buf))
		/* if we vmalloced a large buffer drop it */
		lu_buf_free(ldata->ld_buf);
out_pending:
	return rc;
}

static int mdd_mark_orphan_object(const struct lu_env *env,
				struct mdd_object *obj, struct thandle *handle,
				bool declare)
{
	struct lu_attr *attr = MDD_ENV_VAR(env, la_for_start);
	int rc;

	attr->la_valid = LA_FLAGS;
	attr->la_flags = LUSTRE_ORPHAN_FL;

	if (declare)
		rc = mdo_declare_attr_set(env, obj, attr, handle);
	else
		rc = mdo_attr_set(env, obj, attr, handle);

	return rc;
}

static int mdd_declare_finish_unlink(const struct lu_env *env,
				     struct mdd_object *obj,
				     struct thandle *handle)
{
	int rc;

	/* Sigh, we do not know if the unlink object will become orphan in
	 * declare phase, but fortunately the flags here does not matter
	 * in current declare implementation */
	rc = mdd_mark_orphan_object(env, obj, handle, true);
	if (rc != 0)
		return rc;

	rc = mdo_declare_destroy(env, obj, handle);
	if (rc != 0)
		return rc;

	rc = mdd_orphan_declare_insert(env, obj, mdd_object_type(obj), handle);
	if (rc != 0)
		return rc;

	return mdd_declare_links_del(env, obj, handle);
}

/* caller should take a lock before calling */
int mdd_finish_unlink(const struct lu_env *env,
		      struct mdd_object *obj, struct md_attr *ma,
		      struct mdd_object *pobj,
		      const struct lu_name *lname,
		      struct thandle *th)
{
	int rc = 0;
	int is_dir = S_ISDIR(ma->ma_attr.la_mode);
	ENTRY;

	LASSERT(mdd_write_locked(env, obj) != 0);

	if (ma->ma_attr.la_nlink == 0 || is_dir) {
		/* add new orphan and the object
		 * will be deleted during mdd_close() */
		obj->mod_flags |= DEAD_OBJ;
		if (obj->mod_count) {
			rc = mdd_orphan_insert(env, obj, th);
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

			/* mark object as an orphan here, not
			 * before mdd_orphan_insert() as racing
			 * mdd_la_get() may propagate ORPHAN_OBJ
			 * causing the asserition */
			rc = mdd_mark_orphan_object(env, obj, th, false);
		} else {
			rc = mdo_destroy(env, obj, th);
		}
	} else if (!is_dir) {
		/* old files may not have link ea; ignore errors */
		mdd_links_del(env, obj, mdd_object_fid(pobj), lname, th);
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
	struct lu_attr *la = &mdd_env_info(env)->mdi_la_for_fix;
	int rc;

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
		rc = mdd_declare_changelog_store(env, mdd, CL_UNLINK, name,
						 NULL, handle);
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
		rc = mdo_xattr_get(env, obj, hsm_buf, XATTR_NAME_HSM);
		rc = lustre_buf2hsm(hsm_buf->lb_buf, rc, &ma->ma_hsm);
		lu_buf_free(hsm_buf);
		if (rc < 0)
			RETURN(false);

		ma->ma_valid |= MA_HSM;
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
	char *name = (char *)lname->ln_name;
	struct lu_attr *pattr = MDD_ENV_VAR(env, pattr);
	struct lu_attr *cattr = MDD_ENV_VAR(env, cattr);
	struct lu_attr *la = &mdd_env_info(env)->mdi_la_for_fix;
	struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
	struct mdd_object *mdd_cobj = NULL;
	struct mdd_device *mdd = mdo2mdd(pobj);
	struct thandle    *handle;
	int rc, is_dir = 0, cl_flags = 0;
	ENTRY;

	/* let shutdown to start */
	CFS_FAIL_TIMEOUT(OBD_FAIL_TGT_REPLY_DATA_RACE, 1);

	/* cobj == NULL means only delete name entry */
	if (likely(cobj != NULL)) {
		mdd_cobj = md2mdd_obj(cobj);
		if (mdd_object_exists(mdd_cobj) == 0)
			RETURN(-ENOENT);
	}

	rc = mdd_la_get(env, mdd_pobj, pattr);
	if (rc)
		RETURN(rc);

	if (likely(mdd_cobj != NULL)) {
		/* fetch cattr */
		rc = mdd_la_get(env, mdd_cobj, cattr);
		if (rc)
			RETURN(rc);

		is_dir = S_ISDIR(cattr->la_mode);
		/* search for an existing archive.
		 * we should check ahead as the object
		 * can be destroyed in this transaction */
		if (mdd_hsm_archive_exists(env, mdd_cobj, ma))
			cl_flags |= CLF_UNLINK_HSM_EXISTS;
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
		mdd_write_lock(env, mdd_cobj, DT_TGT_CHILD);

	if (lname->ln_name[lname->ln_namelen] != '\0') {
		/* lname->ln_name is not necessarily NUL terminated */
		name = kmalloc(lname->ln_namelen + 1, GFP_NOFS);
		if (!name)
			GOTO(cleanup, rc = -ENOMEM);

		memcpy(name, lname->ln_name, lname->ln_namelen);
		name[lname->ln_namelen] = '\0';
	}

	if (likely(no_name == 0) && !OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DANGLING2)) {
		rc = __mdd_index_delete(env, mdd_pobj, name, is_dir, handle);
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
						mdd_object_fid(mdd_cobj),
						mdd_object_type(mdd_cobj),
						name, handle);
			GOTO(cleanup, rc);
		}

		if (is_dir)
			/* unlink dot */
			mdo_ref_del(env, mdd_cobj, handle);

		/* fetch updated nlink */
		rc = mdd_la_get(env, mdd_cobj, cattr);
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
		GOTO(cleanup, rc);

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
	if (rc != 0)
		GOTO(cleanup, rc);

	/* fetch updated nlink */
	rc = mdd_la_get(env, mdd_cobj, cattr);
	/* if object is removed then we can't get its attrs,
	 * use last get */
	if (rc == -ENOENT) {
		cattr->la_nlink = 0;
		rc = 0;
	}

	if (cattr->la_nlink == 0) {
		ma->ma_attr = *cattr;
		ma->ma_valid |= MA_INODE;
	}

	EXIT;
cleanup:
	if (name != lname->ln_name)
		kfree(name);

	if (likely(mdd_cobj != NULL))
		mdd_write_unlock(env, mdd_cobj);

	if (rc == 0) {
		if (cattr->la_nlink == 0)
			cl_flags |= CLF_UNLINK_LAST;
		else
			cl_flags &= ~CLF_UNLINK_HSM_EXISTS;

		rc = mdd_changelog_ns_store(env, mdd,
			is_dir ? CL_RMDIR : CL_UNLINK, cl_flags,
			mdd_cobj, mdd_object_fid(mdd_pobj), NULL, NULL,
			lname, NULL, handle);
	}

stop:
	rc = mdd_trans_stop(env, mdd, rc, handle);

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
			   struct md_object *cobj,
			   const struct md_op_spec *spec, struct md_attr *ma)
{
	struct mdd_device *mdd = mdo2mdd(cobj);
	struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
	struct mdd_object *son = md2mdd_obj(cobj);
	struct thandle *handle;
	const struct lu_buf *buf;
	struct lu_attr *attr = MDD_ENV_VAR(env, cattr);
	struct dt_allocation_hint *hint = &mdd_env_info(env)->mdi_hint;
	int rc;
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
	rc = mdd_la_get(env, son, attr);
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
	CDEBUG(D_OTHER, "ea %p/%u, cr_flags %#llo, no_create %u\n",
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

	rc = mdd_declare_changelog_store(env, mdd, CL_LAYOUT, NULL, NULL,
					 handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop, rc);

	rc = dt_xattr_set(env, mdd_object_child(son), buf, XATTR_NAME_LOV,
			  0, handle);

	if (rc)
		GOTO(stop, rc);

	rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, son, handle,
				      NULL);

stop:
	rc = mdd_trans_stop(env, mdd, rc, handle);

out_free:
	RETURN(rc);
}

static int mdd_declare_object_initialize(const struct lu_env *env,
					 struct mdd_object *parent,
					 struct mdd_object *child,
					 const struct lu_attr *attr,
					 struct thandle *handle)
{
	int rc;
	ENTRY;

	LASSERT(attr->la_valid & (LA_MODE | LA_TYPE));
	if (!S_ISDIR(attr->la_mode))
		RETURN(0);

	rc = mdo_declare_index_insert(env, child, mdd_object_fid(child),
				      S_IFDIR, dot, handle);
	if (rc != 0)
		RETURN(rc);

	rc = mdo_declare_ref_add(env, child, handle);
	if (rc != 0)
		RETURN(rc);

	rc = mdo_declare_index_insert(env, child, mdd_object_fid(parent),
				      S_IFDIR, dotdot, handle);

	RETURN(rc);
}

static int mdd_object_initialize(const struct lu_env *env,
				 const struct lu_fid *pfid,
				 struct mdd_object *child,
				 struct lu_attr *attr,
				 struct thandle *handle)
{
	int rc = 0;
	ENTRY;

	if (S_ISDIR(attr->la_mode)) {
		/* Add "." and ".." for newly created dir */
		mdo_ref_add(env, child, handle);
		rc = __mdd_index_insert_only(env, child, mdd_object_fid(child),
					     S_IFDIR, dot, handle);
		if (rc == 0)
			rc = __mdd_index_insert_only(env, child, pfid, S_IFDIR,
						     dotdot, handle);
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
	struct lu_fid *fid = &info->mdi_fid;
	struct mdd_object *obj = md2mdd_obj(pobj);
	struct mdd_device *m = mdo2mdd(pobj);
	bool check_perm = true;
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

	if (S_ISDIR(cattr->la_mode) &&
	    unlikely(spec != NULL && spec->sp_cr_flags & MDS_OPEN_HAS_EA) &&
	    spec->u.sp_ea.eadata != NULL && spec->u.sp_ea.eadatalen > 0) {
		const struct lmv_user_md *lum = spec->u.sp_ea.eadata;

		if (!lmv_user_magic_supported(le32_to_cpu(lum->lum_magic)) &&
		    le32_to_cpu(lum->lum_magic) != LMV_USER_MAGIC_V0) {
			rc = -EINVAL;
			CERROR("%s: invalid lmv_user_md: magic = %x, "
			       "stripe_offset = %d, stripe_count = %u: "
			       "rc = %d\n", mdd2obd_dev(m)->obd_name,
				le32_to_cpu(lum->lum_magic),
			       (int)le32_to_cpu(lum->lum_stripe_offset),
			       le32_to_cpu(lum->lum_stripe_count), rc);
			return rc;
		}
	}

	rc = mdd_may_create(env, obj, pattr, NULL, check_perm);
	if (rc != 0)
		RETURN(rc);

	/* sgid check */
	if (pattr->la_mode & S_ISGID) {
		struct lu_ucred *uc = lu_ucred(env);

		cattr->la_gid = pattr->la_gid;

		/* Directories are special, and always inherit S_ISGID */
		if (S_ISDIR(cattr->la_mode)) {
			cattr->la_mode |= S_ISGID;
			cattr->la_valid |= LA_MODE;
		} else if ((cattr->la_mode & (S_ISGID | S_IXGRP))
				== (S_ISGID | S_IXGRP) &&
			   !lustre_in_group_p(uc,
					      (cattr->la_valid & LA_GID) ?
					      cattr->la_gid : pattr->la_gid) &&
			   !cap_raised(uc->uc_cap, CAP_FSETID)) {
			cattr->la_mode &= ~S_ISGID;
			cattr->la_valid |= LA_MODE;
		}
	}

	/* Inherit project ID from parent directory */
	if (pattr->la_flags & LUSTRE_PROJINHERIT_FL) {
		cattr->la_projid = pattr->la_projid;
		if (S_ISDIR(cattr->la_mode)) {
			cattr->la_flags |= LUSTRE_PROJINHERIT_FL;
			cattr->la_valid |= LA_FLAGS;
		}
		cattr->la_valid |= LA_PROJID;
	}

	rc = mdd_name_check(env, m, lname);
	if (rc < 0)
		RETURN(rc);

	switch (cattr->la_mode & S_IFMT) {
	case S_IFLNK: {
		unsigned int symlen = spec->u.sp_symname.ln_namelen + 1;

		if (symlen > m->mdd_dt_conf.ddp_symlink_max)
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

static int mdd_declare_create_object(const struct lu_env *env,
				     struct mdd_device *mdd,
				     struct mdd_object *p, struct mdd_object *c,
				     struct lu_attr *attr,
				     struct thandle *handle,
				     const struct md_op_spec *spec,
				     struct lu_buf *def_acl_buf,
				     struct lu_buf *acl_buf,
				     struct lu_buf *hsm_buf,
				     struct dt_allocation_hint *hint)
{
	const struct lu_buf *buf;
	int rc;

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	/* ldiskfs OSD needs this information for credit allocation */
	if (def_acl_buf)
		hint->dah_acl_len = def_acl_buf->lb_len;
#endif
	rc = mdd_declare_create_object_internal(env, p, c, attr, handle, spec,
						hint);
	if (rc)
		GOTO(out, rc);

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	if (def_acl_buf && def_acl_buf->lb_len > 0 && S_ISDIR(attr->la_mode)) {
		/* if dir, then can inherit default ACl */
		rc = mdo_declare_xattr_set(env, c, def_acl_buf,
					   XATTR_NAME_ACL_DEFAULT,
					   0, handle);
		if (rc)
			GOTO(out, rc);
	}

	if (acl_buf && acl_buf->lb_len > 0) {
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
	if ((!(spec->sp_cr_flags & MDS_OPEN_DELAY_CREATE) && spec->no_create) ||
	    (spec->sp_cr_flags & MDS_OPEN_HAS_EA && S_ISREG(attr->la_mode))) {
		buf = mdd_buf_get_const(env, spec->u.sp_ea.eadata,
					spec->u.sp_ea.eadatalen);
		rc = mdo_declare_xattr_set(env, c, buf,
					   S_ISDIR(attr->la_mode) ?
						XATTR_NAME_LMV : XATTR_NAME_LOV,
					   LU_XATTR_CREATE, handle);
		if (rc)
			GOTO(out, rc);

		if (spec->sp_cr_flags & MDS_OPEN_PCC) {
			rc = mdo_declare_xattr_set(env, c, hsm_buf,
						   XATTR_NAME_HSM,
						   0, handle);
			if (rc)
				GOTO(out, rc);
		}
	}

	if (S_ISLNK(attr->la_mode)) {
		const char *target_name = spec->u.sp_symname.ln_name;
		int sym_len = spec->u.sp_symname.ln_namelen;
		const struct lu_buf *buf;

		buf = mdd_buf_get_const(env, target_name, sym_len);
                rc = dt_declare_record_write(env, mdd_object_child(c),
					     buf, 0, handle);
                if (rc)
                        GOTO(out, rc);
        }

	if (spec->sp_cr_file_secctx_name != NULL) {
		buf = mdd_buf_get_const(env, spec->sp_cr_file_secctx,
					spec->sp_cr_file_secctx_size);
		rc = mdo_declare_xattr_set(env, c, buf,
					   spec->sp_cr_file_secctx_name, 0,
					   handle);
		if (rc < 0)
			GOTO(out, rc);
	}

	if (spec->sp_cr_file_encctx != NULL) {
		buf = mdd_buf_get_const(env, spec->sp_cr_file_encctx,
					spec->sp_cr_file_encctx_size);
		rc = mdo_declare_xattr_set(env, c, buf,
					   LL_XATTR_NAME_ENCRYPTION_CONTEXT, 0,
					   handle);
		if (rc < 0)
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
			      struct lu_buf *hsm_buf,
			      struct dt_allocation_hint *hint)
{
	int rc;

	rc = mdd_declare_create_object(env, mdd, p, c, attr, handle, spec,
				       def_acl_buf, acl_buf, hsm_buf, hint);
	if (rc)
		GOTO(out, rc);

	if (S_ISDIR(attr->la_mode)) {
		rc = mdo_declare_ref_add(env, p, handle);
		if (rc)
			GOTO(out, rc);
	}

	if (unlikely(spec->sp_cr_flags & MDS_OPEN_VOLATILE)) {
		rc = mdd_orphan_declare_insert(env, c, attr->la_mode, handle);
		if (rc)
			GOTO(out, rc);
	} else {
		struct lu_attr *la = &mdd_env_info(env)->mdi_la_for_fix;
		enum changelog_rec_type type;

		rc = mdo_declare_index_insert(env, p, mdd_object_fid(c),
					      attr->la_mode, name->ln_name,
					      handle);
		if (rc != 0)
			return rc;

		rc = mdd_declare_links_add(env, c, handle, ldata);
		if (rc)
			return rc;

		*la = *attr;
		la->la_valid = LA_CTIME | LA_MTIME;
		rc = mdo_declare_attr_set(env, p, la, handle);
		if (rc)
			return rc;

		type = S_ISDIR(attr->la_mode) ? CL_MKDIR :
		       S_ISREG(attr->la_mode) ? CL_CREATE :
		       S_ISLNK(attr->la_mode) ? CL_SOFTLINK : CL_MKNOD;

		rc = mdd_declare_changelog_store(env, mdd, type, name, NULL,
						 handle);
		if (rc)
			return rc;
	}
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

	mdd_read_lock(env, pobj, DT_TGT_PARENT);
	rc = mdo_xattr_get(env, pobj, def_acl_buf,
			   XATTR_NAME_ACL_DEFAULT);
	mdd_read_unlock(env, pobj);
	if (rc > 0) {
		/* ACL buffer size is not enough, need realloc */
		if (rc > acl_buf->lb_len)
			RETURN(-ERANGE);

		/* If there are default ACL, fix mode/ACL by default ACL */
		def_acl_buf->lb_len = rc;
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
static int mdd_create_object(const struct lu_env *env, struct mdd_object *pobj,
			     struct mdd_object *son, struct lu_attr *attr,
			     struct md_op_spec *spec, struct lu_buf *acl_buf,
			     struct lu_buf *def_acl_buf,
			     struct lu_buf *hsm_buf,
			     struct dt_allocation_hint *hint,
			     struct thandle *handle, bool initsecctx)
{
	const struct lu_buf *buf;
	int rc;

	mdd_write_lock(env, son, DT_TGT_CHILD);
	rc = mdd_create_object_internal(env, NULL, son, attr, handle, spec,
					hint);
	if (rc)
		GOTO(unlock, rc);

	/* Note: In DNE phase I, for striped dir, though sub-stripes will be
	 * created in declare phase, they also needs to be added to master
	 * object as sub-directory entry. So it has to initialize the master
	 * object, then set dir striped EA.(in mdo_xattr_set) */
	rc = mdd_object_initialize(env, mdd_object_fid(pobj), son, attr,
				   handle);
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
		buf = mdd_buf_get_const(env, spec->u.sp_ea.eadata,
					spec->u.sp_ea.eadatalen);
		rc = mdo_xattr_set(env, son, buf,
				   S_ISDIR(attr->la_mode) ? XATTR_NAME_LMV :
							    XATTR_NAME_LOV,
				   LU_XATTR_CREATE, handle);
		if (rc != 0)
			GOTO(err_destroy, rc);
	}

	if (S_ISREG(attr->la_mode) && spec->sp_cr_flags & MDS_OPEN_PCC) {
		struct md_hsm mh;

		memset(&mh, 0, sizeof(mh));
		mh.mh_flags = HS_EXISTS | HS_ARCHIVED | HS_RELEASED;
		mh.mh_arch_id = spec->sp_archive_id;
		lustre_hsm2buf(hsm_buf->lb_buf, &mh);
		rc = mdo_xattr_set(env, son, hsm_buf, XATTR_NAME_HSM,
				   0, handle);
		if (rc != 0)
			GOTO(err_destroy, rc);
	}

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	if (def_acl_buf != NULL && def_acl_buf->lb_len > 0 &&
	    S_ISDIR(attr->la_mode)) {
		/* set default acl */
		rc = mdo_xattr_set(env, son, def_acl_buf,
				   XATTR_NAME_ACL_DEFAULT, 0,
				   handle);
		if (rc)
			GOTO(err_destroy, rc);
	}
	/* set its own acl */
	if (acl_buf != NULL && acl_buf->lb_len > 0) {
		rc = mdo_xattr_set(env, son, acl_buf,
				   XATTR_NAME_ACL_ACCESS,
				   0, handle);
		if (rc)
			GOTO(err_destroy, rc);
	}
#endif

	if (S_ISLNK(attr->la_mode)) {
		struct dt_object *dt = mdd_object_child(son);
		const char *target_name = spec->u.sp_symname.ln_name;
		int sym_len = spec->u.sp_symname.ln_namelen;
		loff_t pos = 0;

		buf = mdd_buf_get_const(env, target_name, sym_len);
		rc = dt->do_body_ops->dbo_write(env, dt, buf, &pos, handle);
		if (rc == sym_len)
			rc = 0;
		else
			GOTO(err_initlized, rc = -EFAULT);
	}

	if (initsecctx && spec->sp_cr_file_secctx_name != NULL) {
		buf = mdd_buf_get_const(env, spec->sp_cr_file_secctx,
					spec->sp_cr_file_secctx_size);
		rc = mdo_xattr_set(env, son, buf, spec->sp_cr_file_secctx_name,
				   0, handle);
		if (rc < 0)
			GOTO(err_initlized, rc);
	}

	if (spec->sp_cr_file_encctx != NULL) {
		buf = mdd_buf_get_const(env, spec->sp_cr_file_encctx,
					spec->sp_cr_file_encctx_size);
		rc = mdo_xattr_set(env, son, buf,
				   LL_XATTR_NAME_ENCRYPTION_CONTEXT, 0,
				   handle);
		if (rc < 0)
			GOTO(err_initlized, rc);
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

static int mdd_index_delete(const struct lu_env *env,
			    struct mdd_object *mdd_pobj,
			    struct lu_attr *cattr,
			    const struct lu_name *lname)
{
	struct mdd_device *mdd = mdo2mdd(&mdd_pobj->mod_obj);
	struct thandle *handle;
	int rc;
	ENTRY;

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	rc = mdo_declare_index_delete(env, mdd_pobj, lname->ln_name,
				      handle);
	if (rc != 0)
		GOTO(stop, rc);

	if (S_ISDIR(cattr->la_mode)) {
		rc = mdo_declare_ref_del(env, mdd_pobj, handle);
		if (rc != 0)
			GOTO(stop, rc);
	}

	/* Since this will only be used in the error handler path,
	 * Let's set the thandle to be local and not mess the transno */
	handle->th_local = 1;
	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop, rc);

	rc = __mdd_index_delete(env, mdd_pobj, lname->ln_name,
				S_ISDIR(cattr->la_mode), handle);
	if (rc)
		GOTO(stop, rc);
stop:
	rc = mdd_trans_stop(env, mdd, rc, handle);

	RETURN(rc);
}

/**
 * Create object and insert it into namespace.
 *
 * Two operations have to be performed:
 *
 *  - an allocation of a new object (->do_create()), and
 *  - an insertion into a parent index (->dio_insert()).
 *
 * Due to locking, operation order is not important, when both are
 * successful, *but* error handling cases are quite different:
 *
 *  - if insertion is done first, and following object creation fails,
 *  insertion has to be rolled back, but this operation might fail
 *  also leaving us with dangling index entry.
 *
 *  - if creation is done first, is has to be undone if insertion fails,
 *  leaving us with leaked space, which is not good but not fatal.
 *
 * It seems that creation-first is simplest solution, but it is sub-optimal
 * in the frequent
 *
 * $ mkdir foo
 * $ mkdir foo
 *
 * case, because second mkdir is bound to create object, only to
 * destroy it immediately.
 *
 * To avoid this follow local file systems that do double lookup:
 *
 * 0. lookup -> -EEXIST (mdd_create_sanity_check())
 * 1. create            (mdd_create_object_internal())
 * 2. insert            (__mdd_index_insert(), lookup again)
 *
 * \param[in] pobj	parent object
 * \param[in] lname	name of child being created
 * \param[in,out] child	child object being created
 * \param[in] spec	additional create parameters
 * \param[in] ma	attributes for new child object
 *
 * \retval		0 on success
 * \retval		negative errno on failure
 */
int mdd_create(const struct lu_env *env, struct md_object *pobj,
		      const struct lu_name *lname, struct md_object *child,
		      struct md_op_spec *spec, struct md_attr *ma)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct lu_attr *la = &info->mdi_la_for_fix;
	struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
	struct mdd_object *son = md2mdd_obj(child);
	struct mdd_device *mdd = mdo2mdd(pobj);
	struct lu_attr *attr = &ma->ma_attr;
	struct thandle *handle;
	struct lu_attr *pattr = &info->mdi_pattr;
	struct lu_buf acl_buf;
	struct lu_buf def_acl_buf;
	struct lu_buf hsm_buf;
	struct linkea_data *ldata = &info->mdi_link_data;
	const char *name = lname->ln_name;
	struct dt_allocation_hint *hint = &mdd_env_info(env)->mdi_hint;
	int acl_size = LUSTRE_POSIX_ACL_MAX_SIZE_OLD;
	int rc, rc2;

	ENTRY;

	rc = mdd_la_get(env, mdd_pobj, pattr);
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

use_bigger_buffer:
	acl_buf = *lu_buf_check_and_alloc(&info->mdi_xattr_buf, acl_size);
	if (!acl_buf.lb_buf)
		GOTO(out_stop, rc = -ENOMEM);

	def_acl_buf = *lu_buf_check_and_alloc(&info->mdi_big_buf, acl_size);
	if (!def_acl_buf.lb_buf)
		GOTO(out_stop, rc = -ENOMEM);

	rc = mdd_acl_init(env, mdd_pobj, attr, &def_acl_buf, &acl_buf);
	if (unlikely(rc == -ERANGE &&
		     acl_size == LUSTRE_POSIX_ACL_MAX_SIZE_OLD)) {
		/* use maximum-sized xattr buffer for too-big default ACL */
		acl_size = min_t(unsigned int, mdd->mdd_dt_conf.ddp_max_ea_size,
				 XATTR_SIZE_MAX);
		goto use_bigger_buffer;
	}
	if (rc < 0)
		GOTO(out_stop, rc);

	if (S_ISDIR(attr->la_mode)) {
		struct lmv_user_md *lmu = spec->u.sp_ea.eadata;

		/*
		 * migrate may create 1-stripe directory, so lod_ah_init()
		 * doesn't adjust stripe count from lmu.
		 */
		if (lmu && lmu->lum_stripe_count == cpu_to_le32(1))
			lmu->lum_stripe_count = 0;
	}

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

	if (spec->sp_cr_flags & MDS_OPEN_PCC) {
		LASSERT(spec->sp_cr_flags & MDS_OPEN_HAS_EA);

		memset(&hsm_buf, 0, sizeof(hsm_buf));
		lu_buf_alloc(&hsm_buf, sizeof(struct hsm_attrs));
		if (hsm_buf.lb_buf == NULL)
			GOTO(out_stop, rc = -ENOMEM);
	}

	rc = mdd_declare_create(env, mdd, mdd_pobj, son, lname, attr,
				handle, spec, ldata, &def_acl_buf, &acl_buf,
				&hsm_buf, hint);
	if (rc)
		GOTO(out_stop, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(out_stop, rc);

	rc = mdd_create_object(env, mdd_pobj, son, attr, spec, &acl_buf,
			       &def_acl_buf, &hsm_buf, hint, handle, true);
	if (rc != 0)
		GOTO(out_stop, rc);

	if (unlikely(spec->sp_cr_flags & MDS_OPEN_VOLATILE)) {
		mdd_write_lock(env, son, DT_TGT_CHILD);
		son->mod_flags |= VOLATILE_OBJ;
		rc = mdd_orphan_insert(env, son, handle);
		GOTO(out_volatile, rc);
	} else {
		rc = __mdd_index_insert(env, mdd_pobj, mdd_object_fid(son),
					attr->la_mode, name, handle);
		if (rc != 0)
			GOTO(err_created, rc);

		mdd_links_add(env, son, mdd_object_fid(mdd_pobj), lname,
			      handle, ldata, 1);

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
		if (spec->sp_cr_flags & MDS_OPEN_VOLATILE)
			rc2 = mdd_orphan_delete(env, son, handle);
		else
			rc2 = __mdd_index_delete(env, mdd_pobj, name,
						 S_ISDIR(attr->la_mode),
						 handle);
		if (rc2 != 0)
			goto out_stop;

err_created:
		mdd_write_lock(env, son, DT_TGT_CHILD);
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

	if (rc == 0 && fid_is_namespace_visible(mdd_object_fid(son)) &&
	    likely((spec->sp_cr_flags & MDS_OPEN_VOLATILE) == 0))
		rc = mdd_changelog_ns_store(env, mdd,
				S_ISDIR(attr->la_mode) ? CL_MKDIR :
				S_ISREG(attr->la_mode) ? CL_CREATE :
				S_ISLNK(attr->la_mode) ? CL_SOFTLINK : CL_MKNOD,
				0, son, mdd_object_fid(mdd_pobj), NULL, NULL,
				lname, NULL, handle);
out_stop:
	rc2 = mdd_trans_stop(env, mdd, rc, handle);
	if (rc == 0) {
		/* If creation fails, it is most likely due to the remote update
		 * failure, because local transaction will mostly succeed at
		 * this stage. There is no easy way to rollback all of previous
		 * updates, so let's remove the object from namespace, and
		 * LFSCK should handle the orphan object. */
		if (rc2 < 0 && !mdd_object_remote(mdd_pobj))
			mdd_index_delete(env, mdd_pobj, attr, lname);
		rc = rc2;
	}
out_free:
	if (is_vmalloc_addr(ldata->ld_buf))
		/* if we vmalloced a large buffer drop it */
		lu_buf_free(ldata->ld_buf);

	if (spec->sp_cr_flags & MDS_OPEN_PCC)
		lu_buf_free(&hsm_buf);

	/* The child object shouldn't be cached anymore */
	if (rc)
		set_bit(LU_OBJECT_HEARD_BANSHEE,
			&child->mo_lu.lo_header->loh_flags);
	return rc;
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

	/*
	 * If we are using project inheritance, we only allow renames
	 * into our tree when the project IDs are the same; otherwise
	 * tree quota mechanism would be circumvented.
	 */
	if ((((tpattr->la_flags & LUSTRE_PROJINHERIT_FL) &&
	    tpattr->la_projid != cattr->la_projid) ||
	    ((pattr->la_flags & LUSTRE_PROJINHERIT_FL) &&
	    (pattr->la_projid != tpattr->la_projid))) &&
	    S_ISDIR(cattr->la_mode))
		RETURN(-EXDEV);

	/* we prevent an encrypted file from being renamed
	 * into an unencrypted dir
	 */
	if ((pattr->la_valid & LA_FLAGS &&
	     pattr->la_flags & LUSTRE_ENCRYPT_FL) &&
	    !(tpattr->la_valid & LA_FLAGS &&
	      tpattr->la_flags & LUSTRE_ENCRYPT_FL))
		RETURN(-EXDEV);

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
			      const struct lu_name *sname,
			      const struct lu_name *tname,
			      struct md_attr *ma,
			      struct linkea_data *ldata, bool change_projid,
			      struct thandle *handle)
{
	struct lu_attr *la = &mdd_env_info(env)->mdi_la_for_fix;
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
		/* source child can be directory, count by source dir's nlink */
		rc = mdo_declare_ref_del(env, mdd_spobj, handle);
		if (rc)
			return rc;
		if (mdd_spobj != mdd_tpobj) {
			rc = mdo_declare_index_delete(env, mdd_sobj, dotdot,
						      handle);
			if (rc != 0)
				return rc;

			rc = mdo_declare_index_insert(env, mdd_sobj,
						      mdd_object_fid(mdd_tpobj),
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
	if (change_projid)
		la->la_valid |= LA_PROJID;
	rc = mdo_declare_attr_set(env, mdd_sobj, la, handle);
	if (rc)
		return rc;

	rc = mdd_declare_links_add(env, mdd_sobj, handle, ldata);
	if (rc)
		return rc;

	/* new name */
	rc = mdo_declare_index_insert(env, mdd_tpobj, mdd_object_fid(mdd_sobj),
				      mdd_object_type(mdd_sobj),
				      tname->ln_name, handle);
	if (rc != 0)
		return rc;

        if (mdd_tobj && mdd_object_exists(mdd_tobj)) {
                /* delete target child in target parent directory */
		rc = mdo_declare_index_delete(env, mdd_tpobj, tname->ln_name,
					      handle);
		if (rc)
			return rc;

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

	rc = mdd_declare_changelog_store(env, mdd, CL_RENAME, tname, sname,
					 handle);
        if (rc)
                return rc;

        return rc;
}

static int mdd_migrate_object(const struct lu_env *env,
			      struct mdd_object *spobj,
			      struct mdd_object *tpobj,
			      struct mdd_object *sobj,
			      struct mdd_object *tobj,
			      const struct lu_name *sname,
			      const struct lu_name *tname,
			      struct md_op_spec *spec,
			      struct md_attr *ma);

/* src object can be remote that is why we use only fid and type of object */
static int mdd_rename(const struct lu_env *env,
                      struct md_object *src_pobj, struct md_object *tgt_pobj,
                      const struct lu_fid *lf, const struct lu_name *lsname,
                      struct md_object *tobj, const struct lu_name *ltname,
                      struct md_attr *ma)
{
	const char *sname = lsname->ln_name;
	const char *tname = ltname->ln_name;
	struct lu_attr    *la = &mdd_env_info(env)->mdi_la_for_fix;
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
	struct linkea_data  *ldata = &mdd_env_info(env)->mdi_link_data;
	const struct lu_fid *tpobj_fid = mdd_object_fid(mdd_tpobj);
	const struct lu_fid *spobj_fid = mdd_object_fid(mdd_spobj);
	bool is_dir;
	bool tobj_ref = 0;
	bool tobj_locked = 0;
	bool change_projid = false;
	unsigned cl_flags = 0;
	int rc, rc2;
	ENTRY;

	/* let unlink to complete and commit */
	CFS_FAIL_TIMEOUT(OBD_FAIL_TGT_REPLY_DATA_RACE, 2 + cfs_fail_val);

	if (tobj)
		mdd_tobj = md2mdd_obj(tobj);

	mdd_sobj = mdd_object_find(env, mdd, lf);
	if (IS_ERR(mdd_sobj))
		RETURN(PTR_ERR(mdd_sobj));

	rc = mdd_la_get(env, mdd_sobj, cattr);
	if (rc)
		GOTO(out_pending, rc);

	/* if rename is cross MDTs, migrate symlink if it doesn't have other
	 * hard links, and target doesn't exist.
	 */
	if (mdd_object_remote(mdd_sobj) && S_ISLNK(cattr->la_mode) &&
	    cattr->la_nlink == 1 && !tobj) {
		struct md_op_spec *spec = &mdd_env_info(env)->mdi_spec;
		struct lu_device *ld = &mdd->mdd_md_dev.md_lu_dev;
		struct lu_fid tfid;

		rc = ld->ld_ops->ldo_fid_alloc(env, ld, &tfid, &tgt_pobj->mo_lu,
					       NULL);
		if (rc < 0)
			GOTO(out_pending, rc);

		mdd_tobj = mdd_object_find(env, mdd, &tfid);
		if (IS_ERR(mdd_tobj))
			GOTO(out_pending, rc = PTR_ERR(mdd_tobj));

		memset(spec, 0, sizeof(*spec));
		rc = mdd_migrate_object(env, mdd_spobj, mdd_tpobj, mdd_sobj,
					mdd_tobj, lsname, ltname, spec, ma);
		mdd_object_put(env, mdd_tobj);
		GOTO(out_pending, rc);
	}

	rc = mdd_la_get(env, mdd_spobj, pattr);
	if (rc)
		GOTO(out_pending, rc);

	if (mdd_tobj) {
		rc = mdd_la_get(env, mdd_tobj, tattr);
		if (rc)
			GOTO(out_pending, rc);
		/* search for an existing archive.
		 * we should check ahead as the object
		 * can be destroyed in this transaction */
		if (mdd_hsm_archive_exists(env, mdd_tobj, ma))
			cl_flags |= CLF_RENAME_LAST_EXISTS;
	}

	rc = mdd_la_get(env, mdd_tpobj, tpattr);
	if (rc)
		GOTO(out_pending, rc);

	rc = mdd_rename_sanity_check(env, mdd_spobj, pattr, mdd_tpobj, tpattr,
				     mdd_sobj, cattr, mdd_tobj, tattr);
	if (rc)
		GOTO(out_pending, rc);

	rc = mdd_name_check(env, mdd, ltname);
	if (rc < 0)
		GOTO(out_pending, rc);

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                GOTO(out_pending, rc = PTR_ERR(handle));

	memset(ldata, 0, sizeof(*ldata));
	rc = mdd_linkea_prepare(env, mdd_sobj, mdd_object_fid(mdd_spobj),
				lsname, mdd_object_fid(mdd_tpobj), ltname,
				1, 0, ldata);
	if (rc)
		GOTO(stop, rc);

	if (tpattr->la_projid != cattr->la_projid &&
	    tpattr->la_flags & LUSTRE_PROJINHERIT_FL)
		change_projid = true;

	rc = mdd_declare_rename(env, mdd, mdd_spobj, mdd_tpobj, mdd_sobj,
				mdd_tobj, lsname, ltname, ma, ldata,
				change_projid, handle);
	if (rc)
		GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

	is_dir = S_ISDIR(cattr->la_mode);

	/* Remove source name from source directory */
	rc = __mdd_index_delete(env, mdd_spobj, sname, is_dir, handle);
	if (rc != 0)
		GOTO(stop, rc);

	/* "mv dir1 dir2" needs "dir1/.." link update */
	if (is_dir && !lu_fid_eq(spobj_fid, tpobj_fid)) {
		rc = __mdd_index_delete_only(env, mdd_sobj, dotdot, handle);
		if (rc != 0)
			GOTO(fixup_spobj2, rc);

		rc = __mdd_index_insert_only(env, mdd_sobj, tpobj_fid, S_IFDIR,
					     dotdot, handle);
		if (rc != 0)
                        GOTO(fixup_spobj, rc);
        }

	if (mdd_tobj != NULL && mdd_object_exists(mdd_tobj)) {
		rc = __mdd_index_delete(env, mdd_tpobj, tname, is_dir, handle);
		if (rc != 0)
			/* tname might been renamed to something else */
			GOTO(fixup_spobj, rc);
	}

        /* Insert new fid with target name into target dir */
	rc = __mdd_index_insert(env, mdd_tpobj, lf, cattr->la_mode,
				tname, handle);
	if (rc != 0)
                GOTO(fixup_tpobj, rc);

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);
        la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

	/* XXX: mdd_sobj must be local one if it is NOT NULL. */
	la->la_valid = LA_CTIME;
	if (change_projid) {
		/* mdd_update_time honors other valid flags except TIME ones */
		la->la_valid |= LA_PROJID;
		la->la_projid = tpattr->la_projid;
	}
	rc = mdd_update_time(env, mdd_sobj, cattr, la, handle);
	if (rc)
		GOTO(fixup_tpobj, rc);

	/* Update the linkEA for the source object */
	mdd_write_lock(env, mdd_sobj, DT_SRC_CHILD);
	rc = mdd_links_rename(env, mdd_sobj, mdd_object_fid(mdd_spobj),
			      lsname, mdd_object_fid(mdd_tpobj), ltname,
			      handle, ldata, 0, 0);
	if (rc == -ENOENT)
		/* Old files might not have EA entry */
		mdd_links_add(env, mdd_sobj, mdd_object_fid(mdd_spobj),
			      lsname, handle, NULL, 0);
	mdd_write_unlock(env, mdd_sobj);
	/* We don't fail the transaction if the link ea can't be
	   updated -- fid2path will use alternate lookup method. */
	rc = 0;

        /* Remove old target object
         * For tobj is remote case cmm layer has processed
         * and set tobj to NULL then. So when tobj is NOT NULL,
         * it must be local one.
         */
        if (tobj && mdd_object_exists(mdd_tobj)) {
		mdd_write_lock(env, mdd_tobj, DT_TGT_CHILD);
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
		rc = mdd_la_get(env, mdd_tobj, tattr);
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
		rc = mdd_la_get(env, mdd_tobj, tattr);
		if (rc == -ENOENT) {
			/* the object got removed, let's
			 * return the latest known attributes */
			tattr->la_nlink = 0;
			rc = 0;
		} else if (rc != 0) {
			CERROR("%s: Failed to get nlink for tobj "
				DFID": rc = %d\n",
				mdd2obd_dev(mdd)->obd_name,
				PFID(tpobj_fid), rc);
			GOTO(fixup_tpobj, rc);
		}
		/* XXX: this transfer to ma will be removed with LOD/OSP */
		ma->ma_attr = *tattr;
		ma->ma_valid |= MA_INODE;

		if (tattr->la_nlink == 0)
			cl_flags |= CLF_RENAME_LAST;
		else
			cl_flags &= ~CLF_RENAME_LAST_EXISTS;
        }

	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdd_update_time(env, mdd_spobj, pattr, la, handle);
	if (rc)
		GOTO(fixup_tpobj, rc);

	if (mdd_spobj != mdd_tpobj) {
		la->la_valid = LA_CTIME | LA_MTIME;
		rc = mdd_update_time(env, mdd_tpobj, tpattr, la, handle);
		if (rc != 0)
			GOTO(fixup_tpobj, rc);
	}

        EXIT;

fixup_tpobj:
        if (rc) {
		rc2 = __mdd_index_delete(env, mdd_tpobj, tname, is_dir, handle);
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
						 mdd_object_fid(mdd_tobj),
						 mdd_object_type(mdd_tobj),
						 tname, handle);
			if (rc2 != 0)
				CWARN("tp obj fix error: rc = %d\n", rc2);
		}
	}

fixup_spobj:
	if (rc && is_dir && mdd_sobj && mdd_spobj != mdd_tpobj) {
		rc2 = __mdd_index_delete_only(env, mdd_sobj, dotdot, handle);
		if (rc2)
			CWARN("%s: sp obj dotdot delete error: rc = %d\n",
			       mdd2obd_dev(mdd)->obd_name, rc2);


		rc2 = __mdd_index_insert_only(env, mdd_sobj, spobj_fid, S_IFDIR,
					      dotdot, handle);
		if (rc2 != 0)
			CWARN("%s: sp obj dotdot insert error: rc = %d\n",
			      mdd2obd_dev(mdd)->obd_name, rc2);
	}

fixup_spobj2:
	if (rc != 0) {
		rc2 = __mdd_index_insert(env, mdd_spobj, lf,
					 mdd_object_type(mdd_sobj), sname,
					 handle);
		if (rc2 != 0)
			CWARN("sp obj fix error: rc = %d\n", rc2);
	}

cleanup:
	if (tobj_locked)
		mdd_write_unlock(env, mdd_tobj);

	if (rc == 0)
		rc = mdd_changelog_ns_store(env, mdd, CL_RENAME, cl_flags,
					    mdd_tobj, tpobj_fid, lf, spobj_fid,
					    ltname, lsname, handle);

stop:
	rc = mdd_trans_stop(env, mdd, rc, handle);

out_pending:
	mdd_object_put(env, mdd_sobj);
	return rc;
}

/**
 * Check whether we should migrate the file/dir
 * return val
 *	< 0  permission check failed or other error.
 *	= 0  the file can be migrated.
 **/
static int mdd_migrate_sanity_check(const struct lu_env *env,
				    struct mdd_device *mdd,
				    struct mdd_object *spobj,
				    struct mdd_object *tpobj,
				    struct mdd_object *sobj,
				    struct mdd_object *tobj,
				    const struct lu_attr *spattr,
				    const struct lu_attr *tpattr,
				    const struct lu_attr *attr)
{
	int rc;

	ENTRY;

	if (!mdd_object_remote(sobj)) {
		mdd_read_lock(env, sobj, DT_SRC_CHILD);
		if (sobj->mod_count > 0) {
			CDEBUG(D_INFO, "%s: "DFID" is opened, count %d\n",
			       mdd_obj_dev_name(sobj),
			       PFID(mdd_object_fid(sobj)),
			       sobj->mod_count);
			mdd_read_unlock(env, sobj);
			RETURN(-EBUSY);
		}
		mdd_read_unlock(env, sobj);
	}

	if (mdd_object_exists(tobj))
		RETURN(-EEXIST);

	rc = mdd_may_delete(env, spobj, spattr, sobj, attr, NULL, 1, 0);
	if (rc)
		RETURN(rc);

	rc = mdd_may_create(env, tpobj, tpattr, NULL, true);

	RETURN(rc);
}

struct mdd_xattr_entry {
	struct list_head	mxe_linkage;
	char		       *mxe_name;
	struct lu_buf		mxe_buf;
};

struct mdd_xattrs {
	struct lu_buf		mx_namebuf;
	struct list_head	mx_list;
};

static inline void mdd_xattrs_init(struct mdd_xattrs *xattrs)
{
	INIT_LIST_HEAD(&xattrs->mx_list);
	xattrs->mx_namebuf.lb_buf = NULL;
	xattrs->mx_namebuf.lb_len = 0;
}

static inline void mdd_xattrs_fini(struct mdd_xattrs *xattrs)
{
	struct mdd_xattr_entry *entry;
	struct mdd_xattr_entry *tmp;

	list_for_each_entry_safe(entry, tmp, &xattrs->mx_list, mxe_linkage) {
		lu_buf_free(&entry->mxe_buf);
		list_del(&entry->mxe_linkage);
		OBD_FREE_PTR(entry);
	}

	lu_buf_free(&xattrs->mx_namebuf);
}

/* read xattrs into buf, but skip LMA, LMV, LINKEA if 'skip_linkea' is
 * set, and DMV if 'skip_dmv" is set.
 */
static int mdd_xattrs_migrate_prep(const struct lu_env *env,
				   struct mdd_xattrs *xattrs,
				   struct mdd_object *sobj,
				   bool skip_linkea,
				   bool skip_dmv)
{
	struct lu_attr *attr = MDD_ENV_VAR(env, cattr);
	struct mdd_xattr_entry *entry;
	bool needencxattr = false;
	bool encxattrfound = false;
	char *xname;
	int list_xsize;
	int xlen;
	int rem;
	int xsize;
	int rc;

	ENTRY;

	list_xsize = mdo_xattr_list(env, sobj, &LU_BUF_NULL);
	if (list_xsize == -ENODATA)
		RETURN(0);

	if (list_xsize < 0)
		RETURN(list_xsize);

	if (attr->la_valid & LA_FLAGS &&
	    attr->la_flags & LUSTRE_ENCRYPT_FL) {
		needencxattr = true;
		list_xsize +=
			strlen(LL_XATTR_NAME_ENCRYPTION_CONTEXT) + 1;
	}

	lu_buf_alloc(&xattrs->mx_namebuf, list_xsize);
	if (xattrs->mx_namebuf.lb_buf == NULL)
		RETURN(-ENOMEM);

	rc = mdo_xattr_list(env, sobj, &xattrs->mx_namebuf);
	if (rc < 0)
		GOTO(fini, rc);

	rem = rc;
	rc = 0;
	xname = xattrs->mx_namebuf.lb_buf;
reloop:
	for (; rem > 0; xname += xlen, rem -= xlen) {
		if (needencxattr &&
		    strcmp(xname, LL_XATTR_NAME_ENCRYPTION_CONTEXT) == 0)
			encxattrfound = true;
		xlen = strnlen(xname, rem - 1) + 1;
		if (strcmp(XATTR_NAME_LMA, xname) == 0 ||
		    strcmp(XATTR_NAME_LMV, xname) == 0)
			continue;

		if (skip_linkea &&
		    strcmp(XATTR_NAME_LINK, xname) == 0)
			continue;

		if (skip_dmv &&
		    strcmp(XATTR_NAME_DEFAULT_LMV, xname) == 0)
			continue;

		xsize = mdo_xattr_get(env, sobj, &LU_BUF_NULL, xname);
		if (xsize == -ENODATA)
			continue;
		if (xsize < 0)
			GOTO(fini, rc = xsize);

		OBD_ALLOC_PTR(entry);
		if (!entry)
			GOTO(fini, rc = -ENOMEM);

		lu_buf_alloc(&entry->mxe_buf, xsize);
		if (!entry->mxe_buf.lb_buf) {
			OBD_FREE_PTR(entry);
			GOTO(fini, rc = -ENOMEM);
		}

		rc = mdo_xattr_get(env, sobj, &entry->mxe_buf, xname);
		if (rc < 0) {
			lu_buf_free(&entry->mxe_buf);
			OBD_FREE_PTR(entry);
			if (rc == -ENODATA)
				continue;
			GOTO(fini, rc);
		}

		entry->mxe_name = xname;
		list_add_tail(&entry->mxe_linkage, &xattrs->mx_list);
	}

	if (needencxattr && !encxattrfound) {
		xlen = strlen(LL_XATTR_NAME_ENCRYPTION_CONTEXT) + 1;
		strncpy(xname, LL_XATTR_NAME_ENCRYPTION_CONTEXT, xlen);
		rem = xlen;
		GOTO(reloop, 0);
	}

	RETURN(0);
fini:
	mdd_xattrs_fini(xattrs);
	RETURN(rc);
}

typedef int (*mdd_xattr_cb)(const struct lu_env *env,
			    struct mdd_object *obj,
			    const struct lu_buf *buf,
			    const char *name,
			    int fl, struct thandle *handle);

static int mdd_foreach_xattr(const struct lu_env *env,
			     struct mdd_object *tobj,
			     struct mdd_xattrs *xattrs,
			     struct thandle *handle,
			     mdd_xattr_cb cb)
{
	struct mdd_xattr_entry *entry;
	int rc;

	list_for_each_entry(entry, &xattrs->mx_list, mxe_linkage) {
		rc = cb(env, tobj, &entry->mxe_buf, entry->mxe_name, 0, handle);
		if (rc)
			return rc;
	}

	return 0;
}

typedef int (*mdd_linkea_cb)(const struct lu_env *env,
			     struct mdd_object *sobj,
			     struct mdd_object *tobj,
			     const struct lu_name *sname,
			     const struct lu_fid *sfid,
			     const struct lu_name *lname,
			     const struct lu_fid *fid,
			     void *opaque,
			     struct thandle *handle);

static int mdd_declare_update_link(const struct lu_env *env,
				   struct mdd_object *sobj,
				   struct mdd_object *tobj,
				   const struct lu_name *tname,
				   const struct lu_fid *tpfid,
				   const struct lu_name *lname,
				   const struct lu_fid *fid,
				   void *unused,
				   struct thandle *handle)
{
	struct mdd_device *mdd = mdo2mdd(&sobj->mod_obj);
	struct mdd_object *pobj;
	int rc;

	/* ignore tobj */
	if (lu_fid_eq(tpfid, fid) && tname->ln_namelen == lname->ln_namelen &&
	    !strcmp(tname->ln_name, lname->ln_name))
		return 0;

	pobj = mdd_object_find(env, mdd, fid);
	if (IS_ERR(pobj))
		return PTR_ERR(pobj);


	rc = mdo_declare_index_delete(env, pobj, lname->ln_name, handle);
	if (!rc)
		rc = mdo_declare_index_insert(env, pobj, mdd_object_fid(tobj),
					      mdd_object_type(sobj),
					      lname->ln_name, handle);
	mdd_object_put(env, pobj);
	if (rc)
		return rc;

	rc = mdo_declare_ref_add(env, tobj, handle);
	if (rc)
		return rc;

	rc = mdo_declare_ref_del(env, sobj, handle);
	return rc;
}

static int mdd_update_link(const struct lu_env *env,
			   struct mdd_object *sobj,
			   struct mdd_object *tobj,
			   const struct lu_name *tname,
			   const struct lu_fid *tpfid,
			   const struct lu_name *lname,
			   const struct lu_fid *fid,
			   void *unused,
			   struct thandle *handle)
{
	struct mdd_device *mdd = mdo2mdd(&sobj->mod_obj);
	struct mdd_object *pobj;
	int rc;

	ENTRY;

	/* ignore tobj */
	if (lu_fid_eq(tpfid, fid) && tname->ln_namelen == lname->ln_namelen &&
	    !memcmp(tname->ln_name, lname->ln_name, lname->ln_namelen))
		RETURN(0);

	CDEBUG(D_INFO, "update "DFID"/"DNAME":"DFID"\n",
	       PFID(fid), PNAME(lname), PFID(mdd_object_fid(tobj)));

	pobj = mdd_object_find(env, mdd, fid);
	if (IS_ERR(pobj)) {
		CWARN("%s: cannot find obj "DFID": %ld\n",
		      mdd2obd_dev(mdd)->obd_name, PFID(fid), PTR_ERR(pobj));
		RETURN(PTR_ERR(pobj));
	}

	if (!mdd_object_exists(pobj)) {
		CDEBUG(D_INFO, DFID" doesn't exist\n", PFID(fid));
		mdd_object_put(env, pobj);
		RETURN(-ENOENT);
	}

	mdd_write_lock(env, pobj, DT_TGT_PARENT);
	rc = __mdd_index_delete_only(env, pobj, lname->ln_name, handle);
	if (!rc)
		rc = __mdd_index_insert_only(env, pobj, mdd_object_fid(tobj),
					     mdd_object_type(sobj),
					     lname->ln_name, handle);
	mdd_write_unlock(env, pobj);
	mdd_object_put(env, pobj);
	if (rc)
		RETURN(rc);

	mdd_write_lock(env, tobj, DT_TGT_CHILD);
	rc = mdo_ref_add(env, tobj, handle);
	mdd_write_unlock(env, tobj);
	if (rc)
		RETURN(rc);

	mdd_write_lock(env, sobj, DT_SRC_CHILD);
	rc = mdo_ref_del(env, sobj, handle);
	mdd_write_unlock(env, sobj);

	RETURN(rc);
}

static inline int mdd_fld_lookup(const struct lu_env *env,
				 struct mdd_device *mdd,
				 const struct lu_fid *fid,
				 __u32 *mdt_index)
{
	struct lu_seq_range *range = &mdd_env_info(env)->mdi_range;
	struct seq_server_site *ss;
	int rc;

	ss = mdd->mdd_md_dev.md_lu_dev.ld_site->ld_seq_site;

	range->lsr_flags = LU_SEQ_RANGE_MDT;
	rc = fld_server_lookup(env, ss->ss_server_fld, fid->f_seq, range);
	if (rc)
		return rc;

	*mdt_index = range->lsr_index;

	return 0;
}

static int mdd_is_link_on_source_mdt(const struct lu_env *env,
				     struct mdd_object *sobj,
				     struct mdd_object *tobj,
				     const struct lu_name *tname,
				     const struct lu_fid *tpfid,
				     const struct lu_name *lname,
				     const struct lu_fid *fid,
				     void *opaque,
				     struct thandle *handle)
{
	struct mdd_device *mdd = mdo2mdd(&sobj->mod_obj);
	__u32 source_mdt_index = *(__u32 *)opaque;
	__u32 link_mdt_index;
	int rc;

	ENTRY;

	/* ignore tobj */
	if (lu_fid_eq(tpfid, fid) && tname->ln_namelen == lname->ln_namelen &&
	    !memcmp(tname->ln_name, lname->ln_name, lname->ln_namelen))
		return 0;

	rc = mdd_fld_lookup(env, mdd, fid, &link_mdt_index);
	if (rc)
		RETURN(rc);

	RETURN(link_mdt_index == source_mdt_index);
}

static int mdd_iterate_linkea(const struct lu_env *env,
			      struct mdd_object *sobj,
			      struct mdd_object *tobj,
			      const struct lu_name *tname,
			      const struct lu_fid *tpfid,
			      struct linkea_data *ldata,
			      void *opaque,
			      struct thandle *handle,
			      mdd_linkea_cb cb)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	char *filename = info->mdi_name;
	struct lu_name lname;
	struct lu_fid fid;
	int rc = 0;

	if (!ldata->ld_buf)
		return 0;

	for (linkea_first_entry(ldata); ldata->ld_lee && !rc;
	     linkea_next_entry(ldata)) {
		linkea_entry_unpack(ldata->ld_lee, &ldata->ld_reclen, &lname,
				    &fid);

		/* Note: lname might miss \0 at the end */
		snprintf(filename, sizeof(info->mdi_name), "%.*s",
			 lname.ln_namelen, lname.ln_name);
		lname.ln_name = filename;

		CDEBUG(D_INFO, DFID"/"DNAME"\n", PFID(&fid), PNAME(&lname));

		rc = cb(env, sobj, tobj, tname, tpfid, &lname, &fid, opaque,
			handle);
	}

	return rc;
}

/**
 * Prepare linkea, and check whether file needs migrate: if source still has
 * link on source MDT, no need to migrate, just update namespace on source and
 * target parents.
 *
 * \retval	0 do migrate
 * \retval	1 don't migrate
 * \retval	-errno on failure
 */
static int mdd_migrate_linkea_prepare(const struct lu_env *env,
				      struct mdd_device *mdd,
				      struct mdd_object *spobj,
				      struct mdd_object *tpobj,
				      struct mdd_object *sobj,
				      const struct lu_name *sname,
				      const struct lu_name *tname,
				      const struct lu_attr *attr,
				      struct linkea_data *ldata)
{
	__u32 source_mdt_index;
	int rc;

	ENTRY;

	memset(ldata, 0, sizeof(*ldata));
	rc = mdd_linkea_prepare(env, sobj, mdd_object_fid(spobj), sname,
				mdd_object_fid(tpobj), tname, 1, 0, ldata);
	if (rc)
		RETURN(rc);

	/*
	 * Then it will check if the file should be migrated. If the file has
	 * mulitple links, we only need migrate the file if all of its entries
	 * has been migrated to the remote MDT.
	 */
	if (S_ISDIR(attr->la_mode) || attr->la_nlink < 2)
		RETURN(0);

	/* If there are still links locally, don't migrate this file */
	LASSERT(ldata->ld_leh != NULL);

	/*
	 * If linkEA is overflow, it means there are some unknown name entries
	 * under unknown parents, which will prevent the migration.
	 */
	if (unlikely(ldata->ld_leh->leh_overflow_time))
		RETURN(-EOVERFLOW);

	rc = mdd_fld_lookup(env, mdd, mdd_object_fid(sobj), &source_mdt_index);
	if (rc)
		RETURN(rc);

	rc = mdd_iterate_linkea(env, sobj, NULL, tname, mdd_object_fid(tpobj),
				ldata, &source_mdt_index, NULL,
				mdd_is_link_on_source_mdt);
	RETURN(rc);
}

static int mdd_declare_migrate_update(const struct lu_env *env,
				      struct mdd_object *spobj,
				      struct mdd_object *tpobj,
				      struct mdd_object *obj,
				      const struct lu_name *sname,
				      const struct lu_name *tname,
				      struct lu_attr *attr,
				      struct lu_attr *spattr,
				      struct lu_attr *tpattr,
				      struct linkea_data *ldata,
				      struct md_attr *ma,
				      struct thandle *handle)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct lu_attr *la = &info->mdi_la_for_fix;
	int rc;

	rc = mdo_declare_index_delete(env, spobj, sname->ln_name, handle);
	if (rc)
		return rc;

	if (S_ISDIR(attr->la_mode)) {
		rc = mdo_declare_ref_del(env, spobj, handle);
		if (rc)
			return rc;
	}

	rc = mdo_declare_index_insert(env, tpobj, mdd_object_fid(obj),
				      attr->la_mode & S_IFMT,
				      tname->ln_name, handle);
	if (rc)
		return rc;

	rc = mdd_declare_links_add(env, obj, handle, ldata);
	if (rc)
		return rc;

	if (S_ISDIR(attr->la_mode)) {
		rc = mdo_declare_ref_add(env, tpobj, handle);
		if (rc)
			return rc;
	}

	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdo_declare_attr_set(env, spobj, la, handle);
	if (rc)
		return rc;

	if (tpobj != spobj) {
		rc = mdo_declare_attr_set(env, tpobj, la, handle);
		if (rc)
			return rc;
	}

	return rc;
}

static int mdd_declare_migrate_create(const struct lu_env *env,
				      struct mdd_object *spobj,
				      struct mdd_object *tpobj,
				      struct mdd_object *sobj,
				      struct mdd_object *tobj,
				      const struct lu_name *sname,
				      const struct lu_name *tname,
				      struct lu_attr *spattr,
				      struct lu_attr *tpattr,
				      struct lu_attr *attr,
				      struct lu_buf *sbuf,
				      struct linkea_data *ldata,
				      struct mdd_xattrs *xattrs,
				      struct md_attr *ma,
				      struct md_op_spec *spec,
				      struct dt_allocation_hint *hint,
				      struct thandle *handle)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct md_layout_change *mlc = &info->mdi_mlc;
	struct lmv_mds_md_v1 *lmv = sbuf->lb_buf;
	int rc;

	ENTRY;

	if (S_ISDIR(attr->la_mode)) {
		struct lmv_user_md *lum = spec->u.sp_ea.eadata;

		mlc->mlc_opc = MD_LAYOUT_DETACH;
		rc = mdo_declare_layout_change(env, sobj, mlc, handle);
		if (rc)
			return rc;

		lum->lum_hash_type |= cpu_to_le32(LMV_HASH_FLAG_MIGRATION);
	} else if (S_ISLNK(attr->la_mode)) {
		spec->u.sp_symname.ln_name = sbuf->lb_buf;
		/* don't count NUL */
		spec->u.sp_symname.ln_namelen = sbuf->lb_len - 1;
	} else if (S_ISREG(attr->la_mode)) {
		spec->sp_cr_flags |= MDS_OPEN_DELAY_CREATE;
		spec->sp_cr_flags &= ~MDS_OPEN_HAS_EA;
	}

	mdd_object_make_hint(env, tpobj, tobj, attr, spec, hint);

	rc = mdd_declare_create(env, mdo2mdd(&tpobj->mod_obj), tpobj, tobj,
				tname, attr, handle, spec, ldata, NULL, NULL,
				NULL, hint);
	if (rc)
		return rc;

	/*
	 * tobj mode will be used in mdo_declare_layout_change(), but it's not
	 * createb yet, copy from sobj.
	 */
	tobj->mod_obj.mo_lu.lo_header->loh_attr &= ~S_IFMT;
	tobj->mod_obj.mo_lu.lo_header->loh_attr |=
		sobj->mod_obj.mo_lu.lo_header->loh_attr & S_IFMT;

	if (S_ISDIR(attr->la_mode)) {
		if (!lmv) {
			/* if sobj is not striped, fake a 1-stripe LMV */
			LASSERT(sizeof(info->mdi_key) >
				lmv_mds_md_size(1, LMV_MAGIC_V1));
			lmv = (typeof(lmv))info->mdi_key;
			memset(lmv, 0, sizeof(*lmv));
			lmv->lmv_magic = cpu_to_le32(LMV_MAGIC_V1);
			lmv->lmv_stripe_count = cpu_to_le32(1);
			lmv->lmv_hash_type = cpu_to_le32(LMV_HASH_TYPE_DEFAULT);
			fid_le_to_cpu(&lmv->lmv_stripe_fids[0],
				      mdd_object_fid(sobj));
			mlc->mlc_buf.lb_buf = lmv;
			mlc->mlc_buf.lb_len = lmv_mds_md_size(1, LMV_MAGIC_V1);
		} else {
			mlc->mlc_buf = *sbuf;
		}
		mlc->mlc_opc = MD_LAYOUT_ATTACH;
		rc = mdo_declare_layout_change(env, tobj, mlc, handle);
		if (rc)
			return rc;
	}

	rc = mdd_foreach_xattr(env, tobj, xattrs, handle,
			       mdo_declare_xattr_set);
	if (rc)
		return rc;

	if (S_ISREG(attr->la_mode)) {
		struct lu_buf fid_buf;

		handle->th_complex = 1;

		/* target may be remote, update PFID via sobj. */
		fid_buf.lb_buf = (void *)mdd_object_fid(tobj);
		fid_buf.lb_len = sizeof(struct lu_fid);
		rc = mdo_declare_xattr_set(env, sobj, &fid_buf, XATTR_NAME_FID,
					   0, handle);
		if (rc)
			return rc;

		rc = mdo_declare_xattr_del(env, sobj, XATTR_NAME_LOV, handle);
		if (rc)
			return rc;
	}

	if (!S_ISDIR(attr->la_mode)) {
		rc = mdd_iterate_linkea(env, sobj, tobj, tname,
					mdd_object_fid(tpobj), ldata, NULL,
					handle, mdd_declare_update_link);
		if (rc)
			return rc;
	}

	if (!S_ISDIR(attr->la_mode) || lmv) {
		rc = mdo_declare_ref_del(env, sobj, handle);
		if (rc)
			return rc;

		if (S_ISDIR(attr->la_mode)) {
			rc = mdo_declare_ref_del(env, sobj, handle);
			if (rc)
				return rc;
		}

		rc = mdo_declare_destroy(env, sobj, handle);
		if (rc)
			return rc;
	}

	rc = mdd_declare_migrate_update(env, spobj, tpobj, tobj, sname, tname,
					attr, spattr, tpattr, ldata, ma,
					handle);
	return rc;
}

/**
 * migrate dirent from \a spobj to \a tpobj.
 **/
static int mdd_migrate_update(const struct lu_env *env,
			      struct mdd_object *spobj,
			      struct mdd_object *tpobj,
			      struct mdd_object *obj,
			      const struct lu_name *sname,
			      const struct lu_name *tname,
			      struct lu_attr *attr,
			      struct lu_attr *spattr,
			      struct lu_attr *tpattr,
			      struct linkea_data *ldata,
			      struct md_attr *ma,
			      struct thandle *handle)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct lu_attr *la = &info->mdi_la_for_fix;
	int rc;

	ENTRY;

	CDEBUG(D_INFO, "update "DFID" from "DFID"/%s to "DFID"/%s\n",
	       PFID(mdd_object_fid(obj)), PFID(mdd_object_fid(spobj)),
	       sname->ln_name, PFID(mdd_object_fid(tpobj)), tname->ln_name);

	rc = __mdd_index_delete(env, spobj, sname->ln_name,
				S_ISDIR(attr->la_mode), handle);
	if (rc)
		RETURN(rc);

	rc = __mdd_index_insert(env, tpobj, mdd_object_fid(obj),
				attr->la_mode & S_IFMT,
				tname->ln_name, handle);
	if (rc)
		RETURN(rc);

	rc = mdd_links_write(env, obj, ldata, handle);
	if (rc)
		RETURN(rc);

	la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;
	la->la_valid = LA_CTIME | LA_MTIME;
	mdd_write_lock(env, spobj, DT_SRC_PARENT);
	rc = mdd_update_time(env, spobj, spattr, la, handle);
	mdd_write_unlock(env, spobj);
	if (rc)
		RETURN(rc);

	if (tpobj != spobj) {
		la->la_valid = LA_CTIME | LA_MTIME;
		mdd_write_lock(env, tpobj, DT_TGT_PARENT);
		rc = mdd_update_time(env, tpobj, tpattr, la, handle);
		mdd_write_unlock(env, tpobj);
		if (rc)
			RETURN(rc);
	}

	RETURN(rc);
}

/**
 * Migrate file/dir to target MDT.
 *
 * Create target according to \a spec, and then migrate xattrs, if it's
 * directory, migrate source stripes to target.
 *
 * \param[in] env	execution environment
 * \param[in] spobj	source parent object
 * \param[in] tpobj	target parent object
 * \param[in] sobj	source object
 * \param[in] tobj	target object
 * \param[in] lname	file name
 * \param[in] spattr	source parent attributes
 * \param[in] tpattr	target parent attributes
 * \param[in] attr	source attributes
 * \param[in] sbuf	source LMV buf
 * \param[in] spec	migrate create spec
 * \param[in] hint	target creation hint
 * \param[in] handle	tranasction handle
 *
 * \retval	0 on success
 * \retval	-errno on failure
 **/
static int mdd_migrate_create(const struct lu_env *env,
			      struct mdd_object *spobj,
			      struct mdd_object *tpobj,
			      struct mdd_object *sobj,
			      struct mdd_object *tobj,
			      const struct lu_name *sname,
			      const struct lu_name *tname,
			      struct lu_attr *spattr,
			      struct lu_attr *tpattr,
			      struct lu_attr *attr,
			      const struct lu_buf *sbuf,
			      struct linkea_data *ldata,
			      struct mdd_xattrs *xattrs,
			      struct md_attr *ma,
			      struct md_op_spec *spec,
			      struct dt_allocation_hint *hint,
			      struct thandle *handle)
{
	int rc;

	ENTRY;

	/*
	 * migrate sobj stripes to tobj if it's directory:
	 * 1. detach stripes from sobj.
	 * 2. attach stripes to tobj, see mdd_declare_migrate_mdt().
	 * 3. create stripes for tobj, see lod_xattr_set_lmv().
	 */
	if (S_ISDIR(attr->la_mode)) {
		struct mdd_thread_info *info = mdd_env_info(env);
		struct md_layout_change *mlc = &info->mdi_mlc;

		mlc->mlc_opc = MD_LAYOUT_DETACH;

		mdd_write_lock(env, sobj, DT_SRC_PARENT);
		rc = mdo_layout_change(env, sobj, mlc, handle);
		mdd_write_unlock(env, sobj);
		if (rc)
			RETURN(rc);
	}

	/* don't set nlink from sobj */
	attr->la_valid &= ~LA_NLINK;

	rc = mdd_create_object(env, tpobj, tobj, attr, spec, NULL, NULL, NULL,
			       hint, handle, false);
	if (rc)
		RETURN(rc);

	mdd_write_lock(env, tobj, DT_TGT_CHILD);
	rc = mdd_foreach_xattr(env, tobj, xattrs, handle, mdo_xattr_set);
	mdd_write_unlock(env, tobj);
	if (rc)
		RETURN(rc);

	/* for regular file, update OST objects XATTR_NAME_FID */
	if (S_ISREG(attr->la_mode)) {
		struct lu_buf fid_buf;

		/* target may be remote, update PFID via sobj. */
		fid_buf.lb_buf = (void *)mdd_object_fid(tobj);
		fid_buf.lb_len = sizeof(struct lu_fid);
		rc = mdo_xattr_set(env, sobj, &fid_buf, XATTR_NAME_FID, 0,
				   handle);
		if (rc)
			RETURN(rc);

		/* delete LOV to avoid deleting OST objs when destroying sobj */
		mdd_write_lock(env, sobj, DT_SRC_CHILD);
		rc = mdo_xattr_del(env, sobj, XATTR_NAME_LOV, handle);
		mdd_write_unlock(env, sobj);
		/* O_DELAY_CREATE file may not have LOV, ignore -ENODATA */
		if (rc && rc != -ENODATA)
			RETURN(rc);
		rc = 0;
	}

	/* update links FID */
	if (!S_ISDIR(attr->la_mode)) {
		rc = mdd_iterate_linkea(env, sobj, tobj, tname,
					mdd_object_fid(tpobj), ldata,
					NULL, handle, mdd_update_link);
		if (rc)
			RETURN(rc);
	}

	/* don't destroy sobj if it's plain directory */
	if (!S_ISDIR(attr->la_mode) || sbuf->lb_buf) {
		mdd_write_lock(env, sobj, DT_SRC_CHILD);
		rc = mdo_ref_del(env, sobj, handle);
		if (!rc) {
			if (S_ISDIR(attr->la_mode))
				rc = mdo_ref_del(env, sobj, handle);
			if (!rc)
				rc = mdo_destroy(env, sobj, handle);
		}
		mdd_write_unlock(env, sobj);
		if (rc)
			RETURN(rc);
	}

	rc = mdd_migrate_update(env, spobj, tpobj, tobj, sname, tname, attr,
				spattr, tpattr, ldata, ma, handle);

	RETURN(rc);
}

/* NB: if user issued different migrate command, we can't adjust it silently
 * here, because this command will decide target MDT in subdir migration in
 * LMV.
 */
static int mdd_migrate_cmd_check(struct mdd_device *mdd,
				 const struct lmv_mds_md_v1 *lmv,
				 const struct lmv_user_md_v1 *lum,
				 const struct lu_name *lname)
{
	__u32 lum_stripe_count = lum->lum_stripe_count;
	__u32 lum_hash_type = lum->lum_hash_type &
			      cpu_to_le32(LMV_HASH_TYPE_MASK);
	__u32 lmv_hash_type = lmv->lmv_hash_type &
			      cpu_to_le32(LMV_HASH_TYPE_MASK);

	if (!lmv_is_sane(lmv))
		return -EBADF;

	/* if stripe_count unspecified, set to 1 */
	if (!lum_stripe_count)
		lum_stripe_count = cpu_to_le32(1);

	/* TODO: check specific MDTs */
	if (lum_stripe_count != lmv->lmv_migrate_offset ||
	    lum->lum_stripe_offset != lmv->lmv_master_mdt_index ||
	    (lum_hash_type && lum_hash_type != lmv_hash_type)) {
		CERROR("%s: '"DNAME"' migration was interrupted, run 'lfs migrate -m %d -c %d -H %s "DNAME"' to finish migration.\n",
			mdd2obd_dev(mdd)->obd_name, PNAME(lname),
			le32_to_cpu(lmv->lmv_master_mdt_index),
			le32_to_cpu(lmv->lmv_migrate_offset),
			mdt_hash_name[le32_to_cpu(lmv_hash_type)],
			PNAME(lname));
		return -EPERM;
	}

	return -EALREADY;
}

/**
 * Internal function to migrate directory or file between MDTs.
 *
 * migrate source to target in following steps:
 *   1. create target, append source stripes after target's if it's directory,
 *      migrate xattrs and update fid of source links.
 *   2. update namespace: migrate dirent from source parent to target parent,
 *      update file linkea, and destroy source if it's not needed any more.
 *
 * \param[in] env	execution environment
 * \param[in] spobj	source parent object
 * \param[in] tpobj	target parent object
 * \param[in] sobj	source object
 * \param[in] tobj	target object
 * \param[in] sname	source file name
 * \param[in] tname	target file name
 * \param[in] spec	target creation spec
 * \param[in] ma	used to update \a pobj mtime and ctime
 *
 * \retval		0 on success
 * \retval		-errno on failure
 */
static int mdd_migrate_object(const struct lu_env *env,
			      struct mdd_object *spobj,
			      struct mdd_object *tpobj,
			      struct mdd_object *sobj,
			      struct mdd_object *tobj,
			      const struct lu_name *sname,
			      const struct lu_name *tname,
			      struct md_op_spec *spec,
			      struct md_attr *ma)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct mdd_device *mdd = mdo2mdd(&spobj->mod_obj);
	struct lu_attr *spattr = &info->mdi_pattr;
	struct lu_attr *tpattr = &info->mdi_tpattr;
	struct lu_attr *attr = &info->mdi_cattr;
	struct linkea_data *ldata = &info->mdi_link_data;
	struct dt_allocation_hint *hint = &info->mdi_hint;
	struct lu_buf sbuf = { NULL };
	struct mdd_xattrs xattrs;
	struct lmv_mds_md_v1 *lmv;
	struct thandle *handle;
	int rc;

	ENTRY;

	rc = mdd_la_get(env, sobj, attr);
	if (rc)
		RETURN(rc);

	rc = mdd_la_get(env, spobj, spattr);
	if (rc)
		RETURN(rc);

	rc = mdd_la_get(env, tpobj, tpattr);
	if (rc)
		RETURN(rc);

	rc = mdd_migrate_sanity_check(env, mdd, spobj, tpobj, sobj, tobj,
				      spattr, tpattr, attr);
	if (rc)
		RETURN(rc);

	mdd_xattrs_init(&xattrs);

	if (S_ISDIR(attr->la_mode) && !spec->sp_migrate_nsonly) {
		struct lmv_user_md_v1 *lum = spec->u.sp_ea.eadata;

		LASSERT(lum);

		/* if user use default value '0' for stripe_count, we need to
		 * adjust it to '1' to create a 1-stripe directory.
		 */
		if (lum->lum_stripe_count == 0)
			lum->lum_stripe_count = cpu_to_le32(1);

		rc = mdd_stripe_get(env, sobj, &sbuf, XATTR_NAME_LMV);
		if (rc && rc != -ENODATA)
			GOTO(out, rc);

		lmv = sbuf.lb_buf;
		if (lmv) {
			if (!lmv_is_sane(lmv))
				GOTO(out, rc = -EBADF);
			if (lmv_is_migrating(lmv)) {
				rc = mdd_migrate_cmd_check(mdd, lmv, lum,
							   sname);
				GOTO(out, rc);
			}
		}
	} else if (!S_ISDIR(attr->la_mode)) {
		if (spobj == tpobj)
			GOTO(out, rc = -EALREADY);

		/* update namespace only if @sobj is on MDT where @tpobj is. */
		if (!mdd_object_remote(tpobj) && !mdd_object_remote(sobj))
			spec->sp_migrate_nsonly = true;

		if (S_ISLNK(attr->la_mode)) {
			lu_buf_check_and_alloc(&sbuf, attr->la_size + 1);
			if (!sbuf.lb_buf)
				GOTO(out, rc = -ENOMEM);

			rc = mdd_readlink(env, &sobj->mod_obj, &sbuf);
			if (rc <= 0) {
				rc = rc ?: -EFAULT;
				CERROR("%s: "DFID" readlink failed: rc = %d\n",
				       mdd2obd_dev(mdd)->obd_name,
				       PFID(mdd_object_fid(sobj)), rc);
				GOTO(out, rc);
			}
		}
	}

	/* linkea needs update upon FID or parent stripe change */
	rc = mdd_migrate_linkea_prepare(env, mdd, spobj, tpobj, sobj, sname,
					tname, attr, ldata);
	if (rc > 0)
		/* update namespace only if @sobj has link on its MDT. */
		spec->sp_migrate_nsonly = true;
	else if (rc < 0)
		GOTO(out, rc);

	/* migrate inode will migrate xattrs, prepare xattrs early to avoid
	 * RPCs inside transaction.
	 */
	if (!spec->sp_migrate_nsonly) {
		rc = mdd_xattrs_migrate_prep(env, &xattrs, sobj, true, true);
		if (rc)
			GOTO(out, rc);
	}

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		GOTO(out, rc = PTR_ERR(handle));

	if (spec->sp_migrate_nsonly)
		rc = mdd_declare_migrate_update(env, spobj, tpobj, sobj, sname,
						tname, attr, spattr, tpattr,
						ldata, ma, handle);
	else
		rc = mdd_declare_migrate_create(env, spobj, tpobj, sobj, tobj,
						sname, tname, spattr, tpattr,
						attr, &sbuf, ldata, &xattrs, ma,
						spec, hint, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_declare_changelog_store(env, mdd, CL_MIGRATE, tname, sname,
					 handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop, rc);

	if (spec->sp_migrate_nsonly)
		rc = mdd_migrate_update(env, spobj, tpobj, sobj, sname, tname,
					attr, spattr, tpattr, ldata, ma,
					handle);
	else
		rc = mdd_migrate_create(env, spobj, tpobj, sobj, tobj, sname,
					tname, spattr, tpattr, attr, &sbuf,
					ldata, &xattrs, ma, spec, hint, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_changelog_ns_store(env, mdd, CL_MIGRATE, 0,
				    spec->sp_migrate_nsonly ? sobj : tobj,
				    mdd_object_fid(spobj), mdd_object_fid(sobj),
				    mdd_object_fid(tpobj), tname, sname,
				    handle);
	if (rc)
		GOTO(stop, rc);
	EXIT;

stop:
	rc = mdd_trans_stop(env, mdd, rc, handle);
out:
	mdd_xattrs_fini(&xattrs);
	lu_buf_free(&sbuf);

	return rc;
}

/**
 * Migrate directory or file between MDTs.
 *
 * \param[in] env	execution environment
 * \param[in] md_pobj	parent master object
 * \param[in] md_sobj	source object
 * \param[in] lname	file name
 * \param[in] md_tobj	target object
 * \param[in] spec	target creation spec
 * \param[in] ma	used to update \a pobj mtime and ctime
 *
 * \retval		0 on success
 * \retval		-errno on failure
 */
static int mdd_migrate(const struct lu_env *env, struct md_object *md_pobj,
		       struct md_object *md_sobj, const struct lu_name *lname,
		       struct md_object *md_tobj, struct md_op_spec *spec,
		       struct md_attr *ma)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct mdd_device *mdd = mdo2mdd(md_pobj);
	struct mdd_object *pobj = md2mdd_obj(md_pobj);
	struct mdd_object *sobj = md2mdd_obj(md_sobj);
	struct mdd_object *tobj = md2mdd_obj(md_tobj);
	struct mdd_object *spobj = NULL;
	struct mdd_object *tpobj = NULL;
	struct lu_buf pbuf = { NULL };
	struct lu_fid *fid = &info->mdi_fid2;
	struct lmv_mds_md_v1 *lmv;
	int rc;

	ENTRY;

	/* locate source and target stripe on pobj, which are the real parent */
	rc = mdd_stripe_get(env, pobj, &pbuf, XATTR_NAME_LMV);
	if (rc < 0 && rc != -ENODATA)
		RETURN(rc);

	lmv = pbuf.lb_buf;
	if (lmv) {
		int index;

		if (!lmv_is_sane(lmv))
			GOTO(out, rc = -EBADF);

		/* locate target parent stripe */
		/* fail check here to make sure top dir migration succeed. */
		if (lmv_is_migrating(lmv) &&
		    OBD_FAIL_CHECK_RESET(OBD_FAIL_MIGRATE_ENTRIES, 0))
			GOTO(out, rc = -EIO);

		index = lmv_name_to_stripe_index(lmv, lname->ln_name,
						 lname->ln_namelen);
		if (index < 0)
			GOTO(out, rc = index);

		fid_le_to_cpu(fid, &lmv->lmv_stripe_fids[index]);
		tpobj = mdd_object_find(env, mdd, fid);
		if (IS_ERR(tpobj))
			GOTO(out, rc = PTR_ERR(tpobj));

		/* locate source parent stripe */
		if (lmv_is_layout_changing(lmv)) {
			index = lmv_name_to_stripe_index_old(lmv,
							     lname->ln_name,
							     lname->ln_namelen);
			if (index < 0)
				GOTO(out, rc = index);

			fid_le_to_cpu(fid, &lmv->lmv_stripe_fids[index]);
			spobj = mdd_object_find(env, mdd, fid);
			if (IS_ERR(spobj))
				GOTO(out, rc = PTR_ERR(spobj));

			/* parent stripe unchanged */
			if (spobj == tpobj) {
				if (!lmv_is_restriping(lmv))
					GOTO(out, rc = -EINVAL);
				GOTO(out, rc = -EALREADY);
			}
		} else {
			spobj = tpobj;
			mdd_object_get(spobj);
		}
	} else {
		tpobj = pobj;
		spobj = pobj;
		mdd_object_get(tpobj);
		mdd_object_get(spobj);
	}

	rc = mdd_migrate_object(env, spobj, tpobj, sobj, tobj, lname, lname,
				spec, ma);
	GOTO(out, rc);

out:
	if (!IS_ERR_OR_NULL(spobj))
		mdd_object_put(env, spobj);
	if (!IS_ERR_OR_NULL(tpobj))
		mdd_object_put(env, tpobj);
	lu_buf_free(&pbuf);

	return rc;
}

static int mdd_declare_1sd_collapse(const struct lu_env *env,
				    struct mdd_object *pobj,
				    struct mdd_object *obj,
				    struct mdd_object *stripe,
				    struct lu_attr *attr,
				    struct mdd_xattrs *xattrs,
				    struct md_layout_change *mlc,
				    struct lu_name *lname,
				    struct thandle *handle)
{
	int rc;

	mlc->mlc_opc = MD_LAYOUT_DETACH;
	rc = mdo_declare_layout_change(env, obj, mlc, handle);
	if (rc)
		return rc;

	rc = mdo_declare_index_insert(env, stripe, mdd_object_fid(pobj),
				      S_IFDIR, dotdot, handle);
	if (rc)
		return rc;

	rc = mdd_foreach_xattr(env, stripe, xattrs, handle,
			       mdo_declare_xattr_set);
	if (rc)
		return rc;

	rc = mdo_declare_xattr_del(env, stripe, XATTR_NAME_LMV, handle);
	if (rc)
		return rc;

	rc = mdo_declare_attr_set(env, stripe, attr, handle);
	if (rc)
		return rc;

	rc = mdo_declare_index_delete(env, pobj, lname->ln_name, handle);
	if (rc)
		return rc;

	rc = mdo_declare_index_insert(env, pobj, mdd_object_fid(stripe),
				      attr->la_mode, lname->ln_name, handle);
	if (rc)
		return rc;

	rc = mdo_declare_ref_del(env, obj, handle);
	if (rc)
		return rc;

	rc = mdo_declare_ref_del(env, obj, handle);
	if (rc)
		return rc;

	rc = mdo_declare_destroy(env, obj, handle);
	if (rc)
		return rc;

	return rc;
}

/* transform one-stripe directory to a plain directory */
static int mdd_1sd_collapse(const struct lu_env *env,
			    struct mdd_object *pobj,
			    struct mdd_object *obj,
			    struct mdd_object *stripe,
			    struct lu_attr *attr,
			    struct mdd_xattrs *xattrs,
			    struct md_layout_change *mlc,
			    struct lu_name *lname,
			    struct thandle *handle)
{
	int rc;

	ENTRY;

	/* replace 1-stripe directory with its stripe */
	mlc->mlc_opc = MD_LAYOUT_DETACH;

	mdd_write_lock(env, obj, DT_SRC_PARENT);
	rc = mdo_layout_change(env, obj, mlc, handle);
	mdd_write_unlock(env, obj);
	if (rc)
		RETURN(rc);

	mdd_write_lock(env, pobj, DT_SRC_PARENT);
	mdd_write_lock(env, obj, DT_SRC_CHILD);

	/* insert dotdot to stripe which points to parent */
	rc = __mdd_index_insert_only(env, stripe, mdd_object_fid(pobj),
				     S_IFDIR, dotdot, handle);
	if (rc)
		GOTO(out, rc);

	rc = mdd_foreach_xattr(env, stripe, xattrs, handle, mdo_xattr_set);
	if (rc)
		GOTO(out, rc);

	/* delete LMV */
	rc = mdo_xattr_del(env, stripe, XATTR_NAME_LMV, handle);
	if (rc)
		GOTO(out, rc);

	/* don't set nlink from parent */
	attr->la_valid &= ~LA_NLINK;

	rc = mdo_attr_set(env, stripe, attr, handle);
	if (rc)
		GOTO(out, rc);

	/* delete dir name from parent */
	rc = __mdd_index_delete_only(env, pobj, lname->ln_name, handle);
	if (rc)
		GOTO(out, rc);

	/* insert stripe to parent with dir name */
	rc = __mdd_index_insert_only(env, pobj, mdd_object_fid(stripe),
				     attr->la_mode, lname->ln_name, handle);
	if (rc)
		GOTO(out, rc);

	/* destroy dir obj */
	rc = mdo_ref_del(env, obj, handle);
	if (rc)
		GOTO(out, rc);

	rc = mdo_ref_del(env, obj, handle);
	if (rc)
		GOTO(out, rc);

	rc = mdo_destroy(env, obj, handle);
	if (rc)
		GOTO(out, rc);

	EXIT;
out:
	mdd_write_unlock(env, obj);
	mdd_write_unlock(env, pobj);

	return rc;
}

/*
 * shrink directory stripes after migration/merge
 */
int mdd_dir_layout_shrink(const struct lu_env *env,
			  struct md_object *md_obj,
			  struct md_layout_change *mlc)
{
	struct mdd_device *mdd = mdo2mdd(md_obj);
	struct mdd_thread_info *info = mdd_env_info(env);
	struct mdd_object *obj = md2mdd_obj(md_obj);
	struct mdd_object *pobj = NULL;
	struct mdd_object *stripe = NULL;
	struct lu_attr *attr = &info->mdi_pattr;
	struct lu_fid *fid = &info->mdi_fid2;
	struct lu_name lname = { NULL };
	struct lu_buf lmv_buf = { NULL };
	struct mdd_xattrs xattrs;
	struct lmv_mds_md_v1 *lmv;
	struct lmv_user_md *lmu;
	struct thandle *handle;
	int rc;

	ENTRY;

	rc = mdd_la_get(env, obj, attr);
	if (rc)
		RETURN(rc);

	if (!S_ISDIR(attr->la_mode))
		RETURN(-ENOTDIR);

	rc = mdd_stripe_get(env, obj, &lmv_buf, XATTR_NAME_LMV);
	if (rc < 0)
		RETURN(rc);

	lmv = lmv_buf.lb_buf;
	if (!lmv_is_sane(lmv))
		RETURN(-EBADF);

	lmu = mlc->mlc_buf.lb_buf;

	/* adjust the default value '0' to '1' */
	if (lmu->lum_stripe_count == 0)
		lmu->lum_stripe_count = cpu_to_le32(1);

	/* these were checked in MDT */
	LASSERT(le32_to_cpu(lmu->lum_stripe_count) <
		le32_to_cpu(lmv->lmv_stripe_count));
	LASSERT(!lmv_is_splitting(lmv));
	LASSERT(lmv_is_migrating(lmv) || lmv_is_merging(lmv));

	mdd_xattrs_init(&xattrs);

	/* if dir stripe count will be shrunk to 1, it needs to be transformed
	 * to a plain dir, which will cause FID change and namespace update.
	 */
	if (le32_to_cpu(lmu->lum_stripe_count) == 1) {
		struct linkea_data *ldata = &info->mdi_link_data;
		char *filename = info->mdi_name;

		rc = mdd_links_read(env, obj, ldata);
		if (rc)
			GOTO(out, rc);

		if (ldata->ld_leh->leh_reccount > 1)
			GOTO(out, rc = -EINVAL);

		linkea_first_entry(ldata);
		if (!ldata->ld_lee)
			GOTO(out, rc = -ENODATA);

		linkea_entry_unpack(ldata->ld_lee, &ldata->ld_reclen, &lname,
				    fid);

		/* Note: lname might miss \0 at the end */
		snprintf(filename, sizeof(info->mdi_name), "%.*s",
			 lname.ln_namelen, lname.ln_name);
		lname.ln_name = filename;

		pobj = mdd_object_find(env, mdd, fid);
		if (IS_ERR(pobj)) {
			rc = PTR_ERR(pobj);
			pobj = NULL;
			GOTO(out, rc);
		}

		fid_le_to_cpu(fid, &lmv->lmv_stripe_fids[0]);

		stripe = mdd_object_find(env, mdd, fid);
		if (IS_ERR(stripe)) {
			mdd_object_put(env, pobj);
			pobj = NULL;
			GOTO(out, rc = PTR_ERR(stripe));
		}

		if (!lmv_is_fixed(lmv))
			rc = mdd_xattrs_migrate_prep(env, &xattrs, obj, false,
						     false);
	}

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		GOTO(out, rc = PTR_ERR(handle));

	mlc->mlc_opc = MD_LAYOUT_SHRINK;
	rc = mdo_declare_layout_change(env, obj, mlc, handle);
	if (rc)
		GOTO(stop_trans, rc);

	if (le32_to_cpu(lmu->lum_stripe_count) == 1 && !lmv_is_fixed(lmv)) {
		rc = mdd_declare_1sd_collapse(env, pobj, obj, stripe, attr,
					      &xattrs, mlc, &lname, handle);
		if (rc)
			GOTO(stop_trans, rc);
	}

	rc = mdd_declare_changelog_store(env, mdd, CL_LAYOUT, NULL, NULL,
					 handle);
	if (rc)
		GOTO(stop_trans, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop_trans, rc);

	mdd_write_lock(env, obj, DT_SRC_PARENT);
	mlc->mlc_opc = MD_LAYOUT_SHRINK;
	rc = mdo_layout_change(env, obj, mlc, handle);
	mdd_write_unlock(env, obj);
	if (rc)
		GOTO(stop_trans, rc);

	if (le32_to_cpu(lmu->lum_stripe_count) == 1 && !lmv_is_fixed(lmv)) {
		rc = mdd_1sd_collapse(env, pobj, obj, stripe, attr, &xattrs,
				      mlc, &lname, handle);
		if (rc)
			GOTO(stop_trans, rc);
	}

	rc = mdd_changelog_data_store_xattr(env, mdd, CL_LAYOUT, 0, obj,
					    XATTR_NAME_LMV, handle);
	GOTO(stop_trans, rc);

stop_trans:
	rc = mdd_trans_stop(env, mdd, rc, handle);
out:
	mdd_xattrs_fini(&xattrs);
	if (pobj) {
		mdd_object_put(env, stripe);
		mdd_object_put(env, pobj);
	}
	lu_buf_free(&lmv_buf);
	return rc;
}

static int mdd_dir_declare_split_plain(const struct lu_env *env,
					struct mdd_device *mdd,
					struct mdd_object *pobj,
					struct mdd_object *obj,
					struct mdd_object *tobj,
					struct mdd_xattrs *xattrs,
					struct md_layout_change *mlc,
					struct dt_allocation_hint *hint,
					struct thandle *handle)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	const struct lu_name *lname = mlc->mlc_name;
	struct lu_attr *la = &info->mdi_la_for_fix;
	struct lmv_user_md_v1 *lum = mlc->mlc_spec->u.sp_ea.eadata;
	struct linkea_data *ldata = &info->mdi_link_data;
	struct lmv_mds_md_v1 *lmv;
	__u32 count;
	int rc;

	mlc->mlc_opc = MD_LAYOUT_DETACH;
	rc = mdo_declare_layout_change(env, obj, mlc, handle);
	if (rc)
		return rc;

	memset(ldata, 0, sizeof(*ldata));
	rc = mdd_linkea_prepare(env, obj, NULL, NULL, mdd_object_fid(pobj),
				lname, 1, 0, ldata);
	if (rc)
		return rc;

	count = lum->lum_stripe_count;
	lum->lum_stripe_count = 0;
	/* don't set default LMV since it will become a striped dir  */
	lum->lum_max_inherit = LMV_INHERIT_NONE;
	mdd_object_make_hint(env, pobj, tobj, mlc->mlc_attr, mlc->mlc_spec,
			     hint);
	rc = mdd_declare_create(env, mdo2mdd(&pobj->mod_obj), pobj, tobj,
				lname, mlc->mlc_attr, handle, mlc->mlc_spec,
				ldata, NULL, NULL, NULL, hint);
	if (rc)
		return rc;

	/* tobj mode will be used in lod_declare_xattr_set(), but it's not
	 * created yet.
	 */
	tobj->mod_obj.mo_lu.lo_header->loh_attr |= S_IFDIR;

	lmv = (typeof(lmv))info->mdi_key;
	memset(lmv, 0, sizeof(*lmv));
	lmv->lmv_magic = cpu_to_le32(LMV_MAGIC_V1);
	lmv->lmv_stripe_count = cpu_to_le32(1);
	lmv->lmv_hash_type = cpu_to_le32(LMV_HASH_TYPE_DEFAULT);
	fid_le_to_cpu(&lmv->lmv_stripe_fids[0], mdd_object_fid(obj));

	mlc->mlc_opc = MD_LAYOUT_ATTACH;
	mlc->mlc_buf.lb_buf = lmv;
	mlc->mlc_buf.lb_len = lmv_mds_md_size(1, LMV_MAGIC_V1);
	rc = mdo_declare_layout_change(env, tobj, mlc, handle);
	if (rc)
		return rc;

	rc = mdd_foreach_xattr(env, tobj, xattrs, handle,
			       mdo_declare_xattr_set);
	if (rc)
		return rc;

	lum->lum_stripe_count = count;
	mlc->mlc_opc = MD_LAYOUT_SPLIT;
	rc = mdo_declare_layout_change(env, tobj, mlc, handle);
	if (rc)
		return rc;

	rc = mdo_declare_index_delete(env, pobj, lname->ln_name, handle);
	if (rc)
		return rc;

	rc = mdo_declare_index_insert(env, pobj, mdd_object_fid(tobj),
				      S_IFDIR, lname->ln_name, handle);
	if (rc)
		return rc;

	la->la_valid = LA_CTIME | LA_MTIME;
	rc = mdo_declare_attr_set(env, obj, la, handle);
	if (rc)
		return rc;

	rc = mdo_declare_attr_set(env, pobj, la, handle);
	if (rc)
		return rc;

	rc = mdd_declare_changelog_store(env, mdd, CL_MIGRATE, lname, NULL,
					 handle);
	return rc;
}

/**
 * plain directory split:
 * 1. create \a tobj as plain directory.
 * 2. append \a obj as first stripe of \a tobj.
 * 3. migrate xattrs from \a obj to \a tobj.
 * 4. split \a tobj to specific stripe count.
 */
static int mdd_dir_split_plain(const struct lu_env *env,
				struct mdd_device *mdd,
				struct mdd_object *pobj,
				struct mdd_object *obj,
				struct mdd_object *tobj,
				struct mdd_xattrs *xattrs,
				struct md_layout_change *mlc,
				struct dt_allocation_hint *hint,
				struct thandle *handle)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct lu_attr *pattr = &info->mdi_pattr;
	struct lu_attr *la = &info->mdi_la_for_fix;
	const struct lu_name *lname = mlc->mlc_name;
	struct linkea_data *ldata = &info->mdi_link_data;
	int rc;

	ENTRY;

	/* copy linkea out and set on target later */
	rc = mdd_links_read(env, obj, ldata);
	if (rc)
		RETURN(rc);

	mlc->mlc_opc = MD_LAYOUT_DETACH;
	rc = mdo_layout_change(env, obj, mlc, handle);
	if (rc)
		RETURN(rc);

	/* don't set nlink from obj */
	mlc->mlc_attr->la_valid &= ~LA_NLINK;

	rc = mdd_create_object(env, pobj, tobj, mlc->mlc_attr, mlc->mlc_spec,
			       NULL, NULL, NULL, hint, handle, false);
	if (rc)
		RETURN(rc);

	rc = mdd_foreach_xattr(env, tobj, xattrs, handle, mdo_xattr_set);
	if (rc)
		RETURN(rc);

	rc = mdd_links_write(env, tobj, ldata, handle);
	if (rc)
		RETURN(rc);

	rc = __mdd_index_delete(env, pobj, lname->ln_name, true, handle);
	if (rc)
		RETURN(rc);

	rc = __mdd_index_insert(env, pobj, mdd_object_fid(tobj), S_IFDIR,
				lname->ln_name, handle);
	if (rc)
		RETURN(rc);

	la->la_ctime = la->la_mtime = mlc->mlc_attr->la_mtime;
	la->la_valid = LA_CTIME | LA_MTIME;

	mdd_write_lock(env, obj, DT_SRC_CHILD);
	rc = mdd_update_time(env, tobj, mlc->mlc_attr, la, handle);
	mdd_write_unlock(env, obj);
	if (rc)
		RETURN(rc);

	rc = mdd_la_get(env, pobj, pattr);
	if (rc)
		RETURN(rc);

	la->la_valid = LA_CTIME | LA_MTIME;

	mdd_write_lock(env, pobj, DT_SRC_PARENT);
	rc = mdd_update_time(env, pobj, pattr, la, handle);
	mdd_write_unlock(env, pobj);
	if (rc)
		RETURN(rc);

	/* FID changes, record it as CL_MIGRATE */
	rc = mdd_changelog_ns_store(env, mdd, CL_MIGRATE, 0, tobj,
				    mdd_object_fid(pobj), mdd_object_fid(obj),
				    mdd_object_fid(pobj), lname, lname, handle);
	RETURN(rc);
}

int mdd_dir_layout_split(const struct lu_env *env, struct md_object *o,
			 struct md_layout_change *mlc)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct mdd_device *mdd = mdo2mdd(o);
	struct mdd_object *obj = md2mdd_obj(o);
	struct mdd_object *pobj = md2mdd_obj(mlc->mlc_parent);
	struct mdd_object *tobj = md2mdd_obj(mlc->mlc_target);
	struct dt_allocation_hint *hint = &info->mdi_hint;
	bool is_plain = false;
	struct mdd_xattrs xattrs;
	struct thandle *handle;
	int rc;

	ENTRY;

	LASSERT(S_ISDIR(mdd_object_type(obj)));

	rc = mdo_xattr_get(env, obj, &LU_BUF_NULL, XATTR_NAME_LMV);
	if (rc == -ENODATA)
		is_plain = true;
	else if (rc < 0)
		RETURN(rc);

	mdd_xattrs_init(&xattrs);
	if (is_plain)
		rc = mdd_xattrs_migrate_prep(env, &xattrs, obj, true, true);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		GOTO(out, rc = PTR_ERR(handle));

	if (is_plain) {
		rc = mdd_dir_declare_split_plain(env, mdd, pobj, obj, tobj,
						 &xattrs, mlc, hint, handle);
	} else {
		mlc->mlc_opc = MD_LAYOUT_SPLIT;
		rc = mdo_declare_layout_change(env, obj, mlc, handle);
		if (rc)
			GOTO(stop_trans, rc);

		rc = mdd_declare_changelog_store(env, mdd, CL_LAYOUT, NULL,
						 NULL, handle);
	}
	if (rc)
		GOTO(stop_trans, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop_trans, rc);

	if (is_plain) {
		rc = mdd_dir_split_plain(env, mdd, pobj, obj, tobj, &xattrs,
					 mlc, hint, handle);
	} else {
		mdd_write_lock(env, obj, DT_TGT_CHILD);
		rc = mdo_xattr_set(env, obj, NULL, XATTR_NAME_LMV,
				   LU_XATTR_CREATE, handle);
		mdd_write_unlock(env, obj);
		if (rc)
			GOTO(stop_trans, rc);

		rc = mdd_changelog_data_store_xattr(env, mdd, CL_LAYOUT, 0, obj,
						    XATTR_NAME_LMV, handle);
	}
	if (rc)
		GOTO(stop_trans, rc);

	EXIT;

stop_trans:
	rc = mdd_trans_stop(env, mdd, rc, handle);
out:
	mdd_xattrs_fini(&xattrs);

	return rc;
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
