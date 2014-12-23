/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2013, 2014, Intel Corporation.
 */
#define DEBUG_SUBSYSTEM S_MDS

#include <lustre/lustre_idl.h>
#include <lustre_fid.h>
#include <obd_support.h>

#include "mdd_internal.h"

/*
 * To enable DNE functionality we need FID of /ROOT directory
 * (which is / as seen by the clients) to belong to MDT0 and
 * not to FID_SEQ_LOCAL_FILE or some other local sequence,
 * which can be used by any node, so can't be part of FLDB.
 *
 * Pre-production code was using FID_SEQ_LOCAL_FILE for /ROOT
 * making few existing setups incompatibile with DNE. This
 * applies to ZFS-based setups only as ldiskfs-based setups
 * are still using IGIF to identify /ROOT.
 *
 * The intention of this code is to fix on-disk state to use
 * FID_SEQ_ROOT for /ROOT:
 *  - "." and ".." references in /ROOT itself and it`s subdirectories
 *  - LinkEA in all the objects listed in /ROOT
 *
 * Given only ZFS is affected where "." and ".." are not stored, we need to:
 *  - delete "." and ".." from /ROOT and its subdirectories
 *  - rename references in LinkEA in all the objects listed in /ROOT
 *
 * This code is subject for removal in 2.5
 */
static int mdd_convert_remove_dots(const struct lu_env *env,
				   struct mdd_device *mdd,
				   struct mdd_object *o)
{
	struct thandle		*th;
	const struct dt_key	*dot = (const struct dt_key *)".";
	const struct dt_key	*dotdot = (const struct dt_key *)"..";
	int			 rc;

	if (dt_try_as_dir(env, mdd_object_child(o)) == 0)
		RETURN(-ENOTDIR);

	/* remove "."/".." and do not insert them back - not stored in ZFS */
	th = dt_trans_create(env, mdd->mdd_child);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_delete(env, mdd_object_child(o), dot, th);
	if (rc)
		GOTO(out, rc);
	rc = dt_declare_delete(env, mdd_object_child(o), dotdot, th);
	if (rc)
		GOTO(out, rc);
	rc = dt_trans_start_local(env, mdd->mdd_child, th);
	if (rc)
		GOTO(out, rc);
	/* ignore non-existing "."/".." - we stored them on disk for
	 * pre-production systems, but this is not how regular ZFS works */
	rc = dt_delete(env, mdd_object_child(o), dot, th, BYPASS_CAPA);
	if (rc == -ENOENT)
		rc = 0;
	if (rc)
		GOTO(out, rc);
	rc = dt_delete(env, mdd_object_child(o), dotdot, th, BYPASS_CAPA);
	if (rc == -ENOENT)
		rc = 0;
	if (rc)
		GOTO(out, rc);

out:
	dt_trans_stop(env, mdd->mdd_child, th);
	RETURN(rc);
}

static int mdd_convert_linkea(const struct lu_env *env,
			      struct mdd_device *mdd,
			      struct mdd_object *o,
			      const struct lu_name *name)
{
	struct thandle	*th;
	struct lu_fid	 oldfid;
	int		 rc;
	ENTRY;

	th = dt_trans_create(env, mdd->mdd_child);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = mdd_declare_links_add(env, o, th, NULL, MLAO_IGNORE);
	if (rc)
		GOTO(out, rc);
	rc = dt_trans_start_local(env, mdd->mdd_child, th);
	if (rc)
		GOTO(out, rc);

	oldfid.f_seq = FID_SEQ_LOCAL_FILE;
	oldfid.f_oid = MDD_ROOT_INDEX_OID;
	oldfid.f_ver = 0;
	rc = mdd_links_rename(env, o, &oldfid, name, &mdd->mdd_root_fid,
			      name, th, NULL, 0, 1);
	if (rc == -ENOENT || rc == -EEXIST)
		rc = 0;

out:
	dt_trans_stop(env, mdd->mdd_child, th);
	RETURN(rc);
}

static int mdd_convert_object(const struct lu_env *env,
			      struct mdd_device *mdd,
			      const struct lu_fid *fid,
			      const struct lu_name *name)
{
	struct mdd_object	*o;
	struct lu_attr		*la = MDD_ENV_VAR(env, cattr);
	int			 rc;
	ENTRY;

	o = mdd_object_find(env, mdd, fid);
	if (IS_ERR(o)) {
		CERROR("%s: can't access the object: rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name, (int)PTR_ERR(o));
		RETURN(PTR_ERR(o));
	}

	rc = mdo_attr_get(env, o, la, BYPASS_CAPA);
	if (rc)
		GOTO(out, rc);

	if (S_ISDIR(la->la_mode)) {
		/* remove "." and ".." if a directory */
		rc = mdd_convert_remove_dots(env, mdd, o);
		if (rc)
			GOTO(out, rc);
	}

	/* update linkEA */
	rc = mdd_convert_linkea(env, mdd, o, name);
	if (rc)
		CERROR("%s: can't convert: rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name, rc);

out:
	mdd_object_put(env, o);
	RETURN(0);
}

static int mdd_convert_lma(const struct lu_env *env, struct mdd_device *mdd,
			   struct mdd_object *o)
{
	struct lustre_mdt_attrs	*lma;
	struct thandle		*th;
	struct lu_fid		 fid;
	struct lu_buf		 buf;
	int			 rc;
	ENTRY;

	lu_root_fid(&fid);

	lma = (struct lustre_mdt_attrs *)&mdd_env_info(env)->mti_xattr_buf;
	lustre_lma_init(lma, &fid, 0, 0);
	lustre_lma_swab(lma);
	buf.lb_buf = lma;
	buf.lb_len = sizeof(*lma);

	th = dt_trans_create(env, mdd->mdd_child);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));
	rc = mdo_declare_xattr_set(env, o, &buf, XATTR_NAME_LMA, 0, th);
	if (rc)
		GOTO(out, rc);
	rc = dt_trans_start_local(env, mdd->mdd_child, th);
	if (rc)
		GOTO(out, rc);
	rc = mdo_xattr_set(env, o, &buf, XATTR_NAME_LMA, 0, th, BYPASS_CAPA);
out:
	dt_trans_stop(env, mdd->mdd_child, th);
	RETURN(rc);
}

static int mdd_fix_children(const struct lu_env *env,
			    struct mdd_device *mdd,
			    struct dt_object *o)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	const struct dt_it_ops *iops;
	struct lu_name		name;
	struct dt_it	       *it;
	struct lu_dirent       *ent;
	int			rc;
	ENTRY;

	/* scan /ROOT and update all ".." and linkEAs */
	ent = (struct lu_dirent *)&info->mti_xattr_buf;
	iops = &o->do_index_ops->dio_it;

	it = iops->init(env, o, LUDA_64BITHASH, BYPASS_CAPA);
	if (IS_ERR(it)) {
		rc = PTR_ERR(it);
		CERROR("%s: can't initialize the iterator: rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name, rc);
		GOTO(out, rc);
	}

	rc = iops->load(env, it, 0);
	if (rc <= 0)
		GOTO(out_put, rc);

	do {
		size_t lu_dirent_size;

		rc = iops->key_size(env, it);
		if (rc == 0)
			goto next;

		/* calculate max space required for lu_dirent */
		lu_dirent_size = lu_dirent_calc_size(rc, 0);
		LASSERT(lu_dirent_size <= sizeof(info->mti_xattr_buf));

		rc = iops->rec(env, it, (struct dt_rec *)ent, LUDA_TYPE);
		if (rc == 0) {
			CDEBUG(D_OTHER, "convert %*s -> "DFID"\n",
			       ent->lde_namelen, ent->lde_name,
			       PFID(&ent->lde_fid));
			name.ln_namelen = ent->lde_namelen;
			name.ln_name = ent->lde_name;
			rc = mdd_convert_object(env, mdd, &ent->lde_fid, &name);
			if (rc) {
				CERROR("%s: can't convert "DFID": rc = %d\n",
				       mdd2obd_dev(mdd)->obd_name,
				       PFID(&ent->lde_fid), rc);
				break;
			}
		}

next:
		rc = iops->next(env, it);
	} while (rc == 0);
	if (rc > 0)
		rc = 0;

out_put:
	iops->put(env, it);
	iops->fini(env, it);
out:
	RETURN(rc);
}

static int mdd_fill_fldb(const struct lu_env *env, struct mdd_device *mdd)
{
	struct seq_server_site *ss = mdd_seq_site(mdd);
	struct lu_seq_range range;
	int	rc;

	LASSERT(ss->ss_server_seq != NULL);
	LASSERT(ss->ss_server_fld != NULL);

	if (ss->ss_server_seq->lss_space.lsr_end == 0)
		return 0;

	memcpy(&range, &ss->ss_server_seq->lss_space, sizeof(range));

	/* Pre-existing ZFS does not insert any entries to FLDB, we need
	 * to insert it to FLDB during convertion */
	range.lsr_start = FID_SEQ_NORMAL;
	fld_range_set_mdt(&range);

	mutex_lock(&ss->ss_server_fld->lsf_lock);
	rc = fld_insert_entry(env, ss->ss_server_fld, &range);
	mutex_unlock(&ss->ss_server_fld->lsf_lock);

	LCONSOLE_INFO("%s: insert missing range "DRANGE"\n",
		      mdd2obd_dev(mdd)->obd_name, PRANGE(&range));
	return rc;
}
int mdd_compat_fixes(const struct lu_env *env, struct mdd_device *mdd)
{
	struct mdd_thread_info	*info = mdd_env_info(env);
	struct mdd_object	*root;
	struct dt_object	*o;
	struct lustre_mdt_attrs	*lma;
	struct lu_buf		 buf;
	int			 rc;
	ENTRY;

	/* IGIF FIDS are valid for old 1.8 and 2.[123] ROOT and are kept.
	 * Normal FIDs used by Xyratex 1.8->2.1 upgrade tool are also kept. */
	if (fid_is_igif(&mdd->mdd_root_fid) || fid_is_norm(&mdd->mdd_root_fid))
		RETURN(0);

	/*
	 * FID is supposed to be FID_SEQ_ROOT for:
	 *  - new ldiskfs fs
	 *  - new ZFS fs
	 *  - old ZFS fs, by now processed with osd_convert_root_to_new_seq()
	 */
	if (fid_seq(&mdd->mdd_root_fid) != FID_SEQ_ROOT) {
		CERROR("%s: wrong FID "DFID" is used for /ROOT\n",
		       mdd2obd_dev(mdd)->obd_name,
		       PFID(&mdd->mdd_root_fid));
		RETURN(-EINVAL);
	}

	root = mdd_object_find(env, mdd, &mdd->mdd_root_fid);
	if (IS_ERR(root))
		RETURN(PTR_ERR(root));
	o = mdd_object_child(root);

	CDEBUG(D_OTHER, "/ROOT = "DFID"\n", PFID(&mdd->mdd_root_fid));

	if (dt_try_as_dir(env, o) == 0) {
		CERROR("%s: not a directory\n", mdd2obd_dev(mdd)->obd_name);
		GOTO(out, rc = -ENOTDIR);
	}

	lma = (struct lustre_mdt_attrs *)&info->mti_xattr_buf;
	CLASSERT(sizeof(info->mti_xattr_buf) >= LMA_OLD_SIZE);
	buf.lb_len = LMA_OLD_SIZE;
	buf.lb_buf = lma;
	rc = mdo_xattr_get(env, root, &buf, XATTR_NAME_LMA, BYPASS_CAPA);
	if (rc < 0 && rc != -ENODATA) {
		CERROR("%s: can't fetch LMA: rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name, rc);
		GOTO(out, rc);
	}

	lustre_lma_swab(lma);
	if (lu_fid_eq(&lma->lma_self_fid, &mdd->mdd_root_fid)) {
		/* /ROOT has been converted already
		 * or was correct from the beginning */
		CDEBUG(D_OTHER, "%s: converted already\n",
		       mdd2obd_dev(mdd)->obd_name);
		GOTO(out, rc = 0);
	}

	/* this is supposed to happen only on pre-production ZFS backend */
	if (strcmp(mdd->mdd_bottom->dd_lu_dev.ld_type->ldt_name,
		   LUSTRE_OSD_ZFS_NAME) != 0) {
		CERROR("%s: "DFID" is used on ldiskfs?!\n",
		       mdd2obd_dev(mdd)->obd_name, PFID(&mdd->mdd_root_fid));
		GOTO(out, rc = -ENOTSUPP);
	}

	LCONSOLE_INFO("%s: FID of /ROOT has been changed. "
		      "Please remount the clients.\n",
		      mdd2obd_dev(mdd)->obd_name);

	/* Fill FLDB first */
	rc = mdd_fill_fldb(env, mdd);
	if (rc)
		GOTO(out, rc);

	/* remove ./.. from /ROOT */
	rc = mdd_convert_remove_dots(env, mdd, root);
	if (rc)
		GOTO(out, rc);

	/* go over the directory, fix all the objects */
	rc = mdd_fix_children(env, mdd, o);
	if (rc)
		GOTO(out, rc);

	/* Update LMA on /ROOT.  Done for simplicity in MDD, not in osd-zfs.
	 * Correct LMA will imply the whole directory has been coverted
	 * successfully, otherwise it will be retried on next mount. */
	rc = mdd_convert_lma(env, mdd, root);

out:
	mdd_object_put(env, root);
	RETURN(rc);
}
