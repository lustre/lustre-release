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
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/mdt/mdt_restriper.c
 *
 * Lustre directory restripe and auto-split
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/sched.h>
#include <linux/kthread.h>
#include "mdt_internal.h"

/* add directory into splitting list and wake up restripe thread */
void mdt_auto_split_add(struct mdt_thread_info *info, struct mdt_object *o)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_dir_restriper *restriper = &mdt->mdt_restriper;

	spin_lock(&restriper->mdr_lock);
	if (mdt->mdt_enable_dir_auto_split && !o->mot_restriping) {
		o->mot_restriping = 1;
		mdt_object_get(NULL, o);
		LASSERT(list_empty(&o->mot_restripe_linkage));
		list_add_tail(&o->mot_restripe_linkage,
			      &restriper->mdr_auto_splitting);

		CDEBUG(D_INFO, "add "DFID" into auto split list.\n",
		       PFID(mdt_object_fid(o)));
	}
	spin_unlock(&restriper->mdr_lock);

	wake_up_process(restriper->mdr_task);
}

void mdt_restripe_migrate_add(struct mdt_thread_info *info,
			      struct mdt_object *o)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_dir_restriper *restriper = &mdt->mdt_restriper;

	spin_lock(&restriper->mdr_lock);
	if (!o->mot_restriping) {
		o->mot_restriping = 1;
		o->mot_restripe_offset = 0;
		mdt_object_get(NULL, o);
		LASSERT(list_empty(&o->mot_restripe_linkage));
		list_add_tail(&o->mot_restripe_linkage,
			      &restriper->mdr_migrating);

		CDEBUG(D_INFO, "add "DFID" into migrate list.\n",
		       PFID(mdt_object_fid(o)));
	}
	spin_unlock(&restriper->mdr_lock);

	wake_up_process(restriper->mdr_task);
}

void mdt_restripe_update_add(struct mdt_thread_info *info,
			     struct mdt_object *o)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_dir_restriper *restriper = &mdt->mdt_restriper;

	spin_lock(&restriper->mdr_lock);
	if (!o->mot_restriping) {
		/* update LMV */
		o->mot_restriping = 1;
		mdt_object_get(NULL, o);
		if (list_empty(&restriper->mdr_updating))
			restriper->mdr_update_time = ktime_get_real_seconds();
		LASSERT(list_empty(&o->mot_restripe_linkage));
		list_add_tail(&o->mot_restripe_linkage,
			      &restriper->mdr_updating);

		CDEBUG(D_INFO, "add "DFID" into update list.\n",
		       PFID(mdt_object_fid(o)));
	}
	spin_unlock(&restriper->mdr_lock);

	wake_up_process(restriper->mdr_task);
}

static inline int mdt_fid_alloc(const struct lu_env *env,
				struct mdt_device *mdt,
				struct lu_fid *fid,
				struct mdt_object *parent,
				const struct lu_name *name)
{
	struct lu_device *next = &mdt->mdt_child->md_lu_dev;
	struct lu_object *o = lu_object_next(&parent->mot_obj);

	return next->ld_ops->ldo_fid_alloc(env, next, fid, o, name);
}

static void mdt_auto_split_prep(struct mdt_thread_info *info,
				struct md_op_spec *spec,
				struct md_attr *ma,
				u32 lum_stripe_count)
{
	struct lu_attr *attr = &ma->ma_attr;
	struct lmv_user_md_v1 *lum;

	attr->la_ctime = attr->la_mtime = ktime_get_real_seconds();
	attr->la_valid = LA_CTIME | LA_MTIME;

	lum = &info->mti_mdt->mdt_restriper.mdr_lmv.lmv_user_md;
	lum->lum_magic = cpu_to_le32(LMV_USER_MAGIC);
	lum->lum_stripe_count = cpu_to_le32(lum_stripe_count);
	lum->lum_stripe_offset = cpu_to_le32(LMV_OFFSET_DEFAULT);
	lum->lum_hash_type = 0;

	spec->u.sp_ea.eadatalen = sizeof(*lum);
	spec->u.sp_ea.eadata = lum;
	spec->sp_cr_flags = MDS_OPEN_HAS_EA;
	spec->no_create = 0;
	spec->sp_migrate_close = 0;
}

/* restripe directory: split or merge stripes */
int mdt_restripe_internal(struct mdt_thread_info *info,
			  struct mdt_object *parent,
			  struct mdt_object *child,
			  const struct lu_name *lname,
			  struct lu_fid *tfid,
			  struct md_op_spec *spec,
			  struct md_attr *ma)
{
	const struct lu_env *env = info->mti_env;
	struct mdt_device *mdt = info->mti_mdt;
	struct lmv_user_md *lum = spec->u.sp_ea.eadata;
	struct lmv_mds_md_v1 *lmv;
	u32 lmv_stripe_count = 0;
	int rc;

	ENTRY;

	rc = mdt_stripe_get(info, child, ma, XATTR_NAME_LMV);
	if (rc)
		RETURN(rc);

	if (ma->ma_valid & MA_LMV) {
		lmv = &ma->ma_lmv->lmv_md_v1;
		if (!lmv_is_sane(lmv))
			RETURN(-EBADF);

		/* don't allow restripe if dir layout is changing */
		if (lmv_is_layout_changing(lmv))
			RETURN(-EBUSY);

		/* check whether stripe count and hash unchanged */
		if (lum->lum_stripe_count == lmv->lmv_stripe_count &&
		    lum->lum_hash_type == lmv->lmv_hash_type)
			RETURN(-EALREADY);

		lmv_stripe_count = le32_to_cpu(lmv->lmv_stripe_count);
	} else if (le32_to_cpu(lum->lum_stripe_count) < 2) {
		/* stripe count unchanged for plain directory */
		RETURN(-EALREADY);
	}

	if (le32_to_cpu(lum->lum_stripe_count) > lmv_stripe_count) {
		/* split */
		struct md_layout_change *mlc = &info->mti_mlc;
		struct mdt_object *tobj = NULL;
		s64 mtime = ma->ma_attr.la_mtime;

		ma->ma_need = MA_INODE;
		ma->ma_valid = 0;
		rc = mdt_attr_get_complex(info, child, ma);
		if (rc)
			RETURN(rc);

		if (!(ma->ma_valid & MA_INODE))
			RETURN(-EBADF);

		/* mtime is from from client or set outside */
		ma->ma_attr.la_mtime = mtime;

		if (!lmv_stripe_count) {
			/* if child is plain directory, allocate @tobj as the
			 * master object, and make child the first stripe of
			 * @tobj.
			 */
			tobj = mdt_object_new(env, mdt, tfid);
			if (unlikely(IS_ERR(tobj)))
				RETURN(PTR_ERR(tobj));
		}

		mlc->mlc_opc = MD_LAYOUT_SPLIT;
		mlc->mlc_parent = mdt_object_child(parent);
		mlc->mlc_target = tobj ? mdt_object_child(tobj) : NULL;
		mlc->mlc_attr = &ma->ma_attr;
		mlc->mlc_name = lname;
		mlc->mlc_spec = spec;
		rc = mo_layout_change(env, mdt_object_child(child), mlc);
		if (!rc) {
			/* FID and attr need to be replied to client for manual
			 * restripe.
			 */
			ma->ma_need = MA_INODE;
			ma->ma_valid = 0;
			rc = mdt_attr_get_complex(info,
					lmv_stripe_count ? child : tobj, ma);
		}
		if (tobj)
			mdt_object_put(env, tobj);
		else
			*tfid = *mdt_object_fid(child);
	} else {
		/* merge only needs to override LMV */
		struct lu_buf *buf = &info->mti_buf;
		__u32 version;

		LASSERT(ma->ma_valid & MA_LMV);
		lmv = &ma->ma_lmv->lmv_md_v1;
		version = cpu_to_le32(lmv->lmv_layout_version);

		/* adjust 0 to 1 */
		if (lum->lum_stripe_count == 0)
			lum->lum_stripe_count = cpu_to_le32(1);

		lmv->lmv_hash_type |= cpu_to_le32(LMV_HASH_FLAG_MERGE |
						  LMV_HASH_FLAG_MIGRATION);
		lmv->lmv_merge_offset = lum->lum_stripe_count;
		lmv->lmv_merge_hash = lum->lum_hash_type;
		lmv->lmv_layout_version = cpu_to_le32(++version);

		buf->lb_buf = lmv;
		buf->lb_len = sizeof(*lmv);
		rc = mo_xattr_set(env, mdt_object_child(child), buf,
				  XATTR_NAME_LMV, LU_XATTR_REPLACE);
		if (rc)
			RETURN(rc);

		*tfid = *mdt_object_fid(child);
		ma->ma_need = MA_INODE;
		ma->ma_valid = 0;
		rc = mdt_attr_get_complex(info, child, ma);
	}

	RETURN(rc);
}

static int mdt_auto_split(struct mdt_thread_info *info)
{
	const struct lu_env *env = info->mti_env;
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_dir_restriper *restriper = &mdt->mdt_restriper;
	struct md_attr *ma = &info->mti_attr;
	struct md_op_spec *spec = &info->mti_spec;
	struct lu_name *lname = &info->mti_name;
	struct lu_fid *fid = &info->mti_tmp_fid2;
	struct mdt_object *parent = NULL;
	struct mdt_object *child = NULL;
	struct mdt_object *stripe = NULL;
	struct ldlm_enqueue_info *einfo = &info->mti_einfo[0];
	struct mdt_lock_handle *lhp;
	struct mdt_lock_handle *lhc;
	u32 lmv_stripe_count = 0;
	u32 lum_stripe_count = 0;
	int rc;

	ENTRY;

	if (!atomic_read(&mdt->mdt_mds_mds_conns))
		RETURN(-EINVAL);

	spin_lock(&restriper->mdr_lock);
	if (!list_empty(&restriper->mdr_auto_splitting)) {
		child = list_entry(restriper->mdr_auto_splitting.next,
				   typeof(*child), mot_restripe_linkage);
		list_del_init(&child->mot_restripe_linkage);
	}
	spin_unlock(&restriper->mdr_lock);

	if (!child)
		RETURN(0);

	LASSERT(child->mot_restriping);

	rc = mdt_stripe_get(info, child, ma, XATTR_NAME_LMV);
	if (rc)
		GOTO(out, rc);

	if (ma->ma_valid & MA_LMV) {
		/* stripe dirent exceeds threshold, find its master object */
		struct lmv_mds_md_v1 *lmv = &ma->ma_lmv->lmv_md_v1;

		/* auto-split won't be done on striped directory master object
		 * directly, because it's triggered when dirent count exceeds
		 * threshold, however dirent count of master object is its
		 * stripe count.
		 */
		if (le32_to_cpu(lmv->lmv_magic) != LMV_MAGIC_STRIPE)
			GOTO(out, rc = -EINVAL);

		lmv_stripe_count = le32_to_cpu(lmv->lmv_stripe_count);

		/* save stripe to clear 'restriping' flag in the end to avoid
		 * trigger auto-split multiple times.
		 */
		stripe = child;
		child = NULL;

		/* get master object FID from linkea */
		rc = mdt_attr_get_pfid(info, stripe, &ma->ma_pfid);
		if (rc)
			GOTO(out, rc);

		child = mdt_object_find(env, mdt, &ma->ma_pfid);
		if (IS_ERR(child))
			GOTO(out, rc = PTR_ERR(child));

		spin_lock(&restriper->mdr_lock);
		if (child->mot_restriping) {
			/* race? */
			spin_unlock(&restriper->mdr_lock);
			GOTO(out, rc = -EBUSY);
		}
		child->mot_restriping = 1;
		spin_unlock(&restriper->mdr_lock);

		/* skip if master object is remote, let the first stripe
		 * to start splitting because dir split needs to be done
		 * on where master object is.
		 */
		if (mdt_object_remote(child))
			GOTO(restriping_clear, rc = -EREMOTE);
	}

	/* striped directory split adds mdr_auto_split_delta stripes */
	lum_stripe_count = min_t(unsigned int,
				lmv_stripe_count +
					mdt->mdt_restriper.mdr_dir_split_delta,
				atomic_read(&mdt->mdt_mds_mds_conns) + 1);
	if (lmv_stripe_count >= lum_stripe_count)
		GOTO(restriping_clear, rc = -EALREADY);

	/* get dir name and parent FID */
	rc = mdt_attr_get_pfid_name(info, child, fid, lname);
	if (rc)
		GOTO(restriping_clear, rc);

	/* copy name out because mti_linkea will be used later, and name should
	 * end with '\0'
	 */
	memcpy(info->mti_filename, lname->ln_name, lname->ln_namelen);
	info->mti_filename[lname->ln_namelen] = '\0';
	lname->ln_name = info->mti_filename;
	CDEBUG(D_INFO, "split "DFID"/"DNAME" to count %u (MDT count %d)\n",
	       PFID(fid), PNAME(lname), lum_stripe_count,
	       atomic_read(&mdt->mdt_mds_mds_conns) + 1);

	parent = mdt_object_find(env, mdt, fid);
	if (IS_ERR(parent))
		GOTO(restriping_clear, rc = PTR_ERR(parent));

	rc = mdt_fid_alloc(env, mdt, fid, child, NULL);
	if (rc < 0)
		GOTO(restriping_clear, rc);

	lhp = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_pdo_init(lhp, LCK_PW, lname);
	rc = mdt_reint_object_lock(info, parent, lhp, MDS_INODELOCK_UPDATE,
				   true);
	if (rc)
		GOTO(restriping_clear, rc);

	lhc = &info->mti_lh[MDT_LH_CHILD];
	mdt_lock_reg_init(lhc, LCK_EX);
	if (mdt_object_remote(parent)) {
		/* enqueue object remote LOOKUP lock */
		rc = mdt_remote_object_lock(info, parent, mdt_object_fid(child),
					    &lhc->mlh_rreg_lh,
					    lhc->mlh_rreg_mode,
					    MDS_INODELOCK_LOOKUP, false);
		if (rc != ELDLM_OK)
			GOTO(unlock_parent, rc);
	}

	rc = mdt_reint_striped_lock(info, child, lhc, MDS_INODELOCK_FULL, einfo,
				    true);
	if (rc)
		GOTO(unlock_child, rc);

	mdt_auto_split_prep(info, spec, ma, lum_stripe_count);

	rc = mdt_restripe_internal(info, parent, child, lname, fid, spec, ma);
	EXIT;

unlock_child:
	mdt_reint_striped_unlock(info, child, lhc, einfo, rc);
unlock_parent:
	mdt_object_unlock(info, parent, lhp, rc);
restriping_clear:
	child->mot_restriping = 0;
	LASSERT(list_empty(&child->mot_restripe_linkage));
out:
	/* -EALREADY:	dir is split already.
	 * -EBUSY:	dir is opened, or is splitting by others.
	 * -EREMOTE:	dir is remote.
	 */
	if (rc && rc != -EALREADY && rc != -EBUSY && rc != -EREMOTE)
		CERROR("%s: split "DFID"/"DNAME" to count %u failed: rc = %d\n",
		       mdt_obd_name(mdt), PFID(mdt_object_fid(child)),
		       PNAME(lname), lum_stripe_count, rc);

	if (!IS_ERR_OR_NULL(child))
		mdt_object_put(env, child);

	if (stripe) {
		LASSERT(stripe->mot_restriping);
		LASSERT(list_empty(&stripe->mot_restripe_linkage));
		stripe->mot_restriping = 0;
		/* lock may not be taken, don't cache stripe LMV */
		mo_invalidate(env, mdt_object_child(stripe));
		mdt_object_put(env, stripe);
	}

	if (!IS_ERR_OR_NULL(parent))
		mdt_object_put(env, parent);

	return rc;
}

/* sub-files under one stripe are migrated, clear MIGRATION flag in its LMV */
static int mdt_restripe_migrate_finish(struct mdt_thread_info *info,
				       struct mdt_object *stripe,
				       struct lmv_mds_md_v1 *lmv)
{
	struct mdt_device *mdt = info->mti_mdt;
	struct lu_buf buf;
	struct mdt_lock_handle *lh;
	int rc;

	ENTRY;

	LASSERT(le32_to_cpu(lmv->lmv_magic) == LMV_MAGIC_STRIPE);
	LASSERT(lmv_is_restriping(lmv));

	lmv->lmv_hash_type &= ~cpu_to_le32(LMV_HASH_FLAG_MIGRATION);
	buf.lb_buf = lmv;
	buf.lb_len = sizeof(*lmv);

	lh = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_reg_init(lh, LCK_EX);
	rc = mdt_reint_object_lock(info, stripe, lh, MDS_INODELOCK_XATTR,
				   false);
	if (!rc)
		rc = mo_xattr_set(info->mti_env, mdt_object_child(stripe), &buf,
				  XATTR_NAME_LMV, LU_XATTR_REPLACE);
	mdt_object_unlock(info, stripe, lh, rc);
	if (rc)
		CERROR("%s: update "DFID" LMV failed: rc = %d\n",
		       mdt_obd_name(mdt), PFID(mdt_object_fid(stripe)), rc);

	LASSERT(!list_empty(&stripe->mot_restripe_linkage));
	LASSERT(stripe->mot_restriping);

	spin_lock(&mdt->mdt_lock);
	stripe->mot_restriping = 0;
	list_del_init(&stripe->mot_restripe_linkage);
	spin_unlock(&mdt->mdt_lock);

	mdt_object_put(info->mti_env, stripe);

	RETURN(rc);
}

static void mdt_restripe_migrate_prep(struct mdt_thread_info *info,
				      const struct lu_fid *fid1,
				      const struct lu_fid *fid2,
				      const struct lu_name *lname,
				      __u16 type,
				      const struct lmv_mds_md_v1 *lmv)
{
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct md_op_spec *spec = &info->mti_spec;
	struct lmv_user_md_v1 *lum;

	attr->la_ctime = attr->la_mtime = ktime_get_real_seconds();
	attr->la_valid = LA_CTIME | LA_MTIME;

	rr->rr_fid1 = fid1;
	rr->rr_fid2 = fid2;
	rr->rr_name = *lname;

	lum = &info->mti_mdt->mdt_restriper.mdr_lmv.lmv_user_md;
	lum->lum_magic = cpu_to_le32(LMV_USER_MAGIC);
	lum->lum_stripe_offset = cpu_to_le32(LMV_OFFSET_DEFAULT);
	if (lmv_is_splitting(lmv)) {
		lum->lum_stripe_count = lmv->lmv_stripe_count;
		lum->lum_hash_type =
			lmv->lmv_hash_type & le32_to_cpu(LMV_HASH_TYPE_MASK);
	} else if (lmv_is_merging(lmv)) {
		lum->lum_stripe_count = lmv->lmv_merge_offset;
		lum->lum_hash_type = lmv->lmv_merge_hash;
	}

	spec->u.sp_ea.eadatalen = sizeof(*lum);
	spec->u.sp_ea.eadata = lum;
	spec->sp_cr_flags = MDS_OPEN_HAS_EA;
	spec->no_create = 0;
	spec->sp_migrate_close = 0;
	/* if 'nsonly' is set, don't migrate inode */
	if (S_ISDIR(type))
		spec->sp_migrate_nsonly = 1;
	else
		spec->sp_migrate_nsonly =
			info->mti_mdt->mdt_dir_restripe_nsonly;
}

/* migrate sub-file from @mdr_restripe_offset */
static int mdt_restripe_migrate(struct mdt_thread_info *info)
{
	const struct lu_env *env = info->mti_env;
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_dir_restriper *restriper = &mdt->mdt_restriper;
	struct mdt_object *stripe = NULL;
	struct mdt_object *master = NULL;
	struct md_attr *ma = &info->mti_attr;
	struct lmv_mds_md_v1 *lmv;
	struct lu_name *lname = &info->mti_name;
	struct lu_rdpg *rdpg = &info->mti_u.rdpg.mti_rdpg;
	struct lu_fid fid1;
	struct lu_fid fid2;
	struct lu_dirpage *dp;
	struct lu_dirent *ent;
	const char *name = NULL;
	int namelen = 0;
	__u16 type;
	int idx = 0;
	int len;
	int rc;

	ENTRY;

	if (list_empty(&restriper->mdr_migrating))
		RETURN(0);

	stripe = list_entry(restriper->mdr_migrating.next, typeof(*stripe),
			    mot_restripe_linkage);

	/* get master object FID and stripe name */
	rc = mdt_attr_get_pfid_name(info, stripe, &fid1, lname);
	if (rc)
		GOTO(out, rc);

	snprintf(info->mti_filename, sizeof(info->mti_filename), DFID,
		 PFID(mdt_object_fid(stripe)));
	len = strlen(info->mti_filename) + 1;
	if (len >= lname->ln_namelen)
		GOTO(out, rc = -EBADF);

	while (len < lname->ln_namelen) {
		if (!isdigit(lname->ln_name[len]))
			GOTO(out, rc = -EBADF);

		idx = idx * 10 + lname->ln_name[len++] - '0';
	};

	/* check whether stripe is newly created in split */
	rc = mdt_stripe_get(info, stripe, ma, XATTR_NAME_LMV);
	if (rc)
		GOTO(out, rc);

	if (!(ma->ma_valid & MA_LMV))
		GOTO(out, rc = -ENODATA);

	lmv = &ma->ma_lmv->lmv_md_v1;
	if (le32_to_cpu(lmv->lmv_magic) != LMV_MAGIC_STRIPE)
		GOTO(out, rc = -EBADF);

	if (!lmv_is_restriping(lmv))
		GOTO(out, rc = -EINVAL);

	if ((lmv_is_splitting(lmv) &&
	     idx >= le32_to_cpu(lmv->lmv_split_offset)) ||
	    (lmv_is_merging(lmv) &&
	     le32_to_cpu(lmv->lmv_hash_type) == LMV_HASH_TYPE_CRUSH &&
	     idx < le32_to_cpu(lmv->lmv_merge_offset))) {
		/* new stripes doesn't need to migrate sub files in dir
		 * split, neither for target stripes in dir merge if hash type
		 * is CRUSH.
		 */
		rc = mdt_restripe_migrate_finish(info, stripe, lmv);
		RETURN(rc);
	}

	/* get sub file name @mot_restripe_offset.
	 * TODO: read one dirent instead of whole page.
	 */
	rdpg->rp_hash = stripe->mot_restripe_offset;
	rdpg->rp_count = PAGE_SIZE;
	rdpg->rp_npages = 1;
	rdpg->rp_attrs = LUDA_64BITHASH | LUDA_FID | LUDA_TYPE;
	rdpg->rp_pages = &restriper->mdr_page;
	rc = mo_readpage(env, mdt_object_child(stripe), rdpg);
	if (rc < 0)
		GOTO(out, rc);

	dp = page_address(restriper->mdr_page);
	for (ent = lu_dirent_start(dp); ent; ent = lu_dirent_next(ent)) {
		LASSERT(le64_to_cpu(ent->lde_hash) >= rdpg->rp_hash);

		if (unlikely(!(le32_to_cpu(ent->lde_attrs) & LUDA_TYPE)))
			GOTO(out, rc = -EINVAL);

		namelen = le16_to_cpu(ent->lde_namelen);
		if (!namelen)
			continue;

		if (name_is_dot_or_dotdot(ent->lde_name, namelen))
			continue;

		name = ent->lde_name;
		type = lu_dirent_type_get(ent);
		break;
	}

	if (!name) {
		if (le64_to_cpu(dp->ldp_hash_end) == MDS_DIR_END_OFF) {
			rc = mdt_restripe_migrate_finish(info, stripe, lmv);
			RETURN(rc);
		}

		GOTO(out, rc = -EBADF);
	}

	/* copy name out because it should end with '\0' */
	memcpy(info->mti_filename, name, namelen);
	info->mti_filename[namelen] = '\0';
	lname->ln_name = info->mti_filename;
	lname->ln_namelen = namelen;

	CDEBUG(D_INFO, "migrate "DFID"/"DNAME" type %ho\n",
	       PFID(&fid1), PNAME(lname), type);

	master = mdt_object_find(env, mdt, &fid1);
	if (IS_ERR(master))
		GOTO(out, rc = PTR_ERR(master));

	rc = mdt_fid_alloc(env, mdt, &fid2, master, lname);
	mdt_object_put(env, master);
	if (rc < 0)
		GOTO(out, rc);

	mdt_restripe_migrate_prep(info, &fid1, &fid2, lname, type, lmv);

	rc = mdt_reint_migrate(info, NULL);
	/* mti_big_buf is allocated in XATTR migration */
	if (unlikely(info->mti_big_buf.lb_buf))
		lu_buf_free(&info->mti_big_buf);
	if (rc == -EALREADY)
		rc = 0;
	if (rc)
		GOTO(out, rc);

	LASSERT(ent);
	do {
		ent = lu_dirent_next(ent);
		if (!ent)
			break;

		namelen = le16_to_cpu(ent->lde_namelen);
	} while (namelen == 0); /* Skip dummy record */

	if (ent)
		stripe->mot_restripe_offset = le64_to_cpu(ent->lde_hash);
	else
		stripe->mot_restripe_offset = le64_to_cpu(dp->ldp_hash_end);

	EXIT;
out:
	if (rc) {
		/* -EBUSY: file is opened by others */
		if (rc != -EBUSY)
			CERROR("%s: migrate "DFID"/"DNAME" failed: rc = %d\n",
			       mdt_obd_name(mdt), PFID(&fid1), PNAME(lname),
			       rc);

		spin_lock(&mdt->mdt_lock);
		stripe->mot_restriping = 0;
		list_del_init(&stripe->mot_restripe_linkage);
		spin_unlock(&mdt->mdt_lock);

		mdt_object_put(env, stripe);
	}

	return rc;
}

static inline bool mdt_restripe_update_pending(struct mdt_thread_info *info)
{
	struct mdt_device *mdt = info->mti_mdt;

	if (list_empty(&mdt->mdt_restriper.mdr_updating))
		return false;

	return mdt->mdt_restriper.mdr_update_time < ktime_get_real_seconds();
}

static void mdt_restripe_layout_update_prep(struct mdt_thread_info *info,
					    const struct lu_fid *fid,
					    const struct lmv_mds_md_v1 *lmv)
{
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct lmv_user_md_v1 *lum;

	attr->la_ctime = attr->la_mtime = ktime_get_real_seconds();
	attr->la_valid = LA_CTIME | LA_MTIME;

	strncpy(info->mti_filename, XATTR_NAME_LMV,
		sizeof(info->mti_filename));

	lum = &info->mti_mdt->mdt_restriper.mdr_lmv.lmv_user_md;
	lum->lum_magic = cpu_to_le32(LMV_USER_MAGIC);
	lum->lum_stripe_offset = cpu_to_le32(LMV_OFFSET_DEFAULT);
	if (lmv_is_splitting(lmv)) {
		lum->lum_stripe_count = lmv->lmv_stripe_count;
		lum->lum_hash_type =
			lmv->lmv_hash_type & le32_to_cpu(LMV_HASH_TYPE_MASK);
	} else if (lmv_is_merging(lmv)) {
		lum->lum_stripe_count = lmv->lmv_merge_offset;
		lum->lum_hash_type = lmv->lmv_merge_hash;
	}

	rr->rr_opcode = REINT_SETXATTR;
	rr->rr_fid1 = fid;
	rr->rr_name.ln_name = info->mti_filename;
	rr->rr_name.ln_namelen = strlen(info->mti_filename);
	rr->rr_eadata = lum;
	rr->rr_eadatalen = sizeof(*lum);
}

static int mdt_restripe_layout_update(struct mdt_thread_info *info)
{
	const struct lu_env *env = info->mti_env;
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_dir_restriper *restriper = &mdt->mdt_restriper;
	struct md_attr *ma = &info->mti_attr;
	struct lu_fid *fid = &info->mti_tmp_fid1;
	struct mdt_object *master;
	struct mdt_object *stripe;
	struct lmv_mds_md_v1 *lmv;
	int i;
	int rc;

	ENTRY;

	if (list_empty(&restriper->mdr_updating))
		RETURN(0);

	master = list_entry(restriper->mdr_updating.next, typeof(*master),
			    mot_restripe_linkage);

	rc = mdt_stripe_get(info, master, ma, XATTR_NAME_LMV);
	if (rc)
		GOTO(out, rc);

	if (!(ma->ma_valid & MA_LMV))
		GOTO(out, rc = -ENODATA);

	lmv = &ma->ma_lmv->lmv_md_v1;
	if (le32_to_cpu(lmv->lmv_magic) != LMV_MAGIC_V1)
		GOTO(out, rc = -EBADF);

	if (!lmv_is_restriping(lmv))
		GOTO(out, rc = -EINVAL);

	/* use different buffer to store stripe LMV */
	ma->ma_lmv = &restriper->mdr_lmv;
	ma->ma_lmv_size = sizeof(restriper->mdr_lmv);
	for (i = 0; i < le32_to_cpu(lmv->lmv_stripe_count); i++) {
		fid_le_to_cpu(fid, &lmv->lmv_stripe_fids[i]);
		stripe = mdt_object_find(env, mdt, fid);
		if (IS_ERR(stripe))
			GOTO(out, rc = PTR_ERR(stripe));

		ma->ma_valid = 0;
		rc = __mdt_stripe_get(info, stripe, ma, XATTR_NAME_LMV);
		/* LMV is checked without lock, don't cache it */
		mo_invalidate(env, mdt_object_child(stripe));
		mdt_object_put(env, stripe);
		if (rc)
			GOTO(out, rc);

		if (!(ma->ma_valid & MA_LMV))
			GOTO(out, rc = -ENODATA);

		/* check MIGRATION flag cleared on all stripes */
		if (lmv_is_restriping(&ma->ma_lmv->lmv_md_v1))
			GOTO(out, rc = -EINPROGRESS);
	}

	mdt_restripe_layout_update_prep(info, mdt_object_fid(master), lmv);

	rc = mdt_dir_layout_update(info);
	if (rc) {
		CERROR("update "DFID" layout failed: rc = %d\n",
		       PFID(mdt_object_fid(master)), rc);
		GOTO(out, rc);
	}

out:
	LASSERT(!list_empty(&master->mot_restripe_linkage));
	if (rc == -EINPROGRESS) {
		restriper->mdr_update_time = ktime_get_real_seconds() + 5;
	} else {
		spin_lock(&restriper->mdr_lock);
		master->mot_restriping = 0;
		list_del_init(&master->mot_restripe_linkage);
		spin_unlock(&restriper->mdr_lock);

		mdt_object_put(env, master);
	}

	return rc;
}

static int mdt_restriper_main(void *arg)
{
	struct mdt_thread_info *info = arg;
	struct mdt_device *mdt = info->mti_mdt;
	struct mdt_dir_restriper *restriper = &mdt->mdt_restriper;

	ENTRY;

	while (({set_current_state(TASK_IDLE);
		 !kthread_should_stop(); })) {
		if (!list_empty(&restriper->mdr_auto_splitting)) {
			__set_current_state(TASK_RUNNING);
			mdt_auto_split(info);
			cond_resched();
		} else if (mdt_restripe_update_pending(info)) {
			__set_current_state(TASK_RUNNING);
			mdt_restripe_layout_update(info);
			cond_resched();
		} else if (!list_empty(&restriper->mdr_migrating)) {
			__set_current_state(TASK_RUNNING);
			mdt_restripe_migrate(info);
			cond_resched();
		} else {
			schedule();
		}
	}
	__set_current_state(TASK_RUNNING);

	RETURN(0);
}

int mdt_restriper_start(struct mdt_device *mdt)
{
	struct mdt_dir_restriper *restriper = &mdt->mdt_restriper;
	kernel_cap_t kcap = cap_combine(CAP_FS_SET, CAP_NFSD_SET);
	struct task_struct *task;
	struct mdt_thread_info *info;
	struct lu_ucred *uc;
	int rc;

	ENTRY;

	spin_lock_init(&restriper->mdr_lock);
	INIT_LIST_HEAD(&restriper->mdr_auto_splitting);
	INIT_LIST_HEAD(&restriper->mdr_migrating);
	INIT_LIST_HEAD(&restriper->mdr_updating);
	restriper->mdr_dir_split_count = DIR_SPLIT_COUNT_DEFAULT;
	restriper->mdr_dir_split_delta = DIR_SPLIT_DELTA_DEFAULT;

	restriper->mdr_page = alloc_page(GFP_KERNEL);
	if (!restriper->mdr_page)
		RETURN(-ENOMEM);

	rc = lu_env_init(&restriper->mdr_env, LCT_MD_THREAD);
	if (rc)
		GOTO(out_page, rc);

	rc = lu_context_init(&restriper->mdr_session, LCT_SERVER_SESSION);
	if (rc)
		GOTO(out_env, rc);

	lu_context_enter(&restriper->mdr_session);
	restriper->mdr_env.le_ses = &restriper->mdr_session;

	info = lu_context_key_get(&restriper->mdr_env.le_ctx, &mdt_thread_key);
	info->mti_env = &restriper->mdr_env;
	info->mti_mdt = mdt;
	info->mti_pill = NULL;
	info->mti_dlm_req = NULL;

	uc = mdt_ucred(info);
	uc->uc_valid = UCRED_OLD;
	uc->uc_o_uid = 0;
	uc->uc_o_gid = 0;
	uc->uc_o_fsuid = 0;
	uc->uc_o_fsgid = 0;
	uc->uc_uid = 0;
	uc->uc_gid = 0;
	uc->uc_fsuid = 0;
	uc->uc_fsgid = 0;
	uc->uc_suppgids[0] = -1;
	uc->uc_suppgids[1] = -1;
	uc->uc_cap = kcap.cap[0];
	uc->uc_umask = 0644;
	uc->uc_ginfo = NULL;
	uc->uc_identity = NULL;

	task = kthread_create(mdt_restriper_main, info, "mdt_restriper_%03d",
			      mdt_seq_site(mdt)->ss_node_id);
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: Can't start directory restripe thread: rc %d\n",
		       mdt_obd_name(mdt), rc);
		GOTO(out_ses, rc);
	}
	restriper->mdr_task = task;
	wake_up_process(task);

	RETURN(0);

out_ses:
	lu_context_exit(restriper->mdr_env.le_ses);
	lu_context_fini(restriper->mdr_env.le_ses);
out_env:
	lu_env_fini(&restriper->mdr_env);
out_page:
	__free_page(restriper->mdr_page);

	return rc;
}

void mdt_restriper_stop(struct mdt_device *mdt)
{
	struct mdt_dir_restriper *restriper = &mdt->mdt_restriper;
	struct lu_env *env = &restriper->mdr_env;
	struct mdt_object *mo, *next;

	if (!restriper->mdr_task)
		return;

	kthread_stop(restriper->mdr_task);
	restriper->mdr_task = NULL;

	list_for_each_entry_safe(mo, next, &restriper->mdr_auto_splitting,
				 mot_restripe_linkage) {
		list_del_init(&mo->mot_restripe_linkage);
		mdt_object_put(env, mo);
	}

	list_for_each_entry_safe(mo, next, &restriper->mdr_migrating,
				 mot_restripe_linkage) {
		list_del_init(&mo->mot_restripe_linkage);
		mdt_object_put(env, mo);
	}

	list_for_each_entry_safe(mo, next, &restriper->mdr_updating,
				 mot_restripe_linkage) {
		list_del_init(&mo->mot_restripe_linkage);
		mdt_object_put(env, mo);
	}

	__free_page(restriper->mdr_page);

	lu_context_exit(env->le_ses);
	lu_context_fini(env->le_ses);
	lu_env_fini(env);
}
