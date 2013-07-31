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
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * lustre/lod/lod_object.c
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <lustre_fid.h>
#include <lustre_param.h>
#include <lustre_fid.h>
#include <lustre_lmv.h>
#include <obd_lov.h>

#include "lod_internal.h"

static const char dot[] = ".";
static const char dotdot[] = "..";

extern struct kmem_cache *lod_object_kmem;
static const struct dt_body_operations lod_body_lnk_ops;

static int lod_index_lookup(const struct lu_env *env, struct dt_object *dt,
			    struct dt_rec *rec, const struct dt_key *key,
			    struct lustre_capa *capa)
{
	struct dt_object *next = dt_object_child(dt);
	return next->do_index_ops->dio_lookup(env, next, rec, key, capa);
}

static int lod_declare_index_insert(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_rec *rec,
				    const struct dt_key *key,
				    struct thandle *handle)
{
	return dt_declare_insert(env, dt_object_child(dt), rec, key, handle);
}

static int lod_index_insert(const struct lu_env *env,
			    struct dt_object *dt,
			    const struct dt_rec *rec,
			    const struct dt_key *key,
			    struct thandle *th,
			    struct lustre_capa *capa,
			    int ign)
{
	return dt_insert(env, dt_object_child(dt), rec, key, th, capa, ign);
}

static int lod_declare_index_delete(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_key *key,
				    struct thandle *th)
{
	return dt_declare_delete(env, dt_object_child(dt), key, th);
}

static int lod_index_delete(const struct lu_env *env,
			    struct dt_object *dt,
			    const struct dt_key *key,
			    struct thandle *th,
			    struct lustre_capa *capa)
{
	return dt_delete(env, dt_object_child(dt), key, th, capa);
}

static struct dt_it *lod_it_init(const struct lu_env *env,
				 struct dt_object *dt, __u32 attr,
				 struct lustre_capa *capa)
{
	struct dt_object	*next = dt_object_child(dt);
	struct lod_it		*it = &lod_env_info(env)->lti_it;
	struct dt_it		*it_next;


	it_next = next->do_index_ops->dio_it.init(env, next, attr, capa);
	if (IS_ERR(it_next))
		return it_next;

	/* currently we do not use more than one iterator per thread
	 * so we store it in thread info. if at some point we need
	 * more active iterators in a single thread, we can allocate
	 * additional ones */
	LASSERT(it->lit_obj == NULL);

	it->lit_it = it_next;
	it->lit_obj = next;

	return (struct dt_it *)it;
}

#define LOD_CHECK_IT(env, it)					\
{								\
	LASSERT((it)->lit_obj != NULL);				\
	LASSERT((it)->lit_it != NULL);				\
} while(0)

void lod_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	it->lit_obj->do_index_ops->dio_it.fini(env, it->lit_it);

	/* the iterator not in use any more */
	it->lit_obj = NULL;
	it->lit_it = NULL;
}

int lod_it_get(const struct lu_env *env, struct dt_it *di,
	       const struct dt_key *key)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.get(env, it->lit_it, key);
}

void lod_it_put(const struct lu_env *env, struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.put(env, it->lit_it);
}

int lod_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.next(env, it->lit_it);
}

struct dt_key *lod_it_key(const struct lu_env *env, const struct dt_it *di)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.key(env, it->lit_it);
}

int lod_it_key_size(const struct lu_env *env, const struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.key_size(env, it->lit_it);
}

int lod_it_rec(const struct lu_env *env, const struct dt_it *di,
	       struct dt_rec *rec, __u32 attr)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.rec(env, it->lit_it, rec, attr);
}

__u64 lod_it_store(const struct lu_env *env, const struct dt_it *di)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.store(env, it->lit_it);
}

int lod_it_load(const struct lu_env *env, const struct dt_it *di, __u64 hash)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.load(env, it->lit_it, hash);
}

int lod_it_key_rec(const struct lu_env *env, const struct dt_it *di,
		   void* key_rec)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.key_rec(env, it->lit_it, key_rec);
}

static struct dt_index_operations lod_index_ops = {
	.dio_lookup		= lod_index_lookup,
	.dio_declare_insert	= lod_declare_index_insert,
	.dio_insert		= lod_index_insert,
	.dio_declare_delete	= lod_declare_index_delete,
	.dio_delete		= lod_index_delete,
	.dio_it	= {
		.init		= lod_it_init,
		.fini		= lod_it_fini,
		.get		= lod_it_get,
		.put		= lod_it_put,
		.next		= lod_it_next,
		.key		= lod_it_key,
		.key_size	= lod_it_key_size,
		.rec		= lod_it_rec,
		.store		= lod_it_store,
		.load		= lod_it_load,
		.key_rec	= lod_it_key_rec,
	}
};

static void lod_object_read_lock(const struct lu_env *env,
				 struct dt_object *dt, unsigned role)
{
	dt_read_lock(env, dt_object_child(dt), role);
}

static void lod_object_write_lock(const struct lu_env *env,
				  struct dt_object *dt, unsigned role)
{
	dt_write_lock(env, dt_object_child(dt), role);
}

static void lod_object_read_unlock(const struct lu_env *env,
				   struct dt_object *dt)
{
	dt_read_unlock(env, dt_object_child(dt));
}

static void lod_object_write_unlock(const struct lu_env *env,
				    struct dt_object *dt)
{
	dt_write_unlock(env, dt_object_child(dt));
}

static int lod_object_write_locked(const struct lu_env *env,
				   struct dt_object *dt)
{
	return dt_write_locked(env, dt_object_child(dt));
}

static int lod_attr_get(const struct lu_env *env,
			struct dt_object *dt,
			struct lu_attr *attr,
			struct lustre_capa *capa)
{
	return dt_attr_get(env, dt_object_child(dt), attr, capa);
}

static int lod_declare_attr_set(const struct lu_env *env,
				struct dt_object *dt,
				const struct lu_attr *attr,
				struct thandle *handle)
{
	struct dt_object  *next = dt_object_child(dt);
	struct lod_object *lo = lod_dt_obj(dt);
	int                rc, i;
	ENTRY;

	/*
	 * declare setattr on the local object
	 */
	rc = dt_declare_attr_set(env, next, attr, handle);
	if (rc)
		RETURN(rc);

	/* osp_declare_attr_set() ignores all attributes other than
	 * UID, GID, and size, and osp_attr_set() ignores all but UID
	 * and GID.  Declaration of size attr setting happens through
	 * lod_declare_init_size(), and not through this function.
	 * Therefore we need not load striping unless ownership is
	 * changing.  This should save memory and (we hope) speed up
	 * rename(). */
	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		if (!(attr->la_valid & (LA_UID | LA_GID)))
			RETURN(rc);
	} else {
		if (!(attr->la_valid & (LA_UID | LA_GID | LA_MODE |
					LA_ATIME | LA_MTIME | LA_CTIME)))
			RETURN(rc);
	}
	/*
	 * load striping information, notice we don't do this when object
	 * is being initialized as we don't need this information till
	 * few specific cases like destroy, chown
	 */
	rc = lod_load_striping(env, lo);
	if (rc)
		RETURN(rc);

	if (lo->ldo_stripenr == 0)
		RETURN(0);

	if (!(attr->la_valid & ~(LA_ATIME | LA_MTIME | LA_CTIME))) {
		struct lu_attr	 *la = &lod_env_info(env)->lti_attr;
		bool		 setattr_time = false;

		rc = dt_attr_get(env, dt_object_child(dt), la,
				 BYPASS_CAPA);
		if (rc != 0)
			RETURN(rc);

		/* If it will only setattr time, it will only set
		 * time < current_time */
		if ((attr->la_valid & LA_ATIME &&
		     attr->la_atime < la->la_atime) ||
		    (attr->la_valid & LA_CTIME &&
		     attr->la_ctime < la->la_ctime) ||
		    (attr->la_valid & LA_MTIME &&
		     attr->la_mtime < la->la_mtime))
			setattr_time = true;

		if (!setattr_time)
			RETURN(0);
	}
	/*
	 * if object is striped declare changes on the stripes
	 */
	LASSERT(lo->ldo_stripe);
	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);

		rc = dt_declare_attr_set(env, lo->ldo_stripe[i], attr, handle);
		if (rc) {
			CERROR("failed declaration: %d\n", rc);
			break;
		}
	}

	RETURN(rc);
}

static int lod_attr_set(const struct lu_env *env,
			struct dt_object *dt,
			const struct lu_attr *attr,
			struct thandle *handle,
			struct lustre_capa *capa)
{
	struct dt_object  *next = dt_object_child(dt);
	struct lod_object *lo = lod_dt_obj(dt);
	int                rc, i;
	ENTRY;

	/*
	 * apply changes to the local object
	 */
	rc = dt_attr_set(env, next, attr, handle, capa);
	if (rc)
		RETURN(rc);

	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		if (!(attr->la_valid & (LA_UID | LA_GID)))
			RETURN(rc);
	} else {
		if (!(attr->la_valid & (LA_UID | LA_GID | LA_MODE |
					LA_ATIME | LA_MTIME | LA_CTIME)))
			RETURN(rc);
	}

	if (lo->ldo_stripenr == 0)
		RETURN(0);

	if (!(attr->la_valid & ~(LA_ATIME | LA_MTIME | LA_CTIME))) {
		struct lu_attr	 *la = &lod_env_info(env)->lti_attr;
		bool		 setattr_time = false;

		rc = dt_attr_get(env, dt_object_child(dt), la,
				 BYPASS_CAPA);
		if (rc != 0)
			RETURN(rc);

		/* If it will only setattr time, it will only set
		 * time < current_time */
		if ((attr->la_valid & LA_ATIME &&
		     attr->la_atime < la->la_atime) ||
		    (attr->la_valid & LA_CTIME &&
		     attr->la_atime < la->la_ctime) ||
		    (attr->la_valid & LA_MTIME &&
		     attr->la_atime < la->la_mtime))
			setattr_time = true;

		if (!setattr_time)
			RETURN(0);
	}

	/*
	 * if object is striped, apply changes to all the stripes
	 */
	LASSERT(lo->ldo_stripe);
	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);
		rc = dt_attr_set(env, lo->ldo_stripe[i], attr, handle, capa);
		if (rc) {
			CERROR("failed declaration: %d\n", rc);
			break;
		}
	}

	RETURN(rc);
}

static int lod_xattr_get(const struct lu_env *env, struct dt_object *dt,
			 struct lu_buf *buf, const char *name,
			 struct lustre_capa *capa)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_device	*dev = lu2lod_dev(dt->do_lu.lo_dev);
	int			 rc, is_root;
	ENTRY;

	rc = dt_xattr_get(env, dt_object_child(dt), buf, name, capa);
	if (rc != -ENODATA || !S_ISDIR(dt->do_lu.lo_header->loh_attr & S_IFMT))
		RETURN(rc);

	/*
	 * lod returns default striping on the real root of the device
	 * this is like the root stores default striping for the whole
	 * filesystem. historically we've been using a different approach
	 * and store it in the config.
	 */
	dt_root_get(env, dev->lod_child, &info->lti_fid);
	is_root = lu_fid_eq(&info->lti_fid, lu_object_fid(&dt->do_lu));

	if (is_root && strcmp(XATTR_NAME_LOV, name) == 0) {
		struct lov_user_md *lum = buf->lb_buf;
		struct lov_desc    *desc = &dev->lod_desc;

		if (buf->lb_buf == NULL) {
			rc = sizeof(*lum);
		} else if (buf->lb_len >= sizeof(*lum)) {
			lum->lmm_magic = cpu_to_le32(LOV_USER_MAGIC_V1);
			lmm_oi_set_seq(&lum->lmm_oi, FID_SEQ_LOV_DEFAULT);
			lmm_oi_set_id(&lum->lmm_oi, 0);
			lmm_oi_cpu_to_le(&lum->lmm_oi, &lum->lmm_oi);
			lum->lmm_pattern = cpu_to_le32(desc->ld_pattern);
			lum->lmm_stripe_size = cpu_to_le32(
						desc->ld_default_stripe_size);
			lum->lmm_stripe_count = cpu_to_le16(
						desc->ld_default_stripe_count);
			lum->lmm_stripe_offset = cpu_to_le16(
						desc->ld_default_stripe_offset);
			rc = sizeof(*lum);
		} else {
			rc = -ERANGE;
		}
	}

	RETURN(rc);
}

static int lod_verify_md_striping(struct lod_device *lod,
				  const struct lmv_user_md_v1 *lum)
{
	int	rc = 0;
	ENTRY;

	if (unlikely(le32_to_cpu(lum->lum_magic) != LMV_USER_MAGIC))
		GOTO(out, rc = -EINVAL);

	if (unlikely(le32_to_cpu(lum->lum_stripe_count) == 0))
		GOTO(out, rc = -EINVAL);

	if (unlikely(le32_to_cpu(lum->lum_stripe_count) >
				lod->lod_remote_mdt_count + 1))
		GOTO(out, rc = -EINVAL);
out:
	if (rc != 0)
		CERROR("%s: invalid lmv_user_md: magic = %x, "
		       "stripe_offset = %d, stripe_count = %u: rc = %d\n",
		       lod2obd(lod)->obd_name, le32_to_cpu(lum->lum_magic),
		       (int)le32_to_cpu(lum->lum_stripe_offset),
		       le32_to_cpu(lum->lum_stripe_count), rc);
	return rc;
}

int lod_prep_lmv_md(const struct lu_env *env, struct dt_object *dt,
		    struct lu_buf *lmv_buf)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_device	*lod = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object	*lo = lod_dt_obj(dt);
	struct lmv_mds_md_v1	*lmm1;
	int			stripe_count;
	int			lmm_size;
	int			i;
	int			rc;
	__u32			mdtidx;
	ENTRY;

	LASSERT(lo->ldo_dir_striped != 0);
	LASSERT(lo->ldo_stripenr > 0);
	stripe_count = lo->ldo_stripenr + 1;
	lmm_size = lmv_mds_md_size(stripe_count, LMV_MAGIC);
	if (info->lti_ea_store_size < lmm_size) {
		rc = lod_ea_store_resize(info, lmm_size);
		if (rc != 0)
			RETURN(rc);
	}

	lmm1 = (struct lmv_mds_md_v1 *)info->lti_ea_store;
	lmm1->lmv_magic = cpu_to_le32(LMV_MAGIC);
	lmm1->lmv_stripe_count = cpu_to_le32(stripe_count);
	lmm1->lmv_hash_type = cpu_to_le32(lo->ldo_dir_hash_type);
	rc = lod_fld_lookup(env, lod, lu_object_fid(&dt->do_lu),
			    &mdtidx, LU_SEQ_RANGE_MDT);
	if (rc != 0)
		RETURN(rc);

	lmm1->lmv_master_mdt_index = cpu_to_le32(mdtidx);
	fid_cpu_to_le(&lmm1->lmv_stripe_fids[0], lu_object_fid(&dt->do_lu));
	for (i = 0; i < lo->ldo_stripenr; i++) {
		struct dt_object *dto;

		dto = lo->ldo_stripe[i];
		LASSERT(dto != NULL);
		fid_cpu_to_le(&lmm1->lmv_stripe_fids[i + 1],
			      lu_object_fid(&dto->do_lu));
	}

	lmv_buf->lb_buf = info->lti_ea_store;
	lmv_buf->lb_len = lmm_size;
	lo->ldo_dir_striping_cached = 1;

	RETURN(rc);
}

int lod_parse_dir_striping(const struct lu_env *env, struct lod_object *lo,
			   const struct lu_buf *buf)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_device	*lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct lod_tgt_descs	*ltd = &lod->lod_mdt_descs;
	struct dt_object	**stripe;
	union lmv_mds_md	*lmm = buf->lb_buf;
	struct lmv_mds_md_v1	*lmv1 = &lmm->lmv_md_v1;
	struct lu_fid		*fid = &info->lti_fid;
	int			i;
	int			rc = 0;
	ENTRY;

	if (le32_to_cpu(lmv1->lmv_magic) != LMV_MAGIC_V1)
		RETURN(-EINVAL);

	if (le32_to_cpu(lmv1->lmv_stripe_count) <= 1)
		RETURN(0);

	fid_le_to_cpu(fid, &lmv1->lmv_stripe_fids[0]);
	/* Do not load striping information for slave inode */
	if (!lu_fid_eq(fid, lu_object_fid(&lo->ldo_obj.do_lu))) {
		lo->ldo_dir_slave_stripe = 1;
		RETURN(0);
	}

	LASSERT(lo->ldo_stripe == NULL);
	OBD_ALLOC(stripe, sizeof(stripe[0]) *
		  (le32_to_cpu(lmv1->lmv_stripe_count) - 1));
	if (stripe == NULL)
		RETURN(-ENOMEM);

	/* skip master stripe */
	for (i = 1; i < le32_to_cpu(lmv1->lmv_stripe_count); i++) {
		struct lod_tgt_desc	*tgt;
		int			idx;
		struct dt_object	*dto;

		fid_le_to_cpu(fid, &lmv1->lmv_stripe_fids[i]);
		rc = lod_fld_lookup(env, lod, fid,
				    &idx, LU_SEQ_RANGE_MDT);
		if (rc != 0)
			GOTO(out, rc);

		tgt = LTD_TGT(ltd, idx);
		if (tgt == NULL)
			GOTO(out, rc = -ESTALE);

		dto = dt_locate_at(env, tgt->ltd_tgt, fid,
				  lo->ldo_obj.do_lu.lo_dev->ld_site->ls_top_dev,
				  NULL);
		if (IS_ERR(dto))
			GOTO(out, rc = PTR_ERR(dto));

		stripe[i - 1] = dto;
	}
out:
	lo->ldo_stripe = stripe;
	lo->ldo_stripenr = le32_to_cpu(lmv1->lmv_stripe_count) - 1;
	lo->ldo_stripes_allocated = le32_to_cpu(lmv1->lmv_stripe_count) - 1;
	if (rc != 0)
		lod_object_free_striping(env, lo);

	RETURN(rc);
}

static int lod_prep_md_striped_create(const struct lu_env *env,
				      struct dt_object *dt,
				      struct lu_attr *attr,
				      const struct lmv_user_md_v1 *lum,
				      struct thandle *th)
{
	struct lod_device	*lod = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_tgt_descs	*ltd = &lod->lod_mdt_descs;
	struct lod_object	*lo = lod_dt_obj(dt);
	struct dt_object	**stripe;
	struct lu_buf		lmv_buf;
	int			stripe_count;
	int			*idx_array;
	int			rc = 0;
	int			i;
	int			j;
	ENTRY;

	/* The lum has been verifed in lod_verify_md_striping */
	LASSERT(le32_to_cpu(lum->lum_magic) == LMV_USER_MAGIC);
	LASSERT(le32_to_cpu(lum->lum_stripe_count) > 0);

	/* Do not need allocated master stripe */
	stripe_count = le32_to_cpu(lum->lum_stripe_count);
	OBD_ALLOC(stripe, sizeof(stripe[0]) * (stripe_count - 1));
	if (stripe == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC(idx_array, sizeof(idx_array[0]) * stripe_count);
	if (idx_array == NULL)
		GOTO(out_free, rc = -ENOMEM);

	idx_array[0] = le32_to_cpu(lum->lum_stripe_offset);
	for (i = 1; i < stripe_count; i++) {
		struct lod_tgt_desc	*tgt;
		struct dt_object	*dto;
		struct lu_fid		fid;
		int			idx;
		struct lu_object_conf	conf = { 0 };

		idx = (idx_array[i - 1] + 1) % (lod->lod_remote_mdt_count + 1);

		for (j = 0; j < lod->lod_remote_mdt_count;
		     j++, idx = (idx + 1) % (lod->lod_remote_mdt_count + 1)) {
			bool already_allocated = false;
			int k;

			CDEBUG(D_INFO, "try idx %d, mdt cnt %d,"
			       " allocated %d, last allocated %d\n", idx,
			       lod->lod_remote_mdt_count, i, idx_array[i - 1]);

			/* Find next avaible target */
			if (!cfs_bitmap_check(ltd->ltd_tgt_bitmap, idx))
				continue;

			/* check whether the idx already exists
			 * in current allocated array */
			for (k = 0; k < i; k++) {
				if (idx_array[k] == idx) {
					already_allocated = true;
					break;
				}
			}

			if (already_allocated)
				continue;

			break;
		}

		/* Can not allocate more stripes */
		if (j == lod->lod_remote_mdt_count) {
			CDEBUG(D_INFO, "%s: require stripes %d only get %d\n",
			       lod2obd(lod)->obd_name, stripe_count, i - 1);
			break;
		}

		CDEBUG(D_INFO, "idx %d, mdt cnt %d,"
		       " allocated %d, last allocated %d\n", idx,
		       lod->lod_remote_mdt_count, i, idx_array[i - 1]);

		tgt = LTD_TGT(ltd, idx);
		LASSERT(tgt != NULL);

		rc = obd_fid_alloc(tgt->ltd_exp, &fid, NULL);
		if (rc < 0)
			GOTO(out_put, rc);
		rc = 0;

		conf.loc_flags = LOC_F_NEW;
		dto = dt_locate_at(env, tgt->ltd_tgt, &fid,
				  dt->do_lu.lo_dev->ld_site->ls_top_dev, &conf);
		if (IS_ERR(dto))
			GOTO(out_put, rc = PTR_ERR(dto));
		stripe[i - 1] = dto;
		idx_array[i] = idx;
	}

	lo->ldo_dir_striped = 1;
	lo->ldo_stripe = stripe;
	lo->ldo_stripenr = i - 1;
	lo->ldo_stripes_allocated = stripe_count - 1;

	if (lo->ldo_stripenr == 0)
		GOTO(out_put, rc = -ENOSPC);

	rc = lod_prep_lmv_md(env, dt, &lmv_buf);
	if (rc != 0)
		GOTO(out_put, rc);

	for (i = 0; i < lo->ldo_stripenr; i++) {
		struct dt_object *dto;

		dto = stripe[i];
		/* only create slave striped object */
		rc = dt_declare_create(env, dto, attr, NULL, NULL, th);
		if (rc != 0)
			GOTO(out_put, rc);

		if (!dt_try_as_dir(env, dto))
			GOTO(out_put, rc = -EINVAL);

		rc = dt_declare_insert(env, dto,
		     (const struct dt_rec *)lu_object_fid(&dto->do_lu),
		     (const struct dt_key *)dot, th);
		if (rc != 0)
			GOTO(out_put, rc);

		/* master stripe FID will be put to .. */
		rc = dt_declare_insert(env, dto,
		     (const struct dt_rec *)lu_object_fid(&dt->do_lu),
		     (const struct dt_key *)dotdot, th);
		if (rc != 0)
			GOTO(out_put, rc);

		/* probably nothing to inherite */
		if (lo->ldo_striping_cached &&
		    !LOVEA_DELETE_VALUES(lo->ldo_def_stripe_size,
					 lo->ldo_def_stripenr,
					 lo->ldo_def_stripe_offset)) {
			struct lod_thread_info	*info;
			struct lov_user_md_v3	*v3;

			/* sigh, lti_ea_store has been used for lmv_buf,
			 * so we have to allocate buffer for default
			 * stripe EA */
			OBD_ALLOC_PTR(v3);
			if (v3 == NULL)
				GOTO(out_put, rc = -ENOMEM);

			memset(v3, 0, sizeof(*v3));
			v3->lmm_magic = cpu_to_le32(LOV_USER_MAGIC_V3);
			v3->lmm_stripe_count =
				cpu_to_le32(lo->ldo_def_stripenr);
			v3->lmm_stripe_offset =
				cpu_to_le32(lo->ldo_def_stripe_offset);
			v3->lmm_stripe_size =
				cpu_to_le32(lo->ldo_def_stripe_size);
			if (lo->ldo_pool)
				strncpy(v3->lmm_pool_name, lo->ldo_pool,
					LOV_MAXPOOLNAME);

			info = lod_env_info(env);
			info->lti_buf.lb_buf = v3;
			info->lti_buf.lb_len = sizeof(*v3);
			rc = dt_declare_xattr_set(env, dto,
						  &info->lti_buf,
						  XATTR_NAME_LOV,
						  0, th);
			OBD_FREE_PTR(v3);
			if (rc != 0)
				GOTO(out_put, rc);
		}
		rc = dt_declare_xattr_set(env, dto, &lmv_buf, XATTR_NAME_LMV, 0,
					  th);
		if (rc != 0)
			GOTO(out_put, rc);
	}

	rc = dt_declare_xattr_set(env, dt, &lmv_buf, XATTR_NAME_LMV, 0, th);
	if (rc != 0)
		GOTO(out_put, rc);

out_put:
	if (rc < 0) {
		for (i = 0; i < stripe_count - 1; i++)
			if (stripe[i] != NULL)
				lu_object_put(env, &stripe[i]->do_lu);
		OBD_FREE(stripe, sizeof(stripe[0]) * (stripe_count - 1));
	}

out_free:
	if (idx_array != NULL)
		OBD_FREE(idx_array, sizeof(idx_array[0]) * stripe_count);

	RETURN(rc);
}

/**
 * Declare create striped md object.
 */
static int lod_declare_xattr_set_lmv(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lu_attr *attr,
				     const struct lu_buf *lum_buf,
				     struct thandle *th)
{
	struct lod_object	*lo = lod_dt_obj(dt);
	struct lod_device	*lod = lu2lod_dev(dt->do_lu.lo_dev);
	struct lmv_user_md_v1	*lum;
	int			rc;
	ENTRY;

	lum = lum_buf->lb_buf;
	LASSERT(lum != NULL);

	CDEBUG(D_INFO, "lum magic = %x count = %u offset = %d\n",
	       le32_to_cpu(lum->lum_magic), le32_to_cpu(lum->lum_stripe_count),
	       (int)le32_to_cpu(lum->lum_stripe_offset));

	if (le32_to_cpu(lum->lum_stripe_count) <= 1)
		GOTO(out, rc = 0);

	rc = lod_verify_md_striping(lod, lum);
	if (rc != 0)
		GOTO(out, rc);

	/* prepare dir striped objects */
	rc = lod_prep_md_striped_create(env, dt, attr, lum, th);
	if (rc != 0) {
		/* failed to create striping, let's reset
		 * config so that others don't get confused */
		lod_object_free_striping(env, lo);
		GOTO(out, rc);
	}
out:
	RETURN(rc);
}

/*
 * LOV xattr is a storage for striping, and LOD owns this xattr.
 * but LOD allows others to control striping to some extent
 * - to reset strping
 * - to set new defined striping
 * - to set new semi-defined striping
 *   - number of stripes is defined
 *   - number of stripes + osts are defined
 *   - ??
 */
static int lod_declare_xattr_set(const struct lu_env *env,
				 struct dt_object *dt,
				 const struct lu_buf *buf,
				 const char *name, int fl,
				 struct thandle *th)
{
	struct dt_object *next = dt_object_child(dt);
	struct lu_attr	 *attr = &lod_env_info(env)->lti_attr;
	__u32		  mode;
	int		  rc;
	ENTRY;

	/*
	 * allow to declare predefined striping on a new (!mode) object
	 * which is supposed to be replay of regular file creation
	 * (when LOV setting is declared)
	 * LU_XATTR_REPLACE is set to indicate a layout swap
	 */
	mode = dt->do_lu.lo_header->loh_attr & S_IFMT;
	if ((S_ISREG(mode) || mode == 0) && strcmp(name, XATTR_NAME_LOV) == 0 &&
	     !(fl & LU_XATTR_REPLACE)) {
		/*
		 * this is a request to manipulate object's striping
		 */
		if (dt_object_exists(dt)) {
			rc = dt_attr_get(env, next, attr, BYPASS_CAPA);
			if (rc)
				RETURN(rc);
		} else {
			memset(attr, 0, sizeof(*attr));
			attr->la_valid = LA_TYPE | LA_MODE;
			attr->la_mode = S_IFREG;
		}
		rc = lod_declare_striped_object(env, dt, attr, buf, th);
		if (rc)
			RETURN(rc);
	} else {
		rc = dt_declare_xattr_set(env, next, buf, name, fl, th);
	}

	RETURN(rc);
}

static void lod_lov_stripe_cache_clear(struct lod_object *lo)
{
	lo->ldo_striping_cached = 0;
	lo->ldo_def_striping_set = 0;
	lod_object_set_pool(lo, NULL);
	lo->ldo_def_stripe_size = 0;
	lo->ldo_def_stripenr = 0;
}

static int lod_xattr_set_lov_on_dir(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct lu_buf *buf,
				    const char *name, int fl,
				    struct thandle *th,
				    struct lustre_capa *capa)
{
	struct lod_device	*d = lu2lod_dev(dt->do_lu.lo_dev);
	struct dt_object	*next = dt_object_child(dt);
	struct lod_object	*l = lod_dt_obj(dt);
	struct lov_user_md_v1	*lum;
	struct lov_user_md_v3	*v3 = NULL;
	int			 rc;
	ENTRY;

	/* If it is striped dir, we should clear the stripe cache for
	 * slave stripe as well, but there are no effective way to
	 * notify the LOD on the slave MDT, so we do not cache stripe
	 * information for slave stripe for now. XXX*/
	lod_lov_stripe_cache_clear(l);
	LASSERT(buf != NULL && buf->lb_buf != NULL);
	lum = buf->lb_buf;

	rc = lod_verify_striping(d, buf, 0);
	if (rc)
		RETURN(rc);

	if (lum->lmm_magic == LOV_USER_MAGIC_V3)
		v3 = buf->lb_buf;

	/* if { size, offset, count } = { 0, -1, 0 } and no pool
	 * (i.e. all default values specified) then delete default
	 * striping from dir. */
	CDEBUG(D_OTHER,
		"set default striping: sz %u # %u offset %d %s %s\n",
		(unsigned)lum->lmm_stripe_size,
		(unsigned)lum->lmm_stripe_count,
		(int)lum->lmm_stripe_offset,
		v3 ? "from" : "", v3 ? v3->lmm_pool_name : "");

	if (LOVEA_DELETE_VALUES((lum->lmm_stripe_size),
				(lum->lmm_stripe_count),
				(lum->lmm_stripe_offset)) &&
			lum->lmm_magic == LOV_USER_MAGIC_V1) {
		rc = dt_xattr_del(env, next, name, th, capa);
		if (rc == -ENODATA)
			rc = 0;
	} else {
		rc = dt_xattr_set(env, next, buf, name, fl, th, capa);
	}

	RETURN(rc);
}

static int lod_xattr_set_lmv(const struct lu_env *env, struct dt_object *dt,
			     const struct lu_buf *buf, const char *name,
			     int fl, struct thandle *th,
			     struct lustre_capa *capa)
{
	struct lod_object	*lo = lod_dt_obj(dt);
	struct lu_buf		lmv_buf;
	int			i;
	int			rc;
	ENTRY;

	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(-ENOTDIR);

	/* The stripes are supposed to be allocated in declare phase,
	 * if there are no stripes being allocated, it will skip */
	if (lo->ldo_stripenr == 0)
		RETURN(0);

	rc = lod_prep_lmv_md(env, dt, &lmv_buf);
	if (rc != 0)
		RETURN(rc);

	for (i = 0; i < lo->ldo_stripenr; i++) {
		struct dt_object *dto;
		struct lu_attr	*attr = &lod_env_info(env)->lti_attr;

		dto = lo->ldo_stripe[i];
		memset(attr, 0, sizeof(*attr));
		attr->la_valid = LA_TYPE | LA_MODE;
		attr->la_mode = S_IFDIR;
		rc = dt_create(env, dto, attr, NULL, NULL, th);
		if (rc != 0)
			RETURN(rc);

		rc = dt_insert(env, dto,
			      (const struct dt_rec *)lu_object_fid(&dto->do_lu),
			      (const struct dt_key *)dot, th, capa, 0);
		if (rc != 0)
			RETURN(rc);

		rc = dt_insert(env, dto,
			      (struct dt_rec *)lu_object_fid(&dt->do_lu),
			      (const struct dt_key *)dotdot, th, capa, 0);
		if (rc != 0)
			RETURN(rc);

		if (lo->ldo_striping_cached &&
		    !LOVEA_DELETE_VALUES(lo->ldo_def_stripe_size,
					 lo->ldo_def_stripenr,
					 lo->ldo_def_stripe_offset)) {
			struct lod_thread_info	*info;
			struct lov_user_md_v3	*v3;

			/* sigh, lti_ea_store has been used for lmv_buf,
			 * so we have to allocate buffer for default
			 * stripe EA */
			OBD_ALLOC_PTR(v3);
			if (v3 == NULL)
				RETURN(-ENOMEM);

			memset(v3, 0, sizeof(*v3));
			v3->lmm_magic = cpu_to_le32(LOV_USER_MAGIC_V3);
			v3->lmm_stripe_count =
				cpu_to_le32(lo->ldo_def_stripenr);
			v3->lmm_stripe_offset =
				cpu_to_le32(lo->ldo_def_stripe_offset);
			v3->lmm_stripe_size =
				cpu_to_le32(lo->ldo_def_stripe_size);
			if (lo->ldo_pool)
				strncpy(v3->lmm_pool_name, lo->ldo_pool,
					LOV_MAXPOOLNAME);

			info = lod_env_info(env);
			info->lti_buf.lb_buf = v3;
			info->lti_buf.lb_len = sizeof(*v3);
			rc = dt_xattr_set(env, dto, &info->lti_buf,
					  XATTR_NAME_LOV, 0, th, capa);
			OBD_FREE_PTR(v3);
			if (rc != 0)
				RETURN(rc);
		}

		rc = dt_xattr_set(env, dto, &lmv_buf, XATTR_NAME_LMV, fl, th,
				  capa);
	}

	rc = dt_xattr_set(env, dt, &lmv_buf, XATTR_NAME_LMV, fl, th, capa);

	RETURN(rc);
}

static int lod_xattr_set(const struct lu_env *env,
			 struct dt_object *dt, const struct lu_buf *buf,
			 const char *name, int fl, struct thandle *th,
			 struct lustre_capa *capa)
{
	struct dt_object	*next = dt_object_child(dt);
	__u32			 attr;
	int			 rc;
	ENTRY;

	attr = dt->do_lu.lo_header->loh_attr & S_IFMT;
	if (S_ISDIR(attr) && strcmp(name, XATTR_NAME_LOV) == 0) {
		rc = lod_xattr_set_lov_on_dir(env, dt, buf, name, fl, th, capa);
	} else if (S_ISREG(attr) && !strcmp(name, XATTR_NAME_LOV)) {
		/* in case of lov EA swap, just set it
		 * if not, it is a replay so check striping match what we
		 * already have during req replay, declare_xattr_set()
		 * defines striping, then create() does the work
		*/
		if (fl & LU_XATTR_REPLACE) {
			/* free stripes, then update disk */
			lod_object_free_striping(env, lod_dt_obj(dt));
			rc = dt_xattr_set(env, next, buf, name, fl, th, capa);
		} else {
			rc = lod_striping_create(env, dt, NULL, NULL, th);
		}
		RETURN(rc);
	} else {
		/*
		 * behave transparantly for all other EAs
		 */
		rc = dt_xattr_set(env, next, buf, name, fl, th, capa);
	}

	RETURN(rc);
}

static int lod_declare_xattr_del(const struct lu_env *env,
				 struct dt_object *dt, const char *name,
				 struct thandle *th)
{
	return dt_declare_xattr_del(env, dt_object_child(dt), name, th);
}

static int lod_xattr_del(const struct lu_env *env, struct dt_object *dt,
			 const char *name, struct thandle *th,
			 struct lustre_capa *capa)
{
	if (!strcmp(name, XATTR_NAME_LOV))
		lod_object_free_striping(env, lod_dt_obj(dt));
	return dt_xattr_del(env, dt_object_child(dt), name, th, capa);
}

static int lod_xattr_list(const struct lu_env *env,
			  struct dt_object *dt, struct lu_buf *buf,
			  struct lustre_capa *capa)
{
	return dt_xattr_list(env, dt_object_child(dt), buf, capa);
}

int lod_object_set_pool(struct lod_object *o, char *pool)
{
	int len;

	if (o->ldo_pool) {
		len = strlen(o->ldo_pool);
		OBD_FREE(o->ldo_pool, len + 1);
		o->ldo_pool = NULL;
	}
	if (pool) {
		len = strlen(pool);
		OBD_ALLOC(o->ldo_pool, len + 1);
		if (o->ldo_pool == NULL)
			return -ENOMEM;
		strcpy(o->ldo_pool, pool);
	}
	return 0;
}

static inline int lod_object_will_be_striped(int is_reg, const struct lu_fid *fid)
{
	return (is_reg && fid_seq(fid) != FID_SEQ_LOCAL_FILE);
}


static int lod_cache_parent_lov_striping(const struct lu_env *env,
					 struct lod_object *lp)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lov_user_md_v1	*v1 = NULL;
	struct lov_user_md_v3	*v3 = NULL;
	int			 rc;
	ENTRY;

	/* called from MDD without parent being write locked,
	 * lock it here */
	dt_write_lock(env, dt_object_child(&lp->ldo_obj), 0);
	rc = lod_get_lov_ea(env, lp);
	if (rc < 0)
		GOTO(unlock, rc);

	if (rc < sizeof(struct lov_user_md)) {
		/* don't lookup for non-existing or invalid striping */
		lp->ldo_def_striping_set = 0;
		lp->ldo_striping_cached = 1;
		lp->ldo_def_stripe_size = 0;
		lp->ldo_def_stripenr = 0;
		lp->ldo_def_stripe_offset = (typeof(v1->lmm_stripe_offset))(-1);
		GOTO(unlock, rc = 0);
	}

	rc = 0;
	v1 = info->lti_ea_store;
	if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_V1))
		lustre_swab_lov_user_md_v1(v1);
	else if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_V3))
		lustre_swab_lov_user_md_v3(v3);

	if (v1->lmm_magic != LOV_MAGIC_V3 && v1->lmm_magic != LOV_MAGIC_V1)
		GOTO(unlock, rc = 0);

	if (v1->lmm_pattern != LOV_PATTERN_RAID0 && v1->lmm_pattern != 0)
		GOTO(unlock, rc = 0);

	lp->ldo_def_stripenr = v1->lmm_stripe_count;
	lp->ldo_def_stripe_size = v1->lmm_stripe_size;
	lp->ldo_def_stripe_offset = v1->lmm_stripe_offset;
	lp->ldo_striping_cached = 1;
	lp->ldo_def_striping_set = 1;
	if (v1->lmm_magic == LOV_USER_MAGIC_V3) {
		/* XXX: sanity check here */
		v3 = (struct lov_user_md_v3 *) v1;
		if (v3->lmm_pool_name[0])
			lod_object_set_pool(lp, v3->lmm_pool_name);
	}
	EXIT;
unlock:
	dt_write_unlock(env, dt_object_child(&lp->ldo_obj));
	return rc;
}


static int lod_cache_parent_lmv_striping(const struct lu_env *env,
					 struct lod_object *lp)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lmv_user_md_v1	*v1 = NULL;
	int			 rc;
	ENTRY;

	/* called from MDD without parent being write locked,
	 * lock it here */
	dt_write_lock(env, dt_object_child(&lp->ldo_obj), 0);
	rc = lod_get_default_lmv_ea(env, lp);
	if (rc < 0)
		GOTO(unlock, rc);

	if (rc < sizeof(struct lmv_user_md)) {
		/* don't lookup for non-existing or invalid striping */
		lp->ldo_dir_def_striping_set = 0;
		lp->ldo_dir_striping_cached = 1;
		lp->ldo_dir_def_stripenr = 0;
		lp->ldo_dir_def_stripe_offset =
					(typeof(v1->lum_stripe_offset))(-1);
		lp->ldo_dir_def_hash_type = LMV_HASH_TYPE_FNV_1A_64;
		GOTO(unlock, rc = 0);
	}

	rc = 0;
	v1 = info->lti_ea_store;

	lp->ldo_dir_def_stripenr = le32_to_cpu(v1->lum_stripe_count) - 1;
	lp->ldo_dir_def_stripe_offset = le32_to_cpu(v1->lum_stripe_offset);
	lp->ldo_dir_def_hash_type = le32_to_cpu(v1->lum_hash_type);
	lp->ldo_dir_def_striping_set = 1;
	lp->ldo_dir_striping_cached = 1;

	EXIT;
unlock:
	dt_write_unlock(env, dt_object_child(&lp->ldo_obj));
	return rc;
}

static int lod_cache_parent_striping(const struct lu_env *env,
				     struct lod_object *lp,
				     umode_t child_mode)
{
	int rc = 0;
	ENTRY;

	rc = lod_load_striping(env, lp);
	if (rc != 0)
		RETURN(rc);

	if (!lp->ldo_striping_cached) {
		/* we haven't tried to get default striping for
		 * the directory yet, let's cache it in the object */
		rc = lod_cache_parent_lov_striping(env, lp);
		if (rc != 0)
			RETURN(rc);
	}

	if (S_ISDIR(child_mode) && !lp->ldo_dir_striping_cached)
		rc = lod_cache_parent_lmv_striping(env, lp);

	RETURN(rc);
}

/**
 * used to transfer default striping data to the object being created
 */
static void lod_ah_init(const struct lu_env *env,
			struct dt_allocation_hint *ah,
			struct dt_object *parent,
			struct dt_object *child,
			umode_t child_mode)
{
	struct lod_device *d = lu2lod_dev(child->do_lu.lo_dev);
	struct dt_object  *nextp = NULL;
	struct dt_object  *nextc;
	struct lod_object *lp = NULL;
	struct lod_object *lc;
	struct lov_desc   *desc;
	ENTRY;

	LASSERT(child);

	if (likely(parent)) {
		nextp = dt_object_child(parent);
		lp = lod_dt_obj(parent);
	}

	nextc = dt_object_child(child);
	lc = lod_dt_obj(child);

	LASSERT(lc->ldo_stripenr == 0);
	LASSERT(lc->ldo_stripe == NULL);

	/*
	 * local object may want some hints
	 * in case of late striping creation, ->ah_init()
	 * can be called with local object existing
	 */
	if (!dt_object_exists(nextc) || dt_object_remote(nextc))
		nextc->do_ops->do_ah_init(env, ah, dt_object_remote(nextp) ?
					  NULL : nextp, nextc, child_mode);

	if (S_ISDIR(child_mode)) {
		int rc;

		if (lc->ldo_dir_stripe == NULL) {
			OBD_ALLOC_PTR(lc->ldo_dir_stripe);
			if (lc->ldo_dir_stripe == NULL)
				return;
		}

		if (lp->ldo_dir_stripe == NULL) {
			OBD_ALLOC_PTR(lp->ldo_dir_stripe);
			if (lp->ldo_dir_stripe == NULL)
				return;
		}

		rc = lod_cache_parent_striping(env, lp, child_mode);
		if (rc != 0)
			return;

		/* transfer defaults to new directory */
		if (lp->ldo_striping_cached) {
			if (lp->ldo_pool)
				lod_object_set_pool(lc, lp->ldo_pool);
			lc->ldo_def_stripenr = lp->ldo_def_stripenr;
			lc->ldo_def_stripe_size = lp->ldo_def_stripe_size;
			lc->ldo_def_stripe_offset = lp->ldo_def_stripe_offset;
			lc->ldo_striping_cached = 1;
			lc->ldo_def_striping_set = 1;
			CDEBUG(D_OTHER, "inherite EA sz:%d off:%d nr:%d\n",
			       (int)lc->ldo_def_stripe_size,
			       (int)lc->ldo_def_stripe_offset,
			       (int)lc->ldo_def_stripenr);
		}

		/* transfer dir defaults to new directory */
		if (lp->ldo_dir_striping_cached) {
			lc->ldo_dir_def_stripenr = lp->ldo_dir_def_stripenr;
			lc->ldo_dir_def_stripe_offset =
						  lp->ldo_dir_def_stripe_offset;
			lc->ldo_dir_def_hash_type =
						  lp->ldo_dir_def_hash_type;
			lc->ldo_dir_striping_cached = 1;
			lc->ldo_dir_def_striping_set = 1;
			CDEBUG(D_INFO, "inherit default EA nr:%d off:%d t%u\n",
			       (int)lc->ldo_dir_def_stripenr,
			       (int)lc->ldo_dir_def_stripe_offset,
			       lc->ldo_dir_def_hash_type);
		}

		/* If the directory is specified with certain stripes */
		if (ah->dah_eadata != NULL && ah->dah_eadata_len != 0) {
			const struct lmv_user_md_v1 *lum1 = ah->dah_eadata;
			int rc;

			rc = lod_verify_md_striping(d, lum1);
			if (rc == 0 &&
				le32_to_cpu(lum1->lum_stripe_count) > 1) {
				/* Directory will be striped only if
				 * stripe_count > 1 */
				lc->ldo_stripenr =
					le32_to_cpu(lum1->lum_stripe_count) - 1;
				lc->ldo_dir_stripe_offset =
					le32_to_cpu(lum1->lum_stripe_offset);
				lc->ldo_dir_hash_type =
					le32_to_cpu(lum1->lum_hash_type);
				CDEBUG(D_INFO, "set stripe EA nr:%hu off:%d\n",
				       lc->ldo_stripenr,
				       (int)lc->ldo_dir_stripe_offset);
			}
		} else if (lp->ldo_dir_def_striping_set) {
			/* If there are default dir stripe from parent */
			lc->ldo_stripenr = lp->ldo_dir_def_stripenr;
			lc->ldo_dir_stripe_offset =
					lp->ldo_dir_def_stripe_offset;
			lc->ldo_dir_hash_type =
					lp->ldo_dir_def_hash_type;
			CDEBUG(D_INFO, "inherit EA nr:%hu off:%d\n",
			       lc->ldo_stripenr,
			       (int)lc->ldo_dir_stripe_offset);
		} else {
			/* set default stripe for this directory */
			lc->ldo_stripenr = 0;
			lc->ldo_dir_stripe_offset = -1;
		}

		CDEBUG(D_INFO, "final striping count:%hu, offset:%d\n",
		       lc->ldo_stripenr, (int)lc->ldo_dir_stripe_offset);

		goto out;
	}

	/*
	 * if object is going to be striped over OSTs, transfer default
	 * striping information to the child, so that we can use it
	 * during declaration and creation
	 */
	if (!lod_object_will_be_striped(S_ISREG(child_mode),
					lu_object_fid(&child->do_lu)))
		goto out;
	/*
	 * try from the parent
	 */
	if (likely(parent)) {
		lod_cache_parent_striping(env, lp, child_mode);

		lc->ldo_def_stripe_offset = (__u16) -1;

		if (lp->ldo_def_striping_set) {
			if (lp->ldo_pool)
				lod_object_set_pool(lc, lp->ldo_pool);
			lc->ldo_stripenr = lp->ldo_def_stripenr;
			lc->ldo_stripe_size = lp->ldo_def_stripe_size;
			lc->ldo_def_stripe_offset = lp->ldo_def_stripe_offset;
			CDEBUG(D_OTHER, "striping from parent: #%d, sz %d %s\n",
			       lc->ldo_stripenr, lc->ldo_stripe_size,
			       lp->ldo_pool ? lp->ldo_pool : "");
		}
	}

	/*
	 * if the parent doesn't provide with specific pattern, grab fs-wide one
	 */
	desc = &d->lod_desc;
	if (lc->ldo_stripenr == 0)
		lc->ldo_stripenr = desc->ld_default_stripe_count;
	if (lc->ldo_stripe_size == 0)
		lc->ldo_stripe_size = desc->ld_default_stripe_size;
	CDEBUG(D_OTHER, "final striping: # %d stripes, sz %d from %s\n",
	       lc->ldo_stripenr, lc->ldo_stripe_size,
	       lc->ldo_pool ? lc->ldo_pool : "");

out:
	/* we do not cache stripe information for slave stripe, see
	 * lod_xattr_set_lov_on_dir */
	if (lp != NULL && lp->ldo_dir_slave_stripe)
		lod_lov_stripe_cache_clear(lp);

	EXIT;
}

#define ll_do_div64(aaa,bbb)    do_div((aaa), (bbb))
/*
 * this function handles a special case when truncate was done
 * on a stripeless object and now striping is being created
 * we can't lose that size, so we have to propagate it to newly
 * created object
 */
static int lod_declare_init_size(const struct lu_env *env,
				 struct dt_object *dt, struct thandle *th)
{
	struct dt_object   *next = dt_object_child(dt);
	struct lod_object  *lo = lod_dt_obj(dt);
	struct lu_attr	   *attr = &lod_env_info(env)->lti_attr;
	uint64_t	    size, offs;
	int		    rc, stripe;
	ENTRY;

	/* XXX: we support the simplest (RAID0) striping so far */
	LASSERT(lo->ldo_stripe || lo->ldo_stripenr == 0);
	LASSERT(lo->ldo_stripe_size > 0);

	rc = dt_attr_get(env, next, attr, BYPASS_CAPA);
	LASSERT(attr->la_valid & LA_SIZE);
	if (rc)
		RETURN(rc);

	size = attr->la_size;
	if (size == 0)
		RETURN(0);

	/* ll_do_div64(a, b) returns a % b, and a = a / b */
	ll_do_div64(size, (__u64) lo->ldo_stripe_size);
	stripe = ll_do_div64(size, (__u64) lo->ldo_stripenr);

	size = size * lo->ldo_stripe_size;
	offs = attr->la_size;
	size += ll_do_div64(offs, lo->ldo_stripe_size);

	attr->la_valid = LA_SIZE;
	attr->la_size = size;

	rc = dt_declare_attr_set(env, lo->ldo_stripe[stripe], attr, th);

	RETURN(rc);
}

/**
 * Create declaration of striped object
 */
int lod_declare_striped_object(const struct lu_env *env, struct dt_object *dt,
			       struct lu_attr *attr,
			       const struct lu_buf *lovea, struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct dt_object	*next = dt_object_child(dt);
	struct lod_object	*lo = lod_dt_obj(dt);
	int			 rc;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_ALLOC_OBDO)) {
		/* failed to create striping, let's reset
		 * config so that others don't get confused */
		lod_object_free_striping(env, lo);
		GOTO(out, rc = -ENOMEM);
	}

	/* choose OST and generate appropriate objects */
	rc = lod_qos_prep_create(env, lo, attr, lovea, th);
	if (rc) {
		/* failed to create striping, let's reset
		 * config so that others don't get confused */
		lod_object_free_striping(env, lo);
		GOTO(out, rc);
	}

	/*
	 * declare storage for striping data
	 */
	info->lti_buf.lb_len = lov_mds_md_size(lo->ldo_stripenr,
				lo->ldo_pool ?  LOV_MAGIC_V3 : LOV_MAGIC_V1);
	rc = dt_declare_xattr_set(env, next, &info->lti_buf, XATTR_NAME_LOV,
				  0, th);
	if (rc)
		GOTO(out, rc);

	/*
	 * if striping is created with local object's size > 0,
	 * we have to propagate this size to specific object
	 * the case is possible only when local object was created previously
	 */
	if (dt_object_exists(next))
		rc = lod_declare_init_size(env, dt, th);

out:
	RETURN(rc);
}

int lod_dir_striping_create_internal(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lu_attr *attr,
				     const struct dt_object_format *dof,
				     struct thandle *th,
				     bool declare)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct dt_object	*next = dt_object_child(dt);
	struct lod_object	*lo = lod_dt_obj(dt);
	int			rc;
	ENTRY;

	if (lo->ldo_dir_def_striping_set &&
	    !LMVEA_DELETE_VALUES(lo->ldo_stripenr,
				 lo->ldo_dir_stripe_offset)) {
		struct lmv_user_md_v1 *v1 = info->lti_ea_store;
		int stripe_count = lo->ldo_stripenr + 1;

		if (info->lti_ea_store_size < sizeof(*v1)) {
			rc = lod_ea_store_resize(info, sizeof(*v1));
			if (rc != 0)
				RETURN(rc);
			v1 = info->lti_ea_store;
		}

		memset(v1, 0, sizeof(*v1));
		v1->lum_magic = cpu_to_le32(LMV_USER_MAGIC);
		v1->lum_stripe_count = cpu_to_le32(stripe_count);
		v1->lum_stripe_offset =
				cpu_to_le32(lo->ldo_dir_stripe_offset);

		info->lti_buf.lb_buf = v1;
		info->lti_buf.lb_len = sizeof(*v1);

		if (declare)
			rc = lod_declare_xattr_set_lmv(env, dt, attr,
						       &info->lti_buf, th);
		else
			rc = lod_xattr_set_lmv(env, dt, &info->lti_buf,
					       XATTR_NAME_LMV, 0, th,
					       BYPASS_CAPA);
		if (rc != 0)
			RETURN(rc);
	}

	/* Transfer default LMV striping from the parent */
	if (lo->ldo_dir_striping_cached &&
	    !LMVEA_DELETE_VALUES(lo->ldo_dir_def_stripenr,
				 lo->ldo_dir_def_stripe_offset)) {
		struct lmv_user_md_v1 *v1 = info->lti_ea_store;
		int def_stripe_count = lo->ldo_dir_def_stripenr + 1;

		if (info->lti_ea_store_size < sizeof(*v1)) {
			rc = lod_ea_store_resize(info, sizeof(*v1));
			if (rc != 0)
				RETURN(rc);
			v1 = info->lti_ea_store;
		}

		memset(v1, 0, sizeof(*v1));
		v1->lum_magic = cpu_to_le32(LMV_USER_MAGIC);
		v1->lum_stripe_count = cpu_to_le32(def_stripe_count);
		v1->lum_stripe_offset =
				cpu_to_le32(lo->ldo_dir_def_stripe_offset);
		v1->lum_hash_type =
				cpu_to_le32(lo->ldo_dir_def_hash_type);

		info->lti_buf.lb_buf = v1;
		info->lti_buf.lb_len = sizeof(*v1);
		if (declare)
			rc = dt_declare_xattr_set(env, next, &info->lti_buf,
						  XATTR_NAME_DEFALT_LMV, 0,
						  th);
		else
			rc = dt_xattr_set(env, next, &info->lti_buf,
					   XATTR_NAME_DEFALT_LMV, 0, th,
					   BYPASS_CAPA);
		if (rc != 0)
			RETURN(rc);
	}

	/* Transfer default LOV striping from the parent */
	if (lo->ldo_striping_cached &&
	    !LOVEA_DELETE_VALUES(lo->ldo_def_stripe_size,
				 lo->ldo_def_stripenr,
				 lo->ldo_def_stripe_offset)) {
		struct lov_user_md_v3 *v3 = info->lti_ea_store;

		if (info->lti_ea_store_size < sizeof(*v3)) {
			rc = lod_ea_store_resize(info, sizeof(*v3));
			if (rc != 0)
				RETURN(rc);
			v3 = info->lti_ea_store;
		}

		memset(v3, 0, sizeof(*v3));
		v3->lmm_magic = cpu_to_le32(LOV_USER_MAGIC_V3);
		v3->lmm_stripe_count = cpu_to_le16(lo->ldo_def_stripenr);
		v3->lmm_stripe_offset = cpu_to_le16(lo->ldo_def_stripe_offset);
		v3->lmm_stripe_size = cpu_to_le32(lo->ldo_def_stripe_size);
		if (lo->ldo_pool)
			strncpy(v3->lmm_pool_name, lo->ldo_pool,
				LOV_MAXPOOLNAME);

		info->lti_buf.lb_buf = v3;
		info->lti_buf.lb_len = sizeof(*v3);

		if (declare)
			rc = dt_declare_xattr_set(env, next, &info->lti_buf,
						  XATTR_NAME_LOV, 0, th);
		else
			rc = dt_xattr_set(env, next, &info->lti_buf,
					  XATTR_NAME_LOV, 0, th,
					  BYPASS_CAPA);
		if (rc != 0)
			RETURN(rc);
	}

	RETURN(0);
}

static int lod_declare_dir_striping_create(const struct lu_env *env,
					   struct dt_object *dt,
					   struct lu_attr *attr,
					   struct dt_object_format *dof,
					   struct thandle *th)
{
	return lod_dir_striping_create_internal(env, dt, attr, dof, th, true);
}

static int lod_dir_striping_create(const struct lu_env *env,
				   struct dt_object *dt,
				   struct lu_attr *attr,
				   struct dt_object_format *dof,
				   struct thandle *th)
{
	return lod_dir_striping_create_internal(env, dt, attr, dof, th, false);
}

static int lod_declare_object_create(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lu_attr *attr,
				     struct dt_allocation_hint *hint,
				     struct dt_object_format *dof,
				     struct thandle *th)
{
	struct dt_object   *next = dt_object_child(dt);
	struct lod_object  *lo = lod_dt_obj(dt);
	int		    rc;
	ENTRY;

	LASSERT(dof);
	LASSERT(attr);
	LASSERT(th);

	/*
	 * first of all, we declare creation of local object
	 */
	rc = dt_declare_create(env, next, attr, hint, dof, th);
	if (rc)
		GOTO(out, rc);

	if (dof->dof_type == DFT_SYM)
		dt->do_body_ops = &lod_body_lnk_ops;

	/*
	 * it's lod_ah_init() who has decided the object will striped
	 */
	if (dof->dof_type == DFT_REGULAR) {
		/* callers don't want stripes */
		/* XXX: all tricky interactions with ->ah_make_hint() decided
		 * to use striping, then ->declare_create() behaving differently
		 * should be cleaned */
		if (dof->u.dof_reg.striped == 0)
			lo->ldo_stripenr = 0;
		if (lo->ldo_stripenr > 0)
			rc = lod_declare_striped_object(env, dt, attr,
							NULL, th);
	} else if (dof->dof_type == DFT_DIR) {
		rc = lod_declare_dir_striping_create(env, dt, attr, dof, th);
	}
out:
	RETURN(rc);
}

int lod_striping_create(const struct lu_env *env, struct dt_object *dt,
			struct lu_attr *attr, struct dt_object_format *dof,
			struct thandle *th)
{
	struct lod_object *lo = lod_dt_obj(dt);
	int		   rc = 0, i;
	ENTRY;

	LASSERT(lo->ldo_striping_cached == 0);

	/* create all underlying objects */
	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);
		rc = dt_create(env, lo->ldo_stripe[i], attr, NULL, dof, th);

		if (rc)
			break;
	}
	if (rc == 0)
		rc = lod_generate_and_set_lovea(env, lo, th);

	RETURN(rc);
}

static int lod_object_create(const struct lu_env *env, struct dt_object *dt,
			     struct lu_attr *attr,
			     struct dt_allocation_hint *hint,
			     struct dt_object_format *dof, struct thandle *th)
{
	struct dt_object   *next = dt_object_child(dt);
	struct lod_object  *lo = lod_dt_obj(dt);
	int		    rc;
	ENTRY;

	/* create local object */
	rc = dt_create(env, next, attr, hint, dof, th);

	if (rc == 0) {
		if (S_ISDIR(dt->do_lu.lo_header->loh_attr))
			rc = lod_dir_striping_create(env, dt, attr, dof, th);
		else if (lo->ldo_stripe && dof->u.dof_reg.striped != 0)
			rc = lod_striping_create(env, dt, attr, dof, th);
	}

	RETURN(rc);
}

static int lod_declare_object_destroy(const struct lu_env *env,
				      struct dt_object *dt,
				      struct thandle *th)
{
	struct dt_object   *next = dt_object_child(dt);
	struct lod_object  *lo = lod_dt_obj(dt);
	int		    rc, i;
	ENTRY;

	/*
	 * we declare destroy for the local object
	 */
	rc = dt_declare_destroy(env, next, th);
	if (rc)
		RETURN(rc);

	/*
	 * load striping information, notice we don't do this when object
	 * is being initialized as we don't need this information till
	 * few specific cases like destroy, chown
	 */
	rc = lod_load_striping(env, lo);
	if (rc)
		RETURN(rc);

	/* declare destroy for all underlying objects */
	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);
		rc = dt_declare_destroy(env, lo->ldo_stripe[i], th);

		if (rc)
			break;
	}

	RETURN(rc);
}

static int lod_object_destroy(const struct lu_env *env,
		struct dt_object *dt, struct thandle *th)
{
	struct dt_object  *next = dt_object_child(dt);
	struct lod_object *lo = lod_dt_obj(dt);
	int                rc, i;
	ENTRY;

	/* destroy local object */
	rc = dt_destroy(env, next, th);
	if (rc)
		RETURN(rc);

	/* destroy all underlying objects */
	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);
		rc = dt_destroy(env, lo->ldo_stripe[i], th);
		if (rc)
			break;
	}

	RETURN(rc);
}

static int lod_index_try(const struct lu_env *env, struct dt_object *dt,
			 const struct dt_index_features *feat)
{
	struct dt_object *next = dt_object_child(dt);
	int		  rc;
	ENTRY;

	LASSERT(next->do_ops);
	LASSERT(next->do_ops->do_index_try);

	rc = next->do_ops->do_index_try(env, next, feat);
	if (next->do_index_ops && dt->do_index_ops == NULL)
		dt->do_index_ops = &lod_index_ops;

	RETURN(rc);
}

static int lod_declare_ref_add(const struct lu_env *env,
			       struct dt_object *dt, struct thandle *th)
{
	return dt_declare_ref_add(env, dt_object_child(dt), th);
}

static int lod_ref_add(const struct lu_env *env,
		       struct dt_object *dt, struct thandle *th)
{
	return dt_ref_add(env, dt_object_child(dt), th);
}

static int lod_declare_ref_del(const struct lu_env *env,
			       struct dt_object *dt, struct thandle *th)
{
	return dt_declare_ref_del(env, dt_object_child(dt), th);
}

static int lod_ref_del(const struct lu_env *env,
		       struct dt_object *dt, struct thandle *th)
{
	return dt_ref_del(env, dt_object_child(dt), th);
}

static struct obd_capa *lod_capa_get(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lustre_capa *old, __u64 opc)
{
	return dt_capa_get(env, dt_object_child(dt), old, opc);
}

static int lod_object_sync(const struct lu_env *env, struct dt_object *dt)
{
	return dt_object_sync(env, dt_object_child(dt));
}

static int lod_object_lock(const struct lu_env *env,
			   struct dt_object *dt, struct lustre_handle *lh,
			   struct ldlm_enqueue_info *einfo,
			   void *policy)
{
	struct dt_object   *next = dt_object_child(dt);
	int		 rc;
	ENTRY;

	/*
	 * declare setattr on the local object
	 */
	rc = dt_object_lock(env, next, lh, einfo, policy);

	RETURN(rc);
}

struct dt_object_operations lod_obj_ops = {
	.do_read_lock		= lod_object_read_lock,
	.do_write_lock		= lod_object_write_lock,
	.do_read_unlock		= lod_object_read_unlock,
	.do_write_unlock	= lod_object_write_unlock,
	.do_write_locked	= lod_object_write_locked,
	.do_attr_get		= lod_attr_get,
	.do_declare_attr_set	= lod_declare_attr_set,
	.do_attr_set		= lod_attr_set,
	.do_xattr_get		= lod_xattr_get,
	.do_declare_xattr_set	= lod_declare_xattr_set,
	.do_xattr_set		= lod_xattr_set,
	.do_declare_xattr_del	= lod_declare_xattr_del,
	.do_xattr_del		= lod_xattr_del,
	.do_xattr_list		= lod_xattr_list,
	.do_ah_init		= lod_ah_init,
	.do_declare_create	= lod_declare_object_create,
	.do_create		= lod_object_create,
	.do_declare_destroy	= lod_declare_object_destroy,
	.do_destroy		= lod_object_destroy,
	.do_index_try		= lod_index_try,
	.do_declare_ref_add	= lod_declare_ref_add,
	.do_ref_add		= lod_ref_add,
	.do_declare_ref_del	= lod_declare_ref_del,
	.do_ref_del		= lod_ref_del,
	.do_capa_get		= lod_capa_get,
	.do_object_sync		= lod_object_sync,
	.do_object_lock		= lod_object_lock,
};

static ssize_t lod_read(const struct lu_env *env, struct dt_object *dt,
			struct lu_buf *buf, loff_t *pos,
			struct lustre_capa *capa)
{
	struct dt_object *next = dt_object_child(dt);
        return next->do_body_ops->dbo_read(env, next, buf, pos, capa);
}

static ssize_t lod_declare_write(const struct lu_env *env,
				 struct dt_object *dt,
				 const loff_t size, loff_t pos,
				 struct thandle *th)
{
	return dt_declare_record_write(env, dt_object_child(dt),
				       size, pos, th);
}

static ssize_t lod_write(const struct lu_env *env, struct dt_object *dt,
			 const struct lu_buf *buf, loff_t *pos,
			 struct thandle *th, struct lustre_capa *capa, int iq)
{
	struct dt_object *next = dt_object_child(dt);
	LASSERT(next);
	return next->do_body_ops->dbo_write(env, next, buf, pos, th, capa, iq);
}

static const struct dt_body_operations lod_body_lnk_ops = {
	.dbo_read		= lod_read,
	.dbo_declare_write	= lod_declare_write,
	.dbo_write		= lod_write
};

static int lod_object_init(const struct lu_env *env, struct lu_object *o,
			   const struct lu_object_conf *conf)
{
	struct lod_device *d = lu2lod_dev(o->lo_dev);
	struct lu_object  *below;
	struct lu_device  *under;
	ENTRY;

	/*
	 * create local object
	 */
	under = &d->lod_child->dd_lu_dev;
	below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
	if (below == NULL)
		RETURN(-ENOMEM);

	lu_object_add(o, below);

	RETURN(0);
}

void lod_object_free_striping(const struct lu_env *env, struct lod_object *lo)
{
	int i;

	if (lo->ldo_dir_stripe != NULL) {
		OBD_FREE_PTR(lo->ldo_dir_stripe);
		lo->ldo_dir_stripe = NULL;
	}

	if (lo->ldo_stripe) {
		LASSERT(lo->ldo_stripes_allocated > 0);

		for (i = 0; i < lo->ldo_stripenr; i++) {
			if (lo->ldo_stripe[i])
				lu_object_put(env, &lo->ldo_stripe[i]->do_lu);
		}

		i = sizeof(struct dt_object *) * lo->ldo_stripes_allocated;
		OBD_FREE(lo->ldo_stripe, i);
		lo->ldo_stripe = NULL;
		lo->ldo_stripes_allocated = 0;
	}
	lo->ldo_stripenr = 0;
	lo->ldo_pattern = 0;
}

/*
 * ->start is called once all slices are initialized, including header's
 * cache for mode (object type). using the type we can initialize ops
 */
static int lod_object_start(const struct lu_env *env, struct lu_object *o)
{
	if (S_ISLNK(o->lo_header->loh_attr & S_IFMT))
		lu2lod_obj(o)->ldo_obj.do_body_ops = &lod_body_lnk_ops;
	return 0;
}

static void lod_object_free(const struct lu_env *env, struct lu_object *o)
{
	struct lod_object *mo = lu2lod_obj(o);

	/*
	 * release all underlying object pinned
	 */

	lod_object_free_striping(env, mo);

	lod_object_set_pool(mo, NULL);

	lu_object_fini(o);
	OBD_SLAB_FREE_PTR(mo, lod_object_kmem);
}

static void lod_object_release(const struct lu_env *env, struct lu_object *o)
{
	/* XXX: shouldn't we release everything here in case if object
	 * creation failed before? */
}

static int lod_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *l)
{
	struct lod_object *o = lu2lod_obj((struct lu_object *) l);

	return (*p)(env, cookie, LUSTRE_LOD_NAME"-object@%p", o);
}

struct lu_object_operations lod_lu_obj_ops = {
	.loo_object_init	= lod_object_init,
	.loo_object_start	= lod_object_start,
	.loo_object_free	= lod_object_free,
	.loo_object_release	= lod_object_release,
	.loo_object_print	= lod_object_print,
};

/**
 * Init remote lod object
 */
static int lod_robject_init(const struct lu_env *env, struct lu_object *lo,
			    const struct lu_object_conf *conf)
{
	struct lod_device *lod = lu2lod_dev(lo->lo_dev);
	struct lod_tgt_descs *ltd = &lod->lod_mdt_descs;
	struct lu_device  *c_dev = NULL;
	struct lu_object  *c_obj;
	int i;
	ENTRY;

	lod_getref(ltd);
	if (ltd->ltd_tgts_size > 0) {
		cfs_foreach_bit(ltd->ltd_tgt_bitmap, i) {
			struct lod_tgt_desc *tgt;
			tgt = LTD_TGT(ltd, i);
			LASSERT(tgt && tgt->ltd_tgt);
			if (tgt->ltd_index ==
			    lu2lod_obj(lo)->ldo_mds_num) {
				c_dev = &(tgt->ltd_tgt->dd_lu_dev);
				break;
			}
		}
	}
	lod_putref(lod, ltd);

	if (unlikely(c_dev == NULL))
		RETURN(-ENOENT);

	c_obj = c_dev->ld_ops->ldo_object_alloc(env, lo->lo_header, c_dev);
	if (unlikely(c_obj == NULL))
		RETURN(-ENOMEM);

	lu_object_add(lo, c_obj);

	RETURN(0);
}

struct lu_object_operations lod_lu_robj_ops = {
	.loo_object_init      = lod_robject_init,
	.loo_object_start     = lod_object_start,
	.loo_object_free      = lod_object_free,
	.loo_object_release   = lod_object_release,
	.loo_object_print     = lod_object_print,
};
