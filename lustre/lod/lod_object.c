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
#include <obd_lov.h>

#include "lod_internal.h"

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
	if (!(attr->la_valid & (LA_UID | LA_GID)))
		RETURN(rc);

	/*
	 * load striping information, notice we don't do this when object
	 * is being initialized as we don't need this information till
	 * few specific cases like destroy, chown
	 */
	rc = lod_load_striping(env, lo);
	if (rc)
		RETURN(rc);

	/*
	 * if object is striped declare changes on the stripes
	 */
	LASSERT(lo->ldo_stripe || lo->ldo_stripenr == 0);
	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);
		rc = dt_declare_attr_set(env, lo->ldo_stripe[i], attr, handle);
		if (rc) {
			CERROR("failed declaration: %d\n", rc);
			break;
		}
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_MAKE_LOVEA_HOLE) &&
	    dt_object_exists(next) &&
	    dt_object_remote(next) == 0 && S_ISREG(attr->la_mode)) {
		struct lod_thread_info *info = lod_env_info(env);
		struct lu_buf *buf = &info->lti_buf;

		buf->lb_buf = info->lti_ea_store;
		buf->lb_len = info->lti_ea_store_size;
		dt_declare_xattr_set(env, next, buf, XATTR_NAME_LOV,
				     LU_XATTR_REPLACE, handle);
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

	if (!(attr->la_valid & (LA_UID | LA_GID)))
		RETURN(rc);

	/*
	 * if object is striped, apply changes to all the stripes
	 */
	LASSERT(lo->ldo_stripe || lo->ldo_stripenr == 0);
	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);
		rc = dt_attr_set(env, lo->ldo_stripe[i], attr, handle, capa);
		if (rc) {
			CERROR("failed declaration: %d\n", rc);
			break;
		}
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_MAKE_LOVEA_HOLE) &&
	    dt_object_exists(next) &&
	    dt_object_remote(next) == 0 && S_ISREG(attr->la_mode)) {
		struct lod_thread_info *info = lod_env_info(env);
		struct lu_buf *buf = &info->lti_buf;
		struct lov_mds_md_v1 *lmm;
		struct lov_ost_data_v1 *objs;
		__u32 magic;
		int rc1;

		rc1 = lod_get_lov_ea(env, lo);
		if (rc1  <= 0)
			RETURN(rc);

		buf->lb_buf = info->lti_ea_store;
		buf->lb_len = info->lti_ea_store_size;
		lmm = info->lti_ea_store;
		magic = le32_to_cpu(lmm->lmm_magic);
		if (le16_to_cpu(lmm->lmm_stripe_count) >= 2) {
			if (magic == LOV_MAGIC_V1)
				objs = &(lmm->lmm_objects[1]);
			else
				objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[1];
			memset(objs, 0, sizeof(*objs));
			dt_xattr_set(env, next, buf, XATTR_NAME_LOV,
				     LU_XATTR_REPLACE, handle, BYPASS_CAPA);
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
	if ((S_ISREG(mode) || !mode) && !strcmp(name, XATTR_NAME_LOV) &&
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
	}

	rc = dt_declare_xattr_set(env, next, buf, name, fl, th);

	RETURN(rc);
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
	const char		*pool_name = NULL;
	int			 rc;
	ENTRY;

	LASSERT(l->ldo_stripe == NULL);
	l->ldo_striping_cached = 0;
	l->ldo_def_striping_set = 0;
	lod_object_set_pool(l, NULL);
	l->ldo_def_stripe_size = 0;
	l->ldo_def_stripenr = 0;

	LASSERT(buf != NULL && buf->lb_buf != NULL);
	lum = buf->lb_buf;

	rc = lod_verify_striping(d, buf, false);
	if (rc)
		RETURN(rc);

	if (lum->lmm_magic == LOV_USER_MAGIC_V3) {
		v3 = buf->lb_buf;
		if (v3->lmm_pool_name[0] != '\0')
			pool_name = v3->lmm_pool_name;
	}

	/* if { size, offset, count } = { 0, -1, 0 } and no pool
	 * (i.e. all default values specified) then delete default
	 * striping from dir. */
	CDEBUG(D_OTHER,
		"set default striping: sz %u # %u offset %d %s %s\n",
		(unsigned)lum->lmm_stripe_size,
		(unsigned)lum->lmm_stripe_count,
		(int)lum->lmm_stripe_offset,
		v3 ? "from" : "", v3 ? v3->lmm_pool_name : "");

	if (LOVEA_DELETE_VALUES(lum->lmm_stripe_size, lum->lmm_stripe_count,
				lum->lmm_stripe_offset, pool_name)) {
		rc = dt_xattr_del(env, next, name, th, capa);
		if (rc == -ENODATA)
			rc = 0;
	} else {
		rc = dt_xattr_set(env, next, buf, name, fl, th, capa);
	}

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
	if (S_ISDIR(attr)) {
		if (strncmp(name, XATTR_NAME_LOV, strlen(XATTR_NAME_LOV)) == 0)
			rc = lod_xattr_set_lov_on_dir(env, dt, buf, name,
						      fl, th, capa);
		else
			rc = dt_xattr_set(env, next, buf, name, fl, th, capa);

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

static int lod_cache_parent_striping(const struct lu_env *env,
				     struct lod_object *lp)
{
	struct lov_user_md_v1	*v1 = NULL;
	struct lov_user_md_v3	*v3 = NULL;
	int			 rc;
	ENTRY;

	/* dt_ah_init() is called from MDD without parent being write locked
	 * lock it here */
	dt_write_lock(env, dt_object_child(&lp->ldo_obj), 0);
	if (lp->ldo_striping_cached)
		GOTO(unlock, rc = 0);

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

	v1 = (struct lov_user_md_v1 *)lod_env_info(env)->lti_ea_store;
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

	CDEBUG(D_OTHER, "def. striping: # %d, sz %d, off %d %s%s on "DFID"\n",
	       lp->ldo_def_stripenr, lp->ldo_def_stripe_size,
	       lp->ldo_def_stripe_offset, v3 ? "from " : "",
	       v3 ? lp->ldo_pool : "", PFID(lu_object_fid(&lp->ldo_obj.do_lu)));

	EXIT;
unlock:
	dt_write_unlock(env, dt_object_child(&lp->ldo_obj));
	return rc;
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
		if (lp->ldo_striping_cached == 0) {
			/* we haven't tried to get default striping for
			 * the directory yet, let's cache it in the object */
			lod_cache_parent_striping(env, lp);
		}
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
			       (int)lc->ldo_def_stripenr,
			       (int)lc->ldo_def_stripe_size,
			       (int)lc->ldo_def_stripe_offset);
		}
		return;
	}

	/*
	 * if object is going to be striped over OSTs, transfer default
	 * striping information to the child, so that we can use it
	 * during declaration and creation
	 */
	if (!lod_object_will_be_striped(S_ISREG(child_mode),
					lu_object_fid(&child->do_lu)))
		return;

	/*
	 * try from the parent
	 */
	if (likely(parent)) {
		if (lp->ldo_striping_cached == 0) {
			/* we haven't tried to get default striping for
			 * the directory yet, let's cache it in the object */
			lod_cache_parent_striping(env, lp);
		}

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
	} else if (dof->dof_type == DFT_DIR && lo->ldo_striping_cached) {
		struct lod_thread_info *info = lod_env_info(env);

		struct lov_user_md_v3 *v3;

		if (LOVEA_DELETE_VALUES(lo->ldo_def_stripe_size,
					lo->ldo_def_stripenr,
					lo->ldo_def_stripe_offset,
					lo->ldo_pool))
			RETURN(0);

		OBD_ALLOC_PTR(v3);
		if (v3 == NULL)
			RETURN(-ENOMEM);

		v3->lmm_magic = cpu_to_le32(LOV_MAGIC_V3);
		v3->lmm_pattern = cpu_to_le32(LOV_PATTERN_RAID0);
		fid_to_lmm_oi(lu_object_fid(&dt->do_lu), &v3->lmm_oi);
		lmm_oi_cpu_to_le(&v3->lmm_oi, &v3->lmm_oi);
		v3->lmm_stripe_size = cpu_to_le32(lo->ldo_def_stripe_size);
		v3->lmm_stripe_count = cpu_to_le32(lo->ldo_def_stripenr);
		v3->lmm_stripe_offset = cpu_to_le16(lo->ldo_def_stripe_offset);
		if (lo->ldo_pool)
			strncpy(v3->lmm_pool_name, lo->ldo_pool,
				LOV_MAXPOOLNAME);

		info->lti_buf.lb_buf = v3;
		info->lti_buf.lb_len = sizeof(*v3);

		/* to transfer default striping from the parent */
		rc = dt_declare_xattr_set(env, next, &info->lti_buf,
					  XATTR_NAME_LOV, 0, th);
		OBD_FREE_PTR(v3);
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
			rc = lod_store_def_striping(env, dt, th);
		else if (lo->ldo_stripe)
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
