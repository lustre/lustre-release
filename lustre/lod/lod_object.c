/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * lustre/lod/lod_object.c
 *
 * This file contains implementations of methods for the OSD API
 * for the Logical Object Device (LOD) layer, which provides a virtual
 * local OSD object interface to the MDD layer, and abstracts the
 * addressing of local (OSD) and remote (OSP) objects. The API is
 * described in the file lustre/include/dt_object.h and in
 * Documentation/osd-api.txt.
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/random.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>

#include <lustre_fid.h>
#include <lustre_linkea.h>
#include <lustre_lmv.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_swab.h>
#include <uapi/linux/lustre/lustre_ver.h>
#include <lprocfs_status.h>
#include <md_object.h>

#include "lod_internal.h"

static const char dot[] = ".";
static const char dotdot[] = "..";

/**
 * Implementation of dt_index_operations::dio_lookup
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_index_operations::dio_lookup() in the API description for details.
 */
static int lod_lookup(const struct lu_env *env, struct dt_object *dt,
		      struct dt_rec *rec, const struct dt_key *key)
{
	struct dt_object *next = dt_object_child(dt);
	return next->do_index_ops->dio_lookup(env, next, rec, key);
}

/**
 * Implementation of dt_index_operations::dio_declare_insert.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_index_operations::dio_declare_insert() in the API description
 * for details.
 */
static int lod_declare_insert(const struct lu_env *env, struct dt_object *dt,
			      const struct dt_rec *rec,
			      const struct dt_key *key, struct thandle *th)
{
	return lod_sub_declare_insert(env, dt_object_child(dt), rec, key, th);
}

/**
 * Implementation of dt_index_operations::dio_insert.
 *
 * Used with regular (non-striped) objects
 *
 * \see dt_index_operations::dio_insert() in the API description for details.
 */
static int lod_insert(const struct lu_env *env, struct dt_object *dt,
		      const struct dt_rec *rec, const struct dt_key *key,
		      struct thandle *th)
{
	return lod_sub_insert(env, dt_object_child(dt), rec, key, th);
}

/**
 * Implementation of dt_index_operations::dio_declare_delete.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_index_operations::dio_declare_delete() in the API description
 * for details.
 */
static int lod_declare_delete(const struct lu_env *env, struct dt_object *dt,
			      const struct dt_key *key, struct thandle *th)
{
	return lod_sub_declare_delete(env, dt_object_child(dt), key, th);
}

/**
 * Implementation of dt_index_operations::dio_delete.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_index_operations::dio_delete() in the API description for details.
 */
static int lod_delete(const struct lu_env *env, struct dt_object *dt,
		      const struct dt_key *key, struct thandle *th)
{
	return lod_sub_delete(env, dt_object_child(dt), key, th);
}

/**
 * Implementation of dt_it_ops::init.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::init() in the API description for details.
 */
static struct dt_it *lod_it_init(const struct lu_env *env,
				 struct dt_object *dt, __u32 attr)
{
	struct dt_object	*next = dt_object_child(dt);
	struct lod_it		*it = &lod_env_info(env)->lti_it;
	struct dt_it		*it_next;

	it_next = next->do_index_ops->dio_it.init(env, next, attr);
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
do {								\
	LASSERT((it)->lit_obj != NULL);				\
	LASSERT((it)->lit_it != NULL);				\
} while (0)

/**
 * Implementation of dt_index_operations::dio_it.fini.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_index_operations::dio_it.fini() in the API description for details.
 */
static void lod_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	it->lit_obj->do_index_ops->dio_it.fini(env, it->lit_it);

	/* the iterator not in use any more */
	it->lit_obj = NULL;
	it->lit_it = NULL;
}

/**
 * Implementation of dt_it_ops::get.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::get() in the API description for details.
 */
static int lod_it_get(const struct lu_env *env, struct dt_it *di,
		      const struct dt_key *key)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.get(env, it->lit_it, key);
}

/**
 * Implementation of dt_it_ops::put.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::put() in the API description for details.
 */
static void lod_it_put(const struct lu_env *env, struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.put(env, it->lit_it);
}

/**
 * Implementation of dt_it_ops::next.
 *
 * Used with regular (non-striped) objects
 *
 * \see dt_it_ops::next() in the API description for details.
 */
static int lod_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.next(env, it->lit_it);
}

/**
 * Implementation of dt_it_ops::key.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::key() in the API description for details.
 */
static struct dt_key *lod_it_key(const struct lu_env *env,
				 const struct dt_it *di)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.key(env, it->lit_it);
}

/**
 * Implementation of dt_it_ops::key_size.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::key_size() in the API description for details.
 */
static int lod_it_key_size(const struct lu_env *env, const struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.key_size(env, it->lit_it);
}

/**
 * Implementation of dt_it_ops::rec.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::rec() in the API description for details.
 */
static int lod_it_rec(const struct lu_env *env, const struct dt_it *di,
		      struct dt_rec *rec, __u32 attr)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.rec(env, it->lit_it, rec,
						     attr);
}

/**
 * Implementation of dt_it_ops::rec_size.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::rec_size() in the API description for details.
 */
static int lod_it_rec_size(const struct lu_env *env, const struct dt_it *di,
			   __u32 attr)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.rec_size(env, it->lit_it,
							  attr);
}

/**
 * Implementation of dt_it_ops::store.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::store() in the API description for details.
 */
static __u64 lod_it_store(const struct lu_env *env, const struct dt_it *di)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.store(env, it->lit_it);
}

/**
 * Implementation of dt_it_ops::load.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::load() in the API description for details.
 */
static int lod_it_load(const struct lu_env *env, const struct dt_it *di,
		       __u64 hash)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.load(env, it->lit_it, hash);
}

/**
 * Implementation of dt_it_ops::key_rec.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_it_ops::rec() in the API description for details.
 */
static int lod_it_key_rec(const struct lu_env *env, const struct dt_it *di,
			  void *key_rec)
{
	const struct lod_it *it = (const struct lod_it *)di;

	LOD_CHECK_IT(env, it);
	return it->lit_obj->do_index_ops->dio_it.key_rec(env, it->lit_it,
							 key_rec);
}

static const struct dt_index_operations lod_index_ops = {
	.dio_lookup		= lod_lookup,
	.dio_declare_insert	= lod_declare_insert,
	.dio_insert		= lod_insert,
	.dio_declare_delete	= lod_declare_delete,
	.dio_delete		= lod_delete,
	.dio_it	= {
		.init		= lod_it_init,
		.fini		= lod_it_fini,
		.get		= lod_it_get,
		.put		= lod_it_put,
		.next		= lod_it_next,
		.key		= lod_it_key,
		.key_size	= lod_it_key_size,
		.rec		= lod_it_rec,
		.rec_size	= lod_it_rec_size,
		.store		= lod_it_store,
		.load		= lod_it_load,
		.key_rec	= lod_it_key_rec,
	}
};

/**
 * Implementation of dt_index_operations::dio_lookup
 *
 * Used with striped directories.
 *
 * \see dt_index_operations::dio_lookup() in the API description for details.
 */
static int lod_striped_lookup(const struct lu_env *env, struct dt_object *dt,
		      struct dt_rec *rec, const struct dt_key *key)
{
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object *next;
	const char *name = (const char *)key;

	LASSERT(lo->ldo_dir_stripe_count > 0);

	if (strcmp(name, dot) == 0) {
		struct lu_fid *fid = (struct lu_fid *)rec;

		*fid = *lod_object_fid(lo);
		return 1;
	}

	if (strcmp(name, dotdot) == 0) {
		next = dt_object_child(dt);
	} else {
		int index;

		index = __lmv_name_to_stripe_index(lo->ldo_dir_hash_type,
						   lo->ldo_dir_stripe_count,
						   lo->ldo_dir_migrate_hash,
						   lo->ldo_dir_migrate_offset,
						   name, strlen(name), true);
		if (index < 0)
			return index;

		next = lo->ldo_stripe[index];
		if (!next || !dt_object_exists(next))
			return -ENODEV;
	}

	return next->do_index_ops->dio_lookup(env, next, rec, key);
}

/**
 * Implementation of dt_it_ops::init.
 *
 * Used with striped objects. Internally just initializes the iterator
 * on the first stripe.
 *
 * \see dt_it_ops::init() in the API description for details.
 */
static struct dt_it *lod_striped_it_init(const struct lu_env *env,
					 struct dt_object *dt, __u32 attr)
{
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object *next;
	struct lod_it *it = &lod_env_info(env)->lti_it;
	struct dt_it *it_next;
	__u16 index = 0;

	LASSERT(lo->ldo_dir_stripe_count > 0);

	do {
		next = lo->ldo_stripe[index];
		if (next && dt_object_exists(next))
			break;
	} while (++index < lo->ldo_dir_stripe_count);

	/* no valid stripe */
	if (!next || !dt_object_exists(next))
		return ERR_PTR(-ENODEV);

	LASSERT(next->do_index_ops != NULL);

	it_next = next->do_index_ops->dio_it.init(env, next, attr);
	if (IS_ERR(it_next))
		return it_next;

	/* currently we do not use more than one iterator per thread
	 * so we store it in thread info. if at some point we need
	 * more active iterators in a single thread, we can allocate
	 * additional ones */
	LASSERT(it->lit_obj == NULL);

	it->lit_stripe_index = index;
	it->lit_attr = attr;
	it->lit_it = it_next;
	it->lit_obj = dt;

	return (struct dt_it *)it;
}

#define LOD_CHECK_STRIPED_IT(env, it, lo)				\
do {									\
	LASSERT((it)->lit_obj != NULL);					\
	LASSERT((it)->lit_it != NULL);					\
	LASSERT((lo)->ldo_dir_stripe_count > 0);			\
	LASSERT((it)->lit_stripe_index < (lo)->ldo_dir_stripe_count);	\
} while (0)

/**
 * Implementation of dt_it_ops::fini.
 *
 * Used with striped objects.
 *
 * \see dt_it_ops::fini() in the API description for details.
 */
static void lod_striped_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct lod_it		*it = (struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;

	/* If lit_it == NULL, then it means the sub_it has been finished,
	 * which only happens in failure cases, see lod_striped_it_next() */
	if (it->lit_it != NULL) {
		LOD_CHECK_STRIPED_IT(env, it, lo);

		next = lo->ldo_stripe[it->lit_stripe_index];
		if (next) {
			LASSERT(next->do_index_ops != NULL);
			next->do_index_ops->dio_it.fini(env, it->lit_it);
		}
	}

	/* the iterator not in use any more */
	it->lit_obj = NULL;
	it->lit_it = NULL;
	it->lit_stripe_index = 0;
}

/**
 * Implementation of dt_it_ops::get.
 *
 * Right now it's not used widely, only to reset the iterator to the
 * initial position. It should be possible to implement a full version
 * which chooses a correct stripe to be able to position with any key.
 *
 * \see dt_it_ops::get() in the API description for details.
 */
static int lod_striped_it_get(const struct lu_env *env, struct dt_it *di,
			      const struct dt_key *key)
{
	const struct lod_it *it = (const struct lod_it *)di;
	struct lod_object *lo = lod_dt_obj(it->lit_obj);
	struct dt_object *next;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	LASSERT(dt_object_exists(next));
	LASSERT(next->do_index_ops != NULL);

	return next->do_index_ops->dio_it.get(env, it->lit_it, key);
}

/**
 * Implementation of dt_it_ops::put.
 *
 * Used with striped objects.
 *
 * \see dt_it_ops::put() in the API description for details.
 */
static void lod_striped_it_put(const struct lu_env *env, struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;
	struct lod_object *lo = lod_dt_obj(it->lit_obj);
	struct dt_object *next;

	/*
	 * If lit_it == NULL, then it means the sub_it has been finished,
	 * which only happens in failure cases, see lod_striped_it_next()
	 */
	if (!it->lit_it)
		return;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	LASSERT(next->do_index_ops != NULL);

	return next->do_index_ops->dio_it.put(env, it->lit_it);
}

/**
 * Implementation of dt_it_ops::next.
 *
 * Used with striped objects. When the end of the current stripe is
 * reached, the method takes the next stripe's iterator.
 *
 * \see dt_it_ops::next() in the API description for details.
 */
static int lod_striped_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct lod_it *it = (struct lod_it *)di;
	struct lod_object *lo = lod_dt_obj(it->lit_obj);
	struct dt_object *next;
	struct dt_it *it_next;
	__u32 index;
	int rc;

	ENTRY;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	LASSERT(dt_object_exists(next));
	LASSERT(next->do_index_ops != NULL);
again:
	rc = next->do_index_ops->dio_it.next(env, it->lit_it);
	if (rc < 0)
		RETURN(rc);

	if (rc == 0 && it->lit_stripe_index == 0)
		RETURN(rc);

	if (rc == 0 && it->lit_stripe_index > 0) {
		struct lu_dirent *ent;

		ent = (struct lu_dirent *)lod_env_info(env)->lti_key;

		rc = next->do_index_ops->dio_it.rec(env, it->lit_it,
						    (struct dt_rec *)ent,
						    it->lit_attr);
		if (rc != 0)
			RETURN(rc);

		/* skip . and .. for slave stripe */
		if ((strncmp(ent->lde_name, ".",
			     le16_to_cpu(ent->lde_namelen)) == 0 &&
		     le16_to_cpu(ent->lde_namelen) == 1) ||
		    (strncmp(ent->lde_name, "..",
			     le16_to_cpu(ent->lde_namelen)) == 0 &&
		     le16_to_cpu(ent->lde_namelen) == 2))
			goto again;

		RETURN(rc);
	}

	next->do_index_ops->dio_it.put(env, it->lit_it);
	next->do_index_ops->dio_it.fini(env, it->lit_it);
	it->lit_it = NULL;

	/* go to next stripe */
	index = it->lit_stripe_index;
	while (++index < lo->ldo_dir_stripe_count) {
		next = lo->ldo_stripe[index];
		if (!next)
			continue;

		if (!dt_object_exists(next))
			continue;

		rc = next->do_ops->do_index_try(env, next,
						&dt_directory_features);
		if (rc != 0)
			RETURN(rc);

		LASSERT(next->do_index_ops != NULL);

		it_next = next->do_index_ops->dio_it.init(env, next,
							  it->lit_attr);
		if (IS_ERR(it_next))
			RETURN(PTR_ERR(it_next));

		rc = next->do_index_ops->dio_it.get(env, it_next,
						    (const struct dt_key *)"");
		if (rc <= 0)
			RETURN(rc == 0 ? -EIO : rc);

		it->lit_it = it_next;
		it->lit_stripe_index = index;
		goto again;

	}

	RETURN(1);
}

/**
 * Implementation of dt_it_ops::key.
 *
 * Used with striped objects.
 *
 * \see dt_it_ops::key() in the API description for details.
 */
static struct dt_key *lod_striped_it_key(const struct lu_env *env,
					 const struct dt_it *di)
{
	const struct lod_it	*it = (const struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	LASSERT(next->do_index_ops != NULL);

	return next->do_index_ops->dio_it.key(env, it->lit_it);
}

/**
 * Implementation of dt_it_ops::key_size.
 *
 * Used with striped objects.
 *
 * \see dt_it_ops::size() in the API description for details.
 */
static int lod_striped_it_key_size(const struct lu_env *env,
				   const struct dt_it *di)
{
	struct lod_it		*it = (struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	LASSERT(next->do_index_ops != NULL);

	return next->do_index_ops->dio_it.key_size(env, it->lit_it);
}

/**
 * Implementation of dt_it_ops::rec.
 *
 * Used with striped objects.
 *
 * \see dt_it_ops::rec() in the API description for details.
 */
static int lod_striped_it_rec(const struct lu_env *env, const struct dt_it *di,
			      struct dt_rec *rec, __u32 attr)
{
	const struct lod_it	*it = (const struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	LASSERT(next->do_index_ops != NULL);

	return next->do_index_ops->dio_it.rec(env, it->lit_it, rec, attr);
}

/**
 * Implementation of dt_it_ops::rec_size.
 *
 * Used with striped objects.
 *
 * \see dt_it_ops::rec_size() in the API description for details.
 */
static int lod_striped_it_rec_size(const struct lu_env *env,
				   const struct dt_it *di, __u32 attr)
{
	struct lod_it		*it = (struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	LASSERT(next->do_index_ops != NULL);

	return next->do_index_ops->dio_it.rec_size(env, it->lit_it, attr);
}

/**
 * Implementation of dt_it_ops::store.
 *
 * Used with striped objects.
 *
 * \see dt_it_ops::store() in the API description for details.
 */
static __u64 lod_striped_it_store(const struct lu_env *env,
				  const struct dt_it *di)
{
	const struct lod_it	*it = (const struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	LASSERT(next->do_index_ops != NULL);

	return next->do_index_ops->dio_it.store(env, it->lit_it);
}

/**
 * Implementation of dt_it_ops::load.
 *
 * Used with striped objects.
 *
 * \see dt_it_ops::load() in the API description for details.
 */
static int lod_striped_it_load(const struct lu_env *env,
			       const struct dt_it *di, __u64 hash)
{
	const struct lod_it	*it = (const struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	LASSERT(next->do_index_ops != NULL);

	return next->do_index_ops->dio_it.load(env, it->lit_it, hash);
}

static const struct dt_index_operations lod_striped_index_ops = {
	.dio_lookup		= lod_striped_lookup,
	.dio_declare_insert	= lod_declare_insert,
	.dio_insert		= lod_insert,
	.dio_declare_delete	= lod_declare_delete,
	.dio_delete		= lod_delete,
	.dio_it	= {
		.init		= lod_striped_it_init,
		.fini		= lod_striped_it_fini,
		.get		= lod_striped_it_get,
		.put		= lod_striped_it_put,
		.next		= lod_striped_it_next,
		.key		= lod_striped_it_key,
		.key_size	= lod_striped_it_key_size,
		.rec		= lod_striped_it_rec,
		.rec_size	= lod_striped_it_rec_size,
		.store		= lod_striped_it_store,
		.load		= lod_striped_it_load,
	}
};

/**
 * Append the FID for each shard of the striped directory after the
 * given LMV EA header.
 *
 * To simplify striped directory and the consistency verification,
 * we only store the LMV EA header on disk, for both master object
 * and slave objects. When someone wants to know the whole LMV EA,
 * such as client readdir(), we can build the entrie LMV EA on the
 * MDT side (in RAM) via iterating the sub-directory entries that
 * are contained in the master object of the stripe directory.
 *
 * For the master object of the striped directroy, the valid name
 * for each shard is composed of the ${shard_FID}:${shard_idx}.
 *
 * There may be holes in the LMV EA if some shards' name entries
 * are corrupted or lost.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lo	pointer to the master object of the striped directory
 * \param[in] buf	pointer to the lu_buf which will hold the LMV EA
 * \param[in] resize	whether re-allocate the buffer if it is not big enough
 *
 * \retval		positive size of the LMV EA
 * \retval		0 for nothing to be loaded
 * \retval		negative error number on failure
 */
int lod_load_lmv_shards(const struct lu_env *env, struct lod_object *lo,
			struct lu_buf *buf, bool resize)
{
	struct lu_dirent	*ent	=
			(struct lu_dirent *)lod_env_info(env)->lti_key;
	struct lod_device	*lod	= lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct dt_object	*obj	= dt_object_child(&lo->ldo_obj);
	struct lmv_mds_md_v1	*lmv1	= buf->lb_buf;
	struct dt_it		*it;
	const struct dt_it_ops	*iops;
	__u32			 stripes;
	__u32			 magic	= le32_to_cpu(lmv1->lmv_magic);
	size_t			 lmv1_size;
	int			 rc;
	ENTRY;

	if (magic != LMV_MAGIC_V1)
		RETURN(0);

	stripes = le32_to_cpu(lmv1->lmv_stripe_count);
	if (stripes < 1)
		RETURN(0);

	rc = lmv_mds_md_size(stripes, magic);
	if (rc < 0)
		RETURN(rc);
	lmv1_size = rc;
	if (buf->lb_len < lmv1_size) {
		struct lu_buf tbuf;

		if (!resize)
			RETURN(-ERANGE);

		tbuf = *buf;
		buf->lb_buf = NULL;
		buf->lb_len = 0;
		lu_buf_alloc(buf, lmv1_size);
		lmv1 = buf->lb_buf;
		if (lmv1 == NULL)
			RETURN(-ENOMEM);

		memcpy(buf->lb_buf, tbuf.lb_buf, tbuf.lb_len);
	}

	if (unlikely(!dt_try_as_dir(env, obj)))
		RETURN(-ENOTDIR);

	memset(&lmv1->lmv_stripe_fids[0], 0, stripes * sizeof(struct lu_fid));
	iops = &obj->do_index_ops->dio_it;
	it = iops->init(env, obj, LUDA_64BITHASH);
	if (IS_ERR(it))
		RETURN(PTR_ERR(it));

	rc = iops->load(env, it, 0);
	if (rc == 0)
		rc = iops->next(env, it);
	else if (rc > 0)
		rc = 0;

	while (rc == 0) {
		char		 name[FID_LEN + 2] = "";
		struct lu_fid	 fid;
		__u32		 index;
		int		 len;

		rc = iops->rec(env, it, (struct dt_rec *)ent, LUDA_64BITHASH);
		if (rc != 0)
			break;

		rc = -EIO;

		fid_le_to_cpu(&fid, &ent->lde_fid);
		ent->lde_namelen = le16_to_cpu(ent->lde_namelen);
		if (ent->lde_name[0] == '.') {
			if (ent->lde_namelen == 1)
				goto next;

			if (ent->lde_namelen == 2 && ent->lde_name[1] == '.')
				goto next;
		}

		len = scnprintf(name, sizeof(name),
				DFID":", PFID(&ent->lde_fid));
		/* The ent->lde_name is composed of ${FID}:${index} */
		if (ent->lde_namelen < len + 1 ||
		    memcmp(ent->lde_name, name, len) != 0) {
			CDEBUG_LIMIT(lod->lod_lmv_failout ? D_ERROR : D_INFO,
				     "%s: invalid shard name %.*s with the FID "DFID" for the striped directory "DFID", %s\n",
				     lod2obd(lod)->obd_name, ent->lde_namelen,
				     ent->lde_name, PFID(&fid),
				     PFID(lu_object_fid(&obj->do_lu)),
				     lod->lod_lmv_failout ? "failout" : "skip");

			if (lod->lod_lmv_failout)
				break;

			goto next;
		}

		index = 0;
		do {
			if (ent->lde_name[len] < '0' ||
			    ent->lde_name[len] > '9') {
				CDEBUG_LIMIT(lod->lod_lmv_failout ?
					     D_ERROR : D_INFO,
					     "%s: invalid shard name %.*s with the FID "DFID" for the striped directory "DFID", %s\n",
					     lod2obd(lod)->obd_name,
					     ent->lde_namelen,
					     ent->lde_name, PFID(&fid),
					     PFID(lu_object_fid(&obj->do_lu)),
					     lod->lod_lmv_failout ?
					     "failout" : "skip");

				if (lod->lod_lmv_failout)
					break;

				goto next;
			}

			index = index * 10 + ent->lde_name[len++] - '0';
		} while (len < ent->lde_namelen);

		if (len == ent->lde_namelen) {
			/* Out of LMV EA range. */
			if (index >= stripes) {
				CERROR("%s: the shard %.*s for the striped "
				       "directory "DFID" is out of the known "
				       "LMV EA range [0 - %u], failout\n",
				       lod2obd(lod)->obd_name, ent->lde_namelen,
				       ent->lde_name,
				       PFID(lu_object_fid(&obj->do_lu)),
				       stripes - 1);

				break;
			}

			/* The slot has been occupied. */
			if (!fid_is_zero(&lmv1->lmv_stripe_fids[index])) {
				struct lu_fid fid0;

				fid_le_to_cpu(&fid0,
					&lmv1->lmv_stripe_fids[index]);
				CERROR("%s: both the shard "DFID" and "DFID
				       " for the striped directory "DFID
				       " claim the same LMV EA slot at the "
				       "index %d, failout\n",
				       lod2obd(lod)->obd_name,
				       PFID(&fid0), PFID(&fid),
				       PFID(lu_object_fid(&obj->do_lu)), index);

				break;
			}

			/* stored as LE mode */
			lmv1->lmv_stripe_fids[index] = ent->lde_fid;

next:
			rc = iops->next(env, it);
		}
	}

	iops->put(env, it);
	iops->fini(env, it);

	RETURN(rc > 0 ? lmv_mds_md_size(stripes, magic) : rc);
}

/**
 * Implementation of dt_object_operations::do_index_try.
 *
 * \see dt_object_operations::do_index_try() in the API description for details.
 */
static int lod_index_try(const struct lu_env *env, struct dt_object *dt,
			 const struct dt_index_features *feat)
{
	struct lod_object	*lo = lod_dt_obj(dt);
	struct dt_object	*next = dt_object_child(dt);
	int			rc;
	ENTRY;

	LASSERT(next->do_ops);
	LASSERT(next->do_ops->do_index_try);

	rc = lod_striping_load(env, lo);
	if (rc != 0)
		RETURN(rc);

	rc = next->do_ops->do_index_try(env, next, feat);
	if (rc != 0)
		RETURN(rc);

	if (lo->ldo_dir_stripe_count > 0) {
		int i;

		for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
			if (!lo->ldo_stripe[i])
				continue;
			if (!dt_object_exists(lo->ldo_stripe[i]))
				continue;
			rc = lo->ldo_stripe[i]->do_ops->do_index_try(env,
						lo->ldo_stripe[i], feat);
			if (rc != 0)
				RETURN(rc);
		}
		dt->do_index_ops = &lod_striped_index_ops;
	} else {
		dt->do_index_ops = &lod_index_ops;
	}

	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_read_lock.
 *
 * \see dt_object_operations::do_read_lock() in the API description for details.
 */
static void lod_read_lock(const struct lu_env *env, struct dt_object *dt,
			  unsigned role)
{
	dt_read_lock(env, dt_object_child(dt), role);
}

/**
 * Implementation of dt_object_operations::do_write_lock.
 *
 * \see dt_object_operations::do_write_lock() in the API description for
 * details.
 */
static void lod_write_lock(const struct lu_env *env, struct dt_object *dt,
			   unsigned role)
{
	dt_write_lock(env, dt_object_child(dt), role);
}

/**
 * Implementation of dt_object_operations::do_read_unlock.
 *
 * \see dt_object_operations::do_read_unlock() in the API description for
 * details.
 */
static void lod_read_unlock(const struct lu_env *env, struct dt_object *dt)
{
	dt_read_unlock(env, dt_object_child(dt));
}

/**
 * Implementation of dt_object_operations::do_write_unlock.
 *
 * \see dt_object_operations::do_write_unlock() in the API description for
 * details.
 */
static void lod_write_unlock(const struct lu_env *env, struct dt_object *dt)
{
	dt_write_unlock(env, dt_object_child(dt));
}

/**
 * Implementation of dt_object_operations::do_write_locked.
 *
 * \see dt_object_operations::do_write_locked() in the API description for
 * details.
 */
static int lod_write_locked(const struct lu_env *env, struct dt_object *dt)
{
	return dt_write_locked(env, dt_object_child(dt));
}

/**
 * Implementation of dt_object_operations::do_attr_get.
 *
 * \see dt_object_operations::do_attr_get() in the API description for details.
 */
static int lod_attr_get(const struct lu_env *env,
			struct dt_object *dt,
			struct lu_attr *attr)
{
	/* Note: for striped directory, client will merge attributes
	 * from all of the sub-stripes see lmv_merge_attr(), and there
	 * no MDD logic depend on directory nlink/size/time, so we can
	 * always use master inode nlink and size for now. */
	return dt_attr_get(env, dt_object_child(dt), attr);
}

void lod_adjust_stripe_size(struct lod_layout_component *comp,
			    __u32 def_stripe_size)
{
	__u64 comp_end = comp->llc_extent.e_end;

	/* Choose stripe size if not set. Note that default stripe size can't
	 * be used as is, because it must be multiplier of given component end.
	 *  - first check if default stripe size can be used
	 *  - if not than select the lowest set bit from component end and use
	 *    that value as stripe size
	 */
	if (!comp->llc_stripe_size) {
		if (comp_end == LUSTRE_EOF || !(comp_end % def_stripe_size))
			comp->llc_stripe_size = def_stripe_size;
		else
			comp->llc_stripe_size = comp_end & ~(comp_end - 1);
	} else {
		if (comp_end != LUSTRE_EOF &&
		    comp_end & (LOV_MIN_STRIPE_SIZE - 1)) {
			CWARN("Component end %llu is not a multiple of min size %u\n",
			      comp_end, LOV_MIN_STRIPE_SIZE);
			comp_end = round_up(comp_end, LOV_MIN_STRIPE_SIZE);
		}
		/* check stripe size is multiplier of comp_end */
		if (comp_end != LUSTRE_EOF &&
		    comp_end != comp->llc_extent.e_start &&
		    comp_end % comp->llc_stripe_size) {
			/* fix that even for defined stripe size but warn
			 * about the problem, that must not happen
			 */
			CWARN("Component end %llu is not aligned by the stripe size %u\n",
			      comp_end, comp->llc_stripe_size);
			comp->llc_stripe_size = comp_end & ~(comp_end - 1);
		}
	}
}

static inline void lod_adjust_stripe_info(struct lod_layout_component *comp,
					  struct lov_desc *desc,
					  int append_stripes)
{
	if (comp->llc_pattern != LOV_PATTERN_MDT) {
		if (append_stripes) {
			comp->llc_stripe_count = append_stripes;
		} else if (!comp->llc_stripe_count) {
			comp->llc_stripe_count =
				desc->ld_default_stripe_count;
		}
	}

	lod_adjust_stripe_size(comp, desc->ld_default_stripe_size);
}

int lod_obj_for_each_stripe(const struct lu_env *env, struct lod_object *lo,
			    struct thandle *th,
			    struct lod_obj_stripe_cb_data *data)
{
	struct lod_layout_component *lod_comp;
	int i, j, rc = 0;
	ENTRY;

	mutex_lock(&lo->ldo_layout_mutex);
	for (i = 0; i < lo->ldo_comp_cnt; i++) {
		lod_comp = &lo->ldo_comp_entries[i];

		if (lod_comp->llc_stripe == NULL)
			continue;

		/* has stripe but not inited yet, this component has been
		 * declared to be created, but hasn't created yet.
		 */
		if (!lod_comp_inited(lod_comp))
			continue;

		if (data->locd_comp_skip_cb &&
		    data->locd_comp_skip_cb(env, lo, i, data))
			continue;

		if (data->locd_comp_cb) {
			rc = data->locd_comp_cb(env, lo, i, data);
			if (rc)
				GOTO(unlock, rc);
		}

		/* could used just to do sth about component, not each
		 * stripes
		 */
		if (!data->locd_stripe_cb)
			continue;

		LASSERT(lod_comp->llc_stripe_count > 0);
		for (j = 0; j < lod_comp->llc_stripe_count; j++) {
			struct dt_object *dt = lod_comp->llc_stripe[j];

			if (dt == NULL)
				continue;
			rc = data->locd_stripe_cb(env, lo, dt, th, i, j, data);
			if (rc != 0)
				GOTO(unlock, rc);
		}
	}
unlock:
	mutex_unlock(&lo->ldo_layout_mutex);
	RETURN(rc);
}

static bool lod_obj_attr_set_comp_skip_cb(const struct lu_env *env,
		struct lod_object *lo, int comp_idx,
		struct lod_obj_stripe_cb_data *data)
{
	struct lod_layout_component *lod_comp = &lo->ldo_comp_entries[comp_idx];
	bool skipped = false;

	if (!(data->locd_attr->la_valid & LA_LAYOUT_VERSION))
		return skipped;

	switch (lo->ldo_flr_state) {
	case LCM_FL_WRITE_PENDING: {
		int i;

		/* skip stale components */
		if (lod_comp->llc_flags & LCME_FL_STALE) {
			skipped = true;
			break;
		}

		/* skip valid and overlapping components, therefore any
		 * attempts to write overlapped components will never succeed
		 * because client will get EINPROGRESS. */
		for (i = 0; i < lo->ldo_comp_cnt; i++) {
			if (i == comp_idx)
				continue;

			if (lo->ldo_comp_entries[i].llc_flags & LCME_FL_STALE)
				continue;

			if (lu_extent_is_overlapped(&lod_comp->llc_extent,
					&lo->ldo_comp_entries[i].llc_extent)) {
				skipped = true;
				break;
			}
		}
		break;
	}
	default:
		LASSERTF(0, "impossible: %d\n", lo->ldo_flr_state);
	case LCM_FL_SYNC_PENDING:
		break;
	}

	CDEBUG(D_LAYOUT, DFID": %s to set component %x to version: %u\n",
	       PFID(lu_object_fid(&lo->ldo_obj.do_lu)),
	       skipped ? "skipped" : "chose", lod_comp->llc_id,
	       data->locd_attr->la_layout_version);

	return skipped;
}

static inline int
lod_obj_stripe_attr_set_cb(const struct lu_env *env, struct lod_object *lo,
			   struct dt_object *dt, struct thandle *th,
			   int comp_idx, int stripe_idx,
			   struct lod_obj_stripe_cb_data *data)
{
	if (data->locd_declare)
		return lod_sub_declare_attr_set(env, dt, data->locd_attr, th);

	if (data->locd_attr->la_valid & LA_LAYOUT_VERSION) {
		CDEBUG(D_LAYOUT, DFID": set layout version: %u, comp_idx: %d\n",
		       PFID(lu_object_fid(&dt->do_lu)),
		       data->locd_attr->la_layout_version, comp_idx);
	}

	return lod_sub_attr_set(env, dt, data->locd_attr, th);
}

/**
 * Implementation of dt_object_operations::do_declare_attr_set.
 *
 * If the object is striped, then apply the changes to all the stripes.
 *
 * \see dt_object_operations::do_declare_attr_set() in the API description
 * for details.
 */
static int lod_declare_attr_set(const struct lu_env *env,
				struct dt_object *dt,
				const struct lu_attr *attr,
				struct thandle *th)
{
	struct dt_object  *next = dt_object_child(dt);
	struct lod_object *lo = lod_dt_obj(dt);
	int                rc, i;
	ENTRY;

	/*
	 * declare setattr on the local object
	 */
	rc = lod_sub_declare_attr_set(env, next, attr, th);
	if (rc)
		RETURN(rc);

	/* osp_declare_attr_set() ignores all attributes other than
	 * UID, GID, PROJID, and size, and osp_attr_set() ignores all
	 * but UID, GID and PROJID. Declaration of size attr setting
	 * happens through lod_declare_init_size(), and not through
	 * this function. Therefore we need not load striping unless
	 * ownership is changing.  This should save memory and (we hope)
	 * speed up rename().
	 */
	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		if (!(attr->la_valid & LA_REMOTE_ATTR_SET))
			RETURN(rc);

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_OWNER))
			RETURN(0);
	} else {
		if (!(attr->la_valid & (LA_UID | LA_GID | LA_PROJID | LA_MODE |
					LA_ATIME | LA_MTIME | LA_CTIME |
					LA_FLAGS)))
			RETURN(rc);
	}
	/*
	 * load striping information, notice we don't do this when object
	 * is being initialized as we don't need this information till
	 * few specific cases like destroy, chown
	 */
	rc = lod_striping_load(env, lo);
	if (rc)
		RETURN(rc);

	if (!lod_obj_is_striped(dt))
		RETURN(0);

	/*
	 * if object is striped declare changes on the stripes
	 */
	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		LASSERT(lo->ldo_stripe);
		for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
			if (lo->ldo_stripe[i] == NULL)
				continue;
			if (!dt_object_exists(lo->ldo_stripe[i]))
				continue;
			rc = lod_sub_declare_attr_set(env, lo->ldo_stripe[i],
						      attr, th);
			if (rc != 0)
				RETURN(rc);
		}
	} else {
		struct lod_obj_stripe_cb_data data = { { 0 } };

		data.locd_attr = attr;
		data.locd_declare = true;
		data.locd_stripe_cb = lod_obj_stripe_attr_set_cb;
		rc = lod_obj_for_each_stripe(env, lo, th, &data);
	}

	if (rc)
		RETURN(rc);

	if (!dt_object_exists(next) || dt_object_remote(next) ||
	    !S_ISREG(attr->la_mode))
		RETURN(0);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_STRIPE)) {
		rc = lod_sub_declare_xattr_del(env, next, XATTR_NAME_LOV, th);
		RETURN(rc);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_CHANGE_STRIPE) ||
	    OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_PFL_RANGE)) {
		struct lod_thread_info *info = lod_env_info(env);
		struct lu_buf *buf = &info->lti_buf;

		buf->lb_buf = info->lti_ea_store;
		buf->lb_len = info->lti_ea_store_size;
		rc = lod_sub_declare_xattr_set(env, next, buf, XATTR_NAME_LOV,
					       LU_XATTR_REPLACE, th);
	}

	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_attr_set.
 *
 * If the object is striped, then apply the changes to all or subset of
 * the stripes depending on the object type and specific attributes.
 *
 * \see dt_object_operations::do_attr_set() in the API description for details.
 */
static int lod_attr_set(const struct lu_env *env,
			struct dt_object *dt,
			const struct lu_attr *attr,
			struct thandle *th)
{
	struct dt_object	*next = dt_object_child(dt);
	struct lod_object	*lo = lod_dt_obj(dt);
	int			rc, i;
	ENTRY;

	/*
	 * apply changes to the local object
	 */
	rc = lod_sub_attr_set(env, next, attr, th);
	if (rc)
		RETURN(rc);

	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		if (!(attr->la_valid & LA_REMOTE_ATTR_SET))
			RETURN(rc);

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_OWNER))
			RETURN(0);
	} else {
		if (!(attr->la_valid & (LA_UID | LA_GID | LA_MODE | LA_PROJID |
					LA_ATIME | LA_MTIME | LA_CTIME |
					LA_FLAGS)))
			RETURN(rc);
	}

	/* FIXME: a tricky case in the code path of mdd_layout_change():
	 * the in-memory striping information has been freed in lod_xattr_set()
	 * due to layout change. It has to load stripe here again. It only
	 * changes flags of layout so declare_attr_set() is still accurate */
	rc = lod_striping_load(env, lo);
	if (rc)
		RETURN(rc);

	if (!lod_obj_is_striped(dt))
		RETURN(0);

	/*
	 * if object is striped, apply changes to all the stripes
	 */
	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		LASSERT(lo->ldo_stripe);
		for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
			if (unlikely(lo->ldo_stripe[i] == NULL))
				continue;

			if ((dt_object_exists(lo->ldo_stripe[i]) == 0))
				continue;

			rc = lod_sub_attr_set(env, lo->ldo_stripe[i], attr, th);
			if (rc != 0)
				break;
		}
	} else {
		struct lod_obj_stripe_cb_data data = { { 0 } };

		data.locd_attr = attr;
		data.locd_declare = false;
		data.locd_comp_skip_cb = lod_obj_attr_set_comp_skip_cb;
		data.locd_stripe_cb = lod_obj_stripe_attr_set_cb;
		rc = lod_obj_for_each_stripe(env, lo, th, &data);
	}

	if (rc)
		RETURN(rc);

	if (!dt_object_exists(next) || dt_object_remote(next) ||
	    !S_ISREG(attr->la_mode))
		RETURN(0);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_STRIPE)) {
		rc = lod_sub_xattr_del(env, next, XATTR_NAME_LOV, th);
		RETURN(rc);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_CHANGE_STRIPE)) {
		struct lod_thread_info *info = lod_env_info(env);
		struct lu_buf *buf = &info->lti_buf;
		struct ost_id *oi = &info->lti_ostid;
		struct lu_fid *fid = &info->lti_fid;
		struct lov_mds_md_v1 *lmm;
		struct lov_ost_data_v1 *objs;
		__u32 magic;

		rc = lod_get_lov_ea(env, lo);
		if (rc <= 0)
			RETURN(rc);

		buf->lb_buf = info->lti_ea_store;
		buf->lb_len = info->lti_ea_store_size;
		lmm = info->lti_ea_store;
		magic = le32_to_cpu(lmm->lmm_magic);
		if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
			struct lov_comp_md_v1 *lcm = buf->lb_buf;
			struct lov_comp_md_entry_v1 *lcme =
						&lcm->lcm_entries[0];

			lmm = buf->lb_buf + le32_to_cpu(lcme->lcme_offset);
			magic = le32_to_cpu(lmm->lmm_magic);
		}

		if (magic == LOV_MAGIC_V1)
			objs = &(lmm->lmm_objects[0]);
		else
			objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
		ostid_le_to_cpu(&objs->l_ost_oi, oi);
		ostid_to_fid(fid, oi, le32_to_cpu(objs->l_ost_idx));
		fid->f_oid--;
		fid_to_ostid(fid, oi);
		ostid_cpu_to_le(oi, &objs->l_ost_oi);

		rc = lod_sub_xattr_set(env, next, buf, XATTR_NAME_LOV,
				       LU_XATTR_REPLACE, th);
	} else if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_PFL_RANGE)) {
		struct lod_thread_info *info = lod_env_info(env);
		struct lu_buf *buf = &info->lti_buf;
		struct lov_comp_md_v1 *lcm;
		struct lov_comp_md_entry_v1 *lcme;

		rc = lod_get_lov_ea(env, lo);
		if (rc <= 0)
			RETURN(rc);

		buf->lb_buf = info->lti_ea_store;
		buf->lb_len = info->lti_ea_store_size;
		lcm = buf->lb_buf;
		if (le32_to_cpu(lcm->lcm_magic) != LOV_MAGIC_COMP_V1 &&
		    le32_to_cpu(lcm->lcm_magic) != LOV_MAGIC_SEL)
			RETURN(-EINVAL);

		le32_add_cpu(&lcm->lcm_layout_gen, 1);
		lcme = &lcm->lcm_entries[0];
		le64_add_cpu(&lcme->lcme_extent.e_start, 1);
		le64_add_cpu(&lcme->lcme_extent.e_end, -1);

		rc = lod_sub_xattr_set(env, next, buf, XATTR_NAME_LOV,
				       LU_XATTR_REPLACE, th);
	}

	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_xattr_get.
 *
 * If LOV EA is requested from the root object and it's not
 * found, then return default striping for the filesystem.
 *
 * \see dt_object_operations::do_xattr_get() in the API description for details.
 */
static int lod_xattr_get(const struct lu_env *env, struct dt_object *dt,
			 struct lu_buf *buf, const char *name)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_device *dev = lu2lod_dev(dt->do_lu.lo_dev);
	int is_root;
	int rc;
	ENTRY;

	rc = dt_xattr_get(env, dt_object_child(dt), buf, name);
	if (strcmp(name, XATTR_NAME_LMV) == 0) {
		struct lmv_mds_md_v1	*lmv1;
		struct lmv_foreign_md	*lfm;
		int			 rc1 = 0;

		if (rc > (typeof(rc))sizeof(*lmv1))
			RETURN(rc);

		/* short (<= sizeof(struct lmv_mds_md_v1)) foreign LMV case */
		/* XXX empty foreign LMV is not allowed */
		if (rc <= offsetof(typeof(*lfm), lfm_value))
			RETURN(rc = rc > 0 ? -EINVAL : rc);

		if (buf->lb_buf == NULL || buf->lb_len == 0) {
			BUILD_BUG_ON(sizeof(*lmv1) > sizeof(info->lti_key));

			/* lti_buf is large enough for *lmv1 or a short
			 * (<= sizeof(struct lmv_mds_md_v1)) foreign LMV
			 */
			info->lti_buf.lb_buf = info->lti_key;
			info->lti_buf.lb_len = sizeof(*lmv1);
			rc = dt_xattr_get(env, dt_object_child(dt),
					  &info->lti_buf, name);
			if (unlikely(rc <= offsetof(typeof(*lfm),
						    lfm_value)))
				RETURN(rc = rc > 0 ? -EINVAL : rc);

			lfm = info->lti_buf.lb_buf;
			if (le32_to_cpu(lfm->lfm_magic) == LMV_MAGIC_FOREIGN)
				RETURN(rc);

			if (unlikely(rc != sizeof(*lmv1)))
				RETURN(rc = rc > 0 ? -EINVAL : rc);

			lmv1 = info->lti_buf.lb_buf;
			/* The on-disk LMV EA only contains header, but the
			 * returned LMV EA size should contain the space for
			 * the FIDs of all shards of the striped directory. */
			if (le32_to_cpu(lmv1->lmv_magic) == LMV_MAGIC_V1)
				rc = lmv_mds_md_size(
					le32_to_cpu(lmv1->lmv_stripe_count),
					le32_to_cpu(lmv1->lmv_magic));
		} else {
			lmv1 = buf->lb_buf;
			if (le32_to_cpu(lmv1->lmv_magic) != LMV_MAGIC_V1)
				RETURN(rc);

			if (rc != sizeof(*lmv1))
				RETURN(rc = rc > 0 ? -EINVAL : rc);

			rc1 = lod_load_lmv_shards(env, lod_dt_obj(dt),
						  buf, false);
		}

		RETURN(rc = rc1 != 0 ? rc1 : rc);
	}

	if ((rc > 0) && buf->lb_buf && strcmp(name, XATTR_NAME_LOV) == 0) {
		struct lov_comp_md_v1 *lcm = buf->lb_buf;

		if (lcm->lcm_magic == cpu_to_le32(LOV_MAGIC_SEL))
			lcm->lcm_magic = cpu_to_le32(LOV_MAGIC_COMP_V1);
	}

	if (rc != -ENODATA || !S_ISDIR(dt->do_lu.lo_header->loh_attr & S_IFMT))
		RETURN(rc);

	/*
	 * XXX: Only used by lfsck
	 *
	 * lod returns default striping on the real root of the device
	 * this is like the root stores default striping for the whole
	 * filesystem. historically we've been using a different approach
	 * and store it in the config.
	 */
	dt_root_get(env, dev->lod_child, &info->lti_fid);
	is_root = lu_fid_eq(&info->lti_fid, lu_object_fid(&dt->do_lu));

	if (is_root && strcmp(XATTR_NAME_LOV, name) == 0) {
		struct lov_user_md *lum = buf->lb_buf;
		struct lov_desc *desc = &dev->lod_ost_descs.ltd_lov_desc;

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

/**
 * Verify LVM EA.
 *
 * Checks that the magic of the stripe is sane.
 *
 * \param[in] lod	lod device
 * \param[in] lum	a buffer storing LMV EA to verify
 *
 * \retval		0 if the EA is sane
 * \retval		negative otherwise
 */
static int lod_verify_md_striping(struct lod_device *lod,
				  const struct lmv_user_md_v1 *lum)
{
	if (unlikely(le32_to_cpu(lum->lum_magic) != LMV_USER_MAGIC)) {
		CERROR("%s: invalid lmv_user_md: magic = %x, "
		       "stripe_offset = %d, stripe_count = %u: rc = %d\n",
		       lod2obd(lod)->obd_name, le32_to_cpu(lum->lum_magic),
		       (int)le32_to_cpu(lum->lum_stripe_offset),
		       le32_to_cpu(lum->lum_stripe_count), -EINVAL);
		return -EINVAL;
	}

	return 0;
}

/**
 * Initialize LMV EA for a slave.
 *
 * Initialize slave's LMV EA from the master's LMV EA.
 *
 * \param[in] master_lmv	a buffer containing master's EA
 * \param[out] slave_lmv	a buffer where slave's EA will be stored
 *
 */
static void lod_prep_slave_lmv_md(struct lmv_mds_md_v1 *slave_lmv,
				  const struct lmv_mds_md_v1 *master_lmv)
{
	*slave_lmv = *master_lmv;
	slave_lmv->lmv_magic = cpu_to_le32(LMV_MAGIC_STRIPE);
}

/**
 * Generate LMV EA.
 *
 * Generate LMV EA from the object passed as \a dt. The object must have
 * the stripes created and initialized.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[out] lmv_buf	buffer storing generated LMV EA
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_prep_lmv_md(const struct lu_env *env, struct dt_object *dt,
			   struct lu_buf *lmv_buf)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_device	*lod = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object	*lo = lod_dt_obj(dt);
	struct lmv_mds_md_v1	*lmm1;
	int			stripe_count;
	int			type = LU_SEQ_RANGE_ANY;
	int			rc;
	__u32			mdtidx;
	ENTRY;

	LASSERT(lo->ldo_dir_striped != 0);
	LASSERT(lo->ldo_dir_stripe_count > 0);
	stripe_count = lo->ldo_dir_stripe_count;
	/* Only store the LMV EA heahder on the disk. */
	if (info->lti_ea_store_size < sizeof(*lmm1)) {
		rc = lod_ea_store_resize(info, sizeof(*lmm1));
		if (rc != 0)
			RETURN(rc);
	} else {
		memset(info->lti_ea_store, 0, sizeof(*lmm1));
	}

	lmm1 = (struct lmv_mds_md_v1 *)info->lti_ea_store;
	memset(lmm1, 0, sizeof(*lmm1));
	lmm1->lmv_magic = cpu_to_le32(LMV_MAGIC);
	lmm1->lmv_stripe_count = cpu_to_le32(stripe_count);
	lmm1->lmv_hash_type = cpu_to_le32(lo->ldo_dir_hash_type);
	lmm1->lmv_layout_version = cpu_to_le32(lo->ldo_dir_layout_version);
	if (lod_is_layout_changing(lo)) {
		lmm1->lmv_migrate_hash = cpu_to_le32(lo->ldo_dir_migrate_hash);
		lmm1->lmv_migrate_offset =
			cpu_to_le32(lo->ldo_dir_migrate_offset);
	}
	rc = lod_fld_lookup(env, lod, lu_object_fid(&dt->do_lu),
			    &mdtidx, &type);
	if (rc != 0)
		RETURN(rc);

	lmm1->lmv_master_mdt_index = cpu_to_le32(mdtidx);
	lmv_buf->lb_buf = info->lti_ea_store;
	lmv_buf->lb_len = sizeof(*lmm1);

	RETURN(rc);
}

/**
 * Create in-core represenation for a striped directory.
 *
 * Parse the buffer containing LMV EA and instantiate LU objects
 * representing the stripe objects. The pointers to the objects are
 * stored in ldo_stripe field of \a lo. This function is used when
 * we need to access an already created object (i.e. load from a disk).
 *
 * \param[in] env	execution environment
 * \param[in] lo	lod object
 * \param[in] buf	buffer containing LMV EA
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
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
	unsigned int		i;
	int			rc = 0;
	ENTRY;

	LASSERT(mutex_is_locked(&lo->ldo_layout_mutex));

	/* XXX may be useless as not called for foreign LMV ?? */
	if (le32_to_cpu(lmv1->lmv_magic) == LMV_MAGIC_FOREIGN)
		RETURN(0);

	if (le32_to_cpu(lmv1->lmv_magic) == LMV_MAGIC_STRIPE) {
		lo->ldo_dir_slave_stripe = 1;
		RETURN(0);
	}

	if (!lmv_is_sane(lmv1))
		RETURN(-EINVAL);

	LASSERT(lo->ldo_stripe == NULL);
	OBD_ALLOC_PTR_ARRAY(stripe, le32_to_cpu(lmv1->lmv_stripe_count));
	if (stripe == NULL)
		RETURN(-ENOMEM);

	for (i = 0; i < le32_to_cpu(lmv1->lmv_stripe_count); i++) {
		struct dt_device	*tgt_dt;
		struct dt_object	*dto;
		int			type = LU_SEQ_RANGE_ANY;
		__u32			idx;

		fid_le_to_cpu(fid, &lmv1->lmv_stripe_fids[i]);
		if (!fid_is_sane(fid)) {
			stripe[i] = NULL;
			continue;
		}

		rc = lod_fld_lookup(env, lod, fid, &idx, &type);
		if (rc != 0)
			GOTO(out, rc);

		if (idx == lod2lu_dev(lod)->ld_site->ld_seq_site->ss_node_id) {
			tgt_dt = lod->lod_child;
		} else {
			struct lod_tgt_desc	*tgt;

			tgt = LTD_TGT(ltd, idx);
			if (tgt == NULL)
				GOTO(out, rc = -ESTALE);
			tgt_dt = tgt->ltd_tgt;
		}

		dto = dt_locate_at(env, tgt_dt, fid,
				  lo->ldo_obj.do_lu.lo_dev->ld_site->ls_top_dev,
				  NULL);
		if (IS_ERR(dto))
			GOTO(out, rc = PTR_ERR(dto));

		stripe[i] = dto;
	}
out:
	lo->ldo_stripe = stripe;
	lo->ldo_dir_stripe_count = le32_to_cpu(lmv1->lmv_stripe_count);
	lo->ldo_dir_stripes_allocated = le32_to_cpu(lmv1->lmv_stripe_count);
	lo->ldo_dir_layout_version = le32_to_cpu(lmv1->lmv_layout_version);
	lo->ldo_dir_migrate_offset = le32_to_cpu(lmv1->lmv_migrate_offset);
	lo->ldo_dir_migrate_hash = le32_to_cpu(lmv1->lmv_migrate_hash);
	lo->ldo_dir_hash_type = le32_to_cpu(lmv1->lmv_hash_type);
	if (rc != 0)
		lod_striping_free_nolock(env, lo);

	RETURN(rc);
}

/**
 * Declare create a striped directory.
 *
 * Declare creating a striped directory with a given stripe pattern on the
 * specified MDTs. A striped directory is represented as a regular directory
 * - an index listing all the stripes. The stripes point back to the master
 * object with ".." and LinkEA. The master object gets LMV EA which
 * identifies it as a striped directory. The function allocates FIDs
 * for all stripes.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[in] attr	attributes to initialize the objects with
 * \param[in] dof	type of objects to be created
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_dir_declare_create_stripes(const struct lu_env *env,
					  struct dt_object *dt,
					  struct lu_attr *attr,
					  struct dt_object_format *dof,
					  struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lu_buf		lmv_buf;
	struct lu_buf		slave_lmv_buf;
	struct lmv_mds_md_v1	*lmm;
	struct lmv_mds_md_v1	*slave_lmm = NULL;
	struct dt_insert_rec	*rec = &info->lti_dt_rec;
	struct lod_object	*lo = lod_dt_obj(dt);
	int			rc;
	__u32			i;
	ENTRY;

	rc = lod_prep_lmv_md(env, dt, &lmv_buf);
	if (rc != 0)
		GOTO(out, rc);
	lmm = lmv_buf.lb_buf;

	OBD_ALLOC_PTR(slave_lmm);
	if (slave_lmm == NULL)
		GOTO(out, rc = -ENOMEM);

	lod_prep_slave_lmv_md(slave_lmm, lmm);
	slave_lmv_buf.lb_buf = slave_lmm;
	slave_lmv_buf.lb_len = sizeof(*slave_lmm);

	if (!dt_try_as_dir(env, dt_object_child(dt)))
		GOTO(out, rc = -EINVAL);

	rec->rec_type = S_IFDIR;
	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		struct dt_object	*dto = lo->ldo_stripe[i];
		char			*stripe_name = info->lti_key;
		struct lu_name		*sname;
		struct linkea_data	 ldata		= { NULL };
		struct lu_buf		linkea_buf;

		/* OBD_FAIL_MDS_STRIPE_FID may leave stripe uninitialized */
		if (!dto)
			continue;

		/* directory split skip create for existing stripes */
		if (!(lod_is_splitting(lo) && i < lo->ldo_dir_split_offset)) {
			rc = lod_sub_declare_create(env, dto, attr, NULL, dof,
						    th);
			if (rc != 0)
				GOTO(out, rc);

			if (!dt_try_as_dir(env, dto))
				GOTO(out, rc = -EINVAL);

			rc = lod_sub_declare_ref_add(env, dto, th);
			if (rc != 0)
				GOTO(out, rc);

			rec->rec_fid = lu_object_fid(&dto->do_lu);
			rc = lod_sub_declare_insert(env, dto,
						    (const struct dt_rec *)rec,
						    (const struct dt_key *)dot,
						    th);
			if (rc != 0)
				GOTO(out, rc);

			/* master stripe FID will be put to .. */
			rec->rec_fid = lu_object_fid(&dt->do_lu);
			rc = lod_sub_declare_insert(env, dto,
						  (const struct dt_rec *)rec,
						  (const struct dt_key *)dotdot,
						  th);
			if (rc != 0)
				GOTO(out, rc);

			if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_NAME) &&
			    cfs_fail_val == i)
				snprintf(stripe_name, sizeof(info->lti_key),
					 DFID":%u",
					 PFID(lu_object_fid(&dto->do_lu)),
					 i + 1);
			else
				snprintf(stripe_name, sizeof(info->lti_key),
					 DFID":%u",
					 PFID(lu_object_fid(&dto->do_lu)), i);

			sname = lod_name_get(env, stripe_name,
					     strlen(stripe_name));
			rc = linkea_links_new(&ldata, &info->lti_linkea_buf,
					      sname, lu_object_fid(&dt->do_lu));
			if (rc != 0)
				GOTO(out, rc);

			linkea_buf.lb_buf = ldata.ld_buf->lb_buf;
			linkea_buf.lb_len = ldata.ld_leh->leh_len;
			rc = lod_sub_declare_xattr_set(env, dto, &linkea_buf,
						       XATTR_NAME_LINK, 0, th);
			if (rc != 0)
				GOTO(out, rc);

			rec->rec_fid = lu_object_fid(&dto->do_lu);
			rc = lod_sub_declare_insert(env, dt_object_child(dt),
					(const struct dt_rec *)rec,
					(const struct dt_key *)stripe_name, th);
			if (rc != 0)
				GOTO(out, rc);

			rc = lod_sub_declare_ref_add(env, dt_object_child(dt),
						     th);
			if (rc != 0)
				GOTO(out, rc);
		}

		if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_SLAVE_LMV) ||
		    cfs_fail_val != i) {
			if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_LMV) &&
			    cfs_fail_val == i)
				slave_lmm->lmv_master_mdt_index =
							cpu_to_le32(i + 1);
			else
				slave_lmm->lmv_master_mdt_index =
							cpu_to_le32(i);
			rc = lod_sub_declare_xattr_set(env, dto, &slave_lmv_buf,
						       XATTR_NAME_LMV, 0, th);
			if (rc != 0)
				GOTO(out, rc);
		}
	}

	rc = lod_sub_declare_xattr_set(env, dt_object_child(dt),
				       &lmv_buf, XATTR_NAME_LMV, 0, th);
	if (rc != 0)
		GOTO(out, rc);
out:
	if (slave_lmm != NULL)
		OBD_FREE_PTR(slave_lmm);

	RETURN(rc);
}

/**
 * Allocate a striping on a predefined set of MDTs.
 *
 * Allocates new striping using the MDT index range provided by the data from
 * the lum_obejcts contained in the lmv_user_md passed to this method if
 * \a is_specific is true; or allocates new layout starting from MDT index in
 * lo->ldo_dir_stripe_offset. The exact order of MDTs is not important and
 * varies depending on MDT status. The number of stripes needed and stripe
 * offset are taken from the object. If that number cannot be met, then the
 * function returns an error and then it's the caller's responsibility to
 * release the stripes allocated. All the internal structures are protected,
 * but no concurrent allocation is allowed on the same objects.
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lo		LOD object
 * \param[out] stripes		striping created
 * \param[out] mdt_indices	MDT indices of striping created
 * \param[in] is_specific	true if the MDTs are provided by lum; false if
 *				only the starting MDT index is provided
 *
 * \retval positive	stripes allocated, including the first stripe allocated
 *			outside
 * \retval negative	errno on failure
 */
static int lod_mdt_alloc_specific(const struct lu_env *env,
				  struct lod_object *lo,
				  struct dt_object **stripes,
				  __u32 *mdt_indices, bool is_specific)
{
	struct lod_device *lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct lu_tgt_descs *ltd = &lod->lod_mdt_descs;
	struct lu_tgt_desc *tgt = NULL;
	struct lu_object_conf conf = { .loc_flags = LOC_F_NEW };
	struct dt_device *tgt_dt = NULL;
	struct lu_fid fid = { 0 };
	struct dt_object *dto;
	u32 master_index;
	u32 stripe_count = lo->ldo_dir_stripe_count;
	int stripe_idx = 1;
	int j;
	int idx;
	int rc;

	master_index = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id;
	if (!is_specific && stripe_count > 1)
		/* Set the start index for the 2nd stripe allocation */
		mdt_indices[1] = (mdt_indices[0] + 1) %
					(lod->lod_remote_mdt_count + 1);

	for (; stripe_idx < stripe_count; stripe_idx++) {
		/* Try to find next avaible target */
		idx = mdt_indices[stripe_idx];
		for (j = 0; j < lod->lod_remote_mdt_count;
		     j++, idx = (idx + 1) % (lod->lod_remote_mdt_count + 1)) {
			bool already_allocated = false;
			__u32 k;

			CDEBUG(D_INFO, "try idx %d, mdt cnt %u, allocated %u\n",
			       idx, lod->lod_remote_mdt_count + 1, stripe_idx);

			if (likely(!is_specific &&
				   !OBD_FAIL_CHECK(OBD_FAIL_LARGE_STRIPE))) {
				/* check whether the idx already exists
				 * in current allocated array */
				for (k = 0; k < stripe_idx; k++) {
					if (mdt_indices[k] == idx) {
						already_allocated = true;
						break;
					}
				}

				if (already_allocated)
					continue;
			}

			/* Sigh, this index is not in the bitmap, let's check
			 * next available target */
			if (!test_bit(idx, ltd->ltd_tgt_bitmap) &&
			    idx != master_index)
				continue;

			if (idx == master_index) {
				/* Allocate the FID locally */
				tgt_dt = lod->lod_child;
				rc = dt_fid_alloc(env, tgt_dt, &fid, NULL,
						  NULL);
				if (rc < 0)
					continue;
				break;
			}

			/* check the status of the OSP */
			tgt = LTD_TGT(ltd, idx);
			if (!tgt)
				continue;

			tgt_dt = tgt->ltd_tgt;
			if (!tgt->ltd_active)
				/* this OSP doesn't feel well */
				continue;

			rc = dt_fid_alloc(env, tgt_dt, &fid, NULL, NULL);
			if (rc < 0)
				continue;

			break;
		}

		/* Can not allocate more stripes */
		if (j == lod->lod_remote_mdt_count) {
			CDEBUG(D_INFO, "%s: require stripes %u only get %d\n",
			       lod2obd(lod)->obd_name, stripe_count,
			       stripe_idx);
			break;
		}

		CDEBUG(D_INFO, "Get idx %d, for stripe %d "DFID"\n",
		       idx, stripe_idx, PFID(&fid));
		mdt_indices[stripe_idx] = idx;
		/* Set the start index for next stripe allocation */
		if (!is_specific && stripe_idx < stripe_count - 1) {
			/*
			 * for large dir test, put all other slaves on one
			 * remote MDT, otherwise we may save too many local
			 * slave locks which will exceed RS_MAX_LOCKS.
			 */
			if (unlikely(OBD_FAIL_CHECK(OBD_FAIL_LARGE_STRIPE)))
				idx = master_index;
			mdt_indices[stripe_idx + 1] = (idx + 1) %
					   (lod->lod_remote_mdt_count + 1);
		}
		/* tgt_dt and fid must be ready after search avaible OSP
		 * in the above loop */
		LASSERT(tgt_dt != NULL);
		LASSERT(fid_is_sane(&fid));

		/* fail a remote stripe FID allocation */
		if (stripe_idx && OBD_FAIL_CHECK(OBD_FAIL_MDS_STRIPE_FID))
			continue;

		dto = dt_locate_at(env, tgt_dt, &fid,
				  lo->ldo_obj.do_lu.lo_dev->ld_site->ls_top_dev,
				  &conf);
		if (IS_ERR(dto)) {
			rc = PTR_ERR(dto);
			goto error;
		}

		stripes[stripe_idx] = dto;
	}

	return stripe_idx;

error:
	for (j = 1; j < stripe_idx; j++) {
		LASSERT(stripes[j] != NULL);
		dt_object_put(env, stripes[j]);
		stripes[j] = NULL;
	}
	return rc;
}

static int lod_prep_md_striped_create(const struct lu_env *env,
				      struct dt_object *dt,
				      struct lu_attr *attr,
				      const struct lmv_user_md_v1 *lum,
				      struct dt_object_format *dof,
				      struct thandle *th)
{
	struct lod_device *lod = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object **stripes;
	struct lu_object_conf conf = { .loc_flags = LOC_F_NEW };
	struct lu_fid fid = { 0 };
	__u32 stripe_count;
	int i;
	int rc = 0;

	ENTRY;

	/* The lum has been verifed in lod_verify_md_striping */
	LASSERT(le32_to_cpu(lum->lum_magic) == LMV_USER_MAGIC ||
		le32_to_cpu(lum->lum_magic) == LMV_USER_MAGIC_SPECIFIC);

	stripe_count = lo->ldo_dir_stripe_count;

	OBD_ALLOC_PTR_ARRAY(stripes, stripe_count);
	if (!stripes)
		RETURN(-ENOMEM);

	/* Allocate the first stripe locally */
	rc = dt_fid_alloc(env, lod->lod_child, &fid, NULL, NULL);
	if (rc < 0)
		GOTO(out, rc);

	stripes[0] = dt_locate_at(env, lod->lod_child, &fid,
				  dt->do_lu.lo_dev->ld_site->ls_top_dev, &conf);
	if (IS_ERR(stripes[0]))
		GOTO(out, rc = PTR_ERR(stripes[0]));

	if (lo->ldo_dir_stripe_offset == LMV_OFFSET_DEFAULT) {
		lod_qos_statfs_update(env, lod, &lod->lod_mdt_descs);
		rc = lod_mdt_alloc_qos(env, lo, stripes, 1, stripe_count);
		if (rc == -EAGAIN)
			rc = lod_mdt_alloc_rr(env, lo, stripes, 1,
					      stripe_count);
	} else {
		int *idx_array;
		bool is_specific = false;

		OBD_ALLOC_PTR_ARRAY(idx_array, stripe_count);
		if (!idx_array)
			GOTO(out, rc = -ENOMEM);

		if (le32_to_cpu(lum->lum_magic) == LMV_USER_MAGIC_SPECIFIC) {
			is_specific = true;
			for (i = 0; i < stripe_count; i++)
				idx_array[i] =
				       le32_to_cpu(lum->lum_objects[i].lum_mds);
		}

		/* stripe 0 is local */
		idx_array[0] =
			lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id;
		rc = lod_mdt_alloc_specific(env, lo, stripes, idx_array,
					    is_specific);
		OBD_FREE_PTR_ARRAY(idx_array, stripe_count);
	}

	if (rc < 0)
		GOTO(out, rc);

	LASSERT(rc > 0);

	lo->ldo_dir_striped = 1;
	lo->ldo_stripe = stripes;
	lo->ldo_dir_stripe_count = rc;
	lo->ldo_dir_stripes_allocated = stripe_count;
	smp_mb();
	lo->ldo_dir_stripe_loaded = 1;

	rc = lod_dir_declare_create_stripes(env, dt, attr, dof, th);
	if (rc < 0)
		lod_striping_free(env, lo);

	RETURN(rc);

out:
	LASSERT(rc < 0);
	if (!IS_ERR_OR_NULL(stripes[0]))
		dt_object_put(env, stripes[0]);
	for (i = 1; i < stripe_count; i++)
		LASSERT(!stripes[i]);
	OBD_FREE_PTR_ARRAY(stripes, stripe_count);

	return rc;
}

/**
 *
 * Alloc cached foreign LMV
 *
 * \param[in] lo        object
 * \param[in] size      size of foreign LMV
 *
 * \retval              0 on success
 * \retval              negative if failed
 */
int lod_alloc_foreign_lmv(struct lod_object *lo, size_t size)
{
	OBD_ALLOC_LARGE(lo->ldo_foreign_lmv, size);
	if (lo->ldo_foreign_lmv == NULL)
		return -ENOMEM;
	lo->ldo_foreign_lmv_size = size;
	lo->ldo_dir_is_foreign = 1;

	return 0;
}

/**
 * Declare create striped md object.
 *
 * The function declares intention to create a striped directory. This is a
 * wrapper for lod_prep_md_striped_create(). The only additional functionality
 * is to verify pattern \a lum_buf is good. Check that function for the details.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[in] attr	attributes to initialize the objects with
 * \param[in] lum_buf	a pattern specifying the number of stripes and
 *			MDT to start from
 * \param[in] dof	type of objects to be created
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 *
 */
static int lod_declare_xattr_set_lmv(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lu_attr *attr,
				     const struct lu_buf *lum_buf,
				     struct dt_object_format *dof,
				     struct thandle *th)
{
	struct lod_object	*lo = lod_dt_obj(dt);
	struct lmv_user_md_v1	*lum = lum_buf->lb_buf;
	int			rc;
	ENTRY;

	LASSERT(lum != NULL);

	CDEBUG(D_INFO, "lum magic = %x count = %u offset = %d\n",
	       le32_to_cpu(lum->lum_magic), le32_to_cpu(lum->lum_stripe_count),
	       (int)le32_to_cpu(lum->lum_stripe_offset));

	if (lo->ldo_dir_stripe_count == 0) {
		if (lo->ldo_dir_is_foreign) {
			rc = lod_alloc_foreign_lmv(lo, lum_buf->lb_len);
			if (rc != 0)
				GOTO(out, rc);
			memcpy(lo->ldo_foreign_lmv, lum, lum_buf->lb_len);
			lo->ldo_dir_stripe_loaded = 1;
		}
		GOTO(out, rc = 0);
	}

	/* prepare dir striped objects */
	rc = lod_prep_md_striped_create(env, dt, attr, lum, dof, th);
	if (rc != 0) {
		/* failed to create striping, let's reset
		 * config so that others don't get confused */
		lod_striping_free(env, lo);
		GOTO(out, rc);
	}
out:
	RETURN(rc);
}

/**
 * Set or replace striped directory layout, and LFSCK may set layout on a plain
 * directory, so don't check stripe count.
 *
 * \param[in] env	execution environment
 * \param[in] dt	target object
 * \param[in] buf	LMV buf which contains source stripe fids
 * \param[in] fl	set or replace
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_dir_layout_set(const struct lu_env *env,
			      struct dt_object *dt,
			      const struct lu_buf *buf,
			      int fl,
			      struct thandle *th)
{
	struct dt_object *next = dt_object_child(dt);
	struct lod_object *lo = lod_dt_obj(dt);
	struct lod_device *lod = lu2lod_dev(lod2lu_obj(lo)->lo_dev);
	struct lmv_mds_md_v1 *lmv = buf->lb_buf;
	struct lmv_mds_md_v1 *slave_lmv;
	struct lu_buf slave_buf;
	int i;
	int rc;

	ENTRY;

	if (!lmv_is_sane2(lmv))
		RETURN(-EINVAL);

	/* adjust hash for dir merge, which may not be set in user command */
	if (lmv_is_merging(lmv) && !lmv->lmv_migrate_hash)
		lmv->lmv_merge_hash =
			lod->lod_mdt_descs.ltd_lmv_desc.ld_pattern;

	LMV_DEBUG(D_INFO, lmv, "set");

	rc = lod_sub_xattr_set(env, next, buf, XATTR_NAME_LMV, fl, th);
	if (rc)
		RETURN(rc);

	/* directory restripe may update stripe LMV directly */
	if (!lo->ldo_dir_stripe_count)
		RETURN(0);

	lo->ldo_dir_hash_type = le32_to_cpu(lmv->lmv_hash_type);
	lo->ldo_dir_migrate_offset = le32_to_cpu(lmv->lmv_migrate_offset);
	lo->ldo_dir_migrate_hash = le32_to_cpu(lmv->lmv_migrate_hash);
	lo->ldo_dir_layout_version = le32_to_cpu(lmv->lmv_layout_version);

	OBD_ALLOC_PTR(slave_lmv);
	if (!slave_lmv)
		RETURN(-ENOMEM);

	lod_prep_slave_lmv_md(slave_lmv, lmv);
	slave_buf.lb_buf = slave_lmv;
	slave_buf.lb_len = sizeof(*slave_lmv);

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		if (!lo->ldo_stripe[i])
			continue;

		if (!dt_object_exists(lo->ldo_stripe[i]))
			continue;

		rc = lod_sub_xattr_set(env, lo->ldo_stripe[i], &slave_buf,
				       XATTR_NAME_LMV, fl, th);
		if (rc)
			break;
	}

	OBD_FREE_PTR(slave_lmv);

	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_declare_xattr_set.
 *
 * Used with regular (non-striped) objects. Basically it
 * initializes the striping information and applies the
 * change to all the stripes.
 *
 * \see dt_object_operations::do_declare_xattr_set() in the API description
 * for details.
 */
static int lod_dir_declare_xattr_set(const struct lu_env *env,
				     struct dt_object *dt,
				     const struct lu_buf *buf,
				     const char *name, int fl,
				     struct thandle *th)
{
	struct dt_object	*next = dt_object_child(dt);
	struct lod_device	*d = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object	*lo = lod_dt_obj(dt);
	int			i;
	int			rc;
	ENTRY;

	if (strcmp(name, XATTR_NAME_DEFAULT_LMV) == 0) {
		struct lmv_user_md_v1 *lum;

		LASSERT(buf != NULL && buf->lb_buf != NULL);
		lum = buf->lb_buf;
		rc = lod_verify_md_striping(d, lum);
		if (rc != 0)
			RETURN(rc);
	} else if (strcmp(name, XATTR_NAME_LOV) == 0) {
		rc = lod_verify_striping(env, d, lo, buf, false);
		if (rc != 0)
			RETURN(rc);
	}

	rc = lod_sub_declare_xattr_set(env, next, buf, name, fl, th);
	if (rc != 0)
		RETURN(rc);

	/* Note: Do not set LinkEA on sub-stripes, otherwise
	 * it will confuse the fid2path process(see mdt_path_current()).
	 * The linkEA between master and sub-stripes is set in
	 * lod_xattr_set_lmv(). */
	if (strcmp(name, XATTR_NAME_LINK) == 0)
		RETURN(0);

	/* set xattr to each stripes, if needed */
	rc = lod_striping_load(env, lo);
	if (rc != 0)
		RETURN(rc);

	if (lo->ldo_dir_stripe_count == 0)
		RETURN(0);

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		if (!lo->ldo_stripe[i])
			continue;

		if (!dt_object_exists(lo->ldo_stripe[i]))
			continue;

		rc = lod_sub_declare_xattr_set(env, lo->ldo_stripe[i],
					       buf, name, fl, th);
		if (rc != 0)
			break;
	}

	RETURN(rc);
}

static int
lod_obj_stripe_replace_parent_fid_cb(const struct lu_env *env,
				     struct lod_object *lo,
				     struct dt_object *dt, struct thandle *th,
				     int comp_idx, int stripe_idx,
				     struct lod_obj_stripe_cb_data *data)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_layout_component *comp = &lo->ldo_comp_entries[comp_idx];
	struct filter_fid *ff = &info->lti_ff;
	struct lu_buf *buf = &info->lti_buf;
	int rc;

	buf->lb_buf = ff;
	buf->lb_len = sizeof(*ff);
	rc = dt_xattr_get(env, dt, buf, XATTR_NAME_FID);
	if (rc < 0) {
		if (rc == -ENODATA)
			return 0;
		return rc;
	}

	/*
	 * locd_buf is set if it's called by dir migration, which doesn't check
	 * pfid and comp id.
	 */
	if (data->locd_buf) {
		memset(ff, 0, sizeof(*ff));
		ff->ff_parent = *(struct lu_fid *)data->locd_buf->lb_buf;
	} else {
		filter_fid_le_to_cpu(ff, ff, sizeof(*ff));

		if (lu_fid_eq(lod_object_fid(lo), &ff->ff_parent) &&
		    ff->ff_layout.ol_comp_id == comp->llc_id)
			return 0;

		memset(ff, 0, sizeof(*ff));
		ff->ff_parent = *lu_object_fid(&lo->ldo_obj.do_lu);
	}

	/* rewrite filter_fid */
	ff->ff_parent.f_ver = stripe_idx;
	ff->ff_layout.ol_stripe_size = comp->llc_stripe_size;
	ff->ff_layout.ol_stripe_count = comp->llc_stripe_count;
	ff->ff_layout.ol_comp_id = comp->llc_id;
	ff->ff_layout.ol_comp_start = comp->llc_extent.e_start;
	ff->ff_layout.ol_comp_end = comp->llc_extent.e_end;
	filter_fid_cpu_to_le(ff, ff, sizeof(*ff));

	if (data->locd_declare)
		rc = lod_sub_declare_xattr_set(env, dt, buf, XATTR_NAME_FID,
					       LU_XATTR_REPLACE, th);
	else
		rc = lod_sub_xattr_set(env, dt, buf, XATTR_NAME_FID,
				       LU_XATTR_REPLACE, th);

	return rc;
}

/**
 * Reset parent FID on OST object
 *
 * Replace parent FID with @dt object FID, which is only called during migration
 * to reset the parent FID after the MDT object is migrated to the new MDT, i.e.
 * the FID is changed.
 *
 * \param[in] env execution environment
 * \param[in] dt dt_object whose stripes's parent FID will be reset
 * \parem[in] th thandle
 * \param[in] declare if it is declare
 *
 * \retval	0 if reset succeeds
 * \retval	negative errno if reset fails
 */
static int lod_replace_parent_fid(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct lu_buf *buf,
				  struct thandle *th, bool declare)
{
	struct lod_object *lo = lod_dt_obj(dt);
	struct lod_thread_info	*info = lod_env_info(env);
	struct filter_fid *ff;
	struct lod_obj_stripe_cb_data data = { { 0 } };
	int rc;
	ENTRY;

	LASSERT(S_ISREG(dt->do_lu.lo_header->loh_attr));

	/* set xattr to each stripes, if needed */
	rc = lod_striping_load(env, lo);
	if (rc != 0)
		RETURN(rc);

	if (!lod_obj_is_striped(dt))
		RETURN(0);

	if (info->lti_ea_store_size < sizeof(*ff)) {
		rc = lod_ea_store_resize(info, sizeof(*ff));
		if (rc != 0)
			RETURN(rc);
	}

	data.locd_declare = declare;
	data.locd_stripe_cb = lod_obj_stripe_replace_parent_fid_cb;
	data.locd_buf = buf;
	rc = lod_obj_for_each_stripe(env, lo, th, &data);

	RETURN(rc);
}

__u16 lod_comp_entry_stripe_count(struct lod_object *lo,
				  int comp_idx, bool is_dir)
{
	struct lod_device *lod = lu2lod_dev(lod2lu_obj(lo)->lo_dev);
	struct lod_layout_component *entry;

	if (is_dir)
		return  0;

	entry = &lo->ldo_comp_entries[comp_idx];
	if (lod_comp_inited(entry))
		return entry->llc_stripe_count;
	else if ((__u16)-1 == entry->llc_stripe_count)
		return lod->lod_ost_count;
	else
		return lod_get_stripe_count(lod, lo, comp_idx,
					    entry->llc_stripe_count, false);
}

static int lod_comp_md_size(struct lod_object *lo, bool is_dir)
{
	int magic, size = 0, i;
	struct lod_layout_component *comp_entries;
	__u16 comp_cnt;
	bool is_composite, is_foreign = false;

	if (is_dir) {
		comp_cnt = lo->ldo_def_striping->lds_def_comp_cnt;
		comp_entries = lo->ldo_def_striping->lds_def_comp_entries;
		is_composite =
			lo->ldo_def_striping->lds_def_striping_is_composite;
	} else {
		comp_cnt = lo->ldo_comp_cnt;
		comp_entries = lo->ldo_comp_entries;
		is_composite = lo->ldo_is_composite;
		is_foreign = lo->ldo_is_foreign;
	}

	if (is_foreign)
		return lo->ldo_foreign_lov_size;

	LASSERT(comp_cnt != 0 && comp_entries != NULL);
	if (is_composite) {
		size = sizeof(struct lov_comp_md_v1) +
		       sizeof(struct lov_comp_md_entry_v1) * comp_cnt;
		LASSERT(size % sizeof(__u64) == 0);
	}

	for (i = 0; i < comp_cnt; i++) {
		__u16 stripe_count;

		magic = comp_entries[i].llc_pool ? LOV_MAGIC_V3 : LOV_MAGIC_V1;
		stripe_count = lod_comp_entry_stripe_count(lo, i, is_dir);
		if (!is_dir && is_composite)
			lod_comp_shrink_stripe_count(&comp_entries[i],
						     &stripe_count);

		size += lov_user_md_size(stripe_count, magic);
		LASSERT(size % sizeof(__u64) == 0);
	}
	return size;
}

/**
 * Declare component add. The xattr name is XATTR_LUSTRE_LOV.add, and
 * the xattr value is binary lov_comp_md_v1 which contains component(s)
 * to be added.
  *
 * \param[in] env	execution environment
 * \param[in] dt	dt_object to add components on
 * \param[in] buf	buffer contains components to be added
 * \parem[in] th	thandle
 *
 * \retval	0 on success
 * \retval	negative errno on failure
 */
static int lod_declare_layout_add(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct lu_buf *buf,
				  struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_layout_component *comp_array, *lod_comp, *old_array;
	struct lod_device *d = lu2lod_dev(dt->do_lu.lo_dev);
	struct dt_object *next = dt_object_child(dt);
	struct lov_desc	*desc = &d->lod_ost_descs.ltd_lov_desc;
	struct lod_object *lo = lod_dt_obj(dt);
	struct lov_user_md_v3 *v3;
	struct lov_comp_md_v1 *comp_v1 = buf->lb_buf;
	__u32 magic;
	int i, rc, array_cnt, old_array_cnt;
	ENTRY;

	LASSERT(lo->ldo_is_composite);

	if (lo->ldo_flr_state != LCM_FL_NONE)
		RETURN(-EBUSY);

	rc = lod_verify_striping(env, d, lo, buf, false);
	if (rc != 0)
		RETURN(rc);

	magic = comp_v1->lcm_magic;
	if (magic == __swab32(LOV_USER_MAGIC_COMP_V1)) {
		lustre_swab_lov_comp_md_v1(comp_v1);
		magic = comp_v1->lcm_magic;
	}

	if (magic != LOV_USER_MAGIC_COMP_V1)
		RETURN(-EINVAL);

	mutex_lock(&lo->ldo_layout_mutex);

	array_cnt = lo->ldo_comp_cnt + comp_v1->lcm_entry_count;
	OBD_ALLOC_PTR_ARRAY(comp_array, array_cnt);
	if (comp_array == NULL) {
		mutex_unlock(&lo->ldo_layout_mutex);
		RETURN(-ENOMEM);
	}


	memcpy(comp_array, lo->ldo_comp_entries,
	       sizeof(*comp_array) * lo->ldo_comp_cnt);

	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		struct lov_user_md_v1 *v1;
		struct lu_extent *ext;

		v1 = (struct lov_user_md *)((char *)comp_v1 +
				comp_v1->lcm_entries[i].lcme_offset);
		ext = &comp_v1->lcm_entries[i].lcme_extent;

		lod_comp = &comp_array[lo->ldo_comp_cnt + i];
		lod_comp->llc_extent.e_start = ext->e_start;
		lod_comp->llc_extent.e_end = ext->e_end;
		lod_comp->llc_stripe_offset = v1->lmm_stripe_offset;
		lod_comp->llc_flags = comp_v1->lcm_entries[i].lcme_flags;

		lod_comp->llc_stripe_count = v1->lmm_stripe_count;
		lod_comp->llc_stripe_size = v1->lmm_stripe_size;
		lod_adjust_stripe_info(lod_comp, desc, 0);

		if (v1->lmm_magic == LOV_USER_MAGIC_V3) {
			v3 = (struct lov_user_md_v3 *) v1;
			if (v3->lmm_pool_name[0] != '\0') {
				rc = lod_set_pool(&lod_comp->llc_pool,
						  v3->lmm_pool_name);
				if (rc)
					GOTO(error, rc);
			}
		}
	}

	old_array = lo->ldo_comp_entries;
	old_array_cnt = lo->ldo_comp_cnt;

	lo->ldo_comp_entries = comp_array;
	lo->ldo_comp_cnt = array_cnt;

	/* No need to increase layout generation here, it will be increased
	 * later when generating component ID for the new components */

	info->lti_buf.lb_len = lod_comp_md_size(lo, false);
	rc = lod_sub_declare_xattr_set(env, next, &info->lti_buf,
					      XATTR_NAME_LOV, 0, th);
	if (rc) {
		lo->ldo_comp_entries = old_array;
		lo->ldo_comp_cnt = old_array_cnt;
		GOTO(error, rc);
	}

	OBD_FREE_PTR_ARRAY(old_array, old_array_cnt);

	LASSERT(lo->ldo_mirror_count == 1);
	lo->ldo_mirrors[0].lme_end = array_cnt - 1;

	mutex_unlock(&lo->ldo_layout_mutex);

	RETURN(0);

error:
	for (i = lo->ldo_comp_cnt; i < array_cnt; i++) {
		lod_comp = &comp_array[i];
		if (lod_comp->llc_pool != NULL) {
			OBD_FREE(lod_comp->llc_pool,
				 strlen(lod_comp->llc_pool) + 1);
			lod_comp->llc_pool = NULL;
		}
	}
	OBD_FREE_PTR_ARRAY(comp_array, array_cnt);
	mutex_unlock(&lo->ldo_layout_mutex);

	RETURN(rc);
}

/**
 * lod_last_non_stale_mirror() - Check if a mirror is the last non-stale mirror.
 * @mirror_id: Mirror id to be checked.
 * @lo:        LOD object.
 *
 * This function checks if a mirror with specified @mirror_id is the last
 * non-stale mirror of a LOD object @lo.
 *
 * Return: true or false.
 */
static inline
bool lod_last_non_stale_mirror(__u16 mirror_id, struct lod_object *lo)
{
	struct lod_layout_component *lod_comp;
	bool has_stale_flag;
	int i;

	for (i = 0; i < lo->ldo_mirror_count; i++) {
		if (lo->ldo_mirrors[i].lme_id == mirror_id ||
		    lo->ldo_mirrors[i].lme_stale)
			continue;

		has_stale_flag = false;
		lod_foreach_mirror_comp(lod_comp, lo, i) {
			if (lod_comp->llc_flags & LCME_FL_STALE) {
				has_stale_flag = true;
				break;
			}
		}
		if (!has_stale_flag)
			return false;
	}

	return true;
}

/**
 * Declare component set. The xattr is name XATTR_LUSTRE_LOV.set.$field,
 * the '$field' can only be 'flags' now. The xattr value is binary
 * lov_comp_md_v1 which contains the component ID(s) and the value of
 * the field to be modified.
 * Please update allowed_lustre_lov macro if $field groks more values
 * in the future.
 *
 * \param[in] env	execution environment
 * \param[in] dt	dt_object to be modified
 * \param[in] op	operation string, like "set.flags"
 * \param[in] buf	buffer contains components to be set
 * \parem[in] th	thandle
 *
 * \retval	0 on success
 * \retval	negative errno on failure
 */
static int lod_declare_layout_set(const struct lu_env *env,
				  struct dt_object *dt,
				  char *op, const struct lu_buf *buf,
				  struct thandle *th)
{
	struct lod_layout_component	*lod_comp;
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_device	*d = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object	*lo = lod_dt_obj(dt);
	struct lov_comp_md_v1	*comp_v1 = buf->lb_buf;
	__u32	magic;
	int	i, j, rc;
	bool	changed = false;
	ENTRY;

	/* Please update allowed_lustre_lov macro if op
	 * groks more values in the future
	 */
	if (strcmp(op, "set.flags") != 0) {
		CDEBUG(D_LAYOUT, "%s: operation (%s) not supported.\n",
		       lod2obd(d)->obd_name, op);
		RETURN(-ENOTSUPP);
	}

	magic = comp_v1->lcm_magic;
	if (magic == __swab32(LOV_USER_MAGIC_COMP_V1)) {
		lustre_swab_lov_comp_md_v1(comp_v1);
		magic = comp_v1->lcm_magic;
	}

	if (magic != LOV_USER_MAGIC_COMP_V1)
		RETURN(-EINVAL);

	if (comp_v1->lcm_entry_count == 0) {
		CDEBUG(D_LAYOUT, "%s: entry count is zero.\n",
		       lod2obd(d)->obd_name);
		RETURN(-EINVAL);
	}

	mutex_lock(&lo->ldo_layout_mutex);
	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		__u32 id = comp_v1->lcm_entries[i].lcme_id;
		__u32 flags = comp_v1->lcm_entries[i].lcme_flags;
		__u32 mirror_flag = flags & LCME_MIRROR_FLAGS;
		__u16 mirror_id = mirror_id_of(id);
		bool neg = flags & LCME_FL_NEG;

		if (flags & LCME_FL_INIT) {
			if (changed)
				lod_striping_free_nolock(env, lo);
			mutex_unlock(&lo->ldo_layout_mutex);
			RETURN(-EINVAL);
		}

		flags &= ~(LCME_MIRROR_FLAGS | LCME_FL_NEG);
		for (j = 0; j < lo->ldo_comp_cnt; j++) {
			lod_comp = &lo->ldo_comp_entries[j];

			/* lfs only put one flag in each entry */
			if ((flags && id != lod_comp->llc_id) ||
			    (mirror_flag && mirror_id !=
					    mirror_id_of(lod_comp->llc_id)))
				continue;

			if (neg) {
				if (flags)
					lod_comp->llc_flags &= ~flags;
				if (mirror_flag)
					lod_comp->llc_flags &= ~mirror_flag;
			} else {
				if (flags) {
					if ((flags & LCME_FL_STALE) &&
					    lod_last_non_stale_mirror(mirror_id,
								      lo)) {
						mutex_unlock(
							&lo->ldo_layout_mutex);
						RETURN(-EUCLEAN);
					}
					lod_comp->llc_flags |= flags;
				}
				if (mirror_flag) {
					lod_comp->llc_flags |= mirror_flag;
					if (mirror_flag & LCME_FL_NOSYNC)
						lod_comp->llc_timestamp =
						       ktime_get_real_seconds();
				}
			}
			changed = true;
		}
	}
	mutex_unlock(&lo->ldo_layout_mutex);

	if (!changed) {
		CDEBUG(D_LAYOUT, "%s: requested component(s) not found.\n",
		       lod2obd(d)->obd_name);
		RETURN(-EINVAL);
	}

	lod_obj_inc_layout_gen(lo);

	info->lti_buf.lb_len = lod_comp_md_size(lo, false);
	rc = lod_sub_declare_xattr_set(env, dt_object_child(dt), &info->lti_buf,
				       XATTR_NAME_LOV, LU_XATTR_REPLACE, th);
	RETURN(rc);
}

/**
 * Declare component deletion. The xattr name is XATTR_LUSTRE_LOV.del,
 * and the xattr value is a unique component ID or a special lcme_id.
 *
 * \param[in] env	execution environment
 * \param[in] dt	dt_object to be operated on
 * \param[in] buf	buffer contains component ID or lcme_id
 * \parem[in] th	thandle
 *
 * \retval	0 on success
 * \retval	negative errno on failure
 */
static int lod_declare_layout_del(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct lu_buf *buf,
				  struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct dt_object *next = dt_object_child(dt);
	struct lod_device *d = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object *lo = lod_dt_obj(dt);
	struct lu_attr *attr = &lod_env_info(env)->lti_attr;
	struct lov_comp_md_v1 *comp_v1 = buf->lb_buf;
	__u32 magic, id, flags, neg_flags = 0;
	int rc, i, j, left;
	ENTRY;

	LASSERT(lo->ldo_is_composite);

	if (lo->ldo_flr_state != LCM_FL_NONE)
		RETURN(-EBUSY);

	magic = comp_v1->lcm_magic;
	if (magic == __swab32(LOV_USER_MAGIC_COMP_V1)) {
		lustre_swab_lov_comp_md_v1(comp_v1);
		magic = comp_v1->lcm_magic;
	}

	if (magic != LOV_USER_MAGIC_COMP_V1)
		RETURN(-EINVAL);

	id = comp_v1->lcm_entries[0].lcme_id;
	flags = comp_v1->lcm_entries[0].lcme_flags;

	if (id > LCME_ID_MAX || (flags & ~LCME_KNOWN_FLAGS)) {
		CDEBUG(D_LAYOUT, "%s: invalid component id %#x, flags %#x\n",
		       lod2obd(d)->obd_name, id, flags);
		RETURN(-EINVAL);
	}

	if (id != LCME_ID_INVAL && flags != 0) {
		CDEBUG(D_LAYOUT, "%s: specified both id and flags.\n",
		       lod2obd(d)->obd_name);
		RETURN(-EINVAL);
	}

	if (id == LCME_ID_INVAL && !flags) {
		CDEBUG(D_LAYOUT, "%s: no id or flags specified.\n",
		       lod2obd(d)->obd_name);
		RETURN(-EINVAL);
	}

	if (flags & LCME_FL_NEG) {
		neg_flags = flags & ~LCME_FL_NEG;
		flags = 0;
	}

	mutex_lock(&lo->ldo_layout_mutex);

	left = lo->ldo_comp_cnt;
	if (left <= 0) {
		mutex_unlock(&lo->ldo_layout_mutex);
		RETURN(-EINVAL);
	}

	for (i = (lo->ldo_comp_cnt - 1); i >= 0; i--) {
		struct lod_layout_component *lod_comp;

		lod_comp = &lo->ldo_comp_entries[i];

		if (id != LCME_ID_INVAL && id != lod_comp->llc_id)
			continue;
		else if (flags && !(flags & lod_comp->llc_flags))
			continue;
		else if (neg_flags && (neg_flags & lod_comp->llc_flags))
			continue;

		if (left != (i + 1)) {
			CDEBUG(D_LAYOUT, "%s: this deletion will create "
			       "a hole.\n", lod2obd(d)->obd_name);
			mutex_unlock(&lo->ldo_layout_mutex);
			RETURN(-EINVAL);
		}
		left--;

		/* Mark the component as deleted */
		lod_comp->llc_id = LCME_ID_INVAL;

		/* Not instantiated component */
		if (lod_comp->llc_stripe == NULL)
			continue;

		LASSERT(lod_comp->llc_stripe_count > 0);
		for (j = 0; j < lod_comp->llc_stripe_count; j++) {
			struct dt_object *obj = lod_comp->llc_stripe[j];

			if (obj == NULL)
				continue;
			rc = lod_sub_declare_destroy(env, obj, th);
			if (rc) {
				mutex_unlock(&lo->ldo_layout_mutex);
				RETURN(rc);
			}
		}
	}

	LASSERTF(left >= 0, "left = %d\n", left);
	if (left == lo->ldo_comp_cnt) {
		CDEBUG(D_LAYOUT, "%s: requested component id:%#x not found\n",
		       lod2obd(d)->obd_name, id);
		mutex_unlock(&lo->ldo_layout_mutex);
		RETURN(-EINVAL);
	}

	mutex_unlock(&lo->ldo_layout_mutex);

	memset(attr, 0, sizeof(*attr));
	attr->la_valid = LA_SIZE;
	rc = lod_sub_declare_attr_set(env, next, attr, th);
	if (rc)
		RETURN(rc);

	if (left > 0) {
		info->lti_buf.lb_len = lod_comp_md_size(lo, false);
		rc = lod_sub_declare_xattr_set(env, next, &info->lti_buf,
					       XATTR_NAME_LOV, 0, th);
	} else {
		rc = lod_sub_declare_xattr_del(env, next, XATTR_NAME_LOV, th);
	}

	RETURN(rc);
}

/**
 * Declare layout add/set/del operations issued by special xattr names:
 *
 * XATTR_LUSTRE_LOV.add		add component(s) to existing file
 * XATTR_LUSTRE_LOV.del		delete component(s) from existing file
 * XATTR_LUSTRE_LOV.set.$field	set specified field of certain component(s)
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[in] name	name of xattr
 * \param[in] buf	lu_buf contains xattr value
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_declare_modify_layout(const struct lu_env *env,
				     struct dt_object *dt,
				     const char *name,
				     const struct lu_buf *buf,
				     struct thandle *th)
{
	struct lod_device *d = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object *lo = lod_dt_obj(dt);
	char *op;
	int rc, len = strlen(XATTR_LUSTRE_LOV);
	ENTRY;

	LASSERT(dt_object_exists(dt));

	if (strlen(name) <= len || name[len] != '.') {
		CDEBUG(D_LAYOUT, "%s: invalid xattr name: %s\n",
		       lod2obd(d)->obd_name, name);
		RETURN(-EINVAL);
	}
	len++;

	rc = lod_striping_load(env, lo);
	if (rc)
		GOTO(unlock, rc);

	/* the layout to be modified must be a composite layout */
	if (!lo->ldo_is_composite) {
		CDEBUG(D_LAYOUT, "%s: object "DFID" isn't a composite file.\n",
		       lod2obd(d)->obd_name, PFID(lu_object_fid(&dt->do_lu)));
		GOTO(unlock, rc = -EINVAL);
	}

	op = (char *)name + len;
	if (strcmp(op, "add") == 0) {
		rc = lod_declare_layout_add(env, dt, buf, th);
	} else if (strcmp(op, "del") == 0) {
		rc = lod_declare_layout_del(env, dt, buf, th);
	} else if (strncmp(op, "set", strlen("set")) == 0) {
		rc = lod_declare_layout_set(env, dt, op, buf, th);
	} else  {
		CDEBUG(D_LAYOUT, "%s: unsupported xattr name:%s\n",
		       lod2obd(d)->obd_name, name);
		GOTO(unlock, rc = -ENOTSUPP);
	}
unlock:
	if (rc)
		lod_striping_free(env, lo);

	RETURN(rc);
}

/**
 * Convert a plain file lov_mds_md to a composite layout.
 *
 * \param[in,out] info	the thread info::lti_ea_store buffer contains little
 *			endian plain file layout
 *
 * \retval		0 on success, <0 on failure
 */
static int lod_layout_convert(struct lod_thread_info *info)
{
	struct lov_mds_md *lmm = info->lti_ea_store;
	struct lov_mds_md *lmm_save;
	struct lov_comp_md_v1 *lcm;
	struct lov_comp_md_entry_v1 *lcme;
	size_t size;
	__u32 blob_size;
	int rc = 0;
	ENTRY;

	/* realloc buffer to a composite layout which contains one component */
	blob_size = lov_mds_md_size(le16_to_cpu(lmm->lmm_stripe_count),
				    le32_to_cpu(lmm->lmm_magic));
	size = sizeof(*lcm) + sizeof(*lcme) + blob_size;

	OBD_ALLOC_LARGE(lmm_save, blob_size);
	if (!lmm_save)
		GOTO(out, rc = -ENOMEM);

	memcpy(lmm_save, lmm, blob_size);

	if (info->lti_ea_store_size < size) {
		rc = lod_ea_store_resize(info, size);
		if (rc)
			GOTO(out, rc);
	}

	lcm = info->lti_ea_store;
	memset(lcm, 0, sizeof(*lcm) + sizeof(*lcme));
	lcm->lcm_magic = cpu_to_le32(LOV_MAGIC_COMP_V1);
	lcm->lcm_size = cpu_to_le32(size);
	lcm->lcm_layout_gen = cpu_to_le32(le16_to_cpu(
						lmm_save->lmm_layout_gen));
	lcm->lcm_flags = cpu_to_le16(LCM_FL_NONE);
	lcm->lcm_entry_count = cpu_to_le16(1);

	lcme = &lcm->lcm_entries[0];
	lcme->lcme_flags = cpu_to_le32(LCME_FL_INIT);
	lcme->lcme_extent.e_start = 0;
	lcme->lcme_extent.e_end = cpu_to_le64(OBD_OBJECT_EOF);
	lcme->lcme_offset = cpu_to_le32(sizeof(*lcm) + sizeof(*lcme));
	lcme->lcme_size = cpu_to_le32(blob_size);

	memcpy((char *)lcm + lcme->lcme_offset, (char *)lmm_save, blob_size);

	EXIT;
out:
	if (lmm_save)
		OBD_FREE_LARGE(lmm_save, blob_size);
	return rc;
}

/**
 * Merge layouts to form a mirrored file.
 */
static int lod_declare_layout_merge(const struct lu_env *env,
		struct dt_object *dt, const struct lu_buf *mbuf,
		struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lu_buf		*buf = &info->lti_buf;
	struct lod_object	*lo = lod_dt_obj(dt);
	struct lov_comp_md_v1	*lcm;
	struct lov_comp_md_v1	*cur_lcm;
	struct lov_comp_md_v1	*merge_lcm;
	struct lov_comp_md_entry_v1	*lcme;
	struct lov_mds_md_v1 *lmm;
	size_t size = 0;
	size_t offset;
	__u16 cur_entry_count;
	__u16 merge_entry_count;
	__u32 id = 0;
	__u16 mirror_id = 0;
	__u32 mirror_count;
	int	rc, i;
	bool merge_has_dom;

	ENTRY;

	merge_lcm = mbuf->lb_buf;
	if (mbuf->lb_len < sizeof(*merge_lcm))
		RETURN(-EINVAL);

	/* must be an existing layout from disk */
	if (le32_to_cpu(merge_lcm->lcm_magic) != LOV_MAGIC_COMP_V1)
		RETURN(-EINVAL);

	merge_entry_count = le16_to_cpu(merge_lcm->lcm_entry_count);

	/* do not allow to merge two mirrored files */
	if (le16_to_cpu(merge_lcm->lcm_mirror_count))
		RETURN(-EBUSY);

	/* verify the target buffer */
	rc = lod_get_lov_ea(env, lo);
	if (rc <= 0)
		RETURN(rc ? : -ENODATA);

	cur_lcm = info->lti_ea_store;
	switch (le32_to_cpu(cur_lcm->lcm_magic)) {
	case LOV_MAGIC_V1:
	case LOV_MAGIC_V3:
		rc = lod_layout_convert(info);
		break;
	case LOV_MAGIC_COMP_V1:
	case LOV_MAGIC_SEL:
		rc = 0;
		break;
	default:
		rc = -EINVAL;
	}
	if (rc)
		RETURN(rc);

	/* info->lti_ea_store could be reallocated in lod_layout_convert() */
	cur_lcm = info->lti_ea_store;
	cur_entry_count = le16_to_cpu(cur_lcm->lcm_entry_count);

	/* 'lcm_mirror_count + 1' is the current # of mirrors the file has */
	mirror_count = le16_to_cpu(cur_lcm->lcm_mirror_count) + 1;
	if (mirror_count + 1 > LUSTRE_MIRROR_COUNT_MAX)
		RETURN(-ERANGE);

	/* size of new layout */
	size = le32_to_cpu(cur_lcm->lcm_size) +
	       le32_to_cpu(merge_lcm->lcm_size) - sizeof(*cur_lcm);

	memset(buf, 0, sizeof(*buf));
	lu_buf_alloc(buf, size);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);

	lcm = buf->lb_buf;
	memcpy(lcm, cur_lcm, sizeof(*lcm) + cur_entry_count * sizeof(*lcme));

	offset = sizeof(*lcm) +
		 sizeof(*lcme) * (cur_entry_count + merge_entry_count);
	for (i = 0; i < cur_entry_count; i++) {
		struct lov_comp_md_entry_v1 *cur_lcme;

		lcme = &lcm->lcm_entries[i];
		cur_lcme = &cur_lcm->lcm_entries[i];

		lcme->lcme_offset = cpu_to_le32(offset);
		memcpy((char *)lcm + offset,
		       (char *)cur_lcm + le32_to_cpu(cur_lcme->lcme_offset),
		       le32_to_cpu(lcme->lcme_size));

		offset += le32_to_cpu(lcme->lcme_size);

		if (mirror_count == 1 &&
		    mirror_id_of(le32_to_cpu(lcme->lcme_id)) == 0) {
			/* Add mirror from a non-flr file, create new mirror ID.
			 * Otherwise, keep existing mirror's component ID, used
			 * for mirror extension.
			 */
			id = pflr_id(1, i + 1);
			lcme->lcme_id = cpu_to_le32(id);
		}

		id = max(le32_to_cpu(lcme->lcme_id), id);
	}

	mirror_id = mirror_id_of(id) + 1;

	/* check if first entry in new layout is DOM */
	lmm = (struct lov_mds_md_v1 *)((char *)merge_lcm +
					merge_lcm->lcm_entries[0].lcme_offset);
	merge_has_dom = lov_pattern(le32_to_cpu(lmm->lmm_pattern)) ==
			LOV_PATTERN_MDT;

	for (i = 0; i < merge_entry_count; i++) {
		struct lov_comp_md_entry_v1 *merge_lcme;

		merge_lcme = &merge_lcm->lcm_entries[i];
		lcme = &lcm->lcm_entries[cur_entry_count + i];

		*lcme = *merge_lcme;
		lcme->lcme_offset = cpu_to_le32(offset);
		if (merge_has_dom && i == 0)
			lcme->lcme_flags |= cpu_to_le32(LCME_FL_STALE);

		id = pflr_id(mirror_id, i + 1);
		lcme->lcme_id = cpu_to_le32(id);

		memcpy((char *)lcm + offset,
		       (char *)merge_lcm + le32_to_cpu(merge_lcme->lcme_offset),
		       le32_to_cpu(lcme->lcme_size));

		offset += le32_to_cpu(lcme->lcme_size);
	}

	/* fixup layout information */
	lod_obj_inc_layout_gen(lo);
	lcm->lcm_layout_gen = cpu_to_le32(lo->ldo_layout_gen);
	lcm->lcm_size = cpu_to_le32(size);
	lcm->lcm_entry_count = cpu_to_le16(cur_entry_count + merge_entry_count);
	lcm->lcm_mirror_count = cpu_to_le16(mirror_count);
	if ((le16_to_cpu(lcm->lcm_flags) & LCM_FL_FLR_MASK) == LCM_FL_NONE)
		lcm->lcm_flags = cpu_to_le32(LCM_FL_RDONLY);

	rc = lod_striping_reload(env, lo, buf);
	if (rc)
		GOTO(out, rc);

	rc = lod_sub_declare_xattr_set(env, dt_object_child(dt), buf,
					XATTR_NAME_LOV, LU_XATTR_REPLACE, th);

out:
	lu_buf_free(buf);
	RETURN(rc);
}

/**
 * Split layouts, just set the LOVEA with the layout from mbuf.
 */
static int lod_declare_layout_split(const struct lu_env *env,
		struct dt_object *dt, const struct lu_buf *mbuf,
		struct thandle *th)
{
	struct lod_object *lo = lod_dt_obj(dt);
	struct lov_comp_md_v1 *lcm = mbuf->lb_buf;
	int rc;
	ENTRY;

	rc = lod_striping_reload(env, lo, mbuf);
	if (rc)
		RETURN(rc);

	lod_obj_inc_layout_gen(lo);
	/* fix on-disk layout gen */
	lcm->lcm_layout_gen = cpu_to_le32(lo->ldo_layout_gen);

	rc = lod_sub_declare_xattr_set(env, dt_object_child(dt), mbuf,
				       XATTR_NAME_LOV, LU_XATTR_REPLACE, th);
	RETURN(rc);
}

static int lod_layout_declare_or_purge_mirror(const struct lu_env *env,
			struct dt_object *dt, const struct lu_buf *buf,
			struct thandle *th, bool declare)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_device *d = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object *lo = lod_dt_obj(dt);
	struct lov_comp_md_v1 *comp_v1 = buf->lb_buf;
	struct lov_comp_md_entry_v1 *entry;
	struct lov_mds_md_v1 *lmm;
	struct dt_object **sub_objs = NULL;
	int rc = 0, i, k, array_count = 0;

	ENTRY;

	/**
	 * other ops (like lod_declare_destroy) could destroying sub objects
	 * as well.
	 */
	mutex_lock(&lo->ldo_layout_mutex);

	if (!declare) {
		/* prepare sub-objects array */
		for (i = 0; i < comp_v1->lcm_entry_count; i++) {
			entry = &comp_v1->lcm_entries[i];

			if (!(entry->lcme_flags & LCME_FL_INIT))
				continue;

			lmm = (struct lov_mds_md_v1 *)
					((char *)comp_v1 + entry->lcme_offset);
			array_count += lmm->lmm_stripe_count;
		}
		OBD_ALLOC_PTR_ARRAY(sub_objs, array_count);
		if (sub_objs == NULL) {
			mutex_unlock(&lo->ldo_layout_mutex);
			RETURN(-ENOMEM);
		}
	}

	k = 0;	/* sub_objs index */
	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		struct lov_ost_data_v1 *objs;
		struct lu_object *o, *n;
		struct dt_object *dto;
		struct lu_device *nd;
		struct lov_mds_md_v3 *v3;
		__u32 idx;
		int j;

		entry = &comp_v1->lcm_entries[i];

		if (!(entry->lcme_flags & LCME_FL_INIT))
			continue;

		lmm = (struct lov_mds_md_v1 *)
				((char *)comp_v1 + entry->lcme_offset);
		v3 = (struct lov_mds_md_v3 *)lmm;
		if (lmm->lmm_magic == LOV_MAGIC_V3)
			objs = &v3->lmm_objects[0];
		else
			objs = &lmm->lmm_objects[0];

		for (j = 0; j < lmm->lmm_stripe_count; j++) {
			idx = objs[j].l_ost_idx;
			rc = ostid_to_fid(&info->lti_fid, &objs[j].l_ost_oi,
					  idx);
			if (rc)
				GOTO(out, rc);

			if (!fid_is_sane(&info->lti_fid)) {
				CERROR("%s: sub-object insane fid "DFID"\n",
				       lod2obd(d)->obd_name,
				       PFID(&info->lti_fid));
				GOTO(out, rc = -EINVAL);
			}

			lod_getref(&d->lod_ost_descs);

			rc = validate_lod_and_idx(d, idx);
			if (unlikely(rc)) {
				lod_putref(d, &d->lod_ost_descs);
				GOTO(out, rc);
			}

			nd = &OST_TGT(d, idx)->ltd_tgt->dd_lu_dev;
			lod_putref(d, &d->lod_ost_descs);

			o = lu_object_find_at(env, nd, &info->lti_fid, NULL);
			if (IS_ERR(o))
				GOTO(out, rc = PTR_ERR(o));

			n = lu_object_locate(o->lo_header, nd->ld_type);
			if (unlikely(!n)) {
				lu_object_put(env, n);
				GOTO(out, rc = -ENOENT);
			}

			dto = container_of(n, struct dt_object, do_lu);

			if (declare) {
				rc = lod_sub_declare_destroy(env, dto, th);
				dt_object_put(env, dto);
				if (rc)
					GOTO(out, rc);
			} else {
				/**
				 * collect to-be-destroyed sub objects, the
				 * reference would be released after actual
				 * deletion.
				 */
				sub_objs[k] = dto;
				k++;
			}
		} /* for each stripe */
	} /* for each component in the mirror */
out:
	if (!declare) {
		i = 0;
		if (!rc) {
			/* destroy the sub objects */
			for (; i < k; i++) {
				rc = lod_sub_destroy(env, sub_objs[i], th);
				if (rc)
					break;
				dt_object_put(env, sub_objs[i]);
			}
		}
		/**
		 * if a sub object destroy failed, we'd release sub objects
		 * reference get from above sub_objs collection.
		 */
		for (; i < k; i++)
			dt_object_put(env, sub_objs[i]);

		OBD_FREE_PTR_ARRAY(sub_objs, array_count);
	}
	mutex_unlock(&lo->ldo_layout_mutex);

	RETURN(rc);
}

/**
 * Purge layouts, delete sub objects in the mirror stored in the vic_buf,
 * and set the LOVEA with the layout from mbuf.
 */
static int lod_declare_layout_purge(const struct lu_env *env,
		struct dt_object *dt, const struct lu_buf *buf,
		struct thandle *th)
{
	struct lod_device *d = lu2lod_dev(dt->do_lu.lo_dev);
	struct lov_comp_md_v1 *comp_v1 = buf->lb_buf;
	int rc;

	ENTRY;

	if (le32_to_cpu(comp_v1->lcm_magic) != LOV_MAGIC_COMP_V1) {
		CERROR("%s: invalid layout magic %#x != %#x\n",
		       lod2obd(d)->obd_name, le32_to_cpu(comp_v1->lcm_magic),
		       LOV_MAGIC_COMP_V1);
		RETURN(-EINVAL);
	}

	if (cpu_to_le32(LOV_MAGIC_COMP_V1) != LOV_MAGIC_COMP_V1)
		lustre_swab_lov_comp_md_v1(comp_v1);

	/* from now on, @buf contains cpu endian data */

	if (comp_v1->lcm_mirror_count != 0) {
		CERROR("%s: can only purge one mirror from "DFID"\n",
		       lod2obd(d)->obd_name, PFID(lu_object_fid(&dt->do_lu)));
		RETURN(-EINVAL);
	}

	/* delcare sub objects deletion in the mirror stored in @buf */
	rc = lod_layout_declare_or_purge_mirror(env, dt, buf, th, true);
	RETURN(rc);
}

/* delete sub objects from the mirror stored in @buf */
static int lod_layout_purge(const struct lu_env *env, struct dt_object *dt,
			    const struct lu_buf *buf, struct thandle *th)
{
	int rc;

	ENTRY;
	rc = lod_layout_declare_or_purge_mirror(env, dt, buf, th, false);
	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_declare_xattr_set.
 *
 * \see dt_object_operations::do_declare_xattr_set() in the API description
 * for details.
 *
 * the extension to the API:
 *   - declaring LOVEA requests striping creation
 *   - LU_XATTR_REPLACE means layout swap
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

	mode = dt->do_lu.lo_header->loh_attr & S_IFMT;
	if ((S_ISREG(mode) || mode == 0) &&
	    !(fl & (LU_XATTR_REPLACE | LU_XATTR_MERGE | LU_XATTR_SPLIT |
		    LU_XATTR_PURGE)) &&
	    (strcmp(name, XATTR_NAME_LOV) == 0 ||
	     strcmp(name, XATTR_LUSTRE_LOV) == 0)) {
		/*
		 * this is a request to create object's striping.
		 *
		 * allow to declare predefined striping on a new (!mode) object
		 * which is supposed to be replay of regular file creation
		 * (when LOV setting is declared)
		 *
		 * LU_XATTR_REPLACE is set to indicate a layout swap
		 */
		if (dt_object_exists(dt)) {
			rc = dt_attr_get(env, next, attr);
			if (rc)
				RETURN(rc);
		} else {
			memset(attr, 0, sizeof(*attr));
			attr->la_valid = LA_TYPE | LA_MODE;
			attr->la_mode = S_IFREG;
		}
		rc = lod_declare_striped_create(env, dt, attr, buf, th);
	} else if (fl & LU_XATTR_MERGE) {
		LASSERT(strcmp(name, XATTR_NAME_LOV) == 0 ||
			strcmp(name, XATTR_LUSTRE_LOV) == 0);
		rc = lod_declare_layout_merge(env, dt, buf, th);
	} else if (fl & LU_XATTR_SPLIT) {
		LASSERT(strcmp(name, XATTR_NAME_LOV) == 0 ||
			strcmp(name, XATTR_LUSTRE_LOV) == 0);
		rc = lod_declare_layout_split(env, dt, buf, th);
	} else if (fl & LU_XATTR_PURGE) {
		LASSERT(strcmp(name, XATTR_NAME_LOV) == 0 ||
			strcmp(name, XATTR_LUSTRE_LOV) == 0);
		rc = lod_declare_layout_purge(env, dt, buf, th);
	} else if (S_ISREG(mode) &&
		   strlen(name) >= sizeof(XATTR_LUSTRE_LOV) + 3 &&
		   allowed_lustre_lov(name)) {
		/*
		 * this is a request to modify object's striping.
		 * add/set/del component(s).
		 */
		if (!dt_object_exists(dt))
			RETURN(-ENOENT);

		rc = lod_declare_modify_layout(env, dt, name, buf, th);
	} else if (S_ISDIR(mode)) {
		rc = lod_dir_declare_xattr_set(env, dt, buf, name, fl, th);
	} else if (strcmp(name, XATTR_NAME_FID) == 0) {
		rc = lod_replace_parent_fid(env, dt, buf, th, true);
	} else {
		rc = lod_sub_declare_xattr_set(env, next, buf, name, fl, th);
	}

	RETURN(rc);
}

/**
 * Apply xattr changes to the object.
 *
 * Applies xattr changes to the object and the stripes if the latter exist.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[in] buf	buffer pointing to the new value of xattr
 * \param[in] name	name of xattr
 * \param[in] fl	flags
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_xattr_set_internal(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct lu_buf *buf,
				  const char *name, int fl,
				  struct thandle *th)
{
	struct dt_object	*next = dt_object_child(dt);
	struct lod_object	*lo = lod_dt_obj(dt);
	int			rc;
	int			i;
	ENTRY;

	rc = lod_sub_xattr_set(env, next, buf, name, fl, th);
	if (rc != 0 || !S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(rc);

	/* Note: Do not set LinkEA on sub-stripes, otherwise
	 * it will confuse the fid2path process(see mdt_path_current()).
	 * The linkEA between master and sub-stripes is set in
	 * lod_xattr_set_lmv(). */
	if (lo->ldo_dir_stripe_count == 0 || strcmp(name, XATTR_NAME_LINK) == 0)
		RETURN(0);

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		if (!lo->ldo_stripe[i])
			continue;

		if (!dt_object_exists(lo->ldo_stripe[i]))
			continue;

		rc = lod_sub_xattr_set(env, lo->ldo_stripe[i], buf, name,
				       fl, th);
		if (rc != 0)
			break;
	}

	RETURN(rc);
}

/**
 * Delete an extended attribute.
 *
 * Deletes specified xattr from the object and the stripes if the latter exist.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[in] name	name of xattr
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_xattr_del_internal(const struct lu_env *env,
				  struct dt_object *dt,
				  const char *name, struct thandle *th)
{
	struct dt_object *next = dt_object_child(dt);
	struct lod_object *lo = lod_dt_obj(dt);
	int i;
	int rc;

	ENTRY;

	rc = lod_sub_xattr_del(env, next, name, th);
	if (rc != 0 || !S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(rc);

	if (lo->ldo_dir_stripe_count == 0)
		RETURN(rc);

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		if (!lo->ldo_stripe[i])
			continue;

		if (!dt_object_exists(lo->ldo_stripe[i]))
			continue;

		rc = lod_sub_xattr_del(env, lo->ldo_stripe[i], name, th);
		if (rc != 0)
			break;
	}

	RETURN(rc);
}

/**
 * Set default striping on a directory.
 *
 * Sets specified striping on a directory object unless it matches the default
 * striping (LOVEA_DELETE_VALUES() macro). In the latter case remove existing
 * EA. This striping will be used when regular file is being created in this
 * directory.
 *
 * \param[in] env	execution environment
 * \param[in] dt	the striped object
 * \param[in] buf	buffer with the striping
 * \param[in] name	name of EA
 * \param[in] fl	xattr flag (see OSD API description)
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_xattr_set_lov_on_dir(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct lu_buf *buf,
				    const char *name, int fl,
				    struct thandle *th)
{
	struct lov_user_md_v1	*lum;
	struct lov_user_md_v3	*v3 = NULL;
	const char		*pool_name = NULL;
	int			 rc;
	bool			 is_del;
	ENTRY;

	LASSERT(buf != NULL && buf->lb_buf != NULL);
	lum = buf->lb_buf;

	switch (lum->lmm_magic) {
	case LOV_USER_MAGIC_SPECIFIC:
	case LOV_USER_MAGIC_V3:
		v3 = buf->lb_buf;
		if (v3->lmm_pool_name[0] != '\0')
			pool_name = v3->lmm_pool_name;
		/* fall through */
	case LOV_USER_MAGIC_V1:
		/* if { size, offset, count } = { 0, -1, 0 } and no pool
		 * (i.e. all default values specified) then delete default
		 * striping from dir. */
		CDEBUG(D_LAYOUT,
		       "set default striping: sz %u # %u offset %d %s %s\n",
		       (unsigned)lum->lmm_stripe_size,
		       (unsigned)lum->lmm_stripe_count,
		       (int)lum->lmm_stripe_offset,
		       v3 ? "from" : "", v3 ? v3->lmm_pool_name : "");

		is_del = LOVEA_DELETE_VALUES(lum->lmm_stripe_size,
					     lum->lmm_stripe_count,
					     lum->lmm_stripe_offset,
					     pool_name);
		break;
	case LOV_USER_MAGIC_COMP_V1:
	{
		struct lov_comp_md_v1 *lcm = (struct lov_comp_md_v1 *)lum;
		struct lov_comp_md_entry_v1 *lcme;
		int i, comp_cnt;

		comp_cnt = le16_to_cpu(lcm->lcm_entry_count);
		for (i = 0; i < comp_cnt; i++) {
			lcme = &lcm->lcm_entries[i];
			if (lcme->lcme_flags & cpu_to_le32(LCME_FL_EXTENSION)) {
				lcm->lcm_magic = cpu_to_le32(LOV_MAGIC_SEL);
				break;
			}
		}

		is_del = false;
		break;
	}
	default:
		CERROR("Invalid magic %x\n", lum->lmm_magic);
		RETURN(-EINVAL);
	}

	if (is_del) {
		rc = lod_xattr_del_internal(env, dt, name, th);
		if (rc == -ENODATA)
			rc = 0;
	} else {
		rc = lod_xattr_set_internal(env, dt, buf, name, fl, th);
	}

	RETURN(rc);
}

/**
 * Set default striping on a directory object.
 *
 * Sets specified striping on a directory object unless it matches the default
 * striping (LOVEA_DELETE_VALUES() macro). In the latter case remove existing
 * EA. This striping will be used when a new directory is being created in the
 * directory.
 *
 * \param[in] env	execution environment
 * \param[in] dt	the striped object
 * \param[in] buf	buffer with the striping
 * \param[in] name	name of EA
 * \param[in] fl	xattr flag (see OSD API description)
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_xattr_set_default_lmv_on_dir(const struct lu_env *env,
					    struct dt_object *dt,
					    const struct lu_buf *buf,
					    const char *name, int fl,
					    struct thandle *th)
{
	struct lmv_user_md_v1 *lum;
	int rc;

	ENTRY;

	LASSERT(buf != NULL && buf->lb_buf != NULL);
	lum = buf->lb_buf;

	CDEBUG(D_INFO,
	       "set default stripe_count # %u stripe_offset %d hash %u\n",
	      le32_to_cpu(lum->lum_stripe_count),
	      (int)le32_to_cpu(lum->lum_stripe_offset),
	      le32_to_cpu(lum->lum_hash_type));

	if (LMVEA_DELETE_VALUES((le32_to_cpu(lum->lum_stripe_count)),
				 le32_to_cpu(lum->lum_stripe_offset)) &&
	    le32_to_cpu(lum->lum_magic) == LMV_USER_MAGIC) {
		rc = lod_xattr_del_internal(env, dt, name, th);
		if (rc == -ENODATA)
			rc = 0;
	} else {
		rc = lod_xattr_set_internal(env, dt, buf, name, fl, th);
		if (rc != 0)
			RETURN(rc);
	}

	RETURN(rc);
}

/**
 * Turn directory into a striped directory.
 *
 * During replay the client sends the striping created before MDT
 * failure, then the layer above LOD sends this defined striping
 * using ->do_xattr_set(), so LOD uses this method to replay creation
 * of the stripes. Notice the original information for the striping
 * (#stripes, FIDs, etc) was transferred in declare path.
 *
 * \param[in] env	execution environment
 * \param[in] dt	the striped object
 * \param[in] buf	not used currently
 * \param[in] name	not used currently
 * \param[in] fl	xattr flag (see OSD API description)
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_xattr_set_lmv(const struct lu_env *env, struct dt_object *dt,
			     const struct lu_buf *buf, const char *name,
			     int fl, struct thandle *th)
{
	struct lod_object	*lo = lod_dt_obj(dt);
	struct lod_thread_info	*info = lod_env_info(env);
	struct lu_attr		*attr = &info->lti_attr;
	struct dt_object_format *dof = &info->lti_format;
	struct lu_buf		lmv_buf;
	struct lu_buf		slave_lmv_buf;
	struct lmv_mds_md_v1	*lmm;
	struct lmv_mds_md_v1	*slave_lmm = NULL;
	struct dt_insert_rec	*rec = &info->lti_dt_rec;
	int			i;
	int			rc;
	ENTRY;

	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(-ENOTDIR);

	/* The stripes are supposed to be allocated in declare phase,
	 * if there are no stripes being allocated, it will skip */
	if (lo->ldo_dir_stripe_count == 0) {
		if (lo->ldo_dir_is_foreign) {
			rc = lod_sub_xattr_set(env, dt_object_child(dt), buf,
					       XATTR_NAME_LMV, fl, th);
			if (rc != 0)
				RETURN(rc);
		}
		RETURN(0);
	}

	rc = dt_attr_get(env, dt_object_child(dt), attr);
	if (rc != 0)
		RETURN(rc);

	attr->la_valid = LA_ATIME | LA_MTIME | LA_CTIME | LA_FLAGS |
			 LA_MODE | LA_UID | LA_GID | LA_TYPE | LA_PROJID;
	dof->dof_type = DFT_DIR;

	rc = lod_prep_lmv_md(env, dt, &lmv_buf);
	if (rc != 0)
		RETURN(rc);
	lmm = lmv_buf.lb_buf;

	OBD_ALLOC_PTR(slave_lmm);
	if (slave_lmm == NULL)
		RETURN(-ENOMEM);

	lod_prep_slave_lmv_md(slave_lmm, lmm);
	slave_lmv_buf.lb_buf = slave_lmm;
	slave_lmv_buf.lb_len = sizeof(*slave_lmm);

	rec->rec_type = S_IFDIR;
	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		struct dt_object *dto = lo->ldo_stripe[i];
		char *stripe_name = info->lti_key;
		struct lu_name *sname;
		struct linkea_data ldata = { NULL };
		struct lu_buf linkea_buf;

		/* OBD_FAIL_MDS_STRIPE_FID may leave stripe uninitialized */
		if (!dto)
			continue;

		/* fail a remote stripe creation */
		if (i && OBD_FAIL_CHECK(OBD_FAIL_MDS_STRIPE_CREATE))
			continue;

		/* don't create stripe if:
		 * 1. it's source stripe of migrating directory
		 * 2. it's existed stripe of splitting directory
		 */
		if ((lod_is_migrating(lo) && i >= lo->ldo_dir_migrate_offset) ||
		    (lod_is_splitting(lo) && i < lo->ldo_dir_split_offset)) {
			if (!dt_object_exists(dto))
				GOTO(out, rc = -EINVAL);
		} else {
			dt_write_lock(env, dto, DT_TGT_CHILD);
			rc = lod_sub_create(env, dto, attr, NULL, dof, th);
			if (rc != 0) {
				dt_write_unlock(env, dto);
				GOTO(out, rc);
			}

			rc = lod_sub_ref_add(env, dto, th);
			dt_write_unlock(env, dto);
			if (rc != 0)
				GOTO(out, rc);

			rec->rec_fid = lu_object_fid(&dto->do_lu);
			rc = lod_sub_insert(env, dto,
					    (const struct dt_rec *)rec,
					    (const struct dt_key *)dot, th);
			if (rc != 0)
				GOTO(out, rc);
		}

		if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_SLAVE_LMV) ||
		    cfs_fail_val != i) {
			if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_LMV) &&
			    cfs_fail_val == i)
				slave_lmm->lmv_master_mdt_index =
							cpu_to_le32(i + 1);
			else
				slave_lmm->lmv_master_mdt_index =
							cpu_to_le32(i);

			rc = lod_sub_xattr_set(env, dto, &slave_lmv_buf,
					       XATTR_NAME_LMV, 0, th);
			if (rc != 0)
				GOTO(out, rc);
		}

		/* don't insert stripe if it's existed stripe of splitting
		 * directory (this directory is striped).
		 * NB, plain directory will insert itself as the first
		 * stripe in target.
		 */
		if (lod_is_splitting(lo) && lo->ldo_dir_split_offset > 1 &&
		    lo->ldo_dir_split_offset > i)
			continue;

		rec->rec_fid = lu_object_fid(&dt->do_lu);
		rc = lod_sub_insert(env, dto, (struct dt_rec *)rec,
				    (const struct dt_key *)dotdot, th);
		if (rc != 0)
			GOTO(out, rc);

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_NAME) &&
		    cfs_fail_val == i)
			snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
				 PFID(lu_object_fid(&dto->do_lu)), i + 1);
		else
			snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
				 PFID(lu_object_fid(&dto->do_lu)), i);

		sname = lod_name_get(env, stripe_name, strlen(stripe_name));
		rc = linkea_links_new(&ldata, &info->lti_linkea_buf,
				      sname, lu_object_fid(&dt->do_lu));
		if (rc != 0)
			GOTO(out, rc);

		linkea_buf.lb_buf = ldata.ld_buf->lb_buf;
		linkea_buf.lb_len = ldata.ld_leh->leh_len;
		rc = lod_sub_xattr_set(env, dto, &linkea_buf,
				       XATTR_NAME_LINK, 0, th);
		if (rc != 0)
			GOTO(out, rc);

		rec->rec_fid = lu_object_fid(&dto->do_lu);
		rc = lod_sub_insert(env, dt_object_child(dt),
				    (const struct dt_rec *)rec,
				    (const struct dt_key *)stripe_name, th);
		if (rc != 0)
			GOTO(out, rc);

		rc = lod_sub_ref_add(env, dt_object_child(dt), th);
		if (rc != 0)
			GOTO(out, rc);
	}

	if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_MASTER_LMV))
		rc = lod_sub_xattr_set(env, dt_object_child(dt),
				       &lmv_buf, XATTR_NAME_LMV, fl, th);
out:
	if (slave_lmm != NULL)
		OBD_FREE_PTR(slave_lmm);

	RETURN(rc);
}

/**
 * Helper function to declare/execute creation of a striped directory
 *
 * Called in declare/create object path, prepare striping for a directory
 * and prepare defaults data striping for the objects to be created in
 * that directory. Notice the function calls "declaration" or "execution"
 * methods depending on \a declare param. This is a consequence of the
 * current approach while we don't have natural distributed transactions:
 * we basically execute non-local updates in the declare phase. So, the
 * arguments for the both phases are the same and this is the reason for
 * this function to exist.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[in] attr	attributes the stripes will be created with
 * \param[in] lmu	lmv_user_md if MDT indices are specified
 * \param[in] dof	format of stripes (see OSD API description)
 * \param[in] th	transaction handle
 * \param[in] declare	where to call "declare" or "execute" methods
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_dir_striping_create_internal(const struct lu_env *env,
					    struct dt_object *dt,
					    struct lu_attr *attr,
					    const struct lu_buf *lmu,
					    struct dt_object_format *dof,
					    struct thandle *th,
					    bool declare)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_object *lo = lod_dt_obj(dt);
	const struct lod_default_striping *lds = lo->ldo_def_striping;
	int rc;
	ENTRY;

	LASSERT(ergo(lds != NULL,
		     lds->lds_def_striping_set ||
		     lds->lds_dir_def_striping_set));

	if (!LMVEA_DELETE_VALUES(lo->ldo_dir_stripe_count,
				 lo->ldo_dir_stripe_offset)) {
		if (!lmu) {
			struct lmv_user_md_v1 *v1 = info->lti_ea_store;
			int stripe_count = lo->ldo_dir_stripe_count;

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
			lmu = &info->lti_buf;
		}

		if (declare)
			rc = lod_declare_xattr_set_lmv(env, dt, attr, lmu, dof,
						       th);
		else
			rc = lod_xattr_set_lmv(env, dt, lmu, XATTR_NAME_LMV, 0,
					       th);
		if (rc != 0)
			RETURN(rc);
	} else {
		/* foreign LMV EA case */
		if (lmu) {
			struct lmv_foreign_md *lfm = lmu->lb_buf;

			if (lfm->lfm_magic == LMV_MAGIC_FOREIGN) {
				rc = lod_declare_xattr_set_lmv(env, dt, attr,
							       lmu, dof, th);
			}
		} else {
			if (lo->ldo_dir_is_foreign) {
				LASSERT(lo->ldo_foreign_lmv != NULL &&
					lo->ldo_foreign_lmv_size > 0);
				info->lti_buf.lb_buf = lo->ldo_foreign_lmv;
				info->lti_buf.lb_len = lo->ldo_foreign_lmv_size;
				lmu = &info->lti_buf;
				rc = lod_xattr_set_lmv(env, dt, lmu,
						       XATTR_NAME_LMV, 0, th);
			}
		}
	}

	/* Transfer default LMV striping from the parent */
	if (lds != NULL && lds->lds_dir_def_striping_set &&
	    lds->lds_dir_def_max_inherit != LMV_INHERIT_END &&
	    lds->lds_dir_def_max_inherit != LMV_INHERIT_NONE &&
	    !(LMVEA_DELETE_VALUES(lds->lds_dir_def_stripe_count,
				 lds->lds_dir_def_stripe_offset) &&
	      le32_to_cpu(lds->lds_dir_def_hash_type) !=
	      LMV_HASH_TYPE_UNKNOWN)) {
		struct lmv_user_md_v1 *v1 = info->lti_ea_store;

		if (info->lti_ea_store_size < sizeof(*v1)) {
			rc = lod_ea_store_resize(info, sizeof(*v1));
			if (rc != 0)
				RETURN(rc);
			v1 = info->lti_ea_store;
		}

		memset(v1, 0, sizeof(*v1));
		v1->lum_magic = cpu_to_le32(LMV_USER_MAGIC);
		v1->lum_stripe_count =
			cpu_to_le32(lds->lds_dir_def_stripe_count);
		v1->lum_stripe_offset =
			cpu_to_le32(lds->lds_dir_def_stripe_offset);
		v1->lum_hash_type =
			cpu_to_le32(lds->lds_dir_def_hash_type);
		v1->lum_max_inherit =
			lmv_inherit_next(lds->lds_dir_def_max_inherit);
		v1->lum_max_inherit_rr =
			lmv_inherit_rr_next(lds->lds_dir_def_max_inherit_rr);

		info->lti_buf.lb_buf = v1;
		info->lti_buf.lb_len = sizeof(*v1);
		if (declare)
			rc = lod_dir_declare_xattr_set(env, dt, &info->lti_buf,
						       XATTR_NAME_DEFAULT_LMV,
						       0, th);
		else
			rc = lod_xattr_set_default_lmv_on_dir(env, dt,
						  &info->lti_buf,
						  XATTR_NAME_DEFAULT_LMV, 0,
						  th);
		if (rc != 0)
			RETURN(rc);
	}

	/* Transfer default LOV striping from the parent */
	if (lds != NULL && lds->lds_def_striping_set &&
	    lds->lds_def_comp_cnt != 0) {
		struct lov_mds_md *lmm;
		int lmm_size = lod_comp_md_size(lo, true);

		if (info->lti_ea_store_size < lmm_size) {
			rc = lod_ea_store_resize(info, lmm_size);
			if (rc != 0)
				RETURN(rc);
		}
		lmm = info->lti_ea_store;

		rc = lod_generate_lovea(env, lo, lmm, &lmm_size, true);
		if (rc != 0)
			RETURN(rc);

		info->lti_buf.lb_buf = lmm;
		info->lti_buf.lb_len = lmm_size;

		if (declare)
			rc = lod_dir_declare_xattr_set(env, dt, &info->lti_buf,
						       XATTR_NAME_LOV, 0, th);
		else
			rc = lod_xattr_set_lov_on_dir(env, dt, &info->lti_buf,
						      XATTR_NAME_LOV, 0, th);
		if (rc != 0)
			RETURN(rc);
	}

	RETURN(0);
}

static int lod_declare_dir_striping_create(const struct lu_env *env,
					   struct dt_object *dt,
					   struct lu_attr *attr,
					   struct lu_buf *lmu,
					   struct dt_object_format *dof,
					   struct thandle *th)
{
	return lod_dir_striping_create_internal(env, dt, attr, lmu, dof, th,
						true);
}

static int lod_dir_striping_create(const struct lu_env *env,
				   struct dt_object *dt,
				   struct lu_attr *attr,
				   struct dt_object_format *dof,
				   struct thandle *th)
{
	return lod_dir_striping_create_internal(env, dt, attr, NULL, dof, th,
						false);
}

/**
 * Make LOV EA for striped object.
 *
 * Generate striping information and store it in the LOV EA of the given
 * object. The caller must ensure nobody else is calling the function
 * against the object concurrently. The transaction must be started.
 * FLDB service must be running as well; it's used to map FID to the target,
 * which is stored in LOV EA.
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lo		LOD object
 * \param[in] th		transaction handle
 *
 * \retval			0 if LOV EA is stored successfully
 * \retval			negative error number on failure
 */
static int lod_generate_and_set_lovea(const struct lu_env *env,
				      struct lod_object *lo,
				      struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct dt_object	*next = dt_object_child(&lo->ldo_obj);
	struct lov_mds_md_v1	*lmm;
	int			 rc, lmm_size;
	ENTRY;

	LASSERT(lo);

	if (lo->ldo_comp_cnt == 0 && !lo->ldo_is_foreign) {
		lod_striping_free_nolock(env, lo);
		rc = lod_sub_xattr_del(env, next, XATTR_NAME_LOV, th);
		RETURN(rc);
	}

	lmm_size = lod_comp_md_size(lo, false);
	if (info->lti_ea_store_size < lmm_size) {
		rc = lod_ea_store_resize(info, lmm_size);
		if (rc)
			RETURN(rc);
	}
	lmm = info->lti_ea_store;

	rc = lod_generate_lovea(env, lo, lmm, &lmm_size, false);
	if (rc)
		RETURN(rc);

	info->lti_buf.lb_buf = lmm;
	info->lti_buf.lb_len = lmm_size;
	rc = lod_sub_xattr_set(env, next, &info->lti_buf,
			       XATTR_NAME_LOV, 0, th);
	RETURN(rc);
}

static __u32 lod_gen_component_id(struct lod_object *lo,
				  int mirror_id, int comp_idx);

/**
 * Repeat an existing component
 *
 * Creates a new layout by replicating an existing component.  Uses striping
 * policy from previous component as a template for the striping for the new
 * new component.
 *
 * New component starts with zero length, will be extended (or removed) before
 * returning layout to client.
 *
 * NB: Reallocates layout components array (lo->ldo_comp_entries), invalidating
 * any pre-existing pointers to components.  Handle with care.
 *
 * \param[in] env	execution environment for this thread
 * \param[in,out] lo	object to update the layout of
 * \param[in] index	index of component to copy
 *
 * \retval	0 on success
 * \retval	negative errno on error
 */
static int lod_layout_repeat_comp(const struct lu_env *env,
				  struct lod_object *lo, int index)
{
	struct lod_layout_component *lod_comp;
	struct lod_layout_component *new_comp = NULL;
	struct lod_layout_component *comp_array;
	int rc = 0, i, new_cnt = lo->ldo_comp_cnt + 1;
	__u16 mirror_id;
	int offset = 0;
	ENTRY;

	lod_comp = &lo->ldo_comp_entries[index];
	LASSERT(lod_comp_inited(lod_comp) && lod_comp->llc_id != LCME_ID_INVAL);

	CDEBUG(D_LAYOUT, "repeating component %d\n", index);

	OBD_ALLOC_PTR_ARRAY(comp_array, new_cnt);
	if (comp_array == NULL)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < lo->ldo_comp_cnt; i++) {
		memcpy(&comp_array[i + offset], &lo->ldo_comp_entries[i],
		       sizeof(*comp_array));

		/* Duplicate this component in to the next slot */
		if (i == index) {
			new_comp = &comp_array[i + 1];
			memcpy(&comp_array[i + 1], &lo->ldo_comp_entries[i],
			       sizeof(*comp_array));
			/* We must now skip this new component when copying */
			offset = 1;
		}
	}

	/* Set up copied component */
	new_comp->llc_flags &= ~LCME_FL_INIT;
	new_comp->llc_stripe = NULL;
	new_comp->llc_stripes_allocated = 0;
	new_comp->llc_ost_indices = NULL;
	new_comp->llc_stripe_offset = LOV_OFFSET_DEFAULT;
	/* for uninstantiated components, layout gen stores default stripe
	 * offset */
	new_comp->llc_layout_gen = lod_comp->llc_stripe_offset;
	/* This makes the repeated component zero-length, placed at the end of
	 * the preceding component */
	new_comp->llc_extent.e_start = new_comp->llc_extent.e_end;
	new_comp->llc_timestamp = lod_comp->llc_timestamp;
	new_comp->llc_pool = NULL;

	rc = lod_set_pool(&new_comp->llc_pool, lod_comp->llc_pool);
	if (rc)
		GOTO(out, rc);

	if (new_comp->llc_ostlist.op_array) {
		__u32 *op_array = NULL;

		OBD_ALLOC(op_array, new_comp->llc_ostlist.op_size);
		if (!op_array)
			GOTO(out, rc = -ENOMEM);
		memcpy(op_array, &new_comp->llc_ostlist.op_array,
		       new_comp->llc_ostlist.op_size);
		new_comp->llc_ostlist.op_array = op_array;
	}

	OBD_FREE_PTR_ARRAY(lo->ldo_comp_entries, lo->ldo_comp_cnt);
	lo->ldo_comp_entries = comp_array;
	lo->ldo_comp_cnt = new_cnt;

	/* Generate an id for the new component */
	mirror_id = mirror_id_of(new_comp->llc_id);
	new_comp->llc_id = LCME_ID_INVAL;
	new_comp->llc_id = lod_gen_component_id(lo, mirror_id, index + 1);
	if (new_comp->llc_id == LCME_ID_INVAL)
		GOTO(out, rc = -ERANGE);

	EXIT;
out:
	if (rc)
		OBD_FREE_PTR_ARRAY(comp_array, new_cnt);

	return rc;
}

static int lod_layout_data_init(struct lod_thread_info *info, __u32 comp_cnt)
{
	ENTRY;

	/* clear memory region that will be used for layout change */
	memset(&info->lti_layout_attr, 0, sizeof(struct lu_attr));
	info->lti_count = 0;

	if (info->lti_comp_size >= comp_cnt)
		RETURN(0);

	if (info->lti_comp_size > 0) {
		OBD_FREE_PTR_ARRAY(info->lti_comp_idx, info->lti_comp_size);
		info->lti_comp_size = 0;
	}

	OBD_ALLOC_PTR_ARRAY(info->lti_comp_idx, comp_cnt);
	if (!info->lti_comp_idx)
		RETURN(-ENOMEM);

	info->lti_comp_size = comp_cnt;
	RETURN(0);
}

/**
 * Prepare new layout minus deleted components
 *
 * Removes components marked for deletion (LCME_ID_INVAL) by copying to a new
 * layout and skipping those components.  Removes stripe objects if any exist.
 *
 * NB:
 * Reallocates layout components array (lo->ldo_comp_entries), invalidating
 * any pre-existing pointers to components.
 *
 * Caller is responsible for updating mirror end (ldo_mirror[].lme_end).
 *
 * \param[in] env       execution environment for this thread
 * \param[in,out] lo    object to update the layout of
 * \param[in] th        transaction handle for this operation
 *
 * \retval      # of components deleted
 * \retval      negative errno on error
 */
static int lod_layout_del_prep_layout(const struct lu_env *env,
				      struct lod_object *lo,
				      struct thandle *th)
{
	struct lod_layout_component     *lod_comp;
	struct lod_thread_info  *info = lod_env_info(env);
	int rc = 0, i, j, deleted = 0;

	ENTRY;

	LASSERT(lo->ldo_is_composite);
	LASSERT(lo->ldo_comp_cnt > 0 && lo->ldo_comp_entries != NULL);

	rc = lod_layout_data_init(info, lo->ldo_comp_cnt);
	if (rc)
		RETURN(rc);

	for (i = 0; i < lo->ldo_comp_cnt; i++) {
		lod_comp = &lo->ldo_comp_entries[i];

		if (lod_comp->llc_id != LCME_ID_INVAL) {
			/* Build array of things to keep */
			info->lti_comp_idx[info->lti_count++] = i;
			continue;
		}

		lod_obj_set_pool(lo, i, NULL);
		if (lod_comp->llc_ostlist.op_array) {
			OBD_FREE(lod_comp->llc_ostlist.op_array,
				 lod_comp->llc_ostlist.op_size);
			lod_comp->llc_ostlist.op_array = NULL;
			lod_comp->llc_ostlist.op_size = 0;
		}

		deleted++;
		CDEBUG(D_LAYOUT, "deleting comp %d, left %d\n", i,
		       lo->ldo_comp_cnt - deleted);

		/* No striping info for this component */
		if (lod_comp->llc_stripe == NULL)
			continue;

		LASSERT(lod_comp->llc_stripe_count > 0);
		for (j = 0; j < lod_comp->llc_stripe_count; j++) {
			struct dt_object *obj = lod_comp->llc_stripe[j];

			if (obj == NULL)
				continue;

			/* components which are not init have no sub objects
			 * to destroy */
			if (lod_comp_inited(lod_comp)) {
				rc = lod_sub_destroy(env, obj, th);
				if (rc)
					GOTO(out, rc);
			}

			lu_object_put(env, &obj->do_lu);
			lod_comp->llc_stripe[j] = NULL;
		}
		OBD_FREE_PTR_ARRAY(lod_comp->llc_stripe,
				   lod_comp->llc_stripes_allocated);
		lod_comp->llc_stripe = NULL;
		OBD_FREE_PTR_ARRAY(lod_comp->llc_ost_indices,
				   lod_comp->llc_stripes_allocated);
		lod_comp->llc_ost_indices = NULL;
		lod_comp->llc_stripes_allocated = 0;
	}

	/* info->lti_count has the amount of left components */
	LASSERTF(info->lti_count >= 0 && info->lti_count < lo->ldo_comp_cnt,
		 "left = %d, lo->ldo_comp_cnt %d\n", (int)info->lti_count,
		 (int)lo->ldo_comp_cnt);

	if (info->lti_count > 0) {
		struct lod_layout_component *comp_array;

		OBD_ALLOC_PTR_ARRAY(comp_array, info->lti_count);
		if (comp_array == NULL)
			GOTO(out, rc = -ENOMEM);

		for (i = 0; i < info->lti_count; i++) {
			memcpy(&comp_array[i],
			       &lo->ldo_comp_entries[info->lti_comp_idx[i]],
			       sizeof(*comp_array));
		}

		OBD_FREE_PTR_ARRAY(lo->ldo_comp_entries, lo->ldo_comp_cnt);
		lo->ldo_comp_entries = comp_array;
		lo->ldo_comp_cnt = info->lti_count;
	} else {
		lod_free_comp_entries(lo);
	}

	EXIT;
out:
	return rc ? rc : deleted;
}

/**
 * Delete layout component(s)
 *
 * This function sets up the layout data in the env and does the setattrs
 * required to write out the new layout.  The layout itself is modified in
 * lod_layout_del_prep_layout.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] dt	object
 * \param[in] th	transaction handle
 *
 * \retval	0 on success
 * \retval	negative error number on failure
 */
static int lod_layout_del(const struct lu_env *env, struct dt_object *dt,
			  struct thandle *th)
{
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object *next = dt_object_child(dt);
	struct lu_attr *attr = &lod_env_info(env)->lti_attr;
	int rc;

	LASSERT(lo->ldo_mirror_count == 1);

	mutex_lock(&lo->ldo_layout_mutex);

	rc = lod_layout_del_prep_layout(env, lo, th);
	if (rc < 0)
		GOTO(out, rc);

	/* Only do this if we didn't delete all components */
	if (lo->ldo_comp_cnt > 0) {
		lo->ldo_mirrors[0].lme_end = lo->ldo_comp_cnt - 1;
		lod_obj_inc_layout_gen(lo);
	}

	LASSERT(dt_object_exists(dt));
	rc = dt_attr_get(env, next, attr);
	if (rc)
		GOTO(out, rc);

	if (attr->la_size > 0) {
		attr->la_size = 0;
		attr->la_valid = LA_SIZE;
		rc = lod_sub_attr_set(env, next, attr, th);
		if (rc)
			GOTO(out, rc);
	}

	rc = lod_generate_and_set_lovea(env, lo, th);
	EXIT;
out:
	if (rc)
		lod_striping_free_nolock(env, lo);

	mutex_unlock(&lo->ldo_layout_mutex);

	return rc;
}


static int lod_get_default_lov_striping(const struct lu_env *env,
					struct lod_object *lo,
					struct lod_default_striping *lds,
					struct dt_allocation_hint *ah);
/**
 * Implementation of dt_object_operations::do_xattr_set.
 *
 * Sets specified extended attribute on the object. Three types of EAs are
 * special:
 *   LOV EA - stores striping for a regular file or default striping (when set
 *	      on a directory)
 *   LMV EA - stores a marker for the striped directories
 *   DMV EA - stores default directory striping
 *
 * When striping is applied to a non-striped existing object (this is called
 * late striping), then LOD notices the caller wants to turn the object into a
 * striped one. The stripe objects are created and appropriate EA is set:
 * LOV EA storing all the stripes directly or LMV EA storing just a small header
 * with striping configuration.
 *
 * \see dt_object_operations::do_xattr_set() in the API description for details.
 */
static int lod_xattr_set(const struct lu_env *env,
			 struct dt_object *dt, const struct lu_buf *buf,
			 const char *name, int fl, struct thandle *th)
{
	struct dt_object *next = dt_object_child(dt);
	int rc;

	ENTRY;

	if (S_ISDIR(dt->do_lu.lo_header->loh_attr) &&
	    !strcmp(name, XATTR_NAME_LMV)) {
		switch (fl) {
		case LU_XATTR_CREATE:
			rc = lod_dir_striping_create(env, dt, NULL, NULL, th);
			break;
		case 0:
		case LU_XATTR_REPLACE:
			rc = lod_dir_layout_set(env, dt, buf, fl, th);
			break;
		default:
			LBUG();
		}

		RETURN(rc);
	} else if (S_ISDIR(dt->do_lu.lo_header->loh_attr) &&
		   strcmp(name, XATTR_NAME_LOV) == 0) {
		struct lod_default_striping *lds = lod_lds_buf_get(env);
		struct lov_user_md_v1 *v1 = buf->lb_buf;
		char pool[LOV_MAXPOOLNAME + 1];
		bool is_del;

		/* get existing striping config */
		rc = lod_get_default_lov_striping(env, lod_dt_obj(dt), lds,
						  NULL);
		if (rc)
			RETURN(rc);

		memset(pool, 0, sizeof(pool));
		if (lds->lds_def_striping_set == 1)
			lod_layout_get_pool(lds->lds_def_comp_entries,
					    lds->lds_def_comp_cnt, pool,
					    sizeof(pool));

		is_del = LOVEA_DELETE_VALUES(v1->lmm_stripe_size,
					     v1->lmm_stripe_count,
					     v1->lmm_stripe_offset,
					     NULL);

		/* Retain the pool name if it is not given */
		if (v1->lmm_magic == LOV_USER_MAGIC_V1 && pool[0] != '\0' &&
			!is_del) {
			struct lod_thread_info *info = lod_env_info(env);
			struct lov_user_md_v3 *v3  = info->lti_ea_store;

			memset(v3, 0, sizeof(*v3));
			v3->lmm_magic = cpu_to_le32(LOV_USER_MAGIC_V3);
			v3->lmm_pattern = cpu_to_le32(v1->lmm_pattern);
			v3->lmm_stripe_count =
					cpu_to_le32(v1->lmm_stripe_count);
			v3->lmm_stripe_offset =
					cpu_to_le32(v1->lmm_stripe_offset);
			v3->lmm_stripe_size = cpu_to_le32(v1->lmm_stripe_size);

			strlcpy(v3->lmm_pool_name, pool,
				sizeof(v3->lmm_pool_name));

			info->lti_buf.lb_buf = v3;
			info->lti_buf.lb_len = sizeof(*v3);
			rc = lod_xattr_set_lov_on_dir(env, dt, &info->lti_buf,
						      name, fl, th);
		} else {
			rc = lod_xattr_set_lov_on_dir(env, dt, buf, name,
						      fl, th);
		}

		if (lds->lds_def_striping_set == 1 &&
		    lds->lds_def_comp_entries != NULL)
			lod_free_def_comp_entries(lds);

		RETURN(rc);
	} else if (S_ISDIR(dt->do_lu.lo_header->loh_attr) &&
		   strcmp(name, XATTR_NAME_DEFAULT_LMV) == 0) {
		/* default LMVEA */
		rc = lod_xattr_set_default_lmv_on_dir(env, dt, buf, name, fl,
						      th);
		RETURN(rc);
	} else if (S_ISREG(dt->do_lu.lo_header->loh_attr) &&
		   (strcmp(name, XATTR_NAME_LOV) == 0 ||
		    strcmp(name, XATTR_LUSTRE_LOV) == 0 ||
		    allowed_lustre_lov(name))) {
		/* in case of lov EA swap, just set it
		 * if not, it is a replay so check striping match what we
		 * already have during req replay, declare_xattr_set()
		 * defines striping, then create() does the work */
		if (fl & LU_XATTR_REPLACE) {
			/* free stripes, then update disk */
			lod_striping_free(env, lod_dt_obj(dt));

			rc = lod_sub_xattr_set(env, next, buf, name, fl, th);
		} else if (fl & LU_XATTR_PURGE) {
			rc = lod_layout_purge(env, dt, buf, th);
		} else if (dt_object_remote(dt)) {
			/* This only happens during migration, see
			 * mdd_migrate_create(), in which Master MDT will
			 * create a remote target object, and only set
			 * (migrating) stripe EA on the remote object,
			 * and does not need creating each stripes. */
			rc = lod_sub_xattr_set(env, next, buf, name,
						      fl, th);
		} else if (strcmp(name, XATTR_LUSTRE_LOV".del") == 0) {
			/* delete component(s) */
			LASSERT(lod_dt_obj(dt)->ldo_comp_cached);
			rc = lod_layout_del(env, dt, th);
		} else {
			/*
			 * When 'name' is XATTR_LUSTRE_LOV or XATTR_NAME_LOV,
			 * it's going to create create file with specified
			 * component(s), the striping must have not being
			 * cached in this case;
			 *
			 * Otherwise, it's going to add/change component(s) to
			 * an existing file, the striping must have been cached
			 * in this case.
			 */
			LASSERT(equi(!strcmp(name, XATTR_LUSTRE_LOV) ||
				     !strcmp(name, XATTR_NAME_LOV),
				!lod_dt_obj(dt)->ldo_comp_cached));

			rc = lod_striped_create(env, dt, NULL, NULL, th);
		}
		RETURN(rc);
	} else if (strcmp(name, XATTR_NAME_FID) == 0) {
		rc = lod_replace_parent_fid(env, dt, buf, th, false);

		RETURN(rc);
	}

	/* then all other xattr */
	rc = lod_xattr_set_internal(env, dt, buf, name, fl, th);

	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_declare_xattr_del.
 *
 * \see dt_object_operations::do_declare_xattr_del() in the API description
 * for details.
 */
static int lod_declare_xattr_del(const struct lu_env *env,
				 struct dt_object *dt, const char *name,
				 struct thandle *th)
{
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object *next = dt_object_child(dt);
	int i;
	int rc;
	ENTRY;

	rc = lod_sub_declare_xattr_del(env, next, name, th);
	if (rc != 0)
		RETURN(rc);

	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(0);

	/* NB: don't delete stripe LMV, because when we do this, normally we
	 * will remove stripes, besides, if directory LMV is corrupt, this will
	 * prevent deleting its LMV and fixing it (via LFSCK).
	 */
	if (!strcmp(name, XATTR_NAME_LMV))
		RETURN(0);

	rc = lod_striping_load(env, lo);
	if (rc != 0)
		RETURN(rc);

	if (lo->ldo_dir_stripe_count == 0)
		RETURN(0);

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		struct dt_object *dto = lo->ldo_stripe[i];

		if (!dto)
			continue;

		if (!dt_object_exists(dto))
			continue;

		rc = lod_sub_declare_xattr_del(env, dto, name, th);
		if (rc != 0)
			break;
	}

	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_xattr_del.
 *
 * If EA storing a regular striping is being deleted, then release
 * all the references to the stripe objects in core.
 *
 * \see dt_object_operations::do_xattr_del() in the API description for details.
 */
static int lod_xattr_del(const struct lu_env *env, struct dt_object *dt,
			 const char *name, struct thandle *th)
{
	int rc;

	ENTRY;

	if (!strcmp(name, XATTR_NAME_LOV) || !strcmp(name, XATTR_NAME_LMV))
		lod_striping_free(env, lod_dt_obj(dt));

	rc = lod_xattr_del_internal(env, dt, name, th);

	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_xattr_list.
 *
 * \see dt_object_operations::do_xattr_list() in the API description
 * for details.
 */
static int lod_xattr_list(const struct lu_env *env,
			  struct dt_object *dt, const struct lu_buf *buf)
{
	return dt_xattr_list(env, dt_object_child(dt), buf);
}

static inline int lod_object_will_be_striped(int is_reg, const struct lu_fid *fid)
{
	return (is_reg && fid_seq(fid) != FID_SEQ_LOCAL_FILE);
}

/**
 * Copy OST list from layout provided by user.
 *
 * \param[in] lod_comp		layout_component to be filled
 * \param[in] v3		LOV EA V3 user data
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
int lod_comp_copy_ost_lists(struct lod_layout_component *lod_comp,
			    struct lov_user_md_v3 *v3)
{
	int j;

	ENTRY;

	if (v3->lmm_stripe_offset == LOV_OFFSET_DEFAULT)
		v3->lmm_stripe_offset = v3->lmm_objects[0].l_ost_idx;

	if (lod_comp->llc_ostlist.op_array) {
		if (lod_comp->llc_ostlist.op_size >=
		    v3->lmm_stripe_count * sizeof(__u32))  {
			lod_comp->llc_ostlist.op_count =
					v3->lmm_stripe_count;
			goto skip;
		}
		OBD_FREE(lod_comp->llc_ostlist.op_array,
			 lod_comp->llc_ostlist.op_size);
	}

	/* copy ost list from lmm */
	lod_comp->llc_ostlist.op_count = v3->lmm_stripe_count;
	lod_comp->llc_ostlist.op_size = v3->lmm_stripe_count * sizeof(__u32);
	OBD_ALLOC(lod_comp->llc_ostlist.op_array,
		  lod_comp->llc_ostlist.op_size);
	if (!lod_comp->llc_ostlist.op_array)
		RETURN(-ENOMEM);
skip:
	for (j = 0; j < v3->lmm_stripe_count; j++) {
		lod_comp->llc_ostlist.op_array[j] =
			v3->lmm_objects[j].l_ost_idx;
	}

	RETURN(0);
}


/**
 * Get default striping.
 *
 * \param[in] env		execution environment
 * \param[in] lo		object
 * \param[out] lds		default striping
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_get_default_lov_striping(const struct lu_env *env,
					struct lod_object *lo,
					struct lod_default_striping *lds,
					struct dt_allocation_hint *ah)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lov_user_md_v1 *v1 = NULL;
	struct lov_user_md_v3 *v3 = NULL;
	struct lov_comp_md_v1 *comp_v1 = NULL;
	__u16 comp_cnt;
	__u16 mirror_cnt;
	bool composite;
	int rc, i, j;

	ENTRY;

	rc = lod_get_lov_ea(env, lo);
	if (rc < 0)
		RETURN(rc);

	if (rc < (typeof(rc))sizeof(struct lov_user_md))
		RETURN(0);

	v1 = info->lti_ea_store;
	if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_V1)) {
		lustre_swab_lov_user_md_v1(v1);
	} else if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_V3)) {
		v3 = (struct lov_user_md_v3 *)v1;
		lustre_swab_lov_user_md_v3(v3);
	} else if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_SPECIFIC)) {
		v3 = (struct lov_user_md_v3 *)v1;
		lustre_swab_lov_user_md_v3(v3);
		lustre_swab_lov_user_md_objects(v3->lmm_objects,
						v3->lmm_stripe_count);
	} else if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_COMP_V1) ||
		   v1->lmm_magic == __swab32(LOV_USER_MAGIC_SEL)) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		lustre_swab_lov_comp_md_v1(comp_v1);
	}

	if (v1->lmm_magic != LOV_MAGIC_V3 && v1->lmm_magic != LOV_MAGIC_V1 &&
	    v1->lmm_magic != LOV_MAGIC_COMP_V1 &&
	    v1->lmm_magic != LOV_MAGIC_SEL &&
	    v1->lmm_magic != LOV_USER_MAGIC_SPECIFIC)
		RETURN(-ENOTSUPP);

	if ((v1->lmm_magic == LOV_MAGIC_COMP_V1 ||
	    v1->lmm_magic == LOV_MAGIC_SEL) &&
	     !(ah && ah->dah_append_stripes)) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		comp_cnt = comp_v1->lcm_entry_count;
		if (comp_cnt == 0)
			RETURN(-EINVAL);
		mirror_cnt = comp_v1->lcm_mirror_count + 1;
		composite = true;
	} else {
		comp_cnt = 1;
		mirror_cnt = 0;
		composite = false;
	}

	/* realloc default comp entries if necessary */
	rc = lod_def_striping_comp_resize(lds, comp_cnt);
	if (rc < 0)
		RETURN(rc);

	lds->lds_def_comp_cnt = comp_cnt;
	lds->lds_def_striping_is_composite = composite;
	lds->lds_def_mirror_cnt = mirror_cnt;

	for (i = 0; i < comp_cnt; i++) {
		struct lod_layout_component *lod_comp;
		char *pool;

		lod_comp = &lds->lds_def_comp_entries[i];
		/*
		 * reset lod_comp values, llc_stripes is always NULL in
		 * the default striping template, llc_pool will be reset
		 * later below.
		 */
		memset(lod_comp, 0, offsetof(typeof(*lod_comp), llc_pool));

		if (composite) {
			v1 = (struct lov_user_md *)((char *)comp_v1 +
					comp_v1->lcm_entries[i].lcme_offset);
			lod_comp->llc_extent =
					comp_v1->lcm_entries[i].lcme_extent;
			/* We only inherit certain flags from the layout */
			lod_comp->llc_flags =
					comp_v1->lcm_entries[i].lcme_flags &
					LCME_TEMPLATE_FLAGS;
		}

		if (!lov_pattern_supported(v1->lmm_pattern) &&
		    !(v1->lmm_pattern & LOV_PATTERN_F_RELEASED)) {
			lod_free_def_comp_entries(lds);
			RETURN(-EINVAL);
		}

		CDEBUG(D_LAYOUT, DFID" stripe_count=%d stripe_size=%d stripe_offset=%d append_stripes=%d\n",
		       PFID(lu_object_fid(&lo->ldo_obj.do_lu)),
		       (int)v1->lmm_stripe_count, (int)v1->lmm_stripe_size,
		       (int)v1->lmm_stripe_offset,
		       ah ? ah->dah_append_stripes : 0);

		if (ah && ah->dah_append_stripes)
			lod_comp->llc_stripe_count = ah->dah_append_stripes;
		else
			lod_comp->llc_stripe_count = v1->lmm_stripe_count;
		lod_comp->llc_stripe_size = v1->lmm_stripe_size;
		lod_comp->llc_stripe_offset = v1->lmm_stripe_offset;
		lod_comp->llc_pattern = v1->lmm_pattern;

		pool = NULL;
		if (ah && ah->dah_append_pool && ah->dah_append_pool[0]) {
			pool = ah->dah_append_pool;
		} else if (v1->lmm_magic == LOV_USER_MAGIC_V3) {
			/* XXX: sanity check here */
			v3 = (struct lov_user_md_v3 *) v1;
			if (v3->lmm_pool_name[0] != '\0')
				pool = v3->lmm_pool_name;
		}
		lod_set_def_pool(lds, i, pool);
		if (v1->lmm_magic == LOV_USER_MAGIC_SPECIFIC) {
			v3 = (struct lov_user_md_v3 *)v1;
			rc = lod_comp_copy_ost_lists(lod_comp, v3);
			if (rc)
				RETURN(rc);
		} else if (lod_comp->llc_ostlist.op_array &&
			   lod_comp->llc_ostlist.op_count) {
			for (j = 0; j < lod_comp->llc_ostlist.op_count; j++)
				lod_comp->llc_ostlist.op_array[j] = -1;
			lod_comp->llc_ostlist.op_count = 0;
		}
	}

	lds->lds_def_striping_set = 1;
	RETURN(rc);
}

/**
 * Get default directory striping.
 *
 * \param[in] env		execution environment
 * \param[in] lo		object
 * \param[out] lds		default striping
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_get_default_lmv_striping(const struct lu_env *env,
					struct lod_object *lo,
					struct lod_default_striping *lds)
{
	struct lmv_user_md *lmu;
	int rc;

	lds->lds_dir_def_striping_set = 0;

	rc = lod_get_default_lmv_ea(env, lo);
	if (rc < 0)
		return rc;

	if (rc >= (int)sizeof(*lmu)) {
		struct lod_thread_info *info = lod_env_info(env);

		lmu = info->lti_ea_store;

		lds->lds_dir_def_stripe_count =
				le32_to_cpu(lmu->lum_stripe_count);
		lds->lds_dir_def_stripe_offset =
				le32_to_cpu(lmu->lum_stripe_offset);
		lds->lds_dir_def_hash_type =
				le32_to_cpu(lmu->lum_hash_type);
		lds->lds_dir_def_max_inherit = lmu->lum_max_inherit;
		lds->lds_dir_def_max_inherit_rr = lmu->lum_max_inherit_rr;
		lds->lds_dir_def_striping_set = 1;
	}

	return 0;
}

/**
 * Get default striping in the object.
 *
 * Get object default striping and default directory striping.
 *
 * \param[in] env		execution environment
 * \param[in] lo		object
 * \param[out] lds		default striping
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_get_default_striping(const struct lu_env *env,
				    struct lod_object *lo,
				    struct lod_default_striping *lds)
{
	int rc, rc1;

	rc = lod_get_default_lov_striping(env, lo, lds, NULL);
	rc1 = lod_get_default_lmv_striping(env, lo, lds);
	if (rc == 0 && rc1 < 0)
		rc = rc1;

	return rc;
}

/**
 * Apply default striping on object.
 *
 * If object striping pattern is not set, set to the one in default striping.
 * The default striping is from parent or fs.
 *
 * \param[in] lo		new object
 * \param[in] lds		default striping
 * \param[in] mode		new object's mode
 */
static void lod_striping_from_default(struct lod_object *lo,
				      const struct lod_default_striping *lds,
				      umode_t mode)
{
	struct lod_device *d = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	int i, rc;

	if (lds->lds_def_striping_set && S_ISREG(mode)) {
		struct lov_desc *desc = &d->lod_ost_descs.ltd_lov_desc;

		rc = lod_alloc_comp_entries(lo, lds->lds_def_mirror_cnt,
					    lds->lds_def_comp_cnt);
		if (rc != 0)
			return;

		lo->ldo_is_composite = lds->lds_def_striping_is_composite;
		if (lds->lds_def_mirror_cnt > 1)
			lo->ldo_flr_state = LCM_FL_RDONLY;

		for (i = 0; i < lo->ldo_comp_cnt; i++) {
			struct lod_layout_component *obj_comp =
						&lo->ldo_comp_entries[i];
			struct lod_layout_component *def_comp =
						&lds->lds_def_comp_entries[i];

			CDEBUG(D_LAYOUT, "Inherit from default: flags=%#x "
			       "size=%hu nr=%u offset=%u pattern=%#x pool=%s\n",
			       def_comp->llc_flags,
			       def_comp->llc_stripe_size,
			       def_comp->llc_stripe_count,
			       def_comp->llc_stripe_offset,
			       def_comp->llc_pattern,
			       def_comp->llc_pool ?: "");

			*obj_comp = *def_comp;
			if (def_comp->llc_pool != NULL) {
				/* pointer was copied from def_comp */
				obj_comp->llc_pool = NULL;
				lod_obj_set_pool(lo, i, def_comp->llc_pool);
			}

			/* copy ost list */
			if (def_comp->llc_ostlist.op_array &&
			    def_comp->llc_ostlist.op_count) {
				OBD_ALLOC(obj_comp->llc_ostlist.op_array,
					  obj_comp->llc_ostlist.op_size);
				if (!obj_comp->llc_ostlist.op_array)
					return;
				memcpy(obj_comp->llc_ostlist.op_array,
				       def_comp->llc_ostlist.op_array,
				       obj_comp->llc_ostlist.op_size);
			} else if (def_comp->llc_ostlist.op_array) {
				obj_comp->llc_ostlist.op_array = NULL;
			}

			/*
			 * Don't initialize these fields for plain layout
			 * (v1/v3) here, they are inherited in the order of
			 * 'parent' -> 'fs default (root)' -> 'global default
			 * values for stripe_count & stripe_size'.
			 *
			 * see lod_ah_init().
			 */
			if (!lo->ldo_is_composite)
				continue;

			lod_adjust_stripe_info(obj_comp, desc, 0);
		}
	} else if (lds->lds_dir_def_striping_set && S_ISDIR(mode)) {
		if (lo->ldo_dir_stripe_count == 0)
			lo->ldo_dir_stripe_count =
				lds->lds_dir_def_stripe_count;
		if (lo->ldo_dir_stripe_offset == -1)
			lo->ldo_dir_stripe_offset =
				lds->lds_dir_def_stripe_offset;
		if (lo->ldo_dir_hash_type == 0)
			lo->ldo_dir_hash_type = lds->lds_dir_def_hash_type;

		CDEBUG(D_LAYOUT, "striping from default dir: count:%hu, "
		       "offset:%u, hash_type:%u\n",
		       lo->ldo_dir_stripe_count, lo->ldo_dir_stripe_offset,
		       lo->ldo_dir_hash_type);
	}
}

static inline bool lod_need_inherit_more(struct lod_object *lo, bool from_root,
					 char *append_pool)
{
	struct lod_layout_component *lod_comp;

	if (lo->ldo_comp_cnt == 0)
		return true;

	if (lo->ldo_is_composite)
		return false;

	lod_comp = &lo->ldo_comp_entries[0];

	if (lod_comp->llc_stripe_count <= 0 ||
	    lod_comp->llc_stripe_size <= 0)
		return true;

	if (from_root && (lod_comp->llc_pool == NULL ||
			  lod_comp->llc_stripe_offset == LOV_OFFSET_DEFAULT))
		return true;

	if (append_pool && append_pool[0])
		return true;

	return false;
}

/**
 * Implementation of dt_object_operations::do_ah_init.
 *
 * This method is used to make a decision on the striping configuration for the
 * object being created. It can be taken from the \a parent object if it exists,
 * or filesystem's default. The resulting configuration (number of stripes,
 * stripe size/offset, pool name, etc) is stored in the object itself and will
 * be used by the methods like ->doo_declare_create().
 *
 * \see dt_object_operations::do_ah_init() in the API description for details.
 */
static void lod_ah_init(const struct lu_env *env,
			struct dt_allocation_hint *ah,
			struct dt_object *parent,
			struct dt_object *child,
			umode_t child_mode)
{
	struct lod_device *d = lu2lod_dev(child->do_lu.lo_dev);
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_default_striping *lds = lod_lds_buf_get(env);
	struct dt_object *nextp = NULL;
	struct dt_object *nextc;
	struct lod_object *lp = NULL;
	struct lod_object *lc;
	struct lov_desc *desc;
	struct lod_layout_component *lod_comp;
	int rc;
	ENTRY;

	LASSERT(child);

	if (ah->dah_append_stripes == -1)
		ah->dah_append_stripes =
			d->lod_ost_descs.ltd_lov_desc.ld_tgt_count;

	if (likely(parent)) {
		nextp = dt_object_child(parent);
		lp = lod_dt_obj(parent);
	}

	nextc = dt_object_child(child);
	lc = lod_dt_obj(child);

	LASSERT(!lod_obj_is_striped(child));
	/* default layout template may have been set on the regular file
	 * when this is called from mdd_create_data() */
	if (S_ISREG(child_mode))
		lod_free_comp_entries(lc);

	if (!dt_object_exists(nextc))
		nextc->do_ops->do_ah_init(env, ah, nextp, nextc, child_mode);

	if (S_ISDIR(child_mode)) {
		const struct lmv_user_md_v1 *lum1 = ah->dah_eadata;

		/* other default values are 0 */
		lc->ldo_dir_stripe_offset = -1;

		/* no default striping configuration is needed for
		 * foreign dirs
		 */
		if (ah->dah_eadata != NULL && ah->dah_eadata_len != 0 &&
		    le32_to_cpu(lum1->lum_magic) == LMV_MAGIC_FOREIGN) {
			lc->ldo_dir_is_foreign = true;
			/* keep stripe_count 0 and stripe_offset -1 */
			CDEBUG(D_INFO, "no default striping for foreign dir\n");
			RETURN_EXIT;
		}

		/*
		 * If parent object is not root directory,
		 * then get default striping from parent object.
		 */
		if (likely(lp != NULL)) {
			lod_get_default_striping(env, lp, lds);

			/* inherit default striping except ROOT */
			if ((lds->lds_def_striping_set ||
			     lds->lds_dir_def_striping_set) &&
			    !fid_is_root(lod_object_fid(lp)))
				lc->ldo_def_striping = lds;
		}

		/* It should always honour the specified stripes */
		/* Note: old client (< 2.7)might also do lfs mkdir, whose EA
		 * will have old magic. In this case, we should ignore the
		 * stripe count and try to create dir by default stripe.
		 */
		if (ah->dah_eadata != NULL && ah->dah_eadata_len != 0 &&
		    (le32_to_cpu(lum1->lum_magic) == LMV_USER_MAGIC ||
		     le32_to_cpu(lum1->lum_magic) == LMV_USER_MAGIC_SPECIFIC)) {
			lc->ldo_dir_stripe_count =
				le32_to_cpu(lum1->lum_stripe_count);
			lc->ldo_dir_stripe_offset =
				le32_to_cpu(lum1->lum_stripe_offset);
			lc->ldo_dir_hash_type =
				le32_to_cpu(lum1->lum_hash_type);
			CDEBUG(D_INFO,
			       "set dirstripe: count %hu, offset %d, hash %u\n",
				lc->ldo_dir_stripe_count,
				(int)lc->ldo_dir_stripe_offset,
				lc->ldo_dir_hash_type);
		} else {
			/* transfer defaults LMV to new directory */
			lod_striping_from_default(lc, lds, child_mode);

			/* set count 0 to create normal directory */
			if (lc->ldo_dir_stripe_count == 1)
				lc->ldo_dir_stripe_count = 0;
		}

		/* shrink the stripe_count to the avaible MDT count */
		if (lc->ldo_dir_stripe_count > d->lod_remote_mdt_count + 1 &&
		    !OBD_FAIL_CHECK(OBD_FAIL_LARGE_STRIPE)) {
			lc->ldo_dir_stripe_count = d->lod_remote_mdt_count + 1;
			if (lc->ldo_dir_stripe_count == 1)
				lc->ldo_dir_stripe_count = 0;
		}

		if (!(lc->ldo_dir_hash_type & LMV_HASH_TYPE_MASK))
			lc->ldo_dir_hash_type |=
				d->lod_mdt_descs.ltd_lmv_desc.ld_pattern;

		CDEBUG(D_INFO, "final dir stripe [%hu %d %u]\n",
		       lc->ldo_dir_stripe_count,
		       (int)lc->ldo_dir_stripe_offset, lc->ldo_dir_hash_type);

		RETURN_EXIT;
	}

	/* child object regular file*/

	if (!lod_object_will_be_striped(S_ISREG(child_mode),
					lu_object_fid(&child->do_lu)))
		RETURN_EXIT;

	/* If object is going to be striped over OSTs, transfer default
	 * striping information to the child, so that we can use it
	 * during declaration and creation.
	 *
	 * Try from the parent first.
	 */
	if (likely(lp != NULL)) {
		rc = lod_get_default_lov_striping(env, lp, lds, ah);
		if (rc == 0)
			lod_striping_from_default(lc, lds, child_mode);
	}

	/* Initialize lod_device::lod_md_root object reference */
	if (d->lod_md_root == NULL) {
		struct dt_object *root;
		struct lod_object *lroot;

		lu_root_fid(&info->lti_fid);
		root = dt_locate(env, &d->lod_dt_dev, &info->lti_fid);
		if (!IS_ERR(root)) {
			lroot = lod_dt_obj(root);

			spin_lock(&d->lod_lock);
			if (d->lod_md_root != NULL)
				dt_object_put(env, &d->lod_md_root->ldo_obj);
			d->lod_md_root = lroot;
			spin_unlock(&d->lod_lock);
		}
	}

	/* try inherit layout from the root object (fs default) when:
	 *  - parent does not have default layout; or
	 *  - parent has plain(v1/v3) default layout, and some attributes
	 *    are not specified in the default layout;
	 */
	if (d->lod_md_root != NULL &&
	    lod_need_inherit_more(lc, true, ah->dah_append_pool)) {
		rc = lod_get_default_lov_striping(env, d->lod_md_root, lds,
						  ah);
		if (rc)
			goto out;
		if (lc->ldo_comp_cnt == 0) {
			lod_striping_from_default(lc, lds, child_mode);
		} else if (!lds->lds_def_striping_is_composite) {
			struct lod_layout_component *def_comp;

			LASSERT(!lc->ldo_is_composite);
			lod_comp = &lc->ldo_comp_entries[0];
			def_comp = &lds->lds_def_comp_entries[0];

			if (lod_comp->llc_stripe_count <= 0)
				lod_comp->llc_stripe_count =
					def_comp->llc_stripe_count;
			if (lod_comp->llc_stripe_size <= 0)
				lod_comp->llc_stripe_size =
					def_comp->llc_stripe_size;
			if (lod_comp->llc_stripe_offset == LOV_OFFSET_DEFAULT &&
			    (!lod_comp->llc_pool || !lod_comp->llc_pool[0]))
				lod_comp->llc_stripe_offset =
					def_comp->llc_stripe_offset;
			if (lod_comp->llc_pool == NULL)
				lod_obj_set_pool(lc, 0, def_comp->llc_pool);
		}
	}
out:
	/*
	 * fs default striping may not be explicitly set, or historically set
	 * in config log, use them.
	 */
	if (lod_need_inherit_more(lc, false, ah->dah_append_pool)) {
		if (lc->ldo_comp_cnt == 0) {
			rc = lod_alloc_comp_entries(lc, 0, 1);
			if (rc)
				/* fail to allocate memory, will create a
				 * non-striped file. */
				RETURN_EXIT;
			lc->ldo_is_composite = 0;
			lod_comp = &lc->ldo_comp_entries[0];
			lod_comp->llc_stripe_offset = LOV_OFFSET_DEFAULT;
		}
		LASSERT(!lc->ldo_is_composite);
		lod_comp = &lc->ldo_comp_entries[0];
		desc = &d->lod_ost_descs.ltd_lov_desc;
		lod_adjust_stripe_info(lod_comp, desc, ah->dah_append_stripes);
		if (ah->dah_append_pool && ah->dah_append_pool[0])
			lod_obj_set_pool(lc, 0, ah->dah_append_pool);
	}

	EXIT;
}

/**
 * Size initialization on late striping.
 *
 * Propagate the size of a truncated object to a deferred striping.
 * This function handles a special case when truncate was done on a
 * non-striped object and now while the striping is being created
 * we can't lose that size, so we have to propagate it to the stripes
 * being created.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_declare_init_size(const struct lu_env *env,
				 struct dt_object *dt, struct thandle *th)
{
	struct dt_object	*next = dt_object_child(dt);
	struct lod_object	*lo = lod_dt_obj(dt);
	struct dt_object	**objects = NULL;
	struct lu_attr	*attr = &lod_env_info(env)->lti_attr;
	uint64_t	size, offs;
	int	i, rc, stripe, stripe_count = 0, stripe_size = 0;
	struct lu_extent size_ext;
	ENTRY;

	if (!lod_obj_is_striped(dt))
		RETURN(0);

	rc = dt_attr_get(env, next, attr);
	LASSERT(attr->la_valid & LA_SIZE);
	if (rc)
		RETURN(rc);

	size = attr->la_size;
	if (size == 0)
		RETURN(0);

	size_ext = (typeof(size_ext)){ .e_start = size - 1, .e_end = size };
	for (i = 0; i < lo->ldo_comp_cnt; i++) {
		struct lod_layout_component *lod_comp;
		struct lu_extent *extent;

		lod_comp = &lo->ldo_comp_entries[i];

		if (lod_comp->llc_stripe == NULL)
			continue;

		extent = &lod_comp->llc_extent;
		CDEBUG(D_INFO, "%lld "DEXT"\n", size, PEXT(extent));
		if (!lo->ldo_is_composite ||
		    lu_extent_is_overlapped(extent, &size_ext)) {
			objects = lod_comp->llc_stripe;
			stripe_count = lod_comp->llc_stripe_count;
			stripe_size = lod_comp->llc_stripe_size;

			/* next mirror */
			if (stripe_count == 0)
				continue;

			LASSERT(objects != NULL && stripe_size != 0);
			do_div(size, stripe_size);
			stripe = do_div(size, stripe_count);
			LASSERT(objects[stripe] != NULL);

			size = size * stripe_size;
			offs = attr->la_size;
			size += do_div(offs, stripe_size);

			attr->la_valid = LA_SIZE;
			attr->la_size = size;

			rc = lod_sub_declare_attr_set(env, objects[stripe],
						      attr, th);
		}
	}

	RETURN(rc);
}

/**
 * Declare creation of striped object.
 *
 * The function declares creation stripes for a regular object. The function
 * also declares whether the stripes will be created with non-zero size if
 * previously size was set non-zero on the master object. If object \a dt is
 * not local, then only fully defined striping can be applied in \a lovea.
 * Otherwise \a lovea can be in the form of pattern, see lod_qos_parse_config()
 * for the details.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[in] attr	attributes the stripes will be created with
 * \param[in] lovea	a buffer containing striping description
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
int lod_declare_striped_create(const struct lu_env *env, struct dt_object *dt,
			       struct lu_attr *attr,
			       const struct lu_buf *lovea, struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct dt_object	*next = dt_object_child(dt);
	struct lod_object	*lo = lod_dt_obj(dt);
	int			 rc;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_ALLOC_OBDO))
		GOTO(out, rc = -ENOMEM);

	if (!dt_object_remote(next)) {
		/* choose OST and generate appropriate objects */
		rc = lod_prepare_create(env, lo, attr, lovea, th);
		if (rc)
			GOTO(out, rc);

		/*
		 * declare storage for striping data
		 */
		info->lti_buf.lb_len = lod_comp_md_size(lo, false);
	} else {
		/* LOD can not choose OST objects for remote objects, i.e.
		 * stripes must be ready before that. Right now, it can only
		 * happen during migrate, i.e. migrate process needs to create
		 * remote regular file (mdd_migrate_create), then the migrate
		 * process will provide stripeEA. */
		LASSERT(lovea != NULL);
		info->lti_buf = *lovea;
	}

	rc = lod_sub_declare_xattr_set(env, next, &info->lti_buf,
				       XATTR_NAME_LOV, 0, th);
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
	/* failed to create striping or to set initial size, let's reset
	 * config so that others don't get confused */
	if (rc)
		lod_striping_free(env, lo);

	RETURN(rc);
}

/*
 * Whether subdirectories under \a dt should be created on MDTs by space QoS
 *
 * If LMV_HASH_FLAG_SPACE is set on directory default layout, its subdirectories
 * should be created on MDT by space QoS.
 *
 * \param[in] env	execution environment
 * \param[in] dev	lu device
 * \param[in] dt	object
 *
 * \retval		1 if directory should create subdir by space usage
 * \retval		0 if not
 * \retval		-ev if failed
 */
static inline int dt_object_qos_mkdir(const struct lu_env *env,
				      struct lu_device *dev,
				      struct dt_object *dt)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lu_object *obj;
	struct lod_object *lo;
	struct lmv_user_md *lmu;
	int rc;

	obj = lu_object_find_slice(env, dev, lu_object_fid(&dt->do_lu), NULL);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	lo = lu2lod_obj(obj);

	rc = lod_get_default_lmv_ea(env, lo);
	dt_object_put(env, dt);
	if (rc <= 0)
		return rc;

	if (rc < (int)sizeof(*lmu))
		return -EINVAL;

	lmu = info->lti_ea_store;
	return le32_to_cpu(lmu->lum_stripe_offset) == LMV_OFFSET_DEFAULT;
}

/**
 * Implementation of dt_object_operations::do_declare_create.
 *
 * The method declares creation of a new object. If the object will be striped,
 * then helper functions are called to find FIDs for the stripes, declare
 * creation of the stripes and declare initialization of the striping
 * information to be stored in the master object.
 *
 * \see dt_object_operations::do_declare_create() in the API description
 * for details.
 */
static int lod_declare_create(const struct lu_env *env, struct dt_object *dt,
			      struct lu_attr *attr,
			      struct dt_allocation_hint *hint,
			      struct dt_object_format *dof, struct thandle *th)
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
	rc = lod_sub_declare_create(env, next, attr, hint, dof, th);
	if (rc != 0)
		GOTO(out, rc);

	/*
	 * it's lod_ah_init() that has decided the object will be striped
	 */
	if (dof->dof_type == DFT_REGULAR) {
		/* callers don't want stripes */
		/* XXX: all tricky interactions with ->ah_make_hint() decided
		 * to use striping, then ->declare_create() behaving differently
		 * should be cleaned */
		if (dof->u.dof_reg.striped != 0)
			rc = lod_declare_striped_create(env, dt, attr,
							NULL, th);
	} else if (dof->dof_type == DFT_DIR) {
		struct seq_server_site *ss;
		struct lu_buf buf = { NULL };
		struct lu_buf *lmu = NULL;

		ss = lu_site2seq(dt->do_lu.lo_dev->ld_site);

		/* If the parent has default stripeEA, and client
		 * did not find it before sending create request,
		 * then MDT will return -EREMOTE, and client will
		 * retrieve the default stripeEA and re-create the
		 * sub directory.
		 *
		 * Note: if dah_eadata != NULL, it means creating the
		 * striped directory with specified stripeEA, then it
		 * should ignore the default stripeEA */
		if (hint != NULL && hint->dah_eadata == NULL) {
			if (OBD_FAIL_CHECK(OBD_FAIL_MDS_STALE_DIR_LAYOUT))
				GOTO(out, rc = -EREMOTE);

			if (lo->ldo_dir_stripe_offset == LMV_OFFSET_DEFAULT) {
				struct lod_default_striping *lds;

				lds = lo->ldo_def_striping;
				/*
				 * child and parent should be on the same MDT,
				 * but if parent has default LMV, and the start
				 * MDT offset is -1, it's allowed. This check
				 * is not necessary after 2.12.22 because client
				 * follows this already, but old client may not.
				 */
				if (hint->dah_parent &&
				    dt_object_remote(hint->dah_parent) && lds &&
				    lds->lds_dir_def_stripe_offset !=
				    LMV_OFFSET_DEFAULT)
					GOTO(out, rc = -EREMOTE);
			} else if (lo->ldo_dir_stripe_offset !=
				   ss->ss_node_id) {
				struct lod_device *lod;
				struct lu_tgt_desc *mdt = NULL;
				bool found_mdt = false;

				lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
				lod_foreach_mdt(lod, mdt) {
					if (mdt->ltd_index ==
						lo->ldo_dir_stripe_offset) {
						found_mdt = true;
						break;
					}
				}

				/* If the MDT indicated by stripe_offset can be
				 * found, then tell client to resend the create
				 * request to the correct MDT, otherwise return
				 * error to client */
				if (found_mdt)
					GOTO(out, rc = -EREMOTE);
				else
					GOTO(out, rc = -EINVAL);
			}
		} else if (hint && hint->dah_eadata) {
			lmu = &buf;
			lmu->lb_buf = (void *)hint->dah_eadata;
			lmu->lb_len = hint->dah_eadata_len;
		}

		rc = lod_declare_dir_striping_create(env, dt, attr, lmu, dof,
						     th);
	}
out:
	/* failed to create striping or to set initial size, let's reset
	 * config so that others don't get confused */
	if (rc)
		lod_striping_free(env, lo);
	RETURN(rc);
}

/**
 * Generate component ID for new created component.
 *
 * \param[in] lo		LOD object
 * \param[in] comp_idx		index of ldo_comp_entries
 *
 * \retval			component ID on success
 * \retval			LCME_ID_INVAL on failure
 */
static __u32 lod_gen_component_id(struct lod_object *lo,
				  int mirror_id, int comp_idx)
{
	struct lod_layout_component *lod_comp;
	__u32	id, start, end;
	int	i;

	LASSERT(lo->ldo_comp_entries[comp_idx].llc_id == LCME_ID_INVAL);

	lod_obj_inc_layout_gen(lo);
	id = lo->ldo_layout_gen;
	if (likely(id <= SEQ_ID_MAX))
		RETURN(pflr_id(mirror_id, id & SEQ_ID_MASK));

	/* Layout generation wraps, need to check collisions. */
	start = id & SEQ_ID_MASK;
	end = SEQ_ID_MAX;
again:
	for (id = start; id <= end; id++) {
		for (i = 0; i < lo->ldo_comp_cnt; i++) {
			lod_comp = &lo->ldo_comp_entries[i];
			if (pflr_id(mirror_id, id) == lod_comp->llc_id)
				break;
		}
		/* Found the ununsed ID */
		if (i == lo->ldo_comp_cnt)
			RETURN(pflr_id(mirror_id, id));
	}
	if (end == LCME_ID_MAX) {
		start = 1;
		end = min(lo->ldo_layout_gen & LCME_ID_MASK,
			  (__u32)(LCME_ID_MAX - 1));
		goto again;
	}

	RETURN(LCME_ID_INVAL);
}

/**
 * Creation of a striped regular object.
 *
 * The function is called to create the stripe objects for a regular
 * striped file. This can happen at the initial object creation or
 * when the caller asks LOD to do so using ->do_xattr_set() method
 * (so called late striping). Notice all the information are already
 * prepared in the form of the list of objects (ldo_stripe field).
 * This is done during declare phase.
 *
 * \param[in] env	execution environment
 * \param[in] dt	object
 * \param[in] attr	attributes the stripes will be created with
 * \param[in] dof	format of stripes (see OSD API description)
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
int lod_striped_create(const struct lu_env *env, struct dt_object *dt,
		       struct lu_attr *attr, struct dt_object_format *dof,
		       struct thandle *th)
{
	struct lod_layout_component	*lod_comp;
	struct lod_object	*lo = lod_dt_obj(dt);
	__u16	mirror_id;
	int	rc = 0, i, j;
	ENTRY;

	mutex_lock(&lo->ldo_layout_mutex);

	LASSERT((lo->ldo_comp_cnt != 0 && lo->ldo_comp_entries != NULL) ||
		lo->ldo_is_foreign);

	mirror_id = 0; /* non-flr file's mirror_id is 0 */
	if (lo->ldo_mirror_count > 1) {
		for (i = 0; i < lo->ldo_comp_cnt; i++) {
			lod_comp = &lo->ldo_comp_entries[i];
			if (lod_comp->llc_id != LCME_ID_INVAL &&
			    mirror_id_of(lod_comp->llc_id) > mirror_id)
				mirror_id = mirror_id_of(lod_comp->llc_id);
		}
	}

	/* create all underlying objects */
	for (i = 0; i < lo->ldo_comp_cnt; i++) {
		lod_comp = &lo->ldo_comp_entries[i];

		if (lod_comp->llc_id == LCME_ID_INVAL) {
			/* only the component of FLR layout with more than 1
			 * mirror has mirror ID in its component ID.
			 */
			if (lod_comp->llc_extent.e_start == 0 &&
			    lo->ldo_mirror_count > 1)
				++mirror_id;

			lod_comp->llc_id = lod_gen_component_id(lo,
								mirror_id, i);
			if (lod_comp->llc_id == LCME_ID_INVAL)
				GOTO(out, rc = -ERANGE);
		}

		if (lod_comp_inited(lod_comp))
			continue;

		if (lod_comp->llc_pattern & LOV_PATTERN_F_RELEASED)
			lod_comp_set_init(lod_comp);

		if (lov_pattern(lod_comp->llc_pattern) == LOV_PATTERN_MDT)
			lod_comp_set_init(lod_comp);

		if (lod_comp->llc_stripe == NULL)
			continue;

		LASSERT(lod_comp->llc_stripe_count);
		for (j = 0; j < lod_comp->llc_stripe_count; j++) {
			struct dt_object *object = lod_comp->llc_stripe[j];
			LASSERT(object != NULL);
			rc = lod_sub_create(env, object, attr, NULL, dof, th);
			if (rc)
				GOTO(out, rc);
		}
		lod_comp_set_init(lod_comp);
	}

	rc = lod_fill_mirrors(lo);
	if (rc)
		GOTO(out, rc);

	lo->ldo_comp_cached = 1;

	rc = lod_generate_and_set_lovea(env, lo, th);
	if (rc)
		GOTO(out, rc);

	mutex_unlock(&lo->ldo_layout_mutex);

	RETURN(0);

out:
	lod_striping_free_nolock(env, lo);
	mutex_unlock(&lo->ldo_layout_mutex);

	RETURN(rc);
}

static inline bool lod_obj_is_dom(struct dt_object *dt)
{
	struct lod_object *lo = lod_dt_obj(dt);

	if (!dt_object_exists(dt_object_child(dt)))
		return false;

	if (S_ISDIR(dt->do_lu.lo_header->loh_attr))
		return false;

	if (!lo->ldo_comp_cnt)
		return false;

	return (lov_pattern(lo->ldo_comp_entries[0].llc_pattern) ==
		LOV_PATTERN_MDT);
}

/**
 * Implementation of dt_object_operations::do_create.
 *
 * If any of preceeding methods (like ->do_declare_create(),
 * ->do_ah_init(), etc) chose to create a striped object,
 * then this method will create the master and the stripes.
 *
 * \see dt_object_operations::do_create() in the API description for details.
 */
static int lod_create(const struct lu_env *env, struct dt_object *dt,
		      struct lu_attr *attr, struct dt_allocation_hint *hint,
		      struct dt_object_format *dof, struct thandle *th)
{
	int		    rc;
	ENTRY;

	/* create local object */
	rc = lod_sub_create(env, dt_object_child(dt), attr, hint, dof, th);
	if (rc != 0)
		RETURN(rc);

	if (S_ISREG(dt->do_lu.lo_header->loh_attr) &&
	    (lod_obj_is_striped(dt) || lod_obj_is_dom(dt)) &&
	    dof->u.dof_reg.striped != 0) {
		LASSERT(lod_dt_obj(dt)->ldo_comp_cached == 0);
		rc = lod_striped_create(env, dt, attr, dof, th);
	}

	RETURN(rc);
}

static inline int
lod_obj_stripe_destroy_cb(const struct lu_env *env, struct lod_object *lo,
			  struct dt_object *dt, struct thandle *th,
			  int comp_idx, int stripe_idx,
			  struct lod_obj_stripe_cb_data *data)
{
	if (data->locd_declare)
		return lod_sub_declare_destroy(env, dt, th);

	if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_SPEOBJ) ||
	    stripe_idx == cfs_fail_val)
		return lod_sub_destroy(env, dt, th);

	return 0;
}

/**
 * Implementation of dt_object_operations::do_declare_destroy.
 *
 * If the object is a striped directory, then the function declares reference
 * removal from the master object (this is an index) to the stripes and declares
 * destroy of all the stripes. In all the cases, it declares an intention to
 * destroy the object itself.
 *
 * \see dt_object_operations::do_declare_destroy() in the API description
 * for details.
 */
static int lod_declare_destroy(const struct lu_env *env, struct dt_object *dt,
			       struct thandle *th)
{
	struct dt_object *next = dt_object_child(dt);
	struct lod_object *lo = lod_dt_obj(dt);
	struct lod_thread_info *info = lod_env_info(env);
	struct dt_object *stripe;
	char *stripe_name = info->lti_key;
	int rc, i;

	ENTRY;

	/*
	 * load striping information, notice we don't do this when object
	 * is being initialized as we don't need this information till
	 * few specific cases like destroy, chown
	 */
	rc = lod_striping_load(env, lo);
	if (rc)
		RETURN(rc);

	/* declare destroy for all underlying objects */
	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		rc = next->do_ops->do_index_try(env, next,
						&dt_directory_features);
		if (rc != 0)
			RETURN(rc);

		for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
			stripe = lo->ldo_stripe[i];
			if (!stripe)
				continue;

			rc = lod_sub_declare_ref_del(env, next, th);
			if (rc != 0)
				RETURN(rc);

			snprintf(stripe_name, sizeof(info->lti_key),
				 DFID":%d",
				 PFID(lu_object_fid(&stripe->do_lu)), i);
			rc = lod_sub_declare_delete(env, next,
					(const struct dt_key *)stripe_name, th);
			if (rc != 0)
				RETURN(rc);
		}
	}

	/*
	 * we declare destroy for the local object
	 */
	rc = lod_sub_declare_destroy(env, next, th);
	if (rc)
		RETURN(rc);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_MDTOBJ) ||
	    OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_MDTOBJ2))
		RETURN(0);

	if (!lod_obj_is_striped(dt))
		RETURN(0);

	/* declare destroy all striped objects */
	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
			stripe = lo->ldo_stripe[i];
			if (!stripe)
				continue;

			if (!dt_object_exists(stripe))
				continue;

			rc = lod_sub_declare_ref_del(env, stripe, th);
			if (rc != 0)
				break;

			rc = lod_sub_declare_destroy(env, stripe, th);
			if (rc != 0)
				break;
		}
	} else {
		struct lod_obj_stripe_cb_data data = { { 0 } };

		data.locd_declare = true;
		data.locd_stripe_cb = lod_obj_stripe_destroy_cb;
		rc = lod_obj_for_each_stripe(env, lo, th, &data);
	}

	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_destroy.
 *
 * If the object is a striped directory, then the function removes references
 * from the master object (this is an index) to the stripes and destroys all
 * the stripes. In all the cases, the function destroys the object itself.
 *
 * \see dt_object_operations::do_destroy() in the API description for details.
 */
static int lod_destroy(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	struct dt_object  *next = dt_object_child(dt);
	struct lod_object *lo = lod_dt_obj(dt);
	struct lod_thread_info *info = lod_env_info(env);
	char *stripe_name = info->lti_key;
	struct dt_object *stripe;
	unsigned int i;
	int rc;

	ENTRY;

	/* destroy sub-stripe of master object */
	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		rc = next->do_ops->do_index_try(env, next,
						&dt_directory_features);
		if (rc != 0)
			RETURN(rc);

		for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
			stripe = lo->ldo_stripe[i];
			if (!stripe)
				continue;

			rc = lod_sub_ref_del(env, next, th);
			if (rc != 0)
				RETURN(rc);

			snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
				PFID(lu_object_fid(&stripe->do_lu)), i);

			CDEBUG(D_INFO, DFID" delete stripe %s "DFID"\n",
			       PFID(lu_object_fid(&dt->do_lu)), stripe_name,
			       PFID(lu_object_fid(&stripe->do_lu)));

			rc = lod_sub_delete(env, next,
				       (const struct dt_key *)stripe_name, th);
			if (rc != 0)
				RETURN(rc);
		}
	}

	rc = lod_sub_destroy(env, next, th);
	if (rc != 0)
		RETURN(rc);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_MDTOBJ) ||
	    OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_MDTOBJ2))
		RETURN(0);

	if (!lod_obj_is_striped(dt))
		RETURN(0);

	/* destroy all striped objects */
	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
			stripe = lo->ldo_stripe[i];
			if (!stripe)
				continue;

			if (!dt_object_exists(stripe))
				continue;

			if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_SPEOBJ) ||
			    i == cfs_fail_val) {
				dt_write_lock(env, stripe, DT_TGT_CHILD);
				rc = lod_sub_ref_del(env, stripe, th);
				dt_write_unlock(env, stripe);
				if (rc != 0)
					break;

				rc = lod_sub_destroy(env, stripe, th);
				if (rc != 0)
					break;
			}
		}
	} else {
		struct lod_obj_stripe_cb_data data = { { 0 } };

		data.locd_declare = false;
		data.locd_stripe_cb = lod_obj_stripe_destroy_cb;
		rc = lod_obj_for_each_stripe(env, lo, th, &data);
	}

	RETURN(rc);
}

/**
 * Implementation of dt_object_operations::do_declare_ref_add.
 *
 * \see dt_object_operations::do_declare_ref_add() in the API description
 * for details.
 */
static int lod_declare_ref_add(const struct lu_env *env,
			       struct dt_object *dt, struct thandle *th)
{
	return lod_sub_declare_ref_add(env, dt_object_child(dt), th);
}

/**
 * Implementation of dt_object_operations::do_ref_add.
 *
 * \see dt_object_operations::do_ref_add() in the API description for details.
 */
static int lod_ref_add(const struct lu_env *env,
		       struct dt_object *dt, struct thandle *th)
{
	return lod_sub_ref_add(env, dt_object_child(dt), th);
}

/**
 * Implementation of dt_object_operations::do_declare_ref_del.
 *
 * \see dt_object_operations::do_declare_ref_del() in the API description
 * for details.
 */
static int lod_declare_ref_del(const struct lu_env *env,
			       struct dt_object *dt, struct thandle *th)
{
	return lod_sub_declare_ref_del(env, dt_object_child(dt), th);
}

/**
 * Implementation of dt_object_operations::do_ref_del
 *
 * \see dt_object_operations::do_ref_del() in the API description for details.
 */
static int lod_ref_del(const struct lu_env *env,
		       struct dt_object *dt, struct thandle *th)
{
	return lod_sub_ref_del(env, dt_object_child(dt), th);
}

/**
 * Implementation of dt_object_operations::do_object_sync.
 *
 * \see dt_object_operations::do_object_sync() in the API description
 * for details.
 */
static int lod_object_sync(const struct lu_env *env, struct dt_object *dt,
			   __u64 start, __u64 end)
{
	return dt_object_sync(env, dt_object_child(dt), start, end);
}

/**
 * Implementation of dt_object_operations::do_object_unlock.
 *
 * Used to release LDLM lock(s).
 *
 * \see dt_object_operations::do_object_unlock() in the API description
 * for details.
 */
static int lod_object_unlock(const struct lu_env *env, struct dt_object *dt,
			     struct ldlm_enqueue_info *einfo,
			     union ldlm_policy_data *policy)
{
	struct lod_object *lo = lod_dt_obj(dt);
	struct lustre_handle_array *slave_locks = einfo->ei_cbdata;
	int slave_locks_size;
	int i;
	ENTRY;

	if (slave_locks == NULL)
		RETURN(0);

	LASSERT(S_ISDIR(dt->do_lu.lo_header->loh_attr));
	/* Note: for remote lock for single stripe dir, MDT will cancel
	 * the lock by lockh directly */
	LASSERT(!dt_object_remote(dt_object_child(dt)));

	/* locks were unlocked in MDT layer */
	for (i = 0; i < slave_locks->ha_count; i++)
		LASSERT(!lustre_handle_is_used(&slave_locks->ha_handles[i]));

	/*
	 * NB, ha_count may not equal to ldo_dir_stripe_count, because dir
	 * layout may change, e.g., shrink dir layout after migration.
	 */
	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		if (lo->ldo_stripe[i])
			dt_invalidate(env, lo->ldo_stripe[i]);
	}

	slave_locks_size = offsetof(typeof(*slave_locks),
				    ha_handles[slave_locks->ha_count]);
	OBD_FREE(slave_locks, slave_locks_size);
	einfo->ei_cbdata = NULL;

	RETURN(0);
}

/**
 * Implementation of dt_object_operations::do_object_lock.
 *
 * Used to get LDLM lock on the non-striped and striped objects.
 *
 * \see dt_object_operations::do_object_lock() in the API description
 * for details.
 */
static int lod_object_lock(const struct lu_env *env,
			   struct dt_object *dt,
			   struct lustre_handle *lh,
			   struct ldlm_enqueue_info *einfo,
			   union ldlm_policy_data *policy)
{
	struct lod_object *lo = lod_dt_obj(dt);
	int slave_locks_size;
	struct lustre_handle_array *slave_locks = NULL;
	int i;
	int rc;
	ENTRY;

	/* remote object lock */
	if (!einfo->ei_enq_slave) {
		LASSERT(dt_object_remote(dt));
		return dt_object_lock(env, dt_object_child(dt), lh, einfo,
				      policy);
	}

	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(-ENOTDIR);

	rc = lod_striping_load(env, lo);
	if (rc != 0)
		RETURN(rc);

	/* No stripes */
	if (lo->ldo_dir_stripe_count <= 1)
		RETURN(0);

	slave_locks_size = offsetof(typeof(*slave_locks),
				    ha_handles[lo->ldo_dir_stripe_count]);
	/* Freed in lod_object_unlock */
	OBD_ALLOC(slave_locks, slave_locks_size);
	if (!slave_locks)
		RETURN(-ENOMEM);
	slave_locks->ha_count = lo->ldo_dir_stripe_count;

	/* striped directory lock */
	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		struct lustre_handle lockh;
		struct ldlm_res_id *res_id;
		struct dt_object *stripe;

		stripe = lo->ldo_stripe[i];
		if (!stripe)
			continue;

		res_id = &lod_env_info(env)->lti_res_id;
		fid_build_reg_res_name(lu_object_fid(&stripe->do_lu), res_id);
		einfo->ei_res_id = res_id;

		if (dt_object_remote(stripe)) {
			set_bit(i, (void *)slave_locks->ha_map);
			rc = dt_object_lock(env, stripe, &lockh, einfo, policy);
		} else {
			struct ldlm_namespace *ns = einfo->ei_namespace;
			ldlm_blocking_callback blocking = einfo->ei_cb_local_bl;
			ldlm_completion_callback completion = einfo->ei_cb_cp;
			__u64 dlmflags = LDLM_FL_ATOMIC_CB;

			if (einfo->ei_mode == LCK_PW ||
			    einfo->ei_mode == LCK_EX)
				dlmflags |= LDLM_FL_COS_INCOMPAT;

			LASSERT(ns != NULL);
			rc = ldlm_cli_enqueue_local(env, ns, res_id, LDLM_IBITS,
						    policy, einfo->ei_mode,
						    &dlmflags, blocking,
						    completion, NULL,
						    NULL, 0, LVB_T_NONE,
						    NULL, &lockh);
		}
		if (rc) {
			while (i--)
				ldlm_lock_decref_and_cancel(
						&slave_locks->ha_handles[i],
						einfo->ei_mode);
			OBD_FREE(slave_locks, slave_locks_size);
			RETURN(rc);
		}
		slave_locks->ha_handles[i] = lockh;
	}
	einfo->ei_cbdata = slave_locks;

	RETURN(0);
}

/**
 * Implementation of dt_object_operations::do_invalidate.
 *
 * \see dt_object_operations::do_invalidate() in the API description for details
 */
static int lod_invalidate(const struct lu_env *env, struct dt_object *dt)
{
	return dt_invalidate(env, dt_object_child(dt));
}

static int lod_declare_instantiate_components(const struct lu_env *env,
					      struct lod_object *lo,
					      struct thandle *th,
					      __u64 reserve)
{
	struct lod_thread_info *info = lod_env_info(env);
	int i;
	int rc = 0;
	ENTRY;

	LASSERT(info->lti_count < lo->ldo_comp_cnt);

	for (i = 0; i < info->lti_count; i++) {
		rc = lod_qos_prep_create(env, lo, NULL, th,
					 info->lti_comp_idx[i], reserve);
		if (rc)
			break;
	}

	if (!rc) {
		info->lti_buf.lb_len = lod_comp_md_size(lo, false);
		rc = lod_sub_declare_xattr_set(env, lod_object_child(lo),
				&info->lti_buf, XATTR_NAME_LOV, 0, th);
	}

	RETURN(rc);
}

/**
 * Check OSTs for an existing component for further extension
 *
 * Checks if OSTs are still healthy and not out of space.  Gets free space
 * on OSTs (relative to allocation watermark rmb_low) and compares to
 * the proposed new_end for this component.
 *
 * Decides whether or not to extend a component on its current OSTs.
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lo		object we're checking
 * \param[in] index		index of this component
 * \param[in] extension_size	extension size for this component
 * \param[in] extent		layout extent for requested operation
 * \param[in] comp_extent	extension component extent
 * \param[in] write		if this is write operation
 *
 * \retval	true - OK to extend on current OSTs
 * \retval	false - do not extend on current OSTs
 */
static bool lod_sel_osts_allowed(const struct lu_env *env,
				 struct lod_object *lo,
				 int index, __u64 reserve,
				 struct lu_extent *extent,
				 struct lu_extent *comp_extent, int write)
{
	struct lod_layout_component *lod_comp = &lo->ldo_comp_entries[index];
	struct lod_device *lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct lod_thread_info *tinfo = lod_env_info(env);
	struct obd_statfs *sfs = &tinfo->lti_osfs;
	__u64 available = 0;
	bool ret = true;
	int i, rc;

	ENTRY;

	LASSERT(lod_comp->llc_stripe_count != 0);

	lod_getref(&lod->lod_ost_descs);
	for (i = 0; i < lod_comp->llc_stripe_count; i++) {
		int index = lod_comp->llc_ost_indices[i];
		struct lod_tgt_desc *ost = OST_TGT(lod, index);
		struct obd_statfs_info info = { 0 };
		int j, repeated = 0;

		LASSERT(ost);

		/* Get the number of times this OST repeats in this component.
		 * Note: inter-component repeats are not counted as this is
		 * considered as a rare case: we try to not repeat OST in other
		 * components if possible. */
		for (j = 0; j < lod_comp->llc_stripe_count; j++) {
			if (index != lod_comp->llc_ost_indices[j])
				continue;

			/* already handled */
			if (j < i)
				break;

			repeated++;
		}
		if (j < lod_comp->llc_stripe_count)
			continue;

		if (!test_bit(index, lod->lod_ost_bitmap)) {
			CDEBUG(D_LAYOUT, "ost %d no longer present\n", index);
			ret = false;
			break;
		}

		rc = dt_statfs_info(env, ost->ltd_tgt, sfs, &info);
		if (rc) {
			CDEBUG(D_LAYOUT, "statfs failed for ost %d, error %d\n",
			       index, rc);
			ret = false;
			break;
		}

		if (sfs->os_state & OS_STATFS_ENOSPC ||
		    sfs->os_state & OS_STATFS_READONLY ||
		    sfs->os_state & OS_STATFS_DEGRADED) {
			CDEBUG(D_LAYOUT, "ost %d is not availble for SEL "
			       "extension, state %u\n", index, sfs->os_state);
			ret = false;
			break;
		}

		/* In bytes */
		available = sfs->os_bavail * sfs->os_bsize;
		/* 'available' is relative to the allocation threshold */
		available -= (__u64) info.os_reserved_mb_low << 20;

		CDEBUG(D_LAYOUT, "ost %d lowwm: %d highwm: %d, "
		       "%llu %% blocks available, %llu %% blocks free\n",
		       index, info.os_reserved_mb_low, info.os_reserved_mb_high,
		       (100ull * sfs->os_bavail) / sfs->os_blocks,
		       (100ull * sfs->os_bfree) / sfs->os_blocks);

		if (reserve * repeated > available) {
			ret = false;
			CDEBUG(D_LAYOUT, "low space on ost %d, available %llu "
			       "< extension size %llu repeated %d\n", index,
			       available, reserve, repeated);
			break;
		}
	}
	lod_putref(lod, &lod->lod_ost_descs);

	RETURN(ret);
}

/**
 * Adjust extents after component removal
 *
 * When we remove an extension component, we move the start of the next
 * component to match the start of the extension component, so no space is left
 * without layout.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] lo	object
 * \param[in] max_comp	layout component
 * \param[in] index	index of this component
 *
 * \retval		0 on success
 * \retval		negative errno on error
 */
static void lod_sel_adjust_extents(const struct lu_env *env,
				   struct lod_object *lo,
				   int max_comp, int index)
{
	struct lod_layout_component *lod_comp = NULL;
	struct lod_layout_component *next = NULL;
	struct lod_layout_component *prev = NULL;
	__u64 new_start = 0;
	__u64 start;
	int i;

	/* Extension space component */
	lod_comp = &lo->ldo_comp_entries[index];
	next = &lo->ldo_comp_entries[index + 1];
	prev = &lo->ldo_comp_entries[index - 1];

	LASSERT(lod_comp != NULL && prev != NULL && next != NULL);
	LASSERT(lod_comp->llc_flags & LCME_FL_EXTENSION);

	/* Previous is being removed */
	if (prev && prev->llc_id == LCME_ID_INVAL)
		new_start = prev->llc_extent.e_start;
	else
		new_start = lod_comp->llc_extent.e_start;

	for (i = index + 1; i < max_comp; i++) {
		lod_comp = &lo->ldo_comp_entries[i];

		start = lod_comp->llc_extent.e_start;
		lod_comp->llc_extent.e_start = new_start;

		/* We only move zero length extendable components */
		if (!(start == lod_comp->llc_extent.e_end))
			break;

		LASSERT(!(lod_comp->llc_flags & LCME_FL_INIT));

		lod_comp->llc_extent.e_end = new_start;
	}
}

/* Calculate the proposed 'new end' for a component we're extending */
static __u64 lod_extension_new_end(__u64 extension_size, __u64 extent_end,
				   __u32 stripe_size, __u64 component_end,
				   __u64 extension_end)
{
	__u64 new_end;

	LASSERT(extension_size != 0 && stripe_size != 0);

	/* Round up to extension size */
	if (extent_end == OBD_OBJECT_EOF) {
		new_end = OBD_OBJECT_EOF;
	} else {
		/* Add at least extension_size to the previous component_end,
		 * covering the req layout extent */
		new_end = max(extent_end - component_end, extension_size);
		new_end = roundup(new_end, extension_size);
		new_end += component_end;

		/* Component end must be min stripe size aligned */
		if (new_end % stripe_size) {
			CDEBUG(D_LAYOUT, "new component end is not aligned "
			       "by the stripe size %u: [%llu, %llu) ext size "
			       "%llu new end %llu, aligning\n",
			       stripe_size, component_end, extent_end,
			       extension_size, new_end);
			new_end = roundup(new_end, stripe_size);
		}

		/* Overflow */
		if (new_end < extent_end)
			new_end = OBD_OBJECT_EOF;
	}

	/* Don't extend past the end of the extension component */
	if (new_end > extension_end)
		new_end = extension_end;

	return new_end;
}

/**
 * Calculate the exact reservation (per-OST extension_size) on the OSTs being
 * instantiated. It needs to be calculated in advance and taken into account at
 * the instantiation time, because otherwise lod_statfs_and_check() may consider
 * an OST as OK, but SEL needs its extension_size to fit the free space and the
 * OST may turn out to be low-on-space, thus inappropriate OST may be used and
 * ENOSPC occurs.
 *
 * \param[in] lod_comp		lod component we are checking
 *
 * \retval	size to reserved on each OST of lod_comp's stripe.
 */
static __u64 lod_sel_stripe_reserved(struct lod_layout_component *lod_comp)
{
	/* extension_size is file level, so we must divide by stripe count to
	 * compare it to available space on a single OST */
	return  lod_comp->llc_stripe_size * SEL_UNIT_SIZE /
		lod_comp->llc_stripe_count;
}

/* As lod_sel_handler() could be re-entered for the same component several
 * times, this is the data for the next call. Fields could be changed to
 * component indexes when needed, (e.g. if there is no need to instantiate
 * all the previous components up to the current position) to tell the caller
 * where to start over from. */
struct sel_data {
	int sd_force;
	int sd_repeat;
};

/**
 * Process extent updates for a particular layout component
 *
 * Handle layout updates for a particular extension space component touched by
 * a layout update operation.  Core function of self-extending PFL feature.
 *
 * In general, this function processes exactly *one* stage of an extension
 * operation, modifying the layout accordingly, then returns to the caller.
 * The caller is responsible for restarting processing with the new layout,
 * which may repeatedly return to this function until the extension updates
 * are complete.
 *
 * This function does one of a few things to the layout:
 * 1. Extends the component before the current extension space component to
 * allow it to accomodate the requested operation (if space/policy permit that
 * component to continue on its current OSTs)
 *
 * 2. If extension of the existing component fails, we do one of two things:
 *    a. If there is a component after the extension space, we remove the
 *       extension space component, move the start of the next component down
 *       accordingly, then notify the caller to restart processing w/the new
 *       layout.
 *    b. If there is no following component, we try repeating the current
 *       component, creating a new component using the current one as a
 *       template (keeping its stripe properties but not specific striping),
 *       and try assigning striping for this component.  If there is sufficient
 *       free space on the OSTs chosen for this component, it is instantiated
 *       and i/o continues there.
 *
 *       If there is not sufficient space on the new OSTs, we remove this new
 *       component & extend the current component.
 *
 * Note further that uninited components followed by extension space can be zero
 * length meaning that we will try to extend them before initializing them, and
 * if that fails, they will be removed without initialization.
 *
 * 3. If we extend to/beyond the end of an extension space component, that
 * component is exhausted (all of its range has been given to real components),
 * so we remove it and restart processing.
 *
 * \param[in] env		execution environment for this thread
 * \param[in,out] lo		object to update the layout of
 * \param[in] extent		layout extent for requested operation, update
 *				layout to fit this operation
 * \param[in] th		transaction handle for this operation
 * \param[in,out] max_comp	the highest comp for the portion of the layout
 *				we are operating on (For FLR, the chosen
 *				replica).  Updated because we may remove
 *				components.
 * \param[in] index		index of the extension space component we're
 *				working on
 * \param[in] write		if this is write op
 * \param[in,out] force		if the extension is to be forced; set here
				to force it on the 2nd call for the same
				extension component
 *
 * \retval	0 on success
 * \retval	negative errno on error
 */
static int lod_sel_handler(const struct lu_env *env,
			  struct lod_object *lo,
			  struct lu_extent *extent,
			  struct thandle *th, int *max_comp,
			  int index, int write,
			  struct sel_data *sd)
{
	struct lod_device *d = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_layout_component *lod_comp;
	struct lod_layout_component *prev;
	struct lod_layout_component *next = NULL;
	__u64 extension_size, reserve;
	__u64 new_end = 0;
	bool repeated;
	int change = 0;
	int rc = 0;
	ENTRY;

	/* First component cannot be extension space */
	if (index == 0) {
		CERROR("%s: "DFID" first component cannot be extension space\n",
		       lod2obd(d)->obd_name, PFID(lod_object_fid(lo)));
		RETURN(-EINVAL);
	}

	lod_comp = &lo->ldo_comp_entries[index];
	prev = &lo->ldo_comp_entries[index - 1];
	if ((index + 1) < *max_comp)
		next = &lo->ldo_comp_entries[index + 1];

	/* extension size uses the stripe size field as KiB */
	extension_size = lod_comp->llc_stripe_size * SEL_UNIT_SIZE;

	CDEBUG(D_LAYOUT, "prev start %llu, extension start %llu, extension end"
	       " %llu, extension size %llu\n", prev->llc_extent.e_start,
	       lod_comp->llc_extent.e_start, lod_comp->llc_extent.e_end,
	       extension_size);

	/* Two extension space components cannot be adjacent & extension space
	 * components cannot be init */
	if ((prev->llc_flags & LCME_FL_EXTENSION) ||
	    !(ergo(next, !(next->llc_flags & LCME_FL_EXTENSION))) ||
	     lod_comp_inited(lod_comp)) {
		CERROR("%s: "DFID" invalid extension space components\n",
		       lod2obd(d)->obd_name, PFID(lod_object_fid(lo)));
		RETURN(-EINVAL);
	}

	reserve = lod_sel_stripe_reserved(lod_comp);

	if (!prev->llc_stripe) {
		CDEBUG(D_LAYOUT, "Previous component not inited\n");
		info->lti_count = 1;
		info->lti_comp_idx[0] = index - 1;
		rc = lod_declare_instantiate_components(env, lo, th, reserve);
		/* ENOSPC tells us we can't use this component.  If there is
		 * a next or we are repeating, we either spill over (next) or
		 * extend the original comp (repeat).  Otherwise, return the
		 * error to the user. */
		if (rc == -ENOSPC && (next || sd->sd_repeat))
			rc = 1;
		if (rc < 0)
			RETURN(rc);
	}

	if (sd->sd_force == 0 && rc == 0)
		rc = !lod_sel_osts_allowed(env, lo, index - 1, reserve, extent,
					   &lod_comp->llc_extent, write);

	repeated = !!(sd->sd_repeat);
	sd->sd_repeat = 0;
	sd->sd_force = 0;

	/* Extend previous component */
	if (rc == 0) {
		new_end = lod_extension_new_end(extension_size, extent->e_end,
						prev->llc_stripe_size,
						prev->llc_extent.e_end,
						lod_comp->llc_extent.e_end);

		CDEBUG(D_LAYOUT, "new end %llu\n", new_end);
		lod_comp->llc_extent.e_start = new_end;
		prev->llc_extent.e_end = new_end;

		if (prev->llc_extent.e_end == lod_comp->llc_extent.e_end) {
			CDEBUG(D_LAYOUT, "Extension component exhausted\n");
			lod_comp->llc_id = LCME_ID_INVAL;
			change--;
		}
	} else {
		/* rc == 1, failed to extend current component */
		LASSERT(rc == 1);
		if (next) {
			/* Normal 'spillover' case - Remove the extension
			 * space component & bring down the start of the next
			 * component. */
			lod_comp->llc_id = LCME_ID_INVAL;
			change--;
			if (!(prev->llc_flags & LCME_FL_INIT)) {
				prev->llc_id = LCME_ID_INVAL;
				change--;
			}
			lod_sel_adjust_extents(env, lo, *max_comp, index);
		} else if (lod_comp_inited(prev)) {
			/* If there is no next, and the previous component is
			 * INIT'ed, try repeating the previous component. */
			LASSERT(repeated == 0);
			rc = lod_layout_repeat_comp(env, lo, index - 1);
			if (rc < 0)
				RETURN(rc);
			change++;
			/* The previous component is a repeated component.
			 * Record this so we don't keep trying to repeat it. */
			sd->sd_repeat = 1;
		} else {
			/* If the previous component is not INIT'ed, this may
			 * be a component we have just instantiated but failed
			 * to extend. Or even a repeated component we failed
			 * to prepare a striping for. Do not repeat but instead
			 * remove the repeated component & force the extention
			 * of the original one */
			sd->sd_force = 1;
			if (repeated) {
				prev->llc_id = LCME_ID_INVAL;
				change--;
			}
		}
	}

	if (change < 0) {
		rc = lod_layout_del_prep_layout(env, lo, NULL);
		if (rc < 0)
			RETURN(rc);
		LASSERTF(-rc == change,
			 "number deleted %d != requested %d\n", -rc,
			 change);
	}
	*max_comp = *max_comp + change;

	/* lod_del_prep_layout reallocates ldo_comp_entries, so we must
	 * refresh these pointers before using them */
	lod_comp = &lo->ldo_comp_entries[index];
	prev = &lo->ldo_comp_entries[index - 1];
	CDEBUG(D_LAYOUT, "After extent updates: prev start %llu, current start "
	       "%llu, current end %llu max_comp %d ldo_comp_cnt %d\n",
	       prev->llc_extent.e_start, lod_comp->llc_extent.e_start,
	       lod_comp->llc_extent.e_end, *max_comp, lo->ldo_comp_cnt);

	/* Layout changed successfully */
	RETURN(0);
}

/**
 * Declare layout extent updates
 *
 * Handles extensions.  Identifies extension components touched by current
 * operation and passes them to processing function.
 *
 * Restarts with updated layouts from the processing function until the current
 * operation no longer touches an extension space component.
 *
 * \param[in] env	execution environment for this thread
 * \param[in,out] lo	object to update the layout of
 * \param[in] extent	layout extent for requested operation, update layout to
 *			fit this operation
 * \param[in] th	transaction handle for this operation
 * \param[in] pick	identifies chosen mirror for FLR layouts
 * \param[in] write	if this is write op
 *
 * \retval	1 on layout changed, 0 on no change
 * \retval	negative errno on error
 */
static int lod_declare_update_extents(const struct lu_env *env,
		struct lod_object *lo, struct lu_extent *extent,
		struct thandle *th, int pick, int write)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_layout_component *lod_comp;
	bool layout_changed = false;
	struct sel_data sd = { 0 };
	int start_index;
	int i = 0;
	int max_comp = 0;
	int rc = 0, rc2;
	int change = 0;
	ENTRY;

	/* This makes us work on the components of the chosen mirror */
	start_index = lo->ldo_mirrors[pick].lme_start;
	max_comp = lo->ldo_mirrors[pick].lme_end + 1;
	if (lo->ldo_flr_state == LCM_FL_NONE)
		LASSERT(start_index == 0 && max_comp == lo->ldo_comp_cnt);

	CDEBUG(D_LAYOUT, "extent->e_start %llu, extent->e_end %llu\n",
	       extent->e_start, extent->e_end);
	for (i = start_index; i < max_comp; i++) {
		lod_comp = &lo->ldo_comp_entries[i];

		/* We've passed all components of interest */
		if (lod_comp->llc_extent.e_start >= extent->e_end)
			break;

		if (lod_comp->llc_flags & LCME_FL_EXTENSION) {
			layout_changed = true;
			rc = lod_sel_handler(env, lo, extent, th, &max_comp,
					     i, write, &sd);
			if (rc < 0)
				GOTO(out, rc);

			/* Nothing has changed behind the prev one */
			i -= 2;
			continue;
		}
	}

	/* We may have added or removed components.  If so, we must update the
	 * start & ends of all the mirrors after the current one, and the end
	 * of the current mirror. */
	change = max_comp - 1 - lo->ldo_mirrors[pick].lme_end;
	if (change) {
		lo->ldo_mirrors[pick].lme_end += change;
		for (i = pick + 1; i < lo->ldo_mirror_count; i++) {
			lo->ldo_mirrors[i].lme_start += change;
			lo->ldo_mirrors[i].lme_end += change;
		}
	}

	EXIT;
out:
	/* The amount of components has changed, adjust the lti_comp_idx */
	rc2 = lod_layout_data_init(info, lo->ldo_comp_cnt);

	return rc < 0 ? rc : rc2 < 0 ? rc2 : layout_changed;
}

/* If striping is already instantiated or INIT'ed DOM? */
static bool lod_is_instantiation_needed(struct lod_layout_component *comp)
{
	return !(((lov_pattern(comp->llc_pattern) == LOV_PATTERN_MDT) &&
		  lod_comp_inited(comp)) || comp->llc_stripe);
}

/**
 * Declare layout update for a non-FLR layout.
 *
 * \param[in] env	execution environment for this thread
 * \param[in,out] lo	object to update the layout of
 * \param[in] layout	layout intent for requested operation, "update" is
 *			a process of reacting to this
 * \param[in] buf	buffer containing lov ea (see comment on usage inline)
 * \param[in] th	transaction handle for this operation
 *
 * \retval	0 on success
 * \retval	negative errno on error
 */
static int lod_declare_update_plain(const struct lu_env *env,
		struct lod_object *lo, struct layout_intent *layout,
		const struct lu_buf *buf, struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_device *d = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct lod_layout_component *lod_comp;
	struct lov_comp_md_v1 *comp_v1 = NULL;
	bool layout_changed = false;
	bool replay = false;
	int i, rc;
	ENTRY;

	LASSERT(lo->ldo_flr_state == LCM_FL_NONE);

	/*
	 * In case the client is passing lovea, which only happens during
	 * the replay of layout intent write RPC for now, we may need to
	 * parse the lovea and apply new layout configuration.
	 */
	if (buf && buf->lb_len)  {
		struct lov_user_md_v1 *v1 = buf->lb_buf;

		if (v1->lmm_magic != (LOV_MAGIC_DEFINED | LOV_MAGIC_COMP_V1) &&
		    v1->lmm_magic != __swab32(LOV_MAGIC_DEFINED |
					      LOV_MAGIC_COMP_V1)) {
			CERROR("%s: the replay buffer of layout extend "
			       "(magic %#x) does not contain expected "
			       "composite layout.\n",
			       lod2obd(d)->obd_name, v1->lmm_magic);
			GOTO(out, rc = -EINVAL);
		}

		rc = lod_use_defined_striping(env, lo, buf);
		if (rc)
			GOTO(out, rc);
		lo->ldo_comp_cached = 1;

		rc = lod_get_lov_ea(env, lo);
		if (rc <= 0)
			GOTO(out, rc);
		/* old on-disk EA is stored in info->lti_buf */
		comp_v1 = (struct lov_comp_md_v1 *)info->lti_buf.lb_buf;
		replay = true;
		layout_changed = true;

		rc = lod_layout_data_init(info, lo->ldo_comp_cnt);
		if (rc)
			GOTO(out, rc);
	} else {
		/* non replay path */
		rc = lod_striping_load(env, lo);
		if (rc)
			GOTO(out, rc);
	}

	/* Make sure defined layout covers the requested write range. */
	lod_comp = &lo->ldo_comp_entries[lo->ldo_comp_cnt - 1];
	if (lo->ldo_comp_cnt > 1 &&
	    lod_comp->llc_extent.e_end != OBD_OBJECT_EOF &&
	    lod_comp->llc_extent.e_end < layout->li_extent.e_end) {
		CDEBUG_LIMIT(replay ? D_ERROR : D_LAYOUT,
			     "%s: the defined layout [0, %#llx) does not "
			     "covers the write range "DEXT"\n",
			     lod2obd(d)->obd_name, lod_comp->llc_extent.e_end,
			     PEXT(&layout->li_extent));
		GOTO(out, rc = -EINVAL);
	}

	CDEBUG(D_LAYOUT, "%s: "DFID": update components "DEXT"\n",
	       lod2obd(d)->obd_name, PFID(lod_object_fid(lo)),
	       PEXT(&layout->li_extent));

	if (!replay) {
		rc = lod_declare_update_extents(env, lo, &layout->li_extent,
				th, 0, layout->li_opc == LAYOUT_INTENT_WRITE);
		if (rc < 0)
			GOTO(out, rc);
		else if (rc)
			layout_changed = true;
	}

	/*
	 * Iterate ld->ldo_comp_entries, find the component whose extent under
	 * the write range and not instantianted.
	 */
	for (i = 0; i < lo->ldo_comp_cnt; i++) {
		lod_comp = &lo->ldo_comp_entries[i];

		if (lod_comp->llc_extent.e_start >= layout->li_extent.e_end)
			break;

		if (!replay) {
			/* If striping is instantiated or INIT'ed DOM skip */
			if (!lod_is_instantiation_needed(lod_comp))
				continue;
		} else {
			/**
			 * In replay path, lod_comp is the EA passed by
			 * client replay buffer,  comp_v1 is the pre-recovery
			 * on-disk EA, we'd sift out those components which
			 * were init-ed in the on-disk EA.
			 */
			if (le32_to_cpu(comp_v1->lcm_entries[i].lcme_flags) &
			    LCME_FL_INIT)
				continue;
		}
		/*
		 * this component hasn't instantiated in normal path, or during
		 * replay it needs replay the instantiation.
		 */

		/* A released component is being extended */
		if (lod_comp->llc_pattern & LOV_PATTERN_F_RELEASED)
			GOTO(out, rc = -EINVAL);

		LASSERT(info->lti_comp_idx != NULL);
		info->lti_comp_idx[info->lti_count++] = i;
		layout_changed = true;
	}

	if (!layout_changed)
		RETURN(-EALREADY);

	lod_obj_inc_layout_gen(lo);
	rc = lod_declare_instantiate_components(env, lo, th, 0);
	EXIT;
out:
	if (rc)
		lod_striping_free(env, lo);
	return rc;
}

static inline int lod_comp_index(struct lod_object *lo,
				 struct lod_layout_component *lod_comp)
{
	LASSERT(lod_comp >= lo->ldo_comp_entries &&
		lod_comp <= &lo->ldo_comp_entries[lo->ldo_comp_cnt - 1]);

	return lod_comp - lo->ldo_comp_entries;
}

/**
 * Stale other mirrors by writing extent.
 */
static int lod_stale_components(const struct lu_env *env, struct lod_object *lo,
				int primary, struct lu_extent *extent,
				struct thandle *th)
{
	struct lod_layout_component *pri_comp, *lod_comp;
	struct lu_extent pri_extent;
	int rc = 0;
	int i;
	ENTRY;

	/* The writing extent decides which components in the primary
	 * are affected... */
	CDEBUG(D_LAYOUT, "primary mirror %d, "DEXT"\n", primary, PEXT(extent));

restart:
	lod_foreach_mirror_comp(pri_comp, lo, primary) {
		if (!lu_extent_is_overlapped(extent, &pri_comp->llc_extent))
			continue;

		CDEBUG(D_LAYOUT, "primary comp %u "DEXT"\n",
		       lod_comp_index(lo, pri_comp),
		       PEXT(&pri_comp->llc_extent));

		pri_extent.e_start = pri_comp->llc_extent.e_start;
		pri_extent.e_end = pri_comp->llc_extent.e_end;

		for (i = 0; i < lo->ldo_mirror_count; i++) {
			if (i == primary)
				continue;
			rc = lod_declare_update_extents(env, lo, &pri_extent,
							th, i, 0);
			/* if update_extents changed the layout, it may have
			 * reallocated the component array, so start over to
			 * avoid using stale pointers */
			if (rc == 1)
				goto restart;
			if (rc < 0)
				RETURN(rc);

			/* ... and then stale other components that are
			 * overlapping with primary components */
			lod_foreach_mirror_comp(lod_comp, lo, i) {
				if (!lu_extent_is_overlapped(
							&pri_extent,
							&lod_comp->llc_extent))
					continue;

				CDEBUG(D_LAYOUT, "stale: %u / %u\n",
				      i, lod_comp_index(lo, lod_comp));

				lod_comp->llc_flags |= LCME_FL_STALE;
				lo->ldo_mirrors[i].lme_stale = 1;
			}
		}
	}

	RETURN(rc);
}

/**
 * check an OST's availability
 * \param[in] env	execution environment
 * \param[in] lo	lod object
 * \param[in] dt	dt object
 * \param[in] index	mirror index
 *
 * \retval	negative if failed
 * \retval	1 if \a dt is available
 * \retval	0 if \a dt is not available
 */
static inline int lod_check_ost_avail(const struct lu_env *env,
				      struct lod_object *lo,
				      struct dt_object *dt, int index)
{
	struct lod_device *lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct lod_tgt_desc *ost;
	__u32 idx;
	int type = LU_SEQ_RANGE_OST;
	int rc;

	rc = lod_fld_lookup(env, lod, lu_object_fid(&dt->do_lu), &idx, &type);
	if (rc < 0) {
		CERROR("%s: can't locate "DFID":rc = %d\n",
		       lod2obd(lod)->obd_name, PFID(lu_object_fid(&dt->do_lu)),
		       rc);
		return rc;
	}

	ost = OST_TGT(lod, idx);
	if (ost->ltd_statfs.os_state &
		(OS_STATFS_READONLY | OS_STATFS_ENOSPC | OS_STATFS_ENOINO |
		 OS_STATFS_NOPRECREATE) ||
	    ost->ltd_active == 0) {
		CDEBUG(D_LAYOUT, DFID ": mirror %d OST%d unavail, rc = %d\n",
		       PFID(lod_object_fid(lo)), index, idx, rc);
		return 0;
	}

	return 1;
}

/**
 * Pick primary mirror for write
 * \param[in] env	execution environment
 * \param[in] lo	object
 * \param[in] extent	write range
 */
static int lod_primary_pick(const struct lu_env *env, struct lod_object *lo,
			    struct lu_extent *extent)
{
	struct lod_device *lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	unsigned int seq = 0;
	struct lod_layout_component *lod_comp;
	int i, j, rc;
	int picked = -1, second_pick = -1, third_pick = -1;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_FLR_RANDOM_PICK_MIRROR)) {
		get_random_bytes(&seq, sizeof(seq));
		seq %= lo->ldo_mirror_count;
	}

	/**
	 * Pick a mirror as the primary, and check the availability of OSTs.
	 *
	 * This algo can be revised later after knowing the topology of
	 * cluster.
	 */
	lod_qos_statfs_update(env, lod, &lod->lod_ost_descs);
	for (i = 0; i < lo->ldo_mirror_count; i++) {
		bool ost_avail = true;
		int index = (i + seq) % lo->ldo_mirror_count;

		if (lo->ldo_mirrors[index].lme_stale) {
			CDEBUG(D_LAYOUT, DFID": mirror %d stale\n",
			       PFID(lod_object_fid(lo)), index);
			continue;
		}

		/* 2nd pick is for the primary mirror containing unavail OST */
		if (lo->ldo_mirrors[index].lme_prefer && second_pick < 0)
			second_pick = index;

		/* 3rd pick is for non-primary mirror containing unavail OST */
		if (second_pick < 0 && third_pick < 0)
			third_pick = index;

		/**
		 * we found a non-primary 1st pick, we'd like to find a
		 * potential pirmary mirror.
		 */
		if (picked >= 0 && !lo->ldo_mirrors[index].lme_prefer)
			continue;

		/* check the availability of OSTs */
		lod_foreach_mirror_comp(lod_comp, lo, index) {
			if (!lod_comp_inited(lod_comp) || !lod_comp->llc_stripe)
				continue;

			for (j = 0; j < lod_comp->llc_stripe_count; j++) {
				struct dt_object *dt = lod_comp->llc_stripe[j];

				rc = lod_check_ost_avail(env, lo, dt, index);
				if (rc < 0)
					RETURN(rc);

				ost_avail = !!rc;
				if (!ost_avail)
					break;
			} /* for all dt object in one component */
			if (!ost_avail)
				break;
		} /* for all components in a mirror */

		/**
		 * the OSTs where allocated objects locates in the components
		 * of the mirror are available.
		 */
		if (!ost_avail)
			continue;

		/* this mirror has all OSTs available */
		picked = index;

		/**
		 * primary with all OSTs are available, this is the perfect
		 * 1st pick.
		 */
		if (lo->ldo_mirrors[index].lme_prefer)
			break;
	} /* for all mirrors */

	/* failed to pick a sound mirror, lower our expectation */
	if (picked < 0)
		picked = second_pick;
	if (picked < 0)
		picked = third_pick;
	if (picked < 0)
		RETURN(-ENODATA);

	RETURN(picked);
}

static int lod_prepare_resync_mirror(const struct lu_env *env,
				     struct lod_object *lo,
				     __u16 mirror_id)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_layout_component *lod_comp;
	bool neg = !!(MIRROR_ID_NEG & mirror_id);
	int i;

	mirror_id &= ~MIRROR_ID_NEG;

	for (i = 0; i < lo->ldo_mirror_count; i++) {
		if ((!neg && lo->ldo_mirrors[i].lme_id != mirror_id) ||
		    (neg && lo->ldo_mirrors[i].lme_id == mirror_id))
			continue;

		lod_foreach_mirror_comp(lod_comp, lo, i) {
			if (lod_comp_inited(lod_comp))
				continue;

			info->lti_comp_idx[info->lti_count++] =
				lod_comp_index(lo, lod_comp);
		}
	}

	return 0;
}

/**
 * figure out the components should be instantiated for resync.
 */
static int lod_prepare_resync(const struct lu_env *env, struct lod_object *lo,
			      struct lu_extent *extent)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_layout_component *lod_comp;
	unsigned int need_sync = 0;
	int i;

	CDEBUG(D_LAYOUT,
	       DFID": instantiate all stale components in "DEXT"\n",
	       PFID(lod_object_fid(lo)), PEXT(extent));

	/**
	 * instantiate all components within this extent, even non-stale
	 * components.
	 */
	for (i = 0; i < lo->ldo_mirror_count; i++) {
		if (!lo->ldo_mirrors[i].lme_stale)
			continue;

		lod_foreach_mirror_comp(lod_comp, lo, i) {
			if (!lu_extent_is_overlapped(extent,
						&lod_comp->llc_extent))
				break;

			need_sync++;

			if (lod_comp_inited(lod_comp))
				continue;

			CDEBUG(D_LAYOUT, "resync instantiate %d / %d\n",
			       i, lod_comp_index(lo, lod_comp));
			info->lti_comp_idx[info->lti_count++] =
					lod_comp_index(lo, lod_comp);
		}
	}

	return need_sync ? 0 : -EALREADY;
}

static int lod_declare_update_rdonly(const struct lu_env *env,
		struct lod_object *lo, struct md_layout_change *mlc,
		struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lu_attr *layout_attr = &info->lti_layout_attr;
	struct lod_layout_component *lod_comp;
	struct lu_extent extent = { 0 };
	int rc;
	ENTRY;

	LASSERT(lo->ldo_flr_state == LCM_FL_RDONLY);
	LASSERT(mlc->mlc_opc == MD_LAYOUT_WRITE ||
		mlc->mlc_opc == MD_LAYOUT_RESYNC);
	LASSERT(lo->ldo_mirror_count > 0);

	if (mlc->mlc_opc == MD_LAYOUT_WRITE) {
		struct layout_intent *layout = mlc->mlc_intent;
		int write = layout->li_opc == LAYOUT_INTENT_WRITE;
		int picked;

		extent = layout->li_extent;
		CDEBUG(D_LAYOUT, DFID": trying to write :"DEXT"\n",
		       PFID(lod_object_fid(lo)), PEXT(&extent));

		picked = lod_primary_pick(env, lo, &extent);
		if (picked < 0)
			RETURN(picked);

		CDEBUG(D_LAYOUT, DFID": picked mirror id %u as primary\n",
		       PFID(lod_object_fid(lo)),
		       lo->ldo_mirrors[picked].lme_id);

		/* Update extents of primary before staling */
		rc = lod_declare_update_extents(env, lo, &extent, th, picked,
						write);
		if (rc < 0)
			GOTO(out, rc);

		if (layout->li_opc == LAYOUT_INTENT_TRUNC) {
			/**
			 * trunc transfers [0, size) in the intent extent, we'd
			 * stale components overlapping [size, eof).
			 */
			extent.e_start = extent.e_end;
			extent.e_end = OBD_OBJECT_EOF;
		}

		/* stale overlapping components from other mirrors */
		rc = lod_stale_components(env, lo, picked, &extent, th);
		if (rc < 0)
			GOTO(out, rc);

		/* restore truncate intent extent */
		if (layout->li_opc == LAYOUT_INTENT_TRUNC)
			extent.e_end = extent.e_start;

		/* instantiate components for the picked mirror, start from 0 */
		extent.e_start = 0;

		lod_foreach_mirror_comp(lod_comp, lo, picked) {
			if (!lu_extent_is_overlapped(&extent,
						     &lod_comp->llc_extent))
				break;

			if (!lod_is_instantiation_needed(lod_comp))
				continue;

			info->lti_comp_idx[info->lti_count++] =
						lod_comp_index(lo, lod_comp);
		}

		lo->ldo_flr_state = LCM_FL_WRITE_PENDING;
	} else { /* MD_LAYOUT_RESYNC */
		int i;

		/**
		 * could contain multiple non-stale mirrors, so we need to
		 * prep uninited all components assuming any non-stale mirror
		 * could be picked as the primary mirror.
		 */
		if (mlc->mlc_mirror_id == 0) {
			/* normal resync */
			for (i = 0; i < lo->ldo_mirror_count; i++) {
				if (lo->ldo_mirrors[i].lme_stale)
					continue;

				lod_foreach_mirror_comp(lod_comp, lo, i) {
					if (!lod_comp_inited(lod_comp))
						break;

					if (extent.e_end <
						lod_comp->llc_extent.e_end)
						extent.e_end =
						     lod_comp->llc_extent.e_end;
				}
			}
			rc = lod_prepare_resync(env, lo, &extent);
			if (rc)
				GOTO(out, rc);
		} else {
			/* mirror write, try to init its all components */
			rc = lod_prepare_resync_mirror(env, lo,
						       mlc->mlc_mirror_id);
			if (rc)
				GOTO(out, rc);
		}

		/* change the file state to SYNC_PENDING */
		lo->ldo_flr_state = LCM_FL_SYNC_PENDING;
	}

	/* Reset the layout version once it's becoming too large.
	 * This way it can make sure that the layout version is
	 * monotonously increased in this writing era. */
	lod_obj_inc_layout_gen(lo);
	if (lo->ldo_layout_gen > (LCME_ID_MAX >> 1)) {
		__u32 layout_version;

		get_random_bytes(&layout_version, sizeof(layout_version));
		lo->ldo_layout_gen = layout_version & 0xffff;
	}

	rc = lod_declare_instantiate_components(env, lo, th, 0);
	if (rc)
		GOTO(out, rc);

	layout_attr->la_valid = LA_LAYOUT_VERSION;
	layout_attr->la_layout_version = 0; /* set current version */
	if (mlc->mlc_opc == MD_LAYOUT_RESYNC)
		layout_attr->la_layout_version = LU_LAYOUT_RESYNC;
	rc = lod_declare_attr_set(env, &lo->ldo_obj, layout_attr, th);
	if (rc)
		GOTO(out, rc);

out:
	if (rc)
		lod_striping_free(env, lo);
	RETURN(rc);
}

static int lod_declare_update_write_pending(const struct lu_env *env,
		struct lod_object *lo, struct md_layout_change *mlc,
		struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lu_attr *layout_attr = &info->lti_layout_attr;
	struct lod_layout_component *lod_comp;
	struct lu_extent extent = { 0 };
	int primary = -1;
	int i;
	int rc;
	ENTRY;

	LASSERT(lo->ldo_flr_state == LCM_FL_WRITE_PENDING);
	LASSERT(mlc->mlc_opc == MD_LAYOUT_WRITE ||
		mlc->mlc_opc == MD_LAYOUT_RESYNC);

	/* look for the first preferred mirror */
	for (i = 0; i < lo->ldo_mirror_count; i++) {
		if (lo->ldo_mirrors[i].lme_stale)
			continue;
		if (lo->ldo_mirrors[i].lme_prefer == 0)
			continue;

		primary = i;
		break;
	}
	if (primary < 0) {
		/* no primary, use any in-sync */
		for (i = 0; i < lo->ldo_mirror_count; i++) {
			if (lo->ldo_mirrors[i].lme_stale)
				continue;
			primary = i;
			break;
		}
		if (primary < 0) {
			CERROR(DFID ": doesn't have a primary mirror\n",
			       PFID(lod_object_fid(lo)));
			GOTO(out, rc = -ENODATA);
		}
	}

	CDEBUG(D_LAYOUT, DFID": found primary %u\n",
	       PFID(lod_object_fid(lo)), lo->ldo_mirrors[primary].lme_id);

	LASSERT(!lo->ldo_mirrors[primary].lme_stale);

	/* for LAYOUT_WRITE opc, it has to do the following operations:
	 * 1. stale overlapping componets from stale mirrors;
	 * 2. instantiate components of the primary mirror;
	 * 3. transfter layout version to all objects of the primary;
	 *
	 * for LAYOUT_RESYNC opc, it will do:
	 * 1. instantiate components of all stale mirrors;
	 * 2. transfer layout version to all objects to close write era. */

	if (mlc->mlc_opc == MD_LAYOUT_WRITE) {
		struct layout_intent *layout = mlc->mlc_intent;
		int write = layout->li_opc == LAYOUT_INTENT_WRITE;

		LASSERT(mlc->mlc_intent != NULL);

		extent = mlc->mlc_intent->li_extent;

		CDEBUG(D_LAYOUT, DFID": intent to write: "DEXT"\n",
		       PFID(lod_object_fid(lo)), PEXT(&extent));

		/* 1. Update extents of primary before staling */
		rc = lod_declare_update_extents(env, lo, &extent, th, primary,
						write);
		if (rc < 0)
			GOTO(out, rc);

		if (mlc->mlc_intent->li_opc == LAYOUT_INTENT_TRUNC) {
			/**
			 * trunc transfers [0, size) in the intent extent, we'd
			 * stale components overlapping [size, eof).
			 */
			extent.e_start = extent.e_end;
			extent.e_end = OBD_OBJECT_EOF;
		}

		/* 2. stale overlapping components */
		rc = lod_stale_components(env, lo, primary, &extent, th);
		if (rc < 0)
			GOTO(out, rc);

		/* 3. find the components which need instantiating.
		 * instantiate [0, mlc->mlc_intent->e_end) */

		/* restore truncate intent extent */
		if (mlc->mlc_intent->li_opc == LAYOUT_INTENT_TRUNC)
			extent.e_end = extent.e_start;
		extent.e_start = 0;

		lod_foreach_mirror_comp(lod_comp, lo, primary) {
			if (!lu_extent_is_overlapped(&extent,
						     &lod_comp->llc_extent))
				break;

			if (!lod_is_instantiation_needed(lod_comp))
				continue;

			CDEBUG(D_LAYOUT, "write instantiate %d / %d\n",
			       primary, lod_comp_index(lo, lod_comp));
			info->lti_comp_idx[info->lti_count++] =
						lod_comp_index(lo, lod_comp);
		}
	} else { /* MD_LAYOUT_RESYNC */
		if (mlc->mlc_mirror_id == 0) {
			/* normal resync */
			lod_foreach_mirror_comp(lod_comp, lo, primary) {
				if (!lod_comp_inited(lod_comp))
					break;

				extent.e_end = lod_comp->llc_extent.e_end;
			}

			rc = lod_prepare_resync(env, lo, &extent);
			if (rc)
				GOTO(out, rc);
		} else {
			/* mirror write, try to init its all components */
			rc = lod_prepare_resync_mirror(env, lo,
						       mlc->mlc_mirror_id);
			if (rc)
				GOTO(out, rc);
		}

		/* change the file state to SYNC_PENDING */
		lo->ldo_flr_state = LCM_FL_SYNC_PENDING;
	}

	rc = lod_declare_instantiate_components(env, lo, th, 0);
	if (rc)
		GOTO(out, rc);

	/* 3. transfer layout version to OST objects.
	 * transfer new layout version to OST objects so that stale writes
	 * can be denied. It also ends an era of writing by setting
	 * LU_LAYOUT_RESYNC. Normal client can never use this bit to
	 * send write RPC; only resync RPCs could do it. */
	layout_attr->la_valid = LA_LAYOUT_VERSION;
	layout_attr->la_layout_version = 0; /* set current version */
	if (mlc->mlc_opc == MD_LAYOUT_RESYNC)
		layout_attr->la_layout_version = LU_LAYOUT_RESYNC;
	rc = lod_declare_attr_set(env, &lo->ldo_obj, layout_attr, th);
	if (rc)
		GOTO(out, rc);

	lod_obj_inc_layout_gen(lo);
out:
	if (rc)
		lod_striping_free(env, lo);
	RETURN(rc);
}

static int lod_declare_update_sync_pending(const struct lu_env *env,
		struct lod_object *lo, struct md_layout_change *mlc,
		struct thandle *th)
{
	struct lod_thread_info  *info = lod_env_info(env);
	unsigned sync_components = 0;
	unsigned resync_components = 0;
	int i;
	int rc;
	ENTRY;

	LASSERT(lo->ldo_flr_state == LCM_FL_SYNC_PENDING);
	LASSERT(mlc->mlc_opc == MD_LAYOUT_RESYNC_DONE ||
		mlc->mlc_opc == MD_LAYOUT_WRITE);

	CDEBUG(D_LAYOUT, DFID ": received op %d in sync pending\n",
	       PFID(lod_object_fid(lo)), mlc->mlc_opc);

	if (mlc->mlc_opc == MD_LAYOUT_WRITE) {
		CDEBUG(D_LAYOUT, DFID": cocurrent write to sync pending\n",
		       PFID(lod_object_fid(lo)));

		lo->ldo_flr_state = LCM_FL_WRITE_PENDING;
		return lod_declare_update_write_pending(env, lo, mlc, th);
	}

	/* MD_LAYOUT_RESYNC_DONE */

	for (i = 0; i < lo->ldo_comp_cnt; i++) {
		struct lod_layout_component *lod_comp;
		int j;

		lod_comp = &lo->ldo_comp_entries[i];

		if (!(lod_comp->llc_flags & LCME_FL_STALE)) {
			sync_components++;
			continue;
		}

		for (j = 0; j < mlc->mlc_resync_count; j++) {
			if (lod_comp->llc_id != mlc->mlc_resync_ids[j])
				continue;

			mlc->mlc_resync_ids[j] = LCME_ID_INVAL;
			lod_comp->llc_flags &= ~LCME_FL_STALE;
			resync_components++;
			break;
		}
	}

	/* valid check */
	for (i = 0; i < mlc->mlc_resync_count; i++) {
		if (mlc->mlc_resync_ids[i] == LCME_ID_INVAL)
			continue;

		CDEBUG(D_LAYOUT, DFID": lcme id %u (%d / %zd) not exist "
		       "or already synced\n", PFID(lod_object_fid(lo)),
		       mlc->mlc_resync_ids[i], i, mlc->mlc_resync_count);
		GOTO(out, rc = -EINVAL);
	}

	if (!sync_components || (mlc->mlc_resync_count && !resync_components)) {
		CDEBUG(D_LAYOUT, DFID": no mirror in sync\n",
		       PFID(lod_object_fid(lo)));

		/* tend to return an error code here to prevent
		 * the MDT from setting SoM attribute */
		GOTO(out, rc = -EINVAL);
	}

	CDEBUG(D_LAYOUT, DFID": synced %u resynced %u/%zu components\n",
	       PFID(lod_object_fid(lo)),
	       sync_components, resync_components, mlc->mlc_resync_count);

	lo->ldo_flr_state = LCM_FL_RDONLY;
	lod_obj_inc_layout_gen(lo);

	info->lti_buf.lb_len = lod_comp_md_size(lo, false);
	rc = lod_sub_declare_xattr_set(env, lod_object_child(lo),
				       &info->lti_buf, XATTR_NAME_LOV, 0, th);
	EXIT;

out:
	if (rc)
		lod_striping_free(env, lo);
	RETURN(rc);
}

typedef int (*mlc_handler)(const struct lu_env *env, struct dt_object *dt,
			   const struct md_layout_change *mlc,
			   struct thandle *th);

/**
 * Attach stripes after target's for migrating directory. NB, we
 * only need to declare this, the actual work is done inside
 * lod_xattr_set_lmv().
 *
 * \param[in] env	execution environment
 * \param[in] dt	target object
 * \param[in] mlc	layout change data
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_dir_declare_layout_attach(const struct lu_env *env,
					 struct dt_object *dt,
					 const struct md_layout_change *mlc,
					 struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_device *lod = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_tgt_descs *ltd = &lod->lod_mdt_descs;
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object *next = dt_object_child(dt);
	struct dt_object_format *dof = &info->lti_format;
	struct lmv_mds_md_v1 *lmv = mlc->mlc_buf.lb_buf;
	struct dt_object **stripes;
	__u32 stripe_count = le32_to_cpu(lmv->lmv_stripe_count);
	struct lu_fid *fid = &info->lti_fid;
	struct lod_tgt_desc *tgt;
	struct dt_object *dto;
	struct dt_device *tgt_dt;
	int type = LU_SEQ_RANGE_ANY;
	struct dt_insert_rec *rec = &info->lti_dt_rec;
	char *stripe_name = info->lti_key;
	struct lu_name *sname;
	struct linkea_data ldata = { NULL };
	struct lu_buf linkea_buf;
	__u32 idx;
	int i;
	int rc;

	ENTRY;

	if (!lmv_is_sane(lmv))
		RETURN(-EINVAL);

	if (!dt_try_as_dir(env, dt))
		return -ENOTDIR;

	dof->dof_type = DFT_DIR;

	OBD_ALLOC_PTR_ARRAY(stripes, (lo->ldo_dir_stripe_count + stripe_count));
	if (!stripes)
		RETURN(-ENOMEM);

	for (i = 0; i < lo->ldo_dir_stripe_count; i++)
		stripes[i] = lo->ldo_stripe[i];

	rec->rec_type = S_IFDIR;

	for (i = 0; i < stripe_count; i++) {
		fid_le_to_cpu(fid,
			&lmv->lmv_stripe_fids[i]);
		if (!fid_is_sane(fid))
			continue;

		rc = lod_fld_lookup(env, lod, fid, &idx, &type);
		if (rc)
			GOTO(out, rc);

		if (idx == lod2lu_dev(lod)->ld_site->ld_seq_site->ss_node_id) {
			tgt_dt = lod->lod_child;
		} else {
			tgt = LTD_TGT(ltd, idx);
			if (tgt == NULL)
				GOTO(out, rc = -ESTALE);
			tgt_dt = tgt->ltd_tgt;
		}

		dto = dt_locate_at(env, tgt_dt, fid,
				  lo->ldo_obj.do_lu.lo_dev->ld_site->ls_top_dev,
				  NULL);
		if (IS_ERR(dto))
			GOTO(out, rc = PTR_ERR(dto));

		stripes[i + lo->ldo_dir_stripe_count] = dto;

		if (!dt_try_as_dir(env, dto))
			GOTO(out, rc = -ENOTDIR);

		rc = lod_sub_declare_ref_add(env, dto, th);
		if (rc)
			GOTO(out, rc);

		rec->rec_fid = lu_object_fid(&dto->do_lu);
		rc = lod_sub_declare_insert(env, dto,
					    (const struct dt_rec *)rec,
					    (const struct dt_key *)dot, th);
		if (rc)
			GOTO(out, rc);

		rc = lod_sub_declare_insert(env, dto,
					    (const struct dt_rec *)rec,
					    (const struct dt_key *)dotdot, th);
		if (rc)
			GOTO(out, rc);

		rc = lod_sub_declare_xattr_set(env, dto, &mlc->mlc_buf,
						XATTR_NAME_LMV, 0, th);
		if (rc)
			GOTO(out, rc);

		snprintf(stripe_name, sizeof(info->lti_key), DFID":%u",
			 PFID(lu_object_fid(&dto->do_lu)),
			 i + lo->ldo_dir_stripe_count);

		sname = lod_name_get(env, stripe_name, strlen(stripe_name));
		rc = linkea_links_new(&ldata, &info->lti_linkea_buf,
				      sname, lu_object_fid(&dt->do_lu));
		if (rc)
			GOTO(out, rc);

		linkea_buf.lb_buf = ldata.ld_buf->lb_buf;
		linkea_buf.lb_len = ldata.ld_leh->leh_len;
		rc = lod_sub_declare_xattr_set(env, dto, &linkea_buf,
					       XATTR_NAME_LINK, 0, th);
		if (rc)
			GOTO(out, rc);

		rc = lod_sub_declare_insert(env, next,
					    (const struct dt_rec *)rec,
					    (const struct dt_key *)stripe_name,
					    th);
		if (rc)
			GOTO(out, rc);

		rc = lod_sub_declare_ref_add(env, next, th);
		if (rc)
			GOTO(out, rc);
	}

	if (lo->ldo_stripe)
		OBD_FREE_PTR_ARRAY(lo->ldo_stripe,
				   lo->ldo_dir_stripes_allocated);
	lo->ldo_stripe = stripes;
	lo->ldo_dir_migrate_offset = lo->ldo_dir_stripe_count;
	lo->ldo_dir_migrate_hash = le32_to_cpu(lmv->lmv_hash_type);
	lo->ldo_dir_stripe_count += stripe_count;
	lo->ldo_dir_stripes_allocated += stripe_count;

	/* plain directory split creates target as a plain directory, while
	 * after source attached as the first stripe, it becomes a striped
	 * directory, set correct do_index_ops, otherwise it can't be unlinked.
	 */
	dt->do_index_ops = &lod_striped_index_ops;

	RETURN(0);
out:
	i = lo->ldo_dir_stripe_count;
	while (i < lo->ldo_dir_stripe_count + stripe_count && stripes[i])
		dt_object_put(env, stripes[i++]);

	OBD_FREE_PTR_ARRAY(stripes, stripe_count + lo->ldo_dir_stripe_count);
	return rc;
}

static int lod_dir_declare_layout_detach(const struct lu_env *env,
					 struct dt_object *dt,
					 const struct md_layout_change *unused,
					 struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object *next = dt_object_child(dt);
	char *stripe_name = info->lti_key;
	struct dt_object *dto;
	int i;
	int rc = 0;

	if (!dt_try_as_dir(env, dt))
		return -ENOTDIR;

	if (!lo->ldo_dir_stripe_count)
		return lod_sub_declare_delete(env, next,
					(const struct dt_key *)dotdot, th);

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		dto = lo->ldo_stripe[i];
		if (!dto)
			continue;

		if (!dt_try_as_dir(env, dto))
			return -ENOTDIR;

		rc = lod_sub_declare_delete(env, dto,
					(const struct dt_key *)dotdot, th);
		if (rc)
			return rc;

		snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
			 PFID(lu_object_fid(&dto->do_lu)), i);

		rc = lod_sub_declare_delete(env, next,
					(const struct dt_key *)stripe_name, th);
		if (rc)
			return rc;

		rc = lod_sub_declare_ref_del(env, next, th);
		if (rc)
			return rc;
	}

	return 0;
}

static int dt_dir_is_empty(const struct lu_env *env,
			   struct dt_object *obj)
{
	struct dt_it *it;
	const struct dt_it_ops *iops;
	int rc;

	ENTRY;

	if (!dt_try_as_dir(env, obj))
		RETURN(-ENOTDIR);

	iops = &obj->do_index_ops->dio_it;
	it = iops->init(env, obj, LUDA_64BITHASH);
	if (IS_ERR(it))
		RETURN(PTR_ERR(it));

	rc = iops->get(env, it, (const struct dt_key *)"");
	if (rc > 0) {
		int i;

		for (rc = 0, i = 0; rc == 0 && i < 3; ++i)
			rc = iops->next(env, it);
		if (!rc)
			rc = -ENOTEMPTY;
		else if (rc == 1)
			rc = 0;
	} else if (!rc) {
		/* Huh? Index contains no zero key? */
		rc = -EIO;
	}

	iops->put(env, it);
	iops->fini(env, it);

	RETURN(rc);
}

static int lod_dir_declare_layout_shrink(const struct lu_env *env,
					 struct dt_object *dt,
					 const struct md_layout_change *mlc,
					 struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object *next = dt_object_child(dt);
	struct lmv_user_md *lmu = mlc->mlc_buf.lb_buf;
	__u32 final_stripe_count;
	char *stripe_name = info->lti_key;
	struct lu_buf *lmv_buf = &info->lti_buf;
	struct dt_object *dto;
	int i;
	int rc;

	LASSERT(lmu);

	if (!dt_try_as_dir(env, dt))
		return -ENOTDIR;

	/* shouldn't be called on plain directory */
	LASSERT(lo->ldo_dir_stripe_count);

	lmv_buf->lb_buf = &info->lti_lmv.lmv_md_v1;
	lmv_buf->lb_len = sizeof(info->lti_lmv.lmv_md_v1);

	final_stripe_count = le32_to_cpu(lmu->lum_stripe_count);
	LASSERT(final_stripe_count &&
		final_stripe_count < lo->ldo_dir_stripe_count);

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		dto = lo->ldo_stripe[i];
		if (!dto)
			continue;

		if (i < final_stripe_count) {
			if (final_stripe_count == 1)
				continue;

			rc = lod_sub_declare_xattr_set(env, dto, lmv_buf,
						       XATTR_NAME_LMV,
						       LU_XATTR_REPLACE, th);
			if (rc)
				return rc;

			continue;
		}

		rc = dt_dir_is_empty(env, dto);
		if (rc < 0)
			return rc;

		rc = lod_sub_declare_ref_del(env, dto, th);
		if (rc)
			return rc;

		rc = lod_sub_declare_destroy(env, dto, th);
		if (rc)
			return rc;

		snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
			 PFID(lu_object_fid(&dto->do_lu)), i);

		rc = lod_sub_declare_delete(env, next,
					(const struct dt_key *)stripe_name, th);
		if (rc)
			return rc;

		rc = lod_sub_declare_ref_del(env, next, th);
		if (rc)
			return rc;
	}

	rc = lod_sub_declare_xattr_set(env, next, lmv_buf, XATTR_NAME_LMV,
				       LU_XATTR_REPLACE, th);
	return rc;
}

/**
 * Allocate stripes for split directory.
 *
 * \param[in] env	execution environment
 * \param[in] dt	target object
 * \param[in] mlc	layout change data
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_dir_declare_layout_split(const struct lu_env *env,
					struct dt_object *dt,
					const struct md_layout_change *mlc,
					struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_device *lod = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object_format *dof = &info->lti_format;
	struct lmv_user_md_v1 *lum = mlc->mlc_spec->u.sp_ea.eadata;
	struct dt_object **stripes;
	u32 stripe_count;
	u32 saved_count;
	int i;
	int rc;

	ENTRY;

	LASSERT(le32_to_cpu(lum->lum_magic) == LMV_USER_MAGIC);
	LASSERT(le32_to_cpu(lum->lum_stripe_offset) == LMV_OFFSET_DEFAULT);

	saved_count = lo->ldo_dir_stripes_allocated;
	stripe_count = le32_to_cpu(lum->lum_stripe_count);
	if (stripe_count <= saved_count)
		RETURN(-EINVAL);

	dof->dof_type = DFT_DIR;

	OBD_ALLOC(stripes, sizeof(*stripes) * stripe_count);
	if (!stripes)
		RETURN(-ENOMEM);

	for (i = 0; i < lo->ldo_dir_stripes_allocated; i++)
		stripes[i] = lo->ldo_stripe[i];

	lod_qos_statfs_update(env, lod, &lod->lod_mdt_descs);
	rc = lod_mdt_alloc_qos(env, lo, stripes, saved_count, stripe_count);
	if (rc == -EAGAIN)
		rc = lod_mdt_alloc_rr(env, lo, stripes, saved_count,
				      stripe_count);
	if (rc < 0) {
		OBD_FREE(stripes, sizeof(*stripes) * stripe_count);
		RETURN(rc);
	}

	LASSERT(rc > saved_count);
	OBD_FREE(lo->ldo_stripe,
		 sizeof(*stripes) * lo->ldo_dir_stripes_allocated);
	lo->ldo_stripe = stripes;
	lo->ldo_dir_striped = 1;
	lo->ldo_dir_stripe_count = rc;
	lo->ldo_dir_stripes_allocated = stripe_count;
	lo->ldo_dir_split_hash = lo->ldo_dir_hash_type;
	lo->ldo_dir_hash_type = le32_to_cpu(lum->lum_hash_type);
	if (!lmv_is_known_hash_type(lo->ldo_dir_hash_type))
		lo->ldo_dir_hash_type =
			lod->lod_mdt_descs.ltd_lmv_desc.ld_pattern;
	lo->ldo_dir_hash_type |= LMV_HASH_FLAG_SPLIT | LMV_HASH_FLAG_MIGRATION;
	lo->ldo_dir_split_offset = saved_count;
	lo->ldo_dir_layout_version++;
	lo->ldo_dir_stripe_loaded = 1;

	rc = lod_dir_declare_create_stripes(env, dt, mlc->mlc_attr, dof, th);
	if (rc)
		lod_striping_free(env, lo);

	RETURN(rc);
}

/*
 * detach all stripes from dir master object, NB, stripes are not destroyed, but
 * deleted from it's parent namespace, this function is called in two places:
 * 1. mdd_migrate_mdt() detach stripes from source, and attach them to
 *    target.
 * 2. mdd_dir_layout_update() detach stripe before turning 1-stripe directory to
 *    a plain directory.
 *
 * \param[in] env	execution environment
 * \param[in] dt	target object
 * \param[in] mlc	layout change data
 * \param[in] th	transaction handle
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_dir_layout_detach(const struct lu_env *env,
				 struct dt_object *dt,
				 const struct md_layout_change *mlc,
				 struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_object *lo = lod_dt_obj(dt);
	struct dt_object *next = dt_object_child(dt);
	char *stripe_name = info->lti_key;
	struct dt_object *dto;
	int i;
	int rc = 0;

	ENTRY;

	if (!lo->ldo_dir_stripe_count) {
		/* plain directory delete .. */
		rc = lod_sub_delete(env, next,
				    (const struct dt_key *)dotdot, th);
		RETURN(rc);
	}

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		dto = lo->ldo_stripe[i];
		if (!dto)
			continue;

		rc = lod_sub_delete(env, dto,
				    (const struct dt_key *)dotdot, th);
		if (rc)
			break;

		snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
			 PFID(lu_object_fid(&dto->do_lu)), i);

		rc = lod_sub_delete(env, next,
				    (const struct dt_key *)stripe_name, th);
		if (rc)
			break;

		rc = lod_sub_ref_del(env, next, th);
		if (rc)
			break;
	}

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		dto = lo->ldo_stripe[i];
		if (dto)
			dt_object_put(env, dto);
	}
	OBD_FREE_PTR_ARRAY(lo->ldo_stripe, lo->ldo_dir_stripes_allocated);
	lo->ldo_stripe = NULL;
	lo->ldo_dir_stripes_allocated = 0;
	lo->ldo_dir_stripe_count = 0;
	dt->do_index_ops = &lod_index_ops;

	RETURN(rc);
}

static int lod_dir_layout_shrink(const struct lu_env *env,
				 struct dt_object *dt,
				 const struct md_layout_change *mlc,
				 struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_object *lo = lod_dt_obj(dt);
	struct lod_device *lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct dt_object *next = dt_object_child(dt);
	struct lmv_user_md *lmu = mlc->mlc_buf.lb_buf;
	__u32 final_stripe_count;
	char *stripe_name = info->lti_key;
	struct dt_object *dto;
	struct lu_buf *lmv_buf = &info->lti_buf;
	struct lmv_mds_md_v1 *lmv = &info->lti_lmv.lmv_md_v1;
	u32 mdtidx;
	int type = LU_SEQ_RANGE_ANY;
	int i;
	int rc;

	ENTRY;

	final_stripe_count = le32_to_cpu(lmu->lum_stripe_count);

	lmv_buf->lb_buf = lmv;
	lmv_buf->lb_len = sizeof(*lmv);
	lmv->lmv_magic = cpu_to_le32(LMV_MAGIC_STRIPE);
	lmv->lmv_stripe_count = cpu_to_le32(final_stripe_count);
	lmv->lmv_hash_type = cpu_to_le32(lo->ldo_dir_hash_type) &
			     cpu_to_le32(LMV_HASH_TYPE_MASK);
	lmv->lmv_layout_version =
			cpu_to_le32(lo->ldo_dir_layout_version + 1);

	for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
		dto = lo->ldo_stripe[i];
		if (!dto)
			continue;

		if (i < final_stripe_count) {
			/* if only one stripe left, no need to update
			 * LMV because this stripe will replace master
			 * object and act as a plain directory.
			 */
			if (final_stripe_count == 1)
				continue;


			rc = lod_fld_lookup(env, lod,
					    lu_object_fid(&dto->do_lu),
					    &mdtidx, &type);
			if (rc)
				RETURN(rc);

			lmv->lmv_master_mdt_index = cpu_to_le32(mdtidx);
			rc = lod_sub_xattr_set(env, dto, lmv_buf,
					       XATTR_NAME_LMV,
					       LU_XATTR_REPLACE, th);
			if (rc)
				RETURN(rc);

			continue;
		}

		dt_write_lock(env, dto, DT_TGT_CHILD);
		rc = lod_sub_ref_del(env, dto, th);
		dt_write_unlock(env, dto);
		if (rc)
			RETURN(rc);

		rc = lod_sub_destroy(env, dto, th);
		if (rc)
			RETURN(rc);

		snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
			 PFID(lu_object_fid(&dto->do_lu)), i);

		rc = lod_sub_delete(env, next,
				    (const struct dt_key *)stripe_name, th);
		if (rc)
			RETURN(rc);

		rc = lod_sub_ref_del(env, next, th);
		if (rc)
			RETURN(rc);
	}

	rc = lod_fld_lookup(env, lod, lu_object_fid(&dt->do_lu), &mdtidx,
			    &type);
	if (rc)
		RETURN(rc);

	lmv->lmv_magic = cpu_to_le32(LMV_MAGIC_V1);
	lmv->lmv_master_mdt_index = cpu_to_le32(mdtidx);
	rc = lod_sub_xattr_set(env, next, lmv_buf, XATTR_NAME_LMV,
			       LU_XATTR_REPLACE, th);
	if (rc)
		RETURN(rc);

	for (i = final_stripe_count; i < lo->ldo_dir_stripe_count; i++) {
		dto = lo->ldo_stripe[i];
		if (dto)
			dt_object_put(env, dto);
	}
	lo->ldo_dir_stripe_count = final_stripe_count;

	RETURN(rc);
}

static mlc_handler dir_mlc_declare_ops[MD_LAYOUT_MAX] = {
	[MD_LAYOUT_ATTACH] = lod_dir_declare_layout_attach,
	[MD_LAYOUT_DETACH] = lod_dir_declare_layout_detach,
	[MD_LAYOUT_SHRINK] = lod_dir_declare_layout_shrink,
	[MD_LAYOUT_SPLIT]  = lod_dir_declare_layout_split,
};

static mlc_handler dir_mlc_ops[MD_LAYOUT_MAX] = {
	[MD_LAYOUT_DETACH] = lod_dir_layout_detach,
	[MD_LAYOUT_SHRINK] = lod_dir_layout_shrink,
};

static int lod_declare_layout_change(const struct lu_env *env,
		struct dt_object *dt, struct md_layout_change *mlc,
		struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_object *lo = lod_dt_obj(dt);
	int rc;

	ENTRY;

	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		LASSERT(dir_mlc_declare_ops[mlc->mlc_opc]);
		rc = dir_mlc_declare_ops[mlc->mlc_opc](env, dt, mlc, th);
		RETURN(rc);
	}

	if (!S_ISREG(dt->do_lu.lo_header->loh_attr) || !dt_object_exists(dt) ||
	    dt_object_remote(dt_object_child(dt)))
		RETURN(-EINVAL);

	rc = lod_striping_load(env, lo);
	if (rc)
		GOTO(out, rc);

	LASSERT(lo->ldo_comp_cnt > 0);

	rc = lod_layout_data_init(info, lo->ldo_comp_cnt);
	if (rc)
		GOTO(out, rc);

	switch (lo->ldo_flr_state) {
	case LCM_FL_NONE:
		rc = lod_declare_update_plain(env, lo, mlc->mlc_intent,
					      &mlc->mlc_buf, th);
		break;
	case LCM_FL_RDONLY:
		rc = lod_declare_update_rdonly(env, lo, mlc, th);
		break;
	case LCM_FL_WRITE_PENDING:
		rc = lod_declare_update_write_pending(env, lo, mlc, th);
		break;
	case LCM_FL_SYNC_PENDING:
		rc = lod_declare_update_sync_pending(env, lo, mlc, th);
		break;
	default:
		rc = -ENOTSUPP;
		break;
	}
out:
	RETURN(rc);
}

/**
 * Instantiate layout component objects which covers the intent write offset.
 */
static int lod_layout_change(const struct lu_env *env, struct dt_object *dt,
			     struct md_layout_change *mlc, struct thandle *th)
{
	struct lu_attr *attr = &lod_env_info(env)->lti_attr;
	struct lu_attr *layout_attr = &lod_env_info(env)->lti_layout_attr;
	struct lod_object *lo = lod_dt_obj(dt);
	int rc;

	ENTRY;

	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		LASSERT(dir_mlc_ops[mlc->mlc_opc]);
		rc = dir_mlc_ops[mlc->mlc_opc](env, dt, mlc, th);
		RETURN(rc);
	}

	rc = lod_striped_create(env, dt, attr, NULL, th);
	if (!rc && layout_attr->la_valid & LA_LAYOUT_VERSION) {
		layout_attr->la_layout_version |= lo->ldo_layout_gen;
		rc = lod_attr_set(env, dt, layout_attr, th);
	}

	RETURN(rc);
}

const struct dt_object_operations lod_obj_ops = {
	.do_read_lock		= lod_read_lock,
	.do_write_lock		= lod_write_lock,
	.do_read_unlock		= lod_read_unlock,
	.do_write_unlock	= lod_write_unlock,
	.do_write_locked	= lod_write_locked,
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
	.do_declare_create	= lod_declare_create,
	.do_create		= lod_create,
	.do_declare_destroy	= lod_declare_destroy,
	.do_destroy		= lod_destroy,
	.do_index_try		= lod_index_try,
	.do_declare_ref_add	= lod_declare_ref_add,
	.do_ref_add		= lod_ref_add,
	.do_declare_ref_del	= lod_declare_ref_del,
	.do_ref_del		= lod_ref_del,
	.do_object_sync		= lod_object_sync,
	.do_object_lock		= lod_object_lock,
	.do_object_unlock	= lod_object_unlock,
	.do_invalidate		= lod_invalidate,
	.do_declare_layout_change = lod_declare_layout_change,
	.do_layout_change	= lod_layout_change,
};

/**
 * Implementation of dt_body_operations::dbo_read.
 *
 * \see dt_body_operations::dbo_read() in the API description for details.
 */
static ssize_t lod_read(const struct lu_env *env, struct dt_object *dt,
			struct lu_buf *buf, loff_t *pos)
{
	struct dt_object *next = dt_object_child(dt);

	LASSERT(S_ISREG(dt->do_lu.lo_header->loh_attr) ||
		S_ISLNK(dt->do_lu.lo_header->loh_attr));
	return next->do_body_ops->dbo_read(env, next, buf, pos);
}

/**
 * Implementation of dt_body_operations::dbo_declare_write.
 *
 * \see dt_body_operations::dbo_declare_write() in the API description
 * for details.
 */
static ssize_t lod_declare_write(const struct lu_env *env,
				 struct dt_object *dt,
				 const struct lu_buf *buf, loff_t pos,
				 struct thandle *th)
{
	return lod_sub_declare_write(env, dt_object_child(dt), buf, pos, th);
}

/**
 * Implementation of dt_body_operations::dbo_write.
 *
 * \see dt_body_operations::dbo_write() in the API description for details.
 */
static ssize_t lod_write(const struct lu_env *env, struct dt_object *dt,
			 const struct lu_buf *buf, loff_t *pos,
			 struct thandle *th)
{
	LASSERT(S_ISREG(dt->do_lu.lo_header->loh_attr) ||
		S_ISLNK(dt->do_lu.lo_header->loh_attr));
	return lod_sub_write(env, dt_object_child(dt), buf, pos, th);
}

static int lod_declare_punch(const struct lu_env *env, struct dt_object *dt,
			     __u64 start, __u64 end, struct thandle *th)
{
	if (dt_object_remote(dt))
		return -ENOTSUPP;

	return lod_sub_declare_punch(env, dt_object_child(dt), start, end, th);
}

static int lod_punch(const struct lu_env *env, struct dt_object *dt,
		     __u64 start, __u64 end, struct thandle *th)
{
	if (dt_object_remote(dt))
		return -ENOTSUPP;

	LASSERT(S_ISREG(dt->do_lu.lo_header->loh_attr));
	return lod_sub_punch(env, dt_object_child(dt), start, end, th);
}

/*
 * different type of files use the same body_ops because object may be created
 * in OUT, where there is no chance to set correct body_ops for each type, so
 * body_ops themselves will check file type inside, see lod_read/write/punch for
 * details.
 */
static const struct dt_body_operations lod_body_ops = {
	.dbo_read		= lod_read,
	.dbo_declare_write	= lod_declare_write,
	.dbo_write		= lod_write,
	.dbo_declare_punch	= lod_declare_punch,
	.dbo_punch		= lod_punch,
};

/**
 * Implementation of lu_object_operations::loo_object_init.
 *
 * The function determines the type and the index of the target device using
 * sequence of the object's FID. Then passes control down to the
 * corresponding device:
 *  OSD for the local objects, OSP for remote
 *
 * \see lu_object_operations::loo_object_init() in the API description
 * for details.
 */
static int lod_object_init(const struct lu_env *env, struct lu_object *lo,
			   const struct lu_object_conf *conf)
{
	struct lod_device	*lod	= lu2lod_dev(lo->lo_dev);
	struct lu_device	*cdev	= NULL;
	struct lu_object	*cobj;
	struct lod_tgt_descs	*ltd	= NULL;
	struct lod_tgt_desc	*tgt;
	u32			 idx	= 0;
	int			 type	= LU_SEQ_RANGE_ANY;
	int			 rc;
	ENTRY;

	rc = lod_fld_lookup(env, lod, lu_object_fid(lo), &idx, &type);
	if (rc != 0)
		RETURN(rc);

	if (type == LU_SEQ_RANGE_MDT &&
	    idx == lu_site2seq(lo->lo_dev->ld_site)->ss_node_id) {
		cdev = &lod->lod_child->dd_lu_dev;
	} else if (type == LU_SEQ_RANGE_MDT) {
		ltd = &lod->lod_mdt_descs;
		lod_getref(ltd);
	} else if (type == LU_SEQ_RANGE_OST) {
		ltd = &lod->lod_ost_descs;
		lod_getref(ltd);
	} else {
		LBUG();
	}

	if (ltd != NULL) {
		if (ltd->ltd_tgts_size > idx &&
		    test_bit(idx, ltd->ltd_tgt_bitmap)) {
			tgt = LTD_TGT(ltd, idx);

			LASSERT(tgt != NULL);
			LASSERT(tgt->ltd_tgt != NULL);

			cdev = &(tgt->ltd_tgt->dd_lu_dev);
		}
		lod_putref(lod, ltd);
	}

	if (unlikely(cdev == NULL))
		RETURN(-ENOENT);

	cobj = cdev->ld_ops->ldo_object_alloc(env, lo->lo_header, cdev);
	if (unlikely(cobj == NULL))
		RETURN(-ENOMEM);

	lu2lod_obj(lo)->ldo_obj.do_body_ops = &lod_body_ops;

	lu_object_add(lo, cobj);

	RETURN(0);
}

/**
 *
 * Alloc cached foreign LOV
 *
 * \param[in] lo        object
 * \param[in] size      size of foreign LOV
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
int lod_alloc_foreign_lov(struct lod_object *lo, size_t size)
{
	OBD_ALLOC_LARGE(lo->ldo_foreign_lov, size);
	if (lo->ldo_foreign_lov == NULL)
		return -ENOMEM;
	lo->ldo_foreign_lov_size = size;
	lo->ldo_is_foreign = 1;
	return 0;
}

/**
 *
 * Free cached foreign LOV
 *
 * \param[in] lo        object
 */
void lod_free_foreign_lov(struct lod_object *lo)
{
	if (lo->ldo_foreign_lov != NULL)
		OBD_FREE_LARGE(lo->ldo_foreign_lov, lo->ldo_foreign_lov_size);
	lo->ldo_foreign_lov = NULL;
	lo->ldo_foreign_lov_size = 0;
	lo->ldo_is_foreign = 0;
}

/**
 *
 * Free cached foreign LMV
 *
 * \param[in] lo        object
 */
void lod_free_foreign_lmv(struct lod_object *lo)
{
	if (lo->ldo_foreign_lmv != NULL)
		OBD_FREE_LARGE(lo->ldo_foreign_lmv, lo->ldo_foreign_lmv_size);
	lo->ldo_foreign_lmv = NULL;
	lo->ldo_foreign_lmv_size = 0;
	lo->ldo_dir_is_foreign = 0;
}

/**
 *
 * Release resources associated with striping.
 *
 * If the object is striped (regular or directory), then release
 * the stripe objects references and free the ldo_stripe array.
 *
 * \param[in] env	execution environment
 * \param[in] lo	object
 */
void lod_striping_free_nolock(const struct lu_env *env, struct lod_object *lo)
{
	struct lod_layout_component *lod_comp;
	int i, j;

	if (unlikely(lo->ldo_is_foreign)) {
		lod_free_foreign_lov(lo);
		lo->ldo_comp_cached = 0;
	} else if (unlikely(lo->ldo_dir_is_foreign)) {
		lod_free_foreign_lmv(lo);
		lo->ldo_dir_stripe_loaded = 0;
	} else if (lo->ldo_stripe != NULL) {
		LASSERT(lo->ldo_comp_entries == NULL);
		LASSERT(lo->ldo_dir_stripes_allocated > 0);

		for (i = 0; i < lo->ldo_dir_stripe_count; i++) {
			if (lo->ldo_stripe[i])
				dt_object_put(env, lo->ldo_stripe[i]);
		}

		j = sizeof(struct dt_object *) * lo->ldo_dir_stripes_allocated;
		OBD_FREE(lo->ldo_stripe, j);
		lo->ldo_stripe = NULL;
		lo->ldo_dir_stripes_allocated = 0;
		lo->ldo_dir_stripe_loaded = 0;
		lo->ldo_dir_stripe_count = 0;
	} else if (lo->ldo_comp_entries != NULL) {
		for (i = 0; i < lo->ldo_comp_cnt; i++) {
			/* free lod_layout_component::llc_stripe array */
			lod_comp = &lo->ldo_comp_entries[i];

			if (lod_comp->llc_stripe == NULL)
				continue;
			LASSERT(lod_comp->llc_stripes_allocated != 0);
			for (j = 0; j < lod_comp->llc_stripes_allocated; j++) {
				if (lod_comp->llc_stripe[j] != NULL)
					lu_object_put(env,
					       &lod_comp->llc_stripe[j]->do_lu);
			}
			OBD_FREE_PTR_ARRAY(lod_comp->llc_stripe,
					   lod_comp->llc_stripes_allocated);
			lod_comp->llc_stripe = NULL;
			OBD_FREE_PTR_ARRAY(lod_comp->llc_ost_indices,
					   lod_comp->llc_stripes_allocated);
			lod_comp->llc_ost_indices = NULL;
			lod_comp->llc_stripes_allocated = 0;
		}
		lod_free_comp_entries(lo);
		lo->ldo_comp_cached = 0;
	}
}

void lod_striping_free(const struct lu_env *env, struct lod_object *lo)
{
	mutex_lock(&lo->ldo_layout_mutex);
	lod_striping_free_nolock(env, lo);
	mutex_unlock(&lo->ldo_layout_mutex);
}

/**
 * Implementation of lu_object_operations::loo_object_free.
 *
 * \see lu_object_operations::loo_object_free() in the API description
 * for details.
 */
static void lod_object_free(const struct lu_env *env, struct lu_object *o)
{
	struct lod_object *lo = lu2lod_obj(o);

	/* release all underlying object pinned */
	lod_striping_free(env, lo);
	lu_object_fini(o);
	/* lo doesn't contain a lu_object_header, so we don't need call_rcu */
	OBD_SLAB_FREE_PTR(lo, lod_object_kmem);
}

/**
 * Implementation of lu_object_operations::loo_object_release.
 *
 * \see lu_object_operations::loo_object_release() in the API description
 * for details.
 */
static void lod_object_release(const struct lu_env *env, struct lu_object *o)
{
	/* XXX: shouldn't we release everything here in case if object
	 * creation failed before? */
}

/**
 * Implementation of lu_object_operations::loo_object_print.
 *
 * \see lu_object_operations::loo_object_print() in the API description
 * for details.
 */
static int lod_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *l)
{
	struct lod_object *o = lu2lod_obj((struct lu_object *) l);

	return (*p)(env, cookie, LUSTRE_LOD_NAME"-object@%p", o);
}

const struct lu_object_operations lod_lu_obj_ops = {
	.loo_object_init	= lod_object_init,
	.loo_object_free	= lod_object_free,
	.loo_object_release	= lod_object_release,
	.loo_object_print	= lod_object_print,
};
