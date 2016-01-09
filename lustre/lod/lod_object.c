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
 * Copyright (c) 2012, 2015, Intel Corporation.
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

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>

#include <lustre_fid.h>
#include <lustre_linkea.h>
#include <lustre_lmv.h>
#include <lustre_param.h>
#include <lustre_swab.h>
#include <lustre_ver.h>
#include <lprocfs_status.h>
#include <md_object.h>

#include "lod_internal.h"

static const char dot[] = ".";
static const char dotdot[] = "..";

static const struct dt_body_operations lod_body_lnk_ops;
static const struct dt_body_operations lod_body_ops;

/**
 * Implementation of dt_index_operations::dio_lookup
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_index_operations::dio_lookup() in the API description for details.
 */
static int lod_index_lookup(const struct lu_env *env, struct dt_object *dt,
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
static int lod_declare_index_insert(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_rec *rec,
				    const struct dt_key *key,
				    struct thandle *th)
{
	return lod_sub_object_declare_insert(env, dt_object_child(dt),
					     rec, key, th);
}

/**
 * Implementation of dt_index_operations::dio_insert.
 *
 * Used with regular (non-striped) objects
 *
 * \see dt_index_operations::dio_insert() in the API description for details.
 */
static int lod_index_insert(const struct lu_env *env,
			    struct dt_object *dt,
			    const struct dt_rec *rec,
			    const struct dt_key *key,
			    struct thandle *th,
			    int ign)
{
	return lod_sub_object_index_insert(env, dt_object_child(dt), rec, key,
					   th, ign);
}

/**
 * Implementation of dt_index_operations::dio_declare_delete.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_index_operations::dio_declare_delete() in the API description
 * for details.
 */
static int lod_declare_index_delete(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_key *key,
				    struct thandle *th)
{
	return lod_sub_object_declare_delete(env, dt_object_child(dt), key,
					     th);
}

/**
 * Implementation of dt_index_operations::dio_delete.
 *
 * Used with regular (non-striped) objects.
 *
 * \see dt_index_operations::dio_delete() in the API description for details.
 */
static int lod_index_delete(const struct lu_env *env,
			    struct dt_object *dt,
			    const struct dt_key *key,
			    struct thandle *th)
{
	return lod_sub_object_delete(env, dt_object_child(dt), key, th);
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
		.rec_size	= lod_it_rec_size,
		.store		= lod_it_store,
		.load		= lod_it_load,
		.key_rec	= lod_it_key_rec,
	}
};

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
	struct lod_object	*lo = lod_dt_obj(dt);
	struct dt_object	*next;
	struct lod_it		*it = &lod_env_info(env)->lti_it;
	struct dt_it		*it_next;
	ENTRY;

	LASSERT(lo->ldo_stripenr > 0);
	next = lo->ldo_stripe[0];
	LASSERT(next != NULL);
	LASSERT(next->do_index_ops != NULL);

	it_next = next->do_index_ops->dio_it.init(env, next, attr);
	if (IS_ERR(it_next))
		return it_next;

	/* currently we do not use more than one iterator per thread
	 * so we store it in thread info. if at some point we need
	 * more active iterators in a single thread, we can allocate
	 * additional ones */
	LASSERT(it->lit_obj == NULL);

	it->lit_stripe_index = 0;
	it->lit_attr = attr;
	it->lit_it = it_next;
	it->lit_obj = dt;

	return (struct dt_it *)it;
}

#define LOD_CHECK_STRIPED_IT(env, it, lo)			\
do {								\
	LASSERT((it)->lit_obj != NULL);				\
	LASSERT((it)->lit_it != NULL);				\
	LASSERT((lo)->ldo_stripenr > 0);			\
	LASSERT((it)->lit_stripe_index < (lo)->ldo_stripenr);	\
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
		LASSERT(next != NULL);
		LASSERT(next->do_index_ops != NULL);

		next->do_index_ops->dio_it.fini(env, it->lit_it);
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
	const struct lod_it	*it = (const struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;
	ENTRY;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
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
	struct lod_it		*it = (struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;

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
	struct lod_it		*it = (struct lod_it *)di;
	struct lod_object	*lo = lod_dt_obj(it->lit_obj);
	struct dt_object	*next;
	struct dt_it		*it_next;
	int			rc;
	ENTRY;

	LOD_CHECK_STRIPED_IT(env, it, lo);

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
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

	/* go to next stripe */
	if (it->lit_stripe_index + 1 >= lo->ldo_stripenr)
		RETURN(1);

	it->lit_stripe_index++;

	next->do_index_ops->dio_it.put(env, it->lit_it);
	next->do_index_ops->dio_it.fini(env, it->lit_it);
	it->lit_it = NULL;

	next = lo->ldo_stripe[it->lit_stripe_index];
	LASSERT(next != NULL);
	rc = next->do_ops->do_index_try(env, next, &dt_directory_features);
	if (rc != 0)
		RETURN(rc);

	LASSERT(next->do_index_ops != NULL);

	it_next = next->do_index_ops->dio_it.init(env, next, it->lit_attr);
	if (!IS_ERR(it_next)) {
		it->lit_it = it_next;
		goto again;
	} else {
		rc = PTR_ERR(it_next);
	}

	RETURN(rc);
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

static struct dt_index_operations lod_striped_index_ops = {
	.dio_lookup		= lod_index_lookup,
	.dio_declare_insert	= lod_declare_index_insert,
	.dio_insert		= lod_index_insert,
	.dio_declare_delete	= lod_declare_index_delete,
	.dio_delete		= lod_index_delete,
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

	/* If it is not a striped directory, then load nothing. */
	if (magic != LMV_MAGIC_V1)
		RETURN(0);

	/* If it is in migration (or failure), then load nothing. */
	if (le32_to_cpu(lmv1->lmv_hash_type) & LMV_HASH_FLAG_MIGRATION)
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

		len = snprintf(name, sizeof(name),
			       DFID":", PFID(&ent->lde_fid));
		/* The ent->lde_name is composed of ${FID}:${index} */
		if (ent->lde_namelen < len + 1 ||
		    memcmp(ent->lde_name, name, len) != 0) {
			CDEBUG(lod->lod_lmv_failout ? D_ERROR : D_INFO,
			       "%s: invalid shard name %.*s with the FID "DFID
			       " for the striped directory "DFID", %s\n",
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
				CDEBUG(lod->lod_lmv_failout ? D_ERROR : D_INFO,
				       "%s: invalid shard name %.*s with the "
				       "FID "DFID" for the striped directory "
				       DFID", %s\n",
				       lod2obd(lod)->obd_name, ent->lde_namelen,
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

	rc = lod_load_striping_locked(env, lo);
	if (rc != 0)
		RETURN(rc);

	rc = next->do_ops->do_index_try(env, next, feat);
	if (rc != 0)
		RETURN(rc);

	if (lo->ldo_stripenr > 0) {
		int i;

		for (i = 0; i < lo->ldo_stripenr; i++) {
			if (dt_object_exists(lo->ldo_stripe[i]) == 0)
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
static void lod_object_read_lock(const struct lu_env *env,
				 struct dt_object *dt, unsigned role)
{
	dt_read_lock(env, dt_object_child(dt), role);
}

/**
 * Implementation of dt_object_operations::do_write_lock.
 *
 * \see dt_object_operations::do_write_lock() in the API description for
 * details.
 */
static void lod_object_write_lock(const struct lu_env *env,
				  struct dt_object *dt, unsigned role)
{
	dt_write_lock(env, dt_object_child(dt), role);
}

/**
 * Implementation of dt_object_operations::do_read_unlock.
 *
 * \see dt_object_operations::do_read_unlock() in the API description for
 * details.
 */
static void lod_object_read_unlock(const struct lu_env *env,
				   struct dt_object *dt)
{
	dt_read_unlock(env, dt_object_child(dt));
}

/**
 * Implementation of dt_object_operations::do_write_unlock.
 *
 * \see dt_object_operations::do_write_unlock() in the API description for
 * details.
 */
static void lod_object_write_unlock(const struct lu_env *env,
				    struct dt_object *dt)
{
	dt_write_unlock(env, dt_object_child(dt));
}

/**
 * Implementation of dt_object_operations::do_write_locked.
 *
 * \see dt_object_operations::do_write_locked() in the API description for
 * details.
 */
static int lod_object_write_locked(const struct lu_env *env,
				   struct dt_object *dt)
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
	rc = lod_sub_object_declare_attr_set(env, next, attr, th);
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

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_OWNER))
			RETURN(0);
	} else {
		if (!(attr->la_valid & (LA_UID | LA_GID | LA_MODE |
					LA_ATIME | LA_MTIME | LA_CTIME |
					LA_FLAGS)))
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

	/*
	 * if object is striped declare changes on the stripes
	 */
	LASSERT(lo->ldo_stripe);
	for (i = 0; i < lo->ldo_stripenr; i++) {
		if (lo->ldo_stripe[i] == NULL)
			continue;
		rc = lod_sub_object_declare_attr_set(env,
					lo->ldo_stripe[i], attr,
					th);
		if (rc != 0)
			RETURN(rc);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_STRIPE) &&
	    dt_object_exists(next) != 0 &&
	    dt_object_remote(next) == 0)
		lod_sub_object_declare_xattr_del(env, next,
						XATTR_NAME_LOV, th);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_CHANGE_STRIPE) &&
	    dt_object_exists(next) &&
	    dt_object_remote(next) == 0 && S_ISREG(attr->la_mode)) {
		struct lod_thread_info *info = lod_env_info(env);
		struct lu_buf *buf = &info->lti_buf;

		buf->lb_buf = info->lti_ea_store;
		buf->lb_len = info->lti_ea_store_size;
		lod_sub_object_declare_xattr_set(env, next, buf,
						 XATTR_NAME_LOV,
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
	rc = lod_sub_object_attr_set(env, next, attr, th);
	if (rc)
		RETURN(rc);

	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		if (!(attr->la_valid & (LA_UID | LA_GID)))
			RETURN(rc);

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_OWNER))
			RETURN(0);
	} else {
		if (!(attr->la_valid & (LA_UID | LA_GID | LA_MODE |
					LA_ATIME | LA_MTIME | LA_CTIME |
					LA_FLAGS)))
			RETURN(rc);
	}

	if (lo->ldo_stripenr == 0)
		RETURN(0);

	/*
	 * if object is striped, apply changes to all the stripes
	 */
	LASSERT(lo->ldo_stripe);
	for (i = 0; i < lo->ldo_stripenr; i++) {
		if (unlikely(lo->ldo_stripe[i] == NULL))
			continue;

		if (S_ISDIR(dt->do_lu.lo_header->loh_attr) &&
		    (dt_object_exists(lo->ldo_stripe[i]) == 0))
			continue;

		rc = lod_sub_object_attr_set(env, lo->ldo_stripe[i], attr, th);
		if (rc != 0)
			break;
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_STRIPE) &&
	    dt_object_exists(next) != 0 &&
	    dt_object_remote(next) == 0)
		rc = lod_sub_object_xattr_del(env, next, XATTR_NAME_LOV, th);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_CHANGE_STRIPE) &&
	    dt_object_exists(next) &&
	    dt_object_remote(next) == 0 && S_ISREG(attr->la_mode)) {
		struct lod_thread_info *info = lod_env_info(env);
		struct lu_buf *buf = &info->lti_buf;
		struct ost_id *oi = &info->lti_ostid;
		struct lu_fid *fid = &info->lti_fid;
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
		if (magic == LOV_MAGIC_V1)
			objs = &(lmm->lmm_objects[0]);
		else
			objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
		ostid_le_to_cpu(&objs->l_ost_oi, oi);
		ostid_to_fid(fid, oi, le32_to_cpu(objs->l_ost_idx));
		fid->f_oid--;
		fid_to_ostid(fid, oi);
		ostid_cpu_to_le(oi, &objs->l_ost_oi);

		rc = lod_sub_object_xattr_set(env, next, buf, XATTR_NAME_LOV,
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
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_device	*dev = lu2lod_dev(dt->do_lu.lo_dev);
	int			 rc, is_root;
	ENTRY;

	rc = dt_xattr_get(env, dt_object_child(dt), buf, name);
	if (strcmp(name, XATTR_NAME_LMV) == 0) {
		struct lmv_mds_md_v1	*lmv1;
		int			 rc1 = 0;

		if (rc > (typeof(rc))sizeof(*lmv1))
			RETURN(rc);

		if (rc < (typeof(rc))sizeof(*lmv1))
			RETURN(rc = rc > 0 ? -EINVAL : rc);

		if (buf->lb_buf == NULL || buf->lb_len == 0) {
			CLASSERT(sizeof(*lmv1) <= sizeof(info->lti_key));

			info->lti_buf.lb_buf = info->lti_key;
			info->lti_buf.lb_len = sizeof(*lmv1);
			rc = dt_xattr_get(env, dt_object_child(dt),
					  &info->lti_buf, name);
			if (unlikely(rc != sizeof(*lmv1)))
				RETURN(rc = rc > 0 ? -EINVAL : rc);

			lmv1 = info->lti_buf.lb_buf;
			/* The on-disk LMV EA only contains header, but the
			 * returned LMV EA size should contain the space for
			 * the FIDs of all shards of the striped directory. */
			if (le32_to_cpu(lmv1->lmv_magic) == LMV_MAGIC_V1)
				rc = lmv_mds_md_size(
					le32_to_cpu(lmv1->lmv_stripe_count),
					LMV_MAGIC_V1);
		} else {
			rc1 = lod_load_lmv_shards(env, lod_dt_obj(dt),
						  buf, false);
		}

		RETURN(rc = rc1 != 0 ? rc1 : rc);
	}

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
	LASSERT(lo->ldo_stripenr > 0);
	stripe_count = lo->ldo_stripenr;
	/* Only store the LMV EA heahder on the disk. */
	if (info->lti_ea_store_size < sizeof(*lmm1)) {
		rc = lod_ea_store_resize(info, sizeof(*lmm1));
		if (rc != 0)
			RETURN(rc);
	} else {
		memset(info->lti_ea_store, 0, sizeof(*lmm1));
	}

	lmm1 = (struct lmv_mds_md_v1 *)info->lti_ea_store;
	lmm1->lmv_magic = cpu_to_le32(LMV_MAGIC);
	lmm1->lmv_stripe_count = cpu_to_le32(stripe_count);
	lmm1->lmv_hash_type = cpu_to_le32(lo->ldo_dir_hash_type);
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

	if (le32_to_cpu(lmv1->lmv_hash_type) & LMV_HASH_FLAG_MIGRATION)
		RETURN(0);

	if (le32_to_cpu(lmv1->lmv_magic) == LMV_MAGIC_STRIPE) {
		lo->ldo_dir_slave_stripe = 1;
		RETURN(0);
	}

	if (le32_to_cpu(lmv1->lmv_magic) != LMV_MAGIC_V1)
		RETURN(-EINVAL);

	if (le32_to_cpu(lmv1->lmv_stripe_count) < 1)
		RETURN(0);

	LASSERT(lo->ldo_stripe == NULL);
	OBD_ALLOC(stripe, sizeof(stripe[0]) *
		  (le32_to_cpu(lmv1->lmv_stripe_count)));
	if (stripe == NULL)
		RETURN(-ENOMEM);

	for (i = 0; i < le32_to_cpu(lmv1->lmv_stripe_count); i++) {
		struct dt_device	*tgt_dt;
		struct dt_object	*dto;
		int			type = LU_SEQ_RANGE_ANY;
		__u32			idx;

		fid_le_to_cpu(fid, &lmv1->lmv_stripe_fids[i]);
		if (!fid_is_sane(fid))
			GOTO(out, rc = -ESTALE);

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
	lo->ldo_stripenr = le32_to_cpu(lmv1->lmv_stripe_count);
	lo->ldo_stripes_allocated = le32_to_cpu(lmv1->lmv_stripe_count);
	if (rc != 0)
		lod_object_free_striping(env, lo);

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
	for (i = 0; i < lo->ldo_stripenr; i++) {
		struct dt_object	*dto = lo->ldo_stripe[i];
		char			*stripe_name = info->lti_key;
		struct lu_name		*sname;
		struct linkea_data	 ldata		= { NULL };
		struct lu_buf		linkea_buf;

		rc = lod_sub_object_declare_create(env, dto, attr, NULL,
						   dof, th);
		if (rc != 0)
			GOTO(out, rc);

		if (!dt_try_as_dir(env, dto))
			GOTO(out, rc = -EINVAL);

		rc = lod_sub_object_declare_ref_add(env, dto, th);
		if (rc != 0)
			GOTO(out, rc);

		rec->rec_fid = lu_object_fid(&dto->do_lu);
		rc = lod_sub_object_declare_insert(env, dto,
					(const struct dt_rec *)rec,
					(const struct dt_key *)dot, th);
		if (rc != 0)
			GOTO(out, rc);

		/* master stripe FID will be put to .. */
		rec->rec_fid = lu_object_fid(&dt->do_lu);
		rc = lod_sub_object_declare_insert(env, dto,
					(const struct dt_rec *)rec,
					(const struct dt_key *)dotdot,
					th);
		if (rc != 0)
			GOTO(out, rc);

		if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_SLAVE_LMV) ||
		    cfs_fail_val != i) {
			if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_LMV) &&
			    cfs_fail_val == i)
				slave_lmm->lmv_master_mdt_index =
							cpu_to_le32(i + 1);
			else
				slave_lmm->lmv_master_mdt_index =
							cpu_to_le32(i);
			rc = lod_sub_object_declare_xattr_set(env, dto,
					&slave_lmv_buf, XATTR_NAME_LMV, 0, th);
			if (rc != 0)
				GOTO(out, rc);
		}

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_NAME) &&
		    cfs_fail_val == i)
			snprintf(stripe_name, sizeof(info->lti_key), DFID":%u",
				PFID(lu_object_fid(&dto->do_lu)), i + 1);
		else
			snprintf(stripe_name, sizeof(info->lti_key), DFID":%u",
				PFID(lu_object_fid(&dto->do_lu)), i);

		sname = lod_name_get(env, stripe_name, strlen(stripe_name));
		rc = linkea_data_new(&ldata, &info->lti_linkea_buf);
		if (rc != 0)
			GOTO(out, rc);

		rc = linkea_add_buf(&ldata, sname, lu_object_fid(&dt->do_lu));
		if (rc != 0)
			GOTO(out, rc);

		linkea_buf.lb_buf = ldata.ld_buf->lb_buf;
		linkea_buf.lb_len = ldata.ld_leh->leh_len;
		rc = lod_sub_object_declare_xattr_set(env, dto, &linkea_buf,
					  XATTR_NAME_LINK, 0, th);
		if (rc != 0)
			GOTO(out, rc);

		rec->rec_fid = lu_object_fid(&dto->do_lu);
		rc = lod_sub_object_declare_insert(env, dt_object_child(dt),
				       (const struct dt_rec *)rec,
				       (const struct dt_key *)stripe_name,
				       th);
		if (rc != 0)
			GOTO(out, rc);

		rc = lod_sub_object_declare_ref_add(env, dt_object_child(dt),
						    th);
		if (rc != 0)
			GOTO(out, rc);
	}

	rc = lod_sub_object_declare_xattr_set(env, dt_object_child(dt),
				&lmv_buf, XATTR_NAME_LMV, 0, th);
	if (rc != 0)
		GOTO(out, rc);
out:
	if (slave_lmm != NULL)
		OBD_FREE_PTR(slave_lmm);

	RETURN(rc);
}

static int lod_prep_md_striped_create(const struct lu_env *env,
				      struct dt_object *dt,
				      struct lu_attr *attr,
				      const struct lmv_user_md_v1 *lum,
				      struct dt_object_format *dof,
				      struct thandle *th)
{
	struct lod_device	*lod = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_tgt_descs	*ltd = &lod->lod_mdt_descs;
	struct lod_object	*lo = lod_dt_obj(dt);
	struct dt_object	**stripe;
	__u32			stripe_count;
	int			*idx_array;
	__u32			master_index;
	int			rc = 0;
	__u32			i;
	__u32			j;
	ENTRY;

	/* The lum has been verifed in lod_verify_md_striping */
	LASSERT(le32_to_cpu(lum->lum_magic) == LMV_USER_MAGIC);
	LASSERT(le32_to_cpu(lum->lum_stripe_count) > 0);

	stripe_count = le32_to_cpu(lum->lum_stripe_count);

	OBD_ALLOC(stripe, sizeof(stripe[0]) * stripe_count);
	if (stripe == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC(idx_array, sizeof(idx_array[0]) * stripe_count);
	if (idx_array == NULL)
		GOTO(out_free, rc = -ENOMEM);

	/* Start index will be the master MDT */
	master_index = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id;
	idx_array[0] = master_index;
	for (i = 0; i < stripe_count; i++) {
		struct lod_tgt_desc	*tgt = NULL;
		struct dt_object	*dto;
		struct lu_fid		fid = { 0 };
		int			idx;
		struct lu_object_conf	conf = { 0 };
		struct dt_device	*tgt_dt = NULL;

		/* Try to find next avaible target */
		idx = idx_array[i];
		for (j = 0; j < lod->lod_remote_mdt_count;
		     j++, idx = (idx + 1) % (lod->lod_remote_mdt_count + 1)) {
			bool already_allocated = false;
			__u32 k;

			CDEBUG(D_INFO, "try idx %d, mdt cnt %u, allocated %u\n",
			       idx, lod->lod_remote_mdt_count + 1, i);
			if (idx == master_index) {
				/* Allocate the FID locally */
				rc = obd_fid_alloc(env, lod->lod_child_exp,
						   &fid, NULL);
				if (rc < 0)
					GOTO(out_put, rc);
				tgt_dt = lod->lod_child;
				break;
			}

			/* Find next available target */
			if (!cfs_bitmap_check(ltd->ltd_tgt_bitmap, idx))
				continue;

			if (likely(!OBD_FAIL_CHECK(OBD_FAIL_LARGE_STRIPE))) {
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
			}

			/* check the status of the OSP */
			tgt = LTD_TGT(ltd, idx);
			if (tgt == NULL)
				continue;

			tgt_dt = tgt->ltd_tgt;
			rc = dt_statfs(env, tgt_dt, NULL);
			if (rc) {
				/* this OSP doesn't feel well */
				rc = 0;
				continue;
			}

			rc = obd_fid_alloc(env, tgt->ltd_exp, &fid, NULL);
			if (rc < 0) {
				rc = 0;
				continue;
			}

			break;
		}

		/* Can not allocate more stripes */
		if (j == lod->lod_remote_mdt_count) {
			CDEBUG(D_INFO, "%s: require stripes %u only get %d\n",
			       lod2obd(lod)->obd_name, stripe_count, i - 1);
			break;
		}

		CDEBUG(D_INFO, "Get idx %d, for stripe %d "DFID"\n",
		       idx, i, PFID(&fid));
		idx_array[i] = idx;
		/* Set the start index for next stripe allocation */
		if (i < stripe_count - 1)
			idx_array[i + 1] = (idx + 1) %
					   (lod->lod_remote_mdt_count + 1);
		/* tgt_dt and fid must be ready after search avaible OSP
		 * in the above loop */
		LASSERT(tgt_dt != NULL);
		LASSERT(fid_is_sane(&fid));
		conf.loc_flags = LOC_F_NEW;
		dto = dt_locate_at(env, tgt_dt, &fid,
				   dt->do_lu.lo_dev->ld_site->ls_top_dev,
				   &conf);
		if (IS_ERR(dto))
			GOTO(out_put, rc = PTR_ERR(dto));
		stripe[i] = dto;
	}

	lo->ldo_dir_striped = 1;
	lo->ldo_stripe = stripe;
	lo->ldo_stripenr = i;
	lo->ldo_stripes_allocated = stripe_count;

	if (lo->ldo_stripenr == 0)
		GOTO(out_put, rc = -ENOSPC);

	rc = lod_dir_declare_create_stripes(env, dt, attr, dof, th);
	if (rc != 0)
		GOTO(out_put, rc);

out_put:
	if (rc < 0) {
		for (i = 0; i < stripe_count; i++)
			if (stripe[i] != NULL)
				lu_object_put(env, &stripe[i]->do_lu);
		OBD_FREE(stripe, sizeof(stripe[0]) * stripe_count);
		lo->ldo_stripenr = 0;
		lo->ldo_stripes_allocated = 0;
		lo->ldo_stripe = NULL;
	}

out_free:
	if (idx_array != NULL)
		OBD_FREE(idx_array, sizeof(idx_array[0]) * stripe_count);

	RETURN(rc);
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
	struct lod_device	*lod = lu2lod_dev(dt->do_lu.lo_dev);
	struct lmv_user_md_v1	*lum;
	int			rc;
	ENTRY;

	lum = lum_buf->lb_buf;
	LASSERT(lum != NULL);

	CDEBUG(D_INFO, "lum magic = %x count = %u offset = %d\n",
	       le32_to_cpu(lum->lum_magic), le32_to_cpu(lum->lum_stripe_count),
	       (int)le32_to_cpu(lum->lum_stripe_offset));

	if (le32_to_cpu(lum->lum_stripe_count) == 0)
		GOTO(out, rc = 0);

	rc = lod_verify_md_striping(lod, lum);
	if (rc != 0)
		GOTO(out, rc);

	/* prepare dir striped objects */
	rc = lod_prep_md_striped_create(env, dt, attr, lum, dof, th);
	if (rc != 0) {
		/* failed to create striping, let's reset
		 * config so that others don't get confused */
		lod_object_free_striping(env, lo);
		GOTO(out, rc);
	}
out:
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
	}

	rc = lod_sub_object_declare_xattr_set(env, next, buf, name, fl, th);
	if (rc != 0)
		RETURN(rc);

	/* Note: Do not set LinkEA on sub-stripes, otherwise
	 * it will confuse the fid2path process(see mdt_path_current()).
	 * The linkEA between master and sub-stripes is set in
	 * lod_xattr_set_lmv(). */
	if (strcmp(name, XATTR_NAME_LINK) == 0)
		RETURN(0);

	/* set xattr to each stripes, if needed */
	rc = lod_load_striping(env, lo);
	if (rc != 0)
		RETURN(rc);

	if (lo->ldo_stripenr == 0)
		RETURN(0);

	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);

		rc = lod_sub_object_declare_xattr_set(env, lo->ldo_stripe[i],
						buf, name, fl, th);
		if (rc != 0)
			break;
	}

	RETURN(rc);
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
 * \retval	negative errno if reset fais
 */
static int lod_object_replace_parent_fid(const struct lu_env *env,
					 struct dt_object *dt,
					 struct thandle *th, bool declare)
{
	struct lod_object *lo = lod_dt_obj(dt);
	struct lod_thread_info	*info = lod_env_info(env);
	struct lu_buf *buf = &info->lti_buf;
	struct filter_fid *ff;
	int i, rc;
	ENTRY;

	LASSERT(S_ISREG(dt->do_lu.lo_header->loh_attr));

	/* set xattr to each stripes, if needed */
	rc = lod_load_striping(env, lo);
	if (rc != 0)
		RETURN(rc);

	if (lo->ldo_stripenr == 0)
		RETURN(0);

	if (info->lti_ea_store_size < sizeof(*ff)) {
		rc = lod_ea_store_resize(info, sizeof(*ff));
		if (rc != 0)
			RETURN(rc);
	}

	buf->lb_buf = info->lti_ea_store;
	buf->lb_len = info->lti_ea_store_size;

	for (i = 0; i < lo->ldo_stripenr; i++) {
		if (lo->ldo_stripe[i] == NULL)
			continue;

		rc = dt_xattr_get(env, lo->ldo_stripe[i], buf,
				  XATTR_NAME_FID);
		if (rc < 0) {
			rc = 0;
			continue;
		}

		ff = buf->lb_buf;
		fid_le_to_cpu(&ff->ff_parent, &ff->ff_parent);
		ff->ff_parent.f_seq = lu_object_fid(&dt->do_lu)->f_seq;
		ff->ff_parent.f_oid = lu_object_fid(&dt->do_lu)->f_oid;
		fid_cpu_to_le(&ff->ff_parent, &ff->ff_parent);

		if (declare) {
			rc = lod_sub_object_declare_xattr_set(env,
						lo->ldo_stripe[i], buf,
						XATTR_NAME_FID,
						LU_XATTR_REPLACE, th);
		} else {
			rc = lod_sub_object_xattr_set(env, lo->ldo_stripe[i],
						      buf, XATTR_NAME_FID,
						      LU_XATTR_REPLACE, th);
		}
		if (rc < 0)
			break;
	}

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
			rc = dt_attr_get(env, next, attr);
			if (rc)
				RETURN(rc);
		} else {
			memset(attr, 0, sizeof(*attr));
			attr->la_valid = LA_TYPE | LA_MODE;
			attr->la_mode = S_IFREG;
		}
		rc = lod_declare_striped_object(env, dt, attr, buf, th);
	} else if (S_ISDIR(mode)) {
		rc = lod_dir_declare_xattr_set(env, dt, buf, name, fl, th);
	} else if (strcmp(name, XATTR_NAME_FID) == 0) {
		rc = lod_object_replace_parent_fid(env, dt, th, true);
	} else {
		rc = lod_sub_object_declare_xattr_set(env, next, buf, name,
						      fl, th);
	}

	RETURN(rc);
}

/**
 * Resets cached default striping in the object.
 *
 * \param[in] lo	object
 */
static void lod_lov_stripe_cache_clear(struct lod_object *lo)
{
	lo->ldo_def_striping_set = 0;
	lo->ldo_def_striping_cached = 0;
	lod_object_set_pool(lo, NULL);
	lo->ldo_def_stripe_size = 0;
	lo->ldo_def_stripenr = 0;
	if (lo->ldo_dir_stripe != NULL)
		lo->ldo_dir_def_striping_cached = 0;
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

	rc = lod_sub_object_xattr_set(env, next, buf, name, fl, th);
	if (rc != 0 || !S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(rc);

	/* Note: Do not set LinkEA on sub-stripes, otherwise
	 * it will confuse the fid2path process(see mdt_path_current()).
	 * The linkEA between master and sub-stripes is set in
	 * lod_xattr_set_lmv(). */
	if (lo->ldo_stripenr == 0 || strcmp(name, XATTR_NAME_LINK) == 0)
		RETURN(0);

	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);

		rc = lod_sub_object_xattr_set(env, lo->ldo_stripe[i], buf, name,
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
	struct dt_object	*next = dt_object_child(dt);
	struct lod_object	*lo = lod_dt_obj(dt);
	int			rc;
	int			i;
	ENTRY;

	rc = lod_sub_object_xattr_del(env, next, name, th);
	if (rc != 0 || !S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(rc);

	if (lo->ldo_stripenr == 0)
		RETURN(rc);

	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);

		rc = lod_sub_object_xattr_del(env, lo->ldo_stripe[i], name,
					      th);
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
	struct lod_device	*d = lu2lod_dev(dt->do_lu.lo_dev);
	struct lod_object	*l = lod_dt_obj(dt);
	struct lov_user_md_v1	*lum;
	struct lov_user_md_v3	*v3 = NULL;
	const char		*pool_name = NULL;
	int			 rc;
	ENTRY;

	/* If it is striped dir, we should clear the stripe cache for
	 * slave stripe as well, but there are no effective way to
	 * notify the LOD on the slave MDT, so we do not cache stripe
	 * information for slave stripe for now. XXX*/
	lod_lov_stripe_cache_clear(l);
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
	struct lod_object	*l = lod_dt_obj(dt);
	struct lmv_user_md_v1	*lum;
	int			 rc;
	ENTRY;

	LASSERT(buf != NULL && buf->lb_buf != NULL);
	lum = buf->lb_buf;

	CDEBUG(D_OTHER, "set default stripe_count # %u stripe_offset %d\n",
	      le32_to_cpu(lum->lum_stripe_count),
	      (int)le32_to_cpu(lum->lum_stripe_offset));

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

	/* Update default stripe cache */
	if (l->ldo_dir_stripe == NULL) {
		OBD_ALLOC_PTR(l->ldo_dir_stripe);
		if (l->ldo_dir_stripe == NULL)
			RETURN(-ENOMEM);
	}

	l->ldo_dir_def_striping_cached = 0;
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
	if (lo->ldo_stripenr == 0)
		RETURN(0);

	rc = dt_attr_get(env, dt_object_child(dt), attr);
	if (rc != 0)
		RETURN(rc);

	attr->la_valid = LA_ATIME | LA_MTIME | LA_CTIME |
			 LA_MODE | LA_UID | LA_GID | LA_TYPE;
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
	for (i = 0; i < lo->ldo_stripenr; i++) {
		struct dt_object *dto;
		char		 *stripe_name = info->lti_key;
		struct lu_name		*sname;
		struct linkea_data	 ldata		= { NULL };
		struct lu_buf		 linkea_buf;

		dto = lo->ldo_stripe[i];

		dt_write_lock(env, dto, MOR_TGT_CHILD);
		rc = lod_sub_object_create(env, dto, attr, NULL, dof,
					   th);
		if (rc != 0) {
			dt_write_unlock(env, dto);
			GOTO(out, rc);
		}

		rc = lod_sub_object_ref_add(env, dto, th);
		dt_write_unlock(env, dto);
		if (rc != 0)
			GOTO(out, rc);

		rec->rec_fid = lu_object_fid(&dto->do_lu);
		rc = lod_sub_object_index_insert(env, dto,
				(const struct dt_rec *)rec,
				(const struct dt_key *)dot, th, 0);
		if (rc != 0)
			GOTO(out, rc);

		rec->rec_fid = lu_object_fid(&dt->do_lu);
		rc = lod_sub_object_index_insert(env, dto, (struct dt_rec *)rec,
			       (const struct dt_key *)dotdot, th, 0);
		if (rc != 0)
			GOTO(out, rc);

		if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_SLAVE_LMV) ||
		    cfs_fail_val != i) {
			if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_LMV) &&
			    cfs_fail_val == i)
				slave_lmm->lmv_master_mdt_index =
							cpu_to_le32(i + 1);
			else
				slave_lmm->lmv_master_mdt_index =
							cpu_to_le32(i);

			rc = lod_sub_object_xattr_set(env, dto, &slave_lmv_buf,
						      XATTR_NAME_LMV, fl, th);
			if (rc != 0)
				GOTO(out, rc);
		}

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_SLAVE_NAME) &&
		    cfs_fail_val == i)
			snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
				 PFID(lu_object_fid(&dto->do_lu)), i + 1);
		else
			snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
				 PFID(lu_object_fid(&dto->do_lu)), i);

		sname = lod_name_get(env, stripe_name, strlen(stripe_name));
		rc = linkea_data_new(&ldata, &info->lti_linkea_buf);
		if (rc != 0)
			GOTO(out, rc);

		rc = linkea_add_buf(&ldata, sname, lu_object_fid(&dt->do_lu));
		if (rc != 0)
			GOTO(out, rc);

		linkea_buf.lb_buf = ldata.ld_buf->lb_buf;
		linkea_buf.lb_len = ldata.ld_leh->leh_len;
		rc = lod_sub_object_xattr_set(env, dto, &linkea_buf,
					XATTR_NAME_LINK, 0, th);
		if (rc != 0)
			GOTO(out, rc);

		rec->rec_fid = lu_object_fid(&dto->do_lu);
		rc = lod_sub_object_index_insert(env, dt_object_child(dt),
			       (const struct dt_rec *)rec,
			       (const struct dt_key *)stripe_name, th, 0);
		if (rc != 0)
			GOTO(out, rc);

		rc = lod_sub_object_ref_add(env, dt_object_child(dt), th);
		if (rc != 0)
			GOTO(out, rc);
	}

	if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_MASTER_LMV))
		rc = lod_sub_object_xattr_set(env, dt_object_child(dt),
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
					    struct dt_object_format *dof,
					    struct thandle *th,
					    bool declare)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_object	*lo = lod_dt_obj(dt);
	int			rc;
	ENTRY;

	if (!LMVEA_DELETE_VALUES(lo->ldo_stripenr,
				 lo->ldo_dir_stripe_offset)) {
		struct lmv_user_md_v1 *v1 = info->lti_ea_store;
		int stripe_count = lo->ldo_stripenr;

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
						       &info->lti_buf, dof, th);
		else
			rc = lod_xattr_set_lmv(env, dt, &info->lti_buf,
					       XATTR_NAME_LMV, 0, th);
		if (rc != 0)
			RETURN(rc);
	}

	/* Transfer default LMV striping from the parent */
	if (lo->ldo_dir_def_striping_set &&
	    !LMVEA_DELETE_VALUES(lo->ldo_dir_def_stripenr,
				 lo->ldo_dir_def_stripe_offset)) {
		struct lmv_user_md_v1 *v1 = info->lti_ea_store;
		int def_stripe_count = lo->ldo_dir_def_stripenr;

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
	if (lo->ldo_def_striping_set &&
	    !LOVEA_DELETE_VALUES(lo->ldo_def_stripe_size,
				 lo->ldo_def_stripenr,
				 lo->ldo_def_stripe_offset,
				 lo->ldo_pool)) {
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
		if (lo->ldo_pool != NULL)
			strlcpy(v3->lmm_pool_name, lo->ldo_pool,
				sizeof(v3->lmm_pool_name));

		info->lti_buf.lb_buf = v3;
		info->lti_buf.lb_len = sizeof(*v3);

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
	struct lod_object *lo = lod_dt_obj(dt);
	int rc;

	rc = lod_dir_striping_create_internal(env, dt, attr, dof, th, false);
	if (rc == 0)
		lo->ldo_striping_cached = 1;

	return rc;
}

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
	struct dt_object	*next = dt_object_child(dt);
	int			 rc;
	ENTRY;

	if (S_ISDIR(dt->do_lu.lo_header->loh_attr) &&
	    strcmp(name, XATTR_NAME_LMV) == 0) {
		struct lmv_mds_md_v1 *lmm = buf->lb_buf;

		if (lmm != NULL && le32_to_cpu(lmm->lmv_hash_type) &
						LMV_HASH_FLAG_MIGRATION)
			rc = lod_sub_object_xattr_set(env, next, buf, name, fl,
						      th);
		else
			rc = lod_dir_striping_create(env, dt, NULL, NULL, th);

		RETURN(rc);
	}

	if (S_ISDIR(dt->do_lu.lo_header->loh_attr) &&
	    strcmp(name, XATTR_NAME_LOV) == 0) {
		/* default LOVEA */
		rc = lod_xattr_set_lov_on_dir(env, dt, buf, name, fl, th);
		RETURN(rc);
	} else if (S_ISDIR(dt->do_lu.lo_header->loh_attr) &&
		   strcmp(name, XATTR_NAME_DEFAULT_LMV) == 0) {
		/* default LMVEA */
		rc = lod_xattr_set_default_lmv_on_dir(env, dt, buf, name, fl,
						      th);
		RETURN(rc);
	} else if (S_ISREG(dt->do_lu.lo_header->loh_attr) &&
		   !strcmp(name, XATTR_NAME_LOV)) {
		/* in case of lov EA swap, just set it
		 * if not, it is a replay so check striping match what we
		 * already have during req replay, declare_xattr_set()
		 * defines striping, then create() does the work */
		if (fl & LU_XATTR_REPLACE) {
			/* free stripes, then update disk */
			lod_object_free_striping(env, lod_dt_obj(dt));

			rc = lod_sub_object_xattr_set(env, next, buf, name,
						      fl, th);
		} else if (dt_object_remote(dt)) {
			/* This only happens during migration, see
			 * mdd_migrate_create(), in which Master MDT will
			 * create a remote target object, and only set
			 * (migrating) stripe EA on the remote object,
			 * and does not need creating each stripes. */
			rc = lod_sub_object_xattr_set(env, next, buf, name,
						      fl, th);
		} else {
			rc = lod_striping_create(env, dt, NULL, NULL, th);
		}
		RETURN(rc);
	} else if (strcmp(name, XATTR_NAME_FID) == 0) {
		rc = lod_object_replace_parent_fid(env, dt, th, false);

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
	struct lod_object	*lo = lod_dt_obj(dt);
	int			rc;
	int			i;
	ENTRY;

	rc = lod_sub_object_declare_xattr_del(env, dt_object_child(dt),
					      name, th);
	if (rc != 0)
		RETURN(rc);

	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(0);

	/* set xattr to each stripes, if needed */
	rc = lod_load_striping(env, lo);
	if (rc != 0)
		RETURN(rc);

	if (lo->ldo_stripenr == 0)
		RETURN(0);

	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);
		rc = lod_sub_object_declare_xattr_del(env, lo->ldo_stripe[i],
						      name, th);
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
	struct dt_object	*next = dt_object_child(dt);
	struct lod_object	*lo = lod_dt_obj(dt);
	int			rc;
	int			i;
	ENTRY;

	if (!strcmp(name, XATTR_NAME_LOV))
		lod_object_free_striping(env, lod_dt_obj(dt));

	rc = lod_sub_object_xattr_del(env, next, name, th);
	if (rc != 0 || !S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(rc);

	if (lo->ldo_stripenr == 0)
		RETURN(0);

	for (i = 0; i < lo->ldo_stripenr; i++) {
		LASSERT(lo->ldo_stripe[i]);

		rc = lod_sub_object_xattr_del(env, lo->ldo_stripe[i], name, th);
		if (rc != 0)
			break;
	}

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

/**
 * Initialize a pool the object belongs to.
 *
 * When a striped object is being created, striping configuration
 * may demand the stripes are allocated on a limited set of the
 * targets. These limited sets are known as "pools". So we copy
 * a pool name into the object and later actual creation methods
 * (like lod_object_create()) will use this information to allocate
 * the stripes properly.
 *
 * \param[in] o		object
 * \param[in] pool	pool name
 */
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


/**
 * Cache default regular striping in the object.
 *
 * To improve performance of striped regular object creation we cache
 * default LOV striping (if it exists) in the parent directory object.
 *
 * \param[in] env		execution environment
 * \param[in] lp		object
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
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

	if (rc < (typeof(rc))sizeof(struct lov_user_md)) {
		/* don't lookup for non-existing or invalid striping */
		lp->ldo_def_striping_set = 0;
		lp->ldo_def_striping_cached = 1;
		lp->ldo_def_stripe_size = 0;
		lp->ldo_def_stripenr = 0;
		lp->ldo_def_stripe_offset = (typeof(v1->lmm_stripe_offset))(-1);
		GOTO(unlock, rc = 0);
	}

	rc = 0;
	v1 = info->lti_ea_store;
	if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_V1)) {
		lustre_swab_lov_user_md_v1(v1);
	} else if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_V3)) {
		v3 = (struct lov_user_md_v3 *)v1;
		lustre_swab_lov_user_md_v3(v3);
	}

	if (v1->lmm_magic != LOV_MAGIC_V3 && v1->lmm_magic != LOV_MAGIC_V1)
		GOTO(unlock, rc = 0);

	if (v1->lmm_pattern != LOV_PATTERN_RAID0 && v1->lmm_pattern != 0)
		GOTO(unlock, rc = 0);

	CDEBUG(D_INFO, DFID" stripe_count=%d stripe_size=%d stripe_offset=%d\n",
	       PFID(lu_object_fid(&lp->ldo_obj.do_lu)),
	       (int)v1->lmm_stripe_count,
	       (int)v1->lmm_stripe_size, (int)v1->lmm_stripe_offset);

	lp->ldo_def_stripenr = v1->lmm_stripe_count;
	lp->ldo_def_stripe_size = v1->lmm_stripe_size;
	lp->ldo_def_stripe_offset = v1->lmm_stripe_offset;
	lp->ldo_def_striping_cached = 1;
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


/**
 * Cache default directory striping in the object.
 *
 * To improve performance of striped directory creation we cache default
 * directory striping (if it exists) in the parent directory object.
 *
 * \param[in] env		execution environment
 * \param[in] lp		object
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
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

	if (rc < (typeof(rc))sizeof(struct lmv_user_md)) {
		/* don't lookup for non-existing or invalid striping */
		lp->ldo_dir_def_striping_set = 0;
		lp->ldo_dir_def_striping_cached = 1;
		lp->ldo_dir_def_stripenr = 0;
		lp->ldo_dir_def_stripe_offset =
					(typeof(v1->lum_stripe_offset))(-1);
		lp->ldo_dir_def_hash_type = LMV_HASH_TYPE_FNV_1A_64;
		GOTO(unlock, rc = 0);
	}

	rc = 0;
	v1 = info->lti_ea_store;

	lp->ldo_dir_def_stripenr = le32_to_cpu(v1->lum_stripe_count);
	lp->ldo_dir_def_stripe_offset = le32_to_cpu(v1->lum_stripe_offset);
	lp->ldo_dir_def_hash_type = le32_to_cpu(v1->lum_hash_type);
	lp->ldo_dir_def_striping_set = 1;
	lp->ldo_dir_def_striping_cached = 1;

	EXIT;
unlock:
	dt_write_unlock(env, dt_object_child(&lp->ldo_obj));
	return rc;
}

/**
 * Cache default striping in the object.
 *
 * To improve performance of striped object creation we cache default striping
 * (if it exists) in the parent directory object. We always cache default
 * striping for the regular files (stored in LOV EA) and we cache default
 * striping for the directories if requested by \a child_mode (when a new
 * directory is being created).
 *
 * \param[in] env		execution environment
 * \param[in] lp		object
 * \param[in] child_mode	new object's mode
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_cache_parent_striping(const struct lu_env *env,
				     struct lod_object *lp,
				     umode_t child_mode)
{
	int rc = 0;
	ENTRY;

	if (!lp->ldo_def_striping_cached) {
		/* we haven't tried to get default striping for
		 * the directory yet, let's cache it in the object */
		rc = lod_cache_parent_lov_striping(env, lp);
		if (rc != 0)
			RETURN(rc);
	}

	/* If the parent is on the remote MDT, we should always
	 * try to refresh the default stripeEA cache, because we
	 * do not cache default striping information for remote
	 * object. */
	if (S_ISDIR(child_mode) && (!lp->ldo_dir_def_striping_cached ||
				    dt_object_remote(&lp->ldo_obj)))
		rc = lod_cache_parent_lmv_striping(env, lp);

	RETURN(rc);
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
	struct dt_object  *nextp = NULL;
	struct dt_object  *nextc;
	struct lod_object *lp = NULL;
	struct lod_object *lc;
	struct lov_desc   *desc;
	int		  rc;
	ENTRY;

	LASSERT(child);

	if (likely(parent)) {
		nextp = dt_object_child(parent);
		lp = lod_dt_obj(parent);
		rc = lod_load_striping(env, lp);
		if (rc != 0)
			return;
	}

	nextc = dt_object_child(child);
	lc = lod_dt_obj(child);

	LASSERT(lc->ldo_stripenr == 0);
	LASSERT(lc->ldo_stripe == NULL);

	if (!dt_object_exists(nextc))
		nextc->do_ops->do_ah_init(env, ah, nextp, nextc, child_mode);

	if (S_ISDIR(child_mode)) {
		if (lc->ldo_dir_stripe == NULL) {
			OBD_ALLOC_PTR(lc->ldo_dir_stripe);
			if (lc->ldo_dir_stripe == NULL)
				return;
		}

		LASSERT(lp != NULL);
		if (lp->ldo_dir_stripe == NULL) {
			OBD_ALLOC_PTR(lp->ldo_dir_stripe);
			if (lp->ldo_dir_stripe == NULL)
				return;
		}

		rc = lod_cache_parent_striping(env, lp, child_mode);
		if (rc != 0)
			return;

		/* transfer defaults to new directory */
		if (lp->ldo_def_striping_set) {
			if (lp->ldo_pool)
				lod_object_set_pool(lc, lp->ldo_pool);
			lc->ldo_def_stripenr = lp->ldo_def_stripenr;
			lc->ldo_def_stripe_size = lp->ldo_def_stripe_size;
			lc->ldo_def_stripe_offset = lp->ldo_def_stripe_offset;
			lc->ldo_def_striping_set = 1;
			lc->ldo_def_striping_cached = 1;
			CDEBUG(D_OTHER, "inherite EA sz:%d off:%d nr:%d\n",
			       (int)lc->ldo_def_stripe_size,
			       (int)lc->ldo_def_stripe_offset,
			       (int)lc->ldo_def_stripenr);
		}

		/* transfer dir defaults to new directory */
		if (lp->ldo_dir_def_striping_set) {
			lc->ldo_dir_def_stripenr = lp->ldo_dir_def_stripenr;
			lc->ldo_dir_def_stripe_offset =
						  lp->ldo_dir_def_stripe_offset;
			lc->ldo_dir_def_hash_type =
						  lp->ldo_dir_def_hash_type;
			lc->ldo_dir_def_striping_set = 1;
			lc->ldo_dir_def_striping_cached = 1;
			CDEBUG(D_INFO, "inherit default EA nr:%d off:%d t%u\n",
			       (int)lc->ldo_dir_def_stripenr,
			       (int)lc->ldo_dir_def_stripe_offset,
			       lc->ldo_dir_def_hash_type);
		}

		/* It should always honour the specified stripes */
		if (ah->dah_eadata != NULL && ah->dah_eadata_len != 0) {
			const struct lmv_user_md_v1 *lum1 = ah->dah_eadata;

			rc = lod_verify_md_striping(d, lum1);
			if (rc == 0 &&
				le32_to_cpu(lum1->lum_stripe_count) > 1) {
				lc->ldo_stripenr =
					le32_to_cpu(lum1->lum_stripe_count);
				lc->ldo_dir_stripe_offset =
					le32_to_cpu(lum1->lum_stripe_offset);
				lc->ldo_dir_hash_type =
					le32_to_cpu(lum1->lum_hash_type);
				CDEBUG(D_INFO, "set stripe EA nr:%hu off:%d\n",
				       lc->ldo_stripenr,
				       (int)lc->ldo_dir_stripe_offset);
			}
		/* then check whether there is default stripes from parent */
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

		/* shrink the stripe_count to the avaible MDT count */
		if (lc->ldo_stripenr > d->lod_remote_mdt_count + 1 &&
		    !OBD_FAIL_CHECK(OBD_FAIL_LARGE_STRIPE))
			lc->ldo_stripenr = d->lod_remote_mdt_count + 1;

		/* Directory will be striped only if stripe_count > 1, if
		 * stripe_count == 1, let's reset stripenr = 0 to avoid
		 * create single master stripe and also help to unify the
		 * stripe handling of directories and files */
		if (lc->ldo_stripenr == 1)
			lc->ldo_stripenr = 0;

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

		lc->ldo_def_stripe_offset = LOV_OFFSET_DEFAULT;

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
	struct dt_object   *next = dt_object_child(dt);
	struct lod_object  *lo = lod_dt_obj(dt);
	struct lu_attr	   *attr = &lod_env_info(env)->lti_attr;
	uint64_t	    size, offs;
	int		    rc, stripe;
	ENTRY;

	/* XXX: we support the simplest (RAID0) striping so far */
	LASSERT(lo->ldo_stripe || lo->ldo_stripenr == 0);
	LASSERT(lo->ldo_stripe_size > 0);

	if (lo->ldo_stripenr == 0)
		RETURN(0);

	rc = dt_attr_get(env, next, attr);
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

	rc = lod_sub_object_declare_attr_set(env, lo->ldo_stripe[stripe], attr,
					     th);

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

	if (!dt_object_remote(next)) {
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
	} else {
		/* LOD can not choose OST objects for remote objects, i.e.
		 * stripes must be ready before that. Right now, it can only
		 * happen during migrate, i.e. migrate process needs to create
		 * remote regular file (mdd_migrate_create), then the migrate
		 * process will provide stripeEA. */
		LASSERT(lovea != NULL);
		info->lti_buf = *lovea;
	}

	rc = lod_sub_object_declare_xattr_set(env, next, &info->lti_buf,
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
	RETURN(rc);
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
	rc = lod_sub_object_declare_create(env, next, attr, hint, dof, th);
	if (rc != 0)
		GOTO(out, rc);

	if (dof->dof_type == DFT_SYM)
		dt->do_body_ops = &lod_body_lnk_ops;
	else if (dof->dof_type == DFT_REGULAR)
		dt->do_body_ops = &lod_body_ops;

	/*
	 * it's lod_ah_init() that has decided the object will be striped
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
		struct seq_server_site *ss;

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

			if (lo->ldo_dir_stripe_offset == -1) {
				/* child and parent should be in the same MDT */
				if (hint->dah_parent != NULL &&
				    dt_object_remote(hint->dah_parent))
					GOTO(out, rc = -EREMOTE);
			} else if (lo->ldo_dir_stripe_offset !=
				   ss->ss_node_id) {
				struct lod_device *lod;
				struct lod_tgt_descs *ltd;
				struct lod_tgt_desc *tgt = NULL;
				bool found_mdt = false;
				int i;

				lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
				ltd = &lod->lod_mdt_descs;
				cfs_foreach_bit(ltd->ltd_tgt_bitmap, i) {
					tgt = LTD_TGT(ltd, i);
					if (tgt->ltd_index ==
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
		}

		/* Orphan object (like migrating object) does not have
		 * lod_dir_stripe, see lod_ah_init */
		if (lo->ldo_dir_stripe != NULL)
			rc = lod_declare_dir_striping_create(env, dt, attr,
							     dof, th);
	}
out:
	RETURN(rc);
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
		rc = lod_sub_object_create(env, lo->ldo_stripe[i], attr, NULL,
					   dof, th);
		if (rc)
			break;
	}

	if (rc == 0) {
		rc = lod_generate_and_set_lovea(env, lo, th);
		if (rc == 0)
			lo->ldo_striping_cached = 1;
	}

	RETURN(rc);
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
static int lod_object_create(const struct lu_env *env, struct dt_object *dt,
			     struct lu_attr *attr,
			     struct dt_allocation_hint *hint,
			     struct dt_object_format *dof, struct thandle *th)
{
	struct lod_object  *lo = lod_dt_obj(dt);
	int		    rc;
	ENTRY;

	/* create local object */
	rc = lod_sub_object_create(env, dt_object_child(dt), attr, hint, dof,
				   th);
	if (rc != 0)
		RETURN(rc);

	if (S_ISREG(dt->do_lu.lo_header->loh_attr) &&
	    lo->ldo_stripe && dof->u.dof_reg.striped != 0)
		rc = lod_striping_create(env, dt, attr, dof, th);

	RETURN(rc);
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
static int lod_declare_object_destroy(const struct lu_env *env,
				      struct dt_object *dt,
				      struct thandle *th)
{
	struct dt_object   *next = dt_object_child(dt);
	struct lod_object  *lo = lod_dt_obj(dt);
	struct lod_thread_info *info = lod_env_info(env);
	char		   *stripe_name = info->lti_key;
	int		    rc, i;
	ENTRY;

	/*
	 * load striping information, notice we don't do this when object
	 * is being initialized as we don't need this information till
	 * few specific cases like destroy, chown
	 */
	rc = lod_load_striping(env, lo);
	if (rc)
		RETURN(rc);

	/* declare destroy for all underlying objects */
	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		rc = next->do_ops->do_index_try(env, next,
						&dt_directory_features);
		if (rc != 0)
			RETURN(rc);

		for (i = 0; i < lo->ldo_stripenr; i++) {
			rc = lod_sub_object_declare_ref_del(env, next, th);
			if (rc != 0)
				RETURN(rc);

			snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
				PFID(lu_object_fid(&lo->ldo_stripe[i]->do_lu)),
				i);
			rc = lod_sub_object_declare_delete(env, next,
					(const struct dt_key *)stripe_name, th);
			if (rc != 0)
				RETURN(rc);
		}
	}

	/*
	 * we declare destroy for the local object
	 */
	rc = lod_sub_object_declare_destroy(env, next, th);
	if (rc)
		RETURN(rc);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_MDTOBJ))
		RETURN(0);

	/* declare destroy all striped objects */
	for (i = 0; i < lo->ldo_stripenr; i++) {
		if (lo->ldo_stripe[i] == NULL)
			continue;

		if (S_ISDIR(dt->do_lu.lo_header->loh_attr))
			rc = lod_sub_object_declare_ref_del(env,
					lo->ldo_stripe[i], th);

		rc = lod_sub_object_declare_destroy(env, lo->ldo_stripe[i],
					th);
		if (rc != 0)
			break;
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
static int lod_object_destroy(const struct lu_env *env,
		struct dt_object *dt, struct thandle *th)
{
	struct dt_object  *next = dt_object_child(dt);
	struct lod_object *lo = lod_dt_obj(dt);
	struct lod_thread_info *info = lod_env_info(env);
	char		   *stripe_name = info->lti_key;
	unsigned int       i;
	int                rc;
	ENTRY;

	/* destroy sub-stripe of master object */
	if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
		rc = next->do_ops->do_index_try(env, next,
						&dt_directory_features);
		if (rc != 0)
			RETURN(rc);

		for (i = 0; i < lo->ldo_stripenr; i++) {
			rc = lod_sub_object_ref_del(env, next, th);
			if (rc != 0)
				RETURN(rc);

			snprintf(stripe_name, sizeof(info->lti_key), DFID":%d",
				PFID(lu_object_fid(&lo->ldo_stripe[i]->do_lu)),
				i);

			CDEBUG(D_INFO, DFID" delete stripe %s "DFID"\n",
			       PFID(lu_object_fid(&dt->do_lu)), stripe_name,
			       PFID(lu_object_fid(&lo->ldo_stripe[i]->do_lu)));

			rc = lod_sub_object_delete(env, next,
				       (const struct dt_key *)stripe_name, th);
			if (rc != 0)
				RETURN(rc);
		}
	}

	rc = lod_sub_object_destroy(env, next, th);
	if (rc != 0)
		RETURN(rc);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_MDTOBJ))
		RETURN(0);

	/* destroy all striped objects */
	for (i = 0; i < lo->ldo_stripenr; i++) {
		if (likely(lo->ldo_stripe[i] != NULL) &&
		    (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_LOST_SPEOBJ) ||
		     i == cfs_fail_val)) {
			if (S_ISDIR(dt->do_lu.lo_header->loh_attr)) {
				dt_write_lock(env, lo->ldo_stripe[i],
					      MOR_TGT_CHILD);
				rc = lod_sub_object_ref_del(env,
						lo->ldo_stripe[i], th);
				dt_write_unlock(env, lo->ldo_stripe[i]);
				if (rc != 0)
					break;
			}

			rc = lod_sub_object_destroy(env, lo->ldo_stripe[i], th);
			if (rc != 0)
				break;
		}
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
	return lod_sub_object_declare_ref_add(env, dt_object_child(dt), th);
}

/**
 * Implementation of dt_object_operations::do_ref_add.
 *
 * \see dt_object_operations::do_ref_add() in the API description for details.
 */
static int lod_ref_add(const struct lu_env *env,
		       struct dt_object *dt, struct thandle *th)
{
	return lod_sub_object_ref_add(env, dt_object_child(dt), th);
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
	return lod_sub_object_declare_ref_del(env, dt_object_child(dt), th);
}

/**
 * Implementation of dt_object_operations::do_ref_del
 *
 * \see dt_object_operations::do_ref_del() in the API description for details.
 */
static int lod_ref_del(const struct lu_env *env,
		       struct dt_object *dt, struct thandle *th)
{
	return lod_sub_object_ref_del(env, dt_object_child(dt), th);
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
 * Release LDLM locks on the stripes of a striped directory.
 *
 * Iterates over all the locks taken on the stripe objects and
 * release them using ->do_object_unlock() method.
 *
 * \param[in] env	execution environment
 * \param[in] dt	striped object
 * \param[in] einfo	lock description
 * \param[in] policy	data describing requested lock
 *
 * \retval		0 on success
 * \retval		negative if failed
 */
static int lod_object_unlock_internal(const struct lu_env *env,
				      struct dt_object *dt,
				      struct ldlm_enqueue_info *einfo,
				      union ldlm_policy_data *policy)
{
	struct lustre_handle_array *slave_locks = einfo->ei_cbdata;
	int			rc = 0;
	int			i;
	ENTRY;

	if (slave_locks == NULL)
		RETURN(0);

	for (i = 1; i < slave_locks->count; i++) {
		if (lustre_handle_is_used(&slave_locks->handles[i]))
			ldlm_lock_decref(&slave_locks->handles[i],
					 einfo->ei_mode);
	}

	RETURN(rc);
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
	LASSERT(lo->ldo_stripenr > 1);
	/* Note: for remote lock for single stripe dir, MDT will cancel
	 * the lock by lockh directly */
	LASSERT(!dt_object_remote(dt_object_child(dt)));

	/* locks were unlocked in MDT layer */
	for (i = 1; i < slave_locks->count; i++)
		LASSERT(!lustre_handle_is_used(&slave_locks->handles[i]));

	slave_locks_size = sizeof(*slave_locks) + slave_locks->count *
			   sizeof(slave_locks->handles[0]);
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
	struct lod_object	*lo = lod_dt_obj(dt);
	int			rc = 0;
	int			i;
	int			slave_locks_size;
	struct lustre_handle_array *slave_locks = NULL;
	ENTRY;

	/* remote object lock */
	if (!einfo->ei_enq_slave) {
		LASSERT(dt_object_remote(dt));
		return dt_object_lock(env, dt_object_child(dt), lh, einfo,
				      policy);
	}

	if (!S_ISDIR(dt->do_lu.lo_header->loh_attr))
		RETURN(-ENOTDIR);

	rc = lod_load_striping(env, lo);
	if (rc != 0)
		RETURN(rc);

	/* No stripes */
	if (lo->ldo_stripenr <= 1)
		RETURN(0);

	slave_locks_size = sizeof(*slave_locks) + lo->ldo_stripenr *
			   sizeof(slave_locks->handles[0]);
	/* Freed in lod_object_unlock */
	OBD_ALLOC(slave_locks, slave_locks_size);
	if (slave_locks == NULL)
		RETURN(-ENOMEM);
	slave_locks->count = lo->ldo_stripenr;

	/* striped directory lock */
	for (i = 1; i < lo->ldo_stripenr; i++) {
		struct lustre_handle	lockh;
		struct ldlm_res_id	*res_id;

		res_id = &lod_env_info(env)->lti_res_id;
		fid_build_reg_res_name(lu_object_fid(&lo->ldo_stripe[i]->do_lu),
				       res_id);
		einfo->ei_res_id = res_id;

		LASSERT(lo->ldo_stripe[i] != NULL);
		if (likely(dt_object_remote(lo->ldo_stripe[i]))) {
			rc = dt_object_lock(env, lo->ldo_stripe[i], &lockh,
					    einfo, policy);
		} else {
			struct ldlm_namespace *ns = einfo->ei_namespace;
			ldlm_blocking_callback blocking = einfo->ei_cb_local_bl;
			ldlm_completion_callback completion = einfo->ei_cb_cp;
			__u64	dlmflags = LDLM_FL_ATOMIC_CB;

			if (einfo->ei_mode == LCK_PW ||
			    einfo->ei_mode == LCK_EX)
				dlmflags |= LDLM_FL_COS_INCOMPAT;

			/* This only happens if there are mulitple stripes
			 * on the master MDT, i.e. except stripe0, there are
			 * other stripes on the Master MDT as well, Only
			 * happens in the test case right now. */
			LASSERT(ns != NULL);
			rc = ldlm_cli_enqueue_local(ns, res_id, LDLM_IBITS,
						    policy, einfo->ei_mode,
						    &dlmflags, blocking,
						    completion, NULL,
						    NULL, 0, LVB_T_NONE,
						    NULL, &lockh);
		}
		if (rc != 0)
			GOTO(out, rc);
		slave_locks->handles[i] = lockh;
	}

	einfo->ei_cbdata = slave_locks;

out:
	if (rc != 0 && slave_locks != NULL) {
		einfo->ei_cbdata = slave_locks;
		lod_object_unlock_internal(env, dt, einfo, policy);
		OBD_FREE(slave_locks, slave_locks_size);
		einfo->ei_cbdata = NULL;
	}

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
	.do_object_sync		= lod_object_sync,
	.do_object_lock		= lod_object_lock,
	.do_object_unlock	= lod_object_unlock,
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
	return lod_sub_object_declare_write(env, dt_object_child(dt), buf, pos,
					    th);
}

/**
 * Implementation of dt_body_operations::dbo_write.
 *
 * \see dt_body_operations::dbo_write() in the API description for details.
 */
static ssize_t lod_write(const struct lu_env *env, struct dt_object *dt,
			 const struct lu_buf *buf, loff_t *pos,
			 struct thandle *th, int iq)
{
	return lod_sub_object_write(env, dt_object_child(dt), buf, pos, th, iq);
}

static int lod_declare_punch(const struct lu_env *env, struct dt_object *dt,
			     __u64 start, __u64 end, struct thandle *th)
{
	if (dt_object_remote(dt))
		return -ENOTSUPP;

	return lod_sub_object_declare_punch(env, dt_object_child(dt), start,
					    end, th);
}

static int lod_punch(const struct lu_env *env, struct dt_object *dt,
		     __u64 start, __u64 end, struct thandle *th)
{
	if (dt_object_remote(dt))
		return -ENOTSUPP;

	return lod_sub_object_punch(env, dt_object_child(dt), start, end, th);
}

static const struct dt_body_operations lod_body_lnk_ops = {
	.dbo_read		= lod_read,
	.dbo_declare_write	= lod_declare_write,
	.dbo_write		= lod_write
};

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
	if (rc != 0) {
		/* Note: Sometimes, it will Return EAGAIN here, see
		 * ptrlpc_import_delay_req(), which might confuse
		 * lu_object_find_at() and make it wait there incorrectly.
		 * so we convert it to EIO here.*/
		if (rc == -EAGAIN)
			rc = -EIO;

		RETURN(rc);
	}

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
		    cfs_bitmap_check(ltd->ltd_tgt_bitmap, idx)) {
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

	lu_object_add(lo, cobj);

	RETURN(0);
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
	lo->ldo_striping_cached = 0;
	lo->ldo_stripenr = 0;
	lo->ldo_pattern = 0;
}

/**
 * Implementation of lu_object_operations::loo_object_start.
 *
 * \see lu_object_operations::loo_object_start() in the API description
 * for details.
 */
static int lod_object_start(const struct lu_env *env, struct lu_object *o)
{
	if (S_ISLNK(o->lo_header->loh_attr & S_IFMT)) {
		lu2lod_obj(o)->ldo_obj.do_body_ops = &lod_body_lnk_ops;
	} else if (S_ISREG(o->lo_header->loh_attr & S_IFMT) ||
		   fid_is_local_file(lu_object_fid(o))) {
		/* Note: some local file (like last rcvd) is created
		 * through bottom layer (OSD), so the object initialization
		 * comes to lod, it does not set loh_attr yet, so
		 * set do_body_ops for local file anyway */
		lu2lod_obj(o)->ldo_obj.do_body_ops = &lod_body_ops;
	}
	return 0;
}

/**
 * Implementation of lu_object_operations::loo_object_free.
 *
 * \see lu_object_operations::loo_object_free() in the API description
 * for details.
 */
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

struct lu_object_operations lod_lu_obj_ops = {
	.loo_object_init	= lod_object_init,
	.loo_object_start	= lod_object_start,
	.loo_object_free	= lod_object_free,
	.loo_object_release	= lod_object_release,
	.loo_object_print	= lod_object_print,
};
