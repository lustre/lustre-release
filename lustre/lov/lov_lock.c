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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_lock for LOV layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include "lov_cl_internal.h"

/** \addtogroup lov
 *  @{
 */

/*****************************************************************************
 *
 * Lov lock operations.
 *
 */

static struct lov_sublock_env *lov_sublock_env_get(const struct lu_env *env,
						   const struct cl_lock *parent,
						   struct lov_lock_sub *lls)
{
	struct lov_sublock_env *subenv;
	struct lov_io          *lio    = lov_env_io(env);
	struct cl_io           *io     = lio->lis_cl.cis_io;
	struct lov_io_sub      *sub;

	subenv = &lov_env_session(env)->ls_subenv;

	/*
	 * FIXME: We tend to use the subio's env & io to call the sublock
	 * lock operations because osc lock sometimes stores some control
	 * variables in thread's IO infomation(Now only lockless information).
	 * However, if the lock's host(object) is different from the object
	 * for current IO, we have no way to get the subenv and subio because
	 * they are not initialized at all. As a temp fix, in this case,
	 * we still borrow the parent's env to call sublock operations.
	 */
	if (!io || !cl_object_same(io->ci_obj, parent->cll_descr.cld_obj)) {
		subenv->lse_env = env;
		subenv->lse_io = io;
	} else {
		sub = lov_sub_get(env, lio, lls->sub_index);
		if (!IS_ERR(sub)) {
			subenv->lse_env = sub->sub_env;
			subenv->lse_io  = &sub->sub_io;
		} else {
			subenv = (void *)sub;
		}
	}
	return subenv;
}

static int lov_sublock_init(const struct lu_env *env,
			    const struct cl_lock *parent,
			    struct lov_lock_sub *lls)
{
	struct lov_sublock_env *subenv;
	int result;

	ENTRY;

	subenv = lov_sublock_env_get(env, parent, lls);
	if (!IS_ERR(subenv)) {
		result = cl_lock_init(subenv->lse_env, &lls->sub_lock,
				      subenv->lse_io);
	} else {
		/* error occurs. */
		result = PTR_ERR(subenv);
	}
	RETURN(result);
}

/**
 * Creates sub-locks for a given lov_lock for the first time.
 *
 * Goes through all sub-objects of top-object, and creates sub-locks on every
 * sub-object intersecting with top-lock extent. This is complicated by the
 * fact that top-lock (that is being created) can be accessed concurrently
 * through already created sub-locks (possibly shared with other top-locks).
 */
static struct lov_lock *lov_lock_sub_init(const struct lu_env *env,
					  const struct cl_io *io,
					  const struct cl_object *obj,
					  struct cl_lock *lock)
{
	struct lov_object *lov = cl2lov(obj);
	struct lov_lock *lovlck;
	struct lu_extent ext;
	loff_t start;
	loff_t end;
	int result = 0;
	int i;
	int index;
	int nr;

	ENTRY;

	ext.e_start = cl_offset(obj, lock->cll_descr.cld_start);
	if (lock->cll_descr.cld_end == CL_PAGE_EOF)
		ext.e_end = OBD_OBJECT_EOF;
	else
		ext.e_end  = cl_offset(obj, lock->cll_descr.cld_end + 1);

	nr = 0;
	lov_foreach_io_layout(index, lov_env_io(env), &ext) {
		struct lov_layout_raid0 *r0 = lov_r0(lov, index);

		for (i = 0; i < r0->lo_nr; i++) {
			if (likely(r0->lo_sub[i])) {/* spare layout */
				if (lov_stripe_intersects(lov->lo_lsm, index, i,
							  &ext, &start, &end))
					nr++;
				else if (cl_io_is_trunc(io) &&
					 r0->lo_trunc_stripeno == i)
					nr++;
			}
		}
	}
	/**
	 * Aggressive lock request (from cl_setattr_ost) which asks for
	 * [eof, -1) lock, could come across uninstantiated layout extent,
	 * hence a 0 nr is possible.
	 */

	OBD_ALLOC_LARGE(lovlck, offsetof(struct lov_lock, lls_sub[nr]));
	if (!lovlck)
		RETURN(ERR_PTR(-ENOMEM));

	lovlck->lls_nr = nr;
	nr = 0;
	lov_foreach_io_layout(index, lov_env_io(env), &ext) {
		struct lov_layout_raid0 *r0 = lov_r0(lov, index);

		for (i = 0; i < r0->lo_nr; ++i) {
			struct lov_lock_sub *lls = &lovlck->lls_sub[nr];
			struct cl_lock_descr *descr = &lls->sub_lock.cll_descr;
			bool intersect = false;

			if (unlikely(!r0->lo_sub[i]))
				continue;

			intersect = lov_stripe_intersects(lov->lo_lsm, index, i,
							  &ext, &start, &end);
			if (intersect)
				goto init_sublock;

			if (cl_io_is_trunc(io) && i == r0->lo_trunc_stripeno)
				goto init_sublock;

			continue;

init_sublock:
			LASSERT(descr->cld_obj == NULL);
			descr->cld_obj   = lovsub2cl(r0->lo_sub[i]);
			descr->cld_start = cl_index(descr->cld_obj, start);
			descr->cld_end   = cl_index(descr->cld_obj, end);
			descr->cld_mode  = lock->cll_descr.cld_mode;
			descr->cld_gid   = lock->cll_descr.cld_gid;
			descr->cld_enq_flags = lock->cll_descr.cld_enq_flags;

			lls->sub_index = lov_comp_index(index, i);

			/* initialize sub lock */
			result = lov_sublock_init(env, lock, lls);
			if (result < 0)
				break;

			lls->sub_initialized = 1;
			nr++;
		}
		if (result < 0)
			break;
	}
	LASSERT(ergo(result == 0, nr == lovlck->lls_nr));

	if (result != 0) {
		for (i = 0; i < nr; ++i) {
			if (!lovlck->lls_sub[i].sub_initialized)
				break;

			cl_lock_fini(env, &lovlck->lls_sub[i].sub_lock);
		}

		OBD_FREE_LARGE(lovlck,
				offsetof(struct lov_lock, lls_sub[nr]));
		lovlck = ERR_PTR(result);
	}

	RETURN(lovlck);
}

static void lov_lock_fini(const struct lu_env *env,
                          struct cl_lock_slice *slice)
{
	struct lov_lock *lovlck;
	int i;

	ENTRY;
	lovlck = cl2lov_lock(slice);
	for (i = 0; i < lovlck->lls_nr; ++i) {
		LASSERT(!lovlck->lls_sub[i].sub_is_enqueued);
		if (lovlck->lls_sub[i].sub_initialized)
			cl_lock_fini(env, &lovlck->lls_sub[i].sub_lock);
	}
	OBD_FREE_LARGE(lovlck,
		       offsetof(struct lov_lock, lls_sub[lovlck->lls_nr]));
	EXIT;
}

/**
 * Implementation of cl_lock_operations::clo_enqueue() for lov layer. This
 * function is rather subtle, as it enqueues top-lock (i.e., advances top-lock
 * state machine from CLS_QUEUING to CLS_ENQUEUED states) by juggling sub-lock
 * state machines in the face of sub-locks sharing (by multiple top-locks),
 * and concurrent sub-lock cancellations.
 */
static int lov_lock_enqueue(const struct lu_env *env,
			    const struct cl_lock_slice *slice,
			    struct cl_io *io, struct cl_sync_io *anchor)
{
	struct cl_lock *lock = slice->cls_lock;
	struct lov_lock *lovlck = cl2lov_lock(slice);
	int i;
	int rc = 0;

	ENTRY;

	for (i = 0; i < lovlck->lls_nr; ++i) {
		struct lov_lock_sub     *lls = &lovlck->lls_sub[i];
		struct lov_sublock_env  *subenv;

		subenv = lov_sublock_env_get(env, lock, lls);
		if (IS_ERR(subenv)) {
			rc = PTR_ERR(subenv);
			break;
		}

		rc = cl_lock_enqueue(subenv->lse_env, subenv->lse_io,
				     &lls->sub_lock, anchor);
		if (rc != 0)
			break;

		lls->sub_is_enqueued = 1;
	}
	RETURN(rc);
}

static void lov_lock_cancel(const struct lu_env *env,
			    const struct cl_lock_slice *slice)
{
	struct cl_lock *lock = slice->cls_lock;
	struct lov_lock *lovlck = cl2lov_lock(slice);
	int i;

	ENTRY;

	for (i = 0; i < lovlck->lls_nr; ++i) {
		struct lov_lock_sub *lls = &lovlck->lls_sub[i];
		struct cl_lock *sublock = &lls->sub_lock;
		struct lov_sublock_env *subenv;

		if (!lls->sub_is_enqueued)
			continue;

		lls->sub_is_enqueued = 0;
		subenv = lov_sublock_env_get(env, lock, lls);
		if (!IS_ERR(subenv)) {
			cl_lock_cancel(subenv->lse_env, sublock);
		} else {
			CL_LOCK_DEBUG(D_ERROR, env, slice->cls_lock,
				      "lov_lock_cancel fails with %ld.\n",
				      PTR_ERR(subenv));
		}
	}
}

static int lov_lock_print(const struct lu_env *env, void *cookie,
			  lu_printer_t p, const struct cl_lock_slice *slice)
{
	struct lov_lock *lck = cl2lov_lock(slice);
	int i;

	(*p)(env, cookie, "%d\n", lck->lls_nr);
	for (i = 0; i < lck->lls_nr; ++i) {
		struct lov_lock_sub *sub;

		sub = &lck->lls_sub[i];
		(*p)(env, cookie, "    %d %x: ", i, sub->sub_is_enqueued);
		cl_lock_print(env, cookie, p, &sub->sub_lock);
	}
	return 0;
}

static const struct cl_lock_operations lov_lock_ops = {
	.clo_fini      = lov_lock_fini,
	.clo_enqueue   = lov_lock_enqueue,
	.clo_cancel    = lov_lock_cancel,
	.clo_print     = lov_lock_print
};

int lov_lock_init_composite(const struct lu_env *env, struct cl_object *obj,
			    struct cl_lock *lock, const struct cl_io *io)
{
	struct lov_lock *lck;
	int result = 0;

	ENTRY;
	lck = lov_lock_sub_init(env, io, obj, lock);
	if (!IS_ERR(lck))
		cl_lock_slice_add(lock, &lck->lls_cl, obj, &lov_lock_ops);
	else
		result = PTR_ERR(lck);
	RETURN(result);
}

static void lov_empty_lock_fini(const struct lu_env *env,
				struct cl_lock_slice *slice)
{
	struct lov_lock *lck = cl2lov_lock(slice);

	OBD_SLAB_FREE_PTR(lck, lov_lock_kmem);
}

static int lov_empty_lock_print(const struct lu_env *env, void *cookie,
			lu_printer_t p, const struct cl_lock_slice *slice)
{
	(*p)(env, cookie, "empty\n");
	return 0;
}

/* XXX: more methods will be added later. */
static const struct cl_lock_operations lov_empty_lock_ops = {
	.clo_fini  = lov_empty_lock_fini,
	.clo_print = lov_empty_lock_print
};

int lov_lock_init_empty(const struct lu_env *env, struct cl_object *obj,
			struct cl_lock *lock, const struct cl_io *io)
{
	struct lov_lock *lck;
	int result = -ENOMEM;

	ENTRY;
	OBD_SLAB_ALLOC_PTR_GFP(lck, lov_lock_kmem, GFP_NOFS);
	if (lck) {
		cl_lock_slice_add(lock, &lck->lls_cl, obj, &lov_empty_lock_ops);
		result = 0;
	}
	RETURN(result);
}

/** @} lov */
