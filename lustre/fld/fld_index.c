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
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/fld/fld_index.c
 *
 * Author: WangDi <wangdi@clusterfs.com>
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_FLD

#include <libcfs/libcfs.h>
#include <linux/module.h>
#include <obd_support.h>
#include <dt_object.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include "fld_internal.h"

static const char fld_index_name[] = "fld";

static const struct lu_seq_range IGIF_FLD_RANGE = {
	.lsr_start = FID_SEQ_IGIF,
	.lsr_end   = FID_SEQ_IGIF_MAX + 1,
	.lsr_index = 0,
	.lsr_flags = LU_SEQ_RANGE_MDT
};

static const struct lu_seq_range DOT_LUSTRE_FLD_RANGE = {
	.lsr_start = FID_SEQ_DOT_LUSTRE,
	.lsr_end   = FID_SEQ_DOT_LUSTRE + 1,
	.lsr_index = 0,
	.lsr_flags = LU_SEQ_RANGE_MDT
};

static const struct lu_seq_range ROOT_FLD_RANGE = {
	.lsr_start = FID_SEQ_ROOT,
	.lsr_end   = FID_SEQ_ROOT + 1,
	.lsr_index = 0,
	.lsr_flags = LU_SEQ_RANGE_MDT
};

static const struct dt_index_features fld_index_features = {
	.dif_flags       = DT_IND_UPDATE,
	.dif_keysize_min = sizeof(u64),
	.dif_keysize_max = sizeof(u64),
	.dif_recsize_min = sizeof(struct lu_seq_range),
	.dif_recsize_max = sizeof(struct lu_seq_range),
	.dif_ptrsize     = 4
};

extern struct lu_context_key fld_thread_key;

int fld_declare_index_create(const struct lu_env *env,
			     struct lu_server_fld *fld,
			     const struct lu_seq_range *new_range,
			     struct thandle *th)
{
	struct lu_seq_range *tmp;
	struct lu_seq_range *range;
	struct fld_thread_info *info;
	int rc = 0;

	ENTRY;

	info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
	range = &info->fti_lrange;
	tmp = &info->fti_irange;
	memset(range, 0, sizeof(*range));

	rc = fld_index_lookup(env, fld, new_range->lsr_start, range);
	if (rc == 0) {
		/* In case of duplicate entry, the location must be same */
		LASSERT((lu_seq_range_compare_loc(new_range, range) == 0));
		GOTO(out, rc = -EEXIST);
	}

	if (rc != -ENOENT) {
		CERROR("%s: lookup range "DRANGE" error: rc = %d\n",
			fld->lsf_name, PRANGE(range), rc);
		GOTO(out, rc);
	}

	/*
	 * Check for merge case, since the fld entry can only be increamental,
	 * so we will only check whether it can be merged from the left.
	 */
	if (new_range->lsr_start == range->lsr_end && range->lsr_end != 0 &&
	    lu_seq_range_compare_loc(new_range, range) == 0) {
		range_cpu_to_be(tmp, range);
		rc = dt_declare_delete(env, fld->lsf_obj,
				       (struct dt_key *)&tmp->lsr_start, th);
		if (rc) {
			CERROR("%s: declare record "DRANGE" failed: rc = %d\n",
			       fld->lsf_name, PRANGE(range), rc);
			GOTO(out, rc);
		}
		*tmp = *new_range;
		tmp->lsr_start = range->lsr_start;
	} else {
		*tmp = *new_range;
	}

	range_cpu_to_be(tmp, tmp);
	rc = dt_declare_insert(env, fld->lsf_obj, (struct dt_rec *)tmp,
			       (struct dt_key *)&tmp->lsr_start, th);
out:
	RETURN(rc);
}

/**
 * insert range in fld store.
 *
 *      \param  range  range to be inserted
 *      \param  th     transaction for this operation as it could compound
 *                     transaction.
 *
 *      \retval  0  success
 *      \retval  -ve error
 *
 * The whole fld index insertion is protected by seq->lss_mutex (see
 * seq_server_alloc_super), i.e. only one thread will access fldb each
 * time, so we do not need worry the fld file and cache will being
 * changed between declare and create.
 * Because the fld entry can only be increamental, so we will only check
 * whether it can be merged from the left.
 *
 * Caller must hold fld->lsf_lock
 **/
int fld_index_create(const struct lu_env *env, struct lu_server_fld *fld,
		     const struct lu_seq_range *new_range, struct thandle *th)
{
	struct lu_seq_range *range;
	struct lu_seq_range *tmp;
	struct fld_thread_info *info;
	int rc = 0;
	int deleted = 0;
	struct fld_cache_entry *flde;

	ENTRY;

	info = lu_context_key_get(&env->le_ctx, &fld_thread_key);

	LASSERT(mutex_is_locked(&fld->lsf_lock));

	range = &info->fti_lrange;
	memset(range, 0, sizeof(*range));
	tmp = &info->fti_irange;
	rc = fld_index_lookup(env, fld, new_range->lsr_start, range);
	if (rc != -ENOENT) {
		rc = rc == 0 ? -EEXIST : rc;
		GOTO(out, rc);
	}

	if (new_range->lsr_start == range->lsr_end && range->lsr_end != 0 &&
	    lu_seq_range_compare_loc(new_range, range) == 0) {
		range_cpu_to_be(tmp, range);
		rc = dt_delete(env, fld->lsf_obj,
			       (struct dt_key *)&tmp->lsr_start, th);
		if (rc != 0)
			GOTO(out, rc);
		*tmp = *new_range;
		tmp->lsr_start = range->lsr_start;
		deleted = 1;
	} else {
		*tmp = *new_range;
	}

	range_cpu_to_be(tmp, tmp);
	rc = dt_insert(env, fld->lsf_obj, (struct dt_rec *)tmp,
		       (struct dt_key *)&tmp->lsr_start, th);
	if (rc != 0) {
		CERROR("%s: insert range "DRANGE" failed: rc = %d\n",
		       fld->lsf_name, PRANGE(new_range), rc);
		GOTO(out, rc);
	}

	flde = fld_cache_entry_create(new_range);
	if (IS_ERR(flde))
		GOTO(out, rc = PTR_ERR(flde));

	write_lock(&fld->lsf_cache->fci_lock);
	if (deleted)
		fld_cache_delete_nolock(fld->lsf_cache, new_range);
	rc = fld_cache_insert_nolock(fld->lsf_cache, flde);
	write_unlock(&fld->lsf_cache->fci_lock);
	if (rc)
		OBD_FREE_PTR(flde);
out:
	RETURN(rc);
}

/**
 * lookup range for a seq passed. note here we only care about the start/end,
 * caller should handle the attached location data (flags, index).
 *
 * \param  seq     seq for lookup.
 * \param  range   result of lookup.
 *
 * \retval  0           found, \a range is the matched range;
 * \retval -ENOENT      not found, \a range is the left-side range;
 * \retval  -ve         other error;
 */
int fld_index_lookup(const struct lu_env *env, struct lu_server_fld *fld,
		     u64 seq, struct lu_seq_range *range)
{
	struct lu_seq_range *fld_rec;
	struct fld_thread_info *info;
	int rc;

	ENTRY;

	info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
	fld_rec = &info->fti_rec;

	rc = fld_cache_lookup(fld->lsf_cache, seq, fld_rec);
	if (rc == 0) {
		*range = *fld_rec;
		if (lu_seq_range_within(range, seq))
			rc = 0;
		else
			rc = -ENOENT;
	}

	CDEBUG(D_INFO, "%s: lookup seq = %#llx range : "DRANGE" rc = %d\n",
	       fld->lsf_name, seq, PRANGE(range), rc);

	RETURN(rc);
}

/**
 * insert entry in fld store.
 *
 * \param  env    relevant lu_env
 * \param  fld    fld store
 * \param  range  range to be inserted
 *
 * \retval  0  success
 * \retval  -ve error
 *
 * Caller must hold fld->lsf_lock
 **/

int fld_insert_entry(const struct lu_env *env,
		     struct lu_server_fld *fld,
		     const struct lu_seq_range *range)
{
	struct thandle *th;
	struct dt_device *dt = lu2dt_dev(fld->lsf_obj->do_lu.lo_dev);
	int rc;

	ENTRY;

	LASSERT(mutex_is_locked(&fld->lsf_lock));

	if (dt->dd_rdonly)
		RETURN(0);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = fld_declare_index_create(env, fld, range, th);
	if (rc != 0) {
		if (rc == -EEXIST)
			rc = 0;
		GOTO(out, rc);
	}

	rc = dt_trans_start_local(env, dt, th);
	if (rc)
		GOTO(out, rc);

	rc = fld_index_create(env, fld, range, th);
	if (rc == -EEXIST)
		rc = 0;
out:
	dt_trans_stop(env, dt, th);
	RETURN(rc);
}
EXPORT_SYMBOL(fld_insert_entry);

static int fld_insert_special_entries(const struct lu_env *env,
				      struct lu_server_fld *fld)
{
	int rc;

	rc = fld_insert_entry(env, fld, &IGIF_FLD_RANGE);
	if (rc != 0)
		RETURN(rc);

	rc = fld_insert_entry(env, fld, &DOT_LUSTRE_FLD_RANGE);
	if (rc != 0)
		RETURN(rc);

	rc = fld_insert_entry(env, fld, &ROOT_FLD_RANGE);

	RETURN(rc);
}

int fld_index_init(const struct lu_env *env, struct lu_server_fld *fld,
		   struct dt_device *dt, int type)
{
	struct dt_object *dt_obj = NULL;
	struct lu_fid fid;
	struct lu_attr *attr = NULL;
	struct lu_seq_range *range = NULL;
	struct fld_thread_info *info;
	struct dt_object_format dof;
	struct dt_it *it;
	const struct dt_it_ops *iops;
	int rc;
	u32 index;
	int range_count = 0;

	ENTRY;

	info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
	LASSERT(info != NULL);

	lu_local_obj_fid(&fid, FLD_INDEX_OID);
	OBD_ALLOC_PTR(attr);
	if (!attr)
		RETURN(-ENOMEM);

	memset(attr, 0, sizeof(*attr));
	attr->la_valid = LA_MODE;
	attr->la_mode = S_IFREG | 0666;
	dof.dof_type = DFT_INDEX;
	dof.u.dof_idx.di_feat = &fld_index_features;

	dt_obj = dt_locate(env, dt, &fid);
	if (IS_ERR(dt_obj)) {
		rc = PTR_ERR(dt_obj);
		dt_obj = NULL;
		GOTO(out, rc);
	}

	LASSERT(dt_obj != NULL);
	if (!dt_object_exists(dt_obj)) {
		dt_object_put(env, dt_obj);
		dt_obj = dt_find_or_create(env, dt, &fid, &dof, attr);
		fld->lsf_new = 1;
		if (IS_ERR(dt_obj)) {
			rc = PTR_ERR(dt_obj);
			CERROR("%s: Can't find \"%s\" obj %d\n", fld->lsf_name,
				fld_index_name, rc);
			dt_obj = NULL;
			GOTO(out, rc);
		}
	}

	fld->lsf_obj = dt_obj;
	rc = dt_obj->do_ops->do_index_try(env, dt_obj, &fld_index_features);
	if (rc != 0) {
		CERROR("%s: File \"%s\" is not an index: rc = %d!\n",
		       fld->lsf_name, fld_index_name, rc);
		GOTO(out, rc);
	}

	range = &info->fti_rec;
	/* Load fld entry to cache */
	iops = &dt_obj->do_index_ops->dio_it;
	it = iops->init(env, dt_obj, 0);
	if (IS_ERR(it))
		GOTO(out, rc = PTR_ERR(it));

	rc = iops->load(env, it, 0);
	if (rc > 0)
		rc = 0;
	else if (rc == 0)
		rc = iops->next(env, it);

	if (rc < 0)
		GOTO(out_it_fini, rc);

	while (rc == 0) {
		rc = iops->rec(env, it, (struct dt_rec *)range, 0);
		if (rc != 0)
			GOTO(out_it_put, rc);

		range_be_to_cpu(range, range);

		/*
		 * Newly created ldiskfs IAM indexes may include a
		 * zeroed-out key and record. Ignore it here.
		 */
		if (range->lsr_start < range->lsr_end) {
			rc = fld_cache_insert(fld->lsf_cache, range);
			if (rc != 0)
				GOTO(out_it_put, rc);

			range_count++;
		}

		rc = iops->next(env, it);
		if (rc < 0)
			GOTO(out_it_fini, rc);
	}

	if (range_count == 0)
		fld->lsf_new = 1;

	rc = fld_name_to_index(fld->lsf_name, &index);
	if (rc < 0)
		GOTO(out_it_put, rc);
	else
		rc = 0;

	if (index == 0 && type == LU_SEQ_RANGE_MDT) {
		/*
		 * Note: fld_insert_entry will detect whether these
		 * special entries already exist inside FLDB
		 */
		mutex_lock(&fld->lsf_lock);
		rc = fld_insert_special_entries(env, fld);
		mutex_unlock(&fld->lsf_lock);
		if (rc != 0) {
			CERROR("%s: insert special entries failed!: rc = %d\n",
			       fld->lsf_name, rc);
			GOTO(out_it_put, rc);
		}
	}
out_it_put:
	iops->put(env, it);
out_it_fini:
	iops->fini(env, it);
out:
	if (attr)
		OBD_FREE_PTR(attr);

	if (rc < 0) {
		if (dt_obj)
			dt_object_put(env, dt_obj);
		fld->lsf_obj = NULL;
	}
	RETURN(rc);
}

void fld_index_fini(const struct lu_env *env, struct lu_server_fld *fld)
{
	ENTRY;
	if (fld->lsf_obj) {
		if (!IS_ERR(fld->lsf_obj))
			dt_object_put(env, fld->lsf_obj);
		fld->lsf_obj = NULL;
	}
	EXIT;
}

int fld_server_read(const struct lu_env *env, struct lu_server_fld *fld,
		    struct lu_seq_range *range, void *data, int data_len)
{
	struct lu_seq_range_array *lsra = data;
	struct fld_thread_info *info;
	struct dt_object *dt_obj = fld->lsf_obj;
	struct lu_seq_range *entry;
	struct dt_it *it;
	const struct dt_it_ops *iops;
	int rc;

	ENTRY;

	lsra->lsra_count = 0;
	iops = &dt_obj->do_index_ops->dio_it;
	it = iops->init(env, dt_obj, 0);
	if (IS_ERR(it))
		RETURN(PTR_ERR(it));

	rc = iops->load(env, it, range->lsr_end);
	if (rc <= 0)
		GOTO(out_it_fini, rc);

	info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
	LASSERT(info != NULL);
	entry = &info->fti_rec;
	do {
		rc = iops->rec(env, it, (struct dt_rec *)entry, 0);
		if (rc != 0)
			GOTO(out_it_put, rc);

		if (offsetof(typeof(*lsra), lsra_lsr[lsra->lsra_count + 1]) >
		    data_len)
			GOTO(out, rc = -EAGAIN);

		range_be_to_cpu(entry, entry);
		if (entry->lsr_index == range->lsr_index &&
		    entry->lsr_flags == range->lsr_flags &&
		    entry->lsr_start > range->lsr_start) {
			lsra->lsra_lsr[lsra->lsra_count] = *entry;
			lsra->lsra_count++;
		}

		rc = iops->next(env, it);
	} while (rc == 0);
	if (rc > 0)
		rc = 0;
out:
	range_array_cpu_to_le(lsra, lsra);
out_it_put:
	iops->put(env, it);
out_it_fini:
	iops->fini(env, it);

	RETURN(rc);
}
