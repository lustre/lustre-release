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
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
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

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/module.h>
# include <linux/jbd.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <dt_object.h>
#include <md_object.h>
#include <lustre_mdc.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include "fld_internal.h"

const char fld_index_name[] = "fld";

static const struct lu_seq_range IGIF_FLD_RANGE = {
        .lsr_start = 1,
        .lsr_end   = FID_SEQ_IDIF,
        .lsr_index   = 0,
        .lsr_flags  = LU_SEQ_RANGE_MDT
};

const struct dt_index_features fld_index_features = {
	.dif_flags       = DT_IND_UPDATE | DT_IND_RANGE,
        .dif_keysize_min = sizeof(seqno_t),
        .dif_keysize_max = sizeof(seqno_t),
        .dif_recsize_min = sizeof(struct lu_seq_range),
        .dif_recsize_max = sizeof(struct lu_seq_range),
        .dif_ptrsize     = 4
};

extern struct lu_context_key fld_thread_key;

static struct dt_key *fld_key(const struct lu_env *env, const seqno_t seq)
{
        struct fld_thread_info *info;
        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
        LASSERT(info != NULL);

        info->fti_key = cpu_to_be64(seq);
        RETURN((void *)&info->fti_key);
}

static struct dt_rec *fld_rec(const struct lu_env *env,
                              const struct lu_seq_range *range)
{
        struct fld_thread_info *info;
        struct lu_seq_range *rec;
        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
        LASSERT(info != NULL);
        rec = &info->fti_rec;

        range_cpu_to_be(rec, range);
        RETURN((void *)rec);
}

struct thandle *fld_trans_create(struct lu_server_fld *fld,
                                const struct lu_env *env)
{
        struct dt_device *dt_dev;

        dt_dev = lu2dt_dev(fld->lsf_obj->do_lu.lo_dev);

        return dt_dev->dd_ops->dt_trans_create(env, dt_dev);
}

int fld_trans_start(struct lu_server_fld *fld,
                                const struct lu_env *env, struct thandle *th)
{
        struct dt_device *dt_dev;

        dt_dev = lu2dt_dev(fld->lsf_obj->do_lu.lo_dev);

        return dt_dev->dd_ops->dt_trans_start(env, dt_dev, th);
}

void fld_trans_stop(struct lu_server_fld *fld,
                    const struct lu_env *env, struct thandle* th)
{
        struct dt_device *dt_dev;

        dt_dev = lu2dt_dev(fld->lsf_obj->do_lu.lo_dev);
        dt_dev->dd_ops->dt_trans_stop(env, th);
}

int fld_declare_index_create(struct lu_server_fld *fld,
                             const struct lu_env *env,
                             const struct lu_seq_range *range,
                             struct thandle *th)
{
        struct dt_object *dt_obj = fld->lsf_obj;
        seqno_t start;
        int rc;

        ENTRY;

	if (fld->lsf_no_range_lookup) {
		/* Stub for underlying FS which can't lookup ranges */
		return 0;
	}

        start = range->lsr_start;
        LASSERT(range_is_sane(range));

        rc = dt_obj->do_index_ops->dio_declare_insert(env, dt_obj,
                                                      fld_rec(env, range),
                                                      fld_key(env, start), th);
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
 */

int fld_index_create(struct lu_server_fld *fld,
                     const struct lu_env *env,
                     const struct lu_seq_range *range,
                     struct thandle *th)
{
        struct dt_object *dt_obj = fld->lsf_obj;
        seqno_t start;
        int rc;

        ENTRY;

	if (fld->lsf_no_range_lookup) {
		/* Stub for underlying FS which can't lookup ranges */
		if (range->lsr_index != 0) {
			CERROR("%s: FLD backend does not support range"
			       "lookups, so DNE and FIDs-on-OST are not"
			       "supported in this configuration\n",
			       fld->lsf_name);
			return -EINVAL;
		}
	}

        start = range->lsr_start;
        LASSERT(range_is_sane(range));

        rc = dt_obj->do_index_ops->dio_insert(env, dt_obj,
                                              fld_rec(env, range),
                                              fld_key(env, start),
                                              th, BYPASS_CAPA, 1);

        CDEBUG(D_INFO, "%s: insert given range : "DRANGE" rc = %d\n",
               fld->lsf_name, PRANGE(range), rc);
        RETURN(rc);
}

/**
 * delete range in fld store.
 *
 *      \param  range range to be deleted
 *      \param  th     transaction
 *
 *      \retval  0  success
 *      \retval  -ve error
 */

int fld_index_delete(struct lu_server_fld *fld,
                     const struct lu_env *env,
                     struct lu_seq_range *range,
                     struct thandle   *th)
{
        struct dt_object *dt_obj = fld->lsf_obj;
        seqno_t seq = range->lsr_start;
        int rc;

        ENTRY;

        rc = dt_obj->do_index_ops->dio_delete(env, dt_obj, fld_key(env, seq),
                                              th, BYPASS_CAPA);

        CDEBUG(D_INFO, "%s: delete given range : "DRANGE" rc = %d\n",
               fld->lsf_name, PRANGE(range), rc);

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

int fld_index_lookup(struct lu_server_fld *fld,
                     const struct lu_env *env,
                     seqno_t seq,
                     struct lu_seq_range *range)
{
        struct dt_object        *dt_obj = fld->lsf_obj;
        struct lu_seq_range     *fld_rec;
        struct dt_key           *key = fld_key(env, seq);
        struct fld_thread_info  *info;
        int rc;

        ENTRY;

	if (fld->lsf_no_range_lookup) {
		/* Stub for underlying FS which can't lookup ranges */
		range->lsr_start = 0;
		range->lsr_end = ~0;
		range->lsr_index = 0;
		range->lsr_flags = LU_SEQ_RANGE_MDT;

		range_cpu_to_be(range, range);
		return 0;
	}

        info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
        fld_rec = &info->fti_rec;

        rc = dt_obj->do_index_ops->dio_lookup(env, dt_obj,
                                              (struct dt_rec*) fld_rec,
                                              key, BYPASS_CAPA);

        if (rc >= 0) {
                range_be_to_cpu(fld_rec, fld_rec);
                *range = *fld_rec;
                if (range_within(range, seq))
                        rc = 0;
                else
                        rc = -ENOENT;
        }

        CDEBUG(D_INFO, "%s: lookup seq = "LPX64" range : "DRANGE" rc = %d\n",
               fld->lsf_name, seq, PRANGE(range), rc);

        RETURN(rc);
}

static int fld_insert_igif_fld(struct lu_server_fld *fld,
                               const struct lu_env *env)
{
        struct thandle *th;
        int rc;
        ENTRY;

        /* FLD_TXN_INDEX_INSERT_CREDITS */
        th = fld_trans_create(fld, env);
        if (IS_ERR(th))
                RETURN(PTR_ERR(th));
        rc = fld_declare_index_create(fld, env, &IGIF_FLD_RANGE, th);
        if (rc) {
                fld_trans_stop(fld, env, th);
                RETURN(rc);
        }
        rc = fld_trans_start(fld, env, th);
        if (rc) {
                fld_trans_stop(fld, env, th);
                RETURN(rc);
        }

        rc = fld_index_create(fld, env, &IGIF_FLD_RANGE, th);
        fld_trans_stop(fld, env, th);
        if (rc == -EEXIST)
                rc = 0;
        RETURN(rc);
}

int fld_index_init(struct lu_server_fld *fld,
                   const struct lu_env *env,
                   struct dt_device *dt)
{
        struct dt_object *dt_obj;
        struct lu_fid fid;
	struct lu_attr attr;
	struct dt_object_format dof;
        int rc;
        ENTRY;

	lu_local_obj_fid(&fid, FLD_INDEX_OID);

	memset(&attr, 0, sizeof(attr));
	attr.la_valid = LA_MODE;
	attr.la_mode = S_IFREG | 0666;
	dof.dof_type = DFT_INDEX;
	dof.u.dof_idx.di_feat = &fld_index_features;

	dt_obj = dt_find_or_create(env, dt, &fid, &dof, &attr);
        if (!IS_ERR(dt_obj)) {
                fld->lsf_obj = dt_obj;
                rc = dt_obj->do_ops->do_index_try(env, dt_obj,
                                                  &fld_index_features);
                if (rc == 0) {
                        LASSERT(dt_obj->do_index_ops != NULL);
                        rc = fld_insert_igif_fld(fld, env);

                        if (rc != 0) {
                                CERROR("insert igif in fld! = %d\n", rc);
                                lu_object_put(env, &dt_obj->do_lu);
                                fld->lsf_obj = NULL;
                        }
		} else if (rc == -ERANGE) {
			CWARN("%s: File \"%s\" doesn't support range lookup, "
			      "using stub. DNE and FIDs on OST will not work "
			      "with this backend\n",
			      fld->lsf_name, fld_index_name);

			LASSERT(dt_obj->do_index_ops == NULL);
			fld->lsf_no_range_lookup = 1;
			rc = 0;
		} else {
			CERROR("%s: File \"%s\" is not index, rc %d!\n",
			       fld->lsf_name, fld_index_name, rc);
			lu_object_put(env, &fld->lsf_obj->do_lu);
			fld->lsf_obj = NULL;
		}


        } else {
                CERROR("%s: Can't find \"%s\" obj %d\n",
                       fld->lsf_name, fld_index_name, (int)PTR_ERR(dt_obj));
                rc = PTR_ERR(dt_obj);
        }

        RETURN(rc);
}

void fld_index_fini(struct lu_server_fld *fld,
                    const struct lu_env *env)
{
        ENTRY;
        if (fld->lsf_obj != NULL) {
                if (!IS_ERR(fld->lsf_obj))
                        lu_object_put(env, &fld->lsf_obj->do_lu);
                fld->lsf_obj = NULL;
        }
        EXIT;
}
