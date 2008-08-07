/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
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
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
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
#include <lustre_fld.h>
#include "fld_internal.h"

const char fld_index_name[] = "fld";

static const struct dt_index_features fld_index_features = {
        .dif_flags       = DT_IND_UPDATE,
        .dif_keysize_min = sizeof(seqno_t),
        .dif_keysize_max = sizeof(seqno_t),
        .dif_recsize_min = sizeof(mdsno_t),
        .dif_recsize_max = sizeof(mdsno_t)
};

/*
 * number of blocks to reserve for particular operations. Should be function of
 * ... something. Stub for now.
 */
enum {
        FLD_TXN_INDEX_INSERT_CREDITS  = 20,
        FLD_TXN_INDEX_DELETE_CREDITS  = 20,
};

extern struct lu_context_key fld_thread_key;

static struct dt_key *fld_key(const struct lu_env *env,
                              const seqno_t seq)
{
        struct fld_thread_info *info;
        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
        LASSERT(info != NULL);

        info->fti_key = cpu_to_be64(seq);
        RETURN((void *)&info->fti_key);
}

static struct dt_rec *fld_rec(const struct lu_env *env,
                              const mdsno_t mds)
{
        struct fld_thread_info *info;
        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
        LASSERT(info != NULL);

        info->fti_rec = cpu_to_be64(mds);
        RETURN((void *)&info->fti_rec);
}

int fld_index_create(struct lu_server_fld *fld,
                     const struct lu_env *env,
                     seqno_t seq, mdsno_t mds)
{
        struct dt_object *dt_obj = fld->lsf_obj;
        struct dt_device *dt_dev;
        struct txn_param txn;
        struct thandle *th;
        int rc;
        ENTRY;

        dt_dev = lu2dt_dev(fld->lsf_obj->do_lu.lo_dev);

        /* stub here, will fix it later */
        txn_param_init(&txn, FLD_TXN_INDEX_INSERT_CREDITS);

        th = dt_dev->dd_ops->dt_trans_start(env, dt_dev, &txn);
        if (!IS_ERR(th)) {
                rc = dt_obj->do_index_ops->dio_insert(env, dt_obj,
                                                      fld_rec(env, mds),
                                                      fld_key(env, seq),
                                                      th, BYPASS_CAPA);
                dt_dev->dd_ops->dt_trans_stop(env, th);
        } else
                rc = PTR_ERR(th);
        RETURN(rc);
}

int fld_index_delete(struct lu_server_fld *fld,
                     const struct lu_env *env,
                     seqno_t seq)
{
        struct dt_object *dt_obj = fld->lsf_obj;
        struct dt_device *dt_dev;
        struct txn_param txn;
        struct thandle *th;
        int rc;
        ENTRY;

        dt_dev = lu2dt_dev(fld->lsf_obj->do_lu.lo_dev);
        txn_param_init(&txn, FLD_TXN_INDEX_DELETE_CREDITS);
        th = dt_dev->dd_ops->dt_trans_start(env, dt_dev, &txn);
        if (!IS_ERR(th)) {
                rc = dt_obj->do_index_ops->dio_delete(env, dt_obj,
                                                      fld_key(env, seq), th,
                                                      BYPASS_CAPA);
                dt_dev->dd_ops->dt_trans_stop(env, th);
        } else
                rc = PTR_ERR(th);
        RETURN(rc);
}

int fld_index_lookup(struct lu_server_fld *fld,
                     const struct lu_env *env,
                     seqno_t seq, mdsno_t *mds)
{
        struct dt_object *dt_obj = fld->lsf_obj;
        struct dt_rec    *rec = fld_rec(env, 0);
        int rc;
        ENTRY;

        rc = dt_obj->do_index_ops->dio_lookup(env, dt_obj, rec,
                                              fld_key(env, seq), BYPASS_CAPA);
        if (rc == 0)
                *mds = be64_to_cpu(*(__u64 *)rec);
        RETURN(rc);
}

int fld_index_init(struct lu_server_fld *fld,
                   const struct lu_env *env,
                   struct dt_device *dt)
{
        struct dt_object *dt_obj;
        struct lu_fid fid;
        int rc;
        ENTRY;

        dt_obj = dt_store_open(env, dt, fld_index_name, &fid);
        if (!IS_ERR(dt_obj)) {
                fld->lsf_obj = dt_obj;
                rc = dt_obj->do_ops->do_index_try(env, dt_obj,
                                                  &fld_index_features);
                if (rc == 0)
                        LASSERT(dt_obj->do_index_ops != NULL);
                else
                        CERROR("%s: File \"%s\" is not an index!\n",
                               fld->lsf_name, fld_index_name);
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
