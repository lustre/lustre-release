/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  fld/fld.c
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: WangDi <wangdi@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
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


static const struct dt_index_features fld_index_features = {
        .dif_flags       = DT_IND_UPDATE,
        .dif_keysize_min = sizeof(fidseq_t),
        .dif_keysize_max = sizeof(fidseq_t),
        .dif_recsize_min = sizeof(mdsno_t),
        .dif_recsize_max = sizeof(mdsno_t)
};

/*
 * number of blocks to reserve for particular operations. Should be function
 * of ... something. Stub for now.
 */

enum {
        FLD_TXN_INDEX_INSERT_CREDITS  = 10,
        FLD_TXN_INDEX_DELETE_CREDITS  = 10
};

struct fld_thread_info {
        __u64 fti_key;
        __u64 fti_rec;
};

static void *fld_key_init(const struct lu_context *ctx,
                          struct lu_context_key *key)
{
        struct fld_thread_info *info;
        ENTRY;

        OBD_ALLOC_PTR(info);
        if (info == NULL)
                info = ERR_PTR(-ENOMEM);
        RETURN(info);
}

static void fld_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct fld_thread_info *info = data;
        ENTRY;
        OBD_FREE_PTR(info);
        EXIT;
}

static int fld_key_registered = 0;

static struct lu_context_key fld_thread_key = {
        .lct_init = fld_key_init,
        .lct_fini = fld_key_fini
};

static struct dt_key *fld_key(const struct lu_context *ctx,
                              const fidseq_t seq_num)
{
        struct fld_thread_info *info;
        ENTRY;
        
        info = lu_context_key_get(ctx, &fld_thread_key);
        LASSERT(info != NULL);

        info->fti_key = cpu_to_be64(seq_num);
        RETURN((void *)&info->fti_key);
}

static struct dt_rec *fld_rec(const struct lu_context *ctx,
                              const mdsno_t mds_num)
{
        struct fld_thread_info *info;
        ENTRY;
        
        info = lu_context_key_get(ctx, &fld_thread_key);
        LASSERT(info != NULL);

        info->fti_rec = cpu_to_be64(mds_num);
        RETURN((void *)&info->fti_rec);
}

int fld_handle_insert(struct lu_server_fld *fld,
                      const struct lu_context *ctx,
                      fidseq_t seq_num, mdsno_t mds_num)
{
        struct dt_device *dt = fld->fld_dt;
        struct dt_object *dt_obj = fld->fld_obj;
        struct txn_param txn;
        struct thandle *th;
        int rc;
        ENTRY;

        /*stub here, will fix it later*/
        txn.tp_credits = FLD_TXN_INDEX_INSERT_CREDITS;

        th = dt->dd_ops->dt_trans_start(ctx, dt, &txn);

        rc = dt_obj->do_index_ops->dio_insert(ctx, dt_obj,
                                              fld_rec(ctx, mds_num),
                                              fld_key(ctx, seq_num), th);
        dt->dd_ops->dt_trans_stop(ctx, th);

        RETURN(rc);
}

int fld_handle_delete(struct lu_server_fld *fld,
                      const struct lu_context *ctx,
                      fidseq_t seq_num)
{
        struct dt_device *dt = fld->fld_dt;
        struct dt_object *dt_obj = fld->fld_obj;
        struct txn_param txn;
        struct thandle *th;
        int rc;
        ENTRY;

        txn.tp_credits = FLD_TXN_INDEX_DELETE_CREDITS;
        th = dt->dd_ops->dt_trans_start(ctx, dt, &txn);
        rc = dt_obj->do_index_ops->dio_delete(ctx, dt_obj,
                                              fld_key(ctx, seq_num), th);
        dt->dd_ops->dt_trans_stop(ctx, th);

        RETURN(rc);
}

int fld_handle_lookup(struct lu_server_fld *fld,
                      const struct lu_context *ctx,
                      fidseq_t seq_num, mdsno_t *mds_num)
{
        struct dt_object *dt_obj = fld->fld_obj;
        struct dt_rec    *rec = fld_rec(ctx, 0);
        int rc;
        ENTRY;

        rc = dt_obj->do_index_ops->dio_lookup(ctx, dt_obj, rec,
                                              fld_key(ctx, seq_num));
        if (rc == 0)
                *mds_num = be64_to_cpu(*(__u64 *)rec);
        RETURN(rc);
}

int fld_iam_init(struct lu_server_fld *fld,
                 const struct lu_context *ctx)
{
        struct dt_device *dt = fld->fld_dt;
        struct dt_object *dt_obj;
        int rc;
        ENTRY;

        if (fld_key_registered == 0) {
                rc = lu_context_key_register(&fld_thread_key);
                if (rc != 0)
                        return rc;
        }
        fld_key_registered++;

        /*
         * lu_context_key has to be registered before threads are started,
         * check this.
         */
        LASSERT(fld->fld_service == NULL);

        fld->fld_cookie = dt->dd_ops->dt_index_init(ctx, &fld_index_features);
        if (IS_ERR(fld->fld_cookie) != 0)
                return PTR_ERR(fld->fld_cookie);

        dt_obj = dt_store_open(ctx, dt, "fld", &fld->fld_fid);
        if (!IS_ERR(dt_obj)) {
                fld->fld_obj = dt_obj;
                rc = dt_obj->do_ops->do_object_index_try(ctx, dt_obj,
                                                         &fld_index_features,
                                                         fld->fld_cookie);
                if (rc == 0)
                        LASSERT(dt_obj->do_index_ops != NULL);
                else
                        CERROR("fld is not an index!\n");
        } else {
                CERROR("Cannot find fld obj %lu \n", PTR_ERR(dt_obj));
                rc = PTR_ERR(dt_obj);
        }

        RETURN(rc);
}

void fld_iam_fini(struct lu_server_fld *fld,
                  const struct lu_context *ctx)
{
        ENTRY;
        if (!IS_ERR(fld->fld_cookie) && fld->fld_cookie != NULL) {
                fld->fld_dt->dd_ops->dt_index_fini(ctx, fld->fld_cookie);
                fld->fld_cookie = NULL;
        }
        if (fld->fld_obj != NULL) {
                lu_object_put(ctx, &fld->fld_obj->do_lu);
                fld->fld_obj = NULL;
        }
        if (fld_key_registered > 0) {
                if (--fld_key_registered == 0)
                        lu_context_key_degister(&fld_thread_key);
        }
        EXIT;
}
