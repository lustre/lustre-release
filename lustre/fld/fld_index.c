/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  fld/fld_index.c
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: WangDi <wangdi@clusterfs.com>
 *           Yury Umanets <umka@clusterfs.com>
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
        .lct_tags = LCT_MD_THREAD|LCT_DT_THREAD,
        .lct_init = fld_key_init,
        .lct_fini = fld_key_fini
};

static struct dt_key *fld_key(const struct lu_context *ctx,
                              const seqno_t seq)
{
        struct fld_thread_info *info;
        ENTRY;

        info = lu_context_key_get(ctx, &fld_thread_key);
        LASSERT(info != NULL);

        info->fti_key = cpu_to_be64(seq);
        RETURN((void *)&info->fti_key);
}

static struct dt_rec *fld_rec(const struct lu_context *ctx,
                              const mdsno_t mds)
{
        struct fld_thread_info *info;
        ENTRY;

        info = lu_context_key_get(ctx, &fld_thread_key);
        LASSERT(info != NULL);

        info->fti_rec = cpu_to_be64(mds);
        RETURN((void *)&info->fti_rec);
}

int fld_index_create(struct lu_server_fld *fld,
                     const struct lu_context *ctx,
                     seqno_t seq, mdsno_t mds)
{
        struct dt_object *dt_obj = fld->fld_obj;
        struct dt_device *dt_dev;
        struct txn_param txn;
        struct thandle *th;
        int rc;
        ENTRY;

        dt_dev = lu2dt_dev(fld->fld_obj->do_lu.lo_dev);
        
        /* stub here, will fix it later */
        txn.tp_credits = FLD_TXN_INDEX_INSERT_CREDITS;

        th = dt_dev->dd_ops->dt_trans_start(ctx, dt_dev, &txn);
        if (!IS_ERR(th)) {
                rc = dt_obj->do_index_ops->dio_insert(ctx, dt_obj,
                                                      fld_rec(ctx, mds),
                                                      fld_key(ctx, seq), th);
                dt_dev->dd_ops->dt_trans_stop(ctx, th);
        } else
                rc = PTR_ERR(th);
        RETURN(rc);
}

int fld_index_delete(struct lu_server_fld *fld,
                     const struct lu_context *ctx,
                     seqno_t seq)
{
        struct dt_object *dt_obj = fld->fld_obj;
        struct dt_device *dt_dev;
        struct txn_param txn;
        struct thandle *th;
        int rc;
        ENTRY;

        dt_dev = lu2dt_dev(fld->fld_obj->do_lu.lo_dev);
        txn.tp_credits = FLD_TXN_INDEX_DELETE_CREDITS;
        th = dt_dev->dd_ops->dt_trans_start(ctx, dt_dev, &txn);
        if (!IS_ERR(th)) {
                rc = dt_obj->do_index_ops->dio_delete(ctx, dt_obj,
                                                      fld_key(ctx, seq), th);
                dt_dev->dd_ops->dt_trans_stop(ctx, th);
        } else
                rc = PTR_ERR(th);
        RETURN(rc);
}

int fld_index_lookup(struct lu_server_fld *fld,
                     const struct lu_context *ctx,
                     seqno_t seq, mdsno_t *mds)
{
        struct dt_object *dt_obj = fld->fld_obj;
        struct dt_rec    *rec = fld_rec(ctx, 0);
        int rc;
        ENTRY;

        rc = dt_obj->do_index_ops->dio_lookup(ctx, dt_obj, rec,
                                              fld_key(ctx, seq));
        if (rc == 0)
                *mds = be64_to_cpu(*(__u64 *)rec);
        RETURN(rc);
}

int fld_index_init(struct lu_server_fld *fld,
                   const struct lu_context *ctx,
                   struct dt_device *dt)
{
        struct dt_object *dt_obj;
        struct lu_fid fid;
        int rc;
        ENTRY;

        if (fld_key_registered == 0) {
                rc = lu_context_key_register(&fld_thread_key);
                if (rc != 0)
                        RETURN(rc);
        }
        fld_key_registered++;

        /*
         * lu_context_key has to be registered before threads are started,
         * check this.
         */
        LASSERT(fld->fld_service == NULL);

        dt_obj = dt_store_open(ctx, dt, fld_index_name, &fid);
        if (!IS_ERR(dt_obj)) {
                fld->fld_obj = dt_obj;
                rc = dt_obj->do_ops->do_index_try(ctx, dt_obj,
                                                  &fld_index_features);
                if (rc == 0)
                        LASSERT(dt_obj->do_index_ops != NULL);
                else
                        CERROR("\"%s\" is not an index!\n", fld_index_name);
        } else {
                CERROR("cannot find \"%s\" obj %d\n",
                       fld_index_name, (int)PTR_ERR(dt_obj));
                rc = PTR_ERR(dt_obj);
        }

        RETURN(rc);
}

void fld_index_fini(struct lu_server_fld *fld,
                    const struct lu_context *ctx)
{
        ENTRY;
        if (fld->fld_obj != NULL) {
                if (!IS_ERR(fld->fld_obj))
                        lu_object_put(ctx, &fld->fld_obj->do_lu);
                fld->fld_obj = NULL;
        }
        if (fld_key_registered > 0) {
                if (--fld_key_registered == 0)
                        lu_context_key_degister(&fld_thread_key);
        }
        EXIT;
}
