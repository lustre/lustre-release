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
#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>
#include <linux/jbd.h>

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <dt_object.h>
#include <md_object.h>
#include <lustre_mdc.h>
#include <lustre_fid.h>
#include <linux/lustre_iam.h>
#include "fld_internal.h"


struct iam_descr fld_param = {
        .id_key_size = sizeof ((struct lu_fid *)0)->f_seq,
        .id_ptr_size = 4, /* 32 bit block numbers for now */
        .id_rec_size = sizeof(mdsno_t),
        .id_node_gap = 0, /* no gaps in index nodes */
        .id_root_gap = sizeof(struct iam_root),
        .id_ops      = &generic_iam_ops,
        .id_leaf_ops = &lfix_leaf_ops
};
/*
 * number of blocks to reserve for particular operations. Should be function
 * of ... something. Stub for now.
 */

enum {
        FLD_TXN_INDEX_INSERT_CREDITS  = 10,
        FLD_TXN_INDEX_DELETE_CREDITS  = 10
};

static int fld_keycmp(struct iam_container *c, struct iam_key *k1,
                      struct iam_key *k2)
{
        __u64 p1 = le64_to_cpu(*(__u32 *)k1);
        __u64 p2 = le64_to_cpu(*(__u32 *)k2);

        return p1 > p2 ? +1 : (p1 < p2 ? -1 : 0);

}

int fld_handle_insert(const struct lu_context *ctx, struct fld *fld,
                      fidseq_t seq_num, mdsno_t mds_num)
{
        struct dt_device *dt = fld->fld_dt;
        struct dt_object *dt_obj = fld->fld_obj;
        struct txn_param txn;
        struct thandle *th;
        int    rc;


        /*stub here, will fix it later*/
        txn.tp_credits = FLD_TXN_INDEX_INSERT_CREDITS;

        th = dt->dd_ops->dt_trans_start(ctx, dt, &txn);

        rc = dt_obj->do_index_ops->dio_insert(ctx, dt_obj,
                                              (struct dt_rec*)(&mds_num),
                                              (struct dt_key*)(&seq_num), th);
        dt->dd_ops->dt_trans_stop(ctx, th);

        RETURN(rc);
}

int fld_handle_delete(const struct lu_context *ctx, struct fld *fld,
                      fidseq_t seq_num, mdsno_t mds_num)
{
        struct dt_device *dt = fld->fld_dt;
        struct dt_object *dt_obj = fld->fld_obj;
        struct txn_param txn;
        struct thandle *th;
        int    rc;


        txn.tp_credits = FLD_TXN_INDEX_DELETE_CREDITS;
        th = dt->dd_ops->dt_trans_start(ctx, dt, &txn);
        rc = dt_obj->do_index_ops->dio_delete(ctx, dt_obj,
                                              (struct dt_rec*)(&mds_num),
                                              (struct dt_key*)(&seq_num), th);
        dt->dd_ops->dt_trans_stop(ctx, th);

        RETURN(rc);
}

int fld_handle_lookup(const struct lu_context *ctx,
                      struct fld *fld, fidseq_t seq_num, mdsno_t *mds_num)
{

        struct dt_object *dt_obj = fld->fld_obj;

        return dt_obj->do_index_ops->dio_lookup(ctx, dt_obj,
                                             (struct dt_rec*)(&mds_num),
                                             (struct dt_key*)(&seq_num));
}

int fld_iam_init(const struct lu_context *ctx, struct fld *fld)
{
        struct dt_device *dt = fld->fld_dt;
        struct dt_object *dt_obj;
        struct iam_container *ic = NULL;
        int rc;

        ENTRY;

        dt_obj = dt_store_open(ctx, dt, "fld", &fld->fld_fid);
        if (!IS_ERR(dt_obj)) {
                fld->fld_obj = dt_obj;
                if (dt_obj->do_index_ops != NULL) {
                        rc = dt_obj->do_index_ops->dio_init(ctx, dt_obj,
                                                            ic, &fld_param);
                        fld_param.id_ops->id_keycmp = fld_keycmp;
                } else {
                        CERROR("fld is not an index!\n");
                        rc = -EINVAL;
                }
        } else {
                CERROR("Cannot find fld obj %lu \n", PTR_ERR(dt_obj));
                rc = PTR_ERR(dt_obj);
        }


        RETURN(rc);
}

void fld_iam_fini(const struct lu_context *ctx, struct fld *fld)
{
        struct dt_object *dt_obj = fld->fld_obj;

        dt_obj->do_index_ops->dio_fini(ctx, dt_obj);
        /*XXX Should put object here,
          lu_object_put(fld->fld_obj->do_lu);
         *but no ctxt in this func, FIX later*/
        fld->fld_obj = NULL;
}
