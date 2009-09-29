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
 * lustre/mdd/mdd_trans.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#ifdef HAVE_EXT4_LDISKFS
#include <ldiskfs/ldiskfs_jbd2.h>
#else
#include <linux/jbd.h>
#endif
#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#ifdef HAVE_EXT4_LDISKFS
#include <ldiskfs/ldiskfs.h>
#else
#include <linux/ldiskfs_fs.h>
#endif
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>

#include "mdd_internal.h"

int mdd_txn_start_cb(const struct lu_env *env, struct thandle *txn,
                     void *cookie)
{
        struct mdd_device *mdd = cookie;
        struct obd_device *obd = mdd2obd_dev(mdd);

        /* Each transaction updates lov objids, the credits should be added for
         * this */
        int blk, shift = mdd->mdd_dt_conf.ddp_block_shift;
        blk = ((obd->u.mds.mds_lov_desc.ld_tgt_count * sizeof(obd_id) +
               (1 << shift) - 1) >> shift) + 1;

        /* add lov objids credits */
        /*LBUG();
                rc = fsfilt_write_record(obd, mds->mds_lov_objid_filp, data,
                                         size, &off, 0);*/

        return 0;
}

int mdd_txn_stop_cb(const struct lu_env *env, struct thandle *txn,
                    void *cookie)
{
        struct mdd_device *mdd = cookie;
        struct obd_device *obd = mdd2obd_dev(mdd);

        LASSERT(obd);
        return mds_lov_write_objids(env, obd, txn);
}

int mdd_txn_commit_cb(const struct lu_env *env, struct thandle *txn,
                      void *cookie)
{
        return 0;
}

/*int mdd_log_txn_param_build(const struct lu_env *env, struct md_object *obj,
                            struct md_attr *ma, enum mdd_txn_op op)
{
        struct mdd_device *mdd = mdo2mdd(&md2mdd_obj(obj)->mod_obj);
        int rc, log_credits, stripe;
        ENTRY;

        mdd_txn_param_build(env, mdd, op);

        if (S_ISDIR(lu_object_attr(&obj->mo_lu)))
                RETURN(0);

        LASSERT(op == MDD_TXN_UNLINK_OP || op == MDD_TXN_RENAME_OP);
        rc = mdd_lmm_get_locked(env, md2mdd_obj(obj), ma);
        if (rc || !(ma->ma_valid & MA_LOV))
                RETURN(rc);

        LASSERTF(le32_to_cpu(ma->ma_lmm->lmm_magic) == LOV_MAGIC_V1 ||
                 le32_to_cpu(ma->ma_lmm->lmm_magic) == LOV_MAGIC_V3,
                 "%08x", le32_to_cpu(ma->ma_lmm->lmm_magic));

        if ((int)le32_to_cpu(ma->ma_lmm->lmm_stripe_count) < 0)
                stripe = mdd2obd_dev(mdd)->u.mds.mds_lov_desc.ld_tgt_count;
        else
                stripe = le32_to_cpu(ma->ma_lmm->lmm_stripe_count);

        log_credits = stripe * dto_txn_credits[DTO_LOG_REC];
        txn_param_credit_add(&mdd_env_info(env)->mti_param, log_credits);
        RETURN(rc);
}*/

struct thandle* mdd_trans_create(const struct lu_env *env,
                                struct mdd_device *mdd)
{
        struct thandle *th;
 
        th = mdd_child_ops(mdd)->dt_trans_create(env, mdd->mdd_child);
        return th;
}

int mdd_trans_start(const struct lu_env *env,
                                struct mdd_device *mdd, struct thandle *handle)
{
                
        return mdd_child_ops(mdd)->dt_trans_start(env, mdd->mdd_child, handle);
}

void mdd_trans_stop(const struct lu_env *env, struct mdd_device *mdd,
                    int result, struct thandle *handle)
{
        handle->th_result = result;
        mdd_child_ops(mdd)->dt_trans_stop(env, handle);
}
