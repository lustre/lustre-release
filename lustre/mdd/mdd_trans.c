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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011 Whamcloud, Inc.
 *
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

static int dto_txn_credits[DTO_NR];

int mdd_txn_start_cb(const struct lu_env *env, struct txn_param *param,
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
        param->tp_credits += blk * dto_txn_credits[DTO_WRITE_BLOCK] +
                             dto_txn_credits[DTO_WRITE_BASE];

        return 0;
}

int mdd_txn_stop_cb(const struct lu_env *env, struct thandle *txn,
                    void *cookie)
{
        struct mdd_device *mdd = cookie;
        struct obd_device *obd = mdd2obd_dev(mdd);

        LASSERT(obd);
        return mds_lov_write_objids(obd);
}

int mdd_txn_commit_cb(const struct lu_env *env, struct thandle *txn,
                      void *cookie)
{
        return 0;
}

void mdd_txn_param_build(const struct lu_env *env, struct mdd_device *mdd,
                         enum mdd_txn_op op, int changelog_cnt)
{
        LASSERT(0 <= op && op < MDD_TXN_LAST_OP);

        txn_param_init(&mdd_env_info(env)->mti_param,
                       mdd->mdd_tod[op].mod_credits);
        if (changelog_cnt > 0) {
                txn_param_credit_add(&mdd_env_info(env)->mti_param,
                                  changelog_cnt * dto_txn_credits[DTO_LOG_REC]);
        }
}

int mdd_create_txn_param_build(const struct lu_env *env, struct mdd_device *mdd,
                               struct lov_mds_md *lmm, enum mdd_txn_op op,
                               int changelog_cnt)
{
        int stripes = 0;
        ENTRY;

        LASSERT(op == MDD_TXN_CREATE_DATA_OP || op == MDD_TXN_MKDIR_OP);

        if (lmm == NULL)
                GOTO(out, 0);
        /* only replay create request will cause lov_objid update */
        if (!mdd->mdd_obd_dev->obd_recovering)
                GOTO(out, 0);

        /* add possible orphan unlink rec credits used in lov_objid update */
        if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_V1) {
                stripes = le32_to_cpu(((struct lov_mds_md_v1*)lmm)
                                      ->lmm_stripe_count);
        } else if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_V3){
                stripes = le32_to_cpu(((struct lov_mds_md_v3*)lmm)
                                      ->lmm_stripe_count);
        } else {
                CERROR("Unknown lmm type %X\n", le32_to_cpu(lmm->lmm_magic));
                LBUG();
        }
out:
        mdd_txn_param_build(env, mdd, op, stripes + changelog_cnt);
        RETURN(0);
}

int mdd_log_txn_param_build(const struct lu_env *env, struct md_object *obj,
                            struct md_attr *ma, enum mdd_txn_op op,
                            int changelog_cnt)
{
        struct mdd_device *mdd = mdo2mdd(&md2mdd_obj(obj)->mod_obj);
        int rc, stripe = 0;
        ENTRY;

        if (S_ISDIR(lu_object_attr(&obj->mo_lu)))
                GOTO(out, rc = 0);

        LASSERT(op == MDD_TXN_UNLINK_OP || op == MDD_TXN_RENAME_OP ||
                op == MDD_TXN_RENAME_TGT_OP);
        rc = mdd_lmm_get_locked(env, md2mdd_obj(obj), ma);
        if (rc || !(ma->ma_valid & MA_LOV))
                GOTO(out, rc);

        LASSERTF(le32_to_cpu(ma->ma_lmm->lmm_magic) == LOV_MAGIC_V1 ||
                 le32_to_cpu(ma->ma_lmm->lmm_magic) == LOV_MAGIC_V3,
                 "%08x", le32_to_cpu(ma->ma_lmm->lmm_magic));

        if ((int)le32_to_cpu(ma->ma_lmm->lmm_stripe_count) < 0)
                stripe = mdd2obd_dev(mdd)->u.mds.mds_lov_desc.ld_tgt_count;
        else
                stripe = le32_to_cpu(ma->ma_lmm->lmm_stripe_count);

out:
        mdd_txn_param_build(env, mdd, op, stripe + changelog_cnt);

        RETURN(rc);
}

int mdd_setattr_txn_param_build(const struct lu_env *env, struct md_object *obj,
                                struct md_attr *ma, enum mdd_txn_op op,
                                int changelog_cnt)
{
        struct mdd_device *mdd = mdo2mdd(&md2mdd_obj(obj)->mod_obj);
        ENTRY;

        mdd_txn_param_build(env, mdd, op, changelog_cnt);
        if (ma->ma_attr.la_valid & (LA_UID | LA_GID))
                txn_param_credit_add(&mdd_env_info(env)->mti_param,
                                     dto_txn_credits[DTO_ATTR_SET_CHOWN]);

        /* permission changes may require sync operation */
        if (ma->ma_attr.la_valid & (LA_MODE|LA_UID|LA_GID) &&
            mdd->mdd_sync_permission == 1)
                txn_param_sync(&mdd_env_info(env)->mti_param);

        RETURN(0);
}

static void mdd_txn_init_dto_credits(const struct lu_env *env,
                                     struct mdd_device *mdd, int *dto_credits)
{
        int op, credits;
        for (op = 0; op < DTO_NR; op++) {
                credits = mdd_child_ops(mdd)->dt_credit_get(env, mdd->mdd_child,
                                                            op);
                LASSERT(credits >= 0);
                dto_txn_credits[op] = credits;
        }
}

int mdd_txn_init_credits(const struct lu_env *env, struct mdd_device *mdd)
{
        int op;

        /* Init credits for each ops. */
        mdd_txn_init_dto_credits(env, mdd, dto_txn_credits);

        /* Calculate the mdd credits. */
        for (op = MDD_TXN_OBJECT_DESTROY_OP; op < MDD_TXN_LAST_OP; op++) {
                int *c = &mdd->mdd_tod[op].mod_credits;
                int *dt = dto_txn_credits;
                mdd->mdd_tod[op].mod_op = op;
                switch(op) {
                        case MDD_TXN_OBJECT_DESTROY_OP:
                                /* Unused now */
                                *c = dt[DTO_OBJECT_DELETE];
                                break;
                        case MDD_TXN_OBJECT_CREATE_OP:
                                /* OI INSERT + CREATE OBJECT */
                                *c = dt[DTO_INDEX_INSERT] +
                                     dt[DTO_OBJECT_CREATE];
                                break;
                        case MDD_TXN_ATTR_SET_OP:
                                /* ATTR set + XATTR(lsm, lmv) set */
                                *c = dt[DTO_ATTR_SET_BASE] +
                                     dt[DTO_XATTR_SET];
                                break;
                        case MDD_TXN_XATTR_SET_OP:
                                *c = dt[DTO_XATTR_SET];
                                break;
                        case MDD_TXN_INDEX_INSERT_OP:
                                *c = dt[DTO_INDEX_INSERT];
                                break;
                        case MDD_TXN_INDEX_DELETE_OP:
                                *c = dt[DTO_INDEX_DELETE];
                                break;
                        case MDD_TXN_LINK_OP:
                                *c = dt[DTO_INDEX_INSERT];
                                break;
                        case MDD_TXN_UNLINK_OP:
                                /* delete index + Unlink log +
                                 * mdd orphan handling */
                                *c = dt[DTO_INDEX_DELETE] +
                                        dt[DTO_INDEX_DELETE] +
                                        dt[DTO_INDEX_INSERT] * 2 +
                                        dt[DTO_XATTR_SET] * 3;
                                break;
                        case MDD_TXN_RENAME_OP:
                                /* 2 delete index + 1 insert + Unlink log */
                                *c = 2 * dt[DTO_INDEX_DELETE] +
                                        dt[DTO_INDEX_INSERT] +
                                        dt[DTO_INDEX_DELETE] +
                                        dt[DTO_INDEX_INSERT] * 2 +
                                        dt[DTO_XATTR_SET] * 3;
                                break;
                        case MDD_TXN_RENAME_TGT_OP:
                                /* index insert + index delete */
                                *c = dt[DTO_INDEX_DELETE] +
                                        dt[DTO_INDEX_INSERT] +
                                        dt[DTO_INDEX_DELETE] +
                                        dt[DTO_INDEX_INSERT] * 2 +
                                        dt[DTO_XATTR_SET] * 3;
                                break;
                        case MDD_TXN_CREATE_DATA_OP:
                                /* same as set xattr(lsm) */
                                *c = dt[DTO_XATTR_SET];
                                break;
                        case MDD_TXN_MKDIR_OP:
                                /* INDEX INSERT + OI INSERT +
                                 * CREATE_OBJECT_CREDITS
                                 * SET_MD CREDITS is already counted in
                                 * CREATE_OBJECT CREDITS
                                 */
                                 *c = 2 * dt[DTO_INDEX_INSERT] +
                                          dt[DTO_OBJECT_CREATE];
                                break;
                        default:
                                CERROR("Invalid op %d init its credit\n", op);
                                LBUG();
                }
        }
        RETURN(0);
}

struct thandle* mdd_trans_start(const struct lu_env *env,
                                struct mdd_device *mdd)
{
        struct txn_param *p = &mdd_env_info(env)->mti_param;
        struct thandle *th;

        th = mdd_child_ops(mdd)->dt_trans_start(env, mdd->mdd_child, p);
        return th;
}

void mdd_trans_stop(const struct lu_env *env, struct mdd_device *mdd,
                    int result, struct thandle *handle)
{
        handle->th_result = result;
        mdd_child_ops(mdd)->dt_trans_stop(env, handle);
}
