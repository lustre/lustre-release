/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  mdd/mdd_handler.c
 *  Lustre Metadata Server (mdd) routines
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Wang Di <wangdi@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/jbd.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <linux/ldiskfs_fs.h>
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>

#include "mdd_internal.h"


struct mdd_txn_op_descr {
        enum mdd_txn_op mod_op;
        unsigned int    mod_credits;
};

enum {
        MDD_TXN_OBJECT_DESTROY_CREDITS = 0,
        MDD_TXN_OBJECT_CREATE_CREDITS = 0,
        MDD_TXN_ATTR_SET_CREDITS = 0,
        MDD_TXN_XATTR_SET_CREDITS = 0,
        MDD_TXN_INDEX_INSERT_CREDITS = 0,
        MDD_TXN_INDEX_DELETE_CREDITS = 0,
        MDD_TXN_LINK_CREDITS = 0,
        MDD_TXN_UNLINK_CREDITS = 0,
        MDD_TXN_RENAME_CREDITS = 0,
        MDD_TXN_RENAME_TGT_CREDITS = 0,
        MDD_TXN_CREATE_DATA_CREDITS = 0,
        MDD_TXN_MKDIR_CREDITS = 0
};

#define DEFINE_MDD_TXN_OP_ARRAY(opname, base)   \
[opname ## _OP - base ## _OP]= {                \
        .mod_op      = opname ## _OP,           \
        .mod_credits = opname ## _CREDITS,      \
}

/*
 * number of blocks to reserve for particular operations. Should be function
 * of ... something. Stub for now.
 */

#define DEFINE_MDD_TXN_OP_DESC(opname)          \
        DEFINE_MDD_TXN_OP_ARRAY(opname, MDD_TXN_OBJECT_DESTROY)

static struct mdd_txn_op_descr mdd_txn_descrs[] = {
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_OBJECT_DESTROY),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_OBJECT_CREATE),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_ATTR_SET),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_XATTR_SET),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_INDEX_INSERT),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_INDEX_DELETE),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_LINK),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_UNLINK),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_RENAME),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_RENAME_TGT),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_CREATE_DATA),
        DEFINE_MDD_TXN_OP_DESC(MDD_TXN_MKDIR)
};

int mdd_txn_start_cb(const struct lu_env *env, struct txn_param *param, 
                     void *cookie)
{
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

void mdd_txn_param_build(const struct lu_env *env, enum mdd_txn_op op)
{
        LASSERT(0 <= op && op < ARRAY_SIZE(mdd_txn_descrs));

        mdd_env_info(env)->mti_param.tp_credits =
                mdd_txn_descrs[op].mod_credits;
}

static int mdd_credit_get(const struct lu_env *env, struct mdd_device *mdd,
                          int op)
{
        int credits;
        credits = mdd_child_ops(mdd)->dt_credit_get(env, mdd->mdd_child,
                                                    op);
        LASSERT(credits > 0);
        return credits;
}

/* XXX: we should calculate it by lsm count, not ost count. */
int mdd_txn_init_credits(const struct lu_env *env, struct mdd_device *mdd)
{
        struct mds_obd *mds = &mdd->mdd_obd_dev->u.mds;
        int ost_count = mds->mds_lov_desc.ld_tgt_count;

        int index_create_credits;
        int index_delete_credits;

        int xattr_credits;
        int log_credits;
        int create_credits;
        int destroy_credits;
        int attr_credits;
        int num_entries;
        int i;

        /* Init credits for each ops. */
        num_entries = ARRAY_SIZE(mdd_txn_descrs);
        LASSERT(num_entries > 0);

        /* Init the basic credits from osd layer. */
        index_create_credits = mdd_credit_get(env, mdd, DTO_INDEX_INSERT);
        index_delete_credits = mdd_credit_get(env, mdd, DTO_INDEX_DELETE);
        log_credits = mdd_credit_get(env, mdd, DTO_LOG_REC);
        attr_credits = mdd_credit_get(env, mdd, DTO_ATTR_SET);
        xattr_credits = mdd_credit_get(env, mdd, DTO_XATTR_SET);
        create_credits = mdd_credit_get(env, mdd, DTO_OBJECT_CREATE);
        destroy_credits = mdd_credit_get(env, mdd, DTO_OBJECT_DELETE);

        /* Calculate the mdd credits. */
        for (i = 0; i < num_entries; i++) {
                int opcode = mdd_txn_descrs[i].mod_op;
                int *c = &mdd_txn_descrs[i].mod_credits;
                switch(opcode) {
                        case MDD_TXN_OBJECT_DESTROY_OP:
                                *c = destroy_credits;
                                break;
                        case MDD_TXN_OBJECT_CREATE_OP:
                                /* OI_INSERT + CREATE OBJECT */
                                *c = index_create_credits + create_credits;
                                break;
                        case MDD_TXN_ATTR_SET_OP:
                                /* ATTR set + XATTR(lsm, lmv) set */
                                *c = attr_credits + xattr_credits;
                                break;
                        case MDD_TXN_XATTR_SET_OP:
                                *c = xattr_credits;
                                break;
                        case MDD_TXN_INDEX_INSERT_OP:
                                *c = index_create_credits;
                                break;
                        case MDD_TXN_INDEX_DELETE_OP:
                                *c = index_delete_credits;
                                break;
                        case MDD_TXN_LINK_OP:
                                *c = index_create_credits;
                                break;
                        case MDD_TXN_UNLINK_OP:
                                /* delete index + Unlink log */
                                *c = index_delete_credits +
                                        log_credits * ost_count;
                                break;
                        case MDD_TXN_RENAME_OP:
                                /* 2 delete index + 1 insert + Unlink log */
                                *c = 2 * index_delete_credits +
                                        index_create_credits +
                                        log_credits * ost_count;
                                break;
                        case MDD_TXN_RENAME_TGT_OP:
                                /* index insert + index delete */
                                *c = index_delete_credits +
                                        index_create_credits;
                                break;
                        case MDD_TXN_CREATE_DATA_OP:
                                /* same as set xattr(lsm) */
                                *c = xattr_credits;
                                break;
                        case MDD_TXN_MKDIR_OP:
                                /* INDEX INSERT + OI INSERT + CREATE_OBJECT_CREDITS
                                 * SET_MD CREDITS is already counted in
                                 * CREATE_OBJECT CREDITS
                                 */
                                 *c = 2 * index_create_credits + create_credits;
                                break;
                        default:
                                CERROR("Invalid op %d init its credit\n",
                                       opcode);
                                LBUG();
                }
        }
        RETURN(0);
}


