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


static struct thandle* mdd_trans_start(const struct lu_env *env,
                                       struct mdd_device *);
static void mdd_trans_stop(const struct lu_env *env,
                           struct mdd_device *mdd, int rc,
                           struct thandle *handle);
static struct dt_object* mdd_object_child(struct mdd_object *o);
static void __mdd_ref_add(const struct lu_env *env, struct mdd_object *obj,
                          struct thandle *handle);
static void __mdd_ref_del(const struct lu_env *env, struct mdd_object *obj,
                          struct thandle *handle);
static int __mdd_lookup(const struct lu_env *env,
                        struct md_object *pobj,
                        const char *name, const struct lu_fid* fid,
                        int mask);
static int __mdd_lookup_locked(const struct lu_env *env,
                               struct md_object *pobj,
                               const char *name, const struct lu_fid* fid,
                               int mask);
static int mdd_exec_permission_lite(const struct lu_env *env,
                                    struct mdd_object *obj);
static int __mdd_permission_internal(const struct lu_env *env,
                                     struct mdd_object *obj,
                                     int mask, int getattr);

static struct md_object_operations mdd_obj_ops;
static struct md_dir_operations    mdd_dir_ops;
static struct lu_object_operations mdd_lu_obj_ops;

static struct lu_context_key       mdd_thread_key;

static const char *mdd_root_dir_name = "root";
static const char dot[] = ".";
static const char dotdot[] = "..";

enum mdd_txn_op {
        MDD_TXN_OBJECT_DESTROY_OP,
        MDD_TXN_OBJECT_CREATE_OP,
        MDD_TXN_ATTR_SET_OP,
        MDD_TXN_XATTR_SET_OP,
        MDD_TXN_INDEX_INSERT_OP,
        MDD_TXN_INDEX_DELETE_OP,
        MDD_TXN_LINK_OP,
        MDD_TXN_UNLINK_OP,
        MDD_TXN_RENAME_OP,
        MDD_TXN_RENAME_TGT_OP,
        MDD_TXN_CREATE_DATA_OP,
        MDD_TXN_MKDIR_OP
};

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

spinlock_t mdd_txn_lock;

static void mdd_txn_param_build(const struct lu_env *env, int op)
{
        int num_entries, i;
        
        /* init credits for each ops */
        num_entries = ARRAY_SIZE(mdd_txn_descrs);
        LASSERT(num_entries > 0);

        spin_lock(&mdd_txn_lock);
        for (i = 0; i < num_entries; i++) {
                if (mdd_txn_descrs[i].mod_op == op) {
                        LASSERT(mdd_txn_descrs[i].mod_credits > 0);
                        mdd_env_info(env)->mti_param.tp_credits = 
                                mdd_txn_descrs[i].mod_credits;
                        spin_unlock(&mdd_txn_lock);
                        return;
                }
        }
        spin_unlock(&mdd_txn_lock);
        CERROR("Wrong txn operation %d\n", op);
        LBUG();
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
        int iam_credits, xattr_credits, log_credits, create_credits;
        int num_entries, i, attr_credits;

        /* Init credits for each ops. */
        num_entries = ARRAY_SIZE(mdd_txn_descrs);
        LASSERT(num_entries > 0);

        /* Init the basic credits from osd layer. */
        iam_credits = mdd_credit_get(env, mdd, INSERT_IAM);
        log_credits = mdd_credit_get(env, mdd, LOG_REC);
        attr_credits = mdd_credit_get(env, mdd, ATTR_SET);
        xattr_credits = mdd_credit_get(env, mdd, XATTR_SET);
        create_credits = mdd_credit_get(env, mdd, CREATE_OBJECT);
        
        /* Calculate the mdd credits. */
        spin_lock(&mdd_txn_lock);
        for (i = 0; i < num_entries; i++) {
                int opcode = mdd_txn_descrs[i].mod_op;
                int *c = &mdd_txn_descrs[i].mod_credits;
                switch(opcode) {
                        case MDD_TXN_OBJECT_DESTROY_OP:
                                *c = 20;
                                break;
                        case MDD_TXN_OBJECT_CREATE_OP:
                                /* OI_INSERT + CREATE OBJECT */
                                *c = iam_credits + create_credits; 
                                break;
                        case MDD_TXN_ATTR_SET_OP:
                                /* ATTR set + XATTR(lsm, lmv) set */
                                *c = attr_credits + xattr_credits;
                                break;
                        case MDD_TXN_XATTR_SET_OP:
                                *c = xattr_credits;
                                break;
                        case MDD_TXN_INDEX_INSERT_OP:
                                *c = iam_credits;
                                break;
                        case MDD_TXN_INDEX_DELETE_OP:
                                *c = iam_credits;
                                break;
                        case MDD_TXN_LINK_OP:
                                *c = iam_credits;
                                break;
                        case MDD_TXN_UNLINK_OP:
                                /* delete IAM + Unlink log */
                                *c = iam_credits + log_credits * ost_count;
                                break;
                        case MDD_TXN_RENAME_OP:
                                /* 2 delete IAM + 1 insert + Unlink log */
                                *c = 3 * iam_credits + log_credits * ost_count;
                                break;
                        case MDD_TXN_RENAME_TGT_OP:
                                /* iam insert + iam delete */
                                *c = 2 * iam_credits;
                                break;
                        case MDD_TXN_CREATE_DATA_OP:
                                /* same as set xattr(lsm) */
                                *c = xattr_credits;
                                break;
                        case MDD_TXN_MKDIR_OP:
                                /* IAM_INSERT + OI_INSERT + CREATE_OBJECT_CREDITS
                                 * SET_MD CREDITS is already counted in 
                                 * CREATE_OBJECT CREDITS 
                                 */
                                 *c = 2 * iam_credits + create_credits;
                                break;
                        default:
                                spin_unlock(&mdd_txn_lock);
                                CERROR("Invalid op %d init its credit\n",
                                       opcode);
                                LBUG();
                }
        }
        spin_unlock(&mdd_txn_lock);
        RETURN(0);        
}

struct lu_buf *mdd_buf_get(const struct lu_env *env, void *area, ssize_t len)
{
        struct lu_buf *buf;

        buf = &mdd_env_info(env)->mti_buf;
        buf->lb_buf = area;
        buf->lb_len = len;
        return buf;
}

const struct lu_buf *mdd_buf_get_const(const struct lu_env *env,
                                       const void *area, ssize_t len)
{
        struct lu_buf *buf;

        buf = &mdd_env_info(env)->mti_buf;
        buf->lb_buf = (void *)area;
        buf->lb_len = len;
        return buf;
}

#define mdd_get_group_info(group_info) do {             \
        atomic_inc(&(group_info)->usage);               \
} while (0)

#define mdd_put_group_info(group_info) do {             \
        if (atomic_dec_and_test(&(group_info)->usage))  \
                groups_free(group_info);                \
} while (0)

#define MDD_NGROUPS_PER_BLOCK       ((int)(CFS_PAGE_SIZE / sizeof(gid_t)))

#define MDD_GROUP_AT(gi, i) \
    ((gi)->blocks[(i) / MDD_NGROUPS_PER_BLOCK][(i) % MDD_NGROUPS_PER_BLOCK])

/* groups_search() is copied from linux kernel! */
/* a simple bsearch */
static int mdd_groups_search(struct group_info *group_info, gid_t grp)
{
        int left, right;

        if (!group_info)
                return 0;

        left = 0;
        right = group_info->ngroups;
        while (left < right) {
                int mid = (left + right) / 2;
                int cmp = grp - MDD_GROUP_AT(group_info, mid);

                if (cmp > 0)
                        left = mid + 1;
                else if (cmp < 0)
                        right = mid;
                else
                        return 1;
        }
        return 0;
}

static int mdd_in_group_p(struct md_ucred *uc, gid_t grp)
{
        int rc = 1;

        if (grp != uc->mu_fsgid) {
                struct group_info *group_info = NULL;

                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD) ||
                    (!uc->mu_ginfo && !uc->mu_identity))
                        if ((grp == uc->mu_suppgids[0]) ||
                            (grp == uc->mu_suppgids[1]))
                                return 1;

                if (uc->mu_ginfo)
                        group_info = uc->mu_ginfo;
                else if (uc->mu_identity)
                        group_info = uc->mu_identity->mi_ginfo;

                if (!group_info)
                        return 0;

                mdd_get_group_info(group_info);
                rc = mdd_groups_search(group_info, grp);
                mdd_put_group_info(group_info);
        }
        return rc;
}

static inline int mdd_permission_internal(const struct lu_env *env,
                                          struct mdd_object *obj, int mask)
{
        return __mdd_permission_internal(env, obj, mask, 1);
}

struct mdd_thread_info *mdd_env_info(const struct lu_env *env)
{
        struct mdd_thread_info *info;

        info = lu_context_key_get(&env->le_ctx, &mdd_thread_key);
        LASSERT(info != NULL);
        return info;
}

static struct lu_object *mdd_object_alloc(const struct lu_env *env,
                                          const struct lu_object_header *hdr,
                                          struct lu_device *d)
{
        struct mdd_object *mdd_obj;

        OBD_ALLOC_PTR(mdd_obj);
        if (mdd_obj != NULL) {
                struct lu_object *o;

                o = mdd2lu_obj(mdd_obj);
                lu_object_init(o, NULL, d);
                mdd_obj->mod_obj.mo_ops = &mdd_obj_ops;
                mdd_obj->mod_obj.mo_dir_ops = &mdd_dir_ops;
                mdd_obj->mod_count = 0;
                o->lo_ops = &mdd_lu_obj_ops;
                return o;
        } else {
                return NULL;
        }
}

static int mdd_object_init(const struct lu_env *env, struct lu_object *o)
{
	struct mdd_device *d = lu2mdd_dev(o->lo_dev);
	struct lu_object  *below;
        struct lu_device  *under;
        ENTRY;

	under = &d->mdd_child->dd_lu_dev;
	below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);

        if (below == NULL)
		RETURN(-ENOMEM);

        lu_object_add(o, below);
        RETURN(0);
}

static int mdd_get_flags(const struct lu_env *env, struct mdd_object *obj);

static int mdd_object_start(const struct lu_env *env, struct lu_object *o)
{
        if (lu_object_exists(o))
                return mdd_get_flags(env, lu2mdd_obj(o));
        else
                return 0;
}

static void mdd_object_free(const struct lu_env *env, struct lu_object *o)
{
        struct mdd_object *mdd = lu2mdd_obj(o);
	
        lu_object_fini(o);
        OBD_FREE_PTR(mdd);
}

static int mdd_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        return (*p)(env, cookie, LUSTRE_MDD_NAME"-object@%p", o);
}

/* orphan handling is here */
static void mdd_object_delete(const struct lu_env *env,
                               struct lu_object *o)
{
        struct mdd_object *mdd_obj = lu2mdd_obj(o);
        struct thandle *handle = NULL;
        ENTRY;

        if (lu2mdd_dev(o->lo_dev)->mdd_orphans == NULL)
                return;

        if (test_bit(LU_OBJECT_ORPHAN, &o->lo_header->loh_flags)) {
                mdd_txn_param_build(env, MDD_TXN_INDEX_DELETE_OP);
                handle = mdd_trans_start(env, lu2mdd_dev(o->lo_dev));
                if (IS_ERR(handle))
                        CERROR("Cannot get thandle\n");
                else {
                        mdd_write_lock(env, mdd_obj);
                        /* let's remove obj from the orphan list */
                        __mdd_orphan_del(env, mdd_obj, handle);
                        mdd_write_unlock(env, mdd_obj);
                        mdd_trans_stop(env, lu2mdd_dev(o->lo_dev),
                                       0, handle);
                }
        }
}

static struct lu_object_operations mdd_lu_obj_ops = {
	.loo_object_init    = mdd_object_init,
	.loo_object_start   = mdd_object_start,
	.loo_object_free    = mdd_object_free,
	.loo_object_print   = mdd_object_print,
        .loo_object_delete  = mdd_object_delete
};

struct mdd_object *mdd_object_find(const struct lu_env *env,
                                   struct mdd_device *d,
                                   const struct lu_fid *f)
{
        struct lu_object *o, *lo;
        struct mdd_object *m;
        ENTRY;

        o = lu_object_find(env, mdd2lu_dev(d)->ld_site, f);
        if (IS_ERR(o))
                m = (struct mdd_object *)o;
        else {
                lo = lu_object_locate(o->lo_header, mdd2lu_dev(d)->ld_type);
                /* remote object can't be located and should be put then */
                if (lo == NULL)
                        lu_object_put(env, o);
                m = lu2mdd_obj(lo);
        }
        RETURN(m);
}

static inline int mdd_is_immutable(struct mdd_object *obj)
{
        return obj->mod_flags & IMMUTE_OBJ;
}

static inline int mdd_is_append(struct mdd_object *obj)
{
        return obj->mod_flags & APPEND_OBJ;
}

static inline void mdd_set_dead_obj(struct mdd_object *obj)
{
        if (obj)
                obj->mod_flags |= DEAD_OBJ;
}

static inline int mdd_is_dead_obj(struct mdd_object *obj)
{
        return obj && obj->mod_flags & DEAD_OBJ;
}

/*Check whether it may create the cobj under the pobj*/
static int mdd_may_create(const struct lu_env *env,
                          struct mdd_object *pobj, struct mdd_object *cobj,
                          int need_check)
{
        int rc = 0;
        ENTRY;

        if (cobj && lu_object_exists(&cobj->mod_obj.mo_lu))
                RETURN(-EEXIST);

        if (mdd_is_dead_obj(pobj))
                RETURN(-ENOENT);

        /*check pobj may create or not*/
        if (need_check)
                rc = mdd_permission_internal(env, pobj,
                                             MAY_WRITE | MAY_EXEC);

        RETURN(rc);
}

static inline int __mdd_la_get(const struct lu_env *env, struct mdd_object *obj,
                               struct lu_attr *la, struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(obj);
        LASSERT(lu_object_exists(mdd2lu_obj(obj)));
        return next->do_ops->do_attr_get(env, next, la, capa);
}

static void mdd_flags_xlate(struct mdd_object *obj, __u32 flags)
{
        obj->mod_flags &= ~(APPEND_OBJ|IMMUTE_OBJ);

        if (flags & LUSTRE_APPEND_FL)
                obj->mod_flags |= APPEND_OBJ;

        if (flags & LUSTRE_IMMUTABLE_FL)
                obj->mod_flags |= IMMUTE_OBJ;
}

static int mdd_get_flags(const struct lu_env *env, struct mdd_object *obj)
{
        struct lu_attr *la = &mdd_env_info(env)->mti_la;
        int rc;

        ENTRY;
        mdd_read_lock(env, obj);
        rc = __mdd_la_get(env, obj, la, BYPASS_CAPA);
        mdd_read_unlock(env, obj);
        if (rc == 0)
                mdd_flags_xlate(obj, la->la_flags);
        RETURN(rc);
}

#define mdd_cap_t(x) (x)

#define MDD_CAP_TO_MASK(x) (1 << (x))

#define mdd_cap_raised(c, flag) (mdd_cap_t(c) & MDD_CAP_TO_MASK(flag))

/* capable() is copied from linux kernel! */
static inline int mdd_capable(struct md_ucred *uc, int cap)
{
        if (mdd_cap_raised(uc->mu_cap, cap))
                return 1;
        return 0;
}

/*
 * It's inline, so penalty for filesystems that don't use sticky bit is
 * minimal.
 */
static inline int mdd_is_sticky(const struct lu_env *env,
                                struct mdd_object *pobj,
                                struct mdd_object *cobj)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc = md_ucred(env);
        int rc;

        rc = __mdd_la_get(env, cobj, tmp_la, BYPASS_CAPA);
        if (rc) {
                return rc;
        } else if (tmp_la->la_uid == uc->mu_fsuid) {
                return 0;
        } else {
                rc = __mdd_la_get(env, pobj, tmp_la, BYPASS_CAPA);
                if (rc)
                        return rc;
                else if (!(tmp_la->la_mode & S_ISVTX))
                        return 0;
                else if (tmp_la->la_uid == uc->mu_fsuid)
                        return 0;
                else
                        return !mdd_capable(uc, CAP_FOWNER);
        }
}

/* Check whether it may delete the cobj under the pobj. */
static int mdd_may_delete(const struct lu_env *env,
                          struct mdd_object *pobj,
                          struct mdd_object *cobj,
                          int is_dir, int need_check)
{
        struct mdd_device *mdd = mdo2mdd(&cobj->mod_obj);
        int rc = 0;
        ENTRY;

        LASSERT(cobj);

        if (!lu_object_exists(&cobj->mod_obj.mo_lu))
                RETURN(-ENOENT);

        if (mdd_is_immutable(cobj) || mdd_is_append(cobj))
                RETURN(-EPERM);

        if (is_dir) {
                if (!S_ISDIR(mdd_object_type(cobj)))
                        RETURN(-ENOTDIR);

                if (lu_fid_eq(mdo2fid(cobj), &mdd->mdd_root_fid))
                        RETURN(-EBUSY);

        } else if (S_ISDIR(mdd_object_type(cobj))) {
                        RETURN(-EISDIR);
        }

        if (pobj) {
                if (mdd_is_dead_obj(pobj))
                        RETURN(-ENOENT);

                if (mdd_is_sticky(env, pobj, cobj))
                        RETURN(-EPERM);

                if (need_check)
                        rc = mdd_permission_internal(env, pobj,
                                                     MAY_WRITE | MAY_EXEC);
        }
        RETURN(rc);
}

/* get only inode attributes */
static int __mdd_iattr_get(const struct lu_env *env,
                           struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        rc = __mdd_la_get(env, mdd_obj, &ma->ma_attr,
                          mdd_object_capa(env, mdd_obj));
        if (rc == 0)
                ma->ma_valid = MA_INODE;
        RETURN(rc);
}

/* get lov EA only */
static int __mdd_lmm_get(const struct lu_env *env,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;
        ENTRY;

        LASSERT(ma->ma_lmm != NULL && ma->ma_lmm_size > 0);
        rc = mdd_get_md(env, mdd_obj, ma->ma_lmm, &ma->ma_lmm_size,
                        MDS_LOV_MD_NAME);
        if (rc > 0) {
                ma->ma_valid |= MA_LOV;
                rc = 0;
        }
        RETURN(rc);
}

/* get lmv EA only*/
static int __mdd_lmv_get(const struct lu_env *env,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;

        rc = mdd_get_md(env, mdd_obj, ma->ma_lmv, &ma->ma_lmv_size,
                        MDS_LMV_MD_NAME);
        if (rc > 0) {
                ma->ma_valid |= MA_LMV;
                rc = 0;
        }
        RETURN(rc);
}

static int mdd_attr_get_internal(const struct lu_env *env,
                                 struct mdd_object *mdd_obj,
                                 struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        if (ma->ma_need & MA_INODE)
                rc = __mdd_iattr_get(env, mdd_obj, ma);

        if (rc == 0 && ma->ma_need & MA_LOV) {
                if (S_ISREG(mdd_object_type(mdd_obj)) ||
                    S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = __mdd_lmm_get(env, mdd_obj, ma);
        }
        if (rc == 0 && ma->ma_need & MA_LMV) {
                if (S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = __mdd_lmv_get(env, mdd_obj, ma);
        }
        CDEBUG(D_INODE, "after getattr rc = %d, ma_valid = "LPX64"\n",
                        rc, ma->ma_valid);
        RETURN(rc);
}

static inline int mdd_attr_get_internal_locked(const struct lu_env *env,
                                               struct mdd_object *mdd_obj,
                                               struct md_attr *ma)
{
        int rc;
        mdd_read_lock(env, mdd_obj);
        rc = mdd_attr_get_internal(env, mdd_obj, ma);
        mdd_read_unlock(env, mdd_obj);
        return rc;
}

/*
 * No permission check is needed.
 */
static int mdd_attr_get(const struct lu_env *env, struct md_object *obj,
                        struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int                rc;

        ENTRY;
        rc = mdd_attr_get_internal_locked(env, mdd_obj, ma);
        RETURN(rc);
}

/*
 * No permission check is needed.
 */
static int mdd_xattr_get(const struct lu_env *env,
                         struct md_object *obj, struct lu_buf *buf,
                         const char *name)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        int rc;

        ENTRY;

        LASSERT(lu_object_exists(&obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(env, mdd_obj);
        rc = next->do_ops->do_xattr_get(env, next, buf, name,
                                        mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);

        RETURN(rc);
}

/*
 * Permission check is done when open,
 * no need check again.
 */
static int mdd_readlink(const struct lu_env *env, struct md_object *obj,
                        struct lu_buf *buf)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        loff_t             pos = 0;
        int                rc;
        ENTRY;

        LASSERT(lu_object_exists(&obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(env, mdd_obj);
        rc = next->do_body_ops->dbo_read(env, next, buf, &pos,
                                         mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);
        RETURN(rc);
}

static int mdd_xattr_list(const struct lu_env *env, struct md_object *obj,
                          struct lu_buf *buf)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        int rc;

        ENTRY;

        LASSERT(lu_object_exists(&obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(env, mdd_obj);
        rc = next->do_ops->do_xattr_list(env, next, buf,
                                         mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);

        RETURN(rc);
}

static int mdd_txn_start_cb(const struct lu_env *env,
                            struct txn_param *param, void *cookie)
{
        return 0;
}

static int mdd_txn_stop_cb(const struct lu_env *env,
                           struct thandle *txn, void *cookie)
{
        struct mdd_device *mdd = cookie;
        struct obd_device *obd = mdd2obd_dev(mdd);

        LASSERT(obd);
        return mds_lov_write_objids(obd);
}

static int mdd_txn_commit_cb(const struct lu_env *env,
                             struct thandle *txn, void *cookie)
{
        return 0;
}

static int mdd_device_init(const struct lu_env *env,
                           struct lu_device *d, struct lu_device *next)
{
        struct mdd_device *mdd = lu2mdd_dev(d);
        struct dt_device  *dt;
        int rc = 0;
        ENTRY;

        mdd->mdd_child = lu2dt_dev(next);

        dt = mdd->mdd_child;
        /* prepare transactions callbacks */
        mdd->mdd_txn_cb.dtc_txn_start = mdd_txn_start_cb;
        mdd->mdd_txn_cb.dtc_txn_stop = mdd_txn_stop_cb;
        mdd->mdd_txn_cb.dtc_txn_commit = mdd_txn_commit_cb;
        mdd->mdd_txn_cb.dtc_cookie = mdd;

        /* init txn credits */
        spin_lock_init(&mdd_txn_lock);
        RETURN(rc);
}

static struct lu_device *mdd_device_fini(const struct lu_env *env,
                                         struct lu_device *d)
{
	struct mdd_device *mdd = lu2mdd_dev(d);
        struct lu_device *next = &mdd->mdd_child->dd_lu_dev;

        return next;
}

static int mdd_mount(const struct lu_env *env, struct mdd_device *mdd)
{
        int rc;
        struct dt_object *root;
        ENTRY;

        dt_txn_callback_add(mdd->mdd_child, &mdd->mdd_txn_cb);
        root = dt_store_open(env, mdd->mdd_child, mdd_root_dir_name,
                             &mdd->mdd_root_fid);
        if (!IS_ERR(root)) {
                LASSERT(root != NULL);
                lu_object_put(env, &root->do_lu);
                rc = orph_index_init(env, mdd);
        } else
                rc = PTR_ERR(root);

        RETURN(rc);
}

static void mdd_device_shutdown(const struct lu_env *env,
                                struct mdd_device *m)
{
        dt_txn_callback_del(m->mdd_child, &m->mdd_txn_cb);
        if (m->mdd_obd_dev)
                mdd_fini_obd(env, m);
        orph_index_fini(env, m);
}

static int mdd_process_config(const struct lu_env *env,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct mdd_device *m    = lu2mdd_dev(d);
        struct dt_device  *dt   = m->mdd_child;
        struct lu_device  *next = &dt->dd_lu_dev;
        int rc;
        ENTRY;

        switch (cfg->lcfg_command) {
        case LCFG_SETUP:
                rc = next->ld_ops->ldo_process_config(env, next, cfg);
                if (rc)
                        GOTO(out, rc);
                dt->dd_ops->dt_conf_get(env, dt, &m->mdd_dt_conf);

                rc = mdd_init_obd(env, m, cfg);
                if (rc) {
                        CERROR("lov init error %d \n", rc);
                        GOTO(out, rc);
                }
                rc = mdd_mount(env, m);
                if (rc)
                        GOTO(out, rc);
                rc = mdd_txn_init_credits(env, m);
                break;
        case LCFG_CLEANUP:
                mdd_device_shutdown(env, m);
        default:
                rc = next->ld_ops->ldo_process_config(env, next, cfg);
                break;
        }
out:
        RETURN(rc);
}
#if 0
static int mdd_lov_set_nextid(const struct lu_env *env,
                              struct mdd_device *mdd)
{
        struct mds_obd *mds = &mdd->mdd_obd_dev->u.mds;
        int rc;
        ENTRY;

        LASSERT(mds->mds_lov_objids != NULL);
        rc = obd_set_info_async(mds->mds_osc_exp, strlen(KEY_NEXT_ID),
                                KEY_NEXT_ID, mds->mds_lov_desc.ld_tgt_count,
                                mds->mds_lov_objids, NULL);

        RETURN(rc);
}

static int mdd_cleanup_unlink_llog(const struct lu_env *env,
                                   struct mdd_device *mdd)
{
        /* XXX: to be implemented! */
        return 0;
}
#endif

static int mdd_recovery_complete(const struct lu_env *env,
                                 struct lu_device *d)
{
        struct mdd_device *mdd = lu2mdd_dev(d);
        struct lu_device *next = &mdd->mdd_child->dd_lu_dev;
        struct obd_device *obd = mdd2obd_dev(mdd);
        int rc;
        ENTRY;
        
        LASSERT(mdd != NULL);
        LASSERT(obd != NULL);
#if 0
        /* XXX: Do we need this in new stack? */
        rc = mdd_lov_set_nextid(env, mdd);
        if (rc) {
                CERROR("mdd_lov_set_nextid() failed %d\n",
                       rc);
                RETURN(rc);
        }

        /* XXX: cleanup unlink. */
        rc = mdd_cleanup_unlink_llog(env, mdd);
        if (rc) {
                CERROR("mdd_cleanup_unlink_llog() failed %d\n",
                       rc);
                RETURN(rc);
        }
#endif
        obd_notify(obd->u.mds.mds_osc_obd, NULL,
                   (obd->obd_async_recov ?
                    OBD_NOTIFY_SYNC_NONBLOCK :
                    OBD_NOTIFY_SYNC), NULL);

        obd->obd_recovering = 0;
        obd->obd_type->typ_dt_ops->o_postrecov(obd);
        
        /* XXX: orphans handling. */
        __mdd_orphan_cleanup(env, mdd);
        rc = next->ld_ops->ldo_recovery_complete(env, next);

        RETURN(rc);
}

struct lu_device_operations mdd_lu_ops = {
	.ldo_object_alloc      = mdd_object_alloc,
        .ldo_process_config    = mdd_process_config,
        .ldo_recovery_complete = mdd_recovery_complete
};

void mdd_write_lock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_write_lock(env, next);
}

void mdd_read_lock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_read_lock(env, next);
}

void mdd_write_unlock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_write_unlock(env, next);
}

void mdd_read_unlock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_read_unlock(env, next);
}

static void mdd_lock2(const struct lu_env *env,
                      struct mdd_object *o0, struct mdd_object *o1)
{
        mdd_write_lock(env, o0);
        mdd_write_lock(env, o1);
}

static void mdd_unlock2(const struct lu_env *env,
                        struct mdd_object *o0, struct mdd_object *o1)
{
        mdd_write_unlock(env, o1);
        mdd_write_unlock(env, o0);
}

static struct thandle* mdd_trans_start(const struct lu_env *env,
                                       struct mdd_device *mdd)
{
        struct txn_param *p = &mdd_env_info(env)->mti_param;

        return mdd_child_ops(mdd)->dt_trans_start(env, mdd->mdd_child, p);
}

static void mdd_trans_stop(const struct lu_env *env,
                           struct mdd_device *mdd, int result,
                           struct thandle *handle)
{
        handle->th_result = result;
        mdd_child_ops(mdd)->dt_trans_stop(env, handle);
}

static int __mdd_object_create(const struct lu_env *env,
                               struct mdd_object *obj, struct md_attr *ma,
                               struct thandle *handle)
{
        struct dt_object *next;
        struct lu_attr *attr = &ma->ma_attr;
        int rc;
        ENTRY;

        if (!lu_object_exists(mdd2lu_obj(obj))) {
                next = mdd_object_child(obj);
                rc = next->do_ops->do_create(env, next, attr, handle);
        } else
                rc = -EEXIST;

        LASSERT(ergo(rc == 0, lu_object_exists(mdd2lu_obj(obj))));

        RETURN(rc);
}

int mdd_attr_set_internal(const struct lu_env *env, struct mdd_object *o,
                          const struct lu_attr *attr, struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(mdd2lu_obj(o)));
        next = mdd_object_child(o);
        return next->do_ops->do_attr_set(env, next, attr, handle,
                                         mdd_object_capa(env, o));
}

int mdd_attr_set_internal_locked(const struct lu_env *env,
                                 struct mdd_object *o,
                                 const struct lu_attr *attr,
                                 struct thandle *handle)
{
        int rc;
        mdd_write_lock(env, o);
        rc = mdd_attr_set_internal(env, o, attr, handle);
        mdd_write_unlock(env, o);
        return rc;
}

static int __mdd_xattr_set(const struct lu_env *env, struct mdd_object *o,
                           const struct lu_buf *buf, const char *name,
                           int fl, struct thandle *handle)
{
        struct dt_object *next;
        struct lustre_capa *capa = mdd_object_capa(env, o);
        int rc = 0;
        ENTRY;

        LASSERT(lu_object_exists(mdd2lu_obj(o)));
        next = mdd_object_child(o);
        if (buf->lb_buf && buf->lb_len > 0) {
                rc = next->do_ops->do_xattr_set(env, next, buf, name, 0, handle,
                                                capa);
        } else if (buf->lb_buf == NULL && buf->lb_len == 0) {
                rc = next->do_ops->do_xattr_del(env, next, name, handle, capa);
        }
        RETURN(rc);
}

/* this gives the same functionality as the code between
 * sys_chmod and inode_setattr
 * chown_common and inode_setattr
 * utimes and inode_setattr
 * This API is ported from mds_fix_attr but remove some unnecesssary stuff.
 * and port to
 */
int mdd_fix_attr(const struct lu_env *env, struct mdd_object *obj,
                 struct lu_attr *la)
{
        struct lu_attr   *tmp_la     = &mdd_env_info(env)->mti_la;
        struct md_ucred  *uc         = md_ucred(env);
        time_t            now        = CURRENT_SECONDS;
        int               rc;
        ENTRY;

        if (!la->la_valid)
                RETURN(0);

        /* Do not permit change file type */
        if (la->la_valid & LA_TYPE)
                RETURN(-EPERM);

        /* They should not be processed by setattr */
        if (la->la_valid & (LA_NLINK | LA_RDEV | LA_BLKSIZE))
                RETURN(-EPERM);

        rc = __mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        if (mdd_is_immutable(obj) || mdd_is_append(obj)) {

                /*
                 * If only change flags of the object, we should
                 * let it pass, but also need capability check
                 * here if (!capable(CAP_LINUX_IMMUTABLE)),
                 * fix it, when implement capable in mds
                 */
                if (la->la_valid & ~LA_FLAGS)
                        RETURN(-EPERM);

                if (!mdd_capable(uc, CAP_LINUX_IMMUTABLE))
                        RETURN(-EPERM);

                if ((uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CAP_FOWNER))
                        RETURN(-EPERM);

                /*
                 * According to Ext3 implementation on this, the
                 * Ctime will be changed, but not clear why?
                 */
                la->la_ctime = now;
                la->la_valid |= LA_CTIME;
                RETURN(0);
        }

        /* Check for setting the obj time. */
        if ((la->la_valid & (LA_MTIME | LA_ATIME | LA_CTIME)) &&
            !(la->la_valid & ~(LA_MTIME | LA_ATIME | LA_CTIME))) {
                rc = __mdd_permission_internal(env, obj, MAY_WRITE, 0);
                if (rc)
                        RETURN(rc);
        }

        /* Make sure a caller can chmod. */
        if (la->la_valid & LA_MODE) {
                /*
                 * Bypass la_vaild == LA_MODE,
                 * this is for changing file with SUID or SGID.
                 */
                if ((la->la_valid & ~LA_MODE) &&
                    (uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CAP_FOWNER))
                        RETURN(-EPERM);

                if (la->la_mode == (umode_t) -1)
                        la->la_mode = tmp_la->la_mode;
                else
                        la->la_mode = (la->la_mode & S_IALLUGO) |
                                      (tmp_la->la_mode & ~S_IALLUGO);

                /* Also check the setgid bit! */
                if (!mdd_in_group_p(uc, (la->la_valid & LA_GID) ? la->la_gid :
                                tmp_la->la_gid) && !mdd_capable(uc, CAP_FSETID))
                        la->la_mode &= ~S_ISGID;
        } else {
               la->la_mode = tmp_la->la_mode;
        }

        /* Make sure a caller can chown. */
        if (la->la_valid & LA_UID) {
                if (la->la_uid == (uid_t) -1)
                        la->la_uid = tmp_la->la_uid;
                if (((uc->mu_fsuid != tmp_la->la_uid) ||
                    (la->la_uid != tmp_la->la_uid)) &&
                    !mdd_capable(uc, CAP_CHOWN))
                        RETURN(-EPERM);

                /*
                 * If the user or group of a non-directory has been
                 * changed by a non-root user, remove the setuid bit.
                 * 19981026 David C Niemi <niemi@tux.org>
                 *
                 * Changed this to apply to all users, including root,
                 * to avoid some races. This is the behavior we had in
                 * 2.0. The check for non-root was definitely wrong
                 * for 2.2 anyway, as it should have been using
                 * CAP_FSETID rather than fsuid -- 19990830 SD.
                 */
                if (((tmp_la->la_mode & S_ISUID) == S_ISUID) &&
                    !S_ISDIR(tmp_la->la_mode)) {
                        la->la_mode &= ~S_ISUID;
                        la->la_valid |= LA_MODE;
                }
        }

        /* Make sure caller can chgrp. */
        if (la->la_valid & LA_GID) {
                if (la->la_gid == (gid_t) -1)
                        la->la_gid = tmp_la->la_gid;
                if (((uc->mu_fsuid != tmp_la->la_uid) ||
                    ((la->la_gid != tmp_la->la_gid) &&
                    !mdd_in_group_p(uc, la->la_gid))) &&
                    !mdd_capable(uc, CAP_CHOWN))
                        RETURN(-EPERM);

                /*
                 * Likewise, if the user or group of a non-directory
                 * has been changed by a non-root user, remove the
                 * setgid bit UNLESS there is no group execute bit
                 * (this would be a file marked for mandatory
                 * locking).  19981026 David C Niemi <niemi@tux.org>
                 *
                 * Removed the fsuid check (see the comment above) --
                 * 19990830 SD.
                 */
                if (((tmp_la->la_mode & (S_ISGID | S_IXGRP)) ==
                     (S_ISGID | S_IXGRP)) && !S_ISDIR(tmp_la->la_mode)) {
                        la->la_mode &= ~S_ISGID;
                        la->la_valid |= LA_MODE;
                }
        }

        /* For tuncate (or setsize), we should have MAY_WRITE perm */
        if (la->la_valid & (LA_SIZE | LA_BLOCKS)) {
                rc = mdd_permission_internal(env, obj, MAY_WRITE);
                if (rc)
                        RETURN(rc);

                /*
                 * For the "Size-on-MDS" setattr update, merge coming
                 * attributes with the set in the inode. BUG 10641
                 */
                if ((la->la_valid & LA_ATIME) &&
                    (la->la_atime < tmp_la->la_atime))
                        la->la_valid &= ~LA_ATIME;

                if ((la->la_valid & LA_CTIME) &&
                    (la->la_ctime < tmp_la->la_ctime))
                        la->la_valid &= ~(LA_MTIME | LA_CTIME);

                if (!(la->la_valid & LA_MTIME) && (now > tmp_la->la_mtime)) {
                        la->la_mtime = now;
                        la->la_valid |= LA_MTIME;
                }
        }

        /* For last, ctime must be fixed */
        if (!(la->la_valid & LA_CTIME) && (now > tmp_la->la_ctime)) {
                la->la_ctime = now;
                la->la_valid |= LA_CTIME;
        }

        RETURN(0);
}

/* set attr and LOV EA at once, return updated attr */
static int mdd_attr_set(const struct lu_env *env, struct md_object *obj,
                        const struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        struct lov_mds_md *lmm = NULL;
        int  rc = 0, lmm_size = 0, max_size = 0;
        struct lu_attr *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_ATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));
        /*TODO: add lock here*/
        /* start a log jounal handle if needed */
        if (S_ISREG(mdd_object_type(mdd_obj)) &&
            ma->ma_attr.la_valid & (LA_UID | LA_GID)) {
                max_size = mdd_lov_mdsize(env, mdd);
                OBD_ALLOC(lmm, max_size);
                if (lmm == NULL)
                        GOTO(cleanup, rc = -ENOMEM);

                rc = mdd_get_md_locked(env, mdd_obj, lmm, &lmm_size,
                                MDS_LOV_MD_NAME);

                if (rc < 0)
                        GOTO(cleanup, rc);
        }

        if (ma->ma_attr.la_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime "LPU64", ctime "LPU64"\n",
                       ma->ma_attr.la_mtime, ma->ma_attr.la_ctime);

        *la_copy = ma->ma_attr;
        mdd_write_lock(env, mdd_obj);
        rc = mdd_fix_attr(env, mdd_obj, la_copy);
        mdd_write_unlock(env, mdd_obj);
        if (rc)
                GOTO(cleanup, rc);

        if (la_copy->la_valid & LA_FLAGS) {
                rc = mdd_attr_set_internal_locked(env, mdd_obj, la_copy,
                                                  handle);
                if (rc == 0)
                        mdd_flags_xlate(mdd_obj, la_copy->la_flags);
        } else if (la_copy->la_valid) {            /* setattr */
                rc = mdd_attr_set_internal_locked(env, mdd_obj, la_copy,
                                                  handle);
                /* journal chown/chgrp in llog, just like unlink */
                if (rc == 0 && lmm_size){
                        /*TODO set_attr llog */
                }
        }

        if (rc == 0 && ma->ma_valid & MA_LOV) {
                umode_t mode;

                mode = mdd_object_type(mdd_obj);
                if (S_ISREG(mode) || S_ISDIR(mode)) {
                        /*TODO check permission*/
                        rc = mdd_lov_set_md(env, NULL, mdd_obj, ma->ma_lmm,
                                            ma->ma_lmm_size, handle, 1);
                }

        }
cleanup:
        mdd_trans_stop(env, mdd, rc, handle);
        if (rc == 0 && lmm_size) {
                /*set obd attr, if needed*/
                rc = mdd_lov_setattr_async(env, mdd_obj, lmm, lmm_size);
        }
        if (lmm != NULL) {
                OBD_FREE(lmm, max_size);
        }

        RETURN(rc);
}

int mdd_xattr_set_txn(const struct lu_env *env, struct mdd_object *obj,
                      const struct lu_buf *buf, const char *name, int fl,
                      struct thandle *handle)
{
        int  rc;
        ENTRY;

        mdd_write_lock(env, obj);
        rc = __mdd_xattr_set(env, obj, buf, name, fl, handle);
        mdd_write_unlock(env, obj);

        RETURN(rc);
}

static int mdd_xattr_sanity_check(const struct lu_env *env,
                                  struct mdd_object *obj)
{
        struct lu_attr  *tmp_la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc     = md_ucred(env);
        int rc;
        ENTRY;

        if (mdd_is_immutable(obj) || mdd_is_append(obj))
                RETURN(-EPERM);

        mdd_read_lock(env, obj);
        rc = __mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        mdd_read_unlock(env, obj);
        if (rc)
                RETURN(rc);

        if ((uc->mu_fsuid != tmp_la->la_uid) && !mdd_capable(uc, CAP_FOWNER))
                RETURN(-EPERM);

        RETURN(rc);
}

static int mdd_xattr_set(const struct lu_env *env, struct md_object *obj,
                         const struct lu_buf *buf, const char *name, int fl)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        rc = mdd_xattr_sanity_check(env, mdd_obj);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, MDD_TXN_XATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = mdd_xattr_set_txn(env, md2mdd_obj(obj), buf, name,
                               fl, handle);
#ifdef HAVE_SPLIT_SUPPORT
        if (rc == 0) {
                /* very ugly hack, if setting lmv, it means splitting
                 * sucess, we should return -ERESTART to notify the
                 * client, so transno for this splitting should be
                 * zero according to the replay rules. so return -ERESTART
                 * here let mdt trans stop callback know this.
                 */
                 if (strncmp(name, MDS_LMV_MD_NAME, strlen(name)) == 0)
                        rc = -ERESTART;
        }
#endif
        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

static int __mdd_xattr_del(const struct lu_env *env,struct mdd_device *mdd,
                           struct mdd_object *obj,
                           const char *name, struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(mdd2lu_obj(obj)));
        next = mdd_object_child(obj);
        return next->do_ops->do_xattr_del(env, next, name, handle,
                                          mdd_object_capa(env, obj));
}

int mdd_xattr_del(const struct lu_env *env, struct md_object *obj,
                  const char *name)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        rc = mdd_xattr_sanity_check(env, mdd_obj);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, MDD_TXN_XATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = __mdd_xattr_del(env, mdd, md2mdd_obj(obj), name, handle);
        mdd_write_unlock(env, mdd_obj);

        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

static int __mdd_index_insert_only(const struct lu_env *env,
                                   struct mdd_object *pobj,
                                   const struct lu_fid *lf,
                                   const char *name, struct thandle *th,
                                   struct lustre_capa *capa)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

        if (dt_try_as_dir(env, next))
                rc = next->do_index_ops->dio_insert(env, next,
                                         (struct dt_rec *)lf,
                                         (struct dt_key *)name, th, capa);
        else
                rc = -ENOTDIR;
        RETURN(rc);
}

/* insert new index, add reference if isdir, update times */
static int __mdd_index_insert(const struct lu_env *env,
                             struct mdd_object *pobj, const struct lu_fid *lf,
                             const char *name, int isdir, struct thandle *th,
                             struct lustre_capa *capa)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

#if 0
        struct lu_attr   *la = &mdd_env_info(env)->mti_la;
#endif

        if (dt_try_as_dir(env, next))
                rc = next->do_index_ops->dio_insert(env, next,
                                                    (struct dt_rec *)lf,
                                                    (struct dt_key *)name,
                                                    th, capa);
        else
                rc = -ENOTDIR;

        if (rc == 0) {
                if (isdir)
                        __mdd_ref_add(env, pobj, th);
#if 0
                la->la_valid = LA_MTIME|LA_CTIME;
                la->la_atime = ma->ma_attr.la_atime;
                la->la_ctime = ma->ma_attr.la_ctime;
                rc = mdd_attr_set_internal(env, mdd_obj, la, handle);
#endif
        }
        return rc;
}

static int __mdd_index_delete(const struct lu_env *env,
                              struct mdd_object *pobj, const char *name,
                              int is_dir, struct thandle *handle,
                              struct lustre_capa *capa)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

        if (dt_try_as_dir(env, next)) {
                rc = next->do_index_ops->dio_delete(env, next,
                                                    (struct dt_key *)name,
                                                    handle, capa);
                if (rc == 0 && is_dir)
                        __mdd_ref_del(env, pobj, handle);
        } else
                rc = -ENOTDIR;
        RETURN(rc);
}

static int mdd_link_sanity_check(const struct lu_env *env,
                                 struct mdd_object *tgt_obj,
                                 struct mdd_object *src_obj)
{
        int rc = 0;
        ENTRY;

        if (tgt_obj) {
                rc = mdd_may_create(env, tgt_obj, NULL, 1);
                if (rc)
                        RETURN(rc);
        }

        if (S_ISDIR(mdd_object_type(src_obj)))
                RETURN(-EPERM);

        if (mdd_is_immutable(src_obj) || mdd_is_append(src_obj))
                RETURN(-EPERM);

        RETURN(rc);
}

static int mdd_link(const struct lu_env *env, struct md_object *tgt_obj,
                    struct md_object *src_obj, const char *name,
                    struct md_attr *ma)
{
        struct mdd_object *mdd_tobj = md2mdd_obj(tgt_obj);
        struct mdd_object *mdd_sobj = md2mdd_obj(src_obj);
        struct mdd_device *mdd = mdo2mdd(src_obj);
        struct lu_attr    *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_LINK_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock2(env, mdd_tobj, mdd_sobj);

        rc = mdd_link_sanity_check(env, mdd_tobj, mdd_sobj);
        if (rc)
                GOTO(out, rc);

        rc = __mdd_index_insert_only(env, mdd_tobj, mdo2fid(mdd_sobj),
                                     name, handle,
                                     mdd_object_capa(env, mdd_tobj));
        if (rc == 0)
                __mdd_ref_add(env, mdd_sobj, handle);

        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME;
        rc = mdd_attr_set_internal(env, mdd_sobj, la_copy, handle);
        if (rc)
                GOTO(out, rc);

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(env, mdd_tobj, la_copy, handle);

out:
        mdd_unlock2(env, mdd_tobj, mdd_sobj);
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

/*
 * Check that @dir contains no entries except (possibly) dot and dotdot.
 *
 * Returns:
 *
 *             0        empty
 *    -ENOTEMPTY        not empty
 *           -ve        other error
 *
 */
static int mdd_dir_is_empty(const struct lu_env *env,
                            struct mdd_object *dir)
{
        struct dt_it     *it;
        struct dt_object *obj;
        struct dt_it_ops *iops;
        int result;
        ENTRY;

        obj = mdd_object_child(dir);
        iops = &obj->do_index_ops->dio_it;
        it = iops->init(env, obj, 0);
        if (it != NULL) {
                result = iops->get(env, it, (const void *)"");
                if (result > 0) {
                        int i;
                        for (result = 0, i = 0; result == 0 && i < 3; ++i)
                                result = iops->next(env, it);
                        if (result == 0)
                                result = -ENOTEMPTY;
                        else if (result == +1)
                                result = 0;
                } else if (result == 0)
                        /*
                         * Huh? Index contains no zero key?
                         */
                        result = -EIO;

                iops->put(env, it);
                iops->fini(env, it);
        } else
                result = -ENOMEM;
        RETURN(result);
}

/* return md_attr back,
 * if it is last unlink then return lov ea + llog cookie*/
int __mdd_object_kill(const struct lu_env *env,
                      struct mdd_object *obj,
                      struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        mdd_set_dead_obj(obj);
        if (S_ISREG(mdd_object_type(obj))) {
                /* Return LOV & COOKIES unconditionally here. We clean evth up.
                 * Caller must be ready for that. */
                rc = __mdd_lmm_get(env, obj, ma);
                if ((ma->ma_valid & MA_LOV))
                        rc = mdd_unlink_log(env, mdo2mdd(&obj->mod_obj),
                                            obj, ma);
        }
        RETURN(rc);
}

/* caller should take a lock before calling */
static int __mdd_finish_unlink(const struct lu_env *env,
                               struct mdd_object *obj, struct md_attr *ma,
                               struct thandle *th)
{
        int rc;
        ENTRY;

        rc = __mdd_iattr_get(env, obj, ma);
        if (rc == 0 && ma->ma_attr.la_nlink == 0) {
                /* add new orphan and the object
                 * will be deleted during the object_put() */
                if (__mdd_orphan_add(env, obj, th) == 0)
                        set_bit(LU_OBJECT_ORPHAN,
                                &mdd2lu_obj(obj)->lo_header->loh_flags);

                if (obj->mod_count == 0)
                        rc = __mdd_object_kill(env, obj, ma);
        }
        RETURN(rc);
}

static int mdd_unlink_sanity_check(const struct lu_env *env,
                                   struct mdd_object *pobj,
                                   struct mdd_object *cobj,
                                   struct md_attr *ma)
{
        struct dt_object  *dt_cobj  = mdd_object_child(cobj);
        int rc = 0;
        ENTRY;

        rc = mdd_may_delete(env, pobj, cobj,
                            S_ISDIR(ma->ma_attr.la_mode), 1);
        if (rc)
                RETURN(rc);

        if (S_ISDIR(mdd_object_type(cobj))) {
                if (dt_try_as_dir(env, dt_cobj))
                        rc = mdd_dir_is_empty(env, cobj);
                else
                        rc = -ENOTDIR;
        }

        RETURN(rc);
}

static int mdd_unlink(const struct lu_env *env,
                      struct md_object *pobj, struct md_object *cobj,
                      const char *name, struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object *mdd_cobj = md2mdd_obj(cobj);
        struct lu_attr    *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct thandle    *handle;
        int rc, is_dir;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_UNLINK_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock2(env, mdd_pobj, mdd_cobj);

        rc = mdd_unlink_sanity_check(env, mdd_pobj, mdd_cobj, ma);
        if (rc)
                GOTO(cleanup, rc);

        is_dir = S_ISDIR(lu_object_attr(&cobj->mo_lu));
        rc = __mdd_index_delete(env, mdd_pobj, name, is_dir, handle,
                                mdd_object_capa(env, mdd_pobj));
        if (rc)
                GOTO(cleanup, rc);

        __mdd_ref_del(env, mdd_cobj, handle);
        *la_copy = ma->ma_attr;
        if (is_dir) {
                /* unlink dot */
                __mdd_ref_del(env, mdd_cobj, handle);
        } else {
                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_set_internal(env, mdd_cobj, la_copy, handle);
                if (rc)
                        GOTO(cleanup, rc);
        }

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(env, mdd_pobj, la_copy, handle);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_finish_unlink(env, mdd_cobj, ma, handle);

        if (rc == 0)
                obd_set_info_async(mdd2obd_dev(mdd)->u.mds.mds_osc_exp,
                                   strlen("unlinked"), "unlinked", 0,
                                   NULL, NULL);

cleanup:
        mdd_unlock2(env, mdd_pobj, mdd_cobj);
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

/* partial unlink */
static int mdd_ref_del(const struct lu_env *env, struct md_object *obj,
                       struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_UNLINK_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_write_lock(env, mdd_obj);

        rc = mdd_unlink_sanity_check(env, NULL, mdd_obj, ma);
        if (rc)
                GOTO(cleanup, rc);

        __mdd_ref_del(env, mdd_obj, handle);

        if (S_ISDIR(lu_object_attr(&obj->mo_lu))) {
                /* unlink dot */
                __mdd_ref_del(env, mdd_obj, handle);
        }

        rc = __mdd_finish_unlink(env, mdd_obj, ma, handle);

        EXIT;
cleanup:
        mdd_write_unlock(env, mdd_obj);
        mdd_trans_stop(env, mdd, rc, handle);
        return rc;
}

static int mdd_parent_fid(const struct lu_env *env,
                          struct mdd_object *obj,
                          struct lu_fid *fid)
{
        return __mdd_lookup_locked(env, &obj->mod_obj,
                                   dotdot, fid, 0);
}

/*
 * return 1: if lf is the fid of the ancestor of p1;
 * return 0: if not;
 *
 * return -EREMOTE: if remote object is found, in this
 * case fid of remote object is saved to @pf;
 *
 * otherwise: values < 0, errors.
 */
static int mdd_is_parent(const struct lu_env *env,
                         struct mdd_device *mdd,
                         struct mdd_object *p1,
                         const struct lu_fid *lf,
                         struct lu_fid *pf)
{
        struct mdd_object *parent = NULL;
        struct lu_fid *pfid;
        int rc;
        ENTRY;

        LASSERT(!lu_fid_eq(mdo2fid(p1), lf));
        pfid = &mdd_env_info(env)->mti_fid;

        /* Do not lookup ".." in root, they do not exist there. */
        if (lu_fid_eq(mdo2fid(p1), &mdd->mdd_root_fid))
                RETURN(0);

        for(;;) {
                rc = mdd_parent_fid(env, p1, pfid);
                if (rc)
                        GOTO(out, rc);
                if (lu_fid_eq(pfid, &mdd->mdd_root_fid))
                        GOTO(out, rc = 0);
                if (lu_fid_eq(pfid, lf))
                        GOTO(out, rc = 1);
                if (parent)
                        mdd_object_put(env, parent);
                parent = mdd_object_find(env, mdd, pfid);

                /* cross-ref parent */
                if (parent == NULL) {
                        if (pf != NULL)
                                *pf = *pfid;
                        GOTO(out, rc = EREMOTE);
                } else if (IS_ERR(parent))
                        GOTO(out, rc = PTR_ERR(parent));
                p1 = parent;
        }
        EXIT;
out:
        if (parent && !IS_ERR(parent))
                mdd_object_put(env, parent);
        return rc;
}

static int mdd_rename_lock(const struct lu_env *env,
                           struct mdd_device *mdd,
                           struct mdd_object *src_pobj,
                           struct mdd_object *tgt_pobj)
{
        int rc;
        ENTRY;

        if (src_pobj == tgt_pobj) {
                mdd_write_lock(env, src_pobj);
                RETURN(0);
        }

        /* compared the parent child relationship of src_p&tgt_p */
        if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(src_pobj))){
                mdd_lock2(env, src_pobj, tgt_pobj);
                RETURN(0);
        } else if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(tgt_pobj))) {
                mdd_lock2(env, tgt_pobj, src_pobj);
                RETURN(0);
        }

        rc = mdd_is_parent(env, mdd, src_pobj, mdo2fid(tgt_pobj), NULL);
        if (rc < 0)
                RETURN(rc);

        if (rc == 1) {
                mdd_lock2(env, tgt_pobj, src_pobj);
                RETURN(0);
        }

        mdd_lock2(env, src_pobj, tgt_pobj);

        RETURN(0);
}

static void mdd_rename_unlock(const struct lu_env *env,
                              struct mdd_object *src_pobj,
                              struct mdd_object *tgt_pobj)
{
        mdd_write_unlock(env, src_pobj);
        if (src_pobj != tgt_pobj)
                mdd_write_unlock(env, tgt_pobj);
}

static int mdd_rename_sanity_check(const struct lu_env *env,
                                   struct mdd_object *src_pobj,
                                   struct mdd_object *tgt_pobj,
                                   const struct lu_fid *sfid,
                                   int src_is_dir,
                                   struct mdd_object *tobj)
{
        int rc;
        ENTRY;

        if (mdd_is_dead_obj(src_pobj))
                RETURN(-ENOENT);

        /* The sobj maybe on the remote, check parent permission only here */
        rc = mdd_permission_internal(env, src_pobj, MAY_WRITE | MAY_EXEC);
        if (rc)
                RETURN(rc);

        if (!tobj) {
                rc = mdd_may_create(env, tgt_pobj, NULL,
                                    (src_pobj != tgt_pobj));
        } else {
                mdd_read_lock(env, tobj);
                rc = mdd_may_delete(env, tgt_pobj, tobj, src_is_dir,
                                    (src_pobj != tgt_pobj));
                if (rc == 0)
                        if (S_ISDIR(mdd_object_type(tobj))
                            && mdd_dir_is_empty(env, tobj))
                                rc = -ENOTEMPTY;
                mdd_read_unlock(env, tobj);
        }
        
        RETURN(rc);
}
/* src object can be remote that is why we use only fid and type of object */
static int mdd_rename(const struct lu_env *env,
                      struct md_object *src_pobj, struct md_object *tgt_pobj,
                      const struct lu_fid *lf, const char *sname,
                      struct md_object *tobj, const char *tname,
                      struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(src_pobj);
        struct mdd_object *mdd_spobj = md2mdd_obj(src_pobj);
        struct mdd_object *mdd_tpobj = md2mdd_obj(tgt_pobj);
        struct mdd_object *mdd_sobj = NULL;
        struct mdd_object *mdd_tobj = NULL;
        struct lu_attr    *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct thandle *handle;
        int is_dir;
        int rc;
        ENTRY;

        LASSERT(ma->ma_attr.la_mode & S_IFMT);
        is_dir = S_ISDIR(ma->ma_attr.la_mode);
        if (ma->ma_attr.la_valid & LA_FLAGS &&
            ma->ma_attr.la_flags & (LUSTRE_APPEND_FL | LUSTRE_IMMUTABLE_FL))
                RETURN(-EPERM);

        if (tobj)
                mdd_tobj = md2mdd_obj(tobj);

        mdd_txn_param_build(env, MDD_TXN_RENAME_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        /*FIXME: Should consider tobj and sobj too in rename_lock*/
        rc = mdd_rename_lock(env, mdd, mdd_spobj, mdd_tpobj);
        if (rc)
                GOTO(cleanup_unlocked, rc);

        rc = mdd_rename_sanity_check(env, mdd_spobj, mdd_tpobj,
                                     lf, is_dir, mdd_tobj);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_delete(env, mdd_spobj, sname, is_dir, handle,
                                mdd_object_capa(env, mdd_spobj));
        if (rc)
                GOTO(cleanup, rc);

        /* tobj can be remote one,
         * so we do index_delete unconditionally and -ENOENT is allowed */
        rc = __mdd_index_delete(env, mdd_tpobj, tname, is_dir, handle,
                                mdd_object_capa(env, mdd_tpobj));
        if (rc != 0 && rc != -ENOENT)
                GOTO(cleanup, rc);

        rc = __mdd_index_insert(env, mdd_tpobj, lf, tname, is_dir, handle,
                                mdd_object_capa(env, mdd_tpobj));
        if (rc)
                GOTO(cleanup, rc);
        
        mdd_sobj = mdd_object_find(env, mdd, lf);
        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME;
        if (mdd_sobj) {
                /*XXX: how to update ctime for remote sobj? */
                rc = mdd_attr_set_internal_locked(env, mdd_sobj, la_copy, handle);
                if (rc)
                        GOTO(cleanup, rc);
        }
        if (tobj && lu_object_exists(&tobj->mo_lu)) {
                mdd_write_lock(env, mdd_tobj);
                __mdd_ref_del(env, mdd_tobj, handle);
                /* remove dot reference */
                if (is_dir)
                        __mdd_ref_del(env, mdd_tobj, handle);

                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_set_internal(env, mdd_tobj, la_copy, handle);
                if (rc)
                        GOTO(cleanup, rc);

                rc = __mdd_finish_unlink(env, mdd_tobj, ma, handle);
                mdd_write_unlock(env, mdd_tobj);
                if (rc)
                        GOTO(cleanup, rc);
        }

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(env, mdd_spobj, la_copy, handle);
        if (rc)
                GOTO(cleanup, rc);

        if (mdd_spobj != mdd_tpobj) {
                la_copy->la_valid = LA_CTIME | LA_MTIME;
                rc = mdd_attr_set_internal(env, mdd_tpobj, la_copy, handle);
        }

cleanup:
        mdd_rename_unlock(env, mdd_spobj, mdd_tpobj);
cleanup_unlocked:
        mdd_trans_stop(env, mdd, rc, handle);
        if (mdd_sobj)
                mdd_object_put(env, mdd_sobj);
        RETURN(rc);
}

static int
__mdd_lookup(const struct lu_env *env, struct md_object *pobj,
             const char *name, const struct lu_fid* fid, int mask)
{
        struct mdd_object   *mdd_obj = md2mdd_obj(pobj);
        struct dt_object    *dir = mdd_object_child(mdd_obj);
        struct dt_rec       *rec = (struct dt_rec *)fid;
        const struct dt_key *key = (const struct dt_key *)name;
        int rc;
        ENTRY;

        if (mdd_is_dead_obj(mdd_obj))
                RETURN(-ESTALE);

        rc = lu_object_exists(mdd2lu_obj(mdd_obj));
        if (rc == 0)
                RETURN(-ESTALE);
        else if (rc < 0) {
                CERROR("Object "DFID" locates on remote server\n",
                        PFID(mdo2fid(mdd_obj)));
                LBUG();
        }

        if (mask == MAY_EXEC)
                rc = mdd_exec_permission_lite(env, mdd_obj);
        else
                rc = mdd_permission_internal(env, mdd_obj, mask);
        if (rc)
                RETURN(rc);

        if (S_ISDIR(mdd_object_type(mdd_obj)) && dt_try_as_dir(env, dir))
                rc = dir->do_index_ops->dio_lookup(env, dir, rec, key,
                                                 mdd_object_capa(env, mdd_obj));
        else
                rc = -ENOTDIR;

        RETURN(rc);
}

static int
__mdd_lookup_locked(const struct lu_env *env, struct md_object *pobj,
                    const char *name, const struct lu_fid* fid, int mask)
{
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        int rc;

        mdd_read_lock(env, mdd_obj);
        rc = __mdd_lookup(env, pobj, name, fid, mask);
        mdd_read_unlock(env, mdd_obj);

       return rc;
}

static int mdd_lookup(const struct lu_env *env,
                      struct md_object *pobj, const char *name,
                      struct lu_fid* fid)
{
        int rc;
        ENTRY;
        rc = __mdd_lookup_locked(env, pobj, name, fid, MAY_EXEC);
        RETURN(rc);
}

/*
 * No permission check is needed.
 *
 * returns 1: if fid is ancestor of @mo;
 * returns 0: if fid is not a ancestor of @mo;
 *
 * returns EREMOTE if remote object is found, fid of remote object is saved to
 * @fid;
 *
 * returns < 0: if error
 */
static int mdd_is_subdir(const struct lu_env *env,
                         struct md_object *mo, const struct lu_fid *fid,
                         struct lu_fid *sfid)
{
        struct mdd_device *mdd = mdo2mdd(mo);
        int rc;
        ENTRY;

        if (!S_ISDIR(mdd_object_type(md2mdd_obj(mo))))
                RETURN(0);

        rc = mdd_is_parent(env, mdd, md2mdd_obj(mo), fid, sfid);

        RETURN(rc);
}

static int __mdd_object_initialize(const struct lu_env *env,
                                   const struct lu_fid *pfid,
                                   struct mdd_object *child,
                                   struct md_attr *ma, struct thandle *handle)
{
        int rc;
        ENTRY;

        /* update attributes for child.
         * FIXME:
         *  (1) the valid bits should be converted between Lustre and Linux;
         *  (2) maybe, the child attributes should be set in OSD when creation.
         */

        rc = mdd_attr_set_internal(env, child, &ma->ma_attr, handle);
        if (rc != 0)
                RETURN(rc);

        if (S_ISDIR(ma->ma_attr.la_mode)) {
                /* add . and .. for newly created dir */
                __mdd_ref_add(env, child, handle);
                rc = __mdd_index_insert_only(env, child, mdo2fid(child),
                                             dot, handle, BYPASS_CAPA);
                if (rc == 0) {
                        rc = __mdd_index_insert_only(env, child, pfid,
                                                     dotdot, handle,
                                                     BYPASS_CAPA);
                        if (rc != 0) {
                                int rc2;

                                rc2 = __mdd_index_delete(env, child, dot, 0,
                                                         handle, BYPASS_CAPA);
                                if (rc2 != 0)
                                        CERROR("Failure to cleanup after dotdot"
                                               " creation: %d (%d)\n", rc2, rc);
                                else
                                        __mdd_ref_del(env, child, handle);
                        }
                }
        }
        RETURN(rc);
}

/*
 * The permission has been checked when obj created,
 * no need check again.
 */
static int mdd_cd_sanity_check(const struct lu_env *env,
                               struct mdd_object *obj)
{
        int rc = 0;
        ENTRY;

        /* EEXIST check */
        if (!obj || mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

#if 0
        mdd_read_lock(env, obj);
        rc = mdd_permission_internal(env, obj, MAY_WRITE);
        mdd_read_unlock(env, obj);
#endif

        RETURN(rc);

}

static int mdd_create_data(const struct lu_env *env,
                           struct md_object *pobj, struct md_object *cobj,
                           const struct md_create_spec *spec,
                           struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(cobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);/* XXX maybe NULL */
        struct mdd_object *son = md2mdd_obj(cobj);
        struct lu_attr    *attr = &ma->ma_attr;
        struct lov_mds_md *lmm = NULL;
        int                lmm_size = 0;
        struct thandle    *handle;
        int                rc;
        ENTRY;

        rc = mdd_cd_sanity_check(env, son);
        if (rc)
                RETURN(rc);

        if (spec->sp_cr_flags & MDS_OPEN_DELAY_CREATE ||
                        !(spec->sp_cr_flags & FMODE_WRITE))
                RETURN(0);
        rc = mdd_lov_create(env, mdd, mdd_pobj, son, &lmm, &lmm_size, spec,
                            attr);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, MDD_TXN_CREATE_DATA_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(rc = PTR_ERR(handle));

        /*XXX: setting the lov ea is not locked
         * but setting the attr is locked? */

        /* replay creates has objects already */
        if (spec->u.sp_ea.no_lov_create) {
                CDEBUG(D_INFO, "we already have lov ea\n");
                rc = mdd_lov_set_md(env, mdd_pobj, son,
                                    (struct lov_mds_md *)spec->u.sp_ea.eadata,
                                    spec->u.sp_ea.eadatalen, handle, 0);
        } else
                rc = mdd_lov_set_md(env, mdd_pobj, son, lmm,
                                    lmm_size, handle, 0);

        if (rc == 0)
               rc = mdd_attr_get_internal_locked(env, son, ma);

        /* finish mdd_lov_create() stuff */
        mdd_lov_create_finish(env, mdd, rc);
        mdd_trans_stop(env, mdd, rc, handle);
        if (lmm)
                OBD_FREE(lmm, lmm_size);
        RETURN(rc);
}

static int mdd_create_sanity_check(const struct lu_env *env,
                                   struct md_object *pobj,
                                   const char *name, struct md_attr *ma)
{
        struct mdd_thread_info *info = mdd_env_info(env);
        struct lu_attr    *la        = &info->mti_la;
        struct lu_fid     *fid       = &info->mti_fid;
        struct mdd_object *obj       = md2mdd_obj(pobj);
        int rc;

        ENTRY;
        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

        /*
         * Check if the name already exist, though it will be checked
         * in _index_insert also, for avoiding rolling back if exists
         * _index_insert.
         */
        rc = __mdd_lookup_locked(env, pobj, name, fid,
                                 MAY_WRITE | MAY_EXEC);
        if (rc != -ENOENT)
                RETURN(rc ? : -EEXIST);

        /* sgid check */
        mdd_read_lock(env, obj);
        rc = __mdd_la_get(env, obj, la, BYPASS_CAPA);
        mdd_read_unlock(env, obj);
        if (rc != 0)
                RETURN(rc);

        if (la->la_mode & S_ISGID) {
                ma->ma_attr.la_gid = la->la_gid;
                if (S_ISDIR(ma->ma_attr.la_mode)) {
                        ma->ma_attr.la_mode |= S_ISGID;
                        ma->ma_attr.la_valid |= LA_MODE;
                }
        }

        switch (ma->ma_attr.la_mode & S_IFMT) {
        case S_IFREG:
        case S_IFDIR:
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                rc = 0;
                break;
        default:
                rc = -EINVAL;
                break;
        }
        RETURN(rc);
}

/*
 * Create object and insert it into namespace.
 */
static int mdd_create(const struct lu_env *env,
                      struct md_object *pobj, const char *name,
                      struct md_object *child,
                      const struct md_create_spec *spec,
                      struct md_attr* ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object *son = md2mdd_obj(child);
        struct lu_attr    *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct lu_attr    *attr = &ma->ma_attr;
        struct lov_mds_md *lmm = NULL;
        struct thandle    *handle;
        int rc, created = 0, inserted = 0, lmm_size = 0;
        ENTRY;

        /* sanity checks before big job */
        rc = mdd_create_sanity_check(env, pobj, name, ma);
        if (rc)
                RETURN(rc);

        /* no RPC inside the transaction, so OST objects should be created at
         * first */
        if (S_ISREG(attr->la_mode)) {
                rc = mdd_lov_create(env, mdd, mdd_pobj, son, &lmm, &lmm_size,
                                    spec, attr);
                if (rc)
                        RETURN(rc);
        }

        mdd_txn_param_build(env, MDD_TXN_MKDIR_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_pobj);

        /*
         * XXX check that link can be added to the parent in mkdir case.
         */

        /*
         * Two operations have to be performed:
         *
         *  - allocation of new object (->do_create()), and
         *
         *  - insertion into parent index (->dio_insert()).
         *
         * Due to locking, operation order is not important, when both are
         * successful, *but* error handling cases are quite different:
         *
         *  - if insertion is done first, and following object creation fails,
         *  insertion has to be rolled back, but this operation might fail
         *  also leaving us with dangling index entry.
         *
         *  - if creation is done first, is has to be undone if insertion
         *  fails, leaving us with leaked space, which is neither good, nor
         *  fatal.
         *
         * It seems that creation-first is simplest solution, but it is
         * sub-optimal in the frequent
         *
         *         $ mkdir foo
         *         $ mkdir foo
         *
         * case, because second mkdir is bound to create object, only to
         * destroy it immediately.
         *
         * Note that local file systems do
         *
         *     0. lookup -> -EEXIST
         *
         *     1. create
         *
         *     2. insert
         *
         * Maybe we should do the same. For now: creation-first.
         */

        mdd_write_lock(env, son);
        rc = __mdd_object_create(env, son, ma, handle);
        if (rc) {
                mdd_write_unlock(env, son);
                GOTO(cleanup, rc);
        }

        created = 1;

        rc = __mdd_object_initialize(env, mdo2fid(mdd_pobj),
                                     son, ma, handle);
        mdd_write_unlock(env, son);
        if (rc)
                /*
                 * Object has no links, so it will be destroyed when last
                 * reference is released. (XXX not now.)
                 */
                GOTO(cleanup, rc);

        rc = __mdd_index_insert(env, mdd_pobj, mdo2fid(son),
                                name, S_ISDIR(attr->la_mode), handle,
                                mdd_object_capa(env, mdd_pobj));

        if (rc)
                GOTO(cleanup, rc);

        inserted = 1;
        /* replay creates has objects already */
        if (spec->u.sp_ea.no_lov_create) {
                CDEBUG(D_INFO, "we already have lov ea\n");
                rc = mdd_lov_set_md(env, mdd_pobj, son,
                                    (struct lov_mds_md *)spec->u.sp_ea.eadata,
                                    spec->u.sp_ea.eadatalen, handle, 0);
        } else
                rc = mdd_lov_set_md(env, mdd_pobj, son, lmm,
                                    lmm_size, handle, 0);
        if (rc) {
                CERROR("error on stripe info copy %d \n", rc);
                GOTO(cleanup, rc);
        }

        if (S_ISLNK(attr->la_mode)) {
                struct dt_object *dt = mdd_object_child(son);
                const char *target_name = spec->u.sp_symname;
                int sym_len = strlen(target_name);
                const struct lu_buf *buf;
                loff_t pos = 0;

                buf = mdd_buf_get_const(env, target_name, sym_len);
                rc = dt->do_body_ops->dbo_write(env, dt, buf, &pos, handle,
                                                mdd_object_capa(env, son));
                if (rc == sym_len)
                        rc = 0;
                else
                        rc = -EFAULT;
        }

        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(env, mdd_pobj, la_copy, handle);
        if (rc)
                GOTO(cleanup, rc);

        /* return attr back */
        rc = mdd_attr_get_internal_locked(env, son, ma);
cleanup:
        if (rc && created) {
                int rc2 = 0;

                if (inserted) {
                        rc2 = __mdd_index_delete(env, mdd_pobj, name,
                                                 S_ISDIR(attr->la_mode),
                                                 handle, BYPASS_CAPA);
                        if (rc2)
                                CERROR("error can not cleanup destroy %d\n",
                                       rc2);
                }
                if (rc2 == 0)
                        __mdd_ref_del(env, son, handle);
        }
        /* finish mdd_lov_create() stuff */
        mdd_lov_create_finish(env, mdd, rc);
        if (lmm)
                OBD_FREE(lmm, lmm_size);
        mdd_write_unlock(env, mdd_pobj);
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

/* partial operation */
static int mdd_oc_sanity_check(const struct lu_env *env,
                               struct mdd_object *obj,
                               struct md_attr *ma)
{
        int rc;
        ENTRY;

        switch (ma->ma_attr.la_mode & S_IFMT) {
        case S_IFREG:
        case S_IFDIR:
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                rc = 0;
                break;
        default:
                rc = -EINVAL;
                break;
        }
        RETURN(rc);
}

static int mdd_object_create(const struct lu_env *env,
                             struct md_object *obj,
                             const struct md_create_spec *spec,
                             struct md_attr *ma)
{

        struct mdd_device *mdd = mdo2mdd(obj);
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct thandle *handle;
        const struct lu_fid *pfid = spec->u.sp_pfid;
        int rc;
        ENTRY;

        rc = mdd_oc_sanity_check(env, mdd_obj, ma);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, MDD_TXN_OBJECT_CREATE_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = __mdd_object_create(env, mdd_obj, ma, handle);
        if (rc)
                GOTO (unlock, rc);

        if (spec->sp_cr_flags & MDS_CREATE_SLAVE_OBJ) {
                /* if creating the slave object, set slave EA here */
                int lmv_size = spec->u.sp_ea.eadatalen;
                struct lmv_stripe_md *lmv;

                lmv = (struct lmv_stripe_md *)spec->u.sp_ea.eadata;
                LASSERT(lmv != NULL && lmv_size > 0);
                rc = __mdd_xattr_set(env, mdd_obj,
                                     mdd_buf_get_const(env, lmv, lmv_size),
                                     MDS_LMV_MD_NAME, 0, handle);
                if (rc)
                        GOTO(unlock, rc);
                pfid = spec->u.sp_ea.fid;
                CWARN("set slave ea "DFID" eadatalen %d rc %d\n",
                       PFID(mdo2fid(mdd_obj)), spec->u.sp_ea.eadatalen, rc);
                rc = mdd_attr_set_internal(env, mdd_obj, &ma->ma_attr, handle);
        } else
                rc = __mdd_object_initialize(env, pfid, mdd_obj, ma, handle);
unlock:
        mdd_write_unlock(env, mdd_obj);
        if (rc == 0)
                rc = mdd_attr_get_internal_locked(env, mdd_obj, ma);

        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

/*
 * Partial operation. Be aware, this is called with write lock taken, so we use
 * locksless version of __mdd_lookup() here.
 */
static int mdd_ni_sanity_check(const struct lu_env *env,
                               struct md_object *pobj,
                               const char *name,
                               const struct lu_fid *fid)
{
        struct mdd_object *obj       = md2mdd_obj(pobj);
#if 0
        int rc;
#endif
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

         /* The exist of the name will be checked in _index_insert. */
#if 0
        rc = __mdd_lookup(env, pobj, name, fid, MAY_WRITE | MAY_EXEC);
        if (rc != -ENOENT)
                RETURN(rc ? : -EEXIST);
        else
                RETURN(0);
#endif
        RETURN(mdd_permission_internal(env, obj, MAY_WRITE | MAY_EXEC));
}

static int mdd_name_insert(const struct lu_env *env,
                           struct md_object *pobj,
                           const char *name, const struct lu_fid *fid,
                           int isdir)
{
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_INDEX_INSERT_OP);
        handle = mdd_trans_start(env, mdo2mdd(pobj));
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = mdd_ni_sanity_check(env, pobj, name, fid);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_insert(env, mdd_obj, fid, name, isdir, handle,
                                BYPASS_CAPA);

out_unlock:
        mdd_write_unlock(env, mdd_obj);

        mdd_trans_stop(env, mdo2mdd(pobj), rc, handle);
        RETURN(rc);
}

/*
 * Be aware, this is called with write lock taken, so we use locksless version
 * of __mdd_lookup() here.
 */
static int mdd_nr_sanity_check(const struct lu_env *env,
                               struct md_object *pobj,
                               const char *name)
{
        struct mdd_object *obj       = md2mdd_obj(pobj);
#if 0
        struct mdd_thread_info *info = mdd_env_info(env);
        struct lu_fid     *fid       = &info->mti_fid;
        int rc;
#endif
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

         /* The exist of the name will be checked in _index_delete. */
#if 0
        rc = __mdd_lookup(env, pobj, name, fid, MAY_WRITE | MAY_EXEC);
        RETURN(rc);
#endif
        RETURN(mdd_permission_internal(env, obj, MAY_WRITE | MAY_EXEC));
}

static int mdd_name_remove(const struct lu_env *env,
                           struct md_object *pobj,
                           const char *name, int is_dir)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_INDEX_DELETE_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = mdd_nr_sanity_check(env, pobj, name);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_delete(env, mdd_obj, name, is_dir, handle,
                                BYPASS_CAPA);

out_unlock:
        mdd_write_unlock(env, mdd_obj);

        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

static int mdd_rt_sanity_check(const struct lu_env *env,
                               struct mdd_object *tgt_pobj,
                               struct mdd_object *tobj,
                               const struct lu_fid *sfid,
                               const char *name, struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(&tgt_pobj->mod_obj);
        int rc, src_is_dir;
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(tgt_pobj))
                RETURN(-ENOENT);

        src_is_dir = S_ISDIR(ma->ma_attr.la_mode);
        if (tobj) {
                rc = mdd_may_delete(env, tgt_pobj, tobj, src_is_dir, 1);
                if (!rc && S_ISDIR(mdd_object_type(tobj)) &&
                     mdd_dir_is_empty(env, tobj))
                                RETURN(-ENOTEMPTY);
        } else {
                rc = mdd_may_create(env, tgt_pobj, NULL, 1);
        }

        /* source should not be ancestor of target dir */
        if (!rc &&& src_is_dir && mdd_is_parent(env, mdd, tgt_pobj, sfid, NULL))
                RETURN(-EINVAL);

        RETURN(rc);
}

static int mdd_rename_tgt(const struct lu_env *env,
                          struct md_object *pobj, struct md_object *tobj,
                          const struct lu_fid *lf, const char *name,
                          struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_tpobj = md2mdd_obj(pobj);
        struct mdd_object *mdd_tobj = md2mdd_obj(tobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_RENAME_TGT_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        if (mdd_tobj)
                mdd_lock2(env, mdd_tpobj, mdd_tobj);
        else
                mdd_write_lock(env, mdd_tpobj);

        /*TODO rename sanity checking*/
        rc = mdd_rt_sanity_check(env, mdd_tpobj, mdd_tobj, lf, name, ma);
        if (rc)
                GOTO(cleanup, rc);

        /* if rename_tgt is called then we should just re-insert name with
         * correct fid, no need to dec/inc parent nlink if obj is dir */
        rc = __mdd_index_delete(env, mdd_tpobj, name, 0, handle, BYPASS_CAPA);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_insert_only(env, mdd_tpobj, lf, name, handle,
                                     BYPASS_CAPA);
        if (rc)
                GOTO(cleanup, rc);

        if (tobj && lu_object_exists(&tobj->mo_lu))
                __mdd_ref_del(env, mdd_tobj, handle);
cleanup:
        if (tobj)
                mdd_unlock2(env, mdd_tpobj, mdd_tobj);
        else
                mdd_write_unlock(env, mdd_tpobj);
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

/*
 * No permission check is needed.
 */
static int mdd_root_get(const struct lu_env *env,
                        struct md_device *m, struct lu_fid *f)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);

        ENTRY;
        *f = mdd->mdd_root_fid;
        RETURN(0);
}

/*
 * No permission check is needed.
 */
static int mdd_statfs(const struct lu_env *env, struct md_device *m,
                      struct kstatfs *sfs)
{
	struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        int rc;

        ENTRY;

        rc = mdd_child_ops(mdd)->dt_statfs(env, mdd->mdd_child, sfs);

        RETURN(rc);
}

/*
 * No permission check is needed.
 */
static int mdd_maxsize_get(const struct lu_env *env, struct md_device *m,
                           int *md_size, int *cookie_size)
{
	struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        ENTRY;

        *md_size = mdd_lov_mdsize(env, mdd);
        *cookie_size = mdd_lov_cookiesize(env, mdd);

        RETURN(0);
}

static int mdd_init_capa_ctxt(const struct lu_env *env, struct md_device *m,
                              int mode, unsigned long timeout, __u32 alg,
                              struct lustre_capa_key *keys)
{
	struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct mds_obd    *mds = &mdd2obd_dev(mdd)->u.mds;
        int rc;
        ENTRY;

        mds->mds_capa_keys = keys;
        rc = mdd_child_ops(mdd)->dt_init_capa_ctxt(env, mdd->mdd_child, mode,
                                                   timeout, alg, keys);
        RETURN(rc);
}

static int mdd_update_capa_key(const struct lu_env *env,
                               struct md_device *m,
                               struct lustre_capa_key *key)
{
	struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_export *lov_exp = mdd2obd_dev(mdd)->u.mds.mds_osc_exp;
        int rc;
        ENTRY;

        rc = obd_set_info_async(lov_exp, strlen(KEY_CAPA_KEY), KEY_CAPA_KEY,
                                sizeof(*key), key, NULL);
        RETURN(rc);
}

static void __mdd_ref_add(const struct lu_env *env, struct mdd_object *obj,
                         struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(mdd2lu_obj(obj)));
        next = mdd_object_child(obj);
        next->do_ops->do_ref_add(env, next, handle);
}

/*
 * XXX: if permission check is needed here?
 */
static int mdd_ref_add(const struct lu_env *env,
                       struct md_object *obj)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_XATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_write_lock(env, mdd_obj);
        rc = mdd_link_sanity_check(env, NULL, mdd_obj);
        if (!rc)
                __mdd_ref_add(env, mdd_obj, handle);
        mdd_write_unlock(env, mdd_obj);

        mdd_trans_stop(env, mdd, 0, handle);

        RETURN(0);
}

static void
__mdd_ref_del(const struct lu_env *env, struct mdd_object *obj,
              struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        ENTRY;

        LASSERT(lu_object_exists(mdd2lu_obj(obj)));

        next->do_ops->do_ref_del(env, next, handle);
        EXIT;
}

/* do NOT or the MAY_*'s, you'll get the weakest */
static int accmode(struct mdd_object *mdd_obj, int flags)
{
        int res = 0;

#if 0
        /* Sadly, NFSD reopens a file repeatedly during operation, so the
         * "acc_mode = 0" allowance for newly-created files isn't honoured.
         * NFSD uses the MDS_OPEN_OWNEROVERRIDE flag to say that a file
         * owner can write to a file even if it is marked readonly to hide
         * its brokenness. (bug 5781) */
        if (flags & MDS_OPEN_OWNEROVERRIDE && inode->i_uid == current->fsuid)
                return 0;
#endif
        if (flags & FMODE_READ)
                res = MAY_READ;
        if (flags & (FMODE_WRITE | MDS_OPEN_TRUNC | MDS_OPEN_APPEND))
                res |= MAY_WRITE;
        if (flags & MDS_FMODE_EXEC)
                res = MAY_EXEC;
        return res;
}

static int mdd_open_sanity_check(const struct lu_env *env,
                                 struct mdd_object *obj, int flag)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        int mode = accmode(obj, flag);
        int rc;
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

        rc = __mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
               RETURN(rc);

        if (S_ISLNK(tmp_la->la_mode))
                RETURN(-ELOOP);

        if (S_ISDIR(tmp_la->la_mode) && (mode & MAY_WRITE))
                RETURN(-EISDIR);

        if (!(flag & MDS_OPEN_CREATED)) {
                rc = __mdd_permission_internal(env, obj, mode, 0);
                if (rc)
                        RETURN(rc);
        }

        /*
         * FIFO's, sockets and device files are special: they don't
         * actually live on the filesystem itself, and as such you
         * can write to them even if the filesystem is read-only.
         */
        if (S_ISFIFO(tmp_la->la_mode) || S_ISSOCK(tmp_la->la_mode) ||
            S_ISBLK(tmp_la->la_mode) || S_ISCHR(tmp_la->la_mode))
                flag &= ~O_TRUNC;

        /*
         * An append-only file must be opened in append mode for writing.
         */
        if (mdd_is_append(obj)) {
                if ((flag & FMODE_WRITE) && !(flag & O_APPEND))
                        RETURN(-EPERM);
                if (flag & O_TRUNC)
                        RETURN(-EPERM);
        }

        /* O_NOATIME can only be set by the owner or superuser */
        if (flag & O_NOATIME) {
                struct md_ucred *uc = md_ucred(env);

                if (uc->mu_fsuid != tmp_la->la_uid &&
                    !mdd_capable(uc, CAP_FOWNER))
                        RETURN(-EPERM);
        }

        RETURN(0);
}

static int mdd_open(const struct lu_env *env, struct md_object *obj,
                    int flags)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc = 0;

        mdd_write_lock(env, mdd_obj);

        rc = mdd_open_sanity_check(env, mdd_obj, flags);
        if (rc == 0)
                mdd_obj->mod_count++;

        mdd_write_unlock(env, mdd_obj);
        return rc;
}

/*
 * No permission check is needed.
 */
static int mdd_close(const struct lu_env *env, struct md_object *obj,
                     struct md_attr *ma)
{
        int rc;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        ENTRY;

        mdd_write_lock(env, mdd_obj);
        /* release open count */
        mdd_obj->mod_count --;

        rc = __mdd_iattr_get(env, mdd_obj, ma);
        if (rc == 0 && mdd_obj->mod_count == 0) {
                if (ma->ma_attr.la_nlink == 0)
                        rc = __mdd_object_kill(env, mdd_obj, ma);
        }
        mdd_write_unlock(env, mdd_obj);
        RETURN(rc);
}

/*
 * Permission check is done when open,
 * no need check again.
 */
static int mdd_readpage_sanity_check(const struct lu_env *env,
                                     struct mdd_object *obj)
{
        struct dt_object *next = mdd_object_child(obj);
        int rc;
        ENTRY;

        if (S_ISDIR(mdd_object_type(obj)) && dt_try_as_dir(env, next))
#if 0
                rc = mdd_permission_internal(env, obj, MAY_READ);
#else
                rc = 0;
#endif
        else
                rc = -ENOTDIR;

        RETURN(rc);
}

static int mdd_readpage(const struct lu_env *env, struct md_object *obj,
                        const struct lu_rdpg *rdpg)
{
        struct dt_object *next;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;
        ENTRY;

        LASSERT(lu_object_exists(mdd2lu_obj(mdd_obj)));
        next = mdd_object_child(mdd_obj);

        mdd_read_lock(env, mdd_obj);
        rc = mdd_readpage_sanity_check(env, mdd_obj);
        if (rc)
                GOTO(out_unlock, rc);

        rc = next->do_ops->do_readpage(env, next, rdpg,
                                       mdd_object_capa(env, mdd_obj));

out_unlock:
        mdd_read_unlock(env, mdd_obj);
        RETURN(rc);
}

#ifdef CONFIG_FS_POSIX_ACL
#include <linux/posix_acl_xattr.h>
#include <linux/posix_acl.h>

static int mdd_posix_acl_permission(struct md_ucred *uc, struct lu_attr *la,
                                    int want, posix_acl_xattr_entry *entry,
                                    int count)
{
        posix_acl_xattr_entry *pa, *pe, *mask_obj;
        int found = 0;
        ENTRY;

        if (count <= 0)
                RETURN(-EACCES);

        pa = &entry[0];
        pe = &entry[count - 1];
        for (; pa <= pe; pa++) {
                switch(pa->e_tag) {
                        case ACL_USER_OBJ:
                                /* (May have been checked already) */
                                if (la->la_uid == uc->mu_fsuid)
                                        goto check_perm;
                                break;
                        case ACL_USER:
                                if (pa->e_id == uc->mu_fsuid)
                                        goto mask;
                                break;
                        case ACL_GROUP_OBJ:
                                if (mdd_in_group_p(uc, la->la_gid)) {
                                        found = 1;
                                        if ((pa->e_perm & want) == want)
                                                goto mask;
                                }
                                break;
                        case ACL_GROUP:
                                if (mdd_in_group_p(uc, pa->e_id)) {
                                        found = 1;
                                        if ((pa->e_perm & want) == want)
                                                goto mask;
                                }
                                break;
                        case ACL_MASK:
                                break;
                        case ACL_OTHER:
                                if (found)
                                        RETURN(-EACCES);
                                else
                                        goto check_perm;
                        default:
                                RETURN(-EIO);
                }
        }
        RETURN(-EIO);

mask:
        for (mask_obj = pa + 1; mask_obj <= pe; mask_obj++) {
                if (mask_obj->e_tag == ACL_MASK) {
                        if ((pa->e_perm & mask_obj->e_perm & want) == want)
                                RETURN(0);

                        RETURN(-EACCES);
                }
        }

check_perm:
        if ((pa->e_perm & want) == want)
                RETURN(0);

        RETURN(-EACCES);
}
#endif

static int mdd_check_acl(const struct lu_env *env, struct mdd_object *obj,
                         struct lu_attr* la, int mask)
{
#ifdef CONFIG_FS_POSIX_ACL
        struct dt_object *next;
        struct lu_buf    *buf = &mdd_env_info(env)->mti_buf;
        struct md_ucred  *uc  = md_ucred(env);
        posix_acl_xattr_entry *entry;
        int entry_count;
        int rc;
        ENTRY;

        next = mdd_object_child(obj);

        buf->lb_buf = mdd_env_info(env)->mti_xattr_buf;
        buf->lb_len = sizeof(mdd_env_info(env)->mti_xattr_buf);
        rc = next->do_ops->do_xattr_get(env, next, buf,
                                        XATTR_NAME_ACL_ACCESS,
                                        mdd_object_capa(env, obj));
        if (rc <= 0)
                RETURN(rc ? : -EACCES);

        entry = ((posix_acl_xattr_header *)(buf->lb_buf))->a_entries;
        entry_count = (rc - 4) / sizeof(posix_acl_xattr_entry);

        rc = mdd_posix_acl_permission(uc, la, mask, entry, entry_count);
        RETURN(rc);
#else
        ENTRY;
        RETURN(-EAGAIN);
#endif
}

static int mdd_exec_permission_lite(const struct lu_env *env,
                                    struct mdd_object *obj)
{
        struct lu_attr  *la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc = md_ucred(env);
        umode_t mode;
        int rc;
        ENTRY;

        /* These means unnecessary for permission check */
        if ((uc == NULL) || (uc->mu_valid == UCRED_INIT))
                RETURN(0);

        /* Invalid user credit */
        if (uc->mu_valid == UCRED_INVALID)
                RETURN(-EACCES);

        rc = __mdd_la_get(env, obj, la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        mode = la->la_mode;
        if (uc->mu_fsuid == la->la_uid)
                mode >>= 6;
        else if (mdd_in_group_p(uc, la->la_gid))
                mode >>= 3;

        if (mode & MAY_EXEC)
                RETURN(0);

        if (((la->la_mode & S_IXUGO) || S_ISDIR(la->la_mode)) &&
            mdd_capable(uc, CAP_DAC_OVERRIDE))
                RETURN(0);

        if (S_ISDIR(la->la_mode) && mdd_capable(uc, CAP_DAC_READ_SEARCH))
                RETURN(0);

        RETURN(-EACCES);
}

static int __mdd_permission_internal(const struct lu_env *env,
                                     struct mdd_object *obj,
                                     int mask, int getattr)
{
        struct lu_attr  *la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc = md_ucred(env);
        __u32 mode;
        int rc;

        ENTRY;

        if (mask == 0)
                RETURN(0);

        /* These means unnecessary for permission check */
        if ((uc == NULL) || (uc->mu_valid == UCRED_INIT))
                RETURN(0);

        /* Invalid user credit */
        if (uc->mu_valid == UCRED_INVALID)
                RETURN(-EACCES);

        /*
         * Nobody gets write access to an immutable file.
         */
        if ((mask & MAY_WRITE) && mdd_is_immutable(obj))
                RETURN(-EACCES);

        if (getattr) {
                rc = __mdd_la_get(env, obj, la, BYPASS_CAPA);
                if (rc)
                        RETURN(rc);
        }

        mode = la->la_mode;
        if (uc->mu_fsuid == la->la_uid) {
                mode >>= 6;
        } else {
                if (mode & S_IRWXG) {
                        rc = mdd_check_acl(env, obj, la, mask);
                        if (rc == -EACCES)
                                goto check_capabilities;
                        else if ((rc != -EAGAIN) && (rc != -EOPNOTSUPP) &&
                                 (rc != -ENODATA))
                                RETURN(rc);
                }
                if (mdd_in_group_p(uc, la->la_gid))
                        mode >>= 3;
        }

        /*
         * If the DACs are ok we don't need any capability check.
         */
        if (((mode & mask & S_IRWXO) == mask))
                RETURN(0);

check_capabilities:

        /*
         * Read/write DACs are always overridable.
         * Executable DACs are overridable if at least one exec bit is set.
         * Dir's DACs are always overridable.
         */
        if (!(mask & MAY_EXEC) ||
            (la->la_mode & S_IXUGO) || S_ISDIR(la->la_mode))
                if (mdd_capable(uc, CAP_DAC_OVERRIDE))
                        RETURN(0);

        /*
         * Searching includes executable on directories, else just read.
         */
        if ((mask == MAY_READ) ||
            (S_ISDIR(la->la_mode) && !(mask & MAY_WRITE)))
                if (mdd_capable(uc, CAP_DAC_READ_SEARCH))
                        RETURN(0);

        RETURN(-EACCES);
}

static inline int mdd_permission_internal_locked(const struct lu_env *env,
                                                 struct mdd_object *obj,
                                                 int mask)
{
        int rc;

        mdd_read_lock(env, obj);
        rc = mdd_permission_internal(env, obj, mask);
        mdd_read_unlock(env, obj);

        return rc;
}

static int mdd_permission(const struct lu_env *env, struct md_object *obj,
                          int mask)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;
        ENTRY;

        rc = mdd_permission_internal_locked(env, mdd_obj, mask);

        RETURN(rc);
}

static int mdd_capa_get(const struct lu_env *env, struct md_object *obj,
                        struct lustre_capa *capa)
{
        struct dt_object *next;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct obd_capa *oc;
        ENTRY;

        LASSERT(lu_object_exists(mdd2lu_obj(mdd_obj)));
        next = mdd_object_child(mdd_obj);

        oc = next->do_ops->do_capa_get(env, next, capa->lc_opc);
        if (oc) {
                capa_cpy(capa, oc);
                capa_put(oc);
        }

        RETURN(0);
}

struct md_device_operations mdd_ops = {
        .mdo_statfs         = mdd_statfs,
        .mdo_root_get       = mdd_root_get,
        .mdo_maxsize_get    = mdd_maxsize_get,
        .mdo_init_capa_ctxt = mdd_init_capa_ctxt,
        .mdo_update_capa_key= mdd_update_capa_key,
};

static struct md_dir_operations mdd_dir_ops = {
        .mdo_is_subdir     = mdd_is_subdir,
        .mdo_lookup        = mdd_lookup,
        .mdo_create        = mdd_create,
        .mdo_rename        = mdd_rename,
        .mdo_link          = mdd_link,
        .mdo_unlink        = mdd_unlink,
        .mdo_name_insert   = mdd_name_insert,
        .mdo_name_remove   = mdd_name_remove,
        .mdo_rename_tgt    = mdd_rename_tgt,
        .mdo_create_data   = mdd_create_data
};

static struct md_object_operations mdd_obj_ops = {
        .moo_permission    = mdd_permission,
        .moo_attr_get      = mdd_attr_get,
        .moo_attr_set      = mdd_attr_set,
        .moo_xattr_get     = mdd_xattr_get,
        .moo_xattr_set     = mdd_xattr_set,
        .moo_xattr_list    = mdd_xattr_list,
        .moo_xattr_del     = mdd_xattr_del,
        .moo_object_create = mdd_object_create,
        .moo_ref_add       = mdd_ref_add,
        .moo_ref_del       = mdd_ref_del,
        .moo_open          = mdd_open,
        .moo_close         = mdd_close,
        .moo_readpage      = mdd_readpage,
        .moo_readlink      = mdd_readlink,
        .moo_capa_get      = mdd_capa_get
};

static struct obd_ops mdd_obd_device_ops = {
        .o_owner = THIS_MODULE
};

static struct lu_device *mdd_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *lcfg)
{
        struct lu_device  *l;
        struct mdd_device *m;

        OBD_ALLOC_PTR(m);
        if (m == NULL) {
                l = ERR_PTR(-ENOMEM);
        } else {
                md_device_init(&m->mdd_md_dev, t);
                l = mdd2lu_dev(m);
	        l->ld_ops = &mdd_lu_ops;
                m->mdd_md_dev.md_ops = &mdd_ops;
        }

        return l;
}

static void mdd_device_free(const struct lu_env *env,
                            struct lu_device *lu)
{
        struct mdd_device *m = lu2mdd_dev(lu);

        LASSERT(atomic_read(&lu->ld_ref) == 0);
        md_device_fini(&m->mdd_md_dev);
        OBD_FREE_PTR(m);
}

static void *mdd_ucred_key_init(const struct lu_context *ctx,
                                struct lu_context_key *key)
{
        struct md_ucred *uc;

        OBD_ALLOC_PTR(uc);
        if (uc == NULL)
                uc = ERR_PTR(-ENOMEM);
        return uc;
}

static void mdd_ucred_key_fini(const struct lu_context *ctx,
                             struct lu_context_key *key, void *data)
{
        struct md_ucred *uc = data;
        OBD_FREE_PTR(uc);
}

static struct lu_context_key mdd_ucred_key = {
        .lct_tags = LCT_SESSION,
        .lct_init = mdd_ucred_key_init,
        .lct_fini = mdd_ucred_key_fini
};

struct md_ucred *md_ucred(const struct lu_env *env)
{
        LASSERT(env->le_ses != NULL);
        return lu_context_key_get(env->le_ses, &mdd_ucred_key);
}
EXPORT_SYMBOL(md_ucred);

static void *mdd_capainfo_key_init(const struct lu_context *ctx,
                                   struct lu_context_key *key)
{
        struct md_capainfo *ci;

        OBD_ALLOC_PTR(ci);
        if (ci == NULL)
                ci = ERR_PTR(-ENOMEM);
        return ci;
}

static void mdd_capainfo_key_fini(const struct lu_context *ctx,
                                  struct lu_context_key *key, void *data)
{
        struct md_capainfo *ci = data;
        OBD_FREE_PTR(ci);
}

struct lu_context_key mdd_capainfo_key = {
        .lct_tags = LCT_SESSION,
        .lct_init = mdd_capainfo_key_init,
        .lct_fini = mdd_capainfo_key_fini
};

struct md_capainfo *md_capainfo(const struct lu_env *env)
{
        /* NB, in mdt_init0 */
        if (env->le_ses == NULL)
                return NULL;
        return lu_context_key_get(env->le_ses, &mdd_capainfo_key);
}
EXPORT_SYMBOL(md_capainfo);

static int mdd_type_init(struct lu_device_type *t)
{
        int result;

        result = lu_context_key_register(&mdd_thread_key);
        if (result == 0)
                result = lu_context_key_register(&mdd_ucred_key);
        if (result == 0)
                result = lu_context_key_register(&mdd_capainfo_key);
        return result;
}

static void mdd_type_fini(struct lu_device_type *t)
{
        lu_context_key_degister(&mdd_capainfo_key);
        lu_context_key_degister(&mdd_ucred_key);
        lu_context_key_degister(&mdd_thread_key);
}

static struct lu_device_type_operations mdd_device_type_ops = {
        .ldto_init = mdd_type_init,
        .ldto_fini = mdd_type_fini,

        .ldto_device_alloc = mdd_device_alloc,
        .ldto_device_free  = mdd_device_free,

        .ldto_device_init    = mdd_device_init,
        .ldto_device_fini    = mdd_device_fini
};

static struct lu_device_type mdd_device_type = {
        .ldt_tags     = LU_DEVICE_MD,
        .ldt_name     = LUSTRE_MDD_NAME,
        .ldt_ops      = &mdd_device_type_ops,
        .ldt_ctx_tags = LCT_MD_THREAD
};

static void *mdd_key_init(const struct lu_context *ctx,
                          struct lu_context_key *key)
{
        struct mdd_thread_info *info;

        OBD_ALLOC_PTR(info);
        if (info == NULL)
                info = ERR_PTR(-ENOMEM);
        return info;
}

static void mdd_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct mdd_thread_info *info = data;
        OBD_FREE_PTR(info);
}

static struct lu_context_key mdd_thread_key = {
        .lct_tags = LCT_MD_THREAD,
        .lct_init = mdd_key_init,
        .lct_fini = mdd_key_fini
};

struct lprocfs_vars lprocfs_mdd_obd_vars[] = {
        { 0 }
};

struct lprocfs_vars lprocfs_mdd_module_vars[] = {
        { 0 }
};

LPROCFS_INIT_VARS(mdd, lprocfs_mdd_module_vars, lprocfs_mdd_obd_vars);

static int __init mdd_mod_init(void)
{
        struct lprocfs_static_vars lvars;
        printk(KERN_INFO "Lustre: MetaData Device; info@clusterfs.com\n");
        lprocfs_init_vars(mdd, &lvars);
        return class_register_type(&mdd_obd_device_ops, NULL, lvars.module_vars,
                                   LUSTRE_MDD_NAME, &mdd_device_type);
}

static void __exit mdd_mod_exit(void)
{
        class_unregister_type(LUSTRE_MDD_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Meta-data Device Prototype ("LUSTRE_MDD_NAME")");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.1.0", mdd_mod_init, mdd_mod_exit);
