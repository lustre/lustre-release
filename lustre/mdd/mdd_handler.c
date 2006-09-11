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

#include "mdd_internal.h"


static struct thandle* mdd_trans_start(const struct lu_context *ctxt,
                                       struct mdd_device *);
static void mdd_trans_stop(const struct lu_context *ctxt,
                           struct mdd_device *mdd, int rc,
                           struct thandle *handle);
static struct dt_object* mdd_object_child(struct mdd_object *o);
static void __mdd_ref_add(const struct lu_context *ctxt, struct mdd_object *obj,
                          struct thandle *handle);
static void __mdd_ref_del(const struct lu_context *ctxt, struct mdd_object *obj,
                          struct thandle *handle);
static int mdd_lookup(const struct lu_context *ctxt, struct md_object *pobj,
                      const char *name, struct lu_fid* fid);

static struct md_object_operations mdd_obj_ops;
static struct md_dir_operations    mdd_dir_ops;
static struct lu_object_operations mdd_lu_obj_ops;

static struct lu_context_key       mdd_thread_key;

static const char *mdd_root_dir_name = "root";
static const char dot[] = ".";
static const char dotdot[] = "..";


struct mdd_thread_info *mdd_ctx_info(const struct lu_context *ctx)
{
        struct mdd_thread_info *info;

        info = lu_context_key_get(ctx, &mdd_thread_key);
        LASSERT(info != NULL);
        return info;
}

static struct lu_object *mdd_object_alloc(const struct lu_context *ctxt,
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

static int mdd_object_init(const struct lu_context *ctxt, struct lu_object *o)
{
	struct mdd_device *d = lu2mdd_dev(o->lo_dev);
	struct lu_object  *below;
        struct lu_device  *under;
        ENTRY;

	under = &d->mdd_child->dd_lu_dev;
	below = under->ld_ops->ldo_object_alloc(ctxt, o->lo_header, under);

        if (below == NULL)
		RETURN(-ENOMEM);

        lu_object_add(o, below);
        RETURN(0);
}

static int mdd_get_flags(const struct lu_context *ctxt, struct mdd_object *obj);

static int mdd_object_start(const struct lu_context *ctxt, struct lu_object *o)
{
        if (lu_object_exists(o))
                return mdd_get_flags(ctxt, lu2mdd_obj(o));
        else
                return 0;
}

static void mdd_object_free(const struct lu_context *ctxt, struct lu_object *o)
{
        struct mdd_object *mdd = lu2mdd_obj(o);
	
        lu_object_fini(o);
        OBD_FREE_PTR(mdd);
}

struct mdd_object *mdd_object_find(const struct lu_context *ctxt,
                                   struct mdd_device *d,
                                   const struct lu_fid *f)
{
        struct lu_object *o;
        struct mdd_object *m;
        ENTRY;

        o = lu_object_find(ctxt, mdd2lu_dev(d)->ld_site, f);
        if (IS_ERR(o))
                m = (struct mdd_object *)o;
        else {
                o = lu_object_locate(o->lo_header, mdd2lu_dev(d)->ld_type);
                m = o ? lu2mdd_obj(o) : NULL;
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

static void mdd_set_dead_obj(struct mdd_object *obj)
{
        if (obj)
                obj->mod_flags |= DEAD_OBJ;
}

static int mdd_is_dead_obj(struct mdd_object *obj)
{
        return obj && obj->mod_flags & DEAD_OBJ;
}

/*Check whether it may create the cobj under the pobj*/
static int mdd_may_create(const struct lu_context *ctxt,
                          struct mdd_object *pobj, struct mdd_object *cobj)
{
        ENTRY;
        if (cobj && lu_object_exists(&cobj->mod_obj.mo_lu))
                RETURN(-EEXIST);

        if (mdd_is_dead_obj(pobj))
                RETURN(-ENOENT);

        /*check pobj may create or not*/
        RETURN(0);
}

static inline int __mdd_la_get(const struct lu_context *ctxt,
                               struct mdd_object *obj, struct lu_attr *la)
{
        struct dt_object  *next = mdd_object_child(obj);
        LASSERT(lu_object_exists(mdd2lu_obj(obj)));
        return next->do_ops->do_attr_get(ctxt, next, la);
}

static void mdd_flags_xlate(struct mdd_object *obj, __u32 flags)
{
        obj->mod_flags &= ~(APPEND_OBJ|IMMUTE_OBJ);

        if (flags & LUSTRE_APPEND_FL)
                obj->mod_flags |= APPEND_OBJ;

        if (flags & LUSTRE_IMMUTABLE_FL)
                obj->mod_flags |= IMMUTE_OBJ;
}

static int mdd_get_flags(const struct lu_context *ctxt, struct mdd_object *obj)
{
        struct lu_attr *la = &mdd_ctx_info(ctxt)->mti_la;
        int rc;

        ENTRY;
        mdd_read_lock(ctxt, obj);
        rc = __mdd_la_get(ctxt, obj, la);
        mdd_read_unlock(ctxt, obj);
        if (rc == 0)
                mdd_flags_xlate(obj, la->la_flags);
        RETURN(rc);
}

/*Check whether it may delete the cobj under the pobj*/
static int mdd_may_delete(const struct lu_context *ctxt,
                          struct mdd_object *pobj, struct mdd_object *cobj,
                          int is_dir)
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

        } else if (S_ISDIR(mdd_object_type(cobj)))
                        RETURN(-EISDIR);

        if (pobj && mdd_is_dead_obj(pobj))
                RETURN(-ENOENT);

        RETURN(rc);
}
/* get only inode attributes */
static int __mdd_iattr_get(const struct lu_context *ctxt,
                           struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        rc = __mdd_la_get(ctxt, mdd_obj, &ma->ma_attr);
        if (rc == 0)
                ma->ma_valid = MA_INODE;
        RETURN(rc);
}
/* get lov EA only */
static int __mdd_lmm_get(const struct lu_context *ctxt,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;

        LASSERT(ma->ma_lmm != NULL && ma->ma_lmm_size > 0);
        rc = mdd_get_md(ctxt, mdd_obj, ma->ma_lmm, &ma->ma_lmm_size,
                        MDS_LOV_MD_NAME);
        if (rc > 0) {
                ma->ma_valid |= MA_LOV;
                rc = 0;
        }
        RETURN(rc);
}

#ifdef HAVE_SPLIT_SUPPORT
/* get lmv EA only*/
static int __mdd_lmv_get(const struct lu_context *ctxt,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;

        rc = mdd_get_md(ctxt, mdd_obj, ma->ma_lmv, &ma->ma_lmv_size,
                        MDS_LMV_MD_NAME);
        if (rc > 0) {
                ma->ma_valid |= MA_LMV;
                rc = 0;
        }
        RETURN(rc);
}
#endif

static int mdd_attr_get_internal(const struct lu_context *ctxt,
                                 struct mdd_object *mdd_obj,
                                 struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        if (ma->ma_need & MA_INODE)
                rc = __mdd_iattr_get(ctxt, mdd_obj, ma);

        if (rc == 0 && ma->ma_need & MA_LOV) {
                if (S_ISREG(mdd_object_type(mdd_obj)) ||
                    S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = __mdd_lmm_get(ctxt, mdd_obj, ma);
        }
#ifdef HAVE_SPLIT_SUPPORT
        if (rc == 0 && ma->ma_need & MA_LMV) {
                if (S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = __mdd_lmv_get(ctxt, mdd_obj, ma);
        }
#endif
        CDEBUG(D_INODE, "after getattr rc = %d, ma_valid = "LPX64"\n",
                        rc, ma->ma_valid);
        RETURN(rc);
}

static inline int mdd_attr_get_internal_locked(const struct lu_context *ctxt,
                                               struct mdd_object *mdd_obj,
                                               struct md_attr *ma)
{
        int rc;
        mdd_read_lock(ctxt, mdd_obj);
        rc = mdd_attr_get_internal(ctxt, mdd_obj, ma);
        mdd_read_unlock(ctxt, mdd_obj);
        return rc;
}

static int mdd_attr_get(const struct lu_context *ctxt,
                        struct md_object *obj, struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int                rc;

        ENTRY;
        rc = mdd_attr_get_internal_locked(ctxt, mdd_obj, ma);
        RETURN(rc);
}

static int mdd_xattr_get(const struct lu_context *ctxt, struct md_object *obj,
                         void *buf, int buf_len, const char *name)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        int rc;

        ENTRY;

        LASSERT(lu_object_exists(&obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(ctxt, mdd_obj);
        rc = next->do_ops->do_xattr_get(ctxt, next, buf, buf_len, name);
        mdd_read_unlock(ctxt, mdd_obj);

        RETURN(rc);
}

static int mdd_readlink(const struct lu_context *ctxt, struct md_object *obj,
                        void *buf, int buf_len)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        loff_t             pos = 0;
        int                rc;
        ENTRY;

        LASSERT(lu_object_exists(&obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        rc = next->do_body_ops->dbo_read(ctxt, next, buf, buf_len, &pos);
        RETURN(rc);
}
static int mdd_xattr_list(const struct lu_context *ctxt, struct md_object *obj,
                          void *buf, int buf_len)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        int rc;

        ENTRY;

        LASSERT(lu_object_exists(&obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        rc = next->do_ops->do_xattr_list(ctxt, next, buf, buf_len);

        RETURN(rc);
}

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
        MDD_TXN_CREATE_DATA_OP,
        MDD_TXN_MKDIR_OP
};

struct mdd_txn_op_descr {
        enum mdd_txn_op mod_op;
        unsigned int    mod_credits;
};

enum {
        MDD_TXN_OBJECT_DESTROY_CREDITS = 20,
        MDD_TXN_OBJECT_CREATE_CREDITS  = 20,
        MDD_TXN_ATTR_SET_CREDITS       = 20,
        MDD_TXN_XATTR_SET_CREDITS      = 20,
        MDD_TXN_INDEX_INSERT_CREDITS   = 20,
        MDD_TXN_INDEX_DELETE_CREDITS   = 20,
        MDD_TXN_LINK_CREDITS           = 20,
        MDD_TXN_UNLINK_CREDITS         = 20,
        MDD_TXN_RENAME_CREDITS         = 20,
        MDD_TXN_CREATE_DATA_CREDITS    = 20,
        MDD_TXN_MKDIR_CREDITS          = 20
};

#define DEFINE_MDD_TXN_OP_DESC(opname)          \
static const struct mdd_txn_op_descr opname = { \
        .mod_op      = opname ## _OP,           \
        .mod_credits = opname ## _CREDITS,      \
}

/*
 * number of blocks to reserve for particular operations. Should be function
 * of ... something. Stub for now.
 */
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_OBJECT_DESTROY);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_OBJECT_CREATE);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_ATTR_SET);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_XATTR_SET);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_INDEX_INSERT);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_INDEX_DELETE);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_LINK);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_UNLINK);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_RENAME);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_CREATE_DATA);
DEFINE_MDD_TXN_OP_DESC(MDD_TXN_MKDIR);

static void mdd_txn_param_build(const struct lu_context *ctx,
                                const struct mdd_txn_op_descr *opd)
{
        mdd_ctx_info(ctx)->mti_param.tp_credits = opd->mod_credits;
}

static int mdd_object_print(const struct lu_context *ctxt, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        return (*p)(ctxt, cookie, LUSTRE_MDD_NAME"-object@%p", o);
}

static int mdd_mount(const struct lu_context *ctx, struct mdd_device *mdd)
{
        int rc;
        struct dt_object *root;
        ENTRY;

        root = dt_store_open(ctx, mdd->mdd_child, mdd_root_dir_name,
                             &mdd->mdd_root_fid);
        if (!IS_ERR(root)) {
                LASSERT(root != NULL);
                lu_object_put(ctx, &root->do_lu);
                rc = orph_index_init(ctx, mdd);
        } else
                rc = PTR_ERR(root);

        RETURN(rc);
}

static int mdd_txn_start_cb(const struct lu_context *ctx,
                            struct txn_param *param, void *cookie)
{
        return 0;
}

static int mdd_txn_stop_cb(const struct lu_context *ctx,
                           struct thandle *txn, void *cookie)
{
        struct mdd_device *mdd = cookie;
        struct obd_device *obd = mdd2obd_dev(mdd);
        
        return mds_lov_write_objids(obd);
}

static int mdd_txn_commit_cb(const struct lu_context *ctx,
                             struct thandle *txn, void *cookie)
{
        return 0;
}

static int mdd_device_init(const struct lu_context *ctx,
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

        dt_txn_callback_add(dt, &mdd->mdd_txn_cb);

        RETURN(rc);
}

static struct lu_device *mdd_device_fini(const struct lu_context *ctx,
                                         struct lu_device *d)
{
	struct mdd_device *mdd = lu2mdd_dev(d);
        struct lu_device *next = &mdd->mdd_child->dd_lu_dev;

        dt_txn_callback_del(mdd->mdd_child, &mdd->mdd_txn_cb);
        
        return next;
}

static void mdd_device_shutdown(const struct lu_context *ctxt,
                                struct mdd_device *m)
{
        if (m->mdd_obd_dev)
                mdd_fini_obd(ctxt, m);
        orph_index_fini(ctxt, m);
}

static int mdd_process_config(const struct lu_context *ctxt,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct mdd_device *m    = lu2mdd_dev(d);
        struct dt_device  *dt   = m->mdd_child;
        struct lu_device  *next = &dt->dd_lu_dev;
        int rc;
        ENTRY;

        switch (cfg->lcfg_command) {
        case LCFG_SETUP:
                rc = next->ld_ops->ldo_process_config(ctxt, next, cfg);
                if (rc)
                        GOTO(out, rc);
                dt->dd_ops->dt_conf_get(ctxt, dt, &m->mdd_dt_conf);

                rc = mdd_mount(ctxt, m);
                if (rc)
                        GOTO(out, rc);
                rc = mdd_init_obd(ctxt, m, cfg);
                if (rc) {
                        CERROR("lov init error %d \n", rc);
                        GOTO(out, rc);
                }
                break;
        case LCFG_CLEANUP:
                mdd_device_shutdown(ctxt, m);
        default:
                rc = next->ld_ops->ldo_process_config(ctxt, next, cfg);
                break;
        }
out:
        RETURN(rc);
}

static int mdd_recovery_complete(const struct lu_context *ctxt,
                                 struct lu_device *d)
{
        struct mdd_device *mdd = lu2mdd_dev(d);
        struct lu_device *next = &mdd->mdd_child->dd_lu_dev;
        int rc;
        ENTRY;
/* TODO:
        rc = mdd_lov_set_nextid(ctx, mdd);
        if (rc) {
                CERROR("%s: mdd_lov_set_nextid failed %d\n",
                       obd->obd_name, rc);
                GOTO(out, rc);
        }
        rc = mdd_cleanup_unlink_llog(ctx, mdd);

        obd_notify(obd->u.mds.mds_osc_obd, NULL,
                   obd->obd_async_recov ? OBD_NOTIFY_SYNC_NONBLOCK :
                   OBD_NOTIFY_SYNC, NULL);
*/
        /* TODO: orphans handling */
        rc = next->ld_ops->ldo_recovery_complete(ctxt, next);
        RETURN(rc);
}

struct lu_device_operations mdd_lu_ops = {
	.ldo_object_alloc      = mdd_object_alloc,
        .ldo_process_config    = mdd_process_config,
        .ldo_recovery_complete = mdd_recovery_complete
};

static struct lu_object_operations mdd_lu_obj_ops = {
	.loo_object_init    = mdd_object_init,
	.loo_object_start   = mdd_object_start,
	.loo_object_free    = mdd_object_free,
	.loo_object_print   = mdd_object_print
};

void mdd_write_lock(const struct lu_context *ctxt, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_write_lock(ctxt, next);
}

void mdd_read_lock(const struct lu_context *ctxt, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_read_lock(ctxt, next);
}

void mdd_write_unlock(const struct lu_context *ctxt, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_write_unlock(ctxt, next);
}

void mdd_read_unlock(const struct lu_context *ctxt, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_read_unlock(ctxt, next);
}

static void mdd_lock2(const struct lu_context *ctxt,
                      struct mdd_object *o0, struct mdd_object *o1)
{
        mdd_write_lock(ctxt, o0);
        mdd_write_lock(ctxt, o1);
}

static void mdd_unlock2(const struct lu_context *ctxt,
                        struct mdd_object *o0, struct mdd_object *o1)
{
        mdd_write_unlock(ctxt, o1);
        mdd_write_unlock(ctxt, o0);
}

static struct thandle* mdd_trans_start(const struct lu_context *ctxt,
                                       struct mdd_device *mdd)
{
        struct txn_param *p = &mdd_ctx_info(ctxt)->mti_param;

        return mdd_child_ops(mdd)->dt_trans_start(ctxt, mdd->mdd_child, p);
}

static void mdd_trans_stop(const struct lu_context *ctxt,
                           struct mdd_device *mdd, int result,
                           struct thandle *handle)
{
        handle->th_result = result;
        mdd_child_ops(mdd)->dt_trans_stop(ctxt, handle);
}

static int __mdd_object_create(const struct lu_context *ctxt,
                               struct mdd_object *obj, struct md_attr *ma,
                               struct thandle *handle)
{
        struct dt_object *next;
        struct lu_attr *attr = &ma->ma_attr;
        int rc;
        ENTRY;

        if (!lu_object_exists(mdd2lu_obj(obj))) {
                next = mdd_object_child(obj);
                rc = next->do_ops->do_create(ctxt, next, attr, handle);
        } else
                rc = -EEXIST;

        LASSERT(ergo(rc == 0, lu_object_exists(mdd2lu_obj(obj))));

        RETURN(rc);
}

int mdd_attr_set_internal(const struct lu_context *ctxt, struct mdd_object *o,
                          const struct lu_attr *attr, struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(mdd2lu_obj(o)));
        next = mdd_object_child(o);
        return next->do_ops->do_attr_set(ctxt, next, attr, handle);
}

int mdd_attr_set_internal_locked(const struct lu_context *ctxt,
                                 struct mdd_object *o,
                                 const struct lu_attr *attr,
                                 struct thandle *handle)
{
        int rc;
        mdd_write_lock(ctxt, o);
        rc = mdd_attr_set_internal(ctxt, o, attr, handle);
        mdd_write_unlock(ctxt, o);
        return rc;
}

static int __mdd_xattr_set(const struct lu_context *ctxt, struct mdd_object *o,
                           const void *buf, int buf_len, const char *name,
                           int fl, struct thandle *handle)
{
        struct dt_object *next;
        int rc = 0;
        ENTRY;

        LASSERT(lu_object_exists(mdd2lu_obj(o)));
        next = mdd_object_child(o);
        if (buf && buf_len > 0) {
                rc = next->do_ops->do_xattr_set(ctxt, next, buf, buf_len, name,
                                                0, handle);
        }else if (buf == NULL && buf_len == 0) {
                rc = next->do_ops->do_xattr_del(ctxt, next, name, handle);
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
int mdd_fix_attr(const struct lu_context *ctxt, struct mdd_object *obj,
                 const struct md_attr *ma, struct lu_attr *la)
{
        struct lu_attr   *tmp_la = &mdd_ctx_info(ctxt)->mti_la;
        time_t            now = CURRENT_SECONDS;
        int               rc;
        ENTRY;

        rc = __mdd_la_get(ctxt, obj, tmp_la);
        if (rc)
                RETURN(rc);
        /*XXX Check permission */
        if (mdd_is_immutable(obj) || mdd_is_append(obj)) {

                /*If only change flags of the object, we should
                 * let it pass, but also need capability check
                 * here if (!capable(CAP_LINUX_IMMUTABLE)),
                 * fix it, when implement capable in mds*/
                if (la->la_valid & ~LA_FLAGS)
                        RETURN(-EPERM);

                /*According to Ext3 implementation on this, the
                 *Ctime will be changed, but not clear why?*/
                la->la_ctime = now;
                la->la_valid |= LA_CTIME;
                RETURN(0);
        }
        if (!(la->la_valid & LA_CTIME)) {
                la->la_ctime = now;
                la->la_valid |= LA_CTIME;
        }

#if 0
        /* times */
        if ((ia_valid & (ATTR_MTIME|ATTR_ATIME)) == (ATTR_MTIME|ATTR_ATIME)) {
                if (current->fsuid != inode->i_uid &&
                    (error = ll_permission(inode, MAY_WRITE, NULL)) != 0)
                        RETURN(error);
        }
        if (ia_valid & ATTR_SIZE &&
            /* NFSD hack for open(O_CREAT|O_TRUNC)=mknod+truncate (bug 5781) */
            !(rec->ur_uc.luc_fsuid == inode->i_uid &&
              ia_valid & MDS_OPEN_OWNEROVERRIDE)) {
                if ((error = ll_permission(inode, MAY_WRITE, NULL)) != 0)
                        RETURN(error);
        }
#endif

        if (la->la_valid & (LA_UID | LA_GID)) {
                /* chown */

                if (mdd_is_immutable(obj) || mdd_is_append(obj))
                        RETURN(-EPERM);
                if (la->la_uid == (uid_t) -1)
                        la->la_uid = tmp_la->la_uid;
                if (la->la_gid == (gid_t) -1)
                        la->la_gid = tmp_la->la_gid;
                if (!(la->la_valid & LA_MODE))
                        la->la_mode = tmp_la->la_mode;
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
                if ((tmp_la->la_mode & S_ISUID) == S_ISUID &&
                    !S_ISDIR(tmp_la->la_mode)) {
                        la->la_mode &= ~S_ISUID;
                        la->la_valid |= LA_MODE;
                }
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
        } else if (la->la_valid & LA_MODE) {
                int mode = la->la_mode;
                /* chmod */
                if (la->la_mode == (umode_t)-1)
                        mode = tmp_la->la_mode;
                la->la_mode =
                        (mode & S_IALLUGO) | (tmp_la->la_mode & ~S_IALLUGO);
        }
        RETURN(rc);
}


/* set attr and LOV EA at once, return updated attr */
static int mdd_attr_set(const struct lu_context *ctxt,
                        struct md_object *obj,
                        const struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        struct lov_mds_md *lmm = NULL;
        int  rc = 0, lmm_size = 0, max_size;
        struct lu_attr *la_copy = &mdd_ctx_info(ctxt)->mti_la_for_fix;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_ATTR_SET);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));
        /*TODO: add lock here*/
        /* start a log jounal handle if needed */
        if (S_ISREG(mdd_object_type(mdd_obj)) &&
            ma->ma_attr.la_valid & (LA_UID | LA_GID)) {
                max_size = mdd_lov_mdsize(ctxt, mdd);
                OBD_ALLOC(lmm, max_size);
                if (lmm == NULL)
                        GOTO(cleanup, rc = -ENOMEM);

                rc = mdd_get_md_locked(ctxt, mdd_obj, lmm, &lmm_size,
                                MDS_LOV_MD_NAME);

                if (rc < 0)
                        GOTO(cleanup, rc);
        }

        if (ma->ma_attr.la_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime "LPU64", ctime "LPU64"\n",
                       ma->ma_attr.la_mtime, ma->ma_attr.la_ctime);

        *la_copy = ma->ma_attr;
        mdd_write_lock(ctxt, mdd_obj);
        rc = mdd_fix_attr(ctxt, mdd_obj, ma, la_copy);
        mdd_write_unlock(ctxt, mdd_obj);
        if (rc)
                GOTO(cleanup, rc);

        if (la_copy->la_valid & LA_FLAGS) {
                rc = mdd_attr_set_internal_locked(ctxt, mdd_obj, la_copy,
                                                  handle);
                if (rc == 0)
                        mdd_flags_xlate(mdd_obj, la_copy->la_flags);
        } else if (la_copy->la_valid) {            /* setattr */
                rc = mdd_attr_set_internal_locked(ctxt, mdd_obj, la_copy,
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
                        rc = mdd_lov_set_md(ctxt, NULL, mdd_obj, ma->ma_lmm,
                                            ma->ma_lmm_size, handle, 1);
                }

        }
cleanup:
        mdd_trans_stop(ctxt, mdd, rc, handle);
        if (rc == 0 && lmm_size) {
                /*set obd attr, if needed*/
                rc = mdd_lov_setattr_async(ctxt, mdd_obj, lmm, lmm_size);
        }
        if (lmm != NULL) {
                OBD_FREE(lmm, max_size);
        }

        RETURN(rc);
}

int mdd_xattr_set_txn(const struct lu_context *ctxt, struct mdd_object *obj,
                      const void *buf, int buf_len, const char *name, int fl,
                      struct thandle *handle)
{
        int  rc;
        ENTRY;

        mdd_write_lock(ctxt, obj);
        rc = __mdd_xattr_set(ctxt, obj, buf, buf_len, name, fl, handle);
        mdd_write_unlock(ctxt, obj);

        RETURN(rc);
}

static int mdd_xattr_set(const struct lu_context *ctxt, struct md_object *obj,
                         const void *buf, int buf_len, const char *name,
                         int fl)
{
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_XATTR_SET);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = mdd_xattr_set_txn(ctxt, md2mdd_obj(obj), buf, buf_len, name,
                               fl, handle);

        mdd_trans_stop(ctxt, mdd, rc, handle);

        RETURN(rc);
}

static int __mdd_xattr_del(const struct lu_context *ctxt,struct mdd_device *mdd,
                           struct mdd_object *obj,
                           const char *name, struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(mdd2lu_obj(obj)));
        next = mdd_object_child(obj);
        return next->do_ops->do_xattr_del(ctxt, next, name, handle);
}

int mdd_xattr_del(const struct lu_context *ctxt, struct md_object *obj,
                  const char *name)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_XATTR_SET);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(ctxt, mdd_obj);
        rc = __mdd_xattr_del(ctxt, mdd, md2mdd_obj(obj), name, handle);
        mdd_write_unlock(ctxt, mdd_obj);

        mdd_trans_stop(ctxt, mdd, rc, handle);

        RETURN(rc);
}

static int __mdd_index_insert_only(const struct lu_context *ctxt,
                                   struct mdd_object *pobj,
                                   const struct lu_fid *lf,
                                   const char *name, struct thandle *th)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

        if (dt_try_as_dir(ctxt, next))
                rc = next->do_index_ops->dio_insert(ctxt, next,
                                         (struct dt_rec *)lf,
                                         (struct dt_key *)name, th);
        else
                rc = -ENOTDIR;
        RETURN(rc);
}

/* insert new index, add reference if isdir, update times */
static int __mdd_index_insert(const struct lu_context *ctxt,
                             struct mdd_object *pobj, const struct lu_fid *lf,
                             const char *name, int isdir, struct thandle *th)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

#if 0
        struct lu_attr   *la = &mdd_ctx_info(ctxt)->mti_la;
#endif

        if (dt_try_as_dir(ctxt, next))
                rc = next->do_index_ops->dio_insert(ctxt, next,
                                         (struct dt_rec *)lf,
                                         (struct dt_key *)name, th);
        else
                rc = -ENOTDIR;

        if (rc == 0) {
                if (isdir)
                        __mdd_ref_add(ctxt, pobj, th);
#if 0
                la->la_valid = LA_MTIME|LA_CTIME;
                la->la_atime = ma->ma_attr.la_atime;
                la->la_ctime = ma->ma_attr.la_ctime;
                rc = mdd_attr_set_internal(ctxt, mdd_obj, la, handle);
#endif
        }
        return rc;
}

static int __mdd_index_delete(const struct lu_context *ctxt,
                              struct mdd_object *pobj, const char *name,
                              struct thandle *handle)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

        if (dt_try_as_dir(ctxt, next))
                rc = next->do_index_ops->dio_delete(ctxt, next,
                                        (struct dt_key *)name, handle);
        else
                rc = -ENOTDIR;
        RETURN(rc);
}

static int mdd_link_sanity_check(const struct lu_context *ctxt,
                                 struct mdd_object *tgt_obj,
                                 struct mdd_object *src_obj)
{
        int rc;

        rc = mdd_may_create(ctxt, tgt_obj, NULL);
        if (rc)
                RETURN(rc);
        if (S_ISDIR(mdd_object_type(src_obj)))
                RETURN(-EPERM);

        if (mdd_is_immutable(src_obj) || mdd_is_append(src_obj))
                RETURN(-EPERM);

        RETURN(rc);
}

static int mdd_link(const struct lu_context *ctxt, struct md_object *tgt_obj,
                    struct md_object *src_obj, const char *name,
                    struct md_attr *ma)
{
        struct mdd_object *mdd_tobj = md2mdd_obj(tgt_obj);
        struct mdd_object *mdd_sobj = md2mdd_obj(src_obj);
        struct mdd_device *mdd = mdo2mdd(src_obj);
        struct lu_attr    *la_copy = &mdd_ctx_info(ctxt)->mti_la_for_fix;
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_LINK);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock2(ctxt, mdd_tobj, mdd_sobj);

        rc = mdd_link_sanity_check(ctxt, mdd_tobj, mdd_sobj);
        if (rc)
                GOTO(out, rc);

        rc = __mdd_index_insert_only(ctxt, mdd_tobj, mdo2fid(mdd_sobj),
                                     name, handle);
        if (rc == 0)
                __mdd_ref_add(ctxt, mdd_sobj, handle);

        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME;
        rc = mdd_attr_set_internal(ctxt, mdd_sobj, la_copy, handle);
        if (rc)
                GOTO(out, rc);

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(ctxt, mdd_tobj, la_copy, handle);

out:
        mdd_unlock2(ctxt, mdd_tobj, mdd_sobj);
        mdd_trans_stop(ctxt, mdd, rc, handle);
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
static int mdd_dir_is_empty(const struct lu_context *ctx,
                            struct mdd_object *dir)
{
        struct dt_it     *it;
        struct dt_object *obj;
        struct dt_it_ops *iops;
        int result;

        obj = mdd_object_child(dir);
        iops = &obj->do_index_ops->dio_it;
        it = iops->init(ctx, obj, 0);
        if (it != NULL) {
                result = iops->get(ctx, it, (const void *)"");
                if (result > 0) {
                        int i;
                        for (result = 0, i = 0; result == 0 && i < 3; ++i)
                                result = iops->next(ctx, it);
                        iops->put(ctx, it);
                        if (result == 0)
                                result = -ENOTEMPTY;
                        else if (result == +1)
                                result = 0;
                } else if (result == 0)
                        /*
                         * Huh? Index contains no zero key?
                         */
                        result = -EIO;
                iops->fini(ctx, it);
        } else
                result = -ENOMEM;
        return result;
}

/* return md_attr back,
 * if it is last unlink then return lov ea + llog cookie*/
int __mdd_object_kill(const struct lu_context *ctxt,
                      struct mdd_object *obj,
                      struct md_attr *ma)
{
        int rc = 0;

        mdd_set_dead_obj(obj);
        if (S_ISREG(mdd_object_type(obj))) {
                rc = __mdd_lmm_get(ctxt, obj, ma);
                if (ma->ma_valid & MA_LOV)
                        rc = mdd_unlink_log(ctxt, mdo2mdd(&obj->mod_obj),
                                            obj, ma);
        }
        return rc;
}
/* caller should take a lock before calling */
static int __mdd_finish_unlink(const struct lu_context *ctxt,
                               struct mdd_object *obj, struct md_attr *ma,
                               struct thandle *th)
{
        int rc;
        ENTRY;

        rc = __mdd_iattr_get(ctxt, obj, ma);
        if (rc == 0 && ma->ma_attr.la_nlink == 0) {
                if (obj->mod_count == 0) {
                        rc = __mdd_object_kill(ctxt, obj, ma);
                } else {
                        /* add new orphan */
                        rc = __mdd_orphan_add(ctxt, obj, th);
                }
        }
        RETURN(rc);
}

static int mdd_unlink_sanity_check(const struct lu_context *ctxt,
                                   struct mdd_object *pobj,
                                   struct mdd_object *cobj,
                                   struct md_attr *ma)
{
        struct dt_object  *dt_cobj  = mdd_object_child(cobj);
        int rc = 0;
        ENTRY;

        rc = mdd_may_delete(ctxt, pobj, cobj, S_ISDIR(ma->ma_attr.la_mode));
        if (rc)
                RETURN(rc);

        if (S_ISDIR(mdd_object_type(cobj)) &&
            dt_try_as_dir(ctxt, dt_cobj)) {
                rc = mdd_dir_is_empty(ctxt, cobj);
                if (rc != 0)
                        RETURN(rc);
        }

        RETURN(rc);
}

static int mdd_unlink(const struct lu_context *ctxt, struct md_object *pobj,
                      struct md_object *cobj, const char *name,
                      struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object *mdd_cobj = md2mdd_obj(cobj);
        struct lu_attr    *la_copy = &mdd_ctx_info(ctxt)->mti_la_for_fix;
        struct thandle    *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_UNLINK);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock2(ctxt, mdd_pobj, mdd_cobj);

        rc = mdd_unlink_sanity_check(ctxt, mdd_pobj, mdd_cobj, ma);
        if (rc)
                GOTO(cleanup, rc);


        rc = __mdd_index_delete(ctxt, mdd_pobj, name, handle);
        if (rc)
                GOTO(cleanup, rc);

        __mdd_ref_del(ctxt, mdd_cobj, handle);
        *la_copy = ma->ma_attr;
        if (S_ISDIR(lu_object_attr(&cobj->mo_lu))) {
                /* unlink dot */
                __mdd_ref_del(ctxt, mdd_cobj, handle);
                /* unlink dotdot */
                __mdd_ref_del(ctxt, mdd_pobj, handle);
        } else {
                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_set_internal(ctxt, mdd_cobj, la_copy, handle);
                if (rc)
                        GOTO(cleanup, rc);
        }

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(ctxt, mdd_pobj, la_copy, handle);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_finish_unlink(ctxt, mdd_cobj, ma, handle);

cleanup:
        mdd_unlock2(ctxt, mdd_pobj, mdd_cobj);
        mdd_trans_stop(ctxt, mdd, rc, handle);
        RETURN(rc);
}
/* partial unlink */
static int mdd_ref_del(const struct lu_context *ctxt, struct md_object *obj,
                       struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_XATTR_SET);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_write_lock(ctxt, mdd_obj);

        rc = mdd_unlink_sanity_check(ctxt, NULL, mdd_obj, ma);
        if (rc)
                GOTO(cleanup, rc);

        __mdd_ref_del(ctxt, mdd_obj, handle);

        if (S_ISDIR(lu_object_attr(&obj->mo_lu))) {
                /* unlink dot */
                __mdd_ref_del(ctxt, mdd_obj, handle);
        }

        rc = __mdd_finish_unlink(ctxt, mdd_obj, ma, handle);

cleanup:
        mdd_write_unlock(ctxt, mdd_obj);
        mdd_trans_stop(ctxt, mdd, rc, handle);
        RETURN(rc);
}

static int mdd_parent_fid(const struct lu_context *ctxt,
                          struct mdd_object *obj,
                          struct lu_fid *fid)
{
        return mdd_lookup(ctxt, &obj->mod_obj, dotdot, fid);
}

/*
 * return 0: if p2 is the parent of p1
 * otherwise: other_value
 */
static int mdd_is_parent(const struct lu_context *ctxt,
                         struct mdd_device *mdd,
                         struct mdd_object *p1,
                         struct mdd_object *p2)
{
        struct lu_fid * pfid;
        struct mdd_object *parent = NULL;
        int rc;
        ENTRY;

        pfid = &mdd_ctx_info(ctxt)->mti_fid;
        if (lu_fid_eq(mdo2fid(p1), &mdd->mdd_root_fid))
                RETURN(1);
        for(;;) {
                rc = mdd_parent_fid(ctxt, p1, pfid);
                if (rc)
                        GOTO(out, rc);
                if (lu_fid_eq(pfid, mdo2fid(p2)))
                        GOTO(out, rc = 0);
                if (lu_fid_eq(pfid, &mdd->mdd_root_fid))
                        GOTO(out, rc = 1);
                if (parent)
                        mdd_object_put(ctxt, parent);
                parent = mdd_object_find(ctxt, mdd, pfid);
                /* cross-ref parent, not supported yet */
                if (parent == NULL)
                        GOTO(out, rc = -EOPNOTSUPP);
                else if (IS_ERR(parent))
                        GOTO(out, rc = PTR_ERR(parent));
                p1 = parent;
        }
out:
        if (parent && !IS_ERR(parent))
                mdd_object_put(ctxt, parent);
        RETURN(rc);
}

static int mdd_rename_lock(const struct lu_context *ctxt,
                           struct mdd_device *mdd,
                           struct mdd_object *src_pobj,
                           struct mdd_object *tgt_pobj)
{
        ENTRY;

        if (src_pobj == tgt_pobj) {
                mdd_write_lock(ctxt, src_pobj);
                RETURN(0);
        }
        /*compared the parent child relationship of src_p&tgt_p*/
        if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(src_pobj))){
                mdd_lock2(ctxt, src_pobj, tgt_pobj);
                RETURN(0);
        } else if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(tgt_pobj))) {
                mdd_lock2(ctxt, tgt_pobj, src_pobj);
                RETURN(0);
        }

        if (!mdd_is_parent(ctxt, mdd, src_pobj, tgt_pobj)) {
                mdd_lock2(ctxt, tgt_pobj, src_pobj);
                RETURN(0);
        }

        mdd_lock2(ctxt, src_pobj, tgt_pobj);

        RETURN(0);
}

static void mdd_rename_unlock(const struct lu_context *ctxt,
                              struct mdd_object *src_pobj,
                              struct mdd_object *tgt_pobj)
{
        mdd_write_unlock(ctxt, src_pobj);
        if (src_pobj != tgt_pobj)
                mdd_write_unlock(ctxt, tgt_pobj);
}

static int mdd_rename_sanity_check(const struct lu_context *ctxt,
                                   struct mdd_object *src_pobj,
                                   struct mdd_object *tgt_pobj,
                                   struct mdd_object *sobj,
                                   struct mdd_object *tobj)
{
        struct mdd_device *mdd =mdo2mdd(&src_pobj->mod_obj);
        int rc = 0, src_is_dir, tgt_is_dir;
        ENTRY;

        src_is_dir = S_ISDIR(mdd_object_type(sobj));
        rc = mdd_may_delete(ctxt, src_pobj, sobj, src_is_dir);
        if (rc)
                GOTO(out, rc);

        if (!tobj) {
                rc = mdd_may_create(ctxt, tgt_pobj, NULL);
        } else {
                rc = mdd_may_delete(ctxt, tgt_pobj, tobj, src_is_dir);
                if (rc == 0) {
                        tgt_is_dir = S_ISDIR(mdd_object_type(tobj));
                        if (tgt_is_dir && mdd_dir_is_empty(ctxt, tobj))
                                rc = -ENOTEMPTY;
                }
        }
        if (rc)
                GOTO(out, rc);

        /* source should not be ancestor of target dir */
        if (src_is_dir && !mdd_is_parent(ctxt, mdd, tgt_pobj, sobj))
                rc = -EINVAL;

out:
        mdd_object_put(ctxt, sobj);
        RETURN(rc);
}

static int mdd_rename(const struct lu_context *ctxt, struct md_object *src_pobj,
                      struct md_object *tgt_pobj, const struct lu_fid *lf,
                      const char *sname, struct md_object *tobj,
                      const char *tname, struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(src_pobj);
        struct mdd_object *mdd_spobj = md2mdd_obj(src_pobj);
        struct mdd_object *mdd_tpobj = md2mdd_obj(tgt_pobj);
        struct mdd_object *mdd_sobj = mdd_object_find(ctxt, mdd, lf);
        struct mdd_object *mdd_tobj = NULL;
        struct lu_attr    *la_copy = &mdd_ctx_info(ctxt)->mti_la_for_fix;
        struct thandle *handle;
        int is_dir;
        int rc;
        ENTRY;

        /* the source can be remote one, not supported yet */
        if (mdd_sobj == NULL)
                RETURN(-EOPNOTSUPP);

        is_dir = S_ISDIR(mdd_object_type(mdd_sobj));
        
        if (tobj)
                mdd_tobj = md2mdd_obj(tobj);

        /*XXX: shouldn't this check be done under lock below? */
        rc = mdd_rename_sanity_check(ctxt, mdd_spobj, mdd_tpobj,
                                     mdd_sobj, mdd_tobj);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(ctxt, &MDD_TXN_RENAME);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        /*FIXME: Should consider tobj and sobj too in rename_lock*/
        rc = mdd_rename_lock(ctxt, mdd, mdd_spobj, mdd_tpobj);
        if (rc)
                GOTO(cleanup_unlocked, rc);

        rc = __mdd_index_delete(ctxt, mdd_spobj, sname, handle);
        if (rc)
                GOTO(cleanup, rc);

        /*if sobj is dir, its parent object nlink should be dec too*/
        if (is_dir)
                __mdd_ref_del(ctxt, mdd_spobj, handle);

        if (tobj) {
                rc = __mdd_index_delete(ctxt, mdd_tpobj, tname, handle);
                if (rc)
                        GOTO(cleanup, rc);
        }

        rc = __mdd_index_insert(ctxt, mdd_tpobj, lf, tname, is_dir, handle);
        if (rc)
                GOTO(cleanup, rc);

        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME;
        rc = mdd_attr_set_internal_locked(ctxt, mdd_sobj, la_copy, handle);
        if (rc)
                GOTO(cleanup, rc);

        if (tobj && lu_object_exists(&tobj->mo_lu)) {
                mdd_write_lock(ctxt, mdd_tobj);
                __mdd_ref_del(ctxt, mdd_tobj, handle);
                /* remove dot reference */
                if (is_dir)
                        __mdd_ref_del(ctxt, mdd_tobj, handle);

                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_set_internal(ctxt, mdd_tobj, la_copy, handle);
                if (rc)
                        GOTO(cleanup, rc);

                rc = __mdd_finish_unlink(ctxt, mdd_tobj, ma, handle);
                mdd_write_unlock(ctxt, mdd_tobj);
                if (rc)
                        GOTO(cleanup, rc);
        }

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(ctxt, mdd_spobj, la_copy, handle);
        if (rc)
                GOTO(cleanup, rc);

        if (mdd_spobj != mdd_tpobj) {
                la_copy->la_valid = LA_CTIME | LA_MTIME;
                rc = mdd_attr_set_internal(ctxt, mdd_tpobj, la_copy, handle);
        }

cleanup:
        mdd_rename_unlock(ctxt, mdd_spobj, mdd_tpobj);
cleanup_unlocked:
        mdd_trans_stop(ctxt, mdd, rc, handle);
        RETURN(rc);
}

static int mdd_lookup(const struct lu_context *ctxt, struct md_object *pobj,
                      const char *name, struct lu_fid* fid)
{
        struct mdd_object   *mdd_obj = md2mdd_obj(pobj);
        struct dt_object    *dir = mdd_object_child(mdd_obj);
        struct dt_rec       *rec    = (struct dt_rec *)fid;
        const struct dt_key *key = (const struct dt_key *)name;
        int rc;
        ENTRY;

        if (mdd_is_dead_obj(mdd_obj))
                RETURN(-ESTALE);
        mdd_read_lock(ctxt, mdd_obj);
        if (S_ISDIR(mdd_object_type(mdd_obj)) && dt_try_as_dir(ctxt, dir))
                rc = dir->do_index_ops->dio_lookup(ctxt, dir, rec, key);
        else
                rc = -ENOTDIR;
        mdd_read_unlock(ctxt, mdd_obj);
        RETURN(rc);
}

static int __mdd_object_initialize(const struct lu_context *ctxt,
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

        rc = mdd_attr_set_internal(ctxt, child, &ma->ma_attr, handle);
        if (rc != 0)
                RETURN(rc);

        if (S_ISDIR(ma->ma_attr.la_mode)) {
                /* add . and .. for newly created dir */
                __mdd_ref_add(ctxt, child, handle);
                rc = __mdd_index_insert_only(ctxt, child, mdo2fid(child),
                                             dot, handle);
                if (rc == 0) {
                        rc = __mdd_index_insert_only(ctxt, child, pfid,
                                                     dotdot, handle);
                        if (rc != 0) {
                                int rc2;

                                rc2 = __mdd_index_delete(ctxt,
                                                         child, dot, handle);
                                if (rc2 != 0)
                                        CERROR("Failure to cleanup after dotdot"
                                               " creation: %d (%d)\n", rc2, rc);
                                else
                                        __mdd_ref_del(ctxt, child, handle);
                        }
                }
        }
        RETURN(rc);
}

static int mdd_create_data(const struct lu_context *ctxt,
                           struct md_object *pobj, struct md_object *cobj,
                           const struct md_create_spec *spec,
                           struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object *son = md2mdd_obj(cobj);
        struct lu_attr    *attr = &ma->ma_attr;
        struct lov_mds_md *lmm = NULL;
        int                lmm_size = 0;
        struct thandle    *handle;
        int                rc;
        ENTRY;

        rc = mdd_lov_create(ctxt, mdd, mdd_pobj, son, &lmm, &lmm_size, spec,
                            attr);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(ctxt, &MDD_TXN_CREATE_DATA);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                rc = PTR_ERR(handle);
        else {
                /*XXX: setting the lov ea is not locked
                 * but setting the attr is locked? */
                rc = mdd_lov_set_md(ctxt, mdd_pobj, son, lmm, lmm_size,
                                    handle, 0);
                if (rc == 0)
                        rc = mdd_attr_get_internal_locked(ctxt, son, ma);
        }
out:
        /* finish mdd_lov_create() stuff */
        mdd_lov_create_finish(ctxt, mdd, rc);
        mdd_trans_stop(ctxt, mdd, rc, handle);
        if (lmm)
                OBD_FREE(lmm, lmm_size);
        RETURN(rc);
}

static int mdd_create_sanity_check(const struct lu_context *ctxt,
                                   struct mdd_device *mdd,
                                   struct md_object *pobj,
                                   const char *name, struct md_attr *ma)
{
        struct mdd_thread_info *info = mdd_ctx_info(ctxt);
        struct lu_attr    *la        = &info->mti_la;
        struct lu_fid     *fid       = &info->mti_fid;
        struct mdd_object *obj       = md2mdd_obj(pobj);
        int rc;

        ENTRY;
        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);
        rc = mdd_lookup(ctxt, pobj, name, fid);
        if (rc != -ENOENT)
                RETURN(rc ? : -EEXIST);

        /* sgid check */
        mdd_read_lock(ctxt, obj);
        rc = __mdd_la_get(ctxt, obj, la);
        mdd_read_unlock(ctxt, obj);
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
static int mdd_create(const struct lu_context *ctxt, struct md_object *pobj,
                      const char *name, struct md_object *child,
                      const struct md_create_spec *spec,
                      struct md_attr* ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object *son = md2mdd_obj(child);
        struct lu_attr    *la_copy = &mdd_ctx_info(ctxt)->mti_la_for_fix;
        struct lu_attr    *attr = &ma->ma_attr;
        struct lov_mds_md *lmm = NULL;
        struct thandle    *handle;
        int rc, created = 0, inserted = 0, lmm_size = 0;
        ENTRY;

        /* sanity checks before big job */
        rc = mdd_create_sanity_check(ctxt, mdd, pobj, name, ma);
        if (rc)
                RETURN(rc);
        /* no RPC inside the transaction, so OST objects should be created at
         * first */
        if (S_ISREG(attr->la_mode)) {
                rc = mdd_lov_create(ctxt, mdd, mdd_pobj, son, &lmm, &lmm_size,
                                    spec, attr);
                if (rc)
                        RETURN(rc);
        }

        mdd_txn_param_build(ctxt, &MDD_TXN_MKDIR);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(ctxt, mdd_pobj);

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

        mdd_write_lock(ctxt, son);
        rc = __mdd_object_create(ctxt, son, ma, handle);
        if (rc) {
                mdd_write_unlock(ctxt, son);
                GOTO(cleanup, rc);
        }

        created = 1;

        rc = __mdd_object_initialize(ctxt, mdo2fid(mdd_pobj),
                                     son, ma, handle);
        mdd_write_unlock(ctxt, son);
        if (rc)
                /*
                 * Object has no links, so it will be destroyed when last
                 * reference is released. (XXX not now.)
                 */
                GOTO(cleanup, rc);

        rc = __mdd_index_insert(ctxt, mdd_pobj, mdo2fid(son),
                                name, S_ISDIR(attr->la_mode), handle);

        if (rc)
                GOTO(cleanup, rc);

        inserted = 1;
        rc = mdd_lov_set_md(ctxt, mdd_pobj, son, lmm, lmm_size, handle, 0);
        if (rc) {
                CERROR("error on stripe info copy %d \n", rc);
                GOTO(cleanup, rc);
        }

        if (S_ISLNK(attr->la_mode)) {
                struct dt_object *dt = mdd_object_child(son);
                const char *target_name = spec->u.sp_symname;
                int sym_len = strlen(target_name);
                loff_t pos = 0;

                rc = dt->do_body_ops->dbo_write(ctxt, dt, target_name,
                                                sym_len, &pos, handle);
                if (rc == sym_len)
                        rc = 0;
                else
                        rc = -EFAULT;
        }

        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(ctxt, mdd_pobj, la_copy, handle);
        if (rc)
                GOTO(cleanup, rc);

        /* return attr back */
        rc = mdd_attr_get_internal_locked(ctxt, son, ma);
cleanup:
        if (rc && created) {
                int rc2 = 0;

                if (inserted) {
                        rc2 = __mdd_index_delete(ctxt, mdd_pobj, name, handle);
                        if (rc2)
                                CERROR("error can not cleanup destroy %d\n",
                                       rc2);
                }
                if (rc2 == 0)
                        __mdd_ref_del(ctxt, son, handle);
        }
        /* finish mdd_lov_create() stuff */
        mdd_lov_create_finish(ctxt, mdd, rc);
        if (lmm)
                OBD_FREE(lmm, lmm_size);
        mdd_write_unlock(ctxt, mdd_pobj);
        mdd_trans_stop(ctxt, mdd, rc, handle);
        RETURN(rc);
}
/* partial operation */
static int mdd_object_create(const struct lu_context *ctxt,
                             struct md_object *obj,
                             const struct md_create_spec *spec,
                             struct md_attr *ma)
{

        struct mdd_device *mdd = mdo2mdd(obj);
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_OBJECT_CREATE);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(ctxt, mdd_obj);
        rc = __mdd_object_create(ctxt, mdd_obj, ma, handle);
        if (rc == 0)
                rc = __mdd_object_initialize(ctxt, spec->u.sp_pfid, mdd_obj,
                                     ma, handle);
        mdd_write_unlock(ctxt, mdd_obj);

        if (rc == 0)
                rc = mdd_attr_get_internal_locked(ctxt, mdd_obj, ma);

        mdd_trans_stop(ctxt, mdd, rc, handle);
        RETURN(rc);
}
/* partial operation */
static int mdd_name_insert(const struct lu_context *ctxt,
                           struct md_object *pobj, const char *name,
                           const struct lu_fid *fid, int isdir)
{
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_INDEX_INSERT);
        handle = mdd_trans_start(ctxt, mdo2mdd(pobj));
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(ctxt, mdd_obj);
        rc = __mdd_index_insert(ctxt, mdd_obj, fid, name, isdir, handle);
        mdd_write_unlock(ctxt, mdd_obj);

        mdd_trans_stop(ctxt, mdo2mdd(pobj), rc, handle);
        RETURN(rc);
}

static int mdd_name_remove(const struct lu_context *ctxt,
                           struct md_object *pobj,
                           const char *name)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_INDEX_DELETE);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(ctxt, mdd_obj);

        rc = __mdd_index_delete(ctxt, mdd_obj, name, handle);

        mdd_write_unlock(ctxt, mdd_obj);

        mdd_trans_stop(ctxt, mdd, rc, handle);
        RETURN(rc);
}

static int mdd_rename_tgt(const struct lu_context *ctxt, struct md_object *pobj,
                          struct md_object *tobj, const struct lu_fid *lf,
                          const char *name, struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_tpobj = md2mdd_obj(pobj);
        struct mdd_object *mdd_tobj = NULL;
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_RENAME);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        if (tobj)
                mdd_tobj = md2mdd_obj(tobj);

        mdd_lock2(ctxt, mdd_tpobj, mdd_tobj);

        /*TODO rename sanity checking*/
        if (tobj) {
                rc = __mdd_index_delete(ctxt, mdd_tpobj, name, handle);
                if (rc)
                        GOTO(cleanup, rc);
        }

        rc = __mdd_index_insert_only(ctxt, mdd_tpobj, lf, name, handle);
        if (rc)
                GOTO(cleanup, rc);

        if (tobj && lu_object_exists(&tobj->mo_lu))
                __mdd_ref_del(ctxt, mdd_tobj, handle);
cleanup:
        mdd_unlock2(ctxt, mdd_tpobj, mdd_tobj);
        mdd_trans_stop(ctxt, mdd, rc, handle);
        RETURN(rc);
}

static int mdd_root_get(const struct lu_context *ctx,
                        struct md_device *m, struct lu_fid *f)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);

        ENTRY;
        *f = mdd->mdd_root_fid;
        RETURN(0);
}

static int mdd_statfs(const struct lu_context *ctx,
                      struct md_device *m, struct kstatfs *sfs)
{
	struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        int rc;

        ENTRY;

        rc = mdd_child_ops(mdd)->dt_statfs(ctx, mdd->mdd_child, sfs);

        RETURN(rc);
}

static int mdd_get_maxsize(const struct lu_context *ctx,
                           struct md_device *m, int *md_size,
                           int *cookie_size)
{
	struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        ENTRY;

        *md_size =  mdd_lov_mdsize(ctx, mdd);
        *cookie_size = mdd_lov_cookiesize(ctx, mdd);

        RETURN(0);
}

static void __mdd_ref_add(const struct lu_context *ctxt, struct mdd_object *obj,
                         struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(mdd2lu_obj(obj)));
        next = mdd_object_child(obj);
        next->do_ops->do_ref_add(ctxt, next, handle);
}

static int mdd_ref_add(const struct lu_context *ctxt, struct md_object *obj)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_XATTR_SET);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_write_lock(ctxt, mdd_obj);
        __mdd_ref_add(ctxt, mdd_obj, handle);
        mdd_write_unlock(ctxt, mdd_obj);

        mdd_trans_stop(ctxt, mdd, 0, handle);

        RETURN(0);
}

static void
__mdd_ref_del(const struct lu_context *ctxt, struct mdd_object *obj,
              struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);

        LASSERT(lu_object_exists(mdd2lu_obj(obj)));

        next->do_ops->do_ref_del(ctxt, next, handle);
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
        if (flags & (FMODE_WRITE|MDS_OPEN_TRUNC))
                res |= MAY_WRITE;
        if (flags & MDS_FMODE_EXEC)
                res = MAY_EXEC;
        return res;
}

static int mdd_open(const struct lu_context *ctxt, struct md_object *obj,
                    int flags)
{
        int mode = accmode(md2mdd_obj(obj), flags);
        int rc = 0;

        mdd_write_lock(ctxt, md2mdd_obj(obj));

        if (mode & MAY_WRITE) {
                if (mdd_is_immutable(md2mdd_obj(obj)))
                        rc = -EACCES;
        }
        
        if (rc == 0)
                md2mdd_obj(obj)->mod_count ++;

        mdd_write_unlock(ctxt, md2mdd_obj(obj));
        return rc;
}

static int mdd_close(const struct lu_context *ctxt, struct md_object *obj,
                     struct md_attr *ma)
{
        int rc;
        struct mdd_object *mdd_obj;
        struct thandle *handle = NULL;
        ENTRY;

        mdd_obj = md2mdd_obj(obj);
        mdd_txn_param_build(ctxt, &MDD_TXN_MKDIR);
        handle = mdd_trans_start(ctxt, mdo2mdd(obj));
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_write_lock(ctxt, mdd_obj);
        rc = __mdd_iattr_get(ctxt, mdd_obj, ma);
        if (rc == 0 && (-- mdd_obj->mod_count) == 0) {
                if (ma->ma_attr.la_nlink == 0) {
                        rc = __mdd_object_kill(ctxt, mdd_obj, ma);
                        if (rc == 0)
                                /* let's remove obj from the orphan list */
                                rc = __mdd_orphan_del(ctxt, mdd_obj, handle);
                }
        }
        mdd_write_unlock(ctxt, mdd_obj);
        mdd_trans_stop(ctxt, mdo2mdd(obj), rc, handle);
        RETURN(rc);
}

static int mdd_readpage(const struct lu_context *ctxt, struct md_object *obj,
                        const struct lu_rdpg *rdpg)
{
        struct dt_object *next;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;

        LASSERT(lu_object_exists(mdd2lu_obj(mdd_obj)));
        next = mdd_object_child(mdd_obj);

        mdd_read_lock(ctxt, mdd_obj);
        if (S_ISDIR(mdd_object_type(mdd_obj)) &&
            dt_try_as_dir(ctxt, next))
                rc = next->do_ops->do_readpage(ctxt, next, rdpg);
        else
                rc = -ENOTDIR;
        mdd_read_unlock(ctxt, mdd_obj);
        return rc;
}

struct md_device_operations mdd_ops = {
        .mdo_root_get       = mdd_root_get,
        .mdo_statfs         = mdd_statfs,
        .mdo_get_maxsize    = mdd_get_maxsize,
};

static struct md_dir_operations mdd_dir_ops = {
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
        .moo_readlink      = mdd_readlink
};

static struct obd_ops mdd_obd_device_ops = {
        .o_owner = THIS_MODULE
};

static struct lu_device *mdd_device_alloc(const struct lu_context *ctx,
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

static void mdd_device_free(const struct lu_context *ctx,
                            struct lu_device *lu)
{
        struct mdd_device *m = lu2mdd_dev(lu);

        LASSERT(atomic_read(&lu->ld_ref) == 0);
        md_device_fini(&m->mdd_md_dev);
        OBD_FREE_PTR(m);
}

static int mdd_type_init(struct lu_device_type *t)
{
        return lu_context_key_register(&mdd_thread_key);
}

static void mdd_type_fini(struct lu_device_type *t)
{
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
