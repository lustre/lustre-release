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

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <lu_object.h>
#include <md_object.h>
#include <dt_object.h>

#include "mdd_internal.h"


static struct thandle* mdd_trans_start(const struct lu_context *ctxt,
                                       struct mdd_device *);
static void mdd_trans_stop(const struct lu_context *ctxt,
                           struct mdd_device *mdd, struct thandle *handle);
static struct dt_object* mdd_object_child(struct mdd_object *o);
static void mdd_lock(const struct lu_context *ctx,
                     struct mdd_object *obj, enum dt_lock_mode mode);
static void mdd_unlock(const struct lu_context *ctx,
                       struct mdd_object *obj, enum dt_lock_mode mode);
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
        struct mdd_object *mdo;

        OBD_ALLOC_PTR(mdo);
        if (mdo != NULL) {
                struct lu_object *o;
		
                o = mdd2lu_obj(mdo);
                lu_object_init(o, NULL, d);
                mdo->mod_obj.mo_ops = &mdd_obj_ops;
                mdo->mod_obj.mo_dir_ops = &mdd_dir_ops;
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

        o = lu_object_find(ctxt, d->mdd_md_dev.md_lu_dev.ld_site, f);
        if (IS_ERR(o))
                m = (struct mdd_object *)o;
        else
                m = lu2mdd_obj(lu_object_locate(o->lo_header, 
                                 d->mdd_md_dev.md_lu_dev.ld_type));
        RETURN(m);
}

static inline void mdd_object_put(const struct lu_context *ctxt,
                                  struct mdd_object *o)
{
        lu_object_put(ctxt, &o->mod_obj.mo_lu);
}

static int mdd_attr_get(const struct lu_context *ctxt,
                        struct md_object *obj, struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        int                rc;

        ENTRY;

        LASSERT(lu_object_exists(ctxt, &obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        rc = next->do_ops->do_attr_get(ctxt, next, &ma->ma_attr);
        if (rc == 0) {
                LASSERT((ma->ma_attr.la_mode & S_IFMT) ==
                        (obj->mo_lu.lo_header->loh_attr & S_IFMT));
                ma->ma_valid = MA_INODE;
                /* get LOV EA also */
                if ((S_ISREG(ma->ma_attr.la_mode)
                     || S_ISDIR(ma->ma_attr.la_mode))
                     && ma->ma_lmm != 0 && ma->ma_lmm_size > 0) {
                        rc = mdd_get_md(ctxt, obj, ma->ma_lmm, &ma->ma_lmm_size);
                        if (rc > 0) {
                                ma->ma_valid |= MA_LOV;
                                rc = 0;
                        }
                }
        }
        CDEBUG(D_INODE, "after getattr rc = %d, ma_valid = "LPX64"\n",
                        rc, ma->ma_valid);
        RETURN(rc);
}

static int mdd_xattr_get(const struct lu_context *ctxt, struct md_object *obj,
                         void *buf, int buf_len, const char *name)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        int rc;

        ENTRY;

        LASSERT(lu_object_exists(ctxt, &obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        rc = next->do_ops->do_xattr_get(ctxt, next, buf, buf_len, name);

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

        LASSERT(lu_object_exists(ctxt, &obj->mo_lu));

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

        LASSERT(lu_object_exists(ctxt, &obj->mo_lu));

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
        return (*p)(ctxt, cookie, LUSTRE_MDD0_NAME"-object@%p", o);
}

static int mdd_object_exists(const struct lu_context *ctx,
                             const struct lu_object *o)
{
        return lu_object_exists(ctx, lu_object_next(o));
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
                rc = 0;
        } else
                rc = PTR_ERR(root);
        RETURN(rc);
}

static int mdd_fs_setup(const struct lu_context *ctx, struct mdd_device *mdd)
{
        /*create PENDING and OBJECTS dir for open and llog*/
        return 0;
}

static int mdd_fs_cleanup(struct mdd_device *mdd)
{
        /*create PENDING and OBJECTS dir for open and llog*/
        return 0;
}

static int mdd_device_init(const struct lu_context *ctx,
                           struct lu_device *d, struct lu_device *next)
{
        struct mdd_device *mdd = lu2mdd_dev(d);
        int rc;
        ENTRY;

        mdd->mdd_child = lu2dt_dev(next);

        rc = mdd_fs_setup(ctx, mdd);
        if (rc)
                mdd_fs_cleanup(mdd);
        RETURN(rc);
}

static struct lu_device *mdd_device_fini(const struct lu_context *ctx,
                                         struct lu_device *d)
{
	struct mdd_device *m = lu2mdd_dev(d);
        struct lu_device *next = &m->mdd_child->dd_lu_dev;

        dt_device_fini(&m->mdd_lov_dev);

        return next;
}

static int mdd_process_config(const struct lu_context *ctxt,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct mdd_device *m    = lu2mdd_dev(d);
        struct dt_device  *dt   = m->mdd_child;
        struct lu_device  *next = &dt->dd_lu_dev;
        char              *dev = lustre_cfg_string(cfg, 0);
        int rc;

        switch(cfg->lcfg_command) {
        case LCFG_SETUP:
                rc = next->ld_ops->ldo_process_config(ctxt, next, cfg);
                if (rc)
                        GOTO(out, rc);
                dt->dd_ops->dt_conf_get(ctxt, dt, &m->mdd_dt_conf);

                rc = mdd_mount(ctxt, m);
                if (rc)
                        GOTO(out, rc);
                rc = mdd_init_obd(ctxt, m, dev);
                if (rc) {
                        CERROR("lov init error %d \n", rc);
                        GOTO(out, rc);
                }
                break;
        default:
                rc = next->ld_ops->ldo_process_config(ctxt, next, cfg);
                break;
        }
out:
        RETURN(rc);
}

struct lu_device_operations mdd_lu_ops = {
	.ldo_object_alloc   = mdd_object_alloc,
        .ldo_process_config = mdd_process_config,
};

static struct lu_object_operations mdd_lu_obj_ops = {
	.loo_object_init    = mdd_object_init,
	.loo_object_free    = mdd_object_free,
	.loo_object_print   = mdd_object_print,
	.loo_object_exists  = mdd_object_exists,
};

static void mdd_lock(const struct lu_context *ctxt,
                     struct mdd_object *obj, enum dt_lock_mode mode)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_lock(ctxt, next, mode);
}

static void mdd_unlock(const struct lu_context *ctxt,
                       struct mdd_object *obj, enum dt_lock_mode mode)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_unlock(ctxt, next, mode);
}

static void mdd_lock2(const struct lu_context *ctxt,
                      struct mdd_object *o0, struct mdd_object *o1)
{
        mdd_lock(ctxt, o0, DT_WRITE_LOCK);
        mdd_lock(ctxt, o1, DT_WRITE_LOCK);
}

static void mdd_unlock2(const struct lu_context *ctxt,
                        struct mdd_object *o0, struct mdd_object *o1)
{
        mdd_unlock(ctxt, o0, DT_WRITE_LOCK);
        mdd_unlock(ctxt, o1, DT_WRITE_LOCK);
}

static struct thandle* mdd_trans_start(const struct lu_context *ctxt,
                                       struct mdd_device *mdd)
{
        struct txn_param *p = &mdd_ctx_info(ctxt)->mti_param;

        return mdd_child_ops(mdd)->dt_trans_start(ctxt, mdd->mdd_child, p);
}

static void mdd_trans_stop(const struct lu_context *ctxt,
                           struct mdd_device *mdd, struct thandle *handle)
{
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

        if (!lu_object_exists(ctxt, mdd2lu_obj(obj))) {
                next = mdd_object_child(obj);
                rc = next->do_ops->do_create(ctxt, next, attr, handle);
        } else
                rc = -EEXIST;

        LASSERT(ergo(rc == 0, lu_object_exists(ctxt, mdd2lu_obj(obj))));

        RETURN(rc);
}

static int __mdd_attr_set(const struct lu_context *ctxt, struct mdd_object *o,
                          const struct lu_attr *attr, struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(ctxt, mdd2lu_obj(o)));
        next = mdd_object_child(o);
        return next->do_ops->do_attr_set(ctxt, next, attr, handle);
}

static int __mdd_xattr_set(const struct lu_context *ctxt, struct mdd_object *o,
                           const void *buf, int buf_len, const char *name,
                           int fl, struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(ctxt, mdd2lu_obj(o)));
        next = mdd_object_child(o);
        return next->do_ops->do_xattr_set(ctxt, next, buf, buf_len, name, fl,
                                          handle);
}


/* set attr and LOV EA at once, return updated attr */
static int mdd_attr_set(const struct lu_context *ctxt,
                        struct md_object *obj, struct md_attr *ma)
{
        struct mdd_object *mdo = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_ATTR_SET);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock(ctxt, mdo, DT_WRITE_LOCK);

        rc = __mdd_attr_set(ctxt, md2mdd_obj(obj), &ma->ma_attr, handle);
        if (rc == 0 && (ma->ma_valid & MA_LOV)) {
                /* set LOV ea now */
                rc = __mdd_xattr_set(ctxt, md2mdd_obj(obj),
                                     ma->ma_lmm, ma->ma_lmm_size,
                                     XATTR_NAME_LOV, 0, handle);
        }
        /* XXX: llog cancel cookie? */

        if (rc == 0)
                rc = mdd_attr_get(ctxt, obj, ma);

        mdd_unlock(ctxt, mdo, DT_WRITE_LOCK);
        mdd_trans_stop(ctxt, mdd, handle);

        RETURN(rc);
}

int mdd_xattr_set_txn(const struct lu_context *ctxt, struct md_object *obj,
                      const void *buf, int buf_len, const char *name, int fl,
                      struct thandle *handle)
{
        struct mdd_object *mdo = md2mdd_obj(obj);
        int  rc;
        ENTRY;

        mdd_lock(ctxt, mdo, DT_WRITE_LOCK);
        rc = __mdd_xattr_set(ctxt, md2mdd_obj(obj), buf, buf_len, name,
                             fl, handle);
        mdd_unlock(ctxt, mdo, DT_WRITE_LOCK);

        RETURN(rc);
}

static int mdd_xattr_set(const struct lu_context *ctxt, struct md_object *obj,
                         const void *buf, int buf_len, const char *name, int fl)
{
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_XATTR_SET);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = mdd_xattr_set_txn(ctxt, obj, buf, buf_len, name, fl, handle);

        mdd_trans_stop(ctxt, mdd, handle);

        RETURN(rc);
}

static int __mdd_xattr_del(const struct lu_context *ctxt,struct mdd_device *mdd,
                           struct mdd_object *obj,
                           const char *name, struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(ctxt, mdd2lu_obj(obj)));
        next = mdd_object_child(obj);
        return next->do_ops->do_xattr_del(ctxt, next, name, handle);
}

int mdd_xattr_del(const struct lu_context *ctxt, struct md_object *obj,
                  const char *name)
{
        struct mdd_object *mdo = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_XATTR_SET);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock(ctxt, mdo, DT_WRITE_LOCK);
        rc = __mdd_xattr_del(ctxt, mdd, md2mdd_obj(obj), name, handle);
        mdd_unlock(ctxt, mdo, DT_WRITE_LOCK);

        mdd_trans_stop(ctxt, mdd, handle);

        RETURN(rc);
}

static int __mdd_index_insert(const struct lu_context *ctxt,
                              struct mdd_object *pobj, const struct lu_fid *lf,
                              const char *name, struct thandle *handle)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

        if (dt_try_as_dir(ctxt, next))
                rc = next->do_index_ops->dio_insert(ctxt, next,
                                         (struct dt_rec *)lf,
                                         (struct dt_key *)name, handle);
        else
                rc = -ENOTDIR;
        RETURN(rc);
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

/*Check whether it may create the cobj under the pobj*/ 
static int mdd_may_create(const struct lu_context *ctxt, 
                          struct mdd_object *pobj, struct mdd_object *cobj)
{
        ENTRY;
        if (cobj && lu_object_exists(ctxt, &cobj->mod_obj.mo_lu))
                RETURN(-EEXIST);

        /*check pobj may create or not*/
        RETURN(0);
}
/*Check whether it may delete the cobj under the pobj*/
static int mdd_may_delete(const struct lu_context *ctxt,
                          struct mdd_object *pobj, struct mdd_object *cobj,
                          struct lu_attr *cla, int is_dir)
{
        struct mdd_device *mdd = mdo2mdd(&pobj->mod_obj);
        int rc = 0;
        
        ENTRY;
        if (!cobj || !lu_object_exists(ctxt, &cobj->mod_obj.mo_lu))
                RETURN(-ENOENT);
      
        /*TODO:check append flags*/
        if (is_dir) {
                if (!S_ISDIR(cla->la_mode))
                        RETURN(-ENOTDIR);

                if (lu_fid_eq(mdd2_lu_fid(cobj), 
                                        &mdd->mdd_root_fid))
                        RETURN(-EBUSY);
                
        } else if (S_ISDIR(cla->la_mode))
                        RETURN(-EISDIR);
                
        /*DEAD dir checking*/
        RETURN(rc);
}

static int mdd_link(const struct lu_context *ctxt, struct md_object *tgt_obj,
                    struct md_object *src_obj, const char *name)
{
        struct mdd_object *mdd_tobj = md2mdd_obj(tgt_obj);
        struct mdd_object *mdd_sobj = md2mdd_obj(src_obj);
        struct mdd_device *mdd = mdo2mdd(src_obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_LINK);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock2(ctxt, mdd_tobj, mdd_sobj);

        /*
         * XXX Check that link can be added to the child.
         */

        rc = __mdd_index_insert(ctxt, mdd_tobj, lu_object_fid(&src_obj->mo_lu),
                                name, handle);
        if (rc == 0)
                __mdd_ref_add(ctxt, mdd_sobj, handle);

        mdd_unlock2(ctxt, mdd_tobj, mdd_sobj);
        mdd_trans_stop(ctxt, mdd, handle);
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
        it = iops->init(ctx, obj);
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

static int mdd_unlink(const struct lu_context *ctxt, struct md_object *pobj,
                      struct md_object *cobj, const char *name,
                      struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object *mdd_cobj = md2mdd_obj(cobj);
        struct thandle    *handle;
        int rc;
        ENTRY;

        if (S_ISDIR(lu_object_attr(&cobj->mo_lu))) {
                if (!S_ISDIR(ma->ma_attr.la_mode))
                        RETURN(-EISDIR);
        } else if (S_ISDIR(ma->ma_attr.la_mode))
                RETURN(-ENOTDIR);

        mdd_txn_param_build(ctxt, &MDD_TXN_UNLINK);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock2(ctxt, mdd_pobj, mdd_cobj);

        /* rmdir checks */
        if (S_ISDIR(lu_object_attr(&cobj->mo_lu))) {
                rc = mdd_dir_is_empty(ctxt, mdd_cobj);
                if (rc != 0)
                        GOTO(cleanup, rc);
        }

        rc = __mdd_index_delete(ctxt, mdd_pobj, name, handle);
        if (rc)
                GOTO(cleanup, rc);

        __mdd_ref_del(ctxt, mdd_cobj, handle);
        if (S_ISDIR(ma->ma_attr.la_mode)) {
                /* unlink dot */
                __mdd_ref_del(ctxt, mdd_cobj, handle);
                /* unlink dotdot */
                __mdd_ref_del(ctxt, mdd_pobj, handle);
        }
        mdd_attr_get(ctxt, cobj, ma);

#if 0
        /*This should be moved to handle last unlink. wait open
         * orphan prototype finished*/
        if (S_ISREG(ma->ma_attr.la_mode) && (ma->ma_valid & MA_LOV) &&
            ma->ma_attr.la_nlink == 0 && cobj->mo_lu.lo_header->loh_ref == 1) {
                rc = mdd_unlink_log(ctxt, mdd, mdd_cobj, ma);
        }
#endif
cleanup:
        mdd_unlock2(ctxt, mdd_pobj, mdd_cobj);
        mdd_trans_stop(ctxt, mdd, handle);
        RETURN(rc);
}

static int mdd_parent_fid(const struct lu_context *ctxt,
                          struct mdd_object *obj,
                          struct lu_fid *fid)
{
        int rc;

        rc = mdd_lookup(ctxt, &obj->mod_obj, dotdot, fid);

        return rc;
}

static inline const struct lu_fid *mdo2fid(const struct mdd_object *obj)
{
        return lu_object_fid(&obj->mod_obj.mo_lu);
}

static int mdd_is_parent(const struct lu_context *ctxt,
                         struct mdd_device *mdd,
                         struct mdd_object *p1,
                         struct mdd_object *p2)
{
        struct lu_fid * pfid;
        int rc;

        pfid = &mdd_ctx_info(ctxt)->mti_fid;
        do {
                rc = mdd_parent_fid(ctxt, p1, pfid);
                if (rc)
                        RETURN(rc);
                if (lu_fid_eq(pfid, mdo2fid(p2))) {
                        RETURN(1);
                }
        } while (!lu_fid_eq(pfid, &mdd->mdd_root_fid));

        RETURN(rc);
}

static int mdd_rename_lock(const struct lu_context *ctxt,
                           struct mdd_device *mdd,
                           struct mdd_object *src_pobj,
                           struct mdd_object *tgt_pobj)
{
        ENTRY;

        if (src_pobj == tgt_pobj) {
                mdd_lock(ctxt, src_pobj, DT_WRITE_LOCK);
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
        if (mdd_is_parent(ctxt, mdd, src_pobj, tgt_pobj)) {
                mdd_lock2(ctxt, tgt_pobj, src_pobj);
                RETURN(0);
        }
        if (mdd_is_parent(ctxt, mdd, tgt_pobj, src_pobj)) {
                mdd_lock2(ctxt, src_pobj, tgt_pobj);
                RETURN(0);
        }

        mdd_lock2(ctxt, src_pobj, tgt_pobj);
        RETURN(0);
}

static void mdd_rename_unlock(const struct lu_context *ctxt,
                              struct mdd_object *src_pobj,
                              struct mdd_object *tgt_pobj)
{
        mdd_unlock(ctxt, src_pobj, DT_WRITE_LOCK);
        if (src_pobj != tgt_pobj)
                mdd_unlock(ctxt, tgt_pobj, DT_WRITE_LOCK);
}

static umode_t mdd_object_type(const struct mdd_object *obj)
{
        return lu_object_attr(&obj->mod_obj.mo_lu);
}

static int mdd_rename_sanity_check (const struct lu_context *ctxt,
                                    struct md_object *src_pobj,
                                    struct md_object *tgt_pobj,
                                    const struct lu_fid *lf,
                                    struct md_object *tobj)
{
        struct mdd_device *mdd =mdo2mdd(src_pobj);
        struct mdd_object *sobj = mdd_object_find(ctxt, mdd, lf);
        struct lu_attr *la = &mdd_ctx_info(ctxt)->mti_la; 
        struct dt_object  *next;
        int rc = 0, src_is_dir, tgt_is_dir;
        ENTRY;

        next = mdd_object_child(sobj);
        rc = next->do_ops->do_attr_get(ctxt, next, la);
        if (rc) 
                GOTO(out, rc);
        src_is_dir = S_ISDIR(la->la_mode);
        rc = mdd_may_delete(ctxt, md2mdd_obj(src_pobj), sobj, la, src_is_dir);
        if (rc)
                GOTO(out, rc);
        if (!tobj) {
                rc = mdd_may_create(ctxt, md2mdd_obj(tgt_pobj), NULL);
                GOTO(out, rc);
        }
        
        next = mdd_object_child(md2mdd_obj(tobj));
        rc = next->do_ops->do_attr_get(ctxt, next, la);
        if (rc)
                GOTO(out, rc);
        rc = mdd_may_delete(ctxt, md2mdd_obj(tgt_pobj),md2mdd_obj(tobj),
                            la, src_is_dir);
        if (rc)
                GOTO(out, rc);

        tgt_is_dir = S_ISDIR(la->la_mode);
        if (tgt_is_dir && mdd_dir_is_empty(ctxt, md2mdd_obj(tobj)))
                GOTO(out, rc = -ENOTEMPTY);
out:
        mdd_object_put(ctxt, sobj);
        RETURN(rc);
}

static int mdd_rename(const struct lu_context *ctxt, struct md_object *src_pobj,
                      struct md_object *tgt_pobj, const struct lu_fid *lf,
                      const char *sname, struct md_object *tobj,
                      const char *tname)
{
        struct mdd_device *mdd = mdo2mdd(src_pobj);
        struct mdd_object *mdd_spobj = md2mdd_obj(src_pobj);
        struct mdd_object *mdd_tpobj = md2mdd_obj(tgt_pobj);
        struct mdd_object *mdd_tobj = NULL;
        struct thandle *handle;
        int rc, locked = 0;
        ENTRY;

        rc = mdd_rename_sanity_check(ctxt, src_pobj, tgt_pobj, lf, tobj);
        if (rc)
                RETURN(rc);
        mdd_txn_param_build(ctxt, &MDD_TXN_RENAME);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        /*FIXME: Should consider tobj and sobj too in rename_lock*/
        rc = mdd_rename_lock(ctxt, mdd, mdd_spobj, mdd_tpobj);
        if (rc)
                GOTO(cleanup, rc);
        locked = 1;
        if (tobj)
                mdd_tobj = md2mdd_obj(tobj);

        rc = __mdd_index_delete(ctxt, mdd_spobj, sname, handle);
        if (rc)
                GOTO(cleanup, rc);
        /*FIXME: no sobj now, we should check sobj type, if it is dir,
         * the nlink of its parent should be dec
         */
        if (tobj) {
                rc = __mdd_index_delete(ctxt, mdd_tpobj, tname, handle);
                if (rc)
                        GOTO(cleanup, rc);
        }

        rc = __mdd_index_insert(ctxt, mdd_tpobj, lf, tname, handle);
        if (rc)
                GOTO(cleanup, rc);

        if (tobj && lu_object_exists(ctxt, &tobj->mo_lu)) {
                __mdd_ref_del(ctxt, mdd_tobj, handle);
                if (S_ISDIR(mdd_object_type(mdd_tobj)))
                        __mdd_ref_del(ctxt, mdd_tpobj, handle);
                /* XXX: mdd_attr_get(ctxt, tobj, ma); needed here */
        }

cleanup:
       /*FIXME: should we do error handling here?*/
        if (locked)
                mdd_rename_unlock(ctxt, mdd_spobj, mdd_tpobj);
        mdd_trans_stop(ctxt, mdd, handle);
        RETURN(rc);
}

static int mdd_lookup(const struct lu_context *ctxt, struct md_object *pobj,
                      const char *name, struct lu_fid* fid)
{
        struct mdd_object   *mdo = md2mdd_obj(pobj);
        struct dt_object    *dir = mdd_object_child(mdo);
        struct dt_rec       *rec    = (struct dt_rec *)fid;
        const struct dt_key *key = (const struct dt_key *)name;
        int rc;
        ENTRY;

        mdd_lock(ctxt, mdo, DT_READ_LOCK);
        if (S_ISDIR(mdd_object_type(mdo)) && dt_try_as_dir(ctxt, dir))
                rc = dir->do_index_ops->dio_lookup(ctxt, dir, rec, key);
        else
                rc = -ENOTDIR;
        mdd_unlock(ctxt, mdo, DT_READ_LOCK);
        RETURN(rc);
}

static int __mdd_object_initialize(const struct lu_context *ctxt,
                                   struct mdd_object *parent,
                                   struct mdd_object *child,
                                   struct md_attr *ma, struct thandle *handle)
{
        struct lu_attr    *la = &mdd_ctx_info(ctxt)->mti_la;
        struct dt_object  *dt_parent = mdd_object_child(parent);
        struct dt_object  *dt_child = mdd_object_child(child);
        int                rc;
        ENTRY;

        /* FIXME & TODO: valid code need some convertion from Lustre to linux */
        ma->ma_attr.la_valid = ATTR_UID   | ATTR_GID   | ATTR_ATIME |
                               ATTR_MTIME | ATTR_CTIME;

        rc = dt_parent->do_ops->do_attr_get(ctxt, dt_parent, la);
        if (rc != 0)
                RETURN(rc);
        if (la->la_mode & S_ISGID) {
                CDEBUG(D_ERROR, "Parent "DFID3" is a GID\n", 
                                PFID3(mdo2fid(parent)));
                ma->ma_attr.la_gid = la->la_gid;
                rc = dt_child->do_ops->do_attr_get(ctxt, dt_child, la);
                if (rc != 0)
                        RETURN(rc);

                if (S_ISDIR(la->la_mode)) {
                        ma->ma_attr.la_mode = la->la_mode | S_ISGID;
                        ma->ma_attr.la_valid |= ATTR_MODE;
                }
        }

        CDEBUG(D_ERROR, "Child "DFID3" has u/gid: %d:%d\n", 
                        PFID3(mdo2fid(child)), ma->ma_attr.la_uid, 
                        ma->ma_attr.la_gid);
        rc = dt_child->do_ops->do_attr_set(ctxt, dt_child, &ma->ma_attr,handle);
        if (rc != 0)
                RETURN(rc); 

        ma->ma_attr.la_valid = ATTR_MTIME | ATTR_CTIME;
        rc = dt_parent->do_ops->do_attr_set(ctxt, dt_parent, &ma->ma_attr, handle);
        if (rc != 0)
                RETURN(rc); 
        
        if (S_ISDIR(ma->ma_attr.la_mode)) {
                /* add . and .. for newly created dir */
                __mdd_ref_add(ctxt, child, handle);
                rc = __mdd_index_insert(ctxt, child,
                                        mdo2fid(child), dot, handle);
                if (rc == 0) {
                        rc = __mdd_index_insert(ctxt, child, mdo2fid(parent),
                                                dotdot, handle);
                        if (rc == 0)
                                __mdd_ref_add(ctxt, parent, handle);
                        else {
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
                           const void *eadata, int eadatasize,
                           struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdo = md2mdd_obj(pobj);
        struct mdd_object *son = md2mdd_obj(cobj);
        struct lu_attr    *attr = &ma->ma_attr;
        struct lov_mds_md *lmm = NULL;
        struct thandle    *handle;
        int lmm_size = 0;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_CREATE_DATA);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        /*
         * XXX: should take transaction handle.
         */
        rc = mdd_lov_create(ctxt, mdd, mdo, son, &lmm, &lmm_size, eadata,
                            eadatasize, attr);
        if (rc == 0) {
                rc = mdd_lov_set_md(ctxt, pobj, cobj, lmm,
                                    lmm_size, attr->la_mode, handle);
                if (rc == 0)
                        rc = mdd_attr_get(ctxt, cobj, ma);
        }

        mdd_trans_stop(ctxt, mdd, handle);
        RETURN(rc);
}

static int mdd_create_sanity_check(const struct lu_context *ctxt,
                                   struct mdd_device *mdd,
                                   struct md_object *pobj,
                                   const char *name, struct md_attr *ma)
{
        struct lu_fid *fid;
        int rc;

        fid = &mdd_ctx_info(ctxt)->mti_fid;
        rc = mdd_lookup(ctxt, pobj, name, fid);
        if (rc != -ENOENT) {
                rc = rc ? rc : -EEXIST;
                RETURN(rc);
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
        struct mdd_object *mdo = md2mdd_obj(pobj);
        struct mdd_object *son = md2mdd_obj(child);
        struct lu_attr *attr = &ma->ma_attr;
        struct lov_mds_md *lmm = NULL;
        struct thandle *handle;
        int rc, created = 0, inserted = 0, lmm_size = 0;
        ENTRY;

        /* sanity checks before big job */
        rc = mdd_create_sanity_check(ctxt, mdd, pobj, name, ma);
        if (rc)
                RETURN(rc);
        /* no RPC inside the transaction, so OST objects should be created at
         * first */
        if (S_ISREG(attr->la_mode)) {
                const void *eadata = spec->u.sp_ea.eadata;
                int eadatasize = spec->u.sp_ea.eadatalen;

                rc = mdd_lov_create(ctxt, mdd, mdo, son, &lmm, &lmm_size,
                                    eadata, eadatasize, attr);
                if (rc)
                        RETURN(rc);
        }

        mdd_txn_param_build(ctxt, &MDD_TXN_MKDIR);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock(ctxt, mdo, DT_WRITE_LOCK);

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

        rc = __mdd_object_create(ctxt, son, ma, handle);
        if (rc)
                GOTO(cleanup, rc);

        created = 1;

        rc = __mdd_object_initialize(ctxt, mdo, son, ma, handle);
        if (rc)
                /*
                 * Object has no links, so it will be destroyed when last
                 * reference is released. (XXX not now.)
                 */
                GOTO(cleanup, rc);

        rc = __mdd_index_insert(ctxt, mdo, lu_object_fid(&child->mo_lu),
                                name, handle);

        if (rc)
                GOTO(cleanup, rc);

        inserted = 1;
        rc = mdd_lov_set_md(ctxt, pobj, child, lmm, lmm_size, attr->la_mode,
                            handle);
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
        mdd_attr_get(ctxt, child, ma);
cleanup:
        if (rc && created) {
                int rc2 = 0;

                if (inserted) {
                        rc2 = __mdd_index_delete(ctxt, mdo, name, handle);
                        if (rc2)
                                CERROR("error can not cleanup destroy %d\n",
                                       rc2);
                }
                if (rc2 == 0)
                        __mdd_ref_del(ctxt, son, handle);
        }
        if (lmm)
                OBD_FREE(lmm, lmm_size);
        mdd_unlock(ctxt, mdo, DT_WRITE_LOCK);
        mdd_trans_stop(ctxt, mdd, handle);
        RETURN(rc);
}
/* partial operation */
static int mdd_object_create(const struct lu_context *ctxt,
                             struct md_object *obj,
                             const struct md_create_spec *spec,
                             struct md_attr *ma)
{

        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_OBJECT_CREATE);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = __mdd_object_create(ctxt, md2mdd_obj(obj), ma, handle);
/* XXX: parent fid is needed here
        rc = __mdd_object_initialize(ctxt, mdo, son, ma, handle);
*/
        mdd_attr_get(ctxt, obj, ma);

        mdd_trans_stop(ctxt, mdd, handle);

        RETURN(rc);
}
/* partial operation */
static int mdd_name_insert(const struct lu_context *ctxt,
                           struct md_object *pobj,
                           const char *name, const struct lu_fid *fid)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdo = md2mdd_obj(pobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_INDEX_INSERT);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock(ctxt, mdo, DT_WRITE_LOCK);

        rc = __mdd_index_insert(ctxt, mdo, fid, name, handle);

        mdd_unlock(ctxt, mdo, DT_WRITE_LOCK);
        mdd_trans_stop(ctxt, mdd, handle);
        RETURN(rc);
}

static int mdd_name_remove(const struct lu_context *ctxt,
                           struct md_object *pobj,
                           const char *name)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdo = md2mdd_obj(pobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_INDEX_DELETE);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock(ctxt, mdo, DT_WRITE_LOCK);

        rc = __mdd_index_delete(ctxt, mdo, name, handle);

        mdd_unlock(ctxt, mdo, DT_WRITE_LOCK);

        mdd_trans_stop(ctxt, mdd, handle);
        RETURN(rc);
}

static int mdd_rename_tgt(const struct lu_context *ctxt, struct md_object *pobj,
                          struct md_object *tobj, const struct lu_fid *lf,
                          const char *name)
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

        if (tobj) {
                rc = __mdd_index_delete(ctxt, mdd_tpobj, name, handle);
                if (rc)
                        GOTO(cleanup, rc);
        }

        rc = __mdd_index_insert(ctxt, mdd_tpobj, lf, name, handle);
        if (rc)
                GOTO(cleanup, rc);

        if (tobj && lu_object_exists(ctxt, &tobj->mo_lu))
                __mdd_ref_del(ctxt, mdd_tobj, handle);
cleanup:
       /*FIXME: should we do error handling here?*/
        mdd_unlock2(ctxt, mdd_tpobj, mdd_tobj);
        mdd_trans_stop(ctxt, mdd, handle);
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
        int rc;

        ENTRY;

        rc = mdd_lov_mdsize(ctx, mdd, md_size);
        if (rc)
                RETURN(rc);
        rc = mdd_lov_cookiesize(ctx, mdd, cookie_size);

        RETURN(rc);
}

static void __mdd_ref_add(const struct lu_context *ctxt, struct mdd_object *obj,
                         struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(ctxt, mdd2lu_obj(obj)));
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

        mdd_lock(ctxt, mdd_obj, DT_WRITE_LOCK);
        __mdd_ref_add(ctxt, mdd_obj, handle);
        mdd_unlock(ctxt, mdd_obj, DT_WRITE_LOCK);

        mdd_trans_stop(ctxt, mdd, handle);

        RETURN(0);
}

static void
__mdd_ref_del(const struct lu_context *ctxt, struct mdd_object *obj,
              struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);

        LASSERT(lu_object_exists(ctxt, mdd2lu_obj(obj)));

        next->do_ops->do_ref_del(ctxt, next, handle);
}

static int mdd_ref_del(const struct lu_context *ctxt, struct md_object *obj,
                       struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        ENTRY;

        mdd_txn_param_build(ctxt, &MDD_TXN_XATTR_SET);
        handle = mdd_trans_start(ctxt, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_lock(ctxt, mdd_obj, DT_WRITE_LOCK);
        __mdd_ref_del(ctxt, mdd_obj, handle);
        mdd_attr_get(ctxt, obj, ma);
        mdd_unlock(ctxt, mdd_obj, DT_WRITE_LOCK);

        mdd_trans_stop(ctxt, mdd, handle);

        RETURN(0);
}

static int mdd_open(const struct lu_context *ctxt, struct md_object *obj)
{
        return 0;
}

static int mdd_close(const struct lu_context *ctxt, struct md_object *obj)
{
        return 0;
}

static int mdd_readpage(const struct lu_context *ctxt, struct md_object *obj,
                        const struct lu_rdpg *rdpg)
{
        struct dt_object *next;
        struct mdd_object *mdd = md2mdd_obj(obj);
        int rc;

        LASSERT(lu_object_exists(ctxt, mdd2lu_obj(md2mdd_obj(obj))));
        next = mdd_object_child(md2mdd_obj(obj));

        mdd_lock(ctxt, mdd, DT_READ_LOCK);
        if (S_ISDIR(mdd_object_type(mdd)) && dt_try_as_dir(ctxt, next))
                rc = next->do_ops->do_readpage(ctxt, next, rdpg);
        else
                rc = -ENOTDIR;
        mdd_unlock(ctxt, mdd, DT_READ_LOCK);
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

struct lu_device *mdd_device_alloc(const struct lu_context *ctx,
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

static void mdd_device_free(const struct lu_context *ctx, struct lu_device *lu)
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
        .ldt_name     = LUSTRE_MDD0_NAME,
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

        lprocfs_init_vars(mdd, &lvars);
        return class_register_type(&mdd_obd_device_ops, NULL, lvars.module_vars,
                                   LUSTRE_MDD0_NAME, &mdd_device_type);
}

static void __exit mdd_mod_exit(void)
{
        class_unregister_type(LUSTRE_MDD0_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Meta-data Device Prototype ("LUSTRE_MDD0_NAME")");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.1.0", mdd_mod_init, mdd_mod_exit);
