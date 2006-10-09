/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/osd/osd_handler.c
 *  Top-level entry points into osd module
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/* prerequisite for linux/xattr.h */
#include <linux/types.h>
/* prerequisite for linux/xattr.h */
#include <linux/fs.h>
/* XATTR_{REPLACE,CREATE} */
#include <linux/xattr.h>
/*
 * XXX temporary stuff: direct access to ldiskfs/jdb. Interface between osd
 * and file system is not yet specified.
 */
/* handle_t, journal_start(), journal_stop() */
#include <linux/jbd.h>
/* LDISKFS_SB() */
#include <linux/ldiskfs_fs.h>
#include <linux/ldiskfs_jbd.h>
/* simple_mkdir() */
#include <lvfs.h>

/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd_support.h>
/* struct ptlrpc_thread */
#include <lustre_net.h>
/* LUSTRE_OSD_NAME */
#include <obd.h>
/* class_register_type(), class_unregister_type(), class_get_type() */
#include <obd_class.h>
#include <lustre_disk.h>

/* fid_is_local() */
#include <lustre_fid.h>
#include <linux/lustre_iam.h>

#include "osd_internal.h"
#include "osd_igif.h"

struct osd_object {
        struct dt_object       oo_dt;
        /*
         * Inode for file system object represented by this osd_object. This
         * inode is pinned for the whole duration of lu_object life.
         */
        struct inode          *oo_inode;
        struct rw_semaphore    oo_sem;
        struct iam_container   oo_container;
        struct iam_descr       oo_descr;
        struct iam_path_descr *oo_ipd;
        const struct lu_env   *oo_owner;
};

/*
 * osd device.
 */
struct osd_device {
        /* super-class */
        struct dt_device          od_dt_dev;
        /* information about underlying file system */
        struct lustre_mount_info *od_mount;
        /* object index */
        struct osd_oi             od_oi;
        /*
         * XXX temporary stuff for object index: directory where every object
         * is named by its fid.
         */
        struct dentry            *od_obj_area;

        /* Environment for transaction commit callback.
         * Currently, OSD is based on ext3/JBD. Transaction commit in ext3/JBD
         * is serialized, that is there is no more than one transaction commit
         * at a time (JBD journal_commit_transaction() is serialized).
         * This means that it's enough to have _one_ lu_context.
         */
        struct lu_env             od_env_for_commit;
        /*
         * Capability
         */
        unsigned int              od_fl_capa:1;
        unsigned long             od_capa_timeout;
        __u32                     od_capa_alg;
        struct lustre_capa_key   *od_capa_keys;
};

static int   osd_root_get      (const struct lu_env *env,
                                struct dt_device *dev, struct lu_fid *f);
static int   osd_statfs        (const struct lu_env *env,
                                struct dt_device *dev, struct kstatfs *sfs);

static int   lu_device_is_osd  (const struct lu_device *d);
static void  osd_mod_exit      (void) __exit;
static int   osd_mod_init      (void) __init;
static int   osd_type_init     (struct lu_device_type *t);
static void  osd_type_fini     (struct lu_device_type *t);
static int   osd_object_init   (const struct lu_env *env,
                                struct lu_object *l);
static void  osd_object_release(const struct lu_env *env,
                                struct lu_object *l);
static int   osd_object_print  (const struct lu_env *env, void *cookie,
                                lu_printer_t p, const struct lu_object *o);
static void  osd_device_free   (const struct lu_env *env,
                                struct lu_device *m);
static void *osd_key_init      (const struct lu_context *ctx,
                                struct lu_context_key *key);
static void  osd_key_fini      (const struct lu_context *ctx,
                                struct lu_context_key *key, void *data);
static void  osd_key_exit      (const struct lu_context *ctx,
                                struct lu_context_key *key, void *data);
static int   osd_has_index     (const struct osd_object *obj);
static void  osd_object_init0  (struct osd_object *obj);
static int   osd_device_init   (const struct lu_env *env,
                                struct lu_device *d, struct lu_device *);
static int   osd_fid_lookup    (const struct lu_env *env,
                                struct osd_object *obj,
                                const struct lu_fid *fid);
static int   osd_inode_getattr (const struct lu_env *env,
                                struct inode *inode, struct lu_attr *attr);
static int   osd_inode_setattr (const struct lu_env *env,
                                struct inode *inode, const struct lu_attr *attr);
static int   osd_param_is_sane (const struct osd_device *dev,
                                const struct txn_param *param);
static int   osd_index_lookup  (const struct lu_env *env,
                                struct dt_object *dt,
                                struct dt_rec *rec, const struct dt_key *key,
                                struct lustre_capa *capa);
static int   osd_index_insert  (const struct lu_env *env,
                                struct dt_object *dt,
                                const struct dt_rec *rec,
                                const struct dt_key *key,
                                struct thandle *handle,
                                struct lustre_capa *capa);
static int   osd_index_delete  (const struct lu_env *env,
                                struct dt_object *dt, const struct dt_key *key,
                                struct thandle *handle,
                                struct lustre_capa *capa);
static int   osd_index_probe   (const struct lu_env *env,
                                struct osd_object *o,
                                const struct dt_index_features *feat);
static int   osd_index_try     (const struct lu_env *env,
                                struct dt_object *dt,
                                const struct dt_index_features *feat);
static void  osd_index_fini    (struct osd_object *o);

static void  osd_it_fini       (const struct lu_env *env, struct dt_it *di);
static int   osd_it_get        (const struct lu_env *env,
                                struct dt_it *di, const struct dt_key *key);
static void  osd_it_put        (const struct lu_env *env, struct dt_it *di);
static int   osd_it_next       (const struct lu_env *env, struct dt_it *di);
static int   osd_it_del        (const struct lu_env *env, struct dt_it *di,
                                struct thandle *th);
static int   osd_it_key_size   (const struct lu_env *env,
                                const struct dt_it *di);
static void  osd_conf_get      (const struct lu_env *env,
                                const struct dt_device *dev,
                                struct dt_device_param *param);
static int   osd_read_locked   (const struct lu_env *env,
                                struct osd_object *o);
static int   osd_write_locked  (const struct lu_env *env,
                                struct osd_object *o);
static void  osd_trans_stop    (const struct lu_env *env,
                                struct thandle *th);

static struct osd_object  *osd_obj          (const struct lu_object *o);
static struct osd_device  *osd_dev          (const struct lu_device *d);
static struct osd_device  *osd_dt_dev       (const struct dt_device *d);
static struct osd_object  *osd_dt_obj       (const struct dt_object *d);
static struct osd_device  *osd_obj2dev      (const struct osd_object *o);
static struct lu_device   *osd2lu_dev       (struct osd_device *osd);
static struct lu_device   *osd_device_fini  (const struct lu_env *env,
                                             struct lu_device *d);
static struct lu_device   *osd_device_alloc (const struct lu_env *env,
                                             struct lu_device_type *t,
                                             struct lustre_cfg *cfg);
static struct lu_object   *osd_object_alloc (const struct lu_env *env,
                                             const struct lu_object_header *hdr,
                                             struct lu_device *d);
static struct inode       *osd_iget         (struct osd_thread_info *info,
                                             struct osd_device *dev,
                                             const struct osd_inode_id *id);
static struct super_block *osd_sb           (const struct osd_device *dev);
static struct dt_it       *osd_it_init      (const struct lu_env *env,
                                             struct dt_object *dt, int wable);
static struct dt_key      *osd_it_key       (const struct lu_env *env,
                                             const struct dt_it *di);
static struct dt_rec      *osd_it_rec       (const struct lu_env *env,
                                             const struct dt_it *di);
static struct timespec    *osd_inode_time   (const struct lu_env *env,
                                             struct inode *inode,
                                             __u64 seconds);
static struct thandle     *osd_trans_start  (const struct lu_env *env,
                                             struct dt_device *d,
                                             struct txn_param *p);
static journal_t          *osd_journal      (const struct osd_device *dev);

static struct lu_device_type_operations osd_device_type_ops;
static struct lu_device_type            osd_device_type;
static struct lu_object_operations      osd_lu_obj_ops;
static struct obd_ops                   osd_obd_device_ops;
static struct lprocfs_vars              lprocfs_osd_module_vars[];
static struct lprocfs_vars              lprocfs_osd_obd_vars[];
static struct lu_device_operations      osd_lu_ops;
static struct lu_context_key            osd_key;
static struct dt_object_operations      osd_obj_ops;
static struct dt_body_operations        osd_body_ops;
static struct dt_index_operations       osd_index_ops;
static struct dt_index_operations       osd_index_compat_ops;

struct osd_thandle {
        struct thandle          ot_super;
        handle_t               *ot_handle;
        struct journal_callback ot_jcb;
};

/*
 * Invariants, assertions.
 */

#define OSD_INVARIANT_CHECKS (0)

#if OSD_INVARIANT_CHECKS
static int osd_invariant(const struct osd_object *obj)
{
        return
                obj != NULL &&
                ergo(obj->oo_inode != NULL,
                     obj->oo_inode->i_sb == osd_sb(osd_obj2dev(obj)) &&
                     atomic_read(&obj->oo_inode->i_count) > 0) &&
                ergo(obj->oo_container.ic_object != NULL,
                     obj->oo_container.ic_object == obj->oo_inode);
}
#else
#define osd_invariant(obj) (1)
#endif

static int osd_read_locked(const struct lu_env *env, struct osd_object *o)
{
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);

        return oti->oti_r_locks > 0;
}

static int osd_write_locked(const struct lu_env *env, struct osd_object *o)
{
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);

        return oti->oti_w_locks > 0 && o->oo_owner == env;
}

static void osd_fid_build_name(const struct lu_fid *fid, char *name)
{
        static const char *qfmt = LPX64":%lx:%lx";

        sprintf(name, qfmt, fid_seq(fid), fid_oid(fid), fid_ver(fid));
}

/* helper to push us into KERNEL_DS context */
static struct file *osd_rw_init(const struct lu_env *env,
                                struct inode *inode, mm_segment_t *seg)
{
        struct osd_thread_info *info   = lu_context_key_get(&env->le_ctx, &osd_key);
        struct dentry          *dentry = &info->oti_dentry;
        struct file            *file   = &info->oti_file;

        file->f_dentry = dentry;
        file->f_mapping = inode->i_mapping;
        file->f_op      = inode->i_fop;
        file->f_mode    = FMODE_WRITE|FMODE_READ;
        dentry->d_inode = inode;

        *seg = get_fs();
        set_fs(KERNEL_DS);
        return file;
}

/* helper to pop us from KERNEL_DS context */
static void osd_rw_fini(mm_segment_t *seg)
{
        set_fs(*seg);
}

static int osd_root_get(const struct lu_env *env,
                        struct dt_device *dev, struct lu_fid *f)
{
        struct inode *inode;

        inode = osd_sb(osd_dt_dev(dev))->s_root->d_inode;
        lu_igif_build(f, inode->i_ino, inode->i_generation);
        return 0;
}

/*
 * OSD object methods.
 */

static struct lu_object *osd_object_alloc(const struct lu_env *env,
                                          const struct lu_object_header *hdr,
                                          struct lu_device *d)
{
        struct osd_object *mo;

        OBD_ALLOC_PTR(mo);
        if (mo != NULL) {
                struct lu_object *l;

                l = &mo->oo_dt.do_lu;
                dt_object_init(&mo->oo_dt, NULL, d);
                mo->oo_dt.do_ops = &osd_obj_ops;
                l->lo_ops = &osd_lu_obj_ops;
                init_rwsem(&mo->oo_sem);
                return l;
        } else
                return NULL;
}

static void osd_object_init0(struct osd_object *obj)
{
        LASSERT(obj->oo_inode != NULL);
        obj->oo_dt.do_body_ops = &osd_body_ops;
        obj->oo_dt.do_lu.lo_header->loh_attr |=
                (LOHA_EXISTS | (obj->oo_inode->i_mode & S_IFMT));
}

static int osd_object_init(const struct lu_env *env, struct lu_object *l)
{
        struct osd_object *obj = osd_obj(l);
        int result;

        LASSERT(osd_invariant(obj));

        result = osd_fid_lookup(env, obj, lu_object_fid(l));
        if (result == 0) {
                if (obj->oo_inode != NULL)
                        osd_object_init0(obj);
        }
        LASSERT(osd_invariant(obj));
        return result;
}

static void osd_object_free(const struct lu_env *env, struct lu_object *l)
{
        struct osd_object *obj = osd_obj(l);

        LASSERT(osd_invariant(obj));

        dt_object_fini(&obj->oo_dt);
        OBD_FREE_PTR(obj);
}

static void osd_index_fini(struct osd_object *o)
{
        struct iam_container *bag;

        bag = &o->oo_container;
        if (o->oo_ipd != NULL) {
                LASSERT(bag->ic_descr->id_ops->id_ipd_free != NULL);
                bag->ic_descr->id_ops->id_ipd_free(&o->oo_container, o->oo_ipd);
        }
        if (o->oo_inode != NULL) {
                if (o->oo_container.ic_object == o->oo_inode)
                        iam_container_fini(&o->oo_container);
        }
}

static int osd_inode_unlinked(const struct inode *inode)
{
        /*
         * This is modified by huanghua@lusterfs.com:
         * i_nlink of an unlinked object is zero even if it is a dir.
         return inode->i_nlink == !!S_ISDIR(inode->i_mode);
         */
        return inode->i_nlink == 0;
}

enum {
        OSD_TXN_OI_DELETE_CREDITS = 20,
        OSD_TXN_RMENTRY_CREDITS = 20
};

static int osd_inode_remove(const struct lu_env *env,
                            struct osd_object *obj)
{
        const struct lu_fid    *fid = lu_object_fid(&obj->oo_dt.do_lu);
        struct osd_device      *osd = osd_obj2dev(obj);
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);
        struct txn_param       *prm = &oti->oti_txn;
        struct thandle         *th;
        struct dentry          *dentry;
        int result;

        prm->tp_credits = OSD_TXN_OI_DELETE_CREDITS + OSD_TXN_RMENTRY_CREDITS;
        th = osd_trans_start(env, &osd->od_dt_dev, prm);
        if (!IS_ERR(th)) {
                osd_oi_write_lock(&osd->od_oi);
                result = osd_oi_delete(oti, &osd->od_oi, fid, th);
                osd_oi_write_unlock(&osd->od_oi);

                /*
                 * The following is added by huanghua@clusterfs.com as
                 * a temporary hack, to remove the directory entry in
                 * "*OBJ_TEMP*". We will finally do not use this hack,
                 * and at that time we will remove these code under #if.
                 */
#if 1
                osd_fid_build_name(fid, oti->oti_name);
                oti->oti_str.name = oti->oti_name;
                oti->oti_str.len  = strlen(oti->oti_name);

                dentry = d_alloc(osd->od_obj_area, &oti->oti_str);
                if (dentry != NULL) {
                        struct inode *dir = osd->od_obj_area->d_inode;
                        obj->oo_inode->i_nlink = 1;
                        d_instantiate(dentry, obj->oo_inode);
                        result = dir->i_op->unlink(dir, dentry);
                        obj->oo_inode->i_nlink = 0;
                        mark_inode_dirty(obj->oo_inode);
                        dput(dentry);
                } else
#endif
                        iput(obj->oo_inode);
                osd_trans_stop(env, th);
        } else
                result = PTR_ERR(th);
        return result;
}

/*
 * Called just before object is freed. Releases all resources except for
 * object itself (that is released by osd_object_free()).
 */
static void osd_object_delete(const struct lu_env *env, struct lu_object *l)
{
        struct osd_object *obj   = osd_obj(l);
        struct inode      *inode = obj->oo_inode;

        LASSERT(osd_invariant(obj));

        /*
         * If object is unlinked remove fid->ino mapping from object index.
         *
         * File body will be deleted by iput().
         *
         * NOTE: currently objects are created in ->od_obj_area directory
         * ("*OBJ-TEMP*"), but name in that directory is _not_ counted in
         * inode ->i_nlink.
         */

        osd_index_fini(obj);
        if (inode != NULL) {
                int result;

                if (osd_inode_unlinked(inode)) {
                        result = osd_inode_remove(env, obj);
                        if (result != 0)
                                LU_OBJECT_DEBUG(D_ERROR, env, l,
                                                "Failed to cleanup: %d\n",
                                                result);
                } else
                        iput(inode);
                obj->oo_inode = NULL;
        }
}

static void osd_object_release(const struct lu_env *env,
                               struct lu_object *l)
{
        struct osd_object *o = osd_obj(l);

        LASSERT(!lu_object_is_dying(l->lo_header));
        if (o->oo_inode != NULL && osd_inode_unlinked(o->oo_inode))
                set_bit(LU_OBJECT_HEARD_BANSHEE, &l->lo_header->loh_flags);
}

static int osd_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *l)
{
        struct osd_object *o = osd_obj(l);
        struct iam_descr  *d;

        d = o->oo_container.ic_descr;
        return (*p)(env, cookie, LUSTRE_OSD_NAME"-object@%p(i:%p:%lu/%u)[%s]",
                    o, o->oo_inode,
                    o->oo_inode ? o->oo_inode->i_ino : 0UL,
                    o->oo_inode ? o->oo_inode->i_generation : 0,
                    d ? d->id_ops->id_name : "plain");
}

static int osd_statfs(const struct lu_env *env,
                      struct dt_device *d, struct kstatfs *sfs)
{
        struct osd_device *osd = osd_dt_dev(d);
        struct super_block *sb = osd_sb(osd);
        int result;

        ENTRY;

        memset(sfs, 0, sizeof *sfs);
        result = sb->s_op->statfs(sb, sfs);

        RETURN (result);
}

static void osd_conf_get(const struct lu_env *env,
                         const struct dt_device *dev,
                         struct dt_device_param *param)
{
        /*
         * XXX should be taken from not-yet-existing fs abstraction layer.
         */
        param->ddp_max_name_len  = LDISKFS_NAME_LEN;
        param->ddp_max_nlink     = LDISKFS_LINK_MAX;
        param->ddp_block_shift   = osd_sb(osd_dt_dev(dev))->s_blocksize_bits;
}

/*
 * Journal
 */

static int osd_param_is_sane(const struct osd_device *dev,
                             const struct txn_param *param)
{
        return param->tp_credits <= osd_journal(dev)->j_max_transaction_buffers;
}

static void osd_trans_commit_cb(struct journal_callback *jcb, int error)
{
        struct osd_thandle *oh = container_of0(jcb, struct osd_thandle, ot_jcb);
        struct thandle     *th = &oh->ot_super;
        struct dt_device   *dev = th->th_dev;

        LASSERT(dev != NULL);

        if (error) {
                CERROR("transaction @0x%p commit error: %d\n", th, error);
        } else {
                /* This dd_ctx_for_commit is only for commit usage.
                 * see "struct dt_device"
                 */
                dt_txn_hook_commit(&osd_dt_dev(dev)->od_env_for_commit, th);
        }

        lu_device_put(&dev->dd_lu_dev);
        th->th_dev = NULL;

        lu_context_exit(&th->th_ctx);
        lu_context_fini(&th->th_ctx);
        OBD_FREE_PTR(oh);
}

static struct thandle *osd_trans_start(const struct lu_env *env,
                                       struct dt_device *d,
                                       struct txn_param *p)
{
        struct osd_device      *dev = osd_dt_dev(d);
        handle_t               *jh;
        struct osd_thandle     *oh;
        struct thandle         *th;
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);
        int hook_res;

        ENTRY;

        hook_res = dt_txn_hook_start(env, d, p);
        if (hook_res != 0)
                RETURN(ERR_PTR(hook_res));

        if (osd_param_is_sane(dev, p)) {
                OBD_ALLOC_GFP(oh, sizeof *oh, GFP_NOFS);
                if (oh != NULL) {
                        /*
                         * XXX temporary stuff. Some abstraction layer should
                         * be used.
                         */

                        jh = journal_start(osd_journal(dev), p->tp_credits);
                        if (!IS_ERR(jh)) {
                                oh->ot_handle = jh;
                                th = &oh->ot_super;
                                th->th_dev = d;
                                lu_device_get(&d->dd_lu_dev);
                                /* add commit callback */
                                lu_context_init(&th->th_ctx, LCT_TX_HANDLE);
                                lu_context_enter(&th->th_ctx);
                                journal_callback_set(jh, osd_trans_commit_cb,
                                                     (struct journal_callback *)&oh->ot_jcb);
                                LASSERT(oti->oti_txns == 0);
                                LASSERT(oti->oti_r_locks == 0);
                                LASSERT(oti->oti_w_locks == 0);
                                oti->oti_txns++;
                        } else {
                                OBD_FREE_PTR(oh);
                                th = (void *)jh;
                        }
                } else
                        th = ERR_PTR(-ENOMEM);
        } else {
                CERROR("Invalid transaction parameters\n");
                th = ERR_PTR(-EINVAL);
        }

        RETURN(th);
}

static void osd_trans_stop(const struct lu_env *env, struct thandle *th)
{
        int result;
        struct osd_thandle     *oh;
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);

        ENTRY;

        oh = container_of0(th, struct osd_thandle, ot_super);
        if (oh->ot_handle != NULL) {
                handle_t *hdl = oh->ot_handle;
                /*
                 * XXX temporary stuff. Some abstraction layer should be used.
                 */
                result = dt_txn_hook_stop(env, th);
                if (result != 0)
                        CERROR("Failure in transaction hook: %d\n", result);

                /**/
                oh->ot_handle = NULL;
                result = journal_stop(hdl);
                if (result != 0)
                        CERROR("Failure to stop transaction: %d\n", result);

                LASSERT(oti->oti_txns == 1);
                LASSERT(oti->oti_r_locks == 0);
                LASSERT(oti->oti_w_locks == 0);
                oti->oti_txns--;
        }
        EXIT;
}

static int osd_sync(const struct lu_env *env, struct dt_device *d)
{
        CDEBUG(D_HA, "syncing OSD %s\n", LUSTRE_OSD_NAME);
        return ldiskfs_force_commit(osd_sb(osd_dt_dev(d)));
}

static void osd_ro(const struct lu_env *env, struct dt_device *d)
{
        ENTRY;

        CERROR("*** setting device %s read-only ***\n", LUSTRE_OSD_NAME);

        lvfs_set_rdonly(lvfs_sbdev(osd_sb(osd_dt_dev(d))));
        EXIT;
}

static int osd_init_capa_ctxt(const struct lu_env *env, struct dt_device *d,
                              int mode, unsigned long timeout, __u32 alg,
                              struct lustre_capa_key *keys)
{
        struct osd_device *dev = osd_dt_dev(d);
        ENTRY;

        dev->od_fl_capa = mode;
        dev->od_capa_timeout = timeout;
        dev->od_capa_alg = alg;
        dev->od_capa_keys = keys;
        RETURN(0);
}

/* Note: we did not count into QUOTA here, If we mount with --data_journal
 * we may need more*/
enum {
        /* Insert/Delete IAM
         * EXT3_INDEX_EXTRA_TRANS_BLOCKS(8) + EXT3_SINGLEDATA_TRANS_BLOCKS 8
         * XXX Note: maybe iam need more,since iam have more level than Ext3 
         * htree
         */
        INSERT_IAM_CREDITS  = 16,

        /* Create a object
         * Same as create object in Ext3 filesystem, but did not count QUOTA i
         * EXT3_DATA_TRANS_BLOCKS(12) + INDEX_EXTRA_BLOCKS(8) +
         * 3(inode bits,groups, GDT)*/
         CREATE_OBJECT_CREDITS = 23,

        /* XATTR_SET
         * SAME AS XATTR of EXT3 EXT3_DATA_TRANS_BLOCKS
         * XXX Note: in original MDS implmentation EXT3_INDEX_EXTRA_TRANS_BLOCKS are
         * also counted in. Do not know why? */
         XATTR_SET_CREDITS = 12,

        /* A log rec need EXT3_INDEX_EXTRA_TRANS_BLOCKS(8) +
         *                EXT3_SINGLEDATA_TRANS_BLOCKS(8))
         */
        LOG_REC_CREDIT = 16,

        /* Attr set credits 3 inode, group, GDT */
        ATTR_SET_CREDITS = 3
};

static int osd_credit_get(const struct lu_env *env, struct dt_device *d,
                          int op)
{
        switch(op) {
                case INSERT_IAM:
                        return INSERT_IAM_CREDITS;
                case CREATE_OBJECT:
                        return CREATE_OBJECT_CREDITS;
                case XATTR_SET:
                        return XATTR_SET_CREDITS;
                case LOG_REC:
                        return LOG_REC_CREDIT;
                case ATTR_SET:
                        return ATTR_SET_CREDITS;
                default:
                        CERROR("Not recorgonized op %d", op);
                        LBUG();
                        return -EINVAL; 
        }
        return (-EINVAL);
}
                
static struct dt_device_operations osd_dt_ops = {
        .dt_root_get       = osd_root_get,
        .dt_statfs         = osd_statfs,
        .dt_trans_start    = osd_trans_start,
        .dt_trans_stop     = osd_trans_stop,
        .dt_conf_get       = osd_conf_get,
        .dt_sync           = osd_sync,
        .dt_ro             = osd_ro,
        .dt_credit_get     = osd_credit_get,
        .dt_init_capa_ctxt = osd_init_capa_ctxt,
};

static void osd_object_read_lock(const struct lu_env *env,
                                 struct dt_object *dt)
{
        struct osd_object      *obj = osd_dt_obj(dt);
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);

        LASSERT(osd_invariant(obj));

        LASSERT(obj->oo_owner != env);
        down_read(&obj->oo_sem);
        LASSERT(obj->oo_owner == NULL);
        oti->oti_r_locks++;
}

static void osd_object_write_lock(const struct lu_env *env,
                                  struct dt_object *dt)
{
        struct osd_object      *obj = osd_dt_obj(dt);
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);

        LASSERT(osd_invariant(obj));

        LASSERT(obj->oo_owner != env);
        down_write(&obj->oo_sem);
        LASSERT(obj->oo_owner == NULL);
        obj->oo_owner = env;
        oti->oti_w_locks++;
}

static void osd_object_read_unlock(const struct lu_env *env,
                                   struct dt_object *dt)
{
        struct osd_object      *obj = osd_dt_obj(dt);
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);

        LASSERT(osd_invariant(obj));
        LASSERT(oti->oti_r_locks > 0);
        oti->oti_r_locks--;
        up_read(&obj->oo_sem);
}

static void osd_object_write_unlock(const struct lu_env *env,
                                    struct dt_object *dt)
{
        struct osd_object      *obj = osd_dt_obj(dt);
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);

        LASSERT(osd_invariant(obj));
        LASSERT(obj->oo_owner == env);
        LASSERT(oti->oti_w_locks > 0);
        oti->oti_w_locks--;
        obj->oo_owner = NULL;
        up_write(&obj->oo_sem);
}

static int capa_is_sane(const struct lu_env *env,
                        struct lustre_capa *capa,
                        struct lustre_capa_key *keys)
{
        struct osd_thread_info *oti;
        struct obd_capa *oc;
        int i, rc = 1;
        ENTRY;

        oti = lu_context_key_get(&env->le_ctx, &osd_key);

        oc = capa_lookup(capa);
        if (oc) {
                if (memcmp(&oc->c_capa, capa, sizeof(*capa))) {
                        DEBUG_CAPA(D_ERROR, capa, "HMAC mismatch");
                        rc = -EACCES;
                } else if (capa_is_expired(oc)) {
                        DEBUG_CAPA(D_ERROR, capa, "expired");
                        rc = -ESTALE;
                }
                capa_put(oc);
                RETURN(rc);
        }

        spin_lock(&capa_lock);
        for (i = 0; i < 2; i++) {
                if (keys[i].lk_keyid == capa->lc_keyid) {
                        oti->oti_capa_key = keys[i];
                        break;
                }
        }
        spin_unlock(&capa_lock);

        if (i == 2) {
                DEBUG_CAPA(D_ERROR, capa, "no matched capa key");
                RETURN(-ESTALE);
        }

        rc = capa_hmac(oti->oti_capa_hmac, capa, oti->oti_capa_key.lk_key);
        if (rc)
                RETURN(rc);
        if (memcmp(oti->oti_capa_hmac, capa->lc_hmac, sizeof(capa->lc_hmac))) {
                DEBUG_CAPA(D_ERROR, capa, "HMAC mismatch");
                RETURN(-EACCES);
        }

        oc = capa_add(capa);
        capa_put(oc);

        RETURN(1);
}

static int osd_object_auth(const struct lu_env *env, struct dt_object *dt,
                           struct lustre_capa *capa, __u64 opc)
{
        const struct lu_fid *fid = lu_object_fid(&dt->do_lu);
        struct osd_device *dev = osd_dev(dt->do_lu.lo_dev);

        if (!dev->od_fl_capa)
                return 0;

        if (capa == BYPASS_CAPA)
                return 0;

        if (!capa) {
                CERROR("no capability is provided for fid "DFID"\n", PFID(fid));
                return -EACCES;
        }

        if (!lu_fid_eq(fid, &capa->lc_fid)) {
                DEBUG_CAPA(D_ERROR, capa, "fid "DFID" mismatch with",
                           PFID(fid));
                return -EACCES;
        }

        if (!capa_opc_supported(capa, opc)) {
                DEBUG_CAPA(D_ERROR, capa, "opc "LPX64" not supported by", opc);
                return -EACCES;
        }

        if (!capa_is_sane(env, capa, dev->od_capa_keys)) {
                DEBUG_CAPA(D_ERROR, capa, "insane");
                return -EACCES;
        }

        return 0;
}

static int osd_attr_get(const struct lu_env *env,
                        struct dt_object *dt,
                        struct lu_attr *attr,
                        struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);

        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));
        LASSERT(osd_read_locked(env, obj) || osd_write_locked(env, obj));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_READ))
                return -EACCES;

        return osd_inode_getattr(env, obj->oo_inode, attr);
}

static int osd_attr_set(const struct lu_env *env,
                        struct dt_object *dt,
                        const struct lu_attr *attr,
                        struct thandle *handle,
                        struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);
        LASSERT(handle != NULL);
        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));
        LASSERT(osd_write_locked(env, obj));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_WRITE))
                return -EACCES;

        return osd_inode_setattr(env, obj->oo_inode, attr);
}

static struct timespec *osd_inode_time(const struct lu_env *env,
                                       struct inode *inode, __u64 seconds)
{
        struct osd_thread_info *oti = lu_context_key_get(&env->le_ctx, &osd_key);
        struct timespec        *t   = &oti->oti_time;

        t->tv_sec  = seconds;
        t->tv_nsec = 0;
        *t = timespec_trunc(*t, get_sb_time_gran(inode->i_sb));
        return t;
}

static int osd_inode_setattr(const struct lu_env *env,
                             struct inode *inode, const struct lu_attr *attr)
{
        __u64 bits;
        int rc = 0;

        bits = attr->la_valid;

        LASSERT(!(bits & LA_TYPE)); /* Huh? You want too much. */

        if (bits & LA_ATIME)
                inode->i_atime  = *osd_inode_time(env, inode, attr->la_atime);
        if (bits & LA_CTIME)
                inode->i_ctime  = *osd_inode_time(env, inode, attr->la_ctime);
        if (bits & LA_MTIME)
                inode->i_mtime  = *osd_inode_time(env, inode, attr->la_mtime);
        if (bits & LA_SIZE)
                LDISKFS_I(inode)->i_disksize = inode->i_size = attr->la_size;
        if (bits & LA_BLOCKS)
                inode->i_blocks = attr->la_blocks;
        if (bits & LA_MODE)
                inode->i_mode   = (inode->i_mode & S_IFMT) |
                        (attr->la_mode & ~S_IFMT);
        if (bits & LA_UID)
                inode->i_uid    = attr->la_uid;
        if (bits & LA_GID)
                inode->i_gid    = attr->la_gid;
        if (bits & LA_NLINK)
                inode->i_nlink  = attr->la_nlink;
        if (bits & LA_RDEV)
                inode->i_rdev   = attr->la_rdev;
        if (bits & LA_BLKSIZE)
                inode->i_blksize = attr->la_blksize;

        if (bits & LA_FLAGS) {
                struct ldiskfs_inode_info *li = LDISKFS_I(inode);

                li->i_flags = (li->i_flags & ~LDISKFS_FL_USER_MODIFIABLE) |
                        (attr->la_flags & LDISKFS_FL_USER_MODIFIABLE);
        }
        mark_inode_dirty(inode);
        return rc;
}

/*
 * Object creation.
 *
 * XXX temporary solution.
 */

static int osd_create_pre(struct osd_thread_info *info, struct osd_object *obj,
                          struct lu_attr *attr, struct thandle *th)
{
        return 0;
}

static int osd_create_post(struct osd_thread_info *info, struct osd_object *obj,
                           struct lu_attr *attr, struct thandle *th)
{
        LASSERT(obj->oo_inode != NULL);

        osd_object_init0(obj);
        return 0;
}

static int osd_mkfile(struct osd_thread_info *info, struct osd_object *obj,
                      umode_t mode, struct thandle *th)
{
        int result;
        struct osd_device *osd = osd_obj2dev(obj);
        struct inode      *dir;

        /*
         * XXX temporary solution.
         */
        struct dentry     *dentry;

        LASSERT(osd_invariant(obj));
        LASSERT(obj->oo_inode == NULL);
        LASSERT(osd->od_obj_area != NULL);

        dir = osd->od_obj_area->d_inode;
        LASSERT(dir->i_op != NULL && dir->i_op->create != NULL);

        osd_fid_build_name(lu_object_fid(&obj->oo_dt.do_lu), info->oti_name);
        info->oti_str.name = info->oti_name;
        info->oti_str.len  = strlen(info->oti_name);

        dentry = d_alloc(osd->od_obj_area, &info->oti_str);
        if (dentry != NULL) {
               result = dir->i_op->create(dir, dentry, mode, NULL);
               if (result == 0) {
                        LASSERT(dentry->d_inode != NULL);
                        obj->oo_inode = dentry->d_inode;
                        igrab(obj->oo_inode);
                }
                dput(dentry);
        } else
                result = -ENOMEM;
        LASSERT(osd_invariant(obj));
        return result;
}


extern int iam_lvar_create(struct inode *obj, int keysize, int ptrsize,
                           int recsize, handle_t *handle);

enum {
        OSD_NAME_LEN = 255
};

static int osd_mkdir(struct osd_thread_info *info, struct osd_object *obj,
                     struct lu_attr *attr, struct thandle *th)
{
        int result;
        struct osd_thandle *oth;

        oth = container_of0(th, struct osd_thandle, ot_super);
        LASSERT(S_ISDIR(attr->la_mode));
        result = osd_mkfile(info, obj, (attr->la_mode &
                            (S_IFMT | S_IRWXUGO | S_ISVTX)), th);
        if (result == 0) {
                LASSERT(obj->oo_inode != NULL);
                /*
                 * XXX uh-oh... call low-level iam function directly.
                 */
                result = iam_lvar_create(obj->oo_inode, OSD_NAME_LEN, 4,
                                         sizeof (struct lu_fid),
                                         oth->ot_handle);
        }
        return result;
}

static int osd_mkreg(struct osd_thread_info *info, struct osd_object *obj,
                     struct lu_attr *attr, struct thandle *th)
{
        LASSERT(S_ISREG(attr->la_mode));
        return osd_mkfile(info, obj, (attr->la_mode &
                               (S_IFMT | S_IRWXUGO | S_ISVTX)), th);
}

static int osd_mksym(struct osd_thread_info *info, struct osd_object *obj,
                     struct lu_attr *attr, struct thandle *th)
{
        LASSERT(S_ISLNK(attr->la_mode));
        return osd_mkfile(info, obj, (attr->la_mode &
                              (S_IFMT | S_IRWXUGO | S_ISVTX)), th);
}

static int osd_mknod(struct osd_thread_info *info, struct osd_object *obj,
                     struct lu_attr *attr, struct thandle *th)
{
        int result;
        struct osd_device *osd = osd_obj2dev(obj);
        struct inode      *dir;
        umode_t mode = attr->la_mode & (S_IFMT | S_IRWXUGO | S_ISVTX);

        /*
         * XXX temporary solution.
         */
        struct dentry     *dentry;

        LASSERT(osd_invariant(obj));
        LASSERT(obj->oo_inode == NULL);
        LASSERT(osd->od_obj_area != NULL);

        dir = osd->od_obj_area->d_inode;
        LASSERT(dir->i_op != NULL && dir->i_op->create != NULL);

        osd_fid_build_name(lu_object_fid(&obj->oo_dt.do_lu), info->oti_name);
        info->oti_str.name = info->oti_name;
        info->oti_str.len  = strlen(info->oti_name);

        dentry = d_alloc(osd->od_obj_area, &info->oti_str);
        if (dentry != NULL) {
                result = dir->i_op->mknod(dir, dentry, mode, attr->la_rdev);
                if (result == 0) {
                        LASSERT(dentry->d_inode != NULL);
                        obj->oo_inode = dentry->d_inode;
                        igrab(obj->oo_inode);
                }
                dput(dentry);
        } else
                result = -ENOMEM;
        LASSERT(osd_invariant(obj));
        return result;
}

typedef int (*osd_obj_type_f)(struct osd_thread_info *, struct osd_object *,
                              struct lu_attr *, struct thandle *);

static osd_obj_type_f osd_create_type_f(__u32 mode)
{
        osd_obj_type_f result;

        switch (mode) {
        case S_IFDIR:
                result = osd_mkdir;
                break;
        case S_IFREG:
                result = osd_mkreg;
                break;
        case S_IFLNK:
                result = osd_mksym;
                break;
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                result = osd_mknod;
                break;
        default:
                LBUG();
                break;
        }
        return result;
}

static int osd_object_create(const struct lu_env *env, struct dt_object *dt,
                             struct lu_attr *attr, struct thandle *th)
{
        const struct lu_fid    *fid  = lu_object_fid(&dt->do_lu);
        struct osd_object      *obj  = osd_dt_obj(dt);
        struct osd_device      *osd  = osd_obj2dev(obj);
        struct osd_thread_info *info = lu_context_key_get(&env->le_ctx, &osd_key);
        int result;

        ENTRY;

        LASSERT(osd_invariant(obj));
        LASSERT(!dt_object_exists(dt));
        LASSERT(osd_write_locked(env, obj));
        LASSERT(th != NULL);

        /*
         * XXX missing: permission checks.
         */

        /*
         * XXX missing: sanity checks (valid ->la_mode, etc.)
         */

        /*
         * XXX missing: Quote handling.
         */

        result = osd_create_pre(info, obj, attr, th);
        if (result == 0) {
                result = osd_create_type_f(attr->la_mode & S_IFMT)(info, obj,
                                                                   attr, th);
                if (result == 0)
                        result = osd_create_post(info, obj, attr, th);
        }
        if (result == 0) {
                struct osd_inode_id *id = &info->oti_id;

                LASSERT(obj->oo_inode != NULL);

                id->oii_ino = obj->oo_inode->i_ino;
                id->oii_gen = obj->oo_inode->i_generation;

                osd_oi_write_lock(&osd->od_oi);
                result = osd_oi_insert(info, &osd->od_oi, fid, id, th);
                osd_oi_write_unlock(&osd->od_oi);
        }

        LASSERT(ergo(result == 0, dt_object_exists(dt)));
        LASSERT(osd_invariant(obj));
        return result;
}

static void osd_object_ref_add(const struct lu_env *env,
                               struct dt_object *dt,
                               struct thandle *th)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct inode *inode = obj->oo_inode;

        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));
        LASSERT(osd_write_locked(env, obj));
        LASSERT(th != NULL);

        if (inode->i_nlink < LDISKFS_LINK_MAX) {
                inode->i_nlink ++;
                mark_inode_dirty(inode);
        } else
                LU_OBJECT_DEBUG(D_ERROR, env, &dt->do_lu,
                                "Overflowed nlink\n");
        LASSERT(osd_invariant(obj));
}

static void osd_object_ref_del(const struct lu_env *env,
                               struct dt_object *dt,
                               struct thandle *th)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct inode *inode = obj->oo_inode;

        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));
        LASSERT(osd_write_locked(env, obj));
        LASSERT(th != NULL);

        if (inode->i_nlink > 0) {
                inode->i_nlink --;
                mark_inode_dirty(inode);
        } else
                LU_OBJECT_DEBUG(D_ERROR, env, &dt->do_lu,
                                "Underflowed nlink\n");
        LASSERT(osd_invariant(obj));
}

static int osd_xattr_get(const struct lu_env *env,
                         struct dt_object *dt,
                         struct lu_buf *buf,
                         const char *name,
                         struct lustre_capa *capa)
{
        struct osd_object      *obj    = osd_dt_obj(dt);
        struct inode           *inode  = obj->oo_inode;
        struct osd_thread_info *info   = lu_context_key_get(&env->le_ctx, &osd_key);
        struct dentry          *dentry = &info->oti_dentry;

        LASSERT(dt_object_exists(dt));
        LASSERT(inode->i_op != NULL && inode->i_op->getxattr != NULL);
        LASSERT(osd_read_locked(env, obj) || osd_write_locked(env, obj));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_READ))
                return -EACCES;

        dentry->d_inode = inode;
        return inode->i_op->getxattr(dentry, name, buf->lb_buf, buf->lb_len);
}

static int osd_xattr_set(const struct lu_env *env, struct dt_object *dt,
                         const struct lu_buf *buf, const char *name, int fl,
                         struct thandle *handle, struct lustre_capa *capa)
{
        int fs_flags;

        struct osd_object      *obj    = osd_dt_obj(dt);
        struct inode           *inode  = obj->oo_inode;
        struct osd_thread_info *info   = lu_context_key_get(&env->le_ctx, &osd_key);
        struct dentry          *dentry = &info->oti_dentry;

        LASSERT(dt_object_exists(dt));
        LASSERT(inode->i_op != NULL && inode->i_op->setxattr != NULL);
        LASSERT(osd_write_locked(env, obj));
        LASSERT(handle != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_WRITE))
                return -EACCES;

        dentry->d_inode = inode;

        fs_flags = 0;
        if (fl & LU_XATTR_REPLACE)
                fs_flags |= XATTR_REPLACE;

        if (fl & LU_XATTR_CREATE)
                fs_flags |= XATTR_CREATE;

        return inode->i_op->setxattr(dentry, name,
                                     buf->lb_buf, buf->lb_len, fs_flags);
}

static int osd_xattr_list(const struct lu_env *env,
                          struct dt_object *dt,
                          struct lu_buf *buf,
                          struct lustre_capa *capa)
{
        struct osd_object      *obj    = osd_dt_obj(dt);
        struct inode           *inode  = obj->oo_inode;
        struct osd_thread_info *info   = lu_context_key_get(&env->le_ctx, &osd_key);
        struct dentry          *dentry = &info->oti_dentry;

        LASSERT(dt_object_exists(dt));
        LASSERT(inode->i_op != NULL && inode->i_op->listxattr != NULL);
        LASSERT(osd_read_locked(env, obj) || osd_write_locked(env, obj));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_READ))
                return -EACCES;

        dentry->d_inode = inode;
        return inode->i_op->listxattr(dentry, buf->lb_buf, buf->lb_len);
}

static int osd_xattr_del(const struct lu_env *env,
                         struct dt_object *dt,
                         const char *name,
                         struct thandle *handle,
                         struct lustre_capa *capa)
{
        struct osd_object      *obj    = osd_dt_obj(dt);
        struct inode           *inode  = obj->oo_inode;
        struct osd_thread_info *info   = lu_context_key_get(&env->le_ctx, &osd_key);
        struct dentry          *dentry = &info->oti_dentry;

        LASSERT(dt_object_exists(dt));
        LASSERT(inode->i_op != NULL && inode->i_op->removexattr != NULL);
        LASSERT(osd_write_locked(env, obj));
        LASSERT(handle != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_WRITE))
                return -EACCES;

        dentry->d_inode = inode;
        return inode->i_op->removexattr(dentry, name);
}

static int osd_dir_page_build(const struct lu_env *env, int first,
                              void *area, int nob,
                              struct dt_it_ops  *iops, struct dt_it *it,
                              __u32 *start, __u32 *end, struct lu_dirent **last)
{
        int result;
        struct osd_thread_info *info = lu_context_key_get(&env->le_ctx,
                                                          &osd_key);
        struct lu_fid          *fid  = &info->oti_fid;
        struct lu_dirent       *ent;

        if (first) {
                area += sizeof (struct lu_dirpage);
                nob  -= sizeof (struct lu_dirpage);
        }

        LASSERT(nob > sizeof *ent);

        ent  = area;
        result = 0;
        do {
                char  *name;
                int    len;
                int    recsize;
                __u32  hash;

                name = (char *)iops->key(env, it);
                len  = iops->key_size(env, it);

                *fid  = *(struct lu_fid *)iops->rec(env, it);
                fid_cpu_to_le(fid, fid);

                recsize = (sizeof *ent + len + 3) & ~3;
                hash = iops->store(env, it);
                *end = hash;
                CDEBUG(D_INODE, "%p %p %d "DFID": %#8.8x (%d)\"%*.*s\"\n",
                       area, ent, nob, PFID(fid), hash, len, len, len, name);
                if (nob >= recsize) {
                        ent->lde_fid = *fid;
                        ent->lde_hash = hash;
                        ent->lde_namelen = cpu_to_le16(len);
                        ent->lde_reclen  = cpu_to_le16(recsize);
                        memcpy(ent->lde_name, name, len);
                        if (first && ent == area)
                                *start = hash;
                        *last = ent;
                        ent = (void *)ent + recsize;
                        nob -= recsize;
                        result = iops->next(env, it);
                } else {
                        /*
                         * record doesn't fit into page, enlarge previous one.
                         */
                        LASSERT(*last != NULL);
                        (*last)->lde_reclen =
                                cpu_to_le16(le16_to_cpu((*last)->lde_reclen) +
                                            nob);
                        break;
                }
        } while (result == 0);
        return result;
}

static int osd_readpage(const struct lu_env *env,
                        struct dt_object *dt,
                        const struct lu_rdpg *rdpg,
                        struct lustre_capa *capa)
{
        struct dt_it      *it;
        struct osd_object *obj = osd_dt_obj(dt);
        struct dt_it_ops  *iops;
        int i, rc, rc1 = 0, nob;

        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));
        LASSERT(osd_has_index(obj));
        LASSERT(osd_read_locked(env, obj) || osd_write_locked(env, obj));

        LASSERT(rdpg->rp_pages != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_BODY_READ))
                return -EACCES;

        if (rdpg->rp_count <= 0)
                return -EFAULT;

        if (rdpg->rp_count & (obj->oo_inode->i_blksize - 1)) {
                CERROR("size %u is not multiple of blocksize %lu\n",
                       rdpg->rp_count, obj->oo_inode->i_blksize);
                return -EFAULT;
        }

        /*
         * iterating through directory and fill pages from @rdpg
         */
        iops = &dt->do_index_ops->dio_it;
        it = iops->init(env, dt, 0);
        if (it == NULL)
                return -ENOMEM;
        /*
         * XXX position iterator at rdpg->rp_hash
         */
        rc = iops->load(env, it, rdpg->rp_hash);

        /* When spliting, it need read entries from some offset by computing
         * not by some entries offset like readdir, so it might return 0 here.
         */
        if (rc == 0)
                rc1 = -ERANGE;

        if (rc >= 0) {
                struct page      *pg; /* no, Richard, it _is_ initialized */
                struct lu_dirent *last;
                __u32             hash_start;
                __u32             hash_end;

                for (i = 0, rc = 0, nob = rdpg->rp_count;
                     rc == 0 && nob > 0; i++, nob -= CFS_PAGE_SIZE) {
                        LASSERT(i < rdpg->rp_npages);
                        pg = rdpg->rp_pages[i];
                        rc = osd_dir_page_build(env, !i, kmap(pg),
                                                min_t(int, nob, CFS_PAGE_SIZE),
                                                iops, it,
                                                &hash_start, &hash_end, &last);
                        if (rc != 0 || i == rdpg->rp_npages - 1)
                                last->lde_reclen = 0;
                        kunmap(pg);
                }
                iops->put(env, it);
                if (rc > 0) {
                        /*
                         * end of directory.
                         */
                        hash_end = ~0ul;
                        rc = 0;
                }
                if (rc == 0) {
                        struct lu_dirpage *dp;

                        dp = kmap(rdpg->rp_pages[0]);
                        dp->ldp_hash_start = hash_start;
                        dp->ldp_hash_end   = hash_end;
                        kunmap(rdpg->rp_pages[0]);
                }
        }
        iops->put(env, it);
        iops->fini(env, it);

        return rc ? rc : rc1;
}

static struct obd_capa *osd_capa_get(const struct lu_env *env,
                                     struct dt_object *dt,
                                     __u64 opc)
{
        struct osd_thread_info *info = lu_context_key_get(&env->le_ctx,
                                                          &osd_key);
        const struct lu_fid *fid = lu_object_fid(&dt->do_lu);
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_device *dev = osd_obj2dev(obj);
        struct lustre_capa_key *key = &info->oti_capa_key;
        struct lustre_capa *capa = &info->oti_capa;
        struct obd_capa *oc;
        int rc;
        ENTRY;

        if (!dev->od_fl_capa)
                RETURN(NULL);

        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));

        capa->lc_fid = *fid;
        capa->lc_opc = opc;
        capa->lc_flags |= dev->od_capa_alg << 24;
        if (dev->od_capa_timeout < CAPA_TIMEOUT)
                capa->lc_flags |= CAPA_FL_SHORT_EXPIRY;

        oc = capa_lookup(capa);
        if (oc) {
                LASSERT(!capa_is_expired(oc));
                RETURN(oc);
        }

        spin_lock(&capa_lock);
        *key = dev->od_capa_keys[1];
        spin_unlock(&capa_lock);

        capa->lc_keyid = key->lk_keyid;
        capa->lc_expiry = CURRENT_SECONDS + dev->od_capa_timeout;

        rc = capa_hmac(capa->lc_hmac, capa, key->lk_key);
        if (rc) {
                DEBUG_CAPA(D_ERROR, capa, "HMAC failed: %d for", rc);
                RETURN(NULL);
        }

        oc = capa_add(capa);
        RETURN(oc);
}

static struct dt_object_operations osd_obj_ops = {
        .do_read_lock    = osd_object_read_lock,
        .do_write_lock   = osd_object_write_lock,
        .do_read_unlock  = osd_object_read_unlock,
        .do_write_unlock = osd_object_write_unlock,
        .do_attr_get     = osd_attr_get,
        .do_attr_set     = osd_attr_set,
        .do_create       = osd_object_create,
        .do_index_try    = osd_index_try,
        .do_ref_add      = osd_object_ref_add,
        .do_ref_del      = osd_object_ref_del,
        .do_xattr_get    = osd_xattr_get,
        .do_xattr_set    = osd_xattr_set,
        .do_xattr_del    = osd_xattr_del,
        .do_xattr_list   = osd_xattr_list,
        .do_readpage     = osd_readpage,
        .do_capa_get     = osd_capa_get,
};

/*
 * Body operations.
 */

static ssize_t osd_read(const struct lu_env *env, struct dt_object *dt,
                        struct lu_buf *buf, loff_t *pos,
                        struct lustre_capa *capa)
{
        struct inode *inode = osd_dt_obj(dt)->oo_inode;
        struct file  *file;
        mm_segment_t  seg;
        ssize_t       result;

        if (osd_object_auth(env, dt, capa, CAPA_OPC_BODY_READ))
                RETURN(-EACCES);

        file = osd_rw_init(env, inode, &seg);
        /*
         * We'd like to use vfs_read() here, but it messes with
         * dnotify_parent() and locks.
         */
        if (file->f_op->read)
                result = file->f_op->read(file, buf->lb_buf, buf->lb_len, pos);
        else {
                /* TODO: how to serve symlink readlink()? */
                CERROR("read not implemented currently\n");
                result = -ENOSYS;
        }
        osd_rw_fini(&seg);
        return result;
}

static ssize_t osd_write(const struct lu_env *env, struct dt_object *dt,
                         const struct lu_buf *buf, loff_t *pos,
                         struct thandle *handle, struct lustre_capa *capa)
{
        struct inode *inode = osd_dt_obj(dt)->oo_inode;
        struct file  *file;
        mm_segment_t  seg;
        ssize_t       result;

        LASSERT(handle != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_BODY_WRITE))
                RETURN(-EACCES);

        file = osd_rw_init(env, inode, &seg);
        if (file->f_op->write)
                result = file->f_op->write(file, buf->lb_buf, buf->lb_len, pos);
        else {
                CERROR("write not implemented currently\n");
                result = -ENOSYS;
        }
        osd_rw_fini(&seg);
        return result;
}

static struct dt_body_operations osd_body_ops = {
        .dbo_read  = osd_read,
        .dbo_write = osd_write
};

/*
 * Index operations.
 */

static int osd_index_probe(const struct lu_env *env, struct osd_object *o,
                           const struct dt_index_features *feat)
{
        struct iam_descr *descr;

        descr = o->oo_container.ic_descr;
        if (feat == &dt_directory_features)
                return osd_sb(osd_obj2dev(o))->s_root->d_inode == o->oo_inode ||
                        descr == &iam_htree_compat_param ||
                        (descr->id_rec_size == sizeof(struct lu_fid) &&
                         1 /*
                            * XXX check that index looks like directory.
                            */
                                );

        else
                return
                        feat->dif_keysize_min <= descr->id_key_size &&
                        descr->id_key_size <= feat->dif_keysize_max &&
                        feat->dif_recsize_min <= descr->id_rec_size &&
                        descr->id_rec_size <= feat->dif_recsize_max &&
                        !(feat->dif_flags & (DT_IND_VARKEY |
                                             DT_IND_VARREC | DT_IND_NONUNQ)) &&
                        ergo(feat->dif_flags & DT_IND_UPDATE,
                             1 /* XXX check that object (and file system) is
                                * writable */);
}

static int osd_index_try(const struct lu_env *env, struct dt_object *dt,
                         const struct dt_index_features *feat)
{
        int result;
        struct osd_object *obj = osd_dt_obj(dt);

        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));

        if (osd_sb(osd_obj2dev(obj))->s_root->d_inode == obj->oo_inode) {
                dt->do_index_ops = &osd_index_compat_ops;
                result = 0;
        } else if (!osd_has_index(obj)) {
                struct iam_container *bag;

                bag = &obj->oo_container;
                result = iam_container_init(bag, &obj->oo_descr, obj->oo_inode);
                if (result == 0) {
                        result = iam_container_setup(bag);
                        if (result == 0) {
                                struct iam_path_descr *ipd;

                                LASSERT(obj->oo_ipd == NULL);
                                ipd = bag->ic_descr->id_ops->id_ipd_alloc(bag);
                                if (ipd != NULL) {
                                        obj->oo_ipd = ipd;
                                        dt->do_index_ops = &osd_index_ops;
                                } else
                                        result = -ENOMEM;
                        }
                }
        } else
                result = 0;

        if (result == 0) {
                if (osd_index_probe(env, obj, feat))
                        result = 0;
                else
                        result = -ENOTDIR;
        }
        LASSERT(osd_invariant(obj));

        return result;
}

static int osd_index_delete(const struct lu_env *env, struct dt_object *dt,
                            const struct dt_key *key, struct thandle *handle,
                            struct lustre_capa *capa)
{
        struct osd_object     *obj = osd_dt_obj(dt);
        struct osd_thandle    *oh;
        int rc;

        ENTRY;

        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));
        LASSERT(obj->oo_container.ic_object == obj->oo_inode);
        LASSERT(obj->oo_ipd != NULL);
        LASSERT(handle != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_DELETE))
                RETURN(-EACCES);

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);

        rc = iam_delete(oh->ot_handle, &obj->oo_container,
                        (const struct iam_key *)key, obj->oo_ipd);

        LASSERT(osd_invariant(obj));
        RETURN(rc);
}

static int osd_index_lookup(const struct lu_env *env, struct dt_object *dt,
                            struct dt_rec *rec, const struct dt_key *key,
                            struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);
        int rc;

        ENTRY;

        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));
        LASSERT(obj->oo_container.ic_object == obj->oo_inode);
        LASSERT(obj->oo_ipd != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_LOOKUP))
                return -EACCES;

        rc = iam_lookup(&obj->oo_container, (const struct iam_key *)key,
                        (struct iam_rec *)rec, obj->oo_ipd);

        LASSERT(osd_invariant(obj));

        RETURN(rc);
}

static int osd_index_insert(const struct lu_env *env, struct dt_object *dt,
                            const struct dt_rec *rec, const struct dt_key *key,
                            struct thandle *th, struct lustre_capa *capa)
{
        struct osd_object     *obj = osd_dt_obj(dt);

        struct osd_thandle    *oh;
        int rc;

        ENTRY;

        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));
        LASSERT(obj->oo_container.ic_object == obj->oo_inode);
        LASSERT(obj->oo_ipd != NULL);
        LASSERT(th != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_INSERT))
                return -EACCES;

        oh = container_of0(th, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);
        rc = iam_insert(oh->ot_handle, &obj->oo_container,
                        (const struct iam_key *)key,
                        (struct iam_rec *)rec, obj->oo_ipd);

        LASSERT(osd_invariant(obj));
        RETURN(rc);
}

/*
 * Iterator operations.
 */
struct osd_it {
        struct osd_object  *oi_obj;
        struct iam_iterator oi_it;
};

static struct dt_it *osd_it_init(const struct lu_env *env,
                                 struct dt_object *dt, int writable)
{
        struct osd_it     *it;
        struct osd_object *obj = osd_dt_obj(dt);
        struct lu_object  *lo  = &dt->do_lu;
        __u32              flags;

        LASSERT(lu_object_exists(lo));
        LASSERT(obj->oo_ipd != NULL);

        flags = writable ? IAM_IT_MOVE|IAM_IT_WRITE : IAM_IT_MOVE;
        OBD_ALLOC_PTR(it);
        if (it != NULL) {
                it->oi_obj = obj;
                lu_object_get(lo);
                iam_it_init(&it->oi_it, &obj->oo_container, flags, obj->oo_ipd);
        }
        return (struct dt_it *)it;
}

static void osd_it_fini(const struct lu_env *env, struct dt_it *di)
{
        struct osd_it *it = (struct osd_it *)di;

        iam_it_fini(&it->oi_it);
        lu_object_put(env, &it->oi_obj->oo_dt.do_lu);
        OBD_FREE_PTR(it);
}

static int osd_it_get(const struct lu_env *env,
                      struct dt_it *di, const struct dt_key *key)
{
        struct osd_it *it = (struct osd_it *)di;

        return iam_it_get(&it->oi_it, (const struct iam_key *)key);
}

static void osd_it_put(const struct lu_env *env, struct dt_it *di)
{
        struct osd_it *it = (struct osd_it *)di;

        iam_it_put(&it->oi_it);
}

static int osd_it_next(const struct lu_env *env, struct dt_it *di)
{
        struct osd_it *it = (struct osd_it *)di;

        return iam_it_next(&it->oi_it);
}

static int osd_it_del(const struct lu_env *env, struct dt_it *di,
                      struct thandle *th)
{
        struct osd_it      *it = (struct osd_it *)di;
        struct osd_thandle *oh;

        LASSERT(th != NULL);

        oh = container_of0(th, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);

        return iam_it_rec_delete(oh->ot_handle, &it->oi_it);
}

static struct dt_key *osd_it_key(const struct lu_env *env,
                                 const struct dt_it *di)
{
        struct osd_it *it = (struct osd_it *)di;

        return (struct dt_key *)iam_it_key_get(&it->oi_it);
}

static int osd_it_key_size(const struct lu_env *env, const struct dt_it *di)
{
        struct osd_it *it = (struct osd_it *)di;

        return iam_it_key_size(&it->oi_it);
}

static struct dt_rec *osd_it_rec(const struct lu_env *env,
                                 const struct dt_it *di)
{
        struct osd_it *it = (struct osd_it *)di;

        return (struct dt_rec *)iam_it_rec_get(&it->oi_it);
}

static __u32 osd_it_store(const struct lu_env *env, const struct dt_it *di)
{
        struct osd_it *it = (struct osd_it *)di;

        return iam_it_store(&it->oi_it);
}

static int osd_it_load(const struct lu_env *env,
                       const struct dt_it *di, __u32 hash)
{
        struct osd_it *it = (struct osd_it *)di;

        return iam_it_load(&it->oi_it, hash);
}

static struct dt_index_operations osd_index_ops = {
        .dio_lookup = osd_index_lookup,
        .dio_insert = osd_index_insert,
        .dio_delete = osd_index_delete,
        .dio_it     = {
                .init     = osd_it_init,
                .fini     = osd_it_fini,
                .get      = osd_it_get,
                .put      = osd_it_put,
                .del      = osd_it_del,
                .next     = osd_it_next,
                .key      = osd_it_key,
                .key_size = osd_it_key_size,
                .rec      = osd_it_rec,
                .store    = osd_it_store,
                .load     = osd_it_load
        }
};

static int osd_index_compat_delete(const struct lu_env *env,
                                   struct dt_object *dt,
                                   const struct dt_key *key,
                                   struct thandle *handle,
                                   struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);

        LASSERT(handle != NULL);
        LASSERT(S_ISDIR(obj->oo_inode->i_mode));
        ENTRY;

#if 0
        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_DELETE))
                RETURN(-EACCES);
#endif

        RETURN(-EOPNOTSUPP);
}

/*
 * Compatibility index operations.
 */


static int osd_build_fid(struct osd_device *osd,
                         struct dentry *dentry, struct lu_fid *fid)
{
        struct inode *inode = dentry->d_inode;

        lu_igif_build(fid, inode->i_ino, inode->i_generation);
        return 0;
}

static int osd_index_compat_lookup(const struct lu_env *env,
                                   struct dt_object *dt,
                                   struct dt_rec *rec, const struct dt_key *key,
                                   struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);

        struct osd_device      *osd  = osd_obj2dev(obj);
        struct osd_thread_info *info = lu_context_key_get(&env->le_ctx, &osd_key);
        struct inode           *dir;

        int result;

        /*
         * XXX temporary solution.
         */
        struct dentry *dentry;
        struct dentry *parent;

        LASSERT(osd_invariant(obj));
        LASSERT(S_ISDIR(obj->oo_inode->i_mode));
        LASSERT(osd_has_index(obj));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_LOOKUP))
                return -EACCES;

        info->oti_str.name = (const char *)key;
        info->oti_str.len  = strlen((const char *)key);

        dir = obj->oo_inode;
        LASSERT(dir->i_op != NULL && dir->i_op->lookup != NULL);

        parent = d_alloc_root(dir);
        if (parent == NULL)
                return -ENOMEM;
        igrab(dir);
        dentry = d_alloc(parent, &info->oti_str);
        if (dentry != NULL) {
                struct dentry *d;

                /*
                 * XXX passing NULL for nameidata should work for
                 * ext3/ldiskfs.
                 */
                d = dir->i_op->lookup(dir, dentry, NULL);
                if (d == NULL) {
                        /*
                         * normal case, result is in @dentry.
                         */
                        if (dentry->d_inode != NULL)
                                result = osd_build_fid(osd, dentry,
                                                       (struct lu_fid *)rec);
                        else
                                result = -ENOENT;
                 } else {
                        /* What? Disconnected alias? Ppheeeww... */
                        CERROR("Aliasing where not expected\n");
                        result = -EIO;
                        dput(d);
                }
                dput(dentry);
        } else
                result = -ENOMEM;
        dput(parent);
        LASSERT(osd_invariant(obj));
        return result;
}

static int osd_add_rec(struct osd_thread_info *info, struct osd_device *dev,
                       struct inode *dir, struct inode *inode, const char *name)
{
        struct dentry *old;
        struct dentry *new;
        struct dentry *parent;

        int result;

        info->oti_str.name = name;
        info->oti_str.len  = strlen(name);

        LASSERT(atomic_read(&dir->i_count) > 0);
        result = -ENOMEM;
        old = d_alloc(dev->od_obj_area, &info->oti_str);
        if (old != NULL) {
                d_instantiate(old, inode);
                igrab(inode);
                LASSERT(atomic_read(&dir->i_count) > 0);
                parent = d_alloc_root(dir);
                if (parent != NULL) {
                        igrab(dir);
                        LASSERT(atomic_read(&dir->i_count) > 1);
                        new = d_alloc(parent, &info->oti_str);
                        LASSERT(atomic_read(&dir->i_count) > 1);
                        if (new != NULL) {
                                LASSERT(atomic_read(&dir->i_count) > 1);
                                result = dir->i_op->link(old, dir, new);
                                LASSERT(atomic_read(&dir->i_count) > 1);
                                dput(new);
                                LASSERT(atomic_read(&dir->i_count) > 1);
                        }
                        LASSERT(atomic_read(&dir->i_count) > 1);
                        dput(parent);
                        LASSERT(atomic_read(&dir->i_count) > 0);
                }
                dput(old);
        }
        LASSERT(atomic_read(&dir->i_count) > 0);
        return result;
}


/*
 * XXX Temporary stuff.
 */
static int osd_index_compat_insert(const struct lu_env *env,
                                   struct dt_object *dt,
                                   const struct dt_rec *rec,
                                   const struct dt_key *key, struct thandle *th,
                                   struct lustre_capa *capa)
{
        struct osd_object     *obj = osd_dt_obj(dt);

        const struct lu_fid *fid  = (const struct lu_fid *)rec;
        const char          *name = (const char *)key;

        struct lu_device    *ludev = dt->do_lu.lo_dev;
        struct lu_object    *luch;

        struct osd_thread_info *info = lu_context_key_get(&env->le_ctx, &osd_key);

        int result;

        LASSERT(S_ISDIR(obj->oo_inode->i_mode));
        LASSERT(osd_invariant(obj));
        LASSERT(th != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_INSERT))
                return -EACCES;

        luch = lu_object_find(env, ludev->ld_site, fid);
        if (!IS_ERR(luch)) {
                if (lu_object_exists(luch)) {
                        struct osd_object *child;

                        child = osd_obj(lu_object_locate(luch->lo_header,
                                                         ludev->ld_type));
                        if (child != NULL)
                                result = osd_add_rec(info, osd_obj2dev(obj),
                                                     obj->oo_inode,
                                                     child->oo_inode, name);
                        else {
                                CERROR("No osd slice.\n");
                                result = -ENOENT;
                        }
                        LASSERT(osd_invariant(obj));
                        LASSERT(osd_invariant(child));
                } else {
                        CERROR("Sorry.\n");
                        result = -ENOENT;
                }
                lu_object_put(env, luch);
        } else
                result = PTR_ERR(luch);
        LASSERT(osd_invariant(obj));
        return result;
}

static struct dt_index_operations osd_index_compat_ops = {
        .dio_lookup = osd_index_compat_lookup,
        .dio_insert = osd_index_compat_insert,
        .dio_delete = osd_index_compat_delete
};

/*
 * OSD device type methods
 */
static int osd_type_init(struct lu_device_type *t)
{
        return lu_context_key_register(&osd_key);
}

static void osd_type_fini(struct lu_device_type *t)
{
        lu_context_key_degister(&osd_key);
}

static struct lu_context_key osd_key = {
        .lct_tags = LCT_DT_THREAD | LCT_MD_THREAD,
        .lct_init = osd_key_init,
        .lct_fini = osd_key_fini,
        .lct_exit = osd_key_exit
};

static void *osd_key_init(const struct lu_context *ctx,
                          struct lu_context_key *key)
{
        struct osd_thread_info *info;

        OBD_ALLOC_PTR(info);
        if (info != NULL)
                info->oti_env = container_of(ctx, struct lu_env, le_ctx);
        else
                info = ERR_PTR(-ENOMEM);
        return info;
}

static void osd_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct osd_thread_info *info = data;
        OBD_FREE_PTR(info);
}

static void osd_key_exit(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct osd_thread_info *info = data;

        LASSERT(info->oti_r_locks == 0);
        LASSERT(info->oti_w_locks == 0);
        LASSERT(info->oti_txns    == 0);
}

static int osd_device_init(const struct lu_env *env,
                           struct lu_device *d, struct lu_device *next)
{
        return lu_env_init(&osd_dev(d)->od_env_for_commit, NULL, LCT_MD_THREAD);
}

static int osd_shutdown(const struct lu_env *env, struct osd_device *o)
{
        struct osd_thread_info *info = lu_context_key_get(&env->le_ctx, &osd_key);
        ENTRY;
        if (o->od_obj_area != NULL) {
                dput(o->od_obj_area);
                o->od_obj_area = NULL;
        }
        osd_oi_fini(info, &o->od_oi);

        RETURN(0);
}

static int osd_mount(const struct lu_env *env,
                     struct osd_device *o, struct lustre_cfg *cfg)
{
        struct lustre_mount_info *lmi;
        const char               *dev = lustre_cfg_string(cfg, 0);
        struct osd_thread_info   *info = lu_context_key_get(&env->le_ctx, &osd_key);
        int result;

        ENTRY;

        if (o->od_mount != NULL) {
                CERROR("Already mounted (%s)\n", dev);
                RETURN(-EEXIST);
        }

        /* get mount */
        lmi = server_get_mount(dev);
        if (lmi == NULL) {
                CERROR("Cannot get mount info for %s!\n", dev);
                RETURN(-EFAULT);
        }

        LASSERT(lmi != NULL);
        /* save lustre_mount_info in dt_device */
        o->od_mount = lmi;

        result = osd_oi_init(info, &o->od_oi, &o->od_dt_dev);
        if (result == 0) {
                struct dentry *d;

                d = simple_mkdir(osd_sb(o)->s_root, "*OBJ-TEMP*", 0777, 1);
                if (!IS_ERR(d)) {
                        o->od_obj_area = d;
                } else
                        result = PTR_ERR(d);
        }
        if (result != 0)
                osd_shutdown(env, o);
        RETURN(result);
}

static struct lu_device *osd_device_fini(const struct lu_env *env,
                                         struct lu_device *d)
{
        ENTRY;

        shrink_dcache_sb(osd_sb(osd_dev(d)));
        osd_sync(env, lu2dt_dev(d));

        if (osd_dev(d)->od_mount)
                server_put_mount(osd_dev(d)->od_mount->lmi_name,
                                 osd_dev(d)->od_mount->lmi_mnt);
        osd_dev(d)->od_mount = NULL;

        lu_env_fini(&osd_dev(d)->od_env_for_commit);
        RETURN(NULL);
}

static struct lu_device *osd_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct osd_device *o;

        OBD_ALLOC_PTR(o);
        if (o != NULL) {
                int result;

                result = dt_device_init(&o->od_dt_dev, t);
                if (result == 0) {
                        l = osd2lu_dev(o);
                        l->ld_ops = &osd_lu_ops;
                        o->od_dt_dev.dd_ops = &osd_dt_ops;
                } else
                        l = ERR_PTR(result);
        } else
                l = ERR_PTR(-ENOMEM);
        return l;
}

static void osd_device_free(const struct lu_env *env, struct lu_device *d)
{
        struct osd_device *o = osd_dev(d);

        dt_device_fini(&o->od_dt_dev);
        OBD_FREE_PTR(o);
}

static int osd_process_config(const struct lu_env *env,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct osd_device *o = osd_dev(d);
        int err;
        ENTRY;

        switch(cfg->lcfg_command) {
        case LCFG_SETUP:
                err = osd_mount(env, o, cfg);
                break;
        case LCFG_CLEANUP:
                err = osd_shutdown(env, o);
                break;
        default:
                err = -ENOTTY;
        }

        RETURN(err);
}
extern void ldiskfs_orphan_cleanup (struct super_block * sb,
				    struct ldiskfs_super_block * es);

static int osd_recovery_complete(const struct lu_env *env,
                                 struct lu_device *d)
{
        struct osd_device *o = osd_dev(d);
        ENTRY;
        /* TODO: orphans handling */
        ldiskfs_orphan_cleanup(osd_sb(o), LDISKFS_SB(osd_sb(o))->s_es);
        RETURN(0);
}

/*
 * fid<->inode<->object functions.
 */

static struct inode *osd_open(struct dentry *parent,
                              const char *name, mode_t mode)
{
        struct dentry *dentry;
        struct inode *result;

        dentry = osd_lookup(parent, name);
        if (IS_ERR(dentry)) {
                CERROR("Error opening %s: %ld\n", name, PTR_ERR(dentry));
                result = NULL; /* dput(NULL) below is OK */
        } else if (dentry->d_inode == NULL) {
                CERROR("Not found: %s\n", name);
                result = ERR_PTR(-ENOENT);
        } else if ((dentry->d_inode->i_mode & S_IFMT) != mode) {
                CERROR("Wrong mode: %s: %o != %o\n", name,
                       dentry->d_inode->i_mode, mode);
                result = ERR_PTR(mode == S_IFDIR ? -ENOTDIR : -EISDIR);
        } else {
                result = dentry->d_inode;
                igrab(result);
        }
        dput(dentry);
        return result;
}

struct dentry *osd_lookup(struct dentry *parent, const char *name)
{
        struct dentry *dentry;

        CDEBUG(D_INODE, "looking up object %s\n", name);
        down(&parent->d_inode->i_sem);
        dentry = lookup_one_len(name, parent, strlen(name));
        up(&parent->d_inode->i_sem);

        if (IS_ERR(dentry)) {
                CERROR("error getting %s: %ld\n", name, PTR_ERR(dentry));
        } else if (dentry->d_inode != NULL && is_bad_inode(dentry->d_inode)) {
                CERROR("got bad object %s inode %lu\n",
                       name, dentry->d_inode->i_ino);
                dput(dentry);
                dentry = ERR_PTR(-ENOENT);
        }
        return dentry;
}

int osd_lookup_id(struct dt_device *dev, const char *name, mode_t mode,
                  struct osd_inode_id *id)
{
        struct inode *inode;
        struct osd_device *osd = osd_dt_dev(dev);
        int result;

        inode = osd_open(osd_sb(osd)->s_root, name, mode);
        if (!IS_ERR(inode)) {
                LASSERT(inode != NULL);
                id->oii_ino = inode->i_ino;
                id->oii_gen = inode->i_generation;
                result = 0;
        } else
                result = PTR_ERR(inode);
        return result;
}

static struct inode *osd_iget(struct osd_thread_info *info,
                              struct osd_device *dev,
                              const struct osd_inode_id *id)
{
        struct inode *inode;

        inode = iget(osd_sb(dev), id->oii_ino);
        if (inode == NULL) {
                CERROR("no inode\n");
                inode = ERR_PTR(-EACCES);
        } else if (is_bad_inode(inode)) {
                CERROR("bad inode\n");
                iput(inode);
                inode = ERR_PTR(-ENOENT);
        } else if (inode->i_generation != id->oii_gen) {
                CERROR("stale inode\n");
                iput(inode);
                inode = ERR_PTR(-ESTALE);
        }

        return inode;

}

static int osd_fid_lookup(const struct lu_env *env,
                          struct osd_object *obj, const struct lu_fid *fid)
{
        struct osd_thread_info *info;
        struct lu_device       *ldev = obj->oo_dt.do_lu.lo_dev;
        struct osd_device      *dev;
        struct osd_inode_id    *id;
        struct osd_oi          *oi;
        struct inode           *inode;
        int                     result;

        LASSERT(osd_invariant(obj));
        LASSERT(obj->oo_inode == NULL);
        LASSERT(fid_is_sane(fid));
        LASSERT(fid_is_local(ldev->ld_site, fid));

        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &osd_key);
        dev  = osd_dev(ldev);
        id   = &info->oti_id;
        oi   = &dev->od_oi;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT))
                RETURN(-ENOENT);

        osd_oi_read_lock(oi);
        result = osd_oi_lookup(info, oi, fid, id);
        if (result == 0) {
                inode = osd_iget(info, dev, id);
                if (!IS_ERR(inode)) {
                        obj->oo_inode = inode;
                        LASSERT(obj->oo_inode->i_sb == osd_sb(dev));
                        result = 0;
                } else
                        /*
                         * If fid wasn't found in oi, inode-less object is
                         * created, for which lu_object_exists() returns
                         * false. This is used in a (frequent) case when
                         * objects are created as locking anchors or
                         * place holders for objects yet to be created.
                         */
                        result = PTR_ERR(inode);
        } else if (result == -ENOENT)
                result = 0;
        osd_oi_read_unlock(oi);
        LASSERT(osd_invariant(obj));
        RETURN(result);
}

static int osd_inode_getattr(const struct lu_env *env,
                             struct inode *inode, struct lu_attr *attr)
{
        attr->la_valid      |= LA_ATIME | LA_MTIME | LA_CTIME | LA_MODE |
                               LA_SIZE | LA_BLOCKS | LA_UID | LA_GID |
                               LA_FLAGS | LA_NLINK | LA_RDEV | LA_BLKSIZE;

        attr->la_atime      = LTIME_S(inode->i_atime);
        attr->la_mtime      = LTIME_S(inode->i_mtime);
        attr->la_ctime      = LTIME_S(inode->i_ctime);
        attr->la_mode       = inode->i_mode;
        attr->la_size       = inode->i_size;
        attr->la_blocks     = inode->i_blocks;
        attr->la_uid        = inode->i_uid;
        attr->la_gid        = inode->i_gid;
        attr->la_flags      = LDISKFS_I(inode)->i_flags;
        attr->la_nlink      = inode->i_nlink;
        attr->la_rdev       = inode->i_rdev;
        attr->la_blksize    = inode->i_blksize;
        return 0;
}

/*
 * Helpers.
 */

static int lu_device_is_osd(const struct lu_device *d)
{
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &osd_lu_ops);
}

static struct osd_object *osd_obj(const struct lu_object *o)
{
        LASSERT(lu_device_is_osd(o->lo_dev));
        return container_of0(o, struct osd_object, oo_dt.do_lu);
}

static struct osd_device *osd_dt_dev(const struct dt_device *d)
{
        LASSERT(lu_device_is_osd(&d->dd_lu_dev));
        return container_of0(d, struct osd_device, od_dt_dev);
}

static struct osd_device *osd_dev(const struct lu_device *d)
{
        LASSERT(lu_device_is_osd(d));
        return osd_dt_dev(container_of0(d, struct dt_device, dd_lu_dev));
}

static struct osd_object *osd_dt_obj(const struct dt_object *d)
{
        return osd_obj(&d->do_lu);
}

static struct osd_device *osd_obj2dev(const struct osd_object *o)
{
        return osd_dev(o->oo_dt.do_lu.lo_dev);
}

static struct lu_device *osd2lu_dev(struct osd_device *osd)
{
        return &osd->od_dt_dev.dd_lu_dev;
}

static struct super_block *osd_sb(const struct osd_device *dev)
{
        return dev->od_mount->lmi_mnt->mnt_sb;
}

static journal_t *osd_journal(const struct osd_device *dev)
{
        return LDISKFS_SB(osd_sb(dev))->s_journal;
}

static int osd_has_index(const struct osd_object *obj)
{
        return obj->oo_dt.do_index_ops != NULL;
}

static int osd_object_invariant(const struct lu_object *l)
{
        return osd_invariant(osd_obj(l));
}

static struct lu_object_operations osd_lu_obj_ops = {
        .loo_object_init      = osd_object_init,
        .loo_object_delete    = osd_object_delete,
        .loo_object_release   = osd_object_release,
        .loo_object_free      = osd_object_free,
        .loo_object_print     = osd_object_print,
        .loo_object_invariant = osd_object_invariant
};

static struct lu_device_operations osd_lu_ops = {
        .ldo_object_alloc      = osd_object_alloc,
        .ldo_process_config    = osd_process_config,
        .ldo_recovery_complete = osd_recovery_complete
};

static struct lu_device_type_operations osd_device_type_ops = {
        .ldto_init = osd_type_init,
        .ldto_fini = osd_type_fini,

        .ldto_device_alloc = osd_device_alloc,
        .ldto_device_free  = osd_device_free,

        .ldto_device_init    = osd_device_init,
        .ldto_device_fini    = osd_device_fini
};

static struct lu_device_type osd_device_type = {
        .ldt_tags     = LU_DEVICE_DT,
        .ldt_name     = LUSTRE_OSD_NAME,
        .ldt_ops      = &osd_device_type_ops,
        .ldt_ctx_tags = LCT_MD_THREAD|LCT_DT_THREAD
};

/*
 * lprocfs legacy support.
 */
static struct lprocfs_vars lprocfs_osd_obd_vars[] = {
        { 0 }
};

static struct lprocfs_vars lprocfs_osd_module_vars[] = {
        { 0 }
};

static struct obd_ops osd_obd_device_ops = {
        .o_owner = THIS_MODULE
};

LPROCFS_INIT_VARS(osd, lprocfs_osd_module_vars, lprocfs_osd_obd_vars);

static int __init osd_mod_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(osd, &lvars);
        return class_register_type(&osd_obd_device_ops, NULL, lvars.module_vars,
                                   LUSTRE_OSD_NAME, &osd_device_type);
}

static void __exit osd_mod_exit(void)
{
        class_unregister_type(LUSTRE_OSD_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Device ("LUSTRE_OSD_NAME")");
MODULE_LICENSE("GPL");

cfs_module(osd, "0.0.2", osd_mod_init, osd_mod_exit);
