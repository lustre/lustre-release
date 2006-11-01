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
#include <lustre_fid.h>

#include "mdd_internal.h"

static const char dot[] = ".";
static const char dotdot[] = "..";

static int __mdd_lookup(const struct lu_env *env, struct md_object *pobj,
                        const char *name, struct lu_fid* fid, int mask);
static int
__mdd_lookup_locked(const struct lu_env *env, struct md_object *pobj,
                    const char *name, struct lu_fid* fid, int mask)
{
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct dynlock_handle *dlh;
        int rc;

        dlh = mdd_pdo_read_lock(env, mdd_obj, name);
        if (dlh == NULL)
                return -ENOMEM;
        rc = __mdd_lookup(env, pobj, name, fid, mask);
        mdd_pdo_read_unlock(env, mdd_obj, dlh);

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


static int mdd_parent_fid(const struct lu_env *env, struct mdd_object *obj,
                          struct lu_fid *fid)
{
        return __mdd_lookup_locked(env, &obj->mod_obj, dotdot, fid, 0);
}

/*
 * For root fid use special function, whcih does not compare version component
 * of fid. Vresion component is different for root fids on all MDTs.
 */
static int mdd_is_root(struct mdd_device *mdd, const struct lu_fid *fid)
{
        return fid_seq(&mdd->mdd_root_fid) == fid_seq(fid) &&
                fid_oid(&mdd->mdd_root_fid) == fid_oid(fid);
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

        /* Check for root first. */
        if (mdd_is_root(mdd, mdo2fid(p1)))
                RETURN(0);

        for(;;) {
                rc = mdd_parent_fid(env, p1, pfid);
                if (rc)
                        GOTO(out, rc);
                if (mdd_is_root(mdd, pfid))
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
                        GOTO(out, rc = -EREMOTE);
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
        if (rc == 0) {
                /* found root */
                fid_zero(sfid);
        } else if (rc == 1) {
                /* found @fid is parent */
                *sfid = *fid;
                rc = 0;
        }
        RETURN(rc);
}

/* Check whether it may create the cobj under the pobj */
static int mdd_may_create(const struct lu_env *env, struct mdd_object *pobj,
                          struct mdd_object *cobj, int need_check, int lock)
{
        int rc = 0;
        ENTRY;

        if (cobj && lu_object_exists(&cobj->mod_obj.mo_lu))
                RETURN(-EEXIST);

        if (mdd_is_dead_obj(pobj))
                RETURN(-ENOENT);

        if (need_check) {
                if (lock) {
                        rc = mdd_permission_internal_locked(env, pobj,
                                                            (MAY_WRITE |
                                                             MAY_EXEC));
                } else {
                        rc = mdd_permission_internal(env, pobj, (MAY_WRITE |
                                                                 MAY_EXEC));
                }
        }
        RETURN(rc);
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

        rc = mdd_la_get(env, cobj, tmp_la, BYPASS_CAPA);
        if (rc) {
                return rc;
        } else if (tmp_la->la_uid == uc->mu_fsuid) {
                return 0;
        } else {
                mdd_read_lock(env, pobj);
                rc = mdd_la_get(env, pobj, tmp_la, BYPASS_CAPA);
                mdd_read_unlock(env, pobj);
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
                        rc = mdd_permission_internal_locked(env, pobj,
                                                            MAY_WRITE |
                                                            MAY_EXEC);
        }
        RETURN(rc);
}

int mdd_link_sanity_check(const struct lu_env *env, struct mdd_object *tgt_obj,
                          struct mdd_object *src_obj)
{
        int rc = 0;
        ENTRY;

        if (tgt_obj) {
                /* 
                 * Lock only if tgt and src not same object. This is because
                 * mdd_link() already locked src and we try to lock it again we
                 * have a problem.
                 */
                rc = mdd_may_create(env, tgt_obj, NULL, 1, (src_obj != tgt_obj));
                if (rc)
                        RETURN(rc);
        }

        if (mdd_is_immutable(src_obj) || mdd_is_append(src_obj))
                RETURN(-EPERM);

        if (S_ISDIR(mdd_object_type(src_obj)))
                RETURN(-EPERM);

        RETURN(rc);
}

const struct dt_rec *__mdd_fid_rec(const struct lu_env *env,
                                   const struct lu_fid *fid)
{
        struct mdd_thread_info *info = mdd_env_info(env);

        fid_cpu_to_be(&info->mti_fid2, fid);
        return (const struct dt_rec *)&info->mti_fid2;
}


/* insert new index, add reference if isdir, update times */
static int __mdd_index_insert(const struct lu_env *env,
                             struct mdd_object *pobj, const struct lu_fid *lf,
                             const char *name, int isdir, struct thandle *th,
                             struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(pobj);
        struct timeval start;
        int rc;
        ENTRY;

        mdd_lproc_time_start(mdo2mdd(&pobj->mod_obj), &start,
                             LPROC_MDD_INDEX_INSERT);
#if 0
        struct lu_attr   *la = &mdd_env_info(env)->mti_la;
#endif

        if (dt_try_as_dir(env, next))
                rc = next->do_index_ops->dio_insert(env, next,
                                                    __mdd_fid_rec(env, lf),
                                                    (const struct dt_key *)name,
                                                    th, capa);
        else
                rc = -ENOTDIR;

        if (rc == 0) {
                if (isdir) {
                        mdd_write_lock(env, pobj);
                        mdd_ref_add_internal(env, pobj, th);
                        mdd_write_unlock(env, pobj);
                }
#if 0
                la->la_valid = LA_MTIME|LA_CTIME;
                la->la_atime = ma->ma_attr.la_atime;
                la->la_ctime = ma->ma_attr.la_ctime;
                rc = mdd_attr_set_internal(env, mdd_obj, la, handle, 0);
#endif
        }
        mdd_lproc_time_end(mdo2mdd(&pobj->mod_obj), &start,
                           LPROC_MDD_INDEX_INSERT);
        return rc;
}

static int __mdd_index_delete(const struct lu_env *env,
                              struct mdd_object *pobj, const char *name,
                              int is_dir, struct thandle *handle,
                              struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(pobj);
        struct timeval start;
        int rc;
        ENTRY;

        mdd_lproc_time_start(mdo2mdd(&pobj->mod_obj), &start,
                             LPROC_MDD_INDEX_DELETE);
        if (dt_try_as_dir(env, next)) {
                rc = next->do_index_ops->dio_delete(env, next,
                                                    (struct dt_key *)name,
                                                    handle, capa);
                if (rc == 0 && is_dir) {
                        mdd_write_lock(env, pobj);
                        mdd_ref_del_internal(env, pobj, handle);
                        mdd_write_unlock(env, pobj);
                }
        } else
                rc = -ENOTDIR;
        mdd_lproc_time_end(mdo2mdd(&pobj->mod_obj), &start,
                           LPROC_MDD_INDEX_DELETE);
        RETURN(rc);
}

static int __mdd_index_insert_only(const struct lu_env *env,
                                   struct mdd_object *pobj,
                                   const struct lu_fid *lf,
                                   const char *name, struct thandle *th,
                                   struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(pobj);
        int rc;
        ENTRY;

        if (dt_try_as_dir(env, next)) {
                rc = next->do_index_ops->dio_insert(env, next,
                                                    __mdd_fid_rec(env, lf),
                                                    (const struct dt_key *)name,
                                                    th, capa);
        } else {
                rc = -ENOTDIR;
        }
        RETURN(rc);
}

static int mdd_link(const struct lu_env *env, struct md_object *tgt_obj,
                    struct md_object *src_obj, const char *name,
                    struct md_attr *ma)
{
        struct lu_attr    *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_tobj = md2mdd_obj(tgt_obj);
        struct mdd_object *mdd_sobj = md2mdd_obj(src_obj);
        struct mdd_device *mdd = mdo2mdd(src_obj);
        struct dynlock_handle *dlh;
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_LINK_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_tobj, name);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);
        mdd_write_lock(env, mdd_sobj);

        rc = mdd_link_sanity_check(env, mdd_tobj, mdd_sobj);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_insert_only(env, mdd_tobj, mdo2fid(mdd_sobj),
                                     name, handle,
                                     mdd_object_capa(env, mdd_tobj));
        if (rc)
                GOTO(out_unlock, rc);
        
        mdd_ref_add_internal(env, mdd_sobj, handle);

        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME;
        rc = mdd_attr_set_internal(env, mdd_sobj, la_copy, handle, 0);
        if (rc)
                GOTO(out_unlock, rc);

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal_locked(env, mdd_tobj, la_copy, handle, 0);

out_unlock:
        mdd_write_unlock(env, mdd_sobj);
        mdd_pdo_write_unlock(env, mdd_tobj, dlh);
out_trans:
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

/* caller should take a lock before calling */
int mdd_finish_unlink(const struct lu_env *env,
                      struct mdd_object *obj, struct md_attr *ma,
                      struct thandle *th)
{
        int rc;
        ENTRY;

        rc = mdd_iattr_get(env, obj, ma);
        if (rc == 0 && ma->ma_attr.la_nlink == 0) {
                /* add new orphan and the object
                 * will be deleted during the object_put() */
                if (__mdd_orphan_add(env, obj, th) == 0)
                        obj->mod_flags |= ORPHAN_OBJ;

                if (obj->mod_count == 0)
                        rc = mdd_object_kill(env, obj, ma);
                else
                        /* clear MA_LOV | MA_COOKIE, if we do not
                         * unlink it in case we get it somewhere */
                        ma->ma_valid &= ~(MA_LOV | MA_COOKIE);
        } else
                ma->ma_valid &= ~(MA_LOV | MA_COOKIE);

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
        it = iops->init(env, obj, 0, BYPASS_CAPA);
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

int mdd_unlink_sanity_check(const struct lu_env *env, struct mdd_object *pobj,
                            struct mdd_object *cobj, struct md_attr *ma)
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
        struct dynlock_handle *dlh;
        int rc, is_dir;
        ENTRY;

        rc = mdd_log_txn_param_build(env, cobj, ma, MDD_TXN_UNLINK_OP);
        if (rc)
                RETURN(rc);

        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_pobj, name);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);
        mdd_write_lock(env, mdd_cobj);

        rc = mdd_unlink_sanity_check(env, mdd_pobj, mdd_cobj, ma);
        if (rc)
                GOTO(cleanup, rc);

        is_dir = S_ISDIR(lu_object_attr(&cobj->mo_lu));
        rc = __mdd_index_delete(env, mdd_pobj, name, is_dir, handle,
                                mdd_object_capa(env, mdd_pobj));
        if (rc)
                GOTO(cleanup, rc);

        mdd_ref_del_internal(env, mdd_cobj, handle);
        *la_copy = ma->ma_attr;
        if (is_dir) {
                /* unlink dot */
                mdd_ref_del_internal(env, mdd_cobj, handle);
        } else {
                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_set_internal(env, mdd_cobj, la_copy, handle, 0);
                if (rc)
                        GOTO(cleanup, rc);
        }

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal_locked(env, mdd_pobj, la_copy, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        rc = mdd_finish_unlink(env, mdd_cobj, ma, handle);

        if (rc == 0)
                obd_set_info_async(mdd2obd_dev(mdd)->u.mds.mds_osc_exp,
                                   strlen("unlinked"), "unlinked", 0,
                                   NULL, NULL);
cleanup:
        mdd_write_unlock(env, mdd_cobj);
        mdd_pdo_write_unlock(env, mdd_pobj, dlh);
out_trans:
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
        RETURN(mdd_permission_internal_locked(env, obj,
                                              MAY_WRITE | MAY_EXEC));
}

static int mdd_name_insert(const struct lu_env *env,
                           struct md_object *pobj,
                           const char *name, const struct lu_fid *fid,
                           int isdir)
{
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct thandle *handle;
        struct dynlock_handle *dlh;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_INDEX_INSERT_OP);
        handle = mdd_trans_start(env, mdo2mdd(pobj));
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_obj, name);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);
        rc = mdd_ni_sanity_check(env, pobj, name, fid);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_insert(env, mdd_obj, fid, name, isdir, handle,
                                BYPASS_CAPA);

        EXIT;
out_unlock:
        mdd_pdo_write_unlock(env, mdd_obj, dlh);
out_trans:
        mdd_trans_stop(env, mdo2mdd(pobj), rc, handle);
        return rc;
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
        RETURN(mdd_permission_internal_locked(env, obj,
                                              MAY_WRITE | MAY_EXEC));
}

static int mdd_name_remove(const struct lu_env *env,
                           struct md_object *pobj,
                           const char *name, int is_dir)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct thandle *handle;
        struct dynlock_handle *dlh;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_INDEX_DELETE_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_obj, name);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);
        rc = mdd_nr_sanity_check(env, pobj, name);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_delete(env, mdd_obj, name, is_dir, handle,
                                BYPASS_CAPA);

out_unlock:
        mdd_pdo_write_unlock(env, mdd_obj, dlh);
out_trans:
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

static int mdd_rt_sanity_check(const struct lu_env *env,
                               struct mdd_object *tgt_pobj,
                               struct mdd_object *tobj,
                               const struct lu_fid *sfid,
                               const char *name, struct md_attr *ma)
{
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
                rc = mdd_may_create(env, tgt_pobj, NULL, 1, 1);
        }

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
        struct dynlock_handle *dlh;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_RENAME_TGT_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_tpobj, name);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);
        if (mdd_tobj)
                mdd_write_lock(env, mdd_tobj);

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
                mdd_ref_del_internal(env, mdd_tobj, handle);
cleanup:
        if (tobj)
                mdd_write_unlock(env, mdd_tobj);
        mdd_pdo_write_unlock(env, mdd_tpobj, dlh);
out_trans:
        mdd_trans_stop(env, mdd, rc, handle);
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

        mdd_txn_param_build(env, mdd, MDD_TXN_CREATE_DATA_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(rc = PTR_ERR(handle));

        /*
         * XXX: Setting the lov ea is not locked but setting the attr is locked?
         */

        /* Replay creates has objects already */
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

        /* Finish mdd_lov_create() stuff. */
        mdd_lov_create_finish(env, mdd, rc);
        mdd_trans_stop(env, mdd, rc, handle);
        if (lmm)
                OBD_FREE(lmm, lmm_size);
        RETURN(rc);
}

static int
__mdd_lookup(const struct lu_env *env, struct md_object *pobj,
             const char *name, struct lu_fid* fid, int mask)
{
        struct mdd_object   *mdd_obj = md2mdd_obj(pobj);
        struct dt_object    *dir = mdd_object_child(mdd_obj);
        struct dt_rec       *rec = (struct dt_rec *)fid;
        const struct dt_key *key = (const struct dt_key *)name;
        struct timeval       start;
        int rc;
        ENTRY;

        mdd_lproc_time_start(mdo2mdd(pobj), &start, LPROC_MDD_LOOKUP);
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

#if 0
        if (mask == MAY_EXEC)
                rc = mdd_exec_permission_lite(env, mdd_obj);
        else
#endif
        rc = mdd_permission_internal_locked(env, mdd_obj, mask);
        if (rc)
                RETURN(rc);

        if (S_ISDIR(mdd_object_type(mdd_obj)) && dt_try_as_dir(env, dir)) {
                rc = dir->do_index_ops->dio_lookup(env, dir, rec, key,
                                                   mdd_object_capa(env, mdd_obj));
                if (rc == 0)
                        fid_be_to_cpu(fid, fid);
        } else
                rc = -ENOTDIR;

        mdd_lproc_time_end(mdo2mdd(pobj), &start, LPROC_MDD_LOOKUP);
        RETURN(rc);
}

int mdd_object_initialize(const struct lu_env *env, const struct lu_fid *pfid,
                          struct mdd_object *child, struct md_attr *ma,
                          struct thandle *handle)
{
        int rc;
        ENTRY;

        /* update attributes for child.
         * FIXME:
         *  (1) the valid bits should be converted between Lustre and Linux;
         *  (2) maybe, the child attributes should be set in OSD when creation.
         */

        rc = mdd_attr_set_internal(env, child, &ma->ma_attr, handle, 0);
        if (rc != 0)
                RETURN(rc);

        if (S_ISDIR(ma->ma_attr.la_mode)) {
                /* add . and .. for newly created dir */
                mdd_ref_add_internal(env, child, handle);
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
                                        mdd_ref_del_internal(env, child, handle);
                        }
                }
        }
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
        rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
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
                      struct md_create_spec *spec,
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
        struct dynlock_handle *dlh;
        struct timeval  start;
        ENTRY;

        mdd_lproc_time_start(mdd, &start, LPROC_MDD_CREATE);
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
         * To avoid this follow local file systems that do double lookup:
         *
         *     0. lookup -> -EEXIST (mdd_create_sanity_check())
         *
         *     1. create            (mdd_object_create_internal())
         *
         *     2. insert            (__mdd_index_insert(), lookup again)
         */

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

        mdd_txn_param_build(env, mdd, MDD_TXN_MKDIR_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_pobj, name);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);

        /*
         * XXX check that link can be added to the parent in mkdir case.
         */

        mdd_write_lock(env, son);
        rc = mdd_object_create_internal(env, son, ma, handle);
        if (rc) {
                mdd_write_unlock(env, son);
                GOTO(cleanup, rc);
        }

        created = 1;

#ifdef CONFIG_FS_POSIX_ACL
        mdd_read_lock(env, mdd_pobj);
        rc = mdd_acl_init(env, mdd_pobj, son, &ma->ma_attr.la_mode, handle);
        mdd_read_unlock(env, mdd_pobj);
        if (rc) {
                mdd_write_unlock(env, son);
                GOTO(cleanup, rc);
        } else {
                ma->ma_attr.la_valid |= LA_MODE;
        }
#endif

        rc = mdd_object_initialize(env, mdo2fid(mdd_pobj),
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
                LASSERT(lmm == NULL);
                lmm = (struct lov_mds_md *)spec->u.sp_ea.eadata;
                lmm_size = spec->u.sp_ea.eadatalen;
        }
        rc = mdd_lov_set_md(env, mdd_pobj, son, lmm, lmm_size, handle, 0);
        if (rc) {
                CERROR("error on stripe info copy %d \n", rc);
                GOTO(cleanup, rc);
        }
        if (lmm && lmm_size > 0) {
                /* set Lov here, do not get lmm again later */
                memcpy(ma->ma_lmm, lmm, lmm_size);
                ma->ma_lmm_size = lmm_size;
                ma->ma_valid |= MA_LOV;
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
        rc = mdd_attr_set_internal_locked(env, mdd_pobj, la_copy, handle, 0);
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
                if (rc2 == 0) {
                        mdd_write_lock(env, son);
                        mdd_ref_del_internal(env, son, handle);
                        mdd_write_unlock(env, son);
                }
        }
        /* finish mdd_lov_create() stuff */
        mdd_lov_create_finish(env, mdd, rc);
        if (lmm && !spec->u.sp_ea.no_lov_create)
                OBD_FREE(lmm, lmm_size);
        mdd_pdo_write_unlock(env, mdd_pobj, dlh);
out_trans:
        mdd_trans_stop(env, mdd, rc, handle);
        mdd_lproc_time_end(mdd, &start, LPROC_MDD_CREATE);
        RETURN(rc);
}

/*
 * Get locks on parents in proper order
 * RETURN: < 0 - error, rename_order if successful
 */
enum rename_order {
        MDD_RN_SAME,
        MDD_RN_SRCTGT,
        MDD_RN_TGTSRC
};

static int mdd_rename_order(const struct lu_env *env,
                            struct mdd_device *mdd,
                            struct mdd_object *src_pobj,
                            struct mdd_object *tgt_pobj)
{
        /* order of locking, 1 - tgt-src, 0 - src-tgt*/
        int rc;
        ENTRY;

        if (src_pobj == tgt_pobj)
                RETURN(MDD_RN_SAME);

        /* compared the parent child relationship of src_p&tgt_p */
        if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(src_pobj))){
                rc = MDD_RN_SRCTGT;
        } else if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(tgt_pobj))) {
                rc = MDD_RN_TGTSRC;
        } else {
                rc = mdd_is_parent(env, mdd, src_pobj, mdo2fid(tgt_pobj), NULL);
                if (rc == -EREMOTE)
                        rc = 0;

                if (rc == 1)
                        rc = MDD_RN_TGTSRC;
                else if (rc == 0)
                        rc = MDD_RN_SRCTGT;
        }

        RETURN(rc);
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
        rc = mdd_permission_internal_locked(env, src_pobj,
                                            MAY_WRITE | MAY_EXEC);
        if (rc)
                RETURN(rc);

        if (!tobj) {
                rc = mdd_may_create(env, tgt_pobj, NULL,
                                    (src_pobj != tgt_pobj), 1);
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
        struct dynlock_handle *sdlh, *tdlh;
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

        mdd_txn_param_build(env, mdd, MDD_TXN_RENAME_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        /* FIXME: Should consider tobj and sobj too in rename_lock. */
        rc = mdd_rename_order(env, mdd, mdd_spobj, mdd_tpobj);
        if (rc < 0)
                GOTO(cleanup_unlocked, rc);

        /* get locks in determined order */
        if (rc == MDD_RN_SAME) {
                sdlh = mdd_pdo_write_lock(env, mdd_spobj, sname);
                /* check hashes to determine do we need one lock or two */
                if (mdd_name2hash(sname) != mdd_name2hash(tname))
                        tdlh = mdd_pdo_write_lock(env, mdd_tpobj, tname);
                else
                        tdlh = sdlh;
        } else if (rc == MDD_RN_SRCTGT) {
                sdlh = mdd_pdo_write_lock(env, mdd_spobj, sname);
                tdlh = mdd_pdo_write_lock(env, mdd_tpobj, tname);
        } else {
                tdlh = mdd_pdo_write_lock(env, mdd_tpobj, tname);
                sdlh = mdd_pdo_write_lock(env, mdd_spobj, sname);
        }
        if (sdlh == NULL || tdlh == NULL)
                GOTO(cleanup, rc = -ENOMEM);

        rc = mdd_rename_sanity_check(env, mdd_spobj, mdd_tpobj,
                                     lf, is_dir, mdd_tobj);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_delete(env, mdd_spobj, sname, is_dir, handle,
                                mdd_object_capa(env, mdd_spobj));
        if (rc)
                GOTO(cleanup, rc);

        /*
         * Here tobj can be remote one, so we do index_delete unconditionally
         * and -ENOENT is allowed.
         */
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
                rc = mdd_attr_set_internal_locked(env, mdd_sobj, la_copy,
                                                  handle, 1);
                if (rc)
                        GOTO(cleanup, rc);
        }
        if (tobj && lu_object_exists(&tobj->mo_lu)) {
                mdd_write_lock(env, mdd_tobj);
                mdd_ref_del_internal(env, mdd_tobj, handle);
                /* remove dot reference */
                if (is_dir)
                        mdd_ref_del_internal(env, mdd_tobj, handle);

                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_set_internal(env, mdd_tobj, la_copy, handle, 0);
                if (rc)
                        GOTO(cleanup, rc);

                rc = mdd_finish_unlink(env, mdd_tobj, ma, handle);
                mdd_write_unlock(env, mdd_tobj);
                if (rc)
                        GOTO(cleanup, rc);
        }

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal_locked(env, mdd_spobj, la_copy, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        if (mdd_spobj != mdd_tpobj) {
                la_copy->la_valid = LA_CTIME | LA_MTIME;
                rc = mdd_attr_set_internal_locked(env, mdd_tpobj, la_copy,
                                                  handle, 0);
        }

cleanup:
        if (likely(tdlh) && sdlh != tdlh)
                mdd_pdo_write_unlock(env, mdd_tpobj, tdlh);
        if (likely(sdlh))
                mdd_pdo_write_unlock(env, mdd_spobj, sdlh);
cleanup_unlocked:
        mdd_trans_stop(env, mdd, rc, handle);
        if (mdd_sobj)
                mdd_object_put(env, mdd_sobj);
        RETURN(rc);
}

struct md_dir_operations mdd_dir_ops = {
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
