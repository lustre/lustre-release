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
 * lustre/mdd/mdd_dir.c
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

static struct lu_name lname_dotdot = {
        (char *) dotdot,
        sizeof(dotdot) - 1
};

static int __mdd_lookup(const struct lu_env *env, struct md_object *pobj,
                        const struct lu_name *lname, struct lu_fid* fid,
                        int mask);
static int
__mdd_lookup_locked(const struct lu_env *env, struct md_object *pobj,
                    const struct lu_name *lname, struct lu_fid* fid, int mask)
{
        char *name = lname->ln_name;
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct dynlock_handle *dlh;
        int rc;

        dlh = mdd_pdo_read_lock(env, mdd_obj, name, MOR_TGT_PARENT);
        if (unlikely(dlh == NULL))
                return -ENOMEM;
        rc = __mdd_lookup(env, pobj, lname, fid, mask);
        mdd_pdo_read_unlock(env, mdd_obj, dlh);

        return rc;
}

static int mdd_lookup(const struct lu_env *env,
                      struct md_object *pobj, const struct lu_name *lname,
                      struct lu_fid* fid, struct md_op_spec *spec)
{
        int rc;
        ENTRY;
        rc = __mdd_lookup_locked(env, pobj, lname, fid, MAY_EXEC);
        RETURN(rc);
}


static int mdd_parent_fid(const struct lu_env *env, struct mdd_object *obj,
                          struct lu_fid *fid)
{
        return __mdd_lookup_locked(env, &obj->mod_obj, &lname_dotdot, fid, 0);
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
                /* this is done recursively, bypass capa for each obj */
                mdd_set_capainfo(env, 4, p1, BYPASS_CAPA);
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

/*
 * Check that @dir contains no entries except (possibly) dot and dotdot.
 *
 * Returns:
 *
 *             0        empty
 *      -ENOTDIR        not a directory object
 *    -ENOTEMPTY        not empty
 *           -ve        other error
 *
 */
static int mdd_dir_is_empty(const struct lu_env *env,
                            struct mdd_object *dir)
{
        struct dt_it     *it;
        struct dt_object *obj;
        const struct dt_it_ops *iops;
        int result;
        ENTRY;

        obj = mdd_object_child(dir);
        if (!dt_try_as_dir(env, obj))
                RETURN(-ENOTDIR);

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

static int __mdd_may_link(const struct lu_env *env, struct mdd_object *obj)
{
        struct mdd_device *m = mdd_obj2mdd_dev(obj);
        struct lu_attr *la = &mdd_env_info(env)->mti_la;
        int rc;
        ENTRY;

        rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        /*
         * Subdir count limitation can be broken through.
         */ 
        if (la->la_nlink >= m->mdd_dt_conf.ddp_max_nlink &&
            !S_ISDIR(la->la_mode))
                RETURN(-EMLINK);
        else
                RETURN(0);
}

/*
 * Check whether it may create the cobj under the pobj.
 * cobj maybe NULL
 */
int mdd_may_create(const struct lu_env *env, struct mdd_object *pobj,
                   struct mdd_object *cobj, int check_perm, int check_nlink)
{
        int rc = 0;
        ENTRY;

        if (cobj && mdd_object_exists(cobj))
                RETURN(-EEXIST);

        if (mdd_is_dead_obj(pobj))
                RETURN(-ENOENT);

        if (check_perm)
                rc = mdd_permission_internal_locked(env, pobj, NULL,
                                                    MAY_WRITE | MAY_EXEC,
                                                    MOR_TGT_PARENT);

        if (!rc && check_nlink)
                rc = __mdd_may_link(env, pobj);

        RETURN(rc);
}

/*
 * Check whether can unlink from the pobj in the case of "cobj == NULL".
 */
int mdd_may_unlink(const struct lu_env *env, struct mdd_object *pobj,
                   const struct md_attr *ma)
{
        int rc;
        ENTRY;

        if (mdd_is_dead_obj(pobj))
                RETURN(-ENOENT);

        if ((ma->ma_attr.la_valid & LA_FLAGS) &&
            (ma->ma_attr.la_flags & (LUSTRE_APPEND_FL | LUSTRE_IMMUTABLE_FL)))
                RETURN(-EPERM);

        rc = mdd_permission_internal_locked(env, pobj, NULL,
                                            MAY_WRITE | MAY_EXEC,
                                            MOR_TGT_PARENT);
        if (rc)
                RETURN(rc);

        if (mdd_is_append(pobj))
                RETURN(-EPERM);

        RETURN(rc);
}

/*
 * pobj == NULL is remote ops case, under such case, pobj's
 * VTX feature has been checked already, no need check again.
 */
static inline int mdd_is_sticky(const struct lu_env *env,
                                struct mdd_object *pobj,
                                struct mdd_object *cobj)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc = md_ucred(env);
        int rc;

        if (pobj) {
                rc = mdd_la_get(env, pobj, tmp_la, BYPASS_CAPA);
                if (rc)
                        return rc;
        
                if (!(tmp_la->la_mode & S_ISVTX) ||
                     (tmp_la->la_uid == uc->mu_fsuid))
                        return 0;
        }

        rc = mdd_la_get(env, cobj, tmp_la, BYPASS_CAPA);
        if (rc) 
                return rc;
        
        if (tmp_la->la_uid == uc->mu_fsuid)
                return 0;
        
        return !mdd_capable(uc, CFS_CAP_FOWNER);
}

/*
 * Check whether it may delete the cobj from the pobj.
 * pobj maybe NULL
 */
int mdd_may_delete(const struct lu_env *env, struct mdd_object *pobj,
                   struct mdd_object *cobj, struct md_attr *ma,
                   int check_perm, int check_empty)
{
        int rc = 0;
        ENTRY;

        LASSERT(cobj);
        if (!mdd_object_exists(cobj))
                RETURN(-ENOENT);

        if (pobj) {
                if (mdd_is_dead_obj(pobj))
                        RETURN(-ENOENT);

                if (check_perm) {
                        rc = mdd_permission_internal_locked(env, pobj, NULL,
                                                    MAY_WRITE | MAY_EXEC,
                                                    MOR_TGT_PARENT);
                        if (rc)
                                RETURN(rc);
                }

                if (mdd_is_append(pobj))
                        RETURN(-EPERM);
        }

        if (!(ma->ma_attr_flags & MDS_VTX_BYPASS) &&
            mdd_is_sticky(env, pobj, cobj))
                RETURN(-EPERM);

        if (mdd_is_immutable(cobj) || mdd_is_append(cobj))
                RETURN(-EPERM);

        if ((ma->ma_attr.la_valid & LA_FLAGS) &&
            (ma->ma_attr.la_flags & (LUSTRE_APPEND_FL | LUSTRE_IMMUTABLE_FL)))
                RETURN(-EPERM);

        if (S_ISDIR(ma->ma_attr.la_mode)) {
                struct mdd_device *mdd = mdo2mdd(&cobj->mod_obj);

                if (!S_ISDIR(mdd_object_type(cobj)))
                        RETURN(-ENOTDIR);

                if (lu_fid_eq(mdo2fid(cobj), &mdd->mdd_root_fid))
                        RETURN(-EBUSY);
        } else if (S_ISDIR(mdd_object_type(cobj)))
                RETURN(-EISDIR);

        if (S_ISDIR(ma->ma_attr.la_mode) && check_empty)
                rc = mdd_dir_is_empty(env, cobj);

        RETURN(rc);
}

/*
 * tgt maybe NULL
 * has mdd_write_lock on src already, but not on tgt yet
 */
int mdd_link_sanity_check(const struct lu_env *env,
                          struct mdd_object *tgt_obj,
                          const struct lu_name *lname,
                          struct mdd_object *src_obj)
{
        struct mdd_device *m = mdd_obj2mdd_dev(src_obj);
        int rc = 0;
        ENTRY;

        /* Local ops, no lookup before link, check filename length here. */
        if (lname && (lname->ln_namelen > m->mdd_dt_conf.ddp_max_name_len))
                RETURN(-ENAMETOOLONG);

        if (mdd_is_immutable(src_obj) || mdd_is_append(src_obj))
                RETURN(-EPERM);

        if (S_ISDIR(mdd_object_type(src_obj)))
                RETURN(-EPERM);

        LASSERT(src_obj != tgt_obj);
        if (tgt_obj) {
                rc = mdd_may_create(env, tgt_obj, NULL, 1, 0);
                if (rc)
                        RETURN(rc);
        }

        rc = __mdd_may_link(env, src_obj);

        RETURN(rc);
}

const struct dt_rec *__mdd_fid_rec(const struct lu_env *env,
                                   const struct lu_fid *fid)
{
        struct lu_fid_pack *pack = &mdd_env_info(env)->mti_pack;

        fid_pack(pack, fid, &mdd_env_info(env)->mti_fid2);
        return (const struct dt_rec *)pack;
}

/**
 * If subdir count is up to ddp_max_nlink, then enable MNLINK_OBJ flag and
 * assign i_nlink to 1 which means the i_nlink for subdir count is incredible
 * (maybe too large to be represented). It is a trick to break through the
 * "i_nlink" limitation for subdir count.
 */
void __mdd_ref_add(const struct lu_env *env, struct mdd_object *obj,
                   struct thandle *handle)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        struct mdd_device *m = mdd_obj2mdd_dev(obj);

        if (!mdd_is_mnlink(obj)) {
                if (S_ISDIR(mdd_object_type(obj))) {
                        if (mdd_la_get(env, obj, tmp_la, BYPASS_CAPA))
                                return;

                        if (tmp_la->la_nlink >= m->mdd_dt_conf.ddp_max_nlink) {
                                obj->mod_flags |= MNLINK_OBJ;
                                tmp_la->la_nlink = 1;
                                tmp_la->la_valid = LA_NLINK;
                                mdd_attr_set_internal(env, obj, tmp_la, handle,
                                                      0);
                                return;
                        }
                }
                mdo_ref_add(env, obj, handle);
        }
}

void __mdd_ref_del(const struct lu_env *env, struct mdd_object *obj,
                   struct thandle *handle, int is_dot)
{
        if (!mdd_is_mnlink(obj) || is_dot)
                mdo_ref_del(env, obj, handle);
}

/* insert named index, add reference if isdir */
static int __mdd_index_insert(const struct lu_env *env, struct mdd_object *pobj,
                              const struct lu_fid *lf, const char *name, int is_dir,
                              struct thandle *handle, struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(pobj);
        int               rc;
        ENTRY;

        if (dt_try_as_dir(env, next)) {
                rc = next->do_index_ops->dio_insert(env, next,
                                                    __mdd_fid_rec(env, lf),
                                                    (const struct dt_key *)name,
                                                    handle, capa);
        } else {
                rc = -ENOTDIR;
        }

        if (rc == 0) {
                if (is_dir) {
                        mdd_write_lock(env, pobj, MOR_TGT_PARENT);
                        __mdd_ref_add(env, pobj, handle);
                        mdd_write_unlock(env, pobj);
                }
        }
        RETURN(rc);
}

/* delete named index, drop reference if isdir */
static int __mdd_index_delete(const struct lu_env *env, struct mdd_object *pobj,
                              const char *name, int is_dir, struct thandle *handle,
                              struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(pobj);
        int               rc;
        ENTRY;

        if (dt_try_as_dir(env, next)) {
                rc = next->do_index_ops->dio_delete(env, next,
                                                    (struct dt_key *)name,
                                                    handle, capa);
                if (rc == 0 && is_dir) {
                        int is_dot = 0;

                        if (name != NULL && name[0] == '.' && name[1] == 0)
                                is_dot = 1;
                        mdd_write_lock(env, pobj, MOR_TGT_PARENT);
                        __mdd_ref_del(env, pobj, handle, is_dot);
                        mdd_write_unlock(env, pobj);
                }
        } else
                rc = -ENOTDIR;

        RETURN(rc);
}

static int
__mdd_index_insert_only(const struct lu_env *env, struct mdd_object *pobj,
                        const struct lu_fid *lf, const char *name,
                        struct thandle *handle, struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(pobj);
        int               rc;
        ENTRY;

        if (dt_try_as_dir(env, next)) {
                rc = next->do_index_ops->dio_insert(env, next,
                                                    __mdd_fid_rec(env, lf),
                                                    (const struct dt_key *)name,
                                                    handle, capa);
        } else {
                rc = -ENOTDIR;
        }
        RETURN(rc);
}

static int mdd_link(const struct lu_env *env, struct md_object *tgt_obj,
                    struct md_object *src_obj, const struct lu_name *lname,
                    struct md_attr *ma)
{
        char *name = lname->ln_name;
        struct lu_attr    *la = &mdd_env_info(env)->mti_la_for_fix;
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

        dlh = mdd_pdo_write_lock(env, mdd_tobj, name, MOR_TGT_CHILD);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);
        mdd_write_lock(env, mdd_sobj, MOR_TGT_CHILD);

        rc = mdd_link_sanity_check(env, mdd_tobj, lname, mdd_sobj);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_insert_only(env, mdd_tobj, mdo2fid(mdd_sobj),
                                     name, handle,
                                     mdd_object_capa(env, mdd_tobj));
        if (rc)
                GOTO(out_unlock, rc);

        __mdd_ref_add(env, mdd_sobj, handle);

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);
        la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

        la->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_check_set_internal_locked(env, mdd_tobj, la, handle, 0);
        if (rc)
                GOTO(out_unlock, rc);

        la->la_valid = LA_CTIME;
        rc = mdd_attr_check_set_internal(env, mdd_sobj, la, handle, 0);
        EXIT;
out_unlock:
        mdd_write_unlock(env, mdd_sobj);
        mdd_pdo_write_unlock(env, mdd_tobj, dlh);
out_trans:
        mdd_trans_stop(env, mdd, rc, handle);
        return rc;
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

                obj->mod_flags |= DEAD_OBJ;
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
 * pobj maybe NULL
 * has mdd_write_lock on cobj already, but not on pobj yet
 */
int mdd_unlink_sanity_check(const struct lu_env *env, struct mdd_object *pobj,
                            struct mdd_object *cobj, struct md_attr *ma)
{
        int rc;
        ENTRY;

        rc = mdd_may_delete(env, pobj, cobj, ma, 1, 1);

        RETURN(rc);
}

static int mdd_unlink(const struct lu_env *env, struct md_object *pobj,
                      struct md_object *cobj, const struct lu_name *lname,
                      struct md_attr *ma)
{
        char *name = lname->ln_name;
        struct lu_attr    *la = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object *mdd_cobj = md2mdd_obj(cobj);
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct dynlock_handle *dlh;
        struct thandle    *handle;
        int rc, is_dir;
        ENTRY;

        LASSERTF(mdd_object_exists(mdd_cobj) > 0, "FID is "DFID"\n",
                 PFID(mdd_object_fid(mdd_cobj)));

        rc = mdd_log_txn_param_build(env, cobj, ma, MDD_TXN_UNLINK_OP);
        if (rc)
                RETURN(rc);

        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));


        dlh = mdd_pdo_write_lock(env, mdd_pobj, name, MOR_TGT_PARENT);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);
        mdd_write_lock(env, mdd_cobj, MOR_TGT_CHILD);

        is_dir = S_ISDIR(ma->ma_attr.la_mode);
        rc = mdd_unlink_sanity_check(env, mdd_pobj, mdd_cobj, ma);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_delete(env, mdd_pobj, name, is_dir, handle,
                                mdd_object_capa(env, mdd_pobj));
        if (rc)
                GOTO(cleanup, rc);

        __mdd_ref_del(env, mdd_cobj, handle, 0);
        if (is_dir)
                /* unlink dot */
                __mdd_ref_del(env, mdd_cobj, handle, 1);

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);
        la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

        la->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_check_set_internal_locked(env, mdd_pobj, la, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        la->la_valid = LA_CTIME;
        rc = mdd_attr_check_set_internal(env, mdd_cobj, la, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        rc = mdd_finish_unlink(env, mdd_cobj, ma, handle);

        if (rc == 0)
                obd_set_info_async(mdd2obd_dev(mdd)->u.mds.mds_osc_exp,
                                   sizeof(KEY_UNLINKED), KEY_UNLINKED, 0,
                                   NULL, NULL);
        EXIT;
cleanup:
        mdd_write_unlock(env, mdd_cobj);
        mdd_pdo_write_unlock(env, mdd_pobj, dlh);
out_trans:
        mdd_trans_stop(env, mdd, rc, handle);
        return rc;
}

/* has not lock on pobj yet */
static int mdd_ni_sanity_check(const struct lu_env *env,
                               struct md_object *pobj,
                               const struct md_attr *ma)
{
        struct mdd_object *obj = md2mdd_obj(pobj);
        int rc;
        ENTRY;

        if (ma->ma_attr_flags & MDS_PERM_BYPASS)
                RETURN(0);

        rc = mdd_may_create(env, obj, NULL, 1, S_ISDIR(ma->ma_attr.la_mode));

        RETURN(rc);
}

/*
 * Partial operation.
 */
static int mdd_name_insert(const struct lu_env *env,
                           struct md_object *pobj,
                           const struct lu_name *lname,
                           const struct lu_fid *fid,
                           const struct md_attr *ma)
{
        char *name = lname->ln_name;
        struct lu_attr   *la = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct dynlock_handle *dlh;
        struct thandle *handle;
        int is_dir = S_ISDIR(ma->ma_attr.la_mode);
        int rc;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_INDEX_INSERT_OP);
        handle = mdd_trans_start(env, mdo2mdd(pobj));
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_obj, name, MOR_TGT_PARENT);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);

        rc = mdd_ni_sanity_check(env, pobj, ma);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_insert(env, mdd_obj, fid, name, is_dir,
                                handle, BYPASS_CAPA);
        if (rc)
                GOTO(out_unlock, rc);

        /*
         * For some case, no need update obj's ctime (LA_CTIME is not set),
         * e.g. split_dir.
         * For other cases, update obj's ctime (LA_CTIME is set),
         * e.g. cmr_link.
         */
        if (ma->ma_attr.la_valid & LA_CTIME) {
                la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;
                la->la_valid = LA_CTIME | LA_MTIME;
                rc = mdd_attr_check_set_internal_locked(env, mdd_obj, la,
                                                        handle, 0);
        }
        EXIT;
out_unlock:
        mdd_pdo_write_unlock(env, mdd_obj, dlh);
out_trans:
        mdd_trans_stop(env, mdo2mdd(pobj), rc, handle);
        return rc;
}

/* has not lock on pobj yet */
static int mdd_nr_sanity_check(const struct lu_env *env,
                               struct md_object *pobj,
                               const struct md_attr *ma)
{
        struct mdd_object *obj = md2mdd_obj(pobj);
        int rc;
        ENTRY;

        if (ma->ma_attr_flags & MDS_PERM_BYPASS)
                RETURN(0);

        rc = mdd_may_unlink(env, obj, ma);

        RETURN(rc);
}

/*
 * Partial operation.
 */
static int mdd_name_remove(const struct lu_env *env,
                           struct md_object *pobj,
                           const struct lu_name *lname,
                           const struct md_attr *ma)
{
        char *name = lname->ln_name;
        struct lu_attr    *la = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct dynlock_handle *dlh;
        struct thandle *handle;
        int is_dir = S_ISDIR(ma->ma_attr.la_mode);
        int rc;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_INDEX_DELETE_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_obj, name, MOR_TGT_PARENT);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);

        rc = mdd_nr_sanity_check(env, pobj, ma);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_delete(env, mdd_obj, name, is_dir,
                                handle, BYPASS_CAPA);
        if (rc)
                GOTO(out_unlock, rc);

        /*
         * For some case, no need update obj's ctime (LA_CTIME is not set),
         * e.g. split_dir.
         * For other cases, update obj's ctime (LA_CTIME is set),
         * e.g. cmr_unlink.
         */
        if (ma->ma_attr.la_valid & LA_CTIME) {
                la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;
                la->la_valid = LA_CTIME | LA_MTIME;
                rc = mdd_attr_check_set_internal_locked(env, mdd_obj, la,
                                                        handle, 0);
        }
        EXIT;
out_unlock:
        mdd_pdo_write_unlock(env, mdd_obj, dlh);
out_trans:
        mdd_trans_stop(env, mdd, rc, handle);
        return rc;
}

/*
 * tobj maybe NULL
 * has mdd_write_lock on tobj alreay, but not on tgt_pobj yet
 */
static int mdd_rt_sanity_check(const struct lu_env *env,
                               struct mdd_object *tgt_pobj,
                               struct mdd_object *tobj,
                               struct md_attr *ma)
{
        int rc;
        ENTRY;

        if (unlikely(ma->ma_attr_flags & MDS_PERM_BYPASS))
                RETURN(0);

        /* XXX: for mdd_rename_tgt, "tobj == NULL" does not mean tobj not
         * exist. In fact, tobj must exist, otherwise the call trace will be:
         * mdt_reint_rename_tgt -> mdo_name_insert -> ... -> mdd_name_insert.
         * When get here, tobj must be NOT NULL, the other case has been
         * processed in cmr_rename_tgt before mdd_rename_tgt and enable
         * MDS_PERM_BYPASS.
         * So check may_delete, but not check nlink of tgt_pobj. */
        LASSERT(tobj);
        rc = mdd_may_delete(env, tgt_pobj, tobj, ma, 1, 1);

        RETURN(rc);
}

static int mdd_rename_tgt(const struct lu_env *env,
                          struct md_object *pobj, struct md_object *tobj,
                          const struct lu_fid *lf, const struct lu_name *lname,
                          struct md_attr *ma)
{
        char *name = lname->ln_name;
        struct lu_attr    *la = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_tpobj = md2mdd_obj(pobj);
        struct mdd_object *mdd_tobj = md2mdd_obj(tobj);
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct dynlock_handle *dlh;
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_RENAME_TGT_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_tpobj, name, MOR_TGT_PARENT);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);
        if (tobj)
                mdd_write_lock(env, mdd_tobj, MOR_TGT_CHILD);

        rc = mdd_rt_sanity_check(env, mdd_tpobj, mdd_tobj, ma);
        if (rc)
                GOTO(cleanup, rc);

        /*
         * If rename_tgt is called then we should just re-insert name with
         * correct fid, no need to dec/inc parent nlink if obj is dir.
         */
        rc = __mdd_index_delete(env, mdd_tpobj, name, 0, handle, BYPASS_CAPA);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_insert_only(env, mdd_tpobj, lf, name, handle,
                                     BYPASS_CAPA);
        if (rc)
                GOTO(cleanup, rc);

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);
        la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

        la->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_check_set_internal_locked(env, mdd_tpobj, la, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        /* 
         * For tobj is remote case cmm layer has processed
         * and pass NULL tobj to here. So when tobj is NOT NULL,
         * it must be local one.
         */
        if (tobj && mdd_object_exists(mdd_tobj)) {
                __mdd_ref_del(env, mdd_tobj, handle, 0);

                /* Remove dot reference. */
                if (S_ISDIR(ma->ma_attr.la_mode))
                        __mdd_ref_del(env, mdd_tobj, handle, 1);

                la->la_valid = LA_CTIME;
                rc = mdd_attr_check_set_internal(env, mdd_tobj, la, handle, 0);
                if (rc)
                        GOTO(cleanup, rc);

                rc = mdd_finish_unlink(env, mdd_tobj, ma, handle);
                if (rc)
                        GOTO(cleanup, rc);
        }
        EXIT;
cleanup:
        if (tobj)
                mdd_write_unlock(env, mdd_tobj);
        mdd_pdo_write_unlock(env, mdd_tpobj, dlh);
out_trans:
        mdd_trans_stop(env, mdd, rc, handle);
        return rc;
}

/*
 * The permission has been checked when obj created, no need check again.
 */
static int mdd_cd_sanity_check(const struct lu_env *env,
                               struct mdd_object *obj)
{
        ENTRY;

        /* EEXIST check */
        if (!obj || mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

        RETURN(0);

}

static int mdd_create_data(const struct lu_env *env, struct md_object *pobj,
                           struct md_object *cobj, const struct md_op_spec *spec,
                           struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(cobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
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

        if (!md_should_create(spec->sp_cr_flags))
                RETURN(0);

        rc = mdd_lov_create(env, mdd, mdd_pobj, son, &lmm, &lmm_size,
                            spec, attr);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, mdd, MDD_TXN_CREATE_DATA_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                GOTO(out_free, rc = PTR_ERR(handle));

        /*
         * XXX: Setting the lov ea is not locked but setting the attr is locked?
         * Should this be fixed?
         */

        /* Replay creates has objects already */
#if 0
        if (spec->u.sp_ea.no_lov_create) {
                CDEBUG(D_INFO, "we already have lov ea\n");
                rc = mdd_lov_set_md(env, mdd_pobj, son,
                                    (struct lov_mds_md *)spec->u.sp_ea.eadata,
                                    spec->u.sp_ea.eadatalen, handle, 0);
        } else
#endif
                /* No need mdd_lsm_sanity_check here */
                rc = mdd_lov_set_md(env, mdd_pobj, son, lmm,
                                    lmm_size, handle, 0);

        if (rc == 0)
               rc = mdd_attr_get_internal_locked(env, son, ma);

        /* update lov_objid data, must be before transaction stop! */
        if (rc == 0)
                mdd_lov_objid_update(mdd, lmm);

        mdd_trans_stop(env, mdd, rc, handle);
out_free:
        /* Finish mdd_lov_create() stuff. */
        mdd_lov_create_finish(env, mdd, lmm, lmm_size, spec);
        RETURN(rc);
}

static int
__mdd_lookup(const struct lu_env *env, struct md_object *pobj,
             const struct lu_name *lname, struct lu_fid* fid, int mask)
{
        char                *name = lname->ln_name;
        const struct dt_key *key = (const struct dt_key *)name;
        struct mdd_object   *mdd_obj = md2mdd_obj(pobj);
        struct mdd_device   *m = mdo2mdd(pobj);
        struct dt_object    *dir = mdd_object_child(mdd_obj);
        struct lu_fid_pack  *pack = &mdd_env_info(env)->mti_pack;
        int rc;
        ENTRY;

        if (unlikely(mdd_is_dead_obj(mdd_obj)))
                RETURN(-ESTALE);

        rc = mdd_object_exists(mdd_obj);
        if (unlikely(rc == 0))
                RETURN(-ESTALE);
        else if (unlikely(rc < 0)) {
                CERROR("Object "DFID" locates on remote server\n",
                        PFID(mdo2fid(mdd_obj)));
                LBUG();
        }

        /* The common filename length check. */
        if (unlikely(lname->ln_namelen > m->mdd_dt_conf.ddp_max_name_len))
                RETURN(-ENAMETOOLONG);

        rc = mdd_permission_internal_locked(env, mdd_obj, NULL, mask,
                                            MOR_TGT_PARENT);
        if (rc)
                RETURN(rc);

        if (likely(S_ISDIR(mdd_object_type(mdd_obj)) &&
                   dt_try_as_dir(env, dir))) {
                rc = dir->do_index_ops->dio_lookup(env, dir,
                                                 (struct dt_rec *)pack, key,
                                                 mdd_object_capa(env, mdd_obj));
                if (rc == 0)
                        rc = fid_unpack(pack, fid);
        } else
                rc = -ENOTDIR;

        RETURN(rc);
}

int mdd_object_initialize(const struct lu_env *env, const struct lu_fid *pfid,
                          struct mdd_object *child, struct md_attr *ma,
                          struct thandle *handle)
{
        int rc;
        ENTRY;

        /*
         * Update attributes for child.
         *
         * FIXME:
         *  (1) the valid bits should be converted between Lustre and Linux;
         *  (2) maybe, the child attributes should be set in OSD when creation.
         */

        rc = mdd_attr_set_internal(env, child, &ma->ma_attr, handle, 0);
        if (rc != 0)
                RETURN(rc);

        if (S_ISDIR(ma->ma_attr.la_mode)) {
                /* Add "." and ".." for newly created dir */
                __mdd_ref_add(env, child, handle);
                rc = __mdd_index_insert_only(env, child, mdo2fid(child),
                                             dot, handle, BYPASS_CAPA);
                if (rc == 0) {
                        rc = __mdd_index_insert_only(env, child, pfid,
                                                     dotdot, handle,
                                                     BYPASS_CAPA);
                        if (rc != 0) {
                                int rc2;

                                rc2 = __mdd_index_delete(env, child, dot, 1,
                                                         handle, BYPASS_CAPA);
                                if (rc2 != 0)
                                        CERROR("Failure to cleanup after dotdot"
                                               " creation: %d (%d)\n", rc2, rc);
                        }
                }
        }
        RETURN(rc);
}

/* has not lock on pobj yet */
static int mdd_create_sanity_check(const struct lu_env *env,
                                   struct md_object *pobj,
                                   const struct lu_name *lname,
                                   struct md_attr *ma,
                                   struct md_op_spec *spec)
{
        struct mdd_thread_info *info = mdd_env_info(env);
        struct lu_attr    *la        = &info->mti_la;
        struct lu_fid     *fid       = &info->mti_fid;
        struct mdd_object *obj       = md2mdd_obj(pobj);
        struct mdd_device *m         = mdo2mdd(pobj);
        int lookup                   = spec->sp_cr_lookup;
        int rc;
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

        /*
         * In some cases this lookup is not needed - we know before if name
         * exists or not because MDT performs lookup for it.
         * name length check is done in lookup.
         */
        if (lookup) {
                /*
                 * Check if the name already exist, though it will be checked in
                 * _index_insert also, for avoiding rolling back if exists
                 * _index_insert.
                 */
                rc = __mdd_lookup_locked(env, pobj, lname, fid,
                                         MAY_WRITE | MAY_EXEC);
                if (rc != -ENOENT)
                        RETURN(rc ? : -EEXIST);
        } else {
                /*
                 * Check WRITE permission for the parent.
                 * EXEC permission have been checked
                 * when lookup before create already.
                 */
                rc = mdd_permission_internal_locked(env, obj, NULL, MAY_WRITE,
                                                    MOR_TGT_PARENT);
                if (rc)
                        RETURN(rc);
        }

        /* sgid check */
        rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
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
        case S_IFLNK: {
                unsigned int symlen = strlen(spec->u.sp_symname) + 1;

                if (symlen > (1 << m->mdd_dt_conf.ddp_block_shift))
                        RETURN(-ENAMETOOLONG);
                else
                        RETURN(0);
        }
        case S_IFDIR:
        case S_IFREG:
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
                      struct md_object *pobj,
                      const struct lu_name *lname,
                      struct md_object *child,
                      struct md_op_spec *spec,
                      struct md_attr* ma)
{
        struct mdd_thread_info *info = mdd_env_info(env);
        struct lu_attr         *la = &info->mti_la_for_fix;
        struct md_attr         *ma_acl = &info->mti_ma;
        struct mdd_object      *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object      *son = md2mdd_obj(child);
        struct mdd_device      *mdd = mdo2mdd(pobj);
        struct lu_attr         *attr = &ma->ma_attr;
        struct lov_mds_md      *lmm = NULL;
        struct thandle         *handle;
        struct dynlock_handle  *dlh;
        char                   *name = lname->ln_name;
        int rc, created = 0, initialized = 0, inserted = 0, lmm_size = 0;
        int got_def_acl = 0;
        ENTRY;

        /*
         * Two operations have to be performed:
         *
         *  - an allocation of a new object (->do_create()), and
         *
         *  - an insertion into a parent index (->dio_insert()).
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

        /* Sanity checks before big job. */
        rc = mdd_create_sanity_check(env, pobj, lname, ma, spec);
        if (rc)
                RETURN(rc);

        /*
         * No RPC inside the transaction, so OST objects should be created at
         * first.
         */
        if (S_ISREG(attr->la_mode)) {
                rc = mdd_lov_create(env, mdd, mdd_pobj, son, &lmm, &lmm_size,
                                    spec, attr);
                if (rc)
                        RETURN(rc);
        }

        if (!S_ISLNK(attr->la_mode)) {
                ma_acl->ma_acl_size = sizeof info->mti_xattr_buf;
                ma_acl->ma_acl = info->mti_xattr_buf;
                ma_acl->ma_need = MA_ACL_DEF;
                ma_acl->ma_valid = 0;

                mdd_read_lock(env, mdd_pobj, MOR_TGT_PARENT);
                rc = mdd_def_acl_get(env, mdd_pobj, ma_acl);
                mdd_read_unlock(env, mdd_pobj);
                if (rc)
                        GOTO(out_free, rc);
                else if (ma_acl->ma_valid & MA_ACL_DEF)
                        got_def_acl = 1;
        }

        mdd_txn_param_build(env, mdd, MDD_TXN_MKDIR_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                GOTO(out_free, rc = PTR_ERR(handle));

        dlh = mdd_pdo_write_lock(env, mdd_pobj, name, MOR_TGT_PARENT);
        if (dlh == NULL)
                GOTO(out_trans, rc = -ENOMEM);

        mdd_write_lock(env, son, MOR_TGT_CHILD);
        rc = mdd_object_create_internal(env, mdd_pobj, son, ma, handle);
        if (rc) {
                mdd_write_unlock(env, son);
                GOTO(cleanup, rc);
        }

        created = 1;

#ifdef CONFIG_FS_POSIX_ACL
        if (got_def_acl) {
                struct lu_buf *acl_buf = &info->mti_buf;
                acl_buf->lb_buf = ma_acl->ma_acl;
                acl_buf->lb_len = ma_acl->ma_acl_size;

                rc = __mdd_acl_init(env, son, acl_buf, &attr->la_mode, handle);
                if (rc) {
                        mdd_write_unlock(env, son);
                        GOTO(cleanup, rc);
                } else {
                        ma->ma_attr.la_valid |= LA_MODE;
                }
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

        initialized = 1;

        rc = __mdd_index_insert(env, mdd_pobj, mdo2fid(son),
                                name, S_ISDIR(attr->la_mode), handle,
                                mdd_object_capa(env, mdd_pobj));

        if (rc)
                GOTO(cleanup, rc);

        inserted = 1;

        /* No need mdd_lsm_sanity_check here */
        rc = mdd_lov_set_md(env, mdd_pobj, son, lmm, lmm_size, handle, 0);
        if (rc) {
                CERROR("error on stripe info copy %d \n", rc);
                GOTO(cleanup, rc);
        }
        if (lmm && lmm_size > 0) {
                /* Set Lov here, do not get lmm again later */
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
                        GOTO(cleanup, rc = -EFAULT);
        }

        *la = ma->ma_attr;
        la->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_check_set_internal_locked(env, mdd_pobj, la, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        /* Return attr back. */
        rc = mdd_attr_get_internal_locked(env, son, ma);
        EXIT;
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
                        mdd_write_lock(env, son, MOR_TGT_CHILD);
                        __mdd_ref_del(env, son, handle, 0);
                        if (initialized && S_ISDIR(attr->la_mode))
                                __mdd_ref_del(env, son, handle, 1);
                        mdd_write_unlock(env, son);
                }
        }

        /* update lov_objid data, must be before transaction stop! */
        if (rc == 0)
                mdd_lov_objid_update(mdd, lmm);

        mdd_pdo_write_unlock(env, mdd_pobj, dlh);
out_trans:
        mdd_trans_stop(env, mdd, rc, handle);
out_free:
        /* finis lov_create stuff, free all temporary data */
        mdd_lov_create_finish(env, mdd, lmm, lmm_size, spec);
        return rc;
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

/* has not mdd_write{read}_lock on any obj yet. */
static int mdd_rename_sanity_check(const struct lu_env *env,
                                   struct mdd_object *src_pobj,
                                   struct mdd_object *tgt_pobj,
                                   struct mdd_object *sobj,
                                   struct mdd_object *tobj,
                                   struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        if (unlikely(ma->ma_attr_flags & MDS_PERM_BYPASS))
                RETURN(0);

        /* XXX: when get here, sobj must NOT be NULL,
         * the other case has been processed in cml_rename
         * before mdd_rename and enable MDS_PERM_BYPASS. */
        LASSERT(sobj);
        rc = mdd_may_delete(env, src_pobj, sobj, ma, 1, 0);
        if (rc)
                RETURN(rc);

        /* XXX: when get here, "tobj == NULL" means tobj must
         * NOT exist (neither on remote MDS, such case has been
         * processed in cml_rename before mdd_rename and enable
         * MDS_PERM_BYPASS).
         * So check may_create, but not check may_unlink. */
        if (!tobj)
                rc = mdd_may_create(env, tgt_pobj, NULL,
                                    (src_pobj != tgt_pobj), 0);
        else
                rc = mdd_may_delete(env, tgt_pobj, tobj, ma,
                                    (src_pobj != tgt_pobj), 1);

        if (!rc && !tobj && (src_pobj != tgt_pobj) &&
            S_ISDIR(ma->ma_attr.la_mode))
                rc = __mdd_may_link(env, tgt_pobj);

        RETURN(rc);
}

/* src object can be remote that is why we use only fid and type of object */
static int mdd_rename(const struct lu_env *env,
                      struct md_object *src_pobj, struct md_object *tgt_pobj,
                      const struct lu_fid *lf, const struct lu_name *lsname,
                      struct md_object *tobj, const struct lu_name *ltname,
                      struct md_attr *ma)
{
        char *sname = lsname->ln_name;
        char *tname = ltname->ln_name;
        struct lu_attr    *la = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_spobj = md2mdd_obj(src_pobj);
        struct mdd_object *mdd_tpobj = md2mdd_obj(tgt_pobj);
        struct mdd_device *mdd = mdo2mdd(src_pobj);
        struct mdd_object *mdd_sobj = NULL;
        struct mdd_object *mdd_tobj = NULL;
        struct dynlock_handle *sdlh, *tdlh;
        struct thandle *handle;
        int is_dir;
        int rc;
        ENTRY;

        LASSERT(ma->ma_attr.la_mode & S_IFMT);
        is_dir = S_ISDIR(ma->ma_attr.la_mode);

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

        /* Get locks in determined order */
        if (rc == MDD_RN_SAME) {
                sdlh = mdd_pdo_write_lock(env, mdd_spobj,
                                          sname, MOR_SRC_PARENT);
                /* check hashes to determine do we need one lock or two */
                if (mdd_name2hash(sname) != mdd_name2hash(tname))
                        tdlh = mdd_pdo_write_lock(env, mdd_tpobj, tname,
                                MOR_TGT_PARENT);
                else
                        tdlh = sdlh;
        } else if (rc == MDD_RN_SRCTGT) {
                sdlh = mdd_pdo_write_lock(env, mdd_spobj, sname,MOR_SRC_PARENT);
                tdlh = mdd_pdo_write_lock(env, mdd_tpobj, tname,MOR_TGT_PARENT);
        } else {
                tdlh = mdd_pdo_write_lock(env, mdd_tpobj, tname,MOR_SRC_PARENT);
                sdlh = mdd_pdo_write_lock(env, mdd_spobj, sname,MOR_TGT_PARENT);
        }
        if (sdlh == NULL || tdlh == NULL)
                GOTO(cleanup, rc = -ENOMEM);

        mdd_sobj = mdd_object_find(env, mdd, lf);
        rc = mdd_rename_sanity_check(env, mdd_spobj, mdd_tpobj,
                                     mdd_sobj, mdd_tobj, ma);
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

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);
        la->la_ctime = la->la_mtime = ma->ma_attr.la_ctime;

        /* XXX: mdd_sobj must be local one if it is NOT NULL. */
        if (mdd_sobj) {
                la->la_valid = LA_CTIME;
                rc = mdd_attr_check_set_internal_locked(env, mdd_sobj, la,
                                                        handle, 0);
                if (rc)
                        GOTO(cleanup, rc);
        }

        /* 
         * For tobj is remote case cmm layer has processed
         * and set tobj to NULL then. So when tobj is NOT NULL,
         * it must be local one.
         */
        if (tobj && mdd_object_exists(mdd_tobj)) {
                mdd_write_lock(env, mdd_tobj, MOR_TGT_CHILD);
                __mdd_ref_del(env, mdd_tobj, handle, 0);

                /* Remove dot reference. */
                if (is_dir)
                        __mdd_ref_del(env, mdd_tobj, handle, 1);

                la->la_valid = LA_CTIME;
                rc = mdd_attr_check_set_internal(env, mdd_tobj, la, handle, 0);
                if (rc)
                        GOTO(cleanup, rc);

                rc = mdd_finish_unlink(env, mdd_tobj, ma, handle);
                mdd_write_unlock(env, mdd_tobj);
                if (rc)
                        GOTO(cleanup, rc);
        }

        la->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_check_set_internal_locked(env, mdd_spobj, la, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        if (mdd_spobj != mdd_tpobj) {
                la->la_valid = LA_CTIME | LA_MTIME;
                rc = mdd_attr_check_set_internal_locked(env, mdd_tpobj, la,
                                                  handle, 0);
        }

        EXIT;
cleanup:
        if (likely(tdlh) && sdlh != tdlh)
                mdd_pdo_write_unlock(env, mdd_tpobj, tdlh);
        if (likely(sdlh))
                mdd_pdo_write_unlock(env, mdd_spobj, sdlh);
cleanup_unlocked:
        mdd_trans_stop(env, mdd, rc, handle);
        if (mdd_sobj)
                mdd_object_put(env, mdd_sobj);
        return rc;
}

const struct md_dir_operations mdd_dir_ops = {
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
