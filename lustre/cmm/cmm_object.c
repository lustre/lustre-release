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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/cmm/cmm_object.c
 *
 * Lustre Cluster Metadata Manager (cmm)
 *
 * Author: Mike Pershin <tappro@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_MDS

#include <lustre_fid.h>
#include "cmm_internal.h"
#include "mdc_internal.h"
/**
 * \ingroup cmm
 * Lookup MDS number \a mds by FID \a fid.
 *
 * \param fid FID of object to find MDS
 * \param mds mds number to return.
 */
int cmm_fld_lookup(struct cmm_device *cm, const struct lu_fid *fid,
                   mdsno_t *mds, const struct lu_env *env)
{
        int rc = 0;
        ENTRY;

        LASSERT(fid_is_sane(fid));

        rc = fld_client_lookup(cm->cmm_fld, fid_seq(fid), mds,
                               LU_SEQ_RANGE_MDT, env);
        if (rc) {
                CERROR("Can't find mds by seq "LPX64", rc %d\n",
                       fid_seq(fid), rc);
                RETURN(rc);
        }

        if (*mds > cm->cmm_tgt_count) {
                CERROR("Got invalid mdsno: %x (max: %x)\n",
                       *mds, cm->cmm_tgt_count);
                rc = -EINVAL;
        } else {
                CDEBUG(D_INFO, "CMM: got MDS %x for sequence: "
                       LPX64"\n", *mds, fid_seq(fid));
        }

        RETURN (rc);
}

/**
 * \addtogroup cml
 * @{
 */
static const struct md_object_operations cml_mo_ops;
static const struct md_dir_operations    cml_dir_ops;
static const struct lu_object_operations cml_obj_ops;

static const struct md_object_operations cmr_mo_ops;
static const struct md_dir_operations    cmr_dir_ops;
static const struct lu_object_operations cmr_obj_ops;

/**
 * \ingroup cmm
 * Allocate CMM object.
 */
struct lu_object *cmm_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *loh,
                                   struct lu_device *ld)
{
        const struct lu_fid *fid = &loh->loh_fid;
        struct lu_object  *lo = NULL;
        struct cmm_device *cd;
        mdsno_t mds;
        int rc = 0;

        ENTRY;

        cd = lu2cmm_dev(ld);
        if (cd->cmm_flags & CMM_INITIALIZED) {
                /* get object location */
                rc = cmm_fld_lookup(lu2cmm_dev(ld), fid, &mds, env);
                if (rc)
                        RETURN(NULL);
        } else
                /*
                 * Device is not yet initialized, cmm_object is being created
                 * as part of early bootstrap procedure (it is /ROOT, or /fld,
                 * etc.). Such object *has* to be local.
                 */
                mds = cd->cmm_local_num;

        /* select the proper set of operations based on object location */
        if (mds == cd->cmm_local_num) {
                struct cml_object *clo;

                OBD_ALLOC_PTR(clo);
                if (clo != NULL) {
                        lo = &clo->cmm_obj.cmo_obj.mo_lu;
                        lu_object_init(lo, NULL, ld);
                        clo->cmm_obj.cmo_obj.mo_ops = &cml_mo_ops;
                        clo->cmm_obj.cmo_obj.mo_dir_ops = &cml_dir_ops;
                        lo->lo_ops = &cml_obj_ops;
                }
        } else {
                struct cmr_object *cro;

                OBD_ALLOC_PTR(cro);
                if (cro != NULL) {
                        lo = &cro->cmm_obj.cmo_obj.mo_lu;
                        lu_object_init(lo, NULL, ld);
                        cro->cmm_obj.cmo_obj.mo_ops = &cmr_mo_ops;
                        cro->cmm_obj.cmo_obj.mo_dir_ops = &cmr_dir_ops;
                        lo->lo_ops = &cmr_obj_ops;
                        cro->cmo_num = mds;
                }
        }
        RETURN(lo);
}

/**
 * Get local child device.
 */
static struct lu_device *cml_child_dev(struct cmm_device *d)
{
        return &d->cmm_child->md_lu_dev;
}

/**
 * Free cml_object.
 */
static void cml_object_free(const struct lu_env *env,
                            struct lu_object *lo)
{
        struct cml_object *clo = lu2cml_obj(lo);
        lu_object_fini(lo);
        OBD_FREE_PTR(clo);
}

/**
 * Initialize cml_object.
 */
static int cml_object_init(const struct lu_env *env, struct lu_object *lo,
                           const struct lu_object_conf *unused)
{
        struct cmm_device *cd = lu2cmm_dev(lo->lo_dev);
        struct lu_device  *c_dev;
        struct lu_object  *c_obj;
        int rc;

        ENTRY;

#ifdef HAVE_SPLIT_SUPPORT
        if (cd->cmm_tgt_count == 0)
                lu2cml_obj(lo)->clo_split = CMM_SPLIT_DENIED;
        else
                lu2cml_obj(lo)->clo_split = CMM_SPLIT_UNKNOWN;
#endif
        c_dev = cml_child_dev(cd);
        if (c_dev == NULL) {
                rc = -ENOENT;
        } else {
                c_obj = c_dev->ld_ops->ldo_object_alloc(env,
                                                        lo->lo_header, c_dev);
                if (c_obj != NULL) {
                        lu_object_add(lo, c_obj);
                        rc = 0;
                } else {
                        rc = -ENOMEM;
                }
        }

        RETURN(rc);
}

static int cml_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *lo)
{
        return (*p)(env, cookie, "[local]");
}

static const struct lu_object_operations cml_obj_ops = {
        .loo_object_init    = cml_object_init,
        .loo_object_free    = cml_object_free,
        .loo_object_print   = cml_object_print
};

/**
 * \name CMM local md_object operations.
 * All of them call just corresponding operations on next layer.
 * @{
 */
static int cml_object_create(const struct lu_env *env,
                             struct md_object *mo,
                             const struct md_op_spec *spec,
                             struct md_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_object_create(env, md_object_next(mo), spec, attr);
        RETURN(rc);
}

static int cml_permission(const struct lu_env *env,
                          struct md_object *p, struct md_object *c,
                          struct md_attr *attr, int mask)
{
        int rc;
        ENTRY;
        rc = mo_permission(env, md_object_next(p), md_object_next(c),
                           attr, mask);
        RETURN(rc);
}

static int cml_attr_get(const struct lu_env *env, struct md_object *mo,
                        struct md_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_attr_get(env, md_object_next(mo), attr);
        RETURN(rc);
}

static int cml_attr_set(const struct lu_env *env, struct md_object *mo,
                        const struct md_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_attr_set(env, md_object_next(mo), attr);
        RETURN(rc);
}

static int cml_xattr_get(const struct lu_env *env, struct md_object *mo,
                         struct lu_buf *buf, const char *name)
{
        int rc;
        ENTRY;
        rc = mo_xattr_get(env, md_object_next(mo), buf, name);
        RETURN(rc);
}

static int cml_readlink(const struct lu_env *env, struct md_object *mo,
                        struct lu_buf *buf)
{
        int rc;
        ENTRY;
        rc = mo_readlink(env, md_object_next(mo), buf);
        RETURN(rc);
}

static int cml_changelog(const struct lu_env *env, enum changelog_rec_type type,
                         int flags, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_changelog(env, type, flags, md_object_next(mo));
        RETURN(rc);
}

static int cml_xattr_list(const struct lu_env *env, struct md_object *mo,
                          struct lu_buf *buf)
{
        int rc;
        ENTRY;
        rc = mo_xattr_list(env, md_object_next(mo), buf);
        RETURN(rc);
}

static int cml_xattr_set(const struct lu_env *env, struct md_object *mo,
                         const struct lu_buf *buf, const char *name,
                         int fl)
{
        int rc;
        ENTRY;
        rc = mo_xattr_set(env, md_object_next(mo), buf, name, fl);
        RETURN(rc);
}

static int cml_xattr_del(const struct lu_env *env, struct md_object *mo,
                         const char *name)
{
        int rc;
        ENTRY;
        rc = mo_xattr_del(env, md_object_next(mo), name);
        RETURN(rc);
}

static int cml_ref_add(const struct lu_env *env, struct md_object *mo,
                       const struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mo_ref_add(env, md_object_next(mo), ma);
        RETURN(rc);
}

static int cml_ref_del(const struct lu_env *env, struct md_object *mo,
                       struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mo_ref_del(env, md_object_next(mo), ma);
        RETURN(rc);
}

static int cml_open(const struct lu_env *env, struct md_object *mo,
                    int flags)
{
        int rc;
        ENTRY;
        rc = mo_open(env, md_object_next(mo), flags);
        RETURN(rc);
}

static int cml_close(const struct lu_env *env, struct md_object *mo,
                     struct md_attr *ma, int mode)
{
        int rc;
        ENTRY;
        rc = mo_close(env, md_object_next(mo), ma, mode);
        RETURN(rc);
}

static int cml_readpage(const struct lu_env *env, struct md_object *mo,
                        const struct lu_rdpg *rdpg)
{
        int rc;
        ENTRY;
        rc = mo_readpage(env, md_object_next(mo), rdpg);
        RETURN(rc);
}

static int cml_capa_get(const struct lu_env *env, struct md_object *mo,
                        struct lustre_capa *capa, int renewal)
{
        int rc;
        ENTRY;
        rc = mo_capa_get(env, md_object_next(mo), capa, renewal);
        RETURN(rc);
}

static int cml_path(const struct lu_env *env, struct md_object *mo,
                    char *path, int pathlen, __u64 *recno, int *linkno)
{
        int rc;
        ENTRY;
        rc = mo_path(env, md_object_next(mo), path, pathlen, recno, linkno);
        RETURN(rc);
}

static int cml_file_lock(const struct lu_env *env, struct md_object *mo,
                         struct lov_mds_md *lmm, struct ldlm_extent *extent,
                         struct lustre_handle *lockh)
{
        int rc;
        ENTRY;
        rc = mo_file_lock(env, md_object_next(mo), lmm, extent, lockh);
        RETURN(rc);
}

static int cml_file_unlock(const struct lu_env *env, struct md_object *mo,
                           struct lov_mds_md *lmm, struct lustre_handle *lockh)
{
        int rc;
        ENTRY;
        rc = mo_file_unlock(env, md_object_next(mo), lmm, lockh);
        RETURN(rc);
}

static int cml_object_sync(const struct lu_env *env, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_object_sync(env, md_object_next(mo));
        RETURN(rc);
}

static dt_obj_version_t cml_version_get(const struct lu_env *env,
                                        struct md_object *mo)
{
        return mo_version_get(env, md_object_next(mo));
}

static void cml_version_set(const struct lu_env *env, struct md_object *mo,
                            dt_obj_version_t version)
{
        return mo_version_set(env, md_object_next(mo), version);
}

static const struct md_object_operations cml_mo_ops = {
        .moo_permission    = cml_permission,
        .moo_attr_get      = cml_attr_get,
        .moo_attr_set      = cml_attr_set,
        .moo_xattr_get     = cml_xattr_get,
        .moo_xattr_list    = cml_xattr_list,
        .moo_xattr_set     = cml_xattr_set,
        .moo_xattr_del     = cml_xattr_del,
        .moo_object_create = cml_object_create,
        .moo_ref_add       = cml_ref_add,
        .moo_ref_del       = cml_ref_del,
        .moo_open          = cml_open,
        .moo_close         = cml_close,
        .moo_readpage      = cml_readpage,
        .moo_readlink      = cml_readlink,
        .moo_changelog     = cml_changelog,
        .moo_capa_get      = cml_capa_get,
        .moo_object_sync   = cml_object_sync,
        .moo_version_get   = cml_version_get,
        .moo_version_set   = cml_version_set,
        .moo_path          = cml_path,
        .moo_file_lock     = cml_file_lock,
        .moo_file_unlock   = cml_file_unlock,
};
/** @} */

/**
 * \name CMM local md_dir_operations.
 * @{
 */
/**
 * cml lookup object fid by name.
 * This returns only FID by name.
 */
static int cml_lookup(const struct lu_env *env, struct md_object *mo_p,
                      const struct lu_name *lname, struct lu_fid *lf,
                      struct md_op_spec *spec)
{
        int rc;
        ENTRY;

#ifdef HAVE_SPLIT_SUPPORT
        if (spec != NULL && spec->sp_ck_split) {
                rc = cmm_split_check(env, mo_p, lname->ln_name);
                if (rc)
                        RETURN(rc);
        }
#endif
        rc = mdo_lookup(env, md_object_next(mo_p), lname, lf, spec);
        RETURN(rc);

}

/**
 * Helper to return lock mode. Used in split cases only.
 */
static mdl_mode_t cml_lock_mode(const struct lu_env *env,
                                struct md_object *mo, mdl_mode_t lm)
{
        int rc = MDL_MINMODE;
        ENTRY;

#ifdef HAVE_SPLIT_SUPPORT
        rc = cmm_split_access(env, mo, lm);
#endif

        RETURN(rc);
}

/**
 * Create operation for cml.
 * Objects are local, but split can happen.
 * If split is not needed this will call next layer mdo_create().
 *
 * \param mo_p Parent directory. Local object.
 * \param lname name of file to create.
 * \param mo_c Child object. It has no real inode yet.
 * \param spec creation specification.
 * \param ma child object attributes.
 */
static int cml_create(const struct lu_env *env, struct md_object *mo_p,
                      const struct lu_name *lname, struct md_object *mo_c,
                      struct md_op_spec *spec, struct md_attr *ma)
{
        int rc;
        ENTRY;

#ifdef HAVE_SPLIT_SUPPORT
        /* Lock mode always should be sane. */
        LASSERT(spec->sp_cr_mode != MDL_MINMODE);

        /*
         * Sigh... This is long story. MDT may have race with detecting if split
         * is possible in cmm. We know this race and let it live, because
         * getting it rid (with some sem or spinlock) will also mean that
         * PDIROPS for create will not work because we kill parallel work, what
         * is really bad for performance and makes no sense having PDIROPS. So,
         * we better allow the race to live, but split dir only if some of
         * concurrent threads takes EX lock, not matter which one. So that, say,
         * two concurrent threads may have different lock modes on directory (CW
         * and EX) and not first one which comes here and see that split is
         * possible should split the dir, but only that one which has EX
         * lock. And we do not care that in this case, split may happen a bit
         * later (when dir size will not be necessarily 64K, but may be a bit
         * larger). So that, we allow concurrent creates and protect split by EX
         * lock.
         */
        if (spec->sp_cr_mode == MDL_EX) {
                /**
                 * Split cases:
                 * - Try to split \a mo_p upon each create operation.
                 *   If split is ok, -ERESTART is returned and current thread
                 *   will not peoceed with create. Instead it sends -ERESTART
                 *   to client to let it know that correct MDT must be chosen.
                 * \see cmm_split_dir()
                 */
                rc = cmm_split_dir(env, mo_p);
                if (rc)
                        /*
                         * -ERESTART or some split error is returned, we can't
                         * proceed with create.
                         */
                        GOTO(out, rc);
        }

        if (spec != NULL && spec->sp_ck_split) {
                /**
                 * - Directory is split already. Let the caller know that
                 * it should tell client that directory is split and operation
                 * should repeat to correct MDT.
                 * \see cmm_split_check()
                 */
                rc = cmm_split_check(env, mo_p, lname->ln_name);
                if (rc)
                        GOTO(out, rc);
        }
#endif

        rc = mdo_create(env, md_object_next(mo_p), lname, md_object_next(mo_c),
                        spec, ma);

        EXIT;
#ifdef HAVE_SPLIT_SUPPORT
out:
#endif
        return rc;
}

/** Call mdo_create_data() on next layer. All objects are local. */
static int cml_create_data(const struct lu_env *env, struct md_object *p,
                           struct md_object *o,
                           const struct md_op_spec *spec,
                           struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mdo_create_data(env, md_object_next(p), md_object_next(o),
                             spec, ma);
        RETURN(rc);
}

/** Call mdo_link() on next layer. All objects are local. */
static int cml_link(const struct lu_env *env, struct md_object *mo_p,
                    struct md_object *mo_s, const struct lu_name *lname,
                    struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mdo_link(env, md_object_next(mo_p), md_object_next(mo_s),
                      lname, ma);
        RETURN(rc);
}

/** Call mdo_unlink() on next layer. All objects are local. */
static int cml_unlink(const struct lu_env *env, struct md_object *mo_p,
                      struct md_object *mo_c, const struct lu_name *lname,
                      struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mdo_unlink(env, md_object_next(mo_p), md_object_next(mo_c),
                        lname, ma);
        RETURN(rc);
}

/**
 * \ingroup cmm
 * Get mode of object.
 * Used in both cml and cmr hence can produce RPC to another server.
 */
static int cmm_mode_get(const struct lu_env *env, struct md_device *md,
                        const struct lu_fid *lf, struct md_attr *ma,
                        int *remote)
{
        struct md_object *mo_s = md_object_find_slice(env, md, lf);
        struct cmm_thread_info *cmi;
        struct md_attr *tmp_ma;
        int rc;
        ENTRY;

        if (IS_ERR(mo_s))
                RETURN(PTR_ERR(mo_s));

        if (remote && (lu_object_exists(&mo_s->mo_lu) < 0))
                *remote = 1;

        cmi = cmm_env_info(env);
        tmp_ma = &cmi->cmi_ma;
        tmp_ma->ma_need = MA_INODE;
        tmp_ma->ma_valid = 0;
        /* get type from src, can be remote req */
        rc = mo_attr_get(env, md_object_next(mo_s), tmp_ma);
        if (rc == 0) {
                ma->ma_attr.la_mode = tmp_ma->ma_attr.la_mode;
                ma->ma_attr.la_uid = tmp_ma->ma_attr.la_uid;
                ma->ma_attr.la_gid = tmp_ma->ma_attr.la_gid;
                ma->ma_attr.la_flags = tmp_ma->ma_attr.la_flags;
                ma->ma_attr.la_valid |= LA_MODE | LA_UID | LA_GID | LA_FLAGS;
        }
        lu_object_put(env, &mo_s->mo_lu);
        RETURN(rc);
}

/**
 * \ingroup cmm
 * Set ctime for object.
 * Used in both cml and cmr hence can produce RPC to another server.
 */
static int cmm_rename_ctime(const struct lu_env *env, struct md_device *md,
                            const struct lu_fid *lf, struct md_attr *ma)
{
        struct md_object *mo_s = md_object_find_slice(env, md, lf);
        int rc;
        ENTRY;

        if (IS_ERR(mo_s))
                RETURN(PTR_ERR(mo_s));

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);
        /* set ctime to obj, can be remote req */
        rc = mo_attr_set(env, md_object_next(mo_s), ma);
        lu_object_put(env, &mo_s->mo_lu);
        RETURN(rc);
}

/** Helper to output debug information about rename operation. */
static inline void cml_rename_warn(const char *fname,
                                  struct md_object *mo_po,
                                  struct md_object *mo_pn,
                                  const struct lu_fid *lf,
                                  const char *s_name,
                                  struct md_object *mo_t,
                                  const char *t_name,
                                  int err)
{
        if (mo_t)
                CWARN("cml_rename failed for %s, should revoke: [mo_po "DFID"] "
                      "[mo_pn "DFID"] [lf "DFID"] [sname %s] [mo_t "DFID"] "
                      "[tname %s] [err %d]\n", fname,
                      PFID(lu_object_fid(&mo_po->mo_lu)),
                      PFID(lu_object_fid(&mo_pn->mo_lu)),
                      PFID(lf), s_name,
                      PFID(lu_object_fid(&mo_t->mo_lu)),
                      t_name, err);
        else
                CWARN("cml_rename failed for %s, should revoke: [mo_po "DFID"] "
                      "[mo_pn "DFID"] [lf "DFID"] [sname %s] [mo_t NULL] "
                      "[tname %s] [err %d]\n", fname,
                      PFID(lu_object_fid(&mo_po->mo_lu)),
                      PFID(lu_object_fid(&mo_pn->mo_lu)),
                      PFID(lf), s_name,
                      t_name, err);
}

/**
 * Rename operation for cml.
 *
 * This is the most complex cross-reference operation. It may consist of up to 4
 * MDS server and require several RPCs to be sent.
 *
 * \param mo_po Old parent object.
 * \param mo_pn New parent object.
 * \param lf FID of object to rename.
 * \param ls_name Source file name.
 * \param mo_t target object. Should be NULL here.
 * \param lt_name Name of target file.
 * \param ma object attributes.
 */
static int cml_rename(const struct lu_env *env, struct md_object *mo_po,
                      struct md_object *mo_pn, const struct lu_fid *lf,
                      const struct lu_name *ls_name, struct md_object *mo_t,
                      const struct lu_name *lt_name, struct md_attr *ma)
{
        struct cmm_thread_info *cmi;
        struct md_attr *tmp_ma = NULL;
        struct md_object *tmp_t = mo_t;
        int remote = 0, rc;
        ENTRY;

        rc = cmm_mode_get(env, md_obj2dev(mo_po), lf, ma, &remote);
        if (rc)
                RETURN(rc);

        if (mo_t && lu_object_exists(&mo_t->mo_lu) < 0) {
                /**
                 * \note \a mo_t is remote object and there is RPC to unlink it.
                 * Before that, do local sanity check for rename first.
                 */
                if (!remote) {
                        struct md_object *mo_s = md_object_find_slice(env,
                                                        md_obj2dev(mo_po), lf);
                        if (IS_ERR(mo_s))
                                RETURN(PTR_ERR(mo_s));

                        LASSERT(lu_object_exists(&mo_s->mo_lu) > 0);
                        rc = mo_permission(env, md_object_next(mo_po),
                                           md_object_next(mo_s),
                                           ma, MAY_RENAME_SRC);
                        lu_object_put(env, &mo_s->mo_lu);
                        if (rc)
                                RETURN(rc);
                } else {
                        rc = mo_permission(env, NULL, md_object_next(mo_po),
                                           ma, MAY_UNLINK | MAY_VTX_FULL);
                        if (rc)
                                RETURN(rc);
                }

                rc = mo_permission(env, NULL, md_object_next(mo_pn), ma,
                                   MAY_UNLINK | MAY_VTX_PART);
                if (rc)
                        RETURN(rc);

                /*
                 * /note \a ma will be changed after mo_ref_del(), but we will use
                 * it for mdo_rename() later, so save it before mo_ref_del().
                 */
                cmi = cmm_env_info(env);
                tmp_ma = &cmi->cmi_ma;
                *tmp_ma = *ma;
                rc = mo_ref_del(env, md_object_next(mo_t), ma);
                if (rc)
                        RETURN(rc);

                tmp_ma->ma_attr_flags |= MDS_PERM_BYPASS;
                mo_t = NULL;
        }

        /**
         * \note for src on remote MDS case, change its ctime before local
         * rename. Firstly, do local sanity check for rename if necessary.
         */
        if (remote) {
                if (!tmp_ma) {
                        rc = mo_permission(env, NULL, md_object_next(mo_po),
                                           ma, MAY_UNLINK | MAY_VTX_FULL);
                        if (rc)
                                RETURN(rc);

                        if (mo_t) {
                                LASSERT(lu_object_exists(&mo_t->mo_lu) > 0);
                                rc = mo_permission(env, md_object_next(mo_pn),
                                                   md_object_next(mo_t),
                                                   ma, MAY_RENAME_TAR);
                                if (rc)
                                        RETURN(rc);
                        } else {
                                int mask;

                                if (mo_po != mo_pn)
                                        mask = (S_ISDIR(ma->ma_attr.la_mode) ?
                                                MAY_LINK : MAY_CREATE);
                                else
                                        mask = MAY_CREATE;
                                rc = mo_permission(env, NULL,
                                                   md_object_next(mo_pn),
                                                   NULL, mask);
                                if (rc)
                                        RETURN(rc);
                        }

                        ma->ma_attr_flags |= MDS_PERM_BYPASS;
                } else {
                        LASSERT(tmp_ma->ma_attr_flags & MDS_PERM_BYPASS);
                }

                rc = cmm_rename_ctime(env, md_obj2dev(mo_po), lf,
                                      tmp_ma ? tmp_ma : ma);
                if (rc) {
                        /* TODO: revoke mo_t if necessary. */
                        cml_rename_warn("cmm_rename_ctime", mo_po,
                                        mo_pn, lf, ls_name->ln_name,
                                        tmp_t, lt_name->ln_name, rc);
                        RETURN(rc);
                }
        }

        /* local rename, mo_t can be NULL */
        rc = mdo_rename(env, md_object_next(mo_po),
                        md_object_next(mo_pn), lf, ls_name,
                        md_object_next(mo_t), lt_name, tmp_ma ? tmp_ma : ma);
        if (rc)
                /* TODO: revoke all cml_rename */
                cml_rename_warn("mdo_rename", mo_po, mo_pn, lf,
                                ls_name->ln_name, tmp_t, lt_name->ln_name, rc);

        RETURN(rc);
}

/**
 * Rename target partial operation.
 * Used for cross-ref rename.
 */
static int cml_rename_tgt(const struct lu_env *env, struct md_object *mo_p,
                          struct md_object *mo_t, const struct lu_fid *lf,
                          const struct lu_name *lname, struct md_attr *ma)
{
        int rc;
        ENTRY;

        rc = mdo_rename_tgt(env, md_object_next(mo_p),
                            md_object_next(mo_t), lf, lname, ma);
        RETURN(rc);
}

/**
 * Name insert only operation.
 * used only in case of rename_tgt() when target doesn't exist.
 */
static int cml_name_insert(const struct lu_env *env, struct md_object *p,
                           const struct lu_name *lname, const struct lu_fid *lf,
                           const struct md_attr *ma)
{
        int rc;
        ENTRY;

        rc = mdo_name_insert(env, md_object_next(p), lname, lf, ma);

        RETURN(rc);
}

/**
 * \ingroup cmm
 * Check two fids are not subdirectories.
 */
static int cmm_is_subdir(const struct lu_env *env, struct md_object *mo,
                         const struct lu_fid *fid, struct lu_fid *sfid)
{
        struct cmm_thread_info *cmi;
        int rc;
        ENTRY;

        cmi = cmm_env_info(env);
        rc = cmm_mode_get(env, md_obj2dev(mo), fid, &cmi->cmi_ma, NULL);
        if (rc)
                RETURN(rc);

        if (!S_ISDIR(cmi->cmi_ma.ma_attr.la_mode))
                RETURN(0);

        rc = mdo_is_subdir(env, md_object_next(mo), fid, sfid);
        RETURN(rc);
}

static const struct md_dir_operations cml_dir_ops = {
        .mdo_is_subdir   = cmm_is_subdir,
        .mdo_lookup      = cml_lookup,
        .mdo_lock_mode   = cml_lock_mode,
        .mdo_create      = cml_create,
        .mdo_link        = cml_link,
        .mdo_unlink      = cml_unlink,
        .mdo_name_insert = cml_name_insert,
        .mdo_rename      = cml_rename,
        .mdo_rename_tgt  = cml_rename_tgt,
        .mdo_create_data = cml_create_data,
};
/** @} */
/** @} */

/**
 * \addtogroup cmr
 * @{
 */
/**
 * \name cmr helpers
 * @{
 */
/** Get cmr_object from lu_object. */
static inline struct cmr_object *lu2cmr_obj(struct lu_object *o)
{
        return container_of0(o, struct cmr_object, cmm_obj.cmo_obj.mo_lu);
}
/** Get cmr_object from md_object. */
static inline struct cmr_object *md2cmr_obj(struct md_object *mo)
{
        return container_of0(mo, struct cmr_object, cmm_obj.cmo_obj);
}
/** Get cmr_object from cmm_object. */
static inline struct cmr_object *cmm2cmr_obj(struct cmm_object *co)
{
        return container_of0(co, struct cmr_object, cmm_obj);
}
/** @} */

/**
 * Get proper child device from MDCs.
 */
static struct lu_device *cmr_child_dev(struct cmm_device *d, __u32 num)
{
        struct lu_device *next = NULL;
        struct mdc_device *mdc;

        cfs_spin_lock(&d->cmm_tgt_guard);
        cfs_list_for_each_entry(mdc, &d->cmm_targets, mc_linkage) {
                if (mdc->mc_num == num) {
                        next = mdc2lu_dev(mdc);
                        break;
                }
        }
        cfs_spin_unlock(&d->cmm_tgt_guard);
        return next;
}

/**
 * Free cmr_object.
 */
static void cmr_object_free(const struct lu_env *env,
                            struct lu_object *lo)
{
        struct cmr_object *cro = lu2cmr_obj(lo);
        lu_object_fini(lo);
        OBD_FREE_PTR(cro);
}

/**
 * Initialize cmr object.
 */
static int cmr_object_init(const struct lu_env *env, struct lu_object *lo,
                           const struct lu_object_conf *unused)
{
        struct cmm_device *cd = lu2cmm_dev(lo->lo_dev);
        struct lu_device  *c_dev;
        struct lu_object  *c_obj;
        int rc;

        ENTRY;

        c_dev = cmr_child_dev(cd, lu2cmr_obj(lo)->cmo_num);
        if (c_dev == NULL) {
                rc = -ENOENT;
        } else {
                c_obj = c_dev->ld_ops->ldo_object_alloc(env,
                                                        lo->lo_header, c_dev);
                if (c_obj != NULL) {
                        lu_object_add(lo, c_obj);
                        rc = 0;
                } else {
                        rc = -ENOMEM;
                }
        }

        RETURN(rc);
}

/**
 * Output lu_object data.
 */
static int cmr_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *lo)
{
        const struct cmr_object *cro = lu2cmr_obj((struct lu_object *)lo);
        return (*p)(env, cookie, "[remote](mds_num=%d)", cro->cmo_num);
}

/**
 * Cmr instance of lu_object_operations.
 */
static const struct lu_object_operations cmr_obj_ops = {
        .loo_object_init    = cmr_object_init,
        .loo_object_free    = cmr_object_free,
        .loo_object_print   = cmr_object_print
};

/**
 * \name cmr remote md_object operations.
 * All operations here are invalid and return errors. There is no local object
 * so these operations return two kinds of error:
 * -# -EFAULT if operation is prohibited.
 * -# -EREMOTE if operation can be done just to notify upper level about remote
 *  object.
 *
 * @{
 */
static int cmr_object_create(const struct lu_env *env,
                             struct md_object *mo,
                             const struct md_op_spec *spec,
                             struct md_attr *ma)
{
        return -EFAULT;
}

static int cmr_permission(const struct lu_env *env,
                          struct md_object *p, struct md_object *c,
                          struct md_attr *attr, int mask)
{
        return -EREMOTE;
}

static int cmr_attr_get(const struct lu_env *env, struct md_object *mo,
                        struct md_attr *attr)
{
        return -EREMOTE;
}

static int cmr_attr_set(const struct lu_env *env, struct md_object *mo,
                        const struct md_attr *attr)
{
        return -EFAULT;
}

static int cmr_xattr_get(const struct lu_env *env, struct md_object *mo,
                         struct lu_buf *buf, const char *name)
{
        return -EFAULT;
}

static int cmr_readlink(const struct lu_env *env, struct md_object *mo,
                        struct lu_buf *buf)
{
        return -EFAULT;
}

static int cmr_changelog(const struct lu_env *env, enum changelog_rec_type type,
                         int flags, struct md_object *mo)
{
        return -EFAULT;
}

static int cmr_xattr_list(const struct lu_env *env, struct md_object *mo,
                          struct lu_buf *buf)
{
        return -EFAULT;
}

static int cmr_xattr_set(const struct lu_env *env, struct md_object *mo,
                         const struct lu_buf *buf, const char *name,
                         int fl)
{
        return -EFAULT;
}

static int cmr_xattr_del(const struct lu_env *env, struct md_object *mo,
                         const char *name)
{
        return -EFAULT;
}

static int cmr_ref_add(const struct lu_env *env, struct md_object *mo,
                       const struct md_attr *ma)
{
        return -EFAULT;
}

static int cmr_ref_del(const struct lu_env *env, struct md_object *mo,
                       struct md_attr *ma)
{
        return -EFAULT;
}

static int cmr_open(const struct lu_env *env, struct md_object *mo,
                    int flags)
{
        return -EREMOTE;
}

static int cmr_close(const struct lu_env *env, struct md_object *mo,
                     struct md_attr *ma, int mode)
{
        return -EFAULT;
}

static int cmr_readpage(const struct lu_env *env, struct md_object *mo,
                        const struct lu_rdpg *rdpg)
{
        return -EREMOTE;
}

static int cmr_capa_get(const struct lu_env *env, struct md_object *mo,
                        struct lustre_capa *capa, int renewal)
{
        return -EFAULT;
}

static int cmr_path(const struct lu_env *env, struct md_object *obj,
                    char *path, int pathlen, __u64 *recno, int *linkno)
{
        return -EREMOTE;
}

static int cmr_object_sync(const struct lu_env *env, struct md_object *mo)
{
        return -EFAULT;
}

static int cmr_file_lock(const struct lu_env *env, struct md_object *mo,
                         struct lov_mds_md *lmm, struct ldlm_extent *extent,
                         struct lustre_handle *lockh)
{
        return -EREMOTE;
}

static int cmr_file_unlock(const struct lu_env *env, struct md_object *mo,
                           struct lov_mds_md *lmm, struct lustre_handle *lockh)
{
        return -EREMOTE;
}

/**
 * cmr moo_version_get().
 */
static dt_obj_version_t cmr_version_get(const struct lu_env *env,
                                        struct md_object *mo)
{
        /** Don't check remote object version */
        return 0;
}


/**
 * cmr moo_version_set().
 * No need to update remote object version here, it is done as a part
 * of reintegration of partial operation on the remote server.
 */
static void cmr_version_set(const struct lu_env *env, struct md_object *mo,
                            dt_obj_version_t version)
{
        return;
}

/** Set of md_object_operations for cmr. */
static const struct md_object_operations cmr_mo_ops = {
        .moo_permission    = cmr_permission,
        .moo_attr_get      = cmr_attr_get,
        .moo_attr_set      = cmr_attr_set,
        .moo_xattr_get     = cmr_xattr_get,
        .moo_xattr_set     = cmr_xattr_set,
        .moo_xattr_list    = cmr_xattr_list,
        .moo_xattr_del     = cmr_xattr_del,
        .moo_object_create = cmr_object_create,
        .moo_ref_add       = cmr_ref_add,
        .moo_ref_del       = cmr_ref_del,
        .moo_open          = cmr_open,
        .moo_close         = cmr_close,
        .moo_readpage      = cmr_readpage,
        .moo_readlink      = cmr_readlink,
        .moo_changelog     = cmr_changelog,
        .moo_capa_get      = cmr_capa_get,
        .moo_object_sync   = cmr_object_sync,
        .moo_version_get   = cmr_version_get,
        .moo_version_set   = cmr_version_set,
        .moo_path          = cmr_path,
        .moo_file_lock     = cmr_file_lock,
        .moo_file_unlock   = cmr_file_unlock,
};
/** @} */

/**
 * \name cmr md_dir operations.
 *
 * All methods below are cross-ref by nature. They consist of remote call and
 * local operation. Due to future rollback functionality there are several
 * limitations for such methods:
 * -# remote call should be done at first to do epoch negotiation between all
 * MDS involved and to avoid the RPC inside transaction.
 * -# only one RPC can be sent - also due to epoch negotiation.
 * For more details see rollback HLD/DLD.
 * @{
 */
static int cmr_lookup(const struct lu_env *env, struct md_object *mo_p,
                      const struct lu_name *lname, struct lu_fid *lf,
                      struct md_op_spec *spec)
{
        /*
         * This can happens while rename() If new parent is remote dir, lookup
         * will happen here.
         */

        return -EREMOTE;
}

/** Return lock mode. */
static mdl_mode_t cmr_lock_mode(const struct lu_env *env,
                                struct md_object *mo, mdl_mode_t lm)
{
        return MDL_MINMODE;
}

/**
 * Create operation for cmr.
 * Remote object creation and local name insert.
 *
 * \param mo_p Parent directory. Local object.
 * \param lchild_name name of file to create.
 * \param mo_c Child object. It has no real inode yet.
 * \param spec creation specification.
 * \param ma child object attributes.
 */
static int cmr_create(const struct lu_env *env, struct md_object *mo_p,
                      const struct lu_name *lchild_name, struct md_object *mo_c,
                      struct md_op_spec *spec,
                      struct md_attr *ma)
{
        struct cmm_thread_info *cmi;
        struct md_attr *tmp_ma;
        int rc;
        ENTRY;

        /* Make sure that name isn't exist before doing remote call. */
        rc = mdo_lookup(env, md_object_next(mo_p), lchild_name,
                        &cmm_env_info(env)->cmi_fid, NULL);
        if (rc == 0)
                RETURN(-EEXIST);
        else if (rc != -ENOENT)
                RETURN(rc);

        /* check the SGID attr */
        cmi = cmm_env_info(env);
        LASSERT(cmi);
        tmp_ma = &cmi->cmi_ma;
        tmp_ma->ma_valid = 0;
        tmp_ma->ma_need = MA_INODE;

#ifdef CONFIG_FS_POSIX_ACL
        if (!S_ISLNK(ma->ma_attr.la_mode)) {
                tmp_ma->ma_acl = cmi->cmi_xattr_buf;
                tmp_ma->ma_acl_size = sizeof(cmi->cmi_xattr_buf);
                tmp_ma->ma_need |= MA_ACL_DEF;
        }
#endif
        rc = mo_attr_get(env, md_object_next(mo_p), tmp_ma);
        if (rc)
                RETURN(rc);

        if (tmp_ma->ma_attr.la_mode & S_ISGID) {
                ma->ma_attr.la_gid = tmp_ma->ma_attr.la_gid;
                if (S_ISDIR(ma->ma_attr.la_mode)) {
                        ma->ma_attr.la_mode |= S_ISGID;
                        ma->ma_attr.la_valid |= LA_MODE;
                }
        }

#ifdef CONFIG_FS_POSIX_ACL
        if (tmp_ma->ma_valid & MA_ACL_DEF) {
                spec->u.sp_ea.fid = spec->u.sp_pfid;
                spec->u.sp_ea.eadata = tmp_ma->ma_acl;
                spec->u.sp_ea.eadatalen = tmp_ma->ma_acl_size;
                spec->sp_cr_flags |= MDS_CREATE_RMT_ACL;
        }
#endif

        /* Local permission check for name_insert before remote ops. */
        rc = mo_permission(env, NULL, md_object_next(mo_p), NULL,
                           (S_ISDIR(ma->ma_attr.la_mode) ?
                           MAY_LINK : MAY_CREATE));
        if (rc)
                RETURN(rc);

        /**
         * \note \a ma will be changed after mo_object_create(), but we will use
         * it for mdo_name_insert() later, so save it before mo_object_create().
         */
        *tmp_ma = *ma;
        rc = mo_object_create(env, md_object_next(mo_c), spec, ma);
        if (rc == 0) {
                tmp_ma->ma_attr_flags |= MDS_PERM_BYPASS;
                rc = mdo_name_insert(env, md_object_next(mo_p), lchild_name,
                                     lu_object_fid(&mo_c->mo_lu), tmp_ma);
                if (unlikely(rc)) {
                        /* TODO: remove object mo_c on remote MDS */
                        CWARN("cmr_create failed, should revoke: [mo_p "DFID"]"
                              " [name %s] [mo_c "DFID"] [err %d]\n",
                              PFID(lu_object_fid(&mo_p->mo_lu)),
                              lchild_name->ln_name,
                              PFID(lu_object_fid(&mo_c->mo_lu)), rc);
                }
        }

        RETURN(rc);
}

/**
 * Link operations for cmr.
 *
 * The link RPC is always issued to the server where source parent is living.
 * The first operation to do is object nlink increment on remote server.
 * Second one is local mdo_name_insert().
 *
 * \param mo_p parent directory. It is local.
 * \param mo_s source object to link. It is remote.
 * \param lname Name of link file.
 * \param ma object attributes.
 */
static int cmr_link(const struct lu_env *env, struct md_object *mo_p,
                    struct md_object *mo_s, const struct lu_name *lname,
                    struct md_attr *ma)
{
        int rc;
        ENTRY;

        /* Make sure that name isn't exist before doing remote call. */
        rc = mdo_lookup(env, md_object_next(mo_p), lname,
                        &cmm_env_info(env)->cmi_fid, NULL);
        if (rc == 0) {
                rc = -EEXIST;
        } else if (rc == -ENOENT) {
                /* Local permission check for name_insert before remote ops. */
                rc = mo_permission(env, NULL, md_object_next(mo_p), NULL,
                                   MAY_CREATE);
                if (rc)
                        RETURN(rc);

                rc = mo_ref_add(env, md_object_next(mo_s), ma);
                if (rc == 0) {
                        ma->ma_attr_flags |= MDS_PERM_BYPASS;
                        rc = mdo_name_insert(env, md_object_next(mo_p), lname,
                                             lu_object_fid(&mo_s->mo_lu), ma);
                        if (unlikely(rc)) {
                                /* TODO: ref_del from mo_s on remote MDS */
                                CWARN("cmr_link failed, should revoke: "
                                      "[mo_p "DFID"] [mo_s "DFID"] "
                                      "[name %s] [err %d]\n",
                                      PFID(lu_object_fid(&mo_p->mo_lu)),
                                      PFID(lu_object_fid(&mo_s->mo_lu)),
                                      lname->ln_name, rc);
                        }
                }
        }
        RETURN(rc);
}

/**
 * Unlink operations for cmr.
 *
 * The unlink RPC is always issued to the server where parent is living. Hence
 * the first operation to do is object unlink on remote server. Second one is
 * local mdo_name_remove().
 *
 * \param mo_p parent md_object. It is local.
 * \param mo_c child object to be unlinked. It is remote.
 * \param lname Name of file to unlink.
 * \param ma object attributes.
 */
static int cmr_unlink(const struct lu_env *env, struct md_object *mo_p,
                      struct md_object *mo_c, const struct lu_name *lname,
                      struct md_attr *ma)
{
        struct cmm_thread_info *cmi;
        struct md_attr *tmp_ma;
        int rc;
        ENTRY;

        /* Local permission check for name_remove before remote ops. */
        rc = mo_permission(env, NULL, md_object_next(mo_p), ma,
                           MAY_UNLINK | MAY_VTX_PART);
        if (rc)
                RETURN(rc);

        /*
         * \note \a ma will be changed after mo_ref_del, but we will use
         * it for mdo_name_remove() later, so save it before mo_ref_del().
         */
        cmi = cmm_env_info(env);
        tmp_ma = &cmi->cmi_ma;
        *tmp_ma = *ma;
        rc = mo_ref_del(env, md_object_next(mo_c), ma);
        if (rc == 0) {
                tmp_ma->ma_attr_flags |= MDS_PERM_BYPASS;
                rc = mdo_name_remove(env, md_object_next(mo_p), lname, tmp_ma);
                if (unlikely(rc)) {
                        /* TODO: ref_add to mo_c on remote MDS */
                        CWARN("cmr_unlink failed, should revoke: [mo_p "DFID"]"
                              " [mo_c "DFID"] [name %s] [err %d]\n",
                              PFID(lu_object_fid(&mo_p->mo_lu)),
                              PFID(lu_object_fid(&mo_c->mo_lu)),
                              lname->ln_name, rc);
                }
        }

        RETURN(rc);
}

/** Helper which outputs error message during cmr_rename() */
static inline void cmr_rename_warn(const char *fname,
                                  struct md_object *mo_po,
                                  struct md_object *mo_pn,
                                  const struct lu_fid *lf,
                                  const char *s_name,
                                  const char *t_name,
                                  int err)
{
        CWARN("cmr_rename failed for %s, should revoke: "
              "[mo_po "DFID"] [mo_pn "DFID"] [lf "DFID"] "
              "[sname %s] [tname %s] [err %d]\n", fname,
              PFID(lu_object_fid(&mo_po->mo_lu)),
              PFID(lu_object_fid(&mo_pn->mo_lu)),
              PFID(lf), s_name, t_name, err);
}

/**
 * Rename operation for cmr.
 *
 * This is the most complex cross-reference operation. It may consist of up to 4
 * MDS server and require several RPCs to be sent.
 *
 * \param mo_po Old parent object.
 * \param mo_pn New parent object.
 * \param lf FID of object to rename.
 * \param ls_name Source file name.
 * \param mo_t target object. Should be NULL here.
 * \param lt_name Name of target file.
 * \param ma object attributes.
 */
static int cmr_rename(const struct lu_env *env,
                      struct md_object *mo_po, struct md_object *mo_pn,
                      const struct lu_fid *lf, const struct lu_name *ls_name,
                      struct md_object *mo_t, const struct lu_name *lt_name,
                      struct md_attr *ma)
{
        struct cmm_thread_info *cmi;
        struct md_attr *tmp_ma;
        int rc;
        ENTRY;

        LASSERT(mo_t == NULL);

        /* get real type of src */
        rc = cmm_mode_get(env, md_obj2dev(mo_po), lf, ma, NULL);
        if (rc)
                RETURN(rc);

        /* Local permission check for name_remove before remote ops. */
        rc = mo_permission(env, NULL, md_object_next(mo_po), ma,
                           MAY_UNLINK | MAY_VTX_FULL);
        if (rc)
                RETURN(rc);

        /**
         * \todo \a ma maybe changed after mdo_rename_tgt(), but we will use it
         * for mdo_name_remove() later, so save it before mdo_rename_tgt.
         */
        cmi = cmm_env_info(env);
        tmp_ma = &cmi->cmi_ma;
        *tmp_ma = *ma;
        /**
         * \note The \a mo_pn is remote directory, so we cannot even know if there is
         * \a mo_t or not. Therefore \a mo_t is NULL here but remote server should do
         * lookup and process this further.
         */
        rc = mdo_rename_tgt(env, md_object_next(mo_pn),
                            NULL/* mo_t */, lf, lt_name, ma);
        if (rc)
                RETURN(rc);

        tmp_ma->ma_attr_flags |= MDS_PERM_BYPASS;

        /* src object maybe on remote MDS, do remote ops first. */
        rc = cmm_rename_ctime(env, md_obj2dev(mo_po), lf, tmp_ma);
        if (unlikely(rc)) {
                /* TODO: revoke mdo_rename_tgt */
                cmr_rename_warn("cmm_rename_ctime", mo_po, mo_pn, lf,
                                ls_name->ln_name, lt_name->ln_name, rc);
                RETURN(rc);
        }

        /* only old name is removed localy */
        rc = mdo_name_remove(env, md_object_next(mo_po), ls_name, tmp_ma);
        if (unlikely(rc))
                /* TODO: revoke all cmr_rename */
                cmr_rename_warn("mdo_name_remove", mo_po, mo_pn, lf,
                                ls_name->ln_name, lt_name->ln_name, rc);

        RETURN(rc);
}

/**
 * Part of cross-ref rename().
 * Used to insert new name in new parent and unlink target.
 */
static int cmr_rename_tgt(const struct lu_env *env,
                          struct md_object *mo_p, struct md_object *mo_t,
                          const struct lu_fid *lf, const struct lu_name *lname,
                          struct md_attr *ma)
{
        struct cmm_thread_info *cmi;
        struct md_attr *tmp_ma;
        int rc;
        ENTRY;

        /* target object is remote one */
        /* Local permission check for rename_tgt before remote ops. */
        rc = mo_permission(env, NULL, md_object_next(mo_p), ma,
                           MAY_UNLINK | MAY_VTX_PART);
        if (rc)
                RETURN(rc);

        /*
         * XXX: @ma maybe changed after mo_ref_del, but we will use
         * it for mdo_rename_tgt later, so save it before mo_ref_del.
         */
        cmi = cmm_env_info(env);
        tmp_ma = &cmi->cmi_ma;
        *tmp_ma = *ma;
        rc = mo_ref_del(env, md_object_next(mo_t), ma);
        /* continue locally with name handling only */
        if (rc == 0) {
                tmp_ma->ma_attr_flags |= MDS_PERM_BYPASS;
                rc = mdo_rename_tgt(env, md_object_next(mo_p),
                                    NULL, lf, lname, tmp_ma);
                if (unlikely(rc)) {
                        /* TODO: ref_add to mo_t on remote MDS */
                        CWARN("cmr_rename_tgt failed, should revoke: "
                              "[mo_p "DFID"] [mo_t "DFID"] [lf "DFID"] "
                              "[name %s] [err %d]\n",
                              PFID(lu_object_fid(&mo_p->mo_lu)),
                              PFID(lu_object_fid(&mo_t->mo_lu)),
                              PFID(lf),
                              lname->ln_name, rc);
                }
        }
        RETURN(rc);
}
/** @} */
/**
 * The md_dir_operations for cmr.
 */
static const struct md_dir_operations cmr_dir_ops = {
        .mdo_is_subdir   = cmm_is_subdir,
        .mdo_lookup      = cmr_lookup,
        .mdo_lock_mode   = cmr_lock_mode,
        .mdo_create      = cmr_create,
        .mdo_link        = cmr_link,
        .mdo_unlink      = cmr_unlink,
        .mdo_rename      = cmr_rename,
        .mdo_rename_tgt  = cmr_rename_tgt
};
/** @} */
