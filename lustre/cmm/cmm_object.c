/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/cmm_object.c
 *  Lustre Cluster Metadata Manager (cmm)
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Mike Pershin <tappro@clusterfs.com>
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

#include <lustre_fid.h>
#include "cmm_internal.h"
#include "mdc_internal.h"

static int cmm_fld_lookup(struct cmm_device *cm,
                          const struct lu_fid *fid, mdsno_t *mds,
                          const struct lu_env *env)
{
        int rc = 0;
        ENTRY;

        LASSERT(fid_is_sane(fid));

        rc = fld_client_lookup(cm->cmm_fld, fid_seq(fid), mds, env);
        if (rc) {
                CERROR("Can't find mds by seq "LPX64", rc %d\n",
                       fid_seq(fid), rc);
                RETURN(rc);
        }

        if (*mds > cm->cmm_tgt_count) {
                CERROR("Got invalid mdsno: "LPU64" (max: %u)\n",
                       *mds, cm->cmm_tgt_count);
                rc = -EINVAL;
        } else {
                CDEBUG(D_INFO, "CMM: got MDS "LPU64" for sequence: "
                       LPU64"\n", *mds, fid_seq(fid));
        }

        RETURN (rc);
}

static struct md_object_operations cml_mo_ops;
static struct md_dir_operations    cml_dir_ops;
static struct lu_object_operations cml_obj_ops;

static struct md_object_operations cmr_mo_ops;
static struct md_dir_operations    cmr_dir_ops;
static struct lu_object_operations cmr_obj_ops;

struct lu_object *cmm_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *loh,
                                   struct lu_device *ld)
{
        struct lu_object  *lo = NULL;
        const struct lu_fid *fid = &loh->loh_fid;
        struct cmm_device *cd;
        mdsno_t mdsnum;
        int rc = 0;

        ENTRY;

        cd = lu2cmm_dev(ld);
        if (cd->cmm_flags & CMM_INITIALIZED) {
                /* get object location */
                rc = cmm_fld_lookup(lu2cmm_dev(ld), fid, &mdsnum, env);
                if (rc)
                        RETURN(NULL);
        } else
                /*
                 * Device is not yet initialized, cmm_object is being created
                 * as part of early bootstrap procedure (it is /ROOT, or /fld,
                 * etc.). Such object *has* to be local.
                 */
                mdsnum = cd->cmm_local_num;

        /* select the proper set of operations based on object location */
        if (mdsnum == cd->cmm_local_num) {
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
                        cro->cmo_num = mdsnum;
                }
        }
        RETURN(lo);
}

/*
 * CMM has two types of objects - local and remote. They have different set
 * of operations so we are avoiding multiple checks in code.
 */

/*
 * local CMM object operations. cml_...
 */
static inline struct cml_object *lu2cml_obj(struct lu_object *o)
{
        return container_of0(o, struct cml_object, cmm_obj.cmo_obj.mo_lu);
}
static inline struct cml_object *md2cml_obj(struct md_object *mo)
{
        return container_of0(mo, struct cml_object, cmm_obj.cmo_obj);
}
static inline struct cml_object *cmm2cml_obj(struct cmm_object *co)
{
        return container_of0(co, struct cml_object, cmm_obj);
}
/* get local child device */
static struct lu_device *cml_child_dev(struct cmm_device *d)
{
        return &d->cmm_child->md_lu_dev;
}

/* lu_object operations */
static void cml_object_free(const struct lu_env *env,
                            struct lu_object *lo)
{
        struct cml_object *clo = lu2cml_obj(lo);
        lu_object_fini(lo);
        OBD_FREE_PTR(clo);
}

static int cml_object_init(const struct lu_env *env, struct lu_object *lo)
{
        struct cmm_device *cd = lu2cmm_dev(lo->lo_dev);
        struct lu_device  *c_dev;
        struct lu_object  *c_obj;
        int rc;

        ENTRY;

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
	return (*p)(env, cookie, LUSTRE_CMM_NAME"-local@%p", lo);
}

static struct lu_object_operations cml_obj_ops = {
	.loo_object_init    = cml_object_init,
	.loo_object_free    = cml_object_free,
	.loo_object_print   = cml_object_print
};

/* CMM local md_object operations */
static int cml_object_create(const struct lu_env *env,
                             struct md_object *mo,
                             const struct md_create_spec *spec,
                             struct md_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_object_create(env, md_object_next(mo), spec, attr);
        RETURN(rc);
}

static int cml_permission(const struct lu_env *env,
                        struct md_object *mo, int mask)
{
        int rc;
        ENTRY;
        rc = mo_permission(env, md_object_next(mo), mask);
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

static int cml_xattr_list(const struct lu_env *env, struct md_object *mo,
                          struct lu_buf *buf)
{
        int rc;
        ENTRY;
        rc = mo_xattr_list(env, md_object_next(mo), buf);
        RETURN(rc);
}

static int cml_xattr_set(const struct lu_env *env, struct md_object *mo,
                         const struct lu_buf *buf,
                         const char *name, int fl)
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

static int cml_ref_add(const struct lu_env *env, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_ref_add(env, md_object_next(mo));
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
                     struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mo_close(env, md_object_next(mo), ma);
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

static struct md_object_operations cml_mo_ops = {
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
        .moo_capa_get      = cml_capa_get
};

/* md_dir operations */
static int cml_lookup(const struct lu_env *env, struct md_object *mo_p,
                      const char *name, struct lu_fid *lf)
{
        int rc;
        ENTRY;

#ifdef HAVE_SPLIT_SUPPORT
        rc = cmm_mdsnum_check(env, mo_p, name);
        if (rc)
                RETURN(rc);
#endif
        rc = mdo_lookup(env, md_object_next(mo_p), name, lf);
        RETURN(rc);

}

static mdl_mode_t cml_lock_mode(const struct lu_env *env,
                                struct md_object *mo, mdl_mode_t lm)
{
#if defined(HAVE_SPLIT_SUPPORT)
        struct md_attr *ma = &cmm_env_info(env)->cmi_ma;
        int rc, split;
        ENTRY;
        memset(ma, 0, sizeof(*ma));

        /*
         * Check only if we need protection from split. If not - mdt
         * handles other cases.
         */
        rc = cmm_expect_splitting(env, mo, ma, &split);
        if (rc) {
                CERROR("Can't check for possible split, error %d\n",
                       rc);
                RETURN(MDL_MINMODE);
        }

        if (lm == MDL_PW && split == CMM_EXPECT_SPLIT)
                RETURN(MDL_EX);
        RETURN(MDL_MINMODE);
#endif
        return MDL_MINMODE;
}

static int cml_create(const struct lu_env *env,
                      struct md_object *mo_p, const char *child_name,
                      struct md_object *mo_c, struct md_create_spec *spec,
                      struct md_attr *ma)
{
        int rc;
        ENTRY;

#ifdef HAVE_SPLIT_SUPPORT
        rc = cmm_try_to_split(env, mo_p);
        if (rc)
                RETURN(rc);

        rc = cmm_mdsnum_check(env, mo_p, child_name);
        if (rc)
                RETURN(rc);
#endif

        rc = mdo_create(env, md_object_next(mo_p), child_name,
                        md_object_next(mo_c), spec, ma);


        RETURN(rc);
}

static int cml_create_data(const struct lu_env *env, struct md_object *p,
                           struct md_object *o,
                           const struct md_create_spec *spec,
                           struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mdo_create_data(env, md_object_next(p), md_object_next(o),
                             spec, ma);
        RETURN(rc);
}

static int cml_link(const struct lu_env *env, struct md_object *mo_p,
                    struct md_object *mo_s, const char *name,
                    struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mdo_link(env, md_object_next(mo_p), md_object_next(mo_s),
                      name, ma);
        RETURN(rc);
}

static int cml_unlink(const struct lu_env *env, struct md_object *mo_p,
                      struct md_object *mo_c, const char *name,
                      struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mdo_unlink(env, md_object_next(mo_p), md_object_next(mo_c),
                        name, ma);
        RETURN(rc);
}

/* rename is split to local/remote by location of new parent dir */
struct md_object *md_object_find(const struct lu_env *env,
                                 struct md_device *md,
                                 const struct lu_fid *f)
{
        struct lu_object *o;
        struct md_object *m;
        ENTRY;

        o = lu_object_find(env, md2lu_dev(md)->ld_site, f);
        if (IS_ERR(o))
                m = (struct md_object *)o;
        else {
                o = lu_object_locate(o->lo_header, md2lu_dev(md)->ld_type);
                m = o ? lu2md(o) : NULL;
        }
        RETURN(m);
}

static int __cmm_mode_get(const struct lu_env *env, struct md_device *md,
                          const struct lu_fid *lf, struct md_attr *ma)
{
        struct cmm_thread_info *cmi;
        struct md_object *mo_s = md_object_find(env, md, lf);
        struct md_attr *tmp_ma;
        int rc;
        ENTRY;

        if (IS_ERR(mo_s))
                RETURN(PTR_ERR(mo_s));

        cmi = cmm_env_info(env);
        LASSERT(cmi);
        tmp_ma = &cmi->cmi_ma;
        tmp_ma->ma_need = MA_INODE;
        tmp_ma->ma_valid = 0;
        /* get type from src, can be remote req */
        rc = mo_attr_get(env, md_object_next(mo_s), tmp_ma);
        if (rc == 0) {
                ma->ma_attr.la_mode = tmp_ma->ma_attr.la_mode;
                ma->ma_attr.la_flags = tmp_ma->ma_attr.la_flags;
                ma->ma_attr.la_valid |= LA_MODE | LA_FLAGS;
        }
        lu_object_put(env, &mo_s->mo_lu);
        return rc;
}

static int cml_rename(const struct lu_env *env, struct md_object *mo_po,
                      struct md_object *mo_pn, const struct lu_fid *lf,
                      const char *s_name, struct md_object *mo_t,
                      const char *t_name, struct md_attr *ma)
{
        int rc;
        ENTRY;

        rc = __cmm_mode_get(env, md_obj2dev(mo_po), lf, ma);
        if (rc != 0)
                RETURN(rc);

        if (mo_t && lu_object_exists(&mo_t->mo_lu) < 0) {
                /* mo_t is remote object and there is RPC to unlink it */
                rc = mo_ref_del(env, md_object_next(mo_t), ma);
                if (rc)
                        RETURN(rc);
                mo_t = NULL;
        }

        /* local rename, mo_t can be NULL */
        rc = mdo_rename(env, md_object_next(mo_po),
                        md_object_next(mo_pn), lf, s_name,
                        md_object_next(mo_t), t_name, ma);
        RETURN(rc);
}

static int cml_rename_tgt(const struct lu_env *env, struct md_object *mo_p,
                          struct md_object *mo_t, const struct lu_fid *lf,
                          const char *name, struct md_attr *ma)
{
        int rc;
        ENTRY;

        rc = mdo_rename_tgt(env, md_object_next(mo_p),
                            md_object_next(mo_t), lf, name, ma);
        RETURN(rc);
}
/* used only in case of rename_tgt() when target is not exist */
static int cml_name_insert(const struct lu_env *env, struct md_object *p,
                           const char *name, const struct lu_fid *lf, int isdir)
{
        int rc;
        ENTRY;

        rc = mdo_name_insert(env, md_object_next(p), name, lf, isdir);

        RETURN(rc);
}

/* Common method for remote and local use. */
static int cmm_is_subdir(const struct lu_env *env, struct md_object *mo,
                         const struct lu_fid *fid, struct lu_fid *sfid)
{
        struct cmm_thread_info *cmi;
        int rc;
        ENTRY;

        cmi = cmm_env_info(env);
        rc = __cmm_mode_get(env, md_obj2dev(mo), fid, &cmi->cmi_ma);
        if (rc)
                RETURN(rc);

        if (!S_ISDIR(cmi->cmi_ma.ma_attr.la_mode))
                RETURN(0);

        rc = mdo_is_subdir(env, md_object_next(mo), fid, sfid);
        RETURN(rc);
}

static struct md_dir_operations cml_dir_ops = {
        .mdo_is_subdir   = cmm_is_subdir,
        .mdo_lookup      = cml_lookup,
        .mdo_lock_mode   = cml_lock_mode,
        .mdo_create      = cml_create,
        .mdo_link        = cml_link,
        .mdo_unlink      = cml_unlink,
        .mdo_name_insert = cml_name_insert,
        .mdo_rename      = cml_rename,
        .mdo_rename_tgt  = cml_rename_tgt,
        .mdo_create_data = cml_create_data
};

/* -------------------------------------------------------------------
 * remote CMM object operations. cmr_...
 */
static inline struct cmr_object *lu2cmr_obj(struct lu_object *o)
{
        return container_of0(o, struct cmr_object, cmm_obj.cmo_obj.mo_lu);
}
static inline struct cmr_object *md2cmr_obj(struct md_object *mo)
{
        return container_of0(mo, struct cmr_object, cmm_obj.cmo_obj);
}
static inline struct cmr_object *cmm2cmr_obj(struct cmm_object *co)
{
        return container_of0(co, struct cmr_object, cmm_obj);
}

/* get proper child device from MDCs */
static struct lu_device *cmr_child_dev(struct cmm_device *d, __u32 num)
{
        struct lu_device *next = NULL;
        struct mdc_device *mdc;

        spin_lock(&d->cmm_tgt_guard);
        list_for_each_entry(mdc, &d->cmm_targets, mc_linkage) {
                if (mdc->mc_num == num) {
                        next = mdc2lu_dev(mdc);
                        break;
                }
        }
        spin_unlock(&d->cmm_tgt_guard);
        return next;
}

/* lu_object operations */
static void cmr_object_free(const struct lu_env *env,
                            struct lu_object *lo)
{
        struct cmr_object *cro = lu2cmr_obj(lo);
        lu_object_fini(lo);
        OBD_FREE_PTR(cro);
}

static int cmr_object_init(const struct lu_env *env, struct lu_object *lo)
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

static int cmr_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *lo)
{
	return (*p)(env, cookie, LUSTRE_CMM_NAME"-remote@%p", lo);
}

static struct lu_object_operations cmr_obj_ops = {
	.loo_object_init    = cmr_object_init,
	.loo_object_free    = cmr_object_free,
	.loo_object_print   = cmr_object_print
};

/* CMM remote md_object operations. All are invalid */
static int cmr_object_create(const struct lu_env *env,
                             struct md_object *mo,
                             const struct md_create_spec *spec,
                             struct md_attr *ma)
{
        RETURN(-EFAULT);
}

static int cmr_permission(const struct lu_env *env, struct md_object *mo,
                          int mask)
{
        RETURN(-EREMOTE);
}

static int cmr_attr_get(const struct lu_env *env, struct md_object *mo,
                        struct md_attr *attr)
{
        RETURN(-EREMOTE);
}

static int cmr_attr_set(const struct lu_env *env, struct md_object *mo,
                        const struct md_attr *attr)
{
        RETURN(-EFAULT);
}

static int cmr_xattr_get(const struct lu_env *env, struct md_object *mo,
                         struct lu_buf *buf, const char *name)
{
        RETURN(-EFAULT);
}

static int cmr_readlink(const struct lu_env *env, struct md_object *mo,
                        struct lu_buf *buf)
{
        RETURN(-EFAULT);
}

static int cmr_xattr_list(const struct lu_env *env, struct md_object *mo,
                          struct lu_buf *buf)
{
        RETURN(-EFAULT);
}

static int cmr_xattr_set(const struct lu_env *env, struct md_object *mo,
                         const struct lu_buf *buf, const char *name, int fl)
{
        RETURN(-EFAULT);
}

static int cmr_xattr_del(const struct lu_env *env, struct md_object *mo,
                         const char *name)
{
        RETURN(-EFAULT);
}

static int cmr_ref_add(const struct lu_env *env, struct md_object *mo)
{
        RETURN(-EFAULT);
}

static int cmr_ref_del(const struct lu_env *env, struct md_object *mo,
                       struct md_attr *ma)
{
        RETURN(-EFAULT);
}

static int cmr_open(const struct lu_env *env, struct md_object *mo,
                    int flags)
{
        RETURN(-EREMOTE);
}

static int cmr_close(const struct lu_env *env, struct md_object *mo,
                     struct md_attr *ma)
{
        RETURN(-EFAULT);
}

static int cmr_readpage(const struct lu_env *env, struct md_object *mo,
                        const struct lu_rdpg *rdpg)
{
        RETURN(-EREMOTE);
}

static int cmr_capa_get(const struct lu_env *env, struct md_object *mo,
                        struct lustre_capa *capa, int renewal)
{
        RETURN(-EFAULT);
}

static struct md_object_operations cmr_mo_ops = {
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
        .moo_capa_get      = cmr_capa_get
};

/* remote part of md_dir operations */
static int cmr_lookup(const struct lu_env *env, struct md_object *mo_p,
                      const char *name, struct lu_fid *lf)
{
        /*
         * This can happens while rename() If new parent is remote dir, lookup
         * will happen here.
         */

        RETURN(-EREMOTE);
}

static mdl_mode_t cmr_lock_mode(const struct lu_env *env,
                                struct md_object *mo, mdl_mode_t lm)
{
        RETURN(MDL_MINMODE);
}

/*
 * All methods below are cross-ref by nature. They consist of remote call and
 * local operation. Due to future rollback functionality there are several
 * limitations for such methods:
 * 1) remote call should be done at first to do epoch negotiation between all
 * MDS involved and to avoid the RPC inside transaction.
 * 2) only one RPC can be sent - also due to epoch negotiation.
 * For more details see rollback HLD/DLD.
 */
static int cmr_create(const struct lu_env *env, struct md_object *mo_p,
                      const char *child_name, struct md_object *mo_c,
                      struct md_create_spec *spec,
                      struct md_attr *ma)
{
        struct cmm_thread_info *cmi;
        struct md_attr *tmp_ma;
        int rc;

        ENTRY;
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
                spec->u.sp_ea.eadata = tmp_ma->ma_acl;
                spec->u.sp_ea.eadatalen = tmp_ma->ma_acl_size;
                spec->sp_cr_flags |= MDS_CREATE_RMT_ACL;
        }
#endif

        /* remote object creation and local name insert */
        rc = mo_object_create(env, md_object_next(mo_c), spec, ma);
        if (rc == 0) {
                rc = mdo_name_insert(env, md_object_next(mo_p),
                                     child_name, lu_object_fid(&mo_c->mo_lu),
                                     S_ISDIR(ma->ma_attr.la_mode));
        }

        RETURN(rc);
}

static int cmr_link(const struct lu_env *env, struct md_object *mo_p,
                    struct md_object *mo_s, const char *name,
                    struct md_attr *ma)
{
        int rc;
        ENTRY;

        //XXX: make sure that MDT checks name isn't exist

        rc = mo_ref_add(env, md_object_next(mo_s));
        if (rc == 0) {
                rc = mdo_name_insert(env, md_object_next(mo_p),
                                     name, lu_object_fid(&mo_s->mo_lu), 0);
        }

        RETURN(rc);
}

static int cmr_unlink(const struct lu_env *env, struct md_object *mo_p,
                      struct md_object *mo_c, const char *name,
                      struct md_attr *ma)
{
        int rc;
        ENTRY;

        rc = mo_ref_del(env, md_object_next(mo_c), ma);
        if (rc == 0) {
                rc = mdo_name_remove(env, md_object_next(mo_p),
                                     name, S_ISDIR(ma->ma_attr.la_mode));
        }

        RETURN(rc);
}

static int cmr_rename(const struct lu_env *env,
                      struct md_object *mo_po, struct md_object *mo_pn,
                      const struct lu_fid *lf, const char *s_name,
                      struct md_object *mo_t, const char *t_name,
                      struct md_attr *ma)
{
        int rc;
        ENTRY;

        /* get real type of src */
        rc = __cmm_mode_get(env, md_obj2dev(mo_po), lf, ma);
        if (rc != 0)
                RETURN(rc);

        LASSERT(mo_t == NULL);
        /* the mo_pn is remote directory, so we cannot even know if there is
         * mo_t or not. Therefore mo_t is NULL here but remote server should do
         * lookup and process this further */
        rc = mdo_rename_tgt(env, md_object_next(mo_pn),
                            NULL/* mo_t */, lf, t_name, ma);
        /* only old name is removed localy */
        if (rc == 0)
                rc = mdo_name_remove(env, md_object_next(mo_po),
                                     s_name, S_ISDIR(ma->ma_attr.la_mode));

        RETURN(rc);
}

/* part of cross-ref rename(). Used to insert new name in new parent
 * and unlink target */
static int cmr_rename_tgt(const struct lu_env *env,
                          struct md_object *mo_p, struct md_object *mo_t,
                          const struct lu_fid *lf, const char *name,
                          struct md_attr *ma)
{
        int rc;
        ENTRY;
        /* target object is remote one */
        rc = mo_ref_del(env, md_object_next(mo_t), ma);
        /* continue locally with name handling only */
        if (rc == 0)
                rc = mdo_rename_tgt(env, md_object_next(mo_p),
                                    NULL, lf, name, ma);
        RETURN(rc);
}

static struct md_dir_operations cmr_dir_ops = {
        .mdo_is_subdir   = cmm_is_subdir,
        .mdo_lookup      = cmr_lookup,
        .mdo_lock_mode   = cmr_lock_mode,
        .mdo_create      = cmr_create,
        .mdo_link        = cmr_link,
        .mdo_unlink      = cmr_unlink,
        .mdo_rename      = cmr_rename,
        .mdo_rename_tgt  = cmr_rename_tgt,
};
