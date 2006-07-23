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
                          const struct lu_fid *fid, mdsno_t *mds)
{
        struct lu_site *ls;
        int rc = 0;
        ENTRY;

        LASSERT(fid_is_sane(fid));

        ls = cm->cmm_md_dev.md_lu_dev.ld_site;

        rc = fld_client_lookup(ls->ls_client_fld,
                               fid_seq(fid), mds);
        if (rc) {
                CERROR("can't find mds by seq "LPX64", rc %d\n",
                       fid_seq(fid), rc);
                RETURN(rc);
        }

        if (*mds >= cm->cmm_tgt_count) {
                CERROR("Got invalid mdsno: "LPU64" (max: %u)\n",
                       *mds, cm->cmm_tgt_count);
                rc = -EINVAL;
        } else {
                CDEBUG(D_INFO, "CMM: got MDS "LPU64" for sequence: "LPU64"\n",
                       *mds, fid_seq(fid));
        }

        RETURN (rc);
}

static struct md_object_operations cml_mo_ops;
static struct md_dir_operations    cml_dir_ops;
static struct lu_object_operations cml_obj_ops;

static struct md_object_operations cmr_mo_ops;
static struct md_dir_operations    cmr_dir_ops;
static struct lu_object_operations cmr_obj_ops;

struct lu_object *cmm_object_alloc(const struct lu_context *ctx,
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
                rc = cmm_fld_lookup(lu2cmm_dev(ld), fid, &mdsnum);
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
static void cml_object_free(const struct lu_context *ctx,
                            struct lu_object *lo)
{
        struct cml_object *clo = lu2cml_obj(lo);
        lu_object_fini(lo);
        OBD_FREE_PTR(clo);
}

static int cml_object_init(const struct lu_context *ctx, struct lu_object *lo)
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
                c_obj = c_dev->ld_ops->ldo_object_alloc(ctx,
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

static int cml_object_exists(const struct lu_context *ctx,
                             const struct lu_object *lo)
{
        return lu_object_exists(ctx, lu_object_next(lo));
}

static int cml_object_print(const struct lu_context *ctx, void *cookie,
                            lu_printer_t p, const struct lu_object *lo)
{
	return (*p)(ctx, cookie, LUSTRE_CMM0_NAME"-local@%p", lo);
}

static struct lu_object_operations cml_obj_ops = {
	.loo_object_init    = cml_object_init,
	.loo_object_free    = cml_object_free,
	.loo_object_print   = cml_object_print,
	.loo_object_exists  = cml_object_exists
};

/* CMM local md_object operations */
static int cml_object_create(const struct lu_context *ctx,
                             struct md_object *mo,
                             struct md_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_object_create(ctx, md_object_next(mo), attr);
        RETURN(rc);
}

static int cml_attr_get(const struct lu_context *ctx, struct md_object *mo,
                        struct lu_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_attr_get(ctx, md_object_next(mo), attr);
        RETURN(rc);
}

static int cml_attr_set(const struct lu_context *ctx, struct md_object *mo,
                        const struct lu_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_attr_set(ctx, md_object_next(mo), attr);
        RETURN(rc);
}

static int cml_xattr_get(const struct lu_context *ctx, struct md_object *mo,
                         void *buf, int buflen, const char *name)
{
        int rc;
        ENTRY;
        rc = mo_xattr_get(ctx, md_object_next(mo),
                         buf, buflen, name);
        RETURN(rc);
}

static int cml_xattr_set(const struct lu_context *ctx, struct md_object *mo,
                         const void *buf, int buflen, const char *name)
{
        int rc;
        ENTRY;
        rc = mo_xattr_set(ctx, md_object_next(mo),
                          buf, buflen, name);
        RETURN(rc);
}

static int cml_ref_add(const struct lu_context *ctx, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_ref_add(ctx, md_object_next(mo));
        RETURN(rc);
}

static int cml_ref_del(const struct lu_context *ctx, struct md_object *mo,
                       struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mo_ref_del(ctx, md_object_next(mo), ma);
        RETURN(rc);
}

static int cml_open(const struct lu_context *ctx, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_open(ctx, md_object_next(mo));
        RETURN(rc);
}

static int cml_close(const struct lu_context *ctx, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_close(ctx, md_object_next(mo));
        RETURN(rc);
}

static int cml_readpage(const struct lu_context *ctxt, struct md_object *mo,
                        struct lu_rdpg *rdpg)
{
        int rc;
        ENTRY;
        rc = mo_readpage(ctxt, md_object_next(mo), rdpg);
        RETURN(rc);
}

static struct md_object_operations cml_mo_ops = {
        .moo_attr_get      = cml_attr_get,
        .moo_attr_set      = cml_attr_set,
        .moo_xattr_get     = cml_xattr_get,
        .moo_xattr_set     = cml_xattr_set,
        .moo_object_create = cml_object_create,
        .moo_ref_add       = cml_ref_add,
        .moo_ref_del       = cml_ref_del,
        .moo_open          = cml_open,
        .moo_close         = cml_close,
        .moo_readpage      = cml_readpage
};

/* md_dir operations */
static int cml_lookup(const struct lu_context *ctx, struct md_object *mo_p,
                      const char *name, struct lu_fid *lf)
{
        int rc;
        ENTRY;
        rc = mdo_lookup(ctx, md_object_next(mo_p), name, lf);
        RETURN(rc);

}

static int cml_create(const struct lu_context *ctx, struct md_object *mo_p,
                      const char *child_name, struct md_object *mo_c,
                      const char *target_name, struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mdo_create(ctx, md_object_next(mo_p), child_name,
                        md_object_next(mo_c), target_name, ma);
        RETURN(rc);
}

static int cml_link(const struct lu_context *ctx, struct md_object *mo_p,
                    struct md_object *mo_s, const char *name)
{
        int rc;
        ENTRY;
        rc = mdo_link(ctx, md_object_next(mo_p),
                      md_object_next(mo_s), name);
        RETURN(rc);
}

static int cml_unlink(const struct lu_context *ctx, struct md_object *mo_p,
                      struct md_object *mo_c, const char *name,
                      struct md_attr *ma)
{
        int rc;
        ENTRY;
        rc = mdo_unlink(ctx, md_object_next(mo_p), md_object_next(mo_c),
                        name, ma);
        RETURN(rc);
}

/* rename is split to local/remote by location of new parent dir */
static int cml_rename(const struct lu_context *ctx, struct md_object *mo_po,
                       struct md_object *mo_pn, const struct lu_fid *lf,
                       const char *s_name, struct md_object *mo_t,
                       const char *t_name)
{
        int rc;
        ENTRY;

        if (mo_t && lu_object_exists(ctx, &mo_t->mo_lu) < 0) {
                /* mo_t is remote object and there is RPC to unlink it */
                rc = mo_ref_del(ctx, md_object_next(mo_t), NULL);
                if (rc)
                        RETURN(rc);
                mo_t = NULL;
        }
        /* local rename, mo_t can be NULL */
        rc = mdo_rename(ctx, md_object_next(mo_po),
                        md_object_next(mo_pn), lf, s_name,
                        md_object_next(mo_t), t_name);

        RETURN(rc);
}

static int cml_rename_tgt(const struct lu_context *ctx,
                          struct md_object *mo_p, struct md_object *mo_t,
                          const struct lu_fid *lf, const char *name)
{
        int rc;
        ENTRY;

        rc = mdo_rename_tgt(ctx, md_object_next(mo_p),
                            md_object_next(mo_t), lf, name);
        RETURN(rc);
}
/* used only in case of rename_tgt() when target is not exist */
static int cml_name_insert(const struct lu_context *ctx,
                           struct md_object *p, const char *name,
                           const struct lu_fid *lf)
{
        int rc;
        ENTRY;

        rc = mdo_name_insert(ctx, md_object_next(p), name, lf);

        RETURN(rc);
}

static struct md_dir_operations cml_dir_ops = {
        .mdo_lookup      = cml_lookup,
        .mdo_create      = cml_create,
        .mdo_link        = cml_link,
        .mdo_unlink      = cml_unlink,
        .mdo_name_insert = cml_name_insert,
        .mdo_rename      = cml_rename,
        .mdo_rename_tgt  = cml_rename_tgt,
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
static void cmr_object_free(const struct lu_context *ctx,
                            struct lu_object *lo)
{
        struct cmr_object *cro = lu2cmr_obj(lo);
        lu_object_fini(lo);
        OBD_FREE_PTR(cro);
}

static int cmr_object_init(const struct lu_context *ctx, struct lu_object *lo)
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
                c_obj = c_dev->ld_ops->ldo_object_alloc(ctx,
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

/* -1 is returned for remote object */
static int cmr_object_exists(const struct lu_context *ctx,
                             const struct lu_object *lo)
{
        return -1;
}

static int cmr_object_print(const struct lu_context *ctx, void *cookie,
                            lu_printer_t p, const struct lu_object *lo)
{
	return (*p)(ctx, cookie, LUSTRE_CMM0_NAME"-remote@%p", lo);
}

static struct lu_object_operations cmr_obj_ops = {
	.loo_object_init    = cmr_object_init,
	.loo_object_free    = cmr_object_free,
	.loo_object_print   = cmr_object_print,
	.loo_object_exists  = cmr_object_exists
};

/* CMM remote md_object operations. All are invalid */
static int cmr_object_create(const struct lu_context *ctx,
                             struct md_object *mo,
                             struct md_attr *ma)
{
        RETURN(-EFAULT);
}

static int cmr_attr_get(const struct lu_context *ctx, struct md_object *mo,
                        struct lu_attr *attr)
{
        RETURN(-EREMOTE);
}

static int cmr_attr_set(const struct lu_context *ctx, struct md_object *mo,
                        const struct lu_attr *attr)
{
        RETURN(-EFAULT);
}

static int cmr_xattr_get(const struct lu_context *ctx, struct md_object *mo,
                         void *buf, int buflen, const char *name)
{
        RETURN(-EFAULT);
}

static int cmr_xattr_set(const struct lu_context *ctx, struct md_object *mo,
                         const void *buf, int buflen, const char *name)
{
        RETURN(-EFAULT);
}

static int cmr_ref_add(const struct lu_context *ctx, struct md_object *mo)
{
        RETURN(-EFAULT);
}

static int cmr_ref_del(const struct lu_context *ctx, struct md_object *mo,
                       struct md_attr *ma)
{
        RETURN(-EFAULT);
}

static int cmr_open(const struct lu_context *ctx, struct md_object *mo)
{
        RETURN(-EREMOTE);
}

static int cmr_close(const struct lu_context *ctx, struct md_object *mo)
{
        RETURN(-EFAULT);
}

static struct md_object_operations cmr_mo_ops = {
        .moo_attr_get      = cmr_attr_get,
        .moo_attr_set      = cmr_attr_set,
        .moo_xattr_get     = cmr_xattr_get,
        .moo_xattr_set     = cmr_xattr_set,
        .moo_object_create = cmr_object_create,
        .moo_ref_add       = cmr_ref_add,
        .moo_ref_del       = cmr_ref_del,
        .moo_open          = cmr_open,
        .moo_close         = cmr_close
};

/* remote part of md_dir operations */
static int cmr_lookup(const struct lu_context *ctx, struct md_object *mo_p,
                      const char *name, struct lu_fid *lf)
{
        /*this can happens while rename()
         * If new parent is remote dir, lookup will happens here */

        RETURN(-EREMOTE);
}

/*
 * All methods below are cross-ref by nature. They consist of remote call and
 * local operation. Due to future rollback functionality there are several
 * limitations for such methods:
 * 1) remote call should be done at first to do epoch negotiation between all
 * MDS involved and to avoid the RPC inside transaction.
 * 2) only one RPC can be sent - also due to epoch negotiation.
 * For more details see rollback HLD/DLD.
 *
 */
static int cmr_create(const struct lu_context *ctx, struct md_object *mo_p,
                      const char *child_name, struct md_object *mo_c,
                      const char *target_name, struct md_attr *ma)
{
        int rc;

        ENTRY;

        //XXX: make sure that MDT checks name isn't exist

        /* remote object creation and local name insert */
        rc = mo_object_create(ctx, md_object_next(mo_c), ma);
        if (rc == 0) {
                rc = mdo_name_insert(ctx, md_object_next(mo_p),
                                     child_name, lu_object_fid(&mo_c->mo_lu));
        }

        RETURN(rc);
}

static int cmr_link(const struct lu_context *ctx, struct md_object *mo_p,
                    struct md_object *mo_s, const char *name)
{
        int rc;
        ENTRY;

        //XXX: make sure that MDT checks name isn't exist

        rc = mo_ref_add(ctx, md_object_next(mo_s));
        if (rc == 0) {
                rc = mdo_name_insert(ctx, md_object_next(mo_p),
                                     name, lu_object_fid(&mo_s->mo_lu));
        }

        RETURN(rc);
}

static int cmr_unlink(const struct lu_context *ctx, struct md_object *mo_p,
                      struct md_object *mo_c, const char *name,
                      struct md_attr *ma)
{
        int rc;
        ENTRY;

        rc = mo_ref_del(ctx, md_object_next(mo_c), ma);
        if (rc == 0) {
                rc = mdo_name_remove(ctx, md_object_next(mo_p),
                                     name);
        }

        RETURN(rc);
}

static int cmr_rename(const struct lu_context *ctx, struct md_object *mo_po,
                       struct md_object *mo_pn, const struct lu_fid *lf,
                       const char *s_name, struct md_object *mo_t,
                       const char *t_name)
{
        int rc;
        ENTRY;

        /* the mo_pn is remote directory, so we cannot even know if there is
         * mo_t or not. Therefore mo_t is NULL here but remote server should do
         * lookup and process this further */

        LASSERT(mo_t == NULL);
        rc = mdo_rename_tgt(ctx, md_object_next(mo_pn),
                            NULL/* mo_t */, lf, t_name);
        /* only old name is removed localy */
        if (rc == 0)
                rc = mdo_name_remove(ctx, md_object_next(mo_po),
                                     s_name);

        RETURN(rc);
}

/* part of cross-ref rename(). Used to insert new name in new parent
 * and unlink target with same name if it exists */
static int cmr_rename_tgt(const struct lu_context *ctx,
                          struct md_object *mo_p, struct md_object *mo_t,
                          const struct lu_fid *lf, const char *name)
{
        int rc;
        ENTRY;
        /* target object is remote one */
        rc = mo_ref_del(ctx, md_object_next(mo_t), NULL);
        /* continue locally with name handling only */
        if (rc == 0)
                rc = mdo_rename_tgt(ctx, md_object_next(mo_p),
                                    NULL, lf, name);
        RETURN(rc);
}

static struct md_dir_operations cmr_dir_ops = {
        .mdo_lookup      = cmr_lookup,
        .mdo_create      = cmr_create,
        .mdo_link        = cmr_link,
        .mdo_unlink      = cmr_unlink,
        .mdo_rename      = cmr_rename,
        .mdo_rename_tgt  = cmr_rename_tgt,
};


