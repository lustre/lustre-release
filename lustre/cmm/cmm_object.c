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

#include "cmm_internal.h"
#include "mdc_internal.h"

#ifdef CMM_CODE
static int cmm_fld_lookup(const struct lu_fid *fid)
{
        int rc;
        /* temporary hack for proto mkdir */
        rc = (unsigned long)fid_seq(fid) / LUSTRE_SEQ_RANGE;
        CWARN("Get MDS %d for sequence: "LPU64"\n", rc, fid_seq(fid));
        RETURN(rc);
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
        const struct lu_fid *fid = loh->loh_fid;
        int mdsnum, rc;
        ENTRY;

        /* get object location */
        mdsnum = cmm_fld_lookup(fid);

        /* select the proper set of operations based on object location */
        if (mdsnum == lu2cmm_dev(ld)->cmm_local_num) {
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
        return next = &d->cmm_child->md_lu_dev;
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
                             struct lu_object *lo)
{
        return lu_object_exists(ctx, lu_object_next(lo));
}

static int cml_object_print(const struct lu_context *ctx,
                            struct seq_file *f, const struct lu_object *lo)
{
	return seq_printf(f, LUSTRE_CMM0_NAME"-object@%p", lo);
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
                             struct lu_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_object_create(ctx, cmm2child_obj(md2cmm_obj(mo)), attr);
        RETURN(rc);
}

static int cml_attr_get(const struct lu_context *ctx, struct md_object *mo,
                        struct lu_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_attr_get(ctx, cmm2child_obj(md2cmm_obj(mo)), attr);
        RETURN(rc);
}

static int cml_attr_set(const struct lu_context *ctx, struct md_object *mo,
                        struct lu_attr *attr)
{
        int rc;
        ENTRY;
        rc = mo_attr_set(ctx, cmm2child_obj(md2cmm_obj(mo)), attr);
        RETURN(rc);
}

static int cml_xattr_get(const struct lu_context *ctx, struct md_object *mo,
                         void *buf, int buflen, const char *name)
{
        int rc;
        ENTRY;
        rc = mo_xattr_get(ctx, cmm2child_obj(md2cmm_obj(mo)),
                         buf, buflen, name);
        RETURN(rc);
}

static int cml_xattr_set(const struct lu_context *ctx, struct md_object *mo,
                         void *buf, int buflen, const char *name)
{
        int rc;
        ENTRY;
        rc = mo_xattr_set(ctx, cmm2child_obj(md2cmm_obj(mo)),
                          buf, buflen, name);
        RETURN(rc);
}

static int cml_ref_add(const struct lu_context *ctx, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_ref_add(ctx, cmm2child_obj(md2cmm_obj(mo)));
        RETURN(rc);
}

static int cml_ref_del(const struct lu_context *ctx, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_ref_del(ctx, cmm2child_obj(md2cmm_obj(mo)));
        RETURN(rc);
}

static int cml_open(const struct lu_context *ctx, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_open(ctx, cmm2child_obj(md2cmm_obj(mo)));
        RETURN(rc);
}

static int cml_close(const struct lu_context *ctx, struct md_object *mo)
{
        int rc;
        ENTRY;
        rc = mo_close(ctx, cmm2child_obj(md2cmm_obj(mo)));
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
        .moo_close         = cml_close
};

/* md_dir operations */
static int cml_lookup(const struct lu_context *ctx, struct md_object *mo_p,
                      const char *name, struct lu_fid *lf)
{
        int rc;
        ENTRY;
        rc = mdo_lookup(ctx, cmm2child_obj(md2cmm_obj(mo_p)), name, lf);
        RETURN(rc);

}

static int cml_create(const struct lu_context *ctx,
                      struct md_object *mo_p, const char *name,
                      struct md_object *mo_c, struct lu_attr *attr)
{
        int rc;
        ENTRY;
        rc = mdo_create(ctx, cmm2child_obj(md2cmm_obj(mo_p)), name,
                        cmm2child_obj(md2cmm_obj(mo_c)), attr);
        RETURN(rc);
}

static int cml_link(const struct lu_context *ctx, struct md_object *mo_p,
                    struct md_object *mo_s, const char *name)
{
        int rc;
        ENTRY;
        rc = mdo_link(ctx, cmm2child_obj(md2cmm_obj(mo_p)),
                      cmm2child_obj(md2cmm_obj(mo_s)), name);
        RETURN(rc);
}

static int cml_unlink(const struct lu_context *ctx, struct md_object *mo_p,
                      struct md_object *mo_c, const char *name)
{
        int rc;
        ENTRY;
        rc = mdo_unlink(ctx, cmm2child_obj(md2cmm_obj(mo_p)),
                        cmm2child_obj(md2cmm_obj(mo_c)), name);
        RETURN(rc);
}

static int cml_rename(const struct lu_context *ctx, struct md_object *mo_po,
                       struct md_object *mo_pn, struct md_object *mo_s,
                       const char *s_name, struct md_object *mo_t,
                       const char *t_name)
{
        int rc;
        ENTRY;

        if (mo_t && !cmm_is_local_obj(md2cmm_obj(mo_t))) {
                /* remote object */
                rc = moo_ref_del(ctx, cmm2child_obj(md2cmm_obj(mo_t)));
                if (rc)
                        RETURN(rc);
                mo_t = NULL;
        }

        rc = mdo_rename(ctx, cmm2child_obj(md2cmm_obj(mo_po)),
                        cmm2child_obj(md2cmm_obj(mo_pn)),
                        cmm2child_obj(md2cmm_obj(mo_s)), s_name,
                        cmm2child_obj(md2cmm_obj(mo_t)), t_name);
        RETURN(rc);
}

static int cml_rename_tgt(const struct lu_context *ctx,
                          struct md_object *mo_p,
                          struct md_object *mo_s, struct md_object *mo_t,
                          const char *name)
{
        int rc;
        ENTRY;

        rc = mdo_rename_tgt(ctx, cmm2child_obj(md2cmm_obj(mo_po)),
                            cmm2child_obj(md2cmm_obj(mo_s)),
                            cmm2child_obj(md2cmm_obj(mo_t)), name);
        RETURN(rc);
}

static int cml_name_insert(const struct lu_context * ctx,
                           struct md_object *mo_p,
                           const char *name, const struct lu_fid *lf)
{
        int rc;
        ENTRY;
        
        rc = mdo_name_insert(ctx, cmm2child_obj(md2cmm_obj(mo_po)), name, lf);

        RETURN(rc);
}

static struct md_dir_operations cmm_dir_ops = {
        .mdo_lookup      = cml_lookup,
        .mdo_create      = cml_create,
        .mdo_link        = cml_link,
        .mdo_unlink      = cml_unlink,
        .mdo_rename      = cml_rename,
        .mdo_rename_tgt  = cml_rename_tgt,
        .mdo_name_insert = cml_name_insert
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

/* get local child device */
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
        const struct lu_fid *fid = lu_object_fid(lo);
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


static int cmr_object_exists(const struct lu_context *ctx,
                             struct lu_object *lo)
{
        return lu_object_exists(ctx, lu_object_next(lo));
}

static int cmr_object_print(const struct lu_context *ctx,
                            struct seq_file *f, const struct lu_object *lo)
{
	return seq_printf(f, LUSTRE_CMM0_NAME"-object@%p", lo);
}

static struct lu_object_operations cml_obj_ops = {
	.loo_object_init    = cmr_object_init,
	.loo_object_free    = cmr_object_free,
	.loo_object_print   = cmr_object_print,
	.loo_object_exists  = cmr_object_exists
};

/* CMM remote md_object operations. All are invalid */
static int cmr_object_create(const struct lu_context *ctx,
                             struct md_object *mo,
                             struct lu_attr *attr)
{
        RETURN(-EFAULT);
}

static int cmr_attr_get(const struct lu_context *ctx, struct md_object *mo,
                        struct lu_attr *attr)
{
        RETURN(-EFAULT);
}

static int cmr_attr_set(const struct lu_context *ctx, struct md_object *mo,
                        struct lu_attr *attr)
{
        RETURN(-EFAULT);
}

static int cmr_xattr_get(const struct lu_context *ctx, struct md_object *mo,
                         void *buf, int buflen, const char *name)
{
        RETURN(-EFAULT);
}

static int cmr_xattr_set(const struct lu_context *ctx, struct md_object *mo,
                         void *buf, int buflen, const char *name)
{
        RETURN(-EFAULT);
}

static int cmr_ref_add(const struct lu_context *ctx, struct md_object *mo)
{
        RETURN(-EFAULT);
}

static int cmr_ref_del(const struct lu_context *ctx, struct md_object *mo)
{
        RETURN(-EFAULT);
}

static int cmr_open(const struct lu_context *ctx, struct md_object *mo)
{
        RETURN(-EFAULT);
}

static int cmr_close(const struct lu_context *ctx, struct md_object *mo)
{
        RETURN(-EFAULT);
}

static struct md_object_operations cml_mo_ops = {
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
        RETURN(-EFAULT);
}

static int cmr_create(const struct lu_context *ctx,
                      struct md_object *mo_p, const char *name,
                      struct md_object *mo_c, struct lu_attr *attr)
{
        int rc;

        ENTRY;

        //TODO: check the name isn't exist

        /* remote object creation and local name insert */
        rc = mo_object_create(ctx, cmm2child_obj(md2cmm_obj(mo_c)), attr);
        if (rc == 0) {
                rc = mdo_name_insert(ctx, cmm2child_obj(md2cmm_obj(mo_p)),
                                     name, lu_object_fid(&mo_c->mo_lu));
        }

        RETURN(rc);
}

static int cmr_link(const struct lu_context *ctx, struct md_object *mo_p,
                    struct md_object *mo_s, const char *name)
{
        int rc;
        ENTRY;

        //TODO: check the name isn't exist

        rc = mo_ref_add(ctx, cmm2child_obj(md2cmm_obj(mo_s)));
        if (rc == 0) {
                rc = mdo_name_insert(ctx, cmm2child_obj(md2cmm_obj(mo_p)),
                                     name, lu_object_fid(&mo_s->mo_lu));
        }

        RETURN(rc);
}

static int cmr_unlink(const struct lu_context *ctx, struct md_object *mo_p,
                      struct md_object *mo_c, const char *name)
{
        int rc;
        ENTRY;

        rc = mo_ref_del(ctx, cmm2child_obj(md2cmm_obj(mo_c)));
        if (rc == 0) {
                rc = mdo_name_remove(ctx, cmm2child_obj(md2cmm_obj(mo_p)),
                                     name, lu_object_fid(&mo_c->mo_lu));
        }

        RETURN(rc);
}

static int cmr_rename(const struct lu_context *ctx, struct md_object *mo_po,
                       struct md_object *mo_pn, struct md_object *mo_s,
                       const char *s_name, struct md_object *mo_t,
                       const char *t_name)
{
        int rc;
        ENTRY;
        rc = mdo_rename(ctx, cmm2child_obj(md2cmm_obj(mo_po)),
                        cmm2child_obj(md2cmm_obj(mo_pn)),
                        cmm2child_obj(md2cmm_obj(mo_s)), s_name,
                        cmm2child_obj(md2cmm_obj(mo_t)), t_name);
        
        if (mo_t == NULL) { 
                rc = mdo_name_insert(ctx, c_pn, t_name, lu_object_fid(c_s->mo_lu));
                rc = mdo_name_remove(ctx, c_po, s_name); 
        } else {
                c_t =  cmm2child_obj(md2cmm_obj(mo_t));
                if (cmm_is_local_obj(md2cmm_obj(mo_t))) {
                        /*
                         * target object is local so only name should
                         * deleted/inserted on remote server 
                         */
                        rc = mdo_rename_tgt(ctx, c_pn, c_s,
                                            NULL, t_name);
                        /* localy the old name will be removed and target object
                         * will be destroeyd*/
                        rc = mdo_rename(ctx, c_po, NULL, c_s, 
                                        s_name, c_t, NULL); 
               } else {
                        /* target object is remote one so just ask remote server
                         * to continue with rename */
                        rc = mdo_rename_tgt(ctx, c_pn, c_s,
                                            c_t, t_name);
                        /* only old name is removed localy */
                        rc = mdo_name_destroy(ctx, c_po, s_name); 
               }
       }

        RETURN(rc);
}

static int cmr_rename_tgt(const struct lu_context *ctx,
                          struct md_object *mo_p,
                          struct md_object *mo_s, struct md_object *mo_t,
                          const char *name)
{
        int rc;
        ENTRY;
        /* target object is remote one */
        rc = mo_ref_del(ctx, cmm2child_obj(md2cmm_obj(mo_t)));
        /* continue locally with name handling only */
        rc = mdo_rename_tgt(ctx, cmm2child_obj(md2cmm_obj(mo_po)),
                            cmm2child_obj(md2cmm_obj(mo_s)),
                            NULL, name);
        RETURN(rc);
}

static int cmr_name_insert(const struct lu_context * ctx,
                           struct md_object *mo_p,
                           const char *name, const struct lu_fid *lf)
{
        RETURN(-EFAULT);
}

static struct md_dir_operations cmm_dir_ops = {
        .mdo_lookup      = cmr_lookup,
        .mdo_create      = cmr_create,
        .mdo_link        = cmr_link,
        .mdo_unlink      = cmr_unlink,
        .mdo_rename      = cmr_rename,
        .mdo_rename_tgt  = cmr_rename_tgt,
        .mdo_name_insert = cmr_name_insert,
};

#else /* CMM_CODE */
static struct md_object_operations cmm_mo_ops;
static struct md_dir_operations    cmm_dir_ops;
static struct lu_object_operations cmm_obj_ops;

static int cmm_fld_lookup(const struct lu_fid *fid)
{
        int rc;
        /* temporary hack for proto mkdir */
        rc = (unsigned long)fid_seq(fid) / LUSTRE_SEQ_RANGE;
        CWARN("Get MDS %d for sequence: "LPU64"\n", rc, fid_seq(fid));
        RETURN(rc);
}

/* get child device by mdsnum*/
static struct lu_device *cmm_get_child(struct cmm_device *d, __u32 num)
{
        struct lu_device *next = NULL;
        ENTRY;
        if (likely(num == d->cmm_local_num)) {
	        next = &d->cmm_child->md_lu_dev;
        } else {
                struct mdc_device *mdc;
                list_for_each_entry(mdc, &d->cmm_targets, mc_linkage) {
                        if (mdc->mc_num == num) {
                                next = mdc2lu_dev(mdc);
                                break;
                        }
                }
        }
        RETURN(next);
}

struct lu_object *cmm_object_alloc(const struct lu_context *ctx,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *ld)
{
        struct cmm_object *co;
        struct lu_object  *lo;
        ENTRY;

        OBD_ALLOC_PTR(co);
	if (co != NULL) {
		lo = &co->cmo_obj.mo_lu;
                lu_object_init(lo, NULL, ld);
                co->cmo_obj.mo_ops = &cmm_mo_ops;
                co->cmo_obj.mo_dir_ops = &cmm_dir_ops;
                lo->lo_ops = &cmm_obj_ops;
        } else
                lo = NULL;

        RETURN(lo);
}

static void cmm_object_free(const struct lu_context *ctx, struct lu_object *lo)
{
        struct cmm_object *co = lu2cmm_obj(lo);
        lu_object_fini(lo);
        OBD_FREE_PTR(co);
}

static int cmm_object_init(const struct lu_context *ctx, struct lu_object *lo)
{
        struct cmm_device *cd = lu2cmm_dev(lo->lo_dev);
        struct lu_device  *c_dev;
        struct lu_object  *c_obj;
        const struct lu_fid *fid = lu_object_fid(lo);
        int mdsnum, rc;

        ENTRY;

        /* under device can be MDD or MDC */
        mdsnum = cmm_fld_lookup(fid);
        c_dev = cmm_get_child(cd, mdsnum);
        if (c_dev == NULL) {
                rc = -ENOENT;
        } else {
                c_obj = c_dev->ld_ops->ldo_object_alloc(ctx,
                                                        lo->lo_header, c_dev);
                if (c_obj != NULL) {
                        struct cmm_object *co = lu2cmm_obj(lo);

                        lu_object_add(lo, c_obj);
                        co->cmo_num = mdsnum;
                        rc = 0;
                } else {
                        rc = -ENOMEM;
                }
        }

        RETURN(rc);
}

static int cmm_object_exists(const struct lu_context *ctx, struct lu_object *lo)
{
        return lu_object_exists(ctx, lu_object_next(lo));
}

static int cmm_object_print(const struct lu_context *ctx,
                            struct seq_file *f, const struct lu_object *lo)
{
	return seq_printf(f, LUSTRE_CMM0_NAME"-object@%p", lo);
}

static struct lu_object_operations cmm_obj_ops = {
	.loo_object_init    = cmm_object_init,
	.loo_object_free    = cmm_object_free,
	.loo_object_print   = cmm_object_print,
	.loo_object_exists  = cmm_object_exists
};

/* md_object operations */
static int cmm_object_create(const struct lu_context *ctx, struct md_object *mo,
                             struct lu_attr *attr)
{
        struct md_object  *ch = cmm2child_obj(md2cmm_obj(mo));
        int rc;

        ENTRY;

        LASSERT (cmm_is_local_obj(md2cmm_obj(mo)));

        rc = mo_object_create(ctx, ch, attr);

        RETURN(rc);
}

static int cmm_attr_get(const struct lu_context *ctx, struct md_object *mo,
                        struct lu_attr *attr)
{
        struct md_object *ch = cmm2child_obj(md2cmm_obj(mo));
        int rc;

        ENTRY;

        LASSERT (cmm_is_local_obj(md2cmm_obj(mo)));

        rc = mo_attr_get(ctx, ch, attr);

        RETURN(rc);
}

static struct md_object_operations cmm_mo_ops = {
        .moo_attr_get      = cmm_attr_get,
        .moo_object_create = cmm_object_create,
};

static int cmm_lookup(const struct lu_context *ctx, struct md_object *mo_p,
                      const char *name, struct lu_fid *lf)
{
        struct md_object *ch_p = cmm2child_obj(md2cmm_obj(mo_p));
        int rc;

        ENTRY;

        LASSERT(cmm_is_local_obj(md2cmm_obj(mo_p)));

        rc = mdo_lookup(ctx, ch_p, name, lf);

        RETURN(rc);

}

static int cmm_create(const struct lu_context *ctx,
                      struct md_object *mo_p, const char *name,
                      struct md_object *mo_c, struct lu_attr *attr)
{
	struct md_object *ch_c = cmm2child_obj(md2cmm_obj(mo_c));
        struct md_object *ch_p = cmm2child_obj(md2cmm_obj(mo_p));
        int rc;

        ENTRY;

        if (cmm_is_local_obj(md2cmm_obj(mo_c))) {
                rc = mdo_create(ctx, ch_p, name, ch_c, attr);
        } else {
                const struct lu_fid *lf = lu_object_fid(&mo_c->mo_lu);

                /* remote object creation and local name insert */
                rc = mo_object_create(ctx, ch_c, attr);
                if (rc == 0) {
                        rc = mdo_name_insert(ctx, ch_p, name, lf);
                }
        }

        RETURN(rc);
}

static int cmm_mkdir(const struct lu_context *ctx, struct lu_attr *attr,
                     struct md_object *mo_p, const char *name,
                     struct md_object *mo_c)
{
	struct md_object *ch_c = cmm2child_obj(md2cmm_obj(mo_c));
        struct md_object *ch_p = cmm2child_obj(md2cmm_obj(mo_p));
        int rc;

        ENTRY;

        if (cmm_is_local_obj(md2cmm_obj(mo_c))) {
                /* fully local mkdir */
                rc = mdo_mkdir(ctx, attr, ch_p, name, ch_c);
        } else {
                const struct lu_fid *lf = lu_object_fid(&mo_c->mo_lu);

                /* remote object creation and local name insert */
                rc = mo_object_create(ctx, ch_c, attr);
                if (rc == 0) {
                        rc = mdo_name_insert(ctx, ch_p, name, lf);
                }
        }

        RETURN(rc);
}

static struct md_dir_operations cmm_dir_ops = {
        .mdo_lookup        = cmm_lookup,
        .mdo_mkdir         = cmm_mkdir,
        .mdo_create        = cmm_create
};
#endif /* CMM_CODE */


