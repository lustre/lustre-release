/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_lov.c
 *  Lustre Metadata Server (mds) handling of striped file data
 *
 *  Copyright (C) 2001-2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *           wangdi <wangdi@clusterfs.com>
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
#include <obd_lov.h>
#include <lprocfs_status.h>

#include <lu_object.h>
#include <md_object.h>
#include <dt_object.h>
#include <lustre_mds.h>
#include <lustre_fid.h>
#include <lustre/lustre_idl.h>

#include "mdd_internal.h"

static const char mdd_lov_objid_name[] = "lov_objid";

static int mdd_lov_read_objids(struct obd_device *obd, struct md_lov_info *mli,
                               const void *ctxt)
{
        struct dt_object *obj_ids = mli->md_lov_objid_obj;
        struct lu_attr *lu_attr = NULL;
        obd_id *ids;
        int i, rc;
        loff_t off = 0;
        ENTRY;

        LASSERT(!mli->md_lov_objids_size);
        LASSERT(!mli->md_lov_objids_dirty);

        /* Read everything in the file, even if our current lov desc
           has fewer targets. Old targets not in the lov descriptor
           during mds setup may still have valid objids. */

        OBD_ALLOC_PTR(lu_attr);
        if (!lu_attr)
                GOTO(out, rc = -ENOMEM);
        rc = obj_ids->do_ops->do_attr_get(ctxt, obj_ids, lu_attr);
        if (rc)
                GOTO(out, rc);

        if (lu_attr->la_size == 0)
                GOTO(out, rc);

        OBD_ALLOC(ids, lu_attr->la_size);
        if (ids == NULL)
                RETURN(-ENOMEM);

        mli->md_lov_objids = ids;
        mli->md_lov_objids_size = lu_attr->la_size;

        rc = obj_ids->do_body_ops->dbo_read(ctxt, obj_ids, (char *)ids,
                                            lu_attr->la_size, &off);
        if (rc < 0) {
                CERROR("Error reading objids %d\n", rc);
                RETURN(rc);
        }

        mli->md_lov_objids_in_file = lu_attr->la_size / sizeof(*ids);

        for (i = 0; i < mli->md_lov_objids_in_file; i++) {
                CDEBUG(D_INFO, "read last object "LPU64" for idx %d\n",
                       mli->md_lov_objids[i], i);
        }
out:
        if (lu_attr)
                OBD_FREE_PTR(lu_attr);
        RETURN(0);
}

int mdd_lov_write_objids(struct obd_device *obd, struct md_lov_info *mli,
                         const void *ctxt)
{
        int i, rc = 0, tgts;
        ENTRY;

        if (!mli->md_lov_objids_dirty)
                RETURN(0);

        tgts = max(mli->md_lov_desc.ld_tgt_count,
                   mli->md_lov_objids_in_file);
        if (!tgts)
                RETURN(0);

        for (i = 0; i < tgts; i++)
                CDEBUG(D_INFO, "writing last object "LPU64" for idx %d\n",
                       mli->md_lov_objids[i], i);
#if 0
        rc = ids_obj->do_body_ops->dbo_write(ctxt, obj_ids,
                                             (char *)mli->mdd_lov_objids,
                                             tgts * sizeof(obd_id), &off,
                                             NULL /* XXX transaction handle */);
        if (rc >= 0) {
                mli->mdd_lov_objids_dirty = 0;
                rc = 0;
        }
#endif
        RETURN(rc);
}
static int mdd_lov_write_catlist(struct obd_device *obd, void *idarray, int size,
                                 const void *ctxt)
{
        int rc = 0;
        RETURN(rc);
}

static int mdd_lov_read_catlist(struct obd_device *obd, void *idarray, int size,
                                const void *ctxt)
{
        int rc = 0;
        RETURN(rc);
}

static struct md_lov_ops mdd_lov_ops = {
        .ml_read_objids = mdd_lov_read_objids,
        .ml_write_objids = mdd_lov_write_objids,
        .ml_read_catlist = mdd_lov_read_catlist,
        .ml_write_catlist = mdd_lov_write_catlist
};

static int mdd_lov_update(struct obd_device *host,
                          struct obd_device *watched,
                          enum obd_notify_event ev, void *owner)
{
        struct mdd_device *mdd = owner;
        struct obd_device *obd;
        struct md_device *upcall_dev;
        int rc;
        ENTRY;

        LASSERT(owner != NULL);
        obd = mdd2_obd(mdd);

        upcall_dev = mdd->mdd_md_dev.md_upcall.mu_upcall_dev;

        rc = upcall_dev->md_upcall.mu_upcall(NULL, upcall_dev, MD_LOV_SYNC);

        RETURN(rc);
}

/*The obd is created for handling data stack for mdd*/
int mdd_init_obd(const struct lu_context *ctxt, struct mdd_device *mdd,
                 char *dev)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg      *lcfg;
        struct obd_device      *obd;
        struct dt_object *obj_id;
        struct md_lov_info    *mli;
        int rc;
        ENTRY;

        lustre_cfg_bufs_reset(&bufs, MDD_OBD_NAME);
        lustre_cfg_bufs_set_string(&bufs, 1, MDD_OBD_TYPE);
        lustre_cfg_bufs_set_string(&bufs, 2, MDD_OBD_UUID);
        lustre_cfg_bufs_set_string(&bufs, 3, MDD_OBD_PROFILE);
        lustre_cfg_bufs_set_string(&bufs, 4, (char*)dev);

        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
        if (!lcfg)
                RETURN(-ENOMEM);

        rc = class_attach(lcfg);
        if (rc)
                GOTO(lcfg_cleanup, rc);

        obd = class_name2obd(MDD_OBD_NAME);
        if (!obd) {
                CERROR("can not find obd %s \n", MDD_OBD_NAME);
                LBUG();
        }

        /*init mli, which will be used in following mds setup*/
        mli = &obd->u.mds.mds_lov_info;
        mli->md_lov_ops = &mdd_lov_ops;

        obj_id = dt_store_open(ctxt, mdd->mdd_child, mdd_lov_objid_name,
                               &mli->md_lov_objid_fid);
        if (IS_ERR(obj_id)){
                rc = PTR_ERR(obj_id);
                RETURN(rc);
        }
        mli->md_lov_objid_obj = obj_id;

        rc = class_setup(obd, lcfg);
        if (rc)
                GOTO(class_detach, rc);
        /*Add here for obd notify mechiasm,
         *when adding a new ost, the mds will notify this mdd*/

        obd->obd_upcall.onu_owner = mdd;
        obd->obd_upcall.onu_upcall = mdd_lov_update;
        mdd->mdd_md_dev.md_lu_dev.ld_obd = obd;
class_detach:
        if (rc)
                class_detach(obd, lcfg);
lcfg_cleanup:
        lustre_cfg_free(lcfg);
        RETURN(rc);
}

int mdd_cleanup_obd(struct mdd_device *mdd)
{
        struct lustre_cfg_bufs bufs;
        struct md_lov_info     *mli;
        struct lustre_cfg      *lcfg;
        struct obd_device      *obd;
        int rc;
        ENTRY;

        obd = mdd->mdd_md_dev.md_lu_dev.ld_obd;
        LASSERT(obd);

        mli = &obd->u.mds.mds_lov_info;
        dt_object_fini(mli->md_lov_objid_obj);

        lustre_cfg_bufs_reset(&bufs, MDD_OBD_NAME);
        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
        if (!lcfg)
                RETURN(-ENOMEM);

        rc = class_cleanup(obd, lcfg);
        if (rc)
                GOTO(lcfg_cleanup, rc);

        rc = class_detach(obd, lcfg);
        if (rc)
                GOTO(lcfg_cleanup, rc);
        mdd->mdd_md_dev.md_lu_dev.ld_obd = NULL;
lcfg_cleanup:
        lustre_cfg_free(lcfg);
        RETURN(rc);
}

int mdd_get_md(const struct lu_context *ctxt, struct md_object *obj,
               void *md, int *md_size)
{
        struct dt_object *next;
        int rc = 0;
        ENTRY;

        next = mdd_object_child(md2mdd_obj(obj));
        rc = next->do_ops->do_xattr_get(ctxt, next, md, *md_size,
                                        MDS_LOV_MD_NAME);
        /*
         * XXX: handling of -ENODATA, the right way is to have ->do_md_get()
         * exported by dt layer.
         */
        if (rc == 0 || rc == -ENODATA) {
                *md_size = 0;
                rc = 0;
        } else if (rc < 0) {
                CERROR("Error %d reading eadata \n", rc);
        } else if (rc > 0) {
                /*FIXME convert lov EA necessary for this version?*/
                *md_size = rc;
        }

        RETURN (rc);
}

int mdd_lov_set_md(const struct lu_context *ctxt, struct md_object *pobj,
                   struct md_object *child, struct lov_mds_md *lmmp,
                   int lmm_size, int mode)
{
        int rc = 0;
        ENTRY;

        if (S_ISREG(mode) && lmm_size > 0) {
                LASSERT(lmmp != NULL);
                rc = mdd_xattr_set(ctxt, child, lmmp, lmm_size,
                                   MDS_LOV_MD_NAME, 0);
                if (rc)
                        CERROR("error on set stripe info: rc = %d\n", rc);
        }else  if (S_ISDIR(mode)) {
                struct lov_mds_md *lmm = &mdd_ctx_info(ctxt)->mti_lmm;
                int size = sizeof(lmm);
                rc = mdd_get_md(ctxt, pobj, &lmm, &size);
                if (rc > 0) {
                        rc = mdd_xattr_set(ctxt, child, lmm, size,
                                           /*
                                            * Flags are 0: we don't care
                                            * whether attribute exists
                                            * already.
                                            */
                                           MDS_LOV_MD_NAME, 0);
                        if (rc)
                                CERROR("error on copy stripe info: rc = %d\n",
                                        rc);
                }
        }

        RETURN(rc);
}

/*FIXME: this is for create lsm object id, which should identify the
 * lsm object unique in the whole mds, as I see. But it seems, we
 * still not need it now. right? so just borrow the ll_fid_build_ino
 */
static obd_id mdd_lov_create_id(struct lu_fid *fid)
{
        return ((fid_seq(fid) - 1) * LUSTRE_SEQ_MAX_WIDTH + fid_oid(fid));
}

int mdd_lov_create(const struct lu_context *ctxt, struct mdd_device *mdd,
                   struct mdd_object *parent, struct mdd_object *child,
                   struct lov_mds_md **lmm, int *lmm_size, const void *eadata,
                   int eadatasize, struct lu_attr *la)
{
        struct obd_device *obd = mdd2_obd(mdd);
        struct obd_export *lov_exp = obd->u.mds.mds_osc_exp;
        struct obdo *oa;
        struct lov_stripe_md *lsm = NULL;
        int rc = 0;
        ENTRY;

        if (la->la_flags & MDS_OPEN_DELAY_CREATE ||
                        !(la->la_flags & FMODE_WRITE))
                RETURN(0);

        oa = obdo_alloc();

        oa->o_uid = 0; /* must have 0 uid / gid on OST */
        oa->o_gid = 0;
        oa->o_mode = S_IFREG | 0600;
        oa->o_id = mdd_lov_create_id(lu_object_fid(mdd2lu_obj(child)));
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLFLAGS |
                OBD_MD_FLMODE | OBD_MD_FLUID | OBD_MD_FLGID;
        oa->o_size = 0;

        if (!(la->la_flags & MDS_OPEN_HAS_OBJS)) {
                if (la->la_flags & MDS_OPEN_HAS_EA) {
                        LASSERT(eadata != NULL);
                        rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE, lov_exp,
                                           0, &lsm, (void*)eadata);
                        if (rc)
                                GOTO(out_oa, rc);
                } else {
                        LASSERT(*lmm == NULL);
                        rc = mdd_get_md(ctxt, &parent->mod_obj, *lmm,
                                        lmm_size);
                        if (rc > 0)
                                rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                                   lov_exp, 0, &lsm, *lmm);
                }
                rc = obd_create(lov_exp, oa, &lsm, NULL);
                if (rc) {
                        if (rc > 0) {
                                CERROR("obd_create returned invalid "
                                       "rc %d\n", rc);
                                rc = -EIO;
                        }
                        GOTO(out_oa, rc);
                }
        } else {
                LASSERT(eadata != NULL);
                rc = obd_iocontrol(OBD_IOC_LOV_SETEA, lov_exp, 0, &lsm,
                                   (void*)eadata);
                if (rc) {
                        GOTO(out_oa, rc);
                }
                lsm->lsm_object_id = oa->o_id;
        }

        rc = obd_packmd(lov_exp, lmm, lsm);
        if (rc < 0) {
                CERROR("cannot pack lsm, err = %d\n", rc);
                GOTO(out_oa, rc);
        }
        *lmm_size = rc;
        rc = 0;
out_oa:
        obdo_free(oa);
        RETURN(rc);
}

int mdd_unlink_log(const struct lu_context *ctxt, struct mdd_device *mdd,
                   struct mdd_object *mdd_cobj, struct md_attr *ma)
{
        struct obd_device *obd = mdd2_obd(mdd);

        if (mds_log_op_unlink(obd, NULL, ma->ma_lmm, ma->ma_lmm_size,
                                 ma->ma_cookie, ma->ma_cookie_size)) {
                ma->ma_valid |= MA_COOKIE;
        }
        return 0;
}

int mdd_lov_mdsize(const struct lu_context *ctxt, struct mdd_device *mdd,
                   int *md_size)
{
        struct obd_device *obd = mdd2_obd(mdd);
        *md_size = obd->u.mds.mds_max_mdsize;
        RETURN(0);
}

int mdd_lov_cookiesize(const struct lu_context *ctxt, struct mdd_device *mdd,
                       int *cookie_size)
{
        struct obd_device *obd = mdd2_obd(mdd);
        *cookie_size = obd->u.mds.mds_max_cookiesize;
        RETURN(0);
}

