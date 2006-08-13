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

int mdd_get_md(const struct lu_context *ctxt, struct mdd_object *obj,
               void *md, int *md_size, int need_locked)
{
        struct dt_object *next;
        int rc = 0;
        ENTRY;

        if (need_locked)
                mdd_lock(ctxt, obj, DT_READ_LOCK);
        next = mdd_object_child(obj);
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

        if (need_locked)
                mdd_unlock(ctxt, obj, DT_READ_LOCK);

        RETURN (rc);
}

static int mdd_lov_set_stripe_md(const struct lu_context *ctxt,
                                 struct mdd_object *obj, struct lov_mds_md *lmmp,
                                 int lmm_size, struct thandle *handle)
{
        struct mdd_device       *mdd = mdo2mdd(&obj->mod_obj);
        struct obd_device       *obd = mdd2_obd(mdd);
        struct obd_export       *lov_exp = obd->u.mds.mds_osc_exp;
        struct lov_stripe_md    *lsm = NULL;
        int rc;
        ENTRY;
        
        LASSERT(S_ISDIR(mdd_object_type(obj)) && S_ISREG(mdd_object_type(obj)));

        rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE, lov_exp, 0, &lsm, lmmp);
        if (rc)
                RETURN(rc);
        obd_free_memmd(lov_exp, &lsm);

        rc = mdd_xattr_set_txn(ctxt, obj, lmmp, lmm_size, MDS_LOV_MD_NAME, 0, 
                               handle);
        
        CDEBUG(D_INFO, "set lov ea of "DFID" rc %d \n", PFID(mdo2fid(obj)), rc);
        RETURN(rc);
}
                
static int mdd_lov_set_dir_md(const struct lu_context *ctxt, 
                              struct mdd_object *obj, struct lov_mds_md *lmmp,
                              int lmm_size, struct thandle *handle)
{
        struct lov_user_md *lum = NULL;
        int rc = 0;
        ENTRY;

        /*TODO check permission*/
        LASSERT(S_ISDIR(mdd_object_type(obj)));
        lum = (struct lov_user_md*)lmmp;

        /* if { size, offset, count } = { 0, -1, 0 } (i.e. all default
         * values specified) then delete default striping from dir. */
        if ((lum->lmm_stripe_size == 0 && lum->lmm_stripe_count == 0 && 
             lum->lmm_stripe_offset == (typeof(lum->lmm_stripe_offset))(-1)) ||
             /* lmm_stripe_size == -1 is deprecated in 1.4.6 */
             lum->lmm_stripe_size == (typeof(lum->lmm_stripe_size))(-1)){
                rc = mdd_xattr_set_txn(ctxt, obj, NULL, 0, MDS_LOV_MD_NAME, 0, 
                                       handle);
                CDEBUG(D_INFO, "delete lov ea of "DFID" rc %d \n",
                                PFID(mdo2fid(obj)), rc);
        } else {
                rc = mdd_lov_set_stripe_md(ctxt, obj, lmmp, lmm_size, handle); 
        }
        RETURN(rc);
}
        
int mdd_lov_set_md(const struct lu_context *ctxt, struct mdd_object *pobj,
                   struct mdd_object *child, struct lov_mds_md *lmmp,
                   int lmm_size, struct thandle *handle, int set_stripe)
{
        int rc = 0;
        ENTRY;

        if (S_ISREG(mdd_object_type(child)) && lmm_size > 0) {
                if (set_stripe) {
                        rc = mdd_lov_set_stripe_md(ctxt, child, lmmp, lmm_size,
                                                   handle);
                } else {
                        rc = mdd_xattr_set_txn(ctxt, child, lmmp, lmm_size,
                                               MDS_LOV_MD_NAME, 0, handle);
                }
        } else  if (S_ISDIR(mdd_object_type(child))) {
                if (lmmp == NULL && lmm_size == 0) {
                        struct lov_mds_md *lmm = &mdd_ctx_info(ctxt)->mti_lmm;
                        int size = sizeof(lmm);
                        /*Get parent dir stripe and set*/
                        rc = mdd_get_md(ctxt, pobj, &lmm, &size, 0);
                        if (rc > 0) {
                                rc = mdd_xattr_set_txn(ctxt, child, lmm, size,
                                               MDS_LOV_MD_NAME, 0, handle);
                                if (rc)
                                        CERROR("error on copy stripe info: rc = %d\n",
                                                rc);
                        }
                } else {
                       LASSERT(lmmp != NULL && lmm_size > 0);
                        /*delete lmm*/
                       rc = mdd_lov_set_dir_md(ctxt, child, lmmp, lmm_size, handle);
                }
        }
        CDEBUG(D_INFO, "Set lov md %p size %d for fid "DFID" rc%d/n",
                        lmmp, lmm_size, PFID(mdo2fid(child)), rc);
        RETURN(rc);
}

/*FIXME: this is for create lsm object id, which should identify the
 * lsm object unique in the whole mds, as I see. But it seems, we
 * still not need it now. right? so just borrow the ll_fid_build_ino
 */
static obd_id mdd_lov_create_id(const struct lu_fid *fid)
{
        return ((fid_seq(fid) - 1) * LUSTRE_SEQ_MAX_WIDTH + fid_oid(fid));
}

/*FIXME: it is just the helper function used by mdd lov obd to 
 * get attr from obdo, copied from obdo_from_inode*/
static void obdo_from_la(struct obdo *dst, struct lu_attr *la, obd_flag valid)
{
        obd_flag newvalid = 0;

        if (valid & OBD_MD_FLATIME) {
                dst->o_atime = la->la_atime;
                newvalid |= OBD_MD_FLATIME;
        }
        if (valid & OBD_MD_FLMTIME) {
                dst->o_mtime = la->la_mtime;
                newvalid |= OBD_MD_FLMTIME;
        }
        if (valid & OBD_MD_FLCTIME) {
                dst->o_ctime = la->la_ctime;
                newvalid |= OBD_MD_FLCTIME;
        }
        if (valid & OBD_MD_FLSIZE) {
                dst->o_size = la->la_size;
                newvalid |= OBD_MD_FLSIZE;
        }
        if (valid & OBD_MD_FLBLOCKS) {  /* allocation of space (x512 bytes) */
                dst->o_blocks = la->la_blocks;
                newvalid |= OBD_MD_FLBLOCKS;
        }
        if (valid & OBD_MD_FLTYPE) {
                dst->o_mode = (la->la_mode & S_IALLUGO)|(la->la_mode & S_IFMT);
                newvalid |= OBD_MD_FLTYPE;
        }
        if (valid & OBD_MD_FLMODE) {
                dst->o_mode = (la->la_mode & S_IFMT)|(la->la_mode & S_IALLUGO);
                newvalid |= OBD_MD_FLMODE;
        }
        if (valid & OBD_MD_FLUID) {
                dst->o_uid = la->la_uid;
                newvalid |= OBD_MD_FLUID;
        }
        if (valid & OBD_MD_FLGID) {
                dst->o_gid = la->la_gid;
                newvalid |= OBD_MD_FLGID;
        }
        dst->o_valid |= newvalid;
}

int mdd_lov_create(const struct lu_context *ctxt, struct mdd_device *mdd,
                   struct mdd_object *parent, struct mdd_object *child,
                   struct lov_mds_md **lmm, int *lmm_size,
                   const struct md_create_spec *spec, struct lu_attr *la)
{
        struct obd_device       *obd = mdd2_obd(mdd);
        struct obd_export       *lov_exp = obd->u.mds.mds_osc_exp;
        struct obdo             *oa;
        struct lov_stripe_md    *lsm = NULL;
        const void              *eadata = spec->u.sp_ea.eadata;
/*      int                      eadatasize  = spec->u.sp_ea.eadatalen;*/
        __u32                    create_flags = spec->sp_cr_flags;
        int                      rc = 0;
        ENTRY;

        if (create_flags & MDS_OPEN_DELAY_CREATE ||
                        !(create_flags & FMODE_WRITE))
                RETURN(0);

        oa = obdo_alloc();

        oa->o_uid = 0; /* must have 0 uid / gid on OST */
        oa->o_gid = 0;
        oa->o_mode = S_IFREG | 0600;
        oa->o_id = mdd_lov_create_id(lu_object_fid(mdd2lu_obj(child)));
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLFLAGS |
                OBD_MD_FLMODE | OBD_MD_FLUID | OBD_MD_FLGID;
        oa->o_size = 0;

        if (!(create_flags & MDS_OPEN_HAS_OBJS)) {
                if (create_flags & MDS_OPEN_HAS_EA) {
                        LASSERT(eadata != NULL);
                        rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE, lov_exp,
                                           0, &lsm, (void*)eadata);
                        if (rc)
                                GOTO(out_oa, rc);
                } else {
                        /* get lov ea from parent and set to lov */
                        struct lov_mds_md *__lmm;
                        int __lmm_size, returned_lmm_size;
                        __lmm_size = mdd2_obd(mdd)->u.mds.mds_max_mdsize;

                        OBD_ALLOC(__lmm, __lmm_size);
                        if (__lmm == NULL)
                                GOTO(out_oa, rc = -ENOMEM);

                        rc = mdd_get_md(ctxt, parent, __lmm,
                                        &returned_lmm_size, 1);
                        if (rc > 0)
                                rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                                   lov_exp, 0, &lsm, __lmm);
                        OBD_FREE(__lmm, __lmm_size);
                        if (rc)
                                GOTO(out_oa, rc);
                }
                rc = obd_create(lov_exp, oa, &lsm, NULL);
                if (rc) {
                        if (rc > 0) {
                                CERROR("create errro for "DFID": %d \n",
                                       PFID(mdo2fid(child)), rc);
                                rc = -EIO;
                        }
                        GOTO(out_oa, rc);
                }
        } else {
                LASSERT(eadata != NULL);
                rc = obd_iocontrol(OBD_IOC_LOV_SETEA, lov_exp, 0, &lsm,
                                   (void*)eadata);
                if (rc) 
                        GOTO(out_oa, rc);
                lsm->lsm_object_id = oa->o_id;
        }
        /*Sometimes, we may truncate some object(without lsm) 
         *then open (with write flags)it, so creating lsm above. 
         *The Nonzero(truncated) size should tell ost. since size 
         *attr is in charged by OST.
         */
        if (la->la_size && la->la_valid & LA_SIZE) {
                oa->o_size = la->la_size;
                obdo_from_la(oa, la, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                OBD_MD_FLMTIME | OBD_MD_FLCTIME | OBD_MD_FLSIZE);

                /* FIXME:pack lustre id to OST, in OST, it will be packed 
                 * by filter_fid, but can not see what is the usages. So just 
                 * pack o_seq o_ver here, maybe fix it after this cycle*/
                oa->o_fid = lu_object_fid(mdd2lu_obj(child))->f_seq;
                oa->o_generation = lu_object_fid(mdd2lu_obj(child))->f_oid;
                oa->o_valid |= OBD_MD_FLFID | OBD_MD_FLGENER;

                rc = obd_setattr(lov_exp, oa, lsm, NULL);
                if (rc) {
                        CERROR("error setting attrs for "DFID": rc %d\n",
                               PFID(mdo2fid(child)), rc);
                        if (rc > 0) {
                                CERROR("obd_setattr for "DFID" rc %d\n", 
                                        PFID(mdo2fid(child)), rc);
                                rc = -EIO;
                        }
                        GOTO(out_oa, rc);
                }
        }
        /*blksize should be changed after create data object*/
        la->la_valid |= LA_BLKSIZE;
        la->la_blksize = oa->o_blksize;

        rc = obd_packmd(lov_exp, lmm, lsm);
        if (rc < 0) {
                CERROR("cannot pack lsm, err = %d\n", rc);
                GOTO(out_oa, rc);
        }
        *lmm_size = rc;
        rc = 0;
out_oa:
        obdo_free(oa);
        if (lsm)
                obd_free_memmd(lov_exp, &lsm);
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
int mdd_lov_setattr_async(const struct lu_context *ctxt, struct mdd_object *obj,
                          struct lov_mds_md *lmm, int lmm_size)
{
        struct mdd_device       *mdd = mdo2mdd(&obj->mod_obj);
        struct obd_device       *obd = mdd2_obd(mdd);
        struct lu_attr          *tmp_la = &mdd_ctx_info(ctxt)->mti_la;
        struct dt_object        *next = mdd_object_child(obj);
        __u32  seq  = lu_object_fid(mdd2lu_obj(obj))->f_seq;
        __u32  oid  = lu_object_fid(mdd2lu_obj(obj))->f_oid;
        int rc = 0;
        ENTRY;

        rc = next->do_ops->do_attr_get(ctxt, next, tmp_la);
        if (rc)
                RETURN(rc);

        rc = mds_osc_setattr_async(obd, tmp_la->la_uid, tmp_la->la_gid, lmm,
                                   lmm_size, NULL, seq, oid);

        RETURN(rc);
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

