/*
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
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdd/mdd_lov.c
 *
 * Lustre Metadata Server (mds) handling of striped file data
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: wangdi <wangdi@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <obd_lov.h>
#include <lprocfs_status.h>
#include <lustre_mds.h>
#include <lustre_fid.h>
#include <lustre/lustre_idl.h>

#include "mdd_internal.h"

static int mdd_notify(struct obd_device *host, struct obd_device *watched,
                      enum obd_notify_event ev, void *owner, void *data)
{
        struct mdd_device *mdd = owner;
        int rc = 0;
        ENTRY;

        LASSERT(owner != NULL);
        switch (ev)
        {
                case OBD_NOTIFY_ACTIVE:
                case OBD_NOTIFY_SYNC:
                case OBD_NOTIFY_SYNC_NONBLOCK:
                        rc = md_do_upcall(NULL, &mdd->mdd_md_dev,
                                          MD_LOV_SYNC, data);
                        break;
                case OBD_NOTIFY_CONFIG:
                        rc = md_do_upcall(NULL, &mdd->mdd_md_dev,
                                          MD_LOV_CONFIG, data);
                        break;
#ifdef HAVE_QUOTA_SUPPORT
                case OBD_NOTIFY_QUOTA:
                        rc = md_do_upcall(NULL, &mdd->mdd_md_dev,
                                          MD_LOV_QUOTA, data);
                        break;
#endif
                default:
                        CDEBUG(D_INFO, "Unhandled notification %#x\n", ev);
        }

        RETURN(rc);
}

/* The obd is created for handling data stack for mdd */
int mdd_init_obd(const struct lu_env *env, struct mdd_device *mdd,
                 struct lustre_cfg *cfg)
{
        char                   *dev = lustre_cfg_string(cfg, 0);
        int                     rc, name_size, uuid_size;
        char                   *name, *uuid;
        __u32                   mds_id;
        struct lustre_cfg_bufs *bufs;
        struct lustre_cfg      *lcfg;
        struct obd_device      *obd;
        ENTRY;

        mds_id = lu_site2md(mdd2lu_dev(mdd)->ld_site)->ms_node_id;
        name_size = strlen(MDD_OBD_NAME) + 35;
        uuid_size = strlen(MDD_OBD_UUID) + 35;

        OBD_ALLOC(name, name_size);
        OBD_ALLOC(uuid, uuid_size);
        if (name == NULL || uuid == NULL)
                GOTO(cleanup_mem, rc = -ENOMEM);

        OBD_ALLOC_PTR(bufs);
        if (!bufs)
                GOTO(cleanup_mem, rc = -ENOMEM);

        snprintf(name, strlen(MDD_OBD_NAME) + 35, "%s-%s",
                 MDD_OBD_NAME, dev);

        snprintf(uuid, strlen(MDD_OBD_UUID) + 35, "%s-%s",
                 MDD_OBD_UUID, dev);

        lustre_cfg_bufs_reset(bufs, name);
        lustre_cfg_bufs_set_string(bufs, 1, MDD_OBD_TYPE);
        lustre_cfg_bufs_set_string(bufs, 2, uuid);
        lustre_cfg_bufs_set_string(bufs, 3, (char*)dev/* MDD_OBD_PROFILE */);
        lustre_cfg_bufs_set_string(bufs, 4, (char*)dev);

        lcfg = lustre_cfg_new(LCFG_ATTACH, bufs);
        OBD_FREE_PTR(bufs);
        if (!lcfg)
                GOTO(cleanup_mem, rc = -ENOMEM);

        rc = class_attach(lcfg);
        if (rc)
                GOTO(lcfg_cleanup, rc);

        obd = class_name2obd(name);
        if (!obd) {
                CERROR("Can not find obd %s\n", MDD_OBD_NAME);
                LBUG();
        }

        cfs_spin_lock(&obd->obd_dev_lock);
        obd->obd_recovering = 1;
        cfs_spin_unlock(&obd->obd_dev_lock);
        obd->u.mds.mds_id = mds_id;
        obd->u.obt.obt_osd_properties.osd_max_ea_size =
                                               mdd->mdd_dt_conf.ddp_max_ea_size;

        rc = class_setup(obd, lcfg);
        if (rc)
                GOTO(class_detach, rc);

        /*
         * Add here for obd notify mechanism, when adding a new ost, the mds
         * will notify this mdd. The mds will be used for quota also.
         */
        obd->obd_upcall.onu_upcall = mdd_notify;
        obd->obd_upcall.onu_owner = mdd;
        mdd->mdd_obd_dev = obd;

        EXIT;
class_detach:
        if (rc)
                class_detach(obd, lcfg);
lcfg_cleanup:
        lustre_cfg_free(lcfg);
cleanup_mem:
        if (name)
                OBD_FREE(name, name_size);
        if (uuid)
                OBD_FREE(uuid, uuid_size);
        return rc;
}

int mdd_fini_obd(const struct lu_env *env, struct mdd_device *mdd,
                 struct lustre_cfg *lcfg)
{
        struct obd_device      *obd;
        int rc;
        ENTRY;

        obd = mdd2obd_dev(mdd);
        LASSERT(obd);

        rc = class_cleanup(obd, lcfg);
        if (rc)
                GOTO(lcfg_cleanup, rc);

        obd->obd_upcall.onu_upcall = NULL;
        obd->obd_upcall.onu_owner = NULL;
        rc = class_detach(obd, lcfg);
        if (rc)
                GOTO(lcfg_cleanup, rc);
        mdd->mdd_obd_dev = NULL;

        EXIT;
lcfg_cleanup:
        return rc;
}

int mdd_get_md(const struct lu_env *env, struct mdd_object *obj,
               void *md, int *md_size, const char *name)
{
        int rc;
        ENTRY;

        rc = mdo_xattr_get(env, obj, mdd_buf_get(env, md, *md_size), name,
                           mdd_object_capa(env, obj));
        /*
         * XXX: Handling of -ENODATA, the right way is to have ->do_md_get()
         * exported by dt layer.
         */
        if (rc == 0 || rc == -ENODATA) {
                *md_size = 0;
                rc = 0;
        } else if (rc < 0) {
                CDEBUG(D_OTHER, "Error %d reading eadata - %d\n",
                       rc, *md_size);
        } else {
                /* XXX: Convert lov EA but fixed after verification test. */
                *md_size = rc;
        }

        RETURN(rc);
}

int mdd_get_md_locked(const struct lu_env *env, struct mdd_object *obj,
                      void *md, int *md_size, const char *name)
{
        int rc = 0;
        mdd_read_lock(env, obj, MOR_TGT_CHILD);
        rc = mdd_get_md(env, obj, md, md_size, name);
        mdd_read_unlock(env, obj);
        return rc;
}

static int mdd_lov_set_stripe_md(const struct lu_env *env,
                                 struct mdd_object *obj, struct lu_buf *buf,
                                 struct thandle *handle)
{
        struct mdd_device       *mdd = mdo2mdd(&obj->mod_obj);
        struct obd_device       *obd = mdd2obd_dev(mdd);
        struct obd_export       *lov_exp = obd->u.mds.mds_lov_exp;
        struct lov_stripe_md    *lsm = NULL;
        int rc;
        ENTRY;

        LASSERT(S_ISDIR(mdd_object_type(obj)) || S_ISREG(mdd_object_type(obj)));
        rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE, lov_exp, 0,
                           &lsm, buf->lb_buf);
        if (rc)
                RETURN(rc);
        obd_free_memmd(lov_exp, &lsm);

        rc = mdd_xattr_set_txn(env, obj, buf, XATTR_NAME_LOV, 0, handle);

        CDEBUG(D_INFO, "set lov ea of "DFID" rc %d \n", PFID(mdo2fid(obj)), rc);
        RETURN(rc);
}

/*
 * Permission check is done before call it,
 * no need check again.
 */
static int mdd_lov_set_dir_md(const struct lu_env *env,
                              struct mdd_object *obj, struct lu_buf *buf,
                              struct thandle *handle)
{
        struct lov_user_md *lum = NULL;
        int rc = 0;
        ENTRY;

        LASSERT(S_ISDIR(mdd_object_type(obj)));
        lum = (struct lov_user_md*)buf->lb_buf;

        /* if { size, offset, count } = { 0, -1, 0 } and no pool
         * (i.e. all default values specified) then delete default
         * striping from dir. */
        if (LOVEA_DELETE_VALUES(lum->lmm_stripe_size, lum->lmm_stripe_count,
                                lum->lmm_stripe_offset) &&
            lum->lmm_magic != LOV_USER_MAGIC_V3) {
                rc = mdd_xattr_set_txn(env, obj, &LU_BUF_NULL,
                                       XATTR_NAME_LOV, 0, handle);
                if (rc == -ENODATA)
                        rc = 0;
                CDEBUG(D_INFO, "delete lov ea of "DFID" rc %d \n",
                                PFID(mdo2fid(obj)), rc);
        } else {
                rc = mdd_lov_set_stripe_md(env, obj, buf, handle);
        }
        RETURN(rc);
}

int mdd_lsm_sanity_check(const struct lu_env *env,  struct mdd_object *obj)
{
        struct lu_attr   *tmp_la = &mdd_env_info(env)->mti_la;
        struct md_ucred  *uc     = md_ucred(env);
        int rc;
        ENTRY;

        rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        if ((uc->mu_fsuid != tmp_la->la_uid) &&
            !mdd_capable(uc, CFS_CAP_FOWNER))
                rc = mdd_permission_internal_locked(env, obj, tmp_la,
                                                    MAY_WRITE, MOR_TGT_CHILD);

        RETURN(rc);
}

int mdd_lov_set_md(const struct lu_env *env, struct mdd_object *pobj,
                   struct mdd_object *child, struct lov_mds_md *lmmp,
                   int lmm_size, struct thandle *handle, int set_stripe)
{
        struct lu_buf *buf;
        cfs_umode_t mode;
        int rc = 0;
        ENTRY;

        buf = mdd_buf_get(env, lmmp, lmm_size);
        mode = mdd_object_type(child);
        if (S_ISREG(mode) && lmm_size > 0) {
                if (set_stripe) {
                        rc = mdd_lov_set_stripe_md(env, child, buf, handle);
                } else {
                        rc = mdd_xattr_set_txn(env, child, buf,
                                               XATTR_NAME_LOV, 0, handle);
                }
        } else if (S_ISDIR(mode)) {
                if (lmmp == NULL && lmm_size == 0) {
                        struct mdd_device *mdd = mdd_obj2mdd_dev(child);
                        struct lov_mds_md *lmm = mdd_max_lmm_get(env, mdd);
                        int size = sizeof(struct lov_mds_md_v3);

                        /* Get parent dir stripe and set */
                        if (pobj != NULL)
                                rc = mdd_get_md_locked(env, pobj, lmm, &size,
                                                       XATTR_NAME_LOV);
                        if (rc > 0) {
                                buf = mdd_buf_get(env, lmm, size);
                                rc = mdd_xattr_set_txn(env, child, buf,
                                                       XATTR_NAME_LOV, 0,
                                                       handle);
                                if (rc)
                                        CERROR("error on copy stripe info: rc "
                                                "= %d\n", rc);
                        }
                } else {
                        LASSERT(lmmp != NULL && lmm_size > 0);
                        rc = mdd_lov_set_dir_md(env, child, buf, handle);
                }
        }
        CDEBUG(D_INFO, "Set lov md %p size %d for fid "DFID" rc %d\n",
                        lmmp, lmm_size, PFID(mdo2fid(child)), rc);
        RETURN(rc);
}

int mdd_lov_objid_prepare(struct mdd_device *mdd, struct lov_mds_md *lmm)
{
        /* copy mds_lov code is using wrong layer */
        return mds_lov_prepare_objids(mdd->mdd_obd_dev, lmm);
}

int mdd_declare_lov_objid_update(const struct lu_env *env,
                                 struct mdd_device *mdd,
                                 struct thandle *handle)
{
        struct obd_device *obd = mdd2obd_dev(mdd);
        int size;

        /* in prepare we create local files */
        if (unlikely(mdd->mdd_capa == NULL))
                return 0;

        /* XXX: this is a temporary solution to declare llog changes
         *      will be fixed in 2.3 with new llog implementation */

        size = obd->u.mds.mds_lov_desc.ld_tgt_count * sizeof(obd_id);
        return dt_declare_record_write(env, mdd->mdd_capa, size, 0, handle);
}

void mdd_lov_objid_update(struct mdd_device *mdd, struct lov_mds_md *lmm)
{
        /* copy mds_lov code is using wrong layer */
        mds_lov_update_objids(mdd->mdd_obd_dev, lmm);
}

void mdd_lov_create_finish(const struct lu_env *env, struct mdd_device *mdd,
                           struct lov_mds_md *lmm, int lmm_size,
                           const struct md_op_spec *spec)
{
        if (lmm && !spec->no_create)
                OBD_FREE_LARGE(lmm, lmm_size);
}

int mdd_lov_create(const struct lu_env *env, struct mdd_device *mdd,
                   struct mdd_object *parent, struct mdd_object *child,
                   struct lov_mds_md **lmm, int *lmm_size,
                   const struct md_op_spec *spec, struct md_attr *ma)
{
        struct obd_device     *obd = mdd2obd_dev(mdd);
        struct obd_export     *lov_exp = obd->u.mds.mds_lov_exp;
        struct lu_site        *site = mdd2lu_dev(mdd)->ld_site;
        struct obdo           *oa;
        struct lov_stripe_md  *lsm = NULL;
        const void            *eadata = spec->u.sp_ea.eadata;
        __u64                  create_flags = spec->sp_cr_flags;
        struct obd_trans_info *oti = &mdd_env_info(env)->mti_oti;
        struct lu_attr        *la = &ma->ma_attr;
        int                    rc = 0;
        ENTRY;

        if (!md_should_create(create_flags)) {
                *lmm_size = 0;
                RETURN(0);
        }
        oti_init(oti, NULL);

        /* replay case, has objects already, only get lov from eadata */
        if (spec->no_create != 0) {
                *lmm = (struct lov_mds_md *)spec->u.sp_ea.eadata;
                *lmm_size = spec->u.sp_ea.eadatalen;
                if (*lmm_size == lov_mds_md_size((*lmm)->lmm_stripe_count,
                                                 (*lmm)->lmm_magic)) {
                        RETURN(0);
                } else {
                        CERROR("incorrect lsm received during recovery\n");
                        RETURN(-EPROTO);
                }
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_ALLOC_OBDO))
                GOTO(out_ids, rc = -ENOMEM);

        LASSERT(lov_exp != NULL);
        oa = &mdd_env_info(env)->mti_oa;

        oa->o_uid = 0; /* must have 0 uid / gid on OST */
        oa->o_gid = 0;
        oa->o_seq = mdt_to_obd_objseq(lu_site2md(site)->ms_node_id);
        oa->o_mode = S_IFREG | 0600;
        oa->o_id = fid_ver_oid(mdd_object_fid(child));
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLFLAGS |
                OBD_MD_FLMODE | OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLGROUP;
        oa->o_size = 0;

        if (!(create_flags & MDS_OPEN_HAS_OBJS)) {
                if (create_flags & MDS_OPEN_HAS_EA) {
                        LASSERT(eadata != NULL);
                        rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE, lov_exp,
                                           0, &lsm, (void*)eadata);
                        if (rc)
                                GOTO(out_oti, rc);
                } else {
                        /* get lov ea from parent and set to lov */
                        struct lov_mds_md *_lmm;
                        int _lmm_size = mdd_lov_mdsize(env, mdd);

                        LASSERT(parent != NULL);

                        _lmm = mdd_max_lmm_get(env, mdd);
                        if (_lmm == NULL)
                                GOTO(out_oti, rc = -ENOMEM);

                        rc = mdd_get_md_locked(env, parent, _lmm,
                                               &_lmm_size,
                                               XATTR_NAME_LOV);
                        if (rc > 0) {
                                _lmm_size = mdd_lov_mdsize(env, mdd);
                                rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                                   lov_exp, _lmm_size,
                                                   &lsm, _lmm);
                        }
                        if (rc)
                                GOTO(out_oti, rc);
                }

                OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_OPEN_WAIT_CREATE, 10);
                rc = obd_create(env, lov_exp, oa, &lsm, oti);
                if (rc) {
                        if (rc > 0) {
                                CERROR("Create error for "DFID": %d\n",
                                       PFID(mdo2fid(child)), rc);
                                rc = -EIO;
                        }
                        GOTO(out_oti, rc);
                }

                if (ma->ma_valid & MA_LAY_GEN)
                        /* If we already have a lsm, the file is not new and we
                         * are about to change the layout, so we have to bump
                         * the generation. It is worth noting that old versions
                         * will be confused by a non-zero gen, that's why
                         * OBD_INCOMPAT_LMM_VER has been introduced */
                        lsm->lsm_layout_gen = ma->ma_layout_gen + 1;
                else
                        /* Start with a null generation for backward
                         * compatiblity with old versions */
                        lsm->lsm_layout_gen = 0;

                LASSERT_SEQ_IS_MDT(lsm->lsm_object_seq);
        } else {
                LASSERT(eadata != NULL);
                rc = obd_iocontrol(OBD_IOC_LOV_SETEA, lov_exp, 0, &lsm,
                                   (void*)eadata);
                if (rc)
                        GOTO(out_oti, rc);

                if (ma->ma_valid & MA_LAY_GEN)
                        lsm->lsm_layout_gen = ma->ma_layout_gen;
                else
                        lsm->lsm_layout_gen = 0;
        }

        lsm->lsm_object_id = fid_ver_oid(mdd_object_fid(child));
        lsm->lsm_object_seq = fid_seq(mdd_object_fid(child));
        /*
         * Sometimes, we may truncate some object(without lsm) then open it
         * (with write flags), so creating lsm above.  The Nonzero(truncated)
         * size should tell ost, since size attr is in charge by OST.
         */
        if (la->la_size && la->la_valid & LA_SIZE) {
                struct obd_info *oinfo = &mdd_env_info(env)->mti_oi;

                memset(oinfo, 0, sizeof(*oinfo));

                /* When setting attr to ost, FLBKSZ is not needed. */
                oa->o_valid &= ~OBD_MD_FLBLKSZ;
                obdo_from_la(oa, la, LA_TYPE | LA_ATIME | LA_MTIME |
                                     LA_CTIME | LA_SIZE);
                /*
                 * XXX: Pack lustre id to OST, in OST, it will be packed by
                 * filter_fid, but can not see what is the usages. So just pack
                 * o_seq o_ver here, maybe fix it after this cycle.
                 */
                obdo_set_parent_fid(oa, mdd_object_fid(child));
                oinfo->oi_oa = oa;
                oinfo->oi_md = lsm;
                oinfo->oi_capa = NULL;
                oinfo->oi_policy.l_extent.start = la->la_size;
                oinfo->oi_policy.l_extent.end = OBD_OBJECT_EOF;

                rc = obd_punch_rqset(lov_exp, oinfo, oti);
                if (rc) {
                        CERROR("Error setting attrs for "DFID": rc %d\n",
                               PFID(mdo2fid(child)), rc);
                        if (rc > 0) {
                                CERROR("obd_setattr for "DFID" rc %d\n",
                                        PFID(mdo2fid(child)), rc);
                                rc = -EIO;
                        }
                        GOTO(out_oti, rc);
                }
        }
        /* blksize should be changed after create data object */
        la->la_valid |= LA_BLKSIZE;
        la->la_blksize = oa->o_blksize;
        *lmm = NULL;
        rc = obd_packmd(lov_exp, lmm, lsm);
        if (rc < 0) {
                CERROR("Cannot pack lsm, err = %d\n", rc);
                GOTO(out_oti, rc);
        }
        if (mdd_lov_objid_prepare(mdd, *lmm) != 0) {
                CERROR("Not have memory for update objid\n");
                OBD_FREE(*lmm, rc);
                *lmm = NULL;
                GOTO(out_oti, rc = -ENOMEM);
        }
        *lmm_size = rc;
        rc = 0;
        EXIT;
out_oti:
        oti_free_cookies(oti);
out_ids:
        if (lsm)
                obd_free_memmd(lov_exp, &lsm);

        return rc;
}

/*
 * used when destroying orphans and from mds_reint_unlink() when MDS wants to
 * destroy objects on OSS.
 */
int mdd_lovobj_unlink(const struct lu_env *env, struct mdd_device *mdd,
		      struct mdd_object *obj, struct lu_attr *la,
		      struct md_attr *ma, int log_unlink)
{
        struct obd_device     *obd = mdd2obd_dev(mdd);
        struct obd_export     *lov_exp = obd->u.mds.mds_lov_exp;
        struct lov_stripe_md  *lsm = NULL;
        struct obd_trans_info *oti = &mdd_env_info(env)->mti_oti;
        struct obdo           *oa = &mdd_env_info(env)->mti_oa;
        struct lu_site        *site = mdd2lu_dev(mdd)->ld_site;
	struct lov_mds_md     *lmm = ma->ma_lmm;
	int                    lmm_size = ma->ma_lmm_size;
	struct llog_cookie    *logcookies = ma->ma_cookie;
	int                    rc;
        ENTRY;

        if (lmm_size == 0)
                RETURN(0);

        rc = obd_unpackmd(lov_exp, &lsm, lmm, lmm_size);
        if (rc < 0) {
                CERROR("Error unpack md %p\n", lmm);
                RETURN(rc);
        } else {
                LASSERT(rc >= sizeof(*lsm));
                rc = 0;
        }

        oa->o_id = lsm->lsm_object_id;
        oa->o_seq = mdt_to_obd_objseq(lu_site2md(site)->ms_node_id);
        oa->o_mode = la->la_mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLGROUP;

        oti_init(oti, NULL);
        if (log_unlink && logcookies) {
                oa->o_valid |= OBD_MD_FLCOOKIE;
                oti->oti_logcookies = logcookies;
        }

	if (!(ma->ma_attr_flags & MDS_UNLINK_DESTROY))
		oa->o_flags = OBD_FL_DELORPHAN;

        CDEBUG(D_INFO, "destroying OSS object "LPU64":"LPU64"\n", oa->o_seq,
               oa->o_id);

        rc = obd_destroy(env, lov_exp, oa, lsm, oti, NULL, NULL);

        obd_free_memmd(lov_exp, &lsm);
        RETURN(rc);
}

/*
 * called with obj locked.
 */
int mdd_lov_destroy(const struct lu_env *env, struct mdd_device *mdd,
                    struct mdd_object *obj, struct lu_attr *la)
{
        struct md_attr    *ma = &mdd_env_info(env)->mti_ma;
        int                rc;
        ENTRY;

        LASSERT(mdd_write_locked(env, obj) != 0);

        if (unlikely(!S_ISREG(mdd_object_type(obj))))
                RETURN(0);

        if (unlikely(la->la_nlink != 0)) {
                CWARN("Attempt to destroy OSS object when nlink == %d\n",
                      la->la_nlink);
                RETURN(0);
        }

        ma->ma_lmm_size = mdd_lov_mdsize(env, mdd);
        ma->ma_lmm = mdd_max_lmm_get(env, mdd);
        ma->ma_cookie_size = mdd_lov_cookiesize(env, mdd);
        ma->ma_cookie = mdd_max_cookie_get(env, mdd);
        if (ma->ma_lmm == NULL || ma->ma_cookie == NULL)
                RETURN(rc = -ENOMEM);

        /* get lov ea */

        rc = mdd_get_md(env, obj, ma->ma_lmm, &ma->ma_lmm_size,
                        XATTR_NAME_LOV);

        if (rc <= 0) {
                CWARN("Get lov ea failed for "DFID" rc = %d\n",
                         PFID(mdo2fid(obj)), rc);
                if (rc == 0)
                        rc = -ENOENT;
                RETURN(rc);
        }

        ma->ma_valid = MA_LOV;

        rc = mdd_unlink_log(env, mdd, obj, ma);
        if (rc) {
                CWARN("mds unlink log for "DFID" failed: %d\n",
                       PFID(mdo2fid(obj)), rc);
                RETURN(rc);
        }

	if (ma->ma_valid & MA_COOKIE)
		rc = mdd_lovobj_unlink(env, mdd, obj, la, ma, 1);

	RETURN(rc);
}

int mdd_declare_unlink_log(const struct lu_env *env, struct mdd_object *obj,
                           struct md_attr *ma, struct thandle *handle)
{
        struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
        int rc, i;
        __u16 stripe;

        LASSERT(obj);
        LASSERT(ma);

        if (!S_ISREG(lu_object_attr(&obj->mod_obj.mo_lu)))
                return 0;

        rc = mdd_lmm_get_locked(env, obj, ma);
        if (rc || !(ma->ma_valid & MA_LOV))
                return rc;

        LASSERT(ma->ma_lmm);
        if (le32_to_cpu(ma->ma_lmm->lmm_magic) != LOV_MAGIC_V1 &&
                        le32_to_cpu(ma->ma_lmm->lmm_magic) != LOV_MAGIC_V3) {
                CERROR("%s: invalid LOV_MAGIC %08x on object "DFID"\n",
                                mdd->mdd_obd_dev->obd_name,
                                le32_to_cpu(ma->ma_lmm->lmm_magic),
                                PFID(lu_object_fid(&obj->mod_obj.mo_lu)));
                return -EINVAL;
        }

        stripe = le16_to_cpu(ma->ma_lmm->lmm_stripe_count);
        if (stripe == LOV_ALL_STRIPES);
                stripe = mdd2obd_dev(mdd)->u.mds.mds_lov_desc.ld_tgt_count;

        for (i = 0; i < stripe; i++) {
                rc = mdd_declare_llog_record(env, mdd,
                                             sizeof(struct llog_unlink_rec),
                                             handle);
                if (rc)
                        return rc;
        }

        return rc;
}

int mdd_unlink_log(const struct lu_env *env, struct mdd_device *mdd,
                   struct mdd_object *mdd_cobj, struct md_attr *ma)
{
        LASSERT(ma->ma_valid & MA_LOV);

        if ((ma->ma_cookie_size > 0) &&
            (mds_log_op_unlink(mdd2obd_dev(mdd), ma->ma_lmm, ma->ma_lmm_size,
                               ma->ma_cookie, ma->ma_cookie_size) > 0)) {
                CDEBUG(D_HA, "DEBUG: unlink log is added for object "DFID"\n",
                       PFID(mdd_object_fid(mdd_cobj)));
                ma->ma_valid |= MA_COOKIE;
        }
        return 0;
}

int mdd_log_op_setattr(struct obd_device *obd, __u32 uid, __u32 gid,
                       struct lov_mds_md *lmm, int lmm_size,
                       struct llog_cookie *logcookies, int cookies_size)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_stripe_md *lsm = NULL;
        struct llog_setattr64_rec *lsr;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        if (IS_ERR(mds->mds_lov_obd))
                RETURN(PTR_ERR(mds->mds_lov_obd));

        rc = obd_unpackmd(mds->mds_lov_exp, &lsm, lmm, lmm_size);
        if (rc < 0)
                RETURN(rc);

        OBD_ALLOC(lsr, sizeof(*lsr));
        if (!lsr)
                GOTO(out, rc = -ENOMEM);

        /* prepare setattr log record */
        lsr->lsr_hdr.lrh_len = lsr->lsr_tail.lrt_len = sizeof(*lsr);
        lsr->lsr_hdr.lrh_type = MDS_SETATTR64_REC;
        lsr->lsr_uid = uid;
        lsr->lsr_gid = gid;

        /* write setattr log */
        ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
	rc = llog_add(NULL, ctxt, &lsr->lsr_hdr, lsm, logcookies,
		      cookies_size / sizeof(struct llog_cookie));

        llog_ctxt_put(ctxt);

        OBD_FREE(lsr, sizeof(*lsr));
 out:
        obd_free_memmd(mds->mds_lov_exp, &lsm);
        RETURN(rc);
}

int mdd_setattr_log(const struct lu_env *env, struct mdd_device *mdd,
                    const struct md_attr *ma,
                    struct lov_mds_md *lmm, int lmm_size,
                    struct llog_cookie *logcookies, int cookies_size)
{
        struct obd_device *obd = mdd2obd_dev(mdd);

        /* journal chown/chgrp in llog, just like unlink */
        if (lmm_size > 0) {
                CDEBUG(D_INFO, "setattr llog for uid/gid=%lu/%lu\n",
                        (unsigned long)ma->ma_attr.la_uid,
                        (unsigned long)ma->ma_attr.la_gid);
                return mdd_log_op_setattr(obd, ma->ma_attr.la_uid,
                                          ma->ma_attr.la_gid, lmm,
                                          lmm_size, logcookies,
                                          cookies_size);
        } else
                return 0;
}

static int mdd_osc_setattr_async(struct obd_device *obd, __u32 uid, __u32 gid,
                          struct lov_mds_md *lmm, int lmm_size,
                          struct llog_cookie *logcookies, const struct lu_fid *parent,
                          struct obd_capa *oc)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_trans_info oti = { 0 };
        struct obd_info oinfo = { { { 0 } } };
        int rc;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OST_SETATTR))
                RETURN(0);

        /* first get memory EA */
        OBDO_ALLOC(oinfo.oi_oa);
        if (!oinfo.oi_oa)
                RETURN(-ENOMEM);

        LASSERT(lmm);

        rc = obd_unpackmd(mds->mds_lov_exp, &oinfo.oi_md, lmm, lmm_size);
        if (rc < 0) {
                CERROR("Error unpack md %p for obj "DFID"\n", lmm,
                        PFID(parent));
                GOTO(out, rc);
        }

        /* then fill oa */
        oinfo.oi_oa->o_uid = uid;
        oinfo.oi_oa->o_gid = gid;
        oinfo.oi_oa->o_id = oinfo.oi_md->lsm_object_id;
        oinfo.oi_oa->o_seq = oinfo.oi_md->lsm_object_seq;
        oinfo.oi_oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP |
                                OBD_MD_FLUID | OBD_MD_FLGID;
        if (logcookies) {
                oinfo.oi_oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies = logcookies;
        }

        obdo_set_parent_fid(oinfo.oi_oa, parent);
        oinfo.oi_capa = oc;

        /* do async setattr from mds to ost not waiting for responses. */
        rc = obd_setattr_async(mds->mds_lov_exp, &oinfo, &oti, NULL);
        if (rc)
                CDEBUG(D_INODE, "mds to ost setattr objid 0x"LPX64
                       " on ost error %d\n", oinfo.oi_md->lsm_object_id, rc);
out:
        if (oinfo.oi_md)
                obd_free_memmd(mds->mds_lov_exp, &oinfo.oi_md);
        OBDO_FREE(oinfo.oi_oa);
        RETURN(rc);
}

int mdd_lov_setattr_async(const struct lu_env *env, struct mdd_object *obj,
                          struct lov_mds_md *lmm, int lmm_size,
                          struct llog_cookie *logcookies)
{
        struct mdd_device   *mdd = mdo2mdd(&obj->mod_obj);
        struct obd_device   *obd = mdd2obd_dev(mdd);
        struct lu_attr      *tmp_la = &mdd_env_info(env)->mti_la;
        const struct lu_fid *fid = mdd_object_fid(obj);
        int rc = 0;
        ENTRY;

        mdd_read_lock(env, obj, MOR_TGT_CHILD);
        rc = mdo_attr_get(env, obj, tmp_la, mdd_object_capa(env, obj));
        mdd_read_unlock(env, obj);
        if (rc)
                RETURN(rc);

        rc = mdd_osc_setattr_async(obd, tmp_la->la_uid, tmp_la->la_gid, lmm,
                                   lmm_size, logcookies, fid, NULL);
        RETURN(rc);
}

static int grouplock_blocking_ast(struct ldlm_lock *lock,
                                  struct ldlm_lock_desc *desc,
                                  void *data, int flag)
{
        struct md_attr *ma = data;
        struct lustre_handle lockh;
        int rc = 0;
        ENTRY;

        switch (flag)
        {
                case LDLM_CB_BLOCKING :
                        /* lock is canceled */
                        CDEBUG(D_DLMTRACE, "Lock %p is canceled\n", lock);

                        ldlm_lock2handle(lock, &lockh);
                        rc = ldlm_cli_cancel(&lockh);

                        break;
                case LDLM_CB_CANCELING :
                        CDEBUG(D_DLMTRACE,
                               "Lock %p has been canceled, do cleaning\n",
                               lock);

                        if (ma && ma->ma_som)
                                OBD_FREE_PTR(ma->ma_som);
                        if (ma)
                                OBD_FREE_PTR(ma);
                        break;
                default:
                        LBUG();
        }
        RETURN(rc);
}

static int grouplock_glimpse_ast(struct ldlm_lock *lock, void *data)
{
        struct ptlrpc_request *req = data;
        struct ost_lvb *lvb;
        int rc;
        struct md_attr *ma;
        ENTRY;

        ma = lock->l_ast_data;

        req_capsule_extend(&req->rq_pill, &RQF_LDLM_GL_CALLBACK);
        req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
                             sizeof(*lvb));
        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc) {
                CERROR("failed pack reply: %d\n", rc);
                GOTO(out, rc);
        }

        lvb = req_capsule_server_get(&req->rq_pill, &RMF_DLM_LVB);

        if ((ma) && (ma->ma_valid & MA_SOM)) {
                lvb->lvb_size = ma->ma_som->msd_size;
                lvb->lvb_blocks = ma->ma_som->msd_blocks;
        } else if ((ma) && (ma->ma_valid & MA_INODE)) {
                lvb->lvb_size = ma->ma_attr.la_size;
                lvb->lvb_blocks = ma->ma_attr.la_blocks;
        } else {
                lvb->lvb_size = 0;
                rc = -ELDLM_NO_LOCK_DATA;
        }

        EXIT;
out:
        if (rc == -ELDLM_NO_LOCK_DATA)
                lustre_pack_reply(req, 1, NULL, NULL);

        req->rq_status = rc;
        return rc;
}

int mdd_file_lock(const struct lu_env *env, struct md_object *obj,
                  struct lov_mds_md *lmm, struct ldlm_extent *extent,
                  struct lustre_handle *lockh)
{
        struct ldlm_enqueue_info einfo = { 0 };
        struct obd_info oinfo = { { { 0 } } };
        struct obd_device *obd;
        struct obd_export *lov_exp;
        struct lov_stripe_md *lsm = NULL;
        struct md_attr *ma = NULL;
        int rc;
        ENTRY;

        obd = mdo2mdd(obj)->mdd_obd_dev;
        lov_exp = obd->u.mds.mds_lov_exp;

        obd_unpackmd(lov_exp, &lsm, lmm,
                     lov_mds_md_size(lmm->lmm_stripe_count, lmm->lmm_magic));

        OBD_ALLOC_PTR(ma);
        if (ma == NULL)
                GOTO(out, rc = -ENOMEM);

        OBD_ALLOC_PTR(ma->ma_som);
        if (ma->ma_som == NULL)
                GOTO(out, rc = -ENOMEM);

        ma->ma_need = MA_SOM | MA_INODE;
        mo_attr_get(env, obj, ma);

        einfo.ei_type = LDLM_EXTENT;
        einfo.ei_mode = LCK_GROUP;
        einfo.ei_cb_bl = grouplock_blocking_ast;
        einfo.ei_cb_cp = ldlm_completion_ast;
        einfo.ei_cb_gl = grouplock_glimpse_ast;

        if (ma->ma_valid & (MA_SOM | MA_INODE))
                einfo.ei_cbdata = ma;
        else
                einfo.ei_cbdata = NULL;

        memset(&oinfo.oi_policy, 0, sizeof(oinfo.oi_policy));
        oinfo.oi_policy.l_extent = *extent;
        oinfo.oi_lockh = lockh;
        oinfo.oi_md = lsm;
        oinfo.oi_flags = 0;

        rc = obd_enqueue(lov_exp, &oinfo, &einfo, NULL);
        /* ei_cbdata is used as a free flag at exit */
        if (rc)
                einfo.ei_cbdata = NULL;

        obd_unpackmd(lov_exp, &lsm, NULL, 0);

out:
        /* ma is freed if not used as callback data */
        if ((einfo.ei_cbdata == NULL) && ma && ma->ma_som)
                OBD_FREE_PTR(ma->ma_som);
        if ((einfo.ei_cbdata == NULL) && ma)
                OBD_FREE_PTR(ma);

        RETURN(rc);
}

int mdd_file_unlock(const struct lu_env *env, struct md_object *obj,
                    struct lov_mds_md *lmm, struct lustre_handle *lockh)
{
        struct obd_device *obd;
        struct obd_export *lov_exp;
        struct lov_stripe_md *lsm = NULL;
        int rc;
        ENTRY;

        LASSERT(lustre_handle_is_used(lockh));

        obd = mdo2mdd(obj)->mdd_obd_dev;
        lov_exp = obd->u.mds.mds_lov_exp;

        obd_unpackmd(lov_exp, &lsm, lmm,
                     lov_mds_md_size(lmm->lmm_stripe_count, lmm->lmm_magic));

        rc = obd_cancel(lov_exp, lsm, LCK_GROUP, lockh);

        obd_unpackmd(lov_exp, &lsm, NULL, 0);

        RETURN(rc);
}

/* file lov is in ma->ma_lmm */
/* requested lov is in info->mti_spec.u.sp_ea.eadata */
int mdd_lum_lmm_cmp(const struct lu_env *env, struct md_object *cobj,
                    const struct md_op_spec *spec, struct md_attr *ma)
{
        struct obd_export *lov_exp =
                mdd2obd_dev(mdo2mdd(cobj))->u.mds.mds_lov_exp;
        struct lov_mds_md *lmm = ma->ma_lmm;
        struct lov_user_md_v3 *lum =
                (struct lov_user_md_v3 *)(spec->u.sp_ea.eadata);
        struct lov_stripe_md *lsm = NULL;
        int lmm_magic, rc;
        ENTRY;

        rc = obd_unpackmd(lov_exp, &lsm, lmm,
                          lov_mds_md_size(lmm->lmm_stripe_count,
                                          lmm->lmm_magic));
        ma->ma_layout_gen = lsm->lsm_layout_gen;
        ma->ma_valid |= MA_LAY_GEN;

        rc = lov_lum_swab_if_needed(lum, &lmm_magic, NULL);
        if (rc)
                GOTO(out, rc);

        rc = lov_lum_lsm_cmp((struct lov_user_md *)lum, lsm);
        if (rc)
                GOTO(out, rc);  /* keep GOTO to for traces */

out:
        /* free lsm */
        obd_unpackmd(lov_exp, &lsm, NULL, 0);
        return rc;
}
