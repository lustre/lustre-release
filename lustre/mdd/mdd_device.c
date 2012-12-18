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
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdd/mdd_device.c
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
#ifdef HAVE_EXT4_LDISKFS
#include <ldiskfs/ldiskfs_jbd2.h>
#else
#include <linux/jbd.h>
#endif
#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <lustre_disk.h>
#include <lustre_fid.h>
#ifdef HAVE_EXT4_LDISKFS
#include <ldiskfs/ldiskfs.h>
#else
#include <linux/ldiskfs_fs.h>
#endif
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>
#include <lustre_disk.h>      /* for changelogs */
#include <lustre_param.h>
#include <lustre_fid.h>

#include "mdd_internal.h"

const struct md_device_operations mdd_ops;
static struct lu_device_type mdd_device_type;

static const char mdd_root_dir_name[] = "ROOT";
static const char mdd_obf_dir_name[] = "fid";

static int mdd_device_init(const struct lu_env *env, struct lu_device *d,
                           const char *name, struct lu_device *next)
{
        struct mdd_device *mdd = lu2mdd_dev(d);
        int rc;
        ENTRY;

        mdd->mdd_child = lu2dt_dev(next);

        /* Prepare transactions callbacks. */
        mdd->mdd_txn_cb.dtc_txn_start = mdd_txn_start_cb;
        mdd->mdd_txn_cb.dtc_txn_stop = mdd_txn_stop_cb;
        mdd->mdd_txn_cb.dtc_txn_commit = mdd_txn_commit_cb;
        mdd->mdd_txn_cb.dtc_cookie = mdd;
        mdd->mdd_txn_cb.dtc_tag = LCT_MD_THREAD;
        CFS_INIT_LIST_HEAD(&mdd->mdd_txn_cb.dtc_linkage);
        mdd->mdd_atime_diff = MAX_ATIME_DIFF;
        /* sync permission changes */
        mdd->mdd_sync_permission = 1;

        rc = mdd_procfs_init(mdd, name);
        RETURN(rc);
}

static struct lu_device *mdd_device_fini(const struct lu_env *env,
                                         struct lu_device *d)
{
        struct mdd_device *mdd = lu2mdd_dev(d);
        struct lu_device *next = &mdd->mdd_child->dd_lu_dev;
        int rc;

        rc = mdd_procfs_fini(mdd);
        if (rc) {
                CERROR("proc fini error %d \n", rc);
                return ERR_PTR(rc);
        }
        return next;
}

static void mdd_changelog_fini(const struct lu_env *env,
                               struct mdd_device *mdd);

static void mdd_device_shutdown(const struct lu_env *env,
                                struct mdd_device *m, struct lustre_cfg *cfg)
{
        ENTRY;
        mdd_changelog_fini(env, m);
        dt_txn_callback_del(m->mdd_child, &m->mdd_txn_cb);
        if (m->mdd_dot_lustre_objs.mdd_obf)
                mdd_object_put(env, m->mdd_dot_lustre_objs.mdd_obf);
        if (m->mdd_dot_lustre)
                mdd_object_put(env, m->mdd_dot_lustre);
        if (m->mdd_obd_dev)
                mdd_fini_obd(env, m, cfg);
        orph_index_fini(env, m);
        /* remove upcall device*/
        md_upcall_fini(&m->mdd_md_dev);
        EXIT;
}

static int changelog_init_cb(struct llog_handle *llh, struct llog_rec_hdr *hdr,
                             void *data)
{
        struct mdd_device *mdd = (struct mdd_device *)data;
        struct llog_changelog_rec *rec = (struct llog_changelog_rec *)hdr;
        ENTRY;

        LASSERT(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN);
        LASSERT(rec->cr_hdr.lrh_type == CHANGELOG_REC);

        CDEBUG(D_INFO,
               "seeing record at index %d/%d/"LPU64" t=%x %.*s in log "LPX64"\n",
               hdr->lrh_index, rec->cr_hdr.lrh_index, rec->cr.cr_index,
               rec->cr.cr_type, rec->cr.cr_namelen, rec->cr.cr_name,
               llh->lgh_id.lgl_oid);

        mdd->mdd_cl.mc_index = rec->cr.cr_index;
        RETURN(LLOG_PROC_BREAK);
}

static int changelog_user_init_cb(struct llog_handle *llh,
                                  struct llog_rec_hdr *hdr, void *data)
{
        struct mdd_device *mdd = (struct mdd_device *)data;
        struct llog_changelog_user_rec *rec =
                (struct llog_changelog_user_rec *)hdr;
        ENTRY;

        LASSERT(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN);
        LASSERT(rec->cur_hdr.lrh_type == CHANGELOG_USER_REC);

        CDEBUG(D_INFO, "seeing user at index %d/%d id=%d endrec="LPU64
               " in log "LPX64"\n", hdr->lrh_index, rec->cur_hdr.lrh_index,
               rec->cur_id, rec->cur_endrec, llh->lgh_id.lgl_oid);

        cfs_spin_lock(&mdd->mdd_cl.mc_user_lock);
        mdd->mdd_cl.mc_lastuser = rec->cur_id;
        cfs_spin_unlock(&mdd->mdd_cl.mc_user_lock);

        RETURN(LLOG_PROC_BREAK);
}


static int mdd_changelog_llog_init(struct mdd_device *mdd)
{
        struct obd_device *obd = mdd2obd_dev(mdd);
        struct llog_ctxt *ctxt;
        int rc;

        /* Find last changelog entry number */
        ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
        if (ctxt == NULL) {
                CERROR("no changelog context\n");
                return -EINVAL;
        }
        if (!ctxt->loc_handle) {
                llog_ctxt_put(ctxt);
                return -EINVAL;
        }

        rc = llog_cat_reverse_process(ctxt->loc_handle, changelog_init_cb, mdd);
        llog_ctxt_put(ctxt);

        if (rc < 0) {
                CERROR("changelog init failed: %d\n", rc);
                return rc;
        }
        CDEBUG(D_IOCTL, "changelog starting index="LPU64"\n",
               mdd->mdd_cl.mc_index);

        /* Find last changelog user id */
        ctxt = llog_get_context(obd, LLOG_CHANGELOG_USER_ORIG_CTXT);
        if (ctxt == NULL) {
                CERROR("no changelog user context\n");
                return -EINVAL;
        }
        if (!ctxt->loc_handle) {
                llog_ctxt_put(ctxt);
                return -EINVAL;
        }

        rc = llog_cat_reverse_process(ctxt->loc_handle, changelog_user_init_cb,
                                      mdd);
        llog_ctxt_put(ctxt);

        if (rc < 0) {
                CERROR("changelog user init failed: %d\n", rc);
                return rc;
        }

        /* If we have registered users, assume we want changelogs on */
        if (mdd->mdd_cl.mc_lastuser > 0)
                rc = mdd_changelog_on(mdd, 1);

        return rc;
}

static int mdd_changelog_init(const struct lu_env *env, struct mdd_device *mdd)
{
        int rc;

        mdd->mdd_cl.mc_index = 0;
        cfs_spin_lock_init(&mdd->mdd_cl.mc_lock);
        mdd->mdd_cl.mc_starttime = cfs_time_current_64();
        mdd->mdd_cl.mc_flags = 0; /* off by default */
        mdd->mdd_cl.mc_mask = CHANGELOG_DEFMASK;
        cfs_spin_lock_init(&mdd->mdd_cl.mc_user_lock);
        mdd->mdd_cl.mc_lastuser = 0;

        rc = mdd_changelog_llog_init(mdd);
        if (rc) {
                CERROR("Changelog setup during init failed %d\n", rc);
                mdd->mdd_cl.mc_flags |= CLM_ERR;
        }

        return rc;
}

static void mdd_changelog_fini(const struct lu_env *env, struct mdd_device *mdd)
{
        mdd->mdd_cl.mc_flags = 0;
}

/* Start / stop recording */
int mdd_changelog_on(struct mdd_device *mdd, int on)
{
        int rc = 0;

        if ((on == 1) && ((mdd->mdd_cl.mc_flags & CLM_ON) == 0)) {
                LCONSOLE_INFO("%s: changelog on\n", mdd2obd_dev(mdd)->obd_name);
                if (mdd->mdd_cl.mc_flags & CLM_ERR) {
                        CERROR("Changelogs cannot be enabled due to error "
                               "condition (see %s log).\n",
                               mdd2obd_dev(mdd)->obd_name);
                        rc = -ESRCH;
                } else {
                        cfs_spin_lock(&mdd->mdd_cl.mc_lock);
                        mdd->mdd_cl.mc_flags |= CLM_ON;
                        cfs_spin_unlock(&mdd->mdd_cl.mc_lock);
                        rc = mdd_changelog_write_header(mdd, CLM_START);
                }
        } else if ((on == 0) && ((mdd->mdd_cl.mc_flags & CLM_ON) == CLM_ON)) {
                LCONSOLE_INFO("%s: changelog off\n",mdd2obd_dev(mdd)->obd_name);
                rc = mdd_changelog_write_header(mdd, CLM_FINI);
                cfs_spin_lock(&mdd->mdd_cl.mc_lock);
                mdd->mdd_cl.mc_flags &= ~CLM_ON;
                cfs_spin_unlock(&mdd->mdd_cl.mc_lock);
        }
        return rc;
}

static __u64 cl_time(void) {
        cfs_fs_time_t time;

        cfs_fs_time_current(&time);
        return (((__u64)time.tv_sec) << 30) + time.tv_nsec;
}

/** Add a changelog entry \a rec to the changelog llog
 * \param mdd
 * \param rec
 * \param handle - currently ignored since llogs start their own transaction;
 *                 this will hopefully be fixed in llog rewrite
 * \retval 0 ok
 */
int mdd_changelog_llog_write(struct mdd_device         *mdd,
                             struct llog_changelog_rec *rec,
                             struct thandle            *handle)
{
        struct obd_device *obd = mdd2obd_dev(mdd);
        struct llog_ctxt *ctxt;
        int rc;

        rec->cr_hdr.lrh_len = llog_data_len(sizeof(*rec) + rec->cr.cr_namelen);
        /* llog_lvfs_write_rec sets the llog tail len */
        rec->cr_hdr.lrh_type = CHANGELOG_REC;
        rec->cr.cr_time = cl_time();
        cfs_spin_lock(&mdd->mdd_cl.mc_lock);
        /* NB: I suppose it's possible llog_add adds out of order wrt cr_index,
           but as long as the MDD transactions are ordered correctly for e.g.
           rename conflicts, I don't think this should matter. */
        rec->cr.cr_index = ++mdd->mdd_cl.mc_index;
        cfs_spin_unlock(&mdd->mdd_cl.mc_lock);
        ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
        if (ctxt == NULL)
                return -ENXIO;

        /* nested journal transaction */
        rc = llog_add(ctxt, &rec->cr_hdr, NULL, NULL, 0);
        llog_ctxt_put(ctxt);

        return rc;
}

/** Remove entries with indicies up to and including \a endrec from the
 *  changelog
 * \param mdd
 * \param endrec
 * \retval 0 ok
 */
int mdd_changelog_llog_cancel(struct mdd_device *mdd, long long endrec)
{
        struct obd_device *obd = mdd2obd_dev(mdd);
        struct llog_ctxt *ctxt;
        long long unsigned cur;
        int rc;

        ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
        if (ctxt == NULL)
                return -ENXIO;

        cfs_spin_lock(&mdd->mdd_cl.mc_lock);
        cur = (long long)mdd->mdd_cl.mc_index;
        cfs_spin_unlock(&mdd->mdd_cl.mc_lock);
        if (endrec > cur)
                endrec = cur;

        /* purge to "0" is shorthand for everything */
        if (endrec == 0)
                endrec = cur;

        /* If purging all records, write a header entry so we don't have an
           empty catalog and we're sure to have a valid starting index next
           time.  In case of crash, we just restart with old log so we're
           allright. */
        if (endrec == cur) {
                rc = mdd_changelog_write_header(mdd, CLM_PURGE);
                if (rc)
                      goto out;
        }

        /* Some records were purged, so reset repeat-access time (so we
           record new mtime update records, so users can see a file has been
           changed since the last purge) */
        mdd->mdd_cl.mc_starttime = cfs_time_current_64();

        rc = llog_cancel(ctxt, NULL, 1, (struct llog_cookie *)&endrec, 0);
out:
        llog_ctxt_put(ctxt);
        return rc;
}

/** Add a CL_MARK record to the changelog
 * \param mdd
 * \param markerflags - CLM_*
 * \retval 0 ok
 */
int mdd_changelog_write_header(struct mdd_device *mdd, int markerflags)
{
        struct obd_device *obd = mdd2obd_dev(mdd);
        struct llog_changelog_rec *rec;
        int reclen;
        int len = strlen(obd->obd_name);
        int rc;
        ENTRY;

        reclen = llog_data_len(sizeof(*rec) + len);
        OBD_ALLOC(rec, reclen);
        if (rec == NULL)
                RETURN(-ENOMEM);

        rec->cr.cr_flags = CLF_VERSION;
        rec->cr.cr_type = CL_MARK;
        rec->cr.cr_namelen = len;
        memcpy(rec->cr.cr_name, obd->obd_name, rec->cr.cr_namelen);
        /* Status and action flags */
        rec->cr.cr_markerflags = mdd->mdd_cl.mc_flags | markerflags;

        rc = (mdd->mdd_cl.mc_mask & (1 << CL_MARK)) ?
                mdd_changelog_llog_write(mdd, rec, NULL) : 0;

        /* assume on or off event; reset repeat-access time */
        mdd->mdd_cl.mc_starttime = cfs_time_current_64();

        OBD_FREE(rec, reclen);
        RETURN(rc);
}

/**
 * Create ".lustre" directory.
 */
static int create_dot_lustre_dir(const struct lu_env *env, struct mdd_device *m)
{
        struct lu_fid *fid = &mdd_env_info(env)->mti_fid;
        struct md_object *mdo;
        int rc;

        memcpy(fid, &LU_DOT_LUSTRE_FID, sizeof(struct lu_fid));
        mdo = llo_store_create_index(env, &m->mdd_md_dev, m->mdd_child,
                                     mdd_root_dir_name, dot_lustre_name,
                                     fid, &dt_directory_features);
        /* .lustre dir may be already present */
        if (IS_ERR(mdo) && PTR_ERR(mdo) != -EEXIST) {
                rc = PTR_ERR(mdo);
                CERROR("creating obj [%s] fid = "DFID" rc = %d\n",
                        dot_lustre_name, PFID(fid), rc);
                RETURN(rc);
        }

        if (!IS_ERR(mdo))
                lu_object_put(env, &mdo->mo_lu);

        return 0;
}


static int dot_lustre_mdd_permission(const struct lu_env *env,
                                     struct md_object *pobj,
                                     struct md_object *cobj,
                                     struct md_attr *attr, int mask)
{
        if (mask & ~(MAY_READ | MAY_EXEC))
                return -EPERM;
        else
                return 0;
}

static int dot_lustre_mdd_xattr_get(const struct lu_env *env,
                                    struct md_object *obj, struct lu_buf *buf,
                                    const char *name)
{
        return 0;
}

static int dot_lustre_mdd_xattr_list(const struct lu_env *env,
                                     struct md_object *obj, struct lu_buf *buf)
{
        return 0;
}

static int dot_lustre_mdd_xattr_set(const struct lu_env *env,
                                    struct md_object *obj,
                                    const struct lu_buf *buf, const char *name,
                                    int fl)
{
        return -EPERM;
}

static int dot_lustre_mdd_xattr_del(const struct lu_env *env,
                                    struct md_object *obj,
                                    const char *name)
{
        return -EPERM;
}

static int dot_lustre_mdd_readlink(const struct lu_env *env,
                                   struct md_object *obj, struct lu_buf *buf)
{
        return 0;
}

static int dot_lustre_mdd_object_create(const struct lu_env *env,
                                        struct md_object *obj,
                                        const struct md_op_spec *spec,
                                        struct md_attr *ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_ref_add(const struct lu_env *env,
                                  struct md_object *obj,
                                  const struct md_attr *ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_ref_del(const struct lu_env *env,
                                  struct md_object *obj,
                                  struct md_attr *ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_open(const struct lu_env *env, struct md_object *obj,
                               int flags)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
        mdd_obj->mod_count++;
        mdd_write_unlock(env, mdd_obj);

        return 0;
}

static int dot_lustre_mdd_close(const struct lu_env *env, struct md_object *obj,
                                struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
        mdd_obj->mod_count--;
        mdd_write_unlock(env, mdd_obj);

        return 0;
}

static int dot_lustre_mdd_object_sync(const struct lu_env *env,
                                      struct md_object *obj)
{
        return -ENOSYS;
}

static dt_obj_version_t dot_lustre_mdd_version_get(const struct lu_env *env,
                                                   struct md_object *obj)
{
        return 0;
}

static void dot_lustre_mdd_version_set(const struct lu_env *env,
                                       struct md_object *obj,
                                       dt_obj_version_t version)
{
        return;
}

static int dot_lustre_mdd_path(const struct lu_env *env, struct md_object *obj,
                           char *path, int pathlen, __u64 *recno, int *linkno)
{
        return -ENOSYS;
}

static int dot_file_lock(const struct lu_env *env, struct md_object *obj,
                         struct lov_mds_md *lmm, struct ldlm_extent *extent,
                         struct lustre_handle *lockh)
{
        return -ENOSYS;
}

static int dot_file_unlock(const struct lu_env *env, struct md_object *obj,
                           struct lov_mds_md *lmm, struct lustre_handle *lockh)
{
        return -ENOSYS;
}

static struct md_object_operations mdd_dot_lustre_obj_ops = {
        .moo_permission    = dot_lustre_mdd_permission,
        .moo_attr_get      = mdd_attr_get,
        .moo_attr_set      = mdd_attr_set,
        .moo_xattr_get     = dot_lustre_mdd_xattr_get,
        .moo_xattr_list    = dot_lustre_mdd_xattr_list,
        .moo_xattr_set     = dot_lustre_mdd_xattr_set,
        .moo_xattr_del     = dot_lustre_mdd_xattr_del,
        .moo_readpage      = mdd_readpage,
        .moo_readlink      = dot_lustre_mdd_readlink,
        .moo_object_create = dot_lustre_mdd_object_create,
        .moo_ref_add       = dot_lustre_mdd_ref_add,
        .moo_ref_del       = dot_lustre_mdd_ref_del,
        .moo_open          = dot_lustre_mdd_open,
        .moo_close         = dot_lustre_mdd_close,
        .moo_capa_get      = mdd_capa_get,
        .moo_object_sync   = dot_lustre_mdd_object_sync,
        .moo_version_get   = dot_lustre_mdd_version_get,
        .moo_version_set   = dot_lustre_mdd_version_set,
        .moo_path          = dot_lustre_mdd_path,
        .moo_file_lock     = dot_file_lock,
        .moo_file_unlock   = dot_file_unlock,
};


static int dot_lustre_mdd_lookup(const struct lu_env *env, struct md_object *p,
                                 const struct lu_name *lname, struct lu_fid *f,
                                 struct md_op_spec *spec)
{
        if (strcmp(lname->ln_name, mdd_obf_dir_name) == 0)
                *f = LU_OBF_FID;
        else
                return -ENOENT;

        return 0;
}

static mdl_mode_t dot_lustre_mdd_lock_mode(const struct lu_env *env,
                                           struct md_object *obj,
                                           mdl_mode_t mode)
{
        return MDL_MINMODE;
}

static int dot_lustre_mdd_create(const struct lu_env *env,
                                 struct md_object *pobj,
                                 const struct lu_name *lname,
                                 struct md_object *child,
                                 struct md_op_spec *spec,
                                 struct md_attr* ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_create_data(const struct lu_env *env,
                                      struct md_object *p,
                                      struct md_object *o,
                                      const struct md_op_spec *spec,
                                      struct md_attr *ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_rename(const struct lu_env *env,
                                 struct md_object *src_pobj,
                                 struct md_object *tgt_pobj,
                                 const struct lu_fid *lf,
                                 const struct lu_name *lsname,
                                 struct md_object *tobj,
                                 const struct lu_name *ltname,
                                 struct md_attr *ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_link(const struct lu_env *env,
                               struct md_object *tgt_obj,
                               struct md_object *src_obj,
                               const struct lu_name *lname,
                               struct md_attr *ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_unlink(const struct lu_env *env,
                                 struct md_object *pobj,
                                 struct md_object *cobj,
                                 const struct lu_name *lname,
                                 struct md_attr *ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_name_insert(const struct lu_env *env,
                                      struct md_object *obj,
                                      const struct lu_name *lname,
                                      const struct lu_fid *fid,
                                      const struct md_attr *ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_name_remove(const struct lu_env *env,
                                      struct md_object *obj,
                                      const struct lu_name *lname,
                                      const struct md_attr *ma)
{
        return -EPERM;
}

static int dot_lustre_mdd_rename_tgt(const struct lu_env *env,
                                     struct md_object *pobj,
                                     struct md_object *tobj,
                                     const struct lu_fid *fid,
                                     const struct lu_name *lname,
                                     struct md_attr *ma)
{
        return -EPERM;
}


static struct md_dir_operations mdd_dot_lustre_dir_ops = {
        .mdo_is_subdir   = mdd_is_subdir,
        .mdo_lookup      = dot_lustre_mdd_lookup,
        .mdo_lock_mode   = dot_lustre_mdd_lock_mode,
        .mdo_create      = dot_lustre_mdd_create,
        .mdo_create_data = dot_lustre_mdd_create_data,
        .mdo_rename      = dot_lustre_mdd_rename,
        .mdo_link        = dot_lustre_mdd_link,
        .mdo_unlink      = dot_lustre_mdd_unlink,
        .mdo_name_insert = dot_lustre_mdd_name_insert,
        .mdo_name_remove = dot_lustre_mdd_name_remove,
        .mdo_rename_tgt  = dot_lustre_mdd_rename_tgt,
};

static int obf_attr_get(const struct lu_env *env, struct md_object *obj,
                        struct md_attr *ma)
{
        int rc = 0;

        if (ma->ma_need & MA_INODE) {
                struct mdd_device *mdd = mdo2mdd(obj);

                /* "fid" is a virtual object and hence does not have any "real"
                 * attributes. So we reuse attributes of .lustre for "fid" dir */
                ma->ma_need |= MA_INODE;
                rc = mdd_attr_get(env, &mdd->mdd_dot_lustre->mod_obj, ma);
                if (rc)
                        return rc;
                ma->ma_valid |= MA_INODE;
        }

        /* "fid" directory does not have any striping information. */
        if (ma->ma_need & MA_LOV) {
                struct mdd_object *mdd_obj = md2mdd_obj(obj);

                if (ma->ma_valid & MA_LOV)
                        return 0;

                if (!(S_ISREG(mdd_object_type(mdd_obj)) ||
                      S_ISDIR(mdd_object_type(mdd_obj))))
                        return 0;

                if (ma->ma_need & MA_LOV_DEF) {
                        rc = mdd_get_default_md(mdd_obj, ma->ma_lmm);
                        if (rc > 0) {
                                ma->ma_lmm_size = rc;
                                ma->ma_valid |= MA_LOV;
                                rc = 0;
                        }
                }
        }

        return rc;
}

static int obf_attr_set(const struct lu_env *env, struct md_object *obj,
                        const struct md_attr *ma)
{
        return -EPERM;
}

static int obf_xattr_list(const struct lu_env *env,
                          struct md_object *obj, struct lu_buf *buf)
{
        return 0;
}

static int obf_xattr_get(const struct lu_env *env,
                         struct md_object *obj, struct lu_buf *buf,
                         const char *name)
{
        return 0;
}

static int obf_xattr_set(const struct lu_env *env,
                         struct md_object *obj,
                         const struct lu_buf *buf, const char *name,
                         int fl)
{
        return -EPERM;
}

static int obf_xattr_del(const struct lu_env *env,
                         struct md_object *obj,
                         const char *name)
{
        return -EPERM;
}

static int obf_mdd_open(const struct lu_env *env, struct md_object *obj,
                        int flags)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
        mdd_obj->mod_count++;
        mdd_write_unlock(env, mdd_obj);

        return 0;
}

static int obf_mdd_close(const struct lu_env *env, struct md_object *obj,
                         struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
        mdd_obj->mod_count--;
        mdd_write_unlock(env, mdd_obj);

        return 0;
}

/** Nothing to list in "fid" directory */
static int obf_mdd_readpage(const struct lu_env *env, struct md_object *obj,
                            const struct lu_rdpg *rdpg)
{
        return -EPERM;
}

static int obf_path(const struct lu_env *env, struct md_object *obj,
                    char *path, int pathlen, __u64 *recno, int *linkno)
{
        return -ENOSYS;
}

static dt_obj_version_t obf_version_get(const struct lu_env *env,
                                        struct md_object *obj)
{
        return 0;
}

static struct md_object_operations mdd_obf_obj_ops = {
        .moo_attr_get    = obf_attr_get,
        .moo_attr_set    = obf_attr_set,
        .moo_xattr_list  = obf_xattr_list,
        .moo_xattr_get   = obf_xattr_get,
        .moo_xattr_set   = obf_xattr_set,
        .moo_xattr_del   = obf_xattr_del,
        .moo_open        = obf_mdd_open,
        .moo_close       = obf_mdd_close,
        .moo_readpage    = obf_mdd_readpage,
        .moo_version_get = obf_version_get,
        .moo_path        = obf_path
};

/**
 * Lookup method for "fid" object. Only filenames with correct SEQ:OID format
 * are valid. We also check if object with passed fid exists or not.
 */
static int obf_lookup(const struct lu_env *env, struct md_object *p,
                      const struct lu_name *lname, struct lu_fid *f,
                      struct md_op_spec *spec)
{
        char *name = (char *)lname->ln_name;
        struct mdd_device *mdd = mdo2mdd(p);
        struct mdd_object *child;
        int rc = 0;

        while (*name == '[')
                name++;

        sscanf(name, SFID, RFID(f));
        if (!fid_is_sane(f)) {
                CWARN("bad FID format [%s], should be "DFID"\n", lname->ln_name,
                      (__u64)1, 2, 0);
                GOTO(out, rc = -EINVAL);
        }

        /* Check if object with this fid exists */
        child = mdd_object_find(env, mdd, f);
        if (child == NULL)
                GOTO(out, rc = 0);
        if (IS_ERR(child))
                GOTO(out, rc = PTR_ERR(child));

        if (mdd_object_exists(child) == 0)
                rc = -ENOENT;

        mdd_object_put(env, child);

out:
        return rc;
}

static int obf_create(const struct lu_env *env, struct md_object *pobj,
                      const struct lu_name *lname, struct md_object *child,
                      struct md_op_spec *spec, struct md_attr* ma)
{
        return -EPERM;
}

static int obf_rename(const struct lu_env *env,
                      struct md_object *src_pobj, struct md_object *tgt_pobj,
                      const struct lu_fid *lf, const struct lu_name *lsname,
                      struct md_object *tobj, const struct lu_name *ltname,
                      struct md_attr *ma)
{
        return -EPERM;
}

static int obf_link(const struct lu_env *env, struct md_object *tgt_obj,
                    struct md_object *src_obj, const struct lu_name *lname,
                    struct md_attr *ma)
{
        return -EPERM;
}

static int obf_unlink(const struct lu_env *env, struct md_object *pobj,
                      struct md_object *cobj, const struct lu_name *lname,
                      struct md_attr *ma)
{
        return -EPERM;
}

static struct md_dir_operations mdd_obf_dir_ops = {
        .mdo_lookup = obf_lookup,
        .mdo_create = obf_create,
        .mdo_rename = obf_rename,
        .mdo_link   = obf_link,
        .mdo_unlink = obf_unlink
};

/**
 * Create special in-memory "fid" object for open-by-fid.
 */
static int mdd_obf_setup(const struct lu_env *env, struct mdd_device *m)
{
        struct mdd_object *mdd_obf;
        struct lu_object *obf_lu_obj;
        int rc = 0;

        m->mdd_dot_lustre_objs.mdd_obf = mdd_object_find(env, m,
                                                         &LU_OBF_FID);
        if (m->mdd_dot_lustre_objs.mdd_obf == NULL ||
            IS_ERR(m->mdd_dot_lustre_objs.mdd_obf))
                GOTO(out, rc = -ENOENT);

        mdd_obf = m->mdd_dot_lustre_objs.mdd_obf;
        mdd_obf->mod_obj.mo_dir_ops = &mdd_obf_dir_ops;
        mdd_obf->mod_obj.mo_ops = &mdd_obf_obj_ops;
        /* Don't allow objects to be created in "fid" dir */
        mdd_obf->mod_flags |= IMMUTE_OBJ;

        obf_lu_obj = mdd2lu_obj(mdd_obf);
        obf_lu_obj->lo_header->loh_attr |= (LOHA_EXISTS | S_IFDIR);

out:
        return rc;
}

/** Setup ".lustre" directory object */
static int mdd_dot_lustre_setup(const struct lu_env *env, struct mdd_device *m)
{
        struct dt_object *dt_dot_lustre;
        struct lu_fid *fid = &mdd_env_info(env)->mti_fid;
        int rc;

        rc = create_dot_lustre_dir(env, m);
        if (rc)
                return rc;

        dt_dot_lustre = dt_store_open(env, m->mdd_child, mdd_root_dir_name,
                                      dot_lustre_name, fid);
        if (IS_ERR(dt_dot_lustre)) {
                rc = PTR_ERR(dt_dot_lustre);
                GOTO(out, rc);
        }

        /* references are released in mdd_device_shutdown() */
        m->mdd_dot_lustre = lu2mdd_obj(lu_object_locate(dt_dot_lustre->do_lu.lo_header,
                                                        &mdd_device_type));

        m->mdd_dot_lustre->mod_obj.mo_dir_ops = &mdd_dot_lustre_dir_ops;
        m->mdd_dot_lustre->mod_obj.mo_ops = &mdd_dot_lustre_obj_ops;

        rc = mdd_obf_setup(env, m);
        if (rc)
                CERROR("Error initializing \"fid\" object - %d.\n", rc);

out:
        RETURN(rc);
}

static int mdd_process_config(const struct lu_env *env,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct mdd_device *m    = lu2mdd_dev(d);
        struct dt_device  *dt   = m->mdd_child;
        struct lu_device  *next = &dt->dd_lu_dev;
        int rc;
        ENTRY;

        switch (cfg->lcfg_command) {
        case LCFG_PARAM: {
                struct lprocfs_static_vars lvars;

                lprocfs_mdd_init_vars(&lvars);
                rc = class_process_proc_param(PARAM_MDD, lvars.obd_vars, cfg,m);
                if (rc > 0 || rc == -ENOSYS)
                        /* we don't understand; pass it on */
                        rc = next->ld_ops->ldo_process_config(env, next, cfg);
                break;
        }
        case LCFG_SETUP:
                rc = next->ld_ops->ldo_process_config(env, next, cfg);
                if (rc)
                        GOTO(out, rc);
                dt->dd_ops->dt_conf_get(env, dt, &m->mdd_dt_conf);

                rc = mdd_init_obd(env, m, cfg);
                if (rc) {
                        CERROR("lov init error %d \n", rc);
                        GOTO(out, rc);
                }
                rc = mdd_txn_init_credits(env, m);
                if (rc)
                        break;

                mdd_changelog_init(env, m);
                break;
        case LCFG_CLEANUP:
                mdd_device_shutdown(env, m, cfg);
        default:
                rc = next->ld_ops->ldo_process_config(env, next, cfg);
                break;
        }
out:
        RETURN(rc);
}

#if 0
static int mdd_lov_set_nextid(const struct lu_env *env,
                              struct mdd_device *mdd)
{
        struct mds_obd *mds = &mdd->mdd_obd_dev->u.mds;
        int rc;
        ENTRY;

        LASSERT(mds->mds_lov_objids != NULL);
        rc = obd_set_info_async(mds->mds_lov_exp, strlen(KEY_NEXT_ID),
                                KEY_NEXT_ID, mds->mds_lov_desc.ld_tgt_count,
                                mds->mds_lov_objids, NULL);

        RETURN(rc);
}

static int mdd_cleanup_unlink_llog(const struct lu_env *env,
                                   struct mdd_device *mdd)
{
        /* XXX: to be implemented! */
        return 0;
}
#endif

static int mdd_recovery_complete(const struct lu_env *env,
                                 struct lu_device *d)
{
        struct mdd_device *mdd = lu2mdd_dev(d);
        struct lu_device *next = &mdd->mdd_child->dd_lu_dev;
        struct obd_device *obd = mdd2obd_dev(mdd);
        int rc;
        ENTRY;

        LASSERT(mdd != NULL);
        LASSERT(obd != NULL);
#if 0
        /* XXX: Do we need this in new stack? */
        rc = mdd_lov_set_nextid(env, mdd);
        if (rc) {
                CERROR("mdd_lov_set_nextid() failed %d\n",
                       rc);
                RETURN(rc);
        }

        /* XXX: cleanup unlink. */
        rc = mdd_cleanup_unlink_llog(env, mdd);
        if (rc) {
                CERROR("mdd_cleanup_unlink_llog() failed %d\n",
                       rc);
                RETURN(rc);
        }
#endif
        /* Call that with obd_recovering = 1 just to update objids */
        obd_notify(obd->u.mds.mds_lov_obd, NULL, (obd->obd_async_recov ?
                    OBD_NOTIFY_SYNC_NONBLOCK : OBD_NOTIFY_SYNC), NULL);

        /* Drop obd_recovering to 0 and call o_postrecov to recover mds_lov */
        cfs_spin_lock(&obd->obd_dev_lock);
        obd->obd_recovering = 0;
        cfs_spin_unlock(&obd->obd_dev_lock);
        obd->obd_type->typ_dt_ops->o_postrecov(obd);

        /* XXX: orphans handling. */
        __mdd_orphan_cleanup(env, mdd);
        rc = next->ld_ops->ldo_recovery_complete(env, next);

        RETURN(rc);
}

static int mdd_prepare(const struct lu_env *env,
                       struct lu_device *pdev,
                       struct lu_device *cdev)
{
        struct mdd_device *mdd = lu2mdd_dev(cdev);
        struct lu_device *next = &mdd->mdd_child->dd_lu_dev;
        struct dt_object *root;
        int rc;

        ENTRY;
        rc = next->ld_ops->ldo_prepare(env, cdev, next);
        if (rc)
                GOTO(out, rc);

        dt_txn_callback_add(mdd->mdd_child, &mdd->mdd_txn_cb);
        root = dt_store_open(env, mdd->mdd_child, "", mdd_root_dir_name,
                             &mdd->mdd_root_fid);
        if (!IS_ERR(root)) {
                LASSERT(root != NULL);
                lu_object_put(env, &root->do_lu);
                rc = orph_index_init(env, mdd);
        } else {
                rc = PTR_ERR(root);
        }
        if (rc)
                GOTO(out, rc);

        rc = mdd_dot_lustre_setup(env, mdd);
        if (rc) {
                CERROR("Error(%d) initializing .lustre objects\n", rc);
                GOTO(out, rc);
        }

out:
        RETURN(rc);
}

const struct lu_device_operations mdd_lu_ops = {
        .ldo_object_alloc      = mdd_object_alloc,
        .ldo_process_config    = mdd_process_config,
        .ldo_recovery_complete = mdd_recovery_complete,
        .ldo_prepare           = mdd_prepare,
};

/*
 * No permission check is needed.
 */
static int mdd_root_get(const struct lu_env *env,
                        struct md_device *m, struct lu_fid *f)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);

        ENTRY;
        *f = mdd->mdd_root_fid;
        RETURN(0);
}

/*
 * No permission check is needed.
 */
static int mdd_statfs(const struct lu_env *env, struct md_device *m,
                      cfs_kstatfs_t *sfs)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        int rc;

        ENTRY;

        rc = mdd_child_ops(mdd)->dt_statfs(env, mdd->mdd_child, sfs);

        RETURN(rc);
}

/*
 * No permission check is needed.
 */
static int mdd_maxsize_get(const struct lu_env *env, struct md_device *m,
                           int *md_size, int *cookie_size)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        ENTRY;

        *md_size = mdd_lov_mdsize(env, mdd);
        *cookie_size = mdd_lov_cookiesize(env, mdd);

        RETURN(0);
}

static int mdd_init_capa_ctxt(const struct lu_env *env, struct md_device *m,
                              int mode, unsigned long timeout, __u32 alg,
                              struct lustre_capa_key *keys)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct mds_obd    *mds = &mdd2obd_dev(mdd)->u.mds;
        int rc;
        ENTRY;

        /* need barrier for mds_capa_keys access. */
        cfs_down_write(&mds->mds_notify_lock);
        mds->mds_capa_keys = keys;
        cfs_up_write(&mds->mds_notify_lock);

        rc = mdd_child_ops(mdd)->dt_init_capa_ctxt(env, mdd->mdd_child, mode,
                                                   timeout, alg, keys);
        RETURN(rc);
}

static int mdd_update_capa_key(const struct lu_env *env,
                               struct md_device *m,
                               struct lustre_capa_key *key)
{
        struct mds_capa_info info = { .uuid = NULL, .capa = key };
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_export *lov_exp = mdd2obd_dev(mdd)->u.mds.mds_lov_exp;
        int rc;
        ENTRY;

        rc = obd_set_info_async(lov_exp, sizeof(KEY_CAPA_KEY), KEY_CAPA_KEY,
                                sizeof(info), &info, NULL);
        RETURN(rc);
}

static int mdd_llog_ctxt_get(const struct lu_env *env, struct md_device *m,
                             int idx, void **h)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);

        *h = llog_group_get_ctxt(&mdd2obd_dev(mdd)->obd_olg, idx);
        return (*h == NULL ? -ENOENT : 0);
}

static struct lu_device *mdd_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *lcfg)
{
        struct lu_device  *l;
        struct mdd_device *m;

        OBD_ALLOC_PTR(m);
        if (m == NULL) {
                l = ERR_PTR(-ENOMEM);
        } else {
                md_device_init(&m->mdd_md_dev, t);
                l = mdd2lu_dev(m);
                l->ld_ops = &mdd_lu_ops;
                m->mdd_md_dev.md_ops = &mdd_ops;
                md_upcall_init(&m->mdd_md_dev, NULL);
        }

        return l;
}

static struct lu_device *mdd_device_free(const struct lu_env *env,
                                         struct lu_device *lu)
{
        struct mdd_device *m = lu2mdd_dev(lu);
        struct lu_device  *next = &m->mdd_child->dd_lu_dev;
        ENTRY;

        LASSERT(cfs_atomic_read(&lu->ld_ref) == 0);
        md_device_fini(&m->mdd_md_dev);
        OBD_FREE_PTR(m);
        RETURN(next);
}

static struct obd_ops mdd_obd_device_ops = {
        .o_owner = THIS_MODULE
};

/* context key constructor/destructor: mdd_ucred_key_init, mdd_ucred_key_fini */
LU_KEY_INIT_FINI(mdd_ucred, struct md_ucred);

static struct lu_context_key mdd_ucred_key = {
        .lct_tags = LCT_SESSION,
        .lct_init = mdd_ucred_key_init,
        .lct_fini = mdd_ucred_key_fini
};

struct md_ucred *md_ucred(const struct lu_env *env)
{
        LASSERT(env->le_ses != NULL);
        return lu_context_key_get(env->le_ses, &mdd_ucred_key);
}
EXPORT_SYMBOL(md_ucred);

/*
 * context key constructor/destructor:
 * mdd_capainfo_key_init, mdd_capainfo_key_fini
 */
LU_KEY_INIT_FINI(mdd_capainfo, struct md_capainfo);

struct lu_context_key mdd_capainfo_key = {
        .lct_tags = LCT_SESSION,
        .lct_init = mdd_capainfo_key_init,
        .lct_fini = mdd_capainfo_key_fini
};

struct md_capainfo *md_capainfo(const struct lu_env *env)
{
        /* NB, in mdt_init0 */
        if (env->le_ses == NULL)
                return NULL;
        return lu_context_key_get(env->le_ses, &mdd_capainfo_key);
}
EXPORT_SYMBOL(md_capainfo);

/*
 * context key constructor/destructor:
 * mdd_quota_key_init, mdd_quota_key_fini
 */
LU_KEY_INIT_FINI(mdd_quota, struct md_quota);

struct lu_context_key mdd_quota_key = {
        .lct_tags = LCT_SESSION,
        .lct_init = mdd_quota_key_init,
        .lct_fini = mdd_quota_key_fini
};

struct md_quota *md_quota(const struct lu_env *env)
{
        LASSERT(env->le_ses != NULL);
        return lu_context_key_get(env->le_ses, &mdd_quota_key);
}
EXPORT_SYMBOL(md_quota);

static int mdd_changelog_user_register(struct mdd_device *mdd, int *id)
{
        struct llog_ctxt *ctxt;
        struct llog_changelog_user_rec *rec;
        int rc;
        ENTRY;

        ctxt = llog_get_context(mdd2obd_dev(mdd),LLOG_CHANGELOG_USER_ORIG_CTXT);
        if (ctxt == NULL)
                RETURN(-ENXIO);

        OBD_ALLOC_PTR(rec);
        if (rec == NULL) {
                llog_ctxt_put(ctxt);
                RETURN(-ENOMEM);
        }

        /* Assume we want it on since somebody registered */
        rc = mdd_changelog_on(mdd, 1);
        if (rc)
                GOTO(out, rc);

        rec->cur_hdr.lrh_len = sizeof(*rec);
        rec->cur_hdr.lrh_type = CHANGELOG_USER_REC;
        cfs_spin_lock(&mdd->mdd_cl.mc_user_lock);
        if (mdd->mdd_cl.mc_lastuser == (unsigned int)(-1)) {
                cfs_spin_unlock(&mdd->mdd_cl.mc_user_lock);
                CERROR("Maximum number of changelog users exceeded!\n");
                GOTO(out, rc = -EOVERFLOW);
        }
        *id = rec->cur_id = ++mdd->mdd_cl.mc_lastuser;
        rec->cur_endrec = mdd->mdd_cl.mc_index;
        cfs_spin_unlock(&mdd->mdd_cl.mc_user_lock);

        rc = llog_add(ctxt, &rec->cur_hdr, NULL, NULL, 0);

        CDEBUG(D_IOCTL, "Registered changelog user %d\n", *id);
out:
        OBD_FREE_PTR(rec);
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

struct mdd_changelog_user_data {
        __u64 mcud_endrec; /**< purge record for this user */
        __u64 mcud_minrec; /**< lowest changelog recno still referenced */
        __u32 mcud_id;
        __u32 mcud_minid;  /**< user id with lowest rec reference */
        __u32 mcud_usercount;
        int   mcud_found:1;
        struct mdd_device   *mcud_mdd;
        const struct lu_env *mcud_env;
};
#define MCUD_UNREGISTER -1LL

/** Two things:
 * 1. Find the smallest record everyone is willing to purge
 * 2. Update the last purgeable record for this user
 */
static int mdd_changelog_user_purge_cb(struct llog_handle *llh,
                                       struct llog_rec_hdr *hdr, void *data)
{
        struct llog_changelog_user_rec *rec;
        struct mdd_changelog_user_data *mcud =
                (struct mdd_changelog_user_data *)data;
        int rc;
        ENTRY;

        LASSERT(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN);

        rec = (struct llog_changelog_user_rec *)hdr;

        mcud->mcud_usercount++;

        /* If we have a new endrec for this id, use it for the following
           min check instead of its old value */
        if (rec->cur_id == mcud->mcud_id)
                rec->cur_endrec = max(rec->cur_endrec, mcud->mcud_endrec);

        /* Track the minimum referenced record */
        if (mcud->mcud_minid == 0 || mcud->mcud_minrec > rec->cur_endrec) {
                mcud->mcud_minid = rec->cur_id;
                mcud->mcud_minrec = rec->cur_endrec;
        }

        if (rec->cur_id != mcud->mcud_id)
                RETURN(0);

        /* Update this user's record */
        mcud->mcud_found = 1;

        /* Special case: unregister this user */
        if (mcud->mcud_endrec == MCUD_UNREGISTER) {
                struct llog_cookie cookie;
                void *trans_h;
                struct mdd_device *mdd = mcud->mcud_mdd;

                cookie.lgc_lgl = llh->lgh_id;
                cookie.lgc_index = hdr->lrh_index;

                /* XXX This is a workaround for the deadlock of changelog
                 * adding vs. changelog cancelling. LU-81. */
                mdd_txn_param_build(mcud->mcud_env, mdd, MDD_TXN_UNLINK_OP, 0);
                trans_h = mdd_trans_start(mcud->mcud_env, mdd);
                if (IS_ERR(trans_h)) {
                        CERROR("fsfilt_start_log failed: %ld\n",
                               PTR_ERR(trans_h));
                        RETURN(PTR_ERR(trans_h));
                }

                rc = llog_cat_cancel_records(llh->u.phd.phd_cat_handle,
                                             1, &cookie);
                if (rc == 0)
                        mcud->mcud_usercount--;

                mdd_trans_stop(mcud->mcud_env, mdd, rc, trans_h);
                RETURN(rc);
        }

        /* Update the endrec */
        CDEBUG(D_IOCTL, "Rewriting changelog user %d endrec to "LPU64"\n",
               mcud->mcud_id, rec->cur_endrec);

        /* hdr+1 is loc of data */
        hdr->lrh_len -= sizeof(*hdr) + sizeof(struct llog_rec_tail);
        rc = llog_write_rec(llh, hdr, NULL, 0, (void *)(hdr + 1),
                            hdr->lrh_index);

        RETURN(rc);
}

static int mdd_changelog_user_purge(const struct lu_env *env,
                                    struct mdd_device *mdd, int id,
                                    long long endrec)
{
        struct mdd_changelog_user_data data;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        CDEBUG(D_IOCTL, "Purge request: id=%d, endrec=%lld\n", id, endrec);

        data.mcud_id = id;
        data.mcud_minid = 0;
        data.mcud_minrec = 0;
        data.mcud_usercount = 0;
        data.mcud_endrec = endrec;
        data.mcud_mdd = mdd;
        data.mcud_env = env;
        cfs_spin_lock(&mdd->mdd_cl.mc_lock);
        endrec = mdd->mdd_cl.mc_index;
        cfs_spin_unlock(&mdd->mdd_cl.mc_lock);
        if ((data.mcud_endrec == 0) ||
            ((data.mcud_endrec > endrec) &&
             (data.mcud_endrec != MCUD_UNREGISTER)))
                data.mcud_endrec = endrec;

        ctxt = llog_get_context(mdd2obd_dev(mdd),LLOG_CHANGELOG_USER_ORIG_CTXT);
        if (ctxt == NULL)
                return -ENXIO;
        LASSERT(ctxt->loc_handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT);

        rc = llog_cat_process(ctxt->loc_handle, mdd_changelog_user_purge_cb,
                              (void *)&data, 0, 0);
        if ((rc >= 0) && (data.mcud_minrec > 0)) {
                CDEBUG(D_IOCTL, "Purging changelog entries up to "LPD64
                       ", referenced by "CHANGELOG_USER_PREFIX"%d\n",
                       data.mcud_minrec, data.mcud_minid);
                rc = mdd_changelog_llog_cancel(mdd, data.mcud_minrec);
        } else {
                CWARN("Could not determine changelog records to purge; rc=%d\n",
                      rc);
        }

        llog_ctxt_put(ctxt);

        if (!data.mcud_found) {
                CWARN("No entry for user %d.  Last changelog reference is "
                      LPD64" by changelog user %d\n", data.mcud_id,
                      data.mcud_minrec, data.mcud_minid);
               rc = -ENOENT;
        }

        if (!rc && data.mcud_usercount == 0)
                /* No more users; turn changelogs off */
                rc = mdd_changelog_on(mdd, 0);

        RETURN (rc);
}

/** mdd_iocontrol
 * May be called remotely from mdt_iocontrol_handle or locally from
 * mdt_iocontrol. Data may be freeform - remote handling doesn't enforce
 * an obd_ioctl_data format (but local ioctl handler does).
 * \param cmd - ioc
 * \param len - data len
 * \param karg - ioctl data, in kernel space
 */
static int mdd_iocontrol(const struct lu_env *env, struct md_device *m,
                         unsigned int cmd, int len, void *karg)
{
        struct mdd_device *mdd;
        struct obd_ioctl_data *data = karg;
        int rc;
        ENTRY;

        mdd = lu2mdd_dev(&m->md_lu_dev);

        /* Doesn't use obd_ioctl_data */
        if (cmd == OBD_IOC_CHANGELOG_CLEAR) {
                struct changelog_setinfo *cs = karg;
                rc = mdd_changelog_user_purge(env, mdd, cs->cs_id,
                                              cs->cs_recno);
                RETURN(rc);
        }

        /* Below ioctls use obd_ioctl_data */
        if (len != sizeof(*data)) {
                CERROR("Bad ioctl size %d\n", len);
                RETURN(-EINVAL);
        }
        if (data->ioc_version != OBD_IOCTL_VERSION) {
                CERROR("Bad magic %x != %x\n", data->ioc_version,
                       OBD_IOCTL_VERSION);
                RETURN(-EINVAL);
        }

        switch (cmd) {
        case OBD_IOC_CHANGELOG_REG:
                rc = mdd_changelog_user_register(mdd, &data->ioc_u32_1);
                break;
        case OBD_IOC_CHANGELOG_DEREG:
                rc = mdd_changelog_user_purge(env, mdd, data->ioc_u32_1,
                                              MCUD_UNREGISTER);
                break;
        default:
                rc = -EOPNOTSUPP;
        }

        RETURN (rc);
}

/* type constructor/destructor: mdd_type_init, mdd_type_fini */
LU_TYPE_INIT_FINI(mdd, &mdd_thread_key, &mdd_ucred_key, &mdd_capainfo_key,
                  &mdd_quota_key);

const struct md_device_operations mdd_ops = {
        .mdo_statfs         = mdd_statfs,
        .mdo_root_get       = mdd_root_get,
        .mdo_maxsize_get    = mdd_maxsize_get,
        .mdo_init_capa_ctxt = mdd_init_capa_ctxt,
        .mdo_update_capa_key= mdd_update_capa_key,
        .mdo_llog_ctxt_get  = mdd_llog_ctxt_get,
        .mdo_iocontrol      = mdd_iocontrol,
#ifdef HAVE_QUOTA_SUPPORT
        .mdo_quota          = {
                .mqo_notify      = mdd_quota_notify,
                .mqo_setup       = mdd_quota_setup,
                .mqo_cleanup     = mdd_quota_cleanup,
                .mqo_recovery    = mdd_quota_recovery,
                .mqo_check       = mdd_quota_check,
                .mqo_on          = mdd_quota_on,
                .mqo_off         = mdd_quota_off,
                .mqo_setinfo     = mdd_quota_setinfo,
                .mqo_getinfo     = mdd_quota_getinfo,
                .mqo_setquota    = mdd_quota_setquota,
                .mqo_getquota    = mdd_quota_getquota,
                .mqo_getoinfo    = mdd_quota_getoinfo,
                .mqo_getoquota   = mdd_quota_getoquota,
                .mqo_invalidate  = mdd_quota_invalidate,
                .mqo_finvalidate = mdd_quota_finvalidate
        }
#endif
};

static struct lu_device_type_operations mdd_device_type_ops = {
        .ldto_init = mdd_type_init,
        .ldto_fini = mdd_type_fini,

        .ldto_start = mdd_type_start,
        .ldto_stop  = mdd_type_stop,

        .ldto_device_alloc = mdd_device_alloc,
        .ldto_device_free  = mdd_device_free,

        .ldto_device_init    = mdd_device_init,
        .ldto_device_fini    = mdd_device_fini
};

static struct lu_device_type mdd_device_type = {
        .ldt_tags     = LU_DEVICE_MD,
        .ldt_name     = LUSTRE_MDD_NAME,
        .ldt_ops      = &mdd_device_type_ops,
        .ldt_ctx_tags = LCT_MD_THREAD
};

/* context key constructor: mdd_key_init */
LU_KEY_INIT(mdd, struct mdd_thread_info);

static void mdd_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct mdd_thread_info *info = data;
        if (info->mti_max_lmm != NULL)
                OBD_FREE(info->mti_max_lmm, info->mti_max_lmm_size);
        if (info->mti_max_cookie != NULL)
                OBD_FREE(info->mti_max_cookie, info->mti_max_cookie_size);
        mdd_buf_put(&info->mti_big_buf);

        OBD_FREE_PTR(info);
}

/* context key: mdd_thread_key */
LU_CONTEXT_KEY_DEFINE(mdd, LCT_MD_THREAD);

static struct lu_local_obj_desc llod_capa_key = {
        .llod_name      = CAPA_KEYS,
        .llod_oid       = MDD_CAPA_KEYS_OID,
        .llod_is_index  = 0,
};

static struct lu_local_obj_desc llod_mdd_orphan = {
        .llod_name      = orph_index_name,
        .llod_oid       = MDD_ORPHAN_OID,
        .llod_is_index  = 1,
        .llod_feat      = &dt_directory_features,
};

static struct lu_local_obj_desc llod_mdd_root = {
        .llod_name      = mdd_root_dir_name,
        .llod_oid       = MDD_ROOT_INDEX_OID,
        .llod_is_index  = 1,
        .llod_feat      = &dt_directory_features,
};

static int __init mdd_mod_init(void)
{
        struct lprocfs_static_vars lvars;
        lprocfs_mdd_init_vars(&lvars);

        llo_local_obj_register(&llod_capa_key);
        llo_local_obj_register(&llod_mdd_orphan);
        llo_local_obj_register(&llod_mdd_root);

        return class_register_type(&mdd_obd_device_ops, NULL, lvars.module_vars,
                                   LUSTRE_MDD_NAME, &mdd_device_type);
}

static void __exit mdd_mod_exit(void)
{
        llo_local_obj_unregister(&llod_capa_key);
        llo_local_obj_unregister(&llod_mdd_orphan);
        llo_local_obj_unregister(&llod_mdd_root);

        class_unregister_type(LUSTRE_MDD_NAME);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Meta-data Device Prototype ("LUSTRE_MDD_NAME")");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.1.0", mdd_mod_init, mdd_mod_exit);
