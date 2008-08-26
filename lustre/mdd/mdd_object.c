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
 * lustre/mdd/mdd_object.c
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
#include <obd_support.h>
#include <lprocfs_status.h>
/* fid_be_cpu(), fid_cpu_to_be(). */
#include <lustre_fid.h>

#include <linux/ldiskfs_fs.h>
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>

#include "mdd_internal.h"

static struct lu_object_operations mdd_lu_obj_ops;

int mdd_la_get(const struct lu_env *env, struct mdd_object *obj,
               struct lu_attr *la, struct lustre_capa *capa)
{
        LASSERTF(mdd_object_exists(obj), "FID is "DFID"\n",
                 PFID(mdd_object_fid(obj)));
        return mdo_attr_get(env, obj, la, capa);
}

static void mdd_flags_xlate(struct mdd_object *obj, __u32 flags)
{
        obj->mod_flags &= ~(APPEND_OBJ|IMMUTE_OBJ);

        if (flags & LUSTRE_APPEND_FL)
                obj->mod_flags |= APPEND_OBJ;

        if (flags & LUSTRE_IMMUTABLE_FL)
                obj->mod_flags |= IMMUTE_OBJ;
}

struct lu_buf *mdd_buf_get(const struct lu_env *env, void *area, ssize_t len)
{
        struct lu_buf *buf;

        buf = &mdd_env_info(env)->mti_buf;
        buf->lb_buf = area;
        buf->lb_len = len;
        return buf;
}

struct llog_cookie *mdd_max_cookie_get(const struct lu_env *env,
                                       struct mdd_device *mdd)
{
        struct mdd_thread_info *mti = mdd_env_info(env);
        int                     max_cookie_size;

        max_cookie_size = mdd_lov_cookiesize(env, mdd);
        if (unlikely(mti->mti_max_cookie_size < max_cookie_size)) {
                if (mti->mti_max_cookie)
                        OBD_FREE(mti->mti_max_cookie, mti->mti_max_cookie_size);
                mti->mti_max_cookie = NULL;
                mti->mti_max_cookie_size = 0;
        }
        if (unlikely(mti->mti_max_cookie == NULL)) {
                OBD_ALLOC(mti->mti_max_cookie, max_cookie_size);
                if (unlikely(mti->mti_max_cookie != NULL))
                        mti->mti_max_cookie_size = max_cookie_size;
        }
        return mti->mti_max_cookie;
}

struct lov_mds_md *mdd_max_lmm_get(const struct lu_env *env,
                                   struct mdd_device *mdd)
{
        struct mdd_thread_info *mti = mdd_env_info(env);
        int                     max_lmm_size;

        max_lmm_size = mdd_lov_mdsize(env, mdd);
        if (unlikely(mti->mti_max_lmm_size < max_lmm_size)) {
                if (mti->mti_max_lmm)
                        OBD_FREE(mti->mti_max_lmm, mti->mti_max_lmm_size);
                mti->mti_max_lmm = NULL;
                mti->mti_max_lmm_size = 0;
        }
        if (unlikely(mti->mti_max_lmm == NULL)) {
                OBD_ALLOC(mti->mti_max_lmm, max_lmm_size);
                if (unlikely(mti->mti_max_lmm != NULL))
                        mti->mti_max_lmm_size = max_lmm_size;
        }
        return mti->mti_max_lmm;
}

const struct lu_buf *mdd_buf_get_const(const struct lu_env *env,
                                       const void *area, ssize_t len)
{
        struct lu_buf *buf;

        buf = &mdd_env_info(env)->mti_buf;
        buf->lb_buf = (void *)area;
        buf->lb_len = len;
        return buf;
}

struct mdd_thread_info *mdd_env_info(const struct lu_env *env)
{
        struct mdd_thread_info *info;

        info = lu_context_key_get(&env->le_ctx, &mdd_thread_key);
        LASSERT(info != NULL);
        return info;
}

struct lu_object *mdd_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *d)
{
        struct mdd_object *mdd_obj;

        OBD_ALLOC_PTR(mdd_obj);
        if (mdd_obj != NULL) {
                struct lu_object *o;

                o = mdd2lu_obj(mdd_obj);
                lu_object_init(o, NULL, d);
                mdd_obj->mod_obj.mo_ops = &mdd_obj_ops;
                mdd_obj->mod_obj.mo_dir_ops = &mdd_dir_ops;
                mdd_obj->mod_count = 0;
                o->lo_ops = &mdd_lu_obj_ops;
                return o;
        } else {
                return NULL;
        }
}

static int mdd_object_init(const struct lu_env *env, struct lu_object *o)
{
	struct mdd_device *d = lu2mdd_dev(o->lo_dev);
	struct lu_object  *below;
        struct lu_device  *under;
        ENTRY;

	under = &d->mdd_child->dd_lu_dev;
	below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
        mdd_pdlock_init(lu2mdd_obj(o));
        if (below == NULL)
		RETURN(-ENOMEM);

        lu_object_add(o, below);
        RETURN(0);
}

static int mdd_object_start(const struct lu_env *env, struct lu_object *o)
{
        if (lu_object_exists(o))
                return mdd_get_flags(env, lu2mdd_obj(o));
        else
                return 0;
}

static void mdd_object_free(const struct lu_env *env, struct lu_object *o)
{
        struct mdd_object *mdd = lu2mdd_obj(o);
	
        lu_object_fini(o);
        OBD_FREE_PTR(mdd);
}

static int mdd_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        return (*p)(env, cookie, LUSTRE_MDD_NAME"-object@%p", o);
}

/* orphan handling is here */
static void mdd_object_delete(const struct lu_env *env,
                               struct lu_object *o)
{
        struct mdd_object *mdd_obj = lu2mdd_obj(o);
        struct thandle *handle = NULL;
        ENTRY;

        if (lu2mdd_dev(o->lo_dev)->mdd_orphans == NULL)
                return;

        if (mdd_obj->mod_flags & ORPHAN_OBJ) {
                mdd_txn_param_build(env, lu2mdd_dev(o->lo_dev),
                                    MDD_TXN_INDEX_DELETE_OP);
                handle = mdd_trans_start(env, lu2mdd_dev(o->lo_dev));
                if (IS_ERR(handle))
                        CERROR("Cannot get thandle\n");
                else {
                        mdd_write_lock(env, mdd_obj);
                        /* let's remove obj from the orphan list */
                        __mdd_orphan_del(env, mdd_obj, handle);
                        mdd_write_unlock(env, mdd_obj);
                        mdd_trans_stop(env, lu2mdd_dev(o->lo_dev),
                                       0, handle);
                }
        }
}

static struct lu_object_operations mdd_lu_obj_ops = {
	.loo_object_init    = mdd_object_init,
	.loo_object_start   = mdd_object_start,
	.loo_object_free    = mdd_object_free,
	.loo_object_print   = mdd_object_print,
        .loo_object_delete  = mdd_object_delete
};

struct mdd_object *mdd_object_find(const struct lu_env *env,
                                   struct mdd_device *d,
                                   const struct lu_fid *f)
{
        struct lu_object *o, *lo;
        struct mdd_object *m;
        ENTRY;

        o = lu_object_find(env, mdd2lu_dev(d)->ld_site, f);
        if (IS_ERR(o))
                m = (struct mdd_object *)o;
        else {
                lo = lu_object_locate(o->lo_header, mdd2lu_dev(d)->ld_type);
                /* remote object can't be located and should be put then */
                if (lo == NULL)
                        lu_object_put(env, o);
                m = lu2mdd_obj(lo);
        }
        RETURN(m);
}

int mdd_get_flags(const struct lu_env *env, struct mdd_object *obj)
{
        struct lu_attr *la = &mdd_env_info(env)->mti_la;
        int rc;

        ENTRY;
        rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
        if (rc == 0) {
                mdd_flags_xlate(obj, la->la_flags);
                if (S_ISDIR(la->la_mode) && la->la_nlink == 1)
                        obj->mod_flags |= MNLINK_OBJ;
        }
        RETURN(rc);
}

/* get only inode attributes */
int mdd_iattr_get(const struct lu_env *env, struct mdd_object *mdd_obj,
                  struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        if (ma->ma_valid & MA_INODE)
                RETURN(0);

        rc = mdd_la_get(env, mdd_obj, &ma->ma_attr,
                          mdd_object_capa(env, mdd_obj));
        if (rc == 0)
                ma->ma_valid |= MA_INODE;
        RETURN(rc);
}

static int mdd_get_default_md(struct mdd_object *mdd_obj,
                struct lov_mds_md *lmm, int *size)
{
        struct lov_desc *ldesc;
        struct mdd_device *mdd = mdo2mdd(&mdd_obj->mod_obj);
        ENTRY;

        ldesc = &mdd->mdd_obd_dev->u.mds.mds_lov_desc;
        LASSERT(ldesc != NULL);

        if (!lmm)
                RETURN(0);

        lmm->lmm_magic = LOV_MAGIC_V1;
        lmm->lmm_object_gr = LOV_OBJECT_GROUP_DEFAULT;
        lmm->lmm_pattern = ldesc->ld_pattern;
        lmm->lmm_stripe_size = ldesc->ld_default_stripe_size;
        lmm->lmm_stripe_count = ldesc->ld_default_stripe_count;
        *size = sizeof(struct lov_mds_md);

        RETURN(sizeof(struct lov_mds_md));
}

/* get lov EA only */
static int __mdd_lmm_get(const struct lu_env *env,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;
        ENTRY;

        if (ma->ma_valid & MA_LOV)
                RETURN(0);

        rc = mdd_get_md(env, mdd_obj, ma->ma_lmm, &ma->ma_lmm_size,
                        MDS_LOV_MD_NAME);

        if (rc == 0 && (ma->ma_need & MA_LOV_DEF)) {
                rc = mdd_get_default_md(mdd_obj, ma->ma_lmm,
                                &ma->ma_lmm_size);
        }

        if (rc > 0) {
                ma->ma_valid |= MA_LOV;
                rc = 0;
        }
        RETURN(rc);
}

int mdd_lmm_get_locked(const struct lu_env *env, struct mdd_object *mdd_obj,
                       struct md_attr *ma)
{
        int rc;
        ENTRY;

        mdd_read_lock(env, mdd_obj);
        rc = __mdd_lmm_get(env, mdd_obj, ma);
        mdd_read_unlock(env, mdd_obj);
        RETURN(rc);
}

/* get lmv EA only*/
static int __mdd_lmv_get(const struct lu_env *env,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;
        ENTRY;

        if (ma->ma_valid & MA_LMV)
                RETURN(0);

        rc = mdd_get_md(env, mdd_obj, ma->ma_lmv, &ma->ma_lmv_size,
                        MDS_LMV_MD_NAME);
        if (rc > 0) {
                ma->ma_valid |= MA_LMV;
                rc = 0;
        }
        RETURN(rc);
}

static int mdd_attr_get_internal(const struct lu_env *env,
                                 struct mdd_object *mdd_obj,
                                 struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        if (ma->ma_need & MA_INODE)
                rc = mdd_iattr_get(env, mdd_obj, ma);

        if (rc == 0 && ma->ma_need & MA_LOV) {
                if (S_ISREG(mdd_object_type(mdd_obj)) ||
                    S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = __mdd_lmm_get(env, mdd_obj, ma);
        }
        if (rc == 0 && ma->ma_need & MA_LMV) {
                if (S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = __mdd_lmv_get(env, mdd_obj, ma);
        }
#ifdef CONFIG_FS_POSIX_ACL
        if (rc == 0 && ma->ma_need & MA_ACL_DEF) {
                if (S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = mdd_def_acl_get(env, mdd_obj, ma);
        }
#endif
        CDEBUG(D_INODE, "after getattr rc = %d, ma_valid = "LPX64"\n",
               rc, ma->ma_valid);
        RETURN(rc);
}

int mdd_attr_get_internal_locked(const struct lu_env *env,
                                 struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;
        int needlock = ma->ma_need & (MA_LOV | MA_LMV | MA_ACL_DEF);

        if (needlock)
                mdd_read_lock(env, mdd_obj);
        rc = mdd_attr_get_internal(env, mdd_obj, ma);
        if (needlock)
                mdd_read_unlock(env, mdd_obj);
        return rc;
}

/*
 * No permission check is needed.
 */
static int mdd_attr_get(const struct lu_env *env, struct md_object *obj,
                        struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int                rc;

        ENTRY;
        rc = mdd_attr_get_internal_locked(env, mdd_obj, ma);
        RETURN(rc);
}

/*
 * No permission check is needed.
 */
static int mdd_xattr_get(const struct lu_env *env,
                         struct md_object *obj, struct lu_buf *buf,
                         const char *name)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;

        ENTRY;

        LASSERT(mdd_object_exists(mdd_obj));

        mdd_read_lock(env, mdd_obj);
        rc = mdo_xattr_get(env, mdd_obj, buf, name,
                           mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);

        RETURN(rc);
}

/*
 * Permission check is done when open,
 * no need check again.
 */
static int mdd_readlink(const struct lu_env *env, struct md_object *obj,
                        struct lu_buf *buf)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        loff_t             pos = 0;
        int                rc;
        ENTRY;

        LASSERT(mdd_object_exists(mdd_obj));

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(env, mdd_obj);
        rc = next->do_body_ops->dbo_read(env, next, buf, &pos,
                                         mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);
        RETURN(rc);
}

/*
 * No permission check is needed.
 */
static int mdd_xattr_list(const struct lu_env *env, struct md_object *obj,
                          struct lu_buf *buf)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;

        ENTRY;

        mdd_read_lock(env, mdd_obj);
        rc = mdo_xattr_list(env, mdd_obj, buf, mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);

        RETURN(rc);
}

int mdd_object_create_internal(const struct lu_env *env, struct mdd_object *p,
                               struct mdd_object *c, struct md_attr *ma,
                               struct thandle *handle)
{
        struct lu_attr *attr = &ma->ma_attr;
        struct dt_allocation_hint *hint = &mdd_env_info(env)->mti_hint;
        int rc;
        ENTRY;

        if (!mdd_object_exists(c)) {
                struct dt_object *next = mdd_object_child(c);
                LASSERT(next);

                /* @hint will be initialized by underlying device. */
                next->do_ops->do_ah_init(env, hint,
                                         p ? mdd_object_child(p) : NULL,
                                         attr->la_mode & S_IFMT);
                rc = mdo_create_obj(env, c, attr, hint, handle);
                LASSERT(ergo(rc == 0, mdd_object_exists(c)));
        } else
                rc = -EEXIST;

        RETURN(rc);
}

/**
 * Make sure the ctime is increased only.
 */
static inline int mdd_attr_check(const struct lu_env *env,
                                 struct mdd_object *obj,
                                 struct lu_attr *attr)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        int rc;
        ENTRY;

        if (attr->la_valid & LA_CTIME) {
                rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
                if (rc)
                        RETURN(rc);

                if (attr->la_ctime < tmp_la->la_ctime)
                        attr->la_valid &= ~(LA_MTIME | LA_CTIME);
                else if (attr->la_valid == LA_CTIME &&
                         attr->la_ctime == tmp_la->la_ctime)
                        attr->la_valid &= ~LA_CTIME;
        }
        RETURN(0);
}

int mdd_attr_set_internal(const struct lu_env *env,
                          struct mdd_object *obj,
                          struct lu_attr *attr,
                          struct thandle *handle,
                          int needacl)
{
        int rc;
        ENTRY;

        rc = mdo_attr_set(env, obj, attr, handle, mdd_object_capa(env, obj));
#ifdef CONFIG_FS_POSIX_ACL
        if (!rc && (attr->la_valid & LA_MODE) && needacl)
                rc = mdd_acl_chmod(env, obj, attr->la_mode, handle);
#endif
        RETURN(rc);
}

int mdd_attr_check_set_internal(const struct lu_env *env,
                                struct mdd_object *obj,
                                struct lu_attr *attr,
                                struct thandle *handle,
                                int needacl)
{
        int rc;
        ENTRY;

        rc = mdd_attr_check(env, obj, attr);
        if (rc)
                RETURN(rc);

        if (attr->la_valid)
                rc = mdd_attr_set_internal(env, obj, attr, handle, needacl);
        RETURN(rc);
}

static int mdd_attr_set_internal_locked(const struct lu_env *env,
                                        struct mdd_object *obj,
                                        struct lu_attr *attr,
                                        struct thandle *handle,
                                        int needacl)
{
        int rc;
        ENTRY;

        needacl = needacl && (attr->la_valid & LA_MODE);
        if (needacl)
                mdd_write_lock(env, obj);
        rc = mdd_attr_set_internal(env, obj, attr, handle, needacl);
        if (needacl)
                mdd_write_unlock(env, obj);
        RETURN(rc);
}

int mdd_attr_check_set_internal_locked(const struct lu_env *env,
                                       struct mdd_object *obj,
                                       struct lu_attr *attr,
                                       struct thandle *handle,
                                       int needacl)
{
        int rc;
        ENTRY;

        needacl = needacl && (attr->la_valid & LA_MODE);
        if (needacl)
                mdd_write_lock(env, obj);
        rc = mdd_attr_check_set_internal(env, obj, attr, handle, needacl);
        if (needacl)
                mdd_write_unlock(env, obj);
        RETURN(rc);
}

static int __mdd_xattr_set(const struct lu_env *env, struct mdd_object *obj,
                           const struct lu_buf *buf, const char *name,
                           int fl, struct thandle *handle)
{
        struct lustre_capa *capa = mdd_object_capa(env, obj);
        int rc = -EINVAL;
        ENTRY;

        if (buf->lb_buf && buf->lb_len > 0)
                rc = mdo_xattr_set(env, obj, buf, name, 0, handle, capa);
        else if (buf->lb_buf == NULL && buf->lb_len == 0)
                rc = mdo_xattr_del(env, obj, name, handle, capa);

        RETURN(rc);
}

/*
 * This gives the same functionality as the code between
 * sys_chmod and inode_setattr
 * chown_common and inode_setattr
 * utimes and inode_setattr
 * This API is ported from mds_fix_attr but remove some unnecesssary stuff.
 */
static int mdd_fix_attr(const struct lu_env *env, struct mdd_object *obj,
                        struct lu_attr *la, const struct md_attr *ma)
{
        struct lu_attr   *tmp_la     = &mdd_env_info(env)->mti_la;
        struct md_ucred  *uc         = md_ucred(env);
        int               rc;
        ENTRY;

        if (!la->la_valid)
                RETURN(0);

        /* Do not permit change file type */
        if (la->la_valid & LA_TYPE)
                RETURN(-EPERM);

        /* They should not be processed by setattr */
        if (la->la_valid & (LA_NLINK | LA_RDEV | LA_BLKSIZE))
                RETURN(-EPERM);

        rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        if (la->la_valid == LA_CTIME) {
                if (!(ma->ma_attr_flags & MDS_PERM_BYPASS))
                        /* This is only for set ctime when rename's source is
                         * on remote MDS. */
                        rc = mdd_may_delete(env, NULL, obj,
                                            (struct md_attr *)ma, 1, 0);
                if (rc == 0 && la->la_ctime <= tmp_la->la_ctime)
                        la->la_valid &= ~LA_CTIME;
                RETURN(rc);
        }

        if (la->la_valid == LA_ATIME) {
                /* This is atime only set for read atime update on close. */
                if (la->la_atime <= tmp_la->la_atime +
                                    mdd_obj2mdd_dev(obj)->mdd_atime_diff)
                        la->la_valid &= ~LA_ATIME;
                RETURN(0);
        }
 
        /* Check if flags change. */
        if (la->la_valid & LA_FLAGS) {
                unsigned int oldflags = 0;
                unsigned int newflags = la->la_flags &
                                (LUSTRE_IMMUTABLE_FL | LUSTRE_APPEND_FL);

                if ((uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CAP_FOWNER))
                        RETURN(-EPERM);

                /* XXX: the IMMUTABLE and APPEND_ONLY flags can
                 * only be changed by the relevant capability. */
                if (mdd_is_immutable(obj))
                        oldflags |= LUSTRE_IMMUTABLE_FL;
                if (mdd_is_append(obj))
                        oldflags |= LUSTRE_APPEND_FL; 
                if ((oldflags ^ newflags) &&
                    !mdd_capable(uc, CAP_LINUX_IMMUTABLE))
                        RETURN(-EPERM);

                if (!S_ISDIR(tmp_la->la_mode))
                        la->la_flags &= ~LUSTRE_DIRSYNC_FL;
        }

        if ((mdd_is_immutable(obj) || mdd_is_append(obj)) &&
            (la->la_valid & ~LA_FLAGS) &&
            !(ma->ma_attr_flags & MDS_PERM_BYPASS))
                RETURN(-EPERM);

        /* Check for setting the obj time. */
        if ((la->la_valid & (LA_MTIME | LA_ATIME | LA_CTIME)) &&
            !(la->la_valid & ~(LA_MTIME | LA_ATIME | LA_CTIME))) {
                if ((uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CAP_FOWNER)) {
                        rc = mdd_permission_internal_locked(env, obj, tmp_la,
                                                            MAY_WRITE);
                        if (rc)
                                RETURN(rc);
                }
        }

        /* Make sure a caller can chmod. */
        if (la->la_valid & LA_MODE) {
                /* Bypass la_vaild == LA_MODE,
                 * this is for changing file with SUID or SGID. */
                if ((la->la_valid & ~LA_MODE) &&
                    (uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CAP_FOWNER))
                        RETURN(-EPERM);

                if (la->la_mode == (umode_t) -1)
                        la->la_mode = tmp_la->la_mode;
                else
                        la->la_mode = (la->la_mode & S_IALLUGO) |
                                      (tmp_la->la_mode & ~S_IALLUGO);

                /* Also check the setgid bit! */
                if (!lustre_in_group_p(uc, (la->la_valid & LA_GID) ? la->la_gid :
                                tmp_la->la_gid) && !mdd_capable(uc, CAP_FSETID))
                        la->la_mode &= ~S_ISGID;
        } else {
               la->la_mode = tmp_la->la_mode;
        }

        /* Make sure a caller can chown. */
        if (la->la_valid & LA_UID) {
                if (la->la_uid == (uid_t) -1)
                        la->la_uid = tmp_la->la_uid;
                if (((uc->mu_fsuid != tmp_la->la_uid) ||
                    (la->la_uid != tmp_la->la_uid)) &&
                    !mdd_capable(uc, CAP_CHOWN))
                        RETURN(-EPERM);

                /* If the user or group of a non-directory has been
                 * changed by a non-root user, remove the setuid bit.
                 * 19981026 David C Niemi <niemi@tux.org>
                 *
                 * Changed this to apply to all users, including root,
                 * to avoid some races. This is the behavior we had in
                 * 2.0. The check for non-root was definitely wrong
                 * for 2.2 anyway, as it should have been using
                 * CAP_FSETID rather than fsuid -- 19990830 SD. */
                if (((tmp_la->la_mode & S_ISUID) == S_ISUID) &&
                    !S_ISDIR(tmp_la->la_mode)) {
                        la->la_mode &= ~S_ISUID;
                        la->la_valid |= LA_MODE;
                }
        }

        /* Make sure caller can chgrp. */
        if (la->la_valid & LA_GID) {
                if (la->la_gid == (gid_t) -1)
                        la->la_gid = tmp_la->la_gid;
                if (((uc->mu_fsuid != tmp_la->la_uid) ||
                    ((la->la_gid != tmp_la->la_gid) &&
                    !lustre_in_group_p(uc, la->la_gid))) &&
                    !mdd_capable(uc, CAP_CHOWN))
                        RETURN(-EPERM);

                /* Likewise, if the user or group of a non-directory
                 * has been changed by a non-root user, remove the
                 * setgid bit UNLESS there is no group execute bit
                 * (this would be a file marked for mandatory
                 * locking).  19981026 David C Niemi <niemi@tux.org>
                 *
                 * Removed the fsuid check (see the comment above) --
                 * 19990830 SD. */
                if (((tmp_la->la_mode & (S_ISGID | S_IXGRP)) ==
                     (S_ISGID | S_IXGRP)) && !S_ISDIR(tmp_la->la_mode)) {
                        la->la_mode &= ~S_ISGID;
                        la->la_valid |= LA_MODE;
                }
        }

        /* For both Size-on-MDS case and truncate case,
         * "la->la_valid & (LA_SIZE | LA_BLOCKS)" are ture.
         * We distinguish them by "ma->ma_attr_flags & MDS_SOM".
         * For SOM case, it is true, the MAY_WRITE perm has been checked
         * when open, no need check again. For truncate case, it is false,
         * the MAY_WRITE perm should be checked here. */
        if (ma->ma_attr_flags & MDS_SOM) {
                /* For the "Size-on-MDS" setattr update, merge coming
                 * attributes with the set in the inode. BUG 10641 */
                if ((la->la_valid & LA_ATIME) &&
                    (la->la_atime <= tmp_la->la_atime))
                        la->la_valid &= ~LA_ATIME;

                /* OST attributes do not have a priority over MDS attributes,
                 * so drop times if ctime is equal. */
                if ((la->la_valid & LA_CTIME) &&
                    (la->la_ctime <= tmp_la->la_ctime))
                        la->la_valid &= ~(LA_MTIME | LA_CTIME);
        } else {
                if (la->la_valid & (LA_SIZE | LA_BLOCKS)) {
                        if (!((ma->ma_attr_flags & MDS_OPEN_OWNEROVERRIDE) &&
                              (uc->mu_fsuid == tmp_la->la_uid)) &&
                            !(ma->ma_attr_flags & MDS_PERM_BYPASS)) {
                                rc = mdd_permission_internal_locked(env, obj,
                                                            tmp_la, MAY_WRITE);
                                if (rc)
                                        RETURN(rc);
                        }
                }
                if (la->la_valid & LA_CTIME) {
                        /* The pure setattr, it has the priority over what is
                         * already set, do not drop it if ctime is equal. */
                        if (la->la_ctime < tmp_la->la_ctime)
                                la->la_valid &= ~(LA_ATIME | LA_MTIME |
                                                  LA_CTIME);
                }
        }

        RETURN(0);
}

/* set attr and LOV EA at once, return updated attr */
static int mdd_attr_set(const struct lu_env *env, struct md_object *obj,
                        const struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        struct lov_mds_md *lmm = NULL;
        struct llog_cookie *logcookies = NULL;
        int  rc, lmm_size = 0, cookie_size = 0;
        struct lu_attr *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_ATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));
        /*TODO: add lock here*/
        /* start a log jounal handle if needed */
        if (S_ISREG(mdd_object_type(mdd_obj)) &&
            ma->ma_attr.la_valid & (LA_UID | LA_GID)) {
                lmm_size = mdd_lov_mdsize(env, mdd);
                lmm = mdd_max_lmm_get(env, mdd);
                if (lmm == NULL)
                        GOTO(cleanup, rc = -ENOMEM);

                rc = mdd_get_md_locked(env, mdd_obj, lmm, &lmm_size,
                                MDS_LOV_MD_NAME);

                if (rc < 0)
                        GOTO(cleanup, rc);
        }

        if (ma->ma_attr.la_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime "LPU64", ctime "LPU64"\n",
                       ma->ma_attr.la_mtime, ma->ma_attr.la_ctime);

        *la_copy = ma->ma_attr;
        rc = mdd_fix_attr(env, mdd_obj, la_copy, ma);
        if (rc)
                GOTO(cleanup, rc);

        if (la_copy->la_valid & LA_FLAGS) {
                rc = mdd_attr_set_internal_locked(env, mdd_obj, la_copy,
                                                  handle, 1);
                if (rc == 0)
                        mdd_flags_xlate(mdd_obj, la_copy->la_flags);
        } else if (la_copy->la_valid) {            /* setattr */
                rc = mdd_attr_set_internal_locked(env, mdd_obj, la_copy,
                                                  handle, 1);
                /* journal chown/chgrp in llog, just like unlink */
                if (rc == 0 && lmm_size){
                        cookie_size = mdd_lov_cookiesize(env, mdd);
                        logcookies = mdd_max_cookie_get(env, mdd);
                        if (logcookies == NULL)
                                GOTO(cleanup, rc = -ENOMEM);

                        if (mdd_setattr_log(env, mdd, ma, lmm, lmm_size,
                                            logcookies, cookie_size) <= 0)
                                logcookies = NULL;
                }
        }

        if (rc == 0 && ma->ma_valid & MA_LOV) {
                umode_t mode;

                mode = mdd_object_type(mdd_obj);
                if (S_ISREG(mode) || S_ISDIR(mode)) {
                        rc = mdd_lsm_sanity_check(env, mdd_obj);
                        if (rc)
                                GOTO(cleanup, rc);

                        rc = mdd_lov_set_md(env, NULL, mdd_obj, ma->ma_lmm,
                                            ma->ma_lmm_size, handle, 1);
                }

        }
cleanup:
        mdd_trans_stop(env, mdd, rc, handle);
        if (rc == 0 && (lmm != NULL && lmm_size > 0 )) {
                /*set obd attr, if needed*/
                rc = mdd_lov_setattr_async(env, mdd_obj, lmm, lmm_size,
                                           logcookies);
        }
        RETURN(rc);
}

int mdd_xattr_set_txn(const struct lu_env *env, struct mdd_object *obj,
                      const struct lu_buf *buf, const char *name, int fl,
                      struct thandle *handle)
{
        int  rc;
        ENTRY;

        mdd_write_lock(env, obj);
        rc = __mdd_xattr_set(env, obj, buf, name, fl, handle);
        mdd_write_unlock(env, obj);

        RETURN(rc);
}

static int mdd_xattr_sanity_check(const struct lu_env *env,
                                  struct mdd_object *obj)
{
        struct lu_attr  *tmp_la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc     = md_ucred(env);
        int rc;
        ENTRY;

        if (mdd_is_immutable(obj) || mdd_is_append(obj))
                RETURN(-EPERM);

        rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        if ((uc->mu_fsuid != tmp_la->la_uid) && !mdd_capable(uc, CAP_FOWNER))
                RETURN(-EPERM);

        RETURN(rc);
}

/**
 * The caller should guarantee to update the object ctime
 * after xattr_set if needed.
 */
static int mdd_xattr_set(const struct lu_env *env, struct md_object *obj,
                         const struct lu_buf *buf, const char *name,
                         int fl)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        rc = mdd_xattr_sanity_check(env, mdd_obj);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, mdd, MDD_TXN_XATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = mdd_xattr_set_txn(env, mdd_obj, buf, name, fl, handle);
        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

/**
 * The caller should guarantee to update the object ctime
 * after xattr_set if needed.
 */
int mdd_xattr_del(const struct lu_env *env, struct md_object *obj,
                  const char *name)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        rc = mdd_xattr_sanity_check(env, mdd_obj);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, mdd, MDD_TXN_XATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = mdo_xattr_del(env, mdd_obj, name, handle,
                           mdd_object_capa(env, mdd_obj));
        mdd_write_unlock(env, mdd_obj);
        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

/* partial unlink */
static int mdd_ref_del(const struct lu_env *env, struct md_object *obj,
                       struct md_attr *ma)
{
        struct lu_attr *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        /*
         * Check -ENOENT early here because we need to get object type
         * to calculate credits before transaction start
         */
        if (!mdd_object_exists(mdd_obj))
                RETURN(-ENOENT);

        LASSERT(mdd_object_exists(mdd_obj) > 0);

        rc = mdd_log_txn_param_build(env, obj, ma, MDD_TXN_UNLINK_OP);
        if (rc)
                RETURN(rc);

        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_write_lock(env, mdd_obj);

        rc = mdd_unlink_sanity_check(env, NULL, mdd_obj, ma);
        if (rc)
                GOTO(cleanup, rc);

        __mdd_ref_del(env, mdd_obj, handle, 0);

        if (S_ISDIR(lu_object_attr(&obj->mo_lu))) {
                /* unlink dot */
                __mdd_ref_del(env, mdd_obj, handle, 1);
        }

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);
        la_copy->la_ctime = ma->ma_attr.la_ctime;

        la_copy->la_valid = LA_CTIME;
        rc = mdd_attr_check_set_internal(env, mdd_obj, la_copy, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        rc = mdd_finish_unlink(env, mdd_obj, ma, handle);

        EXIT;
cleanup:
        mdd_write_unlock(env, mdd_obj);
        mdd_trans_stop(env, mdd, rc, handle);
        return rc;
}

/* partial operation */
static int mdd_oc_sanity_check(const struct lu_env *env,
                               struct mdd_object *obj,
                               struct md_attr *ma)
{
        int rc;
        ENTRY;

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

static int mdd_object_create(const struct lu_env *env,
                             struct md_object *obj,
                             const struct md_op_spec *spec,
                             struct md_attr *ma)
{

        struct mdd_device *mdd = mdo2mdd(obj);
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        const struct lu_fid *pfid = spec->u.sp_pfid;
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_OBJECT_CREATE_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = mdd_oc_sanity_check(env, mdd_obj, ma);
        if (rc)
                GOTO(unlock, rc);

        rc = mdd_object_create_internal(env, NULL, mdd_obj, ma, handle);
        if (rc)
                GOTO(unlock, rc);

        if (spec->sp_cr_flags & MDS_CREATE_SLAVE_OBJ) {
                /* If creating the slave object, set slave EA here. */
                int lmv_size = spec->u.sp_ea.eadatalen;
                struct lmv_stripe_md *lmv;

                lmv = (struct lmv_stripe_md *)spec->u.sp_ea.eadata;
                LASSERT(lmv != NULL && lmv_size > 0);

                rc = __mdd_xattr_set(env, mdd_obj,
                                     mdd_buf_get_const(env, lmv, lmv_size),
                                     MDS_LMV_MD_NAME, 0, handle);
                if (rc)
                        GOTO(unlock, rc);

                rc = mdd_attr_set_internal(env, mdd_obj, &ma->ma_attr,
                                           handle, 0);
        } else {
#ifdef CONFIG_FS_POSIX_ACL
                if (spec->sp_cr_flags & MDS_CREATE_RMT_ACL) {
                        struct lu_buf *buf = &mdd_env_info(env)->mti_buf;

                        buf->lb_buf = (void *)spec->u.sp_ea.eadata;
                        buf->lb_len = spec->u.sp_ea.eadatalen;
                        if ((buf->lb_len > 0) && (buf->lb_buf != NULL)) {
                                rc = __mdd_acl_init(env, mdd_obj, buf,
                                                    &ma->ma_attr.la_mode,
                                                    handle);
                                if (rc)
                                        GOTO(unlock, rc);
                                else
                                        ma->ma_attr.la_valid |= LA_MODE;
                        }

                        pfid = spec->u.sp_ea.fid;
                }
#endif
                rc = mdd_object_initialize(env, pfid, mdd_obj, ma, handle);
        }
        EXIT;
unlock:
        mdd_write_unlock(env, mdd_obj);
        if (rc == 0)
                rc = mdd_attr_get_internal_locked(env, mdd_obj, ma);

        mdd_trans_stop(env, mdd, rc, handle);
        return rc;
}

/* partial link */
static int mdd_ref_add(const struct lu_env *env, struct md_object *obj,
                       const struct md_attr *ma)
{
        struct lu_attr *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, mdd, MDD_TXN_XATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_write_lock(env, mdd_obj);
        rc = mdd_link_sanity_check(env, NULL, NULL, mdd_obj);
        if (rc == 0)
                __mdd_ref_add(env, mdd_obj, handle);
        mdd_write_unlock(env, mdd_obj);
        if (rc == 0) {
                LASSERT(ma->ma_attr.la_valid & LA_CTIME);
                la_copy->la_ctime = ma->ma_attr.la_ctime;

                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_check_set_internal_locked(env, mdd_obj, la_copy,
                                                        handle, 0);
        }
        mdd_trans_stop(env, mdd, 0, handle);

        RETURN(rc);
}

/*
 * do NOT or the MAY_*'s, you'll get the weakest
 */
int accmode(const struct lu_env *env, struct lu_attr *la, int flags)
{
        int res = 0;

        /* Sadly, NFSD reopens a file repeatedly during operation, so the
         * "acc_mode = 0" allowance for newly-created files isn't honoured.
         * NFSD uses the MDS_OPEN_OWNEROVERRIDE flag to say that a file
         * owner can write to a file even if it is marked readonly to hide
         * its brokenness. (bug 5781) */
        if (flags & MDS_OPEN_OWNEROVERRIDE) {
                struct md_ucred *uc = md_ucred(env);

                if ((uc == NULL) || (uc->mu_valid == UCRED_INIT) ||
                    (la->la_uid == uc->mu_fsuid))
                        return 0;
        }

        if (flags & FMODE_READ)
                res |= MAY_READ;
        if (flags & (FMODE_WRITE | MDS_OPEN_TRUNC | MDS_OPEN_APPEND))
                res |= MAY_WRITE;
        if (flags & MDS_FMODE_EXEC)
                res |= MAY_EXEC;
        return res;
}

static int mdd_open_sanity_check(const struct lu_env *env,
                                 struct mdd_object *obj, int flag)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        int mode, rc;
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

        rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
               RETURN(rc);

        if (S_ISLNK(tmp_la->la_mode))
                RETURN(-ELOOP);

        mode = accmode(env, tmp_la, flag);

        if (S_ISDIR(tmp_la->la_mode) && (mode & MAY_WRITE))
                RETURN(-EISDIR);

        if (!(flag & MDS_OPEN_CREATED)) {
                rc = mdd_permission_internal(env, obj, tmp_la, mode);
                if (rc)
                        RETURN(rc);
        }

        if (S_ISFIFO(tmp_la->la_mode) || S_ISSOCK(tmp_la->la_mode) ||
            S_ISBLK(tmp_la->la_mode) || S_ISCHR(tmp_la->la_mode))
                flag &= ~MDS_OPEN_TRUNC;

        /* For writing append-only file must open it with append mode. */
        if (mdd_is_append(obj)) {
                if ((flag & FMODE_WRITE) && !(flag & MDS_OPEN_APPEND))
                        RETURN(-EPERM);
                if (flag & MDS_OPEN_TRUNC)
                        RETURN(-EPERM);
        }

#if 0
        /*
         * Now, flag -- O_NOATIME does not be packed by client.
         */
        if (flag & O_NOATIME) {
                struct md_ucred *uc = md_ucred(env);

                if (uc && ((uc->mu_valid == UCRED_OLD) ||
                    (uc->mu_valid == UCRED_NEW)) &&
                    (uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CAP_FOWNER))
                        RETURN(-EPERM);
        }
#endif

        RETURN(0);
}

static int mdd_open(const struct lu_env *env, struct md_object *obj,
                    int flags)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc = 0;

        mdd_write_lock(env, mdd_obj);

        rc = mdd_open_sanity_check(env, mdd_obj, flags);
        if (rc == 0)
                mdd_obj->mod_count++;

        mdd_write_unlock(env, mdd_obj);
        return rc;
}

/* return md_attr back,
 * if it is last unlink then return lov ea + llog cookie*/
int mdd_object_kill(const struct lu_env *env, struct mdd_object *obj,
                    struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        if (S_ISREG(mdd_object_type(obj))) {
                /* Return LOV & COOKIES unconditionally here. We clean evth up.
                 * Caller must be ready for that. */
                rc = __mdd_lmm_get(env, obj, ma);
                if ((ma->ma_valid & MA_LOV))
                        rc = mdd_unlink_log(env, mdo2mdd(&obj->mod_obj),
                                            obj, ma);
        }
        RETURN(rc);
}

/*
 * No permission check is needed.
 */
static int mdd_close(const struct lu_env *env, struct md_object *obj,
                     struct md_attr *ma)
{
        int rc;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct thandle    *handle;
        ENTRY;

        rc = mdd_log_txn_param_build(env, obj, ma, MDD_TXN_UNLINK_OP);
        if (rc)
                RETURN(rc);
        handle = mdd_trans_start(env, mdo2mdd(obj));
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        /* release open count */
        mdd_obj->mod_count --;

        rc = mdd_iattr_get(env, mdd_obj, ma);
        if (rc == 0 && mdd_obj->mod_count == 0 && ma->ma_attr.la_nlink == 0)
                rc = mdd_object_kill(env, mdd_obj, ma);
        else
                ma->ma_valid &= ~(MA_LOV | MA_COOKIE);
        
        mdd_write_unlock(env, mdd_obj);
        mdd_trans_stop(env, mdo2mdd(obj), rc, handle);
        RETURN(rc);
}

/*
 * Permission check is done when open,
 * no need check again.
 */
static int mdd_readpage_sanity_check(const struct lu_env *env,
                                     struct mdd_object *obj)
{
        struct dt_object *next = mdd_object_child(obj);
        int rc;
        ENTRY;

        if (S_ISDIR(mdd_object_type(obj)) && dt_try_as_dir(env, next))
                rc = 0;
        else
                rc = -ENOTDIR;

        RETURN(rc);
}

static int mdd_dir_page_build(const struct lu_env *env, int first,
                              void *area, int nob, struct dt_it_ops *iops,
                              struct dt_it *it, __u64 *start, __u64 *end,
                              struct lu_dirent **last)
{
        struct lu_fid          *fid  = &mdd_env_info(env)->mti_fid2;
        struct mdd_thread_info *info = mdd_env_info(env);
        struct lu_fid_pack     *pack = &info->mti_pack;
        int                     result;
        struct lu_dirent       *ent;

        if (first) {
                memset(area, 0, sizeof (struct lu_dirpage));
                area += sizeof (struct lu_dirpage);
                nob  -= sizeof (struct lu_dirpage);
        }

        LASSERT(nob > sizeof *ent);

        ent  = area;
        result = 0;
        do {
                char  *name;
                int    len;
                int    recsize;
                __u64  hash;

                name = (char *)iops->key(env, it);
                len  = iops->key_size(env, it);

                pack = (struct lu_fid_pack *)iops->rec(env, it);
                result = fid_unpack(pack, fid);
                if (result != 0)
                        break;

                recsize = (sizeof(*ent) + len + 7) & ~7;
                hash = iops->store(env, it);
                *end = hash;

                CDEBUG(D_INFO, "%p %p %d "DFID": "LPU64" (%d) \"%*.*s\"\n",
                       name, ent, nob, PFID(fid), hash, len, len, len, name);

                if (nob >= recsize) {
                        ent->lde_fid = *fid;
                        fid_cpu_to_le(&ent->lde_fid, &ent->lde_fid);
                        ent->lde_hash = hash;
                        ent->lde_namelen = cpu_to_le16(len);
                        ent->lde_reclen  = cpu_to_le16(recsize);
                        memcpy(ent->lde_name, name, len);
                        if (first && ent == area)
                                *start = hash;
                        *last = ent;
                        ent = (void *)ent + recsize;
                        nob -= recsize;
                        result = iops->next(env, it);
                } else {
                        /*
                         * record doesn't fit into page, enlarge previous one.
                         */
                        LASSERT(*last != NULL);
                        (*last)->lde_reclen =
                                cpu_to_le16(le16_to_cpu((*last)->lde_reclen) +
                                            nob);
                        break;
                }
        } while (result == 0);

        return result;
}

static int __mdd_readpage(const struct lu_env *env, struct mdd_object *obj,
                          const struct lu_rdpg *rdpg)
{
        struct dt_it      *it;
        struct dt_object  *next = mdd_object_child(obj);
        struct dt_it_ops  *iops;
        struct page       *pg;
        struct lu_dirent  *last = NULL;
        int i;
        int rc;
        int nob;
        __u64 hash_start;
        __u64 hash_end = 0;

        LASSERT(rdpg->rp_pages != NULL);
        LASSERT(next->do_index_ops != NULL);

        if (rdpg->rp_count <= 0)
                return -EFAULT;

        /*
         * iterate through directory and fill pages from @rdpg
         */
        iops = &next->do_index_ops->dio_it;
        it = iops->init(env, next, 0, mdd_object_capa(env, obj));
        if (IS_ERR(it))
                return PTR_ERR(it);

        rc = iops->load(env, it, rdpg->rp_hash);

        if (rc == 0)
                /*
                 * Iterator didn't find record with exactly the key requested.
                 *
                 * It is currently either
                 *
                 *     - positioned above record with key less than
                 *     requested---skip it.
                 *
                 *     - or not positioned at all (is in IAM_IT_SKEWED
                 *     state)---position it on the next item.
                 */
                rc = iops->next(env, it);
        else if (rc > 0)
                rc = 0;

        /*
         * At this point and across for-loop:
         *
         *  rc == 0 -> ok, proceed.
         *  rc >  0 -> end of directory.
         *  rc <  0 -> error.
         */
        for (i = 0, nob = rdpg->rp_count; rc == 0 && nob > 0;
             i++, nob -= CFS_PAGE_SIZE) {
                LASSERT(i < rdpg->rp_npages);
                pg = rdpg->rp_pages[i];
                rc = mdd_dir_page_build(env, !i, cfs_kmap(pg),
                                        min_t(int, nob, CFS_PAGE_SIZE), iops,
                                        it, &hash_start, &hash_end, &last);
                if (rc != 0 || i == rdpg->rp_npages - 1)
                        last->lde_reclen = 0;
                cfs_kunmap(pg);
        }
        if (rc > 0) {
                /*
                 * end of directory.
                 */
                hash_end = DIR_END_OFF;
                rc = 0;
        }
        if (rc == 0) {
                struct lu_dirpage *dp;

                dp = cfs_kmap(rdpg->rp_pages[0]);
                dp->ldp_hash_start = rdpg->rp_hash;
                dp->ldp_hash_end   = hash_end;
                if (i == 0)
                        /*
                         * No pages were processed, mark this.
                         */
                        dp->ldp_flags |= LDF_EMPTY;
                dp->ldp_flags = cpu_to_le32(dp->ldp_flags);
                cfs_kunmap(rdpg->rp_pages[0]);
        }
        iops->put(env, it);
        iops->fini(env, it);

        return rc;
}

static int mdd_readpage(const struct lu_env *env, struct md_object *obj,
                        const struct lu_rdpg *rdpg)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;
        ENTRY;

        LASSERT(mdd_object_exists(mdd_obj));

        mdd_read_lock(env, mdd_obj);
        rc = mdd_readpage_sanity_check(env, mdd_obj);
        if (rc)
                GOTO(out_unlock, rc);

        if (mdd_is_dead_obj(mdd_obj)) {
                struct page *pg;
                struct lu_dirpage *dp;

                /*
                 * According to POSIX, please do not return any entry to client:
                 * even dot and dotdot should not be returned.
                 */
                CWARN("readdir from dead object: "DFID"\n",
                        PFID(mdd_object_fid(mdd_obj)));

                if (rdpg->rp_count <= 0)
                        GOTO(out_unlock, rc = -EFAULT);
                LASSERT(rdpg->rp_pages != NULL);

                pg = rdpg->rp_pages[0];
                dp = (struct lu_dirpage*)cfs_kmap(pg);
                memset(dp, 0 , sizeof(struct lu_dirpage));
                dp->ldp_hash_start = rdpg->rp_hash;
                dp->ldp_hash_end   = DIR_END_OFF;
                dp->ldp_flags |= LDF_EMPTY;
                dp->ldp_flags = cpu_to_le32(dp->ldp_flags);
                cfs_kunmap(pg);
                GOTO(out_unlock, rc = 0);
        }

        rc = __mdd_readpage(env, mdd_obj, rdpg);

        EXIT;
out_unlock:
        mdd_read_unlock(env, mdd_obj);
        return rc;
}

struct md_object_operations mdd_obj_ops = {
        .moo_permission    = mdd_permission,
        .moo_attr_get      = mdd_attr_get,
        .moo_attr_set      = mdd_attr_set,
        .moo_xattr_get     = mdd_xattr_get,
        .moo_xattr_set     = mdd_xattr_set,
        .moo_xattr_list    = mdd_xattr_list,
        .moo_xattr_del     = mdd_xattr_del,
        .moo_object_create = mdd_object_create,
        .moo_ref_add       = mdd_ref_add,
        .moo_ref_del       = mdd_ref_del,
        .moo_open          = mdd_open,
        .moo_close         = mdd_close,
        .moo_readpage      = mdd_readpage,
        .moo_readlink      = mdd_readlink,
        .moo_capa_get      = mdd_capa_get
};
