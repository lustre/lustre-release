/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  mdd/mdd_handler.c
 *  Lustre Metadata Server (mdd) routines
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Wang Di <wangdi@clusterfs.com>
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
#include <linux/jbd.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <linux/ldiskfs_fs.h>
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>

#include "mdd_internal.h"


#if 0
static int mdd_exec_permission_lite(const struct lu_env *env,
                                    struct mdd_object *obj);
#endif

static const char dot[] = ".";
static const char dotdot[] = "..";

static inline int mdd_is_immutable(struct mdd_object *obj)
{
        return obj->mod_flags & IMMUTE_OBJ;
}

static inline int mdd_is_append(struct mdd_object *obj)
{
        return obj->mod_flags & APPEND_OBJ;
}

static inline void mdd_set_dead_obj(struct mdd_object *obj)
{
        if (obj)
                obj->mod_flags |= DEAD_OBJ;
}

static inline int mdd_is_dead_obj(struct mdd_object *obj)
{
        return obj && obj->mod_flags & DEAD_OBJ;
}

static inline int __mdd_la_get(const struct lu_env *env, struct mdd_object *obj,
                               struct lu_attr *la, struct lustre_capa *capa)
{
        struct dt_object *next = mdd_object_child(obj);
        LASSERT(lu_object_exists(mdd2lu_obj(obj)));
        return next->do_ops->do_attr_get(env, next, la, capa);
}

static void mdd_flags_xlate(struct mdd_object *obj, __u32 flags)
{
        obj->mod_flags &= ~(APPEND_OBJ|IMMUTE_OBJ);

        if (flags & LUSTRE_APPEND_FL)
                obj->mod_flags |= APPEND_OBJ;

        if (flags & LUSTRE_IMMUTABLE_FL)
                obj->mod_flags |= IMMUTE_OBJ;
}

int mdd_get_flags(const struct lu_env *env, struct mdd_object *obj)
{
        struct lu_attr *la = &mdd_env_info(env)->mti_la;
        int rc;

        ENTRY;
        mdd_read_lock(env, obj);
        rc = __mdd_la_get(env, obj, la, BYPASS_CAPA);
        mdd_read_unlock(env, obj);
        if (rc == 0)
                mdd_flags_xlate(obj, la->la_flags);
        RETURN(rc);
}

static void __mdd_ref_add(const struct lu_env *env, struct mdd_object *obj,
                         struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(mdd2lu_obj(obj)));
        next = mdd_object_child(obj);
        next->do_ops->do_ref_add(env, next, handle);
}

static void
__mdd_ref_del(const struct lu_env *env, struct mdd_object *obj,
              struct thandle *handle)
{
        struct dt_object *next = mdd_object_child(obj);
        ENTRY;

        LASSERT(lu_object_exists(mdd2lu_obj(obj)));

        next->do_ops->do_ref_del(env, next, handle);
        EXIT;
}

#define mdd_get_group_info(group_info) do {             \
        atomic_inc(&(group_info)->usage);               \
} while (0)

#define mdd_put_group_info(group_info) do {             \
        if (atomic_dec_and_test(&(group_info)->usage))  \
                groups_free(group_info);                \
} while (0)

#define MDD_NGROUPS_PER_BLOCK       ((int)(CFS_PAGE_SIZE / sizeof(gid_t)))

#define MDD_GROUP_AT(gi, i) \
    ((gi)->blocks[(i) / MDD_NGROUPS_PER_BLOCK][(i) % MDD_NGROUPS_PER_BLOCK])

/* groups_search() is copied from linux kernel! */
/* a simple bsearch */
static int mdd_groups_search(struct group_info *group_info, gid_t grp)
{
        int left, right;

        if (!group_info)
                return 0;

        left = 0;
        right = group_info->ngroups;
        while (left < right) {
                int mid = (left + right) / 2;
                int cmp = grp - MDD_GROUP_AT(group_info, mid);

                if (cmp > 0)
                        left = mid + 1;
                else if (cmp < 0)
                        right = mid;
                else
                        return 1;
        }
        return 0;
}

static int mdd_in_group_p(struct md_ucred *uc, gid_t grp)
{
        int rc = 1;

        if (grp != uc->mu_fsgid) {
                struct group_info *group_info = NULL;

                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD) ||
                    (!uc->mu_ginfo && !uc->mu_identity))
                        if ((grp == uc->mu_suppgids[0]) ||
                            (grp == uc->mu_suppgids[1]))
                                return 1;

                if (uc->mu_ginfo)
                        group_info = uc->mu_ginfo;
                else if (uc->mu_identity)
                        group_info = uc->mu_identity->mi_ginfo;

                if (!group_info)
                        return 0;

                mdd_get_group_info(group_info);
                rc = mdd_groups_search(group_info, grp);
                mdd_put_group_info(group_info);
        }
        return rc;
}

#ifdef CONFIG_FS_POSIX_ACL
static int mdd_posix_acl_permission(struct md_ucred *uc, struct lu_attr *la,
                                    int want, posix_acl_xattr_entry *entry,
                                    int count)
{
        posix_acl_xattr_entry *pa, *pe, *mask_obj;
        int found = 0;
        ENTRY;

        if (count <= 0)
                RETURN(-EACCES);

        pa = &entry[0];
        pe = &entry[count - 1];
        for (; pa <= pe; pa++) {
                switch(pa->e_tag) {
                        case ACL_USER_OBJ:
                                /* (May have been checked already) */
                                if (la->la_uid == uc->mu_fsuid)
                                        goto check_perm;
                                break;
                        case ACL_USER:
                                if (pa->e_id == uc->mu_fsuid)
                                        goto mask;
                                break;
                        case ACL_GROUP_OBJ:
                                if (mdd_in_group_p(uc, la->la_gid)) {
                                        found = 1;
                                        if ((pa->e_perm & want) == want)
                                                goto mask;
                                }
                                break;
                        case ACL_GROUP:
                                if (mdd_in_group_p(uc, pa->e_id)) {
                                        found = 1;
                                        if ((pa->e_perm & want) == want)
                                                goto mask;
                                }
                                break;
                        case ACL_MASK:
                                break;
                        case ACL_OTHER:
                                if (found)
                                        RETURN(-EACCES);
                                else
                                        goto check_perm;
                        default:
                                RETURN(-EIO);
                }
        }
        RETURN(-EIO);

mask:
        for (mask_obj = pa + 1; mask_obj <= pe; mask_obj++) {
                if (mask_obj->e_tag == ACL_MASK) {
                        if ((pa->e_perm & mask_obj->e_perm & want) == want)
                                RETURN(0);

                        RETURN(-EACCES);
                }
        }

check_perm:
        if ((pa->e_perm & want) == want)
                RETURN(0);

        RETURN(-EACCES);
}
#endif

static int mdd_check_acl(const struct lu_env *env, struct mdd_object *obj,
                         struct lu_attr* la, int mask)
{
#ifdef CONFIG_FS_POSIX_ACL
        struct dt_object *next;
        struct lu_buf    *buf = &mdd_env_info(env)->mti_buf;
        struct md_ucred  *uc  = md_ucred(env);
        posix_acl_xattr_entry *entry;
        int entry_count;
        int rc;
        ENTRY;

        next = mdd_object_child(obj);

        buf->lb_buf = mdd_env_info(env)->mti_xattr_buf;
        buf->lb_len = sizeof(mdd_env_info(env)->mti_xattr_buf);
        rc = next->do_ops->do_xattr_get(env, next, buf,
                                        XATTR_NAME_ACL_ACCESS,
                                        mdd_object_capa(env, obj));
        if (rc <= 0)
                RETURN(rc ? : -EACCES);

        entry = ((posix_acl_xattr_header *)(buf->lb_buf))->a_entries;
        entry_count = (rc - 4) / sizeof(posix_acl_xattr_entry);

        rc = mdd_posix_acl_permission(uc, la, mask, entry, entry_count);
        RETURN(rc);
#else
        ENTRY;
        RETURN(-EAGAIN);
#endif
}

#define mdd_cap_t(x) (x)

#define MDD_CAP_TO_MASK(x) (1 << (x))

#define mdd_cap_raised(c, flag) (mdd_cap_t(c) & MDD_CAP_TO_MASK(flag))

/* capable() is copied from linux kernel! */
static inline int mdd_capable(struct md_ucred *uc, int cap)
{
        if (mdd_cap_raised(uc->mu_cap, cap))
                return 1;
        return 0;
}

static int __mdd_permission_internal(const struct lu_env *env,
                                     struct mdd_object *obj,
                                     int mask, int getattr)
{
        struct lu_attr  *la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc = md_ucred(env);
        __u32 mode;
        int rc;

        ENTRY;

        if (mask == 0)
                RETURN(0);

        /* These means unnecessary for permission check */
        if ((uc == NULL) || (uc->mu_valid == UCRED_INIT))
                RETURN(0);

        /* Invalid user credit */
        if (uc->mu_valid == UCRED_INVALID)
                RETURN(-EACCES);

        /*
         * Nobody gets write access to an immutable file.
         */
        if ((mask & MAY_WRITE) && mdd_is_immutable(obj))
                RETURN(-EACCES);

        if (getattr) {
                rc = __mdd_la_get(env, obj, la, BYPASS_CAPA);
                if (rc)
                        RETURN(rc);
        }

        mode = la->la_mode;
        if (uc->mu_fsuid == la->la_uid) {
                mode >>= 6;
        } else {
                if (mode & S_IRWXG) {
                        rc = mdd_check_acl(env, obj, la, mask);
                        if (rc == -EACCES)
                                goto check_capabilities;
                        else if ((rc != -EAGAIN) && (rc != -EOPNOTSUPP) &&
                                 (rc != -ENODATA))
                                RETURN(rc);
                }
                if (mdd_in_group_p(uc, la->la_gid))
                        mode >>= 3;
        }

        /*
         * If the DACs are ok we don't need any capability check.
         */
        if (((mode & mask & S_IRWXO) == mask))
                RETURN(0);

check_capabilities:

        /*
         * Read/write DACs are always overridable.
         * Executable DACs are overridable if at least one exec bit is set.
         * Dir's DACs are always overridable.
         */
        if (!(mask & MAY_EXEC) ||
            (la->la_mode & S_IXUGO) || S_ISDIR(la->la_mode))
                if (mdd_capable(uc, CAP_DAC_OVERRIDE))
                        RETURN(0);

        /*
         * Searching includes executable on directories, else just read.
         */
        if ((mask == MAY_READ) ||
            (S_ISDIR(la->la_mode) && !(mask & MAY_WRITE)))
                if (mdd_capable(uc, CAP_DAC_READ_SEARCH))
                        RETURN(0);

        RETURN(-EACCES);
}

static inline int mdd_permission_internal(const struct lu_env *env,
                                          struct mdd_object *obj, int mask)
{
        return __mdd_permission_internal(env, obj, mask, 1);
}

/*Check whether it may create the cobj under the pobj*/
static int mdd_may_create(const struct lu_env *env,
                          struct mdd_object *pobj, struct mdd_object *cobj,
                          int need_check)
{
        int rc = 0;
        ENTRY;

        if (cobj && lu_object_exists(&cobj->mod_obj.mo_lu))
                RETURN(-EEXIST);

        if (mdd_is_dead_obj(pobj))
                RETURN(-ENOENT);

        /*check pobj may create or not*/
        if (need_check)
                rc = mdd_permission_internal(env, pobj,
                                             MAY_WRITE | MAY_EXEC);

        RETURN(rc);
}

/*
 * It's inline, so penalty for filesystems that don't use sticky bit is
 * minimal.
 */
static inline int mdd_is_sticky(const struct lu_env *env,
                                struct mdd_object *pobj,
                                struct mdd_object *cobj)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc = md_ucred(env);
        int rc;

        rc = __mdd_la_get(env, cobj, tmp_la, BYPASS_CAPA);
        if (rc) {
                return rc;
        } else if (tmp_la->la_uid == uc->mu_fsuid) {
                return 0;
        } else {
                rc = __mdd_la_get(env, pobj, tmp_la, BYPASS_CAPA);
                if (rc)
                        return rc;
                else if (!(tmp_la->la_mode & S_ISVTX))
                        return 0;
                else if (tmp_la->la_uid == uc->mu_fsuid)
                        return 0;
                else
                        return !mdd_capable(uc, CAP_FOWNER);
        }
}

/* Check whether it may delete the cobj under the pobj. */
static int mdd_may_delete(const struct lu_env *env,
                          struct mdd_object *pobj,
                          struct mdd_object *cobj,
                          int is_dir, int need_check)
{
        struct mdd_device *mdd = mdo2mdd(&cobj->mod_obj);
        int rc = 0;
        ENTRY;

        LASSERT(cobj);

        if (!lu_object_exists(&cobj->mod_obj.mo_lu))
                RETURN(-ENOENT);

        if (mdd_is_immutable(cobj) || mdd_is_append(cobj))
                RETURN(-EPERM);

        if (is_dir) {
                if (!S_ISDIR(mdd_object_type(cobj)))
                        RETURN(-ENOTDIR);

                if (lu_fid_eq(mdo2fid(cobj), &mdd->mdd_root_fid))
                        RETURN(-EBUSY);

        } else if (S_ISDIR(mdd_object_type(cobj))) {
                        RETURN(-EISDIR);
        }

        if (pobj) {
                if (mdd_is_dead_obj(pobj))
                        RETURN(-ENOENT);

                if (mdd_is_sticky(env, pobj, cobj))
                        RETURN(-EPERM);

                if (need_check)
                        rc = mdd_permission_internal(env, pobj,
                                                     MAY_WRITE | MAY_EXEC);
        }
        RETURN(rc);
}

/* get only inode attributes */
static int __mdd_iattr_get(const struct lu_env *env,
                           struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        rc = __mdd_la_get(env, mdd_obj, &ma->ma_attr,
                          mdd_object_capa(env, mdd_obj));
        if (rc == 0)
                ma->ma_valid = MA_INODE;
        RETURN(rc);
}

/* get lov EA only */
static int __mdd_lmm_get(const struct lu_env *env,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;
        ENTRY;

        LASSERT(ma->ma_lmm != NULL && ma->ma_lmm_size > 0);
        rc = mdd_get_md(env, mdd_obj, ma->ma_lmm, &ma->ma_lmm_size,
                        MDS_LOV_MD_NAME);
        if (rc > 0) {
                ma->ma_valid |= MA_LOV;
                rc = 0;
        }
        RETURN(rc);
}

/* get lmv EA only*/
static int __mdd_lmv_get(const struct lu_env *env,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;

        rc = mdd_get_md(env, mdd_obj, ma->ma_lmv, &ma->ma_lmv_size,
                        MDS_LMV_MD_NAME);
        if (rc > 0) {
                ma->ma_valid |= MA_LMV;
                rc = 0;
        }
        RETURN(rc);
}

#ifdef CONFIG_FS_POSIX_ACL
/* get default acl EA only */
static int __mdd_acl_def_get(const struct lu_env *env,
                             struct mdd_object *mdd_obj, struct md_attr *ma)
{
        struct dt_object *next = mdd_object_child(mdd_obj);
        int rc;

        rc = next->do_ops->do_xattr_get(env, next,
                                        mdd_buf_get(env, ma->ma_lmv,
                                                    ma->ma_lmv_size),
                                        XATTR_NAME_ACL_DEFAULT, BYPASS_CAPA);
        if (rc > 0) {
                ma->ma_lmv_size = rc;
                ma->ma_valid |= MA_ACL_DEF;
                rc = 0;
        } else if ((rc == -EOPNOTSUPP) || (rc == -ENODATA)) {
                rc = 0;
        }
        RETURN(rc);
}
#endif

static int mdd_attr_get_internal(const struct lu_env *env,
                                 struct mdd_object *mdd_obj,
                                 struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        if (ma->ma_need & MA_INODE)
                rc = __mdd_iattr_get(env, mdd_obj, ma);

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
        else if (rc == 0 && ma->ma_need & MA_ACL_DEF) {
                if (S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = __mdd_acl_def_get(env, mdd_obj, ma);
        }
#endif
        CDEBUG(D_INODE, "after getattr rc = %d, ma_valid = "LPX64"\n",
                        rc, ma->ma_valid);
        RETURN(rc);
}

static inline int mdd_attr_get_internal_locked(const struct lu_env *env,
                                               struct mdd_object *mdd_obj,
                                               struct md_attr *ma)
{
        int rc;
        mdd_read_lock(env, mdd_obj);
        rc = mdd_attr_get_internal(env, mdd_obj, ma);
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
        struct dt_object  *next;
        int rc;

        ENTRY;

        LASSERT(lu_object_exists(&obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(env, mdd_obj);
        rc = next->do_ops->do_xattr_get(env, next, buf, name,
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

        LASSERT(lu_object_exists(&obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(env, mdd_obj);
        rc = next->do_body_ops->dbo_read(env, next, buf, &pos,
                                         mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);
        RETURN(rc);
}

static int mdd_xattr_list(const struct lu_env *env, struct md_object *obj,
                          struct lu_buf *buf)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        int rc;

        ENTRY;

        LASSERT(lu_object_exists(&obj->mo_lu));

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(env, mdd_obj);
        rc = next->do_ops->do_xattr_list(env, next, buf,
                                         mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);

        RETURN(rc);
}

void mdd_write_lock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_write_lock(env, next);
}

void mdd_read_lock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_read_lock(env, next);
}

void mdd_write_unlock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_write_unlock(env, next);
}

void mdd_read_unlock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_read_unlock(env, next);
}

static void mdd_lock2(const struct lu_env *env,
                      struct mdd_object *o0, struct mdd_object *o1)
{
        mdd_write_lock(env, o0);
        mdd_write_lock(env, o1);
}

static void mdd_unlock2(const struct lu_env *env,
                        struct mdd_object *o0, struct mdd_object *o1)
{
        mdd_write_unlock(env, o1);
        mdd_write_unlock(env, o0);
}

static int __mdd_object_create(const struct lu_env *env,
                               struct mdd_object *obj, struct md_attr *ma,
                               struct thandle *handle)
{
        struct dt_object *next;
        struct lu_attr *attr = &ma->ma_attr;
        int rc;
        ENTRY;

        if (!lu_object_exists(mdd2lu_obj(obj))) {
                next = mdd_object_child(obj);
                rc = next->do_ops->do_create(env, next, attr, handle);
        } else
                rc = -EEXIST;

        LASSERT(ergo(rc == 0, lu_object_exists(mdd2lu_obj(obj))));

        RETURN(rc);
}

#ifdef CONFIG_FS_POSIX_ACL
#include <linux/posix_acl_xattr.h>
#include <linux/posix_acl.h>

/*
 * Modify the ACL for the chmod.
 */
static int mdd_posix_acl_chmod_masq(posix_acl_xattr_entry *entry,
                                    __u32 mode, int count)
{
	posix_acl_xattr_entry *group_obj = NULL, *mask_obj = NULL, *pa, *pe;

        pa = &entry[0];
        pe = &entry[count - 1];
        for (; pa <= pe; pa++) {
		switch(pa->e_tag) {
			case ACL_USER_OBJ:
				pa->e_perm = (mode & S_IRWXU) >> 6;
				break;

			case ACL_USER:
			case ACL_GROUP:
				break;

			case ACL_GROUP_OBJ:
				group_obj = pa;
				break;

			case ACL_MASK:
				mask_obj = pa;
				break;

			case ACL_OTHER:
				pa->e_perm = (mode & S_IRWXO);
				break;

			default:
				return -EIO;
		}
	}

	if (mask_obj) {
		mask_obj->e_perm = (mode & S_IRWXG) >> 3;
	} else {
		if (!group_obj)
			return -EIO;
		group_obj->e_perm = (mode & S_IRWXG) >> 3;
	}

	return 0;
}

static int mdd_acl_chmod(const struct lu_env *env, struct mdd_object *o,
                         __u32 mode, struct thandle *handle)
{
        struct dt_object        *next;
        struct lu_buf           *buf;
        posix_acl_xattr_entry   *entry;
        int                      entry_count;
        int                      rc;

        ENTRY;

        next = mdd_object_child(o);
        buf = &mdd_env_info(env)->mti_buf;
        buf->lb_buf = mdd_env_info(env)->mti_xattr_buf;
        buf->lb_len = sizeof(mdd_env_info(env)->mti_xattr_buf);
        rc = next->do_ops->do_xattr_get(env, next, buf,
                                        XATTR_NAME_ACL_ACCESS, BYPASS_CAPA);
        if ((rc == -EOPNOTSUPP) || (rc == -ENODATA))
                RETURN(0);
        else if (rc <= 0)
                RETURN(rc);

        buf->lb_len = rc;
        entry = ((posix_acl_xattr_header *)(buf->lb_buf))->a_entries;
        entry_count = (rc - 4) / sizeof(posix_acl_xattr_entry);
        if (entry_count <= 0)
                RETURN(0);
       
        rc = mdd_posix_acl_chmod_masq(entry, mode, entry_count);
        if (rc)
                RETURN(rc);

        rc = next->do_ops->do_xattr_set(env, next, buf, XATTR_NAME_ACL_ACCESS,
                                        0, handle, BYPASS_CAPA);
        RETURN(rc);
}
#endif

int mdd_attr_set_internal(const struct lu_env *env, struct mdd_object *o,
                          const struct lu_attr *attr, struct thandle *handle,
                          const int needacl)
{
        struct dt_object *next;
        int rc;

        LASSERT(lu_object_exists(mdd2lu_obj(o)));
        next = mdd_object_child(o);
        rc = next->do_ops->do_attr_set(env, next, attr, handle,
                                       mdd_object_capa(env, o));
#ifdef CONFIG_FS_POSIX_ACL
        if (!rc && (attr->la_valid & LA_MODE) && needacl)
                rc = mdd_acl_chmod(env, o, attr->la_mode, handle);
#endif
        return rc;
}

int mdd_attr_set_internal_locked(const struct lu_env *env,
                                 struct mdd_object *o,
                                 const struct lu_attr *attr,
                                 struct thandle *handle)
{
        int rc;
        mdd_write_lock(env, o);
        rc = mdd_attr_set_internal(env, o, attr, handle, 1);
        mdd_write_unlock(env, o);
        return rc;
}

static int __mdd_xattr_set(const struct lu_env *env, struct mdd_object *o,
                           const struct lu_buf *buf, const char *name,
                           int fl, struct thandle *handle)
{
        struct dt_object *next;
        struct lustre_capa *capa = mdd_object_capa(env, o);
        int rc = 0;
        ENTRY;

        LASSERT(lu_object_exists(mdd2lu_obj(o)));
        next = mdd_object_child(o);
        if (buf->lb_buf && buf->lb_len > 0) {
                rc = next->do_ops->do_xattr_set(env, next, buf, name, 0, handle,
                                                capa);
        } else if (buf->lb_buf == NULL && buf->lb_len == 0) {
                rc = next->do_ops->do_xattr_del(env, next, name, handle, capa);
        }
        RETURN(rc);
}

/* this gives the same functionality as the code between
 * sys_chmod and inode_setattr
 * chown_common and inode_setattr
 * utimes and inode_setattr
 * This API is ported from mds_fix_attr but remove some unnecesssary stuff.
 * and port to
 */
int mdd_fix_attr(const struct lu_env *env, struct mdd_object *obj,
                 struct lu_attr *la)
{
        struct lu_attr   *tmp_la     = &mdd_env_info(env)->mti_la;
        struct md_ucred  *uc         = md_ucred(env);
        time_t            now        = CURRENT_SECONDS;
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

        rc = __mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        if (mdd_is_immutable(obj) || mdd_is_append(obj)) {

                /*
                 * If only change flags of the object, we should
                 * let it pass, but also need capability check
                 * here if (!capable(CAP_LINUX_IMMUTABLE)),
                 * fix it, when implement capable in mds
                 */
                if (la->la_valid & ~LA_FLAGS)
                        RETURN(-EPERM);

                if (!mdd_capable(uc, CAP_LINUX_IMMUTABLE))
                        RETURN(-EPERM);

                if ((uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CAP_FOWNER))
                        RETURN(-EPERM);

                /*
                 * According to Ext3 implementation on this, the
                 * Ctime will be changed, but not clear why?
                 */
                la->la_ctime = now;
                la->la_valid |= LA_CTIME;
                RETURN(0);
        }

        /* Check for setting the obj time. */
        if ((la->la_valid & (LA_MTIME | LA_ATIME | LA_CTIME)) &&
            !(la->la_valid & ~(LA_MTIME | LA_ATIME | LA_CTIME))) {
                rc = __mdd_permission_internal(env, obj, MAY_WRITE, 0);
                if (rc)
                        RETURN(rc);
        }

        /* Make sure a caller can chmod. */
        if (la->la_valid & LA_MODE) {
                /*
                 * Bypass la_vaild == LA_MODE,
                 * this is for changing file with SUID or SGID.
                 */
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
                if (!mdd_in_group_p(uc, (la->la_valid & LA_GID) ? la->la_gid :
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

                /*
                 * If the user or group of a non-directory has been
                 * changed by a non-root user, remove the setuid bit.
                 * 19981026 David C Niemi <niemi@tux.org>
                 *
                 * Changed this to apply to all users, including root,
                 * to avoid some races. This is the behavior we had in
                 * 2.0. The check for non-root was definitely wrong
                 * for 2.2 anyway, as it should have been using
                 * CAP_FSETID rather than fsuid -- 19990830 SD.
                 */
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
                    !mdd_in_group_p(uc, la->la_gid))) &&
                    !mdd_capable(uc, CAP_CHOWN))
                        RETURN(-EPERM);

                /*
                 * Likewise, if the user or group of a non-directory
                 * has been changed by a non-root user, remove the
                 * setgid bit UNLESS there is no group execute bit
                 * (this would be a file marked for mandatory
                 * locking).  19981026 David C Niemi <niemi@tux.org>
                 *
                 * Removed the fsuid check (see the comment above) --
                 * 19990830 SD.
                 */
                if (((tmp_la->la_mode & (S_ISGID | S_IXGRP)) ==
                     (S_ISGID | S_IXGRP)) && !S_ISDIR(tmp_la->la_mode)) {
                        la->la_mode &= ~S_ISGID;
                        la->la_valid |= LA_MODE;
                }
        }

        /* For tuncate (or setsize), we should have MAY_WRITE perm */
        if (la->la_valid & (LA_SIZE | LA_BLOCKS)) {
                rc = mdd_permission_internal(env, obj, MAY_WRITE);
                if (rc)
                        RETURN(rc);

                /*
                 * For the "Size-on-MDS" setattr update, merge coming
                 * attributes with the set in the inode. BUG 10641
                 */
                if ((la->la_valid & LA_ATIME) &&
                    (la->la_atime < tmp_la->la_atime))
                        la->la_valid &= ~LA_ATIME;

                if ((la->la_valid & LA_CTIME) &&
                    (la->la_ctime < tmp_la->la_ctime))
                        la->la_valid &= ~(LA_MTIME | LA_CTIME);

                if (!(la->la_valid & LA_MTIME) && (now > tmp_la->la_mtime)) {
                        la->la_mtime = now;
                        la->la_valid |= LA_MTIME;
                }
        }

        /* For last, ctime must be fixed */
        if (!(la->la_valid & LA_CTIME) && (now > tmp_la->la_ctime)) {
                la->la_ctime = now;
                la->la_valid |= LA_CTIME;
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
        int  rc = 0, lmm_size = 0, max_size = 0;
        struct lu_attr *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_ATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));
        /*TODO: add lock here*/
        /* start a log jounal handle if needed */
        if (S_ISREG(mdd_object_type(mdd_obj)) &&
            ma->ma_attr.la_valid & (LA_UID | LA_GID)) {
                max_size = mdd_lov_mdsize(env, mdd);
                OBD_ALLOC(lmm, max_size);
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
        mdd_write_lock(env, mdd_obj);
        rc = mdd_fix_attr(env, mdd_obj, la_copy);
        mdd_write_unlock(env, mdd_obj);
        if (rc)
                GOTO(cleanup, rc);

        if (la_copy->la_valid & LA_FLAGS) {
                rc = mdd_attr_set_internal_locked(env, mdd_obj, la_copy,
                                                  handle);
                if (rc == 0)
                        mdd_flags_xlate(mdd_obj, la_copy->la_flags);
        } else if (la_copy->la_valid) {            /* setattr */
                rc = mdd_attr_set_internal_locked(env, mdd_obj, la_copy,
                                                  handle);
                /* journal chown/chgrp in llog, just like unlink */
                if (rc == 0 && lmm_size){
                        /*TODO set_attr llog */
                }
        }

        if (rc == 0 && ma->ma_valid & MA_LOV) {
                umode_t mode;

                mode = mdd_object_type(mdd_obj);
                if (S_ISREG(mode) || S_ISDIR(mode)) {
                        /*TODO check permission*/
                        rc = mdd_lov_set_md(env, NULL, mdd_obj, ma->ma_lmm,
                                            ma->ma_lmm_size, handle, 1);
                }

        }
cleanup:
        mdd_trans_stop(env, mdd, rc, handle);
        if (rc == 0 && lmm_size) {
                /*set obd attr, if needed*/
                rc = mdd_lov_setattr_async(env, mdd_obj, lmm, lmm_size);
        }
        if (lmm != NULL) {
                OBD_FREE(lmm, max_size);
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

        mdd_read_lock(env, obj);
        rc = __mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        mdd_read_unlock(env, obj);
        if (rc)
                RETURN(rc);

        if ((uc->mu_fsuid != tmp_la->la_uid) && !mdd_capable(uc, CAP_FOWNER))
                RETURN(-EPERM);

        RETURN(rc);
}

static int mdd_xattr_set(const struct lu_env *env, struct md_object *obj,
                         const struct lu_buf *buf, const char *name, int fl)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        rc = mdd_xattr_sanity_check(env, mdd_obj);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, MDD_TXN_XATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = mdd_xattr_set_txn(env, md2mdd_obj(obj), buf, name,
                               fl, handle);
#ifdef HAVE_SPLIT_SUPPORT
        if (rc == 0) {
                /*
                 * XXX: Very ugly hack, if setting lmv, it means splitting
                 * sucess, we should return -ERESTART to notify the client, so
                 * transno for this splitting should be zero according to the
                 * replay rules. so return -ERESTART here let mdt trans stop
                 * callback know this.
                 */
                 if (strncmp(name, MDS_LMV_MD_NAME, strlen(name)) == 0)
                         rc = -ERESTART;
        }
#endif
        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

static int __mdd_xattr_del(const struct lu_env *env,struct mdd_device *mdd,
                           struct mdd_object *obj,
                           const char *name, struct thandle *handle)
{
        struct dt_object *next;

        LASSERT(lu_object_exists(mdd2lu_obj(obj)));
        next = mdd_object_child(obj);
        return next->do_ops->do_xattr_del(env, next, name, handle,
                                          mdd_object_capa(env, obj));
}

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

        mdd_txn_param_build(env, MDD_TXN_XATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = __mdd_xattr_del(env, mdd, md2mdd_obj(obj), name, handle);
        mdd_write_unlock(env, mdd_obj);

        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

static int __mdd_index_insert_only(const struct lu_env *env,
                                   struct mdd_object *pobj,
                                   const struct lu_fid *lf,
                                   const char *name, struct thandle *th,
                                   struct lustre_capa *capa)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

        if (dt_try_as_dir(env, next))
                rc = next->do_index_ops->dio_insert(env, next,
                                         (struct dt_rec *)lf,
                                         (struct dt_key *)name, th, capa);
        else
                rc = -ENOTDIR;
        RETURN(rc);
}

/* insert new index, add reference if isdir, update times */
static int __mdd_index_insert(const struct lu_env *env,
                             struct mdd_object *pobj, const struct lu_fid *lf,
                             const char *name, int isdir, struct thandle *th,
                             struct lustre_capa *capa)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

#if 0
        struct lu_attr   *la = &mdd_env_info(env)->mti_la;
#endif

        if (dt_try_as_dir(env, next))
                rc = next->do_index_ops->dio_insert(env, next,
                                                    (struct dt_rec *)lf,
                                                    (struct dt_key *)name,
                                                    th, capa);
        else
                rc = -ENOTDIR;

        if (rc == 0) {
                if (isdir)
                        __mdd_ref_add(env, pobj, th);
#if 0
                la->la_valid = LA_MTIME|LA_CTIME;
                la->la_atime = ma->ma_attr.la_atime;
                la->la_ctime = ma->ma_attr.la_ctime;
                rc = mdd_attr_set_internal(env, mdd_obj, la, handle, 0);
#endif
        }
        return rc;
}

static int __mdd_index_delete(const struct lu_env *env,
                              struct mdd_object *pobj, const char *name,
                              int is_dir, struct thandle *handle,
                              struct lustre_capa *capa)
{
        int rc;
        struct dt_object *next = mdd_object_child(pobj);
        ENTRY;

        if (dt_try_as_dir(env, next)) {
                rc = next->do_index_ops->dio_delete(env, next,
                                                    (struct dt_key *)name,
                                                    handle, capa);
                if (rc == 0 && is_dir)
                        __mdd_ref_del(env, pobj, handle);
        } else
                rc = -ENOTDIR;
        RETURN(rc);
}

static int mdd_link_sanity_check(const struct lu_env *env,
                                 struct mdd_object *tgt_obj,
                                 struct mdd_object *src_obj)
{
        int rc = 0;
        ENTRY;

        if (tgt_obj) {
                rc = mdd_may_create(env, tgt_obj, NULL, 1);
                if (rc)
                        RETURN(rc);
        }

        if (S_ISDIR(mdd_object_type(src_obj)))
                RETURN(-EPERM);

        if (mdd_is_immutable(src_obj) || mdd_is_append(src_obj))
                RETURN(-EPERM);

        RETURN(rc);
}

static int mdd_link(const struct lu_env *env, struct md_object *tgt_obj,
                    struct md_object *src_obj, const char *name,
                    struct md_attr *ma)
{
        struct mdd_object *mdd_tobj = md2mdd_obj(tgt_obj);
        struct mdd_object *mdd_sobj = md2mdd_obj(src_obj);
        struct mdd_device *mdd = mdo2mdd(src_obj);
        struct lu_attr    *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_LINK_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock2(env, mdd_tobj, mdd_sobj);

        rc = mdd_link_sanity_check(env, mdd_tobj, mdd_sobj);
        if (rc)
                GOTO(out, rc);

        rc = __mdd_index_insert_only(env, mdd_tobj, mdo2fid(mdd_sobj),
                                     name, handle,
                                     mdd_object_capa(env, mdd_tobj));
        if (rc == 0)
                __mdd_ref_add(env, mdd_sobj, handle);

        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME;
        rc = mdd_attr_set_internal(env, mdd_sobj, la_copy, handle, 0);
        if (rc)
                GOTO(out, rc);

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(env, mdd_tobj, la_copy, handle, 0);

out:
        mdd_unlock2(env, mdd_tobj, mdd_sobj);
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

/*
 * Check that @dir contains no entries except (possibly) dot and dotdot.
 *
 * Returns:
 *
 *             0        empty
 *    -ENOTEMPTY        not empty
 *           -ve        other error
 *
 */
static int mdd_dir_is_empty(const struct lu_env *env,
                            struct mdd_object *dir)
{
        struct dt_it     *it;
        struct dt_object *obj;
        struct dt_it_ops *iops;
        int result;
        ENTRY;

        obj = mdd_object_child(dir);
        iops = &obj->do_index_ops->dio_it;
        it = iops->init(env, obj, 0);
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

/* return md_attr back,
 * if it is last unlink then return lov ea + llog cookie*/
int __mdd_object_kill(const struct lu_env *env,
                      struct mdd_object *obj,
                      struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        mdd_set_dead_obj(obj);
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

/* caller should take a lock before calling */
static int __mdd_finish_unlink(const struct lu_env *env,
                               struct mdd_object *obj, struct md_attr *ma,
                               struct thandle *th)
{
        int rc;
        ENTRY;

        rc = __mdd_iattr_get(env, obj, ma);
        if (rc == 0 && ma->ma_attr.la_nlink == 0) {
                /* add new orphan and the object
                 * will be deleted during the object_put() */
                if (__mdd_orphan_add(env, obj, th) == 0)
                        set_bit(LU_OBJECT_ORPHAN,
                                &mdd2lu_obj(obj)->lo_header->loh_flags);

                if (obj->mod_count == 0)
                        rc = __mdd_object_kill(env, obj, ma);
        }
        RETURN(rc);
}

static int mdd_unlink_sanity_check(const struct lu_env *env,
                                   struct mdd_object *pobj,
                                   struct mdd_object *cobj,
                                   struct md_attr *ma)
{
        struct dt_object  *dt_cobj  = mdd_object_child(cobj);
        int rc = 0;
        ENTRY;

        rc = mdd_may_delete(env, pobj, cobj,
                            S_ISDIR(ma->ma_attr.la_mode), 1);
        if (rc)
                RETURN(rc);

        if (S_ISDIR(mdd_object_type(cobj))) {
                if (dt_try_as_dir(env, dt_cobj))
                        rc = mdd_dir_is_empty(env, cobj);
                else
                        rc = -ENOTDIR;
        }

        RETURN(rc);
}

static int mdd_unlink(const struct lu_env *env,
                      struct md_object *pobj, struct md_object *cobj,
                      const char *name, struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object *mdd_cobj = md2mdd_obj(cobj);
        struct lu_attr    *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct thandle    *handle;
        int rc, is_dir;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_UNLINK_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_lock2(env, mdd_pobj, mdd_cobj);

        rc = mdd_unlink_sanity_check(env, mdd_pobj, mdd_cobj, ma);
        if (rc)
                GOTO(cleanup, rc);

        is_dir = S_ISDIR(lu_object_attr(&cobj->mo_lu));
        rc = __mdd_index_delete(env, mdd_pobj, name, is_dir, handle,
                                mdd_object_capa(env, mdd_pobj));
        if (rc)
                GOTO(cleanup, rc);

        __mdd_ref_del(env, mdd_cobj, handle);
        *la_copy = ma->ma_attr;
        if (is_dir) {
                /* unlink dot */
                __mdd_ref_del(env, mdd_cobj, handle);
        } else {
                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_set_internal(env, mdd_cobj, la_copy, handle, 0);
                if (rc)
                        GOTO(cleanup, rc);
        }

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(env, mdd_pobj, la_copy, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_finish_unlink(env, mdd_cobj, ma, handle);

        if (rc == 0)
                obd_set_info_async(mdd2obd_dev(mdd)->u.mds.mds_osc_exp,
                                   strlen("unlinked"), "unlinked", 0,
                                   NULL, NULL);

cleanup:
        mdd_unlock2(env, mdd_pobj, mdd_cobj);
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

/* partial unlink */
static int mdd_ref_del(const struct lu_env *env, struct md_object *obj,
                       struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_UNLINK_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_write_lock(env, mdd_obj);

        rc = mdd_unlink_sanity_check(env, NULL, mdd_obj, ma);
        if (rc)
                GOTO(cleanup, rc);

        __mdd_ref_del(env, mdd_obj, handle);

        if (S_ISDIR(lu_object_attr(&obj->mo_lu))) {
                /* unlink dot */
                __mdd_ref_del(env, mdd_obj, handle);
        }

        rc = __mdd_finish_unlink(env, mdd_obj, ma, handle);

        EXIT;
cleanup:
        mdd_write_unlock(env, mdd_obj);
        mdd_trans_stop(env, mdd, rc, handle);
        return rc;
}

static int __mdd_lookup(const struct lu_env *env, struct md_object *pobj,
                        const char *name, const struct lu_fid* fid, int mask);

static int
__mdd_lookup_locked(const struct lu_env *env, struct md_object *pobj,
                    const char *name, const struct lu_fid* fid, int mask)
{
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        int rc;

        mdd_read_lock(env, mdd_obj);
        rc = __mdd_lookup(env, pobj, name, fid, mask);
        mdd_read_unlock(env, mdd_obj);

       return rc;
}

static int mdd_lookup(const struct lu_env *env,
                      struct md_object *pobj, const char *name,
                      struct lu_fid* fid)
{
        int rc;
        ENTRY;
        rc = __mdd_lookup_locked(env, pobj, name, fid, MAY_EXEC);
        RETURN(rc);
}

static int mdd_parent_fid(const struct lu_env *env, struct mdd_object *obj,
                          struct lu_fid *fid)
{
        return __mdd_lookup_locked(env, &obj->mod_obj, dotdot, fid, 0);
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

        /* Do not lookup ".." in root, they do not exist there. */
        if (lu_fid_eq(mdo2fid(p1), &mdd->mdd_root_fid))
                RETURN(0);

        for(;;) {
                rc = mdd_parent_fid(env, p1, pfid);
                if (rc)
                        GOTO(out, rc);
                if (lu_fid_eq(pfid, &mdd->mdd_root_fid))
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
                        GOTO(out, rc = EREMOTE);
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

static int mdd_rename_lock(const struct lu_env *env,
                           struct mdd_device *mdd,
                           struct mdd_object *src_pobj,
                           struct mdd_object *tgt_pobj)
{
        int rc;
        ENTRY;

        if (src_pobj == tgt_pobj) {
                mdd_write_lock(env, src_pobj);
                RETURN(0);
        }

        /* compared the parent child relationship of src_p&tgt_p */
        if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(src_pobj))){
                mdd_lock2(env, src_pobj, tgt_pobj);
                RETURN(0);
        } else if (lu_fid_eq(&mdd->mdd_root_fid, mdo2fid(tgt_pobj))) {
                mdd_lock2(env, tgt_pobj, src_pobj);
                RETURN(0);
        }

        rc = mdd_is_parent(env, mdd, src_pobj, mdo2fid(tgt_pobj), NULL);
        if (rc < 0)
                RETURN(rc);

        if (rc == 1) {
                mdd_lock2(env, tgt_pobj, src_pobj);
                RETURN(0);
        }

        mdd_lock2(env, src_pobj, tgt_pobj);
        RETURN(0);
}

static void mdd_rename_unlock(const struct lu_env *env,
                              struct mdd_object *src_pobj,
                              struct mdd_object *tgt_pobj)
{
        mdd_write_unlock(env, src_pobj);
        if (src_pobj != tgt_pobj)
                mdd_write_unlock(env, tgt_pobj);
}

static int mdd_rename_sanity_check(const struct lu_env *env,
                                   struct mdd_object *src_pobj,
                                   struct mdd_object *tgt_pobj,
                                   const struct lu_fid *sfid,
                                   int src_is_dir,
                                   struct mdd_object *tobj)
{
        int rc;
        ENTRY;

        if (mdd_is_dead_obj(src_pobj))
                RETURN(-ENOENT);

        /* The sobj maybe on the remote, check parent permission only here */
        rc = mdd_permission_internal(env, src_pobj, MAY_WRITE | MAY_EXEC);
        if (rc)
                RETURN(rc);

        if (!tobj) {
                rc = mdd_may_create(env, tgt_pobj, NULL,
                                    (src_pobj != tgt_pobj));
        } else {
                mdd_read_lock(env, tobj);
                rc = mdd_may_delete(env, tgt_pobj, tobj, src_is_dir,
                                    (src_pobj != tgt_pobj));
                if (rc == 0)
                        if (S_ISDIR(mdd_object_type(tobj))
                            && mdd_dir_is_empty(env, tobj))
                                rc = -ENOTEMPTY;
                mdd_read_unlock(env, tobj);
        }

        RETURN(rc);
}
/* src object can be remote that is why we use only fid and type of object */
static int mdd_rename(const struct lu_env *env,
                      struct md_object *src_pobj, struct md_object *tgt_pobj,
                      const struct lu_fid *lf, const char *sname,
                      struct md_object *tobj, const char *tname,
                      struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(src_pobj);
        struct mdd_object *mdd_spobj = md2mdd_obj(src_pobj);
        struct mdd_object *mdd_tpobj = md2mdd_obj(tgt_pobj);
        struct mdd_object *mdd_sobj = NULL;
        struct mdd_object *mdd_tobj = NULL;
        struct lu_attr    *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct thandle *handle;
        int is_dir;
        int rc;
        ENTRY;

        LASSERT(ma->ma_attr.la_mode & S_IFMT);
        is_dir = S_ISDIR(ma->ma_attr.la_mode);
        if (ma->ma_attr.la_valid & LA_FLAGS &&
            ma->ma_attr.la_flags & (LUSTRE_APPEND_FL | LUSTRE_IMMUTABLE_FL))
                RETURN(-EPERM);

        if (tobj)
                mdd_tobj = md2mdd_obj(tobj);

        mdd_txn_param_build(env, MDD_TXN_RENAME_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        /* FIXME: Should consider tobj and sobj too in rename_lock. */
        rc = mdd_rename_lock(env, mdd, mdd_spobj, mdd_tpobj);
        if (rc)
                GOTO(cleanup_unlocked, rc);

        rc = mdd_rename_sanity_check(env, mdd_spobj, mdd_tpobj,
                                     lf, is_dir, mdd_tobj);
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

        mdd_sobj = mdd_object_find(env, mdd, lf);
        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME;
        if (mdd_sobj) {
                /*XXX: how to update ctime for remote sobj? */
                rc = mdd_attr_set_internal_locked(env, mdd_sobj, la_copy, handle);
                if (rc)
                        GOTO(cleanup, rc);
        }
        if (tobj && lu_object_exists(&tobj->mo_lu)) {
                mdd_write_lock(env, mdd_tobj);
                __mdd_ref_del(env, mdd_tobj, handle);
                /* remove dot reference */
                if (is_dir)
                        __mdd_ref_del(env, mdd_tobj, handle);

                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_set_internal(env, mdd_tobj, la_copy, handle, 0);
                if (rc)
                        GOTO(cleanup, rc);

                rc = __mdd_finish_unlink(env, mdd_tobj, ma, handle);
                mdd_write_unlock(env, mdd_tobj);
                if (rc)
                        GOTO(cleanup, rc);
        }

        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(env, mdd_spobj, la_copy, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        if (mdd_spobj != mdd_tpobj) {
                la_copy->la_valid = LA_CTIME | LA_MTIME;
                rc = mdd_attr_set_internal(env, mdd_tpobj, la_copy, handle, 0);
        }

cleanup:
        mdd_rename_unlock(env, mdd_spobj, mdd_tpobj);
cleanup_unlocked:
        mdd_trans_stop(env, mdd, rc, handle);
        if (mdd_sobj)
                mdd_object_put(env, mdd_sobj);
        RETURN(rc);
}

static int
__mdd_lookup(const struct lu_env *env, struct md_object *pobj,
             const char *name, const struct lu_fid* fid, int mask)
{
        struct mdd_object   *mdd_obj = md2mdd_obj(pobj);
        struct dt_object    *dir = mdd_object_child(mdd_obj);
        struct dt_rec       *rec = (struct dt_rec *)fid;
        const struct dt_key *key = (const struct dt_key *)name;
        int rc;
        ENTRY;

        if (mdd_is_dead_obj(mdd_obj))
                RETURN(-ESTALE);

        rc = lu_object_exists(mdd2lu_obj(mdd_obj));
        if (rc == 0)
                RETURN(-ESTALE);
        else if (rc < 0) {
                CERROR("Object "DFID" locates on remote server\n",
                        PFID(mdo2fid(mdd_obj)));
                LBUG();
        }

#if 0
        if (mask == MAY_EXEC)
                rc = mdd_exec_permission_lite(env, mdd_obj);
        else
#endif
        rc = mdd_permission_internal(env, mdd_obj, mask);
        if (rc)
                RETURN(rc);

        if (S_ISDIR(mdd_object_type(mdd_obj)) && dt_try_as_dir(env, dir))
                rc = dir->do_index_ops->dio_lookup(env, dir, rec, key,
                                                   mdd_object_capa(env, mdd_obj));
        else
                rc = -ENOTDIR;

        RETURN(rc);
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

        RETURN(rc);
}

static int __mdd_object_initialize(const struct lu_env *env,
                                   const struct lu_fid *pfid,
                                   struct mdd_object *child,
                                   struct md_attr *ma, struct thandle *handle)
{
        int rc;
        ENTRY;

        /* update attributes for child.
         * FIXME:
         *  (1) the valid bits should be converted between Lustre and Linux;
         *  (2) maybe, the child attributes should be set in OSD when creation.
         */

        rc = mdd_attr_set_internal(env, child, &ma->ma_attr, handle, 0);
        if (rc != 0)
                RETURN(rc);

        if (S_ISDIR(ma->ma_attr.la_mode)) {
                /* add . and .. for newly created dir */
                __mdd_ref_add(env, child, handle);
                rc = __mdd_index_insert_only(env, child, mdo2fid(child),
                                             dot, handle, BYPASS_CAPA);
                if (rc == 0) {
                        rc = __mdd_index_insert_only(env, child, pfid,
                                                     dotdot, handle,
                                                     BYPASS_CAPA);
                        if (rc != 0) {
                                int rc2;

                                rc2 = __mdd_index_delete(env, child, dot, 0,
                                                         handle, BYPASS_CAPA);
                                if (rc2 != 0)
                                        CERROR("Failure to cleanup after dotdot"
                                               " creation: %d (%d)\n", rc2, rc);
                                else
                                        __mdd_ref_del(env, child, handle);
                        }
                }
        }
        RETURN(rc);
}

/*
 * The permission has been checked when obj created,
 * no need check again.
 */
static int mdd_cd_sanity_check(const struct lu_env *env,
                               struct mdd_object *obj)
{
        int rc = 0;
        ENTRY;

        /* EEXIST check */
        if (!obj || mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

#if 0
        mdd_read_lock(env, obj);
        rc = mdd_permission_internal(env, obj, MAY_WRITE);
        mdd_read_unlock(env, obj);
#endif

        RETURN(rc);

}

static int mdd_create_data(const struct lu_env *env,
                           struct md_object *pobj, struct md_object *cobj,
                           const struct md_create_spec *spec,
                           struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(cobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);/* XXX maybe NULL */
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

        if (spec->sp_cr_flags & MDS_OPEN_DELAY_CREATE ||
                        !(spec->sp_cr_flags & FMODE_WRITE))
                RETURN(0);
        rc = mdd_lov_create(env, mdd, mdd_pobj, son, &lmm, &lmm_size, spec,
                            attr);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, MDD_TXN_CREATE_DATA_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(rc = PTR_ERR(handle));

        /*
         * XXX: Setting the lov ea is not locked but setting the attr is locked?
         */

        /* Replay creates has objects already */
        if (spec->u.sp_ea.no_lov_create) {
                CDEBUG(D_INFO, "we already have lov ea\n");
                rc = mdd_lov_set_md(env, mdd_pobj, son,
                                    (struct lov_mds_md *)spec->u.sp_ea.eadata,
                                    spec->u.sp_ea.eadatalen, handle, 0);
        } else
                rc = mdd_lov_set_md(env, mdd_pobj, son, lmm,
                                    lmm_size, handle, 0);

        if (rc == 0)
               rc = mdd_attr_get_internal_locked(env, son, ma);

        /* Finish mdd_lov_create() stuff. */
        mdd_lov_create_finish(env, mdd, rc);
        mdd_trans_stop(env, mdd, rc, handle);
        if (lmm)
                OBD_FREE(lmm, lmm_size);
        RETURN(rc);
}

#ifdef CONFIG_FS_POSIX_ACL
/*
 * Modify acl when creating a new obj.
 *
 * mode_p initially must contain the mode parameter to the open() / creat()
 * system calls. All permissions that are not granted by the acl are removed.
 * The permissions in the acl are changed to reflect the mode_p parameter.
 */
static int mdd_posix_acl_create_masq(posix_acl_xattr_entry *entry,
                                     __u32 *mode_p, int count)
{
        posix_acl_xattr_entry *group_obj = NULL, *mask_obj = NULL, *pa, *pe;
	__u32 mode = *mode_p;
	int not_equiv = 0;

        pa = &entry[0];
        pe = &entry[count - 1];
        for (; pa <= pe; pa++) {
                switch(pa->e_tag) {
                        case ACL_USER_OBJ:
				pa->e_perm &= (mode >> 6) | ~S_IRWXO;
				mode &= (pa->e_perm << 6) | ~S_IRWXU;
				break;

			case ACL_USER:
			case ACL_GROUP:
				not_equiv = 1;
				break;

                        case ACL_GROUP_OBJ:
				group_obj = pa;
                                break;

                        case ACL_OTHER:
				pa->e_perm &= mode | ~S_IRWXO;
				mode &= pa->e_perm | ~S_IRWXO;
                                break;

                        case ACL_MASK:
				mask_obj = pa;
				not_equiv = 1;
                                break;

			default:
				return -EIO;
                }
        }

	if (mask_obj) {
		mask_obj->e_perm &= (mode >> 3) | ~S_IRWXO;
		mode &= (mask_obj->e_perm << 3) | ~S_IRWXG;
	} else {
		if (!group_obj)
			return -EIO;
		group_obj->e_perm &= (mode >> 3) | ~S_IRWXO;
		mode &= (group_obj->e_perm << 3) | ~S_IRWXG;
	}

	*mode_p = (*mode_p & ~S_IRWXUGO) | mode;
        return not_equiv;
}

static int __mdd_acl_init(const struct lu_env *env, struct mdd_object *obj,
                          struct lu_buf *buf, __u32 *mode,
                          struct thandle *handle)
{
        struct dt_object        *next;
        posix_acl_xattr_entry   *entry;
        int                      entry_count;
        int                      rc;

        ENTRY;

        entry = ((posix_acl_xattr_header *)(buf->lb_buf))->a_entries;
        entry_count = (buf->lb_len - 4) / sizeof(posix_acl_xattr_entry);
        if (entry_count <= 0)
                RETURN(0);
       
        next = mdd_object_child(obj);
	if (S_ISDIR(*mode)) {
                rc = next->do_ops->do_xattr_set(env, next, buf,
                                                XATTR_NAME_ACL_DEFAULT,
                                                0, handle, BYPASS_CAPA);
                if (rc)
                        RETURN(rc);
	}

        rc = mdd_posix_acl_create_masq(entry, mode, entry_count);
        if (rc < 0)
                RETURN(rc);
        else if (rc > 0)
                rc = next->do_ops->do_xattr_set(env, next, buf,
                                                XATTR_NAME_ACL_ACCESS,
                                                0, handle, BYPASS_CAPA);
        RETURN(rc);
}

static int mdd_acl_init(const struct lu_env *env, struct mdd_object *pobj,
                        struct mdd_object *cobj, __u32 *mode,
                        struct thandle *handle)
{
        struct dt_object        *next = mdd_object_child(pobj);
        struct lu_buf           *buf = &mdd_env_info(env)->mti_buf;
        int                      rc;

        ENTRY;

	if (S_ISLNK(*mode))
                RETURN(0);

        buf->lb_buf = mdd_env_info(env)->mti_xattr_buf;
        buf->lb_len = sizeof(mdd_env_info(env)->mti_xattr_buf);
        rc = next->do_ops->do_xattr_get(env, next, buf,
                                        XATTR_NAME_ACL_DEFAULT, BYPASS_CAPA);
        if ((rc == -EOPNOTSUPP) || (rc == -ENODATA))
                RETURN(0);
        else if (rc <= 0)
                RETURN(rc);

        buf->lb_len = rc;
        rc = __mdd_acl_init(env, cobj, buf, mode, handle);
        RETURN(rc);
}
#endif

static int mdd_create_sanity_check(const struct lu_env *env,
                                   struct md_object *pobj,
                                   const char *name, struct md_attr *ma)
{
        struct mdd_thread_info *info = mdd_env_info(env);
        struct lu_attr    *la        = &info->mti_la;
        struct lu_fid     *fid       = &info->mti_fid;
        struct mdd_object *obj       = md2mdd_obj(pobj);
        int rc;
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

        /*
         * Check if the name already exist, though it will be checked
         * in _index_insert also, for avoiding rolling back if exists
         * _index_insert.
         */
        rc = __mdd_lookup_locked(env, pobj, name, fid,
                                 MAY_WRITE | MAY_EXEC);
        if (rc != -ENOENT)
                RETURN(rc ? : -EEXIST);

        /* sgid check */
        mdd_read_lock(env, obj);
        rc = __mdd_la_get(env, obj, la, BYPASS_CAPA);
        mdd_read_unlock(env, obj);
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

/*
 * Create object and insert it into namespace.
 */
static int mdd_create(const struct lu_env *env,
                      struct md_object *pobj, const char *name,
                      struct md_object *child,
                      struct md_create_spec *spec,
                      struct md_attr* ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_pobj = md2mdd_obj(pobj);
        struct mdd_object *son = md2mdd_obj(child);
        struct lu_attr    *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct lu_attr    *attr = &ma->ma_attr;
        struct lov_mds_md *lmm = NULL;
        struct thandle    *handle;
        int rc, created = 0, inserted = 0, lmm_size = 0;
        struct timeval  start;
        ENTRY;

        mdd_lproc_time_start(mdd, &start, LPROC_MDD_CREATE);
        /*
         * Two operations have to be performed:
         *
         *  - allocation of new object (->do_create()), and
         *
         *  - insertion into parent index (->dio_insert()).
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
         *     1. create            (__mdd_object_create())
         *
         *     2. insert            (__mdd_index_insert(), lookup again)
         */

        /* sanity checks before big job */
        rc = mdd_create_sanity_check(env, pobj, name, ma);
        if (rc)
                RETURN(rc);

        /* no RPC inside the transaction, so OST objects should be created at
         * first */
        if (S_ISREG(attr->la_mode)) {
                rc = mdd_lov_create(env, mdd, mdd_pobj, son, &lmm, &lmm_size,
                                    spec, attr);
                if (rc)
                        RETURN(rc);
        }

        mdd_txn_param_build(env, MDD_TXN_MKDIR_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_pobj);

        /*
         * XXX check that link can be added to the parent in mkdir case.
         */

        mdd_write_lock(env, son);
        rc = __mdd_object_create(env, son, ma, handle);
        if (rc) {
                mdd_write_unlock(env, son);
                GOTO(cleanup, rc);
        }

        created = 1;

#ifdef CONFIG_FS_POSIX_ACL
        rc = mdd_acl_init(env, mdd_pobj, son, &ma->ma_attr.la_mode, handle);
        if (rc) {
                mdd_write_unlock(env, son);
                GOTO(cleanup, rc);
        } else {
                ma->ma_attr.la_valid |= LA_MODE;
        }
#endif

        rc = __mdd_object_initialize(env, mdo2fid(mdd_pobj),
                                     son, ma, handle);
        mdd_write_unlock(env, son);
        if (rc)
                /*
                 * Object has no links, so it will be destroyed when last
                 * reference is released. (XXX not now.)
                 */
                GOTO(cleanup, rc);

        rc = __mdd_index_insert(env, mdd_pobj, mdo2fid(son),
                                name, S_ISDIR(attr->la_mode), handle,
                                mdd_object_capa(env, mdd_pobj));

        if (rc)
                GOTO(cleanup, rc);

        inserted = 1;
        /* replay creates has objects already */
        if (spec->u.sp_ea.no_lov_create) {
                CDEBUG(D_INFO, "we already have lov ea\n");
                rc = mdd_lov_set_md(env, mdd_pobj, son,
                                    (struct lov_mds_md *)spec->u.sp_ea.eadata,
                                    spec->u.sp_ea.eadatalen, handle, 0);
        } else
                rc = mdd_lov_set_md(env, mdd_pobj, son, lmm,
                                    lmm_size, handle, 0);
        if (rc) {
                CERROR("error on stripe info copy %d \n", rc);
                GOTO(cleanup, rc);
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
                        rc = -EFAULT;
        }

        *la_copy = ma->ma_attr;
        la_copy->la_valid = LA_CTIME | LA_MTIME;
        rc = mdd_attr_set_internal(env, mdd_pobj, la_copy, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        /* return attr back */
        rc = mdd_attr_get_internal_locked(env, son, ma);
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
                        mdd_write_lock(env, son);
                        __mdd_ref_del(env, son, handle);
                        mdd_write_unlock(env, son);
                }
        }
        /* finish mdd_lov_create() stuff */
        mdd_lov_create_finish(env, mdd, rc);
        if (lmm)
                OBD_FREE(lmm, lmm_size);
        mdd_write_unlock(env, mdd_pobj);
        mdd_trans_stop(env, mdd, rc, handle);
        mdd_lproc_time_end(mdd, &start, LPROC_MDD_CREATE);
        RETURN(rc);
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
                             const struct md_create_spec *spec,
                             struct md_attr *ma)
{

        struct mdd_device *mdd = mdo2mdd(obj);
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        const struct lu_fid *pfid = spec->u.sp_pfid;
        struct thandle *handle;
        int rc;
        ENTRY;

        rc = mdd_oc_sanity_check(env, mdd_obj, ma);
        if (rc)
                RETURN(rc);

        mdd_txn_param_build(env, MDD_TXN_OBJECT_CREATE_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = __mdd_object_create(env, mdd_obj, ma, handle);
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
                pfid = spec->u.sp_ea.fid;

                CDEBUG(D_INFO, "Set slave ea "DFID", eadatalen %d, rc %d\n",
                       PFID(mdo2fid(mdd_obj)), spec->u.sp_ea.eadatalen, rc);
                rc = mdd_attr_set_internal(env, mdd_obj, &ma->ma_attr, handle, 0);
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
                }
#endif
                rc = __mdd_object_initialize(env, pfid, mdd_obj, ma, handle);
        }
        EXIT;
unlock:
        mdd_write_unlock(env, mdd_obj);
        if (rc == 0)
                rc = mdd_attr_get_internal_locked(env, mdd_obj, ma);

        mdd_trans_stop(env, mdd, rc, handle);
        return rc;
}

/*
 * Partial operation. Be aware, this is called with write lock taken, so we use
 * locksless version of __mdd_lookup() here.
 */
static int mdd_ni_sanity_check(const struct lu_env *env,
                               struct md_object *pobj,
                               const char *name,
                               const struct lu_fid *fid)
{
        struct mdd_object *obj       = md2mdd_obj(pobj);
#if 0
        int rc;
#endif
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

         /* The exist of the name will be checked in _index_insert. */
#if 0
        rc = __mdd_lookup(env, pobj, name, fid, MAY_WRITE | MAY_EXEC);
        if (rc != -ENOENT)
                RETURN(rc ? : -EEXIST);
        else
                RETURN(0);
#endif
        RETURN(mdd_permission_internal(env, obj, MAY_WRITE | MAY_EXEC));
}

static int mdd_name_insert(const struct lu_env *env,
                           struct md_object *pobj,
                           const char *name, const struct lu_fid *fid,
                           int isdir)
{
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_INDEX_INSERT_OP);
        handle = mdd_trans_start(env, mdo2mdd(pobj));
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = mdd_ni_sanity_check(env, pobj, name, fid);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_insert(env, mdd_obj, fid, name, isdir, handle,
                                BYPASS_CAPA);

out_unlock:
        mdd_write_unlock(env, mdd_obj);

        mdd_trans_stop(env, mdo2mdd(pobj), rc, handle);
        RETURN(rc);
}

/*
 * Be aware, this is called with write lock taken, so we use locksless version
 * of __mdd_lookup() here.
 */
static int mdd_nr_sanity_check(const struct lu_env *env,
                               struct md_object *pobj,
                               const char *name)
{
        struct mdd_object *obj       = md2mdd_obj(pobj);
#if 0
        struct mdd_thread_info *info = mdd_env_info(env);
        struct lu_fid     *fid       = &info->mti_fid;
        int rc;
#endif
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

         /* The exist of the name will be checked in _index_delete. */
#if 0
        rc = __mdd_lookup(env, pobj, name, fid, MAY_WRITE | MAY_EXEC);
        RETURN(rc);
#endif
        RETURN(mdd_permission_internal(env, obj, MAY_WRITE | MAY_EXEC));
}

static int mdd_name_remove(const struct lu_env *env,
                           struct md_object *pobj,
                           const char *name, int is_dir)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_obj = md2mdd_obj(pobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_INDEX_DELETE_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        mdd_write_lock(env, mdd_obj);
        rc = mdd_nr_sanity_check(env, pobj, name);
        if (rc)
                GOTO(out_unlock, rc);

        rc = __mdd_index_delete(env, mdd_obj, name, is_dir, handle,
                                BYPASS_CAPA);

out_unlock:
        mdd_write_unlock(env, mdd_obj);

        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

static int mdd_rt_sanity_check(const struct lu_env *env,
                               struct mdd_object *tgt_pobj,
                               struct mdd_object *tobj,
                               const struct lu_fid *sfid,
                               const char *name, struct md_attr *ma)
{
        int rc, src_is_dir;
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(tgt_pobj))
                RETURN(-ENOENT);

        src_is_dir = S_ISDIR(ma->ma_attr.la_mode);
        if (tobj) {
                rc = mdd_may_delete(env, tgt_pobj, tobj, src_is_dir, 1);
                if (!rc && S_ISDIR(mdd_object_type(tobj)) &&
                     mdd_dir_is_empty(env, tobj))
                                RETURN(-ENOTEMPTY);
        } else {
                rc = mdd_may_create(env, tgt_pobj, NULL, 1);
        }

        RETURN(rc);
}

static int mdd_rename_tgt(const struct lu_env *env,
                          struct md_object *pobj, struct md_object *tobj,
                          const struct lu_fid *lf, const char *name,
                          struct md_attr *ma)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_tpobj = md2mdd_obj(pobj);
        struct mdd_object *mdd_tobj = md2mdd_obj(tobj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_RENAME_TGT_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        if (mdd_tobj)
                mdd_lock2(env, mdd_tpobj, mdd_tobj);
        else
                mdd_write_lock(env, mdd_tpobj);

        /*TODO rename sanity checking*/
        rc = mdd_rt_sanity_check(env, mdd_tpobj, mdd_tobj, lf, name, ma);
        if (rc)
                GOTO(cleanup, rc);

        /* if rename_tgt is called then we should just re-insert name with
         * correct fid, no need to dec/inc parent nlink if obj is dir */
        rc = __mdd_index_delete(env, mdd_tpobj, name, 0, handle, BYPASS_CAPA);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_insert_only(env, mdd_tpobj, lf, name, handle,
                                     BYPASS_CAPA);
        if (rc)
                GOTO(cleanup, rc);

        if (tobj && lu_object_exists(&tobj->mo_lu))
                __mdd_ref_del(env, mdd_tobj, handle);
cleanup:
        if (tobj)
                mdd_unlock2(env, mdd_tpobj, mdd_tobj);
        else
                mdd_write_unlock(env, mdd_tpobj);
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

/*
 * XXX: if permission check is needed here?
 */
static int mdd_ref_add(const struct lu_env *env,
                       struct md_object *obj)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        mdd_txn_param_build(env, MDD_TXN_XATTR_SET_OP);
        handle = mdd_trans_start(env, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        mdd_write_lock(env, mdd_obj);
        rc = mdd_link_sanity_check(env, NULL, mdd_obj);
        if (!rc)
                __mdd_ref_add(env, mdd_obj, handle);
        mdd_write_unlock(env, mdd_obj);

        mdd_trans_stop(env, mdd, 0, handle);

        RETURN(0);
}

/* do NOT or the MAY_*'s, you'll get the weakest */
static int accmode(struct mdd_object *mdd_obj, int flags)
{
        int res = 0;

#if 0
        /* Sadly, NFSD reopens a file repeatedly during operation, so the
         * "acc_mode = 0" allowance for newly-created files isn't honoured.
         * NFSD uses the MDS_OPEN_OWNEROVERRIDE flag to say that a file
         * owner can write to a file even if it is marked readonly to hide
         * its brokenness. (bug 5781) */
        if (flags & MDS_OPEN_OWNEROVERRIDE && inode->i_uid == current->fsuid)
                return 0;
#endif
        if (flags & FMODE_READ)
                res = MAY_READ;
        if (flags & (FMODE_WRITE | MDS_OPEN_TRUNC | MDS_OPEN_APPEND))
                res |= MAY_WRITE;
        if (flags & MDS_FMODE_EXEC)
                res = MAY_EXEC;
        return res;
}

static int mdd_open_sanity_check(const struct lu_env *env,
                                 struct mdd_object *obj, int flag)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        int mode = accmode(obj, flag);
        int rc;
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

        rc = __mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
               RETURN(rc);

        if (S_ISLNK(tmp_la->la_mode))
                RETURN(-ELOOP);

        if (S_ISDIR(tmp_la->la_mode) && (mode & MAY_WRITE))
                RETURN(-EISDIR);

        if (!(flag & MDS_OPEN_CREATED)) {
                rc = __mdd_permission_internal(env, obj, mode, 0);
                if (rc)
                        RETURN(rc);
        }

        /*
         * FIFO's, sockets and device files are special: they don't
         * actually live on the filesystem itself, and as such you
         * can write to them even if the filesystem is read-only.
         */
        if (S_ISFIFO(tmp_la->la_mode) || S_ISSOCK(tmp_la->la_mode) ||
            S_ISBLK(tmp_la->la_mode) || S_ISCHR(tmp_la->la_mode))
                flag &= ~O_TRUNC;

        /*
         * An append-only file must be opened in append mode for writing.
         */
        if (mdd_is_append(obj)) {
                if ((flag & FMODE_WRITE) && !(flag & O_APPEND))
                        RETURN(-EPERM);
                if (flag & O_TRUNC)
                        RETURN(-EPERM);
        }

        /* O_NOATIME can only be set by the owner or superuser */
        if (flag & O_NOATIME) {
                struct md_ucred *uc = md_ucred(env);

                if (uc->mu_fsuid != tmp_la->la_uid &&
                    !mdd_capable(uc, CAP_FOWNER))
                        RETURN(-EPERM);
        }

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

/*
 * No permission check is needed.
 */
static int mdd_close(const struct lu_env *env, struct md_object *obj,
                     struct md_attr *ma)
{
        int rc;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        ENTRY;

        mdd_write_lock(env, mdd_obj);
        /* release open count */
        mdd_obj->mod_count --;

        rc = __mdd_iattr_get(env, mdd_obj, ma);
        if (rc == 0 && mdd_obj->mod_count == 0) {
                if (ma->ma_attr.la_nlink == 0)
                        rc = __mdd_object_kill(env, mdd_obj, ma);
        }
        mdd_write_unlock(env, mdd_obj);
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
#if 0
                rc = mdd_permission_internal(env, obj, MAY_READ);
#else
                rc = 0;
#endif
        else
                rc = -ENOTDIR;

        RETURN(rc);
}

static int mdd_readpage(const struct lu_env *env, struct md_object *obj,
                        const struct lu_rdpg *rdpg)
{
        struct dt_object *next;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;
        ENTRY;

        LASSERT(lu_object_exists(mdd2lu_obj(mdd_obj)));
        next = mdd_object_child(mdd_obj);

        mdd_read_lock(env, mdd_obj);
        rc = mdd_readpage_sanity_check(env, mdd_obj);
        if (rc)
                GOTO(out_unlock, rc);

        rc = next->do_ops->do_readpage(env, next, rdpg,
                                       mdd_object_capa(env, mdd_obj));

out_unlock:
        mdd_read_unlock(env, mdd_obj);
        RETURN(rc);
}

#if 0
static int mdd_exec_permission_lite(const struct lu_env *env,
                                    struct mdd_object *obj)
{
        struct lu_attr  *la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc = md_ucred(env);
        umode_t mode;
        int rc;
        ENTRY;

        /* These means unnecessary for permission check */
        if ((uc == NULL) || (uc->mu_valid == UCRED_INIT))
                RETURN(0);

        /* Invalid user credit */
        if (uc->mu_valid == UCRED_INVALID)
                RETURN(-EACCES);

        rc = __mdd_la_get(env, obj, la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        mode = la->la_mode;
        if (uc->mu_fsuid == la->la_uid)
                mode >>= 6;
        else if (mdd_in_group_p(uc, la->la_gid))
                mode >>= 3;

        if (mode & MAY_EXEC)
                RETURN(0);

        if (((la->la_mode & S_IXUGO) || S_ISDIR(la->la_mode)) &&
            mdd_capable(uc, CAP_DAC_OVERRIDE))
                RETURN(0);

        if (S_ISDIR(la->la_mode) && mdd_capable(uc, CAP_DAC_READ_SEARCH))
                RETURN(0);

        RETURN(-EACCES);
}
#endif

static inline int mdd_permission_internal_locked(const struct lu_env *env,
                                                 struct mdd_object *obj,
                                                 int mask)
{
        int rc;

        mdd_read_lock(env, obj);
        rc = mdd_permission_internal(env, obj, mask);
        mdd_read_unlock(env, obj);

        return rc;
}

static int mdd_permission(const struct lu_env *env, struct md_object *obj,
                          int mask)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;
        ENTRY;

        rc = mdd_permission_internal_locked(env, mdd_obj, mask);

        RETURN(rc);
}

static int mdd_capa_get(const struct lu_env *env, struct md_object *obj,
                        struct lustre_capa *capa, int renewal)
{
        struct dt_object *next;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct obd_capa *oc;
        int rc = 0;
        ENTRY;

        LASSERT(lu_object_exists(mdd2lu_obj(mdd_obj)));
        next = mdd_object_child(mdd_obj);

        oc = next->do_ops->do_capa_get(env, next, renewal ? capa : NULL,
                                       capa->lc_opc);
        if (IS_ERR(oc)) {
                rc = PTR_ERR(oc);
        } else {
                capa_cpy(capa, oc);
                capa_put(oc);
        }

        RETURN(rc);
}

struct md_dir_operations mdd_dir_ops = {
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

