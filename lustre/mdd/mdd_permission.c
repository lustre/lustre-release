/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  mdd/mdd_handler.c
 *  Lustre Metadata Server (mdd) routines
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: fangyong@clusterfs.com 
 *	     lsy@clusterfs.com
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

#ifdef CONFIG_FS_POSIX_ACL
# include <linux/posix_acl_xattr.h>
# include <linux/posix_acl.h>
#endif

#include "mdd_internal.h"

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

/*
 * groups_search() is copied from linux kernel!
 * A simple bsearch.
 */
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

int mdd_in_group_p(struct md_ucred *uc, gid_t grp)
{
        int rc = 1;

        if (grp != uc->mu_fsgid) {
                struct group_info *group_info = NULL;

                if (uc->mu_ginfo || !uc->mu_identity ||
                    uc->mu_valid == UCRED_OLD)
                        if (grp == uc->mu_suppgids[0] ||
                            grp == uc->mu_suppgids[1])
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
static inline void mdd_acl_le_to_cpu(posix_acl_xattr_entry *p)
{
        p->e_tag = le16_to_cpu(p->e_tag);
        p->e_perm = le16_to_cpu(p->e_perm);
        p->e_id = le32_to_cpu(p->e_id);
}

static inline void mdd_acl_cpu_to_le(posix_acl_xattr_entry *p)
{
        p->e_tag = cpu_to_le16(p->e_tag);
        p->e_perm = cpu_to_le16(p->e_perm);
        p->e_id = cpu_to_le32(p->e_id);
}

/*
 * Check permission based on POSIX ACL.
 */
static int mdd_posix_acl_permission(struct md_ucred *uc, struct lu_attr *la,
                                    int want, posix_acl_xattr_entry *entry,
                                    int count)
{
        posix_acl_xattr_entry *pa, *pe, *mask_obj;
        int found = 0;
        ENTRY;

        if (count <= 0)
                RETURN(-EACCES);

        for (pa = &entry[0], pe = &entry[count - 1]; pa <= pe; pa++) {
                mdd_acl_le_to_cpu(pa);
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
                mdd_acl_le_to_cpu(mask_obj);
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

/*
 * Get default acl EA only.
 * Hold read_lock for mdd_obj.
 */
int mdd_acl_def_get(const struct lu_env *env, struct mdd_object *mdd_obj, 
                    struct md_attr *ma)
{
        struct lu_buf *buf;
        int rc;
        ENTRY;

        if (ma->ma_valid & MA_ACL_DEF)
                RETURN(0);
        
        buf = mdd_buf_get(env, ma->ma_acl, ma->ma_acl_size);
        rc = mdo_xattr_get(env, mdd_obj, buf, XATTR_NAME_ACL_DEFAULT,
                           BYPASS_CAPA);
        if (rc > 0) {
                ma->ma_acl_size = rc;
                ma->ma_valid |= MA_ACL_DEF;
                rc = 0;
        } else if ((rc == -EOPNOTSUPP) || (rc == -ENODATA)) {
                rc = 0;
        }
        RETURN(rc);
}

/*
 * Modify the ACL for the chmod.
 */
static int mdd_posix_acl_chmod_masq(posix_acl_xattr_entry *entry,
                                    __u32 mode, int count)
{
	posix_acl_xattr_entry *group_obj = NULL, *mask_obj = NULL, *pa, *pe;

        for (pa = &entry[0], pe = &entry[count - 1]; pa <= pe; pa++) {
                mdd_acl_le_to_cpu(pa);
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
                mdd_acl_cpu_to_le(pa);
	}

	if (mask_obj) {
		mask_obj->e_perm = cpu_to_le16((mode & S_IRWXG) >> 3);
	} else {
		if (!group_obj)
			return -EIO;
		group_obj->e_perm = cpu_to_le16((mode & S_IRWXG) >> 3);
	}

	return 0;
}

/*
 * Hold write_lock for o.
 */
int mdd_acl_chmod(const struct lu_env *env, struct mdd_object *o, __u32 mode, 
                  struct thandle *handle)
{
        struct lu_buf           *buf;
        posix_acl_xattr_header  *head;
        posix_acl_xattr_entry   *entry;
        int                      entry_count;
        int                      rc;

        ENTRY;

        buf = mdd_buf_get(env, mdd_env_info(env)->mti_xattr_buf, 
                          sizeof(mdd_env_info(env)->mti_xattr_buf));
        
        rc = mdo_xattr_get(env, o, buf, XATTR_NAME_ACL_ACCESS, BYPASS_CAPA);
        if ((rc == -EOPNOTSUPP) || (rc == -ENODATA))
                RETURN(0);
        else if (rc <= 0)
                RETURN(rc);

        buf->lb_len = rc;
        head = (posix_acl_xattr_header *)(buf->lb_buf);
        entry = head->a_entries;
        entry_count = (buf->lb_len - sizeof(head->a_version)) /
                      sizeof(posix_acl_xattr_entry);
        if (entry_count <= 0)
                RETURN(0);
       
        rc = mdd_posix_acl_chmod_masq(entry, mode, entry_count);
        if (rc)
                RETURN(rc);

        rc = mdo_xattr_set(env, o, buf, XATTR_NAME_ACL_ACCESS,
                           0, handle, BYPASS_CAPA);
        RETURN(rc);
}

/*
 * Modify acl when creating a new obj.
 */
static int mdd_posix_acl_create_masq(posix_acl_xattr_entry *entry,
                                     __u32 *mode_p, int count)
{
        posix_acl_xattr_entry *group_obj = NULL, *mask_obj = NULL, *pa, *pe;
	__u32 mode = *mode_p;
	int not_equiv = 0;

        for (pa = &entry[0], pe = &entry[count - 1]; pa <= pe; pa++) {
                mdd_acl_le_to_cpu(pa);
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
                mdd_acl_cpu_to_le(pa);
        }

	if (mask_obj) {
		mask_obj->e_perm = le16_to_cpu(mask_obj->e_perm) &
                                   ((mode >> 3) | ~S_IRWXO);
		mode &= (mask_obj->e_perm << 3) | ~S_IRWXG;
                mask_obj->e_perm = cpu_to_le16(mask_obj->e_perm);
	} else {
		if (!group_obj)
			return -EIO;
		group_obj->e_perm = le16_to_cpu(group_obj->e_perm) &
                                    ((mode >> 3) | ~S_IRWXO);
		mode &= (group_obj->e_perm << 3) | ~S_IRWXG;
                group_obj->e_perm = cpu_to_le16(group_obj->e_perm);
	}

	*mode_p = (*mode_p & ~S_IRWXUGO) | mode;
        return not_equiv;
}

/*
 * Hold write_lock for obj.
 */
int __mdd_acl_init(const struct lu_env *env, struct mdd_object *obj,
                   struct lu_buf *buf, __u32 *mode, struct thandle *handle)
{
        posix_acl_xattr_header  *head;
        posix_acl_xattr_entry   *entry;
        int                      entry_count;
        int                      rc;

        ENTRY;

        head = (posix_acl_xattr_header *)(buf->lb_buf);
        entry = head->a_entries;
        entry_count = (buf->lb_len - sizeof(head->a_version)) /
                      sizeof(posix_acl_xattr_entry);
        if (entry_count <= 0)
                RETURN(0);
       
	if (S_ISDIR(*mode)) {
                rc = mdo_xattr_set(env, obj, buf, XATTR_NAME_ACL_DEFAULT, 0, 
                                   handle, BYPASS_CAPA);
                if (rc)
                        RETURN(rc);
	}

        rc = mdd_posix_acl_create_masq(entry, mode, entry_count);
        if (rc <= 0)
                RETURN(rc);

        rc = mdo_xattr_set(env, obj, buf, XATTR_NAME_ACL_ACCESS, 0, handle,
                           BYPASS_CAPA);
        RETURN(rc);
}

/*
 * Hold read_lock for pobj.
 * Hold write_lock for cobj.
 */
int mdd_acl_init(const struct lu_env *env, struct mdd_object *pobj,
                 struct mdd_object *cobj, __u32 *mode, struct thandle *handle)
{
        struct lu_buf   *buf;
        int             rc;
        ENTRY;

	if (S_ISLNK(*mode))
                RETURN(0);

        buf = mdd_buf_get(env, mdd_env_info(env)->mti_xattr_buf, 
                          sizeof(mdd_env_info(env)->mti_xattr_buf));
        rc = mdo_xattr_get(env, pobj, buf, XATTR_NAME_ACL_DEFAULT, BYPASS_CAPA);
        if ((rc == -EOPNOTSUPP) || (rc == -ENODATA))
                RETURN(0);
        else if (rc <= 0)
                RETURN(rc);

        buf->lb_len = rc;
        rc = __mdd_acl_init(env, cobj, buf, mode, handle);
        RETURN(rc);
}
#endif

/*
 * Hold read_lock for obj.
 */
static int mdd_check_acl(const struct lu_env *env, struct mdd_object *obj,
                         struct lu_attr *la, int mask)
{
#ifdef CONFIG_FS_POSIX_ACL
        struct md_ucred  *uc  = md_ucred(env);
        posix_acl_xattr_header *head;
        posix_acl_xattr_entry *entry;
        struct lu_buf   *buf;
        int entry_count;
        int rc;
        ENTRY;

        buf = mdd_buf_get(env, mdd_env_info(env)->mti_xattr_buf, 
                          sizeof(mdd_env_info(env)->mti_xattr_buf));
        rc = mdo_xattr_get(env, obj, buf, XATTR_NAME_ACL_ACCESS,
                           mdd_object_capa(env, obj));
        if (rc <= 0)
                RETURN(rc ? : -EACCES);

        buf->lb_len = rc;
        head = (posix_acl_xattr_header *)(buf->lb_buf);
        entry = head->a_entries;
        entry_count = (buf->lb_len - sizeof(head->a_version)) /
                      sizeof(posix_acl_xattr_entry);

        rc = mdd_posix_acl_permission(uc, la, mask, entry, entry_count);
        RETURN(rc);
#else
        ENTRY;
        RETURN(-EAGAIN);
#endif
}

int __mdd_permission_internal(const struct lu_env *env, struct mdd_object *obj,
                              struct lu_attr *la, int mask, int needlock)
{
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

        if (la == NULL) {
                la = &mdd_env_info(env)->mti_la;
                rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
                if (rc)
                        RETURN(rc);
        }

        mode = la->la_mode;
        if (uc->mu_fsuid == la->la_uid) {
                mode >>= 6;
        } else {
                if (mode & S_IRWXG) {
                        if (needlock)
                                mdd_read_lock(env, obj);
                        rc = mdd_check_acl(env, obj, la, mask);
                        if (needlock)
                                mdd_read_unlock(env, obj);
                        if (rc == -EACCES)
                                goto check_capabilities;
                        else if ((rc != -EAGAIN) && (rc != -EOPNOTSUPP) &&
                                 (rc != -ENODATA))
                                RETURN(rc);
                }
                if (mdd_in_group_p(uc, la->la_gid))
                        mode >>= 3;
        }

        if (((mode & mask & S_IRWXO) == mask))
                RETURN(0);

check_capabilities:
        if (!(mask & MAY_EXEC) ||
            (la->la_mode & S_IXUGO) || S_ISDIR(la->la_mode))
                if (mdd_capable(uc, CAP_DAC_OVERRIDE))
                        RETURN(0);

        if ((mask == MAY_READ) ||
            (S_ISDIR(la->la_mode) && !(mask & MAY_WRITE)))
                if (mdd_capable(uc, CAP_DAC_READ_SEARCH))
                        RETURN(0);

        RETURN(-EACCES);
}

int mdd_permission(const struct lu_env *env, 
                   struct md_object *pobj, struct md_object *cobj,
                   struct md_attr *ma, int mask)
{
        struct mdd_object *mdd_pobj, *mdd_cobj;
        struct lu_attr *la = NULL;
        int check_create, check_link;
        int check_unlink;
        int check_rename_src, check_rename_tar;
        int check_vtx_part, check_vtx_full;
        int rc = 0;
        ENTRY;

        LASSERT(cobj);
        mdd_cobj = md2mdd_obj(cobj);

        /* For cross_open case, the "mask" is open flags,
         * so convert it to permission mask first.
         * XXX: MDS_OPEN_CROSS must be NOT equal to permission mask MAY_*. */
        if (unlikely(mask & MDS_OPEN_CROSS)) {
                la = &mdd_env_info(env)->mti_la;
                rc = mdd_la_get(env, mdd_cobj, la, BYPASS_CAPA);
                if (rc)
                        RETURN(rc);

                mask = accmode(env, la, mask & ~MDS_OPEN_CROSS);
        }

        check_create = mask & MAY_CREATE;
        check_link = mask & MAY_LINK;
        check_unlink = mask & MAY_UNLINK;
        check_rename_src = mask & MAY_RENAME_SRC;
        check_rename_tar = mask & MAY_RENAME_TAR;
        check_vtx_part = mask & MAY_VTX_PART;
        check_vtx_full = mask & MAY_VTX_FULL;

        mask &= ~(MAY_CREATE | MAY_LINK |
                MAY_UNLINK |
                MAY_RENAME_SRC | MAY_RENAME_TAR |
                MAY_VTX_PART | MAY_VTX_FULL);

        rc = mdd_permission_internal_locked(env, mdd_cobj, NULL, mask);

        if (!rc && (check_create || check_link))
                rc = mdd_may_create(env, mdd_cobj, NULL, 1, check_link);

        if (!rc && check_unlink) {
                LASSERT(ma);
                rc = mdd_may_unlink(env, mdd_cobj, ma);
        }

        if (!rc && (check_rename_src || check_rename_tar)) {
                LASSERT(pobj);
                LASSERT(ma);
                mdd_pobj = md2mdd_obj(pobj);
                rc = mdd_may_delete(env, mdd_pobj, mdd_cobj, ma, 1,
                                    check_rename_tar);
        }

        if (!rc && (check_vtx_part || check_vtx_full)) {
                struct md_ucred *uc = md_ucred(env);

                LASSERT(ma);
                if (likely(!la)) {
                        la = &mdd_env_info(env)->mti_la;
                        rc = mdd_la_get(env, mdd_cobj, la, BYPASS_CAPA);
                        if (rc)
                                RETURN(rc);
                }

                if (!(la->la_mode & S_ISVTX) || (la->la_uid == uc->mu_fsuid) ||
                    (check_vtx_full && (ma->ma_attr.la_valid & LA_UID) &&
                    (ma->ma_attr.la_uid == uc->mu_fsuid))) {
                        ma->ma_attr_flags |= MDS_VTX_BYPASS;
                } else {
                        ma->ma_attr_flags &= ~MDS_VTX_BYPASS;
                        if (check_vtx_full)
                                rc = -EPERM;
                }
        }

        RETURN(rc);
}

int mdd_capa_get(const struct lu_env *env, struct md_object *obj,
                 struct lustre_capa *capa, int renewal)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct obd_capa *oc;
        int rc = 0;
        ENTRY;

        oc = mdo_capa_get(env, mdd_obj, renewal ? capa : NULL,
                          capa->lc_opc);
        if (IS_ERR(oc)) {
                rc = PTR_ERR(oc);
        } else {
                capa_cpy(capa, oc);
                capa_put(oc);
        }

        RETURN(rc);
}
