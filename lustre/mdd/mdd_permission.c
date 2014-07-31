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
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdd/mdd_permission.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: fangyong@clusterfs.com
 * Author: lsy@clusterfs.com
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_class.h>
#include <lustre_ver.h>
#include <lprocfs_status.h>
#include <lustre_mds.h>
#include <lustre_idmap.h>
#include "mdd_internal.h"

#ifdef CONFIG_FS_POSIX_ACL

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

	rc = lustre_posix_acl_chmod_masq(entry, mode, entry_count);
	if (rc)
		RETURN(rc);

	rc = mdo_xattr_set(env, o, buf, XATTR_NAME_ACL_ACCESS,
			   0, handle, BYPASS_CAPA);
	RETURN(rc);
}

int mdd_acl_set(const struct lu_env *env, struct mdd_object *obj,
		const struct lu_buf *buf, int fl)
{
	struct mdd_device	*mdd = mdd_obj2mdd_dev(obj);
	struct lu_attr		*la = &mdd_env_info(env)->mti_la;
	struct thandle		*handle;
	posix_acl_xattr_header	*head;
	posix_acl_xattr_entry	*entry;
	int			 rc, entry_count;
	bool			 not_equiv, mode_change;
	mode_t			 mode;
	ENTRY;

	rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
	if (rc)
		RETURN(rc);

	head = (posix_acl_xattr_header *)(buf->lb_buf);
	entry = head->a_entries;
	entry_count = (buf->lb_len - sizeof(head->a_version)) /
		sizeof(posix_acl_xattr_entry);
	if (entry_count <= 0)
		RETURN(0);

	LASSERT(la->la_valid & LA_MODE);
	mode = la->la_mode;
	rc = lustre_posix_acl_equiv_mode(entry, &mode, entry_count);
	if (rc < 0)
		RETURN(rc);

	not_equiv = (rc > 0);
	mode_change = (mode != la->la_mode);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	/* rc tells whether ACL can be represented by i_mode only */
	if (not_equiv)
		rc = mdo_declare_xattr_set(env, obj, buf,
				XATTR_NAME_ACL_ACCESS, fl, handle);
	else
		rc = mdo_declare_xattr_del(env, obj, XATTR_NAME_ACL_ACCESS,
				handle);
	if (rc)
		GOTO(stop, rc);

	if (mode_change) {
		la->la_mode = mode;
		rc = mdo_declare_attr_set(env, obj, la, handle);
	}

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop, rc);

	mdd_write_lock(env, obj, MOR_TGT_CHILD);
	/* whether ACL can be represented by i_mode only */
	if (not_equiv)
		rc = mdo_xattr_set(env, obj, buf, XATTR_NAME_ACL_ACCESS, fl,
				handle, mdd_object_capa(env, obj));
	else
		rc = mdo_xattr_del(env, obj, XATTR_NAME_ACL_ACCESS, handle,
				mdd_object_capa(env, obj));
	if (rc)
		GOTO(unlock, rc);

	if (mode_change)
		rc = mdo_attr_set(env, obj, la, handle,
				mdd_object_capa(env, obj));

	/* security-replated changes may require sync */
	if (S_ISDIR(mdd_object_type(obj)))
		handle->th_sync |= !!mdd->mdd_sync_permission;
unlock:
	mdd_write_unlock(env, obj);
stop:
	mdd_trans_stop(env, mdd, rc, handle);

	RETURN(rc);
}

/**
 * Fix mode and ACL according to the default ACL(buf)
 * \retval = 0 ACL does not need to be reset.
 * \retval = 1 ACL needs to be reset.
 * \retval < 0 error.
 **/
int __mdd_fix_mode_acl(const struct lu_env *env, struct lu_buf *buf,
		       __u32 *mode)
{
	posix_acl_xattr_header  *head;
	posix_acl_xattr_entry   *entry;
	int                      entry_count;
	int			 rc;

	ENTRY;

	head = (posix_acl_xattr_header *)(buf->lb_buf);
	entry = head->a_entries;
	entry_count = (buf->lb_len - sizeof(head->a_version)) /
		      sizeof(posix_acl_xattr_entry);
	if (entry_count <= 0)
		RETURN(0);

	rc = lustre_posix_acl_create_masq(entry, mode, entry_count);

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
	struct lu_ucred  *uc  = lu_ucred_assert(env);
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
	entry_count = posix_acl_xattr_count(buf->lb_len);

	/* Disregard empty ACLs and fall back to
	 * standard UNIX permissions. See LU-5434 */
	if (entry_count <= 0)
		RETURN(-EAGAIN);

	rc = lustre_posix_acl_permission(uc, la, mask, entry, entry_count);
	RETURN(rc);
#else
	ENTRY;
	RETURN(-EAGAIN);
#endif
}

int __mdd_permission_internal(const struct lu_env *env, struct mdd_object *obj,
                              struct lu_attr *la, int mask, int role)
{
	struct lu_ucred *uc = lu_ucred(env);
        __u32 mode;
        int rc;
        ENTRY;

        if (mask == 0)
                RETURN(0);

	/* These means unnecessary for permission check */
	if ((uc == NULL) || (uc->uc_valid == UCRED_INIT))
		RETURN(0);

	/* Invalid user credit */
	if (uc->uc_valid == UCRED_INVALID)
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
	if (uc->uc_fsuid == la->la_uid) {
		mode >>= 6;
        } else {
                if (mode & S_IRWXG) {
                        if (role != -1)
                                mdd_read_lock(env, obj, role);
                        rc = mdd_check_acl(env, obj, la, mask);
                        if (role != -1)
                                mdd_read_unlock(env, obj);
                        if (rc == -EACCES)
                                goto check_capabilities;
                        else if ((rc != -EAGAIN) && (rc != -EOPNOTSUPP) &&
                                 (rc != -ENODATA))
                                RETURN(rc);
                }
                if (lustre_in_group_p(uc, la->la_gid))
                        mode >>= 3;
        }

        if (((mode & mask & S_IRWXO) == mask))
                RETURN(0);

check_capabilities:
	if (!(mask & MAY_EXEC) ||
	    (la->la_mode & S_IXUGO) || S_ISDIR(la->la_mode))
		if (md_capable(uc, CFS_CAP_DAC_OVERRIDE))
			RETURN(0);

	if ((mask == MAY_READ) ||
	    (S_ISDIR(la->la_mode) && !(mask & MAY_WRITE)))
		if (md_capable(uc, CFS_CAP_DAC_READ_SEARCH))
			RETURN(0);

	RETURN(-EACCES);
}

int mdd_permission(const struct lu_env *env,
                   struct md_object *pobj, struct md_object *cobj,
                   struct md_attr *ma, int mask)
{
        struct mdd_object *mdd_pobj, *mdd_cobj;
	struct lu_ucred *uc = NULL;
	struct lu_attr *la = &mdd_env_info(env)->mti_cattr;
        int check_create, check_link;
        int check_unlink;
        int check_rename_src, check_rename_tar;
        int check_vtx_part, check_vtx_full;
        int check_rgetfacl;
        int rc = 0;
        ENTRY;

        LASSERT(cobj);
        mdd_cobj = md2mdd_obj(cobj);

	rc = mdd_la_get(env, mdd_cobj, la, BYPASS_CAPA);
	if (rc)
		RETURN(rc);

        /* For cross_open case, the "mask" is open flags,
         * so convert it to permission mask first.
         * XXX: MDS_OPEN_CROSS must be NOT equal to permission mask MAY_*. */
	if (unlikely(mask & MDS_OPEN_CROSS))
		mask = accmode(env, la, mask & ~MDS_OPEN_CROSS);

        check_create = mask & MAY_CREATE;
        check_link = mask & MAY_LINK;
        check_unlink = mask & MAY_UNLINK;
        check_rename_src = mask & MAY_RENAME_SRC;
        check_rename_tar = mask & MAY_RENAME_TAR;
        check_vtx_part = mask & MAY_VTX_PART;
        check_vtx_full = mask & MAY_VTX_FULL;
        check_rgetfacl = mask & MAY_RGETFACL;

        mask &= ~(MAY_CREATE | MAY_LINK |
                MAY_UNLINK |
                MAY_RENAME_SRC | MAY_RENAME_TAR |
                MAY_VTX_PART | MAY_VTX_FULL |
                MAY_RGETFACL);

        rc = mdd_permission_internal_locked(env, mdd_cobj, NULL, mask,
                                            MOR_TGT_CHILD);

        if (!rc && (check_create || check_link))
                rc = mdd_may_create(env, mdd_cobj, NULL, 1, check_link);

	if (!rc && check_unlink)
		rc = mdd_may_unlink(env, mdd_cobj, la);

        if (!rc && (check_rename_src || check_rename_tar)) {
                LASSERT(pobj);
                mdd_pobj = md2mdd_obj(pobj);
		rc = mdd_may_delete(env, mdd_pobj, mdd_cobj, la, NULL, 1,
                                    check_rename_tar);
        }

        if (!rc && (check_vtx_part || check_vtx_full)) {
		uc = lu_ucred_assert(env);
                if (likely(!la)) {
                        la = &mdd_env_info(env)->mti_la;
                        rc = mdd_la_get(env, mdd_cobj, la, BYPASS_CAPA);
                        if (rc)
                                RETURN(rc);
                }

		if (!(la->la_mode & S_ISVTX) || (la->la_uid == uc->uc_fsuid) ||
		    (check_vtx_full && (ma->ma_attr.la_valid & LA_UID) &&
		     (ma->ma_attr.la_uid == uc->uc_fsuid))) {
			ma->ma_attr_flags |= MDS_VTX_BYPASS;
                } else {
                        ma->ma_attr_flags &= ~MDS_VTX_BYPASS;
                        if (check_vtx_full)
                                rc = -EPERM;
                }
        }

        if (unlikely(!rc && check_rgetfacl)) {
                if (likely(!uc))
			uc = lu_ucred_assert(env);

		if (la->la_uid != uc->uc_fsuid &&
		    !md_capable(uc, CFS_CAP_FOWNER))
			rc = -EPERM;
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
        } else if (likely(oc != NULL)) {
                capa_cpy(capa, oc);
                capa_put(oc);
        }

        RETURN(rc);
}
