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
 * Copyright (c) 2011, 2013, Intel Corporation.
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

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lprocfs_status.h>
/* fid_be_cpu(), fid_cpu_to_be(). */
#include <lustre_fid.h>
#include <obd_lov.h>
#include <lustre_idmap.h>
#include <lustre_param.h>
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>

#include "mdd_internal.h"

static const struct lu_object_operations mdd_lu_obj_ops;
extern struct kmem_cache *mdd_object_kmem;

static int mdd_xattr_get(const struct lu_env *env,
                         struct md_object *obj, struct lu_buf *buf,
                         const char *name);

int mdd_data_get(const struct lu_env *env, struct mdd_object *obj,
                 void **data)
{
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
        mdo_data_get(env, obj, data);
        return 0;
}

int mdd_la_get(const struct lu_env *env, struct mdd_object *obj,
               struct lu_attr *la, struct lustre_capa *capa)
{
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
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

struct mdd_thread_info *mdd_env_info(const struct lu_env *env)
{
        struct mdd_thread_info *info;

        info = lu_context_key_get(&env->le_ctx, &mdd_thread_key);
        LASSERT(info != NULL);
        return info;
}

const struct lu_name *mdd_name_get_const(const struct lu_env *env,
					 const void *area, ssize_t len)
{
	struct lu_name *lname;

	lname = &mdd_env_info(env)->mti_name;
	lname->ln_name = area;
	lname->ln_namelen = len;
	return lname;
}

struct lu_buf *mdd_buf_get(const struct lu_env *env, void *area, ssize_t len)
{
	struct lu_buf *buf;

	buf = &mdd_env_info(env)->mti_buf[0];
	buf->lb_buf = area;
	buf->lb_len = len;
	return buf;
}

const struct lu_buf *mdd_buf_get_const(const struct lu_env *env,
                                       const void *area, ssize_t len)
{
	struct lu_buf *buf;

	buf = &mdd_env_info(env)->mti_buf[0];
	buf->lb_buf = (void *)area;
	buf->lb_len = len;
	return buf;
}

struct lu_object *mdd_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *d)
{
	struct mdd_object *mdd_obj;

	OBD_SLAB_ALLOC_PTR_GFP(mdd_obj, mdd_object_kmem, GFP_NOFS);
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

static int mdd_object_init(const struct lu_env *env, struct lu_object *o,
                           const struct lu_object_conf *unused)
{
        struct mdd_device *d = lu2mdd_dev(o->lo_dev);
        struct mdd_object *mdd_obj = lu2mdd_obj(o);
        struct lu_object  *below;
        struct lu_device  *under;
        ENTRY;

        mdd_obj->mod_cltime = 0;
        under = &d->mdd_child->dd_lu_dev;
        below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
	if (IS_ERR(below))
		RETURN(PTR_ERR(below));

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
	OBD_SLAB_FREE_PTR(mdd, mdd_object_kmem);
}

static int mdd_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        struct mdd_object *mdd = lu2mdd_obj((struct lu_object *)o);
        return (*p)(env, cookie, LUSTRE_MDD_NAME"-object@%p(open_count=%d, "
                    "valid=%x, cltime="LPU64", flags=%lx)",
                    mdd, mdd->mod_count, mdd->mod_valid,
                    mdd->mod_cltime, mdd->mod_flags);
}

static const struct lu_object_operations mdd_lu_obj_ops = {
        .loo_object_init    = mdd_object_init,
        .loo_object_start   = mdd_object_start,
        .loo_object_free    = mdd_object_free,
        .loo_object_print   = mdd_object_print,
};

struct mdd_object *mdd_object_find(const struct lu_env *env,
                                   struct mdd_device *d,
                                   const struct lu_fid *f)
{
        return md2mdd_obj(md_object_find_slice(env, &d->mdd_md_dev, f));
}

/* Returns the full path to this fid, as of changelog record recno. */
int mdd_get_flags(const struct lu_env *env, struct mdd_object *obj)
{
        struct lu_attr *la = &mdd_env_info(env)->mti_la;
        int rc;

        ENTRY;
        rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
        if (rc == 0) {
                mdd_flags_xlate(obj, la->la_flags);
        }
        RETURN(rc);
}

/*
 * No permission check is needed.
 */
int mdd_attr_get(const struct lu_env *env, struct md_object *obj,
		 struct md_attr *ma)
{
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	int		  rc;

	ENTRY;

	rc = mdd_la_get(env, mdd_obj, &ma->ma_attr,
			mdd_object_capa(env, md2mdd_obj(obj)));
	if ((ma->ma_need & MA_INODE) != 0 && mdd_is_dead_obj(mdd_obj))
		ma->ma_attr.la_nlink = 0;

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

        if (mdd_object_exists(mdd_obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(mdd_obj),PFID(mdd_object_fid(mdd_obj)));
                return -ENOENT;
        }

	/* If the object has been delete from the namespace, then
	 * get linkEA should return -ENOENT as well */
	if (unlikely((mdd_obj->mod_flags & (DEAD_OBJ | ORPHAN_OBJ)) &&
		      strcmp(name, XATTR_NAME_LINK) == 0))
		RETURN(-ENOENT);

        mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
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

        if (mdd_object_exists(mdd_obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(mdd_obj),PFID(mdd_object_fid(mdd_obj)));
                return -ENOENT;
        }

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
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

        mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = mdo_xattr_list(env, mdd_obj, buf, mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);

        RETURN(rc);
}

int mdd_declare_object_create_internal(const struct lu_env *env,
				       struct mdd_object *p,
				       struct mdd_object *c,
				       struct lu_attr *attr,
				       struct thandle *handle,
				       const struct md_op_spec *spec)
{
        struct dt_object_format *dof = &mdd_env_info(env)->mti_dof;
	struct dt_allocation_hint *hint = &mdd_env_info(env)->mti_hint;
        const struct dt_index_features *feat = spec->sp_feat;
        int rc;
        ENTRY;

	if (feat != &dt_directory_features && feat != NULL) {
                dof->dof_type = DFT_INDEX;
		dof->u.dof_idx.di_feat = feat;

	} else {
		dof->dof_type = dt_mode_to_dft(attr->la_mode);
		if (dof->dof_type == DFT_REGULAR) {
			dof->u.dof_reg.striped =
				md_should_create(spec->sp_cr_flags);
			if (spec->sp_cr_flags & MDS_OPEN_HAS_EA)
				dof->u.dof_reg.striped = 0;
			/* is this replay? */
			if (spec->no_create)
				dof->u.dof_reg.striped = 0;
		}
	}

	rc = mdo_declare_create_obj(env, c, attr, hint, dof, handle);

        RETURN(rc);
}

int mdd_object_create_internal(const struct lu_env *env, struct mdd_object *p,
			       struct mdd_object *c, struct lu_attr *attr,
                               struct thandle *handle,
                               const struct md_op_spec *spec)
{
        struct dt_allocation_hint *hint = &mdd_env_info(env)->mti_hint;
        struct dt_object_format *dof = &mdd_env_info(env)->mti_dof;
        int rc;
        ENTRY;

	LASSERT(!mdd_object_exists(c));

	rc = mdo_create_obj(env, c, attr, hint, dof, handle);

	LASSERT(ergo(rc == 0, mdd_object_exists(c)));

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

int mdd_attr_set_internal(const struct lu_env *env, struct mdd_object *obj,
			  const struct lu_attr *attr, struct thandle *handle,
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
				struct mdd_object *obj, struct lu_attr *attr,
				struct thandle *handle, int needacl)
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

/*
 * This gives the same functionality as the code between
 * sys_chmod and inode_setattr
 * chown_common and inode_setattr
 * utimes and inode_setattr
 * This API is ported from mds_fix_attr but remove some unnecesssary stuff.
 */
static int mdd_fix_attr(const struct lu_env *env, struct mdd_object *obj,
			struct lu_attr *la, const unsigned long flags)
{
        struct lu_attr   *tmp_la     = &mdd_env_info(env)->mti_la;
	struct lu_ucred  *uc;
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

	/* export destroy does not have ->le_ses, but we may want
	 * to drop LUSTRE_SOM_FL. */
	uc = lu_ucred_check(env);
	if (uc == NULL)
		RETURN(0);

        rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        if (la->la_valid == LA_CTIME) {
		if (!(flags & MDS_PERM_BYPASS))
                        /* This is only for set ctime when rename's source is
                         * on remote MDS. */
			rc = mdd_may_delete(env, NULL, obj, tmp_la, NULL, 1, 0);
                if (rc == 0 && la->la_ctime <= tmp_la->la_ctime)
                        la->la_valid &= ~LA_CTIME;
                RETURN(rc);
        }

        if (la->la_valid == LA_ATIME) {
                /* This is atime only set for read atime update on close. */
                if (la->la_atime >= tmp_la->la_atime &&
                    la->la_atime < (tmp_la->la_atime +
                                    mdd_obj2mdd_dev(obj)->mdd_atime_diff))
                        la->la_valid &= ~LA_ATIME;
                RETURN(0);
        }

        /* Check if flags change. */
        if (la->la_valid & LA_FLAGS) {
                unsigned int oldflags = 0;
                unsigned int newflags = la->la_flags &
                                (LUSTRE_IMMUTABLE_FL | LUSTRE_APPEND_FL);

		if ((uc->uc_fsuid != tmp_la->la_uid) &&
		    !md_capable(uc, CFS_CAP_FOWNER))
			RETURN(-EPERM);

		/* XXX: the IMMUTABLE and APPEND_ONLY flags can
		 * only be changed by the relevant capability. */
		if (mdd_is_immutable(obj))
			oldflags |= LUSTRE_IMMUTABLE_FL;
		if (mdd_is_append(obj))
			oldflags |= LUSTRE_APPEND_FL;
		if ((oldflags ^ newflags) &&
		    !md_capable(uc, CFS_CAP_LINUX_IMMUTABLE))
			RETURN(-EPERM);

                if (!S_ISDIR(tmp_la->la_mode))
                        la->la_flags &= ~LUSTRE_DIRSYNC_FL;
        }

        if ((mdd_is_immutable(obj) || mdd_is_append(obj)) &&
            (la->la_valid & ~LA_FLAGS) &&
	    !(flags & MDS_PERM_BYPASS))
                RETURN(-EPERM);

	/* Check for setting the obj time. */
	if ((la->la_valid & (LA_MTIME | LA_ATIME | LA_CTIME)) &&
	    !(la->la_valid & ~(LA_MTIME | LA_ATIME | LA_CTIME))) {
		if ((uc->uc_fsuid != tmp_la->la_uid) &&
		    !md_capable(uc, CFS_CAP_FOWNER)) {
			rc = mdd_permission_internal(env, obj, tmp_la,
						     MAY_WRITE);
			if (rc)
				RETURN(rc);
		}
	}

        if (la->la_valid & LA_KILL_SUID) {
                la->la_valid &= ~LA_KILL_SUID;
                if ((tmp_la->la_mode & S_ISUID) &&
                    !(la->la_valid & LA_MODE)) {
                        la->la_mode = tmp_la->la_mode;
                        la->la_valid |= LA_MODE;
                }
                la->la_mode &= ~S_ISUID;
        }

        if (la->la_valid & LA_KILL_SGID) {
                la->la_valid &= ~LA_KILL_SGID;
                if (((tmp_la->la_mode & (S_ISGID | S_IXGRP)) ==
                                        (S_ISGID | S_IXGRP)) &&
                    !(la->la_valid & LA_MODE)) {
                        la->la_mode = tmp_la->la_mode;
                        la->la_valid |= LA_MODE;
                }
                la->la_mode &= ~S_ISGID;
        }

        /* Make sure a caller can chmod. */
        if (la->la_valid & LA_MODE) {
		if (!(flags & MDS_PERM_BYPASS) &&
		    (uc->uc_fsuid != tmp_la->la_uid) &&
		    !md_capable(uc, CFS_CAP_FOWNER))
			RETURN(-EPERM);

		if (la->la_mode == (umode_t) -1)
			la->la_mode = tmp_la->la_mode;
		else
			la->la_mode = (la->la_mode & S_IALLUGO) |
				      (tmp_la->la_mode & ~S_IALLUGO);

		/* Also check the setgid bit! */
		if (!lustre_in_group_p(uc, (la->la_valid & LA_GID) ?
				       la->la_gid : tmp_la->la_gid) &&
		    !md_capable(uc, CFS_CAP_FSETID))
			la->la_mode &= ~S_ISGID;
	} else {
	       la->la_mode = tmp_la->la_mode;
	}

        /* Make sure a caller can chown. */
        if (la->la_valid & LA_UID) {
                if (la->la_uid == (uid_t) -1)
                        la->la_uid = tmp_la->la_uid;
		if (((uc->uc_fsuid != tmp_la->la_uid) ||
		     (la->la_uid != tmp_la->la_uid)) &&
		    !md_capable(uc, CFS_CAP_CHOWN))
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
		if (((uc->uc_fsuid != tmp_la->la_uid) ||
		     ((la->la_gid != tmp_la->la_gid) &&
		      !lustre_in_group_p(uc, la->la_gid))) &&
		    !md_capable(uc, CFS_CAP_CHOWN))
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
	 * We distinguish them by "flags & MDS_SOM".
         * For SOM case, it is true, the MAY_WRITE perm has been checked
         * when open, no need check again. For truncate case, it is false,
         * the MAY_WRITE perm should be checked here. */
	if (flags & MDS_SOM) {
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
			if (!((flags & MDS_OWNEROVERRIDE) &&
			      (uc->uc_fsuid == tmp_la->la_uid)) &&
			    !(flags & MDS_PERM_BYPASS)) {
				rc = mdd_permission_internal(env, obj,
							     tmp_la, MAY_WRITE);
				if (rc != 0)
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

/** Store a data change changelog record
 * If this fails, we must fail the whole transaction; we don't
 * want the change to commit without the log entry.
 * \param mdd_obj - mdd_object of change
 * \param handle - transacion handle
 */
int mdd_changelog_data_store(const struct lu_env *env, struct mdd_device *mdd,
			     enum changelog_rec_type type, int flags,
			     struct mdd_object *mdd_obj, struct thandle *handle)
{
	const struct lu_fid		*tfid;
	struct llog_changelog_rec	*rec;
	struct lu_buf			*buf;
	int				 reclen;
	int				 rc;

        /* Not recording */
        if (!(mdd->mdd_cl.mc_flags & CLM_ON))
                RETURN(0);
        if ((mdd->mdd_cl.mc_mask & (1 << type)) == 0)
                RETURN(0);

        LASSERT(mdd_obj != NULL);
        LASSERT(handle != NULL);

	tfid = mdo2fid(mdd_obj);

        if ((type >= CL_MTIME) && (type <= CL_ATIME) &&
            cfs_time_before_64(mdd->mdd_cl.mc_starttime, mdd_obj->mod_cltime)) {
                /* Don't need multiple updates in this log */
                /* Don't check under lock - no big deal if we get an extra
                   entry */
                RETURN(0);
        }

	reclen = llog_data_len(sizeof(*rec));
	buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mti_big_buf, reclen);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);
	rec = buf->lb_buf;

        rec->cr.cr_flags = CLF_VERSION | (CLF_FLAGMASK & flags);
        rec->cr.cr_type = (__u32)type;
        rec->cr.cr_tfid = *tfid;
        rec->cr.cr_namelen = 0;
        mdd_obj->mod_cltime = cfs_time_current_64();

	rc = mdd_changelog_store(env, mdd, rec, handle);

	RETURN(rc);
}

int mdd_changelog(const struct lu_env *env, enum changelog_rec_type type,
                  int flags, struct md_object *obj)
{
        struct thandle *handle;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        int rc;
        ENTRY;

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

        rc = mdd_declare_changelog_store(env, mdd, NULL, handle);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_changelog_data_store(env, mdd, type, flags, mdd_obj,
                                      handle);

stop:
        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

/**
 * Save LMA extended attributes with data from \a ma.
 *
 * HSM and Size-On-MDS data will be extracted from \ma if they are valid, if
 * not, LMA EA will be first read from disk, modified and write back.
 *
 */
/* Precedence for choosing record type when multiple
 * attributes change: setattr > mtime > ctime > atime
 * (ctime changes when mtime does, plus chmod/chown.
 * atime and ctime are independent.) */
static int mdd_attr_set_changelog(const struct lu_env *env,
                                  struct md_object *obj, struct thandle *handle,
                                  __u64 valid)
{
        struct mdd_device *mdd = mdo2mdd(obj);
        int bits, type = 0;

	bits =  (valid & LA_SIZE)  ? 1 << CL_TRUNC : 0;
	bits |= (valid & ~(LA_CTIME|LA_MTIME|LA_ATIME)) ? 1 << CL_SETATTR : 0;
        bits |= (valid & LA_MTIME) ? 1 << CL_MTIME : 0;
        bits |= (valid & LA_CTIME) ? 1 << CL_CTIME : 0;
        bits |= (valid & LA_ATIME) ? 1 << CL_ATIME : 0;
        bits = bits & mdd->mdd_cl.mc_mask;
	/* This is an implementation limit rather than a protocol limit */
	CLASSERT(CL_LAST <= sizeof(int) * 8);
        if (bits == 0)
                return 0;

        /* The record type is the lowest non-masked set bit */
	type = __ffs(bits);

        /* FYI we only store the first CLF_FLAGMASK bits of la_valid */
        return mdd_changelog_data_store(env, mdd, type, (int)valid,
                                        md2mdd_obj(obj), handle);
}

static int mdd_declare_attr_set(const struct lu_env *env,
                                struct mdd_device *mdd,
                                struct mdd_object *obj,
				const struct lu_attr *attr,
                                struct thandle *handle)
{
	int rc;

	rc = mdo_declare_attr_set(env, obj, attr, handle);
        if (rc)
                return rc;

#ifdef CONFIG_FS_POSIX_ACL
	if (attr->la_valid & LA_MODE) {
                mdd_read_lock(env, obj, MOR_TGT_CHILD);
		rc = mdo_xattr_get(env, obj, &LU_BUF_NULL,
				   XATTR_NAME_ACL_ACCESS, BYPASS_CAPA);
                mdd_read_unlock(env, obj);
                if (rc == -EOPNOTSUPP || rc == -ENODATA)
                        rc = 0;
                else if (rc < 0)
                        return rc;

                if (rc != 0) {
			struct lu_buf *buf = mdd_buf_get(env, NULL, rc);
                        rc = mdo_declare_xattr_set(env, obj, buf,
                                                   XATTR_NAME_ACL_ACCESS, 0,
                                                   handle);
                        if (rc)
                                return rc;
                }
        }
#endif

	rc = mdd_declare_changelog_store(env, mdd, NULL, handle);
	return rc;
}

static inline bool permission_is_reduced(const struct lu_attr *old,
					 const struct lu_attr *new)
{
	return ((new->la_mode & old->la_mode) & S_IRWXUGO) !=
	       (old->la_mode & S_IRWXUGO);
}

/* set attr and LOV EA at once, return updated attr */
int mdd_attr_set(const struct lu_env *env, struct md_object *obj,
		 const struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        struct lu_attr *la_copy = &mdd_env_info(env)->mti_la_for_fix;
	const struct lu_attr *la = &ma->ma_attr;
	bool sync_perm = false;
	int rc;
        ENTRY;

	/* we do not use ->attr_set() for LOV/SOM/HSM EA any more */
	LASSERT((ma->ma_valid & MA_LOV) == 0);
	LASSERT((ma->ma_valid & MA_HSM) == 0);
	LASSERT((ma->ma_valid & MA_SOM) == 0);

        *la_copy = ma->ma_attr;
	rc = mdd_fix_attr(env, mdd_obj, la_copy, ma->ma_attr_flags);
	if (rc)
                RETURN(rc);

        /* setattr on "close" only change atime, or do nothing */
	if (la->la_valid == LA_ATIME && la_copy->la_valid == 0)
                RETURN(0);

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

	rc = mdd_declare_attr_set(env, mdd, mdd_obj, la, handle);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

	/*
	 * LU-3671
	 *
	 * permission changes may require sync operation, to mitigate
	 * performance impact, only do this for dir and when permission is
	 * reduced.
	 *
	 * For regular files, version is updated with permission change
	 * (see VBR), async permission won't cause any issue, while missing
	 * permission change on directory may affect accessibility of other
	 * objects.
	 */
	if (S_ISDIR(mdd_object_type(mdd_obj))) {
		if (la->la_valid & (LA_UID | LA_GID)) {
			sync_perm = true;
		} else if (la->la_valid & LA_MODE &&
			   la->la_mode & (S_ISUID | S_ISGID | S_ISVTX)) {
			sync_perm = true;
		} else if (la->la_valid & LA_MODE) {
			struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;

			rc = mdd_la_get(env, mdd_obj, tmp_la, BYPASS_CAPA);
			if (rc)
				GOTO(stop, rc);

			if (permission_is_reduced(tmp_la, la))
				sync_perm = true;
		}
	}

	if (sync_perm)
		handle->th_sync |= !!mdd->mdd_sync_permission;

	if (la->la_valid & (LA_MTIME | LA_CTIME))
                CDEBUG(D_INODE, "setting mtime "LPU64", ctime "LPU64"\n",
		       la->la_mtime, la->la_ctime);

        if (la_copy->la_valid & LA_FLAGS) {
		rc = mdd_attr_set_internal(env, mdd_obj, la_copy, handle, 1);
                if (rc == 0)
                        mdd_flags_xlate(mdd_obj, la_copy->la_flags);
        } else if (la_copy->la_valid) {            /* setattr */
		rc = mdd_attr_set_internal(env, mdd_obj, la_copy, handle, 1);
        }

        if (rc == 0)
                rc = mdd_attr_set_changelog(env, obj, handle,
					    la->la_valid);
stop:
        mdd_trans_stop(env, mdd, rc, handle);
        RETURN(rc);
}

static int mdd_xattr_sanity_check(const struct lu_env *env,
				  struct mdd_object *obj)
{
	struct lu_attr  *tmp_la = &mdd_env_info(env)->mti_la;
	struct lu_ucred *uc     = lu_ucred_assert(env);
	int rc;
	ENTRY;

	if (mdd_is_immutable(obj) || mdd_is_append(obj))
		RETURN(-EPERM);

	rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
	if (rc)
		RETURN(rc);

	if ((uc->uc_fsuid != tmp_la->la_uid) &&
	    !md_capable(uc, CFS_CAP_FOWNER))
		RETURN(-EPERM);

	RETURN(rc);
}

static int mdd_declare_xattr_set(const struct lu_env *env,
				 struct mdd_device *mdd,
				 struct mdd_object *obj,
				 const struct lu_buf *buf,
				 const char *name,
				 int fl, struct thandle *handle)
{
	int	rc;

	rc = mdo_declare_xattr_set(env, obj, buf, name, fl, handle);
	if (rc)
		return rc;

	/* Only record user and layout xattr changes */
	if (strncmp(XATTR_USER_PREFIX, name,
		    sizeof(XATTR_USER_PREFIX) - 1) == 0 ||
	    strncmp(XATTR_NAME_LOV, name,
		    sizeof(XATTR_NAME_LOV) - 1) == 0) {
		rc = mdd_declare_changelog_store(env, mdd, NULL, handle);
		if (rc)
			return rc;
	}

	/* If HSM data is modified, this could add a changelog */
	if (strncmp(XATTR_NAME_HSM, name, sizeof(XATTR_NAME_HSM) - 1) == 0) {
		rc = mdd_declare_changelog_store(env, mdd, NULL, handle);
		if (rc)
			return rc;
	}

	rc = mdd_declare_changelog_store(env, mdd, NULL, handle);
	return rc;
}

/*
 * Compare current and future data of HSM EA and add a changelog if needed.
 *
 * Caller should have write-locked \param obj.
 *
 * \param buf - Future HSM EA content.
 * \retval 0 if no changelog is needed or changelog was added properly.
 * \retval -ve errno if there was a problem
 */
static int mdd_hsm_update_locked(const struct lu_env *env,
				 struct md_object *obj,
				 const struct lu_buf *buf,
				 struct thandle *handle)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct mdd_device      *mdd = mdo2mdd(obj);
	struct mdd_object      *mdd_obj = md2mdd_obj(obj);
	struct lu_buf          *current_buf;
	struct md_hsm          *current_mh;
	struct md_hsm          *new_mh;
	int                     rc;
	ENTRY;

	OBD_ALLOC_PTR(current_mh);
	if (current_mh == NULL)
		RETURN(-ENOMEM);

	/* Read HSM attrs from disk */
	CLASSERT(sizeof(struct hsm_attrs) <= sizeof(info->mti_xattr_buf));
	current_buf = mdd_buf_get(env, info->mti_xattr_buf,
				  sizeof(info->mti_xattr_buf));
	rc = mdo_xattr_get(env, mdd_obj, current_buf, XATTR_NAME_HSM,
			   mdd_object_capa(env, mdd_obj));
	rc = lustre_buf2hsm(current_buf->lb_buf, rc, current_mh);
	if (rc < 0 && rc != -ENODATA)
		GOTO(free, rc);
	else if (rc == -ENODATA)
		current_mh->mh_flags = 0;

	/* Map future HSM xattr */
	OBD_ALLOC_PTR(new_mh);
	if (new_mh == NULL)
		GOTO(free, rc = -ENOMEM);
	lustre_buf2hsm(buf->lb_buf, buf->lb_len, new_mh);

	/* If HSM flags are different, add a changelog */
	rc = 0;
	if (current_mh->mh_flags != new_mh->mh_flags) {
		int flags = 0;
		hsm_set_cl_event(&flags, HE_STATE);
		if (new_mh->mh_flags & HS_DIRTY)
			hsm_set_cl_flags(&flags, CLF_HSM_DIRTY);

		rc = mdd_changelog_data_store(env, mdd, CL_HSM, flags, mdd_obj,
					      handle);
	}

	OBD_FREE_PTR(new_mh);
free:
	OBD_FREE_PTR(current_mh);
	return(rc);
}

static int mdd_xattr_del(const struct lu_env *env, struct md_object *obj,
			 const char *name);

/**
 * The caller should guarantee to update the object ctime
 * after xattr_set if needed.
 */
static int mdd_xattr_set(const struct lu_env *env, struct md_object *obj,
			 const struct lu_buf *buf, const char *name,
			 int fl)
{
	struct mdd_object	*mdd_obj = md2mdd_obj(obj);
	struct mdd_device	*mdd = mdo2mdd(obj);
	struct thandle		*handle;
	int			 rc;
        ENTRY;

	rc = mdd_xattr_sanity_check(env, mdd_obj);
	if (rc)
		RETURN(rc);

	if (strcmp(name, XATTR_NAME_ACL_ACCESS) == 0 ||
	    strcmp(name, XATTR_NAME_ACL_DEFAULT) == 0) {
		struct posix_acl *acl;

		/* user may set empty ACL, which should be treated as removing
		 * ACL. */
		acl = posix_acl_from_xattr(&init_user_ns, buf->lb_buf,
					   buf->lb_len);
		if (acl == NULL) {
			rc = mdd_xattr_del(env, obj, name);
			RETURN(rc);
		}
		posix_acl_release(acl);
	}

	if (!strcmp(name, XATTR_NAME_ACL_ACCESS)) {
		rc = mdd_acl_set(env, mdd_obj, buf, fl);
		RETURN(rc);
	}

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	rc = mdd_declare_xattr_set(env, mdd, mdd_obj, buf, name, fl, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop, rc);

	mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);

	if (strncmp(XATTR_NAME_HSM, name, sizeof(XATTR_NAME_HSM) - 1) == 0) {
		rc = mdd_hsm_update_locked(env, obj, buf, handle);
		if (rc) {
			mdd_write_unlock(env, mdd_obj);
			GOTO(stop, rc);
		}
	}

	rc = mdo_xattr_set(env, mdd_obj, buf, name, fl, handle,
			   mdd_object_capa(env, mdd_obj));
	mdd_write_unlock(env, mdd_obj);
	if (rc)
		GOTO(stop, rc);

	if (strncmp(XATTR_NAME_LOV, name, sizeof(XATTR_NAME_LOV) - 1) == 0)
		rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, mdd_obj,
					      handle);
	else if (strncmp(XATTR_USER_PREFIX, name,
			sizeof(XATTR_USER_PREFIX) - 1) == 0 ||
	    strncmp(POSIX_ACL_XATTR_ACCESS, name,
			sizeof(POSIX_ACL_XATTR_ACCESS) - 1) == 0 ||
	    strncmp(POSIX_ACL_XATTR_DEFAULT, name,
			sizeof(POSIX_ACL_XATTR_DEFAULT) - 1) == 0)
		rc = mdd_changelog_data_store(env, mdd, CL_XATTR, 0, mdd_obj,
					      handle);

stop:
	mdd_trans_stop(env, mdd, rc, handle);

	RETURN(rc);
}

static int mdd_declare_xattr_del(const struct lu_env *env,
                                 struct mdd_device *mdd,
                                 struct mdd_object *obj,
                                 const char *name,
                                 struct thandle *handle)
{
        int rc;

        rc = mdo_declare_xattr_del(env, obj, name, handle);
        if (rc)
                return rc;

        /* Only record user xattr changes */
        if ((strncmp("user.", name, 5) == 0))
                rc = mdd_declare_changelog_store(env, mdd, NULL, handle);

        return rc;
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

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = mdd_declare_xattr_del(env, mdd, mdd_obj, name, handle);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = mdo_xattr_del(env, mdd_obj, name, handle,
                           mdd_object_capa(env, mdd_obj));
        mdd_write_unlock(env, mdd_obj);
	if (rc)
		GOTO(stop, rc);

        /* Only record system & user xattr changes */
	if (strncmp(XATTR_USER_PREFIX, name,
                                  sizeof(XATTR_USER_PREFIX) - 1) == 0 ||
                          strncmp(POSIX_ACL_XATTR_ACCESS, name,
                                  sizeof(POSIX_ACL_XATTR_ACCESS) - 1) == 0 ||
                          strncmp(POSIX_ACL_XATTR_DEFAULT, name,
				  sizeof(POSIX_ACL_XATTR_DEFAULT) - 1) == 0)
                rc = mdd_changelog_data_store(env, mdd, CL_XATTR, 0, mdd_obj,
                                              handle);

stop:
        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

/*
 * read lov EA of an object
 * return the lov EA in an allocated lu_buf
 */
static int mdd_get_lov_ea(const struct lu_env *env,
			  struct mdd_object *obj,
			  struct lu_buf *lmm_buf)
{
	struct lu_buf	*buf = &mdd_env_info(env)->mti_big_buf;
	int		 rc, sz;
	ENTRY;

repeat:
	rc = mdo_xattr_get(env, obj, buf, XATTR_NAME_LOV,
			   mdd_object_capa(env, obj));

	if (rc == -ERANGE) {
		/* mti_big_buf is allocated but is too small
		 * we need to increase it */
		buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mti_big_buf,
					     buf->lb_len * 2);
		if (buf->lb_buf == NULL)
			GOTO(out, rc = -ENOMEM);
		goto repeat;
	}

	if (rc < 0)
		GOTO(out, rc);

	if (rc == 0)
		GOTO(out, rc = -ENODATA);

	sz = rc;
	if (memcmp(buf, &LU_BUF_NULL, sizeof(*buf)) == 0) {
		/* mti_big_buf was not allocated, so we have to
		 * allocate it based on the ea size */
		buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mti_big_buf,
					     sz);
		if (buf->lb_buf == NULL)
			GOTO(out, rc = -ENOMEM);
		goto repeat;
	}

	lu_buf_alloc(lmm_buf, sz);
	if (lmm_buf->lb_buf == NULL)
		GOTO(out, rc = -ENOMEM);

	memcpy(lmm_buf->lb_buf, buf->lb_buf, sz);
	rc = 0;
	EXIT;

out:
	if (rc < 0)
		lu_buf_free(lmm_buf);
	return rc;
}

static int mdd_xattr_hsm_replace(const struct lu_env *env,
				 struct mdd_object *o, struct lu_buf *buf,
				 struct thandle *handle)
{
	struct hsm_attrs *attrs;
	__u32 hsm_flags;
	int flags = 0;
	int rc;
	ENTRY;

	rc = mdo_xattr_set(env, o, buf, XATTR_NAME_HSM, LU_XATTR_REPLACE,
			   handle, mdd_object_capa(env, o));
	if (rc != 0)
		RETURN(rc);

	attrs = buf->lb_buf;
	hsm_flags = le32_to_cpu(attrs->hsm_flags);
	if (!(hsm_flags & HS_RELEASED) || mdd_is_dead_obj(o))
		RETURN(0);

	/* Add a changelog record for release. */
	hsm_set_cl_event(&flags, HE_RELEASE);
	rc = mdd_changelog_data_store(env, mdo2mdd(&o->mod_obj), CL_HSM,
				      flags, o, handle);
	RETURN(rc);
}

/*
 *  check if layout swapping between 2 objects is allowed
 *  the rules are:
 *  - only normal FIDs or non-system IGIFs
 *  - same type of objects
 *  - same owner/group (so quotas are still valid)
 */
static int mdd_layout_swap_allowed(const struct lu_env *env,
				   struct mdd_object *o1,
				   struct mdd_object *o2)
{
	const struct lu_fid	*fid1, *fid2;
	__u32			 uid, gid;
	struct lu_attr		*tmp_la = &mdd_env_info(env)->mti_la;
	int			 rc;
	ENTRY;

	fid1 = mdo2fid(o1);
	fid2 = mdo2fid(o2);

	if (!fid_is_norm(fid1) &&
	    (!fid_is_igif(fid1) || IS_ERR(mdd_links_get(env, o1))))
		RETURN(-EBADF);

	if (!fid_is_norm(fid2) &&
	    (!fid_is_igif(fid2) || IS_ERR(mdd_links_get(env, o2))))
		RETURN(-EBADF);

	if (mdd_object_type(o1) != mdd_object_type(o2)) {
		if (S_ISDIR(mdd_object_type(o1)))
			RETURN(-ENOTDIR);
		if (S_ISREG(mdd_object_type(o1)))
			RETURN(-EISDIR);
		RETURN(-EBADF);
	}

	tmp_la->la_valid = 0;
	rc = mdd_la_get(env, o1, tmp_la, BYPASS_CAPA);
	if (rc)
		RETURN(rc);
	uid = tmp_la->la_uid;
	gid = tmp_la->la_gid;

	tmp_la->la_valid = 0;
	rc = mdd_la_get(env, o2, tmp_la, BYPASS_CAPA);
	if (rc)
		RETURN(rc);

	if ((uid != tmp_la->la_uid) || (gid != tmp_la->la_gid))
		RETURN(-EPERM);

	RETURN(0);
}

/**
 * swap layouts between 2 lustre objects
 */
static int mdd_swap_layouts(const struct lu_env *env, struct md_object *obj1,
			    struct md_object *obj2, __u64 flags)
{
	struct mdd_thread_info	*info = mdd_env_info(env);
	struct mdd_object	*fst_o = md2mdd_obj(obj1);
	struct mdd_object	*snd_o = md2mdd_obj(obj2);
	struct mdd_device	*mdd = mdo2mdd(obj1);
	struct lov_mds_md	*fst_lmm, *snd_lmm;
	struct lu_buf		*fst_buf = &info->mti_buf[0];
	struct lu_buf		*snd_buf = &info->mti_buf[1];
	struct lu_buf		*fst_hsm_buf = &info->mti_buf[2];
	struct lu_buf		*snd_hsm_buf = &info->mti_buf[3];
	struct ost_id		*saved_oi = NULL;
	struct thandle		*handle;
	__u16			 fst_gen, snd_gen;
	int			 fst_fl;
	int			 rc;
	int			 rc2;
	ENTRY;

	CLASSERT(ARRAY_SIZE(info->mti_buf) >= 4);
	memset(info->mti_buf, 0, sizeof(info->mti_buf));

	/* we have to sort the 2 obj, so locking will always
	 * be in the same order, even in case of 2 concurrent swaps */
	rc = lu_fid_cmp(mdo2fid(fst_o), mdo2fid(snd_o));
	if (rc == 0) /* same fid ? */
		RETURN(-EPERM);

	if (rc < 0)
		swap(fst_o, snd_o);

	/* check if layout swapping is allowed */
	rc = mdd_layout_swap_allowed(env, fst_o, snd_o);
	if (rc != 0)
		RETURN(rc);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	/* objects are already sorted */
	mdd_write_lock(env, fst_o, MOR_TGT_CHILD);
	mdd_write_lock(env, snd_o, MOR_TGT_CHILD);

	rc = mdd_get_lov_ea(env, fst_o, fst_buf);
	if (rc < 0 && rc != -ENODATA)
		GOTO(stop, rc);

	rc = mdd_get_lov_ea(env, snd_o, snd_buf);
	if (rc < 0 && rc != -ENODATA)
		GOTO(stop, rc);

	/* swapping 2 non existant layouts is a success */
	if (fst_buf->lb_buf == NULL && snd_buf->lb_buf == NULL)
		GOTO(stop, rc = 0);

	/* to help inode migration between MDT, it is better to
	 * start by the no layout file (if one), so we order the swap */
	if (snd_buf->lb_buf == NULL) {
		swap(fst_o, snd_o);
		swap(fst_buf, snd_buf);
	}

	/* lmm and generation layout initialization */
	if (fst_buf->lb_buf != NULL) {
		fst_lmm = fst_buf->lb_buf;
		fst_gen = le16_to_cpu(fst_lmm->lmm_layout_gen);
		fst_fl  = LU_XATTR_REPLACE;
	} else {
		fst_lmm = NULL;
		fst_gen = 0;
		fst_fl  = LU_XATTR_CREATE;
	}

	snd_lmm = snd_buf->lb_buf;
	snd_gen = le16_to_cpu(snd_lmm->lmm_layout_gen);

	/* increase the generation layout numbers */
	snd_gen++;
	fst_gen++;

	/* set the file specific informations in lmm */
	if (fst_lmm != NULL) {
		saved_oi = &info->mti_oa.o_oi;

		*saved_oi = fst_lmm->lmm_oi;
		fst_lmm->lmm_layout_gen = cpu_to_le16(snd_gen);
		fst_lmm->lmm_oi = snd_lmm->lmm_oi;
		snd_lmm->lmm_oi = *saved_oi;
	} else {
		if (snd_lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V1))
			snd_lmm->lmm_magic = cpu_to_le32(LOV_MAGIC_V1_DEF);
		else if (snd_lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V3))
			snd_lmm->lmm_magic = cpu_to_le32(LOV_MAGIC_V3_DEF);
		else
			GOTO(stop, rc = -EPROTO);
	}
	snd_lmm->lmm_layout_gen = cpu_to_le16(fst_gen);

	/* Prepare HSM attribute if it's required */
	if (flags & SWAP_LAYOUTS_MDS_HSM) {
		const int buflen = sizeof(struct hsm_attrs);

		lu_buf_alloc(fst_hsm_buf, buflen);
		lu_buf_alloc(snd_hsm_buf, buflen);
		if (fst_hsm_buf->lb_buf == NULL || snd_hsm_buf->lb_buf == NULL)
			GOTO(stop, rc = -ENOMEM);

		/* Read HSM attribute */
		rc = mdo_xattr_get(env, fst_o, fst_hsm_buf, XATTR_NAME_HSM,
				   BYPASS_CAPA);
		if (rc < 0)
			GOTO(stop, rc);

		rc = mdo_xattr_get(env, snd_o, snd_hsm_buf, XATTR_NAME_HSM,
				   BYPASS_CAPA);
		if (rc < 0)
			GOTO(stop, rc);

		rc = mdd_declare_xattr_set(env, mdd, fst_o, snd_hsm_buf,
					   XATTR_NAME_HSM, LU_XATTR_REPLACE,
					   handle);
		if (rc < 0)
			GOTO(stop, rc);

		rc = mdd_declare_xattr_set(env, mdd, snd_o, fst_hsm_buf,
					   XATTR_NAME_HSM, LU_XATTR_REPLACE,
					   handle);
		if (rc < 0)
			GOTO(stop, rc);
	}

	/* prepare transaction */
	rc = mdd_declare_xattr_set(env, mdd, fst_o, snd_buf, XATTR_NAME_LOV,
				   fst_fl, handle);
	if (rc != 0)
		GOTO(stop, rc);

	if (fst_buf->lb_buf != NULL)
		rc = mdd_declare_xattr_set(env, mdd, snd_o, fst_buf,
					   XATTR_NAME_LOV, LU_XATTR_REPLACE,
					   handle);
	else
		rc = mdd_declare_xattr_del(env, mdd, snd_o, XATTR_NAME_LOV,
					   handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc != 0)
		GOTO(stop, rc);

	if (flags & SWAP_LAYOUTS_MDS_HSM) {
		rc = mdd_xattr_hsm_replace(env, fst_o, snd_hsm_buf, handle);
		if (rc < 0)
			GOTO(stop, rc);

		rc = mdd_xattr_hsm_replace(env, snd_o, fst_hsm_buf, handle);
		if (rc < 0) {
			rc2 = mdd_xattr_hsm_replace(env, fst_o, fst_hsm_buf,
						    handle);
			if (rc2 < 0)
				CERROR("%s: restore "DFID" HSM error: %d/%d\n",
				       mdd_obj_dev_name(fst_o),
				       PFID(mdo2fid(fst_o)), rc, rc2);
			GOTO(stop, rc);
		}
	}

	rc = mdo_xattr_set(env, fst_o, snd_buf, XATTR_NAME_LOV, fst_fl, handle,
			   mdd_object_capa(env, fst_o));
	if (rc != 0)
		GOTO(stop, rc);

	if (unlikely(OBD_FAIL_CHECK(OBD_FAIL_MDS_HSM_SWAP_LAYOUTS))) {
		rc = -EOPNOTSUPP;
	} else {
		if (fst_buf->lb_buf != NULL)
			rc = mdo_xattr_set(env, snd_o, fst_buf, XATTR_NAME_LOV,
					   LU_XATTR_REPLACE, handle,
					   mdd_object_capa(env, snd_o));
		else
			rc = mdo_xattr_del(env, snd_o, XATTR_NAME_LOV, handle,
					   mdd_object_capa(env, snd_o));
	}

	if (rc != 0) {
		int steps = 0;

		/* failure on second file, but first was done, so we have
		 * to roll back first. */
		if (fst_buf->lb_buf != NULL) {
			fst_lmm->lmm_oi = *saved_oi;
			fst_lmm->lmm_layout_gen = cpu_to_le16(fst_gen - 1);
			rc2 = mdo_xattr_set(env, fst_o, fst_buf, XATTR_NAME_LOV,
					    LU_XATTR_REPLACE, handle,
					    mdd_object_capa(env, fst_o));
		} else {
			rc2 = mdo_xattr_del(env, fst_o, XATTR_NAME_LOV, handle,
					    mdd_object_capa(env, fst_o));
		}
		if (rc2 < 0)
			goto do_lbug;

		++steps;
		rc2 = mdd_xattr_hsm_replace(env, fst_o, fst_hsm_buf, handle);
		if (rc2 < 0)
			goto do_lbug;

		++steps;
		rc2 = mdd_xattr_hsm_replace(env, snd_o, snd_hsm_buf, handle);

	do_lbug:
		if (rc2 < 0) {
			/* very bad day */
			CERROR("%s: unable to roll back layout swap. FIDs: "
			       DFID" and "DFID "error: %d/%d, steps: %d\n",
			       mdd_obj_dev_name(fst_o),
			       PFID(mdo2fid(snd_o)), PFID(mdo2fid(fst_o)),
			       rc, rc2, steps);
			/* a solution to avoid journal commit is to panic,
			 * but it has strong consequences so we use LBUG to
			 * allow sysdamin to choose to panic or not
			 */
			LBUG();
		}
		GOTO(stop, rc);
	}

	/* Issue one changelog record per file */
	rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, fst_o, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, snd_o, handle);
	if (rc)
		GOTO(stop, rc);
	EXIT;

stop:
	mdd_trans_stop(env, mdd, rc, handle);
	mdd_write_unlock(env, snd_o);
	mdd_write_unlock(env, fst_o);

	lu_buf_free(fst_buf);
	lu_buf_free(snd_buf);
	lu_buf_free(fst_hsm_buf);
	lu_buf_free(snd_hsm_buf);
	return rc;
}

void mdd_object_make_hint(const struct lu_env *env, struct mdd_object *parent,
		struct mdd_object *child, struct lu_attr *attr)
{
	struct dt_allocation_hint *hint = &mdd_env_info(env)->mti_hint;
	struct dt_object *np = parent ? mdd_object_child(parent) : NULL;
	struct dt_object *nc = mdd_object_child(child);

	/* @hint will be initialized by underlying device. */
	nc->do_ops->do_ah_init(env, hint, np, nc, attr->la_mode & S_IFMT);
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
		struct lu_ucred *uc = lu_ucred_check(env);

		if ((uc == NULL) || (la->la_uid == uc->uc_fsuid))
			return 0;
	}

	if (flags & FMODE_READ)
		res |= MAY_READ;
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
		struct lu_ucred *uc = lu_ucred(env);

		if (uc && ((uc->uc_valid == UCRED_OLD) ||
			   (uc->uc_valid == UCRED_NEW)) &&
		    (uc->uc_fsuid != tmp_la->la_uid) &&
		    !md_capable(uc, CFS_CAP_FOWNER))
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

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);

        rc = mdd_open_sanity_check(env, mdd_obj, flags);
        if (rc == 0)
                mdd_obj->mod_count++;

        mdd_write_unlock(env, mdd_obj);
        return rc;
}

int mdd_declare_object_kill(const struct lu_env *env, struct mdd_object *obj,
                            struct md_attr *ma, struct thandle *handle)
{
        return mdo_declare_destroy(env, obj, handle);
}

/* return md_attr back,
 * if it is last unlink then return lov ea + llog cookie*/
int mdd_object_kill(const struct lu_env *env, struct mdd_object *obj,
                    struct md_attr *ma, struct thandle *handle)
{
	int rc;
        ENTRY;

	rc = mdo_destroy(env, obj, handle);

        RETURN(rc);
}

static int mdd_declare_close(const struct lu_env *env,
                             struct mdd_object *obj,
                             struct md_attr *ma,
                             struct thandle *handle)
{
        int rc;

        rc = orph_declare_index_delete(env, obj, handle);
        if (rc)
                return rc;

	return mdo_declare_destroy(env, obj, handle);
}

/*
 * No permission check is needed.
 */
static int mdd_close(const struct lu_env *env, struct md_object *obj,
                     struct md_attr *ma, int mode)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle    *handle = NULL;
	int rc, is_orphan = 0;
        ENTRY;

        if (ma->ma_valid & MA_FLAGS && ma->ma_attr_flags & MDS_KEEP_ORPHAN) {
		mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
		mdd_obj->mod_count--;
		mdd_write_unlock(env, mdd_obj);

                if (mdd_obj->mod_flags & ORPHAN_OBJ && !mdd_obj->mod_count)
                        CDEBUG(D_HA, "Object "DFID" is retained in orphan "
                               "list\n", PFID(mdd_object_fid(mdd_obj)));
                RETURN(0);
        }

	/* mdd_finish_unlink() will always set orphan object as DEAD_OBJ, but
	 * it might fail to add the object to orphan list (w/o ORPHAN_OBJ). */
	/* check without any lock */
	is_orphan = mdd_obj->mod_count == 1 &&
		    (mdd_obj->mod_flags & (ORPHAN_OBJ | DEAD_OBJ)) != 0;

again:
	if (is_orphan) {
                handle = mdd_trans_create(env, mdo2mdd(obj));
                if (IS_ERR(handle))
                        RETURN(PTR_ERR(handle));

                rc = mdd_declare_close(env, mdd_obj, ma, handle);
                if (rc)
                        GOTO(stop, rc);

                rc = mdd_declare_changelog_store(env, mdd, NULL, handle);
                if (rc)
                        GOTO(stop, rc);

                rc = mdd_trans_start(env, mdo2mdd(obj), handle);
                if (rc)
                        GOTO(stop, rc);
        }

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
	rc = mdd_la_get(env, mdd_obj, &ma->ma_attr,
			mdd_object_capa(env, mdd_obj));
	if (rc != 0) {
		CERROR("Failed to get lu_attr of "DFID": %d\n",
		       PFID(mdd_object_fid(mdd_obj)), rc);
		GOTO(out, rc);
	}

	/* check again with lock */
	is_orphan = (mdd_obj->mod_count == 1) &&
		    ((mdd_obj->mod_flags & (ORPHAN_OBJ | DEAD_OBJ)) != 0 ||
		     ma->ma_attr.la_nlink == 0);

	if (is_orphan && handle == NULL) {
		mdd_write_unlock(env, mdd_obj);
		goto again;
	}

	mdd_obj->mod_count--; /*release open count */

	if (!is_orphan)
		GOTO(out, rc = 0);

	/* Orphan object */
	/* NB: Object maybe not in orphan list originally, it is rare case for
	 * mdd_finish_unlink() failure, in that case, the object doesn't have
	 * ORPHAN_OBJ flag */
	if ((mdd_obj->mod_flags & ORPHAN_OBJ) != 0) {
		/* remove link to object from orphan index */
		LASSERT(handle != NULL);
		rc = __mdd_orphan_del(env, mdd_obj, handle);
		if (rc != 0) {
			CERROR("%s: unable to delete "DFID" from orphan list: "
			       "rc = %d\n", lu_dev_name(mdd2lu_dev(mdd)),
			       PFID(mdd_object_fid(mdd_obj)), rc);
			/* If object was not deleted from orphan list, do not
			 * destroy OSS objects, which will be done when next
			 * recovery. */
			GOTO(out, rc);
		}

		CDEBUG(D_HA, "Object "DFID" is deleted from orphan "
		       "list, OSS objects to be destroyed.\n",
		       PFID(mdd_object_fid(mdd_obj)));
	}

	rc = mdo_destroy(env, mdd_obj, handle);

	if (rc != 0) {
		CERROR("%s: unable to delete "DFID" from orphan list: "
		       "rc = %d\n", lu_dev_name(mdd2lu_dev(mdd)),
		       PFID(mdd_object_fid(mdd_obj)), rc);
	}
	EXIT;

out:
        mdd_write_unlock(env, mdd_obj);

        if (rc == 0 &&
            (mode & (FMODE_WRITE | MDS_OPEN_APPEND | MDS_OPEN_TRUNC)) &&
            !(ma->ma_valid & MA_FLAGS && ma->ma_attr_flags & MDS_RECOV_OPEN)) {
                if (handle == NULL) {
                        handle = mdd_trans_create(env, mdo2mdd(obj));
                        if (IS_ERR(handle))
				GOTO(stop, rc = PTR_ERR(handle));

                        rc = mdd_declare_changelog_store(env, mdd, NULL,
                                                         handle);
                        if (rc)
                                GOTO(stop, rc);

                        rc = mdd_trans_start(env, mdo2mdd(obj), handle);
                        if (rc)
                                GOTO(stop, rc);
                }

                mdd_changelog_data_store(env, mdd, CL_CLOSE, mode,
                                         mdd_obj, handle);
        }

stop:
	if (handle != NULL && !IS_ERR(handle))
		mdd_trans_stop(env, mdd, rc, handle);

	return rc;
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

static int mdd_dir_page_build(const struct lu_env *env, union lu_page *lp,
			      int nob, const struct dt_it_ops *iops,
			      struct dt_it *it, __u32 attr, void *arg)
{
	struct lu_dirpage	*dp = &lp->lp_dir;
	void			*area = dp;
	int			 result;
	__u64			 hash = 0;
	struct lu_dirent	*ent;
	struct lu_dirent	*last = NULL;
	int			 first = 1;

        memset(area, 0, sizeof (*dp));
        area += sizeof (*dp);
        nob  -= sizeof (*dp);

        ent  = area;
        do {
                int    len;
                int    recsize;

                len = iops->key_size(env, it);

                /* IAM iterator can return record with zero len. */
                if (len == 0)
                        goto next;

                hash = iops->store(env, it);
                if (unlikely(first)) {
                        first = 0;
                        dp->ldp_hash_start = cpu_to_le64(hash);
                }

                /* calculate max space required for lu_dirent */
                recsize = lu_dirent_calc_size(len, attr);

                if (nob >= recsize) {
                        result = iops->rec(env, it, (struct dt_rec *)ent, attr);
                        if (result == -ESTALE)
                                goto next;
                        if (result != 0)
                                goto out;

                        /* osd might not able to pack all attributes,
                         * so recheck rec length */
                        recsize = le16_to_cpu(ent->lde_reclen);
                } else {
                        result = (last != NULL) ? 0 :-EINVAL;
                        goto out;
                }
                last = ent;
                ent = (void *)ent + recsize;
                nob -= recsize;

next:
                result = iops->next(env, it);
                if (result == -ESTALE)
                        goto next;
        } while (result == 0);

out:
        dp->ldp_hash_end = cpu_to_le64(hash);
        if (last != NULL) {
                if (last->lde_hash == dp->ldp_hash_end)
                        dp->ldp_flags |= cpu_to_le32(LDF_COLLIDE);
                last->lde_reclen = 0; /* end mark */
        }
	if (result > 0)
		/* end of directory */
		dp->ldp_hash_end = cpu_to_le64(MDS_DIR_END_OFF);
	else if (result < 0)
		CWARN("build page failed: %d!\n", result);
        return result;
}

int mdd_readpage(const struct lu_env *env, struct md_object *obj,
                 const struct lu_rdpg *rdpg)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;
        ENTRY;

        if (mdd_object_exists(mdd_obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(mdd_obj),PFID(mdd_object_fid(mdd_obj)));
                return -ENOENT;
        }

        mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
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
		CDEBUG(D_INODE, "readdir from dead object: "DFID"\n",
		       PFID(mdd_object_fid(mdd_obj)));

                if (rdpg->rp_count <= 0)
                        GOTO(out_unlock, rc = -EFAULT);
                LASSERT(rdpg->rp_pages != NULL);

                pg = rdpg->rp_pages[0];
		dp = (struct lu_dirpage *)kmap(pg);
                memset(dp, 0 , sizeof(struct lu_dirpage));
                dp->ldp_hash_start = cpu_to_le64(rdpg->rp_hash);
                dp->ldp_hash_end   = cpu_to_le64(MDS_DIR_END_OFF);
                dp->ldp_flags = cpu_to_le32(LDF_EMPTY);
		kunmap(pg);
                GOTO(out_unlock, rc = LU_PAGE_SIZE);
        }

	rc = dt_index_walk(env, mdd_object_child(mdd_obj), rdpg,
			   mdd_dir_page_build, NULL);
	if (rc >= 0) {
		struct lu_dirpage	*dp;

		dp = kmap(rdpg->rp_pages[0]);
		dp->ldp_hash_start = cpu_to_le64(rdpg->rp_hash);
		if (rc == 0) {
			/*
			 * No pages were processed, mark this for first page
			 * and send back.
			 */
			dp->ldp_flags = cpu_to_le32(LDF_EMPTY);
			rc = min_t(unsigned int, LU_PAGE_SIZE, rdpg->rp_count);
		}
		kunmap(rdpg->rp_pages[0]);
	}

	GOTO(out_unlock, rc);
out_unlock:
        mdd_read_unlock(env, mdd_obj);
        return rc;
}

static int mdd_object_sync(const struct lu_env *env, struct md_object *obj)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);

        if (mdd_object_exists(mdd_obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(mdd_obj),PFID(mdd_object_fid(mdd_obj)));
                return -ENOENT;
        }
        return dt_object_sync(env, mdd_object_child(mdd_obj));
}

static int mdd_object_lock(const struct lu_env *env,
			   struct md_object *obj,
			   struct lustre_handle *lh,
			   struct ldlm_enqueue_info *einfo,
			   void *policy)
{
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	return dt_object_lock(env, mdd_object_child(mdd_obj), lh,
			      einfo, policy);
}

const struct md_object_operations mdd_obj_ops = {
	.moo_permission		= mdd_permission,
	.moo_attr_get		= mdd_attr_get,
	.moo_attr_set		= mdd_attr_set,
	.moo_xattr_get		= mdd_xattr_get,
	.moo_xattr_set		= mdd_xattr_set,
	.moo_xattr_list		= mdd_xattr_list,
	.moo_xattr_del		= mdd_xattr_del,
	.moo_swap_layouts	= mdd_swap_layouts,
	.moo_open		= mdd_open,
	.moo_close		= mdd_close,
	.moo_readpage		= mdd_readpage,
	.moo_readlink		= mdd_readlink,
	.moo_changelog		= mdd_changelog,
	.moo_capa_get		= mdd_capa_get,
	.moo_object_sync	= mdd_object_sync,
	.moo_object_lock	= mdd_object_lock,
};
