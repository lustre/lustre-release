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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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
#include <lustre_idmap.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_mds.h>

#include "mdd_internal.h"

static const struct lu_object_operations mdd_lu_obj_ops;

struct mdd_object_user {
	struct list_head	mou_list;	/**< linked off mod_users */
	u64			mou_open_flags;	/**< open mode by client */
	__u64			mou_uidgid;	/**< uid_gid on client */
	int			mou_opencount;	/**< # opened */
	ktime_t			mou_deniednext; /**< time of next access denied
						 * notfication
						 */
};

static int mdd_xattr_get(const struct lu_env *env,
                         struct md_object *obj, struct lu_buf *buf,
                         const char *name);

static int mdd_changelog_data_store_by_fid(const struct lu_env *env,
					   struct mdd_device *mdd,
					   enum changelog_rec_type type,
					   enum changelog_rec_flags clf_flags,
					   const struct lu_fid *fid,
					   const struct lu_fid *pfid,
					   const char *xattr_name,
					   struct thandle *handle);

static inline bool has_prefix(const char *str, const char *prefix);


static u32 flags_helper(u64 open_flags)
{
	u32 open_mode = 0;

	if (open_flags & MDS_FMODE_EXEC) {
		open_mode = MDS_FMODE_EXEC;
	} else {
		if (open_flags & MDS_FMODE_READ)
			open_mode = MDS_FMODE_READ;
		if (open_flags &
		    (MDS_FMODE_WRITE | MDS_OPEN_TRUNC | MDS_OPEN_APPEND))
			open_mode |= MDS_FMODE_WRITE;
	}

	return open_mode;
}

/** Allocate/init a user and its sub-structures.
 *
 * \param flags [IN]
 * \param uid [IN]
 * \param gid [IN]
 * \retval mou [OUT] success valid structure
 * \retval mou [OUT]
 */
static struct mdd_object_user *mdd_obj_user_alloc(u64 open_flags,
						  uid_t uid, gid_t gid)
{
	struct mdd_object_user *mou;

	ENTRY;

	OBD_SLAB_ALLOC_PTR(mou, mdd_object_kmem);
	if (mou == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	mou->mou_open_flags = open_flags;
	mou->mou_uidgid = ((__u64)uid << 32) | gid;
	mou->mou_opencount = 0;
	mou->mou_deniednext = ktime_set(0, 0);

	RETURN(mou);
}

/**
 * Free a user and its sub-structures.
 *
 * \param mou [IN]  user to be freed.
 */
static void mdd_obj_user_free(struct mdd_object_user *mou)
{
	OBD_SLAB_FREE_PTR(mou, mdd_object_kmem);
}

/**
 * Find if UID/GID already has this file open
 *
 * Caller should have write-locked \param mdd_obj.
 * \param mdd_obj [IN] mdd_obj
 * \param uid [IN] client uid
 * \param gid [IN] client gid
 * \retval user pointer or NULL if not found
 */
static
struct mdd_object_user *mdd_obj_user_find(struct mdd_object *mdd_obj,
					  uid_t uid, gid_t gid,
					  u64 open_flags)
{
	struct mdd_object_user *mou;
	__u64 uidgid;

	ENTRY;

	uidgid = ((__u64)uid << 32) | gid;
	list_for_each_entry(mou, &mdd_obj->mod_users, mou_list) {
		if (mou->mou_uidgid == uidgid &&
		    flags_helper(mou->mou_open_flags) ==
		    flags_helper(open_flags))
			RETURN(mou);
	}
	RETURN(NULL);
}

/**
 * Add a user to the list of openers for this file
 *
 * Caller should have write-locked \param mdd_obj.
 * \param mdd_obj [IN] mdd_obj
 * \param mou [IN] user
 * \retval 0 success
 * \retval -ve failure
 */
static int mdd_obj_user_add(struct mdd_object *mdd_obj,
			    struct mdd_object_user *mou,
			    bool denied)
{
	struct mdd_device *mdd = mdd_obj2mdd_dev(mdd_obj);
	struct mdd_object_user *tmp;
	__u32 uid = mou->mou_uidgid >> 32;
	__u32 gid = mou->mou_uidgid & ((1UL << 32) - 1);

	ENTRY;
	tmp = mdd_obj_user_find(mdd_obj, uid, gid, mou->mou_open_flags);
	if (tmp != NULL)
		RETURN(-EEXIST);

	list_add_tail(&mou->mou_list, &mdd_obj->mod_users);

	if (denied)
		/* next 'access denied' notification cannot happen before
		 * mou_deniednext
		 */
		mou->mou_deniednext =
			ktime_add(ktime_get(),
				  ktime_set(mdd->mdd_cl.mc_deniednext, 0));
	else
		mou->mou_opencount++;

	RETURN(0);
}
/**
 * Remove UID from the list
 *
 * Caller should have write-locked \param mdd_obj.
 * \param mdd_obj [IN] mdd_obj
 * \param uid [IN] user
 * \retval -ve failure
 */
static int mdd_obj_user_remove(struct mdd_object *mdd_obj,
			       struct mdd_object_user *mou)
{
	ENTRY;

	if (mou == NULL)
		RETURN(-ENOENT);

	list_del_init(&mou->mou_list);

	mdd_obj_user_free(mou);

	RETURN(0);
}
int mdd_la_get(const struct lu_env *env, struct mdd_object *obj,
	       struct lu_attr *la)
{
	int rc;

	if (mdd_object_exists(obj) == 0)
		return -ENOENT;

	rc = mdo_attr_get(env, obj, la);
	if (unlikely(rc != 0)) {
		if (rc == -ENOENT)
			obj->mod_flags |= DEAD_OBJ;
		return rc;
	}

	if (la->la_valid & LA_FLAGS && la->la_flags & LUSTRE_ORPHAN_FL)
		obj->mod_flags |= ORPHAN_OBJ | DEAD_OBJ;

	return 0;
}

struct mdd_thread_info *mdd_env_info(const struct lu_env *env)
{
	return lu_env_info(env, &mdd_thread_key);
}

struct lu_buf *mdd_buf_get(const struct lu_env *env, void *area, ssize_t len)
{
	struct lu_buf *buf;

	buf = &mdd_env_info(env)->mdi_buf[0];
	buf->lb_buf = area;
	buf->lb_len = len;
	return buf;
}

const struct lu_buf *mdd_buf_get_const(const struct lu_env *env,
                                       const void *area, ssize_t len)
{
	struct lu_buf *buf;

	buf = &mdd_env_info(env)->mdi_buf[0];
	buf->lb_buf = (void *)area;
	buf->lb_len = len;
	return buf;
}

struct lu_object *mdd_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *d)
{
	struct mdd_object *mdd_obj;
	struct lu_object *o;

	OBD_SLAB_ALLOC_PTR_GFP(mdd_obj, mdd_object_kmem, GFP_NOFS);
	if (!mdd_obj)
		return NULL;

	o = mdd2lu_obj(mdd_obj);
	lu_object_init(o, NULL, d);
	mdd_obj->mod_obj.mo_ops = &mdd_obj_ops;
	mdd_obj->mod_obj.mo_dir_ops = &mdd_dir_ops;
	mdd_obj->mod_count = 0;
	o->lo_ops = &mdd_lu_obj_ops;
	INIT_LIST_HEAD(&mdd_obj->mod_users);

	return o;
}

static int mdd_object_init(const struct lu_env *env, struct lu_object *o,
                           const struct lu_object_conf *unused)
{
        struct mdd_device *d = lu2mdd_dev(o->lo_dev);
        struct mdd_object *mdd_obj = lu2mdd_obj(o);
        struct lu_object  *below;
        struct lu_device  *under;
        ENTRY;

	mdd_obj->mod_cltime = ktime_set(0, 0);
        under = &d->mdd_child->dd_lu_dev;
        below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
	if (IS_ERR(below))
		RETURN(PTR_ERR(below));

        lu_object_add(o, below);

        RETURN(0);
}

static int mdd_object_start(const struct lu_env *env, struct lu_object *o)
{
	int rc = 0;

	if (lu_object_exists(o)) {
		struct mdd_object *mdd_obj = lu2mdd_obj(o);
		struct lu_attr *attr = MDD_ENV_VAR(env, la_for_start);

		rc = mdd_la_get(env, mdd_obj, attr);
	}

	return rc;
}

static void mdd_object_free(const struct lu_env *env, struct lu_object *o)
{
	struct mdd_object *mdd = lu2mdd_obj(o);
	struct mdd_object_user *mou, *tmp2;

	/* free user list */
	list_for_each_entry_safe(mou, tmp2, &mdd->mod_users, mou_list) {
		list_del(&mou->mou_list);
		mdd_obj_user_free(mou);
	}

	lu_object_fini(o);
	/* mdd doesn't contain an lu_object_header, so don't need call_rcu */
	OBD_SLAB_FREE_PTR(mdd, mdd_object_kmem);
}

static int mdd_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
	struct mdd_object *mdd = lu2mdd_obj((struct lu_object *)o);

	return (*p)(env, cookie,
		    LUSTRE_MDD_NAME"-object@%p(open_count=%d, valid=%x, cltime=%lldns, flags=%lx)",
                    mdd, mdd->mod_count, mdd->mod_valid,
		    ktime_to_ns(mdd->mod_cltime), mdd->mod_flags);
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

/*
 * No permission check is needed.
 */
int mdd_attr_get(const struct lu_env *env, struct md_object *obj,
		 struct md_attr *ma)
{
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	int		  rc;

	ENTRY;

	rc = mdd_la_get(env, mdd_obj, &ma->ma_attr);
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
	struct mdd_device *mdd;
	int rc;

	ENTRY;

	if (mdd_object_exists(mdd_obj) == 0) {
		CERROR("%s: object "DFID" not found: rc = -2\n",
		       mdd_obj_dev_name(mdd_obj),
		       PFID(mdd_object_fid(mdd_obj)));
		return -ENOENT;
	}

	/* If the object has been destroyed, then do not get LMVEA, because
	 * it needs to load stripes from the iteration of the master object,
	 * and it will cause problem if master object has been destroyed, see
	 * LU-6427 */
	if (unlikely((mdd_obj->mod_flags & DEAD_OBJ) &&
		     !(mdd_obj->mod_flags & ORPHAN_OBJ) &&
		      strcmp(name, XATTR_NAME_LMV) == 0))
		RETURN(-ENOENT);

	/* If the object has been delete from the namespace, then
	 * get linkEA should return -ENOENT as well */
	if (unlikely((mdd_obj->mod_flags & (DEAD_OBJ | ORPHAN_OBJ)) &&
		      strcmp(name, XATTR_NAME_LINK) == 0))
		RETURN(-ENOENT);

	mdd_read_lock(env, mdd_obj, DT_TGT_CHILD);
	rc = mdo_xattr_get(env, mdd_obj, buf, name);
	mdd_read_unlock(env, mdd_obj);

	mdd = mdo2mdd(obj);

	/* record only getting user xattrs and acls */
	if (rc >= 0 && buf->lb_buf &&
	    mdd_changelog_enabled(env, mdd, CL_GETXATTR) &&
	    (has_prefix(name, XATTR_USER_PREFIX) ||
	     has_prefix(name, XATTR_NAME_POSIX_ACL_ACCESS) ||
	     has_prefix(name, XATTR_NAME_POSIX_ACL_DEFAULT))) {
		struct thandle *handle;
		int rc2;

		LASSERT(mdd_object_fid(mdd_obj) != NULL);

		handle = mdd_trans_create(env, mdd);
		if (IS_ERR(handle))
			RETURN(PTR_ERR(handle));

		rc2 = mdd_declare_changelog_store(env, mdd, CL_GETXATTR, NULL,
						  NULL, handle);
		if (rc2)
			GOTO(stop, rc2);

		rc2 = mdd_trans_start(env, mdd, handle);
		if (rc2)
			GOTO(stop, rc2);

		rc2 = mdd_changelog_data_store_by_fid(env, mdd, CL_GETXATTR, 0,
						      mdd_object_fid(mdd_obj),
						      NULL, name, handle);

stop:
		rc2 = mdd_trans_stop(env, mdd, rc2, handle);
		if (rc2)
			rc = rc2;
	}

	RETURN(rc);
}

/*
 * Permission check is done when open,
 * no need check again.
 */
int mdd_readlink(const struct lu_env *env, struct md_object *obj,
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
	LASSERT(next != NULL);
	LASSERT(next->do_body_ops != NULL);
	LASSERT(next->do_body_ops->dbo_read != NULL);
	mdd_read_lock(env, mdd_obj, DT_TGT_CHILD);
	rc = dt_read(env, next, buf, &pos);
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

	mdd_read_lock(env, mdd_obj, DT_TGT_CHILD);
	rc = mdo_xattr_list(env, mdd_obj, buf);
        mdd_read_unlock(env, mdd_obj);

	/* If the buffer is NULL then we are only here to get the
	 * length of the xattr name list. */
	if (rc < 0 || buf->lb_buf == NULL)
		RETURN(rc);

	/*
	 * Filter out XATTR_NAME_LINK if this is an orphan object.  See
	 * mdd_xattr_get().
	 */
	if (unlikely(mdd_obj->mod_flags & (DEAD_OBJ | ORPHAN_OBJ))) {
		char   *end = (char *)buf->lb_buf + rc;
		char   *p = buf->lb_buf;

		while (p < end) {
			char   *next = p + strlen(p) + 1;

			if (strcmp(p, XATTR_NAME_LINK) == 0) {
				if (end - next > 0)
					memmove(p, next, end - next);
				rc -= next - p;
				CDEBUG(D_INFO, "Filtered out "XATTR_NAME_LINK
				       " of orphan "DFID"\n",
				       PFID(mdd_object_fid(mdd_obj)));
				break;
			}

			p = next;
		}
	}

	RETURN(rc);
}

int mdd_invalidate(const struct lu_env *env, struct md_object *obj)
{
	return mdo_invalidate(env, md2mdd_obj(obj));
}

int mdd_declare_create_object_internal(const struct lu_env *env,
				       struct mdd_object *p,
				       struct mdd_object *c,
				       struct lu_attr *attr,
				       struct thandle *handle,
				       const struct md_op_spec *spec,
				       struct dt_allocation_hint *hint)
{
	struct dt_object_format *dof = &mdd_env_info(env)->mdi_dof;
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

	rc = mdo_declare_create_object(env, c, attr, hint, dof, handle);

	RETURN(rc);
}

int mdd_create_object_internal(const struct lu_env *env, struct mdd_object *p,
			       struct mdd_object *c, struct lu_attr *attr,
			       struct thandle *handle,
			       const struct md_op_spec *spec,
			       struct dt_allocation_hint *hint)
{
	struct dt_object_format *dof = &mdd_env_info(env)->mdi_dof;
	int rc;
	ENTRY;

	LASSERT(!mdd_object_exists(c));

	rc = mdo_create_object(env, c, attr, hint, dof, handle);

	RETURN(rc);
}

int mdd_attr_set_internal(const struct lu_env *env, struct mdd_object *obj,
			  const struct lu_attr *attr, struct thandle *handle,
			  int needacl)
{
	int rc;
	ENTRY;

	rc = mdo_attr_set(env, obj, attr, handle);
#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	if (!rc && (attr->la_valid & LA_MODE) && needacl)
		rc = mdd_acl_chmod(env, obj, attr->la_mode, handle);
#endif
	RETURN(rc);
}

int mdd_update_time(const struct lu_env *env, struct mdd_object *obj,
		    const struct lu_attr *oattr, struct lu_attr *attr,
		    struct thandle *handle)
{
	int rc = 0;
	ENTRY;

	LASSERT(attr->la_valid & LA_CTIME);
	LASSERT(oattr != NULL);

	/* Make sure the ctime is increased only, however, it's not strictly
	 * reliable at here because there is not guarantee to hold lock on
	 * object, so we just bypass some unnecessary cmtime setting first
	 * and OSD has to check it again. */
	if (attr->la_ctime < oattr->la_ctime)
		attr->la_valid &= ~(LA_MTIME | LA_CTIME);
	else if (attr->la_valid == LA_CTIME &&
		 attr->la_ctime == oattr->la_ctime)
		attr->la_valid &= ~LA_CTIME;

	if (attr->la_valid != 0)
		rc = mdd_attr_set_internal(env, obj, attr, handle, 0);
	RETURN(rc);
}


static bool is_project_state_change(const struct lu_attr *oattr,
				    struct lu_attr *la)
{
	if (la->la_valid & LA_PROJID &&
	    oattr->la_projid != la->la_projid)
		return true;

	if ((la->la_valid & LA_FLAGS) &&
	    (la->la_flags & LUSTRE_PROJINHERIT_FL) !=
	    (oattr->la_flags & LUSTRE_PROJINHERIT_FL))
		return true;

	return false;
}

/*
 * This gives the same functionality as the code between
 * sys_chmod and inode_setattr
 * chown_common and inode_setattr
 * utimes and inode_setattr
 * This API is ported from mds_fix_attr but remove some unnecesssary stuff.
 */
static int mdd_fix_attr(const struct lu_env *env, struct mdd_object *obj,
			const struct lu_attr *oattr, struct lu_attr *la,
			const struct md_attr *ma)
{
	struct lu_ucred  *uc;
	int		  rc = 0;
	const unsigned long flags = ma->ma_attr_flags;

	ENTRY;

	if (!la->la_valid)
		RETURN(0);

	/* Do not permit change file type */
	if (la->la_valid & LA_TYPE)
		RETURN(-EPERM);

	/* They should not be processed by setattr */
	if (la->la_valid & (LA_NLINK | LA_RDEV | LA_BLKSIZE))
		RETURN(-EPERM);

	LASSERT(oattr != NULL);

	uc = lu_ucred_check(env);
	if (uc == NULL)
		RETURN(0);

	if (is_project_state_change(oattr, la)) {
		if (!cap_raised(uc->uc_cap, CAP_SYS_RESOURCE) &&
		    !lustre_in_group_p(uc, ma->ma_enable_chprojid_gid) &&
		    !(ma->ma_enable_chprojid_gid == -1 &&
		      mdd_permission_internal(env, obj, oattr, MAY_WRITE)))
			RETURN(-EPERM);
	}

	if (la->la_valid == LA_CTIME) {
		if (!(flags & MDS_PERM_BYPASS))
			/* This is only for set ctime when rename's source is
			 * on remote MDS. */
			rc = mdd_may_delete(env, NULL, NULL, obj, oattr, NULL,
					    1, 0);
		if (rc == 0 && la->la_ctime <= oattr->la_ctime)
			la->la_valid &= ~LA_CTIME;
		RETURN(rc);
	}

	if (flags & MDS_CLOSE_UPDATE_TIMES &&
	    la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME)) {
		/* This is an atime/mtime/ctime attribute update for
		 * close RPCs.
		 */
		if (la->la_valid & LA_ATIME &&
		    la->la_atime <= (oattr->la_atime +
				mdd_obj2mdd_dev(obj)->mdd_atime_diff))
			la->la_valid &= ~LA_ATIME;
		if (la->la_valid & LA_CTIME && la->la_ctime <= oattr->la_ctime)
			la->la_valid &= ~LA_CTIME;
		if (la->la_valid & LA_MTIME && la->la_mtime <= oattr->la_mtime)
			la->la_valid &= ~LA_MTIME;
		RETURN(0);
	}

	/* Check if flags change. */
	if (la->la_valid & LA_FLAGS) {
		unsigned int oldflags = oattr->la_flags &
				(LUSTRE_IMMUTABLE_FL | LUSTRE_APPEND_FL);
		unsigned int newflags = la->la_flags &
				(LUSTRE_IMMUTABLE_FL | LUSTRE_APPEND_FL);

		if ((uc->uc_fsuid != oattr->la_uid) &&
		    !cap_raised(uc->uc_cap, CAP_FOWNER))
			RETURN(-EPERM);

		/* The IMMUTABLE and APPEND_ONLY flags can
		 * only be changed by the relevant capability. */
		if ((oldflags ^ newflags) &&
		    !cap_raised(uc->uc_cap, CAP_LINUX_IMMUTABLE))
			RETURN(-EPERM);

		if (!S_ISDIR(oattr->la_mode)) {
			la->la_flags &= ~(LUSTRE_DIRSYNC_FL | LUSTRE_TOPDIR_FL);
		} else if (la->la_flags & LUSTRE_ENCRYPT_FL) {
			/* when trying to add encryption flag on dir,
			 * make sure it is empty
			 */
			rc = mdd_dir_is_empty(env, obj);
			if (rc)
				RETURN(rc);
			rc = 0;
		}
	}

	if (oattr->la_flags & (LUSTRE_IMMUTABLE_FL | LUSTRE_APPEND_FL) &&
	    (la->la_valid & ~LA_FLAGS) &&
	    !(flags & MDS_PERM_BYPASS))
		RETURN(-EPERM);

	/* Check for setting the obj time. */
	if ((la->la_valid & (LA_MTIME | LA_ATIME | LA_CTIME)) &&
	    !(la->la_valid & ~(LA_MTIME | LA_ATIME | LA_CTIME))) {
		if ((uc->uc_fsuid != oattr->la_uid) &&
		    !cap_raised(uc->uc_cap, CAP_FOWNER)) {
			rc = mdd_permission_internal(env, obj, oattr,
						     MAY_WRITE);
			if (rc)
				RETURN(rc);
		}
	}

	if (la->la_valid & LA_KILL_SUID) {
		la->la_valid &= ~LA_KILL_SUID;
		if ((oattr->la_mode & S_ISUID) &&
		    !(la->la_valid & LA_MODE)) {
			la->la_mode = oattr->la_mode;
			la->la_valid |= LA_MODE;
		}
		la->la_mode &= ~S_ISUID;
	}

	if (la->la_valid & LA_KILL_SGID) {
		la->la_valid &= ~LA_KILL_SGID;
		if (((oattr->la_mode & (S_ISGID | S_IXGRP)) ==
			(S_ISGID | S_IXGRP)) &&
		    !(la->la_valid & LA_MODE)) {
			la->la_mode = oattr->la_mode;
			la->la_valid |= LA_MODE;
		}
		la->la_mode &= ~S_ISGID;
	}

	/* Make sure a caller can chmod. */
	if (la->la_valid & LA_MODE) {
		if (!(flags & MDS_PERM_BYPASS) &&
		    (uc->uc_fsuid != oattr->la_uid) &&
		    !cap_raised(uc->uc_cap, CAP_FOWNER))
			RETURN(-EPERM);

		if (la->la_mode == (umode_t) -1)
			la->la_mode = oattr->la_mode;
		else
			la->la_mode = (la->la_mode & S_IALLUGO) |
					(oattr->la_mode & ~S_IALLUGO);

		/* Also check the setgid bit! */
		if (!lustre_in_group_p(uc, (la->la_valid & LA_GID) ?
				       la->la_gid : oattr->la_gid) &&
		    !cap_raised(uc->uc_cap, CAP_FSETID))
			la->la_mode &= ~S_ISGID;
	} else {
	       la->la_mode = oattr->la_mode;
	}

	/* Make sure a caller can chown. */
	if (la->la_valid & LA_UID) {
		if (la->la_uid == (uid_t) -1)
			la->la_uid = oattr->la_uid;
		if (((uc->uc_fsuid != oattr->la_uid) ||
		     (la->la_uid != oattr->la_uid)) &&
		    !cap_raised(uc->uc_cap, CAP_CHOWN))
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
		if (((oattr->la_mode & S_ISUID) == S_ISUID) &&
		!S_ISDIR(oattr->la_mode)) {
			la->la_mode &= ~S_ISUID;
			la->la_valid |= LA_MODE;
		}
	}

	/* Make sure caller can chgrp. */
	if (la->la_valid & LA_GID) {
		if (la->la_gid == (gid_t) -1)
			la->la_gid = oattr->la_gid;
		if (((uc->uc_fsuid != oattr->la_uid) ||
		     ((la->la_gid != oattr->la_gid) &&
		      !lustre_in_group_p(uc, la->la_gid))) &&
		    !cap_raised(uc->uc_cap, CAP_CHOWN))
			RETURN(-EPERM);

		/* Likewise, if the user or group of a non-directory
		 * has been changed by a non-root user, remove the
		 * setgid bit UNLESS there is no group execute bit
		 * (this would be a file marked for mandatory
		 * locking).  19981026 David C Niemi <niemi@tux.org>
		 *
		 * Removed the fsuid check (see the comment above) --
		 * 19990830 SD. */
		if (((oattr->la_mode & (S_ISGID | S_IXGRP)) ==
		    (S_ISGID | S_IXGRP)) && !S_ISDIR(oattr->la_mode)) {
			la->la_mode &= ~S_ISGID;
			la->la_valid |= LA_MODE;
		}
	}

	if (la->la_valid & (LA_SIZE | LA_BLOCKS)) {
		if (!((flags & MDS_OWNEROVERRIDE) &&
		      (uc->uc_fsuid == oattr->la_uid)) &&
		    !(flags & MDS_PERM_BYPASS)) {
			rc = mdd_permission_internal(env, obj, oattr,
						     MAY_WRITE);
			if (rc != 0)
				RETURN(rc);
		}
	}

	if (la->la_valid & LA_CTIME) {
		/**
		 * The pure setattr, it has the priority over what is
		 * already set, do not drop it if ctime is equal.
		 */
		if (la->la_ctime < oattr->la_ctime)
			la->la_valid &= ~(LA_ATIME | LA_MTIME | LA_CTIME);
	}

	RETURN(0);
}

static int mdd_changelog_data_store_by_fid(const struct lu_env *env,
					   struct mdd_device *mdd,
					   enum changelog_rec_type type,
					   enum changelog_rec_flags clf_flags,
					   const struct lu_fid *fid,
					   const struct lu_fid *pfid,
					   const char *xattr_name,
					   struct thandle *handle)
{
	const struct lu_ucred *uc = lu_ucred(env);
	enum changelog_rec_extra_flags xflags = CLFE_INVALID;
	struct llog_changelog_rec *rec;
	struct lu_buf *buf;
	int reclen;
	int rc;

	clf_flags = (clf_flags & CLF_FLAGMASK) | CLF_VERSION | CLF_EXTRA_FLAGS;

	if (uc) {
		if (uc->uc_jobid[0] != '\0')
			clf_flags |= CLF_JOBID;
		xflags |= CLFE_UIDGID;
		xflags |= CLFE_NID;
	}
	if (type == CL_OPEN || type == CL_DN_OPEN)
		xflags |= CLFE_OPEN;
	if (type == CL_SETXATTR || type == CL_GETXATTR)
		xflags |= CLFE_XATTR;

	reclen = llog_data_len(LLOG_CHANGELOG_HDR_SZ +
			       changelog_rec_offset(clf_flags & CLF_SUPPORTED,
						    xflags & CLFE_SUPPORTED));
	buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mdi_chlg_buf, reclen);
	if (buf->lb_buf == NULL)
		RETURN(-ENOMEM);
	rec = buf->lb_buf;

	rec->cr_hdr.lrh_len = reclen;
	rec->cr.cr_flags = clf_flags;
	rec->cr.cr_type = (__u32)type;
	rec->cr.cr_tfid = *fid;
	if (pfid)
		rec->cr.cr_pfid = *pfid;
	rec->cr.cr_namelen = 0;

	if (clf_flags & CLF_JOBID)
		mdd_changelog_rec_ext_jobid(&rec->cr, uc->uc_jobid);

	if (clf_flags & CLF_EXTRA_FLAGS) {
		mdd_changelog_rec_ext_extra_flags(&rec->cr, xflags);
		if (xflags & CLFE_UIDGID)
			mdd_changelog_rec_extra_uidgid(&rec->cr,
						       uc->uc_uid, uc->uc_gid);
		if (xflags & CLFE_NID)
			mdd_changelog_rec_extra_nid(&rec->cr, uc->uc_nid);
		if (xflags & CLFE_OPEN)
			mdd_changelog_rec_extra_omode(&rec->cr, clf_flags);
		if (xflags & CLFE_XATTR) {
			if (xattr_name == NULL)
				RETURN(-EINVAL);
			mdd_changelog_rec_extra_xattr(&rec->cr, xattr_name);
		}
	}

	rc = mdd_changelog_store(env, mdd, rec, handle);
	RETURN(rc);
}


/** Store a data change changelog record
 * If this fails, we must fail the whole transaction; we don't
 * want the change to commit without the log entry.
 * \param mdd_obj - mdd_object of change
 * \param handle - transaction handle
 * \param pfid - parent FID for CL_MTIME changelogs
 */
int mdd_changelog_data_store(const struct lu_env *env, struct mdd_device *mdd,
			     enum changelog_rec_type type,
			     enum changelog_rec_flags clf_flags,
			     struct mdd_object *mdd_obj, struct thandle *handle,
			     const struct lu_fid *pfid)
{
	int				 rc;

	LASSERT(mdd_obj != NULL);
	LASSERT(handle != NULL);

	if (!mdd_changelog_enabled(env, mdd, type))
		RETURN(0);

	if (mdd_is_volatile_obj(mdd_obj))
		RETURN(0);

	if ((type >= CL_MTIME) && (type <= CL_ATIME) &&
	    ktime_before(mdd->mdd_cl.mc_starttime, mdd_obj->mod_cltime)) {
		/* Don't need multiple updates in this log */
		/* Don't check under lock - no big deal if we get an extra
		   entry */
		RETURN(0);
	}

	rc = mdd_changelog_data_store_by_fid(env, mdd, type, clf_flags,
					     mdd_object_fid(mdd_obj), pfid,
					     NULL, handle);
	if (rc == 0)
		mdd_obj->mod_cltime = ktime_get();

	RETURN(rc);
}

int mdd_changelog_data_store_xattr(const struct lu_env *env,
				   struct mdd_device *mdd,
				   enum changelog_rec_type type,
				   enum changelog_rec_flags clf_flags,
				   struct mdd_object *mdd_obj,
				   const char *xattr_name,
				   struct thandle *handle)
{
	int rc;

	LASSERT(mdd_obj != NULL);
	LASSERT(handle != NULL);

	if (!mdd_changelog_enabled(env, mdd, type))
		RETURN(0);

	if (mdd_is_volatile_obj(mdd_obj))
		RETURN(0);

	if ((type >= CL_MTIME) && (type <= CL_ATIME) &&
	    ktime_before(mdd->mdd_cl.mc_starttime, mdd_obj->mod_cltime)) {
		/* Don't need multiple updates in this log */
		/* Don't check under lock - no big deal if we get an extra
		 * entry
		 */
		RETURN(0);
	}

	rc = mdd_changelog_data_store_by_fid(env, mdd, type, clf_flags,
					     mdd_object_fid(mdd_obj), NULL,
					     xattr_name, handle);
	if (rc == 0)
		mdd_obj->mod_cltime = ktime_get();

	RETURN(rc);
}

/* only the bottom CLF_FLAGSHIFT bits of @flags are stored in the record,
 * except for open flags have a dedicated record to store 32 bits of flags */
static int mdd_changelog(const struct lu_env *env, enum changelog_rec_type type,
			 enum changelog_rec_flags clf_flags,
			 struct md_device *m, const struct lu_fid *fid)
{
	struct thandle *handle;
	struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
	int rc;
	ENTRY;

	LASSERT(fid != NULL);

	/* We'll check this again below, but we check now before we
	 * start a transaction. */
	if (!mdd_changelog_enabled(env, mdd, type))
		RETURN(0);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	rc = mdd_declare_changelog_store(env, mdd, type, NULL, NULL, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_changelog_data_store_by_fid(env, mdd, type, clf_flags,
					     fid, NULL, NULL, handle);

stop:
	rc = mdd_trans_stop(env, mdd, rc, handle);

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
				  const struct lu_fid *pfid, __u64 valid)
{
	struct mdd_device *mdd = mdo2mdd(obj);
	int bits, type = 0;

	bits =  (valid & LA_SIZE)  ? BIT(CL_TRUNC) : 0;
	bits |= (valid & ~(LA_CTIME|LA_MTIME|LA_ATIME)) ? BIT(CL_SETATTR) : 0;
	bits |= (valid & LA_MTIME) ? BIT(CL_MTIME) : 0;
	bits |= (valid & LA_CTIME) ? BIT(CL_CTIME) : 0;
	bits |= (valid & LA_ATIME) ? BIT(CL_ATIME) : 0;
	bits = bits & mdd->mdd_cl.mc_current_mask;
	/* This is an implementation limit rather than a protocol limit */
	BUILD_BUG_ON(CL_LAST > sizeof(int) * 8);
	if (bits == 0)
		return 0;

	/* The record type is the lowest non-masked set bit */
	type = __ffs(bits);

	/* XXX: we only store the low CLF_FLAGMASK bits of la_valid */
	return mdd_changelog_data_store(env, mdd, type, valid, md2mdd_obj(obj),
					handle, pfid);
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

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	if (attr->la_valid & LA_MODE) {
		mdd_read_lock(env, obj, DT_TGT_CHILD);
		rc = mdo_xattr_get(env, obj, &LU_BUF_NULL,
				   XATTR_NAME_ACL_ACCESS);
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

	rc = mdd_declare_changelog_store(env, mdd, CL_SETXATTR, NULL, NULL,
					 handle);
	return rc;
}

/*
 * LU-3671
 * LU-7239
 *
 * permission changes may require sync operation, to mitigate performance
 * impact, only do this for dir and when permission is reduced.
 *
 * For regular files, version is updated with permission change (see VBR), async
 * permission won't cause any issue, while missing permission change on
 * directory may affect accessibility of other objects after recovery.
 */
static inline bool permission_needs_sync(const struct lu_attr *old,
					 const struct lu_attr *new)
{
	if (!S_ISDIR(old->la_mode))
		return false;

	if (new->la_valid & LA_UID && old->la_uid != new->la_uid)
		return true;

	if (new->la_valid & LA_GID && old->la_gid != new->la_gid)
		return true;

	if (new->la_valid & LA_MODE) {
		/* turned on sticky bit */
		if (!(old->la_mode & S_ISVTX) && (new->la_mode & S_ISVTX))
			return true;

		/* set-GID has no impact on what is allowed, not checked */

		/* turned off setuid bit, or one of rwx for someone */
		if (((new->la_mode & old->la_mode) & (0777 | S_ISUID)) !=
		     (old->la_mode & (0777 | S_ISUID)))
			return true;
	}

	return false;
}

static inline __u64 mdd_lmm_dom_size(void *buf)
{
	struct lov_mds_md *lmm = buf;
	struct lov_comp_md_v1 *comp_v1;
	struct lov_mds_md *v1;
	__u32 off;

	if (lmm == NULL)
		return 0;

	if (le32_to_cpu(lmm->lmm_magic) != LOV_MAGIC_COMP_V1)
		return 0;

	comp_v1 = (struct lov_comp_md_v1 *)lmm;
	off = le32_to_cpu(comp_v1->lcm_entries[0].lcme_offset);
	v1 = (struct lov_mds_md *)((char *)comp_v1 + off);

	/* DoM entry is the first entry always */
	if (lov_pattern(le32_to_cpu(v1->lmm_pattern)) == LOV_PATTERN_MDT)
		return le64_to_cpu(comp_v1->lcm_entries[0].lcme_extent.e_end);

	return 0;
}

/* set attr and LOV EA at once, return updated attr */
int mdd_attr_set(const struct lu_env *env, struct md_object *obj,
		 const struct md_attr *ma)
{
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	struct mdd_device *mdd = mdo2mdd(obj);
	struct thandle *handle = NULL;
	struct lu_attr *la_copy = &mdd_env_info(env)->mdi_la_for_fix;
	struct lu_attr *attr = MDD_ENV_VAR(env, cattr);
	const struct lu_attr *la = &ma->ma_attr;
	struct lu_ucred  *uc;
	bool quota_reserved = false;
	bool chrgrp_by_unprivileged_user = false;
	__s64 quota_size = 0;
	int rc;
	ENTRY;

	/* we do not use ->attr_set() for LOV/HSM EA any more */
	LASSERT((ma->ma_valid & MA_LOV) == 0);
	LASSERT((ma->ma_valid & MA_HSM) == 0);

	rc = mdd_la_get(env, mdd_obj, attr);
	if (rc)
		RETURN(rc);

	*la_copy = ma->ma_attr;
	rc = mdd_fix_attr(env, mdd_obj, attr, la_copy, ma);
	if (rc)
		RETURN(rc);

	/* no need to setattr anymore */
	if (la_copy->la_valid == 0) {
		CDEBUG(D_INODE,
		       "%s: no valid attribute on "DFID", previous was %#llx\n",
		       mdd_obj_dev_name(mdd_obj),
		       PFID(mdd_object_fid(mdd_obj)), la->la_valid);

		RETURN(0);
	}

	/* If an unprivileged user changes group of some file,
	 * the setattr operation will be processed synchronously to
	 * honor the quota limit of the corresponding group. see LU-5152 */
	uc = lu_ucred_check(env);
	if (S_ISREG(attr->la_mode) && la->la_valid & LA_GID &&
	    la->la_gid != attr->la_gid && uc != NULL && uc->uc_fsuid != 0) {
		CDEBUG(D_QUOTA, "%s: reserve quota for changing group: gid=%u size=%llu\n",
		       mdd2obd_dev(mdd)->obd_name, la->la_gid, la->la_size);

		if (la->la_valid & LA_BLOCKS)
			quota_size = la->la_blocks << 9;
		else if (la->la_valid & LA_SIZE)
			quota_size = la->la_size;
		/* use local attr gotten above */
		else if (attr->la_valid & LA_BLOCKS)
			quota_size = attr->la_blocks << 9;
		else if (attr->la_valid & LA_SIZE)
			quota_size = attr->la_size;

		if (quota_size > 0) {
			rc = dt_reserve_or_free_quota(env, mdd->mdd_bottom,
						      GRPQUOTA, attr->la_uid,
						      la->la_gid, quota_size,
						      false);

			if (rc) {
				CDEBUG(D_QUOTA, "%s: failed to reserve quota for gid %d size %llu\n",
				       mdd2obd_dev(mdd)->obd_name,
				       la->la_gid, quota_size);

				GOTO(out, rc);
			}

			quota_reserved = true;
			la_copy->la_valid |= LA_FLAGS;
		}

		chrgrp_by_unprivileged_user = true;

		/* Flush the possible existing client setattr requests to OSTs
		 * to keep the order with the current setattr operation that
		 * will be sent directly to OSTs. see LU-5152 */
		/* LU-11303 disable sync as this is too heavyweight.
		 * This should be replaced with a sync only for the object
		 * being modified here, not the whole filesystem.
		rc = dt_sync(env, mdd->mdd_child);
		if (rc)
			GOTO(out, rc);
		 */
	}

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle)) {
		rc = PTR_ERR(handle);
		handle = NULL;

		GOTO(out, rc);
	}

	rc = mdd_declare_attr_set(env, mdd, mdd_obj, la_copy, handle);
	if (rc)
		GOTO(out, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(out, rc);

	if (!chrgrp_by_unprivileged_user && mdd->mdd_sync_permission &&
	    permission_needs_sync(attr, la))
		handle->th_sync = 1;

	if (la->la_valid & (LA_MTIME | LA_CTIME))
		CDEBUG(D_INODE, "setting mtime %llu, ctime %llu\n",
		       la->la_mtime, la->la_ctime);

	mdd_write_lock(env, mdd_obj, DT_TGT_CHILD);

	/* LU-10509: setattr of LA_SIZE should be skipped case of DOM,
	 * otherwise following truncate will do nothing and truncated
	 * data may be read again. This is a quick fix until LU-11033
	 * will be resolved.
	 */
	if (la_copy->la_valid & LA_SIZE) {
		struct lu_buf *lov_buf = mdd_buf_get(env, NULL, 0);

		rc = mdd_stripe_get(env, mdd_obj, lov_buf, XATTR_NAME_LOV);
		if (rc) {
			rc = 0;
		} else {
			if (mdd_lmm_dom_size(lov_buf->lb_buf) > 0)
				la_copy->la_valid &= ~LA_SIZE;
			lu_buf_free(lov_buf);
		}
	}

	if (la_copy->la_valid) {
		rc = mdd_attr_set_internal(env, mdd_obj, la_copy, handle, 1);

		if (rc == -EDQUOT && la_copy->la_flags & LUSTRE_SET_SYNC_FL) {
			/* rollback to the original gid */
			la_copy->la_flags &= ~LUSTRE_SET_SYNC_FL;
			la_copy->la_gid = attr->la_gid;
			mdd_attr_set_internal(env, mdd_obj, la_copy, handle, 1);
		}
	}
	mdd_write_unlock(env, mdd_obj);

out:
	if (rc == 0)
		rc = mdd_attr_set_changelog(env, obj, handle, &ma->ma_pfid,
					    la_copy->la_valid);

	if (rc == 0 && quota_reserved) {
		struct thandle *sub_th;

		sub_th = thandle_get_sub_by_dt(env, handle, mdd->mdd_bottom);
		if (unlikely(IS_ERR(sub_th))) {
			dt_reserve_or_free_quota(env, mdd->mdd_bottom, GRPQUOTA,
						 attr->la_uid, la->la_gid,
						 -quota_size, false);
		} else {
			sub_th->th_reserved_quota.qrr_type = GRPQUOTA;
			sub_th->th_reserved_quota.qrr_id.qid_gid = la->la_gid;
			sub_th->th_reserved_quota.qrr_count = quota_size;
		}
	}

	if (handle != NULL)
		rc = mdd_trans_stop(env, mdd, rc, handle);

	return rc;
}

static int mdd_xattr_sanity_check(const struct lu_env *env,
				  struct mdd_object *obj,
				  const struct lu_attr *attr,
				  const char *name)
{
	struct lu_ucred *uc     = lu_ucred_assert(env);
	ENTRY;

	if (attr->la_flags & (LUSTRE_IMMUTABLE_FL | LUSTRE_APPEND_FL))
		RETURN(-EPERM);

	if (strncmp(XATTR_USER_PREFIX, name,
		    sizeof(XATTR_USER_PREFIX) - 1) == 0) {
		/* For sticky directories, only the owner and privileged user
		 * can write attributes. */
		if (S_ISDIR(attr->la_mode) && (attr->la_mode & S_ISVTX) &&
		    (uc->uc_fsuid != attr->la_uid) &&
		    !cap_raised(uc->uc_cap, CAP_FOWNER))
			RETURN(-EPERM);
	} else if (strcmp(name, XATTR_NAME_SOM) != 0 &&
		   (uc->uc_fsuid != attr->la_uid) &&
		   !cap_raised(uc->uc_cap, CAP_FOWNER)) {
		RETURN(-EPERM);
	}

	RETURN(0);
}

/**
 * Check if a string begins with a given prefix.
 *
 * \param str	  String to check
 * \param prefix  Substring to check at the beginning of \a str
 * \return true/false whether the condition is verified.
 */
static inline bool has_prefix(const char *str, const char *prefix)
{
	return strncmp(prefix, str, strlen(prefix)) == 0;
}

/**
 * Indicate the kind of changelog to store (if any) for a xattr set/del.
 *
 * \param[in]  xattr_name  Full extended attribute name.
 *
 * \return type of changelog to use, or CL_NONE if no changelog is to be emitted
 */
static enum changelog_rec_type
mdd_xattr_changelog_type(const struct lu_env *env, struct mdd_device *mdd,
			 const char *xattr_name)
{
	/* Layout changes systematically recorded */
	if (strcmp(XATTR_NAME_LOV, xattr_name) == 0 ||
	    strcmp(XATTR_LUSTRE_LOV, xattr_name) == 0 ||
	    allowed_lustre_lov(xattr_name))
		return CL_LAYOUT;

	/* HSM information changes systematically recorded */
	if (strcmp(XATTR_NAME_HSM, xattr_name) == 0)
		return CL_HSM;

	/* Avoid logging SOM xattr for every file */
	if (strcmp(XATTR_NAME_SOM, xattr_name) == 0)
		return CL_NONE;

	if (has_prefix(xattr_name, XATTR_USER_PREFIX) ||
	    has_prefix(xattr_name, XATTR_NAME_POSIX_ACL_ACCESS) ||
	    has_prefix(xattr_name, XATTR_NAME_POSIX_ACL_DEFAULT) ||
	    has_prefix(xattr_name, XATTR_TRUSTED_PREFIX) ||
	    has_prefix(xattr_name, XATTR_SECURITY_PREFIX))
		return CL_SETXATTR;

	return CL_NONE;
}

static int mdd_declare_xattr_set(const struct lu_env *env,
				 struct mdd_device *mdd,
				 struct mdd_object *obj,
				 const struct lu_buf *buf,
				 const char *name,
				 int fl, struct thandle *handle)
{
	enum changelog_rec_type type;
	int rc;

	rc = mdo_declare_xattr_set(env, obj, buf, name, fl, handle);
	if (rc)
		return rc;

	type = mdd_xattr_changelog_type(env, mdd, name);
	if (type < 0)
		return 0; /* no changelog to store */

	return mdd_declare_changelog_store(env, mdd, type, NULL, NULL, handle);
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
				 struct thandle *handle,
				 enum changelog_rec_flags *clf_flags)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	struct lu_buf *current_buf;
	struct md_hsm *current_mh;
	struct md_hsm *new_mh;
	int rc;

	ENTRY;
	OBD_ALLOC_PTR(current_mh);
	if (current_mh == NULL)
		RETURN(-ENOMEM);

	/* Read HSM attrs from disk */
	current_buf = lu_buf_check_and_alloc(&info->mdi_xattr_buf,
			min_t(unsigned int,
			      mdd_obj2mdd_dev(mdd_obj)->mdd_dt_conf.ddp_max_ea_size,
			    XATTR_SIZE_MAX));
	rc = mdo_xattr_get(env, mdd_obj, current_buf, XATTR_NAME_HSM);
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

	rc = 0;

	/* Flags differ, set flags for the changelog that will be added */
	if (current_mh->mh_flags != new_mh->mh_flags) {
		hsm_set_cl_event(clf_flags, HE_STATE);
		if (new_mh->mh_flags & HS_DIRTY)
			hsm_set_cl_flags(clf_flags, CLF_HSM_DIRTY);
	}

	OBD_FREE_PTR(new_mh);
	EXIT;
free:
	OBD_FREE_PTR(current_mh);
	return rc;
}

static int mdd_object_pfid_replace(const struct lu_env *env,
				   struct mdd_object *o)
{
	struct mdd_device *mdd = mdo2mdd(&o->mod_obj);
	struct thandle *handle;
	int rc;

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	handle->th_complex = 1;

	/* it doesn't need to track the PFID update via llog, because LFSCK
	 * will repair it even it goes wrong */
	rc = mdd_declare_xattr_set(env, mdd, o, NULL, XATTR_NAME_FID,
				   0, handle);
	if (rc)
		GOTO(out, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc != 0)
		GOTO(out, rc);

	rc = mdo_xattr_set(env, o, NULL, XATTR_NAME_FID, 0, handle);
	if (rc)
		GOTO(out, rc);

out:
	mdd_trans_stop(env, mdd, rc, handle);
	return rc;
}


static int mdd_declare_xattr_del(const struct lu_env *env,
				 struct mdd_device *mdd,
				 struct mdd_object *obj,
				 const char *name,
				 struct thandle *handle);

static int mdd_xattr_del(const struct lu_env *env, struct md_object *obj,
			 const char *name);

static int mdd_xattr_merge(const struct lu_env *env, struct md_object *md_obj,
			   struct md_object *md_vic)
{
	struct mdd_device *mdd = mdo2mdd(md_obj);
	struct mdd_object *obj = md2mdd_obj(md_obj);
	struct mdd_object *vic = md2mdd_obj(md_vic);
	struct lu_buf *buf = &mdd_env_info(env)->mdi_buf[0];
	struct lu_buf *buf_vic = &mdd_env_info(env)->mdi_buf[1];
	struct lov_mds_md *lmm;
	struct thandle *handle;
	int rc, lock_order;
	ENTRY;

	lock_order = lu_fid_cmp(mdd_object_fid(obj), mdd_object_fid(vic));
	if (lock_order == 0) /* same fid */
		RETURN(-EPERM);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	/* get EA of victim file */
	memset(buf_vic, 0, sizeof(*buf_vic));
	rc = mdd_stripe_get(env, vic, buf_vic, XATTR_NAME_LOV);
	if (rc < 0) {
		if (rc == -ENODATA)
			rc = 0;
		GOTO(stop, rc);
	}

	/* parse the layout of victim file */
	lmm = buf_vic->lb_buf;
	if (le32_to_cpu(lmm->lmm_magic) != LOV_MAGIC_COMP_V1)
		GOTO(stop, rc = -EINVAL);

	/* save EA of target file for restore */
	memset(buf, 0, sizeof(*buf));
	rc = mdd_stripe_get(env, obj, buf, XATTR_NAME_LOV);
	if (rc < 0)
		GOTO(stop, rc);

	/* Get rid of the layout from victim object */
	rc = mdd_declare_xattr_del(env, mdd, vic, XATTR_NAME_LOV, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_declare_xattr_set(env, mdd, obj, buf_vic, XATTR_NAME_LOV,
				   LU_XATTR_MERGE, handle);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc != 0)
		GOTO(stop, rc);

	if (lock_order > 0) {
		mdd_write_lock(env, obj, DT_TGT_CHILD);
		mdd_write_lock(env, vic, DT_TGT_CHILD);
	} else {
		mdd_write_lock(env, vic, DT_TGT_CHILD);
		mdd_write_lock(env, obj, DT_TGT_CHILD);
	}

	rc = mdo_xattr_set(env, obj, buf_vic, XATTR_NAME_LOV, LU_XATTR_MERGE,
			   handle);
	if (rc)
		GOTO(out, rc);

	rc = mdo_xattr_del(env, vic, XATTR_NAME_LOV, handle);
	if (rc) /* wtf? */
		GOTO(out_restore, rc);

	(void)mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, obj, handle,
				       NULL);
	(void)mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, vic, handle,
				       NULL);
	EXIT;

out_restore:
	if (rc) {
		int rc2 = mdo_xattr_set(env, obj, buf, XATTR_NAME_LOV,
					LU_XATTR_REPLACE, handle);
		if (rc2)
			CERROR("%s: failed rollback of "DFID" layout: file state unknown: rc = %d\n",
			       mdd_obj_dev_name(obj),
			       PFID(mdd_object_fid(obj)), rc2);
	}

out:
	mdd_write_unlock(env, obj);
	mdd_write_unlock(env, vic);
stop:
	mdd_trans_stop(env, mdd, rc, handle);
	lu_buf_free(buf);
	lu_buf_free(buf_vic);

	if (!rc)
		(void) mdd_object_pfid_replace(env, obj);

	return rc;
}

/**
 * Extract the mirror with specified mirror id, and store the splitted
 * mirror layout to @buf.
 *
 * \param[in] comp_v1	mirrored layout
 * \param[in] mirror_id	the mirror with mirror_id to be extracted
 * \param[out] buf	store the layout excluding the extracted mirror,
 *			caller free the buffer we allocated in this function
 * \param[out] buf_vic	store the extracted layout, caller free the buffer
 *			we allocated in this function
 *
 * \retval	0 on success; < 0 if error happens
 */
static int mdd_split_ea(struct lov_comp_md_v1 *comp_v1, __u16 mirror_id,
			struct lu_buf *buf, struct lu_buf *buf_vic)
{
	struct lov_comp_md_v1 *comp_rem;
	struct lov_comp_md_v1 *comp_vic;
	struct lov_comp_md_entry_v1 *entry;
	struct lov_comp_md_entry_v1 *entry_rem;
	struct lov_comp_md_entry_v1 *entry_vic;
	__u16 mirror_cnt;
	__u16 comp_cnt, count = 0;
	int lmm_size, lmm_size_vic = 0;
	int i, j, k;
	int offset, offset_rem, offset_vic;

	mirror_cnt = le16_to_cpu(comp_v1->lcm_mirror_count) + 1;
	/* comp_v1 should contains more than 1 mirror */
	if (mirror_cnt <= 1)
		return -EINVAL;
	comp_cnt = le16_to_cpu(comp_v1->lcm_entry_count);
	lmm_size = le32_to_cpu(comp_v1->lcm_size);

	for (i = 0; i < comp_cnt; i++) {
		entry = &comp_v1->lcm_entries[i];
		if (mirror_id_of(le32_to_cpu(entry->lcme_id)) == mirror_id) {
			count++;
			lmm_size_vic += sizeof(*entry);
			lmm_size_vic += le32_to_cpu(entry->lcme_size);
		} else if (count > 0) {
			/* find the specified mirror */
			break;
		}
	}

	if (count == 0)
		return -EINVAL;

	lu_buf_alloc(buf, lmm_size - lmm_size_vic);
	if (!buf->lb_buf)
		return -ENOMEM;

	lu_buf_alloc(buf_vic, sizeof(*comp_vic) + lmm_size_vic);
	if (!buf_vic->lb_buf) {
		lu_buf_free(buf);
		return -ENOMEM;
	}

	comp_rem = (struct lov_comp_md_v1 *)buf->lb_buf;
	comp_vic = (struct lov_comp_md_v1 *)buf_vic->lb_buf;

	memcpy(comp_rem, comp_v1, sizeof(*comp_v1));
	comp_rem->lcm_mirror_count = cpu_to_le16(mirror_cnt - 2);
	comp_rem->lcm_entry_count = cpu_to_le32(comp_cnt - count);
	comp_rem->lcm_size = cpu_to_le32(lmm_size - lmm_size_vic);
	if (!comp_rem->lcm_mirror_count)
		comp_rem->lcm_flags = cpu_to_le16(LCM_FL_NONE);

	memset(comp_vic, 0, sizeof(*comp_v1));
	comp_vic->lcm_magic = cpu_to_le32(LOV_MAGIC_COMP_V1);
	comp_vic->lcm_mirror_count = 0;
	comp_vic->lcm_entry_count = cpu_to_le32(count);
	comp_vic->lcm_size = cpu_to_le32(lmm_size_vic + sizeof(*comp_vic));
	comp_vic->lcm_flags = cpu_to_le16(LCM_FL_NONE);
	comp_vic->lcm_layout_gen = 0;

	offset = sizeof(*comp_v1) + sizeof(*entry) * comp_cnt;
	offset_rem = sizeof(*comp_rem) +
		     sizeof(*entry_rem) * (comp_cnt - count);
	offset_vic = sizeof(*comp_vic) + sizeof(*entry_vic) * count;
	for (i = j = k = 0; i < comp_cnt; i++) {
		struct lov_mds_md *lmm, *lmm_dst;
		bool vic = false;

		entry = &comp_v1->lcm_entries[i];
		entry_vic = &comp_vic->lcm_entries[j];
		entry_rem = &comp_rem->lcm_entries[k];

		if (mirror_id_of(le32_to_cpu(entry->lcme_id)) == mirror_id)
			vic = true;

		/* copy component entry */
		if (vic) {
			memcpy(entry_vic, entry, sizeof(*entry));
			entry_vic->lcme_flags &= cpu_to_le32(LCME_FL_INIT);
			entry_vic->lcme_offset = cpu_to_le32(offset_vic);
			j++;
		} else {
			memcpy(entry_rem, entry, sizeof(*entry));
			entry_rem->lcme_offset = cpu_to_le32(offset_rem);
			k++;
		}

		lmm = (struct lov_mds_md *)((char *)comp_v1 + offset);
		if (vic)
			lmm_dst = (struct lov_mds_md *)
					((char *)comp_vic + offset_vic);
		else
			lmm_dst = (struct lov_mds_md *)
					((char *)comp_rem + offset_rem);

		/* copy component entry blob */
		memcpy(lmm_dst, lmm, le32_to_cpu(entry->lcme_size));

		/* blob offset advance */
		offset += le32_to_cpu(entry->lcme_size);
		if (vic)
			offset_vic += le32_to_cpu(entry->lcme_size);
		else
			offset_rem += le32_to_cpu(entry->lcme_size);
	}

	return 0;
}

static int mdd_dom_data_truncate(const struct lu_env *env,
				 struct mdd_device *mdd, struct mdd_object *mo);

static int mdd_xattr_split(const struct lu_env *env, struct md_object *md_obj,
			   struct md_rejig_data *mrd)
{
	struct mdd_device *mdd = mdo2mdd(md_obj);
	struct mdd_object *obj = md2mdd_obj(md_obj);
	struct mdd_object *vic = NULL;
	struct lu_buf *buf = &mdd_env_info(env)->mdi_buf[0];
	struct lu_buf *buf_save = &mdd_env_info(env)->mdi_buf[1];
	struct lu_buf *buf_vic = &mdd_env_info(env)->mdi_buf[2];
	struct lov_comp_md_v1 *lcm;
	struct thandle *handle;
	int rc;
	bool dom_stripe = false;

	ENTRY;

	/**
	 * NULL @mrd_obj means mirror deleting, and use NULL vic to indicate
	 * mirror deleting
	 */
	if (mrd->mrd_obj)
		vic = md2mdd_obj(mrd->mrd_obj);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	/* get EA of mirrored file */
	memset(buf_save, 0, sizeof(*buf));
	rc = mdd_stripe_get(env, obj, buf_save, XATTR_NAME_LOV);
	if (rc < 0)
		GOTO(stop, rc);

	lcm = buf_save->lb_buf;
	if (le32_to_cpu(lcm->lcm_magic) != LOV_MAGIC_COMP_V1)
		GOTO(stop, rc = -EINVAL);

	/**
	 * Extract the mirror with specified mirror id, and store the splitted
	 * mirror layout to the victim buffer.
	 */
	memset(buf, 0, sizeof(*buf));
	memset(buf_vic, 0, sizeof(*buf_vic));
	rc = mdd_split_ea(lcm, mrd->mrd_mirror_id, buf, buf_vic);
	if (rc < 0)
		GOTO(stop, rc);
	/**
	 * @buf stores layout w/o the specified mirror, @buf_vic stores the
	 * splitted mirror
	 */

	dom_stripe = mdd_lmm_dom_size(buf_vic->lb_buf) > 0;

	if (vic) {
		/**
		 * non delete mirror split
		 *
		 * declare obj set remaining layout in @buf, will set obj's
		 * in-memory layout
		 */
		rc = mdd_declare_xattr_set(env, mdd, obj, buf, XATTR_NAME_LOV,
					   LU_XATTR_SPLIT, handle);
		if (rc)
			GOTO(stop, rc);

		/* declare vic set splitted layout in @buf_vic */
		rc = mdd_declare_xattr_set(env, mdd, vic, buf_vic,
					   XATTR_NAME_LOV, LU_XATTR_SPLIT,
					   handle);
		if (rc)
			GOTO(stop, rc);
	} else {
		/**
		 * declare delete mirror objects in @buf_vic, will change obj's
		 * in-memory layout
		 */
		rc = mdd_declare_xattr_set(env, mdd, obj, buf_vic,
					   XATTR_NAME_LOV, LU_XATTR_PURGE,
					   handle);
		if (rc)
			GOTO(stop, rc);

		/* declare obj set remaining layout in @buf */
		rc = mdd_declare_xattr_set(env, mdd, obj, buf,
					   XATTR_NAME_LOV, LU_XATTR_SPLIT,
					   handle);
		if (rc)
			GOTO(stop, rc);
	}

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(stop, rc);

	if (vic) {
		/* don't use the same file to save the splitted mirror */
		rc = lu_fid_cmp(mdd_object_fid(obj), mdd_object_fid(vic));
		if (rc == 0)
			GOTO(stop, rc = -EPERM);

		if (rc > 0) {
			mdd_write_lock(env, obj, DT_TGT_CHILD);
			mdd_write_lock(env, vic, DT_TGT_CHILD);
		} else {
			mdd_write_lock(env, vic, DT_TGT_CHILD);
			mdd_write_lock(env, obj, DT_TGT_CHILD);
		}
	} else {
		mdd_write_lock(env, obj, DT_TGT_CHILD);
	}

	/* set obj's layout in @buf */
	rc = mdo_xattr_set(env, obj, buf, XATTR_NAME_LOV, LU_XATTR_SPLIT,
			   handle);
	if (rc)
		GOTO(unlock, rc);

	if (vic) {
		/* set vic's layout in @buf_vic */
		rc = mdo_xattr_set(env, vic, buf_vic, XATTR_NAME_LOV,
				   LU_XATTR_CREATE, handle);
		if (rc)
			GOTO(out_restore, rc);
	} else {
		/* delete mirror objects */
		rc = mdo_xattr_set(env, obj, buf_vic, XATTR_NAME_LOV,
				   LU_XATTR_PURGE, handle);
		if (rc)
			GOTO(out_restore, rc);
	}

	rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, obj, handle,
				      NULL);
	if (rc)
		GOTO(out_restore, rc);

	if (vic) {
		rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, vic,
					      handle, NULL);
		if (rc)
			GOTO(out_restore, rc);
	}

out_restore:
	if (rc) {
		/* restore obj's in-memory and on-disk layout */
		int rc2 = mdo_xattr_set(env, obj, buf_save, XATTR_NAME_LOV,
					LU_XATTR_REPLACE, handle);
		if (rc2)
			CERROR("%s: failed rollback "DFID
			       " layout: file state unknown: rc = %d\n",
			       mdd_obj_dev_name(obj),
			       PFID(mdd_object_fid(obj)), rc);
	}

unlock:
	mdd_write_unlock(env, obj);
	if (vic)
		mdd_write_unlock(env, vic);
stop:
	rc = mdd_trans_stop(env, mdd, rc, handle);

	/* Truncate local DOM data if all went well */
	if (!rc && dom_stripe)
		mdd_dom_data_truncate(env, mdd, obj);

	lu_buf_free(buf_save);
	lu_buf_free(buf);
	lu_buf_free(buf_vic);

	if (!rc)
		(void) mdd_object_pfid_replace(env, obj);

	return rc;
}

static int mdd_layout_merge_allowed(const struct lu_env *env,
				    struct md_object *target,
				    struct md_object *victim)
{
	struct mdd_object *o1 = md2mdd_obj(target);

	/* cannot extend directory's LOVEA */
	if (S_ISDIR(mdd_object_type(o1))) {
		CERROR("%s: Don't extend directory's LOVEA, just set it.\n",
		       mdd_obj_dev_name(o1));
		RETURN(-EISDIR);
	}

	RETURN(0);
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
	struct lu_attr *attr = MDD_ENV_VAR(env, cattr);
	struct mdd_device *mdd = mdo2mdd(obj);
	struct thandle *handle;
	enum changelog_rec_type	 cl_type;
	enum changelog_rec_flags clf_flags = 0;
	int rc;
	ENTRY;

	rc = mdd_la_get(env, mdd_obj, attr);
	if (rc)
		RETURN(rc);

	rc = mdd_xattr_sanity_check(env, mdd_obj, attr, name);
	if (rc)
		RETURN(rc);

	if (strcmp(name, XATTR_LUSTRE_LOV) == 0 &&
	    (fl == LU_XATTR_MERGE || fl == LU_XATTR_SPLIT)) {
		struct md_rejig_data *mrd = buf->lb_buf;
		struct md_object *victim = mrd->mrd_obj;

		if (buf->lb_len != sizeof(*mrd))
			RETURN(-EINVAL);


		if (fl == LU_XATTR_MERGE) {
			rc = mdd_layout_merge_allowed(env, obj, victim);
			if (rc)
				RETURN(rc);
			/* merge layout of victim as a mirror of obj's. */
			rc = mdd_xattr_merge(env, obj, victim);
		} else {
			rc = mdd_xattr_split(env, obj, mrd);
		}
		RETURN(rc);
	}

	if (strcmp(name, XATTR_NAME_ACL_ACCESS) == 0 ||
	    strcmp(name, XATTR_NAME_ACL_DEFAULT) == 0) {
		struct posix_acl *acl;

		/* user may set empty ACL, which should be treated as removing
		 * ACL. */
		acl = posix_acl_from_xattr(&init_user_ns, buf->lb_buf,
					   buf->lb_len);
		if (IS_ERR(acl))
			RETURN(PTR_ERR(acl));
		if (acl == NULL) {
			rc = mdd_xattr_del(env, obj, name);
			RETURN(rc);
		}
		posix_acl_release(acl);
	}

	if (!strcmp(name, XATTR_NAME_ACL_ACCESS)) {
		rc = mdd_acl_set(env, mdd_obj, attr, buf, fl);
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

	mdd_write_lock(env, mdd_obj, DT_TGT_CHILD);

	if (strcmp(XATTR_NAME_HSM, name) == 0) {
		rc = mdd_hsm_update_locked(env, obj, buf, handle, &clf_flags);
		if (rc) {
			mdd_write_unlock(env, mdd_obj);
			GOTO(stop, rc);
		}
	}

	rc = mdo_xattr_set(env, mdd_obj, buf, name, fl, handle);
	mdd_write_unlock(env, mdd_obj);
	if (rc)
		GOTO(stop, rc);

	cl_type = mdd_xattr_changelog_type(env, mdd, name);
	if (cl_type < 0)
		GOTO(stop, rc = 0);

	rc = mdd_changelog_data_store_xattr(env, mdd, cl_type, clf_flags,
					    mdd_obj, name, handle);

	EXIT;
stop:
	return mdd_trans_stop(env, mdd, rc, handle);
}

static int mdd_declare_xattr_del(const struct lu_env *env,
                                 struct mdd_device *mdd,
                                 struct mdd_object *obj,
                                 const char *name,
                                 struct thandle *handle)
{
	enum changelog_rec_type type;
	int rc;

	rc = mdo_declare_xattr_del(env, obj, name, handle);
	if (rc)
		return rc;

	type = mdd_xattr_changelog_type(env, mdd, name);
	if (type < 0)
		return 0; /* no changelog to store */

	return mdd_declare_changelog_store(env, mdd, type, NULL, NULL, handle);
}

/**
 * The caller should guarantee to update the object ctime
 * after xattr_set if needed.
 */
static int mdd_xattr_del(const struct lu_env *env, struct md_object *obj,
			 const char *name)
{
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	struct lu_attr *attr = MDD_ENV_VAR(env, cattr);
	struct mdd_device *mdd = mdo2mdd(obj);
	struct thandle *handle;
	int rc;
	ENTRY;

	rc = mdd_la_get(env, mdd_obj, attr);
	if (rc)
		RETURN(rc);

	rc = mdd_xattr_sanity_check(env, mdd_obj, attr, name);
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

	mdd_write_lock(env, mdd_obj, DT_TGT_CHILD);
	rc = mdo_xattr_del(env, mdd_obj, name, handle);
	mdd_write_unlock(env, mdd_obj);
	if (rc)
		GOTO(stop, rc);

	if (mdd_xattr_changelog_type(env, mdd, name) < 0)
		GOTO(stop, rc = 0);

	rc = mdd_changelog_data_store_xattr(env, mdd, CL_SETXATTR, 0, mdd_obj,
					    name, handle);

	EXIT;
stop:
	return mdd_trans_stop(env, mdd, rc, handle);
}

/*
 * read lov/lmv EA of an object
 * return the lov/lmv EA in an allocated lu_buf
 */
int mdd_stripe_get(const struct lu_env *env, struct mdd_object *obj,
		   struct lu_buf *lmm_buf, const char *name)
{
	struct lu_buf *buf = &mdd_env_info(env)->mdi_big_buf;
	int rc;

	ENTRY;

	if (buf->lb_buf == NULL) {
		buf = lu_buf_check_and_alloc(buf, 4096);
		if (buf->lb_buf == NULL)
			RETURN(-ENOMEM);
	}

repeat:
	rc = mdo_xattr_get(env, obj, buf, name);
	if (rc == -ERANGE) {
		/* mdi_big_buf is allocated but is too small
		 * we need to increase it */
		buf = lu_buf_check_and_alloc(&mdd_env_info(env)->mdi_big_buf,
					     buf->lb_len * 2);
		if (buf->lb_buf == NULL)
			RETURN(-ENOMEM);
		goto repeat;
	} else if (rc < 0) {
		RETURN(rc);
	} else if (rc == 0) {
		RETURN(-ENODATA);
	}

	lu_buf_alloc(lmm_buf, rc);
	if (lmm_buf->lb_buf == NULL)
		RETURN(-ENOMEM);

	/*
	 * we don't use lmm_buf directly, because we don't know xattr size, so
	 * by using mdi_big_buf we can avoid calling mdo_xattr_get() twice.
	 */
	memcpy(lmm_buf->lb_buf, buf->lb_buf, rc);

	RETURN(0);
}

static int mdd_xattr_hsm_replace(const struct lu_env *env,
				 struct mdd_object *o, struct lu_buf *buf,
				 struct thandle *handle)
{
	struct hsm_attrs *attrs;
	enum hsm_states hsm_flags;
	enum changelog_rec_flags clf_flags = 0;
	int rc;
	ENTRY;

	rc = mdo_xattr_set(env, o, buf, XATTR_NAME_HSM, LU_XATTR_REPLACE,
			   handle);
	if (rc != 0)
		RETURN(rc);

	attrs = buf->lb_buf;
	hsm_flags = le32_to_cpu(attrs->hsm_flags);
	if (!(hsm_flags & HS_RELEASED) || mdd_is_dead_obj(o))
		RETURN(0);

	/* Add a changelog record for release. */
	hsm_set_cl_event(&clf_flags, HE_RELEASE);
	rc = mdd_changelog_data_store(env, mdo2mdd(&o->mod_obj), CL_HSM,
				      clf_flags, o, handle, NULL);
	RETURN(rc);
}

/*
 *  check if layout swapping between 2 objects is allowed
 *  the rules are:
 *  - only normal FIDs or non-system IGIFs
 *  - same type of objects
 *  - same owner/group (so quotas are still valid) unless this is from HSM
 *    release.
 */
static int mdd_layout_swap_allowed(const struct lu_env *env,
				   struct mdd_object *o1,
				   const struct lu_attr *attr1,
				   struct mdd_object *o2,
				   const struct lu_attr *attr2,
				   __u64 flags)
{
	const struct lu_fid *fid1, *fid2;
	ENTRY;

	fid1 = mdd_object_fid(o1);
	fid2 = mdd_object_fid(o2);

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

	if (flags & SWAP_LAYOUTS_MDS_HSM)
		RETURN(0);

	if ((attr1->la_uid != attr2->la_uid) ||
	    (attr1->la_gid != attr2->la_gid))
		RETURN(-EPERM);

	RETURN(0);
}

/* XXX To set the proper lmm_oi & lmm_layout_gen when swap layouts, we have to
 *     look into the layout in MDD layer. */
static int mdd_lmm_oi(struct lov_mds_md *lmm, struct ost_id *oi, bool get)
{
	struct lov_comp_md_v1	*comp_v1;
	struct lov_mds_md	*v1;
	int			 i, ent_count;
	__u32			 off;

	if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)lmm;
		ent_count = le16_to_cpu(comp_v1->lcm_entry_count);

		if (ent_count == 0)
			return -EINVAL;

		if (get) {
			off = le32_to_cpu(comp_v1->lcm_entries[0].lcme_offset);
			v1 = (struct lov_mds_md *)((char *)comp_v1 + off);
			*oi = v1->lmm_oi;
		} else {
			for (i = 0; i < le32_to_cpu(ent_count); i++) {
				off = le32_to_cpu(comp_v1->lcm_entries[i].
						lcme_offset);
				v1 = (struct lov_mds_md *)((char *)comp_v1 +
						off);
				v1->lmm_oi = *oi;
			}
		}
	} else if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_V1 ||
		   le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_V3) {
		if (get)
			*oi = lmm->lmm_oi;
		else
			lmm->lmm_oi = *oi;
	} else {
		return -EINVAL;
	}
	return 0;
}

static inline int mdd_get_lmm_oi(struct lov_mds_md *lmm, struct ost_id *oi)
{
	return mdd_lmm_oi(lmm, oi, true);
}

static inline int mdd_set_lmm_oi(struct lov_mds_md *lmm, struct ost_id *oi)
{
	return mdd_lmm_oi(lmm, oi, false);
}

static int mdd_lmm_gen(struct lov_mds_md *lmm, __u32 *gen, bool get)
{
	struct lov_comp_md_v1 *comp_v1;

	if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)lmm;
		if (get)
			*gen = le32_to_cpu(comp_v1->lcm_layout_gen);
		else
			comp_v1->lcm_layout_gen = cpu_to_le32(*gen);
	} else if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_V1 ||
		   le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_V3) {
		__u16 tmp_gen = *gen;
		if (get)
			*gen = le16_to_cpu(lmm->lmm_layout_gen);
		else
			lmm->lmm_layout_gen = cpu_to_le16(tmp_gen);
	} else {
		return -EINVAL;
	}
	return 0;
}

static inline int mdd_get_lmm_gen(struct lov_mds_md *lmm, __u32 *gen)
{
	return mdd_lmm_gen(lmm, gen, true);
}

static inline int mdd_set_lmm_gen(struct lov_mds_md *lmm, __u32 *gen)
{
	return mdd_lmm_gen(lmm, gen, false);
}

static int mdd_dom_data_truncate(const struct lu_env *env,
				 struct mdd_device *mdd, struct mdd_object *mo)
{
	struct thandle *th;
	struct dt_object *dom;
	int rc;

	dom = dt_object_locate(mdd_object_child(mo), mdd->mdd_bottom);
	if (!dom)
		GOTO(out, rc = -ENODATA);

	th = dt_trans_create(env, mdd->mdd_bottom);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_punch(env, dom, 0, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, mdd->mdd_bottom, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_punch(env, dom, 0, OBD_OBJECT_EOF, th);
stop:
	dt_trans_stop(env, mdd->mdd_bottom, th);
out:
	/* Ignore failure but report the error */
	if (rc)
		CERROR("%s: can't truncate DOM inode "DFID" data: rc = %d\n",
		       mdd_obj_dev_name(mo), PFID(mdd_object_fid(mo)), rc);
	return rc;
}

/**
 * swap layouts between 2 lustre objects
 */
static int mdd_swap_layouts(const struct lu_env *env, struct md_object *obj1,
			    struct md_object *obj2, __u64 flags)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	struct mdd_object *fst_o = md2mdd_obj(obj1);
	struct mdd_object *snd_o = md2mdd_obj(obj2);
	struct lu_attr *fst_la = MDD_ENV_VAR(env, cattr);
	struct lu_attr *snd_la = MDD_ENV_VAR(env, tattr);
	struct mdd_device *mdd = mdo2mdd(obj1);
	struct lov_mds_md *fst_lmm, *snd_lmm;
	struct lu_buf *fst_buf = &info->mdi_buf[0];
	struct lu_buf *snd_buf = &info->mdi_buf[1];
	struct lu_buf *fst_hsm_buf = &info->mdi_buf[2];
	struct lu_buf *snd_hsm_buf = &info->mdi_buf[3];
	struct ost_id *saved_oi = NULL;
	struct thandle *handle;
	struct mdd_object *dom_o = NULL;
	__u64 domsize_dom, domsize_vlt;
	__u32 fst_gen, snd_gen, saved_gen;
	int fst_fl;
	int rc, rc2;

	ENTRY;

	BUILD_BUG_ON(ARRAY_SIZE(info->mdi_buf) < 4);
	memset(info->mdi_buf, 0, sizeof(info->mdi_buf));

	/* we have to sort the 2 obj, so locking will always
	 * be in the same order, even in case of 2 concurrent swaps */
	rc = lu_fid_cmp(mdd_object_fid(fst_o), mdd_object_fid(snd_o));
	if (rc == 0) /* same fid ? */
		RETURN(-EPERM);

	if (rc < 0)
		swap(fst_o, snd_o);

	rc = mdd_la_get(env, fst_o, fst_la);
	if (rc != 0)
		RETURN(rc);

	rc = mdd_la_get(env, snd_o, snd_la);
	if (rc != 0)
		RETURN(rc);

	/* check if layout swapping is allowed */
	rc = mdd_layout_swap_allowed(env, fst_o, fst_la, snd_o, snd_la, flags);
	if (rc != 0)
		RETURN(rc);

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	/* objects are already sorted */
	mdd_write_lock(env, fst_o, DT_TGT_CHILD);
	mdd_write_lock(env, snd_o, DT_TGT_CHILD);

	rc = mdd_stripe_get(env, fst_o, fst_buf, XATTR_NAME_LOV);
	if (rc < 0 && rc != -ENODATA)
		GOTO(stop, rc);

	rc = mdd_stripe_get(env, snd_o, snd_buf, XATTR_NAME_LOV);
	if (rc < 0 && rc != -ENODATA)
		GOTO(stop, rc);

	/* check if file has DoM. DoM file can be migrated only to another
	 * DoM layout with the same DoM component size or to an non-DOM
	 * layout. After migration to OSTs layout, local MDT inode data
	 * should be truncated.
	 * Objects are sorted by FIDs, considering that original file's FID
	 * is always smaller the snd_o is always original file we are migrating
	 * from.
	 */
	domsize_dom = mdd_lmm_dom_size(snd_buf->lb_buf);
	domsize_vlt = mdd_lmm_dom_size(fst_buf->lb_buf);

	/* Only migration is supported for DoM files, not 'swap_layouts' so
	 * target file must be volatile and orphan.
	 */
	if (fst_o->mod_flags & (ORPHAN_OBJ | VOLATILE_OBJ)) {
		dom_o = domsize_dom ? snd_o : NULL;
	} else if (snd_o->mod_flags & (ORPHAN_OBJ | VOLATILE_OBJ)) {
		swap(domsize_dom, domsize_vlt);
		dom_o = domsize_dom ? fst_o : NULL;
	} else if (domsize_dom > 0 || domsize_vlt > 0) {
		/* 'lfs swap_layouts' case, neither file should have DoM */
		rc = -EOPNOTSUPP;
		CDEBUG(D_LAYOUT, "cannot swap layouts with DOM component, "
		       "use migration instead: rc = %d\n", rc);
		GOTO(stop, rc);
	}

	if (domsize_vlt > 0 && domsize_dom == 0) {
		rc = -EOPNOTSUPP;
		CDEBUG(D_LAYOUT,
		       "%s: cannot swap "DFID" layout: OST to DOM migration not supported: rc = %d\n",
		       mdd_obj_dev_name(snd_o),
		       PFID(mdd_object_fid(snd_o)), rc);
		GOTO(stop, rc);
	} else if (domsize_vlt > 0 && domsize_dom != domsize_vlt) {
		rc = -EOPNOTSUPP;
		CDEBUG(D_LAYOUT,
		       "%s: cannot swap "DFID" layout: new layout must have same DoM component size: rc = %d\n",
		       mdd_obj_dev_name(fst_o),
		       PFID(mdd_object_fid(fst_o)), rc);
		GOTO(stop, rc);
	} else if (domsize_vlt > 0) {
		/* Migration with the same DOM component size, no need to
		 * truncate local data, it is still being used */
		dom_o = NULL;
	}

	/* swapping 2 non existant layouts is a success */
	if (fst_buf->lb_buf == NULL && snd_buf->lb_buf == NULL)
		GOTO(stop, rc = 0);

	/* to help inode migration between MDT, it is better to
	 * start by the no layout file (if one), so we order the swap */
	if (snd_buf->lb_buf == NULL) {
		swap(fst_o, snd_o);
		swap(fst_buf, snd_buf);
	}

	fst_gen = snd_gen = 0;
	/* lmm and generation layout initialization */
	if (fst_buf->lb_buf != NULL) {
		fst_lmm = fst_buf->lb_buf;
		mdd_get_lmm_gen(fst_lmm, &fst_gen);
		fst_fl  = LU_XATTR_REPLACE;
	} else {
		fst_lmm = NULL;
		fst_gen = 0;
		fst_fl  = LU_XATTR_CREATE;
	}

	snd_lmm = snd_buf->lb_buf;
	mdd_get_lmm_gen(snd_lmm, &snd_gen);

	saved_gen = fst_gen;
	/* increase the generation layout numbers */
	snd_gen++;
	fst_gen++;

	/*
	 * XXX The layout generation is used to generate component IDs for
	 *     the composite file, we have to do some special tweaks to make
	 *     sure the layout generation is always adequate for that job.
	 */

	/* Skip invalid generation number for composite layout */
	if ((snd_gen & LCME_ID_MASK) == 0)
		snd_gen++;
	if ((fst_gen & LCME_ID_MASK) == 0)
		fst_gen++;
	/* Make sure the generation is greater than all the component IDs */
	if (fst_gen < snd_gen)
		fst_gen = snd_gen;
	else if (fst_gen > snd_gen)
		snd_gen = fst_gen;

	/* set the file specific informations in lmm */
	if (fst_lmm != NULL) {
		struct ost_id temp_oi;

		saved_oi = &info->mdi_oa.o_oi;
		mdd_get_lmm_oi(fst_lmm, saved_oi);
		mdd_get_lmm_oi(snd_lmm, &temp_oi);
		mdd_set_lmm_gen(fst_lmm, &snd_gen);
		mdd_set_lmm_oi(fst_lmm, &temp_oi);
		mdd_set_lmm_oi(snd_lmm, saved_oi);
	} else {
		if ((snd_lmm->lmm_magic & cpu_to_le32(LOV_MAGIC_MASK)) ==
		    cpu_to_le32(LOV_MAGIC_MAGIC))
			snd_lmm->lmm_magic |= cpu_to_le32(LOV_MAGIC_DEFINED);
		else
			GOTO(stop, rc = -EPROTO);
	}
	mdd_set_lmm_gen(snd_lmm, &fst_gen);

	/* Prepare HSM attribute if it's required */
	if (flags & SWAP_LAYOUTS_MDS_HSM) {
		const int buflen = sizeof(struct hsm_attrs);

		lu_buf_alloc(fst_hsm_buf, buflen);
		lu_buf_alloc(snd_hsm_buf, buflen);
		if (fst_hsm_buf->lb_buf == NULL || snd_hsm_buf->lb_buf == NULL)
			GOTO(stop, rc = -ENOMEM);

		/* Read HSM attribute */
		rc = mdo_xattr_get(env, fst_o, fst_hsm_buf, XATTR_NAME_HSM);
		if (rc < 0)
			GOTO(stop, rc);

		rc = mdo_xattr_get(env, snd_o, snd_hsm_buf, XATTR_NAME_HSM);
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
				CERROR("%s: HSM error restoring "DFID": rc = %d/%d\n",
				       mdd_obj_dev_name(fst_o),
				       PFID(mdd_object_fid(fst_o)), rc, rc2);
			GOTO(stop, rc);
		}
	}

	rc = mdo_xattr_set(env, fst_o, snd_buf, XATTR_NAME_LOV, fst_fl, handle);
	if (rc != 0)
		GOTO(stop, rc);

	if (unlikely(OBD_FAIL_CHECK(OBD_FAIL_MDS_HSM_SWAP_LAYOUTS))) {
		rc = -EOPNOTSUPP;
	} else {
		if (fst_buf->lb_buf != NULL)
			rc = mdo_xattr_set(env, snd_o, fst_buf, XATTR_NAME_LOV,
					   LU_XATTR_REPLACE, handle);
		else
			rc = mdo_xattr_del(env, snd_o, XATTR_NAME_LOV, handle);
	}
	if (rc != 0)
		GOTO(out_restore, rc);

	/* Issue one changelog record per file */
	rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, fst_o, handle,
				      NULL);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, snd_o, handle,
				      NULL);
	if (rc)
		GOTO(stop, rc);
	EXIT;

out_restore:
	if (rc != 0) {
		int steps = 0;

		/* failure on second file, but first was done, so we have
		 * to roll back first. */
		if (fst_buf->lb_buf != NULL) {
			mdd_set_lmm_oi(fst_lmm, saved_oi);
			mdd_set_lmm_gen(fst_lmm, &saved_gen);
			rc2 = mdo_xattr_set(env, fst_o, fst_buf, XATTR_NAME_LOV,
					    LU_XATTR_REPLACE, handle);
		} else {
			rc2 = mdo_xattr_del(env, fst_o, XATTR_NAME_LOV, handle);
		}
		if (rc2 < 0)
			goto do_lbug;

		if (flags & SWAP_LAYOUTS_MDS_HSM) {
			++steps;
			rc2 = mdd_xattr_hsm_replace(env, fst_o, fst_hsm_buf,
						    handle);
			if (rc2 < 0)
				goto do_lbug;

			++steps;
			rc2 = mdd_xattr_hsm_replace(env, snd_o, snd_hsm_buf,
						    handle);
		}

	do_lbug:
		if (rc2 < 0) {
			/* very bad day */
			CERROR("%s: unable to roll back layout swap of "DFID" and "DFID", steps: %d: rc = %d/%d\n",
			       mdd_obj_dev_name(fst_o),
			       PFID(mdd_object_fid(snd_o)),
			       PFID(mdd_object_fid(fst_o)),
			       rc, rc2, steps);
			/* a solution to avoid journal commit is to panic,
			 * but it has strong consequences so we use LBUG to
			 * allow sysdamin to choose to panic or not
			 */
			LBUG();
		}
	}

stop:
	rc = mdd_trans_stop(env, mdd, rc, handle);

	/* Truncate local DOM data if all went well */
	if (!rc && dom_o)
		mdd_dom_data_truncate(env, mdd, dom_o);

	mdd_write_unlock(env, snd_o);
	mdd_write_unlock(env, fst_o);

	lu_buf_free(fst_buf);
	lu_buf_free(snd_buf);
	lu_buf_free(fst_hsm_buf);
	lu_buf_free(snd_hsm_buf);

	if (!rc) {
		(void) mdd_object_pfid_replace(env, fst_o);
		(void) mdd_object_pfid_replace(env, snd_o);
	}
	return rc;
}

static int mdd_declare_layout_change(const struct lu_env *env,
				     struct mdd_device *mdd,
				     struct mdd_object *obj,
				     struct md_layout_change *mlc,
				     struct thandle *handle)
{
	int rc;

	rc = mdo_declare_layout_change(env, obj, mlc, handle);
	if (rc)
		return rc;

	return mdd_declare_changelog_store(env, mdd, CL_LAYOUT, NULL, NULL,
					   handle);
}

/* For PFL, this is used to instantiate necessary component objects. */
static int
mdd_layout_instantiate_component(const struct lu_env *env,
		struct mdd_object *obj, struct md_layout_change *mlc,
		struct thandle *handle)
{
	struct mdd_device *mdd = mdd_obj2mdd_dev(obj);
	int rc;
	ENTRY;

	if (mlc->mlc_opc != MD_LAYOUT_WRITE)
		RETURN(-ENOTSUPP);

	rc = mdd_declare_layout_change(env, mdd, obj, mlc, handle);
	/**
	 * It's possible that another layout write intent has already
	 * instantiated our objects, so a -EALREADY returned, and we need to
	 * do nothing.
	 */
	if (rc)
		RETURN(rc == -EALREADY ? 0 : rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		RETURN(rc);

	mdd_write_lock(env, obj, DT_TGT_CHILD);
	rc = mdo_layout_change(env, obj, mlc, handle);
	mdd_write_unlock(env, obj);
	if (rc)
		RETURN(rc);

	rc = mdd_changelog_data_store(env, mdd, CL_LAYOUT, 0, obj, handle,
				      NULL);
	RETURN(rc);
}

/**
 * Change the FLR layout from RDONLY to WRITE_PENDING.
 *
 * It picks the primary mirror, and bumps the layout version, and set
 * layout version xattr to OST objects in a sync tx. In order to facilitate
 * the handling of phantom writers from evicted clients, the clients carry
 * layout version of the file with write RPC, so that the OSTs can verify
 * if the write RPCs are legitimate, meaning not from evicted clients.
 */
static int
mdd_layout_update_rdonly(const struct lu_env *env, struct mdd_object *obj,
			 struct md_layout_change *mlc, struct thandle *handle)
{
	struct mdd_device *mdd = mdd_obj2mdd_dev(obj);
	struct lu_buf *som_buf = &mdd_env_info(env)->mdi_buf[1];
	struct lustre_som_attrs *som = &mlc->mlc_som;
	int fl = 0;
	int rc;
	ENTRY;

	/* Verify acceptable operations */
	switch (mlc->mlc_opc) {
	case MD_LAYOUT_WRITE:
	case MD_LAYOUT_RESYNC:
		/* these are legal operations - this represents the case that
		 * a few mirrors were missed in the last resync. */
		break;
	case MD_LAYOUT_RESYNC_DONE:
	default:
		RETURN(0);
	}

	som_buf->lb_buf = som;
	som_buf->lb_len = sizeof(*som);
	rc = mdo_xattr_get(env, obj, som_buf, XATTR_NAME_SOM);
	if (rc < 0 && rc != -ENODATA)
		RETURN(rc);

	if (rc > 0) {
		lustre_som_swab(som);
		if (som->lsa_valid & SOM_FL_STRICT)
			fl = LU_XATTR_REPLACE;

		if (mlc->mlc_opc == MD_LAYOUT_WRITE &&
		    mlc->mlc_intent->li_extent.e_end > som->lsa_size) {
			som->lsa_size = mlc->mlc_intent->li_extent.e_end + 1;
			fl = LU_XATTR_REPLACE;
		}
	}

	rc = mdd_declare_layout_change(env, mdd, obj, mlc, handle);
	if (rc)
		GOTO(out, rc);

	if (fl) {
		rc = mdd_declare_xattr_set(env, mdd, obj, som_buf,
					   XATTR_NAME_SOM, fl, handle);
		if (rc)
			GOTO(out, rc);
	}

	/* record a changelog for data mover to consume */
	rc = mdd_declare_changelog_store(env, mdd, CL_FLRW, NULL, NULL, handle);
	if (rc)
		GOTO(out, rc);

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(out, rc);

	/* it needs a sync tx to make FLR to work properly */
	handle->th_sync = 1;

	mdd_write_lock(env, obj, DT_TGT_CHILD);
	rc = mdo_layout_change(env, obj, mlc, handle);
	if (!rc && fl) {
		/* SOM state transition from STRICT to STALE */
		som->lsa_valid = SOM_FL_STALE;
		lustre_som_swab(som);
		rc = mdo_xattr_set(env, obj, som_buf, XATTR_NAME_SOM,
				   fl, handle);
	}
	mdd_write_unlock(env, obj);
	if (rc)
		GOTO(out, rc);

	rc = mdd_changelog_data_store(env, mdd, CL_FLRW, 0, obj, handle, NULL);
	if (rc)
		GOTO(out, rc);

	EXIT;

out:
	return rc;
}

/**
 * Handle mirrored file state transition when it's in WRITE_PENDING.
 *
 * Only MD_LAYOUT_RESYNC, which represents start of resync, is allowed when
 * the file is in WRITE_PENDING state. If everything goes fine, the file's
 * layout version will be increased, and the file's state will be changed to
 * SYNC_PENDING.
 */
static int
mdd_layout_update_write_pending(const struct lu_env *env,
		struct mdd_object *obj, struct md_layout_change *mlc,
		struct thandle *handle)
{
	struct mdd_device *mdd = mdd_obj2mdd_dev(obj);
	struct lu_buf *som_buf = &mdd_env_info(env)->mdi_buf[1];
	struct lustre_som_attrs *som = &mlc->mlc_som;
	int fl = 0;
	int rc;
	ENTRY;

	switch (mlc->mlc_opc) {
	case MD_LAYOUT_RESYNC:
		/* Upon receiving the resync request, it should
		 * instantiate all stale components right away to get ready
		 * for mirror copy. In order to avoid layout version change,
		 * client should avoid sending LAYOUT_WRITE request at the
		 * resync state. */
		break;
	case MD_LAYOUT_WRITE:
		/**
		 * legal race for concurrent write, the file state has been
		 * changed by another client. Or a jump over file size and
		 * write.
		 */
		som_buf->lb_buf = som;
		som_buf->lb_len = sizeof(*som);
		rc = mdo_xattr_get(env, obj, som_buf, XATTR_NAME_SOM);
		if (rc < 0 && rc != -ENODATA)
			RETURN(rc);

		if (rc > 0) {
			lustre_som_swab(som);
			if (mlc->mlc_intent->li_extent.e_end > som->lsa_size) {
				som->lsa_size =
					mlc->mlc_intent->li_extent.e_end + 1;
				fl = LU_XATTR_REPLACE;
			}
		}
		break;
	default:
		RETURN(-EBUSY);
	}

	rc = mdd_declare_layout_change(env, mdd, obj, mlc, handle);
	if (rc)
		GOTO(out, rc);

	if (fl) {
		rc = mdd_declare_xattr_set(env, mdd, obj, som_buf,
					   XATTR_NAME_SOM, fl, handle);
		if (rc)
			GOTO(out, rc);
	}

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(out, rc);

	/* it needs a sync tx to make FLR to work properly */
	handle->th_sync = 1;

	mdd_write_lock(env, obj, DT_TGT_CHILD);
	rc = mdo_layout_change(env, obj, mlc, handle);
	if (!rc && fl) {
		som->lsa_valid = SOM_FL_STALE;
		lustre_som_swab(som);
		rc = mdo_xattr_set(env, obj, som_buf, XATTR_NAME_SOM,
				   fl, handle);
	}
	mdd_write_unlock(env, obj);
	if (rc)
		GOTO(out, rc);

	EXIT;

out:
	return rc;
}

/**
 * Handle the requests when a FLR file's state is in SYNC_PENDING.
 *
 * Only concurrent write and sync complete requests are possible when the
 * file is in SYNC_PENDING. For the latter request, it will pass in the
 * mirrors that have been synchronized, then the stale bit will be cleared
 * to make the file's state turn into RDONLY.
 * For concurrent write reqeust, it just needs to change the file's state
 * to WRITE_PENDING in a sync tx. It doesn't have to change the layout
 * version because the version will be increased in the transition to
 * SYNC_PENDING later so that it can deny the write request from potential
 * evicted SYNC clients. */
static int
mdd_object_update_sync_pending(const struct lu_env *env, struct mdd_object *obj,
		struct md_layout_change *mlc, struct thandle *handle)
{
	struct mdd_device *mdd = mdd_obj2mdd_dev(obj);
	struct lu_buf *som_buf = &mdd_env_info(env)->mdi_buf[1];
	int fl = 0;
	int rc;
	ENTRY;

	/* operation validation */
	switch (mlc->mlc_opc) {
	case MD_LAYOUT_RESYNC_DONE:
		/* resync complete. */
	case MD_LAYOUT_WRITE:
		/* concurrent write. */
		break;
	case MD_LAYOUT_RESYNC:
		/* resync again, most likely the previous run failed.
		 * no-op if it's already in SYNC_PENDING state */
		RETURN(0);
	default:
		RETURN(-EBUSY);
	}

	if (mlc->mlc_som.lsa_valid & SOM_FL_STRICT) {
		rc = mdo_xattr_get(env, obj, &LU_BUF_NULL, XATTR_NAME_SOM);
		if (rc < 0 && rc != -ENODATA)
			RETURN(rc);

		fl = rc == -ENODATA ? LU_XATTR_CREATE : LU_XATTR_REPLACE;
		lustre_som_swab(&mlc->mlc_som);
		som_buf->lb_buf = &mlc->mlc_som;
		som_buf->lb_len = sizeof(mlc->mlc_som);
	}

	rc = mdd_declare_layout_change(env, mdd, obj, mlc, handle);
	if (rc)
		GOTO(out, rc);

	/* record a changelog for the completion of resync */
	rc = mdd_declare_changelog_store(env, mdd, CL_RESYNC, NULL, NULL,
					 handle);
	if (rc)
		GOTO(out, rc);

	/* RESYNC_DONE has piggybacked size and blocks */
	if (fl) {
		rc = mdd_declare_xattr_set(env, mdd, obj, som_buf,
					   XATTR_NAME_SOM, fl, handle);
		if (rc)
			GOTO(out, rc);
	}

	rc = mdd_trans_start(env, mdd, handle);
	if (rc)
		GOTO(out, rc);

	/* it needs a sync tx to make FLR to work properly */
	handle->th_sync = 1;

	rc = mdo_layout_change(env, obj, mlc, handle);
	if (rc)
		GOTO(out, rc);

	if (fl) {
		rc = mdo_xattr_set(env, obj, som_buf, XATTR_NAME_SOM,
				   fl, handle);
		if (rc)
			GOTO(out, rc);
	}

	rc = mdd_changelog_data_store(env, mdd, CL_RESYNC, 0, obj, handle,
				      NULL);
	if (rc)
		GOTO(out, rc);
	EXIT;
out:
	return rc;
}

/**
 * Layout change callback for object.
 *
 * This is only used by FLR for now. In the future, it can be exteneded to
 * handle all layout change.
 */
static int
mdd_layout_change(const struct lu_env *env, struct md_object *o,
		  struct md_layout_change *mlc)
{
	struct mdd_object       *obj = md2mdd_obj(o);
	struct mdd_device	*mdd = mdd_obj2mdd_dev(obj);
	struct lu_buf           *buf = mdd_buf_get(env, NULL, 0);
	struct lov_comp_md_v1   *lcm;
	struct thandle		*handle;
	int flr_state;
	int rc;

	ENTRY;

	if (S_ISDIR(mdd_object_type(obj))) {
		switch (mlc->mlc_opc) {
		case MD_LAYOUT_SHRINK:
			rc = mdd_dir_layout_shrink(env, o, mlc);
			break;
		case MD_LAYOUT_SPLIT:
			rc = mdd_dir_layout_split(env, o, mlc);
			break;
		default:
			LBUG();
		}

		RETURN(rc);
	}

	/* Verify acceptable operations */
	switch (mlc->mlc_opc) {
	case MD_LAYOUT_WRITE:
	case MD_LAYOUT_RESYNC:
	case MD_LAYOUT_RESYNC_DONE:
		break;
	default:
		RETURN(-ENOTSUPP);
	}

	handle = mdd_trans_create(env, mdd);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	rc = mdd_stripe_get(env, obj, buf, XATTR_NAME_LOV);
	if (rc < 0) {
		if (rc == -ENODATA)
			rc = -EINVAL;
		GOTO(out, rc);
	}

	/* analyze the layout to make sure it's a FLR file */
	lcm = buf->lb_buf;
	if (le32_to_cpu(lcm->lcm_magic) != LOV_MAGIC_COMP_V1)
		GOTO(out, rc = -EINVAL);

	flr_state = le16_to_cpu(lcm->lcm_flags) & LCM_FL_FLR_MASK;

	/* please refer to HLD of FLR for state transition */
	switch (flr_state) {
	case LCM_FL_NONE:
		rc = mdd_layout_instantiate_component(env, obj, mlc, handle);
		break;
	case LCM_FL_WRITE_PENDING:
		rc = mdd_layout_update_write_pending(env, obj, mlc, handle);
		break;
	case LCM_FL_RDONLY:
		rc = mdd_layout_update_rdonly(env, obj, mlc, handle);
		break;
	case LCM_FL_SYNC_PENDING:
		rc = mdd_object_update_sync_pending(env, obj, mlc, handle);
		break;
	default:
		rc = 0;
		break;
	}
	EXIT;

out:
	mdd_trans_stop(env, mdd, rc, handle);
	lu_buf_free(buf);
	return rc;
}

void mdd_object_make_hint(const struct lu_env *env, struct mdd_object *parent,
			  struct mdd_object *child, const struct lu_attr *attr,
			  const struct md_op_spec *spec,
			  struct dt_allocation_hint *hint)
{
	struct dt_object *np = parent ?  mdd_object_child(parent) : NULL;
	struct mdd_device *mdd = mdd_obj2mdd_dev(child);
	struct dt_object *nc = mdd_object_child(child);

	memset(hint, 0, sizeof(*hint));

	/* For striped directory, give striping EA to lod_ah_init, which will
	 * decide the stripe_offset and stripe count by it. */
	if (S_ISDIR(attr->la_mode) &&
	    unlikely(spec != NULL && spec->sp_cr_flags & MDS_OPEN_HAS_EA)) {
		hint->dah_eadata = spec->u.sp_ea.eadata;
		hint->dah_eadata_len = spec->u.sp_ea.eadatalen;
	} else {
		hint->dah_eadata = NULL;
		hint->dah_eadata_len = 0;
		if (spec->sp_cr_flags & MDS_OPEN_APPEND) {
			if (mdd->mdd_append_stripe_count != 0 ||
			    mdd->mdd_append_pool[0])
				CDEBUG(D_INFO,
				       "using O_APPEND file striping\n");
			if (mdd->mdd_append_stripe_count)
				hint->dah_append_stripes =
					mdd->mdd_append_stripe_count;
			if (mdd->mdd_append_pool[0])
				hint->dah_append_pool = mdd->mdd_append_pool;
		} else {
			hint->dah_append_stripes = 0;
		}
	}

	CDEBUG(D_INFO, DFID" eadata %p len %d\n", PFID(mdd_object_fid(child)),
	       hint->dah_eadata, hint->dah_eadata_len);
	/* @hint will be initialized by underlying device. */
	nc->do_ops->do_ah_init(env, hint, np, nc, attr->la_mode & S_IFMT);
}

static int mdd_accmode(const struct lu_env *env, const struct lu_attr *la,
		       u64 open_flags)
{
	/* Sadly, NFSD reopens a file repeatedly during operation, so the
	 * "acc_mode = 0" allowance for newly-created files isn't honoured.
	 * NFSD uses the MDS_OPEN_OWNEROVERRIDE flag to say that a file
	 * owner can write to a file even if it is marked readonly to hide
	 * its brokenness. (bug 5781) */
	if (open_flags & MDS_OPEN_OWNEROVERRIDE) {
		struct lu_ucred *uc = lu_ucred_check(env);

		if ((uc == NULL) || (la->la_uid == uc->uc_fsuid))
			return 0;
	}

	return mds_accmode(open_flags);
}

static int mdd_open_sanity_check(const struct lu_env *env,
				 struct mdd_object *obj,
				 const struct lu_attr *attr, u64 open_flags,
				 int is_replay)
{
	unsigned int may_mask;
	int rc;
	ENTRY;

	/* EEXIST check, also opening of *open* orphans is allowed so we can
	 * open-by-handle unlinked files
	 */
	if (mdd_is_dead_obj(obj) && !is_replay &&
	    likely(!(mdd_is_orphan_obj(obj) && obj->mod_count > 0)))
		RETURN(-ENOENT);

	if (S_ISLNK(attr->la_mode))
		RETURN(-ELOOP);

	may_mask = mdd_accmode(env, attr, open_flags);

	if (S_ISDIR(attr->la_mode) && (may_mask & MAY_WRITE))
		RETURN(-EISDIR);

	if (!(open_flags & MDS_OPEN_CREATED)) {
		rc = mdd_permission_internal(env, obj, attr, may_mask);
		if (rc)
			RETURN(rc);
	}

	if (S_ISFIFO(attr->la_mode) || S_ISSOCK(attr->la_mode) ||
	    S_ISBLK(attr->la_mode) || S_ISCHR(attr->la_mode))
		open_flags &= ~MDS_OPEN_TRUNC;

	/* For writing append-only file must open it with append mode. */
	if (attr->la_flags & LUSTRE_APPEND_FL) {
		if ((open_flags & MDS_FMODE_WRITE) &&
		    !(open_flags & MDS_OPEN_APPEND))
			RETURN(-EPERM);
		if (open_flags & MDS_OPEN_TRUNC)
			RETURN(-EPERM);
	}

	RETURN(0);
}

static int mdd_open(const struct lu_env *env, struct md_object *obj,
		    u64 open_flags, struct md_op_spec *spec)
{
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	struct md_device *md_dev = lu2md_dev(mdd2lu_dev(mdo2mdd(obj)));
	struct lu_attr *attr = MDD_ENV_VAR(env, cattr);
	struct mdd_object_user *mou = NULL;
	const struct lu_ucred *uc = lu_ucred(env);
	struct mdd_device *mdd = mdo2mdd(obj);
	enum changelog_rec_type type = CL_OPEN;
	int rc = 0;
	ENTRY;

	mdd_write_lock(env, mdd_obj, DT_TGT_CHILD);

	rc = mdd_la_get(env, mdd_obj, attr);
	if (rc != 0)
		GOTO(out, rc);

	rc = mdd_open_sanity_check(env, mdd_obj, attr, open_flags,
				   spec->no_create);
	if ((rc == -EACCES) && (mdd->mdd_cl.mc_current_mask & BIT(CL_DN_OPEN)))
		type = CL_DN_OPEN;
	else if (rc != 0)
		GOTO(out, rc);
	else
		mdd_obj->mod_count++;

	if (!mdd_changelog_enabled(env, mdd, type))
		GOTO(out, rc);

find:
	/* look for existing opener in list under mdd_write_lock */
	mou = mdd_obj_user_find(mdd_obj, uc->uc_uid, uc->uc_gid, open_flags);

	if (!mou) {
		int rc2;

		/* add user to list */
		mou = mdd_obj_user_alloc(open_flags, uc->uc_uid, uc->uc_gid);
		if (IS_ERR(mou)) {
			if (rc == 0)
				rc = PTR_ERR(mou);
			GOTO(out, rc);
		}
		rc2 = mdd_obj_user_add(mdd_obj, mou, type == CL_DN_OPEN);
		if (rc2 != 0) {
			mdd_obj_user_free(mou);
			if (rc2 == -EEXIST)
				GOTO(find, rc2);
		}
	} else {
		if (type == CL_DN_OPEN) {
			if (ktime_before(ktime_get(), mou->mou_deniednext))
				/* same user denied again same access within
				 * time interval: do not record
				 */
				GOTO(out, rc);

			/* this user already denied, but some time ago:
			 * update denied time
			 */
			mou->mou_deniednext =
				ktime_add(ktime_get(),
					  ktime_set(mdd->mdd_cl.mc_deniednext,
						    0));
		} else {
			mou->mou_opencount++;
			/* same user opening file again with same flags:
			 * don't record
			 */
			GOTO(out, rc);
		}
	}

	/* FYI, only the bottom 32 bits of open_flags are recorded */
	mdd_changelog(env, type, open_flags, md_dev, mdd_object_fid(mdd_obj));

	EXIT;
out:
	mdd_write_unlock(env, mdd_obj);
	return rc;
}

static int mdd_declare_close(const struct lu_env *env, struct mdd_object *obj,
			     struct md_attr *ma, struct thandle *handle)
{
	int rc;

	rc = mdd_orphan_declare_delete(env, obj, handle);
	if (rc)
		return rc;

	return mdo_declare_destroy(env, obj, handle);
}

/*
 * No permission check is needed.
 */
static int mdd_close(const struct lu_env *env, struct md_object *obj,
		     struct md_attr *ma, u64 open_flags)
{
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	struct mdd_device *mdd = mdo2mdd(obj);
	struct thandle *handle = NULL;
	int is_orphan = 0;
	int rc;
	bool blocked = false;
	bool last_close_by_uid = false;
	const struct lu_ucred *uc = lu_ucred(env);
	ENTRY;

	if (ma->ma_valid & MA_FLAGS && ma->ma_attr_flags & MDS_KEEP_ORPHAN) {
		mdd_write_lock(env, mdd_obj, DT_TGT_CHILD);
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
		/* mdd_trans_create() maybe failed because of barrier_entry(),
		 * under such case, the orphan MDT-object will be left in the
		 * orphan list, and when the MDT remount next time, the unused
		 * orphans will be destroyed automatically.
		 *
		 * One exception: the former mdd_finish_unlink may failed to
		 * add the orphan MDT-object to the orphan list, then if the
		 * mdd_trans_create() failed because of barrier_entry(), the
		 * MDT-object will become real orphan that is neither in the
		 * namespace nor in the orphan list. Such bad case should be
		 * very rare and will be handled by e2fsck/lfsck. */
		handle = mdd_trans_create(env, mdo2mdd(obj));
		if (IS_ERR(handle)) {
			rc = PTR_ERR(handle);
			if (rc != -EINPROGRESS)
				GOTO(stop, rc);

			handle = NULL;
			blocked = true;
			goto cont;
		}

		rc = mdd_declare_close(env, mdd_obj, ma, handle);
		if (rc)
			GOTO(stop, rc);

		rc = mdd_declare_changelog_store(env, mdd, CL_CLOSE, NULL, NULL,
						 handle);
		if (rc)
			GOTO(stop, rc);

		rc = mdd_trans_start(env, mdo2mdd(obj), handle);
		if (rc)
			GOTO(stop, rc);
	}

cont:
	mdd_write_lock(env, mdd_obj, DT_TGT_CHILD);
	rc = mdd_la_get(env, mdd_obj, &ma->ma_attr);
	if (rc != 0) {
		CERROR("%s: failed to get lu_attr of "DFID": rc = %d\n",
		       lu_dev_name(mdd2lu_dev(mdd)),
		       PFID(mdd_object_fid(mdd_obj)), rc);
		GOTO(out, rc);
	}

	/* check again with lock */
	is_orphan = (mdd_obj->mod_count == 1) &&
		    ((mdd_obj->mod_flags & (ORPHAN_OBJ | DEAD_OBJ)) != 0 ||
		     ma->ma_attr.la_nlink == 0);

	if (is_orphan && !handle && !blocked) {
		mdd_write_unlock(env, mdd_obj);
		goto again;
	}

	mdd_obj->mod_count--; /*release open count */

	/* under mdd write lock */
	/* If recording, see if we need to remove UID from list. uc is not
	 * initialized if the client has been evicted. */
	if (mdd_changelog_enabled(env, mdd, CL_OPEN) && uc) {
		struct mdd_object_user *mou;

		/* look for UID in list */
		/* If mou is NULL, it probably means logging was enabled after
		 * the user had the file open. So the corresponding close
		 * will not be logged.
		 */
		mou = mdd_obj_user_find(mdd_obj, uc->uc_uid, uc->uc_gid,
					open_flags);
		if (mou) {
			mou->mou_opencount--;
			if (mou->mou_opencount == 0) {
				mdd_obj_user_remove(mdd_obj, mou);
				last_close_by_uid = true;
			}
		}
	}

	if (!is_orphan || blocked)
		GOTO(out, rc = 0);

	/* Orphan object */
	/* NB: Object maybe not in orphan list originally, it is rare case for
	 * mdd_finish_unlink() failure, in that case, the object doesn't have
	 * ORPHAN_OBJ flag */
	if ((mdd_obj->mod_flags & ORPHAN_OBJ) != 0) {
		/* remove link to object from orphan index */
		LASSERT(handle != NULL);
		rc = mdd_orphan_delete(env, mdd_obj, handle);
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

	if (rc != 0 || blocked ||
	    !mdd_changelog_enabled(env, mdd, CL_CLOSE))
		GOTO(stop, rc);

	/* Record CL_CLOSE in changelog only if file was opened in write mode,
	 * or if CL_OPEN was recorded and it's last close by user.
	 * Changelogs mask may change between open and close operations, but
	 * this is not a big deal if we have a CL_CLOSE entry with no matching
	 * CL_OPEN. Plus Changelogs mask may not change often.
	 */
	if (((!(mdd->mdd_cl.mc_current_mask & BIT(CL_OPEN)) &&
	      (open_flags & (MDS_FMODE_WRITE | MDS_OPEN_APPEND |
			     MDS_OPEN_TRUNC))) ||
	     ((mdd->mdd_cl.mc_current_mask & BIT(CL_OPEN)) &&
	      last_close_by_uid)) &&
	    !(ma->ma_valid & MA_FLAGS && ma->ma_attr_flags & MDS_RECOV_OPEN)) {
		if (handle == NULL) {
			handle = mdd_trans_create(env, mdo2mdd(obj));
			if (IS_ERR(handle))
				GOTO(stop, rc = PTR_ERR(handle));

			rc = mdd_declare_changelog_store(env, mdd, CL_CLOSE,
							 NULL, NULL, handle);
			if (rc)
				GOTO(stop, rc);

			rc = mdd_trans_start(env, mdo2mdd(obj), handle);
			if (rc)
				GOTO(stop, rc);
		}

		/* FYI, only the bottom 32 bits of open_flags are recorded */
		mdd_changelog_data_store(env, mdd, CL_CLOSE, open_flags,
					 mdd_obj, handle, NULL);
	}

stop:
	if (handle != NULL && !IS_ERR(handle))
		rc = mdd_trans_stop(env, mdd, rc, handle);

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
			      size_t nob, const struct dt_it_ops *iops,
			      struct dt_it *it, __u32 attr, void *arg)
{
	struct lu_dirpage	*dp = &lp->lp_dir;
	void			*area = dp;
	int			 result;
	__u64			 hash = 0;
	struct lu_dirent	*ent;
	struct lu_dirent	*last = NULL;
	struct lu_fid		 fid;
	int			 first = 1;

	if (nob < sizeof(*dp))
		return -EINVAL;

        memset(area, 0, sizeof (*dp));
        area += sizeof (*dp);
        nob  -= sizeof (*dp);

        ent  = area;
        do {
                int    len;
		size_t recsize;

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

			if (le32_to_cpu(ent->lde_attrs) & LUDA_FID) {
				fid_le_to_cpu(&fid, &ent->lde_fid);
				if (fid_is_dot_lustre(&fid))
					goto next;
			}
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

	mdd_read_lock(env, mdd_obj, DT_TGT_CHILD);
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
			dp->ldp_hash_end = cpu_to_le64(MDS_DIR_END_OFF);
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
		int rc = -ENOENT;

		CERROR("%s: object "DFID" not found: rc = %d\n",
		       mdd_obj_dev_name(mdd_obj),
		       PFID(mdd_object_fid(mdd_obj)), rc);
		return rc;
	}
	return dt_object_sync(env, mdd_object_child(mdd_obj),
			      0, OBD_OBJECT_EOF);
}

static int mdd_object_lock(const struct lu_env *env,
			   struct md_object *obj,
			   struct lustre_handle *lh,
			   struct ldlm_enqueue_info *einfo,
			   union ldlm_policy_data *policy)
{
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	return dt_object_lock(env, mdd_object_child(mdd_obj), lh,
			      einfo, policy);
}

static int mdd_object_unlock(const struct lu_env *env,
			     struct md_object *obj,
			     struct ldlm_enqueue_info *einfo,
			     union ldlm_policy_data *policy)
{
	struct mdd_object *mdd_obj = md2mdd_obj(obj);
	return dt_object_unlock(env, mdd_object_child(mdd_obj), einfo, policy);
}

const struct md_object_operations mdd_obj_ops = {
	.moo_permission		= mdd_permission,
	.moo_attr_get		= mdd_attr_get,
	.moo_attr_set		= mdd_attr_set,
	.moo_xattr_get		= mdd_xattr_get,
	.moo_xattr_set		= mdd_xattr_set,
	.moo_xattr_list		= mdd_xattr_list,
	.moo_invalidate		= mdd_invalidate,
	.moo_xattr_del		= mdd_xattr_del,
	.moo_swap_layouts	= mdd_swap_layouts,
	.moo_open		= mdd_open,
	.moo_close		= mdd_close,
	.moo_readpage		= mdd_readpage,
	.moo_readlink		= mdd_readlink,
	.moo_changelog		= mdd_changelog,
	.moo_object_sync	= mdd_object_sync,
	.moo_object_lock	= mdd_object_lock,
	.moo_object_unlock	= mdd_object_unlock,
	.moo_layout_change	= mdd_layout_change,
};
