// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2025-2026, DDN/Whamcloud, Inc.
 */

/*
 * Author: Yingjin Qian <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM	S_OSD

#include <linux/fs_struct.h>

#include <dt_object.h>

#include "osd_internal.h"
#include "wbcfs.h"

/* Concurrency: no external locking is necessary. */
static int osd_index_try(const struct lu_env *env, struct dt_object *dt,
			 const struct dt_index_features *feat)
{
	int rc;

	if (likely(feat == &dt_directory_features)) {
		dt->do_index_ops = &osd_dir_ops;
		rc = 0;
	} else if (unlikely(feat == &dt_acct_features)) {
		/* TODO: Add quota support. */
		rc = -ENOTSUPP;
	} else if (unlikely(feat == &dt_otable_features)) {
		/* TODO: Add scrub support. */
		dt->do_index_ops = &osd_hash_index_ops;
		rc = 0;
	} else {
		dt->do_index_ops = &osd_hash_index_ops;
		rc = 0;
	}

	return rc;
}

static int osd_otable_it_attr_get(const struct lu_env *env,
				 struct dt_object *dt,
				 struct lu_attr *attr)
{
	attr->la_valid = 0;
	return 0;
}

static const struct dt_object_operations osd_obj_otable_it_ops = {
	.do_attr_get	= osd_otable_it_attr_get,
	.do_index_try	= osd_index_try,
};

static void __osd_object_init(struct osd_object *obj)
{
	LASSERT(obj->oo_inode != NULL);
	obj->oo_dt.do_body_ops = &osd_body_ops;
	obj->oo_dt.do_lu.lo_header->loh_attr |=
		(LOHA_EXISTS | (obj->oo_inode->i_mode & S_IFMT));
}

/*
 * Concurrency: No concurrent access is possible that early in object
 * life cycle.
 */
static int osd_object_init(const struct lu_env *env, struct lu_object *l,
			   const struct lu_object_conf *conf)
{
	struct osd_object *obj = osd_obj(l);
	struct osd_device *osd = osd_obj2dev(obj);
	const struct lu_fid *fid = lu_object_fid(l);
	struct inode *inode = NULL;
	__u64 hash;

	if (fid_is_otable_it(&l->lo_header->loh_fid)) {
		obj->oo_dt.do_ops = &osd_obj_otable_it_ops;
		l->lo_header->loh_attr |= LOHA_EXISTS;
		return 0;
	}

	hash = lu_fid_build_ino(fid, 0);
	inode = ilookup5(osd_sb(osd), hash, memfs_test_inode_by_fid,
			 (void *)fid);
	obj->oo_dt.do_body_ops = &osd_body_ops;
	if (inode) {
		obj->oo_inode = inode;
		__osd_object_init(obj);

		/*
		 * TODO: check LMA EA and convert LMAI flags to lustre
		 * LMA flags and cache it in object.
		 */
	}

	CDEBUG(D_INODE, "%s: object init for fid="DFID" inode@%pK nlink=%d\n",
	       osd_name(osd), PFID(fid), inode, inode ? inode->i_nlink : 0);

	return 0;
}

static void osd_object_free(const struct lu_env *env, struct lu_object *l)
{
	struct osd_object *obj = osd_obj(l);
	struct lu_object_header *h = obj->oo_header;

	dt_object_fini(&obj->oo_dt);
	OBD_FREE_PTR(obj);
	if (unlikely(h))
		lu_object_header_free(h);
}

/*
 * Called just before the object is freed. Releases all resources except for
 * object itself (that is released by osd_object_free()).
 *
 * Concurrency: no concurrent access is possible that late in object
 * life-cycle.
 */
static void osd_object_delete(const struct lu_env *env, struct lu_object *l)
{
	struct osd_object *obj = osd_obj(l);
	struct inode *inode = obj->oo_inode;

	if (!inode)
		return;

	obj->oo_inode = NULL;
	CDEBUG(D_INODE,
	       "%s: object "DFID" delete: inode@%pK nlink=%u count=%d\n",
	       osd_name(osd_obj2dev(obj)), PFID(lu_object_fid(l)),
	       inode, inode->i_nlink, atomic_read(&inode->i_count));
	iput(inode);
}

/* Concurrency: ->loo_object_release() is called under site spin-lock. */
static void osd_object_release(const struct lu_env *env, struct lu_object *l)
{
	struct osd_object *o = osd_obj(l);

	/*
	 * Nobody should be releasing a non-destroyed object with nlink=0
	 * the API allows this, but wbcfs does not like and then report
	 * this inode as deleted.
	 */
	if (o->oo_destroyed == 0 && o->oo_inode && o->oo_inode->i_nlink == 0)
		CERROR("%s: Object "DFID" wrong: %d inode@%pK nlink=%u\n",
		       osd_name(osd_obj2dev(o)), PFID(lu_object_fid(l)),
		       o->oo_destroyed, o->oo_inode,
		       o->oo_inode ? o->oo_inode->i_nlink : 0);

	LASSERT(!(o->oo_destroyed == 0 && o->oo_inode &&
		  o->oo_inode->i_nlink == 0));
}

static int osd_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *l)
{
	struct osd_object *o = osd_obj(l);

	return (*p)(env, cookie,
		    LUSTRE_OSD_WBCFS_NAME"-object@%p(i:%p:%lu/%u)",
		    o, o->oo_inode,
		    o->oo_inode ? o->oo_inode->i_ino : 0UL,
		    o->oo_inode ? o->oo_inode->i_generation : 0);
}

static void osd_inode_getattr(const struct lu_env *env,
			      struct inode *inode, struct lu_attr *attr)
{
	attr->la_valid	|= LA_ATIME | LA_MTIME | LA_CTIME | LA_MODE |
			   LA_SIZE | LA_BLOCKS | LA_UID | LA_GID |
			   LA_PROJID | LA_FLAGS | LA_NLINK | LA_RDEV |
			   LA_BLKSIZE | LA_TYPE | LA_BTIME;

	attr->la_atime = inode_get_atime_sec(inode);
	attr->la_mtime = inode_get_mtime_sec(inode);
	attr->la_ctime = inode_get_ctime_sec(inode);
	attr->la_btime = memfs_get_btime(inode);
	attr->la_mode = inode->i_mode;
	attr->la_size = i_size_read(inode);
	attr->la_blocks = inode->i_blocks;
	attr->la_uid = i_uid_read(inode);
	attr->la_gid = i_gid_read(inode);
	attr->la_projid = i_projid_read(inode);
	attr->la_flags = ll_inode_to_ext_flags(inode->i_flags);
	attr->la_nlink = inode->i_nlink;
	attr->la_rdev = inode->i_rdev;
	attr->la_blksize = 1 << inode->i_blkbits;
	attr->la_blkbits = inode->i_blkbits;
	/*
	 * MemFS did not transfer inherit flags from raw inode
	 * to inode flags, and MemFS internally test raw inode
	 * @i_flags directly. Instead of patching ext4, we do it here.
	 */
	if (memfs_get_flags(inode) & LUSTRE_PROJINHERIT_FL)
		attr->la_flags |= LUSTRE_PROJINHERIT_FL;
}

static int osd_attr_get(const struct lu_env *env, struct dt_object *dt,
			struct lu_attr *attr)
{
	struct osd_object *obj = osd_dt_obj(dt);

	if (unlikely(!dt_object_exists(dt)))
		return -ENOENT;
	if (unlikely(obj->oo_destroyed))
		return -ENOENT;

	LASSERT(!dt_object_remote(dt));

	spin_lock(&obj->oo_guard);
	osd_inode_getattr(env, obj->oo_inode, attr);
	if (obj->oo_lma_flags & LUSTRE_ORPHAN_FL) {
		attr->la_valid |= LA_FLAGS;
		attr->la_flags |= LUSTRE_ORPHAN_FL;
	}
	if (obj->oo_lma_flags & LUSTRE_ENCRYPT_FL) {
		attr->la_valid |= LA_FLAGS;
		attr->la_flags |= LUSTRE_ENCRYPT_FL;
	}
	spin_unlock(&obj->oo_guard);
	CDEBUG(D_INFO, "%s: getattr "DFID" inode@%pK nlink=%d\n",
	       osd_name(osd_obj2dev(obj)), PFID(lu_object_fid(&dt->do_lu)),
	       obj->oo_inode, obj->oo_inode->i_nlink);
	return 0;
}

static int osd_inode_setattr(const struct lu_env *env,
			     struct inode *inode, const struct lu_attr *attr)
{
	__u64 bits = attr->la_valid;

	/* Only allow set size for regular file */
	if (!S_ISREG(inode->i_mode))
		bits &= ~(LA_SIZE | LA_BLOCKS);

	if (bits == 0)
		return 0;

	if (bits & LA_ATIME)
		inode_set_atime_to_ts(inode,
				      osd_inode_time(inode, attr->la_atime));
	if (bits & LA_CTIME)
		inode_set_ctime_to_ts(inode,
				      osd_inode_time(inode, attr->la_ctime));
	if (bits & LA_MTIME)
		inode_set_mtime_to_ts(inode,
				      osd_inode_time(inode, attr->la_mtime));
	if (bits & LA_SIZE) {
		spin_lock(&inode->i_lock);
		i_size_write(inode, attr->la_size);
		spin_unlock(&inode->i_lock);
	}

	/*
	 * OSD should not change "i_blocks" which is used by quota.
	 * "i_blocks" should be changed by ldiskfs only.
	 */
	if (bits & LA_MODE)
		inode->i_mode = (inode->i_mode & S_IFMT) |
				(attr->la_mode & ~S_IFMT);
	if (bits & LA_UID)
		i_uid_write(inode, attr->la_uid);
	if (bits & LA_GID)
		i_gid_write(inode, attr->la_gid);
	if (bits & LA_PROJID)
		i_projid_write(inode, attr->la_projid);
	if (bits & LA_NLINK)
		set_nlink(inode, attr->la_nlink);
	if (bits & LA_RDEV)
		inode->i_rdev = attr->la_rdev;

	if (bits & LA_FLAGS) {
		/* always keep S_NOCMTIME */
		inode->i_flags = ll_ext_to_inode_flags(attr->la_flags) |
				 S_NOCMTIME;
#if defined(S_ENCRYPTED)
		/* Always remove S_ENCRYPTED, because ldiskfs must not be
		 * aware of encryption status. It is just stored into LMA
		 * so that it can be forwared to client side.
		 */
		inode->i_flags &= ~S_ENCRYPTED;
#endif
		/*
		 * MemFS did not transfer inherit flags from
		 * @inode->i_flags to raw inode i_flags when writing
		 * flags, we do it explictly here.
		 */
		if (attr->la_flags & LUSTRE_PROJINHERIT_FL)
			MEMFS_I(inode)->mei_flags |= LUSTRE_PROJINHERIT_FL;
		else
			MEMFS_I(inode)->mei_flags &= ~LUSTRE_PROJINHERIT_FL;
	}
	return 0;
}

static int osd_attr_set(const struct lu_env *env, struct dt_object *dt,
			const struct lu_attr *attr, struct thandle *handle)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct inode *inode;
	int rc;

	if (!dt_object_exists(dt))
		return -ENOENT;

	LASSERT(!dt_object_remote(dt));
	inode = obj->oo_inode;
	spin_lock(&obj->oo_guard);
	rc = osd_inode_setattr(env, inode, attr);
	spin_unlock(&obj->oo_guard);
	if (rc)
		RETURN(rc);

	/* TODO: extra flags for LUSTRE_LMA_FL_MASKS */

	return 0;
}

static int osd_mkfile(const struct lu_env *env, struct osd_object *obj,
		      umode_t mode, struct dt_allocation_hint *hint,
		      struct thandle *th, struct lu_attr *attr)
{
	struct osd_device *osd = osd_obj2dev(obj);
	struct dt_object *parent = NULL;
	struct inode *inode;
	struct iattr iattr = {
		.ia_valid = ATTR_UID | ATTR_GID |
			    ATTR_CTIME | ATTR_MTIME | ATTR_ATIME,
		.ia_ctime.tv_sec = attr->la_ctime,
		.ia_mtime.tv_sec = attr->la_mtime,
		.ia_atime.tv_sec = attr->la_atime,
		.ia_uid = GLOBAL_ROOT_UID,
		.ia_gid = GLOBAL_ROOT_GID,
	};
	const struct osd_timespec omit = { .tv_nsec = UTIME_OMIT };
	const struct lu_fid *fid = lu_object_fid(&obj->oo_dt.do_lu);

	if (attr->la_valid & LA_UID)
		iattr.ia_uid = make_kuid(&init_user_ns, attr->la_uid);
	if (attr->la_valid & LA_GID)
		iattr.ia_gid = make_kgid(&init_user_ns, attr->la_gid);

	LASSERT(obj->oo_inode == NULL);

	if (hint != NULL && hint->dah_parent != NULL &&
	    !dt_object_remote(hint->dah_parent))
		parent = hint->dah_parent;

	/* if a time component is not valid set it to UTIME_OMIT */
	if (!(attr->la_valid & LA_CTIME))
		iattr.ia_ctime = omit;
	if (!(attr->la_valid & LA_MTIME))
		iattr.ia_mtime = omit;
	if (!(attr->la_valid & LA_ATIME))
		iattr.ia_atime = omit;

	inode = memfs_create_inode(osd_sb(osd),
				   parent ? osd_dt_obj(parent)->oo_inode :
					    osd_sb(osd)->s_root->d_inode,
				   mode, &iattr, 0, false);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	/* Do not update file c/mtime in MemFS. */
	inode->i_flags |= S_NOCMTIME;
	inode->i_ino = lu_fid_build_ino(fid, 0);
	inode->i_generation = lu_fid_build_gen(fid);
	MEMFS_I(inode)->mei_fid = *fid;
	if (unlikely(insert_inode_locked(inode) < 0)) {
		CERROR("%s: Failed to insert inode %lu "DFID": doubly allocated?\n",
		       osd_name(osd), inode->i_ino, PFID(fid));
		iput(inode);
		RETURN(-EIO);
	}

	CDEBUG(D_INODE,
	       "%s: create object "DFID": inode@%pK nlink=%d mode=%#o\n",
	       osd_name(osd), PFID(fid), inode, inode->i_nlink, inode->i_mode);
	obj->oo_inode = inode;
	RETURN(0);
}

static int osd_mkdir(const struct lu_env *env, struct osd_object *obj,
		     struct lu_attr *attr,
		     struct dt_allocation_hint *hint,
		     struct dt_object_format *dof,
		     struct thandle *th)
{
	__u32 mode = (attr->la_mode & (S_IFMT | S_IRWXUGO | S_ISVTX | S_ISGID));

	LASSERT(S_ISDIR(attr->la_mode));

	return osd_mkfile(env, obj, mode, hint, th, attr);
}

static int osd_mk_index(const struct lu_env *env, struct osd_object *obj,
			struct lu_attr *attr,
			struct dt_allocation_hint *hint,
			struct dt_object_format *dof,
			struct thandle *th)
{
	__u32 mode = (attr->la_mode & (S_IFMT | S_IALLUGO | S_ISVTX));
	const struct dt_index_features *feat = dof->u.dof_idx.di_feat;
	struct memfs_inode_info *mei;
	size_t keylen = 0;
	size_t reclen = 0;
	int rc;

	ENTRY;

	LASSERT(S_ISREG(attr->la_mode));

	/* Only support index with fixed key length. */
	if (feat->dif_flags & DT_IND_VARKEY)
		RETURN(-EINVAL);

	keylen = feat->dif_keysize_max;
	if (!(feat->dif_flags & DT_IND_VARREC))
		reclen = feat->dif_recsize_max;

	rc = osd_mkfile(env, obj, mode, hint, th, attr);
	if (rc)
		GOTO(out, rc);

	LASSERT(obj->oo_inode != NULL);
	mei = MEMFS_I(obj->oo_inode);
	mei->mei_index_type = INDEX_TYPE_HASH;
	rc = hash_index_init(&mei->mei_hash_index, keylen, reclen);
	if (rc) {
		CERROR("%s: failed to create index for FID="DFID": rc=%d\n",
		       osd_name(osd_obj2dev(obj)),
		       PFID(lu_object_fid(&obj->oo_dt.do_lu)), rc);
		/* TODO: cleanup @oo_inode... */
	}
out:
	RETURN(rc);
}

static int osd_mkreg(const struct lu_env *env, struct osd_object *obj,
		     struct lu_attr *attr,
		     struct dt_allocation_hint *hint,
		     struct dt_object_format *dof,
		     struct thandle *th)
{
	LASSERT(S_ISREG(attr->la_mode));
	return osd_mkfile(env, obj, (attr->la_mode &
			 (S_IFMT | S_IALLUGO | S_ISVTX)), hint, th,
			  attr);
}

static int osd_mksym(const struct lu_env *env, struct osd_object *obj,
		     struct lu_attr *attr,
		     struct dt_allocation_hint *hint,
		     struct dt_object_format *dof,
		     struct thandle *th)
{
	LASSERT(S_ISLNK(attr->la_mode));
	/* TODO: symlink support. */
	RETURN(-EOPNOTSUPP);
}

static int osd_mknod(const struct lu_env *env, struct osd_object *obj,
		     struct lu_attr *attr,
		     struct dt_allocation_hint *hint,
		     struct dt_object_format *dof,
		     struct thandle *th)
{
	umode_t mode = attr->la_mode & (S_IFMT | S_IALLUGO | S_ISVTX);
	int result;

	LASSERT(obj->oo_inode == NULL);
	LASSERT(S_ISCHR(mode) || S_ISBLK(mode) ||
		S_ISFIFO(mode) || S_ISSOCK(mode));

	result = osd_mkfile(env, obj, mode, hint, th, attr);
	if (result == 0) {
		LASSERT(obj->oo_inode != NULL);
		/*
		 * This inode should be marked dirty for i_rdev.  Currently
		 * that is done in the osd_attr_init().
		 */
		init_special_inode(obj->oo_inode, obj->oo_inode->i_mode,
				   attr->la_rdev);
	}
	return result;
}

typedef int (*osd_obj_type_f)(const struct lu_env *env,
			      struct osd_object *obj,
			      struct lu_attr *attr,
			      struct dt_allocation_hint *hint,
			      struct dt_object_format *dof,
			      struct thandle *th);

static osd_obj_type_f osd_create_type_f(enum dt_format_type type)
{
	osd_obj_type_f result;

	switch (type) {
	case DFT_DIR:
		result = osd_mkdir;
		break;
	case DFT_REGULAR:
		result = osd_mkreg;
		break;
	case DFT_SYM:
		result = osd_mksym;
		break;
	case DFT_NODE:
		result = osd_mknod;
		break;
	case DFT_INDEX:
		result = osd_mk_index;
		break;
	default:
		LBUG();
		break;
	}
	return result;
}

static void osd_attr_init(const struct lu_env *env, struct osd_object *obj,
			  struct lu_attr *attr, struct dt_object_format *dof,
			  struct thandle *handle)
{
	struct inode *inode = obj->oo_inode;
	__u64 valid = attr->la_valid;
	int result;

	attr->la_valid &= ~(LA_TYPE | LA_MODE);

	if (dof->dof_type != DFT_NODE)
		attr->la_valid &= ~LA_RDEV;
	if ((valid & LA_ATIME) &&
	    (attr->la_atime == inode_get_atime_sec(inode)))
		attr->la_valid &= ~LA_ATIME;
	if ((valid & LA_CTIME) &&
	    (attr->la_ctime == inode_get_ctime_sec(inode)))
		attr->la_valid &= ~LA_CTIME;
	if ((valid & LA_MTIME) &&
	    (attr->la_mtime == inode_get_mtime_sec(inode)))
		attr->la_valid &= ~LA_MTIME;

	/* TODO: Perform quota transfer. */

	if (attr->la_valid != 0) {
		result = osd_inode_setattr(env, inode, attr);
		/*
		 * The osd_inode_setattr() should always succeed here.  The
		 * only error that could be returned is EDQUOT when we are
		 * trying to change the UID or GID of the inode. However, this
		 * should not happen since quota enforcement is no longer
		 * enabled on MemFS (lquota is supported and takes care of it).
		 */
		LASSERTF(result == 0, "%d\n", result);
	}

	attr->la_valid = valid;
}

/* Helper function for osd_create(). */
static int __osd_create(const struct lu_env *env, struct osd_object *obj,
			struct lu_attr *attr, struct dt_allocation_hint *hint,
			struct dt_object_format *dof, struct thandle *th)
{
	int result;
	__u32 umask;

	/* we drop umask so that permissions we pass are not affected */
	umask = current->fs->umask;
	current->fs->umask = 0;

	result = osd_create_type_f(dof->dof_type)(env, obj, attr, hint, dof,
						  th);
	if (likely(obj->oo_inode && result == 0)) {
		LASSERT(obj->oo_inode->i_state & I_NEW);

		/*
		 * Unlock the inode before attr initialization to avoid
		 * unnecessary dqget operations. LU-6378
		 */
		unlock_new_inode(obj->oo_inode);
		osd_attr_init(env, obj, attr, dof, th);
		__osd_object_init(obj);
	}

	/* restore previous umask value */
	current->fs->umask = umask;

	return result;
}

static void osd_ah_init(const struct lu_env *env, struct dt_allocation_hint *ah,
			struct dt_object *parent, struct dt_object *child,
			umode_t child_mode)
{
	LASSERT(ah);

	ah->dah_parent = parent;
}

/* OSD layer object creation funcation for OST objects. */
static int osd_create(const struct lu_env *env, struct dt_object *dt,
		      struct lu_attr *attr, struct dt_allocation_hint *hint,
		      struct dt_object_format *dof, struct thandle *th)
{
	const struct lu_fid *fid = lu_object_fid(&dt->do_lu);
	struct osd_object *obj = osd_dt_obj(dt);
	int rc;

	ENTRY;

	if (dt_object_exists(dt))
		RETURN(-EEXIST);

	LASSERT(!dt_object_remote(dt));
	LASSERT(dt_write_locked(env, dt));

	/* Quota files cannot be created from the kernel any more */
	if (unlikely(fid_is_acct(fid)))
		RETURN(-EPERM);

	rc = __osd_create(env, obj, attr, hint, dof, th);
	/* TODO: Update LMA EA with @fid. */
	LASSERT(ergo(rc == 0,
		     dt_object_exists(dt) && !dt_object_remote(dt)));
	RETURN(rc);
}

static int osd_destroy(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	const struct lu_fid *fid = lu_object_fid(&dt->do_lu);
	struct osd_object *obj = osd_dt_obj(dt);
	struct inode *inode = obj->oo_inode;
	struct osd_device *osd = osd_obj2dev(obj);

	ENTRY;

	LASSERT(inode);
	LASSERT(!lu_object_is_dying(dt->do_lu.lo_header));

	if (unlikely(fid_is_acct(fid)))
		RETURN(-EPERM);

	/* TODO: Agent entry remvoal... */
	if (S_ISDIR(inode->i_mode)) {
		if (inode->i_nlink > 2)
			CERROR("%s: dir "DFID" ino %lu nlink %u at unlink.\n",
			       osd_name(osd), PFID(fid), inode->i_ino,
			       inode->i_nlink);

		spin_lock(&obj->oo_guard);
		clear_nlink(inode);
		spin_unlock(&obj->oo_guard);
	}

	set_bit(LU_OBJECT_HEARD_BANSHEE, &dt->do_lu.lo_header->loh_flags);
	obj->oo_destroyed = 1;
	CDEBUG(D_INODE,
	       "%s: Object "DFID" destroyed: inode@%pK nlink=%d mode=%#o\n",
	       osd_name(osd), PFID(lu_object_fid(&dt->do_lu)), inode,
	       inode->i_nlink, inode->i_mode);

	RETURN(0);
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_ref_add(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct inode *inode = obj->oo_inode;
	int rc = 0;

	if (!dt_object_exists(dt) || obj->oo_destroyed)
		return -ENOENT;

	LASSERT(!dt_object_remote(dt));
	LASSERT(dt_write_locked(env, dt));

	CDEBUG(D_INODE, "%s:"DFID" increase nlink %d inode@%pK\n",
	       osd_name(osd_obj2dev(obj)), PFID(lu_object_fid(&dt->do_lu)),
	       inode->i_nlink, inode);
	/*
	 * The DIR_NLINK feature allows directories to exceed LDISKFS_LINK_MAX
	 * (65000) subdirectories by storing "1" in i_nlink if the link count
	 * would otherwise overflow. Directory tranversal tools understand
	 * that (st_nlink == 1) indicates that the filesystem dose not track
	 * hard links count on the directory, and will not abort subdirectory
	 * scanning early once (st_nlink - 2) subdirs have been found.
	 *
	 * This also has to properly handle the case of inodes with nlink == 0
	 * in case they are being linked into the PENDING directory
	 */
	spin_lock(&obj->oo_guard);
	if (unlikely(inode->i_nlink == 0))
		/* inc_nlink from 0 may cause WARN_ON */
		set_nlink(inode, 1);
	else
		inc_nlink(inode);
	spin_unlock(&obj->oo_guard);

	return rc;
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_ref_del(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct inode *inode = obj->oo_inode;
	struct osd_device *osd = osd_dev(dt->do_lu.lo_dev);

	if (!dt_object_exists(dt))
		return -ENOENT;

	LASSERT(!dt_object_remote(dt));
	LASSERT(dt_write_locked(env, dt));

	if (CFS_FAIL_CHECK(OBD_FAIL_OSD_REF_DEL))
		return -EIO;

	spin_lock(&obj->oo_guard);
	if (inode->i_nlink == 0) {
		CDEBUG_LIMIT(fid_is_norm(lu_object_fid(&dt->do_lu)) ?
			     D_ERROR : D_INODE, "%s: nlink == 0 on "DFID".\n",
			     osd_name(osd), PFID(lu_object_fid(&dt->do_lu)));
		spin_unlock(&obj->oo_guard);
		return 0;
	}

	CDEBUG(D_INODE, DFID" decrease nlink %d inode@%pK\n",
	       PFID(lu_object_fid(&dt->do_lu)), inode->i_nlink, inode);

	if (!S_ISDIR(inode->i_mode) || inode->i_nlink > 2)
		drop_nlink(inode);
	spin_unlock(&obj->oo_guard);

	return 0;
}

/* Concurrency: @dt is write locked. */
static int osd_xattr_set(const struct lu_env *env, struct dt_object *dt,
			 const struct lu_buf *buf, const char *name, int fl,
			 struct thandle *handle)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	int flags = 0;
	int rc;

	ENTRY;

	LASSERT(inode);
	LASSERT(buf);

	if (fl & LU_XATTR_REPLACE)
		flags |= XATTR_REPLACE;
	if (fl & LU_XATTR_CREATE)
		flags |= XATTR_CREATE;

	/* FIXME: using VFS i_op->setxattr()? */
	rc = memfs_xattr_set(inode, buf->lb_buf, buf->lb_len, name, flags);

	RETURN(rc);
}

/* Concurrency: @dt is read locked. */
static int osd_xattr_get(const struct lu_env *env, struct dt_object *dt,
			 struct lu_buf *buf, const char *name)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;
	int rc;

	ENTRY;
	LASSERT(buf);

	if (!dt_object_exists(dt))
		RETURN(-ENOENT);

	LASSERT(!dt_object_remote(dt));

	/* FIXME: using VFS i_op->getxattr()? */
	rc = memfs_xattr_get(inode, buf->lb_buf, buf->lb_len, name);
	RETURN(rc);
}

/* Concurrency: @dt is write locked. */
static int osd_xattr_del(const struct lu_env *env, struct dt_object *dt,
			 const char *name, struct thandle *handle)
{
	struct inode *inode = osd_dt_obj(dt)->oo_inode;

	if (!dt_object_exists(dt))
		return -ENOENT;

	LASSERT(!dt_object_remote(dt));
	/* FIXME: using VFS i_op->removexattr() */
	memfs_xattr_del(inode, name);

	return 0;
}

/* TODO: Implement xattr listing. */
static int osd_xattr_list(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *buf)
{
	RETURN(0);
}

/* MemFS does not support object sync, return zero to ignore the error. */
static int osd_object_sync(const struct lu_env *env, struct dt_object *dt,
			   __u64 start, __u64 end)
{
	RETURN(0);
}

const struct dt_object_operations osd_obj_ops = {
	.do_attr_get		= osd_attr_get,
	.do_attr_set		= osd_attr_set,
	.do_ah_init		= osd_ah_init,
	.do_create		= osd_create,
	.do_destroy		= osd_destroy,
	.do_index_try		= osd_index_try,
	.do_ref_add		= osd_ref_add,
	.do_ref_del		= osd_ref_del,
	.do_xattr_get		= osd_xattr_get,
	.do_xattr_set		= osd_xattr_set,
	.do_xattr_del		= osd_xattr_del,
	.do_xattr_list		= osd_xattr_list,
	.do_object_sync		= osd_object_sync,
};

const struct lu_object_operations osd_lu_obj_ops = {
	.loo_object_init      = osd_object_init,
	.loo_object_delete    = osd_object_delete,
	.loo_object_release   = osd_object_release,
	.loo_object_free      = osd_object_free,
	.loo_object_print     = osd_object_print,
};
