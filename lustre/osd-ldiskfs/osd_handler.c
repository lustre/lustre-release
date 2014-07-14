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
 * lustre/osd/osd_handler.c
 *
 * Top-level entry points into osd module
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 *         Pravin Shelar <pravin.shelar@sun.com> : Added fid in dirent
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/* prerequisite for linux/xattr.h */
#include <linux/types.h>
/* prerequisite for linux/xattr.h */
#include <linux/fs.h>
/* XATTR_{REPLACE,CREATE} */
#include <linux/xattr.h>

/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd_support.h>
/* struct ptlrpc_thread */
#include <lustre_net.h>
#include <lustre_fid.h>
/* process_config */
#include <lustre_param.h>

#include "osd_internal.h"
#include "osd_dynlocks.h"

/* llo_* api support */
#include <md_object.h>
#include <lustre_quota.h>

#include <ldiskfs/xattr.h>

int ldiskfs_pdo = 1;
CFS_MODULE_PARM(ldiskfs_pdo, "i", int, 0644,
                "ldiskfs with parallel directory operations");

int ldiskfs_track_declares_assert;
CFS_MODULE_PARM(ldiskfs_track_declares_assert, "i", int, 0644,
		"LBUG during tracking of declares");

/* Slab to allocate dynlocks */
struct kmem_cache *dynlock_cachep;

static struct lu_kmem_descr ldiskfs_caches[] = {
	{
		.ckd_cache = &dynlock_cachep,
		.ckd_name  = "dynlock_cache",
		.ckd_size  = sizeof(struct dynlock_handle)
	},
	{
		.ckd_cache = NULL
	}
};

static const char dot[] = ".";
static const char dotdot[] = "..";
static const char remote_obj_dir[] = "REM_OBJ_DIR";

static const struct lu_object_operations      osd_lu_obj_ops;
static const struct dt_object_operations      osd_obj_ops;
static const struct dt_object_operations      osd_obj_ea_ops;
static const struct dt_object_operations      osd_obj_otable_it_ops;
static const struct dt_index_operations       osd_index_iam_ops;
static const struct dt_index_operations       osd_index_ea_ops;

int osd_trans_declare_op2rb[] = {
	[OSD_OT_ATTR_SET]	= OSD_OT_ATTR_SET,
	[OSD_OT_PUNCH]		= OSD_OT_MAX,
	[OSD_OT_XATTR_SET]	= OSD_OT_XATTR_SET,
	[OSD_OT_CREATE]		= OSD_OT_DESTROY,
	[OSD_OT_DESTROY]	= OSD_OT_CREATE,
	[OSD_OT_REF_ADD]	= OSD_OT_REF_DEL,
	[OSD_OT_REF_DEL]	= OSD_OT_REF_ADD,
	[OSD_OT_WRITE]		= OSD_OT_WRITE,
	[OSD_OT_INSERT]		= OSD_OT_DELETE,
	[OSD_OT_DELETE]		= OSD_OT_INSERT,
	[OSD_OT_UPDATE]		= OSD_OT_MAX,
	[OSD_OT_QUOTA]		= OSD_OT_MAX,
};

static int osd_has_index(const struct osd_object *obj)
{
        return obj->oo_dt.do_index_ops != NULL;
}

static int osd_object_invariant(const struct lu_object *l)
{
        return osd_invariant(osd_obj(l));
}

/*
 * Concurrency: doesn't matter
 */
static int osd_read_locked(const struct lu_env *env, struct osd_object *o)
{
        return osd_oti_get(env)->oti_r_locks > 0;
}

/*
 * Concurrency: doesn't matter
 */
static int osd_write_locked(const struct lu_env *env, struct osd_object *o)
{
        struct osd_thread_info *oti = osd_oti_get(env);
        return oti->oti_w_locks > 0 && o->oo_owner == env;
}

/*
 * Concurrency: doesn't access mutable data
 */
static int osd_root_get(const struct lu_env *env,
                        struct dt_device *dev, struct lu_fid *f)
{
        lu_local_obj_fid(f, OSD_FS_ROOT_OID);
        return 0;
}

/*
 * OSD object methods.
 */

/*
 * Concurrency: no concurrent access is possible that early in object
 * life-cycle.
 */
static struct lu_object *osd_object_alloc(const struct lu_env *env,
                                          const struct lu_object_header *hdr,
                                          struct lu_device *d)
{
        struct osd_object *mo;

        OBD_ALLOC_PTR(mo);
        if (mo != NULL) {
                struct lu_object *l;

                l = &mo->oo_dt.do_lu;
                dt_object_init(&mo->oo_dt, NULL, d);
		mo->oo_dt.do_ops = &osd_obj_ea_ops;
                l->lo_ops = &osd_lu_obj_ops;
		init_rwsem(&mo->oo_sem);
		init_rwsem(&mo->oo_ext_idx_sem);
		spin_lock_init(&mo->oo_guard);
                return l;
        } else {
                return NULL;
        }
}

int osd_get_lma(struct osd_thread_info *info, struct inode *inode,
		struct dentry *dentry, struct lustre_mdt_attrs *lma)
{
	int rc;

	CLASSERT(LMA_OLD_SIZE >= sizeof(*lma));
	rc = __osd_xattr_get(inode, dentry, XATTR_NAME_LMA,
			     info->oti_mdt_attrs_old, LMA_OLD_SIZE);
	if (rc > 0) {
		if ((void *)lma != (void *)info->oti_mdt_attrs_old)
			memcpy(lma, info->oti_mdt_attrs_old, sizeof(*lma));
		rc = 0;
		lustre_lma_swab(lma);
		/* Check LMA compatibility */
		if (lma->lma_incompat & ~LMA_INCOMPAT_SUPP) {
			CWARN("%.16s: unsupported incompat LMA feature(s) %#x "
			      "for fid = "DFID", ino = %lu\n",
			      LDISKFS_SB(inode->i_sb)->s_es->s_volume_name,
			      lma->lma_incompat & ~LMA_INCOMPAT_SUPP,
			      PFID(&lma->lma_self_fid), inode->i_ino);
			rc = -EOPNOTSUPP;
		}
	} else if (rc == 0) {
		rc = -ENODATA;
	}

	return rc;
}

/*
 * retrieve object from backend ext fs.
 **/
struct inode *osd_iget(struct osd_thread_info *info, struct osd_device *dev,
		       struct osd_inode_id *id)
{
	struct inode *inode = NULL;

	inode = ldiskfs_iget(osd_sb(dev), id->oii_ino);
	if (IS_ERR(inode)) {
		CDEBUG(D_INODE, "no inode: ino = %u, rc = %ld\n",
		       id->oii_ino, PTR_ERR(inode));
	} else if (id->oii_gen != OSD_OII_NOGEN &&
		   inode->i_generation != id->oii_gen) {
		CDEBUG(D_INODE, "unmatched inode: ino = %u, oii_gen = %u, "
		       "i_generation = %u\n",
		       id->oii_ino, id->oii_gen, inode->i_generation);
		iput(inode);
		inode = ERR_PTR(-ESTALE);
	} else if (inode->i_nlink == 0) {
		/* due to parallel readdir and unlink,
		* we can have dead inode here. */
		CDEBUG(D_INODE, "stale inode: ino = %u\n", id->oii_ino);
		iput(inode);
		inode = ERR_PTR(-ESTALE);
	} else if (is_bad_inode(inode)) {
		CWARN("%.16s: bad inode: ino = %u\n",
		LDISKFS_SB(osd_sb(dev))->s_es->s_volume_name, id->oii_ino);
		iput(inode);
		inode = ERR_PTR(-ENOENT);
	} else {
		if (id->oii_gen == OSD_OII_NOGEN)
			osd_id_gen(id, inode->i_ino, inode->i_generation);

		/* Do not update file c/mtime in ldiskfs.
		 * NB: we don't have any lock to protect this because we don't
		 * have reference on osd_object now, but contention with
		 * another lookup + attr_set can't happen in the tiny window
		 * between if (...) and set S_NOCMTIME. */
		if (!(inode->i_flags & S_NOCMTIME))
			inode->i_flags |= S_NOCMTIME;
	}
	return inode;
}

static struct inode *
osd_iget_fid(struct osd_thread_info *info, struct osd_device *dev,
	     struct osd_inode_id *id, struct lu_fid *fid)
{
	struct lustre_mdt_attrs *lma   = &info->oti_mdt_attrs;
	struct inode		*inode;
	int			 rc;

	inode = osd_iget(info, dev, id);
	if (IS_ERR(inode))
		return inode;

	rc = osd_get_lma(info, inode, &info->oti_obj_dentry, lma);
	if (rc == 0) {
		*fid = lma->lma_self_fid;
	} else if (rc == -ENODATA) {
		if (unlikely(inode == osd_sb(dev)->s_root->d_inode))
			lu_local_obj_fid(fid, OSD_FS_ROOT_OID);
		else
			lu_igif_build(fid, inode->i_ino, inode->i_generation);
	} else {
		iput(inode);
		inode = ERR_PTR(rc);
	}
	return inode;
}

static struct inode *osd_iget_check(struct osd_thread_info *info,
				    struct osd_device *dev,
				    const struct lu_fid *fid,
				    struct osd_inode_id *id,
				    bool in_oi)
{
	struct inode	*inode;
	int		 rc	= 0;
	ENTRY;

	inode = ldiskfs_iget(osd_sb(dev), id->oii_ino);
	if (IS_ERR(inode)) {
		rc = PTR_ERR(inode);
		if (!in_oi || (rc != -ENOENT && rc != -ESTALE)) {
			CDEBUG(D_INODE, "no inode: ino = %u, rc = %d\n",
			       id->oii_ino, rc);

			GOTO(put, rc);
		}

		goto check_oi;
	}

	if (is_bad_inode(inode)) {
		rc = -ENOENT;
		if (!in_oi) {
			CDEBUG(D_INODE, "bad inode: ino = %u\n", id->oii_ino);

			GOTO(put, rc);
		}

		goto check_oi;
	}

	if (id->oii_gen != OSD_OII_NOGEN &&
	    inode->i_generation != id->oii_gen) {
		rc = -ESTALE;
		if (!in_oi) {
			CDEBUG(D_INODE, "unmatched inode: ino = %u, "
			       "oii_gen = %u, i_generation = %u\n",
			       id->oii_ino, id->oii_gen, inode->i_generation);

			GOTO(put, rc);
		}

		goto check_oi;
	}

	if (inode->i_nlink == 0) {
		rc = -ENOENT;
		if (!in_oi) {
			CDEBUG(D_INODE, "stale inode: ino = %u\n", id->oii_ino);

			GOTO(put, rc);
		}

		goto check_oi;
	}

check_oi:
	if (rc != 0) {
		LASSERTF(rc == -ESTALE || rc == -ENOENT, "rc = %d\n", rc);

		rc = osd_oi_lookup(info, dev, fid, id, OI_CHECK_FLD);
		/* XXX: There are three possible cases:
		 *	1. rc = 0.
		 *	   Backup/restore caused the OI invalid.
		 *	2. rc = 0.
		 *	   Someone unlinked the object but NOT removed
		 *	   the OI mapping, such as mount target device
		 *	   as ldiskfs, and modify something directly.
		 *	3. rc = -ENOENT.
		 *	   Someone just removed the object between the
		 *	   former oi_lookup and the iget. It is normal.
		 *	4. Other failure cases.
		 *
		 *	Generally, when the device is mounted, it will
		 *	auto check whether the system is restored from
		 *	file-level backup or not. We trust such detect
		 *	to distinguish the 1st case from the 2nd case. */
		if (rc == 0) {
			if (!IS_ERR(inode) && inode->i_generation != 0 &&
			    inode->i_generation == id->oii_gen)
				rc = -ENOENT;
			else
				rc = -EREMCHG;
		}
	} else {
		if (id->oii_gen == OSD_OII_NOGEN)
			osd_id_gen(id, inode->i_ino, inode->i_generation);

		/* Do not update file c/mtime in ldiskfs.
		 * NB: we don't have any lock to protect this because we don't
		 * have reference on osd_object now, but contention with
		 * another lookup + attr_set can't happen in the tiny window
		 * between if (...) and set S_NOCMTIME. */
		if (!(inode->i_flags & S_NOCMTIME))
			inode->i_flags |= S_NOCMTIME;
	}

	GOTO(put, rc);

put:
	if (rc != 0) {
		if (!IS_ERR(inode))
			iput(inode);

		inode = ERR_PTR(rc);
	}

	return inode;
}

/**
 * \retval +v: new filter_fid, does not contain self-fid
 * \retval 0:  filter_fid_old, contains self-fid
 * \retval -v: other failure cases
 */
int osd_get_idif(struct osd_thread_info *info, struct inode *inode,
		 struct dentry *dentry, struct lu_fid *fid)
{
	struct filter_fid_old	*ff	= &info->oti_ff;
	struct ost_id		*ostid	= &info->oti_ostid;
	int			 rc;

	rc = __osd_xattr_get(inode, dentry, XATTR_NAME_FID, ff, sizeof(*ff));
	if (rc == sizeof(*ff)) {
		rc = 0;
		ostid_set_seq(ostid, le64_to_cpu(ff->ff_seq));
		ostid_set_id(ostid, le64_to_cpu(ff->ff_objid));
		/* XXX: should use real OST index in the future. LU-3569 */
		ostid_to_fid(fid, ostid, 0);
	} else if (rc == sizeof(struct filter_fid)) {
		rc = 1;
	} else if (rc >= 0) {
		rc = -EINVAL;
	}

	return rc;
}

static int osd_check_lma(const struct lu_env *env, struct osd_object *obj)
{
	struct osd_thread_info	*info	= osd_oti_get(env);
	struct lustre_mdt_attrs	*lma	= &info->oti_mdt_attrs;
	struct inode		*inode	= obj->oo_inode;
	struct dentry		*dentry = &info->oti_obj_dentry;
	struct lu_fid		*fid	= NULL;
	int			 rc;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_OSD_COMPAT_INVALID_ENTRY))
		RETURN(0);

	CLASSERT(LMA_OLD_SIZE >= sizeof(*lma));
	rc = __osd_xattr_get(inode, dentry, XATTR_NAME_LMA,
			     info->oti_mdt_attrs_old, LMA_OLD_SIZE);
	if (rc == -ENODATA && !fid_is_igif(lu_object_fid(&obj->oo_dt.do_lu)) &&
	    osd_obj2dev(obj)->od_check_ff) {
		fid = &lma->lma_self_fid;
		rc = osd_get_idif(info, inode, dentry, fid);
		if (rc > 0)
			RETURN(0);
	}

	if (unlikely(rc == -ENODATA))
		RETURN(0);

	if (rc < 0)
		RETURN(rc);

	if (rc > 0) {
		rc = 0;
		lustre_lma_swab(lma);
		if (unlikely((lma->lma_incompat & ~LMA_INCOMPAT_SUPP) ||
			     CFS_FAIL_CHECK(OBD_FAIL_OSD_LMA_INCOMPAT))) {
			CWARN("%s: unsupported incompat LMA feature(s) %#x for "
			      "fid = "DFID", ino = %lu\n",
			      osd_obj2dev(obj)->od_svname,
			      lma->lma_incompat & ~LMA_INCOMPAT_SUPP,
			      PFID(lu_object_fid(&obj->oo_dt.do_lu)),
			      inode->i_ino);
			rc = -EOPNOTSUPP;
		} else if (!(lma->lma_compat & LMAC_NOT_IN_OI)) {
			fid = &lma->lma_self_fid;
		}
	}

	if (fid != NULL &&
	    unlikely(!lu_fid_eq(lu_object_fid(&obj->oo_dt.do_lu), fid))) {
		CDEBUG(D_INODE, "%s: FID "DFID" != self_fid "DFID"\n",
		       osd_obj2dev(obj)->od_svname,
		       PFID(lu_object_fid(&obj->oo_dt.do_lu)),
		       PFID(&lma->lma_self_fid));
		rc = -EREMCHG;
	}

	RETURN(rc);
}

static int osd_fid_lookup(const struct lu_env *env, struct osd_object *obj,
			  const struct lu_fid *fid,
			  const struct lu_object_conf *conf)
{
	struct osd_thread_info *info;
	struct lu_device       *ldev   = obj->oo_dt.do_lu.lo_dev;
	struct osd_device      *dev;
	struct osd_idmap_cache *oic;
	struct osd_inode_id    *id;
	struct inode	       *inode;
	struct osd_scrub       *scrub;
	struct scrub_file      *sf;
	int			result;
	int			saved  = 0;
	bool			in_oi  = false;
	bool			triggered = false;
	ENTRY;

	LINVRNT(osd_invariant(obj));
	LASSERT(obj->oo_inode == NULL);
	LASSERTF(fid_is_sane(fid) || fid_is_idif(fid), DFID, PFID(fid));

	dev = osd_dev(ldev);
	scrub = &dev->od_scrub;
	sf = &scrub->os_file;
	info = osd_oti_get(env);
	LASSERT(info);
	oic = &info->oti_cache;

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT))
		RETURN(-ENOENT);

	/* For the object is created as locking anchor, or for the object to
	 * be created on disk. No need to osd_oi_lookup() at here because FID
	 * shouldn't never be re-used, if it's really a duplicate FID from
	 * unexpected reason, we should be able to detect it later by calling
	 * do_create->osd_oi_insert(). */
	if (conf != NULL && conf->loc_flags & LOC_F_NEW)
		GOTO(out, result = 0);

	/* Search order: 1. per-thread cache. */
	if (lu_fid_eq(fid, &oic->oic_fid) &&
	    likely(oic->oic_dev == dev)) {
		id = &oic->oic_lid;
		goto iget;
	}

	id = &info->oti_id;
	if (!cfs_list_empty(&scrub->os_inconsistent_items)) {
		/* Search order: 2. OI scrub pending list. */
		result = osd_oii_lookup(dev, fid, id);
		if (result == 0)
			goto iget;
	}

	/* Search order: 3. OI files. */
	result = osd_oi_lookup(info, dev, fid, id, OI_CHECK_FLD);
	if (result == -ENOENT) {
		if (!fid_is_norm(fid) ||
		    fid_is_on_ost(info, dev, fid, OI_CHECK_FLD) ||
		    !ldiskfs_test_bit(osd_oi_fid2idx(dev,fid),
				      sf->sf_oi_bitmap))
			GOTO(out, result = 0);

		goto trigger;
	}

	if (result != 0)
		GOTO(out, result);

	in_oi = true;

iget:
	inode = osd_iget_check(info, dev, fid, id, in_oi);
	if (IS_ERR(inode)) {
		result = PTR_ERR(inode);
		if (result == -ENOENT || result == -ESTALE) {
			if (!in_oi)
				fid_zero(&oic->oic_fid);

			GOTO(out, result = -ENOENT);
		} else if (result == -EREMCHG) {

trigger:
			if (!in_oi)
				fid_zero(&oic->oic_fid);

			if (unlikely(triggered))
				GOTO(out, result = saved);

			triggered = true;
			if (thread_is_running(&scrub->os_thread)) {
				result = -EINPROGRESS;
			} else if (!dev->od_noscrub) {
				result = osd_scrub_start(dev);
				LCONSOLE_WARN("%.16s: trigger OI scrub by RPC "
					      "for "DFID", rc = %d [1]\n",
					      osd_name(dev), PFID(fid), result);
				if (result == 0 || result == -EALREADY)
					result = -EINPROGRESS;
				else
					result = -EREMCHG;
			}

			/* We still have chance to get the valid inode: for the
			 * object which is referenced by remote name entry, the
			 * object on the local MDT will be linked under the dir
			 * of "/REMOTE_PARENT_DIR" with its FID string as name.
			 *
			 * We do not know whether the object for the given FID
			 * is referenced by some remote name entry or not, and
			 * especially for DNE II, a multiple-linked object may
			 * have many name entries reside on many MDTs.
			 *
			 * To simplify the operation, OSD will not distinguish
			 * more, just lookup "/REMOTE_PARENT_DIR". Usually, it
			 * only happened for the RPC from other MDT during the
			 * OI scrub, or for the client side RPC with FID only,
			 * such as FID to path, or from old connected client. */
			saved = result;
			result = osd_lookup_in_remote_parent(info, dev,
							     fid, id);
			if (result == 0) {
				in_oi = false;
				goto iget;
			}

			result = saved;
		}

                GOTO(out, result);
        }

        obj->oo_inode = inode;
        LASSERT(obj->oo_inode->i_sb == osd_sb(dev));

	result = osd_check_lma(env, obj);
	if (result != 0) {
		iput(inode);
		obj->oo_inode = NULL;
		if (result == -EREMCHG) {
			if (!in_oi) {
				result = osd_oi_lookup(info, dev, fid, id,
						       OI_CHECK_FLD);
				if (result != 0) {
					fid_zero(&oic->oic_fid);
					GOTO(out, result);
				}
			}

			goto trigger;
		}

		GOTO(out, result);
	}

	obj->oo_compat_dot_created = 1;
	obj->oo_compat_dotdot_created = 1;

        if (!S_ISDIR(inode->i_mode) || !ldiskfs_pdo) /* done */
		GOTO(out, result = 0);

	LASSERT(obj->oo_hl_head == NULL);
	obj->oo_hl_head = ldiskfs_htree_lock_head_alloc(HTREE_HBITS_DEF);
	if (obj->oo_hl_head == NULL) {
		obj->oo_inode = NULL;
		iput(inode);
		GOTO(out, result = -ENOMEM);
	}
	GOTO(out, result = 0);

out:
	LINVRNT(osd_invariant(obj));
	return result;
}

/*
 * Concurrency: shouldn't matter.
 */
static void osd_object_init0(struct osd_object *obj)
{
        LASSERT(obj->oo_inode != NULL);
        obj->oo_dt.do_body_ops = &osd_body_ops;
        obj->oo_dt.do_lu.lo_header->loh_attr |=
                (LOHA_EXISTS | (obj->oo_inode->i_mode & S_IFMT));
}

/*
 * Concurrency: no concurrent access is possible that early in object
 * life-cycle.
 */
static int osd_object_init(const struct lu_env *env, struct lu_object *l,
			   const struct lu_object_conf *conf)
{
	struct osd_object *obj = osd_obj(l);
	int result;

	LINVRNT(osd_invariant(obj));

	if (fid_is_otable_it(&l->lo_header->loh_fid)) {
		obj->oo_dt.do_ops = &osd_obj_otable_it_ops;
		l->lo_header->loh_attr |= LOHA_EXISTS;
		return 0;
	}

	result = osd_fid_lookup(env, obj, lu_object_fid(l), conf);
	obj->oo_dt.do_body_ops = &osd_body_ops_new;
	if (result == 0 && obj->oo_inode != NULL)
		osd_object_init0(obj);

	LINVRNT(osd_invariant(obj));
	return result;
}

/*
 * Concurrency: no concurrent access is possible that late in object
 * life-cycle.
 */
static void osd_object_free(const struct lu_env *env, struct lu_object *l)
{
        struct osd_object *obj = osd_obj(l);

        LINVRNT(osd_invariant(obj));

        dt_object_fini(&obj->oo_dt);
        if (obj->oo_hl_head != NULL)
                ldiskfs_htree_lock_head_free(obj->oo_hl_head);
        OBD_FREE_PTR(obj);
}

/*
 * Concurrency: no concurrent access is possible that late in object
 * life-cycle.
 */
static void osd_index_fini(struct osd_object *o)
{
        struct iam_container *bag;

        if (o->oo_dir != NULL) {
                bag = &o->oo_dir->od_container;
                if (o->oo_inode != NULL) {
                        if (bag->ic_object == o->oo_inode)
                                iam_container_fini(bag);
                }
                OBD_FREE_PTR(o->oo_dir);
                o->oo_dir = NULL;
        }
}

/*
 * Concurrency: no concurrent access is possible that late in object
 * life-cycle (for all existing callers, that is. New callers have to provide
 * their own locking.)
 */
static int osd_inode_unlinked(const struct inode *inode)
{
        return inode->i_nlink == 0;
}

enum {
        OSD_TXN_OI_DELETE_CREDITS    = 20,
        OSD_TXN_INODE_DELETE_CREDITS = 20
};

/*
 * Journal
 */

#if OSD_THANDLE_STATS
/**
 * Set time when the handle is allocated
 */
static void osd_th_alloced(struct osd_thandle *oth)
{
        oth->oth_alloced = cfs_time_current();
}

/**
 * Set time when the handle started
 */
static void osd_th_started(struct osd_thandle *oth)
{
        oth->oth_started = cfs_time_current();
}

/**
 * Helper function to convert time interval to microseconds packed in
 * long int.
 */
static long interval_to_usec(cfs_time_t start, cfs_time_t end)
{
        struct timeval val;

        cfs_duration_usec(cfs_time_sub(end, start), &val);
        return val.tv_sec * 1000000 + val.tv_usec;
}

/**
 * Check whether the we deal with this handle for too long.
 */
static void __osd_th_check_slow(void *oth, struct osd_device *dev,
                                cfs_time_t alloced, cfs_time_t started,
                                cfs_time_t closed)
{
        cfs_time_t now = cfs_time_current();

        LASSERT(dev != NULL);

        lprocfs_counter_add(dev->od_stats, LPROC_OSD_THANDLE_STARTING,
                            interval_to_usec(alloced, started));
        lprocfs_counter_add(dev->od_stats, LPROC_OSD_THANDLE_OPEN,
                            interval_to_usec(started, closed));
        lprocfs_counter_add(dev->od_stats, LPROC_OSD_THANDLE_CLOSING,
                            interval_to_usec(closed, now));

        if (cfs_time_before(cfs_time_add(alloced, cfs_time_seconds(30)), now)) {
                CWARN("transaction handle %p was open for too long: "
                      "now "CFS_TIME_T" ,"
                      "alloced "CFS_TIME_T" ,"
                      "started "CFS_TIME_T" ,"
                      "closed "CFS_TIME_T"\n",
                      oth, now, alloced, started, closed);
                libcfs_debug_dumpstack(NULL);
        }
}

#define OSD_CHECK_SLOW_TH(oth, dev, expr)                               \
{                                                                       \
        cfs_time_t __closed = cfs_time_current();                       \
        cfs_time_t __alloced = oth->oth_alloced;                        \
        cfs_time_t __started = oth->oth_started;                        \
                                                                        \
        expr;                                                           \
        __osd_th_check_slow(oth, dev, __alloced, __started, __closed);  \
}

#else /* OSD_THANDLE_STATS */

#define osd_th_alloced(h)                  do {} while(0)
#define osd_th_started(h)                  do {} while(0)
#define OSD_CHECK_SLOW_TH(oth, dev, expr)  expr

#endif /* OSD_THANDLE_STATS */

/*
 * Concurrency: doesn't access mutable data.
 */
static int osd_param_is_not_sane(const struct osd_device *dev,
				 const struct thandle *th)
{
	struct osd_thandle *oh = container_of(th, typeof(*oh), ot_super);

	return oh->ot_credits > osd_journal(dev)->j_max_transaction_buffers;
}

/*
 * Concurrency: shouldn't matter.
 */
static void osd_trans_commit_cb(struct super_block *sb,
                                struct ldiskfs_journal_cb_entry *jcb, int error)
{
        struct osd_thandle *oh = container_of0(jcb, struct osd_thandle, ot_jcb);
        struct thandle     *th  = &oh->ot_super;
        struct lu_device   *lud = &th->th_dev->dd_lu_dev;
        struct dt_txn_commit_cb *dcb, *tmp;

        LASSERT(oh->ot_handle == NULL);

        if (error)
                CERROR("transaction @0x%p commit error: %d\n", th, error);

        dt_txn_hook_commit(th);

	/* call per-transaction callbacks if any */
	cfs_list_for_each_entry_safe(dcb, tmp, &oh->ot_dcb_list, dcb_linkage) {
		LASSERTF(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC,
			 "commit callback entry: magic=%x name='%s'\n",
			 dcb->dcb_magic, dcb->dcb_name);
		cfs_list_del_init(&dcb->dcb_linkage);
		dcb->dcb_func(NULL, th, dcb, error);
	}

	lu_ref_del_at(&lud->ld_reference, &oh->ot_dev_link, "osd-tx", th);
        lu_device_put(lud);
        th->th_dev = NULL;

        lu_context_exit(&th->th_ctx);
        lu_context_fini(&th->th_ctx);
        OBD_FREE_PTR(oh);
}

static struct thandle *osd_trans_create(const struct lu_env *env,
                                        struct dt_device *d)
{
        struct osd_thread_info *oti = osd_oti_get(env);
        struct osd_iobuf       *iobuf = &oti->oti_iobuf;
        struct osd_thandle     *oh;
        struct thandle         *th;
        ENTRY;

        /* on pending IO in this thread should left from prev. request */
        LASSERT(cfs_atomic_read(&iobuf->dr_numreqs) == 0);

	th = ERR_PTR(-ENOMEM);
	OBD_ALLOC_GFP(oh, sizeof *oh, GFP_NOFS);
	if (oh != NULL) {
		oh->ot_quota_trans = &oti->oti_quota_trans;
		memset(oh->ot_quota_trans, 0, sizeof(*oh->ot_quota_trans));
		th = &oh->ot_super;
		th->th_dev = d;
		th->th_result = 0;
		th->th_tags = LCT_TX_HANDLE;
		oh->ot_credits = 0;
		oti->oti_dev = osd_dt_dev(d);
		CFS_INIT_LIST_HEAD(&oh->ot_dcb_list);
		osd_th_alloced(oh);

		memset(oti->oti_declare_ops, 0,
					sizeof(oti->oti_declare_ops));
		memset(oti->oti_declare_ops_rb, 0,
					sizeof(oti->oti_declare_ops_rb));
		memset(oti->oti_declare_ops_cred, 0,
					sizeof(oti->oti_declare_ops_cred));
		oti->oti_rollback = false;
	}
	RETURN(th);
}

/*
 * Concurrency: shouldn't matter.
 */
int osd_trans_start(const struct lu_env *env, struct dt_device *d,
                    struct thandle *th)
{
        struct osd_thread_info *oti = osd_oti_get(env);
        struct osd_device  *dev = osd_dt_dev(d);
        handle_t           *jh;
        struct osd_thandle *oh;
        int rc;

        ENTRY;

        LASSERT(current->journal_info == NULL);

        oh = container_of0(th, struct osd_thandle, ot_super);
        LASSERT(oh != NULL);
        LASSERT(oh->ot_handle == NULL);

        rc = dt_txn_hook_start(env, d, th);
        if (rc != 0)
                GOTO(out, rc);

	if (unlikely(osd_param_is_not_sane(dev, th))) {
		static unsigned long last_printed;
		static int last_credits;

		CWARN("%.16s: too many transaction credits (%d > %d)\n",
		      LDISKFS_SB(osd_sb(dev))->s_es->s_volume_name,
		      oh->ot_credits,
		      osd_journal(dev)->j_max_transaction_buffers);
		CWARN("  create: %u/%u, destroy: %u/%u\n",
		      oti->oti_declare_ops[OSD_OT_CREATE],
		      oti->oti_declare_ops_cred[OSD_OT_CREATE],
		      oti->oti_declare_ops[OSD_OT_DESTROY],
		      oti->oti_declare_ops_cred[OSD_OT_DESTROY]);
		CWARN("  attr_set: %u/%u, xattr_set: %u/%u\n",
		      oti->oti_declare_ops[OSD_OT_ATTR_SET],
		      oti->oti_declare_ops_cred[OSD_OT_ATTR_SET],
		      oti->oti_declare_ops[OSD_OT_XATTR_SET],
		      oti->oti_declare_ops_cred[OSD_OT_XATTR_SET]);
		CWARN("  write: %u/%u, punch: %u/%u, quota %u/%u\n",
		      oti->oti_declare_ops[OSD_OT_WRITE],
		      oti->oti_declare_ops_cred[OSD_OT_WRITE],
		      oti->oti_declare_ops[OSD_OT_PUNCH],
		      oti->oti_declare_ops_cred[OSD_OT_PUNCH],
		      oti->oti_declare_ops[OSD_OT_QUOTA],
		      oti->oti_declare_ops_cred[OSD_OT_QUOTA]);
		CWARN("  insert: %u/%u, delete: %u/%u\n",
		      oti->oti_declare_ops[OSD_OT_INSERT],
		      oti->oti_declare_ops_cred[OSD_OT_INSERT],
		      oti->oti_declare_ops[OSD_OT_DELETE],
		      oti->oti_declare_ops_cred[OSD_OT_DELETE]);
		CWARN("  ref_add: %u/%u, ref_del: %u/%u\n",
		      oti->oti_declare_ops[OSD_OT_REF_ADD],
		      oti->oti_declare_ops_cred[OSD_OT_REF_ADD],
		      oti->oti_declare_ops[OSD_OT_REF_DEL],
		      oti->oti_declare_ops_cred[OSD_OT_REF_DEL]);

		if (last_credits != oh->ot_credits &&
		    time_after(jiffies, last_printed + 60 * HZ)) {
			libcfs_debug_dumpstack(NULL);
			last_credits = oh->ot_credits;
			last_printed = jiffies;
		}
		/* XXX Limit the credits to 'max_transaction_buffers', and
		 *     let the underlying filesystem to catch the error if
		 *     we really need so many credits.
		 *
		 *     This should be removed when we can calculate the
		 *     credits precisely. */
		oh->ot_credits = osd_journal(dev)->j_max_transaction_buffers;
	}

        /*
         * XXX temporary stuff. Some abstraction layer should
         * be used.
         */
        jh = osd_journal_start_sb(osd_sb(dev), LDISKFS_HT_MISC, oh->ot_credits);
        osd_th_started(oh);
        if (!IS_ERR(jh)) {
                oh->ot_handle = jh;
                LASSERT(oti->oti_txns == 0);
                lu_context_init(&th->th_ctx, th->th_tags);
                lu_context_enter(&th->th_ctx);

                lu_device_get(&d->dd_lu_dev);
		lu_ref_add_at(&d->dd_lu_dev.ld_reference, &oh->ot_dev_link,
			      "osd-tx", th);
                oti->oti_txns++;
                rc = 0;
        } else {
                rc = PTR_ERR(jh);
        }
out:
        RETURN(rc);
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_trans_stop(const struct lu_env *env, struct thandle *th)
{
	int                     rc = 0;
	struct osd_thandle     *oh;
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_iobuf       *iobuf = &oti->oti_iobuf;
	struct qsd_instance    *qsd = oti->oti_dev->od_quota_slave;
	struct lquota_trans    *qtrans;
	ENTRY;

	oh = container_of0(th, struct osd_thandle, ot_super);

	qtrans = oh->ot_quota_trans;
	oh->ot_quota_trans = NULL;

        if (oh->ot_handle != NULL) {
                handle_t *hdl = oh->ot_handle;

                /*
                 * add commit callback
                 * notice we don't do this in osd_trans_start()
                 * as underlying transaction can change during truncate
                 */
                ldiskfs_journal_callback_add(hdl, osd_trans_commit_cb,
                                         &oh->ot_jcb);

                LASSERT(oti->oti_txns == 1);
                oti->oti_txns--;
                rc = dt_txn_hook_stop(env, th);
                if (rc != 0)
                        CERROR("Failure in transaction hook: %d\n", rc);

		/* hook functions might modify th_sync */
		hdl->h_sync = th->th_sync;

                oh->ot_handle = NULL;
                OSD_CHECK_SLOW_TH(oh, oti->oti_dev,
                                  rc = ldiskfs_journal_stop(hdl));
                if (rc != 0)
                        CERROR("Failure to stop transaction: %d\n", rc);
        } else {
                OBD_FREE_PTR(oh);
        }

	/* inform the quota slave device that the transaction is stopping */
	qsd_op_end(env, qsd, qtrans);

	/* as we want IO to journal and data IO be concurrent, we don't block
	 * awaiting data IO completion in osd_do_bio(), instead we wait here
	 * once transaction is submitted to the journal. all reqular requests
	 * don't do direct IO (except read/write), thus this wait_event becomes
	 * no-op for them.
	 *
	 * IMPORTANT: we have to wait till any IO submited by the thread is
	 * completed otherwise iobuf may be corrupted by different request
	 */
	wait_event(iobuf->dr_wait,
		       cfs_atomic_read(&iobuf->dr_numreqs) == 0);
	osd_fini_iobuf(oti->oti_dev, iobuf);
	if (!rc)
		rc = iobuf->dr_error;

	RETURN(rc);
}

static int osd_trans_cb_add(struct thandle *th, struct dt_txn_commit_cb *dcb)
{
	struct osd_thandle *oh = container_of0(th, struct osd_thandle,
					       ot_super);

	LASSERT(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC);
	LASSERT(&dcb->dcb_func != NULL);
	cfs_list_add(&dcb->dcb_linkage, &oh->ot_dcb_list);

	return 0;
}

/*
 * Called just before object is freed. Releases all resources except for
 * object itself (that is released by osd_object_free()).
 *
 * Concurrency: no concurrent access is possible that late in object
 * life-cycle.
 */
static void osd_object_delete(const struct lu_env *env, struct lu_object *l)
{
        struct osd_object *obj   = osd_obj(l);
        struct inode      *inode = obj->oo_inode;

        LINVRNT(osd_invariant(obj));

        /*
         * If object is unlinked remove fid->ino mapping from object index.
         */

        osd_index_fini(obj);
        if (inode != NULL) {
		struct qsd_instance	*qsd = osd_obj2dev(obj)->od_quota_slave;
		qid_t			 uid = inode->i_uid;
		qid_t			 gid = inode->i_gid;

                iput(inode);
                obj->oo_inode = NULL;

		if (qsd != NULL) {
			struct osd_thread_info	*info = osd_oti_get(env);
			struct lquota_id_info	*qi = &info->oti_qi;

			/* Release granted quota to master if necessary */
			qi->lqi_id.qid_uid = uid;
			qsd_op_adjust(env, qsd, &qi->lqi_id, USRQUOTA);

			qi->lqi_id.qid_uid = gid;
			qsd_op_adjust(env, qsd, &qi->lqi_id, GRPQUOTA);
		}
        }
}

/*
 * Concurrency: ->loo_object_release() is called under site spin-lock.
 */
static void osd_object_release(const struct lu_env *env,
                               struct lu_object *l)
{
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *l)
{
        struct osd_object *o = osd_obj(l);
        struct iam_descr  *d;

        if (o->oo_dir != NULL)
                d = o->oo_dir->od_container.ic_descr;
        else
                d = NULL;
	return (*p)(env, cookie,
		    LUSTRE_OSD_LDISKFS_NAME"-object@%p(i:%p:%lu/%u)[%s]",
                    o, o->oo_inode,
                    o->oo_inode ? o->oo_inode->i_ino : 0UL,
                    o->oo_inode ? o->oo_inode->i_generation : 0,
                    d ? d->id_ops->id_name : "plain");
}

/*
 * Concurrency: shouldn't matter.
 */
int osd_statfs(const struct lu_env *env, struct dt_device *d,
               struct obd_statfs *sfs)
{
        struct osd_device  *osd = osd_dt_dev(d);
        struct super_block *sb = osd_sb(osd);
        struct kstatfs     *ksfs;
        int result = 0;

	if (unlikely(osd->od_mnt == NULL))
		return -EINPROGRESS;

        /* osd_lproc.c call this without env, allocate ksfs for that case */
        if (unlikely(env == NULL)) {
                OBD_ALLOC_PTR(ksfs);
                if (ksfs == NULL)
                        return -ENOMEM;
        } else {
                ksfs = &osd_oti_get(env)->oti_ksfs;
        }

	spin_lock(&osd->od_osfs_lock);
	/* cache 1 second */
	if (cfs_time_before_64(osd->od_osfs_age, cfs_time_shift_64(-1))) {
		result = sb->s_op->statfs(sb->s_root, ksfs);
		if (likely(result == 0)) { /* N.B. statfs can't really fail */
			osd->od_osfs_age = cfs_time_current_64();
			statfs_pack(&osd->od_statfs, ksfs);
			if (sb->s_flags & MS_RDONLY)
				sfs->os_state = OS_STATE_READONLY;
		}
	}

	if (likely(result == 0))
		*sfs = osd->od_statfs;
	spin_unlock(&osd->od_osfs_lock);

        if (unlikely(env == NULL))
                OBD_FREE_PTR(ksfs);

        return result;
}

/**
 * Estimate space needed for file creations. We assume the largest filename
 * which is 2^64 - 1, hence a filename of 20 chars.
 * This is 28 bytes per object which is 28MB for 1M objects ... no so bad.
 */
#ifdef __LDISKFS_DIR_REC_LEN
#define PER_OBJ_USAGE __LDISKFS_DIR_REC_LEN(20)
#else
#define PER_OBJ_USAGE LDISKFS_DIR_REC_LEN(20)
#endif

/*
 * Concurrency: doesn't access mutable data.
 */
static void osd_conf_get(const struct lu_env *env,
                         const struct dt_device *dev,
                         struct dt_device_param *param)
{
        struct super_block *sb = osd_sb(osd_dt_dev(dev));
	int		   ea_overhead;

        /*
         * XXX should be taken from not-yet-existing fs abstraction layer.
         */
        param->ddp_max_name_len = LDISKFS_NAME_LEN;
        param->ddp_max_nlink    = LDISKFS_LINK_MAX;
	param->ddp_block_shift  = sb->s_blocksize_bits;
	param->ddp_mount_type     = LDD_MT_LDISKFS;
	param->ddp_maxbytes       = sb->s_maxbytes;
	/* Overhead estimate should be fairly accurate, so we really take a tiny
	 * error margin which also avoids fragmenting the filesystem too much */
	param->ddp_grant_reserved = 2; /* end up to be 1.9% after conversion */
	/* inode are statically allocated, so per-inode space consumption
	 * is the space consumed by the directory entry */
	param->ddp_inodespace     = PER_OBJ_USAGE;
	/* per-fragment overhead to be used by the client code */
	param->ddp_grant_frag     = 6 * LDISKFS_BLOCK_SIZE(sb);
        param->ddp_mntopts      = 0;
        if (test_opt(sb, XATTR_USER))
                param->ddp_mntopts |= MNTOPT_USERXATTR;
        if (test_opt(sb, POSIX_ACL))
                param->ddp_mntopts |= MNTOPT_ACL;

	/* LOD might calculate the max stripe count based on max_ea_size,
	 * so we need take account in the overhead as well,
	 * xattr_header + magic + xattr_entry_head */
	ea_overhead = sizeof(struct ldiskfs_xattr_header) + sizeof(__u32) +
		      LDISKFS_XATTR_LEN(XATTR_NAME_MAX_LEN);

#if defined(LDISKFS_FEATURE_INCOMPAT_EA_INODE)
	if (LDISKFS_HAS_INCOMPAT_FEATURE(sb, LDISKFS_FEATURE_INCOMPAT_EA_INODE))
		param->ddp_max_ea_size = LDISKFS_XATTR_MAX_LARGE_EA_SIZE -
								ea_overhead;
	else
#endif
		param->ddp_max_ea_size = sb->s_blocksize - ea_overhead;
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_sync(const struct lu_env *env, struct dt_device *d)
{
	CDEBUG(D_HA, "syncing OSD %s\n", LUSTRE_OSD_LDISKFS_NAME);
        return ldiskfs_force_commit(osd_sb(osd_dt_dev(d)));
}

/**
 * Start commit for OSD device.
 *
 * An implementation of dt_commit_async method for OSD device.
 * Asychronously starts underlayng fs sync and thereby a transaction
 * commit.
 *
 * \param env environment
 * \param d dt device
 *
 * \see dt_device_operations
 */
static int osd_commit_async(const struct lu_env *env,
                            struct dt_device *d)
{
        struct super_block *s = osd_sb(osd_dt_dev(d));
        ENTRY;

	CDEBUG(D_HA, "async commit OSD %s\n", LUSTRE_OSD_LDISKFS_NAME);
        RETURN(s->s_op->sync_fs(s, 0));
}

/*
 * Concurrency: shouldn't matter.
 */

static int osd_ro(const struct lu_env *env, struct dt_device *d)
{
	struct super_block *sb = osd_sb(osd_dt_dev(d));
	struct block_device *dev = sb->s_bdev;
#ifdef HAVE_DEV_SET_RDONLY
	struct block_device *jdev = LDISKFS_SB(sb)->journal_bdev;
	int rc = 0;
#else
	int rc = -EOPNOTSUPP;
#endif
	ENTRY;

#ifdef HAVE_DEV_SET_RDONLY
	CERROR("*** setting %s read-only ***\n", osd_dt_dev(d)->od_svname);

	if (jdev && (jdev != dev)) {
		CDEBUG(D_IOCTL | D_HA, "set journal dev %lx rdonly\n",
		       (long)jdev);
		dev_set_rdonly(jdev);
	}
	CDEBUG(D_IOCTL | D_HA, "set dev %lx rdonly\n", (long)dev);
	dev_set_rdonly(dev);
#else
	CERROR("%s: %lx CANNOT BE SET READONLY: rc = %d\n",
	       osd_dt_dev(d)->od_svname, (long)dev, rc);
#endif
	RETURN(rc);
}

/*
 * Concurrency: serialization provided by callers.
 */
static int osd_init_capa_ctxt(const struct lu_env *env, struct dt_device *d,
                              int mode, unsigned long timeout, __u32 alg,
                              struct lustre_capa_key *keys)
{
        struct osd_device *dev = osd_dt_dev(d);
        ENTRY;

        dev->od_fl_capa = mode;
        dev->od_capa_timeout = timeout;
        dev->od_capa_alg = alg;
        dev->od_capa_keys = keys;
        RETURN(0);
}

/**
 * Note: we do not count into QUOTA here.
 * If we mount with --data_journal we may need more.
 */
const int osd_dto_credits_noquota[DTO_NR] = {
	/**
	 * Insert.
	 * INDEX_EXTRA_TRANS_BLOCKS(8) +
	 * SINGLEDATA_TRANS_BLOCKS(8)
	 * XXX Note: maybe iam need more, since iam have more level than
	 *           EXT3 htree.
	 */
	[DTO_INDEX_INSERT]  = 16,
	/**
	 * Delete
	 * just modify a single entry, probably merge few within a block
	 */
	[DTO_INDEX_DELETE]  = 1,
	/**
	 * Used for OI scrub
	 */
	[DTO_INDEX_UPDATE]  = 16,
	/**
	 * 4(inode, inode bits, groups, GDT)
	 *   notice: OI updates are counted separately with DTO_INDEX_INSERT
	 */
	[DTO_OBJECT_CREATE] = 4,
	/**
	 * 4(inode, inode bits, groups, GDT)
	 *   notice: OI updates are counted separately with DTO_INDEX_DELETE
	 */
	[DTO_OBJECT_DELETE] = 4,
	/**
	 * Attr set credits (inode)
	 */
	[DTO_ATTR_SET_BASE] = 1,
	/**
	 * Xattr set. The same as xattr of EXT3.
	 * DATA_TRANS_BLOCKS(14)
	 * XXX Note: in original MDS implmentation INDEX_EXTRA_TRANS_BLOCKS
	 * are also counted in. Do not know why?
	 */
	[DTO_XATTR_SET]     = 14,
	/**
	 * credits for inode change during write.
	 */
	[DTO_WRITE_BASE]    = 3,
	/**
	 * credits for single block write.
	 */
	[DTO_WRITE_BLOCK]   = 14,
	/**
	 * Attr set credits for chown.
	 * This is extra credits for setattr, and it is null without quota
	 */
	[DTO_ATTR_SET_CHOWN] = 0
};

static const struct dt_device_operations osd_dt_ops = {
        .dt_root_get       = osd_root_get,
        .dt_statfs         = osd_statfs,
        .dt_trans_create   = osd_trans_create,
        .dt_trans_start    = osd_trans_start,
        .dt_trans_stop     = osd_trans_stop,
        .dt_trans_cb_add   = osd_trans_cb_add,
        .dt_conf_get       = osd_conf_get,
        .dt_sync           = osd_sync,
        .dt_ro             = osd_ro,
        .dt_commit_async   = osd_commit_async,
        .dt_init_capa_ctxt = osd_init_capa_ctxt,
};

static void osd_object_read_lock(const struct lu_env *env,
                                 struct dt_object *dt, unsigned role)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_thread_info *oti = osd_oti_get(env);

        LINVRNT(osd_invariant(obj));

        LASSERT(obj->oo_owner != env);
	down_read_nested(&obj->oo_sem, role);

        LASSERT(obj->oo_owner == NULL);
        oti->oti_r_locks++;
}

static void osd_object_write_lock(const struct lu_env *env,
                                  struct dt_object *dt, unsigned role)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_thread_info *oti = osd_oti_get(env);

        LINVRNT(osd_invariant(obj));

        LASSERT(obj->oo_owner != env);
	down_write_nested(&obj->oo_sem, role);

        LASSERT(obj->oo_owner == NULL);
        obj->oo_owner = env;
        oti->oti_w_locks++;
}

static void osd_object_read_unlock(const struct lu_env *env,
                                   struct dt_object *dt)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_thread_info *oti = osd_oti_get(env);

        LINVRNT(osd_invariant(obj));

        LASSERT(oti->oti_r_locks > 0);
        oti->oti_r_locks--;
	up_read(&obj->oo_sem);
}

static void osd_object_write_unlock(const struct lu_env *env,
                                    struct dt_object *dt)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_thread_info *oti = osd_oti_get(env);

        LINVRNT(osd_invariant(obj));

        LASSERT(obj->oo_owner == env);
        LASSERT(oti->oti_w_locks > 0);
        oti->oti_w_locks--;
        obj->oo_owner = NULL;
	up_write(&obj->oo_sem);
}

static int osd_object_write_locked(const struct lu_env *env,
                                   struct dt_object *dt)
{
        struct osd_object *obj = osd_dt_obj(dt);

        LINVRNT(osd_invariant(obj));

        return obj->oo_owner == env;
}

static int capa_is_sane(const struct lu_env *env,
                        struct osd_device *dev,
                        struct lustre_capa *capa,
                        struct lustre_capa_key *keys)
{
        struct osd_thread_info *oti = osd_oti_get(env);
        struct lustre_capa *tcapa = &oti->oti_capa;
        struct obd_capa *oc;
        int i, rc = 0;
        ENTRY;

        oc = capa_lookup(dev->od_capa_hash, capa, 0);
        if (oc) {
                if (capa_is_expired(oc)) {
                        DEBUG_CAPA(D_ERROR, capa, "expired");
                        rc = -ESTALE;
                }
                capa_put(oc);
                RETURN(rc);
        }

        if (capa_is_expired_sec(capa)) {
                DEBUG_CAPA(D_ERROR, capa, "expired");
                RETURN(-ESTALE);
        }

	spin_lock(&capa_lock);
	for (i = 0; i < 2; i++) {
		if (keys[i].lk_keyid == capa->lc_keyid) {
			oti->oti_capa_key = keys[i];
			break;
		}
	}
	spin_unlock(&capa_lock);

        if (i == 2) {
                DEBUG_CAPA(D_ERROR, capa, "no matched capa key");
                RETURN(-ESTALE);
        }

        rc = capa_hmac(tcapa->lc_hmac, capa, oti->oti_capa_key.lk_key);
        if (rc)
                RETURN(rc);

        if (memcmp(tcapa->lc_hmac, capa->lc_hmac, sizeof(capa->lc_hmac))) {
                DEBUG_CAPA(D_ERROR, capa, "HMAC mismatch");
                RETURN(-EACCES);
        }

        oc = capa_add(dev->od_capa_hash, capa);
        capa_put(oc);

        RETURN(0);
}

int osd_object_auth(const struct lu_env *env, struct dt_object *dt,
		    struct lustre_capa *capa, __u64 opc)
{
	const struct lu_fid *fid = lu_object_fid(&dt->do_lu);
	struct osd_device *osd = osd_dev(dt->do_lu.lo_dev);
	struct lu_capainfo *lci;
	int rc;

	if (!osd->od_fl_capa)
		return 0;

	if (capa == BYPASS_CAPA)
		return 0;

	lci = lu_capainfo_get(env);
	if (unlikely(lci == NULL))
		return 0;

	if (lci->lci_auth == LC_ID_NONE)
		return 0;

	if (capa == NULL) {
		CERROR("%s: no capability provided for FID "DFID": rc = %d\n",
		       osd_name(osd), PFID(fid), -EACCES);
		return -EACCES;
	}

	if (!lu_fid_eq(fid, &capa->lc_fid)) {
		DEBUG_CAPA(D_ERROR, capa, "fid "DFID" mismatch with",
			   PFID(fid));
		return -EACCES;
	}

	if (!capa_opc_supported(capa, opc)) {
		DEBUG_CAPA(D_ERROR, capa, "opc "LPX64" not supported by", opc);
		return -EACCES;
	}

	rc = capa_is_sane(env, osd, capa, osd->od_capa_keys);
	if (rc != 0) {
		DEBUG_CAPA(D_ERROR, capa, "insane: rc = %d", rc);
		return -EACCES;
	}

	return 0;
}

static struct timespec *osd_inode_time(const struct lu_env *env,
				       struct inode *inode, __u64 seconds)
{
	struct osd_thread_info	*oti = osd_oti_get(env);
	struct timespec		*t   = &oti->oti_time;

	t->tv_sec = seconds;
	t->tv_nsec = 0;
	*t = timespec_trunc(*t, inode->i_sb->s_time_gran);
	return t;
}


static void osd_inode_getattr(const struct lu_env *env,
                              struct inode *inode, struct lu_attr *attr)
{
        attr->la_valid      |= LA_ATIME | LA_MTIME | LA_CTIME | LA_MODE |
                               LA_SIZE | LA_BLOCKS | LA_UID | LA_GID |
                               LA_FLAGS | LA_NLINK | LA_RDEV | LA_BLKSIZE |
			       LA_TYPE;

        attr->la_atime      = LTIME_S(inode->i_atime);
        attr->la_mtime      = LTIME_S(inode->i_mtime);
        attr->la_ctime      = LTIME_S(inode->i_ctime);
        attr->la_mode       = inode->i_mode;
        attr->la_size       = i_size_read(inode);
        attr->la_blocks     = inode->i_blocks;
        attr->la_uid        = inode->i_uid;
        attr->la_gid        = inode->i_gid;
        attr->la_flags      = LDISKFS_I(inode)->i_flags;
        attr->la_nlink      = inode->i_nlink;
        attr->la_rdev       = inode->i_rdev;
	attr->la_blksize    = 1 << inode->i_blkbits;
	attr->la_blkbits    = inode->i_blkbits;
}

static int osd_attr_get(const struct lu_env *env,
                        struct dt_object *dt,
                        struct lu_attr *attr,
                        struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LINVRNT(osd_invariant(obj));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_READ))
                return -EACCES;

	spin_lock(&obj->oo_guard);
	osd_inode_getattr(env, obj->oo_inode, attr);
	spin_unlock(&obj->oo_guard);
	return 0;
}

static int osd_declare_attr_set(const struct lu_env *env,
                                struct dt_object *dt,
                                const struct lu_attr *attr,
                                struct thandle *handle)
{
	struct osd_thandle     *oh;
	struct osd_object      *obj;
	struct osd_thread_info *info = osd_oti_get(env);
	struct lquota_id_info  *qi = &info->oti_qi;
	long long               bspace;
	int			rc = 0;
	bool			enforce;
	ENTRY;

	LASSERT(dt != NULL);
	LASSERT(handle != NULL);

	obj = osd_dt_obj(dt);
	LASSERT(osd_invariant(obj));

	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle == NULL);

	osd_trans_declare_op(env, oh, OSD_OT_ATTR_SET,
			     osd_dto_credits_noquota[DTO_ATTR_SET_BASE]);

	if (attr == NULL || obj->oo_inode == NULL)
		RETURN(rc);

	bspace   = obj->oo_inode->i_blocks;
	bspace <<= obj->oo_inode->i_sb->s_blocksize_bits;
	bspace   = toqb(bspace);

	/* Changing ownership is always preformed by super user, it should not
	 * fail with EDQUOT.
	 *
	 * We still need to call the osd_declare_qid() to calculate the journal
	 * credits for updating quota accounting files and to trigger quota
	 * space adjustment once the operation is completed.*/
	if (attr->la_valid & LA_UID || attr->la_valid & LA_GID) {
		/* USERQUOTA */
		qi->lqi_type = USRQUOTA;
		enforce = (attr->la_valid & LA_UID) &&
			  (attr->la_uid != obj->oo_inode->i_uid);
		/* inode accounting */
		qi->lqi_is_blk = false;

		/* one more inode for the new uid ... */
		qi->lqi_id.qid_uid = attr->la_uid;
		qi->lqi_space      = 1;
		/* Reserve credits for the new uid */
		rc = osd_declare_qid(env, oh, qi, NULL, enforce, NULL);
		if (rc == -EDQUOT || rc == -EINPROGRESS)
			rc = 0;
		if (rc)
			RETURN(rc);

		/* and one less inode for the current uid */
		qi->lqi_id.qid_uid = obj->oo_inode->i_uid;
		qi->lqi_space      = -1;
		rc = osd_declare_qid(env, oh, qi, obj, enforce, NULL);
		if (rc == -EDQUOT || rc == -EINPROGRESS)
			rc = 0;
		if (rc)
			RETURN(rc);

		/* block accounting */
		qi->lqi_is_blk = true;

		/* more blocks for the new uid ... */
		qi->lqi_id.qid_uid = attr->la_uid;
		qi->lqi_space      = bspace;
		/*
		 * Credits for the new uid has been reserved, re-use "obj"
		 * to save credit reservation.
		 */
		rc = osd_declare_qid(env, oh, qi, obj, enforce, NULL);
		if (rc == -EDQUOT || rc == -EINPROGRESS)
			rc = 0;
		if (rc)
			RETURN(rc);

		/* and finally less blocks for the current uid */
		qi->lqi_id.qid_uid = obj->oo_inode->i_uid;
		qi->lqi_space      = -bspace;
		rc = osd_declare_qid(env, oh, qi, obj, enforce, NULL);
		if (rc == -EDQUOT || rc == -EINPROGRESS)
			rc = 0;
		if (rc)
			RETURN(rc);

		/* GROUP QUOTA */
		qi->lqi_type = GRPQUOTA;
		enforce = (attr->la_valid & LA_GID) &&
			  (attr->la_gid != obj->oo_inode->i_gid);

		/* inode accounting */
		qi->lqi_is_blk = false;

		/* one more inode for the new gid ... */
		qi->lqi_id.qid_gid = attr->la_gid;
		qi->lqi_space      = 1;
		rc = osd_declare_qid(env, oh, qi, NULL, enforce, NULL);
		if (rc == -EDQUOT || rc == -EINPROGRESS)
			rc = 0;
		if (rc)
			RETURN(rc);

		/* and one less inode for the current gid */
		qi->lqi_id.qid_gid = obj->oo_inode->i_gid;
		qi->lqi_space      = -1;
		rc = osd_declare_qid(env, oh, qi, obj, enforce, NULL);
		if (rc == -EDQUOT || rc == -EINPROGRESS)
			rc = 0;
		if (rc)
			RETURN(rc);

		/* block accounting */
		qi->lqi_is_blk = true;

		/* more blocks for the new gid ... */
		qi->lqi_id.qid_gid = attr->la_gid;
		qi->lqi_space      = bspace;
		rc = osd_declare_qid(env, oh, qi, obj, enforce, NULL);
		if (rc == -EDQUOT || rc == -EINPROGRESS)
			rc = 0;
		if (rc)
			RETURN(rc);

		/* and finally less blocks for the current gid */
		qi->lqi_id.qid_gid = obj->oo_inode->i_gid;
		qi->lqi_space      = -bspace;
		rc = osd_declare_qid(env, oh, qi, obj, enforce, NULL);
		if (rc == -EDQUOT || rc == -EINPROGRESS)
			rc = 0;
		if (rc)
			RETURN(rc);
	}

	RETURN(rc);
}

static int osd_inode_setattr(const struct lu_env *env,
                             struct inode *inode, const struct lu_attr *attr)
{
        __u64 bits;

        bits = attr->la_valid;

        if (bits & LA_ATIME)
                inode->i_atime  = *osd_inode_time(env, inode, attr->la_atime);
        if (bits & LA_CTIME)
                inode->i_ctime  = *osd_inode_time(env, inode, attr->la_ctime);
        if (bits & LA_MTIME)
                inode->i_mtime  = *osd_inode_time(env, inode, attr->la_mtime);
        if (bits & LA_SIZE) {
                LDISKFS_I(inode)->i_disksize = attr->la_size;
                i_size_write(inode, attr->la_size);
        }

#if 0
        /* OSD should not change "i_blocks" which is used by quota.
         * "i_blocks" should be changed by ldiskfs only. */
        if (bits & LA_BLOCKS)
                inode->i_blocks = attr->la_blocks;
#endif
        if (bits & LA_MODE)
                inode->i_mode   = (inode->i_mode & S_IFMT) |
                        (attr->la_mode & ~S_IFMT);
        if (bits & LA_UID)
                inode->i_uid    = attr->la_uid;
        if (bits & LA_GID)
                inode->i_gid    = attr->la_gid;
        if (bits & LA_NLINK)
		set_nlink(inode, attr->la_nlink);
        if (bits & LA_RDEV)
                inode->i_rdev   = attr->la_rdev;

        if (bits & LA_FLAGS) {
                /* always keep S_NOCMTIME */
                inode->i_flags = ll_ext_to_inode_flags(attr->la_flags) |
                                 S_NOCMTIME;
        }
        return 0;
}

static int osd_quota_transfer(struct inode *inode, const struct lu_attr *attr)
{
	if ((attr->la_valid & LA_UID && attr->la_uid != inode->i_uid) ||
	    (attr->la_valid & LA_GID && attr->la_gid != inode->i_gid)) {
		struct iattr	iattr;
		int		rc;

		ll_vfs_dq_init(inode);
		iattr.ia_valid = 0;
		if (attr->la_valid & LA_UID)
			iattr.ia_valid |= ATTR_UID;
		if (attr->la_valid & LA_GID)
			iattr.ia_valid |= ATTR_GID;
		iattr.ia_uid = attr->la_uid;
		iattr.ia_gid = attr->la_gid;

		rc = ll_vfs_dq_transfer(inode, &iattr);
		if (rc) {
			CERROR("%s: quota transfer failed: rc = %d. Is quota "
			       "enforcement enabled on the ldiskfs filesystem?",
			       inode->i_sb->s_id, rc);
			return rc;
		}
	}
	return 0;
}

static int osd_attr_set(const struct lu_env *env,
                        struct dt_object *dt,
                        const struct lu_attr *attr,
                        struct thandle *handle,
                        struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct inode      *inode;
        int rc;

        LASSERT(handle != NULL);
	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(osd_invariant(obj));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_WRITE))
                return -EACCES;

	osd_trans_exec_op(env, handle, OSD_OT_ATTR_SET);

	if (OBD_FAIL_CHECK(OBD_FAIL_OSD_FID_MAPPING)) {
		struct osd_thread_info	*oti  = osd_oti_get(env);
		const struct lu_fid	*fid0 = lu_object_fid(&dt->do_lu);
		struct lu_fid		*fid1 = &oti->oti_fid;
		struct osd_inode_id	*id   = &oti->oti_id;
		struct iam_path_descr	*ipd;
		struct iam_container	*bag;
		struct osd_thandle	*oh;
		int			 rc;

		fid_cpu_to_be(fid1, fid0);
		memset(id, 1, sizeof(*id));
		bag = &osd_fid2oi(osd_dev(dt->do_lu.lo_dev),
				  fid0)->oi_dir.od_container;
		ipd = osd_idx_ipd_get(env, bag);
		if (unlikely(ipd == NULL))
			RETURN(-ENOMEM);

		oh = container_of0(handle, struct osd_thandle, ot_super);
		rc = iam_update(oh->ot_handle, bag, (const struct iam_key *)fid1,
				(const struct iam_rec *)id, ipd);
		osd_ipd_put(env, bag, ipd);
		return(rc > 0 ? 0 : rc);
	}

        inode = obj->oo_inode;

	rc = osd_quota_transfer(inode, attr);
	if (rc)
		return rc;

	spin_lock(&obj->oo_guard);
	rc = osd_inode_setattr(env, inode, attr);
	spin_unlock(&obj->oo_guard);

        if (!rc)
		ll_dirty_inode(inode, I_DIRTY_DATASYNC);
        return rc;
}

struct dentry *osd_child_dentry_get(const struct lu_env *env,
                                    struct osd_object *obj,
                                    const char *name, const int namelen)
{
        return osd_child_dentry_by_inode(env, obj->oo_inode, name, namelen);
}

static int osd_mkfile(struct osd_thread_info *info, struct osd_object *obj,
		      umode_t mode, struct dt_allocation_hint *hint,
		      struct thandle *th)
{
        int result;
        struct osd_device  *osd = osd_obj2dev(obj);
        struct osd_thandle *oth;
        struct dt_object   *parent = NULL;
        struct inode       *inode;

        LINVRNT(osd_invariant(obj));
        LASSERT(obj->oo_inode == NULL);
        LASSERT(obj->oo_hl_head == NULL);

        if (S_ISDIR(mode) && ldiskfs_pdo) {
                obj->oo_hl_head =ldiskfs_htree_lock_head_alloc(HTREE_HBITS_DEF);
                if (obj->oo_hl_head == NULL)
                        return -ENOMEM;
        }

        oth = container_of(th, struct osd_thandle, ot_super);
        LASSERT(oth->ot_handle->h_transaction != NULL);

        if (hint && hint->dah_parent)
                parent = hint->dah_parent;

        inode = ldiskfs_create_inode(oth->ot_handle,
                                     parent ? osd_dt_obj(parent)->oo_inode :
                                              osd_sb(osd)->s_root->d_inode,
                                     mode);
        if (!IS_ERR(inode)) {
                /* Do not update file c/mtime in ldiskfs.
                 * NB: don't need any lock because no contention at this
                 * early stage */
                inode->i_flags |= S_NOCMTIME;

		/* For new created object, it must be consistent,
		 * and it is unnecessary to scrub against it. */
		ldiskfs_set_inode_state(inode, LDISKFS_STATE_LUSTRE_NOSCRUB);
		ldiskfs_clear_inode_state(inode, LDISKFS_STATE_LUSTRE_NO_OI);
                obj->oo_inode = inode;
                result = 0;
        } else {
                if (obj->oo_hl_head != NULL) {
                        ldiskfs_htree_lock_head_free(obj->oo_hl_head);
                        obj->oo_hl_head = NULL;
                }
                result = PTR_ERR(inode);
        }
        LINVRNT(osd_invariant(obj));
        return result;
}

enum {
        OSD_NAME_LEN = 255
};

static int osd_mkdir(struct osd_thread_info *info, struct osd_object *obj,
                     struct lu_attr *attr,
                     struct dt_allocation_hint *hint,
                     struct dt_object_format *dof,
                     struct thandle *th)
{
        int result;
        struct osd_thandle *oth;
        __u32 mode = (attr->la_mode & (S_IFMT | S_IRWXUGO | S_ISVTX));

        LASSERT(S_ISDIR(attr->la_mode));

        oth = container_of(th, struct osd_thandle, ot_super);
        LASSERT(oth->ot_handle->h_transaction != NULL);
        result = osd_mkfile(info, obj, mode, hint, th);

        return result;
}

static int osd_mk_index(struct osd_thread_info *info, struct osd_object *obj,
                        struct lu_attr *attr,
                        struct dt_allocation_hint *hint,
                        struct dt_object_format *dof,
                        struct thandle *th)
{
        int result;
        struct osd_thandle *oth;
        const struct dt_index_features *feat = dof->u.dof_idx.di_feat;

        __u32 mode = (attr->la_mode & (S_IFMT | S_IALLUGO | S_ISVTX));

        LASSERT(S_ISREG(attr->la_mode));

        oth = container_of(th, struct osd_thandle, ot_super);
        LASSERT(oth->ot_handle->h_transaction != NULL);

        result = osd_mkfile(info, obj, mode, hint, th);
        if (result == 0) {
                LASSERT(obj->oo_inode != NULL);
                if (feat->dif_flags & DT_IND_VARKEY)
                        result = iam_lvar_create(obj->oo_inode,
                                                 feat->dif_keysize_max,
                                                 feat->dif_ptrsize,
                                                 feat->dif_recsize_max,
                                                 oth->ot_handle);
                else
                        result = iam_lfix_create(obj->oo_inode,
                                                 feat->dif_keysize_max,
                                                 feat->dif_ptrsize,
                                                 feat->dif_recsize_max,
                                                 oth->ot_handle);

        }
        return result;
}

static int osd_mkreg(struct osd_thread_info *info, struct osd_object *obj,
                     struct lu_attr *attr,
                     struct dt_allocation_hint *hint,
                     struct dt_object_format *dof,
                     struct thandle *th)
{
        LASSERT(S_ISREG(attr->la_mode));
        return osd_mkfile(info, obj, (attr->la_mode &
                               (S_IFMT | S_IALLUGO | S_ISVTX)), hint, th);
}

static int osd_mksym(struct osd_thread_info *info, struct osd_object *obj,
                     struct lu_attr *attr,
                     struct dt_allocation_hint *hint,
                     struct dt_object_format *dof,
                     struct thandle *th)
{
        LASSERT(S_ISLNK(attr->la_mode));
        return osd_mkfile(info, obj, (attr->la_mode &
                              (S_IFMT | S_IALLUGO | S_ISVTX)), hint, th);
}

static int osd_mknod(struct osd_thread_info *info, struct osd_object *obj,
		     struct lu_attr *attr,
		     struct dt_allocation_hint *hint,
		     struct dt_object_format *dof,
		     struct thandle *th)
{
	umode_t mode = attr->la_mode & (S_IFMT | S_IALLUGO | S_ISVTX);
	int result;

	LINVRNT(osd_invariant(obj));
	LASSERT(obj->oo_inode == NULL);
        LASSERT(S_ISCHR(mode) || S_ISBLK(mode) ||
                S_ISFIFO(mode) || S_ISSOCK(mode));

        result = osd_mkfile(info, obj, mode, hint, th);
        if (result == 0) {
                LASSERT(obj->oo_inode != NULL);
		/*
		 * This inode should be marked dirty for i_rdev.  Currently
		 * that is done in the osd_attr_init().
		 */
		init_special_inode(obj->oo_inode, obj->oo_inode->i_mode,
				   attr->la_rdev);
        }
        LINVRNT(osd_invariant(obj));
        return result;
}

typedef int (*osd_obj_type_f)(struct osd_thread_info *, struct osd_object *,
                              struct lu_attr *,
                              struct dt_allocation_hint *hint,
                              struct dt_object_format *dof,
                              struct thandle *);

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


static void osd_ah_init(const struct lu_env *env, struct dt_allocation_hint *ah,
			struct dt_object *parent, struct dt_object *child,
			umode_t child_mode)
{
        LASSERT(ah);

        memset(ah, 0, sizeof(*ah));
        ah->dah_parent = parent;
        ah->dah_mode = child_mode;
}

static void osd_attr_init(struct osd_thread_info *info, struct osd_object *obj,
			  struct lu_attr *attr, struct dt_object_format *dof)
{
	struct inode   *inode = obj->oo_inode;
	__u64           valid = attr->la_valid;
	int             result;

	attr->la_valid &= ~(LA_TYPE | LA_MODE);

        if (dof->dof_type != DFT_NODE)
                attr->la_valid &= ~LA_RDEV;
        if ((valid & LA_ATIME) && (attr->la_atime == LTIME_S(inode->i_atime)))
                attr->la_valid &= ~LA_ATIME;
        if ((valid & LA_CTIME) && (attr->la_ctime == LTIME_S(inode->i_ctime)))
                attr->la_valid &= ~LA_CTIME;
        if ((valid & LA_MTIME) && (attr->la_mtime == LTIME_S(inode->i_mtime)))
                attr->la_valid &= ~LA_MTIME;

	result = osd_quota_transfer(inode, attr);
	if (result)
		return;

        if (attr->la_valid != 0) {
                result = osd_inode_setattr(info->oti_env, inode, attr);
                /*
                 * The osd_inode_setattr() should always succeed here.  The
                 * only error that could be returned is EDQUOT when we are
                 * trying to change the UID or GID of the inode. However, this
                 * should not happen since quota enforcement is no longer
                 * enabled on ldiskfs (lquota takes care of it).
                 */
                LASSERTF(result == 0, "%d", result);
		ll_dirty_inode(inode, I_DIRTY_DATASYNC);
        }

        attr->la_valid = valid;
}

/**
 * Helper function for osd_object_create()
 *
 * \retval 0, on success
 */
static int __osd_object_create(struct osd_thread_info *info,
                               struct osd_object *obj, struct lu_attr *attr,
                               struct dt_allocation_hint *hint,
                               struct dt_object_format *dof,
                               struct thandle *th)
{
	int	result;
	__u32	umask;

	/* we drop umask so that permissions we pass are not affected */
	umask = current->fs->umask;
	current->fs->umask = 0;

	result = osd_create_type_f(dof->dof_type)(info, obj, attr, hint, dof,
						  th);
        if (result == 0) {
		osd_attr_init(info, obj, attr, dof);
		osd_object_init0(obj);
		/* bz 24037 */
		if (obj->oo_inode && (obj->oo_inode->i_state & I_NEW))
			unlock_new_inode(obj->oo_inode);
        }

	/* restore previous umask value */
	current->fs->umask = umask;

	return result;
}

/**
 * Helper function for osd_object_create()
 *
 * \retval 0, on success
 */
static int __osd_oi_insert(const struct lu_env *env, struct osd_object *obj,
                           const struct lu_fid *fid, struct thandle *th)
{
        struct osd_thread_info *info = osd_oti_get(env);
        struct osd_inode_id    *id   = &info->oti_id;
        struct osd_device      *osd  = osd_obj2dev(obj);

        LASSERT(obj->oo_inode != NULL);

	osd_id_gen(id, obj->oo_inode->i_ino, obj->oo_inode->i_generation);
	return osd_oi_insert(info, osd, fid, id, th, OI_CHECK_FLD);
}

int osd_fld_lookup(const struct lu_env *env, struct osd_device *osd,
		   obd_seq seq, struct lu_seq_range *range)
{
	struct seq_server_site	*ss = osd_seq_site(osd);
	int			rc;

	if (fid_seq_is_idif(seq)) {
		fld_range_set_ost(range);
		range->lsr_index = idif_ost_idx(seq);
		return 0;
	}

	if (!fid_seq_in_fldb(seq)) {
		fld_range_set_mdt(range);
		if (ss != NULL)
			/* FIXME: If ss is NULL, it suppose not get lsr_index
			 * at all */
			range->lsr_index = ss->ss_node_id;
		return 0;
	}

	LASSERT(ss != NULL);
	fld_range_set_any(range);
	rc = fld_server_lookup(env, ss->ss_server_fld, seq, range);
	if (rc != 0) {
		CERROR("%s: cannot find FLD range for "LPX64": rc = %d\n",
		       osd_name(osd), seq, rc);
	}
	return rc;
}

/*
 * Concurrency: no external locking is necessary.
 */
static int osd_declare_object_create(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lu_attr *attr,
				     struct dt_allocation_hint *hint,
				     struct dt_object_format *dof,
				     struct thandle *handle)
{
	struct lu_seq_range	*range = &osd_oti_get(env)->oti_seq_range;
	struct osd_thandle	*oh;
	int			 rc;
	ENTRY;

	LASSERT(handle != NULL);

	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle == NULL);

	osd_trans_declare_op(env, oh, OSD_OT_CREATE,
			     osd_dto_credits_noquota[DTO_OBJECT_CREATE]);
	/* Reuse idle OI block may cause additional one OI block
	 * to be changed. */
	osd_trans_declare_op(env, oh, OSD_OT_INSERT,
			     osd_dto_credits_noquota[DTO_INDEX_INSERT] + 1);

	/* If this is directory, then we expect . and .. to be inserted as
	 * well. The one directory block always needs to be created for the
	 * directory, so we could use DTO_WRITE_BASE here (GDT, block bitmap,
	 * block), there is no danger of needing a tree for the first block.
	 */
	if (attr && S_ISDIR(attr->la_mode)) {
		osd_trans_declare_op(env, oh, OSD_OT_INSERT,
				     osd_dto_credits_noquota[DTO_WRITE_BASE]);
		osd_trans_declare_op(env, oh, OSD_OT_INSERT, 0);
	}

	if (!attr)
		RETURN(0);

	rc = osd_declare_inode_qid(env, attr->la_uid, attr->la_gid, 1, oh,
				   osd_dt_obj(dt), false, NULL, false);
	if (rc != 0)
		RETURN(rc);

	/* It does fld look up inside declare, and the result will be
	 * added to fld cache, so the following fld lookup inside insert
	 * does not need send RPC anymore, so avoid send rpc with holding
	 * transaction */
	if (fid_is_norm(lu_object_fid(&dt->do_lu)) &&
		!fid_is_last_id(lu_object_fid(&dt->do_lu)))
		osd_fld_lookup(env, osd_dt_dev(handle->th_dev),
			       fid_seq(lu_object_fid(&dt->do_lu)), range);


	RETURN(rc);
}

static int osd_object_create(const struct lu_env *env, struct dt_object *dt,
                             struct lu_attr *attr,
                             struct dt_allocation_hint *hint,
                             struct dt_object_format *dof,
                             struct thandle *th)
{
        const struct lu_fid    *fid    = lu_object_fid(&dt->do_lu);
        struct osd_object      *obj    = osd_dt_obj(dt);
        struct osd_thread_info *info   = osd_oti_get(env);
        int result;

        ENTRY;

        LINVRNT(osd_invariant(obj));
	LASSERT(!dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(osd_write_locked(env, obj));
        LASSERT(th != NULL);

	if (unlikely(fid_is_acct(fid)))
		/* Quota files can't be created from the kernel any more,
		 * 'tune2fs -O quota' will take care of creating them */
		RETURN(-EPERM);

	osd_trans_exec_op(env, th, OSD_OT_CREATE);
	osd_trans_declare_rb(env, th, OSD_OT_REF_ADD);

        result = __osd_object_create(info, obj, attr, hint, dof, th);
        if (result == 0)
                result = __osd_oi_insert(env, obj, fid, th);

	LASSERT(ergo(result == 0,
		     dt_object_exists(dt) && !dt_object_remote(dt)));

        LASSERT(osd_invariant(obj));
        RETURN(result);
}

/**
 * Called to destroy on-disk representation of the object
 *
 * Concurrency: must be locked
 */
static int osd_declare_object_destroy(const struct lu_env *env,
				      struct dt_object *dt,
				      struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct inode       *inode = obj->oo_inode;
	struct osd_thandle *oh;
	int		    rc;
	ENTRY;

	oh = container_of0(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle == NULL);
	LASSERT(inode);

	osd_trans_declare_op(env, oh, OSD_OT_DESTROY,
			     osd_dto_credits_noquota[DTO_OBJECT_DELETE]);
	/* Recycle idle OI leaf may cause additional three OI blocks
	 * to be changed. */
	osd_trans_declare_op(env, oh, OSD_OT_DELETE,
			     osd_dto_credits_noquota[DTO_INDEX_DELETE] + 3);
	/* one less inode */
	rc = osd_declare_inode_qid(env, inode->i_uid, inode->i_gid, -1, oh,
				   obj, false, NULL, false);
	if (rc)
		RETURN(rc);
	/* data to be truncated */
	rc = osd_declare_inode_qid(env, inode->i_uid, inode->i_gid, 0, oh,
				   obj, true, NULL, false);
	RETURN(rc);
}

static int osd_object_destroy(const struct lu_env *env,
                              struct dt_object *dt,
                              struct thandle *th)
{
        const struct lu_fid    *fid = lu_object_fid(&dt->do_lu);
        struct osd_object      *obj = osd_dt_obj(dt);
        struct inode           *inode = obj->oo_inode;
        struct osd_device      *osd = osd_obj2dev(obj);
        struct osd_thandle     *oh;
        int                     result;
        ENTRY;

        oh = container_of0(th, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle);
        LASSERT(inode);
        LASSERT(!lu_object_is_dying(dt->do_lu.lo_header));

	if (unlikely(fid_is_acct(fid)))
		RETURN(-EPERM);

	if (S_ISDIR(inode->i_mode)) {
		LASSERT(osd_inode_unlinked(inode) || inode->i_nlink == 1 ||
			inode->i_nlink == 2);
		/* it will check/delete the inode from remote parent,
		 * how to optimize it? unlink performance impaction XXX */
		result = osd_delete_from_remote_parent(env, osd, obj, oh);
		if (result != 0 && result != -ENOENT) {
			CERROR("%s: delete inode "DFID": rc = %d\n",
			       osd_name(osd), PFID(fid), result);
		}
		spin_lock(&obj->oo_guard);
		clear_nlink(inode);
		spin_unlock(&obj->oo_guard);
		ll_dirty_inode(inode, I_DIRTY_DATASYNC);
	}

	osd_trans_exec_op(env, th, OSD_OT_DESTROY);

        result = osd_oi_delete(osd_oti_get(env), osd, fid, th, OI_CHECK_FLD);

        /* XXX: add to ext3 orphan list */
        /* rc = ext3_orphan_add(handle_t *handle, struct inode *inode) */

        /* not needed in the cache anymore */
        set_bit(LU_OBJECT_HEARD_BANSHEE, &dt->do_lu.lo_header->loh_flags);

        RETURN(0);
}

/**
 * Put the fid into lustre_mdt_attrs, and then place the structure
 * inode's ea. This fid should not be altered during the life time
 * of the inode.
 *
 * \retval +ve, on success
 * \retval -ve, on error
 *
 * FIXME: It is good to have/use ldiskfs_xattr_set_handle() here
 */
int osd_ea_fid_set(struct osd_thread_info *info, struct inode *inode,
		   const struct lu_fid *fid, __u32 compat, __u32 incompat)
{
	struct lustre_mdt_attrs	*lma = &info->oti_mdt_attrs;
	int			 rc;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_FID_INLMA))
		RETURN(0);

	lustre_lma_init(lma, fid, compat, incompat);
	lustre_lma_swab(lma);

	rc = __osd_xattr_set(info, inode, XATTR_NAME_LMA, lma, sizeof(*lma),
			     XATTR_CREATE);
	/* LMA may already exist, but we need to check that all the
	 * desired compat/incompat flags have been added. */
	if (unlikely(rc == -EEXIST)) {
		if (compat == 0 && incompat == 0)
			RETURN(0);

		rc = __osd_xattr_get(inode, &info->oti_obj_dentry,
				     XATTR_NAME_LMA, info->oti_mdt_attrs_old,
				     LMA_OLD_SIZE);
		if (rc <= 0)
			RETURN(-EINVAL);

		lustre_lma_swab(lma);
		if (!(~lma->lma_compat & compat) &&
		    !(~lma->lma_incompat & incompat))
			RETURN(0);

		lma->lma_compat |= compat;
		lma->lma_incompat |= incompat;
		lustre_lma_swab(lma);
		rc = __osd_xattr_set(info, inode, XATTR_NAME_LMA, lma,
				     sizeof(*lma), XATTR_REPLACE);
	}

	RETURN(rc);
}

/**
 * ldiskfs supports fid in dirent, it is passed in dentry->d_fsdata.
 * lustre 1.8 also uses d_fsdata for passing other info to ldiskfs.
 * To have compatilibility with 1.8 ldiskfs driver we need to have
 * magic number at start of fid data.
 * \ldiskfs_dentry_param is used only to pass fid from osd to ldiskfs.
 * its inmemory API.
 */
void osd_get_ldiskfs_dirent_param(struct ldiskfs_dentry_param *param,
				  const struct dt_rec *fid)
{
	if (!fid_is_namespace_visible((const struct lu_fid *)fid) ||
	    OBD_FAIL_CHECK(OBD_FAIL_FID_IGIF)) {
		param->edp_magic = 0;
		return;
	}

	param->edp_magic = LDISKFS_LUFID_MAGIC;
	param->edp_len =  sizeof(struct lu_fid) + 1;
	fid_cpu_to_be((struct lu_fid *)param->edp_data, (struct lu_fid *)fid);
}

/**
 * Try to read the fid from inode ea into dt_rec.
 *
 * \param fid object fid.
 *
 * \retval 0 on success
 */
static int osd_ea_fid_get(const struct lu_env *env, struct osd_object *obj,
			  __u32 ino, struct lu_fid *fid,
			  struct osd_inode_id *id)
{
	struct osd_thread_info *info  = osd_oti_get(env);
	struct inode	       *inode;
	ENTRY;

	osd_id_gen(id, ino, OSD_OII_NOGEN);
	inode = osd_iget_fid(info, osd_obj2dev(obj), id, fid);
	if (IS_ERR(inode))
		RETURN(PTR_ERR(inode));

	iput(inode);
	RETURN(0);
}

static int osd_add_dot_dotdot_internal(struct osd_thread_info *info,
					struct inode *dir,
					struct inode  *parent_dir,
					const struct dt_rec *dot_fid,
					const struct dt_rec *dot_dot_fid,
					struct osd_thandle *oth)
{
	struct ldiskfs_dentry_param *dot_ldp;
	struct ldiskfs_dentry_param *dot_dot_ldp;

	dot_dot_ldp = (struct ldiskfs_dentry_param *)info->oti_ldp2;
	osd_get_ldiskfs_dirent_param(dot_dot_ldp, dot_dot_fid);

	dot_ldp = (struct ldiskfs_dentry_param *)info->oti_ldp;
	dot_ldp->edp_magic = 0;
	return ldiskfs_add_dot_dotdot(oth->ot_handle, parent_dir,
					dir, dot_ldp, dot_dot_ldp);
}

/**
 * Create an local agent inode for remote entry
 */
static struct inode *osd_create_local_agent_inode(const struct lu_env *env,
						  struct osd_device *osd,
						  struct osd_object *pobj,
						  const struct lu_fid *fid,
						  struct thandle *th)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	struct inode		*local;
	struct osd_thandle	*oh;
	int			rc;
	ENTRY;

	LASSERT(th);
	oh = container_of(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle->h_transaction != NULL);

	/* FIXME: Insert index api needs to know the mode of
	 * the remote object. Just use S_IFDIR for now */
	local = ldiskfs_create_inode(oh->ot_handle, pobj->oo_inode, S_IFDIR);
	if (IS_ERR(local)) {
		CERROR("%s: create local error %d\n", osd_name(osd),
		       (int)PTR_ERR(local));
		RETURN(local);
	}

	ldiskfs_set_inode_state(local, LDISKFS_STATE_LUSTRE_NO_OI);
	/* Set special LMA flag for local agent inode */
	rc = osd_ea_fid_set(info, local, fid, 0, LMAI_AGENT);
	if (rc != 0) {
		CERROR("%s: set LMA for "DFID" remote inode failed: rc = %d\n",
		       osd_name(osd), PFID(fid), rc);
		RETURN(ERR_PTR(rc));
	}

	rc = osd_add_dot_dotdot_internal(info, local, pobj->oo_inode,
		(const struct dt_rec *)lu_object_fid(&pobj->oo_dt.do_lu),
		(const struct dt_rec *)fid, oh);
	if (rc != 0) {
		CERROR("%s: "DFID" add dot dotdot error: rc = %d\n",
			osd_name(osd), PFID(fid), rc);
		RETURN(ERR_PTR(rc));
	}

	RETURN(local);
}

/**
 * Delete local agent inode for remote entry
 */
static int osd_delete_local_agent_inode(const struct lu_env *env,
					struct osd_device *osd,
					const struct lu_fid *fid,
					__u32 ino, struct osd_thandle *oh)
{
	struct osd_thread_info	*oti = osd_oti_get(env);
	struct osd_inode_id	*id = &oti->oti_id;
	struct inode		*inode;
	ENTRY;

	id->oii_ino = le32_to_cpu(ino);
	id->oii_gen = OSD_OII_NOGEN;
	inode = osd_iget(oti, osd, id);
	if (IS_ERR(inode)) {
		CERROR("%s: iget error "DFID" id %u:%u\n", osd_name(osd),
		       PFID(fid), id->oii_ino, id->oii_gen);
		RETURN(PTR_ERR(inode));
	}

	clear_nlink(inode);
	mark_inode_dirty(inode);
	CDEBUG(D_INODE, "%s: delete remote inode "DFID" %lu\n",
		osd_name(osd), PFID(fid), inode->i_ino);
	iput(inode);
	RETURN(0);
}

/**
 * OSD layer object create function for interoperability mode (b11826).
 * This is mostly similar to osd_object_create(). Only difference being, fid is
 * inserted into inode ea here.
 *
 * \retval   0, on success
 * \retval -ve, on error
 */
static int osd_object_ea_create(const struct lu_env *env, struct dt_object *dt,
                                struct lu_attr *attr,
                                struct dt_allocation_hint *hint,
                                struct dt_object_format *dof,
                                struct thandle *th)
{
        const struct lu_fid    *fid    = lu_object_fid(&dt->do_lu);
        struct osd_object      *obj    = osd_dt_obj(dt);
        struct osd_thread_info *info   = osd_oti_get(env);
        int                     result;

        ENTRY;

        LASSERT(osd_invariant(obj));
	LASSERT(!dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(osd_write_locked(env, obj));
        LASSERT(th != NULL);

	if (unlikely(fid_is_acct(fid)))
		/* Quota files can't be created from the kernel any more,
		 * 'tune2fs -O quota' will take care of creating them */
		RETURN(-EPERM);

	osd_trans_exec_op(env, th, OSD_OT_CREATE);
	osd_trans_declare_rb(env, th, OSD_OT_REF_ADD);

        result = __osd_object_create(info, obj, attr, hint, dof, th);
	if (result == 0)
		result = osd_ea_fid_set(info, obj->oo_inode, fid,
				fid_is_on_ost(info, osd_obj2dev(obj),
					      fid, OI_CHECK_FLD) ?
				LMAC_FID_ON_OST : 0, 0);

	if (result == 0)
		result = __osd_oi_insert(env, obj, fid, th);

	LASSERT(ergo(result == 0,
		     dt_object_exists(dt) && !dt_object_remote(dt)));
        LINVRNT(osd_invariant(obj));
        RETURN(result);
}

static int osd_declare_object_ref_add(const struct lu_env *env,
                                      struct dt_object *dt,
                                      struct thandle *handle)
{
	struct osd_thandle       *oh;

        /* it's possible that object doesn't exist yet */
        LASSERT(handle != NULL);

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle == NULL);

	osd_trans_declare_op(env, oh, OSD_OT_REF_ADD,
			     osd_dto_credits_noquota[DTO_ATTR_SET_BASE]);

	return 0;
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_object_ref_add(const struct lu_env *env,
                              struct dt_object *dt, struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct inode       *inode = obj->oo_inode;
	struct osd_thandle *oh;
	int		    rc = 0;

        LINVRNT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(osd_write_locked(env, obj));
        LASSERT(th != NULL);

        oh = container_of0(th, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);

	osd_trans_exec_op(env, th, OSD_OT_REF_ADD);

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
	ldiskfs_inc_count(oh->ot_handle, inode);
	LASSERT(inode->i_nlink <= LDISKFS_LINK_MAX);
	spin_unlock(&obj->oo_guard);

	ll_dirty_inode(inode, I_DIRTY_DATASYNC);
	LINVRNT(osd_invariant(obj));

	return rc;
}

static int osd_declare_object_ref_del(const struct lu_env *env,
                                      struct dt_object *dt,
                                      struct thandle *handle)
{
        struct osd_thandle *oh;

	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(handle != NULL);

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle == NULL);

	osd_trans_declare_op(env, oh, OSD_OT_REF_DEL,
			     osd_dto_credits_noquota[DTO_ATTR_SET_BASE]);

	return 0;
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_object_ref_del(const struct lu_env *env, struct dt_object *dt,
                              struct thandle *th)
{
	struct osd_object	*obj = osd_dt_obj(dt);
	struct inode		*inode = obj->oo_inode;
	struct osd_device	*osd = osd_dev(dt->do_lu.lo_dev);
	struct osd_thandle      *oh;

	LINVRNT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
	LASSERT(osd_write_locked(env, obj));
	LASSERT(th != NULL);

        oh = container_of0(th, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);

	osd_trans_exec_op(env, th, OSD_OT_REF_DEL);

	spin_lock(&obj->oo_guard);
	/* That can be result of upgrade from old Lustre version and
	 * applied only to local files.  Just skip this ref_del call.
	 * ext4_unlink() only treats this as a warning, don't LASSERT here.*/
	if (inode->i_nlink == 0) {
		CDEBUG_LIMIT(fid_is_norm(lu_object_fid(&dt->do_lu)) ?
			     D_ERROR : D_INODE, "%s: nlink == 0 on "DFID
			     ", maybe an upgraded file? (LU-3915)\n",
			     osd_name(osd), PFID(lu_object_fid(&dt->do_lu)));
		spin_unlock(&obj->oo_guard);
		return 0;
	}

	ldiskfs_dec_count(oh->ot_handle, inode);
	spin_unlock(&obj->oo_guard);

	ll_dirty_inode(inode, I_DIRTY_DATASYNC);
	LINVRNT(osd_invariant(obj));

	return 0;
}

/*
 * Get the 64-bit version for an inode.
 */
static int osd_object_version_get(const struct lu_env *env,
                                  struct dt_object *dt, dt_obj_version_t *ver)
{
        struct inode *inode = osd_dt_obj(dt)->oo_inode;

        CDEBUG(D_INODE, "Get version "LPX64" for inode %lu\n",
               LDISKFS_I(inode)->i_fs_version, inode->i_ino);
        *ver = LDISKFS_I(inode)->i_fs_version;
        return 0;
}

/*
 * Concurrency: @dt is read locked.
 */
static int osd_xattr_get(const struct lu_env *env, struct dt_object *dt,
                         struct lu_buf *buf, const char *name,
                         struct lustre_capa *capa)
{
        struct osd_object      *obj    = osd_dt_obj(dt);
        struct inode           *inode  = obj->oo_inode;
        struct osd_thread_info *info   = osd_oti_get(env);
        struct dentry          *dentry = &info->oti_obj_dentry;

        /* version get is not real XATTR but uses xattr API */
        if (strcmp(name, XATTR_NAME_VERSION) == 0) {
                /* for version we are just using xattr API but change inode
                 * field instead */
                LASSERT(buf->lb_len == sizeof(dt_obj_version_t));
                osd_object_version_get(env, dt, buf->lb_buf);
                return sizeof(dt_obj_version_t);
        }

	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(inode->i_op != NULL && inode->i_op->getxattr != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_READ))
                return -EACCES;

	return __osd_xattr_get(inode, dentry, name, buf->lb_buf, buf->lb_len);
}


static int osd_declare_xattr_set(const struct lu_env *env,
                                 struct dt_object *dt,
                                 const struct lu_buf *buf, const char *name,
                                 int fl, struct thandle *handle)
{
	struct osd_thandle *oh;
	int credits;
	struct super_block *sb = osd_sb(osd_dev(dt->do_lu.lo_dev));

	LASSERT(handle != NULL);

	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle == NULL);

	/* optimistic optimization: LMA is set first and usually fit inode */
	if (strcmp(name, XATTR_NAME_LMA) == 0) {
		if (dt_object_exists(dt))
			credits = 0;
		else
			credits = 1;
	} else if (strcmp(name, XATTR_NAME_VERSION) == 0) {
		credits = 1;
	} else {
		credits = osd_dto_credits_noquota[DTO_XATTR_SET];
		if (buf && buf->lb_len > sb->s_blocksize) {
			credits *= (buf->lb_len + sb->s_blocksize - 1) >>
					sb->s_blocksize_bits;
		}
		/*
		 * xattr set may involve inode quota change, reserve credits for
		 * dquot_initialize()
		 */
		oh->ot_credits += LDISKFS_MAXQUOTAS_INIT_BLOCKS(sb);
	}

	osd_trans_declare_op(env, oh, OSD_OT_XATTR_SET, credits);

	return 0;
}

/*
 * Set the 64-bit version for object
 */
static void osd_object_version_set(const struct lu_env *env,
                                   struct dt_object *dt,
                                   dt_obj_version_t *new_version)
{
        struct inode *inode = osd_dt_obj(dt)->oo_inode;

        CDEBUG(D_INODE, "Set version "LPX64" (old "LPX64") for inode %lu\n",
               *new_version, LDISKFS_I(inode)->i_fs_version, inode->i_ino);

        LDISKFS_I(inode)->i_fs_version = *new_version;
        /** Version is set after all inode operations are finished,
         *  so we should mark it dirty here */
	ll_dirty_inode(inode, I_DIRTY_DATASYNC);
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_xattr_set(const struct lu_env *env, struct dt_object *dt,
                         const struct lu_buf *buf, const char *name, int fl,
                         struct thandle *handle, struct lustre_capa *capa)
{
	struct osd_object      *obj      = osd_dt_obj(dt);
	struct inode	       *inode    = obj->oo_inode;
	struct osd_thread_info *info     = osd_oti_get(env);
	int			fs_flags = 0;
	ENTRY;

        LASSERT(handle != NULL);

        /* version set is not real XATTR */
        if (strcmp(name, XATTR_NAME_VERSION) == 0) {
                /* for version we are just using xattr API but change inode
                 * field instead */
                LASSERT(buf->lb_len == sizeof(dt_obj_version_t));
                osd_object_version_set(env, dt, buf->lb_buf);
                return sizeof(dt_obj_version_t);
        }

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_WRITE))
                return -EACCES;

	osd_trans_exec_op(env, handle, OSD_OT_XATTR_SET);
	if (fl & LU_XATTR_REPLACE)
		fs_flags |= XATTR_REPLACE;

	if (fl & LU_XATTR_CREATE)
		fs_flags |= XATTR_CREATE;

	return __osd_xattr_set(info, inode, name, buf->lb_buf, buf->lb_len,
			       fs_flags);
}

/*
 * Concurrency: @dt is read locked.
 */
static int osd_xattr_list(const struct lu_env *env, struct dt_object *dt,
                          struct lu_buf *buf, struct lustre_capa *capa)
{
        struct osd_object      *obj    = osd_dt_obj(dt);
        struct inode           *inode  = obj->oo_inode;
        struct osd_thread_info *info   = osd_oti_get(env);
        struct dentry          *dentry = &info->oti_obj_dentry;

	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(inode->i_op != NULL && inode->i_op->listxattr != NULL);
        LASSERT(osd_read_locked(env, obj) || osd_write_locked(env, obj));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_READ))
                return -EACCES;

        dentry->d_inode = inode;
	dentry->d_sb = inode->i_sb;
        return inode->i_op->listxattr(dentry, buf->lb_buf, buf->lb_len);
}

static int osd_declare_xattr_del(const struct lu_env *env,
                                 struct dt_object *dt, const char *name,
                                 struct thandle *handle)
{
        struct osd_thandle *oh;
	struct super_block *sb = osd_sb(osd_dev(dt->do_lu.lo_dev));

	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(handle != NULL);

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle == NULL);

	osd_trans_declare_op(env, oh, OSD_OT_XATTR_SET,
			     osd_dto_credits_noquota[DTO_XATTR_SET]);
	/*
	 * xattr del may involve inode quota change, reserve credits for
	 * dquot_initialize()
	 */
	oh->ot_credits += LDISKFS_MAXQUOTAS_INIT_BLOCKS(sb);

	return 0;
}

/*
 * Concurrency: @dt is write locked.
 */
static int osd_xattr_del(const struct lu_env *env, struct dt_object *dt,
                         const char *name, struct thandle *handle,
                         struct lustre_capa *capa)
{
        struct osd_object      *obj    = osd_dt_obj(dt);
        struct inode           *inode  = obj->oo_inode;
        struct osd_thread_info *info   = osd_oti_get(env);
        struct dentry          *dentry = &info->oti_obj_dentry;
        int                     rc;

	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(inode->i_op != NULL && inode->i_op->removexattr != NULL);
        LASSERT(handle != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_META_WRITE))
                return -EACCES;

	osd_trans_exec_op(env, handle, OSD_OT_XATTR_SET);

	ll_vfs_dq_init(inode);
        dentry->d_inode = inode;
	dentry->d_sb = inode->i_sb;
        rc = inode->i_op->removexattr(dentry, name);
        return rc;
}

static struct obd_capa *osd_capa_get(const struct lu_env *env,
				     struct dt_object *dt,
				     struct lustre_capa *old, __u64 opc)
{
	struct osd_thread_info *info = osd_oti_get(env);
	const struct lu_fid *fid = lu_object_fid(&dt->do_lu);
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	struct lustre_capa_key *key = &info->oti_capa_key;
	struct lustre_capa *capa = &info->oti_capa;
	struct obd_capa *oc;
	struct lu_capainfo *lci;
	int rc;
	ENTRY;

	if (!osd->od_fl_capa)
		RETURN(ERR_PTR(-ENOENT));

	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
	LINVRNT(osd_invariant(obj));

	/* renewal sanity check */
	if (old && osd_object_auth(env, dt, old, opc))
		RETURN(ERR_PTR(-EACCES));

	lci = lu_capainfo_get(env);
	if (unlikely(lci == NULL))
		RETURN(ERR_PTR(-ENOENT));

	switch (lci->lci_auth) {
	case LC_ID_NONE:
		RETURN(NULL);
	case LC_ID_PLAIN:
		capa->lc_uid = obj->oo_inode->i_uid;
		capa->lc_gid = obj->oo_inode->i_gid;
		capa->lc_flags = LC_ID_PLAIN;
		break;
	case LC_ID_CONVERT: {
		__u32 d[4], s[4];

		s[0] = obj->oo_inode->i_uid;
		cfs_get_random_bytes(&(s[1]), sizeof(__u32));
		s[2] = obj->oo_inode->i_gid;
		cfs_get_random_bytes(&(s[3]), sizeof(__u32));
		rc = capa_encrypt_id(d, s, key->lk_key, CAPA_HMAC_KEY_MAX_LEN);
		if (unlikely(rc))
			RETURN(ERR_PTR(rc));

		capa->lc_uid   = ((__u64)d[1] << 32) | d[0];
		capa->lc_gid   = ((__u64)d[3] << 32) | d[2];
		capa->lc_flags = LC_ID_CONVERT;
		break;
        }
	default:
		RETURN(ERR_PTR(-EINVAL));
	}

	capa->lc_fid = *fid;
	capa->lc_opc = opc;
	capa->lc_flags |= osd->od_capa_alg << 24;
	capa->lc_timeout = osd->od_capa_timeout;
	capa->lc_expiry = 0;

	oc = capa_lookup(osd->od_capa_hash, capa, 1);
	if (oc) {
		LASSERT(!capa_is_expired(oc));
		RETURN(oc);
	}

	spin_lock(&capa_lock);
	*key = osd->od_capa_keys[1];
	spin_unlock(&capa_lock);

	capa->lc_keyid = key->lk_keyid;
	capa->lc_expiry = cfs_time_current_sec() + osd->od_capa_timeout;

	rc = capa_hmac(capa->lc_hmac, capa, key->lk_key);
	if (rc) {
		DEBUG_CAPA(D_ERROR, capa, "HMAC failed: %d for", rc);
		RETURN(ERR_PTR(rc));
	}

	oc = capa_add(osd->od_capa_hash, capa);
	RETURN(oc);
}

static int osd_object_sync(const struct lu_env *env, struct dt_object *dt)
{
	struct osd_object	*obj    = osd_dt_obj(dt);
	struct inode		*inode  = obj->oo_inode;
	struct osd_thread_info	*info   = osd_oti_get(env);
	struct dentry		*dentry = &info->oti_obj_dentry;
	struct file		*file   = &info->oti_file;
	int			rc;

	ENTRY;

	dentry->d_inode = inode;
	dentry->d_sb = inode->i_sb;
	file->f_dentry = dentry;
	file->f_mapping = inode->i_mapping;
	file->f_op = inode->i_fop;
#ifndef HAVE_FILE_FSYNC_4ARGS
	mutex_lock(&inode->i_mutex);
#endif
	rc = do_fsync(file, 0);
#ifndef HAVE_FILE_FSYNC_4ARGS
	mutex_unlock(&inode->i_mutex);
#endif
	RETURN(rc);
}

static int osd_data_get(const struct lu_env *env, struct dt_object *dt,
                        void **data)
{
        struct osd_object *obj = osd_dt_obj(dt);
        ENTRY;

        *data = (void *)obj->oo_inode;
        RETURN(0);
}

/*
 * Index operations.
 */

static int osd_iam_index_probe(const struct lu_env *env, struct osd_object *o,
                           const struct dt_index_features *feat)
{
        struct iam_descr *descr;

        if (osd_object_is_root(o))
                return feat == &dt_directory_features;

        LASSERT(o->oo_dir != NULL);

        descr = o->oo_dir->od_container.ic_descr;
        if (feat == &dt_directory_features) {
                if (descr->id_rec_size == sizeof(struct osd_fid_pack))
                        return 1;
                else
                        return 0;
        } else {
                return
                        feat->dif_keysize_min <= descr->id_key_size &&
                        descr->id_key_size <= feat->dif_keysize_max &&
                        feat->dif_recsize_min <= descr->id_rec_size &&
                        descr->id_rec_size <= feat->dif_recsize_max &&
                        !(feat->dif_flags & (DT_IND_VARKEY |
                                             DT_IND_VARREC | DT_IND_NONUNQ)) &&
                        ergo(feat->dif_flags & DT_IND_UPDATE,
                             1 /* XXX check that object (and file system) is
                                * writable */);
        }
}

static int osd_iam_container_init(const struct lu_env *env,
                                  struct osd_object *obj,
                                  struct osd_directory *dir)
{
        struct iam_container *bag = &dir->od_container;
        int result;

        result = iam_container_init(bag, &dir->od_descr, obj->oo_inode);
        if (result != 0)
                return result;

        result = iam_container_setup(bag);
        if (result == 0)
                obj->oo_dt.do_index_ops = &osd_index_iam_ops;
        else
                iam_container_fini(bag);

        return result;
}


/*
 * Concurrency: no external locking is necessary.
 */
static int osd_index_try(const struct lu_env *env, struct dt_object *dt,
                         const struct dt_index_features *feat)
{
	int			 result;
	int			 skip_iam = 0;
	struct osd_object	*obj = osd_dt_obj(dt);

        LINVRNT(osd_invariant(obj));

        if (osd_object_is_root(obj)) {
                dt->do_index_ops = &osd_index_ea_ops;
                result = 0;
	} else if (feat == &dt_directory_features) {
                dt->do_index_ops = &osd_index_ea_ops;
		if (obj->oo_inode != NULL && S_ISDIR(obj->oo_inode->i_mode))
                        result = 0;
                else
                        result = -ENOTDIR;
		skip_iam = 1;
	} else if (unlikely(feat == &dt_otable_features)) {
		dt->do_index_ops = &osd_otable_ops;
		return 0;
	} else if (unlikely(feat == &dt_acct_features)) {
		dt->do_index_ops = &osd_acct_index_ops;
		result = 0;
		skip_iam = 1;
        } else if (!osd_has_index(obj)) {
                struct osd_directory *dir;

                OBD_ALLOC_PTR(dir);
                if (dir != NULL) {

			spin_lock(&obj->oo_guard);
			if (obj->oo_dir == NULL)
				obj->oo_dir = dir;
			else
				/*
				 * Concurrent thread allocated container data.
				 */
				OBD_FREE_PTR(dir);
			spin_unlock(&obj->oo_guard);
			/*
			 * Now, that we have container data, serialize its
			 * initialization.
			 */
			down_write(&obj->oo_ext_idx_sem);
			/*
			 * recheck under lock.
			 */
			if (!osd_has_index(obj))
				result = osd_iam_container_init(env, obj, dir);
			else
				result = 0;
			up_write(&obj->oo_ext_idx_sem);
                } else {
                        result = -ENOMEM;
                }
        } else {
                result = 0;
        }

	if (result == 0 && skip_iam == 0) {
                if (!osd_iam_index_probe(env, obj, feat))
                        result = -ENOTDIR;
        }
        LINVRNT(osd_invariant(obj));

	if (result == 0 && is_quota_glb_feat(feat) &&
	    fid_seq(lu_object_fid(&dt->do_lu)) == FID_SEQ_QUOTA_GLB)
		result = osd_quota_migration(env, dt, feat);

        return result;
}

static int osd_otable_it_attr_get(const struct lu_env *env,
				 struct dt_object *dt,
				 struct lu_attr *attr,
				 struct lustre_capa *capa)
{
	attr->la_valid = 0;
	return 0;
}

static const struct dt_object_operations osd_obj_ops = {
        .do_read_lock         = osd_object_read_lock,
        .do_write_lock        = osd_object_write_lock,
        .do_read_unlock       = osd_object_read_unlock,
        .do_write_unlock      = osd_object_write_unlock,
        .do_write_locked      = osd_object_write_locked,
        .do_attr_get          = osd_attr_get,
        .do_declare_attr_set  = osd_declare_attr_set,
        .do_attr_set          = osd_attr_set,
        .do_ah_init           = osd_ah_init,
        .do_declare_create    = osd_declare_object_create,
        .do_create            = osd_object_create,
        .do_declare_destroy   = osd_declare_object_destroy,
        .do_destroy           = osd_object_destroy,
        .do_index_try         = osd_index_try,
        .do_declare_ref_add   = osd_declare_object_ref_add,
        .do_ref_add           = osd_object_ref_add,
        .do_declare_ref_del   = osd_declare_object_ref_del,
        .do_ref_del           = osd_object_ref_del,
        .do_xattr_get         = osd_xattr_get,
        .do_declare_xattr_set = osd_declare_xattr_set,
        .do_xattr_set         = osd_xattr_set,
        .do_declare_xattr_del = osd_declare_xattr_del,
        .do_xattr_del         = osd_xattr_del,
        .do_xattr_list        = osd_xattr_list,
        .do_capa_get          = osd_capa_get,
        .do_object_sync       = osd_object_sync,
        .do_data_get          = osd_data_get,
};

/**
 * dt_object_operations for interoperability mode
 * (i.e. to run 2.0 mds on 1.8 disk) (b11826)
 */
static const struct dt_object_operations osd_obj_ea_ops = {
        .do_read_lock         = osd_object_read_lock,
        .do_write_lock        = osd_object_write_lock,
        .do_read_unlock       = osd_object_read_unlock,
        .do_write_unlock      = osd_object_write_unlock,
        .do_write_locked      = osd_object_write_locked,
        .do_attr_get          = osd_attr_get,
        .do_declare_attr_set  = osd_declare_attr_set,
        .do_attr_set          = osd_attr_set,
        .do_ah_init           = osd_ah_init,
        .do_declare_create    = osd_declare_object_create,
        .do_create            = osd_object_ea_create,
        .do_declare_destroy   = osd_declare_object_destroy,
        .do_destroy           = osd_object_destroy,
        .do_index_try         = osd_index_try,
        .do_declare_ref_add   = osd_declare_object_ref_add,
        .do_ref_add           = osd_object_ref_add,
        .do_declare_ref_del   = osd_declare_object_ref_del,
        .do_ref_del           = osd_object_ref_del,
        .do_xattr_get         = osd_xattr_get,
        .do_declare_xattr_set = osd_declare_xattr_set,
        .do_xattr_set         = osd_xattr_set,
        .do_declare_xattr_del = osd_declare_xattr_del,
        .do_xattr_del         = osd_xattr_del,
        .do_xattr_list        = osd_xattr_list,
        .do_capa_get          = osd_capa_get,
        .do_object_sync       = osd_object_sync,
        .do_data_get          = osd_data_get,
};

static const struct dt_object_operations osd_obj_otable_it_ops = {
	.do_attr_get	= osd_otable_it_attr_get,
	.do_index_try	= osd_index_try,
};

static int osd_index_declare_iam_delete(const struct lu_env *env,
                                        struct dt_object *dt,
                                        const struct dt_key *key,
                                        struct thandle *handle)
{
        struct osd_thandle    *oh;

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle == NULL);

	osd_trans_declare_op(env, oh, OSD_OT_DELETE,
			     osd_dto_credits_noquota[DTO_INDEX_DELETE]);

	return 0;
}

/**
 *      delete a (key, value) pair from index \a dt specified by \a key
 *
 *      \param  dt      osd index object
 *      \param  key     key for index
 *      \param  rec     record reference
 *      \param  handle  transaction handler
 *
 *      \retval  0  success
 *      \retval -ve   failure
 */

static int osd_index_iam_delete(const struct lu_env *env, struct dt_object *dt,
                                const struct dt_key *key,
                                struct thandle *handle,
                                struct lustre_capa *capa)
{
        struct osd_thread_info *oti = osd_oti_get(env);
        struct osd_object      *obj = osd_dt_obj(dt);
        struct osd_thandle     *oh;
        struct iam_path_descr  *ipd;
        struct iam_container   *bag = &obj->oo_dir->od_container;
        int                     rc;

        ENTRY;

        LINVRNT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(bag->ic_object == obj->oo_inode);
        LASSERT(handle != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_DELETE))
                RETURN(-EACCES);

	osd_trans_exec_op(env, handle, OSD_OT_DELETE);

        ipd = osd_idx_ipd_get(env, bag);
        if (unlikely(ipd == NULL))
                RETURN(-ENOMEM);

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);
        LASSERT(oh->ot_handle->h_transaction != NULL);

	if (fid_is_quota(lu_object_fid(&dt->do_lu))) {
		/* swab quota uid/gid provided by caller */
		oti->oti_quota_id = cpu_to_le64(*((__u64 *)key));
		key = (const struct dt_key *)&oti->oti_quota_id;
	}

        rc = iam_delete(oh->ot_handle, bag, (const struct iam_key *)key, ipd);
        osd_ipd_put(env, bag, ipd);
        LINVRNT(osd_invariant(obj));
        RETURN(rc);
}

static int osd_index_declare_ea_delete(const struct lu_env *env,
				       struct dt_object *dt,
				       const struct dt_key *key,
				       struct thandle *handle)
{
	struct osd_thandle *oh;
	struct inode	   *inode;
	int		    rc;
	ENTRY;

	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
	LASSERT(handle != NULL);

	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle == NULL);

	osd_trans_declare_op(env, oh, OSD_OT_DELETE,
			     osd_dto_credits_noquota[DTO_INDEX_DELETE]);

	inode = osd_dt_obj(dt)->oo_inode;
	LASSERT(inode);

	rc = osd_declare_inode_qid(env, inode->i_uid, inode->i_gid, 0, oh,
				   osd_dt_obj(dt), true, NULL, false);
	RETURN(rc);
}

static inline int osd_get_fid_from_dentry(struct ldiskfs_dir_entry_2 *de,
                                          struct dt_rec *fid)
{
        struct osd_fid_pack *rec;
        int                  rc = -ENODATA;

        if (de->file_type & LDISKFS_DIRENT_LUFID) {
                rec = (struct osd_fid_pack *) (de->name + de->name_len + 1);
                rc = osd_fid_unpack((struct lu_fid *)fid, rec);
        }
	return rc;
}

static int osd_mdt_seq_exists(const struct lu_env *env,
			      struct osd_device *osd, obd_seq seq)
{
	struct lu_seq_range	*range = &osd_oti_get(env)->oti_seq_range;
	struct seq_server_site	*ss = osd_seq_site(osd);
	int			rc;
	ENTRY;

	if (ss == NULL)
		RETURN(1);

	/* XXX: currently, each MDT only store avaible sequence on disk, and no
	 * allocated sequences information on disk, so we have to lookup FLDB,
	 * but it probably makes more sense also store allocated sequence
	 * locally, so we do not need do remote FLDB lookup in OSD */
	rc = osd_fld_lookup(env, osd, seq, range);
	if (rc != 0) {
		CERROR("%s: Can not lookup fld for "LPX64"\n",
		       osd_name(osd), seq);
		RETURN(0);
	}

	RETURN(ss->ss_node_id == range->lsr_index);
}

static int osd_remote_fid(const struct lu_env *env, struct osd_device *osd,
			  struct lu_fid *fid)
{
	ENTRY;

	/* FID seqs not in FLDB, must be local seq */
	if (unlikely(!fid_seq_in_fldb(fid_seq(fid))))
		RETURN(0);

	/* Currently only check this for FID on MDT */
	if (osd_mdt_seq_exists(env, osd, fid_seq(fid)))
		RETURN(0);

	RETURN(1);
}

/**
 * Index delete function for interoperability mode (b11826).
 * It will remove the directory entry added by osd_index_ea_insert().
 * This entry is needed to maintain name->fid mapping.
 *
 * \param key,  key i.e. file entry to be deleted
 *
 * \retval   0, on success
 * \retval -ve, on error
 */
static int osd_index_ea_delete(const struct lu_env *env, struct dt_object *dt,
                               const struct dt_key *key,
                               struct thandle *handle,
                               struct lustre_capa *capa)
{
        struct osd_object          *obj    = osd_dt_obj(dt);
        struct inode               *dir    = obj->oo_inode;
        struct dentry              *dentry;
        struct osd_thandle         *oh;
	struct ldiskfs_dir_entry_2 *de = NULL;
        struct buffer_head         *bh;
        struct htree_lock          *hlock = NULL;
	struct lu_fid		   *fid = &osd_oti_get(env)->oti_fid;
	struct osd_device	   *osd = osd_dev(dt->do_lu.lo_dev);
	int			   rc;
        ENTRY;

        LINVRNT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(handle != NULL);

	osd_trans_exec_op(env, handle, OSD_OT_DELETE);

        oh = container_of(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);
        LASSERT(oh->ot_handle->h_transaction != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_DELETE))
                RETURN(-EACCES);

	ll_vfs_dq_init(dir);
        dentry = osd_child_dentry_get(env, obj,
                                      (char *)key, strlen((char *)key));

        if (obj->oo_hl_head != NULL) {
                hlock = osd_oti_get(env)->oti_hlock;
                ldiskfs_htree_lock(hlock, obj->oo_hl_head,
                                   dir, LDISKFS_HLOCK_DEL);
        } else {
		down_write(&obj->oo_ext_idx_sem);
        }

        bh = osd_ldiskfs_find_entry(dir, &dentry->d_name, &de, NULL, hlock);
        if (bh) {
		__u32 ino = 0;

		/* If this is not the ".." entry, it might be a remote DNE
		 * entry and  we need to check if the FID is for a remote
		 * MDT.  If the FID is  not in the directory entry (e.g.
		 * upgraded 1.8 filesystem without dirdata enabled) then
		 * we need to get the FID from the LMA. For a remote directory
		 * there HAS to be an LMA, it cannot be an IGIF inode in this
		 * case.
		 *
		 * Delete the entry before the agent inode in order to
		 * simplify error handling.  At worst an error after deleting
		 * the entry first might leak the agent inode afterward. The
		 * reverse would need filesystem abort in case of error deleting
		 * the entry after the agent had been removed, or leave a
		 * dangling entry pointing at a random inode. */
		if (strcmp((char *)key, dotdot) != 0) {
			LASSERT(de != NULL);
			rc = osd_get_fid_from_dentry(de, (struct dt_rec *)fid);
			/* If Fid is not in dentry, try to get it from LMA */
			if (rc == -ENODATA) {
				struct osd_inode_id *id;
				struct inode *inode;

				/* Before trying to get fid from the inode,
				 * check whether the inode is valid.
				 *
				 * If the inode has been deleted, do not go
				 * ahead to do osd_ea_fid_get, which will set
				 * the inode to bad inode, which might cause
				 * the inode to be deleted uncorrectly */
				inode = ldiskfs_iget(osd_sb(osd),
						     le32_to_cpu(de->inode));
				if (IS_ERR(inode)) {
					CDEBUG(D_INODE, "%s: "DFID"get inode"
					       "error.\n", osd_name(osd),
					       PFID(fid));
					rc = PTR_ERR(inode);
				} else {
					if (likely(inode->i_nlink != 0)) {
						id = &osd_oti_get(env)->oti_id;
						rc = osd_ea_fid_get(env, obj,
						        le32_to_cpu(de->inode),
								    fid, id);
					} else {
						CDEBUG(D_INFO, "%s: %u "DFID
						       "deleted.\n",
						       osd_name(osd),
						       le32_to_cpu(de->inode),
						       PFID(fid));
						rc = -ESTALE;
					}
					iput(inode);
				}
			}
			if (rc == 0 &&
			    unlikely(osd_remote_fid(env, osd, fid)))
				/* Need to delete agent inode */
				ino = le32_to_cpu(de->inode);
		}
                rc = ldiskfs_delete_entry(oh->ot_handle, dir, de, bh);
                brelse(bh);
		if (rc == 0 && unlikely(ino != 0)) {
			rc = osd_delete_local_agent_inode(env, osd, fid, ino,
							  oh);
			if (rc != 0)
				CERROR("%s: del local inode "DFID": rc = %d\n",
				       osd_name(osd), PFID(fid), rc);
		}
        } else {
                rc = -ENOENT;
        }
        if (hlock != NULL)
                ldiskfs_htree_unlock(hlock);
        else
		up_write(&obj->oo_ext_idx_sem);

	if (rc != 0)
		GOTO(out, rc);

	/* For inode on the remote MDT, .. will point to
	 * /Agent directory, Check whether it needs to delete
	 * from agent directory */
	if (unlikely(strcmp((char *)key, dotdot) == 0)) {
		rc = osd_delete_from_remote_parent(env, osd_obj2dev(obj), obj,
						   oh);
		if (rc != 0 && rc != -ENOENT) {
			CERROR("%s: delete agent inode "DFID": rc = %d\n",
			       osd_name(osd), PFID(fid), rc);
		}

		if (rc == -ENOENT)
			rc = 0;

		GOTO(out, rc);
	}
out:

        LASSERT(osd_invariant(obj));
        RETURN(rc);
}

/**
 *      Lookup index for \a key and copy record to \a rec.
 *
 *      \param  dt      osd index object
 *      \param  key     key for index
 *      \param  rec     record reference
 *
 *      \retval  +ve  success : exact mach
 *      \retval  0    return record with key not greater than \a key
 *      \retval -ve   failure
 */
static int osd_index_iam_lookup(const struct lu_env *env, struct dt_object *dt,
                                struct dt_rec *rec, const struct dt_key *key,
                                struct lustre_capa *capa)
{
        struct osd_object      *obj = osd_dt_obj(dt);
        struct iam_path_descr  *ipd;
        struct iam_container   *bag = &obj->oo_dir->od_container;
        struct osd_thread_info *oti = osd_oti_get(env);
        struct iam_iterator    *it = &oti->oti_idx_it;
        struct iam_rec         *iam_rec;
        int                     rc;

        ENTRY;

        LASSERT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(bag->ic_object == obj->oo_inode);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_LOOKUP))
                RETURN(-EACCES);

        ipd = osd_idx_ipd_get(env, bag);
        if (IS_ERR(ipd))
                RETURN(-ENOMEM);

        /* got ipd now we can start iterator. */
        iam_it_init(it, bag, 0, ipd);

	if (fid_is_quota(lu_object_fid(&dt->do_lu))) {
		/* swab quota uid/gid provided by caller */
		oti->oti_quota_id = cpu_to_le64(*((__u64 *)key));
		key = (const struct dt_key *)&oti->oti_quota_id;
	}

        rc = iam_it_get(it, (struct iam_key *)key);
        if (rc >= 0) {
                if (S_ISDIR(obj->oo_inode->i_mode))
                        iam_rec = (struct iam_rec *)oti->oti_ldp;
                else
                        iam_rec = (struct iam_rec *) rec;

                iam_reccpy(&it->ii_path.ip_leaf, (struct iam_rec *)iam_rec);

                if (S_ISDIR(obj->oo_inode->i_mode))
                        osd_fid_unpack((struct lu_fid *) rec,
                                       (struct osd_fid_pack *)iam_rec);
		else if (fid_is_quota(lu_object_fid(&dt->do_lu)))
			osd_quota_unpack(obj, rec);
        }

        iam_it_put(it);
        iam_it_fini(it);
        osd_ipd_put(env, bag, ipd);

        LINVRNT(osd_invariant(obj));

        RETURN(rc);
}

static int osd_index_declare_iam_insert(const struct lu_env *env,
                                        struct dt_object *dt,
                                        const struct dt_rec *rec,
                                        const struct dt_key *key,
                                        struct thandle *handle)
{
        struct osd_thandle *oh;

        LASSERT(handle != NULL);

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle == NULL);

	osd_trans_declare_op(env, oh, OSD_OT_INSERT,
			     osd_dto_credits_noquota[DTO_INDEX_INSERT]);

	return 0;
}

/**
 *      Inserts (key, value) pair in \a dt index object.
 *
 *      \param  dt      osd index object
 *      \param  key     key for index
 *      \param  rec     record reference
 *      \param  th      transaction handler
 *
 *      \retval  0  success
 *      \retval -ve failure
 */
static int osd_index_iam_insert(const struct lu_env *env, struct dt_object *dt,
                                const struct dt_rec *rec,
                                const struct dt_key *key, struct thandle *th,
                                struct lustre_capa *capa, int ignore_quota)
{
        struct osd_object     *obj = osd_dt_obj(dt);
        struct iam_path_descr *ipd;
        struct osd_thandle    *oh;
        struct iam_container  *bag = &obj->oo_dir->od_container;
        struct osd_thread_info *oti = osd_oti_get(env);
        struct iam_rec         *iam_rec;
        int                     rc;

        ENTRY;

        LINVRNT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(bag->ic_object == obj->oo_inode);
        LASSERT(th != NULL);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_INSERT))
		RETURN(-EACCES);

	osd_trans_exec_op(env, th, OSD_OT_INSERT);

        ipd = osd_idx_ipd_get(env, bag);
        if (unlikely(ipd == NULL))
                RETURN(-ENOMEM);

        oh = container_of0(th, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);
        LASSERT(oh->ot_handle->h_transaction != NULL);
	if (S_ISDIR(obj->oo_inode->i_mode)) {
		iam_rec = (struct iam_rec *)oti->oti_ldp;
		osd_fid_pack((struct osd_fid_pack *)iam_rec, rec, &oti->oti_fid);
	} else if (fid_is_quota(lu_object_fid(&dt->do_lu))) {
		/* pack quota uid/gid */
		oti->oti_quota_id = cpu_to_le64(*((__u64 *)key));
		key = (const struct dt_key *)&oti->oti_quota_id;
		/* pack quota record */
		rec = osd_quota_pack(obj, rec, &oti->oti_quota_rec);
		iam_rec = (struct iam_rec *)rec;
	} else {
		iam_rec = (struct iam_rec *)rec;
	}

        rc = iam_insert(oh->ot_handle, bag, (const struct iam_key *)key,
                        iam_rec, ipd);
        osd_ipd_put(env, bag, ipd);
        LINVRNT(osd_invariant(obj));
        RETURN(rc);
}

/**
 * Calls ldiskfs_add_entry() to add directory entry
 * into the directory. This is required for
 * interoperability mode (b11826)
 *
 * \retval   0, on success
 * \retval -ve, on error
 */
static int __osd_ea_add_rec(struct osd_thread_info *info,
                            struct osd_object *pobj, struct inode  *cinode,
                            const char *name, const struct dt_rec *fid,
                            struct htree_lock *hlock, struct thandle *th)
{
        struct ldiskfs_dentry_param *ldp;
        struct dentry               *child;
        struct osd_thandle          *oth;
        int                          rc;

        oth = container_of(th, struct osd_thandle, ot_super);
        LASSERT(oth->ot_handle != NULL);
        LASSERT(oth->ot_handle->h_transaction != NULL);
	LASSERT(pobj->oo_inode);

	ldp = (struct ldiskfs_dentry_param *)info->oti_ldp;
	if (unlikely(pobj->oo_inode ==
		     osd_sb(osd_obj2dev(pobj))->s_root->d_inode))
		ldp->edp_magic = 0;
	else
		osd_get_ldiskfs_dirent_param(ldp, fid);
	child = osd_child_dentry_get(info->oti_env, pobj, name, strlen(name));
	child->d_fsdata = (void *)ldp;
	ll_vfs_dq_init(pobj->oo_inode);
	rc = osd_ldiskfs_add_entry(oth->ot_handle, child, cinode, hlock);

	RETURN(rc);
}

/**
 * Calls ldiskfs_add_dot_dotdot() to add dot and dotdot entries
 * into the directory.Also sets flags into osd object to
 * indicate dot and dotdot are created. This is required for
 * interoperability mode (b11826)
 *
 * \param dir   directory for dot and dotdot fixup.
 * \param obj   child object for linking
 *
 * \retval   0, on success
 * \retval -ve, on error
 */
static int osd_add_dot_dotdot(struct osd_thread_info *info,
                              struct osd_object *dir,
                              struct inode  *parent_dir, const char *name,
                              const struct dt_rec *dot_fid,
                              const struct dt_rec *dot_dot_fid,
                              struct thandle *th)
{
        struct inode                *inode = dir->oo_inode;
        struct osd_thandle          *oth;
        int result = 0;

        oth = container_of(th, struct osd_thandle, ot_super);
        LASSERT(oth->ot_handle->h_transaction != NULL);
        LASSERT(S_ISDIR(dir->oo_inode->i_mode));

        if (strcmp(name, dot) == 0) {
                if (dir->oo_compat_dot_created) {
                        result = -EEXIST;
                } else {
                        LASSERT(inode == parent_dir);
                        dir->oo_compat_dot_created = 1;
                        result = 0;
                }
	} else if (strcmp(name, dotdot) == 0) {
		if (!dir->oo_compat_dot_created)
			return -EINVAL;
		/* in case of rename, dotdot is already created */
		if (dir->oo_compat_dotdot_created) {
			return __osd_ea_add_rec(info, dir, parent_dir, name,
						dot_dot_fid, NULL, th);
		}

		result = osd_add_dot_dotdot_internal(info, dir->oo_inode,
						parent_dir, dot_fid,
						dot_dot_fid, oth);
		if (result == 0)
			dir->oo_compat_dotdot_created = 1;
	}

	return result;
}


/**
 * It will call the appropriate osd_add* function and return the
 * value, return by respective functions.
 */
static int osd_ea_add_rec(const struct lu_env *env, struct osd_object *pobj,
                          struct inode *cinode, const char *name,
                          const struct dt_rec *fid, struct thandle *th)
{
        struct osd_thread_info *info   = osd_oti_get(env);
        struct htree_lock      *hlock;
        int                     rc;

        hlock = pobj->oo_hl_head != NULL ? info->oti_hlock : NULL;

        if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' &&
                                                   name[2] =='\0'))) {
                if (hlock != NULL) {
                        ldiskfs_htree_lock(hlock, pobj->oo_hl_head,
                                           pobj->oo_inode, 0);
                } else {
			down_write(&pobj->oo_ext_idx_sem);
                }
                rc = osd_add_dot_dotdot(info, pobj, cinode, name,
                     (struct dt_rec *)lu_object_fid(&pobj->oo_dt.do_lu),
                                        fid, th);
        } else {
                if (hlock != NULL) {
                        ldiskfs_htree_lock(hlock, pobj->oo_hl_head,
                                           pobj->oo_inode, LDISKFS_HLOCK_ADD);
                } else {
			down_write(&pobj->oo_ext_idx_sem);
                }

		if (OBD_FAIL_CHECK(OBD_FAIL_FID_INDIR)) {
			struct lu_fid *tfid = &info->oti_fid;

			*tfid = *(const struct lu_fid *)fid;
			tfid->f_ver = ~0;
			rc = __osd_ea_add_rec(info, pobj, cinode, name,
					      (const struct dt_rec *)tfid,
					      hlock, th);
		} else {
			rc = __osd_ea_add_rec(info, pobj, cinode, name, fid,
					      hlock, th);
		}
        }
        if (hlock != NULL)
                ldiskfs_htree_unlock(hlock);
        else
		up_write(&pobj->oo_ext_idx_sem);

        return rc;
}

static void
osd_consistency_check(struct osd_thread_info *oti, struct osd_device *dev,
		      struct osd_idmap_cache *oic)
{
	struct osd_scrub    *scrub = &dev->od_scrub;
	struct lu_fid	    *fid   = &oic->oic_fid;
	struct osd_inode_id *id    = &oti->oti_id;
	int		     once  = 0;
	int		     rc;
	ENTRY;

	if (!fid_is_norm(fid) && !fid_is_igif(fid))
		RETURN_EXIT;

again:
	rc = osd_oi_lookup(oti, dev, fid, id, OI_CHECK_FLD);
	if (rc != 0 && rc != -ENOENT)
		RETURN_EXIT;

	if (rc == 0 && osd_id_eq(id, &oic->oic_lid))
		RETURN_EXIT;

	if (thread_is_running(&scrub->os_thread)) {
		rc = osd_oii_insert(dev, oic, rc == -ENOENT);
		/* There is race condition between osd_oi_lookup and OI scrub.
		 * The OI scrub finished just after osd_oi_lookup() failure.
		 * Under such case, it is unnecessary to trigger OI scrub again,
		 * but try to call osd_oi_lookup() again. */
		if (unlikely(rc == -EAGAIN))
			goto again;

		RETURN_EXIT;
	}

	if (!dev->od_noscrub && ++once == 1) {
		rc = osd_scrub_start(dev);
		LCONSOLE_WARN("%.16s: trigger OI scrub by RPC for "DFID
			      ", rc = %d [2]\n",
			      LDISKFS_SB(osd_sb(dev))->s_es->s_volume_name,
			      PFID(fid), rc);
		if (rc == 0)
			goto again;
	}

	EXIT;
}

static int osd_fail_fid_lookup(struct osd_thread_info *oti,
			       struct osd_device *dev,
			       struct osd_idmap_cache *oic,
			       struct lu_fid *fid, __u32 ino)
{
	struct lustre_mdt_attrs *lma   = &oti->oti_mdt_attrs;
	struct inode		*inode;
	int			 rc;

	osd_id_gen(&oic->oic_lid, ino, OSD_OII_NOGEN);
	inode = osd_iget(oti, dev, &oic->oic_lid);
	if (IS_ERR(inode)) {
		fid_zero(&oic->oic_fid);
		return PTR_ERR(inode);
	}

	rc = osd_get_lma(oti, inode, &oti->oti_obj_dentry, lma);
	iput(inode);
	if (rc != 0)
		fid_zero(&oic->oic_fid);
	else
		*fid = oic->oic_fid = lma->lma_self_fid;
	return rc;
}

int osd_add_oi_cache(struct osd_thread_info *info, struct osd_device *osd,
		     struct osd_inode_id *id, const struct lu_fid *fid)
{
	CDEBUG(D_INODE, "add "DFID" %u:%u to info %p\n", PFID(fid),
	       id->oii_ino, id->oii_gen, info);
	info->oti_cache.oic_lid = *id;
	info->oti_cache.oic_fid = *fid;
	info->oti_cache.oic_dev = osd;

	return 0;
}

/**
 * Calls ->lookup() to find dentry. From dentry get inode and
 * read inode's ea to get fid. This is required for  interoperability
 * mode (b11826)
 *
 * \retval   0, on success
 * \retval -ve, on error
 */
static int osd_ea_lookup_rec(const struct lu_env *env, struct osd_object *obj,
                             struct dt_rec *rec, const struct dt_key *key)
{
        struct inode               *dir    = obj->oo_inode;
        struct dentry              *dentry;
        struct ldiskfs_dir_entry_2 *de;
        struct buffer_head         *bh;
        struct lu_fid              *fid = (struct lu_fid *) rec;
        struct htree_lock          *hlock = NULL;
        int                         ino;
        int                         rc;
	ENTRY;

        LASSERT(dir->i_op != NULL && dir->i_op->lookup != NULL);

        dentry = osd_child_dentry_get(env, obj,
                                      (char *)key, strlen((char *)key));

        if (obj->oo_hl_head != NULL) {
                hlock = osd_oti_get(env)->oti_hlock;
                ldiskfs_htree_lock(hlock, obj->oo_hl_head,
                                   dir, LDISKFS_HLOCK_LOOKUP);
        } else {
		down_read(&obj->oo_ext_idx_sem);
        }

        bh = osd_ldiskfs_find_entry(dir, &dentry->d_name, &de, NULL, hlock);
        if (bh) {
		struct osd_thread_info *oti = osd_oti_get(env);
		struct osd_inode_id *id = &oti->oti_id;
		struct osd_idmap_cache *oic = &oti->oti_cache;
		struct osd_device *dev = osd_obj2dev(obj);
		struct osd_scrub *scrub = &dev->od_scrub;
		struct scrub_file *sf = &scrub->os_file;

		ino = le32_to_cpu(de->inode);
		if (OBD_FAIL_CHECK(OBD_FAIL_FID_LOOKUP)) {
			brelse(bh);
			rc = osd_fail_fid_lookup(oti, dev, oic, fid, ino);
			GOTO(out, rc);
		}

		rc = osd_get_fid_from_dentry(de, rec);

		/* done with de, release bh */
		brelse(bh);
		if (rc != 0)
			rc = osd_ea_fid_get(env, obj, ino, fid, id);
		else
			osd_id_gen(id, ino, OSD_OII_NOGEN);
		if (rc != 0) {
			fid_zero(&oic->oic_fid);
			GOTO(out, rc);
		}

		if (osd_remote_fid(env, dev, fid))
			GOTO(out, rc = 0);

		rc = osd_add_oi_cache(osd_oti_get(env), osd_obj2dev(obj), id,
				      fid);
		if (rc != 0)
			GOTO(out, rc);
		if ((scrub->os_pos_current <= ino) &&
		    ((sf->sf_flags & SF_INCONSISTENT) ||
		     (sf->sf_flags & SF_UPGRADE && fid_is_igif(fid)) ||
		     ldiskfs_test_bit(osd_oi_fid2idx(dev, fid),
				      sf->sf_oi_bitmap)))
			osd_consistency_check(oti, dev, oic);
	} else {
		rc = -ENOENT;
	}

	GOTO(out, rc);

out:
	if (hlock != NULL)
		ldiskfs_htree_unlock(hlock);
	else
		up_read(&obj->oo_ext_idx_sem);
	return rc;
}

/**
 * Find the osd object for given fid.
 *
 * \param fid need to find the osd object having this fid
 *
 * \retval osd_object on success
 * \retval        -ve on error
 */
struct osd_object *osd_object_find(const struct lu_env *env,
                                   struct dt_object *dt,
                                   const struct lu_fid *fid)
{
        struct lu_device  *ludev = dt->do_lu.lo_dev;
        struct osd_object *child = NULL;
        struct lu_object  *luch;
        struct lu_object  *lo;

	/*
	 * at this point topdev might not exist yet
	 * (i.e. MGS is preparing profiles). so we can
	 * not rely on topdev and instead lookup with
	 * our device passed as topdev. this can't work
	 * if the object isn't cached yet (as osd doesn't
	 * allocate lu_header). IOW, the object must be
	 * in the cache, otherwise lu_object_alloc() crashes
	 * -bzzz
	 */
	luch = lu_object_find_at(env, ludev, fid, NULL);
        if (!IS_ERR(luch)) {
                if (lu_object_exists(luch)) {
                        lo = lu_object_locate(luch->lo_header, ludev->ld_type);
                        if (lo != NULL)
                                child = osd_obj(lo);
                        else
                                LU_OBJECT_DEBUG(D_ERROR, env, luch,
                                                "lu_object can't be located"
						DFID"\n", PFID(fid));

                        if (child == NULL) {
                                lu_object_put(env, luch);
                                CERROR("Unable to get osd_object\n");
                                child = ERR_PTR(-ENOENT);
                        }
                } else {
                        LU_OBJECT_DEBUG(D_ERROR, env, luch,
                                        "lu_object does not exists "DFID"\n",
                                        PFID(fid));
			lu_object_put(env, luch);
                        child = ERR_PTR(-ENOENT);
                }
	} else {
		child = ERR_CAST(luch);
	}

	return child;
}

/**
 * Put the osd object once done with it.
 *
 * \param obj osd object that needs to be put
 */
static inline void osd_object_put(const struct lu_env *env,
                                  struct osd_object *obj)
{
        lu_object_put(env, &obj->oo_dt.do_lu);
}

static int osd_index_declare_ea_insert(const struct lu_env *env,
				       struct dt_object *dt,
				       const struct dt_rec *rec,
				       const struct dt_key *key,
				       struct thandle *handle)
{
	struct osd_thandle	*oh;
	struct osd_device	*osd   = osd_dev(dt->do_lu.lo_dev);
	struct lu_fid		*fid = (struct lu_fid *)rec;
	int			rc;
	ENTRY;

	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
	LASSERT(handle != NULL);

	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle == NULL);

	osd_trans_declare_op(env, oh, OSD_OT_INSERT,
			     osd_dto_credits_noquota[DTO_INDEX_INSERT]);

	if (osd_dt_obj(dt)->oo_inode == NULL) {
		const char *name  = (const char *)key;
		/* Object is not being created yet. Only happens when
		 *     1. declare directory create
		 *     2. declare insert .
		 *     3. declare insert ..
		 */
		LASSERT(strcmp(name, dotdot) == 0 || strcmp(name, dot) == 0);
	} else {
		struct inode *inode = osd_dt_obj(dt)->oo_inode;

		/* We ignore block quota on meta pool (MDTs), so needn't
		 * calculate how many blocks will be consumed by this index
		 * insert */
		rc = osd_declare_inode_qid(env, inode->i_uid, inode->i_gid, 0,
					   oh, osd_dt_obj(dt), true, NULL,
					   false);
	}

	if (fid == NULL)
		RETURN(0);

	rc = osd_remote_fid(env, osd, fid);
	if (rc <= 0)
		RETURN(rc);

	rc = 0;

	osd_trans_declare_op(env, oh, OSD_OT_CREATE,
			     osd_dto_credits_noquota[DTO_OBJECT_CREATE]);
	osd_trans_declare_op(env, oh, OSD_OT_INSERT,
			     osd_dto_credits_noquota[DTO_INDEX_INSERT] + 1);
	osd_trans_declare_op(env, oh, OSD_OT_INSERT,
			     osd_dto_credits_noquota[DTO_INDEX_INSERT] + 1);

	RETURN(rc);
}

/**
 * Index add function for interoperability mode (b11826).
 * It will add the directory entry.This entry is needed to
 * maintain name->fid mapping.
 *
 * \param key it is key i.e. file entry to be inserted
 * \param rec it is value of given key i.e. fid
 *
 * \retval   0, on success
 * \retval -ve, on error
 */
static int osd_index_ea_insert(const struct lu_env *env, struct dt_object *dt,
                               const struct dt_rec *rec,
                               const struct dt_key *key, struct thandle *th,
                               struct lustre_capa *capa, int ignore_quota)
{
	struct osd_object	*obj = osd_dt_obj(dt);
	struct osd_device	*osd = osd_dev(dt->do_lu.lo_dev);
	struct lu_fid		*fid = (struct lu_fid *) rec;
	const char		*name = (const char *)key;
	struct osd_thread_info	*oti   = osd_oti_get(env);
	struct osd_inode_id	*id    = &oti->oti_id;
	struct inode		*child_inode = NULL;
	struct osd_object	*child = NULL;
	int			rc;
	ENTRY;

        LASSERT(osd_invariant(obj));
	LASSERT(dt_object_exists(dt) && !dt_object_remote(dt));
        LASSERT(th != NULL);

	osd_trans_exec_op(env, th, OSD_OT_INSERT);

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_INSERT))
                RETURN(-EACCES);

	LASSERTF(fid_is_sane(fid), "fid"DFID" is insane!", PFID(fid));

	rc = osd_remote_fid(env, osd, fid);
	if (rc < 0) {
		CERROR("%s: Can not find object "DFID" rc %d\n",
		       osd_name(osd), PFID(fid), rc);
		RETURN(rc);
	}

	if (rc == 1) {
		/* Insert remote entry */
		if (strcmp(name, dotdot) == 0 && strlen(name) == 2) {
			struct osd_mdobj_map	*omm = osd->od_mdt_map;
			struct osd_thandle	*oh;

			/* If parent on remote MDT, we need put this object
			 * under AGENT */
			oh = container_of(th, typeof(*oh), ot_super);
			rc = osd_add_to_remote_parent(env, osd, obj, oh);
			if (rc != 0) {
				CERROR("%s: add "DFID" error: rc = %d\n",
				       osd_name(osd),
				       PFID(lu_object_fid(&dt->do_lu)), rc);
				RETURN(rc);
			}

			child_inode = igrab(omm->omm_remote_parent->d_inode);
		} else {
			child_inode = osd_create_local_agent_inode(env, osd,
								   obj, fid,
								   th);
			if (IS_ERR(child_inode))
				RETURN(PTR_ERR(child_inode));
		}
	} else {
		/* Insert local entry */
		child = osd_object_find(env, dt, fid);
		if (IS_ERR(child)) {
			CERROR("%s: Can not find object "DFID"%u:%u: rc = %d\n",
			       osd_name(osd), PFID(fid),
			       id->oii_ino, id->oii_gen,
			       (int)PTR_ERR(child));
			RETURN(PTR_ERR(child));
		}
		child_inode = igrab(child->oo_inode);
	}

	rc = osd_ea_add_rec(env, obj, child_inode, name, rec, th);

	iput(child_inode);
	if (child != NULL)
		osd_object_put(env, child);
	LASSERT(osd_invariant(obj));
	RETURN(rc);
}

/**
 *  Initialize osd Iterator for given osd index object.
 *
 *  \param  dt      osd index object
 */

static struct dt_it *osd_it_iam_init(const struct lu_env *env,
                                     struct dt_object *dt,
                                     __u32 unused,
                                     struct lustre_capa *capa)
{
        struct osd_it_iam      *it;
        struct osd_thread_info *oti = osd_oti_get(env);
        struct osd_object      *obj = osd_dt_obj(dt);
        struct lu_object       *lo  = &dt->do_lu;
        struct iam_path_descr  *ipd;
        struct iam_container   *bag = &obj->oo_dir->od_container;

        LASSERT(lu_object_exists(lo));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_BODY_READ))
                return ERR_PTR(-EACCES);

        it = &oti->oti_it;
        ipd = osd_it_ipd_get(env, bag);
        if (likely(ipd != NULL)) {
                it->oi_obj = obj;
                it->oi_ipd = ipd;
                lu_object_get(lo);
                iam_it_init(&it->oi_it, bag, IAM_IT_MOVE, ipd);
                return (struct dt_it *)it;
        }
        return ERR_PTR(-ENOMEM);
}

/**
 * free given Iterator.
 */

static void osd_it_iam_fini(const struct lu_env *env, struct dt_it *di)
{
        struct osd_it_iam *it = (struct osd_it_iam *)di;
        struct osd_object *obj = it->oi_obj;

        iam_it_fini(&it->oi_it);
        osd_ipd_put(env, &obj->oo_dir->od_container, it->oi_ipd);
        lu_object_put(env, &obj->oo_dt.do_lu);
}

/**
 *  Move Iterator to record specified by \a key
 *
 *  \param  di      osd iterator
 *  \param  key     key for index
 *
 *  \retval +ve  di points to record with least key not larger than key
 *  \retval  0   di points to exact matched key
 *  \retval -ve  failure
 */

static int osd_it_iam_get(const struct lu_env *env,
                          struct dt_it *di, const struct dt_key *key)
{
	struct osd_thread_info	*oti = osd_oti_get(env);
	struct osd_it_iam	*it = (struct osd_it_iam *)di;

	if (fid_is_quota(lu_object_fid(&it->oi_obj->oo_dt.do_lu))) {
		/* swab quota uid/gid */
		oti->oti_quota_id = cpu_to_le64(*((__u64 *)key));
		key = (struct dt_key *)&oti->oti_quota_id;
	}

        return iam_it_get(&it->oi_it, (const struct iam_key *)key);
}

/**
 *  Release Iterator
 *
 *  \param  di      osd iterator
 */
static void osd_it_iam_put(const struct lu_env *env, struct dt_it *di)
{
        struct osd_it_iam *it = (struct osd_it_iam *)di;

        iam_it_put(&it->oi_it);
}

/**
 *  Move iterator by one record
 *
 *  \param  di      osd iterator
 *
 *  \retval +1   end of container reached
 *  \retval  0   success
 *  \retval -ve  failure
 */

static int osd_it_iam_next(const struct lu_env *env, struct dt_it *di)
{
        struct osd_it_iam *it = (struct osd_it_iam *)di;

        return iam_it_next(&it->oi_it);
}

/**
 * Return pointer to the key under iterator.
 */

static struct dt_key *osd_it_iam_key(const struct lu_env *env,
                                 const struct dt_it *di)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_it_iam      *it = (struct osd_it_iam *)di;
	struct osd_object      *obj = it->oi_obj;
	struct dt_key          *key;

	key = (struct dt_key *)iam_it_key_get(&it->oi_it);

	if (!IS_ERR(key) && fid_is_quota(lu_object_fid(&obj->oo_dt.do_lu))) {
		/* swab quota uid/gid */
		oti->oti_quota_id = le64_to_cpu(*((__u64 *)key));
		key = (struct dt_key *)&oti->oti_quota_id;
	}

	return key;
}

/**
 * Return size of key under iterator (in bytes)
 */

static int osd_it_iam_key_size(const struct lu_env *env, const struct dt_it *di)
{
        struct osd_it_iam *it = (struct osd_it_iam *)di;

        return iam_it_key_size(&it->oi_it);
}

static inline void
osd_it_append_attrs(struct lu_dirent *ent, int len, __u16 type)
{
	/* check if file type is required */
	if (ent->lde_attrs & LUDA_TYPE) {
		struct luda_type *lt;
		int align = sizeof(*lt) - 1;

		len = (len + align) & ~align;
		lt = (struct luda_type *)(ent->lde_name + len);
		lt->lt_type = cpu_to_le16(DTTOIF(type));
	}

	ent->lde_attrs = cpu_to_le32(ent->lde_attrs);
}

/**
 * build lu direct from backend fs dirent.
 */

static inline void
osd_it_pack_dirent(struct lu_dirent *ent, struct lu_fid *fid, __u64 offset,
		   char *name, __u16 namelen, __u16 type, __u32 attr)
{
	ent->lde_attrs = attr | LUDA_FID;
	fid_cpu_to_le(&ent->lde_fid, fid);

	ent->lde_hash = cpu_to_le64(offset);
	ent->lde_reclen = cpu_to_le16(lu_dirent_calc_size(namelen, attr));

	strncpy(ent->lde_name, name, namelen);
	ent->lde_name[namelen] = '\0';
	ent->lde_namelen = cpu_to_le16(namelen);

	/* append lustre attributes */
	osd_it_append_attrs(ent, namelen, type);
}

/**
 * Return pointer to the record under iterator.
 */
static int osd_it_iam_rec(const struct lu_env *env,
                          const struct dt_it *di,
                          struct dt_rec *dtrec, __u32 attr)
{
	struct osd_it_iam      *it   = (struct osd_it_iam *)di;
	struct osd_thread_info *info = osd_oti_get(env);
	ENTRY;

	if (S_ISDIR(it->oi_obj->oo_inode->i_mode)) {
		const struct osd_fid_pack *rec;
		struct lu_fid             *fid = &info->oti_fid;
		struct lu_dirent          *lde = (struct lu_dirent *)dtrec;
		char                      *name;
		int                        namelen;
		__u64                      hash;
		int                        rc;

		name = (char *)iam_it_key_get(&it->oi_it);
		if (IS_ERR(name))
			RETURN(PTR_ERR(name));

		namelen = iam_it_key_size(&it->oi_it);

		rec = (const struct osd_fid_pack *)iam_it_rec_get(&it->oi_it);
		if (IS_ERR(rec))
			RETURN(PTR_ERR(rec));

		rc = osd_fid_unpack(fid, rec);
		if (rc)
			RETURN(rc);

		hash = iam_it_store(&it->oi_it);

		/* IAM does not store object type in IAM index (dir) */
		osd_it_pack_dirent(lde, fid, hash, name, namelen,
				   0, LUDA_FID);
	} else if (fid_is_quota(lu_object_fid(&it->oi_obj->oo_dt.do_lu))) {
		iam_reccpy(&it->oi_it.ii_path.ip_leaf,
			   (struct iam_rec *)dtrec);
		osd_quota_unpack(it->oi_obj, dtrec);
	} else {
		iam_reccpy(&it->oi_it.ii_path.ip_leaf,
			   (struct iam_rec *)dtrec);
	}

	RETURN(0);
}

/**
 * Returns cookie for current Iterator position.
 */
static __u64 osd_it_iam_store(const struct lu_env *env, const struct dt_it *di)
{
        struct osd_it_iam *it = (struct osd_it_iam *)di;

        return iam_it_store(&it->oi_it);
}

/**
 * Restore iterator from cookie.
 *
 * \param  di      osd iterator
 * \param  hash    Iterator location cookie
 *
 * \retval +ve  di points to record with least key not larger than key.
 * \retval  0   di points to exact matched key
 * \retval -ve  failure
 */

static int osd_it_iam_load(const struct lu_env *env,
                           const struct dt_it *di, __u64 hash)
{
        struct osd_it_iam *it = (struct osd_it_iam *)di;

        return iam_it_load(&it->oi_it, hash);
}

static const struct dt_index_operations osd_index_iam_ops = {
        .dio_lookup         = osd_index_iam_lookup,
        .dio_declare_insert = osd_index_declare_iam_insert,
        .dio_insert         = osd_index_iam_insert,
        .dio_declare_delete = osd_index_declare_iam_delete,
        .dio_delete         = osd_index_iam_delete,
        .dio_it     = {
                .init     = osd_it_iam_init,
                .fini     = osd_it_iam_fini,
                .get      = osd_it_iam_get,
                .put      = osd_it_iam_put,
                .next     = osd_it_iam_next,
                .key      = osd_it_iam_key,
                .key_size = osd_it_iam_key_size,
                .rec      = osd_it_iam_rec,
                .store    = osd_it_iam_store,
                .load     = osd_it_iam_load
        }
};


/**
 * Creates or initializes iterator context.
 *
 * \retval struct osd_it_ea, iterator structure on success
 *
 */
static struct dt_it *osd_it_ea_init(const struct lu_env *env,
                                    struct dt_object *dt,
                                    __u32 attr,
                                    struct lustre_capa *capa)
{
        struct osd_object       *obj  = osd_dt_obj(dt);
        struct osd_thread_info  *info = osd_oti_get(env);
        struct osd_it_ea        *it   = &info->oti_it_ea;
	struct file		*file = &it->oie_file;
        struct lu_object        *lo   = &dt->do_lu;
        struct dentry           *obj_dentry = &info->oti_it_dentry;
        ENTRY;
        LASSERT(lu_object_exists(lo));

        obj_dentry->d_inode = obj->oo_inode;
        obj_dentry->d_sb = osd_sb(osd_obj2dev(obj));
        obj_dentry->d_name.hash = 0;

        it->oie_rd_dirent       = 0;
        it->oie_it_dirent       = 0;
        it->oie_dirent          = NULL;
        it->oie_buf             = info->oti_it_ea_buf;
        it->oie_obj             = obj;

	/* Reset the "file" totally to avoid to reuse any old value from
	 * former readdir handling, the "file->f_pos" should be zero. */
	memset(file, 0, sizeof(*file));
	/* Only FMODE_64BITHASH or FMODE_32BITHASH should be set, NOT both. */
	if (attr & LUDA_64BITHASH)
		file->f_mode	= FMODE_64BITHASH;
	else
		file->f_mode	= FMODE_32BITHASH;
	file->f_dentry		= obj_dentry;
	file->f_mapping 	= obj->oo_inode->i_mapping;
	file->f_op		= obj->oo_inode->i_fop;
	lu_object_get(lo);
	RETURN((struct dt_it *) it);
}

/**
 * Destroy or finishes iterator context.
 *
 * \param di iterator structure to be destroyed
 */
static void osd_it_ea_fini(const struct lu_env *env, struct dt_it *di)
{
        struct osd_it_ea     *it   = (struct osd_it_ea *)di;
        struct osd_object    *obj  = it->oie_obj;
        struct inode       *inode  = obj->oo_inode;

        ENTRY;
        it->oie_file.f_op->release(inode, &it->oie_file);
        lu_object_put(env, &obj->oo_dt.do_lu);
        EXIT;
}

/**
 * It position the iterator at given key, so that next lookup continues from
 * that key Or it is similar to dio_it->load() but based on a key,
 * rather than file position.
 *
 * As a special convention, osd_it_ea_get(env, di, "") has to rewind iterator
 * to the beginning.
 *
 * TODO: Presently return +1 considering it is only used by mdd_dir_is_empty().
 */
static int osd_it_ea_get(const struct lu_env *env,
                         struct dt_it *di, const struct dt_key *key)
{
        struct osd_it_ea     *it   = (struct osd_it_ea *)di;

        ENTRY;
        LASSERT(((const char *)key)[0] == '\0');
        it->oie_file.f_pos      = 0;
        it->oie_rd_dirent       = 0;
        it->oie_it_dirent       = 0;
        it->oie_dirent          = NULL;

        RETURN(+1);
}

/**
 * Does nothing
 */
static void osd_it_ea_put(const struct lu_env *env, struct dt_it *di)
{
}

/**
 * It is called internally by ->readdir(). It fills the
 * iterator's in-memory data structure with required
 * information i.e. name, namelen, rec_size etc.
 *
 * \param buf in which information to be filled in.
 * \param name name of the file in given dir
 *
 * \retval 0 on success
 * \retval 1 on buffer full
 */
static int osd_ldiskfs_filldir(char *buf, const char *name, int namelen,
                               loff_t offset, __u64 ino,
                               unsigned d_type)
{
        struct osd_it_ea        *it   = (struct osd_it_ea *)buf;
	struct osd_object	*obj  = it->oie_obj;
        struct osd_it_ea_dirent *ent  = it->oie_dirent;
        struct lu_fid           *fid  = &ent->oied_fid;
        struct osd_fid_pack     *rec;
        ENTRY;

        /* this should never happen */
        if (unlikely(namelen == 0 || namelen > LDISKFS_NAME_LEN)) {
                CERROR("ldiskfs return invalid namelen %d\n", namelen);
                RETURN(-EIO);
        }

        if ((void *) ent - it->oie_buf + sizeof(*ent) + namelen >
            OSD_IT_EA_BUFSIZE)
                RETURN(1);

	/* "." is just the object itself. */
	if (namelen == 1 && name[0] == '.') {
		*fid = obj->oo_dt.do_lu.lo_header->loh_fid;
	} else if (d_type & LDISKFS_DIRENT_LUFID) {
		rec = (struct osd_fid_pack*) (name + namelen + 1);
		if (osd_fid_unpack(fid, rec) != 0)
			fid_zero(fid);
	} else {
		fid_zero(fid);
	}
	d_type &= ~LDISKFS_DIRENT_LUFID;

	/* NOT export local root. */
	if (unlikely(osd_sb(osd_obj2dev(obj))->s_root->d_inode->i_ino == ino)) {
		ino = obj->oo_inode->i_ino;
		*fid = obj->oo_dt.do_lu.lo_header->loh_fid;
	}

        ent->oied_ino     = ino;
        ent->oied_off     = offset;
        ent->oied_namelen = namelen;
        ent->oied_type    = d_type;

        memcpy(ent->oied_name, name, namelen);

        it->oie_rd_dirent++;
        it->oie_dirent = (void *) ent + cfs_size_round(sizeof(*ent) + namelen);
        RETURN(0);
}

/**
 * Calls ->readdir() to load a directory entry at a time
 * and stored it in iterator's in-memory data structure.
 *
 * \param di iterator's in memory structure
 *
 * \retval   0 on success
 * \retval -ve on error
 */
static int osd_ldiskfs_it_fill(const struct lu_env *env,
                               const struct dt_it *di)
{
        struct osd_it_ea   *it    = (struct osd_it_ea *)di;
        struct osd_object  *obj   = it->oie_obj;
        struct inode       *inode = obj->oo_inode;
        struct htree_lock  *hlock = NULL;
        int                 result = 0;

        ENTRY;
        it->oie_dirent = it->oie_buf;
        it->oie_rd_dirent = 0;

        if (obj->oo_hl_head != NULL) {
                hlock = osd_oti_get(env)->oti_hlock;
                ldiskfs_htree_lock(hlock, obj->oo_hl_head,
                                   inode, LDISKFS_HLOCK_READDIR);
        } else {
		down_read(&obj->oo_ext_idx_sem);
        }

        result = inode->i_fop->readdir(&it->oie_file, it,
                                       (filldir_t) osd_ldiskfs_filldir);

        if (hlock != NULL)
                ldiskfs_htree_unlock(hlock);
        else
		up_read(&obj->oo_ext_idx_sem);

        if (it->oie_rd_dirent == 0) {
                result = -EIO;
        } else {
                it->oie_dirent = it->oie_buf;
                it->oie_it_dirent = 1;
        }

        RETURN(result);
}

/**
 * It calls osd_ldiskfs_it_fill() which will use ->readdir()
 * to load a directory entry at a time and stored it in
 * iterator's in-memory data structure.
 *
 * \param di iterator's in memory structure
 *
 * \retval +ve iterator reached to end
 * \retval   0 iterator not reached to end
 * \retval -ve on error
 */
static int osd_it_ea_next(const struct lu_env *env, struct dt_it *di)
{
        struct osd_it_ea *it = (struct osd_it_ea *)di;
        int rc;

        ENTRY;

        if (it->oie_it_dirent < it->oie_rd_dirent) {
                it->oie_dirent =
                        (void *) it->oie_dirent +
                        cfs_size_round(sizeof(struct osd_it_ea_dirent) +
                                       it->oie_dirent->oied_namelen);
                it->oie_it_dirent++;
                RETURN(0);
        } else {
		if (it->oie_file.f_pos == ldiskfs_get_htree_eof(&it->oie_file))
                        rc = +1;
                else
                        rc = osd_ldiskfs_it_fill(env, di);
        }

        RETURN(rc);
}

/**
 * Returns the key at current position from iterator's in memory structure.
 *
 * \param di iterator's in memory structure
 *
 * \retval key i.e. struct dt_key on success
 */
static struct dt_key *osd_it_ea_key(const struct lu_env *env,
                                    const struct dt_it *di)
{
        struct osd_it_ea *it = (struct osd_it_ea *)di;

        return (struct dt_key *)it->oie_dirent->oied_name;
}

/**
 * Returns the key's size at current position from iterator's in memory structure.
 *
 * \param di iterator's in memory structure
 *
 * \retval key_size i.e. struct dt_key on success
 */
static int osd_it_ea_key_size(const struct lu_env *env, const struct dt_it *di)
{
        struct osd_it_ea *it = (struct osd_it_ea *)di;

        return it->oie_dirent->oied_namelen;
}

static int
osd_dirent_update(handle_t *jh, struct super_block *sb,
		  struct osd_it_ea_dirent *ent, struct lu_fid *fid,
		  struct buffer_head *bh, struct ldiskfs_dir_entry_2 *de)
{
	struct osd_fid_pack *rec;
	int		     rc;
	ENTRY;

	LASSERT(de->file_type & LDISKFS_DIRENT_LUFID);
	LASSERT(de->rec_len >= de->name_len + sizeof(struct osd_fid_pack));

	rc = ldiskfs_journal_get_write_access(jh, bh);
	if (rc != 0) {
		CERROR("%.16s: fail to write access for update dirent: "
		       "name = %.*s, rc = %d\n",
		       LDISKFS_SB(sb)->s_es->s_volume_name,
		       ent->oied_namelen, ent->oied_name, rc);
		RETURN(rc);
	}

	rec = (struct osd_fid_pack *)(de->name + de->name_len + 1);
	fid_cpu_to_be((struct lu_fid *)rec->fp_area, fid);
	rc = ldiskfs_journal_dirty_metadata(jh, bh);
	if (rc != 0)
		CERROR("%.16s: fail to dirty metadata for update dirent: "
		       "name = %.*s, rc = %d\n",
		       LDISKFS_SB(sb)->s_es->s_volume_name,
		       ent->oied_namelen, ent->oied_name, rc);

	RETURN(rc);
}

static inline int
osd_dirent_has_space(__u16 reclen, __u16 namelen, unsigned blocksize)
{
	if (ldiskfs_rec_len_from_disk(reclen, blocksize) >=
	    __LDISKFS_DIR_REC_LEN(namelen + 1 + sizeof(struct osd_fid_pack)))
		return 1;
	else
		return 0;
}

static inline int
osd_dot_dotdot_has_space(struct ldiskfs_dir_entry_2 *de, int dot_dotdot)
{
	LASSERTF(dot_dotdot == 1 || dot_dotdot == 2,
		 "dot_dotdot = %d\n", dot_dotdot);

	if (LDISKFS_DIR_REC_LEN(de) >=
	    __LDISKFS_DIR_REC_LEN(dot_dotdot + 1 + sizeof(struct osd_fid_pack)))
		return 1;
	else
		return 0;
}

static int
osd_dirent_reinsert(const struct lu_env *env, handle_t *jh,
		    struct inode *dir, struct inode *inode,
		    struct osd_it_ea_dirent *ent, struct lu_fid *fid,
		    struct buffer_head *bh, struct ldiskfs_dir_entry_2 *de,
		    struct htree_lock *hlock)
{
	struct dentry		    *dentry;
	struct osd_fid_pack	    *rec;
	struct ldiskfs_dentry_param *ldp;
	int			     rc;
	ENTRY;

	if (!LDISKFS_HAS_INCOMPAT_FEATURE(inode->i_sb,
					  LDISKFS_FEATURE_INCOMPAT_DIRDATA))
		RETURN(0);

	/* There is enough space to hold the FID-in-dirent. */
	if (osd_dirent_has_space(de->rec_len, ent->oied_namelen,
				 dir->i_sb->s_blocksize)) {
		rc = ldiskfs_journal_get_write_access(jh, bh);
		if (rc != 0) {
			CERROR("%.16s: fail to write access for reinsert "
			       "dirent: name = %.*s, rc = %d\n",
			       LDISKFS_SB(inode->i_sb)->s_es->s_volume_name,
			       ent->oied_namelen, ent->oied_name, rc);
			RETURN(rc);
		}

		de->name[de->name_len] = 0;
		rec = (struct osd_fid_pack *)(de->name + de->name_len + 1);
		rec->fp_len = sizeof(struct lu_fid) + 1;
		fid_cpu_to_be((struct lu_fid *)rec->fp_area, fid);
		de->file_type |= LDISKFS_DIRENT_LUFID;

		rc = ldiskfs_journal_dirty_metadata(jh, bh);
		if (rc != 0)
			CERROR("%.16s: fail to dirty metadata for reinsert "
			       "dirent: name = %.*s, rc = %d\n",
			       LDISKFS_SB(inode->i_sb)->s_es->s_volume_name,
			       ent->oied_namelen, ent->oied_name, rc);

		RETURN(rc);
	}

	rc = ldiskfs_delete_entry(jh, dir, de, bh);
	if (rc != 0) {
		CERROR("%.16s: fail to delete entry for reinsert dirent: "
		       "name = %.*s, rc = %d\n",
		       LDISKFS_SB(inode->i_sb)->s_es->s_volume_name,
		       ent->oied_namelen, ent->oied_name, rc);
		RETURN(rc);
	}

	dentry = osd_child_dentry_by_inode(env, dir, ent->oied_name,
					   ent->oied_namelen);
	ldp = (struct ldiskfs_dentry_param *)osd_oti_get(env)->oti_ldp;
	osd_get_ldiskfs_dirent_param(ldp, (const struct dt_rec *)fid);
	dentry->d_fsdata = (void *)ldp;
	ll_vfs_dq_init(dir);
	rc = osd_ldiskfs_add_entry(jh, dentry, inode, hlock);
	/* It is too bad, we cannot reinsert the name entry back.
	 * That means we lose it! */
	if (rc != 0)
		CERROR("%.16s: fail to insert entry for reinsert dirent: "
		       "name = %.*s, rc = %d\n",
		       LDISKFS_SB(inode->i_sb)->s_es->s_volume_name,
		       ent->oied_namelen, ent->oied_name, rc);

	RETURN(rc);
}

static int
osd_dirent_check_repair(const struct lu_env *env, struct osd_object *obj,
			struct osd_it_ea *it, struct lu_fid *fid,
			struct osd_inode_id *id, __u32 *attr)
{
	struct osd_thread_info     *info	= osd_oti_get(env);
	struct lustre_mdt_attrs    *lma		= &info->oti_mdt_attrs;
	struct osd_device	   *dev		= osd_obj2dev(obj);
	struct super_block	   *sb		= osd_sb(dev);
	const char		   *devname	=
					LDISKFS_SB(sb)->s_es->s_volume_name;
	struct osd_it_ea_dirent    *ent		= it->oie_dirent;
	struct inode		   *dir		= obj->oo_inode;
	struct htree_lock	   *hlock	= NULL;
	struct buffer_head	   *bh		= NULL;
	handle_t		   *jh		= NULL;
	struct ldiskfs_dir_entry_2 *de;
	struct dentry		   *dentry;
	struct inode		   *inode;
	int			    credits;
	int			    rc;
	int			    dot_dotdot	= 0;
	bool			    dirty	= false;
	ENTRY;

	if (ent->oied_name[0] == '.') {
		if (ent->oied_namelen == 1)
			dot_dotdot = 1;
		else if (ent->oied_namelen == 2 && ent->oied_name[1] == '.')
			dot_dotdot = 2;
	}

	dentry = osd_child_dentry_get(env, obj, ent->oied_name,
				      ent->oied_namelen);

	/* We need to ensure that the name entry is still valid.
	 * Because it may be removed or renamed by other already.
	 *
	 * The unlink or rename operation will start journal before PDO lock,
	 * so to avoid deadlock, here we need to start journal handle before
	 * related PDO lock also. But because we do not know whether there
	 * will be something to be repaired before PDO lock, we just start
	 * journal without conditions.
	 *
	 * We may need to remove the name entry firstly, then insert back.
	 * One credit is for user quota file update.
	 * One credit is for group quota file update.
	 * Two credits are for dirty inode. */
	credits = osd_dto_credits_noquota[DTO_INDEX_DELETE] +
		  osd_dto_credits_noquota[DTO_INDEX_INSERT] + 1 + 1 + 2;

again:
	if (dev->od_dirent_journal) {
		jh = osd_journal_start_sb(sb, LDISKFS_HT_MISC, credits);
		if (IS_ERR(jh)) {
			rc = PTR_ERR(jh);
			CERROR("%.16s: fail to start trans for dirent "
			       "check_repair: credits %d, name %.*s, rc %d\n",
			       devname, credits, ent->oied_namelen,
			       ent->oied_name, rc);
			RETURN(rc);
		}

		if (obj->oo_hl_head != NULL) {
			hlock = osd_oti_get(env)->oti_hlock;
			/* "0" means exclusive lock for the whole directory.
			 * We need to prevent others access such name entry
			 * during the delete + insert. Neither HLOCK_ADD nor
			 * HLOCK_DEL cannot guarantee the atomicity. */
			ldiskfs_htree_lock(hlock, obj->oo_hl_head, dir, 0);
		} else {
			down_write(&obj->oo_ext_idx_sem);
		}
	} else {
		if (obj->oo_hl_head != NULL) {
			hlock = osd_oti_get(env)->oti_hlock;
			ldiskfs_htree_lock(hlock, obj->oo_hl_head, dir,
					   LDISKFS_HLOCK_LOOKUP);
		} else {
			down_read(&obj->oo_ext_idx_sem);
		}
	}

	bh = osd_ldiskfs_find_entry(dir, &dentry->d_name, &de, NULL, hlock);
	/* For dot/dotdot entry, if there is not enough space to hold the
	 * FID-in-dirent, just keep them there. It only happens when the
	 * device upgraded from 1.8 or restored from MDT file-level backup.
	 * For the whole directory, only dot/dotdot entry have no FID-in-dirent
	 * and needs to get FID from LMA when readdir, it will not affect the
	 * performance much. */
	if ((bh == NULL) || (le32_to_cpu(de->inode) != ent->oied_ino) ||
	    (dot_dotdot != 0 && !osd_dot_dotdot_has_space(de, dot_dotdot))) {
		*attr |= LUDA_IGNORE;
		GOTO(out_journal, rc = 0);
	}

	osd_id_gen(id, ent->oied_ino, OSD_OII_NOGEN);
	inode = osd_iget(info, dev, id);
	if (IS_ERR(inode)) {
		rc = PTR_ERR(inode);
		if (rc == -ENOENT || rc == -ESTALE) {
			*attr |= LUDA_IGNORE;
			rc = 0;
		}

		GOTO(out_journal, rc);
	}

	/* skip the REMOTE_PARENT_DIR. */
	if (inode == dev->od_mdt_map->omm_remote_parent->d_inode)
		GOTO(out_inode, rc = 0);

	rc = osd_get_lma(info, inode, &info->oti_obj_dentry, lma);
	if (rc == 0) {
		LASSERT(!(lma->lma_compat & LMAC_NOT_IN_OI));

		if (fid_is_sane(fid)) {
			/* FID-in-dirent is valid. */
			if (lu_fid_eq(fid, &lma->lma_self_fid))
				GOTO(out_inode, rc = 0);

			/* Do not repair under dryrun mode. */
			if (*attr & LUDA_VERIFY_DRYRUN) {
				*attr |= LUDA_REPAIR;
				GOTO(out_inode, rc = 0);
			}

			if (!dev->od_dirent_journal) {
				iput(inode);
				brelse(bh);
				if (hlock != NULL)
					ldiskfs_htree_unlock(hlock);
				else
					up_read(&obj->oo_ext_idx_sem);
				dev->od_dirent_journal = 1;
				goto again;
			}

			*fid = lma->lma_self_fid;
			dirty = true;
			/* Update the FID-in-dirent. */
			rc = osd_dirent_update(jh, sb, ent, fid, bh, de);
			if (rc == 0)
				*attr |= LUDA_REPAIR;
		} else {
			/* Do not repair under dryrun mode. */
			if (*attr & LUDA_VERIFY_DRYRUN) {
				*fid = lma->lma_self_fid;
				*attr |= LUDA_REPAIR;
				GOTO(out_inode, rc = 0);
			}

			if (!dev->od_dirent_journal) {
				iput(inode);
				brelse(bh);
				if (hlock != NULL)
					ldiskfs_htree_unlock(hlock);
				else
					up_read(&obj->oo_ext_idx_sem);
				dev->od_dirent_journal = 1;
				goto again;
			}

			*fid = lma->lma_self_fid;
			dirty = true;
			/* Append the FID-in-dirent. */
			rc = osd_dirent_reinsert(env, jh, dir, inode, ent,
						 fid, bh, de, hlock);
			if (rc == 0)
				*attr |= LUDA_REPAIR;
		}
	} else if (rc == -ENODATA) {
		/* Do not repair under dryrun mode. */
		if (*attr & LUDA_VERIFY_DRYRUN) {
			if (fid_is_sane(fid)) {
				*attr |= LUDA_REPAIR;
			} else {
				lu_igif_build(fid, inode->i_ino,
					      inode->i_generation);
				*attr |= LUDA_UPGRADE;
			}
			GOTO(out_inode, rc = 0);
		}

		if (!dev->od_dirent_journal) {
			iput(inode);
			brelse(bh);
			if (hlock != NULL)
				ldiskfs_htree_unlock(hlock);
			else
				up_read(&obj->oo_ext_idx_sem);
			dev->od_dirent_journal = 1;
			goto again;
		}

		dirty = true;
		if (unlikely(fid_is_sane(fid))) {
			/* FID-in-dirent exists, but FID-in-LMA is lost.
			 * Trust the FID-in-dirent, and add FID-in-LMA. */
			rc = osd_ea_fid_set(info, inode, fid, 0, 0);
			if (rc == 0)
				*attr |= LUDA_REPAIR;
		} else {
			lu_igif_build(fid, inode->i_ino, inode->i_generation);
			/* It is probably IGIF object. Only aappend the
			 * FID-in-dirent. OI scrub will process FID-in-LMA. */
			rc = osd_dirent_reinsert(env, jh, dir, inode, ent,
						 fid, bh, de, hlock);
			if (rc == 0)
				*attr |= LUDA_UPGRADE;
		}
	}

	GOTO(out_inode, rc);

out_inode:
	iput(inode);

out_journal:
	brelse(bh);
	if (hlock != NULL) {
		ldiskfs_htree_unlock(hlock);
	} else {
		if (dev->od_dirent_journal)
			up_write(&obj->oo_ext_idx_sem);
		else
			up_read(&obj->oo_ext_idx_sem);
	}
	if (jh != NULL)
		ldiskfs_journal_stop(jh);
	if (rc >= 0 && !dirty)
		dev->od_dirent_journal = 0;
	return rc;
}

/**
 * Returns the value at current position from iterator's in memory structure.
 *
 * \param di struct osd_it_ea, iterator's in memory structure
 * \param attr attr requested for dirent.
 * \param lde lustre dirent
 *
 * \retval   0 no error and \param lde has correct lustre dirent.
 * \retval -ve on error
 */
static inline int osd_it_ea_rec(const struct lu_env *env,
				const struct dt_it *di,
				struct dt_rec *dtrec, __u32 attr)
{
	struct osd_it_ea       *it    = (struct osd_it_ea *)di;
	struct osd_object      *obj   = it->oie_obj;
	struct osd_device      *dev   = osd_obj2dev(obj);
	struct osd_scrub       *scrub = &dev->od_scrub;
	struct scrub_file      *sf    = &scrub->os_file;
	struct osd_thread_info *oti   = osd_oti_get(env);
	struct osd_inode_id    *id    = &oti->oti_id;
	struct osd_idmap_cache *oic   = &oti->oti_cache;
	struct lu_fid	       *fid   = &it->oie_dirent->oied_fid;
	struct lu_dirent       *lde   = (struct lu_dirent *)dtrec;
	__u32			ino   = it->oie_dirent->oied_ino;
	int			rc    = 0;
	ENTRY;

	if (attr & LUDA_VERIFY) {
		attr |= LUDA_TYPE;
		if (unlikely(ino == osd_sb(dev)->s_root->d_inode->i_ino)) {
			attr |= LUDA_IGNORE;
			rc = 0;
		} else {
			rc = osd_dirent_check_repair(env, obj, it, fid, id,
						     &attr);
		}
	} else {
		attr &= ~LU_DIRENT_ATTRS_MASK;
		if (!fid_is_sane(fid)) {
			if (OBD_FAIL_CHECK(OBD_FAIL_FID_LOOKUP))
				RETURN(-ENOENT);

			rc = osd_ea_fid_get(env, obj, ino, fid, id);
		} else {
			osd_id_gen(id, ino, OSD_OII_NOGEN);
		}
	}

	/* Pack the entry anyway, at least the offset is right. */
	osd_it_pack_dirent(lde, fid, it->oie_dirent->oied_off,
			   it->oie_dirent->oied_name,
			   it->oie_dirent->oied_namelen,
			   it->oie_dirent->oied_type, attr);

	if (rc < 0)
		RETURN(rc);

	if (osd_remote_fid(env, dev, fid))
		RETURN(0);

	if (likely(!(attr & LUDA_IGNORE)))
		rc = osd_add_oi_cache(oti, dev, id, fid);

	if (!(attr & LUDA_VERIFY) &&
	    (scrub->os_pos_current <= ino) &&
	    ((sf->sf_flags & SF_INCONSISTENT) ||
	     (sf->sf_flags & SF_UPGRADE && fid_is_igif(fid)) ||
	     ldiskfs_test_bit(osd_oi_fid2idx(dev, fid), sf->sf_oi_bitmap)))
		osd_consistency_check(oti, dev, oic);

	RETURN(rc);
}

/**
 * Returns a cookie for current position of the iterator head, so that
 * user can use this cookie to load/start the iterator next time.
 *
 * \param di iterator's in memory structure
 *
 * \retval cookie for current position, on success
 */
static __u64 osd_it_ea_store(const struct lu_env *env, const struct dt_it *di)
{
        struct osd_it_ea *it = (struct osd_it_ea *)di;

        return it->oie_dirent->oied_off;
}

/**
 * It calls osd_ldiskfs_it_fill() which will use ->readdir()
 * to load a directory entry at a time and stored it i inn,
 * in iterator's in-memory data structure.
 *
 * \param di struct osd_it_ea, iterator's in memory structure
 *
 * \retval +ve on success
 * \retval -ve on error
 */
static int osd_it_ea_load(const struct lu_env *env,
                          const struct dt_it *di, __u64 hash)
{
        struct osd_it_ea *it = (struct osd_it_ea *)di;
        int rc;

        ENTRY;
        it->oie_file.f_pos = hash;

        rc =  osd_ldiskfs_it_fill(env, di);
        if (rc == 0)
                rc = +1;

        RETURN(rc);
}

/**
 * Index lookup function for interoperability mode (b11826).
 *
 * \param key,  key i.e. file name to be searched
 *
 * \retval +ve, on success
 * \retval -ve, on error
 */
static int osd_index_ea_lookup(const struct lu_env *env, struct dt_object *dt,
                               struct dt_rec *rec, const struct dt_key *key,
                               struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);
        int rc = 0;

        ENTRY;

        LASSERT(S_ISDIR(obj->oo_inode->i_mode));
        LINVRNT(osd_invariant(obj));

        if (osd_object_auth(env, dt, capa, CAPA_OPC_INDEX_LOOKUP))
                return -EACCES;

        rc = osd_ea_lookup_rec(env, obj, rec, key);
        if (rc == 0)
                rc = +1;
        RETURN(rc);
}

/**
 * Index and Iterator operations for interoperability
 * mode (i.e. to run 2.0 mds on 1.8 disk) (b11826)
 */
static const struct dt_index_operations osd_index_ea_ops = {
        .dio_lookup         = osd_index_ea_lookup,
        .dio_declare_insert = osd_index_declare_ea_insert,
        .dio_insert         = osd_index_ea_insert,
        .dio_declare_delete = osd_index_declare_ea_delete,
        .dio_delete         = osd_index_ea_delete,
        .dio_it     = {
                .init     = osd_it_ea_init,
                .fini     = osd_it_ea_fini,
                .get      = osd_it_ea_get,
                .put      = osd_it_ea_put,
                .next     = osd_it_ea_next,
                .key      = osd_it_ea_key,
                .key_size = osd_it_ea_key_size,
                .rec      = osd_it_ea_rec,
                .store    = osd_it_ea_store,
                .load     = osd_it_ea_load
        }
};

static void *osd_key_init(const struct lu_context *ctx,
                          struct lu_context_key *key)
{
        struct osd_thread_info *info;

        OBD_ALLOC_PTR(info);
        if (info == NULL)
                return ERR_PTR(-ENOMEM);

        OBD_ALLOC(info->oti_it_ea_buf, OSD_IT_EA_BUFSIZE);
        if (info->oti_it_ea_buf == NULL)
                goto out_free_info;

        info->oti_env = container_of(ctx, struct lu_env, le_ctx);

        info->oti_hlock = ldiskfs_htree_lock_alloc();
        if (info->oti_hlock == NULL)
                goto out_free_ea;

        return info;

 out_free_ea:
        OBD_FREE(info->oti_it_ea_buf, OSD_IT_EA_BUFSIZE);
 out_free_info:
        OBD_FREE_PTR(info);
        return ERR_PTR(-ENOMEM);
}

static void osd_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void* data)
{
	struct osd_thread_info *info = data;

	if (info->oti_hlock != NULL)
		ldiskfs_htree_lock_free(info->oti_hlock);
	OBD_FREE(info->oti_it_ea_buf, OSD_IT_EA_BUFSIZE);
	lu_buf_free(&info->oti_iobuf.dr_pg_buf);
	lu_buf_free(&info->oti_iobuf.dr_bl_buf);
	OBD_FREE_PTR(info);
}

static void osd_key_exit(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct osd_thread_info *info = data;

        LASSERT(info->oti_r_locks == 0);
        LASSERT(info->oti_w_locks == 0);
        LASSERT(info->oti_txns    == 0);
}

/* type constructor/destructor: osd_type_init, osd_type_fini */
LU_TYPE_INIT_FINI(osd, &osd_key);

struct lu_context_key osd_key = {
        .lct_tags = LCT_DT_THREAD | LCT_MD_THREAD | LCT_MG_THREAD | LCT_LOCAL,
        .lct_init = osd_key_init,
        .lct_fini = osd_key_fini,
        .lct_exit = osd_key_exit
};


static int osd_device_init(const struct lu_env *env, struct lu_device *d,
                           const char *name, struct lu_device *next)
{
	struct osd_device *osd = osd_dev(d);

	if (strlcpy(osd->od_svname, name, sizeof(osd->od_svname))
	    >= sizeof(osd->od_svname))
		return -E2BIG;
	return osd_procfs_init(osd, name);
}

static int osd_shutdown(const struct lu_env *env, struct osd_device *o)
{
	ENTRY;

	/* shutdown quota slave instance associated with the device */
	if (o->od_quota_slave != NULL) {
		qsd_fini(env, o->od_quota_slave);
		o->od_quota_slave = NULL;
	}

	RETURN(0);
}

static void osd_umount(const struct lu_env *env, struct osd_device *o)
{
	ENTRY;

	if (o->od_fsops) {
		fsfilt_put_ops(o->od_fsops);
		o->od_fsops = NULL;
	}

	if (o->od_mnt != NULL) {
		shrink_dcache_sb(osd_sb(o));
		osd_sync(env, &o->od_dt_dev);

		mntput(o->od_mnt);
		o->od_mnt = NULL;
	}

	EXIT;
}

static int osd_mount(const struct lu_env *env,
                     struct osd_device *o, struct lustre_cfg *cfg)
{
	const char		*name  = lustre_cfg_string(cfg, 0);
	const char		*dev  = lustre_cfg_string(cfg, 1);
	const char              *opts;
	unsigned long            page, s_flags, lmd_flags = 0;
	struct page             *__page;
	struct file_system_type *type;
	char                    *options = NULL;
	char			*str;
	struct osd_thread_info	*info = osd_oti_get(env);
	struct lu_fid		*fid = &info->oti_fid;
	struct inode		*inode;
	int			 rc = 0;
        ENTRY;

	if (o->od_mnt != NULL)
		RETURN(0);

	if (strlen(dev) >= sizeof(o->od_mntdev))
		RETURN(-E2BIG);
	strcpy(o->od_mntdev, dev);

	o->od_fsops = fsfilt_get_ops(mt_str(LDD_MT_LDISKFS));
	if (IS_ERR(o->od_fsops)) {
		CERROR("%s: Can't find fsfilt_ldiskfs\n", name);
		o->od_fsops = NULL;
		RETURN(-ENOTSUPP);
	}

	OBD_PAGE_ALLOC(__page, GFP_IOFS);
	if (__page == NULL)
		GOTO(out, rc = -ENOMEM);

	str = lustre_cfg_string(cfg, 2);
	s_flags = simple_strtoul(str, NULL, 0);
	str = strstr(str, ":");
	if (str)
		lmd_flags = simple_strtoul(str + 1, NULL, 0);
	opts = lustre_cfg_string(cfg, 3);
	page = (unsigned long)page_address(__page);
	options = (char *)page;
	*options = '\0';
	if (opts == NULL)
		strcat(options, "user_xattr,acl");
	else
		strcat(options, opts);

	/* Glom up mount options */
	if (*options != '\0')
		strcat(options, ",");
	strlcat(options, "no_mbcache", PAGE_CACHE_SIZE);

	type = get_fs_type("ldiskfs");
	if (!type) {
		CERROR("%s: cannot find ldiskfs module\n", name);
		GOTO(out, rc = -ENODEV);
	}

	o->od_mnt = vfs_kern_mount(type, s_flags, dev, options);
	module_put(type->owner);

	if (IS_ERR(o->od_mnt)) {
		rc = PTR_ERR(o->od_mnt);
		o->od_mnt = NULL;
		CERROR("%s: can't mount %s: %d\n", name, dev, rc);
		GOTO(out, rc);
	}

#ifdef HAVE_DEV_SET_RDONLY
	if (dev_check_rdonly(o->od_mnt->mnt_sb->s_bdev)) {
		CERROR("%s: underlying device %s is marked as read-only. "
		       "Setup failed\n", name, dev);
		GOTO(out_mnt, rc = -EROFS);
	}
#endif

	if (!LDISKFS_HAS_COMPAT_FEATURE(o->od_mnt->mnt_sb,
					LDISKFS_FEATURE_COMPAT_HAS_JOURNAL)) {
		CERROR("%s: device %s is mounted w/o journal\n", name, dev);
		GOTO(out_mnt, rc = -EINVAL);
	}

#ifdef LDISKFS_MOUNT_DIRDATA
	if (LDISKFS_HAS_INCOMPAT_FEATURE(o->od_mnt->mnt_sb,
					 LDISKFS_FEATURE_INCOMPAT_DIRDATA))
		LDISKFS_SB(osd_sb(o))->s_mount_opt |= LDISKFS_MOUNT_DIRDATA;
#endif
	inode = osd_sb(o)->s_root->d_inode;
	ldiskfs_set_inode_state(inode, LDISKFS_STATE_LUSTRE_NO_OI);
	lu_local_obj_fid(fid, OSD_FS_ROOT_OID);
	rc = osd_ea_fid_set(info, inode, fid, LMAC_NOT_IN_OI, 0);
	if (rc != 0) {
		CERROR("%s: failed to set lma on %s root inode\n", name, dev);
		GOTO(out_mnt, rc);
	}

	if (lmd_flags & LMD_FLG_NOSCRUB)
		o->od_noscrub = 1;

	GOTO(out, rc = 0);

out_mnt:
	mntput(o->od_mnt);
	o->od_mnt = NULL;

out:
	if (__page)
		OBD_PAGE_FREE(__page);
	if (rc)
		fsfilt_put_ops(o->od_fsops);

	return rc;
}

static struct lu_device *osd_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct osd_device *o = osd_dev(d);
	ENTRY;

	osd_shutdown(env, o);
	osd_procfs_fini(o);
	osd_scrub_cleanup(env, o);
	osd_obj_map_fini(o);
	osd_umount(env, o);

	RETURN(NULL);
}

static int osd_device_init0(const struct lu_env *env,
			    struct osd_device *o,
			    struct lustre_cfg *cfg)
{
	struct lu_device	*l = osd2lu_dev(o);
	struct osd_thread_info *info;
	int			rc;
	int			cplen = 0;

	/* if the module was re-loaded, env can loose its keys */
	rc = lu_env_refill((struct lu_env *) env);
	if (rc)
		GOTO(out, rc);
	info = osd_oti_get(env);
	LASSERT(info);

	l->ld_ops = &osd_lu_ops;
	o->od_dt_dev.dd_ops = &osd_dt_ops;

	spin_lock_init(&o->od_osfs_lock);
	mutex_init(&o->od_otable_mutex);
	o->od_osfs_age = cfs_time_shift_64(-1000);

	o->od_capa_hash = init_capa_hash();
	if (o->od_capa_hash == NULL)
		GOTO(out, rc = -ENOMEM);

	o->od_read_cache = 1;
	o->od_writethrough_cache = 1;
	o->od_readcache_max_filesize = OSD_MAX_CACHE_SIZE;

	rc = osd_mount(env, o, cfg);
	if (rc)
		GOTO(out_capa, rc);

	cplen = strlcpy(o->od_svname, lustre_cfg_string(cfg, 4),
			sizeof(o->od_svname));
	if (cplen >= sizeof(o->od_svname)) {
		rc = -E2BIG;
		GOTO(out_mnt, rc);
	}

	if (server_name_is_ost(o->od_svname))
		o->od_is_ost = 1;

	rc = osd_obj_map_init(env, o);
	if (rc != 0)
		GOTO(out_mnt, rc);

	rc = lu_site_init(&o->od_site, l);
	if (rc != 0)
		GOTO(out_compat, rc);
	o->od_site.ls_bottom_dev = l;

	rc = lu_site_init_finish(&o->od_site);
	if (rc != 0)
		GOTO(out_site, rc);

	CFS_INIT_LIST_HEAD(&o->od_ios_list);
	/* setup scrub, including OI files initialization */
	rc = osd_scrub_setup(env, o);
	if (rc < 0)
		GOTO(out_site, rc);

	rc = osd_procfs_init(o, o->od_svname);
	if (rc != 0) {
		CERROR("%s: can't initialize procfs: rc = %d\n",
		       o->od_svname, rc);
		GOTO(out_scrub, rc);
	}

	LASSERT(l->ld_site->ls_linkage.next && l->ld_site->ls_linkage.prev);

	/* initialize quota slave instance */
	o->od_quota_slave = qsd_init(env, o->od_svname, &o->od_dt_dev,
				     o->od_proc_entry);
	if (IS_ERR(o->od_quota_slave)) {
		rc = PTR_ERR(o->od_quota_slave);
		o->od_quota_slave = NULL;
		GOTO(out_procfs, rc);
	}

	RETURN(0);

out_procfs:
	osd_procfs_fini(o);
out_scrub:
	osd_scrub_cleanup(env, o);
out_site:
	lu_site_fini(&o->od_site);
out_compat:
	osd_obj_map_fini(o);
out_mnt:
	osd_umount(env, o);
out_capa:
	cleanup_capa_hash(o->od_capa_hash);
out:
	return rc;
}

static struct lu_device *osd_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
	struct osd_device *o;
	int                rc;

	OBD_ALLOC_PTR(o);
	if (o == NULL)
		return ERR_PTR(-ENOMEM);

	rc = dt_device_init(&o->od_dt_dev, t);
	if (rc == 0) {
		/* Because the ctx might be revived in dt_device_init,
		 * refill the env here */
		lu_env_refill((struct lu_env *)env);
		rc = osd_device_init0(env, o, cfg);
		if (rc)
			dt_device_fini(&o->od_dt_dev);
	}

	if (unlikely(rc != 0))
		OBD_FREE_PTR(o);

	return rc == 0 ? osd2lu_dev(o) : ERR_PTR(rc);
}

static struct lu_device *osd_device_free(const struct lu_env *env,
                                         struct lu_device *d)
{
        struct osd_device *o = osd_dev(d);
        ENTRY;

        cleanup_capa_hash(o->od_capa_hash);
	/* XXX: make osd top device in order to release reference */
	d->ld_site->ls_top_dev = d;
	lu_site_purge(env, d->ld_site, -1);
	if (!cfs_hash_is_empty(d->ld_site->ls_obj_hash)) {
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_ERROR, NULL);
		lu_site_print(env, d->ld_site, &msgdata, lu_cdebug_printer);
	}
	lu_site_fini(&o->od_site);
        dt_device_fini(&o->od_dt_dev);
        OBD_FREE_PTR(o);
        RETURN(NULL);
}

static int osd_process_config(const struct lu_env *env,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
	struct osd_device		*o = osd_dev(d);
	int				rc;
	ENTRY;

	switch (cfg->lcfg_command) {
	case LCFG_SETUP:
		rc = osd_mount(env, o, cfg);
		break;
	case LCFG_CLEANUP:
		lu_dev_del_linkage(d->ld_site, d);
		rc = osd_shutdown(env, o);
		break;
	case LCFG_PARAM:
		LASSERT(&o->od_dt_dev);
		rc = class_process_proc_param(PARAM_OSD, lprocfs_osd_obd_vars,
					      cfg, &o->od_dt_dev);
		if (rc > 0 || rc == -ENOSYS)
			rc = class_process_proc_param(PARAM_OST,
						      lprocfs_osd_obd_vars,
						      cfg, &o->od_dt_dev);
		break;
	default:
		rc = -ENOSYS;
	}

	RETURN(rc);
}

static int osd_recovery_complete(const struct lu_env *env,
                                 struct lu_device *d)
{
	struct osd_device	*osd = osd_dev(d);
	int			 rc = 0;
	ENTRY;

	if (osd->od_quota_slave == NULL)
		RETURN(0);

	/* start qsd instance on recovery completion, this notifies the quota
	 * slave code that we are about to process new requests now */
	rc = qsd_start(env, osd->od_quota_slave);
	RETURN(rc);
}

/*
 * we use exports to track all osd users
 */
static int osd_obd_connect(const struct lu_env *env, struct obd_export **exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct osd_device    *osd = osd_dev(obd->obd_lu_dev);
	struct lustre_handle  conn;
	int                   rc;
	ENTRY;

	CDEBUG(D_CONFIG, "connect #%d\n", osd->od_connects);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	*exp = class_conn2export(&conn);

	spin_lock(&osd->od_osfs_lock);
	osd->od_connects++;
	spin_unlock(&osd->od_osfs_lock);

	RETURN(0);
}

/*
 * once last export (we don't count self-export) disappeared
 * osd can be released
 */
static int osd_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct osd_device *osd = osd_dev(obd->obd_lu_dev);
	int                rc, release = 0;
	ENTRY;

	/* Only disconnect the underlying layers on the final disconnect. */
	spin_lock(&osd->od_osfs_lock);
	osd->od_connects--;
	if (osd->od_connects == 0)
		release = 1;
	spin_unlock(&osd->od_osfs_lock);

	rc = class_disconnect(exp); /* bz 9811 */

	if (rc == 0 && release)
		class_manual_cleanup(obd);
	RETURN(rc);
}

static int osd_prepare(const struct lu_env *env, struct lu_device *pdev,
                       struct lu_device *dev)
{
	struct osd_device *osd = osd_dev(dev);
	int		   result = 0;
	ENTRY;

	if (osd->od_quota_slave != NULL)
		/* set up quota slave objects */
		result = qsd_prepare(env, osd->od_quota_slave);

	RETURN(result);
}

static const struct lu_object_operations osd_lu_obj_ops = {
        .loo_object_init      = osd_object_init,
        .loo_object_delete    = osd_object_delete,
        .loo_object_release   = osd_object_release,
        .loo_object_free      = osd_object_free,
        .loo_object_print     = osd_object_print,
        .loo_object_invariant = osd_object_invariant
};

const struct lu_device_operations osd_lu_ops = {
        .ldo_object_alloc      = osd_object_alloc,
        .ldo_process_config    = osd_process_config,
        .ldo_recovery_complete = osd_recovery_complete,
        .ldo_prepare           = osd_prepare,
};

static const struct lu_device_type_operations osd_device_type_ops = {
        .ldto_init = osd_type_init,
        .ldto_fini = osd_type_fini,

        .ldto_start = osd_type_start,
        .ldto_stop  = osd_type_stop,

        .ldto_device_alloc = osd_device_alloc,
        .ldto_device_free  = osd_device_free,

        .ldto_device_init    = osd_device_init,
        .ldto_device_fini    = osd_device_fini
};

struct lu_device_type osd_device_type = {
        .ldt_tags     = LU_DEVICE_DT,
	.ldt_name     = LUSTRE_OSD_LDISKFS_NAME,
        .ldt_ops      = &osd_device_type_ops,
        .ldt_ctx_tags = LCT_LOCAL,
};

/*
 * lprocfs legacy support.
 */
static struct obd_ops osd_obd_device_ops = {
	.o_owner = THIS_MODULE,
	.o_connect	= osd_obd_connect,
	.o_disconnect	= osd_obd_disconnect
};

static int __init osd_mod_init(void)
{
	int rc;

	osd_oi_mod_init();

	rc = lu_kmem_init(ldiskfs_caches);
	if (rc)
		return rc;

	rc = class_register_type(&osd_obd_device_ops, NULL,
				 lprocfs_osd_module_vars,
				 LUSTRE_OSD_LDISKFS_NAME, &osd_device_type);
	if (rc)
		lu_kmem_fini(ldiskfs_caches);
	return rc;
}

static void __exit osd_mod_exit(void)
{
	class_unregister_type(LUSTRE_OSD_LDISKFS_NAME);
	lu_kmem_fini(ldiskfs_caches);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Device ("LUSTRE_OSD_LDISKFS_NAME")");
MODULE_LICENSE("GPL");

cfs_module(osd, "0.1.0", osd_mod_init, osd_mod_exit);
