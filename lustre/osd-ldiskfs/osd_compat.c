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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_compat.c
 *
 * on-disk structure for managing /O
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 */

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

#include "osd_internal.h"
#include "osd_oi.h"

static void osd_push_ctxt(const struct osd_device *dev,
                          struct lvfs_run_ctxt *newctxt,
                          struct lvfs_run_ctxt *save)
{
	OBD_SET_CTXT_MAGIC(newctxt);
	newctxt->pwdmnt = dev->od_mnt;
	newctxt->pwd = dev->od_mnt->mnt_root;
	newctxt->fs = get_ds();
	newctxt->umask = current_umask();
	newctxt->dt = NULL;

	push_ctxt(save, newctxt);
}

/* utility to make a directory */
static struct dentry *simple_mkdir(struct dentry *dir, struct vfsmount *mnt,
				   const char *name, int mode, int fix)
{
	struct dentry *dchild;
	int err = 0;
	ENTRY;

	// ASSERT_KERNEL_CTXT("kernel doing mkdir outside kernel context\n");
	CDEBUG(D_INODE, "creating directory %.*s\n", (int)strlen(name), name);
	dchild = ll_lookup_one_len(name, dir, strlen(name));
	if (IS_ERR(dchild))
		GOTO(out_up, dchild);

	if (dchild->d_inode) {
		int old_mode = dchild->d_inode->i_mode;
		if (!S_ISDIR(old_mode)) {
			CERROR("found %s (%lu/%u) is mode %o\n", name,
			       dchild->d_inode->i_ino,
			       dchild->d_inode->i_generation, old_mode);
			GOTO(out_err, err = -ENOTDIR);
		}

		/* Fixup directory permissions if necessary */
		if (fix && (old_mode & S_IALLUGO) != (mode & S_IALLUGO)) {
			CDEBUG(D_CONFIG,
			       "fixing permissions on %s from %o to %o\n",
			       name, old_mode, mode);
			dchild->d_inode->i_mode = (mode & S_IALLUGO) |
						  (old_mode & ~S_IALLUGO);
			mark_inode_dirty(dchild->d_inode);
		}
		GOTO(out_up, dchild);
	}

	err = vfs_mkdir(dir->d_inode, dchild, mode);
	if (err)
		GOTO(out_err, err);

	RETURN(dchild);

out_err:
	dput(dchild);
	dchild = ERR_PTR(err);
out_up:
	return dchild;
}

static int osd_last_rcvd_subdir_count(struct osd_device *osd)
{
        struct lr_server_data lsd;
        struct dentry        *dlast;
        loff_t                off;
        int                   rc = 0;
	int                   count = OBJ_SUBDIR_COUNT;

        ENTRY;

        dlast = ll_lookup_one_len(LAST_RCVD, osd_sb(osd)->s_root,
                                  strlen(LAST_RCVD));
        if (IS_ERR(dlast))
                return PTR_ERR(dlast);
        else if (dlast->d_inode == NULL)
                goto out;

        off = 0;
        rc = osd_ldiskfs_read(dlast->d_inode, &lsd, sizeof(lsd), &off);
        if (rc == sizeof(lsd)) {
                CDEBUG(D_INFO, "read last_rcvd header, uuid = %s, "
                       "subdir count = %d\n", lsd.lsd_uuid,
                       lsd.lsd_subdir_count);
		if (le16_to_cpu(lsd.lsd_subdir_count) > 0)
			count = le16_to_cpu(lsd.lsd_subdir_count);
	} else if (rc != 0) {
		CERROR("Can't read last_rcvd file, rc = %d\n", rc);
		if (rc > 0)
			rc = -EFAULT;
		dput(dlast);
		return rc;
	}
out:
	dput(dlast);
	LASSERT(count > 0);
	return count;
}

static const char remote_parent_dir[] = "REMOTE_PARENT_DIR";
static int osd_mdt_init(const struct lu_env *env, struct osd_device *dev)
{
	struct lvfs_run_ctxt	new;
	struct lvfs_run_ctxt	save;
	struct dentry		*parent;
	struct osd_mdobj_map	*omm;
	struct dentry		*d;
	struct osd_thread_info	*info = osd_oti_get(env);
	struct lu_fid		*fid = &info->oti_fid3;
	int			rc = 0;
	ENTRY;

	OBD_ALLOC_PTR(dev->od_mdt_map);
	if (dev->od_mdt_map == NULL)
		RETURN(-ENOMEM);

	omm = dev->od_mdt_map;

	parent = osd_sb(dev)->s_root;
	osd_push_ctxt(dev, &new, &save);

	d = simple_mkdir(parent, dev->od_mnt, remote_parent_dir,
			 0755, 1);
	if (IS_ERR(d))
		GOTO(cleanup, rc = PTR_ERR(d));

	omm->omm_remote_parent = d;

	/* Set LMA for remote parent inode */
	lu_local_obj_fid(fid, REMOTE_PARENT_DIR_OID);
	rc = osd_ea_fid_set(info, d->d_inode, fid, LMAC_NOT_IN_OI, 0);

	GOTO(cleanup, rc);

cleanup:
	pop_ctxt(&save, &new);
	if (rc) {
		if (omm->omm_remote_parent != NULL)
			dput(omm->omm_remote_parent);
		OBD_FREE_PTR(omm);
		dev->od_mdt_map = NULL;
	}
	return rc;
}

static void osd_mdt_fini(struct osd_device *osd)
{
	struct osd_mdobj_map *omm = osd->od_mdt_map;

	if (omm == NULL)
		return;

	if (omm->omm_remote_parent)
		dput(omm->omm_remote_parent);

	OBD_FREE_PTR(omm);
	osd->od_ost_map = NULL;
}

int osd_add_to_remote_parent(const struct lu_env *env, struct osd_device *osd,
			     struct osd_object *obj, struct osd_thandle *oh)
{
	struct osd_mdobj_map	*omm = osd->od_mdt_map;
	struct osd_thread_info	*oti = osd_oti_get(env);
	struct lustre_mdt_attrs	*lma = &oti->oti_ost_attrs.loa_lma;
	char			*name = oti->oti_name;
	struct osd_thread_info  *info = osd_oti_get(env);
	struct dentry		*dentry;
	struct dentry		*parent;
	int			rc;

	/* Set REMOTE_PARENT in lma, so other process like unlink or lfsck
	 * can identify this object quickly */
	rc = osd_get_lma(oti, obj->oo_inode, &oti->oti_obj_dentry,
			 &oti->oti_ost_attrs);
	if (rc)
		RETURN(rc);

	lma->lma_incompat |= LMAI_REMOTE_PARENT;
	lustre_lma_swab(lma);
	rc = __osd_xattr_set(oti, obj->oo_inode, XATTR_NAME_LMA, lma,
			     sizeof(*lma), XATTR_REPLACE);
	if (rc)
		RETURN(rc);

	parent = omm->omm_remote_parent;
	sprintf(name, DFID_NOBRACE, PFID(lu_object_fid(&obj->oo_dt.do_lu)));
	dentry = osd_child_dentry_by_inode(env, parent->d_inode,
					   name, strlen(name));
	mutex_lock(&parent->d_inode->i_mutex);
	rc = osd_ldiskfs_add_entry(info, osd, oh->ot_handle, dentry,
				   obj->oo_inode, NULL);
	CDEBUG(D_INODE, "%s: add %s:%lu to remote parent %lu.\n", osd_name(osd),
	       name, obj->oo_inode->i_ino, parent->d_inode->i_ino);
	ldiskfs_inc_count(oh->ot_handle, parent->d_inode);
	mark_inode_dirty(parent->d_inode);
	mutex_unlock(&parent->d_inode->i_mutex);
	RETURN(rc);
}

int osd_delete_from_remote_parent(const struct lu_env *env,
				  struct osd_device *osd,
				  struct osd_object *obj,
				  struct osd_thandle *oh)
{
	struct osd_mdobj_map	   *omm = osd->od_mdt_map;
	struct osd_thread_info	   *oti = osd_oti_get(env);
	struct lustre_mdt_attrs    *lma = &oti->oti_ost_attrs.loa_lma;
	char			   *name = oti->oti_name;
	struct dentry		   *dentry;
	struct dentry		   *parent;
	struct ldiskfs_dir_entry_2 *de;
	struct buffer_head	   *bh;
	int			   rc;

	/* Check lma to see whether it is remote object */
	rc = osd_get_lma(oti, obj->oo_inode, &oti->oti_obj_dentry,
			 &oti->oti_ost_attrs);
	if (rc != 0) {
		/* No LMA if the directory is created before 2.0 */
		if (rc == -ENODATA)
			rc = 0;
		RETURN(rc);
	}

	if (likely(!(lma->lma_incompat & LMAI_REMOTE_PARENT)))
		RETURN(0);

	parent = omm->omm_remote_parent;
	sprintf(name, DFID_NOBRACE, PFID(lu_object_fid(&obj->oo_dt.do_lu)));
	dentry = osd_child_dentry_by_inode(env, parent->d_inode,
					   name, strlen(name));
	mutex_lock(&parent->d_inode->i_mutex);
	bh = osd_ldiskfs_find_entry(parent->d_inode, &dentry->d_name, &de,
				    NULL, NULL);
	if (IS_ERR(bh)) {
		mutex_unlock(&parent->d_inode->i_mutex);
		RETURN(PTR_ERR(bh));
	}
	CDEBUG(D_INODE, "%s: el %s:%lu to remote parent %lu.\n", osd_name(osd),
	       name, obj->oo_inode->i_ino, parent->d_inode->i_ino);
	rc = ldiskfs_delete_entry(oh->ot_handle, parent->d_inode, de, bh);
	ldiskfs_dec_count(oh->ot_handle, parent->d_inode);
	mark_inode_dirty(parent->d_inode);
	mutex_unlock(&parent->d_inode->i_mutex);
	brelse(bh);

	/* Get rid of REMOTE_PARENT flag from incompat */
	lma->lma_incompat &= ~LMAI_REMOTE_PARENT;
	lustre_lma_swab(lma);
	rc = __osd_xattr_set(oti, obj->oo_inode, XATTR_NAME_LMA, lma,
			     sizeof(*lma), XATTR_REPLACE);
	RETURN(rc);
}

int osd_lookup_in_remote_parent(struct osd_thread_info *oti,
				struct osd_device *osd,
				const struct lu_fid *fid,
				struct osd_inode_id *id)
{
	struct osd_mdobj_map	    *omm = osd->od_mdt_map;
	char			    *name = oti->oti_name;
	struct dentry		    *parent;
	struct dentry		    *dentry;
	struct ldiskfs_dir_entry_2 *de;
	struct buffer_head	   *bh;
	int			    rc;
	ENTRY;

	parent = omm->omm_remote_parent;
	sprintf(name, DFID_NOBRACE, PFID(fid));
	dentry = osd_child_dentry_by_inode(oti->oti_env, parent->d_inode,
					   name, strlen(name));
	mutex_lock(&parent->d_inode->i_mutex);
	bh = osd_ldiskfs_find_entry(parent->d_inode, &dentry->d_name, &de,
				    NULL, NULL);
	if (IS_ERR(bh)) {
		rc = PTR_ERR(bh);
	} else {
		struct inode *inode;

		osd_id_gen(id, le32_to_cpu(de->inode), OSD_OII_NOGEN);
		brelse(bh);
		inode = osd_iget(oti, osd, id);
		if (IS_ERR(inode)) {
			rc = PTR_ERR(inode);
			if (rc == -ESTALE)
				rc = -ENOENT;
		} else {
			iput(inode);
			rc = 0;
		}
	}
	mutex_unlock(&parent->d_inode->i_mutex);
	if (rc == 0)
		osd_add_oi_cache(oti, osd, id, fid);
	RETURN(rc);
}

/*
 * directory structure on legacy OST:
 *
 * O/<seq>/d0-31/<objid>
 * O/<seq>/LAST_ID
 * last_rcvd
 * LAST_GROUP
 * CONFIGS
 *
 */
static int osd_ost_init(const struct lu_env *env, struct osd_device *dev)
{
	struct lvfs_run_ctxt	 new;
	struct lvfs_run_ctxt	 save;
	struct dentry		*rootd = osd_sb(dev)->s_root;
	struct dentry		*d;
	struct osd_thread_info	*info = osd_oti_get(env);
	struct inode		*inode;
	struct lu_fid		*fid = &info->oti_fid3;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(dev->od_ost_map);
	if (dev->od_ost_map == NULL)
		RETURN(-ENOMEM);

	/* to get subdir count from last_rcvd */
	rc = osd_last_rcvd_subdir_count(dev);
	if (rc < 0)
		GOTO(cleanup_alloc, rc);

	dev->od_ost_map->om_subdir_count = rc;
        rc = 0;

	INIT_LIST_HEAD(&dev->od_ost_map->om_seq_list);
	rwlock_init(&dev->od_ost_map->om_seq_list_lock);
	mutex_init(&dev->od_ost_map->om_dir_init_mutex);

        osd_push_ctxt(dev, &new, &save);

	d = ll_lookup_one_len("O", rootd, strlen("O"));
	if (IS_ERR(d))
		GOTO(cleanup_ctxt, rc = PTR_ERR(d));
	if (d->d_inode == NULL) {
		dput(d);
		/* The lookup() may be called again inside simple_mkdir().
		 * Since the repeated lookup() only be called for "/O" at
		 * mount time, it will not affect the whole performance. */
		d = simple_mkdir(rootd, dev->od_mnt, "O", 0755, 1);
		if (IS_ERR(d))
			GOTO(cleanup_ctxt, rc = PTR_ERR(d));

		/* It is quite probably that the device is new formatted. */
		dev->od_maybe_new = 1;
	}

	inode = d->d_inode;
	dev->od_ost_map->om_root = d;

	/* 'What the @fid is' is not imporatant, because the object
	 * has no OI mapping, and only is visible inside the OSD.*/
	lu_igif_build(fid, inode->i_ino, inode->i_generation);
	rc = osd_ea_fid_set(info, inode, fid,
		    LMAC_NOT_IN_OI | LMAC_FID_ON_OST, 0);
	if (rc)
		GOTO(cleanup_dentry, rc);

	pop_ctxt(&save, &new);
	RETURN(0);

cleanup_dentry:
	dput(d);
cleanup_ctxt:
	pop_ctxt(&save, &new);
cleanup_alloc:
	OBD_FREE_PTR(dev->od_ost_map);
	return rc;
}

static void osd_seq_free(struct osd_obj_seq *osd_seq)
{
	int j;

	if (osd_seq->oos_dirs) {
		for (j = 0; j < osd_seq->oos_subdir_count; j++) {
			if (osd_seq->oos_dirs[j])
				dput(osd_seq->oos_dirs[j]);
                }
		OBD_FREE(osd_seq->oos_dirs,
			 sizeof(struct dentry *) * osd_seq->oos_subdir_count);
        }

	if (osd_seq->oos_root)
		dput(osd_seq->oos_root);

	OBD_FREE_PTR(osd_seq);
}

static void osd_ost_fini(struct osd_device *osd)
{
	struct osd_obj_seq    *osd_seq;
	struct osd_obj_seq    *tmp;
	struct osd_obj_map    *map = osd->od_ost_map;
	ENTRY;

	if (map == NULL)
		return;

	write_lock(&map->om_seq_list_lock);
	list_for_each_entry_safe(osd_seq, tmp, &map->om_seq_list,
				 oos_seq_list) {
		list_del_init(&osd_seq->oos_seq_list);
		write_unlock(&map->om_seq_list_lock);
		osd_seq_free(osd_seq);
		write_lock(&map->om_seq_list_lock);
	}
	write_unlock(&map->om_seq_list_lock);
	if (map->om_root)
		dput(map->om_root);
	OBD_FREE_PTR(map);
	osd->od_ost_map = NULL;
	EXIT;
}

int osd_obj_map_init(const struct lu_env *env, struct osd_device *dev)
{
	int rc;
	ENTRY;

	/* prepare structures for OST */
	rc = osd_ost_init(env, dev);
	if (rc)
		RETURN(rc);

	/* prepare structures for MDS */
	rc = osd_mdt_init(env, dev);
	if (rc)
		osd_ost_fini(dev);

        RETURN(rc);
}

static struct osd_obj_seq *osd_seq_find_locked(struct osd_obj_map *map, u64 seq)
{
	struct osd_obj_seq *osd_seq;

	list_for_each_entry(osd_seq, &map->om_seq_list, oos_seq_list) {
		if (osd_seq->oos_seq == seq)
			return osd_seq;
	}
	return NULL;
}

static struct osd_obj_seq *osd_seq_find(struct osd_obj_map *map, u64 seq)
{
	struct osd_obj_seq *osd_seq;

	read_lock(&map->om_seq_list_lock);
	osd_seq = osd_seq_find_locked(map, seq);
	read_unlock(&map->om_seq_list_lock);
	return osd_seq;
}

void osd_obj_map_fini(struct osd_device *dev)
{
	osd_ost_fini(dev);
	osd_mdt_fini(dev);
}

/**
 * Update the specified OI mapping.
 *
 * \retval   1, changed nothing
 * \retval   0, changed successfully
 * \retval -ve, on error
 */
static int osd_obj_update_entry(struct osd_thread_info *info,
				struct osd_device *osd,
				struct dentry *dir, const char *name,
				const struct lu_fid *fid,
				const struct osd_inode_id *id,
				handle_t *th)
{
	struct inode		   *parent = dir->d_inode;
	struct dentry		   *child;
	struct ldiskfs_dir_entry_2 *de;
	struct buffer_head	   *bh;
	struct inode		   *inode;
	struct dentry		   *dentry = &info->oti_obj_dentry;
	struct osd_inode_id	   *oi_id  = &info->oti_id3;
	struct lustre_mdt_attrs	   *lma    = &info->oti_ost_attrs.loa_lma;
	struct lu_fid		   *oi_fid = &lma->lma_self_fid;
	int			    rc;
	ENTRY;

	LASSERT(th != NULL);
	LASSERT(th->h_transaction != NULL);

	child = &info->oti_child_dentry;
	child->d_parent = dir;
	child->d_name.hash = 0;
	child->d_name.name = name;
	child->d_name.len = strlen(name);

	ll_vfs_dq_init(parent);
	mutex_lock(&parent->i_mutex);
	bh = osd_ldiskfs_find_entry(parent, &child->d_name, &de, NULL, NULL);
	if (IS_ERR(bh))
		GOTO(out, rc = PTR_ERR(bh));

	if (le32_to_cpu(de->inode) == id->oii_ino)
		GOTO(out, rc = 1);

	osd_id_gen(oi_id, le32_to_cpu(de->inode), OSD_OII_NOGEN);
	inode = osd_iget(info, osd, oi_id);
	if (IS_ERR(inode)) {
		rc = PTR_ERR(inode);
		if (rc == -ENOENT || rc == -ESTALE)
			goto update;
		GOTO(out, rc);
	}

	/* The EA inode should NOT be in OI, old OI scrub may added
	 * such OI mapping by wrong, replace it. */
	if (unlikely(osd_is_ea_inode(inode))) {
		iput(inode);
		goto update;
	}

	rc = osd_get_lma(info, inode, dentry, &info->oti_ost_attrs);
	if (rc == -ENODATA) {
		rc = osd_get_idif(info, inode, dentry, oi_fid);
		if (rc > 0 || rc == -ENODATA) {
			oi_fid = NULL;
			rc = 0;
		}
	}
	iput(inode);

	if (rc != 0)
		GOTO(out, rc);

	/* If the OST-object has neither FID-in-LMA nor FID-in-ff, it is
	 * either a crashed object or a uninitialized one. Replace it. */
	if (oi_fid != NULL && lu_fid_eq(fid, oi_fid)) {
		CERROR("%s: the FID "DFID" is used by two objects: "
		       "%u/%u %u/%u\n", osd_name(osd), PFID(fid),
		       oi_id->oii_ino, oi_id->oii_gen,
		       id->oii_ino, id->oii_gen);
		GOTO(out, rc = -EEXIST);
	}

	if (fid_is_idif(fid) && oi_fid != NULL && fid_is_idif(oi_fid)) {
		__u32 idx1 = fid_idif_ost_idx(fid);
		__u32 idx2 = fid_idif_ost_idx(oi_fid);
		struct ost_id *ostid = &info->oti_ostid;
		struct lu_fid *tfid = &info->oti_fid3;

		LASSERTF(idx1 == 0 || idx1 == osd->od_index,
			 "invalid given FID "DFID", not match the "
			 "device index %u\n", PFID(fid), osd->od_index);

		if (idx1 != idx2) {
			if (idx1 == 0 && idx2 == osd->od_index) {
				fid_to_ostid(fid, ostid);
				ostid_to_fid(tfid, ostid, idx2);
				if (lu_fid_eq(tfid, oi_fid)) {
					CERROR("%s: the FID "DFID" is used by "
					       "two objects(2): %u/%u %u/%u\n",
					       osd_name(osd), PFID(fid),
					       oi_id->oii_ino, oi_id->oii_gen,
					       id->oii_ino, id->oii_gen);

					GOTO(out, rc = -EEXIST);
				}
			} else if (idx2 == 0 && idx1 == osd->od_index) {
				fid_to_ostid(oi_fid, ostid);
				ostid_to_fid(tfid, ostid, idx1);
				if (lu_fid_eq(tfid, fid)) {
					CERROR("%s: the FID "DFID" is used by "
					       "two objects(2): %u/%u %u/%u\n",
					       osd_name(osd), PFID(fid),
					       oi_id->oii_ino, oi_id->oii_gen,
					       id->oii_ino, id->oii_gen);

					GOTO(out, rc = -EEXIST);
				}
			}
		}
	}

update:
	/* There may be temporary inconsistency: On one hand, the new
	 * object may be referenced by multiple entries, which is out
	 * of our control unless we traverse the whole /O completely,
	 * which is non-flat order and inefficient, should be avoided;
	 * On the other hand, the old object may become orphan if it
	 * is still valid. Since it was referenced by an invalid entry,
	 * making it as invisible temporary may be not worse. OI scrub
	 * will process it later. */
	rc = ldiskfs_journal_get_write_access(th, bh);
	if (rc != 0)
		GOTO(out, rc);

	de->inode = cpu_to_le32(id->oii_ino);
	rc = ldiskfs_handle_dirty_metadata(th, NULL, bh);

	GOTO(out, rc);

out:
	if (!IS_ERR(bh))
		brelse(bh);
	mutex_unlock(&parent->i_mutex);
	return rc;
}

static int osd_obj_del_entry(struct osd_thread_info *info,
			     struct osd_device *osd,
			     struct dentry *dird, char *name,
			     handle_t *th)
{
	struct ldiskfs_dir_entry_2 *de;
	struct buffer_head         *bh;
	struct dentry              *child;
	struct inode               *dir = dird->d_inode;
	int                         rc;
	ENTRY;

	LASSERT(th != NULL);
	LASSERT(th->h_transaction != NULL);


	child = &info->oti_child_dentry;
	child->d_name.hash = 0;
	child->d_name.name = name;
	child->d_name.len = strlen(name);
	child->d_parent = dird;
	child->d_inode = NULL;

	ll_vfs_dq_init(dir);
	mutex_lock(&dir->i_mutex);
	bh = osd_ldiskfs_find_entry(dir, &child->d_name, &de, NULL, NULL);
	if (IS_ERR(bh)) {
		rc = PTR_ERR(bh);
	} else {
		rc = ldiskfs_delete_entry(th, dir, de, bh);
		brelse(bh);
	}
	mutex_unlock(&dir->i_mutex);

	RETURN(rc);
}

static int osd_obj_add_entry(struct osd_thread_info *info,
			     struct osd_device *osd,
			     struct dentry *dir, char *name,
			     const struct osd_inode_id *id,
			     handle_t *th)
{
	struct dentry *child;
	struct inode *inode;
	int rc;

	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_OSD_COMPAT_NO_ENTRY))
		RETURN(0);

	LASSERT(th != NULL);
	LASSERT(th->h_transaction != NULL);

	inode = info->oti_inode;
	if (unlikely(inode == NULL)) {
		struct ldiskfs_inode_info *lii;
		OBD_ALLOC_PTR(lii);
		if (lii == NULL)
			RETURN(-ENOMEM);
		inode = info->oti_inode = &lii->vfs_inode;
	}

	inode->i_sb = osd_sb(osd);
	osd_id_to_inode(inode, id);
	inode->i_mode = S_IFREG; /* for type in ldiskfs dir entry */

	child = &info->oti_child_dentry;
	child->d_name.hash = 0;
	child->d_name.name = name;
	child->d_name.len = strlen(name);
	child->d_parent = dir;
	child->d_inode = inode;

	if (OBD_FAIL_CHECK(OBD_FAIL_OSD_COMPAT_INVALID_ENTRY))
		inode->i_ino++;

	ll_vfs_dq_init(dir->d_inode);
	mutex_lock(&dir->d_inode->i_mutex);
	rc = osd_ldiskfs_add_entry(info, osd, th, child, inode, NULL);
	mutex_unlock(&dir->d_inode->i_mutex);

	RETURN(rc);
}

/**
 * Use %llu for legacy OST sequences, but use %llx for new
 * sequences names, so that the O/{seq}/dN/{oid} more closely
 * follows the DFID/PFID format. This makes it easier to map from
 * debug messages to objects in the future, and the legacy space
 * of FID_SEQ_OST_MDT0 will be unused in the future.
 **/
static inline void osd_seq_name(char *seq_name, size_t name_size, u64 seq)
{
	snprintf(seq_name, name_size,
		 (fid_seq_is_rsvd(seq) ||
		  fid_seq_is_mdt0(seq)) ? "%llu" : "%llx",
		 fid_seq_is_idif(seq) ? 0 : seq);
}

static inline void osd_oid_name(char *name, size_t name_size,
				const struct lu_fid *fid, u64 id)
{
	snprintf(name, name_size,
		 (fid_seq_is_rsvd(fid_seq(fid)) ||
		  fid_seq_is_mdt0(fid_seq(fid)) ||
		  fid_seq_is_idif(fid_seq(fid))) ? "%llu" : "%llx", id);
}

/* external locking is required */
static int osd_seq_load_locked(struct osd_thread_info *info,
			       struct osd_device *osd,
			       struct osd_obj_seq *osd_seq)
{
	struct osd_obj_map  *map = osd->od_ost_map;
	struct dentry       *seq_dir;
	struct inode	    *inode;
	struct lu_fid	    *fid = &info->oti_fid3;
	int		    rc = 0;
	int		    i;
	char		    dir_name[32];
	ENTRY;

	if (osd_seq->oos_root != NULL)
		RETURN(0);

	LASSERT(map);
	LASSERT(map->om_root);

	osd_seq_name(dir_name, sizeof(dir_name), osd_seq->oos_seq);

	seq_dir = simple_mkdir(map->om_root, osd->od_mnt, dir_name, 0755, 1);
	if (IS_ERR(seq_dir))
		GOTO(out_err, rc = PTR_ERR(seq_dir));
	else if (seq_dir->d_inode == NULL)
		GOTO(out_put, rc = -EFAULT);

	inode = seq_dir->d_inode;
	osd_seq->oos_root = seq_dir;

	/* 'What the @fid is' is not imporatant, because the object
	 * has no OI mapping, and only is visible inside the OSD.*/
	lu_igif_build(fid, inode->i_ino, inode->i_generation);
	rc = osd_ea_fid_set(info, inode, fid,
			    LMAC_NOT_IN_OI | LMAC_FID_ON_OST, 0);
	if (rc != 0)
		GOTO(out_put, rc);

	LASSERT(osd_seq->oos_dirs == NULL);
	OBD_ALLOC(osd_seq->oos_dirs,
		  sizeof(seq_dir) * osd_seq->oos_subdir_count);
	if (osd_seq->oos_dirs == NULL)
		GOTO(out_put, rc = -ENOMEM);

	for (i = 0; i < osd_seq->oos_subdir_count; i++) {
		struct dentry   *dir;

		snprintf(dir_name, sizeof(dir_name), "d%u", i);
		dir = simple_mkdir(osd_seq->oos_root, osd->od_mnt, dir_name,
				   0700, 1);
		if (IS_ERR(dir)) {
			GOTO(out_free, rc = PTR_ERR(dir));
		} else if (dir->d_inode == NULL) {
			dput(dir);
			GOTO(out_free, rc = -EFAULT);
		}

		inode = dir->d_inode;
		osd_seq->oos_dirs[i] = dir;

		/* 'What the @fid is' is not imporatant, because the object
		 * has no OI mapping, and only is visible inside the OSD.*/
		lu_igif_build(fid, inode->i_ino, inode->i_generation);
		rc = osd_ea_fid_set(info, inode, fid,
				    LMAC_NOT_IN_OI | LMAC_FID_ON_OST, 0);
		if (rc != 0)
			GOTO(out_free, rc);
	}

	if (rc != 0) {
out_free:
		for (i = 0; i < osd_seq->oos_subdir_count; i++) {
			if (osd_seq->oos_dirs[i] != NULL)
				dput(osd_seq->oos_dirs[i]);
		}
		OBD_FREE(osd_seq->oos_dirs,
			 sizeof(seq_dir) * osd_seq->oos_subdir_count);
out_put:
		dput(seq_dir);
		osd_seq->oos_root = NULL;
	}
out_err:
	RETURN(rc);
}

static struct osd_obj_seq *osd_seq_load(struct osd_thread_info *info,
					struct osd_device *osd, u64 seq)
{
	struct osd_obj_map	*map;
	struct osd_obj_seq	*osd_seq;
	int			rc = 0;
	ENTRY;

	map = osd->od_ost_map;
	LASSERT(map);
	LASSERT(map->om_root);

	osd_seq = osd_seq_find(map, seq);
	if (likely(osd_seq != NULL))
		RETURN(osd_seq);

	/* Serializing init process */
	mutex_lock(&map->om_dir_init_mutex);

	/* Check whether the seq has been added */
	read_lock(&map->om_seq_list_lock);
	osd_seq = osd_seq_find_locked(map, seq);
	if (osd_seq != NULL) {
		read_unlock(&map->om_seq_list_lock);
		GOTO(cleanup, rc = 0);
	}
	read_unlock(&map->om_seq_list_lock);

	OBD_ALLOC_PTR(osd_seq);
	if (osd_seq == NULL)
		GOTO(cleanup, rc = -ENOMEM);

	INIT_LIST_HEAD(&osd_seq->oos_seq_list);
	osd_seq->oos_seq = seq;
	/* Init subdir count to be 32, but each seq can have
	 * different subdir count */
	osd_seq->oos_subdir_count = map->om_subdir_count;
	rc = osd_seq_load_locked(info, osd, osd_seq);
	if (rc != 0)
		GOTO(cleanup, rc);

	write_lock(&map->om_seq_list_lock);
	list_add(&osd_seq->oos_seq_list, &map->om_seq_list);
	write_unlock(&map->om_seq_list_lock);

cleanup:
	mutex_unlock(&map->om_dir_init_mutex);
	if (rc != 0) {
		if (osd_seq != NULL)
			OBD_FREE_PTR(osd_seq);
		RETURN(ERR_PTR(rc));
	}

	RETURN(osd_seq);
}

int osd_obj_map_lookup(struct osd_thread_info *info, struct osd_device *dev,
		       const struct lu_fid *fid, struct osd_inode_id *id)
{
	struct osd_obj_map		*map;
	struct osd_obj_seq		*osd_seq;
	struct dentry			*d_seq;
	struct dentry			*child;
	struct ost_id			*ostid = &info->oti_ostid;
	int				dirn;
	char				name[32];
	struct ldiskfs_dir_entry_2	*de;
	struct buffer_head		*bh;
	struct inode			*dir;
	struct inode			*inode;
        ENTRY;

        /* on the very first lookup we find and open directories */

        map = dev->od_ost_map;
        LASSERT(map);
	LASSERT(map->om_root);

        fid_to_ostid(fid, ostid);
	osd_seq = osd_seq_load(info, dev, ostid_seq(ostid));
	if (IS_ERR(osd_seq))
		RETURN(PTR_ERR(osd_seq));

	dirn = ostid_id(ostid) & (osd_seq->oos_subdir_count - 1);
	d_seq = osd_seq->oos_dirs[dirn];
	LASSERT(d_seq);

	osd_oid_name(name, sizeof(name), fid, ostid_id(ostid));

	child = &info->oti_child_dentry;
	child->d_parent = d_seq;
	child->d_name.hash = 0;
	child->d_name.name = name;
	/* XXX: we can use rc from sprintf() instead of strlen() */
	child->d_name.len = strlen(name);

	dir = d_seq->d_inode;
	mutex_lock(&dir->i_mutex);
	bh = osd_ldiskfs_find_entry(dir, &child->d_name, &de, NULL, NULL);
	mutex_unlock(&dir->i_mutex);

	if (IS_ERR(bh))
		RETURN(PTR_ERR(bh));

	osd_id_gen(id, le32_to_cpu(de->inode), OSD_OII_NOGEN);
	brelse(bh);

	inode = osd_iget(info, dev, id);
	if (IS_ERR(inode)) {
		int rc = PTR_ERR(inode);

		RETURN(rc == -ENOENT ? -ESTALE : rc);
	}

	iput(inode);
	RETURN(0);
}

int osd_obj_map_insert(struct osd_thread_info *info,
		       struct osd_device *osd,
		       const struct lu_fid *fid,
		       const struct osd_inode_id *id,
		       handle_t *th)
{
	struct osd_obj_map	*map;
	struct osd_obj_seq	*osd_seq;
	struct dentry		*d;
	struct ost_id		*ostid = &info->oti_ostid;
	u64			 oid;
	int			dirn, rc = 0;
	char			name[32];
	ENTRY;

	map = osd->od_ost_map;
	LASSERT(map);

	/* map fid to seq:objid */
	fid_to_ostid(fid, ostid);

	oid = ostid_id(ostid);
	osd_seq = osd_seq_load(info, osd, ostid_seq(ostid));
	if (IS_ERR(osd_seq))
		RETURN(PTR_ERR(osd_seq));

	dirn = oid & (osd_seq->oos_subdir_count - 1);
	d = osd_seq->oos_dirs[dirn];
	LASSERT(d);

	osd_oid_name(name, sizeof(name), fid, oid);

again:
	rc = osd_obj_add_entry(info, osd, d, name, id, th);
	if (rc == -EEXIST) {
		rc = osd_obj_update_entry(info, osd, d, name, fid, id, th);
		if (unlikely(rc == -ENOENT))
			goto again;

		if (unlikely(rc == 1))
			RETURN(0);
	}

	RETURN(rc);
}

int osd_obj_map_delete(struct osd_thread_info *info, struct osd_device *osd,
		       const struct lu_fid *fid, handle_t *th)
{
	struct osd_obj_map	*map;
	struct osd_obj_seq	*osd_seq;
	struct dentry		*d;
	struct ost_id		*ostid = &info->oti_ostid;
	int			dirn, rc = 0;
	char			name[32];
        ENTRY;

        map = osd->od_ost_map;
        LASSERT(map);

	/* map fid to seq:objid */
        fid_to_ostid(fid, ostid);

	osd_seq = osd_seq_load(info, osd, ostid_seq(ostid));
	if (IS_ERR(osd_seq))
		GOTO(cleanup, rc = PTR_ERR(osd_seq));

	dirn = ostid_id(ostid) & (osd_seq->oos_subdir_count - 1);
	d = osd_seq->oos_dirs[dirn];
	LASSERT(d);

	osd_oid_name(name, sizeof(name), fid, ostid_id(ostid));
	rc = osd_obj_del_entry(info, osd, d, name, th);
cleanup:
        RETURN(rc);
}

int osd_obj_map_update(struct osd_thread_info *info,
		       struct osd_device *osd,
		       const struct lu_fid *fid,
		       const struct osd_inode_id *id,
		       handle_t *th)
{
	struct osd_obj_seq	*osd_seq;
	struct dentry		*d;
	struct ost_id		*ostid = &info->oti_ostid;
	int			dirn, rc = 0;
	char			name[32];
	ENTRY;

	fid_to_ostid(fid, ostid);
	osd_seq = osd_seq_load(info, osd, ostid_seq(ostid));
	if (IS_ERR(osd_seq))
		RETURN(PTR_ERR(osd_seq));

	dirn = ostid_id(ostid) & (osd_seq->oos_subdir_count - 1);
	d = osd_seq->oos_dirs[dirn];
	LASSERT(d);

	osd_oid_name(name, sizeof(name), fid, ostid_id(ostid));
	rc = osd_obj_update_entry(info, osd, d, name, fid, id, th);

	RETURN(rc);
}

int osd_obj_map_recover(struct osd_thread_info *info,
			struct osd_device *osd,
			struct inode *src_parent,
			struct dentry *src_child,
			const struct lu_fid *fid)
{
	struct osd_obj_seq	   *osd_seq;
	struct dentry		   *tgt_parent;
	struct dentry		   *tgt_child = &info->oti_child_dentry;
	struct inode		   *dir;
	struct inode		   *inode     = src_child->d_inode;
	struct ost_id		   *ostid     = &info->oti_ostid;
	handle_t		   *jh;
	struct ldiskfs_dir_entry_2 *de;
	struct buffer_head	   *bh;
	char			    name[32];
	int			    dirn;
	int			    rc	      = 0;
	ENTRY;

	if (fid_is_last_id(fid)) {
		osd_seq = osd_seq_load(info, osd, fid_seq(fid));
		if (IS_ERR(osd_seq))
			RETURN(PTR_ERR(osd_seq));

		tgt_parent = osd_seq->oos_root;
		tgt_child->d_name.name = "LAST_ID";
		tgt_child->d_name.len = strlen("LAST_ID");
	} else {
		fid_to_ostid(fid, ostid);
		osd_seq = osd_seq_load(info, osd, ostid_seq(ostid));
		if (IS_ERR(osd_seq))
			RETURN(PTR_ERR(osd_seq));

		dirn = ostid_id(ostid) & (osd_seq->oos_subdir_count - 1);
		tgt_parent = osd_seq->oos_dirs[dirn];
		osd_oid_name(name, sizeof(name), fid, ostid_id(ostid));
		tgt_child->d_name.name = name;
		tgt_child->d_name.len = strlen(name);
	}
	LASSERT(tgt_parent != NULL);

	dir = tgt_parent->d_inode;
	tgt_child->d_name.hash = 0;
	tgt_child->d_parent = tgt_parent;
	tgt_child->d_inode = inode;

	/* The non-initialized src_child may be destroyed. */
	jh = osd_journal_start_sb(osd_sb(osd), LDISKFS_HT_MISC,
				osd_dto_credits_noquota[DTO_INDEX_DELETE] +
				osd_dto_credits_noquota[DTO_INDEX_INSERT] +
				osd_dto_credits_noquota[DTO_OBJECT_DELETE]);
	if (IS_ERR(jh))
		RETURN(PTR_ERR(jh));

	ll_vfs_dq_init(src_parent);
	ll_vfs_dq_init(dir);

	mutex_lock(&src_parent->i_mutex);
	mutex_lock(&dir->i_mutex);
	bh = osd_ldiskfs_find_entry(dir, &tgt_child->d_name, &de, NULL, NULL);
	if (!IS_ERR(bh)) {
		/* XXX: If some other object occupied the same slot. And If such
		 * 	inode is zero-sized and with SUID+SGID, then means it is
		 * 	a new created one. Maybe we can remove it and insert the
		 * 	original one back to the /O/<seq>/d<x>. But there are
		 * 	something to be considered:
		 *
		 * 	1) The OST-object under /lost+found has crashed LMA.
		 * 	   So it should not conflict with the current one.
		 *
		 *	2) There are race conditions that: someone may just want
		 *	   to modify the current one. Even if the OI scrub takes
		 *	   the object lock when remove the current one, it still
		 *	   cause the modification to be lost becasue the target
		 *	   has been removed when the RPC service thread waiting
		 *	   for the lock.
		 *
		 * 	So keep it there before we have suitable solution. */
		brelse(bh);
		mutex_unlock(&dir->i_mutex);
		mutex_unlock(&src_parent->i_mutex);
		ldiskfs_journal_stop(jh);

		rc = -EEXIST;
		/* If the src object has never been modified, then remove it. */
		if (inode->i_size == 0 && inode->i_mode & S_ISUID &&
		    inode->i_mode & S_ISGID) {
			rc = ll_vfs_unlink(src_parent, src_child);
			if (unlikely(rc == -ENOENT))
				rc = 0;
		}
		RETURN(rc);
	}

	bh = osd_ldiskfs_find_entry(src_parent, &src_child->d_name, &de,
				    NULL, NULL);
	if (unlikely(IS_ERR(bh)))
		GOTO(unlock, rc = PTR_ERR(bh));

	rc = ldiskfs_delete_entry(jh, src_parent, de, bh);
	brelse(bh);
	if (rc != 0)
		GOTO(unlock, rc);

	rc = osd_ldiskfs_add_entry(info, osd, jh, tgt_child, inode, NULL);

	GOTO(unlock, rc);

unlock:
	mutex_unlock(&dir->i_mutex);
	mutex_unlock(&src_parent->i_mutex);
	ldiskfs_journal_stop(jh);
	return rc;
}

static struct dentry *
osd_object_spec_find(struct osd_thread_info *info, struct osd_device *osd,
		     const struct lu_fid *fid, char **name)
{
	struct dentry *root = ERR_PTR(-ENOENT);

	if (fid_is_last_id(fid)) {
		struct osd_obj_seq *osd_seq;

		/* on creation of LAST_ID we create O/<seq> hierarchy */
		osd_seq = osd_seq_load(info, osd, fid_seq(fid));
		if (IS_ERR(osd_seq))
			RETURN((struct dentry *)osd_seq);

		*name = "LAST_ID";
		root = osd_seq->oos_root;
	} else {
		*name = osd_lf_fid2name(fid);
		if (*name == NULL)
			CWARN("UNKNOWN COMPAT FID "DFID"\n", PFID(fid));
		else if ((*name)[0])
			root = osd_sb(osd)->s_root;
	}

	return root;
}

int osd_obj_spec_update(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, const struct osd_inode_id *id,
			handle_t *th)
{
	struct dentry	*root;
	char		*name = NULL;
	int		 rc;
	ENTRY;

	root = osd_object_spec_find(info, osd, fid, &name);
	if (!IS_ERR(root)) {
		rc = osd_obj_update_entry(info, osd, root, name, fid, id, th);
	} else {
		rc = PTR_ERR(root);
		if (rc == -ENOENT)
			rc = 1;
	}

	RETURN(rc);
}

int osd_obj_spec_insert(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, const struct osd_inode_id *id,
			handle_t *th)
{
	struct dentry	*root;
	char		*name = NULL;
	int		 rc;
	ENTRY;

	root = osd_object_spec_find(info, osd, fid, &name);
	if (!IS_ERR(root)) {
		rc = osd_obj_add_entry(info, osd, root, name, id, th);
	} else {
		rc = PTR_ERR(root);
		if (rc == -ENOENT)
			rc = 0;
	}

	RETURN(rc);
}

int osd_obj_spec_lookup(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct osd_inode_id *id)
{
	struct dentry	*root;
	struct dentry	*dentry;
	struct inode	*inode;
	char		*name = NULL;
	int		rc = -ENOENT;
	ENTRY;

	if (fid_is_last_id(fid)) {
		struct osd_obj_seq *osd_seq;

		osd_seq = osd_seq_load(info, osd, fid_seq(fid));
		if (IS_ERR(osd_seq))
			RETURN(PTR_ERR(osd_seq));
		root = osd_seq->oos_root;
		name = "LAST_ID";
	} else {
		root = osd_sb(osd)->s_root;
		name = osd_lf_fid2name(fid);
		if (name == NULL || strlen(name) == 0)
			RETURN(-ENOENT);
	}

	dentry = ll_lookup_one_len(name, root, strlen(name));
	if (!IS_ERR(dentry)) {
		inode = dentry->d_inode;
		if (inode) {
			if (is_bad_inode(inode)) {
				rc = -EIO;
			} else {
				osd_id_gen(id, inode->i_ino,
					   inode->i_generation);
				rc = 0;
			}
		}
		/* if dentry is accessible after osd_compat_spec_insert it
		 * will still contain NULL inode, so don't keep it in cache */
		d_invalidate(dentry);
		dput(dentry);
	}

	RETURN(rc);
}
