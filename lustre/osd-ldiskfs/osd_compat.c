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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
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

        push_ctxt(save, newctxt, NULL);
}

static void osd_pop_ctxt(const struct osd_device *dev,
			 struct lvfs_run_ctxt *new,
			 struct lvfs_run_ctxt *save)
{
	pop_ctxt(save, new, NULL);
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

	err = ll_vfs_mkdir(dir->d_inode, dchild, mnt, mode);
	if (err)
		GOTO(out_err, err);

	RETURN(dchild);

out_err:
	dput(dchild);
	dchild = ERR_PTR(err);
out_up:
	return dchild;
}

int osd_last_rcvd_subdir_count(struct osd_device *osd)
{
        struct lr_server_data lsd;
        struct dentry        *dlast;
        loff_t                off;
        int                   rc = 0;
	int                   count = FILTER_SUBDIR_COUNT;

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
	struct lu_fid		*fid = &info->oti_fid;
	int			rc = 0;
	ENTRY;

	OBD_ALLOC_PTR(dev->od_mdt_map);
	if (dev->od_mdt_map == NULL)
		RETURN(-ENOMEM);

	omm = dev->od_mdt_map;

	LASSERT(dev->od_fsops);

	parent = osd_sb(dev)->s_root;
	osd_push_ctxt(dev, &new, &save);

	d = simple_mkdir(parent, dev->od_mnt, remote_parent_dir,
			 0755, 1);
	if (IS_ERR(d))
		GOTO(cleanup, rc = PTR_ERR(d));

	ldiskfs_set_inode_state(d->d_inode, LDISKFS_STATE_LUSTRE_NO_OI);
	omm->omm_remote_parent = d;

	/* Set LMA for remote parent inode */
	lu_local_obj_fid(fid, REMOTE_PARENT_DIR_OID);
	rc = osd_ea_fid_set(info, d->d_inode, fid, 0);
	if (rc != 0)
		GOTO(cleanup, rc);
cleanup:
	pop_ctxt(&save, &new, NULL);
	if (rc) {
		if (omm->omm_remote_parent != NULL)
			dput(omm->omm_remote_parent);
		OBD_FREE_PTR(omm);
		dev->od_mdt_map = NULL;
	}
	RETURN(rc);
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
	struct lustre_mdt_attrs	*lma = &oti->oti_mdt_attrs;
	char			*name = oti->oti_name;
	struct dentry		*dentry;
	struct dentry		*parent;
	int			rc;

	/* Set REMOTE_PARENT in lma, so other process like unlink or lfsck
	 * can identify this object quickly */
	rc = osd_get_lma(oti, obj->oo_inode, &oti->oti_obj_dentry, lma);
	if (rc != 0)
		RETURN(rc);

	lma->lma_incompat |= LMAI_REMOTE_PARENT;
	lustre_lma_swab(lma);
	rc = __osd_xattr_set(oti, obj->oo_inode, XATTR_NAME_LMA, lma,
			     sizeof(*lma), XATTR_REPLACE);
	if (rc != 0)
		RETURN(rc);

	parent = omm->omm_remote_parent;
	sprintf(name, DFID_NOBRACE, PFID(lu_object_fid(&obj->oo_dt.do_lu)));
	dentry = osd_child_dentry_by_inode(env, parent->d_inode,
					   name, strlen(name));
	mutex_lock(&parent->d_inode->i_mutex);
	rc = osd_ldiskfs_add_entry(oh->ot_handle, dentry, obj->oo_inode,
				   NULL);
	CDEBUG(D_INODE, "%s: add %s:%lu to remote parent %lu.\n", osd_name(osd),
	       name, obj->oo_inode->i_ino, parent->d_inode->i_ino);
	LASSERTF(parent->d_inode->i_nlink > 1, "%s: %lu nlink %d",
		 osd_name(osd), parent->d_inode->i_ino,
		 parent->d_inode->i_nlink);
	parent->d_inode->i_nlink++;
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
	struct lustre_mdt_attrs    *lma = &oti->oti_mdt_attrs;
	char			   *name = oti->oti_name;
	struct dentry		   *dentry;
	struct dentry		   *parent;
	struct ldiskfs_dir_entry_2 *de;
	struct buffer_head	   *bh;
	int			   rc;

	/* Check lma to see whether it is remote object */
	rc = osd_get_lma(oti, obj->oo_inode, &oti->oti_obj_dentry, lma);
	if (rc != 0)
		RETURN(rc);

	if (likely(!(lma->lma_incompat & LMAI_REMOTE_PARENT)))
		RETURN(0);

	parent = omm->omm_remote_parent;
	sprintf(name, DFID_NOBRACE, PFID(lu_object_fid(&obj->oo_dt.do_lu)));
	dentry = osd_child_dentry_by_inode(env, parent->d_inode,
					   name, strlen(name));
	mutex_lock(&parent->d_inode->i_mutex);
	bh = osd_ldiskfs_find_entry(parent->d_inode, dentry, &de, NULL);
	if (bh == NULL) {
		mutex_unlock(&parent->d_inode->i_mutex);
		RETURN(-ENOENT);
	}
	CDEBUG(D_INODE, "%s: el %s:%lu to remote parent %lu.\n", osd_name(osd),
	       name, obj->oo_inode->i_ino, parent->d_inode->i_ino);
	rc = ldiskfs_delete_entry(oh->ot_handle, parent->d_inode, de, bh);
	LASSERTF(parent->d_inode->i_nlink > 1, "%s: %lu nlink %d",
		 osd_name(osd), parent->d_inode->i_ino,
		 parent->d_inode->i_nlink);
	parent->d_inode->i_nlink--;
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
	bh = osd_ldiskfs_find_entry(parent->d_inode, dentry, &de, NULL);
	if (bh == NULL) {
		rc = -ENOENT;
	} else {
		rc = 0;
		osd_id_gen(id, le32_to_cpu(de->inode), OSD_OII_NOGEN);
		brelse(bh);
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
static int osd_ost_init(struct osd_device *dev)
{
	struct lvfs_run_ctxt  new;
	struct lvfs_run_ctxt  save;
	struct dentry	     *rootd = osd_sb(dev)->s_root;
	struct dentry	     *d;
	int		      rc;
	ENTRY;

	OBD_ALLOC_PTR(dev->od_ost_map);
	if (dev->od_ost_map == NULL)
		RETURN(-ENOMEM);

	/* to get subdir count from last_rcvd */
	rc = osd_last_rcvd_subdir_count(dev);
	if (rc < 0) {
		OBD_FREE_PTR(dev->od_ost_map);
		RETURN(rc);
	}

	dev->od_ost_map->om_subdir_count = rc;
        rc = 0;

	CFS_INIT_LIST_HEAD(&dev->od_ost_map->om_seq_list);
	rwlock_init(&dev->od_ost_map->om_seq_list_lock);
	sema_init(&dev->od_ost_map->om_dir_init_sem, 1);

        LASSERT(dev->od_fsops);
        osd_push_ctxt(dev, &new, &save);

        d = simple_mkdir(rootd, dev->od_mnt, "O", 0755, 1);
	if (IS_ERR(d))
		GOTO(cleanup, rc = PTR_ERR(d));

	ldiskfs_set_inode_state(d->d_inode, LDISKFS_STATE_LUSTRE_NO_OI);
	dev->od_ost_map->om_root = d;

cleanup:
	osd_pop_ctxt(dev, &new, &save);
        if (IS_ERR(d)) {
                OBD_FREE_PTR(dev->od_ost_map);
                RETURN(PTR_ERR(d));
        }

	RETURN(rc);
}

static void osd_seq_free(struct osd_obj_map *map,
			 struct osd_obj_seq *osd_seq)
{
	int j;

	cfs_list_del_init(&osd_seq->oos_seq_list);

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
	cfs_list_for_each_entry_safe(osd_seq, tmp,
				     &map->om_seq_list,
				     oos_seq_list) {
		osd_seq_free(map, osd_seq);
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
	rc = osd_ost_init(dev);
	if (rc)
		RETURN(rc);

	/* prepare structures for MDS */
	rc = osd_mdt_init(env, dev);

        RETURN(rc);
}

struct osd_obj_seq *osd_seq_find_locked(struct osd_obj_map *map, obd_seq seq)
{
	struct osd_obj_seq *osd_seq;

	cfs_list_for_each_entry(osd_seq, &map->om_seq_list, oos_seq_list) {
		if (osd_seq->oos_seq == seq)
			return osd_seq;
	}
	return NULL;
}

struct osd_obj_seq *osd_seq_find(struct osd_obj_map *map, obd_seq seq)
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

static int osd_obj_del_entry(struct osd_thread_info *info,
			     struct osd_device *osd,
			     struct dentry *dird, char *name,
			     struct thandle *th)
{
	struct ldiskfs_dir_entry_2 *de;
	struct buffer_head         *bh;
	struct osd_thandle         *oh;
	struct dentry              *child;
	struct inode               *dir = dird->d_inode;
	int                         rc;
	ENTRY;

	oh = container_of(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle != NULL);
	LASSERT(oh->ot_handle->h_transaction != NULL);


	child = &info->oti_child_dentry;
	child->d_name.hash = 0;
	child->d_name.name = name;
	child->d_name.len = strlen(name);
	child->d_parent = dird;
	child->d_inode = NULL;

	ll_vfs_dq_init(dir);
	mutex_lock(&dir->i_mutex);
	rc = -ENOENT;
	bh = osd_ldiskfs_find_entry(dir, child, &de, NULL);
	if (bh) {
		rc = ldiskfs_delete_entry(oh->ot_handle, dir, de, bh);
		brelse(bh);
	}
	mutex_unlock(&dir->i_mutex);

	RETURN(rc);
}

int osd_obj_add_entry(struct osd_thread_info *info,
		      struct osd_device *osd,
		      struct dentry *dir, char *name,
		      const struct osd_inode_id *id,
		      struct thandle *th)
{
        struct osd_thandle *oh;
        struct dentry *child;
        struct inode *inode;
        int rc;

        ENTRY;

        oh = container_of(th, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);
        LASSERT(oh->ot_handle->h_transaction != NULL);

        inode = &info->oti_inode;
        inode->i_sb = osd_sb(osd);
	osd_id_to_inode(inode, id);
	inode->i_mode = S_IFREG; /* for type in ldiskfs dir entry */

        child = &info->oti_child_dentry;
        child->d_name.hash = 0;
        child->d_name.name = name;
        child->d_name.len = strlen(name);
        child->d_parent = dir;
        child->d_inode = inode;

	ll_vfs_dq_init(dir->d_inode);
	mutex_lock(&dir->d_inode->i_mutex);
	rc = osd_ldiskfs_add_entry(oh->ot_handle, child, inode, NULL);
	mutex_unlock(&dir->d_inode->i_mutex);

	RETURN(rc);
}

/**
 * Use LPU64 for legacy OST sequences, but use LPX64i for new
 * sequences names, so that the O/{seq}/dN/{oid} more closely
 * follows the DFID/PFID format. This makes it easier to map from
 * debug messages to objects in the future, and the legacy space
 * of FID_SEQ_OST_MDT0 will be unused in the future.
 **/
static inline void osd_seq_name(char *seq_name, size_t name_size, obd_seq seq)
{
	snprintf(seq_name, name_size,
		 (fid_seq_is_rsvd(seq) ||
		  fid_seq_is_mdt0(seq)) ? LPU64 : LPX64i,
		 fid_seq_is_idif(seq) ? 0 : seq);
}

static inline void osd_oid_name(char *name, size_t name_size,
				const struct lu_fid *fid, obd_id id)
{
	snprintf(name, name_size,
		 (fid_seq_is_rsvd(fid_seq(fid)) ||
		  fid_seq_is_mdt0(fid_seq(fid)) ||
		  fid_seq_is_idif(fid_seq(fid))) ? LPU64 : LPX64i, id);
}

/* external locking is required */
static int osd_seq_load_locked(struct osd_device *osd,
			       struct osd_obj_seq *osd_seq)
{
	struct osd_obj_map  *map = osd->od_ost_map;
	struct dentry       *seq_dir;
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

	ldiskfs_set_inode_state(seq_dir->d_inode, LDISKFS_STATE_LUSTRE_NO_OI);
	osd_seq->oos_root = seq_dir;

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

		ldiskfs_set_inode_state(dir->d_inode, LDISKFS_STATE_LUSTRE_NO_OI);
		osd_seq->oos_dirs[i] = dir;
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

struct osd_obj_seq *osd_seq_load(struct osd_device *osd, obd_seq seq)
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
	down(&map->om_dir_init_sem);

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

	CFS_INIT_LIST_HEAD(&osd_seq->oos_seq_list);
	osd_seq->oos_seq = seq;
	/* Init subdir count to be 32, but each seq can have
	 * different subdir count */
	osd_seq->oos_subdir_count = map->om_subdir_count;
	rc = osd_seq_load_locked(osd, osd_seq);
	if (rc != 0)
		GOTO(cleanup, rc);

	write_lock(&map->om_seq_list_lock);
	cfs_list_add(&osd_seq->oos_seq_list, &map->om_seq_list);
	write_unlock(&map->om_seq_list_lock);

cleanup:
	up(&map->om_dir_init_sem);
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
	osd_seq = osd_seq_load(dev, ostid_seq(ostid));
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
	bh = osd_ldiskfs_find_entry(dir, child, &de, NULL);
	mutex_unlock(&dir->i_mutex);

	if (bh == NULL)
		RETURN(-ENOENT);

	osd_id_gen(id, le32_to_cpu(de->inode), OSD_OII_NOGEN);
	brelse(bh);

	inode = osd_iget(info, dev, id);
	if (IS_ERR(inode))
		RETURN(PTR_ERR(inode));

	iput(inode);
	RETURN(0);
}

int osd_obj_map_insert(struct osd_thread_info *info,
		       struct osd_device *osd,
		       const struct lu_fid *fid,
		       const struct osd_inode_id *id,
		       struct thandle *th)
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

	osd_seq = osd_seq_load(osd, ostid_seq(ostid));
	if (IS_ERR(osd_seq))
		RETURN(PTR_ERR(osd_seq));

	dirn = ostid_id(ostid) & (osd_seq->oos_subdir_count - 1);
	d = osd_seq->oos_dirs[dirn];
        LASSERT(d);

	osd_oid_name(name, sizeof(name), fid, ostid_id(ostid));
	rc = osd_obj_add_entry(info, osd, d, name, id, th);

        RETURN(rc);
}

int osd_obj_map_delete(struct osd_thread_info *info, struct osd_device *osd,
		       const struct lu_fid *fid, struct thandle *th)
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

	osd_seq = osd_seq_load(osd, ostid_seq(ostid));
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

int osd_obj_spec_insert(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid,
			const struct osd_inode_id *id,
			struct thandle *th)
{
	struct osd_obj_map	*map = osd->od_ost_map;
	struct dentry		*root = osd_sb(osd)->s_root;
	char			*name;
	int			rc = 0;
	ENTRY;

	if (fid_is_last_id(fid)) {
		struct osd_obj_seq	*osd_seq;

		/* on creation of LAST_ID we create O/<seq> hierarchy */
		LASSERT(map);
		osd_seq = osd_seq_load(osd, fid_seq(fid));
		if (IS_ERR(osd_seq))
			RETURN(PTR_ERR(osd_seq));
		rc = osd_obj_add_entry(info, osd, osd_seq->oos_root,
				       "LAST_ID", id, th);
	} else {
		name = osd_lf_fid2name(fid);
		if (name == NULL)
			CWARN("UNKNOWN COMPAT FID "DFID"\n", PFID(fid));
		else if (name[0])
			rc = osd_obj_add_entry(info, osd, root, name, id, th);
	}

	RETURN(rc);
}

int osd_obj_spec_lookup(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct osd_inode_id *id)
{
	struct dentry	*root;
	struct dentry	*dentry;
	struct inode	*inode;
	char		*name;
	int		rc = -ENOENT;
	ENTRY;

	if (fid_is_last_id(fid)) {
		struct osd_obj_seq *osd_seq;

		osd_seq = osd_seq_load(osd, fid_seq(fid));
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
