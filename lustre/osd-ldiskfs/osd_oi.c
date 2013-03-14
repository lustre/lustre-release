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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_oi.c
 *
 * Object Index.
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

/*
 * oi uses two mechanisms to implement fid->cookie mapping:
 *
 *     - persistent index, where cookie is a record and fid is a key, and
 *
 *     - algorithmic mapping for "igif" fids.
 *
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd.h>
#include <obd_support.h>

/* fid_cpu_to_be() */
#include <lustre_fid.h>

#include "osd_oi.h"
/* osd_lookup(), struct osd_thread_info */
#include "osd_internal.h"
#include "osd_igif.h"
#include "dt_object.h"

struct oi_descr {
        int   fid_size;
        char *name;
        __u32 oid;
};

/** to serialize concurrent OI index initialization */
static cfs_mutex_t oi_init_lock;

static struct dt_index_features oi_feat = {
        .dif_flags       = DT_IND_UPDATE,
        .dif_recsize_min = sizeof(struct osd_inode_id),
        .dif_recsize_max = sizeof(struct osd_inode_id),
        .dif_ptrsize     = 4
};

static const struct oi_descr oi_descr[OSD_OI_FID_NR] = {
        [OSD_OI_FID_16] = {
                .fid_size = sizeof(struct lu_fid),
                .name     = "oi.16",
                .oid      = OSD_OI_FID_16_OID
        }
};

static int osd_oi_index_create_one(struct osd_thread_info *info,
				   struct osd_device *osd, const char *name,
				   struct dt_index_features *feat)
{
	const struct lu_env		*env = info->oti_env;
	struct osd_inode_id		*id = &info->oti_id;
	struct buffer_head		*bh;
	struct inode			*inode;
	struct ldiskfs_dir_entry_2	*de;
	struct dentry			*dentry;
	struct super_block		*sb = osd_sb(osd);
	struct inode			*dir = sb->s_root->d_inode;
	handle_t			*jh;
	int				rc;

	dentry = osd_child_dentry_by_inode(env, dir, name, strlen(name));
	bh = osd_ldiskfs_find_entry(dir, dentry, &de);
	if (bh) {
		id->oii_ino = le32_to_cpu(de->inode);
		id->oii_gen = OSD_OII_NOGEN;
		brelse(bh);
		inode = osd_iget(info, osd, id);
		if (!IS_ERR(inode)) {
			iput(inode);
			RETURN(-EEXIST);
		}
		return PTR_ERR(inode);
	}

	jh = ldiskfs_journal_start_sb(sb, 100);
	if (IS_ERR(jh))
		return PTR_ERR(jh);

	inode = ldiskfs_create_inode(jh, dir, (S_IFREG | S_IRUGO | S_IWUSR));
	if (IS_ERR(inode)) {
		ldiskfs_journal_stop(jh);
		return PTR_ERR(inode);
	}

	if (feat->dif_flags & DT_IND_VARKEY)
		rc = iam_lvar_create(inode, feat->dif_keysize_max,
				     feat->dif_ptrsize, feat->dif_recsize_max,
				     jh);
	else
		rc = iam_lfix_create(inode, feat->dif_keysize_max,
				     feat->dif_ptrsize, feat->dif_recsize_max,
				     jh);

	dentry = osd_child_dentry_by_inode(env, dir, name, strlen(name));
	rc = osd_ldiskfs_add_entry(jh, dentry, inode);
	ldiskfs_journal_stop(jh);
	iput(inode);

	return rc;
}

static struct inode *osd_oi_index_open(struct osd_thread_info *info,
				       struct osd_device *osd,
				       const char *name,
				       struct dt_index_features *f)
{
	struct dentry	*dentry;
	struct inode	*inode;
	int		rc;

	dentry = ll_lookup_one_len(name, osd_sb(osd)->s_root, strlen(name));
	if (IS_ERR(dentry))
		return (void *)dentry;

	if (dentry->d_inode) {
		LASSERT(!is_bad_inode(dentry->d_inode));
		inode = dentry->d_inode;
		atomic_inc(&inode->i_count);
		dput(dentry);
		return inode;
	}

	/* create */
	dput(dentry);
	shrink_dcache_parent(osd_sb(osd)->s_root);

	rc = osd_oi_index_create_one(info, osd, name, f);
	if (rc != 0)
		RETURN(ERR_PTR(rc));

	dentry = ll_lookup_one_len(name, osd_sb(osd)->s_root, strlen(name));
	if (IS_ERR(dentry))
		return (void *)dentry;

	if (dentry->d_inode) {
		LASSERT(!is_bad_inode(dentry->d_inode));
		inode = dentry->d_inode;
		atomic_inc(&inode->i_count);
		dput(dentry);
		return inode;
	}

	dput(dentry);
	return ERR_PTR(-ENOENT);
}

/**
 * Open an OI(Object Index) container.
 */
static int osd_oi_open(struct osd_thread_info *info, struct osd_device *osd,
		       char *name)
{
	struct osd_directory	*dir;
	struct iam_container	*bag;
	struct inode		*inode;
	struct osd_oi		*oi = &osd->od_oi;
	int			rc;

	ENTRY;

	oi_feat.dif_keysize_min = sizeof(struct lu_fid);
	oi_feat.dif_keysize_max = sizeof(struct lu_fid);

	inode = osd_oi_index_open(info, osd, name, &oi_feat);
	if (IS_ERR(inode))
		RETURN(PTR_ERR(inode));

	oi->oi_inode = inode;
	dir = &oi->oi_dir;
	bag = &dir->od_container;

	rc = iam_container_init(bag, &dir->od_descr, inode);
	if (rc < 0)
		GOTO(out_inode, rc);
	rc = iam_container_setup(bag);
	if (rc < 0)
		GOTO(out_container, rc);
	RETURN(0);

out_container:
	iam_container_fini(bag);
out_inode:
	iput(inode);
	return rc;
}

int osd_oi_init(struct osd_thread_info *info, struct osd_device *osd)
{
	struct dt_device	*dev = &osd->od_dt_dev;
        int			rc;

        cfs_mutex_lock(&oi_init_lock);
	rc = osd_oi_open(info, osd, oi_descr[0].name);
	if (rc < 0) {
		CERROR("%s: can't open %s: rc = %d\n",
		       dev->dd_lu_dev.ld_obd->obd_name, oi_descr[0].name, rc);
	}
        cfs_mutex_unlock(&oi_init_lock);
        return rc;
}

void osd_oi_fini(struct osd_thread_info *info, struct osd_device *osd)
{
	struct iam_container	*bag;

	LASSERT(osd->od_oi.oi_inode != NULL);

	bag = &(osd->od_oi.oi_dir.od_container);
	if (bag->ic_object == osd->od_oi.oi_inode)
		iam_container_fini(bag);
	iput(osd->od_oi.oi_inode);
	osd->od_oi.oi_inode = NULL;
}

static int osd_oi_iam_lookup(struct osd_thread_info *oti,
			     struct osd_oi *oi, struct dt_rec *rec,
			     const struct dt_key *key)
{
	struct iam_container  *bag;
	struct iam_iterator   *it = &oti->oti_idx_it;
	struct iam_path_descr *ipd;
	int                    rc;
	ENTRY;

	LASSERT(oi);
	LASSERT(oi->oi_inode);

	bag = &oi->oi_dir.od_container;
	ipd = osd_idx_ipd_get(oti->oti_env, bag);
	if (IS_ERR(ipd))
		RETURN(-ENOMEM);

	/* got ipd now we can start iterator. */
	iam_it_init(it, bag, 0, ipd);

	rc = iam_it_get(it, (struct iam_key *)key);
	if (rc > 0)
		iam_reccpy(&it->ii_path.ip_leaf, (struct iam_rec *)rec);
	iam_it_put(it);
	iam_it_fini(it);
	osd_ipd_put(oti->oti_env, bag, ipd);

	LINVRNT(osd_invariant(obj));

	RETURN(rc);
}

int osd_oi_lookup(struct osd_thread_info *info, struct osd_device *osd,
                  const struct lu_fid *fid, struct osd_inode_id *id)
{
        struct lu_fid *oi_fid = &info->oti_fid2;
        int rc;

        if (osd_fid_is_igif(fid)) {
                lu_igif_to_id(fid, id);
                rc = 0;
        } else {
		fid_cpu_to_be(oi_fid, fid);
		rc = osd_oi_iam_lookup(info, &osd->od_oi, (struct dt_rec *)id,
				       (const struct dt_key *)oi_fid);
		if (rc > 0) {
			osd_id_unpack(id, id);
			rc = 0;
		} else if (rc == 0) {
			rc = -ENOENT;
		}
	}
        return rc;
}

static int osd_oi_iam_refresh(struct osd_thread_info *info, struct osd_oi *oi,
			      const struct dt_rec *rec,
			      const struct dt_key *key, struct thandle *th,
			      bool insert)
{
	struct iam_container	*bag;
	struct iam_path_descr	*ipd;
	struct osd_thandle	*oh;
	int			rc;
	ENTRY;

	LASSERT(oi);
	LASSERT(oi->oi_inode);
	ll_vfs_dq_init(oi->oi_inode);

	bag = &oi->oi_dir.od_container;
	ipd = osd_idx_ipd_get(info->oti_env, bag);
	if (unlikely(ipd == NULL))
		RETURN(-ENOMEM);

	oh = container_of0(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle != NULL);
	LASSERT(oh->ot_handle->h_transaction != NULL);
	if (insert)
		rc = iam_insert(oh->ot_handle, bag,
				(const struct iam_key *)key,
				(const struct iam_rec *)rec, ipd);
	else
		rc = iam_update(oh->ot_handle, bag,
				(const struct iam_key *)key,
				(const struct iam_rec *)rec,
				ipd);
	osd_ipd_put(info->oti_env, bag, ipd);
	RETURN(rc);
}

int osd_oi_insert(struct osd_thread_info *info, struct osd_device *osd,
                  const struct lu_fid *fid, const struct osd_inode_id *id,
                  struct thandle *th, int ignore_quota)
{
        struct lu_fid		*oi_fid = &info->oti_fid2;
        struct osd_inode_id	*oi_id  = &info->oti_id2;
	int			rc      = 0;

	if (fid_seq(fid) == FID_SEQ_LOCAL_FILE)
		return 0;

        if (osd_fid_is_igif(fid))
                return 0;

        fid_cpu_to_be(oi_fid, fid);
	osd_id_pack(oi_id, id);
	rc = osd_oi_iam_refresh(info, &osd->od_oi,
				(const struct dt_rec *)oi_id,
				(const struct dt_key *)oi_fid, th, true);
	if (rc != 0) {
		struct inode *inode;
		struct lustre_mdt_attrs *lma = &info->oti_mdt_attrs;

		if (rc != -EEXIST)
			return rc;

		rc = osd_oi_lookup(info, osd, fid, oi_id);
		if (unlikely(rc != 0))
			return rc;

		if (osd_id_eq(id, oi_id)) {
			CERROR("%.16s: the FID "DFID" is ther already:%u/%u\n",
			       LDISKFS_SB(osd_sb(osd))->s_es->s_volume_name,
			       PFID(fid), id->oii_ino, id->oii_gen);
			return -EEXIST;
		}

		/* Check whether the mapping for oi_id is valid or not. */
		inode = osd_iget(info, osd, oi_id);
		if (IS_ERR(inode)) {
			rc = PTR_ERR(inode);
			if (rc == -ENOENT || rc == -ESTALE)
				goto update;
			return rc;
		}

		rc = osd_get_lma(info, inode, &info->oti_obj_dentry, lma);
		iput(inode);
		if (rc == -ENODATA)
			goto update;

		if (rc != 0)
			return rc;

		if (lu_fid_eq(fid, &lma->lma_self_fid)) {
			CERROR("%.16s: the FID "DFID" is used by two objects: "
			       "%u/%u %u/%u\n",
			       LDISKFS_SB(osd_sb(osd))->s_es->s_volume_name,
			       PFID(fid), oi_id->oii_ino, oi_id->oii_gen,
			       id->oii_ino, id->oii_gen);
			return -EEXIST;
		}
update:
		osd_id_pack(oi_id, id);
		rc = osd_oi_iam_refresh(info, &osd->od_oi,
					(const struct dt_rec *)oi_id,
					(const struct dt_key *)oi_fid, th,
					false);
	}

	return rc;
}

static int osd_oi_iam_delete(struct osd_thread_info *info, struct osd_oi *oi,
			     const struct dt_key *key, struct thandle *handle)
{
	struct iam_container	*bag;
	struct iam_path_descr	*ipd;
	struct osd_thandle	*oh;
	int			rc;
	ENTRY;

	LASSERT(oi);
	LASSERT(oi->oi_inode);
	ll_vfs_dq_init(oi->oi_inode);

	bag = &oi->oi_dir.od_container;
	ipd = osd_idx_ipd_get(info->oti_env, bag);
	if (unlikely(ipd == NULL))
		RETURN(-ENOMEM);

	oh = container_of0(handle, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle != NULL);
	LASSERT(oh->ot_handle->h_transaction != NULL);

	rc = iam_delete(oh->ot_handle, bag, (const struct iam_key *)key, ipd);
	osd_ipd_put(info->oti_env, bag, ipd);
	RETURN(rc);
}

int osd_oi_delete(struct osd_thread_info *info, struct osd_device *osd,
                  const struct lu_fid *fid, struct thandle *th)
{
        struct lu_fid *oi_fid = &info->oti_fid2;

        if (osd_fid_is_igif(fid))
                return 0;

        fid_cpu_to_be(oi_fid, fid);
	return osd_oi_iam_delete(info, &osd->od_oi,
				 (const struct dt_key *)oi_fid, th);
}

int osd_oi_mod_init()
{
        cfs_mutex_init(&oi_init_lock);
        return 0;
}
