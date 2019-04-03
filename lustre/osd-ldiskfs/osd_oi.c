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
 * Copyright (c) 2012, 2017, Intel Corporation.
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

#define DEBUG_SUBSYSTEM S_OSD

#include <linux/module.h>

/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd.h>
#include <obd_support.h>

/* fid_cpu_to_be() */
#include <lustre_fid.h>
#include <dt_object.h>
#include <lustre_scrub.h>

#include "osd_oi.h"
/* osd_lookup(), struct osd_thread_info */
#include "osd_internal.h"

unsigned int osd_oi_count = OSD_OI_FID_NR;
module_param(osd_oi_count, int, 0444);
MODULE_PARM_DESC(osd_oi_count, "Number of Object Index containers to be created, it's only valid for new filesystem.");

static struct dt_index_features oi_feat = {
        .dif_flags       = DT_IND_UPDATE,
        .dif_recsize_min = sizeof(struct osd_inode_id),
        .dif_recsize_max = sizeof(struct osd_inode_id),
        .dif_ptrsize     = 4
};

#define OSD_OI_NAME_BASE        "oi.16"

static void osd_oi_table_put(struct osd_thread_info *info,
			     struct osd_oi **oi_table, unsigned oi_count)
{
	struct iam_container *bag;
	int		      i;

	for (i = 0; i < oi_count; i++) {
		if (oi_table[i] == NULL)
			continue;

		LASSERT(oi_table[i]->oi_inode != NULL);

		bag = &(oi_table[i]->oi_dir.od_container);
		if (bag->ic_object == oi_table[i]->oi_inode)
			iam_container_fini(bag);
		iput(oi_table[i]->oi_inode);
		oi_table[i]->oi_inode = NULL;
		OBD_FREE_PTR(oi_table[i]);
		oi_table[i] = NULL;
	}
}

static int osd_oi_index_create_one(struct osd_thread_info *info,
				   struct osd_device *osd, const char *name,
				   struct dt_index_features *feat)
{
	const struct lu_env		*env = info->oti_env;
	struct osd_inode_id		*id  = &info->oti_id;
	struct buffer_head		*bh;
	struct inode			*inode;
	struct ldiskfs_dir_entry_2	*de;
	struct dentry			*dentry;
	struct super_block		*sb  = osd_sb(osd);
	struct inode			*dir = sb->s_root->d_inode;
	handle_t			*jh;
	int				 rc;

	dentry = osd_child_dentry_by_inode(env, dir, name, strlen(name));
	bh = osd_ldiskfs_find_entry(dir, &dentry->d_name, &de, NULL, NULL);
	if (!IS_ERR(bh)) {
		osd_id_gen(id, le32_to_cpu(de->inode), OSD_OII_NOGEN);
		brelse(bh);
		inode = osd_iget(info, osd, id);
		if (!IS_ERR(inode)) {
			iput(inode);
			inode = ERR_PTR(-EEXIST);
		}
		return PTR_ERR(inode);
	}

	if (osd->od_dt_dev.dd_rdonly)
		RETURN(-EROFS);

	jh = osd_journal_start_sb(sb, LDISKFS_HT_MISC, 100);
	if (IS_ERR(jh))
		return PTR_ERR(jh);

	inode = ldiskfs_create_inode(jh, dir, (S_IFREG | S_IRUGO | S_IWUSR),
				     NULL);
	if (IS_ERR(inode)) {
		ldiskfs_journal_stop(jh);
		return PTR_ERR(inode);
	}

	ldiskfs_set_inode_state(inode, LDISKFS_STATE_LUSTRE_NOSCRUB);
	unlock_new_inode(inode);

	if (feat->dif_flags & DT_IND_VARKEY)
		rc = iam_lvar_create(inode, feat->dif_keysize_max,
				     feat->dif_ptrsize, feat->dif_recsize_max,
				     jh);
	else
		rc = iam_lfix_create(inode, feat->dif_keysize_max,
				     feat->dif_ptrsize, feat->dif_recsize_max,
				     jh);
	dentry = osd_child_dentry_by_inode(env, dir, name, strlen(name));
	rc = osd_ldiskfs_add_entry(info, osd, jh, dentry, inode, NULL);
	ldiskfs_journal_stop(jh);
	iput(inode);
	return rc;
}

static struct inode *osd_oi_index_open(struct osd_thread_info *info,
                                       struct osd_device *osd,
                                       const char *name,
                                       struct dt_index_features *f,
                                       bool create)
{
        struct dentry *dentry;
        struct inode  *inode;
        int            rc;

        dentry = ll_lookup_one_len(name, osd_sb(osd)->s_root, strlen(name));
        if (IS_ERR(dentry))
                return (void *) dentry;

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
        if (!create)
                return ERR_PTR(-ENOENT);

        rc = osd_oi_index_create_one(info, osd, name, f);
        if (rc)
		return ERR_PTR(rc);

        dentry = ll_lookup_one_len(name, osd_sb(osd)->s_root, strlen(name));
        if (IS_ERR(dentry))
                return (void *) dentry;

        if (dentry->d_inode) {
                LASSERT(!is_bad_inode(dentry->d_inode));
                inode = dentry->d_inode;
                atomic_inc(&inode->i_count);
                dput(dentry);
                return inode;
        }

        return ERR_PTR(-ENOENT);
}

/**
 * Open an OI(Ojbect Index) container.
 *
 * \param       name    Name of OI container
 * \param       objp    Pointer of returned OI
 *
 * \retval      0       success
 * \retval      -ve     failure
 */
static int osd_oi_open(struct osd_thread_info *info, struct osd_device *osd,
                       char *name, struct osd_oi **oi_slot, bool create)
{
        struct osd_directory *dir;
        struct iam_container *bag;
        struct inode         *inode;
        struct osd_oi        *oi;
        int                   rc;

        ENTRY;

        oi_feat.dif_keysize_min = sizeof(struct lu_fid);
        oi_feat.dif_keysize_max = sizeof(struct lu_fid);

        inode = osd_oi_index_open(info, osd, name, &oi_feat, create);
        if (IS_ERR(inode))
                RETURN(PTR_ERR(inode));

	if (!osd->od_dt_dev.dd_rdonly) {
		/* 'What the @fid is' is not imporatant, because these objects
		 * have no OI mappings, and only are visible inside the OSD.*/
		lu_igif_build(&info->oti_fid, inode->i_ino,
			      inode->i_generation);
		rc = osd_ea_fid_set(info, inode, &info->oti_fid,
				    LMAC_NOT_IN_OI, 0);
		if (rc)
			GOTO(out_inode, rc);
	}

        OBD_ALLOC_PTR(oi);
        if (oi == NULL)
                GOTO(out_inode, rc = -ENOMEM);

        oi->oi_inode = inode;
        dir = &oi->oi_dir;

        bag = &dir->od_container;
        rc = iam_container_init(bag, &dir->od_descr, inode);
        if (rc < 0)
                GOTO(out_free, rc);

        rc = iam_container_setup(bag);
        if (rc < 0)
                GOTO(out_container, rc);

        *oi_slot = oi;
        RETURN(0);

out_container:
        iam_container_fini(bag);
out_free:
        OBD_FREE_PTR(oi);
out_inode:
        iput(inode);
        return rc;
}

/**
 * Open OI(Object Index) table.
 * If \a oi_count is zero, which means caller doesn't know how many OIs there
 * will be, this function can either return 0 for new filesystem, or number
 * of OIs on existed filesystem.
 *
 * If \a oi_count is non-zero, which means caller does know number of OIs on
 * filesystem, this function should return the exactly same number on
 * success, or error code in failure.
 *
 * \param     oi_count  Number of expected OI containers
 * \param     create    Create OIs if doesn't exist
 *
 * \retval    +ve       number of opened OI containers
 * \retval      0       no OI containers found
 * \retval    -ve       failure
 */
static int
osd_oi_table_open(struct osd_thread_info *info, struct osd_device *osd,
		  struct osd_oi **oi_table, unsigned oi_count, bool create)
{
	struct scrub_file *sf = &osd->od_scrub.os_scrub.os_file;
	int count = 0;
	int rc = 0;
	int i;
	ENTRY;

	/* NB: oi_count != 0 means that we have already created/known all OIs
	 * and have known exact number of OIs. */
	LASSERT(oi_count <= OSD_OI_FID_NR_MAX);

	for (i = 0; i < (oi_count != 0 ? oi_count : OSD_OI_FID_NR_MAX); i++) {
		char name[sizeof(OSD_OI_NAME_BASE) + 3 * sizeof(i) + 1];

		if (oi_table[i] != NULL) {
			count++;
			continue;
		}

		snprintf(name, sizeof(name), "%s.%d", OSD_OI_NAME_BASE, i);
		rc = osd_oi_open(info, osd, name, &oi_table[i], create);
		if (rc == 0) {
			count++;
			continue;
		}

		if (rc == -ENOENT && create == false) {
			if (oi_count == 0)
				return count;

			rc = 0;
			ldiskfs_set_bit(i, sf->sf_oi_bitmap);
			continue;
		}

		CERROR("%s: can't open %s: rc = %d\n",
		       osd_dev2name(osd), name, rc);
		if (oi_count > 0)
			CERROR("%s: expect to open total %d OI files.\n",
			       osd_dev2name(osd), oi_count);
		break;
	}

	if (rc < 0) {
		osd_oi_table_put(info, oi_table, oi_count > 0 ? oi_count : i);
		count = rc;
	}

	RETURN(count);
}

static int osd_remove_oi_one(struct dentry *parent, const char *name,
			     int namelen)
{
	struct dentry *child;
	int rc;

	child = ll_lookup_one_len(name, parent, namelen);
	if (IS_ERR(child)) {
		rc = PTR_ERR(child);
	} else {
		rc = ll_vfs_unlink(parent->d_inode, child);
		dput(child);
	}

	return rc == -ENOENT ? 0 : rc;
}

static int osd_remove_ois(struct osd_thread_info *info, struct osd_device *osd)
{
	char name[16];
	int namelen;
	int rc;
	int i;

	if (osd->od_dt_dev.dd_rdonly)
		RETURN(-EROFS);

	for (i = 0; i < OSD_OI_FID_NR_MAX; i++) {
		namelen = snprintf(name, sizeof(name), "%s.%d",
				   OSD_OI_NAME_BASE, i);
		rc = osd_remove_oi_one(osd_sb(osd)->s_root, name, namelen);
		if (rc != 0) {
			CERROR("%s: fail to remove the stale OI file %s: "
			       "rc = %d\n", osd_dev2name(osd), name, rc);
			return rc;
		}
	}

	namelen = snprintf(name, sizeof(name), "%s", OSD_OI_NAME_BASE);
	rc = osd_remove_oi_one(osd_sb(osd)->s_root, name, namelen);
	if (rc != 0)
		CERROR("%s: fail to remove the stale OI file %s: rc = %d\n",
		       osd_dev2name(osd), name, rc);

	return rc;
}

int osd_oi_init(struct osd_thread_info *info, struct osd_device *osd,
		bool restored)
{
	struct lustre_scrub *scrub = &osd->od_scrub.os_scrub;
	struct scrub_file *sf = &scrub->os_file;
	struct osd_oi **oi;
	int count;
	int rc;
	ENTRY;

	if (unlikely(sf->sf_oi_count & (sf->sf_oi_count - 1)) != 0) {
		LCONSOLE_WARN("%s: Invalid OI count in scrub file %d\n",
			      osd_dev2name(osd), sf->sf_oi_count);
		sf->sf_oi_count = 0;
	}

	if (restored) {
		rc = osd_remove_ois(info, osd);
		if (rc)
			RETURN(rc);
	}

	OBD_ALLOC(oi, sizeof(*oi) * OSD_OI_FID_NR_MAX);
	if (oi == NULL)
		RETURN(-ENOMEM);

	/* try to open existing multiple OIs first */
	count = osd_oi_table_open(info, osd, oi, sf->sf_oi_count, false);
	if (count < 0)
		GOTO(out, rc = count);

	if (count > 0) {
		if (count == sf->sf_oi_count)
			GOTO(out, rc = count);

		if (sf->sf_oi_count == 0) {
			if (likely((count & (count - 1)) == 0))
				GOTO(out, rc = count);

			LCONSOLE_WARN("%s: invalid oi count %d, remove them, "
				      "then set it to %d\n", osd_dev2name(osd),
				      count, osd_oi_count);
			osd_oi_table_put(info, oi, count);
			rc = osd_remove_ois(info, osd);
			if (rc)
				GOTO(out, rc);

			sf->sf_oi_count = osd_oi_count;
		}

		scrub_file_reset(scrub, LDISKFS_SB(osd_sb(osd))->s_es->s_uuid,
				 SF_RECREATED);
		count = sf->sf_oi_count;
		goto create;
	}

	/* if previous failed then try found single OI from old filesystem */
	rc = osd_oi_open(info, osd, OSD_OI_NAME_BASE, &oi[0], false);
	if (rc == 0) { /* found single OI from old filesystem */
		count = 1;
		ldiskfs_clear_bit(0, sf->sf_oi_bitmap);
		if (sf->sf_success_count == 0)
			/* XXX: There is one corner case that if the OI_scrub
			 *	file crashed or lost and we regard it upgrade,
			 *	then we allow IGIF lookup to bypass OI files.
			 *
			 *	The risk is that osd_fid_lookup() may found
			 *	a wrong inode with the given IGIF especially
			 *	when the MDT has performed file-level backup
			 *	and restored after former upgrading from 1.8
			 *	to 2.x. Fortunately, the osd_fid_lookup()can
			 *	verify the inode to decrease the risk. */
			scrub_file_reset(scrub,
					 LDISKFS_SB(osd_sb(osd))->s_es->s_uuid,
					 SF_UPGRADE);
		GOTO(out, rc = 1);
	} else if (rc != -ENOENT) {
		CERROR("%s: can't open %s: rc = %d\n",
		       osd_dev2name(osd), OSD_OI_NAME_BASE, rc);
		GOTO(out, rc);
	}

	if (sf->sf_oi_count > 0) {
		int i;

		count = sf->sf_oi_count;
		memset(sf->sf_oi_bitmap, 0, SCRUB_OI_BITMAP_SIZE);
		for (i = 0; i < count; i++)
			ldiskfs_set_bit(i, sf->sf_oi_bitmap);
		scrub_file_reset(scrub, LDISKFS_SB(osd_sb(osd))->s_es->s_uuid,
				 SF_RECREATED);
	} else {
		count = sf->sf_oi_count = osd_oi_count;
	}

create:
	rc = scrub_file_store(info->oti_env, scrub);
	if (rc < 0) {
		osd_oi_table_put(info, oi, count);
		GOTO(out, rc);
	}

	/* No OIs exist, new filesystem, create OI objects */
	rc = osd_oi_table_open(info, osd, oi, count, true);
	LASSERT(ergo(rc >= 0, rc == count));

	GOTO(out, rc);

out:
	if (rc < 0) {
		OBD_FREE(oi, sizeof(*oi) * OSD_OI_FID_NR_MAX);
	} else {
		LASSERTF((rc & (rc - 1)) == 0, "Invalid OI count %d\n", rc);

		osd->od_oi_table = oi;
		osd->od_oi_count = rc;
		if (sf->sf_oi_count != rc) {
			sf->sf_oi_count = rc;
			rc = scrub_file_store(info->oti_env, scrub);
			if (rc < 0) {
				osd_oi_table_put(info, oi, count);
				OBD_FREE(oi, sizeof(*oi) * OSD_OI_FID_NR_MAX);
			}
		} else {
			rc = 0;
		}
	}

	return rc;
}

void osd_oi_fini(struct osd_thread_info *info, struct osd_device *osd)
{
	if (unlikely(!osd->od_oi_table))
		return;

	osd_oi_table_put(info, osd->od_oi_table, osd->od_oi_count);

	OBD_FREE(osd->od_oi_table,
		 sizeof(*(osd->od_oi_table)) * OSD_OI_FID_NR_MAX);
	osd->od_oi_table = NULL;
}

static inline int fid_is_fs_root(const struct lu_fid *fid)
{
        /* Map root inode to special local object FID */
        return (unlikely(fid_seq(fid) == FID_SEQ_LOCAL_FILE &&
                         fid_oid(fid) == OSD_FS_ROOT_OID));
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

int fid_is_on_ost(struct osd_thread_info *info, struct osd_device *osd,
		  const struct lu_fid *fid, enum oi_check_flags flags)
{
	struct lu_seq_range	*range = &info->oti_seq_range;
	int			rc;
	ENTRY;

	if (flags & OI_KNOWN_ON_OST)
		RETURN(1);

	if (unlikely(fid_is_local_file(fid) || fid_is_igif(fid) ||
		     fid_is_llog(fid)) || fid_is_name_llog(fid) ||
		     fid_is_quota(fid))
		RETURN(0);

	if (fid_is_idif(fid) || fid_is_last_id(fid))
		RETURN(1);

	if (!(flags & OI_CHECK_FLD))
		RETURN(0);

	if (osd_seq_site(osd)->ss_server_fld == NULL)
		RETURN(0);

	rc = osd_fld_lookup(info->oti_env, osd, fid_seq(fid), range);
	if (rc != 0) {
		/* During upgrade, OST FLDB might not be loaded because
		 * OST FLDB is not created until 2.6, so if some DNE
		 * filesystem upgrade from 2.5 to 2.7/2.8, they will
		 * not be able to find the sequence from local FLDB
		 * cache see fld_index_init(). */
		if (rc == -ENOENT && osd->od_is_ost)
			RETURN(1);

		if (rc != -ENOENT)
			CERROR("%s: lookup FLD "DFID": rc = %d\n",
			       osd_name(osd), PFID(fid), rc);
		RETURN(0);
	}

	if (fld_range_is_ost(range))
		RETURN(1);

	RETURN(0);
}

static int __osd_oi_lookup(struct osd_thread_info *info, struct osd_device *osd,
			   const struct lu_fid *fid, struct osd_inode_id *id)
{
	struct lu_fid *oi_fid = &info->oti_fid2;
	int	       rc;

	fid_cpu_to_be(oi_fid, fid);
	rc = osd_oi_iam_lookup(info, osd_fid2oi(osd, fid), (struct dt_rec *)id,
			       (const struct dt_key *)oi_fid);
	if (rc > 0) {
		osd_id_unpack(id, id);
		rc = 0;
	} else if (rc == 0) {
		rc = -ENOENT;
	}
	return rc;
}

int osd_oi_lookup(struct osd_thread_info *info, struct osd_device *osd,
		  const struct lu_fid *fid, struct osd_inode_id *id,
		  enum oi_check_flags flags)
{
	if (unlikely(fid_is_last_id(fid)))
		return osd_obj_spec_lookup(info, osd, fid, id);

	if (fid_is_llog(fid) || fid_is_on_ost(info, osd, fid, flags))
		return osd_obj_map_lookup(info, osd, fid, id);


	if (unlikely(fid_seq(fid) == FID_SEQ_LOCAL_FILE)) {
		int rc;
		if (fid_is_fs_root(fid)) {
			osd_id_gen(id, osd_sb(osd)->s_root->d_inode->i_ino,
				   osd_sb(osd)->s_root->d_inode->i_generation);
			return 0;
		}
		if (unlikely(fid_is_acct(fid)))
			return osd_acct_obj_lookup(info, osd, fid, id);

		/* For other special FIDs, try OI first, then do spec lookup */
		rc = __osd_oi_lookup(info, osd, fid, id);
		if (rc == -ENOENT)
			return osd_obj_spec_lookup(info, osd, fid, id);
		return rc;
	}

	if (!osd->od_igif_inoi && fid_is_igif(fid)) {
		osd_id_gen(id, lu_igif_ino(fid), lu_igif_gen(fid));
		return 0;
	}

	return __osd_oi_lookup(info, osd, fid, id);
}

static int osd_oi_iam_refresh(struct osd_thread_info *oti, struct osd_oi *oi,
			     const struct dt_rec *rec, const struct dt_key *key,
			     handle_t *th, bool insert)
{
	struct iam_container	*bag;
	struct iam_path_descr	*ipd;
	int			rc;
	ENTRY;

	LASSERT(oi);
	LASSERT(oi->oi_inode);
	ll_vfs_dq_init(oi->oi_inode);

	bag = &oi->oi_dir.od_container;
	ipd = osd_idx_ipd_get(oti->oti_env, bag);
	if (unlikely(ipd == NULL))
		RETURN(-ENOMEM);

	LASSERT(th != NULL);
	LASSERT(th->h_transaction != NULL);
	if (insert)
		rc = iam_insert(th, bag, (const struct iam_key *)key,
				(const struct iam_rec *)rec, ipd);
	else
		rc = iam_update(th, bag, (const struct iam_key *)key,
				(const struct iam_rec *)rec, ipd);
	osd_ipd_put(oti->oti_env, bag, ipd);
	LINVRNT(osd_invariant(obj));
	RETURN(rc);
}

int osd_oi_insert(struct osd_thread_info *info, struct osd_device *osd,
		  const struct lu_fid *fid, const struct osd_inode_id *id,
		  handle_t *th, enum oi_check_flags flags, bool *exist)
{
	struct lu_fid	    *oi_fid = &info->oti_fid2;
	struct osd_inode_id *oi_id  = &info->oti_id2;
	int		     rc     = 0;

	if (unlikely(fid_is_last_id(fid)))
		return osd_obj_spec_insert(info, osd, fid, id, th);

	if (fid_is_llog(fid) || fid_is_on_ost(info, osd, fid, flags))
		return osd_obj_map_insert(info, osd, fid, id, th);

	fid_cpu_to_be(oi_fid, fid);
	osd_id_pack(oi_id, id);
	rc = osd_oi_iam_refresh(info, osd_fid2oi(osd, fid),
			       (const struct dt_rec *)oi_id,
			       (const struct dt_key *)oi_fid, th, true);
	if (rc != 0) {
		struct inode *inode;
		struct lustre_mdt_attrs *lma = &info->oti_ost_attrs.loa_lma;

		if (rc != -EEXIST)
			return rc;

		rc = osd_oi_lookup(info, osd, fid, oi_id, 0);
		if (rc != 0)
			return rc;

		if (unlikely(osd_id_eq(id, oi_id)))
			return 1;

		/* Check whether the mapping for oi_id is valid or not. */
		inode = osd_iget(info, osd, oi_id);
		if (IS_ERR(inode)) {
			rc = PTR_ERR(inode);
			if (rc == -ENOENT || rc == -ESTALE)
				goto update;
			return rc;
		}

		/* The EA inode should NOT be in OI, old OI scrub may added
		 * such OI mapping by wrong, replace it. */
		if (unlikely(osd_is_ea_inode(inode))) {
			iput(inode);
			goto update;
		}

		rc = osd_get_lma(info, inode, &info->oti_obj_dentry,
				 &info->oti_ost_attrs);
		iput(inode);
		if (rc == -ENODATA)
			goto update;

		if (rc != 0)
			return rc;

		if (!(lma->lma_compat & LMAC_NOT_IN_OI) &&
		    lu_fid_eq(fid, &lma->lma_self_fid)) {
			CERROR("%s: the FID "DFID" is used by two objects: "
			       "%u/%u %u/%u\n", osd_dev2name(osd),
			       PFID(fid), oi_id->oii_ino, oi_id->oii_gen,
			       id->oii_ino, id->oii_gen);
			return -EEXIST;
		}

update:
		osd_id_pack(oi_id, id);
		rc = osd_oi_iam_refresh(info, osd_fid2oi(osd, fid),
					(const struct dt_rec *)oi_id,
					(const struct dt_key *)oi_fid, th, false);
		if (rc != 0)
			return rc;

		if (exist != NULL)
			*exist = true;
	}

	if (unlikely(fid_seq(fid) == FID_SEQ_LOCAL_FILE))
		rc = osd_obj_spec_insert(info, osd, fid, id, th);
	return rc;
}

static int osd_oi_iam_delete(struct osd_thread_info *oti, struct osd_oi *oi,
			     const struct dt_key *key, handle_t *th)
{
	struct iam_container	*bag;
	struct iam_path_descr	*ipd;
	int			 rc;
	ENTRY;

	LASSERT(oi);
	LASSERT(oi->oi_inode);
	ll_vfs_dq_init(oi->oi_inode);

	bag = &oi->oi_dir.od_container;
	ipd = osd_idx_ipd_get(oti->oti_env, bag);
	if (unlikely(ipd == NULL))
		RETURN(-ENOMEM);

	LASSERT(th != NULL);
	LASSERT(th->h_transaction != NULL);

	rc = iam_delete(th, bag, (const struct iam_key *)key, ipd);
	osd_ipd_put(oti->oti_env, bag, ipd);
	LINVRNT(osd_invariant(obj));
	RETURN(rc);
}

int osd_oi_delete(struct osd_thread_info *info,
		  struct osd_device *osd, const struct lu_fid *fid,
		  handle_t *th, enum oi_check_flags flags)
{
	struct lu_fid *oi_fid = &info->oti_fid2;

	/* clear idmap cache */
	if (lu_fid_eq(fid, &info->oti_cache.oic_fid))
		fid_zero(&info->oti_cache.oic_fid);

	if (fid_is_last_id(fid))
		return 0;

	if (fid_is_llog(fid) || fid_is_on_ost(info, osd, fid, flags))
		return osd_obj_map_delete(info, osd, fid, th);

	fid_cpu_to_be(oi_fid, fid);
	return osd_oi_iam_delete(info, osd_fid2oi(osd, fid),
				 (const struct dt_key *)oi_fid, th);
}

int osd_oi_update(struct osd_thread_info *info, struct osd_device *osd,
		  const struct lu_fid *fid, const struct osd_inode_id *id,
		  handle_t *th, enum oi_check_flags flags)
{
	struct lu_fid	    *oi_fid = &info->oti_fid2;
	struct osd_inode_id *oi_id  = &info->oti_id2;
	int		     rc     = 0;

	if (unlikely(fid_is_last_id(fid)))
		return osd_obj_spec_update(info, osd, fid, id, th);

	if (fid_is_llog(fid) || fid_is_on_ost(info, osd, fid, flags))
		return osd_obj_map_update(info, osd, fid, id, th);

	fid_cpu_to_be(oi_fid, fid);
	osd_id_pack(oi_id, id);
	rc = osd_oi_iam_refresh(info, osd_fid2oi(osd, fid),
			       (const struct dt_rec *)oi_id,
			       (const struct dt_key *)oi_fid, th, false);
	if (rc != 0)
		return rc;

	if (unlikely(fid_seq(fid) == FID_SEQ_LOCAL_FILE))
		rc = osd_obj_spec_update(info, osd, fid, id, th);
	return rc;
}

int osd_oi_mod_init(void)
{
	if (osd_oi_count == 0 || osd_oi_count > OSD_OI_FID_NR_MAX)
		osd_oi_count = OSD_OI_FID_NR;

	if ((osd_oi_count & (osd_oi_count - 1)) != 0) {
		LCONSOLE_WARN("Round up oi_count %d to power2 %d\n",
			      osd_oi_count, size_roundup_power2(osd_oi_count));
		osd_oi_count = size_roundup_power2(osd_oi_count);
	}

	return 0;
}
