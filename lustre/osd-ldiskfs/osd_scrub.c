/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * lustre/osd-ldiskfs/osd_scrub.c
 *
 * Top-level entry points into osd module
 *
 * The OI scrub is used for rebuilding Object Index files when restores MDT from
 * file-level backup.
 *
 * The otable based iterator scans ldiskfs inode table to feed up layer LFSCK.
 *
 * Author: Fan Yong <yong.fan@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <lustre/lustre_idl.h>
#include <lustre_disk.h>
#include <dt_object.h>
#include <linux/xattr.h>

#include "osd_internal.h"
#include "osd_oi.h"
#include "osd_scrub.h"

#define HALF_SEC	(HZ >> 1)

#define OSD_OTABLE_MAX_HASH		0x00000000ffffffffULL

#define SCRUB_NEXT_BREAK	1 /* exit current loop and process next group */
#define SCRUB_NEXT_CONTINUE	2 /* skip current object and process next bit */
#define SCRUB_NEXT_EXIT 	3 /* exit all the loops */
#define SCRUB_NEXT_WAIT 	4 /* wait for free cache slot */
#define SCRUB_NEXT_CRASH	5 /* simulate system crash during OI scrub */
#define SCRUB_NEXT_FATAL	6 /* simulate failure during OI scrub */
#define SCRUB_NEXT_NOSCRUB	7 /* new created object, no scrub on it */
#define SCRUB_NEXT_NOLMA	8 /* the inode has no FID-in-LMA */
#define SCRUB_NEXT_OSTOBJ	9 /* for OST-object */
#define SCRUB_NEXT_OSTOBJ_OLD	10 /* old OST-object, no LMA or no FID-on-OST
				    * flags in LMA */

/* misc functions */

static inline struct osd_device *osd_scrub2dev(struct osd_scrub *scrub)
{
	return container_of0(scrub, struct osd_device, od_scrub);
}

static inline struct super_block *osd_scrub2sb(struct osd_scrub *scrub)
{
	return osd_sb(osd_scrub2dev(scrub));
}

static inline int osd_scrub_has_window(struct osd_scrub *scrub,
				       struct osd_otable_cache *ooc)
{
	return scrub->os_pos_current < ooc->ooc_pos_preload + SCRUB_WINDOW_SIZE;
}

/**
 * update/insert/delete the specified OI mapping (@fid @id) according to the ops
 *
 * \retval   1, changed nothing
 * \retval   0, changed successfully
 * \retval -ve, on error
 */
static int osd_scrub_refresh_mapping(struct osd_thread_info *info,
				     struct osd_device *dev,
				     const struct lu_fid *fid,
				     const struct osd_inode_id *id,
				     int ops, bool force,
				     enum oi_check_flags flags)
{
	const struct lu_env *env = info->oti_env;
	struct thandle	    *th;
	struct osd_thandle  *oh;
	int		     rc;
	ENTRY;

	if (dev->od_scrub.os_file.sf_param & SP_DRYRUN && !force)
		RETURN(0);

	th = dt_trans_create(env, &dev->od_dt_dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	oh = container_of0(th, struct osd_thandle, ot_super);
	LASSERT(oh->ot_handle == NULL);

	switch (ops) {
	case DTO_INDEX_UPDATE:
		osd_trans_declare_op(env, oh, OSD_OT_UPDATE,
				     osd_dto_credits_noquota[DTO_INDEX_UPDATE]);
		rc = dt_trans_start_local(env, &dev->od_dt_dev, th);
		if (rc != 0)
			GOTO(stop, rc);

		rc = osd_oi_update(info, dev, fid, id, th, flags);
		if (unlikely(rc == -ENOENT)) {
			/* Some unlink thread may removed the OI mapping. */
			rc = 1;
		}
		break;
	case DTO_INDEX_INSERT:
		osd_trans_declare_op(env, oh, OSD_OT_INSERT,
				     osd_dto_credits_noquota[DTO_INDEX_INSERT]);
		rc = dt_trans_start_local(env, &dev->od_dt_dev, th);
		if (rc != 0)
			GOTO(stop, rc);

		rc = osd_oi_insert(info, dev, fid, id, th, flags);
		if (unlikely(rc == -EEXIST)) {
			rc = 1;
			/* XXX: There are trouble things when adding OI
			 *	mapping for IGIF object, which may cause
			 *	multiple objects to be mapped to the same
			 *	IGIF formatted FID. Consider the following
			 *	situations:
			 *
			 *	1) The MDT is upgrading from 1.8 device.
			 *	The OI scrub generates IGIF FID1 for the
			 *	OBJ1 and adds the OI mapping.
			 *
			 *	2) For some reason, the OI scrub does not
			 *	process all the IGIF objects completely.
			 *
			 *	3) The MDT is backuped and restored against
			 *	this device.
			 *
			 *	4) When the MDT mounts up, the OI scrub will
			 *	try to rebuild the OI files. For some IGIF
			 *	object, OBJ2, which was not processed by the
			 *	OI scrub before the backup/restore, and the
			 *	new generated IGIF formatted FID may be just
			 *	the FID1, the same as OBJ1.
			 *
			 *	Under such case, the OI scrub cannot know how
			 *	to generate new FID for the OBJ2.
			 *
			 *	Currently, we do nothing for that. One possible
			 *	solution is to generate new normal FID for the
			 *	conflict object.
			 *
			 *	Anyway, it is rare, only exists in theory. */
		}
		break;
	case DTO_INDEX_DELETE:
		osd_trans_declare_op(env, oh, OSD_OT_DELETE,
				     osd_dto_credits_noquota[DTO_INDEX_DELETE]);
		rc = dt_trans_start_local(env, &dev->od_dt_dev, th);
		if (rc != 0)
			GOTO(stop, rc);

		rc = osd_oi_delete(info, dev, fid, th, flags);
		if (rc == -ENOENT) {
			/* It is normal that the unlink thread has removed the
			 * OI mapping already. */
			rc = 1;
		}
		break;
	default:
		LASSERTF(0, "Unexpected ops %d\n", ops);
		break;
	}

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, &dev->od_dt_dev, th);
	return rc;
}

/* OI_scrub file ops */

static void osd_scrub_file_to_cpu(struct scrub_file *des,
				  struct scrub_file *src)
{
	memcpy(des->sf_uuid, src->sf_uuid, 16);
	des->sf_flags	= le64_to_cpu(src->sf_flags);
	des->sf_magic	= le32_to_cpu(src->sf_magic);
	des->sf_status	= le16_to_cpu(src->sf_status);
	des->sf_param	= le16_to_cpu(src->sf_param);
	des->sf_time_last_complete      =
				le64_to_cpu(src->sf_time_last_complete);
	des->sf_time_latest_start       =
				le64_to_cpu(src->sf_time_latest_start);
	des->sf_time_last_checkpoint    =
				le64_to_cpu(src->sf_time_last_checkpoint);
	des->sf_pos_latest_start	=
				le64_to_cpu(src->sf_pos_latest_start);
	des->sf_pos_last_checkpoint     =
				le64_to_cpu(src->sf_pos_last_checkpoint);
	des->sf_pos_first_inconsistent  =
				le64_to_cpu(src->sf_pos_first_inconsistent);
	des->sf_items_checked		=
				le64_to_cpu(src->sf_items_checked);
	des->sf_items_updated		=
				le64_to_cpu(src->sf_items_updated);
	des->sf_items_failed		=
				le64_to_cpu(src->sf_items_failed);
	des->sf_items_updated_prior     =
				le64_to_cpu(src->sf_items_updated_prior);
	des->sf_run_time	= le32_to_cpu(src->sf_run_time);
	des->sf_success_count   = le32_to_cpu(src->sf_success_count);
	des->sf_oi_count	= le16_to_cpu(src->sf_oi_count);
	des->sf_internal_flags	= le16_to_cpu(src->sf_internal_flags);
	memcpy(des->sf_oi_bitmap, src->sf_oi_bitmap, SCRUB_OI_BITMAP_SIZE);
}

static void osd_scrub_file_to_le(struct scrub_file *des,
				 struct scrub_file *src)
{
	memcpy(des->sf_uuid, src->sf_uuid, 16);
	des->sf_flags	= cpu_to_le64(src->sf_flags);
	des->sf_magic	= cpu_to_le32(src->sf_magic);
	des->sf_status	= cpu_to_le16(src->sf_status);
	des->sf_param	= cpu_to_le16(src->sf_param);
	des->sf_time_last_complete      =
				cpu_to_le64(src->sf_time_last_complete);
	des->sf_time_latest_start       =
				cpu_to_le64(src->sf_time_latest_start);
	des->sf_time_last_checkpoint    =
				cpu_to_le64(src->sf_time_last_checkpoint);
	des->sf_pos_latest_start	=
				cpu_to_le64(src->sf_pos_latest_start);
	des->sf_pos_last_checkpoint     =
				cpu_to_le64(src->sf_pos_last_checkpoint);
	des->sf_pos_first_inconsistent  =
				cpu_to_le64(src->sf_pos_first_inconsistent);
	des->sf_items_checked		=
				cpu_to_le64(src->sf_items_checked);
	des->sf_items_updated		=
				cpu_to_le64(src->sf_items_updated);
	des->sf_items_failed		=
				cpu_to_le64(src->sf_items_failed);
	des->sf_items_updated_prior     =
				cpu_to_le64(src->sf_items_updated_prior);
	des->sf_run_time	= cpu_to_le32(src->sf_run_time);
	des->sf_success_count   = cpu_to_le32(src->sf_success_count);
	des->sf_oi_count	= cpu_to_le16(src->sf_oi_count);
	des->sf_internal_flags	= cpu_to_le16(src->sf_internal_flags);
	memcpy(des->sf_oi_bitmap, src->sf_oi_bitmap, SCRUB_OI_BITMAP_SIZE);
}

static void osd_scrub_file_init(struct osd_scrub *scrub, __u8 *uuid)
{
	struct scrub_file *sf = &scrub->os_file;

	memset(sf, 0, sizeof(*sf));
	memcpy(sf->sf_uuid, uuid, 16);
	sf->sf_magic = SCRUB_MAGIC_V1;
	sf->sf_status = SS_INIT;
}

void osd_scrub_file_reset(struct osd_scrub *scrub, __u8 *uuid, __u64 flags)
{
	struct scrub_file *sf = &scrub->os_file;

	CDEBUG(D_LFSCK, "Reset OI scrub file, flags = "LPX64"\n", flags);
	memcpy(sf->sf_uuid, uuid, 16);
	sf->sf_status = SS_INIT;
	sf->sf_flags |= flags;
	sf->sf_run_time = 0;
	sf->sf_time_latest_start = 0;
	sf->sf_time_last_checkpoint = 0;
	sf->sf_pos_latest_start = 0;
	sf->sf_pos_last_checkpoint = 0;
	sf->sf_pos_first_inconsistent = 0;
	sf->sf_items_checked = 0;
	sf->sf_items_updated = 0;
	sf->sf_items_failed = 0;
	sf->sf_items_updated_prior = 0;
	sf->sf_items_noscrub = 0;
	sf->sf_items_igif = 0;
}

static int osd_scrub_file_load(struct osd_scrub *scrub)
{
	loff_t	pos  = 0;
	char   *name = LDISKFS_SB(osd_scrub2sb(scrub))->s_es->s_volume_name;
	int	len  = sizeof(scrub->os_file_disk);
	int	rc;

	rc = osd_ldiskfs_read(scrub->os_inode, &scrub->os_file_disk, len, &pos);
	if (rc == len) {
		struct scrub_file *sf = &scrub->os_file;

		osd_scrub_file_to_cpu(sf, &scrub->os_file_disk);
		if (sf->sf_magic != SCRUB_MAGIC_V1) {
			CWARN("%.16s: invalid scrub magic 0x%x != 0x%x\n,",
			      name, sf->sf_magic, SCRUB_MAGIC_V1);
			/* Process it as new scrub file. */
			rc = -ENOENT;
		} else {
			rc = 0;
		}
	} else if (rc != 0) {
		CERROR("%.16s: fail to load scrub file, expected = %d, "
		       "rc = %d\n", name, len, rc);
		if (rc > 0)
			rc = -EFAULT;
	} else {
		/* return -ENOENT for empty scrub file case. */
		rc = -ENOENT;
	}

	return rc;
}

int osd_scrub_file_store(struct osd_scrub *scrub)
{
	struct osd_device *dev;
	handle_t	  *jh;
	loff_t		   pos     = 0;
	int		   len     = sizeof(scrub->os_file_disk);
	int		   credits;
	int		   rc;

	dev = container_of0(scrub, struct osd_device, od_scrub);
	credits = osd_dto_credits_noquota[DTO_WRITE_BASE] +
		  osd_dto_credits_noquota[DTO_WRITE_BLOCK];
	jh = osd_journal_start_sb(osd_sb(dev), LDISKFS_HT_MISC, credits);
	if (IS_ERR(jh)) {
		rc = PTR_ERR(jh);
		CERROR("%.16s: fail to start trans for scrub store, rc = %d\n",
		       LDISKFS_SB(osd_scrub2sb(scrub))->s_es->s_volume_name,rc);
		return rc;
	}

	osd_scrub_file_to_le(&scrub->os_file_disk, &scrub->os_file);
	rc = osd_ldiskfs_write_record(scrub->os_inode, &scrub->os_file_disk,
				      len, 0, &pos, jh);
	ldiskfs_journal_stop(jh);
	if (rc != 0)
		CERROR("%.16s: fail to store scrub file, expected = %d, "
		       "rc = %d\n",
		       LDISKFS_SB(osd_scrub2sb(scrub))->s_es->s_volume_name,
		       len, rc);
	scrub->os_time_last_checkpoint = cfs_time_current();
	scrub->os_time_next_checkpoint = scrub->os_time_last_checkpoint +
				cfs_time_seconds(SCRUB_CHECKPOINT_INTERVAL);
	return rc;
}

static int
osd_scrub_convert_ff(struct osd_thread_info *info, struct osd_device *dev,
		     struct inode *inode, const struct lu_fid *fid)
{
	struct filter_fid_old   *ff	 = &info->oti_ff;
	struct dentry		*dentry  = &info->oti_obj_dentry;
	handle_t		*jh;
	int			 size	 = 0;
	int			 rc;
	bool			 removed = false;
	bool			 reset   = true;
	ENTRY;

	if (dev->od_scrub.os_file.sf_param & SP_DRYRUN)
		RETURN(0);

	/* We want the LMA to fit into the 256-byte OST inode, so operate
	 * as following:
	 * 1) read old XATTR_NAME_FID and save the parent FID;
	 * 2) delete the old XATTR_NAME_FID;
	 * 3) make new LMA and add it;
	 * 4) generate new XATTR_NAME_FID with the saved parent FID and add it.
	 *
	 * Making the LMA to fit into the 256-byte OST inode can save time for
	 * normal osd_check_lma() and for other OI scrub scanning in future.
	 * So it is worth to make some slow conversion here. */
	jh = osd_journal_start_sb(osd_sb(dev), LDISKFS_HT_MISC,
				osd_dto_credits_noquota[DTO_XATTR_SET] * 3);
	if (IS_ERR(jh)) {
		rc = PTR_ERR(jh);
		CERROR("%s: fail to start trans for convert ff: "DFID
		       ": rc = %d\n",
		       osd_name(dev), PFID(fid), rc);
		RETURN(rc);
	}

	/* 1) read old XATTR_NAME_FID and save the parent FID */
	rc = __osd_xattr_get(inode, dentry, XATTR_NAME_FID, ff, sizeof(*ff));
	if (rc == sizeof(*ff)) {
		/* 2) delete the old XATTR_NAME_FID */
		ll_vfs_dq_init(inode);
		rc = inode->i_op->removexattr(dentry, XATTR_NAME_FID);
		if (rc != 0)
			GOTO(stop, rc);

		removed = true;
	} else if (unlikely(rc == -ENODATA)) {
		reset = false;
	} else if (rc != sizeof(struct filter_fid)) {
		GOTO(stop, rc = -EINVAL);
	}

	/* 3) make new LMA and add it */
	rc = osd_ea_fid_set(info, inode, fid, LMAC_FID_ON_OST, 0);
	if (rc == 0 && reset)
		size = sizeof(struct filter_fid);
	else if (rc != 0 && removed)
		/* If failed, we should try to add the old back. */
		size = sizeof(struct filter_fid_old);

	/* 4) generate new XATTR_NAME_FID with the saved parent FID and add it*/
	if (size > 0) {
		int rc1;

		rc1 = __osd_xattr_set(info, inode, XATTR_NAME_FID, ff, size,
				      XATTR_CREATE);
		if (rc1 != 0 && rc == 0)
			rc = rc1;
	}

	GOTO(stop, rc);

stop:
	ldiskfs_journal_stop(jh);
	return rc;
}

static int
osd_scrub_check_update(struct osd_thread_info *info, struct osd_device *dev,
		       struct osd_idmap_cache *oic, int val)
{
	struct osd_scrub	     *scrub  = &dev->od_scrub;
	struct scrub_file	     *sf     = &scrub->os_file;
	struct lu_fid		     *fid    = &oic->oic_fid;
	struct osd_inode_id	     *lid    = &oic->oic_lid;
	struct osd_inode_id	     *lid2   = &info->oti_id;
	struct osd_inconsistent_item *oii    = NULL;
	struct inode		     *inode  = NULL;
	int			      ops    = DTO_INDEX_UPDATE;
	int			      idx;
	int			      rc;
	bool			      converted = false;
	ENTRY;

	down_write(&scrub->os_rwsem);
	scrub->os_new_checked++;
	if (val < 0)
		GOTO(out, rc = val);

	if (scrub->os_in_prior)
		oii = cfs_list_entry(oic, struct osd_inconsistent_item,
				     oii_cache);

	if (lid->oii_ino < sf->sf_pos_latest_start && oii == NULL)
		GOTO(out, rc = 0);

	if (fid_is_igif(fid))
		sf->sf_items_igif++;

	if (val == SCRUB_NEXT_OSTOBJ_OLD) {
		inode = osd_iget(info, dev, lid);
		if (IS_ERR(inode)) {
			rc = PTR_ERR(inode);
			/* Someone removed the inode. */
			if (rc == -ENOENT || rc == -ESTALE)
				rc = 0;
			GOTO(out, rc);
		}

		sf->sf_flags |= SF_UPGRADE;
		sf->sf_internal_flags &= ~SIF_NO_HANDLE_OLD_FID;
		dev->od_check_ff = 1;
		rc = osd_scrub_convert_ff(info, dev, inode, fid);
		if (rc != 0)
			GOTO(out, rc);

		converted = true;
	}

	if ((val == SCRUB_NEXT_NOLMA) &&
	    (!scrub->os_convert_igif || OBD_FAIL_CHECK(OBD_FAIL_FID_NOLMA)))
		GOTO(out, rc = 0);

	if ((oii != NULL && oii->oii_insert) || (val == SCRUB_NEXT_NOLMA))
		goto iget;

	rc = osd_oi_lookup(info, dev, fid, lid2,
		(val == SCRUB_NEXT_OSTOBJ ||
		 val == SCRUB_NEXT_OSTOBJ_OLD) ? OI_KNOWN_ON_OST : 0);
	if (rc != 0) {
		if (rc != -ENOENT)
			GOTO(out, rc);

iget:
		if (inode == NULL) {
			inode = osd_iget(info, dev, lid);
			if (IS_ERR(inode)) {
				rc = PTR_ERR(inode);
				/* Someone removed the inode. */
				if (rc == -ENOENT || rc == -ESTALE)
					rc = 0;
				GOTO(out, rc);
			}
		}

		scrub->os_full_speed = 1;
		ops = DTO_INDEX_INSERT;
		idx = osd_oi_fid2idx(dev, fid);
		switch (val) {
		case SCRUB_NEXT_NOLMA:
			sf->sf_flags |= SF_UPGRADE;
			if (!(sf->sf_param & SP_DRYRUN)) {
				rc = osd_ea_fid_set(info, inode, fid, 0, 0);
				if (rc != 0)
					GOTO(out, rc);
			}

			if (!(sf->sf_flags & SF_INCONSISTENT))
				dev->od_igif_inoi = 0;
			break;
		case SCRUB_NEXT_OSTOBJ:
			sf->sf_flags |= SF_INCONSISTENT;
		case SCRUB_NEXT_OSTOBJ_OLD:
			break;
		default:
			sf->sf_flags |= SF_RECREATED;
			if (unlikely(!ldiskfs_test_bit(idx, sf->sf_oi_bitmap)))
				ldiskfs_set_bit(idx, sf->sf_oi_bitmap);
			break;
		}
	} else if (osd_id_eq(lid, lid2)) {
		if (converted)
			sf->sf_items_updated++;

		GOTO(out, rc = 0);
	} else {
		scrub->os_full_speed = 1;
		sf->sf_flags |= SF_INCONSISTENT;

		/* XXX: If the device is restored from file-level backup, then
		 *	some IGIFs may have been already in OI files, and some
		 *	may be not yet. Means upgrading from 1.8 may be partly
		 *	processed, but some clients may hold some immobilized
		 *	IGIFs, and use them to access related objects. Under
		 *	such case, OSD does not know whether an given IGIF has
		 *	been processed or to be processed, and it also cannot
		 *	generate local ino#/gen# directly from the immobilized
		 *	IGIF because of the backup/restore. Then force OSD to
		 *	lookup the given IGIF in OI files, and if no entry,
		 *	then ask the client to retry after upgrading completed.
		 *	No better choice. */
		dev->od_igif_inoi = 1;
	}

	rc = osd_scrub_refresh_mapping(info, dev, fid, lid, ops, false,
			(val == SCRUB_NEXT_OSTOBJ ||
			 val == SCRUB_NEXT_OSTOBJ_OLD) ? OI_KNOWN_ON_OST : 0);
	if (rc == 0) {
		if (scrub->os_in_prior)
			sf->sf_items_updated_prior++;
		else
			sf->sf_items_updated++;

		/* The target has been changed, need to be re-loaded. */
		lu_object_purge(info->oti_env, osd2lu_dev(dev), fid);
	}

	GOTO(out, rc);

out:
	if (rc < 0) {
		sf->sf_items_failed++;
		if (sf->sf_pos_first_inconsistent == 0 ||
		    sf->sf_pos_first_inconsistent > lid->oii_ino)
			sf->sf_pos_first_inconsistent = lid->oii_ino;
	} else {
		rc = 0;
	}

	/* There may be conflict unlink during the OI scrub,
	 * if happend, then remove the new added OI mapping. */
	if (ops == DTO_INDEX_INSERT && inode != NULL && !IS_ERR(inode) &&
	    unlikely(inode->i_nlink == 0))
		osd_scrub_refresh_mapping(info, dev, fid, lid,
				DTO_INDEX_DELETE, false,
				(val == SCRUB_NEXT_OSTOBJ ||
				 val == SCRUB_NEXT_OSTOBJ_OLD) ?
				OI_KNOWN_ON_OST : 0);
	up_write(&scrub->os_rwsem);

	if (inode != NULL && !IS_ERR(inode))
		iput(inode);

	if (oii != NULL) {
		LASSERT(!cfs_list_empty(&oii->oii_list));

		spin_lock(&scrub->os_lock);
		cfs_list_del_init(&oii->oii_list);
		spin_unlock(&scrub->os_lock);
		OBD_FREE_PTR(oii);
	}
	RETURN(sf->sf_param & SP_FAILOUT ? rc : 0);
}

/* OI scrub APIs */

static int osd_scrub_prep(struct osd_device *dev)
{
	struct osd_scrub     *scrub  = &dev->od_scrub;
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct scrub_file    *sf     = &scrub->os_file;
	__u32		      flags  = scrub->os_start_flags;
	int		      rc;
	bool		      drop_dryrun = false;
	ENTRY;

	down_write(&scrub->os_rwsem);
	if (flags & SS_SET_FAILOUT)
		sf->sf_param |= SP_FAILOUT;

	if (flags & SS_CLEAR_FAILOUT)
		sf->sf_param &= ~SP_FAILOUT;

	if (flags & SS_SET_DRYRUN)
		sf->sf_param |= SP_DRYRUN;

	if (flags & SS_CLEAR_DRYRUN && sf->sf_param & SP_DRYRUN) {
		sf->sf_param &= ~SP_DRYRUN;
		drop_dryrun = true;
	}

	if (flags & SS_RESET)
		osd_scrub_file_reset(scrub,
			LDISKFS_SB(osd_sb(dev))->s_es->s_uuid, 0);

	if (flags & SS_AUTO) {
		scrub->os_full_speed = 1;
		sf->sf_flags |= SF_AUTO;
		/* For the case of OI scrub auto triggered, NOT dryrun. */
		sf->sf_param &= ~SP_FAILOUT;
	} else {
		scrub->os_full_speed = 0;
	}

	if (sf->sf_flags & (SF_RECREATED | SF_INCONSISTENT | SF_UPGRADE))
		scrub->os_full_speed = 1;

	scrub->os_in_prior = 0;
	spin_lock(&scrub->os_lock);
	scrub->os_waiting = 0;
	scrub->os_paused = 0;
	spin_unlock(&scrub->os_lock);
	scrub->os_new_checked = 0;
	if (drop_dryrun && sf->sf_pos_first_inconsistent != 0)
		sf->sf_pos_latest_start = sf->sf_pos_first_inconsistent;
	else if (sf->sf_pos_last_checkpoint != 0)
		sf->sf_pos_latest_start = sf->sf_pos_last_checkpoint + 1;
	else
		sf->sf_pos_latest_start = LDISKFS_FIRST_INO(osd_sb(dev)) + 1;

	scrub->os_pos_current = sf->sf_pos_latest_start;
	sf->sf_status = SS_SCANNING;
	sf->sf_time_latest_start = cfs_time_current_sec();
	sf->sf_time_last_checkpoint = sf->sf_time_latest_start;
	rc = osd_scrub_file_store(scrub);
	if (rc == 0) {
		spin_lock(&scrub->os_lock);
		thread_set_flags(thread, SVC_RUNNING);
		spin_unlock(&scrub->os_lock);
		wake_up_all(&thread->t_ctl_waitq);
	}
	up_write(&scrub->os_rwsem);

	RETURN(rc);
}

static int osd_scrub_checkpoint(struct osd_scrub *scrub)
{
	struct scrub_file *sf = &scrub->os_file;
	int		   rc;

	if (likely(cfs_time_before(cfs_time_current(),
				   scrub->os_time_next_checkpoint) ||
		   scrub->os_new_checked == 0))
		return 0;

	down_write(&scrub->os_rwsem);
	sf->sf_items_checked += scrub->os_new_checked;
	scrub->os_new_checked = 0;
	sf->sf_pos_last_checkpoint = scrub->os_pos_current;
	sf->sf_time_last_checkpoint = cfs_time_current_sec();
	sf->sf_run_time += cfs_duration_sec(cfs_time_current() + HALF_SEC -
					    scrub->os_time_last_checkpoint);
	rc = osd_scrub_file_store(scrub);
	up_write(&scrub->os_rwsem);

	return rc;
}

static void osd_scrub_post(struct osd_scrub *scrub, int result)
{
	struct scrub_file *sf = &scrub->os_file;
	ENTRY;

	down_write(&scrub->os_rwsem);
	spin_lock(&scrub->os_lock);
	thread_set_flags(&scrub->os_thread, SVC_STOPPING);
	spin_unlock(&scrub->os_lock);
	if (scrub->os_new_checked > 0) {
		sf->sf_items_checked += scrub->os_new_checked;
		scrub->os_new_checked = 0;
		sf->sf_pos_last_checkpoint = scrub->os_pos_current;
	}
	sf->sf_time_last_checkpoint = cfs_time_current_sec();
	if (result > 0) {
		struct osd_device *dev =
			container_of0(scrub, struct osd_device, od_scrub);

		dev->od_igif_inoi = 1;
		dev->od_check_ff = 0;
		sf->sf_status = SS_COMPLETED;
		if (!(sf->sf_param & SP_DRYRUN)) {
			memset(sf->sf_oi_bitmap, 0, SCRUB_OI_BITMAP_SIZE);
			sf->sf_flags &= ~(SF_RECREATED | SF_INCONSISTENT |
					  SF_UPGRADE | SF_AUTO);
		}
		sf->sf_time_last_complete = sf->sf_time_last_checkpoint;
		sf->sf_success_count++;
	} else if (result == 0) {
		if (scrub->os_paused)
			sf->sf_status = SS_PAUSED;
		else
			sf->sf_status = SS_STOPPED;
	} else {
		sf->sf_status = SS_FAILED;
	}
	sf->sf_run_time += cfs_duration_sec(cfs_time_current() + HALF_SEC -
					    scrub->os_time_last_checkpoint);
	result = osd_scrub_file_store(scrub);
	if (result < 0)
		CERROR("%.16s: fail to osd_scrub_post, rc = %d\n",
		       LDISKFS_SB(osd_scrub2sb(scrub))->s_es->s_volume_name,
		       result);
	up_write(&scrub->os_rwsem);

	EXIT;
}

/* iteration engine */

struct osd_iit_param {
	struct super_block *sb;
	struct buffer_head *bitmap;
	ldiskfs_group_t bg;
	__u32 gbase;
	__u32 offset;
};

typedef int (*osd_iit_next_policy)(struct osd_thread_info *info,
				   struct osd_device *dev,
				   struct osd_iit_param *param,
				   struct osd_idmap_cache **oic,
				   int noslot);

typedef int (*osd_iit_exec_policy)(struct osd_thread_info *info,
				   struct osd_device *dev,
				   struct osd_iit_param *param,
				   struct osd_idmap_cache *oic,
				   int *noslot, int rc);

static int osd_iit_next(struct osd_iit_param *param, __u32 *pos)
{
	param->offset = ldiskfs_find_next_bit(param->bitmap->b_data,
			LDISKFS_INODES_PER_GROUP(param->sb), param->offset);
	if (param->offset >= LDISKFS_INODES_PER_GROUP(param->sb)) {
		*pos = 1 + (param->bg+1) * LDISKFS_INODES_PER_GROUP(param->sb);
		return SCRUB_NEXT_BREAK;
	} else {
		*pos = param->gbase + param->offset;
		return 0;
	}
}

/**
 * \retval SCRUB_NEXT_OSTOBJ_OLD: FID-on-OST
 * \retval 0: FID-on-MDT
 */
static int osd_scrub_check_local_fldb(struct osd_thread_info *info,
				      struct osd_device *dev,
				      struct lu_fid *fid)
{
	/* XXX: The initial OI scrub will scan the top level /O to generate
	 *	a small local FLDB according to the <seq>. If the given FID
	 *	is in the local FLDB, then it is FID-on-OST; otherwise it's
	 *	quite possible for FID-on-MDT. */
	if (dev->od_is_ost)
		return SCRUB_NEXT_OSTOBJ_OLD;
	else
		return 0;
}

static int osd_scrub_get_fid(struct osd_thread_info *info,
			     struct osd_device *dev, struct inode *inode,
			     struct lu_fid *fid, bool scrub)
{
	struct lustre_mdt_attrs *lma	 = &info->oti_mdt_attrs;
	int			 rc;
	bool			 has_lma = false;

	rc = osd_get_lma(info, inode, &info->oti_obj_dentry, lma);
	if (rc == 0) {
		has_lma = true;
		if (lma->lma_compat & LMAC_NOT_IN_OI) {
			ldiskfs_set_inode_state(inode,
						LDISKFS_STATE_LUSTRE_NO_OI);
			return SCRUB_NEXT_CONTINUE;
		}

		*fid = lma->lma_self_fid;
		if (fid_is_internal(&lma->lma_self_fid)) {
			if (!scrub)
				rc = SCRUB_NEXT_CONTINUE;
			return rc;
		}

		if (!scrub)
			return 0;

		if (fid_is_namespace_visible(fid) && !fid_is_norm(fid))
			return 0;

		if (lma->lma_compat & LMAC_FID_ON_OST)
			return SCRUB_NEXT_OSTOBJ;

		if (fid_is_idif(fid) || fid_is_last_id(fid))
			return SCRUB_NEXT_OSTOBJ_OLD;

		if (lma->lma_incompat & LMAI_AGENT)
			return SCRUB_NEXT_CONTINUE;

		/* Here, it may be MDT-object, or may be 2.4 OST-object.
		 * Fall through. */
	}

	if (rc == -ENODATA || rc == 0) {
		rc = osd_get_idif(info, inode, &info->oti_obj_dentry, fid);
		if (rc == 0) {
			if (scrub)
				/* It is old 2.x (x <= 3) or 1.8 OST-object. */
				rc = SCRUB_NEXT_OSTOBJ_OLD;
			return rc;
		}

		if (rc > 0) {
			if (!has_lma)
				/* It is FID-on-OST, but we do not know how
				 * to generate its FID, ignore it directly. */
				rc = SCRUB_NEXT_CONTINUE;
			else
				/* It is 2.4 OST-object. */
				rc = SCRUB_NEXT_OSTOBJ_OLD;
			return rc;
		}

		if (rc != -ENODATA)
			return rc;

		if (!has_lma) {
			if (dev->od_scrub.os_convert_igif) {
				lu_igif_build(fid, inode->i_ino,
					      inode->i_generation);
				if (scrub)
					rc = SCRUB_NEXT_NOLMA;
				else
					rc = 0;
			} else {
				/* It may be FID-on-OST, or may be FID for
				 * non-MDT0, anyway, we do not know how to
				 * generate its FID, ignore it directly. */
				rc = SCRUB_NEXT_CONTINUE;
			}
			return rc;
		}

		/* For OI scrub case only: the object has LMA but has no ff
		 * (or ff crashed). It may be MDT-object, may be OST-object
		 * with crashed ff. The last check is local FLDB. */
		rc = osd_scrub_check_local_fldb(info, dev, fid);
	}

	return rc;
}

static int osd_iit_iget(struct osd_thread_info *info, struct osd_device *dev,
			struct lu_fid *fid, struct osd_inode_id *lid, __u32 pos,
			struct super_block *sb, bool scrub)
{
	struct inode *inode;
	int	      rc;
	ENTRY;

	osd_id_gen(lid, pos, OSD_OII_NOGEN);
	inode = osd_iget(info, dev, lid);
	if (IS_ERR(inode)) {
		rc = PTR_ERR(inode);
		/* The inode may be removed after bitmap searching, or the
		 * file is new created without inode initialized yet. */
		if (rc == -ENOENT || rc == -ESTALE)
			RETURN(SCRUB_NEXT_CONTINUE);

		CERROR("%.16s: fail to read inode, ino# = %u, rc = %d\n",
		       LDISKFS_SB(sb)->s_es->s_volume_name, pos, rc);
		RETURN(rc);
	}

	/* If the inode has no OI mapping, then it is special locally used,
	 * should be invisible to OI scrub or up layer LFSCK. */
	if (ldiskfs_test_inode_state(inode, LDISKFS_STATE_LUSTRE_NO_OI))
		GOTO(put, rc = SCRUB_NEXT_CONTINUE);

	if (scrub &&
	    ldiskfs_test_inode_state(inode, LDISKFS_STATE_LUSTRE_NOSCRUB)) {
		/* Only skip it for the first OI scrub accessing. */
		ldiskfs_clear_inode_state(inode, LDISKFS_STATE_LUSTRE_NOSCRUB);
		GOTO(put, rc = SCRUB_NEXT_NOSCRUB);
	}

	rc = osd_scrub_get_fid(info, dev, inode, fid, scrub);

	GOTO(put, rc);

put:
	iput(inode);
	return rc;
}

static int osd_scrub_next(struct osd_thread_info *info, struct osd_device *dev,
			  struct osd_iit_param *param,
			  struct osd_idmap_cache **oic, int noslot)
{
	struct osd_scrub     *scrub  = &dev->od_scrub;
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct lu_fid	     *fid;
	struct osd_inode_id  *lid;
	int		      rc;

	if (OBD_FAIL_CHECK(OBD_FAIL_OSD_SCRUB_DELAY) && cfs_fail_val > 0) {
		struct l_wait_info lwi;

		lwi = LWI_TIMEOUT(cfs_time_seconds(cfs_fail_val), NULL, NULL);
		l_wait_event(thread->t_ctl_waitq,
			     !cfs_list_empty(&scrub->os_inconsistent_items) ||
			     !thread_is_running(thread),
			     &lwi);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_OSD_SCRUB_CRASH)) {
		spin_lock(&scrub->os_lock);
		thread_set_flags(thread, SVC_STOPPING);
		spin_unlock(&scrub->os_lock);
		return SCRUB_NEXT_CRASH;
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_OSD_SCRUB_FATAL))
		return SCRUB_NEXT_FATAL;

	if (unlikely(!thread_is_running(thread)))
		return SCRUB_NEXT_EXIT;

	if (!cfs_list_empty(&scrub->os_inconsistent_items)) {
		struct osd_inconsistent_item *oii;

		oii = cfs_list_entry(scrub->os_inconsistent_items.next,
				     struct osd_inconsistent_item, oii_list);
		*oic = &oii->oii_cache;
		scrub->os_in_prior = 1;
		return 0;
	}

	if (noslot != 0)
		return SCRUB_NEXT_WAIT;

	rc = osd_iit_next(param, &scrub->os_pos_current);
	if (rc != 0)
		return rc;

	*oic = &scrub->os_oic;
	fid = &(*oic)->oic_fid;
	lid = &(*oic)->oic_lid;
	rc = osd_iit_iget(info, dev, fid, lid,
			  scrub->os_pos_current, param->sb, true);
	return rc;
}

static int osd_preload_next(struct osd_thread_info *info,
			    struct osd_device *dev, struct osd_iit_param *param,
			    struct osd_idmap_cache **oic, int noslot)
{
	struct osd_otable_cache *ooc    = &dev->od_otable_it->ooi_cache;
	struct osd_scrub	*scrub;
	struct ptlrpc_thread	*thread;
	int			 rc;

	rc = osd_iit_next(param, &ooc->ooc_pos_preload);
	if (rc != 0)
		return rc;

	scrub = &dev->od_scrub;
	thread = &scrub->os_thread;
	if (thread_is_running(thread) &&
	    ooc->ooc_pos_preload >= scrub->os_pos_current)
		return SCRUB_NEXT_EXIT;

	rc = osd_iit_iget(info, dev,
			  &ooc->ooc_cache[ooc->ooc_producer_idx].oic_fid,
			  &ooc->ooc_cache[ooc->ooc_producer_idx].oic_lid,
			  ooc->ooc_pos_preload, param->sb, false);
	/* If succeed, it needs to move forward; otherwise up layer LFSCK may
	 * ignore the failure, so it still need to skip the inode next time. */
	ooc->ooc_pos_preload = param->gbase + ++(param->offset);
	return rc;
}

static inline int
osd_scrub_wakeup(struct osd_scrub *scrub, struct osd_otable_it *it)
{
	spin_lock(&scrub->os_lock);
	if (osd_scrub_has_window(scrub, &it->ooi_cache) ||
	    !cfs_list_empty(&scrub->os_inconsistent_items) ||
	    it->ooi_waiting || !thread_is_running(&scrub->os_thread))
		scrub->os_waiting = 0;
	else
		scrub->os_waiting = 1;
	spin_unlock(&scrub->os_lock);

	return !scrub->os_waiting;
}

static int osd_scrub_exec(struct osd_thread_info *info, struct osd_device *dev,
			  struct osd_iit_param *param,
			  struct osd_idmap_cache *oic, int *noslot, int rc)
{
	struct l_wait_info	 lwi    = { 0 };
	struct osd_scrub	*scrub  = &dev->od_scrub;
	struct scrub_file	*sf     = &scrub->os_file;
	struct ptlrpc_thread	*thread = &scrub->os_thread;
	struct osd_otable_it	*it     = dev->od_otable_it;
	struct osd_otable_cache *ooc    = it ? &it->ooi_cache : NULL;

	switch (rc) {
	case SCRUB_NEXT_CONTINUE:
		goto next;
	case SCRUB_NEXT_WAIT:
		goto wait;
	case SCRUB_NEXT_NOSCRUB:
		down_write(&scrub->os_rwsem);
		scrub->os_new_checked++;
		sf->sf_items_noscrub++;
		up_write(&scrub->os_rwsem);
		goto next;
	}

	rc = osd_scrub_check_update(info, dev, oic, rc);
	if (rc != 0)
		return rc;

	rc = osd_scrub_checkpoint(scrub);
	if (rc != 0) {
		CERROR("%.16s: fail to checkpoint, pos = %u, rc = %d\n",
		       LDISKFS_SB(param->sb)->s_es->s_volume_name,
		       scrub->os_pos_current, rc);
		/* Continue, as long as the scrub itself can go ahead. */
	}

	if (scrub->os_in_prior) {
		scrub->os_in_prior = 0;
		return 0;
	}

next:
	scrub->os_pos_current = param->gbase + ++(param->offset);

wait:
	if (it != NULL && it->ooi_waiting && ooc != NULL &&
	    ooc->ooc_pos_preload < scrub->os_pos_current) {
		spin_lock(&scrub->os_lock);
		it->ooi_waiting = 0;
		wake_up_all(&thread->t_ctl_waitq);
		spin_unlock(&scrub->os_lock);
	}

	if (scrub->os_full_speed || rc == SCRUB_NEXT_CONTINUE)
		return 0;

	if (osd_scrub_has_window(scrub, ooc)) {
		*noslot = 0;
		return 0;
	}

	l_wait_event(thread->t_ctl_waitq,
		     osd_scrub_wakeup(scrub, it),
		     &lwi);

	if (osd_scrub_has_window(scrub, ooc))
		*noslot = 0;
	else
		*noslot = 1;
	return 0;
}

static int osd_preload_exec(struct osd_thread_info *info,
			    struct osd_device *dev, struct osd_iit_param *param,
			    struct osd_idmap_cache *oic, int *noslot, int rc)
{
	struct osd_otable_cache *ooc = &dev->od_otable_it->ooi_cache;

	if (rc == 0) {
		ooc->ooc_cached_items++;
		ooc->ooc_producer_idx = (ooc->ooc_producer_idx + 1) &
					~OSD_OTABLE_IT_CACHE_MASK;
	}
	return rc > 0 ? 0 : rc;
}

#define SCRUB_IT_ALL	1
#define SCRUB_IT_CRASH	2

static int osd_inode_iteration(struct osd_thread_info *info,
			       struct osd_device *dev, __u32 max, bool preload)
{
	osd_iit_next_policy   next;
	osd_iit_exec_policy   exec;
	__u32		     *pos;
	__u32		     *count;
	struct osd_iit_param  param;
	__u32		      limit;
	int		      noslot = 0;
	int		      rc;
	ENTRY;

	if (!preload) {
		struct osd_scrub *scrub = &dev->od_scrub;

		next = osd_scrub_next;
		exec = osd_scrub_exec;
		pos = &scrub->os_pos_current;
		count = &scrub->os_new_checked;
	} else {
		struct osd_otable_cache *ooc = &dev->od_otable_it->ooi_cache;

		next = osd_preload_next;
		exec = osd_preload_exec;
		pos = &ooc->ooc_pos_preload;
		count = &ooc->ooc_cached_items;
	}
	param.sb = osd_sb(dev);
	limit = le32_to_cpu(LDISKFS_SB(param.sb)->s_es->s_inodes_count);

	while (*pos <= limit && *count < max) {
		struct osd_idmap_cache *oic = NULL;

		param.bg = (*pos - 1) / LDISKFS_INODES_PER_GROUP(param.sb);
		param.offset = (*pos - 1) % LDISKFS_INODES_PER_GROUP(param.sb);
		param.gbase = 1 + param.bg * LDISKFS_INODES_PER_GROUP(param.sb);
		param.bitmap = ldiskfs_read_inode_bitmap(param.sb, param.bg);
		if (param.bitmap == NULL) {
			CERROR("%.16s: fail to read bitmap for %u, "
			       "scrub will stop, urgent mode\n",
			       LDISKFS_SB(param.sb)->s_es->s_volume_name,
			       (__u32)param.bg);
			RETURN(-EIO);
		}

		while (param.offset < LDISKFS_INODES_PER_GROUP(param.sb) &&
		       *count < max) {
			rc = next(info, dev, &param, &oic, noslot);
			switch (rc) {
			case SCRUB_NEXT_BREAK:
				goto next_group;
			case SCRUB_NEXT_EXIT:
				brelse(param.bitmap);
				RETURN(0);
			case SCRUB_NEXT_CRASH:
				brelse(param.bitmap);
				RETURN(SCRUB_IT_CRASH);
			case SCRUB_NEXT_FATAL:
				brelse(param.bitmap);
				RETURN(-EINVAL);
			}

			rc = exec(info, dev, &param, oic, &noslot, rc);
			if (rc != 0) {
				brelse(param.bitmap);
				RETURN(rc);
			}
		}

next_group:
		brelse(param.bitmap);
	}

	if (*pos > limit)
		RETURN(SCRUB_IT_ALL);
	RETURN(0);
}

static int osd_otable_it_preload(const struct lu_env *env,
				 struct osd_otable_it *it)
{
	struct osd_device       *dev   = it->ooi_dev;
	struct osd_scrub	*scrub = &dev->od_scrub;
	struct osd_otable_cache *ooc   = &it->ooi_cache;
	int			 rc;
	ENTRY;

	rc = osd_inode_iteration(osd_oti_get(env), dev,
				 OSD_OTABLE_IT_CACHE_SIZE, true);
	if (rc == SCRUB_IT_ALL)
		it->ooi_all_cached = 1;

	CDEBUG(D_LFSCK, "OSD pre-loaded: max = %u, preload = %u, rc = %d\n",
	       le32_to_cpu(LDISKFS_SB(osd_sb(dev))->s_es->s_inodes_count),
	       ooc->ooc_pos_preload, rc);

	if (scrub->os_waiting && osd_scrub_has_window(scrub, ooc)) {
		spin_lock(&scrub->os_lock);
		scrub->os_waiting = 0;
		wake_up_all(&scrub->os_thread.t_ctl_waitq);
		spin_unlock(&scrub->os_lock);
	}

	RETURN(rc < 0 ? rc : ooc->ooc_cached_items);
}

static int osd_scrub_main(void *args)
{
	struct lu_env	      env;
	struct osd_device    *dev    = (struct osd_device *)args;
	struct osd_scrub     *scrub  = &dev->od_scrub;
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct super_block   *sb     = osd_sb(dev);
	int		      rc;
	ENTRY;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0) {
		CERROR("%.16s: OI scrub, fail to init env, rc = %d\n",
		       LDISKFS_SB(sb)->s_es->s_volume_name, rc);
		GOTO(noenv, rc);
	}

	rc = osd_scrub_prep(dev);
	if (rc != 0) {
		CERROR("%.16s: OI scrub, fail to scrub prep, rc = %d\n",
		       LDISKFS_SB(sb)->s_es->s_volume_name, rc);
		GOTO(out, rc);
	}

	if (!scrub->os_full_speed) {
		struct l_wait_info lwi = { 0 };
		struct osd_otable_it *it = dev->od_otable_it;
		struct osd_otable_cache *ooc = &it->ooi_cache;

		l_wait_event(thread->t_ctl_waitq,
			     it->ooi_user_ready || !thread_is_running(thread),
			     &lwi);
		if (unlikely(!thread_is_running(thread)))
			GOTO(post, rc = 0);

		scrub->os_pos_current = ooc->ooc_pos_preload;
	}

	CDEBUG(D_LFSCK, "OI scrub: flags = 0x%x, pos = %u\n",
	       scrub->os_start_flags, scrub->os_pos_current);

	rc = osd_inode_iteration(osd_oti_get(&env), dev, ~0U, false);
	if (unlikely(rc == SCRUB_IT_CRASH))
		GOTO(out, rc = -EINVAL);
	GOTO(post, rc);

post:
	osd_scrub_post(scrub, rc);
	CDEBUG(D_LFSCK, "OI scrub: stop, rc = %d, pos = %u\n",
	       rc, scrub->os_pos_current);

out:
	while (!cfs_list_empty(&scrub->os_inconsistent_items)) {
		struct osd_inconsistent_item *oii;

		oii = cfs_list_entry(scrub->os_inconsistent_items.next,
				     struct osd_inconsistent_item, oii_list);
		cfs_list_del_init(&oii->oii_list);
		OBD_FREE_PTR(oii);
	}
	lu_env_fini(&env);

noenv:
	spin_lock(&scrub->os_lock);
	thread_set_flags(thread, SVC_STOPPED);
	wake_up_all(&thread->t_ctl_waitq);
	spin_unlock(&scrub->os_lock);
	return rc;
}

/* initial OI scrub */

typedef int (*scandir_t)(struct osd_thread_info *, struct osd_device *,
			 struct dentry *, filldir_t filldir);

static int osd_ios_varfid_fill(void *buf, const char *name, int namelen,
			       loff_t offset, __u64 ino, unsigned d_type);
static int osd_ios_lf_fill(void *buf, const char *name, int namelen,
			   loff_t offset, __u64 ino, unsigned d_type);
static int osd_ios_dl_fill(void *buf, const char *name, int namelen,
			   loff_t offset, __u64 ino, unsigned d_type);

static int
osd_ios_general_scan(struct osd_thread_info *info, struct osd_device *dev,
		     struct dentry *dentry, filldir_t filldir);
static int
osd_ios_ROOT_scan(struct osd_thread_info *info, struct osd_device *dev,
		  struct dentry *dentry, filldir_t filldir);

static int
osd_ios_OBJECTS_scan(struct osd_thread_info *info, struct osd_device *dev,
		     struct dentry *dentry, filldir_t filldir);

enum osd_lf_flags {
	OLF_SCAN_SUBITEMS	= 0x0001,
	OLF_HIDE_FID		= 0x0002,
	OLF_SHOW_NAME		= 0x0004,
	OLF_NO_OI		= 0x0008,
};

struct osd_lf_map {
	char		*olm_name;
	struct lu_fid	 olm_fid;
	__u16		 olm_flags;
	scandir_t	 olm_scandir;
	filldir_t	 olm_filldir;
};

/* Add the new introduced local files in the list in the future. */
static const struct osd_lf_map osd_lf_maps[] = {
	/* CATALOGS */
	{ CATLIST, { FID_SEQ_LOCAL_FILE, LLOG_CATALOGS_OID, 0 }, OLF_SHOW_NAME,
		NULL, NULL },

	/* CONFIGS */
	{ MOUNT_CONFIGS_DIR, { FID_SEQ_LOCAL_FILE, MGS_CONFIGS_OID, 0 },
		OLF_SCAN_SUBITEMS, osd_ios_general_scan,
		osd_ios_varfid_fill },

	/* NIDTBL_VERSIONS */
	{ MGS_NIDTBL_DIR, { 0, 0, 0 }, OLF_SCAN_SUBITEMS,
		osd_ios_general_scan, osd_ios_varfid_fill },

	/* PENDING */
	{ "PENDING", { 0, 0, 0 }, 0, NULL, NULL },

	/* ROOT */
	{ "ROOT", { FID_SEQ_ROOT, 1, 0 },
		OLF_SCAN_SUBITEMS | OLF_HIDE_FID, osd_ios_ROOT_scan, NULL },

	/* changelog_catalog */
	{ CHANGELOG_CATALOG, { 0, 0, 0 }, 0, NULL, NULL },

	/* changelog_users */
	{ CHANGELOG_USERS, { 0, 0, 0 }, 0, NULL, NULL },

	/* fld */
	{ "fld", { FID_SEQ_LOCAL_FILE, FLD_INDEX_OID, 0 }, OLF_SHOW_NAME,
		NULL, NULL },

	/* last_rcvd */
	{ LAST_RCVD, { FID_SEQ_LOCAL_FILE, LAST_RECV_OID, 0 }, OLF_SHOW_NAME,
		NULL, NULL },

	/* lfsck_bookmark */
	{ "lfsck_bookmark", { 0, 0, 0 }, 0, NULL, NULL },

	/* lov_objid */
	{ LOV_OBJID, { FID_SEQ_LOCAL_FILE, MDD_LOV_OBJ_OID, 0 }, OLF_SHOW_NAME,
		NULL, NULL },

	/* lov_objseq */
	{ LOV_OBJSEQ, { FID_SEQ_LOCAL_FILE, MDD_LOV_OBJ_OSEQ, 0 },
		OLF_SHOW_NAME, NULL, NULL },

	/* quota_master */
	{ QMT_DIR, { 0, 0, 0 }, OLF_SCAN_SUBITEMS,
		osd_ios_general_scan, osd_ios_varfid_fill },

	/* quota_slave */
	{ QSD_DIR, { 0, 0, 0 }, OLF_SCAN_SUBITEMS,
		osd_ios_general_scan, osd_ios_varfid_fill },

	/* seq_ctl */
	{ "seq_ctl", { FID_SEQ_LOCAL_FILE, FID_SEQ_CTL_OID, 0 },
		OLF_SHOW_NAME, NULL, NULL },

	/* seq_srv */
	{ "seq_srv", { FID_SEQ_LOCAL_FILE, FID_SEQ_SRV_OID, 0 },
		OLF_SHOW_NAME, NULL, NULL },

	/* health_check */
	{ HEALTH_CHECK, { FID_SEQ_LOCAL_FILE, OFD_HEALTH_CHECK_OID, 0 },
		OLF_SHOW_NAME, NULL, NULL },

	/* lfsck_namespace */
	{ "lfsck_namespace", { 0, 0, 0 }, 0, NULL, NULL },

	/* OBJECTS, upgrade from old device */
	{ OBJECTS, { 0, 0, 0 }, OLF_SCAN_SUBITEMS, osd_ios_OBJECTS_scan, NULL },

	/* lquota_v2.user, upgrade from old device */
	{ "lquota_v2.user", { 0, 0, 0 }, 0, NULL, NULL },

	/* lquota_v2.group, upgrade from old device */
	{ "lquota_v2.group", { 0, 0, 0 }, 0, NULL, NULL },

	/* LAST_GROUP, upgrade from old device */
	{ "LAST_GROUP", { FID_SEQ_LOCAL_FILE, OFD_LAST_GROUP_OID, 0 },
		OLF_SHOW_NAME, NULL, NULL },

	/* lost+found */
	{ "lost+found", { 0, 0, 0 }, OLF_SCAN_SUBITEMS | OLF_NO_OI,
		osd_ios_general_scan, osd_ios_lf_fill },

	{ NULL, { 0, 0, 0 }, 0, NULL, NULL }
};

/* Add the new introduced files under .lustre/ in the list in the future. */
static const struct osd_lf_map osd_dl_maps[] = {
	/* .lustre/fid */
	{ "fid", { FID_SEQ_DOT_LUSTRE, FID_OID_DOT_LUSTRE_OBF, 0 }, 0,
		NULL, NULL },

	{ NULL, { 0, 0, 0 }, 0, NULL, NULL }
};

struct osd_ios_item {
	cfs_list_t	 oii_list;
	struct dentry	*oii_dentry;
	scandir_t	 oii_scandir;
	filldir_t	 oii_filldir;
};

struct osd_ios_filldir_buf {
	struct osd_thread_info	*oifb_info;
	struct osd_device	*oifb_dev;
	struct dentry		*oifb_dentry;
};

static inline struct dentry *
osd_ios_lookup_one_len(const char *name, struct dentry *parent, int namelen)
{
	struct dentry *dentry;

	CDEBUG(D_LFSCK, "init lookup one: parent = %.*s, name = %.*s\n",
	       parent->d_name.len, parent->d_name.name, namelen, name);

	dentry = ll_lookup_one_len(name, parent, namelen);
	if (!IS_ERR(dentry) && dentry->d_inode == NULL) {
		dput(dentry);
		return ERR_PTR(-ENOENT);
	}

	return dentry;
}

static int
osd_ios_new_item(struct osd_device *dev, struct dentry *dentry,
		 scandir_t scandir, filldir_t filldir)
{
	struct osd_ios_item *item;
	ENTRY;

	OBD_ALLOC_PTR(item);
	if (item == NULL)
		RETURN(-ENOMEM);

	CFS_INIT_LIST_HEAD(&item->oii_list);
	item->oii_dentry = dget(dentry);
	item->oii_scandir = scandir;
	item->oii_filldir = filldir;
	cfs_list_add_tail(&item->oii_list, &dev->od_ios_list);

	RETURN(0);
}

/**
 * osd_ios_scan_one() - check/fix LMA FID and OI entry for one inode
 *
 * The passed \a inode's \a fid is verified against the LMA FID. If the \a fid
 * is NULL or is empty the IGIF FID is used. The FID is verified in the OI to
 * reference the inode, or fixed if it is missing or references another inode.
 */
static int
osd_ios_scan_one(struct osd_thread_info *info, struct osd_device *dev,
		 struct inode *inode, const struct lu_fid *fid, int flags)
{
	struct lustre_mdt_attrs	*lma	= &info->oti_mdt_attrs;
	struct osd_inode_id	*id	= &info->oti_id;
	struct osd_inode_id	*id2	= &info->oti_id2;
	struct osd_scrub	*scrub  = &dev->od_scrub;
	struct scrub_file	*sf     = &scrub->os_file;
	struct lu_fid		 tfid;
	int			 rc;
	ENTRY;

	CDEBUG(D_LFSCK, "init scan one: ino = %ld\n", inode->i_ino);

	rc = osd_get_lma(info, inode, &info->oti_obj_dentry, lma);
	if (rc != 0 && rc != -ENODATA)
		RETURN(rc);

	osd_id_gen(id, inode->i_ino, inode->i_generation);
	if (rc == -ENODATA) {
		if (fid == NULL || fid_is_zero(fid) || flags & OLF_HIDE_FID)
			lu_igif_build(&tfid, inode->i_ino, inode->i_generation);
		else
			tfid = *fid;
		rc = osd_ea_fid_set(info, inode, &tfid, 0, 0);
		if (rc != 0)
			RETURN(rc);
	} else {
		if (lma->lma_compat & LMAC_NOT_IN_OI)
			RETURN(0);

		tfid = lma->lma_self_fid;
	}

	rc = osd_oi_lookup(info, dev, &tfid, id2, 0);
	if (rc != 0) {
		if (rc != -ENOENT)
			RETURN(rc);

		rc = osd_scrub_refresh_mapping(info, dev, &tfid, id,
					       DTO_INDEX_INSERT, true, 0);
		if (rc > 0)
			rc = 0;

		RETURN(rc);
	}

	if (osd_id_eq_strict(id, id2))
		RETURN(0);

	if (!(sf->sf_flags & SF_INCONSISTENT)) {
		osd_scrub_file_reset(scrub,
				     LDISKFS_SB(osd_sb(dev))->s_es->s_uuid,
				     SF_INCONSISTENT);
		rc = osd_scrub_file_store(scrub);
		if (rc != 0)
			RETURN(rc);
	}

	rc = osd_scrub_refresh_mapping(info, dev, &tfid, id,
				       DTO_INDEX_UPDATE, true, 0);
	if (rc > 0)
		rc = 0;

	RETURN(rc);
}

/**
 * It scans the /lost+found, and for the OST-object (with filter_fid
 * or filter_fid_old), move them back to its proper /O/<seq>/d<x>.
 */
static int osd_ios_lf_fill(void *buf, const char *name, int namelen,
			   loff_t offset, __u64 ino, unsigned d_type)
{
	struct osd_ios_filldir_buf *fill_buf = buf;
	struct osd_thread_info     *info     = fill_buf->oifb_info;
	struct osd_device	   *dev      = fill_buf->oifb_dev;
	struct lu_fid		   *fid      = &info->oti_fid;
	struct osd_scrub	   *scrub    = &dev->od_scrub;
	struct dentry		   *parent   = fill_buf->oifb_dentry;
	struct dentry		   *child;
	struct inode		   *dir      = parent->d_inode;
	struct inode		   *inode;
	int			    rc;
	ENTRY;

	/* skip any '.' started names */
	if (name[0] == '.')
		RETURN(0);

	scrub->os_lf_scanned++;
	child = osd_ios_lookup_one_len(name, parent, namelen);
	if (IS_ERR(child)) {
		CWARN("%s: cannot lookup child '%.*s': rc = %d\n",
		      osd_name(dev), namelen, name, (int)PTR_ERR(child));
		RETURN(0);
	}

	inode = child->d_inode;
	if (S_ISDIR(inode->i_mode)) {
		rc = osd_ios_new_item(dev, child, osd_ios_general_scan,
				      osd_ios_lf_fill);
		if (rc != 0)
			CWARN("%s: cannot add child '%.*s': rc = %d\n",
			      osd_name(dev), namelen, name, rc);
		GOTO(put, rc);
	}

	if (!S_ISREG(inode->i_mode))
		GOTO(put, rc = 0);

	rc = osd_scrub_get_fid(info, dev, inode, fid, true);
	if (rc == SCRUB_NEXT_OSTOBJ || rc == SCRUB_NEXT_OSTOBJ_OLD) {
		rc = osd_obj_map_recover(info, dev, dir, child, fid);
		if (rc == 0) {
			CDEBUG(D_LFSCK, "recovered '%.*s' ["DFID"] from "
			       "/lost+found.\n", namelen, name, PFID(fid));
			scrub->os_lf_repaired++;
		} else {
			CWARN("%s: cannot rename for '%.*s' "DFID": rc = %d\n",
			      osd_name(dev), namelen, name, PFID(fid), rc);
		}
	}

	/* XXX: For MDT-objects, we can move them from /lost+found to namespace
	 * 	visible place, such as the /ROOT/.lustre/lost+found, then LFSCK
	 * 	can process them in furtuer. */

	GOTO(put, rc);

put:
	if (rc < 0)
		scrub->os_lf_failed++;
	dput(child);
	/* skip the failure to make the scanning to continue. */
	return 0;
}

static int osd_ios_varfid_fill(void *buf, const char *name, int namelen,
			       loff_t offset, __u64 ino, unsigned d_type)
{
	struct osd_ios_filldir_buf *fill_buf = buf;
	struct osd_device	   *dev      = fill_buf->oifb_dev;
	struct dentry		   *child;
	int			    rc;
	ENTRY;

	/* skip any '.' started names */
	if (name[0] == '.')
		RETURN(0);

	child = osd_ios_lookup_one_len(name, fill_buf->oifb_dentry, namelen);
	if (IS_ERR(child))
		RETURN(PTR_ERR(child));

	rc = osd_ios_scan_one(fill_buf->oifb_info, dev, child->d_inode,
			      NULL, 0);
	if (rc == 0 && S_ISDIR(child->d_inode->i_mode))
		rc = osd_ios_new_item(dev, child, osd_ios_general_scan,
				      osd_ios_varfid_fill);
	dput(child);

	RETURN(rc);
}

static int osd_ios_dl_fill(void *buf, const char *name, int namelen,
			   loff_t offset, __u64 ino, unsigned d_type)
{
	struct osd_ios_filldir_buf *fill_buf = buf;
	struct osd_device	   *dev      = fill_buf->oifb_dev;
	const struct osd_lf_map    *map;
	struct dentry		   *child;
	int			    rc       = 0;
	ENTRY;

	/* skip any '.' started names */
	if (name[0] == '.')
		RETURN(0);

	for (map = osd_dl_maps; map->olm_name != NULL; map++) {
		if (strlen(map->olm_name) != namelen)
			continue;

		if (strncmp(map->olm_name, name, namelen) == 0)
			break;
	}

	if (map->olm_name == NULL)
		RETURN(0);

	child = osd_ios_lookup_one_len(name, fill_buf->oifb_dentry, namelen);
	if (IS_ERR(child))
		RETURN(PTR_ERR(child));

	rc = osd_ios_scan_one(fill_buf->oifb_info, dev, child->d_inode,
			      &map->olm_fid, map->olm_flags);
	dput(child);

	RETURN(rc);
}

static int osd_ios_root_fill(void *buf, const char *name, int namelen,
			     loff_t offset, __u64 ino, unsigned d_type)
{
	struct osd_ios_filldir_buf *fill_buf = buf;
	struct osd_device	   *dev      = fill_buf->oifb_dev;
	const struct osd_lf_map    *map;
	struct dentry		   *child;
	int			    rc       = 0;
	ENTRY;

	/* skip any '.' started names */
	if (name[0] == '.')
		RETURN(0);

	for (map = osd_lf_maps; map->olm_name != NULL; map++) {
		if (strlen(map->olm_name) != namelen)
			continue;

		if (strncmp(map->olm_name, name, namelen) == 0)
			break;
	}

	if (map->olm_name == NULL)
		RETURN(0);

	child = osd_ios_lookup_one_len(name, fill_buf->oifb_dentry, namelen);
	if (IS_ERR(child))
		RETURN(PTR_ERR(child));

	if (!(map->olm_flags & OLF_NO_OI))
		rc = osd_ios_scan_one(fill_buf->oifb_info, dev, child->d_inode,
				      &map->olm_fid, map->olm_flags);
	if (rc == 0 && map->olm_flags & OLF_SCAN_SUBITEMS)
		rc = osd_ios_new_item(dev, child, map->olm_scandir,
				      map->olm_filldir);
	dput(child);

	RETURN(rc);
}

static int
osd_ios_general_scan(struct osd_thread_info *info, struct osd_device *dev,
		     struct dentry *dentry, filldir_t filldir)
{
	struct osd_ios_filldir_buf    buf   = { info, dev, dentry };
	struct file		     *filp  = &info->oti_it_ea.oie_file;
	struct inode		     *inode = dentry->d_inode;
	const struct file_operations *fops  = inode->i_fop;
	int			      rc;
	ENTRY;

	LASSERT(filldir != NULL);

	filp->f_pos = 0;
	filp->f_dentry = dentry;
	filp->f_mode = FMODE_64BITHASH;
	filp->f_mapping = inode->i_mapping;
	filp->f_op = fops;
	filp->private_data = NULL;

	rc = fops->readdir(filp, &buf, filldir);
	fops->release(inode, filp);

	RETURN(rc);
}

static int
osd_ios_ROOT_scan(struct osd_thread_info *info, struct osd_device *dev,
		  struct dentry *dentry, filldir_t filldir)
{
	struct osd_scrub  *scrub  = &dev->od_scrub;
	struct scrub_file *sf     = &scrub->os_file;
	struct dentry	  *child;
	int		   rc;
	ENTRY;

	/* It is existing MDT0 device. We only allow the case of object without
	 * LMA to happen on the MDT0, which is usually for old 1.8 MDT. Then we
	 * can generate IGIF mode FID for the object and related OI mapping. If
	 * it is on other MDTs, then becuase file-level backup/restore, related
	 * OI mapping may be invalid already, we do not know which is the right
	 * FID for the object. We only allow IGIF objects to reside on the MDT0.
	 *
	 * XXX: For the case of object on non-MDT0 device with neither LMA nor
	 *	"fid" xattr, then something crashed. We cannot re-generate the
	 *	FID directly, instead, the OI scrub will scan the OI structure
	 *	and try to re-generate the LMA from the OI mapping. But if the
	 *	OI mapping crashed or lost also, then we have to give up under
	 *	double failure cases. */
	scrub->os_convert_igif = 1;
	child = osd_ios_lookup_one_len(dot_lustre_name, dentry,
				       strlen(dot_lustre_name));
	if (IS_ERR(child)) {
		rc = PTR_ERR(child);
		if (rc == -ENOENT) {
			/* It is 1.8 MDT device. */
			if (!(sf->sf_flags & SF_UPGRADE)) {
				osd_scrub_file_reset(scrub,
					LDISKFS_SB(osd_sb(dev))->s_es->s_uuid,
					SF_UPGRADE);
				sf->sf_internal_flags &= ~SIF_NO_HANDLE_OLD_FID;
				rc = osd_scrub_file_store(scrub);
			} else {
				rc = 0;
			}
		}
	} else {
		/* For lustre-2.x (x <= 3), the ".lustre" has NO FID-in-LMA,
		 * so the client will get IGIF for the ".lustre" object when
		 * the MDT restart.
		 *
		 * From the OI scrub view, when the MDT upgrade to Lustre-2.4,
		 * it does not know whether there are some old clients cached
		 * the ".lustre" IGIF during the upgrading. Two choices:
		 *
		 * 1) Generate IGIF-in-LMA and IGIF-in-OI for the ".lustre".
		 *    It will allow the old connected clients to access the
		 *    ".lustre" with cached IGIF. But it will cause others
		 *    on the MDT failed to check "fid_is_dot_lustre()".
		 *
		 * 2) Use fixed FID {FID_SEQ_DOT_LUSTRE, FID_OID_DOT_LUSTRE, 0}
		 *    for ".lustre" in spite of whether there are some clients
		 *    cached the ".lustre" IGIF or not. It enables the check
		 *    "fid_is_dot_lustre()" on the MDT, although it will cause
		 *    that the old connected clients cannot access the ".lustre"
		 *    with the cached IGIF.
		 *
		 * Usually, it is rare case for the old connected clients
		 * to access the ".lustre" with cached IGIF. So we prefer
		 * to the solution 2). */
		rc = osd_ios_scan_one(info, dev, child->d_inode,
				      &LU_DOT_LUSTRE_FID, 0);
		if (rc == 0)
			rc = osd_ios_new_item(dev, child, osd_ios_general_scan,
					      osd_ios_dl_fill);
		dput(child);
	}

	RETURN(rc);
}

static int
osd_ios_OBJECTS_scan(struct osd_thread_info *info, struct osd_device *dev,
		     struct dentry *dentry, filldir_t filldir)
{
	struct osd_scrub  *scrub  = &dev->od_scrub;
	struct scrub_file *sf     = &scrub->os_file;
	struct dentry	  *child;
	int		   rc;
	ENTRY;

	if (unlikely(sf->sf_internal_flags & SIF_NO_HANDLE_OLD_FID)) {
		sf->sf_internal_flags &= ~SIF_NO_HANDLE_OLD_FID;
		rc = osd_scrub_file_store(scrub);
		if (rc != 0)
			RETURN(rc);
	}

	child = osd_ios_lookup_one_len(ADMIN_USR, dentry, strlen(ADMIN_USR));
	if (!IS_ERR(child)) {
		rc = osd_ios_scan_one(info, dev, child->d_inode, NULL, 0);
		dput(child);
	} else {
		rc = PTR_ERR(child);
	}

	if (rc != 0 && rc != -ENOENT)
		RETURN(rc);

	child = osd_ios_lookup_one_len(ADMIN_GRP, dentry, strlen(ADMIN_GRP));
	if (!IS_ERR(child)) {
		rc = osd_ios_scan_one(info, dev, child->d_inode, NULL, 0);
		dput(child);
	} else {
		rc = PTR_ERR(child);
	}

	if (rc == -ENOENT)
		rc = 0;

	RETURN(rc);
}

static int osd_initial_OI_scrub(struct osd_thread_info *info,
				struct osd_device *dev)
{
	struct osd_ios_item	*item    = NULL;
	scandir_t		 scandir = osd_ios_general_scan;
	filldir_t		 filldir = osd_ios_root_fill;
	struct dentry		*dentry  = osd_sb(dev)->s_root;
	const struct osd_lf_map *map     = osd_lf_maps;
	int			 rc;
	ENTRY;

	/* Lookup IGIF in OI by force for initial OI scrub. */
	dev->od_igif_inoi = 1;

	while (1) {
		rc = scandir(info, dev, dentry, filldir);
		if (item != NULL) {
			dput(item->oii_dentry);
			OBD_FREE_PTR(item);
		}

		if (rc != 0)
			break;

		if (cfs_list_empty(&dev->od_ios_list))
			break;

		item = cfs_list_entry(dev->od_ios_list.next,
				      struct osd_ios_item, oii_list);
		cfs_list_del_init(&item->oii_list);

		LASSERT(item->oii_scandir != NULL);
		scandir = item->oii_scandir;
		filldir = item->oii_filldir;
		dentry = item->oii_dentry;
	}

	while (!cfs_list_empty(&dev->od_ios_list)) {
		item = cfs_list_entry(dev->od_ios_list.next,
				      struct osd_ios_item, oii_list);
		cfs_list_del_init(&item->oii_list);
		dput(item->oii_dentry);
		OBD_FREE_PTR(item);
	}

	if (rc != 0)
		RETURN(rc);

	/* There maybe the case that the object has been removed, but its OI
	 * mapping is still in the OI file, such as the "CATALOGS" after MDT
	 * file-level backup/restore. So here cleanup the stale OI mappings. */
	while (map->olm_name != NULL) {
		struct dentry *child;

		if (fid_is_zero(&map->olm_fid)) {
			map++;
			continue;
		}

		child = osd_ios_lookup_one_len(map->olm_name,
					       osd_sb(dev)->s_root,
					       strlen(map->olm_name));
		if (!IS_ERR(child))
			dput(child);
		else if (PTR_ERR(child) == -ENOENT)
			osd_scrub_refresh_mapping(info, dev, &map->olm_fid,
						  NULL, DTO_INDEX_DELETE,
						  true, 0);
		map++;
	}

	RETURN(0);
}

char *osd_lf_fid2name(const struct lu_fid *fid)
{
	const struct osd_lf_map *map = osd_lf_maps;

	while (map->olm_name != NULL) {
		if (!lu_fid_eq(fid, &map->olm_fid)) {
			map++;
			continue;
		}

		if (map->olm_flags & OLF_SHOW_NAME)
			return map->olm_name;
		else
			return "";
	}

	return NULL;
}

/* OI scrub start/stop */

static int do_osd_scrub_start(struct osd_device *dev, __u32 flags)
{
	struct osd_scrub     *scrub  = &dev->od_scrub;
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct l_wait_info    lwi    = { 0 };
	struct task_struct   *task;
	int		      rc;
	ENTRY;

again:
	/* os_lock: sync status between stop and scrub thread */
	spin_lock(&scrub->os_lock);
	if (thread_is_running(thread)) {
		spin_unlock(&scrub->os_lock);
		RETURN(-EALREADY);
	} else if (unlikely(thread_is_stopping(thread))) {
		spin_unlock(&scrub->os_lock);
		l_wait_event(thread->t_ctl_waitq,
			     thread_is_stopped(thread),
			     &lwi);
		goto again;
	}
	spin_unlock(&scrub->os_lock);

	if (scrub->os_file.sf_status == SS_COMPLETED)
		flags |= SS_RESET;

	scrub->os_start_flags = flags;
	thread_set_flags(thread, 0);
	task = kthread_run(osd_scrub_main, dev, "OI_scrub");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%.16s: cannot start iteration thread: rc = %d\n",
		       LDISKFS_SB(osd_sb(dev))->s_es->s_volume_name, rc);
		RETURN(rc);
	}

	l_wait_event(thread->t_ctl_waitq,
		     thread_is_running(thread) || thread_is_stopped(thread),
		     &lwi);

	RETURN(0);
}

int osd_scrub_start(struct osd_device *dev)
{
	int rc;
	ENTRY;

	/* od_otable_mutex: prevent curcurrent start/stop */
	mutex_lock(&dev->od_otable_mutex);
	rc = do_osd_scrub_start(dev, SS_AUTO);
	mutex_unlock(&dev->od_otable_mutex);

	RETURN(rc == -EALREADY ? 0 : rc);
}

static void do_osd_scrub_stop(struct osd_scrub *scrub)
{
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct l_wait_info    lwi    = { 0 };

	/* os_lock: sync status between stop and scrub thread */
	spin_lock(&scrub->os_lock);
	if (!thread_is_init(thread) && !thread_is_stopped(thread)) {
		thread_set_flags(thread, SVC_STOPPING);
		spin_unlock(&scrub->os_lock);
		wake_up_all(&thread->t_ctl_waitq);
		l_wait_event(thread->t_ctl_waitq,
			     thread_is_stopped(thread),
			     &lwi);
		/* Do not skip the last lock/unlock, which can guarantee that
		 * the caller cannot return until the OI scrub thread exit. */
		spin_lock(&scrub->os_lock);
	}
	spin_unlock(&scrub->os_lock);
}

static void osd_scrub_stop(struct osd_device *dev)
{
	/* od_otable_mutex: prevent curcurrent start/stop */
	mutex_lock(&dev->od_otable_mutex);
	dev->od_scrub.os_paused = 1;
	do_osd_scrub_stop(&dev->od_scrub);
	mutex_unlock(&dev->od_otable_mutex);
}

/* OI scrub setup/cleanup */

static const char osd_scrub_name[] = "OI_scrub";

int osd_scrub_setup(const struct lu_env *env, struct osd_device *dev)
{
	struct osd_thread_info	   *info   = osd_oti_get(env);
	struct osd_scrub	   *scrub  = &dev->od_scrub;
	struct lvfs_run_ctxt	   *ctxt   = &scrub->os_ctxt;
	struct scrub_file	   *sf     = &scrub->os_file;
	struct super_block	   *sb     = osd_sb(dev);
	struct ldiskfs_super_block *es     = LDISKFS_SB(sb)->s_es;
	struct lvfs_run_ctxt	    saved;
	struct file		   *filp;
	struct inode		   *inode;
	struct lu_fid		   *fid    = &info->oti_fid;
	int			    dirty  = 0;
	int			    rc     = 0;
	ENTRY;

	memset(scrub, 0, sizeof(*scrub));
	OBD_SET_CTXT_MAGIC(ctxt);
	ctxt->pwdmnt = dev->od_mnt;
	ctxt->pwd = dev->od_mnt->mnt_root;
	ctxt->fs = get_ds();

	init_waitqueue_head(&scrub->os_thread.t_ctl_waitq);
	init_rwsem(&scrub->os_rwsem);
	spin_lock_init(&scrub->os_lock);
	CFS_INIT_LIST_HEAD(&scrub->os_inconsistent_items);

	push_ctxt(&saved, ctxt, NULL);
	filp = filp_open(osd_scrub_name, O_RDWR | O_CREAT, 0644);
	if (IS_ERR(filp)) {
		pop_ctxt(&saved, ctxt, NULL);
		RETURN(PTR_ERR(filp));
	}

	inode = filp->f_dentry->d_inode;
	ldiskfs_set_inode_state(inode, LDISKFS_STATE_LUSTRE_NO_OI);
	/* 'What the @fid is' is not imporatant, because the object
	 * has no OI mapping, and only is visible inside the OSD.*/
	lu_igif_build(fid, inode->i_ino, inode->i_generation);
	rc = osd_ea_fid_set(info, inode, fid, LMAC_NOT_IN_OI, 0);
	if (rc != 0) {
		filp_close(filp, 0);
		pop_ctxt(&saved, ctxt, NULL);
		RETURN(rc);
	}

	scrub->os_inode = igrab(inode);
	filp_close(filp, 0);
	pop_ctxt(&saved, ctxt, NULL);

	rc = osd_scrub_file_load(scrub);
	if (rc == -ENOENT) {
		osd_scrub_file_init(scrub, es->s_uuid);
		/* If the "/O" dir does not exist when mount (indicated by
		 * osd_device::od_maybe_new), neither for the "/OI_scrub",
		 * then it is quite probably that the device is a new one,
		 * under such case, mark it as SIF_NO_HANDLE_OLD_FID.
		 *
		 * For the rare case that "/O" and "OI_scrub" both lost on
		 * an old device, it can be found and cleared later.
		 *
		 * For the system with "SIF_NO_HANDLE_OLD_FID", we do not
		 * need to check "filter_fid_old" and to convert it to
		 * "filter_fid" for each object, and all the IGIF should
		 * have their FID mapping in OI files already. */
		if (dev->od_maybe_new)
			sf->sf_internal_flags = SIF_NO_HANDLE_OLD_FID;
		dirty = 1;
	} else if (rc != 0) {
		RETURN(rc);
	} else {
		if (memcmp(sf->sf_uuid, es->s_uuid, 16) != 0) {
			osd_scrub_file_reset(scrub, es->s_uuid,SF_INCONSISTENT);
			dirty = 1;
		} else if (sf->sf_status == SS_SCANNING) {
			sf->sf_status = SS_CRASHED;
			dirty = 1;
		}
	}

	if (sf->sf_pos_last_checkpoint != 0)
		scrub->os_pos_current = sf->sf_pos_last_checkpoint + 1;
	else
		scrub->os_pos_current = LDISKFS_FIRST_INO(sb) + 1;

	if (dirty != 0) {
		rc = osd_scrub_file_store(scrub);
		if (rc != 0)
			RETURN(rc);
	}

	/* Initialize OI files. */
	rc = osd_oi_init(info, dev);
	if (rc < 0)
		RETURN(rc);

	rc = osd_initial_OI_scrub(info, dev);
	if (rc == 0) {
		if (sf->sf_flags & SF_UPGRADE ||
		    !(sf->sf_internal_flags & SIF_NO_HANDLE_OLD_FID ||
		      sf->sf_success_count > 0)) {
			dev->od_igif_inoi = 0;
			dev->od_check_ff = dev->od_is_ost;
		} else {
			dev->od_igif_inoi = 1;
			dev->od_check_ff = 0;
		}

		if (sf->sf_flags & SF_INCONSISTENT)
			/* The 'od_igif_inoi' will be set under the
			 * following cases:
			 * 1) new created system, or
			 * 2) restored from file-level backup, or
			 * 3) the upgrading completed.
			 *
			 * The 'od_igif_inoi' may be cleared by OI scrub
			 * later if found that the system is upgrading. */
			dev->od_igif_inoi = 1;

		if (!dev->od_noscrub &&
		    ((sf->sf_status == SS_PAUSED) ||
		     (sf->sf_status == SS_CRASHED &&
		      sf->sf_flags & (SF_RECREATED | SF_INCONSISTENT |
				      SF_UPGRADE | SF_AUTO)) ||
		     (sf->sf_status == SS_INIT &&
		      sf->sf_flags & (SF_RECREATED | SF_INCONSISTENT |
				      SF_UPGRADE))))
			rc = osd_scrub_start(dev);
	}

	/* it is possible that dcache entries may keep objects after they are
	 * deleted by OSD. While it looks safe this can cause object data to
	 * stay until umount causing failures in tests calculating free space,
	 * e.g. replay-ost-single. Since those dcache entries are not used
	 * anymore let's just free them after use here */
	shrink_dcache_sb(sb);

	RETURN(rc);
}

void osd_scrub_cleanup(const struct lu_env *env, struct osd_device *dev)
{
	struct osd_scrub *scrub = &dev->od_scrub;

	LASSERT(dev->od_otable_it == NULL);

	if (scrub->os_inode != NULL) {
		osd_scrub_stop(dev);
		iput(scrub->os_inode);
		scrub->os_inode = NULL;
	}
	if (dev->od_oi_table != NULL)
		osd_oi_fini(osd_oti_get(env), dev);
}

/* object table based iteration APIs */

static struct dt_it *osd_otable_it_init(const struct lu_env *env,
				       struct dt_object *dt, __u32 attr,
				       struct lustre_capa *capa)
{
	enum dt_otable_it_flags flags = attr >> DT_OTABLE_IT_FLAGS_SHIFT;
	enum dt_otable_it_valid valid = attr & ~DT_OTABLE_IT_FLAGS_MASK;
	struct osd_device      *dev   = osd_dev(dt->do_lu.lo_dev);
	struct osd_scrub       *scrub = &dev->od_scrub;
	struct osd_otable_it   *it;
	__u32			start = 0;
	int			rc;
	ENTRY;

	/* od_otable_mutex: prevent curcurrent init/fini */
	mutex_lock(&dev->od_otable_mutex);
	if (dev->od_otable_it != NULL)
		GOTO(out, it = ERR_PTR(-EALREADY));

	OBD_ALLOC_PTR(it);
	if (it == NULL)
		GOTO(out, it = ERR_PTR(-ENOMEM));

	dev->od_otable_it = it;
	it->ooi_dev = dev;
	it->ooi_cache.ooc_consumer_idx = -1;
	if (flags & DOIF_OUTUSED)
		it->ooi_used_outside = 1;

	if (flags & DOIF_RESET)
		start |= SS_RESET;

	if (valid & DOIV_ERROR_HANDLE) {
		if (flags & DOIF_FAILOUT)
			start |= SS_SET_FAILOUT;
		else
			start |= SS_CLEAR_FAILOUT;
	}

	if (valid & DOIV_DRYRUN) {
		if (flags & DOIF_DRYRUN)
			start |= SS_SET_DRYRUN;
		else
			start |= SS_CLEAR_DRYRUN;
	}

	rc = do_osd_scrub_start(dev, start);
	if (rc < 0 && rc != -EALREADY) {
		dev->od_otable_it = NULL;
		OBD_FREE_PTR(it);
		GOTO(out, it = ERR_PTR(rc));
	}

	it->ooi_cache.ooc_pos_preload = scrub->os_pos_current;

	GOTO(out, it);

out:
	mutex_unlock(&dev->od_otable_mutex);
	return (struct dt_it *)it;
}

static void osd_otable_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_otable_it *it  = (struct osd_otable_it *)di;
	struct osd_device    *dev = it->ooi_dev;

	/* od_otable_mutex: prevent curcurrent init/fini */
	mutex_lock(&dev->od_otable_mutex);
	do_osd_scrub_stop(&dev->od_scrub);
	LASSERT(dev->od_otable_it == it);

	dev->od_otable_it = NULL;
	mutex_unlock(&dev->od_otable_mutex);
	OBD_FREE_PTR(it);
}

static int osd_otable_it_get(const struct lu_env *env,
			     struct dt_it *di, const struct dt_key *key)
{
	return 0;
}

static void osd_otable_it_put(const struct lu_env *env, struct dt_it *di)
{
}

static inline int
osd_otable_it_wakeup(struct osd_scrub *scrub, struct osd_otable_it *it)
{
	spin_lock(&scrub->os_lock);
	if (it->ooi_cache.ooc_pos_preload < scrub->os_pos_current ||
	    scrub->os_waiting ||
	    !thread_is_running(&scrub->os_thread))
		it->ooi_waiting = 0;
	else
		it->ooi_waiting = 1;
	spin_unlock(&scrub->os_lock);

	return !it->ooi_waiting;
}

static int osd_otable_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_otable_it    *it     = (struct osd_otable_it *)di;
	struct osd_device       *dev    = it->ooi_dev;
	struct osd_scrub	*scrub  = &dev->od_scrub;
	struct osd_otable_cache *ooc    = &it->ooi_cache;
	struct ptlrpc_thread    *thread = &scrub->os_thread;
	struct l_wait_info       lwi    = { 0 };
	int			 rc;
	ENTRY;

	LASSERT(it->ooi_user_ready);

again:
	if (!thread_is_running(thread) && !it->ooi_used_outside)
		RETURN(1);

	if (ooc->ooc_cached_items > 0) {
		ooc->ooc_cached_items--;
		ooc->ooc_consumer_idx = (ooc->ooc_consumer_idx + 1) &
					~OSD_OTABLE_IT_CACHE_MASK;
		RETURN(0);
	}

	if (it->ooi_all_cached) {
		l_wait_event(thread->t_ctl_waitq,
			     !thread_is_running(thread),
			     &lwi);
		RETURN(1);
	}

	if (scrub->os_waiting && osd_scrub_has_window(scrub, ooc)) {
		spin_lock(&scrub->os_lock);
		scrub->os_waiting = 0;
		wake_up_all(&scrub->os_thread.t_ctl_waitq);
		spin_unlock(&scrub->os_lock);
	}

	if (it->ooi_cache.ooc_pos_preload >= scrub->os_pos_current)
		l_wait_event(thread->t_ctl_waitq,
			     osd_otable_it_wakeup(scrub, it),
			     &lwi);

	if (!thread_is_running(thread) && !it->ooi_used_outside)
		RETURN(1);

	rc = osd_otable_it_preload(env, it);
	if (rc >= 0)
		goto again;

	RETURN(rc);
}

static struct dt_key *osd_otable_it_key(const struct lu_env *env,
					const struct dt_it *di)
{
	return NULL;
}

static int osd_otable_it_key_size(const struct lu_env *env,
				  const struct dt_it *di)
{
	return sizeof(__u64);
}

static int osd_otable_it_rec(const struct lu_env *env, const struct dt_it *di,
			     struct dt_rec *rec, __u32 attr)
{
	struct osd_otable_it    *it  = (struct osd_otable_it *)di;
	struct osd_otable_cache *ooc = &it->ooi_cache;

	*(struct lu_fid *)rec = ooc->ooc_cache[ooc->ooc_consumer_idx].oic_fid;

	/* Filter out Invald FID already. */
	LASSERTF(fid_is_sane((struct lu_fid *)rec),
		 "Invalid FID "DFID", p_idx = %d, c_idx = %d\n",
		 PFID((struct lu_fid *)rec),
		 ooc->ooc_producer_idx, ooc->ooc_consumer_idx);

	return 0;
}

static __u64 osd_otable_it_store(const struct lu_env *env,
				 const struct dt_it *di)
{
	struct osd_otable_it    *it  = (struct osd_otable_it *)di;
	struct osd_otable_cache *ooc = &it->ooi_cache;
	__u64			 hash;

	if (it->ooi_user_ready && ooc->ooc_consumer_idx != -1)
		hash = ooc->ooc_cache[ooc->ooc_consumer_idx].oic_lid.oii_ino;
	else
		hash = ooc->ooc_pos_preload;
	return hash;
}

/**
 * Set the OSD layer iteration start position as the specified hash.
 */
static int osd_otable_it_load(const struct lu_env *env,
			      const struct dt_it *di, __u64 hash)
{
	struct osd_otable_it    *it    = (struct osd_otable_it *)di;
	struct osd_device       *dev   = it->ooi_dev;
	struct osd_otable_cache *ooc   = &it->ooi_cache;
	struct osd_scrub	*scrub = &dev->od_scrub;
	int			 rc;
	ENTRY;

	/* Forbid to set iteration position after iteration started. */
	if (it->ooi_user_ready)
		RETURN(-EPERM);

	if (hash > OSD_OTABLE_MAX_HASH)
		hash = OSD_OTABLE_MAX_HASH;

	ooc->ooc_pos_preload = hash;
	if (ooc->ooc_pos_preload <= LDISKFS_FIRST_INO(osd_sb(dev)))
		ooc->ooc_pos_preload = LDISKFS_FIRST_INO(osd_sb(dev)) + 1;

	it->ooi_user_ready = 1;
	if (!scrub->os_full_speed)
		wake_up_all(&scrub->os_thread.t_ctl_waitq);

	/* Unplug OSD layer iteration by the first next() call. */
	rc = osd_otable_it_next(env, (struct dt_it *)it);

	RETURN(rc);
}

static int osd_otable_it_key_rec(const struct lu_env *env,
				 const struct dt_it *di, void *key_rec)
{
	return 0;
}

const struct dt_index_operations osd_otable_ops = {
	.dio_it = {
		.init     = osd_otable_it_init,
		.fini     = osd_otable_it_fini,
		.get      = osd_otable_it_get,
		.put	  = osd_otable_it_put,
		.next     = osd_otable_it_next,
		.key	  = osd_otable_it_key,
		.key_size = osd_otable_it_key_size,
		.rec      = osd_otable_it_rec,
		.store    = osd_otable_it_store,
		.load     = osd_otable_it_load,
		.key_rec  = osd_otable_it_key_rec,
	}
};

/* high priority inconsistent items list APIs */

int osd_oii_insert(struct osd_device *dev, struct osd_idmap_cache *oic,
		   int insert)
{
	struct osd_inconsistent_item *oii;
	struct osd_scrub	     *scrub  = &dev->od_scrub;
	struct ptlrpc_thread	     *thread = &scrub->os_thread;
	int			      wakeup = 0;
	ENTRY;

	OBD_ALLOC_PTR(oii);
	if (unlikely(oii == NULL))
		RETURN(-ENOMEM);

	CFS_INIT_LIST_HEAD(&oii->oii_list);
	oii->oii_cache = *oic;
	oii->oii_insert = insert;

	spin_lock(&scrub->os_lock);
	if (unlikely(!thread_is_running(thread))) {
		spin_unlock(&scrub->os_lock);
		OBD_FREE_PTR(oii);
		RETURN(-EAGAIN);
	}

	if (cfs_list_empty(&scrub->os_inconsistent_items))
		wakeup = 1;
	cfs_list_add_tail(&oii->oii_list, &scrub->os_inconsistent_items);
	spin_unlock(&scrub->os_lock);

	if (wakeup != 0)
		wake_up_all(&thread->t_ctl_waitq);

	RETURN(0);
}

int osd_oii_lookup(struct osd_device *dev, const struct lu_fid *fid,
		   struct osd_inode_id *id)
{
	struct osd_scrub	     *scrub = &dev->od_scrub;
	struct osd_inconsistent_item *oii;
	ENTRY;

	spin_lock(&scrub->os_lock);
	cfs_list_for_each_entry(oii, &scrub->os_inconsistent_items, oii_list) {
		if (lu_fid_eq(fid, &oii->oii_cache.oic_fid)) {
			*id = oii->oii_cache.oic_lid;
			spin_unlock(&scrub->os_lock);
			RETURN(0);
		}
	}
	spin_unlock(&scrub->os_lock);

	RETURN(-ENOENT);
}

/* OI scrub dump */

static const char *scrub_status_names[] = {
	"init",
	"scanning",
	"completed",
	"failed",
	"stopped",
	"paused",
	"crashed",
	NULL
};

static const char *scrub_flags_names[] = {
	"recreated",
	"inconsistent",
	"auto",
	"upgrade",
	NULL
};

static const char *scrub_param_names[] = {
	"failout",
	"dryrun",
	NULL
};

static int scrub_bits_dump(char **buf, int *len, int bits, const char *names[],
			   const char *prefix)
{
	int save = *len;
	int flag;
	int rc;
	int i;

	rc = snprintf(*buf, *len, "%s:%c", prefix, bits != 0 ? ' ' : '\n');
	if (rc <= 0)
		return -ENOSPC;

	*buf += rc;
	*len -= rc;
	for (i = 0, flag = 1; bits != 0; i++, flag = 1 << i) {
		if (flag & bits) {
			bits &= ~flag;
			rc = snprintf(*buf, *len, "%s%c", names[i],
				      bits != 0 ? ',' : '\n');
			if (rc <= 0)
				return -ENOSPC;

			*buf += rc;
			*len -= rc;
		}
	}
	return save - *len;
}

static int scrub_time_dump(char **buf, int *len, __u64 time, const char *prefix)
{
	int rc;

	if (time != 0)
		rc = snprintf(*buf, *len, "%s: "LPU64" seconds\n", prefix,
			      cfs_time_current_sec() - time);
	else
		rc = snprintf(*buf, *len, "%s: N/A\n", prefix);
	if (rc <= 0)
		return -ENOSPC;

	*buf += rc;
	*len -= rc;
	return rc;
}

static int scrub_pos_dump(char **buf, int *len, __u64 pos, const char *prefix)
{
	int rc;

	if (pos != 0)
		rc = snprintf(*buf, *len, "%s: "LPU64"\n", prefix, pos);
	else
		rc = snprintf(*buf, *len, "%s: N/A\n", prefix);
	if (rc <= 0)
		return -ENOSPC;

	*buf += rc;
	*len -= rc;
	return rc;
}

int osd_scrub_dump(struct osd_device *dev, char *buf, int len)
{
	struct osd_scrub  *scrub   = &dev->od_scrub;
	struct scrub_file *sf      = &scrub->os_file;
	__u64		   checked;
	__u64		   speed;
	int		   save    = len;
	int		   ret     = -ENOSPC;
	int		   rc;

	down_read(&scrub->os_rwsem);
	rc = snprintf(buf, len,
		      "name: OI_scrub\n"
		      "magic: 0x%x\n"
		      "oi_files: %d\n"
		      "status: %s\n",
		      sf->sf_magic, (int)sf->sf_oi_count,
		      scrub_status_names[sf->sf_status]);
	if (rc <= 0)
		goto out;

	buf += rc;
	len -= rc;
	rc = scrub_bits_dump(&buf, &len, sf->sf_flags, scrub_flags_names,
			     "flags");
	if (rc < 0)
		goto out;

	rc = scrub_bits_dump(&buf, &len, sf->sf_param, scrub_param_names,
			     "param");
	if (rc < 0)
		goto out;

	rc = scrub_time_dump(&buf, &len, sf->sf_time_last_complete,
			     "time_since_last_completed");
	if (rc < 0)
		goto out;

	rc = scrub_time_dump(&buf, &len, sf->sf_time_latest_start,
			     "time_since_latest_start");
	if (rc < 0)
		goto out;

	rc = scrub_time_dump(&buf, &len, sf->sf_time_last_checkpoint,
			     "time_since_last_checkpoint");
	if (rc < 0)
		goto out;

	rc = scrub_pos_dump(&buf, &len, sf->sf_pos_latest_start,
			    "latest_start_position");
	if (rc < 0)
		goto out;

	rc = scrub_pos_dump(&buf, &len, sf->sf_pos_last_checkpoint,
			    "last_checkpoint_position");
	if (rc < 0)
		goto out;

	rc = scrub_pos_dump(&buf, &len, sf->sf_pos_first_inconsistent,
			    "first_failure_position");
	if (rc < 0)
		goto out;

	checked = sf->sf_items_checked + scrub->os_new_checked;
	rc = snprintf(buf, len,
		      "checked: "LPU64"\n"
		      "updated: "LPU64"\n"
		      "failed: "LPU64"\n"
		      "prior_updated: "LPU64"\n"
		      "noscrub: "LPU64"\n"
		      "igif: "LPU64"\n"
		      "success_count: %u\n",
		      checked, sf->sf_items_updated, sf->sf_items_failed,
		      sf->sf_items_updated_prior, sf->sf_items_noscrub,
		      sf->sf_items_igif, sf->sf_success_count);
	if (rc <= 0)
		goto out;

	buf += rc;
	len -= rc;
	speed = checked;
	if (thread_is_running(&scrub->os_thread)) {
		cfs_duration_t duration = cfs_time_current() -
					  scrub->os_time_last_checkpoint;
		__u64 new_checked = scrub->os_new_checked * HZ;
		__u32 rtime = sf->sf_run_time +
			      cfs_duration_sec(duration + HALF_SEC);

		if (duration != 0)
			do_div(new_checked, duration);
		if (rtime != 0)
			do_div(speed, rtime);
		rc = snprintf(buf, len,
			      "run_time: %u seconds\n"
			      "average_speed: "LPU64" objects/sec\n"
			      "real-time_speed: "LPU64" objects/sec\n"
			      "current_position: %u\n"
			      "lf_scanned: "LPU64"\n"
			      "lf_reparied: "LPU64"\n"
			      "lf_failed: "LPU64"\n",
			      rtime, speed, new_checked, scrub->os_pos_current,
			      scrub->os_lf_scanned, scrub->os_lf_repaired,
			      scrub->os_lf_failed);
	} else {
		if (sf->sf_run_time != 0)
			do_div(speed, sf->sf_run_time);
		rc = snprintf(buf, len,
			      "run_time: %u seconds\n"
			      "average_speed: "LPU64" objects/sec\n"
			      "real-time_speed: N/A\n"
			      "current_position: N/A\n"
			      "lf_scanned: "LPU64"\n"
			      "lf_reparied: "LPU64"\n"
			      "lf_failed: "LPU64"\n",
			      sf->sf_run_time, speed, scrub->os_lf_scanned,
			      scrub->os_lf_repaired, scrub->os_lf_failed);
	}
	if (rc <= 0)
		goto out;

	buf += rc;
	len -= rc;
	ret = save - len;

out:
	up_read(&scrub->os_rwsem);
	return ret;
}
