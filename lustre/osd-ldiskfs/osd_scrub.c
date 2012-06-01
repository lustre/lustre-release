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
 * Copyright (c) 2012 Whamcloud, Inc.
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <lustre/lustre_idl.h>
#include <lustre_disk.h>
#include <dt_object.h>

#include "osd_internal.h"
#include "osd_oi.h"
#include "osd_scrub.h"

#define HALF_SEC	(CFS_HZ >> 1)

static inline struct osd_device *osd_scrub2dev(struct osd_scrub *scrub)
{
	return container_of0(scrub, struct osd_device, od_scrub);
}

static inline struct super_block *osd_scrub2sb(struct osd_scrub *scrub)
{
	return osd_sb(osd_scrub2dev(scrub));
}

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
	sf->sf_param = 0;
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
	jh = ldiskfs_journal_start_sb(osd_sb(dev), credits);
	if (IS_ERR(jh)) {
		rc = PTR_ERR(jh);
		CERROR("%.16s: fail to start trans for scrub store, rc = %d\n",
		       LDISKFS_SB(osd_scrub2sb(scrub))->s_es->s_volume_name,rc);
		return rc;
	}

	osd_scrub_file_to_le(&scrub->os_file_disk, &scrub->os_file);
	rc = osd_ldiskfs_write_record(scrub->os_inode, &scrub->os_file_disk,
				      len, &pos, jh);
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

static int osd_scrub_prep(struct osd_device *dev)
{
	struct osd_scrub     *scrub  = &dev->od_scrub;
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct scrub_file    *sf     = &scrub->os_file;
	__u32		      flags  = scrub->os_start_flags;
	int		      rc;
	ENTRY;

	cfs_down_write(&scrub->os_rwsem);
	if (flags & SS_SET_FAILOUT)
		sf->sf_param |= SP_FAILOUT;

	if (flags & SS_CLEAR_FAILOUT)
		sf->sf_param &= ~SP_FAILOUT;

	if (flags & SS_RESET)
		osd_scrub_file_reset(scrub,
			LDISKFS_SB(osd_sb(dev))->s_es->s_uuid, sf->sf_flags);

	if (flags & SS_AUTO) {
		scrub->os_full_speed = 1;
		sf->sf_flags |= SF_AUTO;
	} else {
		scrub->os_full_speed = 0;
	}

	if (sf->sf_flags & (SF_RECREATED | SF_INCONSISTENT))
		scrub->os_full_speed = 1;

	scrub->os_in_prior = 0;
	scrub->os_waiting = 0;
	scrub->os_new_checked = 0;
	if (sf->sf_pos_last_checkpoint != 0)
		sf->sf_pos_latest_start = sf->sf_pos_last_checkpoint + 1;
	else
		sf->sf_pos_latest_start = LDISKFS_FIRST_INO(osd_sb(dev));

	scrub->os_pos_current = sf->sf_pos_latest_start;
	sf->sf_status = SS_SCANNING;
	sf->sf_time_latest_start = cfs_time_current_sec();
	sf->sf_time_last_checkpoint = sf->sf_time_latest_start;
	rc = osd_scrub_file_store(scrub);
	if (rc == 0) {
		cfs_spin_lock(&scrub->os_lock);
		thread_set_flags(thread, SVC_RUNNING);
		cfs_spin_unlock(&scrub->os_lock);
		cfs_waitq_broadcast(&thread->t_ctl_waitq);
	}
	cfs_up_write(&scrub->os_rwsem);

	RETURN(rc);
}

static int osd_scrub_error_handler(struct osd_device *dev,
				   struct osd_inode_id *lid, int rc)
{
	struct osd_scrub  *scrub = &dev->od_scrub;
	struct scrub_file *sf    = &scrub->os_file;

	cfs_down_write(&scrub->os_rwsem);
	scrub->os_new_checked++;
	sf->sf_items_failed++;
	if (sf->sf_pos_first_inconsistent == 0 ||
	    sf->sf_pos_first_inconsistent > lid->oii_ino)
		sf->sf_pos_first_inconsistent = lid->oii_ino;
	cfs_up_write(&scrub->os_rwsem);
	return sf->sf_param & SP_FAILOUT ? rc : 0;
}

static int
osd_scrub_check_update(struct osd_thread_info *info,  struct osd_device *dev,
		       struct osd_idmap_cache *oic)
{
	struct osd_scrub	     *scrub  = &dev->od_scrub;
	struct scrub_file	     *sf     = &scrub->os_file;
	struct osd_inode_id	     *lid2   = &info->oti_id;
	struct lu_fid		     *oi_fid = &info->oti_fid;
	struct osd_inode_id	     *oi_id  = &info->oti_id;
	handle_t		     *jh     = NULL;
	struct osd_inconsistent_item *oii    = NULL;
	struct inode		     *inode  = NULL;
	struct lu_fid		     *fid    = &oic->oic_fid;
	struct osd_inode_id	     *lid    = &oic->oic_lid;
	struct iam_container	     *bag;
	struct iam_path_descr	     *ipd;
	int			      ops    = DTO_INDEX_UPDATE;
	int			      idx;
	int			      rc;
	ENTRY;

	if (scrub->os_in_prior)
		oii = cfs_list_entry(oic, struct osd_inconsistent_item,
				     oii_cache);

	cfs_down_write(&scrub->os_rwsem);
	scrub->os_new_checked++;
	if (lid->oii_ino < sf->sf_pos_latest_start && oii == NULL)
		GOTO(out, rc = 0);

	if (oii != NULL && oii->oii_insert)
		goto iget;

	rc = osd_oi_lookup(info, dev, fid, lid2);
	if (rc != 0) {
		if (rc != -ENOENT)
			GOTO(out, rc);

iget:
		inode = osd_iget(info, dev, lid);
		if (IS_ERR(inode)) {
			rc = PTR_ERR(inode);
			/* Someone removed the inode. */
			if (rc == -ENOENT || rc == -ESTALE)
				rc = 0;
			GOTO(out, rc);
		}

		/* Prevent the inode to be unlinked during OI scrub. */
		cfs_mutex_lock(&inode->i_mutex);
		if (unlikely(inode->i_nlink == 0)) {
			cfs_mutex_unlock(&inode->i_mutex);
			iput(inode);
			GOTO(out, rc = 0);
		}

		ops = DTO_INDEX_INSERT;
		idx = osd_oi_fid2idx(dev, fid);
		if (unlikely(!ldiskfs_test_bit(idx, sf->sf_oi_bitmap)))
			ldiskfs_set_bit(idx, sf->sf_oi_bitmap);
		sf->sf_flags |= SF_RECREATED;
	} else if (osd_id_eq(lid, lid2)) {
			GOTO(out, rc = 0);
	}

	sf->sf_flags |= SF_INCONSISTENT;
	fid_cpu_to_be(oi_fid, fid);
	osd_id_pack(oi_id, &oic->oic_lid);
	jh = ldiskfs_journal_start_sb(osd_sb(dev),
				osd_dto_credits_noquota[ops]);
	if (IS_ERR(jh)) {
		rc = PTR_ERR(jh);
		CERROR("%.16s: fail to start trans for scrub store, rc = %d\n",
		       LDISKFS_SB(osd_sb(dev))->s_es->s_volume_name, rc);
		GOTO(out, rc);
	}

	bag = &osd_fid2oi(dev, fid)->oi_dir.od_container;
	ipd = osd_idx_ipd_get(info->oti_env, bag);
	if (unlikely(ipd == NULL)) {
		ldiskfs_journal_stop(jh);
		CERROR("%.16s: fail to get ipd for scrub store\n",
			LDISKFS_SB(osd_sb(dev))->s_es->s_volume_name);
		GOTO(out, rc = -ENOMEM);
	}

	if (ops == DTO_INDEX_UPDATE)
		rc = iam_update(jh, bag, (const struct iam_key *)oi_fid,
				(struct iam_rec *)oi_id, ipd);
	else
		rc = iam_insert(jh, bag, (const struct iam_key *)oi_fid,
				(struct iam_rec *)oi_id, ipd);
	osd_ipd_put(info->oti_env, bag, ipd);
	ldiskfs_journal_stop(jh);
	if (rc == 0) {
		if (scrub->os_in_prior)
			sf->sf_items_updated_prior++;
		else
			sf->sf_items_updated++;
	}

	GOTO(out, rc);

out:
	if (rc != 0) {
		sf->sf_items_failed++;
		if (sf->sf_pos_first_inconsistent == 0 ||
		    sf->sf_pos_first_inconsistent > lid->oii_ino)
			sf->sf_pos_first_inconsistent = lid->oii_ino;
	}

	if (ops == DTO_INDEX_INSERT) {
		cfs_mutex_unlock(&inode->i_mutex);
		iput(inode);
	}
	cfs_up_write(&scrub->os_rwsem);

	if (oii != NULL) {
		LASSERT(!cfs_list_empty(&oii->oii_list));

		cfs_spin_lock(&scrub->os_lock);
		cfs_list_del_init(&oii->oii_list);
		cfs_spin_unlock(&scrub->os_lock);
		OBD_FREE_PTR(oii);
	}
	RETURN(sf->sf_param & SP_FAILOUT ? rc : 0);
}

static int do_osd_scrub_checkpoint(struct osd_scrub *scrub)
{
	struct scrub_file *sf = &scrub->os_file;
	int		   rc;
	ENTRY;

	cfs_down_write(&scrub->os_rwsem);
	sf->sf_items_checked += scrub->os_new_checked;
	scrub->os_new_checked = 0;
	sf->sf_pos_last_checkpoint = scrub->os_pos_current;
	sf->sf_time_last_checkpoint = cfs_time_current_sec();
	sf->sf_run_time += cfs_duration_sec(cfs_time_current() + HALF_SEC -
					    scrub->os_time_last_checkpoint);
	rc = osd_scrub_file_store(scrub);
	cfs_up_write(&scrub->os_rwsem);

	RETURN(rc);
}

static inline int osd_scrub_checkpoint(struct osd_scrub *scrub)
{
	if (unlikely(cfs_time_beforeq(scrub->os_time_next_checkpoint,
				      cfs_time_current()) &&
		     scrub->os_new_checked > 0))
		return do_osd_scrub_checkpoint(scrub);
	return 0;
}

static void osd_scrub_post(struct osd_scrub *scrub, int result)
{
	struct scrub_file *sf = &scrub->os_file;
	ENTRY;

	cfs_down_write(&scrub->os_rwsem);
	cfs_spin_lock(&scrub->os_lock);
	thread_set_flags(&scrub->os_thread, SVC_STOPPING);
	cfs_spin_unlock(&scrub->os_lock);
	if (scrub->os_new_checked > 0) {
		sf->sf_items_checked += scrub->os_new_checked;
		scrub->os_new_checked = 0;
		sf->sf_pos_last_checkpoint = scrub->os_pos_current;
	}
	sf->sf_time_last_checkpoint = cfs_time_current_sec();
	if (result > 0) {
		sf->sf_status = SS_COMPLETED;
		memset(sf->sf_oi_bitmap, 0, SCRUB_OI_BITMAP_SIZE);
		sf->sf_flags &= ~(SF_RECREATED | SF_INCONSISTENT | SF_AUTO);
		sf->sf_time_last_complete = sf->sf_time_last_checkpoint;
		sf->sf_success_count++;
	} else if (result == 0) {
		sf->sf_status = SS_PAUSED;
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
	cfs_up_write(&scrub->os_rwsem);

	EXIT;
}

#define SCRUB_NEXT_BREAK	1
#define SCRUB_NEXT_CONTINUE	2

static int
osd_scrub_next(struct osd_thread_info *info, struct osd_device *dev,
	       struct osd_scrub *scrub, struct super_block *sb,
	       ldiskfs_group_t bg, struct buffer_head *bitmap, __u32 gbase,
	       __u32 *offset, struct osd_idmap_cache **oic)
{
	struct osd_inconsistent_item *oii;
	struct lu_fid		     *fid;
	struct osd_inode_id	     *lid;
	struct inode		     *inode;
	int			     rc    = 0;

	if (!cfs_list_empty(&scrub->os_inconsistent_items)) {
		oii = cfs_list_entry(scrub->os_inconsistent_items.next,
				     struct osd_inconsistent_item, oii_list);
		*oic = &oii->oii_cache;
		scrub->os_in_prior = 1;
		return 0;
	}

	*oic = &scrub->os_oic;
	fid = &(*oic)->oic_fid;
	lid = &(*oic)->oic_lid;
	*offset = ldiskfs_find_next_bit(bitmap->b_data,
					LDISKFS_INODES_PER_GROUP(sb), *offset);
	if (*offset >= LDISKFS_INODES_PER_GROUP(sb)) {
		brelse(bitmap);
		scrub->os_pos_current = 1 + (bg + 1) *
					LDISKFS_INODES_PER_GROUP(sb);
		return SCRUB_NEXT_BREAK;
	}

	scrub->os_pos_current = gbase + *offset;
	osd_id_gen(lid, scrub->os_pos_current, OSD_OII_NOGEN);
	inode = osd_iget_fid(info, dev, lid, fid);
	if (IS_ERR(inode)) {
		rc = PTR_ERR(inode);
		/* The inode may be removed after bitmap searching, or the
		 * file is new created without inode initialized yet. */
		if (rc == -ENOENT || rc == -ESTALE)
			rc = SCRUB_NEXT_CONTINUE;
		else
			CERROR("%.16s: fail to read inode, group = %u, "
			       "ino# = %u, rc = %d\n",
			       LDISKFS_SB(sb)->s_es->s_volume_name,
			       bg, scrub->os_pos_current, rc);
	} else {
		if (fid_is_igif(fid) || fid_is_idif(fid) ||
		    fid_seq(fid) == FID_SEQ_LLOG ||
		    fid_seq(fid) == FID_SEQ_LOCAL_FILE ||
		    fid_seq_is_rsvd(fid_seq(fid)) ||
		    inode->i_state & I_LUSTRE_NOSCRUB)
			rc = SCRUB_NEXT_CONTINUE;
		iput(inode);
	}
	return rc;
}

static inline int osd_scrub_has_window(struct osd_scrub *scrub,
				       struct osd_otable_cache *ooc)
{
	return scrub->os_pos_current < ooc->ooc_pos_preload + SCRUB_WINDOW_SIZE;
}

static int osd_scrub_main(void *args)
{
	struct lu_env		      env;
	struct osd_thread_info	     *info;
	struct osd_device	     *dev    = (struct osd_device *)args;
	struct osd_scrub	     *scrub  = &dev->od_scrub;
	struct ptlrpc_thread	     *thread = &scrub->os_thread;
	cfs_list_t		     *list   = &scrub->os_inconsistent_items;
	struct l_wait_info	      lwi    = { 0 };
	struct super_block	     *sb     = osd_sb(dev);
	struct osd_otable_it	     *it     = NULL;
	struct osd_otable_cache	     *ooc    = NULL;
	int			      noslot = 0;
	int			      rc;
	__u32			      max;
	ENTRY;

	cfs_daemonize("OI_scrub");
	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc != 0) {
		CERROR("%.16s: OI scrub, fail to init env, rc = %d\n",
		       LDISKFS_SB(sb)->s_es->s_volume_name, rc);
		GOTO(noenv, rc);
	}

	info = osd_oti_get(&env);
	rc = osd_scrub_prep(dev);
	if (rc != 0) {
		CERROR("%.16s: OI scrub, fail to scrub prep, rc = %d\n",
		       LDISKFS_SB(sb)->s_es->s_volume_name, rc);
		GOTO(out, rc);
	}

	if (!scrub->os_full_speed) {
		LASSERT(dev->od_otable_it != NULL);

		it = dev->od_otable_it;
		ooc = &it->ooi_cache;
		l_wait_event(thread->t_ctl_waitq,
			     it->ooi_user_ready || !thread_is_running(thread),
			     &lwi);
		if (unlikely(!thread_is_running(thread)))
			GOTO(post, rc = 0);

		LASSERT(scrub->os_pos_current >= ooc->ooc_pos_preload);
		scrub->os_pos_current = ooc->ooc_pos_preload;
	}

	CDEBUG(D_LFSCK, "OI scrub: flags = 0x%x, pos = %u\n",
	       scrub->os_start_flags, scrub->os_pos_current);

	max = le32_to_cpu(LDISKFS_SB(sb)->s_es->s_inodes_count);
	while (scrub->os_pos_current <= max) {
		struct buffer_head *bitmap = NULL;
		struct osd_idmap_cache *oic = NULL;
		ldiskfs_group_t bg = (scrub->os_pos_current - 1) /
				     LDISKFS_INODES_PER_GROUP(sb);
		__u32 offset = (scrub->os_pos_current - 1) %
			       LDISKFS_INODES_PER_GROUP(sb);
		__u32 gbase = 1 + bg * LDISKFS_INODES_PER_GROUP(sb);

		bitmap = ldiskfs_read_inode_bitmap(sb, bg);
		if (bitmap == NULL) {
			CERROR("%.16s: fail to read bitmap at pos = %u, "
			       "bg = %u, scrub will stop\n",
			       LDISKFS_SB(sb)->s_es->s_volume_name,
			       scrub->os_pos_current, (__u32)bg);
			GOTO(post, rc = -EIO);
		}

		while (offset < LDISKFS_INODES_PER_GROUP(sb)) {
			if (unlikely(!thread_is_running(thread))) {
				brelse(bitmap);
				GOTO(post, rc = 0);
			}

			if (cfs_list_empty(list) && noslot != 0)
				goto wait;

			rc = osd_scrub_next(info, dev, scrub, sb, bg,
					    bitmap, gbase, &offset, &oic);
			if (rc == SCRUB_NEXT_BREAK)
				break;
			else if (rc == SCRUB_NEXT_CONTINUE)
				goto next;

			if (rc != 0)
				rc = osd_scrub_error_handler(dev, &oic->oic_lid,
							     rc);
			else
				rc = osd_scrub_check_update(info, dev, oic);
			if (rc != 0) {
				brelse(bitmap);
				GOTO(post, rc);
			}

			rc = osd_scrub_checkpoint(scrub);
			if (rc != 0) {
				CERROR("%.16s: fail to checkpoint, pos = %u, "
				       "rc = %d\n",
				       LDISKFS_SB(sb)->s_es->s_volume_name,
				       scrub->os_pos_current, rc);
				brelse(bitmap);
				GOTO(post, rc);
			}

			if (scrub->os_in_prior) {
				scrub->os_in_prior = 0;
				continue;
			}

next:
			scrub->os_pos_current = gbase + ++offset;
			if (dev->od_otable_it != NULL) {
				if (unlikely(it == NULL)) {
					it = dev->od_otable_it;
					ooc = &it->ooi_cache;
				}

				if (it->ooi_waiting &&
				    (ooc->ooc_pos_preload <
				     scrub->os_pos_current)) {
					it->ooi_waiting = 0;
					cfs_waitq_broadcast(
							&thread->t_ctl_waitq);
				}
			}

			if (scrub->os_full_speed || rc == SCRUB_NEXT_CONTINUE)
				continue;

wait:
			if (osd_scrub_has_window(scrub, ooc)) {
				noslot = 0;
				continue;
			}

			scrub->os_waiting = 1;
			l_wait_event(thread->t_ctl_waitq,
				     osd_scrub_has_window(scrub, ooc) ||
				     !cfs_list_empty(list) ||
				     !thread_is_running(thread),
				     &lwi);
			scrub->os_waiting = 0;

			if (osd_scrub_has_window(scrub, ooc))
				noslot = 0;
			else
				noslot = 1;
		}
	}

	GOTO(post, rc = (scrub->os_pos_current > max ? 1 : rc));

post:
	osd_scrub_post(scrub, rc);
	CDEBUG(D_LFSCK, "OI scrub: stop, rc = %d, pos = %u\n",
	       rc, scrub->os_pos_current);

out:
	while (!cfs_list_empty(list)) {
		struct osd_inconsistent_item *oii;

		oii = cfs_list_entry(list->next,
				     struct osd_inconsistent_item, oii_list);
		cfs_list_del_init(&oii->oii_list);
		OBD_FREE_PTR(oii);
	}
	lu_env_fini(&env);

noenv:
	cfs_spin_lock(&scrub->os_lock);
	thread_set_flags(thread, SVC_STOPPED);
	cfs_waitq_broadcast(&thread->t_ctl_waitq);
	cfs_spin_unlock(&scrub->os_lock);
	return rc;
}

static int do_osd_scrub_start(struct osd_device *dev, __u32 flags)
{
	struct osd_scrub     *scrub  = &dev->od_scrub;
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct l_wait_info    lwi    = { 0 };
	int		      rc;
	ENTRY;

again:
	/* os_lock: sync status between stop and scrub thread */
	cfs_spin_lock(&scrub->os_lock);
	if (thread_is_running(thread)) {
		cfs_spin_unlock(&scrub->os_lock);
		RETURN(-EALREADY);
	} else if (unlikely(thread_is_stopping(thread))) {
		cfs_spin_unlock(&scrub->os_lock);
		l_wait_event(thread->t_ctl_waitq,
			     thread_is_stopped(thread),
			     &lwi);
		goto again;
	}
	cfs_spin_unlock(&scrub->os_lock);

	scrub->os_start_flags = flags;
	thread_set_flags(thread, 0);
	rc = cfs_create_thread(osd_scrub_main, dev, 0);
	if (rc < 0) {
		CERROR("%.16s: cannot start iteration thread, rc = %d\n",
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
	__u32 flags = SS_AUTO;
	int   rc;
	ENTRY;

	if (dev->od_scrub.os_file.sf_status == SS_COMPLETED)
		flags |= SS_RESET;

	/* od_otable_mutex: prevent curcurrent start/stop */
	cfs_mutex_lock(&dev->od_otable_mutex);
	rc = do_osd_scrub_start(dev, flags);
	cfs_mutex_unlock(&dev->od_otable_mutex);

	RETURN(rc == -EALREADY ? 0 : rc);
}

static void do_osd_scrub_stop(struct osd_scrub *scrub)
{
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct l_wait_info    lwi    = { 0 };

	/* os_lock: sync status between stop and scrub thread */
	cfs_spin_lock(&scrub->os_lock);
	if (!thread_is_init(thread) && !thread_is_stopped(thread)) {
		thread_set_flags(thread, SVC_STOPPING);
		cfs_spin_unlock(&scrub->os_lock);
		cfs_waitq_broadcast(&thread->t_ctl_waitq);
		l_wait_event(thread->t_ctl_waitq,
			     thread_is_stopped(thread),
			     &lwi);
		/* Do not skip the last lock/unlock, which can guarantee that
		 * the caller cannot return until the OI scrub thread exit. */
		cfs_spin_lock(&scrub->os_lock);
	}
	cfs_spin_unlock(&scrub->os_lock);
}

static void osd_scrub_stop(struct osd_device *dev)
{
	/* od_otable_mutex: prevent curcurrent start/stop */
	cfs_mutex_lock(&dev->od_otable_mutex);
	do_osd_scrub_stop(&dev->od_scrub);
	cfs_mutex_unlock(&dev->od_otable_mutex);
}

static const char osd_scrub_name[] = "OI_scrub";

int osd_scrub_setup(const struct lu_env *env, struct osd_device *dev)
{
	struct osd_thread_info	   *info   = osd_oti_get(env);
	struct osd_scrub	   *scrub  = &dev->od_scrub;
	struct lvfs_run_ctxt	   *ctxt   = &scrub->os_ctxt;
	struct scrub_file	   *sf     = &scrub->os_file;
	struct osd_inode_id	   *id     = &scrub->os_oic.oic_lid;
	struct super_block	   *sb     = osd_sb(dev);
	struct ldiskfs_super_block *es     = LDISKFS_SB(sb)->s_es;
	struct inode		   *inode;
	struct lvfs_run_ctxt	    saved;
	struct file		   *filp;
	int			    dirty  = 0;
	int			    init   = 0;
	int			    rc     = 0;
	ENTRY;

	OBD_SET_CTXT_MAGIC(ctxt);
	ctxt->pwdmnt = dev->od_mnt;
	ctxt->pwd = dev->od_mnt->mnt_root;
	ctxt->fs = get_ds();

	cfs_waitq_init(&scrub->os_thread.t_ctl_waitq);
	cfs_init_rwsem(&scrub->os_rwsem);
	cfs_spin_lock_init(&scrub->os_lock);
	CFS_INIT_LIST_HEAD(&scrub->os_inconsistent_items);
	if (get_mount_flags(dev->od_mount->lmi_sb) & LMD_FLG_NOSCRUB)
		scrub->os_no_scrub = 1;

	push_ctxt(&saved, ctxt, NULL);
	filp = filp_open(osd_scrub_name, O_RDWR | O_CREAT, 0644);
	if (IS_ERR(filp))
		RETURN(PTR_ERR(filp));

	scrub->os_inode = igrab(filp->f_dentry->d_inode);
	filp_close(filp, 0);
	pop_ctxt(&saved, ctxt, NULL);

	rc = osd_scrub_file_load(scrub);
	if (rc == -ENOENT) {
		osd_scrub_file_init(scrub, es->s_uuid);
		dirty = 1;
		init = 1;
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
		scrub->os_pos_current = LDISKFS_FIRST_INO(sb);

	if (dirty != 0) {
		rc = osd_scrub_file_store(scrub);
		if (rc != 0)
			RETURN(rc);
	}

	/* Initialize OI files. */
	rc = osd_oi_init(info, dev);
	if (rc < 0)
		RETURN(rc);

	if (init != 0) {
		rc = __osd_oi_lookup(info, dev, &LU_DOT_LUSTRE_FID, id);
		if (rc == 0) {
			inode = osd_iget(info, dev, id);
			if (IS_ERR(inode)) {
				rc = PTR_ERR(inode);
				/* It is restored from old 2.x backup. */
				if (rc == -ENOENT || rc == -ESTALE) {
					osd_scrub_file_reset(scrub, es->s_uuid,
							     SF_INCONSISTENT);
					rc = osd_scrub_file_store(scrub);
				}
			} else {
				iput(inode);
			}
		} else if (rc == -ENOENT) {
			rc = 0;
		}
	}

	if (rc == 0 && !scrub->os_no_scrub &&
	    ((sf->sf_status == SS_CRASHED &&
	      sf->sf_flags & (SF_RECREATED | SF_INCONSISTENT | SF_AUTO)) ||
	     (sf->sf_status == SS_INIT &&
	      sf->sf_flags & (SF_RECREATED | SF_INCONSISTENT))))
		rc = osd_scrub_start(dev);

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
