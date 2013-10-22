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
 * lustre/mdd/mdd_lfsck.c
 *
 * Top-level entry points into mdd module
 *
 * LFSCK controller, which scans the whole device through low layer
 * iteration APIs, drives all lfsck compeonents, controls the speed.
 *
 * Author: Fan Yong <yong.fan@whamcloud.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <lustre/lustre_idl.h>
#include <lustre_fid.h>
#include <obd_support.h>

#include "mdd_internal.h"
#include "mdd_lfsck.h"

#define HALF_SEC			(CFS_HZ >> 1)
#define LFSCK_CHECKPOINT_INTERVAL	60

#define LFSCK_NAMEENTRY_DEAD    	1 /* The object has been unlinked. */
#define LFSCK_NAMEENTRY_REMOVED 	2 /* The entry has been removed. */
#define LFSCK_NAMEENTRY_RECREATED	3 /* The entry has been recreated. */

const char lfsck_bookmark_name[] = "lfsck_bookmark";
const char lfsck_namespace_name[] = "lfsck_namespace";

static const char *lfsck_status_names[] = {
	"init",
	"scanning-phase1",
	"scanning-phase2",
	"completed",
	"failed",
	"stopped",
	"paused",
	"crashed",
	NULL
};

static const char *lfsck_flags_names[] = {
	"scanned-once",
	"inconsistent",
	"upgrade",
	NULL
};

static const char *lfsck_param_names[] = {
	"failout",
	"dryrun",
	NULL
};

/* misc functions */

static inline struct mdd_device *mdd_lfsck2mdd(struct md_lfsck *lfsck)
{
	return container_of0(lfsck, struct mdd_device, mdd_lfsck);
}

static inline char *mdd_lfsck2name(struct md_lfsck *lfsck)
{
	struct mdd_device *mdd = mdd_lfsck2mdd(lfsck);

	return mdd2obd_dev(mdd)->obd_name;
}

static inline void mdd_lfsck_component_get(struct lfsck_component *com)
{
	atomic_inc(&com->lc_ref);
}

static inline void mdd_lfsck_component_put(const struct lu_env *env,
					   struct lfsck_component *com)
{
	if (atomic_dec_and_test(&com->lc_ref)) {
		if (com->lc_obj != NULL)
			lu_object_put(env, &com->lc_obj->do_lu);
		if (com->lc_file_ram != NULL)
			OBD_FREE(com->lc_file_ram, com->lc_file_size);
		if (com->lc_file_disk != NULL)
			OBD_FREE(com->lc_file_disk, com->lc_file_size);
		OBD_FREE_PTR(com);
	}
}

static inline struct lfsck_component *
__mdd_lfsck_component_find(struct md_lfsck *lfsck, __u16 type, cfs_list_t *list)
{
	struct lfsck_component *com;

	cfs_list_for_each_entry(com, list, lc_link) {
		if (com->lc_type == type)
			return com;
	}
	return NULL;
}

static struct lfsck_component *
mdd_lfsck_component_find(struct md_lfsck *lfsck, __u16 type)
{
	struct lfsck_component *com;

	spin_lock(&lfsck->ml_lock);
	com = __mdd_lfsck_component_find(lfsck, type, &lfsck->ml_list_scan);
	if (com != NULL)
		goto unlock;

	com = __mdd_lfsck_component_find(lfsck, type,
					 &lfsck->ml_list_double_scan);
	if (com != NULL)
		goto unlock;

	com = __mdd_lfsck_component_find(lfsck, type, &lfsck->ml_list_idle);

unlock:
	if (com != NULL)
		mdd_lfsck_component_get(com);
	spin_unlock(&lfsck->ml_lock);
	return com;
}

static void mdd_lfsck_component_cleanup(const struct lu_env *env,
					struct lfsck_component *com)
{
	if (!cfs_list_empty(&com->lc_link))
		cfs_list_del_init(&com->lc_link);
	if (!cfs_list_empty(&com->lc_link_dir))
		cfs_list_del_init(&com->lc_link_dir);

	mdd_lfsck_component_put(env, com);
}

static int lfsck_bits_dump(char **buf, int *len, int bits, const char *names[],
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

static int lfsck_time_dump(char **buf, int *len, __u64 time, const char *prefix)
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

static int lfsck_pos_dump(char **buf, int *len, struct lfsck_position *pos,
			  const char *prefix)
{
	int rc;

	if (fid_is_zero(&pos->lp_dir_parent)) {
		if (pos->lp_oit_cookie == 0)
			rc = snprintf(*buf, *len, "%s: N/A, N/A, N/A\n",
				      prefix);
		else
			rc = snprintf(*buf, *len, "%s: "LPU64", N/A, N/A\n",
				      prefix, pos->lp_oit_cookie);
	} else {
		rc = snprintf(*buf, *len, "%s: "LPU64", "DFID", "LPU64"\n",
			      prefix, pos->lp_oit_cookie,
			      PFID(&pos->lp_dir_parent), pos->lp_dir_cookie);
	}
	if (rc <= 0)
		return -ENOSPC;

	*buf += rc;
	*len -= rc;
	return rc;
}

static void mdd_lfsck_pos_fill(const struct lu_env *env, struct md_lfsck *lfsck,
			       struct lfsck_position *pos, bool init)
{
	const struct dt_it_ops *iops = &lfsck->ml_obj_oit->do_index_ops->dio_it;

	spin_lock(&lfsck->ml_lock);
	if (unlikely(lfsck->ml_di_oit == NULL)) {
		spin_unlock(&lfsck->ml_lock);
		memset(pos, 0, sizeof(*pos));
		return;
	}

	pos->lp_oit_cookie = iops->store(env, lfsck->ml_di_oit);
	if (!lfsck->ml_current_oit_processed && !init)
		pos->lp_oit_cookie--;

	LASSERT(pos->lp_oit_cookie > 0);

	if (lfsck->ml_di_dir != NULL) {
		struct dt_object *dto = lfsck->ml_obj_dir;

		pos->lp_dir_cookie = dto->do_index_ops->dio_it.store(env,
							lfsck->ml_di_dir);

		if (pos->lp_dir_cookie >= MDS_DIR_END_OFF) {
			fid_zero(&pos->lp_dir_parent);
			pos->lp_dir_cookie = 0;
		} else {
			pos->lp_dir_parent = *lu_object_fid(&dto->do_lu);
		}
	} else {
		fid_zero(&pos->lp_dir_parent);
		pos->lp_dir_cookie = 0;
	}
	spin_unlock(&lfsck->ml_lock);
}

static inline void mdd_lfsck_pos_set_zero(struct lfsck_position *pos)
{
	memset(pos, 0, sizeof(*pos));
}

static inline int mdd_lfsck_pos_is_zero(const struct lfsck_position *pos)
{
	return pos->lp_oit_cookie == 0 && fid_is_zero(&pos->lp_dir_parent);
}

static inline int mdd_lfsck_pos_is_eq(const struct lfsck_position *pos1,
				      const struct lfsck_position *pos2)
{
	if (pos1->lp_oit_cookie < pos2->lp_oit_cookie)
		return -1;

	if (pos1->lp_oit_cookie > pos2->lp_oit_cookie)
		return 1;

	if (fid_is_zero(&pos1->lp_dir_parent) &&
	    !fid_is_zero(&pos2->lp_dir_parent))
		return -1;

	if (!fid_is_zero(&pos1->lp_dir_parent) &&
	    fid_is_zero(&pos2->lp_dir_parent))
		return 1;

	if (fid_is_zero(&pos1->lp_dir_parent) &&
	    fid_is_zero(&pos2->lp_dir_parent))
		return 0;

	LASSERT(lu_fid_eq(&pos1->lp_dir_parent, &pos2->lp_dir_parent));

	if (pos1->lp_dir_cookie < pos2->lp_dir_cookie)
		return -1;

	if (pos1->lp_dir_cookie > pos2->lp_dir_cookie)
		return 1;

	return 0;
}

static void mdd_lfsck_close_dir(const struct lu_env *env,
				struct md_lfsck *lfsck)
{
	struct dt_object	*dir_obj  = lfsck->ml_obj_dir;
	const struct dt_it_ops	*dir_iops = &dir_obj->do_index_ops->dio_it;
	struct dt_it		*dir_di   = lfsck->ml_di_dir;

	spin_lock(&lfsck->ml_lock);
	lfsck->ml_di_dir = NULL;
	spin_unlock(&lfsck->ml_lock);

	dir_iops->put(env, dir_di);
	dir_iops->fini(env, dir_di);
	lfsck->ml_obj_dir = NULL;
	lu_object_put(env, &dir_obj->do_lu);
}

static void __mdd_lfsck_set_speed(struct md_lfsck *lfsck, __u32 limit)
{
	lfsck->ml_bookmark_ram.lb_speed_limit = limit;
	if (limit != LFSCK_SPEED_NO_LIMIT) {
		if (limit > CFS_HZ) {
			lfsck->ml_sleep_rate = limit / CFS_HZ;
			lfsck->ml_sleep_jif = 1;
		} else {
			lfsck->ml_sleep_rate = 1;
			lfsck->ml_sleep_jif = CFS_HZ / limit;
		}
	} else {
		lfsck->ml_sleep_jif = 0;
		lfsck->ml_sleep_rate = 0;
	}
}

static void mdd_lfsck_control_speed(struct md_lfsck *lfsck)
{
	struct ptlrpc_thread *thread = &lfsck->ml_thread;
	struct l_wait_info    lwi;

	if (lfsck->ml_sleep_jif > 0 &&
	    lfsck->ml_new_scanned >= lfsck->ml_sleep_rate) {
		spin_lock(&lfsck->ml_lock);
		if (likely(lfsck->ml_sleep_jif > 0 &&
			   lfsck->ml_new_scanned >= lfsck->ml_sleep_rate)) {
			lwi = LWI_TIMEOUT_INTR(lfsck->ml_sleep_jif, NULL,
					       LWI_ON_SIGNAL_NOOP, NULL);
			spin_unlock(&lfsck->ml_lock);

			l_wait_event(thread->t_ctl_waitq,
				     !thread_is_running(thread),
				     &lwi);
			lfsck->ml_new_scanned = 0;
		} else {
			spin_unlock(&lfsck->ml_lock);
		}
	}
}

/* lfsck_bookmark file ops */

static void inline mdd_lfsck_bookmark_to_cpu(struct lfsck_bookmark *des,
					     struct lfsck_bookmark *src)
{
	des->lb_magic = le32_to_cpu(src->lb_magic);
	des->lb_version = le16_to_cpu(src->lb_version);
	des->lb_param = le16_to_cpu(src->lb_param);
	des->lb_speed_limit = le32_to_cpu(src->lb_speed_limit);
}

static void inline mdd_lfsck_bookmark_to_le(struct lfsck_bookmark *des,
					    struct lfsck_bookmark *src)
{
	des->lb_magic = cpu_to_le32(src->lb_magic);
	des->lb_version = cpu_to_le16(src->lb_version);
	des->lb_param = cpu_to_le16(src->lb_param);
	des->lb_speed_limit = cpu_to_le32(src->lb_speed_limit);
}

static int mdd_lfsck_bookmark_load(const struct lu_env *env,
				   struct md_lfsck *lfsck)
{
	loff_t pos = 0;
	int    len = sizeof(struct lfsck_bookmark);
	int    rc;

	rc = dt_record_read(env, lfsck->ml_bookmark_obj,
			    mdd_buf_get(env, &lfsck->ml_bookmark_disk, len),
			    &pos);
	if (rc == 0) {
		struct lfsck_bookmark *bm = &lfsck->ml_bookmark_ram;

		mdd_lfsck_bookmark_to_cpu(bm, &lfsck->ml_bookmark_disk);
		if (bm->lb_magic != LFSCK_BOOKMARK_MAGIC) {
			CWARN("%.16s: invalid lfsck_bookmark magic "
			      "0x%x != 0x%x\n", mdd_lfsck2name(lfsck),
			      bm->lb_magic, LFSCK_BOOKMARK_MAGIC);
			/* Process it as new lfsck_bookmark. */
			rc = -ENODATA;
		}
	} else {
		if (rc == -EFAULT && pos == 0)
			/* return -ENODATA for empty lfsck_bookmark. */
			rc = -ENODATA;
		else
			CERROR("%.16s: fail to load lfsck_bookmark, "
			       "expected = %d, rc = %d\n",
			       mdd_lfsck2name(lfsck), len, rc);
	}
	return rc;
}

static int mdd_lfsck_bookmark_store(const struct lu_env *env,
				    struct md_lfsck *lfsck)
{
	struct mdd_device *mdd    = mdd_lfsck2mdd(lfsck);
	struct thandle    *handle;
	struct dt_object  *obj    = lfsck->ml_bookmark_obj;
	loff_t		   pos    = 0;
	int		   len    = sizeof(struct lfsck_bookmark);
	int		   rc;
	ENTRY;

	mdd_lfsck_bookmark_to_le(&lfsck->ml_bookmark_disk,
				 &lfsck->ml_bookmark_ram);
	handle = dt_trans_create(env, mdd->mdd_bottom);
	if (IS_ERR(handle)) {
		rc = PTR_ERR(handle);
		CERROR("%.16s: fail to create trans for storing "
		       "lfsck_bookmark: %d\n,", mdd_lfsck2name(lfsck), rc);
		RETURN(rc);
	}

	rc = dt_declare_record_write(env, obj, len, 0, handle);
	if (rc != 0) {
		CERROR("%.16s: fail to declare trans for storing "
		       "lfsck_bookmark: %d\n,", mdd_lfsck2name(lfsck), rc);
		GOTO(out, rc);
	}

	rc = dt_trans_start_local(env, mdd->mdd_bottom, handle);
	if (rc != 0) {
		CERROR("%.16s: fail to start trans for storing "
		       "lfsck_bookmark: %d\n,", mdd_lfsck2name(lfsck), rc);
		GOTO(out, rc);
	}

	rc = dt_record_write(env, obj,
			     mdd_buf_get(env, &lfsck->ml_bookmark_disk, len),
			     &pos, handle);
	if (rc != 0)
		CERROR("%.16s: fail to store lfsck_bookmark, expected = %d, "
		       "rc = %d\n", mdd_lfsck2name(lfsck), len, rc);

	GOTO(out, rc);

out:
	dt_trans_stop(env, mdd->mdd_bottom, handle);
	return rc;
}

static int mdd_lfsck_bookmark_init(const struct lu_env *env,
				   struct md_lfsck *lfsck)
{
	struct lfsck_bookmark *mb = &lfsck->ml_bookmark_ram;
	int rc;

	memset(mb, 0, sizeof(*mb));
	mb->lb_magic = LFSCK_BOOKMARK_MAGIC;
	mb->lb_version = LFSCK_VERSION_V2;
	mutex_lock(&lfsck->ml_mutex);
	rc = mdd_lfsck_bookmark_store(env, lfsck);
	mutex_unlock(&lfsck->ml_mutex);
	return rc;
}

/* lfsck_namespace file ops */

static void inline mdd_lfsck_position_to_cpu(struct lfsck_position *des,
					     struct lfsck_position *src)
{
	des->lp_oit_cookie = le64_to_cpu(src->lp_oit_cookie);
	fid_le_to_cpu(&des->lp_dir_parent, &src->lp_dir_parent);
	des->lp_dir_cookie = le64_to_cpu(src->lp_dir_cookie);
}

static void inline mdd_lfsck_position_to_le(struct lfsck_position *des,
					     struct lfsck_position *src)
{
	des->lp_oit_cookie = cpu_to_le64(src->lp_oit_cookie);
	fid_cpu_to_le(&des->lp_dir_parent, &src->lp_dir_parent);
	des->lp_dir_cookie = cpu_to_le64(src->lp_dir_cookie);
}

static void inline mdd_lfsck_namespace_to_cpu(struct lfsck_namespace *des,
					      struct lfsck_namespace *src)
{
	des->ln_magic = le32_to_cpu(src->ln_magic);
	des->ln_status = le32_to_cpu(src->ln_status);
	des->ln_flags = le32_to_cpu(src->ln_flags);
	des->ln_success_count = le32_to_cpu(src->ln_success_count);
	des->ln_run_time_phase1 = le32_to_cpu(src->ln_run_time_phase1);
	des->ln_run_time_phase2 = le32_to_cpu(src->ln_run_time_phase2);
	des->ln_time_last_complete = le64_to_cpu(src->ln_time_last_complete);
	des->ln_time_latest_start = le64_to_cpu(src->ln_time_latest_start);
	des->ln_time_last_checkpoint =
				le64_to_cpu(src->ln_time_last_checkpoint);
	mdd_lfsck_position_to_cpu(&des->ln_pos_latest_start,
				  &src->ln_pos_latest_start);
	mdd_lfsck_position_to_cpu(&des->ln_pos_last_checkpoint,
				  &src->ln_pos_last_checkpoint);
	mdd_lfsck_position_to_cpu(&des->ln_pos_first_inconsistent,
				  &src->ln_pos_first_inconsistent);
	des->ln_items_checked = le64_to_cpu(src->ln_items_checked);
	des->ln_items_repaired = le64_to_cpu(src->ln_items_repaired);
	des->ln_items_failed = le64_to_cpu(src->ln_items_failed);
	des->ln_dirs_checked = le64_to_cpu(src->ln_dirs_checked);
	des->ln_mlinked_checked = le64_to_cpu(src->ln_mlinked_checked);
	des->ln_objs_checked_phase2 = le64_to_cpu(src->ln_objs_checked_phase2);
	des->ln_objs_repaired_phase2 =
				le64_to_cpu(src->ln_objs_repaired_phase2);
	des->ln_objs_failed_phase2 = le64_to_cpu(src->ln_objs_failed_phase2);
	des->ln_objs_nlink_repaired = le64_to_cpu(src->ln_objs_nlink_repaired);
	des->ln_objs_lost_found = le64_to_cpu(src->ln_objs_lost_found);
	fid_le_to_cpu(&des->ln_fid_latest_scanned_phase2,
		      &src->ln_fid_latest_scanned_phase2);
}

static void inline mdd_lfsck_namespace_to_le(struct lfsck_namespace *des,
					     struct lfsck_namespace *src)
{
	des->ln_magic = cpu_to_le32(src->ln_magic);
	des->ln_status = cpu_to_le32(src->ln_status);
	des->ln_flags = cpu_to_le32(src->ln_flags);
	des->ln_success_count = cpu_to_le32(src->ln_success_count);
	des->ln_run_time_phase1 = cpu_to_le32(src->ln_run_time_phase1);
	des->ln_run_time_phase2 = cpu_to_le32(src->ln_run_time_phase2);
	des->ln_time_last_complete = cpu_to_le64(src->ln_time_last_complete);
	des->ln_time_latest_start = cpu_to_le64(src->ln_time_latest_start);
	des->ln_time_last_checkpoint =
				cpu_to_le64(src->ln_time_last_checkpoint);
	mdd_lfsck_position_to_le(&des->ln_pos_latest_start,
				 &src->ln_pos_latest_start);
	mdd_lfsck_position_to_le(&des->ln_pos_last_checkpoint,
				 &src->ln_pos_last_checkpoint);
	mdd_lfsck_position_to_le(&des->ln_pos_first_inconsistent,
				 &src->ln_pos_first_inconsistent);
	des->ln_items_checked = cpu_to_le64(src->ln_items_checked);
	des->ln_items_repaired = cpu_to_le64(src->ln_items_repaired);
	des->ln_items_failed = cpu_to_le64(src->ln_items_failed);
	des->ln_dirs_checked = cpu_to_le64(src->ln_dirs_checked);
	des->ln_mlinked_checked = cpu_to_le64(src->ln_mlinked_checked);
	des->ln_objs_checked_phase2 = cpu_to_le64(src->ln_objs_checked_phase2);
	des->ln_objs_repaired_phase2 =
				cpu_to_le64(src->ln_objs_repaired_phase2);
	des->ln_objs_failed_phase2 = cpu_to_le64(src->ln_objs_failed_phase2);
	des->ln_objs_nlink_repaired = cpu_to_le64(src->ln_objs_nlink_repaired);
	des->ln_objs_lost_found = cpu_to_le64(src->ln_objs_lost_found);
	fid_cpu_to_le(&des->ln_fid_latest_scanned_phase2,
		      &src->ln_fid_latest_scanned_phase2);
}

/**
 * \retval +ve: the lfsck_namespace is broken, the caller should reset it.
 * \retval 0: succeed.
 * \retval -ve: failed cases.
 */
static int mdd_lfsck_namespace_load(const struct lu_env *env,
				    struct lfsck_component *com)
{
	int len = com->lc_file_size;
	int rc;

	rc = dt_xattr_get(env, com->lc_obj,
			  mdd_buf_get(env, com->lc_file_disk, len),
			  XATTR_NAME_LFSCK_NAMESPACE, BYPASS_CAPA);
	if (rc == len) {
		struct lfsck_namespace *ns = com->lc_file_ram;

		mdd_lfsck_namespace_to_cpu(ns,
				(struct lfsck_namespace *)com->lc_file_disk);
		if (ns->ln_magic != LFSCK_NAMESPACE_MAGIC) {
			CWARN("%.16s: invalid lfsck_namespace magic "
			      "0x%x != 0x%x\n",
			      mdd_lfsck2name(com->lc_lfsck),
			      ns->ln_magic, LFSCK_NAMESPACE_MAGIC);
			rc = 1;
		} else {
			rc = 0;
		}
	} else if (rc != -ENODATA) {
		CERROR("%.16s: fail to load lfsck_namespace, expected = %d, "
		       "rc = %d\n", mdd_lfsck2name(com->lc_lfsck), len, rc);
		if (rc >= 0)
			rc = 1;
	}
	return rc;
}

static int mdd_lfsck_namespace_store(const struct lu_env *env,
				     struct lfsck_component *com, bool init)
{
	struct dt_object  *obj    = com->lc_obj;
	struct md_lfsck   *lfsck  = com->lc_lfsck;
	struct mdd_device *mdd    = mdd_lfsck2mdd(lfsck);
	struct thandle    *handle;
	int		   len    = com->lc_file_size;
	int		   rc;
	ENTRY;

	mdd_lfsck_namespace_to_le((struct lfsck_namespace *)com->lc_file_disk,
				  (struct lfsck_namespace *)com->lc_file_ram);
	handle = dt_trans_create(env, mdd->mdd_bottom);
	if (IS_ERR(handle)) {
		rc = PTR_ERR(handle);
		CERROR("%.16s: fail to create trans for storing "
		       "lfsck_namespace: %d\n,", mdd_lfsck2name(lfsck), rc);
		RETURN(rc);
	}

	rc = dt_declare_xattr_set(env, obj,
				  mdd_buf_get(env, com->lc_file_disk, len),
				  XATTR_NAME_LFSCK_NAMESPACE, 0, handle);
	if (rc != 0) {
		CERROR("%.16s: fail to declare trans for storing "
		       "lfsck_namespace: %d\n,", mdd_lfsck2name(lfsck), rc);
		GOTO(out, rc);
	}

	rc = dt_trans_start_local(env, mdd->mdd_bottom, handle);
	if (rc != 0) {
		CERROR("%.16s: fail to start trans for storing "
		       "lfsck_namespace: %d\n,", mdd_lfsck2name(lfsck), rc);
		GOTO(out, rc);
	}

	rc = dt_xattr_set(env, obj,
			  mdd_buf_get(env, com->lc_file_disk, len),
			  XATTR_NAME_LFSCK_NAMESPACE,
			  init ? LU_XATTR_CREATE : LU_XATTR_REPLACE,
			  handle, BYPASS_CAPA);
	if (rc != 0)
		CERROR("%.16s: fail to store lfsck_namespace, len = %d, "
		       "rc = %d\n", mdd_lfsck2name(lfsck), len, rc);

	GOTO(out, rc);

out:
	dt_trans_stop(env, mdd->mdd_bottom, handle);
	return rc;
}

static int mdd_lfsck_namespace_init(const struct lu_env *env,
				    struct lfsck_component *com)
{
	struct lfsck_namespace *ns = (struct lfsck_namespace *)com->lc_file_ram;
	int rc;

	memset(ns, 0, sizeof(*ns));
	ns->ln_magic = LFSCK_NAMESPACE_MAGIC;
	ns->ln_status = LS_INIT;
	down_write(&com->lc_sem);
	rc = mdd_lfsck_namespace_store(env, com, true);
	up_write(&com->lc_sem);
	return rc;
}

static int mdd_lfsck_namespace_lookup(const struct lu_env *env,
				      struct lfsck_component *com,
				      const struct lu_fid *fid,
				      __u8 *flags)
{
	struct lu_fid *key = &mdd_env_info(env)->mti_fid;
	int	       rc;

	fid_cpu_to_be(key, fid);
	rc = dt_lookup(env, com->lc_obj, (struct dt_rec *)flags,
		       (const struct dt_key *)key, BYPASS_CAPA);
	return rc;
}

static int mdd_lfsck_namespace_delete(const struct lu_env *env,
				      struct lfsck_component *com,
				      const struct lu_fid *fid)
{
	struct mdd_device *mdd    = mdd_lfsck2mdd(com->lc_lfsck);
	struct lu_fid	  *key    = &mdd_env_info(env)->mti_fid;
	struct thandle    *handle;
	struct dt_object *obj     = com->lc_obj;
	int		  rc;
	ENTRY;

	handle = dt_trans_create(env, mdd->mdd_bottom);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	rc = dt_declare_delete(env, obj, (const struct dt_key *)fid, handle);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, mdd->mdd_bottom, handle);
	if (rc != 0)
		GOTO(out, rc);

	fid_cpu_to_be(key, fid);
	rc = dt_delete(env, obj, (const struct dt_key *)key, handle,
		       BYPASS_CAPA);

	GOTO(out, rc);

out:
	dt_trans_stop(env, mdd->mdd_bottom, handle);
	return rc;
}

static int mdd_lfsck_namespace_update(const struct lu_env *env,
				      struct lfsck_component *com,
				      const struct lu_fid *fid,
				      __u8 flags, bool force)
{
	struct mdd_device *mdd    = mdd_lfsck2mdd(com->lc_lfsck);
	struct lu_fid	  *key    = &mdd_env_info(env)->mti_fid;
	struct thandle    *handle;
	struct dt_object *obj     = com->lc_obj;
	int		  rc;
	bool		  exist   = false;
	__u8		  tf;
	ENTRY;

	rc = mdd_lfsck_namespace_lookup(env, com, fid, &tf);
	if (rc != 0 && rc != -ENOENT)
		RETURN(rc);

	if (rc == 0) {
		if (!force || flags == tf)
			RETURN(0);

		exist = true;
		handle = dt_trans_create(env, mdd->mdd_bottom);
		if (IS_ERR(handle))
			RETURN(PTR_ERR(handle));

		rc = dt_declare_delete(env, obj, (const struct dt_key *)fid,
				       handle);
		if (rc != 0)
			GOTO(out, rc);
	} else {
		handle = dt_trans_create(env, mdd->mdd_bottom);
		if (IS_ERR(handle))
			RETURN(PTR_ERR(handle));
	}

	rc = dt_declare_insert(env, obj, (const struct dt_rec *)&flags,
			       (const struct dt_key *)fid, handle);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, mdd->mdd_bottom, handle);
	if (rc != 0)
		GOTO(out, rc);

	fid_cpu_to_be(key, fid);
	if (exist) {
		rc = dt_delete(env, obj, (const struct dt_key *)key, handle,
			       BYPASS_CAPA);
		if (rc != 0) {
			CERROR("%s: fail to insert "DFID", rc = %d\n",
			       mdd_lfsck2name(com->lc_lfsck), PFID(fid), rc);
			GOTO(out, rc);
		}
	}

	rc = dt_insert(env, obj, (const struct dt_rec *)&flags,
		       (const struct dt_key *)key, handle, BYPASS_CAPA, 1);

	GOTO(out, rc);

out:
	dt_trans_stop(env, mdd->mdd_bottom, handle);
	return rc;
}

/**
 * \retval +ve	repaired
 * \retval 0	no need to repair
 * \retval -ve	error cases
 */
static int mdd_lfsck_namespace_double_scan_one(const struct lu_env *env,
					       struct lfsck_component *com,
					       struct mdd_object *child,
					       __u8 flags)
{
	struct mdd_thread_info	*info	  = mdd_env_info(env);
	struct lu_attr		*la	  = &info->mti_la;
	struct lu_name		*cname	  = &info->mti_name;
	struct lu_fid		*pfid	  = &info->mti_fid;
	struct lu_fid		*cfid	  = &info->mti_fid2;
	struct md_lfsck		*lfsck	  = com->lc_lfsck;
	struct mdd_device	*mdd	  = mdd_lfsck2mdd(lfsck);
	struct lfsck_bookmark	*bk	  = &lfsck->ml_bookmark_ram;
	struct lfsck_namespace	*ns	  =
				(struct lfsck_namespace *)com->lc_file_ram;
	struct linkea_data	 ldata	  = { 0 };
	struct thandle		*handle   = NULL;
	bool			 locked   = false;
	bool			 update	  = false;
	int			 count;
	int			 rc;
	ENTRY;

	if (com->lc_journal) {

again:
		LASSERT(!locked);

		com->lc_journal = 1;
		handle = mdd_trans_create(env, mdd);
		if (IS_ERR(handle))
			RETURN(rc = PTR_ERR(handle));

		rc = mdd_declare_links_add(env, child, handle, NULL);
		if (rc != 0)
			GOTO(stop, rc);

		rc = mdd_trans_start(env, mdd, handle);
		if (rc != 0)
			GOTO(stop, rc);

		mdd_write_lock(env, child, MOR_TGT_CHILD);
		locked = true;
	}

	if (unlikely(mdd_is_dead_obj(child)))
		GOTO(stop, rc = 0);

	rc = mdd_links_read(env, child, &ldata);
	if (rc != 0) {
		if ((bk->lb_param & LPF_DRYRUN) &&
		    (rc == -EINVAL || rc == -ENODATA))
			rc = 1;

		GOTO(stop, rc);
	}

	rc = mdd_la_get(env, child, la, BYPASS_CAPA);
	if (rc != 0)
		GOTO(stop, rc);

	ldata.ld_lee = LINKEA_FIRST_ENTRY(ldata);
	count = ldata.ld_leh->leh_reccount;
	while (count-- > 0) {
		struct mdd_object *parent = NULL;
		struct dt_object *dir;

		linkea_entry_unpack(ldata.ld_lee, &ldata.ld_reclen, cname,
				    pfid);
		if (!fid_is_sane(pfid))
			goto shrink;

		parent = mdd_object_find(env, mdd, pfid);
		if (parent == NULL)
			goto shrink;
		else if (IS_ERR(parent))
			GOTO(stop, rc = PTR_ERR(parent));

		if (!mdd_object_exists(parent))
			goto shrink;

		/* XXX: Currently, skip remote object, the consistency for
		 *	remote object will be processed in LFSCK phase III. */
		if (mdd_object_remote(parent)) {
			mdd_object_put(env, parent);
			ldata.ld_lee = LINKEA_NEXT_ENTRY(ldata);
			continue;
		}

		dir = mdd_object_child(parent);
		if (unlikely(!dt_try_as_dir(env, dir)))
			goto shrink;

		/* To guarantee the 'name' is terminated with '0'. */
		memcpy(info->mti_key, cname->ln_name, cname->ln_namelen);
		info->mti_key[cname->ln_namelen] = 0;
		cname->ln_name = info->mti_key;
		rc = dt_lookup(env, dir, (struct dt_rec *)cfid,
			       (const struct dt_key *)cname->ln_name,
			       BYPASS_CAPA);
		if (rc != 0 && rc != -ENOENT) {
			mdd_object_put(env, parent);
			GOTO(stop, rc);
		}

		if (rc == 0) {
			if (lu_fid_eq(cfid, mdo2fid(child))) {
				mdd_object_put(env, parent);
				ldata.ld_lee = LINKEA_NEXT_ENTRY(ldata);
				continue;
			}

			goto shrink;
		}

		if (ldata.ld_leh->leh_reccount > la->la_nlink)
			goto shrink;

		/* XXX: For the case of there is linkea entry, but without name
		 *	entry pointing to the object, and the object link count
		 *	isn't less than the count of name entries, then add the
		 *	name entry back to namespace.
		 *
		 *	It is out of LFSCK 1.5 scope, will implement it in the
		 *	future. Keep the linkEA entry. */
		mdd_object_put(env, parent);
		ldata.ld_lee = LINKEA_NEXT_ENTRY(ldata);
		continue;

shrink:
		if (parent != NULL)
			mdd_object_put(env, parent);
		if (bk->lb_param & LPF_DRYRUN)
			RETURN(1);

		CDEBUG(D_LFSCK, "Remove linkEA: "DFID"[%.*s], "DFID"\n",
		       PFID(mdo2fid(child)), cname->ln_namelen, cname->ln_name,
		       PFID(pfid));
		linkea_del_buf(&ldata, cname);
		update = true;
	}

	if (update) {
		if (!com->lc_journal) {
			com->lc_journal = 1;
			goto again;
		}

		rc = mdd_links_write(env, child, &ldata, handle);
	}

	GOTO(stop, rc);

stop:
	if (locked)
		mdd_write_unlock(env, child);

	if (handle != NULL)
		mdd_trans_stop(env, mdd, rc, handle);

	if (rc == 0 && update) {
		ns->ln_objs_nlink_repaired++;
		rc = 1;
	}
	return rc;
}

/* namespace APIs */

static int mdd_lfsck_namespace_reset(const struct lu_env *env,
				     struct lfsck_component *com, bool init)
{
	struct lfsck_namespace	*ns   = (struct lfsck_namespace *)com->lc_file_ram;
	struct mdd_device	*mdd  = mdd_lfsck2mdd(com->lc_lfsck);
	struct dt_object	*dto, *root;
	int			 rc;
	ENTRY;

	down_write(&com->lc_sem);
	if (init) {
		memset(ns, 0, sizeof(*ns));
	} else {
		__u32 count = ns->ln_success_count;
		__u64 last_time = ns->ln_time_last_complete;

		memset(ns, 0, sizeof(*ns));
		ns->ln_success_count = count;
		ns->ln_time_last_complete = last_time;
	}
	ns->ln_magic = LFSCK_NAMESPACE_MAGIC;
	ns->ln_status = LS_INIT;

	root = dt_locate(env, mdd->mdd_bottom, &mdd->mdd_local_root_fid);
	if (unlikely(IS_ERR(root)))
		GOTO(out, rc = PTR_ERR(root));

	rc = local_object_unlink(env, mdd->mdd_bottom, root,
				 lfsck_namespace_name);
	if (rc != 0)
		GOTO(out, rc);

	lu_object_put(env, &com->lc_obj->do_lu);
	com->lc_obj = NULL;
	dto = local_index_find_or_create(env, mdd->mdd_los, root,
					 lfsck_namespace_name,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 &dt_lfsck_features);
	if (IS_ERR(dto))
		GOTO(out, rc = PTR_ERR(dto));

	rc = dto->do_ops->do_index_try(env, dto, &dt_lfsck_features);
	if (rc != 0)
		GOTO(out, rc);
	com->lc_obj = dto;

	rc = mdd_lfsck_namespace_store(env, com, true);

	GOTO(out, rc);
out:
	lu_object_put(env, &root->do_lu);
	up_write(&com->lc_sem);
	return rc;
}

static void
mdd_lfsck_namespace_fail(const struct lu_env *env, struct lfsck_component *com,
			 bool new_checked)
{
	struct lfsck_namespace *ns = (struct lfsck_namespace *)com->lc_file_ram;

	down_write(&com->lc_sem);
	if (new_checked)
		com->lc_new_checked++;
	ns->ln_items_failed++;
	if (mdd_lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent))
		mdd_lfsck_pos_fill(env, com->lc_lfsck,
				   &ns->ln_pos_first_inconsistent, false);
	up_write(&com->lc_sem);
}

static int mdd_lfsck_namespace_checkpoint(const struct lu_env *env,
					  struct lfsck_component *com,
					  bool init)
{
	struct md_lfsck		*lfsck = com->lc_lfsck;
	struct lfsck_namespace	*ns    =
				(struct lfsck_namespace *)com->lc_file_ram;
	int			 rc;

	if (com->lc_new_checked == 0 && !init)
		return 0;

	down_write(&com->lc_sem);

	if (init) {
		ns->ln_pos_latest_start = lfsck->ml_pos_current;
	} else {
		ns->ln_pos_last_checkpoint = lfsck->ml_pos_current;
		ns->ln_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->ml_time_last_checkpoint);
		ns->ln_time_last_checkpoint = cfs_time_current_sec();
		ns->ln_items_checked += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = mdd_lfsck_namespace_store(env, com, false);

	up_write(&com->lc_sem);
	return rc;
}

static int mdd_lfsck_namespace_prep(const struct lu_env *env,
				    struct lfsck_component *com)
{
	struct md_lfsck		*lfsck	= com->lc_lfsck;
	struct lfsck_namespace	*ns	=
				(struct lfsck_namespace *)com->lc_file_ram;
	struct lfsck_position	*pos	= &com->lc_pos_start;

	if (ns->ln_status == LS_COMPLETED) {
		int rc;

		rc = mdd_lfsck_namespace_reset(env, com, false);
		if (rc != 0)
			return rc;
	}

	down_write(&com->lc_sem);

	ns->ln_time_latest_start = cfs_time_current_sec();

	spin_lock(&lfsck->ml_lock);
	if (ns->ln_flags & LF_SCANNED_ONCE) {
		if (!lfsck->ml_drop_dryrun ||
		    mdd_lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent)) {
			ns->ln_status = LS_SCANNING_PHASE2;
			cfs_list_del_init(&com->lc_link);
			cfs_list_add_tail(&com->lc_link,
					  &lfsck->ml_list_double_scan);
			if (!cfs_list_empty(&com->lc_link_dir))
				cfs_list_del_init(&com->lc_link_dir);
			mdd_lfsck_pos_set_zero(pos);
		} else {
			ns->ln_status = LS_SCANNING_PHASE1;
			ns->ln_run_time_phase1 = 0;
			ns->ln_run_time_phase2 = 0;
			ns->ln_items_checked = 0;
			ns->ln_items_repaired = 0;
			ns->ln_items_failed = 0;
			ns->ln_dirs_checked = 0;
			ns->ln_mlinked_checked = 0;
			ns->ln_objs_checked_phase2 = 0;
			ns->ln_objs_repaired_phase2 = 0;
			ns->ln_objs_failed_phase2 = 0;
			ns->ln_objs_nlink_repaired = 0;
			ns->ln_objs_lost_found = 0;
			fid_zero(&ns->ln_fid_latest_scanned_phase2);
			if (cfs_list_empty(&com->lc_link_dir))
				cfs_list_add_tail(&com->lc_link_dir,
						  &lfsck->ml_list_dir);
			*pos = ns->ln_pos_first_inconsistent;
		}
	} else {
		ns->ln_status = LS_SCANNING_PHASE1;
		if (cfs_list_empty(&com->lc_link_dir))
			cfs_list_add_tail(&com->lc_link_dir,
					  &lfsck->ml_list_dir);
		if (!lfsck->ml_drop_dryrun ||
		    mdd_lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent)) {
			*pos = ns->ln_pos_last_checkpoint;
			pos->lp_oit_cookie++;
		} else {
			*pos = ns->ln_pos_first_inconsistent;
		}
	}
	spin_unlock(&lfsck->ml_lock);

	up_write(&com->lc_sem);
	return 0;
}

static int mdd_lfsck_namespace_exec_oit(const struct lu_env *env,
					struct lfsck_component *com,
					struct mdd_object *obj)
{
	down_write(&com->lc_sem);
	com->lc_new_checked++;
	if (S_ISDIR(mdd_object_type(obj)))
		((struct lfsck_namespace *)com->lc_file_ram)->ln_dirs_checked++;
	up_write(&com->lc_sem);
	return 0;
}

static int mdd_declare_lfsck_namespace_exec_dir(const struct lu_env *env,
						struct mdd_object *obj,
						struct thandle *handle)
{
	int rc;

	/* For destroying all invalid linkEA entries. */
	rc = mdo_declare_xattr_del(env, obj, XATTR_NAME_LINK, handle);
	if (rc != 0)
		return rc;

	/* For insert new linkEA entry. */
	rc = mdd_declare_links_add(env, obj, handle, NULL);
	return rc;
}

static int mdd_lfsck_namespace_check_exist(const struct lu_env *env,
					   struct md_lfsck *lfsck,
					   struct mdd_object *obj,
					   const char *name)
{
	struct dt_object *dir = lfsck->ml_obj_dir;
	struct lu_fid	 *fid = &mdd_env_info(env)->mti_fid;
	int		  rc;
	ENTRY;

	if (unlikely(mdd_is_dead_obj(obj)))
		RETURN(LFSCK_NAMEENTRY_DEAD);

	rc = dt_lookup(env, dir, (struct dt_rec *)fid,
		       (const struct dt_key *)name, BYPASS_CAPA);
	if (rc == -ENOENT)
		RETURN(LFSCK_NAMEENTRY_REMOVED);

	if (rc < 0)
		RETURN(rc);

	if (!lu_fid_eq(fid, mdo2fid(obj)))
		RETURN(LFSCK_NAMEENTRY_RECREATED);

	RETURN(0);
}

static int mdd_lfsck_namespace_exec_dir(const struct lu_env *env,
					struct lfsck_component *com,
					struct mdd_object *obj,
					struct lu_dirent *ent)
{
	struct mdd_thread_info	   *info     = mdd_env_info(env);
	struct lu_attr		   *la	     = &info->mti_la;
	struct md_lfsck		   *lfsck    = com->lc_lfsck;
	struct lfsck_bookmark	   *bk	     = &lfsck->ml_bookmark_ram;
	struct lfsck_namespace	   *ns	     =
				(struct lfsck_namespace *)com->lc_file_ram;
	struct mdd_device	   *mdd      = mdd_lfsck2mdd(lfsck);
	struct linkea_data	    ldata    = { 0 };
	const struct lu_fid	   *pfid     =
				lu_object_fid(&lfsck->ml_obj_dir->do_lu);
	const struct lu_fid	   *cfid     = mdo2fid(obj);
	const struct lu_name	   *cname;
	struct thandle		   *handle   = NULL;
	bool			    repaired = false;
	bool			    locked   = false;
	int			    count    = 0;
	int			    rc;
	ENTRY;

	cname = mdd_name_get_const(env, ent->lde_name, ent->lde_namelen);
	down_write(&com->lc_sem);
	com->lc_new_checked++;

	if (ent->lde_attrs & LUDA_UPGRADE) {
		ns->ln_flags |= LF_UPGRADE;
		repaired = true;
	} else if (ent->lde_attrs & LUDA_REPAIR) {
		ns->ln_flags |= LF_INCONSISTENT;
		repaired = true;
	}

	if (ent->lde_name[0] == '.' &&
	    (ent->lde_namelen == 1 ||
	     (ent->lde_namelen == 2 && ent->lde_name[1] == '.') ||
	     fid_is_dot_lustre(&ent->lde_fid)))
		GOTO(out, rc = 0);

	if (!(bk->lb_param & LPF_DRYRUN) &&
	    (com->lc_journal || repaired)) {

again:
		LASSERT(!locked);

		com->lc_journal = 1;
		handle = mdd_trans_create(env, mdd);
		if (IS_ERR(handle))
			GOTO(out, rc = PTR_ERR(handle));

		rc = mdd_declare_lfsck_namespace_exec_dir(env, obj, handle);
		if (rc != 0)
			GOTO(stop, rc);

		rc = mdd_trans_start(env, mdd, handle);
		if (rc != 0)
			GOTO(stop, rc);

		mdd_write_lock(env, obj, MOR_TGT_CHILD);
		locked = true;
	}

	rc = mdd_lfsck_namespace_check_exist(env, lfsck, obj, ent->lde_name);
	if (rc != 0)
		GOTO(stop, rc);

	rc = mdd_links_read(env, obj, &ldata);
	if (rc == 0) {
		count = ldata.ld_leh->leh_reccount;
		rc = linkea_links_find(&ldata, cname, pfid);
		if (rc == 0) {
			/* For dir, if there are more than one linkea entries,
			 * then remove all the other redundant linkea entries.*/
			if (unlikely(count > 1 &&
				     S_ISDIR(mdd_object_type(obj))))
				goto unmatch;

			goto record;
		} else {

unmatch:
			ns->ln_flags |= LF_INCONSISTENT;
			if (bk->lb_param & LPF_DRYRUN) {
				repaired = true;
				goto record;
			}

			/*For dir, remove the unmatched linkea entry directly.*/
			if (S_ISDIR(mdd_object_type(obj))) {
				if (!com->lc_journal)
					goto again;

				rc = mdo_xattr_del(env, obj, XATTR_NAME_LINK,
						   handle, BYPASS_CAPA);
				if (rc != 0)
					GOTO(stop, rc);

				goto nodata;
			} else {
				goto add;
			}
		}
	} else if (unlikely(rc == -EINVAL)) {
		ns->ln_flags |= LF_INCONSISTENT;
		if (bk->lb_param & LPF_DRYRUN) {
			count = 1;
			repaired = true;
			goto record;
		}

		if (!com->lc_journal)
			goto again;

		/* The magic crashed, we are not sure whether there are more
		 * corrupt data in the linkea, so remove all linkea entries. */
		rc = mdo_xattr_del(env, obj, XATTR_NAME_LINK, handle,
				   BYPASS_CAPA);
		if (rc != 0)
			GOTO(stop, rc);

		goto nodata;
	} else if (rc == -ENODATA) {
		ns->ln_flags |= LF_UPGRADE;
		if (bk->lb_param & LPF_DRYRUN) {
			count = 1;
			repaired = true;
			goto record;
		}

nodata:
		rc = linkea_data_new(&ldata, &mdd_env_info(env)->mti_link_buf);
		if (rc != 0)
			GOTO(stop, rc);

add:
		if (!com->lc_journal)
			goto again;

		rc = linkea_add_buf(&ldata, cname, pfid);
		if (rc != 0)
			GOTO(stop, rc);

		rc = mdd_links_write(env, obj, &ldata, handle);
		if (rc != 0)
			GOTO(stop, rc);

		count = ldata.ld_leh->leh_reccount;
		repaired = true;
	} else {
		GOTO(stop, rc);
	}

record:
	LASSERT(count > 0);

	rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
	if (rc != 0)
		GOTO(stop, rc);

	if ((count == 1) &&
	    (la->la_nlink == 1 || S_ISDIR(mdd_object_type(obj))))
		/* Usually, it is for single linked object or dir, do nothing.*/
		GOTO(stop, rc);

	/* Following modification will be in another transaction.  */
	if (handle != NULL) {
		LASSERT(mdd_write_locked(env, obj));

		mdd_write_unlock(env, obj);
		locked = false;

		mdd_trans_stop(env, mdd, 0, handle);
		handle = NULL;
	}

	ns->ln_mlinked_checked++;
	rc = mdd_lfsck_namespace_update(env, com, cfid,
			count != la->la_nlink ? LLF_UNMATCH_NLINKS : 0, false);

	GOTO(out, rc);

stop:
	if (locked)
		mdd_write_unlock(env, obj);

	if (handle != NULL)
		mdd_trans_stop(env, mdd, rc, handle);

out:
	if (rc < 0) {
		ns->ln_items_failed++;
		if (mdd_lfsck_pos_is_zero(&ns->ln_pos_first_inconsistent))
			mdd_lfsck_pos_fill(env, lfsck,
					   &ns->ln_pos_first_inconsistent,
					   false);
		if (!(bk->lb_param & LPF_FAILOUT))
			rc = 0;
	} else {
		if (repaired)
			ns->ln_items_repaired++;
		else
			com->lc_journal = 0;
		rc = 0;
	}
	up_write(&com->lc_sem);
	return rc;
}

static int mdd_lfsck_namespace_post(const struct lu_env *env,
				    struct lfsck_component *com,
				    int result, bool init)
{
	struct md_lfsck		*lfsck = com->lc_lfsck;
	struct lfsck_namespace	*ns    =
				(struct lfsck_namespace *)com->lc_file_ram;
	int			 rc;

	down_write(&com->lc_sem);

	spin_lock(&lfsck->ml_lock);
	if (!init)
		ns->ln_pos_last_checkpoint = lfsck->ml_pos_current;
	if (result > 0) {
		ns->ln_status = LS_SCANNING_PHASE2;
		ns->ln_flags |= LF_SCANNED_ONCE;
		ns->ln_flags &= ~LF_UPGRADE;
		cfs_list_del_init(&com->lc_link);
		cfs_list_del_init(&com->lc_link_dir);
		cfs_list_add_tail(&com->lc_link, &lfsck->ml_list_double_scan);
	} else if (result == 0) {
		if (lfsck->ml_paused) {
			ns->ln_status = LS_PAUSED;
		} else {
			ns->ln_status = LS_STOPPED;
			cfs_list_del_init(&com->lc_link);
			cfs_list_del_init(&com->lc_link_dir);
			cfs_list_add_tail(&com->lc_link, &lfsck->ml_list_idle);
		}
	} else {
		ns->ln_status = LS_FAILED;
		cfs_list_del_init(&com->lc_link);
		cfs_list_del_init(&com->lc_link_dir);
		cfs_list_add_tail(&com->lc_link, &lfsck->ml_list_idle);
	}
	spin_unlock(&lfsck->ml_lock);

	if (!init) {
		ns->ln_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->ml_time_last_checkpoint);
		ns->ln_time_last_checkpoint = cfs_time_current_sec();
		ns->ln_items_checked += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = mdd_lfsck_namespace_store(env, com, false);

	up_write(&com->lc_sem);
	return rc;
}

static int
mdd_lfsck_namespace_dump(const struct lu_env *env, struct lfsck_component *com,
			 char *buf, int len)
{
	struct md_lfsck		*lfsck = com->lc_lfsck;
	struct lfsck_bookmark	*bk    = &lfsck->ml_bookmark_ram;
	struct lfsck_namespace	*ns    =
				(struct lfsck_namespace *)com->lc_file_ram;
	int			 save  = len;
	int			 ret   = -ENOSPC;
	int			 rc;

	down_read(&com->lc_sem);
	rc = snprintf(buf, len,
		      "name: lfsck_namespace\n"
		      "magic: 0x%x\n"
		      "version: %d\n"
		      "status: %s\n",
		      ns->ln_magic,
		      bk->lb_version,
		      lfsck_status_names[ns->ln_status]);
	if (rc <= 0)
		goto out;

	buf += rc;
	len -= rc;
	rc = lfsck_bits_dump(&buf, &len, ns->ln_flags, lfsck_flags_names,
			     "flags");
	if (rc < 0)
		goto out;

	rc = lfsck_bits_dump(&buf, &len, bk->lb_param, lfsck_param_names,
			     "param");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(&buf, &len, ns->ln_time_last_complete,
			     "time_since_last_completed");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(&buf, &len, ns->ln_time_latest_start,
			     "time_since_latest_start");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(&buf, &len, ns->ln_time_last_checkpoint,
			     "time_since_last_checkpoint");
	if (rc < 0)
		goto out;

	rc = lfsck_pos_dump(&buf, &len, &ns->ln_pos_latest_start,
			    "latest_start_position");
	if (rc < 0)
		goto out;

	rc = lfsck_pos_dump(&buf, &len, &ns->ln_pos_last_checkpoint,
			    "last_checkpoint_position");
	if (rc < 0)
		goto out;

	rc = lfsck_pos_dump(&buf, &len, &ns->ln_pos_first_inconsistent,
			    "first_failure_position");
	if (rc < 0)
		goto out;

	if (ns->ln_status == LS_SCANNING_PHASE1) {
		struct lfsck_position pos;
		cfs_duration_t duration = cfs_time_current() -
					  lfsck->ml_time_last_checkpoint;
		__u64 checked = ns->ln_items_checked + com->lc_new_checked;
		__u64 speed = checked;
		__u64 new_checked = com->lc_new_checked * CFS_HZ;
		__u32 rtime = ns->ln_run_time_phase1 +
			      cfs_duration_sec(duration + HALF_SEC);

		if (duration != 0)
			do_div(new_checked, duration);
		if (rtime != 0)
			do_div(speed, rtime);
		rc = snprintf(buf, len,
			      "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "updated_phase1: "LPU64"\n"
			      "updated_phase2: "LPU64"\n"
			      "failed_phase1: "LPU64"\n"
			      "failed_phase2: "LPU64"\n"
			      "dirs: "LPU64"\n"
			      "M-linked: "LPU64"\n"
			      "nlinks_repaired: "LPU64"\n"
			      "lost_found: "LPU64"\n"
			      "success_count: %u\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: N/A\n"
			      "real-time_speed_phase1: "LPU64" items/sec\n"
			      "real-time_speed_phase2: N/A\n",
			      checked,
			      ns->ln_objs_checked_phase2,
			      ns->ln_items_repaired,
			      ns->ln_objs_repaired_phase2,
			      ns->ln_items_failed,
			      ns->ln_objs_failed_phase2,
			      ns->ln_dirs_checked,
			      ns->ln_mlinked_checked,
			      ns->ln_objs_nlink_repaired,
			      ns->ln_objs_lost_found,
			      ns->ln_success_count,
			      rtime,
			      ns->ln_run_time_phase2,
			      speed,
			      new_checked);
		if (rc <= 0)
			goto out;

		buf += rc;
		len -= rc;
		mdd_lfsck_pos_fill(env, lfsck, &pos, false);
		rc = lfsck_pos_dump(&buf, &len, &pos, "current_position");
		if (rc <= 0)
			goto out;
	} else if (ns->ln_status == LS_SCANNING_PHASE2) {
		cfs_duration_t duration = cfs_time_current() -
					  lfsck->ml_time_last_checkpoint;
		__u64 checked = ns->ln_objs_checked_phase2 +
				com->lc_new_checked;
		__u64 speed1 = ns->ln_items_checked;
		__u64 speed2 = checked;
		__u64 new_checked = com->lc_new_checked * CFS_HZ;
		__u32 rtime = ns->ln_run_time_phase2 +
			      cfs_duration_sec(duration + HALF_SEC);

		if (duration != 0)
			do_div(new_checked, duration);
		if (ns->ln_run_time_phase1 != 0)
			do_div(speed1, ns->ln_run_time_phase1);
		if (rtime != 0)
			do_div(speed2, rtime);
		rc = snprintf(buf, len,
			      "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "updated_phase1: "LPU64"\n"
			      "updated_phase2: "LPU64"\n"
			      "failed_phase1: "LPU64"\n"
			      "failed_phase2: "LPU64"\n"
			      "dirs: "LPU64"\n"
			      "M-linked: "LPU64"\n"
			      "nlinks_repaired: "LPU64"\n"
			      "lost_found: "LPU64"\n"
			      "success_count: %u\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: "LPU64" objs/sec\n"
			      "real-time_speed_phase1: N/A\n"
			      "real-time_speed_phase2: "LPU64" objs/sec\n"
			      "current_position: "DFID"\n",
			      ns->ln_items_checked,
			      checked,
			      ns->ln_items_repaired,
			      ns->ln_objs_repaired_phase2,
			      ns->ln_items_failed,
			      ns->ln_objs_failed_phase2,
			      ns->ln_dirs_checked,
			      ns->ln_mlinked_checked,
			      ns->ln_objs_nlink_repaired,
			      ns->ln_objs_lost_found,
			      ns->ln_success_count,
			      ns->ln_run_time_phase1,
			      rtime,
			      speed1,
			      speed2,
			      new_checked,
			      PFID(&ns->ln_fid_latest_scanned_phase2));
		if (rc <= 0)
			goto out;

		buf += rc;
		len -= rc;
	} else {
		__u64 speed1 = ns->ln_items_checked;
		__u64 speed2 = ns->ln_objs_checked_phase2;

		if (ns->ln_run_time_phase1 != 0)
			do_div(speed1, ns->ln_run_time_phase1);
		if (ns->ln_run_time_phase2 != 0)
			do_div(speed2, ns->ln_run_time_phase2);
		rc = snprintf(buf, len,
			      "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "updated_phase1: "LPU64"\n"
			      "updated_phase2: "LPU64"\n"
			      "failed_phase1: "LPU64"\n"
			      "failed_phase2: "LPU64"\n"
			      "dirs: "LPU64"\n"
			      "M-linked: "LPU64"\n"
			      "nlinks_repaired: "LPU64"\n"
			      "lost_found: "LPU64"\n"
			      "success_count: %u\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: "LPU64" objs/sec\n"
			      "real-time_speed_phase1: N/A\n"
			      "real-time_speed_phase2: N/A\n"
			      "current_position: N/A\n",
			      ns->ln_items_checked,
			      ns->ln_objs_checked_phase2,
			      ns->ln_items_repaired,
			      ns->ln_objs_repaired_phase2,
			      ns->ln_items_failed,
			      ns->ln_objs_failed_phase2,
			      ns->ln_dirs_checked,
			      ns->ln_mlinked_checked,
			      ns->ln_objs_nlink_repaired,
			      ns->ln_objs_lost_found,
			      ns->ln_success_count,
			      ns->ln_run_time_phase1,
			      ns->ln_run_time_phase2,
			      speed1,
			      speed2);
		if (rc <= 0)
			goto out;

		buf += rc;
		len -= rc;
	}
	ret = save - len;

out:
	up_read(&com->lc_sem);
	return ret;
}

static int mdd_lfsck_namespace_double_scan(const struct lu_env *env,
					   struct lfsck_component *com)
{
	struct md_lfsck		*lfsck	= com->lc_lfsck;
	struct ptlrpc_thread	*thread = &lfsck->ml_thread;
	struct mdd_device	*mdd	= mdd_lfsck2mdd(lfsck);
	struct lfsck_bookmark	*bk	= &lfsck->ml_bookmark_ram;
	struct lfsck_namespace	*ns	=
				(struct lfsck_namespace *)com->lc_file_ram;
	struct dt_object	*obj	= com->lc_obj;
	const struct dt_it_ops	*iops	= &obj->do_index_ops->dio_it;
	struct mdd_object	*target;
	struct dt_it		*di;
	struct dt_key		*key;
	struct lu_fid		 fid;
	int			 rc;
	__u8			 flags;
	ENTRY;

	lfsck->ml_new_scanned = 0;
	lfsck->ml_time_last_checkpoint = cfs_time_current();
	lfsck->ml_time_next_checkpoint = lfsck->ml_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);

	di = iops->init(env, obj, 0, BYPASS_CAPA);
	if (IS_ERR(di))
		RETURN(PTR_ERR(di));

	fid_cpu_to_be(&fid, &ns->ln_fid_latest_scanned_phase2);
	rc = iops->get(env, di, (const struct dt_key *)&fid);
	if (rc < 0)
		GOTO(fini, rc);

	/* Skip the start one, which either has been processed or non-exist. */
	rc = iops->next(env, di);
	if (rc != 0)
		GOTO(put, rc);

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_DOUBLESCAN))
		GOTO(put, rc = 0);

	do {
		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DELAY3) &&
		    cfs_fail_val > 0) {
			struct l_wait_info lwi;

			lwi = LWI_TIMEOUT(cfs_time_seconds(cfs_fail_val),
					  NULL, NULL);
			l_wait_event(thread->t_ctl_waitq,
				     !thread_is_running(thread),
				     &lwi);
		}

		key = iops->key(env, di);
		fid_be_to_cpu(&fid, (const struct lu_fid *)key);
		target = mdd_object_find(env, mdd, &fid);
		down_write(&com->lc_sem);
		if (target == NULL) {
			rc = 0;
			goto checkpoint;
		} else if (IS_ERR(target)) {
			rc = PTR_ERR(target);
			goto checkpoint;
		}

		/* XXX: Currently, skip remote object, the consistency for
		 *	remote object will be processed in LFSCK phase III. */
		if (!mdd_object_exists(target) || mdd_object_remote(target))
			goto obj_put;

		rc = iops->rec(env, di, (struct dt_rec *)&flags, 0);
		if (rc == 0)
			rc = mdd_lfsck_namespace_double_scan_one(env, com,
								 target, flags);

obj_put:
		mdd_object_put(env, target);

checkpoint:
		lfsck->ml_new_scanned++;
		com->lc_new_checked++;
		ns->ln_fid_latest_scanned_phase2 = fid;
		if (rc > 0)
			ns->ln_objs_repaired_phase2++;
		else if (rc < 0)
			ns->ln_objs_failed_phase2++;
		up_write(&com->lc_sem);

		if ((rc == 0) || ((rc > 0) && !(bk->lb_param & LPF_DRYRUN))) {
			mdd_lfsck_namespace_delete(env, com, &fid);
		} else if (rc < 0) {
			flags |= LLF_REPAIR_FAILED;
			mdd_lfsck_namespace_update(env, com, &fid, flags, true);
		}

		if (rc < 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(put, rc);

		if (likely(cfs_time_beforeq(cfs_time_current(),
					    lfsck->ml_time_next_checkpoint)) ||
		    com->lc_new_checked == 0)
			goto speed;

		down_write(&com->lc_sem);
		ns->ln_run_time_phase2 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->ml_time_last_checkpoint);
		ns->ln_time_last_checkpoint = cfs_time_current_sec();
		ns->ln_objs_checked_phase2 += com->lc_new_checked;
		com->lc_new_checked = 0;
		rc = mdd_lfsck_namespace_store(env, com, false);
		up_write(&com->lc_sem);
		if (rc != 0)
			GOTO(put, rc);

		lfsck->ml_time_last_checkpoint = cfs_time_current();
		lfsck->ml_time_next_checkpoint = lfsck->ml_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);

speed:
		mdd_lfsck_control_speed(lfsck);
		if (unlikely(!thread_is_running(thread)))
			GOTO(put, rc = 0);

		rc = iops->next(env, di);
	} while (rc == 0);

	GOTO(put, rc);

put:
	iops->put(env, di);

fini:
	iops->fini(env, di);
	down_write(&com->lc_sem);

	ns->ln_run_time_phase2 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->ml_time_last_checkpoint);
	ns->ln_time_last_checkpoint = cfs_time_current_sec();
	ns->ln_objs_checked_phase2 += com->lc_new_checked;
	com->lc_new_checked = 0;

	if (rc > 0) {
		com->lc_journal = 0;
		ns->ln_status = LS_COMPLETED;
		if (!(bk->lb_param & LPF_DRYRUN))
			ns->ln_flags &=
			~(LF_SCANNED_ONCE | LF_INCONSISTENT | LF_UPGRADE);
		ns->ln_time_last_complete = ns->ln_time_last_checkpoint;
		ns->ln_success_count++;
	} else if (rc == 0) {
		if (lfsck->ml_paused)
			ns->ln_status = LS_PAUSED;
		else
			ns->ln_status = LS_STOPPED;
	} else {
		ns->ln_status = LS_FAILED;
	}

	if (ns->ln_status != LS_PAUSED) {
		spin_lock(&lfsck->ml_lock);
		cfs_list_del_init(&com->lc_link);
		cfs_list_add_tail(&com->lc_link, &lfsck->ml_list_idle);
		spin_unlock(&lfsck->ml_lock);
	}

	rc = mdd_lfsck_namespace_store(env, com, false);

	up_write(&com->lc_sem);
	return rc;
}

static struct lfsck_operations mdd_lfsck_namespace_ops = {
	.lfsck_reset		= mdd_lfsck_namespace_reset,
	.lfsck_fail		= mdd_lfsck_namespace_fail,
	.lfsck_checkpoint	= mdd_lfsck_namespace_checkpoint,
	.lfsck_prep		= mdd_lfsck_namespace_prep,
	.lfsck_exec_oit		= mdd_lfsck_namespace_exec_oit,
	.lfsck_exec_dir		= mdd_lfsck_namespace_exec_dir,
	.lfsck_post		= mdd_lfsck_namespace_post,
	.lfsck_dump		= mdd_lfsck_namespace_dump,
	.lfsck_double_scan	= mdd_lfsck_namespace_double_scan,
};

/* LFSCK component setup/cleanup functions */

static int mdd_lfsck_namespace_setup(const struct lu_env *env,
				     struct md_lfsck *lfsck)
{
	struct mdd_device	*mdd = mdd_lfsck2mdd(lfsck);
	struct lfsck_component	*com;
	struct lfsck_namespace	*ns;
	struct dt_object	*obj, *root;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(com);
	if (com == NULL)
		RETURN(-ENOMEM);

	CFS_INIT_LIST_HEAD(&com->lc_link);
	CFS_INIT_LIST_HEAD(&com->lc_link_dir);
	init_rwsem(&com->lc_sem);
	atomic_set(&com->lc_ref, 1);
	com->lc_lfsck = lfsck;
	com->lc_type = LT_NAMESPACE;
	com->lc_ops = &mdd_lfsck_namespace_ops;
	com->lc_file_size = sizeof(struct lfsck_namespace);
	OBD_ALLOC(com->lc_file_ram, com->lc_file_size);
	if (com->lc_file_ram == NULL)
		GOTO(out, rc = -ENOMEM);

	OBD_ALLOC(com->lc_file_disk, com->lc_file_size);
	if (com->lc_file_disk == NULL)
		GOTO(out, rc = -ENOMEM);

	root = dt_locate(env, mdd->mdd_bottom, &mdd->mdd_local_root_fid);
	if (unlikely(IS_ERR(root)))
		GOTO(out, rc = PTR_ERR(root));

	obj = local_index_find_or_create(env, mdd->mdd_los, root,
					 lfsck_namespace_name,
					 S_IFREG | S_IRUGO | S_IWUSR,
					 &dt_lfsck_features);
	lu_object_put(env, &root->do_lu);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	com->lc_obj = obj;
	rc = obj->do_ops->do_index_try(env, obj, &dt_lfsck_features);
	if (rc != 0)
		GOTO(out, rc);

	rc = mdd_lfsck_namespace_load(env, com);
	if (rc > 0)
		rc = mdd_lfsck_namespace_reset(env, com, true);
	else if (rc == -ENODATA)
		rc = mdd_lfsck_namespace_init(env, com);
	if (rc != 0)
		GOTO(out, rc);

	ns = (struct lfsck_namespace *)com->lc_file_ram;
	switch (ns->ln_status) {
	case LS_INIT:
	case LS_COMPLETED:
	case LS_FAILED:
	case LS_STOPPED:
		cfs_list_add_tail(&com->lc_link, &lfsck->ml_list_idle);
		break;
	default:
		CERROR("%s: unknown status: %u\n",
		       mdd_lfsck2name(lfsck), ns->ln_status);
		/* fall through */
	case LS_SCANNING_PHASE1:
	case LS_SCANNING_PHASE2:
		/* No need to store the status to disk right now.
		 * If the system crashed before the status stored,
		 * it will be loaded back when next time. */
		ns->ln_status = LS_CRASHED;
		/* fall through */
	case LS_PAUSED:
	case LS_CRASHED:
		cfs_list_add_tail(&com->lc_link, &lfsck->ml_list_scan);
		cfs_list_add_tail(&com->lc_link_dir, &lfsck->ml_list_dir);
		break;
	}

	GOTO(out, rc = 0);

out:
	if (rc != 0)
		mdd_lfsck_component_cleanup(env, com);
	return rc;
}

/* helper functions for framework */

static int object_needs_lfsck(const struct lu_env *env, struct mdd_device *mdd,
			      struct mdd_object *obj)
{
	struct lu_fid *fid   = &mdd_env_info(env)->mti_fid;
	int	       depth = 0;
	int	       rc;

	LASSERT(S_ISDIR(mdd_object_type(obj)));

	while (1) {
		if (mdd_is_root(mdd, mdo2fid(obj))) {
			if (depth > 0)
				mdd_object_put(env, obj);
			return 1;
		}

		/* .lustre doesn't contain "real" user objects, no need lfsck */
		if (fid_is_dot_lustre(mdo2fid(obj))) {
			if (depth > 0)
				mdd_object_put(env, obj);
			return 0;
		}

		mdd_read_lock(env, obj, MOR_TGT_CHILD);
		if (unlikely(mdd_is_dead_obj(obj))) {
			mdd_read_unlock(env, obj);
			if (depth > 0)
				mdd_object_put(env, obj);
			return 0;
		}

		rc = dt_xattr_get(env, mdd_object_child(obj),
				  mdd_buf_get(env, NULL, 0), XATTR_NAME_LINK,
				  BYPASS_CAPA);
		mdd_read_unlock(env, obj);
		if (rc >= 0) {
			if (depth > 0)
				mdd_object_put(env, obj);
			return 1;
		}

		if (rc < 0 && rc != -ENODATA) {
			if (depth > 0)
				mdd_object_put(env, obj);
			return rc;
		}

		rc = mdd_parent_fid(env, obj, fid);
		if (depth > 0)
			mdd_object_put(env, obj);
		if (rc != 0)
			return rc;

		if (unlikely(lu_fid_eq(fid, &mdd->mdd_local_root_fid)))
			return 0;

		obj = mdd_object_find(env, mdd, fid);
		if (obj == NULL)
			return 0;
		else if (IS_ERR(obj))
			return PTR_ERR(obj);

		if (!mdd_object_exists(obj)) {
			mdd_object_put(env, obj);
			return 0;
		}

		/* Currently, only client visible directory can be remote. */
		if (mdd_object_remote(obj)) {
			mdd_object_put(env, obj);
			return 1;
		}

		depth++;
	}
	return 0;
}

static void mdd_lfsck_unpack_ent(struct lu_dirent *ent)
{
	fid_le_to_cpu(&ent->lde_fid, &ent->lde_fid);
	ent->lde_hash = le64_to_cpu(ent->lde_hash);
	ent->lde_reclen = le16_to_cpu(ent->lde_reclen);
	ent->lde_namelen = le16_to_cpu(ent->lde_namelen);
	ent->lde_attrs = le32_to_cpu(ent->lde_attrs);

	/* Make sure the name is terminated with '0'.
	 * The data (type) after ent::lde_name maybe
	 * broken, but we do not care. */
	ent->lde_name[ent->lde_namelen] = 0;
}

/* LFSCK wrap functions */

static void mdd_lfsck_fail(const struct lu_env *env, struct md_lfsck *lfsck,
			   bool new_checked)
{
	struct lfsck_component *com;

	cfs_list_for_each_entry(com, &lfsck->ml_list_scan, lc_link) {
		com->lc_ops->lfsck_fail(env, com, new_checked);
	}
}

static int mdd_lfsck_checkpoint(const struct lu_env *env,
				struct md_lfsck *lfsck)
{
	struct lfsck_component *com;
	int			rc;

	if (likely(cfs_time_beforeq(cfs_time_current(),
				    lfsck->ml_time_next_checkpoint)))
		return 0;

	mdd_lfsck_pos_fill(env, lfsck, &lfsck->ml_pos_current, false);
	cfs_list_for_each_entry(com, &lfsck->ml_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_checkpoint(env, com, false);
		if (rc != 0)
			return rc;;
	}

	lfsck->ml_time_last_checkpoint = cfs_time_current();
	lfsck->ml_time_next_checkpoint = lfsck->ml_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);
	return 0;
}

static int mdd_lfsck_prep(struct lu_env *env, struct md_lfsck *lfsck)
{
	struct mdd_device      *mdd	= mdd_lfsck2mdd(lfsck);
	struct mdd_object      *obj	= NULL;
	struct dt_object       *dt_obj;
	struct lfsck_component *com;
	struct lfsck_component *next;
	struct lfsck_position  *pos	= NULL;
	const struct dt_it_ops *iops	=
				&lfsck->ml_obj_oit->do_index_ops->dio_it;
	struct dt_it	       *di;
	int			rc;
	ENTRY;

	LASSERT(lfsck->ml_obj_dir == NULL);
	LASSERT(lfsck->ml_di_dir == NULL);

	lfsck->ml_current_oit_processed = 0;
	cfs_list_for_each_entry_safe(com, next, &lfsck->ml_list_scan, lc_link) {
		com->lc_new_checked = 0;
		if (lfsck->ml_bookmark_ram.lb_param & LPF_DRYRUN)
			com->lc_journal = 0;

		rc = com->lc_ops->lfsck_prep(env, com);
		if (rc != 0)
			RETURN(rc);

		if ((pos == NULL) ||
		    (!mdd_lfsck_pos_is_zero(&com->lc_pos_start) &&
		     mdd_lfsck_pos_is_eq(pos, &com->lc_pos_start) > 0))
			pos = &com->lc_pos_start;
	}

	/* Init otable-based iterator. */
	if (pos == NULL) {
		rc = iops->load(env, lfsck->ml_di_oit, 0);
		if (rc > 0) {
			lfsck->ml_oit_over = 1;
			rc = 0;
		}

		GOTO(out, rc);
	}

	rc = iops->load(env, lfsck->ml_di_oit, pos->lp_oit_cookie);
	if (rc < 0)
		GOTO(out, rc);
	else if (rc > 0)
		lfsck->ml_oit_over = 1;

	if (fid_is_zero(&pos->lp_dir_parent))
		GOTO(out, rc = 0);

	/* Find the directory for namespace-based traverse. */
	obj = mdd_object_find(env, mdd, &pos->lp_dir_parent);
	if (obj == NULL)
		GOTO(out, rc = 0);
	else if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	/* XXX: Currently, skip remote object, the consistency for
	 *	remote object will be processed in LFSCK phase III. */
	if (!mdd_object_exists(obj) || mdd_object_remote(obj) ||
	    unlikely(!S_ISDIR(mdd_object_type(obj))))
		GOTO(out, rc = 0);

	if (unlikely(mdd_is_dead_obj(obj)))
		GOTO(out, rc = 0);

	dt_obj = mdd_object_child(obj);
	if (unlikely(!dt_try_as_dir(env, dt_obj)))
		GOTO(out, rc = -ENOTDIR);

	/* Init the namespace-based directory traverse. */
	iops = &dt_obj->do_index_ops->dio_it;
	di = iops->init(env, dt_obj, lfsck->ml_args_dir, BYPASS_CAPA);
	if (IS_ERR(di))
		GOTO(out, rc = PTR_ERR(di));

	LASSERT(pos->lp_dir_cookie < MDS_DIR_END_OFF);

	rc = iops->load(env, di, pos->lp_dir_cookie);
	if ((rc == 0) || (rc > 0 && pos->lp_dir_cookie > 0))
		rc = iops->next(env, di);
	else if (rc > 0)
		rc = 0;

	if (rc != 0) {
		iops->put(env, di);
		iops->fini(env, di);
		GOTO(out, rc);
	}

	lfsck->ml_obj_dir = dt_obj;
	spin_lock(&lfsck->ml_lock);
	lfsck->ml_di_dir = di;
	spin_unlock(&lfsck->ml_lock);
	obj = NULL;

	GOTO(out, rc = 0);

out:
	if (obj != NULL)
		mdd_object_put(env, obj);

	if (rc < 0) {
		cfs_list_for_each_entry_safe(com, next, &lfsck->ml_list_scan,
					     lc_link)
			com->lc_ops->lfsck_post(env, com, rc, true);

		return rc;
	}

	rc = 0;
	mdd_lfsck_pos_fill(env, lfsck, &lfsck->ml_pos_current, true);
	cfs_list_for_each_entry(com, &lfsck->ml_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_checkpoint(env, com, true);
		if (rc != 0)
			break;
	}

	lfsck->ml_time_last_checkpoint = cfs_time_current();
	lfsck->ml_time_next_checkpoint = lfsck->ml_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);
	return rc;
}

static int mdd_lfsck_exec_oit(const struct lu_env *env, struct md_lfsck *lfsck,
			      struct mdd_object *obj)
{
	struct lfsck_component *com;
	struct dt_object       *dt_obj;
	const struct dt_it_ops *iops;
	struct dt_it	       *di;
	int			rc;
	ENTRY;

	LASSERT(lfsck->ml_obj_dir == NULL);

	cfs_list_for_each_entry(com, &lfsck->ml_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_exec_oit(env, com, obj);
		if (rc != 0)
			RETURN(rc);
	}

	if (!S_ISDIR(mdd_object_type(obj)) ||
	    cfs_list_empty(&lfsck->ml_list_dir))
	       RETURN(0);

	rc = object_needs_lfsck(env, mdd_lfsck2mdd(lfsck), obj);
	if (rc <= 0)
		GOTO(out, rc);

	if (unlikely(mdd_is_dead_obj(obj)))
		GOTO(out, rc = 0);

	dt_obj = mdd_object_child(obj);
	if (unlikely(!dt_try_as_dir(env, dt_obj)))
		GOTO(out, rc = -ENOTDIR);

	iops = &dt_obj->do_index_ops->dio_it;
	di = iops->init(env, dt_obj, lfsck->ml_args_dir, BYPASS_CAPA);
	if (IS_ERR(di))
		GOTO(out, rc = PTR_ERR(di));

	rc = iops->load(env, di, 0);
	if (rc == 0)
		rc = iops->next(env, di);
	else if (rc > 0)
		rc = 0;

	if (rc != 0) {
		iops->put(env, di);
		iops->fini(env, di);
		GOTO(out, rc);
	}

	mdd_object_get(obj);
	lfsck->ml_obj_dir = dt_obj;
	spin_lock(&lfsck->ml_lock);
	lfsck->ml_di_dir = di;
	spin_unlock(&lfsck->ml_lock);

	GOTO(out, rc = 0);

out:
	if (rc < 0)
		mdd_lfsck_fail(env, lfsck, false);
	return (rc > 0 ? 0 : rc);
}

static int mdd_lfsck_exec_dir(const struct lu_env *env, struct md_lfsck *lfsck,
			      struct mdd_object *obj, struct lu_dirent *ent)
{
	struct lfsck_component *com;
	int			rc;

	cfs_list_for_each_entry(com, &lfsck->ml_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_exec_dir(env, com, obj, ent);
		if (rc != 0)
			return rc;
	}
	return 0;
}

static int mdd_lfsck_post(const struct lu_env *env, struct md_lfsck *lfsck,
			  int result)
{
	struct lfsck_component *com;
	struct lfsck_component *next;
	int			rc;

	mdd_lfsck_pos_fill(env, lfsck, &lfsck->ml_pos_current, false);
	cfs_list_for_each_entry_safe(com, next, &lfsck->ml_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_post(env, com, result, false);
		if (rc != 0)
			return rc;
	}

	lfsck->ml_time_last_checkpoint = cfs_time_current();
	lfsck->ml_time_next_checkpoint = lfsck->ml_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);
	return result;
}

static int mdd_lfsck_double_scan(const struct lu_env *env,
				 struct md_lfsck *lfsck)
{
	struct lfsck_component *com;
	struct lfsck_component *next;
	int			rc;

	cfs_list_for_each_entry_safe(com, next, &lfsck->ml_list_double_scan,
				     lc_link) {
		if (lfsck->ml_bookmark_ram.lb_param & LPF_DRYRUN)
			com->lc_journal = 0;

		rc = com->lc_ops->lfsck_double_scan(env, com);
		if (rc != 0)
			return rc;
	}
	return 0;
}

/* LFSCK engines */

static int mdd_lfsck_dir_engine(const struct lu_env *env,
				struct md_lfsck *lfsck)
{
	struct mdd_thread_info	*info	= mdd_env_info(env);
	struct mdd_device	*mdd	= mdd_lfsck2mdd(lfsck);
	const struct dt_it_ops	*iops	=
			&lfsck->ml_obj_dir->do_index_ops->dio_it;
	struct dt_it		*di	= lfsck->ml_di_dir;
	struct lu_dirent	*ent	= &info->mti_ent;
	struct lu_fid		*fid	= &info->mti_fid;
	struct lfsck_bookmark	*bk	= &lfsck->ml_bookmark_ram;
	struct ptlrpc_thread	*thread = &lfsck->ml_thread;
	int			 rc;
	ENTRY;

	do {
		struct mdd_object *child;

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DELAY2) &&
		    cfs_fail_val > 0) {
			struct l_wait_info lwi;

			lwi = LWI_TIMEOUT(cfs_time_seconds(cfs_fail_val),
					  NULL, NULL);
			l_wait_event(thread->t_ctl_waitq,
				     !thread_is_running(thread),
				     &lwi);
		}

		lfsck->ml_new_scanned++;
		rc = iops->rec(env, di, (struct dt_rec *)ent,
			       lfsck->ml_args_dir);
		if (rc != 0) {
			mdd_lfsck_fail(env, lfsck, true);
			if (bk->lb_param & LPF_FAILOUT)
				RETURN(rc);
			else
				goto checkpoint;
		}

		mdd_lfsck_unpack_ent(ent);
		if (ent->lde_attrs & LUDA_IGNORE)
			goto checkpoint;

		*fid = ent->lde_fid;
		child = mdd_object_find(env, mdd, fid);
		if (child == NULL) {
			goto checkpoint;
		} else if (IS_ERR(child)) {
			mdd_lfsck_fail(env, lfsck, true);
			if (bk->lb_param & LPF_FAILOUT)
				RETURN(PTR_ERR(child));
			else
				goto checkpoint;
		}

		/* XXX: Currently, skip remote object, the consistency for
		 *	remote object will be processed in LFSCK phase III. */
		if (mdd_object_exists(child) && !mdd_object_remote(child))
			rc = mdd_lfsck_exec_dir(env, lfsck, child, ent);
		mdd_object_put(env, child);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

checkpoint:
		rc = mdd_lfsck_checkpoint(env, lfsck);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

		/* Rate control. */
		mdd_lfsck_control_speed(lfsck);
		if (unlikely(!thread_is_running(thread)))
			RETURN(0);

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_FATAL2)) {
			spin_lock(&lfsck->ml_lock);
			thread_set_flags(thread, SVC_STOPPING);
			spin_unlock(&lfsck->ml_lock);
			RETURN(-EINVAL);
		}

		rc = iops->next(env, di);
	} while (rc == 0);

	if (rc > 0 && !lfsck->ml_oit_over)
		mdd_lfsck_close_dir(env, lfsck);

	RETURN(rc);
}

static int mdd_lfsck_oit_engine(const struct lu_env *env,
				struct md_lfsck *lfsck)
{
	struct mdd_thread_info	*info	= mdd_env_info(env);
	struct mdd_device	*mdd	= mdd_lfsck2mdd(lfsck);
	const struct dt_it_ops	*iops	=
				&lfsck->ml_obj_oit->do_index_ops->dio_it;
	struct dt_it		*di	= lfsck->ml_di_oit;
	struct lu_fid		*fid	= &info->mti_fid;
	struct lfsck_bookmark	*bk	= &lfsck->ml_bookmark_ram;
	struct ptlrpc_thread	*thread = &lfsck->ml_thread;
	int			 rc;
	ENTRY;

	do {
		struct mdd_object *target;

		if (lfsck->ml_di_dir != NULL) {
			rc = mdd_lfsck_dir_engine(env, lfsck);
			if (rc <= 0)
				RETURN(rc);
		}

		if (unlikely(lfsck->ml_oit_over))
			RETURN(1);

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DELAY1) &&
		    cfs_fail_val > 0) {
			struct l_wait_info lwi;

			lwi = LWI_TIMEOUT(cfs_time_seconds(cfs_fail_val),
					  NULL, NULL);
			l_wait_event(thread->t_ctl_waitq,
				     !thread_is_running(thread),
				     &lwi);
		}

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_CRASH))
			RETURN(0);

		lfsck->ml_current_oit_processed = 1;
		lfsck->ml_new_scanned++;
		rc = iops->rec(env, di, (struct dt_rec *)fid, 0);
		if (rc != 0) {
			mdd_lfsck_fail(env, lfsck, true);
			if (bk->lb_param & LPF_FAILOUT)
				RETURN(rc);
			else
				goto checkpoint;
		}

		target = mdd_object_find(env, mdd, fid);
		if (target == NULL) {
			goto checkpoint;
		} else if (IS_ERR(target)) {
			mdd_lfsck_fail(env, lfsck, true);
			if (bk->lb_param & LPF_FAILOUT)
				RETURN(PTR_ERR(target));
			else
				goto checkpoint;
		}

		/* XXX: Currently, skip remote object, the consistency for
		 *	remote object will be processed in LFSCK phase III. */
		if (mdd_object_exists(target) && !mdd_object_remote(target))
			rc = mdd_lfsck_exec_oit(env, lfsck, target);
		mdd_object_put(env, target);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

checkpoint:
		rc = mdd_lfsck_checkpoint(env, lfsck);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

		/* Rate control. */
		mdd_lfsck_control_speed(lfsck);

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_FATAL1)) {
			spin_lock(&lfsck->ml_lock);
			thread_set_flags(thread, SVC_STOPPING);
			spin_unlock(&lfsck->ml_lock);
			RETURN(-EINVAL);
		}

		rc = iops->next(env, di);
		if (unlikely(rc > 0))
			lfsck->ml_oit_over = 1;
		else if (likely(rc == 0))
			lfsck->ml_current_oit_processed = 0;

		if (unlikely(!thread_is_running(thread)))
			RETURN(0);
	} while (rc == 0 || lfsck->ml_di_dir != NULL);

	RETURN(rc);
}

static int mdd_lfsck_main(void *args)
{
	struct lu_env		 env;
	struct md_lfsck		*lfsck    = (struct md_lfsck *)args;
	struct ptlrpc_thread	*thread   = &lfsck->ml_thread;
	struct dt_object	*oit_obj  = lfsck->ml_obj_oit;
	const struct dt_it_ops	*oit_iops = &oit_obj->do_index_ops->dio_it;
	struct dt_it		*oit_di;
	int			 rc;
	ENTRY;

	cfs_daemonize("lfsck");
	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0) {
		CERROR("%s: LFSCK, fail to init env, rc = %d\n",
		       mdd_lfsck2name(lfsck), rc);
		GOTO(noenv, rc);
	}

	oit_di = oit_iops->init(&env, oit_obj, lfsck->ml_args_oit, BYPASS_CAPA);
	if (IS_ERR(oit_di)) {
		rc = PTR_ERR(oit_di);
		CERROR("%s: LFSCK, fail to init iteration, rc = %d\n",
		       mdd_lfsck2name(lfsck), rc);
		GOTO(fini_env, rc);
	}

	spin_lock(&lfsck->ml_lock);
	lfsck->ml_di_oit = oit_di;
	spin_unlock(&lfsck->ml_lock);
	rc = mdd_lfsck_prep(&env, lfsck);
	if (rc != 0)
		GOTO(fini_oit, rc);

	CDEBUG(D_LFSCK, "LFSCK entry: oit_flags = 0x%x, dir_flags = 0x%x, "
	       "oit_cookie = "LPU64", dir_cookie = "LPU64", parent = "DFID
	       ", pid = %d\n", lfsck->ml_args_oit, lfsck->ml_args_dir,
	       lfsck->ml_pos_current.lp_oit_cookie,
	       lfsck->ml_pos_current.lp_dir_cookie,
	       PFID(&lfsck->ml_pos_current.lp_dir_parent),
	       cfs_curproc_pid());

	spin_lock(&lfsck->ml_lock);
	thread_set_flags(thread, SVC_RUNNING);
	spin_unlock(&lfsck->ml_lock);
	cfs_waitq_broadcast(&thread->t_ctl_waitq);

	if (!cfs_list_empty(&lfsck->ml_list_scan) ||
	    cfs_list_empty(&lfsck->ml_list_double_scan))
		rc = mdd_lfsck_oit_engine(&env, lfsck);
	else
		rc = 1;

	CDEBUG(D_LFSCK, "LFSCK exit: oit_flags = 0x%x, dir_flags = 0x%x, "
	       "oit_cookie = "LPU64", dir_cookie = "LPU64", parent = "DFID
	       ", pid = %d, rc = %d\n", lfsck->ml_args_oit, lfsck->ml_args_dir,
	       lfsck->ml_pos_current.lp_oit_cookie,
	       lfsck->ml_pos_current.lp_dir_cookie,
	       PFID(&lfsck->ml_pos_current.lp_dir_parent),
	       cfs_curproc_pid(), rc);

	if (lfsck->ml_paused && cfs_list_empty(&lfsck->ml_list_scan))
		oit_iops->put(&env, oit_di);

	if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_CRASH))
		rc = mdd_lfsck_post(&env, lfsck, rc);
	if (lfsck->ml_di_dir != NULL)
		mdd_lfsck_close_dir(&env, lfsck);

fini_oit:
	spin_lock(&lfsck->ml_lock);
	lfsck->ml_di_oit = NULL;
	spin_unlock(&lfsck->ml_lock);

	oit_iops->fini(&env, oit_di);
	if (rc == 1) {
		if (!cfs_list_empty(&lfsck->ml_list_double_scan))
			rc = mdd_lfsck_double_scan(&env, lfsck);
		else
			rc = 0;
	}

	/* XXX: Purge the pinned objects in the future. */

fini_env:
	lu_env_fini(&env);

noenv:
	spin_lock(&lfsck->ml_lock);
	thread_set_flags(thread, SVC_STOPPED);
	cfs_waitq_broadcast(&thread->t_ctl_waitq);
	spin_unlock(&lfsck->ml_lock);
	return rc;
}

/* external interfaces */

int mdd_lfsck_set_speed(const struct lu_env *env, struct md_lfsck *lfsck,
			__u32 limit)
{
	int rc;

	mutex_lock(&lfsck->ml_mutex);
	__mdd_lfsck_set_speed(lfsck, limit);
	rc = mdd_lfsck_bookmark_store(env, lfsck);
	mutex_unlock(&lfsck->ml_mutex);
	return rc;
}

int mdd_lfsck_dump(const struct lu_env *env, struct md_lfsck *lfsck,
		   __u16 type, char *buf, int len)
{
	struct lfsck_component *com;
	int			rc;

	if (!lfsck->ml_initialized)
		return -ENODEV;

	com = mdd_lfsck_component_find(lfsck, type);
	if (com == NULL)
		return -ENOTSUPP;

	rc = com->lc_ops->lfsck_dump(env, com, buf, len);
	mdd_lfsck_component_put(env, com);
	return rc;
}

int mdd_lfsck_start(const struct lu_env *env, struct md_lfsck *lfsck,
		    struct lfsck_start *start)
{
	struct lfsck_bookmark  *bk     = &lfsck->ml_bookmark_ram;
	struct ptlrpc_thread   *thread = &lfsck->ml_thread;
	struct lfsck_component *com;
	struct l_wait_info      lwi    = { 0 };
	bool			dirty  = false;
	int			rc     = 0;
	__u16			valid  = 0;
	__u16			flags  = 0;
	ENTRY;

	if (lfsck->ml_obj_oit == NULL)
		RETURN(-ENOTSUPP);

	/* start == NULL means auto trigger paused LFSCK. */
	if ((start == NULL) &&
	    (cfs_list_empty(&lfsck->ml_list_scan) ||
	     OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_AUTO)))
		RETURN(0);

	mutex_lock(&lfsck->ml_mutex);
	spin_lock(&lfsck->ml_lock);
	if (!thread_is_init(thread) && !thread_is_stopped(thread)) {
		spin_unlock(&lfsck->ml_lock);
		mutex_unlock(&lfsck->ml_mutex);
		RETURN(-EALREADY);
	}

	spin_unlock(&lfsck->ml_lock);

	lfsck->ml_paused = 0;
	lfsck->ml_oit_over = 0;
	lfsck->ml_drop_dryrun = 0;
	lfsck->ml_new_scanned = 0;

	/* For auto trigger. */
	if (start == NULL)
		goto trigger;

	start->ls_version = bk->lb_version;
	if (start->ls_valid & LSV_SPEED_LIMIT) {
		__mdd_lfsck_set_speed(lfsck, start->ls_speed_limit);
		dirty = true;
	}

	if (start->ls_valid & LSV_ERROR_HANDLE) {
		valid |= DOIV_ERROR_HANDLE;
		if (start->ls_flags & LPF_FAILOUT)
			flags |= DOIF_FAILOUT;

		if ((start->ls_flags & LPF_FAILOUT) &&
		    !(bk->lb_param & LPF_FAILOUT)) {
			bk->lb_param |= LPF_FAILOUT;
			dirty = true;
		} else if (!(start->ls_flags & LPF_FAILOUT) &&
			   (bk->lb_param & LPF_FAILOUT)) {
			bk->lb_param &= ~LPF_FAILOUT;
			dirty = true;
		}
	}

	if (start->ls_valid & LSV_DRYRUN) {
		valid |= DOIV_DRYRUN;
		if (start->ls_flags & LPF_DRYRUN)
			flags |= DOIF_DRYRUN;

		if ((start->ls_flags & LPF_DRYRUN) &&
		    !(bk->lb_param & LPF_DRYRUN)) {
			bk->lb_param |= LPF_DRYRUN;
			dirty = true;
		} else if (!(start->ls_flags & LPF_DRYRUN) &&
			   (bk->lb_param & LPF_DRYRUN)) {
			bk->lb_param &= ~LPF_DRYRUN;
			lfsck->ml_drop_dryrun = 1;
			dirty = true;
		}
	}

	if (dirty) {
		rc = mdd_lfsck_bookmark_store(env, lfsck);
		if (rc != 0)
			GOTO(out, rc);
	}

	if (start->ls_flags & LPF_RESET)
		flags |= DOIF_RESET;

	if (start->ls_active != 0) {
		struct lfsck_component *next;
		__u16 type = 1;

		if (start->ls_active == LFSCK_TYPES_ALL)
			start->ls_active = LFSCK_TYPES_SUPPORTED;

		if (start->ls_active & ~LFSCK_TYPES_SUPPORTED) {
			start->ls_active &= ~LFSCK_TYPES_SUPPORTED;
			GOTO(out, rc = -ENOTSUPP);
		}

		cfs_list_for_each_entry_safe(com, next,
					     &lfsck->ml_list_scan, lc_link) {
			if (!(com->lc_type & start->ls_active)) {
				rc = com->lc_ops->lfsck_post(env, com, 0,
							     false);
				if (rc != 0)
					GOTO(out, rc);
			}
		}

		while (start->ls_active != 0) {
			if (type & start->ls_active) {
				com = __mdd_lfsck_component_find(lfsck, type,
							&lfsck->ml_list_idle);
				if (com != NULL) {
					/* The component status will be updated
					 * when its prep() is called later by
					 * the LFSCK main engine. */
					cfs_list_del_init(&com->lc_link);
					cfs_list_add_tail(&com->lc_link,
							  &lfsck->ml_list_scan);
				}
				start->ls_active &= ~type;
			}
			type <<= 1;
		}
	}

	cfs_list_for_each_entry(com, &lfsck->ml_list_scan, lc_link) {
		start->ls_active |= com->lc_type;
		if (flags & DOIF_RESET) {
			rc = com->lc_ops->lfsck_reset(env, com, false);
			if (rc != 0)
				GOTO(out, rc);
		}
	}

trigger:
	lfsck->ml_args_dir = LUDA_64BITHASH | LUDA_VERIFY;
	if (bk->lb_param & LPF_DRYRUN) {
		lfsck->ml_args_dir |= LUDA_VERIFY_DRYRUN;
		valid |= DOIV_DRYRUN;
		flags |= DOIF_DRYRUN;
	}

	if (bk->lb_param & LPF_FAILOUT) {
		valid |= DOIV_ERROR_HANDLE;
		flags |= DOIF_FAILOUT;
	}

	if (!cfs_list_empty(&lfsck->ml_list_scan))
		flags |= DOIF_OUTUSED;

	lfsck->ml_args_oit = (flags << DT_OTABLE_IT_FLAGS_SHIFT) | valid;
	thread_set_flags(thread, 0);
	rc = cfs_create_thread(mdd_lfsck_main, lfsck, 0);
	if (rc < 0)
		CERROR("%s: cannot start LFSCK thread, rc = %d\n",
		       mdd_lfsck2name(lfsck), rc);
	else
		l_wait_event(thread->t_ctl_waitq,
			     thread_is_running(thread) ||
			     thread_is_stopped(thread),
			     &lwi);

	GOTO(out, rc = 0);

out:
	mutex_unlock(&lfsck->ml_mutex);
	return (rc < 0 ? rc : 0);
}

int mdd_lfsck_stop(const struct lu_env *env, struct md_lfsck *lfsck,
		   bool pause)
{
	struct ptlrpc_thread *thread = &lfsck->ml_thread;
	struct l_wait_info    lwi    = { 0 };
	ENTRY;

	if (!lfsck->ml_initialized)
		RETURN(0);

	mutex_lock(&lfsck->ml_mutex);
	spin_lock(&lfsck->ml_lock);
	if (thread_is_init(thread) || thread_is_stopped(thread)) {
		spin_unlock(&lfsck->ml_lock);
		mutex_unlock(&lfsck->ml_mutex);
		RETURN(-EALREADY);
	}

	if (pause)
		lfsck->ml_paused = 1;
	thread_set_flags(thread, SVC_STOPPING);
	/* The LFSCK thread may be sleeping on low layer wait queue,
	 * wake it up. */
	if (likely(lfsck->ml_di_oit != NULL))
		lfsck->ml_obj_oit->do_index_ops->dio_it.put(env,
							    lfsck->ml_di_oit);
	spin_unlock(&lfsck->ml_lock);

	cfs_waitq_broadcast(&thread->t_ctl_waitq);
	l_wait_event(thread->t_ctl_waitq,
		     thread_is_stopped(thread),
		     &lwi);
	mutex_unlock(&lfsck->ml_mutex);

	RETURN(0);
}

static const struct lu_fid lfsck_it_fid = { .f_seq = FID_SEQ_LOCAL_FILE,
					    .f_oid = OTABLE_IT_OID,
					    .f_ver = 0 };

int mdd_lfsck_setup(const struct lu_env *env, struct mdd_device *mdd)
{
	struct md_lfsck		*lfsck = &mdd->mdd_lfsck;
	struct dt_object	*obj;
	struct lu_fid		 fid;
	int			 rc;

	ENTRY;

	LASSERT(!lfsck->ml_initialized);

	lfsck->ml_initialized = 1;
	mutex_init(&lfsck->ml_mutex);
	spin_lock_init(&lfsck->ml_lock);
	CFS_INIT_LIST_HEAD(&lfsck->ml_list_scan);
	CFS_INIT_LIST_HEAD(&lfsck->ml_list_dir);
	CFS_INIT_LIST_HEAD(&lfsck->ml_list_double_scan);
	CFS_INIT_LIST_HEAD(&lfsck->ml_list_idle);
	cfs_waitq_init(&lfsck->ml_thread.t_ctl_waitq);

	obj = dt_locate(env, mdd->mdd_bottom, &lfsck_it_fid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	lfsck->ml_obj_oit = obj;
	rc = obj->do_ops->do_index_try(env, obj, &dt_otable_features);
	if (rc != 0) {
		if (rc == -ENOTSUPP)
			RETURN(0);
		GOTO(out, rc);
	}

	/* LFSCK bookmark */
	fid_zero(&fid);
	rc = mdd_local_file_create(env, mdd, &mdd->mdd_local_root_fid,
				   lfsck_bookmark_name,
				   S_IFREG | S_IRUGO | S_IWUSR, &fid);
	if (rc < 0)
		GOTO(out, rc);

	obj = dt_locate(env, mdd->mdd_bottom, &fid);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	LASSERT(lu_object_exists(&obj->do_lu));
	lfsck->ml_bookmark_obj = obj;

	rc = mdd_lfsck_bookmark_load(env, lfsck);
	if (rc == -ENODATA)
		rc = mdd_lfsck_bookmark_init(env, lfsck);
	if (rc != 0)
		GOTO(out, rc);

	rc = mdd_lfsck_namespace_setup(env, lfsck);
	if (rc < 0)
		GOTO(out, rc);
	/* XXX: LFSCK components initialization to be added here. */
	RETURN(0);
out:
	lu_object_put(env, &lfsck->ml_obj_oit->do_lu);
	lfsck->ml_obj_oit = NULL;
	return 0;
}

void mdd_lfsck_cleanup(const struct lu_env *env, struct mdd_device *mdd)
{
	struct md_lfsck		*lfsck  = &mdd->mdd_lfsck;
	struct ptlrpc_thread	*thread = &lfsck->ml_thread;
	struct lfsck_component	*com;

	if (!lfsck->ml_initialized)
		return;

	LASSERT(thread_is_init(thread) || thread_is_stopped(thread));

	if (lfsck->ml_obj_oit != NULL) {
		lu_object_put(env, &lfsck->ml_obj_oit->do_lu);
		lfsck->ml_obj_oit = NULL;
	}

	LASSERT(lfsck->ml_obj_dir == NULL);

	if (lfsck->ml_bookmark_obj != NULL) {
		lu_object_put(env, &lfsck->ml_bookmark_obj->do_lu);
		lfsck->ml_bookmark_obj = NULL;
	}

	while (!cfs_list_empty(&lfsck->ml_list_scan)) {
		com = cfs_list_entry(lfsck->ml_list_scan.next,
				     struct lfsck_component,
				     lc_link);
		mdd_lfsck_component_cleanup(env, com);
	}

	LASSERT(cfs_list_empty(&lfsck->ml_list_dir));

	while (!cfs_list_empty(&lfsck->ml_list_double_scan)) {
		com = cfs_list_entry(lfsck->ml_list_double_scan.next,
				     struct lfsck_component,
				     lc_link);
		mdd_lfsck_component_cleanup(env, com);
	}

	while (!cfs_list_empty(&lfsck->ml_list_idle)) {
		com = cfs_list_entry(lfsck->ml_list_idle.next,
				     struct lfsck_component,
				     lc_link);
		mdd_lfsck_component_cleanup(env, com);
	}
}
