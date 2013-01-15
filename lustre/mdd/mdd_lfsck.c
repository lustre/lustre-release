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
 * Copyright (c) 2012, Intel Corporation.
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
#define MDS_DIR_DUMMY_START		0xffffffffffffffffULL

const char lfsck_bookmark_name[] = "lfsck_bookmark";

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

static void mdd_lfsck_component_cleanup(const struct lu_env *env,
					struct lfsck_component *com)
{
	if (!cfs_list_empty(&com->lc_link))
		cfs_list_del_init(&com->lc_link);
	if (!cfs_list_empty(&com->lc_link_dir))
		cfs_list_del_init(&com->lc_link_dir);

	mdd_lfsck_component_put(env, com);
}

static void mdd_lfsck_pos_fill(const struct lu_env *env, struct md_lfsck *lfsck,
			       struct lfsck_position *pos, bool oit_processed,
			       bool dir_processed)
{
	const struct dt_it_ops *iops = &lfsck->ml_obj_oit->do_index_ops->dio_it;

	spin_lock(&lfsck->ml_lock);
	if (unlikely(lfsck->ml_di_oit == NULL)) {
		spin_unlock(&lfsck->ml_lock);
		memset(pos, 0, sizeof(*pos));
		return;
	}

	pos->lp_oit_cookie = iops->store(env, lfsck->ml_di_oit);

	LASSERT(pos->lp_oit_cookie > 0);

	if (!oit_processed)
		pos->lp_oit_cookie--;

	if (lfsck->ml_di_dir != NULL) {
		struct dt_object *dto = lfsck->ml_obj_dir;

		pos->lp_dir_parent = *lu_object_fid(&dto->do_lu);
		pos->lp_dir_cookie = dto->do_index_ops->dio_it.store(env,
							lfsck->ml_di_dir);

		LASSERT(pos->lp_dir_cookie != MDS_DIR_DUMMY_START);

		if (pos->lp_dir_cookie == MDS_DIR_END_OFF)
			LASSERT(dir_processed);

		/* For the dir which just to be processed,
		 * lp_dir_cookie will become MDS_DIR_DUMMY_START,
		 * which can be correctly handled by mdd_lfsck_prep. */
		if (!dir_processed)
			pos->lp_dir_cookie--;
	} else {
		fid_zero(&pos->lp_dir_parent);
		pos->lp_dir_cookie = 0;
	}
	spin_unlock(&lfsck->ml_lock);
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

	memset(mb, 0, sizeof(mb));
	mb->lb_magic = LFSCK_BOOKMARK_MAGIC;
	mb->lb_version = LFSCK_VERSION_V1;
	mutex_lock(&lfsck->ml_mutex);
	rc = mdd_lfsck_bookmark_store(env, lfsck);
	mutex_unlock(&lfsck->ml_mutex);
	return rc;
}

/* helper functions for framework */

static int object_is_client_visible(const struct lu_env *env,
				    struct mdd_device *mdd,
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

		/* XXX: need more processing for remote object in the future. */
		if (!mdd_object_exists(obj) || mdd_object_remote(obj)) {
			mdd_object_put(env, obj);
			return 0;
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
			   bool oit, bool new_checked)
{
	struct lfsck_component *com;

	cfs_list_for_each_entry(com, &lfsck->ml_list_scan, lc_link) {
		com->lc_ops->lfsck_fail(env, com, oit, new_checked);
	}
}

static int mdd_lfsck_checkpoint(const struct lu_env *env,
				struct md_lfsck *lfsck, bool oit)
{
	struct lfsck_component *com;
	int			rc;

	if (likely(cfs_time_beforeq(cfs_time_current(),
				    lfsck->ml_time_next_checkpoint)))
		return 0;

	mdd_lfsck_pos_fill(env, lfsck, &lfsck->ml_pos_current, oit, !oit);
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
		GOTO(out, rc = (rc >= 0 ? 0 : rc));
	}

	rc = iops->load(env, lfsck->ml_di_oit, pos->lp_oit_cookie);
	if (rc < 0)
		GOTO(out, rc);

	if (fid_is_zero(&pos->lp_dir_parent))
		GOTO(out, rc = 0);

	/* Find the directory for namespace-based traverse. */
	obj = mdd_object_find(env, mdd, &pos->lp_dir_parent);
	if (obj == NULL)
		GOTO(out, rc = 0);
	else if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	/* XXX: need more processing for remote object in the future. */
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

	rc = iops->load(env, di, pos->lp_dir_cookie);
	if (rc == 0)
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

	if (rc != 0)
		return (rc > 0 ? 0 : rc);

	mdd_lfsck_pos_fill(env, lfsck, &lfsck->ml_pos_current, false, false);
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

	rc = object_is_client_visible(env, mdd_lfsck2mdd(lfsck), obj);
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
		mdd_lfsck_fail(env, lfsck, false, false);
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

	mdd_lfsck_pos_fill(env, lfsck, &lfsck->ml_pos_current, true, true);
	cfs_list_for_each_entry_safe(com, next, &lfsck->ml_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_post(env, com, result);
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

		lfsck->ml_new_scanned++;
		rc = iops->rec(env, di, (struct dt_rec *)ent,
			       lfsck->ml_args_dir);
		if (rc != 0) {
			mdd_lfsck_fail(env, lfsck, false, true);
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
			mdd_lfsck_fail(env, lfsck, false, true);
			if (bk->lb_param & LPF_FAILOUT)
				RETURN(PTR_ERR(child));
			else
				goto checkpoint;
		}

		/* XXX: need more processing for remote object in the future. */
		if (mdd_object_exists(child) && !mdd_object_remote(child))
			rc = mdd_lfsck_exec_dir(env, lfsck, child, ent);
		mdd_object_put(env, child);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

checkpoint:
		rc = mdd_lfsck_checkpoint(env, lfsck, false);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

		/* Rate control. */
		mdd_lfsck_control_speed(lfsck);
		if (unlikely(!thread_is_running(thread)))
			RETURN(0);

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

		lfsck->ml_new_scanned++;
		rc = iops->rec(env, di, (struct dt_rec *)fid, 0);
		if (rc != 0) {
			mdd_lfsck_fail(env, lfsck, true, true);
			if (bk->lb_param & LPF_FAILOUT)
				RETURN(rc);
			else
				goto checkpoint;
		}

		target = mdd_object_find(env, mdd, fid);
		if (target == NULL) {
			goto checkpoint;
		} else if (IS_ERR(target)) {
			mdd_lfsck_fail(env, lfsck, true, true);
			if (bk->lb_param & LPF_FAILOUT)
				RETURN(PTR_ERR(target));
			else
				goto checkpoint;
		}

		/* XXX: In fact, low layer otable-based iteration should not
		 * 	return agent object. But before LU-2646 resolved, we
		 * 	need more processing for agent object. */
		if (mdd_object_exists(target) && !mdd_object_remote(target))
			rc = mdd_lfsck_exec_oit(env, lfsck, target);
		mdd_object_put(env, target);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

checkpoint:
		rc = mdd_lfsck_checkpoint(env, lfsck, true);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

		/* Rate control. */
		mdd_lfsck_control_speed(lfsck);

		rc = iops->next(env, di);
		if (rc > 0)
			lfsck->ml_oit_over = 1;

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
	if (start == NULL && cfs_list_empty(&lfsck->ml_list_scan))
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
				rc = com->lc_ops->lfsck_post(env, com, 0);
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
	if (bk->lb_param & LPF_DRYRUN)
		lfsck->ml_args_dir |= LUDA_VERIFY_DRYRUN;

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
	struct md_lfsck  *lfsck = &mdd->mdd_lfsck;
	struct dt_object *obj;
	int		  rc;
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
			rc = 0;

		RETURN(rc);
	}

	obj = dt_store_open(env, mdd->mdd_bottom, "", lfsck_bookmark_name,
			    &mdd_env_info(env)->mti_fid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	lfsck->ml_bookmark_obj = obj;
	rc = mdd_lfsck_bookmark_load(env, lfsck);
	if (rc == -ENODATA)
		rc = mdd_lfsck_bookmark_init(env, lfsck);

	/* XXX: LFSCK components initialization to be added here. */

	RETURN(rc);
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
