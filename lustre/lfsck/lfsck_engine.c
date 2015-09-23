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
 * Copyright (c) 2013, 2015, Intel Corporation.
 */
/*
 * lustre/lfsck/lfsck_engine.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LFSCK

#include <lu_object.h>
#include <dt_object.h>
#include <lustre_net.h>
#include <lustre_fid.h>
#include <obd_support.h>
#include <lustre_lib.h>

#include "lfsck_internal.h"

int lfsck_unpack_ent(struct lu_dirent *ent, __u64 *cookie, __u16 *type)
{
	struct luda_type	*lt;
	int			 align = sizeof(*lt) - 1;
	int			 len;

	fid_le_to_cpu(&ent->lde_fid, &ent->lde_fid);
	*cookie = le64_to_cpu(ent->lde_hash);
	ent->lde_reclen = le16_to_cpu(ent->lde_reclen);
	ent->lde_namelen = le16_to_cpu(ent->lde_namelen);
	ent->lde_attrs = le32_to_cpu(ent->lde_attrs);

	if (unlikely(!(ent->lde_attrs & LUDA_TYPE)))
		return -EINVAL;

	len = (ent->lde_namelen + align) & ~align;
	lt = (struct luda_type *)(ent->lde_name + len);
	*type = le16_to_cpu(lt->lt_type);

	/* Make sure the name is terminated with '\0'. The data (object type)
	 * after ent::lde_name maybe broken, but we have stored such data in
	 * the output parameter @type as above. */
	ent->lde_name[ent->lde_namelen] = '\0';

	return 0;
}

static void lfsck_di_oit_put(const struct lu_env *env, struct lfsck_instance *lfsck)
{
	const struct dt_it_ops	*iops;
	struct dt_it		*di;

	spin_lock(&lfsck->li_lock);
	iops = &lfsck->li_obj_oit->do_index_ops->dio_it;
	di = lfsck->li_di_oit;
	lfsck->li_di_oit = NULL;
	spin_unlock(&lfsck->li_lock);
	iops->put(env, di);
}

static void lfsck_di_dir_put(const struct lu_env *env, struct lfsck_instance *lfsck)
{
	const struct dt_it_ops	*iops;
	struct dt_it		*di;

	spin_lock(&lfsck->li_lock);
	iops = &lfsck->li_obj_dir->do_index_ops->dio_it;
	di = lfsck->li_di_dir;
	lfsck->li_di_dir = NULL;
	lfsck->li_cookie_dir = 0;
	spin_unlock(&lfsck->li_lock);
	iops->put(env, di);
}

static int lfsck_parent_fid(const struct lu_env *env, struct dt_object *obj,
			    struct lu_fid *fid)
{
	if (unlikely(!S_ISDIR(lfsck_object_type(obj)) ||
		     !dt_try_as_dir(env, obj)))
		return -ENOTDIR;

	return dt_lookup(env, obj, (struct dt_rec *)fid,
			 (const struct dt_key *)"..");
}

/**
 * Check whether needs to scan the directory or not.
 *
 * 1) If we are not doing namespace LFSCK, or the given @obj is not directory,
 *    then needs not to scan the @obj. Otherwise,
 * 2) Global /ROOT needs to be scanned, backend root needs not to be scanned.
 * 3) If the @obj is neither IGIF nor normal FID (including .lustre and its
 *    sub-directories that have been scanned when the LFSCK engine start),
 *    then needs not to be scanned.
 * 4) If it is a remote object, then scanning the object will be done on the
 *    MDT on which the object really resides.
 * 5) If the local object has normal FID, then needs to be scanned. Otherwise,
 * 6) If the object has linkEA, then needs to be scanned. Otherwise,
 * 7) If none of the previous conditions are true, we need to check the parent
 *    directories whether this subdirectory is in a tree that should be scanned.
 *    Set the parent as current @obj, repeat 2)-7).
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 * \param[in] obj	pointer to the object to be checked
 *
 * \retval		positive number if the directory needs to be scanned
 * \retval		0 if the directory needs NOT to be scanned
 * \retval		negative error number on failure
 */
static int lfsck_needs_scan_dir(const struct lu_env *env,
				struct lfsck_instance *lfsck,
				struct dt_object *obj)
{
	struct lfsck_thread_info *info    = lfsck_env_info(env);
	struct lu_fid		 *fid     = &info->lti_fid;
	struct lu_seq_range	 *range   = &info->lti_range;
	struct seq_server_site	 *ss	  = lfsck_dev_site(lfsck);
	__u32			  idx	  = lfsck_dev_idx(lfsck);
	int			  depth   = 0;
	int			  rc      = 0;

	if (list_empty(&lfsck->li_list_dir) || !S_ISDIR(lfsck_object_type(obj)))
		return 0;

	LASSERT(ss != NULL);

	*fid = *lfsck_dto2fid(obj);
	while (1) {
		/* Global /ROOT is visible. */
		if (unlikely(lu_fid_eq(fid, &lfsck->li_global_root_fid)))
			return 1;

		/* Backend root is invisible. */
		if (unlikely(lu_fid_eq(fid, &lfsck->li_local_root_fid)))
			return 0;

		if (!fid_is_norm(fid) && !fid_is_igif(fid))
			return 0;

		fld_range_set_mdt(range);
		rc = fld_local_lookup(env, ss->ss_server_fld,
				      fid_seq(fid), range);
		if (rc != 0 || range->lsr_index != idx)
			/* Current FID should NOT be for the input parameter
			 * @obj, because the lfsck_master_oit_engine() has
			 * filtered out agent object. So current FID is for
			 * the ancestor of the original input parameter @obj.
			 * So the ancestor is a remote directory. The input
			 * parameter @obj is local directory, and should be
			 * scanned under such case. */
			return 1;

		/* normal FID on this target (locally) must be for the
		 * client-side visiable object. */
		if (fid_is_norm(fid))
			return 1;

		if (obj == NULL) {
			obj = lfsck_object_find_bottom(env, lfsck, fid);
			if (IS_ERR(obj))
				return PTR_ERR(obj);

			depth++;
			if (!dt_object_exists(obj))
				GOTO(out, rc = 0);
		}

		dt_read_lock(env, obj, MOR_TGT_CHILD);
		if (unlikely(lfsck_is_dead_obj(obj))) {
			dt_read_unlock(env, obj);

			GOTO(out, rc = 0);
		}

		rc = dt_xattr_get(env, obj,
				  lfsck_buf_get(env, NULL, 0), XATTR_NAME_LINK);
		dt_read_unlock(env, obj);
		if (rc >= 0)
			GOTO(out, rc = 1);

		if (rc < 0 && rc != -ENODATA)
			GOTO(out, rc);

		rc = lfsck_parent_fid(env, obj, fid);
		if (depth > 0)
			lfsck_object_put(env, obj);

		obj = NULL;
		if (rc != 0)
			return rc;

		if (!fid_is_sane(fid))
			return 0;
	}

out:
	if (depth > 0 && obj != NULL)
		lfsck_object_put(env, obj);

	return rc;
}

static int lfsck_load_stripe_lmv(const struct lu_env *env,
				 struct lfsck_instance *lfsck,
				 struct dt_object *obj)
{
	struct lmv_mds_md_v1	*lmv	= &lfsck_env_info(env)->lti_lmv;
	struct lfsck_lmv	*llmv;
	int			 rc;
	ENTRY;

	LASSERT(lfsck->li_obj_dir == NULL);
	LASSERT(lfsck->li_lmv == NULL);

	rc = lfsck_read_stripe_lmv(env, obj, lmv);
	if (rc == -ENODATA) {
		lfsck->li_obj_dir = lfsck_object_get(obj);

		RETURN(0);
	}

	if (rc < 0)
		RETURN(rc);

	OBD_ALLOC_PTR(llmv);
	if (llmv == NULL)
		RETURN(-ENOMEM);

	if (lmv->lmv_magic == LMV_MAGIC) {
		struct lfsck_slave_lmv_rec	*lslr;
		__u32				 stripes;

		llmv->ll_lmv_master = 1;
		if (lmv->lmv_stripe_count < 1)
			stripes = LFSCK_LMV_DEF_STRIPES;
		else if (lmv->lmv_stripe_count > LFSCK_LMV_MAX_STRIPES)
			stripes = LFSCK_LMV_MAX_STRIPES;
		else
			stripes = lmv->lmv_stripe_count;

		OBD_ALLOC_LARGE(lslr, sizeof(*lslr) * stripes);
		if (lslr == NULL) {
			OBD_FREE_PTR(llmv);

			RETURN(-ENOMEM);
		}

		llmv->ll_stripes_allocated = stripes;
		llmv->ll_hash_type = LMV_HASH_TYPE_UNKNOWN;
		llmv->ll_lslr = lslr;
	} else {
		llmv->ll_lmv_slave = 1;
	}

	lfsck->li_obj_dir = lfsck_object_get(obj);
	llmv->ll_lmv = *lmv;
	atomic_set(&llmv->ll_ref, 1);
	lfsck->li_lmv = llmv;

	RETURN(0);
}

/* LFSCK wrap functions */

static void lfsck_fail(const struct lu_env *env, struct lfsck_instance *lfsck,
		       bool new_checked)
{
	struct lfsck_component *com;

	list_for_each_entry(com, &lfsck->li_list_scan, lc_link) {
		com->lc_ops->lfsck_fail(env, com, new_checked);
	}
}

void lfsck_close_dir(const struct lu_env *env,
		     struct lfsck_instance *lfsck, int result)
{
	struct lfsck_component *com;
	ENTRY;

	if (lfsck->li_lmv != NULL) {
		lfsck->li_lmv->ll_exit_value = result;
		if (lfsck->li_obj_dir != NULL) {
			list_for_each_entry(com, &lfsck->li_list_dir,
					    lc_link_dir) {
				com->lc_ops->lfsck_close_dir(env, com);
			}
		}

		lfsck_lmv_put(env, lfsck->li_lmv);
		lfsck->li_lmv = NULL;
	}

	if (lfsck->li_di_dir != NULL) {
		const struct dt_it_ops	*dir_iops;
		struct dt_it		*dir_di   = lfsck->li_di_dir;

		LASSERT(lfsck->li_obj_dir != NULL);

		dir_iops = &lfsck->li_obj_dir->do_index_ops->dio_it;
		lfsck_di_dir_put(env, lfsck);
		dir_iops->fini(env, dir_di);
	}

	if (lfsck->li_obj_dir != NULL) {
		struct dt_object	*dir_obj  = lfsck->li_obj_dir;

		lfsck->li_obj_dir = NULL;
		lfsck_object_put(env, dir_obj);
	}

	EXIT;
}

int lfsck_open_dir(const struct lu_env *env,
		   struct lfsck_instance *lfsck, __u64 cookie)
{
	struct dt_object	*obj	= lfsck->li_obj_dir;
	struct dt_it		*di	= lfsck->li_di_dir;
	struct lfsck_component	*com;
	const struct dt_it_ops	*iops;
	int			 rc	= 0;
	ENTRY;

	LASSERT(obj != NULL);
	LASSERT(di == NULL);

	if (unlikely(!dt_try_as_dir(env, obj)))
		GOTO(out, rc = -ENOTDIR);

	list_for_each_entry(com, &lfsck->li_list_dir, lc_link_dir) {
		rc = com->lc_ops->lfsck_open_dir(env, com);
		if (rc != 0)
			GOTO(out, rc);
	}

	iops = &obj->do_index_ops->dio_it;
	di = iops->init(env, obj, lfsck->li_args_dir);
	if (IS_ERR(di))
		GOTO(out, rc = PTR_ERR(di));

	rc = iops->load(env, di, cookie);
	if (rc == 0 || (rc > 0 && cookie > 0))
		rc = iops->next(env, di);
	else if (rc > 0)
		rc = 0;

	if (rc != 0) {
		iops->put(env, di);
		iops->fini(env, di);
	} else {
		lfsck->li_cookie_dir = iops->store(env, di);
		spin_lock(&lfsck->li_lock);
		lfsck->li_di_dir = di;
		spin_unlock(&lfsck->li_lock);
	}

	GOTO(out, rc);

out:
	if (rc != 0)
		lfsck_close_dir(env, lfsck, rc);

	return rc;
}

static int lfsck_checkpoint(const struct lu_env *env,
			    struct lfsck_instance *lfsck)
{
	struct lfsck_component *com;
	int			rc  = 0;
	int			rc1 = 0;

	if (likely(cfs_time_beforeq(cfs_time_current(),
				    lfsck->li_time_next_checkpoint)))
		return 0;

	lfsck_pos_fill(env, lfsck, &lfsck->li_pos_checkpoint, false);
	list_for_each_entry(com, &lfsck->li_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_checkpoint(env, com, false);
		if (rc != 0)
			rc1 = rc;
	}

	lfsck->li_time_last_checkpoint = cfs_time_current();
	lfsck->li_time_next_checkpoint = lfsck->li_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);
	return rc1 != 0 ? rc1 : rc;
}

static int lfsck_prep(const struct lu_env *env, struct lfsck_instance *lfsck,
		      struct lfsck_start_param *lsp)
{
	struct dt_object       *obj	= NULL;
	struct lfsck_component *com;
	struct lfsck_component *next;
	struct lfsck_position  *pos	= NULL;
	const struct dt_it_ops *iops	=
				&lfsck->li_obj_oit->do_index_ops->dio_it;
	int			rc;
	ENTRY;

	LASSERT(lfsck->li_obj_dir == NULL);
	LASSERT(lfsck->li_di_dir == NULL);

	lfsck->li_current_oit_processed = 0;
	list_for_each_entry_safe(com, next, &lfsck->li_list_scan, lc_link) {
		com->lc_new_checked = 0;
		rc = com->lc_ops->lfsck_prep(env, com, lsp);
		if (rc != 0)
			GOTO(out, rc);

		if ((pos == NULL) ||
		    (!lfsck_pos_is_zero(&com->lc_pos_start) &&
		     lfsck_pos_is_eq(pos, &com->lc_pos_start) > 0))
			pos = &com->lc_pos_start;
	}

	/* Init otable-based iterator. */
	if (pos == NULL) {
		rc = iops->load(env, lfsck->li_di_oit, 0);
		if (rc > 0) {
			lfsck->li_oit_over = 1;
			rc = 0;
		}

		GOTO(out, rc);
	}

	rc = iops->load(env, lfsck->li_di_oit, pos->lp_oit_cookie);
	if (rc < 0)
		GOTO(out, rc);
	else if (rc > 0)
		lfsck->li_oit_over = 1;

	if (!lfsck->li_master || fid_is_zero(&pos->lp_dir_parent))
		GOTO(out, rc = 0);

	/* Find the directory for namespace-based traverse. */
	obj = lfsck_object_find_bottom(env, lfsck, &pos->lp_dir_parent);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	/* Remote directory will be scanned by the LFSCK instance
	 * on the MDT where the remote object really resides on. */
	if (!dt_object_exists(obj) || dt_object_remote(obj) ||
	    unlikely(!S_ISDIR(lfsck_object_type(obj))))
		GOTO(out, rc = 0);

	rc = lfsck_load_stripe_lmv(env, lfsck, obj);
	if (rc == 0) {
		/* For the master MDT-object of a striped directory,
		 * reset the iteration from the directory beginning. */
		if (lfsck->li_lmv != NULL && lfsck->li_lmv->ll_lmv_master)
			pos->lp_dir_cookie = 0;

		rc = lfsck_open_dir(env, lfsck, pos->lp_dir_cookie);
		if (rc > 0)
			/* The end of the directory. */
			rc = 0;
	}

	GOTO(out, rc);

out:
	if (obj != NULL)
		lfsck_object_put(env, obj);

	if (rc != 0) {
		lfsck_close_dir(env, lfsck, rc);
		list_for_each_entry_safe(com, next, &lfsck->li_list_scan,
					 lc_link) {
			com->lc_ops->lfsck_post(env, com, rc, true);
		}

		return rc;
	}

	rc = 0;
	lfsck_pos_fill(env, lfsck, &lfsck->li_pos_checkpoint, true);
	lfsck->li_pos_current = lfsck->li_pos_checkpoint;
	list_for_each_entry(com, &lfsck->li_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_checkpoint(env, com, true);
		if (rc != 0)
			break;
	}

	lfsck->li_time_last_checkpoint = cfs_time_current();
	lfsck->li_time_next_checkpoint = lfsck->li_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);
	return rc;
}

static int lfsck_exec_oit(const struct lu_env *env,
			  struct lfsck_instance *lfsck, struct dt_object *obj)
{
	struct lfsck_component *com;
	int			rc;
	ENTRY;

	LASSERT(lfsck->li_obj_dir == NULL);

	list_for_each_entry(com, &lfsck->li_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_exec_oit(env, com, obj);
		if (rc != 0)
			RETURN(rc);
	}

	rc = lfsck_needs_scan_dir(env, lfsck, obj);
	if (rc <= 0)
		GOTO(out, rc);

	rc = lfsck_load_stripe_lmv(env, lfsck, obj);
	if (rc == 0)
		rc = lfsck_open_dir(env, lfsck, 0);

	GOTO(out, rc);

out:
	if (rc < 0)
		lfsck_fail(env, lfsck, false);

	if (rc != 0)
		lfsck_close_dir(env, lfsck, rc);

	return rc > 0 ? 0 : rc;
}

static int lfsck_exec_dir(const struct lu_env *env,
			  struct lfsck_instance *lfsck,
			  struct lfsck_assistant_object *lso,
			  struct lu_dirent *ent, __u16 type)
{
	struct lfsck_component *com;
	int			rc;

	list_for_each_entry(com, &lfsck->li_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_exec_dir(env, com, lso, ent, type);
		if (rc != 0)
			return rc;
	}
	return 0;
}

static int lfsck_master_dir_engine(const struct lu_env *env,
				   struct lfsck_instance *lfsck);

static int lfsck_post(const struct lu_env *env, struct lfsck_instance *lfsck,
		      int result)
{
	struct lfsck_component *com;
	struct lfsck_component *next;
	int			rc  = result;

	lfsck_pos_fill(env, lfsck, &lfsck->li_pos_checkpoint, false);
	lfsck_close_dir(env, lfsck, result);

	while (thread_is_running(&lfsck->li_thread) && rc > 0 &&
	       !list_empty(&lfsck->li_list_lmv)) {
		struct lfsck_lmv_unit *llu;

		spin_lock(&lfsck->li_lock);
		llu = list_entry(lfsck->li_list_lmv.next,
				 struct lfsck_lmv_unit, llu_link);
		list_del_init(&llu->llu_link);
		spin_unlock(&lfsck->li_lock);

		lfsck->li_lmv = &llu->llu_lmv;
		lfsck->li_obj_dir = lfsck_object_get(llu->llu_obj);
		rc = lfsck_open_dir(env, lfsck, 0);
		if (rc == 0) {
			rc = lfsck_master_dir_engine(env, lfsck);
			lfsck_close_dir(env, lfsck, result);
		}
	}

	result = rc;

	list_for_each_entry_safe(com, next, &lfsck->li_list_scan, lc_link) {
		rc = com->lc_ops->lfsck_post(env, com, result, false);
		if (rc != 0)
			CDEBUG(D_LFSCK, "%s: lfsck_post at the component %u: "
			       "rc = %d\n", lfsck_lfsck2name(lfsck),
			       (__u32)com->lc_type, rc);
	}

	lfsck->li_time_last_checkpoint = cfs_time_current();
	lfsck->li_time_next_checkpoint = lfsck->li_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);

	/* Ignore some component post failure to make other can go ahead. */
	return result;
}

static int lfsck_double_scan(const struct lu_env *env,
			     struct lfsck_instance *lfsck)
{
	struct lfsck_component *com;
	struct lfsck_component *next;
	struct l_wait_info	lwi = { 0 };
	int			rc  = 0;
	int			rc1 = 0;

	list_for_each_entry(com, &lfsck->li_list_double_scan, lc_link) {
		rc = com->lc_ops->lfsck_double_scan(env, com);
		if (rc != 0)
			rc1 = rc;
	}

	l_wait_event(lfsck->li_thread.t_ctl_waitq,
		     atomic_read(&lfsck->li_double_scan_count) == 0,
		     &lwi);

	if (lfsck->li_status != LS_PAUSED &&
	    lfsck->li_status != LS_CO_PAUSED) {
		list_for_each_entry_safe(com, next, &lfsck->li_list_double_scan,
					 lc_link) {
			spin_lock(&lfsck->li_lock);
			list_move_tail(&com->lc_link, &lfsck->li_list_idle);
			spin_unlock(&lfsck->li_lock);
		}
	}

	return rc1 != 0 ? rc1 : rc;
}

static void lfsck_quit(const struct lu_env *env, struct lfsck_instance *lfsck)
{
	struct lfsck_component *com;
	struct lfsck_component *next;

	list_for_each_entry_safe(com, next, &lfsck->li_list_scan,
				 lc_link) {
		if (com->lc_ops->lfsck_quit != NULL)
			com->lc_ops->lfsck_quit(env, com);

		spin_lock(&lfsck->li_lock);
		list_del_init(&com->lc_link_dir);
		list_move_tail(&com->lc_link, &lfsck->li_list_idle);
		spin_unlock(&lfsck->li_lock);
	}

	list_for_each_entry_safe(com, next, &lfsck->li_list_double_scan,
				 lc_link) {
		if (com->lc_ops->lfsck_quit != NULL)
			com->lc_ops->lfsck_quit(env, com);

		spin_lock(&lfsck->li_lock);
		list_move_tail(&com->lc_link, &lfsck->li_list_idle);
		spin_unlock(&lfsck->li_lock);
	}
}

/* LFSCK engines */

static int lfsck_master_dir_engine(const struct lu_env *env,
				   struct lfsck_instance *lfsck)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct dt_object		*dir	= lfsck->li_obj_dir;
	const struct dt_it_ops		*iops	= &dir->do_index_ops->dio_it;
	struct dt_it			*di	= lfsck->li_di_dir;
	struct lu_dirent		*ent	=
			(struct lu_dirent *)info->lti_key;
	struct lfsck_bookmark		*bk	= &lfsck->li_bookmark_ram;
	struct ptlrpc_thread		*thread = &lfsck->li_thread;
	struct lfsck_assistant_object	*lso	= NULL;
	int				 rc;
	__u16				 type;
	ENTRY;

	do {
		if (CFS_FAIL_TIMEOUT(OBD_FAIL_LFSCK_DELAY2, cfs_fail_val) &&
		    unlikely(!thread_is_running(thread))) {
			CDEBUG(D_LFSCK, "%s: scan dir exit for engine stop, "
			       "parent "DFID", cookie "LPX64"\n",
			       lfsck_lfsck2name(lfsck),
			       PFID(lfsck_dto2fid(dir)), lfsck->li_cookie_dir);

			GOTO(out, rc = 0);
		}

		lfsck->li_new_scanned++;
		rc = iops->rec(env, di, (struct dt_rec *)ent,
			       lfsck->li_args_dir);
		if (rc == 0)
			rc = lfsck_unpack_ent(ent, &lfsck->li_cookie_dir,
					      &type);

		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: scan dir failed at rec(), "
			       "parent "DFID", cookie "LPX64": rc = %d\n",
			       lfsck_lfsck2name(lfsck),
			       PFID(lfsck_dto2fid(dir)),
			       lfsck->li_cookie_dir, rc);
			lfsck_fail(env, lfsck, true);
			if (bk->lb_param & LPF_FAILOUT)
				GOTO(out, rc);
			else
				goto checkpoint;
		}

		if (ent->lde_attrs & LUDA_IGNORE)
			goto checkpoint;

		/* skip dot entry. */
		if (ent->lde_namelen == 1 && ent->lde_name[0] == '.')
			goto checkpoint;

		if (lso == NULL) {
			lso = lfsck_assistant_object_init(env,
				lfsck_dto2fid(dir), NULL,
				lfsck->li_pos_current.lp_oit_cookie, true);
			if (IS_ERR(lso)) {
				if (bk->lb_param & LPF_FAILOUT)
					RETURN(PTR_ERR(lso));

				lso = NULL;
				goto checkpoint;
			}
		}

		/* The type in the @ent structure may has been overwritten,
		 * so we need to pass the @type parameter independently. */
		rc = lfsck_exec_dir(env, lfsck, lso, ent, type);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(out, rc);

checkpoint:
		rc = lfsck_checkpoint(env, lfsck);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(out, rc);

		/* Rate control. */
		lfsck_control_speed(lfsck);
		if (unlikely(!thread_is_running(thread))) {
			CDEBUG(D_LFSCK, "%s: scan dir exit for engine stop, "
			       "parent "DFID", cookie "LPX64"\n",
			       lfsck_lfsck2name(lfsck),
			       PFID(lfsck_dto2fid(dir)),
			       lfsck->li_cookie_dir);
			GOTO(out, rc = 0);
		}

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_FATAL2)) {
			spin_lock(&lfsck->li_lock);
			thread_set_flags(thread, SVC_STOPPING);
			spin_unlock(&lfsck->li_lock);
			GOTO(out, rc = -EINVAL);
		}

		rc = iops->next(env, di);
	} while (rc == 0);

	if (rc > 0 && !lfsck->li_oit_over)
		lfsck_close_dir(env, lfsck, rc);

	GOTO(out, rc);

out:
	if (lso != NULL)
		lfsck_assistant_object_put(env, lso);

	return rc;
}

/**
 * Object-table based iteration engine.
 *
 * Object-table based iteration is the basic linear engine to scan all the
 * objects on current device in turn. For each object, it calls all the
 * registered LFSCK component(s)' API to perform related consistency
 * verification.
 *
 * It flushes related LFSCK trace files to disk via making checkpoint
 * periodically. Then if the server crashed or the LFSCK is paused, the
 * LFSCK can resume from the latest checkpoint.
 *
 * It also controls the whole LFSCK speed via lfsck_control_speed() to
 * avoid the server to become overload.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 *
 * \retval		positive number if all objects have been scanned
 * \retval		0 if the iteration is stopped or paused
 * \retval		negative error number on failure
 */
static int lfsck_master_oit_engine(const struct lu_env *env,
				   struct lfsck_instance *lfsck)
{
	struct lfsck_thread_info *info	= lfsck_env_info(env);
	const struct dt_it_ops	 *iops	=
				&lfsck->li_obj_oit->do_index_ops->dio_it;
	struct dt_it		 *di	= lfsck->li_di_oit;
	struct lu_fid		 *fid	= &info->lti_fid;
	struct lfsck_bookmark	 *bk	= &lfsck->li_bookmark_ram;
	struct ptlrpc_thread	 *thread = &lfsck->li_thread;
	struct seq_server_site	 *ss	= lfsck_dev_site(lfsck);
	__u32			 idx	= lfsck_dev_idx(lfsck);
	int			 rc;
	ENTRY;

	if (unlikely(ss == NULL))
		RETURN(-EIO);

	do {
		struct dt_object *target;

		if (lfsck->li_di_dir != NULL) {
			rc = lfsck_master_dir_engine(env, lfsck);
			if (rc <= 0)
				RETURN(rc);
		}

		if (unlikely(lfsck->li_oit_over))
			RETURN(1);

		if (CFS_FAIL_TIMEOUT(OBD_FAIL_LFSCK_DELAY1, cfs_fail_val) &&
		    unlikely(!thread_is_running(thread))) {
			CDEBUG(D_LFSCK, "%s: OIT scan exit for engine stop, "
			       "cookie "LPU64"\n",
			       lfsck_lfsck2name(lfsck), iops->store(env, di));

			RETURN(0);
		}

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_CRASH))
			RETURN(0);

		lfsck->li_current_oit_processed = 1;

		if (!list_empty(&lfsck->li_list_lmv)) {
			struct lfsck_lmv_unit *llu;

			spin_lock(&lfsck->li_lock);
			llu = list_entry(lfsck->li_list_lmv.next,
					 struct lfsck_lmv_unit, llu_link);
			list_del_init(&llu->llu_link);
			spin_unlock(&lfsck->li_lock);

			lfsck->li_lmv = &llu->llu_lmv;
			lfsck->li_obj_dir = lfsck_object_get(llu->llu_obj);
			rc = lfsck_open_dir(env, lfsck, 0);
			if (rc == 0)
				rc = lfsck_master_dir_engine(env, lfsck);

			if (rc <= 0)
				RETURN(rc);
		}

		lfsck->li_new_scanned++;
		lfsck->li_pos_current.lp_oit_cookie = iops->store(env, di);
		rc = iops->rec(env, di, (struct dt_rec *)fid, 0);
		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: OIT scan failed at rec(): "
			       "rc = %d\n", lfsck_lfsck2name(lfsck), rc);
			lfsck_fail(env, lfsck, true);
			if (rc < 0 && bk->lb_param & LPF_FAILOUT)
				RETURN(rc);
			else
				goto checkpoint;
		}

		if (unlikely(!fid_is_sane(fid))) {
			CDEBUG(D_LFSCK, "%s: OIT scan find invalid FID "DFID
			       ", skip it\n",
			       lfsck_lfsck2name(lfsck), PFID(fid));
			goto checkpoint;
		}

		if (fid_is_idif(fid)) {
			__u32 idx1 = fid_idif_ost_idx(fid);

			LASSERT(!lfsck->li_master);

			if (idx != idx1) {
				struct ost_id *oi = &info->lti_oi;

				if (unlikely(idx1 != 0)) {
					CDEBUG(D_LFSCK, "%s: invalid IDIF "DFID
					       ", not match device index %u\n",
					       lfsck_lfsck2name(lfsck),
					       PFID(fid), idx);

					goto checkpoint;
				}

				/* rebuild the IDIF with index to
				 * avoid double instances for the
				 * same object. */
				fid_to_ostid(fid, oi);
				ostid_to_fid(fid, oi, idx);
			}
		} else if (!fid_is_norm(fid) && !fid_is_igif(fid) &&
			   !fid_is_last_id(fid) &&
			   !lu_fid_eq(fid, &lfsck->li_global_root_fid)) {

			/* If the FID/object is only used locally and invisible
			 * to external nodes, then LFSCK will not handle it.
			 *
			 * dot_lustre sequence has been handled specially. */
			goto checkpoint;
		} else {
			struct lu_seq_range *range = &info->lti_range;

			if (lfsck->li_master)
				fld_range_set_mdt(range);
			else
				fld_range_set_ost(range);
			rc = fld_local_lookup(env, ss->ss_server_fld,
					      fid_seq(fid), range);
			if (rc != 0 || range->lsr_index != idx) {
				/* Remote object will be handled by the LFSCK
				 * instance on the MDT where the remote object
				 * really resides on. */
				rc = 0;
				goto checkpoint;
			}
		}

		target = lfsck_object_find_bottom(env, lfsck, fid);
		if (IS_ERR(target)) {
			CDEBUG(D_LFSCK, "%s: OIT scan failed at find target "
			       DFID", cookie "LPU64": rc = %d\n",
			       lfsck_lfsck2name(lfsck), PFID(fid),
			       iops->store(env, di), rc);
			lfsck_fail(env, lfsck, true);
			if (bk->lb_param & LPF_FAILOUT)
				RETURN(PTR_ERR(target));
			else
				goto checkpoint;
		}

		if (dt_object_exists(target))
			rc = lfsck_exec_oit(env, lfsck, target);

		lfsck_object_put(env, target);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

checkpoint:
		rc = lfsck_checkpoint(env, lfsck);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			RETURN(rc);

		/* Rate control. */
		lfsck_control_speed(lfsck);

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_FATAL1)) {
			spin_lock(&lfsck->li_lock);
			thread_set_flags(thread, SVC_STOPPING);
			spin_unlock(&lfsck->li_lock);
			RETURN(-EINVAL);
		}

		rc = iops->next(env, di);
		if (unlikely(rc > 0))
			lfsck->li_oit_over = 1;
		else if (likely(rc == 0))
			lfsck->li_current_oit_processed = 0;

		if (unlikely(!thread_is_running(thread))) {
			CDEBUG(D_LFSCK, "%s: OIT scan exit for engine stop, "
			       "cookie "LPU64"\n", lfsck_lfsck2name(lfsck),
			       iops->store(env, di));
			RETURN(0);
		}
	} while (rc == 0 || lfsck->li_di_dir != NULL);

	RETURN(rc);
}

int lfsck_master_engine(void *args)
{
	struct lfsck_thread_args *lta      = args;
	struct lu_env		 *env	   = &lta->lta_env;
	struct lfsck_instance	 *lfsck    = lta->lta_lfsck;
	struct ptlrpc_thread	 *thread   = &lfsck->li_thread;
	struct dt_object	 *oit_obj  = lfsck->li_obj_oit;
	const struct dt_it_ops	 *oit_iops = &oit_obj->do_index_ops->dio_it;
	struct dt_it		 *oit_di;
	struct l_wait_info	  lwi	   = { 0 };
	int			  rc;
	ENTRY;

	/* There will be some objects verification during the LFSCK start,
	 * such as the subsequent lfsck_verify_lpf(). Trigger low layer OI
	 * OI scrub before that to handle the potential inconsistence. */
	oit_di = oit_iops->init(env, oit_obj, lfsck->li_args_oit);
	if (IS_ERR(oit_di)) {
		rc = PTR_ERR(oit_di);
		CDEBUG(D_LFSCK, "%s: master engine fail to init iteration: "
		       "rc = %d\n", lfsck_lfsck2name(lfsck), rc);

		GOTO(fini_args, rc);
	}

	if (lfsck->li_master &&
	    (!list_empty(&lfsck->li_list_scan) ||
	     !list_empty(&lfsck->li_list_double_scan))) {
		rc = lfsck_verify_lpf(env, lfsck);
		/* Fail to verify the .lustre/lost+found/MDTxxxx/ may be not
		 * fatal, because the .lustre/lost+found/ maybe not accessed
		 * by the LFSCK if it does not add orphans or others to such
		 * directory. So go ahead until hit failure when really uses
		 * the directory. */
		if (rc != 0)
			CDEBUG(D_LFSCK, "%s: master engine fail to verify the "
			       ".lustre/lost+found/, go ahead: rc = %d\n",
			       lfsck_lfsck2name(lfsck), rc);
	}

	spin_lock(&lfsck->li_lock);
	lfsck->li_di_oit = oit_di;
	spin_unlock(&lfsck->li_lock);
	rc = lfsck_prep(env, lfsck, lta->lta_lsp);
	if (rc != 0)
		GOTO(fini_oit, rc);

	CDEBUG(D_LFSCK, "LFSCK entry: oit_flags = %#x, dir_flags = %#x, "
	       "oit_cookie = "LPU64", dir_cookie = "LPX64", parent = "DFID
	       ", pid = %d\n", lfsck->li_args_oit, lfsck->li_args_dir,
	       lfsck->li_pos_checkpoint.lp_oit_cookie,
	       lfsck->li_pos_checkpoint.lp_dir_cookie,
	       PFID(&lfsck->li_pos_checkpoint.lp_dir_parent),
	       current_pid());

	spin_lock(&lfsck->li_lock);
	thread_set_flags(thread, SVC_RUNNING);
	spin_unlock(&lfsck->li_lock);
	wake_up_all(&thread->t_ctl_waitq);

	l_wait_event(thread->t_ctl_waitq,
		     lfsck->li_start_unplug ||
		     !thread_is_running(thread),
		     &lwi);
	if (!thread_is_running(thread))
		GOTO(fini_oit, rc = 0);

	if (!list_empty(&lfsck->li_list_scan) ||
	    list_empty(&lfsck->li_list_double_scan))
		rc = lfsck_master_oit_engine(env, lfsck);
	else
		rc = 1;

	lfsck_pos_fill(env, lfsck, &lfsck->li_pos_checkpoint, false);
	CDEBUG(D_LFSCK, "LFSCK exit: oit_flags = %#x, dir_flags = %#x, "
	       "oit_cookie = "LPU64", dir_cookie = "LPX64", parent = "DFID
	       ", pid = %d, rc = %d\n", lfsck->li_args_oit, lfsck->li_args_dir,
	       lfsck->li_pos_checkpoint.lp_oit_cookie,
	       lfsck->li_pos_checkpoint.lp_dir_cookie,
	       PFID(&lfsck->li_pos_checkpoint.lp_dir_parent),
	       current_pid(), rc);

	if (!OBD_FAIL_CHECK(OBD_FAIL_LFSCK_CRASH))
		rc = lfsck_post(env, lfsck, rc);
	else
		lfsck_close_dir(env, lfsck, rc);

fini_oit:
	lfsck_di_oit_put(env, lfsck);
	oit_iops->fini(env, oit_di);
	if (rc == 1) {
		if (!list_empty(&lfsck->li_list_double_scan))
			rc = lfsck_double_scan(env, lfsck);
		else
			rc = 0;
	} else {
		lfsck_quit(env, lfsck);
	}

	/* XXX: Purge the pinned objects in the future. */

fini_args:
	spin_lock(&lfsck->li_lock);
	thread_set_flags(thread, SVC_STOPPED);
	spin_unlock(&lfsck->li_lock);
	wake_up_all(&thread->t_ctl_waitq);
	lfsck_thread_args_fini(lta);
	return rc;
}

static inline bool lfsck_assistant_req_empty(struct lfsck_assistant_data *lad)
{
	bool empty = false;

	spin_lock(&lad->lad_lock);
	if (list_empty(&lad->lad_req_list))
		empty = true;
	spin_unlock(&lad->lad_lock);

	return empty;
}

/**
 * Query the LFSCK status from the instatnces on remote servers.
 *
 * The LFSCK assistant thread queries the LFSCK instances on other
 * servers (MDT/OST) about their status, such as whether they have
 * finished the phase1/phase2 scanning or not, and so on.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_assistant_query_others(const struct lu_env *env,
					struct lfsck_component *com)
{
	struct lfsck_thread_info	  *info  = lfsck_env_info(env);
	struct lfsck_request		  *lr	 = &info->lti_lr;
	struct lfsck_async_interpret_args *laia  = &info->lti_laia;
	struct lfsck_instance		  *lfsck = com->lc_lfsck;
	struct lfsck_assistant_data	  *lad   = com->lc_data;
	struct ptlrpc_request_set	  *set;
	struct lfsck_tgt_descs		  *ltds;
	struct lfsck_tgt_desc		  *ltd;
	struct list_head		  *phase_head;
	int				   rc    = 0;
	int				   rc1   = 0;
	ENTRY;

	set = ptlrpc_prep_set();
	if (set == NULL)
		RETURN(-ENOMEM);

	lad->lad_touch_gen++;
	memset(lr, 0, sizeof(*lr));
	lr->lr_event = LE_QUERY;
	lr->lr_active = com->lc_type;
	laia->laia_com = com;
	laia->laia_lr = lr;
	laia->laia_shared = 0;

	if (!list_empty(&lad->lad_mdt_phase1_list)) {
		ltds = &lfsck->li_mdt_descs;
		lr->lr_flags = 0;
		phase_head = &lad->lad_mdt_phase1_list;
	} else if (com->lc_type != LFSCK_TYPE_LAYOUT) {
		goto out;
	} else {

again:
		ltds = &lfsck->li_ost_descs;
		lr->lr_flags = LEF_TO_OST;
		phase_head = &lad->lad_ost_phase1_list;
	}

	laia->laia_ltds = ltds;
	spin_lock(&ltds->ltd_lock);
	while (!list_empty(phase_head)) {
		struct list_head *phase_list;
		__u32		 *gen;

		if (com->lc_type == LFSCK_TYPE_LAYOUT) {
			ltd = list_entry(phase_head->next,
					 struct lfsck_tgt_desc,
					 ltd_layout_phase_list);
			phase_list = &ltd->ltd_layout_phase_list;
			gen = &ltd->ltd_layout_gen;
		} else {
			ltd = list_entry(phase_head->next,
					 struct lfsck_tgt_desc,
					 ltd_namespace_phase_list);
			phase_list = &ltd->ltd_namespace_phase_list;
			gen = &ltd->ltd_namespace_gen;
		}

		if (*gen == lad->lad_touch_gen)
			break;

		*gen = lad->lad_touch_gen;
		list_move_tail(phase_list, phase_head);
		atomic_inc(&ltd->ltd_ref);
		laia->laia_ltd = ltd;
		spin_unlock(&ltds->ltd_lock);
		rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					 lfsck_async_interpret_common,
					 laia, LFSCK_QUERY);
		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: LFSCK assistant fail to query "
			       "%s %x for %s: rc = %d\n",
			       lfsck_lfsck2name(lfsck),
			       (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
			       ltd->ltd_index, lad->lad_name, rc);
			lfsck_tgt_put(ltd);
			rc1 = rc;
		}
		spin_lock(&ltds->ltd_lock);
	}
	spin_unlock(&ltds->ltd_lock);

	rc = ptlrpc_set_wait(set);
	if (rc < 0) {
		ptlrpc_set_destroy(set);
		RETURN(rc);
	}

	if (com->lc_type == LFSCK_TYPE_LAYOUT && !(lr->lr_flags & LEF_TO_OST) &&
	    list_empty(&lad->lad_mdt_phase1_list))
		goto again;

out:
	ptlrpc_set_destroy(set);

	RETURN(rc1 != 0 ? rc1 : rc);
}

/**
 * Notify the LFSCK event to the instances on remote servers.
 *
 * The LFSCK assistant thread notifies the LFSCK instances on other
 * servers (MDT/OST) about some events, such as start new scanning,
 * stop the scanning, this LFSCK instance will exit, and so on.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] lr	pointer to the LFSCK event request
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_assistant_notify_others(const struct lu_env *env,
					 struct lfsck_component *com,
					 struct lfsck_request *lr)
{
	struct lfsck_thread_info	  *info  = lfsck_env_info(env);
	struct lfsck_async_interpret_args *laia  = &info->lti_laia;
	struct lfsck_instance		  *lfsck = com->lc_lfsck;
	struct lfsck_assistant_data	  *lad   = com->lc_data;
	struct lfsck_bookmark		  *bk    = &lfsck->li_bookmark_ram;
	struct ptlrpc_request_set	  *set;
	struct lfsck_tgt_descs		  *ltds;
	struct lfsck_tgt_desc		  *ltd;
	struct lfsck_tgt_desc		  *next;
	__u32				   idx;
	int				   rc    = 0;
	int				   rc1	 = 0;
	ENTRY;

	set = ptlrpc_prep_set();
	if (set == NULL)
		RETURN(-ENOMEM);

	lr->lr_index = lfsck_dev_idx(lfsck);
	lr->lr_active = com->lc_type;
	laia->laia_com = com;
	laia->laia_lr = lr;
	laia->laia_shared = 0;

	switch (lr->lr_event) {
	case LE_START:
		if (com->lc_type != LFSCK_TYPE_LAYOUT)
			goto next;

		lr->lr_valid = LSV_SPEED_LIMIT | LSV_ERROR_HANDLE | LSV_DRYRUN;
		lr->lr_speed = bk->lb_speed_limit;
		lr->lr_version = bk->lb_version;
		lr->lr_param |= bk->lb_param;
		lr->lr_async_windows = bk->lb_async_windows;
		lr->lr_flags = LEF_TO_OST;

		/* Notify OSTs firstly, then handle other MDTs if needed. */
		ltds = &lfsck->li_ost_descs;
		laia->laia_ltds = ltds;
		down_read(&ltds->ltd_rw_sem);
		cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
			ltd = lfsck_tgt_get(ltds, idx);
			LASSERT(ltd != NULL);

			laia->laia_ltd = ltd;
			ltd->ltd_layout_done = 0;
			ltd->ltd_synced_failures = 0;
			rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					lfsck_async_interpret_common,
					laia, LFSCK_NOTIFY);
			if (rc != 0) {
				lfsck_lad_set_bitmap(env, com, idx);
				CDEBUG(D_LFSCK, "%s: LFSCK assistant fail to "
				       "notify OST %x for %s start: rc = %d\n",
				       lfsck_lfsck2name(lfsck), idx,
				       lad->lad_name, rc);
				lfsck_tgt_put(ltd);
			}
		}
		up_read(&ltds->ltd_rw_sem);

		/* Sync up */
		rc = ptlrpc_set_wait(set);
		if (rc < 0) {
			ptlrpc_set_destroy(set);
			RETURN(rc);
		}

next:
		if (!(bk->lb_param & LPF_ALL_TGT))
			break;

		/* link other MDT targets locallly. */
		ltds = &lfsck->li_mdt_descs;
		spin_lock(&ltds->ltd_lock);
		if (com->lc_type == LFSCK_TYPE_LAYOUT) {
			cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
				ltd = lfsck_ltd2tgt(ltds, idx);
				LASSERT(ltd != NULL);

				if (!list_empty(&ltd->ltd_layout_list))
					continue;

				list_add_tail(&ltd->ltd_layout_list,
					      &lad->lad_mdt_list);
				list_add_tail(&ltd->ltd_layout_phase_list,
					      &lad->lad_mdt_phase1_list);
			}
		} else {
			cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
				ltd = lfsck_ltd2tgt(ltds, idx);
				LASSERT(ltd != NULL);

				if (!list_empty(&ltd->ltd_namespace_list))
					continue;

				list_add_tail(&ltd->ltd_namespace_list,
					      &lad->lad_mdt_list);
				list_add_tail(&ltd->ltd_namespace_phase_list,
					      &lad->lad_mdt_phase1_list);
			}
		}
		spin_unlock(&ltds->ltd_lock);
		break;
	case LE_STOP:
	case LE_PHASE2_DONE:
	case LE_PEER_EXIT: {
		struct list_head *phase_head;

		/* Handle other MDTs firstly if needed, then notify the OSTs. */
		if (bk->lb_param & LPF_ALL_TGT) {
			phase_head = &lad->lad_mdt_list;
			ltds = &lfsck->li_mdt_descs;
			if (lr->lr_event == LE_STOP) {
				/* unlink other MDT targets locallly. */
				spin_lock(&ltds->ltd_lock);
				if (com->lc_type == LFSCK_TYPE_LAYOUT) {
					list_for_each_entry_safe(ltd, next,
						phase_head, ltd_layout_list) {
						list_del_init(
						&ltd->ltd_layout_phase_list);
						list_del_init(
						&ltd->ltd_layout_list);
					}
				} else {
					list_for_each_entry_safe(ltd, next,
							phase_head,
							ltd_namespace_list) {
						list_del_init(
						&ltd->ltd_namespace_phase_list);
						list_del_init(
						&ltd->ltd_namespace_list);
					}
				}
				spin_unlock(&ltds->ltd_lock);

				if (com->lc_type != LFSCK_TYPE_LAYOUT)
					break;

				lr->lr_flags |= LEF_TO_OST;
				phase_head = &lad->lad_ost_list;
				ltds = &lfsck->li_ost_descs;
			} else {
				lr->lr_flags &= ~LEF_TO_OST;
			}
		} else if (com->lc_type != LFSCK_TYPE_LAYOUT) {
			break;
		} else {
			lr->lr_flags |= LEF_TO_OST;
			phase_head = &lad->lad_ost_list;
			ltds = &lfsck->li_ost_descs;
		}

again:
		laia->laia_ltds = ltds;
		spin_lock(&ltds->ltd_lock);
		while (!list_empty(phase_head)) {
			if (com->lc_type == LFSCK_TYPE_LAYOUT) {
				ltd = list_entry(phase_head->next,
						 struct lfsck_tgt_desc,
						 ltd_layout_list);
				if (!list_empty(&ltd->ltd_layout_phase_list))
					list_del_init(
						&ltd->ltd_layout_phase_list);
				list_del_init(&ltd->ltd_layout_list);
			} else {
				ltd = list_entry(phase_head->next,
						 struct lfsck_tgt_desc,
						 ltd_namespace_list);
				if (!list_empty(&ltd->ltd_namespace_phase_list))
					list_del_init(
						&ltd->ltd_namespace_phase_list);
				list_del_init(&ltd->ltd_namespace_list);
			}
			atomic_inc(&ltd->ltd_ref);
			laia->laia_ltd = ltd;
			spin_unlock(&ltds->ltd_lock);
			rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					lfsck_async_interpret_common,
					laia, LFSCK_NOTIFY);
			if (rc != 0) {
				CDEBUG(D_LFSCK, "%s: LFSCK assistant fail to "
				       "notify %s %x for %s stop/phase2_done/"
				       "peer_exit: rc = %d\n",
				       lfsck_lfsck2name(lfsck),
				       (lr->lr_flags & LEF_TO_OST) ?
				       "OST" : "MDT", ltd->ltd_index,
				       lad->lad_name, rc);
				lfsck_tgt_put(ltd);
			}
			spin_lock(&ltds->ltd_lock);
		}
		spin_unlock(&ltds->ltd_lock);

		rc = ptlrpc_set_wait(set);
		if (rc < 0) {
			ptlrpc_set_destroy(set);
			RETURN(rc);
		}

		if (com->lc_type == LFSCK_TYPE_LAYOUT &&
		    !(lr->lr_flags & LEF_TO_OST)) {
			lr->lr_flags |= LEF_TO_OST;
			phase_head = &lad->lad_ost_list;
			ltds = &lfsck->li_ost_descs;
			goto again;
		}
		break;
	}
	case LE_PHASE1_DONE:
		lad->lad_ops->la_sync_failures(env, com, lr);
		lad->lad_touch_gen++;
		ltds = &lfsck->li_mdt_descs;
		laia->laia_ltds = ltds;
		spin_lock(&ltds->ltd_lock);
		while (!list_empty(&lad->lad_mdt_list)) {
			struct list_head *list;
			__u32		 *gen;

			if (com->lc_type == LFSCK_TYPE_LAYOUT) {
				ltd = list_entry(lad->lad_mdt_list.next,
						 struct lfsck_tgt_desc,
						 ltd_layout_list);
				list = &ltd->ltd_layout_list;
				gen = &ltd->ltd_layout_gen;
			} else {
				struct lfsck_namespace *ns = com->lc_file_ram;

				ltd = list_entry(lad->lad_mdt_list.next,
						 struct lfsck_tgt_desc,
						 ltd_namespace_list);
				list = &ltd->ltd_namespace_list;
				gen = &ltd->ltd_namespace_gen;
				lr->lr_flags2 = ns->ln_flags & ~LF_INCOMPLETE;
			}

			if (*gen == lad->lad_touch_gen)
				break;

			*gen = lad->lad_touch_gen;
			list_move_tail(list, &lad->lad_mdt_list);
			if (ltd->ltd_synced_failures)
				continue;

			atomic_inc(&ltd->ltd_ref);
			laia->laia_ltd = ltd;
			spin_unlock(&ltds->ltd_lock);
			rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					lfsck_async_interpret_common,
					laia, LFSCK_NOTIFY);
			if (rc != 0) {
				CDEBUG(D_LFSCK, "%s: LFSCK assistant fail to "
				       "notify MDT %x for %s phase1 done: "
				       "rc = %d\n", lfsck_lfsck2name(lfsck),
				       ltd->ltd_index, lad->lad_name, rc);
				lfsck_tgt_put(ltd);
			}
			spin_lock(&ltds->ltd_lock);
		}
		spin_unlock(&ltds->ltd_lock);
		break;
	default:
		CDEBUG(D_LFSCK, "%s: LFSCK assistant unexpected LFSCK event: "
		       "rc = %d\n", lfsck_lfsck2name(lfsck), lr->lr_event);
		rc = -EINVAL;
		break;
	}

	rc1 = ptlrpc_set_wait(set);
	ptlrpc_set_destroy(set);

	RETURN(rc != 0 ? rc : rc1);
}

/**
 * The LFSCK assistant thread is triggered by the LFSCK main engine.
 * They co-work together as an asynchronous pipeline: the LFSCK main
 * engine scans the system and pre-fetches the objects, attributes,
 * or name entries, etc, and pushes them into the pipeline as input
 * requests for the LFSCK assistant thread; on the other end of the
 * pipeline, the LFSCK assistant thread performs the real check and
 * repair for every request from the main engine.
 *
 * Generally, the assistant engine may be blocked when check/repair
 * something, so the LFSCK main engine will run some faster. On the
 * other hand, the LFSCK main engine will drive multiple assistant
 * threads in parallel, means for each LFSCK component on the master
 * (such as layout LFSCK, namespace LFSCK), there is an independent
 * LFSCK assistant thread. So under such 1:N multiple asynchronous
 * pipelines mode, the whole LFSCK performance will be much better
 * than check/repair everything by the LFSCK main engine itself.
 */
int lfsck_assistant_engine(void *args)
{
	struct lfsck_thread_args	  *lta	   = args;
	struct lu_env			  *env	   = &lta->lta_env;
	struct lfsck_component		  *com     = lta->lta_com;
	struct lfsck_instance		  *lfsck   = lta->lta_lfsck;
	struct lfsck_bookmark		  *bk	   = &lfsck->li_bookmark_ram;
	struct lfsck_position		  *pos     = &com->lc_pos_start;
	struct lfsck_thread_info	  *info    = lfsck_env_info(env);
	struct lfsck_request		  *lr      = &info->lti_lr;
	struct lfsck_assistant_data	  *lad     = com->lc_data;
	struct ptlrpc_thread		  *mthread = &lfsck->li_thread;
	struct ptlrpc_thread		  *athread = &lad->lad_thread;
	struct lfsck_assistant_operations *lao     = lad->lad_ops;
	struct lfsck_assistant_req	  *lar;
	struct l_wait_info		   lwi     = { 0 };
	int				   rc      = 0;
	int				   rc1	   = 0;
	int				   rc2;
	ENTRY;

	CDEBUG(D_LFSCK, "%s: %s LFSCK assistant thread start\n",
	       lfsck_lfsck2name(lfsck), lad->lad_name);

	memset(lr, 0, sizeof(*lr));
	lr->lr_event = LE_START;
	if (pos->lp_oit_cookie <= 1)
		lr->lr_param = LPF_RESET;
	rc = lfsck_assistant_notify_others(env, com, lr);
	if (rc != 0) {
		CDEBUG(D_LFSCK, "%s: LFSCK assistant fail to notify others "
		       "to start %s: rc = %d\n",
		       lfsck_lfsck2name(lfsck), lad->lad_name, rc);
		GOTO(fini, rc);
	}

	spin_lock(&lad->lad_lock);
	lad->lad_task = current;
	thread_set_flags(athread, SVC_RUNNING);
	spin_unlock(&lad->lad_lock);
	wake_up_all(&mthread->t_ctl_waitq);

	while (1) {
		while (!list_empty(&lad->lad_req_list)) {
			bool wakeup = false;

			if (unlikely(lad->lad_exit ||
				     !thread_is_running(mthread)))
				GOTO(cleanup1, rc = lad->lad_post_result);

			lar = list_entry(lad->lad_req_list.next,
					 struct lfsck_assistant_req,
					 lar_list);
			/* Only the lfsck_assistant_engine thread itself can
			 * remove the "lar" from the head of the list, LFSCK
			 * engine thread only inserts other new "lar" at the
			 * end of the list. So it is safe to handle current
			 * "lar" without the spin_lock. */
			rc = lao->la_handler_p1(env, com, lar);
			spin_lock(&lad->lad_lock);
			list_del_init(&lar->lar_list);
			lad->lad_prefetched--;
			/* Wake up the main engine thread only when the list
			 * is empty or half of the prefetched items have been
			 * handled to avoid too frequent thread schedule. */
			if (lad->lad_prefetched <= (bk->lb_async_windows / 2))
				wakeup = true;
			spin_unlock(&lad->lad_lock);
			if (wakeup)
				wake_up_all(&mthread->t_ctl_waitq);

			lao->la_req_fini(env, lar);
			if (rc < 0 && bk->lb_param & LPF_FAILOUT)
				GOTO(cleanup1, rc);
		}

		l_wait_event(athread->t_ctl_waitq,
			     !lfsck_assistant_req_empty(lad) ||
			     lad->lad_exit ||
			     lad->lad_to_post ||
			     lad->lad_to_double_scan,
			     &lwi);

		if (unlikely(lad->lad_exit))
			GOTO(cleanup1, rc = lad->lad_post_result);

		if (!list_empty(&lad->lad_req_list))
			continue;

		if (lad->lad_to_post) {
			CDEBUG(D_LFSCK, "%s: %s LFSCK assistant thread post\n",
			       lfsck_lfsck2name(lfsck), lad->lad_name);

			if (unlikely(lad->lad_exit))
				GOTO(cleanup1, rc = lad->lad_post_result);

			lad->lad_to_post = 0;
			LASSERT(lad->lad_post_result > 0);

			/* Wakeup the master engine to go ahead. */
			wake_up_all(&mthread->t_ctl_waitq);

			memset(lr, 0, sizeof(*lr));
			lr->lr_event = LE_PHASE1_DONE;
			lr->lr_status = lad->lad_post_result;
			rc = lfsck_assistant_notify_others(env, com, lr);

			CDEBUG(D_LFSCK, "%s: LFSCK assistant notified "
			       "others for %s post: rc = %d\n",
			       lfsck_lfsck2name(lfsck),
			       lad->lad_name, rc);
		}

		if (lad->lad_to_double_scan) {
			lad->lad_to_double_scan = 0;
			atomic_inc(&lfsck->li_double_scan_count);
			lad->lad_in_double_scan = 1;
			wake_up_all(&mthread->t_ctl_waitq);

			com->lc_new_checked = 0;
			com->lc_new_scanned = 0;
			com->lc_time_last_checkpoint = cfs_time_current();
			com->lc_time_next_checkpoint =
				com->lc_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);

			CDEBUG(D_LFSCK, "%s: LFSCK assistant sync before "
			       "the second-stage scaning\n",
			       lfsck_lfsck2name(lfsck));

			/* Flush async updates before handling orphan. */
			rc2 = dt_sync(env, lfsck->li_next);

			CDEBUG(D_LFSCK, "%s: LFSCK assistant phase2 "
			       "scan start, synced: rc = %d\n",
			       lfsck_lfsck2name(lfsck), rc2);

			if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_DOUBLESCAN))
				GOTO(cleanup2, rc = 0);

			while (lad->lad_in_double_scan) {
				rc = lfsck_assistant_query_others(env, com);
				if (lfsck_phase2_next_ready(lad))
					goto p2_next;

				if (rc < 0)
					GOTO(cleanup2, rc);

				/* Pull LFSCK status on related targets once
				 * per 30 seconds if we are not notified. */
				lwi = LWI_TIMEOUT_INTERVAL(cfs_time_seconds(30),
							   cfs_time_seconds(1),
							   NULL, NULL);
				rc = l_wait_event(athread->t_ctl_waitq,
					lfsck_phase2_next_ready(lad) ||
					lad->lad_exit ||
					!thread_is_running(mthread),
					&lwi);

				if (unlikely(lad->lad_exit ||
					     !thread_is_running(mthread)))
					GOTO(cleanup2, rc = 0);

				if (rc == -ETIMEDOUT)
					continue;

				if (rc < 0)
					GOTO(cleanup2, rc);

p2_next:
				rc = lao->la_handler_p2(env, com);
				if (rc != 0)
					GOTO(cleanup2, rc);

				if (unlikely(lad->lad_exit ||
					     !thread_is_running(mthread)))
					GOTO(cleanup2, rc = 0);
			}
		}
	}

cleanup1:
	/* Cleanup the unfinished requests. */
	spin_lock(&lad->lad_lock);
	if (rc < 0)
		lad->lad_assistant_status = rc;

	if (lad->lad_exit && lad->lad_post_result <= 0)
		lao->la_fill_pos(env, com, &lfsck->li_pos_checkpoint);

	while (!list_empty(&lad->lad_req_list)) {
		lar = list_entry(lad->lad_req_list.next,
				 struct lfsck_assistant_req,
				 lar_list);
		list_del_init(&lar->lar_list);
		lad->lad_prefetched--;
		spin_unlock(&lad->lad_lock);
		lao->la_req_fini(env, lar);
		spin_lock(&lad->lad_lock);
	}
	spin_unlock(&lad->lad_lock);

	LASSERTF(lad->lad_prefetched == 0, "unmatched prefeteched objs %d\n",
		 lad->lad_prefetched);

cleanup2:
	memset(lr, 0, sizeof(*lr));
	if (rc > 0) {
		lr->lr_event = LE_PHASE2_DONE;
		lr->lr_status = rc;
	} else if (rc == 0) {
		if (lfsck->li_flags & LPF_ALL_TGT) {
			lr->lr_event = LE_STOP;
			lr->lr_status = LS_STOPPED;
		} else {
			lr->lr_event = LE_PEER_EXIT;
			switch (lfsck->li_status) {
			case LS_PAUSED:
			case LS_CO_PAUSED:
				lr->lr_status = LS_CO_PAUSED;
				break;
			case LS_STOPPED:
			case LS_CO_STOPPED:
				lr->lr_status = LS_CO_STOPPED;
				break;
			default:
				CDEBUG(D_LFSCK, "%s: LFSCK assistant unknown "
				       "status: rc = %d\n",
				       lfsck_lfsck2name(lfsck),
				       lfsck->li_status);
				lr->lr_status = LS_CO_FAILED;
				break;
			}
		}
	} else {
		if (lfsck->li_flags & LPF_ALL_TGT) {
			lr->lr_event = LE_STOP;
			lr->lr_status = LS_FAILED;
		} else {
			lr->lr_event = LE_PEER_EXIT;
			lr->lr_status = LS_CO_FAILED;
		}
	}

	rc1 = lfsck_assistant_notify_others(env, com, lr);
	if (rc1 != 0) {
		CDEBUG(D_LFSCK, "%s: LFSCK assistant failed to notify "
		       "others for %s quit: rc = %d\n",
		       lfsck_lfsck2name(lfsck), lad->lad_name, rc1);
		rc = rc1;
	}

	CDEBUG(D_LFSCK, "%s: LFSCK assistant sync before exit\n",
	       lfsck_lfsck2name(lfsck));

	/* Flush async updates before exit. */
	rc2 = dt_sync(env, lfsck->li_next);

	CDEBUG(D_LFSCK, "%s: LFSCK assistant synced before exit: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc2);

	/* Under force exit case, some requests may be just freed without
	 * verification, those objects should be re-handled when next run.
	 * So not update the on-disk trace file under such case. */
	if (lad->lad_in_double_scan) {
		if (!lad->lad_exit)
			rc1 = lao->la_double_scan_result(env, com, rc);

		CDEBUG(D_LFSCK, "%s: LFSCK assistant phase2 scan "
		       "finished: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc1 != 0 ? rc1 : rc);
	}

fini:
	if (lad->lad_in_double_scan)
		atomic_dec(&lfsck->li_double_scan_count);

	spin_lock(&lad->lad_lock);
	lad->lad_assistant_status = (rc1 != 0 ? rc1 : rc);
	thread_set_flags(athread, SVC_STOPPED);
	wake_up_all(&mthread->t_ctl_waitq);
	lad->lad_task = NULL;
	spin_unlock(&lad->lad_lock);

	CDEBUG(D_LFSCK, "%s: %s LFSCK assistant thread exit: rc = %d\n",
	       lfsck_lfsck2name(lfsck), lad->lad_name,
	       lad->lad_assistant_status);

	lfsck_thread_args_fini(lta);

	return rc;
}
