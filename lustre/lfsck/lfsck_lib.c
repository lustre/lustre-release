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
 * Copyright (c) 2013, 2014, Intel Corporation.
 */
/*
 * lustre/lfsck/lfsck_lib.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LFSCK

#include <libcfs/list.h>
#include <lu_object.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_fld.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_lfsck.h>
#include <lustre/lustre_lfsck_user.h>

#include "lfsck_internal.h"

#define LFSCK_CHECKPOINT_SKIP	1

/* define lfsck thread key */
LU_KEY_INIT(lfsck, struct lfsck_thread_info);

static void lfsck_key_fini(const struct lu_context *ctx,
			   struct lu_context_key *key, void *data)
{
	struct lfsck_thread_info *info = data;

	lu_buf_free(&info->lti_linkea_buf);
	lu_buf_free(&info->lti_linkea_buf2);
	lu_buf_free(&info->lti_big_buf);
	OBD_FREE_PTR(info);
}

LU_CONTEXT_KEY_DEFINE(lfsck, LCT_MD_THREAD | LCT_DT_THREAD);
LU_KEY_INIT_GENERIC(lfsck);

static struct list_head lfsck_instance_list;
static struct list_head lfsck_ost_orphan_list;
static struct list_head lfsck_mdt_orphan_list;
static DEFINE_SPINLOCK(lfsck_instance_lock);

static const char *lfsck_status_names[] = {
	[LS_INIT]		= "init",
	[LS_SCANNING_PHASE1]	= "scanning-phase1",
	[LS_SCANNING_PHASE2]	= "scanning-phase2",
	[LS_COMPLETED]		= "completed",
	[LS_FAILED]		= "failed",
	[LS_STOPPED]		= "stopped",
	[LS_PAUSED]		= "paused",
	[LS_CRASHED]		= "crashed",
	[LS_PARTIAL]		= "partial",
	[LS_CO_FAILED]		= "co-failed",
	[LS_CO_STOPPED] 	= "co-stopped",
	[LS_CO_PAUSED]		= "co-paused"
};

const char *lfsck_flags_names[] = {
	"scanned-once",
	"inconsistent",
	"upgrade",
	"incomplete",
	"crashed_lastid",
	NULL
};

const char *lfsck_param_names[] = {
	NULL,
	"failout",
	"dryrun",
	"all_targets",
	"broadcast",
	"orphan",
	"create_ostobj",
	"create_mdtobj",
	NULL
};

enum lfsck_verify_lpf_types {
	LVLT_BY_BOOKMARK	= 0,
	LVLT_BY_NAMEENTRY	= 1,
};

const char *lfsck_status2names(enum lfsck_status status)
{
	if (unlikely(status < 0 || status >= LS_MAX))
		return "unknown";

	return lfsck_status_names[status];
}

static int lfsck_tgt_descs_init(struct lfsck_tgt_descs *ltds)
{
	spin_lock_init(&ltds->ltd_lock);
	init_rwsem(&ltds->ltd_rw_sem);
	INIT_LIST_HEAD(&ltds->ltd_orphan);
	ltds->ltd_tgts_bitmap = CFS_ALLOCATE_BITMAP(BITS_PER_LONG);
	if (ltds->ltd_tgts_bitmap == NULL)
		return -ENOMEM;

	return 0;
}

static void lfsck_tgt_descs_fini(struct lfsck_tgt_descs *ltds)
{
	struct lfsck_tgt_desc	*ltd;
	struct lfsck_tgt_desc	*next;
	int			 idx;

	down_write(&ltds->ltd_rw_sem);

	list_for_each_entry_safe(ltd, next, &ltds->ltd_orphan,
				 ltd_orphan_list) {
		list_del_init(&ltd->ltd_orphan_list);
		lfsck_tgt_put(ltd);
	}

	if (unlikely(ltds->ltd_tgts_bitmap == NULL)) {
		up_write(&ltds->ltd_rw_sem);

		return;
	}

	cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
		ltd = LTD_TGT(ltds, idx);
		if (likely(ltd != NULL)) {
			LASSERT(list_empty(&ltd->ltd_layout_list));
			LASSERT(list_empty(&ltd->ltd_layout_phase_list));
			LASSERT(list_empty(&ltd->ltd_namespace_list));
			LASSERT(list_empty(&ltd->ltd_namespace_phase_list));

			ltds->ltd_tgtnr--;
			cfs_bitmap_clear(ltds->ltd_tgts_bitmap, idx);
			LTD_TGT(ltds, idx) = NULL;
			lfsck_tgt_put(ltd);
		}
	}

	LASSERTF(ltds->ltd_tgtnr == 0, "tgt count unmatched: %d\n",
		 ltds->ltd_tgtnr);

	for (idx = 0; idx < TGT_PTRS; idx++) {
		if (ltds->ltd_tgts_idx[idx] != NULL) {
			OBD_FREE_PTR(ltds->ltd_tgts_idx[idx]);
			ltds->ltd_tgts_idx[idx] = NULL;
		}
	}

	CFS_FREE_BITMAP(ltds->ltd_tgts_bitmap);
	ltds->ltd_tgts_bitmap = NULL;
	up_write(&ltds->ltd_rw_sem);
}

static int __lfsck_add_target(const struct lu_env *env,
			      struct lfsck_instance *lfsck,
			      struct lfsck_tgt_desc *ltd,
			      bool for_ost, bool locked)
{
	struct lfsck_tgt_descs *ltds;
	__u32			index = ltd->ltd_index;
	int			rc    = 0;
	ENTRY;

	if (for_ost)
		ltds = &lfsck->li_ost_descs;
	else
		ltds = &lfsck->li_mdt_descs;

	if (!locked)
		down_write(&ltds->ltd_rw_sem);

	LASSERT(ltds->ltd_tgts_bitmap != NULL);

	if (index >= ltds->ltd_tgts_bitmap->size) {
		__u32 newsize = max((__u32)ltds->ltd_tgts_bitmap->size,
				    (__u32)BITS_PER_LONG);
		cfs_bitmap_t *old_bitmap = ltds->ltd_tgts_bitmap;
		cfs_bitmap_t *new_bitmap;

		while (newsize < index + 1)
			newsize <<= 1;

		new_bitmap = CFS_ALLOCATE_BITMAP(newsize);
		if (new_bitmap == NULL)
			GOTO(unlock, rc = -ENOMEM);

		if (ltds->ltd_tgtnr > 0)
			cfs_bitmap_copy(new_bitmap, old_bitmap);
		ltds->ltd_tgts_bitmap = new_bitmap;
		CFS_FREE_BITMAP(old_bitmap);
	}

	if (cfs_bitmap_check(ltds->ltd_tgts_bitmap, index)) {
		CERROR("%s: the device %s (%u) is registered already\n",
		       lfsck_lfsck2name(lfsck),
		       ltd->ltd_tgt->dd_lu_dev.ld_obd->obd_name, index);
		GOTO(unlock, rc = -EEXIST);
	}

	if (ltds->ltd_tgts_idx[index / TGT_PTRS_PER_BLOCK] == NULL) {
		OBD_ALLOC_PTR(ltds->ltd_tgts_idx[index / TGT_PTRS_PER_BLOCK]);
		if (ltds->ltd_tgts_idx[index / TGT_PTRS_PER_BLOCK] == NULL)
			GOTO(unlock, rc = -ENOMEM);
	}

	LTD_TGT(ltds, index) = ltd;
	cfs_bitmap_set(ltds->ltd_tgts_bitmap, index);
	ltds->ltd_tgtnr++;

	GOTO(unlock, rc = 0);

unlock:
	if (!locked)
		up_write(&ltds->ltd_rw_sem);

	return rc;
}

static int lfsck_add_target_from_orphan(const struct lu_env *env,
					struct lfsck_instance *lfsck)
{
	struct lfsck_tgt_descs	*ltds    = &lfsck->li_ost_descs;
	struct lfsck_tgt_desc	*ltd;
	struct lfsck_tgt_desc	*next;
	struct list_head	*head    = &lfsck_ost_orphan_list;
	int			 rc;
	bool			 for_ost = true;

again:
	spin_lock(&lfsck_instance_lock);
	list_for_each_entry_safe(ltd, next, head, ltd_orphan_list) {
		if (ltd->ltd_key == lfsck->li_bottom)
			list_move_tail(&ltd->ltd_orphan_list,
				       &ltds->ltd_orphan);
	}
	spin_unlock(&lfsck_instance_lock);

	down_write(&ltds->ltd_rw_sem);
	while (!list_empty(&ltds->ltd_orphan)) {
		ltd = list_entry(ltds->ltd_orphan.next,
				 struct lfsck_tgt_desc,
				 ltd_orphan_list);
		list_del_init(&ltd->ltd_orphan_list);
		rc = __lfsck_add_target(env, lfsck, ltd, for_ost, true);
		/* Do not hold the semaphore for too long time. */
		up_write(&ltds->ltd_rw_sem);
		if (rc != 0)
			return rc;

		down_write(&ltds->ltd_rw_sem);
	}
	up_write(&ltds->ltd_rw_sem);

	if (for_ost) {
		ltds = &lfsck->li_mdt_descs;
		head = &lfsck_mdt_orphan_list;
		for_ost = false;
		goto again;
	}

	return 0;
}

static inline struct lfsck_component *
__lfsck_component_find(struct lfsck_instance *lfsck, __u16 type,
		       struct list_head *list)
{
	struct lfsck_component *com;

	list_for_each_entry(com, list, lc_link) {
		if (com->lc_type == type)
			return com;
	}
	return NULL;
}

struct lfsck_component *
lfsck_component_find(struct lfsck_instance *lfsck, __u16 type)
{
	struct lfsck_component *com;

	spin_lock(&lfsck->li_lock);
	com = __lfsck_component_find(lfsck, type, &lfsck->li_list_scan);
	if (com != NULL)
		goto unlock;

	com = __lfsck_component_find(lfsck, type,
				     &lfsck->li_list_double_scan);
	if (com != NULL)
		goto unlock;

	com = __lfsck_component_find(lfsck, type, &lfsck->li_list_idle);

unlock:
	if (com != NULL)
		lfsck_component_get(com);
	spin_unlock(&lfsck->li_lock);
	return com;
}

void lfsck_component_cleanup(const struct lu_env *env,
			     struct lfsck_component *com)
{
	if (!list_empty(&com->lc_link))
		list_del_init(&com->lc_link);
	if (!list_empty(&com->lc_link_dir))
		list_del_init(&com->lc_link_dir);

	lfsck_component_put(env, com);
}

int lfsck_fid_alloc(const struct lu_env *env, struct lfsck_instance *lfsck,
		    struct lu_fid *fid, bool locked)
{
	struct lfsck_bookmark	*bk = &lfsck->li_bookmark_ram;
	int			 rc = 0;
	ENTRY;

	if (!locked)
		mutex_lock(&lfsck->li_mutex);

	rc = seq_client_alloc_fid(env, lfsck->li_seq, fid);
	if (rc >= 0) {
		bk->lb_last_fid = *fid;
		/* We do not care about whether the subsequent sub-operations
		 * failed or not. The worst case is that one FID is lost that
		 * is not a big issue for the LFSCK since it is relative rare
		 * for LFSCK create. */
		rc = lfsck_bookmark_store(env, lfsck);
	}

	if (!locked)
		mutex_unlock(&lfsck->li_mutex);

	RETURN(rc);
}

/**
 * Request the specified ibits lock for the given object.
 *
 * Before the LFSCK modifying on the namespace visible object,
 * it needs to acquire related ibits ldlm lock.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 * \param[in] obj	pointer to the dt_object to be locked
 * \param[out] lh	pointer to the lock handle
 * \param[in] ibits	the bits for the ldlm lock to be acquired
 * \param[in] mode	the mode for the ldlm lock to be acquired
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int lfsck_ibits_lock(const struct lu_env *env, struct lfsck_instance *lfsck,
		     struct dt_object *obj, struct lustre_handle *lh,
		     __u64 bits, ldlm_mode_t mode)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	ldlm_policy_data_t		*policy = &info->lti_policy;
	struct ldlm_res_id		*resid	= &info->lti_resid;
	__u64				 flags	= LDLM_FL_ATOMIC_CB;
	int				 rc;

	LASSERT(lfsck->li_namespace != NULL);

	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = bits;
	fid_build_reg_res_name(lfsck_dto2fid(obj), resid);
	if (dt_object_remote(obj)) {
		struct ldlm_enqueue_info *einfo = &info->lti_einfo;

		memset(einfo, 0, sizeof(*einfo));
		einfo->ei_type = LDLM_IBITS;
		einfo->ei_mode = mode;
		einfo->ei_cb_bl = ldlm_blocking_ast;
		einfo->ei_cb_cp = ldlm_completion_ast;
		einfo->ei_res_id = resid;

		rc = dt_object_lock(env, obj, lh, einfo, policy);
	} else {
		rc = ldlm_cli_enqueue_local(lfsck->li_namespace, resid,
					    LDLM_IBITS, policy, mode,
					    &flags, ldlm_blocking_ast,
					    ldlm_completion_ast, NULL, NULL,
					    0, LVB_T_NONE, NULL, lh);
	}

	if (rc == ELDLM_OK) {
		rc = 0;
	} else {
		memset(lh, 0, sizeof(*lh));
		rc = -EIO;
	}

	return rc;
}

/**
 * Release the the specified ibits lock.
 *
 * If the lock has been acquired before, release it
 * and cleanup the handle. Otherwise, do nothing.
 *
 * \param[in] lh	pointer to the lock handle
 * \param[in] mode	the mode for the ldlm lock to be released
 */
void lfsck_ibits_unlock(struct lustre_handle *lh, ldlm_mode_t mode)
{
	if (lustre_handle_is_used(lh)) {
		ldlm_lock_decref(lh, mode);
		memset(lh, 0, sizeof(*lh));
	}
}

int lfsck_find_mdt_idx_by_fid(const struct lu_env *env,
			      struct lfsck_instance *lfsck,
			      const struct lu_fid *fid)
{
	struct seq_server_site	*ss	=
			lu_site2seq(lfsck->li_bottom->dd_lu_dev.ld_site);
	struct lu_seq_range	*range	= &lfsck_env_info(env)->lti_range;
	int			 rc;

	fld_range_set_mdt(range);
	rc = fld_server_lookup(env, ss->ss_server_fld, fid_seq(fid), range);
	if (rc == 0)
		rc = range->lsr_index;

	return rc;
}

const char dot[] = ".";
const char dotdot[] = "..";
static const char dotlustre[] = ".lustre";
static const char lostfound[] = "lost+found";

/**
 * Remove the name entry from the .lustre/lost+found directory.
 *
 * No need to care about the object referenced by the name entry,
 * either the name entry is invalid or redundant, or the referenced
 * object has been processed or will be handled by others.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 * \param[in] name	the name for the name entry to be removed
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_lpf_remove_name_entry(const struct lu_env *env,
				       struct lfsck_instance *lfsck,
				       const char *name)
{
	struct dt_object	*parent = lfsck->li_lpf_root_obj;
	struct dt_device	*dev	= lfsck->li_next;
	struct thandle		*th;
	struct lustre_handle	 lh	= { 0 };
	int			 rc;
	ENTRY;

	rc = lfsck_ibits_lock(env, lfsck, parent, &lh,
			      MDS_INODELOCK_UPDATE, LCK_EX);
	if (rc != 0)
		RETURN(rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, parent, (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_ref_del(env, parent, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_delete(env, parent, (const struct dt_key *)name, th,
		       BYPASS_CAPA);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, parent, 0);
	rc = dt_ref_del(env, parent, th);
	dt_write_unlock(env, parent);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);

unlock:
	lfsck_ibits_unlock(&lh, LCK_EX);

	CDEBUG(D_LFSCK, "%s: remove name entry "DFID"/%s: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(lfsck_dto2fid(parent)), name, rc);

	return rc;
}

static int lfsck_create_lpf_local(const struct lu_env *env,
				  struct lfsck_instance *lfsck,
				  struct dt_object *child,
				  struct lu_attr *la,
				  struct dt_object_format *dof,
				  const char *name)
{
	struct dt_insert_rec	*rec	= &lfsck_env_info(env)->lti_dt_rec;
	struct dt_object	*parent	= lfsck->li_lpf_root_obj;
	struct dt_device	*dev	= lfsck->li_bottom;
	struct lfsck_bookmark	*bk	= &lfsck->li_bookmark_ram;
	struct dt_object	*bk_obj = lfsck->li_bookmark_obj;
	const struct lu_fid	*cfid	= lfsck_dto2fid(child);
	struct thandle		*th	= NULL;
	struct linkea_data	 ldata	= { NULL };
	struct lu_buf		 linkea_buf;
	const struct lu_name	*cname;
	loff_t			 pos	= 0;
	int			 len	= sizeof(struct lfsck_bookmark);
	int			 rc;
	ENTRY;

	rc = linkea_data_new(&ldata,
			     &lfsck_env_info(env)->lti_linkea_buf2);
	if (rc != 0)
		RETURN(rc);

	cname = lfsck_name_get_const(env, name, strlen(name));
	rc = linkea_add_buf(&ldata, cname, lfsck_dto2fid(parent));
	if (rc != 0)
		RETURN(rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	/* 1a. create child */
	rc = dt_declare_create(env, child, la, NULL, dof, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 2a. increase child nlink */
	rc = dt_declare_ref_add(env, child, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 3a. insert linkEA for child */
	lfsck_buf_init(&linkea_buf, ldata.ld_buf->lb_buf,
		       ldata.ld_leh->leh_len);
	rc = dt_declare_xattr_set(env, child, &linkea_buf,
				  XATTR_NAME_LINK, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 4a. insert name into parent dir */
	rec->rec_type = S_IFDIR;
	rec->rec_fid = cfid;
	rc = dt_declare_insert(env, parent, (const struct dt_rec *)rec,
			       (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 5a. increase parent nlink */
	rc = dt_declare_ref_add(env, parent, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 6a. update bookmark */
	rc = dt_declare_record_write(env, bk_obj,
				     lfsck_buf_get(env, bk, len), 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, child, 0);
	/* 1b.1. create child */
	rc = dt_create(env, child, la, NULL, dof, th);
	if (rc != 0)
		GOTO(unlock, rc);

	if (unlikely(!dt_try_as_dir(env, child)))
		GOTO(unlock, rc = -ENOTDIR);

	/* 1b.2. insert dot into child dir */
	rec->rec_fid = cfid;
	rc = dt_insert(env, child, (const struct dt_rec *)rec,
		       (const struct dt_key *)dot, th, BYPASS_CAPA, 1);
	if (rc != 0)
		GOTO(unlock, rc);

	/* 1b.3. insert dotdot into child dir */
	rec->rec_fid = &LU_LPF_FID;
	rc = dt_insert(env, child, (const struct dt_rec *)rec,
		       (const struct dt_key *)dotdot, th, BYPASS_CAPA, 1);
	if (rc != 0)
		GOTO(unlock, rc);

	/* 2b. increase child nlink */
	rc = dt_ref_add(env, child, th);
	if (rc != 0)
		GOTO(unlock, rc);

	/* 3b. insert linkEA for child. */
	rc = dt_xattr_set(env, child, &linkea_buf,
			  XATTR_NAME_LINK, 0, th, BYPASS_CAPA);
	dt_write_unlock(env, child);
	if (rc != 0)
		GOTO(stop, rc);

	/* 4b. insert name into parent dir */
	rec->rec_fid = cfid;
	rc = dt_insert(env, parent, (const struct dt_rec *)rec,
		       (const struct dt_key *)name, th, BYPASS_CAPA, 1);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, parent, 0);
	/* 5b. increase parent nlink */
	rc = dt_ref_add(env, parent, th);
	dt_write_unlock(env, parent);
	if (rc != 0)
		GOTO(stop, rc);

	bk->lb_lpf_fid = *cfid;
	lfsck_bookmark_cpu_to_le(&lfsck->li_bookmark_disk, bk);

	/* 6b. update bookmark */
	rc = dt_record_write(env, bk_obj,
			     lfsck_buf_get(env, bk, len), &pos, th);

	GOTO(stop, rc);

unlock:
	dt_write_unlock(env, child);

stop:
	dt_trans_stop(env, dev, th);

	return rc;
}

static int lfsck_create_lpf_remote(const struct lu_env *env,
				   struct lfsck_instance *lfsck,
				   struct dt_object *child,
				   struct lu_attr *la,
				   struct dt_object_format *dof,
				   const char *name)
{
	struct dt_insert_rec	*rec	= &lfsck_env_info(env)->lti_dt_rec;
	struct dt_object	*parent	= lfsck->li_lpf_root_obj;
	struct lfsck_bookmark	*bk	= &lfsck->li_bookmark_ram;
	struct dt_object	*bk_obj = lfsck->li_bookmark_obj;
	const struct lu_fid	*cfid	= lfsck_dto2fid(child);
	struct thandle		*th	= NULL;
	struct linkea_data	 ldata	= { NULL };
	struct lu_buf		 linkea_buf;
	const struct lu_name	*cname;
	struct dt_device	*dev;
	loff_t			 pos	= 0;
	int			 len	= sizeof(struct lfsck_bookmark);
	int			 rc;
	ENTRY;

	rc = linkea_data_new(&ldata,
			     &lfsck_env_info(env)->lti_linkea_buf2);
	if (rc != 0)
		RETURN(rc);

	cname = lfsck_name_get_const(env, name, strlen(name));
	rc = linkea_add_buf(&ldata, cname, lfsck_dto2fid(parent));
	if (rc != 0)
		RETURN(rc);

	/* Create .lustre/lost+found/MDTxxxx. */

	/* XXX: Currently, cross-MDT create operation needs to create the child
	 *	object firstly, then insert name into the parent directory. For
	 *	this case, the child object resides on current MDT (local), but
	 *	the parent ".lustre/lost+found" may be on remote MDT. It is not
	 *	easy to contain all the sub-modifications orderly within single
	 *	transaction.
	 *
	 *	To avoid more inconsistency, we split the create operation into
	 *	two transactions:
	 *
	 *	1) create the child and update the lfsck_bookmark::lb_lpf_fid
	 *	   locally.
	 *	2) insert the name "MDTXXXX" in the parent ".lustre/lost+found"
	 *	   remotely.
	 *
	 *	If 1) done, but 2) failed, then go ahead, the LFSCK will try to
	 *	repair such inconsistency when LFSCK run next time. */

	/* Transaction I: locally */

	dev = lfsck->li_bottom;
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	/* 1a. create child */
	rc = dt_declare_create(env, child, la, NULL, dof, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 2a. increase child nlink */
	rc = dt_declare_ref_add(env, child, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 3a. insert linkEA for child */
	lfsck_buf_init(&linkea_buf, ldata.ld_buf->lb_buf,
		       ldata.ld_leh->leh_len);
	rc = dt_declare_xattr_set(env, child, &linkea_buf,
				  XATTR_NAME_LINK, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 4a. update bookmark */
	rc = dt_declare_record_write(env, bk_obj,
				     lfsck_buf_get(env, bk, len), 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, child, 0);
	/* 1b.1. create child */
	rc = dt_create(env, child, la, NULL, dof, th);
	if (rc != 0)
		GOTO(unlock, rc);

	if (unlikely(!dt_try_as_dir(env, child)))
		GOTO(unlock, rc = -ENOTDIR);

	/* 1b.2. insert dot into child dir */
	rec->rec_type = S_IFDIR;
	rec->rec_fid = cfid;
	rc = dt_insert(env, child, (const struct dt_rec *)rec,
		       (const struct dt_key *)dot, th, BYPASS_CAPA, 1);
	if (rc != 0)
		GOTO(unlock, rc);

	/* 1b.3. insert dotdot into child dir */
	rec->rec_fid = &LU_LPF_FID;
	rc = dt_insert(env, child, (const struct dt_rec *)rec,
		       (const struct dt_key *)dotdot, th, BYPASS_CAPA, 1);
	if (rc != 0)
		GOTO(unlock, rc);

	/* 2b. increase child nlink */
	rc = dt_ref_add(env, child, th);
	if (rc != 0)
		GOTO(unlock, rc);

	/* 3b. insert linkEA for child */
	rc = dt_xattr_set(env, child, &linkea_buf,
			  XATTR_NAME_LINK, 0, th, BYPASS_CAPA);
	if (rc != 0)
		GOTO(unlock, rc);

	bk->lb_lpf_fid = *cfid;
	lfsck_bookmark_cpu_to_le(&lfsck->li_bookmark_disk, bk);

	/* 4b. update bookmark */
	rc = dt_record_write(env, bk_obj,
			     lfsck_buf_get(env, bk, len), &pos, th);

	dt_write_unlock(env, child);
	dt_trans_stop(env, dev, th);
	if (rc != 0)
		RETURN(rc);

	/* Transaction II: remotely */

	dev = lfsck->li_next;
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	/* 5a. insert name into parent dir */
	rec->rec_fid = cfid;
	rc = dt_declare_insert(env, parent, (const struct dt_rec *)rec,
			       (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 6a. increase parent nlink */
	rc = dt_declare_ref_add(env, parent, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 5b. insert name into parent dir */
	rc = dt_insert(env, parent, (const struct dt_rec *)rec,
		       (const struct dt_key *)name, th, BYPASS_CAPA, 1);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, parent, 0);
	/* 6b. increase parent nlink */
	rc = dt_ref_add(env, parent, th);
	dt_write_unlock(env, parent);

	GOTO(stop, rc);

unlock:
	dt_write_unlock(env, child);
stop:
	dt_trans_stop(env, dev, th);

	if (rc != 0 && dev == lfsck->li_next)
		CDEBUG(D_LFSCK, "%s: partially created the object "DFID
		       "for orphans, but failed to insert the name %s "
		       "to the .lustre/lost+found/. Such inconsistency "
		       "will be repaired when LFSCK run next time: rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(cfid), name, rc);

	return rc;
}

/**
 * Create the MDTxxxx directory under /ROOT/.lustre/lost+found/
 *
 * The /ROOT/.lustre/lost+found/MDTxxxx/ directory is used for holding
 * orphans and other uncertain inconsistent objects found during the
 * LFSCK. Such directory will be created by the LFSCK engine on the
 * local MDT before the LFSCK scanning.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_create_lpf(const struct lu_env *env,
			    struct lfsck_instance *lfsck)
{
	struct lfsck_bookmark	 *bk	= &lfsck->li_bookmark_ram;
	struct lfsck_thread_info *info	= lfsck_env_info(env);
	struct lu_fid		 *cfid	= &info->lti_fid2;
	struct lu_attr		 *la	= &info->lti_la;
	struct dt_object_format  *dof	= &info->lti_dof;
	struct dt_object	 *parent = lfsck->li_lpf_root_obj;
	struct dt_object	 *child	= NULL;
	struct lustre_handle	  lh	= { 0 };
	char			  name[8];
	int			  node	= lfsck_dev_idx(lfsck->li_bottom);
	int			  rc	= 0;
	ENTRY;

	LASSERT(lfsck->li_master);
	LASSERT(parent != NULL);
	LASSERT(lfsck->li_lpf_obj == NULL);

	rc = lfsck_ibits_lock(env, lfsck, parent, &lh,
			      MDS_INODELOCK_UPDATE, LCK_EX);
	if (rc != 0)
		RETURN(rc);

	snprintf(name, 8, "MDT%04x", node);
	if (fid_is_zero(&bk->lb_lpf_fid)) {
		/* There is corner case that: in former LFSCK scanning we have
		 * created the .lustre/lost+found/MDTxxxx but failed to update
		 * the lfsck_bookmark::lb_lpf_fid successfully. So need lookup
		 * it from MDT0 firstly. */
		rc = dt_lookup(env, parent, (struct dt_rec *)cfid,
			       (const struct dt_key *)name, BYPASS_CAPA);
		if (rc != 0 && rc != -ENOENT)
			GOTO(unlock, rc);

		if (rc == 0) {
			bk->lb_lpf_fid = *cfid;
			rc = lfsck_bookmark_store(env, lfsck);
		} else {
			rc = lfsck_fid_alloc(env, lfsck, cfid, true);
		}
		if (rc != 0)
			GOTO(unlock, rc);
	} else {
		*cfid = bk->lb_lpf_fid;
	}

	child = lfsck_object_find_by_dev(env, lfsck->li_bottom, cfid);
	if (IS_ERR(child))
		GOTO(unlock, rc = PTR_ERR(child));

	if (dt_object_exists(child) != 0) {
		if (unlikely(!dt_try_as_dir(env, child)))
			rc = -ENOTDIR;
		else
			lfsck->li_lpf_obj = child;

		GOTO(unlock, rc);
	}

	memset(la, 0, sizeof(*la));
	la->la_atime = la->la_mtime = la->la_ctime = cfs_time_current_sec();
	la->la_mode = S_IFDIR | S_IRWXU;
	la->la_valid = LA_ATIME | LA_MTIME | LA_CTIME | LA_MODE |
		       LA_UID | LA_GID;
	memset(dof, 0, sizeof(*dof));
	dof->dof_type = dt_mode_to_dft(S_IFDIR);

	if (node == 0)
		rc = lfsck_create_lpf_local(env, lfsck, child, la, dof, name);
	else
		rc = lfsck_create_lpf_remote(env, lfsck, child, la, dof, name);
	if (rc == 0)
		lfsck->li_lpf_obj = child;

	GOTO(unlock, rc);

unlock:
	lfsck_ibits_unlock(&lh, LCK_EX);
	if (rc != 0 && child != NULL && !IS_ERR(child))
		lu_object_put(env, &child->do_lu);

	return rc;
}

/**
 * Scan .lustre/lost+found for bad name entries and remove them.
 *
 * The valid name entry should be "MDTxxxx", the "xxxx" is the MDT device
 * index in the system. Any other formatted name is invalid and should be
 * removed.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_scan_lpf_bad_entries(const struct lu_env *env,
				      struct lfsck_instance *lfsck)
{
	struct dt_object	*parent = lfsck->li_lpf_root_obj;
	struct lu_dirent	*ent	=
			(struct lu_dirent *)lfsck_env_info(env)->lti_key;
	const struct dt_it_ops	*iops	= &parent->do_index_ops->dio_it;
	struct dt_it		*it;
	int			 rc;
	ENTRY;

	it = iops->init(env, parent, LUDA_64BITHASH, BYPASS_CAPA);
	if (IS_ERR(it))
		RETURN(PTR_ERR(it));

	rc = iops->load(env, it, 0);
	if (rc == 0)
		rc = iops->next(env, it);
	else if (rc > 0)
		rc = 0;

	while (rc == 0) {
		int off = 3;

		rc = iops->rec(env, it, (struct dt_rec *)ent, LUDA_64BITHASH);
		if (rc != 0)
			break;

		ent->lde_namelen = le16_to_cpu(ent->lde_namelen);
		if (name_is_dot_or_dotdot(ent->lde_name, ent->lde_namelen))
			goto next;

		/* name length must be strlen("MDTxxxx") */
		if (ent->lde_namelen != 7)
			goto remove;

		if (memcmp(ent->lde_name, "MDT", off) != 0)
			goto remove;

		while (off < 7 && isxdigit(ent->lde_name[off]))
			off++;

		if (off != 7) {

remove:
			rc = lfsck_lpf_remove_name_entry(env, lfsck,
							 ent->lde_name);
			if (rc != 0)
				break;
		}

next:
		rc = iops->next(env, it);
	}

	iops->put(env, it);
	iops->fini(env, it);

	RETURN(rc > 0 ? 0 : rc);
}

static int lfsck_update_lpf_entry(const struct lu_env *env,
				  struct lfsck_instance *lfsck,
				  struct dt_object *parent,
				  struct dt_object *child,
				  const char *name,
				  enum lfsck_verify_lpf_types type)
{
	int rc;

	if (type == LVLT_BY_BOOKMARK) {
		rc = lfsck_update_name_entry(env, lfsck, parent, name,
					     lfsck_dto2fid(child), S_IFDIR);
	} else /* if (type == LVLT_BY_NAMEENTRY) */ {
		lfsck->li_bookmark_ram.lb_lpf_fid = *lfsck_dto2fid(child);
		rc = lfsck_bookmark_store(env, lfsck);

		CDEBUG(D_LFSCK, "%s: update LPF fid "DFID
		       " in the bookmark file: rc = %d\n",
		       lfsck_lfsck2name(lfsck),
		       PFID(lfsck_dto2fid(child)), rc);
	}

	return rc;
}

/**
 * Check whether the @child back references the @parent.
 *
 * Two cases:
 * 1) The child's FID is stored in the bookmark file. If the child back
 *    references the parent (LU_LPF_FID object) via its ".." entry, then
 *    insert the name (MDTxxxx) to the .lustre/lost+found; otherwise, if
 *    the child back references another parent2, then:
 * 1.1) If the parent2 recognizes the child, then update the bookmark file;
 * 1.2) Otherwise, the LFSCK cannot know whether there will be parent3 that
 *	references the child. So keep them there. As the LFSCK processing,
 *	the parent3 may be found, then when the LFSCK run next time, the
 *	inconsistency can be repaired.
 *
 * 2) The child's FID is stored in the .lustre/lost+found/ sub-directory name
 *    entry (MDTxxxx). If the child back references the parent (LU_LPF_FID obj)
 *    via its ".." entry, then update the bookmark file, otherwise, if the child
 *    back references another parent2, then:
 * 2.1) If the parent2 recognizes the child, then remove the sub-directory
 *	from .lustre/lost+found/;
 * 2.2) Otherwise, if the parent2 does not recognizes the child, trust the
 *	sub-directory name entry and update the child;
 * 2.3) Otherwise, if we do not know whether the parent2 recognizes the child
 *	or not, then keep them there.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 * \param[in] child	pointer to the lost+found sub-directory object
 * \param[in] name	the name for lost+found sub-directory object
 * \param[out] fid	pointer to the buffer to hold the FID of the object
 *			(called it as parent2) that is referenced via the
 *			child's dotdot entry; it also can be the FID that
 *			is referenced by the name entry under the parent2.
 * \param[in] type	to indicate where the child's FID is stored in
 *
 * \retval		positive number for uncertain inconsistency
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_verify_lpf_pairs(const struct lu_env *env,
				  struct lfsck_instance *lfsck,
				  struct dt_object *child, const char *name,
				  struct lu_fid *fid,
				  enum lfsck_verify_lpf_types type)
{
	struct dt_object	 *parent  = lfsck->li_lpf_root_obj;
	struct lfsck_thread_info *info    = lfsck_env_info(env);
	char			 *name2   = info->lti_key;
	struct lu_fid		 *fid2    = &info->lti_fid3;
	struct dt_object	 *parent2 = NULL;
	struct lustre_handle	  lh      = { 0 };
	int			  rc;
	ENTRY;

	fid_zero(fid);
	rc = dt_lookup(env, child, (struct dt_rec *)fid,
		       (const struct dt_key *)dotdot, BYPASS_CAPA);
	if (rc != 0)
		GOTO(linkea, rc);

	if (!fid_is_sane(fid))
		GOTO(linkea, rc = -EINVAL);

	if (lu_fid_eq(fid, &LU_LPF_FID)) {
		const struct lu_name *cname;

		if (lfsck->li_lpf_obj == NULL) {
			lu_object_get(&child->do_lu);
			lfsck->li_lpf_obj = child;
		}

		cname = lfsck_name_get_const(env, name, strlen(name));
		rc = lfsck_verify_linkea(env, lfsck->li_bottom, child, cname,
					 &LU_LPF_FID);
		if (rc == 0)
			rc = lfsck_update_lpf_entry(env, lfsck, parent, child,
						    name, type);

		GOTO(out_done, rc);
	}

	parent2 = lfsck_object_find_by_dev(env, lfsck->li_next, fid);
	if (IS_ERR(parent2))
		GOTO(linkea, parent2);

	if (!dt_object_exists(parent2)) {
		lu_object_put(env, &parent2->do_lu);

		GOTO(linkea, parent2 = ERR_PTR(-ENOENT));
	}

	if (!dt_try_as_dir(env, parent2)) {
		lu_object_put(env, &parent2->do_lu);

		GOTO(linkea, parent2 = ERR_PTR(-ENOTDIR));
	}

linkea:
	/* To prevent rename/unlink race */
	rc = lfsck_ibits_lock(env, lfsck, child, &lh,
			      MDS_INODELOCK_UPDATE, LCK_PR);
	if (rc != 0)
		GOTO(out_put, rc);

	dt_read_lock(env, child, 0);
	rc = lfsck_links_get_first(env, child, name2, fid2);
	if (rc != 0) {
		dt_read_unlock(env, child);
		lfsck_ibits_unlock(&lh, LCK_PR);

		GOTO(out_put, rc = 1);
	}

	/* It is almost impossible that the bookmark file (or the name entry)
	 * and the linkEA hit the same data corruption. Trust the linkEA. */
	if (lu_fid_eq(fid2, &LU_LPF_FID) && strcmp(name, name2) == 0) {
		dt_read_unlock(env, child);
		lfsck_ibits_unlock(&lh, LCK_PR);

		*fid = *fid2;
		if (lfsck->li_lpf_obj == NULL) {
			lu_object_get(&child->do_lu);
			lfsck->li_lpf_obj = child;
		}

		/* Update the child's dotdot entry */
		rc = lfsck_update_name_entry(env, lfsck, child, dotdot,
					     &LU_LPF_FID, S_IFDIR);
		if (rc == 0)
			rc = lfsck_update_lpf_entry(env, lfsck, parent, child,
						    name, type);

		GOTO(out_put, rc);
	}

	if (parent2 == NULL || IS_ERR(parent2)) {
		dt_read_unlock(env, child);
		lfsck_ibits_unlock(&lh, LCK_PR);

		GOTO(out_done, rc = 1);
	}

	rc = dt_lookup(env, parent2, (struct dt_rec *)fid,
		       (const struct dt_key *)name2, BYPASS_CAPA);
	dt_read_unlock(env, child);
	lfsck_ibits_unlock(&lh, LCK_PR);
	if (rc != 0 && rc != -ENOENT)
		GOTO(out_put, rc);

	if (rc == -ENOENT || !lu_fid_eq(fid, lfsck_dto2fid(child))) {
		if (type == LVLT_BY_BOOKMARK)
			GOTO(out_put, rc = 1);

		/* Trust the name entry, update the child's dotdot entry. */
		rc = lfsck_update_name_entry(env, lfsck, child, dotdot,
					     &LU_LPF_FID, S_IFDIR);

		GOTO(out_put, rc);
	}

	if (type == LVLT_BY_BOOKMARK) {
		/* Invalid FID record in the bookmark file, reset it. */
		fid_zero(&lfsck->li_bookmark_ram.lb_lpf_fid);
		rc = lfsck_bookmark_store(env, lfsck);

		CDEBUG(D_LFSCK, "%s: reset invalid LPF fid "DFID
		       " in the bookmark file: rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(lfsck_dto2fid(child)), rc);
	} else /* if (type == LVLT_BY_NAMEENTRY) */ {
		/* The name entry is wrong, remove it. */
		rc = lfsck_lpf_remove_name_entry(env, lfsck, name);
	}

	GOTO(out_put, rc);

out_put:
	if (parent2 != NULL && !IS_ERR(parent2))
		lu_object_put(env, &parent2->do_lu);

out_done:
	return rc;
}

/**
 * Verify the /ROOT/.lustre/lost+found/ directory.
 *
 * /ROOT/.lustre/lost+found/ is a special directory to hold the objects that
 * the LFSCK does not exactly know how to handle, such as orphans. So before
 * the LFSCK scanning the system, the consistency of such directory needs to
 * be verified firstly to allow the users to use it during the LFSCK.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 *
 * \retval		positive number for uncertain inconsistency
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int lfsck_verify_lpf(const struct lu_env *env, struct lfsck_instance *lfsck)
{
	struct lfsck_thread_info *info	 = lfsck_env_info(env);
	struct lu_fid		 *pfid	 = &info->lti_fid;
	struct lu_fid		 *cfid	 = &info->lti_fid2;
	struct lfsck_bookmark	 *bk	 = &lfsck->li_bookmark_ram;
	struct dt_object	 *parent;
	/* child1's FID is in the bookmark file. */
	struct dt_object	 *child1 = NULL;
	/* child2's FID is in the name entry MDTxxxx. */
	struct dt_object	 *child2 = NULL;
	struct dt_device	 *dev	 = lfsck->li_bottom;
	const struct lu_name	 *cname;
	char			  name[8];
	int			  node   = lfsck_dev_idx(dev);
	int			  rc	 = 0;
	ENTRY;

	LASSERT(lfsck->li_master);

	if (lfsck->li_lpf_root_obj != NULL)
		RETURN(0);

	if (node == 0) {
		parent = lfsck_object_find_by_dev(env, dev, &LU_LPF_FID);
	} else {
		struct lfsck_tgt_desc *ltd;

		ltd = lfsck_tgt_get(&lfsck->li_mdt_descs, 0);
		if (unlikely(ltd == NULL))
			RETURN(-ENXIO);

		parent = lfsck_object_find_by_dev(env, ltd->ltd_tgt,
						  &LU_LPF_FID);
		lfsck_tgt_put(ltd);
	}

	if (IS_ERR(parent))
		RETURN(PTR_ERR(parent));

	LASSERT(dt_object_exists(parent));

	if (unlikely(!dt_try_as_dir(env, parent))) {
		lu_object_put(env, &parent->do_lu);

		GOTO(put, rc = -ENOTDIR);
	}

	lfsck->li_lpf_root_obj = parent;
	if (node == 0) {
		rc = lfsck_scan_lpf_bad_entries(env, lfsck);
		if (rc != 0)
			CDEBUG(D_LFSCK, "%s: scan .lustre/lost+found/ "
			       "for bad sub-directories: rc = %d\n",
			       lfsck_lfsck2name(lfsck), rc);
	}

	if (!fid_is_zero(&bk->lb_lpf_fid)) {
		if (unlikely(!fid_is_norm(&bk->lb_lpf_fid))) {
			struct lu_fid tfid = bk->lb_lpf_fid;

			/* Invalid FID record in the bookmark file, reset it. */
			fid_zero(&bk->lb_lpf_fid);
			rc = lfsck_bookmark_store(env, lfsck);

			CDEBUG(D_LFSCK, "%s: reset invalid LPF fid "DFID
			       " in the bookmark file: rc = %d\n",
			       lfsck_lfsck2name(lfsck), PFID(&tfid), rc);

			if (rc != 0)
				GOTO(put, rc);
		} else {
			child1 = lfsck_object_find_by_dev(env, dev,
							  &bk->lb_lpf_fid);
			if (IS_ERR(child1)) {
				child1 = NULL;
				goto find_child2;
			}

			if (unlikely(!dt_object_exists(child1) ||
				     dt_object_remote(child1)) ||
				     !S_ISDIR(lfsck_object_type(child1))) {
				/* Invalid FID record in the bookmark file,
				 * reset it. */
				fid_zero(&bk->lb_lpf_fid);
				rc = lfsck_bookmark_store(env, lfsck);

				CDEBUG(D_LFSCK, "%s: reset invalid LPF fid "DFID
				       " in the bookmark file: rc = %d\n",
				       lfsck_lfsck2name(lfsck),
				       PFID(lfsck_dto2fid(child1)), rc);

				if (rc != 0)
					GOTO(put, rc);

				lu_object_put(env, &child1->do_lu);
				child1 = NULL;
			} else if (unlikely(!dt_try_as_dir(env, child1))) {
				GOTO(put, rc = -ENOTDIR);
			}
		}
	}

find_child2:
	snprintf(name, 8, "MDT%04x", node);
	rc = dt_lookup(env, parent, (struct dt_rec *)cfid,
		       (const struct dt_key *)name, BYPASS_CAPA);
	if (rc == -ENOENT) {
		if (!fid_is_zero(&bk->lb_lpf_fid))
			goto check_child1;

		GOTO(put, rc = 0);
	}

	if (rc != 0)
		GOTO(put, rc);

	/* Invalid FID in the name entry, remove the name entry. */
	if (!fid_is_norm(cfid)) {
		rc = lfsck_lpf_remove_name_entry(env, lfsck, name);
		if (rc != 0)
			GOTO(put, rc);

		goto check_child1;
	}

	child2 = lfsck_object_find_by_dev(env, dev, cfid);
	if (IS_ERR(child2))
		GOTO(put, rc = PTR_ERR(child2));

	if (unlikely(!dt_object_exists(child2) ||
		     dt_object_remote(child2)) ||
		     !S_ISDIR(lfsck_object_type(child2))) {
		rc = lfsck_lpf_remove_name_entry(env, lfsck, name);
		if (rc != 0)
			GOTO(put, rc);

		goto check_child1;
	}

	if (unlikely(!dt_try_as_dir(env, child2)))
		GOTO(put, rc = -ENOTDIR);

	if (child1 == NULL) {
		rc = lfsck_verify_lpf_pairs(env, lfsck, child2, name,
					    pfid, LVLT_BY_NAMEENTRY);
	} else if (!lu_fid_eq(cfid, &bk->lb_lpf_fid)) {
		rc = lfsck_verify_lpf_pairs(env, lfsck, child1, name,
					    pfid, LVLT_BY_BOOKMARK);
		if (!lu_fid_eq(pfid, &LU_LPF_FID))
			rc = lfsck_verify_lpf_pairs(env, lfsck, child2,
						    name, pfid,
						    LVLT_BY_NAMEENTRY);
	} else {
		if (lfsck->li_lpf_obj == NULL) {
			lu_object_get(&child2->do_lu);
			lfsck->li_lpf_obj = child2;
		}

		cname = lfsck_name_get_const(env, name, strlen(name));
		rc = lfsck_verify_linkea(env, dev, child2, cname, &LU_LPF_FID);
	}

	GOTO(put, rc);

check_child1:
	if (child1 != NULL)
		rc = lfsck_verify_lpf_pairs(env, lfsck, child1, name,
					    pfid, LVLT_BY_BOOKMARK);

	GOTO(put, rc);

put:
	if (lfsck->li_lpf_obj != NULL) {
		if (unlikely(!dt_try_as_dir(env, lfsck->li_lpf_obj))) {
			lu_object_put(env, &lfsck->li_lpf_obj->do_lu);
			lfsck->li_lpf_obj = NULL;
			rc = -ENOTDIR;
		}
	} else if (rc == 0) {
		rc = lfsck_create_lpf(env, lfsck);
	}

	if (child2 != NULL && !IS_ERR(child2))
		lu_object_put(env, &child2->do_lu);
	if (child1 != NULL && !IS_ERR(child1))
		lu_object_put(env, &child1->do_lu);

	return rc;
}

static int lfsck_fid_init(struct lfsck_instance *lfsck)
{
	struct lfsck_bookmark	*bk	= &lfsck->li_bookmark_ram;
	struct seq_server_site	*ss;
	char			*prefix;
	int			 rc	= 0;
	ENTRY;

	ss = lu_site2seq(lfsck->li_bottom->dd_lu_dev.ld_site);
	if (unlikely(ss == NULL))
		RETURN(-ENXIO);

	OBD_ALLOC_PTR(lfsck->li_seq);
	if (lfsck->li_seq == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC(prefix, MAX_OBD_NAME + 7);
	if (prefix == NULL)
		GOTO(out, rc = -ENOMEM);

	snprintf(prefix, MAX_OBD_NAME + 7, "lfsck-%s", lfsck_lfsck2name(lfsck));
	rc = seq_client_init(lfsck->li_seq, NULL, LUSTRE_SEQ_METADATA, prefix,
			     ss->ss_server_seq);
	OBD_FREE(prefix, MAX_OBD_NAME + 7);
	if (rc != 0)
		GOTO(out, rc);

	if (fid_is_sane(&bk->lb_last_fid))
		lfsck->li_seq->lcs_fid = bk->lb_last_fid;

	RETURN(0);

out:
	OBD_FREE_PTR(lfsck->li_seq);
	lfsck->li_seq = NULL;

	return rc;
}

static void lfsck_fid_fini(struct lfsck_instance *lfsck)
{
	if (lfsck->li_seq != NULL) {
		seq_client_fini(lfsck->li_seq);
		OBD_FREE_PTR(lfsck->li_seq);
		lfsck->li_seq = NULL;
	}
}

void lfsck_instance_cleanup(const struct lu_env *env,
			    struct lfsck_instance *lfsck)
{
	struct ptlrpc_thread	*thread = &lfsck->li_thread;
	struct lfsck_component	*com;
	struct lfsck_component	*next;
	struct lfsck_lmv_unit	*llu;
	struct lfsck_lmv_unit	*llu_next;
	struct lfsck_lmv	*llmv;
	ENTRY;

	LASSERT(list_empty(&lfsck->li_link));
	LASSERT(thread_is_init(thread) || thread_is_stopped(thread));

	if (lfsck->li_obj_oit != NULL) {
		lu_object_put_nocache(env, &lfsck->li_obj_oit->do_lu);
		lfsck->li_obj_oit = NULL;
	}

	LASSERT(lfsck->li_obj_dir == NULL);
	LASSERT(lfsck->li_lmv == NULL);

	list_for_each_entry_safe(llu, llu_next, &lfsck->li_list_lmv, llu_link) {
		llmv = &llu->llu_lmv;

		LASSERTF(atomic_read(&llmv->ll_ref) == 1,
			 "still in using: %u\n",
			 atomic_read(&llmv->ll_ref));

		lfsck_lmv_put(env, llmv);
	}

	list_for_each_entry_safe(com, next, &lfsck->li_list_scan, lc_link) {
		lfsck_component_cleanup(env, com);
	}

	LASSERT(list_empty(&lfsck->li_list_dir));

	list_for_each_entry_safe(com, next, &lfsck->li_list_double_scan,
				 lc_link) {
		lfsck_component_cleanup(env, com);
	}

	list_for_each_entry_safe(com, next, &lfsck->li_list_idle, lc_link) {
		lfsck_component_cleanup(env, com);
	}

	lfsck_tgt_descs_fini(&lfsck->li_ost_descs);
	lfsck_tgt_descs_fini(&lfsck->li_mdt_descs);

	if (lfsck->li_bookmark_obj != NULL) {
		lu_object_put_nocache(env, &lfsck->li_bookmark_obj->do_lu);
		lfsck->li_bookmark_obj = NULL;
	}

	if (lfsck->li_lpf_obj != NULL) {
		lu_object_put(env, &lfsck->li_lpf_obj->do_lu);
		lfsck->li_lpf_obj = NULL;
	}

	if (lfsck->li_lpf_root_obj != NULL) {
		lu_object_put(env, &lfsck->li_lpf_root_obj->do_lu);
		lfsck->li_lpf_root_obj = NULL;
	}

	if (lfsck->li_los != NULL) {
		local_oid_storage_fini(env, lfsck->li_los);
		lfsck->li_los = NULL;
	}

	lfsck_fid_fini(lfsck);

	OBD_FREE_PTR(lfsck);
}

static inline struct lfsck_instance *
__lfsck_instance_find(struct dt_device *key, bool ref, bool unlink)
{
	struct lfsck_instance *lfsck;

	list_for_each_entry(lfsck, &lfsck_instance_list, li_link) {
		if (lfsck->li_bottom == key) {
			if (ref)
				lfsck_instance_get(lfsck);
			if (unlink)
				list_del_init(&lfsck->li_link);

			return lfsck;
		}
	}

	return NULL;
}

struct lfsck_instance *lfsck_instance_find(struct dt_device *key, bool ref,
					   bool unlink)
{
	struct lfsck_instance *lfsck;

	spin_lock(&lfsck_instance_lock);
	lfsck = __lfsck_instance_find(key, ref, unlink);
	spin_unlock(&lfsck_instance_lock);

	return lfsck;
}

static inline int lfsck_instance_add(struct lfsck_instance *lfsck)
{
	struct lfsck_instance *tmp;

	spin_lock(&lfsck_instance_lock);
	list_for_each_entry(tmp, &lfsck_instance_list, li_link) {
		if (lfsck->li_bottom == tmp->li_bottom) {
			spin_unlock(&lfsck_instance_lock);
			return -EEXIST;
		}
	}

	list_add_tail(&lfsck->li_link, &lfsck_instance_list);
	spin_unlock(&lfsck_instance_lock);
	return 0;
}

int lfsck_bits_dump(struct seq_file *m, int bits, const char *names[],
		    const char *prefix)
{
	int flag;
	int i;
	bool newline = (bits != 0 ? false : true);

	seq_printf(m, "%s:%c", prefix, bits != 0 ? ' ' : '\n');

	for (i = 0, flag = 1; bits != 0; i++, flag = 1 << i) {
		if (flag & bits) {
			bits &= ~flag;
			if (names[i] != NULL) {
				if (bits == 0)
					newline = true;

				seq_printf(m, "%s%c", names[i],
					   newline ? '\n' : ',');
			}
		}
	}

	if (!newline)
		seq_printf(m, "\n");
	return 0;
}

int lfsck_time_dump(struct seq_file *m, __u64 time, const char *prefix)
{
	if (time != 0)
		seq_printf(m, "%s: "LPU64" seconds\n", prefix,
			  cfs_time_current_sec() - time);
	else
		seq_printf(m, "%s: N/A\n", prefix);
	return 0;
}

int lfsck_pos_dump(struct seq_file *m, struct lfsck_position *pos,
		   const char *prefix)
{
	if (fid_is_zero(&pos->lp_dir_parent)) {
		if (pos->lp_oit_cookie == 0)
			seq_printf(m, "%s: N/A, N/A, N/A\n",
				   prefix);
		else
			seq_printf(m, "%s: "LPU64", N/A, N/A\n",
				   prefix, pos->lp_oit_cookie);
	} else {
		seq_printf(m, "%s: "LPU64", "DFID", "LPX64"\n",
			   prefix, pos->lp_oit_cookie,
			   PFID(&pos->lp_dir_parent), pos->lp_dir_cookie);
	}
	return 0;
}

void lfsck_pos_fill(const struct lu_env *env, struct lfsck_instance *lfsck,
		    struct lfsck_position *pos, bool init)
{
	const struct dt_it_ops *iops = &lfsck->li_obj_oit->do_index_ops->dio_it;

	if (unlikely(lfsck->li_di_oit == NULL)) {
		memset(pos, 0, sizeof(*pos));
		return;
	}

	pos->lp_oit_cookie = iops->store(env, lfsck->li_di_oit);
	if (!lfsck->li_current_oit_processed && !init)
		pos->lp_oit_cookie--;

	LASSERT(pos->lp_oit_cookie > 0);

	if (lfsck->li_di_dir != NULL) {
		struct dt_object *dto = lfsck->li_obj_dir;

		pos->lp_dir_cookie = dto->do_index_ops->dio_it.store(env,
							lfsck->li_di_dir);

		if (pos->lp_dir_cookie >= MDS_DIR_END_OFF) {
			fid_zero(&pos->lp_dir_parent);
			pos->lp_dir_cookie = 0;
		} else {
			pos->lp_dir_parent = *lfsck_dto2fid(dto);
		}
	} else {
		fid_zero(&pos->lp_dir_parent);
		pos->lp_dir_cookie = 0;
	}
}

bool __lfsck_set_speed(struct lfsck_instance *lfsck, __u32 limit)
{
	bool dirty = false;

	if (limit != LFSCK_SPEED_NO_LIMIT) {
		if (limit > msecs_to_jiffies(MSEC_PER_SEC)) {
			lfsck->li_sleep_rate = limit /
					       msecs_to_jiffies(MSEC_PER_SEC);
			lfsck->li_sleep_jif = 1;
		} else {
			lfsck->li_sleep_rate = 1;
			lfsck->li_sleep_jif = msecs_to_jiffies(MSEC_PER_SEC) /
					      limit;
		}
	} else {
		lfsck->li_sleep_jif = 0;
		lfsck->li_sleep_rate = 0;
	}

	if (lfsck->li_bookmark_ram.lb_speed_limit != limit) {
		lfsck->li_bookmark_ram.lb_speed_limit = limit;
		dirty = true;
	}

	return dirty;
}

void lfsck_control_speed(struct lfsck_instance *lfsck)
{
	struct ptlrpc_thread *thread = &lfsck->li_thread;
	struct l_wait_info    lwi;

	if (lfsck->li_sleep_jif > 0 &&
	    lfsck->li_new_scanned >= lfsck->li_sleep_rate) {
		lwi = LWI_TIMEOUT_INTR(lfsck->li_sleep_jif, NULL,
				       LWI_ON_SIGNAL_NOOP, NULL);

		l_wait_event(thread->t_ctl_waitq,
			     !thread_is_running(thread),
			     &lwi);
		lfsck->li_new_scanned = 0;
	}
}

void lfsck_control_speed_by_self(struct lfsck_component *com)
{
	struct lfsck_instance	*lfsck  = com->lc_lfsck;
	struct ptlrpc_thread	*thread = &lfsck->li_thread;
	struct l_wait_info	 lwi;

	if (lfsck->li_sleep_jif > 0 &&
	    com->lc_new_scanned >= lfsck->li_sleep_rate) {
		lwi = LWI_TIMEOUT_INTR(lfsck->li_sleep_jif, NULL,
				       LWI_ON_SIGNAL_NOOP, NULL);

		l_wait_event(thread->t_ctl_waitq,
			     !thread_is_running(thread),
			     &lwi);
		com->lc_new_scanned = 0;
	}
}

static struct lfsck_thread_args *
lfsck_thread_args_init(struct lfsck_instance *lfsck,
		       struct lfsck_component *com,
		       struct lfsck_start_param *lsp)
{
	struct lfsck_thread_args *lta;
	int			  rc;

	OBD_ALLOC_PTR(lta);
	if (lta == NULL)
		return ERR_PTR(-ENOMEM);

	rc = lu_env_init(&lta->lta_env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0) {
		OBD_FREE_PTR(lta);
		return ERR_PTR(rc);
	}

	lta->lta_lfsck = lfsck_instance_get(lfsck);
	if (com != NULL)
		lta->lta_com = lfsck_component_get(com);

	lta->lta_lsp = lsp;

	return lta;
}

void lfsck_thread_args_fini(struct lfsck_thread_args *lta)
{
	if (lta->lta_com != NULL)
		lfsck_component_put(&lta->lta_env, lta->lta_com);
	lfsck_instance_put(&lta->lta_env, lta->lta_lfsck);
	lu_env_fini(&lta->lta_env);
	OBD_FREE_PTR(lta);
}

struct lfsck_assistant_data *
lfsck_assistant_data_init(struct lfsck_assistant_operations *lao,
			  const char *name)
{
	struct lfsck_assistant_data *lad;

	OBD_ALLOC_PTR(lad);
	if (lad != NULL) {
		lad->lad_bitmap = CFS_ALLOCATE_BITMAP(BITS_PER_LONG);
		if (lad->lad_bitmap == NULL) {
			OBD_FREE_PTR(lad);
			return NULL;
		}

		INIT_LIST_HEAD(&lad->lad_req_list);
		spin_lock_init(&lad->lad_lock);
		INIT_LIST_HEAD(&lad->lad_ost_list);
		INIT_LIST_HEAD(&lad->lad_ost_phase1_list);
		INIT_LIST_HEAD(&lad->lad_ost_phase2_list);
		INIT_LIST_HEAD(&lad->lad_mdt_list);
		INIT_LIST_HEAD(&lad->lad_mdt_phase1_list);
		INIT_LIST_HEAD(&lad->lad_mdt_phase2_list);
		init_waitqueue_head(&lad->lad_thread.t_ctl_waitq);
		lad->lad_ops = lao;
		lad->lad_name = name;
	}

	return lad;
}

/**
 * Generic LFSCK asynchronous communication interpretor function.
 * The LFSCK RPC reply for both the event notification and status
 * querying will be handled here.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] req	pointer to the LFSCK request
 * \param[in] args	pointer to the lfsck_async_interpret_args
 * \param[in] rc	the result for handling the LFSCK request
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int lfsck_async_interpret_common(const struct lu_env *env,
				 struct ptlrpc_request *req,
				 void *args, int rc)
{
	struct lfsck_async_interpret_args *laia = args;
	struct lfsck_component		  *com  = laia->laia_com;
	struct lfsck_assistant_data	  *lad  = com->lc_data;
	struct lfsck_tgt_descs		  *ltds = laia->laia_ltds;
	struct lfsck_tgt_desc		  *ltd  = laia->laia_ltd;
	struct lfsck_request		  *lr   = laia->laia_lr;

	LASSERT(com->lc_lfsck->li_master);

	switch (lr->lr_event) {
	case LE_START:
		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: fail to notify %s %x for %s "
			       "start: rc = %d\n",
			       lfsck_lfsck2name(com->lc_lfsck),
			       (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
			       ltd->ltd_index, lad->lad_name, rc);

			if (com->lc_type == LFSCK_TYPE_LAYOUT) {
				struct lfsck_layout *lo = com->lc_file_ram;

				if (lr->lr_flags & LEF_TO_OST)
					lfsck_lad_set_bitmap(env, com,
							     ltd->ltd_index);
				else
					lo->ll_flags |= LF_INCOMPLETE;
			} else {
				struct lfsck_namespace *ns = com->lc_file_ram;

				/* If some MDT does not join the namespace
				 * LFSCK, then we cannot know whether there
				 * is some name entry on such MDT that with
				 * the referenced MDT-object on this MDT or
				 * not. So the namespace LFSCK on this MDT
				 * cannot handle orphan MDT-objects properly.
				 * So we mark the LFSCK as LF_INCOMPLETE and
				 * skip orphan MDT-objects handling. */
				ns->ln_flags |= LF_INCOMPLETE;
			}
			break;
		}

		spin_lock(&ltds->ltd_lock);
		if (ltd->ltd_dead) {
			spin_unlock(&ltds->ltd_lock);
			break;
		}

		if (com->lc_type == LFSCK_TYPE_LAYOUT) {
			struct list_head *list;
			struct list_head *phase_list;

			if (ltd->ltd_layout_done) {
				spin_unlock(&ltds->ltd_lock);
				break;
			}

			if (lr->lr_flags & LEF_TO_OST) {
				list = &lad->lad_ost_list;
				phase_list = &lad->lad_ost_phase1_list;
			} else {
				list = &lad->lad_mdt_list;
				phase_list = &lad->lad_mdt_phase1_list;
			}

			if (list_empty(&ltd->ltd_layout_list))
				list_add_tail(&ltd->ltd_layout_list, list);
			if (list_empty(&ltd->ltd_layout_phase_list))
				list_add_tail(&ltd->ltd_layout_phase_list,
					      phase_list);
		} else {
			if (ltd->ltd_namespace_done) {
				spin_unlock(&ltds->ltd_lock);
				break;
			}

			if (list_empty(&ltd->ltd_namespace_list))
				list_add_tail(&ltd->ltd_namespace_list,
					      &lad->lad_mdt_list);
			if (list_empty(&ltd->ltd_namespace_phase_list))
				list_add_tail(&ltd->ltd_namespace_phase_list,
					      &lad->lad_mdt_phase1_list);
		}
		spin_unlock(&ltds->ltd_lock);
		break;
	case LE_STOP:
	case LE_PHASE1_DONE:
	case LE_PHASE2_DONE:
	case LE_PEER_EXIT:
		if (rc != 0 && rc != -EALREADY)
			CDEBUG(D_LFSCK, "%s: fail to notify %s %x for %s: "
			      "event = %d, rc = %d\n",
			      lfsck_lfsck2name(com->lc_lfsck),
			      (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
			      ltd->ltd_index, lad->lad_name, lr->lr_event, rc);
		break;
	case LE_QUERY: {
		struct lfsck_reply *reply;
		struct list_head *list;
		struct list_head *phase_list;

		if (com->lc_type == LFSCK_TYPE_LAYOUT) {
			list = &ltd->ltd_layout_list;
			phase_list = &ltd->ltd_layout_phase_list;
		} else {
			list = &ltd->ltd_namespace_list;
			phase_list = &ltd->ltd_namespace_phase_list;
		}

		if (rc != 0) {
			spin_lock(&ltds->ltd_lock);
			list_del_init(phase_list);
			list_del_init(list);
			spin_unlock(&ltds->ltd_lock);
			break;
		}

		reply = req_capsule_server_get(&req->rq_pill,
					       &RMF_LFSCK_REPLY);
		if (reply == NULL) {
			rc = -EPROTO;
			CDEBUG(D_LFSCK, "%s: invalid query reply for %s: "
			       "rc = %d\n", lfsck_lfsck2name(com->lc_lfsck),
			       lad->lad_name, rc);
			spin_lock(&ltds->ltd_lock);
			list_del_init(phase_list);
			list_del_init(list);
			spin_unlock(&ltds->ltd_lock);
			break;
		}

		switch (reply->lr_status) {
		case LS_SCANNING_PHASE1:
			break;
		case LS_SCANNING_PHASE2:
			spin_lock(&ltds->ltd_lock);
			list_del_init(phase_list);
			if (ltd->ltd_dead) {
				spin_unlock(&ltds->ltd_lock);
				break;
			}

			if (com->lc_type == LFSCK_TYPE_LAYOUT) {
				if (ltd->ltd_layout_done) {
					spin_unlock(&ltds->ltd_lock);
					break;
				}

				if (lr->lr_flags & LEF_TO_OST)
					list_add_tail(phase_list,
						&lad->lad_ost_phase2_list);
				else
					list_add_tail(phase_list,
						&lad->lad_mdt_phase2_list);
			} else {
				if (ltd->ltd_namespace_done) {
					spin_unlock(&ltds->ltd_lock);
					break;
				}

				list_add_tail(phase_list,
					      &lad->lad_mdt_phase2_list);
			}
			spin_unlock(&ltds->ltd_lock);
			break;
		default:
			spin_lock(&ltds->ltd_lock);
			list_del_init(phase_list);
			list_del_init(list);
			spin_unlock(&ltds->ltd_lock);
			break;
		}
		break;
	}
	default:
		CDEBUG(D_LFSCK, "%s: unexpected event: rc = %d\n",
		       lfsck_lfsck2name(com->lc_lfsck), lr->lr_event);
		break;
	}

	if (!laia->laia_shared) {
		lfsck_tgt_put(ltd);
		lfsck_component_put(env, com);
	}

	return 0;
}

static void lfsck_interpret(const struct lu_env *env,
			    struct lfsck_instance *lfsck,
			    struct ptlrpc_request *req, void *args, int result)
{
	struct lfsck_async_interpret_args *laia = args;
	struct lfsck_component		  *com;

	LASSERT(laia->laia_com == NULL);
	LASSERT(laia->laia_shared);

	spin_lock(&lfsck->li_lock);
	list_for_each_entry(com, &lfsck->li_list_scan, lc_link) {
		laia->laia_com = com;
		lfsck_async_interpret_common(env, req, laia, result);
	}

	list_for_each_entry(com, &lfsck->li_list_double_scan, lc_link) {
		laia->laia_com = com;
		lfsck_async_interpret_common(env, req, laia, result);
	}
	spin_unlock(&lfsck->li_lock);
}

static int lfsck_stop_notify(const struct lu_env *env,
			     struct lfsck_instance *lfsck,
			     struct lfsck_tgt_descs *ltds,
			     struct lfsck_tgt_desc *ltd, __u16 type)
{
	struct lfsck_component *com;
	int			rc = 0;
	ENTRY;

	LASSERT(lfsck->li_master);

	spin_lock(&lfsck->li_lock);
	com = __lfsck_component_find(lfsck, type, &lfsck->li_list_scan);
	if (com == NULL)
		com = __lfsck_component_find(lfsck, type,
					     &lfsck->li_list_double_scan);
	if (com != NULL)
		lfsck_component_get(com);
	spin_unlock(&lfsck->li_lock);

	if (com != NULL) {
		struct lfsck_thread_info	  *info  = lfsck_env_info(env);
		struct lfsck_async_interpret_args *laia  = &info->lti_laia;
		struct lfsck_request		  *lr	 = &info->lti_lr;
		struct lfsck_assistant_data	  *lad	 = com->lc_data;
		struct list_head		  *list;
		struct list_head		  *phase_list;
		struct ptlrpc_request_set	  *set;

		set = ptlrpc_prep_set();
		if (set == NULL) {
			lfsck_component_put(env, com);

			RETURN(-ENOMEM);
		}

		if (type == LFSCK_TYPE_LAYOUT) {
			list = &ltd->ltd_layout_list;
			phase_list = &ltd->ltd_layout_phase_list;
		} else {
			list = &ltd->ltd_namespace_list;
			phase_list = &ltd->ltd_namespace_phase_list;
		}

		spin_lock(&ltds->ltd_lock);
		if (list_empty(list)) {
			LASSERT(list_empty(phase_list));
			spin_unlock(&ltds->ltd_lock);
			ptlrpc_set_destroy(set);

			RETURN(0);
		}

		list_del_init(phase_list);
		list_del_init(list);
		spin_unlock(&ltds->ltd_lock);

		memset(lr, 0, sizeof(*lr));
		lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
		lr->lr_event = LE_PEER_EXIT;
		lr->lr_active = type;
		lr->lr_status = LS_CO_PAUSED;
		if (ltds == &lfsck->li_ost_descs)
			lr->lr_flags = LEF_TO_OST;

		laia->laia_com = com;
		laia->laia_ltds = ltds;
		atomic_inc(&ltd->ltd_ref);
		laia->laia_ltd = ltd;
		laia->laia_lr = lr;
		laia->laia_shared = 0;

		rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					 lfsck_async_interpret_common,
					 laia, LFSCK_NOTIFY);
		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: fail to notify %s %x for "
			       "co-stop for %s: rc = %d\n",
			       lfsck_lfsck2name(lfsck),
			       (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
			       ltd->ltd_index, lad->lad_name, rc);
			lfsck_tgt_put(ltd);
		} else {
			rc = ptlrpc_set_wait(set);
		}

		ptlrpc_set_destroy(set);
		lfsck_component_put(env, com);
	}

	RETURN(rc);
}

static int lfsck_async_interpret(const struct lu_env *env,
				 struct ptlrpc_request *req,
				 void *args, int rc)
{
	struct lfsck_async_interpret_args *laia = args;
	struct lfsck_instance		  *lfsck;

	lfsck = container_of0(laia->laia_ltds, struct lfsck_instance,
			      li_mdt_descs);
	lfsck_interpret(env, lfsck, req, laia, rc);
	lfsck_tgt_put(laia->laia_ltd);
	if (rc != 0 && laia->laia_result != -EALREADY)
		laia->laia_result = rc;

	return 0;
}

int lfsck_async_request(const struct lu_env *env, struct obd_export *exp,
			struct lfsck_request *lr,
			struct ptlrpc_request_set *set,
			ptlrpc_interpterer_t interpreter,
			void *args, int request)
{
	struct lfsck_async_interpret_args *laia;
	struct ptlrpc_request		  *req;
	struct lfsck_request		  *tmp;
	struct req_format		  *format;
	int				   rc;

	switch (request) {
	case LFSCK_NOTIFY:
		format = &RQF_LFSCK_NOTIFY;
		break;
	case LFSCK_QUERY:
		format = &RQF_LFSCK_QUERY;
		break;
	default:
		CDEBUG(D_LFSCK, "%s: unknown async request %d: rc = %d\n",
		       exp->exp_obd->obd_name, request, -EINVAL);
		return -EINVAL;
	}

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), format);
	if (req == NULL)
		return -ENOMEM;

	rc = ptlrpc_request_pack(req, LUSTRE_OBD_VERSION, request);
	if (rc != 0) {
		ptlrpc_request_free(req);

		return rc;
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_LFSCK_REQUEST);
	*tmp = *lr;
	ptlrpc_request_set_replen(req);

	laia = ptlrpc_req_async_args(req);
	*laia = *(struct lfsck_async_interpret_args *)args;
	if (laia->laia_com != NULL)
		lfsck_component_get(laia->laia_com);
	req->rq_interpret_reply = interpreter;
	ptlrpc_set_add_req(set, req);

	return 0;
}

int lfsck_start_assistant(const struct lu_env *env, struct lfsck_component *com,
			  struct lfsck_start_param *lsp)
{
	struct lfsck_instance		*lfsck   = com->lc_lfsck;
	struct lfsck_assistant_data	*lad	 = com->lc_data;
	struct ptlrpc_thread		*mthread = &lfsck->li_thread;
	struct ptlrpc_thread		*athread = &lad->lad_thread;
	struct lfsck_thread_args	*lta;
	struct task_struct		*task;
	int				 rc;
	ENTRY;

	lad->lad_assistant_status = 0;
	lad->lad_post_result = 0;
	lad->lad_to_post = 0;
	lad->lad_to_double_scan = 0;
	lad->lad_in_double_scan = 0;
	lad->lad_exit = 0;
	thread_set_flags(athread, 0);

	lta = lfsck_thread_args_init(lfsck, com, lsp);
	if (IS_ERR(lta))
		RETURN(PTR_ERR(lta));

	task = kthread_run(lfsck_assistant_engine, lta, lad->lad_name);
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start LFSCK assistant thread for %s: "
		       "rc = %d\n", lfsck_lfsck2name(lfsck), lad->lad_name, rc);
		lfsck_thread_args_fini(lta);
	} else {
		struct l_wait_info lwi = { 0 };

		l_wait_event(mthread->t_ctl_waitq,
			     thread_is_running(athread) ||
			     thread_is_stopped(athread),
			     &lwi);
		if (unlikely(!thread_is_running(athread)))
			rc = lad->lad_assistant_status;
		else
			rc = 0;
	}

	RETURN(rc);
}

int lfsck_checkpoint_generic(const struct lu_env *env,
			     struct lfsck_component *com)
{
	struct lfsck_assistant_data	*lad	 = com->lc_data;
	struct ptlrpc_thread		*mthread = &com->lc_lfsck->li_thread;
	struct ptlrpc_thread		*athread = &lad->lad_thread;
	struct l_wait_info		 lwi	 = { 0 };

	if (com->lc_new_checked == 0)
		return LFSCK_CHECKPOINT_SKIP;

	l_wait_event(mthread->t_ctl_waitq,
		     list_empty(&lad->lad_req_list) ||
		     !thread_is_running(mthread) ||
		     thread_is_stopped(athread),
		     &lwi);

	if (!thread_is_running(mthread) || thread_is_stopped(athread))
		return LFSCK_CHECKPOINT_SKIP;

	return 0;
}

void lfsck_post_generic(const struct lu_env *env,
			struct lfsck_component *com, int *result)
{
	struct lfsck_assistant_data	*lad	 = com->lc_data;
	struct ptlrpc_thread		*athread = &lad->lad_thread;
	struct ptlrpc_thread		*mthread = &com->lc_lfsck->li_thread;
	struct l_wait_info		 lwi	 = { 0 };

	lad->lad_post_result = *result;
	if (*result <= 0)
		lad->lad_exit = 1;
	lad->lad_to_post = 1;

	wake_up_all(&athread->t_ctl_waitq);
	l_wait_event(mthread->t_ctl_waitq,
		     (*result > 0 && list_empty(&lad->lad_req_list)) ||
		     thread_is_stopped(athread),
		     &lwi);

	if (lad->lad_assistant_status < 0)
		*result = lad->lad_assistant_status;
}

int lfsck_double_scan_generic(const struct lu_env *env,
			      struct lfsck_component *com, int status)
{
	struct lfsck_assistant_data	*lad	 = com->lc_data;
	struct ptlrpc_thread		*mthread = &com->lc_lfsck->li_thread;
	struct ptlrpc_thread		*athread = &lad->lad_thread;
	struct l_wait_info		 lwi	 = { 0 };

	if (status != LS_SCANNING_PHASE2)
		lad->lad_exit = 1;
	else
		lad->lad_to_double_scan = 1;

	wake_up_all(&athread->t_ctl_waitq);
	l_wait_event(mthread->t_ctl_waitq,
		     lad->lad_in_double_scan ||
		     thread_is_stopped(athread),
		     &lwi);

	if (lad->lad_assistant_status < 0)
		return lad->lad_assistant_status;

	return 0;
}

void lfsck_quit_generic(const struct lu_env *env,
			struct lfsck_component *com)
{
	struct lfsck_assistant_data	*lad	 = com->lc_data;
	struct ptlrpc_thread		*mthread = &com->lc_lfsck->li_thread;
	struct ptlrpc_thread		*athread = &lad->lad_thread;
	struct l_wait_info		 lwi     = { 0 };

	lad->lad_exit = 1;
	wake_up_all(&athread->t_ctl_waitq);
	l_wait_event(mthread->t_ctl_waitq,
		     thread_is_init(athread) ||
		     thread_is_stopped(athread),
		     &lwi);
}

/* external interfaces */

int lfsck_get_speed(struct seq_file *m, struct dt_device *key)
{
	struct lu_env		env;
	struct lfsck_instance  *lfsck;
	int			rc;
	ENTRY;

	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0)
		RETURN(rc);

	lfsck = lfsck_instance_find(key, true, false);
	if (likely(lfsck != NULL)) {
		seq_printf(m, "%u\n", lfsck->li_bookmark_ram.lb_speed_limit);
		lfsck_instance_put(&env, lfsck);
	} else {
		rc = -ENXIO;
	}

	lu_env_fini(&env);

	RETURN(rc);
}
EXPORT_SYMBOL(lfsck_get_speed);

int lfsck_set_speed(struct dt_device *key, int val)
{
	struct lu_env		env;
	struct lfsck_instance  *lfsck;
	int			rc;
	ENTRY;

	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0)
		RETURN(rc);

	lfsck = lfsck_instance_find(key, true, false);
	if (likely(lfsck != NULL)) {
		mutex_lock(&lfsck->li_mutex);
		if (__lfsck_set_speed(lfsck, val))
			rc = lfsck_bookmark_store(&env, lfsck);
		mutex_unlock(&lfsck->li_mutex);
		lfsck_instance_put(&env, lfsck);
	} else {
		rc = -ENXIO;
	}

	lu_env_fini(&env);

	RETURN(rc);
}
EXPORT_SYMBOL(lfsck_set_speed);

int lfsck_get_windows(struct seq_file *m, struct dt_device *key)
{
	struct lu_env		env;
	struct lfsck_instance  *lfsck;
	int			rc;
	ENTRY;

	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0)
		RETURN(rc);

	lfsck = lfsck_instance_find(key, true, false);
	if (likely(lfsck != NULL)) {
		seq_printf(m, "%u\n", lfsck->li_bookmark_ram.lb_async_windows);
		lfsck_instance_put(&env, lfsck);
	} else {
		rc = -ENXIO;
	}

	lu_env_fini(&env);

	RETURN(rc);
}
EXPORT_SYMBOL(lfsck_get_windows);

int lfsck_set_windows(struct dt_device *key, int val)
{
	struct lu_env		env;
	struct lfsck_instance  *lfsck;
	int			rc;
	ENTRY;

	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0)
		RETURN(rc);

	lfsck = lfsck_instance_find(key, true, false);
	if (likely(lfsck != NULL)) {
		if (val > LFSCK_ASYNC_WIN_MAX) {
			CWARN("%s: Too large async window size, which "
			      "may cause memory issues. The valid range "
			      "is [0 - %u]. If you do not want to restrict "
			      "the window size for async requests pipeline, "
			      "just set it as 0.\n",
			      lfsck_lfsck2name(lfsck), LFSCK_ASYNC_WIN_MAX);
			rc = -EINVAL;
		} else if (lfsck->li_bookmark_ram.lb_async_windows != val) {
			mutex_lock(&lfsck->li_mutex);
			lfsck->li_bookmark_ram.lb_async_windows = val;
			rc = lfsck_bookmark_store(&env, lfsck);
			mutex_unlock(&lfsck->li_mutex);
		}
		lfsck_instance_put(&env, lfsck);
	} else {
		rc = -ENXIO;
	}

	lu_env_fini(&env);

	RETURN(rc);
}
EXPORT_SYMBOL(lfsck_set_windows);

int lfsck_dump(struct seq_file *m, struct dt_device *key, enum lfsck_type type)
{
	struct lu_env		env;
	struct lfsck_instance  *lfsck;
	struct lfsck_component *com;
	int			rc;
	ENTRY;

	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0)
		RETURN(rc);

	lfsck = lfsck_instance_find(key, true, false);
	if (likely(lfsck != NULL)) {
		com = lfsck_component_find(lfsck, type);
		if (likely(com != NULL)) {
			rc = com->lc_ops->lfsck_dump(&env, com, m);
			lfsck_component_put(&env, com);
		} else {
			rc = -ENOTSUPP;
		}

		lfsck_instance_put(&env, lfsck);
	} else {
		rc = -ENXIO;
	}

	lu_env_fini(&env);

	RETURN(rc);
}
EXPORT_SYMBOL(lfsck_dump);

static int lfsck_stop_all(const struct lu_env *env,
			  struct lfsck_instance *lfsck,
			  struct lfsck_stop *stop)
{
	struct lfsck_thread_info	  *info	  = lfsck_env_info(env);
	struct lfsck_request		  *lr	  = &info->lti_lr;
	struct lfsck_async_interpret_args *laia	  = &info->lti_laia;
	struct ptlrpc_request_set	  *set;
	struct lfsck_tgt_descs		  *ltds   = &lfsck->li_mdt_descs;
	struct lfsck_tgt_desc		  *ltd;
	struct lfsck_bookmark		  *bk	  = &lfsck->li_bookmark_ram;
	__u32				   idx;
	int				   rc	  = 0;
	int				   rc1	  = 0;
	ENTRY;

	LASSERT(stop->ls_flags & LPF_BROADCAST);

	set = ptlrpc_prep_set();
	if (unlikely(set == NULL))
		RETURN(-ENOMEM);

	memset(lr, 0, sizeof(*lr));
	lr->lr_event = LE_STOP;
	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	lr->lr_status = stop->ls_status;
	lr->lr_version = bk->lb_version;
	lr->lr_active = LFSCK_TYPES_ALL;
	lr->lr_param = stop->ls_flags;

	laia->laia_com = NULL;
	laia->laia_ltds = ltds;
	laia->laia_lr = lr;
	laia->laia_result = 0;
	laia->laia_shared = 1;

	down_read(&ltds->ltd_rw_sem);
	cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
		ltd = lfsck_tgt_get(ltds, idx);
		LASSERT(ltd != NULL);

		laia->laia_ltd = ltd;
		rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					 lfsck_async_interpret, laia,
					 LFSCK_NOTIFY);
		if (rc != 0) {
			lfsck_interpret(env, lfsck, NULL, laia, rc);
			lfsck_tgt_put(ltd);
			CERROR("%s: cannot notify MDT %x for LFSCK stop: "
			       "rc = %d\n", lfsck_lfsck2name(lfsck), idx, rc);
			rc1 = rc;
		}
	}
	up_read(&ltds->ltd_rw_sem);

	rc = ptlrpc_set_wait(set);
	ptlrpc_set_destroy(set);

	if (rc == 0)
		rc = laia->laia_result;

	if (rc == -EALREADY)
		rc = 0;

	if (rc != 0)
		CERROR("%s: fail to stop LFSCK on some MDTs: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);

	RETURN(rc != 0 ? rc : rc1);
}

static int lfsck_start_all(const struct lu_env *env,
			   struct lfsck_instance *lfsck,
			   struct lfsck_start *start)
{
	struct lfsck_thread_info	  *info	  = lfsck_env_info(env);
	struct lfsck_request		  *lr	  = &info->lti_lr;
	struct lfsck_async_interpret_args *laia	  = &info->lti_laia;
	struct ptlrpc_request_set	  *set;
	struct lfsck_tgt_descs		  *ltds   = &lfsck->li_mdt_descs;
	struct lfsck_tgt_desc		  *ltd;
	struct lfsck_bookmark		  *bk	  = &lfsck->li_bookmark_ram;
	__u32				   idx;
	int				   rc	  = 0;
	ENTRY;

	LASSERT(start->ls_flags & LPF_BROADCAST);

	set = ptlrpc_prep_set();
	if (unlikely(set == NULL))
		RETURN(-ENOMEM);

	memset(lr, 0, sizeof(*lr));
	lr->lr_event = LE_START;
	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	lr->lr_speed = bk->lb_speed_limit;
	lr->lr_version = bk->lb_version;
	lr->lr_active = start->ls_active;
	lr->lr_param = start->ls_flags;
	lr->lr_async_windows = bk->lb_async_windows;
	lr->lr_valid = LSV_SPEED_LIMIT | LSV_ERROR_HANDLE | LSV_DRYRUN |
		       LSV_ASYNC_WINDOWS | LSV_CREATE_OSTOBJ |
		       LSV_CREATE_MDTOBJ;

	laia->laia_com = NULL;
	laia->laia_ltds = ltds;
	laia->laia_lr = lr;
	laia->laia_result = 0;
	laia->laia_shared = 1;

	down_read(&ltds->ltd_rw_sem);
	cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
		ltd = lfsck_tgt_get(ltds, idx);
		LASSERT(ltd != NULL);

		laia->laia_ltd = ltd;
		ltd->ltd_layout_done = 0;
		ltd->ltd_namespace_done = 0;
		rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					 lfsck_async_interpret, laia,
					 LFSCK_NOTIFY);
		if (rc != 0) {
			lfsck_interpret(env, lfsck, NULL, laia, rc);
			lfsck_tgt_put(ltd);
			CERROR("%s: cannot notify MDT %x for LFSCK "
			       "start, failout: rc = %d\n",
			       lfsck_lfsck2name(lfsck), idx, rc);
			break;
		}
	}
	up_read(&ltds->ltd_rw_sem);

	if (rc != 0) {
		ptlrpc_set_destroy(set);

		RETURN(rc);
	}

	rc = ptlrpc_set_wait(set);
	ptlrpc_set_destroy(set);

	if (rc == 0)
		rc = laia->laia_result;

	if (rc != 0) {
		struct lfsck_stop *stop = &info->lti_stop;

		CERROR("%s: cannot start LFSCK on some MDTs, "
		       "stop all: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);
		if (rc != -EALREADY) {
			stop->ls_status = LS_FAILED;
			stop->ls_flags = LPF_ALL_TGT | LPF_BROADCAST;
			lfsck_stop_all(env, lfsck, stop);
		}
	}

	RETURN(rc);
}

int lfsck_start(const struct lu_env *env, struct dt_device *key,
		struct lfsck_start_param *lsp)
{
	struct lfsck_start		*start  = lsp->lsp_start;
	struct lfsck_instance		*lfsck;
	struct lfsck_bookmark		*bk;
	struct ptlrpc_thread		*thread;
	struct lfsck_component		*com;
	struct l_wait_info		 lwi    = { 0 };
	struct lfsck_thread_args	*lta;
	struct task_struct		*task;
	int				 rc     = 0;
	__u16				 valid  = 0;
	__u16				 flags  = 0;
	__u16				 type   = 1;
	ENTRY;

	lfsck = lfsck_instance_find(key, true, false);
	if (unlikely(lfsck == NULL))
		RETURN(-ENXIO);

	/* System is not ready, try again later. */
	if (unlikely(lfsck->li_namespace == NULL))
		GOTO(put, rc = -EAGAIN);

	/* start == NULL means auto trigger paused LFSCK. */
	if ((start == NULL) &&
	    (list_empty(&lfsck->li_list_scan) ||
	     OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NO_AUTO)))
		GOTO(put, rc = 0);

	bk = &lfsck->li_bookmark_ram;
	thread = &lfsck->li_thread;
	mutex_lock(&lfsck->li_mutex);
	spin_lock(&lfsck->li_lock);
	if (!thread_is_init(thread) && !thread_is_stopped(thread)) {
		rc = -EALREADY;
		if (unlikely(start == NULL)) {
			spin_unlock(&lfsck->li_lock);
			GOTO(out, rc);
		}

		while (start->ls_active != 0) {
			if (!(type & start->ls_active)) {
				type <<= 1;
				continue;
			}

			com = __lfsck_component_find(lfsck, type,
						     &lfsck->li_list_scan);
			if (com == NULL)
				com = __lfsck_component_find(lfsck, type,
						&lfsck->li_list_double_scan);
			if (com == NULL) {
				rc = -EOPNOTSUPP;
				break;
			}

			if (com->lc_ops->lfsck_join != NULL) {
				rc = com->lc_ops->lfsck_join( env, com, lsp);
				if (rc != 0 && rc != -EALREADY)
					break;
			}
			start->ls_active &= ~type;
			type <<= 1;
		}
		spin_unlock(&lfsck->li_lock);
		GOTO(out, rc);
	}
	spin_unlock(&lfsck->li_lock);

	lfsck->li_status = 0;
	lfsck->li_oit_over = 0;
	lfsck->li_start_unplug = 0;
	lfsck->li_drop_dryrun = 0;
	lfsck->li_new_scanned = 0;

	/* For auto trigger. */
	if (start == NULL)
		goto trigger;

	if (start->ls_flags & LPF_BROADCAST && !lfsck->li_master) {
		CERROR("%s: only allow to specify '-A | -o' via MDS\n",
		       lfsck_lfsck2name(lfsck));

		GOTO(out, rc = -EPERM);
	}

	start->ls_version = bk->lb_version;

	if (start->ls_active != 0) {
		struct lfsck_component *next;

		if (start->ls_active == LFSCK_TYPES_ALL)
			start->ls_active = LFSCK_TYPES_SUPPORTED;

		if (start->ls_active & ~LFSCK_TYPES_SUPPORTED) {
			start->ls_active &= ~LFSCK_TYPES_SUPPORTED;
			GOTO(out, rc = -ENOTSUPP);
		}

		list_for_each_entry_safe(com, next,
					 &lfsck->li_list_scan, lc_link) {
			if (!(com->lc_type & start->ls_active)) {
				rc = com->lc_ops->lfsck_post(env, com, 0,
							     false);
				if (rc != 0)
					GOTO(out, rc);
			}
		}

		while (start->ls_active != 0) {
			if (type & start->ls_active) {
				com = __lfsck_component_find(lfsck, type,
							&lfsck->li_list_idle);
				if (com != NULL)
					/* The component status will be updated
					 * when its prep() is called later by
					 * the LFSCK main engine. */
					list_move_tail(&com->lc_link,
						       &lfsck->li_list_scan);
				start->ls_active &= ~type;
			}
			type <<= 1;
		}
	}

	if (list_empty(&lfsck->li_list_scan)) {
		/* The speed limit will be used to control both the LFSCK and
		 * low layer scrub (if applied), need to be handled firstly. */
		if (start->ls_valid & LSV_SPEED_LIMIT) {
			if (__lfsck_set_speed(lfsck, start->ls_speed_limit)) {
				rc = lfsck_bookmark_store(env, lfsck);
				if (rc != 0)
					GOTO(out, rc);
			}
		}

		goto trigger;
	}

	if (start->ls_flags & LPF_RESET)
		flags |= DOIF_RESET;

	rc = lfsck_set_param(env, lfsck, start, !!(flags & DOIF_RESET));
	if (rc != 0)
		GOTO(out, rc);

	list_for_each_entry(com, &lfsck->li_list_scan, lc_link) {
		start->ls_active |= com->lc_type;
		if (flags & DOIF_RESET) {
			rc = com->lc_ops->lfsck_reset(env, com, false);
			if (rc != 0)
				GOTO(out, rc);
		}
	}

trigger:
	lfsck->li_args_dir = LUDA_64BITHASH | LUDA_VERIFY | LUDA_TYPE;
	if (bk->lb_param & LPF_DRYRUN)
		lfsck->li_args_dir |= LUDA_VERIFY_DRYRUN;

	if (start != NULL && start->ls_valid & LSV_ERROR_HANDLE) {
		valid |= DOIV_ERROR_HANDLE;
		if (start->ls_flags & LPF_FAILOUT)
			flags |= DOIF_FAILOUT;
	}

	if (start != NULL && start->ls_valid & LSV_DRYRUN) {
		valid |= DOIV_DRYRUN;
		if (start->ls_flags & LPF_DRYRUN)
			flags |= DOIF_DRYRUN;
	}

	if (!list_empty(&lfsck->li_list_scan))
		flags |= DOIF_OUTUSED;

	lfsck->li_args_oit = (flags << DT_OTABLE_IT_FLAGS_SHIFT) | valid;
	thread_set_flags(thread, 0);
	lta = lfsck_thread_args_init(lfsck, NULL, lsp);
	if (IS_ERR(lta))
		GOTO(out, rc = PTR_ERR(lta));

	__lfsck_set_speed(lfsck, bk->lb_speed_limit);
	task = kthread_run(lfsck_master_engine, lta, "lfsck");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start LFSCK thread: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);
		lfsck_thread_args_fini(lta);

		GOTO(out, rc);
	}

	l_wait_event(thread->t_ctl_waitq,
		     thread_is_running(thread) ||
		     thread_is_stopped(thread),
		     &lwi);
	if (start == NULL || !(start->ls_flags & LPF_BROADCAST)) {
		lfsck->li_start_unplug = 1;
		wake_up_all(&thread->t_ctl_waitq);

		GOTO(out, rc = 0);
	}

	/* release lfsck::li_mutex to avoid deadlock. */
	mutex_unlock(&lfsck->li_mutex);
	rc = lfsck_start_all(env, lfsck, start);
	if (rc != 0) {
		spin_lock(&lfsck->li_lock);
		if (thread_is_stopped(thread)) {
			spin_unlock(&lfsck->li_lock);
		} else {
			lfsck->li_status = LS_FAILED;
			lfsck->li_flags = 0;
			thread_set_flags(thread, SVC_STOPPING);
			spin_unlock(&lfsck->li_lock);

			lfsck->li_start_unplug = 1;
			wake_up_all(&thread->t_ctl_waitq);
			l_wait_event(thread->t_ctl_waitq,
				     thread_is_stopped(thread),
				     &lwi);
		}
	} else {
		lfsck->li_start_unplug = 1;
		wake_up_all(&thread->t_ctl_waitq);
	}

	GOTO(put, rc);

out:
	mutex_unlock(&lfsck->li_mutex);

put:
	lfsck_instance_put(env, lfsck);

	return rc < 0 ? rc : 0;
}
EXPORT_SYMBOL(lfsck_start);

int lfsck_stop(const struct lu_env *env, struct dt_device *key,
	       struct lfsck_stop *stop)
{
	struct lfsck_instance	*lfsck;
	struct ptlrpc_thread	*thread;
	struct l_wait_info	 lwi    = { 0 };
	int			 rc	= 0;
	int			 rc1	= 0;
	ENTRY;

	lfsck = lfsck_instance_find(key, true, false);
	if (unlikely(lfsck == NULL))
		RETURN(-ENXIO);

	thread = &lfsck->li_thread;
	/* release lfsck::li_mutex to avoid deadlock. */
	if (stop != NULL && stop->ls_flags & LPF_BROADCAST) {
		if (!lfsck->li_master) {
			CERROR("%s: only allow to specify '-A' via MDS\n",
			       lfsck_lfsck2name(lfsck));

			GOTO(out, rc = -EPERM);
		}

		rc1 = lfsck_stop_all(env, lfsck, stop);
	}

	mutex_lock(&lfsck->li_mutex);
	spin_lock(&lfsck->li_lock);
	/* no error if LFSCK is already stopped, or was never started */
	if (thread_is_init(thread) || thread_is_stopped(thread)) {
		spin_unlock(&lfsck->li_lock);
		GOTO(out, rc = 0);
	}

	if (stop != NULL) {
		lfsck->li_status = stop->ls_status;
		lfsck->li_flags = stop->ls_flags;
	} else {
		lfsck->li_status = LS_STOPPED;
		lfsck->li_flags = 0;
	}

	thread_set_flags(thread, SVC_STOPPING);
	spin_unlock(&lfsck->li_lock);

	wake_up_all(&thread->t_ctl_waitq);
	l_wait_event(thread->t_ctl_waitq,
		     thread_is_stopped(thread),
		     &lwi);

	GOTO(out, rc = 0);

out:
	mutex_unlock(&lfsck->li_mutex);
	lfsck_instance_put(env, lfsck);

	return rc != 0 ? rc : rc1;
}
EXPORT_SYMBOL(lfsck_stop);

int lfsck_in_notify(const struct lu_env *env, struct dt_device *key,
		    struct lfsck_request *lr, struct thandle *th)
{
	int rc = -EOPNOTSUPP;
	ENTRY;

	switch (lr->lr_event) {
	case LE_START: {
		struct lfsck_start	 *start = &lfsck_env_info(env)->lti_start;
		struct lfsck_start_param  lsp;

		memset(start, 0, sizeof(*start));
		start->ls_valid = lr->lr_valid;
		start->ls_speed_limit = lr->lr_speed;
		start->ls_version = lr->lr_version;
		start->ls_active = lr->lr_active;
		start->ls_flags = lr->lr_param & ~LPF_BROADCAST;
		start->ls_async_windows = lr->lr_async_windows;

		lsp.lsp_start = start;
		lsp.lsp_index = lr->lr_index;
		lsp.lsp_index_valid = 1;
		rc = lfsck_start(env, key, &lsp);
		break;
	}
	case LE_STOP: {
		struct lfsck_stop *stop = &lfsck_env_info(env)->lti_stop;

		memset(stop, 0, sizeof(*stop));
		stop->ls_status = lr->lr_status;
		stop->ls_flags = lr->lr_param & ~LPF_BROADCAST;
		rc = lfsck_stop(env, key, stop);
		break;
	}
	case LE_PHASE1_DONE:
	case LE_PHASE2_DONE:
	case LE_FID_ACCESSED:
	case LE_PEER_EXIT:
	case LE_CONDITIONAL_DESTROY:
	case LE_SKIP_NLINK_DECLARE:
	case LE_SKIP_NLINK:
	case LE_SET_LMV_MASTER:
	case LE_SET_LMV_SLAVE:
	case LE_PAIRS_VERIFY: {
		struct lfsck_instance  *lfsck;
		struct lfsck_component *com;

		lfsck = lfsck_instance_find(key, true, false);
		if (unlikely(lfsck == NULL))
			RETURN(-ENXIO);

		com = lfsck_component_find(lfsck, lr->lr_active);
		if (likely(com != NULL)) {
			rc = com->lc_ops->lfsck_in_notify(env, com, lr, th);
			lfsck_component_put(env, com);
		}

		lfsck_instance_put(env, lfsck);
		break;
	}
	default:
		break;
	}

	RETURN(rc);
}
EXPORT_SYMBOL(lfsck_in_notify);

int lfsck_query(const struct lu_env *env, struct dt_device *key,
		struct lfsck_request *lr)
{
	struct lfsck_instance  *lfsck;
	struct lfsck_component *com;
	int			rc;
	ENTRY;

	lfsck = lfsck_instance_find(key, true, false);
	if (unlikely(lfsck == NULL))
		RETURN(-ENXIO);

	com = lfsck_component_find(lfsck, lr->lr_active);
	if (likely(com != NULL)) {
		rc = com->lc_ops->lfsck_query(env, com);
		lfsck_component_put(env, com);
	} else {
		rc = -ENOTSUPP;
	}

	lfsck_instance_put(env, lfsck);

	RETURN(rc);
}
EXPORT_SYMBOL(lfsck_query);

int lfsck_register_namespace(const struct lu_env *env, struct dt_device *key,
			     struct ldlm_namespace *ns)
{
	struct lfsck_instance  *lfsck;
	int			rc	= -ENXIO;

	lfsck = lfsck_instance_find(key, true, false);
	if (likely(lfsck != NULL)) {
		lfsck->li_namespace = ns;
		lfsck_instance_put(env, lfsck);
		rc = 0;
	}

	return rc;
}
EXPORT_SYMBOL(lfsck_register_namespace);

int lfsck_register(const struct lu_env *env, struct dt_device *key,
		   struct dt_device *next, struct obd_device *obd,
		   lfsck_out_notify notify, void *notify_data, bool master)
{
	struct lfsck_instance	*lfsck;
	struct dt_object	*root  = NULL;
	struct dt_object	*obj   = NULL;
	struct lu_fid		*fid   = &lfsck_env_info(env)->lti_fid;
	int			 rc;
	ENTRY;

	lfsck = lfsck_instance_find(key, false, false);
	if (unlikely(lfsck != NULL))
		RETURN(-EEXIST);

	OBD_ALLOC_PTR(lfsck);
	if (lfsck == NULL)
		RETURN(-ENOMEM);

	mutex_init(&lfsck->li_mutex);
	spin_lock_init(&lfsck->li_lock);
	INIT_LIST_HEAD(&lfsck->li_link);
	INIT_LIST_HEAD(&lfsck->li_list_scan);
	INIT_LIST_HEAD(&lfsck->li_list_dir);
	INIT_LIST_HEAD(&lfsck->li_list_double_scan);
	INIT_LIST_HEAD(&lfsck->li_list_idle);
	INIT_LIST_HEAD(&lfsck->li_list_lmv);
	atomic_set(&lfsck->li_ref, 1);
	atomic_set(&lfsck->li_double_scan_count, 0);
	init_waitqueue_head(&lfsck->li_thread.t_ctl_waitq);
	lfsck->li_out_notify = notify;
	lfsck->li_out_notify_data = notify_data;
	lfsck->li_next = next;
	lfsck->li_bottom = key;
	lfsck->li_obd = obd;

	rc = lfsck_tgt_descs_init(&lfsck->li_ost_descs);
	if (rc != 0)
		GOTO(out, rc);

	rc = lfsck_tgt_descs_init(&lfsck->li_mdt_descs);
	if (rc != 0)
		GOTO(out, rc);

	fid->f_seq = FID_SEQ_LOCAL_NAME;
	fid->f_oid = 1;
	fid->f_ver = 0;
	rc = local_oid_storage_init(env, key, fid, &lfsck->li_los);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_root_get(env, key, fid);
	if (rc != 0)
		GOTO(out, rc);

	root = dt_locate(env, key, fid);
	if (IS_ERR(root))
		GOTO(out, rc = PTR_ERR(root));

	if (unlikely(!dt_try_as_dir(env, root)))
		GOTO(out, rc = -ENOTDIR);

	lfsck->li_local_root_fid = *fid;
	if (master) {
		lfsck->li_master = 1;
		if (lfsck_dev_idx(key) == 0) {
			struct lu_fid *pfid = &lfsck_env_info(env)->lti_fid2;
			const struct lu_name *cname;

			rc = dt_lookup(env, root,
				(struct dt_rec *)(&lfsck->li_global_root_fid),
				(const struct dt_key *)"ROOT", BYPASS_CAPA);
			if (rc != 0)
				GOTO(out, rc);

			obj = dt_locate(env, key, &lfsck->li_global_root_fid);
			if (IS_ERR(obj))
				GOTO(out, rc = PTR_ERR(obj));

			if (unlikely(!dt_try_as_dir(env, obj)))
				GOTO(out, rc = -ENOTDIR);

			rc = dt_lookup(env, obj, (struct dt_rec *)fid,
				(const struct dt_key *)dotlustre, BYPASS_CAPA);
			if (rc != 0)
				GOTO(out, rc);

			lu_object_put(env, &obj->do_lu);
			obj = dt_locate(env, key, fid);
			if (IS_ERR(obj))
				GOTO(out, rc = PTR_ERR(obj));

			cname = lfsck_name_get_const(env, dotlustre,
						     strlen(dotlustre));
			rc = lfsck_verify_linkea(env, key, obj, cname,
						 &lfsck->li_global_root_fid);
			if (rc != 0)
				GOTO(out, rc);

			if (unlikely(!dt_try_as_dir(env, obj)))
				GOTO(out, rc = -ENOTDIR);

			*pfid = *fid;
			rc = dt_lookup(env, obj, (struct dt_rec *)fid,
				       (const struct dt_key *)lostfound,
				       BYPASS_CAPA);
			if (rc != 0)
				GOTO(out, rc);

			lu_object_put(env, &obj->do_lu);
			obj = dt_locate(env, key, fid);
			if (IS_ERR(obj))
				GOTO(out, rc = PTR_ERR(obj));

			cname = lfsck_name_get_const(env, lostfound,
						     strlen(lostfound));
			rc = lfsck_verify_linkea(env, key, obj, cname, pfid);
			if (rc != 0)
				GOTO(out, rc);

			lu_object_put(env, &obj->do_lu);
			obj = NULL;
		}
	}

	fid->f_seq = FID_SEQ_LOCAL_FILE;
	fid->f_oid = OTABLE_IT_OID;
	fid->f_ver = 0;
	obj = dt_locate(env, key, fid);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	lu_object_get(&obj->do_lu);
	lfsck->li_obj_oit = obj;
	rc = obj->do_ops->do_index_try(env, obj, &dt_otable_features);
	if (rc != 0)
		GOTO(out, rc);

	rc = lfsck_bookmark_setup(env, lfsck);
	if (rc != 0)
		GOTO(out, rc);

	if (master) {
		rc = lfsck_fid_init(lfsck);
		if (rc < 0)
			GOTO(out, rc);

		rc = lfsck_namespace_setup(env, lfsck);
		if (rc < 0)
			GOTO(out, rc);
	}

	rc = lfsck_layout_setup(env, lfsck);
	if (rc < 0)
		GOTO(out, rc);

	/* XXX: more LFSCK components initialization to be added here. */

	rc = lfsck_instance_add(lfsck);
	if (rc == 0)
		rc = lfsck_add_target_from_orphan(env, lfsck);
out:
	if (obj != NULL && !IS_ERR(obj))
		lu_object_put(env, &obj->do_lu);
	if (root != NULL && !IS_ERR(root))
		lu_object_put(env, &root->do_lu);
	if (rc != 0)
		lfsck_instance_cleanup(env, lfsck);
	return rc;
}
EXPORT_SYMBOL(lfsck_register);

void lfsck_degister(const struct lu_env *env, struct dt_device *key)
{
	struct lfsck_instance *lfsck;

	lfsck = lfsck_instance_find(key, false, true);
	if (lfsck != NULL)
		lfsck_instance_put(env, lfsck);
}
EXPORT_SYMBOL(lfsck_degister);

int lfsck_add_target(const struct lu_env *env, struct dt_device *key,
		     struct dt_device *tgt, struct obd_export *exp,
		     __u32 index, bool for_ost)
{
	struct lfsck_instance	*lfsck;
	struct lfsck_tgt_desc	*ltd;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(ltd);
	if (ltd == NULL)
		RETURN(-ENOMEM);

	ltd->ltd_tgt = tgt;
	ltd->ltd_key = key;
	ltd->ltd_exp = exp;
	INIT_LIST_HEAD(&ltd->ltd_orphan_list);
	INIT_LIST_HEAD(&ltd->ltd_layout_list);
	INIT_LIST_HEAD(&ltd->ltd_layout_phase_list);
	INIT_LIST_HEAD(&ltd->ltd_namespace_list);
	INIT_LIST_HEAD(&ltd->ltd_namespace_phase_list);
	atomic_set(&ltd->ltd_ref, 1);
	ltd->ltd_index = index;

	spin_lock(&lfsck_instance_lock);
	lfsck = __lfsck_instance_find(key, true, false);
	if (lfsck == NULL) {
		if (for_ost)
			list_add_tail(&ltd->ltd_orphan_list,
				      &lfsck_ost_orphan_list);
		else
			list_add_tail(&ltd->ltd_orphan_list,
				      &lfsck_mdt_orphan_list);
		spin_unlock(&lfsck_instance_lock);

		RETURN(0);
	}
	spin_unlock(&lfsck_instance_lock);

	rc = __lfsck_add_target(env, lfsck, ltd, for_ost, false);
	if (rc != 0)
		lfsck_tgt_put(ltd);

	lfsck_instance_put(env, lfsck);

	RETURN(rc);
}
EXPORT_SYMBOL(lfsck_add_target);

void lfsck_del_target(const struct lu_env *env, struct dt_device *key,
		      struct dt_device *tgt, __u32 index, bool for_ost)
{
	struct lfsck_instance	*lfsck;
	struct lfsck_tgt_descs	*ltds;
	struct lfsck_tgt_desc	*ltd;
	struct list_head	*head;

	if (for_ost)
		head = &lfsck_ost_orphan_list;
	else
		head = &lfsck_mdt_orphan_list;

	spin_lock(&lfsck_instance_lock);
	list_for_each_entry(ltd, head, ltd_orphan_list) {
		if (ltd->ltd_tgt == tgt) {
			list_del_init(&ltd->ltd_orphan_list);
			spin_unlock(&lfsck_instance_lock);
			lfsck_tgt_put(ltd);

			return;
		}
	}

	ltd = NULL;
	lfsck = __lfsck_instance_find(key, true, false);
	spin_unlock(&lfsck_instance_lock);
	if (unlikely(lfsck == NULL))
		return;

	if (for_ost)
		ltds = &lfsck->li_ost_descs;
	else
		ltds = &lfsck->li_mdt_descs;

	down_write(&ltds->ltd_rw_sem);
	LASSERT(ltds->ltd_tgts_bitmap != NULL);

	if (unlikely(index >= ltds->ltd_tgts_bitmap->size))
		goto unlock;

	ltd = LTD_TGT(ltds, index);
	if (unlikely(ltd == NULL))
		goto unlock;

	LASSERT(ltds->ltd_tgtnr > 0);

	ltds->ltd_tgtnr--;
	cfs_bitmap_clear(ltds->ltd_tgts_bitmap, index);
	LTD_TGT(ltds, index) = NULL;

unlock:
	if (ltd == NULL) {
		if (for_ost)
			head = &lfsck->li_ost_descs.ltd_orphan;
		else
			head = &lfsck->li_mdt_descs.ltd_orphan;

		list_for_each_entry(ltd, head, ltd_orphan_list) {
			if (ltd->ltd_tgt == tgt) {
				list_del_init(&ltd->ltd_orphan_list);
				break;
			}
		}
	}

	up_write(&ltds->ltd_rw_sem);
	if (ltd != NULL) {
		spin_lock(&ltds->ltd_lock);
		ltd->ltd_dead = 1;
		spin_unlock(&ltds->ltd_lock);
		lfsck_stop_notify(env, lfsck, ltds, ltd, LFSCK_TYPE_NAMESPACE);
		lfsck_stop_notify(env, lfsck, ltds, ltd, LFSCK_TYPE_LAYOUT);
		lfsck_tgt_put(ltd);
	}

	lfsck_instance_put(env, lfsck);
}
EXPORT_SYMBOL(lfsck_del_target);

static int __init lfsck_init(void)
{
	int rc;

	INIT_LIST_HEAD(&lfsck_instance_list);
	INIT_LIST_HEAD(&lfsck_ost_orphan_list);
	INIT_LIST_HEAD(&lfsck_mdt_orphan_list);
	lfsck_key_init_generic(&lfsck_thread_key, NULL);
	rc = lu_context_key_register(&lfsck_thread_key);
	if (rc == 0) {
		tgt_register_lfsck_in_notify(lfsck_in_notify);
		tgt_register_lfsck_query(lfsck_query);
	}

	return rc;
}

static void __exit lfsck_exit(void)
{
	struct lfsck_tgt_desc *ltd;
	struct lfsck_tgt_desc *next;

	LASSERT(list_empty(&lfsck_instance_list));

	list_for_each_entry_safe(ltd, next, &lfsck_ost_orphan_list,
				 ltd_orphan_list) {
		list_del_init(&ltd->ltd_orphan_list);
		lfsck_tgt_put(ltd);
	}

	list_for_each_entry_safe(ltd, next, &lfsck_mdt_orphan_list,
				 ltd_orphan_list) {
		list_del_init(&ltd->ltd_orphan_list);
		lfsck_tgt_put(ltd);
	}

	lu_context_key_degister(&lfsck_thread_key);
}

MODULE_AUTHOR("Intel Corporation <http://www.intel.com/>");
MODULE_DESCRIPTION("LFSCK");
MODULE_LICENSE("GPL");

cfs_module(lfsck, LUSTRE_VERSION_STRING, lfsck_init, lfsck_exit);
