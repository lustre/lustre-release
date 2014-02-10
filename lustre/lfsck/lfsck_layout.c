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
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * lustre/lfsck/lfsck_layout.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LFSCK

#include <linux/bitops.h>

#include <lustre/lustre_idl.h>
#include <lu_object.h>
#include <dt_object.h>
#include <lustre_linkea.h>
#include <lustre_fid.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre/lustre_user.h>
#include <md_object.h>
#include <obd_class.h>

#include "lfsck_internal.h"

#define LFSCK_LAYOUT_MAGIC		0xB173AE14

static const char lfsck_layout_name[] = "lfsck_layout";

struct lfsck_layout_seq {
	struct list_head	 lls_list;
	__u64			 lls_seq;
	__u64			 lls_lastid;
	__u64			 lls_lastid_known;
	struct dt_object	*lls_lastid_obj;
	unsigned int		 lls_dirty:1;
};

struct lfsck_layout_slave_target {
	/* link into lfsck_layout_slave_data::llsd_master_list. */
	struct list_head	llst_list;
	__u64			llst_gen;
	atomic_t		llst_ref;
	__u32			llst_index;
};

struct lfsck_layout_slave_data {
	/* list for lfsck_layout_seq */
	struct list_head	 llsd_seq_list;

	/* list for the masters involve layout verification. */
	struct list_head	 llsd_master_list;
	spinlock_t		 llsd_lock;
	__u64			 llsd_touch_gen;
};

struct lfsck_layout_object {
	struct dt_object	*llo_obj;
	struct lu_attr		 llo_attr;
	atomic_t		 llo_ref;
	__u16			 llo_gen;
};

struct lfsck_layout_req {
	struct list_head		 llr_list;
	struct lfsck_layout_object	*llr_parent;
	struct dt_object		*llr_child;
	__u32				 llr_ost_idx;
	__u32				 llr_lov_idx; /* offset in LOV EA */
};

struct lfsck_layout_master_data {
	spinlock_t		llmd_lock;
	struct list_head	llmd_req_list;

	/* list for the ost targets involve layout verification. */
	struct list_head	llmd_ost_list;

	/* list for the ost targets in phase1 scanning. */
	struct list_head	llmd_ost_phase1_list;

	/* list for the ost targets in phase1 scanning. */
	struct list_head	llmd_ost_phase2_list;

	/* list for the mdt targets involve layout verification. */
	struct list_head	llmd_mdt_list;

	/* list for the mdt targets in phase1 scanning. */
	struct list_head	llmd_mdt_phase1_list;

	/* list for the mdt targets in phase1 scanning. */
	struct list_head	llmd_mdt_phase2_list;

	struct ptlrpc_thread	llmd_thread;
	__u32			llmd_touch_gen;
	int			llmd_prefetched;
	int			llmd_assistant_status;
	int			llmd_post_result;
	unsigned int		llmd_to_post:1,
				llmd_to_double_scan:1,
				llmd_in_double_scan:1,
				llmd_exit:1;
};

struct lfsck_layout_slave_async_args {
	struct obd_export		 *llsaa_exp;
	struct lfsck_component		 *llsaa_com;
	struct lfsck_layout_slave_target *llsaa_llst;
};

static struct lfsck_layout_object *
lfsck_layout_object_init(const struct lu_env *env, struct dt_object *obj,
			 __u16 gen)
{
	struct lfsck_layout_object *llo;
	int			    rc;

	OBD_ALLOC_PTR(llo);
	if (llo == NULL)
		return ERR_PTR(-ENOMEM);

	rc = dt_attr_get(env, obj, &llo->llo_attr, BYPASS_CAPA);
	if (rc != 0) {
		OBD_FREE_PTR(llo);

		return ERR_PTR(rc);
	}

	lu_object_get(&obj->do_lu);
	llo->llo_obj = obj;
	/* The gen can be used to check whether some others have changed the
	 * file layout after LFSCK pre-fetching but before real verification. */
	llo->llo_gen = gen;
	atomic_set(&llo->llo_ref, 1);

	return llo;
}

static inline void
lfsck_layout_llst_put(struct lfsck_layout_slave_target *llst)
{
	if (atomic_dec_and_test(&llst->llst_ref)) {
		LASSERT(list_empty(&llst->llst_list));

		OBD_FREE_PTR(llst);
	}
}

static inline int
lfsck_layout_llst_add(struct lfsck_layout_slave_data *llsd, __u32 index)
{
	struct lfsck_layout_slave_target *llst;
	struct lfsck_layout_slave_target *tmp;
	int				  rc   = 0;

	OBD_ALLOC_PTR(llst);
	if (llst == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&llst->llst_list);
	llst->llst_gen = 0;
	llst->llst_index = index;
	atomic_set(&llst->llst_ref, 1);

	spin_lock(&llsd->llsd_lock);
	list_for_each_entry(tmp, &llsd->llsd_master_list, llst_list) {
		if (tmp->llst_index == index) {
			rc = -EALREADY;
			break;
		}
	}
	if (rc == 0)
		list_add_tail(&llst->llst_list, &llsd->llsd_master_list);
	spin_unlock(&llsd->llsd_lock);

	if (rc != 0)
		OBD_FREE_PTR(llst);

	return rc;
}

static inline void
lfsck_layout_llst_del(struct lfsck_layout_slave_data *llsd,
		      struct lfsck_layout_slave_target *llst)
{
	bool del = false;

	spin_lock(&llsd->llsd_lock);
	if (!list_empty(&llst->llst_list)) {
		list_del_init(&llst->llst_list);
		del = true;
	}
	spin_unlock(&llsd->llsd_lock);

	if (del)
		lfsck_layout_llst_put(llst);
}

static inline struct lfsck_layout_slave_target *
lfsck_layout_llst_find_and_del(struct lfsck_layout_slave_data *llsd,
			       __u32 index)
{
	struct lfsck_layout_slave_target *llst;

	spin_lock(&llsd->llsd_lock);
	list_for_each_entry(llst, &llsd->llsd_master_list, llst_list) {
		if (llst->llst_index == index) {
			list_del_init(&llst->llst_list);
			spin_unlock(&llsd->llsd_lock);

			return llst;
		}
	}
	spin_unlock(&llsd->llsd_lock);

	return NULL;
}

static inline void lfsck_layout_object_put(const struct lu_env *env,
					   struct lfsck_layout_object *llo)
{
	if (atomic_dec_and_test(&llo->llo_ref)) {
		lfsck_object_put(env, llo->llo_obj);
		OBD_FREE_PTR(llo);
	}
}

static struct lfsck_layout_req *
lfsck_layout_req_init(struct lfsck_layout_object *parent,
		      struct dt_object *child, __u32 ost_idx, __u32 lov_idx)
{
	struct lfsck_layout_req *llr;

	OBD_ALLOC_PTR(llr);
	if (llr == NULL)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&llr->llr_list);
	atomic_inc(&parent->llo_ref);
	llr->llr_parent = parent;
	llr->llr_child = child;
	llr->llr_ost_idx = ost_idx;
	llr->llr_lov_idx = lov_idx;

	return llr;
}

static inline void lfsck_layout_req_fini(const struct lu_env *env,
					 struct lfsck_layout_req *llr)
{
	lu_object_put(env, &llr->llr_child->do_lu);
	lfsck_layout_object_put(env, llr->llr_parent);
	OBD_FREE_PTR(llr);
}

static inline bool lfsck_layout_req_empty(struct lfsck_layout_master_data *llmd)
{
	bool empty = false;

	spin_lock(&llmd->llmd_lock);
	if (list_empty(&llmd->llmd_req_list))
		empty = true;
	spin_unlock(&llmd->llmd_lock);

	return empty;
}

static int lfsck_layout_get_lovea(const struct lu_env *env,
				  struct dt_object *obj,
				  struct lu_buf *buf, ssize_t *buflen)
{
	int rc;

again:
	rc = dt_xattr_get(env, obj, buf, XATTR_NAME_LOV, BYPASS_CAPA);
	if (rc == -ERANGE) {
		rc = dt_xattr_get(env, obj, &LU_BUF_NULL, XATTR_NAME_LOV,
				  BYPASS_CAPA);
		if (rc <= 0)
			return rc;

		lu_buf_realloc(buf, rc);
		if (buflen != NULL)
			*buflen = buf->lb_len;

		if (buf->lb_buf == NULL)
			return -ENOMEM;

		goto again;
	}

	if (rc == -ENODATA)
		rc = 0;

	if (rc <= 0)
		return rc;

	if (unlikely(buf->lb_buf == NULL)) {
		lu_buf_alloc(buf, rc);
		if (buflen != NULL)
			*buflen = buf->lb_len;

		if (buf->lb_buf == NULL)
			return -ENOMEM;

		goto again;
	}

	return rc;
}

static int lfsck_layout_verify_header(struct lov_mds_md_v1 *lmm)
{
	__u32 magic;
	__u32 patten;

	magic = le32_to_cpu(lmm->lmm_magic);
	/* If magic crashed, keep it there. Sometime later, during OST-object
	 * orphan handling, if some OST-object(s) back-point to it, it can be
	 * verified and repaired. */
	if (magic != LOV_MAGIC_V1 && magic != LOV_MAGIC_V3)
		return -EINVAL;

	patten = le32_to_cpu(lmm->lmm_pattern);
	/* XXX: currently, we only support LOV_PATTERN_RAID0. */
	if (patten != LOV_PATTERN_RAID0)
		return -EOPNOTSUPP;

	return 0;
}

static void lfsck_layout_le_to_cpu(struct lfsck_layout *des,
				   const struct lfsck_layout *src)
{
	int i;

	des->ll_magic = le32_to_cpu(src->ll_magic);
	des->ll_status = le32_to_cpu(src->ll_status);
	des->ll_flags = le32_to_cpu(src->ll_flags);
	des->ll_success_count = le32_to_cpu(src->ll_success_count);
	des->ll_run_time_phase1 = le32_to_cpu(src->ll_run_time_phase1);
	des->ll_run_time_phase2 = le32_to_cpu(src->ll_run_time_phase2);
	des->ll_time_last_complete = le64_to_cpu(src->ll_time_last_complete);
	des->ll_time_latest_start = le64_to_cpu(src->ll_time_latest_start);
	des->ll_time_last_checkpoint =
				le64_to_cpu(src->ll_time_last_checkpoint);
	des->ll_pos_latest_start = le64_to_cpu(src->ll_pos_latest_start);
	des->ll_pos_last_checkpoint = le64_to_cpu(src->ll_pos_last_checkpoint);
	des->ll_pos_first_inconsistent =
			le64_to_cpu(src->ll_pos_first_inconsistent);
	des->ll_objs_checked_phase1 = le64_to_cpu(src->ll_objs_checked_phase1);
	des->ll_objs_failed_phase1 = le64_to_cpu(src->ll_objs_failed_phase1);
	des->ll_objs_checked_phase2 = le64_to_cpu(src->ll_objs_checked_phase2);
	des->ll_objs_failed_phase2 = le64_to_cpu(src->ll_objs_failed_phase2);
	for (i = 0; i < LLIT_MAX; i++)
		des->ll_objs_repaired[i] =
				le64_to_cpu(src->ll_objs_repaired[i]);
	des->ll_objs_skipped = le64_to_cpu(src->ll_objs_skipped);
}

static void lfsck_layout_cpu_to_le(struct lfsck_layout *des,
				   const struct lfsck_layout *src)
{
	int i;

	des->ll_magic = cpu_to_le32(src->ll_magic);
	des->ll_status = cpu_to_le32(src->ll_status);
	des->ll_flags = cpu_to_le32(src->ll_flags);
	des->ll_success_count = cpu_to_le32(src->ll_success_count);
	des->ll_run_time_phase1 = cpu_to_le32(src->ll_run_time_phase1);
	des->ll_run_time_phase2 = cpu_to_le32(src->ll_run_time_phase2);
	des->ll_time_last_complete = cpu_to_le64(src->ll_time_last_complete);
	des->ll_time_latest_start = cpu_to_le64(src->ll_time_latest_start);
	des->ll_time_last_checkpoint =
				cpu_to_le64(src->ll_time_last_checkpoint);
	des->ll_pos_latest_start = cpu_to_le64(src->ll_pos_latest_start);
	des->ll_pos_last_checkpoint = cpu_to_le64(src->ll_pos_last_checkpoint);
	des->ll_pos_first_inconsistent =
			cpu_to_le64(src->ll_pos_first_inconsistent);
	des->ll_objs_checked_phase1 = cpu_to_le64(src->ll_objs_checked_phase1);
	des->ll_objs_failed_phase1 = cpu_to_le64(src->ll_objs_failed_phase1);
	des->ll_objs_checked_phase2 = cpu_to_le64(src->ll_objs_checked_phase2);
	des->ll_objs_failed_phase2 = cpu_to_le64(src->ll_objs_failed_phase2);
	for (i = 0; i < LLIT_MAX; i++)
		des->ll_objs_repaired[i] =
				cpu_to_le64(src->ll_objs_repaired[i]);
	des->ll_objs_skipped = cpu_to_le64(src->ll_objs_skipped);
}

/**
 * \retval +ve: the lfsck_layout is broken, the caller should reset it.
 * \retval 0: succeed.
 * \retval -ve: failed cases.
 */
static int lfsck_layout_load(const struct lu_env *env,
			     struct lfsck_component *com)
{
	struct lfsck_layout		*lo	= com->lc_file_ram;
	const struct dt_body_operations *dbo	= com->lc_obj->do_body_ops;
	ssize_t				 size	= com->lc_file_size;
	loff_t				 pos	= 0;
	int				 rc;

	rc = dbo->dbo_read(env, com->lc_obj,
			   lfsck_buf_get(env, com->lc_file_disk, size), &pos,
			   BYPASS_CAPA);
	if (rc == 0) {
		return -ENOENT;
	} else if (rc < 0) {
		CWARN("%s: failed to load lfsck_layout: rc = %d\n",
		      lfsck_lfsck2name(com->lc_lfsck), rc);
		return rc;
	} else if (rc != size) {
		CWARN("%s: crashed lfsck_layout, to be reset: rc = %d\n",
		      lfsck_lfsck2name(com->lc_lfsck), rc);
		return 1;
	}

	lfsck_layout_le_to_cpu(lo, com->lc_file_disk);
	if (lo->ll_magic != LFSCK_LAYOUT_MAGIC) {
		CWARN("%s: invalid lfsck_layout magic %#x != %#x, "
		      "to be reset\n", lfsck_lfsck2name(com->lc_lfsck),
		      lo->ll_magic, LFSCK_LAYOUT_MAGIC);
		return 1;
	}

	return 0;
}

static int lfsck_layout_store(const struct lu_env *env,
			      struct lfsck_component *com)
{
	struct dt_object	 *obj		= com->lc_obj;
	struct lfsck_instance	 *lfsck		= com->lc_lfsck;
	struct lfsck_layout	 *lo		= com->lc_file_disk;
	struct thandle		 *handle;
	ssize_t			  size		= com->lc_file_size;
	loff_t			  pos		= 0;
	int			  rc;
	ENTRY;

	lfsck_layout_cpu_to_le(lo, com->lc_file_ram);
	handle = dt_trans_create(env, lfsck->li_bottom);
	if (IS_ERR(handle)) {
		rc = PTR_ERR(handle);
		CERROR("%s: fail to create trans for storing lfsck_layout: "
		       "rc = %d\n", lfsck_lfsck2name(lfsck), rc);
		RETURN(rc);
	}

	rc = dt_declare_record_write(env, obj, size, pos, handle);
	if (rc != 0) {
		CERROR("%s: fail to declare trans for storing lfsck_layout(1): "
		       "rc = %d\n", lfsck_lfsck2name(lfsck), rc);
		GOTO(out, rc);
	}

	rc = dt_trans_start_local(env, lfsck->li_bottom, handle);
	if (rc != 0) {
		CERROR("%s: fail to start trans for storing lfsck_layout: "
		       "rc = %d\n", lfsck_lfsck2name(lfsck), rc);
		GOTO(out, rc);
	}

	rc = dt_record_write(env, obj, lfsck_buf_get(env, lo, size), &pos,
			     handle);
	if (rc != 0)
		CERROR("%s: fail to store lfsck_layout(1): size = %d, "
		       "rc = %d\n", lfsck_lfsck2name(lfsck), (int)size, rc);

	GOTO(out, rc);

out:
	dt_trans_stop(env, lfsck->li_bottom, handle);

	return rc;
}

static int lfsck_layout_init(const struct lu_env *env,
			     struct lfsck_component *com)
{
	struct lfsck_layout *lo = com->lc_file_ram;
	int rc;

	memset(lo, 0, com->lc_file_size);
	lo->ll_magic = LFSCK_LAYOUT_MAGIC;
	lo->ll_status = LS_INIT;
	down_write(&com->lc_sem);
	rc = lfsck_layout_store(env, com);
	up_write(&com->lc_sem);

	return rc;
}

static int fid_is_for_ostobj(const struct lu_env *env, struct dt_device *dt,
			     struct dt_object *obj, const struct lu_fid *fid)
{
	struct seq_server_site	*ss	= lu_site2seq(dt->dd_lu_dev.ld_site);
	struct lu_seq_range	 range	= { 0 };
	struct lustre_mdt_attrs *lma;
	int			 rc;

	fld_range_set_any(&range);
	rc = fld_server_lookup(env, ss->ss_server_fld, fid_seq(fid), &range);
	if (rc == 0) {
		if (fld_range_is_ost(&range))
			return 1;

		return 0;
	}

	lma = &lfsck_env_info(env)->lti_lma;
	rc = dt_xattr_get(env, obj, lfsck_buf_get(env, lma, sizeof(*lma)),
			  XATTR_NAME_LMA, BYPASS_CAPA);
	if (rc == sizeof(*lma)) {
		lustre_lma_swab(lma);

		return lma->lma_compat & LMAC_FID_ON_OST ? 1 : 0;
	}

	rc = dt_xattr_get(env, obj, &LU_BUF_NULL, XATTR_NAME_FID, BYPASS_CAPA);

	return rc > 0;
}

static struct lfsck_layout_seq *
lfsck_layout_seq_lookup(struct lfsck_layout_slave_data *llsd, __u64 seq)
{
	struct lfsck_layout_seq *lls;

	list_for_each_entry(lls, &llsd->llsd_seq_list, lls_list) {
		if (lls->lls_seq == seq)
			return lls;

		if (lls->lls_seq > seq)
			return NULL;
	}

	return NULL;
}

static void
lfsck_layout_seq_insert(struct lfsck_layout_slave_data *llsd,
			struct lfsck_layout_seq *lls)
{
	struct lfsck_layout_seq *tmp;
	struct list_head	*pos = &llsd->llsd_seq_list;

	list_for_each_entry(tmp, &llsd->llsd_seq_list, lls_list) {
		if (lls->lls_seq < tmp->lls_seq) {
			pos = &tmp->lls_list;
			break;
		}
	}
	list_add_tail(&lls->lls_list, pos);
}

static int
lfsck_layout_lastid_create(const struct lu_env *env,
			   struct lfsck_instance *lfsck,
			   struct dt_object *obj)
{
	struct lfsck_thread_info *info	 = lfsck_env_info(env);
	struct lu_attr		 *la	 = &info->lti_la;
	struct dt_object_format  *dof	 = &info->lti_dof;
	struct lfsck_bookmark	 *bk	 = &lfsck->li_bookmark_ram;
	struct dt_device	 *dt	 = lfsck->li_bottom;
	struct thandle		 *th;
	__u64			  lastid = 0;
	loff_t			  pos	 = 0;
	int			  rc;
	ENTRY;

	CDEBUG(D_LFSCK, "To create LAST_ID for <seq> "LPX64"\n",
	       fid_seq(lfsck_dto2fid(obj)));

	if (bk->lb_param & LPF_DRYRUN)
		return 0;

	memset(la, 0, sizeof(*la));
	la->la_mode = S_IFREG |  S_IRUGO | S_IWUSR;
	la->la_valid = LA_MODE | LA_UID | LA_GID;
	dof->dof_type = dt_mode_to_dft(S_IFREG);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(rc = PTR_ERR(th));

	rc = dt_declare_create(env, obj, la, NULL, dof, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_record_write(env, obj, sizeof(lastid), pos, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dt, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	if (likely(!dt_object_exists(obj))) {
		rc = dt_create(env, obj, la, NULL, dof, th);
		if (rc == 0)
			rc = dt_record_write(env, obj,
				lfsck_buf_get(env, &lastid, sizeof(lastid)),
				&pos, th);
	}
	dt_write_unlock(env, obj);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dt, th);

	return rc;
}

static int
lfsck_layout_lastid_reload(const struct lu_env *env,
			   struct lfsck_component *com,
			   struct lfsck_layout_seq *lls)
{
	__u64	lastid;
	loff_t	pos	= 0;
	int	rc;

	dt_read_lock(env, lls->lls_lastid_obj, 0);
	rc = dt_record_read(env, lls->lls_lastid_obj,
			    lfsck_buf_get(env, &lastid, sizeof(lastid)), &pos);
	dt_read_unlock(env, lls->lls_lastid_obj);
	if (unlikely(rc != 0))
		return rc;

	lastid = le64_to_cpu(lastid);
	if (lastid < lls->lls_lastid_known) {
		struct lfsck_instance	*lfsck	= com->lc_lfsck;
		struct lfsck_layout	*lo	= com->lc_file_ram;

		lls->lls_lastid = lls->lls_lastid_known;
		lls->lls_dirty = 1;
		if (!(lo->ll_flags & LF_CRASHED_LASTID)) {
			LASSERT(lfsck->li_out_notify != NULL);

			lfsck->li_out_notify(env, lfsck->li_out_notify_data,
					     LE_LASTID_REBUILDING);
			lo->ll_flags |= LF_CRASHED_LASTID;
		}
	} else if (lastid >= lls->lls_lastid) {
		lls->lls_lastid = lastid;
		lls->lls_dirty = 0;
	}

	return 0;
}

static int
lfsck_layout_lastid_store(const struct lu_env *env,
			  struct lfsck_component *com)
{
	struct lfsck_instance		*lfsck  = com->lc_lfsck;
	struct lfsck_bookmark		*bk	= &lfsck->li_bookmark_ram;
	struct dt_device		*dt	= lfsck->li_bottom;
	struct lfsck_layout_slave_data	*llsd	= com->lc_data;
	struct lfsck_layout_seq 	*lls;
	struct thandle			*th;
	__u64				 lastid;
	int				 rc	= 0;
	int				 rc1	= 0;

	list_for_each_entry(lls, &llsd->llsd_seq_list, lls_list) {
		loff_t pos = 0;

		/* XXX: Add the code back if we really found related
		 *	inconsistent cases in the future. */
#if 0
		if (!lls->lls_dirty) {
			/* In OFD, before the pre-creation, the LAST_ID
			 * file will be updated firstly, which may hide
			 * some potential crashed cases. For example:
			 *
			 * The old obj1's ID is higher than old LAST_ID
			 * but lower than the new LAST_ID, but the LFSCK
			 * have not touch the obj1 until the OFD updated
			 * the LAST_ID. So the LFSCK does not regard it
			 * as crashed case. But when OFD does not create
			 * successfully, it will set the LAST_ID as the
			 * real created objects' ID, then LFSCK needs to
			 * found related inconsistency. */
			rc = lfsck_layout_lastid_reload(env, com, lls);
			if (likely(!lls->lls_dirty))
				continue;
		}
#endif

		CDEBUG(D_LFSCK, "To sync the LAST_ID for <seq> "LPX64
		       " as <oid> "LPU64"\n", lls->lls_seq, lls->lls_lastid);

		if (bk->lb_param & LPF_DRYRUN) {
			lls->lls_dirty = 0;
			continue;
		}

		th = dt_trans_create(env, dt);
		if (IS_ERR(th)) {
			rc1 = PTR_ERR(th);
			CERROR("%s: (1) failed to store "LPX64": rc = %d\n",
			       lfsck_lfsck2name(com->lc_lfsck),
			       lls->lls_seq, rc1);
			continue;
		}

		rc = dt_declare_record_write(env, lls->lls_lastid_obj,
					     sizeof(lastid), pos, th);
		if (rc != 0)
			goto stop;

		rc = dt_trans_start_local(env, dt, th);
		if (rc != 0)
			goto stop;

		lastid = cpu_to_le64(lls->lls_lastid);
		dt_write_lock(env, lls->lls_lastid_obj, 0);
		rc = dt_record_write(env, lls->lls_lastid_obj,
				     lfsck_buf_get(env, &lastid,
				     sizeof(lastid)), &pos, th);
		dt_write_unlock(env, lls->lls_lastid_obj);
		if (rc == 0)
			lls->lls_dirty = 0;

stop:
		dt_trans_stop(env, dt, th);
		if (rc != 0) {
			rc1 = rc;
			CERROR("%s: (2) failed to store "LPX64": rc = %d\n",
			       lfsck_lfsck2name(com->lc_lfsck),
			       lls->lls_seq, rc1);
		}
	}

	return rc1;
}

static int
lfsck_layout_lastid_load(const struct lu_env *env,
			 struct lfsck_component *com,
			 struct lfsck_layout_seq *lls)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_layout	*lo	= com->lc_file_ram;
	struct lu_fid		*fid	= &lfsck_env_info(env)->lti_fid;
	struct dt_object	*obj;
	loff_t			 pos	= 0;
	int			 rc;
	ENTRY;

	lu_last_id_fid(fid, lls->lls_seq, lfsck_dev_idx(lfsck->li_bottom));
	obj = dt_locate(env, lfsck->li_bottom, fid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	/* LAST_ID crashed, to be rebuilt */
	if (!dt_object_exists(obj)) {
		if (!(lo->ll_flags & LF_CRASHED_LASTID)) {
			LASSERT(lfsck->li_out_notify != NULL);

			lfsck->li_out_notify(env, lfsck->li_out_notify_data,
					     LE_LASTID_REBUILDING);
			lo->ll_flags |= LF_CRASHED_LASTID;

			if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DELAY4) &&
			    cfs_fail_val > 0) {
				struct l_wait_info lwi = LWI_TIMEOUT(
						cfs_time_seconds(cfs_fail_val),
						NULL, NULL);

				up_write(&com->lc_sem);
				l_wait_event(lfsck->li_thread.t_ctl_waitq,
					     !thread_is_running(&lfsck->li_thread),
					     &lwi);
				down_write(&com->lc_sem);
			}
		}

		rc = lfsck_layout_lastid_create(env, lfsck, obj);
	} else {
		dt_read_lock(env, obj, 0);
		rc = dt_read(env, obj,
			lfsck_buf_get(env, &lls->lls_lastid, sizeof(__u64)),
			&pos);
		dt_read_unlock(env, obj);
		if (rc != 0 && rc != sizeof(__u64))
			GOTO(out, rc = (rc > 0 ? -EFAULT : rc));

		if (rc == 0 && !(lo->ll_flags & LF_CRASHED_LASTID)) {
			LASSERT(lfsck->li_out_notify != NULL);

			lfsck->li_out_notify(env, lfsck->li_out_notify_data,
					     LE_LASTID_REBUILDING);
			lo->ll_flags |= LF_CRASHED_LASTID;
		}

		lls->lls_lastid = le64_to_cpu(lls->lls_lastid);
		rc = 0;
	}

	GOTO(out, rc);

out:
	if (rc != 0)
		lfsck_object_put(env, obj);
	else
		lls->lls_lastid_obj = obj;

	return rc;
}

static int lfsck_layout_master_async_interpret(const struct lu_env *env,
					       struct ptlrpc_request *req,
					       void *args, int rc)
{
	struct lfsck_async_interpret_args *laia = args;
	struct lfsck_component		  *com  = laia->laia_com;
	struct lfsck_layout_master_data	  *llmd = com->lc_data;
	struct lfsck_tgt_descs		  *ltds = laia->laia_ltds;
	struct lfsck_tgt_desc		  *ltd  = laia->laia_ltd;
	struct lfsck_request		  *lr   = laia->laia_lr;

	switch (lr->lr_event) {
	case LE_START:
		if (rc != 0) {
			struct lfsck_layout *lo = com->lc_file_ram;

			lo->ll_flags |= LF_INCOMPLETE;
			lfsck_tgt_put(ltd);
			break;
		}

		spin_lock(&ltds->ltd_lock);
		if (ltd->ltd_dead || ltd->ltd_layout_done) {
			spin_unlock(&ltds->ltd_lock);
			lfsck_tgt_put(ltd);
			break;
		}

		if (lr->lr_flags & LEF_TO_OST) {
			if (list_empty(&ltd->ltd_layout_list))
				list_add_tail(&ltd->ltd_layout_list,
					      &llmd->llmd_ost_list);
			if (list_empty(&ltd->ltd_layout_phase_list))
				list_add_tail(&ltd->ltd_layout_phase_list,
					      &llmd->llmd_ost_phase1_list);
		} else {
			if (list_empty(&ltd->ltd_layout_list))
				list_add_tail(&ltd->ltd_layout_list,
					      &llmd->llmd_mdt_list);
			if (list_empty(&ltd->ltd_layout_phase_list))
				list_add_tail(&ltd->ltd_layout_phase_list,
					      &llmd->llmd_mdt_phase1_list);
		}
		spin_unlock(&ltds->ltd_lock);
		lfsck_tgt_put(ltd);
		break;
	case LE_STOP:
	case LE_PHASE1_DONE:
	case LE_PHASE2_DONE:
		if (rc != 0)
			CERROR("%s: fail to notify %s %x for layout: "
			       "event = %d, rc = %d\n",
			       lfsck_lfsck2name(com->lc_lfsck),
			       (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
			       ltd->ltd_index, lr->lr_event, rc);
		break;
	case LE_QUERY: {
		struct lfsck_reply *reply;

		if (rc != 0) {
			spin_lock(&ltds->ltd_lock);
			list_del_init(&ltd->ltd_layout_phase_list);
			list_del_init(&ltd->ltd_layout_list);
			spin_unlock(&ltds->ltd_lock);
			lfsck_tgt_put(ltd);
			break;
		}

		reply = req_capsule_server_get(&req->rq_pill,
					       &RMF_LFSCK_REPLY);
		if (reply == NULL) {
			rc = -EPROTO;
			CERROR("%s: invalid return value: rc = %d\n",
			       lfsck_lfsck2name(com->lc_lfsck), rc);
			spin_lock(&ltds->ltd_lock);
			list_del_init(&ltd->ltd_layout_phase_list);
			list_del_init(&ltd->ltd_layout_list);
			spin_unlock(&ltds->ltd_lock);
			lfsck_tgt_put(ltd);
			break;
		}

		switch (reply->lr_status) {
		case LS_SCANNING_PHASE1:
			break;
		case LS_SCANNING_PHASE2:
			spin_lock(&ltds->ltd_lock);
			list_del_init(&ltd->ltd_layout_phase_list);
			if (ltd->ltd_dead || ltd->ltd_layout_done) {
				spin_unlock(&ltds->ltd_lock);
				break;
			}

			if (lr->lr_flags & LEF_TO_OST)
				list_add_tail(&ltd->ltd_layout_phase_list,
					      &llmd->llmd_ost_phase2_list);
			else
				list_add_tail(&ltd->ltd_layout_phase_list,
					      &llmd->llmd_mdt_phase2_list);
			spin_unlock(&ltds->ltd_lock);
			break;
		default:
			spin_lock(&ltds->ltd_lock);
			list_del_init(&ltd->ltd_layout_phase_list);
			list_del_init(&ltd->ltd_layout_list);
			spin_unlock(&ltds->ltd_lock);
			break;
		}
		lfsck_tgt_put(ltd);
		break;
	}
	default:
		CERROR("%s: unexpected event: rc = %d\n",
		       lfsck_lfsck2name(com->lc_lfsck), lr->lr_event);
		break;
	}

	lfsck_component_put(env, com);

	return 0;
}

static int lfsck_layout_master_query_others(const struct lu_env *env,
					    struct lfsck_component *com)
{
	struct lfsck_thread_info	  *info  = lfsck_env_info(env);
	struct lfsck_request		  *lr	 = &info->lti_lr;
	struct lfsck_async_interpret_args *laia  = &info->lti_laia;
	struct lfsck_instance		  *lfsck = com->lc_lfsck;
	struct lfsck_layout_master_data	  *llmd  = com->lc_data;
	struct ptlrpc_request_set	  *set;
	struct lfsck_tgt_descs		  *ltds;
	struct lfsck_tgt_desc		  *ltd;
	struct list_head		  *head;
	__u32				   cnt   = 0;
	int				   rc    = 0;
	int				   rc1   = 0;
	ENTRY;

	set = ptlrpc_prep_set();
	if (set == NULL)
		RETURN(-ENOMEM);

	llmd->llmd_touch_gen++;
	memset(lr, 0, sizeof(*lr));
	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	lr->lr_event = LE_QUERY;
	lr->lr_active = LT_LAYOUT;
	laia->laia_com = com;
	laia->laia_lr = lr;

	if (!list_empty(&llmd->llmd_mdt_phase1_list)) {
		ltds = &lfsck->li_mdt_descs;
		lr->lr_flags = 0;
		head = &llmd->llmd_mdt_phase1_list;
	} else {

again:
		ltds = &lfsck->li_ost_descs;
		lr->lr_flags = LEF_TO_OST;
		head = &llmd->llmd_ost_phase1_list;
	}

	laia->laia_ltds = ltds;
	spin_lock(&ltds->ltd_lock);
	while (!list_empty(head)) {
		ltd = list_entry(head->next,
				 struct lfsck_tgt_desc,
				 ltd_layout_phase_list);
		if (ltd->ltd_layout_gen == llmd->llmd_touch_gen)
			break;

		ltd->ltd_layout_gen = llmd->llmd_touch_gen;
		list_del(&ltd->ltd_layout_phase_list);
		list_add_tail(&ltd->ltd_layout_phase_list, head);
		atomic_inc(&ltd->ltd_ref);
		laia->laia_ltd = ltd;
		spin_unlock(&ltds->ltd_lock);
		rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					 lfsck_layout_master_async_interpret,
					 laia, LFSCK_QUERY);
		if (rc != 0) {
			CERROR("%s: fail to query %s %x for layout: rc = %d\n",
			       lfsck_lfsck2name(lfsck),
			       (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
			       ltd->ltd_index, rc);
			lfsck_tgt_put(ltd);
			rc1 = rc;
		} else {
			cnt++;
		}
		spin_lock(&ltds->ltd_lock);
	}
	spin_unlock(&ltds->ltd_lock);

	if (cnt > 0) {
		rc = ptlrpc_set_wait(set);
		if (rc < 0) {
			ptlrpc_set_destroy(set);
			RETURN(rc);
		}
		cnt = 0;
	}

	if (!(lr->lr_flags & LEF_TO_OST) &&
	    list_empty(&llmd->llmd_mdt_phase1_list))
		goto again;

	ptlrpc_set_destroy(set);

	RETURN(rc1 != 0 ? rc1 : rc);
}

static inline bool
lfsck_layout_master_to_orphan(struct lfsck_layout_master_data *llmd)
{
	return list_empty(&llmd->llmd_mdt_phase1_list) &&
	       (!list_empty(&llmd->llmd_ost_phase2_list) ||
		list_empty(&llmd->llmd_ost_phase1_list));
}

static int lfsck_layout_master_notify_others(const struct lu_env *env,
					     struct lfsck_component *com,
					     struct lfsck_request *lr,
					     __u32 flags)
{
	struct lfsck_thread_info	  *info  = lfsck_env_info(env);
	struct lfsck_async_interpret_args *laia  = &info->lti_laia;
	struct lfsck_instance		  *lfsck = com->lc_lfsck;
	struct lfsck_layout_master_data	  *llmd  = com->lc_data;
	struct lfsck_layout		  *lo	 = com->lc_file_ram;
	struct ptlrpc_request_set	  *set;
	struct lfsck_tgt_descs		  *ltds;
	struct lfsck_tgt_desc		  *ltd;
	struct lfsck_tgt_desc		  *next;
	struct list_head		  *head;
	__u32				   idx;
	__u32				   cnt   = 0;
	int				   rc    = 0;
	ENTRY;

	set = ptlrpc_prep_set();
	if (set == NULL)
		RETURN(-ENOMEM);

	lr->lr_active = LT_LAYOUT;
	laia->laia_com = com;
	laia->laia_lr = lr;
	lr->lr_flags = 0;
	switch (lr->lr_event) {
	case LE_START:
		/* Notify OSTs firstly, then other MDTs if needed. */
		lr->lr_flags |= LEF_TO_OST;
		ltds = &lfsck->li_ost_descs;

lable1:
		laia->laia_ltds = ltds;
		down_read(&ltds->ltd_rw_sem);
		cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
			ltd = lfsck_tgt_get(ltds, idx);
			LASSERT(ltd != NULL);

			laia->laia_ltd = ltd;
			ltd->ltd_layout_done = 0;
			rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					lfsck_layout_master_async_interpret,
					laia, LFSCK_NOTIFY);
			if (rc != 0) {
				CERROR("%s: fail to notify %s %x for layout "
				       "start: rc = %d\n",
				       lfsck_lfsck2name(lfsck),
				       (lr->lr_flags & LEF_TO_OST) ? "OST" :
				       "MDT", idx, rc);
				lfsck_tgt_put(ltd);
				lo->ll_flags |= LF_INCOMPLETE;
			} else {
				cnt++;
			}
		}
		up_read(&ltds->ltd_rw_sem);

		/* Sync up */
		if (cnt > 0) {
			rc = ptlrpc_set_wait(set);
			if (rc < 0) {
				ptlrpc_set_destroy(set);
				RETURN(rc);
			}
			cnt = 0;
		}

		if (!(flags & LPF_ALL_MDT))
			break;

		ltds = &lfsck->li_mdt_descs;
		/* The sponsor broadcasts the request to other MDTs. */
		if (flags & LPF_BROADCAST) {
			flags &= ~LPF_ALL_MDT;
			lr->lr_flags &= ~LEF_TO_OST;
			goto lable1;
		}

		/* non-sponsors link other MDT targets locallly. */
		spin_lock(&ltds->ltd_lock);
		cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
			ltd = LTD_TGT(ltds, idx);
			LASSERT(ltd != NULL);

			if (!list_empty(&ltd->ltd_layout_list))
				continue;

			list_add_tail(&ltd->ltd_layout_list,
				      &llmd->llmd_mdt_list);
			list_add_tail(&ltd->ltd_layout_phase_list,
				      &llmd->llmd_mdt_phase1_list);
		}
		spin_unlock(&ltds->ltd_lock);

		break;
	case LE_STOP:
		if (flags & LPF_BROADCAST)
			lr->lr_flags |= LEF_FORCE_STOP;
	case LE_PHASE2_DONE:
		/* Notify other MDTs if needed, then the OSTs. */
		if (flags & LPF_ALL_MDT) {
			/* The sponsor broadcasts the request to other MDTs. */
			if (flags & LPF_BROADCAST) {
				lr->lr_flags &= ~LEF_TO_OST;
				head = &llmd->llmd_mdt_list;
				ltds = &lfsck->li_mdt_descs;
				goto lable3;
			}

			/* non-sponsors unlink other MDT targets locallly. */
			ltds = &lfsck->li_mdt_descs;
			spin_lock(&ltds->ltd_lock);
			list_for_each_entry_safe(ltd, next,
						 &llmd->llmd_mdt_list,
						 ltd_layout_list) {
				list_del_init(&ltd->ltd_layout_phase_list);
				list_del_init(&ltd->ltd_layout_list);
			}
			spin_unlock(&ltds->ltd_lock);
		}

lable2:
		lr->lr_flags |= LEF_TO_OST;
		head = &llmd->llmd_ost_list;
		ltds = &lfsck->li_ost_descs;

lable3:
		laia->laia_ltds = ltds;
		spin_lock(&ltds->ltd_lock);
		while (!list_empty(head)) {
			ltd = list_entry(head->next, struct lfsck_tgt_desc,
					 ltd_layout_list);
			if (!list_empty(&ltd->ltd_layout_phase_list))
				list_del_init(&ltd->ltd_layout_phase_list);
			list_del_init(&ltd->ltd_layout_list);
			laia->laia_ltd = ltd;
			spin_unlock(&ltds->ltd_lock);
			rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					lfsck_layout_master_async_interpret,
					laia, LFSCK_NOTIFY);
			if (rc != 0)
				CERROR("%s: fail to notify %s %x for layout "
				       "stop/phase2: rc = %d\n",
				       lfsck_lfsck2name(lfsck),
				       (lr->lr_flags & LEF_TO_OST) ? "OST" :
				       "MDT", ltd->ltd_index, rc);
			else
				cnt++;
			spin_lock(&ltds->ltd_lock);
		}
		spin_unlock(&ltds->ltd_lock);

		if (!(flags & LPF_BROADCAST))
			break;

		/* Sync up */
		if (cnt > 0) {
			rc = ptlrpc_set_wait(set);
			if (rc < 0) {
				ptlrpc_set_destroy(set);
				RETURN(rc);
			}
			cnt = 0;
		}

		flags &= ~LPF_BROADCAST;
		goto lable2;
	case LE_PHASE1_DONE:
		llmd->llmd_touch_gen++;
		lr->lr_flags &= ~LEF_TO_OST;
		ltds = &lfsck->li_mdt_descs;
		laia->laia_ltds = ltds;
		spin_lock(&ltds->ltd_lock);
		while (!list_empty(&llmd->llmd_mdt_phase1_list)) {
			ltd = list_entry(llmd->llmd_mdt_phase1_list.next,
					 struct lfsck_tgt_desc,
					 ltd_layout_phase_list);
			if (ltd->ltd_layout_gen == llmd->llmd_touch_gen)
				break;

			ltd->ltd_layout_gen = llmd->llmd_touch_gen;
			list_del_init(&ltd->ltd_layout_phase_list);
			list_add_tail(&ltd->ltd_layout_phase_list,
				      &llmd->llmd_mdt_phase1_list);
			laia->laia_ltd = ltd;
			spin_unlock(&ltds->ltd_lock);
			rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					lfsck_layout_master_async_interpret,
					laia, LFSCK_NOTIFY);
			if (rc != 0)
				CERROR("%s: fail to notify MDT %x for layout "
				       "phase1 done: rc = %d\n",
				       lfsck_lfsck2name(lfsck),
				       ltd->ltd_index, rc);
			else
				cnt++;
			spin_lock(&ltds->ltd_lock);
		}
		spin_unlock(&ltds->ltd_lock);
		break;
	default:
		CERROR("%s: unexpected LFSCK event: rc = %d\n",
		       lfsck_lfsck2name(lfsck), lr->lr_event);
		rc = -EINVAL;
		break;
	}

	if (cnt > 0)
		rc = ptlrpc_set_wait(set);
	ptlrpc_set_destroy(set);

	if (rc == 0 && lr->lr_event == LE_START &&
	    list_empty(&llmd->llmd_ost_list))
		rc = -ENODEV;

	RETURN(rc);
}

static int lfsck_layout_double_scan_result(const struct lu_env *env,
					   struct lfsck_component *com,
					   int rc)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_layout	*lo    = com->lc_file_ram;
	struct lfsck_bookmark	*bk    = &lfsck->li_bookmark_ram;

	down_write(&com->lc_sem);

	lo->ll_run_time_phase2 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
	lo->ll_time_last_checkpoint = cfs_time_current_sec();
	lo->ll_objs_checked_phase2 += com->lc_new_checked;

	if (rc > 0) {
		com->lc_journal = 0;
		if (lo->ll_flags & LF_INCOMPLETE)
			lo->ll_status = LS_PARTIAL;
		else
			lo->ll_status = LS_COMPLETED;
		if (!(bk->lb_param & LPF_DRYRUN))
			lo->ll_flags &= ~(LF_SCANNED_ONCE | LF_INCONSISTENT);
		lo->ll_time_last_complete = lo->ll_time_last_checkpoint;
		lo->ll_success_count++;
	} else if (rc == 0) {
		lo->ll_status = lfsck->li_status;
		if (lo->ll_status == 0)
			lo->ll_status = LS_STOPPED;
	} else {
		lo->ll_status = LS_FAILED;
	}

	if (lo->ll_status != LS_PAUSED) {
		spin_lock(&lfsck->li_lock);
		list_del_init(&com->lc_link);
		list_add_tail(&com->lc_link, &lfsck->li_list_idle);
		spin_unlock(&lfsck->li_lock);
	}

	rc = lfsck_layout_store(env, com);

	up_write(&com->lc_sem);

	return rc;
}

static int lfsck_layout_lock(const struct lu_env *env,
			     struct lfsck_component *com,
			     struct dt_object *obj,
			     struct lustre_handle *lh, __u64 bits)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	ldlm_policy_data_t		*policy = &info->lti_policy;
	struct ldlm_res_id		*resid	= &info->lti_resid;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	__u64				 flags	= LDLM_FL_ATOMIC_CB;
	int				 rc;

	LASSERT(lfsck->li_namespace != NULL);

	memset(policy, 0, sizeof(*policy));
	policy->l_inodebits.bits = bits;
	fid_build_reg_res_name(lfsck_dto2fid(obj), resid);
	rc = ldlm_cli_enqueue_local(lfsck->li_namespace, resid, LDLM_IBITS,
				    policy, LCK_EX, &flags, ldlm_blocking_ast,
				    ldlm_completion_ast, NULL, NULL, 0,
				    LVB_T_NONE, NULL, lh);
	if (rc == ELDLM_OK) {
		rc = 0;
	} else {
		memset(lh, 0, sizeof(*lh));
		rc = -EIO;
	}

	return rc;
}

static void lfsck_layout_unlock(struct lustre_handle *lh)
{
	if (lustre_handle_is_used(lh)) {
		ldlm_lock_decref(lh, LCK_EX);
		memset(lh, 0, sizeof(*lh));
	}
}

static int lfsck_layout_trans_stop(const struct lu_env *env,
				   struct dt_device *dev,
				   struct thandle *handle, int result)
{
	int rc;

	handle->th_result = result;
	rc = dt_trans_stop(env, dev, handle);
	if (rc > 0)
		rc = 0;
	else if (rc == 0)
		rc = 1;

	return rc;
}

static int lfsck_layout_scan_orphan(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct lfsck_tgt_desc *ltd)
{
	/* XXX: To be extended in other patch. */

	return 0;
}

/* For the MDT-object with dangling reference, we need to re-create
 * the missed OST-object with the known FID/owner information. */
static int lfsck_layout_recreate_ostobj(const struct lu_env *env,
					struct lfsck_component *com,
					struct lfsck_layout_req *llr,
					struct lu_attr *la)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct filter_fid		*pfid	= &info->lti_new_pfid;
	struct dt_allocation_hint	*hint	= &info->lti_hint;
	struct dt_object		*parent = llr->llr_parent->llo_obj;
	struct dt_object		*child  = llr->llr_child;
	struct dt_device		*dev	= lfsck_obj2dt_dev(child);
	const struct lu_fid		*tfid	= lu_object_fid(&parent->do_lu);
	struct thandle			*handle;
	struct lu_buf			*buf;
	struct lustre_handle		 lh	= { 0 };
	int				 rc;
	ENTRY;

	CDEBUG(D_LFSCK, "Repair dangling reference for: parent "DFID
	       ", child "DFID", OST-index %u, stripe-index %u, owner %u:%u\n",
	       PFID(lfsck_dto2fid(parent)), PFID(lfsck_dto2fid(child)),
	       llr->llr_ost_idx, llr->llr_lov_idx, la->la_uid, la->la_gid);

	rc = lfsck_layout_lock(env, com, parent, &lh,
			       MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR);
	if (rc != 0)
		RETURN(rc);

	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		GOTO(unlock1, rc = PTR_ERR(handle));

	hint->dah_parent = NULL;
	hint->dah_mode = 0;
	pfid->ff_parent.f_seq = cpu_to_le64(tfid->f_seq);
	pfid->ff_parent.f_oid = cpu_to_le32(tfid->f_oid);
	pfid->ff_parent.f_ver = cpu_to_le32(llr->llr_lov_idx);
	buf = lfsck_buf_get(env, pfid, sizeof(struct filter_fid));

	rc = dt_declare_create(env, child, la, hint, NULL, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_xattr_set(env, child, buf, XATTR_NAME_FID,
				  LU_XATTR_CREATE, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	dt_read_lock(env, parent, 0);
	if (unlikely(lu_object_is_dying(parent->do_lu.lo_header)))
		GOTO(unlock2, rc = 1);

	rc = dt_create(env, child, la, hint, NULL, handle);
	if (rc != 0)
		GOTO(unlock2, rc);

	rc = dt_xattr_set(env, child, buf, XATTR_NAME_FID, LU_XATTR_CREATE,
			  handle, BYPASS_CAPA);

	GOTO(unlock2, rc);

unlock2:
	dt_read_unlock(env, parent);

stop:
	rc = lfsck_layout_trans_stop(env, dev, handle, rc);

unlock1:
	lfsck_layout_unlock(&lh);

	return rc;
}

/* If the OST-object does not recognize the MDT-object as its parent, and
 * there is no other MDT-object claims as its parent, then just trust the
 * given MDT-object as its parent. So update the OST-object filter_fid. */
static int lfsck_layout_repair_unmatched_pair(const struct lu_env *env,
					      struct lfsck_component *com,
					      struct lfsck_layout_req *llr,
					      const struct lu_attr *pla)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct filter_fid		*pfid	= &info->lti_new_pfid;
	struct lu_attr			*tla	= &info->lti_la3;
	struct dt_object		*parent = llr->llr_parent->llo_obj;
	struct dt_object		*child  = llr->llr_child;
	struct dt_device		*dev	= lfsck_obj2dt_dev(child);
	const struct lu_fid		*tfid	= lu_object_fid(&parent->do_lu);
	struct thandle			*handle;
	struct lu_buf			*buf;
	struct lustre_handle		 lh	= { 0 };
	int				 rc;
	ENTRY;

	CDEBUG(D_LFSCK, "Repair unmatched MDT-OST pair for: parent "DFID
	       ", child "DFID", OST-index %u, stripe-index %u, owner %u:%u\n",
	       PFID(lfsck_dto2fid(parent)), PFID(lfsck_dto2fid(child)),
	       llr->llr_ost_idx, llr->llr_lov_idx, pla->la_uid, pla->la_gid);

	rc = lfsck_layout_lock(env, com, parent, &lh,
			       MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR);
	if (rc != 0)
		RETURN(rc);

	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		GOTO(unlock1, rc = PTR_ERR(handle));

	pfid->ff_parent.f_seq = cpu_to_le64(tfid->f_seq);
	pfid->ff_parent.f_oid = cpu_to_le32(tfid->f_oid);
	/* The ff_parent->f_ver is not the real parent fid->f_ver. Instead,
	 * it is the OST-object index in the parent MDT-object layout. */
	pfid->ff_parent.f_ver = cpu_to_le32(llr->llr_lov_idx);
	buf = lfsck_buf_get(env, pfid, sizeof(struct filter_fid));

	rc = dt_declare_xattr_set(env, child, buf, XATTR_NAME_FID, 0, handle);
	if (rc != 0)
		GOTO(stop, rc);

	tla->la_valid = LA_UID | LA_GID;
	tla->la_uid = pla->la_uid;
	tla->la_gid = pla->la_gid;
	rc = dt_declare_attr_set(env, child, tla, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, parent, 0);
	if (unlikely(lu_object_is_dying(parent->do_lu.lo_header)))
		GOTO(unlock2, rc = 1);

	rc = dt_xattr_set(env, child, buf, XATTR_NAME_FID, 0, handle,
			  BYPASS_CAPA);
	if (rc != 0)
		GOTO(unlock2, rc);

	/* Get the latest parent's owner. */
	rc = dt_attr_get(env, parent, tla, BYPASS_CAPA);
	if (rc != 0)
		GOTO(unlock2, rc);

	tla->la_valid = LA_UID | LA_GID;
	rc = dt_attr_set(env, child, tla, handle, BYPASS_CAPA);

	GOTO(unlock2, rc);

unlock2:
	dt_write_unlock(env, parent);

stop:
	rc = lfsck_layout_trans_stop(env, dev, handle, rc);

unlock1:
	lfsck_layout_unlock(&lh);

	return rc;
}

/* If there are more than one MDT-objects claim as the OST-object's parent,
 * and the OST-object only recognizes one of them, then we need to generate
 * new OST-object(s) with new fid(s) for the non-recognized MDT-object(s). */
static int lfsck_layout_repair_multiple_references(const struct lu_env *env,
						   struct lfsck_component *com,
						   struct lfsck_layout_req *llr,
						   struct lu_attr *la,
						   struct lu_buf *buf)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct dt_allocation_hint	*hint	= &info->lti_hint;
	struct dt_object_format 	*dof	= &info->lti_dof;
	struct dt_device		*pdev	= com->lc_lfsck->li_next;
	struct ost_id			*oi	= &info->lti_oi;
	struct dt_object		*parent = llr->llr_parent->llo_obj;
	struct dt_device		*cdev	= lfsck_obj2dt_dev(llr->llr_child);
	struct dt_object		*child	= NULL;
	struct lu_device		*d	= &cdev->dd_lu_dev;
	struct lu_object		*o	= NULL;
	struct thandle			*handle;
	struct lov_mds_md_v1		*lmm;
	struct lov_ost_data_v1		*objs;
	struct lustre_handle		 lh	= { 0 };
	__u32				 magic;
	int				 rc;
	ENTRY;

	CDEBUG(D_LFSCK, "Repair multiple references for: parent "DFID
	       ", OST-index %u, stripe-index %u, owner %u:%u\n",
	       PFID(lfsck_dto2fid(parent)), llr->llr_ost_idx,
	       llr->llr_lov_idx, la->la_uid, la->la_gid);

	rc = lfsck_layout_lock(env, com, parent, &lh,
			       MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR);
	if (rc != 0)
		RETURN(rc);

	handle = dt_trans_create(env, pdev);
	if (IS_ERR(handle))
		GOTO(unlock1, rc = PTR_ERR(handle));

	o = lu_object_anon(env, d, NULL);
	if (IS_ERR(o))
		GOTO(stop, rc = PTR_ERR(o));

	child = container_of(o, struct dt_object, do_lu);
	o = lu_object_locate(o->lo_header, d->ld_type);
	if (unlikely(o == NULL))
		GOTO(stop, rc = -EINVAL);

	child = container_of(o, struct dt_object, do_lu);
	la->la_valid = LA_UID | LA_GID;
	hint->dah_parent = NULL;
	hint->dah_mode = 0;
	dof->dof_type = DFT_REGULAR;
	rc = dt_declare_create(env, child, la, NULL, NULL, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_xattr_set(env, parent, buf, XATTR_NAME_LOV,
				  LU_XATTR_REPLACE, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start(env, pdev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, parent, 0);
	if (unlikely(lu_object_is_dying(parent->do_lu.lo_header)))
		GOTO(unlock2, rc = 0);

	rc = dt_xattr_get(env, parent, buf, XATTR_NAME_LOV, BYPASS_CAPA);
	if (unlikely(rc == 0 || rc == -ENODATA || rc == -ERANGE))
		GOTO(unlock2, rc = 0);

	lmm = buf->lb_buf;
	rc = lfsck_layout_verify_header(lmm);
	if (rc != 0)
		GOTO(unlock2, rc);

	/* Someone change layout during the LFSCK, no need to repair then. */
	if (le16_to_cpu(lmm->lmm_layout_gen) != llr->llr_parent->llo_gen)
		GOTO(unlock2, rc = 0);

	rc = dt_create(env, child, la, hint, dof, handle);
	if (rc != 0)
		GOTO(unlock2, rc);

	/* Currently, we only support LOV_MAGIC_V1/LOV_MAGIC_V3 which has
	 * been verified in lfsck_layout_verify_header() already. If some
	 * new magic introduced in the future, then layout LFSCK needs to
	 * be updated also. */
	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic == LOV_MAGIC_V1) {
		objs = &(lmm->lmm_objects[0]);
	} else {
		LASSERT(magic == LOV_MAGIC_V3);
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
	}

	lmm->lmm_layout_gen = cpu_to_le16(llr->llr_parent->llo_gen + 1);
	fid_to_ostid(lu_object_fid(&child->do_lu), oi);
	ostid_cpu_to_le(oi, &objs[llr->llr_lov_idx].l_ost_oi);
	objs[llr->llr_lov_idx].l_ost_gen = cpu_to_le32(0);
	objs[llr->llr_lov_idx].l_ost_idx = cpu_to_le32(llr->llr_ost_idx);
	rc = dt_xattr_set(env, parent, buf, XATTR_NAME_LOV,
			  LU_XATTR_REPLACE, handle, BYPASS_CAPA);

	GOTO(unlock2, rc = (rc == 0 ? 1 : rc));

unlock2:
	dt_write_unlock(env, parent);

stop:
	if (child != NULL)
		lu_object_put(env, &child->do_lu);

	dt_trans_stop(env, pdev, handle);

unlock1:
	lfsck_layout_unlock(&lh);

	return rc;
}

/* If the MDT-object and the OST-object have different owner information,
 * then trust the MDT-object, because the normal chown/chgrp handle order
 * is from MDT to OST, and it is possible that some chown/chgrp operation
 * is partly done. */
static int lfsck_layout_repair_owner(const struct lu_env *env,
				     struct lfsck_component *com,
				     struct lfsck_layout_req *llr,
				     struct lu_attr *pla)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_attr			*tla	= &info->lti_la3;
	struct dt_object		*parent = llr->llr_parent->llo_obj;
	struct dt_object		*child  = llr->llr_child;
	struct dt_device		*dev	= lfsck_obj2dt_dev(child);
	struct thandle			*handle;
	int				 rc;
	ENTRY;

	CDEBUG(D_LFSCK, "Repair inconsistent file owner for: parent "DFID
	       ", child "DFID", OST-index %u, stripe-index %u, owner %u:%u\n",
	       PFID(lfsck_dto2fid(parent)), PFID(lfsck_dto2fid(child)),
	       llr->llr_ost_idx, llr->llr_lov_idx, pla->la_uid, pla->la_gid);

	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	tla->la_uid = pla->la_uid;
	tla->la_gid = pla->la_gid;
	tla->la_valid = LA_UID | LA_GID;
	rc = dt_declare_attr_set(env, child, tla, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	/* Use the dt_object lock to serialize with destroy and attr_set. */
	dt_read_lock(env, parent, 0);
	if (unlikely(lu_object_is_dying(parent->do_lu.lo_header)))
		GOTO(unlock, rc = 1);

	/* Get the latest parent's owner. */
	rc = dt_attr_get(env, parent, tla, BYPASS_CAPA);
	if (rc != 0) {
		CWARN("%s: fail to get the latest parent's ("DFID") owner, "
		      "not sure whether some others chown/chgrp during the "
		      "LFSCK: rc = %d\n", lfsck_lfsck2name(com->lc_lfsck),
		      PFID(lfsck_dto2fid(parent)), rc);

		GOTO(unlock, rc);
	}

	/* Some others chown/chgrp during the LFSCK, needs to do nothing. */
	if (unlikely(tla->la_uid != pla->la_uid ||
		     tla->la_gid != pla->la_gid))
		GOTO(unlock, rc = 1);

	tla->la_valid = LA_UID | LA_GID;
	rc = dt_attr_set(env, child, tla, handle, BYPASS_CAPA);

	GOTO(unlock, rc);

unlock:
	dt_read_unlock(env, parent);

stop:
	rc = lfsck_layout_trans_stop(env, dev, handle, rc);

	return rc;
}

/* Check whether the OST-object correctly back points to the
 * MDT-object (@parent) via the XATTR_NAME_FID xattr (@pfid). */
static int lfsck_layout_check_parent(const struct lu_env *env,
				     struct lfsck_component *com,
				     struct dt_object *parent,
				     const struct lu_fid *pfid,
				     const struct lu_fid *cfid,
				     const struct lu_attr *pla,
				     const struct lu_attr *cla,
				     struct lfsck_layout_req *llr,
				     struct lu_buf *lov_ea, __u32 idx)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_buf			*buf	= &info->lti_big_buf;
	struct dt_object		*tobj;
	struct lov_mds_md_v1		*lmm;
	struct lov_ost_data_v1		*objs;
	int				 rc;
	int				 i;
	__u32				 magic;
	__u16				 count;
	ENTRY;

	if (fid_is_zero(pfid)) {
		/* client never wrote. */
		if (cla->la_size == 0 && cla->la_blocks == 0) {
			if (unlikely(cla->la_uid != pla->la_uid ||
				     cla->la_gid != pla->la_gid))
				RETURN (LLIT_INCONSISTENT_OWNER);

			RETURN(0);
		}

		RETURN(LLIT_UNMATCHED_PAIR);
	}

	if (unlikely(!fid_is_sane(pfid)))
		RETURN(LLIT_UNMATCHED_PAIR);

	if (lu_fid_eq(pfid, lu_object_fid(&parent->do_lu))) {
		if (llr->llr_lov_idx == idx)
			RETURN(0);

		RETURN(LLIT_UNMATCHED_PAIR);
	}

	tobj = lfsck_object_find(env, com->lc_lfsck, pfid);
	if (tobj == NULL)
		RETURN(LLIT_UNMATCHED_PAIR);

	if (IS_ERR(tobj))
		RETURN(PTR_ERR(tobj));

	if (!dt_object_exists(tobj))
		GOTO(out, rc = LLIT_UNMATCHED_PAIR);

	/* Load the tobj's layout EA, in spite of it is a local MDT-object or
	 * remote one on another MDT. Then check whether the given OST-object
	 * is in such layout. If yes, it is multiple referenced, otherwise it
	 * is unmatched referenced case. */
	rc = lfsck_layout_get_lovea(env, tobj, buf, NULL);
	if (rc == 0)
		GOTO(out, rc = LLIT_UNMATCHED_PAIR);

	if (rc < 0)
		GOTO(out, rc);

	lmm = buf->lb_buf;
	rc = lfsck_layout_verify_header(lmm);
	if (rc != 0)
		GOTO(out, rc);

	/* Currently, we only support LOV_MAGIC_V1/LOV_MAGIC_V3 which has
	 * been verified in lfsck_layout_verify_header() already. If some
	 * new magic introduced in the future, then layout LFSCK needs to
	 * be updated also. */
	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic == LOV_MAGIC_V1) {
		objs = &(lmm->lmm_objects[0]);
	} else {
		LASSERT(magic == LOV_MAGIC_V3);
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
	}

	count = le16_to_cpu(lmm->lmm_stripe_count);
	for (i = 0; i < count; i++, objs++) {
		struct lu_fid		*tfid	= &info->lti_fid2;
		struct ost_id		*oi	= &info->lti_oi;

		ostid_le_to_cpu(&objs->l_ost_oi, oi);
		ostid_to_fid(tfid, oi, le32_to_cpu(objs->l_ost_idx));
		if (lu_fid_eq(cfid, tfid)) {
			*lov_ea = *buf;

			GOTO(out, rc = LLIT_MULTIPLE_REFERENCED);
		}
	}

	GOTO(out, rc = LLIT_UNMATCHED_PAIR);

out:
	lfsck_object_put(env, tobj);

	return rc;
}

static int lfsck_layout_assistant_handle_one(const struct lu_env *env,
					     struct lfsck_component *com,
					     struct lfsck_layout_req *llr)
{
	struct lfsck_layout		     *lo     = com->lc_file_ram;
	struct lfsck_thread_info	     *info   = lfsck_env_info(env);
	struct filter_fid_old		     *pea    = &info->lti_old_pfid;
	struct lu_fid			     *pfid   = &info->lti_fid;
	struct lu_buf			     *buf    = NULL;
	struct dt_object		     *parent = llr->llr_parent->llo_obj;
	struct dt_object		     *child  = llr->llr_child;
	struct lu_attr			     *pla    = &info->lti_la;
	struct lu_attr			     *cla    = &info->lti_la2;
	struct lfsck_instance		     *lfsck  = com->lc_lfsck;
	struct lfsck_bookmark		     *bk     = &lfsck->li_bookmark_ram;
	enum lfsck_layout_inconsistency_type  type   = LLIT_NONE;
	__u32				      idx    = 0;
	int				      rc;
	ENTRY;

	rc = dt_attr_get(env, parent, pla, BYPASS_CAPA);
	if (rc != 0) {
		if (lu_object_is_dying(parent->do_lu.lo_header))
			RETURN(0);

		GOTO(out, rc);
	}

	rc = dt_attr_get(env, child, cla, BYPASS_CAPA);
	if (rc == -ENOENT) {
		if (lu_object_is_dying(parent->do_lu.lo_header))
			RETURN(0);

		type = LLIT_DANGLING;
		goto repair;
	}

	if (rc != 0)
		GOTO(out, rc);

	buf = lfsck_buf_get(env, pea, sizeof(struct filter_fid_old));
	rc= dt_xattr_get(env, child, buf, XATTR_NAME_FID, BYPASS_CAPA);
	if (unlikely(rc >= 0 && rc != sizeof(struct filter_fid_old) &&
		     rc != sizeof(struct filter_fid))) {
		type = LLIT_UNMATCHED_PAIR;
		goto repair;
	}

	if (rc < 0 && rc != -ENODATA)
		GOTO(out, rc);

	if (rc == -ENODATA) {
		fid_zero(pfid);
	} else {
		fid_le_to_cpu(pfid, &pea->ff_parent);
		/* OST-object does not save parent FID::f_ver, instead,
		 * the OST-object index in the parent MDT-object layout
		 * EA reuses the pfid->f_ver. */
		idx = pfid->f_ver;
		pfid->f_ver = 0;
	}

	rc = lfsck_layout_check_parent(env, com, parent, pfid,
				       lu_object_fid(&child->do_lu),
				       pla, cla, llr, buf, idx);
	if (rc > 0) {
		type = rc;
		goto repair;
	}

	if (rc < 0)
		GOTO(out, rc);

	if (unlikely(cla->la_uid != pla->la_uid ||
		     cla->la_gid != pla->la_gid)) {
		type = LLIT_INCONSISTENT_OWNER;
		goto repair;
	}

repair:
	if (bk->lb_param & LPF_DRYRUN) {
		if (type != LLIT_NONE)
			GOTO(out, rc = 1);
		else
			GOTO(out, rc = 0);
	}

	switch (type) {
	case LLIT_DANGLING:
		memset(cla, 0, sizeof(*cla));
		cla->la_uid = pla->la_uid;
		cla->la_gid = pla->la_gid;
		cla->la_mode = S_IFREG | 0666;
		cla->la_valid = LA_TYPE | LA_MODE | LA_UID | LA_GID |
				LA_ATIME | LA_MTIME | LA_CTIME;
		rc = lfsck_layout_recreate_ostobj(env, com, llr, cla);
		break;
	case LLIT_UNMATCHED_PAIR:
		rc = lfsck_layout_repair_unmatched_pair(env, com, llr, pla);
		break;
	case LLIT_MULTIPLE_REFERENCED:
		rc = lfsck_layout_repair_multiple_references(env, com, llr,
							     pla, buf);
		break;
	case LLIT_INCONSISTENT_OWNER:
		rc = lfsck_layout_repair_owner(env, com, llr, pla);
		break;
	default:
		rc = 0;
		break;
	}

	GOTO(out, rc);

out:
	down_write(&com->lc_sem);
	if (rc < 0) {
		/* If cannot touch the target server,
		 * mark the LFSCK as INCOMPLETE. */
		if (rc == -ENOTCONN || rc == -ESHUTDOWN || rc == -ETIMEDOUT ||
		    rc == -EHOSTDOWN || rc == -EHOSTUNREACH) {
			lo->ll_flags |= LF_INCOMPLETE;
			lo->ll_objs_skipped++;
			rc = 0;
		} else {
			lo->ll_objs_failed_phase1++;
		}
	} else if (rc > 0) {
		LASSERTF(type > LLIT_NONE && type <= LLIT_MAX,
			 "unknown type = %d\n", type);

		lo->ll_objs_repaired[type - 1]++;
	}
	up_write(&com->lc_sem);

	return rc;
}

static int lfsck_layout_assistant(void *args)
{
	struct lfsck_thread_args	*lta	 = args;
	struct lu_env			*env	 = &lta->lta_env;
	struct lfsck_component		*com     = lta->lta_com;
	struct lfsck_instance		*lfsck   = lta->lta_lfsck;
	struct lfsck_bookmark		*bk	 = &lfsck->li_bookmark_ram;
	struct lfsck_position		*pos	 = &com->lc_pos_start;
	struct lfsck_thread_info	*info	 = lfsck_env_info(env);
	struct lfsck_request		*lr	 = &info->lti_lr;
	struct lfsck_layout_master_data *llmd    = com->lc_data;
	struct ptlrpc_thread		*mthread = &lfsck->li_thread;
	struct ptlrpc_thread		*athread = &llmd->llmd_thread;
	struct lfsck_layout_req		*llr;
	struct l_wait_info		 lwi     = { 0 };
	int				 rc	 = 0;
	int				 rc1	 = 0;
	__u32				 flags;
	ENTRY;

	if (lta->lta_lsp->lsp_start != NULL)
		flags  = lta->lta_lsp->lsp_start->ls_flags;
	else
		flags = bk->lb_param;
	memset(lr, 0, sizeof(*lr));
	lr->lr_event = LE_START;
	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	lr->lr_valid = LSV_SPEED_LIMIT | LSV_ERROR_HANDLE | LSV_DRYRUN |
		       LSV_ASYNC_WINDOWS;
	lr->lr_speed = bk->lb_speed_limit;
	lr->lr_version = bk->lb_version;
	lr->lr_param = bk->lb_param;
	lr->lr_async_windows = bk->lb_async_windows;
	if (pos->lp_oit_cookie <= 1)
		lr->lr_param |= LPF_RESET;

	rc = lfsck_layout_master_notify_others(env, com, lr, flags);
	if (rc != 0) {
		CERROR("%s: fail to notify others for layout start: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);
		GOTO(fini, rc);
	}

	spin_lock(&llmd->llmd_lock);
	thread_set_flags(athread, SVC_RUNNING);
	spin_unlock(&llmd->llmd_lock);
	wake_up_all(&mthread->t_ctl_waitq);

	while (1) {
		while (!list_empty(&llmd->llmd_req_list)) {
			bool wakeup = false;

			if (unlikely(llmd->llmd_exit))
				GOTO(cleanup1, rc = llmd->llmd_post_result);

			llr = list_entry(llmd->llmd_req_list.next,
					 struct lfsck_layout_req,
					 llr_list);
			/* Only the lfsck_layout_assistant thread itself can
			 * remove the "llr" from the head of the list, LFSCK
			 * engine thread only inserts other new "lld" at the
			 * end of the list. So it is safe to handle current
			 * "llr" without the spin_lock. */
			rc = lfsck_layout_assistant_handle_one(env, com, llr);
			spin_lock(&llmd->llmd_lock);
			list_del_init(&llr->llr_list);
			if (bk->lb_async_windows != 0 &&
			    llmd->llmd_prefetched >= bk->lb_async_windows)
				wakeup = true;

			llmd->llmd_prefetched--;
			spin_unlock(&llmd->llmd_lock);
			if (wakeup)
				wake_up_all(&mthread->t_ctl_waitq);

			lfsck_layout_req_fini(env, llr);
			if (rc < 0 && bk->lb_param & LPF_FAILOUT)
				GOTO(cleanup1, rc);
		}

		/* Wakeup the master engine if it is waiting in checkpoint. */
		wake_up_all(&mthread->t_ctl_waitq);

		l_wait_event(athread->t_ctl_waitq,
			     !lfsck_layout_req_empty(llmd) ||
			     llmd->llmd_exit ||
			     llmd->llmd_to_post ||
			     llmd->llmd_to_double_scan,
			     &lwi);

		if (unlikely(llmd->llmd_exit))
			GOTO(cleanup1, rc = llmd->llmd_post_result);

		if (!list_empty(&llmd->llmd_req_list))
			continue;

		if (llmd->llmd_to_post) {
			llmd->llmd_to_post = 0;
			LASSERT(llmd->llmd_post_result > 0);

			memset(lr, 0, sizeof(*lr));
			lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
			lr->lr_event = LE_PHASE1_DONE;
			lr->lr_status = llmd->llmd_post_result;
			rc = lfsck_layout_master_notify_others(env, com, lr, 0);
			if (rc != 0)
				CERROR("%s: failed to notify others "
				       "for layout post: rc = %d\n",
				       lfsck_lfsck2name(lfsck), rc);

			/* Wakeup the master engine to go ahead. */
			wake_up_all(&mthread->t_ctl_waitq);
		}

		if (llmd->llmd_to_double_scan) {
			llmd->llmd_to_double_scan = 0;
			atomic_inc(&lfsck->li_double_scan_count);
			llmd->llmd_in_double_scan = 1;
			wake_up_all(&mthread->t_ctl_waitq);

			while (llmd->llmd_in_double_scan) {
				struct lfsck_tgt_descs	*ltds =
							&lfsck->li_ost_descs;
				struct lfsck_tgt_desc	*ltd;

				rc = lfsck_layout_master_query_others(env, com);
				if (lfsck_layout_master_to_orphan(llmd))
					goto orphan;

				if (rc < 0)
					GOTO(cleanup2, rc);

				/* Pull LFSCK status on related targets once
				 * per 30 seconds if we are not notified. */
				lwi = LWI_TIMEOUT_INTERVAL(cfs_time_seconds(30),
							   cfs_time_seconds(1),
							   NULL, NULL);
				rc = l_wait_event(athread->t_ctl_waitq,
					lfsck_layout_master_to_orphan(llmd) ||
					llmd->llmd_exit ||
					!thread_is_running(mthread),
					&lwi);

				if (unlikely(llmd->llmd_exit ||
					     !thread_is_running(mthread)))
					GOTO(cleanup2, rc = 0);

				if (rc == -ETIMEDOUT)
					continue;

				if (rc < 0)
					GOTO(cleanup2, rc);

orphan:
				spin_lock(&ltds->ltd_lock);
				while (!list_empty(
						&llmd->llmd_ost_phase2_list)) {
					ltd = list_entry(
					      llmd->llmd_ost_phase2_list.next,
					      struct lfsck_tgt_desc,
					      ltd_layout_phase_list);
					list_del_init(
						&ltd->ltd_layout_phase_list);
					spin_unlock(&ltds->ltd_lock);

					rc = lfsck_layout_scan_orphan(env, com,
								      ltd);
					if (rc != 0 &&
					    bk->lb_param & LPF_FAILOUT)
						GOTO(cleanup2, rc);

					if (unlikely(llmd->llmd_exit ||
						!thread_is_running(mthread)))
						GOTO(cleanup2, rc = 0);

					spin_lock(&ltds->ltd_lock);
				}

				if (list_empty(&llmd->llmd_ost_phase1_list)) {
					spin_unlock(&ltds->ltd_lock);
					GOTO(cleanup2, rc = 1);
				}
				spin_unlock(&ltds->ltd_lock);
			}
		}
	}

cleanup1:
	/* Cleanup the unfinished requests. */
	spin_lock(&llmd->llmd_lock);
	if (rc < 0)
		llmd->llmd_assistant_status = rc;

	while (!list_empty(&llmd->llmd_req_list)) {
		llr = list_entry(llmd->llmd_req_list.next,
				 struct lfsck_layout_req,
				 llr_list);
		list_del_init(&llr->llr_list);
		llmd->llmd_prefetched--;
		spin_unlock(&llmd->llmd_lock);
		lfsck_layout_req_fini(env, llr);
		spin_lock(&llmd->llmd_lock);
	}
	spin_unlock(&llmd->llmd_lock);

	LASSERTF(llmd->llmd_prefetched == 0, "unmatched prefeteched objs %d\n",
		 llmd->llmd_prefetched);

cleanup2:
	memset(lr, 0, sizeof(*lr));
	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	if (rc > 0) {
		lr->lr_event = LE_PHASE2_DONE;
		flags = 0;
		lr->lr_status = rc;
	} else if (rc == 0) {
		lr->lr_event = LE_STOP;
		if (lfsck->li_status == LS_PAUSED ||
		    lfsck->li_status == LS_CO_PAUSED) {
			flags = 0;
			lr->lr_status = LS_CO_PAUSED;
		} else if (lfsck->li_status == LS_STOPPED ||
			 lfsck->li_status == LS_CO_STOPPED) {
			flags = lfsck->li_flags;
			if (flags & LPF_BROADCAST)
				lr->lr_status = LS_STOPPED;
			else
				lr->lr_status = LS_CO_STOPPED;
		} else {
			LBUG();
		}
	} else {
		lr->lr_event = LE_STOP;
		flags = 0;
		lr->lr_status = LS_CO_FAILED;
	}

	rc1 = lfsck_layout_master_notify_others(env, com, lr, flags);
	if (rc1 != 0) {
		CERROR("%s: failed to notify others for layout quit: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc1);
		rc = rc1;
	}

	/* Under force exit case, some requests may be just freed without
	 * verification, those objects should be re-handled when next run.
	 * So not update the on-disk tracing file under such case. */
	if (!llmd->llmd_exit)
		rc1 = lfsck_layout_double_scan_result(env, com, rc);

fini:
	if (llmd->llmd_in_double_scan)
		atomic_dec(&lfsck->li_double_scan_count);

	spin_lock(&llmd->llmd_lock);
	llmd->llmd_assistant_status = (rc1 != 0 ? rc1 : rc);
	thread_set_flags(athread, SVC_STOPPED);
	wake_up_all(&mthread->t_ctl_waitq);
	spin_unlock(&llmd->llmd_lock);
	lfsck_thread_args_fini(lta);

	return rc;
}

static int
lfsck_layout_slave_async_interpret(const struct lu_env *env,
				   struct ptlrpc_request *req,
				   void *args, int rc)
{
	struct lfsck_layout_slave_async_args *llsaa = args;
	struct obd_export		     *exp   = llsaa->llsaa_exp;
	struct lfsck_component		     *com   = llsaa->llsaa_com;
	struct lfsck_layout_slave_target     *llst  = llsaa->llsaa_llst;
	struct lfsck_layout_slave_data	     *llsd  = com->lc_data;
	bool				      done  = false;

	if (rc != 0) {
		/* It is quite probably caused by target crash,
		 * to make the LFSCK can go ahead, assume that
		 * the target finished the LFSCK prcoessing. */
		done = true;
	} else {
		struct lfsck_reply *lr;

		lr = req_capsule_server_get(&req->rq_pill, &RMF_LFSCK_REPLY);
		if (lr->lr_status != LS_SCANNING_PHASE1 &&
		    lr->lr_status != LS_SCANNING_PHASE2)
			done = true;
	}
	if (done)
		lfsck_layout_llst_del(llsd, llst);
	lfsck_layout_llst_put(llst);
	lfsck_component_put(env, com);
	class_export_put(exp);

	return 0;
}

static int lfsck_layout_async_query(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct obd_export *exp,
				    struct lfsck_layout_slave_target *llst,
				    struct lfsck_request *lr,
				    struct ptlrpc_request_set *set)
{
	struct lfsck_layout_slave_async_args *llsaa;
	struct ptlrpc_request		     *req;
	struct lfsck_request		     *tmp;
	int				      rc;
	ENTRY;

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_LFSCK_QUERY);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OBD_VERSION, LFSCK_QUERY);
	if (rc != 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_LFSCK_REQUEST);
	*tmp = *lr;
	ptlrpc_request_set_replen(req);

	llsaa = ptlrpc_req_async_args(req);
	llsaa->llsaa_exp = exp;
	llsaa->llsaa_com = lfsck_component_get(com);
	llsaa->llsaa_llst = llst;
	req->rq_interpret_reply = lfsck_layout_slave_async_interpret;
	ptlrpc_set_add_req(set, req);

	RETURN(0);
}

static int lfsck_layout_async_notify(const struct lu_env *env,
				     struct obd_export *exp,
				     struct lfsck_request *lr,
				     struct ptlrpc_request_set *set)
{
	struct ptlrpc_request	*req;
	struct lfsck_request	*tmp;
	int			 rc;
	ENTRY;

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_LFSCK_NOTIFY);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OBD_VERSION, LFSCK_NOTIFY);
	if (rc != 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_LFSCK_REQUEST);
	*tmp = *lr;
	ptlrpc_request_set_replen(req);
	ptlrpc_set_add_req(set, req);

	RETURN(0);
}

static int
lfsck_layout_slave_query_master(const struct lu_env *env,
				struct lfsck_component *com)
{
	struct lfsck_request		 *lr    = &lfsck_env_info(env)->lti_lr;
	struct lfsck_instance		 *lfsck = com->lc_lfsck;
	struct lfsck_layout_slave_data	 *llsd  = com->lc_data;
	struct lfsck_layout_slave_target *llst;
	struct obd_export		 *exp;
	struct ptlrpc_request_set	 *set;
	int				  cnt   = 0;
	int				  rc    = 0;
	int				  rc1   = 0;
	ENTRY;

	set = ptlrpc_prep_set();
	if (set == NULL)
		RETURN(-ENOMEM);

	memset(lr, 0, sizeof(*lr));
	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	lr->lr_event = LE_QUERY;
	lr->lr_active = LT_LAYOUT;

	llsd->llsd_touch_gen++;
	spin_lock(&llsd->llsd_lock);
	while (!list_empty(&llsd->llsd_master_list)) {
		llst = list_entry(llsd->llsd_master_list.next,
				  struct lfsck_layout_slave_target,
				  llst_list);
		if (llst->llst_gen == llsd->llsd_touch_gen)
			break;

		llst->llst_gen = llsd->llsd_touch_gen;
		list_del(&llst->llst_list);
		list_add_tail(&llst->llst_list,
			      &llsd->llsd_master_list);
		atomic_inc(&llst->llst_ref);
		spin_unlock(&llsd->llsd_lock);

		exp = lustre_find_lwp_by_index(lfsck->li_obd->obd_name,
					       llst->llst_index);
		if (exp == NULL) {
			lfsck_layout_llst_del(llsd, llst);
			lfsck_layout_llst_put(llst);
			spin_lock(&llsd->llsd_lock);
			continue;
		}

		rc = lfsck_layout_async_query(env, com, exp, llst, lr, set);
		if (rc != 0) {
			CERROR("%s: slave fail to query %s for layout: "
			       "rc = %d\n", lfsck_lfsck2name(lfsck),
			       exp->exp_obd->obd_name, rc);
			rc1 = rc;
			lfsck_layout_llst_put(llst);
			class_export_put(exp);
		} else {
			cnt++;
		}
		spin_lock(&llsd->llsd_lock);
	}
	spin_unlock(&llsd->llsd_lock);

	if (cnt > 0)
		rc = ptlrpc_set_wait(set);
	ptlrpc_set_destroy(set);

	RETURN(rc1 != 0 ? rc1 : rc);
}

static void
lfsck_layout_slave_notify_master(const struct lu_env *env,
				 struct lfsck_component *com,
				 enum lfsck_events event, int result)
{
	struct lfsck_instance		 *lfsck = com->lc_lfsck;
	struct lfsck_layout_slave_data	 *llsd  = com->lc_data;
	struct lfsck_request		 *lr    = &lfsck_env_info(env)->lti_lr;
	struct lfsck_layout_slave_target *llst;
	struct obd_export		 *exp;
	struct ptlrpc_request_set	 *set;
	int				  cnt   = 0;
	int				  rc;
	ENTRY;

	set = ptlrpc_prep_set();
	if (set == NULL)
		RETURN_EXIT;

	memset(lr, 0, sizeof(*lr));
	lr->lr_event = event;
	lr->lr_flags = LEF_FROM_OST;
	lr->lr_status = result;
	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	lr->lr_active = LT_LAYOUT;
	llsd->llsd_touch_gen++;
	spin_lock(&llsd->llsd_lock);
	while (!list_empty(&llsd->llsd_master_list)) {
		llst = list_entry(llsd->llsd_master_list.next,
				  struct lfsck_layout_slave_target,
				  llst_list);
		if (llst->llst_gen == llsd->llsd_touch_gen)
			break;

		llst->llst_gen = llsd->llsd_touch_gen;
		list_del(&llst->llst_list);
		list_add_tail(&llst->llst_list,
			      &llsd->llsd_master_list);
		atomic_inc(&llst->llst_ref);
		spin_unlock(&llsd->llsd_lock);

		exp = lustre_find_lwp_by_index(lfsck->li_obd->obd_name,
					       llst->llst_index);
		if (exp == NULL) {
			lfsck_layout_llst_del(llsd, llst);
			lfsck_layout_llst_put(llst);
			spin_lock(&llsd->llsd_lock);
			continue;
		}

		rc = lfsck_layout_async_notify(env, exp, lr, set);
		if (rc != 0)
			CERROR("%s: slave fail to notify %s for layout: "
			       "rc = %d\n", lfsck_lfsck2name(lfsck),
			       exp->exp_obd->obd_name, rc);
		else
			cnt++;
		lfsck_layout_llst_put(llst);
		class_export_put(exp);
		spin_lock(&llsd->llsd_lock);
	}
	spin_unlock(&llsd->llsd_lock);

	if (cnt > 0)
		rc = ptlrpc_set_wait(set);

	ptlrpc_set_destroy(set);

	RETURN_EXIT;
}

/* layout APIs */

static int lfsck_layout_reset(const struct lu_env *env,
			      struct lfsck_component *com, bool init)
{
	struct lfsck_layout	*lo    = com->lc_file_ram;
	int			 rc;

	down_write(&com->lc_sem);
	if (init) {
		memset(lo, 0, com->lc_file_size);
	} else {
		__u32 count = lo->ll_success_count;
		__u64 last_time = lo->ll_time_last_complete;

		memset(lo, 0, com->lc_file_size);
		lo->ll_success_count = count;
		lo->ll_time_last_complete = last_time;
	}

	lo->ll_magic = LFSCK_LAYOUT_MAGIC;
	lo->ll_status = LS_INIT;

	rc = lfsck_layout_store(env, com);
	up_write(&com->lc_sem);

	return rc;
}

static void lfsck_layout_fail(const struct lu_env *env,
			      struct lfsck_component *com, bool new_checked)
{
	struct lfsck_layout *lo = com->lc_file_ram;

	down_write(&com->lc_sem);
	if (new_checked)
		com->lc_new_checked++;
	lo->ll_objs_failed_phase1++;
	if (lo->ll_pos_first_inconsistent == 0) {
		struct lfsck_instance *lfsck = com->lc_lfsck;

		lo->ll_pos_first_inconsistent =
			lfsck->li_obj_oit->do_index_ops->dio_it.store(env,
							lfsck->li_di_oit);
	}
	up_write(&com->lc_sem);
}

static int lfsck_layout_master_checkpoint(const struct lu_env *env,
					  struct lfsck_component *com, bool init)
{
	struct lfsck_instance		*lfsck	 = com->lc_lfsck;
	struct lfsck_layout		*lo	 = com->lc_file_ram;
	struct lfsck_layout_master_data *llmd	 = com->lc_data;
	struct ptlrpc_thread		*mthread = &lfsck->li_thread;
	struct ptlrpc_thread		*athread = &llmd->llmd_thread;
	struct l_wait_info		 lwi	 = { 0 };
	int				 rc;

	if (com->lc_new_checked == 0 && !init)
		return 0;

	l_wait_event(mthread->t_ctl_waitq,
		     list_empty(&llmd->llmd_req_list) ||
		     !thread_is_running(mthread) ||
		     thread_is_stopped(athread),
		     &lwi);

	if (!thread_is_running(mthread) || thread_is_stopped(athread))
		return 0;

	down_write(&com->lc_sem);
	if (init) {
		lo->ll_pos_latest_start = lfsck->li_pos_current.lp_oit_cookie;
	} else {
		lo->ll_pos_last_checkpoint =
					lfsck->li_pos_current.lp_oit_cookie;
		lo->ll_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
		lo->ll_time_last_checkpoint = cfs_time_current_sec();
		lo->ll_objs_checked_phase1 += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_layout_store(env, com);
	up_write(&com->lc_sem);

	return rc;
}

static int lfsck_layout_slave_checkpoint(const struct lu_env *env,
					 struct lfsck_component *com, bool init)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_layout	*lo    = com->lc_file_ram;
	int			 rc;

	if (com->lc_new_checked == 0 && !init)
		return 0;

	down_write(&com->lc_sem);

	if (init) {
		lo->ll_pos_latest_start = lfsck->li_pos_current.lp_oit_cookie;
	} else {
		lo->ll_pos_last_checkpoint =
					lfsck->li_pos_current.lp_oit_cookie;
		lo->ll_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
		lo->ll_time_last_checkpoint = cfs_time_current_sec();
		lo->ll_objs_checked_phase1 += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_layout_store(env, com);

	up_write(&com->lc_sem);

	return rc;
}

static int lfsck_layout_prep(const struct lu_env *env,
			     struct lfsck_component *com)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_layout	*lo	= com->lc_file_ram;
	struct lfsck_position	*pos	= &com->lc_pos_start;

	fid_zero(&pos->lp_dir_parent);
	pos->lp_dir_cookie = 0;
	if (lo->ll_status == LS_COMPLETED ||
	    lo->ll_status == LS_PARTIAL) {
		int rc;

		rc = lfsck_layout_reset(env, com, false);
		if (rc != 0)
			return rc;
	}

	down_write(&com->lc_sem);

	lo->ll_time_latest_start = cfs_time_current_sec();

	spin_lock(&lfsck->li_lock);
	if (lo->ll_flags & LF_SCANNED_ONCE) {
		if (!lfsck->li_drop_dryrun ||
		    lo->ll_pos_first_inconsistent == 0) {
			lo->ll_status = LS_SCANNING_PHASE2;
			list_del_init(&com->lc_link);
			list_add_tail(&com->lc_link,
				      &lfsck->li_list_double_scan);
			pos->lp_oit_cookie = 0;
		} else {
			int i;

			lo->ll_status = LS_SCANNING_PHASE1;
			lo->ll_run_time_phase1 = 0;
			lo->ll_run_time_phase2 = 0;
			lo->ll_objs_checked_phase1 = 0;
			lo->ll_objs_checked_phase2 = 0;
			lo->ll_objs_failed_phase1 = 0;
			lo->ll_objs_failed_phase2 = 0;
			for (i = 0; i < LLIT_MAX; i++)
				lo->ll_objs_repaired[i] = 0;

			pos->lp_oit_cookie = lo->ll_pos_first_inconsistent;
		}
	} else {
		lo->ll_status = LS_SCANNING_PHASE1;
		if (!lfsck->li_drop_dryrun ||
		    lo->ll_pos_first_inconsistent == 0)
			pos->lp_oit_cookie = lo->ll_pos_last_checkpoint + 1;
		else
			pos->lp_oit_cookie = lo->ll_pos_first_inconsistent;
	}
	spin_unlock(&lfsck->li_lock);

	up_write(&com->lc_sem);

	return 0;
}

static int lfsck_layout_slave_prep(const struct lu_env *env,
				   struct lfsck_component *com,
				   struct lfsck_start_param *lsp)
{
	struct lfsck_layout		*lo	= com->lc_file_ram;
	struct lfsck_layout_slave_data	*llsd	= com->lc_data;
	int				 rc;

	/* XXX: For a new scanning, generate OST-objects
	 *	bitmap for orphan detection. */

	rc = lfsck_layout_prep(env, com);
	if (rc != 0 || lo->ll_status != LS_SCANNING_PHASE1 ||
	    !lsp->lsp_index_valid)
		return rc;

	rc = lfsck_layout_llst_add(llsd, lsp->lsp_index);

	return rc;
}

static int lfsck_layout_master_prep(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct lfsck_start_param *lsp)
{
	struct lfsck_instance		*lfsck   = com->lc_lfsck;
	struct lfsck_layout_master_data *llmd    = com->lc_data;
	struct ptlrpc_thread		*mthread = &lfsck->li_thread;
	struct ptlrpc_thread		*athread = &llmd->llmd_thread;
	struct lfsck_thread_args	*lta;
	long				 rc;
	ENTRY;

	rc = lfsck_layout_prep(env, com);
	if (rc != 0)
		RETURN(rc);

	llmd->llmd_assistant_status = 0;
	llmd->llmd_post_result = 0;
	llmd->llmd_to_post = 0;
	llmd->llmd_to_double_scan = 0;
	llmd->llmd_in_double_scan = 0;
	llmd->llmd_exit = 0;
	thread_set_flags(athread, 0);

	lta = lfsck_thread_args_init(lfsck, com, lsp);
	if (IS_ERR(lta))
		RETURN(PTR_ERR(lta));

	rc = PTR_ERR(kthread_run(lfsck_layout_assistant, lta, "lfsck_layout"));
	if (IS_ERR_VALUE(rc)) {
		CERROR("%s: Cannot start LFSCK layout assistant thread: "
		       "rc = %ld\n", lfsck_lfsck2name(lfsck), rc);
		lfsck_thread_args_fini(lta);
	} else {
		struct l_wait_info lwi = { 0 };

		l_wait_event(mthread->t_ctl_waitq,
			     thread_is_running(athread) ||
			     thread_is_stopped(athread),
			     &lwi);
		if (unlikely(!thread_is_running(athread)))
			rc = llmd->llmd_assistant_status;
		else
			rc = 0;
	}

	RETURN(rc);
}

/* Pre-fetch the attribute for each stripe in the given layout EA. */
static int lfsck_layout_scan_stripes(const struct lu_env *env,
				     struct lfsck_component *com,
				     struct dt_object *parent,
				     struct lov_mds_md_v1 *lmm)
{
	struct lfsck_thread_info	*info 	 = lfsck_env_info(env);
	struct lfsck_instance		*lfsck	 = com->lc_lfsck;
	struct lfsck_bookmark		*bk	 = &lfsck->li_bookmark_ram;
	struct lfsck_layout		*lo	 = com->lc_file_ram;
	struct lfsck_layout_master_data *llmd	 = com->lc_data;
	struct lfsck_layout_object	*llo 	 = NULL;
	struct lov_ost_data_v1		*objs;
	struct lfsck_tgt_descs		*ltds	 = &lfsck->li_ost_descs;
	struct ptlrpc_thread		*mthread = &lfsck->li_thread;
	struct ptlrpc_thread		*athread = &llmd->llmd_thread;
		struct l_wait_info	 lwi	 = { 0 };
	struct lu_buf			*buf;
	int				 rc	 = 0;
	int				 i;
	__u32				 magic;
	__u16				 count;
	__u16				 gen;
	ENTRY;

	buf = lfsck_buf_get(env, &info->lti_old_pfid,
			    sizeof(struct filter_fid_old));
	count = le16_to_cpu(lmm->lmm_stripe_count);
	gen = le16_to_cpu(lmm->lmm_layout_gen);
	/* Currently, we only support LOV_MAGIC_V1/LOV_MAGIC_V3 which has
	 * been verified in lfsck_layout_verify_header() already. If some
	 * new magic introduced in the future, then layout LFSCK needs to
	 * be updated also. */
	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic == LOV_MAGIC_V1) {
		objs = &(lmm->lmm_objects[0]);
	} else {
		LASSERT(magic == LOV_MAGIC_V3);
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
	}

	for (i = 0; i < count; i++, objs++) {
		struct lu_fid		*fid	= &info->lti_fid;
		struct ost_id		*oi	= &info->lti_oi;
		struct lfsck_layout_req *llr;
		struct lfsck_tgt_desc	*tgt	= NULL;
		struct dt_object	*cobj	= NULL;
		__u32			 index	=
					le32_to_cpu(objs->l_ost_idx);
		bool			 wakeup = false;

		l_wait_event(mthread->t_ctl_waitq,
			     bk->lb_async_windows == 0 ||
			     llmd->llmd_prefetched < bk->lb_async_windows ||
			     !thread_is_running(mthread) ||
			     thread_is_stopped(athread),
			     &lwi);

		if (unlikely(!thread_is_running(mthread)) ||
			     thread_is_stopped(athread))
			GOTO(out, rc = 0);

		ostid_le_to_cpu(&objs->l_ost_oi, oi);
		ostid_to_fid(fid, oi, index);
		tgt = lfsck_tgt_get(ltds, index);
		if (unlikely(tgt == NULL)) {
			lo->ll_flags |= LF_INCOMPLETE;
			goto next;
		}

		cobj = lfsck_object_find_by_dev(env, tgt->ltd_tgt, fid);
		if (IS_ERR(cobj)) {
			rc = PTR_ERR(cobj);
			goto next;
		}

		rc = dt_declare_attr_get(env, cobj, BYPASS_CAPA);
		if (rc != 0)
			goto next;

		rc = dt_declare_xattr_get(env, cobj, buf, XATTR_NAME_FID,
					  BYPASS_CAPA);
		if (rc != 0)
			goto next;

		if (llo == NULL) {
			llo = lfsck_layout_object_init(env, parent, gen);
			if (IS_ERR(llo)) {
				rc = PTR_ERR(llo);
				goto next;
			}
		}

		llr = lfsck_layout_req_init(llo, cobj, index, i);
		if (IS_ERR(llr)) {
			rc = PTR_ERR(llr);
			goto next;
		}

		cobj = NULL;
		spin_lock(&llmd->llmd_lock);
		if (llmd->llmd_assistant_status < 0) {
			spin_unlock(&llmd->llmd_lock);
			lfsck_layout_req_fini(env, llr);
			lfsck_tgt_put(tgt);
			RETURN(llmd->llmd_assistant_status);
		}

		list_add_tail(&llr->llr_list, &llmd->llmd_req_list);
		if (llmd->llmd_prefetched == 0)
			wakeup = true;

		llmd->llmd_prefetched++;
		spin_unlock(&llmd->llmd_lock);
		if (wakeup)
			wake_up_all(&athread->t_ctl_waitq);

next:
		down_write(&com->lc_sem);
		com->lc_new_checked++;
		if (rc < 0)
			lo->ll_objs_failed_phase1++;
		up_write(&com->lc_sem);

		if (cobj != NULL && !IS_ERR(cobj))
			lu_object_put(env, &cobj->do_lu);

		if (likely(tgt != NULL))
			lfsck_tgt_put(tgt);

		if (rc < 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(out, rc);
	}

	GOTO(out, rc = 0);

out:
	if (llo != NULL && !IS_ERR(llo))
		lfsck_layout_object_put(env, llo);

	return rc;
}

/* For the given object, read its layout EA locally. For each stripe, pre-fetch
 * the OST-object's attribute and generate an structure lfsck_layout_req on the
 * list ::llmd_req_list.
 *
 * For each request on above list, the lfsck_layout_assistant thread compares
 * the OST side attribute with local attribute, if inconsistent, then repair it.
 *
 * All above processing is async mode with pipeline. */
static int lfsck_layout_master_exec_oit(const struct lu_env *env,
					struct lfsck_component *com,
					struct dt_object *obj)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct ost_id			*oi	= &info->lti_oi;
	struct lfsck_layout		*lo	= com->lc_file_ram;
	struct lfsck_layout_master_data *llmd	= com->lc_data;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_bookmark		*bk	= &lfsck->li_bookmark_ram;
	struct thandle			*handle = NULL;
	struct lu_buf			*buf	= &info->lti_big_buf;
	struct lov_mds_md_v1		*lmm	= NULL;
	struct dt_device		*dev	= lfsck->li_bottom;
	struct lustre_handle		 lh	= { 0 };
	ssize_t				 buflen = buf->lb_len;
	int				 rc	= 0;
	bool				 locked	= false;
	bool				 stripe = false;
	ENTRY;

	if (!S_ISREG(lfsck_object_type(obj)))
		GOTO(out, rc = 0);

	if (llmd->llmd_assistant_status < 0)
		GOTO(out, rc = -ESRCH);

	fid_to_lmm_oi(lfsck_dto2fid(obj), oi);
	lmm_oi_cpu_to_le(oi, oi);
	dt_read_lock(env, obj, 0);
	locked = true;

again:
	rc = lfsck_layout_get_lovea(env, obj, buf, &buflen);
	if (rc <= 0)
		GOTO(out, rc);

	buf->lb_len = rc;
	lmm = buf->lb_buf;
	rc = lfsck_layout_verify_header(lmm);
	if (rc != 0)
		GOTO(out, rc);

	if (memcmp(oi, &lmm->lmm_oi, sizeof(*oi)) == 0)
		GOTO(out, stripe = true);

	/* Inconsistent lmm_oi, should be repaired. */
	CDEBUG(D_LFSCK, "Repair bad lmm_oi for "DFID"\n",
	       PFID(lfsck_dto2fid(obj)));

	if (bk->lb_param & LPF_DRYRUN) {
		down_write(&com->lc_sem);
		lo->ll_objs_repaired[LLIT_OTHERS - 1]++;
		up_write(&com->lc_sem);

		GOTO(out, stripe = true);
	}

	if (!lustre_handle_is_used(&lh)) {
		dt_read_unlock(env, obj);
		locked = false;
		buf->lb_len = buflen;
		rc = lfsck_layout_lock(env, com, obj, &lh,
				       MDS_INODELOCK_LAYOUT |
				       MDS_INODELOCK_XATTR);
		if (rc != 0)
			GOTO(out, rc);

		handle = dt_trans_create(env, dev);
		if (IS_ERR(handle))
			GOTO(out, rc = PTR_ERR(handle));

		rc = dt_declare_xattr_set(env, obj, buf, XATTR_NAME_LOV,
					  LU_XATTR_REPLACE, handle);
		if (rc != 0)
			GOTO(out, rc);

		rc = dt_trans_start_local(env, dev, handle);
		if (rc != 0)
			GOTO(out, rc);

		dt_write_lock(env, obj, 0);
		locked = true;

		goto again;
	}

	lmm->lmm_oi = *oi;
	rc = dt_xattr_set(env, obj, buf, XATTR_NAME_LOV,
			  LU_XATTR_REPLACE, handle, BYPASS_CAPA);
	if (rc != 0)
		GOTO(out, rc);

	down_write(&com->lc_sem);
	lo->ll_objs_repaired[LLIT_OTHERS - 1]++;
	up_write(&com->lc_sem);

	GOTO(out, stripe = true);

out:
	if (locked) {
		if (lustre_handle_is_used(&lh))
			dt_write_unlock(env, obj);
		else
			dt_read_unlock(env, obj);
	}

	if (handle != NULL && !IS_ERR(handle))
		dt_trans_stop(env, dev, handle);

	lfsck_layout_unlock(&lh);
	if (stripe) {
		rc = lfsck_layout_scan_stripes(env, com, obj, lmm);
	} else {
		down_write(&com->lc_sem);
		com->lc_new_checked++;
		if (rc < 0)
			lo->ll_objs_failed_phase1++;
		up_write(&com->lc_sem);
	}
	buf->lb_len = buflen;

	return rc;
}

static int lfsck_layout_slave_exec_oit(const struct lu_env *env,
				       struct lfsck_component *com,
				       struct dt_object *obj)
{
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_layout		*lo	= com->lc_file_ram;
	const struct lu_fid		*fid	= lfsck_dto2fid(obj);
	struct lfsck_layout_slave_data	*llsd	= com->lc_data;
	struct lfsck_layout_seq		*lls;
	__u64				 seq;
	__u64				 oid;
	int				 rc;
	ENTRY;

	/* XXX: Update OST-objects bitmap for orphan detection. */

	LASSERT(llsd != NULL);

	down_write(&com->lc_sem);
	if (fid_is_idif(fid))
		seq = 0;
	else if (!fid_is_norm(fid) ||
		 !fid_is_for_ostobj(env, lfsck->li_next, obj, fid))
		GOTO(unlock, rc = 0);
	else
		seq = fid_seq(fid);
	com->lc_new_checked++;

	lls = lfsck_layout_seq_lookup(llsd, seq);
	if (lls == NULL) {
		OBD_ALLOC_PTR(lls);
		if (unlikely(lls == NULL))
			GOTO(unlock, rc = -ENOMEM);

		INIT_LIST_HEAD(&lls->lls_list);
		lls->lls_seq = seq;
		rc = lfsck_layout_lastid_load(env, com, lls);
		if (rc != 0) {
			lo->ll_objs_failed_phase1++;
			OBD_FREE_PTR(lls);
			GOTO(unlock, rc);
		}

		lfsck_layout_seq_insert(llsd, lls);
	}

	if (unlikely(fid_is_last_id(fid)))
		GOTO(unlock, rc = 0);

	oid = fid_oid(fid);
	if (oid > lls->lls_lastid_known)
		lls->lls_lastid_known = oid;

	if (oid > lls->lls_lastid) {
		if (!(lo->ll_flags & LF_CRASHED_LASTID)) {
			/* OFD may create new objects during LFSCK scanning. */
			rc = lfsck_layout_lastid_reload(env, com, lls);
			if (unlikely(rc != 0))
				CWARN("%s: failed to reload LAST_ID for "LPX64
				      ": rc = %d\n",
				      lfsck_lfsck2name(com->lc_lfsck),
				      lls->lls_seq, rc);
			if (oid <= lls->lls_lastid)
				GOTO(unlock, rc = 0);

			LASSERT(lfsck->li_out_notify != NULL);

			lfsck->li_out_notify(env, lfsck->li_out_notify_data,
					     LE_LASTID_REBUILDING);
			lo->ll_flags |= LF_CRASHED_LASTID;
		}

		lls->lls_lastid = oid;
		lls->lls_dirty = 1;
	}

	GOTO(unlock, rc = 0);

unlock:
	up_write(&com->lc_sem);

	return rc;
}

static int lfsck_layout_exec_dir(const struct lu_env *env,
				 struct lfsck_component *com,
				 struct dt_object *obj,
				 struct lu_dirent *ent)
{
	return 0;
}

static int lfsck_layout_master_post(const struct lu_env *env,
				    struct lfsck_component *com,
				    int result, bool init)
{
	struct lfsck_instance		*lfsck   = com->lc_lfsck;
	struct lfsck_layout		*lo	 = com->lc_file_ram;
	struct lfsck_layout_master_data *llmd	 = com->lc_data;
	struct ptlrpc_thread		*mthread = &lfsck->li_thread;
	struct ptlrpc_thread		*athread = &llmd->llmd_thread;
	struct l_wait_info		 lwi	 = { 0 };
	int				 rc;
	ENTRY;


	llmd->llmd_post_result = result;
	llmd->llmd_to_post = 1;
	if (llmd->llmd_post_result <= 0)
		llmd->llmd_exit = 1;

	wake_up_all(&athread->t_ctl_waitq);
	l_wait_event(mthread->t_ctl_waitq,
		     (result > 0 && list_empty(&llmd->llmd_req_list)) ||
		     thread_is_stopped(athread),
		     &lwi);

	if (llmd->llmd_assistant_status < 0)
		result = llmd->llmd_assistant_status;

	down_write(&com->lc_sem);
	spin_lock(&lfsck->li_lock);
	/* When LFSCK failed, there may be some prefetched objects those are
	 * not been processed yet, we do not know the exactly position, then
	 * just restart from last check-point next time. */
	if (!init && !llmd->llmd_exit)
		lo->ll_pos_last_checkpoint =
					lfsck->li_pos_current.lp_oit_cookie;

	if (result > 0) {
		lo->ll_status = LS_SCANNING_PHASE2;
		lo->ll_flags |= LF_SCANNED_ONCE;
		lo->ll_flags &= ~LF_UPGRADE;
		list_del_init(&com->lc_link);
		list_add_tail(&com->lc_link, &lfsck->li_list_double_scan);
	} else if (result == 0) {
		lo->ll_status = lfsck->li_status;
		if (lo->ll_status == 0)
			lo->ll_status = LS_STOPPED;
		if (lo->ll_status != LS_PAUSED) {
			list_del_init(&com->lc_link);
			list_add_tail(&com->lc_link, &lfsck->li_list_idle);
		}
	} else {
		lo->ll_status = LS_FAILED;
		list_del_init(&com->lc_link);
		list_add_tail(&com->lc_link, &lfsck->li_list_idle);
	}
	spin_unlock(&lfsck->li_lock);

	if (!init) {
		lo->ll_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
		lo->ll_time_last_checkpoint = cfs_time_current_sec();
		lo->ll_objs_checked_phase1 += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_layout_store(env, com);
	up_write(&com->lc_sem);

	RETURN(rc);
}

static int lfsck_layout_slave_post(const struct lu_env *env,
				   struct lfsck_component *com,
				   int result, bool init)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_layout	*lo    = com->lc_file_ram;
	int			 rc;
	bool			 done  = false;

	rc = lfsck_layout_lastid_store(env, com);
	if (rc != 0)
		result = rc;

	LASSERT(lfsck->li_out_notify != NULL);

	down_write(&com->lc_sem);

	spin_lock(&lfsck->li_lock);
	if (!init)
		lo->ll_pos_last_checkpoint =
					lfsck->li_pos_current.lp_oit_cookie;
	if (result > 0) {
		lo->ll_status = LS_SCANNING_PHASE2;
		lo->ll_flags |= LF_SCANNED_ONCE;
		if (lo->ll_flags & LF_CRASHED_LASTID) {
			done = true;
			lo->ll_flags &= ~LF_CRASHED_LASTID;
		}
		lo->ll_flags &= ~LF_UPGRADE;
		list_del_init(&com->lc_link);
		list_add_tail(&com->lc_link, &lfsck->li_list_double_scan);
	} else if (result == 0) {
		lo->ll_status = lfsck->li_status;
		if (lo->ll_status == 0)
			lo->ll_status = LS_STOPPED;
		if (lo->ll_status != LS_PAUSED) {
			list_del_init(&com->lc_link);
			list_add_tail(&com->lc_link, &lfsck->li_list_idle);
		}
	} else {
		lo->ll_status = LS_FAILED;
		list_del_init(&com->lc_link);
		list_add_tail(&com->lc_link, &lfsck->li_list_idle);
	}
	spin_unlock(&lfsck->li_lock);

	if (done)
		lfsck->li_out_notify(env, lfsck->li_out_notify_data,
				     LE_LASTID_REBUILT);

	if (!init) {
		lo->ll_run_time_phase1 += cfs_duration_sec(cfs_time_current() +
				HALF_SEC - lfsck->li_time_last_checkpoint);
		lo->ll_time_last_checkpoint = cfs_time_current_sec();
		lo->ll_objs_checked_phase1 += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_layout_store(env, com);

	up_write(&com->lc_sem);

	lfsck_layout_slave_notify_master(env, com, LE_PHASE1_DONE, result);

	return rc;
}

static int lfsck_layout_dump(const struct lu_env *env,
			     struct lfsck_component *com, char *buf, int len)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_bookmark	*bk    = &lfsck->li_bookmark_ram;
	struct lfsck_layout	*lo    = com->lc_file_ram;
	int			 save  = len;
	int			 ret   = -ENOSPC;
	int			 rc;

	down_read(&com->lc_sem);
	rc = snprintf(buf, len,
		      "name: lfsck_layout\n"
		      "magic: %#x\n"
		      "version: %d\n"
		      "status: %s\n",
		      lo->ll_magic,
		      bk->lb_version,
		      lfsck_status2names(lo->ll_status));
	if (rc <= 0)
		goto out;

	buf += rc;
	len -= rc;
	rc = lfsck_bits_dump(&buf, &len, lo->ll_flags, lfsck_flags_names,
			     "flags");
	if (rc < 0)
		goto out;

	rc = lfsck_bits_dump(&buf, &len, bk->lb_param, lfsck_param_names,
			     "param");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(&buf, &len, lo->ll_time_last_complete,
			     "time_since_last_completed");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(&buf, &len, lo->ll_time_latest_start,
			     "time_since_latest_start");
	if (rc < 0)
		goto out;

	rc = lfsck_time_dump(&buf, &len, lo->ll_time_last_checkpoint,
			     "time_since_last_checkpoint");
	if (rc < 0)
		goto out;

	rc = snprintf(buf, len,
		      "latest_start_position: "LPU64"\n"
		      "last_checkpoint_position: "LPU64"\n"
		      "first_failure_position: "LPU64"\n",
		      lo->ll_pos_latest_start,
		      lo->ll_pos_last_checkpoint,
		      lo->ll_pos_first_inconsistent);
	if (rc <= 0)
		goto out;

	buf += rc;
	len -= rc;

	rc = snprintf(buf, len,
		      "success_count: %u\n"
		      "repaired_dangling: "LPU64"\n"
		      "repaired_unmatched_pair: "LPU64"\n"
		      "repaired_multiple_referenced: "LPU64"\n"
		      "repaired_orphan: "LPU64"\n"
		      "repaired_inconsistent_owner: "LPU64"\n"
		      "repaired_others: "LPU64"\n"
		      "skipped: "LPU64"\n"
		      "failed_phase1: "LPU64"\n"
		      "failed_phase2: "LPU64"\n",
		      lo->ll_success_count,
		      lo->ll_objs_repaired[LLIT_DANGLING - 1],
		      lo->ll_objs_repaired[LLIT_UNMATCHED_PAIR - 1],
		      lo->ll_objs_repaired[LLIT_MULTIPLE_REFERENCED - 1],
		      lo->ll_objs_repaired[LLIT_ORPHAN - 1],
		      lo->ll_objs_repaired[LLIT_INCONSISTENT_OWNER - 1],
		      lo->ll_objs_repaired[LLIT_OTHERS - 1],
		      lo->ll_objs_skipped,
		      lo->ll_objs_failed_phase1,
		      lo->ll_objs_failed_phase2);
	if (rc <= 0)
		goto out;

	buf += rc;
	len -= rc;

	if (lo->ll_status == LS_SCANNING_PHASE1) {
		__u64 pos;
		const struct dt_it_ops *iops;
		cfs_duration_t duration = cfs_time_current() -
					  lfsck->li_time_last_checkpoint;
		__u64 checked = lo->ll_objs_checked_phase1 + com->lc_new_checked;
		__u64 speed = checked;
		__u64 new_checked = com->lc_new_checked * HZ;
		__u32 rtime = lo->ll_run_time_phase1 +
			      cfs_duration_sec(duration + HALF_SEC);

		if (duration != 0)
			do_div(new_checked, duration);
		if (rtime != 0)
			do_div(speed, rtime);
		rc = snprintf(buf, len,
			      "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: N/A\n"
			      "real-time_speed_phase1: "LPU64" items/sec\n"
			      "real-time_speed_phase2: N/A\n",
			      checked,
			      lo->ll_objs_checked_phase2,
			      rtime,
			      lo->ll_run_time_phase2,
			      speed,
			      new_checked);
		if (rc <= 0)
			goto out;

		buf += rc;
		len -= rc;

		LASSERT(lfsck->li_di_oit != NULL);

		iops = &lfsck->li_obj_oit->do_index_ops->dio_it;

		/* The low layer otable-based iteration position may NOT
		 * exactly match the layout-based directory traversal
		 * cookie. Generally, it is not a serious issue. But the
		 * caller should NOT make assumption on that. */
		pos = iops->store(env, lfsck->li_di_oit);
		if (!lfsck->li_current_oit_processed)
			pos--;
		rc = snprintf(buf, len, "current_position: "LPU64"\n", pos);
		if (rc <= 0)
			goto out;

		buf += rc;
		len -= rc;
	} else {
		/* XXX: LS_SCANNING_PHASE2 will be handled in the future. */
		__u64 speed1 = lo->ll_objs_checked_phase1;
		__u64 speed2 = lo->ll_objs_checked_phase2;

		if (lo->ll_run_time_phase1 != 0)
			do_div(speed1, lo->ll_run_time_phase1);
		if (lo->ll_run_time_phase2 != 0)
			do_div(speed2, lo->ll_run_time_phase2);
		rc = snprintf(buf, len,
			      "checked_phase1: "LPU64"\n"
			      "checked_phase2: "LPU64"\n"
			      "run_time_phase1: %u seconds\n"
			      "run_time_phase2: %u seconds\n"
			      "average_speed_phase1: "LPU64" items/sec\n"
			      "average_speed_phase2: "LPU64" objs/sec\n"
			      "real-time_speed_phase1: N/A\n"
			      "real-time_speed_phase2: N/A\n"
			      "current_position: N/A\n",
			      lo->ll_objs_checked_phase1,
			      lo->ll_objs_checked_phase2,
			      lo->ll_run_time_phase1,
			      lo->ll_run_time_phase2,
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

static int lfsck_layout_master_double_scan(const struct lu_env *env,
					   struct lfsck_component *com)
{
	struct lfsck_layout_master_data *llmd    = com->lc_data;
	struct ptlrpc_thread		*mthread = &com->lc_lfsck->li_thread;
	struct ptlrpc_thread		*athread = &llmd->llmd_thread;
	struct lfsck_layout		*lo	 = com->lc_file_ram;
	struct l_wait_info		 lwi	 = { 0 };

	if (unlikely(lo->ll_status != LS_SCANNING_PHASE2))
		return 0;

	llmd->llmd_to_double_scan = 1;
	wake_up_all(&athread->t_ctl_waitq);
	l_wait_event(mthread->t_ctl_waitq,
		     llmd->llmd_in_double_scan ||
		     thread_is_stopped(athread),
		     &lwi);
	if (llmd->llmd_assistant_status < 0)
		return llmd->llmd_assistant_status;

	return 0;
}

static int lfsck_layout_slave_double_scan(const struct lu_env *env,
					  struct lfsck_component *com)
{
	struct lfsck_instance		*lfsck  = com->lc_lfsck;
	struct lfsck_layout_slave_data	*llsd	= com->lc_data;
	struct lfsck_layout		*lo     = com->lc_file_ram;
	struct ptlrpc_thread		*thread = &lfsck->li_thread;
	int				 rc;
	ENTRY;

	if (unlikely(lo->ll_status != LS_SCANNING_PHASE2))
		RETURN(0);

	atomic_inc(&lfsck->li_double_scan_count);

	com->lc_new_checked = 0;
	com->lc_new_scanned = 0;
	com->lc_time_last_checkpoint = cfs_time_current();
	com->lc_time_next_checkpoint = com->lc_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);

	while (1) {
		struct l_wait_info lwi = LWI_TIMEOUT(cfs_time_seconds(30),
						     NULL, NULL);

		rc = lfsck_layout_slave_query_master(env, com);
		if (list_empty(&llsd->llsd_master_list)) {
			if (unlikely(!thread_is_running(thread)))
				rc = 0;
			else
				rc = 1;

			GOTO(done, rc);
		}

		if (rc < 0)
			GOTO(done, rc);

		rc = l_wait_event(thread->t_ctl_waitq,
				  !thread_is_running(thread) ||
				  list_empty(&llsd->llsd_master_list),
				  &lwi);
		if (unlikely(!thread_is_running(thread)))
			GOTO(done, rc = 0);

		if (rc == -ETIMEDOUT)
			continue;

		GOTO(done, rc = (rc < 0 ? rc : 1));
	}

done:
	rc = lfsck_layout_double_scan_result(env, com, rc);

	if (atomic_dec_and_test(&lfsck->li_double_scan_count))
		wake_up_all(&lfsck->li_thread.t_ctl_waitq);

	return rc;
}

static void lfsck_layout_master_data_release(const struct lu_env *env,
					     struct lfsck_component *com)
{
	struct lfsck_layout_master_data	*llmd   = com->lc_data;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_tgt_descs		*ltds;
	struct lfsck_tgt_desc		*ltd;
	struct lfsck_tgt_desc		*next;

	LASSERT(llmd != NULL);
	LASSERT(thread_is_init(&llmd->llmd_thread) ||
		thread_is_stopped(&llmd->llmd_thread));
	LASSERT(list_empty(&llmd->llmd_req_list));

	com->lc_data = NULL;

	ltds = &lfsck->li_ost_descs;
	spin_lock(&ltds->ltd_lock);
	list_for_each_entry_safe(ltd, next, &llmd->llmd_ost_phase1_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &llmd->llmd_ost_phase2_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &llmd->llmd_ost_list,
				 ltd_layout_list) {
		list_del_init(&ltd->ltd_layout_list);
	}
	list_for_each_entry_safe(ltd, next, &llmd->llmd_mdt_phase1_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &llmd->llmd_mdt_phase2_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &llmd->llmd_mdt_list,
				 ltd_layout_list) {
		list_del_init(&ltd->ltd_layout_list);
	}
	spin_unlock(&ltds->ltd_lock);

	OBD_FREE_PTR(llmd);
}

static void lfsck_layout_slave_data_release(const struct lu_env *env,
					    struct lfsck_component *com)
{
	struct lfsck_layout_slave_data	 *llsd	= com->lc_data;
	struct lfsck_layout_seq		 *lls;
	struct lfsck_layout_seq		 *next;
	struct lfsck_layout_slave_target *llst;
	struct lfsck_layout_slave_target *tmp;

	LASSERT(llsd != NULL);

	com->lc_data = NULL;

	list_for_each_entry_safe(lls, next, &llsd->llsd_seq_list,
				     lls_list) {
		list_del_init(&lls->lls_list);
		lfsck_object_put(env, lls->lls_lastid_obj);
		OBD_FREE_PTR(lls);
	}

	list_for_each_entry_safe(llst, tmp, &llsd->llsd_master_list,
				 llst_list) {
		list_del_init(&llst->llst_list);
		OBD_FREE_PTR(llst);
	}

	OBD_FREE_PTR(llsd);
}

static void lfsck_layout_master_quit(const struct lu_env *env,
				     struct lfsck_component *com)
{
	struct lfsck_layout_master_data *llmd	 = com->lc_data;
	struct ptlrpc_thread		*mthread = &com->lc_lfsck->li_thread;
	struct ptlrpc_thread		*athread = &llmd->llmd_thread;
	struct l_wait_info		 lwi     = { 0 };

	llmd->llmd_exit = 1;
	wake_up_all(&athread->t_ctl_waitq);
	l_wait_event(mthread->t_ctl_waitq,
		     thread_is_init(athread) ||
		     thread_is_stopped(athread),
		     &lwi);
}

static int lfsck_layout_master_in_notify(const struct lu_env *env,
					 struct lfsck_component *com,
					 struct lfsck_request *lr)
{
	struct lfsck_instance		*lfsck = com->lc_lfsck;
	struct lfsck_layout		*lo    = com->lc_file_ram;
	struct lfsck_layout_master_data *llmd  = com->lc_data;
	struct lfsck_tgt_descs		*ltds;
	struct lfsck_tgt_desc		*ltd;
	ENTRY;

	if (lr->lr_event != LE_PHASE1_DONE &&
	    lr->lr_event != LE_PHASE2_DONE &&
	    lr->lr_event != LE_STOP)
		RETURN(-EINVAL);

	if (lr->lr_flags & LEF_FROM_OST)
		ltds = &lfsck->li_ost_descs;
	else
		ltds = &lfsck->li_mdt_descs;
	spin_lock(&ltds->ltd_lock);
	ltd = LTD_TGT(ltds, lr->lr_index);
	if (ltd == NULL) {
		spin_unlock(&ltds->ltd_lock);

		RETURN(-ENODEV);
	}

	list_del_init(&ltd->ltd_layout_phase_list);
	switch (lr->lr_event) {
	case LE_PHASE1_DONE:
		if (lr->lr_status <= 0) {
			ltd->ltd_layout_done = 1;
			list_del_init(&ltd->ltd_layout_list);
			lo->ll_flags |= LF_INCOMPLETE;
			break;
		}

		if (lr->lr_flags & LEF_FROM_OST) {
			if (list_empty(&ltd->ltd_layout_list))
				list_add_tail(&ltd->ltd_layout_list,
					      &llmd->llmd_ost_list);
			list_add_tail(&ltd->ltd_layout_phase_list,
				      &llmd->llmd_ost_phase2_list);
		} else {
			if (list_empty(&ltd->ltd_layout_list))
				list_add_tail(&ltd->ltd_layout_list,
					      &llmd->llmd_mdt_list);
			list_add_tail(&ltd->ltd_layout_phase_list,
				      &llmd->llmd_mdt_phase2_list);
		}
		break;
	case LE_PHASE2_DONE:
		ltd->ltd_layout_done = 1;
		list_del_init(&ltd->ltd_layout_list);
		break;
	case LE_STOP:
		ltd->ltd_layout_done = 1;
		list_del_init(&ltd->ltd_layout_list);
		if (!(lr->lr_flags & LEF_FORCE_STOP))
			lo->ll_flags |= LF_INCOMPLETE;
		break;
	default:
		break;
	}
	spin_unlock(&ltds->ltd_lock);

	if (lr->lr_flags & LEF_FORCE_STOP) {
		struct lfsck_stop *stop = &lfsck_env_info(env)->lti_stop;

		memset(stop, 0, sizeof(*stop));
		stop->ls_status = lr->lr_status;
		stop->ls_flags = lr->lr_param;
		lfsck_stop(env, lfsck->li_bottom, stop);
	} else if (lfsck_layout_master_to_orphan(llmd)) {
		wake_up_all(&llmd->llmd_thread.t_ctl_waitq);
	}

	RETURN(0);
}

static int lfsck_layout_slave_in_notify(const struct lu_env *env,
					struct lfsck_component *com,
					struct lfsck_request *lr)
{
	struct lfsck_instance		 *lfsck = com->lc_lfsck;
	struct lfsck_layout_slave_data	 *llsd  = com->lc_data;
	struct lfsck_layout_slave_target *llst;
	ENTRY;

	if (lr->lr_event != LE_PHASE2_DONE &&
	    lr->lr_event != LE_STOP)
		RETURN(-EINVAL);

	llst = lfsck_layout_llst_find_and_del(llsd, lr->lr_index);
	if (llst == NULL)
		RETURN(-ENODEV);

	lfsck_layout_llst_put(llst);
	if (list_empty(&llsd->llsd_master_list)) {
		switch (lr->lr_event) {
		case LE_PHASE2_DONE:
			wake_up_all(&lfsck->li_thread.t_ctl_waitq);
			break;
		case LE_STOP: {
			struct lfsck_stop *stop = &lfsck_env_info(env)->lti_stop;

			memset(stop, 0, sizeof(*stop));
			stop->ls_status = lr->lr_status;
			stop->ls_flags = lr->lr_param;
			lfsck_stop(env, lfsck->li_bottom, stop);
			break;
		}
		default:
			break;
		}
	}

	RETURN(0);
}

static int lfsck_layout_query(const struct lu_env *env,
			      struct lfsck_component *com)
{
	struct lfsck_layout *lo = com->lc_file_ram;

	return lo->ll_status;
}

static int lfsck_layout_master_stop_notify(const struct lu_env *env,
					   struct lfsck_component *com,
					   struct lfsck_tgt_descs *ltds,
					   struct lfsck_tgt_desc *ltd,
					   struct ptlrpc_request_set *set)
{
	struct lfsck_thread_info	  *info  = lfsck_env_info(env);
	struct lfsck_async_interpret_args *laia  = &info->lti_laia;
	struct lfsck_request		  *lr	 = &info->lti_lr;
	struct lfsck_instance		  *lfsck = com->lc_lfsck;
	int				   rc;

	LASSERT(list_empty(&ltd->ltd_layout_list));
	LASSERT(list_empty(&ltd->ltd_layout_phase_list));

	memset(lr, 0, sizeof(*lr));
	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	lr->lr_event = LE_STOP;
	lr->lr_active = LT_LAYOUT;
	if (ltds == &lfsck->li_ost_descs) {
		lr->lr_flags = LEF_TO_OST;
	} else {
		if (ltd->ltd_index == lfsck_dev_idx(lfsck->li_bottom))
			return 0;

		lr->lr_flags = 0;
	}
	lr->lr_status = LS_CO_STOPPED;

	laia->laia_com = com;
	laia->laia_ltds = ltds;
	laia->laia_ltd = ltd;
	laia->laia_lr = lr;

	rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
				 lfsck_layout_master_async_interpret,
				 laia, LFSCK_NOTIFY);
	if (rc != 0)
		CERROR("%s: Fail to notify %s %x for co-stop: rc = %d\n",
		       lfsck_lfsck2name(lfsck),
		       (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
		       ltd->ltd_index, rc);

	return rc;
}

/* with lfsck::li_lock held */
static int lfsck_layout_slave_join(const struct lu_env *env,
				   struct lfsck_component *com,
				   struct lfsck_start_param *lsp)
{
	struct lfsck_instance		 *lfsck = com->lc_lfsck;
	struct lfsck_layout_slave_data	 *llsd  = com->lc_data;
	struct lfsck_layout_slave_target *llst;
	struct lfsck_start		 *start = lsp->lsp_start;
	int				  rc    = 0;
	ENTRY;

	if (!lsp->lsp_index_valid || start == NULL ||
	    !(start->ls_flags & LPF_ALL_MDT))
		RETURN(-EALREADY);

	spin_unlock(&lfsck->li_lock);
	rc = lfsck_layout_llst_add(llsd, lsp->lsp_index);
	spin_lock(&lfsck->li_lock);
	if (rc == 0 && !thread_is_running(&lfsck->li_thread)) {
		spin_unlock(&lfsck->li_lock);
		llst = lfsck_layout_llst_find_and_del(llsd, lsp->lsp_index);
		if (llst != NULL)
			lfsck_layout_llst_put(llst);
		spin_lock(&lfsck->li_lock);
		rc = -EAGAIN;
	}

	RETURN(rc);
}

static struct lfsck_operations lfsck_layout_master_ops = {
	.lfsck_reset		= lfsck_layout_reset,
	.lfsck_fail		= lfsck_layout_fail,
	.lfsck_checkpoint	= lfsck_layout_master_checkpoint,
	.lfsck_prep		= lfsck_layout_master_prep,
	.lfsck_exec_oit		= lfsck_layout_master_exec_oit,
	.lfsck_exec_dir		= lfsck_layout_exec_dir,
	.lfsck_post		= lfsck_layout_master_post,
	.lfsck_dump		= lfsck_layout_dump,
	.lfsck_double_scan	= lfsck_layout_master_double_scan,
	.lfsck_data_release	= lfsck_layout_master_data_release,
	.lfsck_quit		= lfsck_layout_master_quit,
	.lfsck_in_notify	= lfsck_layout_master_in_notify,
	.lfsck_query		= lfsck_layout_query,
	.lfsck_stop_notify	= lfsck_layout_master_stop_notify,
};

static struct lfsck_operations lfsck_layout_slave_ops = {
	.lfsck_reset		= lfsck_layout_reset,
	.lfsck_fail		= lfsck_layout_fail,
	.lfsck_checkpoint	= lfsck_layout_slave_checkpoint,
	.lfsck_prep		= lfsck_layout_slave_prep,
	.lfsck_exec_oit		= lfsck_layout_slave_exec_oit,
	.lfsck_exec_dir		= lfsck_layout_exec_dir,
	.lfsck_post		= lfsck_layout_slave_post,
	.lfsck_dump		= lfsck_layout_dump,
	.lfsck_double_scan	= lfsck_layout_slave_double_scan,
	.lfsck_data_release	= lfsck_layout_slave_data_release,
	.lfsck_in_notify	= lfsck_layout_slave_in_notify,
	.lfsck_query		= lfsck_layout_query,
	.lfsck_join		= lfsck_layout_slave_join,
};

int lfsck_layout_setup(const struct lu_env *env, struct lfsck_instance *lfsck)
{
	struct lfsck_component	*com;
	struct lfsck_layout	*lo;
	struct dt_object	*root = NULL;
	struct dt_object	*obj;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(com);
	if (com == NULL)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&com->lc_link);
	INIT_LIST_HEAD(&com->lc_link_dir);
	init_rwsem(&com->lc_sem);
	atomic_set(&com->lc_ref, 1);
	com->lc_lfsck = lfsck;
	com->lc_type = LT_LAYOUT;
	if (lfsck->li_master) {
		struct lfsck_layout_master_data *llmd;

		com->lc_ops = &lfsck_layout_master_ops;
		OBD_ALLOC_PTR(llmd);
		if (llmd == NULL)
			GOTO(out, rc = -ENOMEM);

		INIT_LIST_HEAD(&llmd->llmd_req_list);
		spin_lock_init(&llmd->llmd_lock);
		INIT_LIST_HEAD(&llmd->llmd_ost_list);
		INIT_LIST_HEAD(&llmd->llmd_ost_phase1_list);
		INIT_LIST_HEAD(&llmd->llmd_ost_phase2_list);
		INIT_LIST_HEAD(&llmd->llmd_mdt_list);
		INIT_LIST_HEAD(&llmd->llmd_mdt_phase1_list);
		INIT_LIST_HEAD(&llmd->llmd_mdt_phase2_list);
		init_waitqueue_head(&llmd->llmd_thread.t_ctl_waitq);
		com->lc_data = llmd;
	} else {
		struct lfsck_layout_slave_data *llsd;

		com->lc_ops = &lfsck_layout_slave_ops;
		OBD_ALLOC_PTR(llsd);
		if (llsd == NULL)
			GOTO(out, rc = -ENOMEM);

		INIT_LIST_HEAD(&llsd->llsd_seq_list);
		INIT_LIST_HEAD(&llsd->llsd_master_list);
		spin_lock_init(&llsd->llsd_lock);
		com->lc_data = llsd;
	}
	com->lc_file_size = sizeof(*lo);
	OBD_ALLOC(com->lc_file_ram, com->lc_file_size);
	if (com->lc_file_ram == NULL)
		GOTO(out, rc = -ENOMEM);

	OBD_ALLOC(com->lc_file_disk, com->lc_file_size);
	if (com->lc_file_disk == NULL)
		GOTO(out, rc = -ENOMEM);

	root = dt_locate(env, lfsck->li_bottom, &lfsck->li_local_root_fid);
	if (IS_ERR(root))
		GOTO(out, rc = PTR_ERR(root));

	if (unlikely(!dt_try_as_dir(env, root)))
		GOTO(out, rc = -ENOTDIR);

	obj = local_file_find_or_create(env, lfsck->li_los, root,
					lfsck_layout_name,
					S_IFREG | S_IRUGO | S_IWUSR);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	com->lc_obj = obj;
	rc = lfsck_layout_load(env, com);
	if (rc > 0)
		rc = lfsck_layout_reset(env, com, true);
	else if (rc == -ENOENT)
		rc = lfsck_layout_init(env, com);

	if (rc != 0)
		GOTO(out, rc);

	lo = com->lc_file_ram;
	switch (lo->ll_status) {
	case LS_INIT:
	case LS_COMPLETED:
	case LS_FAILED:
	case LS_STOPPED:
	case LS_PARTIAL:
		spin_lock(&lfsck->li_lock);
		list_add_tail(&com->lc_link, &lfsck->li_list_idle);
		spin_unlock(&lfsck->li_lock);
		break;
	default:
		CERROR("%s: unknown lfsck_layout status: rc = %u\n",
		       lfsck_lfsck2name(lfsck), lo->ll_status);
		/* fall through */
	case LS_SCANNING_PHASE1:
	case LS_SCANNING_PHASE2:
		/* No need to store the status to disk right now.
		 * If the system crashed before the status stored,
		 * it will be loaded back when next time. */
		lo->ll_status = LS_CRASHED;
		lo->ll_flags |= LF_INCOMPLETE;
		/* fall through */
	case LS_PAUSED:
	case LS_CRASHED:
	case LS_CO_FAILED:
	case LS_CO_STOPPED:
	case LS_CO_PAUSED:
		spin_lock(&lfsck->li_lock);
		list_add_tail(&com->lc_link, &lfsck->li_list_scan);
		spin_unlock(&lfsck->li_lock);
		break;
	}

	if (lo->ll_flags & LF_CRASHED_LASTID) {
		LASSERT(lfsck->li_out_notify != NULL);

		lfsck->li_out_notify(env, lfsck->li_out_notify_data,
				     LE_LASTID_REBUILDING);
	}

	GOTO(out, rc = 0);

out:
	if (root != NULL && !IS_ERR(root))
		lu_object_put(env, &root->do_lu);

	if (rc != 0)
		lfsck_component_cleanup(env, com);

	return rc;
}
