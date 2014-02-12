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
#include <linux/rbtree.h>

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
	/* The position for next record in the rbtree for iteration. */
	struct lu_fid		llst_fid;
	/* Dummy hash for iteration against the rbtree. */
	__u64			llst_hash;
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
	struct dt_object	*llsd_rb_obj;
	struct rb_root		 llsd_rb_root;
	rwlock_t		 llsd_rb_lock;
	unsigned int		 llsd_rbtree_valid:1;
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
			       __u32 index, bool unlink)
{
	struct lfsck_layout_slave_target *llst;

	spin_lock(&llsd->llsd_lock);
	list_for_each_entry(llst, &llsd->llsd_master_list, llst_list) {
		if (llst->llst_index == index) {
			if (unlink)
				list_del_init(&llst->llst_list);
			else
				atomic_inc(&llst->llst_ref);
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

#define LFSCK_RBTREE_BITMAP_SIZE	PAGE_CACHE_SIZE
#define LFSCK_RBTREE_BITMAP_WIDTH	(LFSCK_RBTREE_BITMAP_SIZE << 3)
#define LFSCK_RBTREE_BITMAP_MASK	(LFSCK_RBTREE_BITMAP_SIZE - 1)

struct lfsck_rbtree_node {
	struct rb_node	 lrn_node;
	__u64		 lrn_seq;
	__u32		 lrn_first_oid;
	atomic_t	 lrn_known_count;
	atomic_t	 lrn_accessed_count;
	void		*lrn_known_bitmap;
	void		*lrn_accessed_bitmap;
};

static inline int lfsck_rbtree_cmp(struct lfsck_rbtree_node *lrn,
				   __u64 seq, __u32 oid)
{
	if (seq < lrn->lrn_seq)
		return -1;

	if (seq > lrn->lrn_seq)
		return 1;

	if (oid < lrn->lrn_first_oid)
		return -1;

	if (oid >= lrn->lrn_first_oid + LFSCK_RBTREE_BITMAP_WIDTH)
		return 1;

	return 0;
}

/* The caller should hold llsd->llsd_rb_lock. */
static struct lfsck_rbtree_node *
lfsck_rbtree_search(struct lfsck_layout_slave_data *llsd,
		    const struct lu_fid *fid, bool *exact)
{
	struct rb_node		 *node	= llsd->llsd_rb_root.rb_node;
	struct rb_node		 *prev	= NULL;
	struct lfsck_rbtree_node *lrn	= NULL;
	int			  rc	= 0;

	if (exact != NULL)
		*exact = true;

	while (node != NULL) {
		prev = node;
		lrn = rb_entry(node, struct lfsck_rbtree_node, lrn_node);
		rc = lfsck_rbtree_cmp(lrn, fid_seq(fid), fid_oid(fid));
		if (rc < 0)
			node = node->rb_left;
		else if (rc > 0)
			node = node->rb_right;
		else
			return lrn;
	}

	if (exact == NULL)
		return NULL;

	/* If there is no exactly matched one, then to the next valid one. */
	*exact = false;

	/* The rbtree is empty. */
	if (rc == 0)
		return NULL;

	if (rc < 0)
		return lrn;

	node = rb_next(prev);

	/* The end of the rbtree. */
	if (node == NULL)
		return NULL;

	lrn = rb_entry(node, struct lfsck_rbtree_node, lrn_node);

	return lrn;
}

static struct lfsck_rbtree_node *lfsck_rbtree_new(const struct lu_env *env,
						  const struct lu_fid *fid)
{
	struct lfsck_rbtree_node *lrn;

	OBD_ALLOC_PTR(lrn);
	if (lrn == NULL)
		return ERR_PTR(-ENOMEM);

	OBD_ALLOC(lrn->lrn_known_bitmap, LFSCK_RBTREE_BITMAP_SIZE);
	if (lrn->lrn_known_bitmap == NULL) {
		OBD_FREE_PTR(lrn);

		return ERR_PTR(-ENOMEM);
	}

	OBD_ALLOC(lrn->lrn_accessed_bitmap, LFSCK_RBTREE_BITMAP_SIZE);
	if (lrn->lrn_accessed_bitmap == NULL) {
		OBD_FREE(lrn->lrn_known_bitmap, LFSCK_RBTREE_BITMAP_SIZE);
		OBD_FREE_PTR(lrn);

		return ERR_PTR(-ENOMEM);
	}

	rb_init_node(&lrn->lrn_node);
	lrn->lrn_seq = fid_seq(fid);
	lrn->lrn_first_oid = fid_oid(fid) & ~LFSCK_RBTREE_BITMAP_MASK;
	atomic_set(&lrn->lrn_known_count, 0);
	atomic_set(&lrn->lrn_accessed_count, 0);

	return lrn;
}

static void lfsck_rbtree_free(struct lfsck_rbtree_node *lrn)
{
	OBD_FREE(lrn->lrn_accessed_bitmap, LFSCK_RBTREE_BITMAP_SIZE);
	OBD_FREE(lrn->lrn_known_bitmap, LFSCK_RBTREE_BITMAP_SIZE);
	OBD_FREE_PTR(lrn);
}

/* The caller should hold lock. */
static struct lfsck_rbtree_node *
lfsck_rbtree_insert(struct lfsck_layout_slave_data *llsd,
		    struct lfsck_rbtree_node *lrn)
{
	struct rb_node		 **pos    = &(llsd->llsd_rb_root.rb_node);
	struct rb_node		  *parent = NULL;
	struct lfsck_rbtree_node  *tmp;
	int			   rc;

	while (*pos) {
		parent = *pos;
		tmp = rb_entry(*pos, struct lfsck_rbtree_node, lrn_node);
		rc = lfsck_rbtree_cmp(tmp, lrn->lrn_seq, lrn->lrn_first_oid);
		if (rc < 0)
			pos = &((*pos)->rb_left);
		else if (rc > 0)
			pos = &((*pos)->rb_right);
		else
			return tmp;
	}

	rb_link_node(&lrn->lrn_node, parent, pos);
	rb_insert_color(&lrn->lrn_node, &llsd->llsd_rb_root);

	return lrn;
}

extern const struct dt_index_operations lfsck_orphan_index_ops;

static int lfsck_rbtree_setup(const struct lu_env *env,
			      struct lfsck_component *com)
{
	struct lu_fid			*fid	= &lfsck_env_info(env)->lti_fid;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck->li_bottom;
	struct lfsck_layout_slave_data	*llsd	= com->lc_data;
	struct dt_object		*obj;

	fid->f_seq = FID_SEQ_LAYOUT_RBTREE;
	fid->f_oid = lfsck_dev_idx(dev);
	fid->f_ver = 0;
	obj = dt_locate(env, dev, fid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	/* Generate an in-RAM object to stand for the layout rbtree.
	 * Scanning the layout rbtree will be via the iteration over
	 * the object. In the future, the rbtree may be written onto
	 * disk with the object.
	 *
	 * Mark the object to be as exist. */
	obj->do_lu.lo_header->loh_attr |= LOHA_EXISTS;
	obj->do_index_ops = &lfsck_orphan_index_ops;
	llsd->llsd_rb_obj = obj;
	llsd->llsd_rbtree_valid = 1;
	dev->dd_record_fid_accessed = 1;

	return 0;
}

static void lfsck_rbtree_cleanup(const struct lu_env *env,
				 struct lfsck_component *com)
{
	struct lfsck_instance		*lfsck = com->lc_lfsck;
	struct lfsck_layout_slave_data	*llsd  = com->lc_data;
	struct rb_node			*node  = rb_first(&llsd->llsd_rb_root);
	struct rb_node			*next;
	struct lfsck_rbtree_node	*lrn;

	lfsck->li_bottom->dd_record_fid_accessed = 0;
	/* Invalid the rbtree, then no others will use it. */
	write_lock(&llsd->llsd_rb_lock);
	llsd->llsd_rbtree_valid = 0;
	write_unlock(&llsd->llsd_rb_lock);

	while (node != NULL) {
		next = rb_next(node);
		lrn = rb_entry(node, struct lfsck_rbtree_node, lrn_node);
		rb_erase(node, &llsd->llsd_rb_root);
		lfsck_rbtree_free(lrn);
		node = next;
	}

	if (llsd->llsd_rb_obj != NULL) {
		lu_object_put(env, &llsd->llsd_rb_obj->do_lu);
		llsd->llsd_rb_obj = NULL;
	}
}

static void lfsck_rbtree_update_bitmap(const struct lu_env *env,
				       struct lfsck_component *com,
				       const struct lu_fid *fid,
				       bool accessed)
{
	struct lfsck_layout_slave_data	*llsd	= com->lc_data;
	struct lfsck_rbtree_node	*lrn;
	bool				 insert = false;
	int				 idx;
	int				 rc	= 0;
	ENTRY;

	CDEBUG(D_LFSCK, "%s: update bitmap for "DFID"\n",
	       lfsck_lfsck2name(com->lc_lfsck), PFID(fid));

	if (unlikely(!fid_is_sane(fid) || fid_is_last_id(fid)))
		RETURN_EXIT;

	if (!fid_is_idif(fid) && !fid_is_norm(fid))
		RETURN_EXIT;

	read_lock(&llsd->llsd_rb_lock);
	if (!llsd->llsd_rbtree_valid)
		GOTO(unlock, rc = 0);

	lrn = lfsck_rbtree_search(llsd, fid, NULL);
	if (lrn == NULL) {
		struct lfsck_rbtree_node *tmp;

		LASSERT(!insert);

		read_unlock(&llsd->llsd_rb_lock);
		tmp = lfsck_rbtree_new(env, fid);
		if (IS_ERR(tmp))
			GOTO(out, rc = PTR_ERR(tmp));

		insert = true;
		write_lock(&llsd->llsd_rb_lock);
		if (!llsd->llsd_rbtree_valid) {
			lfsck_rbtree_free(tmp);
			GOTO(unlock, rc = 0);
		}

		lrn = lfsck_rbtree_insert(llsd, tmp);
		if (lrn != tmp)
			lfsck_rbtree_free(tmp);
	}

	idx = fid_oid(fid) & LFSCK_RBTREE_BITMAP_MASK;
	/* Any accessed object must be a known object. */
	if (!test_and_set_bit(idx, lrn->lrn_known_bitmap))
		atomic_inc(&lrn->lrn_known_count);
	if (accessed && !test_and_set_bit(idx, lrn->lrn_accessed_bitmap))
		atomic_inc(&lrn->lrn_accessed_count);

	GOTO(unlock, rc = 0);

unlock:
	if (insert)
		write_unlock(&llsd->llsd_rb_lock);
	else
		read_unlock(&llsd->llsd_rb_lock);
out:
	if (rc != 0 && accessed) {
		struct lfsck_layout *lo = com->lc_file_ram;

		CERROR("%s: Fail to update object accessed bitmap, will cause "
		       "incorrect LFSCK OST-object handling, so disable it to "
		       "cancel orphan handling for related device. rc = %d.\n",
		       lfsck_lfsck2name(com->lc_lfsck), rc);
		lo->ll_flags |= LF_INCOMPLETE;
		lfsck_rbtree_cleanup(env, com);
	}
}

static inline bool is_dummy_lov_ost_data(struct lov_ost_data_v1 *obj)
{
	if (fid_is_zero(&obj->l_ost_oi.oi_fid) &&
	    obj->l_ost_gen == 0 && obj->l_ost_idx == 0)
		return true;

	return false;
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

			CERROR("%s: fail to notify %s %x for layout start: "
			       "rc = %d\n", lfsck_lfsck2name(com->lc_lfsck),
			       (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
			       ltd->ltd_index, rc);
			lo->ll_flags |= LF_INCOMPLETE;
			break;
		}

		spin_lock(&ltds->ltd_lock);
		if (ltd->ltd_dead || ltd->ltd_layout_done) {
			spin_unlock(&ltds->ltd_lock);
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
		break;
	case LE_STOP:
	case LE_PHASE1_DONE:
	case LE_PHASE2_DONE:
	case LE_PEER_EXIT:
		if (rc != 0 && rc != -EALREADY)
			CWARN("%s: fail to notify %s %x for layout: "
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
		break;
	}
	default:
		CERROR("%s: unexpected event: rc = %d\n",
		       lfsck_lfsck2name(com->lc_lfsck), lr->lr_event);
		break;
	}

	if (!laia->laia_shared) {
		lfsck_tgt_put(ltd);
		lfsck_component_put(env, com);
	}

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
	laia->laia_shared = 0;

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
		}
		spin_lock(&ltds->ltd_lock);
	}
	spin_unlock(&ltds->ltd_lock);

	rc = ptlrpc_set_wait(set);
	if (rc < 0) {
		ptlrpc_set_destroy(set);
		RETURN(rc);
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
					     struct lfsck_request *lr)
{
	struct lfsck_thread_info	  *info  = lfsck_env_info(env);
	struct lfsck_async_interpret_args *laia  = &info->lti_laia;
	struct lfsck_instance		  *lfsck = com->lc_lfsck;
	struct lfsck_layout_master_data	  *llmd  = com->lc_data;
	struct lfsck_layout		  *lo	 = com->lc_file_ram;
	struct lfsck_bookmark		  *bk    = &lfsck->li_bookmark_ram;
	struct ptlrpc_request_set	  *set;
	struct lfsck_tgt_descs		  *ltds;
	struct lfsck_tgt_desc		  *ltd;
	struct lfsck_tgt_desc		  *next;
	struct list_head		  *head;
	__u32				   idx;
	int				   rc    = 0;
	ENTRY;

	set = ptlrpc_prep_set();
	if (set == NULL)
		RETURN(-ENOMEM);

	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	lr->lr_active = LT_LAYOUT;
	laia->laia_com = com;
	laia->laia_lr = lr;
	laia->laia_shared = 0;
	switch (lr->lr_event) {
	case LE_START:
		/* Notify OSTs firstly, then handle other MDTs if needed. */
		ltds = &lfsck->li_ost_descs;
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
			}
		}
		up_read(&ltds->ltd_rw_sem);

		/* Sync up */
		rc = ptlrpc_set_wait(set);
		if (rc < 0) {
			ptlrpc_set_destroy(set);
			RETURN(rc);
		}

		if (!(bk->lb_param & LPF_ALL_TGT))
			break;

		/* link other MDT targets locallly. */
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
	case LE_PHASE2_DONE:
	case LE_PEER_EXIT: {
		/* Handle other MDTs firstly if needed, then notify the OSTs. */
		if (bk->lb_param & LPF_ALL_TGT) {
			head = &llmd->llmd_mdt_list;
			ltds = &lfsck->li_mdt_descs;
			if (lr->lr_event == LE_STOP) {
				/* unlink other MDT targets locallly. */
				spin_lock(&ltds->ltd_lock);
				list_for_each_entry_safe(ltd, next, head,
							 ltd_layout_list) {
					list_del_init(&ltd->ltd_layout_phase_list);
					list_del_init(&ltd->ltd_layout_list);
				}
				spin_unlock(&ltds->ltd_lock);

				lr->lr_flags |= LEF_TO_OST;
				head = &llmd->llmd_ost_list;
				ltds = &lfsck->li_ost_descs;
			} else {
				lr->lr_flags &= ~LEF_TO_OST;
			}
		} else {
			lr->lr_flags |= LEF_TO_OST;
			head = &llmd->llmd_ost_list;
			ltds = &lfsck->li_ost_descs;
		}

again:
		laia->laia_ltds = ltds;
		spin_lock(&ltds->ltd_lock);
		while (!list_empty(head)) {
			ltd = list_entry(head->next, struct lfsck_tgt_desc,
					 ltd_layout_list);
			if (!list_empty(&ltd->ltd_layout_phase_list))
				list_del_init(&ltd->ltd_layout_phase_list);
			list_del_init(&ltd->ltd_layout_list);
			atomic_inc(&ltd->ltd_ref);
			laia->laia_ltd = ltd;
			spin_unlock(&ltds->ltd_lock);
			rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					lfsck_layout_master_async_interpret,
					laia, LFSCK_NOTIFY);
			if (rc != 0) {
				CERROR("%s: fail to notify %s %x for layout "
				       "stop/phase2: rc = %d\n",
				       lfsck_lfsck2name(lfsck),
				       (lr->lr_flags & LEF_TO_OST) ? "OST" :
				       "MDT", ltd->ltd_index, rc);
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

		if (!(lr->lr_flags & LEF_TO_OST)) {
			lr->lr_flags |= LEF_TO_OST;
			head = &llmd->llmd_ost_list;
			ltds = &lfsck->li_ost_descs;
			goto again;
		}
		break;
	}
	case LE_PHASE1_DONE:
		llmd->llmd_touch_gen++;
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
			atomic_inc(&ltd->ltd_ref);
			laia->laia_ltd = ltd;
			spin_unlock(&ltds->ltd_lock);
			rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
					lfsck_layout_master_async_interpret,
					laia, LFSCK_NOTIFY);
			if (rc != 0) {
				CERROR("%s: fail to notify MDT %x for layout "
				       "phase1 done: rc = %d\n",
				       lfsck_lfsck2name(lfsck),
				       ltd->ltd_index, rc);
				lfsck_tgt_put(ltd);
			}
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

	rc = ptlrpc_set_wait(set);
	ptlrpc_set_destroy(set);

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

/**
 * \retval	 +1: repaired
 * \retval	  0: did nothing
 * \retval	-ve: on error
 */
static int lfsck_layout_refill_lovea(const struct lu_env *env,
				     struct thandle *handle,
				     struct dt_object *parent,
				     struct lu_fid *cfid,
				     struct lu_buf *buf,
				     struct lov_ost_data_v1 *slot,
				     int fl, __u32 ost_idx)
{
	struct ost_id	*oi	= &lfsck_env_info(env)->lti_oi;
	int		 rc;

	fid_to_ostid(cfid, oi);
	ostid_cpu_to_le(oi, &slot->l_ost_oi);
	slot->l_ost_gen = cpu_to_le32(0);
	slot->l_ost_idx = cpu_to_le32(ost_idx);
	rc = dt_xattr_set(env, parent, buf, XATTR_NAME_LOV, fl, handle,
			  BYPASS_CAPA);
	if (rc == 0)
		rc = 1;

	return rc;
}

/**
 * \retval	 +1: repaired
 * \retval	  0: did nothing
 * \retval	-ve: on error
 */
static int lfsck_layout_extend_lovea(const struct lu_env *env,
				     struct thandle *handle,
				     struct dt_object *parent,
				     struct lu_fid *cfid,
				     struct lu_buf *buf, int fl,
				     __u32 ost_idx, __u32 ea_off)
{
	struct lov_mds_md_v1	*lmm	= buf->lb_buf;
	struct lov_ost_data_v1	*objs;
	int			 rc;
	ENTRY;

	if (fl == LU_XATTR_CREATE) {
		LASSERT(buf->lb_len == lov_mds_md_size(ea_off + 1,
						       LOV_MAGIC_V1));

		memset(lmm, 0, buf->lb_len);
		lmm->lmm_magic = cpu_to_le32(LOV_MAGIC_V1);
		/* XXX: currently, we only support LOV_PATTERN_RAID0. */
		lmm->lmm_pattern = cpu_to_le32(LOV_PATTERN_RAID0);
		fid_to_lmm_oi(lfsck_dto2fid(parent), &lmm->lmm_oi);
		lmm_oi_cpu_to_le(&lmm->lmm_oi, &lmm->lmm_oi);
		/* XXX: We cannot know the stripe size,
		 *	then use the default value (1 MB). */
		lmm->lmm_stripe_size = cpu_to_le32(1024 * 1024);
		lmm->lmm_layout_gen = cpu_to_le16(0);
		objs = &(lmm->lmm_objects[ea_off]);
	} else {
		__u16	count = le16_to_cpu(lmm->lmm_stripe_count);
		int	gap   = ea_off - count;
		__u32	magic = le32_to_cpu(lmm->lmm_magic);

		/* Currently, we only support LOV_MAGIC_V1/LOV_MAGIC_V3
		 * which has been verified in lfsck_layout_verify_header()
		 * already. If some new magic introduced in the future,
		 * then layout LFSCK needs to be updated also. */
		if (magic == LOV_MAGIC_V1) {
			objs = &(lmm->lmm_objects[count]);
		} else {
			LASSERT(magic == LOV_MAGIC_V3);
			objs = &((struct lov_mds_md_v3 *)lmm)->
							lmm_objects[count];
		}

		if (gap > 0)
			memset(objs, 0, gap * sizeof(*objs));
		lmm->lmm_layout_gen =
			    cpu_to_le16(le16_to_cpu(lmm->lmm_layout_gen) + 1);
		objs += gap;

		LASSERT(buf->lb_len == lov_mds_md_size(ea_off + 1, magic));
	}

	lmm->lmm_stripe_count = cpu_to_le16(ea_off + 1);
	rc = lfsck_layout_refill_lovea(env, handle, parent, cfid, buf, objs,
				       fl, ost_idx);

	RETURN(rc);
}

/**
 * \retval	 +1: repaired
 * \retval	  0: did nothing
 * \retval	-ve: on error
 */
static int lfsck_layout_update_pfid(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct dt_object *parent,
				    struct lu_fid *cfid,
				    struct dt_device *cdev, __u32 ea_off)
{
	struct filter_fid	*pfid	= &lfsck_env_info(env)->lti_new_pfid;
	struct dt_object	*child;
	struct thandle		*handle;
	const struct lu_fid	*tfid	= lu_object_fid(&parent->do_lu);
	struct lu_buf		*buf;
	int			 rc	= 0;
	ENTRY;

	child = lfsck_object_find_by_dev(env, cdev, cfid);
	if (IS_ERR(child))
		RETURN(PTR_ERR(child));

	handle = dt_trans_create(env, cdev);
	if (IS_ERR(handle))
		GOTO(out, rc = PTR_ERR(handle));

	pfid->ff_parent.f_seq = cpu_to_le64(tfid->f_seq);
	pfid->ff_parent.f_oid = cpu_to_le32(tfid->f_oid);
	/* In fact, the ff_parent::f_ver is not the real parent FID::f_ver,
	 * instead, it is the OST-object index in its parent MDT-object
	 * layout EA. */
	pfid->ff_parent.f_ver = cpu_to_le32(ea_off);
	buf = lfsck_buf_get(env, pfid, sizeof(struct filter_fid));

	rc = dt_declare_xattr_set(env, child, buf, XATTR_NAME_FID, 0, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start(env, cdev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_xattr_set(env, child, buf, XATTR_NAME_FID, 0, handle,
			  BYPASS_CAPA);

	GOTO(stop, rc = (rc == 0 ? 1 : rc));

stop:
	dt_trans_stop(env, cdev, handle);

out:
	lu_object_put(env, &child->do_lu);

	return rc;
}

/**
 * \retval	 +1: repaired
 * \retval	  0: did nothing
 * \retval	-ve: on error
 */
static int lfsck_layout_recreate_parent(const struct lu_env *env,
					struct lfsck_component *com,
					struct lfsck_tgt_desc *ltd,
					struct lu_orphan_rec *rec,
					struct lu_fid *cfid,
					const char *prefix,
					const char *postfix,
					__u32 ea_off)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	char				*name	= info->lti_key;
	struct lu_attr			*la	= &info->lti_la;
	struct dt_object_format 	*dof	= &info->lti_dof;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lu_fid			*pfid	= &rec->lor_fid;
	struct lu_fid			*tfid	= &info->lti_fid3;
	struct dt_device		*next	= lfsck->li_next;
	struct dt_object		*pobj	= NULL;
	struct dt_object		*cobj	= NULL;
	struct thandle			*th	= NULL;
	struct lu_buf			*pbuf	= NULL;
	struct lu_buf			*ea_buf = &info->lti_big_buf;
	int				 buflen = ea_buf->lb_len;
	int				 rc	= 0;
	ENTRY;

	/* Create .lustre/lost+found/MDTxxxx when needed. */
	if (unlikely(lfsck->li_lpf_obj == NULL)) {
		rc = lfsck_create_lpf(env, lfsck);
		if (rc != 0)
			RETURN(rc);
	}

	if (fid_is_zero(pfid)) {
		struct filter_fid *ff = &info->lti_new_pfid;

		rc = lfsck_fid_alloc(env, lfsck, pfid, false);
		if (rc != 0)
			RETURN(rc);

		ff->ff_parent.f_seq = cpu_to_le64(pfid->f_seq);
		ff->ff_parent.f_oid = cpu_to_le32(pfid->f_oid);
		/* In fact, the ff_parent::f_ver is not the real parent FID::f_ver,
		 * instead, it is the OST-object index in its parent MDT-object
		 * layout EA. */
		ff->ff_parent.f_ver = cpu_to_le32(ea_off);
		pbuf = lfsck_buf_get(env, ff, sizeof(struct filter_fid));
		cobj = lfsck_object_find_by_dev(env, ltd->ltd_tgt, cfid);
		if (IS_ERR(cobj))
			RETURN(PTR_ERR(cobj));
	}

	CDEBUG(D_LFSCK, "Re-create the lost MDT-object: parent "
	       DFID", child "DFID", OST-index %u, stripe-index %u, "
	       "prefix %s, postfix %s\n",
	       PFID(pfid), PFID(cfid), ltd->ltd_index, ea_off, prefix, postfix);

	pobj = lfsck_object_find_by_dev(env, lfsck->li_bottom, pfid);
	if (IS_ERR(pobj))
		GOTO(put, rc = PTR_ERR(pobj));

	LASSERT(prefix != NULL);
	LASSERT(postfix != NULL);

	/** name rules:
	 *
	 *  1. Use the MDT-object's FID as the name with prefix and postfix.
	 *
	 *  1.1 prefix "C-":	More than one OST-objects cliam the same
	 *			MDT-object and the same slot in the layout EA.
	 *			It may be created for dangling referenced MDT
	 *			object or may be not.
	 *  1.2 prefix "N-":	The orphan OST-object does not know which one
	 *			is the real parent, so the LFSCK assign a new
	 *			FID as its parent.
	 *  1.3 prefix "R-":	The orphan OST-object know its parent FID but
	 *			does not know the position in the namespace.
	 *
	 *  2. If there is name conflict, increase FID::f_ver for new name. */
	sprintf(name, "%s"DFID"%s", prefix, PFID(pfid), postfix);
	do {
		rc = dt_lookup(env, lfsck->li_lpf_obj, (struct dt_rec *)tfid,
			       (const struct dt_key *)name, BYPASS_CAPA);
		if (rc != 0 && rc != -ENOENT)
			GOTO(put, rc);

		if (unlikely(rc == 0)) {
			CWARN("%s: The name %s under lost+found has been used "
			      "by the "DFID". Try to increase the FID version "
			      "for the new file name.\n",
			      lfsck_lfsck2name(lfsck), name, PFID(tfid));
			*tfid = *pfid;
			tfid->f_ver++;
			sprintf(name, "%s"DFID"%s", prefix, PFID(tfid), postfix);
		}
	} while (rc == 0);

	memset(la, 0, sizeof(*la));
	la->la_uid = rec->lor_uid;
	la->la_gid = rec->lor_gid;
	la->la_mode = S_IFREG | S_IRUSR | S_IWUSR;
	la->la_valid = LA_MODE | LA_UID | LA_GID;

	memset(dof, 0, sizeof(*dof));
	dof->dof_type = dt_mode_to_dft(S_IFREG);

	rc = lov_mds_md_size(ea_off + 1, LOV_MAGIC_V1);
	if (buflen < rc) {
		lu_buf_realloc(ea_buf, rc);
		buflen = ea_buf->lb_len;
		if (ea_buf->lb_buf == NULL)
			GOTO(put, rc = -ENOMEM);
	} else {
		ea_buf->lb_len = rc;
	}

	th = dt_trans_create(env, next);
	if (IS_ERR(th))
		GOTO(put, rc = PTR_ERR(th));

	/* 1a. Update OST-object's parent information remotely.
	 *
	 * If other subsequent modifications failed, then next LFSCK scanning
	 * will process the OST-object as orphan again with known parent FID. */
	if (cobj != NULL) {
		rc = dt_declare_xattr_set(env, cobj, pbuf, XATTR_NAME_FID, 0, th);
		if (rc != 0)
			GOTO(stop, rc);
	}

	/* 2a. Create the MDT-object locally. */
	rc = dt_declare_create(env, pobj, la, NULL, dof, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 3a. Add layout EA for the MDT-object. */
	rc = dt_declare_xattr_set(env, pobj, ea_buf, XATTR_NAME_LOV,
				  LU_XATTR_CREATE, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 4a. Insert the MDT-object to .lustre/lost+found/MDTxxxx/ */
	rc = dt_declare_insert(env, lfsck->li_lpf_obj,
			       (const struct dt_rec *)pfid,
			       (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start(env, next, th);
	if (rc != 0)
		GOTO(stop, rc);

	/* 1b. Update OST-object's parent information remotely. */
	if (cobj != NULL) {
		rc = dt_xattr_set(env, cobj, pbuf, XATTR_NAME_FID, 0, th,
				  BYPASS_CAPA);
		if (rc != 0)
			GOTO(stop, rc);
	}

	dt_write_lock(env, pobj, 0);
	/* 2b. Create the MDT-object locally. */
	rc = dt_create(env, pobj, la, NULL, dof, th);
	if (rc == 0)
		/* 3b. Add layout EA for the MDT-object. */
		rc = lfsck_layout_extend_lovea(env, th, pobj, cfid, ea_buf,
					       LU_XATTR_CREATE, ltd->ltd_index,
					       ea_off);
	dt_write_unlock(env, pobj);
	if (rc < 0)
		GOTO(stop, rc);

	/* 4b. Insert the MDT-object to .lustre/lost+found/MDTxxxx/ */
	rc = dt_insert(env, lfsck->li_lpf_obj,
		       (const struct dt_rec *)pfid,
		       (const struct dt_key *)name, th, BYPASS_CAPA, 1);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, next, th);
put:
	if (cobj != NULL && !IS_ERR(cobj))
		lu_object_put(env, &cobj->do_lu);
	if (pobj != NULL && !IS_ERR(pobj))
		lu_object_put(env, &pobj->do_lu);
	ea_buf->lb_len = buflen;

	return rc >= 0 ? 1 : rc;
}

static int lfsck_layout_master_conditional_destroy(const struct lu_env *env,
						   struct lfsck_component *com,
						   const struct lu_fid *fid,
						   __u32 index)
{
	struct lfsck_thread_info *info	= lfsck_env_info(env);
	struct lfsck_request	 *lr	= &info->lti_lr;
	struct lfsck_instance	 *lfsck = com->lc_lfsck;
	struct lfsck_tgt_desc	 *ltd;
	struct ptlrpc_request	 *req;
	struct lfsck_request	 *tmp;
	struct obd_export	 *exp;
	int			  rc	= 0;
	ENTRY;

	ltd = lfsck_tgt_get(&lfsck->li_ost_descs, index);
	if (unlikely(ltd == NULL))
		RETURN(-ENODEV);

	exp = ltd->ltd_exp;
	if (!(exp_connect_flags(exp) & OBD_CONNECT_LFSCK))
		GOTO(put, rc = -EOPNOTSUPP);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_LFSCK_NOTIFY);
	if (req == NULL)
		GOTO(put, rc = -ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OBD_VERSION, LFSCK_NOTIFY);
	if (rc != 0) {
		ptlrpc_request_free(req);

		GOTO(put, rc);
	}

	memset(lr, 0, sizeof(*lr));
	lr->lr_event = LE_CONDITIONAL_DESTROY;
	lr->lr_active = LT_LAYOUT;
	lr->lr_fid = *fid;

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_LFSCK_REQUEST);
	*tmp = *lr;
	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	ptlrpc_req_finished(req);

	GOTO(put, rc);

put:
	lfsck_tgt_put(ltd);

	return rc;
}

static int lfsck_layout_slave_conditional_destroy(const struct lu_env *env,
						  struct lfsck_component *com,
						  struct lfsck_request *lr)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_attr			*la	= &info->lti_la;
	ldlm_policy_data_t		*policy = &info->lti_policy;
	struct ldlm_res_id		*resid	= &info->lti_resid;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck->li_bottom;
	struct lu_fid			*fid	= &lr->lr_fid;
	struct dt_object		*obj;
	struct thandle			*th	= NULL;
	struct lustre_handle		 lh	= { 0 };
	__u64				 flags	= 0;
	int				 rc	= 0;
	ENTRY;

	obj = lfsck_object_find_by_dev(env, dev, fid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	dt_read_lock(env, obj, 0);
	if (dt_object_exists(obj) == 0) {
		dt_read_unlock(env, obj);

		GOTO(put, rc = -ENOENT);
	}

	/* Get obj's attr without lock firstly. */
	rc = dt_attr_get(env, obj, la, BYPASS_CAPA);
	dt_read_unlock(env, obj);
	if (rc != 0)
		GOTO(put, rc);

	if (likely(la->la_ctime != 0 || la->la_mode & S_ISUID))
		GOTO(put, rc = -ETXTBSY);

	/* Acquire extent lock on [0, EOF] to sync with all possible written. */
	LASSERT(lfsck->li_namespace != NULL);

	memset(policy, 0, sizeof(*policy));
	policy->l_extent.end = OBD_OBJECT_EOF;
	ost_fid_build_resid(fid, resid);
	rc = ldlm_cli_enqueue_local(lfsck->li_namespace, resid, LDLM_EXTENT,
				    policy, LCK_EX, &flags, ldlm_blocking_ast,
				    ldlm_completion_ast, NULL, NULL, 0,
				    LVB_T_NONE, NULL, &lh);
	if (rc != ELDLM_OK)
		GOTO(put, rc = -EIO);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock1, rc = PTR_ERR(th));

	rc = dt_declare_ref_del(env, obj, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_destroy(env, obj, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	/* Get obj's attr within lock again. */
	rc = dt_attr_get(env, obj, la, BYPASS_CAPA);
	if (rc != 0)
		GOTO(unlock2, rc);

	if (la->la_ctime != 0)
		GOTO(unlock2, rc = -ETXTBSY);

	rc = dt_ref_del(env, obj, th);
	if (rc != 0)
		GOTO(unlock2, rc);

	rc = dt_destroy(env, obj, th);
	if (rc == 0)
		CDEBUG(D_LFSCK, "Destroy the empty OST-object "DFID" which "
		       "was created for reparing dangling referenced case. "
		       "But the original missed OST-object is found now.\n",
		       PFID(fid));

	GOTO(unlock2, rc);

unlock2:
	dt_write_unlock(env, obj);

stop:
	dt_trans_stop(env, dev, th);

unlock1:
	ldlm_lock_decref(&lh, LCK_EX);

put:
	lu_object_put(env, &obj->do_lu);

	return rc;
}

/**
 * Some OST-object has occupied the specified layout EA slot.
 * Such OST-object may be generated by the LFSCK when repair
 * dangling referenced MDT-object, which can be indicated by
 * attr::la_ctime == 0 but without S_ISUID in la_mode. If it
 * is true and such OST-object has not been modified yet, we
 * will replace it with the orphan OST-object; otherwise the
 * LFSCK will create new MDT-object to reference the orphan.
 *
 * \retval	 +1: repaired
 * \retval	  0: did nothing
 * \retval	-ve: on error
 */
static int lfsck_layout_conflict_create(const struct lu_env *env,
					struct lfsck_component *com,
					struct lfsck_tgt_desc *ltd,
					struct lu_orphan_rec *rec,
					struct dt_object *parent,
					struct lu_fid *cfid,
					struct lu_buf *ea_buf,
					struct lov_ost_data_v1 *slot,
					__u32 ea_off, __u32 ori_len)
{
	struct lfsck_thread_info *info		= lfsck_env_info(env);
	struct lu_fid		 *cfid2		= &info->lti_fid2;
	struct ost_id		 *oi		= &info->lti_oi;
	struct lov_mds_md_v1	 *lmm		= ea_buf->lb_buf;
	struct dt_device	 *dev		= com->lc_lfsck->li_bottom;
	struct thandle		 *th		= NULL;
	struct lustre_handle	  lh		= { 0 };
	char			  postfix[64];
	__u32			  ost_idx2	= le32_to_cpu(slot->l_ost_idx);
	int			  rc		= 0;
	ENTRY;

	ostid_le_to_cpu(&slot->l_ost_oi, oi);
	ostid_to_fid(cfid2, oi, ost_idx2);

	CDEBUG(D_LFSCK, "Handle layout EA conflict: parent "DFID
	       ", cur-child "DFID" on the OST %u, orphan-child "
	       DFID" on the OST %u, stripe-index %u\n",
	       PFID(lfsck_dto2fid(parent)), PFID(cfid2), ost_idx2,
	       PFID(cfid), ltd->ltd_index, ea_off);

	/* Hold layout lock on the parent to prevent others to access. */
	rc = lfsck_layout_lock(env, com, parent, &lh,
			       MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR);
	if (rc != 0)
		GOTO(out, rc);

	rc = lfsck_layout_master_conditional_destroy(env, com, cfid2, ost_idx2);

	/* If the conflict OST-obejct is not created for fixing dangling
	 * referenced MDT-object in former LFSCK check/repair, or it has
	 * been modified by others, then we cannot destroy it. Re-create
	 * a new MDT-object for the orphan OST-object. */
	if (rc == -ETXTBSY) {
		/* No need the layout lock on the original parent. */
		lfsck_layout_unlock(&lh);
		ea_buf->lb_len = ori_len;

		fid_zero(&rec->lor_fid);
		snprintf(postfix, 64, "-"DFID"-%x",
			 PFID(lu_object_fid(&parent->do_lu)), ea_off);
		rc = lfsck_layout_recreate_parent(env, com, ltd, rec, cfid,
						  "C-", postfix, ea_off);

		RETURN(rc);
	}

	if (rc != 0 && rc != -ENOENT)
		GOTO(unlock, rc);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_xattr_set(env, parent, ea_buf, XATTR_NAME_LOV,
				  LU_XATTR_REPLACE, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, parent, 0);
	lmm->lmm_layout_gen = cpu_to_le16(le16_to_cpu(lmm->lmm_layout_gen) + 1);
	rc = lfsck_layout_refill_lovea(env, th, parent, cfid, ea_buf, slot,
				       LU_XATTR_REPLACE, ltd->ltd_index);
	dt_write_unlock(env, parent);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);

unlock:
	lfsck_layout_unlock(&lh);

out:
	ea_buf->lb_len = ori_len;

	return rc >= 0 ? 1 : rc;
}

/**
 * \retval	 +1: repaired
 * \retval	  0: did nothing
 * \retval	-ve: on error
 */
static int lfsck_layout_recreate_lovea(const struct lu_env *env,
				       struct lfsck_component *com,
				       struct lfsck_tgt_desc *ltd,
				       struct lu_orphan_rec *rec,
				       struct dt_object *parent,
				       struct lu_fid *cfid,
				       __u32 ost_idx, __u32 ea_off)
{
	struct lfsck_thread_info *info		= lfsck_env_info(env);
	struct lu_buf		 *buf		= &info->lti_big_buf;
	struct lu_fid		 *fid		= &info->lti_fid2;
	struct ost_id		 *oi		= &info->lti_oi;
	struct lfsck_instance	 *lfsck 	= com->lc_lfsck;
	struct dt_device	 *dt		= lfsck->li_bottom;
	struct lfsck_bookmark	 *bk		= &lfsck->li_bookmark_ram;
	struct thandle		  *handle	= NULL;
	size_t			  buflen	= buf->lb_len;
	struct lov_mds_md_v1	 *lmm;
	struct lov_ost_data_v1   *objs;
	struct lustre_handle	  lh		= { 0 };
	__u32			  magic;
	int			  fl		= 0;
	int			  rc;
	int			  rc1;
	int			  i;
	__u16			  count;
	ENTRY;

	CDEBUG(D_LFSCK, "Re-create the crashed layout EA: parent "
	       DFID", child "DFID", OST-index %u, stripe-index %u\n",
	       PFID(lfsck_dto2fid(parent)), PFID(cfid), ost_idx, ea_off);

	rc = lfsck_layout_lock(env, com, parent, &lh,
			       MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR);
	if (rc != 0)
		RETURN(rc);

again:
	if (!(bk->lb_param & LPF_DRYRUN)) {
		handle = dt_trans_create(env, dt);
		if (IS_ERR(handle))
			GOTO(unlock_layout, rc = PTR_ERR(handle));

		rc = dt_declare_xattr_set(env, parent, buf, XATTR_NAME_LOV,
					  fl, handle);
		if (rc != 0)
			GOTO(stop, rc);

		rc = dt_trans_start_local(env, dt, handle);
		if (rc != 0)
			GOTO(stop, rc);
	}

	dt_write_lock(env, parent, 0);
	rc = dt_xattr_get(env, parent, buf, XATTR_NAME_LOV, BYPASS_CAPA);
	if (rc == -ERANGE) {
		rc = dt_xattr_get(env, parent, &LU_BUF_NULL, XATTR_NAME_LOV,
				  BYPASS_CAPA);
		LASSERT(rc != 0);

		dt_write_unlock(env, parent);
		if (handle != NULL) {
			dt_trans_stop(env, dt, handle);
			handle = NULL;
		}

		if (rc < 0)
			GOTO(unlock_layout, rc);

		lu_buf_realloc(buf, rc);
		buflen = buf->lb_len;
		if (buf->lb_buf == NULL)
			GOTO(unlock_layout, rc = -ENOMEM);

		fl = LU_XATTR_REPLACE;
		goto again;
	} else if (rc == -ENODATA || rc == 0) {
		fl = LU_XATTR_CREATE;
	} else if (rc < 0) {
		GOTO(unlock_parent, rc);
	} else if (unlikely(buf->lb_len == 0)) {
		dt_write_unlock(env, parent);
		if (handle != NULL) {
			dt_trans_stop(env, dt, handle);
			handle = NULL;
		}

		lu_buf_alloc(buf, rc);
		buflen = buf->lb_len;
		if (buf->lb_buf == NULL)
			GOTO(unlock_layout, rc = -ENOMEM);

		fl = LU_XATTR_REPLACE;
		goto again;
	} else {
		fl = LU_XATTR_REPLACE;
	}

	if (fl == LU_XATTR_CREATE) {
		if (bk->lb_param & LPF_DRYRUN)
			GOTO(unlock_parent, rc = 1);

		rc = lov_mds_md_size(ea_off + 1, LOV_MAGIC_V1);
		/* If the declared is not big enough, re-try. */
		if (buf->lb_len < rc) {
			dt_write_unlock(env, parent);
			if (handle != NULL) {
				dt_trans_stop(env, dt, handle);
				handle = NULL;
			}

			lu_buf_realloc(buf, rc);
			buflen = buf->lb_len;
			if (buf->lb_buf == NULL)
				GOTO(unlock_layout, rc = -ENOMEM);

			goto again;
		}

		buf->lb_len = rc;
		rc = lfsck_layout_extend_lovea(env, handle, parent, cfid, buf,
					       fl, ost_idx, ea_off);

		GOTO(unlock_parent, rc);
	}

	lmm = buf->lb_buf;
	rc1 = lfsck_layout_verify_header(lmm);
	if (rc1 != 0)
		GOTO(unlock_parent, rc = rc1);

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
	if (count == 0)
		GOTO(unlock_parent, rc = -EINVAL);
	LASSERT(count > 0);

	/* Exceed the current end of MDT-object layout EA. Then extend it. */
	if (count <= ea_off) {
		if (bk->lb_param & LPF_DRYRUN)
			GOTO(unlock_parent, rc = 1);

		rc = lov_mds_md_size(ea_off + 1, LOV_MAGIC_V1);
		/* If the declared is not big enough, re-try. */
		if (buf->lb_len < rc) {
			dt_write_unlock(env, parent);
			if (handle != NULL) {
				dt_trans_stop(env, dt, handle);
				handle = NULL;
			}

			lu_buf_realloc(buf, rc);
			buflen = buf->lb_len;
			if (buf->lb_buf == NULL)
				GOTO(unlock_layout, rc = -ENOMEM);

			goto again;
		}

		buf->lb_len = rc;
		rc = lfsck_layout_extend_lovea(env, handle, parent, cfid, buf,
					       fl, ost_idx, ea_off);
		GOTO(unlock_parent, rc);
	}

	LASSERTF(rc > 0, "invalid rc = %d\n", rc);

	buf->lb_len = rc;
	for (i = 0; i < count; i++, objs++) {
		/* The MDT-object was created via lfsck_layout_recover_create()
		 * by others before, and we fill the dummy layout EA. */
		if (is_dummy_lov_ost_data(objs)) {
			if (i != ea_off)
				continue;

			if (bk->lb_param & LPF_DRYRUN)
				GOTO(unlock_parent, rc = 1);

			lmm->lmm_layout_gen =
			    cpu_to_le16(le16_to_cpu(lmm->lmm_layout_gen) + 1);
			rc = lfsck_layout_refill_lovea(env, handle, parent,
						       cfid, buf, objs, fl,
						       ost_idx);
			GOTO(unlock_parent, rc);
		}

		ostid_le_to_cpu(&objs->l_ost_oi, oi);
		ostid_to_fid(fid, oi, le32_to_cpu(objs->l_ost_idx));
		/* It should be rare case, the slot is there, but the LFSCK
		 * does not handle it during the first-phase cycle scanning. */
		if (unlikely(lu_fid_eq(fid, cfid))) {
			if (i == ea_off) {
				GOTO(unlock_parent, rc = 0);
			} else {
				/* Rare case that the OST-object index
				 * does not match the parent MDT-object
				 * layout EA. We trust the later one. */
				if (bk->lb_param & LPF_DRYRUN)
					GOTO(unlock_parent, rc = 1);

				dt_write_unlock(env, parent);
				if (handle != NULL)
					dt_trans_stop(env, dt, handle);
				lfsck_layout_unlock(&lh);
				buf->lb_len = buflen;
				rc = lfsck_layout_update_pfid(env, com, parent,
							cfid, ltd->ltd_tgt, i);

				RETURN(rc);
			}
		}
	}

	/* The MDT-object exists, but related layout EA slot is occupied
	 * by others. */
	if (bk->lb_param & LPF_DRYRUN)
		GOTO(unlock_parent, rc = 1);

	dt_write_unlock(env, parent);
	if (handle != NULL)
		dt_trans_stop(env, dt, handle);
	lfsck_layout_unlock(&lh);
	if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_V1)
		objs = &(lmm->lmm_objects[ea_off]);
	else
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[ea_off];
	rc = lfsck_layout_conflict_create(env, com, ltd, rec, parent, cfid,
					  buf, objs, ea_off, buflen);

	RETURN(rc);

unlock_parent:
	dt_write_unlock(env, parent);

stop:
	if (handle != NULL)
		dt_trans_stop(env, dt, handle);

unlock_layout:
	lfsck_layout_unlock(&lh);
	buf->lb_len = buflen;

	return rc;
}

static int lfsck_layout_scan_orphan_one(const struct lu_env *env,
					struct lfsck_component *com,
					struct lfsck_tgt_desc *ltd,
					struct lu_orphan_rec *rec,
					struct lu_fid *cfid)
{
	struct lfsck_layout	*lo	= com->lc_file_ram;
	struct lu_fid		*pfid	= &rec->lor_fid;
	struct dt_object	*parent = NULL;
	__u32			 ea_off = pfid->f_ver;
	int			 rc	= 0;
	ENTRY;

	if (!fid_is_sane(cfid))
		GOTO(out, rc = -EINVAL);

	if (fid_is_zero(pfid)) {
		rc = lfsck_layout_recreate_parent(env, com, ltd, rec, cfid,
						  "N-", "", ea_off);
		GOTO(out, rc);
	}

	pfid->f_ver = 0;
	if (!fid_is_sane(pfid))
		GOTO(out, rc = -EINVAL);

	parent = lfsck_object_find_by_dev(env, com->lc_lfsck->li_bottom, pfid);
	if (IS_ERR(parent))
		GOTO(out, rc = PTR_ERR(parent));

	if (unlikely(dt_object_remote(parent) != 0))
		GOTO(put, rc = -EXDEV);

	if (dt_object_exists(parent) == 0) {
		lu_object_put(env, &parent->do_lu);
		rc = lfsck_layout_recreate_parent(env, com, ltd, rec, cfid,
						  "R-", "", ea_off);
		GOTO(out, rc);
	}

	if (!S_ISREG(lu_object_attr(&parent->do_lu)))
		GOTO(put, rc = -EISDIR);

	rc = lfsck_layout_recreate_lovea(env, com, ltd, rec, parent, cfid,
					 ltd->ltd_index, ea_off);

	GOTO(put, rc);

put:
	if (rc <= 0)
		lu_object_put(env, &parent->do_lu);
	else
		/* The layout EA is changed, need to be reloaded next time. */
		lu_object_put_nocache(env, &parent->do_lu);

out:
	down_write(&com->lc_sem);
	com->lc_new_scanned++;
	com->lc_new_checked++;
	if (rc > 0) {
		lo->ll_objs_repaired[LLIT_ORPHAN - 1]++;
		rc = 0;
	} else if (rc < 0) {
		lo->ll_objs_failed_phase2++;
	}
	up_write(&com->lc_sem);

	return rc;
}

static int lfsck_layout_scan_orphan(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct lfsck_tgt_desc *ltd)
{
	struct lfsck_layout		*lo	= com->lc_file_ram;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_bookmark		*bk	= &lfsck->li_bookmark_ram;
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct ost_id			*oi	= &info->lti_oi;
	struct lu_fid			*fid	= &info->lti_fid;
	struct dt_object		*obj;
	const struct dt_it_ops		*iops;
	struct dt_it			*di;
	int				 rc	= 0;
	ENTRY;

	CDEBUG(D_LFSCK, "%s: start the orphan scanning for OST%04x\n",
	       lfsck_lfsck2name(lfsck), ltd->ltd_index);

	ostid_set_seq(oi, FID_SEQ_IDIF);
	ostid_set_id(oi, 0);
	ostid_to_fid(fid, oi, ltd->ltd_index);
	obj = lfsck_object_find_by_dev(env, ltd->ltd_tgt, fid);
	if (unlikely(IS_ERR(obj)))
		RETURN(PTR_ERR(obj));

	rc = obj->do_ops->do_index_try(env, obj, &dt_lfsck_orphan_features);
	if (rc != 0)
		GOTO(put, rc);

	iops = &obj->do_index_ops->dio_it;
	di = iops->init(env, obj, 0, BYPASS_CAPA);
	if (IS_ERR(di))
		GOTO(put, rc = PTR_ERR(di));

	rc = iops->load(env, di, 0);
	if (rc == -ESRCH) {
		/* -ESRCH means that the orphan OST-objects rbtree has been
		 * cleanup because of the OSS server restart or other errors. */
		lo->ll_flags |= LF_INCOMPLETE;
		GOTO(fini, rc);
	}

	if (rc == 0)
		rc = iops->next(env, di);
	else if (rc > 0)
		rc = 0;

	if (rc < 0)
		GOTO(fini, rc);

	if (rc > 0)
		GOTO(fini, rc = 0);

	do {
		struct dt_key		*key;
		struct lu_orphan_rec	*rec = &info->lti_rec;

		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DELAY3) &&
		    cfs_fail_val > 0) {
			struct ptlrpc_thread	*thread = &lfsck->li_thread;
			struct l_wait_info	 lwi;

			lwi = LWI_TIMEOUT(cfs_time_seconds(cfs_fail_val),
					  NULL, NULL);
			l_wait_event(thread->t_ctl_waitq,
				     !thread_is_running(thread),
				     &lwi);
		}

		key = iops->key(env, di);
		com->lc_fid_latest_scanned_phase2 = *(struct lu_fid *)key;
		rc = iops->rec(env, di, (struct dt_rec *)rec, 0);
		if (rc == 0)
			rc = lfsck_layout_scan_orphan_one(env, com, ltd, rec,
					&com->lc_fid_latest_scanned_phase2);
		if (rc != 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(fini, rc);

		lfsck_control_speed_by_self(com);
		do {
			rc = iops->next(env, di);
		} while (rc < 0 && !(bk->lb_param & LPF_FAILOUT));
	} while (rc == 0);

	GOTO(fini, rc);

fini:
	iops->put(env, di);
	iops->fini(env, di);
put:
	lu_object_put(env, &obj->do_lu);

	CDEBUG(D_LFSCK, "%s: finish the orphan scanning for OST%04x, rc = %d\n",
	       lfsck_lfsck2name(lfsck), ltd->ltd_index, rc);

	return rc > 0 ? 0 : rc;
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

		if (is_dummy_lov_ost_data(objs))
			continue;

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
			CERROR("%s: Fail to talk with OST %x: rc = %d.\n",
			       lfsck_lfsck2name(lfsck), llr->llr_ost_idx, rc);
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
	ENTRY;

	memset(lr, 0, sizeof(*lr));
	lr->lr_event = LE_START;
	lr->lr_valid = LSV_SPEED_LIMIT | LSV_ERROR_HANDLE | LSV_DRYRUN |
		       LSV_ASYNC_WINDOWS;
	lr->lr_speed = bk->lb_speed_limit;
	lr->lr_version = bk->lb_version;
	lr->lr_param = bk->lb_param;
	lr->lr_async_windows = bk->lb_async_windows;
	lr->lr_flags = LEF_TO_OST;
	if (pos->lp_oit_cookie <= 1)
		lr->lr_param |= LPF_RESET;

	rc = lfsck_layout_master_notify_others(env, com, lr);
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
			llmd->llmd_prefetched--;
			/* Wake up the main engine thread only when the list
			 * is empty or half of the prefetched items have been
			 * handled to avoid too frequent thread schedule. */
			if (llmd->llmd_prefetched == 0 ||
			    (bk->lb_async_windows != 0 &&
			     (bk->lb_async_windows >> 1) ==
			     llmd->llmd_prefetched))
				wakeup = true;
			spin_unlock(&llmd->llmd_lock);
			if (wakeup)
				wake_up_all(&mthread->t_ctl_waitq);

			lfsck_layout_req_fini(env, llr);
			if (rc < 0 && bk->lb_param & LPF_FAILOUT)
				GOTO(cleanup1, rc);
		}

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
			lr->lr_event = LE_PHASE1_DONE;
			lr->lr_status = llmd->llmd_post_result;
			rc = lfsck_layout_master_notify_others(env, com, lr);
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

			com->lc_new_checked = 0;
			com->lc_new_scanned = 0;
			com->lc_time_last_checkpoint = cfs_time_current();
			com->lc_time_next_checkpoint =
				com->lc_time_last_checkpoint +
				cfs_time_seconds(LFSCK_CHECKPOINT_INTERVAL);

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

					if (bk->lb_param & LPF_ALL_TGT) {
						rc = lfsck_layout_scan_orphan(
								env, com, ltd);
						if (rc != 0 &&
						    bk->lb_param & LPF_FAILOUT)
							GOTO(cleanup2, rc);
					}

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
				CERROR("%s: unknown status: rc = %d\n",
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

	rc1 = lfsck_layout_master_notify_others(env, com, lr);
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
		}
		spin_lock(&llsd->llsd_lock);
	}
	spin_unlock(&llsd->llsd_lock);

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
		lfsck_layout_llst_put(llst);
		class_export_put(exp);
		spin_lock(&llsd->llsd_lock);
	}
	spin_unlock(&llsd->llsd_lock);

	ptlrpc_set_wait(set);
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
			     struct lfsck_component *com,
			     struct lfsck_start *start)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_layout	*lo	= com->lc_file_ram;
	struct lfsck_position	*pos	= &com->lc_pos_start;

	fid_zero(&pos->lp_dir_parent);
	pos->lp_dir_cookie = 0;
	if (lo->ll_status == LS_COMPLETED ||
	    lo->ll_status == LS_PARTIAL ||
	    /* To handle orphan, must scan from the beginning. */
	    (start != NULL && start->ls_flags & LPF_ORPHAN)) {
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
			fid_zero(&com->lc_fid_latest_scanned_phase2);
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
	struct lfsck_layout_slave_data	*llsd	= com->lc_data;
	struct lfsck_start		*start  = lsp->lsp_start;
	int				 rc;

	rc = lfsck_layout_prep(env, com, start);
	if (rc != 0 || !lsp->lsp_index_valid)
		return rc;

	rc = lfsck_layout_llst_add(llsd, lsp->lsp_index);
	if (rc == 0 && start != NULL && start->ls_flags & LPF_ORPHAN) {
		LASSERT(!llsd->llsd_rbtree_valid);

		write_lock(&llsd->llsd_rb_lock);
		rc = lfsck_rbtree_setup(env, com);
		write_unlock(&llsd->llsd_rb_lock);
	}

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

	rc = lfsck_layout_prep(env, com, lsp->lsp_start);
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

		if (is_dummy_lov_ost_data(objs))
			continue;

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
			CERROR("%s: Cannot talk with OST %x which did not join "
			       "the layout LFSCK.\n",
			       lfsck_lfsck2name(lfsck), index);
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

	LASSERT(llsd != NULL);

	lfsck_rbtree_update_bitmap(env, com, fid, false);

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

	if (result <= 0)
		lfsck_rbtree_cleanup(env, com);

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
	} else if (lo->ll_status == LS_SCANNING_PHASE2) {
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
			      "real-time_speed_phase2: N/A\n"
			      "current_position: "DFID"\n",
			      checked,
			      lo->ll_objs_checked_phase2,
			      rtime,
			      lo->ll_run_time_phase2,
			      speed,
			      new_checked,
			      PFID(&com->lc_fid_latest_scanned_phase2));
		if (rc <= 0)
			goto out;

		buf += rc;
		len -= rc;
	} else {
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

	if (unlikely(lo->ll_status != LS_SCANNING_PHASE2)) {
		lfsck_rbtree_cleanup(env, com);
		lfsck_layout_slave_notify_master(env, com, LE_PHASE2_DONE, 0);
		RETURN(0);
	}

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

	lfsck_rbtree_cleanup(env, com);
	lfsck_layout_slave_notify_master(env, com, LE_PHASE2_DONE, rc);
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

	lfsck_rbtree_cleanup(env, com);
	com->lc_data = NULL;
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

static void lfsck_layout_slave_quit(const struct lu_env *env,
				    struct lfsck_component *com)
{
	lfsck_rbtree_cleanup(env, com);
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
	bool				 fail  = false;
	ENTRY;

	if (lr->lr_event != LE_PHASE1_DONE &&
	    lr->lr_event != LE_PHASE2_DONE &&
	    lr->lr_event != LE_PEER_EXIT)
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
			CWARN("%s: %s %x failed/stopped at phase1: rc = %d.\n",
			      lfsck_lfsck2name(lfsck),
			      (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
			      ltd->ltd_index, lr->lr_status);
			lo->ll_flags |= LF_INCOMPLETE;
			fail = true;
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
	case LE_PEER_EXIT:
		fail = true;
		ltd->ltd_layout_done = 1;
		list_del_init(&ltd->ltd_layout_list);
		if (!(lfsck->li_bookmark_ram.lb_param & LPF_FAILOUT)) {
			CWARN("%s: the peer %s %x exit layout LFSCK.\n",
			      lfsck_lfsck2name(lfsck),
			      (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
			      ltd->ltd_index);
			lo->ll_flags |= LF_INCOMPLETE;
		}
		break;
	default:
		break;
	}
	spin_unlock(&ltds->ltd_lock);

	if (fail && lfsck->li_bookmark_ram.lb_param & LPF_FAILOUT) {
		struct lfsck_stop *stop = &lfsck_env_info(env)->lti_stop;

		memset(stop, 0, sizeof(*stop));
		stop->ls_status = lr->lr_status;
		stop->ls_flags = lr->lr_param & ~LPF_BROADCAST;
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

	if (lr->lr_event == LE_FID_ACCESSED) {
		lfsck_rbtree_update_bitmap(env, com, &lr->lr_fid, true);

		RETURN(0);
	}

	if (lr->lr_event == LE_CONDITIONAL_DESTROY) {
		int rc;

		rc = lfsck_layout_slave_conditional_destroy(env, com, lr);

		RETURN(rc);
	}

	if (lr->lr_event != LE_PHASE2_DONE && lr->lr_event != LE_PEER_EXIT)
		RETURN(-EINVAL);

	llst = lfsck_layout_llst_find_and_del(llsd, lr->lr_index, true);
	if (llst == NULL)
		RETURN(-ENODEV);

	lfsck_layout_llst_put(llst);
	if (list_empty(&llsd->llsd_master_list))
		wake_up_all(&lfsck->li_thread.t_ctl_waitq);

	if (lr->lr_event == LE_PEER_EXIT &&
	    lfsck->li_bookmark_ram.lb_param & LPF_FAILOUT) {
		struct lfsck_stop *stop = &lfsck_env_info(env)->lti_stop;

		memset(stop, 0, sizeof(*stop));
		stop->ls_status = lr->lr_status;
		stop->ls_flags = lr->lr_param & ~LPF_BROADCAST;
		lfsck_stop(env, lfsck->li_bottom, stop);
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

	spin_lock(&ltds->ltd_lock);
	if (list_empty(&ltd->ltd_layout_list)) {
		LASSERT(list_empty(&ltd->ltd_layout_phase_list));
		spin_unlock(&ltds->ltd_lock);

		return 0;
	}

	list_del_init(&ltd->ltd_layout_phase_list);
	list_del_init(&ltd->ltd_layout_list);
	spin_unlock(&ltds->ltd_lock);

	memset(lr, 0, sizeof(*lr));
	lr->lr_index = lfsck_dev_idx(lfsck->li_bottom);
	lr->lr_event = LE_PEER_EXIT;
	lr->lr_active = LT_LAYOUT;
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
				 lfsck_layout_master_async_interpret,
				 laia, LFSCK_NOTIFY);
	if (rc != 0) {
		CERROR("%s: Fail to notify %s %x for co-stop: rc = %d\n",
		       lfsck_lfsck2name(lfsck),
		       (lr->lr_flags & LEF_TO_OST) ? "OST" : "MDT",
		       ltd->ltd_index, rc);
		lfsck_tgt_put(ltd);
	}

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
	    !(start->ls_flags & LPF_ALL_TGT) ||
	    !(lfsck->li_bookmark_ram.lb_param & LPF_ALL_TGT))
		RETURN(-EALREADY);

	spin_unlock(&lfsck->li_lock);
	rc = lfsck_layout_llst_add(llsd, lsp->lsp_index);
	spin_lock(&lfsck->li_lock);
	if (rc == 0 && !thread_is_running(&lfsck->li_thread)) {
		spin_unlock(&lfsck->li_lock);
		llst = lfsck_layout_llst_find_and_del(llsd, lsp->lsp_index,
						      true);
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
	.lfsck_interpret	= lfsck_layout_master_async_interpret,
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
	.lfsck_quit		= lfsck_layout_slave_quit,
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
		llsd->llsd_rb_root = RB_ROOT;
		rwlock_init(&llsd->llsd_rb_lock);
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

struct lfsck_orphan_it {
	struct lfsck_component		 *loi_com;
	struct lfsck_rbtree_node	 *loi_lrn;
	struct lfsck_layout_slave_target *loi_llst;
	struct lu_fid			  loi_key;
	struct lu_orphan_rec		  loi_rec;
	__u64				  loi_hash;
	unsigned int			  loi_over:1;
};

static int lfsck_fid_match_idx(const struct lu_env *env,
			       struct lfsck_instance *lfsck,
			       const struct lu_fid *fid, int idx)
{
	struct seq_server_site	*ss;
	struct lu_server_fld	*sf;
	struct lu_seq_range	 range	= { 0 };
	int			 rc;

	/* All abnormal cases will be returned to MDT0. */
	if (!fid_is_norm(fid)) {
		if (idx == 0)
			return 1;

		return 0;
	}

	ss = lu_site2seq(lfsck->li_bottom->dd_lu_dev.ld_site);
	if (unlikely(ss == NULL))
		return -ENOTCONN;

	sf = ss->ss_server_fld;
	LASSERT(sf != NULL);

	fld_range_set_any(&range);
	rc = fld_server_lookup(env, sf, fid_seq(fid), &range);
	if (rc != 0)
		return rc;

	if (!fld_range_is_mdt(&range))
		return -EINVAL;

	if (range.lsr_index == idx)
		return 1;

	return 0;
}

static void lfsck_layout_destroy_orphan(const struct lu_env *env,
					struct dt_device *dev,
					struct dt_object *obj)
{
	struct thandle *handle;
	int		rc;
	ENTRY;

	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		RETURN_EXIT;

	rc = dt_declare_ref_del(env, obj, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_destroy(env, obj, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	rc = dt_ref_del(env, obj, handle);
	if (rc == 0)
		rc = dt_destroy(env, obj, handle);
	dt_write_unlock(env, obj);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, handle);

	RETURN_EXIT;
}

static int lfsck_orphan_index_lookup(const struct lu_env *env,
				     struct dt_object *dt,
				     struct dt_rec *rec,
				     const struct dt_key *key,
				     struct lustre_capa *capa)
{
	return -EOPNOTSUPP;
}

static int lfsck_orphan_index_declare_insert(const struct lu_env *env,
					     struct dt_object *dt,
					     const struct dt_rec *rec,
					     const struct dt_key *key,
					     struct thandle *handle)
{
	return -EOPNOTSUPP;
}

static int lfsck_orphan_index_insert(const struct lu_env *env,
				     struct dt_object *dt,
				     const struct dt_rec *rec,
				     const struct dt_key *key,
				     struct thandle *handle,
				     struct lustre_capa *capa,
				     int ignore_quota)
{
	return -EOPNOTSUPP;
}

static int lfsck_orphan_index_declare_delete(const struct lu_env *env,
					     struct dt_object *dt,
					     const struct dt_key *key,
					     struct thandle *handle)
{
	return -EOPNOTSUPP;
}

static int lfsck_orphan_index_delete(const struct lu_env *env,
				     struct dt_object *dt,
				     const struct dt_key *key,
				     struct thandle *handle,
				     struct lustre_capa *capa)
{
	return -EOPNOTSUPP;
}

static struct dt_it *lfsck_orphan_it_init(const struct lu_env *env,
					  struct dt_object *dt,
					  __u32 attr,
					  struct lustre_capa *capa)
{
	struct dt_device		*dev	= lu2dt_dev(dt->do_lu.lo_dev);
	struct lfsck_instance		*lfsck;
	struct lfsck_component		*com	= NULL;
	struct lfsck_layout_slave_data	*llsd;
	struct lfsck_orphan_it		*it	= NULL;
	int				 rc	= 0;
	ENTRY;

	lfsck = lfsck_instance_find(dev, true, false);
	if (unlikely(lfsck == NULL))
		RETURN(ERR_PTR(-ENODEV));

	com = lfsck_component_find(lfsck, LT_LAYOUT);
	if (unlikely(com == NULL))
		GOTO(out, rc = -ENOENT);

	llsd = com->lc_data;
	if (!llsd->llsd_rbtree_valid)
		GOTO(out, rc = -ESRCH);

	OBD_ALLOC_PTR(it);
	if (it == NULL)
		GOTO(out, rc = -ENOMEM);

	it->loi_llst = lfsck_layout_llst_find_and_del(llsd, attr, false);
	if (it->loi_llst == NULL)
		GOTO(out, rc = -ENODEV);

	if (dev->dd_record_fid_accessed) {
		/* The first iteration against the rbtree, scan the whole rbtree
		 * to remove the nodes which do NOT need to be handled. */
		write_lock(&llsd->llsd_rb_lock);
		if (dev->dd_record_fid_accessed) {
			struct rb_node			*node;
			struct rb_node			*next;
			struct lfsck_rbtree_node	*lrn;

			/* No need to record the fid accessing anymore. */
			dev->dd_record_fid_accessed = 0;

			node = rb_first(&llsd->llsd_rb_root);
			while (node != NULL) {
				next = rb_next(node);
				lrn = rb_entry(node, struct lfsck_rbtree_node,
					       lrn_node);
				if (atomic_read(&lrn->lrn_known_count) <=
				    atomic_read(&lrn->lrn_accessed_count)) {
					rb_erase(node, &llsd->llsd_rb_root);
					lfsck_rbtree_free(lrn);
				}
				node = next;
			}
		}
		write_unlock(&llsd->llsd_rb_lock);
	}

	/* read lock the rbtree when init, and unlock when fini */
	read_lock(&llsd->llsd_rb_lock);
	it->loi_com = com;
	com = NULL;

	GOTO(out, rc = 0);

out:
	if (com != NULL)
		lfsck_component_put(env, com);
	lfsck_instance_put(env, lfsck);
	if (rc != 0) {
		if (it != NULL)
			OBD_FREE_PTR(it);

		it = (struct lfsck_orphan_it *)ERR_PTR(rc);
	}

	return (struct dt_it *)it;
}

static void lfsck_orphan_it_fini(const struct lu_env *env,
				 struct dt_it *di)
{
	struct lfsck_orphan_it		 *it	= (struct lfsck_orphan_it *)di;
	struct lfsck_component		 *com	= it->loi_com;
	struct lfsck_layout_slave_data	 *llsd;
	struct lfsck_layout_slave_target *llst;

	if (com != NULL) {
		llsd = com->lc_data;
		read_unlock(&llsd->llsd_rb_lock);
		llst = it->loi_llst;
		LASSERT(llst != NULL);

		/* Save the key and hash for iterate next. */
		llst->llst_fid = it->loi_key;
		llst->llst_hash = it->loi_hash;
		lfsck_layout_llst_put(llst);
		lfsck_component_put(env, com);
	}
	OBD_FREE_PTR(it);
}

/**
 * \retval	 +1: the iteration finished
 * \retval	  0: on success, not finished
 * \retval	-ve: on error
 */
static int lfsck_orphan_it_next(const struct lu_env *env,
				struct dt_it *di)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct filter_fid_old		*pfid	= &info->lti_old_pfid;
	struct lu_attr			*la	= &info->lti_la;
	struct lfsck_orphan_it		*it	= (struct lfsck_orphan_it *)di;
	struct lu_fid			*key	= &it->loi_key;
	struct lu_orphan_rec		*rec	= &it->loi_rec;
	struct lfsck_component		*com	= it->loi_com;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_layout_slave_data	*llsd	= com->lc_data;
	struct dt_object		*obj;
	struct lfsck_rbtree_node	*lrn;
	int				 pos;
	int				 rc;
	__u32				 save;
	__u32				 idx	= it->loi_llst->llst_index;
	bool				 exact	= false;
	ENTRY;

	if (it->loi_over)
		RETURN(1);

again0:
	lrn = it->loi_lrn;
	if (lrn == NULL) {
		lrn = lfsck_rbtree_search(llsd, key, &exact);
		if (lrn == NULL) {
			it->loi_over = 1;
			RETURN(1);
		}

		it->loi_lrn = lrn;
		if (!exact) {
			key->f_seq = lrn->lrn_seq;
			key->f_oid = lrn->lrn_first_oid;
			key->f_ver = 0;
		}
	} else {
		key->f_oid++;
		if (unlikely(key->f_oid == 0)) {
			key->f_seq++;
			it->loi_lrn = NULL;
			goto again0;
		}

		if (key->f_oid >=
		    lrn->lrn_first_oid + LFSCK_RBTREE_BITMAP_WIDTH) {
			it->loi_lrn = NULL;
			goto again0;
		}
	}

	if (unlikely(atomic_read(&lrn->lrn_known_count) <=
		     atomic_read(&lrn->lrn_accessed_count))) {
		struct rb_node *next = rb_next(&lrn->lrn_node);

		while (next != NULL) {
			lrn = rb_entry(next, struct lfsck_rbtree_node,
				       lrn_node);
			if (atomic_read(&lrn->lrn_known_count) >
			    atomic_read(&lrn->lrn_accessed_count))
				break;
			next = rb_next(next);
		}

		if (next == NULL) {
			it->loi_over = 1;
			RETURN(1);
		}

		it->loi_lrn = lrn;
		key->f_seq = lrn->lrn_seq;
		key->f_oid = lrn->lrn_first_oid;
		key->f_ver = 0;
	}

	pos = key->f_oid - lrn->lrn_first_oid;

again1:
	pos = find_next_bit(lrn->lrn_known_bitmap,
			    LFSCK_RBTREE_BITMAP_WIDTH, pos);
	if (pos >= LFSCK_RBTREE_BITMAP_WIDTH) {
		key->f_oid = lrn->lrn_first_oid + pos;
		if (unlikely(key->f_oid < lrn->lrn_first_oid)) {
			key->f_seq++;
			key->f_oid = 0;
		}
		it->loi_lrn = NULL;
		goto again0;
	}

	if (test_bit(pos, lrn->lrn_accessed_bitmap)) {
		pos++;
		goto again1;
	}

	key->f_oid = lrn->lrn_first_oid + pos;
	obj = lfsck_object_find(env, lfsck, key);
	if (IS_ERR(obj)) {
		rc = PTR_ERR(obj);
		if (rc == -ENOENT) {
			pos++;
			goto again1;
		}
		RETURN(rc);
	}

	dt_read_lock(env, obj, 0);
	if (!dt_object_exists(obj)) {
		dt_read_unlock(env, obj);
		lfsck_object_put(env, obj);
		pos++;
		goto again1;
	}

	rc = dt_attr_get(env, obj, la, BYPASS_CAPA);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_xattr_get(env, obj, lfsck_buf_get(env, pfid, sizeof(*pfid)),
			  XATTR_NAME_FID, BYPASS_CAPA);
	if (rc == -ENODATA) {
		/* For the pre-created OST-object, update the bitmap to avoid
		 * others LFSCK (second phase) iteration to touch it again. */
		if (la->la_ctime == 0) {
			if (!test_and_set_bit(pos, lrn->lrn_accessed_bitmap))
				atomic_inc(&lrn->lrn_accessed_count);

			/* For the race between repairing dangling referenced
			 * MDT-object and unlink the file, it may left orphan
			 * OST-object there. Destroy it now! */
			if (unlikely(!(la->la_mode & S_ISUID))) {
				dt_read_unlock(env, obj);
				lfsck_layout_destroy_orphan(env,
							    lfsck->li_bottom,
							    obj);
				lfsck_object_put(env, obj);
				pos++;
				goto again1;
			}
		} else if (idx == 0) {
			/* If the orphan OST-object has no parent information,
			 * regard it as referenced by the MDT-object on MDT0. */
			fid_zero(&rec->lor_fid);
			rec->lor_uid = la->la_uid;
			rec->lor_gid = la->la_gid;
			GOTO(out, rc = 0);
		}

		dt_read_unlock(env, obj);
		lfsck_object_put(env, obj);
		pos++;
		goto again1;
	}

	if (rc < 0)
		GOTO(out, rc);

	if (rc != sizeof(struct filter_fid) &&
	    rc != sizeof(struct filter_fid_old))
		GOTO(out, rc = -EINVAL);

	fid_le_to_cpu(&rec->lor_fid, &pfid->ff_parent);
	/* In fact, the ff_parent::f_ver is not the real parent FID::f_ver,
	 * instead, it is the OST-object index in its parent MDT-object
	 * layout EA. */
	save = rec->lor_fid.f_ver;
	rec->lor_fid.f_ver = 0;
	rc = lfsck_fid_match_idx(env, lfsck, &rec->lor_fid, idx);
	/* If the orphan OST-object does not claim the MDT, then next.
	 *
	 * If we do not know whether it matches or not, then return it
	 * to the MDT for further check. */
	if (rc == 0) {
		dt_read_unlock(env, obj);
		lfsck_object_put(env, obj);
		pos++;
		goto again1;
	}

	rec->lor_fid.f_ver = save;
	rec->lor_uid = la->la_uid;
	rec->lor_gid = la->la_gid;

	CDEBUG(D_LFSCK, "%s: return orphan "DFID", PFID "DFID", owner %u:%u\n",
	       lfsck_lfsck2name(com->lc_lfsck), PFID(key), PFID(&rec->lor_fid),
	       rec->lor_uid, rec->lor_gid);

	GOTO(out, rc = 0);

out:
	dt_read_unlock(env, obj);
	lfsck_object_put(env, obj);
	if (rc == 0)
		it->loi_hash++;

	return rc;
}

/**
 * \retval	 +1: locate to the exactly position
 * \retval	  0: cannot locate to the exactly position,
 *		     call next() to move to a valid position.
 * \retval	-ve: on error
 */
static int lfsck_orphan_it_get(const struct lu_env *env,
			       struct dt_it *di,
			       const struct dt_key *key)
{
	struct lfsck_orphan_it	*it   = (struct lfsck_orphan_it *)di;
	int			 rc;

	it->loi_key = *(struct lu_fid *)key;
	rc = lfsck_orphan_it_next(env, di);
	if (rc == 1)
		return 0;

	if (rc == 0)
		return 1;

	return rc;
}

static void lfsck_orphan_it_put(const struct lu_env *env,
				struct dt_it *di)
{
}

static struct dt_key *lfsck_orphan_it_key(const struct lu_env *env,
					  const struct dt_it *di)
{
	struct lfsck_orphan_it *it = (struct lfsck_orphan_it *)di;

	return (struct dt_key *)&it->loi_key;
}

static int lfsck_orphan_it_key_size(const struct lu_env *env,
				    const struct dt_it *di)
{
	return sizeof(struct lu_fid);
}

static int lfsck_orphan_it_rec(const struct lu_env *env,
			       const struct dt_it *di,
			       struct dt_rec *rec,
			       __u32 attr)
{
	struct lfsck_orphan_it *it = (struct lfsck_orphan_it *)di;

	*(struct lu_orphan_rec *)rec = it->loi_rec;

	return 0;
}

static __u64 lfsck_orphan_it_store(const struct lu_env *env,
				   const struct dt_it *di)
{
	struct lfsck_orphan_it	*it   = (struct lfsck_orphan_it *)di;

	return it->loi_hash;
}

/**
 * \retval	 +1: locate to the exactly position
 * \retval	  0: cannot locate to the exactly position,
 *		     call next() to move to a valid position.
 * \retval	-ve: on error
 */
static int lfsck_orphan_it_load(const struct lu_env *env,
				const struct dt_it *di,
				__u64 hash)
{
	struct lfsck_orphan_it		 *it   = (struct lfsck_orphan_it *)di;
	struct lfsck_layout_slave_target *llst = it->loi_llst;
	int				  rc;

	LASSERT(llst != NULL);

	if (hash != llst->llst_hash) {
		CWARN("%s: the given hash "LPU64" for orphan iteration does "
		      "not match the one when fini "LPU64", to be reset.\n",
		      lfsck_lfsck2name(it->loi_com->lc_lfsck), hash,
		      llst->llst_hash);
		fid_zero(&llst->llst_fid);
		llst->llst_hash = 0;
	}

	it->loi_key = llst->llst_fid;
	it->loi_hash = llst->llst_hash;
	rc = lfsck_orphan_it_next(env, (struct dt_it *)di);
	if (rc == 1)
		return 0;

	if (rc == 0)
		return 1;

	return rc;
}

static int lfsck_orphan_it_key_rec(const struct lu_env *env,
				   const struct dt_it *di,
				   void *key_rec)
{
	return 0;
}

const struct dt_index_operations lfsck_orphan_index_ops = {
	.dio_lookup		= lfsck_orphan_index_lookup,
	.dio_declare_insert	= lfsck_orphan_index_declare_insert,
	.dio_insert		= lfsck_orphan_index_insert,
	.dio_declare_delete	= lfsck_orphan_index_declare_delete,
	.dio_delete		= lfsck_orphan_index_delete,
	.dio_it = {
		.init		= lfsck_orphan_it_init,
		.fini		= lfsck_orphan_it_fini,
		.get		= lfsck_orphan_it_get,
		.put		= lfsck_orphan_it_put,
		.next		= lfsck_orphan_it_next,
		.key		= lfsck_orphan_it_key,
		.key_size	= lfsck_orphan_it_key_size,
		.rec		= lfsck_orphan_it_rec,
		.store		= lfsck_orphan_it_store,
		.load		= lfsck_orphan_it_load,
		.key_rec	= lfsck_orphan_it_key_rec,
	}
};
