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
 * Copyright (c) 2014, 2017, Intel Corporation.
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

#include <lu_object.h>
#include <dt_object.h>
#include <lustre_fid.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <md_object.h>
#include <obd_class.h>

#include "lfsck_internal.h"

#define LFSCK_LAYOUT_MAGIC_V1		0xB173AE14
#define LFSCK_LAYOUT_MAGIC_V2		0xB1734D76
#define LFSCK_LAYOUT_MAGIC_V3		0xB17371B9
#define LFSCK_LAYOUT_MAGIC_V4		0xB1732FED

#define LFSCK_LAYOUT_MAGIC		LFSCK_LAYOUT_MAGIC_V4

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
	/* How many times we have failed to get the master status. */
	int			llst_failures;
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
	struct rw_semaphore	 llsd_rb_rwsem;
	unsigned int		 llsd_rbtree_valid:1;
};

struct lfsck_layout_slave_async_args {
	struct obd_export		 *llsaa_exp;
	struct lfsck_component		 *llsaa_com;
	struct lfsck_layout_slave_target *llsaa_llst;
};

static inline bool lfsck_comp_extent_aligned(__u64 border, __u32 size)
{
	return (border & (size - 1)) == 0;
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

static struct lfsck_layout_req *
lfsck_layout_assistant_req_init(struct lfsck_assistant_object *lso,
				struct dt_object *child, __u32 comp_id,
				__u32 ost_idx, __u32 lov_idx)
{
	struct lfsck_layout_req *llr;

	OBD_ALLOC_PTR(llr);
	if (llr == NULL)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&llr->llr_lar.lar_list);
	llr->llr_lar.lar_parent = lfsck_assistant_object_get(lso);
	llr->llr_child = child;
	llr->llr_comp_id = comp_id;
	llr->llr_ost_idx = ost_idx;
	llr->llr_lov_idx = lov_idx;

	return llr;
}

static void lfsck_layout_assistant_req_fini(const struct lu_env *env,
					    struct lfsck_assistant_req *lar)
{
	struct lfsck_layout_req *llr =
		container_of(lar, struct lfsck_layout_req, llr_lar);

	lfsck_object_put(env, llr->llr_child);
	lfsck_assistant_object_put(env, lar->lar_parent);
	OBD_FREE_PTR(llr);
}

static int
lfsck_layout_assistant_sync_failures_interpret(const struct lu_env *env,
					       struct ptlrpc_request *req,
					       void *args, int rc)
{
	if (rc == 0) {
		struct lfsck_async_interpret_args *laia = args;
		struct lfsck_tgt_desc		  *ltd	= laia->laia_ltd;

		ltd->ltd_synced_failures = 1;
		atomic_dec(laia->laia_count);
	}

	return 0;
}

/**
 * Notify remote LFSCK instances about former failures.
 *
 * The local LFSCK instance has recorded which OSTs have ever failed to respond
 * some LFSCK verification requests (maybe because of network issues or the OST
 * itself trouble). During the respond gap, the OST may missed some OST-objects
 * verification, then the OST cannot know whether related OST-objects have been
 * referenced by related MDT-objects or not, then in the second-stage scanning,
 * these OST-objects will be regarded as orphan, if the OST-object contains bad
 * parent FID for back reference, then it will misguide the LFSCK to make wrong
 * fixing for the fake orphan.
 *
 * To avoid above trouble, when layout LFSCK finishes the first-stage scanning,
 * it will scan the bitmap for the ever failed OSTs, and notify them that they
 * have ever missed some OST-object verification and should skip the handling
 * for orphan OST-objects on all MDTs that are in the layout LFSCK.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] lr	pointer to the lfsck request
 */
static void lfsck_layout_assistant_sync_failures(const struct lu_env *env,
						 struct lfsck_component *com,
						 struct lfsck_request *lr)
{
	struct lfsck_async_interpret_args *laia  =
				&lfsck_env_info(env)->lti_laia2;
	struct lfsck_assistant_data	  *lad   = com->lc_data;
	struct lfsck_layout		  *lo    = com->lc_file_ram;
	struct lfsck_instance		  *lfsck = com->lc_lfsck;
	struct lfsck_tgt_descs		  *ltds  = &lfsck->li_ost_descs;
	struct lfsck_tgt_desc		  *ltd;
	struct ptlrpc_request_set	  *set;
	atomic_t			   count;
	__u32				   idx;
	int				   rc    = 0;
	ENTRY;

	if (!test_bit(LAD_INCOMPLETE, &lad->lad_flags))
		RETURN_EXIT;

	/* If the MDT has ever failed to verfiy some OST-objects,
	 * then sync failures with them firstly. */
	lr->lr_flags2 = lo->ll_flags | LF_INCOMPLETE;

	atomic_set(&count, 0);
	memset(laia, 0, sizeof(*laia));
	laia->laia_count = &count;
	set = ptlrpc_prep_set();
	if (set == NULL)
		GOTO(out, rc = -ENOMEM);

	down_read(&ltds->ltd_rw_sem);
	cfs_foreach_bit(lad->lad_bitmap, idx) {
		ltd = lfsck_ltd2tgt(ltds, idx);
		if (unlikely(!ltd))
			continue;

		laia->laia_ltd = ltd;
		rc = lfsck_async_request(env, ltd->ltd_exp, lr, set,
				lfsck_layout_assistant_sync_failures_interpret,
				laia, LFSCK_NOTIFY);
		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: LFSCK assistant fail to "
			       "notify target %x for %s phase1 done: "
			       "rc = %d\n", lfsck_lfsck2name(com->lc_lfsck),
			       ltd->ltd_index, lad->lad_name, rc);

			break;
		}

		atomic_inc(&count);
	}
	up_read(&ltds->ltd_rw_sem);

	if (rc == 0 && atomic_read(&count) > 0)
		rc = ptlrpc_set_wait(env, set);

	ptlrpc_set_destroy(set);

	if (rc == 0 && atomic_read(&count) > 0)
		rc = -EINVAL;

	GOTO(out, rc);

out:
	if (rc != 0)
		/* If failed to sync failures with the OSTs, then have to
		 * mark the whole LFSCK as LF_INCOMPLETE to skip the whole
		 * subsequent orphan OST-object handling. */
		lo->ll_flags |= LF_INCOMPLETE;

	lr->lr_flags2 = lo->ll_flags;
}

static int lfsck_layout_verify_header_v1v3(struct dt_object *obj,
					   struct lov_mds_md_v1 *lmm,
					   __u64 start, __u64 end,
					   __u32 comp_id,
					   bool ext, bool *dom)
{
	__u32 magic;
	__u32 pattern;
	__u32 size;

	magic = le32_to_cpu(lmm->lmm_magic);
	/* If magic crashed, keep it there. Sometime later, during OST-object
	 * orphan handling, if some OST-object(s) back-point to it, it can be
	 * verified and repaired. */
	if (magic != LOV_MAGIC_V1 && magic != LOV_MAGIC_V3) {
		int rc;

		if ((magic & LOV_MAGIC_MASK) == LOV_MAGIC_MAGIC)
			rc = -EOPNOTSUPP;
		else
			rc = -EINVAL;

		CDEBUG(D_LFSCK, "%s LOV EA magic 0x%X for the file "DFID"\n",
		       rc == -EINVAL ? "Unknown" : "Unsupported",
		       magic, PFID(lfsck_dto2fid(obj)));

		return rc;
	}

	pattern = le32_to_cpu(lmm->lmm_pattern);
	*dom = !!(lov_pattern(pattern) == LOV_PATTERN_MDT);

	/* XXX: DoM file verification will be supportted via LU-11081. */
	if (lov_pattern(pattern) == LOV_PATTERN_MDT) {
#if 0
		if (start != 0) {
			CDEBUG(D_LFSCK, "The DoM entry for "DFID" is not "
			       "the first component in the mirror %x/%llu\n",
			       PFID(lfsck_dto2fid(obj)), comp_id, start);

			return -EINVAL;
		}
#endif
	} else if (!lov_pattern_supported_normal_comp(lov_pattern(pattern))) {
		CDEBUG(D_LFSCK, "Unsupported LOV EA pattern %u for the file "
		       DFID" in the component %x\n",
		       pattern, PFID(lfsck_dto2fid(obj)), comp_id);

		return -EOPNOTSUPP;
	}

	size = le32_to_cpu(lmm->lmm_stripe_size);
	if (!ext && end != LUSTRE_EOF && start != end &&
	    !lfsck_comp_extent_aligned(end, size)){
		CDEBUG(D_LFSCK, "not aligned border in PFL extent range "
		       "[%llu - %llu) stripesize %u for the file "DFID
		       " at idx %d\n", start, end, size,
		       PFID(lfsck_dto2fid(obj)), comp_id);

		return -EINVAL;
	}

	return 0;
}

static int lfsck_layout_verify_header_foreign(struct dt_object *obj,
					      struct lov_foreign_md *lfm,
					      size_t len)
{
	/* magic has been verified already */
	__u32 value_len = le32_to_cpu(lfm->lfm_length);
	/* type and flags are not checked for instance */

	CDEBUG(D_INFO, "foreign LOV EA, magic %x, len %u, type %x, flags %x, for file "DFID"\n",
	       le32_to_cpu(lfm->lfm_magic), value_len,
	       le32_to_cpu(lfm->lfm_type), le32_to_cpu(lfm->lfm_flags),
	       PFID(lfsck_dto2fid(obj)));

	if (len != value_len + offsetof(typeof(*lfm), lfm_value))
		CDEBUG(D_LFSCK, "foreign LOV EA internal size %u does not match EA full size %zu for file "DFID"\n",
		       value_len, len, PFID(lfsck_dto2fid(obj)));

	/* nothing to repair */
	return -ENODATA;
}

static int lfsck_layout_verify_header(struct dt_object *obj,
				      struct lov_mds_md_v1 *lmm, size_t len)
{
	bool p_dom = false;
	int rc = 0;

	if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_COMP_V1 ||
	    le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_SEL) {
		struct lov_comp_md_v1 *lcm = (struct lov_comp_md_v1 *)lmm;
		bool p_zero = false;
		int i;
		__u16 count = le16_to_cpu(lcm->lcm_entry_count);

		if (unlikely(count == 0)) {
			CDEBUG(D_LFSCK, "the PFL file "DFID" contains invalid "
			       "components count 0\n",
			       PFID(lfsck_dto2fid(obj)));

			return -EINVAL;
		}

		for (i = 0; i < count && !rc; i++) {
			struct lov_comp_md_entry_v1 *lcme =
						&lcm->lcm_entries[i];
			__u64 start = le64_to_cpu(lcme->lcme_extent.e_start);
			__u64 end = le64_to_cpu(lcme->lcme_extent.e_end);
			__u32 comp_id = le32_to_cpu(lcme->lcme_id);
			bool ext, inited, zero;
			__u32 flags;

			if (unlikely(comp_id == LCME_ID_INVAL ||
				     comp_id > LCME_ID_MAX)) {
				CDEBUG(D_LFSCK, "found invalid PFL ID %u "
				       "for the file "DFID" at idx %d\n",
				       comp_id, PFID(lfsck_dto2fid(obj)), i);

				return -EINVAL;
			}

			flags = le32_to_cpu(lcme->lcme_flags);
			ext = flags & LCME_FL_EXTENSION;
			inited = flags & LCME_FL_INIT;
			zero = !!(start == end);

			if ((i == 0) && zero) {
				CDEBUG(D_LFSCK, "invalid PFL comp %d: [%llu "
				       "- %llu) for "DFID"\n", i, start, end,
				       PFID(lfsck_dto2fid(obj)));
				return -EINVAL;
			}

			if ((zero && (inited || (i + 1 == count))) ||
			    (start > end)) {
				CDEBUG(D_LFSCK, "invalid PFL comp %d/%d: "
				       "[%llu, %llu) for "DFID", %sinited\n",
				       i, count, start, end,
				       PFID(lfsck_dto2fid(obj)),
				       inited ? "" : "NOT ");
				return -EINVAL;
			}

			if (!ext && p_zero) {
				CDEBUG(D_LFSCK, "invalid PFL comp %d: [%llu, "
				       "%llu) for "DFID": NOT extension "
				       "after 0-length component\n", i,
				       start, end, PFID(lfsck_dto2fid(obj)));
				return -EINVAL;
			}

			if (ext && (inited || p_dom || zero)) {
				CDEBUG(D_LFSCK, "invalid PFL comp %d: [%llu, "
				       "%llu) for "DFID": %s\n", i,
				       start, end, PFID(lfsck_dto2fid(obj)),
				       inited ? "inited extension" :
				       p_dom ? "extension follows DOM" :
				       zero ? "zero length extension" : "");
				return -EINVAL;
			}

			rc = lfsck_layout_verify_header_v1v3(obj,
					(struct lov_mds_md_v1 *)((char *)lmm +
					le32_to_cpu(lcme->lcme_offset)), start,
					end, comp_id, ext, &p_dom);

			p_zero = zero;
		}
	} else if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_FOREIGN) {
		rc = lfsck_layout_verify_header_foreign(obj,
						(struct lov_foreign_md *)lmm,
						len);
	} else {
		rc = lfsck_layout_verify_header_v1v3(obj, lmm, 0, LUSTRE_EOF,
						     0, false, &p_dom);
	}

	return rc;
}

static int lfsck_layout_get_lovea(const struct lu_env *env,
				  struct dt_object *obj, struct lu_buf *buf)
{
	int rc;
	int rc1;

again:
	rc = dt_xattr_get(env, obj, buf, XATTR_NAME_LOV);
	if (rc == -ERANGE) {
		rc = dt_xattr_get(env, obj, &LU_BUF_NULL, XATTR_NAME_LOV);
		if (rc <= 0)
			return !rc ? -ENODATA : rc;

		lu_buf_realloc(buf, rc);
		if (buf->lb_buf == NULL)
			return -ENOMEM;

		goto again;
	}

	if (rc <= 0)
		return !rc ? -ENODATA : rc;

	if (unlikely(buf->lb_buf == NULL)) {
		lu_buf_alloc(buf, rc);
		if (buf->lb_buf == NULL)
			return -ENOMEM;

		goto again;
	}

	rc1 = lfsck_layout_verify_header(obj, buf->lb_buf, rc);

	return rc1 ? rc1 : rc;
}

#define LFSCK_RBTREE_BITMAP_SIZE	PAGE_SIZE
#define LFSCK_RBTREE_BITMAP_WIDTH	(LFSCK_RBTREE_BITMAP_SIZE << 3)
#define LFSCK_RBTREE_BITMAP_MASK	(LFSCK_RBTREE_BITMAP_WIDTH - 1)

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

	if (oid - lrn->lrn_first_oid >= LFSCK_RBTREE_BITMAP_WIDTH)
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

	RB_CLEAR_NODE(&lrn->lrn_node);
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
	struct rb_node		 **pos    = &llsd->llsd_rb_root.rb_node;
	struct rb_node		  *parent = NULL;
	struct lfsck_rbtree_node  *tmp;
	int			   rc;

	while (*pos != NULL) {
		parent = *pos;
		tmp = rb_entry(parent, struct lfsck_rbtree_node, lrn_node);
		rc = lfsck_rbtree_cmp(tmp, lrn->lrn_seq, lrn->lrn_first_oid);
		if (rc < 0)
			pos = &(*pos)->rb_left;
		else if (rc > 0)
			pos = &(*pos)->rb_right;
		else
			return tmp;
	}

	rb_link_node(&lrn->lrn_node, parent, pos);
	rb_insert_color(&lrn->lrn_node, &llsd->llsd_rb_root);

	return lrn;
}

static const struct dt_index_operations lfsck_orphan_index_ops;

static int lfsck_rbtree_setup(const struct lu_env *env,
			      struct lfsck_component *com)
{
	struct lu_fid			*fid	= &lfsck_env_info(env)->lti_fid;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev	= lfsck->li_bottom;
	struct lfsck_layout_slave_data	*llsd	= com->lc_data;
	struct dt_object		*obj;

	fid->f_seq = FID_SEQ_LAYOUT_RBTREE;
	fid->f_oid = lfsck_dev_idx(lfsck);
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

	CDEBUG(D_LFSCK, "%s: layout LFSCK init OST-objects accessing bitmap\n",
	       lfsck_lfsck2name(lfsck));

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
	down_write(&llsd->llsd_rb_rwsem);
	llsd->llsd_rbtree_valid = 0;
	up_write(&llsd->llsd_rb_rwsem);

	while (node != NULL) {
		next = rb_next(node);
		lrn = rb_entry(node, struct lfsck_rbtree_node, lrn_node);
		rb_erase(node, &llsd->llsd_rb_root);
		lfsck_rbtree_free(lrn);
		node = next;
	}

	if (llsd->llsd_rb_obj != NULL) {
		lfsck_object_put(env, llsd->llsd_rb_obj);
		llsd->llsd_rb_obj = NULL;
	}

	CDEBUG(D_LFSCK, "%s: layout LFSCK fini OST-objects accessing bitmap\n",
	       lfsck_lfsck2name(lfsck));
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

	if (unlikely(!fid_is_sane(fid) || fid_is_last_id(fid)))
		RETURN_EXIT;

	if (!fid_is_idif(fid) && !fid_is_norm(fid))
		RETURN_EXIT;

	down_read(&llsd->llsd_rb_rwsem);
	if (!llsd->llsd_rbtree_valid)
		GOTO(unlock, rc = 0);

	lrn = lfsck_rbtree_search(llsd, fid, NULL);
	if (lrn == NULL) {
		struct lfsck_rbtree_node *tmp;

		LASSERT(!insert);

		up_read(&llsd->llsd_rb_rwsem);
		tmp = lfsck_rbtree_new(env, fid);
		if (IS_ERR(tmp))
			GOTO(out, rc = PTR_ERR(tmp));

		insert = true;
		down_write(&llsd->llsd_rb_rwsem);
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
		up_write(&llsd->llsd_rb_rwsem);
	else
		up_read(&llsd->llsd_rb_rwsem);
out:
	if (rc != 0 && accessed) {
		struct lfsck_layout *lo = com->lc_file_ram;

		CDEBUG(D_LFSCK, "%s: fail to update OST-objects accessing "
		       "bitmap, and will cause incorrect LFSCK OST-object "
		       "handling, so disable it to cancel orphan handling "
		       "for related device. rc = %d\n",
		       lfsck_lfsck2name(com->lc_lfsck), rc);

		lo->ll_flags |= LF_INCOMPLETE;
		lfsck_rbtree_cleanup(env, com);
	}
}

static inline void lldk_le_to_cpu(struct lfsck_layout_dangling_key *des,
				  const struct lfsck_layout_dangling_key *src)
{
	fid_le_to_cpu(&des->lldk_fid, &src->lldk_fid);
	des->lldk_comp_id = le32_to_cpu(src->lldk_comp_id);
	des->lldk_ea_off = le32_to_cpu(src->lldk_ea_off);
}

static inline void lldk_cpu_to_le(struct lfsck_layout_dangling_key *des,
				  const struct lfsck_layout_dangling_key *src)
{
	fid_cpu_to_le(&des->lldk_fid, &src->lldk_fid);
	des->lldk_comp_id = cpu_to_le32(src->lldk_comp_id);
	des->lldk_ea_off = cpu_to_le32(src->lldk_ea_off);
}

static inline void lldk_be_to_cpu(struct lfsck_layout_dangling_key *des,
				  const struct lfsck_layout_dangling_key *src)
{
	fid_be_to_cpu(&des->lldk_fid, &src->lldk_fid);
	des->lldk_comp_id = be32_to_cpu(src->lldk_comp_id);
	des->lldk_ea_off = be32_to_cpu(src->lldk_ea_off);
}

static inline void lldk_cpu_to_be(struct lfsck_layout_dangling_key *des,
				  const struct lfsck_layout_dangling_key *src)
{
	fid_cpu_to_be(&des->lldk_fid, &src->lldk_fid);
	des->lldk_comp_id = cpu_to_be32(src->lldk_comp_id);
	des->lldk_ea_off = cpu_to_be32(src->lldk_ea_off);
}

static void lfsck_layout_le_to_cpu(struct lfsck_layout *des,
				   const struct lfsck_layout *src)
{
	int i;

	des->ll_magic = le32_to_cpu(src->ll_magic);
	des->ll_status = le32_to_cpu(src->ll_status);
	des->ll_flags = le32_to_cpu(src->ll_flags);
	des->ll_success_count = le32_to_cpu(src->ll_success_count);
	des->ll_run_time_phase1 = le64_to_cpu(src->ll_run_time_phase1);
	des->ll_run_time_phase2 = le64_to_cpu(src->ll_run_time_phase2);
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
	des->ll_bitmap_size = le32_to_cpu(src->ll_bitmap_size);
	lldk_le_to_cpu(&des->ll_lldk_latest_scanned_phase2,
		       &src->ll_lldk_latest_scanned_phase2);
}

static void lfsck_layout_cpu_to_le(struct lfsck_layout *des,
				   const struct lfsck_layout *src)
{
	int i;

	des->ll_magic = cpu_to_le32(src->ll_magic);
	des->ll_status = cpu_to_le32(src->ll_status);
	des->ll_flags = cpu_to_le32(src->ll_flags);
	des->ll_success_count = cpu_to_le32(src->ll_success_count);
	des->ll_run_time_phase1 = cpu_to_le64(src->ll_run_time_phase1);
	des->ll_run_time_phase2 = cpu_to_le64(src->ll_run_time_phase2);
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
	des->ll_bitmap_size = cpu_to_le32(src->ll_bitmap_size);
	lldk_cpu_to_le(&des->ll_lldk_latest_scanned_phase2,
		       &src->ll_lldk_latest_scanned_phase2);
}

/**
 * Load the OST bitmap from the lfsck_layout trace file.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 *
 * \retval		0 for success
 * \retval		negative error number on failure or data corruption
 */
static int lfsck_layout_load_bitmap(const struct lu_env *env,
				    struct lfsck_component *com)
{
	struct dt_object		*obj	= com->lc_obj;
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_layout		*lo	= com->lc_file_ram;
	struct cfs_bitmap			*bitmap = lad->lad_bitmap;
	loff_t				 pos	= com->lc_file_size;
	ssize_t				 size;
	__u32				 nbits;
	int				 rc;
	ENTRY;

	if (com->lc_lfsck->li_ost_descs.ltd_tgts_bitmap->size >
	    lo->ll_bitmap_size)
		nbits = com->lc_lfsck->li_ost_descs.ltd_tgts_bitmap->size;
	else
		nbits = lo->ll_bitmap_size;

	if (unlikely(nbits < BITS_PER_LONG))
		nbits = BITS_PER_LONG;

	if (nbits > bitmap->size) {
		__u32 new_bits = bitmap->size;
		struct cfs_bitmap *new_bitmap;

		while (new_bits < nbits)
			new_bits <<= 1;

		new_bitmap = CFS_ALLOCATE_BITMAP(new_bits);
		if (new_bitmap == NULL)
			RETURN(-ENOMEM);

		lad->lad_bitmap = new_bitmap;
		CFS_FREE_BITMAP(bitmap);
		bitmap = new_bitmap;
	}

	if (lo->ll_bitmap_size == 0) {
		clear_bit(LAD_INCOMPLETE, &lad->lad_flags);
		CFS_RESET_BITMAP(bitmap);

		RETURN(0);
	}

	size = (lo->ll_bitmap_size + 7) >> 3;
	rc = dt_read(env, obj, lfsck_buf_get(env, bitmap->data, size), &pos);
	if (rc != size)
		RETURN(rc >= 0 ? -EINVAL : rc);

	if (cfs_bitmap_check_empty(bitmap))
		clear_bit(LAD_INCOMPLETE, &lad->lad_flags);
	else
		set_bit(LAD_INCOMPLETE, &lad->lad_flags);

	RETURN(0);
}

/**
 * Load the layout LFSCK trace file from disk.
 *
 * The layout LFSCK trace file records the layout LFSCK status information
 * and other statistics, such as how many objects have been scanned, and how
 * many objects have been repaired, and etc. It also contains the bitmap for
 * failed OSTs during the layout LFSCK. All these information will be loaded
 * from disk to RAM when the layout LFSCK component setup.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 *
 * \retval		positive number for file data corruption, the caller
 *			should reset the layout LFSCK trace file
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_layout_load(const struct lu_env *env,
			     struct lfsck_component *com)
{
	struct lfsck_layout		*lo	= com->lc_file_ram;
	ssize_t				 size	= com->lc_file_size;
	loff_t				 pos	= 0;
	int				 rc;

	rc = dt_read(env, com->lc_obj,
		     lfsck_buf_get(env, com->lc_file_disk, size), &pos);
	if (rc == 0) {
		return -ENOENT;
	} else if (rc < 0) {
		CDEBUG(D_LFSCK, "%s: failed to load lfsck_layout: rc = %d\n",
		       lfsck_lfsck2name(com->lc_lfsck), rc);
		return rc;
	} else if (rc != size) {
		CDEBUG(D_LFSCK, "%s: lfsck_layout size %u != %u; reset it\n",
		       lfsck_lfsck2name(com->lc_lfsck), rc, (unsigned int)size);
		return 1;
	}

	lfsck_layout_le_to_cpu(lo, com->lc_file_disk);
	if (lo->ll_magic != LFSCK_LAYOUT_MAGIC) {
		CDEBUG(D_LFSCK, "%s: invalid lfsck_layout magic %#x != %#x, "
		       "to be reset\n", lfsck_lfsck2name(com->lc_lfsck),
		       lo->ll_magic, LFSCK_LAYOUT_MAGIC);
		return 1;
	}

	return 0;
}

/**
 * Store the layout LFSCK trace file on disk.
 *
 * The layout LFSCK trace file records the layout LFSCK status information
 * and other statistics, such as how many objects have been scanned, and how
 * many objects have been repaired, and etc. It also contains the bitmap for
 * failed OSTs during the layout LFSCK. All these information will be synced
 * from RAM to disk periodically.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_layout_store(const struct lu_env *env,
			      struct lfsck_component *com)
{
	struct dt_object	*obj	= com->lc_obj;
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_layout	*lo_ram	= com->lc_file_ram;
	struct lfsck_layout	*lo	= com->lc_file_disk;
	struct thandle		*th;
	struct dt_device	*dev	= lfsck_obj2dev(obj);
	struct cfs_bitmap	*bitmap = NULL;
	loff_t			 pos;
	ssize_t			 size	= com->lc_file_size;
	__u32			 nbits	= 0;
	int			 rc;
	ENTRY;

	if (lfsck->li_master) {
		struct lfsck_assistant_data *lad = com->lc_data;

		bitmap = lad->lad_bitmap;
		nbits = bitmap->size;

		LASSERT(nbits > 0);
		LASSERTF((nbits & 7) == 0, "Invalid nbits %u\n", nbits);
	}

	lo_ram->ll_bitmap_size = nbits;
	lfsck_layout_cpu_to_le(lo, lo_ram);
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	rc = dt_declare_record_write(env, obj, lfsck_buf_get(env, lo, size),
				     (loff_t)0, th);
	if (rc != 0)
		GOTO(out, rc);

	if (bitmap != NULL) {
		rc = dt_declare_record_write(env, obj,
				lfsck_buf_get(env, bitmap->data, nbits >> 3),
				(loff_t)size, th);
		if (rc != 0)
			GOTO(out, rc);
	}

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(out, rc);

	pos = 0;
	rc = dt_record_write(env, obj, lfsck_buf_get(env, lo, size), &pos, th);
	if (rc != 0)
		GOTO(out, rc);

	if (bitmap != NULL) {
		pos = size;
		rc = dt_record_write(env, obj,
				lfsck_buf_get(env, bitmap->data, nbits >> 3),
				&pos, th);
	}

	GOTO(out, rc);

out:
	dt_trans_stop(env, dev, th);

log:
	if (rc != 0)
		CDEBUG(D_LFSCK, "%s: fail to store lfsck_layout: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);

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
	if (rc == 0 && com->lc_lfsck->li_master)
		rc = lfsck_load_sub_trace_files(env, com,
			&dt_lfsck_layout_dangling_features, LFSCK_LAYOUT, true);
	up_write(&com->lc_sem);

	return rc;
}

static int fid_is_for_ostobj(const struct lu_env *env,
			     struct lfsck_instance *lfsck,
			     struct dt_object *obj, const struct lu_fid *fid)
{
	struct seq_server_site	*ss	= lfsck_dev_site(lfsck);
	struct lu_seq_range	*range	= &lfsck_env_info(env)->lti_range;
	struct lustre_ost_attrs *loa;
	int			 rc;

	fld_range_set_any(range);
	rc = fld_server_lookup(env, ss->ss_server_fld, fid_seq(fid), range);
	if (rc == 0) {
		if (fld_range_is_ost(range))
			return 1;

		return 0;
	}

	loa = &lfsck_env_info(env)->lti_loa;
	rc = dt_xattr_get(env, obj, lfsck_buf_get(env, loa, sizeof(*loa)),
			  XATTR_NAME_LMA);
	if (rc >= (int)sizeof(struct lustre_mdt_attrs)) {
		lustre_lma_swab(&loa->loa_lma);

		return loa->loa_lma.lma_compat & LMAC_FID_ON_OST ? 1 : 0;
	}

	rc = dt_xattr_get(env, obj, &LU_BUF_NULL, XATTR_NAME_FID);

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
	struct dt_device	 *dt	 = lfsck_obj2dev(obj);
	struct thandle		 *th;
	__u64			  lastid = 0;
	loff_t			  pos	 = 0;
	int			  rc;
	ENTRY;

	if (bk->lb_param & LPF_DRYRUN)
		return 0;

	memset(la, 0, sizeof(*la));
	la->la_mode = S_IFREG |  S_IRUGO | S_IWUSR;
	la->la_valid = LA_MODE | LA_UID | LA_GID;
	memset(dof, 0, sizeof(*dof));
	dof->dof_type = dt_mode_to_dft(S_IFREG);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	rc = dt_declare_create(env, obj, la, NULL, dof, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_record_write(env, obj,
				     lfsck_buf_get(env, &lastid,
						   sizeof(lastid)),
				     pos, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dt, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	if (likely(dt_object_exists(obj) == 0)) {
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

log:
	CDEBUG(D_LFSCK, "%s: layout LFSCK will create LAST_ID for <seq> "
	       "%#llx: rc = %d\n",
	       lfsck_lfsck2name(lfsck), fid_seq(lfsck_dto2fid(obj)), rc);

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

			CDEBUG(D_LFSCK, "%s: layout LFSCK finds crashed "
			       "LAST_ID file (1) for the sequence %#llx"
			       ", old value %llu, known value %llu\n",
			       lfsck_lfsck2name(lfsck), lls->lls_seq,
			       lastid, lls->lls_lastid);
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

		if (!lls->lls_dirty)
			continue;

		CDEBUG(D_LFSCK, "%s: layout LFSCK will sync the LAST_ID for "
		       "<seq> %#llx as <oid> %llu\n",
		       lfsck_lfsck2name(lfsck), lls->lls_seq, lls->lls_lastid);

		if (bk->lb_param & LPF_DRYRUN) {
			lls->lls_dirty = 0;
			continue;
		}

		th = dt_trans_create(env, dt);
		if (IS_ERR(th)) {
			rc1 = PTR_ERR(th);
			CDEBUG(D_LFSCK, "%s: layout LFSCK failed to store "
			       "the LAST_ID for <seq> %#llx(1): rc = %d\n",
			       lfsck_lfsck2name(com->lc_lfsck),
			       lls->lls_seq, rc1);
			continue;
		}

		lastid = cpu_to_le64(lls->lls_lastid);
		rc = dt_declare_record_write(env, lls->lls_lastid_obj,
					     lfsck_buf_get(env, &lastid,
							   sizeof(lastid)),
					     pos, th);
		if (rc != 0)
			goto stop;

		rc = dt_trans_start_local(env, dt, th);
		if (rc != 0)
			goto stop;

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
			CDEBUG(D_LFSCK, "%s: layout LFSCK failed to store "
			       "the LAST_ID for <seq> %#llx(2): rc = %d\n",
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

	lu_last_id_fid(fid, lls->lls_seq, lfsck_dev_idx(lfsck));
	obj = dt_locate(env, lfsck->li_bottom, fid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	/* LAST_ID crashed, to be rebuilt */
	if (dt_object_exists(obj) == 0) {
		if (!(lo->ll_flags & LF_CRASHED_LASTID)) {
			LASSERT(lfsck->li_out_notify != NULL);

			lfsck->li_out_notify(env, lfsck->li_out_notify_data,
					     LE_LASTID_REBUILDING);
			lo->ll_flags |= LF_CRASHED_LASTID;

			CDEBUG(D_LFSCK, "%s: layout LFSCK cannot find the "
			       "LAST_ID file for sequence %#llx\n",
			       lfsck_lfsck2name(lfsck), lls->lls_seq);

			if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DELAY4) &&
			    cfs_fail_val > 0) {
				struct ptlrpc_thread *thread =
					&lfsck->li_thread;

				up_write(&com->lc_sem);
				wait_event_idle_timeout(
					thread->t_ctl_waitq,
					!thread_is_running(thread),
					cfs_time_seconds(cfs_fail_val));
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

			CDEBUG(D_LFSCK, "%s: layout LFSCK finds invalid "
			       "LAST_ID file for the sequence %#llx"
			       ": rc = %d\n",
			       lfsck_lfsck2name(lfsck), lls->lls_seq, rc);
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

static void lfsck_layout_record_failure(const struct lu_env *env,
					struct lfsck_instance *lfsck,
					struct lfsck_layout *lo)
{
	__u64 cookie;

	lo->ll_objs_failed_phase1++;
	cookie = lfsck->li_obj_oit->do_index_ops->dio_it.store(env,
							lfsck->li_di_oit);
	if (lo->ll_pos_first_inconsistent == 0 ||
	    lo->ll_pos_first_inconsistent < cookie) {
		lo->ll_pos_first_inconsistent = cookie;

		CDEBUG(D_LFSCK, "%s: layout LFSCK hit first non-repaired "
		       "inconsistency at the pos [%llu]\n",
		       lfsck_lfsck2name(lfsck),
		       lo->ll_pos_first_inconsistent);
	}
}

static int lfsck_layout_double_scan_result(const struct lu_env *env,
					   struct lfsck_component *com,
					   int rc)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_layout	*lo    = com->lc_file_ram;

	CDEBUG(D_LFSCK, "%s: layout LFSCK double scan: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc);

	down_write(&com->lc_sem);
	lo->ll_run_time_phase2 += ktime_get_seconds() -
				  com->lc_time_last_checkpoint;
	lo->ll_time_last_checkpoint = ktime_get_real_seconds();
	lo->ll_objs_checked_phase2 += com->lc_new_checked;

	if (rc > 0) {
		if (lo->ll_flags & LF_INCOMPLETE) {
			lo->ll_status = LS_PARTIAL;
		} else {
			if (lfsck->li_master) {
				struct lfsck_assistant_data *lad = com->lc_data;

				if (test_bit(LAD_INCOMPLETE, &lad->lad_flags))
					lo->ll_status = LS_PARTIAL;
				else
					lo->ll_status = LS_COMPLETED;
			} else {
				lo->ll_status = LS_COMPLETED;
			}
		}
		lo->ll_flags &= ~LF_SCANNED_ONCE;
		if (!(lfsck->li_bookmark_ram.lb_param & LPF_DRYRUN))
			lo->ll_flags &= ~LF_INCONSISTENT;
		lo->ll_time_last_complete = lo->ll_time_last_checkpoint;
		lo->ll_success_count++;
	} else if (rc == 0) {
		if (lfsck->li_status != 0)
			lo->ll_status = lfsck->li_status;
		else
			lo->ll_status = LS_STOPPED;
	} else {
		lo->ll_status = LS_FAILED;
	}

	rc = lfsck_layout_store(env, com);
	up_write(&com->lc_sem);

	CDEBUG(D_LFSCK, "%s: layout LFSCK double scan result %u: rc = %d\n",
	       lfsck_lfsck2name(lfsck), lo->ll_status, rc);

	return rc;
}

static int lfsck_layout_trans_stop(const struct lu_env *env,
				   struct dt_device *dev,
				   struct thandle *handle, int result)
{
	int rc;

	/* XXX: If there is something worng or it needs to repair nothing,
	 *	then notify the lower to stop the modification. Currently,
	 *	we use th_result for such purpose, that may be replaced by
	 *	some rollback mechanism in the future. */
	handle->th_result = result;
	rc = dt_trans_stop(env, dev, handle);
	if (result != 0)
		return result > 0 ? 0 : result;

	return rc == 0 ? 1 : rc;
}

static int lfsck_layout_ins_dangling_rec(const struct lu_env *env,
					 struct lfsck_component *com,
					 const struct lu_fid *pfid,
					 const struct lu_fid *cfid,
					 __u32 comp_id, __u32 ea_off,
					 __u32 ost_idx)
{
	struct lfsck_layout_dangling_key *key = &lfsck_env_info(env)->lti_lldk;
	struct lu_fid *rec = &lfsck_env_info(env)->lti_fid3;
	struct dt_device *dev;
	struct dt_object *obj;
	struct thandle *th = NULL;
	int idx;
	int rc = 0;
	ENTRY;

	idx = lfsck_sub_trace_file_fid2idx(pfid);
	obj = com->lc_sub_trace_objs[idx].lsto_obj;
	dev = lfsck_obj2dev(obj);

	fid_cpu_to_be(&key->lldk_fid, pfid);
	key->lldk_comp_id = cpu_to_be32(comp_id);
	key->lldk_ea_off = cpu_to_be32(ea_off);

	fid_cpu_to_be(rec, cfid);
	rec->f_ver = cpu_to_be32(ost_idx);

	mutex_lock(&com->lc_sub_trace_objs[idx].lsto_mutex);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_insert(env, obj,
			       (const struct dt_rec *)rec,
			       (const struct dt_key *)key, th);
	if (rc)
		GOTO(unlock, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(unlock, rc);

	rc = dt_insert(env, obj, (const struct dt_rec *)rec,
		       (const struct dt_key *)key, th);

	GOTO(unlock, rc);

unlock:
	if (th && !IS_ERR(th))
		dt_trans_stop(env, dev, th);

	mutex_unlock(&com->lc_sub_trace_objs[idx].lsto_mutex);

	CDEBUG(D_LFSCK, "%s: insert the paris "DFID" => "DFID", comp_id = %u, "
	       "ea_off = %u, ost_idx = %u, into the trace file for further "
	       "dangling check: rc = %d\n", lfsck_lfsck2name(com->lc_lfsck),
	       PFID(pfid), PFID(cfid), comp_id, ea_off, ost_idx, rc);

	return rc;
}

static int lfsck_layout_del_dangling_rec(const struct lu_env *env,
					 struct lfsck_component *com,
					 const struct lu_fid *fid,
					 __u32 comp_id, __u32 ea_off)
{
	struct lfsck_layout_dangling_key *key = &lfsck_env_info(env)->lti_lldk;
	struct dt_device *dev;
	struct dt_object *obj;
	struct thandle *th = NULL;
	int idx;
	int rc = 0;
	ENTRY;

	idx = lfsck_sub_trace_file_fid2idx(fid);
	obj = com->lc_sub_trace_objs[idx].lsto_obj;
	dev = lfsck_obj2dev(obj);

	fid_cpu_to_be(&key->lldk_fid, fid);
	key->lldk_comp_id = cpu_to_be32(comp_id);
	key->lldk_ea_off = cpu_to_be32(ea_off);

	mutex_lock(&com->lc_sub_trace_objs[idx].lsto_mutex);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, obj, (const struct dt_key *)key, th);
	if (rc)
		GOTO(unlock, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(unlock, rc);

	rc = dt_delete(env, obj, (const struct dt_key *)key, th);

	GOTO(unlock, rc);

unlock:
	if (th && !IS_ERR(th))
		dt_trans_stop(env, dev, th);

	mutex_unlock(&com->lc_sub_trace_objs[idx].lsto_mutex);

	CDEBUG(D_LFSCK, "%s: delete the dangling record for "DFID
	       ", comp_id = %u, ea_off = %u from the trace file: rc = %d\n",
	       lfsck_lfsck2name(com->lc_lfsck), PFID(fid), comp_id, ea_off, rc);

	return rc;
}

/**
 * Get the system default stripe size.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] lfsck	pointer to the lfsck instance
 * \param[out] size	pointer to the default stripe size
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int lfsck_layout_get_def_stripesize(const struct lu_env *env,
					   struct lfsck_instance *lfsck,
					   __u32 *size)
{
	struct lov_user_md	*lum = &lfsck_env_info(env)->lti_lum;
	struct dt_object	*root;
	int			 rc;

	root = dt_locate(env, lfsck->li_next, &lfsck->li_local_root_fid);
	if (IS_ERR(root))
		return PTR_ERR(root);

	/* Get the default stripe size via xattr_get on the backend root. */
	rc = dt_xattr_get(env, root, lfsck_buf_get(env, lum, sizeof(*lum)),
			  XATTR_NAME_LOV);
	if (rc > 0) {
		/* The lum->lmm_stripe_size is LE mode. The *size also
		 * should be LE mode. So it is unnecessary to convert. */
		*size = lum->lmm_stripe_size;
		rc = 0;
	} else if (unlikely(rc == 0)) {
		rc = -EINVAL;
	}

	lfsck_object_put(env, root);

	return rc;
}

/**
 * \retval	 +1: repaired
 * \retval	  0: did nothing
 * \retval	-ve: on error
 */
static int lfsck_layout_refill_lovea(const struct lu_env *env,
				     struct lfsck_instance *lfsck,
				     struct thandle *handle,
				     struct dt_object *parent,
				     const struct lu_fid *cfid,
				     struct lu_buf *buf,
				     struct lov_mds_md_v1 *lmm,
				     struct lov_ost_data_v1 *slot,
				     int fl, __u32 ost_idx, int size)
{
	struct ost_id		*oi	= &lfsck_env_info(env)->lti_oi;
	struct lu_buf		 ea_buf;
	int			 rc;
	__u32			 magic;
	__u32			 pattern;
	__u16			 count;
	ENTRY;

	magic = le32_to_cpu(lmm->lmm_magic);
	pattern = le32_to_cpu(lmm->lmm_pattern);
	count = le16_to_cpu(lmm->lmm_stripe_count);

	fid_to_ostid(cfid, oi);
	ostid_cpu_to_le(oi, &slot->l_ost_oi);
	slot->l_ost_gen = cpu_to_le32(0);
	slot->l_ost_idx = cpu_to_le32(ost_idx);

	if (pattern & LOV_PATTERN_F_HOLE) {
		struct lov_ost_data_v1 *objs;
		int			i;

		if (magic == LOV_MAGIC_V1)
			objs = &lmm->lmm_objects[0];
		else
			objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
		for (i = 0; i < count; i++, objs++) {
			if (lovea_slot_is_dummy(objs))
				break;
		}

		/* If the @slot is the last dummy slot to be refilled,
		 * then drop LOV_PATTERN_F_HOLE from lmm::lmm_pattern. */
		if (i == count) {
			lmm->lmm_pattern =
				cpu_to_le32(pattern & ~LOV_PATTERN_F_HOLE);

			CDEBUG(D_LFSCK, "%s: remove layout HOLE for "DFID
			       ": parent "DFID"\n", lfsck_lfsck2name(lfsck),
			       PFID(cfid), PFID(lfsck_dto2fid(parent)));
		}
	}

	lfsck_buf_init(&ea_buf, buf->lb_buf, size);
	rc = dt_xattr_set(env, parent, &ea_buf, XATTR_NAME_LOV, fl, handle);
	if (rc == 0)
		rc = 1;

	RETURN(rc);
}

static struct lov_ost_data_v1 *
__lfsck_layout_new_v1_lovea(struct lov_mds_md_v1 *lmm,
			    const struct lu_fid *pfid,
			    __u32 stripe_size, __u32 ea_off,
			    __u32 pattern, __u16 count)
{
	lmm->lmm_magic = cpu_to_le32(LOV_MAGIC_V1);
	lmm->lmm_pattern = cpu_to_le32(pattern);
	fid_to_lmm_oi(pfid, &lmm->lmm_oi);
	lmm_oi_cpu_to_le(&lmm->lmm_oi, &lmm->lmm_oi);
	lmm->lmm_stripe_size = cpu_to_le32(stripe_size);
	lmm->lmm_stripe_count = cpu_to_le16(count);
	lmm->lmm_layout_gen = cpu_to_le16(1);
	memset(&lmm->lmm_objects[0], 0,
	       sizeof(struct lov_ost_data_v1) * count);

	return &lmm->lmm_objects[ea_off];
}

static int lfsck_layout_new_v1_lovea(const struct lu_env *env,
				     struct lfsck_instance *lfsck,
				     struct ost_layout *ol,
				     struct dt_object *parent,
				     struct lu_buf *buf, __u32 ea_off,
				     struct lov_mds_md_v1 **lmm,
				     struct lov_ost_data_v1 **objs)
{
	int size;
	__u32 stripe_size = ol->ol_stripe_size;
	__u32 pattern = LOV_PATTERN_RAID0;
	__u16 count;

	if (ol->ol_stripe_count != 0)
		count = ol->ol_stripe_count;
	else
		count = ea_off + 1;

	size = lov_mds_md_size(count, LOV_MAGIC_V1);
	LASSERTF(buf->lb_len >= size,
		 "buffer len %d is less than real size %d\n",
		 (int)buf->lb_len, size);

	if (stripe_size == 0) {
		int rc;

		rc = lfsck_layout_get_def_stripesize(env, lfsck, &stripe_size);
		if (rc)
			return rc;
	}

	*lmm = buf->lb_buf;
	if (ol->ol_stripe_count > 1 ||
	    (ol->ol_stripe_count == 0 && ea_off != 0)) {
		pattern |= LOV_PATTERN_F_HOLE;
		memset(&(*lmm)->lmm_objects[0], 0,
		       count * sizeof(struct lov_ost_data_v1));
	}

	*objs = __lfsck_layout_new_v1_lovea(*lmm, lfsck_dto2fid(parent),
				stripe_size, ea_off, pattern, count);

	return size;
}

static int lfsck_layout_new_comp_lovea(const struct lu_env *env,
				       struct lu_orphan_rec_v3 *rec,
				       struct dt_object *parent,
				       struct lu_buf *buf, __u32 ea_off,
				       struct lov_mds_md_v1 **lmm,
				       struct lov_ost_data_v1 **objs)
{
	struct ost_layout *ol = &rec->lor_layout;
	struct lov_comp_md_v1 *lcm;
	struct lov_comp_md_entry_v1 *lcme;
	__u32 pattern = LOV_PATTERN_RAID0;
	__u32 offset = sizeof(*lcm) + sizeof(*lcme);
	int lcme_size = lov_mds_md_size(ol->ol_stripe_count, LOV_MAGIC_V1);
	int size = offset + lcme_size;

	LASSERTF(buf->lb_len >= size,
		 "buffer len %d is less than real size %d\n",
		 (int)buf->lb_len, size);

	lcm = buf->lb_buf;
	lcm->lcm_magic = cpu_to_le32(LOV_MAGIC_COMP_V1);
	lcm->lcm_size = cpu_to_le32(size);
	if (rec->lor_range) {
		lcm->lcm_layout_gen = cpu_to_le32(rec->lor_layout_version +
						  rec->lor_range);
		lcm->lcm_flags = cpu_to_le16(LCM_FL_WRITE_PENDING);
	} else if (rec->lor_layout_version) {
		lcm->lcm_layout_gen = cpu_to_le32(rec->lor_layout_version +
						  rec->lor_range);
		lcm->lcm_flags = cpu_to_le16(LCM_FL_NONE);
	} else {
		lcm->lcm_layout_gen = cpu_to_le32(1);
		lcm->lcm_flags = cpu_to_le16(LCM_FL_NONE);
	}
	lcm->lcm_entry_count = cpu_to_le16(1);
	/* Currently, we do not know how many mirrors will be, set it as zero
	 * at the beginning. It will be updated when more mirrors are found. */
	lcm->lcm_mirror_count = 0;

	lcme = &lcm->lcm_entries[0];
	lcme->lcme_id = cpu_to_le32(ol->ol_comp_id);
	lcme->lcme_flags = cpu_to_le32(LCME_FL_INIT);
	lcme->lcme_extent.e_start = cpu_to_le64(ol->ol_comp_start);
	lcme->lcme_extent.e_end = cpu_to_le64(ol->ol_comp_end);
	lcme->lcme_offset = cpu_to_le32(offset);
	lcme->lcme_size = cpu_to_le32(lcme_size);
	lcme->lcme_layout_gen = lcm->lcm_layout_gen;
	if (ol->ol_stripe_count > 1)
		pattern |= LOV_PATTERN_F_HOLE;

	*lmm = buf->lb_buf + offset;
	*objs = __lfsck_layout_new_v1_lovea(*lmm, lfsck_dto2fid(parent),
					    ol->ol_stripe_size, ea_off,
					    pattern, ol->ol_stripe_count);

	return size;
}

static void lfsck_layout_update_lcm(struct lov_comp_md_v1 *lcm,
				    struct lov_comp_md_entry_v1 *lcme,
				    __u32 version, __u32 range)
{
	struct lov_comp_md_entry_v1 *tmp;
	__u64 start = le64_to_cpu(lcme->lcme_extent.e_start);
	__u64 end = le64_to_cpu(lcme->lcme_extent.e_end);
	__u32 gen = version + range;
	__u32 tmp_gen;
	int i;
	__u16 count = le16_to_cpu(lcm->lcm_entry_count);
	__u16 flags = le16_to_cpu(lcm->lcm_flags);

	if (!gen)
		gen = 1;
	lcme->lcme_layout_gen = cpu_to_le32(gen);
	if (le32_to_cpu(lcm->lcm_layout_gen) < gen)
		lcm->lcm_layout_gen = cpu_to_le32(gen);

	if (range)
		lcm->lcm_flags = cpu_to_le16(LCM_FL_WRITE_PENDING);
	else if (flags == LCM_FL_NONE && le16_to_cpu(lcm->lcm_mirror_count) > 0)
		lcm->lcm_flags = cpu_to_le16(LCM_FL_RDONLY);

	for (i = 0; i < count; i++) {
		tmp = &lcm->lcm_entries[i];
		if (le64_to_cpu(tmp->lcme_extent.e_end) <= start)
			continue;

		if (le64_to_cpu(tmp->lcme_extent.e_start) >= end)
			continue;

		if (le32_to_cpu(tmp->lcme_flags) & LCME_FL_STALE)
			continue;

		tmp_gen = le32_to_cpu(tmp->lcme_layout_gen);
		/* "lcme_layout_gen == 0" but without LCME_FL_STALE flag,
		 * then it should be the latest version of all mirrors. */
		if (tmp_gen == 0 || tmp_gen > gen) {
			lcme->lcme_flags = cpu_to_le32(
				le32_to_cpu(lcme->lcme_flags) | LCME_FL_STALE);
			break;
		}

		if (tmp_gen < gen)
			tmp->lcme_flags = cpu_to_le32(
				le32_to_cpu(tmp->lcme_flags) | LCME_FL_STALE);
	}
}

static int lfsck_layout_add_comp(const struct lu_env *env,
				 struct lfsck_instance *lfsck,
				 struct thandle *handle,
				 struct lu_orphan_rec_v3 *rec,
				 struct dt_object *parent,
				 const struct lu_fid *cfid,
				 struct lu_buf *buf, __u32 ost_idx,
				 __u32 ea_off, int pos, bool new_mirror)
{
	struct ost_layout *ol = &rec->lor_layout;
	struct lov_comp_md_v1 *lcm = buf->lb_buf;
	struct lov_comp_md_entry_v1 *lcme;
	struct lov_mds_md_v1 *lmm;
	struct lov_ost_data_v1 *objs;
	int added = sizeof(*lcme) +
		    lov_mds_md_size(ol->ol_stripe_count, LOV_MAGIC_V1);
	int size = le32_to_cpu(lcm->lcm_size) + added;
	int rc;
	int i;
	__u32 offset;
	__u32 pattern = LOV_PATTERN_RAID0;
	__u16 count = le16_to_cpu(lcm->lcm_entry_count);
	ENTRY;

	lu_buf_check_and_grow(buf, size);
	/* set the lcm again because lu_buf_check_and_grow() may
	 * have reallocated the buf. */
	lcm = buf->lb_buf;
	lcm->lcm_size = cpu_to_le32(size);
	lcm->lcm_entry_count = cpu_to_le16(count + 1);
	if (new_mirror)
		le16_add_cpu(&lcm->lcm_mirror_count, 1);

	/* 1. Move the component bodies from [pos, count-1] to [pos+1, count]
	 *    with distance of 'added'. */
	if (pos < count) {
		size = 0;
		for (i = pos; i < count; i++) {
			lcme = &lcm->lcm_entries[i];
			size += le32_to_cpu(lcme->lcme_size);
		}

		offset = le32_to_cpu(lcm->lcm_entries[pos].lcme_offset);
		memmove(buf->lb_buf + offset + added,
			buf->lb_buf + offset, size);
	}

	size = 0;
	/* 2. Move the component header [0, pos-1] to [0, pos-1] with distance
	 *    of 'sizeof(struct lov_comp_md_entry_v1)' */
	if (pos > 0) {
		for (i = 0; i < pos; i++) {
			lcme = &lcm->lcm_entries[i];
			size += le32_to_cpu(lcme->lcme_size);
		}

		offset = le32_to_cpu(lcm->lcm_entries[0].lcme_offset);
		memmove(buf->lb_buf + offset + sizeof(*lcme),
			buf->lb_buf + offset, size);
	}

	/* 3. Recalculate the enter offset for the component [pos, count-1] */
	for (i = count - 1; i >= pos; i--) {
		lcm->lcm_entries[i + 1] = lcm->lcm_entries[i];
		lcm->lcm_entries[i + 1].lcme_offset =
			cpu_to_le32(le32_to_cpu(lcm->lcm_entries[i + 1].
						lcme_offset) + added);
	}

	/* 4. Recalculate the enter offset for the component [0, pos) */
	for (i = 0; i < pos; i++) {
		lcm->lcm_entries[i].lcme_offset =
			cpu_to_le32(le32_to_cpu(lcm->lcm_entries[i].
						lcme_offset) + sizeof(*lcme));
	}

	offset = sizeof(*lcm) + sizeof(*lcme) * (count + 1) + size;
	/* 4. Insert the new component header (entry) at the slot 'pos'. */
	lcme = &lcm->lcm_entries[pos];
	lcme->lcme_id = cpu_to_le32(ol->ol_comp_id);
	lcme->lcme_flags = cpu_to_le32(LCME_FL_INIT);
	lcme->lcme_extent.e_start = cpu_to_le64(ol->ol_comp_start);
	lcme->lcme_extent.e_end = cpu_to_le64(ol->ol_comp_end);
	lcme->lcme_offset = cpu_to_le32(offset);
	lcme->lcme_size = cpu_to_le32(lov_mds_md_size(ol->ol_stripe_count,
						      LOV_MAGIC_V1));

	if (ol->ol_stripe_count > 1)
		pattern |= LOV_PATTERN_F_HOLE;

	lmm = buf->lb_buf + offset;
	/* 5. Insert teh new component body at the 'offset'. */
	objs = __lfsck_layout_new_v1_lovea(lmm, lfsck_dto2fid(parent),
					   ol->ol_stripe_size, ea_off,
					   pattern, ol->ol_stripe_count);

	/* 6. Update mirror related flags and version. */
	lfsck_layout_update_lcm(lcm, lcme, rec->lor_layout_version,
				rec->lor_range);

	rc = lfsck_layout_refill_lovea(env, lfsck, handle, parent, cfid, buf,
				       lmm, objs, LU_XATTR_REPLACE, ost_idx,
				       le32_to_cpu(lcm->lcm_size));

	CDEBUG(D_LFSCK, "%s: layout LFSCK assistant add new COMP for "
	       DFID": parent "DFID", OST-index %u, stripe-index %u, "
	       "stripe_size %u, stripe_count %u, comp_id %u, comp_start %llu, "
	       "comp_end %llu, layout version %u, range %u, "
	       "%s LOV EA hole: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(cfid), PFID(lfsck_dto2fid(parent)),
	       ost_idx, ea_off, ol->ol_stripe_size, ol->ol_stripe_count,
	       ol->ol_comp_id, ol->ol_comp_start, ol->ol_comp_end,
	       rec->lor_layout_version, rec->lor_range,
	       le32_to_cpu(lmm->lmm_pattern) & LOV_PATTERN_F_HOLE ?
	       "with" : "without", rc);

	RETURN(rc);
}

static int lfsck_layout_extend_v1v3_lovea(const struct lu_env *env,
					  struct lfsck_instance *lfsck,
					  struct thandle *handle,
					  struct ost_layout *ol,
					  struct dt_object *parent,
					  const struct lu_fid *cfid,
					  struct lu_buf *buf, __u32 ost_idx,
					  __u32 ea_off)
{
	struct lov_mds_md_v1 *lmm = buf->lb_buf;
	struct lov_ost_data_v1 *objs;
	__u16 count = le16_to_cpu(lmm->lmm_stripe_count);
	__u32 magic = le32_to_cpu(lmm->lmm_magic);
	int size;
	int gap;
	int rc;
	ENTRY;

	/* The original LOVEA maybe re-generated via old filter_fid, at
	 * that time, we do not know the stripe count and stripe size. */
	if (ol->ol_stripe_count > count)
		count = ol->ol_stripe_count;
	if (ol->ol_stripe_size != 0 &&
	    ol->ol_stripe_size != le32_to_cpu(lmm->lmm_stripe_size))
		lmm->lmm_stripe_size = cpu_to_le32(ol->ol_stripe_size);

	if (magic == LOV_MAGIC_V1)
		objs = &lmm->lmm_objects[count];
	else
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[count];

	gap = ea_off - count;
	if (gap >= 0)
		count = ea_off + 1;

	size = lov_mds_md_size(count, magic);
	LASSERTF(buf->lb_len >= size,
		 "buffer len %d is less than real size %d\n",
		 (int)buf->lb_len, size);

	if (gap > 0) {
		memset(objs, 0, gap * sizeof(*objs));
		lmm->lmm_pattern |= cpu_to_le32(LOV_PATTERN_F_HOLE);
	}

	lmm->lmm_layout_gen = cpu_to_le16(le16_to_cpu(lmm->lmm_layout_gen) + 1);
	lmm->lmm_stripe_count = cpu_to_le16(count);
	objs += gap;

	rc = lfsck_layout_refill_lovea(env, lfsck, handle, parent, cfid, buf,
				lmm, objs, LU_XATTR_REPLACE, ost_idx, size);

	CDEBUG(D_LFSCK, "%s: layout LFSCK assistant extend layout EA for "
	       DFID": parent "DFID", OST-index %u, stripe-index %u, "
	       "stripe_size %u, stripe_count %u, comp_id %u, comp_start %llu, "
	       "comp_end %llu, %s LOV EA hole: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(cfid), PFID(lfsck_dto2fid(parent)),
	       ost_idx, ea_off, ol->ol_stripe_size, ol->ol_stripe_count,
	       ol->ol_comp_id, ol->ol_comp_start, ol->ol_comp_end,
	       le32_to_cpu(lmm->lmm_pattern) & LOV_PATTERN_F_HOLE ?
	       "with" : "without", rc);

	RETURN(rc);
}

/**
 * \retval	 +1: repaired
 * \retval	  0: did nothing
 * \retval	-ve: on error
 */
static int lfsck_layout_update_lovea(const struct lu_env *env,
				     struct lfsck_instance *lfsck,
				     struct thandle *handle,
				     struct lu_orphan_rec_v3 *rec,
				     struct dt_object *parent,
				     const struct lu_fid *cfid,
				     struct lu_buf *buf, int fl,
				     __u32 ost_idx, __u32 ea_off)
{
	struct ost_layout *ol = &rec->lor_layout;
	struct lov_mds_md_v1 *lmm = NULL;
	struct lov_ost_data_v1 *objs = NULL;
	int rc = 0;
	ENTRY;

	if (ol->ol_comp_id != 0)
		rc = lfsck_layout_new_comp_lovea(env, rec, parent, buf, ea_off,
						 &lmm, &objs);
	else
		rc = lfsck_layout_new_v1_lovea(env, lfsck, &rec->lor_layout,
					       parent, buf, ea_off, &lmm,
					       &objs);
	if (rc > 0)
		rc = lfsck_layout_refill_lovea(env, lfsck, handle, parent, cfid,
					       buf, lmm, objs, fl, ost_idx, rc);

	CDEBUG(D_LFSCK, "%s: layout LFSCK assistant created layout EA for "
	       DFID": parent "DFID", OST-index %u, stripe-index %u, "
	       "stripe_size %u, stripe_count %u, comp_id %u, comp_start %llu, "
	       "comp_end %llu, layout version %u, range %u, fl %d, "
	       "%s LOV EA hole: rc = %d\n",
	       lfsck_lfsck2name(lfsck), PFID(cfid), PFID(lfsck_dto2fid(parent)),
	       ost_idx, ea_off, ol->ol_stripe_size, ol->ol_stripe_count,
	       ol->ol_comp_id, ol->ol_comp_start, ol->ol_comp_end,
	       rec->lor_layout_version, rec->lor_range, fl,
	       le32_to_cpu(lmm->lmm_pattern) & LOV_PATTERN_F_HOLE ?
	       "with" : "without", rc);

	RETURN(rc);
}

static int __lfsck_layout_update_pfid(const struct lu_env *env,
				      struct dt_object *child,
				      const struct lu_fid *pfid,
				      const struct ost_layout *ol, __u32 offset,
				      __u32 version, __u32 range)
{
	struct dt_device	*dev	= lfsck_obj2dev(child);
	struct filter_fid	*ff	= &lfsck_env_info(env)->lti_ff;
	struct thandle		*handle;
	struct lu_buf		 buf	= { NULL };
	int			 rc;

	ff->ff_parent.f_seq = cpu_to_le64(pfid->f_seq);
	ff->ff_parent.f_oid = cpu_to_le32(pfid->f_oid);
	/* Currently, the filter_fid::ff_parent::f_ver is not the real parent
	 * MDT-object's FID::f_ver, instead it is the OST-object index in its
	 * parent MDT-object's layout EA. */
	ff->ff_parent.f_stripe_idx = cpu_to_le32(offset);
	ost_layout_cpu_to_le(&ff->ff_layout, ol);
	ff->ff_layout_version = cpu_to_le32(version);
	ff->ff_range = cpu_to_le32(range);
	lfsck_buf_init(&buf, ff, sizeof(*ff));

	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		RETURN(PTR_ERR(handle));

	rc = dt_declare_xattr_set(env, child, &buf, XATTR_NAME_FID, 0, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_xattr_set(env, child, &buf, XATTR_NAME_FID, 0, handle);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, handle);

	return rc;
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
				    struct dt_device *cdev,
				    struct lu_orphan_rec_v3 *rec, __u32 ea_off)
{
	struct dt_object	*child;
	int			 rc	= 0;
	ENTRY;

	child = lfsck_object_find_by_dev(env, cdev, cfid);
	if (IS_ERR(child))
		RETURN(PTR_ERR(child));

	rc = __lfsck_layout_update_pfid(env, child,
					lu_object_fid(&parent->do_lu),
					&rec->lor_layout, ea_off,
					rec->lor_layout_version,
					rec->lor_range);
	lfsck_object_put(env, child);

	RETURN(rc == 0 ? 1 : rc);
}

static int lfsck_lovea_size(struct ost_layout *ol, __u32 ea_off)
{
	if (ol->ol_comp_id != 0)
		return sizeof(struct lov_comp_md_v1) +
		       sizeof(struct lov_comp_md_entry_v1) +
		       lov_mds_md_size(ol->ol_stripe_count, LOV_MAGIC_V1);

	if (ol->ol_stripe_count != 0)
		return lov_mds_md_size(ol->ol_stripe_count, LOV_MAGIC_V1);

	return lov_mds_md_size(ea_off + 1, LOV_MAGIC_V1);
}

/**
 * This function will create the MDT-object with the given (partial) LOV EA.
 *
 * Under some data corruption cases, the MDT-object of the file may be lost,
 * but its OST-objects, or some of them are there. The layout LFSCK needs to
 * re-create the MDT-object with the orphan OST-object(s) information.
 *
 * On the other hand, the LFSCK may has created some OST-object for repairing
 * dangling LOV EA reference, but as the LFSCK processing, it may find that
 * the old OST-object is there and should replace the former new created OST
 * object. Unfortunately, some others have modified such newly created object.
 * To keep the data (both new and old), the LFSCK will create MDT-object with
 * new FID to reference the original OST-object.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	pointer to the lfsck component
 * \param[in] ltd	pointer to target device descriptor
 * \param[in] rec	pointer to the record for the orphan OST-object
 * \param[in] cfid	pointer to FID for the orphan OST-object
 * \param[in] infix	additional information, such as the FID for original
 *			MDT-object and the stripe offset in the LOV EA
 * \param[in] type	the type for describing why the orphan MDT-object is
 *			created. The rules are as following:
 *
 *  type "C":		Multiple OST-objects claim the same MDT-object and the
 *			same slot in the layout EA. Then the LFSCK will create
 *			new MDT-object(s) to hold the conflict OST-object(s).
 *
 *  type "N":		The orphan OST-object does not know which one was the
 *			real parent MDT-object, so the LFSCK uses new FID for
 *			its parent MDT-object.
 *
 *  type "R":		The orphan OST-object knows its parent MDT-object FID,
 *			but does not know the position (the file name) in the
 *			layout.
 *
 *  type "D":		The MDT-object is a directory, it may knows its parent
 *			but because there is no valid linkEA, the LFSCK cannot
 *			know where to put it back to the namespace.
 *  type "O":		The MDT-object has no linkEA, and there is no name
 *			entry that references the MDT-object.
 *
 *  type "P":		The orphan object to be created was a parent directory
 *			of some MDT-object which linkEA shows that the @orphan
 *			object is missing.
 *
 * The orphan name will be like:
 * ${FID}-${infix}-${type}-${conflict_version}
 *
 * \param[in] ea_off	the stripe offset in the LOV EA
 *
 * \retval		positive on repaired something
 * \retval		0 if needs to repair nothing
 * \retval		negative error number on failure
 */
static int lfsck_layout_recreate_parent(const struct lu_env *env,
					struct lfsck_component *com,
					struct lfsck_tgt_desc *ltd,
					struct lu_orphan_rec_v3 *rec,
					struct lu_fid *cfid,
					const char *infix,
					const char *type,
					__u32 ea_off)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct dt_insert_rec		*dtrec	= &info->lti_dt_rec;
	char				*name	= info->lti_key;
	struct lu_attr			*la	= &info->lti_la2;
	struct dt_object_format 	*dof	= &info->lti_dof;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lu_fid			*pfid	= &rec->lor_rec.lor_fid;
	struct lu_fid			*tfid	= &info->lti_fid3;
	struct dt_device		*dev	= lfsck->li_bottom;
	struct dt_object		*lpf	= lfsck->li_lpf_obj;
	struct dt_object		*pobj	= NULL;
	struct dt_object		*cobj	= NULL;
	struct thandle			*th	= NULL;
	struct lu_buf			*ea_buf = &info->lti_big_buf;
	struct lu_buf			 lov_buf;
	struct lfsck_lock_handle	*llh	= &info->lti_llh;
	struct linkea_data		 ldata	= { NULL };
	struct lu_buf			 linkea_buf;
	const struct lu_name		*pname;
	int				 size	= 0;
	int				 idx	= 0;
	int				 rc	= 0;
	ENTRY;

	if (lfsck_is_dryrun(lfsck))
		GOTO(log, rc = 0);

	if (unlikely(lpf == NULL))
		GOTO(log, rc = -ENXIO);

	/* We use two separated transactions to repair the inconsistency.
	 *
	 * 1) create the MDT-object locally.
	 * 2) update the OST-object's PFID EA if necessary.
	 *
	 * If 1) succeed, but 2) failed, then the OST-object's PFID EA will be
	 * updated when the layout LFSCK run next time.
	 *
	 * If 1) failed, but 2) succeed, then such MDT-object will be re-created
	 * when the layout LFSCK run next time. */

	if (fid_is_zero(pfid)) {
		rc = lfsck_fid_alloc(env, lfsck, pfid, false);
		if (rc != 0)
			GOTO(log, rc);

		cobj = lfsck_object_find_by_dev(env, ltd->ltd_tgt, cfid);
		if (IS_ERR(cobj))
			GOTO(log, rc = PTR_ERR(cobj));
	}

	pobj = lfsck_object_find_by_dev(env, dev, pfid);
	if (IS_ERR(pobj))
		GOTO(log, rc = PTR_ERR(pobj));

	LASSERT(infix != NULL);
	LASSERT(type != NULL);

	memset(la, 0, sizeof(*la));
	la->la_uid = rec->lor_rec.lor_uid;
	la->la_gid = rec->lor_rec.lor_gid;
	la->la_mode = S_IFREG | S_IRUSR;
	la->la_valid = LA_MODE | LA_UID | LA_GID;

	memset(dof, 0, sizeof(*dof));
	dof->dof_type = dt_mode_to_dft(S_IFREG);
	/* Because the dof->dof_reg.striped = 0, the LOD will not create
	 * the stripe(s). The LFSCK will specify the LOV EA via
	 * lfsck_layout_update_lovea(). */

	size = lfsck_lovea_size(&rec->lor_layout, ea_off);
	if (ea_buf->lb_len < size) {
		lu_buf_realloc(ea_buf, size);
		if (ea_buf->lb_buf == NULL)
			GOTO(log, rc = -ENOMEM);
	}

again:
	do {
		snprintf(name, NAME_MAX, DFID"%s-%s-%d", PFID(pfid), infix,
			 type, idx++);
		rc = dt_lookup_dir(env, lfsck->li_lpf_obj, name, tfid);
		if (rc != 0 && rc != -ENOENT)
			GOTO(log, rc);
	} while (rc == 0);

	rc = lfsck_lock(env, lfsck, lfsck->li_lpf_obj, name, llh,
			MDS_INODELOCK_UPDATE, LCK_PW);
	if (rc != 0)
		GOTO(log, rc);

	/* Re-check whether the name conflict with othrs after taken
	 * the ldlm lock. */
	rc = dt_lookup_dir(env, lfsck->li_lpf_obj, name, tfid);
	if (unlikely(rc == 0)) {
		lfsck_unlock(llh);
		goto again;
	}

	if (rc != -ENOENT)
		GOTO(unlock, rc);

	pname = lfsck_name_get_const(env, name, strlen(name));
	rc = linkea_links_new(&ldata, &lfsck_env_info(env)->lti_linkea_buf,
			      pname, lfsck_dto2fid(lfsck->li_lpf_obj));
	if (rc != 0)
		GOTO(unlock, rc);

	/* The 1st transaction. */
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_create(env, pobj, la, NULL, dof, th);
	if (rc != 0)
		GOTO(stop, rc);

	lfsck_buf_init(&lov_buf, ea_buf->lb_buf, size);
	rc = dt_declare_xattr_set(env, pobj, &lov_buf, XATTR_NAME_LOV,
				  LU_XATTR_CREATE, th);
	if (rc != 0)
		GOTO(stop, rc);

	dtrec->rec_fid = pfid;
	dtrec->rec_type = S_IFREG;
	rc = dt_declare_insert(env, lpf,
			       (const struct dt_rec *)dtrec,
			       (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	lfsck_buf_init(&linkea_buf, ldata.ld_buf->lb_buf,
		       ldata.ld_leh->leh_len);
	rc = dt_declare_xattr_set(env, pobj, &linkea_buf,
				  XATTR_NAME_LINK, 0, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, pobj, 0);
	rc = dt_create(env, pobj, la, NULL, dof, th);
	if (rc == 0)
		rc = lfsck_layout_update_lovea(env, lfsck, th, rec, pobj, cfid,
			&lov_buf, LU_XATTR_CREATE, ltd->ltd_index, ea_off);
	dt_write_unlock(env, pobj);
	if (rc < 0)
		GOTO(stop, rc);

	rc = dt_insert(env, lpf, (const struct dt_rec *)dtrec,
		       (const struct dt_key *)name, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_xattr_set(env, pobj, &linkea_buf, XATTR_NAME_LINK, 0, th);
	if (rc == 0 && cobj != NULL) {
		dt_trans_stop(env, dev, th);
		th = NULL;

		/* The 2nd transaction. */
		rc = __lfsck_layout_update_pfid(env, cobj, pfid,
						&rec->lor_layout, ea_off,
						rec->lor_layout_version,
						rec->lor_range);
	}

	GOTO(stop, rc);

stop:
	if (th != NULL)
		dt_trans_stop(env, dev, th);

unlock:
	lfsck_unlock(llh);

log:
	if (cobj != NULL && !IS_ERR(cobj))
		lfsck_object_put(env, cobj);
	if (pobj != NULL && !IS_ERR(pobj))
		lfsck_object_put(env, pobj);

	if (rc < 0)
		CDEBUG(D_LFSCK, "%s layout LFSCK assistant failed to "
		       "recreate the lost MDT-object: parent "DFID
		       ", child "DFID", OST-index %u, stripe-index %u, "
		       "infix %s, type %s: rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(pfid), PFID(cfid),
		       ltd->ltd_index, ea_off, infix, type, rc);

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
		RETURN(-ENXIO);

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
	lr->lr_active = LFSCK_TYPE_LAYOUT;
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
	union ldlm_policy_data		*policy = &info->lti_policy;
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
	if (dt_object_exists(obj) == 0 ||
	    lfsck_is_dead_obj(obj)) {
		dt_read_unlock(env, obj);

		GOTO(put, rc = -ENOENT);
	}

	/* Get obj's attr without lock firstly. */
	rc = dt_attr_get(env, obj, la);
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
	rc = ldlm_cli_enqueue_local(env, lfsck->li_namespace, resid,
				    LDLM_EXTENT, policy, LCK_EX, &flags,
				    ldlm_blocking_ast, ldlm_completion_ast,
				    NULL, NULL, 0, LVB_T_NONE, NULL, &lh);
	if (rc != ELDLM_OK)
		GOTO(put, rc = -EIO);

	dt_write_lock(env, obj, 0);
	/* Get obj's attr within lock again. */
	rc = dt_attr_get(env, obj, la);
	if (rc != 0)
		GOTO(unlock, rc);

	if (la->la_ctime != 0)
		GOTO(unlock, rc = -ETXTBSY);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(unlock, rc = PTR_ERR(th));

	rc = dt_declare_ref_del(env, obj, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_destroy(env, obj, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_ref_del(env, obj, th);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_destroy(env, obj, th);
	if (rc == 0)
		CDEBUG(D_LFSCK, "%s: layout LFSCK destroyed the empty "
		       "OST-object "DFID" that was created for reparing "
		       "dangling referenced case. But the original missing "
		       "OST-object is found now.\n",
		       lfsck_lfsck2name(lfsck), PFID(fid));

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);

unlock:
	dt_write_unlock(env, obj);
	ldlm_lock_decref(&lh, LCK_EX);

put:
	lfsck_object_put(env, obj);

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
					struct lu_orphan_rec_v3 *rec,
					struct dt_object *parent,
					struct lu_fid *cfid,
					struct lu_buf *ea_buf,
					struct lov_mds_md_v1 *lmm,
					struct lov_ost_data_v1 *slot,
					__u32 ea_off, int lovea_size)
{
	struct lfsck_thread_info *info		= lfsck_env_info(env);
	struct lu_fid		 *cfid2		= &info->lti_fid2;
	struct ost_id		 *oi		= &info->lti_oi;
	struct dt_device	 *dev		= lfsck_obj2dev(parent);
	struct thandle		 *th		= NULL;
	struct lustre_handle	  lh		= { 0 };
	__u32			  ost_idx2	= le32_to_cpu(slot->l_ost_idx);
	int			  rc		= 0;
	ENTRY;

	while (CFS_FAIL_TIMEOUT(OBD_FAIL_LFSCK_DELAY3, cfs_fail_val)) {
		if (unlikely(!thread_is_running(&com->lc_lfsck->li_thread)))
			RETURN(0);
	}

	ostid_le_to_cpu(&slot->l_ost_oi, oi);
	rc = ostid_to_fid(cfid2, oi, ost_idx2);
	if (rc != 0)
		GOTO(out, rc);

	rc = lfsck_ibits_lock(env, com->lc_lfsck, parent, &lh,
			      MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR,
			      LCK_EX);
	if (rc != 0)
		GOTO(out, rc);

	rc = lfsck_layout_master_conditional_destroy(env, com, cfid2, ost_idx2);

	/* If the conflict OST-obejct is not created for fixing dangling
	 * referenced MDT-object in former LFSCK check/repair, or it has
	 * been modified by others, then we cannot destroy it. Re-create
	 * a new MDT-object for the orphan OST-object. */
	if (rc == -ETXTBSY) {
		/* No need the layout lock on the original parent. */
		lfsck_ibits_unlock(&lh, LCK_EX);

		fid_zero(&rec->lor_rec.lor_fid);
		snprintf(info->lti_tmpbuf, sizeof(info->lti_tmpbuf),
			 "-"DFID"-%x", PFID(lu_object_fid(&parent->do_lu)),
			 ea_off);
		rc = lfsck_layout_recreate_parent(env, com, ltd, rec, cfid,
						info->lti_tmpbuf, "C", ea_off);

		RETURN(rc);
	}

	if (rc != 0 && rc != -ENOENT)
		GOTO(unlock, rc);

	if (lfsck_is_dryrun(com->lc_lfsck))
		GOTO(unlock, rc = 0);

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
	rc = lfsck_layout_refill_lovea(env, com->lc_lfsck, th, parent, cfid,
				       ea_buf, lmm, slot, LU_XATTR_REPLACE,
				       ltd->ltd_index, lovea_size);
	dt_write_unlock(env, parent);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);

unlock:
	lfsck_ibits_unlock(&lh, LCK_EX);

out:
	CDEBUG(D_LFSCK, "%s: layout LFSCK assistant replaced the conflict "
	       "OST-object "DFID" on the OST %x with the orphan "DFID" on "
	       "the OST %x: parent "DFID", stripe-index %u: rc = %d\n",
	       lfsck_lfsck2name(com->lc_lfsck), PFID(cfid2), ost_idx2,
	       PFID(cfid), ltd->ltd_index, PFID(lfsck_dto2fid(parent)),
	       ea_off, rc);

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
				       struct lu_orphan_rec_v3 *rec,
				       struct dt_object *parent,
				       struct lu_fid *cfid,
				       __u32 ost_idx, __u32 ea_off)
{
	struct lfsck_thread_info *info		= lfsck_env_info(env);
	struct lu_buf		 *buf		= &info->lti_big_buf;
	struct lu_fid		 *fid		= &info->lti_fid2;
	struct ost_id		 *oi		= &info->lti_oi;
	struct lfsck_instance	 *lfsck 	= com->lc_lfsck;
	struct dt_device	 *dt		= lfsck_obj2dev(parent);
	struct lfsck_bookmark	 *bk		= &lfsck->li_bookmark_ram;
	struct ost_layout	 *ol		= &rec->lor_layout;
	struct lov_comp_md_v1	 *lcm		= NULL;
	struct lov_comp_md_entry_v1 *lcme	= NULL;
	struct thandle		 *handle	= NULL;
	size_t			  lovea_size;
	struct lov_mds_md_v1	 *lmm;
	struct lov_ost_data_v1   *objs;
	struct lustre_handle	  lh		= { 0 };
	__u32			  magic;
	__u32 flags = 0;
	int			  fl		= 0;
	int			  rc		= 0;
	int			  rc1;
	int			  i;
	int pos = 0;
	__u16 count;
	bool locked = false;
	bool new_mirror = true;
	ENTRY;

	if (lfsck_is_dryrun(lfsck))
		RETURN(0);

	rc = lfsck_ibits_lock(env, lfsck, parent, &lh,
			      MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR,
			      LCK_EX);
	if (rc != 0) {
		CDEBUG(D_LFSCK, "%s: layout LFSCK assistant failed to recreate "
		       "LOV EA for "DFID": parent "DFID", OST-index %u, "
		       "stripe-index %u, comp_id %u, comp_start %llu, "
		       "comp_end %llu, layout version %u, range %u: rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(cfid),
		       PFID(lfsck_dto2fid(parent)), ost_idx, ea_off,
		       ol->ol_comp_id, ol->ol_comp_start,
		       ol->ol_comp_end, rec->lor_layout_version,
		       rec->lor_range, rc);

		RETURN(rc);
	}

again:
	if (locked) {
		dt_write_unlock(env, parent);
		locked = false;
	}

	if (handle != NULL) {
		dt_trans_stop(env, dt, handle);
		handle = NULL;
	}

	if (rc < 0)
		GOTO(unlock_layout, rc);

	lovea_size = rc;
	if (buf->lb_len < lovea_size) {
		lu_buf_realloc(buf, lovea_size);
		if (buf->lb_buf == NULL)
			GOTO(unlock_layout, rc = -ENOMEM);
	}

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
	locked = true;
	rc = dt_xattr_get(env, parent, buf, XATTR_NAME_LOV);
	if (rc == -ERANGE) {
		rc = dt_xattr_get(env, parent, &LU_BUF_NULL, XATTR_NAME_LOV);
		LASSERT(rc != 0);
		goto again;
	} else if (rc == -ENODATA || rc == 0) {
		lovea_size = lfsck_lovea_size(ol, ea_off);
		/* If the declared is not big enough, re-try. */
		if (buf->lb_len < lovea_size) {
			rc = lovea_size;
			goto again;
		}
		fl = LU_XATTR_CREATE;
	} else if (rc < 0) {
		GOTO(unlock_parent, rc);
	} else if (unlikely(buf->lb_len == 0)) {
		goto again;
	} else {
		fl = LU_XATTR_REPLACE;
		lovea_size = rc;
	}

	if (fl == LU_XATTR_CREATE) {
		if (bk->lb_param & LPF_DRYRUN)
			GOTO(unlock_parent, rc = 1);

		LASSERT(buf->lb_len >= lovea_size);

		rc = lfsck_layout_update_lovea(env, lfsck, handle, rec, parent,
					       cfid, buf, fl, ost_idx, ea_off);

		GOTO(unlock_parent, rc);
	}

	lmm = buf->lb_buf;
	rc1 = lfsck_layout_verify_header(parent, lmm, lovea_size);

	/* If the LOV EA crashed, the rebuild it. */
	if (rc1 == -EINVAL) {
		if (bk->lb_param & LPF_DRYRUN)
			GOTO(unlock_parent, rc = 1);

		LASSERT(buf->lb_len >= lovea_size);

		rc = lfsck_layout_update_lovea(env, lfsck, handle, rec, parent,
					       cfid, buf, fl, ost_idx, ea_off);

		GOTO(unlock_parent, rc);
	}

	/* For other unknown magic/pattern, keep the current LOV EA. */
	if (rc1 == -EOPNOTSUPP)
		GOTO(unlock_parent, rc1 = 0);

	if (rc1)
		GOTO(unlock_parent, rc = rc1);

	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
		__u64 start;
		__u64 end;
		__u16 mirror_id0 = mirror_id_of(ol->ol_comp_id);
		__u16 mirror_id1;

		if (bk->lb_param & LPF_DRYRUN)
			GOTO(unlock_parent, rc = 1);

		lcm = buf->lb_buf;
		count = le16_to_cpu(lcm->lcm_entry_count);
		for (i = 0; i < count; pos = ++i) {
			lcme = &lcm->lcm_entries[i];
			start = le64_to_cpu(lcme->lcme_extent.e_start);
			end = le64_to_cpu(lcme->lcme_extent.e_end);
			mirror_id1 = mirror_id_of(le32_to_cpu(lcme->lcme_id));

			if (mirror_id0 > mirror_id1)
				continue;

			if (mirror_id0 < mirror_id1)
				break;

			new_mirror = false;
			if (end <= ol->ol_comp_start)
				continue;

			if (start >= ol->ol_comp_end)
				break;

			lmm = buf->lb_buf + le32_to_cpu(lcme->lcme_offset);
			magic = le32_to_cpu(lmm->lmm_magic);
			flags = le32_to_cpu(lcme->lcme_flags);
			goto further;
		}

		rc = lfsck_layout_add_comp(env, lfsck, handle, rec, parent,
				cfid, buf, ost_idx, ea_off, pos, new_mirror);

		GOTO(unlock_parent, rc);
	}

further:
	count = le16_to_cpu(lmm->lmm_stripe_count);
	if (count == 0)
		GOTO(unlock_parent, rc = -EINVAL);
	LASSERT(count > 0);

	/* Exceed the current end of MDT-object layout EA. Then extend it. */
	if (count <= ea_off) {
		if (bk->lb_param & LPF_DRYRUN)
			GOTO(unlock_parent, rc = 1);

		lovea_size = lov_mds_md_size(ea_off + 1, magic);
		/* If the declared is not big enough, re-try. */
		if (buf->lb_len < lovea_size) {
			rc = lovea_size;
			goto again;
		}

		if (lcm) {
			LASSERT(lcme);

			lcme->lcme_flags = cpu_to_le32(flags | LCME_FL_INIT);
			lfsck_layout_update_lcm(lcm, lcme,
						rec->lor_layout_version,
						rec->lor_range);
		}

		rc = lfsck_layout_extend_v1v3_lovea(env, lfsck, handle, ol,
					parent, cfid, buf, ost_idx, ea_off);

		GOTO(unlock_parent, rc);
	}

	LASSERTF(rc > 0, "invalid rc = %d\n", rc);

	if (magic == LOV_MAGIC_V1) {
		objs = &lmm->lmm_objects[0];
	} else {
		LASSERT(magic == LOV_MAGIC_V3);
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
	}

	for (i = 0; i < count; i++, objs++) {
		/* The MDT-object was created via lfsck_layout_recover_create()
		 * by others before, and we fill the dummy layout EA. */
		if ((lcme && !(flags & LCME_FL_INIT)) ||
		     lovea_slot_is_dummy(objs)) {
			if (i != ea_off)
				continue;

			if (bk->lb_param & LPF_DRYRUN)
				GOTO(unlock_parent, rc = 1);

			lmm->lmm_layout_gen =
			    cpu_to_le16(le16_to_cpu(lmm->lmm_layout_gen) + 1);
			if (lcme) {
				LASSERT(lcm);

				if (le32_to_cpu(lmm->lmm_stripe_size) !=
					ol->ol_stripe_size ||
				    le16_to_cpu(lmm->lmm_stripe_count) !=
					ol->ol_stripe_count ||
				    le64_to_cpu(lcme->lcme_extent.e_start) !=
					ol->ol_comp_start ||
				    le64_to_cpu(lcme->lcme_extent.e_end) !=
					ol->ol_comp_end) {
					CDEBUG(D_LFSCK, "%s: found invalid "
					"component for "DFID ": parent "DFID
					", stripe-index %u, stripe_size %u, "
					"stripe_count %u, comp_id %u, "
					"comp_start %llu, comp_end %llu, "
					"cur_stripe_size %u, "
					"cur_stripe_count %u, "
					"cur_comp_start %llu, "
					"cur_comp_end %llu\n",
					lfsck_lfsck2name(lfsck), PFID(cfid),
					PFID(lfsck_dto2fid(parent)), ea_off,
					ol->ol_stripe_size,
					ol->ol_stripe_count, ol->ol_comp_id,
					ol->ol_comp_start, ol->ol_comp_end,
					le32_to_cpu(lmm->lmm_stripe_size),
					le16_to_cpu(lmm->lmm_stripe_count),
					le64_to_cpu(lcme->lcme_extent.e_start),
					le64_to_cpu(lcme->lcme_extent.e_end));

					GOTO(unlock_parent, rc = -EINVAL);
				}

				lovea_size = le32_to_cpu(lcm->lcm_size);
				lcme->lcme_flags = cpu_to_le32(flags |
							       LCME_FL_INIT);
				lfsck_layout_update_lcm(lcm, lcme,
							rec->lor_layout_version,
							rec->lor_range);
			}

			LASSERTF(buf->lb_len >= lovea_size,
				 "buffer len %d is less than real size %d\n",
				 (int)buf->lb_len, (int)lovea_size);

			rc = lfsck_layout_refill_lovea(env, lfsck, handle,
						parent, cfid, buf, lmm, objs,
						fl, ost_idx, lovea_size);

			CDEBUG(D_LFSCK, "%s layout LFSCK assistant fill "
			       "dummy layout slot for "DFID": parent "DFID
			       ", OST-index %u, stripe-index %u: rc = %d\n",
			       lfsck_lfsck2name(lfsck), PFID(cfid),
			       PFID(lfsck_dto2fid(parent)), ost_idx, i, rc);

			GOTO(unlock_parent, rc);
		}

		ostid_le_to_cpu(&objs->l_ost_oi, oi);
		rc = ostid_to_fid(fid, oi, le32_to_cpu(objs->l_ost_idx));
		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: the parent "DFID" contains "
			       "invalid layout EA at the slot %d, index %u\n",
			       lfsck_lfsck2name(lfsck),
			       PFID(lfsck_dto2fid(parent)), i,
			       le32_to_cpu(objs->l_ost_idx));

			GOTO(unlock_parent, rc);
		}

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
				lfsck_ibits_unlock(&lh, LCK_EX);
				rc = lfsck_layout_update_pfid(env, com, parent,
							cfid, ltd->ltd_tgt,
							rec, i);

				CDEBUG(D_LFSCK, "%s layout LFSCK assistant "
				       "updated OST-object's pfid for "DFID
				       ": parent "DFID", OST-index %u, "
				       "stripe-index %u: rc = %d\n",
				       lfsck_lfsck2name(lfsck), PFID(cfid),
				       PFID(lfsck_dto2fid(parent)),
				       ltd->ltd_index, i, rc);

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
	lfsck_ibits_unlock(&lh, LCK_EX);
	if (magic == LOV_MAGIC_V1)
		objs = &lmm->lmm_objects[ea_off];
	else
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[ea_off];
	rc = lfsck_layout_conflict_create(env, com, ltd, rec, parent, cfid,
					  buf, lmm, objs, ea_off, lovea_size);

	RETURN(rc);

unlock_parent:
	if (locked)
		dt_write_unlock(env, parent);

stop:
	if (handle != NULL)
		dt_trans_stop(env, dt, handle);

unlock_layout:
	lfsck_ibits_unlock(&lh, LCK_EX);

	return rc;
}

static int lfsck_layout_scan_orphan_one(const struct lu_env *env,
					struct lfsck_component *com,
					struct lfsck_tgt_desc *ltd,
					struct lu_orphan_rec_v3 *rec,
					struct lu_fid *cfid)
{
	struct lfsck_layout	*lo	= com->lc_file_ram;
	struct lu_fid		*pfid	= &rec->lor_rec.lor_fid;
	struct dt_object	*parent = NULL;
	__u32			 ea_off = pfid->f_stripe_idx;
	int			 rc	= 0;
	ENTRY;

	if (!fid_is_sane(cfid))
		GOTO(out, rc = -EINVAL);

	pfid->f_ver = 0;
	if (fid_is_zero(pfid)) {
		rc = lfsck_layout_recreate_parent(env, com, ltd, rec, cfid,
						  "", "N", ea_off);
		GOTO(out, rc);
	}

	if (!fid_is_sane(pfid))
		GOTO(out, rc = -EINVAL);

	parent = lfsck_object_find_by_dev(env, com->lc_lfsck->li_bottom, pfid);
	if (IS_ERR(parent))
		GOTO(out, rc = PTR_ERR(parent));

	if (unlikely(dt_object_remote(parent) != 0))
		GOTO(put, rc = -EXDEV);

	if (dt_object_exists(parent) == 0) {
		lfsck_object_put(env, parent);
		rc = lfsck_layout_recreate_parent(env, com, ltd, rec, cfid,
						  "", "R", ea_off);
		GOTO(out, rc);
	}

	if (!S_ISREG(lu_object_attr(&parent->do_lu)))
		GOTO(put, rc = -EISDIR);

	/* The orphan OST-object claims to be the parent's stripe, then
	 * related dangling record in the trace file is meaningless. */
	rc = lfsck_layout_del_dangling_rec(env, com, pfid,
					   rec->lor_layout.ol_comp_id, ea_off);
	if (rc && rc != -ENOENT)
		GOTO(put, rc);

	rc = lfsck_layout_recreate_lovea(env, com, ltd, rec, parent, cfid,
					 ltd->ltd_index, ea_off);

	GOTO(put, rc);

put:
	if (rc <= 0)
		lfsck_object_put(env, parent);
	else
		/* The layout EA is changed, need to be reloaded next time. */
		dt_object_put_nocache(env, parent);

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
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_bookmark		*bk	= &lfsck->li_bookmark_ram;
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_fid			*fid	= &info->lti_fid;
	struct dt_object		*obj;
	const struct dt_it_ops		*iops;
	struct dt_it			*di;
	int				 rc	= 0;
	ENTRY;

	CDEBUG(D_LFSCK, "%s: layout LFSCK assistant starts the orphan "
	       "scanning for OST%04x\n",
	       lfsck_lfsck2name(lfsck), ltd->ltd_index);

	if (cfs_bitmap_check(lad->lad_bitmap, ltd->ltd_index)) {
		CDEBUG(D_LFSCK, "%s: layout LFSCK assistant skip the orphan "
		       "scanning for OST%04x\n",
		       lfsck_lfsck2name(lfsck), ltd->ltd_index);

		RETURN(0);
	}

	fid->f_seq = fid_idif_seq(0, ltd->ltd_index);
	fid->f_oid = fid->f_ver = 0;

	obj = lfsck_object_find_by_dev(env, ltd->ltd_tgt, fid);
	if (unlikely(IS_ERR(obj)))
		GOTO(log, rc = PTR_ERR(obj));

	rc = obj->do_ops->do_index_try(env, obj,
				       &dt_lfsck_layout_orphan_features);
	if (rc != 0)
		GOTO(put, rc);

	iops = &obj->do_index_ops->dio_it;
	di = iops->init(env, obj, 0);
	if (IS_ERR(di))
		GOTO(put, rc = PTR_ERR(di));

	rc = iops->load(env, di, 0);
	if (rc == -ESRCH) {
		/* -ESRCH means that the orphan OST-objects rbtree has been
		 * cleanup because of the OSS server restart or other errors. */
		lfsck_lad_set_bitmap(env, com, ltd->ltd_index);
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
		struct lu_orphan_rec_v3	*rec = &info->lti_rec;

		if (CFS_FAIL_TIMEOUT(OBD_FAIL_LFSCK_DELAY3, cfs_fail_val) &&
		    unlikely(!thread_is_running(&lfsck->li_thread)))
			break;

		key = iops->key(env, di);
		com->lc_fid_latest_scanned_phase2 = *(struct lu_fid *)key;
		/* Remote target OST may be runnning old LFSCK */
		memset(rec, 0, sizeof(*rec));
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
	lfsck_object_put(env, obj);

log:
	CDEBUG(D_LFSCK, "%s: layout LFSCK assistant finished the orphan "
	       "scanning for OST%04x: rc = %d\n",
	       lfsck_lfsck2name(lfsck), ltd->ltd_index, rc);

	return rc > 0 ? 0 : rc;
}

static int lfsck_lov2layout(struct lov_mds_md_v1 *lmm, struct filter_fid *ff,
			    __u32 comp_id)
{
	struct ost_layout *ol = &ff->ff_layout;
	__u32 magic = le32_to_cpu(lmm->lmm_magic);
	int rc = 0;
	ENTRY;

	if (magic == LOV_MAGIC_V1 || magic == LOV_MAGIC_V3) {
		ol->ol_stripe_size = lmm->lmm_stripe_size;
		ol->ol_stripe_count = lmm->lmm_stripe_count;
		ol->ol_comp_start = 0;
		ol->ol_comp_end = 0;
		ol->ol_comp_id = 0;
		ff->ff_layout_version = 0;
		ff->ff_range = 0;
	} else if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
		struct lov_comp_md_v1 *lcm = (struct lov_comp_md_v1 *)lmm;
		struct lov_comp_md_entry_v1 *lcme = NULL;
		__u16 count = le16_to_cpu(lcm->lcm_entry_count);
		int i;

		for (i = 0; i < count; i++) {
			lcme = &lcm->lcm_entries[i];
			if (le32_to_cpu(lcme->lcme_id) == comp_id) {
				LASSERT(le32_to_cpu(lcme->lcme_flags) &
					LCME_FL_INIT);

				break;
			}
		}

		/* The comp has been removed, do nothing. */
		if (i == count)
			GOTO(out, rc = 1);

		lmm = (void *)lmm + le32_to_cpu(lcme->lcme_offset);
		ol->ol_stripe_size = le32_to_cpu(lmm->lmm_stripe_size);
		ol->ol_stripe_count = le32_to_cpu(lmm->lmm_stripe_count);
		ol->ol_comp_start = le64_to_cpu(lcme->lcme_extent.e_start);
		ol->ol_comp_end = le64_to_cpu(lcme->lcme_extent.e_end);
		ol->ol_comp_id = le32_to_cpu(lcme->lcme_id);
		ff->ff_layout_version = le32_to_cpu(lcme->lcme_layout_gen);
		ff->ff_range = 0;
	} else {
		GOTO(out, rc = -EINVAL);
	}

	EXIT;

out:
	return rc;
}

/**
 * Repair the MDT-object with dangling LOV EA reference.
 *
 * we need to repair the inconsistency according to the users' requirement:
 *
 * 1) Keep the inconsistency there and report the inconsistency case,
 *    then give the chance to the application to find related issues,
 *    and the users can make the decision about how to handle it with
 *    more human knownledge. (by default)
 *
 * 2) Re-create the missing OST-object with the FID/owner information.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	the layout LFSCK component
 * \param[in] parent	the MDT-object with dangling LOV EA reference
 * \param[in] child	the OST-object to be created
 * \param[in] comp_id	the component ID of the OST-object in the LOV EA
 * \param[in] ea_off	the offset of the OST-object in the LOV EA
 * \param[in] ost_idx	the index of OST on which the OST-object resides
 *
 * \retval		+1 for repair successfully
 * \retval		0 for did nothing
 * \retval		negative error number on failure
 */
static int __lfsck_layout_repair_dangling(const struct lu_env *env,
					  struct lfsck_component *com,
					  struct dt_object *parent,
					  struct dt_object *child,
					  __u32 comp_id, __u32 ea_off,
					  __u32 ost_idx, bool log)
{
	struct lfsck_thread_info *info = lfsck_env_info(env);
	struct filter_fid *ff = &info->lti_ff;
	struct dt_object_format *dof = &info->lti_dof;
	struct lu_attr *la = &info->lti_la;
	struct lfsck_instance *lfsck = com->lc_lfsck;
	struct dt_device *dev = lfsck_obj2dev(child);
	const struct lu_fid *pfid = lfsck_dto2fid(parent);
	const struct lu_fid *cfid = lfsck_dto2fid(child);
	struct lu_buf *tbuf = &info->lti_big_buf;
	struct thandle *handle;
	struct lu_buf *buf;
	struct lustre_handle lh = { 0 };
	int rc;
	ENTRY;

	if (!(lfsck->li_bookmark_ram.lb_param & LPF_CREATE_OSTOBJ))
		GOTO(log, rc = 1);

	rc = lfsck_ibits_lock(env, lfsck, parent, &lh,
			      MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR,
			      LCK_EX);
	if (rc != 0)
		GOTO(log, rc);

	rc = dt_attr_get(env, parent, la);
	if (rc != 0)
		GOTO(unlock1, rc);

	la->la_mode = S_IFREG | 0666;
	la->la_atime = la->la_mtime = la->la_ctime = 0;
	la->la_valid = LA_TYPE | LA_MODE | LA_UID | LA_GID |
		       LA_ATIME | LA_MTIME | LA_CTIME;
	memset(dof, 0, sizeof(*dof));
	ff->ff_parent.f_seq = cpu_to_le64(pfid->f_seq);
	ff->ff_parent.f_oid = cpu_to_le32(pfid->f_oid);
	/* Currently, the filter_fid::ff_parent::f_ver is not the real parent
	 * MDT-object's FID::f_ver, instead it is the OST-object index in its
	 * parent MDT-object's layout EA. */
	ff->ff_parent.f_stripe_idx = cpu_to_le32(ea_off);

	rc = lfsck_layout_get_lovea(env, parent, tbuf);
	if (unlikely(rc == -ENODATA))
		rc = 0;
	if (rc <= 0)
		GOTO(unlock1, rc);

	rc = lfsck_lov2layout(tbuf->lb_buf, ff, comp_id);
	if (rc)
		GOTO(unlock1, rc);

	buf = lfsck_buf_get(env, ff, sizeof(struct filter_fid));
	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		GOTO(unlock1, rc = PTR_ERR(handle));

	rc = dt_declare_create(env, child, la, NULL, dof, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_declare_xattr_set(env, child, buf, XATTR_NAME_FID,
				  LU_XATTR_CREATE, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	dt_read_lock(env, parent, 0);
	if (unlikely(lfsck_is_dead_obj(parent)))
		GOTO(unlock2, rc = 0);

	if (lfsck->li_bookmark_ram.lb_param & LPF_DELAY_CREATE_OSTOBJ) {
		struct ost_id *oi = &info->lti_oi;
		struct lu_fid *tfid = &info->lti_fid2;
		struct lu_buf *lovea = &info->lti_big_buf;
		struct lov_mds_md_v1 *lmm;
		struct lov_ost_data_v1 *objs;
		__u32 magic;
		int count;
		int idx2;

		rc = lfsck_layout_get_lovea(env, parent, lovea);
		if (unlikely(rc == -ENODATA))
			rc = 0;
		if (rc <= 0)
			GOTO(unlock2, rc);

		lmm = lovea->lb_buf;
		magic = le32_to_cpu(lmm->lmm_magic);
		if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
			struct lov_comp_md_v1 *lcm = buf->lb_buf;
			struct lov_comp_md_entry_v1 *lcme;
			__u16 count = le16_to_cpu(lcm->lcm_entry_count);
			int i;

			for (i = 0; i < count; i++) {
				lcme = &lcm->lcm_entries[i];
				if (le32_to_cpu(lcme->lcme_id) == comp_id) {
					LASSERT(le32_to_cpu(lcme->lcme_flags) &
						LCME_FL_INIT);

					lmm = lovea->lb_buf +
						le32_to_cpu(lcme->lcme_offset);
					magic = le32_to_cpu(lmm->lmm_magic);
					goto check;
				}
			}

			/* Someone removed the component, do nothing. */
			GOTO(unlock2, rc = 0);
		}

check:
		count = le16_to_cpu(lmm->lmm_stripe_count);
		/* Someone changed the LOV EA, do nothing. */
		if (count <= ea_off)
			GOTO(unlock2, rc = 0);

		if (magic == LOV_MAGIC_V1) {
			objs = &lmm->lmm_objects[ea_off];
		} else {
			LASSERT(magic == LOV_MAGIC_V3);

			objs = &((struct lov_mds_md_v3 *)lmm)->\
							lmm_objects[ea_off];
		}

		ostid_le_to_cpu(&objs->l_ost_oi, oi);
		idx2 = le32_to_cpu(objs->l_ost_idx);
		rc = ostid_to_fid(tfid, oi, idx2);
		/* Someone changed the LOV EA, do nothing. */
		if (rc != 0 || !lu_fid_eq(tfid, cfid))
			GOTO(unlock2, rc);
	}

	rc = dt_create(env, child, la, NULL, dof, handle);
	if (rc != 0)
		GOTO(unlock2, rc);

	rc = dt_xattr_set(env, child, buf, XATTR_NAME_FID, LU_XATTR_CREATE,
			  handle);

	GOTO(unlock2, rc);

unlock2:
	dt_read_unlock(env, parent);

stop:
	rc = lfsck_layout_trans_stop(env, dev, handle, rc);

unlock1:
	lfsck_ibits_unlock(&lh, LCK_EX);

log:
	if (rc && log)
		CDEBUG(D_LFSCK, "%s: layout LFSCK assistant found "
		       "dangling reference for: parent "DFID", child "
		       DFID", comp_id %u, ea_off %u, ost_idx %u, %s: "
		       "rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(pfid), PFID(cfid),
		       comp_id, ea_off, ost_idx,
		       (lfsck->li_bookmark_ram.lb_param & LPF_CREATE_OSTOBJ) ?
				"Create the lost OST-object as required" :
				"Keep the MDT-object there by default", rc);

	return rc;
}

/**
 * Repair the MDT-object with dangling LOV EA reference.
 *
 * Prepare parameters and call __lfsck_layout_repair_dangling()
 * to repair the dangling LOV EA reference.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] com	the layout LFSCK component
 * \param[in] pfid	the MDT-object's FID
 * \param[in] cfid	the FID for the OST-object to be created
 * \param[in] comp_id	the component ID of the OST-object in the LOV EA
 * \param[in] ea_off	the offset of the OST-object in the LOV EA
 * \param[in] ost_idx	the index of OST on which the OST-object resides
 *
 * \retval		+1 for repair successfully
 * \retval		0 for did nothing
 * \retval		negative error number on failure
 */
static int lfsck_layout_repair_dangling(const struct lu_env *env,
					struct lfsck_component *com,
					const struct lu_fid *pfid,
					const struct lu_fid *cfid,
					__u32 comp_id, __u32 ea_off,
					__u32 ost_idx)
{
	struct lfsck_instance *lfsck = com->lc_lfsck;
	struct dt_object *parent = NULL;
	struct dt_object *child = NULL;
	struct lfsck_tgt_desc *ltd;
	int rc;
	ENTRY;

	parent = lfsck_object_find_bottom(env, lfsck, pfid);
	if (IS_ERR(parent))
		GOTO(log, rc = PTR_ERR(parent));

	/* The MDT-object has been removed. */
	if (dt_object_exists(parent) == 0)
		GOTO(log, rc = 0);

	ltd = lfsck_ltd2tgt(&lfsck->li_ost_descs, ost_idx);
	if (unlikely(ltd == NULL))
		GOTO(log, rc = -ENODEV);

	child = lfsck_object_find_by_dev(env, ltd->ltd_tgt, cfid);
	if (IS_ERR(child))
		GOTO(log, rc = PTR_ERR(child));

	/* The OST-object has been created. */
	if (unlikely(dt_object_exists(child) != 0))
		GOTO(log, rc = 0);

	rc = __lfsck_layout_repair_dangling(env, com, parent, child,
					    comp_id, ea_off, ost_idx, false);

	GOTO(log, rc);

log:
	if (child != NULL && !IS_ERR(child))
		lfsck_object_put(env, child);

	if (parent != NULL && !IS_ERR(parent))
		lfsck_object_put(env, parent);

	if (rc)
		CDEBUG(D_LFSCK, "%s: layout LFSCK assistant found "
		       "dangling reference for: parent "DFID", child "
		       DFID", comp_id %u, ea_off %u, ost_idx %u, %s: rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(pfid), PFID(cfid),
		       comp_id, ea_off, ost_idx,
		       (lfsck->li_bookmark_ram.lb_param & LPF_CREATE_OSTOBJ) ?
				"Create the lost OST-object as required" :
				"Keep the MDT-object there by default", rc);

	return rc;
}

/* If the OST-object does not recognize the MDT-object as its parent, and
 * there is no other MDT-object claims as its parent, then just trust the
 * given MDT-object as its parent. So update the OST-object filter_fid. */
static int lfsck_layout_repair_unmatched_pair(const struct lu_env *env,
					      struct lfsck_component *com,
					      struct dt_object *parent,
					      struct lfsck_layout_req *llr,
					      struct lu_attr *la)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct filter_fid		*ff	= &info->lti_ff;
	struct dt_object		*child  = llr->llr_child;
	struct dt_device		*dev	= lfsck_obj2dev(child);
	const struct lu_fid		*tfid	= lu_object_fid(&parent->do_lu);
	struct lu_buf			*tbuf	= &info->lti_big_buf;
	struct thandle			*handle;
	struct lu_buf			*buf;
	struct lustre_handle		 lh	= { 0 };
	int				 rc;
	ENTRY;

	rc = lfsck_ibits_lock(env, com->lc_lfsck, parent, &lh,
			      MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR,
			      LCK_EX);
	if (rc != 0)
		GOTO(log, rc);

	ff->ff_parent.f_seq = cpu_to_le64(tfid->f_seq);
	ff->ff_parent.f_oid = cpu_to_le32(tfid->f_oid);
	/* Currently, the filter_fid::ff_parent::f_ver is not the real parent
	 * MDT-object's FID::f_ver, instead it is the OST-object index in its
	 * parent MDT-object's layout EA. */
	ff->ff_parent.f_stripe_idx = cpu_to_le32(llr->llr_lov_idx);

	rc = lfsck_layout_get_lovea(env, parent, tbuf);
	if (unlikely(rc == -ENODATA))
		rc = 0;
	if (rc <= 0)
		GOTO(unlock1, rc);

	rc = lfsck_lov2layout(tbuf->lb_buf, ff, llr->llr_comp_id);
	if (rc)
		GOTO(unlock1, rc);

	buf = lfsck_buf_get(env, ff, sizeof(*ff));

	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		GOTO(unlock1, rc = PTR_ERR(handle));

	rc = dt_declare_xattr_set(env, child, buf, XATTR_NAME_FID, 0, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_attr_get(env, parent, la);
	if (rc != 0)
		GOTO(stop, rc);

	la->la_valid = LA_UID | LA_GID;
	rc = dt_declare_attr_set(env, child, la, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, parent, 0);
	if (unlikely(lfsck_is_dead_obj(parent)))
		GOTO(unlock2, rc = 1);

	rc = dt_xattr_set(env, child, buf, XATTR_NAME_FID, 0, handle);
	if (rc != 0)
		GOTO(unlock2, rc);

	/* Get the latest parent's owner. */
	rc = dt_attr_get(env, parent, la);
	if (rc != 0)
		GOTO(unlock2, rc);

	la->la_valid = LA_UID | LA_GID;
	rc = dt_attr_set(env, child, la, handle);

	GOTO(unlock2, rc);

unlock2:
	dt_write_unlock(env, parent);

stop:
	rc = lfsck_layout_trans_stop(env, dev, handle, rc);

unlock1:
	lfsck_ibits_unlock(&lh, LCK_EX);

log:
	if (rc)
		CDEBUG(D_LFSCK, "%s: layout LFSCK assistant repaired "
		       "unmatched MDT-OST pair for: parent "DFID
		       ", child "DFID", comp_id %u, OST-index %u, "
		       "stripe-index %u, owner %u/%u: rc = %d\n",
		       lfsck_lfsck2name(com->lc_lfsck),
		       PFID(lfsck_dto2fid(parent)),
		       PFID(lfsck_dto2fid(child)),
		       llr->llr_comp_id, llr->llr_ost_idx, llr->llr_lov_idx,
		       la->la_uid, la->la_gid, rc);

	return rc;
}

/* If there are more than one MDT-objects claim as the OST-object's parent,
 * and the OST-object only recognizes one of them, then we need to generate
 * new OST-object(s) with new fid(s) for the non-recognized MDT-object(s). */
static int lfsck_layout_repair_multiple_references(const struct lu_env *env,
						   struct lfsck_component *com,
						   struct dt_object *parent,
						   struct lfsck_layout_req *llr,
						   struct lu_attr *la)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct dt_allocation_hint	*hint	= &info->lti_hint;
	struct dt_object_format 	*dof	= &info->lti_dof;
	struct ost_id			*oi	= &info->lti_oi;
	struct lu_buf			*buf	= &info->lti_big_buf;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct dt_device		*dev;
	struct lu_device		*d	=
				&lfsck_obj2dev(llr->llr_child)->dd_lu_dev;
	struct lu_object		*o;
	struct lu_object		*n;
	struct dt_object		*child	= NULL;
	struct thandle			*handle = NULL;
	struct lov_mds_md_v1		*lmm;
	struct lov_ost_data_v1		*objs;
	const struct lu_fid		*pfid	= lfsck_dto2fid(parent);
	struct lu_fid			 tfid;
	struct lustre_handle		 lh	= { 0 };
	__u32				 magic;
	__u32				 index;
	int				 rc;
	ENTRY;

	/* We use two separated transactions to repair the inconsistency.
	 *
	 * 1) create the child (OST-object).
	 * 2) update the parent LOV EA according to the child's FID.
	 *
	 * If 1) succeed, but 2) failed or aborted, then such OST-object will be
	 * handled as orphan when the layout LFSCK run next time.
	 *
	 * If 1) failed, but 2) succeed, then such OST-object will be re-created
	 * as dangling referened case when the layout LFSCK run next time. */

	/* The 1st transaction. */
	o = lu_object_anon(env, d, NULL);
	if (IS_ERR(o))
		GOTO(log, rc = PTR_ERR(o));

	n = lu_object_locate(o->lo_header, d->ld_type);
	if (unlikely(n == NULL)) {
		lu_object_put_nocache(env, o);

		GOTO(log, rc = -EINVAL);
	}

	child = container_of(n, struct dt_object, do_lu);
	memset(hint, 0, sizeof(*hint));
	rc = dt_attr_get(env, parent, la);
	if (rc != 0)
		GOTO(log, rc);

	la->la_valid = LA_UID | LA_GID;
	memset(dof, 0, sizeof(*dof));

	dev = lfsck_obj2dev(child);
	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		GOTO(log, rc = PTR_ERR(handle));

	rc = dt_declare_create(env, child, la, hint, dof, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_create(env, child, la, hint, dof, handle);
	dt_trans_stop(env, dev, handle);
	handle = NULL;
	if (rc != 0)
		GOTO(log, rc);

	rc = lfsck_ibits_lock(env, lfsck, parent, &lh,
			      MDS_INODELOCK_LAYOUT | MDS_INODELOCK_XATTR,
			      LCK_EX);
	if (rc != 0)
		GOTO(log, rc);

	/* The 2nd transaction. */

	/* XXX: Generally, we should use bottom device (OSD) to update parent
	 *	LOV EA. But because the LOD-object still references the wrong
	 *	OSP-object that should be detached after the parent's LOV EA
	 *	refreshed. Unfortunately, there is no suitable API for that.
	 *	So we have to make the LOD to re-load the OSP-object(s) via
	 *	replacing the LOV EA against the LOD-object.
	 *
	 *	Once the DNE2 patches have been landed, we can replace the
	 *	LOD device with the OSD device. LU-6230. */

	dev = lfsck->li_next;
	parent = lfsck_object_locate(dev, parent);
	if (IS_ERR(parent))
		GOTO(log, rc = PTR_ERR(parent));

	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		GOTO(log, rc = PTR_ERR(handle));

	rc = dt_declare_xattr_set(env, parent, buf, XATTR_NAME_LOV,
				  LU_XATTR_REPLACE, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	dt_write_lock(env, parent, 0);
	if (unlikely(lfsck_is_dead_obj(parent)))
		GOTO(unlock, rc = 0);

	rc = lfsck_layout_get_lovea(env, parent, buf);
	if (unlikely(rc == -ENODATA))
		rc = 0;
	if (rc <= 0)
		GOTO(unlock, rc);

	lmm = buf->lb_buf;
	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
		struct lov_comp_md_v1 *lcm = buf->lb_buf;
		struct lov_comp_md_entry_v1 *lcme;
		__u16 count = le16_to_cpu(lcm->lcm_entry_count);
		int i;

		LASSERT(llr->llr_comp_id != 0);

		for (i = 0; i < count; i++) {
			lcme = &lcm->lcm_entries[i];
			if (le32_to_cpu(lcme->lcme_id) == llr->llr_comp_id) {
				LASSERT(le32_to_cpu(lcme->lcme_flags) &
					LCME_FL_INIT);

				le32_add_cpu(&lcm->lcm_layout_gen, 1);
				lmm = buf->lb_buf +
					le32_to_cpu(lcme->lcme_offset);
				magic = le32_to_cpu(lmm->lmm_magic);
				goto set;
			}
		}

		GOTO(unlock, rc = 0);
	}

set:
	if (magic == LOV_MAGIC_V1) {
		objs = &lmm->lmm_objects[llr->llr_lov_idx];
	} else {
		LASSERT(magic == LOV_MAGIC_V3);
		objs =
		&((struct lov_mds_md_v3 *)lmm)->lmm_objects[llr->llr_lov_idx];
	}

	ostid_le_to_cpu(&objs->l_ost_oi, oi);
	index = le32_to_cpu(objs->l_ost_idx);
	rc = ostid_to_fid(&tfid, oi, index);
	/* Someone changed layout during the LFSCK, no need to repair then. */
	if (rc == 0 && !lu_fid_eq(&tfid, lu_object_fid(&llr->llr_child->do_lu)))
		GOTO(unlock, rc = 0);

	lmm->lmm_layout_gen = cpu_to_le16(le16_to_cpu(lmm->lmm_layout_gen) + 1);
	fid_to_ostid(lu_object_fid(&child->do_lu), oi);
	ostid_cpu_to_le(oi, &objs->l_ost_oi);
	objs->l_ost_gen = cpu_to_le32(0);
	objs->l_ost_idx = cpu_to_le32(llr->llr_ost_idx);
	rc = dt_xattr_set(env, parent, buf, XATTR_NAME_LOV,
			  LU_XATTR_REPLACE, handle);

	GOTO(unlock, rc = (rc == 0 ? 1 : rc));

unlock:
	dt_write_unlock(env, parent);

stop:
	if (handle != NULL)
		dt_trans_stop(env, dev, handle);

log:
	lfsck_ibits_unlock(&lh, LCK_EX);
	if (child != NULL)
		lfsck_object_put(env, child);

	if (rc)
		CDEBUG(D_LFSCK, "%s: layout LFSCK assistant repaired "
		       "multiple references for: parent "DFID", comp_id %u, "
		       "OST-index %u, stripe-index %u, owner %u/%u: rc = %d\n",
		       lfsck_lfsck2name(lfsck), PFID(pfid),
		       llr->llr_comp_id, llr->llr_ost_idx, llr->llr_lov_idx,
		       la->la_uid, la->la_gid, rc);

	return rc;
}

/* If the MDT-object and the OST-object have different owner information,
 * then trust the MDT-object, because the normal chown/chgrp handle order
 * is from MDT to OST, and it is possible that some chown/chgrp operation
 * is partly done. */
static int lfsck_layout_repair_owner(const struct lu_env *env,
				     struct lfsck_component *com,
				     struct dt_object *parent,
				     struct lfsck_layout_req *llr,
				     struct lu_attr *pla,
				     const struct lu_attr *cla)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_attr			*tla	= &info->lti_la2;
	struct dt_object		*child  = llr->llr_child;
	struct dt_device		*dev	= lfsck_obj2dev(child);
	struct thandle			*handle;
	int				 rc;
	dt_obj_version_t		 version;
	ENTRY;

	tla->la_uid = pla->la_uid;
	tla->la_gid = pla->la_gid;
	tla->la_valid = LA_UID | LA_GID;
	handle = dt_trans_create(env, dev);
	if (IS_ERR(handle))
		GOTO(log, rc = PTR_ERR(handle));

	rc = dt_declare_attr_set(env, child, tla, handle);
	if (rc != 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, handle);
	if (rc != 0)
		GOTO(stop, rc);

	/* Use the dt_object lock to serialize with destroy and attr_set. */
	dt_read_lock(env, parent, 0);
	if (unlikely(lfsck_is_dead_obj(parent)))
		GOTO(unlock, rc = 1);

	version = dt_version_get(env, child);
	if (version == -EOPNOTSUPP)
		version = 0;

	/* Get the latest parent's owner. */
	rc = dt_attr_get(env, parent, pla);
	if (rc != 0)
		GOTO(unlock, rc);

	/* Some others chown/chgrp during the LFSCK, needs to do nothing. */
	if (unlikely((!version && tla->la_ctime == 0) ||
		     tla->la_uid != pla->la_uid || tla->la_gid != pla->la_gid))
		rc = 1;
	else
		rc = dt_attr_set(env, child, tla, handle);

	GOTO(unlock, rc);

unlock:
	dt_read_unlock(env, parent);

stop:
	rc = lfsck_layout_trans_stop(env, dev, handle, rc);

log:
	if (rc != 0)
		CDEBUG(D_LFSCK, "%s: layout LFSCK assistant repaired "
		       "inconsistent file owner for: parent "DFID", child "DFID
		       ", OST-index %u, stripe-index %u, old owner %u/%u, "
		       "new owner %u/%u: rc = %d\n",
		       lfsck_lfsck2name(com->lc_lfsck),
		       PFID(lfsck_dto2fid(parent)), PFID(lfsck_dto2fid(child)),
		       llr->llr_ost_idx, llr->llr_lov_idx,
		       cla->la_uid, cla->la_gid, tla->la_uid, tla->la_gid, rc);

	return rc;
}

#define CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid, msg)		 \
	CDEBUG(D_LFSCK, "%s:("DFID"|"DFID")/"DFID":XATTR %s: %s\n",	 \
	       lfsck_lfsck2name(lfsck), PFID(&lso->lso_fid), PFID(pfid), \
	       PFID(cfid), XATTR_NAME_FID, msg);

/* Check whether the OST-object correctly back points to the
 * MDT-object (@parent) via the XATTR_NAME_FID xattr (@pfid). */
static int lfsck_layout_check_parent(const struct lu_env *env,
				     struct lfsck_component *com,
				     struct lfsck_assistant_object *lso,
				     struct filter_fid *ff,
				     const struct lu_fid *cfid,
				     const struct lu_attr *cla,
				     struct lfsck_layout_req *llr)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_buf			*buf	= &info->lti_big_buf;
	struct lu_fid			*pfid   = &info->lti_fid;
	struct dt_object		*tobj;
	struct lov_mds_md_v1		*lmm;
	struct lov_ost_data_v1		*objs;
	struct lustre_handle		 lh	= { 0 };
	struct lfsck_instance		*lfsck  = com->lc_lfsck;
	int				 rc;
	int				 i;
	__u32				 magic;
	__u32				 idx;
	__u16				 count;
	ENTRY;

	*pfid = ff->ff_parent;
	idx = pfid->f_stripe_idx;
	pfid->f_ver = 0;

	if (unlikely(!fid_is_sane(pfid))) {
		CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
				      "the parent FID is invalid");

		RETURN(LLIT_UNMATCHED_PAIR);
	}

	if (lu_fid_eq(pfid, &lso->lso_fid)) {
		if (likely(llr->llr_lov_idx == idx))
			RETURN(0);

		CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
				      "the stripe index is unmatched");

		RETURN(LLIT_UNMATCHED_PAIR);
	}

	tobj = lfsck_object_find_bottom(env, com->lc_lfsck, pfid);
	if (IS_ERR(tobj))
		RETURN(PTR_ERR(tobj));

	if (dt_object_exists(tobj) == 0) {
		CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
				      "the parent is nonexistent");

		GOTO(out, rc = LLIT_UNMATCHED_PAIR);
	}

	if (lfsck_is_dead_obj(tobj)) {
		CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
				      "the parent is dead object");

		GOTO(out, rc = LLIT_UNMATCHED_PAIR);
	}

	if (!S_ISREG(lfsck_object_type(tobj))) {
		CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
				      "the parent is not a regular file");

		GOTO(out, rc = LLIT_UNMATCHED_PAIR);
	}

	/* Load the tobj's layout EA, in spite of it is a local MDT-object or
	 * remote one on another MDT. Then check whether the given OST-object
	 * is in such layout. If yes, it is multiple referenced, otherwise it
	 * is unmatched referenced case. */
	rc = lfsck_layout_get_lovea(env, tobj, buf);
	if (rc == 0 || rc == -ENODATA || rc == -ENOENT) {
		CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
				      "the parent has no stripe data");

		GOTO(out, rc = LLIT_UNMATCHED_PAIR);
	}

	if (unlikely(rc == -EOPNOTSUPP))
		GOTO(out, rc = LLIT_NONE);

	if (rc < 0)
		GOTO(out, rc);

	lmm = buf->lb_buf;
	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
		struct lov_comp_md_v1 *lcm = buf->lb_buf;
		struct lov_comp_md_entry_v1 *lcme;

		if (ff->ff_layout.ol_comp_id == 0) {
			CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
					      "the parent has incorrect comp_id");

			GOTO(out, rc = LLIT_UNMATCHED_PAIR);
		}

		count = le16_to_cpu(lcm->lcm_entry_count);
		for (i = 0; i < count; i++) {
			lcme = &lcm->lcm_entries[i];
			if (le32_to_cpu(lcme->lcme_id) ==
			    ff->ff_layout.ol_comp_id) {
				lmm = buf->lb_buf +
					le32_to_cpu(lcme->lcme_offset);
				magic = le32_to_cpu(lmm->lmm_magic);
				if (!(le32_to_cpu(lcme->lcme_flags) &
				      LCME_FL_INIT)) {
					CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid,
							      cfid,
							      "the parent has uninitialized component");

					GOTO(out, rc = LLIT_UNMATCHED_PAIR);
				}

				goto further;
			}
		}

		CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
				      "the parent has no matched comp_id");

		GOTO(out, rc = LLIT_UNMATCHED_PAIR);
	}

further:
	if (magic == LOV_MAGIC_V1) {
		objs = &lmm->lmm_objects[0];
	} else {
		LASSERT(magic == LOV_MAGIC_V3);
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
	}

	count = le16_to_cpu(lmm->lmm_stripe_count);
	for (i = 0; i < count; i++, objs++) {
		struct lu_fid		*tfid	= &info->lti_fid2;
		struct ost_id		*oi	= &info->lti_oi;
		__u32			 idx2;

		if (lovea_slot_is_dummy(objs))
			continue;

		ostid_le_to_cpu(&objs->l_ost_oi, oi);
		idx2 = le32_to_cpu(objs->l_ost_idx);
		rc = ostid_to_fid(tfid, oi, idx2);
		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: the parent "DFID" contains "
			       "invalid layout EA at the slot %d, index %u\n",
			       lfsck_lfsck2name(com->lc_lfsck),
			       PFID(pfid), i, idx2);

			GOTO(out, rc = LLIT_UNMATCHED_PAIR);
		}

		if (lu_fid_eq(cfid, tfid)) {
			rc = lfsck_ibits_lock(env, com->lc_lfsck, tobj, &lh,
					      MDS_INODELOCK_UPDATE |
					      MDS_INODELOCK_LAYOUT |
					      MDS_INODELOCK_XATTR,
					      LCK_EX);
			if (rc != 0)
				GOTO(out, rc);

			dt_read_lock(env, tobj, 0);

			/* For local MDT-object, re-check existence
			 * after taken the lock. */
			if (!dt_object_remote(tobj)) {
				if (dt_object_exists(tobj) == 0 ||
				    lfsck_is_dead_obj(tobj)) {
					CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid,
							      cfid,
							      "the parent doesn't exist anymore after lock");

					rc = LLIT_UNMATCHED_PAIR;
				} else {
					rc = LLIT_MULTIPLE_REFERENCED;
				}

				GOTO(unlock, rc);
			}

			/* For migration case, the new MDT-object and old
			 * MDT-object may reference the same OST-object at
			 * some migration internal time.
			 *
			 * For remote MDT-object, the local MDT may not know
			 * whether it has been removed or not.  Try checking
			 * for a non-existent xattr to check if this object
			 * has been been removed or not. */
			rc = dt_xattr_get(env, tobj, &LU_BUF_NULL,
					  XATTR_NAME_DUMMY);
			if (unlikely(rc == -ENOENT || rc >= 0)) {
				CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
						      "the parent is remote object and nonexistent after lock");

				rc = LLIT_UNMATCHED_PAIR;
			} else if (rc == -ENODATA) {
				rc = LLIT_MULTIPLE_REFERENCED;
			}

			GOTO(unlock, rc);
		}
	}

	CDEBUG_UNMATCHED_PAIR(lfsck, lso, pfid, cfid,
			      "the parent has no matched stripe");

	GOTO(out, rc = LLIT_UNMATCHED_PAIR);

unlock:
	if (lustre_handle_is_used(&lh)) {
		dt_read_unlock(env, tobj);
		lfsck_ibits_unlock(&lh, LCK_EX);
	}

out:
	lfsck_object_put(env, tobj);

	return rc;
}

static int lfsck_layout_assistant_handler_p1(const struct lu_env *env,
					     struct lfsck_component *com,
					     struct lfsck_assistant_req *lar)
{
	struct lfsck_layout_req		     *llr    =
		container_of(lar, struct lfsck_layout_req, llr_lar);
	struct lfsck_assistant_object	     *lso    = lar->lar_parent;
	struct lfsck_layout		     *lo     = com->lc_file_ram;
	struct lfsck_thread_info	     *info   = lfsck_env_info(env);
	struct filter_fid		     *ff     = &info->lti_ff;
	struct lu_buf buf = { .lb_buf = ff,
			      .lb_len = sizeof(*ff) };
	struct dt_object		     *parent = NULL;
	struct dt_object		     *child  = llr->llr_child;
	struct lu_attr			     *pla    = &lso->lso_attr;
	struct lu_attr			     *cla    = &info->lti_la;
	struct lfsck_instance		     *lfsck  = com->lc_lfsck;
	struct lfsck_bookmark		     *bk     = &lfsck->li_bookmark_ram;
	enum lfsck_layout_inconsistency_type  type   = LLIT_NONE;
	int				      rc;
	ENTRY;

	if (lso->lso_dead)
		RETURN(0);

	CFS_FAIL_TIMEOUT(OBD_FAIL_LFSCK_ENGINE_DELAY, cfs_fail_val);

	rc = dt_attr_get(env, child, cla);
	if (rc == -ENOENT) {
		parent = lfsck_assistant_object_load(env, lfsck, lso);
		if (IS_ERR(parent)) {
			rc = PTR_ERR(parent);

			RETURN(rc == -ENOENT ? 0 : rc);
		}

		type = LLIT_DANGLING;
		goto repair;
	}

	if (rc != 0)
		GOTO(out, rc);

	lfsck_buf_init(&buf, ff, sizeof(*ff));
	rc = dt_xattr_get(env, child, &buf, XATTR_NAME_FID);
	if (unlikely(rc > 0 && rc < sizeof(struct lu_fid))) {
		CDEBUG(D_LFSCK, "%s:"DFID"/"DFID": "
		       "the child object's %s is corrupted\n",
		       lfsck_lfsck2name(lfsck), PFID(&lso->lso_fid),
		       PFID(lu_object_fid(&child->do_lu)),
		       XATTR_NAME_FID);

		type = LLIT_UNMATCHED_PAIR;
		goto repair;
	}

	if (rc < 0 && rc != -ENODATA)
		GOTO(out, rc);

	if (rc == 0 || rc == -ENODATA)
		GOTO(check_owner, rc = 0);

	filter_fid_le_to_cpu(ff, ff, sizeof(*ff));
	rc = lfsck_layout_check_parent(env, com, lso, ff,
				       lu_object_fid(&child->do_lu), cla, llr);
	if (rc > 0) {
		type = rc;
		goto repair;
	}

	if (rc < 0)
		GOTO(out, rc);

check_owner:
	/* Someone may has changed the owner after the parent attr pre-loaded.
	 * It can be handled later inside the lfsck_layout_repair_owner(). */
	if (unlikely(cla->la_uid != pla->la_uid ||
		     cla->la_gid != pla->la_gid)) {
		type = LLIT_INCONSISTENT_OWNER;
		goto repair;
	}

repair:
	if (type == LLIT_NONE)
		GOTO(out, rc = 0);

	if (bk->lb_param & LPF_DRYRUN)
		GOTO(out, rc = 1);

	if (parent == NULL) {
		parent = lfsck_assistant_object_load(env, lfsck, lso);
		if (IS_ERR(parent)) {
			rc = PTR_ERR(parent);

			if (rc == -ENOENT)
				RETURN(0);

			GOTO(out, rc);
		}
	}

	switch (type) {
	case LLIT_DANGLING:
		if (bk->lb_param & LPF_DELAY_CREATE_OSTOBJ)
			rc = lfsck_layout_ins_dangling_rec(env, com,
				lfsck_dto2fid(parent), lfsck_dto2fid(child),
				llr->llr_comp_id, llr->llr_lov_idx,
				llr->llr_ost_idx);
		else
			rc = __lfsck_layout_repair_dangling(env, com, parent,
							    llr->llr_child,
							    llr->llr_comp_id,
							    llr->llr_lov_idx,
							    llr->llr_ost_idx,
							    true);
		break;
	case LLIT_UNMATCHED_PAIR:
		rc = lfsck_layout_repair_unmatched_pair(env, com, parent,
							llr, pla);
		break;
	case LLIT_MULTIPLE_REFERENCED:
		rc = lfsck_layout_repair_multiple_references(env, com, parent,
							     llr, pla);
		break;
	case LLIT_INCONSISTENT_OWNER:
		rc = lfsck_layout_repair_owner(env, com, parent, llr, pla, cla);
		break;
	default:
		rc = 0;
		break;
	}

	GOTO(out, rc);

out:
	down_write(&com->lc_sem);
	if (rc < 0) {
		struct lfsck_assistant_data *lad = com->lc_data;

		if (unlikely(test_bit(LAD_EXIT, &lad->lad_flags))) {
			rc = 0;
		} else if (rc == -ENOTCONN || rc == -ESHUTDOWN ||
			   rc == -ETIMEDOUT || rc == -EHOSTDOWN ||
			   rc == -EHOSTUNREACH) {
			/* If cannot touch the target server,
			 * mark the LFSCK as INCOMPLETE. */
			CDEBUG(D_LFSCK, "%s: layout LFSCK assistant fail to "
			       "talk with OST %x: rc = %d\n",
			       lfsck_lfsck2name(lfsck), llr->llr_ost_idx, rc);
			lfsck_lad_set_bitmap(env, com, llr->llr_ost_idx);
			lo->ll_objs_skipped++;
			rc = 0;
		} else {
			lfsck_layout_record_failure(env, lfsck, lo);
		}
	} else if (rc > 0 && (type != LLIT_DANGLING ||
			      !(bk->lb_param & LPF_DELAY_CREATE_OSTOBJ))) {
		LASSERTF(type > LLIT_NONE && type <= LLIT_MAX,
			 "unknown type = %d\n", type);

		lo->ll_objs_repaired[type - 1]++;
		if (bk->lb_param & LPF_DRYRUN &&
		    unlikely(lo->ll_pos_first_inconsistent == 0))
			lo->ll_pos_first_inconsistent =
			lfsck->li_obj_oit->do_index_ops->dio_it.store(env,
							lfsck->li_di_oit);
	}
	up_write(&com->lc_sem);

	if (parent != NULL && !IS_ERR(parent))
		lfsck_object_put(env, parent);

	return rc;
}

static int
lfsck_layout_double_scan_one_trace_file(const struct lu_env *env,
					struct lfsck_component *com,
					struct dt_object *obj, bool first)
{
	struct lfsck_instance *lfsck = com->lc_lfsck;
	struct ptlrpc_thread *thread = &lfsck->li_thread;
	struct lfsck_bookmark *bk = &lfsck->li_bookmark_ram;
	struct lfsck_layout *lo = com->lc_file_ram;
	const struct dt_it_ops *iops = &obj->do_index_ops->dio_it;
	struct dt_it *di;
	struct dt_key *key;
	struct lfsck_layout_dangling_key *parent =
					&lfsck_env_info(env)->lti_lldk;
	struct lu_fid *cfid = &lfsck_env_info(env)->lti_fid3;
	__u32 ost_idx;
	int rc;
	ENTRY;

	di = iops->init(env, obj, 0);
	if (IS_ERR(di))
		RETURN(PTR_ERR(di));

	if (first)
		lldk_cpu_to_be(parent, &lo->ll_lldk_latest_scanned_phase2);
	else
		memset(parent, 0, sizeof(*parent));
	rc = iops->get(env, di, (const struct dt_key *)parent);
	if (rc < 0)
		GOTO(fini, rc);

	if (first) {
		/* The start one either has been processed or does not exist,
		 * skip it. */
		rc = iops->next(env, di);
		if (rc != 0)
			GOTO(put, rc);
	}

	do {
		if (CFS_FAIL_TIMEOUT(OBD_FAIL_LFSCK_DELAY3, cfs_fail_val) &&
		    unlikely(!thread_is_running(thread)))
			GOTO(put, rc = 0);

		key = iops->key(env, di);
		if (IS_ERR(key)) {
			rc = PTR_ERR(key);
			if (rc == -ENOENT)
				GOTO(put, rc = 1);

			goto checkpoint;
		}

		lldk_be_to_cpu(parent,
				(const struct lfsck_layout_dangling_key *)key);
		if (!fid_is_sane(&parent->lldk_fid)) {
			rc = 0;
			goto checkpoint;
		}

		rc = iops->rec(env, di, (struct dt_rec *)cfid, 0);
		if (rc == 0) {
			fid_be_to_cpu(cfid, cfid);
			ost_idx = cfid->f_ver;
			cfid->f_ver = 0;
			if (!fid_is_sane(cfid)) {
				rc = 0;
				goto checkpoint;
			}

			rc = lfsck_layout_repair_dangling(env, com,
					&parent->lldk_fid, cfid,
					parent->lldk_comp_id,
					parent->lldk_ea_off, ost_idx);
		}

checkpoint:
		down_write(&com->lc_sem);
		com->lc_new_checked++;
		com->lc_new_scanned++;
		if (rc >= 0)
			lo->ll_lldk_latest_scanned_phase2 = *parent;

		if (rc > 0)
			lo->ll_objs_repaired[LLIT_DANGLING - 1]++;
		else if (rc < 0)
			lo->ll_objs_failed_phase2++;
		up_write(&com->lc_sem);

		if (rc < 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(put, rc);

		if (unlikely(com->lc_time_next_checkpoint <=
			     ktime_get_seconds()) &&
		    com->lc_new_checked != 0) {
			down_write(&com->lc_sem);
			lo->ll_run_time_phase2 += ktime_get_seconds() -
						  com->lc_time_last_checkpoint;
			lo->ll_time_last_checkpoint = ktime_get_real_seconds();
			lo->ll_objs_checked_phase2 += com->lc_new_checked;
			com->lc_new_checked = 0;
			lfsck_layout_store(env, com);
			up_write(&com->lc_sem);

			com->lc_time_last_checkpoint = ktime_get_seconds();
			com->lc_time_next_checkpoint =
				com->lc_time_last_checkpoint +
				LFSCK_CHECKPOINT_INTERVAL;
		}

		lfsck_control_speed_by_self(com);
		if (unlikely(!thread_is_running(thread)))
			GOTO(put, rc = 0);

		rc = iops->next(env, di);
	} while (rc == 0);

	GOTO(put, rc);

put:
	iops->put(env, di);

fini:
	iops->fini(env, di);

	return rc;
}

static int lfsck_layout_assistant_handler_p2(const struct lu_env *env,
					     struct lfsck_component *com)
{
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_bookmark		*bk     = &lfsck->li_bookmark_ram;
	struct lfsck_tgt_descs		*ltds	= &lfsck->li_ost_descs;
	struct lfsck_tgt_desc		*ltd;
	int				 rc	= 0;
	ENTRY;

	CDEBUG(D_LFSCK, "%s: layout LFSCK phase2 scan start\n",
	       lfsck_lfsck2name(lfsck));

	spin_lock(&ltds->ltd_lock);
	while (!list_empty(&lad->lad_ost_phase2_list)) {
		ltd = list_entry(lad->lad_ost_phase2_list.next,
				 struct lfsck_tgt_desc,
				 ltd_layout_phase_list);
		list_del_init(&ltd->ltd_layout_phase_list);
		if (bk->lb_param & LPF_OST_ORPHAN) {
			spin_unlock(&ltds->ltd_lock);
			rc = lfsck_layout_scan_orphan(env, com, ltd);
			if (rc != 0 && bk->lb_param & LPF_FAILOUT)
				RETURN(rc);

			if (unlikely(test_bit(LAD_EXIT, &lad->lad_flags) ||
				     !thread_is_running(&lfsck->li_thread)))
				RETURN(0);
			spin_lock(&ltds->ltd_lock);
		}
	}

	if (list_empty(&lad->lad_ost_phase1_list))
		rc = 1;
	else
		rc = 0;
	spin_unlock(&ltds->ltd_lock);

	if (rc == 1 && bk->lb_param & LPF_OST_ORPHAN) {
		struct lfsck_layout *lo = com->lc_file_ram;
		int i;

		com->lc_new_checked = 0;
		com->lc_new_scanned = 0;
		com->lc_time_last_checkpoint = ktime_get_seconds();
		com->lc_time_next_checkpoint = com->lc_time_last_checkpoint +
					       LFSCK_CHECKPOINT_INTERVAL;

		i = lfsck_sub_trace_file_fid2idx(
				&lo->ll_lldk_latest_scanned_phase2.lldk_fid);
		rc = lfsck_layout_double_scan_one_trace_file(env, com,
				com->lc_sub_trace_objs[i].lsto_obj, true);
		while (rc > 0 && ++i < LFSCK_STF_COUNT)
			rc = lfsck_layout_double_scan_one_trace_file(env, com,
				com->lc_sub_trace_objs[i].lsto_obj, false);

		CDEBUG(D_LFSCK, "%s: layout LFSCK phase2 scan dangling stop "
		       "at the No. %d trace file: rc = %d\n",
		       lfsck_lfsck2name(lfsck), i, rc);
	}

	CDEBUG(D_LFSCK, "%s: layout LFSCK phase2 scan stop: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc);

	RETURN(rc);
}

static int
lfsck_layout_slave_async_interpret(const struct lu_env *env,
				   struct ptlrpc_request *req,
				   void *args, int rc)
{
	struct lfsck_layout_slave_async_args *llsaa = args;
	struct obd_export *exp = llsaa->llsaa_exp;
	struct lfsck_component *com = llsaa->llsaa_com;
	struct lfsck_layout_slave_target *llst = llsaa->llsaa_llst;
	struct lfsck_layout_slave_data *llsd = com->lc_data;
	struct lfsck_reply *lr = NULL;
	bool done = false;

	if (rc != 0) {
		/* It is probably caused by network trouble, or target crash,
		 * it will try several times (depends on the obd_timeout, and
		 * will not less than 3 times). But to make the LFSCK can go
		 * ahead, we should not try for ever. After some try but still
		 * hit failure, it will assume that the target exit the LFSCK
		 * prcoessing and stop try. */
		if (rc == -ENOTCONN || rc == -ESHUTDOWN) {
			int max_try = max_t(int, obd_timeout / 30, 3);

			if (++(llst->llst_failures) > max_try)
				done = true;
		} else {
			done = true;
		}
	} else {
		llst->llst_failures = 0;
		lr = req_capsule_server_get(&req->rq_pill, &RMF_LFSCK_REPLY);
		if (lr->lr_status != LS_SCANNING_PHASE1 &&
		    lr->lr_status != LS_SCANNING_PHASE2)
			done = true;
	}

	if (done) {
		CDEBUG(D_LFSCK, "%s: layout LFSCK slave gets the MDT %x "
		       "status %d, failures_try %d\n", lfsck_lfsck2name(com->lc_lfsck),
		       llst->llst_index, lr != NULL ? lr->lr_status : rc,
		       llst->llst_failures);

		lfsck_layout_llst_del(llsd, llst);
	}

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

	llsaa = ptlrpc_req_async_args(llsaa, req);
	llsaa->llsaa_exp = exp;
	llsaa->llsaa_com = lfsck_component_get(com);
	llsaa->llsaa_llst = llst;
	req->rq_interpret_reply = lfsck_layout_slave_async_interpret;
	req->rq_allow_intr = 1;
	req->rq_no_delay = 1;
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
	req->rq_allow_intr = 1;
	req->rq_no_delay = 1;
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
		GOTO(log, rc = -ENOMEM);

	memset(lr, 0, sizeof(*lr));
	lr->lr_event = LE_QUERY;
	lr->lr_active = LFSCK_TYPE_LAYOUT;

	llsd->llsd_touch_gen++;
	spin_lock(&llsd->llsd_lock);
	while (!list_empty(&llsd->llsd_master_list)) {
		llst = list_entry(llsd->llsd_master_list.next,
				  struct lfsck_layout_slave_target,
				  llst_list);
		if (llst->llst_gen == llsd->llsd_touch_gen)
			break;

		llst->llst_gen = llsd->llsd_touch_gen;
		list_move_tail(&llst->llst_list,
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
			CDEBUG(D_LFSCK, "%s: layout LFSCK slave fail to "
			       "query %s for layout: rc = %d\n",
			       lfsck_lfsck2name(lfsck),
			       exp->exp_obd->obd_name, rc);

			rc1 = rc;
			lfsck_layout_llst_put(llst);
			class_export_put(exp);
		}
		spin_lock(&llsd->llsd_lock);
	}
	spin_unlock(&llsd->llsd_lock);

	rc = ptlrpc_set_wait(env, set);
	ptlrpc_set_destroy(set);

	GOTO(log, rc = (rc1 != 0 ? rc1 : rc));

log:
	CDEBUG(D_LFSCK, "%s: layout LFSCK slave queries master: rc = %d\n",
	       lfsck_lfsck2name(com->lc_lfsck), rc);

	return rc;
}

static void
lfsck_layout_slave_notify_master(const struct lu_env *env,
				 struct lfsck_component *com,
				 enum lfsck_events event, int result)
{
	struct lfsck_layout		 *lo    = com->lc_file_ram;
	struct lfsck_instance		 *lfsck = com->lc_lfsck;
	struct lfsck_layout_slave_data	 *llsd  = com->lc_data;
	struct lfsck_request		 *lr    = &lfsck_env_info(env)->lti_lr;
	struct lfsck_layout_slave_target *llst;
	struct obd_export		 *exp;
	struct ptlrpc_request_set	 *set;
	int				  rc;
	ENTRY;

	CDEBUG(D_LFSCK, "%s: layout LFSCK slave notifies master\n",
	       lfsck_lfsck2name(com->lc_lfsck));

	set = ptlrpc_prep_set();
	if (set == NULL)
		RETURN_EXIT;

	memset(lr, 0, sizeof(*lr));
	lr->lr_event = event;
	lr->lr_flags = LEF_FROM_OST;
	lr->lr_status = result;
	lr->lr_index = lfsck_dev_idx(lfsck);
	lr->lr_active = LFSCK_TYPE_LAYOUT;
	lr->lr_flags2 = lo->ll_flags;
	llsd->llsd_touch_gen++;
	spin_lock(&llsd->llsd_lock);
	while (!list_empty(&llsd->llsd_master_list)) {
		llst = list_entry(llsd->llsd_master_list.next,
				  struct lfsck_layout_slave_target,
				  llst_list);
		if (llst->llst_gen == llsd->llsd_touch_gen)
			break;

		llst->llst_gen = llsd->llsd_touch_gen;
		list_move_tail(&llst->llst_list,
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
			CDEBUG(D_LFSCK, "%s: layout LFSCK slave fail to "
			       "notify %s for layout: rc = %d\n",
			       lfsck_lfsck2name(lfsck),
			       exp->exp_obd->obd_name, rc);

		lfsck_layout_llst_put(llst);
		class_export_put(exp);
		spin_lock(&llsd->llsd_lock);
	}
	spin_unlock(&llsd->llsd_lock);

	ptlrpc_set_wait(env, set);
	ptlrpc_set_destroy(set);

	RETURN_EXIT;
}

/*
 * \ret -ENODATA: unrecognized stripe
 * \ret = 0     : recognized stripe
 * \ret < 0     : other failures
 */
static int lfsck_layout_master_check_pairs(const struct lu_env *env,
					   struct lfsck_component *com,
					   struct lu_fid *cfid,
					   struct lu_fid *pfid, __u32 comp_id)
{
	struct lfsck_thread_info	*info	= lfsck_env_info(env);
	struct lu_buf			*buf	= &info->lti_big_buf;
	struct ost_id			*oi     = &info->lti_oi;
	struct dt_object		*obj;
	struct lov_mds_md_v1		*lmm;
	struct lov_ost_data_v1		*objs;
	__u32				 idx	= pfid->f_stripe_idx;
	__u32				 magic;
	int				 rc	= 0;
	int				 i;
	__u16				 count;
	ENTRY;

	pfid->f_ver = 0;
	obj = lfsck_object_find_bottom(env, com->lc_lfsck, pfid);
	if (IS_ERR(obj))
		RETURN(PTR_ERR(obj));

	dt_read_lock(env, obj, 0);
	if (unlikely(dt_object_exists(obj) == 0 ||
		     lfsck_is_dead_obj(obj)))
		GOTO(unlock, rc = -ENOENT);

	if (!S_ISREG(lfsck_object_type(obj)))
		GOTO(unlock, rc = -ENODATA);

	rc = lfsck_layout_get_lovea(env, obj, buf);
	if (rc < 0)
		GOTO(unlock, rc);

	lmm = buf->lb_buf;
	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
		struct lov_comp_md_v1 *lcm = buf->lb_buf;
		struct lov_comp_md_entry_v1 *lcme;

		if (comp_id == 0)
			GOTO(unlock, rc = -ENODATA);

		count = le16_to_cpu(lcm->lcm_entry_count);
		for (i = 0; i < count; i++) {
			lcme = &lcm->lcm_entries[i];
			if (le32_to_cpu(lcme->lcme_id) == comp_id) {
				lmm = buf->lb_buf +
					le32_to_cpu(lcme->lcme_offset);
				magic = le32_to_cpu(lmm->lmm_magic);
				if (!(le32_to_cpu(lcme->lcme_flags) &
				      LCME_FL_INIT))
					GOTO(unlock, rc = -ENODATA);

				goto further;
			}
		}

		GOTO(unlock, rc = -ENODATA);
	}

further:
	if (magic == LOV_MAGIC_V1) {
		objs = &lmm->lmm_objects[0];
	} else {
		LASSERT(magic == LOV_MAGIC_V3);
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
	}

	fid_to_ostid(cfid, oi);
	count = le16_to_cpu(lmm->lmm_stripe_count);
	for (i = 0; i < count; i++, objs++) {
		struct ost_id oi2;

		ostid_le_to_cpu(&objs->l_ost_oi, &oi2);
		if (memcmp(oi, &oi2, sizeof(*oi)) == 0)
			GOTO(unlock, rc = (i != idx ? -ENODATA : 0));
	}

	GOTO(unlock, rc = -ENODATA);

unlock:
	dt_read_unlock(env, obj);
	lfsck_object_put(env, obj);

	return rc;
}

/*
 * The LFSCK-on-OST will ask the LFSCK-on-MDT to check whether the given
 * MDT-object/OST-object pairs match or not to aviod transfer MDT-object
 * layout EA from MDT to OST. On one hand, the OST no need to understand
 * the layout EA structure; on the other hand, it may cause trouble when
 * transfer large layout EA from MDT to OST via normal OUT RPC.
 *
 * \ret > 0: unrecognized stripe
 * \ret = 0: recognized stripe
 * \ret < 0: other failures
 */
static int lfsck_layout_slave_check_pairs(const struct lu_env *env,
					  struct lfsck_component *com,
					  struct lu_fid *cfid,
					  struct lu_fid *pfid, __u32 comp_id)
{
	struct lfsck_instance	 *lfsck	 = com->lc_lfsck;
	struct obd_device	 *obd	 = lfsck->li_obd;
	struct seq_server_site	 *ss	 = lfsck_dev_site(lfsck);
	struct obd_export	 *exp	 = NULL;
	struct ptlrpc_request	 *req	 = NULL;
	struct lfsck_request	 *lr;
	struct lu_seq_range	 *range  = &lfsck_env_info(env)->lti_range;
	int			  rc	 = 0;
	ENTRY;

	if (unlikely(fid_is_idif(pfid)))
		RETURN(1);

	fld_range_set_any(range);
	rc = fld_server_lookup(env, ss->ss_server_fld, fid_seq(pfid), range);
	if (rc != 0)
		RETURN(rc == -ENOENT ? 1 : rc);

	if (unlikely(!fld_range_is_mdt(range)))
		RETURN(1);

	exp = lustre_find_lwp_by_index(obd->obd_name, range->lsr_index);
	if (unlikely(exp == NULL))
		RETURN(1);

	if (!(exp_connect_flags(exp) & OBD_CONNECT_LFSCK))
		GOTO(out, rc = -EOPNOTSUPP);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_LFSCK_NOTIFY);
	if (req == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OBD_VERSION, LFSCK_NOTIFY);
	if (rc != 0) {
		ptlrpc_request_free(req);

		GOTO(out, rc);
	}

	lr = req_capsule_client_get(&req->rq_pill, &RMF_LFSCK_REQUEST);
	memset(lr, 0, sizeof(*lr));
	lr->lr_event = LE_PAIRS_VERIFY;
	lr->lr_active = LFSCK_TYPE_LAYOUT;
	lr->lr_fid = *cfid; /* OST-object itself FID. */
	lr->lr_fid2 = *pfid; /* The claimed parent FID. */
	lr->lr_comp_id = comp_id;

	ptlrpc_request_set_replen(req);
	rc = ptlrpc_queue_wait(req);
	ptlrpc_req_finished(req);

	if (rc == -ENOENT || rc == -ENODATA)
		rc = 1;

	GOTO(out, rc);

out:
	if (exp != NULL)
		class_export_put(exp);

	return rc;
}

static int lfsck_layout_slave_repair_pfid(const struct lu_env *env,
					  struct lfsck_component *com,
					  struct lfsck_req_local *lrl)
{
	struct dt_object	*obj;
	int			 rc	= 0;
	ENTRY;

	obj = lfsck_object_find_bottom(env, com->lc_lfsck, &lrl->lrl_fid);
	if (IS_ERR(obj))
		GOTO(log, rc = PTR_ERR(obj));

	dt_write_lock(env, obj, 0);
	if (unlikely(dt_object_exists(obj) == 0 ||
		     lfsck_is_dead_obj(obj)))
		GOTO(unlock, rc = 0);

	rc = __lfsck_layout_update_pfid(env, obj, &lrl->lrl_ff_client.ff_parent,
					&lrl->lrl_ff_client.ff_layout,
					lrl->lrl_ff_client.ff_layout_version,
					lrl->lrl_ff_client.ff_range,
					lrl->lrl_ff_client.ff_parent.f_ver);

	GOTO(unlock, rc);

unlock:
	dt_write_unlock(env, obj);
	lfsck_object_put(env, obj);

log:
	CDEBUG(D_LFSCK, "%s: layout LFSCK slave repaired pfid for "DFID
	       ", parent "DFID": rc = %d\n", lfsck_lfsck2name(com->lc_lfsck),
	       PFID(&lrl->lrl_fid), PFID(&lrl->lrl_ff_client.ff_parent), rc);

	return rc;
}

/* layout APIs */

static void lfsck_layout_slave_quit(const struct lu_env *env,
				    struct lfsck_component *com);

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
		time64_t last_time = lo->ll_time_last_complete;

		memset(lo, 0, com->lc_file_size);
		lo->ll_success_count = count;
		lo->ll_time_last_complete = last_time;
	}

	lo->ll_magic = LFSCK_LAYOUT_MAGIC;
	lo->ll_status = LS_INIT;

	if (com->lc_lfsck->li_master) {
		struct lfsck_assistant_data *lad = com->lc_data;

		clear_bit(LAD_INCOMPLETE, &lad->lad_flags);
		CFS_RESET_BITMAP(lad->lad_bitmap);
	}

	rc = lfsck_layout_store(env, com);
	if (rc == 0 && com->lc_lfsck->li_master)
		rc = lfsck_load_sub_trace_files(env, com,
			&dt_lfsck_layout_dangling_features, LFSCK_LAYOUT, true);
	up_write(&com->lc_sem);

	CDEBUG(D_LFSCK, "%s: layout LFSCK reset: rc = %d\n",
	       lfsck_lfsck2name(com->lc_lfsck), rc);

	return rc;
}

static void lfsck_layout_fail(const struct lu_env *env,
			      struct lfsck_component *com, bool new_checked)
{
	struct lfsck_layout *lo = com->lc_file_ram;

	down_write(&com->lc_sem);
	if (new_checked)
		com->lc_new_checked++;
	lfsck_layout_record_failure(env, com->lc_lfsck, lo);
	up_write(&com->lc_sem);
}

static int lfsck_layout_master_checkpoint(const struct lu_env *env,
					  struct lfsck_component *com, bool init)
{
	struct lfsck_instance	*lfsck	 = com->lc_lfsck;
	struct lfsck_layout	*lo	 = com->lc_file_ram;
	int			 rc;

	if (!init) {
		rc = lfsck_checkpoint_generic(env, com);
		if (rc != 0)
			return rc > 0 ? 0 : rc;
	}

	down_write(&com->lc_sem);
	if (init) {
		lo->ll_pos_latest_start =
				lfsck->li_pos_checkpoint.lp_oit_cookie;
	} else {
		lo->ll_pos_last_checkpoint =
				lfsck->li_pos_checkpoint.lp_oit_cookie;
		lo->ll_run_time_phase1 += ktime_get_seconds() -
					  lfsck->li_time_last_checkpoint;
		lo->ll_time_last_checkpoint = ktime_get_real_seconds();
		lo->ll_objs_checked_phase1 += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_layout_store(env, com);
	up_write(&com->lc_sem);

	CDEBUG(D_LFSCK, "%s: layout LFSCK master checkpoint at the pos ["
	       "%llu], status = %d: rc = %d\n", lfsck_lfsck2name(lfsck),
	       lfsck->li_pos_current.lp_oit_cookie, lo->ll_status, rc);

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
		lo->ll_pos_latest_start =
				lfsck->li_pos_checkpoint.lp_oit_cookie;
	} else {
		lo->ll_pos_last_checkpoint =
				lfsck->li_pos_checkpoint.lp_oit_cookie;
		lo->ll_run_time_phase1 += ktime_get_seconds() -
					  lfsck->li_time_last_checkpoint;
		lo->ll_time_last_checkpoint = ktime_get_real_seconds();
		lo->ll_objs_checked_phase1 += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_layout_store(env, com);
	up_write(&com->lc_sem);

	CDEBUG(D_LFSCK, "%s: layout LFSCK slave checkpoint at the pos ["
	       "%llu], status = %d: rc = %d\n", lfsck_lfsck2name(lfsck),
	       lfsck->li_pos_current.lp_oit_cookie, lo->ll_status, rc);

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
	    (start != NULL && start->ls_flags & LPF_OST_ORPHAN)) {
		int rc;

		rc = lfsck_layout_reset(env, com, false);
		if (rc == 0)
			rc = lfsck_set_param(env, lfsck, start, true);

		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: layout LFSCK prep failed: "
			       "rc = %d\n", lfsck_lfsck2name(lfsck), rc);

			return rc;
		}
	}

	down_write(&com->lc_sem);
	lo->ll_time_latest_start = ktime_get_real_seconds();
	spin_lock(&lfsck->li_lock);
	if (lo->ll_flags & LF_SCANNED_ONCE) {
		if (!lfsck->li_drop_dryrun ||
		    lo->ll_pos_first_inconsistent == 0) {
			lo->ll_status = LS_SCANNING_PHASE2;
			list_move_tail(&com->lc_link,
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
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_layout		*lo	= com->lc_file_ram;
	struct lfsck_start		*start  = lsp->lsp_start;
	int				 rc;

	rc = lfsck_layout_prep(env, com, start);
	if (rc != 0)
		return rc;

	if (lo->ll_flags & LF_CRASHED_LASTID &&
	    list_empty(&llsd->llsd_master_list)) {
		LASSERT(lfsck->li_out_notify != NULL);

		lfsck->li_out_notify(env, lfsck->li_out_notify_data,
				     LE_LASTID_REBUILDING);
	}

	if (!lsp->lsp_index_valid)
		return 0;

	rc = lfsck_layout_llst_add(llsd, lsp->lsp_index);
	if (rc == 0 && start != NULL && start->ls_flags & LPF_OST_ORPHAN) {
		LASSERT(!llsd->llsd_rbtree_valid);

		down_write(&llsd->llsd_rb_rwsem);
		rc = lfsck_rbtree_setup(env, com);
		up_write(&llsd->llsd_rb_rwsem);
	}

	CDEBUG(D_LFSCK, "%s: layout LFSCK slave prep done, start pos ["
	       "%llu]\n", lfsck_lfsck2name(lfsck),
	       com->lc_pos_start.lp_oit_cookie);

	return rc;
}

static int lfsck_layout_master_prep(const struct lu_env *env,
				    struct lfsck_component *com,
				    struct lfsck_start_param *lsp)
{
	int rc;
	ENTRY;

	rc = lfsck_layout_load_bitmap(env, com);
	if (rc != 0) {
		rc = lfsck_layout_reset(env, com, false);
		if (rc == 0)
			rc = lfsck_set_param(env, com->lc_lfsck,
					     lsp->lsp_start, true);

		if (rc != 0)
			GOTO(log, rc);
	}

	rc = lfsck_layout_prep(env, com, lsp->lsp_start);
	if (rc != 0)
		RETURN(rc);

	rc = lfsck_start_assistant(env, com, lsp);

	GOTO(log, rc);

log:
	CDEBUG(D_LFSCK, "%s: layout LFSCK master prep done, start pos ["
	       "%llu]\n", lfsck_lfsck2name(com->lc_lfsck),
	       com->lc_pos_start.lp_oit_cookie);

	return 0;
}

/* Pre-fetch the attribute for each stripe in the given layout EA. */
static int lfsck_layout_scan_stripes(const struct lu_env *env,
				     struct lfsck_component *com,
				     struct dt_object *parent,
				     struct lov_mds_md_v1 *lmm, __u32 comp_id)
{
	struct lfsck_thread_info	*info	 = lfsck_env_info(env);
	struct lfsck_instance		*lfsck	 = com->lc_lfsck;
	struct lfsck_bookmark		*bk	 = &lfsck->li_bookmark_ram;
	struct lfsck_layout		*lo	 = com->lc_file_ram;
	struct lfsck_assistant_data	*lad	 = com->lc_data;
	struct lfsck_assistant_object	*lso	 = NULL;
	struct lov_ost_data_v1		*objs;
	struct lfsck_tgt_descs		*ltds	 = &lfsck->li_ost_descs;
	struct ptlrpc_thread		*mthread = &lfsck->li_thread;
	struct ptlrpc_thread		*athread = &lad->lad_thread;
	struct lu_buf			 buf;
	int				 rc	 = 0;
	int				 i;
	__u32				 magic;
	__u16				 count;
	ENTRY;

	lfsck_buf_init(&buf, &info->lti_ff, sizeof(struct filter_fid));
	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic == LOV_MAGIC_V1) {
		objs = &lmm->lmm_objects[0];
	} else {
		LASSERT(magic == LOV_MAGIC_V3);
		objs = &((struct lov_mds_md_v3 *)lmm)->lmm_objects[0];
	}

	count = le16_to_cpu(lmm->lmm_stripe_count);
	for (i = 0; i < count; i++, objs++) {
		struct lu_fid		*fid	= &info->lti_fid;
		struct ost_id		*oi	= &info->lti_oi;
		struct lfsck_layout_req *llr;
		struct lfsck_tgt_desc	*tgt	= NULL;
		struct dt_object	*cobj	= NULL;
		__u32			 index;
		bool			 wakeup = false;

		if (unlikely(lovea_slot_is_dummy(objs)))
			continue;

		wait_event_idle(mthread->t_ctl_waitq,
				lad->lad_prefetched < bk->lb_async_windows ||
				!thread_is_running(mthread) ||
				thread_is_stopped(athread));

		if (unlikely(!thread_is_running(mthread)) ||
			     thread_is_stopped(athread))
			GOTO(out, rc = 0);

		if (unlikely(lfsck_is_dead_obj(parent)))
			GOTO(out, rc = 0);

		ostid_le_to_cpu(&objs->l_ost_oi, oi);
		index = le32_to_cpu(objs->l_ost_idx);
		rc = ostid_to_fid(fid, oi, index);
		if (rc != 0) {
			CDEBUG(D_LFSCK, "%s: get invalid layout EA for "DFID
			       ": "DOSTID", idx %u, comp_id %u\n",
			       lfsck_lfsck2name(lfsck),
			       PFID(lfsck_dto2fid(parent)), POSTID(oi),
			       index, comp_id);
			goto next;
		}

		tgt = lfsck_tgt_get(ltds, index);
		if (unlikely(tgt == NULL)) {
			CDEBUG(D_LFSCK, "%s: cannot talk with OST %x which "
			       "did not join the layout LFSCK, comp_id %u\n",
			       lfsck_lfsck2name(lfsck), index, comp_id);
			lfsck_lad_set_bitmap(env, com, index);
			goto next;
		}

		/* There is potential deadlock race condition between object
		 * destroy and layout LFSCK. Consider the following scenario:
		 *
		 * 1) The LFSCK thread obtained the parent object firstly, at
		 *    that time, the parent object has not been destroyed yet.
		 *
		 * 2) One RPC service thread destroyed the parent and all its
		 *    children objects. Because the LFSCK is referencing the
		 *    parent object, then the parent object will be marked as
		 *    dying in RAM. On the other hand, the parent object is
		 *    referencing all its children objects, then all children
		 *    objects will be marked as dying in RAM also.
		 *
		 * 3) The LFSCK thread tries to find some child object with
		 *    the parent object referenced. Then it will find that the
		 *    child object is dying. According to the object visibility
		 *    rules: the object with dying flag cannot be returned to
		 *    others. So the LFSCK thread has to wait until the dying
		 *    object has been purged from RAM, then it can allocate a
		 *    new object (with the same FID) in RAM. Unfortunately, the
		 *    LFSCK thread itself is referencing the parent object, and
		 *    cause the parent object cannot be purged, then cause the
		 *    child object cannot be purged also. So the LFSCK thread
		 *    will fall into deadlock.
		 */
		cobj = lfsck_object_find_by_dev(env, tgt->ltd_tgt, fid);
		if (IS_ERR(cobj)) {
			if (lfsck_is_dead_obj(parent)) {
				lfsck_tgt_put(tgt);

				GOTO(out, rc = 0);
			}

			rc = PTR_ERR(cobj);
			goto next;
		}

		rc = dt_declare_attr_get(env, cobj);
		if (rc)
			goto next;

		rc = dt_declare_xattr_get(env, cobj, &buf, XATTR_NAME_FID);
		if (rc)
			goto next;

		if (lso == NULL) {
			struct lu_attr *attr = &info->lti_la;

			rc = dt_attr_get(env, parent, attr);
			if (rc != 0)
				goto next;

			lso = lfsck_assistant_object_init(env,
				lfsck_dto2fid(parent), attr,
				lfsck->li_pos_current.lp_oit_cookie, false);
			if (IS_ERR(lso)) {
				rc = PTR_ERR(lso);
				lso = NULL;

				goto next;
			}
		}

		llr = lfsck_layout_assistant_req_init(lso, cobj, comp_id,
						      index, i);
		if (IS_ERR(llr)) {
			rc = PTR_ERR(llr);
			goto next;
		}

		cobj = NULL;
		spin_lock(&lad->lad_lock);
		if (lad->lad_assistant_status < 0) {
			spin_unlock(&lad->lad_lock);
			lfsck_layout_assistant_req_fini(env, &llr->llr_lar);
			lfsck_tgt_put(tgt);
			RETURN(lad->lad_assistant_status);
		}

		list_add_tail(&llr->llr_lar.lar_list, &lad->lad_req_list);
		if (lad->lad_prefetched == 0)
			wakeup = true;

		lad->lad_prefetched++;
		spin_unlock(&lad->lad_lock);
		if (wakeup)
			wake_up(&athread->t_ctl_waitq);

next:
		down_write(&com->lc_sem);
		com->lc_new_checked++;
		if (rc < 0)
			lfsck_layout_record_failure(env, lfsck, lo);
		up_write(&com->lc_sem);

		if (cobj != NULL && !IS_ERR(cobj))
			lfsck_object_put(env, cobj);

		if (likely(tgt != NULL))
			lfsck_tgt_put(tgt);

		if (rc < 0 && bk->lb_param & LPF_FAILOUT)
			GOTO(out, rc);
	}

	GOTO(out, rc = 0);

out:
	if (lso != NULL)
		lfsck_assistant_object_put(env, lso);

	return rc;
}

/* For the given object, read its layout EA locally. For each stripe, pre-fetch
 * the OST-object's attribute and generate an structure lfsck_layout_req on the
 * list ::lad_req_list.
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
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_bookmark		*bk	= &lfsck->li_bookmark_ram;
	struct thandle			*handle = NULL;
	struct lu_buf			*buf	= &info->lti_big_buf;
	struct lov_mds_md_v1		*lmm	= NULL;
	struct dt_device		*dev	= lfsck_obj2dev(obj);
	struct lustre_handle		 lh	= { 0 };
	struct lu_buf			 ea_buf = { NULL };
	struct lov_comp_md_v1		*lcm	= NULL;
	struct lov_comp_md_entry_v1	*lcme	= NULL;
	int				 rc	= 0;
	int				 size	= 0;
	__u32				 magic	= 0;
	__u16				 count	= 0;
	bool				 locked	= false;
	bool				 stripe = false;
	bool				 bad_oi = false;
	ENTRY;

	if (!S_ISREG(lfsck_object_type(obj)))
		GOTO(out, rc = 0);

	if (lad->lad_assistant_status < 0)
		GOTO(out, rc = -ESRCH);

	fid_to_lmm_oi(lfsck_dto2fid(obj), oi);
	lmm_oi_cpu_to_le(oi, oi);
	dt_read_lock(env, obj, 0);
	locked = true;

again:
	bad_oi = false;
	if (dt_object_exists(obj) == 0 ||
	    lfsck_is_dead_obj(obj))
		GOTO(out, rc = 0);

	rc = lfsck_layout_get_lovea(env, obj, buf);
	if (rc == -EINVAL || rc == -ENODATA || rc == -EOPNOTSUPP)
		/* Skip bad lov EA during the 1st cycle scanning, and
		 * try to recover it via orphan in the 2nd scanning. */
		rc = 0;
	if (rc <= 0)
		GOTO(out, rc);

	size = rc;
	lmm = buf->lb_buf;
	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
		struct lov_mds_md_v1 *v1;
		int i;

		lcm = buf->lb_buf;
		count = le16_to_cpu(lcm->lcm_entry_count);
		for (i = 0; i < count; i++) {
			lcme = &lcm->lcm_entries[i];
			v1 = buf->lb_buf + le32_to_cpu(lcme->lcme_offset);
			if (memcmp(oi, &v1->lmm_oi, sizeof(*oi)) != 0)
				goto fix;
		}

		GOTO(out, stripe = true);
	} else if (memcmp(oi, &lmm->lmm_oi, sizeof(*oi)) == 0) {
		GOTO(out, stripe = true);
	}

fix:
	/* Inconsistent lmm_oi, should be repaired. */
	bad_oi = true;

	if (bk->lb_param & LPF_DRYRUN) {
		lo->ll_objs_repaired[LLIT_OTHERS - 1]++;

		GOTO(out, stripe = true);
	}

	if (!lustre_handle_is_used(&lh)) {
		dt_read_unlock(env, obj);
		locked = false;
		rc = lfsck_ibits_lock(env, lfsck, obj, &lh,
				      MDS_INODELOCK_LAYOUT |
				      MDS_INODELOCK_XATTR, LCK_EX);
		if (rc != 0)
			GOTO(out, rc);

		handle = dt_trans_create(env, dev);
		if (IS_ERR(handle))
			GOTO(out, rc = PTR_ERR(handle));

		lfsck_buf_init(&ea_buf, buf->lb_buf, size);
		rc = dt_declare_xattr_set(env, obj, &ea_buf, XATTR_NAME_LOV,
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

	if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
		struct lov_mds_md_v1 *v1;
		int i;

		for (i = 0; i < count; i++) {
			lcme = &lcm->lcm_entries[i];
			v1 = buf->lb_buf + le32_to_cpu(lcme->lcme_offset);
			v1->lmm_oi = *oi;
		}
	} else {
		lmm->lmm_oi = *oi;
	}

	rc = dt_xattr_set(env, obj, &ea_buf, XATTR_NAME_LOV,
			  LU_XATTR_REPLACE, handle);
	if (rc != 0)
		GOTO(out, rc);

	lo->ll_objs_repaired[LLIT_OTHERS - 1]++;

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

	lfsck_ibits_unlock(&lh, LCK_EX);

	if (bad_oi)
		CDEBUG(D_LFSCK, "%s: layout LFSCK master %s bad lmm_oi for "
		       DFID": rc = %d\n", lfsck_lfsck2name(lfsck),
		       bk->lb_param & LPF_DRYRUN ? "found" : "repaired",
		       PFID(lfsck_dto2fid(obj)), rc);

	if (stripe) {
		if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
			int i;

			for (i = 0; i < count; i++) {
				lcme = &lcm->lcm_entries[i];
				if (!(le32_to_cpu(lcme->lcme_flags) &
				      LCME_FL_INIT))
					continue;

				rc = lfsck_layout_scan_stripes(env, com, obj,
					(struct lov_mds_md_v1 *)(buf->lb_buf +
					le32_to_cpu(lcme->lcme_offset)),
					le32_to_cpu(lcme->lcme_id));
			}
		} else {
			rc = lfsck_layout_scan_stripes(env, com, obj, lmm, 0);
		}
	} else {
		down_write(&com->lc_sem);
		com->lc_new_checked++;
		if (rc < 0)
			lfsck_layout_record_failure(env, lfsck, lo);
		up_write(&com->lc_sem);
	}

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

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_DELAY5) &&
	    cfs_fail_val == lfsck_dev_idx(lfsck)) {
		struct ptlrpc_thread	*thread = &lfsck->li_thread;

		wait_event_idle_timeout(thread->t_ctl_waitq,
					!thread_is_running(thread),
					cfs_time_seconds(1));
	}

	lfsck_rbtree_update_bitmap(env, com, fid, false);

	down_write(&com->lc_sem);
	if (fid_is_idif(fid))
		seq = 0;
	else if (!fid_is_norm(fid) ||
		 !fid_is_for_ostobj(env, lfsck, obj, fid))
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
			CDEBUG(D_LFSCK, "%s: layout LFSCK failed to "
			      "load LAST_ID for %#llx: rc = %d\n",
			      lfsck_lfsck2name(com->lc_lfsck), seq, rc);
			lo->ll_objs_failed_phase1++;
			OBD_FREE_PTR(lls);
			GOTO(unlock, rc);
		}

		lfsck_layout_seq_insert(llsd, lls);
	}

	if (unlikely(fid_is_last_id(fid)))
		GOTO(unlock, rc = 0);

	if (fid_is_idif(fid))
		oid = fid_idif_id(fid_seq(fid), fid_oid(fid), fid_ver(fid));
	else
		oid = fid_oid(fid);

	if (oid > lls->lls_lastid_known)
		lls->lls_lastid_known = oid;

	if (oid > lls->lls_lastid) {
		if (!(lo->ll_flags & LF_CRASHED_LASTID)) {
			/* OFD may create new objects during LFSCK scanning. */
			rc = lfsck_layout_lastid_reload(env, com, lls);
			if (unlikely(rc != 0)) {
				CDEBUG(D_LFSCK, "%s: layout LFSCK failed to "
				      "reload LAST_ID for %#llx: rc = %d\n",
				      lfsck_lfsck2name(com->lc_lfsck),
				      lls->lls_seq, rc);

				GOTO(unlock, rc);
			}

			if (oid <= lls->lls_lastid ||
			    lo->ll_flags & LF_CRASHED_LASTID)
				GOTO(unlock, rc = 0);

			LASSERT(lfsck->li_out_notify != NULL);

			lfsck->li_out_notify(env, lfsck->li_out_notify_data,
					     LE_LASTID_REBUILDING);
			lo->ll_flags |= LF_CRASHED_LASTID;

			CDEBUG(D_LFSCK, "%s: layout LFSCK finds crashed "
			       "LAST_ID file (2) for the sequence %#llx"
			       ", old value %llu, known value %llu\n",
			       lfsck_lfsck2name(lfsck), lls->lls_seq,
			       lls->lls_lastid, oid);
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
				 struct lfsck_assistant_object *lso,
				 struct lu_dirent *ent, __u16 type)
{
	return 0;
}

static int lfsck_layout_master_post(const struct lu_env *env,
				    struct lfsck_component *com,
				    int result, bool init)
{
	struct lfsck_instance	*lfsck	= com->lc_lfsck;
	struct lfsck_layout	*lo	= com->lc_file_ram;
	int			 rc;
	ENTRY;

	lfsck_post_generic(env, com, &result);

	down_write(&com->lc_sem);
	spin_lock(&lfsck->li_lock);
	if (!init)
		lo->ll_pos_last_checkpoint =
				lfsck->li_pos_checkpoint.lp_oit_cookie;

	if (result > 0) {
		if (lo->ll_flags & LF_INCOMPLETE)
			lo->ll_status = LS_PARTIAL;
		else
			lo->ll_status = LS_SCANNING_PHASE2;
		lo->ll_flags |= LF_SCANNED_ONCE;
		lo->ll_flags &= ~LF_UPGRADE;
		list_move_tail(&com->lc_link, &lfsck->li_list_double_scan);
	} else if (result == 0) {
		if (lfsck->li_status != 0)
			lo->ll_status = lfsck->li_status;
		else
			lo->ll_status = LS_STOPPED;
		if (lo->ll_status != LS_PAUSED)
			list_move_tail(&com->lc_link, &lfsck->li_list_idle);
	} else {
		lo->ll_status = LS_FAILED;
		list_move_tail(&com->lc_link, &lfsck->li_list_idle);
	}
	spin_unlock(&lfsck->li_lock);

	if (!init) {
		lo->ll_run_time_phase1 += ktime_get_seconds() -
					  lfsck->li_time_last_checkpoint;
		lo->ll_time_last_checkpoint = ktime_get_real_seconds();
		lo->ll_objs_checked_phase1 += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_layout_store(env, com);
	up_write(&com->lc_sem);

	CDEBUG(D_LFSCK, "%s: layout LFSCK master post done: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc);

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

	down_write(&com->lc_sem);
	rc = lfsck_layout_lastid_store(env, com);
	if (rc != 0)
		result = rc;

	LASSERT(lfsck->li_out_notify != NULL);

	spin_lock(&lfsck->li_lock);
	if (!init)
		lo->ll_pos_last_checkpoint =
				lfsck->li_pos_checkpoint.lp_oit_cookie;

	if (result > 0) {
		lo->ll_status = LS_SCANNING_PHASE2;
		lo->ll_flags |= LF_SCANNED_ONCE;
		if (lo->ll_flags & LF_CRASHED_LASTID) {
			done = true;
			lo->ll_flags &= ~LF_CRASHED_LASTID;

			CDEBUG(D_LFSCK, "%s: layout LFSCK has rebuilt "
			       "crashed LAST_ID files successfully\n",
			       lfsck_lfsck2name(lfsck));
		}
		lo->ll_flags &= ~LF_UPGRADE;
		list_move_tail(&com->lc_link, &lfsck->li_list_double_scan);
	} else if (result == 0) {
		if (lfsck->li_status != 0)
			lo->ll_status = lfsck->li_status;
		else
			lo->ll_status = LS_STOPPED;
		if (lo->ll_status != LS_PAUSED)
			list_move_tail(&com->lc_link, &lfsck->li_list_idle);
	} else {
		lo->ll_status = LS_FAILED;
		list_move_tail(&com->lc_link, &lfsck->li_list_idle);
	}
	spin_unlock(&lfsck->li_lock);

	if (done)
		lfsck->li_out_notify(env, lfsck->li_out_notify_data,
				     LE_LASTID_REBUILT);

	if (!init) {
		lo->ll_run_time_phase1 += ktime_get_seconds() -
					  lfsck->li_time_last_checkpoint;
		lo->ll_time_last_checkpoint = ktime_get_real_seconds();
		lo->ll_objs_checked_phase1 += com->lc_new_checked;
		com->lc_new_checked = 0;
	}

	rc = lfsck_layout_store(env, com);
	up_write(&com->lc_sem);

	lfsck_layout_slave_notify_master(env, com, LE_PHASE1_DONE, result);

	CDEBUG(D_LFSCK, "%s: layout LFSCK slave post done: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc);

	return rc;
}

static void lfsck_layout_dump(const struct lu_env *env,
			      struct lfsck_component *com, struct seq_file *m)
{
	struct lfsck_instance	*lfsck = com->lc_lfsck;
	struct lfsck_bookmark	*bk    = &lfsck->li_bookmark_ram;
	struct lfsck_layout	*lo    = com->lc_file_ram;
	const char *prefix;

	down_read(&com->lc_sem);
	if (bk->lb_param & LPF_DRYRUN)
		prefix = "inconsistent";
	else
		prefix = "repaired";

	seq_printf(m, "name: lfsck_layout\n"
		   "magic: %#x\n"
		   "version: %d\n"
		   "status: %s\n",
		   lo->ll_magic,
		   bk->lb_version,
		   lfsck_status2name(lo->ll_status));

	lfsck_bits_dump(m, lo->ll_flags, lfsck_flags_names, "flags");

	lfsck_bits_dump(m, bk->lb_param, lfsck_param_names, "param");

	lfsck_time_dump(m, lo->ll_time_last_complete, "last_completed");

	lfsck_time_dump(m, lo->ll_time_latest_start, "latest_start");

	lfsck_time_dump(m, lo->ll_time_last_checkpoint, "last_checkpoint");

	seq_printf(m, "latest_start_position: %llu\n"
		   "last_checkpoint_position: %llu\n"
		   "first_failure_position: %llu\n",
		   lo->ll_pos_latest_start,
		   lo->ll_pos_last_checkpoint,
		   lo->ll_pos_first_inconsistent);

	seq_printf(m, "success_count: %u\n"
		   "%s_dangling: %llu\n"
		   "%s_unmatched_pair: %llu\n"
		   "%s_multiple_referenced: %llu\n"
		   "%s_orphan: %llu\n"
		   "%s_inconsistent_owner: %llu\n"
		   "%s_others: %llu\n"
		   "skipped: %llu\n"
		   "failed_phase1: %llu\n"
		   "failed_phase2: %llu\n",
		   lo->ll_success_count,
		   prefix, lo->ll_objs_repaired[LLIT_DANGLING - 1],
		   prefix, lo->ll_objs_repaired[LLIT_UNMATCHED_PAIR - 1],
		   prefix, lo->ll_objs_repaired[LLIT_MULTIPLE_REFERENCED - 1],
		   prefix, lo->ll_objs_repaired[LLIT_ORPHAN - 1],
		   prefix, lo->ll_objs_repaired[LLIT_INCONSISTENT_OWNER - 1],
		   prefix, lo->ll_objs_repaired[LLIT_OTHERS - 1],
		   lo->ll_objs_skipped,
		   lo->ll_objs_failed_phase1,
		   lo->ll_objs_failed_phase2);

	if (lo->ll_status == LS_SCANNING_PHASE1) {
		time64_t duration = ktime_get_seconds() -
				    lfsck->li_time_last_checkpoint;
		u64 checked = lo->ll_objs_checked_phase1 +
			      com->lc_new_checked;
		u64 speed = checked;
		u64 new_checked = com->lc_new_checked;
		time64_t rtime = lo->ll_run_time_phase1 + duration;
		u64 pos;

		if (duration != 0)
			new_checked = div64_s64(new_checked, duration);
		if (rtime != 0)
			speed = div64_s64(speed, rtime);
		seq_printf(m, "checked_phase1: %llu\n"
			   "checked_phase2: %llu\n"
			   "run_time_phase1: %lld seconds\n"
			   "run_time_phase2: %lld seconds\n"
			   "average_speed_phase1: %llu items/sec\n"
			   "average_speed_phase2: N/A\n"
			   "real_time_speed_phase1: %llu items/sec\n"
			   "real_time_speed_phase2: N/A\n",
			   checked,
			   lo->ll_objs_checked_phase2,
			   rtime,
			   lo->ll_run_time_phase2,
			   speed,
			   new_checked);

		if (likely(lfsck->li_di_oit)) {
			const struct dt_it_ops *iops =
				&lfsck->li_obj_oit->do_index_ops->dio_it;

			/* The low layer otable-based iteration position may NOT
			 * exactly match the layout-based directory traversal
			 * cookie. Generally, it is not a serious issue. But the
			 * caller should NOT make assumption on that. */
			pos = iops->store(env, lfsck->li_di_oit);
			if (!lfsck->li_current_oit_processed)
				pos--;
		} else {
			pos = lo->ll_pos_last_checkpoint;
		}

		seq_printf(m, "current_position: %llu\n", pos);
	} else if (lo->ll_status == LS_SCANNING_PHASE2) {
		time64_t duration = ktime_get_seconds() -
				    com->lc_time_last_checkpoint;
		u64 checked = lo->ll_objs_checked_phase2 +
			      com->lc_new_checked;
		u64 speed1 = lo->ll_objs_checked_phase1;
		u64 speed2 = checked;
		u64 new_checked = com->lc_new_checked;
		time64_t rtime = lo->ll_run_time_phase2 + duration;

		if (duration != 0)
			new_checked = div64_s64(new_checked, duration);
		if (lo->ll_run_time_phase1 != 0)
			speed1 = div64_s64(speed1, lo->ll_run_time_phase1);
		if (rtime != 0)
			speed2 = div64_s64(speed2, rtime);
		seq_printf(m, "checked_phase1: %llu\n"
			   "checked_phase2: %llu\n"
			   "run_time_phase1: %lld seconds\n"
			   "run_time_phase2: %lld seconds\n"
			   "average_speed_phase1: %llu items/sec\n"
			   "average_speed_phase2: %llu items/sec\n"
			   "real_time_speed_phase1: N/A\n"
			   "real_time_speed_phase2: %llu items/sec\n"
			   "current_position: "DFID"\n",
			   lo->ll_objs_checked_phase1,
			   checked,
			   lo->ll_run_time_phase1,
			   rtime,
			   speed1,
			   speed2,
			   new_checked,
			   PFID(&com->lc_fid_latest_scanned_phase2));
	} else {
		__u64 speed1 = lo->ll_objs_checked_phase1;
		__u64 speed2 = lo->ll_objs_checked_phase2;

		if (lo->ll_run_time_phase1 != 0)
			speed1 = div64_s64(speed1, lo->ll_run_time_phase1);
		if (lo->ll_run_time_phase2 != 0)
			speed2 = div64_s64(speed2, lo->ll_run_time_phase2);
		seq_printf(m, "checked_phase1: %llu\n"
			   "checked_phase2: %llu\n"
			   "run_time_phase1: %lld seconds\n"
			   "run_time_phase2: %lld seconds\n"
			   "average_speed_phase1: %llu items/sec\n"
			   "average_speed_phase2: %llu objs/sec\n"
			   "real_time_speed_phase1: N/A\n"
			   "real_time_speed_phase2: N/A\n"
			   "current_position: N/A\n",
			   lo->ll_objs_checked_phase1,
			   lo->ll_objs_checked_phase2,
			   lo->ll_run_time_phase1,
			   lo->ll_run_time_phase2,
			   speed1,
			   speed2);
	}

	up_read(&com->lc_sem);
}

static int lfsck_layout_master_double_scan(const struct lu_env *env,
					   struct lfsck_component *com)
{
	struct lfsck_layout		*lo	= com->lc_file_ram;
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_tgt_descs		*ltds;
	struct lfsck_tgt_desc		*ltd;
	struct lfsck_tgt_desc		*next;
	int				 rc;

	rc = lfsck_double_scan_generic(env, com, lo->ll_status);

	if (thread_is_stopped(&lad->lad_thread)) {
		LASSERT(list_empty(&lad->lad_req_list));
		LASSERT(list_empty(&lad->lad_ost_phase1_list));
		LASSERT(list_empty(&lad->lad_mdt_phase1_list));

		ltds = &lfsck->li_ost_descs;
		spin_lock(&ltds->ltd_lock);
		list_for_each_entry_safe(ltd, next, &lad->lad_ost_phase2_list,
					 ltd_layout_phase_list) {
			list_del_init(&ltd->ltd_layout_phase_list);
		}
		spin_unlock(&ltds->ltd_lock);

		ltds = &lfsck->li_mdt_descs;
		spin_lock(&ltds->ltd_lock);
		list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase2_list,
					 ltd_layout_phase_list) {
			list_del_init(&ltd->ltd_layout_phase_list);
		}
		spin_unlock(&ltds->ltd_lock);
	}

	return rc;
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

	CDEBUG(D_LFSCK, "%s: layout LFSCK slave phase2 scan start\n",
	       lfsck_lfsck2name(lfsck));

	atomic_inc(&lfsck->li_double_scan_count);

	if (lo->ll_flags & LF_INCOMPLETE)
		GOTO(done, rc = 1);

	com->lc_new_checked = 0;
	com->lc_new_scanned = 0;
	com->lc_time_last_checkpoint = ktime_get_seconds();
	com->lc_time_next_checkpoint = com->lc_time_last_checkpoint +
				       LFSCK_CHECKPOINT_INTERVAL;

	while (1) {
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

		rc = wait_event_idle_timeout(
			thread->t_ctl_waitq,
			!thread_is_running(thread) ||
			lo->ll_flags & LF_INCOMPLETE ||
			list_empty(&llsd->llsd_master_list),
			cfs_time_seconds(30));
		if (unlikely(!thread_is_running(thread)))
			GOTO(done, rc = 0);

		if (lo->ll_flags & LF_INCOMPLETE)
			GOTO(done, rc = 1);

		if (rc == 0)
			continue;

		GOTO(done, rc = 1);
	}

done:
	rc = lfsck_layout_double_scan_result(env, com, rc);
	lfsck_layout_slave_notify_master(env, com, LE_PHASE2_DONE,
			(rc > 0 && lo->ll_flags & LF_INCOMPLETE) ? 0 : rc);
	lfsck_layout_slave_quit(env, com);
	if (atomic_dec_and_test(&lfsck->li_double_scan_count))
		wake_up(&lfsck->li_thread.t_ctl_waitq);

	CDEBUG(D_LFSCK, "%s: layout LFSCK slave phase2 scan finished, "
	       "status %d: rc = %d\n",
	       lfsck_lfsck2name(lfsck), lo->ll_status, rc);

	return rc;
}

static void lfsck_layout_master_data_release(const struct lu_env *env,
					     struct lfsck_component *com)
{
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_tgt_descs		*ltds;
	struct lfsck_tgt_desc		*ltd;
	struct lfsck_tgt_desc		*next;

	LASSERT(lad != NULL);
	LASSERT(thread_is_init(&lad->lad_thread) ||
		thread_is_stopped(&lad->lad_thread));
	LASSERT(list_empty(&lad->lad_req_list));

	com->lc_data = NULL;

	ltds = &lfsck->li_ost_descs;
	spin_lock(&ltds->ltd_lock);
	list_for_each_entry_safe(ltd, next, &lad->lad_ost_phase1_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &lad->lad_ost_phase2_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &lad->lad_ost_list,
				 ltd_layout_list) {
		list_del_init(&ltd->ltd_layout_list);
	}
	spin_unlock(&ltds->ltd_lock);

	ltds = &lfsck->li_mdt_descs;
	spin_lock(&ltds->ltd_lock);
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase1_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase2_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_list,
				 ltd_layout_list) {
		list_del_init(&ltd->ltd_layout_list);
	}
	spin_unlock(&ltds->ltd_lock);

	if (likely(lad->lad_bitmap != NULL))
		CFS_FREE_BITMAP(lad->lad_bitmap);

	OBD_FREE_PTR(lad);
}

static void lfsck_layout_slave_data_release(const struct lu_env *env,
					    struct lfsck_component *com)
{
	struct lfsck_layout_slave_data *llsd = com->lc_data;

	lfsck_layout_slave_quit(env, com);
	com->lc_data = NULL;
	OBD_FREE_PTR(llsd);
}

static void lfsck_layout_master_quit(const struct lu_env *env,
				     struct lfsck_component *com)
{
	struct lfsck_assistant_data	*lad	= com->lc_data;
	struct lfsck_instance		*lfsck	= com->lc_lfsck;
	struct lfsck_tgt_descs		*ltds;
	struct lfsck_tgt_desc		*ltd;
	struct lfsck_tgt_desc		*next;

	LASSERT(lad != NULL);

	lfsck_quit_generic(env, com);

	LASSERT(thread_is_init(&lad->lad_thread) ||
		thread_is_stopped(&lad->lad_thread));
	LASSERT(list_empty(&lad->lad_req_list));

	ltds = &lfsck->li_ost_descs;
	spin_lock(&ltds->ltd_lock);
	list_for_each_entry_safe(ltd, next, &lad->lad_ost_phase1_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &lad->lad_ost_phase2_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	spin_unlock(&ltds->ltd_lock);

	ltds = &lfsck->li_mdt_descs;
	spin_lock(&ltds->ltd_lock);
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase1_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	list_for_each_entry_safe(ltd, next, &lad->lad_mdt_phase2_list,
				 ltd_layout_phase_list) {
		list_del_init(&ltd->ltd_layout_phase_list);
	}
	spin_unlock(&ltds->ltd_lock);
}

static void lfsck_layout_slave_quit(const struct lu_env *env,
				    struct lfsck_component *com)
{
	struct lfsck_layout_slave_data	 *llsd	= com->lc_data;
	struct lfsck_layout_seq		 *lls;
	struct lfsck_layout_seq		 *next;
	struct lfsck_layout_slave_target *llst;

	LASSERT(llsd != NULL);

	down_write(&com->lc_sem);
	list_for_each_entry_safe(lls, next, &llsd->llsd_seq_list,
				 lls_list) {
		list_del_init(&lls->lls_list);
		lfsck_object_put(env, lls->lls_lastid_obj);
		OBD_FREE_PTR(lls);
	}
	up_write(&com->lc_sem);

	spin_lock(&llsd->llsd_lock);
	while (!list_empty(&llsd->llsd_master_list)) {
		llst = list_entry(llsd->llsd_master_list.next,
				  struct lfsck_layout_slave_target, llst_list);
		list_del_init(&llst->llst_list);
		spin_unlock(&llsd->llsd_lock);
		lfsck_layout_llst_put(llst);
		spin_lock(&llsd->llsd_lock);
	}
	spin_unlock(&llsd->llsd_lock);

	lfsck_rbtree_cleanup(env, com);
}

static int lfsck_layout_master_in_notify(const struct lu_env *env,
					 struct lfsck_component *com,
					 struct lfsck_request *lr)
{
	struct lfsck_instance		*lfsck = com->lc_lfsck;
	struct lfsck_layout		*lo    = com->lc_file_ram;
	struct lfsck_assistant_data	*lad   = com->lc_data;
	struct lfsck_tgt_descs		*ltds;
	struct lfsck_tgt_desc		*ltd;
	bool				 fail  = false;
	ENTRY;

	if (lr->lr_event == LE_PAIRS_VERIFY) {
		int rc;

		rc = lfsck_layout_master_check_pairs(env, com, &lr->lr_fid,
						     &lr->lr_fid2,
						     lr->lr_comp_id);

		RETURN(rc);
	}

	CDEBUG(D_LFSCK, "%s: layout LFSCK master handles notify %u "
	       "from %s %x, status %d, flags %x, flags2 %x\n",
	       lfsck_lfsck2name(lfsck), lr->lr_event,
	       (lr->lr_flags & LEF_FROM_OST) ? "OST" : "MDT",
	       lr->lr_index, lr->lr_status, lr->lr_flags, lr->lr_flags2);

	if (lr->lr_event != LE_PHASE1_DONE &&
	    lr->lr_event != LE_PHASE2_DONE &&
	    lr->lr_event != LE_PEER_EXIT)
		RETURN(-EINVAL);

	if (lr->lr_flags & LEF_FROM_OST)
		ltds = &lfsck->li_ost_descs;
	else
		ltds = &lfsck->li_mdt_descs;
	spin_lock(&ltds->ltd_lock);
	ltd = lfsck_ltd2tgt(ltds, lr->lr_index);
	if (ltd == NULL) {
		spin_unlock(&ltds->ltd_lock);

		RETURN(-ENXIO);
	}

	list_del_init(&ltd->ltd_layout_phase_list);
	switch (lr->lr_event) {
	case LE_PHASE1_DONE:
		if (lr->lr_status <= 0 || lr->lr_flags2 & LF_INCOMPLETE) {
			if (lr->lr_flags2 & LF_INCOMPLETE) {
				if (lr->lr_flags & LEF_FROM_OST)
					lfsck_lad_set_bitmap(env, com,
							     ltd->ltd_index);
				else
					lo->ll_flags |= LF_INCOMPLETE;
			}
			ltd->ltd_layout_done = 1;
			list_del_init(&ltd->ltd_layout_list);
			fail = true;
			break;
		}

		if (lr->lr_flags & LEF_FROM_OST) {
			if (list_empty(&ltd->ltd_layout_list))
				list_add_tail(&ltd->ltd_layout_list,
					      &lad->lad_ost_list);
			list_add_tail(&ltd->ltd_layout_phase_list,
				      &lad->lad_ost_phase2_list);
		} else {
			if (list_empty(&ltd->ltd_layout_list))
				list_add_tail(&ltd->ltd_layout_list,
					      &lad->lad_mdt_list);
			list_add_tail(&ltd->ltd_layout_phase_list,
				      &lad->lad_mdt_phase2_list);
		}
		break;
	case LE_PHASE2_DONE:
		ltd->ltd_layout_done = 1;
		if (!list_empty(&ltd->ltd_layout_list))
			list_del_init(&ltd->ltd_layout_list);

		if (lr->lr_flags2 & LF_INCOMPLETE) {
			lfsck_lad_set_bitmap(env, com, ltd->ltd_index);
			fail = true;
		}

		break;
	case LE_PEER_EXIT:
		fail = true;
		ltd->ltd_layout_done = 1;
		list_del_init(&ltd->ltd_layout_list);
		if (!(lfsck->li_bookmark_ram.lb_param & LPF_FAILOUT) &&
		    !(lr->lr_flags & LEF_FROM_OST))
				lo->ll_flags |= LF_INCOMPLETE;
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
	} else if (lfsck_phase2_next_ready(lad)) {
		wake_up(&lad->lad_thread.t_ctl_waitq);
	}

	RETURN(0);
}

static int lfsck_layout_slave_in_notify_local(const struct lu_env *env,
					      struct lfsck_component *com,
					      struct lfsck_req_local *lrl,
					      struct thandle *th)
{
	ENTRY;

	switch (lrl->lrl_event) {
	case LEL_FID_ACCESSED:
		lfsck_rbtree_update_bitmap(env, com, &lrl->lrl_fid, true);
		RETURN(0);
	case LEL_PAIRS_VERIFY_LOCAL: {
		int rc;

		lrl->lrl_status = LPVS_INIT;
		/* Firstly, if the MDT-object which is claimed via OST-object
		 * local stored PFID xattr recognizes the OST-object, then it
		 * must be that the client given PFID is wrong. */
		rc = lfsck_layout_slave_check_pairs(env, com, &lrl->lrl_fid,
				&lrl->lrl_ff_local.ff_parent,
				lrl->lrl_ff_local.ff_layout.ol_comp_id);
		if (rc <= 0)
			RETURN(0);

		lrl->lrl_status = LPVS_INCONSISTENT;
		/* The OST-object local stored PFID xattr is stale. We need to
		 * check whether the MDT-object that is claimed via the client
		 * given PFID information recognizes the OST-object or not. If
		 * matches, then need to update the OST-object's PFID xattr. */
		rc = lfsck_layout_slave_check_pairs(env, com, &lrl->lrl_fid,
				&lrl->lrl_ff_client.ff_parent,
				lrl->lrl_ff_client.ff_layout.ol_comp_id);
		/* For rc < 0 case:
		 * We are not sure whether the client given PFID information
		 * is correct or not, do nothing to avoid improper fixing.
		 *
		 * For rc > 0 case:
		 * The client given PFID information is also invalid, we can
		 * NOT fix the OST-object inconsistency.
		 */
		if (!rc) {
			lrl->lrl_status = LPVS_INCONSISTENT_TOFIX;
			rc = lfsck_layout_slave_repair_pfid(env, com, lrl);
		}

		RETURN(rc);
	}
	default:
		break;
	}

	RETURN(-EOPNOTSUPP);
}

static int lfsck_layout_slave_in_notify(const struct lu_env *env,
					struct lfsck_component *com,
					struct lfsck_request *lr)
{
	struct lfsck_instance *lfsck = com->lc_lfsck;
	struct lfsck_layout_slave_data *llsd = com->lc_data;
	struct lfsck_layout_slave_target *llst;
	int rc;
	ENTRY;

	switch (lr->lr_event) {
	case LE_CONDITIONAL_DESTROY:
		rc = lfsck_layout_slave_conditional_destroy(env, com, lr);
		RETURN(rc);
	case LE_PHASE1_DONE: {
		if (lr->lr_flags2 & LF_INCOMPLETE) {
			struct lfsck_layout *lo = com->lc_file_ram;

			lo->ll_flags |= LF_INCOMPLETE;
			llst = lfsck_layout_llst_find_and_del(llsd,
							      lr->lr_index,
							      true);
			if (llst != NULL) {
				lfsck_layout_llst_put(llst);
				wake_up(&lfsck->li_thread.t_ctl_waitq);
			}
		}

		RETURN(0);
	}
	case LE_PHASE2_DONE:
	case LE_PEER_EXIT:
		CDEBUG(D_LFSCK, "%s: layout LFSCK slave handle notify %u "
		       "from MDT %x, status %d\n", lfsck_lfsck2name(lfsck),
		       lr->lr_event, lr->lr_index, lr->lr_status);
		break;
	default:
		RETURN(-EINVAL);
	}

	llst = lfsck_layout_llst_find_and_del(llsd, lr->lr_index, true);
	if (llst == NULL)
		RETURN(0);

	lfsck_layout_llst_put(llst);
	if (list_empty(&llsd->llsd_master_list))
		wake_up(&lfsck->li_thread.t_ctl_waitq);

	if (lr->lr_event == LE_PEER_EXIT &&
	    (lfsck->li_bookmark_ram.lb_param & LPF_FAILOUT ||
	     (list_empty(&llsd->llsd_master_list) &&
	      (lr->lr_status == LS_STOPPED ||
	       lr->lr_status == LS_CO_STOPPED)))) {
		struct lfsck_stop *stop = &lfsck_env_info(env)->lti_stop;

		memset(stop, 0, sizeof(*stop));
		stop->ls_status = lr->lr_status;
		stop->ls_flags = lr->lr_param & ~LPF_BROADCAST;
		lfsck_stop(env, lfsck->li_bottom, stop);
	}

	RETURN(0);
}

static void lfsck_layout_repaired(struct lfsck_layout *lo, __u64 *count)
{
	int i;

	for (i = 0; i < LLIT_MAX; i++)
		*count += lo->ll_objs_repaired[i];
}

static int lfsck_layout_query_all(const struct lu_env *env,
				  struct lfsck_component *com,
				  __u32 *mdts_count, __u32 *osts_count,
				  __u64 *repaired)
{
	struct lfsck_layout *lo = com->lc_file_ram;
	struct lfsck_tgt_descs *ltds;
	struct lfsck_tgt_desc *ltd;
	int idx;
	int rc;
	ENTRY;

	rc = lfsck_query_all(env, com);
	if (rc != 0)
		RETURN(rc);

	ltds = &com->lc_lfsck->li_mdt_descs;
	down_read(&ltds->ltd_rw_sem);
	cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
		ltd = lfsck_ltd2tgt(ltds, idx);
		LASSERT(ltd != NULL);

		mdts_count[ltd->ltd_layout_status]++;
		*repaired += ltd->ltd_layout_repaired;
	}
	up_read(&ltds->ltd_rw_sem);

	ltds = &com->lc_lfsck->li_ost_descs;
	down_read(&ltds->ltd_rw_sem);
	cfs_foreach_bit(ltds->ltd_tgts_bitmap, idx) {
		ltd = lfsck_ltd2tgt(ltds, idx);
		LASSERT(ltd != NULL);

		osts_count[ltd->ltd_layout_status]++;
		*repaired += ltd->ltd_layout_repaired;
	}
	up_read(&ltds->ltd_rw_sem);

	down_read(&com->lc_sem);
	mdts_count[lo->ll_status]++;
	lfsck_layout_repaired(lo, repaired);
	up_read(&com->lc_sem);

	RETURN(0);
}

static int lfsck_layout_query(const struct lu_env *env,
			      struct lfsck_component *com,
			      struct lfsck_request *req,
			      struct lfsck_reply *rep,
			      struct lfsck_query *que, int idx)
{
	struct lfsck_layout *lo = com->lc_file_ram;
	int rc = 0;

	if (que != NULL) {
		LASSERT(com->lc_lfsck->li_master);

		rc = lfsck_layout_query_all(env, com,
					    que->lu_mdts_count[idx],
					    que->lu_osts_count[idx],
					    &que->lu_repaired[idx]);
	} else {
		down_read(&com->lc_sem);
		rep->lr_status = lo->ll_status;
		if (req->lr_flags & LEF_QUERY_ALL)
			lfsck_layout_repaired(lo, &rep->lr_repaired);
		up_read(&com->lc_sem);
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

	if (start == NULL || !(start->ls_flags & LPF_OST_ORPHAN))
		RETURN(0);

	if (!lsp->lsp_index_valid)
		RETURN(-EINVAL);

	/* If someone is running the LFSCK without orphan handling,
	 * it will not maintain the object accessing rbtree. So we
	 * cannot join it for orphan handling. */
	if (!llsd->llsd_rbtree_valid)
		RETURN(-EBUSY);

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

static const struct lfsck_operations lfsck_layout_master_ops = {
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
};

static const struct lfsck_operations lfsck_layout_slave_ops = {
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
	.lfsck_in_notify_local	= lfsck_layout_slave_in_notify_local,
	.lfsck_in_notify	= lfsck_layout_slave_in_notify,
	.lfsck_query		= lfsck_layout_query,
	.lfsck_join		= lfsck_layout_slave_join,
};

static void lfsck_layout_assistant_fill_pos(const struct lu_env *env,
					    struct lfsck_component *com,
					    struct lfsck_position *pos)
{
	struct lfsck_assistant_data	*lad = com->lc_data;
	struct lfsck_layout_req		*llr;

	if (((struct lfsck_layout *)(com->lc_file_ram))->ll_status !=
	    LS_SCANNING_PHASE1)
		return;

	if (list_empty(&lad->lad_req_list))
		return;

	llr = list_entry(lad->lad_req_list.next,
			 struct lfsck_layout_req,
			 llr_lar.lar_list);
	pos->lp_oit_cookie = llr->llr_lar.lar_parent->lso_oit_cookie - 1;
}

const struct lfsck_assistant_operations lfsck_layout_assistant_ops = {
	.la_handler_p1		= lfsck_layout_assistant_handler_p1,
	.la_handler_p2		= lfsck_layout_assistant_handler_p2,
	.la_fill_pos		= lfsck_layout_assistant_fill_pos,
	.la_double_scan_result	= lfsck_layout_double_scan_result,
	.la_req_fini		= lfsck_layout_assistant_req_fini,
	.la_sync_failures	= lfsck_layout_assistant_sync_failures,
};

int lfsck_layout_setup(const struct lu_env *env, struct lfsck_instance *lfsck)
{
	struct lfsck_component	*com;
	struct lfsck_layout	*lo;
	struct dt_object	*root = NULL;
	struct dt_object	*obj;
	int			 i;
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
	com->lc_type = LFSCK_TYPE_LAYOUT;
	if (lfsck->li_master) {
		com->lc_ops = &lfsck_layout_master_ops;
		com->lc_data = lfsck_assistant_data_init(
				&lfsck_layout_assistant_ops,
				LFSCK_LAYOUT);
		if (com->lc_data == NULL)
			GOTO(out, rc = -ENOMEM);

		for (i = 0; i < LFSCK_STF_COUNT; i++)
			mutex_init(&com->lc_sub_trace_objs[i].lsto_mutex);
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
		init_rwsem(&llsd->llsd_rb_rwsem);
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
					LFSCK_LAYOUT,
					S_IFREG | S_IRUGO | S_IWUSR);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	com->lc_obj = obj;
	rc = lfsck_layout_load(env, com);
	if (rc > 0) {
		rc = lfsck_layout_reset(env, com, true);
	} else if (rc == -ENOENT) {
		rc = lfsck_layout_init(env, com);
	} else if (lfsck->li_master) {
		rc = lfsck_load_sub_trace_files(env, com,
				&dt_lfsck_layout_dangling_features,
				LFSCK_LAYOUT, false);
		if (rc)
			rc = lfsck_layout_reset(env, com, true);
	}

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
		CERROR("%s: unknown lfsck_layout status %d\n",
		       lfsck_lfsck2name(lfsck), lo->ll_status);
		/* fall through */
	case LS_SCANNING_PHASE1:
	case LS_SCANNING_PHASE2:
		/* No need to store the status to disk right now.
		 * If the system crashed before the status stored,
		 * it will be loaded back when next time. */
		lo->ll_status = LS_CRASHED;
		if (!lfsck->li_master)
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
		lfsck_object_put(env, root);

	if (rc != 0) {
		lfsck_component_cleanup(env, com);
		CERROR("%s: fail to init layout LFSCK component: rc = %d\n",
		       lfsck_lfsck2name(lfsck), rc);
	}

	return rc;
}

struct lfsck_orphan_it {
	struct lfsck_component		 *loi_com;
	struct lfsck_rbtree_node	 *loi_lrn;
	struct lfsck_layout_slave_target *loi_llst;
	struct lu_fid			  loi_key;
	struct lu_orphan_rec_v3		  loi_rec;
	__u64				  loi_hash;
	unsigned int			  loi_over:1;
};

static int lfsck_fid_match_idx(const struct lu_env *env,
			       struct lfsck_instance *lfsck,
			       const struct lu_fid *fid, int idx)
{
	struct seq_server_site	*ss;
	struct lu_server_fld	*sf;
	struct lu_seq_range	*range = &lfsck_env_info(env)->lti_range;
	int			 rc;

	/* All abnormal cases will be returned to MDT0. */
	if (!fid_is_norm(fid)) {
		if (idx == 0)
			return 1;

		return 0;
	}

	ss = lfsck_dev_site(lfsck);
	if (unlikely(ss == NULL))
		return -ENOTCONN;

	sf = ss->ss_server_fld;
	LASSERT(sf != NULL);

	fld_range_set_any(range);
	rc = fld_server_lookup(env, sf, fid_seq(fid), range);
	if (rc != 0)
		return rc;

	if (!fld_range_is_mdt(range))
		return -EINVAL;

	if (range->lsr_index == idx)
		return 1;

	return 0;
}

static void lfsck_layout_destroy_orphan(const struct lu_env *env,
					struct dt_object *obj)
{
	struct dt_device	*dev	= lfsck_obj2dev(obj);
	struct thandle		*handle;
	int			 rc;
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

	CDEBUG(D_LFSCK, "destroy orphan OST-object "DFID": rc = %d\n",
	       PFID(lfsck_dto2fid(obj)), rc);

	RETURN_EXIT;
}

static int lfsck_orphan_index_lookup(const struct lu_env *env,
				     struct dt_object *dt,
				     struct dt_rec *rec,
				     const struct dt_key *key)
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
				     struct thandle *handle)
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
				     struct thandle *handle)
{
	return -EOPNOTSUPP;
}

static struct dt_it *lfsck_orphan_it_init(const struct lu_env *env,
					  struct dt_object *dt,
					  __u32 attr)
{
	struct dt_device		*dev	= lu2dt_dev(dt->do_lu.lo_dev);
	struct lfsck_instance		*lfsck;
	struct lfsck_component		*com	= NULL;
	struct lfsck_layout_slave_data	*llsd;
	struct lfsck_orphan_it		*it	= NULL;
	struct lfsck_layout		*lo;
	int				 rc	= 0;
	ENTRY;

	lfsck = lfsck_instance_find(dev, true, false);
	if (unlikely(lfsck == NULL))
		RETURN(ERR_PTR(-ENXIO));

	com = lfsck_component_find(lfsck, LFSCK_TYPE_LAYOUT);
	if (unlikely(com == NULL))
		GOTO(out, rc = -ENOENT);

	lo = com->lc_file_ram;
	if (lo->ll_flags & LF_INCOMPLETE)
		GOTO(out, rc = -ESRCH);

	llsd = com->lc_data;
	if (!llsd->llsd_rbtree_valid)
		GOTO(out, rc = -ESRCH);

	OBD_ALLOC_PTR(it);
	if (it == NULL)
		GOTO(out, rc = -ENOMEM);

	it->loi_llst = lfsck_layout_llst_find_and_del(llsd, attr, false);
	if (it->loi_llst == NULL)
		GOTO(out, rc = -ENXIO);

	if (dev->dd_record_fid_accessed) {
		/* The first iteration against the rbtree, scan the whole rbtree
		 * to remove the nodes which do NOT need to be handled. */
		down_write(&llsd->llsd_rb_rwsem);
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
		up_write(&llsd->llsd_rb_rwsem);
	}

	/* read lock the rbtree when init, and unlock when fini */
	down_read(&llsd->llsd_rb_rwsem);
	it->loi_com = com;
	com = NULL;

	GOTO(out, rc = 0);

out:
	if (com != NULL)
		lfsck_component_put(env, com);

	CDEBUG(D_LFSCK, "%s: init the orphan iteration: rc = %d\n",
	       lfsck_lfsck2name(lfsck), rc);

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
		CDEBUG(D_LFSCK, "%s: fini the orphan iteration\n",
		       lfsck_lfsck2name(com->lc_lfsck));

		llsd = com->lc_data;
		up_read(&llsd->llsd_rb_rwsem);
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
	struct filter_fid		*ff	= &info->lti_ff;
	struct lu_attr			*la	= &info->lti_la;
	struct lfsck_orphan_it		*it	= (struct lfsck_orphan_it *)di;
	struct lu_fid			*key	= &it->loi_key;
	struct lu_orphan_rec_v3		*rec	= &it->loi_rec;
	struct ost_layout		*ol	= &rec->lor_layout;
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
	obj = lfsck_object_find_bottom(env, lfsck, key);
	if (IS_ERR(obj)) {
		rc = PTR_ERR(obj);
		if (rc == -ENOENT) {
			pos++;
			goto again1;
		}
		RETURN(rc);
	}

	dt_read_lock(env, obj, 0);
	if (dt_object_exists(obj) == 0 ||
	    lfsck_is_dead_obj(obj)) {
		dt_read_unlock(env, obj);
		lfsck_object_put(env, obj);
		pos++;
		goto again1;
	}

	rc = dt_attr_get(env, obj, la);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_xattr_get(env, obj, lfsck_buf_get(env, ff, sizeof(*ff)),
			  XATTR_NAME_FID);
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
				lfsck_layout_destroy_orphan(env, obj);
				lfsck_object_put(env, obj);
				pos++;
				goto again1;
			}
		} else if (idx == 0) {
			/* If the orphan OST-object has no parent information,
			 * regard it as referenced by the MDT-object on MDT0. */
			fid_zero(&rec->lor_rec.lor_fid);
			rec->lor_rec.lor_uid = la->la_uid;
			rec->lor_rec.lor_gid = la->la_gid;
			memset(ol, 0, sizeof(*ol));
			rec->lor_layout_version = 0;
			rec->lor_range = 0;

			GOTO(out, rc = 0);
		}

		dt_read_unlock(env, obj);
		lfsck_object_put(env, obj);
		pos++;
		goto again1;
	}

	if (rc < sizeof(struct lu_fid))
		GOTO(out, rc = (rc < 0 ? rc : -EINVAL));

	fid_le_to_cpu(&rec->lor_rec.lor_fid, &ff->ff_parent);
	/* Currently, the filter_fid::ff_parent::f_ver is not the real parent
	 * MDT-object's FID::f_ver, instead it is the OST-object index in its
	 * parent MDT-object's layout EA. */
	save = rec->lor_rec.lor_fid.f_stripe_idx;
	rec->lor_rec.lor_fid.f_ver = 0;
	rc = lfsck_fid_match_idx(env, lfsck, &rec->lor_rec.lor_fid, idx);
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

	rec->lor_rec.lor_fid.f_stripe_idx = save;
	rec->lor_rec.lor_uid = la->la_uid;
	rec->lor_rec.lor_gid = la->la_gid;
	ost_layout_le_to_cpu(ol, &ff->ff_layout);
	rec->lor_layout_version =
		le32_to_cpu(ff->ff_layout_version & ~LU_LAYOUT_RESYNC);
	rec->lor_range = le32_to_cpu(ff->ff_range);

	CDEBUG(D_LFSCK, "%s: return orphan "DFID", PFID "DFID", owner %u:%u, "
	       "stripe size %u, stripe count %u, COMP id %u, COMP start %llu, "
	       "COMP end %llu, layout version %u, range %u\n",
	       lfsck_lfsck2name(com->lc_lfsck), PFID(key),
	       PFID(&rec->lor_rec.lor_fid), rec->lor_rec.lor_uid,
	       rec->lor_rec.lor_gid, ol->ol_stripe_size, ol->ol_stripe_count,
	       ol->ol_comp_id, ol->ol_comp_start, ol->ol_comp_end,
	       rec->lor_layout_version, rec->lor_range);

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

	*(struct lu_orphan_rec_v3 *)rec = it->loi_rec;

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
		CDEBUG(D_LFSCK, "%s: the given hash %llu for orphan "
		       "iteration does not match the one when fini "
		       "%llu, to be reset.\n",
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

static const struct dt_index_operations lfsck_orphan_index_ops = {
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
