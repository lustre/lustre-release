/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LMV_INTERNAL_H_
#define _LMV_INTERNAL_H_

#include <obd.h>
#include <lustre_lmv.h>

#define LMV_MAX_TGT_COUNT 128

#define LL_IT2STR(it)				        \
	((it) ? ldlm_it2str((it)->it_op) : "0")

struct lmvsub_batch {
	struct lu_batch		*sbh_sub;
	struct lmv_tgt_desc	*sbh_tgt;
	struct list_head	 sbh_sub_item;
};

struct lmv_batch {
	struct lu_batch			 lbh_super;
	struct ptlrpc_request_set	*lbh_rqset;
	struct list_head		 lbh_sub_batch_list;
};

int lmv_intent_lock(struct obd_export *exp, struct md_op_data *op_data,
		    struct lookup_intent *it, struct ptlrpc_request **reqp,
		    ldlm_blocking_callback cb_blocking,
		    __u64 extra_lock_flags);

int lmv_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
		     void *, int);
int lmv_fld_lookup(struct lmv_obd *lmv, const struct lu_fid *fid, u32 *mds);
int lmv_fid_alloc(const struct lu_env *env, struct obd_export *exp,
		  struct lu_fid *fid, struct md_op_data *op_data);

int lmv_revalidate_slaves(struct obd_export *exp,
			  const struct lmv_stripe_md *lsm,
			  ldlm_blocking_callback cb_blocking,
			  int extra_lock_flags);

int lmv_getattr_name(struct obd_export *exp, struct md_op_data *op_data,
		     struct ptlrpc_request **preq);
void lmv_activate_target(struct lmv_obd *lmv, struct lmv_tgt_desc *tgt,
			 int activate);

int lmv_statfs_check_update(struct obd_device *obd, struct lmv_tgt_desc *tgt);

static inline struct obd_device *lmv2obd_dev(struct lmv_obd *lmv)
{
	return container_of_safe(lmv, struct obd_device, u.lmv);
}

static inline struct lu_tgt_desc *lmv_tgt(struct lmv_obd *lmv, __u32 index)
{
	return index < lmv->lmv_mdt_descs.ltd_tgts_size ?
		LTD_TGT(&lmv->lmv_mdt_descs, index) : NULL;
}
struct lu_tgt_desc *lmv_tgt_retry(struct lmv_obd *lmv, __u32 index);

static inline bool lmv_mdt0_inited(struct lmv_obd *lmv)
{
	return lmv->lmv_mdt_descs.ltd_tgts_size > 0 &&
	       test_bit(0, lmv->lmv_mdt_descs.ltd_tgt_bitmap);
}

#define lmv_foreach_tgt(lmv, tgt) ltd_foreach_tgt(&(lmv)->lmv_mdt_descs, tgt)

#define lmv_foreach_tgt_safe(lmv, tgt, tmp) \
	ltd_foreach_tgt_safe(&(lmv)->lmv_mdt_descs, tgt, tmp)

static inline
struct lu_tgt_desc *lmv_first_connected_tgt(struct lmv_obd *lmv)
{
	struct lu_tgt_desc *tgt;

	tgt = ltd_first_tgt(&lmv->lmv_mdt_descs);
	while (tgt && !tgt->ltd_exp)
		tgt = ltd_next_tgt(&lmv->lmv_mdt_descs, tgt);

	return tgt;
}

static inline
struct lu_tgt_desc *lmv_next_connected_tgt(struct lmv_obd *lmv,
					   struct lu_tgt_desc *tgt)
{
	do {
		tgt = ltd_next_tgt(&lmv->lmv_mdt_descs, tgt);
	} while (tgt && !tgt->ltd_exp);

	return tgt;
}

#define lmv_foreach_connected_tgt(lmv, tgt) \
	for (tgt = lmv_first_connected_tgt(lmv); tgt; \
	     tgt = lmv_next_connected_tgt(lmv, tgt))

static inline int
lmv_fid2tgt_index(struct lmv_obd *lmv, const struct lu_fid *fid)
{
	u32 mdt_idx;
	int rc;

	if (lmv->lmv_mdt_count < 2)
		return 0;

	rc = lmv_fld_lookup(lmv, fid, &mdt_idx);
	if (rc < 0)
		return rc;

	return mdt_idx;
}

static inline struct lmv_tgt_desc *
lmv_fid2tgt(struct lmv_obd *lmv, const struct lu_fid *fid)
{
	struct lu_tgt_desc *tgt;
	int index;

	if (!fid_is_sane(fid))
		return ERR_PTR(-EINVAL);

	index = lmv_fid2tgt_index(lmv, fid);
	if (index < 0)
		return ERR_PTR(index);

	tgt = lmv_tgt_retry(lmv, index);

	return tgt ? tgt : ERR_PTR(-ENODEV);
}

static inline int lmv_stripe_md_size(int stripe_count)
{
	struct lmv_stripe_md *lsm;

	return sizeof(*lsm) + stripe_count * sizeof(lsm->lsm_md_oinfo[0]);
}

/* for file under migrating directory, return the target stripe info */
static inline const struct lmv_oinfo *
lsm_name_to_stripe_info(const struct lmv_stripe_object *lso, const char *name,
			int namelen, bool new_layout)
{
	const struct lmv_stripe_md *lsm;
	int stripe_index;

	LASSERT(lmv_dir_striped(lso));

	lsm = &lso->lso_lsm;
	stripe_index = __lmv_name_to_stripe_index(lsm->lsm_md_hash_type,
						  lsm->lsm_md_stripe_count,
						  lsm->lsm_md_migrate_hash,
						  lsm->lsm_md_migrate_offset,
						  name, namelen, new_layout);
	if (stripe_index < 0)
		return ERR_PTR(stripe_index);

	return &lsm->lsm_md_oinfo[stripe_index];
}

static inline bool lmv_dir_retry_check_update(struct md_op_data *op_data)
{
	const struct lmv_stripe_object *lso = op_data->op_lso1;

	if (!lso)
		return false;

	if (lmv_dir_layout_changing(lso) && !op_data->op_new_layout) {
		op_data->op_new_layout = true;
		return true;
	}

	if (lmv_dir_bad_hash(lso) &&
	    op_data->op_stripe_index < lso->lso_lsm.lsm_md_stripe_count - 1) {
		op_data->op_stripe_index++;
		return true;
	}

	return false;
}

struct lmv_tgt_desc *lmv_locate_tgt_create(struct obd_device *obd,
					   struct lmv_obd *lmv,
					   struct md_op_data *op_data);
struct lmv_tgt_desc *lmv_locate_tgt(struct lmv_obd *lmv,
				    struct md_op_data *op_data);
int lmv_old_layout_lookup(struct lmv_obd *lmv, struct md_op_data *op_data);

extern const struct rhashtable_params qos_exclude_hash_params;
void qos_exclude_prefix_free(void *vprefix, void *data);

/* lproc_lmv.c */
int lmv_tunables_init(struct obd_device *obd);
#endif
