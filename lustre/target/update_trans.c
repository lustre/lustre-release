/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2015, 2017, Intel Corporation.
 */
/*
 * lustre/target/update_trans.c
 *
 * This file implements the update distribute transaction API.
 *
 * To manage the cross-MDT operation (distribute operation) transaction,
 * the transaction will also be separated two layers on MD stack, top
 * transaction and sub transaction.
 *
 * During the distribute operation, top transaction is created in the LOD
 * layer, and represent the operation. Sub transaction is created by
 * each OSD or OSP. Top transaction start/stop will trigger all of its sub
 * transaction start/stop. Top transaction (the whole operation) is committed
 * only all of its sub transaction are committed.
 *
 * there are three kinds of transactions
 * 1. local transaction: All updates are in a single local OSD.
 * 2. Remote transaction: All Updates are only in the remote OSD,
 *    i.e. locally all updates are in OSP.
 * 3. Mixed transaction: Updates are both in local OSD and remote
 *    OSD.
 *
 * Author: Di Wang <di.wang@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/kthread.h>
#include <lu_target.h>
#include <lustre_log.h>
#include <lustre_update.h>
#include <obd.h>
#include <obd_class.h>
#include <tgt_internal.h>

#include <tgt_internal.h>
/**
 * Dump top mulitple thandle
 *
 * Dump top multiple thandle and all of its sub thandle to the debug log.
 *
 * \param[in]mask	debug mask
 * \param[in]top_th	top_thandle to be dumped
 */
static void top_multiple_thandle_dump(struct top_multiple_thandle *tmt,
				      __u32 mask)
{
	struct sub_thandle	*st;

	LASSERT(tmt->tmt_magic == TOP_THANDLE_MAGIC);
	CDEBUG(mask, "%s tmt %p refcount %d committed %d result %d batchid %llu\n",
	       tmt->tmt_master_sub_dt ?
	       tmt->tmt_master_sub_dt->dd_lu_dev.ld_obd->obd_name :
	       "NULL",
	       tmt, atomic_read(&tmt->tmt_refcount), tmt->tmt_committed,
	       tmt->tmt_result, tmt->tmt_batchid);

	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		struct sub_thandle_cookie *stc;

		CDEBUG(mask, "st %p obd %s committed %d started %d stopped %d "
		       "result %d sub_th %p\n",
		       st, st->st_dt->dd_lu_dev.ld_obd->obd_name,
		       st->st_committed, st->st_started, st->st_stopped,
		       st->st_result, st->st_sub_th);

		list_for_each_entry(stc, &st->st_cookie_list, stc_list) {
			CDEBUG(mask, " cookie "DFID".%u\n",
			       PFID(&stc->stc_cookie.lgc_lgl.lgl_oi.oi_fid),
			       stc->stc_cookie.lgc_index);
		}
	}
}

/**
 * Declare write update to sub device
 *
 * Declare Write updates llog records to the sub device during distribute
 * transaction.
 *
 * \param[in] env	execution environment
 * \param[in] record	update records being written
 * \param[in] sub_th	sub transaction handle
 * \param[in] record_size total update record size
 *
 * \retval		0 if writing succeeds
 * \retval		negative errno if writing fails
 */
static int sub_declare_updates_write(const struct lu_env *env,
				     struct llog_update_record *record,
				     struct thandle *sub_th, size_t record_size)
{
	struct llog_ctxt	*ctxt;
	struct dt_device	*dt = sub_th->th_dev;
	int			left = record_size;
	int rc;

	/* If ctxt is NULL, it means not need to write update,
	 * for example if the the OSP is used to connect to OST */
	ctxt = llog_get_context(dt->dd_lu_dev.ld_obd,
				LLOG_UPDATELOG_ORIG_CTXT);

	/* Not ready to record updates yet. */
	if (ctxt == NULL || ctxt->loc_handle == NULL) {
		llog_ctxt_put(ctxt);
		return 0;
	}

	rc = llog_declare_add(env, ctxt->loc_handle,
			      &record->lur_hdr, sub_th);
	if (rc < 0)
		GOTO(out_put, rc);

	while (left > ctxt->loc_chunk_size) {
		rc = llog_declare_add(env, ctxt->loc_handle,
				      &record->lur_hdr, sub_th);
		if (rc < 0)
			GOTO(out_put, rc);

		left -= ctxt->loc_chunk_size;
	}

out_put:
	llog_ctxt_put(ctxt);

	return rc;
}

/**
 * write update to sub device
 *
 * Write llog update record to the sub device during distribute
 * transaction. If it succeeds, llog cookie of the record will be
 * returned by @cookie.
 *
 * \param[in] env	execution environment
 * \param[in] record	update records being written
 * \param[in] sub_th	sub transaction handle
 * \param[out] cookie	llog cookie of the update record.
 *
 * \retval		1 if writing succeeds
 * \retval		negative errno if writing fails
 */
static int sub_updates_write(const struct lu_env *env,
			     struct llog_update_record *record,
			     struct sub_thandle *sub_th)
{
	struct dt_device *dt = sub_th->st_dt;
	struct llog_ctxt *ctxt;
	struct llog_update_record *lur = NULL;
	__u32 update_count = 0;
	__u32 param_count = 0;
	__u32 last_update_count = 0;
	__u32 last_param_count = 0;
	char *start;
	char *cur;
	char *next;
	struct sub_thandle_cookie *stc;
	size_t reclen;
	bool eof = false;
	int rc;
	ENTRY;

	ctxt = llog_get_context(dt->dd_lu_dev.ld_obd,
				LLOG_UPDATELOG_ORIG_CTXT);
	/* If ctxt == NULL, then it means updates on OST (only happens
	 * during migration), and we do not track those updates for now */
	/* If ctxt->loc_handle == NULL, then it does not need to record
	 * update, usually happens in error handler path */
	if (ctxt == NULL || ctxt->loc_handle == NULL) {
		llog_ctxt_put(ctxt);
		RETURN(0);
	}

	/* Since the cross-MDT updates will includes both local
	 * and remote updates, the update ops count must > 1 */
	LASSERT(record->lur_update_rec.ur_update_count > 1);
	LASSERTF(record->lur_hdr.lrh_len == llog_update_record_size(record),
		 "lrh_len %u record_size %zu\n", record->lur_hdr.lrh_len,
		 llog_update_record_size(record));

	/*
	 * If its size > llog chunk_size, then write current chunk to the update
	 * llog, NB the padding should >= LLOG_MIN_REC_SIZE.
	 *
	 * So check padding length is either >= LLOG_MIN_REC_SIZE or is 0
	 * (record length just matches the chunk size).
	 */

	reclen = record->lur_hdr.lrh_len;
	if (reclen + LLOG_MIN_REC_SIZE <= ctxt->loc_chunk_size ||
	    reclen == ctxt->loc_chunk_size) {
		OBD_ALLOC_PTR(stc);
		if (stc == NULL)
			GOTO(llog_put, rc = -ENOMEM);
		INIT_LIST_HEAD(&stc->stc_list);

		rc = llog_add(env, ctxt->loc_handle, &record->lur_hdr,
			      &stc->stc_cookie, sub_th->st_sub_th);

		CDEBUG(D_INFO, "%s: Add update log "DFID".%u: rc = %d\n",
		       dt->dd_lu_dev.ld_obd->obd_name,
		       PFID(&stc->stc_cookie.lgc_lgl.lgl_oi.oi_fid),
		       stc->stc_cookie.lgc_index, rc);

		if (rc > 0) {
			list_add(&stc->stc_list, &sub_th->st_cookie_list);
			rc = 0;
		} else {
			OBD_FREE_PTR(stc);
		}

		GOTO(llog_put, rc);
	}

	/* Split the records into chunk_size update record */
	OBD_ALLOC_LARGE(lur, ctxt->loc_chunk_size);
	if (lur == NULL)
		GOTO(llog_put, rc = -ENOMEM);

	memcpy(lur, &record->lur_hdr, sizeof(record->lur_hdr));
	lur->lur_update_rec.ur_update_count = 0;
	lur->lur_update_rec.ur_param_count = 0;
	start = (char *)&record->lur_update_rec.ur_ops;
	cur = next = start;
	do {
		if (update_count < record->lur_update_rec.ur_update_count)
			next = (char *)update_op_next_op(
						(struct update_op *)cur);
		else if (param_count < record->lur_update_rec.ur_param_count)
			next = (char *)update_param_next_param(
						(struct update_param *)cur);
		else
			eof = true;

		reclen = __llog_update_record_size(
				__update_records_size(next - start));
		if ((reclen + LLOG_MIN_REC_SIZE <= ctxt->loc_chunk_size ||
		     reclen == ctxt->loc_chunk_size) &&
		    !eof) {
			cur = next;

			if (update_count <
			    record->lur_update_rec.ur_update_count)
				update_count++;
			else if (param_count <
				 record->lur_update_rec.ur_param_count)
				param_count++;
			continue;
		}

		lur->lur_update_rec.ur_update_count = update_count -
						      last_update_count;
		lur->lur_update_rec.ur_param_count = param_count -
						     last_param_count;
		memcpy(&lur->lur_update_rec.ur_ops, start, cur - start);
		lur->lur_hdr.lrh_len = llog_update_record_size(lur);

		LASSERT(lur->lur_hdr.lrh_len ==
			 __llog_update_record_size(
				__update_records_size(cur - start)));
		LASSERT(lur->lur_hdr.lrh_len <= ctxt->loc_chunk_size);

		update_records_dump(&lur->lur_update_rec, D_INFO, true);

		OBD_ALLOC_PTR(stc);
		if (stc == NULL)
			GOTO(llog_put, rc = -ENOMEM);
		INIT_LIST_HEAD(&stc->stc_list);

		rc = llog_add(env, ctxt->loc_handle, &lur->lur_hdr,
			      &stc->stc_cookie, sub_th->st_sub_th);

		CDEBUG(D_INFO, "%s: Add update log "DFID".%u: rc = %d\n",
			dt->dd_lu_dev.ld_obd->obd_name,
			PFID(&stc->stc_cookie.lgc_lgl.lgl_oi.oi_fid),
			stc->stc_cookie.lgc_index, rc);

		if (rc > 0) {
			list_add(&stc->stc_list, &sub_th->st_cookie_list);
			rc = 0;
		} else {
			OBD_FREE_PTR(stc);
			GOTO(llog_put, rc);
		}

		last_update_count = update_count;
		last_param_count = param_count;
		start = cur;
		lur->lur_update_rec.ur_update_count = 0;
		lur->lur_update_rec.ur_param_count = 0;
		lur->lur_update_rec.ur_flags |= UPDATE_RECORD_CONTINUE;
	} while (!eof);

llog_put:
	if (lur != NULL)
		OBD_FREE_LARGE(lur, ctxt->loc_chunk_size);
	llog_ctxt_put(ctxt);

	RETURN(rc);
}

/**
 * Prepare the update records.
 *
 * Merge params and ops into the update records, then initializing
 * the update buffer.
 *
 * During transaction execution phase, parameters and update ops
 * are collected in two different buffers (see lod_updates_pack()),
 * during transaction stop, it needs to be merged in one buffer,
 * so it will be written in the update log.
 *
 * \param[in] env	execution environment
 * \param[in] tmt	top_multiple_thandle for distribute txn
 *
 * \retval		0 if merging succeeds.
 * \retval		negaitive errno if merging fails.
 */
static int prepare_writing_updates(const struct lu_env *env,
				   struct top_multiple_thandle *tmt)
{
	struct thandle_update_records	*tur = tmt->tmt_update_records;
	struct llog_update_record	*lur;
	struct update_params *params;
	size_t params_size;
	size_t update_size;

	if (tur == NULL || tur->tur_update_records == NULL ||
	    tur->tur_update_params == NULL)
		return 0;

	lur = tur->tur_update_records;
	/* Extends the update records buffer if needed */
	params_size = update_params_size(tur->tur_update_params,
					 tur->tur_update_param_count);
	LASSERT(lur->lur_update_rec.ur_param_count == 0);
	update_size = llog_update_record_size(lur);
	if (cfs_size_round(update_size + params_size) >
	    tur->tur_update_records_buf_size) {
		int rc;

		rc = tur_update_records_extend(tur,
			cfs_size_round(update_size + params_size));
		if (rc < 0)
			return rc;

		lur = tur->tur_update_records;
	}

	params = update_records_get_params(&lur->lur_update_rec);
	memcpy(params, tur->tur_update_params, params_size);

	lur->lur_update_rec.ur_param_count = tur->tur_update_param_count;
	lur->lur_update_rec.ur_batchid = tmt->tmt_batchid;
	/* Init update record header */
	lur->lur_hdr.lrh_len = llog_update_record_size(lur);
	lur->lur_hdr.lrh_type = UPDATE_REC;

	/* Dump updates for debugging purpose */
	update_records_dump(&lur->lur_update_rec, D_INFO, true);

	return 0;
}

static inline int
distribute_txn_commit_thread_running(struct lu_target *lut)
{
	return lut->lut_tdtd_commit_thread.t_flags & SVC_RUNNING;
}

static inline int
distribute_txn_commit_thread_stopped(struct lu_target *lut)
{
	return lut->lut_tdtd_commit_thread.t_flags & SVC_STOPPED;
}

/**
 * Top thandle commit callback
 *
 * This callback will be called when all of sub transactions are committed.
 *
 * \param[in] th	top thandle to be committed.
 */
static void top_trans_committed_cb(struct top_multiple_thandle *tmt)
{
	struct lu_target *lut;
	ENTRY;

	LASSERT(atomic_read(&tmt->tmt_refcount) > 0);

	top_multiple_thandle_dump(tmt, D_HA);
	tmt->tmt_committed = 1;
	lut = dt2lu_dev(tmt->tmt_master_sub_dt)->ld_site->ls_tgt;
	if (distribute_txn_commit_thread_running(lut))
		wake_up(&lut->lut_tdtd->tdtd_commit_thread_waitq);
	RETURN_EXIT;
}

struct sub_thandle *lookup_sub_thandle(struct top_multiple_thandle *tmt,
				       struct dt_device *dt_dev)
{
	struct sub_thandle *st;

	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		if (st->st_dt == dt_dev)
			return st;
	}
	return NULL;
}
EXPORT_SYMBOL(lookup_sub_thandle);

struct sub_thandle *create_sub_thandle(struct top_multiple_thandle *tmt,
				       struct dt_device *dt_dev)
{
	struct sub_thandle *st;

	OBD_ALLOC_PTR(st);
	if (st == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	INIT_LIST_HEAD(&st->st_sub_list);
	INIT_LIST_HEAD(&st->st_cookie_list);
	st->st_dt = dt_dev;

	list_add(&st->st_sub_list, &tmt->tmt_sub_thandle_list);
	return st;
}

static void sub_trans_commit_cb_internal(struct top_multiple_thandle *tmt,
					 struct thandle *sub_th, int err)
{
	struct sub_thandle	*st;
	bool			all_committed = true;

	/* Check if all sub thandles are committed */
	spin_lock(&tmt->tmt_sub_lock);
	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		if (st->st_sub_th == sub_th) {
			st->st_committed = 1;
			st->st_result = err;
		}
		if (!st->st_committed)
			all_committed = false;
	}
	spin_unlock(&tmt->tmt_sub_lock);

	if (tmt->tmt_result == 0)
		tmt->tmt_result = err;

	if (all_committed)
		top_trans_committed_cb(tmt);

	top_multiple_thandle_dump(tmt, D_INFO);
	top_multiple_thandle_put(tmt);
	RETURN_EXIT;
}

/**
 * sub thandle commit callback
 *
 * Mark the sub thandle to be committed and if all sub thandle are committed
 * notify the top thandle.
 *
 * \param[in] env	execution environment
 * \param[in] sub_th	sub thandle being committed
 * \param[in] cb	commit callback
 * \param[in] err	trans result
 */
static void sub_trans_commit_cb(struct lu_env *env,
				struct thandle *sub_th,
				struct dt_txn_commit_cb *cb, int err)
{
	struct top_multiple_thandle *tmt = cb->dcb_data;

	sub_trans_commit_cb_internal(tmt, sub_th, err);
}

static void sub_thandle_register_commit_cb(struct sub_thandle *st,
				    struct top_multiple_thandle *tmt)
{
	LASSERT(st->st_sub_th != NULL);
	top_multiple_thandle_get(tmt);
	st->st_commit_dcb.dcb_func = sub_trans_commit_cb;
	st->st_commit_dcb.dcb_data = tmt;
	INIT_LIST_HEAD(&st->st_commit_dcb.dcb_linkage);
	dt_trans_cb_add(st->st_sub_th, &st->st_commit_dcb);
}

/**
 * Sub thandle stop call back
 *
 * After sub thandle is stopped, it will call this callback to notify
 * the top thandle.
 *
 * \param[in] th	sub thandle to be stopped
 * \param[in] rc	result of sub trans
 */
static void sub_trans_stop_cb(struct lu_env *env,
			      struct thandle *sub_th,
			      struct dt_txn_commit_cb *cb, int err)
{
	struct sub_thandle		*st;
	struct top_multiple_thandle	*tmt = cb->dcb_data;
	ENTRY;

	spin_lock(&tmt->tmt_sub_lock);
	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		if (st->st_stopped)
			continue;

		if (st->st_dt == sub_th->th_dev) {
			st->st_stopped = 1;
			st->st_result = err;
			break;
		}
	}
	spin_unlock(&tmt->tmt_sub_lock);

	wake_up(&tmt->tmt_stop_waitq);
	RETURN_EXIT;
}

static void sub_thandle_register_stop_cb(struct sub_thandle *st,
					 struct top_multiple_thandle *tmt)
{
	st->st_stop_dcb.dcb_func = sub_trans_stop_cb;
	st->st_stop_dcb.dcb_data = tmt;
	st->st_stop_dcb.dcb_flags = DCB_TRANS_STOP;
	INIT_LIST_HEAD(&st->st_stop_dcb.dcb_linkage);
	dt_trans_cb_add(st->st_sub_th, &st->st_stop_dcb);
}

/**
 * Create sub thandle
 *
 * Create transaction handle for sub_thandle
 *
 * \param[in] env	execution environment
 * \param[in] th	top thandle
 * \param[in] st	sub_thandle
 *
 * \retval		0 if creation succeeds.
 * \retval		negative errno if creation fails.
 */
int sub_thandle_trans_create(const struct lu_env *env,
			     struct top_thandle *top_th,
			     struct sub_thandle *st)
{
	struct thandle *sub_th;

	sub_th = dt_trans_create(env, st->st_dt);
	if (IS_ERR(sub_th))
		return PTR_ERR(sub_th);

	sub_th->th_top = &top_th->tt_super;
	st->st_sub_th = sub_th;

	sub_th->th_wait_submit = 1;
	sub_thandle_register_stop_cb(st, top_th->tt_multiple_thandle);
	return 0;
}

/**
 * Create the top transaction.
 *
 * Create the top transaction on the master device. It will create a top
 * thandle and a sub thandle on the master device.
 *
 * \param[in] env		execution environment
 * \param[in] master_dev	master_dev the top thandle will be created
 *
 * \retval			pointer to the created thandle.
 * \retval			ERR_PTR(errno) if creation failed.
 */
struct thandle *
top_trans_create(const struct lu_env *env, struct dt_device *master_dev)
{
	struct top_thandle	*top_th;
	struct thandle		*child_th;

	OBD_ALLOC_GFP(top_th, sizeof(*top_th), __GFP_IO);
	if (top_th == NULL)
		return ERR_PTR(-ENOMEM);

	top_th->tt_super.th_top = &top_th->tt_super;

	if (master_dev != NULL) {
		child_th = dt_trans_create(env, master_dev);
		if (IS_ERR(child_th)) {
			OBD_FREE_PTR(top_th);
			return child_th;
		}

		child_th->th_top = &top_th->tt_super;
		child_th->th_wait_submit = 1;
		top_th->tt_master_sub_thandle = child_th;
	}
	return &top_th->tt_super;
}
EXPORT_SYMBOL(top_trans_create);

/**
 * Declare write update transaction
 *
 * Check if there are updates being recorded in this transaction,
 * it will write the record into the disk.
 *
 * \param[in] env	execution environment
 * \param[in] tmt	top multiple transaction handle
 *
 * \retval		0 if writing succeeds
 * \retval		negative errno if writing fails
 */
static int declare_updates_write(const struct lu_env *env,
				 struct top_multiple_thandle *tmt)
{
	struct llog_update_record *record;
	struct sub_thandle *st;
	int rc = 0;

	record = tmt->tmt_update_records->tur_update_records;
	/* Declare update write for all other target */
	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		if (st->st_sub_th == NULL)
			continue;

		rc = sub_declare_updates_write(env, record, st->st_sub_th,
					       tmt->tmt_record_size);
		if (rc < 0)
			break;
	}

	return rc;
}

/**
 * Assign batchid to the distribute transaction.
 *
 * Assign batchid to the distribute transaction
 *
 * \param[in] tmt	distribute transaction
 */
static void distribute_txn_assign_batchid(struct top_multiple_thandle *new)
{
	struct target_distribute_txn_data *tdtd;
	struct dt_device *dt = new->tmt_master_sub_dt;
	struct sub_thandle *st;

	LASSERT(dt != NULL);
	tdtd = dt2lu_dev(dt)->ld_site->ls_tgt->lut_tdtd;
	spin_lock(&tdtd->tdtd_batchid_lock);
	new->tmt_batchid = tdtd->tdtd_batchid++;
	list_add_tail(&new->tmt_commit_list, &tdtd->tdtd_list);
	spin_unlock(&tdtd->tdtd_batchid_lock);
	list_for_each_entry(st, &new->tmt_sub_thandle_list, st_sub_list) {
		if (st->st_sub_th != NULL)
			sub_thandle_register_commit_cb(st, new);
	}
	top_multiple_thandle_get(new);
	top_multiple_thandle_dump(new, D_INFO);
}

/**
 * Insert distribute transaction to the distribute txn list.
 *
 * Insert distribute transaction to the distribute txn list.
 *
 * \param[in] new	the distribute txn to be inserted.
 */
void distribute_txn_insert_by_batchid(struct top_multiple_thandle *new)
{
	struct dt_device *dt = new->tmt_master_sub_dt;
	struct top_multiple_thandle *tmt;
	struct target_distribute_txn_data *tdtd;
	struct sub_thandle *st;
	bool	at_head = false;

	LASSERT(dt != NULL);
	tdtd = dt2lu_dev(dt)->ld_site->ls_tgt->lut_tdtd;

	spin_lock(&tdtd->tdtd_batchid_lock);
	list_for_each_entry_reverse(tmt, &tdtd->tdtd_list, tmt_commit_list) {
		if (new->tmt_batchid > tmt->tmt_batchid) {
			list_add(&new->tmt_commit_list, &tmt->tmt_commit_list);
			break;
		}
	}
	if (list_empty(&new->tmt_commit_list)) {
		at_head = true;
		list_add(&new->tmt_commit_list, &tdtd->tdtd_list);
	}
	spin_unlock(&tdtd->tdtd_batchid_lock);

	list_for_each_entry(st, &new->tmt_sub_thandle_list, st_sub_list) {
		if (st->st_sub_th != NULL)
			sub_thandle_register_commit_cb(st, new);
	}

	top_multiple_thandle_get(new);
	top_multiple_thandle_dump(new, D_INFO);
	if (new->tmt_committed && at_head)
		wake_up(&tdtd->tdtd_commit_thread_waitq);
}

/**
 * Prepare cross-MDT operation.
 *
 * Create the update record buffer to record updates for cross-MDT operation,
 * add master sub transaction to tt_sub_trans_list, and declare the update
 * writes.
 *
 * During updates packing, all of parameters will be packed in
 * tur_update_params, and updates will be packed in tur_update_records.
 * Then in transaction stop, parameters and updates will be merged
 * into one updates buffer.
 *
 * And also master thandle will be added to the sub_th list, so it will be
 * easy to track the commit status.
 *
 * \param[in] env	execution environment
 * \param[in] th	top transaction handle
 *
 * \retval		0 if preparation succeeds.
 * \retval		negative errno if preparation fails.
 */
static int prepare_multiple_node_trans(const struct lu_env *env,
				       struct top_multiple_thandle *tmt)
{
	struct thandle_update_records	*tur;
	int				rc;
	ENTRY;

	if (tmt->tmt_update_records == NULL) {
		tur = &update_env_info(env)->uti_tur;
		rc = check_and_prepare_update_record(env, tur);
		if (rc < 0)
			RETURN(rc);

		tmt->tmt_update_records = tur;
		distribute_txn_assign_batchid(tmt);
	}

	rc = declare_updates_write(env, tmt);

	RETURN(rc);
}

/**
 * start the top transaction.
 *
 * Start all of its sub transactions, then start master sub transaction.
 *
 * \param[in] env		execution environment
 * \param[in] master_dev	master_dev the top thandle will be start
 * \param[in] th		top thandle
 *
 * \retval			0 if transaction start succeeds.
 * \retval			negative errno if start fails.
 */
int top_trans_start(const struct lu_env *env, struct dt_device *master_dev,
		    struct thandle *th)
{
	struct top_thandle	*top_th = container_of(th, struct top_thandle,
						       tt_super);
	struct sub_thandle		*st;
	struct top_multiple_thandle	*tmt = top_th->tt_multiple_thandle;
	int				rc = 0;
	ENTRY;

	if (tmt == NULL) {
		if (th->th_sync)
			top_th->tt_master_sub_thandle->th_sync = th->th_sync;
		if (th->th_local)
			top_th->tt_master_sub_thandle->th_local = th->th_local;
		rc = dt_trans_start(env, top_th->tt_master_sub_thandle->th_dev,
				    top_th->tt_master_sub_thandle);
		RETURN(rc);
	}

	tmt = top_th->tt_multiple_thandle;
	rc = prepare_multiple_node_trans(env, tmt);
	if (rc < 0)
		RETURN(rc);

	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		if (st->st_sub_th == NULL)
			continue;
		if (th->th_sync)
			st->st_sub_th->th_sync = th->th_sync;
		if (th->th_local)
			st->st_sub_th->th_local = th->th_local;
		rc = dt_trans_start(env, st->st_sub_th->th_dev,
				    st->st_sub_th);
		if (rc != 0)
			GOTO(out, rc);

		LASSERT(st->st_started == 0);
		st->st_started = 1;
	}
out:
	th->th_result = rc;
	RETURN(rc);
}
EXPORT_SYMBOL(top_trans_start);

/**
 * Check whether we need write updates record
 *
 * Check if the updates for the top_thandle needs to be writen
 * to all targets. Only if the transaction succeeds and the updates
 * number > 2, it will write the updates,
 *
 * \params [in] top_th	top thandle.
 *
 * \retval		true if it needs to write updates
 * \retval		false if it does not need to write updates
 **/
static bool top_check_write_updates(struct top_thandle *top_th)
{
	struct top_multiple_thandle	*tmt;
	struct thandle_update_records	*tur;

	/* Do not write updates to records if the transaction fails */
	if (top_th->tt_super.th_result != 0)
		return false;

	tmt = top_th->tt_multiple_thandle;
	if (tmt == NULL)
		return false;

	tur = tmt->tmt_update_records;
	if (tur == NULL)
		return false;

	/* Hmm, false update records, since the cross-MDT operation
	 * should includes both local and remote updates, so the
	 * updates count should >= 2 */
	if (tur->tur_update_records == NULL ||
	    tur->tur_update_records->lur_update_rec.ur_update_count <= 1)
		return false;

	return true;
}

/**
 * Check if top transaction is stopped
 *
 * Check if top transaction is stopped, only if all sub transaction
 * is stopped, then the top transaction is stopped.
 *
 * \param [in] top_th	top thandle
 *
 * \retval		true if the top transaction is stopped.
 * \retval		false if the top transaction is not stopped.
 */
static bool top_trans_is_stopped(struct top_thandle *top_th)
{
	struct top_multiple_thandle	*tmt;
	struct sub_thandle		*st;
	bool			all_stopped = true;

	tmt = top_th->tt_multiple_thandle;
	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		if (!st->st_stopped && st->st_sub_th != NULL) {
			all_stopped = false;
			break;
		}

		if (st->st_result != 0 &&
		    top_th->tt_super.th_result == 0)
			top_th->tt_super.th_result = st->st_result;
	}

	return all_stopped;
}

/**
 * Wait result of top transaction
 *
 * Wait until all sub transaction get its result.
 *
 * \param [in] top_th	top thandle.
 *
 * \retval		the result of top thandle.
 */
static int top_trans_wait_result(struct top_thandle *top_th)
{
	struct l_wait_info	lwi = {0};

	l_wait_event(top_th->tt_multiple_thandle->tmt_stop_waitq,
		     top_trans_is_stopped(top_th), &lwi);

	RETURN(top_th->tt_super.th_result);
}

/**
 * Stop the top transaction.
 *
 * Stop the transaction on the master device first, then stop transactions
 * on other sub devices.
 *
 * \param[in] env		execution environment
 * \param[in] master_dev	master_dev the top thandle will be created
 * \param[in] th		top thandle
 *
 * \retval			0 if stop transaction succeeds.
 * \retval			negative errno if stop transaction fails.
 */
int top_trans_stop(const struct lu_env *env, struct dt_device *master_dev,
		   struct thandle *th)
{
	struct top_thandle	*top_th = container_of(th, struct top_thandle,
						       tt_super);
	struct sub_thandle		*st;
	struct sub_thandle		*master_st;
	struct top_multiple_thandle	*tmt;
	struct thandle_update_records	*tur;
	bool				write_updates = false;
	int			rc = 0;
	ENTRY;

	if (likely(top_th->tt_multiple_thandle == NULL)) {
		LASSERT(master_dev != NULL);

		if (th->th_sync)
			top_th->tt_master_sub_thandle->th_sync = th->th_sync;
		if (th->th_local)
			top_th->tt_master_sub_thandle->th_local = th->th_local;
		rc = dt_trans_stop(env, master_dev,
				   top_th->tt_master_sub_thandle);
		OBD_FREE_PTR(top_th);
		RETURN(rc);
	}

	tmt = top_th->tt_multiple_thandle;
	tur = tmt->tmt_update_records;

	/* Note: we need stop the master thandle first, then the stop
	 * callback will fill the master transno in the update logs,
	 * then these update logs will be sent to other MDTs */
	/* get the master sub thandle */
	master_st = lookup_sub_thandle(tmt, tmt->tmt_master_sub_dt);
	write_updates = top_check_write_updates(top_th);

	/* Step 1: write the updates log on Master MDT */
	if (master_st != NULL && master_st->st_sub_th != NULL &&
	    write_updates) {
		struct llog_update_record *lur;

		/* Merge the parameters and updates into one buffer */
		rc = prepare_writing_updates(env, tmt);
		if (rc < 0) {
			CERROR("%s: cannot prepare updates: rc = %d\n",
			       master_dev->dd_lu_dev.ld_obd->obd_name, rc);
			th->th_result = rc;
			write_updates = false;
			GOTO(stop_master_trans, rc);
		}

		lur = tur->tur_update_records;
		/* Write updates to the master MDT */
		rc = sub_updates_write(env, lur, master_st);

		/* Cleanup the common parameters in the update records,
		 * master transno callback might add more parameters.
		 * and we need merge the update records again in the
		 * following */
		if (tur->tur_update_params != NULL)
			lur->lur_update_rec.ur_param_count = 0;

		if (rc < 0) {
			CERROR("%s: write updates failed: rc = %d\n",
			       master_dev->dd_lu_dev.ld_obd->obd_name, rc);
			th->th_result = rc;
			write_updates = false;
			GOTO(stop_master_trans, rc);
		}
	}

stop_master_trans:
	/* Step 2: Stop the transaction on the master MDT, and fill the
	 * master transno in the update logs to other MDT. */
	if (master_st != NULL && master_st->st_sub_th != NULL) {
		if (th->th_local)
			master_st->st_sub_th->th_local = th->th_local;
		if (th->th_sync)
			master_st->st_sub_th->th_sync = th->th_sync;
		master_st->st_sub_th->th_result = th->th_result;
		rc = dt_trans_stop(env, master_st->st_dt, master_st->st_sub_th);
		/* If it does not write_updates, then we call submit callback
		 * here, otherwise callback is done through
		 * osd(osp)_trans_commit_cb() */
		if (!master_st->st_started &&
		    !list_empty(&tmt->tmt_commit_list))
			sub_trans_commit_cb_internal(tmt,
						master_st->st_sub_th, rc);
		if (rc < 0) {
			CERROR("%s: stop trans failed: rc = %d\n",
			       master_dev->dd_lu_dev.ld_obd->obd_name, rc);
			th->th_result = rc;
			GOTO(stop_other_trans, rc);
		} else if (tur != NULL && tur->tur_update_records != NULL) {
			struct llog_update_record *lur;

			lur = tur->tur_update_records;
			if (lur->lur_update_rec.ur_master_transno == 0)
				/* Update master transno after master stop
				 * callback */
				lur->lur_update_rec.ur_master_transno =
						tgt_th_info(env)->tti_transno;
		}
	}

	/* Step 3: write updates to other MDTs */
	if (write_updates) {
		struct llog_update_record *lur;

		/* Stop callback of master will add more updates and also update
		 * master transno, so merge the parameters and updates into one
		 * buffer again */
		rc = prepare_writing_updates(env, tmt);
		if (rc < 0) {
			CERROR("%s: prepare updates failed: rc = %d\n",
			       master_dev->dd_lu_dev.ld_obd->obd_name, rc);
			th->th_result = rc;
			GOTO(stop_other_trans, rc);
		}
		lur = tur->tur_update_records;
		list_for_each_entry(st, &tmt->tmt_sub_thandle_list,
				    st_sub_list) {
			if (st->st_sub_th == NULL || st == master_st ||
			    st->st_sub_th->th_result < 0)
				continue;

			rc = sub_updates_write(env, lur, st);
			if (rc < 0) {
				CERROR("%s: write updates failed: rc = %d\n",
				       st->st_dt->dd_lu_dev.ld_obd->obd_name,
				       rc);
				th->th_result = rc;
				break;
			}
		}
	}

stop_other_trans:
	/* Step 4: Stop the transaction on other MDTs */
	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		if (st == master_st || st->st_sub_th == NULL)
			continue;

		if (th->th_sync)
			st->st_sub_th->th_sync = th->th_sync;
		if (th->th_local)
			st->st_sub_th->th_local = th->th_local;
		st->st_sub_th->th_result = th->th_result;
		rc = dt_trans_stop(env, st->st_sub_th->th_dev,
				   st->st_sub_th);
		if (rc < 0) {
			CERROR("%s: stop trans failed: rc = %d\n",
			       st->st_dt->dd_lu_dev.ld_obd->obd_name, rc);
			if (th->th_result == 0)
				th->th_result = rc;
		}
	}

	rc = top_trans_wait_result(top_th);

	tmt->tmt_result = rc;

	/* Balance for the refcount in top_trans_create, Note: if it is NOT
	 * multiple node transaction, the top transaction will be destroyed. */
	top_multiple_thandle_put(tmt);
	OBD_FREE_PTR(top_th);
	RETURN(rc);
}
EXPORT_SYMBOL(top_trans_stop);

/**
 * Create top_multiple_thandle for top_thandle
 *
 * Create top_mutilple_thandle to manage the mutiple node transaction
 * for top_thandle, and it also needs to add master sub thandle to the
 * sub trans list now.
 *
 * \param[in] env	execution environment
 * \param[in] top_th	the top thandle
 *
 * \retval	0 if creation succeeds
 * \retval	negative errno if creation fails
 */
int top_trans_create_tmt(const struct lu_env *env,
			 struct top_thandle *top_th)
{
	struct top_multiple_thandle *tmt;

	OBD_ALLOC_PTR(tmt);
	if (tmt == NULL)
		return -ENOMEM;

	tmt->tmt_magic = TOP_THANDLE_MAGIC;
	INIT_LIST_HEAD(&tmt->tmt_sub_thandle_list);
	INIT_LIST_HEAD(&tmt->tmt_commit_list);
	atomic_set(&tmt->tmt_refcount, 1);
	spin_lock_init(&tmt->tmt_sub_lock);
	init_waitqueue_head(&tmt->tmt_stop_waitq);

	top_th->tt_multiple_thandle = tmt;

	return 0;
}

static struct sub_thandle *
create_sub_thandle_with_thandle(struct top_thandle *top_th,
				struct thandle *sub_th)
{
	struct sub_thandle *st;

	/* create and init sub th to the top trans list */
	st = create_sub_thandle(top_th->tt_multiple_thandle,
				sub_th->th_dev);
	if (IS_ERR(st))
		return st;

	st->st_sub_th = sub_th;

	sub_th->th_top = &top_th->tt_super;
	sub_thandle_register_stop_cb(st, top_th->tt_multiple_thandle);
	return st;
}

/**
 * Get sub thandle.
 *
 * Get sub thandle from the top thandle according to the sub dt_device.
 *
 * \param[in] env	execution environment
 * \param[in] th	thandle on the top layer.
 * \param[in] sub_dt	sub dt_device used to get sub transaction
 *
 * \retval		thandle of sub transaction if succeed
 * \retval		PTR_ERR(errno) if failed
 */
struct thandle *thandle_get_sub_by_dt(const struct lu_env *env,
				      struct thandle *th,
				      struct dt_device *sub_dt)
{
	struct sub_thandle	*st = NULL;
	struct sub_thandle	*master_st = NULL;
	struct top_thandle	*top_th;
	struct thandle		*sub_th = NULL;
	int			rc = 0;
	ENTRY;

	top_th = container_of(th, struct top_thandle, tt_super);

	if (likely(sub_dt == top_th->tt_master_sub_thandle->th_dev))
		RETURN(top_th->tt_master_sub_thandle);

	if (top_th->tt_multiple_thandle != NULL) {
		st = lookup_sub_thandle(top_th->tt_multiple_thandle, sub_dt);
		if (st != NULL)
			RETURN(st->st_sub_th);
	}

	sub_th = dt_trans_create(env, sub_dt);
	if (IS_ERR(sub_th))
		RETURN(sub_th);

	/* Create top_multiple_thandle if necessary */
	if (top_th->tt_multiple_thandle == NULL) {
		struct top_multiple_thandle *tmt;

		rc = top_trans_create_tmt(env, top_th);
		if (rc < 0)
			GOTO(stop_trans, rc);

		tmt = top_th->tt_multiple_thandle;

		/* Add master sub th to the top trans list */
		tmt->tmt_master_sub_dt =
			top_th->tt_master_sub_thandle->th_dev;
		master_st = create_sub_thandle_with_thandle(top_th,
					top_th->tt_master_sub_thandle);
		if (IS_ERR(master_st)) {
			rc = PTR_ERR(master_st);
			master_st = NULL;
			GOTO(stop_trans, rc);
		}
	}

	/* create and init sub th to the top trans list */
	st = create_sub_thandle_with_thandle(top_th, sub_th);
	if (IS_ERR(st)) {
		rc = PTR_ERR(st);
		st = NULL;
		GOTO(stop_trans, rc);
	}
	st->st_sub_th->th_wait_submit = 1;
stop_trans:
	if (rc < 0) {
		if (master_st != NULL) {
			list_del(&master_st->st_sub_list);
			OBD_FREE_PTR(master_st);
		}
		sub_th->th_result = rc;
		dt_trans_stop(env, sub_dt, sub_th);
		sub_th = ERR_PTR(rc);
	}

	RETURN(sub_th);
}
EXPORT_SYMBOL(thandle_get_sub_by_dt);

/**
 * Top multiple thandle destroy
 *
 * Destroy multiple thandle and all its sub thandle.
 *
 * \param[in] tmt	top_multiple_thandle to be destroyed.
 */
void top_multiple_thandle_destroy(struct top_multiple_thandle *tmt)
{
	struct sub_thandle *st;
	struct sub_thandle *tmp;

	LASSERT(tmt->tmt_magic == TOP_THANDLE_MAGIC);
	list_for_each_entry_safe(st, tmp, &tmt->tmt_sub_thandle_list,
				 st_sub_list) {
		struct sub_thandle_cookie *stc;
		struct sub_thandle_cookie *tmp;

		list_del(&st->st_sub_list);
		list_for_each_entry_safe(stc, tmp, &st->st_cookie_list,
					 stc_list) {
			list_del(&stc->stc_list);
			OBD_FREE_PTR(stc);
		}
		OBD_FREE_PTR(st);
	}
	OBD_FREE_PTR(tmt);
}
EXPORT_SYMBOL(top_multiple_thandle_destroy);

/**
 * Cancel the update log on MDTs
 *
 * Cancel the update log on MDTs then destroy the thandle.
 *
 * \param[in] env	execution environment
 * \param[in] tmt	the top multiple thandle whose updates records
 *                      will be cancelled.
 *
 * \retval		0 if cancellation succeeds.
 * \retval		negative errno if cancellation fails.
 */
static int distribute_txn_cancel_records(const struct lu_env *env,
					 struct top_multiple_thandle *tmt)
{
	struct sub_thandle *st;
	ENTRY;

	top_multiple_thandle_dump(tmt, D_INFO);
	/* Cancel update logs on other MDTs */
	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		struct llog_ctxt	*ctxt;
		struct obd_device	*obd;
		struct llog_cookie	*cookie;
		struct sub_thandle_cookie *stc;
		int rc;

		obd = st->st_dt->dd_lu_dev.ld_obd;
		ctxt = llog_get_context(obd, LLOG_UPDATELOG_ORIG_CTXT);
		if (ctxt == NULL)
			continue;
		list_for_each_entry(stc, &st->st_cookie_list, stc_list) {
			cookie = &stc->stc_cookie;
			if (fid_is_zero(&cookie->lgc_lgl.lgl_oi.oi_fid))
				continue;

			rc = llog_cat_cancel_records(env, ctxt->loc_handle, 1,
						     cookie);
			CDEBUG(D_HA, "%s: batchid %llu cancel update log "
			       DFID".%u: rc = %d\n", obd->obd_name,
			       tmt->tmt_batchid,
			       PFID(&cookie->lgc_lgl.lgl_oi.oi_fid),
			       cookie->lgc_index, rc);
		}

		llog_ctxt_put(ctxt);
	}

	RETURN(0);
}

/**
 * Check if there are committed transaction
 *
 * Check if there are committed transaction in the distribute transaction
 * list, then cancel the update records for those committed transaction.
 * Because the distribute transaction in the list are sorted by batchid,
 * and cancellation will be done by batchid order, so we only check the first
 * the transaction(with lowest batchid) in the list.
 *
 * \param[in] lod	lod device where cancel thread is
 *
 * \retval		true if it is ready
 * \retval		false if it is not ready
 */
static bool tdtd_ready_for_cancel_log(struct target_distribute_txn_data *tdtd)
{
	struct top_multiple_thandle	*tmt = NULL;
	struct obd_device		*obd = tdtd->tdtd_lut->lut_obd;
	bool	ready = false;

	spin_lock(&tdtd->tdtd_batchid_lock);
	if (!list_empty(&tdtd->tdtd_list)) {
		tmt = list_entry(tdtd->tdtd_list.next,
				 struct top_multiple_thandle, tmt_commit_list);
		if (tmt->tmt_committed &&
		    (!obd->obd_recovering || (obd->obd_recovering &&
		    tmt->tmt_batchid <= tdtd->tdtd_committed_batchid)))
			ready = true;
	}
	spin_unlock(&tdtd->tdtd_batchid_lock);

	return ready;
}

struct distribute_txn_bid_data {
	struct dt_txn_commit_cb  dtbd_cb;
	struct target_distribute_txn_data      *dtbd_tdtd;
	__u64                    dtbd_batchid;
};

/**
 * callback of updating commit batchid
 *
 * Updating commit batchid then wake up the commit thread to cancel the
 * records.
 *
 * \param[in]env	execution environment
 * \param[in]th		thandle to updating commit batchid
 * \param[in]cb		commit callback
 * \param[in]err	result of thandle
 */
static void distribute_txn_batchid_cb(struct lu_env *env,
				      struct thandle *th,
				      struct dt_txn_commit_cb *cb,
				      int err)
{
	struct distribute_txn_bid_data		*dtbd = NULL;
	struct target_distribute_txn_data	*tdtd;

	dtbd = container_of0(cb, struct distribute_txn_bid_data, dtbd_cb);
	tdtd = dtbd->dtbd_tdtd;

	CDEBUG(D_HA, "%s: %llu batchid updated\n",
	      tdtd->tdtd_lut->lut_obd->obd_name, dtbd->dtbd_batchid);
	spin_lock(&tdtd->tdtd_batchid_lock);
	if (dtbd->dtbd_batchid > tdtd->tdtd_committed_batchid &&
	    !tdtd->tdtd_lut->lut_obd->obd_no_transno)
		tdtd->tdtd_committed_batchid = dtbd->dtbd_batchid;
	spin_unlock(&tdtd->tdtd_batchid_lock);
	atomic_dec(&tdtd->tdtd_refcount);
	wake_up(&tdtd->tdtd_commit_thread_waitq);

	OBD_FREE_PTR(dtbd);
}

/**
 * Update the commit batchid in disk
 *
 * Update commit batchid in the disk, after this is committed, it can start
 * to cancel the update records.
 *
 * \param[in] env	execution environment
 * \param[in] tdtd	distribute transaction structure
 * \param[in] batchid	commit batchid to be updated
 *
 * \retval		0 if update succeeds.
 * \retval		negative errno if update fails.
 */
static int
distribute_txn_commit_batchid_update(const struct lu_env *env,
			      struct target_distribute_txn_data *tdtd,
			      __u64 batchid)
{
	struct distribute_txn_bid_data	*dtbd = NULL;
	struct thandle		*th;
	struct lu_buf		 buf;
	__u64			 tmp;
	__u64			 off;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(dtbd);
	if (dtbd == NULL)
		RETURN(-ENOMEM);
	dtbd->dtbd_batchid = batchid;
	dtbd->dtbd_tdtd = tdtd;
	dtbd->dtbd_cb.dcb_func = distribute_txn_batchid_cb;
	atomic_inc(&tdtd->tdtd_refcount);

	th = dt_trans_create(env, tdtd->tdtd_lut->lut_bottom);
	if (IS_ERR(th)) {
		atomic_dec(&tdtd->tdtd_refcount);
		OBD_FREE_PTR(dtbd);
		RETURN(PTR_ERR(th));
	}

	tmp = cpu_to_le64(batchid);
	buf.lb_buf = &tmp;
	buf.lb_len = sizeof(tmp);
	off = 0;

	rc = dt_declare_record_write(env, tdtd->tdtd_batchid_obj, &buf, off,
				     th);
	if (rc < 0)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, tdtd->tdtd_lut->lut_bottom, th);
	if (rc < 0)
		GOTO(stop, rc);

	rc = dt_trans_cb_add(th, &dtbd->dtbd_cb);
	if (rc < 0)
		GOTO(stop, rc);

	rc = dt_record_write(env, tdtd->tdtd_batchid_obj, &buf,
			     &off, th);

	CDEBUG(D_INFO, "%s: update batchid %llu: rc = %d\n",
	       tdtd->tdtd_lut->lut_obd->obd_name, batchid, rc);

stop:
	dt_trans_stop(env, tdtd->tdtd_lut->lut_bottom, th);
	if (rc < 0) {
		atomic_dec(&tdtd->tdtd_refcount);
		OBD_FREE_PTR(dtbd);
	}
	RETURN(rc);
}

/**
 * Init commit batchid for distribute transaction.
 *
 * Initialize the batchid object and get commit batchid from the object.
 *
 * \param[in] env	execution environment
 * \param[in] tdtd	distribute transaction whose batchid is initialized.
 *
 * \retval		0 if initialization succeeds.
 * \retval		negative errno if initialization fails.
 **/
static int
distribute_txn_commit_batchid_init(const struct lu_env *env,
				   struct target_distribute_txn_data *tdtd)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct lu_target	*lut = tdtd->tdtd_lut;
	struct lu_attr		*attr = &tti->tti_attr;
	struct lu_fid		*fid = &tti->tti_fid1;
	struct dt_object_format	*dof = &tti->tti_u.update.tti_update_dof;
	struct dt_object	*dt_obj = NULL;
	struct lu_buf		buf;
	__u64			tmp;
	__u64			off;
	int			rc;
	ENTRY;

	memset(attr, 0, sizeof(*attr));
	attr->la_valid = LA_MODE;
	attr->la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	dof->dof_type = dt_mode_to_dft(S_IFREG);

	lu_local_obj_fid(fid, BATCHID_COMMITTED_OID);

	dt_obj = dt_find_or_create(env, lut->lut_bottom, fid, dof,
				   attr);
	if (IS_ERR(dt_obj)) {
		rc = PTR_ERR(dt_obj);
		dt_obj = NULL;
		GOTO(out_put, rc);
	}

	tdtd->tdtd_batchid_obj = dt_obj;

	buf.lb_buf = &tmp;
	buf.lb_len = sizeof(tmp);
	off = 0;
	rc = dt_read(env, dt_obj, &buf, &off);
	if (rc < 0 || (rc < buf.lb_len && rc > 0)) {
		CERROR("%s can't read last committed batchid: rc = %d\n",
		       tdtd->tdtd_lut->lut_obd->obd_name, rc);
		if (rc > 0)
			rc = -EINVAL;
		GOTO(out_put, rc);
	} else if (rc == buf.lb_len) {
		tdtd->tdtd_committed_batchid = le64_to_cpu(tmp);
		CDEBUG(D_HA, "%s: committed batchid %llu\n",
		       tdtd->tdtd_lut->lut_obd->obd_name,
		       tdtd->tdtd_committed_batchid);
		rc = 0;
	}

out_put:
	if (rc < 0 && dt_obj != NULL) {
		dt_object_put(env, dt_obj);
		tdtd->tdtd_batchid_obj = NULL;
	}
	return rc;
}

/**
 * manage the distribute transaction thread
 *
 * Distribute transaction are linked to the list, and once the distribute
 * transaction is committed, it will update the last committed batchid first,
 * after it is committed, it will cancel the records.
 *
 * \param[in] _arg	argument for commit thread
 *
 * \retval		0 if thread is running successfully
 * \retval		negative errno if the thread can not be run.
 */
static int distribute_txn_commit_thread(void *_arg)
{
	struct target_distribute_txn_data *tdtd = _arg;
	struct lu_target	*lut = tdtd->tdtd_lut;
	struct ptlrpc_thread	*thread = &lut->lut_tdtd_commit_thread;
	struct l_wait_info	 lwi = { 0 };
	struct lu_env		 env;
	struct list_head	 list;
	int			 rc;
	struct top_multiple_thandle *tmt;
	struct top_multiple_thandle *tmp;
	__u64			 batchid = 0, committed;

	ENTRY;

	rc = lu_env_init(&env, LCT_LOCAL | LCT_MD_THREAD);
	if (rc != 0)
		RETURN(rc);

	spin_lock(&tdtd->tdtd_batchid_lock);
	thread->t_flags = SVC_RUNNING;
	spin_unlock(&tdtd->tdtd_batchid_lock);
	wake_up(&thread->t_ctl_waitq);
	INIT_LIST_HEAD(&list);

	CDEBUG(D_HA, "%s: start commit thread committed batchid %llu\n",
	       tdtd->tdtd_lut->lut_obd->obd_name,
	       tdtd->tdtd_committed_batchid);

	while (distribute_txn_commit_thread_running(lut)) {
		spin_lock(&tdtd->tdtd_batchid_lock);
		list_for_each_entry_safe(tmt, tmp, &tdtd->tdtd_list,
					 tmt_commit_list) {
			if (tmt->tmt_committed == 0)
				break;

			/* Note: right now, replay is based on master MDT
			 * transno, but cancellation is based on batchid.
			 * so we do not try to cancel the update log until
			 * the recoverying is done, unless the update records
			 * batchid < committed_batchid. */
			if (tmt->tmt_batchid <= tdtd->tdtd_committed_batchid) {
				list_move_tail(&tmt->tmt_commit_list, &list);
			} else if (!tdtd->tdtd_lut->lut_obd->obd_recovering) {
				LASSERTF(tmt->tmt_batchid >= batchid,
					 "tmt %p tmt_batchid: %llu, batchid "
					  "%llu\n", tmt, tmt->tmt_batchid,
					 batchid);
				/* There are three types of distribution
				 * transaction result
				 *
				 * 1. If tmt_result < 0, it means the
				 * distribution transaction fails, which should
				 * be rare, because once declare phase succeeds,
				 * the operation should succeeds anyway. Note in
				 * this case, we will still update batchid so
				 * cancellation would be stopped.
				 *
				 * 2. If tmt_result == 0, it means the
				 * distribution transaction succeeds, and we
				 * will update batchid.
				 *
				 * 3. If tmt_result > 0, it means distribute
				 * transaction is not yet committed on every
				 * node, but we need release this tmt before
				 * that, which usuually happens during umount.
				 */
				if (tmt->tmt_result <= 0)
					batchid = tmt->tmt_batchid;
				list_move_tail(&tmt->tmt_commit_list, &list);
			}
		}
		spin_unlock(&tdtd->tdtd_batchid_lock);

		CDEBUG(D_HA, "%s: batchid: %llu committed batchid "
		       "%llu\n", tdtd->tdtd_lut->lut_obd->obd_name, batchid,
		       tdtd->tdtd_committed_batchid);
		/* update globally committed on a storage */
		if (batchid > tdtd->tdtd_committed_batchid) {
			rc = distribute_txn_commit_batchid_update(&env, tdtd,
							     batchid);
			if (rc == 0)
				batchid = 0;
		}
		/* cancel the records for committed batchid's */
		/* XXX: should we postpone cancel's till the end of recovery? */
		committed = tdtd->tdtd_committed_batchid;
		list_for_each_entry_safe(tmt, tmp, &list, tmt_commit_list) {
			if (tmt->tmt_batchid > committed)
				break;
			list_del_init(&tmt->tmt_commit_list);
			if (tmt->tmt_result <= 0)
				distribute_txn_cancel_records(&env, tmt);
			top_multiple_thandle_put(tmt);
		}

		l_wait_event(tdtd->tdtd_commit_thread_waitq,
			     !distribute_txn_commit_thread_running(lut) ||
			     committed < tdtd->tdtd_committed_batchid ||
			     tdtd_ready_for_cancel_log(tdtd), &lwi);
	};

	l_wait_event(tdtd->tdtd_commit_thread_waitq,
		     atomic_read(&tdtd->tdtd_refcount) == 0, &lwi);

	spin_lock(&tdtd->tdtd_batchid_lock);
	list_for_each_entry_safe(tmt, tmp, &tdtd->tdtd_list,
				 tmt_commit_list)
		list_move_tail(&tmt->tmt_commit_list, &list);
	spin_unlock(&tdtd->tdtd_batchid_lock);

	CDEBUG(D_INFO, "%s stopping distribute txn commit thread.\n",
	       tdtd->tdtd_lut->lut_obd->obd_name);
	list_for_each_entry_safe(tmt, tmp, &list, tmt_commit_list) {
		list_del_init(&tmt->tmt_commit_list);
		top_multiple_thandle_dump(tmt, D_HA);
		top_multiple_thandle_put(tmt);
	}

	thread->t_flags = SVC_STOPPED;
	lu_env_fini(&env);
	wake_up(&thread->t_ctl_waitq);

	RETURN(0);
}

/**
 * Start llog cancel thread
 *
 * Start llog cancel(master/slave) thread on LOD
 *
 * \param[in]lclt	cancel log thread to be started.
 *
 * \retval		0 if the thread is started successfully.
 * \retval		negative errno if the thread is not being
 *                      started.
 */
int distribute_txn_init(const struct lu_env *env,
			struct lu_target *lut,
			struct target_distribute_txn_data *tdtd,
			__u32 index)
{
	struct task_struct	*task;
	struct l_wait_info	 lwi = { 0 };
	int			rc;
	ENTRY;

	INIT_LIST_HEAD(&tdtd->tdtd_list);
	INIT_LIST_HEAD(&tdtd->tdtd_replay_finish_list);
	INIT_LIST_HEAD(&tdtd->tdtd_replay_list);
	spin_lock_init(&tdtd->tdtd_batchid_lock);
	spin_lock_init(&tdtd->tdtd_replay_list_lock);
	tdtd->tdtd_replay_handler = distribute_txn_replay_handle;
	tdtd->tdtd_replay_ready = 0;

	tdtd->tdtd_batchid = lut->lut_last_transno + 1;

	init_waitqueue_head(&lut->lut_tdtd_commit_thread.t_ctl_waitq);
	init_waitqueue_head(&tdtd->tdtd_commit_thread_waitq);
	init_waitqueue_head(&tdtd->tdtd_recovery_threads_waitq);
	atomic_set(&tdtd->tdtd_refcount, 0);
	atomic_set(&tdtd->tdtd_recovery_threads_count, 0);

	tdtd->tdtd_lut = lut;
	if (lut->lut_bottom->dd_rdonly)
		RETURN(0);

	rc = distribute_txn_commit_batchid_init(env, tdtd);
	if (rc != 0)
		RETURN(rc);

	task = kthread_run(distribute_txn_commit_thread, tdtd, "dist_txn-%u",
			   index);
	if (IS_ERR(task))
		RETURN(PTR_ERR(task));

	l_wait_event(lut->lut_tdtd_commit_thread.t_ctl_waitq,
		     distribute_txn_commit_thread_running(lut) ||
		     distribute_txn_commit_thread_stopped(lut), &lwi);
	RETURN(0);
}
EXPORT_SYMBOL(distribute_txn_init);

/**
 * Stop llog cancel thread
 *
 * Stop llog cancel(master/slave) thread on LOD and also destory
 * all of transaction in the list.
 *
 * \param[in]lclt	cancel log thread to be stopped.
 */
void distribute_txn_fini(const struct lu_env *env,
			 struct target_distribute_txn_data *tdtd)
{
	struct lu_target *lut = tdtd->tdtd_lut;

	/* Stop cancel thread */
	if (lut == NULL || !distribute_txn_commit_thread_running(lut))
		return;

	spin_lock(&tdtd->tdtd_batchid_lock);
	lut->lut_tdtd_commit_thread.t_flags = SVC_STOPPING;
	spin_unlock(&tdtd->tdtd_batchid_lock);
	wake_up(&tdtd->tdtd_commit_thread_waitq);
	wait_event(lut->lut_tdtd_commit_thread.t_ctl_waitq,
		   lut->lut_tdtd_commit_thread.t_flags & SVC_STOPPED);

	dtrq_list_destroy(tdtd);
	if (tdtd->tdtd_batchid_obj != NULL) {
		dt_object_put(env, tdtd->tdtd_batchid_obj);
		tdtd->tdtd_batchid_obj = NULL;
	}
}
EXPORT_SYMBOL(distribute_txn_fini);
