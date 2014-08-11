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
 * Copyright (c) 2014, Intel Corporation.
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

#include <lu_target.h>
#include <lustre_log.h>
#include <lustre_update.h>
#include <obd.h>
#include <obd_class.h>
#include <tgt_internal.h>

/**
 * Declare write update to sub device
 *
 * Declare Write updates llog records to the sub device during distribute
 * transaction.
 *
 * \param[in] env	execution environment
 * \param[in] record	update records being written
 * \param[in] lst	sub transaction handle
 *
 * \retval		0 if writing succeeds
 * \retval		negative errno if writing fails
 */
static int sub_declare_updates_write(const struct lu_env *env,
				     struct llog_update_record *record,
				     struct sub_thandle *lst)
{
	struct llog_ctxt	*ctxt;
	struct dt_device	*dt = lst->st_sub_th->th_dev;
	int rc;

	/* If ctxt is NULL, it means not need to write update,
	 * for example if the the OSP is used to connect to OST */
	ctxt = llog_get_context(dt->dd_lu_dev.ld_obd,
				LLOG_UPDATELOG_ORIG_CTXT);
	LASSERT(ctxt != NULL);

	/* Not ready to record updates yet. */
	if (ctxt->loc_handle == NULL) {
		llog_ctxt_put(ctxt);
		return 0;
	}

	rc = llog_declare_add(env, ctxt->loc_handle, &record->lur_hdr,
			      lst->st_sub_th);

	llog_ctxt_put(ctxt);

	return rc;
}

/**
 * write update to sub device
 *
 * Write updates llog records to the sub device during distribute
 * transaction.
 *
 * \param[in] env	execution environment
 * \param[in] record	update records being written
 * \param[in] lst	sub transaction handle
 *
 * \retval		1 if writing succeeds
 * \retval		negative errno if writing fails
 */
static int sub_updates_write(const struct lu_env *env,
			     struct llog_update_record *record,
			     struct sub_thandle *lst)
{
	struct llog_ctxt	*ctxt;
	struct dt_device	*dt = lst->st_sub_th->th_dev;
	int			rc;

	ctxt = llog_get_context(dt->dd_lu_dev.ld_obd,
				LLOG_UPDATELOG_ORIG_CTXT);
	LASSERT(ctxt != NULL);

	/* Not ready to record updates yet, usually happens
	 * in error handler path */
	if (ctxt->loc_handle == NULL) {
		llog_ctxt_put(ctxt);
		return 0;
	}

	LASSERTF(record->lur_hdr.lrh_len == llog_update_record_size(record),
		 "lrh_len %u record_size %zu\n", record->lur_hdr.lrh_len,
		 llog_update_record_size(record));

	rc = llog_add(env, ctxt->loc_handle, &record->lur_hdr,
		      NULL, lst->st_sub_th);

	llog_ctxt_put(ctxt);

	return rc;
}

/**
 * write update transaction
 *
 * Check if there are updates being recorded in this transaction,
 * it will write the record into the disk.
 *
 * \param[in] env	execution environment
 * \param[in] top_th	top transaction handle
 *
 * \retval		0 if writing succeeds
 * \retval		negative errno if writing fails
 */
static int top_updates_write(const struct lu_env *env,
			     struct top_thandle *top_th)
{
	struct thandle_update_records *tur;
	struct llog_update_record *lur;
	struct sub_thandle	*lst;
	int			rc;
	ENTRY;

	if (top_th->tt_update_records == NULL)
		RETURN(0);

	tur = top_th->tt_update_records;

	/* merge the parameters and updates into one buffer */
	rc = merge_params_updates_buf(env, tur);
	if (rc < 0)
		RETURN(rc);

	lur = tur->tur_update_records;
	/* Dump updates to debug log */
	update_records_dump(&lur->lur_update_rec, D_INFO, true);

	/* Init update record header */
	lur->lur_hdr.lrh_len = llog_update_record_size(lur);
	lur->lur_hdr.lrh_type = UPDATE_REC;

	list_for_each_entry(lst, &top_th->tt_sub_thandle_list, st_sub_list) {
		if (!lst->st_record_update)
			continue;
		rc = sub_updates_write(env, lur, lst);
		if (rc < 0)
			break;
	}

	if (rc > 0)
		rc = 0;

	RETURN(rc);
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

	child_th = dt_trans_create(env, master_dev);
	if (IS_ERR(child_th)) {
		OBD_FREE_PTR(top_th);
		return child_th;
	}

	top_th->tt_magic = TOP_THANDLE_MAGIC;
	top_th->tt_master_sub_thandle = child_th;
	child_th->th_top = &top_th->tt_super;

	top_th->tt_update_records = NULL;
	top_th->tt_super.th_top = &top_th->tt_super;
	INIT_LIST_HEAD(&top_th->tt_sub_thandle_list);

	return &top_th->tt_super;
}
EXPORT_SYMBOL(top_trans_create);

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
	struct sub_thandle	*lst;
	int			rc;

	LASSERT(top_th->tt_magic == TOP_THANDLE_MAGIC);
	rc = check_and_prepare_update_record(env, th);
	if (rc < 0)
		return rc;
	/* Check if needs to write updates */
	list_for_each_entry(lst, &top_th->tt_sub_thandle_list, st_sub_list) {
		struct llog_update_record *record;

		if (!lst->st_record_update)
			continue;

		record = top_th->tt_update_records->tur_update_records;
		rc = sub_declare_updates_write(env, record, lst);
		if (rc != 0)
			return rc;
	}

	list_for_each_entry(lst, &top_th->tt_sub_thandle_list, st_sub_list) {
		lst->st_sub_th->th_sync = th->th_sync;
		lst->st_sub_th->th_local = th->th_local;
		rc = dt_trans_start(env, lst->st_sub_th->th_dev,
				    lst->st_sub_th);
		if (rc != 0)
			return rc;
	}

	top_th->tt_master_sub_thandle->th_local = th->th_local;
	top_th->tt_master_sub_thandle->th_sync = th->th_sync;

	return dt_trans_start(env, master_dev, top_th->tt_master_sub_thandle);
}
EXPORT_SYMBOL(top_trans_start);

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
	struct thandle_update_records *tur = top_th->tt_update_records;
	struct sub_thandle	*lst;
	int			rc;
	ENTRY;

	/* Note: we always need walk through all of sub_transaction to do
	 * transaction stop to release the resource here */
	if (tur != NULL && th->th_result == 0) {
		rc = top_updates_write(env, top_th);
		if (rc < 0) {
			CERROR("%s: cannot write updates: rc = %d\n",
			       master_dev->dd_lu_dev.ld_obd->obd_name, rc);
			/* Still need call dt_trans_stop to release resources
			 * holding by the transaction */
		}
		top_th->tt_update_records = NULL;
	}

	LASSERT(top_th->tt_magic == TOP_THANDLE_MAGIC);

	top_th->tt_master_sub_thandle->th_local = th->th_local;
	top_th->tt_master_sub_thandle->th_sync = th->th_sync;
	top_th->tt_master_sub_thandle->th_result = th->th_result;
	/* To avoid sending RPC while holding thandle, it always stop local
	 * transaction first, then other sub thandle */
	rc = dt_trans_stop(env, master_dev, top_th->tt_master_sub_thandle);

	list_for_each_entry(lst, &top_th->tt_sub_thandle_list, st_sub_list) {
		int	rc2;

		if (rc != 0)
			lst->st_sub_th->th_result = rc;
		else
			lst->st_sub_th->th_result = th->th_result;
		lst->st_sub_th->th_sync = th->th_sync;
		lst->st_sub_th->th_local = th->th_local;
		rc2 = dt_trans_stop(env, lst->st_sub_th->th_dev,
				    lst->st_sub_th);
		if (unlikely(rc2 < 0 && rc == 0))
			rc = rc2;
	}

	top_thandle_destroy(top_th);

	RETURN(rc);
}
EXPORT_SYMBOL(top_trans_stop);

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
	struct sub_thandle	*lst;
	struct top_thandle	*top_th;
	struct thandle		*sub_th;
	ENTRY;

	top_th = container_of(th, struct top_thandle, tt_super);
	LASSERT(top_th->tt_magic == TOP_THANDLE_MAGIC);
	LASSERT(top_th->tt_master_sub_thandle != NULL);
	if (likely(sub_dt == top_th->tt_master_sub_thandle->th_dev))
		RETURN(top_th->tt_master_sub_thandle);

	/* Find or create the transaction in tt_trans_list, since there is
	 * always only one thread access the list, so no need lock here */
	list_for_each_entry(lst, &top_th->tt_sub_thandle_list, st_sub_list) {
		if (lst->st_sub_th->th_dev == sub_dt)
			RETURN(lst->st_sub_th);
	}

	sub_th = dt_trans_create(env, sub_dt);
	if (IS_ERR(sub_th))
		RETURN(sub_th);

	/* XXX all of mixed transaction (see struct th_handle) will
	 * be synchronized until async update is done */
	th->th_sync = 1;

	sub_th->th_top = th;
	OBD_ALLOC_PTR(lst);
	if (lst == NULL) {
		dt_trans_stop(env, sub_dt, sub_th);
		RETURN(ERR_PTR(-ENOMEM));
	}

	INIT_LIST_HEAD(&lst->st_sub_list);
	lst->st_sub_th = sub_th;
	list_add(&lst->st_sub_list, &top_th->tt_sub_thandle_list);
	lst->st_record_update = 1;

	RETURN(sub_th);
}
EXPORT_SYMBOL(thandle_get_sub_by_dt);

/**
 * Top thandle destroy
 *
 * Destroy the top thandle and all of its sub thandle.
 *
 * \param[in] top_th	top thandle to be destroyed.
 */
void top_thandle_destroy(struct top_thandle *top_th)
{
	struct sub_thandle *st;
	struct sub_thandle *tmp;

	LASSERT(top_th->tt_magic == TOP_THANDLE_MAGIC);
	list_for_each_entry_safe(st, tmp, &top_th->tt_sub_thandle_list,
				 st_sub_list) {
		list_del(&st->st_sub_list);
		OBD_FREE_PTR(st);
	}
	OBD_FREE_PTR(top_th);
}
EXPORT_SYMBOL(top_thandle_destroy);
